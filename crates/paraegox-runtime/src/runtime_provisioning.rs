#![cfg(unix)]

//! Owner-private Runtime provisioning reconstructed from protected local facts.
//!
//! This module deliberately defines no persistent provisioning format. Both
//! install and normal startup rebuild this in-memory capability from exact
//! versioned CLI identities and Runtime-owned key files, then compare its
//! contract-owned fingerprints with sequence one.

use core::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use nix::unistd::{getegid, geteuid};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::BoundedDuration;
use paraegox_runtime_contracts::apply::{
    PlanWriterRef, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
};
use paraegox_runtime_contracts::provenance::SourceScopeRef;
use paraegox_runtime_contracts::reference_control::{
    MAX_REFERENCE_LIFECYCLE_NANOS, REFERENCE_ADMISSION_REQUEST_NONCE_CAPACITY,
    REFERENCE_ADMISSION_TEMPORAL_LINEAGE_CAPACITY, REFERENCE_ADMISSION_TENURE_NONCE_CAPACITY,
    ReferenceAdmissionPolicyInputV1, ReferenceBootstrapChannelPolicyInputV1, ReferenceControlError,
    ed25519_control_key_fingerprint, reference_admission_policy_fingerprint_v1,
    reference_bootstrap_channel_policy_fingerprint_v1,
    reference_developer_local_bootstrap_channel_policy_fingerprint_v1,
};
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};
use zeroize::Zeroize;

use crate::admission::{
    AdmissionConfigurationError, AdmissionStateLimits, ApplyAdmissionPolicy, ED25519_ALGORITHM,
    ED25519_ALGORITHM_VERSION, TrustedApplyIdentity, TrustedApplyKey, TrustedTenureIdentity,
    TrustedTenureKey,
};

pub(crate) const CONTROL_SOCKET_DIRECTORY_MODE: u32 = 0o2750;
pub(crate) const CONTROL_SOCKET_MODE: u32 = 0o660;
pub(crate) const DEVELOPER_LOCAL_SOCKET_DIRECTORY_MODE: u32 = CONTROL_SOCKET_DIRECTORY_MODE;
pub(crate) const DEVELOPER_LOCAL_SOCKET_MODE: u32 = CONTROL_SOCKET_MODE;
const KEY_FILE_MODE: u32 = 0o400;
const MODE_MASK: u32 = 0o7777;
const KEY_BYTES: usize = 32;
const OWNER_TARGET_FINGERPRINT_DOMAIN: &[u8] = b"paraegox.runtime.owner-target.sha256.v1";

/// Exact service identities, protocol selectors and protected key paths.
///
/// Key bytes, fingerprints and policy limits are intentionally absent: the
/// constructor obtains or derives every one of those values itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeProvisioningInputV1 {
    pub(crate) socket_path: PathBuf,
    pub(crate) target: RuntimeHostId,
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) writer: PlanWriterRef,
    pub(crate) runtime_principal: PrincipalRef,
    pub(crate) runtime_uid: u32,
    pub(crate) runtime_gid: u32,
    pub(crate) controller_principal: PrincipalRef,
    pub(crate) controller_uid: u32,
    pub(crate) controller_gid: u32,
    pub(crate) controller_request_key_ref: ApplyAuthKeyRef,
    pub(crate) controller_public_key_path: PathBuf,
    pub(crate) runtime_response_key_ref: ApplyAuthKeyRef,
    pub(crate) runtime_response_public_key_path: PathBuf,
    pub(crate) runtime_response_private_seed_path: PathBuf,
    pub(crate) authority_principal: PrincipalRef,
    pub(crate) authority_uid: u32,
    pub(crate) authority_gid: u32,
    pub(crate) tenure_authority_ref: TenureAuthorityRef,
    pub(crate) tenure_key_ref: TenureKeyRef,
    pub(crate) tenure_public_key_path: PathBuf,
}

/// In-memory identity material admitted only by the explicit DeveloperLocal
/// composition root.  It deliberately has no production constructor and
/// never changes the production protected-key-file path.
pub(crate) struct RuntimeDeveloperLocalProvisioningInputV1 {
    pub(crate) socket_path: PathBuf,
    pub(crate) target: RuntimeHostId,
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) writer: PlanWriterRef,
    pub(crate) runtime_principal: PrincipalRef,
    pub(crate) controller_principal: PrincipalRef,
    pub(crate) controller_request_key_ref: ApplyAuthKeyRef,
    pub(crate) controller_signing_seed: [u8; KEY_BYTES],
    pub(crate) runtime_response_key_ref: ApplyAuthKeyRef,
    pub(crate) runtime_response_signing_seed: [u8; KEY_BYTES],
    pub(crate) authority_principal: PrincipalRef,
    pub(crate) tenure_authority_ref: TenureAuthorityRef,
    pub(crate) tenure_key_ref: TenureKeyRef,
    pub(crate) tenure_signing_seed: [u8; KEY_BYTES],
}

impl Drop for RuntimeDeveloperLocalProvisioningInputV1 {
    fn drop(&mut self) {
        self.controller_signing_seed.zeroize();
        self.runtime_response_signing_seed.zeroize();
        self.tenure_signing_seed.zeroize();
    }
}

struct RuntimeProvisioningMaterialV1 {
    controller_public_key: [u8; KEY_BYTES],
    response_public_key: [u8; KEY_BYTES],
    response_seed: [u8; KEY_BYTES],
    tenure_public_key: [u8; KEY_BYTES],
    socket_directory_mode: u32,
    socket_mode: u32,
    developer_local: bool,
}

impl Drop for RuntimeProvisioningMaterialV1 {
    fn drop(&mut self) {
        self.response_seed.zeroize();
    }
}

/// Validated in-memory Runtime provisioning capability.
///
/// Debug output never exposes public key bytes or the Runtime signing seed.
pub(crate) struct RuntimeProvisioningV1 {
    socket_path: PathBuf,
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    runtime_principal: PrincipalRef,
    controller_principal: PrincipalRef,
    controller_request_key_ref: ApplyAuthKeyRef,
    controller_key: VerifyingKey,
    runtime_response_key_ref: ApplyAuthKeyRef,
    response_signer: SigningKey,
    runtime_uid: u32,
    runtime_gid: u32,
    controller_uid: u32,
    controller_gid: u32,
    socket_directory_mode: u32,
    socket_mode: u32,
    admission_policy: ApplyAdmissionPolicy,
    owner_target_fingerprint: Digest32,
    admission_policy_fingerprint: Digest32,
    channel_policy_fingerprint: Digest32,
    controller_key_fingerprint: Digest32,
}

impl fmt::Debug for RuntimeProvisioningV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProvisioningV1")
            .field("socket_path", &self.socket_path)
            .field("target", &self.target)
            .field("source_scope", &self.source_scope)
            .field("runtime_principal", &self.runtime_principal)
            .field("controller_principal", &self.controller_principal)
            .field("runtime_uid", &self.runtime_uid)
            .field("runtime_gid", &self.runtime_gid)
            .field("controller_uid", &self.controller_uid)
            .field("controller_gid", &self.controller_gid)
            .field("owner_target_fingerprint", &self.owner_target_fingerprint)
            .field(
                "admission_policy_fingerprint",
                &self.admission_policy_fingerprint,
            )
            .field(
                "channel_policy_fingerprint",
                &self.channel_policy_fingerprint,
            )
            .field(
                "controller_key_fingerprint",
                &self.controller_key_fingerprint,
            )
            .finish_non_exhaustive()
    }
}

impl RuntimeProvisioningV1 {
    /// Reconstructs all four sequence-one pins and the executable admission policy.
    pub(crate) fn try_new(
        input: RuntimeProvisioningInputV1,
    ) -> Result<Self, RuntimeProvisioningError> {
        validate_input(&input)?;
        validate_runtime_credentials(input.runtime_uid, input.runtime_gid)?;

        let controller_public_key = read_exact_key_file(
            &input.controller_public_key_path,
            input.runtime_uid,
            input.runtime_gid,
        )?;
        let response_public_key = read_exact_key_file(
            &input.runtime_response_public_key_path,
            input.runtime_uid,
            input.runtime_gid,
        )?;
        let response_seed = read_exact_key_file(
            &input.runtime_response_private_seed_path,
            input.runtime_uid,
            input.runtime_gid,
        )?;
        let tenure_public_key = read_exact_key_file(
            &input.tenure_public_key_path,
            input.runtime_uid,
            input.runtime_gid,
        )?;

        Self::try_new_from_material(
            input,
            RuntimeProvisioningMaterialV1 {
                controller_public_key,
                response_public_key,
                response_seed,
                tenure_public_key,
                socket_directory_mode: CONTROL_SOCKET_DIRECTORY_MODE,
                socket_mode: CONTROL_SOCKET_MODE,
                developer_local: false,
            },
        )
    }

    /// Builds the same authenticated provisioning capability for the explicit
    /// same-user DeveloperLocal launcher.  Role identities and signing keys
    /// remain distinct; only the production multi-UID deployment requirement
    /// is replaced by the current process credentials.
    pub(crate) fn try_new_developer_local(
        input: RuntimeDeveloperLocalProvisioningInputV1,
    ) -> Result<Self, RuntimeProvisioningError> {
        validate_canonical_absolute_path(&input.socket_path, true)?;
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        if uid == 0 || gid == 0 {
            return Err(RuntimeProvisioningError::InvalidProvisioning);
        }
        let controller_signer = SigningKey::from_bytes(&input.controller_signing_seed);
        let response_signer = SigningKey::from_bytes(&input.runtime_response_signing_seed);
        let tenure_signer = SigningKey::from_bytes(&input.tenure_signing_seed);
        let material = RuntimeProvisioningInputV1 {
            socket_path: input.socket_path.clone(),
            target: input.target,
            source_scope: input.source_scope,
            writer: input.writer,
            runtime_principal: input.runtime_principal,
            runtime_uid: uid,
            runtime_gid: gid,
            controller_principal: input.controller_principal,
            controller_uid: uid,
            controller_gid: gid,
            controller_request_key_ref: input.controller_request_key_ref,
            controller_public_key_path: PathBuf::new(),
            runtime_response_key_ref: input.runtime_response_key_ref,
            runtime_response_public_key_path: PathBuf::new(),
            runtime_response_private_seed_path: PathBuf::new(),
            authority_principal: input.authority_principal,
            authority_uid: uid,
            authority_gid: gid,
            tenure_authority_ref: input.tenure_authority_ref,
            tenure_key_ref: input.tenure_key_ref,
            tenure_public_key_path: PathBuf::new(),
        };
        validate_role_identities(&material, false)?;
        let response_seed = input.runtime_response_signing_seed;
        Self::try_new_from_material(
            material,
            RuntimeProvisioningMaterialV1 {
                controller_public_key: controller_signer.verifying_key().to_bytes(),
                response_public_key: response_signer.verifying_key().to_bytes(),
                response_seed,
                tenure_public_key: tenure_signer.verifying_key().to_bytes(),
                socket_directory_mode: DEVELOPER_LOCAL_SOCKET_DIRECTORY_MODE,
                socket_mode: DEVELOPER_LOCAL_SOCKET_MODE,
                developer_local: true,
            },
        )
    }

    fn try_new_from_material(
        input: RuntimeProvisioningInputV1,
        mut material: RuntimeProvisioningMaterialV1,
    ) -> Result<Self, RuntimeProvisioningError> {
        let controller_key = parse_verifying_key(material.controller_public_key)?;
        let response_key = parse_verifying_key(material.response_public_key)?;
        let tenure_key = parse_verifying_key(material.tenure_public_key)?;
        let response_signer = SigningKey::from_bytes(&material.response_seed);
        material.response_seed.zeroize();
        let controller_public_key = material.controller_public_key;
        let response_public_key = material.response_public_key;
        let tenure_public_key = material.tenure_public_key;
        let socket_directory_mode = material.socket_directory_mode;
        let socket_mode = material.socket_mode;
        let developer_local = material.developer_local;
        if response_signer.verifying_key() != response_key
            || controller_key == response_key
            || controller_key == tenure_key
            || response_key == tenure_key
        {
            return Err(RuntimeProvisioningError::InvalidProvisioning);
        }

        let tenure_algorithm = TenureProofAlgorithm::try_new(ED25519_ALGORITHM)
            .map_err(|_| RuntimeProvisioningError::InvalidProvisioning)?;
        let apply_algorithm = ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
            .map_err(|_| RuntimeProvisioningError::InvalidProvisioning)?;
        let state_limits = AdmissionStateLimits::try_new(
            REFERENCE_ADMISSION_TENURE_NONCE_CAPACITY,
            REFERENCE_ADMISSION_REQUEST_NONCE_CAPACITY,
            REFERENCE_ADMISSION_TEMPORAL_LINEAGE_CAPACITY,
        )?;
        let trusted_tenure = TrustedTenureKey::try_new(
            TrustedTenureIdentity::new(
                input.source_scope,
                input.authority_principal,
                input.authority_uid,
                input.authority_gid,
                input.tenure_authority_ref,
            ),
            input.tenure_key_ref,
            tenure_algorithm,
            ED25519_ALGORITHM_VERSION,
            tenure_public_key,
        )?;
        let trusted_apply = TrustedApplyKey::try_new(
            TrustedApplyIdentity::new(
                input.source_scope,
                input.target,
                input.controller_principal,
                input.writer,
            ),
            input.controller_request_key_ref,
            apply_algorithm,
            ED25519_ALGORITHM_VERSION,
            controller_public_key,
        )?;
        let admission_policy = ApplyAdmissionPolicy::try_new(
            BoundedDuration::from_nanos(MAX_REFERENCE_LIFECYCLE_NANOS),
            state_limits,
            [trusted_tenure],
            [trusted_apply],
        )?;
        let sealed_admission =
            reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
                target: input.target,
                source_scope: input.source_scope,
                writer: input.writer,
                controller_principal: input.controller_principal,
                controller_key_ref: input.controller_request_key_ref,
                controller_public_key: &controller_public_key,
                authority_principal: input.authority_principal,
                authority_uid: input.authority_uid,
                authority_gid: input.authority_gid,
                tenure_authority_ref: input.tenure_authority_ref,
                tenure_key_ref: input.tenure_key_ref,
                tenure_public_key: &tenure_public_key,
            })?;
        admission_policy.verify_reference_fingerprint(sealed_admission)?;
        let admission_policy_fingerprint = sealed_admission.digest();
        let owner_target_fingerprint = owner_target_fingerprint(&input)?;
        let channel_input = ReferenceBootstrapChannelPolicyInputV1 {
            canonical_socket_path: input.socket_path.as_os_str().as_bytes(),
            target: input.target,
            source_scope: input.source_scope,
            controller_principal: input.controller_principal,
            controller_key_ref: input.controller_request_key_ref,
            controller_public_key: &controller_public_key,
            runtime_uid: input.runtime_uid,
            runtime_gid: input.runtime_gid,
            controller_uid: input.controller_uid,
            controller_gid: input.controller_gid,
            runtime_principal: input.runtime_principal,
            response_key_ref: input.runtime_response_key_ref,
            response_public_key: &response_public_key,
        };
        let channel_policy_fingerprint = if developer_local {
            reference_developer_local_bootstrap_channel_policy_fingerprint_v1(channel_input)?
        } else {
            reference_bootstrap_channel_policy_fingerprint_v1(channel_input)?
        };
        let controller_key_fingerprint = ed25519_control_key_fingerprint(&controller_public_key)?;

        Ok(Self {
            socket_path: input.socket_path,
            target: input.target,
            source_scope: input.source_scope,
            runtime_principal: input.runtime_principal,
            controller_principal: input.controller_principal,
            controller_request_key_ref: input.controller_request_key_ref,
            controller_key,
            runtime_response_key_ref: input.runtime_response_key_ref,
            response_signer,
            runtime_uid: input.runtime_uid,
            runtime_gid: input.runtime_gid,
            controller_uid: input.controller_uid,
            controller_gid: input.controller_gid,
            socket_directory_mode,
            socket_mode,
            admission_policy,
            owner_target_fingerprint,
            admission_policy_fingerprint,
            channel_policy_fingerprint,
            controller_key_fingerprint,
        })
    }

    #[must_use]
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn source_scope(&self) -> SourceScopeRef {
        self.source_scope
    }

    #[must_use]
    pub(crate) const fn runtime_principal(&self) -> PrincipalRef {
        self.runtime_principal
    }

    #[must_use]
    pub(crate) const fn controller_principal(&self) -> PrincipalRef {
        self.controller_principal
    }

    #[must_use]
    pub(crate) const fn controller_request_key_ref(&self) -> ApplyAuthKeyRef {
        self.controller_request_key_ref
    }

    #[must_use]
    pub(crate) const fn controller_key(&self) -> &VerifyingKey {
        &self.controller_key
    }

    #[must_use]
    pub(crate) const fn runtime_response_key_ref(&self) -> ApplyAuthKeyRef {
        self.runtime_response_key_ref
    }

    #[must_use]
    pub(crate) const fn response_signer(&self) -> &SigningKey {
        &self.response_signer
    }

    #[must_use]
    pub(crate) fn runtime_response_public_key(&self) -> [u8; KEY_BYTES] {
        self.response_signer.verifying_key().to_bytes()
    }

    #[must_use]
    pub(crate) const fn runtime_uid(&self) -> u32 {
        self.runtime_uid
    }

    #[must_use]
    pub(crate) const fn runtime_gid(&self) -> u32 {
        self.runtime_gid
    }

    #[must_use]
    pub(crate) const fn controller_uid(&self) -> u32 {
        self.controller_uid
    }

    #[must_use]
    pub(crate) const fn controller_gid(&self) -> u32 {
        self.controller_gid
    }

    #[must_use]
    pub(crate) const fn socket_directory_mode(&self) -> u32 {
        self.socket_directory_mode
    }

    #[must_use]
    pub(crate) const fn socket_mode(&self) -> u32 {
        self.socket_mode
    }

    #[must_use]
    pub(crate) const fn admission_policy(&self) -> &ApplyAdmissionPolicy {
        &self.admission_policy
    }

    #[must_use]
    pub(crate) const fn owner_target_fingerprint(&self) -> Digest32 {
        self.owner_target_fingerprint
    }

    #[must_use]
    pub(crate) const fn admission_policy_fingerprint(&self) -> Digest32 {
        self.admission_policy_fingerprint
    }

    #[must_use]
    pub(crate) const fn channel_policy_fingerprint(&self) -> Digest32 {
        self.channel_policy_fingerprint
    }

    #[must_use]
    pub(crate) const fn controller_key_fingerprint(&self) -> Digest32 {
        self.controller_key_fingerprint
    }

    pub(crate) fn validate_runtime_credentials(&self) -> Result<(), RuntimeProvisioningError> {
        validate_runtime_credentials(self.runtime_uid, self.runtime_gid)
    }
}

fn owner_target_fingerprint(
    input: &RuntimeProvisioningInputV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(OWNER_TARGET_FINGERPRINT_DOMAIN)?;
    builder.field_bytes(input.target.as_bytes())?;
    builder.field_bytes(input.runtime_principal.as_bytes())?;
    builder.field_u64(u64::from(input.runtime_uid))?;
    builder.field_u64(u64::from(input.runtime_gid))?;
    Ok(builder.finish())
}

fn validate_input(input: &RuntimeProvisioningInputV1) -> Result<(), RuntimeProvisioningError> {
    validate_canonical_absolute_path(&input.socket_path, true)?;
    let key_paths = [
        &input.controller_public_key_path,
        &input.runtime_response_public_key_path,
        &input.runtime_response_private_seed_path,
        &input.tenure_public_key_path,
    ];
    for path in key_paths {
        validate_canonical_absolute_path(path, true)?;
        if path == &input.socket_path {
            return Err(RuntimeProvisioningError::InvalidProvisioning);
        }
    }
    for (index, path) in key_paths.iter().enumerate() {
        if key_paths[index + 1..].contains(path) {
            return Err(RuntimeProvisioningError::InvalidProvisioning);
        }
    }

    validate_role_identities(input, true)
}

fn validate_role_identities(
    input: &RuntimeProvisioningInputV1,
    require_distinct_os_users: bool,
) -> Result<(), RuntimeProvisioningError> {
    let required_refs: [&[u8]; 9] = [
        input.target.as_bytes(),
        input.source_scope.as_bytes(),
        input.writer.as_bytes(),
        input.runtime_principal.as_bytes(),
        input.controller_principal.as_bytes(),
        input.controller_request_key_ref.as_bytes(),
        input.runtime_response_key_ref.as_bytes(),
        input.authority_principal.as_bytes(),
        input.tenure_authority_ref.as_bytes(),
    ];
    if required_refs
        .iter()
        .any(|identity| identity.iter().all(|byte| *byte == 0))
        || input
            .tenure_key_ref
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(RuntimeProvisioningError::InvalidProvisioning);
    }

    let role_refs = [
        input.runtime_principal.as_bytes(),
        input.controller_principal.as_bytes(),
        input.authority_principal.as_bytes(),
        input.controller_request_key_ref.as_bytes(),
        input.runtime_response_key_ref.as_bytes(),
        input.tenure_authority_ref.as_bytes(),
        input.tenure_key_ref.as_bytes(),
    ];
    for (index, identity) in role_refs.iter().enumerate() {
        if role_refs[index + 1..].contains(identity) {
            return Err(RuntimeProvisioningError::InvalidProvisioning);
        }
    }

    let principals = [
        input.runtime_principal,
        input.controller_principal,
        input.authority_principal,
    ];
    if principals[0] == principals[1]
        || principals[0] == principals[2]
        || principals[1] == principals[2]
    {
        return Err(RuntimeProvisioningError::InvalidProvisioning);
    }
    let uids = [input.runtime_uid, input.controller_uid, input.authority_uid];
    if uids.contains(&0)
        || input.runtime_gid == 0
        || input.controller_gid == 0
        || input.authority_gid == 0
        || require_distinct_os_users
            && (uids[0] == uids[1] || uids[0] == uids[2] || uids[1] == uids[2])
    {
        return Err(RuntimeProvisioningError::InvalidProvisioning);
    }
    Ok(())
}

pub(crate) fn validate_canonical_absolute_path(
    path: &Path,
    require_file_name: bool,
) -> Result<(), RuntimeProvisioningError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes.is_empty()
        || bytes.first() != Some(&b'/')
        || bytes.contains(&0)
        || bytes.windows(2).any(|window| window == b"//")
        || (bytes.len() > 1 && bytes.last() == Some(&b'/'))
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component == b"." || component == b"..")
        || (require_file_name && (bytes.len() == 1 || path.file_name().is_none()))
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(RuntimeProvisioningError::InvalidProvisioning);
    }
    Ok(())
}

fn validate_runtime_credentials(
    runtime_uid: u32,
    runtime_gid: u32,
) -> Result<(), RuntimeProvisioningError> {
    if geteuid().as_raw() != runtime_uid || getegid().as_raw() != runtime_gid {
        return Err(RuntimeProvisioningError::RuntimeCredentialsChanged);
    }
    Ok(())
}

fn parse_verifying_key(bytes: [u8; KEY_BYTES]) -> Result<VerifyingKey, RuntimeProvisioningError> {
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| RuntimeProvisioningError::InvalidProvisioning)?;
    if key.is_weak() {
        return Err(RuntimeProvisioningError::InvalidProvisioning);
    }
    Ok(key)
}

fn read_exact_key_file(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<[u8; KEY_BYTES], RuntimeProvisioningError> {
    validate_canonical_absolute_path(path, true)?;
    let before = fs::symlink_metadata(path)
        .map_err(|error| RuntimeProvisioningError::KeyFile(error.kind()))?;
    validate_key_metadata(&before, expected_uid, expected_gid)?;
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        RuntimeProvisioningError::KeyFile(io::Error::from_raw_os_error(error as i32).kind())
    })?;
    let mut file = File::from(owned);
    let after = file
        .metadata()
        .map_err(|error| RuntimeProvisioningError::KeyFile(error.kind()))?;
    validate_key_metadata(&after, expected_uid, expected_gid)?;
    if !KeyFileIdentity::from_metadata(&before).matches(&after) {
        return Err(RuntimeProvisioningError::KeyFileIdentityChanged);
    }
    let mut key = [0_u8; KEY_BYTES];
    file.read_exact(&mut key)
        .map_err(|error| RuntimeProvisioningError::KeyFile(error.kind()))?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| RuntimeProvisioningError::KeyFile(error.kind()))?
        != 0
    {
        return Err(RuntimeProvisioningError::InvalidKeyFile);
    }
    Ok(key)
}

fn validate_key_metadata(
    metadata: &Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RuntimeProvisioningError> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & MODE_MASK != KEY_FILE_MODE
        || metadata.len() != KEY_BYTES as u64
    {
        return Err(RuntimeProvisioningError::InvalidKeyFile);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct KeyFileIdentity {
    device: u64,
    inode: u64,
}

impl KeyFileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn matches(self, metadata: &Metadata) -> bool {
        self.device == metadata.dev() && self.inode == metadata.ino()
    }
}

/// Fail-closed provisioning reconstruction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeProvisioningError {
    InvalidProvisioning,
    RuntimeCredentialsChanged,
    KeyFile(io::ErrorKind),
    KeyFileIdentityChanged,
    InvalidKeyFile,
    Admission(AdmissionConfigurationError),
    Control(ReferenceControlError),
    Digest(DigestBuildError),
}

impl From<AdmissionConfigurationError> for RuntimeProvisioningError {
    fn from(error: AdmissionConfigurationError) -> Self {
        Self::Admission(error)
    }
}

impl From<ReferenceControlError> for RuntimeProvisioningError {
    fn from(error: ReferenceControlError) -> Self {
        Self::Control(error)
    }
}

impl From<DigestBuildError> for RuntimeProvisioningError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

impl fmt::Display for RuntimeProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProvisioning => formatter.write_str("invalid Runtime provisioning"),
            Self::RuntimeCredentialsChanged => {
                formatter.write_str("Runtime service credentials changed")
            }
            Self::KeyFile(kind) => write!(formatter, "provisioning key-file I/O: {kind:?}"),
            Self::KeyFileIdentityChanged => {
                formatter.write_str("provisioning key-file identity changed")
            }
            Self::InvalidKeyFile => formatter.write_str("invalid provisioning key file"),
            Self::Admission(error) => write!(formatter, "admission policy: {error}"),
            Self::Control(error) => write!(formatter, "channel policy: {error}"),
            Self::Digest(error) => write!(formatter, "provisioning fingerprint: {error}"),
        }
    }
}

impl std::error::Error for RuntimeProvisioningError {}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs::Permissions;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const CONTROLLER_SEED: [u8; 32] = [0x41; 32];
    const RESPONSE_SEED: [u8; 32] = [0x42; 32];
    const TENURE_SEED: [u8; 32] = [0x43; 32];
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        directory: PathBuf,
        input: RuntimeProvisioningInputV1,
    }

    impl Fixture {
        fn create() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "paraegox-runtime-provisioning-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory)
                .unwrap_or_else(|error| panic!("fixture directory create failed: {error}"));
            let controller_path = directory.join("controller.pub");
            let response_public_path = directory.join("runtime.pub");
            let response_seed_path = directory.join("runtime.seed");
            let tenure_path = directory.join("authority.pub");
            write_key(
                &controller_path,
                &SigningKey::from_bytes(&CONTROLLER_SEED)
                    .verifying_key()
                    .to_bytes(),
            );
            write_key(
                &response_public_path,
                &SigningKey::from_bytes(&RESPONSE_SEED)
                    .verifying_key()
                    .to_bytes(),
            );
            write_key(&response_seed_path, &RESPONSE_SEED);
            write_key(
                &tenure_path,
                &SigningKey::from_bytes(&TENURE_SEED)
                    .verifying_key()
                    .to_bytes(),
            );
            let runtime_uid = geteuid().as_raw();
            let runtime_gid = getegid().as_raw();
            assert_ne!(runtime_uid, 0, "tests require a non-root Runtime uid");
            assert_ne!(runtime_gid, 0, "tests require a non-root Runtime gid");
            let controller_uid = distinct_uid(runtime_uid, 1);
            let authority_uid = distinct_uid(runtime_uid, 2);
            assert_ne!(controller_uid, authority_uid);
            Self {
                directory: directory.clone(),
                input: RuntimeProvisioningInputV1 {
                    socket_path: directory.join("runtime.sock"),
                    target: RuntimeHostId::from_bytes([0x11; 16]),
                    source_scope: SourceScopeRef::from_bytes([0x12; 16]),
                    writer: PlanWriterRef::from_bytes([0x13; 16]),
                    runtime_principal: PrincipalRef::from_bytes([0x21; 16]),
                    runtime_uid,
                    runtime_gid,
                    controller_principal: PrincipalRef::from_bytes([0x22; 16]),
                    controller_uid,
                    controller_gid: runtime_gid,
                    controller_request_key_ref: ApplyAuthKeyRef::from_bytes([0x31; 16]),
                    controller_public_key_path: controller_path,
                    runtime_response_key_ref: ApplyAuthKeyRef::from_bytes([0x32; 16]),
                    runtime_response_public_key_path: response_public_path,
                    runtime_response_private_seed_path: response_seed_path,
                    authority_principal: PrincipalRef::from_bytes([0x23; 16]),
                    authority_uid,
                    authority_gid: runtime_gid,
                    tenure_authority_ref: TenureAuthorityRef::from_bytes([0x33; 16]),
                    tenure_key_ref: TenureKeyRef::from_bytes([0x34; 16]),
                    tenure_public_key_path: tenure_path,
                },
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn distinct_uid(runtime_uid: u32, distance: u32) -> u32 {
        if runtime_uid <= u32::MAX - distance {
            runtime_uid + distance
        } else {
            runtime_uid - distance
        }
    }

    fn write_key(path: &Path, bytes: &[u8; 32]) {
        if path.exists() {
            fs::set_permissions(path, Permissions::from_mode(0o600))
                .unwrap_or_else(|error| panic!("key fixture writable chmod failed: {error}"));
        }
        fs::write(path, bytes).unwrap_or_else(|error| panic!("key fixture write failed: {error}"));
        fs::set_permissions(path, Permissions::from_mode(KEY_FILE_MODE))
            .unwrap_or_else(|error| panic!("key fixture chmod failed: {error}"));
    }

    #[test]
    fn exact_files_construct_policy_and_all_sequence_one_pins() {
        let fixture = Fixture::create();
        let provisioning = RuntimeProvisioningV1::try_new(fixture.input.clone())
            .unwrap_or_else(|error| panic!("valid provisioning rejected: {error}"));
        assert_eq!(
            provisioning.admission_policy_fingerprint(),
            reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
                target: fixture.input.target,
                source_scope: fixture.input.source_scope,
                writer: fixture.input.writer,
                controller_principal: fixture.input.controller_principal,
                controller_key_ref: fixture.input.controller_request_key_ref,
                controller_public_key: SigningKey::from_bytes(&CONTROLLER_SEED)
                    .verifying_key()
                    .as_bytes(),
                authority_principal: fixture.input.authority_principal,
                authority_uid: fixture.input.authority_uid,
                authority_gid: fixture.input.authority_gid,
                tenure_authority_ref: fixture.input.tenure_authority_ref,
                tenure_key_ref: fixture.input.tenure_key_ref,
                tenure_public_key: SigningKey::from_bytes(&TENURE_SEED)
                    .verifying_key()
                    .as_bytes(),
            })
            .unwrap_or_else(|error| panic!("shared admission fingerprint failed: {error}"))
            .digest()
        );
        for fingerprint in [
            provisioning.owner_target_fingerprint(),
            provisioning.admission_policy_fingerprint(),
            provisioning.channel_policy_fingerprint(),
            provisioning.controller_key_fingerprint(),
        ] {
            assert_ne!(fingerprint, Digest32::from_bytes([0; 32]));
        }
        assert_eq!(
            provisioning.admission_policy().maximum_budget(),
            BoundedDuration::from_nanos(MAX_REFERENCE_LIFECYCLE_NANOS)
        );
        assert_eq!(
            provisioning.admission_policy().state_limits(),
            AdmissionStateLimits::try_new(
                REFERENCE_ADMISSION_TENURE_NONCE_CAPACITY,
                REFERENCE_ADMISSION_REQUEST_NONCE_CAPACITY,
                REFERENCE_ADMISSION_TEMPORAL_LINEAGE_CAPACITY,
            )
            .unwrap_or_else(|error| panic!("fixed limits rejected: {error}"))
        );
    }

    #[test]
    fn each_policy_owner_changes_only_from_canonical_facts() {
        let fixture = Fixture::create();
        let base = RuntimeProvisioningV1::try_new(fixture.input.clone())
            .unwrap_or_else(|error| panic!("base provisioning rejected: {error}"));

        let mut writer = fixture.input.clone();
        writer.writer = PlanWriterRef::from_bytes([0x55; 16]);
        let writer = RuntimeProvisioningV1::try_new(writer)
            .unwrap_or_else(|error| panic!("writer variant rejected: {error}"));
        assert_eq!(
            base.owner_target_fingerprint(),
            writer.owner_target_fingerprint()
        );
        assert_eq!(
            base.channel_policy_fingerprint(),
            writer.channel_policy_fingerprint()
        );
        assert_ne!(
            base.admission_policy_fingerprint(),
            writer.admission_policy_fingerprint()
        );

        let mut authority_uid = fixture.input.clone();
        authority_uid.authority_uid = distinct_uid(authority_uid.authority_uid, 3);
        let authority_uid = RuntimeProvisioningV1::try_new(authority_uid)
            .unwrap_or_else(|error| panic!("Authority UID variant rejected: {error}"));
        assert_ne!(
            base.admission_policy_fingerprint(),
            authority_uid.admission_policy_fingerprint()
        );
    }

    #[test]
    fn identities_uids_keys_and_response_seed_must_be_distinct_and_exact() {
        let fixture = Fixture::create();
        let mut same_principal = fixture.input.clone();
        same_principal.authority_principal = same_principal.controller_principal;
        assert!(matches!(
            RuntimeProvisioningV1::try_new(same_principal),
            Err(RuntimeProvisioningError::InvalidProvisioning)
        ));
        let mut same_uid = fixture.input.clone();
        same_uid.authority_uid = same_uid.controller_uid;
        assert!(matches!(
            RuntimeProvisioningV1::try_new(same_uid),
            Err(RuntimeProvisioningError::InvalidProvisioning)
        ));
        let mut aliased_key_ref = fixture.input.clone();
        aliased_key_ref.tenure_key_ref =
            TenureKeyRef::from_bytes(*aliased_key_ref.controller_request_key_ref.as_bytes());
        assert!(matches!(
            RuntimeProvisioningV1::try_new(aliased_key_ref),
            Err(RuntimeProvisioningError::InvalidProvisioning)
        ));
        write_key(
            &fixture.input.runtime_response_private_seed_path,
            &[0x77; 32],
        );
        assert!(matches!(
            RuntimeProvisioningV1::try_new(fixture.input.clone()),
            Err(RuntimeProvisioningError::InvalidProvisioning)
        ));
    }

    #[test]
    fn canonical_paths_modes_and_no_follow_are_enforced() {
        let fixture = Fixture::create();
        for path in [
            PathBuf::from("relative.sock"),
            PathBuf::from("/tmp//runtime.sock"),
            PathBuf::from("/tmp/runtime.sock/"),
            PathBuf::from("/tmp/./runtime.sock"),
            PathBuf::from("/tmp/../runtime.sock"),
            PathBuf::from(OsString::from_vec(b"/tmp/runtime\0.sock".to_vec())),
        ] {
            let mut input = fixture.input.clone();
            input.socket_path = path;
            assert!(matches!(
                RuntimeProvisioningV1::try_new(input),
                Err(RuntimeProvisioningError::InvalidProvisioning)
            ));
        }

        fs::set_permissions(
            &fixture.input.controller_public_key_path,
            Permissions::from_mode(0o600),
        )
        .unwrap_or_else(|error| panic!("unsafe key chmod failed: {error}"));
        assert!(matches!(
            RuntimeProvisioningV1::try_new(fixture.input.clone()),
            Err(RuntimeProvisioningError::InvalidKeyFile)
        ));
    }

    #[test]
    fn symlink_and_trailing_key_material_fail_closed() {
        let fixture = Fixture::create();
        let symlink_path = fixture.directory.join("controller-link.pub");
        symlink(&fixture.input.controller_public_key_path, &symlink_path)
            .unwrap_or_else(|error| panic!("key symlink failed: {error}"));
        let mut linked = fixture.input.clone();
        linked.controller_public_key_path = symlink_path;
        assert!(matches!(
            RuntimeProvisioningV1::try_new(linked),
            Err(RuntimeProvisioningError::InvalidKeyFile)
        ));

        let mut bytes = SigningKey::from_bytes(&CONTROLLER_SEED)
            .verifying_key()
            .to_bytes()
            .to_vec();
        bytes.push(0);
        fs::set_permissions(
            &fixture.input.controller_public_key_path,
            Permissions::from_mode(0o600),
        )
        .unwrap_or_else(|error| panic!("trailing key writable chmod failed: {error}"));
        fs::write(&fixture.input.controller_public_key_path, bytes)
            .unwrap_or_else(|error| panic!("trailing key write failed: {error}"));
        fs::set_permissions(
            &fixture.input.controller_public_key_path,
            Permissions::from_mode(KEY_FILE_MODE),
        )
        .unwrap_or_else(|error| panic!("trailing key chmod failed: {error}"));
        assert!(matches!(
            RuntimeProvisioningV1::try_new(fixture.input.clone()),
            Err(RuntimeProvisioningError::InvalidKeyFile)
        ));
    }
}
