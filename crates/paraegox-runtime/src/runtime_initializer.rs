#![cfg(unix)]

//! Owner-private one-shot Runtime journal initializer.
//!
//! The validated input type is the boundary between caller-controlled
//! installation evidence and mutation. It consumes the canonical installation
//! verifier before any entropy or filesystem operation. The one-shot function
//! then performs a read-only directory preflight, obtains both random values,
//! constructs the typed sequence-one snapshot, and only then acquires the
//! `RuntimeInitializerGuard` that creates the durable marker and publishes it
//! exactly once. Normal Runtime startup must not call this module as a reset
//! path or reread installer side files.

use core::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_runtime_contracts::installation::{
    InstalledRuntimeArtifactObservationV1, RuntimeCompiledInstallationFactsV1,
    RuntimeInstallationError, verify_existing,
};

use crate::runtime_journal::{
    OpaqueCanonicalValue, RuntimeJournalError, RuntimeJournalSequenceOne, RuntimeJournalSnapshot,
    StorePinnedBuildIdentity,
};
use crate::runtime_provisioning::RuntimeProvisioningV1;
use crate::runtime_store::{
    RuntimeInitializerBeginError, RuntimeInitializerGuard, RuntimeInitializerPreflight,
    RuntimeInitializerPublishError, TEMP_TOKEN_BYTES,
};

const STORE_INSTANCE_ID_BYTES: usize = 32;
const PREVALIDATION_STORE_INSTANCE_ID: [u8; STORE_INSTANCE_ID_BYTES] = [0xff; 32];
const PREVALIDATION_CLOCK_DOMAIN: [u8; 16] = [0xfe; 16];
const CLOCK_DOMAIN_FROM_STORE_ID_DOMAIN: &[u8] =
    b"paraegox.runtime.clock-domain-from-store-instance-id.sha256.v1";
const INITIALIZED_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.initialized-snapshot.sha256.v1";

/// Exact installer output and executable facts presented to Runtime.
///
/// This is deliberately not a validated value. Only
/// [`RuntimeInitializationInputV1::try_new`] can turn it into an input accepted
/// by the mutating initializer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RuntimeInstallationEvidenceV1<'a> {
    descriptor_wire: &'a [u8],
    descriptor_digest: Digest32,
    manifest_wire: &'a [u8],
    manifest_digest: Digest32,
    expected_target: RuntimeHostId,
    artifact: &'a InstalledRuntimeArtifactObservationV1,
    compiled: RuntimeCompiledInstallationFactsV1,
}

impl<'a> RuntimeInstallationEvidenceV1<'a> {
    pub(crate) const fn new(
        descriptor_wire: &'a [u8],
        descriptor_digest: Digest32,
        manifest_wire: &'a [u8],
        manifest_digest: Digest32,
        expected_target: RuntimeHostId,
        artifact: &'a InstalledRuntimeArtifactObservationV1,
        compiled: RuntimeCompiledInstallationFactsV1,
    ) -> Self {
        Self {
            descriptor_wire,
            descriptor_digest,
            manifest_wire,
            manifest_digest,
            expected_target,
            artifact,
            compiled,
        }
    }
}

/// Fully validated, mutation-ready Runtime sequence-one input.
///
/// Construction performs strict descriptor/manifest verification, obtains
/// compiled-actual values from the independent compiled-facts accessors, and
/// runs the complete Runtime journal sequence-one validator with a private
/// non-authoritative sentinel store ID. Consequently the mutating initializer
/// accepts no raw or partially validated installation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeInitializationInputV1 {
    expected_target: RuntimeHostId,
    owner_target_fingerprint: Digest32,
    sequence_one: RuntimeJournalSequenceOne,
}

impl RuntimeInitializationInputV1 {
    pub(crate) fn try_new(
        evidence: RuntimeInstallationEvidenceV1<'_>,
        provisioning: &RuntimeProvisioningV1,
    ) -> Result<Self, RuntimeInitializationError> {
        if evidence.expected_target != provisioning.target() {
            return Err(RuntimeInitializationError::ProvisioningTargetMismatch);
        }
        let verified = verify_existing(
            evidence.descriptor_wire,
            evidence.descriptor_digest,
            evidence.manifest_wire,
            evidence.manifest_digest,
            evidence.expected_target,
            evidence.artifact,
            evidence.compiled,
        )?;

        // These are intentionally read from the independent compiled-facts
        // object. Never replace them with fields echoed by `verified`.
        let compiled_build_instance_id = evidence.compiled.compiled_build_instance_id();
        let compiled_compatibility_digest = evidence
            .compiled
            .compiled_reference_compatibility_digest()?;

        let store_pinned_build_identity = StorePinnedBuildIdentity::try_new(
            verified.build_instance_id(),
            verified.build_descriptor_digest(),
            verified.runtime_artifact_sha256(),
            verified.compiled_reference_compatibility_digest(),
        )?;
        let sequence_one = RuntimeJournalSequenceOne {
            // The authoritative clock domain is derived only after the
            // initializer obtains its fresh CSPRNG store identity. This
            // sentinel exists only for mutation-free structural validation.
            clock_domain: PREVALIDATION_CLOCK_DOMAIN,
            build_descriptor: OpaqueCanonicalValue::try_pinned_artifact(
                verified.descriptor_canonical_wire(),
                verified.descriptor_digest(),
            )?,
            singleton_manifest: OpaqueCanonicalValue::try_pinned_artifact(
                verified.manifest_canonical_wire(),
                verified.manifest_digest(),
            )?,
            store_pinned_build_identity,
            compiled_build_instance_id,
            compiled_compatibility_digest,
            admission_policy_fingerprint: provisioning.admission_policy_fingerprint(),
            channel_policy_fingerprint: provisioning.channel_policy_fingerprint(),
            controller_key_fingerprint: provisioning.controller_key_fingerprint(),
        };

        // Validate every caller-controlled journal field before entropy or I/O.
        // This snapshot is discarded and its sentinel ID is never authoritative.
        RuntimeJournalSnapshot::try_initialize(
            PREVALIDATION_STORE_INSTANCE_ID,
            provisioning.owner_target_fingerprint(),
            sequence_one.clone(),
        )?;

        Ok(Self {
            expected_target: evidence.expected_target,
            owner_target_fingerprint: provisioning.owner_target_fingerprint(),
            sequence_one,
        })
    }
}

/// Initializes a fresh production-reference Runtime store exactly once.
pub(crate) fn initialize_runtime_store(
    directory: &Path,
    input: RuntimeInitializationInputV1,
) -> Result<RuntimeInitializationReceiptV1, RuntimeInitializationError> {
    let preflight = RuntimeInitializerPreflight::open(directory)?;
    initialize_runtime_store_after_preflight(preflight, input)
}

/// Completes initialization from a still-linear read-only directory proof.
///
/// The system install operation uses this seam to validate both its Runtime
/// state directory and immutable manifest output before publishing either one.
pub(crate) fn initialize_runtime_store_after_preflight(
    preflight: RuntimeInitializerPreflight,
    input: RuntimeInitializationInputV1,
) -> Result<RuntimeInitializationReceiptV1, RuntimeInitializationError> {
    let mut entropy = SystemRuntimeInitializationEntropy;
    initialize_runtime_store_after_preflight_with(preflight, input, &mut entropy)
}

fn initialize_runtime_store_with(
    directory: &Path,
    input: RuntimeInitializationInputV1,
    entropy: &mut impl RuntimeInitializationEntropy,
    open_preflight: fn(&Path) -> Result<RuntimeInitializerPreflight, RuntimeInitializerBeginError>,
) -> Result<RuntimeInitializationReceiptV1, RuntimeInitializationError> {
    // The linear preflight validates the complete path/directory/filesystem
    // input without creating the durable marker.
    let preflight = open_preflight(directory)?;
    initialize_runtime_store_after_preflight_with(preflight, input, entropy)
}

fn initialize_runtime_store_after_preflight_with(
    preflight: RuntimeInitializerPreflight,
    input: RuntimeInitializationInputV1,
    entropy: &mut impl RuntimeInitializationEntropy,
) -> Result<RuntimeInitializationReceiptV1, RuntimeInitializationError> {
    // Both random values are obtained and validated before the durable marker
    // or any journal/temp file can be created.
    let store_bytes = entropy.store_instance_id()?;
    if store_bytes.len() != STORE_INSTANCE_ID_BYTES {
        return Err(RuntimeInitializationError::InvalidStoreIdentityWidth);
    }
    let store_instance_id: [u8; STORE_INSTANCE_ID_BYTES] = store_bytes
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeInitializationError::InvalidStoreIdentityWidth)?;
    if store_instance_id == [0; STORE_INSTANCE_ID_BYTES] {
        return Err(RuntimeInitializationError::AllZeroStoreIdentity);
    }

    let temp_bytes = entropy.temp_token()?;
    if temp_bytes.len() != TEMP_TOKEN_BYTES {
        return Err(RuntimeInitializationError::InvalidTempTokenWidth);
    }
    let temp_token: [u8; TEMP_TOKEN_BYTES] = temp_bytes
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeInitializationError::InvalidTempTokenWidth)?;
    if temp_token == [0; TEMP_TOKEN_BYTES] {
        return Err(RuntimeInitializationError::AllZeroTempToken);
    }

    let (snapshot, receipt) = build_sequence_one_snapshot(input, store_instance_id)?;
    let mut guard: RuntimeInitializerGuard = preflight.acquire()?;
    guard.publish_sequence_one(snapshot, temp_token)?;
    Ok(receipt)
}

fn build_sequence_one_snapshot(
    input: RuntimeInitializationInputV1,
    store_instance_id: [u8; STORE_INSTANCE_ID_BYTES],
) -> Result<(RuntimeJournalSnapshot, RuntimeInitializationReceiptV1), RuntimeInitializationError> {
    let RuntimeInitializationInputV1 {
        expected_target,
        owner_target_fingerprint,
        mut sequence_one,
    } = input;
    sequence_one.clock_domain = derive_clock_domain(store_instance_id)?;
    let snapshot = RuntimeJournalSnapshot::try_initialize(
        store_instance_id,
        owner_target_fingerprint,
        sequence_one.clone(),
    )?;
    let receipt =
        RuntimeInitializationReceiptV1::from_snapshot(expected_target, &snapshot, &sequence_one)?;
    Ok((snapshot, receipt))
}

fn derive_clock_domain(
    store_instance_id: [u8; STORE_INSTANCE_ID_BYTES],
) -> Result<[u8; 16], RuntimeInitializationError> {
    let mut builder = Digest32Builder::try_new(CLOCK_DOMAIN_FROM_STORE_ID_DOMAIN)?;
    builder.field_bytes(&store_instance_id)?;
    let digest = builder.finish();
    let mut clock_domain = [0_u8; 16];
    clock_domain.copy_from_slice(&digest.as_bytes()[..16]);
    if clock_domain == [0; 16] {
        return Err(RuntimeInitializationError::AllZeroDerivedClockDomain);
    }
    Ok(clock_domain)
}

trait RuntimeInitializationEntropy {
    fn store_instance_id(&mut self) -> Result<Vec<u8>, RuntimeInitializationEntropyError>;

    fn temp_token(&mut self) -> Result<Vec<u8>, RuntimeInitializationEntropyError>;
}

struct SystemRuntimeInitializationEntropy;

impl RuntimeInitializationEntropy for SystemRuntimeInitializationEntropy {
    fn store_instance_id(&mut self) -> Result<Vec<u8>, RuntimeInitializationEntropyError> {
        read_csprng_exact(STORE_INSTANCE_ID_BYTES)
    }

    fn temp_token(&mut self) -> Result<Vec<u8>, RuntimeInitializationEntropyError> {
        read_csprng_exact(TEMP_TOKEN_BYTES)
    }
}

fn read_csprng_exact(length: usize) -> Result<Vec<u8>, RuntimeInitializationEntropyError> {
    let owned = open(
        Path::new("/dev/urandom"),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        RuntimeInitializationEntropyError::Io(io::Error::from_raw_os_error(error as i32).kind())
    })?;
    let mut source = File::from(owned);
    let mut bytes = vec![0; length];
    source
        .read_exact(&mut bytes)
        .map_err(|error| RuntimeInitializationEntropyError::Io(error.kind()))?;
    Ok(bytes)
}

/// Auditable facts returned only after exact sequence-one read-back succeeds.
///
/// This owner-private value defines no second persistent receipt wire. It
/// carries the exact canonical snapshot and the already verified facts needed
/// to audit it; it contains no path, temporary token, success assertion, or
/// caller-controlled descriptive metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeInitializationReceiptV1 {
    expected_target: RuntimeHostId,
    store_instance_id: [u8; STORE_INSTANCE_ID_BYTES],
    owner_target_fingerprint: Digest32,
    snapshot_sequence: u64,
    initialized_snapshot_canonical_wire: Box<[u8]>,
    initialized_snapshot_digest: Digest32,
    descriptor_canonical_wire: Box<[u8]>,
    descriptor_digest: Digest32,
    manifest_canonical_wire: Box<[u8]>,
    manifest_digest: Digest32,
    store_pinned_build_identity: StorePinnedBuildIdentity,
    compiled_build_instance_id: [u8; 32],
    compiled_compatibility_digest: Digest32,
    clock_domain: [u8; 16],
    admission_policy_fingerprint: Digest32,
    channel_policy_fingerprint: Digest32,
    controller_key_fingerprint: Digest32,
}

impl RuntimeInitializationReceiptV1 {
    fn from_snapshot(
        expected_target: RuntimeHostId,
        snapshot: &RuntimeJournalSnapshot,
        sequence_one: &RuntimeJournalSequenceOne,
    ) -> Result<Self, RuntimeInitializationError> {
        let mut digest = Digest32Builder::try_new(INITIALIZED_SNAPSHOT_DIGEST_DOMAIN)?;
        digest.field_bytes(snapshot.canonical_wire())?;
        Ok(Self {
            expected_target,
            store_instance_id: *snapshot.store_instance_id(),
            owner_target_fingerprint: *snapshot.owner_target_fingerprint(),
            snapshot_sequence: snapshot.sequence(),
            initialized_snapshot_canonical_wire: snapshot.canonical_wire().into(),
            initialized_snapshot_digest: digest.finish(),
            descriptor_canonical_wire: sequence_one.build_descriptor.canonical_bytes.clone(),
            descriptor_digest: sequence_one.build_descriptor.digest,
            manifest_canonical_wire: sequence_one.singleton_manifest.canonical_bytes.clone(),
            manifest_digest: sequence_one.singleton_manifest.digest,
            store_pinned_build_identity: sequence_one.store_pinned_build_identity,
            compiled_build_instance_id: sequence_one.compiled_build_instance_id,
            compiled_compatibility_digest: sequence_one.compiled_compatibility_digest,
            clock_domain: sequence_one.clock_domain,
            admission_policy_fingerprint: sequence_one.admission_policy_fingerprint,
            channel_policy_fingerprint: sequence_one.channel_policy_fingerprint,
            controller_key_fingerprint: sequence_one.controller_key_fingerprint,
        })
    }

    pub(crate) const fn expected_target(&self) -> RuntimeHostId {
        self.expected_target
    }

    pub(crate) const fn store_instance_id(&self) -> &[u8; STORE_INSTANCE_ID_BYTES] {
        &self.store_instance_id
    }

    pub(crate) const fn owner_target_fingerprint(&self) -> Digest32 {
        self.owner_target_fingerprint
    }

    pub(crate) const fn snapshot_sequence(&self) -> u64 {
        self.snapshot_sequence
    }

    pub(crate) fn initialized_snapshot_canonical_wire(&self) -> &[u8] {
        &self.initialized_snapshot_canonical_wire
    }

    pub(crate) const fn initialized_snapshot_digest(&self) -> Digest32 {
        self.initialized_snapshot_digest
    }

    pub(crate) fn descriptor_canonical_wire(&self) -> &[u8] {
        &self.descriptor_canonical_wire
    }

    pub(crate) const fn descriptor_digest(&self) -> Digest32 {
        self.descriptor_digest
    }

    pub(crate) fn manifest_canonical_wire(&self) -> &[u8] {
        &self.manifest_canonical_wire
    }

    pub(crate) const fn manifest_digest(&self) -> Digest32 {
        self.manifest_digest
    }

    pub(crate) const fn store_pinned_build_identity(&self) -> StorePinnedBuildIdentity {
        self.store_pinned_build_identity
    }

    pub(crate) const fn compiled_build_instance_id(&self) -> [u8; 32] {
        self.compiled_build_instance_id
    }

    pub(crate) const fn compiled_compatibility_digest(&self) -> Digest32 {
        self.compiled_compatibility_digest
    }

    pub(crate) const fn clock_domain(&self) -> [u8; 16] {
        self.clock_domain
    }

    pub(crate) const fn admission_policy_fingerprint(&self) -> Digest32 {
        self.admission_policy_fingerprint
    }

    pub(crate) const fn channel_policy_fingerprint(&self) -> Digest32 {
        self.channel_policy_fingerprint
    }

    pub(crate) const fn controller_key_fingerprint(&self) -> Digest32 {
        self.controller_key_fingerprint
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeInitializationEntropyError {
    Io(io::ErrorKind),
    Unavailable,
}

impl fmt::Display for RuntimeInitializationEntropyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime initialization CSPRNG failed: {self:?}")
    }
}

impl std::error::Error for RuntimeInitializationEntropyError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeInitializationError {
    ProvisioningTargetMismatch,
    Installation(RuntimeInstallationError),
    Journal(RuntimeJournalError),
    Digest(DigestBuildError),
    Entropy(RuntimeInitializationEntropyError),
    InvalidStoreIdentityWidth,
    AllZeroStoreIdentity,
    AllZeroDerivedClockDomain,
    InvalidTempTokenWidth,
    AllZeroTempToken,
    Begin(RuntimeInitializerBeginError),
    Publish(RuntimeInitializerPublishError),
}

impl RuntimeInitializationError {
    #[must_use]
    pub(crate) const fn requires_recovery(self) -> bool {
        matches!(
            self,
            Self::Begin(RuntimeInitializerBeginError::MarkerConsumed(_)) | Self::Publish(_)
        )
    }
}

impl From<RuntimeInstallationError> for RuntimeInitializationError {
    fn from(error: RuntimeInstallationError) -> Self {
        Self::Installation(error)
    }
}

impl From<RuntimeJournalError> for RuntimeInitializationError {
    fn from(error: RuntimeJournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<DigestBuildError> for RuntimeInitializationError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

impl From<RuntimeInitializationEntropyError> for RuntimeInitializationError {
    fn from(error: RuntimeInitializationEntropyError) -> Self {
        Self::Entropy(error)
    }
}

impl From<RuntimeInitializerBeginError> for RuntimeInitializationError {
    fn from(error: RuntimeInitializerBeginError) -> Self {
        Self::Begin(error)
    }
}

impl From<RuntimeInitializerPublishError> for RuntimeInitializationError {
    fn from(error: RuntimeInitializerPublishError) -> Self {
        Self::Publish(error)
    }
}

impl fmt::Display for RuntimeInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime initialization failed: {self:?}")
    }
}

impl std::error::Error for RuntimeInitializationError {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use nix::unistd::{getegid, geteuid};
    use paraegox_kernel::identity::PrincipalRef;
    use paraegox_runtime_contracts::apply::{PlanWriterRef, TenureAuthorityRef, TenureKeyRef};
    use paraegox_runtime_contracts::execution::{CardDefinitionRef, CardImplementationRef};
    use paraegox_runtime_contracts::provenance::SourceScopeRef;
    use paraegox_runtime_contracts::wire::ApplyAuthKeyRef;

    use super::*;
    use crate::runtime_provisioning::{RuntimeProvisioningInputV1, RuntimeProvisioningV1};
    use crate::runtime_store::RuntimeStoreOpenError;

    const REFERENCE_FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_reference_successor_v1.json");
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let fixture_root = std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|error| panic!("fixture root canonicalize failed: {error}"));
            let path = fixture_root.join(format!(
                "paraegox-runtime-initializer-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("fixture directory create failed: {error}"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("fixture directory chmod failed: {error}"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn entry_count(&self) -> usize {
            fs::read_dir(&self.0)
                .unwrap_or_else(|error| panic!("fixture directory read failed: {error}"))
                .count()
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone)]
    struct FixtureEntropy {
        store: Result<Vec<u8>, RuntimeInitializationEntropyError>,
        temp: Result<Vec<u8>, RuntimeInitializationEntropyError>,
        store_calls: usize,
        temp_calls: usize,
    }

    impl RuntimeInitializationEntropy for FixtureEntropy {
        fn store_instance_id(&mut self) -> Result<Vec<u8>, RuntimeInitializationEntropyError> {
            self.store_calls += 1;
            self.store.clone()
        }

        fn temp_token(&mut self) -> Result<Vec<u8>, RuntimeInitializationEntropyError> {
            self.temp_calls += 1;
            self.temp.clone()
        }
    }

    fn successful_entropy() -> FixtureEntropy {
        FixtureEntropy {
            store: Ok(vec![0x71; STORE_INSTANCE_ID_BYTES]),
            temp: Ok(vec![0x72; TEMP_TOKEN_BYTES]),
            store_calls: 0,
            temp_calls: 0,
        }
    }

    fn fixture_bytes(field: &str) -> Vec<u8> {
        let marker = format!("\"{field}\": \"");
        let start = REFERENCE_FIXTURE
            .find(&marker)
            .unwrap_or_else(|| panic!("missing fixture field {field}"))
            + marker.len();
        let end = REFERENCE_FIXTURE[start..]
            .find('"')
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("unterminated fixture field {field}"));
        decode_hex(&REFERENCE_FIXTURE[start..end])
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "fixture hex width must be even");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("fixture contains non-lowercase-hex byte"),
        }
    }

    fn fixture_digest(field: &str) -> Digest32 {
        let bytes: [u8; 32] = fixture_bytes(field)
            .try_into()
            .unwrap_or_else(|_| panic!("fixture digest {field} has wrong width"));
        Digest32::from_bytes(bytes)
    }

    fn provisioning(target: RuntimeHostId) -> RuntimeProvisioningV1 {
        let directory = TestDirectory::new();
        let controller_key_path = directory.path().join("controller.pub");
        let response_key_path = directory.path().join("runtime.pub");
        let response_seed_path = directory.path().join("runtime.seed");
        let tenure_key_path = directory.path().join("authority.pub");
        for (path, bytes) in [
            (
                &controller_key_path,
                SigningKey::from_bytes(&[0x31; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            (
                &response_key_path,
                SigningKey::from_bytes(&[0x32; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            (&response_seed_path, [0x32; 32]),
            (
                &tenure_key_path,
                SigningKey::from_bytes(&[0x33; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        ] {
            fs::write(path, bytes)
                .unwrap_or_else(|error| panic!("provisioning key write failed: {error}"));
            fs::set_permissions(path, fs::Permissions::from_mode(0o400))
                .unwrap_or_else(|error| panic!("provisioning key chmod failed: {error}"));
        }
        let runtime_uid = geteuid().as_raw();
        let runtime_gid = getegid().as_raw();
        assert_ne!(runtime_uid, 0, "initializer tests require non-root uid");
        assert_ne!(runtime_gid, 0, "initializer tests require non-root gid");
        RuntimeProvisioningV1::try_new(RuntimeProvisioningInputV1 {
            socket_path: directory.path().join("runtime.sock"),
            target,
            source_scope: SourceScopeRef::from_bytes([0x41; 16]),
            writer: PlanWriterRef::from_bytes([0x42; 16]),
            runtime_principal: PrincipalRef::from_bytes([0x43; 16]),
            runtime_uid,
            runtime_gid,
            controller_principal: PrincipalRef::from_bytes([0x44; 16]),
            controller_uid: distinct_uid(runtime_uid, 1),
            controller_gid: runtime_gid,
            controller_request_key_ref: ApplyAuthKeyRef::from_bytes([0x45; 16]),
            controller_public_key_path: controller_key_path,
            runtime_response_key_ref: ApplyAuthKeyRef::from_bytes([0x46; 16]),
            runtime_response_public_key_path: response_key_path,
            runtime_response_private_seed_path: response_seed_path,
            authority_principal: PrincipalRef::from_bytes([0x47; 16]),
            authority_uid: distinct_uid(runtime_uid, 2),
            authority_gid: runtime_gid,
            tenure_authority_ref: TenureAuthorityRef::from_bytes([0x48; 16]),
            tenure_key_ref: TenureKeyRef::from_bytes([0x49; 16]),
            tenure_public_key_path: tenure_key_path,
        })
        .unwrap_or_else(|error| panic!("initializer provisioning rejected: {error}"))
    }

    fn distinct_uid(runtime_uid: u32, distance: u32) -> u32 {
        if runtime_uid <= u32::MAX - distance {
            runtime_uid + distance
        } else {
            runtime_uid - distance
        }
    }

    fn input_with(
        descriptor_wire: &[u8],
        descriptor_digest: Digest32,
        manifest_wire: &[u8],
        manifest_digest: Digest32,
        expected_target: RuntimeHostId,
        provisioned_target: RuntimeHostId,
    ) -> Result<RuntimeInitializationInputV1, RuntimeInitializationError> {
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            Digest32::from_bytes([0x22; 32]),
            "aarch64-unknown-linux-gnu",
        )
        .unwrap_or_else(|error| panic!("artifact fixture failed: {error}"));
        let compiled = RuntimeCompiledInstallationFactsV1::try_new(
            [0x11; 32],
            CardDefinitionRef::from_bytes([0xa1; 16]),
            CardImplementationRef::from_bytes([0xa2; 16]),
            [0xa3; 16],
            Digest32::from_bytes([0xa4; 32]),
            Digest32::from_bytes([0xa5; 32]),
        )
        .unwrap_or_else(|error| panic!("compiled fixture failed: {error}"));
        RuntimeInitializationInputV1::try_new(
            RuntimeInstallationEvidenceV1::new(
                descriptor_wire,
                descriptor_digest,
                manifest_wire,
                manifest_digest,
                expected_target,
                &artifact,
                compiled,
            ),
            &provisioning(provisioned_target),
        )
    }

    fn valid_input() -> RuntimeInitializationInputV1 {
        let descriptor = fixture_bytes("descriptor_hex");
        let manifest = fixture_bytes("manifest_hex");
        input_with(
            &descriptor,
            fixture_digest("descriptor_digest_hex"),
            &manifest,
            fixture_digest("manifest_digest_hex"),
            RuntimeHostId::from_bytes([0x05; 16]),
            RuntimeHostId::from_bytes([0x05; 16]),
        )
        .unwrap_or_else(|error| panic!("valid initialization input failed: {error}"))
    }

    #[test]
    fn preparation_pins_exact_contract_artifacts_and_independent_compiled_actual() {
        let input = valid_input();
        assert_eq!(
            input.sequence_one.build_descriptor.canonical_bytes.as_ref(),
            fixture_bytes("descriptor_hex")
        );
        assert_eq!(
            input
                .sequence_one
                .singleton_manifest
                .canonical_bytes
                .as_ref(),
            fixture_bytes("manifest_hex")
        );
        assert_eq!(input.sequence_one.compiled_build_instance_id, [0x11; 32]);
        assert_eq!(
            input.sequence_one.compiled_compatibility_digest,
            fixture_digest("compiled_compatibility_digest_hex")
        );
        assert_eq!(
            input
                .sequence_one
                .store_pinned_build_identity
                .build_instance_id(),
            input.sequence_one.compiled_build_instance_id
        );
        assert_eq!(
            input
                .sequence_one
                .store_pinned_build_identity
                .compiled_reference_compatibility_digest(),
            input.sequence_one.compiled_compatibility_digest
        );
    }

    #[test]
    fn clock_domain_is_stably_derived_from_the_fresh_store_identity() {
        let first = derive_clock_domain([0x71; STORE_INSTANCE_ID_BYTES])
            .unwrap_or_else(|error| panic!("first clock-domain derivation failed: {error:?}"));
        let replay = derive_clock_domain([0x71; STORE_INSTANCE_ID_BYTES])
            .unwrap_or_else(|error| panic!("replayed clock-domain derivation failed: {error:?}"));
        let second = derive_clock_domain([0x72; STORE_INSTANCE_ID_BYTES])
            .unwrap_or_else(|error| panic!("second clock-domain derivation failed: {error:?}"));

        assert_eq!(first, replay);
        assert_ne!(first, [0; 16]);
        assert_ne!(first, second);
    }

    #[test]
    fn invalid_contract_or_provisioning_inputs_fail_during_pure_preparation() {
        let mut descriptor = fixture_bytes("descriptor_hex");
        let manifest = fixture_bytes("manifest_hex");
        descriptor.push(0);
        assert_eq!(
            input_with(
                &descriptor,
                fixture_digest("descriptor_digest_hex"),
                &manifest,
                fixture_digest("manifest_digest_hex"),
                RuntimeHostId::from_bytes([0x05; 16]),
                RuntimeHostId::from_bytes([0x05; 16]),
            ),
            Err(RuntimeInitializationError::Installation(
                RuntimeInstallationError::InvalidDescriptor,
            ))
        );

        let descriptor = fixture_bytes("descriptor_hex");
        assert_eq!(
            input_with(
                &descriptor,
                fixture_digest("descriptor_digest_hex"),
                &manifest,
                fixture_digest("manifest_digest_hex"),
                RuntimeHostId::from_bytes([0x05; 16]),
                RuntimeHostId::from_bytes([0x06; 16]),
            ),
            Err(RuntimeInitializationError::ProvisioningTargetMismatch)
        );
    }

    #[test]
    fn entropy_failures_and_invalid_widths_precede_every_directory_mutation() {
        let directory = TestDirectory::new();
        let cases = [
            (
                FixtureEntropy {
                    store: Err(RuntimeInitializationEntropyError::Unavailable),
                    temp: Ok(vec![0x72; TEMP_TOKEN_BYTES]),
                    store_calls: 0,
                    temp_calls: 0,
                },
                RuntimeInitializationError::Entropy(RuntimeInitializationEntropyError::Unavailable),
                0,
            ),
            (
                FixtureEntropy {
                    store: Ok(vec![0x71; STORE_INSTANCE_ID_BYTES - 1]),
                    temp: Ok(vec![0x72; TEMP_TOKEN_BYTES]),
                    store_calls: 0,
                    temp_calls: 0,
                },
                RuntimeInitializationError::InvalidStoreIdentityWidth,
                0,
            ),
            (
                FixtureEntropy {
                    store: Ok(vec![0; STORE_INSTANCE_ID_BYTES]),
                    temp: Ok(vec![0x72; TEMP_TOKEN_BYTES]),
                    store_calls: 0,
                    temp_calls: 0,
                },
                RuntimeInitializationError::AllZeroStoreIdentity,
                0,
            ),
            (
                FixtureEntropy {
                    store: Ok(vec![0x71; STORE_INSTANCE_ID_BYTES]),
                    temp: Ok(vec![0x72; TEMP_TOKEN_BYTES - 1]),
                    store_calls: 0,
                    temp_calls: 0,
                },
                RuntimeInitializationError::InvalidTempTokenWidth,
                1,
            ),
            (
                FixtureEntropy {
                    store: Ok(vec![0x71; STORE_INSTANCE_ID_BYTES]),
                    temp: Ok(vec![0; TEMP_TOKEN_BYTES]),
                    store_calls: 0,
                    temp_calls: 0,
                },
                RuntimeInitializationError::AllZeroTempToken,
                1,
            ),
        ];
        for (mut entropy, expected, expected_temp_calls) in cases {
            assert_eq!(
                initialize_runtime_store_with(
                    directory.path(),
                    valid_input(),
                    &mut entropy,
                    RuntimeInitializerPreflight::open_fixture,
                ),
                Err(expected)
            );
            assert_eq!(entropy.store_calls, 1);
            assert_eq!(entropy.temp_calls, expected_temp_calls);
            assert_eq!(directory.entry_count(), 0);
        }
    }

    #[test]
    fn directory_preflight_rejects_before_requesting_entropy() {
        let mut entropy = successful_entropy();
        let error = initialize_runtime_store_with(
            Path::new("relative-runtime-state"),
            valid_input(),
            &mut entropy,
            RuntimeInitializerPreflight::open_fixture,
        )
        .expect_err("relative path must fail preflight");
        assert_eq!(
            error,
            RuntimeInitializationError::Begin(RuntimeInitializerBeginError::Store(
                RuntimeStoreOpenError::PathMustBeAbsolute,
            ))
        );
        assert_eq!(entropy.store_calls, 0);
        assert_eq!(entropy.temp_calls, 0);
        assert!(!error.requires_recovery());
    }

    #[test]
    fn fixture_guard_publishes_exact_sequence_one_and_receipt_facts_once() {
        let directory = TestDirectory::new();
        let mut entropy = successful_entropy();
        let receipt = initialize_runtime_store_with(
            directory.path(),
            valid_input(),
            &mut entropy,
            RuntimeInitializerPreflight::open_fixture,
        )
        .unwrap_or_else(|error| panic!("fixture initialization failed: {error}"));
        assert_eq!(entropy.store_calls, 1);
        assert_eq!(entropy.temp_calls, 1);
        assert_eq!(receipt.store_instance_id(), &[0x71; 32]);
        assert_eq!(receipt.snapshot_sequence(), 1);
        assert_eq!(
            receipt.expected_target(),
            RuntimeHostId::from_bytes([0x05; 16])
        );
        assert_eq!(
            receipt.descriptor_canonical_wire(),
            fixture_bytes("descriptor_hex")
        );
        assert_eq!(
            receipt.manifest_canonical_wire(),
            fixture_bytes("manifest_hex")
        );
        assert_eq!(receipt.compiled_build_instance_id(), [0x11; 32]);
        assert_eq!(
            receipt.compiled_compatibility_digest(),
            fixture_digest("compiled_compatibility_digest_hex")
        );
        assert_ne!(
            receipt.owner_target_fingerprint(),
            Digest32::from_bytes([0; 32])
        );
        assert_eq!(
            receipt.descriptor_digest(),
            fixture_digest("descriptor_digest_hex")
        );
        assert_eq!(
            receipt.manifest_digest(),
            fixture_digest("manifest_digest_hex")
        );
        assert_eq!(
            receipt.clock_domain(),
            derive_clock_domain([0x71; STORE_INSTANCE_ID_BYTES])
                .unwrap_or_else(|error| panic!("clock-domain derivation failed: {error:?}"))
        );
        assert_ne!(
            receipt.admission_policy_fingerprint(),
            Digest32::from_bytes([0; 32])
        );
        assert_ne!(
            receipt.channel_policy_fingerprint(),
            Digest32::from_bytes([0; 32])
        );
        assert_ne!(
            receipt.controller_key_fingerprint(),
            Digest32::from_bytes([0; 32])
        );
        assert_eq!(
            receipt.store_pinned_build_identity().build_instance_id(),
            receipt.compiled_build_instance_id()
        );

        let active = fs::read(directory.path().join("runtime.snapshot"))
            .unwrap_or_else(|error| panic!("active snapshot read failed: {error}"));
        assert_eq!(active, receipt.initialized_snapshot_canonical_wire());
        let mut initialized_digest = Digest32Builder::try_new(INITIALIZED_SNAPSHOT_DIGEST_DOMAIN)
            .unwrap_or_else(|error| panic!("snapshot digest domain failed: {error}"));
        initialized_digest
            .field_bytes(&active)
            .unwrap_or_else(|error| panic!("snapshot digest field failed: {error}"));
        assert_eq!(
            receipt.initialized_snapshot_digest(),
            initialized_digest.finish()
        );
        let decoded = RuntimeJournalSnapshot::decode(&active)
            .unwrap_or_else(|error| panic!("active snapshot decode failed: {error}"));
        assert_eq!(decoded.sequence(), 1);
        assert_eq!(decoded.store_instance_id(), receipt.store_instance_id());
        assert_eq!(
            decoded.state().host.compiled_build_instance_id,
            receipt.compiled_build_instance_id()
        );
        assert_eq!(
            decoded.state().host.compiled_compatibility_digest,
            receipt.compiled_compatibility_digest()
        );

        let before = active;
        let mut retry_entropy = FixtureEntropy {
            store: Ok(vec![0x81; STORE_INSTANCE_ID_BYTES]),
            temp: Ok(vec![0x82; TEMP_TOKEN_BYTES]),
            store_calls: 0,
            temp_calls: 0,
        };
        let retry = initialize_runtime_store_with(
            directory.path(),
            valid_input(),
            &mut retry_entropy,
            RuntimeInitializerPreflight::open_fixture,
        );
        let retry_error = retry.expect_err("one-shot initialization must not retry");
        assert!(matches!(
            retry_error,
            RuntimeInitializationError::Begin(RuntimeInitializerBeginError::MarkerConsumed(_))
        ));
        assert!(retry_error.requires_recovery());
        assert_eq!(retry_entropy.store_calls, 0);
        assert_eq!(retry_entropy.temp_calls, 0);
        assert_eq!(
            fs::read(directory.path().join("runtime.snapshot"))
                .unwrap_or_else(|error| panic!("active retry read failed: {error}")),
            before
        );
    }
}
