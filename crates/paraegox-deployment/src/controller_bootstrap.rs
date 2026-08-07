//! Controller owner facade for authenticated Runtime bootstrap and durable pinning.
//!
//! This module is the only bridge from Controller journal truth to the local
//! Runtime bootstrap client. It never rereads an installer manifest, accepts
//! caller-constructed compatibility fields, persists a live inode/pid channel
//! digest as stable policy, or treats transport completion as a target binding.

use core::fmt;
use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::PrincipalRef;
use paraegox_runtime_contracts::provenance::SourceScopeRef;
use paraegox_runtime_contracts::reference_control::{
    MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES, ReferenceAdmissionPolicyFingerprintV1,
    ReferenceBootstrapChannelPolicyInputV1, ReferenceBootstrapRequestDraftV1,
    ReferenceBootstrapRequestIdV1, ReferenceBootstrapResponseV1, ReferenceChannelBindingV1,
    ReferenceControlError, ReferenceControllerBootstrapExpectationV1,
    ed25519_control_key_fingerprint, reference_bootstrap_channel_policy_fingerprint_v1,
    reference_developer_local_bootstrap_channel_policy_fingerprint_v1,
};
use paraegox_runtime_contracts::wire::ApplyRequestAuthClaim;

use crate::controller_journal::{
    ControllerBootstrapResponseDigest, ControllerChannelAuthFingerprint, ControllerJournalError,
    ControllerJournalSnapshot, ControllerOwnerIdentityFingerprint,
    ControllerRuntimeResponseAuthPin, ControllerTargetBinding, ControllerTargetBindingInput,
};
use crate::controller_store::{ControllerStore, ControllerStoreError};
use crate::planner::PlanManifestDigest;
use crate::runtime_control_client::{
    PreparedRuntimeBootstrapRequest, RuntimeBootstrapExchangeError, RuntimeBootstrapRequestAuthPin,
    RuntimeBootstrapResponseVerifier, RuntimeBootstrapServingExpectation,
    RuntimeControlClientConfigurationError, RuntimeControlSocketAcl, RuntimeUnixCredentials,
    UnixRuntimeBootstrapClient, UnixRuntimeControlEndpoint, ValidatedRuntimeBootstrapResponse,
};

const ED25519_PUBLIC_KEY_BYTES: usize = 32;

/// Fresh request identity used only when no durable response can reconstruct
/// the exact prior request. Bootstrap is read-only, so a crash before the
/// binding commit may safely allocate another fresh request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreshControllerBootstrapRequestV1 {
    request_id: [u8; 16],
    client_nonce: [u8; 32],
}

impl FreshControllerBootstrapRequestV1 {
    pub(crate) fn try_new(
        request_id: [u8; 16],
        client_nonce: [u8; 32],
    ) -> Result<Self, ControllerBootstrapError> {
        if bytes_are_zero(&request_id) || bytes_are_zero(&client_nonce) {
            return Err(ControllerBootstrapError::InvalidProvisioning);
        }
        Ok(Self {
            request_id,
            client_nonce,
        })
    }
}

/// Protected Runtime/Controller provisioning facts not owned by the journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerBootstrapProvisioningV1 {
    socket_path: PathBuf,
    controller_principal: PrincipalRef,
    runtime_principal: PrincipalRef,
    response_key_ref: paraegox_runtime_contracts::wire::ApplyAuthKeyRef,
    response_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    runtime_uid: u32,
    runtime_gid: u32,
    controller_uid: u32,
    controller_gid: u32,
    admission_policy: ReferenceAdmissionPolicyFingerprintV1,
    exchange_timeout: Duration,
    developer_local: bool,
}

impl ControllerBootstrapProvisioningV1 {
    #[allow(clippy::too_many_arguments)] // GOV-WAIVER-0011
    pub(crate) fn try_new(
        socket_path: PathBuf,
        controller_principal: PrincipalRef,
        runtime_principal: PrincipalRef,
        response_key_ref: paraegox_runtime_contracts::wire::ApplyAuthKeyRef,
        response_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
        runtime_uid: u32,
        runtime_gid: u32,
        controller_uid: u32,
        controller_gid: u32,
        admission_policy: ReferenceAdmissionPolicyFingerprintV1,
        exchange_timeout: Duration,
    ) -> Result<Self, ControllerBootstrapError> {
        if bytes_are_zero(controller_principal.as_bytes())
            || bytes_are_zero(runtime_principal.as_bytes())
            || bytes_are_zero(response_key_ref.as_bytes())
            || bytes_are_zero(&response_public_key)
            || runtime_uid == 0
            || runtime_gid == 0
            || controller_uid == 0
            || controller_gid == 0
            || runtime_uid == controller_uid
            || exchange_timeout.is_zero()
        {
            return Err(ControllerBootstrapError::InvalidProvisioning);
        }
        Ok(Self {
            socket_path,
            controller_principal,
            runtime_principal,
            response_key_ref,
            response_public_key,
            runtime_uid,
            runtime_gid,
            controller_uid,
            controller_gid,
            admission_policy,
            exchange_timeout,
            developer_local: false,
        })
    }

    #[allow(clippy::too_many_arguments)] // GOV-WAIVER-0011
    pub(crate) fn try_new_developer_local(
        socket_path: PathBuf,
        controller_principal: PrincipalRef,
        runtime_principal: PrincipalRef,
        response_key_ref: paraegox_runtime_contracts::wire::ApplyAuthKeyRef,
        response_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
        runtime_uid: u32,
        runtime_gid: u32,
        controller_uid: u32,
        controller_gid: u32,
        admission_policy: ReferenceAdmissionPolicyFingerprintV1,
        exchange_timeout: Duration,
    ) -> Result<Self, ControllerBootstrapError> {
        if bytes_are_zero(controller_principal.as_bytes())
            || bytes_are_zero(runtime_principal.as_bytes())
            || bytes_are_zero(response_key_ref.as_bytes())
            || bytes_are_zero(&response_public_key)
            || runtime_uid == 0
            || runtime_gid == 0
            || controller_uid == 0
            || controller_gid == 0
            || runtime_uid != controller_uid
            || runtime_gid != controller_gid
            || exchange_timeout.is_zero()
        {
            return Err(ControllerBootstrapError::InvalidProvisioning);
        }
        Ok(Self {
            socket_path,
            controller_principal,
            runtime_principal,
            response_key_ref,
            response_public_key,
            runtime_uid,
            runtime_gid,
            controller_uid,
            controller_gid,
            admission_policy,
            exchange_timeout,
            developer_local: true,
        })
    }
}

/// Narrow proof that authenticated bootstrap facts are durably journaled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerBootstrapReceiptV1 {
    controller_store_instance_id: [u8; 32],
    controller_snapshot_sequence: u64,
    target: paraegox_kernel::identity::RuntimeHostId,
    runtime_store_instance_id: [u8; 32],
    runtime_host_epoch: u64,
    channel_policy_fingerprint: Digest32,
    bootstrap_response_digest: Digest32,
    bootstrap_response: Box<[u8]>,
}

impl ControllerBootstrapReceiptV1 {
    #[must_use]
    pub(crate) const fn controller_store_instance_id(&self) -> &[u8; 32] {
        &self.controller_store_instance_id
    }

    #[must_use]
    pub(crate) const fn controller_snapshot_sequence(&self) -> u64 {
        self.controller_snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn target(&self) -> paraegox_kernel::identity::RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn runtime_store_instance_id(&self) -> &[u8; 32] {
        &self.runtime_store_instance_id
    }

    #[must_use]
    pub(crate) const fn runtime_host_epoch(&self) -> u64 {
        self.runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn channel_policy_fingerprint(&self) -> Digest32 {
        self.channel_policy_fingerprint
    }

    #[must_use]
    pub(crate) const fn bootstrap_response_digest(&self) -> Digest32 {
        self.bootstrap_response_digest
    }

    #[must_use]
    pub(crate) fn bootstrap_response(&self) -> &[u8] {
        &self.bootstrap_response
    }
}

/// Performs one authenticated bootstrap exchange and commits its exact result.
pub(crate) async fn bootstrap_runtime_v1(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    controller_signer: &SigningKey,
    provisioning: ControllerBootstrapProvisioningV1,
    fresh_request: FreshControllerBootstrapRequestV1,
) -> Result<ControllerBootstrapReceiptV1, ControllerBootstrapError> {
    let snapshot = store
        .snapshot()
        .map_err(ControllerBootstrapError::Store)?
        .clone();
    if snapshot.owner_identity_fingerprint() != expected_owner {
        return Err(ControllerBootstrapError::OwnerIdentityMismatch);
    }
    let state = snapshot.state();
    let request_auth = state.request_auth();
    validate_controller_signer(
        controller_signer,
        request_auth.verification_key_fingerprint(),
    )?;

    let target = state.installed_manifest().target();
    let source_scope = SourceScopeRef::from_bytes(*state.scope().as_bytes());
    let expectation = ReferenceControllerBootstrapExpectationV1::try_from_verified_manifest(
        state.installed_manifest().verified_manifest(),
        provisioning.admission_policy,
    )
    .map_err(ControllerBootstrapError::ControlContract)?;
    let controller_verification_key = controller_signer.verifying_key();
    let channel_policy_input = ReferenceBootstrapChannelPolicyInputV1 {
        canonical_socket_path: unix_path_bytes(&provisioning.socket_path),
        target,
        source_scope,
        controller_principal: provisioning.controller_principal,
        controller_key_ref: request_auth.key(),
        controller_public_key: controller_verification_key.as_bytes(),
        runtime_uid: provisioning.runtime_uid,
        runtime_gid: provisioning.runtime_gid,
        controller_uid: provisioning.controller_uid,
        controller_gid: provisioning.controller_gid,
        runtime_principal: provisioning.runtime_principal,
        response_key_ref: provisioning.response_key_ref,
        response_public_key: &provisioning.response_public_key,
    };
    let stable_channel_policy = if provisioning.developer_local {
        reference_developer_local_bootstrap_channel_policy_fingerprint_v1(channel_policy_input)
    } else {
        reference_bootstrap_channel_policy_fingerprint_v1(channel_policy_input)
    }
    .map_err(ControllerBootstrapError::ControlContract)?;

    let prepared = prepare_request(
        state,
        controller_signer,
        provisioning.controller_principal,
        source_scope,
        fresh_request,
        stable_channel_policy,
    )?;
    let serving_expectation = serving_expectation(state, stable_channel_policy)?;
    let endpoint = UnixRuntimeControlEndpoint::try_new(
        provisioning.socket_path,
        RuntimeControlSocketAcl::new(provisioning.runtime_uid, provisioning.controller_gid),
        RuntimeUnixCredentials::new(provisioning.runtime_uid, provisioning.runtime_gid),
        target,
        provisioning.runtime_principal,
    )
    .map_err(ControllerBootstrapError::ClientConfiguration)?;
    let request_pin = RuntimeBootstrapRequestAuthPin::try_new(
        provisioning.controller_principal,
        request_auth.key(),
        request_auth.algorithm(),
        request_auth.algorithm_version(),
    )
    .map_err(ControllerBootstrapError::ClientConfiguration)?;
    let response_key = VerifyingKey::from_bytes(&provisioning.response_public_key)
        .map_err(|_| ControllerBootstrapError::InvalidProvisioning)?;
    let response_key_fingerprint = ed25519_control_key_fingerprint(response_key.as_bytes())
        .map_err(ControllerBootstrapError::ControlContract)?;
    let response_verifier = RuntimeBootstrapResponseVerifier::try_new(
        provisioning.runtime_principal,
        provisioning.response_key_ref,
        request_auth.algorithm(),
        request_auth.algorithm_version(),
        response_key_fingerprint,
        response_key,
    )
    .map_err(ControllerBootstrapError::ClientConfiguration)?;
    let client = UnixRuntimeBootstrapClient::try_new(
        endpoint,
        request_pin,
        response_verifier,
        expectation,
        serving_expectation,
        provisioning.exchange_timeout,
    )
    .map_err(ControllerBootstrapError::ClientConfiguration)?;
    let validated = client
        .exchange(&prepared)
        .await
        .map_err(ControllerBootstrapError::Exchange)?;
    commit_validated_response(store, stable_channel_policy, &validated)
}

fn validate_controller_signer(
    signer: &SigningKey,
    expected: crate::controller_journal::ControllerAuthKeyFingerprint,
) -> Result<(), ControllerBootstrapError> {
    let verifying_key = signer.verifying_key();
    if verifying_key.is_weak() {
        return Err(ControllerBootstrapError::ControllerSigningKeyMismatch);
    }
    let fingerprint = ed25519_control_key_fingerprint(verifying_key.as_bytes())
        .map_err(ControllerBootstrapError::ControlContract)?;
    if fingerprint != expected.value() {
        return Err(ControllerBootstrapError::ControllerSigningKeyMismatch);
    }
    Ok(())
}

fn prepare_request(
    state: &crate::controller_journal::ControllerJournalState,
    signer: &SigningKey,
    controller_principal: PrincipalRef,
    source_scope: SourceScopeRef,
    fresh: FreshControllerBootstrapRequestV1,
    stable_channel_policy: Digest32,
) -> Result<PreparedRuntimeBootstrapRequest, ControllerBootstrapError> {
    let (request_id, client_nonce, expected_digest) = match state.target_binding() {
        Some(binding) => {
            validate_stored_binding(binding, state, stable_channel_policy)?;
            let response = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())
                .map_err(ControllerBootstrapError::ControlContract)?;
            (
                response.request_id(),
                response.client_nonce().to_vec(),
                Some(response.request_digest()),
            )
        }
        None => (
            ReferenceBootstrapRequestIdV1::from_bytes(fresh.request_id),
            fresh.client_nonce.to_vec(),
            None,
        ),
    };
    let request_auth = state.request_auth();
    let claim = ApplyRequestAuthClaim::try_new(
        controller_principal,
        request_auth.key(),
        request_auth.algorithm(),
        request_auth.algorithm_version(),
        &client_nonce,
    )
    .map_err(ControllerBootstrapError::WireContract)?;
    let draft = ReferenceBootstrapRequestDraftV1::try_new(
        request_id,
        state.installed_manifest().target(),
        source_scope,
        claim,
        MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES as u32,
    )
    .map_err(ControllerBootstrapError::ControlContract)?;
    let transcript = draft
        .signing_transcript()
        .map_err(ControllerBootstrapError::ControlContract)?;
    let signature = signer.sign(transcript.as_bytes());
    let request = draft
        .finalize(&signature.to_bytes())
        .map_err(ControllerBootstrapError::ControlContract)?;
    if expected_digest.is_some_and(|digest| request.request_digest() != digest) {
        return Err(ControllerBootstrapError::StoredRequestMismatch);
    }
    PreparedRuntimeBootstrapRequest::try_new(request)
        .map_err(ControllerBootstrapError::ControlContract)
}

fn serving_expectation(
    state: &crate::controller_journal::ControllerJournalState,
    stable_channel_policy: Digest32,
) -> Result<RuntimeBootstrapServingExpectation, ControllerBootstrapError> {
    let Some(binding) = state.target_binding() else {
        return Ok(RuntimeBootstrapServingExpectation::Initial);
    };
    validate_stored_binding(binding, state, stable_channel_policy)?;
    let response = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())
        .map_err(ControllerBootstrapError::ControlContract)?;
    let facts = response.facts();
    RuntimeBootstrapServingExpectation::try_pinned(
        binding.runtime_store_instance_id(),
        facts.snapshot_sequence(),
        binding.last_runtime_host_epoch(),
        facts.clock_domain(),
        facts.clock_generation(),
    )
    .map_err(ControllerBootstrapError::ClientConfiguration)
}

fn validate_stored_binding(
    binding: &ControllerTargetBinding,
    state: &crate::controller_journal::ControllerJournalState,
    stable_channel_policy: Digest32,
) -> Result<(), ControllerBootstrapError> {
    let response = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())
        .map_err(ControllerBootstrapError::ControlContract)?;
    let facts = response.facts();
    if response.response_digest() != binding.bootstrap_response_digest().value()
        || binding.target() != state.installed_manifest().target()
        || facts.target() != binding.target()
        || facts.runtime_store_instance_id() != binding.runtime_store_instance_id()
        || facts.runtime_host_epoch() != binding.last_runtime_host_epoch()
        || facts.manifest_digest() != binding.manifest_digest().value()
        || binding.channel_auth_fingerprint().value() != stable_channel_policy
    {
        return Err(ControllerBootstrapError::StoredBindingMismatch);
    }
    Ok(())
}

fn commit_validated_response(
    store: &mut ControllerStore,
    stable_channel_policy: Digest32,
    validated: &ValidatedRuntimeBootstrapResponse,
) -> Result<ControllerBootstrapReceiptV1, ControllerBootstrapError> {
    commit_validated_response_with(store, stable_channel_policy, validated, |store, next| {
        store.commit(next)
    })
}

fn commit_validated_response_with(
    store: &mut ControllerStore,
    stable_channel_policy: Digest32,
    validated: &ValidatedRuntimeBootstrapResponse,
    commit: impl FnOnce(
        &mut ControllerStore,
        ControllerJournalSnapshot,
    ) -> Result<(), ControllerStoreError>,
) -> Result<ControllerBootstrapReceiptV1, ControllerBootstrapError> {
    let current = store
        .snapshot()
        .map_err(ControllerBootstrapError::Store)?
        .clone();
    let facts = validated.facts();
    let response = validated.response();
    let next = target_binding_successor(
        &current,
        stable_channel_policy,
        response,
        facts,
        validated.channel(),
    )?;
    if next != current {
        commit(store, next).map_err(ControllerBootstrapError::Store)?;
    }
    receipt_from_snapshot(store.snapshot().map_err(ControllerBootstrapError::Store)?)
}

#[cfg(test)]
fn commit_validated_response_with_test_failpoint(
    store: &mut ControllerStore,
    stable_channel_policy: Digest32,
    validated: &ValidatedRuntimeBootstrapResponse,
    failpoint: crate::controller_store::ControllerCommitFailpoint,
) -> Result<ControllerBootstrapReceiptV1, ControllerBootstrapError> {
    commit_validated_response_with(store, stable_channel_policy, validated, |store, next| {
        store.commit_with_test_failpoint(next, failpoint)
    })
}

fn target_binding_successor(
    current: &ControllerJournalSnapshot,
    stable_channel_policy: Digest32,
    response: &ReferenceBootstrapResponseV1,
    facts: paraegox_runtime_contracts::reference_control::ReferenceBootstrapFactsV1,
    channel: ReferenceChannelBindingV1,
) -> Result<ControllerJournalSnapshot, ControllerBootstrapError> {
    let first_epoch = current
        .state()
        .target_binding()
        .map_or(facts.runtime_host_epoch(), |binding| {
            binding.first_runtime_host_epoch()
        });
    let binding = ControllerTargetBinding::try_new(ControllerTargetBindingInput {
        target: facts.target(),
        runtime_store_instance_id: facts.runtime_store_instance_id(),
        channel_auth_fingerprint: ControllerChannelAuthFingerprint::from_stored(
            stable_channel_policy,
        ),
        manifest_digest: PlanManifestDigest::try_new(facts.manifest_digest())
            .map_err(|_| ControllerBootstrapError::InvalidValidatedResponse)?,
        first_runtime_host_epoch: first_epoch,
        last_runtime_host_epoch: facts.runtime_host_epoch(),
        bootstrap_response: response.canonical_wire(),
        bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(
            response.response_digest(),
        ),
        runtime_response_auth: ControllerRuntimeResponseAuthPin::try_from_bootstrap_response(
            response, channel,
        )
        .map_err(ControllerBootstrapError::Journal)?,
    })
    .map_err(ControllerBootstrapError::Journal)?;
    let next_state = current
        .state()
        .record_target_binding(binding)
        .map_err(ControllerBootstrapError::Journal)?;
    if &next_state == current.state() {
        Ok(current.clone())
    } else {
        current
            .try_successor(next_state)
            .map_err(ControllerBootstrapError::Journal)
    }
}

fn receipt_from_snapshot(
    snapshot: &ControllerJournalSnapshot,
) -> Result<ControllerBootstrapReceiptV1, ControllerBootstrapError> {
    let binding = snapshot
        .state()
        .target_binding()
        .ok_or(ControllerBootstrapError::StoredBindingMismatch)?;
    validate_stored_binding(
        binding,
        snapshot.state(),
        binding.channel_auth_fingerprint().value(),
    )?;
    Ok(ControllerBootstrapReceiptV1 {
        controller_store_instance_id: *snapshot.store_instance_id(),
        controller_snapshot_sequence: snapshot.snapshot_sequence(),
        target: binding.target(),
        runtime_store_instance_id: binding.runtime_store_instance_id(),
        runtime_host_epoch: binding.last_runtime_host_epoch(),
        channel_policy_fingerprint: binding.channel_auth_fingerprint().value(),
        bootstrap_response_digest: binding.bootstrap_response_digest().value(),
        bootstrap_response: binding.bootstrap_response().into(),
    })
}

#[cfg(unix)]
fn unix_path_bytes(path: &std::path::Path) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes()
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[derive(Debug)]
pub(crate) enum ControllerBootstrapError {
    InvalidProvisioning,
    OwnerIdentityMismatch,
    ControllerSigningKeyMismatch,
    StoredRequestMismatch,
    StoredBindingMismatch,
    InvalidValidatedResponse,
    WireContract(paraegox_runtime_contracts::wire::ApplyAuthError),
    ControlContract(ReferenceControlError),
    ClientConfiguration(RuntimeControlClientConfigurationError),
    Exchange(RuntimeBootstrapExchangeError),
    Journal(ControllerJournalError),
    Store(ControllerStoreError),
}

impl fmt::Display for ControllerBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller bootstrap failed closed: {self:?}")
    }
}

impl std::error::Error for ControllerBootstrapError {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::apply::{PlanWriterRef, TenureAuthorityRef, TenureKeyRef};
    use paraegox_runtime_contracts::execution::{CardDefinitionRef, CardImplementationRef};
    use paraegox_runtime_contracts::installation::{
        InstalledRuntimeArtifactObservationV1, RuntimeCompiledInstallationFactsV1,
        VerifiedRuntimeInstallationV1, generate_build_descriptor, generate_manifest,
    };
    use paraegox_runtime_contracts::provenance::SourceScopeRef;
    use paraegox_runtime_contracts::reference_control::{
        ReferenceAdmissionPolicyInputV1, ReferenceBootstrapCompatibilityV1,
        ReferenceBootstrapFactsV1, ReferenceBootstrapResponseAuthClaimV1,
        ReferenceBootstrapResponseDraftV1, ReferenceBootstrapResponseV1,
        ReferenceBootstrapServingIdentityV1, ReferenceBootstrapStateV1, ReferenceChannelBindingV1,
        ed25519_control_key_fingerprint, reference_admission_policy_fingerprint_v1,
    };
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

    use crate::controller_journal::{
        ControllerAuthKeyFingerprint, ControllerJournalSnapshot, ControllerOperationId,
        ControllerOwnerIdentityFingerprint, ControllerRequestAuthPin, controller_test_manifest,
    };
    use crate::controller_store::{
        ControllerCommitFailpoint, ControllerFilesystemPolicy, ControllerStore,
        create_and_lock_controller_initializer_lock, ensure_fresh_controller_directory,
        open_controller_directory, publish_initial_controller_snapshot,
    };
    use crate::plan::{DeploymentId, DeploymentScopeId};
    use crate::planner::{StableAllocationSnapshot, journal_test_candidate};
    use crate::runtime_control_client::ValidatedRuntimeBootstrapResponse;

    use super::{
        FreshControllerBootstrapRequestV1, commit_validated_response,
        commit_validated_response_with_test_failpoint, prepare_request, target_binding_successor,
    };

    const TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x61; 16]);
    const SCOPE: DeploymentScopeId = DeploymentScopeId::from_bytes([0x21; 16]);
    const PLAN: DeploymentId = DeploymentId::from_bytes([0x22; 16]);
    const CONTROLLER_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x31; 16]);
    const CONTROLLER_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x32; 16]);
    const RUNTIME_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x41; 16]);
    const RESPONSE_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x42; 16]);
    const STABLE_CHANNEL_POLICY: Digest32 = Digest32::from_bytes([0x51; 32]);
    const RUNTIME_STORE: [u8; 32] = [0x52; 32];
    const CLOCK_DOMAIN: ClockDomainRef = ClockDomainRef::from_bytes([0x53; 16]);
    const CONTROLLER_SEED: [u8; 32] = [0x54; 32];
    const RUNTIME_SEED: [u8; 32] = [0x55; 32];
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().canonicalize().expect("temp root");
            let path = root.join(format!(
                "paraegox-controller-bootstrap-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create fixture directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("chmod fixture directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn committed_snapshot() -> ControllerJournalSnapshot {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let fingerprint = ed25519_control_key_fingerprint(controller.verifying_key().as_bytes())
            .expect("Controller key fingerprint");
        let request_auth = ControllerRequestAuthPin::try_new(
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("request algorithm"),
            1,
            ControllerAuthKeyFingerprint::from_stored(fingerprint),
            1,
        )
        .expect("request auth pin");
        let allocation =
            StableAllocationSnapshot::try_new(TARGET, 0, 0, Vec::new()).expect("empty allocation");
        let state = crate::controller_journal::ControllerJournalState::try_initialize(
            SCOPE,
            PLAN,
            allocation,
            controller_test_manifest(TARGET),
            request_auth,
        )
        .expect("initial state");
        let initial = ControllerJournalSnapshot::try_initialize(
            [0x91; 32],
            ControllerOwnerIdentityFingerprint::from_stored(Digest32::from_bytes([0x92; 32])),
            state,
        )
        .expect("initial snapshot");
        let candidate = journal_test_candidate(
            TARGET,
            initial.state().installed_manifest().projection(),
            initial.state().allocation(),
            Some([0x93; 16]),
            0x94,
        )
        .expect("plan candidate");
        let operation = ControllerOperationId::from_bytes([0x95; 16]);
        let prepared_state = initial
            .state()
            .prepare_plan_candidate(operation, &candidate)
            .expect("prepare plan");
        let prepared = initial
            .try_successor(prepared_state)
            .expect("prepared successor");
        let committed_state = prepared
            .state()
            .commit_plan_candidate(operation, &candidate)
            .expect("commit plan");
        prepared
            .try_successor(committed_state)
            .expect("committed successor")
    }

    fn install_snapshot(snapshot: &ControllerJournalSnapshot, directory: &TestDirectory) {
        let handle = open_controller_directory(
            directory.path(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("open fixture directory");
        ensure_fresh_controller_directory(&handle).expect("fresh fixture directory");
        let _lock = create_and_lock_controller_initializer_lock(&handle)
            .expect("create fixture initializer lock");
        let encoded = snapshot.encode().expect("encode fixture snapshot");
        publish_initial_controller_snapshot(
            &handle,
            &encoded,
            [0x96; 16],
            ControllerCommitFailpoint::None,
        )
        .expect("publish fixture snapshot");
    }

    fn open_snapshot(
        snapshot: &ControllerJournalSnapshot,
        directory: &TestDirectory,
    ) -> ControllerStore {
        ControllerStore::open_with_policy(
            directory.path(),
            *snapshot.store_instance_id(),
            snapshot.owner_identity_fingerprint(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("open fixture store")
    }

    fn installation() -> (
        VerifiedRuntimeInstallationV1,
        RuntimeCompiledInstallationFactsV1,
    ) {
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            Digest32::from_bytes([0x22; 32]),
            "aarch64-unknown-linux-gnu",
        )
        .expect("artifact");
        let compiled = RuntimeCompiledInstallationFactsV1::try_new(
            [0x11; 32],
            CardDefinitionRef::from_bytes([0xa1; 16]),
            CardImplementationRef::from_bytes([0xa2; 16]),
            [0xa3; 16],
            Digest32::from_bytes([0xa4; 32]),
            Digest32::from_bytes([0xa5; 32]),
        )
        .expect("compiled facts");
        let descriptor = generate_build_descriptor(&artifact, compiled).expect("descriptor");
        let installation = generate_manifest(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            TARGET,
            &artifact,
            compiled,
        )
        .expect("installation");
        (installation, compiled)
    }

    fn admission_policy(controller: &SigningKey) -> Digest32 {
        reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
            target: TARGET,
            source_scope: SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            writer: PlanWriterRef::from_bytes([0x63; 16]),
            controller_principal: CONTROLLER_PRINCIPAL,
            controller_key_ref: CONTROLLER_KEY_REF,
            controller_public_key: controller.verifying_key().as_bytes(),
            authority_principal: PrincipalRef::from_bytes([0x64; 16]),
            authority_uid: 3_001,
            authority_gid: 3_002,
            tenure_authority_ref: TenureAuthorityRef::from_bytes([0x65; 16]),
            tenure_key_ref: TenureKeyRef::from_bytes([0x66; 16]),
            tenure_public_key: &[0x67; 32],
        })
        .expect("admission policy")
        .digest()
    }

    fn signed_response(
        request: &paraegox_runtime_contracts::reference_control::ReferenceBootstrapRequestV1,
        runtime_host_epoch: u64,
    ) -> (
        ReferenceBootstrapResponseV1,
        ReferenceBootstrapFactsV1,
        ReferenceChannelBindingV1,
    ) {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let runtime = SigningKey::from_bytes(&RUNTIME_SEED);
        let (installation, compiled) = installation();
        let compatibility = ReferenceBootstrapCompatibilityV1::try_from_verified_installation(
            &installation,
            compiled,
            admission_policy(&controller),
        )
        .expect("compatibility");
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            RUNTIME_STORE,
            runtime_host_epoch + 10,
            runtime_host_epoch,
            CLOCK_DOMAIN,
            ClockGeneration::try_new(1).expect("clock generation"),
        )
        .expect("serving identity");
        let facts = ReferenceBootstrapFactsV1::try_new(
            serving,
            &compatibility,
            ReferenceBootstrapStateV1::ReadyForApply,
            None,
        )
        .expect("bootstrap facts");
        let channel = ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            Digest32::from_bytes([0x68; 32]),
            Digest32::from_bytes([0x69; 32]),
        )
        .expect("channel");
        let claim = ReferenceBootstrapResponseAuthClaimV1::try_new(
            channel,
            RESPONSE_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("response algorithm"),
            1,
        )
        .expect("response claim");
        let draft = ReferenceBootstrapResponseDraftV1::try_new(request, facts, channel, claim)
            .expect("response draft");
        let signature = runtime.sign(
            draft
                .signing_transcript()
                .expect("response transcript")
                .as_bytes(),
        );
        let response = draft
            .finalize(&signature.to_bytes())
            .expect("signed response");
        (response, facts, channel)
    }

    fn fresh(byte: u8) -> FreshControllerBootstrapRequestV1 {
        FreshControllerBootstrapRequestV1::try_new([byte; 16], [byte.wrapping_add(1); 32])
            .expect("fresh request")
    }

    #[test]
    fn binding_publish_is_idempotent_and_reconstructs_the_exact_request_after_decode() {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let committed = committed_snapshot();
        let first_request = prepare_request(
            committed.state(),
            &controller,
            CONTROLLER_PRINCIPAL,
            SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            fresh(0x71),
            STABLE_CHANNEL_POLICY,
        )
        .expect("first request");
        let (response, facts, channel) = signed_response(first_request.request(), 2);
        let bound =
            target_binding_successor(&committed, STABLE_CHANNEL_POLICY, &response, facts, channel)
                .expect("binding successor");
        assert_eq!(bound.snapshot_sequence(), committed.snapshot_sequence() + 1);
        assert_eq!(
            target_binding_successor(&bound, STABLE_CHANNEL_POLICY, &response, facts, channel,)
                .expect("exact replay"),
            bound
        );

        let encoded = bound.encode().expect("encoded bound snapshot");
        let recovered = ControllerJournalSnapshot::decode(&encoded).expect("decoded snapshot");
        let replay = prepare_request(
            recovered.state(),
            &controller,
            CONTROLLER_PRINCIPAL,
            SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            fresh(0x81),
            STABLE_CHANNEL_POLICY,
        )
        .expect("reconstructed request");
        assert_eq!(
            replay.request().canonical_wire(),
            first_request.request().canonical_wire()
        );
        assert_eq!(
            replay.transport_frame_bytes(),
            first_request.transport_frame_bytes()
        );
    }

    #[test]
    fn later_runtime_epoch_preserves_first_epoch_and_advances_one_snapshot() {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let committed = committed_snapshot();
        let request = prepare_request(
            committed.state(),
            &controller,
            CONTROLLER_PRINCIPAL,
            SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            fresh(0x91),
            STABLE_CHANNEL_POLICY,
        )
        .expect("request");
        let (first_response, first_facts, first_channel) = signed_response(request.request(), 2);
        let first = target_binding_successor(
            &committed,
            STABLE_CHANNEL_POLICY,
            &first_response,
            first_facts,
            first_channel,
        )
        .expect("first binding");
        let replay = prepare_request(
            first.state(),
            &controller,
            CONTROLLER_PRINCIPAL,
            SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            fresh(0xa1),
            STABLE_CHANNEL_POLICY,
        )
        .expect("replayed request");
        let (advanced_response, advanced_facts, advanced_channel) =
            signed_response(replay.request(), 3);
        let advanced = target_binding_successor(
            &first,
            STABLE_CHANNEL_POLICY,
            &advanced_response,
            advanced_facts,
            advanced_channel,
        )
        .expect("advanced binding");
        let binding = advanced.state().target_binding().expect("stored binding");
        assert_eq!(advanced.snapshot_sequence(), first.snapshot_sequence() + 1);
        assert_eq!(binding.first_runtime_host_epoch(), 2);
        assert_eq!(binding.last_runtime_host_epoch(), 3);
    }

    #[test]
    fn durable_publish_reopens_and_strictly_reconstructs_response_and_request() {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let committed = committed_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&committed, &directory);
        let mut store = open_snapshot(&committed, &directory);
        let request = prepare_request(
            store.snapshot().expect("store snapshot").state(),
            &controller,
            CONTROLLER_PRINCIPAL,
            SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            fresh(0xb1),
            STABLE_CHANNEL_POLICY,
        )
        .expect("request");
        let exact_request = request.request().canonical_wire().to_vec();
        let (response, facts, channel) = signed_response(request.request(), 2);
        let exact_response = response.canonical_wire().to_vec();
        let validated =
            ValidatedRuntimeBootstrapResponse::try_from_contract_fixture(response, facts, channel)
                .expect("validated fixture response");
        let receipt = commit_validated_response(&mut store, STABLE_CHANNEL_POLICY, &validated)
            .expect("durable receipt");
        assert_eq!(
            receipt.controller_snapshot_sequence(),
            committed.snapshot_sequence() + 1
        );
        drop(store);

        let reopened = open_snapshot(&committed, &directory);
        let recovered = reopened.snapshot().expect("reopened snapshot");
        assert_eq!(
            recovered
                .state()
                .target_binding()
                .expect("durable target binding")
                .bootstrap_response(),
            exact_response
        );
        let replay = prepare_request(
            recovered.state(),
            &controller,
            CONTROLLER_PRINCIPAL,
            SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            fresh(0xc1),
            STABLE_CHANNEL_POLICY,
        )
        .expect("strict durable reconstruction");
        assert_eq!(replay.request().canonical_wire(), exact_request);
    }

    #[test]
    fn uncertain_publish_returns_no_receipt_and_requires_reopen() {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let committed = committed_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&committed, &directory);
        let mut store = open_snapshot(&committed, &directory);
        let request = prepare_request(
            store.snapshot().expect("store snapshot").state(),
            &controller,
            CONTROLLER_PRINCIPAL,
            SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            fresh(0xd1),
            STABLE_CHANNEL_POLICY,
        )
        .expect("request");
        let (response, facts, channel) = signed_response(request.request(), 2);
        let validated =
            ValidatedRuntimeBootstrapResponse::try_from_contract_fixture(response, facts, channel)
                .expect("validated fixture response");
        assert!(
            commit_validated_response_with_test_failpoint(
                &mut store,
                STABLE_CHANNEL_POLICY,
                &validated,
                ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn,
            )
            .is_err(),
            "an uncertain publish must never return a success receipt"
        );
        assert!(store.snapshot().is_err(), "uncertain store must stop");
        drop(store);

        let reopened = open_snapshot(&committed, &directory);
        assert!(
            reopened
                .snapshot()
                .expect("authoritative reopened snapshot")
                .state()
                .target_binding()
                .is_some(),
            "after-directory-sync ambiguity is resolved only by reopening disk truth"
        );
    }
}
