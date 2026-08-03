//! Internal S7-D DeploymentController journal codec and pure state validator.
//!
//! This module owns no filesystem, signing key, endpoint, retry loop, or live
//! Controller process. It persists only Planner-owned allocation/plan values
//! and forces every durable mutation through an explicit predecessor check.
//! S7-F query requests and responses use only the canonical PXQR/PXQS owner;
//! the journal persists each request before transport and each authenticated
//! response before any rollout decision.

use core::fmt;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{ClockDomainRef, ClockGeneration};
use paraegox_runtime_contracts::apply::{ApplyOperationId, PlanWriterRef, WriterTenureProof};
use paraegox_runtime_contracts::installation::MAX_INSTALLED_RUNTIME_MANIFEST_BYTES;
use paraegox_runtime_contracts::provenance::{
    SourcePlanDigest, SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetSliceDigest,
};
use paraegox_runtime_contracts::reference_control::{
    MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES, MAX_REFERENCE_QUERY_REQUEST_BYTES,
    MAX_REFERENCE_QUERY_RESPONSE_BYTES, ReferenceApplyRequestV1, ReferenceApplyTerminalHeadV1,
    ReferenceApplyTerminalLifecycleEffectV1, ReferenceApplyTerminalOutcomeV1,
    ReferenceApplyTerminalReceiptV1, ReferenceAssemblyModeV1, ReferenceBootstrapResponseV1,
    ReferenceBootstrapServingIdentityV1, ReferenceChannelBindingV1, ReferenceControlError,
    ReferenceQueryDesiredHeadV1, ReferenceQueryDurablePhaseV1, ReferenceQueryIdV1,
    ReferenceQueryLiveStateV1, ReferenceQueryOperationLookupV1, ReferenceQueryOwnerStateV1,
    ReferenceQueryRequestV1, ReferenceQueryResponseV1,
};
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

use crate::manifest_ingress::ControllerInstalledManifestPin;
use crate::plan::{DeploymentId, DeploymentRevision, DeploymentScopeId};
use crate::planner::{
    AllocationState, DeploymentPlanCandidate, PlanContent, PlanContentDigest, PlanManifestDigest,
    StableAllocationDelta, StableAllocationRecord, StableAllocationSnapshot, TargetIntent,
};
use crate::tenure_protocol::{
    AcquireTenureOperationId, AcquireTenureProtocolError, AcquireTenureRequestV1,
    AcquireTenureResponseV1, MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES,
    MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES, MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
};

const JOURNAL_MAGIC: &[u8; 4] = b"PXJR";
const JOURNAL_ENVELOPE_VERSION: u16 = 1;
const CONTROLLER_OWNER_KIND: u16 = 1;
// Payload v7 retained only an opaque query response after transport. It could
// not prove that the exact canonical PXQR and its request-time channel, Runtime
// response key, store, host epoch, and clock baseline were durable before the
// first send. The exact request -> response -> decision split makes v8 a strict
// successor with no older fallback.
pub(crate) const CONTROLLER_PAYLOAD_VERSION: u16 = 8;
const CONTROLLER_LEGACY_PAYLOAD_VERSION: u16 = 7;
const CHECKSUM_ALGORITHM_SHA256: u16 = 1;
const CHECKSUM_VERSION: u16 = 1;
const CONTROLLER_PAYLOAD_MAGIC: &[u8; 4] = b"PXCP";
const CONTROLLER_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.deployment.controller-journal.checksum.sha256.v1";
const CONTROLLER_PLAN_CONTENT_INTEGRITY_DOMAIN: &[u8] =
    b"paraegox.deployment.controller-journal.plan-content-integrity.sha256.v1";
const DEPLOYMENT_PLAN_DIGEST_DOMAIN: &[u8] = b"paraegox.deployment.committed-plan.sha256.v1";
const PLAN_COMMIT_INTENT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.deployment.controller-plan-commit-intent.sha256.v1";

const JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES: usize =
    4 + (5 * size_of::<u16>()) + 32 + 32 + (2 * size_of::<u64>());
const JOURNAL_HEADER_BYTES: usize = JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES + 32;
pub(crate) const MAX_CONTROLLER_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ALLOCATION_RECORDS: usize = 4_096;
const MAX_CONTROLLER_LEDGER_RECORDS: usize = 256;
const MAX_CONTROLLER_OPERATIONS: usize = MAX_CONTROLLER_LEDGER_RECORDS;
const MAX_CONTROLLER_TENURE_TRANSACTIONS: usize = 256;
// Every archived rollout requires a later retained committed plan operation.
// With one current rollout, the largest reachable split is therefore
// 128 committed plan operations + 127 archives + 1 current = 256.
const MAX_APPLY_OPERATION_HISTORY: usize = (MAX_CONTROLLER_LEDGER_RECORDS - 1) / 2;
const MAX_RECONCILE_ATTEMPTS: usize = 256;
const MAX_PLAN_CONTENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_BOOTSTRAP_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_SIGNED_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const QUERY_CHANNEL_BINDING_BYTES: usize = 16 + 16 + 32 + 32;
const QUERY_SERVING_BASELINE_BYTES: usize = 16 + 32 + 8 + 8 + 16 + 8;
const RUNTIME_RESPONSE_AUTH_PIN_BYTES: usize = 32 + 16 + 32 + 32 + 16 + 2 + 2;
const REFERENCE_RESPONSE_AUTH_ALGORITHM_ED25519: u16 = 1;
const REFERENCE_RESPONSE_AUTH_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub(crate) struct $name([u8; 16]);

        impl $name {
            #[must_use]
            pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

macro_rules! opaque_digest {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub(crate) struct $name(Digest32);

        impl $name {
            #[must_use]
            pub(crate) const fn from_stored(value: Digest32) -> Self {
                Self(value)
            }

            #[must_use]
            pub(crate) const fn value(self) -> Digest32 {
                self.0
            }
        }
    };
}

opaque_id!(ControllerOperationId);
opaque_id!(ControllerReceiptRef);
opaque_digest!(ControllerPlanCommitIntentDigest);
opaque_digest!(ControllerPlanContentStorageChecksum);
opaque_digest!(ControllerApplyRequestDigest);
opaque_digest!(ControllerAuthKeyFingerprint);
opaque_digest!(ControllerChannelAuthFingerprint);
opaque_digest!(ControllerBootstrapResponseDigest);
opaque_digest!(ControllerOwnerIdentityFingerprint);
opaque_digest!(ControllerTenureAuthorityDomainFingerprint);

/// Exact committed plan plus its Controller-local operation cross-reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerCommittedPlan {
    scope: DeploymentScopeId,
    plan: DeploymentId,
    revision: DeploymentRevision,
    target: RuntimeHostId,
    content: PlanContent,
    plan_content_digest: PlanContentDigest,
    deployment_plan_digest: SourcePlanDigest,
    storage_content_checksum: ControllerPlanContentStorageChecksum,
    commit_operation: ControllerOperationId,
    commit_intent_digest: ControllerPlanCommitIntentDigest,
}

struct ControllerStoredCommittedPlanInput<'a> {
    scope: DeploymentScopeId,
    plan: DeploymentId,
    revision: DeploymentRevision,
    target: RuntimeHostId,
    content: &'a [u8],
    plan_content_digest: PlanContentDigest,
    deployment_plan_digest: SourcePlanDigest,
    storage_content_checksum: ControllerPlanContentStorageChecksum,
    commit_operation: ControllerOperationId,
    commit_intent_digest: ControllerPlanCommitIntentDigest,
}

impl ControllerCommittedPlan {
    fn try_from_candidate(
        scope: DeploymentScopeId,
        plan: DeploymentId,
        revision: DeploymentRevision,
        commit_operation: ControllerOperationId,
        commit_intent_digest: ControllerPlanCommitIntentDigest,
        candidate: &DeploymentPlanCandidate,
    ) -> Result<Self, ControllerJournalError> {
        if bytes_are_zero(scope.as_bytes())
            || bytes_are_zero(plan.as_bytes())
            || revision.value() == 0
            || bytes_are_zero(commit_operation.as_bytes())
            || bytes_are_zero(commit_intent_digest.value().as_bytes())
        {
            return Err(ControllerJournalError::InvalidPlanIdentity);
        }
        validate_plan_content_size(candidate.content().canonical_bytes())?;
        let plan_content_digest = PlanContentDigest::try_for_content(candidate.content())
            .map_err(|_| ControllerJournalError::InvalidPlanContent)?;
        if plan_content_digest != candidate.content_digest() {
            return Err(ControllerJournalError::PlanContentDigestMismatch);
        }
        let deployment_plan_digest = deployment_plan_digest(
            scope,
            plan,
            revision,
            candidate.content(),
            plan_content_digest,
        )?;
        Ok(Self {
            scope,
            plan,
            revision,
            target: candidate.content().target(),
            content: candidate.content().clone(),
            plan_content_digest,
            deployment_plan_digest,
            storage_content_checksum: plan_content_storage_checksum(
                candidate.content().canonical_bytes(),
            )?,
            commit_operation,
            commit_intent_digest,
        })
    }

    fn try_from_stored(
        input: ControllerStoredCommittedPlanInput<'_>,
    ) -> Result<Self, ControllerJournalError> {
        if bytes_are_zero(input.scope.as_bytes())
            || bytes_are_zero(input.plan.as_bytes())
            || bytes_are_zero(input.target.as_bytes())
            || input.revision.value() == 0
            || bytes_are_zero(input.commit_operation.as_bytes())
            || bytes_are_zero(input.commit_intent_digest.value().as_bytes())
        {
            return Err(ControllerJournalError::InvalidPlanIdentity);
        }
        validate_plan_content_size(input.content)?;
        let content = PlanContent::try_from_persisted(input.target, input.content)
            .map_err(|_| ControllerJournalError::InvalidPlanContent)?;
        let expected_content_digest = PlanContentDigest::try_for_content(&content)
            .map_err(|_| ControllerJournalError::InvalidPlanContent)?;
        if expected_content_digest != input.plan_content_digest {
            return Err(ControllerJournalError::PlanContentDigestMismatch);
        }
        if plan_content_storage_checksum(content.canonical_bytes())?
            != input.storage_content_checksum
        {
            return Err(ControllerJournalError::PlanContentStorageChecksumMismatch);
        }
        let expected_plan_digest = deployment_plan_digest(
            input.scope,
            input.plan,
            input.revision,
            &content,
            input.plan_content_digest,
        )?;
        if expected_plan_digest != input.deployment_plan_digest {
            return Err(ControllerJournalError::DeploymentPlanDigestMismatch);
        }
        Ok(Self {
            scope: input.scope,
            plan: input.plan,
            revision: input.revision,
            target: input.target,
            content,
            plan_content_digest: input.plan_content_digest,
            deployment_plan_digest: input.deployment_plan_digest,
            storage_content_checksum: input.storage_content_checksum,
            commit_operation: input.commit_operation,
            commit_intent_digest: input.commit_intent_digest,
        })
    }

    #[must_use]
    pub(crate) const fn scope(&self) -> DeploymentScopeId {
        self.scope
    }

    #[must_use]
    pub(crate) const fn plan(&self) -> DeploymentId {
        self.plan
    }

    #[must_use]
    pub(crate) const fn revision(&self) -> DeploymentRevision {
        self.revision
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn content(&self) -> &PlanContent {
        &self.content
    }

    #[must_use]
    pub(crate) const fn deployment_plan_digest(&self) -> SourcePlanDigest {
        self.deployment_plan_digest
    }

    /// Returns the exact Controller operation which committed this plan.
    ///
    /// This is intentionally only a read of the already-validated current
    /// plan cross-reference. It does not expose the operation ledger or permit
    /// callers to construct a plan transition.
    #[must_use]
    pub(crate) const fn commit_operation(&self) -> ControllerOperationId {
        self.commit_operation
    }
}

/// Durable phase of one Controller-local operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ControllerOperationPhase {
    Prepared = 1,
    Committed = 2,
    Uncertain = 3,
    Terminal = 4,
}

impl ControllerOperationPhase {
    fn decode(value: u8) -> Result<Self, ControllerJournalError> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Committed),
            3 => Ok(Self::Uncertain),
            4 => Ok(Self::Terminal),
            _ => Err(ControllerJournalError::UnknownEnum),
        }
    }

    const fn permits(self, next: Self) -> bool {
        match self {
            Self::Prepared => matches!(
                next,
                Self::Prepared | Self::Committed | Self::Uncertain | Self::Terminal
            ),
            Self::Committed => matches!(next, Self::Committed),
            Self::Uncertain => matches!(next, Self::Uncertain | Self::Terminal),
            Self::Terminal => matches!(next, Self::Terminal),
        }
    }
}

/// Bounded idempotency row for a Controller-local operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerOperationRecord {
    operation: ControllerOperationId,
    intent_digest: ControllerPlanCommitIntentDigest,
    expected_revision: u64,
    phase: ControllerOperationPhase,
    result: Option<ControllerReceiptRef>,
    committed_allocation_generation: Option<u64>,
    committed_plan_digest: Option<SourcePlanDigest>,
}

impl ControllerOperationRecord {
    fn try_new(
        operation: ControllerOperationId,
        intent_digest: ControllerPlanCommitIntentDigest,
        expected_revision: u64,
        phase: ControllerOperationPhase,
        result: Option<ControllerReceiptRef>,
        committed_allocation_generation: Option<u64>,
        committed_plan_digest: Option<SourcePlanDigest>,
    ) -> Result<Self, ControllerJournalError> {
        let value = Self {
            operation,
            intent_digest,
            expected_revision,
            phase,
            result,
            committed_allocation_generation,
            committed_plan_digest,
        };
        validate_operation(&value)?;
        Ok(value)
    }
}

/// Runtime-owned request-auth key and algorithm pinned independently of tenure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerRequestAuthPin {
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
    verification_key_fingerprint: ControllerAuthKeyFingerprint,
    rotation_generation: u64,
}

impl ControllerRequestAuthPin {
    pub(crate) fn try_new(
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
        verification_key_fingerprint: ControllerAuthKeyFingerprint,
        rotation_generation: u64,
    ) -> Result<Self, ControllerJournalError> {
        if bytes_are_zero(key.as_bytes())
            || algorithm_version == 0
            || bytes_are_zero(verification_key_fingerprint.value().as_bytes())
            || rotation_generation == 0
        {
            return Err(ControllerJournalError::InvalidAuthPin);
        }
        Ok(Self {
            key,
            algorithm,
            algorithm_version,
            verification_key_fingerprint,
            rotation_generation,
        })
    }

    #[must_use]
    pub(crate) const fn key(self) -> ApplyAuthKeyRef {
        self.key
    }

    #[must_use]
    pub(crate) const fn algorithm(self) -> ApplyAuthAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub(crate) const fn algorithm_version(self) -> u16 {
        self.algorithm_version
    }

    #[must_use]
    pub(crate) const fn verification_key_fingerprint(self) -> ControllerAuthKeyFingerprint {
        self.verification_key_fingerprint
    }
}

/// Authenticated Runtime response facts copied out of one exact bootstrap.
///
/// `ControllerTargetBinding` may advance to a newer Runtime host epoch.  Every
/// apply intent therefore retains the response facts that authenticated its
/// original request so an exact historical PXRT can still be verified after a
/// Runtime restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerRuntimeResponseAuthPin {
    bootstrap_response_digest: ControllerBootstrapResponseDigest,
    runtime_peer: PrincipalRef,
    local_endpoint_identity_digest: Digest32,
    peer_credentials_digest: Digest32,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

struct ControllerStoredRuntimeResponseAuthPinInput {
    bootstrap_response_digest: ControllerBootstrapResponseDigest,
    runtime_peer: PrincipalRef,
    local_endpoint_identity_digest: Digest32,
    peer_credentials_digest: Digest32,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

impl ControllerRuntimeResponseAuthPin {
    pub(crate) fn try_from_bootstrap_response(
        response: &ReferenceBootstrapResponseV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<Self, ControllerJournalError> {
        let decoded = ReferenceBootstrapResponseV1::decode(response.canonical_wire())?;
        if decoded != *response
            || response.authentication_runtime_peer() != channel.runtime_peer()
            || response.authentication_channel_binding_digest() != channel.binding_digest()
            || response.authentication_signature().len() != ED25519_SIGNATURE_BYTES
        {
            return Err(ControllerJournalError::InvalidRuntimeResponseAuthPin);
        }
        Self::try_from_stored(ControllerStoredRuntimeResponseAuthPinInput {
            bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(
                response.response_digest(),
            ),
            runtime_peer: channel.runtime_peer(),
            local_endpoint_identity_digest: channel.local_endpoint_identity_digest(),
            peer_credentials_digest: channel.peer_credentials_digest(),
            key: response.authentication_key(),
            algorithm: response.authentication_algorithm(),
            algorithm_version: response.authentication_algorithm_version(),
        })
    }

    fn try_from_stored(
        input: ControllerStoredRuntimeResponseAuthPinInput,
    ) -> Result<Self, ControllerJournalError> {
        if bytes_are_zero(input.bootstrap_response_digest.value().as_bytes())
            || bytes_are_zero(input.runtime_peer.as_bytes())
            || bytes_are_zero(input.local_endpoint_identity_digest.as_bytes())
            || bytes_are_zero(input.peer_credentials_digest.as_bytes())
            || bytes_are_zero(input.key.as_bytes())
            || input.algorithm.value() != REFERENCE_RESPONSE_AUTH_ALGORITHM_ED25519
            || input.algorithm_version != REFERENCE_RESPONSE_AUTH_ALGORITHM_VERSION
        {
            return Err(ControllerJournalError::InvalidRuntimeResponseAuthPin);
        }
        Ok(Self {
            bootstrap_response_digest: input.bootstrap_response_digest,
            runtime_peer: input.runtime_peer,
            local_endpoint_identity_digest: input.local_endpoint_identity_digest,
            peer_credentials_digest: input.peer_credentials_digest,
            key: input.key,
            algorithm: input.algorithm,
            algorithm_version: input.algorithm_version,
        })
    }

    #[must_use]
    pub(crate) const fn bootstrap_response_digest(self) -> ControllerBootstrapResponseDigest {
        self.bootstrap_response_digest
    }

    #[must_use]
    pub(crate) const fn runtime_peer(self) -> PrincipalRef {
        self.runtime_peer
    }

    pub(crate) fn channel(
        self,
        target: RuntimeHostId,
    ) -> Result<ReferenceChannelBindingV1, ControllerJournalError> {
        ReferenceChannelBindingV1::try_new(
            target,
            self.runtime_peer,
            self.local_endpoint_identity_digest,
            self.peer_credentials_digest,
        )
        .map_err(|_| ControllerJournalError::InvalidRuntimeResponseAuthPin)
    }

    #[must_use]
    pub(crate) const fn key(self) -> ApplyAuthKeyRef {
        self.key
    }

    #[must_use]
    pub(crate) const fn algorithm(self) -> ApplyAuthAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub(crate) const fn algorithm_version(self) -> u16 {
        self.algorithm_version
    }
}

/// Exact Runtime identity and bootstrap evidence pinned before sign/send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerTargetBinding {
    target: RuntimeHostId,
    runtime_store_instance_id: [u8; 32],
    channel_auth_fingerprint: ControllerChannelAuthFingerprint,
    manifest_digest: PlanManifestDigest,
    first_runtime_host_epoch: u64,
    last_runtime_host_epoch: u64,
    bootstrap_response: Box<[u8]>,
    bootstrap_response_digest: ControllerBootstrapResponseDigest,
    runtime_response_auth: ControllerRuntimeResponseAuthPin,
}

pub(crate) struct ControllerTargetBindingInput<'a> {
    pub(crate) target: RuntimeHostId,
    pub(crate) runtime_store_instance_id: [u8; 32],
    pub(crate) channel_auth_fingerprint: ControllerChannelAuthFingerprint,
    pub(crate) manifest_digest: PlanManifestDigest,
    pub(crate) first_runtime_host_epoch: u64,
    pub(crate) last_runtime_host_epoch: u64,
    pub(crate) bootstrap_response: &'a [u8],
    pub(crate) bootstrap_response_digest: ControllerBootstrapResponseDigest,
    pub(crate) runtime_response_auth: ControllerRuntimeResponseAuthPin,
}

impl ControllerTargetBinding {
    pub(crate) fn try_new(
        input: ControllerTargetBindingInput<'_>,
    ) -> Result<Self, ControllerJournalError> {
        if bytes_are_zero(input.target.as_bytes())
            || input.runtime_store_instance_id == [0; 32]
            || bytes_are_zero(input.channel_auth_fingerprint.value().as_bytes())
            || bytes_are_zero(input.manifest_digest.value().as_bytes())
            || input.first_runtime_host_epoch == 0
            || input.last_runtime_host_epoch < input.first_runtime_host_epoch
            || bytes_are_zero(input.bootstrap_response_digest.value().as_bytes())
        {
            return Err(ControllerJournalError::InvalidTargetBinding);
        }
        if input.bootstrap_response.is_empty() {
            return Err(ControllerJournalError::EmptyBootstrapResponse);
        }
        if input.bootstrap_response.len() > MAX_BOOTSTRAP_RESPONSE_BYTES {
            return Err(ControllerJournalError::BootstrapResponseTooLarge);
        }
        let response = ReferenceBootstrapResponseV1::decode(input.bootstrap_response)
            .map_err(|_| ControllerJournalError::InvalidTargetBinding)?;
        let channel = input
            .runtime_response_auth
            .channel(input.target)
            .map_err(|_| ControllerJournalError::InvalidTargetBinding)?;
        let derived_auth =
            ControllerRuntimeResponseAuthPin::try_from_bootstrap_response(&response, channel)
                .map_err(|_| ControllerJournalError::InvalidTargetBinding)?;
        let facts = response.facts();
        if response.canonical_wire() != input.bootstrap_response
            || response.response_digest() != input.bootstrap_response_digest.value()
            || derived_auth != input.runtime_response_auth
            || facts.target() != input.target
            || facts.runtime_store_instance_id() != input.runtime_store_instance_id
            || facts.runtime_host_epoch() != input.last_runtime_host_epoch
            || facts.manifest_digest() != input.manifest_digest.value()
        {
            return Err(ControllerJournalError::InvalidTargetBinding);
        }
        Ok(Self {
            target: input.target,
            runtime_store_instance_id: input.runtime_store_instance_id,
            channel_auth_fingerprint: input.channel_auth_fingerprint,
            manifest_digest: input.manifest_digest,
            first_runtime_host_epoch: input.first_runtime_host_epoch,
            last_runtime_host_epoch: input.last_runtime_host_epoch,
            bootstrap_response: input.bootstrap_response.into(),
            bootstrap_response_digest: input.bootstrap_response_digest,
            runtime_response_auth: input.runtime_response_auth,
        })
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn runtime_store_instance_id(&self) -> [u8; 32] {
        self.runtime_store_instance_id
    }

    #[must_use]
    pub(crate) const fn channel_auth_fingerprint(&self) -> ControllerChannelAuthFingerprint {
        self.channel_auth_fingerprint
    }

    #[must_use]
    pub(crate) const fn manifest_digest(&self) -> PlanManifestDigest {
        self.manifest_digest
    }

    #[must_use]
    pub(crate) const fn first_runtime_host_epoch(&self) -> u64 {
        self.first_runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn last_runtime_host_epoch(&self) -> u64 {
        self.last_runtime_host_epoch
    }

    #[must_use]
    pub(crate) fn bootstrap_response(&self) -> &[u8] {
        &self.bootstrap_response
    }

    #[must_use]
    pub(crate) const fn bootstrap_response_digest(&self) -> ControllerBootstrapResponseDigest {
        self.bootstrap_response_digest
    }

    #[must_use]
    pub(crate) const fn runtime_response_auth(&self) -> ControllerRuntimeResponseAuthPin {
        self.runtime_response_auth
    }

    fn validate_successor_of(&self, previous: &Self) -> Result<(), ControllerJournalError> {
        if self.target != previous.target
            || self.runtime_store_instance_id != previous.runtime_store_instance_id
            || self.channel_auth_fingerprint != previous.channel_auth_fingerprint
            || self.manifest_digest != previous.manifest_digest
            || self.first_runtime_host_epoch != previous.first_runtime_host_epoch
            || self.last_runtime_host_epoch < previous.last_runtime_host_epoch
        {
            return Err(ControllerJournalError::TargetBindingChanged);
        }
        if self.last_runtime_host_epoch == previous.last_runtime_host_epoch
            && (self.bootstrap_response != previous.bootstrap_response
                || self.bootstrap_response_digest != previous.bootstrap_response_digest
                || self.runtime_response_auth != previous.runtime_response_auth)
        {
            return Err(ControllerJournalError::TargetBindingChanged);
        }
        Ok(())
    }
}

/// Last durable target observation; it is not committed plan truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ControllerObservedTarget {
    Prepared = 1,
    Active = 2,
    Retired = 3,
    Uncertain = 4,
}

impl ControllerObservedTarget {
    fn decode(value: u8) -> Result<Self, ControllerJournalError> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Active),
            3 => Ok(Self::Retired),
            4 => Ok(Self::Uncertain),
            _ => Err(ControllerJournalError::UnknownEnum),
        }
    }
}

/// Immutable apply request committed before the first transport send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerSignedApplyIntent {
    target: RuntimeHostId,
    source_plan_digest: SourcePlanDigest,
    target_slice_digest: TargetSliceDigest,
    apply_operation: ApplyOperationId,
    request_digest: ControllerApplyRequestDigest,
    signed_request: Box<[u8]>,
    request_auth: ControllerRequestAuthPin,
    runtime_store_instance_id: [u8; 32],
    binding_channel_auth_fingerprint: ControllerChannelAuthFingerprint,
    binding_manifest_digest: PlanManifestDigest,
    runtime_response_auth: ControllerRuntimeResponseAuthPin,
}

pub(crate) struct ControllerSignedApplyIntentInput<'a> {
    pub(crate) target: RuntimeHostId,
    pub(crate) source_plan_digest: SourcePlanDigest,
    pub(crate) target_slice_digest: TargetSliceDigest,
    pub(crate) apply_operation: ApplyOperationId,
    pub(crate) request_digest: ControllerApplyRequestDigest,
    pub(crate) signed_request: &'a [u8],
}

struct ControllerStoredSignedApplyIntentInput<'a> {
    target: RuntimeHostId,
    source_plan_digest: SourcePlanDigest,
    target_slice_digest: TargetSliceDigest,
    apply_operation: ApplyOperationId,
    request_digest: ControllerApplyRequestDigest,
    signed_request: &'a [u8],
    request_auth: ControllerRequestAuthPin,
    runtime_store_instance_id: [u8; 32],
    binding_channel_auth_fingerprint: ControllerChannelAuthFingerprint,
    binding_manifest_digest: PlanManifestDigest,
    runtime_response_auth: ControllerRuntimeResponseAuthPin,
}

impl ControllerSignedApplyIntent {
    fn try_new(
        input: ControllerSignedApplyIntentInput<'_>,
        binding: &ControllerTargetBinding,
        request_auth: ControllerRequestAuthPin,
    ) -> Result<Self, ControllerJournalError> {
        Self::try_from_stored(ControllerStoredSignedApplyIntentInput {
            target: input.target,
            source_plan_digest: input.source_plan_digest,
            target_slice_digest: input.target_slice_digest,
            apply_operation: input.apply_operation,
            request_digest: input.request_digest,
            signed_request: input.signed_request,
            request_auth,
            runtime_store_instance_id: binding.runtime_store_instance_id,
            binding_channel_auth_fingerprint: binding.channel_auth_fingerprint,
            binding_manifest_digest: binding.manifest_digest,
            runtime_response_auth: binding.runtime_response_auth,
        })
    }

    fn try_from_stored(
        input: ControllerStoredSignedApplyIntentInput<'_>,
    ) -> Result<Self, ControllerJournalError> {
        if bytes_are_zero(input.target.as_bytes())
            || bytes_are_zero(input.source_plan_digest.value().as_bytes())
            || bytes_are_zero(input.target_slice_digest.value().as_bytes())
            || bytes_are_zero(input.apply_operation.as_bytes())
            || bytes_are_zero(input.request_digest.value().as_bytes())
            || input.runtime_store_instance_id == [0; 32]
            || bytes_are_zero(input.binding_channel_auth_fingerprint.value().as_bytes())
            || bytes_are_zero(input.binding_manifest_digest.value().as_bytes())
        {
            return Err(ControllerJournalError::InvalidRolloutEvidence);
        }
        if input.signed_request.is_empty() {
            return Err(ControllerJournalError::EmptySignedRequest);
        }
        if input.signed_request.len() > MAX_SIGNED_REQUEST_BYTES {
            return Err(ControllerJournalError::SignedRequestTooLarge);
        }
        Ok(Self {
            target: input.target,
            source_plan_digest: input.source_plan_digest,
            target_slice_digest: input.target_slice_digest,
            apply_operation: input.apply_operation,
            request_digest: input.request_digest,
            signed_request: input.signed_request.into(),
            request_auth: input.request_auth,
            runtime_store_instance_id: input.runtime_store_instance_id,
            binding_channel_auth_fingerprint: input.binding_channel_auth_fingerprint,
            binding_manifest_digest: input.binding_manifest_digest,
            runtime_response_auth: input.runtime_response_auth,
        })
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn source_plan_digest(&self) -> SourcePlanDigest {
        self.source_plan_digest
    }

    #[must_use]
    pub(crate) const fn target_slice_digest(&self) -> TargetSliceDigest {
        self.target_slice_digest
    }

    #[must_use]
    pub(crate) const fn apply_operation(&self) -> ApplyOperationId {
        self.apply_operation
    }

    #[must_use]
    pub(crate) const fn request_digest(&self) -> ControllerApplyRequestDigest {
        self.request_digest
    }

    #[must_use]
    pub(crate) fn signed_request(&self) -> &[u8] {
        &self.signed_request
    }

    #[must_use]
    pub(crate) const fn request_auth(&self) -> ControllerRequestAuthPin {
        self.request_auth
    }

    #[must_use]
    pub(crate) const fn runtime_store_instance_id(&self) -> [u8; 32] {
        self.runtime_store_instance_id
    }

    #[must_use]
    pub(crate) const fn binding_channel_auth_fingerprint(
        &self,
    ) -> ControllerChannelAuthFingerprint {
        self.binding_channel_auth_fingerprint
    }

    #[must_use]
    pub(crate) const fn binding_manifest_digest(&self) -> PlanManifestDigest {
        self.binding_manifest_digest
    }

    #[must_use]
    pub(crate) const fn runtime_response_auth(&self) -> ControllerRuntimeResponseAuthPin {
        self.runtime_response_auth
    }
}

/// Exact canonical PXQR plus every request-time Runtime verification pin.
///
/// This row is committed before the transport may send a byte. It deliberately
/// stores the canonical contract value rather than copying its selector fields
/// into a Controller-owned protocol approximation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerPreparedQuery {
    request: ReferenceQueryRequestV1,
    request_auth: ControllerRequestAuthPin,
    request_time_channel: ReferenceChannelBindingV1,
    runtime_response_auth: ControllerRuntimeResponseAuthPin,
    serving_baseline: ReferenceBootstrapServingIdentityV1,
}

impl ControllerPreparedQuery {
    fn try_new(
        request: ReferenceQueryRequestV1,
        binding: &ControllerTargetBinding,
        request_auth: ControllerRequestAuthPin,
        source_scope: paraegox_runtime_contracts::provenance::SourceScopeRef,
        intent: &ControllerSignedApplyIntent,
    ) -> Result<Self, ControllerJournalError> {
        let decoded = ReferenceQueryRequestV1::decode(request.canonical_wire())?;
        let apply = ReferenceApplyRequestV1::decode(intent.signed_request())
            .map_err(|_| ControllerJournalError::InvalidQueryRequest)?;
        let claim = request.authentication().claim();
        let runtime_response_auth = binding.runtime_response_auth();
        let request_time_channel = runtime_response_auth.channel(binding.target())?;
        let bootstrap = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())?;
        let facts = bootstrap.facts();
        let serving_baseline = ReferenceBootstrapServingIdentityV1::try_new(
            facts.target(),
            facts.runtime_store_instance_id(),
            facts.snapshot_sequence(),
            facts.runtime_host_epoch(),
            facts.clock_domain(),
            facts.clock_generation(),
        )?;
        if decoded != request
            || request.canonical_wire().is_empty()
            || request.canonical_wire().len() > MAX_REFERENCE_QUERY_REQUEST_BYTES
            || bytes_are_zero(request.query_id().as_bytes())
            || request.target() != binding.target()
            || request.target() != intent.target()
            || request.source_scope() != source_scope
            || request.expected_runtime_store_instance_id() != binding.runtime_store_instance_id()
            || request.requested_operation_id() != intent.apply_operation()
            || request.expected_request_digest() != Some(intent.request_digest().value())
            || claim.principal() != apply.authentication().claim().principal()
            || claim.key() != request_auth.key()
            || claim.algorithm() != request_auth.algorithm()
            || claim.algorithm_version() != request_auth.algorithm_version()
            || claim.algorithm().value() != REFERENCE_RESPONSE_AUTH_ALGORITHM_ED25519
            || claim.algorithm_version() != REFERENCE_RESPONSE_AUTH_ALGORITHM_VERSION
            || request.authentication().signature().len() != ED25519_SIGNATURE_BYTES
            || request.max_response_bytes() as usize > MAX_REFERENCE_QUERY_RESPONSE_BYTES
            || serving_baseline.target() != request.target()
            || serving_baseline.runtime_store_instance_id()
                != request.expected_runtime_store_instance_id()
            || serving_baseline.runtime_host_epoch() != binding.last_runtime_host_epoch()
            || runtime_response_auth.runtime_peer() != request_time_channel.runtime_peer()
        {
            return Err(ControllerJournalError::InvalidQueryRequest);
        }
        Ok(Self {
            request,
            request_auth,
            request_time_channel,
            runtime_response_auth,
            serving_baseline,
        })
    }

    fn validate(
        &self,
        binding: &ControllerTargetBinding,
        source_scope: paraegox_runtime_contracts::provenance::SourceScopeRef,
        intent: &ControllerSignedApplyIntent,
    ) -> Result<(), ControllerJournalError> {
        let decoded = ReferenceQueryRequestV1::decode(self.request.canonical_wire())?;
        let apply = ReferenceApplyRequestV1::decode(intent.signed_request())
            .map_err(|_| ControllerJournalError::InvalidQueryRequest)?;
        let claim = self.request.authentication().claim();
        if decoded != self.request
            || self.request.canonical_wire().is_empty()
            || self.request.canonical_wire().len() > MAX_REFERENCE_QUERY_REQUEST_BYTES
            || bytes_are_zero(self.request.query_id().as_bytes())
            || self.request.target() != binding.target()
            || self.request.target() != intent.target()
            || self.request.source_scope() != source_scope
            || self.request.expected_runtime_store_instance_id()
                != binding.runtime_store_instance_id()
            || self.request.requested_operation_id() != intent.apply_operation()
            || self.request.expected_request_digest() != Some(intent.request_digest().value())
            || claim.principal() != apply.authentication().claim().principal()
            || claim.key() != self.request_auth.key()
            || claim.algorithm() != self.request_auth.algorithm()
            || claim.algorithm_version() != self.request_auth.algorithm_version()
            || claim.algorithm().value() != REFERENCE_RESPONSE_AUTH_ALGORITHM_ED25519
            || claim.algorithm_version() != REFERENCE_RESPONSE_AUTH_ALGORITHM_VERSION
            || self.request.authentication().signature().len() != ED25519_SIGNATURE_BYTES
            || self.request.max_response_bytes() as usize > MAX_REFERENCE_QUERY_RESPONSE_BYTES
            || self.request_time_channel.target() != self.request.target()
            || self.request_time_channel.runtime_peer() != self.runtime_response_auth.runtime_peer()
            || self.runtime_response_auth.channel(self.request.target())?
                != self.request_time_channel
            || self.serving_baseline.target() != self.request.target()
            || self.serving_baseline.runtime_store_instance_id()
                != self.request.expected_runtime_store_instance_id()
            || self.serving_baseline.runtime_host_epoch() < binding.first_runtime_host_epoch()
            || self.serving_baseline.runtime_host_epoch() > binding.last_runtime_host_epoch()
        {
            return Err(ControllerJournalError::InvalidQueryRequest);
        }
        Ok(())
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ReferenceQueryRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) const fn request_auth(&self) -> ControllerRequestAuthPin {
        self.request_auth
    }

    #[must_use]
    pub(crate) const fn request_time_channel(&self) -> ReferenceChannelBindingV1 {
        self.request_time_channel
    }

    #[must_use]
    pub(crate) const fn runtime_response_auth(&self) -> ControllerRuntimeResponseAuthPin {
        self.runtime_response_auth
    }

    #[must_use]
    pub(crate) const fn serving_baseline(&self) -> ReferenceBootstrapServingIdentityV1 {
        self.serving_baseline
    }
}

/// Exact PXQS bytes after signature-first client validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerQueryObservation {
    response: ReferenceQueryResponseV1,
    response_digest: Digest32,
    channel_peer: ReferenceChannelBindingV1,
}

impl ControllerQueryObservation {
    fn try_new(
        response: ReferenceQueryResponseV1,
        channel_peer: ReferenceChannelBindingV1,
        prepared: &ControllerPreparedQuery,
    ) -> Result<Self, ControllerJournalError> {
        let decoded = ReferenceQueryResponseV1::decode(response.canonical_wire())?;
        if decoded != response
            || response.canonical_wire().is_empty()
            || response.canonical_wire().len() > MAX_REFERENCE_QUERY_RESPONSE_BYTES
            || response.canonical_wire().len() > prepared.request().max_response_bytes() as usize
            || channel_peer != prepared.request_time_channel()
            || response.authentication_runtime_peer()
                != prepared.runtime_response_auth().runtime_peer()
            || response.authentication_key() != prepared.runtime_response_auth().key()
            || response.authentication_algorithm() != prepared.runtime_response_auth().algorithm()
            || response.authentication_algorithm_version()
                != prepared.runtime_response_auth().algorithm_version()
            || response.authentication_signature().len() != ED25519_SIGNATURE_BYTES
        {
            return Err(ControllerJournalError::InvalidQueryResponse);
        }
        response.validate_against_request(
            prepared.request(),
            channel_peer,
            prepared.serving_baseline(),
        )?;
        Ok(Self {
            response_digest: response.response_digest(),
            response,
            channel_peer,
        })
    }

    #[must_use]
    pub(crate) const fn response(&self) -> &ReferenceQueryResponseV1 {
        &self.response
    }

    #[must_use]
    pub(crate) const fn channel_peer(&self) -> ReferenceChannelBindingV1 {
        self.channel_peer
    }

    fn query_snapshot_sequence(&self) -> u64 {
        self.response.facts().serving().snapshot_sequence()
    }
}

/// Reconcile decision bound to one already-durable opaque query observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerRolloutDecision {
    query_id: ReferenceQueryIdV1,
    query_snapshot_sequence: u64,
    observed: ControllerObservedTarget,
    receipt: Option<ControllerReceiptRef>,
}

impl ControllerRolloutDecision {
    fn try_new(
        observation: &ControllerQueryObservation,
        observed: ControllerObservedTarget,
        receipt: Option<ControllerReceiptRef>,
    ) -> Result<Self, ControllerJournalError> {
        if receipt.is_some_and(|value| bytes_are_zero(value.as_bytes())) {
            return Err(ControllerJournalError::InvalidRolloutEvidence);
        }
        match observed {
            ControllerObservedTarget::Active | ControllerObservedTarget::Retired
                if receipt.is_none() =>
            {
                return Err(ControllerJournalError::TerminalReceiptRequired);
            }
            ControllerObservedTarget::Prepared | ControllerObservedTarget::Uncertain
                if receipt.is_some() =>
            {
                return Err(ControllerJournalError::NonTerminalReceiptForbidden);
            }
            _ => {}
        }
        if let (
            ControllerObservedTarget::Active | ControllerObservedTarget::Retired,
            Some(terminal_receipt),
        ) = (observed, receipt)
            && !terminal_decision_matches_observation(observation, observed, terminal_receipt)
        {
            return Err(ControllerJournalError::InvalidRolloutEvidence);
        }
        Ok(Self {
            query_id: observation.response.query_id(),
            query_snapshot_sequence: observation.query_snapshot_sequence(),
            observed,
            receipt,
        })
    }

    const fn is_terminal(self) -> bool {
        matches!(
            self.observed,
            ControllerObservedTarget::Active | ControllerObservedTarget::Retired
        ) && self.receipt.is_some()
    }
}

fn terminal_decision_matches_observation(
    observation: &ControllerQueryObservation,
    observed: ControllerObservedTarget,
    receipt: ControllerReceiptRef,
) -> bool {
    let facts = observation.response().facts();
    if facts.operation().owner_state() != ReferenceQueryOwnerStateV1::Operational {
        return false;
    }
    let ReferenceQueryOperationLookupV1::Known {
        durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
        terminal_result: Some(result),
        ..
    } = facts.operation().lookup()
    else {
        return false;
    };
    if result.as_bytes() != receipt.as_bytes() {
        return false;
    }
    matches!(
        (observed, facts.desired().head(), facts.live().state()),
        (
            ControllerObservedTarget::Active,
            ReferenceQueryDesiredHeadV1::OneSourceLoop { .. },
            ReferenceQueryLiveStateV1::LiveReady,
        ) | (
            ControllerObservedTarget::Retired,
            ReferenceQueryDesiredHeadV1::EmptyDeactivate { .. },
            ReferenceQueryLiveStateV1::ExactZero,
        )
    )
}

/// Stable reason that one durable PXQR ended without an authenticated PXQS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ControllerQueryClosureKind {
    NotSent = 1,
    DeliveryUncertain = 2,
    ResidentAuthorityLostAfterRestart = 3,
    ResponseRejected = 4,
}

impl ControllerQueryClosureKind {
    fn decode(value: u8) -> Result<Self, ControllerJournalError> {
        match value {
            1 => Ok(Self::NotSent),
            2 => Ok(Self::DeliveryUncertain),
            3 => Ok(Self::ResidentAuthorityLostAfterRestart),
            4 => Ok(Self::ResponseRejected),
            _ => Err(ControllerJournalError::UnknownEnum),
        }
    }
}

/// One immutable query request followed by either an exact observation or a
/// durable no-response closure, and then an optional observation decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerReconcileAttempt {
    prepared: ControllerPreparedQuery,
    observation: Option<ControllerQueryObservation>,
    closure: Option<ControllerQueryClosureKind>,
    decision: Option<ControllerRolloutDecision>,
}

impl ControllerReconcileAttempt {
    fn validate(&self) -> Result<(), ControllerJournalError> {
        if self.closure.is_some() && (self.observation.is_some() || self.decision.is_some()) {
            return Err(ControllerJournalError::InvalidQueryClosure);
        }
        match (&self.observation, self.decision) {
            (None, Some(_)) => return Err(ControllerJournalError::QueryNotCommittedBeforeDecision),
            (Some(observation), Some(decision))
                if decision.query_id != observation.response.query_id()
                    || decision.query_snapshot_sequence
                        != observation.query_snapshot_sequence()
                    || (decision.is_terminal()
                        && !terminal_decision_matches_observation(
                            observation,
                            decision.observed,
                            decision
                                .receipt
                                .ok_or(ControllerJournalError::DanglingRolloutDecision)?,
                        )) =>
            {
                return Err(ControllerJournalError::DanglingRolloutDecision);
            }
            _ => {}
        }
        Ok(())
    }

    const fn is_closed_without_response(&self) -> bool {
        self.closure.is_some()
    }
}

/// Exact canonical PXRT returned directly by the Runtime apply endpoint.
///
/// This is deliberately separate from opaque query/reconcile evidence. The
/// Controller apply client verifies Runtime signature and live channel before
/// calling the journal transition; the journal independently re-decodes and
/// correlates all request-owned fields before retaining the exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerDirectTerminalReceipt {
    receipt: ReferenceApplyTerminalReceiptV1,
}

impl ControllerDirectTerminalReceipt {
    fn try_new(
        receipt: ReferenceApplyTerminalReceiptV1,
        intent: &ControllerSignedApplyIntent,
    ) -> Result<Self, ControllerJournalError> {
        let decoded = ReferenceApplyTerminalReceiptV1::decode(receipt.canonical_wire())?;
        let request = ReferenceApplyRequestV1::decode(intent.signed_request())?;
        let runtime_auth = intent.runtime_response_auth();
        let original_channel = runtime_auth
            .channel(intent.target())
            .map_err(|_| ControllerJournalError::InvalidDirectTerminalReceipt)?;
        receipt
            .validate_against_request(&request, original_channel)
            .map_err(|_| ControllerJournalError::InvalidDirectTerminalReceipt)?;
        if decoded != receipt
            || receipt.target() != intent.target()
            || receipt.target() != request.target()
            || receipt.runtime_store_instance_id() != intent.runtime_store_instance_id()
            || receipt.runtime_store_instance_id() != request.expected_runtime_store_instance_id()
            || receipt.source_scope() != request.provenance().source_scope()
            || receipt.operation_id() != intent.apply_operation()
            || receipt.operation_id() != request.control_commitment().control().operation_id()
            || receipt.request_digest() != intent.request_digest().value()
            || receipt.request_digest() != request.envelope_request_digest()
            || receipt.request_nonce() != request.authentication().claim().nonce()
            || bytes_are_zero(receipt.facts().terminal_result_ref().as_bytes())
            || receipt.authentication_channel_binding_digest() != original_channel.binding_digest()
            || receipt.authentication_runtime_peer() != runtime_auth.runtime_peer()
            || receipt.authentication_key() != runtime_auth.key()
            || receipt.authentication_algorithm() != runtime_auth.algorithm()
            || receipt.authentication_algorithm_version() != runtime_auth.algorithm_version()
            || receipt.authentication_signature().len() != ED25519_SIGNATURE_BYTES
        {
            return Err(ControllerJournalError::InvalidDirectTerminalReceipt);
        }
        Ok(Self { receipt })
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> &ReferenceApplyTerminalReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub(crate) const fn desired_head_digest(&self) -> Option<TargetSliceDigest> {
        self.receipt.facts().desired_head_digest()
    }
}

/// One-target signed intent plus append-only reconciliation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerRolloutRecord {
    signed_intent: ControllerSignedApplyIntent,
    direct_terminal_receipt: Option<ControllerDirectTerminalReceipt>,
    reconcile_attempts: Box<[ControllerReconcileAttempt]>,
}

impl ControllerRolloutRecord {
    fn validate(&self) -> Result<(), ControllerJournalError> {
        if self.reconcile_attempts.len() > MAX_RECONCILE_ATTEMPTS {
            return Err(ControllerJournalError::ReconcileCapacityExceeded);
        }
        let mut last_sequence = None;
        let mut query_ids = std::collections::BTreeSet::new();
        for (index, attempt) in self.reconcile_attempts.iter().enumerate() {
            attempt.validate()?;
            let query_id = attempt.prepared.request().query_id();
            if !query_ids.insert(query_id) {
                return Err(ControllerJournalError::QueryEvidenceChanged);
            }
            if let Some(observation) = &attempt.observation {
                let sequence = observation.query_snapshot_sequence();
                if last_sequence.is_some_and(|previous| previous > sequence) {
                    return Err(ControllerJournalError::NonCanonicalReconcileHistory);
                }
                last_sequence = Some(sequence);
            }
            if index + 1 != self.reconcile_attempts.len()
                && !attempt.is_closed_without_response()
                && (attempt.observation.is_none() || attempt.decision.is_none())
            {
                return Err(ControllerJournalError::DanglingQueryObservation);
            }
        }
        if let (Some(direct), Some(decision)) = (
            self.direct_terminal_receipt.as_ref(),
            self.reconcile_attempts
                .last()
                .and_then(|attempt| attempt.decision),
        ) {
            if decision.is_terminal() && !direct_terminal_decision_matches(direct, decision) {
                return Err(ControllerJournalError::ConflictingTerminalEvidence);
            }
            if decision.observed == ControllerObservedTarget::Prepared
                && !direct_follows_prepared_query(
                    direct,
                    self.reconcile_attempts
                        .last()
                        .ok_or(ControllerJournalError::DanglingRolloutDecision)?,
                    decision,
                )
            {
                return Err(ControllerJournalError::ConflictingTerminalEvidence);
            }
        }
        if let Some(direct) = self.direct_terminal_receipt.as_ref()
            && self.reconcile_attempts.iter().any(|attempt| {
                attempt.decision.is_some()
                    && attempt_has_conflicting_terminal_observation(direct, attempt)
            })
        {
            return Err(ControllerJournalError::ConflictingTerminalEvidence);
        }
        Ok(())
    }

    fn has_conflicting_terminal_observation(&self) -> bool {
        let Some(direct) = self.direct_terminal_receipt.as_ref() else {
            return false;
        };
        self.reconcile_attempts
            .iter()
            .any(|attempt| attempt_has_conflicting_terminal_observation(direct, attempt))
    }

    fn is_terminal(&self) -> bool {
        self.direct_terminal_receipt.is_some()
            || self
                .reconcile_attempts
                .last()
                .and_then(|attempt| attempt.decision)
                .is_some_and(ControllerRolloutDecision::is_terminal)
    }
}

fn attempt_has_conflicting_terminal_observation(
    direct: &ControllerDirectTerminalReceipt,
    attempt: &ControllerReconcileAttempt,
) -> bool {
    let Some(observation) = attempt.observation.as_ref() else {
        return false;
    };
    let ReferenceQueryOperationLookupV1::Known {
        durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
        terminal_result: Some(queried),
        ..
    } = observation.response().facts().operation().lookup()
    else {
        return false;
    };
    queried.as_bytes() != direct.receipt().facts().terminal_result_ref().as_bytes()
}

fn rollout_permits_plan_advance(
    rollout: &ControllerRolloutRecord,
    binding: &ControllerTargetBinding,
) -> Result<bool, ControllerJournalError> {
    if rollout.has_conflicting_terminal_observation() {
        return Err(ControllerJournalError::ConflictingTerminalEvidence);
    }
    let current_epoch = binding.last_runtime_host_epoch;
    let latest = rollout.reconcile_attempts.last();
    let Some(direct) = rollout.direct_terminal_receipt.as_ref() else {
        return Ok(latest.is_some_and(|attempt| {
            let Some(observation) = attempt.observation.as_ref() else {
                return false;
            };
            attempt
                .decision
                .is_some_and(ControllerRolloutDecision::is_terminal)
                && observation
                    .response()
                    .facts()
                    .serving()
                    .runtime_host_epoch()
                    >= current_epoch
        }));
    };
    if !direct_terminal_is_success(direct, &rollout.signed_intent) {
        return Ok(false);
    }

    let direct_epoch = direct.receipt().facts().completion_runtime_host_epoch();
    if direct_epoch > current_epoch {
        return Ok(false);
    }
    if direct_epoch == current_epoch && latest.is_none() {
        return Ok(true);
    }
    let Some(latest) = latest else {
        return Ok(false);
    };
    if latest.closure.is_some() || latest.observation.is_none() || latest.decision.is_none() {
        return Ok(false);
    }
    if direct_epoch < current_epoch {
        return Ok(terminal_attempt_matches_current_direct(
            direct,
            latest,
            current_epoch,
        ));
    }
    if direct_follows_query_observation(direct, latest) {
        return Ok(true);
    }
    Ok(terminal_attempt_matches_current_direct(
        direct,
        latest,
        current_epoch,
    ))
}

fn direct_terminal_is_success(
    direct: &ControllerDirectTerminalReceipt,
    intent: &ControllerSignedApplyIntent,
) -> bool {
    let Ok(apply) = ReferenceApplyRequestV1::decode(&intent.signed_request) else {
        return false;
    };
    let facts = direct.receipt().facts();
    if facts.head() != ReferenceApplyTerminalHeadV1::CommittedIncoming
        || facts.desired_head_digest() != Some(intent.target_slice_digest)
    {
        return false;
    }
    match (apply.target_execution().mode(), facts.outcome()) {
        (
            ReferenceAssemblyModeV1::OneSourceLoop,
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
        ) => facts.lifecycle_effect() == ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
        (
            ReferenceAssemblyModeV1::EmptyDeactivate,
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero,
        ) => true,
        _ => false,
    }
}

fn terminal_attempt_matches_current_direct(
    direct: &ControllerDirectTerminalReceipt,
    attempt: &ControllerReconcileAttempt,
    current_epoch: u64,
) -> bool {
    let Some(observation) = attempt.observation.as_ref() else {
        return false;
    };
    let Some(decision) = attempt.decision else {
        return false;
    };
    if !decision.is_terminal() || !direct_terminal_decision_matches(direct, decision) {
        return false;
    }
    let serving = observation.response().facts().serving();
    let terminal = direct.receipt().facts();
    serving.runtime_host_epoch() >= current_epoch
        && (serving.runtime_host_epoch() != terminal.completion_runtime_host_epoch()
            || serving.snapshot_sequence() >= terminal.completion_snapshot_sequence())
}

fn direct_terminal_decision_matches(
    direct: &ControllerDirectTerminalReceipt,
    decision: ControllerRolloutDecision,
) -> bool {
    let facts = direct.receipt().facts();
    let expected_observed = match facts.outcome() {
        ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive => ControllerObservedTarget::Active,
        ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero => {
            ControllerObservedTarget::Retired
        }
        _ => return false,
    };
    decision.observed == expected_observed
        && decision.receipt
            == Some(ControllerReceiptRef::from_bytes(
                *facts.terminal_result_ref().as_bytes(),
            ))
}

fn terminal_query_decision_is_current(
    attempt: &ControllerReconcileAttempt,
    binding: &ControllerTargetBinding,
) -> bool {
    attempt
        .decision
        .is_some_and(ControllerRolloutDecision::is_terminal)
        && attempt.observation.as_ref().is_some_and(|observation| {
            observation
                .response()
                .facts()
                .serving()
                .runtime_host_epoch()
                >= binding.last_runtime_host_epoch
        })
}

fn direct_follows_prepared_query(
    direct: &ControllerDirectTerminalReceipt,
    attempt: &ControllerReconcileAttempt,
    decision: ControllerRolloutDecision,
) -> bool {
    decision.query_snapshot_sequence
        == attempt
            .observation
            .as_ref()
            .map_or(0, ControllerQueryObservation::query_snapshot_sequence)
        && direct_follows_query_observation(direct, attempt)
}

fn direct_follows_query_observation(
    direct: &ControllerDirectTerminalReceipt,
    attempt: &ControllerReconcileAttempt,
) -> bool {
    let receipt = direct.receipt();
    let request = attempt.prepared.request();
    let Some(observation) = attempt.observation.as_ref() else {
        return false;
    };
    let serving = observation.response().facts().serving();
    let terminal = receipt.facts();
    request.target() == receipt.target()
        && request.expected_runtime_store_instance_id() == receipt.runtime_store_instance_id()
        && request.requested_operation_id() == receipt.operation_id()
        && request.expected_request_digest() == Some(receipt.request_digest())
        && serving.target() == receipt.target()
        && serving.runtime_store_instance_id() == receipt.runtime_store_instance_id()
        && serving.runtime_host_epoch() == terminal.completion_runtime_host_epoch()
        && observation.query_snapshot_sequence() < terminal.completion_snapshot_sequence()
}

/// Durable phase of one exact Controller-to-Authority tenure exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ControllerTenurePhase {
    Prepared = 1,
    Uncertain = 2,
    Committed = 3,
}

impl ControllerTenurePhase {
    fn decode(value: u8) -> Result<Self, ControllerJournalError> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Uncertain),
            3 => Ok(Self::Committed),
            _ => Err(ControllerJournalError::UnknownEnum),
        }
    }

    const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Prepared,
                Self::Prepared | Self::Uncertain | Self::Committed
            ) | (Self::Uncertain, Self::Uncertain | Self::Committed)
                | (Self::Committed, Self::Committed)
        )
    }

    #[must_use]
    pub(crate) const fn is_committed(self) -> bool {
        matches!(self, Self::Committed)
    }
}

/// Exact persisted acquire-tenure transaction, deliberately separate from the
/// generic plan-operation ledger. Canonical protocol values remain the owner
/// of every request, response, and proof fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerTenureTransaction {
    request: AcquireTenureRequestV1,
    authority_domain_fingerprint: ControllerTenureAuthorityDomainFingerprint,
    phase: ControllerTenurePhase,
    response: Option<AcquireTenureResponseV1>,
}

impl ControllerTenureTransaction {
    fn try_new(
        request: AcquireTenureRequestV1,
        authority_domain_fingerprint: ControllerTenureAuthorityDomainFingerprint,
        phase: ControllerTenurePhase,
        response: Option<AcquireTenureResponseV1>,
    ) -> Result<Self, ControllerJournalError> {
        if bytes_are_zero(authority_domain_fingerprint.value().as_bytes()) {
            return Err(ControllerJournalError::InvalidTenureAuthorityDomainFingerprint);
        }
        match (phase, response.as_ref()) {
            (ControllerTenurePhase::Committed, Some(response)) => {
                let decoded = AcquireTenureResponseV1::decode_for_request(
                    response.canonical_bytes(),
                    &request,
                )?;
                if decoded != *response {
                    return Err(ControllerJournalError::InvalidTenureTransaction);
                }
            }
            (ControllerTenurePhase::Prepared | ControllerTenurePhase::Uncertain, None) => {}
            _ => return Err(ControllerJournalError::InvalidTenureTransaction),
        }
        let decoded = AcquireTenureRequestV1::decode(request.canonical_bytes())?;
        if decoded != request {
            return Err(ControllerJournalError::InvalidTenureTransaction);
        }
        Ok(Self {
            request,
            authority_domain_fingerprint,
            phase,
            response,
        })
    }

    #[must_use]
    pub(crate) const fn operation_id(&self) -> AcquireTenureOperationId {
        self.request.operation_id()
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> ControllerTenurePhase {
        self.phase
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &AcquireTenureRequestV1 {
        &self.request
    }

    /// Returns the exact protected Authority transport/provisioning domain
    /// selected before this request first became durable.
    #[must_use]
    pub(crate) const fn authority_domain_fingerprint(
        &self,
    ) -> ControllerTenureAuthorityDomainFingerprint {
        self.authority_domain_fingerprint
    }

    #[must_use]
    pub(crate) const fn response(&self) -> Option<&AcquireTenureResponseV1> {
        self.response.as_ref()
    }

    #[must_use]
    pub(crate) fn committed_proof(&self) -> Option<&WriterTenureProof> {
        self.response.as_ref().map(AcquireTenureResponseV1::proof)
    }
}

/// Full Controller-owned payload. It is immutable between validated mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerJournalState {
    scope: DeploymentScopeId,
    plan_lineage: DeploymentId,
    allocation: StableAllocationSnapshot,
    installed_manifest: ControllerInstalledManifestPin,
    committed_plan: Option<ControllerCommittedPlan>,
    operations: Box<[ControllerOperationRecord]>,
    tenure_transactions: Box<[ControllerTenureTransaction]>,
    request_auth: ControllerRequestAuthPin,
    target_binding: Option<ControllerTargetBinding>,
    query_snapshot_high_water: u64,
    rollout: Option<ControllerRolloutRecord>,
    apply_history: Box<[ControllerRolloutRecord]>,
}

struct ControllerJournalStateInput {
    scope: DeploymentScopeId,
    plan_lineage: DeploymentId,
    allocation: StableAllocationSnapshot,
    installed_manifest: ControllerInstalledManifestPin,
    committed_plan: Option<ControllerCommittedPlan>,
    operations: Vec<ControllerOperationRecord>,
    tenure_transactions: Vec<ControllerTenureTransaction>,
    request_auth: ControllerRequestAuthPin,
    target_binding: Option<ControllerTargetBinding>,
    query_snapshot_high_water: u64,
    rollout: Option<ControllerRolloutRecord>,
    apply_history: Vec<ControllerRolloutRecord>,
}

struct ControllerJournalMutationInput {
    allocation: StableAllocationSnapshot,
    committed_plan: Option<ControllerCommittedPlan>,
    operations: Vec<ControllerOperationRecord>,
    tenure_transactions: Vec<ControllerTenureTransaction>,
    request_auth: ControllerRequestAuthPin,
    target_binding: Option<ControllerTargetBinding>,
    query_snapshot_high_water: u64,
    rollout: Option<ControllerRolloutRecord>,
    apply_history: Vec<ControllerRolloutRecord>,
}

impl ControllerJournalState {
    pub(crate) fn try_initialize(
        scope: DeploymentScopeId,
        plan_lineage: DeploymentId,
        allocation: StableAllocationSnapshot,
        installed_manifest: ControllerInstalledManifestPin,
        request_auth: ControllerRequestAuthPin,
    ) -> Result<Self, ControllerJournalError> {
        if allocation.generation() != 0
            || allocation.high_water() != 0
            || !allocation.records().is_empty()
        {
            return Err(ControllerJournalError::NonFreshInitialState);
        }
        Self::try_from_stored(ControllerJournalStateInput {
            scope,
            plan_lineage,
            allocation,
            installed_manifest,
            committed_plan: None,
            operations: Vec::new(),
            tenure_transactions: Vec::new(),
            request_auth,
            target_binding: None,
            query_snapshot_high_water: 0,
            rollout: None,
            apply_history: Vec::new(),
        })
    }

    fn try_from_stored(input: ControllerJournalStateInput) -> Result<Self, ControllerJournalError> {
        let state = Self {
            scope: input.scope,
            plan_lineage: input.plan_lineage,
            allocation: input.allocation,
            installed_manifest: input.installed_manifest,
            committed_plan: input.committed_plan,
            operations: input.operations.into_boxed_slice(),
            tenure_transactions: input.tenure_transactions.into_boxed_slice(),
            request_auth: input.request_auth,
            target_binding: input.target_binding,
            query_snapshot_high_water: input.query_snapshot_high_water,
            rollout: input.rollout,
            apply_history: input.apply_history.into_boxed_slice(),
        };
        state.validate()?;
        Ok(state)
    }

    /// Adds the exact typed candidate intent as a durable Prepared operation.
    pub(crate) fn prepare_plan_candidate(
        &self,
        operation: ControllerOperationId,
        candidate: &DeploymentPlanCandidate,
    ) -> Result<Self, ControllerJournalError> {
        self.validate_candidate_identity(candidate)?;
        if let Some(existing) = self
            .operations
            .iter()
            .find(|record| record.operation == operation)
        {
            let intent_digest = plan_commit_intent_digest(
                self.scope,
                self.plan_lineage,
                existing.expected_revision,
                candidate,
            )?;
            if existing.intent_digest == intent_digest {
                return Ok(self.clone());
            }
            return Err(ControllerJournalError::OperationConflict);
        }
        self.allocation
            .apply_delta(candidate.allocation_delta())
            .map_err(|_| ControllerJournalError::InvalidAllocationTransition)?;
        let expected_revision = self.current_revision();
        let intent_digest =
            plan_commit_intent_digest(self.scope, self.plan_lineage, expected_revision, candidate)?;
        if self.operations.len() == MAX_CONTROLLER_OPERATIONS {
            return Err(ControllerJournalError::OperationCapacityExceeded);
        }
        let mut operations = self.operations.to_vec();
        operations.push(ControllerOperationRecord::try_new(
            operation,
            intent_digest,
            expected_revision,
            ControllerOperationPhase::Prepared,
            None,
            None,
            None,
        )?);
        operations.sort_unstable_by_key(|record| record.operation);
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations,
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: self.rollout.clone(),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Atomically applies the exact Planner delta, assigns the next revision,
    /// stores typed committed content, and advances its Prepared operation.
    pub(crate) fn commit_plan_candidate(
        &self,
        operation: ControllerOperationId,
        candidate: &DeploymentPlanCandidate,
    ) -> Result<Self, ControllerJournalError> {
        self.validate_candidate_identity(candidate)?;
        let Some((operation_index, operation_record)) = self
            .operations
            .iter()
            .enumerate()
            .find(|(_, record)| record.operation == operation)
        else {
            return Err(ControllerJournalError::MissingPreparedOperation);
        };
        let intent_digest = plan_commit_intent_digest(
            self.scope,
            self.plan_lineage,
            operation_record.expected_revision,
            candidate,
        )?;
        if intent_digest != operation_record.intent_digest {
            return Err(ControllerJournalError::OperationConflict);
        }
        let next_revision = operation_record
            .expected_revision
            .checked_add(1)
            .ok_or(ControllerJournalError::RevisionExhausted)?;
        let committed_plan = ControllerCommittedPlan::try_from_candidate(
            self.scope,
            self.plan_lineage,
            DeploymentRevision::new(next_revision),
            operation,
            intent_digest,
            candidate,
        )?;

        if operation_record.phase != ControllerOperationPhase::Prepared {
            if self.current_revision() == next_revision
                && self.committed_plan.as_ref() == Some(&committed_plan)
                && allocation_matches_delta_result(&self.allocation, candidate.allocation_delta())
            {
                return Ok(self.clone());
            }
            return Err(ControllerJournalError::InvalidOperationTransition);
        }
        if self.current_revision() != operation_record.expected_revision {
            return Err(ControllerJournalError::StalePlanOperation);
        }
        if self.operations.iter().any(|record| {
            record.operation != operation
                && record.expected_revision == self.current_revision()
                && matches!(
                    record.phase,
                    ControllerOperationPhase::Prepared | ControllerOperationPhase::Uncertain
                )
        }) {
            return Err(ControllerJournalError::UnresolvedPlanOperationBlocksCommit);
        }
        let apply_history = self.apply_history_for_plan_commit()?;

        let allocation = self
            .allocation
            .apply_delta(candidate.allocation_delta())
            .map_err(|_| ControllerJournalError::InvalidAllocationTransition)?;
        let mut operations = self.operations.to_vec();
        operations[operation_index].phase = ControllerOperationPhase::Committed;
        operations[operation_index].committed_allocation_generation = Some(allocation.generation());
        operations[operation_index].committed_plan_digest =
            Some(committed_plan.deployment_plan_digest);
        self.rebuild(ControllerJournalMutationInput {
            allocation,
            committed_plan: Some(committed_plan),
            operations,
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: None,
            apply_history,
        })
    }

    /// Advances a Controller-local operation without changing its identity facts.
    pub(crate) fn transition_operation(
        &self,
        operation: ControllerOperationId,
        phase: ControllerOperationPhase,
        result: Option<ControllerReceiptRef>,
    ) -> Result<Self, ControllerJournalError> {
        let mut operations = self.operations.to_vec();
        let Some(record) = operations
            .iter_mut()
            .find(|record| record.operation == operation)
        else {
            return Err(ControllerJournalError::MissingPreparedOperation);
        };
        if !record.phase.permits(phase) {
            return Err(ControllerJournalError::InvalidOperationTransition);
        }
        let next = ControllerOperationRecord::try_new(
            record.operation,
            record.intent_digest,
            record.expected_revision,
            phase,
            result,
            record.committed_allocation_generation,
            record.committed_plan_digest,
        )?;
        if record.result.is_some() && record.result != next.result {
            return Err(ControllerJournalError::OperationFactChanged);
        }
        *record = next;
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations,
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: self.rollout.clone(),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Persists the exact signed acquire request before any Authority exchange.
    pub(crate) fn prepare_tenure_acquisition(
        &self,
        request: &AcquireTenureRequestV1,
        authority_domain_fingerprint: ControllerTenureAuthorityDomainFingerprint,
    ) -> Result<Self, ControllerJournalError> {
        if bytes_are_zero(authority_domain_fingerprint.value().as_bytes()) {
            return Err(ControllerJournalError::InvalidTenureAuthorityDomainFingerprint);
        }
        if request.scope() != self.scope {
            return Err(ControllerJournalError::TenureScopeMismatch);
        }
        for transaction in &self.tenure_transactions {
            let stored = transaction.request();
            let identity_collides = stored.operation_id() == request.operation_id()
                || stored.request_digest() == request.request_digest()
                || stored.intent_digest() == request.intent_digest()
                || stored.client_nonce() == request.client_nonce();
            if identity_collides {
                return if stored.canonical_bytes() == request.canonical_bytes()
                    && transaction.authority_domain_fingerprint() == authority_domain_fingerprint
                {
                    Ok(self.clone())
                } else if stored.canonical_bytes() == request.canonical_bytes() {
                    Err(ControllerJournalError::TenureAuthorityDomainMismatch)
                } else {
                    Err(ControllerJournalError::TenureTransactionConflict)
                };
            }
        }
        if self.tenure_transactions.len() == MAX_CONTROLLER_TENURE_TRANSACTIONS {
            return Err(ControllerJournalError::TenureCapacityExceeded);
        }
        if self.tenure_transactions.iter().any(|transaction| {
            matches!(
                transaction.phase(),
                ControllerTenurePhase::Prepared | ControllerTenurePhase::Uncertain
            )
        }) {
            return Err(ControllerJournalError::UnresolvedTenureTransactionExists);
        }
        let mut tenure_transactions = self.tenure_transactions.to_vec();
        tenure_transactions.push(ControllerTenureTransaction::try_new(
            request.clone(),
            authority_domain_fingerprint,
            ControllerTenurePhase::Prepared,
            None,
        )?);
        tenure_transactions.sort_unstable_by_key(ControllerTenureTransaction::operation_id);
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions,
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: self.rollout.clone(),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Records an ambiguous exchange result without changing request identity.
    pub(crate) fn mark_tenure_uncertain(
        &self,
        request: &AcquireTenureRequestV1,
    ) -> Result<Self, ControllerJournalError> {
        let mut tenure_transactions = self.tenure_transactions.to_vec();
        let Some(transaction) = tenure_transactions
            .iter_mut()
            .find(|transaction| transaction.operation_id() == request.operation_id())
        else {
            return Err(ControllerJournalError::MissingTenureTransaction);
        };
        if transaction.request().canonical_bytes() != request.canonical_bytes() {
            return Err(ControllerJournalError::TenureTransactionConflict);
        }
        match transaction.phase() {
            ControllerTenurePhase::Prepared => transaction.phase = ControllerTenurePhase::Uncertain,
            ControllerTenurePhase::Uncertain => return Ok(self.clone()),
            ControllerTenurePhase::Committed => {
                return Err(ControllerJournalError::InvalidTenureTransition);
            }
        }
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions,
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: self.rollout.clone(),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Commits the canonical response and its byte-exact embedded proof.
    pub(crate) fn commit_tenure_response(
        &self,
        request: &AcquireTenureRequestV1,
        response: &AcquireTenureResponseV1,
    ) -> Result<Self, ControllerJournalError> {
        let canonical_response =
            AcquireTenureResponseV1::decode_for_request(response.canonical_bytes(), request)?;
        if canonical_response != *response {
            return Err(ControllerJournalError::InvalidTenureTransaction);
        }
        let mut tenure_transactions = self.tenure_transactions.to_vec();
        let Some(transaction_index) = tenure_transactions
            .iter_mut()
            .position(|transaction| transaction.operation_id() == request.operation_id())
        else {
            return Err(ControllerJournalError::MissingTenureTransaction);
        };
        let transaction = &tenure_transactions[transaction_index];
        if transaction.request().canonical_bytes() != request.canonical_bytes() {
            return Err(ControllerJournalError::TenureTransactionConflict);
        }
        if transaction.phase() == ControllerTenurePhase::Committed {
            return if transaction.response() == Some(response) {
                Ok(self.clone())
            } else {
                Err(ControllerJournalError::TenureTransactionConflict)
            };
        }
        validate_new_tenure_proof_successor(
            &self.tenure_transactions,
            request.operation_id(),
            response.proof(),
        )?;
        let transaction = &mut tenure_transactions[transaction_index];
        transaction.phase = ControllerTenurePhase::Committed;
        transaction.response = Some(canonical_response);
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions,
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: self.rollout.clone(),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Pins or refreshes authenticated bootstrap evidence without changing the
    /// target/store/channel/manifest identity tuple.
    pub(crate) fn record_target_binding(
        &self,
        binding: ControllerTargetBinding,
    ) -> Result<Self, ControllerJournalError> {
        let plan = self
            .committed_plan
            .as_ref()
            .ok_or(ControllerJournalError::TargetBindingWithoutPlan)?;
        if binding.target != self.allocation.target()
            || binding.target != self.installed_manifest.target()
            || binding.target != plan.target
        {
            return Err(ControllerJournalError::TargetMismatch);
        }
        if binding.manifest_digest.value() != self.installed_manifest.manifest_digest()
            || binding.manifest_digest != plan.content.manifest_digest()
        {
            return Err(ControllerJournalError::ManifestBindingMismatch);
        }
        if let Some(previous) = &self.target_binding {
            binding.validate_successor_of(previous)?;
        }
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth: self.request_auth,
            target_binding: Some(binding),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: self.rollout.clone(),
            apply_history: self.apply_history.to_vec(),
        })
    }

    pub(crate) fn rotate_request_auth(
        &self,
        request_auth: ControllerRequestAuthPin,
    ) -> Result<Self, ControllerJournalError> {
        validate_auth_successor(request_auth, self.request_auth)?;
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: self.rollout.clone(),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// First rollout transaction: persist exact signed bytes before any send.
    pub(crate) fn record_signed_apply_intent(
        &self,
        input: ControllerSignedApplyIntentInput<'_>,
    ) -> Result<Self, ControllerJournalError> {
        let plan = self
            .committed_plan
            .as_ref()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        let binding = self
            .target_binding
            .as_ref()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        let intent = ControllerSignedApplyIntent::try_new(input, binding, self.request_auth)?;
        if self.apply_identity_exists(&intent)? {
            return Ok(self.clone());
        }
        if intent.target != self.allocation.target()
            || intent.target != plan.target
            || intent.target != binding.target
            || intent.source_plan_digest != plan.deployment_plan_digest
            || intent.request_auth != self.request_auth
            || intent.binding_manifest_digest != plan.content.manifest_digest()
            || binding.manifest_digest != plan.content.manifest_digest()
            || intent.binding_manifest_digest.value() != self.installed_manifest.manifest_digest()
        {
            return Err(ControllerJournalError::RolloutBindingMismatch);
        }
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: Some(ControllerRolloutRecord {
                signed_intent: intent,
                direct_terminal_receipt: None,
                reconcile_attempts: Box::new([]),
            }),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Persists one exact, already authenticated direct PXRT response.
    pub(crate) fn record_direct_terminal_receipt(
        &self,
        receipt: &ReferenceApplyTerminalReceiptV1,
    ) -> Result<Self, ControllerJournalError> {
        let mut rollout = self
            .rollout
            .clone()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        let direct =
            ControllerDirectTerminalReceipt::try_new(receipt.clone(), &rollout.signed_intent)?;
        if let Some(existing) = &rollout.direct_terminal_receipt {
            return if existing == &direct {
                Ok(self.clone())
            } else {
                Err(ControllerJournalError::DirectTerminalReceiptChanged)
            };
        }
        if let Some(decision) = rollout
            .reconcile_attempts
            .last()
            .and_then(|attempt| attempt.decision)
            .filter(|decision| decision.is_terminal())
            && !direct_terminal_decision_matches(&direct, decision)
        {
            return Err(ControllerJournalError::ConflictingTerminalEvidence);
        }
        rollout.direct_terminal_receipt = Some(direct);
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: Some(rollout),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Persists the exact signed PXQR and request-time verification baseline
    /// before any query transport send.
    pub(crate) fn prepare_query_request(
        &self,
        request: &ReferenceQueryRequestV1,
    ) -> Result<Self, ControllerJournalError> {
        let binding = self
            .target_binding
            .as_ref()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        let mut rollout = self
            .rollout
            .clone()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        let source_scope = paraegox_runtime_contracts::provenance::SourceScopeRef::from_bytes(
            *self.scope.as_bytes(),
        );
        let prepared = ControllerPreparedQuery::try_new(
            request.clone(),
            binding,
            self.request_auth,
            source_scope,
            &rollout.signed_intent,
        )?;
        for record in &self.apply_history {
            for attempt in &record.reconcile_attempts {
                let existing = attempt.prepared.request();
                let collides = existing.query_id() == request.query_id()
                    || existing.request_digest() == request.request_digest()
                    || existing.authentication().claim().nonce()
                        == request.authentication().claim().nonce();
                if collides {
                    return Err(ControllerJournalError::QueryIdentityConflict);
                }
            }
        }
        for (index, attempt) in rollout.reconcile_attempts.iter().enumerate() {
            let existing = attempt.prepared.request();
            let collides = existing.query_id() == request.query_id()
                || existing.request_digest() == request.request_digest()
                || existing.authentication().claim().nonce()
                    == request.authentication().claim().nonce();
            if collides {
                if existing.canonical_wire() != request.canonical_wire() {
                    return Err(ControllerJournalError::QueryIdentityConflict);
                }
                if attempt.closure.is_some() {
                    return Err(ControllerJournalError::QueryAlreadyClosed);
                }
                let is_latest_open = index + 1 == rollout.reconcile_attempts.len()
                    && attempt.observation.is_none()
                    && attempt.decision.is_none();
                return if is_latest_open {
                    Ok(self.clone())
                } else {
                    Err(ControllerJournalError::QueryIdentityConflict)
                };
            }
        }
        if let Some(previous) = rollout.reconcile_attempts.last() {
            if !previous.is_closed_without_response()
                && (previous.observation.is_none() || previous.decision.is_none())
            {
                return Err(ControllerJournalError::DanglingQueryObservation);
            }
            if terminal_query_decision_is_current(previous, binding) {
                return Err(ControllerJournalError::EvidenceAfterTerminalDecision);
            }
        }
        if rollout.reconcile_attempts.len() == MAX_RECONCILE_ATTEMPTS {
            return Err(ControllerJournalError::ReconcileCapacityExceeded);
        }
        let mut attempts = rollout.reconcile_attempts.to_vec();
        attempts.push(ControllerReconcileAttempt {
            prepared,
            observation: None,
            closure: None,
            decision: None,
        });
        rollout.reconcile_attempts = attempts.into_boxed_slice();
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: Some(rollout),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Persists one exact PXQS after signature-first client validation. This is
    /// a separate successor from both the prepared PXQR and any later decision.
    pub(crate) fn record_query_response(
        &self,
        response: &ReferenceQueryResponseV1,
        channel_peer: ReferenceChannelBindingV1,
    ) -> Result<Self, ControllerJournalError> {
        let mut rollout = self
            .rollout
            .clone()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        let attempt_index = rollout
            .reconcile_attempts
            .len()
            .checked_sub(1)
            .ok_or(ControllerJournalError::MissingPreparedQuery)?;
        let attempt = &rollout.reconcile_attempts[attempt_index];
        if attempt.closure.is_some() {
            return Err(ControllerJournalError::QueryAlreadyClosed);
        }
        if attempt.prepared.request().query_id() != response.query_id() {
            return Err(ControllerJournalError::QueryIdentityConflict);
        }
        let observation =
            ControllerQueryObservation::try_new(response.clone(), channel_peer, &attempt.prepared)?;
        if let Some(existing) = &attempt.observation {
            return if existing == &observation {
                Ok(self.clone())
            } else {
                Err(ControllerJournalError::QueryEvidenceChanged)
            };
        }
        let sequence = observation.query_snapshot_sequence();
        if sequence < self.query_snapshot_high_water {
            return Err(ControllerJournalError::QuerySequenceRegression);
        }
        if let Some(previous) = rollout.reconcile_attempts[..attempt_index]
            .iter()
            .rev()
            .find_map(|prior| prior.observation.as_ref())
            && sequence < previous.query_snapshot_sequence()
        {
            return Err(ControllerJournalError::QuerySequenceRegression);
        }
        rollout.reconcile_attempts[attempt_index].observation = Some(observation);
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water.max(sequence),
            rollout: Some(rollout),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Closes the latest durable PXQR without manufacturing a PXQS or rollout
    /// decision. The original request/id/nonce remain append-only evidence.
    pub(crate) fn record_query_closure(
        &self,
        closure: ControllerQueryClosureKind,
    ) -> Result<Self, ControllerJournalError> {
        let mut rollout = self
            .rollout
            .clone()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        let attempt = rollout
            .reconcile_attempts
            .last_mut()
            .ok_or(ControllerJournalError::MissingPreparedQuery)?;
        if attempt.observation.is_some() || attempt.decision.is_some() {
            return Err(ControllerJournalError::InvalidQueryClosure);
        }
        if let Some(existing) = attempt.closure {
            return if existing == closure {
                Ok(self.clone())
            } else {
                Err(ControllerJournalError::QueryClosureChanged)
            };
        }
        attempt.closure = Some(closure);
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: Some(rollout),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Binds a decision to an already-durable exact PXQS in a later snapshot.
    pub(crate) fn record_rollout_decision(
        &self,
        observed: ControllerObservedTarget,
        receipt: Option<ControllerReceiptRef>,
    ) -> Result<Self, ControllerJournalError> {
        let mut rollout = self
            .rollout
            .clone()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        if rollout.has_conflicting_terminal_observation() {
            return Err(ControllerJournalError::ConflictingTerminalEvidence);
        }
        let attempt = rollout
            .reconcile_attempts
            .last_mut()
            .ok_or(ControllerJournalError::DanglingRolloutDecision)?;
        if attempt.closure.is_some() {
            return Err(ControllerJournalError::InvalidQueryClosure);
        }
        let observation = attempt
            .observation
            .as_ref()
            .ok_or(ControllerJournalError::QueryNotCommittedBeforeDecision)?;
        let decision = ControllerRolloutDecision::try_new(observation, observed, receipt)?;
        if let Some(direct) = rollout.direct_terminal_receipt.as_ref() {
            if decision.is_terminal() {
                if !direct_terminal_decision_matches(direct, decision) {
                    return Err(ControllerJournalError::ConflictingTerminalEvidence);
                }
            } else if observed == ControllerObservedTarget::Prepared
                && !direct_follows_prepared_query(direct, attempt, decision)
            {
                return Err(ControllerJournalError::ConflictingTerminalEvidence);
            }
        }
        if let Some(previous) = attempt.decision {
            return if previous == decision {
                Ok(self.clone())
            } else {
                Err(ControllerJournalError::RolloutDecisionAlreadyCommitted)
            };
        }
        attempt.decision = Some(decision);
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            tenure_transactions: self.tenure_transactions.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: Some(rollout),
            apply_history: self.apply_history.to_vec(),
        })
    }

    fn rebuild(
        &self,
        input: ControllerJournalMutationInput,
    ) -> Result<Self, ControllerJournalError> {
        Self::try_from_stored(ControllerJournalStateInput {
            scope: self.scope,
            plan_lineage: self.plan_lineage,
            allocation: input.allocation,
            installed_manifest: self.installed_manifest.clone(),
            committed_plan: input.committed_plan,
            operations: input.operations,
            tenure_transactions: input.tenure_transactions,
            request_auth: input.request_auth,
            target_binding: input.target_binding,
            query_snapshot_high_water: input.query_snapshot_high_water,
            rollout: input.rollout,
            apply_history: input.apply_history,
        })
    }

    fn apply_identity_exists(
        &self,
        intent: &ControllerSignedApplyIntent,
    ) -> Result<bool, ControllerJournalError> {
        if let Some(record) = &self.rollout {
            let stored = &record.signed_intent;
            if stored.apply_operation == intent.apply_operation
                || stored.request_digest == intent.request_digest
            {
                return if stored == intent {
                    Ok(true)
                } else {
                    Err(ControllerJournalError::ApplyOperationConflict)
                };
            }
            return Err(ControllerJournalError::CurrentRolloutExists);
        }
        for record in &self.apply_history {
            let stored = &record.signed_intent;
            if stored.apply_operation == intent.apply_operation
                || stored.request_digest == intent.request_digest
            {
                return if stored == intent {
                    Ok(true)
                } else {
                    Err(ControllerJournalError::ApplyOperationConflict)
                };
            }
        }
        Ok(false)
    }

    fn apply_history_for_plan_commit(
        &self,
    ) -> Result<Vec<ControllerRolloutRecord>, ControllerJournalError> {
        let Some(rollout) = &self.rollout else {
            return Ok(self.apply_history.to_vec());
        };
        let binding = self
            .target_binding
            .as_ref()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        if !rollout_permits_plan_advance(rollout, binding)? {
            return Err(ControllerJournalError::NonTerminalRolloutBlocksPlanCommit);
        }
        if self.apply_history.len() == MAX_APPLY_OPERATION_HISTORY {
            return Err(ControllerJournalError::ApplyHistoryCapacityExceeded);
        }
        for stored in &self.apply_history {
            if stored.signed_intent.apply_operation == rollout.signed_intent.apply_operation
                || stored.signed_intent.request_digest == rollout.signed_intent.request_digest
            {
                return Err(ControllerJournalError::ApplyOperationConflict);
            }
        }
        let mut history = self.apply_history.to_vec();
        history.push(rollout.clone());
        Ok(history)
    }

    /// Returns the current committed plan revision, or zero before first commit.
    pub(crate) fn current_revision(&self) -> u64 {
        self.committed_plan
            .as_ref()
            .map_or(0, |plan| plan.revision.value())
    }

    /// Returns the immutable installer artifact pinned in sequence one.
    pub(crate) const fn installed_manifest(&self) -> &ControllerInstalledManifestPin {
        &self.installed_manifest
    }

    /// Returns the immutable desired-state scope pinned in sequence one.
    pub(crate) const fn scope(&self) -> DeploymentScopeId {
        self.scope
    }

    /// Returns the immutable plan lineage pinned in sequence one.
    pub(crate) const fn plan_lineage(&self) -> DeploymentId {
        self.plan_lineage
    }

    /// Returns the Controller-owned allocation snapshot consumed by the Planner.
    pub(crate) const fn allocation(&self) -> &StableAllocationSnapshot {
        &self.allocation
    }

    /// Returns the exact Runtime request-auth pin persisted by sequence one.
    pub(crate) const fn request_auth(&self) -> ControllerRequestAuthPin {
        self.request_auth
    }

    /// Returns the last durable authenticated Runtime binding, if any.
    #[must_use]
    pub(crate) const fn target_binding(&self) -> Option<&ControllerTargetBinding> {
        self.target_binding.as_ref()
    }

    /// Returns the current committed deployment-plan digest when one exists.
    pub(crate) fn committed_plan_digest(&self) -> Option<SourcePlanDigest> {
        self.committed_plan
            .as_ref()
            .map(|plan| plan.deployment_plan_digest)
    }

    /// Returns the exact typed committed plan used by the unique PXAR producer.
    #[must_use]
    pub(crate) const fn committed_plan(&self) -> Option<&ControllerCommittedPlan> {
        self.committed_plan.as_ref()
    }

    /// Returns the exact request already committed before send, when present.
    #[must_use]
    pub(crate) fn current_signed_apply_intent(&self) -> Option<&ControllerSignedApplyIntent> {
        self.rollout.as_ref().map(|rollout| &rollout.signed_intent)
    }

    /// Returns the latest exact PXQR once it is durable. A missing response is
    /// intentionally still returned as recovery evidence; restart code must
    /// explicitly close lost resident authority before a later call may
    /// allocate a fresh query identity.
    #[must_use]
    pub(crate) fn current_prepared_query(&self) -> Option<&ControllerPreparedQuery> {
        self.rollout
            .as_ref()?
            .reconcile_attempts
            .last()
            .map(|attempt| &attempt.prepared)
    }

    /// Returns the latest exact PXQS only after the response has its own
    /// durable journal successor.
    #[must_use]
    pub(crate) fn current_query_observation(&self) -> Option<&ControllerQueryObservation> {
        self.rollout
            .as_ref()?
            .reconcile_attempts
            .last()?
            .observation
            .as_ref()
    }

    /// Returns the stable no-response closure for the latest PXQR, if any.
    #[must_use]
    pub(crate) fn current_query_closure(&self) -> Option<ControllerQueryClosureKind> {
        self.rollout.as_ref()?.reconcile_attempts.last()?.closure
    }

    #[must_use]
    pub(crate) fn current_query_is_open(&self) -> bool {
        self.rollout
            .as_ref()
            .and_then(|rollout| rollout.reconcile_attempts.last())
            .is_some_and(|attempt| {
                attempt.observation.is_none()
                    && attempt.closure.is_none()
                    && attempt.decision.is_none()
            })
    }

    #[must_use]
    pub(crate) fn current_query_has_decision(&self) -> bool {
        self.rollout
            .as_ref()
            .and_then(|rollout| rollout.reconcile_attempts.last())
            .is_some_and(|attempt| attempt.decision.is_some())
    }

    /// Reports only a terminal query-derived decision. A direct PXRT remains
    /// historical operation evidence and does not suppress a fresh current-
    /// epoch PXQR.
    #[must_use]
    pub(crate) fn current_query_decision_is_terminal(&self) -> bool {
        let Some(binding) = self.target_binding.as_ref() else {
            return false;
        };
        self.rollout
            .as_ref()
            .and_then(|rollout| rollout.reconcile_attempts.last())
            .is_some_and(|attempt| terminal_query_decision_is_current(attempt, binding))
    }

    /// Reports whether the current exact apply operation already has durable
    /// terminal evidence. Callers must suppress any second transport send.
    #[must_use]
    pub(crate) fn current_apply_is_terminal(&self) -> bool {
        self.rollout
            .as_ref()
            .is_some_and(ControllerRolloutRecord::is_terminal)
    }

    /// Returns the exact direct PXRT when it is the current terminal evidence.
    #[must_use]
    pub(crate) fn current_direct_terminal_receipt(
        &self,
    ) -> Option<&ReferenceApplyTerminalReceiptV1> {
        self.rollout
            .as_ref()?
            .direct_terminal_receipt
            .as_ref()
            .map(ControllerDirectTerminalReceipt::receipt)
    }

    /// Returns the exact active desired Slice only when the current rollout is
    /// independently eligible to advance the plan. Direct PXRT remains
    /// separately available for audit; a lost PXRT can be replaced only by an
    /// exact current-epoch terminal Active query decision.
    pub(crate) fn current_active_target_slice_digest_for_plan_advance(
        &self,
    ) -> Result<Option<TargetSliceDigest>, ControllerJournalError> {
        let Some(rollout) = self.rollout.as_ref() else {
            return Ok(None);
        };
        let binding = self
            .target_binding
            .as_ref()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        if !rollout_permits_plan_advance(rollout, binding)? {
            return Ok(None);
        }
        if let Some(attempt) = rollout.reconcile_attempts.last()
            && attempt.decision.is_some_and(|decision| {
                decision.is_terminal() && decision.observed == ControllerObservedTarget::Active
            })
            && let Some(ReferenceQueryDesiredHeadV1::OneSourceLoop {
                target_slice_digest,
                ..
            }) = attempt
                .observation
                .as_ref()
                .map(|observation| observation.response().facts().desired().head())
        {
            return Ok(Some(target_slice_digest));
        }
        Ok(rollout
            .direct_terminal_receipt
            .as_ref()
            .filter(|direct| {
                direct_terminal_is_success(direct, &rollout.signed_intent)
                    && direct.receipt().facts().outcome()
                        == ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
            })
            .and_then(|direct| direct.receipt().facts().desired_head_digest()))
    }

    /// Returns the exact direct PXRT from the last plan-chronological archive.
    ///
    /// The full archived rollout chronology is revalidated before selecting
    /// its tail. A terminal rollout backed only by opaque reconcile evidence
    /// is not promoted into a direct Runtime receipt.
    pub(crate) fn last_archived_direct_terminal_receipt(
        &self,
    ) -> Result<Option<&ReferenceApplyTerminalReceiptV1>, ControllerJournalError> {
        validate_apply_history(
            &self.apply_history,
            self.rollout.as_ref(),
            ApplyHistoryValidationContext {
                scope: self.scope,
                plan_lineage: self.plan_lineage,
                target: self.allocation.target(),
                binding: self.target_binding.as_ref(),
                operations: &self.operations,
                current_revision: self.current_revision(),
                current_shape: self
                    .committed_plan
                    .as_ref()
                    .map(|plan| plan.content.shape()),
                query_snapshot_high_water: self.query_snapshot_high_water,
            },
        )?;
        let Some(rollout) = self.apply_history.last() else {
            return Ok(None);
        };
        let receipt = rollout
            .direct_terminal_receipt
            .as_ref()
            .ok_or(ControllerJournalError::TerminalDesiredHeadUnavailable)?;
        Ok(Some(receipt.receipt()))
    }

    /// Returns the most recent terminal desired slice for the next apply CAS.
    pub(crate) fn last_terminal_target_slice_digest(
        &self,
    ) -> Result<Option<TargetSliceDigest>, ControllerJournalError> {
        validate_apply_history(
            &self.apply_history,
            self.rollout.as_ref(),
            ApplyHistoryValidationContext {
                scope: self.scope,
                plan_lineage: self.plan_lineage,
                target: self.allocation.target(),
                binding: self.target_binding.as_ref(),
                operations: &self.operations,
                current_revision: self.current_revision(),
                current_shape: self
                    .committed_plan
                    .as_ref()
                    .map(|plan| plan.content.shape()),
                query_snapshot_high_water: self.query_snapshot_high_water,
            },
        )?;
        let Some(rollout) = self.apply_history.last() else {
            return Ok(None);
        };
        if let Some(attempt) = rollout.reconcile_attempts.last()
            && attempt
                .decision
                .is_some_and(ControllerRolloutDecision::is_terminal)
            && let Some(head) = attempt
                .observation
                .as_ref()
                .map(|observation| observation.response().facts().desired().head())
        {
            return Ok(match head {
                ReferenceQueryDesiredHeadV1::OneSourceLoop {
                    target_slice_digest,
                    ..
                }
                | ReferenceQueryDesiredHeadV1::EmptyDeactivate {
                    target_slice_digest,
                    ..
                } => Some(target_slice_digest),
                ReferenceQueryDesiredHeadV1::None => None,
            });
        }
        Ok(rollout
            .direct_terminal_receipt
            .as_ref()
            .filter(|direct| direct_terminal_is_success(direct, &rollout.signed_intent))
            .and_then(|direct| direct.receipt().facts().desired_head_digest()))
    }

    /// Returns the exact desired Slice from the last archived Active rollout,
    /// whether its terminal evidence was a direct PXRT or a current-epoch
    /// terminal PXQS decision.
    pub(crate) fn last_archived_active_target_slice_digest(
        &self,
    ) -> Result<Option<TargetSliceDigest>, ControllerJournalError> {
        let _ = self.last_terminal_target_slice_digest()?;
        let Some(rollout) = self.apply_history.last() else {
            return Ok(None);
        };
        if let Some(attempt) = rollout.reconcile_attempts.last()
            && attempt.decision.is_some_and(|decision| {
                decision.is_terminal() && decision.observed == ControllerObservedTarget::Active
            })
            && let Some(ReferenceQueryDesiredHeadV1::OneSourceLoop {
                target_slice_digest,
                ..
            }) = attempt
                .observation
                .as_ref()
                .map(|observation| observation.response().facts().desired().head())
        {
            return Ok(Some(target_slice_digest));
        }
        Ok(rollout
            .direct_terminal_receipt
            .as_ref()
            .filter(|direct| {
                direct_terminal_is_success(direct, &rollout.signed_intent)
                    && direct.receipt().facts().outcome()
                        == ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
            })
            .and_then(|direct| direct.receipt().facts().desired_head_digest()))
    }

    /// Returns the globally highest committed Authority proof only when its
    /// writer is the selected writer. A later proof for another writer fences
    /// every older writer immediately.
    #[must_use]
    pub(crate) fn latest_committed_tenure_proof(
        &self,
        writer: PlanWriterRef,
    ) -> Option<&WriterTenureProof> {
        self.tenure_transactions
            .iter()
            .filter_map(ControllerTenureTransaction::committed_proof)
            .max_by_key(|proof| proof.claim().epoch().value())
            .filter(|proof| proof.claim().writer() == writer)
    }

    /// Returns the exact transaction carrying the globally highest committed
    /// proof. Equal-epoch ambiguity is rejected independently of the state
    /// validator.
    pub(crate) fn global_latest_committed_tenure_transaction(
        &self,
    ) -> Result<Option<&ControllerTenureTransaction>, ControllerJournalError> {
        let mut selected: Option<&ControllerTenureTransaction> = None;
        for transaction in &self.tenure_transactions {
            if transaction.phase() != ControllerTenurePhase::Committed {
                continue;
            }
            let proof = transaction
                .committed_proof()
                .ok_or(ControllerJournalError::InvalidTenureTransaction)?;
            let Some(previous) = selected else {
                selected = Some(transaction);
                continue;
            };
            let previous_proof = previous
                .committed_proof()
                .ok_or(ControllerJournalError::InvalidTenureTransaction)?;
            match proof
                .claim()
                .epoch()
                .value()
                .cmp(&previous_proof.claim().epoch().value())
            {
                core::cmp::Ordering::Greater => selected = Some(transaction),
                core::cmp::Ordering::Equal if transaction != previous => {
                    return Err(ControllerJournalError::TenureEpochConflict);
                }
                core::cmp::Ordering::Equal | core::cmp::Ordering::Less => {}
            }
        }
        Ok(selected)
    }

    /// Returns the globally latest transaction only when it belongs to the
    /// selected writer. This preserves the existing process call shape while
    /// preventing replay of a writer fenced by a later cross-writer tenure.
    pub(crate) fn latest_committed_tenure_transaction(
        &self,
        writer: PlanWriterRef,
    ) -> Result<Option<&ControllerTenureTransaction>, ControllerJournalError> {
        Ok(self
            .global_latest_committed_tenure_transaction()?
            .filter(|transaction| {
                transaction
                    .committed_proof()
                    .is_some_and(|proof| proof.claim().writer() == writer)
            }))
    }

    /// Confirms that an exact proof embedded in a durable apply request came
    /// from one already committed Authority response in this journal.
    #[must_use]
    pub(crate) fn contains_committed_tenure_proof(&self, proof: &WriterTenureProof) -> bool {
        self.latest_committed_tenure_proof(proof.claim().writer()) == Some(proof)
    }

    /// Returns one exact tenure transaction by its canonical operation ID.
    pub(crate) fn tenure_transaction(
        &self,
        operation_id: AcquireTenureOperationId,
    ) -> Option<&ControllerTenureTransaction> {
        self.tenure_transactions
            .binary_search_by_key(&operation_id, ControllerTenureTransaction::operation_id)
            .ok()
            .map(|index| &self.tenure_transactions[index])
    }

    /// Returns the unique exact Prepared/Uncertain tenure transaction for
    /// crash replay. The state validator already forbids more than one; this
    /// accessor independently fails closed rather than selecting arbitrarily.
    pub(crate) fn current_unresolved_tenure_transaction(
        &self,
    ) -> Result<Option<&ControllerTenureTransaction>, ControllerJournalError> {
        let mut unresolved = self.tenure_transactions.iter().filter(|transaction| {
            matches!(
                transaction.phase(),
                ControllerTenurePhase::Prepared | ControllerTenurePhase::Uncertain
            )
        });
        let current = unresolved.next();
        if unresolved.next().is_some() {
            return Err(ControllerJournalError::UnresolvedTenureTransactionExists);
        }
        Ok(current)
    }

    fn is_exact_fresh(&self) -> bool {
        self.committed_plan.is_none()
            && self.operations.is_empty()
            && self.tenure_transactions.is_empty()
            && self.target_binding.is_none()
            && self.query_snapshot_high_water == 0
            && self.rollout.is_none()
            && self.apply_history.is_empty()
            && self.allocation.generation() == 0
            && self.allocation.high_water() == 0
            && self.allocation.records().is_empty()
    }

    fn validate_candidate_identity(
        &self,
        candidate: &DeploymentPlanCandidate,
    ) -> Result<(), ControllerJournalError> {
        if candidate.content().target() != self.allocation.target()
            || candidate.content().target() != self.installed_manifest.target()
            || self
                .target_binding
                .as_ref()
                .is_some_and(|binding| binding.target != candidate.content().target())
        {
            return Err(ControllerJournalError::CandidateTargetMismatch);
        }
        if candidate.content().manifest_digest().value()
            != self.installed_manifest.manifest_digest()
            || self.target_binding.as_ref().is_some_and(|binding| {
                binding.manifest_digest != candidate.content().manifest_digest()
            })
        {
            return Err(ControllerJournalError::CandidateManifestMismatch);
        }
        if PlanContentDigest::try_for_content(candidate.content())
            .map_err(|_| ControllerJournalError::InvalidPlanContent)?
            != candidate.content_digest()
        {
            return Err(ControllerJournalError::PlanContentDigestMismatch);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ControllerJournalError> {
        if bytes_are_zero(self.scope.as_bytes()) || bytes_are_zero(self.plan_lineage.as_bytes()) {
            return Err(ControllerJournalError::InvalidPlanIdentity);
        }
        if self.allocation.target() != self.installed_manifest.target() {
            return Err(ControllerJournalError::InstalledManifestTargetMismatch);
        }
        if self.allocation.records().len() > MAX_ALLOCATION_RECORDS {
            return Err(ControllerJournalError::AllocationCapacityExceeded);
        }
        if self.operations.len() > MAX_CONTROLLER_OPERATIONS {
            return Err(ControllerJournalError::OperationCapacityExceeded);
        }
        if self.tenure_transactions.len() > MAX_CONTROLLER_TENURE_TRANSACTIONS {
            return Err(ControllerJournalError::TenureCapacityExceeded);
        }
        if self.apply_history.len() > MAX_APPLY_OPERATION_HISTORY {
            return Err(ControllerJournalError::ApplyHistoryCapacityExceeded);
        }
        let controller_ledger_records = self
            .operations
            .len()
            .checked_add(self.apply_history.len())
            .and_then(|count| count.checked_add(usize::from(self.rollout.is_some())))
            .ok_or(ControllerJournalError::LengthOverflow)?;
        if controller_ledger_records > MAX_CONTROLLER_LEDGER_RECORDS {
            return Err(ControllerJournalError::ControllerLedgerCapacityExceeded);
        }
        let maximum_reachable_history = self.current_revision().saturating_sub(1);
        if u64::try_from(self.apply_history.len())
            .map_err(|_| ControllerJournalError::LengthOverflow)?
            > maximum_reachable_history
        {
            return Err(ControllerJournalError::ApplyHistoryRevisionMismatch);
        }
        validate_request_auth_pin(self.request_auth)?;
        let current_revision = self.current_revision();
        validate_operations(
            &self.operations,
            current_revision,
            self.allocation.generation(),
        )?;
        validate_tenure_transactions(&self.tenure_transactions, self.scope)?;
        if let Some(plan) = &self.committed_plan {
            if plan.scope != self.scope
                || plan.plan != self.plan_lineage
                || plan.target != self.allocation.target()
            {
                return Err(ControllerJournalError::PlanLineageChanged);
            }
            if plan.content.manifest_digest().value() != self.installed_manifest.manifest_digest() {
                return Err(ControllerJournalError::CandidateManifestMismatch);
            }
            let Some(operation) = self
                .operations
                .iter()
                .find(|record| record.operation == plan.commit_operation)
            else {
                return Err(ControllerJournalError::DanglingPlanOperation);
            };
            if operation.intent_digest != plan.commit_intent_digest
                || operation.expected_revision.checked_add(1) != Some(plan.revision.value())
                || operation.phase != ControllerOperationPhase::Committed
                || operation.committed_allocation_generation != Some(self.allocation.generation())
                || operation.committed_plan_digest != Some(plan.deployment_plan_digest)
            {
                return Err(ControllerJournalError::DanglingPlanOperation);
            }
            validate_plan_allocation_coherence(plan, &self.allocation)?;
        } else {
            if self.allocation.generation() != 0
                || self.allocation.high_water() != 0
                || !self.allocation.records().is_empty()
            {
                return Err(ControllerJournalError::AllocationWithoutCommittedPlan);
            }
            if self
                .operations
                .iter()
                .any(|record| record.phase == ControllerOperationPhase::Committed)
            {
                return Err(ControllerJournalError::CommittedOperationWithoutPlan);
            }
        }
        if let Some(binding) = &self.target_binding {
            let plan = self
                .committed_plan
                .as_ref()
                .ok_or(ControllerJournalError::TargetBindingWithoutPlan)?;
            if binding.target != self.allocation.target()
                || binding.target != self.installed_manifest.target()
                || binding.target != plan.target
            {
                return Err(ControllerJournalError::TargetMismatch);
            }
            if binding.manifest_digest.value() != self.installed_manifest.manifest_digest()
                || binding.manifest_digest != plan.content.manifest_digest()
            {
                return Err(ControllerJournalError::ManifestBindingMismatch);
            }
        }
        validate_apply_history(
            &self.apply_history,
            self.rollout.as_ref(),
            ApplyHistoryValidationContext {
                scope: self.scope,
                plan_lineage: self.plan_lineage,
                target: self.allocation.target(),
                binding: self.target_binding.as_ref(),
                operations: &self.operations,
                current_revision,
                current_shape: self
                    .committed_plan
                    .as_ref()
                    .map(|plan| plan.content.shape()),
                query_snapshot_high_water: self.query_snapshot_high_water,
            },
        )?;
        if let Some(rollout) = &self.rollout {
            let plan = self
                .committed_plan
                .as_ref()
                .ok_or(ControllerJournalError::DanglingRollout)?;
            let binding = self
                .target_binding
                .as_ref()
                .ok_or(ControllerJournalError::DanglingRollout)?;
            let intent = &rollout.signed_intent;
            if intent.target != self.allocation.target()
                || intent.target != plan.target
                || intent.target != binding.target
                || intent.source_plan_digest != plan.deployment_plan_digest
                || intent.runtime_store_instance_id != binding.runtime_store_instance_id
                || intent.binding_channel_auth_fingerprint != binding.channel_auth_fingerprint
                || intent.binding_manifest_digest != binding.manifest_digest
                || intent.binding_manifest_digest != plan.content.manifest_digest()
                || intent.binding_manifest_digest.value()
                    != self.installed_manifest.manifest_digest()
            {
                return Err(ControllerJournalError::RolloutBindingMismatch);
            }
        }
        validate_controller_snapshot_size(self)?;
        Ok(())
    }

    fn validate_successor_of(&self, previous: &Self) -> Result<(), ControllerJournalError> {
        if self.scope != previous.scope || self.plan_lineage != previous.plan_lineage {
            return Err(ControllerJournalError::PlanLineageChanged);
        }
        if self.installed_manifest != previous.installed_manifest {
            return Err(ControllerJournalError::InstalledManifestPinChanged);
        }
        self.allocation
            .validate_successor_of(&previous.allocation)
            .map_err(|_| ControllerJournalError::InvalidAllocationTransition)?;
        validate_operation_successors(
            &self.operations,
            &previous.operations,
            previous.current_revision(),
        )?;
        validate_tenure_transaction_successors(
            &self.tenure_transactions,
            &previous.tenure_transactions,
        )?;
        validate_auth_successor(self.request_auth, previous.request_auth)?;
        if self.query_snapshot_high_water < previous.query_snapshot_high_water {
            return Err(ControllerJournalError::QuerySequenceRegression);
        }
        match (&previous.target_binding, &self.target_binding) {
            (None, _) => {}
            (Some(_), None) => return Err(ControllerJournalError::TargetBindingRemoved),
            (Some(old), Some(new)) => new.validate_successor_of(old)?,
        }

        let plan_changed = match (&previous.committed_plan, &self.committed_plan) {
            (None, None) => false,
            (Some(_), None) => return Err(ControllerJournalError::CommittedPlanRemoved),
            (None, Some(next)) => {
                if next.revision.value() != 1 {
                    return Err(ControllerJournalError::RevisionNotNext);
                }
                validate_plan_operation_transition(next, previous, self)?;
                true
            }
            (Some(old), Some(next)) if old == next => false,
            (Some(old), Some(next)) => {
                let expected = old
                    .revision
                    .value()
                    .checked_add(1)
                    .ok_or(ControllerJournalError::RevisionExhausted)?;
                if next.revision.value() != expected {
                    return Err(ControllerJournalError::RevisionNotNext);
                }
                validate_plan_operation_transition(next, previous, self)?;
                true
            }
        };
        if !plan_changed && self.allocation != previous.allocation {
            return Err(ControllerJournalError::AllocationWithoutPlanCommit);
        }

        if previous.rollout.is_none() && self.rollout.is_some() {
            if previous.target_binding.is_none() {
                return Err(ControllerJournalError::TargetBindingNotCommittedFirst);
            }
            if self.request_auth != previous.request_auth {
                return Err(ControllerJournalError::AuthPinNotCommittedFirst);
            }
        }

        validate_apply_history_successor(
            &self.apply_history,
            &previous.apply_history,
            self.rollout.as_ref(),
            previous.rollout.as_ref(),
            self.target_binding.as_ref(),
            plan_changed,
        )?;
        validate_rollout_successor(
            self.rollout.as_ref(),
            previous.rollout.as_ref(),
            self.target_binding.as_ref(),
            plan_changed,
        )?;
        self.validate()
    }
}

fn validate_plan_operation_transition(
    plan: &ControllerCommittedPlan,
    previous: &ControllerJournalState,
    next: &ControllerJournalState,
) -> Result<(), ControllerJournalError> {
    let Some(old_operation) = previous
        .operations
        .iter()
        .find(|record| record.operation == plan.commit_operation)
    else {
        return Err(ControllerJournalError::MissingPreparedOperation);
    };
    let Some(new_operation) = next
        .operations
        .iter()
        .find(|record| record.operation == plan.commit_operation)
    else {
        return Err(ControllerJournalError::DanglingPlanOperation);
    };
    if old_operation.phase != ControllerOperationPhase::Prepared
        || new_operation.phase != ControllerOperationPhase::Committed
        || old_operation.intent_digest != plan.commit_intent_digest
        || old_operation.expected_revision != previous.current_revision()
        || old_operation.committed_allocation_generation.is_some()
        || old_operation.committed_plan_digest.is_some()
        || new_operation.committed_allocation_generation != Some(next.allocation.generation())
        || new_operation.committed_plan_digest != Some(plan.deployment_plan_digest)
    {
        return Err(ControllerJournalError::InvalidOperationTransition);
    }
    Ok(())
}

fn validate_plan_allocation_coherence(
    plan: &ControllerCommittedPlan,
    allocation: &StableAllocationSnapshot,
) -> Result<(), ControllerJournalError> {
    let active = allocation
        .records()
        .iter()
        .filter(|record| record.state() == AllocationState::Active)
        .collect::<Vec<_>>();
    match (
        plan.content().shape(),
        plan.content().stable_allocation_subject(),
    ) {
        (TargetIntent::EmptyTarget, None) if active.is_empty() => Ok(()),
        (TargetIntent::OneSourceLoop, Some((key, instance, domain)))
            if active.len() == 1
                && active[0].key() == key.as_bytes()
                && active[0].instance() == instance
                && active[0].domain() == domain =>
        {
            Ok(())
        }
        _ => Err(ControllerJournalError::PlanAllocationMismatch),
    }
}

trait CommittedPlanContent {
    fn content(&self) -> &PlanContent;
}

impl CommittedPlanContent for ControllerCommittedPlan {
    fn content(&self) -> &PlanContent {
        &self.content
    }
}

fn validate_operation(record: &ControllerOperationRecord) -> Result<(), ControllerJournalError> {
    if bytes_are_zero(record.operation.as_bytes())
        || bytes_are_zero(record.intent_digest.value().as_bytes())
        || record
            .result
            .is_some_and(|result| bytes_are_zero(result.as_bytes()))
    {
        return Err(ControllerJournalError::InvalidOperationIdentity);
    }
    if matches!(
        record.phase,
        ControllerOperationPhase::Uncertain | ControllerOperationPhase::Terminal
    ) != record.result.is_some()
    {
        return Err(ControllerJournalError::InvalidOperationResult);
    }
    if (record.phase == ControllerOperationPhase::Committed)
        != record.committed_allocation_generation.is_some()
    {
        return Err(ControllerJournalError::InvalidCommittedAllocationGeneration);
    }
    if (record.phase == ControllerOperationPhase::Committed)
        != record.committed_plan_digest.is_some()
        || record
            .committed_plan_digest
            .is_some_and(|digest| bytes_are_zero(digest.value().as_bytes()))
    {
        return Err(ControllerJournalError::InvalidCommittedPlanDigest);
    }
    Ok(())
}

fn validate_operations(
    records: &[ControllerOperationRecord],
    current_revision: u64,
    allocation_generation: u64,
) -> Result<(), ControllerJournalError> {
    let mut last = None;
    let mut committed = Vec::new();
    let mut committed_plan_digests = std::collections::BTreeSet::new();
    for record in records {
        if last.is_some_and(|operation| operation >= record.operation) {
            return Err(ControllerJournalError::NonCanonicalOperation);
        }
        validate_operation(record)?;
        match record.phase {
            ControllerOperationPhase::Prepared | ControllerOperationPhase::Uncertain
                if record.expected_revision != current_revision =>
            {
                return Err(ControllerJournalError::OperationRevisionMismatch);
            }
            ControllerOperationPhase::Committed => {
                let digest = record
                    .committed_plan_digest
                    .ok_or(ControllerJournalError::InvalidCommittedPlanDigest)?;
                if !committed_plan_digests.insert(digest) {
                    return Err(ControllerJournalError::CommittedPlanDigestConflict);
                }
                committed.push(record);
            }
            ControllerOperationPhase::Terminal if record.expected_revision > current_revision => {
                return Err(ControllerJournalError::OperationRevisionMismatch);
            }
            _ => {}
        }
        last = Some(record.operation);
    }
    committed.sort_unstable_by_key(|record| record.expected_revision);
    if u64::try_from(committed.len()).map_err(|_| ControllerJournalError::LengthOverflow)?
        != current_revision
    {
        return Err(ControllerJournalError::CommittedOperationHistoryMismatch);
    }
    let mut previous_generation = 0_u64;
    for (revision, record) in committed.into_iter().enumerate() {
        let revision =
            u64::try_from(revision).map_err(|_| ControllerJournalError::LengthOverflow)?;
        let generation = record
            .committed_allocation_generation
            .ok_or(ControllerJournalError::InvalidCommittedAllocationGeneration)?;
        if record.expected_revision != revision
            || generation < previous_generation
            || generation > previous_generation.saturating_add(1)
        {
            return Err(ControllerJournalError::CommittedOperationHistoryMismatch);
        }
        previous_generation = generation;
    }
    if previous_generation != allocation_generation {
        return Err(ControllerJournalError::AllocationGenerationHistoryMismatch);
    }
    Ok(())
}

fn validate_operation_successors(
    current: &[ControllerOperationRecord],
    previous: &[ControllerOperationRecord],
    expected_revision: u64,
) -> Result<(), ControllerJournalError> {
    for old in previous {
        let Some(new) = current
            .iter()
            .find(|record| record.operation == old.operation)
        else {
            return Err(ControllerJournalError::OperationRemoved);
        };
        if new.intent_digest != old.intent_digest
            || new.expected_revision != old.expected_revision
            || new.committed_allocation_generation != old.committed_allocation_generation
                && !(old.phase == ControllerOperationPhase::Prepared
                    && new.phase == ControllerOperationPhase::Committed
                    && old.committed_allocation_generation.is_none()
                    && new.committed_allocation_generation.is_some())
            || new.committed_plan_digest != old.committed_plan_digest
                && !(old.phase == ControllerOperationPhase::Prepared
                    && new.phase == ControllerOperationPhase::Committed
                    && old.committed_plan_digest.is_none()
                    && new.committed_plan_digest.is_some())
            || !old.phase.permits(new.phase)
            || old.result.is_some() && old.result != new.result
            || old.phase == new.phase && old != new
        {
            return Err(ControllerJournalError::OperationFactChanged);
        }
    }
    for new in current {
        if !previous
            .iter()
            .any(|record| record.operation == new.operation)
            && (new.phase != ControllerOperationPhase::Prepared
                || new.expected_revision != expected_revision
                || new.committed_allocation_generation.is_some()
                || new.committed_plan_digest.is_some())
        {
            return Err(ControllerJournalError::InvalidOperationTransition);
        }
    }
    Ok(())
}

fn validate_tenure_transactions(
    transactions: &[ControllerTenureTransaction],
    scope: DeploymentScopeId,
) -> Result<(), ControllerJournalError> {
    let mut last_operation = None;
    let mut request_digests = std::collections::BTreeSet::new();
    let mut intent_digests = std::collections::BTreeSet::new();
    let mut client_nonces = std::collections::BTreeSet::new();
    let mut unresolved = 0_usize;
    let mut committed_proofs: Vec<&WriterTenureProof> = Vec::new();

    for transaction in transactions {
        let request = transaction.request();
        if bytes_are_zero(
            transaction
                .authority_domain_fingerprint()
                .value()
                .as_bytes(),
        ) {
            return Err(ControllerJournalError::InvalidTenureAuthorityDomainFingerprint);
        }
        if last_operation.is_some_and(|operation| operation >= request.operation_id()) {
            return Err(ControllerJournalError::NonCanonicalTenureTransaction);
        }
        if request.scope() != scope {
            return Err(ControllerJournalError::TenureScopeMismatch);
        }
        if AcquireTenureRequestV1::decode(request.canonical_bytes())? != *request {
            return Err(ControllerJournalError::InvalidTenureTransaction);
        }
        if !request_digests.insert(request.request_digest())
            || !intent_digests.insert(request.intent_digest())
            || !client_nonces.insert(request.client_nonce())
        {
            return Err(ControllerJournalError::TenureTransactionConflict);
        }
        match (transaction.phase(), transaction.response()) {
            (ControllerTenurePhase::Prepared | ControllerTenurePhase::Uncertain, None) => {
                unresolved = unresolved
                    .checked_add(1)
                    .ok_or(ControllerJournalError::LengthOverflow)?;
            }
            (ControllerTenurePhase::Committed, Some(response)) => {
                if AcquireTenureResponseV1::decode_for_request(response.canonical_bytes(), request)?
                    != *response
                {
                    return Err(ControllerJournalError::InvalidTenureTransaction);
                }
                let proof = response.proof();
                for previous in &committed_proofs {
                    if previous.claim().epoch() == proof.claim().epoch()
                        && (previous.claim().writer() != proof.claim().writer()
                            || *previous != proof)
                    {
                        return Err(ControllerJournalError::TenureEpochConflict);
                    }
                }
                committed_proofs.push(proof);
            }
            _ => return Err(ControllerJournalError::InvalidTenureTransaction),
        }
        last_operation = Some(request.operation_id());
    }
    if unresolved > 1 {
        return Err(ControllerJournalError::UnresolvedTenureTransactionExists);
    }
    Ok(())
}

fn validate_tenure_transaction_successors(
    current: &[ControllerTenureTransaction],
    previous: &[ControllerTenureTransaction],
) -> Result<(), ControllerJournalError> {
    for old in previous {
        let Some(new) = current
            .iter()
            .find(|transaction| transaction.operation_id() == old.operation_id())
        else {
            return Err(ControllerJournalError::TenureTransactionRemoved);
        };
        if new.request() != old.request()
            || new.authority_domain_fingerprint() != old.authority_domain_fingerprint()
            || !old.phase().permits(new.phase())
            || old.response().is_some() && old.response() != new.response()
            || old.phase() == new.phase() && old != new
        {
            return Err(ControllerJournalError::TenureTransactionFactChanged);
        }
        if new.phase() == ControllerTenurePhase::Committed && new.response().is_none() {
            return Err(ControllerJournalError::InvalidTenureTransition);
        }
        if old.phase() != ControllerTenurePhase::Committed
            && new.phase() == ControllerTenurePhase::Committed
        {
            let proof = new
                .committed_proof()
                .ok_or(ControllerJournalError::InvalidTenureTransition)?;
            validate_new_tenure_proof_successor(previous, new.operation_id(), proof)?;
        }
    }
    for new in current {
        if !previous
            .iter()
            .any(|transaction| transaction.operation_id() == new.operation_id())
            && (new.phase() != ControllerTenurePhase::Prepared || new.response().is_some())
        {
            return Err(ControllerJournalError::InvalidTenureTransition);
        }
    }
    Ok(())
}

fn validate_new_tenure_proof_successor(
    previous: &[ControllerTenureTransaction],
    operation_id: AcquireTenureOperationId,
    proof: &WriterTenureProof,
) -> Result<(), ControllerJournalError> {
    let prior_maximum_epoch = previous
        .iter()
        .filter(|transaction| transaction.operation_id() != operation_id)
        .filter_map(ControllerTenureTransaction::committed_proof)
        .map(|previous_proof| previous_proof.claim().epoch().value())
        .max();
    let Some(prior_maximum_epoch) = prior_maximum_epoch else {
        return Ok(());
    };
    if proof.claim().epoch().value() <= prior_maximum_epoch {
        return Err(ControllerJournalError::TenureEpochNotMonotonic);
    }
    if proof.claim().supersedes_through_epoch().value() < prior_maximum_epoch {
        return Err(ControllerJournalError::TenureSupersessionGap);
    }
    Ok(())
}

fn validate_auth_successor(
    current: ControllerRequestAuthPin,
    previous: ControllerRequestAuthPin,
) -> Result<(), ControllerJournalError> {
    if current.rotation_generation < previous.rotation_generation
        || current.rotation_generation == previous.rotation_generation && current != previous
    {
        return Err(ControllerJournalError::AuthRotationRegression);
    }
    Ok(())
}

fn validate_request_auth_pin(pin: ControllerRequestAuthPin) -> Result<(), ControllerJournalError> {
    if bytes_are_zero(pin.key.as_bytes())
        || pin.algorithm_version == 0
        || bytes_are_zero(pin.verification_key_fingerprint.value().as_bytes())
        || pin.rotation_generation == 0
    {
        return Err(ControllerJournalError::InvalidAuthPin);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ApplyHistoryValidationContext<'a> {
    scope: DeploymentScopeId,
    plan_lineage: DeploymentId,
    target: RuntimeHostId,
    binding: Option<&'a ControllerTargetBinding>,
    operations: &'a [ControllerOperationRecord],
    current_revision: u64,
    current_shape: Option<TargetIntent>,
    query_snapshot_high_water: u64,
}

fn validate_apply_history(
    history: &[ControllerRolloutRecord],
    current: Option<&ControllerRolloutRecord>,
    context: ApplyHistoryValidationContext<'_>,
) -> Result<(), ControllerJournalError> {
    let mut last_archived_plan_revision = None;
    let mut apply_operations = std::collections::BTreeSet::new();
    let mut request_digests = std::collections::BTreeSet::new();
    let mut source_plan_digests = std::collections::BTreeSet::new();
    let mut query_ids = std::collections::BTreeSet::new();
    let mut query_request_digests = std::collections::BTreeSet::new();
    let mut query_client_nonces = std::collections::BTreeSet::new();
    let mut maximum_query_sequence = 0_u64;
    for record in history {
        record.validate()?;
        if record.has_conflicting_terminal_observation() {
            return Err(ControllerJournalError::ConflictingTerminalEvidence);
        }
        if !record.is_terminal() {
            return Err(ControllerJournalError::NonTerminalApplyHistory);
        }
        validate_request_auth_pin(record.signed_intent.request_auth)?;
        validate_archived_binding(&record.signed_intent, context.target, context.binding)?;
        validate_rollout_query_lineage(
            record,
            context.binding,
            context.scope,
            &mut query_ids,
            &mut query_request_digests,
            &mut query_client_nonces,
            &mut maximum_query_sequence,
        )?;
        if !source_plan_digests.insert(record.signed_intent.source_plan_digest) {
            return Err(ControllerJournalError::ApplyPlanAlreadyArchived);
        }
        let mut matching_commits = context.operations.iter().filter(|operation| {
            operation.phase == ControllerOperationPhase::Committed
                && operation.committed_plan_digest == Some(record.signed_intent.source_plan_digest)
        });
        let Some(matching_commit) = matching_commits.next() else {
            return Err(ControllerJournalError::ArchivedPlanDigestMismatch);
        };
        if matching_commits.next().is_some() {
            return Err(ControllerJournalError::ArchivedPlanDigestMismatch);
        }
        let archived_plan_revision = matching_commit
            .expected_revision
            .checked_add(1)
            .ok_or(ControllerJournalError::RevisionExhausted)?;
        validate_terminal_decision_context(
            record,
            context.scope,
            context.plan_lineage,
            archived_plan_revision,
            None,
        )?;
        if archived_plan_revision >= context.current_revision
            || last_archived_plan_revision
                .is_some_and(|previous| previous >= archived_plan_revision)
        {
            return Err(ControllerJournalError::NonCanonicalApplyHistory);
        }
        if !apply_operations.insert(record.signed_intent.apply_operation) {
            return Err(ControllerJournalError::ApplyOperationConflict);
        }
        if !request_digests.insert(record.signed_intent.request_digest) {
            return Err(ControllerJournalError::ApplyOperationConflict);
        }
        last_archived_plan_revision = Some(archived_plan_revision);
    }
    if let Some(record) = current {
        record.validate()?;
        validate_request_auth_pin(record.signed_intent.request_auth)?;
        validate_archived_binding(&record.signed_intent, context.target, context.binding)?;
        validate_rollout_query_lineage(
            record,
            context.binding,
            context.scope,
            &mut query_ids,
            &mut query_request_digests,
            &mut query_client_nonces,
            &mut maximum_query_sequence,
        )?;
        validate_terminal_decision_context(
            record,
            context.scope,
            context.plan_lineage,
            context.current_revision,
            context.current_shape,
        )?;
        if !apply_operations.insert(record.signed_intent.apply_operation)
            || !request_digests.insert(record.signed_intent.request_digest)
        {
            return Err(ControllerJournalError::ApplyOperationConflict);
        }
    }
    if context.query_snapshot_high_water != maximum_query_sequence {
        return Err(ControllerJournalError::QueryHighWaterMismatch);
    }
    Ok(())
}

fn validate_terminal_decision_context(
    record: &ControllerRolloutRecord,
    expected_scope: DeploymentScopeId,
    expected_plan: DeploymentId,
    expected_revision: u64,
    expected_shape: Option<TargetIntent>,
) -> Result<(), ControllerJournalError> {
    let expected_revision = SourcePlanRevision::new(expected_revision);
    for attempt in &record.reconcile_attempts {
        let Some(decision) = attempt.decision.filter(|decision| decision.is_terminal()) else {
            continue;
        };
        let observation = attempt
            .observation
            .as_ref()
            .ok_or(ControllerJournalError::DanglingRolloutDecision)?;
        let apply = ReferenceApplyRequestV1::decode(&record.signed_intent.signed_request)
            .map_err(|_| ControllerJournalError::InvalidRolloutEvidence)?;
        let query = attempt.prepared.request();
        let provenance = apply.provenance();
        let execution = apply.target_execution();
        let expected_mode = match decision.observed {
            ControllerObservedTarget::Active => ReferenceAssemblyModeV1::OneSourceLoop,
            ControllerObservedTarget::Retired => ReferenceAssemblyModeV1::EmptyDeactivate,
            ControllerObservedTarget::Prepared | ControllerObservedTarget::Uncertain => {
                return Err(ControllerJournalError::InvalidRolloutEvidence);
            }
        };
        let mode_matches_plan = match expected_shape {
            Some(TargetIntent::OneSourceLoop) => {
                expected_mode == ReferenceAssemblyModeV1::OneSourceLoop
            }
            Some(TargetIntent::EmptyTarget) => {
                expected_mode == ReferenceAssemblyModeV1::EmptyDeactivate
            }
            Some(TargetIntent::Omitted) => false,
            None => true,
        };
        if !mode_matches_plan
            || apply.canonical_wire() != record.signed_intent.signed_request.as_ref()
            || apply.target() != record.signed_intent.target
            || apply.target_slice_digest() != record.signed_intent.target_slice_digest
            || apply.envelope_request_digest() != record.signed_intent.request_digest.value()
            || apply.expected_runtime_store_instance_id()
                != record.signed_intent.runtime_store_instance_id
            || provenance.source_scope() != SourceScopeRef::from_bytes(*expected_scope.as_bytes())
            || provenance.source_plan() != SourcePlanRef::from_bytes(*expected_plan.as_bytes())
            || provenance.source_revision() != expected_revision
            || provenance.source_plan_digest() != record.signed_intent.source_plan_digest
            || apply.control_commitment().control().operation_id()
                != record.signed_intent.apply_operation
            || execution.mode() != expected_mode
            || execution.target() != record.signed_intent.target
            || execution.manifest_digest() != record.signed_intent.binding_manifest_digest.value()
            || query.expected_request_digest() != Some(record.signed_intent.request_digest.value())
            || query.authentication().claim().principal()
                != apply.authentication().claim().principal()
        {
            return Err(ControllerJournalError::InvalidRolloutEvidence);
        }
        let ReferenceQueryOperationLookupV1::Known {
            request_digest,
            durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
            terminal_result: Some(_),
        } = observation.response().facts().operation().lookup()
        else {
            return Err(ControllerJournalError::InvalidRolloutEvidence);
        };
        if request_digest != record.signed_intent.request_digest.value() {
            return Err(ControllerJournalError::InvalidRolloutEvidence);
        }
        let desired = observation.response().facts().desired();
        if desired.source_revision_high_water() != expected_revision {
            return Err(ControllerJournalError::InvalidRolloutEvidence);
        }
        let exact = match (decision.observed, desired.head()) {
            (
                ControllerObservedTarget::Active,
                ReferenceQueryDesiredHeadV1::OneSourceLoop {
                    source_revision,
                    target_slice_digest,
                    manifest_digest,
                },
            )
            | (
                ControllerObservedTarget::Retired,
                ReferenceQueryDesiredHeadV1::EmptyDeactivate {
                    source_revision,
                    target_slice_digest,
                    manifest_digest,
                },
            ) => {
                source_revision == expected_revision
                    && target_slice_digest == record.signed_intent.target_slice_digest
                    && manifest_digest == record.signed_intent.binding_manifest_digest.value()
            }
            _ => false,
        };
        if !exact {
            return Err(ControllerJournalError::InvalidRolloutEvidence);
        }
    }
    Ok(())
}

fn validate_rollout_query_lineage(
    record: &ControllerRolloutRecord,
    binding: Option<&ControllerTargetBinding>,
    scope: DeploymentScopeId,
    query_ids: &mut std::collections::BTreeSet<ReferenceQueryIdV1>,
    query_request_digests: &mut std::collections::BTreeSet<Digest32>,
    query_client_nonces: &mut std::collections::BTreeSet<Box<[u8]>>,
    maximum_query_sequence: &mut u64,
) -> Result<(), ControllerJournalError> {
    let binding = binding.ok_or(ControllerJournalError::DanglingRollout)?;
    let source_scope =
        paraegox_runtime_contracts::provenance::SourceScopeRef::from_bytes(*scope.as_bytes());
    for (index, attempt) in record.reconcile_attempts.iter().enumerate() {
        attempt
            .prepared
            .validate(binding, source_scope, &record.signed_intent)?;
        let request = attempt.prepared.request();
        if !query_ids.insert(request.query_id())
            || !query_request_digests.insert(request.request_digest())
            || !query_client_nonces.insert(request.authentication().claim().nonce().into())
        {
            return Err(ControllerJournalError::QueryIdentityConflict);
        }
        if let Some(observation) = &attempt.observation {
            let validated = ControllerQueryObservation::try_new(
                observation.response.clone(),
                observation.channel_peer,
                &attempt.prepared,
            )?;
            if &validated != observation || validated.response_digest != observation.response_digest
            {
                return Err(ControllerJournalError::InvalidQueryResponse);
            }
            *maximum_query_sequence =
                (*maximum_query_sequence).max(observation.query_snapshot_sequence());
        }
        if attempt
            .decision
            .is_some_and(ControllerRolloutDecision::is_terminal)
            && index + 1 != record.reconcile_attempts.len()
        {
            let terminal_epoch = attempt
                .observation
                .as_ref()
                .ok_or(ControllerJournalError::DanglingRolloutDecision)?
                .response()
                .facts()
                .serving()
                .runtime_host_epoch();
            let next_epoch = record.reconcile_attempts[index + 1]
                .prepared
                .serving_baseline()
                .runtime_host_epoch();
            if terminal_epoch >= binding.last_runtime_host_epoch() || next_epoch <= terminal_epoch {
                return Err(ControllerJournalError::EvidenceAfterTerminalDecision);
            }
        }
    }
    Ok(())
}

fn validate_archived_binding(
    intent: &ControllerSignedApplyIntent,
    target: RuntimeHostId,
    binding: Option<&ControllerTargetBinding>,
) -> Result<(), ControllerJournalError> {
    let binding = binding.ok_or(ControllerJournalError::DanglingRollout)?;
    if intent.target != target
        || intent.target != binding.target
        || intent.runtime_store_instance_id != binding.runtime_store_instance_id
        || intent.binding_channel_auth_fingerprint != binding.channel_auth_fingerprint
        || intent.binding_manifest_digest != binding.manifest_digest
    {
        return Err(ControllerJournalError::RolloutBindingMismatch);
    }
    Ok(())
}

fn validate_apply_history_successor(
    current_history: &[ControllerRolloutRecord],
    previous_history: &[ControllerRolloutRecord],
    current_rollout: Option<&ControllerRolloutRecord>,
    previous_rollout: Option<&ControllerRolloutRecord>,
    current_binding: Option<&ControllerTargetBinding>,
    plan_changed: bool,
) -> Result<(), ControllerJournalError> {
    for old in previous_history {
        let Some(new) = current_history.iter().find(|record| {
            record.signed_intent.apply_operation == old.signed_intent.apply_operation
        }) else {
            return Err(ControllerJournalError::ApplyHistoryRemoved);
        };
        if new != old {
            return Err(ControllerJournalError::ApplyHistoryChanged);
        }
    }
    if !plan_changed {
        return if current_history == previous_history {
            Ok(())
        } else {
            Err(ControllerJournalError::ApplyHistoryWithoutPlanCommit)
        };
    }
    if current_rollout.is_some() {
        return Err(ControllerJournalError::StaleRolloutRetained);
    }
    let expected_additions = usize::from(previous_rollout.is_some());
    if current_history.len() != previous_history.len() + expected_additions {
        return Err(ControllerJournalError::ApplyHistoryArchiveMismatch);
    }
    if let Some(previous_rollout) = previous_rollout {
        let binding = current_binding.ok_or(ControllerJournalError::DanglingRollout)?;
        if !rollout_permits_plan_advance(previous_rollout, binding)? {
            return Err(ControllerJournalError::NonTerminalRolloutBlocksPlanCommit);
        }
        let Some(archived) = current_history.iter().find(|record| {
            record.signed_intent.apply_operation == previous_rollout.signed_intent.apply_operation
        }) else {
            return Err(ControllerJournalError::ApplyHistoryArchiveMismatch);
        };
        if archived != previous_rollout {
            return Err(ControllerJournalError::ApplyHistoryArchiveMismatch);
        }
    }
    Ok(())
}

fn validate_rollout_successor(
    current: Option<&ControllerRolloutRecord>,
    previous: Option<&ControllerRolloutRecord>,
    current_binding: Option<&ControllerTargetBinding>,
    plan_changed: bool,
) -> Result<(), ControllerJournalError> {
    if plan_changed {
        return if current.is_none() {
            Ok(())
        } else {
            Err(ControllerJournalError::StaleRolloutRetained)
        };
    }
    match (previous, current) {
        (None, None) => Ok(()),
        (None, Some(new)) => {
            if new.direct_terminal_receipt.is_some() || !new.reconcile_attempts.is_empty() {
                Err(ControllerJournalError::SignedIntentNotCommittedFirst)
            } else {
                Ok(())
            }
        }
        (Some(_), None) => Err(ControllerJournalError::RolloutEvidenceRemoved),
        (Some(old), Some(new)) => {
            if new.signed_intent != old.signed_intent {
                return Err(ControllerJournalError::RolloutIntentChanged);
            }
            if new == old {
                return Ok(());
            }
            match (&old.direct_terminal_receipt, &new.direct_terminal_receipt) {
                (None, Some(_)) if old.reconcile_attempts == new.reconcile_attempts => {
                    return new.validate();
                }
                (Some(_), None) => {
                    return Err(ControllerJournalError::DirectTerminalReceiptRemoved);
                }
                (Some(previous), Some(current)) if previous != current => {
                    return Err(ControllerJournalError::DirectTerminalReceiptChanged);
                }
                (Some(_), Some(_)) => {}
                (None, None) => {}
                (None, Some(_)) => {
                    return Err(ControllerJournalError::QueryEvidenceRemoved);
                }
            }
            let old_attempts = &old.reconcile_attempts;
            let new_attempts = &new.reconcile_attempts;
            if new_attempts.len() == old_attempts.len() {
                let Some((old_last, old_prefix)) = old_attempts.split_last() else {
                    return Err(ControllerJournalError::RolloutIntentChanged);
                };
                let Some((new_last, new_prefix)) = new_attempts.split_last() else {
                    return Err(ControllerJournalError::RolloutIntentChanged);
                };
                if old_prefix != new_prefix || old_last.prepared != new_last.prepared {
                    return Err(ControllerJournalError::QueryEvidenceChanged);
                }
                let response_commit = old_last.observation.is_none()
                    && new_last.observation.is_some()
                    && old_last.closure.is_none()
                    && new_last.closure.is_none()
                    && old_last.decision.is_none()
                    && new_last.decision.is_none();
                let closure_commit = old_last.observation.is_none()
                    && new_last.observation.is_none()
                    && old_last.closure.is_none()
                    && new_last.closure.is_some()
                    && old_last.decision.is_none()
                    && new_last.decision.is_none();
                let decision_commit = old_last.observation == new_last.observation
                    && old_last.observation.is_some()
                    && old_last.closure.is_none()
                    && new_last.closure.is_none()
                    && old_last.decision.is_none()
                    && new_last.decision.is_some();
                if !response_commit && !closure_commit && !decision_commit {
                    return Err(ControllerJournalError::QueryNotCommittedBeforeDecision);
                }
            } else if new_attempts.len() == old_attempts.len() + 1 {
                if new_attempts[..old_attempts.len()] != **old_attempts
                    || new_attempts.last().is_some_and(|attempt| {
                        attempt.observation.is_some()
                            || attempt.closure.is_some()
                            || attempt.decision.is_some()
                    })
                {
                    return Err(ControllerJournalError::QueryNotCommittedBeforeDecision);
                }
                if let Some(last) = old_attempts.last()
                    && !last.is_closed_without_response()
                    && (last.observation.is_none() || last.decision.is_none())
                {
                    return Err(ControllerJournalError::EvidenceAfterTerminalDecision);
                }
                if let Some(last) = old_attempts.last()
                    && last
                        .decision
                        .is_some_and(ControllerRolloutDecision::is_terminal)
                {
                    let binding = current_binding.ok_or(ControllerJournalError::DanglingRollout)?;
                    if terminal_query_decision_is_current(last, binding) {
                        return Err(ControllerJournalError::EvidenceAfterTerminalDecision);
                    }
                    let terminal_epoch = last
                        .observation
                        .as_ref()
                        .ok_or(ControllerJournalError::DanglingRolloutDecision)?
                        .response()
                        .facts()
                        .serving()
                        .runtime_host_epoch();
                    if new_attempts.last().is_none_or(|attempt| {
                        attempt.prepared.serving_baseline().runtime_host_epoch() <= terminal_epoch
                    }) {
                        return Err(ControllerJournalError::EvidenceAfterTerminalDecision);
                    }
                }
            } else {
                return Err(ControllerJournalError::QueryEvidenceRemoved);
            }
            new.validate()
        }
    }
}

fn allocation_matches_delta_result(
    allocation: &StableAllocationSnapshot,
    delta: &StableAllocationDelta,
) -> bool {
    allocation.generation() == delta.next_generation()
        && allocation.high_water() == delta.resulting_high_water()
        && delta.records().iter().all(|changed| {
            allocation
                .records()
                .iter()
                .find(|record| record.key() == changed.key())
                == Some(changed)
        })
}

/// Versioned/checksummed Controller snapshot envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerJournalSnapshot {
    store_instance_id: [u8; 32],
    owner_identity_fingerprint: ControllerOwnerIdentityFingerprint,
    snapshot_sequence: u64,
    state: ControllerJournalState,
}

/// Strictly parsed v7 source evidence plus its canonical v8 successor.
///
/// This value is produced only by the explicit offline migration parser. The
/// normal Controller open path remains v8-only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerJournalPayloadV7Migration {
    snapshot: ControllerJournalSnapshot,
    source_payload_version: u16,
    source_checksum: Digest32,
    source_store_instance_id: [u8; 32],
    source_owner_identity_fingerprint: ControllerOwnerIdentityFingerprint,
    source_snapshot_sequence: u64,
}

impl ControllerJournalPayloadV7Migration {
    pub(crate) const fn snapshot(&self) -> &ControllerJournalSnapshot {
        &self.snapshot
    }

    pub(crate) fn into_snapshot(self) -> ControllerJournalSnapshot {
        self.snapshot
    }

    pub(crate) const fn source_payload_version(&self) -> u16 {
        self.source_payload_version
    }

    pub(crate) const fn source_checksum(&self) -> Digest32 {
        self.source_checksum
    }

    pub(crate) const fn source_store_instance_id(&self) -> &[u8; 32] {
        &self.source_store_instance_id
    }

    pub(crate) const fn source_owner_identity_fingerprint(
        &self,
    ) -> ControllerOwnerIdentityFingerprint {
        self.source_owner_identity_fingerprint
    }

    pub(crate) const fn source_snapshot_sequence(&self) -> u64 {
        self.source_snapshot_sequence
    }
}

impl ControllerJournalSnapshot {
    pub(crate) fn try_initialize(
        store_instance_id: [u8; 32],
        owner_identity_fingerprint: ControllerOwnerIdentityFingerprint,
        state: ControllerJournalState,
    ) -> Result<Self, ControllerJournalError> {
        if !state.is_exact_fresh() {
            return Err(ControllerJournalError::NonFreshInitialState);
        }
        Self::try_from_stored(store_instance_id, owner_identity_fingerprint, 1, state)
    }

    fn try_from_stored(
        store_instance_id: [u8; 32],
        owner_identity_fingerprint: ControllerOwnerIdentityFingerprint,
        snapshot_sequence: u64,
        state: ControllerJournalState,
    ) -> Result<Self, ControllerJournalError> {
        if store_instance_id == [0; 32] {
            return Err(ControllerJournalError::ZeroStoreIdentity);
        }
        if bytes_are_zero(owner_identity_fingerprint.value().as_bytes()) {
            return Err(ControllerJournalError::ZeroOwnerIdentityFingerprint);
        }
        if snapshot_sequence == 0 {
            return Err(ControllerJournalError::ZeroSnapshotSequence);
        }
        state.validate()?;
        if snapshot_sequence == 1 && !state.is_exact_fresh() {
            return Err(ControllerJournalError::NonFreshInitialState);
        }
        if snapshot_sequence > 1 && state.is_exact_fresh() {
            return Err(ControllerJournalError::FreshStateAfterInitialization);
        }
        Ok(Self {
            store_instance_id,
            owner_identity_fingerprint,
            snapshot_sequence,
            state,
        })
    }

    pub(crate) fn try_successor(
        &self,
        state: ControllerJournalState,
    ) -> Result<Self, ControllerJournalError> {
        let snapshot_sequence = self
            .snapshot_sequence
            .checked_add(1)
            .ok_or(ControllerJournalError::SnapshotSequenceExhausted)?;
        state.validate_successor_of(&self.state)?;
        Self::try_from_stored(
            self.store_instance_id,
            self.owner_identity_fingerprint,
            snapshot_sequence,
            state,
        )
    }

    pub(crate) fn validate_successor_of(
        &self,
        previous: &Self,
    ) -> Result<(), ControllerJournalError> {
        if self.store_instance_id != previous.store_instance_id
            || self.owner_identity_fingerprint != previous.owner_identity_fingerprint
        {
            return Err(ControllerJournalError::SnapshotOwnerChanged);
        }
        let expected = previous
            .snapshot_sequence
            .checked_add(1)
            .ok_or(ControllerJournalError::SnapshotSequenceExhausted)?;
        if self.snapshot_sequence != expected {
            return Err(ControllerJournalError::SnapshotSequenceNotNext);
        }
        self.state.validate_successor_of(&previous.state)
    }

    pub(crate) const fn store_instance_id(&self) -> &[u8; 32] {
        &self.store_instance_id
    }

    pub(crate) const fn owner_identity_fingerprint(&self) -> ControllerOwnerIdentityFingerprint {
        self.owner_identity_fingerprint
    }

    pub(crate) const fn snapshot_sequence(&self) -> u64 {
        self.snapshot_sequence
    }

    pub(crate) const fn state(&self) -> &ControllerJournalState {
        &self.state
    }

    pub(crate) fn encode(&self) -> Result<Box<[u8]>, ControllerJournalError> {
        self.encode_with_payload_version(CONTROLLER_PAYLOAD_VERSION)
    }

    fn encode_with_payload_version(
        &self,
        payload_version: u16,
    ) -> Result<Box<[u8]>, ControllerJournalError> {
        let payload = encode_payload_version(&self.state, payload_version)?;
        let payload_length =
            u64::try_from(payload.len()).map_err(|_| ControllerJournalError::SnapshotTooLarge)?;
        let total_length = JOURNAL_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(ControllerJournalError::SnapshotTooLarge)?;
        if total_length > MAX_CONTROLLER_SNAPSHOT_BYTES {
            return Err(ControllerJournalError::SnapshotTooLarge);
        }

        let mut prefix = Vec::with_capacity(JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES);
        prefix.extend_from_slice(JOURNAL_MAGIC);
        prefix.extend_from_slice(&JOURNAL_ENVELOPE_VERSION.to_be_bytes());
        prefix.extend_from_slice(&CONTROLLER_OWNER_KIND.to_be_bytes());
        prefix.extend_from_slice(&payload_version.to_be_bytes());
        prefix.extend_from_slice(&CHECKSUM_ALGORITHM_SHA256.to_be_bytes());
        prefix.extend_from_slice(&CHECKSUM_VERSION.to_be_bytes());
        prefix.extend_from_slice(&self.store_instance_id);
        prefix.extend_from_slice(self.owner_identity_fingerprint.value().as_bytes());
        prefix.extend_from_slice(&self.snapshot_sequence.to_be_bytes());
        prefix.extend_from_slice(&payload_length.to_be_bytes());
        debug_assert_eq!(prefix.len(), JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES);

        let checksum = controller_checksum(&prefix, &payload)?;
        let mut encoded = prefix;
        encoded.extend_from_slice(checksum.as_bytes());
        encoded.extend_from_slice(&payload);
        Ok(encoded.into_boxed_slice())
    }

    #[cfg(test)]
    pub(crate) fn encode_payload_v7_for_test(&self) -> Result<Box<[u8]>, ControllerJournalError> {
        self.encode_with_payload_version(CONTROLLER_LEGACY_PAYLOAD_VERSION)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ControllerJournalError> {
        if bytes.len() < JOURNAL_HEADER_BYTES {
            return Err(ControllerJournalError::Truncated);
        }
        if bytes.len() > MAX_CONTROLLER_SNAPSHOT_BYTES {
            return Err(ControllerJournalError::SnapshotTooLarge);
        }
        let mut reader = Reader::new(bytes);
        if reader.take_array::<4>()? != *JOURNAL_MAGIC {
            return Err(ControllerJournalError::InvalidMagic);
        }
        if reader.u16()? != JOURNAL_ENVELOPE_VERSION {
            return Err(ControllerJournalError::UnknownEnvelopeVersion);
        }
        if reader.u16()? != CONTROLLER_OWNER_KIND {
            return Err(ControllerJournalError::OwnerKindMismatch);
        }
        if reader.u16()? != CONTROLLER_PAYLOAD_VERSION {
            return Err(ControllerJournalError::UnknownPayloadVersion);
        }
        if reader.u16()? != CHECKSUM_ALGORITHM_SHA256 || reader.u16()? != CHECKSUM_VERSION {
            return Err(ControllerJournalError::UnknownChecksumVersion);
        }
        let store_instance_id = reader.take_array::<32>()?;
        let owner_identity_fingerprint = ControllerOwnerIdentityFingerprint::from_stored(
            Digest32::from_bytes(reader.take_array::<32>()?),
        );
        let snapshot_sequence = reader.u64()?;
        let payload_length =
            usize::try_from(reader.u64()?).map_err(|_| ControllerJournalError::LengthOverflow)?;
        if payload_length > MAX_CONTROLLER_SNAPSHOT_BYTES - JOURNAL_HEADER_BYTES {
            return Err(ControllerJournalError::SnapshotTooLarge);
        }
        let checksum = Digest32::from_bytes(reader.take_array::<32>()?);
        if payload_length != reader.remaining() {
            return Err(ControllerJournalError::LengthMismatch);
        }
        let prefix = &bytes[..JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES];
        let payload = reader.take(payload_length)?;
        if controller_checksum(prefix, payload)? != checksum {
            return Err(ControllerJournalError::ChecksumMismatch);
        }
        Self::try_from_stored(
            store_instance_id,
            owner_identity_fingerprint,
            snapshot_sequence,
            decode_payload(payload)?,
        )
    }

    /// Converts one strictly validated payload-v7 snapshot to canonical v8.
    /// Normal [`Self::decode`] deliberately never falls back to this parser.
    pub(crate) fn migrate_payload_v7(bytes: &[u8]) -> Result<Self, ControllerJournalError> {
        Ok(Self::migrate_payload_v7_with_metadata(bytes)?.into_snapshot())
    }

    /// Performs the explicit v7 conversion while retaining exact source facts
    /// needed by the store-owned migration receipt.
    pub(crate) fn migrate_payload_v7_with_metadata(
        bytes: &[u8],
    ) -> Result<ControllerJournalPayloadV7Migration, ControllerJournalError> {
        if bytes.len() < JOURNAL_HEADER_BYTES {
            return Err(ControllerJournalError::Truncated);
        }
        if bytes.len() > MAX_CONTROLLER_SNAPSHOT_BYTES {
            return Err(ControllerJournalError::SnapshotTooLarge);
        }
        let mut reader = Reader::new(bytes);
        if reader.take_array::<4>()? != *JOURNAL_MAGIC {
            return Err(ControllerJournalError::InvalidMagic);
        }
        if reader.u16()? != JOURNAL_ENVELOPE_VERSION {
            return Err(ControllerJournalError::UnknownEnvelopeVersion);
        }
        if reader.u16()? != CONTROLLER_OWNER_KIND {
            return Err(ControllerJournalError::OwnerKindMismatch);
        }
        let source_payload_version = reader.u16()?;
        if source_payload_version != CONTROLLER_LEGACY_PAYLOAD_VERSION {
            return Err(ControllerJournalError::UnknownPayloadVersion);
        }
        if reader.u16()? != CHECKSUM_ALGORITHM_SHA256 || reader.u16()? != CHECKSUM_VERSION {
            return Err(ControllerJournalError::UnknownChecksumVersion);
        }
        let store_instance_id = reader.take_array::<32>()?;
        let owner_identity_fingerprint = ControllerOwnerIdentityFingerprint::from_stored(
            Digest32::from_bytes(reader.take_array::<32>()?),
        );
        let snapshot_sequence = reader.u64()?;
        let payload_length =
            usize::try_from(reader.u64()?).map_err(|_| ControllerJournalError::LengthOverflow)?;
        if payload_length > MAX_CONTROLLER_SNAPSHOT_BYTES - JOURNAL_HEADER_BYTES {
            return Err(ControllerJournalError::SnapshotTooLarge);
        }
        let checksum = Digest32::from_bytes(reader.take_array::<32>()?);
        let expected_length = JOURNAL_HEADER_BYTES
            .checked_add(payload_length)
            .ok_or(ControllerJournalError::LengthOverflow)?;
        if expected_length != bytes.len() {
            return if expected_length < bytes.len() {
                Err(ControllerJournalError::TrailingBytes)
            } else {
                Err(ControllerJournalError::Truncated)
            };
        }
        let prefix = &bytes[..JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES];
        let payload = reader.take(payload_length)?;
        if controller_checksum(prefix, payload)? != checksum {
            return Err(ControllerJournalError::ChecksumMismatch);
        }
        let state = decode_payload_version(payload, CONTROLLER_LEGACY_PAYLOAD_VERSION, true)?;
        if encode_payload_version(&state, CONTROLLER_LEGACY_PAYLOAD_VERSION)? != payload {
            return Err(ControllerJournalError::NonCanonicalEncoding);
        }
        let snapshot = Self::try_from_stored(
            store_instance_id,
            owner_identity_fingerprint,
            snapshot_sequence,
            state,
        )?;
        Ok(ControllerJournalPayloadV7Migration {
            snapshot,
            source_payload_version,
            source_checksum: checksum,
            source_store_instance_id: store_instance_id,
            source_owner_identity_fingerprint: owner_identity_fingerprint,
            source_snapshot_sequence: snapshot_sequence,
        })
    }
}

fn deployment_plan_digest(
    scope: DeploymentScopeId,
    plan: DeploymentId,
    revision: DeploymentRevision,
    content: &PlanContent,
    content_digest: PlanContentDigest,
) -> Result<SourcePlanDigest, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(DEPLOYMENT_PLAN_DIGEST_DOMAIN)?;
    builder
        .field_bytes(scope.as_bytes())?
        .field_bytes(plan.as_bytes())?
        .field_u64(revision.value())?
        .field_bytes(content.canonical_bytes())?
        .field_bytes(content_digest.value().as_bytes())?;
    Ok(SourcePlanDigest::new(builder.finish()))
}

fn plan_commit_intent_digest(
    scope: DeploymentScopeId,
    plan: DeploymentId,
    expected_revision: u64,
    candidate: &DeploymentPlanCandidate,
) -> Result<ControllerPlanCommitIntentDigest, ControllerJournalError> {
    let delta = candidate.allocation_delta();
    let mut builder = Digest32Builder::try_new(PLAN_COMMIT_INTENT_DIGEST_DOMAIN)?;
    builder
        .field_bytes(scope.as_bytes())?
        .field_bytes(plan.as_bytes())?
        .field_u64(expected_revision)?
        .field_bytes(candidate.content().target().as_bytes())?
        .field_bytes(candidate.content().canonical_bytes())?
        .field_bytes(candidate.content_digest().value().as_bytes())?
        .field_u64(delta.base_generation())?
        .field_u64(delta.next_generation())?
        .field_u64(delta.resulting_high_water())?
        .field_u64(
            u64::try_from(delta.records().len())
                .map_err(|_| ControllerJournalError::LengthOverflow)?,
        )?;
    for record in delta.records() {
        builder
            .field_bytes(record.key())?
            .field_u64(record.ordinal())?
            .field_bytes(record.instance().as_bytes())?
            .field_bytes(record.domain().as_bytes())?
            .field_u16(allocation_state_tag(record.state()).into())?;
    }
    Ok(ControllerPlanCommitIntentDigest::from_stored(
        builder.finish(),
    ))
}

fn controller_checksum(prefix: &[u8], payload: &[u8]) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(CONTROLLER_CHECKSUM_DOMAIN)?;
    builder.field_bytes(prefix)?.field_bytes(payload)?;
    Ok(builder.finish())
}

#[cfg(test)]
pub(crate) fn refresh_controller_test_checksum(
    encoded: &mut [u8],
) -> Result<(), ControllerJournalError> {
    if encoded.len() < JOURNAL_HEADER_BYTES {
        return Err(ControllerJournalError::Truncated);
    }
    let checksum = controller_checksum(
        &encoded[..JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES],
        &encoded[JOURNAL_HEADER_BYTES..],
    )?;
    encoded[JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES..JOURNAL_HEADER_BYTES]
        .copy_from_slice(checksum.as_bytes());
    Ok(())
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Strict installer-derived manifest pin shared by Controller owner tests.
///
/// The helper intentionally uses the production contract generator and sealed
/// deployment adapter; it does not create a raw or unchecked journal pin.
#[cfg(test)]
pub(crate) fn controller_test_manifest(target: RuntimeHostId) -> ControllerInstalledManifestPin {
    controller_test_manifest_with_build(target, 0x11)
}

#[cfg(test)]
pub(crate) fn controller_test_manifest_with_build(
    target: RuntimeHostId,
    build_marker: u8,
) -> ControllerInstalledManifestPin {
    let (installation, _) = controller_test_installation_with_build(target, build_marker);
    ControllerInstalledManifestPin::from_verified_installation(&installation)
        .expect("Controller test installed manifest pin")
}

#[cfg(test)]
fn controller_test_installation_with_build(
    target: RuntimeHostId,
    build_marker: u8,
) -> (
    paraegox_runtime_contracts::installation::VerifiedRuntimeInstallationV1,
    paraegox_runtime_contracts::installation::RuntimeCompiledInstallationFactsV1,
) {
    use paraegox_runtime_contracts::execution::{CardDefinitionRef, CardImplementationRef};
    use paraegox_runtime_contracts::installation::{
        InstalledRuntimeArtifactObservationV1, RuntimeCompiledInstallationFactsV1,
        generate_build_descriptor, generate_manifest,
    };

    let artifact = InstalledRuntimeArtifactObservationV1::try_new(
        1_048_576,
        Digest32::from_bytes([0x22; 32]),
        "aarch64-unknown-linux-gnu",
    )
    .expect("Controller test artifact facts must validate");
    let compiled = RuntimeCompiledInstallationFactsV1::try_new(
        [build_marker; 32],
        CardDefinitionRef::from_bytes([0xa1; 16]),
        CardImplementationRef::from_bytes([0xa2; 16]),
        [0xa3; 16],
        Digest32::from_bytes([0xa4; 32]),
        Digest32::from_bytes([0xa5; 32]),
    )
    .expect("Controller test compiled facts must validate");
    let descriptor =
        generate_build_descriptor(&artifact, compiled).expect("Controller test descriptor");
    let installation = generate_manifest(
        descriptor.canonical_wire(),
        descriptor.descriptor_digest(),
        target,
        &artifact,
        compiled,
    )
    .expect("Controller test manifest");
    (installation, compiled)
}

fn validate_plan_content_size(bytes: &[u8]) -> Result<(), ControllerJournalError> {
    if bytes.is_empty() {
        return Err(ControllerJournalError::EmptyPlanContent);
    }
    if bytes.len() > MAX_PLAN_CONTENT_BYTES {
        return Err(ControllerJournalError::PlanContentTooLarge);
    }
    Ok(())
}

fn plan_content_storage_checksum(
    bytes: &[u8],
) -> Result<ControllerPlanContentStorageChecksum, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(CONTROLLER_PLAN_CONTENT_INTEGRITY_DOMAIN)?;
    builder.field_bytes(bytes)?;
    Ok(ControllerPlanContentStorageChecksum::from_stored(
        builder.finish(),
    ))
}

const fn allocation_state_tag(state: AllocationState) -> u8 {
    match state {
        AllocationState::Active => 1,
        AllocationState::Tombstone => 2,
    }
}

fn decode_allocation_state(value: u8) -> Result<AllocationState, ControllerJournalError> {
    match value {
        1 => Ok(AllocationState::Active),
        2 => Ok(AllocationState::Tombstone),
        _ => Err(ControllerJournalError::UnknownEnum),
    }
}

fn validate_controller_snapshot_size(
    state: &ControllerJournalState,
) -> Result<(), ControllerJournalError> {
    let payload_length = controller_payload_encoded_len(state)?;
    let snapshot_length = JOURNAL_HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(ControllerJournalError::SnapshotTooLarge)?;
    if snapshot_length > MAX_CONTROLLER_SNAPSHOT_BYTES {
        return Err(ControllerJournalError::SnapshotTooLarge);
    }
    Ok(())
}

fn controller_payload_encoded_len(
    state: &ControllerJournalState,
) -> Result<usize, ControllerJournalError> {
    let mut length = CONTROLLER_PAYLOAD_MAGIC.len()
        + size_of::<u16>()
        + 16
        + 16
        + 16
        + size_of::<u32>()
        + state.installed_manifest.canonical_manifest_wire().len()
        + 32
        + size_of::<u64>()
        + size_of::<u64>()
        + size_of::<u32>();
    checked_encoded_add(
        &mut length,
        state
            .allocation
            .records()
            .len()
            .checked_mul(16 + 8 + 16 + 16 + 1)
            .ok_or(ControllerJournalError::SnapshotTooLarge)?,
    )?;

    checked_encoded_add(&mut length, 1)?;
    if let Some(plan) = &state.committed_plan {
        checked_encoded_add(
            &mut length,
            16 + 16 + 8 + 16 + 4 + plan.content.canonical_bytes().len() + 32 + 32 + 32 + 16 + 32,
        )?;
    }

    checked_encoded_add(&mut length, size_of::<u32>())?;
    for operation in &state.operations {
        checked_encoded_add(
            &mut length,
            16 + 32
                + 8
                + 1
                + 1
                + usize::from(operation.result.is_some()) * 16
                + 1
                + usize::from(operation.committed_allocation_generation.is_some()) * 8
                + 1
                + usize::from(operation.committed_plan_digest.is_some()) * 32,
        )?;
    }
    checked_encoded_add(&mut length, size_of::<u32>())?;
    for transaction in &state.tenure_transactions {
        let request = transaction.request();
        checked_encoded_add(
            &mut length,
            16 + 1
                + 32
                + 16
                + 16
                + 32
                + 32
                + size_of::<u32>()
                + request.client_nonce().len()
                + size_of::<u32>()
                + request.canonical_bytes().len()
                + 1,
        )?;
        if let Some(response) = transaction.response() {
            checked_encoded_add(
                &mut length,
                32 + 32 + size_of::<u32>() + response.canonical_bytes().len(),
            )?;
        }
    }
    checked_encoded_add(&mut length, 16 + 2 + 2 + 32 + 8 + 8)?;

    checked_encoded_add(&mut length, 1)?;
    if let Some(binding) = &state.target_binding {
        checked_encoded_add(
            &mut length,
            16 + 32
                + 32
                + 32
                + 8
                + 8
                + 4
                + binding.bootstrap_response.len()
                + 32
                + RUNTIME_RESPONSE_AUTH_PIN_BYTES,
        )?;
    }

    checked_encoded_add(&mut length, 1)?;
    if let Some(rollout) = &state.rollout {
        checked_encoded_add(&mut length, rollout_encoded_len(rollout)?)?;
    }
    checked_encoded_add(&mut length, size_of::<u32>())?;
    for rollout in &state.apply_history {
        checked_encoded_add(&mut length, rollout_encoded_len(rollout)?)?;
    }
    Ok(length)
}

fn rollout_encoded_len(rollout: &ControllerRolloutRecord) -> Result<usize, ControllerJournalError> {
    let intent = &rollout.signed_intent;
    let mut length = 16
        + 32
        + 32
        + 16
        + 32
        + 4
        + intent.signed_request.len()
        + (16 + 2 + 2 + 32 + 8)
        + 32
        + 32
        + 32
        + RUNTIME_RESPONSE_AUTH_PIN_BYTES
        + 1
        + size_of::<u32>();
    if let Some(direct) = &rollout.direct_terminal_receipt {
        checked_encoded_add(
            &mut length,
            size_of::<u32>() + direct.receipt.canonical_wire().len(),
        )?;
    }
    for attempt in &rollout.reconcile_attempts {
        let prepared = &attempt.prepared;
        checked_encoded_add(
            &mut length,
            size_of::<u32>()
                + prepared.request.canonical_wire().len()
                + (16 + 2 + 2 + 32 + 8)
                + QUERY_CHANNEL_BINDING_BYTES
                + RUNTIME_RESPONSE_AUTH_PIN_BYTES
                + QUERY_SERVING_BASELINE_BYTES
                + 1,
        )?;
        if let Some(observation) = &attempt.observation {
            checked_encoded_add(
                &mut length,
                size_of::<u32>()
                    + observation.response.canonical_wire().len()
                    + 32
                    + QUERY_CHANNEL_BINDING_BYTES,
            )?;
        }
        checked_encoded_add(&mut length, 1 + usize::from(attempt.closure.is_some()))?;
        checked_encoded_add(&mut length, 1)?;
        if let Some(decision) = attempt.decision {
            checked_encoded_add(
                &mut length,
                16 + 8 + 1 + 1 + usize::from(decision.receipt.is_some()) * 16,
            )?;
        }
    }
    Ok(length)
}

fn checked_encoded_add(total: &mut usize, amount: usize) -> Result<(), ControllerJournalError> {
    *total = total
        .checked_add(amount)
        .ok_or(ControllerJournalError::SnapshotTooLarge)?;
    Ok(())
}

fn encode_payload(state: &ControllerJournalState) -> Result<Vec<u8>, ControllerJournalError> {
    encode_payload_version(state, CONTROLLER_PAYLOAD_VERSION)
}

fn encode_payload_version(
    state: &ControllerJournalState,
    payload_version: u16,
) -> Result<Vec<u8>, ControllerJournalError> {
    if payload_version != CONTROLLER_PAYLOAD_VERSION
        && payload_version != CONTROLLER_LEGACY_PAYLOAD_VERSION
    {
        return Err(ControllerJournalError::UnknownPayloadVersion);
    }
    state.validate()?;
    let expected_length = controller_payload_encoded_len(state)?;
    let encoded = encode_payload_fields(state, payload_version)?;
    debug_assert_eq!(encoded.len(), expected_length);
    Ok(encoded)
}

fn encode_payload_fields(
    state: &ControllerJournalState,
    payload_version: u16,
) -> Result<Vec<u8>, ControllerJournalError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(CONTROLLER_PAYLOAD_MAGIC);
    encoded.extend_from_slice(&payload_version.to_be_bytes());
    encoded.extend_from_slice(state.scope.as_bytes());
    encoded.extend_from_slice(state.plan_lineage.as_bytes());
    encoded.extend_from_slice(state.allocation.target().as_bytes());
    append_bytes(
        &mut encoded,
        state.installed_manifest.canonical_manifest_wire(),
    )?;
    encoded.extend_from_slice(state.installed_manifest.manifest_digest().as_bytes());
    encoded.extend_from_slice(&state.allocation.generation().to_be_bytes());
    encoded.extend_from_slice(&state.allocation.high_water().to_be_bytes());
    append_count(&mut encoded, state.allocation.records().len())?;
    for record in state.allocation.records() {
        encoded.extend_from_slice(record.key());
        encoded.extend_from_slice(&record.ordinal().to_be_bytes());
        encoded.extend_from_slice(record.instance().as_bytes());
        encoded.extend_from_slice(record.domain().as_bytes());
        encoded.push(allocation_state_tag(record.state()));
    }
    append_optional_plan(&mut encoded, state.committed_plan.as_ref())?;
    append_count(&mut encoded, state.operations.len())?;
    for operation in &state.operations {
        encoded.extend_from_slice(operation.operation.as_bytes());
        encoded.extend_from_slice(operation.intent_digest.value().as_bytes());
        encoded.extend_from_slice(&operation.expected_revision.to_be_bytes());
        encoded.push(operation.phase as u8);
        append_optional_id(
            &mut encoded,
            operation.result.map(|result| *result.as_bytes()),
        );
        append_optional_u64(&mut encoded, operation.committed_allocation_generation);
        append_optional_source_plan_digest(&mut encoded, operation.committed_plan_digest);
    }
    append_count(&mut encoded, state.tenure_transactions.len())?;
    for transaction in &state.tenure_transactions {
        append_tenure_transaction(&mut encoded, transaction)?;
    }
    append_auth_pin(&mut encoded, state.request_auth);
    encoded.extend_from_slice(&state.query_snapshot_high_water.to_be_bytes());
    append_optional_binding(&mut encoded, state.target_binding.as_ref())?;
    append_optional_rollout(&mut encoded, state.rollout.as_ref())?;
    append_count(&mut encoded, state.apply_history.len())?;
    for rollout in &state.apply_history {
        append_rollout(&mut encoded, rollout)?;
    }
    Ok(encoded)
}

fn decode_payload(bytes: &[u8]) -> Result<ControllerJournalState, ControllerJournalError> {
    decode_payload_version(bytes, CONTROLLER_PAYLOAD_VERSION, false)
}

fn decode_payload_version(
    bytes: &[u8],
    expected_payload_version: u16,
    reject_legacy_query_evidence: bool,
) -> Result<ControllerJournalState, ControllerJournalError> {
    let mut reader = Reader::new(bytes);
    if reader.take_array::<4>()? != *CONTROLLER_PAYLOAD_MAGIC {
        return Err(ControllerJournalError::InvalidPayloadMagic);
    }
    if reader.u16()? != expected_payload_version {
        return Err(ControllerJournalError::UnknownPayloadVersion);
    }
    let scope = DeploymentScopeId::from_bytes(reader.take_array::<16>()?);
    let plan_lineage = DeploymentId::from_bytes(reader.take_array::<16>()?);
    let target = RuntimeHostId::from_bytes(reader.take_array::<16>()?);
    let installed_manifest = ControllerInstalledManifestPin::try_from_persisted_manifest(
        reader.bounded_bytes(MAX_INSTALLED_RUNTIME_MANIFEST_BYTES)?,
        Digest32::from_bytes(reader.take_array::<32>()?),
    )
    .map_err(|_| ControllerJournalError::InvalidInstalledManifestPin)?;
    let generation = reader.u64()?;
    let high_water = reader.u64()?;
    let allocation_count = reader.count(MAX_ALLOCATION_RECORDS)?;
    let mut allocations = Vec::with_capacity(allocation_count);
    let mut previous_key = None;
    for _ in 0..allocation_count {
        let key = reader.take_array::<16>()?;
        if previous_key.is_some_and(|old| old >= key) {
            return Err(ControllerJournalError::NonCanonicalAllocation);
        }
        previous_key = Some(key);
        allocations.push(
            StableAllocationRecord::try_from_persisted(
                target,
                key,
                reader.u64()?,
                reader.take_array::<16>()?,
                reader.take_array::<16>()?,
                decode_allocation_state(reader.u8()?)?,
            )
            .map_err(|_| ControllerJournalError::InvalidAllocation)?,
        );
    }
    let allocation = StableAllocationSnapshot::try_new(target, generation, high_water, allocations)
        .map_err(|_| ControllerJournalError::InvalidAllocation)?;
    let committed_plan = decode_optional_plan(&mut reader)?;
    let operation_count = reader.count(MAX_CONTROLLER_OPERATIONS)?;
    let mut operations = Vec::with_capacity(operation_count);
    for _ in 0..operation_count {
        operations.push(ControllerOperationRecord::try_new(
            ControllerOperationId::from_bytes(reader.take_array::<16>()?),
            ControllerPlanCommitIntentDigest::from_stored(Digest32::from_bytes(
                reader.take_array::<32>()?,
            )),
            reader.u64()?,
            ControllerOperationPhase::decode(reader.u8()?)?,
            decode_optional_id(&mut reader)?.map(ControllerReceiptRef::from_bytes),
            decode_optional_u64(&mut reader)?,
            decode_optional_source_plan_digest(&mut reader)?,
        )?);
    }
    let tenure_count = reader.count(MAX_CONTROLLER_TENURE_TRANSACTIONS)?;
    let mut tenure_transactions = Vec::with_capacity(tenure_count);
    for _ in 0..tenure_count {
        tenure_transactions.push(decode_tenure_transaction(&mut reader)?);
    }
    let request_auth = decode_auth_pin(&mut reader)?;
    let query_snapshot_high_water = reader.u64()?;
    if reject_legacy_query_evidence && query_snapshot_high_water != 0 {
        return Err(ControllerJournalError::LegacyOpaqueQueryEvidenceUnavailable);
    }
    let target_binding = decode_optional_binding(&mut reader)?;
    let rollout = decode_optional_rollout(&mut reader, reject_legacy_query_evidence)?;
    let history_count = reader.count(MAX_APPLY_OPERATION_HISTORY)?;
    let mut apply_history = Vec::with_capacity(history_count);
    for _ in 0..history_count {
        apply_history.push(decode_rollout(&mut reader, reject_legacy_query_evidence)?);
    }
    if reader.remaining() != 0 {
        return Err(ControllerJournalError::TrailingBytes);
    }
    ControllerJournalState::try_from_stored(ControllerJournalStateInput {
        scope,
        plan_lineage,
        allocation,
        installed_manifest,
        committed_plan,
        operations,
        tenure_transactions,
        request_auth,
        target_binding,
        query_snapshot_high_water,
        rollout,
        apply_history,
    })
}

fn append_tenure_transaction(
    encoded: &mut Vec<u8>,
    transaction: &ControllerTenureTransaction,
) -> Result<(), ControllerJournalError> {
    let request = transaction.request();
    encoded.extend_from_slice(request.operation_id().as_bytes());
    encoded.push(transaction.phase() as u8);
    encoded.extend_from_slice(
        transaction
            .authority_domain_fingerprint()
            .value()
            .as_bytes(),
    );
    encoded.extend_from_slice(request.scope().as_bytes());
    encoded.extend_from_slice(request.writer().as_bytes());
    encoded.extend_from_slice(request.intent_digest().as_bytes());
    encoded.extend_from_slice(request.request_digest().as_bytes());
    append_bytes(encoded, request.client_nonce())?;
    append_bytes(encoded, request.canonical_bytes())?;
    let Some(response) = transaction.response() else {
        encoded.push(0);
        return Ok(());
    };
    encoded.push(1);
    encoded.extend_from_slice(response.response_digest().as_bytes());
    encoded.extend_from_slice(response.proof_digest().as_bytes());
    append_bytes(encoded, response.canonical_bytes())?;
    Ok(())
}

fn decode_tenure_transaction(
    reader: &mut Reader<'_>,
) -> Result<ControllerTenureTransaction, ControllerJournalError> {
    let operation_id = reader.take_array::<16>()?;
    let phase = ControllerTenurePhase::decode(reader.u8()?)?;
    let authority_domain_fingerprint = ControllerTenureAuthorityDomainFingerprint::from_stored(
        Digest32::from_bytes(reader.take_array::<32>()?),
    );
    let scope = reader.take_array::<16>()?;
    let writer = reader.take_array::<16>()?;
    let intent_digest = reader.take_array::<32>()?;
    let request_digest = reader.take_array::<32>()?;
    let client_nonce = reader
        .bounded_bytes(MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES)?
        .to_vec();
    let canonical_request = reader
        .bounded_bytes(MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES)?
        .to_vec();
    let request = AcquireTenureRequestV1::decode(&canonical_request)?;
    if request.operation_id().as_bytes() != &operation_id
        || request.scope().as_bytes() != &scope
        || request.writer().as_bytes() != &writer
        || request.intent_digest().as_bytes() != &intent_digest
        || request.request_digest().as_bytes() != &request_digest
        || request.client_nonce() != client_nonce
        || request.canonical_bytes() != canonical_request
    {
        return Err(ControllerJournalError::TenureTransactionFactChanged);
    }

    let response = match reader.u8()? {
        0 => None,
        1 => {
            let response_digest = reader.take_array::<32>()?;
            let proof_digest = reader.take_array::<32>()?;
            let canonical_response = reader
                .bounded_bytes(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)?
                .to_vec();
            let response =
                AcquireTenureResponseV1::decode_for_request(&canonical_response, &request)?;
            if response.response_digest().as_bytes() != &response_digest
                || response.proof_digest().as_bytes() != &proof_digest
                || response.canonical_bytes() != canonical_response
            {
                return Err(ControllerJournalError::TenureTransactionFactChanged);
            }
            Some(response)
        }
        _ => return Err(ControllerJournalError::InvalidPresence),
    };
    ControllerTenureTransaction::try_new(request, authority_domain_fingerprint, phase, response)
}

fn append_optional_plan(
    encoded: &mut Vec<u8>,
    plan: Option<&ControllerCommittedPlan>,
) -> Result<(), ControllerJournalError> {
    let Some(plan) = plan else {
        encoded.push(0);
        return Ok(());
    };
    encoded.push(1);
    encoded.extend_from_slice(plan.scope.as_bytes());
    encoded.extend_from_slice(plan.plan.as_bytes());
    encoded.extend_from_slice(&plan.revision.value().to_be_bytes());
    encoded.extend_from_slice(plan.target.as_bytes());
    append_bytes(encoded, plan.content.canonical_bytes())?;
    encoded.extend_from_slice(plan.plan_content_digest.value().as_bytes());
    encoded.extend_from_slice(plan.deployment_plan_digest.value().as_bytes());
    encoded.extend_from_slice(plan.storage_content_checksum.value().as_bytes());
    encoded.extend_from_slice(plan.commit_operation.as_bytes());
    encoded.extend_from_slice(plan.commit_intent_digest.value().as_bytes());
    Ok(())
}

fn decode_optional_plan(
    reader: &mut Reader<'_>,
) -> Result<Option<ControllerCommittedPlan>, ControllerJournalError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let scope = DeploymentScopeId::from_bytes(reader.take_array::<16>()?);
            let plan = DeploymentId::from_bytes(reader.take_array::<16>()?);
            let revision = DeploymentRevision::new(reader.u64()?);
            let target = RuntimeHostId::from_bytes(reader.take_array::<16>()?);
            let content = reader.bounded_bytes(MAX_PLAN_CONTENT_BYTES)?;
            let content_digest =
                PlanContentDigest::from_stored(Digest32::from_bytes(reader.take_array::<32>()?));
            let plan_digest =
                SourcePlanDigest::new(Digest32::from_bytes(reader.take_array::<32>()?));
            let storage_content_checksum = ControllerPlanContentStorageChecksum::from_stored(
                Digest32::from_bytes(reader.take_array::<32>()?),
            );
            let commit_operation = ControllerOperationId::from_bytes(reader.take_array::<16>()?);
            let commit_intent_digest = ControllerPlanCommitIntentDigest::from_stored(
                Digest32::from_bytes(reader.take_array::<32>()?),
            );
            Ok(Some(ControllerCommittedPlan::try_from_stored(
                ControllerStoredCommittedPlanInput {
                    scope,
                    plan,
                    revision,
                    target,
                    content,
                    plan_content_digest: content_digest,
                    deployment_plan_digest: plan_digest,
                    storage_content_checksum,
                    commit_operation,
                    commit_intent_digest,
                },
            )?))
        }
        _ => Err(ControllerJournalError::InvalidPresence),
    }
}

fn append_auth_pin(encoded: &mut Vec<u8>, auth: ControllerRequestAuthPin) {
    encoded.extend_from_slice(auth.key.as_bytes());
    encoded.extend_from_slice(&auth.algorithm.value().to_be_bytes());
    encoded.extend_from_slice(&auth.algorithm_version.to_be_bytes());
    encoded.extend_from_slice(auth.verification_key_fingerprint.value().as_bytes());
    encoded.extend_from_slice(&auth.rotation_generation.to_be_bytes());
}

fn decode_auth_pin(
    reader: &mut Reader<'_>,
) -> Result<ControllerRequestAuthPin, ControllerJournalError> {
    let key = ApplyAuthKeyRef::from_bytes(reader.take_array::<16>()?);
    let algorithm = ApplyAuthAlgorithm::try_new(reader.u16()?)
        .map_err(|_| ControllerJournalError::InvalidAuthPin)?;
    ControllerRequestAuthPin::try_new(
        key,
        algorithm,
        reader.u16()?,
        ControllerAuthKeyFingerprint::from_stored(Digest32::from_bytes(reader.take_array::<32>()?)),
        reader.u64()?,
    )
}

fn append_runtime_response_auth_pin(encoded: &mut Vec<u8>, pin: ControllerRuntimeResponseAuthPin) {
    encoded.extend_from_slice(pin.bootstrap_response_digest.value().as_bytes());
    encoded.extend_from_slice(pin.runtime_peer.as_bytes());
    encoded.extend_from_slice(pin.local_endpoint_identity_digest.as_bytes());
    encoded.extend_from_slice(pin.peer_credentials_digest.as_bytes());
    encoded.extend_from_slice(pin.key.as_bytes());
    encoded.extend_from_slice(&pin.algorithm.value().to_be_bytes());
    encoded.extend_from_slice(&pin.algorithm_version.to_be_bytes());
}

fn append_query_channel(encoded: &mut Vec<u8>, channel: ReferenceChannelBindingV1) {
    encoded.extend_from_slice(channel.target().as_bytes());
    encoded.extend_from_slice(channel.runtime_peer().as_bytes());
    encoded.extend_from_slice(channel.local_endpoint_identity_digest().as_bytes());
    encoded.extend_from_slice(channel.peer_credentials_digest().as_bytes());
}

fn decode_query_channel(
    reader: &mut Reader<'_>,
) -> Result<ReferenceChannelBindingV1, ControllerJournalError> {
    ReferenceChannelBindingV1::try_new(
        RuntimeHostId::from_bytes(reader.take_array::<16>()?),
        PrincipalRef::from_bytes(reader.take_array::<16>()?),
        Digest32::from_bytes(reader.take_array::<32>()?),
        Digest32::from_bytes(reader.take_array::<32>()?),
    )
    .map_err(Into::into)
}

fn append_query_serving_baseline(
    encoded: &mut Vec<u8>,
    baseline: ReferenceBootstrapServingIdentityV1,
) {
    encoded.extend_from_slice(baseline.target().as_bytes());
    encoded.extend_from_slice(&baseline.runtime_store_instance_id());
    encoded.extend_from_slice(&baseline.snapshot_sequence().to_be_bytes());
    encoded.extend_from_slice(&baseline.runtime_host_epoch().to_be_bytes());
    encoded.extend_from_slice(baseline.clock_domain().as_bytes());
    encoded.extend_from_slice(&baseline.clock_generation().value().to_be_bytes());
}

fn decode_query_serving_baseline(
    reader: &mut Reader<'_>,
) -> Result<ReferenceBootstrapServingIdentityV1, ControllerJournalError> {
    ReferenceBootstrapServingIdentityV1::try_new(
        RuntimeHostId::from_bytes(reader.take_array::<16>()?),
        reader.take_array::<32>()?,
        reader.u64()?,
        reader.u64()?,
        ClockDomainRef::from_bytes(reader.take_array::<16>()?),
        ClockGeneration::try_new(reader.u64()?)
            .map_err(|_| ControllerJournalError::InvalidQueryRequest)?,
    )
    .map_err(Into::into)
}

fn decode_runtime_response_auth_pin(
    reader: &mut Reader<'_>,
) -> Result<ControllerRuntimeResponseAuthPin, ControllerJournalError> {
    ControllerRuntimeResponseAuthPin::try_from_stored(ControllerStoredRuntimeResponseAuthPinInput {
        bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(
            Digest32::from_bytes(reader.take_array::<32>()?),
        ),
        runtime_peer: PrincipalRef::from_bytes(reader.take_array::<16>()?),
        local_endpoint_identity_digest: Digest32::from_bytes(reader.take_array::<32>()?),
        peer_credentials_digest: Digest32::from_bytes(reader.take_array::<32>()?),
        key: ApplyAuthKeyRef::from_bytes(reader.take_array::<16>()?),
        algorithm: ApplyAuthAlgorithm::try_new(reader.u16()?)
            .map_err(|_| ControllerJournalError::InvalidRuntimeResponseAuthPin)?,
        algorithm_version: reader.u16()?,
    })
}

fn append_optional_binding(
    encoded: &mut Vec<u8>,
    binding: Option<&ControllerTargetBinding>,
) -> Result<(), ControllerJournalError> {
    let Some(binding) = binding else {
        encoded.push(0);
        return Ok(());
    };
    encoded.push(1);
    encoded.extend_from_slice(binding.target.as_bytes());
    encoded.extend_from_slice(&binding.runtime_store_instance_id);
    encoded.extend_from_slice(binding.channel_auth_fingerprint.value().as_bytes());
    encoded.extend_from_slice(binding.manifest_digest.value().as_bytes());
    encoded.extend_from_slice(&binding.first_runtime_host_epoch.to_be_bytes());
    encoded.extend_from_slice(&binding.last_runtime_host_epoch.to_be_bytes());
    append_bytes(encoded, &binding.bootstrap_response)?;
    encoded.extend_from_slice(binding.bootstrap_response_digest.value().as_bytes());
    append_runtime_response_auth_pin(encoded, binding.runtime_response_auth);
    Ok(())
}

fn decode_optional_binding(
    reader: &mut Reader<'_>,
) -> Result<Option<ControllerTargetBinding>, ControllerJournalError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ControllerTargetBinding::try_new(
            ControllerTargetBindingInput {
                target: RuntimeHostId::from_bytes(reader.take_array::<16>()?),
                runtime_store_instance_id: reader.take_array::<32>()?,
                channel_auth_fingerprint: ControllerChannelAuthFingerprint::from_stored(
                    Digest32::from_bytes(reader.take_array::<32>()?),
                ),
                manifest_digest: PlanManifestDigest::try_new(Digest32::from_bytes(
                    reader.take_array::<32>()?,
                ))
                .map_err(|_| ControllerJournalError::InvalidTargetBinding)?,
                first_runtime_host_epoch: reader.u64()?,
                last_runtime_host_epoch: reader.u64()?,
                bootstrap_response: reader.bounded_bytes(MAX_BOOTSTRAP_RESPONSE_BYTES)?,
                bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(
                    Digest32::from_bytes(reader.take_array::<32>()?),
                ),
                runtime_response_auth: decode_runtime_response_auth_pin(reader)?,
            },
        )?)),
        _ => Err(ControllerJournalError::InvalidPresence),
    }
}

fn append_optional_rollout(
    encoded: &mut Vec<u8>,
    rollout: Option<&ControllerRolloutRecord>,
) -> Result<(), ControllerJournalError> {
    let Some(rollout) = rollout else {
        encoded.push(0);
        return Ok(());
    };
    encoded.push(1);
    append_rollout(encoded, rollout)
}

fn append_rollout(
    encoded: &mut Vec<u8>,
    rollout: &ControllerRolloutRecord,
) -> Result<(), ControllerJournalError> {
    let intent = &rollout.signed_intent;
    encoded.extend_from_slice(intent.target.as_bytes());
    encoded.extend_from_slice(intent.source_plan_digest.value().as_bytes());
    encoded.extend_from_slice(intent.target_slice_digest.value().as_bytes());
    encoded.extend_from_slice(intent.apply_operation.as_bytes());
    encoded.extend_from_slice(intent.request_digest.value().as_bytes());
    append_bytes(encoded, &intent.signed_request)?;
    append_auth_pin(encoded, intent.request_auth);
    encoded.extend_from_slice(&intent.runtime_store_instance_id);
    encoded.extend_from_slice(intent.binding_channel_auth_fingerprint.value().as_bytes());
    encoded.extend_from_slice(intent.binding_manifest_digest.value().as_bytes());
    append_runtime_response_auth_pin(encoded, intent.runtime_response_auth);

    if let Some(direct) = &rollout.direct_terminal_receipt {
        encoded.push(1);
        append_bytes(encoded, direct.receipt.canonical_wire())?;
    } else {
        encoded.push(0);
    }

    append_count(encoded, rollout.reconcile_attempts.len())?;
    for attempt in &rollout.reconcile_attempts {
        let prepared = &attempt.prepared;
        append_bytes(encoded, prepared.request.canonical_wire())?;
        append_auth_pin(encoded, prepared.request_auth);
        append_query_channel(encoded, prepared.request_time_channel);
        append_runtime_response_auth_pin(encoded, prepared.runtime_response_auth);
        append_query_serving_baseline(encoded, prepared.serving_baseline);
        if let Some(observation) = &attempt.observation {
            encoded.push(1);
            append_bytes(encoded, observation.response.canonical_wire())?;
            encoded.extend_from_slice(observation.response_digest.as_bytes());
            append_query_channel(encoded, observation.channel_peer);
        } else {
            encoded.push(0);
        }
        if let Some(closure) = attempt.closure {
            encoded.push(1);
            encoded.push(closure as u8);
        } else {
            encoded.push(0);
        }
        if let Some(decision) = attempt.decision {
            encoded.push(1);
            encoded.extend_from_slice(decision.query_id.as_bytes());
            encoded.extend_from_slice(&decision.query_snapshot_sequence.to_be_bytes());
            encoded.push(decision.observed as u8);
            append_optional_id(encoded, decision.receipt.map(|receipt| *receipt.as_bytes()));
        } else {
            encoded.push(0);
        }
    }
    Ok(())
}

fn decode_optional_rollout(
    reader: &mut Reader<'_>,
    reject_legacy_query_evidence: bool,
) -> Result<Option<ControllerRolloutRecord>, ControllerJournalError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decode_rollout(reader, reject_legacy_query_evidence)?)),
        _ => Err(ControllerJournalError::InvalidPresence),
    }
}

fn decode_rollout(
    reader: &mut Reader<'_>,
    reject_legacy_query_evidence: bool,
) -> Result<ControllerRolloutRecord, ControllerJournalError> {
    let intent =
        ControllerSignedApplyIntent::try_from_stored(ControllerStoredSignedApplyIntentInput {
            target: RuntimeHostId::from_bytes(reader.take_array::<16>()?),
            source_plan_digest: SourcePlanDigest::new(Digest32::from_bytes(
                reader.take_array::<32>()?,
            )),
            target_slice_digest: TargetSliceDigest::new(Digest32::from_bytes(
                reader.take_array::<32>()?,
            )),
            apply_operation: ApplyOperationId::from_bytes(reader.take_array::<16>()?),
            request_digest: ControllerApplyRequestDigest::from_stored(Digest32::from_bytes(
                reader.take_array::<32>()?,
            )),
            signed_request: reader.bounded_bytes(MAX_SIGNED_REQUEST_BYTES)?,
            request_auth: decode_auth_pin(reader)?,
            runtime_store_instance_id: reader.take_array::<32>()?,
            binding_channel_auth_fingerprint: ControllerChannelAuthFingerprint::from_stored(
                Digest32::from_bytes(reader.take_array::<32>()?),
            ),
            binding_manifest_digest: PlanManifestDigest::try_new(Digest32::from_bytes(
                reader.take_array::<32>()?,
            ))
            .map_err(|_| ControllerJournalError::InvalidRolloutEvidence)?,
            runtime_response_auth: decode_runtime_response_auth_pin(reader)?,
        })?;
    let direct_terminal_receipt = match reader.u8()? {
        0 => None,
        1 => {
            let receipt = ReferenceApplyTerminalReceiptV1::decode(
                reader.bounded_bytes(MAX_REFERENCE_APPLY_TERMINAL_RECEIPT_BYTES)?,
            )?;
            Some(ControllerDirectTerminalReceipt::try_new(receipt, &intent)?)
        }
        _ => return Err(ControllerJournalError::InvalidPresence),
    };
    let attempt_count = reader.count(MAX_RECONCILE_ATTEMPTS)?;
    if reject_legacy_query_evidence && attempt_count != 0 {
        return Err(ControllerJournalError::LegacyOpaqueQueryEvidenceUnavailable);
    }
    let mut attempts = Vec::with_capacity(attempt_count);
    for _ in 0..attempt_count {
        let prepared = ControllerPreparedQuery {
            request: ReferenceQueryRequestV1::decode(
                reader.bounded_bytes(MAX_REFERENCE_QUERY_REQUEST_BYTES)?,
            )?,
            request_auth: decode_auth_pin(reader)?,
            request_time_channel: decode_query_channel(reader)?,
            runtime_response_auth: decode_runtime_response_auth_pin(reader)?,
            serving_baseline: decode_query_serving_baseline(reader)?,
        };
        let observation = match reader.u8()? {
            0 => None,
            1 => {
                let response = ReferenceQueryResponseV1::decode(
                    reader.bounded_bytes(MAX_REFERENCE_QUERY_RESPONSE_BYTES)?,
                )?;
                let response_digest = Digest32::from_bytes(reader.take_array::<32>()?);
                let channel_peer = decode_query_channel(reader)?;
                let observation =
                    ControllerQueryObservation::try_new(response, channel_peer, &prepared)?;
                if observation.response_digest != response_digest {
                    return Err(ControllerJournalError::InvalidQueryResponse);
                }
                Some(observation)
            }
            _ => return Err(ControllerJournalError::InvalidPresence),
        };
        let closure = match reader.u8()? {
            0 => None,
            1 => Some(ControllerQueryClosureKind::decode(reader.u8()?)?),
            _ => return Err(ControllerJournalError::InvalidPresence),
        };
        let decision = match reader.u8()? {
            0 => None,
            1 => {
                let query_id = ReferenceQueryIdV1::from_bytes(reader.take_array::<16>()?);
                let query_snapshot_sequence = reader.u64()?;
                let observed = ControllerObservedTarget::decode(reader.u8()?)?;
                let receipt = decode_optional_id(reader)?.map(ControllerReceiptRef::from_bytes);
                let response = observation
                    .as_ref()
                    .ok_or(ControllerJournalError::QueryNotCommittedBeforeDecision)?;
                let decision = ControllerRolloutDecision::try_new(response, observed, receipt)?;
                if decision.query_id != query_id
                    || decision.query_snapshot_sequence != query_snapshot_sequence
                {
                    return Err(ControllerJournalError::DanglingRolloutDecision);
                }
                Some(decision)
            }
            _ => return Err(ControllerJournalError::InvalidPresence),
        };
        attempts.push(ControllerReconcileAttempt {
            prepared,
            observation,
            closure,
            decision,
        });
    }
    let rollout = ControllerRolloutRecord {
        signed_intent: intent,
        direct_terminal_receipt,
        reconcile_attempts: attempts.into_boxed_slice(),
    };
    rollout.validate()?;
    Ok(rollout)
}

fn append_optional_id(encoded: &mut Vec<u8>, value: Option<[u8; 16]>) {
    if let Some(value) = value {
        encoded.push(1);
        encoded.extend_from_slice(&value);
    } else {
        encoded.push(0);
    }
}

fn decode_optional_id(reader: &mut Reader<'_>) -> Result<Option<[u8; 16]>, ControllerJournalError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.take_array::<16>()?)),
        _ => Err(ControllerJournalError::InvalidPresence),
    }
}

fn append_optional_u64(encoded: &mut Vec<u8>, value: Option<u64>) {
    if let Some(value) = value {
        encoded.push(1);
        encoded.extend_from_slice(&value.to_be_bytes());
    } else {
        encoded.push(0);
    }
}

fn decode_optional_u64(reader: &mut Reader<'_>) -> Result<Option<u64>, ControllerJournalError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.u64()?)),
        _ => Err(ControllerJournalError::InvalidPresence),
    }
}

fn append_optional_source_plan_digest(encoded: &mut Vec<u8>, value: Option<SourcePlanDigest>) {
    if let Some(value) = value {
        encoded.push(1);
        encoded.extend_from_slice(value.value().as_bytes());
    } else {
        encoded.push(0);
    }
}

fn decode_optional_source_plan_digest(
    reader: &mut Reader<'_>,
) -> Result<Option<SourcePlanDigest>, ControllerJournalError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(SourcePlanDigest::new(Digest32::from_bytes(
            reader.take_array::<32>()?,
        )))),
        _ => Err(ControllerJournalError::InvalidPresence),
    }
}

fn append_count(encoded: &mut Vec<u8>, count: usize) -> Result<(), ControllerJournalError> {
    let count = u32::try_from(count).map_err(|_| ControllerJournalError::LengthOverflow)?;
    encoded.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn append_bytes(encoded: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ControllerJournalError> {
    let length = u32::try_from(bytes.len()).map_err(|_| ControllerJournalError::LengthOverflow)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ControllerJournalError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ControllerJournalError::LengthOverflow)?;
        let Some(value) = self.bytes.get(self.offset..end) else {
            return Err(ControllerJournalError::Truncated);
        };
        self.offset = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ControllerJournalError> {
        let bytes = self.take(N)?;
        let mut value = [0; N];
        value.copy_from_slice(bytes);
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ControllerJournalError> {
        Ok(self.take_array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ControllerJournalError> {
        Ok(u16::from_be_bytes(self.take_array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, ControllerJournalError> {
        Ok(u32::from_be_bytes(self.take_array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, ControllerJournalError> {
        Ok(u64::from_be_bytes(self.take_array::<8>()?))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, ControllerJournalError> {
        let count =
            usize::try_from(self.u32()?).map_err(|_| ControllerJournalError::LengthOverflow)?;
        if count > maximum {
            return Err(ControllerJournalError::CountExceeded);
        }
        Ok(count)
    }

    fn bounded_bytes(&mut self, maximum: usize) -> Result<&'a [u8], ControllerJournalError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| ControllerJournalError::LengthOverflow)?;
        if length > maximum {
            return Err(ControllerJournalError::EmbeddedBodyTooLarge);
        }
        self.take(length)
    }
}

/// Stable fail-closed taxonomy for the private Controller codec/model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerJournalError {
    InvalidMagic,
    InvalidPayloadMagic,
    UnknownEnvelopeVersion,
    OwnerKindMismatch,
    UnknownPayloadVersion,
    UnknownChecksumVersion,
    UnknownEnum,
    InvalidPresence,
    Truncated,
    TrailingBytes,
    LengthOverflow,
    LengthMismatch,
    NonCanonicalEncoding,
    CountExceeded,
    SnapshotTooLarge,
    EmbeddedBodyTooLarge,
    ChecksumMismatch,
    ZeroStoreIdentity,
    ZeroOwnerIdentityFingerprint,
    ZeroSnapshotSequence,
    SnapshotSequenceNotNext,
    SnapshotSequenceExhausted,
    SnapshotOwnerChanged,
    AllocationCapacityExceeded,
    InvalidAllocation,
    NonCanonicalAllocation,
    InvalidAllocationTransition,
    AllocationWithoutPlanCommit,
    AllocationWithoutCommittedPlan,
    AllocationGenerationHistoryMismatch,
    OperationCapacityExceeded,
    TenureCapacityExceeded,
    NonCanonicalTenureTransaction,
    InvalidTenureTransaction,
    InvalidTenureAuthorityDomainFingerprint,
    TenureAuthorityDomainMismatch,
    TenureTransactionConflict,
    MissingTenureTransaction,
    TenureTransactionRemoved,
    TenureTransactionFactChanged,
    InvalidTenureTransition,
    UnresolvedTenureTransactionExists,
    TenureScopeMismatch,
    TenureEpochConflict,
    TenureEpochNotMonotonic,
    TenureSupersessionGap,
    ControllerLedgerCapacityExceeded,
    NonCanonicalOperation,
    InvalidOperationIdentity,
    InvalidOperationResult,
    MissingPreparedOperation,
    OperationConflict,
    OperationRemoved,
    OperationFactChanged,
    InvalidOperationTransition,
    OperationRevisionMismatch,
    InvalidCommittedAllocationGeneration,
    InvalidCommittedPlanDigest,
    CommittedPlanDigestConflict,
    CommittedOperationHistoryMismatch,
    CommittedOperationWithoutPlan,
    UnresolvedPlanOperationBlocksCommit,
    StalePlanOperation,
    InvalidPlanIdentity,
    InvalidPlanContent,
    InvalidInstalledManifestPin,
    InstalledManifestTargetMismatch,
    InstalledManifestPinChanged,
    InvalidRevision,
    RevisionNotNext,
    RevisionExhausted,
    EmptyPlanContent,
    PlanContentTooLarge,
    PlanContentDigestMismatch,
    DeploymentPlanDigestMismatch,
    PlanContentStorageChecksumMismatch,
    PlanLineageChanged,
    CommittedPlanRemoved,
    DanglingPlanOperation,
    PlanAllocationMismatch,
    CandidateTargetMismatch,
    CandidateManifestMismatch,
    InvalidAuthPin,
    AuthRotationRegression,
    AuthPinNotCommittedFirst,
    InvalidTargetBinding,
    InvalidRuntimeResponseAuthPin,
    TargetMismatch,
    TargetBindingChanged,
    TargetBindingRemoved,
    TargetBindingNotCommittedFirst,
    TargetBindingWithoutPlan,
    ManifestBindingMismatch,
    EmptyBootstrapResponse,
    BootstrapResponseTooLarge,
    EmptySignedRequest,
    SignedRequestTooLarge,
    InvalidQueryRequest,
    MissingPreparedQuery,
    InvalidQueryResponse,
    EmptyQueryResponse,
    QueryResponseTooLarge,
    InvalidQueryEvidence,
    LegacyOpaqueQueryEvidenceUnavailable,
    InvalidQueryClosure,
    QueryAlreadyClosed,
    QueryClosureChanged,
    QueryChannelMismatch,
    QueryIdentityConflict,
    QueryHighWaterMismatch,
    QuerySequenceRegression,
    QueryEvidenceChanged,
    DanglingQueryObservation,
    ReconcileCapacityExceeded,
    NonCanonicalReconcileHistory,
    EvidenceAfterTerminalDecision,
    InvalidRolloutEvidence,
    RolloutBindingMismatch,
    RolloutIntentChanged,
    RolloutEvidenceRemoved,
    StaleRolloutRetained,
    SignedIntentNotCommittedFirst,
    QueryEvidenceRemoved,
    QueryNotCommittedBeforeDecision,
    DanglingRolloutDecision,
    RolloutDecisionAlreadyCommitted,
    DanglingRollout,
    TerminalReceiptRequired,
    NonTerminalReceiptForbidden,
    InvalidDirectTerminalReceipt,
    DirectTerminalReceiptChanged,
    DirectTerminalReceiptRemoved,
    ConflictingTerminalEvidence,
    TerminalDesiredHeadUnavailable,
    CurrentRolloutExists,
    NonTerminalRolloutBlocksPlanCommit,
    ApplyOperationConflict,
    ApplyHistoryCapacityExceeded,
    NonCanonicalApplyHistory,
    NonTerminalApplyHistory,
    ArchivedPlanDigestMismatch,
    ApplyPlanAlreadyArchived,
    ApplyHistoryRemoved,
    ApplyHistoryChanged,
    ApplyHistoryWithoutPlanCommit,
    ApplyHistoryArchiveMismatch,
    ApplyHistoryRevisionMismatch,
    NonFreshInitialState,
    FreshStateAfterInitialization,
    Digest(DigestBuildError),
    TenureProtocol(AcquireTenureProtocolError),
    ReferenceControl(ReferenceControlError),
}

impl From<DigestBuildError> for ControllerJournalError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<AcquireTenureProtocolError> for ControllerJournalError {
    fn from(value: AcquireTenureProtocolError) -> Self {
        Self::TenureProtocol(value)
    }
}

impl From<ReferenceControlError> for ControllerJournalError {
    fn from(value: ReferenceControlError) -> Self {
        Self::ReferenceControl(value)
    }
}

impl fmt::Display for ControllerJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ControllerJournalError {}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::OnceLock;

    use super::{
        CONTROLLER_PAYLOAD_MAGIC, ControllerApplyRequestDigest, ControllerAuthKeyFingerprint,
        ControllerBootstrapResponseDigest, ControllerChannelAuthFingerprint,
        ControllerJournalError, ControllerJournalSnapshot, ControllerJournalState,
        ControllerObservedTarget, ControllerOperationId, ControllerOperationPhase,
        ControllerOwnerIdentityFingerprint, ControllerPlanCommitIntentDigest,
        ControllerPreparedQuery, ControllerQueryClosureKind, ControllerQueryObservation,
        ControllerReceiptRef, ControllerReconcileAttempt, ControllerRequestAuthPin,
        ControllerRolloutDecision, ControllerRuntimeResponseAuthPin,
        ControllerSignedApplyIntentInput, ControllerTargetBinding, ControllerTargetBindingInput,
        ControllerTenureAuthorityDomainFingerprint, ControllerTenurePhase,
        ControllerTenureTransaction, MAX_CONTROLLER_TENURE_TRANSACTIONS, controller_checksum,
    };
    use crate::plan::{DeploymentId, DeploymentScopeId, DeploymentWriterRef};
    use crate::planner::{
        AllocationState, PlanManifestDigest, StableAllocationSnapshot, TargetIntent,
        journal_test_candidate,
    };
    use crate::tenure_protocol::{
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        AcquireTenureRequestV1, AcquireTenureResponseV1, ControllerAcquireKeyRef,
        ControllerPublicKeyFingerprint, MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::apply::{
        ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterEpoch, RuntimeApplyControl,
        TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
        WriterTenureClaim, WriterTenureProof, WriterTenureSigningTranscript,
    };
    use paraegox_runtime_contracts::provenance::{
        PlanProvenance, SourcePlanDigest, SourcePlanRef, SourcePlanRevision, SourceScopeRef,
        TargetSliceDigest,
    };
    use paraegox_runtime_contracts::reference_control::{
        MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES, ReferenceApplyRequestDraftV1,
        ReferenceApplyRequestV1, ReferenceApplyTerminalFactsV1, ReferenceApplyTerminalHeadV1,
        ReferenceApplyTerminalLifecycleEffectV1, ReferenceApplyTerminalOutcomeV1,
        ReferenceApplyTerminalReceiptAuthClaimV1, ReferenceApplyTerminalReceiptDraftV1,
        ReferenceApplyTerminalReceiptV1, ReferenceBootstrapCompatibilityV1,
        ReferenceBootstrapFactsV1, ReferenceBootstrapRequestDraftV1, ReferenceBootstrapRequestIdV1,
        ReferenceBootstrapResponseAuthClaimV1, ReferenceBootstrapResponseDraftV1,
        ReferenceBootstrapResponseV1, ReferenceBootstrapServingIdentityV1,
        ReferenceBootstrapStateV1, ReferenceChannelBindingV1, ReferenceQueryDesiredHeadV1,
        ReferenceQueryDesiredStateV1, ReferenceQueryDurablePhaseV1, ReferenceQueryFactsV1,
        ReferenceQueryIdV1, ReferenceQueryLiveFactsV1, ReferenceQueryLiveStateV1,
        ReferenceQueryOperationLookupV1, ReferenceQueryOperationStateV1,
        ReferenceQueryOwnerStateV1, ReferenceQueryRequestDraftV1, ReferenceQueryRequestV1,
        ReferenceQueryResponseAuthClaimV1, ReferenceQueryResponseDraftV1, ReferenceQueryResponseV1,
        ReferenceQuerySelectorV1, ReferenceTargetExecutionPlanV4,
    };
    use paraegox_runtime_contracts::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim,
    };

    const SCOPE: DeploymentScopeId = DeploymentScopeId::from_bytes([0x21; 16]);
    const PLAN: DeploymentId = DeploymentId::from_bytes([0x22; 16]);
    const TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x61; 16]);
    const PLAN_OPERATION: ControllerOperationId = ControllerOperationId::from_bytes([0x31; 16]);
    const CONTROLLER_TENURE_SEED: [u8; 32] = [0x71; 32];
    const AUTHORITY_TENURE_SEED: [u8; 32] = [0x72; 32];
    const RUNTIME_RESPONSE_SEED: [u8; 32] = [0x73; 32];

    pub(crate) fn decode_frozen_base64(source: &str) -> Box<[u8]> {
        let compact = source
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        assert_eq!(compact.len() % 4, 0, "frozen base64 width");
        let mut decoded = Vec::with_capacity(compact.len() / 4 * 3);
        for (index, quartet) in compact.chunks_exact(4).enumerate() {
            let last = index + 1 == compact.len() / 4;
            let padding = usize::from(quartet[3] == b'=') + usize::from(quartet[2] == b'=');
            assert!(
                padding <= 2 && (padding == 0 || last),
                "frozen base64 padding"
            );
            let value = |byte: u8| -> u8 {
                match byte {
                    b'A'..=b'Z' => byte - b'A',
                    b'a'..=b'z' => byte - b'a' + 26,
                    b'0'..=b'9' => byte - b'0' + 52,
                    b'+' => 62,
                    b'/' => 63,
                    b'=' => 0,
                    _ => panic!("invalid frozen base64 byte"),
                }
            };
            let word = (u32::from(value(quartet[0])) << 18)
                | (u32::from(value(quartet[1])) << 12)
                | (u32::from(value(quartet[2])) << 6)
                | u32::from(value(quartet[3]));
            decoded.push((word >> 16) as u8);
            if padding < 2 {
                decoded.push((word >> 8) as u8);
            }
            if padding == 0 {
                decoded.push(word as u8);
            }
        }
        decoded.into_boxed_slice()
    }

    pub(crate) fn frozen_v7_zero_wire() -> Box<[u8]> {
        decode_frozen_base64(include_str!("testdata/controller_v7_zero.b64"))
    }

    pub(crate) fn frozen_v7_opaque_query_wire() -> Box<[u8]> {
        decode_frozen_base64(include_str!("testdata/controller_v7_opaque_query.b64"))
    }

    pub(crate) fn frozen_v8_zero_target_wire() -> Box<[u8]> {
        decode_frozen_base64(include_str!("testdata/controller_v8_zero_target.b64"))
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn authority_domain(byte: u8) -> ControllerTenureAuthorityDomainFingerprint {
        ControllerTenureAuthorityDomainFingerprint::from_stored(digest(byte))
    }

    fn auth(key: u8, generation: u64) -> ControllerRequestAuthPin {
        ControllerRequestAuthPin::try_new(
            ApplyAuthKeyRef::from_bytes([key; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("fixture algorithm must validate"),
            1,
            ControllerAuthKeyFingerprint::from_stored(digest(key.wrapping_add(1))),
            generation,
        )
        .expect("fixture auth pin must validate")
    }

    fn empty_allocation(target: RuntimeHostId) -> StableAllocationSnapshot {
        StableAllocationSnapshot::try_new(target, 0, 0, Vec::new())
            .expect("empty allocation must validate")
    }

    fn initial_state() -> ControllerJournalState {
        ControllerJournalState::try_initialize(
            SCOPE,
            PLAN,
            empty_allocation(TARGET),
            super::controller_test_manifest(TARGET),
            auth(0x11, 1),
        )
        .expect("initial state must validate")
    }

    fn initial_snapshot() -> ControllerJournalSnapshot {
        ControllerJournalSnapshot::try_initialize(
            [0x41; 32],
            ControllerOwnerIdentityFingerprint::from_stored(digest(0x42)),
            initial_state(),
        )
        .expect("initial snapshot must validate")
    }

    fn tenure_request(writer: u8, operation: [u8; 16], nonce: &[u8]) -> AcquireTenureRequestV1 {
        let signing_key = SigningKey::from_bytes(&CONTROLLER_TENURE_SEED);
        let fingerprint = ControllerPublicKeyFingerprint::for_ed25519_key(
            &signing_key.verifying_key().to_bytes(),
        )
        .expect("Controller tenure fingerprint must validate");
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                SCOPE,
                DeploymentWriterRef::from_bytes([writer; 16]),
                AcquireTenureOperationId::from_bytes(operation),
            ),
            PrincipalRef::from_bytes([0x73; 16]),
            ControllerAcquireKeyRef::from_bytes([0x74; 16]),
            fingerprint,
            nonce,
            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .expect("response bound must fit"),
        )
        .expect("tenure request draft must validate");
        let transcript = draft
            .signing_transcript()
            .expect("tenure request transcript must validate");
        let signature = signing_key.sign(transcript.as_bytes());
        draft
            .finalize_ed25519(&signature.to_bytes())
            .expect("tenure request must validate")
    }

    fn tenure_response(
        request: &AcquireTenureRequestV1,
        epoch: u64,
        supersedes_through: u64,
    ) -> AcquireTenureResponseV1 {
        let authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([0x75; 16]),
            TenureKeyRef::from_bytes([0x76; 16]),
            TenureProofAlgorithm::try_new(1).expect("proof algorithm must validate"),
            1,
        )
        .expect("proof authority must validate");
        let claim = WriterTenureClaim::try_new(
            request.proof_source_scope(),
            request.proof_writer(),
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(supersedes_through),
        )
        .expect("tenure claim must validate");
        let transcript =
            WriterTenureSigningTranscript::try_new(authority, claim, request.client_nonce())
                .expect("proof transcript must validate");
        let signature = SigningKey::from_bytes(&AUTHORITY_TENURE_SEED).sign(transcript.as_bytes());
        let proof = WriterTenureProof::try_new(
            authority,
            claim,
            request.client_nonce(),
            &signature.to_bytes(),
        )
        .expect("tenure proof must validate");
        AcquireTenureResponseV1::try_new(request, proof).expect("tenure response must validate")
    }

    pub(crate) fn binding(last_epoch: u64, response: &'static [u8]) -> ControllerTargetBinding {
        binding_with_store_and_build(
            [0x62; 32],
            last_epoch,
            response[0],
            0x11,
            PlanManifestDigest::try_new(super::controller_test_manifest(TARGET).manifest_digest())
                .expect("fixture manifest digest must validate"),
        )
    }

    fn binding_with_store_and_build(
        runtime_store_instance_id: [u8; 32],
        last_epoch: u64,
        response_marker: u8,
        build_marker: u8,
        manifest_digest: PlanManifestDigest,
    ) -> ControllerTargetBinding {
        let (response, channel) = bootstrap_evidence(
            runtime_store_instance_id,
            last_epoch,
            response_marker,
            build_marker,
        );
        ControllerTargetBinding::try_new(ControllerTargetBindingInput {
            target: TARGET,
            runtime_store_instance_id,
            channel_auth_fingerprint: ControllerChannelAuthFingerprint::from_stored(digest(0x63)),
            manifest_digest,
            first_runtime_host_epoch: 2,
            last_runtime_host_epoch: last_epoch,
            bootstrap_response: response.canonical_wire(),
            bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(
                response.response_digest(),
            ),
            runtime_response_auth: ControllerRuntimeResponseAuthPin::try_from_bootstrap_response(
                &response, channel,
            )
            .expect("fixture Runtime auth pin"),
        })
        .expect("fixture binding must validate")
    }

    fn bootstrap_evidence(
        runtime_store_instance_id: [u8; 32],
        epoch: u64,
        response_marker: u8,
        build_marker: u8,
    ) -> (ReferenceBootstrapResponseV1, ReferenceChannelBindingV1) {
        let controller = SigningKey::from_bytes(&CONTROLLER_TENURE_SEED);
        let runtime = SigningKey::from_bytes(&RUNTIME_RESPONSE_SEED);
        let request_claim = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([0x81; 16]),
            ApplyAuthKeyRef::from_bytes([0x82; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("request algorithm"),
            1,
            &[response_marker; 32],
        )
        .expect("bootstrap request claim");
        let request_draft = ReferenceBootstrapRequestDraftV1::try_new(
            ReferenceBootstrapRequestIdV1::from_bytes([response_marker; 16]),
            TARGET,
            SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            request_claim,
            u32::try_from(MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES).expect("response bound"),
        )
        .expect("bootstrap request draft");
        let request_signature = controller.sign(
            request_draft
                .signing_transcript()
                .expect("bootstrap request transcript")
                .as_bytes(),
        );
        let request = request_draft
            .finalize(&request_signature.to_bytes())
            .expect("bootstrap request");

        let (installation, compiled) =
            super::controller_test_installation_with_build(TARGET, build_marker);
        let compatibility = ReferenceBootstrapCompatibilityV1::try_from_verified_installation(
            &installation,
            compiled,
            digest(0x83),
        )
        .expect("bootstrap compatibility");
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            runtime_store_instance_id,
            1,
            epoch,
            ClockDomainRef::from_bytes([0x84; 16]),
            ClockGeneration::try_new(3).expect("clock generation"),
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
            PrincipalRef::from_bytes([0x85; 16]),
            digest(u8::try_from(epoch).expect("fixture epoch marker")),
            digest(0x86),
        )
        .expect("bootstrap channel");
        let response_claim = ReferenceBootstrapResponseAuthClaimV1::try_new(
            channel,
            ApplyAuthKeyRef::from_bytes([0x87; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("response algorithm"),
            1,
        )
        .expect("response auth claim");
        let response_draft =
            ReferenceBootstrapResponseDraftV1::try_new(&request, facts, channel, response_claim)
                .expect("bootstrap response draft");
        let response_signature = runtime.sign(
            response_draft
                .signing_transcript()
                .expect("bootstrap response transcript")
                .as_bytes(),
        );
        let response = response_draft
            .finalize(&response_signature.to_bytes())
            .expect("bootstrap response");
        (response, channel)
    }

    fn committed_snapshot() -> ControllerJournalSnapshot {
        let initial = initial_snapshot();
        let candidate = journal_test_candidate(
            TARGET,
            initial.state.installed_manifest().projection(),
            &initial.state.allocation,
            Some([2; 16]),
            0x50,
        )
        .expect("fixture candidate must validate");
        let prepared_state = initial
            .state
            .prepare_plan_candidate(PLAN_OPERATION, &candidate)
            .expect("candidate must prepare");
        let prepared = initial
            .try_successor(prepared_state)
            .expect("prepared snapshot must succeed");
        let committed_state = prepared
            .state
            .commit_plan_candidate(PLAN_OPERATION, &candidate)
            .expect("candidate must commit");
        prepared
            .try_successor(committed_state)
            .expect("committed snapshot must succeed")
    }

    fn bound_snapshot() -> ControllerJournalSnapshot {
        let committed = committed_snapshot();
        let state = committed
            .state
            .record_target_binding(binding(3, b"bootstrap-three"))
            .expect("binding must record");
        committed
            .try_successor(state)
            .expect("binding snapshot must succeed")
    }

    pub(crate) fn signed_snapshot() -> ControllerJournalSnapshot {
        let bound = bound_snapshot();
        let state = bound
            .state
            .record_signed_apply_intent(signed_input(&bound.state))
            .expect("signed intent must record");
        bound
            .try_successor(state)
            .expect("signed snapshot must succeed")
    }

    fn canonical_apply_request(
        state: &ControllerJournalState,
        operation_marker: u8,
    ) -> ReferenceApplyRequestV1 {
        let plan = state.committed_plan().expect("fixture committed plan");
        let execution = match plan.content().shape() {
            TargetIntent::OneSourceLoop => {
                let (_, instance, domain) = plan
                    .content()
                    .stable_allocation_subject()
                    .expect("fixture Loop allocation subject");
                let budgets = plan
                    .content()
                    .reference_lifecycle()
                    .expect("fixture Loop lifecycle");
                ReferenceTargetExecutionPlanV4::try_one_source_loop(
                    state.installed_manifest().verified_manifest(),
                    instance,
                    domain,
                    budgets,
                )
                .expect("fixture Loop execution plan")
            }
            TargetIntent::EmptyTarget => ReferenceTargetExecutionPlanV4::try_empty_deactivate(
                state.installed_manifest().verified_manifest(),
            )
            .expect("fixture empty execution plan"),
            TargetIntent::Omitted => panic!("omitted plan is not an apply fixture"),
        };
        let provenance = PlanProvenance::new(
            SourceScopeRef::from_bytes(*plan.scope().as_bytes()),
            SourcePlanRef::from_bytes(*plan.plan().as_bytes()),
            SourcePlanRevision::new(plan.revision().value()),
            plan.deployment_plan_digest(),
        );
        static TENURE_PROOF: OnceLock<WriterTenureProof> = OnceLock::new();
        let tenure_proof = TENURE_PROOF
            .get_or_init(|| {
                let request = tenure_request(0x31, [0x91; 16], &[0x92; 32]);
                tenure_response(&request, 1, 0).proof().clone()
            })
            .clone();
        let writer_context = PlanWriterContext::try_new(
            tenure_proof.claim().writer(),
            tenure_proof.claim().epoch(),
            tenure_proof,
        )
        .expect("fixture writer context");
        let apply_operation = ApplyOperationId::from_bytes([operation_marker; 16]);
        let control =
            RuntimeApplyControl::new(writer_context, ExpectedActive::None, apply_operation);
        let bootstrap = ReferenceBootstrapResponseV1::decode(
            state
                .target_binding()
                .expect("fixture target binding")
                .bootstrap_response(),
        )
        .expect("fixture bootstrap response");
        let bootstrap_facts = bootstrap.facts();
        let budget = BoundedDuration::from_nanos(1_000);
        let temporal = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([operation_marker.wrapping_add(3); 16]),
            bootstrap_facts.clock_domain(),
            bootstrap_facts.clock_generation(),
            budget,
            budget,
        )
        .expect("fixture temporal constraint");
        let request_auth = state.request_auth();
        let auth_claim = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([0xc3; 16]),
            request_auth.key(),
            request_auth.algorithm(),
            request_auth.algorithm_version(),
            &[operation_marker.wrapping_add(4); 32],
        )
        .expect("fixture request auth claim");
        let request_draft = ReferenceApplyRequestDraftV1::try_new(
            execution,
            provenance,
            control,
            temporal,
            state
                .target_binding()
                .expect("fixture target binding")
                .runtime_store_instance_id(),
            auth_claim,
        )
        .expect("fixture apply request draft");
        let controller = SigningKey::from_bytes(&CONTROLLER_TENURE_SEED);
        let request_signature = controller.sign(
            request_draft
                .signing_transcript()
                .expect("fixture request transcript")
                .as_bytes(),
        );
        request_draft
            .finalize(&request_signature.to_bytes())
            .expect("fixture apply request")
    }

    fn record_canonical_signed_apply(
        state: &ControllerJournalState,
        operation_marker: u8,
    ) -> (ControllerJournalState, ReferenceApplyRequestV1) {
        let request = canonical_apply_request(state, operation_marker);
        let next = state
            .record_signed_apply_intent(ControllerSignedApplyIntentInput {
                target: request.target(),
                source_plan_digest: request.provenance().source_plan_digest(),
                target_slice_digest: request.target_slice_digest(),
                apply_operation: request.control_commitment().control().operation_id(),
                request_digest: ControllerApplyRequestDigest::from_stored(
                    request.envelope_request_digest(),
                ),
                signed_request: request.canonical_wire(),
            })
            .expect("canonical signed apply intent must record");
        (next, request)
    }

    pub(crate) fn canonical_signed_snapshot(operation_marker: u8) -> ControllerJournalSnapshot {
        let bound = bound_snapshot();
        let (state, _) = record_canonical_signed_apply(bound.state(), operation_marker);
        bound
            .try_successor(state)
            .expect("canonical signed snapshot must succeed")
    }

    fn empty_bound_snapshot() -> ControllerJournalSnapshot {
        let initial = initial_snapshot();
        let candidate = journal_test_candidate(
            TARGET,
            initial.state.installed_manifest().projection(),
            &initial.state.allocation,
            None,
            0x50,
        )
        .expect("empty fixture candidate must validate");
        let prepared = initial
            .clone()
            .try_successor(
                initial
                    .state
                    .prepare_plan_candidate(PLAN_OPERATION, &candidate)
                    .expect("empty fixture candidate must prepare"),
            )
            .expect("empty fixture prepared snapshot");
        let committed = prepared
            .clone()
            .try_successor(
                prepared
                    .state
                    .commit_plan_candidate(PLAN_OPERATION, &candidate)
                    .expect("empty fixture candidate must commit"),
            )
            .expect("empty fixture committed snapshot");
        committed
            .clone()
            .try_successor(
                committed
                    .state
                    .record_target_binding(binding(3, b"bootstrap-empty"))
                    .expect("empty fixture binding must record"),
            )
            .expect("empty fixture bound snapshot")
    }

    pub(crate) fn canonical_empty_signed_snapshot(
        operation_marker: u8,
    ) -> ControllerJournalSnapshot {
        let bound = empty_bound_snapshot();
        let (state, _) = record_canonical_signed_apply(bound.state(), operation_marker);
        bound
            .try_successor(state)
            .expect("canonical empty signed snapshot must succeed")
    }

    fn signed_input(state: &ControllerJournalState) -> ControllerSignedApplyIntentInput<'static> {
        ControllerSignedApplyIntentInput {
            target: TARGET,
            source_plan_digest: state
                .committed_plan
                .as_ref()
                .expect("fixture plan must exist")
                .deployment_plan_digest,
            target_slice_digest: TargetSliceDigest::new(digest(0x66)),
            apply_operation: ApplyOperationId::from_bytes([0x67; 16]),
            request_digest: ControllerApplyRequestDigest::from_stored(digest(0x68)),
            signed_request: b"signed-request",
        }
    }

    fn different_signed_input(
        state: &ControllerJournalState,
        operation: u8,
        request: u8,
    ) -> ControllerSignedApplyIntentInput<'static> {
        ControllerSignedApplyIntentInput {
            target: TARGET,
            source_plan_digest: state
                .committed_plan
                .as_ref()
                .expect("fixture plan must exist")
                .deployment_plan_digest,
            target_slice_digest: TargetSliceDigest::new(digest(0x76)),
            apply_operation: ApplyOperationId::from_bytes([operation; 16]),
            request_digest: ControllerApplyRequestDigest::from_stored(digest(request)),
            signed_request: b"different-signed-request",
        }
    }

    fn replay_input(
        intent: &super::ControllerSignedApplyIntent,
    ) -> ControllerSignedApplyIntentInput<'_> {
        ControllerSignedApplyIntentInput {
            target: intent.target,
            source_plan_digest: intent.source_plan_digest,
            target_slice_digest: intent.target_slice_digest,
            apply_operation: intent.apply_operation,
            request_digest: intent.request_digest,
            signed_request: &intent.signed_request,
        }
    }

    #[derive(Clone, Copy)]
    struct QueryDesiredOverride {
        source_revision: SourcePlanRevision,
        target_slice_digest: TargetSliceDigest,
        manifest_digest: Digest32,
        high_water: SourcePlanRevision,
    }

    #[derive(Clone, Copy)]
    struct QueryInput {
        query_id: ReferenceQueryIdV1,
        query_snapshot_sequence: u64,
        marker: u8,
        channel: Option<ReferenceChannelBindingV1>,
        nonterminal_known: bool,
        terminal_observed: Option<ControllerObservedTarget>,
        terminal_result_override: Option<
            paraegox_runtime_contracts::reference_control::ReferenceApplyTerminalResultRefV1,
        >,
        bind_expected_request_digest: bool,
        principal: PrincipalRef,
        lookup_request_digest_override: Option<Digest32>,
        desired_override: Option<QueryDesiredOverride>,
    }

    fn query_input(sequence: u64, response: &'static [u8]) -> QueryInput {
        let mut query_id = [0_u8; 16];
        query_id[0] = 1;
        query_id[8..].copy_from_slice(&sequence.to_be_bytes());
        QueryInput {
            query_id: ReferenceQueryIdV1::from_bytes(query_id),
            query_snapshot_sequence: sequence,
            marker: response[0],
            channel: None,
            nonterminal_known: false,
            terminal_observed: None,
            terminal_result_override: None,
            bind_expected_request_digest: true,
            principal: PrincipalRef::from_bytes([0xc3; 16]),
            lookup_request_digest_override: None,
            desired_override: None,
        }
    }

    fn prepared_query_input(sequence: u64, response: &'static [u8]) -> QueryInput {
        QueryInput {
            nonterminal_known: true,
            ..query_input(sequence, response)
        }
    }

    fn terminal_query_input(
        sequence: u64,
        response: &'static [u8],
        observed: ControllerObservedTarget,
    ) -> QueryInput {
        assert!(matches!(
            observed,
            ControllerObservedTarget::Active | ControllerObservedTarget::Retired
        ));
        QueryInput {
            nonterminal_known: false,
            terminal_observed: Some(observed),
            ..query_input(sequence, response)
        }
    }

    fn fixture_terminal_result_ref()
    -> paraegox_runtime_contracts::reference_control::ReferenceApplyTerminalResultRefV1 {
        static RESULT: OnceLock<
            paraegox_runtime_contracts::reference_control::ReferenceApplyTerminalResultRefV1,
        > = OnceLock::new();
        *RESULT.get_or_init(|| direct_active_snapshot().1.facts().terminal_result_ref())
    }

    fn fixture_controller_receipt_ref() -> ControllerReceiptRef {
        ControllerReceiptRef::from_bytes(*fixture_terminal_result_ref().as_bytes())
    }

    fn query_contract_values(
        state: &ControllerJournalState,
        input: QueryInput,
    ) -> (
        ReferenceQueryRequestV1,
        ReferenceQueryResponseV1,
        ReferenceChannelBindingV1,
    ) {
        let binding = state
            .target_binding()
            .expect("query fixture target binding");
        let intent = state
            .current_signed_apply_intent()
            .expect("query fixture signed apply intent");
        let channel = input.channel.unwrap_or_else(|| {
            binding
                .runtime_response_auth()
                .channel(TARGET)
                .expect("query fixture channel")
        });
        let request_auth = state.request_auth();
        let source_revision = SourcePlanRevision::new(
            state
                .committed_plan()
                .expect("query fixture committed plan")
                .revision()
                .value(),
        );
        let mut client_nonce = [input.marker; 32];
        client_nonce[..16].copy_from_slice(input.query_id.as_bytes());
        client_nonce[24..].copy_from_slice(&input.query_snapshot_sequence.to_be_bytes());
        let claim = ApplyRequestAuthClaim::try_new(
            input.principal,
            request_auth.key(),
            request_auth.algorithm(),
            request_auth.algorithm_version(),
            &client_nonce,
        )
        .expect("query fixture request claim");
        let selector = ReferenceQuerySelectorV1::try_new(
            input.query_id,
            TARGET,
            SourceScopeRef::from_bytes(*state.scope().as_bytes()),
            binding.runtime_store_instance_id(),
            intent.apply_operation(),
            input
                .bind_expected_request_digest
                .then_some(intent.request_digest().value()),
        )
        .expect("query fixture selector");
        let draft = ReferenceQueryRequestDraftV1::try_new(
            selector,
            claim,
            paraegox_runtime_contracts::reference_control::MAX_REFERENCE_QUERY_RESPONSE_BYTES
                as u32,
        )
        .expect("query fixture request draft");
        let signature = SigningKey::from_bytes(&CONTROLLER_TENURE_SEED).sign(
            draft
                .signing_transcript()
                .expect("query fixture request transcript")
                .as_bytes(),
        );
        let request = draft
            .finalize(&signature.to_bytes())
            .expect("query fixture request");

        let bootstrap = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())
            .expect("query fixture bootstrap");
        let bootstrap_facts = bootstrap.facts();
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            binding.runtime_store_instance_id(),
            input.query_snapshot_sequence,
            bootstrap_facts.runtime_host_epoch(),
            bootstrap_facts.clock_domain(),
            bootstrap_facts.clock_generation(),
        )
        .expect("query fixture serving");
        let (lookup, desired_head, desired_high_water, live_state, resource_generation) =
            match input.terminal_observed {
                None if !input.nonterminal_known => (
                    ReferenceQueryOperationLookupV1::Unknown,
                    ReferenceQueryDesiredHeadV1::None,
                    SourcePlanRevision::new(0),
                    ReferenceQueryLiveStateV1::ExactZero,
                    0,
                ),
                None => {
                    let (desired_head, live_state, resource_generation) = match state
                        .committed_plan()
                        .expect("query fixture committed plan")
                        .content()
                        .shape()
                    {
                        TargetIntent::OneSourceLoop => (
                            ReferenceQueryDesiredHeadV1::OneSourceLoop {
                                source_revision,
                                target_slice_digest: intent.target_slice_digest(),
                                manifest_digest: binding.manifest_digest().value(),
                            },
                            ReferenceQueryLiveStateV1::LiveReady,
                            1,
                        ),
                        TargetIntent::EmptyTarget => (
                            ReferenceQueryDesiredHeadV1::EmptyDeactivate {
                                source_revision,
                                target_slice_digest: intent.target_slice_digest(),
                                manifest_digest: binding.manifest_digest().value(),
                            },
                            ReferenceQueryLiveStateV1::ExactZero,
                            0,
                        ),
                        TargetIntent::Omitted => panic!("query fixture plan must be actionable"),
                    };
                    (
                        ReferenceQueryOperationLookupV1::Known {
                            request_digest: intent.request_digest().value(),
                            durable_phase: ReferenceQueryDurablePhaseV1::PreparedNoEffects,
                            terminal_result: None,
                        },
                        desired_head,
                        source_revision,
                        live_state,
                        resource_generation,
                    )
                }
                Some(ControllerObservedTarget::Active) => (
                    ReferenceQueryOperationLookupV1::Known {
                        request_digest: input
                            .lookup_request_digest_override
                            .unwrap_or_else(|| intent.request_digest().value()),
                        durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                        terminal_result: Some(
                            input
                                .terminal_result_override
                                .unwrap_or_else(fixture_terminal_result_ref),
                        ),
                    },
                    ReferenceQueryDesiredHeadV1::OneSourceLoop {
                        source_revision: input
                            .desired_override
                            .map_or(source_revision, |value| value.source_revision),
                        target_slice_digest: input
                            .desired_override
                            .map_or(intent.target_slice_digest(), |value| {
                                value.target_slice_digest
                            }),
                        manifest_digest: input
                            .desired_override
                            .map_or(binding.manifest_digest().value(), |value| {
                                value.manifest_digest
                            }),
                    },
                    input
                        .desired_override
                        .map_or(source_revision, |value| value.high_water),
                    ReferenceQueryLiveStateV1::LiveReady,
                    1,
                ),
                Some(ControllerObservedTarget::Retired) => (
                    ReferenceQueryOperationLookupV1::Known {
                        request_digest: input
                            .lookup_request_digest_override
                            .unwrap_or_else(|| intent.request_digest().value()),
                        durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                        terminal_result: Some(
                            input
                                .terminal_result_override
                                .unwrap_or_else(fixture_terminal_result_ref),
                        ),
                    },
                    ReferenceQueryDesiredHeadV1::EmptyDeactivate {
                        source_revision: input
                            .desired_override
                            .map_or(source_revision, |value| value.source_revision),
                        target_slice_digest: input
                            .desired_override
                            .map_or(intent.target_slice_digest(), |value| {
                                value.target_slice_digest
                            }),
                        manifest_digest: input
                            .desired_override
                            .map_or(binding.manifest_digest().value(), |value| {
                                value.manifest_digest
                            }),
                    },
                    input
                        .desired_override
                        .map_or(source_revision, |value| value.high_water),
                    ReferenceQueryLiveStateV1::ExactZero,
                    0,
                ),
                Some(ControllerObservedTarget::Prepared | ControllerObservedTarget::Uncertain) => {
                    unreachable!("terminal query fixture shape is checked at construction")
                }
            };
        let operation = ReferenceQueryOperationStateV1::try_new(
            ReferenceQueryOwnerStateV1::Operational,
            None,
            lookup,
        )
        .expect("query fixture operation");
        let desired = ReferenceQueryDesiredStateV1::try_new(desired_head, desired_high_water)
            .expect("query fixture desired");
        let live = ReferenceQueryLiveFactsV1::try_new(
            live_state,
            resource_generation,
            input.query_snapshot_sequence,
            digest(input.marker),
        )
        .expect("query fixture live");
        let facts = ReferenceQueryFactsV1::try_new(serving, operation, desired, live)
            .expect("query fixture facts");
        let response_claim = ReferenceQueryResponseAuthClaimV1::try_new(
            channel,
            binding.runtime_response_auth().key(),
            binding.runtime_response_auth().algorithm(),
            binding.runtime_response_auth().algorithm_version(),
        )
        .expect("query fixture response claim");
        let response_draft =
            ReferenceQueryResponseDraftV1::try_new(&request, facts, channel, response_claim)
                .expect("query fixture response draft");
        let response_signature = SigningKey::from_bytes(&RUNTIME_RESPONSE_SEED).sign(
            response_draft
                .signing_transcript()
                .expect("query fixture response transcript")
                .as_bytes(),
        );
        let response = response_draft
            .finalize(&response_signature.to_bytes())
            .expect("query fixture response");
        (request, response, channel)
    }

    fn prepare_query(state: &ControllerJournalState, input: QueryInput) -> ControllerJournalState {
        let (request, _, _) = query_contract_values(state, input);
        state
            .prepare_query_request(&request)
            .expect("query fixture request must prepare")
    }

    fn record_query(state: &ControllerJournalState, input: QueryInput) -> ControllerJournalState {
        let (request, response, channel) = query_contract_values(state, input);
        state
            .prepare_query_request(&request)
            .expect("query fixture request must prepare")
            .record_query_response(&response, channel)
            .expect("query fixture response must record")
    }

    fn record_query_response(
        state: &ControllerJournalState,
        input: QueryInput,
    ) -> ControllerJournalState {
        let (_, response, channel) = query_contract_values(state, input);
        state
            .record_query_response(&response, channel)
            .expect("query fixture response must record")
    }

    pub(crate) fn decided_snapshot() -> ControllerJournalSnapshot {
        let signed = canonical_signed_snapshot(0x67);
        let input = terminal_query_input(9, b"query-nine", ControllerObservedTarget::Active);
        let prepared_state = prepare_query(&signed.state, input);
        let prepared = signed
            .try_successor(prepared_state)
            .expect("query request snapshot must succeed");
        let response_state = record_query_response(&prepared.state, input);
        let queried = prepared
            .try_successor(response_state)
            .expect("query response snapshot must succeed");
        let decision_state = queried
            .state
            .record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(fixture_controller_receipt_ref()),
            )
            .expect("decision must record");
        queried
            .try_successor(decision_state)
            .expect("decision snapshot must succeed")
    }

    pub(crate) fn direct_active_snapshot() -> (
        ControllerJournalSnapshot,
        ReferenceApplyTerminalReceiptV1,
        TargetSliceDigest,
    ) {
        direct_active_snapshot_with_operation(0x93)
    }

    pub(crate) fn direct_active_snapshot_with_operation(
        operation_marker: u8,
    ) -> (
        ControllerJournalSnapshot,
        ReferenceApplyTerminalReceiptV1,
        TargetSliceDigest,
    ) {
        let bound = bound_snapshot();
        let state = bound.state();
        let request = canonical_apply_request(state, operation_marker);
        let bootstrap = ReferenceBootstrapResponseV1::decode(
            state
                .target_binding()
                .expect("fixture target binding")
                .bootstrap_response(),
        )
        .expect("fixture bootstrap response");
        let bootstrap_facts = bootstrap.facts();
        let target_slice = request.target_slice_digest();
        let (signed_state, _) = record_canonical_signed_apply(state, operation_marker);
        let signed = bound
            .try_successor(signed_state)
            .expect("fixture signed apply successor");

        let runtime_auth = signed
            .state()
            .target_binding()
            .expect("fixture target binding")
            .runtime_response_auth();
        let channel = runtime_auth
            .channel(TARGET)
            .expect("fixture Runtime response channel");
        let terminal_facts = ReferenceApplyTerminalFactsV1::try_new(
            &request,
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
            digest(0x97),
            digest(0x98),
            bootstrap_facts.runtime_host_epoch(),
            10,
            bootstrap_facts.clock_generation(),
            11_000,
        )
        .expect("fixture terminal facts");
        let terminal_claim = ReferenceApplyTerminalReceiptAuthClaimV1::try_new(
            channel,
            runtime_auth.key(),
            runtime_auth.algorithm(),
            runtime_auth.algorithm_version(),
        )
        .expect("fixture terminal auth claim");
        let terminal_draft = ReferenceApplyTerminalReceiptDraftV1::try_new(
            &request,
            terminal_facts,
            channel,
            terminal_claim,
        )
        .expect("fixture terminal receipt draft");
        let runtime = SigningKey::from_bytes(&RUNTIME_RESPONSE_SEED);
        let terminal_signature = runtime.sign(
            terminal_draft
                .signing_transcript()
                .expect("fixture terminal transcript")
                .as_bytes(),
        );
        let receipt = terminal_draft
            .finalize(&terminal_signature.to_bytes())
            .expect("fixture terminal receipt");
        let terminal_state = signed
            .state()
            .record_direct_terminal_receipt(&receipt)
            .expect("fixture direct terminal receipt");
        let terminal = signed
            .try_successor(terminal_state)
            .expect("fixture direct terminal successor");
        (terminal, receipt, target_slice)
    }

    fn direct_receipt_for_signed_snapshot(
        signed: &ControllerJournalSnapshot,
        outcome: ReferenceApplyTerminalOutcomeV1,
        lifecycle: ReferenceApplyTerminalLifecycleEffectV1,
        head: ReferenceApplyTerminalHeadV1,
    ) -> ReferenceApplyTerminalReceiptV1 {
        let state = signed.state();
        let intent = state
            .current_signed_apply_intent()
            .expect("fixture signed intent");
        let request = ReferenceApplyRequestV1::decode(intent.signed_request())
            .expect("fixture canonical apply request");
        let binding = state.target_binding().expect("fixture target binding");
        let bootstrap = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())
            .expect("fixture bootstrap response");
        let runtime_auth = binding.runtime_response_auth();
        let channel = runtime_auth
            .channel(TARGET)
            .expect("fixture Runtime response channel");
        let facts = ReferenceApplyTerminalFactsV1::try_new(
            &request,
            outcome,
            lifecycle,
            head,
            digest(0xa7),
            digest(0xa8),
            bootstrap.facts().runtime_host_epoch(),
            10,
            bootstrap.facts().clock_generation(),
            12_000,
        )
        .expect("fixture terminal facts");
        let claim = ReferenceApplyTerminalReceiptAuthClaimV1::try_new(
            channel,
            runtime_auth.key(),
            runtime_auth.algorithm(),
            runtime_auth.algorithm_version(),
        )
        .expect("fixture terminal claim");
        let draft = ReferenceApplyTerminalReceiptDraftV1::try_new(&request, facts, channel, claim)
            .expect("fixture terminal receipt draft");
        let signature = SigningKey::from_bytes(&RUNTIME_RESPONSE_SEED).sign(
            draft
                .signing_transcript()
                .expect("fixture terminal receipt transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("fixture terminal receipt")
    }

    fn state_with_two_archived_rollouts() -> ControllerJournalState {
        let mut state = decided_snapshot().state;
        let second_plan = journal_test_candidate(
            TARGET,
            state.installed_manifest().projection(),
            &state.allocation,
            None,
            0x50,
        )
        .expect("second plan fixture must validate");
        let second_plan_operation = ControllerOperationId::from_bytes([0x32; 16]);
        state = state
            .prepare_plan_candidate(second_plan_operation, &second_plan)
            .expect("second plan must prepare");
        state = state
            .commit_plan_candidate(second_plan_operation, &second_plan)
            .expect("first rollout must archive");
        state = record_canonical_signed_apply(&state, 0x77).0;
        state = record_query(
            &state,
            terminal_query_input(10, b"query-ten", ControllerObservedTarget::Retired),
        );
        state = state
            .record_rollout_decision(
                ControllerObservedTarget::Retired,
                Some(fixture_controller_receipt_ref()),
            )
            .expect("second rollout must become terminal");
        let third_plan = journal_test_candidate(
            TARGET,
            state.installed_manifest().projection(),
            &state.allocation,
            None,
            0x50,
        )
        .expect("third plan fixture must validate");
        let third_plan_operation = ControllerOperationId::from_bytes([0x33; 16]);
        state = state
            .prepare_plan_candidate(third_plan_operation, &third_plan)
            .expect("third plan must prepare");
        state
            .commit_plan_candidate(third_plan_operation, &third_plan)
            .expect("second rollout must archive")
    }

    fn commit_empty_after_rollout(
        state: &ControllerJournalState,
        operation_marker: u8,
    ) -> Result<ControllerJournalState, ControllerJournalError> {
        let candidate = journal_test_candidate(
            TARGET,
            state.installed_manifest().projection(),
            &state.allocation,
            None,
            0x50,
        )
        .expect("Empty successor fixture must validate");
        let operation = ControllerOperationId::from_bytes([operation_marker; 16]);
        state
            .prepare_plan_candidate(operation, &candidate)?
            .commit_plan_candidate(operation, &candidate)
    }

    fn encode_unvalidated_state(state: &ControllerJournalState, snapshot_sequence: u64) -> Vec<u8> {
        let payload = super::encode_payload_fields(state, super::CONTROLLER_PAYLOAD_VERSION)
            .expect("test-only semantic forgery must have bounded fields");
        let mut prefix = Vec::new();
        prefix.extend_from_slice(super::JOURNAL_MAGIC);
        prefix.extend_from_slice(&super::JOURNAL_ENVELOPE_VERSION.to_be_bytes());
        prefix.extend_from_slice(&super::CONTROLLER_OWNER_KIND.to_be_bytes());
        prefix.extend_from_slice(&super::CONTROLLER_PAYLOAD_VERSION.to_be_bytes());
        prefix.extend_from_slice(&super::CHECKSUM_ALGORITHM_SHA256.to_be_bytes());
        prefix.extend_from_slice(&super::CHECKSUM_VERSION.to_be_bytes());
        prefix.extend_from_slice(&[0x41; 32]);
        prefix.extend_from_slice(digest(0x42).as_bytes());
        prefix.extend_from_slice(&snapshot_sequence.to_be_bytes());
        prefix.extend_from_slice(
            &u64::try_from(payload.len())
                .expect("fixture payload length must fit")
                .to_be_bytes(),
        );
        let checksum = controller_checksum(&prefix, &payload)
            .expect("test-only semantic forgery checksum must build");
        prefix.extend_from_slice(checksum.as_bytes());
        prefix.extend_from_slice(&payload);
        prefix
    }

    fn forge_latest_decision(
        state: &mut ControllerJournalState,
        observed: ControllerObservedTarget,
        receipt: Option<ControllerReceiptRef>,
    ) {
        let attempt = state
            .rollout
            .as_mut()
            .expect("forged decision rollout")
            .reconcile_attempts
            .last_mut()
            .expect("forged decision attempt");
        let observation = attempt
            .observation
            .as_ref()
            .expect("forged decision observation");
        attempt.decision = Some(ControllerRolloutDecision {
            query_id: observation.response().query_id(),
            query_snapshot_sequence: observation.query_snapshot_sequence(),
            observed,
            receipt,
        });
    }

    fn archive_forged_first_rollout(forged: &ControllerJournalState) -> ControllerJournalState {
        let (direct, _, _) = direct_active_snapshot();
        let mut archived = commit_empty_after_rollout(direct.state(), 0xd0)
            .expect("valid direct terminal rollout must archive");
        archived.apply_history[0] = forged
            .rollout
            .clone()
            .expect("forged current rollout must exist");
        archived.query_snapshot_high_water = forged.query_snapshot_high_water;
        archived
    }

    fn append_unvalidated_query_attempt(
        state: &ControllerJournalState,
        input: QueryInput,
        response_committed: bool,
        closure: Option<ControllerQueryClosureKind>,
        observed: Option<ControllerObservedTarget>,
    ) -> ControllerJournalState {
        assert!(closure.is_none() || observed.is_none());
        assert!(observed.is_none() || response_committed);
        let (request, response, channel) = query_contract_values(state, input);
        let binding = state
            .target_binding()
            .expect("unvalidated query fixture binding");
        let bootstrap = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())
            .expect("unvalidated query fixture bootstrap");
        let facts = bootstrap.facts();
        let prepared = ControllerPreparedQuery {
            request,
            request_auth: state.request_auth(),
            request_time_channel: channel,
            runtime_response_auth: binding.runtime_response_auth(),
            serving_baseline: ReferenceBootstrapServingIdentityV1::try_new(
                facts.target(),
                facts.runtime_store_instance_id(),
                facts.snapshot_sequence(),
                facts.runtime_host_epoch(),
                facts.clock_domain(),
                facts.clock_generation(),
            )
            .expect("unvalidated query fixture serving baseline"),
        };
        let observation = response_committed.then(|| {
            ControllerQueryObservation::try_new(response, channel, &prepared)
                .expect("unvalidated query fixture response remains contract-valid")
        });
        let decision = observed.map(|value| ControllerRolloutDecision {
            query_id: prepared.request().query_id(),
            query_snapshot_sequence: input.query_snapshot_sequence,
            observed: value,
            receipt: None,
        });
        let mut forged = state.clone();
        let rollout = forged.rollout.as_mut().expect("unvalidated query rollout");
        let mut attempts = rollout.reconcile_attempts.to_vec();
        attempts.push(ControllerReconcileAttempt {
            prepared,
            observation,
            closure,
            decision,
        });
        rollout.reconcile_attempts = attempts.into_boxed_slice();
        if response_committed {
            forged.query_snapshot_high_water = forged
                .query_snapshot_high_water
                .max(input.query_snapshot_sequence);
        }
        forged
    }

    fn refresh_checksum(encoded: &mut [u8]) {
        super::refresh_controller_test_checksum(encoded).expect("mutated envelope must checksum");
    }

    #[test]
    fn full_snapshot_has_frozen_checksum_and_round_trips_byte_identically() {
        let snapshot = decided_snapshot();
        assert_eq!(snapshot.snapshot_sequence, 8);
        let encoded = snapshot.encode().expect("snapshot must encode");
        assert!(encoded.starts_with(b"PXJR\0\x01\0\x01"));
        assert_eq!(
            &encoded[super::JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES..super::JOURNAL_HEADER_BYTES],
            &[
                26, 154, 249, 7, 72, 123, 98, 147, 96, 181, 222, 149, 71, 2, 213, 253, 189, 86, 56,
                0, 32, 131, 180, 0, 47, 40, 80, 45, 75, 187, 161, 37,
            ]
        );
        let decoded = ControllerJournalSnapshot::decode(&encoded).expect("snapshot must decode");
        assert_eq!(decoded, snapshot);
        assert_eq!(
            decoded.state.installed_manifest(),
            snapshot.state.installed_manifest()
        );
        assert_eq!(
            decoded
                .state
                .committed_plan
                .as_ref()
                .expect("decided snapshot must retain its committed plan")
                .content
                .manifest_digest(),
            PlanManifestDigest::try_new(decoded.state.installed_manifest().manifest_digest())
                .expect("installed manifest digest must remain valid")
        );
        assert_eq!(decoded.encode().expect("snapshot must reencode"), encoded);
    }

    #[test]
    fn decode_rederives_allocation_ids_and_rechecks_typed_plan_content() {
        let snapshot = committed_snapshot();
        let encoded = snapshot.encode().expect("snapshot must encode");
        let instance = *snapshot.state.allocation.records()[0].instance().as_bytes();
        let allocation_instance_offset = encoded
            .windows(instance.len())
            .position(|window| window == instance)
            .expect("allocation instance must be encoded");
        let mut forged_allocation = encoded.to_vec();
        forged_allocation[allocation_instance_offset] ^= 1;
        refresh_checksum(&mut forged_allocation);
        assert_eq!(
            ControllerJournalSnapshot::decode(&forged_allocation),
            Err(ControllerJournalError::InvalidAllocation)
        );

        let mut forged_plan = encoded.to_vec();
        let manifest = snapshot
            .state
            .installed_manifest()
            .canonical_manifest_wire();
        let manifest_offset = forged_plan
            .windows(manifest.len())
            .position(|window| window == manifest)
            .expect("exact installed manifest must be encoded");
        let projection = snapshot
            .state
            .installed_manifest()
            .projection()
            .canonical_projection();
        let plan_search_start = manifest_offset + manifest.len();
        let plan_offset = plan_search_start
            + forged_plan[plan_search_start..]
                .windows(projection.len())
                .position(|window| window == projection)
                .expect("fixture PlanContent projection must be encoded");
        forged_plan[plan_offset] ^= 1;
        refresh_checksum(&mut forged_plan);
        assert_eq!(
            ControllerJournalSnapshot::decode(&forged_plan),
            Err(ControllerJournalError::InvalidPlanContent)
        );

        let committed_plan = snapshot
            .state
            .committed_plan
            .as_ref()
            .expect("committed snapshot must retain its plan");
        let content = committed_plan.content.canonical_bytes();
        let content_offset = encoded[plan_search_start..]
            .windows(content.len())
            .position(|window| window == content)
            .map(|offset| plan_search_start + offset)
            .expect("exact committed PlanContent must be encoded");
        let content_digest_offset = content_offset + content.len();
        assert_eq!(
            &encoded[content_digest_offset..content_digest_offset + 32],
            committed_plan.plan_content_digest.value().as_bytes()
        );
        let mut forged_content_digest = encoded.to_vec();
        forged_content_digest[content_digest_offset] ^= 1;
        refresh_checksum(&mut forged_content_digest);
        assert_eq!(
            ControllerJournalSnapshot::decode(&forged_content_digest),
            Err(ControllerJournalError::PlanContentDigestMismatch)
        );
    }

    #[test]
    fn restart_strictly_decodes_the_exact_sequence_one_installed_manifest_pin() {
        let snapshot = initial_snapshot();
        let encoded = snapshot.encode().expect("snapshot must encode");
        let pin = snapshot.state.installed_manifest();
        let manifest = pin.canonical_manifest_wire();
        let manifest_offset = encoded
            .windows(manifest.len())
            .position(|window| window == manifest)
            .expect("exact installed manifest must be persisted");
        assert_eq!(
            &encoded[manifest_offset..manifest_offset + manifest.len()],
            manifest
        );
        assert_eq!(
            ControllerJournalSnapshot::decode(&encoded)
                .expect("strict restart must accept the exact pin")
                .state
                .installed_manifest(),
            pin
        );

        let mut changed_manifest = encoded.to_vec();
        changed_manifest[manifest_offset + manifest.len() - 1] ^= 1;
        refresh_checksum(&mut changed_manifest);
        assert_eq!(
            ControllerJournalSnapshot::decode(&changed_manifest),
            Err(ControllerJournalError::InvalidInstalledManifestPin)
        );

        let manifest_digest = pin.manifest_digest();
        let digest_offset = encoded
            .windows(manifest_digest.as_bytes().len())
            .position(|window| window == manifest_digest.as_bytes())
            .expect("separate installed manifest digest must be persisted");
        let mut changed_digest = encoded.to_vec();
        changed_digest[digest_offset] ^= 1;
        refresh_checksum(&mut changed_digest);
        assert_eq!(
            ControllerJournalSnapshot::decode(&changed_digest),
            Err(ControllerJournalError::InvalidInstalledManifestPin)
        );
    }

    #[test]
    fn envelope_corruption_versions_lengths_and_trailing_bytes_fail_closed() {
        let encoded = decided_snapshot().encode().expect("snapshot must encode");
        for end in 0..encoded.len() {
            assert!(
                ControllerJournalSnapshot::decode(&encoded[..end]).is_err(),
                "truncation at {end} must fail closed"
            );
        }
        for offset in 0..encoded.len() {
            let mut corrupted = encoded.to_vec();
            corrupted[offset] ^= 1;
            assert!(
                ControllerJournalSnapshot::decode(&corrupted).is_err(),
                "single-bit corruption at {offset} must fail closed"
            );
        }

        let mut bad_owner = encoded.to_vec();
        bad_owner[7] = 2;
        assert_eq!(
            ControllerJournalSnapshot::decode(&bad_owner),
            Err(ControllerJournalError::OwnerKindMismatch)
        );
        let mut bad_envelope_version = encoded.to_vec();
        bad_envelope_version[5] = 2;
        assert_eq!(
            ControllerJournalSnapshot::decode(&bad_envelope_version),
            Err(ControllerJournalError::UnknownEnvelopeVersion)
        );
        let mut bad_payload_version = encoded.to_vec();
        bad_payload_version[9] = 3;
        assert_eq!(
            ControllerJournalSnapshot::decode(&bad_payload_version),
            Err(ControllerJournalError::UnknownPayloadVersion)
        );
        let mut bad_checksum_version = encoded.to_vec();
        bad_checksum_version[11] = 2;
        assert_eq!(
            ControllerJournalSnapshot::decode(&bad_checksum_version),
            Err(ControllerJournalError::UnknownChecksumVersion)
        );
        let mut length_bomb = encoded.to_vec();
        let payload_length_offset = super::JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES - 8;
        length_bomb[payload_length_offset..payload_length_offset + 8]
            .copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            ControllerJournalSnapshot::decode(&length_bomb),
            Err(ControllerJournalError::LengthOverflow | ControllerJournalError::SnapshotTooLarge)
        ));
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            ControllerJournalSnapshot::decode(&trailing),
            Err(ControllerJournalError::LengthMismatch)
        );

        let mut payload_trailing = encoded.to_vec();
        payload_trailing.push(0);
        let payload_length = u64::try_from(payload_trailing.len() - super::JOURNAL_HEADER_BYTES)
            .expect("fixture length must fit");
        payload_trailing[payload_length_offset..payload_length_offset + 8]
            .copy_from_slice(&payload_length.to_be_bytes());
        refresh_checksum(&mut payload_trailing);
        assert_eq!(
            ControllerJournalSnapshot::decode(&payload_trailing),
            Err(ControllerJournalError::TrailingBytes)
        );
    }

    #[test]
    fn tenure_codec_persists_exact_prepared_uncertain_and_committed_bytes() {
        let initial = initial_snapshot();
        assert_eq!(
            initial.state().current_unresolved_tenure_transaction(),
            Ok(None)
        );
        let request = tenure_request(0x31, [0x32; 16], b"tenure-codec-nonce");
        let authority_domain = authority_domain(0xa5);
        let prepared_state = initial
            .state()
            .prepare_tenure_acquisition(&request, authority_domain)
            .expect("tenure request must prepare");
        let prepared = initial
            .try_successor(prepared_state)
            .expect("Prepared must be a valid successor");
        let prepared_bytes = prepared.encode().expect("Prepared snapshot must encode");
        let decoded_prepared = ControllerJournalSnapshot::decode(&prepared_bytes)
            .expect("Prepared snapshot must strictly decode");
        let transaction = decoded_prepared
            .state()
            .tenure_transaction(request.operation_id())
            .expect("Prepared transaction must survive restart");
        assert_eq!(transaction.phase(), ControllerTenurePhase::Prepared);
        assert_eq!(transaction.authority_domain_fingerprint(), authority_domain);
        assert_eq!(
            transaction.request().canonical_bytes(),
            request.canonical_bytes()
        );
        assert_eq!(
            decoded_prepared
                .state()
                .current_unresolved_tenure_transaction()
                .expect("unique Prepared transaction"),
            Some(transaction)
        );
        assert_eq!(
            decoded_prepared
                .state()
                .latest_committed_tenure_transaction(request.proof_writer()),
            Ok(None)
        );

        let uncertain_state = prepared
            .state()
            .mark_tenure_uncertain(&request)
            .expect("uncertain result must persist");
        let uncertain = prepared
            .try_successor(uncertain_state)
            .expect("Uncertain must be a valid successor");
        let decoded_uncertain = ControllerJournalSnapshot::decode(
            &uncertain.encode().expect("Uncertain snapshot must encode"),
        )
        .expect("Uncertain snapshot must strictly decode");
        assert_eq!(
            decoded_uncertain
                .state()
                .tenure_transaction(request.operation_id())
                .expect("Uncertain transaction must survive restart")
                .phase(),
            ControllerTenurePhase::Uncertain
        );
        assert_eq!(
            decoded_uncertain
                .state()
                .current_unresolved_tenure_transaction()
                .expect("unique Uncertain transaction")
                .expect("Uncertain transaction")
                .request()
                .canonical_bytes(),
            request.canonical_bytes()
        );

        let response = tenure_response(&request, 5, 4);
        let committed_state = uncertain
            .state()
            .commit_tenure_response(&request, &response)
            .expect("canonical response must commit");
        let committed = uncertain
            .try_successor(committed_state)
            .expect("Committed must be a valid successor");
        let committed_bytes = committed.encode().expect("Committed snapshot must encode");
        let decoded_committed = ControllerJournalSnapshot::decode(&committed_bytes)
            .expect("Committed snapshot must strictly decode");
        let committed_transaction = decoded_committed
            .state()
            .tenure_transaction(request.operation_id())
            .expect("Committed transaction must survive restart");
        assert_eq!(
            committed_transaction.phase(),
            ControllerTenurePhase::Committed
        );
        assert_eq!(committed_transaction.response(), Some(&response));
        assert_eq!(
            committed_transaction
                .committed_proof()
                .expect("committed proof must exist"),
            response.proof()
        );
        assert_eq!(
            decoded_committed
                .state()
                .current_unresolved_tenure_transaction(),
            Ok(None)
        );
        assert_eq!(
            decoded_committed
                .state()
                .latest_committed_tenure_transaction(request.proof_writer())
                .expect("unique highest committed tenure"),
            Some(committed_transaction)
        );

        let mut old_payload_version = prepared_bytes.to_vec();
        old_payload_version[8..10].copy_from_slice(&6_u16.to_be_bytes());
        assert_eq!(
            ControllerJournalSnapshot::decode(&old_payload_version),
            Err(ControllerJournalError::UnknownPayloadVersion)
        );
        let mut old_inner_payload_version = prepared_bytes.to_vec();
        let inner_version_offset = super::JOURNAL_HEADER_BYTES + CONTROLLER_PAYLOAD_MAGIC.len();
        old_inner_payload_version[inner_version_offset..inner_version_offset + 2]
            .copy_from_slice(&6_u16.to_be_bytes());
        refresh_checksum(&mut old_inner_payload_version);
        assert_eq!(
            ControllerJournalSnapshot::decode(&old_inner_payload_version),
            Err(ControllerJournalError::UnknownPayloadVersion)
        );

        let digest_offset = prepared_bytes
            .windows(request.request_digest().as_bytes().len())
            .position(|window| window == request.request_digest().as_bytes())
            .expect("explicit request digest must be persisted");
        let mut changed_identity_fact = prepared_bytes.to_vec();
        changed_identity_fact[digest_offset] ^= 1;
        refresh_checksum(&mut changed_identity_fact);
        assert_eq!(
            ControllerJournalSnapshot::decode(&changed_identity_fact),
            Err(ControllerJournalError::TenureTransactionFactChanged)
        );
        let authority_domain_offset = prepared_bytes
            .windows(16 + 1 + 32)
            .position(|window| {
                &window[..16] == request.operation_id().as_bytes()
                    && window[16] == ControllerTenurePhase::Prepared as u8
                    && &window[17..] == authority_domain.value().as_bytes()
            })
            .map(|offset| offset + 17)
            .expect("Authority domain fingerprint must be persisted after the transaction phase");
        let mut zero_authority_domain = prepared_bytes.to_vec();
        zero_authority_domain[authority_domain_offset..authority_domain_offset + 32].fill(0);
        refresh_checksum(&mut zero_authority_domain);
        assert_eq!(
            ControllerJournalSnapshot::decode(&zero_authority_domain),
            Err(ControllerJournalError::InvalidTenureAuthorityDomainFingerprint)
        );
        assert!(
            ControllerJournalSnapshot::decode(&committed_bytes[..committed_bytes.len() - 1])
                .is_err()
        );
    }

    #[test]
    fn tenure_identity_replay_and_successors_are_exact_and_append_only() {
        let initial = initial_snapshot();
        let request = tenure_request(0x31, [0x32; 16], b"tenure-identity-nonce");
        let prepared_state = initial
            .state()
            .prepare_tenure_acquisition(&request, authority_domain(0xa5))
            .expect("tenure request must prepare");
        assert_eq!(
            prepared_state
                .prepare_tenure_acquisition(&request, authority_domain(0xa5))
                .expect("exact Prepared replay must be idempotent"),
            prepared_state
        );
        assert_eq!(
            prepared_state.prepare_tenure_acquisition(&request, authority_domain(0xa6)),
            Err(ControllerJournalError::TenureAuthorityDomainMismatch)
        );
        assert_eq!(
            initial.state().prepare_tenure_acquisition(
                &request,
                ControllerTenureAuthorityDomainFingerprint::from_stored(Digest32::from_bytes(
                    [0; 32],
                )),
            ),
            Err(ControllerJournalError::InvalidTenureAuthorityDomainFingerprint)
        );
        let changed_nonce = tenure_request(0x31, [0x32; 16], b"changed-tenure-nonce");
        assert_eq!(
            prepared_state.prepare_tenure_acquisition(&changed_nonce, authority_domain(0xa5)),
            Err(ControllerJournalError::TenureTransactionConflict)
        );
        let nonce_collision = tenure_request(0x31, [0x33; 16], b"tenure-identity-nonce");
        assert_eq!(
            prepared_state.prepare_tenure_acquisition(&nonce_collision, authority_domain(0xa5)),
            Err(ControllerJournalError::TenureTransactionConflict)
        );

        let mut removed = prepared_state.clone();
        removed.tenure_transactions = Box::new([]);
        assert_eq!(
            removed.validate_successor_of(&prepared_state),
            Err(ControllerJournalError::TenureTransactionRemoved)
        );
        let mut changed = prepared_state.clone();
        changed.tenure_transactions[0] = ControllerTenureTransaction::try_new(
            changed_nonce,
            authority_domain(0xa5),
            ControllerTenurePhase::Prepared,
            None,
        )
        .expect("changed canonical request is individually valid");
        assert_eq!(
            changed.validate_successor_of(&prepared_state),
            Err(ControllerJournalError::TenureTransactionFactChanged)
        );
        let mut changed_domain = prepared_state.clone();
        changed_domain.tenure_transactions[0].authority_domain_fingerprint = authority_domain(0xa6);
        assert_eq!(
            changed_domain.validate_successor_of(&prepared_state),
            Err(ControllerJournalError::TenureTransactionFactChanged)
        );

        let response = tenure_response(&request, 5, 4);
        let committed = prepared_state
            .commit_tenure_response(&request, &response)
            .expect("tenure response must commit");
        assert_eq!(
            committed
                .commit_tenure_response(&request, &response)
                .expect("exact success replay must be idempotent"),
            committed
        );
    }

    #[test]
    fn tenure_successor_requires_monotonic_covered_epochs_and_consistent_same_epoch_proofs() {
        let first_request = tenure_request(0x31, [1; 16], b"first-tenure-nonce");
        let first_prepared = initial_state()
            .prepare_tenure_acquisition(&first_request, authority_domain(0xa5))
            .expect("first tenure must prepare");
        let first_response = tenure_response(&first_request, 5, 4);
        let first_committed = first_prepared
            .commit_tenure_response(&first_request, &first_response)
            .expect("first tenure must commit");

        let second_request = tenure_request(0x31, [2; 16], b"second-tenure-nonce");
        let second_prepared = first_committed
            .prepare_tenure_acquisition(&second_request, authority_domain(0xa5))
            .expect("second tenure must prepare");

        let lower_response = tenure_response(&second_request, 4, 3);
        assert_eq!(
            second_prepared.commit_tenure_response(&second_request, &lower_response),
            Err(ControllerJournalError::TenureEpochNotMonotonic)
        );
        let mut forged_lower = second_prepared.clone();
        forged_lower.tenure_transactions[1] = ControllerTenureTransaction::try_new(
            second_request.clone(),
            authority_domain(0xa5),
            ControllerTenurePhase::Committed,
            Some(lower_response),
        )
        .expect("lower proof is individually canonical");
        assert_eq!(
            forged_lower.validate_successor_of(&second_prepared),
            Err(ControllerJournalError::TenureEpochNotMonotonic)
        );

        let gap_response = tenure_response(&second_request, 7, 4);
        assert_eq!(
            second_prepared.commit_tenure_response(&second_request, &gap_response),
            Err(ControllerJournalError::TenureSupersessionGap)
        );
        let mut forged_gap = second_prepared.clone();
        forged_gap.tenure_transactions[1] = ControllerTenureTransaction::try_new(
            second_request.clone(),
            authority_domain(0xa5),
            ControllerTenurePhase::Committed,
            Some(gap_response),
        )
        .expect("gap proof is individually canonical");
        assert_eq!(
            forged_gap.validate_successor_of(&second_prepared),
            Err(ControllerJournalError::TenureSupersessionGap)
        );

        let same_epoch_response = tenure_response(&second_request, 5, 4);
        let mut forged_same_epoch = second_prepared.clone();
        forged_same_epoch.tenure_transactions[1] = ControllerTenureTransaction::try_new(
            second_request.clone(),
            authority_domain(0xa5),
            ControllerTenurePhase::Committed,
            Some(same_epoch_response),
        )
        .expect("same-epoch proof is individually canonical");
        assert_eq!(
            forged_same_epoch.validate(),
            Err(ControllerJournalError::TenureEpochConflict)
        );
        assert_eq!(
            forged_same_epoch.latest_committed_tenure_transaction(second_request.proof_writer()),
            Err(ControllerJournalError::TenureEpochConflict)
        );

        let covered_response = tenure_response(&second_request, 7, 5);
        let second_committed = second_prepared
            .commit_tenure_response(&second_request, &covered_response)
            .expect("higher epoch covering the prior maximum must commit");
        assert_eq!(
            second_committed
                .latest_committed_tenure_transaction(second_request.proof_writer())
                .expect("unambiguous latest committed tenure")
                .expect("latest committed tenure")
                .request()
                .canonical_bytes(),
            second_request.canonical_bytes()
        );
    }

    #[test]
    fn globally_latest_writer_fences_every_older_writer_proof() {
        let writer_a_request = tenure_request(0x31, [1; 16], b"writer-a-tenure-nonce");
        let writer_a_prepared = initial_state()
            .prepare_tenure_acquisition(&writer_a_request, authority_domain(0xa5))
            .expect("writer A tenure must prepare");
        let writer_a_response = tenure_response(&writer_a_request, 1, 0);
        let writer_a_committed = writer_a_prepared
            .commit_tenure_response(&writer_a_request, &writer_a_response)
            .expect("writer A tenure must commit");
        assert_eq!(
            writer_a_committed.latest_committed_tenure_proof(writer_a_request.proof_writer()),
            Some(writer_a_response.proof())
        );

        let writer_b_request = tenure_request(0x32, [2; 16], b"writer-b-tenure-nonce");
        let writer_b_prepared = writer_a_committed
            .prepare_tenure_acquisition(&writer_b_request, authority_domain(0xa5))
            .expect("writer B tenure must prepare");
        let writer_b_response = tenure_response(&writer_b_request, 2, 1);
        let writer_b_committed = writer_b_prepared
            .commit_tenure_response(&writer_b_request, &writer_b_response)
            .expect("writer B tenure must commit and cover writer A");

        assert_eq!(
            writer_b_committed
                .global_latest_committed_tenure_transaction()
                .expect("global latest tenure must be unambiguous")
                .expect("global latest tenure must exist")
                .request(),
            &writer_b_request
        );
        assert_eq!(
            writer_b_committed.latest_committed_tenure_proof(writer_a_request.proof_writer()),
            None
        );
        assert_eq!(
            writer_b_committed.latest_committed_tenure_transaction(writer_a_request.proof_writer()),
            Ok(None)
        );
        assert!(
            !writer_b_committed.contains_committed_tenure_proof(writer_a_response.proof()),
            "a globally superseded writer proof must not replay"
        );
        assert_eq!(
            writer_b_committed.latest_committed_tenure_proof(writer_b_request.proof_writer()),
            Some(writer_b_response.proof())
        );
        assert!(writer_b_committed.contains_committed_tenure_proof(writer_b_response.proof()));
    }

    #[test]
    fn tenure_transaction_capacity_is_independent_and_bounded() {
        let mut state = initial_state();
        for index in 1..=MAX_CONTROLLER_TENURE_TRANSACTIONS {
            let operation = u128::try_from(index)
                .expect("fixture index must fit")
                .to_be_bytes();
            let nonce = u64::try_from(index)
                .expect("fixture index must fit")
                .to_be_bytes();
            let request = tenure_request(0x31, operation, &nonce);
            state = state
                .prepare_tenure_acquisition(&request, authority_domain(0xa5))
                .expect("bounded tenure row must prepare");
            let epoch = u64::try_from(index).expect("fixture index must fit") + 1;
            let response = tenure_response(&request, epoch, epoch - 1);
            state = state
                .commit_tenure_response(&request, &response)
                .expect("bounded tenure row must commit");
        }
        assert!(
            state.operations.is_empty(),
            "tenure rows are not plan-ledger rows"
        );
        let overflow_request = tenure_request(
            0x31,
            u128::try_from(MAX_CONTROLLER_TENURE_TRANSACTIONS + 1)
                .expect("overflow fixture index must fit")
                .to_be_bytes(),
            b"overflow-tenure-nonce",
        );
        assert_eq!(
            state.prepare_tenure_acquisition(&overflow_request, authority_domain(0xa5)),
            Err(ControllerJournalError::TenureCapacityExceeded)
        );
    }

    #[test]
    fn plan_commit_requires_exact_typed_candidate_and_prepared_operation() {
        let initial = initial_snapshot();
        let candidate = journal_test_candidate(
            TARGET,
            initial.state.installed_manifest().projection(),
            &initial.state.allocation,
            Some([2; 16]),
            0x50,
        )
        .expect("fixture candidate must validate");
        assert_eq!(
            initial
                .state
                .commit_plan_candidate(PLAN_OPERATION, &candidate),
            Err(ControllerJournalError::MissingPreparedOperation)
        );

        let prepared_state = initial
            .state
            .prepare_plan_candidate(PLAN_OPERATION, &candidate)
            .expect("candidate must prepare");
        let prepared = initial
            .try_successor(prepared_state)
            .expect("prepared state must be a successor");
        let different = journal_test_candidate(
            TARGET,
            prepared.state.installed_manifest().projection(),
            &prepared.state.allocation,
            Some([2; 16]),
            0x51,
        )
        .expect("different typed candidate must validate");
        assert_eq!(
            prepared
                .state
                .commit_plan_candidate(PLAN_OPERATION, &different),
            Err(ControllerJournalError::OperationConflict)
        );

        let committed_state = prepared
            .state
            .commit_plan_candidate(PLAN_OPERATION, &candidate)
            .expect("exact candidate must commit");
        assert_eq!(committed_state.current_revision(), 1);
        assert_eq!(committed_state.allocation.generation(), 1);
        assert_eq!(committed_state.allocation.high_water(), 1);
        assert_eq!(
            committed_state.operations[0].phase,
            ControllerOperationPhase::Committed
        );
        let committed = prepared
            .try_successor(committed_state)
            .expect("commit must be one valid successor");
        assert_eq!(
            committed
                .state
                .prepare_plan_candidate(PLAN_OPERATION, &candidate)
                .expect("same prepared operation retry must resolve idempotently"),
            committed.state
        );
        assert_eq!(
            committed
                .state
                .commit_plan_candidate(PLAN_OPERATION, &candidate)
                .expect("same commit retry must be idempotent"),
            committed.state
        );
    }

    #[test]
    fn snapshot_successor_rejects_owner_sequence_lineage_and_operation_swaps() {
        let initial = initial_snapshot();
        let candidate = journal_test_candidate(
            TARGET,
            initial.state.installed_manifest().projection(),
            &initial.state.allocation,
            Some([2; 16]),
            0x50,
        )
        .expect("fixture candidate must validate");
        let prepared_state = initial
            .state
            .prepare_plan_candidate(PLAN_OPERATION, &candidate)
            .expect("candidate must prepare");
        let prepared = initial
            .try_successor(prepared_state)
            .expect("prepared state must succeed");

        let owner_swap = ControllerJournalSnapshot::try_from_stored(
            [0x99; 32],
            initial.owner_identity_fingerprint,
            2,
            prepared.state.clone(),
        )
        .expect("individually valid swapped snapshot must construct");
        assert_eq!(
            owner_swap.validate_successor_of(&initial),
            Err(ControllerJournalError::SnapshotOwnerChanged)
        );
        let sequence_jump = ControllerJournalSnapshot::try_from_stored(
            initial.store_instance_id,
            initial.owner_identity_fingerprint,
            3,
            prepared.state.clone(),
        )
        .expect("individually valid sequence jump must construct");
        assert_eq!(
            sequence_jump.validate_successor_of(&initial),
            Err(ControllerJournalError::SnapshotSequenceNotNext)
        );

        let mut removed = prepared.state.clone();
        removed.operations = Box::new([]);
        assert_eq!(
            removed.validate_successor_of(&prepared.state),
            Err(ControllerJournalError::OperationRemoved)
        );
        let mut changed_fact = prepared.state.clone();
        changed_fact.operations[0].intent_digest =
            ControllerPlanCommitIntentDigest::from_stored(digest(0xee));
        assert_eq!(
            changed_fact.validate_successor_of(&prepared.state),
            Err(ControllerJournalError::OperationFactChanged)
        );
        let mut wrong_expected_revision = prepared.state.clone();
        wrong_expected_revision.operations[0].expected_revision = 1;
        assert_eq!(
            wrong_expected_revision.validate_successor_of(&initial.state),
            Err(ControllerJournalError::InvalidOperationTransition)
        );

        let mut changed_lineage = prepared.state.clone();
        changed_lineage.scope = DeploymentScopeId::from_bytes([0x77; 16]);
        assert_eq!(
            changed_lineage.validate_successor_of(&prepared.state),
            Err(ControllerJournalError::PlanLineageChanged)
        );
        assert_eq!(
            ControllerJournalSnapshot::try_initialize(
                [0x88; 32],
                ControllerOwnerIdentityFingerprint::from_stored(digest(0x89)),
                prepared.state.clone(),
            ),
            Err(ControllerJournalError::NonFreshInitialState)
        );
    }

    #[test]
    fn installed_manifest_pin_is_required_for_the_target_and_never_changes() {
        let wrong_target = RuntimeHostId::from_bytes([0x62; 16]);
        assert_eq!(
            ControllerJournalState::try_initialize(
                SCOPE,
                PLAN,
                empty_allocation(TARGET),
                super::controller_test_manifest(wrong_target),
                auth(0x11, 1),
            ),
            Err(ControllerJournalError::InstalledManifestTargetMismatch)
        );

        let initial = initial_snapshot();
        let mut changed = initial.state.clone();
        changed.installed_manifest = super::controller_test_manifest_with_build(TARGET, 0x12);
        assert_eq!(
            initial.try_successor(changed),
            Err(ControllerJournalError::InstalledManifestPinChanged)
        );
    }

    #[test]
    fn auth_and_target_binding_are_monotonic_and_identity_fixed() {
        let committed = committed_snapshot();
        let rotated_state = committed
            .state
            .rotate_request_auth(auth(0x12, 2))
            .expect("higher auth generation must validate");
        let rotated = committed
            .try_successor(rotated_state)
            .expect("auth rotation must be a successor");
        assert_eq!(
            rotated.state.rotate_request_auth(auth(0x11, 1)),
            Err(ControllerJournalError::AuthRotationRegression)
        );

        let bound = bound_snapshot();
        let changed_store = binding_with_store_and_build(
            [0x72; 32],
            4,
            b'b',
            0x11,
            PlanManifestDigest::try_new(bound.state.installed_manifest().manifest_digest())
                .expect("installed manifest digest must validate"),
        );
        assert_eq!(
            bound.state.record_target_binding(changed_store),
            Err(ControllerJournalError::TargetBindingChanged)
        );
        assert_eq!(
            bound
                .state
                .record_target_binding(binding(2, b"bootstrap-two")),
            Err(ControllerJournalError::TargetBindingChanged)
        );
        assert_eq!(
            bound
                .state
                .record_target_binding(binding(3, b"changed-three")),
            Err(ControllerJournalError::TargetBindingChanged)
        );
        let refreshed_state = bound
            .state
            .record_target_binding(binding(4, b"bootstrap-four"))
            .expect("higher host epoch must validate");
        bound
            .try_successor(refreshed_state)
            .expect("higher host epoch must be a snapshot successor");

        let other_target = RuntimeHostId::from_bytes([0x71; 16]);
        let other_manifest = super::controller_test_manifest(other_target);
        let other_candidate = journal_test_candidate(
            other_target,
            other_manifest.projection(),
            &empty_allocation(other_target),
            Some([2; 16]),
            0x52,
        )
        .expect("other target candidate must validate");
        assert_eq!(
            bound.state.prepare_plan_candidate(
                ControllerOperationId::from_bytes([0x32; 16]),
                &other_candidate
            ),
            Err(ControllerJournalError::CandidateTargetMismatch)
        );
    }

    #[test]
    fn checksum_valid_single_field_runtime_auth_pin_mutation_is_rejected_on_reopen() {
        let bound = bound_snapshot();
        let pin = bound
            .state
            .target_binding
            .as_ref()
            .expect("fixture target binding")
            .runtime_response_auth;
        let mut encoded_pin = Vec::new();
        super::append_runtime_response_auth_pin(&mut encoded_pin, pin);
        let mut encoded = bound.encode().expect("bound snapshot bytes").into_vec();
        let matches = encoded
            .windows(encoded_pin.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == encoded_pin).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "auth pin encoding must be unique");

        // Keep the exact PXBR and its digest, but alter one endpoint-identity
        // byte inside the separately persisted auth pin.
        let endpoint_digest_offset = matches[0] + 32 + 16;
        encoded[endpoint_digest_offset] ^= 0x01;
        super::refresh_controller_test_checksum(&mut encoded).expect("refresh checksum");
        assert_eq!(
            ControllerJournalSnapshot::decode(&encoded),
            Err(ControllerJournalError::InvalidTargetBinding)
        );
    }

    #[test]
    fn signed_query_response_and_decision_are_four_distinct_successor_transactions() {
        let committed = committed_snapshot();
        let binding_and_intent = committed
            .state
            .record_target_binding(binding(3, b"bootstrap-three"))
            .expect("in-memory binding candidate must validate");
        let binding_and_intent = binding_and_intent
            .record_signed_apply_intent(signed_input(&binding_and_intent))
            .expect("in-memory signed intent candidate must validate");
        assert_eq!(
            committed.try_successor(binding_and_intent),
            Err(ControllerJournalError::TargetBindingNotCommittedFirst)
        );

        let bound = bound_snapshot();
        let signed_state = record_canonical_signed_apply(&bound.state, 0x67).0;
        assert!(
            signed_state
                .rollout
                .as_ref()
                .expect("rollout must exist")
                .reconcile_attempts
                .is_empty()
        );
        let signed = bound
            .try_successor(signed_state)
            .expect("signed-before-send snapshot must succeed");
        let input = terminal_query_input(9, b"query-nine", ControllerObservedTarget::Active);
        let request_state = prepare_query(&signed.state, input);
        assert_eq!(
            request_state.record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(fixture_controller_receipt_ref()),
            ),
            Err(ControllerJournalError::QueryNotCommittedBeforeDecision)
        );
        let combined = record_query(&signed.state, input);
        assert_eq!(
            signed.clone().try_successor(combined),
            Err(ControllerJournalError::QueryNotCommittedBeforeDecision),
            "PXQR and PXQS cannot enter one Controller transaction"
        );
        let requested = signed
            .try_successor(request_state)
            .expect("query request must commit before send");
        let response_state = record_query_response(&requested.state, input);
        let queried = requested
            .try_successor(response_state)
            .expect("query response must commit separately");
        let mut conflicting = input;
        conflicting.marker = b'c';
        let (conflicting_request, _, _) = query_contract_values(&queried.state, conflicting);
        assert_eq!(
            queried.state.prepare_query_request(&conflicting_request),
            Err(ControllerJournalError::QueryIdentityConflict)
        );
        let decided_state = queried
            .state
            .record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(fixture_controller_receipt_ref()),
            )
            .expect("decision must bind durable query");
        let decided = queried
            .try_successor(decided_state)
            .expect("decision must be the fourth transaction");
        let (terminal_request, _, _) =
            query_contract_values(&decided.state, query_input(10, b"query-ten"));
        assert_eq!(
            decided.state.prepare_query_request(&terminal_request),
            Err(ControllerJournalError::EvidenceAfterTerminalDecision)
        );

        let mut changed_request = signed.state.clone();
        changed_request
            .rollout
            .as_mut()
            .expect("rollout must exist")
            .signed_intent
            .signed_request = b"different-signed-request".as_slice().into();
        assert_eq!(
            changed_request.validate_successor_of(&signed.state),
            Err(ControllerJournalError::RolloutIntentChanged)
        );
    }

    #[test]
    fn query_closure_is_a_distinct_exact_successor_and_never_revives_send_authority() {
        let signed = canonical_signed_snapshot(0x67);
        let input = query_input(9, b"query-nine");
        let (request, response, channel) = query_contract_values(&signed.state, input);
        let request_state = signed
            .state
            .prepare_query_request(&request)
            .expect("query request must prepare");
        let requested = signed
            .clone()
            .try_successor(request_state.clone())
            .expect("query request must commit before closure");

        let combined = request_state
            .record_query_closure(ControllerQueryClosureKind::DeliveryUncertain)
            .expect("in-memory combined request and closure can be constructed");
        assert_eq!(
            signed.try_successor(combined),
            Err(ControllerJournalError::QueryNotCommittedBeforeDecision),
            "PXQR and its closure cannot enter one Controller transaction"
        );

        for closure in [
            ControllerQueryClosureKind::NotSent,
            ControllerQueryClosureKind::DeliveryUncertain,
            ControllerQueryClosureKind::ResidentAuthorityLostAfterRestart,
            ControllerQueryClosureKind::ResponseRejected,
        ] {
            let closed_state = requested
                .state
                .record_query_closure(closure)
                .expect("closure must record");
            let closed = requested
                .clone()
                .try_successor(closed_state)
                .expect("closure must be its own successor");
            assert_eq!(closed.state.query_snapshot_high_water, 0);
            assert_eq!(closed.state.current_query_closure(), Some(closure));
            assert!(!closed.state.current_query_is_open());
            let encoded = closed.encode().expect("closed snapshot must encode");
            let decoded = ControllerJournalSnapshot::decode(&encoded)
                .expect("closed snapshot must decode exactly");
            assert_eq!(decoded, closed);
            assert_eq!(
                decoded.encode().expect("closed snapshot must reencode"),
                encoded
            );
        }

        let closed_state = requested
            .state
            .record_query_closure(ControllerQueryClosureKind::DeliveryUncertain)
            .expect("delivery-uncertain closure must record");
        let closed = requested
            .try_successor(closed_state)
            .expect("closure must commit separately");
        assert_eq!(
            closed.state.record_query_response(&response, channel),
            Err(ControllerJournalError::QueryAlreadyClosed)
        );
        assert_eq!(
            closed
                .state
                .record_rollout_decision(ControllerObservedTarget::Prepared, None),
            Err(ControllerJournalError::InvalidQueryClosure)
        );
        assert_eq!(
            closed
                .state
                .record_query_closure(ControllerQueryClosureKind::DeliveryUncertain),
            Ok(closed.state.clone()),
            "replaying the exact closure is an idempotent no-op"
        );
        assert_eq!(
            closed
                .state
                .record_query_closure(ControllerQueryClosureKind::ResponseRejected),
            Err(ControllerJournalError::QueryClosureChanged)
        );
        assert_eq!(
            closed.state.prepare_query_request(&request),
            Err(ControllerJournalError::QueryAlreadyClosed),
            "an exact closed identity must never mint fresh resident send authority"
        );

        let next_input = query_input(10, b"query-ten");
        let next_state = prepare_query(&closed.state, next_input);
        let next = closed
            .try_successor(next_state)
            .expect("a later call may prepare a fresh identity after closure");
        let attempts = &next
            .state
            .rollout
            .as_ref()
            .expect("rollout must remain current")
            .reconcile_attempts;
        assert_eq!(attempts.len(), 2);
        assert_eq!(
            attempts[0].prepared.request().canonical_wire(),
            request.canonical_wire()
        );
        assert_eq!(
            attempts[0].closure,
            Some(ControllerQueryClosureKind::DeliveryUncertain)
        );
        assert_eq!(
            attempts[1].prepared.request().query_id(),
            next_input.query_id
        );
        assert!(next.state.current_query_is_open());

        let mut forged = record_query_response(&requested.state, input);
        forged
            .rollout
            .as_mut()
            .expect("rollout must exist")
            .reconcile_attempts
            .last_mut()
            .expect("query attempt must exist")
            .closure = Some(ControllerQueryClosureKind::DeliveryUncertain);
        assert_eq!(
            forged.validate(),
            Err(ControllerJournalError::InvalidQueryClosure)
        );
        let encoded_forgery = encode_unvalidated_state(
            &forged,
            requested
                .snapshot_sequence
                .checked_add(1)
                .expect("fixture sequence has capacity"),
        );
        assert_eq!(
            ControllerJournalSnapshot::decode(&encoded_forgery),
            Err(ControllerJournalError::InvalidQueryClosure)
        );
    }

    #[test]
    fn nonterminal_rollouts_block_plan_commit_and_no_current_intent_can_be_overwritten() {
        fn assert_plan_commit_blocked(state: &ControllerJournalState) {
            let candidate = journal_test_candidate(
                TARGET,
                state.installed_manifest().projection(),
                &state.allocation,
                None,
                0x50,
            )
            .expect("same-manifest empty candidate must validate");
            let operation = ControllerOperationId::from_bytes([0x32; 16]);
            let prepared = state
                .prepare_plan_candidate(operation, &candidate)
                .expect("plan intent may be prepared while rollout is reconciled");
            assert_eq!(
                prepared.commit_plan_candidate(operation, &candidate),
                Err(ControllerJournalError::NonTerminalRolloutBlocksPlanCommit)
            );
        }

        let signed = canonical_signed_snapshot(0x67);
        let query_only = record_query(&signed.state, query_input(9, b"query-nine"));
        let prepared_decision = query_only
            .record_rollout_decision(ControllerObservedTarget::Prepared, None)
            .expect("Prepared is a nonterminal reconcile decision");
        let uncertain_decision = query_only
            .record_rollout_decision(ControllerObservedTarget::Uncertain, None)
            .expect("Uncertain is a nonterminal reconcile decision");
        let terminal_signed = canonical_signed_snapshot(0x67);
        let terminal_query_only = record_query(
            &terminal_signed.state,
            terminal_query_input(9, b"terminal-nine", ControllerObservedTarget::Active),
        );
        let terminal_decision = terminal_query_only
            .record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(fixture_controller_receipt_ref()),
            )
            .expect("Active with a receipt is terminal");

        for state in [
            &signed.state,
            &query_only,
            &prepared_decision,
            &uncertain_decision,
        ] {
            assert_plan_commit_blocked(state);
        }
        assert_eq!(
            query_only.record_rollout_decision(ControllerObservedTarget::Active, None),
            Err(ControllerJournalError::TerminalReceiptRequired)
        );
        assert_eq!(
            query_only.record_rollout_decision(
                ControllerObservedTarget::Prepared,
                Some(ControllerReceiptRef::from_bytes([0x6d; 16])),
            ),
            Err(ControllerJournalError::NonTerminalReceiptForbidden)
        );

        for state in [
            &signed.state,
            &query_only,
            &prepared_decision,
            &uncertain_decision,
            &terminal_decision,
        ] {
            assert_eq!(
                state.record_signed_apply_intent(different_signed_input(state, 0x77, 0x78)),
                Err(ControllerJournalError::CurrentRolloutExists)
            );
            let mut same_operation_different_digest = signed_input(state);
            same_operation_different_digest.request_digest =
                ControllerApplyRequestDigest::from_stored(digest(0x79));
            assert_eq!(
                state.record_signed_apply_intent(same_operation_different_digest),
                Err(ControllerJournalError::ApplyOperationConflict)
            );
        }
    }

    #[test]
    fn prepared_and_uncertain_reconciliation_append_exact_evidence_until_terminal() {
        let signed = canonical_signed_snapshot(0x67);
        let first_input = query_input(9, b"query-nine");
        let query_request = signed
            .try_successor(prepare_query(&signed.state, first_input))
            .expect("query request must be a separate successor");
        let queried = query_request
            .try_successor(record_query_response(&query_request.state, first_input))
            .expect("query response must be a separate successor");
        let prepared_state = queried
            .state
            .record_rollout_decision(ControllerObservedTarget::Prepared, None)
            .expect("Prepared decision must record");
        let prepared = queried
            .try_successor(prepared_state)
            .expect("Prepared decision must be a separate successor");
        let restarted = ControllerJournalSnapshot::decode(
            &prepared.encode().expect("nonterminal snapshot must encode"),
        )
        .expect("nonterminal snapshot must survive restart");
        let first_attempt = restarted
            .state
            .rollout
            .as_ref()
            .expect("rollout must remain current")
            .reconcile_attempts[0]
            .clone();
        let mut same_snapshot_query =
            terminal_query_input(9, b"query-nine-retry", ControllerObservedTarget::Active);
        same_snapshot_query.query_id = ReferenceQueryIdV1::from_bytes([0x6b; 16]);
        let second_request = restarted
            .try_successor(prepare_query(&restarted.state, same_snapshot_query))
            .expect("next request must append separately");
        let second_query = second_request
            .try_successor(record_query_response(
                &second_request.state,
                same_snapshot_query,
            ))
            .expect("next response must append separately");
        assert_eq!(
            second_query
                .state
                .rollout
                .as_ref()
                .expect("rollout")
                .reconcile_attempts[0],
            first_attempt
        );
        let active_state = second_query
            .state
            .record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(fixture_controller_receipt_ref()),
            )
            .expect("Active terminal decision must record");
        let active = second_query
            .try_successor(active_state)
            .expect("terminal decision must be a separate successor");
        assert_eq!(
            active
                .state
                .rollout
                .as_ref()
                .expect("rollout")
                .reconcile_attempts
                .len(),
            2
        );

        let uncertain_signed = canonical_empty_signed_snapshot(0x77);
        let uncertain_query =
            record_query(&uncertain_signed.state, query_input(20, b"query-twenty"));
        let uncertain_decision = uncertain_query
            .record_rollout_decision(ControllerObservedTarget::Uncertain, None)
            .expect("Uncertain decision must record");
        let later_query = record_query(
            &uncertain_decision,
            terminal_query_input(21, b"query-twenty-one", ControllerObservedTarget::Retired),
        );
        let retired = later_query
            .record_rollout_decision(
                ControllerObservedTarget::Retired,
                Some(fixture_controller_receipt_ref()),
            )
            .expect("Retired with receipt must be terminal");
        assert!(retired.rollout.as_ref().is_some_and(|rollout| {
            rollout.is_terminal() && rollout.reconcile_attempts.len() == 2
        }));
        let restarted_retired = ControllerJournalSnapshot::decode(
            &ControllerJournalSnapshot::try_from_stored(
                uncertain_signed.store_instance_id,
                uncertain_signed.owner_identity_fingerprint,
                9,
                retired,
            )
            .expect("individually valid later snapshot")
            .encode()
            .expect("retired snapshot must encode"),
        )
        .expect("retired evidence must survive restart");
        assert_eq!(
            restarted_retired
                .state
                .rollout
                .expect("retired rollout")
                .reconcile_attempts
                .len(),
            2
        );
    }

    #[test]
    fn checksum_valid_terminal_decision_context_tampers_are_rejected() {
        let signed = canonical_signed_snapshot(0x67);
        let state = signed.state();
        let intent = state
            .current_signed_apply_intent()
            .expect("terminal tamper fixture intent");
        let binding = state
            .target_binding()
            .expect("terminal tamper fixture binding");
        let revision = SourcePlanRevision::new(
            state
                .committed_plan()
                .expect("terminal tamper fixture plan")
                .revision()
                .value(),
        );
        let later_revision = SourcePlanRevision::new(
            revision
                .value()
                .checked_add(1)
                .expect("terminal tamper fixture revision capacity"),
        );
        let exact = QueryDesiredOverride {
            source_revision: revision,
            target_slice_digest: intent.target_slice_digest(),
            manifest_digest: binding.manifest_digest().value(),
            high_water: revision,
        };

        let mut wrong_revision = terminal_query_input(
            9,
            b"wrong-source-revision",
            ControllerObservedTarget::Active,
        );
        wrong_revision.desired_override = Some(QueryDesiredOverride {
            source_revision: later_revision,
            high_water: later_revision,
            ..exact
        });
        let mut wrong_slice =
            terminal_query_input(9, b"wrong-target-slice", ControllerObservedTarget::Active);
        wrong_slice.desired_override = Some(QueryDesiredOverride {
            target_slice_digest: TargetSliceDigest::new(digest(0xb1)),
            ..exact
        });
        let mut wrong_manifest =
            terminal_query_input(9, b"wrong-manifest", ControllerObservedTarget::Active);
        wrong_manifest.desired_override = Some(QueryDesiredOverride {
            manifest_digest: digest(0xb2),
            ..exact
        });
        let mut wrong_high_water =
            terminal_query_input(9, b"wrong-high-water", ControllerObservedTarget::Active);
        wrong_high_water.desired_override = Some(QueryDesiredOverride {
            high_water: later_revision,
            ..exact
        });
        let mut wrong_principal =
            terminal_query_input(9, b"wrong-principal", ControllerObservedTarget::Active);
        wrong_principal.principal = PrincipalRef::from_bytes([0xd0; 16]);

        for (name, input) in [
            ("source revision", wrong_revision),
            ("target slice", wrong_slice),
            ("manifest", wrong_manifest),
            ("high water", wrong_high_water),
            ("principal", wrong_principal),
        ] {
            let mut forged = append_unvalidated_query_attempt(state, input, true, None, None);
            forge_latest_decision(
                &mut forged,
                ControllerObservedTarget::Active,
                Some(fixture_controller_receipt_ref()),
            );
            let expected = if name == "principal" {
                ControllerJournalError::InvalidQueryRequest
            } else {
                ControllerJournalError::InvalidRolloutEvidence
            };
            assert_eq!(
                ControllerJournalSnapshot::decode(&encode_unvalidated_state(&forged, 20)),
                Err(expected),
                "checksum-valid {name} forgery must fail reopen",
            );
        }
    }

    #[test]
    fn checksum_valid_selector_and_lookup_tampers_fail_current_and_archived_reopen() {
        let signed = canonical_signed_snapshot(0x67);
        let mut missing_selector_digest = terminal_query_input(
            9,
            b"missing-selector-digest",
            ControllerObservedTarget::Active,
        );
        missing_selector_digest.bind_expected_request_digest = false;
        let mut wrong_known_digest = terminal_query_input(
            9,
            b"wrong-known-request-digest",
            ControllerObservedTarget::Active,
        );
        wrong_known_digest.bind_expected_request_digest = false;
        wrong_known_digest.lookup_request_digest_override = Some(digest(0xb3));

        for (name, input) in [
            ("missing selector digest", missing_selector_digest),
            ("wrong Known digest", wrong_known_digest),
        ] {
            let mut forged =
                append_unvalidated_query_attempt(signed.state(), input, true, None, None);
            forge_latest_decision(
                &mut forged,
                ControllerObservedTarget::Active,
                Some(fixture_controller_receipt_ref()),
            );
            assert_eq!(
                ControllerJournalSnapshot::decode(&encode_unvalidated_state(&forged, 20)),
                Err(ControllerJournalError::InvalidQueryRequest),
                "checksum-valid current {name} forgery must fail reopen",
            );

            let archived = archive_forged_first_rollout(&forged);
            assert_eq!(
                ControllerJournalSnapshot::decode(&encode_unvalidated_state(&archived, 21)),
                Err(ControllerJournalError::InvalidQueryRequest),
                "checksum-valid archived {name} forgery must fail reopen",
            );
        }
    }

    #[test]
    fn checksum_valid_nonterminal_and_closure_query_binding_tampers_fail_every_reopen() {
        let (direct, _, _) = direct_active_snapshot();
        let scenarios = [
            (
                "open",
                query_input(9, b"bad-binding-open"),
                false,
                None,
                None,
            ),
            (
                "closure",
                query_input(9, b"bad-binding-closure"),
                false,
                Some(ControllerQueryClosureKind::DeliveryUncertain),
                None,
            ),
            (
                "Prepared",
                prepared_query_input(9, b"bad-binding-prepared"),
                true,
                None,
                Some(ControllerObservedTarget::Prepared),
            ),
            (
                "Uncertain",
                query_input(9, b"bad-binding-uncertain"),
                true,
                None,
                Some(ControllerObservedTarget::Uncertain),
            ),
        ];

        for (scenario, base_input, response_committed, closure, observed) in scenarios {
            for tamper in ["selector digest", "principal"] {
                let mut input = base_input;
                match tamper {
                    "selector digest" => input.bind_expected_request_digest = false,
                    "principal" => input.principal = PrincipalRef::from_bytes([0xd1; 16]),
                    _ => unreachable!("closed tamper fixture set"),
                }
                let forged = append_unvalidated_query_attempt(
                    direct.state(),
                    input,
                    response_committed,
                    closure,
                    observed,
                );
                let expected = if scenario == "Prepared" && tamper == "selector digest" {
                    ControllerJournalError::ConflictingTerminalEvidence
                } else {
                    ControllerJournalError::InvalidQueryRequest
                };
                assert_eq!(
                    ControllerJournalSnapshot::decode(&encode_unvalidated_state(&forged, 20)),
                    Err(expected),
                    "checksum-valid current {scenario} {tamper} forgery must fail reopen",
                );

                let archived = archive_forged_first_rollout(&forged);
                assert_eq!(
                    ControllerJournalSnapshot::decode(&encode_unvalidated_state(&archived, 21)),
                    Err(expected),
                    "checksum-valid archived {scenario} {tamper} forgery must fail reopen",
                );
            }
        }
    }

    #[test]
    fn checksum_valid_observed_kind_and_receipt_ref_tampers_are_rejected() {
        let mut receipt_forged = decided_snapshot().state;
        forge_latest_decision(
            &mut receipt_forged,
            ControllerObservedTarget::Active,
            Some(ControllerReceiptRef::from_bytes([0xb4; 16])),
        );
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&receipt_forged, 20)),
            Err(ControllerJournalError::InvalidRolloutEvidence)
        );

        let mut active_as_retired = decided_snapshot().state;
        forge_latest_decision(
            &mut active_as_retired,
            ControllerObservedTarget::Retired,
            Some(fixture_controller_receipt_ref()),
        );
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&active_as_retired, 20)),
            Err(ControllerJournalError::InvalidRolloutEvidence)
        );

        let empty = canonical_empty_signed_snapshot(0x77);
        let mut retired_as_active = record_query(
            empty.state(),
            terminal_query_input(20, b"retired-as-active", ControllerObservedTarget::Retired),
        );
        forge_latest_decision(
            &mut retired_as_active,
            ControllerObservedTarget::Active,
            Some(fixture_controller_receipt_ref()),
        );
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&retired_as_active, 20)),
            Err(ControllerJournalError::InvalidRolloutEvidence)
        );
    }

    #[test]
    fn direct_plus_prepared_codec_accepts_only_strictly_older_query_evidence() {
        let (direct, _, _) = direct_active_snapshot();
        let older = record_query(
            direct.state(),
            prepared_query_input(9, b"codec-prepared-before-direct"),
        )
        .record_rollout_decision(ControllerObservedTarget::Prepared, None)
        .expect("strictly older Prepared decision remains historical");
        let older_wire = encode_unvalidated_state(&older, 20);
        assert_eq!(
            ControllerJournalSnapshot::decode(&older_wire)
                .expect("strictly older Prepared decision must reopen")
                .state,
            older
        );

        for sequence in [10_u64, 11] {
            let mut forged = record_query(
                direct.state(),
                prepared_query_input(sequence, b"codec-prepared-not-before-direct"),
            );
            forge_latest_decision(&mut forged, ControllerObservedTarget::Prepared, None);
            assert_eq!(
                ControllerJournalSnapshot::decode(&encode_unvalidated_state(&forged, 20)),
                Err(ControllerJournalError::ConflictingTerminalEvidence),
                "equal or newer Prepared decision must fail reopen",
            );
        }
    }

    #[test]
    fn plan_advance_gate_tracks_direct_query_chronology_and_current_epoch() {
        let (direct, _, target_slice) = direct_active_snapshot();
        assert_eq!(
            direct
                .state()
                .current_active_target_slice_digest_for_plan_advance(),
            Ok(Some(target_slice))
        );
        assert!(commit_empty_after_rollout(direct.state(), 0x40).is_ok());

        let older = record_query(
            direct.state(),
            prepared_query_input(9, b"prepared-before-direct"),
        )
        .record_rollout_decision(ControllerObservedTarget::Prepared, None)
        .expect("same-epoch Prepared before direct completion is historical");
        assert_eq!(
            older.current_active_target_slice_digest_for_plan_advance(),
            Ok(Some(target_slice))
        );
        assert!(commit_empty_after_rollout(&older, 0x41).is_ok());

        for sequence in [10_u64, 11] {
            let queried = record_query(
                direct.state(),
                prepared_query_input(sequence, b"prepared-not-before-direct"),
            );
            assert_eq!(
                queried.record_rollout_decision(ControllerObservedTarget::Prepared, None),
                Err(ControllerJournalError::ConflictingTerminalEvidence)
            );
            assert_eq!(
                commit_empty_after_rollout(
                    &queried,
                    u8::try_from(sequence).expect("sequence marker") + 0x40,
                ),
                Err(ControllerJournalError::NonTerminalRolloutBlocksPlanCommit)
            );
        }

        let uncertain = record_query(direct.state(), query_input(11, b"uncertain-after-direct"))
            .record_rollout_decision(ControllerObservedTarget::Uncertain, None)
            .expect("an uncertain observation remains durable");
        assert_eq!(
            commit_empty_after_rollout(&uncertain, 0x50),
            Err(ControllerJournalError::NonTerminalRolloutBlocksPlanCommit)
        );

        let open = prepare_query(direct.state(), query_input(11, b"closed-after-direct"));
        let closed = open
            .record_query_closure(ControllerQueryClosureKind::DeliveryUncertain)
            .expect("latest closure remains durable");
        assert_eq!(
            commit_empty_after_rollout(&closed, 0x51),
            Err(ControllerJournalError::NonTerminalRolloutBlocksPlanCommit)
        );
        let settled = record_query(
            &closed,
            terminal_query_input(
                12,
                b"settled-after-closure",
                ControllerObservedTarget::Active,
            ),
        )
        .record_rollout_decision(
            ControllerObservedTarget::Active,
            Some(fixture_controller_receipt_ref()),
        )
        .expect("fresh terminal decision settles the historical closure");
        assert!(commit_empty_after_rollout(&settled, 0x52).is_ok());

        let refreshed = direct
            .state()
            .record_target_binding(binding(4, b"bootstrap-four"))
            .expect("binding epoch may advance");
        assert_eq!(
            commit_empty_after_rollout(&refreshed, 0x53),
            Err(ControllerJournalError::NonTerminalRolloutBlocksPlanCommit)
        );
        let current = record_query(
            &refreshed,
            terminal_query_input(11, b"terminal-epoch-four", ControllerObservedTarget::Active),
        )
        .record_rollout_decision(
            ControllerObservedTarget::Active,
            Some(fixture_controller_receipt_ref()),
        )
        .expect("current-epoch terminal query refreshes direct evidence");
        assert!(commit_empty_after_rollout(&current, 0x54).is_ok());
    }

    #[test]
    fn terminal_failure_receipt_cannot_advance_or_bypass_successor_validation() {
        let signed = canonical_signed_snapshot(0x67);
        let failure_receipt = direct_receipt_for_signed_snapshot(
            &signed,
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects,
            ReferenceApplyTerminalLifecycleEffectV1::ProvenNotStarted,
            ReferenceApplyTerminalHeadV1::PreservedNone,
        );
        let failure = signed
            .state()
            .record_direct_terminal_receipt(&failure_receipt)
            .expect("terminal failure remains exact durable evidence");
        assert!(failure.current_apply_is_terminal());
        assert_eq!(
            failure.current_active_target_slice_digest_for_plan_advance(),
            Ok(None)
        );
        assert_eq!(
            commit_empty_after_rollout(&failure, 0x55),
            Err(ControllerJournalError::NonTerminalRolloutBlocksPlanCommit)
        );

        let (success, _, _) = direct_active_snapshot_with_operation(0x67);
        let candidate = journal_test_candidate(
            TARGET,
            failure.installed_manifest().projection(),
            &failure.allocation,
            None,
            0x50,
        )
        .expect("forged successor Empty candidate");
        let operation = ControllerOperationId::from_bytes([0x56; 16]);
        let failure_prepared = failure
            .prepare_plan_candidate(operation, &candidate)
            .expect("failure evidence does not block plan prepare");
        let success_prepared = success
            .state()
            .prepare_plan_candidate(operation, &candidate)
            .expect("successful evidence plan prepare");
        let valid_next = success_prepared
            .commit_plan_candidate(operation, &candidate)
            .expect("successful direct receipt may advance");
        let mut forged_next = valid_next;
        let archived = forged_next
            .apply_history
            .last_mut()
            .expect("forged successor archived rollout");
        *archived = failure
            .rollout
            .clone()
            .expect("failure rollout remains current");
        assert_eq!(
            forged_next.validate_successor_of(&failure_prepared),
            Err(ControllerJournalError::NonTerminalRolloutBlocksPlanCommit)
        );
    }

    #[test]
    fn raw_terminal_ref_conflict_survives_prior_decision_and_blocks_plan_advance() {
        let signed = canonical_signed_snapshot(0x93);
        let prepared = record_query(
            signed.state(),
            prepared_query_input(9, b"prepared-before-conflict"),
        )
        .record_rollout_decision(ControllerObservedTarget::Prepared, None)
        .expect("historical Prepared decision");
        let (_, direct_receipt, _) = direct_active_snapshot();
        let with_direct = prepared
            .record_direct_terminal_receipt(&direct_receipt)
            .expect("matching direct receipt after historical Prepared");
        let conflicting_result = direct_active_snapshot_with_operation(0x99)
            .1
            .facts()
            .terminal_result_ref();
        let mut conflicting_input = terminal_query_input(
            11,
            b"conflicting-terminal-ref",
            ControllerObservedTarget::Active,
        );
        conflicting_input.terminal_result_override = Some(conflicting_result);
        let conflicting = record_query(&with_direct, conflicting_input);
        assert_eq!(
            conflicting.record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(ControllerReceiptRef::from_bytes(
                    *conflicting_result.as_bytes(),
                )),
            ),
            Err(ControllerJournalError::ConflictingTerminalEvidence)
        );
        assert_eq!(
            commit_empty_after_rollout(&conflicting, 0x57),
            Err(ControllerJournalError::ConflictingTerminalEvidence)
        );

        let snapshot = ControllerJournalSnapshot::try_from_stored(
            [0x41; 32],
            ControllerOwnerIdentityFingerprint::from_stored(digest(0x42)),
            20,
            conflicting,
        )
        .expect("raw conflict without a decision remains valid current evidence");
        let encoded = snapshot.encode().expect("raw conflict snapshot encoding");
        assert_eq!(
            ControllerJournalSnapshot::decode(&encoded)
                .expect("raw conflict must survive restart exactly"),
            snapshot
        );
    }

    #[test]
    fn manifest_binding_and_historical_auth_pin_cannot_swap_after_rotation() {
        let bound = bound_snapshot();
        let installed_manifest_b = super::controller_test_manifest_with_build(TARGET, 0x12);
        let manifest_b = journal_test_candidate(
            TARGET,
            installed_manifest_b.projection(),
            &bound.state.allocation,
            None,
            0x51,
        )
        .expect("different-manifest candidate must be typed");
        assert_eq!(
            bound.state.prepare_plan_candidate(
                ControllerOperationId::from_bytes([0x32; 16]),
                &manifest_b,
            ),
            Err(ControllerJournalError::CandidateManifestMismatch)
        );
        let mismatched_binding = binding_with_store_and_build(
            [0x62; 32],
            4,
            0x73,
            0x12,
            PlanManifestDigest::try_new(installed_manifest_b.manifest_digest())
                .expect("manifest B digest must validate"),
        );
        assert_eq!(
            bound.state.record_target_binding(mismatched_binding),
            Err(ControllerJournalError::ManifestBindingMismatch)
        );

        let signed = canonical_signed_snapshot(0x67);
        let original_auth = signed.state.request_auth;
        let rotated_state = signed
            .state
            .rotate_request_auth(auth(0x12, 2))
            .expect("current auth may rotate after the intent is durable");
        let rotated = signed
            .try_successor(rotated_state)
            .expect("auth rotation must preserve current rollout");
        assert_eq!(
            rotated
                .state
                .rollout
                .as_ref()
                .expect("rollout")
                .signed_intent
                .request_auth,
            original_auth
        );
        assert_ne!(rotated.state.request_auth, original_auth);
        let restarted = ControllerJournalSnapshot::decode(
            &rotated.encode().expect("rotated snapshot must encode"),
        )
        .expect("rotated snapshot must decode");
        assert_eq!(
            restarted
                .state
                .rollout
                .as_ref()
                .expect("rollout")
                .signed_intent
                .request_auth,
            original_auth
        );

        let queried = record_query(
            &restarted.state,
            terminal_query_input(30, b"query-thirty", ControllerObservedTarget::Active),
        );
        let terminal = queried
            .record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(fixture_controller_receipt_ref()),
            )
            .expect("Active decision must record");
        let candidate = journal_test_candidate(
            TARGET,
            terminal.installed_manifest().projection(),
            &terminal.allocation,
            None,
            0x50,
        )
        .expect("same-manifest next plan must validate");
        let operation = ControllerOperationId::from_bytes([0x32; 16]);
        let prepared = terminal
            .prepare_plan_candidate(operation, &candidate)
            .expect("next plan must prepare");
        let archived = prepared
            .commit_plan_candidate(operation, &candidate)
            .expect("terminal rollout must archive on plan commit");
        assert_eq!(archived.request_auth, auth(0x12, 2));
        assert_eq!(
            archived.apply_history[0].signed_intent.request_auth,
            original_auth
        );
        assert_eq!(archived.target_binding, bound.state.target_binding);
    }

    #[test]
    fn apply_history_identity_and_capacity_are_fail_closed_before_plan_mutation() {
        let mut state = bound_snapshot().state;
        for index in 0..super::MAX_APPLY_OPERATION_HISTORY {
            let index = u16::try_from(index).expect("history fixture index must fit");
            let operation_marker = u8::try_from(index)
                .expect("history fixture marker must fit")
                .checked_add(0x20)
                .expect("history fixture marker has capacity");
            state = record_canonical_signed_apply(&state, operation_marker).0;
            let observed = match state
                .committed_plan()
                .expect("capacity fixture committed plan")
                .content()
                .shape()
            {
                TargetIntent::OneSourceLoop => ControllerObservedTarget::Active,
                TargetIntent::EmptyTarget => ControllerObservedTarget::Retired,
                TargetIntent::Omitted => panic!("capacity fixture plan must be actionable"),
            };
            state = record_query(
                &state,
                terminal_query_input(u64::from(index) + 1, b"capacity-query", observed),
            );
            state = state
                .record_rollout_decision(observed, Some(fixture_controller_receipt_ref()))
                .expect("capacity terminal decision must record");
            let candidate = journal_test_candidate(
                TARGET,
                state.installed_manifest().projection(),
                &state.allocation,
                None,
                0x50,
            )
            .expect("capacity next plan must validate");
            let mut controller_operation = [0_u8; 16];
            controller_operation[0] = 0x80;
            controller_operation[14..].copy_from_slice(&index.to_be_bytes());
            let controller_operation = ControllerOperationId::from_bytes(controller_operation);
            state = state
                .prepare_plan_candidate(controller_operation, &candidate)
                .expect("capacity plan must prepare");
            state = state
                .commit_plan_candidate(controller_operation, &candidate)
                .expect("history slots through the exact bound must commit");
        }
        assert_eq!(
            state.apply_history.len(),
            super::MAX_APPLY_OPERATION_HISTORY
        );
        assert_eq!(state.operations.len(), 128);
        assert_eq!(state.operations.len() + state.apply_history.len(), 255);
        let archived_intent = state.apply_history[0].signed_intent.clone();
        assert_eq!(
            state
                .record_signed_apply_intent(replay_input(&archived_intent))
                .expect("exact archived replay must be idempotent"),
            state
        );
        let mut same_operation_different_request = replay_input(&archived_intent);
        same_operation_different_request.request_digest =
            ControllerApplyRequestDigest::from_stored(digest(0xa1));
        assert_eq!(
            state.record_signed_apply_intent(same_operation_different_request),
            Err(ControllerJournalError::ApplyOperationConflict)
        );
        let mut same_request_different_operation = replay_input(&archived_intent);
        same_request_different_operation.apply_operation = ApplyOperationId::from_bytes([0xa2; 16]);
        assert_eq!(
            state.record_signed_apply_intent(same_request_different_operation),
            Err(ControllerJournalError::ApplyOperationConflict)
        );

        state = record_canonical_signed_apply(&state, 0xa3).0;
        state = record_query(
            &state,
            terminal_query_input(
                200,
                b"capacity-final-query",
                ControllerObservedTarget::Retired,
            ),
        );
        state = state
            .record_rollout_decision(
                ControllerObservedTarget::Retired,
                Some(fixture_controller_receipt_ref()),
            )
            .expect("final terminal decision must record");
        assert_eq!(
            state.operations.len()
                + state.apply_history.len()
                + usize::from(state.rollout.is_some()),
            super::MAX_CONTROLLER_LEDGER_RECORDS
        );
        let candidate = journal_test_candidate(
            TARGET,
            state.installed_manifest().projection(),
            &state.allocation,
            None,
            0x50,
        )
        .expect("capacity overflow plan must validate");
        let operation = ControllerOperationId::from_bytes([0xa6; 16]);
        let before = state.clone();
        assert_eq!(
            state.prepare_plan_candidate(operation, &candidate),
            Err(ControllerJournalError::ControllerLedgerCapacityExceeded)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn shared_ledger_allows_255_plan_records_plus_current_and_rejects_the_next_record() {
        let mut state = bound_snapshot().state;
        for index in 0..254_u16 {
            let candidate = journal_test_candidate(
                TARGET,
                state.installed_manifest().projection(),
                &state.allocation,
                None,
                0x50,
            )
            .expect("same-manifest no-change plan must validate");
            let mut operation = [0_u8; 16];
            operation[0] = 0x81;
            operation[14..].copy_from_slice(&index.to_be_bytes());
            let operation = ControllerOperationId::from_bytes(operation);
            state = state
                .prepare_plan_candidate(operation, &candidate)
                .expect("plan record through 255 must prepare");
            state = state
                .commit_plan_candidate(operation, &candidate)
                .expect("plan record through 255 must commit");
        }
        assert_eq!(state.operations.len(), 255);
        assert!(state.apply_history.is_empty());
        state = state
            .record_signed_apply_intent(different_signed_input(&state, 0xb1, 0xb2))
            .expect("the 256th shared ledger record is available to current rollout");
        let candidate = journal_test_candidate(
            TARGET,
            state.installed_manifest().projection(),
            &state.allocation,
            None,
            0x50,
        )
        .expect("next candidate must remain pure");
        let before = state.clone();
        assert_eq!(
            state.prepare_plan_candidate(ControllerOperationId::from_bytes([0xb3; 16]), &candidate),
            Err(ControllerJournalError::ControllerLedgerCapacityExceeded)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn exact_query_history_capacity_is_bounded_without_evicting_evidence() {
        let mut state = canonical_signed_snapshot(0x67).state;
        for sequence in
            1..=u64::try_from(super::MAX_RECONCILE_ATTEMPTS).expect("query capacity fits u64")
        {
            state = record_query(&state, query_input(sequence, b"capacity-query"));
            state = state
                .record_rollout_decision(ControllerObservedTarget::Prepared, None)
                .expect("nonterminal decision permits the next query");
        }
        let before = state.clone();
        let (request, _, _) = query_contract_values(
            &state,
            query_input(
                u64::try_from(super::MAX_RECONCILE_ATTEMPTS).expect("capacity fits") + 1,
                b"capacity-overflow",
            ),
        );
        assert_eq!(
            state.prepare_query_request(&request),
            Err(ControllerJournalError::ReconcileCapacityExceeded)
        );
        assert_eq!(state, before);
        let persistable = ControllerJournalSnapshot::try_from_stored(
            [0x41; 32],
            ControllerOwnerIdentityFingerprint::from_stored(digest(0x42)),
            600,
            state,
        )
        .expect("the previous state remains valid");
        assert!(
            persistable.encode().is_ok(),
            "the previous state remains persistable"
        );
    }

    #[test]
    fn query_evidence_is_channel_bound_and_query_ids_are_scope_unique() {
        let signed = canonical_signed_snapshot(0x67);
        let mut wrong_peer = query_input(9, b"wrong-peer");
        wrong_peer.channel = Some(
            ReferenceChannelBindingV1::try_new(
                TARGET,
                PrincipalRef::from_bytes([0x99; 16]),
                digest(0x98),
                digest(0x97),
            )
            .expect("wrong query channel fixture"),
        );
        let (request, response, wrong_channel) = query_contract_values(&signed.state, wrong_peer);
        let prepared = signed
            .state
            .prepare_query_request(&request)
            .expect("request itself uses the durable channel baseline");
        assert_eq!(
            prepared.record_query_response(&response, wrong_channel),
            Err(ControllerJournalError::InvalidQueryResponse)
        );

        let mut forged_current_peer = decided_snapshot().state;
        forged_current_peer
            .rollout
            .as_mut()
            .expect("current rollout")
            .reconcile_attempts[0]
            .observation
            .as_mut()
            .expect("current response")
            .channel_peer = wrong_channel;
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&forged_current_peer, 7)),
            Err(ControllerJournalError::InvalidQueryResponse)
        );

        let archived = state_with_two_archived_rollouts();
        let mut forged_history_peer = archived.clone();
        forged_history_peer.apply_history[0].reconcile_attempts[0]
            .observation
            .as_mut()
            .expect("archived response")
            .channel_peer = wrong_channel;
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&forged_history_peer, 12)),
            Err(ControllerJournalError::InvalidQueryResponse)
        );

        let (current, _) = record_canonical_signed_apply(&archived, 0x7a);
        let mut reused_archived_query = query_input(11, b"reused-archived-query");
        reused_archived_query.query_id = query_input(9, b"query-nine").query_id;
        let (reused_request, _, _) = query_contract_values(&current, reused_archived_query);
        assert_eq!(
            current.prepare_query_request(&reused_request),
            Err(ControllerJournalError::QueryIdentityConflict)
        );

        let current = record_query(&current, query_input(11, b"query-eleven"))
            .record_rollout_decision(ControllerObservedTarget::Prepared, None)
            .expect("current query decision must record");
        assert_eq!(current.apply_history.len(), 2);
    }

    #[test]
    fn query_snapshot_high_water_is_exact_and_survives_rollout_boundaries() {
        let archived = state_with_two_archived_rollouts();
        assert_eq!(archived.query_snapshot_high_water, 10);
        let (current, _) = record_canonical_signed_apply(&archived, 0x7c);
        let mut regressed = query_input(9, b"cross-rollout-regression");
        regressed.query_id = ReferenceQueryIdV1::from_bytes([0x7e; 16]);
        let (request, response, channel) = query_contract_values(&current, regressed);
        let prepared = current
            .prepare_query_request(&request)
            .expect("regression is not visible until the signed response arrives");
        assert_eq!(
            prepared.record_query_response(&response, channel),
            Err(ControllerJournalError::QuerySequenceRegression)
        );
        let mut equal_high_water = query_input(10, b"equal-high-water");
        equal_high_water.query_id = ReferenceQueryIdV1::from_bytes([0x7f; 16]);
        let equal = record_query(&current, equal_high_water);
        assert_eq!(equal.query_snapshot_high_water, 10);

        let mut forged_jump = archived.clone();
        forged_jump.query_snapshot_high_water = 11;
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&forged_jump, 12)),
            Err(ControllerJournalError::QueryHighWaterMismatch)
        );
        let mut forged_regression = archived;
        forged_regression.query_snapshot_high_water = 9;
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&forged_regression, 12)),
            Err(ControllerJournalError::QueryHighWaterMismatch)
        );
    }

    #[test]
    fn archived_rollouts_are_bound_to_committed_plan_chronology() {
        let archived = state_with_two_archived_rollouts();
        let snapshot = ControllerJournalSnapshot::try_from_stored(
            [0x41; 32],
            ControllerOwnerIdentityFingerprint::from_stored(digest(0x42)),
            12,
            archived.clone(),
        )
        .expect("two-history state must validate");
        let encoded = snapshot.encode().expect("two-history state must encode");
        assert_eq!(
            ControllerJournalSnapshot::decode(&encoded)
                .expect("two-history state must decode")
                .encode()
                .expect("two-history state must reencode"),
            encoded
        );

        let mut swapped_archive_digests = archived.clone();
        let first = swapped_archive_digests.apply_history[0]
            .signed_intent
            .source_plan_digest;
        let second = swapped_archive_digests.apply_history[1]
            .signed_intent
            .source_plan_digest;
        swapped_archive_digests.apply_history[0]
            .signed_intent
            .source_plan_digest = second;
        swapped_archive_digests.apply_history[1]
            .signed_intent
            .source_plan_digest = first;
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(
                &swapped_archive_digests,
                12,
            )),
            Err(ControllerJournalError::InvalidRolloutEvidence)
        );

        let mut swapped_commit_digests = archived.clone();
        let first = swapped_commit_digests.operations[0].committed_plan_digest;
        let second = swapped_commit_digests.operations[1].committed_plan_digest;
        swapped_commit_digests.operations[0].committed_plan_digest = second;
        swapped_commit_digests.operations[1].committed_plan_digest = first;
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(
                &swapped_commit_digests,
                12,
            )),
            Err(ControllerJournalError::InvalidRolloutEvidence)
        );

        let mut unknown_archive_digest = archived;
        unknown_archive_digest.apply_history[0]
            .signed_intent
            .source_plan_digest = SourcePlanDigest::new(digest(0xfe));
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(
                &unknown_archive_digest,
                12,
            )),
            Err(ControllerJournalError::ArchivedPlanDigestMismatch)
        );
    }

    #[test]
    fn checksum_valid_but_unreachable_state_forgery_is_rejected() {
        let initial = initial_snapshot();
        let candidate = journal_test_candidate(
            TARGET,
            initial.state.installed_manifest().projection(),
            &initial.state.allocation,
            Some([2; 16]),
            0x50,
        )
        .expect("fixture candidate must validate");
        let prepared_state = initial
            .state
            .prepare_plan_candidate(PLAN_OPERATION, &candidate)
            .expect("candidate must prepare");
        let prepared = initial
            .try_successor(prepared_state)
            .expect("prepared snapshot must validate");
        let mut sequence_one_nonfresh = prepared
            .encode()
            .expect("prepared snapshot must encode")
            .to_vec();
        let sequence_offset = super::JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES - 16;
        sequence_one_nonfresh[sequence_offset..sequence_offset + 8]
            .copy_from_slice(&1_u64.to_be_bytes());
        refresh_checksum(&mut sequence_one_nonfresh);
        assert_eq!(
            ControllerJournalSnapshot::decode(&sequence_one_nonfresh),
            Err(ControllerJournalError::NonFreshInitialState)
        );

        let mut later_sequence_fresh = initial
            .encode()
            .expect("initial snapshot must encode")
            .to_vec();
        later_sequence_fresh[sequence_offset..sequence_offset + 8]
            .copy_from_slice(&2_u64.to_be_bytes());
        refresh_checksum(&mut later_sequence_fresh);
        assert_eq!(
            ControllerJournalSnapshot::decode(&later_sequence_fresh),
            Err(ControllerJournalError::FreshStateAfterInitialization)
        );

        let mut wrong_operation_revision = prepared.state.clone();
        wrong_operation_revision.operations[0].expected_revision = 1;
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(
                &wrong_operation_revision,
                2,
            )),
            Err(ControllerJournalError::OperationRevisionMismatch)
        );

        let committed = committed_snapshot();
        let mut wrong_generation_history = committed.state.clone();
        wrong_generation_history.operations[0].committed_allocation_generation = Some(0);
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(
                &wrong_generation_history,
                3,
            )),
            Err(ControllerJournalError::AllocationGenerationHistoryMismatch)
        );
        let mut missing_commit_history = committed.state.clone();
        missing_commit_history.operations = Box::new([]);
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(
                &missing_commit_history,
                3,
            )),
            Err(ControllerJournalError::CommittedOperationHistoryMismatch)
        );

        let active_allocation = initial
            .state
            .allocation
            .apply_delta(candidate.allocation_delta())
            .expect("active allocation must apply");
        let empty_candidate = journal_test_candidate(
            TARGET,
            initial.state.installed_manifest().projection(),
            &active_allocation,
            None,
            0x50,
        )
        .expect("empty candidate must validate");
        let tombstones = active_allocation
            .apply_delta(empty_candidate.allocation_delta())
            .expect("tombstone allocation must apply");
        let mut no_plan_with_tombstones = initial.state.clone();
        no_plan_with_tombstones.allocation = tombstones;
        assert!(matches!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(
                &no_plan_with_tombstones,
                2,
            )),
            Err(ControllerJournalError::AllocationGenerationHistoryMismatch
                | ControllerJournalError::AllocationWithoutCommittedPlan)
        ));

        let bound = bound_snapshot();
        let mut manifest_swap = bound.state.clone();
        manifest_swap
            .target_binding
            .as_mut()
            .expect("binding")
            .manifest_digest =
            PlanManifestDigest::try_new(digest(0x53)).expect("manifest B digest must validate");
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&manifest_swap, 4)),
            Err(ControllerJournalError::InvalidTargetBinding)
        );
        let signed = signed_snapshot();
        let mut signed_manifest_swap = signed.state.clone();
        signed_manifest_swap
            .rollout
            .as_mut()
            .expect("rollout")
            .signed_intent
            .binding_manifest_digest =
            PlanManifestDigest::try_new(digest(0x53)).expect("manifest B digest must validate");
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&signed_manifest_swap, 5,)),
            Err(ControllerJournalError::RolloutBindingMismatch)
        );
    }

    #[test]
    fn archived_direct_terminal_receipt_is_exact_and_plan_chronological() {
        let (terminal, receipt, loop_slice) = direct_active_snapshot();
        assert_eq!(
            terminal.state().current_direct_terminal_receipt(),
            Some(&receipt)
        );
        assert_eq!(
            terminal.state().last_archived_direct_terminal_receipt(),
            Ok(None),
            "a current direct PXRT is not archived until a successor plan commits"
        );

        let empty_candidate = journal_test_candidate(
            TARGET,
            terminal.state().installed_manifest().projection(),
            terminal.state().allocation(),
            None,
            0x50,
        )
        .expect("empty candidate must validate");
        let empty_operation = ControllerOperationId::from_bytes([0x32; 16]);
        let prepared_state = terminal
            .state()
            .prepare_plan_candidate(empty_operation, &empty_candidate)
            .expect("empty candidate must prepare");
        let prepared = terminal
            .try_successor(prepared_state)
            .expect("empty prepare must preserve direct receipt");
        let committed_state = prepared
            .state()
            .commit_plan_candidate(empty_operation, &empty_candidate)
            .expect("empty candidate must commit");
        let empty = prepared
            .try_successor(committed_state)
            .expect("empty commit must archive direct receipt");

        let archived = empty
            .state()
            .last_archived_direct_terminal_receipt()
            .expect("archive chronology must validate")
            .expect("direct receipt must be available");
        assert_eq!(archived, &receipt);
        assert_eq!(archived.canonical_wire(), receipt.canonical_wire());
        assert_eq!(archived.facts().desired_head_digest(), Some(loop_slice));
        assert_eq!(
            empty.state().last_terminal_target_slice_digest(),
            Ok(Some(loop_slice))
        );
        assert_eq!(
            empty
                .state()
                .committed_plan()
                .expect("empty committed plan")
                .commit_operation(),
            empty_operation
        );
    }

    #[test]
    fn next_plan_archives_terminal_rollout_and_retains_allocation_history() {
        let decided = decided_snapshot();
        assert_eq!(
            decided.state.last_archived_direct_terminal_receipt(),
            Ok(None),
            "the current terminal rollout is not archived plan history"
        );
        let empty_candidate = journal_test_candidate(
            TARGET,
            decided.state.installed_manifest().projection(),
            &decided.state.allocation,
            None,
            0x50,
        )
        .expect("empty candidate must validate");
        let empty_operation = ControllerOperationId::from_bytes([0x32; 16]);
        let prepared_state = decided
            .state
            .prepare_plan_candidate(empty_operation, &empty_candidate)
            .expect("empty candidate must prepare");
        let prepared = decided
            .try_successor(prepared_state)
            .expect("empty prepare must preserve rollout");
        let committed_state = prepared
            .state
            .commit_plan_candidate(empty_operation, &empty_candidate)
            .expect("empty candidate must commit");
        let empty = prepared
            .try_successor(committed_state)
            .expect("empty commit must atomically archive terminal rollout");
        assert_eq!(empty.state.current_revision(), 2);
        assert!(empty.state.rollout.is_none());
        assert_eq!(empty.state.apply_history.len(), 1);
        assert_eq!(
            empty
                .state
                .committed_plan()
                .expect("empty committed plan")
                .commit_operation(),
            empty_operation
        );
        assert_eq!(
            empty.state.apply_history[0],
            *decided.state.rollout.as_ref().expect("terminal rollout")
        );
        assert_eq!(
            empty.state.last_archived_direct_terminal_receipt(),
            Err(ControllerJournalError::TerminalDesiredHeadUnavailable),
            "opaque reconcile evidence must not be exposed as a direct PXRT"
        );
        let mut wrong_archive_chronology = empty.state.clone();
        wrong_archive_chronology.apply_history[0]
            .signed_intent
            .source_plan_digest = SourcePlanDigest::new(digest(0xf1));
        assert_eq!(
            wrong_archive_chronology.last_archived_direct_terminal_receipt(),
            Err(ControllerJournalError::ArchivedPlanDigestMismatch),
            "the read facade must independently reject an archive outside plan chronology"
        );
        assert_eq!(empty.state.target_binding, decided.state.target_binding);
        assert_eq!(empty.state.operations.len(), 2);
        assert_eq!(empty.state.allocation.records().len(), 1);
        assert_eq!(
            empty.state.allocation.records()[0].state(),
            AllocationState::Tombstone
        );

        let next_candidate = journal_test_candidate(
            TARGET,
            empty.state.installed_manifest().projection(),
            &empty.state.allocation,
            Some([3; 16]),
            0x50,
        )
        .expect("new-key candidate must validate");
        let next_operation = ControllerOperationId::from_bytes([0x33; 16]);
        let prepared_next = empty
            .state
            .prepare_plan_candidate(next_operation, &next_candidate)
            .expect("new-key candidate must prepare");
        let prepared_next_snapshot = empty
            .try_successor(prepared_next)
            .expect("new-key prepare must succeed");
        let committed_next = prepared_next_snapshot
            .state
            .commit_plan_candidate(next_operation, &next_candidate)
            .expect("new-key candidate must commit");
        let next = prepared_next_snapshot
            .try_successor(committed_next)
            .expect("new-key commit must succeed");
        assert_eq!(next.state.allocation.records().len(), 2);
        assert_eq!(next.state.allocation.high_water(), 2);
        assert_eq!(next.state.allocation.records()[0].key(), &[2; 16]);
        assert_eq!(
            next.state.allocation.records()[0].state(),
            AllocationState::Tombstone
        );
        assert_eq!(next.state.allocation.records()[1].key(), &[3; 16]);
        assert_eq!(
            next.state.allocation.records()[1].state(),
            AllocationState::Active
        );
    }

    #[test]
    fn operation_capacity_is_exact_and_never_evicts_history() {
        let mut state = initial_state();
        let candidate = journal_test_candidate(
            TARGET,
            state.installed_manifest().projection(),
            &state.allocation,
            None,
            0x30,
        )
        .expect("no-change candidate must validate");
        for index in 0..super::MAX_CONTROLLER_OPERATIONS {
            let mut operation = [0_u8; 16];
            operation[0] = 1;
            operation[14..].copy_from_slice(
                &u16::try_from(index)
                    .expect("operation fixture index must fit")
                    .to_be_bytes(),
            );
            state = state
                .prepare_plan_candidate(ControllerOperationId::from_bytes(operation), &candidate)
                .expect("exact operation capacity must remain available");
        }
        assert_eq!(state.operations.len(), super::MAX_CONTROLLER_OPERATIONS);
        let before = state.clone();
        assert_eq!(
            state
                .prepare_plan_candidate(ControllerOperationId::from_bytes([0xff; 16]), &candidate,),
            Err(ControllerJournalError::OperationCapacityExceeded)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn payload_magic_is_unique_and_noncanonical_allocation_order_is_rejected() {
        let committed = committed_snapshot();
        let encoded = committed.encode().expect("snapshot must encode");
        assert_eq!(
            &encoded[super::JOURNAL_HEADER_BYTES..super::JOURNAL_HEADER_BYTES + 4],
            CONTROLLER_PAYLOAD_MAGIC
        );

        let decoded = ControllerJournalSnapshot::decode(&encoded).expect("snapshot must decode");
        let record = decoded.state.allocation.records()[0];
        let forged = StableAllocationSnapshot::try_new(
            TARGET,
            decoded.state.allocation.generation(),
            decoded.state.allocation.high_water(),
            vec![record, record],
        );
        assert!(
            forged.is_err(),
            "Planner authority rejects duplicate allocation rows"
        );
    }

    #[test]
    fn explicit_v7_migration_is_zero_query_only_and_normal_decode_never_falls_back() {
        let source_wire = frozen_v7_zero_wire();
        assert_eq!(source_wire.len(), 3_088);
        assert_eq!(
            &source_wire[super::JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES..super::JOURNAL_HEADER_BYTES],
            &[
                0x06, 0x05, 0x8a, 0xbc, 0x8d, 0x49, 0xde, 0xa2, 0x07, 0x4e, 0xc3, 0xa1, 0x30, 0x2a,
                0xb5, 0x11, 0xb2, 0x1e, 0xfb, 0x9f, 0xdc, 0x29, 0x7c, 0xa2, 0xc0, 0xa0, 0x57, 0x96,
                0xe1, 0x0f, 0x85, 0xd5,
            ]
        );
        assert_eq!(
            ControllerJournalSnapshot::decode(&source_wire),
            Err(ControllerJournalError::UnknownPayloadVersion),
            "normal open must remain v8-only"
        );
        let migrated = ControllerJournalSnapshot::migrate_payload_v7_with_metadata(&source_wire)
            .expect("zero-query v7 fixture must migrate");
        assert_eq!(migrated.source_payload_version(), 7);
        assert_eq!(migrated.source_store_instance_id(), &[0x41; 32]);
        assert_eq!(
            migrated.source_owner_identity_fingerprint().value(),
            Digest32::from_bytes([0x42; 32])
        );
        assert_eq!(migrated.source_snapshot_sequence(), 5);
        let target_wire = migrated.snapshot().encode().expect("v8 target must encode");
        assert_eq!(target_wire, frozen_v8_zero_target_wire());
        assert_eq!(
            ControllerJournalSnapshot::migrate_payload_v7(&target_wire),
            Err(ControllerJournalError::UnknownPayloadVersion),
            "the v7-only migration parser must never accept its v8 target"
        );
        assert_eq!(
            ControllerJournalSnapshot::decode(&target_wire).expect("v8 target must decode"),
            migrated.snapshot().clone()
        );

        let queried_v7 = frozen_v7_opaque_query_wire();
        assert_eq!(queried_v7.len(), 3_233);
        assert_eq!(
            ControllerJournalSnapshot::migrate_payload_v7(&queried_v7),
            Err(ControllerJournalError::LegacyOpaqueQueryEvidenceUnavailable),
            "v7 query evidence cannot be guessed into an exact PXQR/PXQS chain"
        );
    }
}
