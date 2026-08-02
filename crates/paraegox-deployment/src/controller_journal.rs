//! Internal S7-D DeploymentController journal codec and pure state validator.
//!
//! This module owns no filesystem, signing key, endpoint, retry loop, or live
//! Controller process. It persists only Planner-owned allocation/plan values
//! and forces every durable mutation through an explicit predecessor check.
//! Runtime query evidence stays opaque and journal-local until its owning
//! contract has a real Controller client in S7-F.

use core::fmt;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_runtime_contracts::apply::ApplyOperationId;
use paraegox_runtime_contracts::provenance::{SourcePlanDigest, TargetSliceDigest};
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

use crate::plan::{DeploymentId, DeploymentRevision, DeploymentScopeId};
use crate::planner::{
    AllocationState, DeploymentPlanCandidate, PlanContent, PlanContentDigest, PlanManifestDigest,
    StableAllocationDelta, StableAllocationRecord, StableAllocationSnapshot, TargetIntent,
};

const JOURNAL_MAGIC: &[u8; 4] = b"PXJR";
const JOURNAL_ENVELOPE_VERSION: u16 = 1;
const CONTROLLER_OWNER_KIND: u16 = 1;
const CONTROLLER_PAYLOAD_VERSION: u16 = 3;
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
// Every archived rollout requires a later retained committed plan operation.
// With one current rollout, the largest reachable split is therefore
// 128 committed plan operations + 127 archives + 1 current = 256.
const MAX_APPLY_OPERATION_HISTORY: usize = (MAX_CONTROLLER_LEDGER_RECORDS - 1) / 2;
const MAX_RECONCILE_ATTEMPTS: usize = 256;
const MAX_PLAN_CONTENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_BOOTSTRAP_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_SIGNED_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_QUERY_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

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
// Opaque Controller-local identity of Runtime query evidence. This is
// deliberately not a Runtime query wire DTO or compatibility promise. S7-F
// must connect the unique runtime-contract query type at the real client seam.
opaque_id!(ControllerOpaqueRuntimeQueryId);
opaque_id!(ControllerReceiptRef);
opaque_digest!(ControllerPlanCommitIntentDigest);
opaque_digest!(ControllerPlanContentStorageChecksum);
opaque_digest!(ControllerApplyRequestDigest);
opaque_digest!(ControllerAuthKeyFingerprint);
opaque_digest!(ControllerChannelAuthFingerprint);
opaque_digest!(ControllerBootstrapResponseDigest);
opaque_digest!(ControllerQueryResponseDigest);
opaque_digest!(ControllerOwnerIdentityFingerprint);

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
        Ok(Self {
            target: input.target,
            runtime_store_instance_id: input.runtime_store_instance_id,
            channel_auth_fingerprint: input.channel_auth_fingerprint,
            manifest_digest: input.manifest_digest,
            first_runtime_host_epoch: input.first_runtime_host_epoch,
            last_runtime_host_epoch: input.last_runtime_host_epoch,
            bootstrap_response: input.bootstrap_response.into(),
            bootstrap_response_digest: input.bootstrap_response_digest,
        })
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
                || self.bootstrap_response_digest != previous.bootstrap_response_digest)
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
        })
    }
}

/// Exact opaque Runtime query evidence, not a duplicated wire contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerOpaqueQueryObservation {
    query_id: ControllerOpaqueRuntimeQueryId,
    query_snapshot_sequence: u64,
    query_response: Box<[u8]>,
    query_response_digest: ControllerQueryResponseDigest,
    channel_peer_fingerprint: ControllerChannelAuthFingerprint,
}

pub(crate) struct ControllerOpaqueQueryObservationInput<'a> {
    pub(crate) query_id: ControllerOpaqueRuntimeQueryId,
    pub(crate) query_snapshot_sequence: u64,
    pub(crate) query_response: &'a [u8],
    pub(crate) query_response_digest: ControllerQueryResponseDigest,
    pub(crate) channel_peer_fingerprint: ControllerChannelAuthFingerprint,
}

impl ControllerOpaqueQueryObservation {
    fn try_new(
        input: ControllerOpaqueQueryObservationInput<'_>,
    ) -> Result<Self, ControllerJournalError> {
        if bytes_are_zero(input.query_id.as_bytes())
            || input.query_snapshot_sequence == 0
            || bytes_are_zero(input.query_response_digest.value().as_bytes())
            || bytes_are_zero(input.channel_peer_fingerprint.value().as_bytes())
        {
            return Err(ControllerJournalError::InvalidQueryEvidence);
        }
        if input.query_response.is_empty() {
            return Err(ControllerJournalError::EmptyQueryResponse);
        }
        if input.query_response.len() > MAX_QUERY_RESPONSE_BYTES {
            return Err(ControllerJournalError::QueryResponseTooLarge);
        }
        Ok(Self {
            query_id: input.query_id,
            query_snapshot_sequence: input.query_snapshot_sequence,
            query_response: input.query_response.into(),
            query_response_digest: input.query_response_digest,
            channel_peer_fingerprint: input.channel_peer_fingerprint,
        })
    }

    fn validate_successor_of(&self, previous: &Self) -> Result<(), ControllerJournalError> {
        if self.query_snapshot_sequence < previous.query_snapshot_sequence {
            return Err(ControllerJournalError::QuerySequenceRegression);
        }
        Ok(())
    }
}

/// Reconcile decision bound to one already-durable opaque query observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerRolloutDecision {
    query_id: ControllerOpaqueRuntimeQueryId,
    query_snapshot_sequence: u64,
    observed: ControllerObservedTarget,
    receipt: Option<ControllerReceiptRef>,
}

impl ControllerRolloutDecision {
    fn try_new(
        observation: &ControllerOpaqueQueryObservation,
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
        Ok(Self {
            query_id: observation.query_id,
            query_snapshot_sequence: observation.query_snapshot_sequence,
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

/// One immutable query observation followed by its optional later decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerReconcileAttempt {
    observation: ControllerOpaqueQueryObservation,
    decision: Option<ControllerRolloutDecision>,
}

impl ControllerReconcileAttempt {
    fn validate(&self) -> Result<(), ControllerJournalError> {
        if let Some(decision) = self.decision
            && (decision.query_id != self.observation.query_id
                || decision.query_snapshot_sequence != self.observation.query_snapshot_sequence)
        {
            return Err(ControllerJournalError::DanglingRolloutDecision);
        }
        Ok(())
    }
}

/// One-target signed intent plus append-only reconciliation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerRolloutRecord {
    signed_intent: ControllerSignedApplyIntent,
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
            let sequence = attempt.observation.query_snapshot_sequence;
            if last_sequence.is_some_and(|previous| previous > sequence) {
                return Err(ControllerJournalError::NonCanonicalReconcileHistory);
            }
            if !query_ids.insert(attempt.observation.query_id) {
                return Err(ControllerJournalError::QueryEvidenceChanged);
            }
            if index + 1 != self.reconcile_attempts.len() && attempt.decision.is_none() {
                return Err(ControllerJournalError::DanglingQueryObservation);
            }
            if attempt
                .decision
                .is_some_and(|decision| decision.is_terminal())
                && index + 1 != self.reconcile_attempts.len()
            {
                return Err(ControllerJournalError::EvidenceAfterTerminalDecision);
            }
            last_sequence = Some(sequence);
        }
        Ok(())
    }

    fn is_terminal(&self) -> bool {
        self.reconcile_attempts
            .last()
            .and_then(|attempt| attempt.decision)
            .is_some_and(ControllerRolloutDecision::is_terminal)
    }
}

/// Full Controller-owned payload. It is immutable between validated mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerJournalState {
    scope: DeploymentScopeId,
    plan_lineage: DeploymentId,
    allocation: StableAllocationSnapshot,
    committed_plan: Option<ControllerCommittedPlan>,
    operations: Box<[ControllerOperationRecord]>,
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
    committed_plan: Option<ControllerCommittedPlan>,
    operations: Vec<ControllerOperationRecord>,
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
            committed_plan: None,
            operations: Vec::new(),
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
            committed_plan: input.committed_plan,
            operations: input.operations.into_boxed_slice(),
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
        if binding.target != self.allocation.target() || binding.target != plan.target {
            return Err(ControllerJournalError::TargetMismatch);
        }
        if binding.manifest_digest != plan.content.manifest_digest() {
            return Err(ControllerJournalError::ManifestBindingMismatch);
        }
        if let Some(previous) = &self.target_binding {
            binding.validate_successor_of(previous)?;
        }
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
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
        {
            return Err(ControllerJournalError::RolloutBindingMismatch);
        }
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water,
            rollout: Some(ControllerRolloutRecord {
                signed_intent: intent,
                reconcile_attempts: Box::new([]),
            }),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Second rollout transaction: persist exact authenticated query evidence.
    pub(crate) fn record_query_observation(
        &self,
        input: ControllerOpaqueQueryObservationInput<'_>,
    ) -> Result<Self, ControllerJournalError> {
        let observation = ControllerOpaqueQueryObservation::try_new(input)?;
        let binding = self
            .target_binding
            .as_ref()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        if observation.channel_peer_fingerprint != binding.channel_auth_fingerprint {
            return Err(ControllerJournalError::QueryChannelMismatch);
        }
        let mut rollout = self
            .rollout
            .clone()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        if let Some(existing) = rollout
            .reconcile_attempts
            .iter()
            .find(|attempt| attempt.observation.query_id == observation.query_id)
        {
            if existing.observation == observation {
                return Ok(self.clone());
            }
            return Err(ControllerJournalError::QueryEvidenceChanged);
        }
        if self.apply_history.iter().any(|record| {
            record
                .reconcile_attempts
                .iter()
                .any(|attempt| attempt.observation.query_id == observation.query_id)
        }) {
            return Err(ControllerJournalError::QueryIdentityConflict);
        }
        if observation.query_snapshot_sequence < self.query_snapshot_high_water {
            return Err(ControllerJournalError::QuerySequenceRegression);
        }
        if let Some(previous) = rollout.reconcile_attempts.last() {
            observation.validate_successor_of(&previous.observation)?;
            if previous.decision.is_none() {
                return Err(ControllerJournalError::DanglingQueryObservation);
            }
            if previous
                .decision
                .is_some_and(ControllerRolloutDecision::is_terminal)
            {
                return Err(ControllerJournalError::EvidenceAfterTerminalDecision);
            }
        }
        if rollout.reconcile_attempts.len() == MAX_RECONCILE_ATTEMPTS {
            return Err(ControllerJournalError::ReconcileCapacityExceeded);
        }
        let query_snapshot_sequence = observation.query_snapshot_sequence;
        let mut attempts = rollout.reconcile_attempts.to_vec();
        attempts.push(ControllerReconcileAttempt {
            observation,
            decision: None,
        });
        rollout.reconcile_attempts = attempts.into_boxed_slice();
        self.rebuild(ControllerJournalMutationInput {
            allocation: self.allocation.clone(),
            committed_plan: self.committed_plan.clone(),
            operations: self.operations.to_vec(),
            request_auth: self.request_auth,
            target_binding: self.target_binding.clone(),
            query_snapshot_high_water: self.query_snapshot_high_water.max(query_snapshot_sequence),
            rollout: Some(rollout),
            apply_history: self.apply_history.to_vec(),
        })
    }

    /// Third rollout transaction: bind a decision to already-durable query facts.
    pub(crate) fn record_rollout_decision(
        &self,
        observed: ControllerObservedTarget,
        receipt: Option<ControllerReceiptRef>,
    ) -> Result<Self, ControllerJournalError> {
        let mut rollout = self
            .rollout
            .clone()
            .ok_or(ControllerJournalError::DanglingRollout)?;
        let attempt = rollout
            .reconcile_attempts
            .last_mut()
            .ok_or(ControllerJournalError::DanglingRolloutDecision)?;
        let decision = ControllerRolloutDecision::try_new(&attempt.observation, observed, receipt)?;
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
            committed_plan: input.committed_plan,
            operations: input.operations,
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
        if !rollout.is_terminal() {
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

    fn current_revision(&self) -> u64 {
        self.committed_plan
            .as_ref()
            .map_or(0, |plan| plan.revision.value())
    }

    fn is_exact_fresh(&self) -> bool {
        self.committed_plan.is_none()
            && self.operations.is_empty()
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
            || self
                .target_binding
                .as_ref()
                .is_some_and(|binding| binding.target != candidate.content().target())
        {
            return Err(ControllerJournalError::CandidateTargetMismatch);
        }
        if self
            .target_binding
            .as_ref()
            .is_some_and(|binding| binding.manifest_digest != candidate.content().manifest_digest())
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
        if self.allocation.records().len() > MAX_ALLOCATION_RECORDS {
            return Err(ControllerJournalError::AllocationCapacityExceeded);
        }
        if self.operations.len() > MAX_CONTROLLER_OPERATIONS {
            return Err(ControllerJournalError::OperationCapacityExceeded);
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
        if let Some(plan) = &self.committed_plan {
            if plan.scope != self.scope
                || plan.plan != self.plan_lineage
                || plan.target != self.allocation.target()
            {
                return Err(ControllerJournalError::PlanLineageChanged);
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
            if binding.target != self.allocation.target() || binding.target != plan.target {
                return Err(ControllerJournalError::TargetMismatch);
            }
            if binding.manifest_digest != plan.content.manifest_digest() {
                return Err(ControllerJournalError::ManifestBindingMismatch);
            }
        }
        validate_apply_history(
            &self.apply_history,
            self.rollout.as_ref(),
            self.allocation.target(),
            self.target_binding.as_ref(),
            &self.operations,
            current_revision,
            self.query_snapshot_high_water,
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
        self.allocation
            .validate_successor_of(&previous.allocation)
            .map_err(|_| ControllerJournalError::InvalidAllocationTransition)?;
        validate_operation_successors(
            &self.operations,
            &previous.operations,
            previous.current_revision(),
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
            plan_changed,
        )?;
        validate_rollout_successor(
            self.rollout.as_ref(),
            previous.rollout.as_ref(),
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

fn validate_apply_history(
    history: &[ControllerRolloutRecord],
    current: Option<&ControllerRolloutRecord>,
    target: RuntimeHostId,
    binding: Option<&ControllerTargetBinding>,
    operations: &[ControllerOperationRecord],
    current_revision: u64,
    query_snapshot_high_water: u64,
) -> Result<(), ControllerJournalError> {
    let mut last_archived_plan_revision = None;
    let mut apply_operations = std::collections::BTreeSet::new();
    let mut request_digests = std::collections::BTreeSet::new();
    let mut source_plan_digests = std::collections::BTreeSet::new();
    let mut query_ids = std::collections::BTreeSet::new();
    let mut maximum_query_sequence = 0_u64;
    for record in history {
        record.validate()?;
        if !record.is_terminal() {
            return Err(ControllerJournalError::NonTerminalApplyHistory);
        }
        validate_request_auth_pin(record.signed_intent.request_auth)?;
        validate_archived_binding(&record.signed_intent, target, binding)?;
        validate_rollout_query_lineage(
            record,
            binding,
            &mut query_ids,
            &mut maximum_query_sequence,
        )?;
        if !source_plan_digests.insert(record.signed_intent.source_plan_digest) {
            return Err(ControllerJournalError::ApplyPlanAlreadyArchived);
        }
        let mut matching_commits = operations.iter().filter(|operation| {
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
        if archived_plan_revision >= current_revision
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
        validate_archived_binding(&record.signed_intent, target, binding)?;
        validate_rollout_query_lineage(
            record,
            binding,
            &mut query_ids,
            &mut maximum_query_sequence,
        )?;
        if !apply_operations.insert(record.signed_intent.apply_operation)
            || !request_digests.insert(record.signed_intent.request_digest)
        {
            return Err(ControllerJournalError::ApplyOperationConflict);
        }
    }
    if query_snapshot_high_water != maximum_query_sequence {
        return Err(ControllerJournalError::QueryHighWaterMismatch);
    }
    Ok(())
}

fn validate_rollout_query_lineage(
    record: &ControllerRolloutRecord,
    binding: Option<&ControllerTargetBinding>,
    query_ids: &mut std::collections::BTreeSet<ControllerOpaqueRuntimeQueryId>,
    maximum_query_sequence: &mut u64,
) -> Result<(), ControllerJournalError> {
    let binding = binding.ok_or(ControllerJournalError::DanglingRollout)?;
    for attempt in &record.reconcile_attempts {
        if attempt.observation.channel_peer_fingerprint != binding.channel_auth_fingerprint {
            return Err(ControllerJournalError::QueryChannelMismatch);
        }
        if !query_ids.insert(attempt.observation.query_id) {
            return Err(ControllerJournalError::QueryIdentityConflict);
        }
        *maximum_query_sequence =
            (*maximum_query_sequence).max(attempt.observation.query_snapshot_sequence);
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
        if !previous_rollout.is_terminal() {
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
            if !new.reconcile_attempts.is_empty() {
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
            let old_attempts = &old.reconcile_attempts;
            let new_attempts = &new.reconcile_attempts;
            if new_attempts.len() == old_attempts.len() {
                let Some((old_last, old_prefix)) = old_attempts.split_last() else {
                    return Err(ControllerJournalError::RolloutIntentChanged);
                };
                let Some((new_last, new_prefix)) = new_attempts.split_last() else {
                    return Err(ControllerJournalError::RolloutIntentChanged);
                };
                if old_prefix != new_prefix
                    || old_last.observation != new_last.observation
                    || old_last.decision.is_some()
                    || new_last.decision.is_none()
                {
                    return Err(ControllerJournalError::QueryNotCommittedBeforeDecision);
                }
            } else if new_attempts.len() == old_attempts.len() + 1 {
                if new_attempts[..old_attempts.len()] != **old_attempts
                    || new_attempts
                        .last()
                        .is_some_and(|attempt| attempt.decision.is_some())
                {
                    return Err(ControllerJournalError::QueryNotCommittedBeforeDecision);
                }
                if let Some(last) = old_attempts.last()
                    && (last.decision.is_none()
                        || last
                            .decision
                            .is_some_and(ControllerRolloutDecision::is_terminal))
                {
                    return Err(ControllerJournalError::EvidenceAfterTerminalDecision);
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
        let payload = encode_payload(&self.state)?;
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
        prefix.extend_from_slice(&CONTROLLER_PAYLOAD_VERSION.to_be_bytes());
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

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
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
    checked_encoded_add(&mut length, 16 + 2 + 2 + 32 + 8 + 8)?;

    checked_encoded_add(&mut length, 1)?;
    if let Some(binding) = &state.target_binding {
        checked_encoded_add(
            &mut length,
            16 + 32 + 32 + 32 + 8 + 8 + 4 + binding.bootstrap_response.len() + 32,
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
        + size_of::<u32>();
    for attempt in &rollout.reconcile_attempts {
        checked_encoded_add(
            &mut length,
            16 + 8 + 4 + attempt.observation.query_response.len() + 32 + 32 + 1,
        )?;
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
    state.validate()?;
    let expected_length = controller_payload_encoded_len(state)?;
    let encoded = encode_payload_fields(state)?;
    debug_assert_eq!(encoded.len(), expected_length);
    Ok(encoded)
}

fn encode_payload_fields(
    state: &ControllerJournalState,
) -> Result<Vec<u8>, ControllerJournalError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(CONTROLLER_PAYLOAD_MAGIC);
    encoded.extend_from_slice(&CONTROLLER_PAYLOAD_VERSION.to_be_bytes());
    encoded.extend_from_slice(state.scope.as_bytes());
    encoded.extend_from_slice(state.plan_lineage.as_bytes());
    encoded.extend_from_slice(state.allocation.target().as_bytes());
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
    let mut reader = Reader::new(bytes);
    if reader.take_array::<4>()? != *CONTROLLER_PAYLOAD_MAGIC {
        return Err(ControllerJournalError::InvalidPayloadMagic);
    }
    if reader.u16()? != CONTROLLER_PAYLOAD_VERSION {
        return Err(ControllerJournalError::UnknownPayloadVersion);
    }
    let scope = DeploymentScopeId::from_bytes(reader.take_array::<16>()?);
    let plan_lineage = DeploymentId::from_bytes(reader.take_array::<16>()?);
    let target = RuntimeHostId::from_bytes(reader.take_array::<16>()?);
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
    let request_auth = decode_auth_pin(&mut reader)?;
    let query_snapshot_high_water = reader.u64()?;
    let target_binding = decode_optional_binding(&mut reader)?;
    let rollout = decode_optional_rollout(&mut reader)?;
    let history_count = reader.count(MAX_APPLY_OPERATION_HISTORY)?;
    let mut apply_history = Vec::with_capacity(history_count);
    for _ in 0..history_count {
        apply_history.push(decode_rollout(&mut reader)?);
    }
    if reader.remaining() != 0 {
        return Err(ControllerJournalError::TrailingBytes);
    }
    ControllerJournalState::try_from_stored(ControllerJournalStateInput {
        scope,
        plan_lineage,
        allocation,
        committed_plan,
        operations,
        request_auth,
        target_binding,
        query_snapshot_high_water,
        rollout,
        apply_history,
    })
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

    append_count(encoded, rollout.reconcile_attempts.len())?;
    for attempt in &rollout.reconcile_attempts {
        let observation = &attempt.observation;
        encoded.extend_from_slice(observation.query_id.as_bytes());
        encoded.extend_from_slice(&observation.query_snapshot_sequence.to_be_bytes());
        append_bytes(encoded, &observation.query_response)?;
        encoded.extend_from_slice(observation.query_response_digest.value().as_bytes());
        encoded.extend_from_slice(observation.channel_peer_fingerprint.value().as_bytes());
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
) -> Result<Option<ControllerRolloutRecord>, ControllerJournalError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decode_rollout(reader)?)),
        _ => Err(ControllerJournalError::InvalidPresence),
    }
}

fn decode_rollout(
    reader: &mut Reader<'_>,
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
        })?;
    let attempt_count = reader.count(MAX_RECONCILE_ATTEMPTS)?;
    let mut attempts = Vec::with_capacity(attempt_count);
    for _ in 0..attempt_count {
        let observation =
            ControllerOpaqueQueryObservation::try_new(ControllerOpaqueQueryObservationInput {
                query_id: ControllerOpaqueRuntimeQueryId::from_bytes(reader.take_array::<16>()?),
                query_snapshot_sequence: reader.u64()?,
                query_response: reader.bounded_bytes(MAX_QUERY_RESPONSE_BYTES)?,
                query_response_digest: ControllerQueryResponseDigest::from_stored(
                    Digest32::from_bytes(reader.take_array::<32>()?),
                ),
                channel_peer_fingerprint: ControllerChannelAuthFingerprint::from_stored(
                    Digest32::from_bytes(reader.take_array::<32>()?),
                ),
            })?;
        let decision = match reader.u8()? {
            0 => None,
            1 => {
                let query_id =
                    ControllerOpaqueRuntimeQueryId::from_bytes(reader.take_array::<16>()?);
                let query_snapshot_sequence = reader.u64()?;
                let observed = ControllerObservedTarget::decode(reader.u8()?)?;
                let receipt = decode_optional_id(reader)?.map(ControllerReceiptRef::from_bytes);
                let decision = ControllerRolloutDecision::try_new(&observation, observed, receipt)?;
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
            observation,
            decision,
        });
    }
    let rollout = ControllerRolloutRecord {
        signed_intent: intent,
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
    EmptyQueryResponse,
    QueryResponseTooLarge,
    InvalidQueryEvidence,
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
}

impl From<DigestBuildError> for ControllerJournalError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ControllerJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ControllerJournalError {}

#[cfg(test)]
mod tests {
    use super::{
        CONTROLLER_PAYLOAD_MAGIC, ControllerApplyRequestDigest, ControllerAuthKeyFingerprint,
        ControllerBootstrapResponseDigest, ControllerChannelAuthFingerprint,
        ControllerJournalError, ControllerJournalSnapshot, ControllerJournalState,
        ControllerObservedTarget, ControllerOpaqueQueryObservationInput,
        ControllerOpaqueRuntimeQueryId, ControllerOperationId, ControllerOperationPhase,
        ControllerOwnerIdentityFingerprint, ControllerPlanCommitIntentDigest,
        ControllerQueryResponseDigest, ControllerReceiptRef, ControllerRequestAuthPin,
        ControllerSignedApplyIntentInput, ControllerTargetBinding, ControllerTargetBindingInput,
        controller_checksum,
    };
    use crate::plan::{DeploymentId, DeploymentScopeId};
    use crate::planner::{
        AllocationState, PlanManifestDigest, StableAllocationSnapshot, journal_test_candidate,
    };
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_runtime_contracts::apply::ApplyOperationId;
    use paraegox_runtime_contracts::provenance::{SourcePlanDigest, TargetSliceDigest};
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

    const SCOPE: DeploymentScopeId = DeploymentScopeId::from_bytes([0x21; 16]);
    const PLAN: DeploymentId = DeploymentId::from_bytes([0x22; 16]);
    const TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x61; 16]);
    const PLAN_OPERATION: ControllerOperationId = ControllerOperationId::from_bytes([0x31; 16]);

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
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
        ControllerJournalState::try_initialize(SCOPE, PLAN, empty_allocation(TARGET), auth(0x11, 1))
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

    fn binding(last_epoch: u64, response: &'static [u8]) -> ControllerTargetBinding {
        ControllerTargetBinding::try_new(ControllerTargetBindingInput {
            target: TARGET,
            runtime_store_instance_id: [0x62; 32],
            channel_auth_fingerprint: ControllerChannelAuthFingerprint::from_stored(digest(0x63)),
            manifest_digest: PlanManifestDigest::try_new(digest(0x52))
                .expect("fixture manifest digest must validate"),
            first_runtime_host_epoch: 2,
            last_runtime_host_epoch: last_epoch,
            bootstrap_response: response,
            bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(digest(
                response[0],
            )),
        })
        .expect("fixture binding must validate")
    }

    fn committed_snapshot() -> ControllerJournalSnapshot {
        let initial = initial_snapshot();
        let candidate =
            journal_test_candidate(TARGET, &initial.state.allocation, Some([2; 16]), 0x50)
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

    fn signed_snapshot() -> ControllerJournalSnapshot {
        let bound = bound_snapshot();
        let state = bound
            .state
            .record_signed_apply_intent(signed_input(&bound.state))
            .expect("signed intent must record");
        bound
            .try_successor(state)
            .expect("signed snapshot must succeed")
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

    fn query_input(
        sequence: u64,
        response: &'static [u8],
    ) -> ControllerOpaqueQueryObservationInput<'static> {
        ControllerOpaqueQueryObservationInput {
            query_id: ControllerOpaqueRuntimeQueryId::from_bytes(
                [u8::try_from(sequence).expect("fixture query sequence must fit"); 16],
            ),
            query_snapshot_sequence: sequence,
            query_response: response,
            query_response_digest: ControllerQueryResponseDigest::from_stored(digest(response[0])),
            channel_peer_fingerprint: ControllerChannelAuthFingerprint::from_stored(digest(0x63)),
        }
    }

    fn decided_snapshot() -> ControllerJournalSnapshot {
        let signed = signed_snapshot();
        let query_state = signed
            .state
            .record_query_observation(query_input(9, b"query-nine"))
            .expect("query evidence must record");
        let queried = signed
            .try_successor(query_state)
            .expect("query snapshot must succeed");
        let decision_state = queried
            .state
            .record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(ControllerReceiptRef::from_bytes([0x6c; 16])),
            )
            .expect("decision must record");
        queried
            .try_successor(decision_state)
            .expect("decision snapshot must succeed")
    }

    fn state_with_two_archived_rollouts() -> ControllerJournalState {
        let mut state = decided_snapshot().state;
        let second_plan = journal_test_candidate(TARGET, &state.allocation, None, 0x50)
            .expect("second plan fixture must validate");
        let second_plan_operation = ControllerOperationId::from_bytes([0x32; 16]);
        state = state
            .prepare_plan_candidate(second_plan_operation, &second_plan)
            .expect("second plan must prepare");
        state = state
            .commit_plan_candidate(second_plan_operation, &second_plan)
            .expect("first rollout must archive");
        state = state
            .record_signed_apply_intent(different_signed_input(&state, 0x77, 0x78))
            .expect("second rollout intent must record");
        state = state
            .record_query_observation(query_input(10, b"query-ten"))
            .expect("second rollout query must record");
        state = state
            .record_rollout_decision(
                ControllerObservedTarget::Retired,
                Some(ControllerReceiptRef::from_bytes([0x79; 16])),
            )
            .expect("second rollout must become terminal");
        let third_plan = journal_test_candidate(TARGET, &state.allocation, None, 0x50)
            .expect("third plan fixture must validate");
        let third_plan_operation = ControllerOperationId::from_bytes([0x33; 16]);
        state = state
            .prepare_plan_candidate(third_plan_operation, &third_plan)
            .expect("third plan must prepare");
        state
            .commit_plan_candidate(third_plan_operation, &third_plan)
            .expect("second rollout must archive")
    }

    fn encode_unvalidated_state(state: &ControllerJournalState, snapshot_sequence: u64) -> Vec<u8> {
        let payload = super::encode_payload_fields(state)
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

    fn refresh_checksum(encoded: &mut [u8]) {
        let checksum = controller_checksum(
            &encoded[..super::JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES],
            &encoded[super::JOURNAL_HEADER_BYTES..],
        )
        .expect("mutated envelope must checksum");
        encoded[super::JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES..super::JOURNAL_HEADER_BYTES]
            .copy_from_slice(checksum.as_bytes());
    }

    #[test]
    fn full_snapshot_has_frozen_checksum_and_round_trips_byte_identically() {
        let snapshot = decided_snapshot();
        assert_eq!(snapshot.snapshot_sequence, 7);
        let encoded = snapshot.encode().expect("snapshot must encode");
        assert!(encoded.starts_with(b"PXJR\0\x01\0\x01"));
        assert_eq!(
            &encoded[super::JOURNAL_HEADER_WITHOUT_CHECKSUM_BYTES..super::JOURNAL_HEADER_BYTES],
            &[
                97, 108, 160, 126, 77, 63, 57, 202, 69, 59, 39, 55, 189, 77, 105, 237, 39, 253, 26,
                225, 232, 116, 23, 235, 217, 27, 130, 182, 138, 156, 155, 58,
            ]
        );
        let decoded = ControllerJournalSnapshot::decode(&encoded).expect("snapshot must decode");
        assert_eq!(decoded, snapshot);
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
        let projection = [0x50; 7];
        let plan_offset = forged_plan
            .windows(projection.len())
            .position(|window| window == projection)
            .expect("fixture PlanContent projection must be encoded");
        forged_plan[plan_offset] ^= 1;
        refresh_checksum(&mut forged_plan);
        assert_eq!(
            ControllerJournalSnapshot::decode(&forged_plan),
            Err(ControllerJournalError::PlanContentDigestMismatch)
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
        bad_payload_version[9] = 4;
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
    fn plan_commit_requires_exact_typed_candidate_and_prepared_operation() {
        let initial = initial_snapshot();
        let candidate =
            journal_test_candidate(TARGET, &initial.state.allocation, Some([2; 16]), 0x50)
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
        let different =
            journal_test_candidate(TARGET, &prepared.state.allocation, Some([2; 16]), 0x51)
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
        let candidate =
            journal_test_candidate(TARGET, &initial.state.allocation, Some([2; 16]), 0x50)
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
        let changed_store = ControllerTargetBinding::try_new(ControllerTargetBindingInput {
            target: TARGET,
            runtime_store_instance_id: [0x72; 32],
            channel_auth_fingerprint: ControllerChannelAuthFingerprint::from_stored(digest(0x63)),
            manifest_digest: PlanManifestDigest::try_new(digest(0x52))
                .expect("fixture manifest digest must validate"),
            first_runtime_host_epoch: 2,
            last_runtime_host_epoch: 4,
            bootstrap_response: b"bootstrap-four",
            bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(digest(b'b')),
        })
        .expect("changed store binding is individually valid");
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
        let other_candidate = journal_test_candidate(
            other_target,
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
    fn signed_query_and_decision_are_three_distinct_successor_transactions() {
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
        let signed_state = bound
            .state
            .record_signed_apply_intent(signed_input(&bound.state))
            .expect("signed intent must record");
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
        let query_state = signed
            .state
            .record_query_observation(query_input(9, b"query-nine"))
            .expect("query must record");
        let premature_decision = query_state
            .record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(ControllerReceiptRef::from_bytes([0x6c; 16])),
            )
            .expect("in-memory decision candidate must validate");
        assert_eq!(
            signed.try_successor(premature_decision),
            Err(ControllerJournalError::QueryNotCommittedBeforeDecision)
        );
        let queried = signed
            .try_successor(query_state)
            .expect("query evidence must commit separately");
        assert_eq!(
            queried
                .state
                .record_query_observation(query_input(8, b"query-eight")),
            Err(ControllerJournalError::QuerySequenceRegression)
        );
        assert_eq!(
            queried
                .state
                .record_query_observation(query_input(9, b"changed-nine")),
            Err(ControllerJournalError::QueryEvidenceChanged)
        );
        let decided_state = queried
            .state
            .record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(ControllerReceiptRef::from_bytes([0x6c; 16])),
            )
            .expect("decision must bind durable query");
        let decided = queried
            .try_successor(decided_state)
            .expect("decision must be the third transaction");
        assert_eq!(
            decided
                .state
                .record_query_observation(query_input(10, b"query-ten")),
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
    fn nonterminal_rollouts_block_plan_commit_and_no_current_intent_can_be_overwritten() {
        fn assert_plan_commit_blocked(state: &ControllerJournalState) {
            let candidate = journal_test_candidate(TARGET, &state.allocation, None, 0x50)
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

        let signed = signed_snapshot();
        let query_only = signed
            .state
            .record_query_observation(query_input(9, b"query-nine"))
            .expect("query-only state must validate");
        let prepared_decision = query_only
            .record_rollout_decision(ControllerObservedTarget::Prepared, None)
            .expect("Prepared is a nonterminal reconcile decision");
        let uncertain_decision = query_only
            .record_rollout_decision(ControllerObservedTarget::Uncertain, None)
            .expect("Uncertain is a nonterminal reconcile decision");
        let terminal_decision = query_only
            .record_rollout_decision(
                ControllerObservedTarget::Active,
                Some(ControllerReceiptRef::from_bytes([0x6c; 16])),
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
        let signed = signed_snapshot();
        let query_state = signed
            .state
            .record_query_observation(query_input(9, b"query-nine"))
            .expect("first query must record");
        let queried = signed
            .try_successor(query_state)
            .expect("query must be a separate successor");
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
        let mut same_snapshot_query = query_input(9, b"query-nine-retry");
        same_snapshot_query.query_id = ControllerOpaqueRuntimeQueryId::from_bytes([0x6b; 16]);
        let second_query_state = restarted
            .state
            .record_query_observation(same_snapshot_query)
            .expect("Prepared must remain queryable");
        let second_query = restarted
            .try_successor(second_query_state)
            .expect("next query must append separately");
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
                Some(ControllerReceiptRef::from_bytes([0x6c; 16])),
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

        let uncertain_signed = signed_snapshot();
        let uncertain_query = uncertain_signed
            .state
            .record_query_observation(query_input(20, b"query-twenty"))
            .expect("Uncertain branch query must record");
        let uncertain_decision = uncertain_query
            .record_rollout_decision(ControllerObservedTarget::Uncertain, None)
            .expect("Uncertain decision must record");
        let later_query = uncertain_decision
            .record_query_observation(query_input(21, b"query-twenty-one"))
            .expect("Uncertain must remain queryable");
        let retired = later_query
            .record_rollout_decision(
                ControllerObservedTarget::Retired,
                Some(ControllerReceiptRef::from_bytes([0x6e; 16])),
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
    fn manifest_binding_and_historical_auth_pin_cannot_swap_after_rotation() {
        let bound = bound_snapshot();
        let manifest_b = journal_test_candidate(TARGET, &bound.state.allocation, None, 0x51)
            .expect("different-manifest candidate must be typed");
        assert_eq!(
            bound.state.prepare_plan_candidate(
                ControllerOperationId::from_bytes([0x32; 16]),
                &manifest_b,
            ),
            Err(ControllerJournalError::CandidateManifestMismatch)
        );
        let mismatched_binding = ControllerTargetBinding::try_new(ControllerTargetBindingInput {
            target: TARGET,
            runtime_store_instance_id: [0x62; 32],
            channel_auth_fingerprint: ControllerChannelAuthFingerprint::from_stored(digest(0x63)),
            manifest_digest: PlanManifestDigest::try_new(digest(0x53))
                .expect("manifest B digest must validate"),
            first_runtime_host_epoch: 2,
            last_runtime_host_epoch: 4,
            bootstrap_response: b"manifest-b-bootstrap",
            bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(digest(0x73)),
        })
        .expect("manifest B binding is individually well formed");
        assert_eq!(
            bound.state.record_target_binding(mismatched_binding),
            Err(ControllerJournalError::ManifestBindingMismatch)
        );

        let signed = signed_snapshot();
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

        let queried = restarted
            .state
            .record_query_observation(query_input(30, b"query-thirty"))
            .expect("old signed pin remains reconcilable after rotation");
        let terminal = queried
            .record_rollout_decision(
                ControllerObservedTarget::Retired,
                Some(ControllerReceiptRef::from_bytes([0x6f; 16])),
            )
            .expect("Retired decision must record");
        let candidate = journal_test_candidate(TARGET, &terminal.allocation, None, 0x50)
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
            let mut apply_operation = [0_u8; 16];
            apply_operation[0] = 0x90;
            apply_operation[14..].copy_from_slice(&index.to_be_bytes());
            let mut request_digest = [0_u8; 32];
            request_digest[0] = 0x91;
            request_digest[30..].copy_from_slice(&index.to_be_bytes());
            let input = ControllerSignedApplyIntentInput {
                target: TARGET,
                source_plan_digest: state
                    .committed_plan
                    .as_ref()
                    .expect("plan")
                    .deployment_plan_digest,
                target_slice_digest: TargetSliceDigest::new(digest(0x76)),
                apply_operation: ApplyOperationId::from_bytes(apply_operation),
                request_digest: ControllerApplyRequestDigest::from_stored(Digest32::from_bytes(
                    request_digest,
                )),
                signed_request: b"capacity-signed-request",
            };
            state = state
                .record_signed_apply_intent(input)
                .expect("unique apply intent must record");
            state = state
                .record_query_observation(query_input(u64::from(index) + 1, b"capacity-query"))
                .expect("capacity query must record");
            let mut receipt = [0_u8; 16];
            receipt[0] = 0x92;
            receipt[14..].copy_from_slice(&index.to_be_bytes());
            state = state
                .record_rollout_decision(
                    ControllerObservedTarget::Active,
                    Some(ControllerReceiptRef::from_bytes(receipt)),
                )
                .expect("capacity terminal decision must record");
            let candidate = journal_test_candidate(TARGET, &state.allocation, None, 0x50)
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

        state = state
            .record_signed_apply_intent(different_signed_input(&state, 0xa3, 0xa4))
            .expect("a fresh current rollout is allowed after the prior one was archived");
        state = state
            .record_query_observation(query_input(200, b"capacity-final-query"))
            .expect("final query must record");
        state = state
            .record_rollout_decision(
                ControllerObservedTarget::Retired,
                Some(ControllerReceiptRef::from_bytes([0xa5; 16])),
            )
            .expect("final terminal decision must record");
        assert_eq!(
            state.operations.len()
                + state.apply_history.len()
                + usize::from(state.rollout.is_some()),
            super::MAX_CONTROLLER_LEDGER_RECORDS
        );
        let candidate = journal_test_candidate(TARGET, &state.allocation, None, 0x50)
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
            let candidate = journal_test_candidate(TARGET, &state.allocation, None, 0x50)
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
        let candidate = journal_test_candidate(TARGET, &state.allocation, None, 0x50)
            .expect("next candidate must remain pure");
        let before = state.clone();
        assert_eq!(
            state.prepare_plan_candidate(ControllerOperationId::from_bytes([0xb3; 16]), &candidate),
            Err(ControllerJournalError::ControllerLedgerCapacityExceeded)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn accumulated_query_evidence_cannot_return_an_unpersistable_state() {
        let mut state = signed_snapshot().state;
        let response = vec![0xc1; super::MAX_QUERY_RESPONSE_BYTES];
        for sequence in 1..=3_u64 {
            state = state
                .record_query_observation(ControllerOpaqueQueryObservationInput {
                    query_id: ControllerOpaqueRuntimeQueryId::from_bytes(
                        [u8::try_from(sequence).expect("fixture sequence must fit"); 16],
                    ),
                    query_snapshot_sequence: sequence,
                    query_response: &response,
                    query_response_digest: ControllerQueryResponseDigest::from_stored(digest(
                        u8::try_from(sequence).expect("fixture sequence must fit"),
                    )),
                    channel_peer_fingerprint: ControllerChannelAuthFingerprint::from_stored(
                        digest(0x63),
                    ),
                })
                .expect("the first three large observations fit the snapshot bound");
            state = state
                .record_rollout_decision(ControllerObservedTarget::Prepared, None)
                .expect("nonterminal decision permits the next query");
        }
        let before = state.clone();
        assert_eq!(
            state.record_query_observation(ControllerOpaqueQueryObservationInput {
                query_id: ControllerOpaqueRuntimeQueryId::from_bytes([4; 16]),
                query_snapshot_sequence: 4,
                query_response: &response,
                query_response_digest: ControllerQueryResponseDigest::from_stored(digest(4)),
                channel_peer_fingerprint: ControllerChannelAuthFingerprint::from_stored(digest(
                    0x63,
                )),
            }),
            Err(ControllerJournalError::SnapshotTooLarge)
        );
        assert_eq!(state, before);
        let persistable = ControllerJournalSnapshot::try_from_stored(
            [0x41; 32],
            ControllerOwnerIdentityFingerprint::from_stored(digest(0x42)),
            10,
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
        let signed = signed_snapshot();
        let mut wrong_peer = query_input(9, b"wrong-peer");
        wrong_peer.channel_peer_fingerprint =
            ControllerChannelAuthFingerprint::from_stored(digest(0x64));
        assert_eq!(
            signed.state.record_query_observation(wrong_peer),
            Err(ControllerJournalError::QueryChannelMismatch)
        );

        let mut forged_current_peer = decided_snapshot().state;
        forged_current_peer
            .rollout
            .as_mut()
            .expect("current rollout")
            .reconcile_attempts[0]
            .observation
            .channel_peer_fingerprint = ControllerChannelAuthFingerprint::from_stored(digest(0x64));
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&forged_current_peer, 7)),
            Err(ControllerJournalError::QueryChannelMismatch)
        );

        let archived = state_with_two_archived_rollouts();
        let mut forged_history_peer = archived.clone();
        forged_history_peer.apply_history[0].reconcile_attempts[0]
            .observation
            .channel_peer_fingerprint = ControllerChannelAuthFingerprint::from_stored(digest(0x64));
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(&forged_history_peer, 12)),
            Err(ControllerJournalError::QueryChannelMismatch)
        );

        let current = archived
            .record_signed_apply_intent(different_signed_input(&archived, 0x7a, 0x7b))
            .expect("fresh current rollout must record");
        let mut reused_archived_query = query_input(11, b"reused-archived-query");
        reused_archived_query.query_id = ControllerOpaqueRuntimeQueryId::from_bytes([9; 16]);
        assert_eq!(
            current.record_query_observation(reused_archived_query),
            Err(ControllerJournalError::QueryIdentityConflict)
        );

        let current = current
            .record_query_observation(query_input(11, b"query-eleven"))
            .expect("unique current query must record")
            .record_rollout_decision(ControllerObservedTarget::Prepared, None)
            .expect("current query decision must record");
        let archived_query_id = current.apply_history[0].reconcile_attempts[0]
            .observation
            .query_id;
        let mut forged_current_history_reuse = current;
        let attempt = &mut forged_current_history_reuse
            .rollout
            .as_mut()
            .expect("current rollout")
            .reconcile_attempts[0];
        attempt.observation.query_id = archived_query_id;
        attempt
            .decision
            .as_mut()
            .expect("current decision")
            .query_id = archived_query_id;
        assert_eq!(
            ControllerJournalSnapshot::decode(&encode_unvalidated_state(
                &forged_current_history_reuse,
                15,
            )),
            Err(ControllerJournalError::QueryIdentityConflict)
        );
    }

    #[test]
    fn query_snapshot_high_water_is_exact_and_survives_rollout_boundaries() {
        let archived = state_with_two_archived_rollouts();
        assert_eq!(archived.query_snapshot_high_water, 10);
        let current = archived
            .record_signed_apply_intent(different_signed_input(&archived, 0x7c, 0x7d))
            .expect("fresh current rollout must record");
        let mut regressed = query_input(9, b"cross-rollout-regression");
        regressed.query_id = ControllerOpaqueRuntimeQueryId::from_bytes([0x7e; 16]);
        assert_eq!(
            current.record_query_observation(regressed),
            Err(ControllerJournalError::QuerySequenceRegression)
        );
        let mut equal_high_water = query_input(10, b"equal-high-water");
        equal_high_water.query_id = ControllerOpaqueRuntimeQueryId::from_bytes([0x7f; 16]);
        let equal = current
            .record_query_observation(equal_high_water)
            .expect("a distinct query may conservatively share the durable sequence");
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
            Err(ControllerJournalError::NonCanonicalApplyHistory)
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
            Err(ControllerJournalError::NonCanonicalApplyHistory)
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
        let candidate =
            journal_test_candidate(TARGET, &initial.state.allocation, Some([2; 16]), 0x50)
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
        let empty_candidate = journal_test_candidate(TARGET, &active_allocation, None, 0x50)
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
            Err(ControllerJournalError::ManifestBindingMismatch)
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
    fn next_plan_archives_terminal_rollout_and_retains_allocation_history() {
        let decided = decided_snapshot();
        let empty_candidate = journal_test_candidate(TARGET, &decided.state.allocation, None, 0x50)
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
            empty.state.apply_history[0],
            *decided.state.rollout.as_ref().expect("terminal rollout")
        );
        assert_eq!(empty.state.target_binding, decided.state.target_binding);
        assert_eq!(empty.state.operations.len(), 2);
        assert_eq!(empty.state.allocation.records().len(), 1);
        assert_eq!(
            empty.state.allocation.records()[0].state(),
            AllocationState::Tombstone
        );

        let next_candidate =
            journal_test_candidate(TARGET, &empty.state.allocation, Some([3; 16]), 0x50)
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
        let candidate = journal_test_candidate(TARGET, &state.allocation, None, 0x30)
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
}
