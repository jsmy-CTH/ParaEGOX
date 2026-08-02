//! Owner-private S7/P2e Runtime journal codec and state validator.
//!
//! This module owns only the deterministic, bounded Runtime snapshot model. It
//! performs no filesystem I/O, initialization, endpoint startup, apply, or
//! recovery action. In particular, descriptor and singleton-manifest values are
//! retained as exact opaque bytes plus their externally supplied digests. Their
//! canonical schemas and semantic bounds remain owned by the crate-private S7-B
//! successor contract until S7-E connects the real producer and Runtime
//! consumer. Nothing here decodes or reconstructs those contracts.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_runtime_contracts::provenance::{SourcePlanDigest, TargetSliceDigest};

pub(crate) const RUNTIME_JOURNAL_ENVELOPE_VERSION: u16 = 1;
pub(crate) const RUNTIME_JOURNAL_PAYLOAD_VERSION: u16 = 2;
pub(crate) const RUNTIME_JOURNAL_OWNER_KIND: u16 = 3;
pub(crate) const RUNTIME_JOURNAL_CHECKSUM_ALGORITHM: u16 = 1;
pub(crate) const RUNTIME_JOURNAL_CHECKSUM_VERSION: u16 = 1;
pub(crate) const MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_RUNTIME_TERMINAL_OPERATIONS: usize = 256;
pub(crate) const MAX_RUNTIME_RECOVERY_TERMINALS: usize = 256;
pub(crate) const MAX_RUNTIME_TENURE_NONCES: usize = 256;
pub(crate) const MAX_RUNTIME_REQUEST_NONCES: usize = 256;
pub(crate) const MAX_RUNTIME_TEMPORAL_LINEAGES: usize = 256;
pub(crate) const MAX_RUNTIME_OWNED_RESOURCES: usize = 4096;
pub(crate) const MAX_RUNTIME_SOURCE_SCOPES: usize = 1;
pub(crate) const MAX_RUNTIME_TERMINAL_RESPONSE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES: usize = 512;

// These are owner-local journal container limits, not copies of the private
// S7-B descriptor, manifest, PXAR, or Slice protocol bounds. The authoritative
// decoder applies its own smaller limits when S7-E supplies the typed adapter.
const MAX_PINNED_OPAQUE_ARTIFACT_BYTES: usize = 1024 * 1024;
const MAX_OPAQUE_REQUEST_OR_SLICE_BYTES: usize = 4 * 1024 * 1024;
const RUNTIME_JOURNAL_MAGIC: &[u8; 4] = b"PXJR";
const RUNTIME_JOURNAL_CHECKSUM_DOMAIN: &[u8] = b"paraegox.runtime.owner-journal.snapshot.sha256.v1";
const RUNTIME_RESOURCE_CENSUS_DOMAIN: &[u8] =
    b"paraegox.runtime.owner-journal.resource-census.sha256.v1";
const RUNTIME_STARTUP_INVALIDATION_DOMAIN: &[u8] =
    b"paraegox.runtime.owner-journal.startup-invalidation.sha256.v1";
const RUNTIME_STARTUP_RECONCILE_DOMAIN: &[u8] =
    b"paraegox.runtime.owner-journal.startup-reconcile.sha256.v1";
const RUNTIME_RECOVERY_FAILURE_DOMAIN: &[u8] =
    b"paraegox.runtime.owner-journal.recovery-failure.sha256.v1";
const HEADER_WITHOUT_CHECKSUM_BYTES: usize = 94;
const HEADER_BYTES: usize = HEADER_WITHOUT_CHECKSUM_BYTES + 32;

type Ref16 = [u8; 16];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OpaqueCanonicalValue {
    pub(crate) canonical_bytes: Box<[u8]>,
    pub(crate) digest: Digest32,
}

impl OpaqueCanonicalValue {
    pub(crate) fn try_pinned_artifact(
        canonical_bytes: &[u8],
        digest: Digest32,
    ) -> Result<Self, RuntimeJournalError> {
        Self::try_new(canonical_bytes, digest, MAX_PINNED_OPAQUE_ARTIFACT_BYTES)
    }

    pub(crate) fn try_request_or_slice(
        canonical_bytes: &[u8],
        digest: Digest32,
    ) -> Result<Self, RuntimeJournalError> {
        Self::try_new(canonical_bytes, digest, MAX_OPAQUE_REQUEST_OR_SLICE_BYTES)
    }

    fn try_new(
        canonical_bytes: &[u8],
        digest: Digest32,
        maximum: usize,
    ) -> Result<Self, RuntimeJournalError> {
        if canonical_bytes.is_empty() {
            return Err(RuntimeJournalError::EmptyOpaqueValue);
        }
        if canonical_bytes.len() > maximum {
            return Err(RuntimeJournalError::OpaqueValueTooLarge);
        }
        ensure_nonzero_digest(&digest)?;
        Ok(Self {
            canonical_bytes: canonical_bytes.into(),
            digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ReplayLedgerRecord {
    pub(crate) identity: Digest32,
    pub(crate) value_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct TemporalLineageRecord {
    pub(crate) constraint_id: Ref16,
    pub(crate) source_scope: Ref16,
    pub(crate) target_fingerprint: Digest32,
    pub(crate) original_budget_nanos: u64,
    pub(crate) remaining_budget_nanos: u64,
    pub(crate) clock_generation: u64,
    pub(crate) deadline_nanos: u64,
    pub(crate) lineage_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostClockAdmissionState {
    pub(crate) runtime_host_epoch_high_water: u64,
    pub(crate) clock_domain: Ref16,
    pub(crate) clock_generation_high_water: u64,
    pub(crate) build_descriptor: OpaqueCanonicalValue,
    pub(crate) singleton_manifest: OpaqueCanonicalValue,
    pub(crate) store_pinned_build_identity: OpaqueCanonicalValue,
    pub(crate) compiled_build_instance_id: [u8; 32],
    pub(crate) compiled_compatibility_digest: Digest32,
    pub(crate) admission_policy_fingerprint: Digest32,
    pub(crate) channel_policy_fingerprint: Digest32,
    pub(crate) controller_key_fingerprint: Digest32,
    pub(crate) tenure_nonces: Vec<ReplayLedgerRecord>,
    pub(crate) request_nonces: Vec<ReplayLedgerRecord>,
    pub(crate) temporal_lineages: Vec<TemporalLineageRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WriterFenceRecord {
    pub(crate) source_scope: Ref16,
    pub(crate) writer: Ref16,
    pub(crate) epoch: u64,
    pub(crate) proof_envelope_digest: Digest32,
    pub(crate) tenure_nonce_identity: Digest32,
    pub(crate) principal: Ref16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceRevisionHighWater {
    pub(crate) source_scope: Ref16,
    pub(crate) revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum JournalActionKind {
    StartOneSourceLoop = 1,
    DrainToEmpty = 2,
    RestartReassembly = 3,
}

impl JournalActionKind {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::StartOneSourceLoop),
            2 => Ok(Self::DrainToEmpty),
            3 => Ok(Self::RestartReassembly),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalActionRef {
    pub(crate) action_id: Ref16,
    pub(crate) kind: JournalActionKind,
    pub(crate) runtime_host_epoch: u64,
    pub(crate) clock_generation: u64,
    pub(crate) domain_generation: u64,
    pub(crate) instance_generation: u64,
    pub(crate) resource_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CallbackOutcome {
    NotInvoked = 1,
    KnownSuccess = 2,
    KnownError = 3,
    Panicked = 4,
    UnknownAfterIntent = 5,
}

impl CallbackOutcome {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::NotInvoked),
            2 => Ok(Self::KnownSuccess),
            3 => Ok(Self::KnownError),
            4 => Ok(Self::Panicked),
            5 => Ok(Self::UnknownAfterIntent),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum DeadlineOutcome {
    NotObserved = 1,
    TimedOut = 2,
    Cancelled = 3,
}

impl DeadlineOutcome {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::NotObserved),
            2 => Ok(Self::TimedOut),
            3 => Ok(Self::Cancelled),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CleanupOutcome {
    NotObserved = 1,
    ExactZero = 2,
    Uncertain = 3,
}

impl CleanupOutcome {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::NotObserved),
            2 => Ok(Self::ExactZero),
            3 => Ok(Self::Uncertain),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawActionOutcomeLatch {
    pub(crate) callback: CallbackOutcome,
    pub(crate) callback_reason_digest: Option<Digest32>,
    pub(crate) deadline: DeadlineOutcome,
    pub(crate) observed_clock_generation: u64,
    pub(crate) observed_at_nanos: u64,
    pub(crate) host_interrupted: bool,
    pub(crate) higher_tenure_takeover: bool,
    pub(crate) cleanup: CleanupOutcome,
    pub(crate) cleanup_evidence_digest: Option<Digest32>,
}

impl RawActionOutcomeLatch {
    fn validate(self) -> Result<(), RuntimeJournalError> {
        match (self.callback, self.callback_reason_digest) {
            (CallbackOutcome::KnownError | CallbackOutcome::Panicked, Some(digest)) => {
                ensure_nonzero_digest(&digest)?;
            }
            (CallbackOutcome::KnownError | CallbackOutcome::Panicked, None) => {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            (_, None) => {}
            (_, Some(_)) => return Err(RuntimeJournalError::InvalidStateInvariant),
        }
        match self.deadline {
            DeadlineOutcome::NotObserved => {
                if self.observed_clock_generation != 0 || self.observed_at_nanos != 0 {
                    return Err(RuntimeJournalError::InvalidStateInvariant);
                }
            }
            DeadlineOutcome::TimedOut | DeadlineOutcome::Cancelled => {
                if self.observed_clock_generation == 0 || self.observed_at_nanos == 0 {
                    return Err(RuntimeJournalError::InvalidStateInvariant);
                }
            }
        }
        if self.deadline == DeadlineOutcome::Cancelled
            && !self.host_interrupted
            && !self.higher_tenure_takeover
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        match (self.cleanup, self.cleanup_evidence_digest) {
            (CleanupOutcome::NotObserved, None) => {}
            (CleanupOutcome::ExactZero | CleanupOutcome::Uncertain, Some(digest)) => {
                ensure_nonzero_digest(&digest)?;
            }
            _ => return Err(RuntimeJournalError::InvalidStateInvariant),
        }
        Ok(())
    }

    fn preserves(self, previous: Self) -> bool {
        self.callback == previous.callback
            && option_fact_preserved(self.callback_reason_digest, previous.callback_reason_digest)
            && (previous.deadline == DeadlineOutcome::NotObserved
                || (self.deadline == previous.deadline
                    && self.observed_clock_generation == previous.observed_clock_generation
                    && self.observed_at_nanos == previous.observed_at_nanos))
            && (!previous.host_interrupted || self.host_interrupted)
            && (!previous.higher_tenure_takeover || self.higher_tenure_takeover)
            && fact_preserved(self.cleanup as u8, previous.cleanup as u8)
            && option_fact_preserved(
                self.cleanup_evidence_digest,
                previous.cleanup_evidence_digest,
            )
    }
}

fn fact_preserved(current: u8, previous: u8) -> bool {
    previous == 1 || current == previous
}

fn option_fact_preserved(current: Option<Digest32>, previous: Option<Digest32>) -> bool {
    previous.is_none() || current == previous
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum PreparedPhase {
    PreparedNoEffects = 1,
    FirstActionIntent = 2,
    HeadCommittedRetiringOld = 3,
    SupersededBeforeEffects = 4,
    SupersededReconcileRequired = 5,
    StartupExpiredNoEffects = 6,
    StartupReconcileRequired = 7,
}

impl PreparedPhase {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::PreparedNoEffects),
            2 => Ok(Self::FirstActionIntent),
            3 => Ok(Self::HeadCommittedRetiringOld),
            4 => Ok(Self::SupersededBeforeEffects),
            5 => Ok(Self::SupersededReconcileRequired),
            6 => Ok(Self::StartupExpiredNoEffects),
            7 => Ok(Self::StartupReconcileRequired),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }

    fn requires_action(self) -> bool {
        matches!(
            self,
            Self::FirstActionIntent
                | Self::HeadCommittedRetiringOld
                | Self::SupersededReconcileRequired
                | Self::StartupReconcileRequired
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedActiveCas {
    None,
    Exact(TargetSliceDigest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetiringLiveFacts {
    pub(crate) old_slice: OpaqueCanonicalValue,
    pub(crate) old_source_plan_digest: SourcePlanDigest,
    pub(crate) old_manifest_digest: Digest32,
    pub(crate) signed_start_budget_nanos: u64,
    pub(crate) signed_drain_budget_nanos: u64,
    pub(crate) signed_cleanup_budget_nanos: u64,
    pub(crate) old_runtime_host_epoch: u64,
    pub(crate) old_clock_generation: u64,
    pub(crate) old_resource_generation: u64,
    pub(crate) old_resource_census_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedOperation {
    pub(crate) source_scope: Ref16,
    pub(crate) operation_id: Ref16,
    pub(crate) source_revision: u64,
    pub(crate) request: OpaqueCanonicalValue,
    // The request is the sole copy of the exact Slice. These owner-owned
    // commitments are cross-checks supplied by the future S7-E strict request
    // decoder, not a second independently mutable Slice body.
    pub(crate) request_nonce_identity: Digest32,
    pub(crate) source_plan_digest: SourcePlanDigest,
    pub(crate) incoming_slice_digest: TargetSliceDigest,
    pub(crate) incoming_kind: DesiredHeadKind,
    pub(crate) manifest_digest: Digest32,
    pub(crate) expected_active: ExpectedActiveCas,
    pub(crate) temporal_constraint_id: Ref16,
    pub(crate) temporal_lineage_digest: Digest32,
    pub(crate) installed_clock_generation: u64,
    pub(crate) installed_deadline_nanos: u64,
    pub(crate) phase: PreparedPhase,
    pub(crate) action: Option<JournalActionRef>,
    pub(crate) retiring: Option<RetiringLiveFacts>,
    pub(crate) raw_outcome: Option<RawActionOutcomeLatch>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum DesiredHeadKind {
    OneSourceLoop = 1,
    EmptyDeactivate = 2,
}

impl DesiredHeadKind {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::OneSourceLoop),
            2 => Ok(Self::EmptyDeactivate),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveDesiredHead {
    pub(crate) kind: DesiredHeadKind,
    pub(crate) source_scope: Ref16,
    pub(crate) source_revision: u64,
    pub(crate) slice: OpaqueCanonicalValue,
    pub(crate) source_plan_digest: SourcePlanDigest,
    pub(crate) manifest_digest: Digest32,
    pub(crate) operation_id: Ref16,
    pub(crate) committing_result_digest: Option<Digest32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum StartupRecoveryEligibility {
    NoActiveHead = 1,
    CanonicalEmptyExactZero = 2,
    EligibleOneSourceLoop = 3,
    RecoveryFailureLatched = 4,
    ReconcileRequired = 5,
}

impl StartupRecoveryEligibility {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::NoActiveHead),
            2 => Ok(Self::CanonicalEmptyExactZero),
            3 => Ok(Self::EligibleOneSourceLoop),
            4 => Ok(Self::RecoveryFailureLatched),
            5 => Ok(Self::ReconcileRequired),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveMaterialization {
    None,
    StartupInvalidated {
        active_slice_digest: Option<TargetSliceDigest>,
        previous_runtime_host_epoch: u64,
        previous_clock_generation: u64,
        recovery_eligibility: StartupRecoveryEligibility,
        invalidation_evidence_digest: Digest32,
        failure_evidence_digest: Option<Digest32>,
        resource_census_digest: Digest32,
    },
    Recovering {
        active_slice_digest: TargetSliceDigest,
        action_id: Ref16,
        resource_generation: u64,
        resource_census_digest: Digest32,
    },
    LiveReady {
        active_slice_digest: TargetSliceDigest,
        runtime_host_epoch: u64,
        resource_generation: u64,
        resource_census_digest: Digest32,
    },
    RecoveryFailedNotReady {
        active_slice_digest: TargetSliceDigest,
        terminal_recovery_action_id: Ref16,
        failure_latch_digest: Digest32,
        resource_census_digest: Digest32,
    },
    Draining {
        active_slice_digest: TargetSliceDigest,
        operation_id: Ref16,
        action_id: Ref16,
        retiring_generation: u64,
        resource_census_digest: Digest32,
    },
    ExactZero {
        active_slice_digest: TargetSliceDigest,
        census_digest: Digest32,
    },
    Quarantined {
        active_slice_digest: Option<TargetSliceDigest>,
        reason_digest: Digest32,
        resource_census_digest: Digest32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum RecoveryPhase {
    RecoveryPlannedNoEffects = 1,
    StartCallIntent = 2,
    StartupInvalidatedNoEffects = 3,
    StartupReconcileRequired = 4,
}

impl RecoveryPhase {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::RecoveryPlannedNoEffects),
            2 => Ok(Self::StartCallIntent),
            3 => Ok(Self::StartupInvalidatedNoEffects),
            4 => Ok(Self::StartupReconcileRequired),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryAction {
    pub(crate) action: JournalActionRef,
    pub(crate) source_scope: Ref16,
    pub(crate) source_revision: u64,
    pub(crate) source_plan_digest: SourcePlanDigest,
    pub(crate) active_slice_digest: TargetSliceDigest,
    pub(crate) manifest_digest: Digest32,
    pub(crate) store_pinned_build_identity_digest: Digest32,
    pub(crate) compiled_build_instance_id: [u8; 32],
    pub(crate) compiled_compatibility_digest: Digest32,
    pub(crate) signed_start_budget_nanos: u64,
    pub(crate) deadline_nanos: u64,
    pub(crate) deadline_evidence_digest: Digest32,
    pub(crate) phase: RecoveryPhase,
    pub(crate) raw_outcome: Option<RawActionOutcomeLatch>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryTerminalRecord {
    pub(crate) recovery: RecoveryAction,
    pub(crate) selection: TerminalOutcomeSelection,
    pub(crate) resource_census_digest: Digest32,
    pub(crate) failure_latch_digest: Option<Digest32>,
    pub(crate) completion_runtime_host_epoch: u64,
    pub(crate) completion_snapshot_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum ResourceKind {
    LoopDomain = 1,
    CardInstance = 2,
    ResourceSlot = 3,
    ExternalHandle = 4,
}

impl ResourceKind {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::LoopDomain),
            2 => Ok(Self::CardInstance),
            3 => Ok(Self::ResourceSlot),
            4 => Ok(Self::ExternalHandle),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum ResourcePhase {
    Reserved = 1,
    Owned = 2,
    CleanupPending = 3,
    Terminal = 4,
}

impl ResourcePhase {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::Reserved),
            2 => Ok(Self::Owned),
            3 => Ok(Self::CleanupPending),
            4 => Ok(Self::Terminal),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }

    fn is_terminal(self) -> bool {
        self == Self::Terminal
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnedResourceRecord {
    pub(crate) kind: ResourceKind,
    pub(crate) logical_ref: Ref16,
    pub(crate) generation: u64,
    pub(crate) runtime_host_epoch: u64,
    pub(crate) phase: ResourcePhase,
    pub(crate) action_id: Option<Ref16>,
    pub(crate) os_identity: Option<OpaqueCanonicalValue>,
    pub(crate) workspace_identity: Option<OpaqueCanonicalValue>,
    pub(crate) containment_identity: Option<OpaqueCanonicalValue>,
    pub(crate) tombstone_evidence: Option<OpaqueCanonicalValue>,
}

impl OwnedResourceRecord {
    fn key(&self) -> (ResourceKind, Ref16, u64) {
        (self.kind, self.logical_ref, self.generation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum TerminalOutcome {
    OneSourceLoopActive = 1,
    EmptyDeactivateExactZero = 2,
    StartTimedOutBeforeIntentNoEffects = 3,
    StopTimedOutBeforeHeadCommitNoEffects = 4,
    StartFailedBeforeHeadCommitExactZero = 5,
    StartTimedOutBeforeHeadCommitExactZero = 6,
    StopFailedButExactZero = 7,
    TimedOutButExactZero = 8,
    AbortedBeforeIntentNoEffects = 9,
    AbortedBeforeHeadCommitExactZero = 10,
    SupersededAfterIntentExactZero = 11,
    InterruptedButNowExactZero = 12,
}

impl TerminalOutcome {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::OneSourceLoopActive),
            2 => Ok(Self::EmptyDeactivateExactZero),
            3 => Ok(Self::StartTimedOutBeforeIntentNoEffects),
            4 => Ok(Self::StopTimedOutBeforeHeadCommitNoEffects),
            5 => Ok(Self::StartFailedBeforeHeadCommitExactZero),
            6 => Ok(Self::StartTimedOutBeforeHeadCommitExactZero),
            7 => Ok(Self::StopFailedButExactZero),
            8 => Ok(Self::TimedOutButExactZero),
            9 => Ok(Self::AbortedBeforeIntentNoEffects),
            10 => Ok(Self::AbortedBeforeHeadCommitExactZero),
            11 => Ok(Self::SupersededAfterIntentExactZero),
            12 => Ok(Self::InterruptedButNowExactZero),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum TerminalLifecycleEffect {
    ProvenNotStarted = 1,
    MayHaveStarted = 2,
}

impl TerminalLifecycleEffect {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::ProvenNotStarted),
            2 => Ok(Self::MayHaveStarted),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalHeadDisposition {
    Preserved(Option<TargetSliceDigest>),
    CommittedIncoming,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TerminalOutcomeSelection {
    pub(crate) primary: TerminalOutcome,
    pub(crate) raw: RawActionOutcomeLatch,
    pub(crate) selection_clock_generation: u64,
    pub(crate) selection_observed_at_nanos: u64,
    pub(crate) lifecycle_effect: TerminalLifecycleEffect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalSelectionContext {
    incoming_kind: DesiredHeadKind,
    predecessor_phase: PreparedPhase,
    installed_clock_generation: u64,
    installed_deadline_nanos: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalSelectionObservation {
    raw: RawActionOutcomeLatch,
    selection_clock_generation: u64,
    selection_observed_at_nanos: u64,
    lifecycle_effect: TerminalLifecycleEffect,
}

impl TerminalOutcomeSelection {
    fn try_select(
        context: TerminalSelectionContext,
        observation: TerminalSelectionObservation,
    ) -> Result<Self, RuntimeJournalError> {
        let TerminalSelectionContext {
            incoming_kind,
            predecessor_phase,
            installed_clock_generation,
            installed_deadline_nanos,
        } = context;
        let TerminalSelectionObservation {
            raw,
            selection_clock_generation,
            selection_observed_at_nanos,
            lifecycle_effect,
        } = observation;
        raw.validate()?;
        if installed_clock_generation == 0
            || installed_deadline_nanos == 0
            || selection_clock_generation == 0
            || selection_clock_generation < installed_clock_generation
            || selection_observed_at_nanos == 0
            || raw.cleanup == CleanupOutcome::Uncertain
            || raw.callback == CallbackOutcome::Panicked
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        if raw.deadline == DeadlineOutcome::TimedOut
            && (raw.observed_clock_generation != installed_clock_generation
                || raw.observed_at_nanos < installed_deadline_nanos)
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        if raw.deadline == DeadlineOutcome::Cancelled
            && !raw.host_interrupted
            && !raw.higher_tenure_takeover
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        if !raw.host_interrupted
            && !raw.higher_tenure_takeover
            && selection_clock_generation != installed_clock_generation
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        let deadline_reached = raw.deadline == DeadlineOutcome::TimedOut
            || (selection_clock_generation == installed_clock_generation
                && selection_observed_at_nanos >= installed_deadline_nanos);
        let before_effects = matches!(
            predecessor_phase,
            PreparedPhase::PreparedNoEffects
                | PreparedPhase::SupersededBeforeEffects
                | PreparedPhase::StartupExpiredNoEffects
        );
        let primary = if before_effects {
            if lifecycle_effect != TerminalLifecycleEffect::ProvenNotStarted
                || raw.callback != CallbackOutcome::NotInvoked
                || raw.cleanup != CleanupOutcome::NotObserved
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            match predecessor_phase {
                PreparedPhase::SupersededBeforeEffects if raw.higher_tenure_takeover => {
                    TerminalOutcome::AbortedBeforeIntentNoEffects
                }
                PreparedPhase::StartupExpiredNoEffects if raw.host_interrupted => {
                    TerminalOutcome::AbortedBeforeIntentNoEffects
                }
                PreparedPhase::PreparedNoEffects if deadline_reached => match incoming_kind {
                    DesiredHeadKind::OneSourceLoop => {
                        TerminalOutcome::StartTimedOutBeforeIntentNoEffects
                    }
                    DesiredHeadKind::EmptyDeactivate => {
                        TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects
                    }
                },
                PreparedPhase::PreparedNoEffects
                    if incoming_kind == DesiredHeadKind::EmptyDeactivate
                        && raw.deadline == DeadlineOutcome::NotObserved
                        && !raw.host_interrupted
                        && !raw.higher_tenure_takeover =>
                {
                    TerminalOutcome::EmptyDeactivateExactZero
                }
                _ => return Err(RuntimeJournalError::InvalidStateInvariant),
            }
        } else {
            let exact_zero_or_success = match incoming_kind {
                DesiredHeadKind::OneSourceLoop => {
                    if raw.higher_tenure_takeover {
                        TerminalOutcome::SupersededAfterIntentExactZero
                    } else if raw.host_interrupted {
                        TerminalOutcome::AbortedBeforeHeadCommitExactZero
                    } else if deadline_reached {
                        TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero
                    } else if raw.callback == CallbackOutcome::KnownError {
                        TerminalOutcome::StartFailedBeforeHeadCommitExactZero
                    } else if raw.callback == CallbackOutcome::KnownSuccess
                        && raw.deadline == DeadlineOutcome::NotObserved
                    {
                        TerminalOutcome::OneSourceLoopActive
                    } else {
                        return Err(RuntimeJournalError::InvalidStateInvariant);
                    }
                }
                DesiredHeadKind::EmptyDeactivate => {
                    if raw.higher_tenure_takeover {
                        TerminalOutcome::SupersededAfterIntentExactZero
                    } else if raw.host_interrupted {
                        TerminalOutcome::InterruptedButNowExactZero
                    } else if deadline_reached {
                        TerminalOutcome::TimedOutButExactZero
                    } else if raw.callback == CallbackOutcome::KnownError {
                        TerminalOutcome::StopFailedButExactZero
                    } else if raw.callback == CallbackOutcome::KnownSuccess
                        && raw.deadline == DeadlineOutcome::NotObserved
                    {
                        TerminalOutcome::EmptyDeactivateExactZero
                    } else {
                        return Err(RuntimeJournalError::InvalidStateInvariant);
                    }
                }
            };
            if exact_zero_or_success == TerminalOutcome::OneSourceLoopActive {
                if lifecycle_effect != TerminalLifecycleEffect::MayHaveStarted
                    || raw.cleanup != CleanupOutcome::NotObserved
                {
                    return Err(RuntimeJournalError::InvalidStateInvariant);
                }
            } else {
                match lifecycle_effect {
                    TerminalLifecycleEffect::MayHaveStarted
                        if raw.cleanup != CleanupOutcome::ExactZero =>
                    {
                        return Err(RuntimeJournalError::InvalidStateInvariant);
                    }
                    TerminalLifecycleEffect::ProvenNotStarted
                        if raw.callback != CallbackOutcome::NotInvoked
                            || raw.cleanup != CleanupOutcome::NotObserved =>
                    {
                        return Err(RuntimeJournalError::InvalidStateInvariant);
                    }
                    _ => {}
                }
            }
            exact_zero_or_success
        };
        Ok(Self {
            primary,
            raw,
            selection_clock_generation,
            selection_observed_at_nanos,
            lifecycle_effect,
        })
    }

    fn validate(
        self,
        incoming_kind: DesiredHeadKind,
        predecessor_phase: PreparedPhase,
        installed_clock_generation: u64,
        installed_deadline_nanos: u64,
    ) -> Result<(), RuntimeJournalError> {
        if Self::try_select(
            TerminalSelectionContext {
                incoming_kind,
                predecessor_phase,
                installed_clock_generation,
                installed_deadline_nanos,
            },
            TerminalSelectionObservation {
                raw: self.raw,
                selection_clock_generation: self.selection_clock_generation,
                selection_observed_at_nanos: self.selection_observed_at_nanos,
                lifecycle_effect: self.lifecycle_effect,
            },
        )? != self
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TerminalOperationRecord {
    pub(crate) source_scope: Ref16,
    pub(crate) operation_id: Ref16,
    pub(crate) request_digest: Digest32,
    pub(crate) request_nonce_identity: Digest32,
    pub(crate) source_revision: u64,
    pub(crate) source_plan_digest: SourcePlanDigest,
    pub(crate) target_slice_digest: TargetSliceDigest,
    pub(crate) temporal_constraint_id: Ref16,
    pub(crate) temporal_lineage_digest: Digest32,
    pub(crate) incoming_kind: DesiredHeadKind,
    pub(crate) completion_predecessor_phase: PreparedPhase,
    pub(crate) installed_clock_generation: u64,
    pub(crate) installed_deadline_nanos: u64,
    pub(crate) action: Option<JournalActionRef>,
    pub(crate) predecessor_raw_outcome: Option<RawActionOutcomeLatch>,
    pub(crate) selection: TerminalOutcomeSelection,
    pub(crate) head_disposition: TerminalHeadDisposition,
    pub(crate) resource_census_digest: Digest32,
    pub(crate) result_digest: Digest32,
    pub(crate) canonical_response: OpaqueCanonicalValue,
    pub(crate) completion_runtime_host_epoch: u64,
    pub(crate) completion_snapshot_sequence: u64,
}

impl TerminalOperationRecord {
    fn key(&self) -> (Ref16, Ref16) {
        (self.source_scope, self.operation_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum RuntimeJournalTransaction {
    Initialized = 1,
    StartupInvalidation = 2,
    TenureOnly = 3,
    FullAdmission = 4,
    PreparedProgress = 5,
    ResourceProgress = 6,
    NormalStartTerminal = 7,
    EmptyHeadRetire = 8,
    ExactZeroTerminal = 9,
    RecoveryPlan = 10,
    RecoveryProgress = 11,
    RecoveryPublish = 12,
    OperationTerminalNoEffects = 13,
    Quarantine = 14,
    RecoveryAbortNoEffects = 15,
}

impl RuntimeJournalTransaction {
    fn decode(value: u8) -> Result<Self, RuntimeJournalError> {
        match value {
            1 => Ok(Self::Initialized),
            2 => Ok(Self::StartupInvalidation),
            3 => Ok(Self::TenureOnly),
            4 => Ok(Self::FullAdmission),
            5 => Ok(Self::PreparedProgress),
            6 => Ok(Self::ResourceProgress),
            7 => Ok(Self::NormalStartTerminal),
            8 => Ok(Self::EmptyHeadRetire),
            9 => Ok(Self::ExactZeroTerminal),
            10 => Ok(Self::RecoveryPlan),
            11 => Ok(Self::RecoveryProgress),
            12 => Ok(Self::RecoveryPublish),
            13 => Ok(Self::OperationTerminalNoEffects),
            14 => Ok(Self::Quarantine),
            15 => Ok(Self::RecoveryAbortNoEffects),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeJournalState {
    pub(crate) last_transaction: RuntimeJournalTransaction,
    pub(crate) host: HostClockAdmissionState,
    pub(crate) writer_fence: Option<WriterFenceRecord>,
    pub(crate) source_revision_high_water: Option<SourceRevisionHighWater>,
    pub(crate) prepared: Option<PreparedOperation>,
    pub(crate) active_desired: Option<ActiveDesiredHead>,
    pub(crate) live_materialization: LiveMaterialization,
    pub(crate) recovery_action: Option<RecoveryAction>,
    pub(crate) recovery_terminals: Vec<RecoveryTerminalRecord>,
    pub(crate) owned_resources: Vec<OwnedResourceRecord>,
    pub(crate) terminal_operations: Vec<TerminalOperationRecord>,
}

impl RuntimeJournalState {
    pub(crate) fn validate(&self, snapshot_sequence: u64) -> Result<(), RuntimeJournalError> {
        if snapshot_sequence == 0 {
            return Err(RuntimeJournalError::InvalidSequence);
        }
        let is_initial_snapshot = snapshot_sequence == 1;
        if is_initial_snapshot != (self.last_transaction == RuntimeJournalTransaction::Initialized)
            || is_initial_snapshot
                != (self.host.runtime_host_epoch_high_water == 0
                    && self.host.clock_generation_high_water == 0)
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        self.validate_host()?;
        self.validate_scope_and_high_water()?;
        self.validate_actions()?;
        self.validate_producer_generations()?;
        self.validate_resources()?;
        self.validate_terminals(snapshot_sequence)?;
        self.validate_recovery_terminals(snapshot_sequence)?;
        self.validate_global_completion_chronology()?;
        self.validate_live_cross_references()?;
        self.validate_terminal_head_chain()?;
        Ok(())
    }

    fn validate_host(&self) -> Result<(), RuntimeJournalError> {
        ensure_nonzero_ref(&self.host.clock_domain)?;
        self.host
            .build_descriptor
            .validate_bound(MAX_PINNED_OPAQUE_ARTIFACT_BYTES)?;
        self.host
            .singleton_manifest
            .validate_bound(MAX_PINNED_OPAQUE_ARTIFACT_BYTES)?;
        self.host
            .store_pinned_build_identity
            .validate_bound(MAX_PINNED_OPAQUE_ARTIFACT_BYTES)?;
        if self
            .host
            .compiled_build_instance_id
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(RuntimeJournalError::ZeroReference);
        }
        ensure_nonzero_digest(&self.host.compiled_compatibility_digest)?;
        ensure_nonzero_digest(&self.host.admission_policy_fingerprint)?;
        ensure_nonzero_digest(&self.host.channel_policy_fingerprint)?;
        ensure_nonzero_digest(&self.host.controller_key_fingerprint)?;
        if (self.host.runtime_host_epoch_high_water == 0)
            != (self.host.clock_generation_high_water == 0)
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        validate_replay_records(&self.host.tenure_nonces, MAX_RUNTIME_TENURE_NONCES)?;
        validate_replay_records(&self.host.request_nonces, MAX_RUNTIME_REQUEST_NONCES)?;
        validate_temporal_records(
            &self.host.temporal_lineages,
            self.host.clock_generation_high_water,
        )?;
        if self.host.runtime_host_epoch_high_water == 0
            && (self.writer_fence.is_some()
                || self.source_revision_high_water.is_some()
                || self.prepared.is_some()
                || self.active_desired.is_some()
                || !matches!(self.live_materialization, LiveMaterialization::None)
                || self.recovery_action.is_some()
                || !self.recovery_terminals.is_empty()
                || !self.owned_resources.is_empty()
                || !self.terminal_operations.is_empty()
                || !self.host.tenure_nonces.is_empty()
                || !self.host.request_nonces.is_empty()
                || !self.host.temporal_lineages.is_empty())
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        Ok(())
    }

    fn validate_owner_target_binding(
        &self,
        owner_target_fingerprint: &Digest32,
    ) -> Result<(), RuntimeJournalError> {
        if self
            .host
            .temporal_lineages
            .iter()
            .any(|lineage| lineage.target_fingerprint != *owner_target_fingerprint)
        {
            return Err(RuntimeJournalError::DanglingReference);
        }
        Ok(())
    }

    fn validate_scope_and_high_water(&self) -> Result<(), RuntimeJournalError> {
        let mut scope = None;
        if let Some(fence) = self.writer_fence {
            if fence.epoch == 0 {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            ensure_nonzero_ref(&fence.writer)?;
            ensure_nonzero_ref(&fence.principal)?;
            ensure_nonzero_digest(&fence.proof_envelope_digest)?;
            ensure_nonzero_digest(&fence.tenure_nonce_identity)?;
            if !self.host.tenure_nonces.iter().any(|record| {
                record.identity == fence.tenure_nonce_identity
                    && record.value_digest == fence.proof_envelope_digest
            }) {
                return Err(RuntimeJournalError::DanglingReference);
            }
            observe_scope(&mut scope, fence.source_scope)?;
        } else if !self.host.tenure_nonces.is_empty() {
            return Err(RuntimeJournalError::DanglingReference);
        }
        if let Some(high_water) = self.source_revision_high_water {
            if high_water.revision == 0 {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            observe_scope(&mut scope, high_water.source_scope)?;
        }
        for temporal in &self.host.temporal_lineages {
            ensure_nonzero_ref(&temporal.constraint_id)?;
            observe_scope(&mut scope, temporal.source_scope)?;
        }
        if let Some(prepared) = &self.prepared {
            ensure_nonzero_ref(&prepared.operation_id)?;
            observe_scope(&mut scope, prepared.source_scope)?;
            let Some(high_water) = self.source_revision_high_water else {
                return Err(RuntimeJournalError::DanglingReference);
            };
            if prepared.source_revision == 0 || prepared.source_revision != high_water.revision {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            if self.writer_fence.is_none() {
                return Err(RuntimeJournalError::DanglingReference);
            }
            prepared.validate(
                &self.host.singleton_manifest.digest,
                &self.host.request_nonces,
                &self.host.temporal_lineages,
            )?;
            if matches!(
                prepared.phase,
                PreparedPhase::PreparedNoEffects
                    | PreparedPhase::FirstActionIntent
                    | PreparedPhase::HeadCommittedRetiringOld
            ) && prepared.installed_clock_generation != self.host.clock_generation_high_water
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
        }
        if let Some(active) = &self.active_desired {
            ensure_nonzero_ref(&active.operation_id)?;
            observe_scope(&mut scope, active.source_scope)?;
            let Some(high_water) = self.source_revision_high_water else {
                return Err(RuntimeJournalError::DanglingReference);
            };
            if active.source_revision == 0 || active.source_revision > high_water.revision {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            if self.writer_fence.is_none() {
                return Err(RuntimeJournalError::DanglingReference);
            }
            active.validate(&self.host.singleton_manifest.digest)?;
        }
        for terminal in &self.terminal_operations {
            ensure_nonzero_ref(&terminal.operation_id)?;
            ensure_nonzero_ref(&terminal.temporal_constraint_id)?;
            observe_scope(&mut scope, terminal.source_scope)?;
        }
        for terminal in &self.recovery_terminals {
            observe_scope(&mut scope, terminal.recovery.source_scope)?;
        }
        if let Some(recovery) = self.recovery_action {
            observe_scope(&mut scope, recovery.source_scope)?;
            let high_water = self
                .source_revision_high_water
                .ok_or(RuntimeJournalError::DanglingReference)?;
            if recovery.source_scope != high_water.source_scope
                || recovery.source_revision > high_water.revision
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
        }
        if !self.terminal_operations.is_empty()
            && (self.source_revision_high_water.is_none() || self.writer_fence.is_none())
        {
            return Err(RuntimeJournalError::DanglingReference);
        }
        self.validate_admission_cross_references()?;
        Ok(())
    }

    fn validate_actions(&self) -> Result<(), RuntimeJournalError> {
        let prepared_action = self.prepared.as_ref().and_then(|value| value.action);
        if let Some(prepared) = &self.prepared {
            if prepared.phase.requires_action() != prepared.action.is_some() {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            if let Some(action) = prepared.action {
                if action.kind == JournalActionKind::RestartReassembly {
                    return Err(RuntimeJournalError::InvalidStateInvariant);
                }
                let phase_kind_is_valid = match prepared.phase {
                    PreparedPhase::FirstActionIntent => {
                        action.kind == JournalActionKind::StartOneSourceLoop
                    }
                    PreparedPhase::HeadCommittedRetiringOld => {
                        action.kind == JournalActionKind::DrainToEmpty
                    }
                    PreparedPhase::SupersededReconcileRequired => matches!(
                        action.kind,
                        JournalActionKind::StartOneSourceLoop | JournalActionKind::DrainToEmpty
                    ),
                    PreparedPhase::StartupReconcileRequired => matches!(
                        action.kind,
                        JournalActionKind::StartOneSourceLoop | JournalActionKind::DrainToEmpty
                    ),
                    PreparedPhase::PreparedNoEffects
                    | PreparedPhase::SupersededBeforeEffects
                    | PreparedPhase::StartupExpiredNoEffects => false,
                };
                if !phase_kind_is_valid {
                    return Err(RuntimeJournalError::InvalidStateInvariant);
                }
                validate_action(action, &self.host)?;
                let host_interrupted = prepared.raw_outcome.is_some_and(|raw| raw.host_interrupted);
                if action.clock_generation != prepared.installed_clock_generation
                    || (host_interrupted
                        && (action.runtime_host_epoch >= self.host.runtime_host_epoch_high_water
                            || action.clock_generation >= self.host.clock_generation_high_water))
                    || (!host_interrupted
                        && (action.runtime_host_epoch != self.host.runtime_host_epoch_high_water
                            || action.clock_generation != self.host.clock_generation_high_water))
                {
                    return Err(RuntimeJournalError::InvalidStateInvariant);
                }
            }
        }
        if let Some(recovery) = self.recovery_action {
            recovery.validate(&self.host, self.active_desired.as_ref())?;
        }
        if prepared_action.is_some() && self.recovery_action.is_some() {
            return Err(RuntimeJournalError::MultipleOwnerActions);
        }
        let mut action_ids = std::collections::BTreeSet::new();
        for action in self
            .terminal_operations
            .iter()
            .filter_map(|terminal| terminal.action)
            .chain(
                self.recovery_terminals
                    .iter()
                    .map(|terminal| terminal.recovery.action),
            )
            .chain(prepared_action)
            .chain(self.recovery_action.map(|recovery| recovery.action))
        {
            if !action_ids.insert(action.action_id) {
                return Err(RuntimeJournalError::MultipleOwnerActions);
            }
        }
        Ok(())
    }

    fn validate_producer_generations(&self) -> Result<(), RuntimeJournalError> {
        let mut completed = self
            .terminal_operations
            .iter()
            .filter_map(|terminal| {
                terminal
                    .action
                    .filter(|action| action.kind == JournalActionKind::StartOneSourceLoop)
                    .map(|action| (terminal.completion_snapshot_sequence, action))
            })
            .chain(self.recovery_terminals.iter().map(|terminal| {
                (
                    terminal.completion_snapshot_sequence,
                    terminal.recovery.action,
                )
            }))
            .collect::<Vec<_>>();
        completed.sort_unstable_by_key(|(sequence, _)| *sequence);
        let mut high_water = None;
        for (_, action) in completed {
            if high_water.is_some_and(|previous: (u64, u64, u64)| {
                action.domain_generation <= previous.0
                    || action.instance_generation <= previous.1
                    || action.resource_generation <= previous.2
            }) {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            high_water = Some((
                action.domain_generation,
                action.instance_generation,
                action.resource_generation,
            ));
        }
        if let Some(action) = self.current_action().filter(|action| {
            matches!(
                action.kind,
                JournalActionKind::StartOneSourceLoop | JournalActionKind::RestartReassembly
            )
        }) && high_water.is_some_and(|previous| {
            action.domain_generation <= previous.0
                || action.instance_generation <= previous.1
                || action.resource_generation <= previous.2
        }) {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        Ok(())
    }

    fn validate_resources(&self) -> Result<(), RuntimeJournalError> {
        if self.owned_resources.len() > MAX_RUNTIME_OWNED_RESOURCES {
            return Err(RuntimeJournalError::CapacityExceeded);
        }
        let mut previous = None;
        let current_action = self.current_action();
        for resource in &self.owned_resources {
            ensure_nonzero_ref(&resource.logical_ref)?;
            if resource.generation == 0
                || resource.runtime_host_epoch == 0
                || resource.runtime_host_epoch > self.host.runtime_host_epoch_high_water
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            let key = resource.key();
            if previous.is_some_and(|value| value >= key) {
                return Err(RuntimeJournalError::NonCanonicalOrdering);
            }
            previous = Some(key);
            validate_resource_evidence(resource)?;
            if resource.phase.is_terminal() {
                if resource.action_id.is_some() {
                    return Err(RuntimeJournalError::DanglingReference);
                }
                continue;
            }
            if let Some(action_id) = resource.action_id {
                ensure_nonzero_ref(&action_id)?;
                if current_action.map(|action| action.action_id) != Some(action_id)
                    || current_action.map(|action| action.resource_generation)
                        != Some(resource.generation)
                    || current_action.map(|action| action.runtime_host_epoch)
                        != Some(resource.runtime_host_epoch)
                {
                    return Err(RuntimeJournalError::DanglingReference);
                }
            } else if !self.resource_belongs_to_live(resource) {
                return Err(RuntimeJournalError::DanglingReference);
            }
        }
        self.validate_reference_profile_census(current_action)?;
        Ok(())
    }

    fn validate_live_cross_references(&self) -> Result<(), RuntimeJournalError> {
        let nonterminal_resources = self
            .owned_resources
            .iter()
            .filter(|resource| !resource.phase.is_terminal())
            .count();
        let unbound_nonterminal_resources = self
            .owned_resources
            .iter()
            .filter(|resource| !resource.phase.is_terminal() && resource.action_id.is_none())
            .count();
        let resource_census_digest = compute_resource_census_digest(&self.owned_resources)?;
        match self.live_materialization {
            LiveMaterialization::None => {
                if self.active_desired.is_some()
                    || self.recovery_action.is_some()
                    || unbound_nonterminal_resources != 0
                {
                    return Err(RuntimeJournalError::DanglingReference);
                }
            }
            LiveMaterialization::StartupInvalidated {
                active_slice_digest,
                previous_runtime_host_epoch,
                previous_clock_generation,
                recovery_eligibility,
                invalidation_evidence_digest,
                failure_evidence_digest,
                resource_census_digest: recorded_census,
            } => {
                if previous_runtime_host_epoch >= self.host.runtime_host_epoch_high_water
                    || previous_clock_generation >= self.host.clock_generation_high_water
                    || recorded_census != resource_census_digest
                {
                    return Err(RuntimeJournalError::InvalidStateInvariant);
                }
                ensure_nonzero_digest(&invalidation_evidence_digest)?;
                match (active_slice_digest, self.active_desired.as_ref()) {
                    (None, None) => {}
                    (Some(expected), Some(active))
                        if expected == TargetSliceDigest::new(active.slice.digest) => {}
                    _ => return Err(RuntimeJournalError::DanglingReference),
                }
                match recovery_eligibility {
                    StartupRecoveryEligibility::NoActiveHead => {
                        if self.active_desired.is_some()
                            || failure_evidence_digest.is_some()
                            || nonterminal_resources != 0
                            || self.current_action().is_some()
                        {
                            return Err(RuntimeJournalError::InvalidStateInvariant);
                        }
                    }
                    StartupRecoveryEligibility::CanonicalEmptyExactZero => {
                        let active = self.expect_active(DesiredHeadKind::EmptyDeactivate)?;
                        if nonterminal_resources != 0
                            || failure_evidence_digest.is_some()
                            || self.current_action().is_some()
                        {
                            return Err(RuntimeJournalError::InvalidStateInvariant);
                        }
                        self.validate_active_commit_ref(active)?;
                    }
                    StartupRecoveryEligibility::EligibleOneSourceLoop => {
                        let active = self.expect_active(DesiredHeadKind::OneSourceLoop)?;
                        if failure_evidence_digest.is_some() {
                            return Err(RuntimeJournalError::InvalidStateInvariant);
                        }
                        self.validate_active_commit_ref(active)?;
                    }
                    StartupRecoveryEligibility::RecoveryFailureLatched => {
                        let active = self.expect_active(DesiredHeadKind::OneSourceLoop)?;
                        let failure_digest = failure_evidence_digest
                            .ok_or(RuntimeJournalError::DanglingReference)?;
                        ensure_nonzero_digest(&failure_digest)?;
                        let matching_failures = self
                            .recovery_terminals
                            .iter()
                            .filter(|terminal| {
                                terminal.failure_latch_digest == Some(failure_digest)
                                    && terminal.recovery.active_slice_digest
                                        == TargetSliceDigest::new(active.slice.digest)
                                    && terminal.recovery.source_scope == active.source_scope
                                    && terminal.recovery.source_revision == active.source_revision
                                    && terminal.recovery.source_plan_digest
                                        == active.source_plan_digest
                                    && terminal.resource_census_digest == recorded_census
                                    && terminal.selection.primary
                                        != TerminalOutcome::OneSourceLoopActive
                                    && terminal.selection.primary
                                        != TerminalOutcome::AbortedBeforeIntentNoEffects
                            })
                            .count();
                        if matching_failures != 1
                            || nonterminal_resources != 0
                            || self.current_action().is_some()
                        {
                            return Err(RuntimeJournalError::DanglingReference);
                        }
                        self.validate_active_commit_ref(active)?;
                    }
                    StartupRecoveryEligibility::ReconcileRequired => {
                        ensure_nonzero_digest(
                            &failure_evidence_digest
                                .ok_or(RuntimeJournalError::DanglingReference)?,
                        )?;
                    }
                }
            }
            LiveMaterialization::Recovering {
                active_slice_digest,
                action_id,
                resource_generation,
                resource_census_digest: recorded_census,
            } => {
                ensure_nonzero_ref(&action_id)?;
                let active = self.expect_active(DesiredHeadKind::OneSourceLoop)?;
                if TargetSliceDigest::new(active.slice.digest) != active_slice_digest
                    || resource_generation == 0
                    || recorded_census != resource_census_digest
                {
                    return Err(RuntimeJournalError::DanglingReference);
                }
                self.validate_active_commit_ref(active)?;
                let Some(recovery) = self.recovery_action else {
                    return Err(RuntimeJournalError::DanglingReference);
                };
                if recovery.action.action_id != action_id
                    || recovery.action.resource_generation != resource_generation
                {
                    return Err(RuntimeJournalError::DanglingReference);
                }
                if recovery.phase == RecoveryPhase::RecoveryPlannedNoEffects
                    && nonterminal_resources != 0
                {
                    return Err(RuntimeJournalError::InvalidStateInvariant);
                }
            }
            LiveMaterialization::LiveReady {
                active_slice_digest,
                runtime_host_epoch,
                resource_generation,
                resource_census_digest: recorded_census,
            } => {
                let active = self.expect_active(DesiredHeadKind::OneSourceLoop)?;
                if TargetSliceDigest::new(active.slice.digest) != active_slice_digest
                    || runtime_host_epoch != self.host.runtime_host_epoch_high_water
                    || resource_generation == 0
                    || recorded_census != resource_census_digest
                    || self.current_action().is_some()
                    || nonterminal_resources == 0
                    || self.owned_resources.iter().any(|resource| {
                        !resource.phase.is_terminal()
                            && (resource.phase != ResourcePhase::Owned
                                || resource.action_id.is_some()
                                || resource.generation != resource_generation
                                || resource.runtime_host_epoch != runtime_host_epoch)
                    })
                {
                    return Err(RuntimeJournalError::DanglingReference);
                }
                self.validate_active_commit_ref(active)?;
                self.validate_live_ready_producer(
                    active,
                    runtime_host_epoch,
                    resource_generation,
                    recorded_census,
                )?;
            }
            LiveMaterialization::RecoveryFailedNotReady {
                active_slice_digest,
                terminal_recovery_action_id,
                failure_latch_digest,
                resource_census_digest: recorded_census,
            } => {
                let active = self.expect_active(DesiredHeadKind::OneSourceLoop)?;
                ensure_nonzero_ref(&terminal_recovery_action_id)?;
                ensure_nonzero_digest(&failure_latch_digest)?;
                let matching_terminal = self
                    .recovery_terminals
                    .iter()
                    .filter(|terminal| {
                        terminal.recovery.action.action_id == terminal_recovery_action_id
                    })
                    .collect::<Vec<_>>();
                let [terminal] = matching_terminal.as_slice() else {
                    return Err(RuntimeJournalError::DanglingReference);
                };
                if TargetSliceDigest::new(active.slice.digest) != active_slice_digest
                    || nonterminal_resources != 0
                    || recorded_census != resource_census_digest
                    || self.current_action().is_some()
                    || terminal.recovery.active_slice_digest != active_slice_digest
                    || terminal.resource_census_digest != recorded_census
                    || terminal.failure_latch_digest != Some(failure_latch_digest)
                    || terminal.selection.primary == TerminalOutcome::OneSourceLoopActive
                    || match terminal.selection.lifecycle_effect {
                        TerminalLifecycleEffect::ProvenNotStarted => {
                            terminal.selection.raw.callback != CallbackOutcome::NotInvoked
                                || terminal.selection.raw.cleanup != CleanupOutcome::NotObserved
                        }
                        TerminalLifecycleEffect::MayHaveStarted => {
                            terminal.selection.raw.cleanup != CleanupOutcome::ExactZero
                        }
                    }
                {
                    return Err(RuntimeJournalError::DanglingReference);
                }
                self.validate_active_commit_ref(active)?;
            }
            LiveMaterialization::Draining {
                active_slice_digest,
                operation_id,
                action_id,
                retiring_generation,
                resource_census_digest: recorded_census,
            } => {
                ensure_nonzero_ref(&operation_id)?;
                ensure_nonzero_ref(&action_id)?;
                let active = self.expect_active(DesiredHeadKind::EmptyDeactivate)?;
                let Some(prepared) = &self.prepared else {
                    return Err(RuntimeJournalError::DanglingReference);
                };
                if TargetSliceDigest::new(active.slice.digest) != active_slice_digest
                    || prepared.operation_id != operation_id
                    || !matches!(
                        prepared.phase,
                        PreparedPhase::HeadCommittedRetiringOld
                            | PreparedPhase::SupersededReconcileRequired
                    )
                    || prepared.action.map(|value| value.action_id) != Some(action_id)
                    || prepared.action.map(|value| value.resource_generation)
                        != Some(retiring_generation)
                    || prepared
                        .retiring
                        .as_ref()
                        .map(|facts| facts.old_resource_generation)
                        != Some(retiring_generation)
                    || recorded_census != resource_census_digest
                    || !self.owned_resources.iter().any(|resource| {
                        !resource.phase.is_terminal()
                            && resource.action_id == Some(action_id)
                            && resource.generation == retiring_generation
                    })
                    || self.owned_resources.iter().any(|resource| {
                        !resource.phase.is_terminal()
                            && (resource.phase != ResourcePhase::CleanupPending
                                || resource.action_id != Some(action_id)
                                || resource.generation != retiring_generation
                                || resource.runtime_host_epoch
                                    != prepared
                                        .action
                                        .map(|action| action.runtime_host_epoch)
                                        .unwrap_or_default())
                    })
                {
                    return Err(RuntimeJournalError::DanglingReference);
                }
            }
            LiveMaterialization::ExactZero {
                active_slice_digest,
                census_digest,
            } => {
                let active = self.expect_active(DesiredHeadKind::EmptyDeactivate)?;
                if TargetSliceDigest::new(active.slice.digest) != active_slice_digest
                    || unbound_nonterminal_resources != 0
                    || census_digest != resource_census_digest
                {
                    return Err(RuntimeJournalError::DanglingReference);
                }
                self.validate_active_commit_ref(active)?;
                self.validate_exact_zero_commit_census(active, census_digest)?;
            }
            LiveMaterialization::Quarantined {
                active_slice_digest,
                reason_digest,
                resource_census_digest: recorded_census,
            } => {
                ensure_nonzero_digest(&reason_digest)?;
                if recorded_census != resource_census_digest {
                    return Err(RuntimeJournalError::DanglingReference);
                }
                match (active_slice_digest, self.active_desired.as_ref()) {
                    (None, None) => {}
                    (Some(expected), Some(active))
                        if expected == TargetSliceDigest::new(active.slice.digest) => {}
                    _ => return Err(RuntimeJournalError::DanglingReference),
                }
            }
        }
        Ok(())
    }

    fn validate_terminals(&self, snapshot_sequence: u64) -> Result<(), RuntimeJournalError> {
        if self.terminal_operations.len() > MAX_RUNTIME_TERMINAL_OPERATIONS {
            return Err(RuntimeJournalError::CapacityExceeded);
        }
        let mut previous = None;
        for terminal in &self.terminal_operations {
            let key = terminal.key();
            if previous.is_some_and(|value| value >= key) {
                return Err(RuntimeJournalError::NonCanonicalOrdering);
            }
            previous = Some(key);
            if terminal.completion_runtime_host_epoch == 0
                || terminal.completion_runtime_host_epoch > self.host.runtime_host_epoch_high_water
                || terminal.completion_snapshot_sequence == 0
                || terminal.completion_snapshot_sequence > snapshot_sequence
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            let high_water = self
                .source_revision_high_water
                .ok_or(RuntimeJournalError::DanglingReference)?;
            if terminal.source_scope != high_water.source_scope
                || terminal.source_revision > high_water.revision
                || terminal.selection.selection_clock_generation
                    > self.host.clock_generation_high_water
            {
                return Err(RuntimeJournalError::DanglingReference);
            }
            if terminal.source_revision == 0 {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            ensure_nonzero_digest(&terminal.request_digest)?;
            ensure_nonzero_digest(&terminal.request_nonce_identity)?;
            ensure_nonzero_digest(terminal.source_plan_digest.value())?;
            ensure_nonzero_digest(terminal.target_slice_digest.value())?;
            ensure_nonzero_ref(&terminal.temporal_constraint_id)?;
            ensure_nonzero_digest(&terminal.temporal_lineage_digest)?;
            if terminal.installed_clock_generation == 0 || terminal.installed_deadline_nanos == 0 {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            if terminal.completion_predecessor_phase.requires_action() != terminal.action.is_some()
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            if matches!(
                (
                    terminal.incoming_kind,
                    terminal.completion_predecessor_phase
                ),
                (
                    DesiredHeadKind::OneSourceLoop,
                    PreparedPhase::HeadCommittedRetiringOld
                ) | (
                    DesiredHeadKind::EmptyDeactivate,
                    PreparedPhase::FirstActionIntent
                )
            ) {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            if let Some(action) = terminal.action {
                validate_action(action, &self.host)?;
                let expected_kind = match terminal.incoming_kind {
                    DesiredHeadKind::OneSourceLoop => JournalActionKind::StartOneSourceLoop,
                    DesiredHeadKind::EmptyDeactivate => JournalActionKind::DrainToEmpty,
                };
                if action.kind != expected_kind
                    || action.clock_generation != terminal.installed_clock_generation
                    || terminal.completion_runtime_host_epoch < action.runtime_host_epoch
                {
                    return Err(RuntimeJournalError::DanglingReference);
                }
            }
            terminal.selection.validate(
                terminal.incoming_kind,
                terminal.completion_predecessor_phase,
                terminal.installed_clock_generation,
                terminal.installed_deadline_nanos,
            )?;
            if !terminal_raw_lineage_is_valid(terminal) {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            match terminal.head_disposition {
                TerminalHeadDisposition::Preserved(digest) => {
                    if let Some(digest) = digest {
                        ensure_nonzero_digest(digest.value())?;
                    }
                    if terminal_head_commits_incoming(
                        terminal.selection.primary,
                        terminal.incoming_kind,
                    ) {
                        return Err(RuntimeJournalError::InvalidStateInvariant);
                    }
                }
                TerminalHeadDisposition::CommittedIncoming
                    if !terminal_head_commits_incoming(
                        terminal.selection.primary,
                        terminal.incoming_kind,
                    ) =>
                {
                    return Err(RuntimeJournalError::InvalidStateInvariant);
                }
                _ => {}
            }
            ensure_nonzero_digest(&terminal.resource_census_digest)?;
            ensure_nonzero_digest(&terminal.result_digest)?;
            terminal
                .canonical_response
                .validate_bound(MAX_RUNTIME_TERMINAL_RESPONSE_BYTES)?;
            if terminal.canonical_response.digest != terminal.result_digest {
                return Err(RuntimeJournalError::DanglingReference);
            }
        }
        Ok(())
    }

    fn validate_terminal_head_chain(&self) -> Result<(), RuntimeJournalError> {
        let mut chronological = self.terminal_operations.iter().collect::<Vec<_>>();
        chronological.sort_unstable_by_key(|terminal| terminal.completion_snapshot_sequence);
        let mut previous_completion = None;
        let mut committed_head = None;
        for terminal in chronological {
            if previous_completion
                .is_some_and(|sequence| sequence >= terminal.completion_snapshot_sequence)
            {
                return Err(RuntimeJournalError::NonCanonicalOrdering);
            }
            match terminal.head_disposition {
                TerminalHeadDisposition::Preserved(expected) if expected == committed_head => {}
                TerminalHeadDisposition::Preserved(_) => {
                    return Err(RuntimeJournalError::DanglingReference);
                }
                TerminalHeadDisposition::CommittedIncoming => {
                    committed_head = Some(terminal.target_slice_digest);
                }
            }
            previous_completion = Some(terminal.completion_snapshot_sequence);
        }
        let active_head = self
            .active_desired
            .as_ref()
            .map(|active| TargetSliceDigest::new(active.slice.digest));
        let head_first_empty_in_progress = self.prepared.as_ref().is_some_and(|prepared| {
            prepared.incoming_kind == DesiredHeadKind::EmptyDeactivate
                && matches!(
                    prepared.phase,
                    PreparedPhase::HeadCommittedRetiringOld
                        | PreparedPhase::SupersededReconcileRequired
                        | PreparedPhase::StartupReconcileRequired
                )
                && active_head == Some(prepared.incoming_slice_digest)
                && match prepared.expected_active {
                    ExpectedActiveCas::Exact(expected) => committed_head == Some(expected),
                    ExpectedActiveCas::None => committed_head.is_none(),
                }
        });
        if !head_first_empty_in_progress && active_head != committed_head {
            return Err(RuntimeJournalError::DanglingReference);
        }
        Ok(())
    }

    fn validate_recovery_terminals(
        &self,
        snapshot_sequence: u64,
    ) -> Result<(), RuntimeJournalError> {
        if self.recovery_terminals.len() > MAX_RUNTIME_RECOVERY_TERMINALS
            || (self.recovery_terminals.len() == MAX_RUNTIME_RECOVERY_TERMINALS
                && self.recovery_action.is_some())
        {
            return Err(RuntimeJournalError::CapacityExceeded);
        }
        let mut previous_completion = None;
        let mut previous_generations = None;
        let mut action_ids = std::collections::BTreeSet::new();
        for record in &self.recovery_terminals {
            record.validate(&self.host, &self.terminal_operations, snapshot_sequence)?;
            if previous_completion
                .is_some_and(|sequence| sequence >= record.completion_snapshot_sequence)
                || !action_ids.insert(record.recovery.action.action_id)
            {
                return Err(RuntimeJournalError::NonCanonicalOrdering);
            }
            let generations = (
                record.recovery.action.domain_generation,
                record.recovery.action.instance_generation,
                record.recovery.action.resource_generation,
            );
            if previous_generations.is_some_and(|previous: (u64, u64, u64)| {
                generations.0 <= previous.0
                    || generations.1 <= previous.1
                    || generations.2 <= previous.2
            }) {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            previous_completion = Some(record.completion_snapshot_sequence);
            previous_generations = Some(generations);
        }
        if let Some(recovery) = self.recovery_action
            && (action_ids.contains(&recovery.action.action_id)
                || previous_generations.is_some_and(|previous| {
                    recovery.action.domain_generation <= previous.0
                        || recovery.action.instance_generation <= previous.1
                        || recovery.action.resource_generation <= previous.2
                }))
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        Ok(())
    }

    fn validate_global_completion_chronology(&self) -> Result<(), RuntimeJournalError> {
        let mut completions = self
            .terminal_operations
            .iter()
            .map(|terminal| {
                (
                    terminal.completion_snapshot_sequence,
                    terminal.completion_runtime_host_epoch,
                    terminal.selection.selection_clock_generation,
                )
            })
            .chain(self.recovery_terminals.iter().map(|terminal| {
                (
                    terminal.completion_snapshot_sequence,
                    terminal.completion_runtime_host_epoch,
                    terminal.selection.selection_clock_generation,
                )
            }))
            .collect::<Vec<_>>();
        completions.sort_unstable_by_key(|completion| completion.0);
        if completions
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0 || pair[0].1 > pair[1].1 || pair[0].2 > pair[1].2)
        {
            return Err(RuntimeJournalError::NonCanonicalOrdering);
        }
        Ok(())
    }

    fn validate_admission_cross_references(&self) -> Result<(), RuntimeJournalError> {
        for request_nonce in &self.host.request_nonces {
            let matches_prepared = self.prepared.as_ref().is_some_and(|prepared| {
                prepared.request_nonce_identity == request_nonce.identity
                    && prepared.request.digest == request_nonce.value_digest
            });
            let terminal_matches = self
                .terminal_operations
                .iter()
                .filter(|terminal| {
                    terminal.request_nonce_identity == request_nonce.identity
                        && terminal.request_digest == request_nonce.value_digest
                })
                .count();
            if usize::from(matches_prepared) + terminal_matches != 1 {
                return Err(RuntimeJournalError::DanglingReference);
            }
        }
        for temporal in &self.host.temporal_lineages {
            let matches_prepared = self.prepared.as_ref().is_some_and(|prepared| {
                prepared.temporal_constraint_id == temporal.constraint_id
                    && prepared.temporal_lineage_digest == temporal.lineage_digest
                    && prepared.installed_clock_generation == temporal.clock_generation
                    && prepared.installed_deadline_nanos == temporal.deadline_nanos
                    && prepared.source_scope == temporal.source_scope
            });
            let terminal_matches = self
                .terminal_operations
                .iter()
                .filter(|terminal| {
                    terminal.temporal_constraint_id == temporal.constraint_id
                        && terminal.temporal_lineage_digest == temporal.lineage_digest
                        && terminal.source_scope == temporal.source_scope
                        && terminal.installed_clock_generation == temporal.clock_generation
                        && terminal.installed_deadline_nanos == temporal.deadline_nanos
                })
                .count();
            if usize::from(matches_prepared) + terminal_matches != 1 {
                return Err(RuntimeJournalError::DanglingReference);
            }
        }
        for terminal in &self.terminal_operations {
            if !self.host.request_nonces.iter().any(|record| {
                record.identity == terminal.request_nonce_identity
                    && record.value_digest == terminal.request_digest
            }) || !self.host.temporal_lineages.iter().any(|record| {
                record.constraint_id == terminal.temporal_constraint_id
                    && record.source_scope == terminal.source_scope
                    && record.lineage_digest == terminal.temporal_lineage_digest
                    && record.clock_generation == terminal.installed_clock_generation
                    && record.deadline_nanos == terminal.installed_deadline_nanos
            }) {
                return Err(RuntimeJournalError::DanglingReference);
            }
            if self.prepared.as_ref().is_some_and(|prepared| {
                prepared.source_scope == terminal.source_scope
                    && prepared.operation_id == terminal.operation_id
            }) {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
        }
        if let Some(high_water) = self.source_revision_high_water {
            let observed_maximum = self
                .terminal_operations
                .iter()
                .map(|terminal| terminal.source_revision)
                .chain(
                    self.prepared
                        .iter()
                        .map(|prepared| prepared.source_revision),
                )
                .max()
                .unwrap_or(0);
            if observed_maximum != high_water.revision {
                return Err(RuntimeJournalError::DanglingReference);
            }
        }
        Ok(())
    }

    fn expect_active(
        &self,
        expected_kind: DesiredHeadKind,
    ) -> Result<&ActiveDesiredHead, RuntimeJournalError> {
        let Some(active) = self.active_desired.as_ref() else {
            return Err(RuntimeJournalError::DanglingReference);
        };
        if active.kind != expected_kind {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        Ok(active)
    }

    fn current_action(&self) -> Option<JournalActionRef> {
        self.prepared
            .as_ref()
            .and_then(|value| value.action)
            .or_else(|| self.recovery_action.map(|value| value.action))
    }

    fn validate_active_commit_ref(
        &self,
        active: &ActiveDesiredHead,
    ) -> Result<(), RuntimeJournalError> {
        let result_digest = active
            .committing_result_digest
            .ok_or(RuntimeJournalError::DanglingReference)?;
        if !self.terminal_operations.iter().any(|terminal| {
            terminal.source_scope == active.source_scope
                && terminal.operation_id == active.operation_id
                && terminal.source_revision == active.source_revision
                && terminal.source_plan_digest == active.source_plan_digest
                && terminal.target_slice_digest == TargetSliceDigest::new(active.slice.digest)
                && terminal.incoming_kind == active.kind
                && terminal.head_disposition == TerminalHeadDisposition::CommittedIncoming
                && terminal.result_digest == result_digest
                && terminal_head_commits_incoming(terminal.selection.primary, active.kind)
        }) {
            return Err(RuntimeJournalError::DanglingReference);
        }
        Ok(())
    }

    fn validate_live_ready_producer(
        &self,
        active: &ActiveDesiredHead,
        runtime_host_epoch: u64,
        resource_generation: u64,
        resource_census_digest: Digest32,
    ) -> Result<(), RuntimeJournalError> {
        let result_digest = active
            .committing_result_digest
            .ok_or(RuntimeJournalError::DanglingReference)?;
        let normal_producers = self
            .terminal_operations
            .iter()
            .filter(|terminal| {
                terminal.source_scope == active.source_scope
                    && terminal.operation_id == active.operation_id
                    && terminal.source_revision == active.source_revision
                    && terminal.source_plan_digest == active.source_plan_digest
                    && terminal.target_slice_digest == TargetSliceDigest::new(active.slice.digest)
                    && terminal.selection.primary == TerminalOutcome::OneSourceLoopActive
                    && terminal.head_disposition == TerminalHeadDisposition::CommittedIncoming
                    && terminal.resource_census_digest == resource_census_digest
                    && terminal.result_digest == result_digest
                    && terminal.action.is_some_and(|action| {
                        action.kind == JournalActionKind::StartOneSourceLoop
                            && action.runtime_host_epoch == runtime_host_epoch
                            && action.resource_generation == resource_generation
                    })
            })
            .count();
        let recovery_producers = self
            .recovery_terminals
            .iter()
            .filter(|terminal| {
                terminal.recovery.source_scope == active.source_scope
                    && terminal.recovery.source_revision == active.source_revision
                    && terminal.recovery.source_plan_digest == active.source_plan_digest
                    && terminal.recovery.active_slice_digest
                        == TargetSliceDigest::new(active.slice.digest)
                    && terminal.selection.primary == TerminalOutcome::OneSourceLoopActive
                    && terminal.failure_latch_digest.is_none()
                    && terminal.resource_census_digest == resource_census_digest
                    && terminal.recovery.action.runtime_host_epoch == runtime_host_epoch
                    && terminal.recovery.action.resource_generation == resource_generation
            })
            .count();
        if normal_producers + recovery_producers != 1 {
            return Err(RuntimeJournalError::DanglingReference);
        }
        Ok(())
    }

    fn validate_exact_zero_commit_census(
        &self,
        active: &ActiveDesiredHead,
        resource_census_digest: Digest32,
    ) -> Result<(), RuntimeJournalError> {
        let result_digest = active
            .committing_result_digest
            .ok_or(RuntimeJournalError::DanglingReference)?;
        if self
            .terminal_operations
            .iter()
            .filter(|terminal| {
                terminal.source_scope == active.source_scope
                    && terminal.operation_id == active.operation_id
                    && terminal.source_revision == active.source_revision
                    && terminal.source_plan_digest == active.source_plan_digest
                    && terminal.target_slice_digest == TargetSliceDigest::new(active.slice.digest)
                    && terminal.incoming_kind == DesiredHeadKind::EmptyDeactivate
                    && terminal.head_disposition == TerminalHeadDisposition::CommittedIncoming
                    && terminal.resource_census_digest == resource_census_digest
                    && terminal.result_digest == result_digest
                    && terminal_head_commits_incoming(
                        terminal.selection.primary,
                        DesiredHeadKind::EmptyDeactivate,
                    )
            })
            .count()
            != 1
        {
            return Err(RuntimeJournalError::DanglingReference);
        }
        Ok(())
    }

    fn validate_reference_profile_census(
        &self,
        current_action: Option<JournalActionRef>,
    ) -> Result<(), RuntimeJournalError> {
        let mut loop_count = 0_usize;
        let mut card_count = 0_usize;
        for resource in self
            .owned_resources
            .iter()
            .filter(|resource| !resource.phase.is_terminal())
        {
            match resource.kind {
                ResourceKind::LoopDomain => loop_count += 1,
                ResourceKind::CardInstance => card_count += 1,
                ResourceKind::ResourceSlot | ResourceKind::ExternalHandle => {
                    return Err(RuntimeJournalError::InvalidStateInvariant);
                }
            }
        }
        if loop_count > 1 || card_count > 1 || card_count > loop_count {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        if matches!(
            self.live_materialization,
            LiveMaterialization::LiveReady { .. }
        ) && (loop_count != 1 || card_count != 1 || current_action.is_some())
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        Ok(())
    }

    fn resource_belongs_to_live(&self, resource: &OwnedResourceRecord) -> bool {
        match self.live_materialization {
            LiveMaterialization::LiveReady {
                runtime_host_epoch,
                resource_generation,
                ..
            } => {
                resource.runtime_host_epoch == runtime_host_epoch
                    && resource.generation == resource_generation
            }
            LiveMaterialization::StartupInvalidated {
                previous_runtime_host_epoch,
                ..
            } => resource.runtime_host_epoch <= previous_runtime_host_epoch,
            LiveMaterialization::Quarantined { .. } => true,
            _ => false,
        }
    }

    fn validate_successor(&self, previous: &Self) -> Result<(), RuntimeJournalError> {
        self.validate_pinned_host_truth(previous)?;
        match self.last_transaction {
            RuntimeJournalTransaction::Initialized => {
                Err(RuntimeJournalError::NonMonotonicTransition)
            }
            RuntimeJournalTransaction::StartupInvalidation => {
                self.validate_startup_invalidation_successor(previous)
            }
            RuntimeJournalTransaction::TenureOnly => self.validate_tenure_only_successor(previous),
            RuntimeJournalTransaction::FullAdmission => {
                self.validate_full_admission_successor(previous)
            }
            RuntimeJournalTransaction::PreparedProgress => {
                self.validate_prepared_progress_successor(previous)
            }
            RuntimeJournalTransaction::ResourceProgress => {
                self.validate_resource_progress_successor(previous)
            }
            RuntimeJournalTransaction::NormalStartTerminal => {
                self.validate_normal_start_terminal_successor(previous)
            }
            RuntimeJournalTransaction::EmptyHeadRetire => {
                self.validate_empty_head_retire_successor(previous)
            }
            RuntimeJournalTransaction::ExactZeroTerminal => {
                self.validate_exact_zero_terminal_successor(previous)
            }
            RuntimeJournalTransaction::RecoveryPlan => {
                self.validate_recovery_plan_successor(previous)
            }
            RuntimeJournalTransaction::RecoveryProgress => {
                self.validate_recovery_progress_successor(previous)
            }
            RuntimeJournalTransaction::RecoveryPublish => {
                self.validate_recovery_publish_successor(previous)
            }
            RuntimeJournalTransaction::OperationTerminalNoEffects => {
                self.validate_operation_terminal_no_effects_successor(previous)
            }
            RuntimeJournalTransaction::Quarantine => self.validate_quarantine_successor(previous),
            RuntimeJournalTransaction::RecoveryAbortNoEffects => {
                self.validate_recovery_abort_no_effects_successor(previous)
            }
        }
    }

    fn validate_pinned_host_truth(&self, previous: &Self) -> Result<(), RuntimeJournalError> {
        if self.host.clock_domain != previous.host.clock_domain
            || self.host.build_descriptor != previous.host.build_descriptor
            || self.host.singleton_manifest != previous.host.singleton_manifest
            || self.host.store_pinned_build_identity != previous.host.store_pinned_build_identity
            || self.host.compiled_build_instance_id != previous.host.compiled_build_instance_id
            || self.host.compiled_compatibility_digest
                != previous.host.compiled_compatibility_digest
            || self.host.admission_policy_fingerprint != previous.host.admission_policy_fingerprint
            || self.host.channel_policy_fingerprint != previous.host.channel_policy_fingerprint
            || self.host.controller_key_fingerprint != previous.host.controller_key_fingerprint
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_new_terminal_metadata(
        &self,
        previous: &Self,
        snapshot_sequence: u64,
    ) -> Result<(), RuntimeJournalError> {
        for terminal in &self.terminal_operations {
            if previous
                .terminal_operations
                .binary_search_by_key(&terminal.key(), TerminalOperationRecord::key)
                .is_err()
                && (terminal.completion_runtime_host_epoch
                    != self.host.runtime_host_epoch_high_water
                    || terminal.completion_snapshot_sequence != snapshot_sequence
                    || terminal.selection.selection_clock_generation
                        != self.host.clock_generation_high_water)
            {
                return Err(RuntimeJournalError::NonMonotonicTransition);
            }
        }
        for terminal in &self.recovery_terminals {
            if !previous
                .recovery_terminals
                .iter()
                .any(|old| old.recovery.action.action_id == terminal.recovery.action.action_id)
                && (terminal.completion_runtime_host_epoch
                    != self.host.runtime_host_epoch_high_water
                    || terminal.completion_snapshot_sequence != snapshot_sequence
                    || terminal.selection.selection_clock_generation
                        != self.host.clock_generation_high_water)
            {
                return Err(RuntimeJournalError::NonMonotonicTransition);
            }
        }
        Ok(())
    }

    fn require_same_host_generation(&self, previous: &Self) -> Result<(), RuntimeJournalError> {
        if self.host.runtime_host_epoch_high_water != previous.host.runtime_host_epoch_high_water
            || self.host.clock_generation_high_water != previous.host.clock_generation_high_water
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_startup_invalidation_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        if previous.host.runtime_host_epoch_high_water.checked_add(1)
            != Some(self.host.runtime_host_epoch_high_water)
            || previous.host.clock_generation_high_water.checked_add(1)
                != Some(self.host.clock_generation_high_water)
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let expected_prepared = startup_invalidated_prepared(previous.prepared.as_ref())?;
        let expected_recovery = startup_invalidated_recovery(previous.recovery_action)?;
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.host.runtime_host_epoch_high_water = self.host.runtime_host_epoch_high_water;
        expected.host.clock_generation_high_water = self.host.clock_generation_high_water;
        expected.prepared = expected_prepared;
        expected.recovery_action = expected_recovery;
        expected.live_materialization = self.live_materialization;
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let LiveMaterialization::StartupInvalidated {
            active_slice_digest,
            previous_runtime_host_epoch,
            previous_clock_generation,
            recovery_eligibility,
            invalidation_evidence_digest,
            failure_evidence_digest,
            resource_census_digest,
        } = self.live_materialization
        else {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        };
        if previous_runtime_host_epoch != previous.host.runtime_host_epoch_high_water
            || previous_clock_generation != previous.host.clock_generation_high_water
            || active_slice_digest
                != previous
                    .active_desired
                    .as_ref()
                    .map(|active| TargetSliceDigest::new(active.slice.digest))
            || resource_census_digest != compute_resource_census_digest(&previous.owned_resources)?
            || invalidation_evidence_digest != startup_invalidation_evidence_digest(previous, self)?
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let (expected_eligibility, expected_failure) = startup_eligibility(previous)?;
        if recovery_eligibility != expected_eligibility
            || failure_evidence_digest != expected_failure
            || self.owned_resources.iter().any(|resource| {
                resource.runtime_host_epoch == self.host.runtime_host_epoch_high_water
            })
            || self.current_action().is_some_and(|action| {
                action.runtime_host_epoch == self.host.runtime_host_epoch_high_water
            })
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_tenure_only_successor(&self, previous: &Self) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.host.tenure_nonces = self.host.tenure_nonces.clone();
        expected.writer_fence = self.writer_fence;
        expected.prepared = self.prepared.clone();
        expected.recovery_action = self.recovery_action;
        if expected != *self
            || self.host.tenure_nonces.len() != previous.host.tenure_nonces.len() + 1
            || !ordered_records_preserved(
                &self.host.tenure_nonces,
                &previous.host.tenure_nonces,
                |record| record.identity,
            )
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let new_fence = self
            .writer_fence
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        if previous.writer_fence.is_some_and(|old| {
            new_fence.source_scope != old.source_scope || new_fence.epoch <= old.epoch
        }) || previous
            .host
            .tenure_nonces
            .iter()
            .any(|record| record.identity == new_fence.tenure_nonce_identity)
            || !self.host.tenure_nonces.iter().any(|record| {
                record.identity == new_fence.tenure_nonce_identity
                    && record.value_digest == new_fence.proof_envelope_digest
            })
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        validate_tenure_prepared_successor(self.prepared.as_ref(), previous.prepared.as_ref())?;
        validate_tenure_recovery_successor(self.recovery_action, previous.recovery_action)
    }

    fn validate_full_admission_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        if previous.prepared.is_some() || previous.current_action().is_some() {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        if prepared.phase != PreparedPhase::PreparedNoEffects
            || prepared.action.is_some()
            || prepared.retiring.is_some()
            || prepared.raw_outcome.is_some()
            || self.host.request_nonces.len() != previous.host.request_nonces.len() + 1
            || self.host.temporal_lineages.len() != previous.host.temporal_lineages.len() + 1
            || !ordered_records_preserved(
                &self.host.request_nonces,
                &previous.host.request_nonces,
                |record| record.identity,
            )
            || !ordered_records_preserved(
                &self.host.temporal_lineages,
                &previous.host.temporal_lineages,
                |record| record.constraint_id,
            )
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let high_water = self
            .source_revision_high_water
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        if high_water.source_scope != prepared.source_scope
            || high_water.revision != prepared.source_revision
            || previous
                .source_revision_high_water
                .is_some_and(|old| high_water.revision <= old.revision)
            || !expected_active_matches(prepared.expected_active, previous.active_desired.as_ref())
            || !full_admission_shape_is_allowed(prepared.incoming_kind, previous)
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.host.request_nonces = self.host.request_nonces.clone();
        expected.host.temporal_lineages = self.host.temporal_lineages.clone();
        expected.source_revision_high_water = self.source_revision_high_water;
        expected.prepared = self.prepared.clone();
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_prepared_progress_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        let current = self
            .prepared
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let old = previous
            .prepared
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        validate_prepared_latch_successor(Some(current), Some(old))?;
        if !same_owner_event_facts(current.raw_outcome, old.raw_outcome)
            || current.operation_id != old.operation_id
            || (current.phase == PreparedPhase::HeadCommittedRetiringOld
                && old.phase != PreparedPhase::HeadCommittedRetiringOld)
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        if current.phase == old.phase {
            if current.action != old.action || current.retiring != old.retiring {
                return Err(RuntimeJournalError::NonMonotonicTransition);
            }
        } else if !(old.phase == PreparedPhase::PreparedNoEffects
            && current.phase == PreparedPhase::FirstActionIntent
            && current.incoming_kind == DesiredHeadKind::OneSourceLoop
            && old.action.is_none()
            && current.raw_outcome.is_none()
            && current.action.is_some_and(|action| {
                action.kind == JournalActionKind::StartOneSourceLoop
                    && action.runtime_host_epoch == self.host.runtime_host_epoch_high_water
                    && action.clock_generation == current.installed_clock_generation
            }))
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.prepared = self.prepared.clone();
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_resource_progress_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        validate_resource_successor(&self.owned_resources, &previous.owned_resources)?;
        if !live_identity_preserved_except_census(
            self.live_materialization,
            previous.live_materialization,
        ) {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        for resource in &self.owned_resources {
            if previous
                .owned_resources
                .binary_search_by_key(&resource.key(), |record| record.key())
                .is_err()
                && (!matches!(
                    resource.phase,
                    ResourcePhase::Reserved | ResourcePhase::Owned
                ) || resource.action_id != self.current_action().map(|action| action.action_id))
            {
                return Err(RuntimeJournalError::NonMonotonicTransition);
            }
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.owned_resources = self.owned_resources.clone();
        expected.live_materialization = self.live_materialization;
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_normal_start_terminal_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        let prepared = previous
            .prepared
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let action = prepared
            .action
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let terminal = appended_terminal_for_prepared(self, previous, prepared)
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let resource_census_digest = compute_resource_census_digest(&self.owned_resources)?;
        if prepared.incoming_kind != DesiredHeadKind::OneSourceLoop
            || !matches!(
                prepared.phase,
                PreparedPhase::FirstActionIntent
                    | PreparedPhase::SupersededReconcileRequired
                    | PreparedPhase::StartupReconcileRequired
            )
            || action.kind != JournalActionKind::StartOneSourceLoop
            || self.prepared.is_some()
            || terminal.resource_census_digest != resource_census_digest
            || !terminal_raw_is_valid_successor(terminal, prepared)
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        match terminal.selection.primary {
            TerminalOutcome::OneSourceLoopActive => {
                let active = self
                    .active_desired
                    .as_ref()
                    .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
                if prepared.phase != PreparedPhase::FirstActionIntent
                    || active.kind != DesiredHeadKind::OneSourceLoop
                    || active.source_scope != prepared.source_scope
                    || active.source_revision != prepared.source_revision
                    || TargetSliceDigest::new(active.slice.digest) != prepared.incoming_slice_digest
                    || active.source_plan_digest != prepared.source_plan_digest
                    || active.manifest_digest != prepared.manifest_digest
                    || active.operation_id != prepared.operation_id
                    || active.committing_result_digest != Some(terminal.result_digest)
                    || terminal.head_disposition != TerminalHeadDisposition::CommittedIncoming
                    || !matches!(
                        self.live_materialization,
                        LiveMaterialization::LiveReady { .. }
                    )
                    || !resources_publish_live_generation(
                        &self.owned_resources,
                        &previous.owned_resources,
                        action,
                    )
                {
                    return Err(RuntimeJournalError::NonMonotonicTransition);
                }
            }
            TerminalOutcome::StartFailedBeforeHeadCommitExactZero
            | TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero
            | TerminalOutcome::AbortedBeforeHeadCommitExactZero
            | TerminalOutcome::SupersededAfterIntentExactZero => {
                if self.active_desired != previous.active_desired
                    || terminal.head_disposition != preserved_head_disposition(previous)
                    || self
                        .owned_resources
                        .iter()
                        .any(|resource| !resource.phase.is_terminal())
                    || !resources_reach_exact_zero(
                        &self.owned_resources,
                        &previous.owned_resources,
                        Some(action),
                    )
                {
                    return Err(RuntimeJournalError::NonMonotonicTransition);
                }
                match (self.active_desired.as_ref(), self.live_materialization) {
                    (None, LiveMaterialization::None) => {}
                    (
                        Some(active),
                        LiveMaterialization::ExactZero {
                            active_slice_digest,
                            census_digest,
                        },
                    ) if active.kind == DesiredHeadKind::EmptyDeactivate
                        && TargetSliceDigest::new(active.slice.digest) == active_slice_digest
                        && census_digest == resource_census_digest => {}
                    _ => return Err(RuntimeJournalError::NonMonotonicTransition),
                }
            }
            _ => return Err(RuntimeJournalError::NonMonotonicTransition),
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.prepared = None;
        expected.active_desired = self.active_desired.clone();
        expected.live_materialization = self.live_materialization;
        expected.owned_resources = self.owned_resources.clone();
        expected.terminal_operations = self.terminal_operations.clone();
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_empty_head_retire_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        let old_prepared = previous
            .prepared
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let current_prepared = self
            .prepared
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let old_active = previous
            .active_desired
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let current_active = self
            .active_desired
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let LiveMaterialization::LiveReady {
            runtime_host_epoch,
            resource_generation,
            resource_census_digest,
            ..
        } = previous.live_materialization
        else {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        };
        let action = current_prepared
            .action
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let retiring = current_prepared
            .retiring
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        if old_prepared.incoming_kind != DesiredHeadKind::EmptyDeactivate
            || old_prepared.phase != PreparedPhase::PreparedNoEffects
            || current_prepared.phase != PreparedPhase::HeadCommittedRetiringOld
            || !prepared_identity_equal(current_prepared, old_prepared)
            || action.kind != JournalActionKind::DrainToEmpty
            || action.runtime_host_epoch != runtime_host_epoch
            || action.resource_generation != resource_generation
            || old_active.kind != DesiredHeadKind::OneSourceLoop
            || retiring.old_slice != old_active.slice
            || retiring.old_source_plan_digest != old_active.source_plan_digest
            || retiring.old_manifest_digest != old_active.manifest_digest
            || retiring.old_runtime_host_epoch != runtime_host_epoch
            || retiring.old_clock_generation != action.clock_generation
            || retiring.old_resource_generation != resource_generation
            || retiring.old_resource_census_digest != resource_census_digest
            || current_active.kind != DesiredHeadKind::EmptyDeactivate
            || current_active.source_scope != current_prepared.source_scope
            || current_active.source_revision != current_prepared.source_revision
            || TargetSliceDigest::new(current_active.slice.digest)
                != current_prepared.incoming_slice_digest
            || current_active.source_plan_digest != current_prepared.source_plan_digest
            || current_active.operation_id != current_prepared.operation_id
            || current_active.committing_result_digest.is_some()
            || current_prepared.raw_outcome.is_some()
            || !matches!(
                self.live_materialization,
                LiveMaterialization::Draining { .. }
            )
            || !resources_begin_retire(&self.owned_resources, &previous.owned_resources, action)
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.prepared = self.prepared.clone();
        expected.active_desired = self.active_desired.clone();
        expected.live_materialization = self.live_materialization;
        expected.owned_resources = self.owned_resources.clone();
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_exact_zero_terminal_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        let prepared = previous
            .prepared
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let active = self
            .active_desired
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let terminal = appended_terminal_for_prepared(self, previous, prepared)
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let resource_census_digest = compute_resource_census_digest(&self.owned_resources)?;
        if prepared.incoming_kind != DesiredHeadKind::EmptyDeactivate
            || self.prepared.is_some()
            || active.kind != DesiredHeadKind::EmptyDeactivate
            || active.source_scope != prepared.source_scope
            || active.source_revision != prepared.source_revision
            || TargetSliceDigest::new(active.slice.digest) != prepared.incoming_slice_digest
            || active.source_plan_digest != prepared.source_plan_digest
            || active.operation_id != prepared.operation_id
            || !matches!(
                self.live_materialization,
                LiveMaterialization::ExactZero { .. }
            )
            || self
                .owned_resources
                .iter()
                .any(|resource| !resource.phase.is_terminal())
            || terminal.head_disposition != TerminalHeadDisposition::CommittedIncoming
            || terminal.resource_census_digest != resource_census_digest
            || active.committing_result_digest != Some(terminal.result_digest)
            || !terminal_raw_is_valid_successor(terminal, prepared)
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let resource_action = if matches!(
            prepared.phase,
            PreparedPhase::HeadCommittedRetiringOld
                | PreparedPhase::SupersededReconcileRequired
                | PreparedPhase::StartupReconcileRequired
        ) {
            if !previous.active_desired.as_ref().is_some_and(|old| {
                old.kind == DesiredHeadKind::EmptyDeactivate
                    && old.operation_id == prepared.operation_id
                    && old.committing_result_digest.is_none()
            }) || !matches!(
                previous.live_materialization,
                LiveMaterialization::Draining { .. }
                    | LiveMaterialization::StartupInvalidated { .. }
            ) {
                return Err(RuntimeJournalError::NonMonotonicTransition);
            }
            prepared.action
        } else if prepared.phase == PreparedPhase::PreparedNoEffects {
            if exact_zero_fast_path_eligible(previous) {
                None
            } else {
                return Err(RuntimeJournalError::NonMonotonicTransition);
            }
        } else {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        };
        if prepared.phase != PreparedPhase::PreparedNoEffects && resource_action.is_none() {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        if !terminal_head_commits_incoming(terminal.selection.primary, active.kind)
            || (resource_action.is_none()
                && terminal.selection.primary != TerminalOutcome::EmptyDeactivateExactZero)
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        if !resources_reach_exact_zero(
            &self.owned_resources,
            &previous.owned_resources,
            resource_action,
        ) {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.prepared = None;
        expected.active_desired = self.active_desired.clone();
        expected.live_materialization = self.live_materialization;
        expected.owned_resources = self.owned_resources.clone();
        expected.terminal_operations = self.terminal_operations.clone();
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_recovery_plan_successor(&self, previous: &Self) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        let LiveMaterialization::StartupInvalidated {
            recovery_eligibility: StartupRecoveryEligibility::EligibleOneSourceLoop,
            ..
        } = previous.live_materialization
        else {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        };
        let recovery = self
            .recovery_action
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        if previous.current_action().is_some()
            || previous
                .owned_resources
                .iter()
                .any(|resource| !resource.phase.is_terminal())
            || recovery.phase != RecoveryPhase::RecoveryPlannedNoEffects
            || recovery.action.runtime_host_epoch != self.host.runtime_host_epoch_high_water
            || recovery.action.clock_generation != self.host.clock_generation_high_water
            || !matches!(
                self.live_materialization,
                LiveMaterialization::Recovering { .. }
            )
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.live_materialization = self.live_materialization;
        expected.recovery_action = self.recovery_action;
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_recovery_progress_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        let current = self
            .recovery_action
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let old = previous
            .recovery_action
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        validate_recovery_latch_successor(Some(current), Some(old))?;
        if !same_owner_event_facts(current.raw_outcome, old.raw_outcome)
            || current.action.action_id != old.action.action_id
            || (current.phase != old.phase && current.raw_outcome.is_some())
            || !matches!(
                self.live_materialization,
                LiveMaterialization::Recovering { .. }
            )
            || !live_identity_preserved_except_census(
                self.live_materialization,
                previous.live_materialization,
            )
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.recovery_action = self.recovery_action;
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_recovery_publish_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        let old = previous
            .recovery_action
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let terminal = appended_recovery_terminal(self, previous, old)
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let resource_census_digest = compute_resource_census_digest(&self.owned_resources)?;
        let valid_predecessor = match old.phase {
            RecoveryPhase::RecoveryPlannedNoEffects | RecoveryPhase::StartCallIntent => matches!(
                previous.live_materialization,
                LiveMaterialization::Recovering {
                    action_id,
                    ..
                } if action_id == old.action.action_id
            ),
            RecoveryPhase::StartupReconcileRequired => matches!(
                previous.live_materialization,
                LiveMaterialization::StartupInvalidated {
                    active_slice_digest: Some(active_slice_digest),
                    recovery_eligibility: StartupRecoveryEligibility::ReconcileRequired,
                    ..
                } if active_slice_digest == old.active_slice_digest
            ),
            RecoveryPhase::StartupInvalidatedNoEffects => false,
        };
        if !valid_predecessor
            || self.recovery_action.is_some()
            || terminal.resource_census_digest != resource_census_digest
            || !matches!(
                self.live_materialization,
                LiveMaterialization::LiveReady { .. }
                    | LiveMaterialization::RecoveryFailedNotReady { .. }
            )
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        match self.live_materialization {
            LiveMaterialization::LiveReady { .. } => {
                if old.phase != RecoveryPhase::StartCallIntent
                    || terminal.selection.primary != TerminalOutcome::OneSourceLoopActive
                    || terminal.failure_latch_digest.is_some()
                    || !resources_publish_live_generation(
                        &self.owned_resources,
                        &previous.owned_resources,
                        old.action,
                    )
                {
                    return Err(RuntimeJournalError::NonMonotonicTransition);
                }
            }
            LiveMaterialization::RecoveryFailedNotReady {
                terminal_recovery_action_id,
                failure_latch_digest,
                ..
            } => {
                if terminal_recovery_action_id != old.action.action_id
                    || terminal.failure_latch_digest != Some(failure_latch_digest)
                    || terminal.selection.primary == TerminalOutcome::OneSourceLoopActive
                    || terminal.selection.primary == TerminalOutcome::AbortedBeforeIntentNoEffects
                    || self
                        .owned_resources
                        .iter()
                        .any(|resource| !resource.phase.is_terminal())
                    || !resources_reach_exact_zero(
                        &self.owned_resources,
                        &previous.owned_resources,
                        Some(old.action),
                    )
                {
                    return Err(RuntimeJournalError::NonMonotonicTransition);
                }
            }
            _ => unreachable!(),
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.live_materialization = self.live_materialization;
        expected.recovery_action = None;
        expected.recovery_terminals = self.recovery_terminals.clone();
        expected.owned_resources = self.owned_resources.clone();
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_recovery_abort_no_effects_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        let old = previous
            .recovery_action
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let terminal = appended_recovery_terminal(self, previous, old)
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        if old.phase != RecoveryPhase::StartupInvalidatedNoEffects
            || old.raw_outcome.is_some()
            || !matches!(
                previous.live_materialization,
                LiveMaterialization::StartupInvalidated {
                    recovery_eligibility: StartupRecoveryEligibility::EligibleOneSourceLoop,
                    ..
                }
            )
            || self.live_materialization != previous.live_materialization
            || self.recovery_action.is_some()
            || self.owned_resources != previous.owned_resources
            || self
                .owned_resources
                .iter()
                .any(|resource| !resource.phase.is_terminal())
            || terminal.selection.primary != TerminalOutcome::AbortedBeforeIntentNoEffects
            || terminal.failure_latch_digest.is_some()
            || terminal.resource_census_digest
                != compute_resource_census_digest(&self.owned_resources)?
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.recovery_action = None;
        expected.recovery_terminals = self.recovery_terminals.clone();
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_operation_terminal_no_effects_successor(
        &self,
        previous: &Self,
    ) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        let prepared = previous
            .prepared
            .as_ref()
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        let terminal = appended_terminal_for_prepared(self, previous, prepared)
            .ok_or(RuntimeJournalError::NonMonotonicTransition)?;
        if !matches!(
            prepared.phase,
            PreparedPhase::PreparedNoEffects
                | PreparedPhase::SupersededBeforeEffects
                | PreparedPhase::StartupExpiredNoEffects
        ) || prepared.action.is_some()
            || self.prepared.is_some()
            || terminal.resource_census_digest
                != compute_resource_census_digest(&self.owned_resources)?
            || !matches!(
                terminal.selection.primary,
                TerminalOutcome::StartTimedOutBeforeIntentNoEffects
                    | TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects
                    | TerminalOutcome::AbortedBeforeIntentNoEffects
            )
            || (terminal.selection.primary == TerminalOutcome::StartTimedOutBeforeIntentNoEffects
                && prepared.incoming_kind != DesiredHeadKind::OneSourceLoop)
            || (terminal.selection.primary
                == TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects
                && prepared.incoming_kind != DesiredHeadKind::EmptyDeactivate)
            || (prepared.phase != PreparedPhase::PreparedNoEffects
                && terminal.selection.primary != TerminalOutcome::AbortedBeforeIntentNoEffects)
            || terminal.head_disposition != preserved_head_disposition(previous)
            || !terminal_raw_is_valid_successor(terminal, prepared)
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.prepared = None;
        expected.terminal_operations = self.terminal_operations.clone();
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }

    fn validate_quarantine_successor(&self, previous: &Self) -> Result<(), RuntimeJournalError> {
        self.require_same_host_generation(previous)?;
        if matches!(
            previous.live_materialization,
            LiveMaterialization::Quarantined { .. }
        ) || !matches!(
            self.live_materialization,
            LiveMaterialization::Quarantined { .. }
        ) {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        let mut expected = previous.clone();
        expected.last_transaction = self.last_transaction;
        expected.live_materialization = self.live_materialization;
        if expected != *self {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        Ok(())
    }
}

fn startup_invalidated_prepared(
    previous: Option<&PreparedOperation>,
) -> Result<Option<PreparedOperation>, RuntimeJournalError> {
    let Some(previous) = previous else {
        return Ok(None);
    };
    let mut current = previous.clone();
    match previous.phase {
        PreparedPhase::PreparedNoEffects
        | PreparedPhase::SupersededBeforeEffects
        | PreparedPhase::StartupExpiredNoEffects => {
            if previous.action.is_some() || previous.raw_outcome.is_some() {
                return Err(RuntimeJournalError::NonMonotonicTransition);
            }
            current.phase = PreparedPhase::StartupExpiredNoEffects;
        }
        PreparedPhase::FirstActionIntent
        | PreparedPhase::HeadCommittedRetiringOld
        | PreparedPhase::SupersededReconcileRequired
        | PreparedPhase::StartupReconcileRequired => {
            if previous.action.is_none() {
                return Err(RuntimeJournalError::NonMonotonicTransition);
            }
            current.phase = PreparedPhase::StartupReconcileRequired;
            current.raw_outcome = Some(interrupted_raw(previous.raw_outcome));
        }
    }
    Ok(Some(current))
}

fn startup_invalidated_recovery(
    previous: Option<RecoveryAction>,
) -> Result<Option<RecoveryAction>, RuntimeJournalError> {
    let Some(mut current) = previous else {
        return Ok(None);
    };
    match current.phase {
        RecoveryPhase::RecoveryPlannedNoEffects | RecoveryPhase::StartupInvalidatedNoEffects => {
            if current.raw_outcome.is_some() {
                return Err(RuntimeJournalError::NonMonotonicTransition);
            }
            current.phase = RecoveryPhase::StartupInvalidatedNoEffects;
        }
        RecoveryPhase::StartCallIntent | RecoveryPhase::StartupReconcileRequired => {
            current.phase = RecoveryPhase::StartupReconcileRequired;
            current.raw_outcome = Some(interrupted_raw(current.raw_outcome));
        }
    }
    Ok(Some(current))
}

fn interrupted_raw(previous: Option<RawActionOutcomeLatch>) -> RawActionOutcomeLatch {
    let mut current = previous.unwrap_or(RawActionOutcomeLatch {
        callback: CallbackOutcome::UnknownAfterIntent,
        callback_reason_digest: None,
        deadline: DeadlineOutcome::NotObserved,
        observed_clock_generation: 0,
        observed_at_nanos: 0,
        host_interrupted: false,
        higher_tenure_takeover: false,
        cleanup: CleanupOutcome::NotObserved,
        cleanup_evidence_digest: None,
    });
    current.host_interrupted = true;
    current
}

fn takeover_raw(previous: Option<RawActionOutcomeLatch>) -> RawActionOutcomeLatch {
    let mut current = previous.unwrap_or(RawActionOutcomeLatch {
        callback: CallbackOutcome::UnknownAfterIntent,
        callback_reason_digest: None,
        deadline: DeadlineOutcome::NotObserved,
        observed_clock_generation: 0,
        observed_at_nanos: 0,
        host_interrupted: false,
        higher_tenure_takeover: false,
        cleanup: CleanupOutcome::NotObserved,
        cleanup_evidence_digest: None,
    });
    current.higher_tenure_takeover = true;
    current
}

fn startup_invalidation_evidence_digest(
    previous: &RuntimeJournalState,
    current: &RuntimeJournalState,
) -> Result<Digest32, RuntimeJournalError> {
    let payload = encode_payload(previous)?;
    let mut builder = Digest32Builder::try_new(RUNTIME_STARTUP_INVALIDATION_DOMAIN)?;
    builder
        .field_u64(previous.host.runtime_host_epoch_high_water)?
        .field_u64(previous.host.clock_generation_high_water)?
        .field_u64(current.host.runtime_host_epoch_high_water)?
        .field_u64(current.host.clock_generation_high_water)?
        .field_bytes(&payload)?;
    Ok(builder.finish())
}

fn startup_reconcile_evidence_digest(
    previous: &RuntimeJournalState,
) -> Result<Digest32, RuntimeJournalError> {
    let payload = encode_payload(previous)?;
    let mut builder = Digest32Builder::try_new(RUNTIME_STARTUP_RECONCILE_DOMAIN)?;
    builder.field_bytes(&payload)?;
    Ok(builder.finish())
}

fn recovery_failure_evidence_digest(
    recovery: RecoveryAction,
    selection: TerminalOutcomeSelection,
    resource_census_digest: Digest32,
) -> Result<Digest32, RuntimeJournalError> {
    let mut encoded = Encoder::with_capacity(512);
    encode_recovery_action(&mut encoded, recovery);
    encode_terminal_selection(&mut encoded, selection);
    encoded.digest(&resource_census_digest);
    let mut builder = Digest32Builder::try_new(RUNTIME_RECOVERY_FAILURE_DOMAIN)?;
    builder.field_bytes(&encoded.bytes)?;
    Ok(builder.finish())
}

fn startup_eligibility(
    previous: &RuntimeJournalState,
) -> Result<(StartupRecoveryEligibility, Option<Digest32>), RuntimeJournalError> {
    if let LiveMaterialization::StartupInvalidated {
        recovery_eligibility,
        failure_evidence_digest,
        ..
    } = previous.live_materialization
    {
        return Ok((recovery_eligibility, failure_evidence_digest));
    }
    if matches!(
        previous.live_materialization,
        LiveMaterialization::Recovering { .. }
    ) && previous.recovery_action.is_some_and(|recovery| {
        recovery.phase == RecoveryPhase::RecoveryPlannedNoEffects && recovery.raw_outcome.is_none()
    }) && previous
        .owned_resources
        .iter()
        .all(|resource| resource.phase.is_terminal())
    {
        return Ok((StartupRecoveryEligibility::EligibleOneSourceLoop, None));
    }
    if previous.current_action().is_some() {
        return Ok((
            StartupRecoveryEligibility::ReconcileRequired,
            Some(startup_reconcile_evidence_digest(previous)?),
        ));
    }
    match (
        previous.active_desired.as_ref(),
        previous.live_materialization,
    ) {
        (None, LiveMaterialization::None) => Ok((StartupRecoveryEligibility::NoActiveHead, None)),
        (
            Some(active),
            LiveMaterialization::ExactZero {
                active_slice_digest,
                ..
            },
        ) if active.kind == DesiredHeadKind::EmptyDeactivate
            && TargetSliceDigest::new(active.slice.digest) == active_slice_digest =>
        {
            Ok((StartupRecoveryEligibility::CanonicalEmptyExactZero, None))
        }
        (
            Some(active),
            LiveMaterialization::LiveReady {
                active_slice_digest,
                ..
            },
        ) if active.kind == DesiredHeadKind::OneSourceLoop
            && TargetSliceDigest::new(active.slice.digest) == active_slice_digest =>
        {
            Ok((StartupRecoveryEligibility::EligibleOneSourceLoop, None))
        }
        (
            Some(active),
            LiveMaterialization::RecoveryFailedNotReady {
                active_slice_digest,
                failure_latch_digest,
                ..
            },
        ) if active.kind == DesiredHeadKind::OneSourceLoop
            && TargetSliceDigest::new(active.slice.digest) == active_slice_digest =>
        {
            Ok((
                StartupRecoveryEligibility::RecoveryFailureLatched,
                Some(failure_latch_digest),
            ))
        }
        (_, LiveMaterialization::Quarantined { reason_digest, .. }) => Ok((
            StartupRecoveryEligibility::ReconcileRequired,
            Some(reason_digest),
        )),
        _ => Ok((
            StartupRecoveryEligibility::ReconcileRequired,
            Some(startup_reconcile_evidence_digest(previous)?),
        )),
    }
}

fn validate_tenure_prepared_successor(
    current: Option<&PreparedOperation>,
    previous: Option<&PreparedOperation>,
) -> Result<(), RuntimeJournalError> {
    match (previous, current) {
        (None, None) => Ok(()),
        (None, Some(_)) | (Some(_), None) => Err(RuntimeJournalError::NonMonotonicTransition),
        (Some(previous), Some(current)) => {
            let mut expected = previous.clone();
            match previous.phase {
                PreparedPhase::PreparedNoEffects
                | PreparedPhase::SupersededBeforeEffects
                | PreparedPhase::StartupExpiredNoEffects => {
                    expected.phase = PreparedPhase::SupersededBeforeEffects;
                }
                PreparedPhase::FirstActionIntent
                | PreparedPhase::HeadCommittedRetiringOld
                | PreparedPhase::SupersededReconcileRequired
                | PreparedPhase::StartupReconcileRequired => {
                    expected.phase = PreparedPhase::SupersededReconcileRequired;
                    expected.raw_outcome = Some(takeover_raw(previous.raw_outcome));
                }
            }
            if &expected == current {
                Ok(())
            } else {
                Err(RuntimeJournalError::NonMonotonicTransition)
            }
        }
    }
}

fn validate_tenure_recovery_successor(
    current: Option<RecoveryAction>,
    previous: Option<RecoveryAction>,
) -> Result<(), RuntimeJournalError> {
    match (previous, current) {
        (None, None) => Ok(()),
        (None, Some(_)) | (Some(_), None) => Err(RuntimeJournalError::NonMonotonicTransition),
        (Some(previous), Some(current)) => {
            let mut expected = previous;
            match previous.phase {
                RecoveryPhase::RecoveryPlannedNoEffects
                | RecoveryPhase::StartupInvalidatedNoEffects => {}
                RecoveryPhase::StartCallIntent | RecoveryPhase::StartupReconcileRequired => {
                    expected.raw_outcome = Some(takeover_raw(previous.raw_outcome));
                }
            }
            if expected == current {
                Ok(())
            } else {
                Err(RuntimeJournalError::NonMonotonicTransition)
            }
        }
    }
}

fn prepared_identity_equal(current: &PreparedOperation, previous: &PreparedOperation) -> bool {
    current.source_scope == previous.source_scope
        && current.operation_id == previous.operation_id
        && current.source_revision == previous.source_revision
        && current.request == previous.request
        && current.request_nonce_identity == previous.request_nonce_identity
        && current.source_plan_digest == previous.source_plan_digest
        && current.incoming_slice_digest == previous.incoming_slice_digest
        && current.incoming_kind == previous.incoming_kind
        && current.manifest_digest == previous.manifest_digest
        && current.expected_active == previous.expected_active
        && current.temporal_constraint_id == previous.temporal_constraint_id
        && current.temporal_lineage_digest == previous.temporal_lineage_digest
        && current.installed_clock_generation == previous.installed_clock_generation
        && current.installed_deadline_nanos == previous.installed_deadline_nanos
}

fn expected_active_matches(
    expected: ExpectedActiveCas,
    active: Option<&ActiveDesiredHead>,
) -> bool {
    match (expected, active) {
        (ExpectedActiveCas::None, None) => true,
        (ExpectedActiveCas::Exact(expected), Some(active)) => {
            expected == TargetSliceDigest::new(active.slice.digest)
        }
        _ => false,
    }
}

fn full_admission_shape_is_allowed(
    incoming: DesiredHeadKind,
    previous: &RuntimeJournalState,
) -> bool {
    if previous.current_action().is_some()
        || previous
            .owned_resources
            .iter()
            .any(|resource| !resource.phase.is_terminal())
            && !matches!(
                previous.live_materialization,
                LiveMaterialization::LiveReady { .. }
            )
    {
        return false;
    }
    match incoming {
        DesiredHeadKind::OneSourceLoop => match (
            previous.active_desired.as_ref(),
            previous.live_materialization,
        ) {
            (None, LiveMaterialization::None)
            | (
                None,
                LiveMaterialization::StartupInvalidated {
                    recovery_eligibility: StartupRecoveryEligibility::NoActiveHead,
                    ..
                },
            ) => true,
            (
                Some(active),
                LiveMaterialization::ExactZero {
                    active_slice_digest,
                    ..
                },
            ) if active.kind == DesiredHeadKind::EmptyDeactivate
                && TargetSliceDigest::new(active.slice.digest) == active_slice_digest =>
            {
                true
            }
            (
                Some(active),
                LiveMaterialization::StartupInvalidated {
                    recovery_eligibility: StartupRecoveryEligibility::CanonicalEmptyExactZero,
                    active_slice_digest: Some(active_slice_digest),
                    ..
                },
            ) if active.kind == DesiredHeadKind::EmptyDeactivate
                && TargetSliceDigest::new(active.slice.digest) == active_slice_digest =>
            {
                true
            }
            _ => false,
        },
        DesiredHeadKind::EmptyDeactivate => match (
            previous.active_desired.as_ref(),
            previous.live_materialization,
        ) {
            (_, LiveMaterialization::LiveReady { .. })
            | (_, LiveMaterialization::ExactZero { .. })
            | (_, LiveMaterialization::RecoveryFailedNotReady { .. }) => true,
            (
                Some(active),
                LiveMaterialization::StartupInvalidated {
                    active_slice_digest: Some(active_slice_digest),
                    recovery_eligibility:
                        StartupRecoveryEligibility::CanonicalEmptyExactZero
                        | StartupRecoveryEligibility::RecoveryFailureLatched,
                    ..
                },
            ) => TargetSliceDigest::new(active.slice.digest) == active_slice_digest,
            _ => false,
        },
    }
}

fn live_identity_preserved_except_census(
    current: LiveMaterialization,
    previous: LiveMaterialization,
) -> bool {
    match (previous, current) {
        (LiveMaterialization::None, LiveMaterialization::None) => true,
        (
            LiveMaterialization::StartupInvalidated {
                active_slice_digest: old_active,
                previous_runtime_host_epoch: old_host,
                previous_clock_generation: old_clock,
                recovery_eligibility: old_eligibility,
                invalidation_evidence_digest: old_invalidation,
                failure_evidence_digest: old_failure,
                ..
            },
            LiveMaterialization::StartupInvalidated {
                active_slice_digest,
                previous_runtime_host_epoch,
                previous_clock_generation,
                recovery_eligibility,
                invalidation_evidence_digest,
                failure_evidence_digest,
                ..
            },
        ) => {
            old_active == active_slice_digest
                && old_host == previous_runtime_host_epoch
                && old_clock == previous_clock_generation
                && old_eligibility == recovery_eligibility
                && old_invalidation == invalidation_evidence_digest
                && old_failure == failure_evidence_digest
        }
        (
            LiveMaterialization::Recovering {
                active_slice_digest: old_active,
                action_id: old_action,
                resource_generation: old_generation,
                ..
            },
            LiveMaterialization::Recovering {
                active_slice_digest,
                action_id,
                resource_generation,
                ..
            },
        ) => {
            old_active == active_slice_digest
                && old_action == action_id
                && old_generation == resource_generation
        }
        (
            LiveMaterialization::LiveReady {
                active_slice_digest: old_active,
                runtime_host_epoch: old_host,
                resource_generation: old_generation,
                ..
            },
            LiveMaterialization::LiveReady {
                active_slice_digest,
                runtime_host_epoch,
                resource_generation,
                ..
            },
        ) => {
            old_active == active_slice_digest
                && old_host == runtime_host_epoch
                && old_generation == resource_generation
        }
        (
            LiveMaterialization::RecoveryFailedNotReady {
                active_slice_digest: old_active,
                terminal_recovery_action_id: old_terminal,
                failure_latch_digest: old_failure,
                ..
            },
            LiveMaterialization::RecoveryFailedNotReady {
                active_slice_digest,
                terminal_recovery_action_id,
                failure_latch_digest,
                ..
            },
        ) => {
            old_active == active_slice_digest
                && old_terminal == terminal_recovery_action_id
                && old_failure == failure_latch_digest
        }
        (
            LiveMaterialization::Draining {
                active_slice_digest: old_active,
                operation_id: old_operation,
                action_id: old_action,
                retiring_generation: old_generation,
                ..
            },
            LiveMaterialization::Draining {
                active_slice_digest,
                operation_id,
                action_id,
                retiring_generation,
                ..
            },
        ) => {
            old_active == active_slice_digest
                && old_operation == operation_id
                && old_action == action_id
                && old_generation == retiring_generation
        }
        (
            LiveMaterialization::ExactZero {
                active_slice_digest: old_active,
                ..
            },
            LiveMaterialization::ExactZero {
                active_slice_digest,
                ..
            },
        ) => old_active == active_slice_digest,
        (
            LiveMaterialization::Quarantined {
                active_slice_digest: old_active,
                reason_digest: old_reason,
                ..
            },
            LiveMaterialization::Quarantined {
                active_slice_digest,
                reason_digest,
                ..
            },
        ) => old_active == active_slice_digest && old_reason == reason_digest,
        _ => false,
    }
}

fn appended_terminal_for_prepared<'a>(
    current: &'a RuntimeJournalState,
    previous: &RuntimeJournalState,
    prepared: &PreparedOperation,
) -> Option<&'a TerminalOperationRecord> {
    if current.terminal_operations.len() != previous.terminal_operations.len() + 1
        || !ordered_records_preserved(
            &current.terminal_operations,
            &previous.terminal_operations,
            |terminal| terminal.key(),
        )
    {
        return None;
    }
    current.terminal_operations.iter().find(|terminal| {
        terminal.source_scope == prepared.source_scope
            && terminal.operation_id == prepared.operation_id
            && terminal.request_digest == prepared.request.digest
            && terminal.request_nonce_identity == prepared.request_nonce_identity
            && terminal.source_revision == prepared.source_revision
            && terminal.source_plan_digest == prepared.source_plan_digest
            && terminal.target_slice_digest == prepared.incoming_slice_digest
            && terminal.temporal_constraint_id == prepared.temporal_constraint_id
            && terminal.temporal_lineage_digest == prepared.temporal_lineage_digest
            && terminal.incoming_kind == prepared.incoming_kind
            && terminal.completion_predecessor_phase == prepared.phase
            && terminal.installed_clock_generation == prepared.installed_clock_generation
            && terminal.installed_deadline_nanos == prepared.installed_deadline_nanos
            && terminal.action == prepared.action
    })
}

fn appended_recovery_terminal<'a>(
    current: &'a RuntimeJournalState,
    previous: &RuntimeJournalState,
    recovery: RecoveryAction,
) -> Option<&'a RecoveryTerminalRecord> {
    if current.recovery_terminals.len() != previous.recovery_terminals.len() + 1
        || !current
            .recovery_terminals
            .starts_with(&previous.recovery_terminals)
    {
        return None;
    }
    current
        .recovery_terminals
        .last()
        .filter(|terminal| terminal.recovery == recovery)
}

fn terminal_raw_is_valid_successor(
    terminal: &TerminalOperationRecord,
    prepared: &PreparedOperation,
) -> bool {
    terminal.predecessor_raw_outcome == prepared.raw_outcome
        && terminal_raw_lineage_is_valid(terminal)
}

fn terminal_raw_lineage_is_valid(terminal: &TerminalOperationRecord) -> bool {
    if let Some(raw) = terminal.predecessor_raw_outcome {
        if raw.validate().is_err() {
            return false;
        }
        let selected = terminal.selection.raw;
        return selected.preserves(raw)
            && selected.callback == raw.callback
            && selected.callback_reason_digest == raw.callback_reason_digest
            && selected.deadline == raw.deadline
            && selected.observed_clock_generation == raw.observed_clock_generation
            && selected.observed_at_nanos == raw.observed_at_nanos
            && selected.host_interrupted == raw.host_interrupted
            && selected.higher_tenure_takeover == raw.higher_tenure_takeover
            && (selected.cleanup == raw.cleanup
                || (raw.cleanup == CleanupOutcome::NotObserved
                    && selected.cleanup == CleanupOutcome::ExactZero));
    }
    let raw = terminal.selection.raw;
    match terminal.selection.primary {
        TerminalOutcome::OneSourceLoopActive => {
            raw.callback == CallbackOutcome::KnownSuccess
                && raw.callback_reason_digest.is_none()
                && raw.deadline == DeadlineOutcome::NotObserved
                && !raw.host_interrupted
                && !raw.higher_tenure_takeover
                && raw.cleanup == CleanupOutcome::NotObserved
        }
        TerminalOutcome::EmptyDeactivateExactZero
            if terminal.completion_predecessor_phase == PreparedPhase::PreparedNoEffects =>
        {
            raw.callback == CallbackOutcome::NotInvoked
                && raw.callback_reason_digest.is_none()
                && raw.deadline == DeadlineOutcome::NotObserved
                && !raw.host_interrupted
                && !raw.higher_tenure_takeover
                && raw.cleanup == CleanupOutcome::NotObserved
        }
        TerminalOutcome::StartTimedOutBeforeIntentNoEffects
        | TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects
        | TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero => {
            terminal.selection.lifecycle_effect == TerminalLifecycleEffect::ProvenNotStarted
                && raw.callback == CallbackOutcome::NotInvoked
                && raw.callback_reason_digest.is_none()
                && raw.deadline == DeadlineOutcome::TimedOut
                && !raw.host_interrupted
                && !raw.higher_tenure_takeover
                && raw.cleanup == CleanupOutcome::NotObserved
        }
        TerminalOutcome::AbortedBeforeIntentNoEffects => {
            terminal.selection.lifecycle_effect == TerminalLifecycleEffect::ProvenNotStarted
                && raw.callback == CallbackOutcome::NotInvoked
                && raw.callback_reason_digest.is_none()
                && raw.deadline == DeadlineOutcome::NotObserved
                && raw.cleanup == CleanupOutcome::NotObserved
                && match terminal.completion_predecessor_phase {
                    PreparedPhase::StartupExpiredNoEffects => {
                        raw.host_interrupted && !raw.higher_tenure_takeover
                    }
                    PreparedPhase::SupersededBeforeEffects => raw.higher_tenure_takeover,
                    _ => false,
                }
        }
        _ => false,
    }
}

fn terminal_head_commits_incoming(outcome: TerminalOutcome, kind: DesiredHeadKind) -> bool {
    match kind {
        DesiredHeadKind::OneSourceLoop => outcome == TerminalOutcome::OneSourceLoopActive,
        DesiredHeadKind::EmptyDeactivate => matches!(
            outcome,
            TerminalOutcome::EmptyDeactivateExactZero
                | TerminalOutcome::StopFailedButExactZero
                | TerminalOutcome::TimedOutButExactZero
                | TerminalOutcome::SupersededAfterIntentExactZero
                | TerminalOutcome::InterruptedButNowExactZero
        ),
    }
}

fn preserved_head_disposition(state: &RuntimeJournalState) -> TerminalHeadDisposition {
    TerminalHeadDisposition::Preserved(
        state
            .active_desired
            .as_ref()
            .map(|active| TargetSliceDigest::new(active.slice.digest)),
    )
}

fn resources_publish_live_generation(
    current: &[OwnedResourceRecord],
    previous: &[OwnedResourceRecord],
    action: JournalActionRef,
) -> bool {
    if current.len() != previous.len() {
        return false;
    }
    let mut loop_count = 0_usize;
    let mut card_count = 0_usize;
    for old in previous {
        let Ok(index) = current.binary_search_by_key(&old.key(), OwnedResourceRecord::key) else {
            return false;
        };
        let new = &current[index];
        if old.phase.is_terminal() {
            if new != old {
                return false;
            }
            continue;
        }
        if old.phase != ResourcePhase::Owned
            || old.action_id != Some(action.action_id)
            || old.generation != action.resource_generation
            || old.runtime_host_epoch != action.runtime_host_epoch
        {
            return false;
        }
        match old.kind {
            ResourceKind::LoopDomain => loop_count += 1,
            ResourceKind::CardInstance => card_count += 1,
            ResourceKind::ResourceSlot | ResourceKind::ExternalHandle => return false,
        }
        let mut expected = old.clone();
        expected.action_id = None;
        if new != &expected {
            return false;
        }
    }
    loop_count == 1 && card_count == 1
}

fn resources_begin_retire(
    current: &[OwnedResourceRecord],
    previous: &[OwnedResourceRecord],
    action: JournalActionRef,
) -> bool {
    if current.len() != previous.len() {
        return false;
    }
    let mut loop_count = 0_usize;
    let mut card_count = 0_usize;
    for old in previous {
        let Ok(index) = current.binary_search_by_key(&old.key(), OwnedResourceRecord::key) else {
            return false;
        };
        let new = &current[index];
        if old.phase.is_terminal() {
            if new != old {
                return false;
            }
            continue;
        }
        if old.phase != ResourcePhase::Owned
            || old.action_id.is_some()
            || old.generation != action.resource_generation
            || old.runtime_host_epoch != action.runtime_host_epoch
        {
            return false;
        }
        match old.kind {
            ResourceKind::LoopDomain => loop_count += 1,
            ResourceKind::CardInstance => card_count += 1,
            ResourceKind::ResourceSlot | ResourceKind::ExternalHandle => return false,
        }
        let mut expected = old.clone();
        expected.phase = ResourcePhase::CleanupPending;
        expected.action_id = Some(action.action_id);
        if new != &expected {
            return false;
        }
    }
    loop_count == 1 && card_count == 1
}

fn resources_reach_exact_zero(
    current: &[OwnedResourceRecord],
    previous: &[OwnedResourceRecord],
    action: Option<JournalActionRef>,
) -> bool {
    if current.len() != previous.len() {
        return false;
    }
    for old in previous {
        let Ok(index) = current.binary_search_by_key(&old.key(), OwnedResourceRecord::key) else {
            return false;
        };
        let new = &current[index];
        if old.phase.is_terminal() {
            if new != old {
                return false;
            }
            continue;
        }
        let Some(action) = action else {
            return false;
        };
        if old.phase != ResourcePhase::CleanupPending
            || old.action_id != Some(action.action_id)
            || old.generation != action.resource_generation
            || old.runtime_host_epoch != action.runtime_host_epoch
            || new.tombstone_evidence.is_none()
        {
            return false;
        }
        let mut expected = old.clone();
        expected.phase = ResourcePhase::Terminal;
        expected.action_id = None;
        expected.tombstone_evidence = new.tombstone_evidence.clone();
        if new != &expected {
            return false;
        }
    }
    true
}

fn exact_zero_fast_path_eligible(previous: &RuntimeJournalState) -> bool {
    if previous.current_action().is_some()
        || previous
            .owned_resources
            .iter()
            .any(|resource| !resource.phase.is_terminal())
    {
        return false;
    }
    match (
        previous.active_desired.as_ref(),
        previous.live_materialization,
    ) {
        (
            Some(active),
            LiveMaterialization::ExactZero {
                active_slice_digest,
                ..
            },
        ) => {
            active.kind == DesiredHeadKind::EmptyDeactivate
                && TargetSliceDigest::new(active.slice.digest) == active_slice_digest
        }
        (
            Some(active),
            LiveMaterialization::RecoveryFailedNotReady {
                active_slice_digest,
                ..
            },
        ) => {
            active.kind == DesiredHeadKind::OneSourceLoop
                && TargetSliceDigest::new(active.slice.digest) == active_slice_digest
        }
        (
            Some(active),
            LiveMaterialization::StartupInvalidated {
                active_slice_digest: Some(active_slice_digest),
                recovery_eligibility:
                    StartupRecoveryEligibility::CanonicalEmptyExactZero
                    | StartupRecoveryEligibility::RecoveryFailureLatched,
                ..
            },
        ) => TargetSliceDigest::new(active.slice.digest) == active_slice_digest,
        _ => false,
    }
}

impl OpaqueCanonicalValue {
    fn validate_bound(&self, maximum: usize) -> Result<(), RuntimeJournalError> {
        if self.canonical_bytes.is_empty() {
            return Err(RuntimeJournalError::EmptyOpaqueValue);
        }
        if self.canonical_bytes.len() > maximum {
            return Err(RuntimeJournalError::OpaqueValueTooLarge);
        }
        ensure_nonzero_digest(&self.digest)
    }
}

impl PreparedOperation {
    fn validate(
        &self,
        pinned_manifest_digest: &Digest32,
        request_nonces: &[ReplayLedgerRecord],
        temporal_lineages: &[TemporalLineageRecord],
    ) -> Result<(), RuntimeJournalError> {
        self.request
            .validate_bound(MAX_OPAQUE_REQUEST_OR_SLICE_BYTES)?;
        ensure_nonzero_digest(&self.request_nonce_identity)?;
        ensure_nonzero_digest(self.source_plan_digest.value())?;
        ensure_nonzero_digest(self.incoming_slice_digest.value())?;
        ensure_nonzero_digest(&self.manifest_digest)?;
        ensure_nonzero_ref(&self.temporal_constraint_id)?;
        ensure_nonzero_digest(&self.temporal_lineage_digest)?;
        if self.installed_clock_generation == 0 || self.installed_deadline_nanos == 0 {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        if &self.manifest_digest != pinned_manifest_digest {
            return Err(RuntimeJournalError::DanglingReference);
        }
        if !request_nonces.iter().any(|record| {
            record.identity == self.request_nonce_identity
                && record.value_digest == self.request.digest
        }) || !temporal_lineages.iter().any(|record| {
            record.constraint_id == self.temporal_constraint_id
                && record.source_scope == self.source_scope
                && record.clock_generation == self.installed_clock_generation
                && record.deadline_nanos == self.installed_deadline_nanos
                && record.lineage_digest == self.temporal_lineage_digest
        }) {
            return Err(RuntimeJournalError::DanglingReference);
        }
        if let ExpectedActiveCas::Exact(digest) = self.expected_active {
            ensure_nonzero_digest(digest.value())?;
        }
        match (self.phase, self.retiring.as_ref()) {
            (PreparedPhase::HeadCommittedRetiringOld, Some(facts))
            | (PreparedPhase::SupersededReconcileRequired, Some(facts))
            | (PreparedPhase::StartupReconcileRequired, Some(facts))
                if self.action.map(|value| value.kind) == Some(JournalActionKind::DrainToEmpty) =>
            {
                facts.validate(pinned_manifest_digest)?;
            }
            (PreparedPhase::HeadCommittedRetiringOld, None) => {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            (_, None) => {}
            (_, Some(_)) => return Err(RuntimeJournalError::InvalidStateInvariant),
        }
        if let Some(raw) = self.raw_outcome {
            if self.action.is_none() {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
            raw.validate()?;
            if raw.deadline != DeadlineOutcome::NotObserved
                && raw.observed_clock_generation != self.installed_clock_generation
            {
                return Err(RuntimeJournalError::DanglingReference);
            }
            if raw.deadline == DeadlineOutcome::TimedOut
                && raw.observed_at_nanos < self.installed_deadline_nanos
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
        }
        if self.raw_outcome.is_some_and(|raw| {
            (raw.host_interrupted || raw.higher_tenure_takeover)
                && !matches!(
                    self.phase,
                    PreparedPhase::SupersededReconcileRequired
                        | PreparedPhase::StartupReconcileRequired
                )
        }) || (self.phase == PreparedPhase::SupersededReconcileRequired
            && !self
                .raw_outcome
                .is_some_and(|raw| raw.higher_tenure_takeover))
            || (self.phase == PreparedPhase::StartupReconcileRequired
                && !self.raw_outcome.is_some_and(|raw| raw.host_interrupted))
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        Ok(())
    }
}

impl RetiringLiveFacts {
    fn validate(&self, pinned_manifest_digest: &Digest32) -> Result<(), RuntimeJournalError> {
        self.old_slice
            .validate_bound(MAX_OPAQUE_REQUEST_OR_SLICE_BYTES)?;
        ensure_nonzero_digest(self.old_source_plan_digest.value())?;
        ensure_nonzero_digest(&self.old_manifest_digest)?;
        ensure_nonzero_digest(&self.old_resource_census_digest)?;
        if &self.old_manifest_digest != pinned_manifest_digest
            || self.signed_start_budget_nanos == 0
            || self.signed_drain_budget_nanos == 0
            || self.signed_cleanup_budget_nanos == 0
            || self.old_runtime_host_epoch == 0
            || self.old_clock_generation == 0
            || self.old_resource_generation == 0
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        Ok(())
    }
}

impl ActiveDesiredHead {
    fn validate(&self, pinned_manifest_digest: &Digest32) -> Result<(), RuntimeJournalError> {
        self.slice
            .validate_bound(MAX_OPAQUE_REQUEST_OR_SLICE_BYTES)?;
        ensure_nonzero_digest(self.source_plan_digest.value())?;
        ensure_nonzero_digest(&self.manifest_digest)?;
        if &self.manifest_digest != pinned_manifest_digest {
            return Err(RuntimeJournalError::DanglingReference);
        }
        if let Some(result_digest) = self.committing_result_digest {
            ensure_nonzero_digest(&result_digest)?;
        }
        Ok(())
    }
}

impl RecoveryAction {
    fn validate(
        self,
        host: &HostClockAdmissionState,
        active: Option<&ActiveDesiredHead>,
    ) -> Result<(), RuntimeJournalError> {
        self.validate_intrinsic(host, true)?;
        let Some(active) = active else {
            return Err(RuntimeJournalError::DanglingReference);
        };
        if active.kind != DesiredHeadKind::OneSourceLoop
            || active.source_scope != self.source_scope
            || active.source_revision != self.source_revision
            || active.source_plan_digest != self.source_plan_digest
            || TargetSliceDigest::new(active.slice.digest) != self.active_slice_digest
            || active.manifest_digest != self.manifest_digest
        {
            return Err(RuntimeJournalError::DanglingReference);
        }
        Ok(())
    }

    fn validate_intrinsic(
        self,
        host: &HostClockAdmissionState,
        require_current_host: bool,
    ) -> Result<(), RuntimeJournalError> {
        if self.action.kind != JournalActionKind::RestartReassembly {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        validate_action(self.action, host)?;
        ensure_nonzero_ref(&self.source_scope)?;
        ensure_nonzero_digest(self.source_plan_digest.value())?;
        ensure_nonzero_digest(self.active_slice_digest.value())?;
        ensure_nonzero_digest(&self.manifest_digest)?;
        ensure_nonzero_digest(&self.store_pinned_build_identity_digest)?;
        ensure_nonzero_digest(&self.compiled_compatibility_digest)?;
        ensure_nonzero_digest(&self.deadline_evidence_digest)?;
        if self
            .compiled_build_instance_id
            .iter()
            .all(|byte| *byte == 0)
            || self.source_revision == 0
            || self.store_pinned_build_identity_digest != host.store_pinned_build_identity.digest
            || self.compiled_build_instance_id != host.compiled_build_instance_id
            || self.compiled_compatibility_digest != host.compiled_compatibility_digest
            || self.manifest_digest != host.singleton_manifest.digest
            || self.signed_start_budget_nanos == 0
            || self.deadline_nanos == 0
            || (require_current_host
                && !matches!(
                    self.phase,
                    RecoveryPhase::StartupInvalidatedNoEffects
                        | RecoveryPhase::StartupReconcileRequired
                )
                && (self.action.clock_generation != host.clock_generation_high_water
                    || self.action.runtime_host_epoch != host.runtime_host_epoch_high_water))
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        if matches!(
            self.phase,
            RecoveryPhase::RecoveryPlannedNoEffects | RecoveryPhase::StartupInvalidatedNoEffects
        ) && self.raw_outcome.is_some()
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        if let Some(raw) = self.raw_outcome {
            raw.validate()?;
            if raw.deadline != DeadlineOutcome::NotObserved
                && raw.observed_clock_generation != self.action.clock_generation
            {
                return Err(RuntimeJournalError::DanglingReference);
            }
            if raw.deadline == DeadlineOutcome::TimedOut
                && raw.observed_at_nanos < self.deadline_nanos
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
        }
        if self.raw_outcome.is_some_and(|raw| raw.host_interrupted)
            != (self.phase == RecoveryPhase::StartupReconcileRequired)
            || self.raw_outcome.is_some_and(|raw| {
                raw.higher_tenure_takeover
                    && !matches!(
                        self.phase,
                        RecoveryPhase::StartCallIntent | RecoveryPhase::StartupReconcileRequired
                    )
            })
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        if self.raw_outcome.is_some_and(|raw| raw.host_interrupted)
            && (self.action.runtime_host_epoch >= host.runtime_host_epoch_high_water
                || self.action.clock_generation >= host.clock_generation_high_water)
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        Ok(())
    }
}

fn recovery_predecessor_phase(phase: RecoveryPhase) -> PreparedPhase {
    match phase {
        RecoveryPhase::RecoveryPlannedNoEffects => PreparedPhase::PreparedNoEffects,
        RecoveryPhase::StartCallIntent => PreparedPhase::FirstActionIntent,
        RecoveryPhase::StartupInvalidatedNoEffects => PreparedPhase::StartupExpiredNoEffects,
        RecoveryPhase::StartupReconcileRequired => PreparedPhase::StartupReconcileRequired,
    }
}

impl RecoveryTerminalRecord {
    fn validate(
        self,
        host: &HostClockAdmissionState,
        terminal_operations: &[TerminalOperationRecord],
        snapshot_sequence: u64,
    ) -> Result<(), RuntimeJournalError> {
        self.recovery.validate_intrinsic(host, false)?;
        if self.recovery.completion_identity_is_invalid(host)
            || self.completion_runtime_host_epoch == 0
            || self.completion_runtime_host_epoch > host.runtime_host_epoch_high_water
            || self.completion_runtime_host_epoch < self.recovery.action.runtime_host_epoch
            || self.completion_snapshot_sequence == 0
            || self.completion_snapshot_sequence > snapshot_sequence
            || self.selection.selection_clock_generation > host.clock_generation_high_water
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        ensure_nonzero_digest(&self.resource_census_digest)?;
        if let Some(digest) = self.failure_latch_digest {
            ensure_nonzero_digest(&digest)?;
        }
        self.selection.validate(
            DesiredHeadKind::OneSourceLoop,
            recovery_predecessor_phase(self.recovery.phase),
            self.recovery.action.clock_generation,
            self.recovery.deadline_nanos,
        )?;
        if !recovery_terminal_raw_lineage_is_valid(&self) {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        let is_success = self.selection.primary == TerminalOutcome::OneSourceLoopActive;
        let is_retryable_abort = self.selection.primary
            == TerminalOutcome::AbortedBeforeIntentNoEffects
            && self.recovery.phase == RecoveryPhase::StartupInvalidatedNoEffects;
        if is_success || is_retryable_abort {
            if self.failure_latch_digest.is_some() {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
        } else if self.failure_latch_digest
            != Some(recovery_failure_evidence_digest(
                self.recovery,
                self.selection,
                self.resource_census_digest,
            )?)
        {
            return Err(RuntimeJournalError::DanglingReference);
        }
        if !terminal_operations.iter().any(|terminal| {
            terminal.source_scope == self.recovery.source_scope
                && terminal.source_revision == self.recovery.source_revision
                && terminal.source_plan_digest == self.recovery.source_plan_digest
                && terminal.target_slice_digest == self.recovery.active_slice_digest
                && terminal.incoming_kind == DesiredHeadKind::OneSourceLoop
                && terminal.head_disposition == TerminalHeadDisposition::CommittedIncoming
        }) {
            return Err(RuntimeJournalError::DanglingReference);
        }
        Ok(())
    }
}

impl RecoveryAction {
    fn completion_identity_is_invalid(self, host: &HostClockAdmissionState) -> bool {
        self.compiled_build_instance_id
            .iter()
            .all(|byte| *byte == 0)
            || self.store_pinned_build_identity_digest != host.store_pinned_build_identity.digest
            || self.compiled_build_instance_id != host.compiled_build_instance_id
            || self.compiled_compatibility_digest != host.compiled_compatibility_digest
            || self.manifest_digest != host.singleton_manifest.digest
            || self.signed_start_budget_nanos == 0
            || self.deadline_nanos == 0
            || self
                .deadline_evidence_digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self
                .active_slice_digest
                .value()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self
                .source_plan_digest
                .value()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self.source_scope == [0; 16]
    }
}

fn recovery_terminal_raw_lineage_is_valid(record: &RecoveryTerminalRecord) -> bool {
    let selected = record.selection.raw;
    let predecessor_is_preserved = record.recovery.raw_outcome.is_none_or(|raw| {
        raw.validate().is_ok()
            && selected.preserves(raw)
            && selected.callback == raw.callback
            && selected.callback_reason_digest == raw.callback_reason_digest
            && selected.deadline == raw.deadline
            && selected.observed_clock_generation == raw.observed_clock_generation
            && selected.observed_at_nanos == raw.observed_at_nanos
            && selected.host_interrupted == raw.host_interrupted
            && selected.higher_tenure_takeover == raw.higher_tenure_takeover
            && (selected.cleanup == raw.cleanup
                || (raw.cleanup == CleanupOutcome::NotObserved
                    && selected.cleanup == CleanupOutcome::ExactZero))
    });
    if !predecessor_is_preserved {
        return false;
    }
    match record.recovery.phase {
        RecoveryPhase::RecoveryPlannedNoEffects => {
            record.recovery.raw_outcome.is_none()
                && record.selection.primary == TerminalOutcome::StartTimedOutBeforeIntentNoEffects
                && selected.callback == CallbackOutcome::NotInvoked
                && selected.callback_reason_digest.is_none()
                && selected.deadline == DeadlineOutcome::TimedOut
                && selected.observed_clock_generation == record.recovery.action.clock_generation
                && selected.observed_at_nanos >= record.recovery.deadline_nanos
                && !selected.host_interrupted
                && !selected.higher_tenure_takeover
                && selected.cleanup == CleanupOutcome::NotObserved
                && record.selection.lifecycle_effect == TerminalLifecycleEffect::ProvenNotStarted
        }
        RecoveryPhase::StartupInvalidatedNoEffects => {
            record.recovery.raw_outcome.is_none()
                && record.selection.primary == TerminalOutcome::AbortedBeforeIntentNoEffects
                && selected.callback == CallbackOutcome::NotInvoked
                && selected.callback_reason_digest.is_none()
                && selected.deadline == DeadlineOutcome::NotObserved
                && selected.host_interrupted
                && !selected.higher_tenure_takeover
                && selected.cleanup == CleanupOutcome::NotObserved
                && record.selection.lifecycle_effect == TerminalLifecycleEffect::ProvenNotStarted
        }
        RecoveryPhase::StartCallIntent if record.recovery.raw_outcome.is_none() => {
            record.selection.primary == TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero
                && selected.callback == CallbackOutcome::NotInvoked
                && selected.callback_reason_digest.is_none()
                && selected.deadline == DeadlineOutcome::TimedOut
                && !selected.host_interrupted
                && !selected.higher_tenure_takeover
                && selected.cleanup == CleanupOutcome::NotObserved
                && record.selection.lifecycle_effect == TerminalLifecycleEffect::ProvenNotStarted
        }
        RecoveryPhase::StartCallIntent => matches!(
            record.selection.primary,
            TerminalOutcome::OneSourceLoopActive
                | TerminalOutcome::StartFailedBeforeHeadCommitExactZero
                | TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero
                | TerminalOutcome::AbortedBeforeHeadCommitExactZero
                | TerminalOutcome::SupersededAfterIntentExactZero
        ),
        RecoveryPhase::StartupReconcileRequired => {
            record
                .recovery
                .raw_outcome
                .is_some_and(|raw| raw.host_interrupted)
                && matches!(
                    record.selection.primary,
                    TerminalOutcome::AbortedBeforeHeadCommitExactZero
                        | TerminalOutcome::SupersededAfterIntentExactZero
                )
                && selected.cleanup == CleanupOutcome::ExactZero
                && record.selection.lifecycle_effect == TerminalLifecycleEffect::MayHaveStarted
        }
    }
}

fn validate_action(
    action: JournalActionRef,
    host: &HostClockAdmissionState,
) -> Result<(), RuntimeJournalError> {
    ensure_nonzero_ref(&action.action_id)?;
    if action.runtime_host_epoch == 0
        || action.runtime_host_epoch > host.runtime_host_epoch_high_water
        || action.clock_generation == 0
        || action.clock_generation > host.clock_generation_high_water
        || action.domain_generation == 0
        || action.instance_generation == 0
        || action.resource_generation == 0
    {
        return Err(RuntimeJournalError::InvalidStateInvariant);
    }
    Ok(())
}

fn validate_replay_records(
    records: &[ReplayLedgerRecord],
    maximum: usize,
) -> Result<(), RuntimeJournalError> {
    if records.len() > maximum {
        return Err(RuntimeJournalError::CapacityExceeded);
    }
    let mut previous = None;
    for record in records {
        ensure_nonzero_digest(&record.identity)?;
        ensure_nonzero_digest(&record.value_digest)?;
        if previous.is_some_and(|value| value >= record.identity) {
            return Err(RuntimeJournalError::NonCanonicalOrdering);
        }
        previous = Some(record.identity);
    }
    Ok(())
}

fn validate_temporal_records(
    records: &[TemporalLineageRecord],
    clock_generation_high_water: u64,
) -> Result<(), RuntimeJournalError> {
    if records.len() > MAX_RUNTIME_TEMPORAL_LINEAGES {
        return Err(RuntimeJournalError::CapacityExceeded);
    }
    let mut previous = None;
    for record in records {
        ensure_nonzero_ref(&record.constraint_id)?;
        ensure_nonzero_ref(&record.source_scope)?;
        ensure_nonzero_digest(&record.target_fingerprint)?;
        if record.original_budget_nanos == 0
            || record.remaining_budget_nanos == 0
            || record.remaining_budget_nanos > record.original_budget_nanos
            || record.clock_generation == 0
            || record.clock_generation > clock_generation_high_water
            || record.deadline_nanos == 0
        {
            return Err(RuntimeJournalError::InvalidStateInvariant);
        }
        ensure_nonzero_digest(&record.lineage_digest)?;
        if previous.is_some_and(|value| value >= record.constraint_id) {
            return Err(RuntimeJournalError::NonCanonicalOrdering);
        }
        previous = Some(record.constraint_id);
    }
    Ok(())
}

fn observe_scope(scope: &mut Option<Ref16>, candidate: Ref16) -> Result<(), RuntimeJournalError> {
    ensure_nonzero_ref(&candidate)?;
    match scope {
        None => {
            *scope = Some(candidate);
            Ok(())
        }
        Some(current) if *current == candidate => Ok(()),
        Some(_) => Err(RuntimeJournalError::MultipleSourceScopes),
    }
}

fn validate_prepared_latch_successor(
    current: Option<&PreparedOperation>,
    previous: Option<&PreparedOperation>,
) -> Result<(), RuntimeJournalError> {
    let (Some(current), Some(previous)) = (current, previous) else {
        return Ok(());
    };
    if current.operation_id != previous.operation_id {
        return Ok(());
    }
    if current.source_scope != previous.source_scope
        || current.source_revision != previous.source_revision
        || current.request != previous.request
        || current.request_nonce_identity != previous.request_nonce_identity
        || current.source_plan_digest != previous.source_plan_digest
        || current.incoming_slice_digest != previous.incoming_slice_digest
        || current.incoming_kind != previous.incoming_kind
        || current.manifest_digest != previous.manifest_digest
        || current.expected_active != previous.expected_active
        || current.temporal_constraint_id != previous.temporal_constraint_id
        || current.temporal_lineage_digest != previous.temporal_lineage_digest
        || current.installed_clock_generation != previous.installed_clock_generation
        || current.installed_deadline_nanos != previous.installed_deadline_nanos
        || !prepared_phase_successor(current.phase, previous.phase)
        || !optional_action_preserved(current.action, previous.action)
        || (previous.retiring.is_some() && current.retiring != previous.retiring)
        || !latch_preserved(current.raw_outcome, previous.raw_outcome)
    {
        return Err(RuntimeJournalError::NonMonotonicTransition);
    }
    Ok(())
}

fn validate_recovery_latch_successor(
    current: Option<RecoveryAction>,
    previous: Option<RecoveryAction>,
) -> Result<(), RuntimeJournalError> {
    let (Some(current), Some(previous)) = (current, previous) else {
        return Ok(());
    };
    if current.action.action_id == previous.action.action_id
        && (current.action != previous.action
            || current.active_slice_digest != previous.active_slice_digest
            || current.manifest_digest != previous.manifest_digest
            || current.store_pinned_build_identity_digest
                != previous.store_pinned_build_identity_digest
            || current.compiled_build_instance_id != previous.compiled_build_instance_id
            || current.compiled_compatibility_digest != previous.compiled_compatibility_digest
            || current.signed_start_budget_nanos != previous.signed_start_budget_nanos
            || current.deadline_nanos != previous.deadline_nanos
            || current.deadline_evidence_digest != previous.deadline_evidence_digest
            || !recovery_phase_successor(current.phase, previous.phase)
            || !latch_preserved(current.raw_outcome, previous.raw_outcome))
    {
        return Err(RuntimeJournalError::NonMonotonicTransition);
    }
    Ok(())
}

fn prepared_phase_successor(current: PreparedPhase, previous: PreparedPhase) -> bool {
    current == previous
        || matches!(
            (previous, current),
            (
                PreparedPhase::PreparedNoEffects,
                PreparedPhase::FirstActionIntent
                    | PreparedPhase::HeadCommittedRetiringOld
                    | PreparedPhase::SupersededBeforeEffects
            ) | (
                PreparedPhase::FirstActionIntent | PreparedPhase::HeadCommittedRetiringOld,
                PreparedPhase::SupersededReconcileRequired
            )
        )
}

fn recovery_phase_successor(current: RecoveryPhase, previous: RecoveryPhase) -> bool {
    current == previous
        || (previous == RecoveryPhase::RecoveryPlannedNoEffects
            && current == RecoveryPhase::StartCallIntent)
}

fn optional_action_preserved(
    current: Option<JournalActionRef>,
    previous: Option<JournalActionRef>,
) -> bool {
    previous.is_none() || current == previous
}

fn latch_preserved(
    current: Option<RawActionOutcomeLatch>,
    previous: Option<RawActionOutcomeLatch>,
) -> bool {
    match (previous, current) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(previous), Some(current)) => current.preserves(previous),
    }
}

fn same_owner_event_facts(
    current: Option<RawActionOutcomeLatch>,
    previous: Option<RawActionOutcomeLatch>,
) -> bool {
    let current_host_interrupted = current.is_some_and(|raw| raw.host_interrupted);
    let previous_host_interrupted = previous.is_some_and(|raw| raw.host_interrupted);
    let current_higher_tenure = current.is_some_and(|raw| raw.higher_tenure_takeover);
    let previous_higher_tenure = previous.is_some_and(|raw| raw.higher_tenure_takeover);
    current_host_interrupted == previous_host_interrupted
        && current_higher_tenure == previous_higher_tenure
}

fn validate_resource_successor(
    current: &[OwnedResourceRecord],
    previous: &[OwnedResourceRecord],
) -> Result<(), RuntimeJournalError> {
    for old in previous {
        let Ok(index) = current.binary_search_by_key(&old.key(), |value| value.key()) else {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        };
        let new = &current[index];
        if new.kind != old.kind
            || new.logical_ref != old.logical_ref
            || new.generation != old.generation
            || new.runtime_host_epoch != old.runtime_host_epoch
            || (new.phase as u8) < (old.phase as u8)
            || (new.phase as u8) > (old.phase as u8).saturating_add(1)
            || (new.phase == old.phase && new != old)
            || (old.os_identity.is_some() && new.os_identity != old.os_identity)
            || (old.workspace_identity.is_some()
                && new.workspace_identity != old.workspace_identity)
            || (old.containment_identity.is_some()
                && new.containment_identity != old.containment_identity)
            || (old.tombstone_evidence.is_some()
                && new.tombstone_evidence != old.tombstone_evidence)
            || (old.action_id.is_some()
                && new.action_id != old.action_id
                && !(new.phase.is_terminal() && new.action_id.is_none()))
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
    }
    Ok(())
}

fn validate_resource_evidence(resource: &OwnedResourceRecord) -> Result<(), RuntimeJournalError> {
    for evidence in [
        resource.os_identity.as_ref(),
        resource.workspace_identity.as_ref(),
        resource.containment_identity.as_ref(),
        resource.tombstone_evidence.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        evidence.validate_bound(MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES)?;
    }
    match resource.phase {
        ResourcePhase::Reserved => {
            if resource.os_identity.is_some()
                || resource.workspace_identity.is_some()
                || resource.containment_identity.is_some()
                || resource.tombstone_evidence.is_some()
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
        }
        ResourcePhase::Owned | ResourcePhase::CleanupPending => {
            if resource.os_identity.is_none()
                || resource.workspace_identity.is_none()
                || resource.containment_identity.is_none()
                || resource.tombstone_evidence.is_some()
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
        }
        ResourcePhase::Terminal => {
            if resource.os_identity.is_none()
                || resource.workspace_identity.is_none()
                || resource.containment_identity.is_none()
                || resource.tombstone_evidence.is_none()
            {
                return Err(RuntimeJournalError::InvalidStateInvariant);
            }
        }
    }
    Ok(())
}

fn compute_resource_census_digest(
    resources: &[OwnedResourceRecord],
) -> Result<Digest32, RuntimeJournalError> {
    let mut builder = Digest32Builder::try_new(RUNTIME_RESOURCE_CENSUS_DOMAIN)?;
    builder.field_u64(
        u64::try_from(resources.len()).map_err(|_| RuntimeJournalError::IntegerOverflow)?,
    )?;
    for resource in resources {
        builder.field_u16(resource.kind as u16)?;
        builder.field_bytes(&resource.logical_ref)?;
        builder.field_u64(resource.generation)?;
        builder.field_u64(resource.runtime_host_epoch)?;
        builder.field_u16(resource.phase as u16)?;
        match resource.action_id {
            None => {
                builder.field_u16(0)?;
            }
            Some(action_id) => {
                builder.field_u16(1)?.field_bytes(&action_id)?;
            }
        }
        for evidence in [
            resource.os_identity.as_ref(),
            resource.workspace_identity.as_ref(),
            resource.containment_identity.as_ref(),
            resource.tombstone_evidence.as_ref(),
        ] {
            match evidence {
                None => {
                    builder.field_u16(0)?;
                }
                Some(evidence) => {
                    builder
                        .field_u16(1)?
                        .field_bytes(&evidence.canonical_bytes)?
                        .field_digest(&evidence.digest)?;
                }
            }
        }
    }
    Ok(builder.finish())
}

fn ordered_records_preserved<T, K: Ord + Copy>(
    current: &[T],
    previous: &[T],
    key: impl Fn(&T) -> K,
) -> bool
where
    T: Eq,
{
    previous.iter().all(|old| {
        current
            .binary_search_by_key(&key(old), &key)
            .is_ok_and(|index| current[index] == *old)
    })
}

fn ensure_nonzero_digest(digest: &Digest32) -> Result<(), RuntimeJournalError> {
    if digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(RuntimeJournalError::ZeroDigest);
    }
    Ok(())
}

fn ensure_nonzero_ref(reference: &Ref16) -> Result<(), RuntimeJournalError> {
    if reference.iter().all(|byte| *byte == 0) {
        return Err(RuntimeJournalError::ZeroReference);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeJournalSnapshot {
    store_instance_id: [u8; 32],
    owner_target_fingerprint: Digest32,
    sequence: u64,
    state: RuntimeJournalState,
    canonical_wire: Box<[u8]>,
}

impl RuntimeJournalSnapshot {
    pub(crate) fn try_new(
        store_instance_id: [u8; 32],
        owner_target_fingerprint: Digest32,
        sequence: u64,
        state: RuntimeJournalState,
    ) -> Result<Self, RuntimeJournalError> {
        validate_envelope_identity(&store_instance_id, &owner_target_fingerprint, sequence)?;
        state.validate(sequence)?;
        state.validate_owner_target_binding(&owner_target_fingerprint)?;
        let payload = encode_payload(&state)?;
        let canonical_wire = encode_snapshot(
            &store_instance_id,
            &owner_target_fingerprint,
            sequence,
            &payload,
        )?;
        Ok(Self {
            store_instance_id,
            owner_target_fingerprint,
            sequence,
            state,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    pub(crate) fn decode(frame: &[u8]) -> Result<Self, RuntimeJournalError> {
        if frame.len() > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES {
            return Err(RuntimeJournalError::SnapshotTooLarge);
        }
        if frame.len() < HEADER_BYTES {
            return Err(RuntimeJournalError::Truncated);
        }
        let mut header = Cursor::new(frame);
        if header.array::<4>()? != *RUNTIME_JOURNAL_MAGIC {
            return Err(RuntimeJournalError::InvalidMagic);
        }
        if header.u16()? != RUNTIME_JOURNAL_ENVELOPE_VERSION {
            return Err(RuntimeJournalError::UnsupportedEnvelopeVersion);
        }
        if header.u16()? != RUNTIME_JOURNAL_OWNER_KIND {
            return Err(RuntimeJournalError::WrongOwnerKind);
        }
        if header.u16()? != RUNTIME_JOURNAL_PAYLOAD_VERSION {
            return Err(RuntimeJournalError::UnsupportedPayloadVersion);
        }
        if header.u16()? != RUNTIME_JOURNAL_CHECKSUM_ALGORITHM
            || header.u16()? != RUNTIME_JOURNAL_CHECKSUM_VERSION
        {
            return Err(RuntimeJournalError::UnsupportedChecksumProfile);
        }
        let store_instance_id = header.array::<32>()?;
        let owner_target_fingerprint = Digest32::from_bytes(header.array::<32>()?);
        let sequence = header.u64()?;
        let payload_length =
            usize::try_from(header.u64()?).map_err(|_| RuntimeJournalError::IntegerOverflow)?;
        validate_envelope_identity(&store_instance_id, &owner_target_fingerprint, sequence)?;
        if payload_length > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES - HEADER_BYTES {
            return Err(RuntimeJournalError::LengthBomb);
        }
        let checksum = Digest32::from_bytes(header.array::<32>()?);
        let expected_length = HEADER_BYTES
            .checked_add(payload_length)
            .ok_or(RuntimeJournalError::IntegerOverflow)?;
        if expected_length != frame.len() {
            return if expected_length < frame.len() {
                Err(RuntimeJournalError::TrailingBytes)
            } else {
                Err(RuntimeJournalError::Truncated)
            };
        }
        let payload = &frame[HEADER_BYTES..];
        if snapshot_checksum(&frame[..HEADER_WITHOUT_CHECKSUM_BYTES], payload)? != checksum {
            return Err(RuntimeJournalError::ChecksumMismatch);
        }
        let state = decode_payload(payload)?;
        state.validate(sequence)?;
        state.validate_owner_target_binding(&owner_target_fingerprint)?;
        if encode_payload(&state)? != payload {
            return Err(RuntimeJournalError::NonCanonicalEncoding);
        }
        Ok(Self {
            store_instance_id,
            owner_target_fingerprint,
            sequence,
            state,
            canonical_wire: frame.into(),
        })
    }

    pub(crate) fn validate_successor_of(&self, previous: &Self) -> Result<(), RuntimeJournalError> {
        if self.store_instance_id != previous.store_instance_id
            || self.owner_target_fingerprint != previous.owner_target_fingerprint
            || self.sequence
                != previous
                    .sequence
                    .checked_add(1)
                    .ok_or(RuntimeJournalError::SequenceOverflow)?
        {
            return Err(RuntimeJournalError::NonMonotonicTransition);
        }
        self.state.validate_successor(&previous.state)?;
        self.state
            .validate_new_terminal_metadata(&previous.state, self.sequence)
    }

    pub(crate) const fn store_instance_id(&self) -> &[u8; 32] {
        &self.store_instance_id
    }

    pub(crate) const fn owner_target_fingerprint(&self) -> &Digest32 {
        &self.owner_target_fingerprint
    }

    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) const fn state(&self) -> &RuntimeJournalState {
        &self.state
    }

    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

fn validate_envelope_identity(
    store_instance_id: &[u8; 32],
    owner_target_fingerprint: &Digest32,
    sequence: u64,
) -> Result<(), RuntimeJournalError> {
    if store_instance_id.iter().all(|byte| *byte == 0) {
        return Err(RuntimeJournalError::ZeroStoreInstanceId);
    }
    ensure_nonzero_digest(owner_target_fingerprint)?;
    if sequence == 0 {
        return Err(RuntimeJournalError::InvalidSequence);
    }
    Ok(())
}

fn encode_snapshot(
    store_instance_id: &[u8; 32],
    owner_target_fingerprint: &Digest32,
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>, RuntimeJournalError> {
    let total_length = HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(RuntimeJournalError::IntegerOverflow)?;
    if total_length > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES {
        return Err(RuntimeJournalError::SnapshotTooLarge);
    }
    let payload_length =
        u64::try_from(payload.len()).map_err(|_| RuntimeJournalError::IntegerOverflow)?;
    let mut header = Encoder::with_capacity(HEADER_WITHOUT_CHECKSUM_BYTES);
    header.bytes(RUNTIME_JOURNAL_MAGIC);
    header.u16(RUNTIME_JOURNAL_ENVELOPE_VERSION);
    header.u16(RUNTIME_JOURNAL_OWNER_KIND);
    header.u16(RUNTIME_JOURNAL_PAYLOAD_VERSION);
    header.u16(RUNTIME_JOURNAL_CHECKSUM_ALGORITHM);
    header.u16(RUNTIME_JOURNAL_CHECKSUM_VERSION);
    header.bytes(store_instance_id);
    header.digest(owner_target_fingerprint);
    header.u64(sequence);
    header.u64(payload_length);
    debug_assert_eq!(header.bytes.len(), HEADER_WITHOUT_CHECKSUM_BYTES);
    let checksum = snapshot_checksum(&header.bytes, payload)?;
    let mut encoded = Vec::with_capacity(total_length);
    encoded.extend_from_slice(&header.bytes);
    encoded.extend_from_slice(checksum.as_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn snapshot_checksum(header: &[u8], payload: &[u8]) -> Result<Digest32, RuntimeJournalError> {
    let mut builder = Digest32Builder::try_new(RUNTIME_JOURNAL_CHECKSUM_DOMAIN)?;
    builder.field_bytes(header)?;
    builder.field_bytes(payload)?;
    Ok(builder.finish())
}

fn encode_payload(state: &RuntimeJournalState) -> Result<Vec<u8>, RuntimeJournalError> {
    let mut encoder = Encoder::with_capacity(1024);
    encoder.u8(state.last_transaction as u8);
    let host = &state.host;
    encoder.u64(host.runtime_host_epoch_high_water);
    encoder.bytes(&host.clock_domain);
    encoder.u64(host.clock_generation_high_water);
    encoder.opaque(&host.build_descriptor)?;
    encoder.opaque(&host.singleton_manifest)?;
    encoder.opaque(&host.store_pinned_build_identity)?;
    encoder.bytes(&host.compiled_build_instance_id);
    encoder.digest(&host.compiled_compatibility_digest);
    encoder.digest(&host.admission_policy_fingerprint);
    encoder.digest(&host.channel_policy_fingerprint);
    encoder.digest(&host.controller_key_fingerprint);

    encoder.count(host.tenure_nonces.len())?;
    for record in &host.tenure_nonces {
        encoder.digest(&record.identity);
        encoder.digest(&record.value_digest);
    }
    encoder.count(host.request_nonces.len())?;
    for record in &host.request_nonces {
        encoder.digest(&record.identity);
        encoder.digest(&record.value_digest);
    }
    encoder.count(host.temporal_lineages.len())?;
    for record in &host.temporal_lineages {
        encoder.bytes(&record.constraint_id);
        encoder.bytes(&record.source_scope);
        encoder.digest(&record.target_fingerprint);
        encoder.u64(record.original_budget_nanos);
        encoder.u64(record.remaining_budget_nanos);
        encoder.u64(record.clock_generation);
        encoder.u64(record.deadline_nanos);
        encoder.digest(&record.lineage_digest);
    }

    encoder.presence(state.writer_fence.is_some());
    if let Some(fence) = state.writer_fence {
        encoder.bytes(&fence.source_scope);
        encoder.bytes(&fence.writer);
        encoder.u64(fence.epoch);
        encoder.digest(&fence.proof_envelope_digest);
        encoder.digest(&fence.tenure_nonce_identity);
        encoder.bytes(&fence.principal);
    }

    encoder.presence(state.source_revision_high_water.is_some());
    if let Some(high_water) = state.source_revision_high_water {
        encoder.bytes(&high_water.source_scope);
        encoder.u64(high_water.revision);
    }

    encoder.presence(state.prepared.is_some());
    if let Some(prepared) = &state.prepared {
        encoder.bytes(&prepared.source_scope);
        encoder.bytes(&prepared.operation_id);
        encoder.u64(prepared.source_revision);
        encoder.opaque(&prepared.request)?;
        encoder.digest(&prepared.request_nonce_identity);
        encoder.digest(prepared.source_plan_digest.value());
        encoder.digest(prepared.incoming_slice_digest.value());
        encoder.u8(prepared.incoming_kind as u8);
        encoder.digest(&prepared.manifest_digest);
        encode_expected_active(&mut encoder, prepared.expected_active);
        encoder.bytes(&prepared.temporal_constraint_id);
        encoder.digest(&prepared.temporal_lineage_digest);
        encoder.u64(prepared.installed_clock_generation);
        encoder.u64(prepared.installed_deadline_nanos);
        encoder.u8(prepared.phase as u8);
        encode_optional_action(&mut encoder, prepared.action);
        encoder.presence(prepared.retiring.is_some());
        if let Some(retiring) = &prepared.retiring {
            encoder.opaque(&retiring.old_slice)?;
            encoder.digest(retiring.old_source_plan_digest.value());
            encoder.digest(&retiring.old_manifest_digest);
            encoder.u64(retiring.signed_start_budget_nanos);
            encoder.u64(retiring.signed_drain_budget_nanos);
            encoder.u64(retiring.signed_cleanup_budget_nanos);
            encoder.u64(retiring.old_runtime_host_epoch);
            encoder.u64(retiring.old_clock_generation);
            encoder.u64(retiring.old_resource_generation);
            encoder.digest(&retiring.old_resource_census_digest);
        }
        encode_optional_raw_outcome(&mut encoder, prepared.raw_outcome);
    }

    encoder.presence(state.active_desired.is_some());
    if let Some(active) = &state.active_desired {
        encoder.u8(active.kind as u8);
        encoder.bytes(&active.source_scope);
        encoder.u64(active.source_revision);
        encoder.opaque(&active.slice)?;
        encoder.digest(active.source_plan_digest.value());
        encoder.digest(&active.manifest_digest);
        encoder.bytes(&active.operation_id);
        encoder.optional_digest(active.committing_result_digest);
    }

    encode_live_materialization(&mut encoder, state.live_materialization);

    encoder.presence(state.recovery_action.is_some());
    if let Some(recovery) = state.recovery_action {
        encode_recovery_action(&mut encoder, recovery);
    }

    encoder.count(state.recovery_terminals.len())?;
    for terminal in &state.recovery_terminals {
        encode_recovery_action(&mut encoder, terminal.recovery);
        encode_terminal_selection(&mut encoder, terminal.selection);
        encoder.digest(&terminal.resource_census_digest);
        encoder.optional_digest(terminal.failure_latch_digest);
        encoder.u64(terminal.completion_runtime_host_epoch);
        encoder.u64(terminal.completion_snapshot_sequence);
    }

    encoder.count(state.owned_resources.len())?;
    for resource in &state.owned_resources {
        encoder.u8(resource.kind as u8);
        encoder.bytes(&resource.logical_ref);
        encoder.u64(resource.generation);
        encoder.u64(resource.runtime_host_epoch);
        encoder.u8(resource.phase as u8);
        encoder.optional_ref16(resource.action_id);
        encoder.optional_opaque(resource.os_identity.as_ref())?;
        encoder.optional_opaque(resource.workspace_identity.as_ref())?;
        encoder.optional_opaque(resource.containment_identity.as_ref())?;
        encoder.optional_opaque(resource.tombstone_evidence.as_ref())?;
    }

    encoder.count(state.terminal_operations.len())?;
    for terminal in &state.terminal_operations {
        encoder.bytes(&terminal.source_scope);
        encoder.bytes(&terminal.operation_id);
        encoder.digest(&terminal.request_digest);
        encoder.digest(&terminal.request_nonce_identity);
        encoder.u64(terminal.source_revision);
        encoder.digest(terminal.source_plan_digest.value());
        encoder.digest(terminal.target_slice_digest.value());
        encoder.bytes(&terminal.temporal_constraint_id);
        encoder.digest(&terminal.temporal_lineage_digest);
        encoder.u8(terminal.incoming_kind as u8);
        encoder.u8(terminal.completion_predecessor_phase as u8);
        encoder.u64(terminal.installed_clock_generation);
        encoder.u64(terminal.installed_deadline_nanos);
        encode_optional_action(&mut encoder, terminal.action);
        encode_optional_raw_outcome(&mut encoder, terminal.predecessor_raw_outcome);
        encode_terminal_selection(&mut encoder, terminal.selection);
        match terminal.head_disposition {
            TerminalHeadDisposition::Preserved(None) => encoder.u8(0),
            TerminalHeadDisposition::Preserved(Some(digest)) => {
                encoder.u8(1);
                encoder.digest(digest.value());
            }
            TerminalHeadDisposition::CommittedIncoming => encoder.u8(2),
        }
        encoder.digest(&terminal.resource_census_digest);
        encoder.digest(&terminal.result_digest);
        encoder.opaque(&terminal.canonical_response)?;
        encoder.u64(terminal.completion_runtime_host_epoch);
        encoder.u64(terminal.completion_snapshot_sequence);
    }

    if encoder.bytes.len() > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES - HEADER_BYTES {
        return Err(RuntimeJournalError::SnapshotTooLarge);
    }
    Ok(encoder.bytes)
}

fn encode_action(encoder: &mut Encoder, action: JournalActionRef) {
    encoder.bytes(&action.action_id);
    encoder.u8(action.kind as u8);
    encoder.u64(action.runtime_host_epoch);
    encoder.u64(action.clock_generation);
    encoder.u64(action.domain_generation);
    encoder.u64(action.instance_generation);
    encoder.u64(action.resource_generation);
}

fn encode_recovery_action(encoder: &mut Encoder, recovery: RecoveryAction) {
    encode_action(encoder, recovery.action);
    encoder.bytes(&recovery.source_scope);
    encoder.u64(recovery.source_revision);
    encoder.digest(recovery.source_plan_digest.value());
    encoder.digest(recovery.active_slice_digest.value());
    encoder.digest(&recovery.manifest_digest);
    encoder.digest(&recovery.store_pinned_build_identity_digest);
    encoder.bytes(&recovery.compiled_build_instance_id);
    encoder.digest(&recovery.compiled_compatibility_digest);
    encoder.u64(recovery.signed_start_budget_nanos);
    encoder.u64(recovery.deadline_nanos);
    encoder.digest(&recovery.deadline_evidence_digest);
    encoder.u8(recovery.phase as u8);
    encode_optional_raw_outcome(encoder, recovery.raw_outcome);
}

fn encode_terminal_selection(encoder: &mut Encoder, selection: TerminalOutcomeSelection) {
    encoder.u8(selection.primary as u8);
    encode_raw_outcome(encoder, selection.raw);
    encoder.u64(selection.selection_clock_generation);
    encoder.u64(selection.selection_observed_at_nanos);
    encoder.u8(selection.lifecycle_effect as u8);
}

fn encode_expected_active(encoder: &mut Encoder, expected: ExpectedActiveCas) {
    match expected {
        ExpectedActiveCas::None => encoder.u8(0),
        ExpectedActiveCas::Exact(digest) => {
            encoder.u8(1);
            encoder.digest(digest.value());
        }
    }
}

fn encode_optional_action(encoder: &mut Encoder, action: Option<JournalActionRef>) {
    encoder.presence(action.is_some());
    if let Some(action) = action {
        encode_action(encoder, action);
    }
}

fn encode_optional_raw_outcome(encoder: &mut Encoder, outcome: Option<RawActionOutcomeLatch>) {
    encoder.presence(outcome.is_some());
    if let Some(outcome) = outcome {
        encode_raw_outcome(encoder, outcome);
    }
}

fn encode_raw_outcome(encoder: &mut Encoder, outcome: RawActionOutcomeLatch) {
    encoder.u8(outcome.callback as u8);
    encoder.optional_digest(outcome.callback_reason_digest);
    encoder.u8(outcome.deadline as u8);
    encoder.u64(outcome.observed_clock_generation);
    encoder.u64(outcome.observed_at_nanos);
    encoder.boolean(outcome.host_interrupted);
    encoder.boolean(outcome.higher_tenure_takeover);
    encoder.u8(outcome.cleanup as u8);
    encoder.optional_digest(outcome.cleanup_evidence_digest);
}

fn encode_live_materialization(encoder: &mut Encoder, live: LiveMaterialization) {
    match live {
        LiveMaterialization::None => encoder.u8(0),
        LiveMaterialization::StartupInvalidated {
            active_slice_digest,
            previous_runtime_host_epoch,
            previous_clock_generation,
            recovery_eligibility,
            invalidation_evidence_digest,
            failure_evidence_digest,
            resource_census_digest,
        } => {
            encoder.u8(1);
            encoder.optional_target_slice_digest(active_slice_digest);
            encoder.u64(previous_runtime_host_epoch);
            encoder.u64(previous_clock_generation);
            encoder.u8(recovery_eligibility as u8);
            encoder.digest(&invalidation_evidence_digest);
            encoder.optional_digest(failure_evidence_digest);
            encoder.digest(&resource_census_digest);
        }
        LiveMaterialization::Recovering {
            active_slice_digest,
            action_id,
            resource_generation,
            resource_census_digest,
        } => {
            encoder.u8(2);
            encoder.digest(active_slice_digest.value());
            encoder.bytes(&action_id);
            encoder.u64(resource_generation);
            encoder.digest(&resource_census_digest);
        }
        LiveMaterialization::LiveReady {
            active_slice_digest,
            runtime_host_epoch,
            resource_generation,
            resource_census_digest,
        } => {
            encoder.u8(3);
            encoder.digest(active_slice_digest.value());
            encoder.u64(runtime_host_epoch);
            encoder.u64(resource_generation);
            encoder.digest(&resource_census_digest);
        }
        LiveMaterialization::RecoveryFailedNotReady {
            active_slice_digest,
            terminal_recovery_action_id,
            failure_latch_digest,
            resource_census_digest,
        } => {
            encoder.u8(4);
            encoder.digest(active_slice_digest.value());
            encoder.bytes(&terminal_recovery_action_id);
            encoder.digest(&failure_latch_digest);
            encoder.digest(&resource_census_digest);
        }
        LiveMaterialization::Draining {
            active_slice_digest,
            operation_id,
            action_id,
            retiring_generation,
            resource_census_digest,
        } => {
            encoder.u8(5);
            encoder.digest(active_slice_digest.value());
            encoder.bytes(&operation_id);
            encoder.bytes(&action_id);
            encoder.u64(retiring_generation);
            encoder.digest(&resource_census_digest);
        }
        LiveMaterialization::ExactZero {
            active_slice_digest,
            census_digest,
        } => {
            encoder.u8(6);
            encoder.digest(active_slice_digest.value());
            encoder.digest(&census_digest);
        }
        LiveMaterialization::Quarantined {
            active_slice_digest,
            reason_digest,
            resource_census_digest,
        } => {
            encoder.u8(7);
            encoder.optional_target_slice_digest(active_slice_digest);
            encoder.digest(&reason_digest);
            encoder.digest(&resource_census_digest);
        }
    }
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn presence(&mut self, present: bool) {
        self.boolean(present);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn digest(&mut self, value: &Digest32) {
        self.bytes(value.as_bytes());
    }

    fn count(&mut self, value: usize) -> Result<(), RuntimeJournalError> {
        self.u16(u16::try_from(value).map_err(|_| RuntimeJournalError::IntegerOverflow)?);
        Ok(())
    }

    fn opaque(&mut self, value: &OpaqueCanonicalValue) -> Result<(), RuntimeJournalError> {
        self.u32(
            u32::try_from(value.canonical_bytes.len())
                .map_err(|_| RuntimeJournalError::IntegerOverflow)?,
        );
        self.bytes(&value.canonical_bytes);
        self.digest(&value.digest);
        Ok(())
    }

    fn optional_digest(&mut self, value: Option<Digest32>) {
        self.presence(value.is_some());
        if let Some(value) = value {
            self.digest(&value);
        }
    }

    fn optional_target_slice_digest(&mut self, value: Option<TargetSliceDigest>) {
        self.presence(value.is_some());
        if let Some(value) = value {
            self.digest(value.value());
        }
    }

    fn optional_ref16(&mut self, value: Option<Ref16>) {
        self.presence(value.is_some());
        if let Some(value) = value {
            self.bytes(&value);
        }
    }

    fn optional_opaque(
        &mut self,
        value: Option<&OpaqueCanonicalValue>,
    ) -> Result<(), RuntimeJournalError> {
        self.presence(value.is_some());
        if let Some(value) = value {
            self.opaque(value)?;
        }
        Ok(())
    }
}

fn decode_payload(payload: &[u8]) -> Result<RuntimeJournalState, RuntimeJournalError> {
    if payload.len() > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES - HEADER_BYTES {
        return Err(RuntimeJournalError::LengthBomb);
    }
    let mut cursor = Cursor::new(payload);
    let last_transaction = RuntimeJournalTransaction::decode(cursor.u8()?)?;
    let runtime_host_epoch_high_water = cursor.u64()?;
    let clock_domain = cursor.array::<16>()?;
    let clock_generation_high_water = cursor.u64()?;
    let build_descriptor = cursor.opaque(MAX_PINNED_OPAQUE_ARTIFACT_BYTES)?;
    let singleton_manifest = cursor.opaque(MAX_PINNED_OPAQUE_ARTIFACT_BYTES)?;
    let store_pinned_build_identity = cursor.opaque(MAX_PINNED_OPAQUE_ARTIFACT_BYTES)?;
    let compiled_build_instance_id = cursor.array::<32>()?;
    let compiled_compatibility_digest = cursor.digest()?;
    let admission_policy_fingerprint = cursor.digest()?;
    let channel_policy_fingerprint = cursor.digest()?;
    let controller_key_fingerprint = cursor.digest()?;

    let tenure_count = cursor.count(MAX_RUNTIME_TENURE_NONCES)?;
    let mut tenure_nonces = Vec::with_capacity(tenure_count);
    for _ in 0..tenure_count {
        tenure_nonces.push(ReplayLedgerRecord {
            identity: cursor.digest()?,
            value_digest: cursor.digest()?,
        });
    }
    let request_count = cursor.count(MAX_RUNTIME_REQUEST_NONCES)?;
    let mut request_nonces = Vec::with_capacity(request_count);
    for _ in 0..request_count {
        request_nonces.push(ReplayLedgerRecord {
            identity: cursor.digest()?,
            value_digest: cursor.digest()?,
        });
    }
    let temporal_count = cursor.count(MAX_RUNTIME_TEMPORAL_LINEAGES)?;
    let mut temporal_lineages = Vec::with_capacity(temporal_count);
    for _ in 0..temporal_count {
        temporal_lineages.push(TemporalLineageRecord {
            constraint_id: cursor.array::<16>()?,
            source_scope: cursor.array::<16>()?,
            target_fingerprint: cursor.digest()?,
            original_budget_nanos: cursor.u64()?,
            remaining_budget_nanos: cursor.u64()?,
            clock_generation: cursor.u64()?,
            deadline_nanos: cursor.u64()?,
            lineage_digest: cursor.digest()?,
        });
    }

    let writer_fence = if cursor.presence()? {
        Some(WriterFenceRecord {
            source_scope: cursor.array::<16>()?,
            writer: cursor.array::<16>()?,
            epoch: cursor.u64()?,
            proof_envelope_digest: cursor.digest()?,
            tenure_nonce_identity: cursor.digest()?,
            principal: cursor.array::<16>()?,
        })
    } else {
        None
    };

    let source_revision_high_water = if cursor.presence()? {
        Some(SourceRevisionHighWater {
            source_scope: cursor.array::<16>()?,
            revision: cursor.u64()?,
        })
    } else {
        None
    };

    let prepared = if cursor.presence()? {
        Some(PreparedOperation {
            source_scope: cursor.array::<16>()?,
            operation_id: cursor.array::<16>()?,
            source_revision: cursor.u64()?,
            request: cursor.opaque(MAX_OPAQUE_REQUEST_OR_SLICE_BYTES)?,
            request_nonce_identity: cursor.digest()?,
            source_plan_digest: SourcePlanDigest::new(cursor.digest()?),
            incoming_slice_digest: TargetSliceDigest::new(cursor.digest()?),
            incoming_kind: DesiredHeadKind::decode(cursor.u8()?)?,
            manifest_digest: cursor.digest()?,
            expected_active: decode_expected_active(&mut cursor)?,
            temporal_constraint_id: cursor.array::<16>()?,
            temporal_lineage_digest: cursor.digest()?,
            installed_clock_generation: cursor.u64()?,
            installed_deadline_nanos: cursor.u64()?,
            phase: PreparedPhase::decode(cursor.u8()?)?,
            action: decode_optional_action(&mut cursor)?,
            retiring: if cursor.presence()? {
                Some(RetiringLiveFacts {
                    old_slice: cursor.opaque(MAX_OPAQUE_REQUEST_OR_SLICE_BYTES)?,
                    old_source_plan_digest: SourcePlanDigest::new(cursor.digest()?),
                    old_manifest_digest: cursor.digest()?,
                    signed_start_budget_nanos: cursor.u64()?,
                    signed_drain_budget_nanos: cursor.u64()?,
                    signed_cleanup_budget_nanos: cursor.u64()?,
                    old_runtime_host_epoch: cursor.u64()?,
                    old_clock_generation: cursor.u64()?,
                    old_resource_generation: cursor.u64()?,
                    old_resource_census_digest: cursor.digest()?,
                })
            } else {
                None
            },
            raw_outcome: decode_optional_raw_outcome(&mut cursor)?,
        })
    } else {
        None
    };

    let active_desired = if cursor.presence()? {
        Some(ActiveDesiredHead {
            kind: DesiredHeadKind::decode(cursor.u8()?)?,
            source_scope: cursor.array::<16>()?,
            source_revision: cursor.u64()?,
            slice: cursor.opaque(MAX_OPAQUE_REQUEST_OR_SLICE_BYTES)?,
            source_plan_digest: SourcePlanDigest::new(cursor.digest()?),
            manifest_digest: cursor.digest()?,
            operation_id: cursor.array::<16>()?,
            committing_result_digest: cursor.optional_digest()?,
        })
    } else {
        None
    };

    let live_materialization = decode_live_materialization(&mut cursor)?;

    let recovery_action = if cursor.presence()? {
        Some(decode_recovery_action(&mut cursor)?)
    } else {
        None
    };

    let recovery_terminal_count = cursor.count(MAX_RUNTIME_RECOVERY_TERMINALS)?;
    let mut recovery_terminals = Vec::with_capacity(recovery_terminal_count);
    for _ in 0..recovery_terminal_count {
        recovery_terminals.push(RecoveryTerminalRecord {
            recovery: decode_recovery_action(&mut cursor)?,
            selection: decode_terminal_selection(&mut cursor)?,
            resource_census_digest: cursor.digest()?,
            failure_latch_digest: cursor.optional_digest()?,
            completion_runtime_host_epoch: cursor.u64()?,
            completion_snapshot_sequence: cursor.u64()?,
        });
    }

    let resource_count = cursor.count(MAX_RUNTIME_OWNED_RESOURCES)?;
    let mut owned_resources = Vec::with_capacity(resource_count);
    for _ in 0..resource_count {
        owned_resources.push(OwnedResourceRecord {
            kind: ResourceKind::decode(cursor.u8()?)?,
            logical_ref: cursor.array::<16>()?,
            generation: cursor.u64()?,
            runtime_host_epoch: cursor.u64()?,
            phase: ResourcePhase::decode(cursor.u8()?)?,
            action_id: cursor.optional_ref16()?,
            os_identity: cursor.optional_opaque(MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES)?,
            workspace_identity: cursor.optional_opaque(MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES)?,
            containment_identity: cursor.optional_opaque(MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES)?,
            tombstone_evidence: cursor.optional_opaque(MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES)?,
        });
    }

    let terminal_count = cursor.count(MAX_RUNTIME_TERMINAL_OPERATIONS)?;
    let mut terminal_operations = Vec::with_capacity(terminal_count);
    for _ in 0..terminal_count {
        terminal_operations.push(TerminalOperationRecord {
            source_scope: cursor.array::<16>()?,
            operation_id: cursor.array::<16>()?,
            request_digest: cursor.digest()?,
            request_nonce_identity: cursor.digest()?,
            source_revision: cursor.u64()?,
            source_plan_digest: SourcePlanDigest::new(cursor.digest()?),
            target_slice_digest: TargetSliceDigest::new(cursor.digest()?),
            temporal_constraint_id: cursor.array::<16>()?,
            temporal_lineage_digest: cursor.digest()?,
            incoming_kind: DesiredHeadKind::decode(cursor.u8()?)?,
            completion_predecessor_phase: PreparedPhase::decode(cursor.u8()?)?,
            installed_clock_generation: cursor.u64()?,
            installed_deadline_nanos: cursor.u64()?,
            action: decode_optional_action(&mut cursor)?,
            predecessor_raw_outcome: decode_optional_raw_outcome(&mut cursor)?,
            selection: decode_terminal_selection(&mut cursor)?,
            head_disposition: match cursor.u8()? {
                0 => TerminalHeadDisposition::Preserved(None),
                1 => TerminalHeadDisposition::Preserved(Some(TargetSliceDigest::new(
                    cursor.digest()?,
                ))),
                2 => TerminalHeadDisposition::CommittedIncoming,
                _ => return Err(RuntimeJournalError::UnknownEnumValue),
            },
            resource_census_digest: cursor.digest()?,
            result_digest: cursor.digest()?,
            canonical_response: cursor.opaque(MAX_RUNTIME_TERMINAL_RESPONSE_BYTES)?,
            completion_runtime_host_epoch: cursor.u64()?,
            completion_snapshot_sequence: cursor.u64()?,
        });
    }
    cursor.finish()?;

    Ok(RuntimeJournalState {
        last_transaction,
        host: HostClockAdmissionState {
            runtime_host_epoch_high_water,
            clock_domain,
            clock_generation_high_water,
            build_descriptor,
            singleton_manifest,
            store_pinned_build_identity,
            compiled_build_instance_id,
            compiled_compatibility_digest,
            admission_policy_fingerprint,
            channel_policy_fingerprint,
            controller_key_fingerprint,
            tenure_nonces,
            request_nonces,
            temporal_lineages,
        },
        writer_fence,
        source_revision_high_water,
        prepared,
        active_desired,
        live_materialization,
        recovery_action,
        recovery_terminals,
        owned_resources,
        terminal_operations,
    })
}

fn decode_action(cursor: &mut Cursor<'_>) -> Result<JournalActionRef, RuntimeJournalError> {
    Ok(JournalActionRef {
        action_id: cursor.array::<16>()?,
        kind: JournalActionKind::decode(cursor.u8()?)?,
        runtime_host_epoch: cursor.u64()?,
        clock_generation: cursor.u64()?,
        domain_generation: cursor.u64()?,
        instance_generation: cursor.u64()?,
        resource_generation: cursor.u64()?,
    })
}

fn decode_recovery_action(cursor: &mut Cursor<'_>) -> Result<RecoveryAction, RuntimeJournalError> {
    Ok(RecoveryAction {
        action: decode_action(cursor)?,
        source_scope: cursor.array::<16>()?,
        source_revision: cursor.u64()?,
        source_plan_digest: SourcePlanDigest::new(cursor.digest()?),
        active_slice_digest: TargetSliceDigest::new(cursor.digest()?),
        manifest_digest: cursor.digest()?,
        store_pinned_build_identity_digest: cursor.digest()?,
        compiled_build_instance_id: cursor.array::<32>()?,
        compiled_compatibility_digest: cursor.digest()?,
        signed_start_budget_nanos: cursor.u64()?,
        deadline_nanos: cursor.u64()?,
        deadline_evidence_digest: cursor.digest()?,
        phase: RecoveryPhase::decode(cursor.u8()?)?,
        raw_outcome: decode_optional_raw_outcome(cursor)?,
    })
}

fn decode_terminal_selection(
    cursor: &mut Cursor<'_>,
) -> Result<TerminalOutcomeSelection, RuntimeJournalError> {
    Ok(TerminalOutcomeSelection {
        primary: TerminalOutcome::decode(cursor.u8()?)?,
        raw: decode_raw_outcome(cursor)?,
        selection_clock_generation: cursor.u64()?,
        selection_observed_at_nanos: cursor.u64()?,
        lifecycle_effect: TerminalLifecycleEffect::decode(cursor.u8()?)?,
    })
}

fn decode_expected_active(
    cursor: &mut Cursor<'_>,
) -> Result<ExpectedActiveCas, RuntimeJournalError> {
    match cursor.u8()? {
        0 => Ok(ExpectedActiveCas::None),
        1 => Ok(ExpectedActiveCas::Exact(TargetSliceDigest::new(
            cursor.digest()?,
        ))),
        _ => Err(RuntimeJournalError::UnknownEnumValue),
    }
}

fn decode_optional_action(
    cursor: &mut Cursor<'_>,
) -> Result<Option<JournalActionRef>, RuntimeJournalError> {
    if cursor.presence()? {
        Ok(Some(decode_action(cursor)?))
    } else {
        Ok(None)
    }
}

fn decode_optional_raw_outcome(
    cursor: &mut Cursor<'_>,
) -> Result<Option<RawActionOutcomeLatch>, RuntimeJournalError> {
    if !cursor.presence()? {
        return Ok(None);
    }
    Ok(Some(decode_raw_outcome(cursor)?))
}

fn decode_raw_outcome(
    cursor: &mut Cursor<'_>,
) -> Result<RawActionOutcomeLatch, RuntimeJournalError> {
    Ok(RawActionOutcomeLatch {
        callback: CallbackOutcome::decode(cursor.u8()?)?,
        callback_reason_digest: cursor.optional_digest()?,
        deadline: DeadlineOutcome::decode(cursor.u8()?)?,
        observed_clock_generation: cursor.u64()?,
        observed_at_nanos: cursor.u64()?,
        host_interrupted: cursor.boolean()?,
        higher_tenure_takeover: cursor.boolean()?,
        cleanup: CleanupOutcome::decode(cursor.u8()?)?,
        cleanup_evidence_digest: cursor.optional_digest()?,
    })
}

fn decode_live_materialization(
    cursor: &mut Cursor<'_>,
) -> Result<LiveMaterialization, RuntimeJournalError> {
    match cursor.u8()? {
        0 => Ok(LiveMaterialization::None),
        1 => Ok(LiveMaterialization::StartupInvalidated {
            active_slice_digest: cursor.optional_digest()?.map(TargetSliceDigest::new),
            previous_runtime_host_epoch: cursor.u64()?,
            previous_clock_generation: cursor.u64()?,
            recovery_eligibility: StartupRecoveryEligibility::decode(cursor.u8()?)?,
            invalidation_evidence_digest: cursor.digest()?,
            failure_evidence_digest: cursor.optional_digest()?,
            resource_census_digest: cursor.digest()?,
        }),
        2 => Ok(LiveMaterialization::Recovering {
            active_slice_digest: TargetSliceDigest::new(cursor.digest()?),
            action_id: cursor.array::<16>()?,
            resource_generation: cursor.u64()?,
            resource_census_digest: cursor.digest()?,
        }),
        3 => Ok(LiveMaterialization::LiveReady {
            active_slice_digest: TargetSliceDigest::new(cursor.digest()?),
            runtime_host_epoch: cursor.u64()?,
            resource_generation: cursor.u64()?,
            resource_census_digest: cursor.digest()?,
        }),
        4 => Ok(LiveMaterialization::RecoveryFailedNotReady {
            active_slice_digest: TargetSliceDigest::new(cursor.digest()?),
            terminal_recovery_action_id: cursor.array::<16>()?,
            failure_latch_digest: cursor.digest()?,
            resource_census_digest: cursor.digest()?,
        }),
        5 => Ok(LiveMaterialization::Draining {
            active_slice_digest: TargetSliceDigest::new(cursor.digest()?),
            operation_id: cursor.array::<16>()?,
            action_id: cursor.array::<16>()?,
            retiring_generation: cursor.u64()?,
            resource_census_digest: cursor.digest()?,
        }),
        6 => Ok(LiveMaterialization::ExactZero {
            active_slice_digest: TargetSliceDigest::new(cursor.digest()?),
            census_digest: cursor.digest()?,
        }),
        7 => Ok(LiveMaterialization::Quarantined {
            active_slice_digest: cursor.optional_digest()?.map(TargetSliceDigest::new),
            reason_digest: cursor.digest()?,
            resource_census_digest: cursor.digest()?,
        }),
        _ => Err(RuntimeJournalError::UnknownEnumValue),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RuntimeJournalError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RuntimeJournalError::IntegerOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(RuntimeJournalError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RuntimeJournalError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RuntimeJournalError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, RuntimeJournalError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, RuntimeJournalError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], RuntimeJournalError> {
        self.take(LENGTH)?
            .try_into()
            .map_err(|_| RuntimeJournalError::Truncated)
    }

    fn boolean(&mut self) -> Result<bool, RuntimeJournalError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(RuntimeJournalError::UnknownEnumValue),
        }
    }

    fn presence(&mut self) -> Result<bool, RuntimeJournalError> {
        self.boolean()
    }

    fn digest(&mut self) -> Result<Digest32, RuntimeJournalError> {
        Ok(Digest32::from_bytes(self.array::<32>()?))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, RuntimeJournalError> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            return Err(RuntimeJournalError::CapacityExceeded);
        }
        Ok(count)
    }

    fn opaque(&mut self, maximum: usize) -> Result<OpaqueCanonicalValue, RuntimeJournalError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| RuntimeJournalError::IntegerOverflow)?;
        if length == 0 {
            return Err(RuntimeJournalError::EmptyOpaqueValue);
        }
        if length > maximum {
            return Err(RuntimeJournalError::OpaqueValueTooLarge);
        }
        let canonical_bytes = self.take(length)?;
        let digest = self.digest()?;
        OpaqueCanonicalValue::try_new(canonical_bytes, digest, maximum)
    }

    fn optional_digest(&mut self) -> Result<Option<Digest32>, RuntimeJournalError> {
        if self.presence()? {
            Ok(Some(self.digest()?))
        } else {
            Ok(None)
        }
    }

    fn optional_ref16(&mut self) -> Result<Option<Ref16>, RuntimeJournalError> {
        if self.presence()? {
            Ok(Some(self.array::<16>()?))
        } else {
            Ok(None)
        }
    }

    fn optional_opaque(
        &mut self,
        maximum: usize,
    ) -> Result<Option<OpaqueCanonicalValue>, RuntimeJournalError> {
        if self.presence()? {
            Ok(Some(self.opaque(maximum)?))
        } else {
            Ok(None)
        }
    }

    fn finish(self) -> Result<(), RuntimeJournalError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(RuntimeJournalError::TrailingBytes)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeJournalError {
    InvalidMagic,
    UnsupportedEnvelopeVersion,
    WrongOwnerKind,
    UnsupportedPayloadVersion,
    UnsupportedChecksumProfile,
    ZeroStoreInstanceId,
    ZeroDigest,
    ZeroReference,
    InvalidSequence,
    SequenceOverflow,
    SnapshotTooLarge,
    LengthBomb,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    NonCanonicalEncoding,
    NonCanonicalOrdering,
    UnknownEnumValue,
    EmptyOpaqueValue,
    OpaqueValueTooLarge,
    CapacityExceeded,
    MultipleSourceScopes,
    MultipleOwnerActions,
    DanglingReference,
    InvalidStateInvariant,
    NonMonotonicTransition,
    IntegerOverflow,
    Digest(DigestBuildError),
}

impl From<DigestBuildError> for RuntimeJournalError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

impl fmt::Display for RuntimeJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMagic => "invalid Runtime journal magic",
            Self::UnsupportedEnvelopeVersion => "unsupported Runtime journal envelope version",
            Self::WrongOwnerKind => "Runtime journal owner kind mismatch",
            Self::UnsupportedPayloadVersion => "unsupported Runtime journal payload version",
            Self::UnsupportedChecksumProfile => "unsupported Runtime journal checksum profile",
            Self::ZeroStoreInstanceId => "Runtime journal store identity is zero",
            Self::ZeroDigest => "Runtime journal digest is zero",
            Self::ZeroReference => "Runtime journal reference is zero",
            Self::InvalidSequence => "Runtime journal sequence must be nonzero",
            Self::SequenceOverflow => "Runtime journal sequence overflow",
            Self::SnapshotTooLarge => "Runtime journal snapshot exceeds its bound",
            Self::LengthBomb => "Runtime journal payload length exceeds its bound",
            Self::Truncated => "Runtime journal snapshot is truncated",
            Self::TrailingBytes => "Runtime journal snapshot has trailing bytes",
            Self::ChecksumMismatch => "Runtime journal checksum mismatch",
            Self::NonCanonicalEncoding => "Runtime journal payload is not canonical",
            Self::NonCanonicalOrdering => "Runtime journal records are not canonically ordered",
            Self::UnknownEnumValue => "Runtime journal contains an unknown enum value",
            Self::EmptyOpaqueValue => "Runtime journal opaque value is empty",
            Self::OpaqueValueTooLarge => "Runtime journal opaque value exceeds its local bound",
            Self::CapacityExceeded => "Runtime journal capacity exceeded",
            Self::MultipleSourceScopes => "Runtime journal contains multiple source scopes",
            Self::MultipleOwnerActions => "Runtime journal contains multiple owner actions",
            Self::DanglingReference => "Runtime journal contains a dangling reference",
            Self::InvalidStateInvariant => "Runtime journal state invariant failed",
            Self::NonMonotonicTransition => "Runtime journal transition is not monotonic",
            Self::IntegerOverflow => "Runtime journal integer conversion overflow",
            Self::Digest(_) => "Runtime journal checksum construction failed",
        })
    }
}

impl std::error::Error for RuntimeJournalError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn source_plan_digest(byte: u8) -> SourcePlanDigest {
        SourcePlanDigest::new(digest(byte))
    }

    fn target_slice_digest(byte: u8) -> TargetSliceDigest {
        TargetSliceDigest::new(digest(byte))
    }

    fn opaque_target_slice(value: &OpaqueCanonicalValue) -> TargetSliceDigest {
        TargetSliceDigest::new(value.digest)
    }

    fn indexed_digest(index: usize) -> Digest32 {
        let mut bytes = [0_u8; 32];
        bytes[30..].copy_from_slice(
            &u16::try_from(index + 1)
                .expect("fixture digest index must fit")
                .to_be_bytes(),
        );
        Digest32::from_bytes(bytes)
    }

    fn indexed_ref(index: usize) -> Ref16 {
        let mut bytes = [0_u8; 16];
        bytes[14..].copy_from_slice(
            &u16::try_from(index + 1)
                .expect("fixture ref index must fit")
                .to_be_bytes(),
        );
        bytes
    }

    fn opaque(bytes: &[u8], digest_byte: u8) -> OpaqueCanonicalValue {
        OpaqueCanonicalValue::try_request_or_slice(bytes, digest(digest_byte))
            .expect("fixture opaque value must validate")
    }

    fn pinned(bytes: &[u8], digest_byte: u8) -> OpaqueCanonicalValue {
        OpaqueCanonicalValue::try_pinned_artifact(bytes, digest(digest_byte))
            .expect("fixture pinned value must validate")
    }

    fn evidence(bytes: &[u8], digest_byte: u8) -> OpaqueCanonicalValue {
        OpaqueCanonicalValue::try_new(
            bytes,
            digest(digest_byte),
            MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES,
        )
        .expect("fixture evidence must validate")
    }

    fn owned_resource(
        kind: ResourceKind,
        logical_ref: Ref16,
        generation: u64,
        runtime_host_epoch: u64,
        action_id: Option<Ref16>,
        byte: u8,
    ) -> OwnedResourceRecord {
        OwnedResourceRecord {
            kind,
            logical_ref,
            generation,
            runtime_host_epoch,
            phase: ResourcePhase::Owned,
            action_id,
            os_identity: Some(evidence(b"os-identity", byte)),
            workspace_identity: Some(evidence(b"workspace-identity", byte.wrapping_add(1))),
            containment_identity: Some(evidence(b"containment-identity", byte.wrapping_add(2))),
            tombstone_evidence: None,
        }
    }

    struct TerminalIdentityFixture {
        operation_id: Ref16,
        request_digest: Digest32,
        request_nonce_identity: Digest32,
        source_revision: u64,
        source_plan_digest: SourcePlanDigest,
        target_slice_digest: TargetSliceDigest,
        temporal_constraint_id: Ref16,
        temporal_lineage_digest: Digest32,
    }

    impl TerminalIdentityFixture {
        fn from_prepared(prepared: &PreparedOperation) -> Self {
            Self {
                operation_id: prepared.operation_id,
                request_digest: prepared.request.digest,
                request_nonce_identity: prepared.request_nonce_identity,
                source_revision: prepared.source_revision,
                source_plan_digest: prepared.source_plan_digest,
                target_slice_digest: prepared.incoming_slice_digest,
                temporal_constraint_id: prepared.temporal_constraint_id,
                temporal_lineage_digest: prepared.temporal_lineage_digest,
            }
        }
    }

    fn terminal_record_for(
        identity: TerminalIdentityFixture,
        outcome: TerminalOutcome,
        result_byte: u8,
        census_digest: Digest32,
        completion_snapshot_sequence: u64,
    ) -> TerminalOperationRecord {
        let incoming_kind = if matches!(
            outcome,
            TerminalOutcome::EmptyDeactivateExactZero
                | TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects
                | TerminalOutcome::StopFailedButExactZero
                | TerminalOutcome::TimedOutButExactZero
                | TerminalOutcome::InterruptedButNowExactZero
        ) {
            DesiredHeadKind::EmptyDeactivate
        } else {
            DesiredHeadKind::OneSourceLoop
        };
        let completion_predecessor_phase = match outcome {
            TerminalOutcome::StartTimedOutBeforeIntentNoEffects
            | TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects => {
                PreparedPhase::PreparedNoEffects
            }
            TerminalOutcome::AbortedBeforeIntentNoEffects => PreparedPhase::StartupExpiredNoEffects,
            TerminalOutcome::EmptyDeactivateExactZero
            | TerminalOutcome::StopFailedButExactZero
            | TerminalOutcome::TimedOutButExactZero
            | TerminalOutcome::InterruptedButNowExactZero => {
                PreparedPhase::HeadCommittedRetiringOld
            }
            _ => PreparedPhase::FirstActionIntent,
        };
        let installed_clock_generation = 5;
        let installed_deadline_nanos = 10_000;
        let (raw, lifecycle_effect) = match outcome {
            TerminalOutcome::OneSourceLoopActive => (
                RawActionOutcomeLatch {
                    callback: CallbackOutcome::KnownSuccess,
                    callback_reason_digest: None,
                    deadline: DeadlineOutcome::NotObserved,
                    observed_clock_generation: 0,
                    observed_at_nanos: 0,
                    host_interrupted: false,
                    higher_tenure_takeover: false,
                    cleanup: CleanupOutcome::NotObserved,
                    cleanup_evidence_digest: None,
                },
                TerminalLifecycleEffect::MayHaveStarted,
            ),
            TerminalOutcome::StartTimedOutBeforeIntentNoEffects
            | TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects => (
                RawActionOutcomeLatch {
                    callback: CallbackOutcome::NotInvoked,
                    callback_reason_digest: None,
                    deadline: DeadlineOutcome::TimedOut,
                    observed_clock_generation: installed_clock_generation,
                    observed_at_nanos: installed_deadline_nanos,
                    host_interrupted: false,
                    higher_tenure_takeover: false,
                    cleanup: CleanupOutcome::NotObserved,
                    cleanup_evidence_digest: None,
                },
                TerminalLifecycleEffect::ProvenNotStarted,
            ),
            TerminalOutcome::AbortedBeforeIntentNoEffects => (
                RawActionOutcomeLatch {
                    callback: CallbackOutcome::NotInvoked,
                    callback_reason_digest: None,
                    deadline: DeadlineOutcome::NotObserved,
                    observed_clock_generation: 0,
                    observed_at_nanos: 0,
                    host_interrupted: true,
                    higher_tenure_takeover: false,
                    cleanup: CleanupOutcome::NotObserved,
                    cleanup_evidence_digest: None,
                },
                TerminalLifecycleEffect::ProvenNotStarted,
            ),
            _ => {
                let callback = if matches!(
                    outcome,
                    TerminalOutcome::StartFailedBeforeHeadCommitExactZero
                        | TerminalOutcome::StopFailedButExactZero
                ) {
                    CallbackOutcome::KnownError
                } else {
                    CallbackOutcome::KnownSuccess
                };
                (
                    RawActionOutcomeLatch {
                        callback,
                        callback_reason_digest: (callback == CallbackOutcome::KnownError)
                            .then(|| digest(0xa0)),
                        deadline: if matches!(
                            outcome,
                            TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero
                                | TerminalOutcome::TimedOutButExactZero
                        ) {
                            DeadlineOutcome::TimedOut
                        } else {
                            DeadlineOutcome::NotObserved
                        },
                        observed_clock_generation: if matches!(
                            outcome,
                            TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero
                                | TerminalOutcome::TimedOutButExactZero
                        ) {
                            installed_clock_generation
                        } else {
                            0
                        },
                        observed_at_nanos: if matches!(
                            outcome,
                            TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero
                                | TerminalOutcome::TimedOutButExactZero
                        ) {
                            installed_deadline_nanos
                        } else {
                            0
                        },
                        host_interrupted: matches!(
                            outcome,
                            TerminalOutcome::AbortedBeforeHeadCommitExactZero
                                | TerminalOutcome::InterruptedButNowExactZero
                        ),
                        higher_tenure_takeover: outcome
                            == TerminalOutcome::SupersededAfterIntentExactZero,
                        cleanup: CleanupOutcome::ExactZero,
                        cleanup_evidence_digest: Some(digest(0xa1)),
                    },
                    TerminalLifecycleEffect::MayHaveStarted,
                )
            }
        };
        let selection_observed_at_nanos = if raw.deadline == DeadlineOutcome::TimedOut {
            installed_deadline_nanos
        } else {
            installed_deadline_nanos - 1
        };
        let selection = TerminalOutcomeSelection::try_select(
            TerminalSelectionContext {
                incoming_kind,
                predecessor_phase: completion_predecessor_phase,
                installed_clock_generation,
                installed_deadline_nanos,
            },
            TerminalSelectionObservation {
                raw,
                selection_clock_generation: installed_clock_generation,
                selection_observed_at_nanos,
                lifecycle_effect,
            },
        )
        .expect("fixture terminal selection must validate");
        assert_eq!(selection.primary, outcome);
        let action = completion_predecessor_phase
            .requires_action()
            .then_some(JournalActionRef {
                action_id: identity.operation_id,
                kind: match incoming_kind {
                    DesiredHeadKind::OneSourceLoop => JournalActionKind::StartOneSourceLoop,
                    DesiredHeadKind::EmptyDeactivate => JournalActionKind::DrainToEmpty,
                },
                runtime_host_epoch: 3,
                clock_generation: installed_clock_generation,
                domain_generation: 1,
                instance_generation: 1,
                resource_generation: 1,
            });
        TerminalOperationRecord {
            source_scope: [0x01; 16],
            operation_id: identity.operation_id,
            request_digest: identity.request_digest,
            request_nonce_identity: identity.request_nonce_identity,
            source_revision: identity.source_revision,
            source_plan_digest: identity.source_plan_digest,
            target_slice_digest: identity.target_slice_digest,
            temporal_constraint_id: identity.temporal_constraint_id,
            temporal_lineage_digest: identity.temporal_lineage_digest,
            incoming_kind,
            completion_predecessor_phase,
            installed_clock_generation,
            installed_deadline_nanos,
            action,
            predecessor_raw_outcome: None,
            selection,
            head_disposition: if terminal_head_commits_incoming(outcome, incoming_kind) {
                TerminalHeadDisposition::CommittedIncoming
            } else {
                TerminalHeadDisposition::Preserved(None)
            },
            resource_census_digest: census_digest,
            result_digest: digest(result_byte),
            canonical_response: opaque(b"terminal-response", result_byte),
            completion_runtime_host_epoch: 3,
            completion_snapshot_sequence,
        }
    }

    fn terminal_record_for_prepared(
        prepared: &PreparedOperation,
        outcome: TerminalOutcome,
        result_byte: u8,
        census_digest: Digest32,
        completion_snapshot_sequence: u64,
        preserved_head: Option<TargetSliceDigest>,
    ) -> TerminalOperationRecord {
        let mut terminal = terminal_record_for(
            TerminalIdentityFixture::from_prepared(prepared),
            outcome,
            result_byte,
            census_digest,
            completion_snapshot_sequence,
        );
        terminal.incoming_kind = prepared.incoming_kind;
        terminal.completion_predecessor_phase = prepared.phase;
        terminal.installed_clock_generation = prepared.installed_clock_generation;
        terminal.installed_deadline_nanos = prepared.installed_deadline_nanos;
        terminal.action = prepared.action;
        terminal.predecessor_raw_outcome = prepared.raw_outcome;
        let generated_raw = terminal.selection.raw;
        let mut lifecycle_effect = terminal.selection.lifecycle_effect;
        let mut raw = prepared.raw_outcome.unwrap_or(generated_raw);
        if prepared.phase == PreparedPhase::PreparedNoEffects
            && prepared.incoming_kind == DesiredHeadKind::EmptyDeactivate
            && outcome == TerminalOutcome::EmptyDeactivateExactZero
        {
            raw = RawActionOutcomeLatch {
                callback: CallbackOutcome::NotInvoked,
                callback_reason_digest: None,
                deadline: DeadlineOutcome::NotObserved,
                observed_clock_generation: 0,
                observed_at_nanos: 0,
                host_interrupted: false,
                higher_tenure_takeover: false,
                cleanup: CleanupOutcome::NotObserved,
                cleanup_evidence_digest: None,
            };
            lifecycle_effect = TerminalLifecycleEffect::ProvenNotStarted;
        }
        if prepared.phase == PreparedPhase::SupersededBeforeEffects
            && outcome == TerminalOutcome::AbortedBeforeIntentNoEffects
        {
            raw = RawActionOutcomeLatch {
                callback: CallbackOutcome::NotInvoked,
                callback_reason_digest: None,
                deadline: DeadlineOutcome::NotObserved,
                observed_clock_generation: 0,
                observed_at_nanos: 0,
                host_interrupted: false,
                higher_tenure_takeover: true,
                cleanup: CleanupOutcome::NotObserved,
                cleanup_evidence_digest: None,
            };
            lifecycle_effect = TerminalLifecycleEffect::ProvenNotStarted;
        }
        if prepared.raw_outcome.is_some()
            && generated_raw.cleanup == CleanupOutcome::ExactZero
            && raw.cleanup == CleanupOutcome::NotObserved
        {
            raw.cleanup = CleanupOutcome::ExactZero;
            raw.cleanup_evidence_digest = generated_raw.cleanup_evidence_digest;
        }
        if raw.deadline != DeadlineOutcome::NotObserved {
            raw.observed_clock_generation = prepared.installed_clock_generation;
            if raw.deadline == DeadlineOutcome::TimedOut {
                raw.observed_at_nanos = prepared.installed_deadline_nanos;
            }
        }
        let selection_observed_at_nanos = if raw.deadline == DeadlineOutcome::TimedOut {
            prepared.installed_deadline_nanos
        } else {
            prepared.installed_deadline_nanos - 1
        };
        terminal.selection = TerminalOutcomeSelection::try_select(
            TerminalSelectionContext {
                incoming_kind: prepared.incoming_kind,
                predecessor_phase: prepared.phase,
                installed_clock_generation: prepared.installed_clock_generation,
                installed_deadline_nanos: prepared.installed_deadline_nanos,
            },
            TerminalSelectionObservation {
                raw,
                selection_clock_generation: prepared.installed_clock_generation,
                selection_observed_at_nanos,
                lifecycle_effect,
            },
        )
        .expect("prepared terminal selection must validate");
        assert_eq!(terminal.selection.primary, outcome);
        terminal.head_disposition =
            if terminal_head_commits_incoming(outcome, prepared.incoming_kind) {
                TerminalHeadDisposition::CommittedIncoming
            } else {
                TerminalHeadDisposition::Preserved(preserved_head)
            };
        terminal
    }

    fn recovery_terminal_record(
        recovery: RecoveryAction,
        observation: TerminalSelectionObservation,
        resource_census_digest: Digest32,
        completion: (u64, u64),
    ) -> RecoveryTerminalRecord {
        let selection = TerminalOutcomeSelection::try_select(
            TerminalSelectionContext {
                incoming_kind: DesiredHeadKind::OneSourceLoop,
                predecessor_phase: recovery_predecessor_phase(recovery.phase),
                installed_clock_generation: recovery.action.clock_generation,
                installed_deadline_nanos: recovery.deadline_nanos,
            },
            observation,
        )
        .expect("fixture recovery terminal selection must validate");
        let failure_latch_digest = (!matches!(
            selection.primary,
            TerminalOutcome::OneSourceLoopActive | TerminalOutcome::AbortedBeforeIntentNoEffects
        ))
        .then(|| {
            recovery_failure_evidence_digest(recovery, selection, resource_census_digest)
                .expect("fixture recovery failure digest must build")
        });
        RecoveryTerminalRecord {
            recovery,
            selection,
            resource_census_digest,
            failure_latch_digest,
            completion_runtime_host_epoch: completion.0,
            completion_snapshot_sequence: completion.1,
        }
    }

    fn sequence_one_state() -> RuntimeJournalState {
        RuntimeJournalState {
            last_transaction: RuntimeJournalTransaction::Initialized,
            host: HostClockAdmissionState {
                runtime_host_epoch_high_water: 0,
                clock_domain: [0x33; 16],
                clock_generation_high_water: 0,
                build_descriptor: pinned(b"descriptor-v1", 0x44),
                singleton_manifest: pinned(b"manifest-v1", 0x55),
                store_pinned_build_identity: pinned(b"build-identity-v1", 0x56),
                compiled_build_instance_id: [0x57; 32],
                compiled_compatibility_digest: digest(0x58),
                admission_policy_fingerprint: digest(0x66),
                channel_policy_fingerprint: digest(0x67),
                controller_key_fingerprint: digest(0x68),
                tenure_nonces: Vec::new(),
                request_nonces: Vec::new(),
                temporal_lineages: Vec::new(),
            },
            writer_fence: None,
            source_revision_high_water: None,
            prepared: None,
            active_desired: None,
            live_materialization: LiveMaterialization::None,
            recovery_action: None,
            recovery_terminals: Vec::new(),
            owned_resources: Vec::new(),
            terminal_operations: Vec::new(),
        }
    }

    fn initialized_idle_state() -> RuntimeJournalState {
        let mut state = sequence_one_state();
        state.last_transaction = RuntimeJournalTransaction::StartupInvalidation;
        state.host.runtime_host_epoch_high_water = 3;
        state.host.clock_generation_high_water = 5;
        state
    }

    fn active_state() -> RuntimeJournalState {
        let scope = [0x01; 16];
        let active_slice = opaque(b"active-slice-v1", 0x71);
        let request_nonce_identity = digest(0x12);
        let request_digest = digest(0x13);
        let temporal_constraint_id = [0x14; 16];
        let temporal_lineage_digest = digest(0x15);
        let source_plan_digest = source_plan_digest(0x70);
        let operation_id = [0x04; 16];
        let mut state = initialized_idle_state();
        state.host.tenure_nonces = vec![ReplayLedgerRecord {
            identity: digest(0x10),
            value_digest: digest(0x16),
        }];
        state.host.request_nonces = vec![ReplayLedgerRecord {
            identity: request_nonce_identity,
            value_digest: request_digest,
        }];
        state.host.temporal_lineages = vec![TemporalLineageRecord {
            constraint_id: temporal_constraint_id,
            source_scope: scope,
            target_fingerprint: digest(0x22),
            original_budget_nanos: 1_000,
            remaining_budget_nanos: 600,
            clock_generation: 5,
            deadline_nanos: 10_000,
            lineage_digest: temporal_lineage_digest,
        }];
        state.writer_fence = Some(WriterFenceRecord {
            source_scope: scope,
            writer: [0x02; 16],
            epoch: 7,
            proof_envelope_digest: digest(0x16),
            tenure_nonce_identity: digest(0x10),
            principal: [0x03; 16],
        });
        state.source_revision_high_water = Some(SourceRevisionHighWater {
            source_scope: scope,
            revision: 11,
        });
        state.active_desired = Some(ActiveDesiredHead {
            kind: DesiredHeadKind::OneSourceLoop,
            source_scope: scope,
            source_revision: 11,
            slice: active_slice.clone(),
            source_plan_digest,
            manifest_digest: digest(0x55),
            operation_id,
            committing_result_digest: Some(digest(0x75)),
        });
        state.owned_resources = vec![
            owned_resource(ResourceKind::LoopDomain, [0x05; 16], 9, 3, None, 0x72),
            owned_resource(ResourceKind::CardInstance, [0x06; 16], 9, 3, None, 0x76),
        ];
        let census = compute_resource_census_digest(&state.owned_resources)
            .expect("fixture census must build");
        state.live_materialization = LiveMaterialization::LiveReady {
            active_slice_digest: opaque_target_slice(&active_slice),
            runtime_host_epoch: 3,
            resource_generation: 9,
            resource_census_digest: census,
        };
        let mut committing_terminal = terminal_record_for(
            TerminalIdentityFixture {
                operation_id,
                request_digest,
                request_nonce_identity,
                source_revision: 11,
                source_plan_digest,
                target_slice_digest: opaque_target_slice(&active_slice),
                temporal_constraint_id,
                temporal_lineage_digest,
            },
            TerminalOutcome::OneSourceLoopActive,
            0x75,
            census,
            1,
        );
        let producer = committing_terminal
            .action
            .as_mut()
            .expect("fixture active terminal must own its producer action");
        producer.domain_generation = 9;
        producer.instance_generation = 9;
        producer.resource_generation = 9;
        state.terminal_operations = vec![committing_terminal];
        state
    }

    fn draining_state() -> RuntimeJournalState {
        let scope = [0x01; 16];
        let operation_id = [0x42; 16];
        let action_id = [0x43; 16];
        let empty_slice = opaque(b"canonical-empty-v1", 0x81);
        let mut state = active_state();
        let old_active = state
            .active_desired
            .clone()
            .expect("active fixture must exist");
        let old_census = compute_resource_census_digest(&state.owned_resources)
            .expect("fixture census must build");
        let request = opaque(b"signed-empty-request-v1", 0x82);
        let request_nonce_identity = digest(0x83);
        let temporal_constraint_id = [0x44; 16];
        let temporal_lineage_digest = digest(0x45);
        state.host.request_nonces.push(ReplayLedgerRecord {
            identity: request_nonce_identity,
            value_digest: request.digest,
        });
        state.host.temporal_lineages.push(TemporalLineageRecord {
            constraint_id: temporal_constraint_id,
            source_scope: scope,
            target_fingerprint: digest(0x22),
            original_budget_nanos: 2_000,
            remaining_budget_nanos: 1_000,
            clock_generation: 5,
            deadline_nanos: 20_000,
            lineage_digest: temporal_lineage_digest,
        });
        state.source_revision_high_water = Some(SourceRevisionHighWater {
            source_scope: scope,
            revision: 12,
        });
        state.prepared = Some(PreparedOperation {
            source_scope: scope,
            operation_id,
            source_revision: 12,
            request,
            request_nonce_identity,
            source_plan_digest: source_plan_digest(0x80),
            incoming_slice_digest: opaque_target_slice(&empty_slice),
            incoming_kind: DesiredHeadKind::EmptyDeactivate,
            manifest_digest: digest(0x55),
            expected_active: ExpectedActiveCas::Exact(opaque_target_slice(&old_active.slice)),
            temporal_constraint_id,
            temporal_lineage_digest,
            installed_clock_generation: 5,
            installed_deadline_nanos: 20_000,
            phase: PreparedPhase::HeadCommittedRetiringOld,
            action: Some(JournalActionRef {
                action_id,
                kind: JournalActionKind::DrainToEmpty,
                runtime_host_epoch: 3,
                clock_generation: 5,
                domain_generation: 9,
                instance_generation: 9,
                resource_generation: 9,
            }),
            retiring: Some(RetiringLiveFacts {
                old_slice: old_active.slice,
                old_source_plan_digest: old_active.source_plan_digest,
                old_manifest_digest: old_active.manifest_digest,
                signed_start_budget_nanos: 100,
                signed_drain_budget_nanos: 200,
                signed_cleanup_budget_nanos: 300,
                old_runtime_host_epoch: 3,
                old_clock_generation: 5,
                old_resource_generation: 9,
                old_resource_census_digest: old_census,
            }),
            raw_outcome: Some(RawActionOutcomeLatch {
                callback: CallbackOutcome::KnownError,
                callback_reason_digest: Some(digest(0x84)),
                deadline: DeadlineOutcome::TimedOut,
                observed_clock_generation: 5,
                observed_at_nanos: 20_000,
                host_interrupted: false,
                higher_tenure_takeover: false,
                cleanup: CleanupOutcome::Uncertain,
                cleanup_evidence_digest: Some(digest(0x85)),
            }),
        });
        state.active_desired = Some(ActiveDesiredHead {
            kind: DesiredHeadKind::EmptyDeactivate,
            source_scope: scope,
            source_revision: 12,
            slice: empty_slice.clone(),
            source_plan_digest: source_plan_digest(0x80),
            manifest_digest: digest(0x55),
            operation_id,
            committing_result_digest: None,
        });
        for resource in &mut state.owned_resources {
            resource.phase = ResourcePhase::CleanupPending;
            resource.action_id = Some(action_id);
        }
        let census = compute_resource_census_digest(&state.owned_resources)
            .expect("fixture census must build");
        state.live_materialization = LiveMaterialization::Draining {
            active_slice_digest: opaque_target_slice(&empty_slice),
            operation_id,
            action_id,
            retiring_generation: 9,
            resource_census_digest: census,
        };
        state
    }

    fn recovering_state() -> RuntimeJournalState {
        let action_id = [0x91; 16];
        let mut state = active_state();
        let active = state
            .active_desired
            .as_ref()
            .expect("fixture active must exist")
            .clone();
        let active_slice_digest = opaque_target_slice(&active.slice);
        let action = JournalActionRef {
            action_id,
            kind: JournalActionKind::RestartReassembly,
            runtime_host_epoch: 3,
            clock_generation: 5,
            domain_generation: 10,
            instance_generation: 10,
            resource_generation: 10,
        };
        state.recovery_action = Some(RecoveryAction {
            action,
            source_scope: active.source_scope,
            source_revision: active.source_revision,
            source_plan_digest: active.source_plan_digest,
            active_slice_digest,
            manifest_digest: digest(0x55),
            store_pinned_build_identity_digest: digest(0x56),
            compiled_build_instance_id: [0x57; 32],
            compiled_compatibility_digest: digest(0x58),
            signed_start_budget_nanos: 100,
            deadline_nanos: 30_000,
            deadline_evidence_digest: digest(0x94),
            phase: RecoveryPhase::StartCallIntent,
            raw_outcome: Some(RawActionOutcomeLatch {
                callback: CallbackOutcome::UnknownAfterIntent,
                callback_reason_digest: None,
                deadline: DeadlineOutcome::NotObserved,
                observed_clock_generation: 0,
                observed_at_nanos: 0,
                host_interrupted: false,
                higher_tenure_takeover: false,
                cleanup: CleanupOutcome::NotObserved,
                cleanup_evidence_digest: None,
            }),
        });
        state.owned_resources = vec![
            OwnedResourceRecord {
                kind: ResourceKind::LoopDomain,
                logical_ref: [0x92; 16],
                generation: 10,
                runtime_host_epoch: 3,
                phase: ResourcePhase::Reserved,
                action_id: Some(action_id),
                os_identity: None,
                workspace_identity: None,
                containment_identity: None,
                tombstone_evidence: None,
            },
            OwnedResourceRecord {
                kind: ResourceKind::CardInstance,
                logical_ref: [0x93; 16],
                generation: 10,
                runtime_host_epoch: 3,
                phase: ResourcePhase::Reserved,
                action_id: Some(action_id),
                os_identity: None,
                workspace_identity: None,
                containment_identity: None,
                tombstone_evidence: None,
            },
        ];
        let census = compute_resource_census_digest(&state.owned_resources)
            .expect("fixture census must build");
        state.live_materialization = LiveMaterialization::Recovering {
            active_slice_digest,
            action_id,
            resource_generation: 10,
            resource_census_digest: census,
        };
        state
    }

    fn snapshot(sequence: u64, state: RuntimeJournalState) -> RuntimeJournalSnapshot {
        RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), sequence, state)
            .expect("fixture snapshot must validate")
    }

    fn validated_successor_chain(
        label: &str,
        first_sequence: u64,
        states: Vec<RuntimeJournalState>,
    ) -> RuntimeJournalSnapshot {
        let mut states = states.into_iter();
        let mut sequence = first_sequence;
        let mut previous = RuntimeJournalSnapshot::try_new(
            [0x11; 32],
            digest(0x22),
            sequence,
            states
                .next()
                .expect("fixture chain must have a starting state"),
        )
        .unwrap_or_else(|error| panic!("{label} state at sequence {sequence}: {error:?}"));
        for state in states {
            sequence += 1;
            let current =
                RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), sequence, state)
                    .unwrap_or_else(|error| {
                        panic!("{label} state at sequence {sequence}: {error:?}")
                    });
            assert_eq!(
                current.validate_successor_of(&previous),
                Ok(()),
                "{label} transition into sequence {sequence} must validate"
            );
            previous = current;
        }
        previous
    }

    fn assert_terminal_outcome(snapshot: &RuntimeJournalSnapshot, expected: TerminalOutcome) {
        assert_eq!(
            snapshot
                .state()
                .terminal_operations
                .last()
                .expect("fixture chain must append a terminal operation")
                .selection
                .primary,
            expected
        );
    }

    fn startup_successor_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::StartupInvalidation;
        current.host.runtime_host_epoch_high_water = previous
            .host
            .runtime_host_epoch_high_water
            .checked_add(1)
            .expect("fixture host epoch must advance");
        current.host.clock_generation_high_water = previous
            .host
            .clock_generation_high_water
            .checked_add(1)
            .expect("fixture clock generation must advance");
        current.prepared = startup_invalidated_prepared(previous.prepared.as_ref())
            .expect("fixture prepared invalidation must derive");
        current.recovery_action = startup_invalidated_recovery(previous.recovery_action)
            .expect("fixture recovery invalidation must derive");
        let (recovery_eligibility, failure_evidence_digest) =
            startup_eligibility(previous).expect("fixture eligibility must derive");
        let resource_census_digest = compute_resource_census_digest(&previous.owned_resources)
            .expect("fixture census must build");
        current.live_materialization = LiveMaterialization::StartupInvalidated {
            active_slice_digest: previous
                .active_desired
                .as_ref()
                .map(|active| opaque_target_slice(&active.slice)),
            previous_runtime_host_epoch: previous.host.runtime_host_epoch_high_water,
            previous_clock_generation: previous.host.clock_generation_high_water,
            recovery_eligibility,
            invalidation_evidence_digest: digest(0xfe),
            failure_evidence_digest,
            resource_census_digest,
        };
        let evidence = startup_invalidation_evidence_digest(previous, &current)
            .expect("fixture invalidation evidence must build");
        let LiveMaterialization::StartupInvalidated {
            invalidation_evidence_digest,
            ..
        } = &mut current.live_materialization
        else {
            unreachable!();
        };
        *invalidation_evidence_digest = evidence;
        current
    }

    fn tenure_successor_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::TenureOnly;
        current.host.tenure_nonces.push(ReplayLedgerRecord {
            identity: digest(0x20),
            value_digest: digest(0x21),
        });
        current.writer_fence = Some(WriterFenceRecord {
            source_scope: [0x01; 16],
            writer: [0x02; 16],
            epoch: 1,
            proof_envelope_digest: digest(0x21),
            tenure_nonce_identity: digest(0x20),
            principal: [0x03; 16],
        });
        current
    }

    fn superseding_tenure_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let old_fence = previous
            .writer_fence
            .expect("fixture writer fence must exist");
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::TenureOnly;
        current.host.tenure_nonces.push(ReplayLedgerRecord {
            identity: digest(0x21),
            value_digest: digest(0x22),
        });
        current.writer_fence = Some(WriterFenceRecord {
            source_scope: old_fence.source_scope,
            writer: [0x23; 16],
            epoch: old_fence.epoch + 1,
            proof_envelope_digest: digest(0x22),
            tenure_nonce_identity: digest(0x21),
            principal: [0x24; 16],
        });
        match (current.prepared.as_mut(), current.recovery_action.as_mut()) {
            (Some(prepared), None) => match prepared.phase {
                PreparedPhase::PreparedNoEffects
                | PreparedPhase::SupersededBeforeEffects
                | PreparedPhase::StartupExpiredNoEffects => {
                    prepared.phase = PreparedPhase::SupersededBeforeEffects;
                }
                PreparedPhase::FirstActionIntent
                | PreparedPhase::HeadCommittedRetiringOld
                | PreparedPhase::SupersededReconcileRequired
                | PreparedPhase::StartupReconcileRequired => {
                    prepared.phase = PreparedPhase::SupersededReconcileRequired;
                    prepared.raw_outcome = Some(takeover_raw(prepared.raw_outcome));
                }
            },
            (None, Some(recovery)) => match recovery.phase {
                RecoveryPhase::RecoveryPlannedNoEffects
                | RecoveryPhase::StartupInvalidatedNoEffects => {}
                RecoveryPhase::StartCallIntent | RecoveryPhase::StartupReconcileRequired => {
                    recovery.raw_outcome = Some(takeover_raw(recovery.raw_outcome));
                }
            },
            _ => panic!("fixture must own exactly one prepared or recovery action"),
        }
        current
    }

    fn admitted_one_source_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let request = opaque(b"one-source-request-with-sole-slice", 0x31);
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::FullAdmission;
        current.host.request_nonces.push(ReplayLedgerRecord {
            identity: digest(0x30),
            value_digest: request.digest,
        });
        current.host.temporal_lineages.push(TemporalLineageRecord {
            constraint_id: [0x32; 16],
            source_scope: [0x01; 16],
            target_fingerprint: digest(0x22),
            original_budget_nanos: 1_000,
            remaining_budget_nanos: 1_000,
            clock_generation: current.host.clock_generation_high_water,
            deadline_nanos: 10_000,
            lineage_digest: digest(0x33),
        });
        current.source_revision_high_water = Some(SourceRevisionHighWater {
            source_scope: [0x01; 16],
            revision: 1,
        });
        current.prepared = Some(PreparedOperation {
            source_scope: [0x01; 16],
            operation_id: [0x34; 16],
            source_revision: 1,
            request,
            request_nonce_identity: digest(0x30),
            source_plan_digest: source_plan_digest(0x35),
            incoming_slice_digest: target_slice_digest(0x36),
            incoming_kind: DesiredHeadKind::OneSourceLoop,
            manifest_digest: digest(0x55),
            expected_active: ExpectedActiveCas::None,
            temporal_constraint_id: [0x32; 16],
            temporal_lineage_digest: digest(0x33),
            installed_clock_generation: current.host.clock_generation_high_water,
            installed_deadline_nanos: 10_000,
            phase: PreparedPhase::PreparedNoEffects,
            action: None,
            retiring: None,
            raw_outcome: None,
        });
        current
    }

    fn one_source_intent_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::PreparedProgress;
        let prepared = current
            .prepared
            .as_mut()
            .expect("fixture prepared must exist");
        prepared.phase = PreparedPhase::FirstActionIntent;
        prepared.action = Some(JournalActionRef {
            action_id: [0x37; 16],
            kind: JournalActionKind::StartOneSourceLoop,
            runtime_host_epoch: current.host.runtime_host_epoch_high_water,
            clock_generation: current.host.clock_generation_high_water,
            domain_generation: 2,
            instance_generation: 2,
            resource_generation: 2,
        });
        current
    }

    fn staged_one_source_resources_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::ResourceProgress;
        let action = current
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.action)
            .expect("fixture action must exist");
        current.owned_resources = vec![
            OwnedResourceRecord {
                kind: ResourceKind::LoopDomain,
                logical_ref: [0x38; 16],
                generation: action.resource_generation,
                runtime_host_epoch: action.runtime_host_epoch,
                phase: ResourcePhase::Reserved,
                action_id: Some(action.action_id),
                os_identity: None,
                workspace_identity: None,
                containment_identity: None,
                tombstone_evidence: None,
            },
            OwnedResourceRecord {
                kind: ResourceKind::CardInstance,
                logical_ref: [0x39; 16],
                generation: action.resource_generation,
                runtime_host_epoch: action.runtime_host_epoch,
                phase: ResourcePhase::Reserved,
                action_id: Some(action.action_id),
                os_identity: None,
                workspace_identity: None,
                containment_identity: None,
                tombstone_evidence: None,
            },
        ];
        current
    }

    fn owned_one_source_resources_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::ResourceProgress;
        for (index, resource) in current.owned_resources.iter_mut().enumerate() {
            resource.phase = ResourcePhase::Owned;
            resource.os_identity = Some(evidence(b"os", 0x40 + index as u8));
            resource.workspace_identity = Some(evidence(b"workspace", 0x42 + index as u8));
            resource.containment_identity = Some(evidence(b"containment", 0x44 + index as u8));
        }
        current
    }

    fn observed_operation_outcome_state(
        previous: &RuntimeJournalState,
        outcome: TerminalOutcome,
    ) -> RuntimeJournalState {
        let prepared = previous
            .prepared
            .as_ref()
            .expect("fixture prepared operation must exist");
        let (callback, callback_reason_digest, deadline, host_interrupted, higher_tenure_takeover) =
            match outcome {
                TerminalOutcome::OneSourceLoopActive
                | TerminalOutcome::EmptyDeactivateExactZero => (
                    CallbackOutcome::KnownSuccess,
                    None,
                    DeadlineOutcome::NotObserved,
                    false,
                    false,
                ),
                TerminalOutcome::StartFailedBeforeHeadCommitExactZero
                | TerminalOutcome::StopFailedButExactZero => (
                    CallbackOutcome::KnownError,
                    Some(digest(0xa0)),
                    DeadlineOutcome::NotObserved,
                    false,
                    false,
                ),
                TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero
                | TerminalOutcome::TimedOutButExactZero => (
                    CallbackOutcome::UnknownAfterIntent,
                    None,
                    DeadlineOutcome::TimedOut,
                    false,
                    false,
                ),
                _ => panic!("fixture outcome must follow an action intent"),
            };
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::PreparedProgress;
        current
            .prepared
            .as_mut()
            .expect("fixture prepared operation must exist")
            .raw_outcome = Some(RawActionOutcomeLatch {
            callback,
            callback_reason_digest,
            deadline,
            observed_clock_generation: if deadline == DeadlineOutcome::NotObserved {
                0
            } else {
                prepared.installed_clock_generation
            },
            observed_at_nanos: if deadline == DeadlineOutcome::NotObserved {
                0
            } else {
                prepared.installed_deadline_nanos
            },
            host_interrupted,
            higher_tenure_takeover,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        });
        current
    }

    fn normal_start_terminal_outcome_state(
        previous: &RuntimeJournalState,
        outcome: TerminalOutcome,
        completion_snapshot_sequence: u64,
    ) -> RuntimeJournalState {
        let prepared = previous
            .prepared
            .as_ref()
            .expect("fixture prepared operation must exist");
        let action = prepared.action.expect("fixture action must exist");
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::NormalStartTerminal;
        if outcome == TerminalOutcome::OneSourceLoopActive {
            for resource in &mut current.owned_resources {
                resource.action_id = None;
            }
        } else {
            for (index, resource) in current.owned_resources.iter_mut().enumerate() {
                if resource.phase.is_terminal() {
                    continue;
                }
                resource.phase = ResourcePhase::Terminal;
                resource.action_id = None;
                resource.tombstone_evidence =
                    Some(evidence(b"start-terminal-tombstone", 0xe0 + index as u8));
            }
        }
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let result_byte = 0x46_u8.wrapping_add(outcome as u8);
        if outcome == TerminalOutcome::OneSourceLoopActive {
            current.active_desired = Some(ActiveDesiredHead {
                kind: DesiredHeadKind::OneSourceLoop,
                source_scope: prepared.source_scope,
                source_revision: prepared.source_revision,
                slice: opaque(b"one-source-slice-from-request", 0x36),
                source_plan_digest: prepared.source_plan_digest,
                manifest_digest: prepared.manifest_digest,
                operation_id: prepared.operation_id,
                committing_result_digest: Some(digest(result_byte)),
            });
            current.live_materialization = LiveMaterialization::LiveReady {
                active_slice_digest: prepared.incoming_slice_digest,
                runtime_host_epoch: action.runtime_host_epoch,
                resource_generation: action.resource_generation,
                resource_census_digest: census,
            };
        } else {
            current.live_materialization = match current.active_desired.as_ref() {
                None => LiveMaterialization::None,
                Some(active) if active.kind == DesiredHeadKind::EmptyDeactivate => {
                    LiveMaterialization::ExactZero {
                        active_slice_digest: opaque_target_slice(&active.slice),
                        census_digest: census,
                    }
                }
                Some(_) => panic!("fixture failure may preserve only an empty active head"),
            };
        }
        let mut terminal = terminal_record_for_prepared(
            prepared,
            outcome,
            result_byte,
            census,
            completion_snapshot_sequence,
            previous
                .active_desired
                .as_ref()
                .map(|active| opaque_target_slice(&active.slice)),
        );
        terminal.completion_runtime_host_epoch = current.host.runtime_host_epoch_high_water;
        if terminal.selection.selection_clock_generation != current.host.clock_generation_high_water
        {
            terminal.selection = TerminalOutcomeSelection::try_select(
                TerminalSelectionContext {
                    incoming_kind: prepared.incoming_kind,
                    predecessor_phase: prepared.phase,
                    installed_clock_generation: prepared.installed_clock_generation,
                    installed_deadline_nanos: prepared.installed_deadline_nanos,
                },
                TerminalSelectionObservation {
                    raw: terminal.selection.raw,
                    selection_clock_generation: current.host.clock_generation_high_water,
                    selection_observed_at_nanos: terminal.selection.selection_observed_at_nanos,
                    lifecycle_effect: terminal.selection.lifecycle_effect,
                },
            )
            .expect("fixture terminal selection must advance with the current host clock");
            assert_eq!(terminal.selection.primary, outcome);
        }
        current.terminal_operations.push(terminal);
        current.prepared = None;
        current
    }

    fn normal_start_terminal_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let prepared = previous
            .prepared
            .as_ref()
            .expect("fixture prepared must exist");
        let action = prepared.action.expect("fixture action must exist");
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::NormalStartTerminal;
        for resource in &mut current.owned_resources {
            resource.action_id = None;
        }
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let result_digest = digest(0x46);
        current.active_desired = Some(ActiveDesiredHead {
            kind: DesiredHeadKind::OneSourceLoop,
            source_scope: prepared.source_scope,
            source_revision: prepared.source_revision,
            slice: opaque(b"one-source-slice-from-request", 0x36),
            source_plan_digest: prepared.source_plan_digest,
            manifest_digest: prepared.manifest_digest,
            operation_id: prepared.operation_id,
            committing_result_digest: Some(result_digest),
        });
        current.live_materialization = LiveMaterialization::LiveReady {
            active_slice_digest: prepared.incoming_slice_digest,
            runtime_host_epoch: action.runtime_host_epoch,
            resource_generation: action.resource_generation,
            resource_census_digest: census,
        };
        current
            .terminal_operations
            .push(terminal_record_for_prepared(
                prepared,
                TerminalOutcome::OneSourceLoopActive,
                0x46,
                census,
                13,
                previous
                    .active_desired
                    .as_ref()
                    .map(|active| opaque_target_slice(&active.slice)),
            ));
        current.prepared = None;
        current
    }

    fn admitted_empty_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let old_active = previous
            .active_desired
            .as_ref()
            .expect("fixture active must exist");
        let next_revision = previous
            .source_revision_high_water
            .expect("fixture revision high water must exist")
            .revision
            + 1;
        let revision_offset = u8::try_from(next_revision - 12)
            .expect("fixture revision offset must fit")
            .saturating_mul(8);
        let fixture_base = 0xb0_u8.wrapping_add(revision_offset);
        let request = opaque(
            b"empty-request-with-sole-slice",
            fixture_base.wrapping_add(1),
        );
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::FullAdmission;
        current.host.request_nonces.push(ReplayLedgerRecord {
            identity: digest(fixture_base),
            value_digest: request.digest,
        });
        current.host.temporal_lineages.push(TemporalLineageRecord {
            constraint_id: [fixture_base.wrapping_add(2); 16],
            source_scope: [0x01; 16],
            target_fingerprint: digest(0x22),
            original_budget_nanos: 2_000,
            remaining_budget_nanos: 2_000,
            clock_generation: current.host.clock_generation_high_water,
            deadline_nanos: 20_000,
            lineage_digest: digest(fixture_base.wrapping_add(3)),
        });
        current.source_revision_high_water = Some(SourceRevisionHighWater {
            source_scope: [0x01; 16],
            revision: next_revision,
        });
        current.prepared = Some(PreparedOperation {
            source_scope: [0x01; 16],
            operation_id: [fixture_base.wrapping_add(4); 16],
            source_revision: next_revision,
            request,
            request_nonce_identity: digest(fixture_base),
            source_plan_digest: source_plan_digest(fixture_base.wrapping_add(5)),
            incoming_slice_digest: target_slice_digest(fixture_base.wrapping_add(6)),
            incoming_kind: DesiredHeadKind::EmptyDeactivate,
            manifest_digest: digest(0x55),
            expected_active: ExpectedActiveCas::Exact(opaque_target_slice(&old_active.slice)),
            temporal_constraint_id: [fixture_base.wrapping_add(2); 16],
            temporal_lineage_digest: digest(fixture_base.wrapping_add(3)),
            installed_clock_generation: current.host.clock_generation_high_water,
            installed_deadline_nanos: 20_000,
            phase: PreparedPhase::PreparedNoEffects,
            action: None,
            retiring: None,
            raw_outcome: None,
        });
        current
    }

    fn empty_head_retire_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let prepared = previous
            .prepared
            .as_ref()
            .expect("fixture prepared must exist");
        let old_active = previous
            .active_desired
            .as_ref()
            .expect("fixture active must exist");
        let LiveMaterialization::LiveReady {
            runtime_host_epoch,
            resource_generation,
            resource_census_digest,
            ..
        } = previous.live_materialization
        else {
            panic!("fixture live state must be ready");
        };
        let action = JournalActionRef {
            action_id: [0xb7; 16],
            kind: JournalActionKind::DrainToEmpty,
            runtime_host_epoch,
            clock_generation: previous.host.clock_generation_high_water,
            domain_generation: resource_generation,
            instance_generation: resource_generation,
            resource_generation,
        };
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::EmptyHeadRetire;
        let current_prepared = current
            .prepared
            .as_mut()
            .expect("fixture prepared must exist");
        current_prepared.phase = PreparedPhase::HeadCommittedRetiringOld;
        current_prepared.action = Some(action);
        current_prepared.retiring = Some(RetiringLiveFacts {
            old_slice: old_active.slice.clone(),
            old_source_plan_digest: old_active.source_plan_digest,
            old_manifest_digest: old_active.manifest_digest,
            signed_start_budget_nanos: 100,
            signed_drain_budget_nanos: 200,
            signed_cleanup_budget_nanos: 300,
            old_runtime_host_epoch: runtime_host_epoch,
            old_clock_generation: action.clock_generation,
            old_resource_generation: resource_generation,
            old_resource_census_digest: resource_census_digest,
        });
        current.active_desired = Some(ActiveDesiredHead {
            kind: DesiredHeadKind::EmptyDeactivate,
            source_scope: prepared.source_scope,
            source_revision: prepared.source_revision,
            slice: opaque(b"canonical-empty-from-request", 0xb6),
            source_plan_digest: prepared.source_plan_digest,
            manifest_digest: prepared.manifest_digest,
            operation_id: prepared.operation_id,
            committing_result_digest: None,
        });
        for resource in &mut current.owned_resources {
            resource.phase = ResourcePhase::CleanupPending;
            resource.action_id = Some(action.action_id);
        }
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        current.live_materialization = LiveMaterialization::Draining {
            active_slice_digest: prepared.incoming_slice_digest,
            operation_id: prepared.operation_id,
            action_id: action.action_id,
            retiring_generation: resource_generation,
            resource_census_digest: census,
        };
        current
    }

    fn exact_zero_terminal_state(
        previous: &RuntimeJournalState,
        outcome: TerminalOutcome,
        completion_snapshot_sequence: u64,
    ) -> RuntimeJournalState {
        let prepared = previous
            .prepared
            .as_ref()
            .expect("fixture prepared must exist");
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::ExactZeroTerminal;
        for (index, resource) in current.owned_resources.iter_mut().enumerate() {
            if resource.phase.is_terminal() {
                continue;
            }
            resource.phase = ResourcePhase::Terminal;
            resource.action_id = None;
            resource.tombstone_evidence = Some(evidence(b"tombstone", 0xc0 + index as u8));
        }
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let result_digest = digest(0xc2);
        if prepared.phase == PreparedPhase::PreparedNoEffects {
            current.active_desired = Some(ActiveDesiredHead {
                kind: DesiredHeadKind::EmptyDeactivate,
                source_scope: prepared.source_scope,
                source_revision: prepared.source_revision,
                slice: OpaqueCanonicalValue {
                    canonical_bytes: b"canonical-empty-from-request".to_vec().into(),
                    digest: *prepared.incoming_slice_digest.value(),
                },
                source_plan_digest: prepared.source_plan_digest,
                manifest_digest: prepared.manifest_digest,
                operation_id: prepared.operation_id,
                committing_result_digest: Some(result_digest),
            });
        } else {
            current
                .active_desired
                .as_mut()
                .expect("fixture active must exist")
                .committing_result_digest = Some(result_digest);
        }
        current.live_materialization = LiveMaterialization::ExactZero {
            active_slice_digest: prepared.incoming_slice_digest,
            census_digest: census,
        };
        let mut terminal = terminal_record_for_prepared(
            prepared,
            outcome,
            0xc2,
            census,
            completion_snapshot_sequence,
            previous
                .active_desired
                .as_ref()
                .map(|active| opaque_target_slice(&active.slice)),
        );
        terminal.completion_runtime_host_epoch = current.host.runtime_host_epoch_high_water;
        if terminal.selection.selection_clock_generation != current.host.clock_generation_high_water
        {
            terminal.selection = TerminalOutcomeSelection::try_select(
                TerminalSelectionContext {
                    incoming_kind: prepared.incoming_kind,
                    predecessor_phase: prepared.phase,
                    installed_clock_generation: prepared.installed_clock_generation,
                    installed_deadline_nanos: prepared.installed_deadline_nanos,
                },
                TerminalSelectionObservation {
                    raw: terminal.selection.raw,
                    selection_clock_generation: current.host.clock_generation_high_water,
                    selection_observed_at_nanos: terminal.selection.selection_observed_at_nanos,
                    lifecycle_effect: terminal.selection.lifecycle_effect,
                },
            )
            .expect("fixture terminal selection must advance with the current host clock");
            assert_eq!(terminal.selection.primary, outcome);
        }
        current.terminal_operations.push(terminal);
        current.prepared = None;
        current
    }

    fn observed_empty_success_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::PreparedProgress;
        current
            .prepared
            .as_mut()
            .expect("fixture prepared must exist")
            .raw_outcome = Some(RawActionOutcomeLatch {
            callback: CallbackOutcome::KnownSuccess,
            callback_reason_digest: None,
            deadline: DeadlineOutcome::NotObserved,
            observed_clock_generation: 0,
            observed_at_nanos: 0,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        });
        current
    }

    fn no_effect_terminal_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let prepared = previous
            .prepared
            .as_ref()
            .expect("fixture prepared must exist");
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::OperationTerminalNoEffects;
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        current
            .terminal_operations
            .push(terminal_record_for_prepared(
                prepared,
                TerminalOutcome::StartTimedOutBeforeIntentNoEffects,
                0xc5,
                census,
                10,
                previous
                    .active_desired
                    .as_ref()
                    .map(|active| opaque_target_slice(&active.slice)),
            ));
        current.prepared = None;
        current
    }

    fn no_effect_terminal_outcome_state(
        previous: &RuntimeJournalState,
        outcome: TerminalOutcome,
        completion_snapshot_sequence: u64,
    ) -> RuntimeJournalState {
        let prepared = previous
            .prepared
            .as_ref()
            .expect("fixture prepared operation must exist");
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::OperationTerminalNoEffects;
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let mut terminal = terminal_record_for_prepared(
            prepared,
            outcome,
            0xd0_u8.wrapping_add(outcome as u8),
            census,
            completion_snapshot_sequence,
            previous
                .active_desired
                .as_ref()
                .map(|active| opaque_target_slice(&active.slice)),
        );
        terminal.completion_runtime_host_epoch = current.host.runtime_host_epoch_high_water;
        if terminal.selection.selection_clock_generation != current.host.clock_generation_high_water
        {
            terminal.selection = TerminalOutcomeSelection::try_select(
                TerminalSelectionContext {
                    incoming_kind: prepared.incoming_kind,
                    predecessor_phase: prepared.phase,
                    installed_clock_generation: prepared.installed_clock_generation,
                    installed_deadline_nanos: prepared.installed_deadline_nanos,
                },
                TerminalSelectionObservation {
                    raw: terminal.selection.raw,
                    selection_clock_generation: current.host.clock_generation_high_water,
                    selection_observed_at_nanos: terminal.selection.selection_observed_at_nanos,
                    lifecycle_effect: terminal.selection.lifecycle_effect,
                },
            )
            .expect("fixture terminal selection must advance with the current host clock");
            assert_eq!(terminal.selection.primary, outcome);
        }
        current.terminal_operations.push(terminal);
        current.prepared = None;
        current
    }

    fn cleanup_old_live_resources_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::ResourceProgress;
        for resource in &mut current.owned_resources {
            resource.phase = ResourcePhase::CleanupPending;
        }
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let LiveMaterialization::StartupInvalidated {
            resource_census_digest,
            ..
        } = &mut current.live_materialization
        else {
            panic!("fixture startup state must be invalidated");
        };
        *resource_census_digest = census;
        current
    }

    fn tombstone_old_live_resources_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::ResourceProgress;
        for (index, resource) in current.owned_resources.iter_mut().enumerate() {
            resource.phase = ResourcePhase::Terminal;
            resource.tombstone_evidence = Some(evidence(b"startup-tombstone", 0xd0 + index as u8));
        }
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let LiveMaterialization::StartupInvalidated {
            resource_census_digest,
            ..
        } = &mut current.live_materialization
        else {
            panic!("fixture startup state must be invalidated");
        };
        *resource_census_digest = census;
        current
    }

    fn recovery_plan_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let active = previous
            .active_desired
            .as_ref()
            .expect("fixture active must exist");
        let recovery_index = u8::try_from(previous.recovery_terminals.len())
            .expect("fixture recovery history must fit");
        let next_generation = previous
            .terminal_operations
            .iter()
            .filter_map(|terminal| terminal.action)
            .filter(|action| action.kind == JournalActionKind::StartOneSourceLoop)
            .chain(
                previous
                    .recovery_terminals
                    .iter()
                    .map(|terminal| terminal.recovery.action),
            )
            .map(|action| {
                action
                    .domain_generation
                    .max(action.instance_generation)
                    .max(action.resource_generation)
            })
            .max()
            .unwrap_or(0)
            + 1;
        let action = JournalActionRef {
            action_id: [0xd2_u8.wrapping_add(recovery_index); 16],
            kind: JournalActionKind::RestartReassembly,
            runtime_host_epoch: previous.host.runtime_host_epoch_high_water,
            clock_generation: previous.host.clock_generation_high_water,
            domain_generation: next_generation,
            instance_generation: next_generation,
            resource_generation: next_generation,
        };
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::RecoveryPlan;
        current.recovery_action = Some(RecoveryAction {
            action,
            source_scope: active.source_scope,
            source_revision: active.source_revision,
            source_plan_digest: active.source_plan_digest,
            active_slice_digest: opaque_target_slice(&active.slice),
            manifest_digest: active.manifest_digest,
            store_pinned_build_identity_digest: previous.host.store_pinned_build_identity.digest,
            compiled_build_instance_id: previous.host.compiled_build_instance_id,
            compiled_compatibility_digest: previous.host.compiled_compatibility_digest,
            signed_start_budget_nanos: 100,
            deadline_nanos: 30_000,
            deadline_evidence_digest: digest(0xd3),
            phase: RecoveryPhase::RecoveryPlannedNoEffects,
            raw_outcome: None,
        });
        current.live_materialization = LiveMaterialization::Recovering {
            active_slice_digest: opaque_target_slice(&active.slice),
            action_id: action.action_id,
            resource_generation: action.resource_generation,
            resource_census_digest: compute_resource_census_digest(&current.owned_resources)
                .expect("fixture census must build"),
        };
        current
    }

    fn recovery_intent_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::RecoveryProgress;
        current
            .recovery_action
            .as_mut()
            .expect("fixture recovery must exist")
            .phase = RecoveryPhase::StartCallIntent;
        current
    }

    fn staged_recovery_resources_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let action = previous
            .recovery_action
            .expect("fixture recovery must exist")
            .action;
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::ResourceProgress;
        current.owned_resources.extend([
            OwnedResourceRecord {
                kind: ResourceKind::LoopDomain,
                logical_ref: [0xd4; 16],
                generation: action.resource_generation,
                runtime_host_epoch: action.runtime_host_epoch,
                phase: ResourcePhase::Reserved,
                action_id: Some(action.action_id),
                os_identity: None,
                workspace_identity: None,
                containment_identity: None,
                tombstone_evidence: None,
            },
            OwnedResourceRecord {
                kind: ResourceKind::CardInstance,
                logical_ref: [0xd5; 16],
                generation: action.resource_generation,
                runtime_host_epoch: action.runtime_host_epoch,
                phase: ResourcePhase::Reserved,
                action_id: Some(action.action_id),
                os_identity: None,
                workspace_identity: None,
                containment_identity: None,
                tombstone_evidence: None,
            },
        ]);
        current
            .owned_resources
            .sort_by_key(OwnedResourceRecord::key);
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let LiveMaterialization::Recovering {
            resource_census_digest,
            ..
        } = &mut current.live_materialization
        else {
            panic!("fixture live state must recover");
        };
        *resource_census_digest = census;
        current
    }

    fn owned_recovery_resources_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::ResourceProgress;
        for (index, resource) in current
            .owned_resources
            .iter_mut()
            .filter(|resource| !resource.phase.is_terminal())
            .enumerate()
        {
            resource.phase = ResourcePhase::Owned;
            resource.os_identity = Some(evidence(b"recovery-os", 0xd6 + index as u8));
            resource.workspace_identity = Some(evidence(b"recovery-workspace", 0xd8 + index as u8));
            resource.containment_identity =
                Some(evidence(b"recovery-containment", 0xda + index as u8));
        }
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let LiveMaterialization::Recovering {
            resource_census_digest,
            ..
        } = &mut current.live_materialization
        else {
            panic!("fixture live state must recover");
        };
        *resource_census_digest = census;
        current
    }

    fn cleanup_owner_event_recovery_resources_state(
        previous: &RuntimeJournalState,
    ) -> RuntimeJournalState {
        let action = previous
            .recovery_action
            .expect("fixture interrupted recovery must retain its action")
            .action;
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::ResourceProgress;
        for resource in current
            .owned_resources
            .iter_mut()
            .filter(|resource| !resource.phase.is_terminal())
        {
            assert_eq!(resource.phase, ResourcePhase::Owned);
            assert_eq!(resource.action_id, Some(action.action_id));
            resource.phase = ResourcePhase::CleanupPending;
        }
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let resource_census_digest = match &mut current.live_materialization {
            LiveMaterialization::Recovering {
                resource_census_digest,
                ..
            }
            | LiveMaterialization::StartupInvalidated {
                resource_census_digest,
                ..
            } => resource_census_digest,
            _ => panic!("fixture owner-event recovery must remain nonterminal"),
        };
        *resource_census_digest = census;
        current
    }

    fn recovery_known_success_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::RecoveryProgress;
        current
            .recovery_action
            .as_mut()
            .expect("fixture recovery must exist")
            .raw_outcome = Some(RawActionOutcomeLatch {
            callback: CallbackOutcome::KnownSuccess,
            callback_reason_digest: None,
            deadline: DeadlineOutcome::NotObserved,
            observed_clock_generation: 0,
            observed_at_nanos: 0,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        });
        current
    }

    fn recovery_live_ready_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let recovery = previous
            .recovery_action
            .expect("fixture recovery must exist");
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::RecoveryPublish;
        for resource in current
            .owned_resources
            .iter_mut()
            .filter(|resource| !resource.phase.is_terminal())
        {
            resource.action_id = None;
        }
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        current.live_materialization = LiveMaterialization::LiveReady {
            active_slice_digest: recovery.active_slice_digest,
            runtime_host_epoch: recovery.action.runtime_host_epoch,
            resource_generation: recovery.action.resource_generation,
            resource_census_digest: census,
        };
        let raw = recovery
            .raw_outcome
            .expect("fixture successful recovery must have a raw outcome");
        current.recovery_terminals.push(recovery_terminal_record(
            recovery,
            TerminalSelectionObservation {
                raw,
                selection_clock_generation: current.host.clock_generation_high_water,
                selection_observed_at_nanos: recovery.deadline_nanos - 1,
                lifecycle_effect: TerminalLifecycleEffect::MayHaveStarted,
            },
            census,
            (current.host.runtime_host_epoch_high_water, 16),
        ));
        current.recovery_action = None;
        current
    }

    fn recovery_timeout_failure_state(
        previous: &RuntimeJournalState,
        completion_snapshot_sequence: u64,
    ) -> RuntimeJournalState {
        let recovery = previous
            .recovery_action
            .expect("fixture recovery must exist");
        let raw = RawActionOutcomeLatch {
            callback: CallbackOutcome::NotInvoked,
            callback_reason_digest: None,
            deadline: DeadlineOutcome::TimedOut,
            observed_clock_generation: recovery.action.clock_generation,
            observed_at_nanos: recovery.deadline_nanos,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        };
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::RecoveryPublish;
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let terminal = recovery_terminal_record(
            recovery,
            TerminalSelectionObservation {
                raw,
                selection_clock_generation: current.host.clock_generation_high_water,
                selection_observed_at_nanos: recovery.deadline_nanos,
                lifecycle_effect: TerminalLifecycleEffect::ProvenNotStarted,
            },
            census,
            (
                current.host.runtime_host_epoch_high_water,
                completion_snapshot_sequence,
            ),
        );
        let failure_latch_digest = terminal
            .failure_latch_digest
            .expect("fixture timeout must be a permanent failure");
        current.recovery_terminals.push(terminal);
        current.recovery_action = None;
        current.live_materialization = LiveMaterialization::RecoveryFailedNotReady {
            active_slice_digest: recovery.active_slice_digest,
            terminal_recovery_action_id: recovery.action.action_id,
            failure_latch_digest,
            resource_census_digest: census,
        };
        current
    }

    fn owner_event_recovery_failure_state(
        previous: &RuntimeJournalState,
        completion_snapshot_sequence: u64,
    ) -> RuntimeJournalState {
        let recovery = previous
            .recovery_action
            .expect("fixture owner-event recovery must retain its action");
        assert!(matches!(
            recovery.phase,
            RecoveryPhase::StartCallIntent | RecoveryPhase::StartupReconcileRequired
        ));
        let mut raw = recovery
            .raw_outcome
            .expect("fixture owner-event recovery must retain provenance");
        assert!(raw.host_interrupted || raw.higher_tenure_takeover);
        raw.cleanup = CleanupOutcome::ExactZero;
        raw.cleanup_evidence_digest = Some(digest(0xe8));
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::RecoveryPublish;
        for (index, resource) in current
            .owned_resources
            .iter_mut()
            .filter(|resource| !resource.phase.is_terminal())
            .enumerate()
        {
            resource.phase = ResourcePhase::Terminal;
            resource.action_id = None;
            resource.tombstone_evidence = Some(evidence(
                b"interrupted-recovery-tombstone",
                0xe9 + index as u8,
            ));
        }
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        let terminal = recovery_terminal_record(
            recovery,
            TerminalSelectionObservation {
                raw,
                selection_clock_generation: current.host.clock_generation_high_water,
                selection_observed_at_nanos: recovery.deadline_nanos - 1,
                lifecycle_effect: TerminalLifecycleEffect::MayHaveStarted,
            },
            census,
            (
                current.host.runtime_host_epoch_high_water,
                completion_snapshot_sequence,
            ),
        );
        let failure_latch_digest = terminal
            .failure_latch_digest
            .expect("fixture owner-event recovery must latch permanent failure evidence");
        current.recovery_terminals.push(terminal);
        current.recovery_action = None;
        current.live_materialization = LiveMaterialization::RecoveryFailedNotReady {
            active_slice_digest: recovery.active_slice_digest,
            terminal_recovery_action_id: recovery.action.action_id,
            failure_latch_digest,
            resource_census_digest: census,
        };
        current
    }

    fn recovery_abort_no_effects_state(
        previous: &RuntimeJournalState,
        completion_snapshot_sequence: u64,
    ) -> RuntimeJournalState {
        let recovery = previous
            .recovery_action
            .expect("fixture invalidated recovery must exist");
        let raw = RawActionOutcomeLatch {
            callback: CallbackOutcome::NotInvoked,
            callback_reason_digest: None,
            deadline: DeadlineOutcome::NotObserved,
            observed_clock_generation: 0,
            observed_at_nanos: 0,
            host_interrupted: true,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        };
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::RecoveryAbortNoEffects;
        let census = compute_resource_census_digest(&current.owned_resources)
            .expect("fixture census must build");
        current.recovery_terminals.push(recovery_terminal_record(
            recovery,
            TerminalSelectionObservation {
                raw,
                selection_clock_generation: current.host.clock_generation_high_water,
                selection_observed_at_nanos: 1,
                lifecycle_effect: TerminalLifecycleEffect::ProvenNotStarted,
            },
            census,
            (
                current.host.runtime_host_epoch_high_water,
                completion_snapshot_sequence,
            ),
        ));
        current.recovery_action = None;
        current
    }

    fn successful_recovery_state() -> RuntimeJournalState {
        let active = active_state();
        let startup = startup_successor_state(&active);
        let cleanup = cleanup_old_live_resources_state(&startup);
        let tombstoned = tombstone_old_live_resources_state(&cleanup);
        let planned = recovery_plan_state(&tombstoned);
        let intent = recovery_intent_state(&planned);
        let staged = staged_recovery_resources_state(&intent);
        let owned = owned_recovery_resources_state(&staged);
        let observed = recovery_known_success_state(&owned);
        recovery_live_ready_state(&observed)
    }

    fn state_at_all_fixed_capacity_limits() -> RuntimeJournalState {
        let mut state = initialized_idle_state();
        state.host.tenure_nonces = (0..MAX_RUNTIME_TENURE_NONCES)
            .map(|index| ReplayLedgerRecord {
                identity: indexed_digest(index),
                value_digest: digest(0xee),
            })
            .collect();
        state.writer_fence = Some(WriterFenceRecord {
            source_scope: [0x01; 16],
            writer: [0x02; 16],
            epoch: 1,
            proof_envelope_digest: digest(0xee),
            tenure_nonce_identity: indexed_digest(MAX_RUNTIME_TENURE_NONCES - 1),
            principal: [0x03; 16],
        });
        state.host.request_nonces = (0..MAX_RUNTIME_REQUEST_NONCES)
            .map(|index| ReplayLedgerRecord {
                identity: indexed_digest(index),
                value_digest: indexed_digest(300 + index),
            })
            .collect();
        state.host.temporal_lineages = (0..MAX_RUNTIME_TEMPORAL_LINEAGES)
            .map(|index| TemporalLineageRecord {
                constraint_id: indexed_ref(index),
                source_scope: [0x01; 16],
                target_fingerprint: digest(0x22),
                original_budget_nanos: 1_000,
                remaining_budget_nanos: 500,
                clock_generation: 5,
                deadline_nanos: 10_000 + index as u64,
                lineage_digest: indexed_digest(600 + index),
            })
            .collect();
        state.source_revision_high_water = Some(SourceRevisionHighWater {
            source_scope: [0x01; 16],
            revision: MAX_RUNTIME_TERMINAL_OPERATIONS as u64,
        });
        state.owned_resources = (0..MAX_RUNTIME_OWNED_RESOURCES)
            .map(|index| OwnedResourceRecord {
                kind: ResourceKind::ResourceSlot,
                logical_ref: indexed_ref(index),
                generation: 1,
                runtime_host_epoch: 3,
                phase: ResourcePhase::Terminal,
                action_id: None,
                os_identity: Some(evidence(b"os", 0xe0)),
                workspace_identity: Some(evidence(b"workspace", 0xe1)),
                containment_identity: Some(evidence(b"containment", 0xe2)),
                tombstone_evidence: Some(evidence(b"tombstone", 0xe3)),
            })
            .collect();
        state.terminal_operations = (0..MAX_RUNTIME_TERMINAL_OPERATIONS)
            .map(|index| {
                let mut terminal = terminal_record_for(
                    TerminalIdentityFixture {
                        operation_id: indexed_ref(index),
                        request_digest: indexed_digest(300 + index),
                        request_nonce_identity: indexed_digest(index),
                        source_revision: (index + 1) as u64,
                        source_plan_digest: source_plan_digest(0xe4),
                        target_slice_digest: target_slice_digest(0xe5),
                        temporal_constraint_id: indexed_ref(index),
                        temporal_lineage_digest: indexed_digest(600 + index),
                    },
                    TerminalOutcome::AbortedBeforeIntentNoEffects,
                    0xe6,
                    digest(0xe7),
                    u64::try_from(index + 1).expect("completion sequence must fit"),
                );
                terminal.installed_deadline_nanos = 10_000 + index as u64;
                terminal.selection.selection_observed_at_nanos = 9_999 + index as u64;
                terminal
            })
            .collect();
        state
    }

    fn unvalidated_wire(sequence: u64, state: &RuntimeJournalState) -> Vec<u8> {
        let payload = encode_payload(state).expect("fixture payload must encode");
        encode_snapshot(&[0x11; 32], &digest(0x22), sequence, &payload)
            .expect("fixture envelope must encode")
    }

    fn assert_exhaustive_fault_rejection(snapshot: &RuntimeJournalSnapshot) {
        let mut encoded = snapshot.canonical_wire().to_vec();
        for cut in 0..encoded.len() {
            assert!(
                RuntimeJournalSnapshot::decode(&encoded[..cut]).is_err(),
                "truncation at byte {cut} was accepted"
            );
        }
        for byte_index in 0..encoded.len() {
            for bit in 0..u8::BITS {
                encoded[byte_index] ^= 1 << bit;
                assert!(
                    RuntimeJournalSnapshot::decode(&encoded).is_err(),
                    "single-bit corruption at byte {byte_index}, bit {bit} was accepted"
                );
                encoded[byte_index] ^= 1 << bit;
            }
        }
    }

    fn recompute_checksum(frame: &mut [u8]) {
        let checksum = snapshot_checksum(
            &frame[..HEADER_WITHOUT_CHECKSUM_BYTES],
            &frame[HEADER_BYTES..],
        )
        .expect("fixture checksum must build");
        frame[HEADER_WITHOUT_CHECKSUM_BYTES..HEADER_BYTES].copy_from_slice(checksum.as_bytes());
    }

    #[test]
    fn sequence_one_has_a_frozen_envelope_checksum_and_round_trips() {
        let snapshot = snapshot(1, sequence_one_state());
        let encoded = snapshot.canonical_wire();
        assert_eq!(encoded.len(), 486);
        assert_eq!(&encoded[..14], b"PXJR\0\x01\0\x03\0\x02\0\x01\0\x01");
        assert_eq!(
            &encoded[HEADER_WITHOUT_CHECKSUM_BYTES..HEADER_BYTES],
            &[
                238, 61, 15, 43, 207, 123, 204, 111, 181, 191, 125, 50, 31, 64, 20, 123, 67, 59,
                93, 127, 231, 166, 19, 40, 132, 73, 238, 23, 117, 79, 195, 43,
            ]
        );
        let decoded = RuntimeJournalSnapshot::decode(encoded).expect("golden must decode");
        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.canonical_wire(), encoded);
        assert_eq!(decoded.sequence(), 1);
        assert_eq!(decoded.store_instance_id(), &[0x11; 32]);
        assert_eq!(decoded.owner_target_fingerprint(), &digest(0x22));
        assert_eq!(decoded.state(), &sequence_one_state());
    }

    #[test]
    fn full_live_ready_state_has_a_frozen_envelope_checksum() {
        let snapshot = snapshot(7, active_state());
        assert_eq!(snapshot.canonical_wire().len(), 2_015);
        assert_eq!(
            &snapshot.canonical_wire()[HEADER_WITHOUT_CHECKSUM_BYTES..HEADER_BYTES],
            &[
                18, 227, 235, 235, 31, 201, 83, 85, 150, 255, 133, 250, 220, 244, 78, 144, 85, 241,
                202, 219, 14, 38, 174, 214, 191, 103, 65, 211, 111, 142, 170, 50,
            ],
        );
    }

    #[test]
    fn optional_state_variants_round_trip_byte_identically() {
        for state in [active_state(), draining_state(), recovering_state()] {
            let snapshot = snapshot(7, state);
            let decoded = RuntimeJournalSnapshot::decode(snapshot.canonical_wire())
                .expect("representative snapshot must decode");
            assert_eq!(decoded, snapshot);
            assert_eq!(decoded.canonical_wire(), snapshot.canonical_wire());
        }
    }

    #[test]
    fn envelope_corruption_unknown_values_lengths_and_trailing_bytes_fail_closed() {
        let minimal = snapshot(1, sequence_one_state());
        assert_exhaustive_fault_rejection(&minimal);
        let full_recovery = snapshot(16, successful_recovery_state());
        assert_exhaustive_fault_rejection(&full_recovery);
        let encoded = minimal.canonical_wire().to_vec();

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            RuntimeJournalSnapshot::decode(&bad_magic),
            Err(RuntimeJournalError::InvalidMagic)
        );
        let mut bad_envelope = encoded.clone();
        bad_envelope[5] = 2;
        assert_eq!(
            RuntimeJournalSnapshot::decode(&bad_envelope),
            Err(RuntimeJournalError::UnsupportedEnvelopeVersion)
        );
        let mut bad_owner = encoded.clone();
        bad_owner[7] = 2;
        assert_eq!(
            RuntimeJournalSnapshot::decode(&bad_owner),
            Err(RuntimeJournalError::WrongOwnerKind)
        );
        let mut bad_payload = encoded.clone();
        bad_payload[9] = 3;
        assert_eq!(
            RuntimeJournalSnapshot::decode(&bad_payload),
            Err(RuntimeJournalError::UnsupportedPayloadVersion)
        );
        let mut bad_checksum_profile = encoded.clone();
        bad_checksum_profile[11] = 2;
        assert_eq!(
            RuntimeJournalSnapshot::decode(&bad_checksum_profile),
            Err(RuntimeJournalError::UnsupportedChecksumProfile)
        );
        let mut bad_checksum = encoded.clone();
        bad_checksum[HEADER_WITHOUT_CHECKSUM_BYTES] ^= 1;
        assert_eq!(
            RuntimeJournalSnapshot::decode(&bad_checksum),
            Err(RuntimeJournalError::ChecksumMismatch)
        );

        let payload_length_offset = HEADER_WITHOUT_CHECKSUM_BYTES - 8;
        let mut length_bomb = encoded.clone();
        length_bomb[payload_length_offset..payload_length_offset + 8]
            .copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            RuntimeJournalSnapshot::decode(&length_bomb),
            Err(RuntimeJournalError::LengthBomb)
        );

        let mut outer_trailing = encoded.clone();
        outer_trailing.push(0);
        assert_eq!(
            RuntimeJournalSnapshot::decode(&outer_trailing),
            Err(RuntimeJournalError::TrailingBytes)
        );
        assert_eq!(
            RuntimeJournalSnapshot::decode(&encoded[..encoded.len() - 1]),
            Err(RuntimeJournalError::Truncated)
        );

        let mut payload_trailing = encoded.clone();
        payload_trailing.push(0);
        let payload_length = u64::try_from(payload_trailing.len() - HEADER_BYTES)
            .expect("fixture payload length must fit");
        payload_trailing[payload_length_offset..payload_length_offset + 8]
            .copy_from_slice(&payload_length.to_be_bytes());
        recompute_checksum(&mut payload_trailing);
        assert_eq!(
            RuntimeJournalSnapshot::decode(&payload_trailing),
            Err(RuntimeJournalError::TrailingBytes)
        );

        let mut unknown_live = encoded.clone();
        let live_tag_offset = unknown_live.len() - 8;
        assert_eq!(unknown_live[live_tag_offset], 0);
        unknown_live[live_tag_offset] = u8::MAX;
        recompute_checksum(&mut unknown_live);
        assert_eq!(
            RuntimeJournalSnapshot::decode(&unknown_live),
            Err(RuntimeJournalError::UnknownEnumValue)
        );

        let mut opaque_length_bomb = encoded;
        let descriptor_length_offset = HEADER_BYTES + 8 + 16 + 8;
        opaque_length_bomb[descriptor_length_offset..descriptor_length_offset + 4].copy_from_slice(
            &u32::try_from(MAX_PINNED_OPAQUE_ARTIFACT_BYTES + 1)
                .expect("bound must fit")
                .to_be_bytes(),
        );
        recompute_checksum(&mut opaque_length_bomb);
        assert_eq!(
            RuntimeJournalSnapshot::decode(&opaque_length_bomb),
            Err(RuntimeJournalError::OpaqueValueTooLarge)
        );
    }

    #[test]
    fn checksum_valid_mixed_semantic_corruption_still_fails_closed() {
        let mut corrupted = active_state();
        corrupted
            .active_desired
            .as_mut()
            .expect("fixture active must exist")
            .operation_id = [0xf7; 16];
        let LiveMaterialization::LiveReady {
            resource_census_digest,
            ..
        } = &mut corrupted.live_materialization
        else {
            unreachable!();
        };
        *resource_census_digest = digest(0xf8);
        corrupted.terminal_operations[0].selection.primary =
            TerminalOutcome::AbortedBeforeHeadCommitExactZero;
        let checksum_valid_wire = unvalidated_wire(7, &corrupted);
        assert_eq!(
            RuntimeJournalSnapshot::decode(&checksum_valid_wire),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );
    }

    #[test]
    fn opaque_values_are_nonempty_nonzero_digest_and_locally_bounded() {
        assert_eq!(
            OpaqueCanonicalValue::try_pinned_artifact(&[], digest(1)),
            Err(RuntimeJournalError::EmptyOpaqueValue)
        );
        assert_eq!(
            OpaqueCanonicalValue::try_pinned_artifact(b"value", Digest32::from_bytes([0; 32])),
            Err(RuntimeJournalError::ZeroDigest)
        );
        let oversized = vec![0_u8; MAX_PINNED_OPAQUE_ARTIFACT_BYTES + 1];
        assert_eq!(
            OpaqueCanonicalValue::try_pinned_artifact(&oversized, digest(1)),
            Err(RuntimeJournalError::OpaqueValueTooLarge)
        );

        let exact_pinned = vec![0_u8; MAX_PINNED_OPAQUE_ARTIFACT_BYTES];
        assert!(OpaqueCanonicalValue::try_pinned_artifact(&exact_pinned, digest(1)).is_ok());

        let exact_request = vec![0_u8; MAX_OPAQUE_REQUEST_OR_SLICE_BYTES];
        assert!(OpaqueCanonicalValue::try_request_or_slice(&exact_request, digest(1)).is_ok());
        let oversized_request = vec![0_u8; MAX_OPAQUE_REQUEST_OR_SLICE_BYTES + 1];
        assert_eq!(
            OpaqueCanonicalValue::try_request_or_slice(&oversized_request, digest(1)),
            Err(RuntimeJournalError::OpaqueValueTooLarge)
        );

        let exact_resource_evidence = vec![0_u8; MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES];
        assert_eq!(
            OpaqueCanonicalValue::try_new(
                &exact_resource_evidence,
                digest(1),
                MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES,
            )
            .and_then(|value| value.validate_bound(MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES)),
            Ok(())
        );
        let oversized_resource_evidence = vec![0_u8; MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES + 1];
        assert_eq!(
            OpaqueCanonicalValue::try_new(
                &oversized_resource_evidence,
                digest(1),
                MAX_RUNTIME_RESOURCE_EVIDENCE_BYTES,
            ),
            Err(RuntimeJournalError::OpaqueValueTooLarge)
        );

        let exact_terminal_body = vec![0_u8; MAX_RUNTIME_TERMINAL_RESPONSE_BYTES];
        assert_eq!(
            OpaqueCanonicalValue::try_new(
                &exact_terminal_body,
                digest(1),
                MAX_RUNTIME_TERMINAL_RESPONSE_BYTES,
            )
            .and_then(|value| value.validate_bound(MAX_RUNTIME_TERMINAL_RESPONSE_BYTES)),
            Ok(())
        );
        let oversized_terminal_body = vec![0_u8; MAX_RUNTIME_TERMINAL_RESPONSE_BYTES + 1];
        assert_eq!(
            OpaqueCanonicalValue::try_new(
                &oversized_terminal_body,
                digest(1),
                MAX_RUNTIME_TERMINAL_RESPONSE_BYTES,
            ),
            Err(RuntimeJournalError::OpaqueValueTooLarge)
        );

        assert_eq!(
            RuntimeJournalSnapshot::decode(&vec![0_u8; MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES + 1]),
            Err(RuntimeJournalError::SnapshotTooLarge)
        );
    }

    #[test]
    fn zero_references_and_invalid_temporal_facts_fail_closed() {
        let mut zero_clock_domain = initialized_idle_state();
        zero_clock_domain.host.clock_domain = [0; 16];
        assert_eq!(
            zero_clock_domain.validate(7),
            Err(RuntimeJournalError::ZeroReference)
        );

        let mut zero_writer = active_state();
        zero_writer
            .writer_fence
            .as_mut()
            .expect("fixture fence must exist")
            .writer = [0; 16];
        assert_eq!(
            zero_writer.validate(7),
            Err(RuntimeJournalError::ZeroReference)
        );

        let mut zero_operation = active_state();
        zero_operation
            .active_desired
            .as_mut()
            .expect("fixture active must exist")
            .operation_id = [0; 16];
        assert_eq!(
            zero_operation.validate(7),
            Err(RuntimeJournalError::ZeroReference)
        );

        let mut zero_action = draining_state();
        zero_action
            .prepared
            .as_mut()
            .expect("fixture prepared must exist")
            .action
            .as_mut()
            .expect("fixture action must exist")
            .action_id = [0; 16];
        assert_eq!(
            zero_action.validate(7),
            Err(RuntimeJournalError::ZeroReference)
        );

        let mut zero_resource = active_state();
        zero_resource.owned_resources[0].logical_ref = [0; 16];
        assert_eq!(
            zero_resource.validate(7),
            Err(RuntimeJournalError::ZeroReference)
        );

        let mut future_temporal_generation = active_state();
        future_temporal_generation.host.temporal_lineages[0].clock_generation = 6;
        assert_eq!(
            future_temporal_generation.validate(7),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut zero_deadline = active_state();
        zero_deadline.host.temporal_lineages[0].deadline_nanos = 0;
        assert_eq!(
            zero_deadline.validate(7),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );
    }

    #[test]
    fn host_and_clock_high_waters_advance_together_by_exactly_one() {
        let previous_state = initialized_idle_state();
        let previous = snapshot(7, previous_state.clone());

        let next_state = startup_successor_state(&previous_state);
        let next = snapshot(8, next_state);
        assert_eq!(next.validate_successor_of(&previous), Ok(()));

        let mut host_only_state = startup_successor_state(&previous_state);
        host_only_state.host.clock_generation_high_water = 5;
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 8, host_only_state),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut clock_only_state = startup_successor_state(&previous_state);
        clock_only_state.host.runtime_host_epoch_high_water = 3;
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 8, clock_only_state),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut jumped_state = startup_successor_state(&previous_state);
        jumped_state.host.runtime_host_epoch_high_water = 5;
        jumped_state.host.clock_generation_high_water = 7;
        let jumped = snapshot(8, jumped_state);
        assert_eq!(
            jumped.validate_successor_of(&previous),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );
    }

    #[test]
    fn all_fixed_capacities_fail_closed_above_their_limits() {
        let replay_record = |index| ReplayLedgerRecord {
            identity: indexed_digest(index),
            value_digest: digest(0xee),
        };

        let mut tenure = initialized_idle_state();
        tenure.host.tenure_nonces = (0..=MAX_RUNTIME_TENURE_NONCES).map(replay_record).collect();
        assert_eq!(
            tenure.validate(7),
            Err(RuntimeJournalError::CapacityExceeded)
        );
        assert_eq!(
            RuntimeJournalSnapshot::decode(&unvalidated_wire(7, &tenure)),
            Err(RuntimeJournalError::CapacityExceeded)
        );

        let mut requests = initialized_idle_state();
        requests.host.request_nonces = (0..=MAX_RUNTIME_REQUEST_NONCES)
            .map(replay_record)
            .collect();
        assert_eq!(
            requests.validate(7),
            Err(RuntimeJournalError::CapacityExceeded)
        );

        let mut temporal = initialized_idle_state();
        temporal.host.temporal_lineages = (0..=MAX_RUNTIME_TEMPORAL_LINEAGES)
            .map(|index| TemporalLineageRecord {
                constraint_id: indexed_ref(index),
                source_scope: [1; 16],
                target_fingerprint: digest(0xed),
                original_budget_nanos: 1,
                remaining_budget_nanos: 1,
                clock_generation: 5,
                deadline_nanos: 1,
                lineage_digest: digest(0xef),
            })
            .collect();
        assert_eq!(
            temporal.validate(7),
            Err(RuntimeJournalError::CapacityExceeded)
        );

        let mut resources = initialized_idle_state();
        resources.owned_resources = (0..=MAX_RUNTIME_OWNED_RESOURCES)
            .map(|index| OwnedResourceRecord {
                kind: ResourceKind::ResourceSlot,
                logical_ref: indexed_ref(index),
                generation: 1,
                runtime_host_epoch: 3,
                phase: ResourcePhase::Terminal,
                action_id: None,
                os_identity: Some(evidence(b"os", 0xf0)),
                workspace_identity: Some(evidence(b"workspace", 0xf1)),
                containment_identity: Some(evidence(b"containment", 0xf2)),
                tombstone_evidence: Some(evidence(b"tombstone", 0xf3)),
            })
            .collect();
        assert_eq!(
            resources.validate(7),
            Err(RuntimeJournalError::CapacityExceeded)
        );

        let mut terminals = initialized_idle_state();
        terminals.terminal_operations = (0..=MAX_RUNTIME_TERMINAL_OPERATIONS)
            .map(|index| {
                terminal_record_for(
                    TerminalIdentityFixture {
                        operation_id: indexed_ref(index),
                        request_digest: digest(0xf1),
                        request_nonce_identity: indexed_digest(index),
                        source_revision: 1,
                        source_plan_digest: source_plan_digest(0xf2),
                        target_slice_digest: target_slice_digest(0xf3),
                        temporal_constraint_id: indexed_ref(index),
                        temporal_lineage_digest: digest(0xf4),
                    },
                    TerminalOutcome::AbortedBeforeIntentNoEffects,
                    0xf5,
                    digest(0xf6),
                    1,
                )
            })
            .collect();
        assert_eq!(
            terminals.validate_terminals(7),
            Err(RuntimeJournalError::CapacityExceeded)
        );
    }

    #[test]
    fn every_fixed_capacity_accepts_exactly_the_limit_in_one_full_snapshot() {
        let state = state_at_all_fixed_capacity_limits();
        let sequence = u64::try_from(MAX_RUNTIME_TERMINAL_OPERATIONS)
            .expect("terminal capacity must fit the snapshot sequence");
        assert_eq!(state.validate(sequence), Ok(()));
        let snapshot = RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), sequence, state)
            .expect("all exact limits must fit the full journal envelope");
        assert!(snapshot.canonical_wire().len() < MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES);
        assert_eq!(
            RuntimeJournalSnapshot::decode(snapshot.canonical_wire()),
            Ok(snapshot)
        );
    }

    #[test]
    fn canonical_ordering_and_single_scope_are_enforced() {
        let mut replay = initialized_idle_state();
        replay.host.tenure_nonces = vec![
            ReplayLedgerRecord {
                identity: digest(2),
                value_digest: digest(3),
            },
            ReplayLedgerRecord {
                identity: digest(1),
                value_digest: digest(4),
            },
        ];
        assert_eq!(
            replay.validate(7),
            Err(RuntimeJournalError::NonCanonicalOrdering)
        );
        assert_eq!(
            RuntimeJournalSnapshot::decode(&unvalidated_wire(7, &replay)),
            Err(RuntimeJournalError::NonCanonicalOrdering)
        );

        let mut resources = initialized_idle_state();
        resources.owned_resources = vec![
            OwnedResourceRecord {
                kind: ResourceKind::ResourceSlot,
                logical_ref: [2; 16],
                generation: 1,
                runtime_host_epoch: 3,
                phase: ResourcePhase::Terminal,
                action_id: None,
                os_identity: Some(evidence(b"os", 5)),
                workspace_identity: Some(evidence(b"workspace", 6)),
                containment_identity: Some(evidence(b"containment", 7)),
                tombstone_evidence: Some(evidence(b"tombstone", 8)),
            },
            OwnedResourceRecord {
                kind: ResourceKind::ResourceSlot,
                logical_ref: [1; 16],
                generation: 1,
                runtime_host_epoch: 3,
                phase: ResourcePhase::Terminal,
                action_id: None,
                os_identity: Some(evidence(b"os", 6)),
                workspace_identity: Some(evidence(b"workspace", 7)),
                containment_identity: Some(evidence(b"containment", 8)),
                tombstone_evidence: Some(evidence(b"tombstone", 9)),
            },
        ];
        assert_eq!(
            resources.validate(7),
            Err(RuntimeJournalError::NonCanonicalOrdering)
        );

        let mut scopes = active_state();
        let mut wrong_scope = terminal_record_for(
            TerminalIdentityFixture {
                operation_id: [1; 16],
                request_digest: digest(7),
                request_nonce_identity: digest(8),
                source_revision: 1,
                source_plan_digest: source_plan_digest(9),
                target_slice_digest: target_slice_digest(10),
                temporal_constraint_id: [2; 16],
                temporal_lineage_digest: digest(11),
            },
            TerminalOutcome::AbortedBeforeIntentNoEffects,
            12,
            digest(13),
            1,
        );
        wrong_scope.source_scope = [2; 16];
        scopes.terminal_operations.push(wrong_scope);
        assert_eq!(
            scopes.validate(7),
            Err(RuntimeJournalError::MultipleSourceScopes)
        );
    }

    #[test]
    fn owner_action_and_cross_reference_contradictions_fail_closed() {
        let mut dangling_live = active_state();
        dangling_live.live_materialization = LiveMaterialization::None;
        assert_eq!(
            dangling_live.validate(7),
            Err(RuntimeJournalError::DanglingReference)
        );

        let mut generation_mismatch = draining_state();
        generation_mismatch.owned_resources[0].generation = 8;
        assert_eq!(
            generation_mismatch.validate(7),
            Err(RuntimeJournalError::DanglingReference)
        );

        let mut multiple = active_state();
        let request = opaque(b"start-request", 0xa2);
        multiple.host.request_nonces.push(ReplayLedgerRecord {
            identity: digest(0xa1),
            value_digest: request.digest,
        });
        multiple.host.temporal_lineages.push(TemporalLineageRecord {
            constraint_id: [0xa1; 16],
            source_scope: [1; 16],
            target_fingerprint: digest(0x22),
            original_budget_nanos: 1_000,
            remaining_budget_nanos: 500,
            clock_generation: 5,
            deadline_nanos: 40_000,
            lineage_digest: digest(0xa4),
        });
        multiple.source_revision_high_water = Some(SourceRevisionHighWater {
            source_scope: [1; 16],
            revision: 12,
        });
        multiple.prepared = Some(PreparedOperation {
            source_scope: [1; 16],
            operation_id: [0xa1; 16],
            source_revision: 12,
            request,
            request_nonce_identity: digest(0xa1),
            source_plan_digest: source_plan_digest(0xa2),
            incoming_slice_digest: target_slice_digest(0xa3),
            incoming_kind: DesiredHeadKind::OneSourceLoop,
            manifest_digest: digest(0x55),
            expected_active: ExpectedActiveCas::Exact(target_slice_digest(0x71)),
            temporal_constraint_id: [0xa1; 16],
            temporal_lineage_digest: digest(0xa4),
            installed_clock_generation: 5,
            installed_deadline_nanos: 40_000,
            phase: PreparedPhase::FirstActionIntent,
            action: Some(JournalActionRef {
                action_id: [0xa4; 16],
                kind: JournalActionKind::StartOneSourceLoop,
                runtime_host_epoch: 3,
                clock_generation: 5,
                domain_generation: 12,
                instance_generation: 12,
                resource_generation: 12,
            }),
            retiring: None,
            raw_outcome: None,
        });
        let active = multiple
            .active_desired
            .as_ref()
            .expect("fixture active must exist")
            .clone();
        let active_slice_digest = opaque_target_slice(&active.slice);
        multiple.recovery_action = Some(RecoveryAction {
            action: JournalActionRef {
                action_id: [0xa5; 16],
                kind: JournalActionKind::RestartReassembly,
                runtime_host_epoch: 3,
                clock_generation: 5,
                domain_generation: 13,
                instance_generation: 13,
                resource_generation: 13,
            },
            source_scope: active.source_scope,
            source_revision: active.source_revision,
            source_plan_digest: active.source_plan_digest,
            active_slice_digest,
            manifest_digest: digest(0x55),
            store_pinned_build_identity_digest: digest(0x56),
            compiled_build_instance_id: [0x57; 32],
            compiled_compatibility_digest: digest(0x58),
            signed_start_budget_nanos: 100,
            deadline_nanos: 50_000,
            deadline_evidence_digest: digest(0xa6),
            phase: RecoveryPhase::RecoveryPlannedNoEffects,
            raw_outcome: None,
        });
        assert_eq!(
            multiple.validate(7),
            Err(RuntimeJournalError::MultipleOwnerActions)
        );
    }

    #[test]
    fn admission_active_live_action_and_census_cross_references_are_bidirectional() {
        let tenure = tenure_successor_state(&initialized_idle_state());
        let admitted = admitted_one_source_state(&tenure);

        let mut wrong_nonce = admitted.clone();
        wrong_nonce.host.request_nonces[0].value_digest = digest(0xf1);
        assert_eq!(
            wrong_nonce.validate(9),
            Err(RuntimeJournalError::DanglingReference)
        );

        let mut wrong_temporal = admitted.clone();
        wrong_temporal
            .prepared
            .as_mut()
            .expect("fixture prepared must exist")
            .temporal_lineage_digest = digest(0xf2);
        assert_eq!(
            wrong_temporal.validate(9),
            Err(RuntimeJournalError::DanglingReference)
        );

        let mut wrong_revision = admitted;
        wrong_revision
            .source_revision_high_water
            .as_mut()
            .expect("fixture revision must exist")
            .revision = 2;
        assert_eq!(
            wrong_revision.validate(9),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut wrong_active_result = active_state();
        wrong_active_result.terminal_operations[0].result_digest = digest(0xf3);
        wrong_active_result.terminal_operations[0].canonical_response =
            opaque(b"changed-terminal-response", 0xf3);
        assert_eq!(
            wrong_active_result.validate(7),
            Err(RuntimeJournalError::DanglingReference)
        );

        let mut wrong_live_census = active_state();
        let LiveMaterialization::LiveReady {
            resource_census_digest,
            ..
        } = &mut wrong_live_census.live_materialization
        else {
            unreachable!();
        };
        *resource_census_digest = digest(0xf4);
        assert_eq!(
            wrong_live_census.validate(7),
            Err(RuntimeJournalError::DanglingReference)
        );

        let mut wrong_action_resource = recovering_state();
        wrong_action_resource.owned_resources[0].action_id = Some([0xf5; 16]);
        assert_eq!(
            wrong_action_resource.validate(7),
            Err(RuntimeJournalError::DanglingReference)
        );
    }

    #[test]
    fn store_build_compiled_channel_and_key_pins_are_immutable_and_recovery_bound() {
        let previous_state = active_state();
        let previous = snapshot(7, previous_state.clone());
        let base = startup_successor_state(&previous_state);
        let mut mutations = Vec::new();

        let mut store_identity = base.clone();
        store_identity.host.store_pinned_build_identity = pinned(b"changed-build-id", 0xf0);
        mutations.push(store_identity);

        let mut compiled_id = base.clone();
        compiled_id.host.compiled_build_instance_id = [0xf1; 32];
        mutations.push(compiled_id);

        let mut compiled_compatibility = base.clone();
        compiled_compatibility.host.compiled_compatibility_digest = digest(0xf2);
        mutations.push(compiled_compatibility);

        let mut channel = base.clone();
        channel.host.channel_policy_fingerprint = digest(0xf3);
        mutations.push(channel);

        let mut key = base;
        key.host.controller_key_fingerprint = digest(0xf4);
        mutations.push(key);

        for mutation in mutations {
            assert_eq!(
                snapshot(8, mutation).validate_successor_of(&previous),
                Err(RuntimeJournalError::NonMonotonicTransition)
            );
        }

        let mut recovery = recovering_state();
        recovery
            .recovery_action
            .as_mut()
            .expect("fixture recovery must exist")
            .compiled_build_instance_id = [0xf5; 32];
        assert_eq!(
            recovery.validate(7),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );
    }

    #[test]
    fn recovery_identity_budget_and_deadline_lineage_are_same_action_immutable() {
        let active = active_state();
        let startup = startup_successor_state(&active);
        let cleanup = cleanup_old_live_resources_state(&startup);
        let tombstoned = tombstone_old_live_resources_state(&cleanup);
        let plan = recovery_plan_state(&tombstoned);
        let intent = recovery_intent_state(&plan);
        let previous = snapshot(11, plan);

        let mut mutations = Vec::new();
        let mut budget = intent.clone();
        budget
            .recovery_action
            .as_mut()
            .expect("fixture recovery must exist")
            .signed_start_budget_nanos += 1;
        mutations.push(budget);

        let mut deadline = intent.clone();
        deadline
            .recovery_action
            .as_mut()
            .expect("fixture recovery must exist")
            .deadline_nanos += 1;
        mutations.push(deadline);

        let mut deadline_evidence = intent;
        deadline_evidence
            .recovery_action
            .as_mut()
            .expect("fixture recovery must exist")
            .deadline_evidence_digest = digest(0xf6);
        mutations.push(deadline_evidence);

        for mutation in mutations {
            assert_eq!(
                snapshot(12, mutation).validate_successor_of(&previous),
                Err(RuntimeJournalError::NonMonotonicTransition)
            );
        }

        let mut intent_with_result = recovery_intent_state(previous.state());
        intent_with_result
            .recovery_action
            .as_mut()
            .expect("fixture recovery must exist")
            .raw_outcome = Some(RawActionOutcomeLatch {
            callback: CallbackOutcome::KnownSuccess,
            callback_reason_digest: None,
            deadline: DeadlineOutcome::NotObserved,
            observed_clock_generation: 0,
            observed_at_nanos: 0,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        });
        assert_eq!(
            snapshot(12, intent_with_result).validate_successor_of(&previous),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let mut premature_timeout = recovering_state();
        let recovery = premature_timeout
            .recovery_action
            .as_mut()
            .expect("fixture recovery must exist");
        recovery.raw_outcome = Some(RawActionOutcomeLatch {
            callback: CallbackOutcome::NotInvoked,
            callback_reason_digest: None,
            deadline: DeadlineOutcome::TimedOut,
            observed_clock_generation: recovery.action.clock_generation,
            observed_at_nanos: recovery.deadline_nanos - 1,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        });
        assert_eq!(
            premature_timeout.validate(7),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );
    }

    #[test]
    fn terminal_transactions_reject_wrong_metadata_outcome_census_and_resource_injection() {
        let idle = initialized_idle_state();
        let tenure = tenure_successor_state(&idle);
        let admitted = admitted_one_source_state(&tenure);
        let intent = one_source_intent_state(&admitted);
        let staged = staged_one_source_resources_state(&intent);
        let owned = owned_one_source_resources_state(&staged);
        let previous = snapshot(12, owned.clone());
        let terminal = normal_start_terminal_state(&owned);

        let failed_raw = RawActionOutcomeLatch {
            callback: CallbackOutcome::KnownError,
            callback_reason_digest: Some(digest(0xfc)),
            deadline: DeadlineOutcome::NotObserved,
            observed_clock_generation: 0,
            observed_at_nanos: 0,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        };
        let mut laundered_success = terminal.clone();
        let terminal_record = laundered_success
            .terminal_operations
            .last_mut()
            .expect("fixture terminal must exist");
        terminal_record.predecessor_raw_outcome = Some(failed_raw);
        terminal_record.selection.raw = failed_raw;
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 13, laundered_success,),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut stale_completion = terminal.clone();
        stale_completion
            .terminal_operations
            .last_mut()
            .expect("fixture terminal must exist")
            .completion_snapshot_sequence = 12;
        assert_eq!(
            snapshot(13, stale_completion).validate_successor_of(&previous),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let mut wrong_census = terminal.clone();
        wrong_census
            .terminal_operations
            .last_mut()
            .expect("fixture terminal must exist")
            .resource_census_digest = digest(0xf7);
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 13, wrong_census),
            Err(RuntimeJournalError::DanglingReference)
        );

        let mut injected_resource = terminal.clone();
        injected_resource.owned_resources.push(OwnedResourceRecord {
            kind: ResourceKind::ResourceSlot,
            logical_ref: [0xf8; 16],
            generation: 1,
            runtime_host_epoch: 3,
            phase: ResourcePhase::Terminal,
            action_id: None,
            os_identity: Some(evidence(b"injected-os", 0xf8)),
            workspace_identity: Some(evidence(b"injected-workspace", 0xf9)),
            containment_identity: Some(evidence(b"injected-containment", 0xfa)),
            tombstone_evidence: Some(evidence(b"injected-tombstone", 0xfb)),
        });
        let census = compute_resource_census_digest(&injected_resource.owned_resources)
            .expect("fixture census must build");
        let LiveMaterialization::LiveReady {
            resource_census_digest,
            ..
        } = &mut injected_resource.live_materialization
        else {
            unreachable!();
        };
        *resource_census_digest = census;
        injected_resource
            .terminal_operations
            .last_mut()
            .expect("fixture terminal must exist")
            .resource_census_digest = census;
        assert_eq!(
            snapshot(13, injected_resource).validate_successor_of(&previous),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let mut wrong_outcome = terminal;
        wrong_outcome
            .terminal_operations
            .last_mut()
            .expect("fixture terminal must exist")
            .selection
            .primary = TerminalOutcome::AbortedBeforeIntentNoEffects;
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 13, wrong_outcome),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let old_active = active_state();
        let admitted_empty = admitted_empty_state(&old_active);
        let mut draining = empty_head_retire_state(&admitted_empty);
        draining
            .prepared
            .as_mut()
            .expect("fixture prepared must exist")
            .raw_outcome = Some(RawActionOutcomeLatch {
            callback: CallbackOutcome::KnownError,
            callback_reason_digest: Some(digest(0xfd)),
            deadline: DeadlineOutcome::NotObserved,
            observed_clock_generation: 0,
            observed_at_nanos: 0,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        });
        let mut laundered_empty_success =
            exact_zero_terminal_state(&draining, TerminalOutcome::StopFailedButExactZero, 10);
        laundered_empty_success
            .terminal_operations
            .last_mut()
            .expect("fixture terminal")
            .selection
            .primary = TerminalOutcome::EmptyDeactivateExactZero;
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 10, laundered_empty_success,),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );
    }

    #[test]
    fn temporal_lineage_is_bound_to_the_envelope_owner_target() {
        let state = active_state();
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x23), 7, state.clone()),
            Err(RuntimeJournalError::DanglingReference)
        );

        let mut rewritten = state;
        rewritten.host.temporal_lineages[0].target_fingerprint = digest(0x23);
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 7, rewritten),
            Err(RuntimeJournalError::DanglingReference)
        );
    }

    #[test]
    fn revision_high_water_and_new_tenure_nonce_have_exact_bidirectional_owners() {
        let mut invented_revision = active_state();
        invented_revision
            .source_revision_high_water
            .as_mut()
            .expect("fixture revision must exist")
            .revision += 1;
        assert_eq!(
            invented_revision.validate(7),
            Err(RuntimeJournalError::DanglingReference)
        );

        let previous_state = active_state();
        let previous = snapshot(7, previous_state.clone());
        let mut reused_nonce = tenure_successor_state(&previous_state);
        let old_nonce = previous_state.host.tenure_nonces[0];
        let fence = reused_nonce
            .writer_fence
            .as_mut()
            .expect("fixture fence must exist");
        fence.tenure_nonce_identity = old_nonce.identity;
        fence.proof_envelope_digest = old_nonce.value_digest;
        assert_eq!(reused_nonce.validate(8), Ok(()));
        assert_eq!(
            snapshot(8, reused_nonce).validate_successor_of(&previous),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );
    }

    #[test]
    fn retire_recovery_resource_and_terminal_evidence_are_mandatory() {
        let mut retire_without_budget = draining_state();
        retire_without_budget
            .prepared
            .as_mut()
            .and_then(|prepared| prepared.retiring.as_mut())
            .expect("fixture retiring facts must exist")
            .signed_cleanup_budget_nanos = 0;
        assert_eq!(
            retire_without_budget.validate(7),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut recovery_without_deadline = recovering_state();
        recovery_without_deadline
            .recovery_action
            .as_mut()
            .expect("fixture recovery must exist")
            .deadline_nanos = 0;
        assert_eq!(
            recovery_without_deadline.validate(7),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut resource_without_workspace = active_state();
        resource_without_workspace.owned_resources[0].workspace_identity = None;
        assert_eq!(
            resource_without_workspace.validate(7),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut terminal_without_tombstone = state_at_all_fixed_capacity_limits();
        terminal_without_tombstone.owned_resources[0].tombstone_evidence = None;
        assert_eq!(
            terminal_without_tombstone.validate(7),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut terminal_without_response = active_state();
        terminal_without_response.terminal_operations[0]
            .canonical_response
            .canonical_bytes = Box::default();
        assert_eq!(
            terminal_without_response.validate(7),
            Err(RuntimeJournalError::EmptyOpaqueValue)
        );

        let tenure = tenure_successor_state(&initialized_idle_state());
        let mut zero_cas = admitted_one_source_state(&tenure);
        zero_cas
            .prepared
            .as_mut()
            .expect("fixture prepared must exist")
            .expected_active =
            ExpectedActiveCas::Exact(TargetSliceDigest::new(Digest32::from_bytes([0; 32])));
        assert_eq!(zero_cas.validate(9), Err(RuntimeJournalError::ZeroDigest));
    }

    #[test]
    fn request_is_the_only_slice_body_and_owner_commitments_cannot_be_swapped_in_successor() {
        let tenure = tenure_successor_state(&initialized_idle_state());
        let admitted = admitted_one_source_state(&tenure);
        let payload = encode_payload(&admitted).expect("fixture payload must encode");
        let request_body = b"one-source-request-with-sole-slice";
        assert_eq!(
            payload
                .windows(request_body.len())
                .filter(|window| *window == request_body)
                .count(),
            1,
            "the journal must not persist a second independently mutable Slice body",
        );

        let mut swapped = admitted.clone();
        swapped
            .prepared
            .as_mut()
            .expect("fixture prepared must exist")
            .incoming_slice_digest = target_slice_digest(0xf6);
        swapped.last_transaction = RuntimeJournalTransaction::PreparedProgress;
        assert_eq!(
            snapshot(10, swapped).validate_successor_of(&snapshot(9, admitted)),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );
    }

    #[test]
    fn startup_is_neutral_not_ready_and_preserves_interrupted_action_truth() {
        let previous_state = draining_state();
        let current_state = startup_successor_state(&previous_state);
        let current = snapshot(8, current_state.clone());
        assert_eq!(
            current.validate_successor_of(&snapshot(7, previous_state.clone())),
            Ok(())
        );
        assert!(matches!(
            current_state.live_materialization,
            LiveMaterialization::StartupInvalidated {
                recovery_eligibility: StartupRecoveryEligibility::ReconcileRequired,
                ..
            }
        ));
        let prepared = current_state
            .prepared
            .as_ref()
            .expect("action must persist");
        assert_eq!(prepared.phase, PreparedPhase::StartupReconcileRequired);
        assert!(prepared.action.is_some());
        assert!(prepared.raw_outcome.is_some_and(|raw| raw.host_interrupted));
        assert_eq!(
            current_state.owned_resources,
            previous_state.owned_resources
        );

        let active_previous = active_state();
        let neutral = startup_successor_state(&active_previous);
        let cleanup = cleanup_old_live_resources_state(&neutral);
        let tombstoned = tombstone_old_live_resources_state(&cleanup);
        let mut direct_recovering = recovery_plan_state(&tombstoned);
        direct_recovering.last_transaction = RuntimeJournalTransaction::StartupInvalidation;
        assert_eq!(
            snapshot(8, direct_recovering).validate_successor_of(&snapshot(7, active_previous)),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let tenured_idle = tenure_successor_state(&initialized_idle_state());
        let admitted = admitted_one_source_state(&tenured_idle);
        let mut direct_prepared = admitted.clone();
        direct_prepared.last_transaction = RuntimeJournalTransaction::StartupInvalidation;
        direct_prepared.host.runtime_host_epoch_high_water += 1;
        direct_prepared.host.clock_generation_high_water += 1;
        direct_prepared.host.temporal_lineages[0].clock_generation += 1;
        let prepared = direct_prepared
            .prepared
            .as_mut()
            .expect("fixture prepared must exist");
        prepared.installed_clock_generation += 1;
        assert_eq!(
            snapshot(9, direct_prepared).validate_successor_of(&snapshot(8, tenured_idle)),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let mut direct_resource =
            staged_one_source_resources_state(&one_source_intent_state(&admitted));
        direct_resource.last_transaction = RuntimeJournalTransaction::StartupInvalidation;
        direct_resource.host.runtime_host_epoch_high_water += 1;
        direct_resource.host.clock_generation_high_water += 1;
        direct_resource.host.temporal_lineages[0].clock_generation += 1;
        let prepared = direct_resource
            .prepared
            .as_mut()
            .expect("fixture prepared must exist");
        prepared.installed_clock_generation += 1;
        let action = prepared.action.as_mut().expect("fixture action must exist");
        action.runtime_host_epoch += 1;
        action.clock_generation += 1;
        for resource in &mut direct_resource.owned_resources {
            resource.runtime_host_epoch += 1;
        }
        assert_eq!(
            snapshot(9, direct_resource).validate_successor_of(&snapshot(
                8,
                tenure_successor_state(&initialized_idle_state())
            )),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );
    }

    #[test]
    fn prepared_raw_resource_and_terminal_truth_never_regress_or_disappear() {
        let tenure = tenure_successor_state(&initialized_idle_state());
        let admitted = admitted_one_source_state(&tenure);
        let intent = one_source_intent_state(&admitted);

        let mut intent_with_result = intent.clone();
        intent_with_result
            .prepared
            .as_mut()
            .expect("fixture prepared must exist")
            .raw_outcome = Some(RawActionOutcomeLatch {
            callback: CallbackOutcome::KnownSuccess,
            callback_reason_digest: None,
            deadline: DeadlineOutcome::NotObserved,
            observed_clock_generation: 0,
            observed_at_nanos: 0,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        });
        assert_eq!(
            snapshot(10, intent_with_result).validate_successor_of(&snapshot(9, admitted.clone())),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let mut regressed_phase = intent.clone();
        regressed_phase.last_transaction = RuntimeJournalTransaction::PreparedProgress;
        let prepared = regressed_phase
            .prepared
            .as_mut()
            .expect("fixture prepared must exist");
        prepared.phase = PreparedPhase::PreparedNoEffects;
        prepared.action = None;
        assert_eq!(
            snapshot(11, regressed_phase).validate_successor_of(&snapshot(10, intent.clone())),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let mut rewritten_action = intent.clone();
        rewritten_action.last_transaction = RuntimeJournalTransaction::PreparedProgress;
        rewritten_action
            .prepared
            .as_mut()
            .and_then(|prepared| prepared.action.as_mut())
            .expect("fixture action must exist")
            .resource_generation = 3;
        assert_eq!(
            snapshot(11, rewritten_action).validate_successor_of(&snapshot(10, intent)),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let previous_drain = draining_state();
        let mut deleted_raw = previous_drain.clone();
        deleted_raw.last_transaction = RuntimeJournalTransaction::PreparedProgress;
        deleted_raw
            .prepared
            .as_mut()
            .expect("fixture prepared must exist")
            .raw_outcome = None;
        assert_eq!(
            snapshot(8, deleted_raw).validate_successor_of(&snapshot(7, previous_drain)),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let mut deleted_terminal = active_state();
        deleted_terminal.terminal_operations.clear();
        assert_eq!(
            deleted_terminal.validate(7),
            Err(RuntimeJournalError::DanglingReference)
        );
    }

    #[test]
    fn canonical_empty_quarantine_and_recovery_failure_cannot_move_back_to_ready() {
        let active = active_state();
        let startup = startup_successor_state(&active);
        let cleanup = cleanup_old_live_resources_state(&startup);
        let tombstoned = tombstone_old_live_resources_state(&cleanup);
        let plan = recovery_plan_state(&tombstoned);
        let intent = recovery_intent_state(&plan);

        let mut failed = intent.clone();
        failed.last_transaction = RuntimeJournalTransaction::RecoveryPublish;
        let recovery = failed.recovery_action.expect("fixture recovery must exist");
        let failure_raw = RawActionOutcomeLatch {
            callback: CallbackOutcome::NotInvoked,
            callback_reason_digest: None,
            deadline: DeadlineOutcome::TimedOut,
            observed_clock_generation: recovery.action.clock_generation,
            observed_at_nanos: recovery.deadline_nanos,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        };
        let failure_census = compute_resource_census_digest(&failed.owned_resources)
            .expect("fixture census must build");
        let failure_terminal = recovery_terminal_record(
            recovery,
            TerminalSelectionObservation {
                raw: failure_raw,
                selection_clock_generation: failed.host.clock_generation_high_water,
                selection_observed_at_nanos: recovery.deadline_nanos,
                lifecycle_effect: TerminalLifecycleEffect::ProvenNotStarted,
            },
            failure_census,
            (failed.host.runtime_host_epoch_high_water, 13),
        );
        let failure_latch_digest = failure_terminal
            .failure_latch_digest
            .expect("fixture permanent failure must have evidence");
        failed.recovery_terminals.push(failure_terminal);
        failed.recovery_action = None;
        failed.live_materialization = LiveMaterialization::RecoveryFailedNotReady {
            active_slice_digest: recovery.active_slice_digest,
            terminal_recovery_action_id: recovery.action.action_id,
            failure_latch_digest,
            resource_census_digest: failure_census,
        };
        let failed_snapshot = snapshot(13, failed.clone());
        assert_eq!(
            failed_snapshot.validate_successor_of(&snapshot(12, intent.clone())),
            Ok(())
        );

        let mut rewritten_failure = failed.clone();
        rewritten_failure.recovery_terminals[0]
            .selection
            .raw
            .higher_tenure_takeover = true;
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 13, rewritten_failure),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut retry = recovery_plan_state(&failed);
        retry.last_transaction = RuntimeJournalTransaction::RecoveryPlan;
        assert_eq!(
            snapshot(14, retry).validate_successor_of(&failed_snapshot),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let mut quarantined = intent.clone();
        quarantined.last_transaction = RuntimeJournalTransaction::Quarantine;
        quarantined.live_materialization = LiveMaterialization::Quarantined {
            active_slice_digest: quarantined
                .active_desired
                .as_ref()
                .map(|head| opaque_target_slice(&head.slice)),
            reason_digest: digest(0xe9),
            resource_census_digest: compute_resource_census_digest(&quarantined.owned_resources)
                .expect("fixture census must build"),
        };
        let quarantined_snapshot = snapshot(13, quarantined.clone());
        assert_eq!(
            quarantined_snapshot.validate_successor_of(&snapshot(12, intent)),
            Ok(())
        );
        let mut unquarantined = quarantined;
        unquarantined.last_transaction = RuntimeJournalTransaction::RecoveryPublish;
        unquarantined.recovery_action = None;
        unquarantined.live_materialization = LiveMaterialization::RecoveryFailedNotReady {
            active_slice_digest: recovery.active_slice_digest,
            terminal_recovery_action_id: recovery.action.action_id,
            failure_latch_digest,
            resource_census_digest: compute_resource_census_digest(&unquarantined.owned_resources)
                .expect("fixture census must build"),
        };
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 14, unquarantined),
            Err(RuntimeJournalError::DanglingReference)
        );

        let old_active = active_state();
        let admitted_empty = admitted_empty_state(&old_active);
        let draining = empty_head_retire_state(&admitted_empty);
        let observed = observed_empty_success_state(&draining);
        let exact_zero =
            exact_zero_terminal_state(&observed, TerminalOutcome::EmptyDeactivateExactZero, 11);
        let exact_zero_snapshot = snapshot(11, exact_zero.clone());
        let mut invented_ready = exact_zero;
        invented_ready.last_transaction = RuntimeJournalTransaction::RecoveryPublish;
        let empty_digest = invented_ready
            .active_desired
            .as_ref()
            .expect("fixture empty head must exist")
            .slice
            .digest;
        invented_ready.live_materialization = LiveMaterialization::RecoveryFailedNotReady {
            active_slice_digest: TargetSliceDigest::new(empty_digest),
            terminal_recovery_action_id: recovery.action.action_id,
            failure_latch_digest: digest(0xeb),
            resource_census_digest: compute_resource_census_digest(&invented_ready.owned_resources)
                .expect("fixture census must build"),
        };
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 11, invented_ready,),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );
        assert_eq!(
            exact_zero_snapshot.state(),
            &exact_zero_terminal_state(&observed, TerminalOutcome::EmptyDeactivateExactZero, 11,)
        );
    }

    #[test]
    fn recovery_abort_history_survives_repeated_startup_and_forces_fresh_producers() {
        let active = active_state();
        let startup = startup_successor_state(&active);
        let cleanup = cleanup_old_live_resources_state(&startup);
        let tombstoned = tombstone_old_live_resources_state(&cleanup);

        let plan_a = recovery_plan_state(&tombstoned);
        assert_eq!(
            snapshot(11, plan_a.clone()).validate_successor_of(&snapshot(10, tombstoned)),
            Ok(())
        );
        let action_a = plan_a.recovery_action.expect("plan A must own an action");

        let crash_a = startup_successor_state(&plan_a);
        assert_eq!(
            snapshot(12, crash_a.clone()).validate_successor_of(&snapshot(11, plan_a)),
            Ok(())
        );
        let invalidated_a = crash_a
            .recovery_action
            .expect("crashed plan A must remain durable");
        assert_eq!(invalidated_a.action, action_a.action);
        assert_eq!(
            invalidated_a.phase,
            RecoveryPhase::StartupInvalidatedNoEffects
        );

        let crash_a_again = startup_successor_state(&crash_a);
        assert_eq!(
            snapshot(13, crash_a_again.clone()).validate_successor_of(&snapshot(12, crash_a)),
            Ok(())
        );
        assert_eq!(crash_a_again.recovery_action, Some(invalidated_a));

        let aborted_a = recovery_abort_no_effects_state(&crash_a_again, 14);
        assert_eq!(
            snapshot(14, aborted_a.clone()).validate_successor_of(&snapshot(13, crash_a_again)),
            Ok(())
        );
        assert!(aborted_a.recovery_action.is_none());
        assert_eq!(aborted_a.recovery_terminals.len(), 1);
        assert_eq!(aborted_a.recovery_terminals[0].recovery, invalidated_a);
        assert_eq!(
            aborted_a.recovery_terminals[0].selection.primary,
            TerminalOutcome::AbortedBeforeIntentNoEffects
        );

        let plan_b = recovery_plan_state(&aborted_a);
        let action_b = plan_b.recovery_action.expect("plan B must own an action");
        assert_ne!(action_b.action.action_id, action_a.action.action_id);
        assert!(action_b.action.domain_generation > action_a.action.domain_generation);
        assert!(action_b.action.instance_generation > action_a.action.instance_generation);
        assert!(action_b.action.resource_generation > action_a.action.resource_generation);
        assert_eq!(
            snapshot(15, plan_b.clone()).validate_successor_of(&snapshot(14, aborted_a.clone())),
            Ok(())
        );

        let crash_b = startup_successor_state(&plan_b);
        assert_eq!(
            snapshot(16, crash_b.clone()).validate_successor_of(&snapshot(15, plan_b)),
            Ok(())
        );
        let aborted_b = recovery_abort_no_effects_state(&crash_b, 17);
        assert_eq!(
            snapshot(17, aborted_b.clone()).validate_successor_of(&snapshot(16, crash_b)),
            Ok(())
        );
        assert_eq!(aborted_b.recovery_terminals.len(), 2);
        assert_eq!(
            aborted_b.recovery_terminals[0],
            aborted_a.recovery_terminals[0]
        );
        assert_eq!(
            aborted_b.recovery_terminals[1].recovery.action,
            action_b.action
        );

        let mut forged_abort = aborted_a;
        let forged_raw = forged_abort.recovery_terminals[0].selection.raw;
        forged_abort.recovery_terminals[0].recovery.raw_outcome = Some(forged_raw);
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 14, forged_abort),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );
    }

    #[test]
    fn recovery_timeouts_are_permanent_and_failure_history_survives_every_startup() {
        let active = active_state();
        let startup = startup_successor_state(&active);
        let cleanup = cleanup_old_live_resources_state(&startup);
        let tombstoned = tombstone_old_live_resources_state(&cleanup);

        let planned = recovery_plan_state(&tombstoned);
        let pre_intent_failure = recovery_timeout_failure_state(&planned, 12);
        assert_eq!(
            snapshot(12, pre_intent_failure.clone())
                .validate_successor_of(&snapshot(11, planned.clone())),
            Ok(())
        );
        assert_eq!(
            pre_intent_failure.recovery_terminals[0].selection.primary,
            TerminalOutcome::StartTimedOutBeforeIntentNoEffects
        );

        let intent = recovery_intent_state(&planned);
        assert_eq!(
            snapshot(12, intent.clone()).validate_successor_of(&snapshot(11, planned)),
            Ok(())
        );
        let post_intent_failure = recovery_timeout_failure_state(&intent, 13);
        assert_eq!(
            snapshot(13, post_intent_failure.clone()).validate_successor_of(&snapshot(12, intent)),
            Ok(())
        );
        assert_eq!(
            post_intent_failure.recovery_terminals[0].selection.primary,
            TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero
        );

        let first_restart = startup_successor_state(&post_intent_failure);
        assert_eq!(
            snapshot(14, first_restart.clone())
                .validate_successor_of(&snapshot(13, post_intent_failure.clone())),
            Ok(())
        );
        let second_restart = startup_successor_state(&first_restart);
        assert_eq!(
            snapshot(15, second_restart.clone())
                .validate_successor_of(&snapshot(14, first_restart.clone())),
            Ok(())
        );
        assert_eq!(
            second_restart.recovery_terminals,
            post_intent_failure.recovery_terminals
        );
        let LiveMaterialization::StartupInvalidated {
            recovery_eligibility,
            failure_evidence_digest,
            ..
        } = second_restart.live_materialization
        else {
            panic!("failure restart must remain startup-invalidated");
        };
        assert_eq!(
            recovery_eligibility,
            StartupRecoveryEligibility::RecoveryFailureLatched
        );
        assert_eq!(
            failure_evidence_digest,
            post_intent_failure.recovery_terminals[0].failure_latch_digest
        );

        let mut deleted_history = second_restart;
        deleted_history.recovery_terminals.clear();
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 15, deleted_history),
            Err(RuntimeJournalError::DanglingReference)
        );

        let active = active_state();
        let startup = startup_successor_state(&active);
        let old_cleanup = cleanup_old_live_resources_state(&startup);
        let tombstoned = tombstone_old_live_resources_state(&old_cleanup);
        let planned = recovery_plan_state(&tombstoned);

        let planned_tenure = superseding_tenure_state(&planned);
        assert_eq!(planned_tenure.recovery_action, planned.recovery_action);
        assert_eq!(
            snapshot(12, planned_tenure).validate_successor_of(&snapshot(11, planned.clone())),
            Ok(())
        );

        let intent = recovery_intent_state(&planned);
        let intent_tenure = superseding_tenure_state(&intent);
        let intent_takeover = intent_tenure
            .recovery_action
            .expect("post-intent tenure must preserve the recovery action");
        assert_eq!(intent_takeover.phase, RecoveryPhase::StartCallIntent);
        assert!(
            intent_takeover
                .raw_outcome
                .is_some_and(|raw| raw.higher_tenure_takeover && !raw.host_interrupted)
        );
        assert_eq!(
            snapshot(13, intent_tenure).validate_successor_of(&snapshot(12, intent.clone())),
            Ok(())
        );

        let staged = staged_recovery_resources_state(&intent);
        let owned = owned_recovery_resources_state(&staged);

        let takeover = superseding_tenure_state(&owned);
        let takeover_raw = takeover
            .recovery_action
            .and_then(|recovery| recovery.raw_outcome)
            .expect("post-intent recovery takeover must be durable");
        assert!(takeover_raw.higher_tenure_takeover && !takeover_raw.host_interrupted);
        let takeover_cleanup = cleanup_owner_event_recovery_resources_state(&takeover);
        let takeover_failure = owner_event_recovery_failure_state(&takeover_cleanup, 17);
        let takeover_final = validated_successor_chain(
            "tenure-superseded recovery exact-zero failure",
            7,
            vec![
                active.clone(),
                startup.clone(),
                old_cleanup.clone(),
                tombstoned.clone(),
                planned.clone(),
                intent.clone(),
                staged.clone(),
                owned.clone(),
                takeover,
                takeover_cleanup,
                takeover_failure,
            ],
        );
        assert_eq!(
            takeover_final.state().recovery_terminals[0]
                .selection
                .primary,
            TerminalOutcome::SupersededAfterIntentExactZero
        );

        let interrupted = startup_successor_state(&owned);
        let interrupted_cleanup = cleanup_owner_event_recovery_resources_state(&interrupted);
        let interrupted_failure = owner_event_recovery_failure_state(&interrupted_cleanup, 17);
        let interrupted_final = validated_successor_chain(
            "startup-interrupted recovery exact-zero failure",
            7,
            vec![
                active.clone(),
                startup.clone(),
                old_cleanup.clone(),
                tombstoned.clone(),
                planned.clone(),
                intent.clone(),
                staged.clone(),
                owned.clone(),
                interrupted.clone(),
                interrupted_cleanup,
                interrupted_failure,
            ],
        );
        assert_eq!(
            interrupted_final.state().recovery_terminals[0]
                .selection
                .primary,
            TerminalOutcome::AbortedBeforeHeadCommitExactZero
        );
        assert!(matches!(
            interrupted_final.state().live_materialization,
            LiveMaterialization::RecoveryFailedNotReady { .. }
        ));

        let superseded = superseding_tenure_state(&interrupted);
        let superseded_raw = superseded
            .recovery_action
            .and_then(|recovery| recovery.raw_outcome)
            .expect("superseding tenure must preserve interruption provenance");
        assert!(superseded_raw.host_interrupted && superseded_raw.higher_tenure_takeover);
        let superseded_cleanup = cleanup_owner_event_recovery_resources_state(&superseded);
        let superseded_failure = owner_event_recovery_failure_state(&superseded_cleanup, 18);
        let superseded_final = validated_successor_chain(
            "tenure-superseded interrupted recovery exact-zero failure",
            7,
            vec![
                active,
                startup,
                old_cleanup,
                tombstoned,
                planned,
                intent,
                staged,
                owned,
                interrupted,
                superseded,
                superseded_cleanup,
                superseded_failure,
            ],
        );
        assert_eq!(
            superseded_final.state().recovery_terminals[0]
                .selection
                .primary,
            TerminalOutcome::SupersededAfterIntentExactZero
        );
    }

    #[test]
    fn startup_failure_and_canonical_empty_accept_higher_revision_empty_fast_paths() {
        let active = active_state();
        let startup = startup_successor_state(&active);
        let cleanup = cleanup_old_live_resources_state(&startup);
        let tombstoned = tombstone_old_live_resources_state(&cleanup);
        let plan = recovery_plan_state(&tombstoned);
        let failure = recovery_timeout_failure_state(&plan, 12);
        let failed_restart = startup_successor_state(&failure);
        let admitted_after_failure = admitted_empty_state(&failed_restart);
        assert_eq!(
            snapshot(14, admitted_after_failure.clone())
                .validate_successor_of(&snapshot(13, failed_restart)),
            Ok(())
        );
        let empty_after_failure = exact_zero_terminal_state(
            &admitted_after_failure,
            TerminalOutcome::EmptyDeactivateExactZero,
            15,
        );
        let prepared_after_failure = admitted_after_failure
            .prepared
            .as_ref()
            .expect("fast path admission must remain prepared");
        let appended_after_failure = appended_terminal_for_prepared(
            &empty_after_failure,
            &admitted_after_failure,
            prepared_after_failure,
        )
        .expect("fast path must append the exact prepared terminal");
        assert!(exact_zero_fast_path_eligible(&admitted_after_failure));
        assert!(terminal_raw_is_valid_successor(
            appended_after_failure,
            prepared_after_failure
        ));
        assert!(resources_reach_exact_zero(
            &empty_after_failure.owned_resources,
            &admitted_after_failure.owned_resources,
            None
        ));
        assert_eq!(
            snapshot(15, empty_after_failure)
                .validate_successor_of(&snapshot(14, admitted_after_failure)),
            Ok(())
        );

        let old_active = active_state();
        let first_empty_admission = admitted_empty_state(&old_active);
        let draining = empty_head_retire_state(&first_empty_admission);
        let observed = observed_empty_success_state(&draining);
        let canonical_empty =
            exact_zero_terminal_state(&observed, TerminalOutcome::EmptyDeactivateExactZero, 11);
        let canonical_restart = startup_successor_state(&canonical_empty);
        let higher_revision_admission = admitted_empty_state(&canonical_restart);
        assert!(
            higher_revision_admission
                .prepared
                .as_ref()
                .expect("higher revision admission must be prepared")
                .source_revision
                > canonical_empty
                    .active_desired
                    .as_ref()
                    .expect("canonical empty must be active")
                    .source_revision
        );
        assert_eq!(
            snapshot(13, higher_revision_admission.clone())
                .validate_successor_of(&snapshot(12, canonical_restart)),
            Ok(())
        );
        let higher_revision_empty = exact_zero_terminal_state(
            &higher_revision_admission,
            TerminalOutcome::EmptyDeactivateExactZero,
            14,
        );
        assert_eq!(
            snapshot(14, higher_revision_empty)
                .validate_successor_of(&snapshot(13, higher_revision_admission)),
            Ok(())
        );
    }

    #[test]
    fn checksum_valid_terminal_and_recovery_fact_rewrites_fail_closed_individually() {
        let assert_resealed_rejected = |sequence: u64, state: &RuntimeJournalState, label: &str| {
            let wire = unvalidated_wire(sequence, state);
            assert!(
                RuntimeJournalSnapshot::decode(&wire).is_err(),
                "checksum-valid {label} rewrite must fail closed"
            );
        };

        let active = active_state();

        let tenure = tenure_successor_state(&initialized_idle_state());
        let admitted = admitted_one_source_state(&tenure);
        let mut prepared_owner_forgery = one_source_intent_state(&admitted);
        prepared_owner_forgery
            .prepared
            .as_mut()
            .expect("fixture prepared operation must exist")
            .raw_outcome = Some(takeover_raw(None));
        assert_resealed_rejected(
            10,
            &prepared_owner_forgery,
            "prepared-owner-event-without-tenure-phase",
        );

        let mut action_kind = active.clone();
        action_kind.terminal_operations[0]
            .action
            .as_mut()
            .expect("fixture terminal must have an action")
            .kind = JournalActionKind::DrainToEmpty;
        assert_resealed_rejected(7, &action_kind, "action-kind");

        let mut raw = active.clone();
        raw.terminal_operations[0].selection.raw.callback = CallbackOutcome::KnownError;
        raw.terminal_operations[0]
            .selection
            .raw
            .callback_reason_digest = Some(digest(0xf0));
        assert_resealed_rejected(7, &raw, "raw-outcome");

        let mut incoming_kind = active.clone();
        incoming_kind.terminal_operations[0].incoming_kind = DesiredHeadKind::EmptyDeactivate;
        assert_resealed_rejected(7, &incoming_kind, "incoming-kind");

        let mut predecessor_phase = active.clone();
        predecessor_phase.terminal_operations[0].completion_predecessor_phase =
            PreparedPhase::HeadCommittedRetiringOld;
        assert_resealed_rejected(7, &predecessor_phase, "completion-predecessor-phase");

        let mut lifecycle = active.clone();
        lifecycle.terminal_operations[0].selection.lifecycle_effect =
            TerminalLifecycleEffect::ProvenNotStarted;
        assert_resealed_rejected(7, &lifecycle, "lifecycle-effect");

        let mut head = active.clone();
        head.terminal_operations[0].head_disposition = TerminalHeadDisposition::Preserved(None);
        assert_resealed_rejected(7, &head, "head-disposition");

        let mut temporal_deadline = active.clone();
        temporal_deadline.terminal_operations[0].installed_deadline_nanos += 1;
        assert_resealed_rejected(7, &temporal_deadline, "terminal-deadline");

        let mut future_clock = active.clone();
        future_clock.terminal_operations[0].installed_clock_generation =
            future_clock.host.clock_generation_high_water + 1;
        assert_resealed_rejected(7, &future_clock, "future-installed-clock");

        let mut early_completion_host = active.clone();
        early_completion_host.terminal_operations[0].completion_runtime_host_epoch = 2;
        assert_resealed_rejected(7, &early_completion_host, "early-completion-host");

        let startup = startup_successor_state(&active);
        let cleanup = cleanup_old_live_resources_state(&startup);
        let tombstoned = tombstone_old_live_resources_state(&cleanup);
        let plan = recovery_plan_state(&tombstoned);
        let mut recovery_owner_forgery = recovery_intent_state(&plan);
        recovery_owner_forgery
            .recovery_action
            .as_mut()
            .expect("fixture recovery action must exist")
            .raw_outcome = Some(interrupted_raw(None));
        assert_resealed_rejected(
            12,
            &recovery_owner_forgery,
            "recovery-owner-event-without-startup-phase",
        );
        let crash = startup_successor_state(&plan);
        let aborted = recovery_abort_no_effects_state(&crash, 13);

        let mut phase_raw = aborted.clone();
        let terminal_raw = phase_raw.recovery_terminals[0].selection.raw;
        phase_raw.recovery_terminals[0].recovery.raw_outcome = Some(terminal_raw);
        assert_resealed_rejected(13, &phase_raw, "recovery-phase-raw");

        let mut recovery_phase = aborted.clone();
        recovery_phase.recovery_terminals[0].recovery.phase = RecoveryPhase::StartCallIntent;
        assert_resealed_rejected(13, &recovery_phase, "recovery-phase");

        let mut time_travel_selection = aborted;
        time_travel_selection.recovery_terminals[0]
            .selection
            .selection_clock_generation = time_travel_selection.recovery_terminals[0]
            .recovery
            .action
            .clock_generation
            - 1;
        assert_resealed_rejected(13, &time_travel_selection, "selection-clock-rollback");

        let successful_recovery = successful_recovery_state();
        let mut deleted_success_producer = successful_recovery.clone();
        deleted_success_producer.recovery_terminals.clear();
        assert_resealed_rejected(16, &deleted_success_producer, "deleted-success-producer");

        let mut rewritten_success_census = successful_recovery.clone();
        rewritten_success_census.recovery_terminals[0].resource_census_digest = digest(0xf1);
        assert_resealed_rejected(16, &rewritten_success_census, "success-census");

        let mut duplicate_completion = successful_recovery;
        duplicate_completion.recovery_terminals[0].completion_snapshot_sequence =
            duplicate_completion.terminal_operations[0].completion_snapshot_sequence;
        assert_resealed_rejected(
            16,
            &duplicate_completion,
            "cross-vector-completion-sequence",
        );

        let intent = recovery_intent_state(&plan);
        let failure = recovery_timeout_failure_state(&intent, 13);
        let mut selection_time = failure.clone();
        selection_time.recovery_terminals[0]
            .selection
            .selection_observed_at_nanos += 1;
        assert_resealed_rejected(13, &selection_time, "failure-selection-time");

        let mut failure_census = failure;
        failure_census.recovery_terminals[0].resource_census_digest = digest(0xf2);
        assert_resealed_rejected(13, &failure_census, "failure-census");

        let first_empty_admission = admitted_empty_state(&active);
        let draining = empty_head_retire_state(&first_empty_admission);
        let observed = observed_empty_success_state(&draining);
        let exact_zero =
            exact_zero_terminal_state(&observed, TerminalOutcome::EmptyDeactivateExactZero, 11);
        let mut exact_zero_census = exact_zero;
        exact_zero_census
            .terminal_operations
            .last_mut()
            .expect("fixture exact-zero terminal must exist")
            .resource_census_digest = digest(0xf3);
        assert_resealed_rejected(11, &exact_zero_census, "exact-zero-census");

        let admitted_stop = admitted_empty_state(&active);
        let prepared_stop = admitted_stop
            .prepared
            .as_ref()
            .expect("fixture stop must be prepared");
        let mut stopped_before_effects = admitted_stop.clone();
        stopped_before_effects.last_transaction =
            RuntimeJournalTransaction::OperationTerminalNoEffects;
        let census = compute_resource_census_digest(&stopped_before_effects.owned_resources)
            .expect("fixture census must build");
        stopped_before_effects
            .terminal_operations
            .push(terminal_record_for_prepared(
                prepared_stop,
                TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects,
                0xf4,
                census,
                8,
                active
                    .active_desired
                    .as_ref()
                    .map(|head| opaque_target_slice(&head.slice)),
            ));
        stopped_before_effects.prepared = None;
        snapshot(8, stopped_before_effects.clone());
        stopped_before_effects
            .terminal_operations
            .last_mut()
            .expect("fixture stop terminal must exist")
            .completion_runtime_host_epoch = 2;
        assert_resealed_rejected(
            8,
            &stopped_before_effects,
            "global-completion-host-rollback",
        );
    }

    #[test]
    fn successor_validation_preserves_pins_high_waters_resources_and_phases() {
        let previous_state = active_state();
        let previous = snapshot(7, previous_state.clone());
        let current_state = startup_successor_state(&previous_state);
        let current = snapshot(8, current_state.clone());
        assert_eq!(current.validate_successor_of(&previous), Ok(()));

        let mut changed_pin_state = current_state.clone();
        changed_pin_state.host.build_descriptor = pinned(b"descriptor-v2", 0xb1);
        let changed_pin = snapshot(8, changed_pin_state);
        assert_eq!(
            changed_pin.validate_successor_of(&previous),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let mut deleted_active_state = current_state.clone();
        deleted_active_state.active_desired = None;
        deleted_active_state.live_materialization = LiveMaterialization::Quarantined {
            active_slice_digest: None,
            reason_digest: digest(0xfa),
            resource_census_digest: compute_resource_census_digest(
                &deleted_active_state.owned_resources,
            )
            .expect("fixture census must build"),
        };
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 8, deleted_active_state,),
            Err(RuntimeJournalError::DanglingReference)
        );

        let mut deleted_resource_state = current_state.clone();
        deleted_resource_state.owned_resources.pop();
        let census = compute_resource_census_digest(&deleted_resource_state.owned_resources)
            .expect("fixture census must build");
        let LiveMaterialization::StartupInvalidated {
            resource_census_digest,
            ..
        } = &mut deleted_resource_state.live_materialization
        else {
            unreachable!();
        };
        *resource_census_digest = census;
        let deleted_resource = snapshot(8, deleted_resource_state);
        assert_eq!(
            deleted_resource.validate_successor_of(&previous),
            Err(RuntimeJournalError::NonMonotonicTransition)
        );

        let mut direct_ready_state = previous_state.clone();
        direct_ready_state.last_transaction = RuntimeJournalTransaction::StartupInvalidation;
        direct_ready_state.host.runtime_host_epoch_high_water = 4;
        direct_ready_state.host.clock_generation_high_water = 6;
        for resource in &mut direct_ready_state.owned_resources {
            resource.runtime_host_epoch = 4;
        }
        let census = compute_resource_census_digest(&direct_ready_state.owned_resources)
            .expect("fixture census must build");
        let active_digest = direct_ready_state
            .active_desired
            .as_ref()
            .expect("fixture active must exist")
            .slice
            .digest;
        direct_ready_state.live_materialization = LiveMaterialization::LiveReady {
            active_slice_digest: TargetSliceDigest::new(active_digest),
            runtime_host_epoch: 4,
            resource_generation: 9,
            resource_census_digest: census,
        };
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 8, direct_ready_state),
            Err(RuntimeJournalError::DanglingReference)
        );

        let mut mismatched_result = active_state();
        mismatched_result
            .active_desired
            .as_mut()
            .expect("fixture active must exist")
            .operation_id = [0x99; 16];
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0x11; 32], digest(0x22), 7, mismatched_result,),
            Err(RuntimeJournalError::DanglingReference)
        );
    }

    #[test]
    fn all_terminal_outcomes_have_real_successor_chains() {
        let mut covered = Vec::new();

        let idle = initialized_idle_state();
        let tenure = tenure_successor_state(&idle);
        let admitted = admitted_one_source_state(&tenure);
        let intent = one_source_intent_state(&admitted);
        let staged = staged_one_source_resources_state(&intent);
        let owned = owned_one_source_resources_state(&staged);
        let observed =
            observed_operation_outcome_state(&owned, TerminalOutcome::OneSourceLoopActive);
        let terminal = normal_start_terminal_outcome_state(
            &observed,
            TerminalOutcome::OneSourceLoopActive,
            14,
        );
        let final_snapshot = validated_successor_chain(
            "OneSourceLoopActive",
            7,
            vec![
                idle, tenure, admitted, intent, staged, owned, observed, terminal,
            ],
        );
        assert_terminal_outcome(&final_snapshot, TerminalOutcome::OneSourceLoopActive);
        covered.push(TerminalOutcome::OneSourceLoopActive);

        for outcome in [
            TerminalOutcome::StartFailedBeforeHeadCommitExactZero,
            TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero,
            TerminalOutcome::AbortedBeforeHeadCommitExactZero,
            TerminalOutcome::SupersededAfterIntentExactZero,
        ] {
            let idle = initialized_idle_state();
            let tenure = tenure_successor_state(&idle);
            let admitted = admitted_one_source_state(&tenure);
            let intent = one_source_intent_state(&admitted);
            let owner_observation = match outcome {
                TerminalOutcome::AbortedBeforeHeadCommitExactZero => {
                    startup_successor_state(&intent)
                }
                TerminalOutcome::SupersededAfterIntentExactZero => {
                    superseding_tenure_state(&intent)
                }
                _ => observed_operation_outcome_state(&intent, outcome),
            };
            let terminal = normal_start_terminal_outcome_state(&owner_observation, outcome, 12);
            let final_snapshot = validated_successor_chain(
                "one-source failure terminal",
                7,
                vec![idle, tenure, admitted, intent, owner_observation, terminal],
            );
            assert_terminal_outcome(&final_snapshot, outcome);
            covered.push(outcome);
        }

        for outcome in [
            TerminalOutcome::EmptyDeactivateExactZero,
            TerminalOutcome::StopFailedButExactZero,
            TerminalOutcome::TimedOutButExactZero,
            TerminalOutcome::SupersededAfterIntentExactZero,
            TerminalOutcome::InterruptedButNowExactZero,
        ] {
            let active = active_state();
            let admitted = admitted_empty_state(&active);
            let retiring = empty_head_retire_state(&admitted);
            let owner_observation = match outcome {
                TerminalOutcome::InterruptedButNowExactZero => startup_successor_state(&retiring),
                TerminalOutcome::SupersededAfterIntentExactZero => {
                    superseding_tenure_state(&retiring)
                }
                _ => observed_operation_outcome_state(&retiring, outcome),
            };
            let terminal = exact_zero_terminal_state(&owner_observation, outcome, 11);
            let final_snapshot = validated_successor_chain(
                "empty-deactivate exact-zero terminal",
                7,
                vec![active, admitted, retiring, owner_observation, terminal],
            );
            assert_terminal_outcome(&final_snapshot, outcome);
            covered.push(outcome);
        }

        let idle = initialized_idle_state();
        let tenure = tenure_successor_state(&idle);
        let admitted = admitted_one_source_state(&tenure);
        let terminal = no_effect_terminal_outcome_state(
            &admitted,
            TerminalOutcome::StartTimedOutBeforeIntentNoEffects,
            10,
        );
        let final_snapshot = validated_successor_chain(
            "start timeout before intent",
            7,
            vec![idle, tenure, admitted, terminal],
        );
        assert_terminal_outcome(
            &final_snapshot,
            TerminalOutcome::StartTimedOutBeforeIntentNoEffects,
        );
        covered.push(TerminalOutcome::StartTimedOutBeforeIntentNoEffects);

        let active = active_state();
        let admitted = admitted_empty_state(&active);
        let terminal = no_effect_terminal_outcome_state(
            &admitted,
            TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects,
            9,
        );
        let final_snapshot = validated_successor_chain(
            "stop timeout before head commit",
            7,
            vec![active, admitted, terminal],
        );
        assert_terminal_outcome(
            &final_snapshot,
            TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects,
        );
        covered.push(TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects);

        let idle = initialized_idle_state();
        let tenure = tenure_successor_state(&idle);
        let admitted = admitted_one_source_state(&tenure);
        let interrupted_startup = startup_successor_state(&admitted);
        let terminal = no_effect_terminal_outcome_state(
            &interrupted_startup,
            TerminalOutcome::AbortedBeforeIntentNoEffects,
            11,
        );
        let final_snapshot = validated_successor_chain(
            "startup-interrupted before intent",
            7,
            vec![idle, tenure, admitted, interrupted_startup, terminal],
        );
        assert_terminal_outcome(
            &final_snapshot,
            TerminalOutcome::AbortedBeforeIntentNoEffects,
        );
        covered.push(TerminalOutcome::AbortedBeforeIntentNoEffects);

        let idle = initialized_idle_state();
        let tenure = tenure_successor_state(&idle);
        let admitted = admitted_one_source_state(&tenure);
        let superseded = superseding_tenure_state(&admitted);
        let terminal = no_effect_terminal_outcome_state(
            &superseded,
            TerminalOutcome::AbortedBeforeIntentNoEffects,
            11,
        );
        let final_snapshot = validated_successor_chain(
            "higher-tenure superseded before effects",
            7,
            vec![idle, tenure, admitted, superseded, terminal],
        );
        assert_terminal_outcome(
            &final_snapshot,
            TerminalOutcome::AbortedBeforeIntentNoEffects,
        );
        covered.push(TerminalOutcome::AbortedBeforeIntentNoEffects);

        assert_eq!(covered.len(), 14);
        for expected in [
            TerminalOutcome::OneSourceLoopActive,
            TerminalOutcome::EmptyDeactivateExactZero,
            TerminalOutcome::StartTimedOutBeforeIntentNoEffects,
            TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects,
            TerminalOutcome::StartFailedBeforeHeadCommitExactZero,
            TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero,
            TerminalOutcome::StopFailedButExactZero,
            TerminalOutcome::TimedOutButExactZero,
            TerminalOutcome::AbortedBeforeIntentNoEffects,
            TerminalOutcome::AbortedBeforeHeadCommitExactZero,
            TerminalOutcome::SupersededAfterIntentExactZero,
            TerminalOutcome::InterruptedButNowExactZero,
        ] {
            assert!(covered.contains(&expected), "missing {expected:?} chain");
        }
        assert_eq!(
            covered
                .iter()
                .filter(|outcome| { **outcome == TerminalOutcome::AbortedBeforeIntentNoEffects })
                .count(),
            2
        );
        assert_eq!(
            covered
                .iter()
                .filter(|outcome| { **outcome == TerminalOutcome::SupersededAfterIntentExactZero })
                .count(),
            2
        );
    }

    #[test]
    fn every_typed_successor_transaction_has_a_legal_reference_path() {
        let idle = initialized_idle_state();
        let tenure = tenure_successor_state(&idle);
        assert_eq!(
            snapshot(8, tenure.clone()).validate_successor_of(&snapshot(7, idle)),
            Ok(())
        );

        let admitted = admitted_one_source_state(&tenure);
        assert_eq!(
            snapshot(9, admitted.clone()).validate_successor_of(&snapshot(8, tenure.clone())),
            Ok(())
        );
        let intent = one_source_intent_state(&admitted);
        assert_eq!(
            snapshot(10, intent.clone()).validate_successor_of(&snapshot(9, admitted.clone())),
            Ok(())
        );
        let staged = staged_one_source_resources_state(&intent);
        assert_eq!(
            snapshot(11, staged.clone()).validate_successor_of(&snapshot(10, intent)),
            Ok(())
        );
        let owned = owned_one_source_resources_state(&staged);
        assert_eq!(
            snapshot(12, owned.clone()).validate_successor_of(&snapshot(11, staged)),
            Ok(())
        );
        let active = normal_start_terminal_state(&owned);
        assert_eq!(
            snapshot(13, active).validate_successor_of(&snapshot(12, owned)),
            Ok(())
        );

        let no_effect_terminal = no_effect_terminal_state(&admitted);
        assert_eq!(
            snapshot(10, no_effect_terminal).validate_successor_of(&snapshot(9, admitted)),
            Ok(())
        );

        let old_active = active_state();
        let admitted_empty = admitted_empty_state(&old_active);
        assert_eq!(
            snapshot(8, admitted_empty.clone())
                .validate_successor_of(&snapshot(7, old_active.clone())),
            Ok(())
        );
        let draining = empty_head_retire_state(&admitted_empty);
        assert_eq!(
            snapshot(9, draining.clone()).validate_successor_of(&snapshot(8, admitted_empty)),
            Ok(())
        );
        let observed = observed_empty_success_state(&draining);
        assert_eq!(
            snapshot(10, observed.clone()).validate_successor_of(&snapshot(9, draining)),
            Ok(())
        );
        let exact_zero =
            exact_zero_terminal_state(&observed, TerminalOutcome::EmptyDeactivateExactZero, 11);
        assert_eq!(
            snapshot(11, exact_zero).validate_successor_of(&snapshot(10, observed)),
            Ok(())
        );

        let startup = startup_successor_state(&old_active);
        assert_eq!(
            snapshot(8, startup.clone()).validate_successor_of(&snapshot(7, old_active)),
            Ok(())
        );
        let cleanup = cleanup_old_live_resources_state(&startup);
        assert_eq!(
            snapshot(9, cleanup.clone()).validate_successor_of(&snapshot(8, startup)),
            Ok(())
        );
        let tombstoned = tombstone_old_live_resources_state(&cleanup);
        assert_eq!(
            snapshot(10, tombstoned.clone()).validate_successor_of(&snapshot(9, cleanup)),
            Ok(())
        );
        let recovery_plan = recovery_plan_state(&tombstoned);
        assert_eq!(
            snapshot(11, recovery_plan.clone())
                .validate_successor_of(&snapshot(10, tombstoned.clone())),
            Ok(())
        );
        let recovery_intent = recovery_intent_state(&recovery_plan);
        assert_eq!(
            snapshot(12, recovery_intent.clone())
                .validate_successor_of(&snapshot(11, recovery_plan)),
            Ok(())
        );
        let recovery_staged = staged_recovery_resources_state(&recovery_intent);
        assert_eq!(
            snapshot(13, recovery_staged.clone())
                .validate_successor_of(&snapshot(12, recovery_intent.clone())),
            Ok(())
        );
        let recovery_owned = owned_recovery_resources_state(&recovery_staged);
        assert_eq!(
            snapshot(14, recovery_owned.clone())
                .validate_successor_of(&snapshot(13, recovery_staged)),
            Ok(())
        );
        let recovery_success = recovery_known_success_state(&recovery_owned);
        assert_eq!(
            snapshot(15, recovery_success.clone())
                .validate_successor_of(&snapshot(14, recovery_owned)),
            Ok(())
        );
        let recovered = recovery_live_ready_state(&recovery_success);
        assert_eq!(
            snapshot(16, recovered).validate_successor_of(&snapshot(15, recovery_success)),
            Ok(())
        );

        let mut quarantined = recovery_intent.clone();
        quarantined.last_transaction = RuntimeJournalTransaction::Quarantine;
        quarantined.live_materialization = LiveMaterialization::Quarantined {
            active_slice_digest: quarantined
                .active_desired
                .as_ref()
                .map(|active| opaque_target_slice(&active.slice)),
            reason_digest: digest(0xdf),
            resource_census_digest: compute_resource_census_digest(&quarantined.owned_resources)
                .expect("fixture census must build"),
        };
        assert_eq!(
            snapshot(13, quarantined).validate_successor_of(&snapshot(12, recovery_intent)),
            Ok(())
        );
    }

    #[test]
    fn raw_outcome_facts_only_advance_from_unobserved_dimensions() {
        let base = RawActionOutcomeLatch {
            callback: CallbackOutcome::NotInvoked,
            callback_reason_digest: None,
            deadline: DeadlineOutcome::NotObserved,
            observed_clock_generation: 0,
            observed_at_nanos: 0,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        };
        let mut supplemented = base;
        supplemented.deadline = DeadlineOutcome::TimedOut;
        supplemented.observed_clock_generation = 5;
        supplemented.observed_at_nanos = 100;
        supplemented.host_interrupted = true;
        supplemented.cleanup = CleanupOutcome::ExactZero;
        supplemented.cleanup_evidence_digest = Some(digest(0xc1));
        assert!(supplemented.preserves(base));

        let mut callback_rewrite = supplemented;
        callback_rewrite.callback = CallbackOutcome::UnknownAfterIntent;
        assert!(!callback_rewrite.preserves(supplemented));

        let mut deadline_rewrite = supplemented;
        deadline_rewrite.observed_at_nanos = 101;
        assert!(!deadline_rewrite.preserves(supplemented));

        let mut fact_deletion = supplemented;
        fact_deletion.cleanup = CleanupOutcome::NotObserved;
        fact_deletion.cleanup_evidence_digest = None;
        assert!(!fact_deletion.preserves(supplemented));
    }

    #[test]
    fn terminal_selection_uses_fixed_owner_priority_and_preserves_lower_raw_facts() {
        let select = |raw, selection_observed_at_nanos| {
            TerminalOutcomeSelection::try_select(
                TerminalSelectionContext {
                    incoming_kind: DesiredHeadKind::OneSourceLoop,
                    predecessor_phase: PreparedPhase::FirstActionIntent,
                    installed_clock_generation: 5,
                    installed_deadline_nanos: 10_000,
                },
                TerminalSelectionObservation {
                    raw,
                    selection_clock_generation: 5,
                    selection_observed_at_nanos,
                    lifecycle_effect: TerminalLifecycleEffect::MayHaveStarted,
                },
            )
        };
        let known_error = RawActionOutcomeLatch {
            callback: CallbackOutcome::KnownError,
            callback_reason_digest: Some(digest(0xc2)),
            deadline: DeadlineOutcome::NotObserved,
            observed_clock_generation: 0,
            observed_at_nanos: 0,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::ExactZero,
            cleanup_evidence_digest: Some(digest(0xc3)),
        };

        let before_deadline = select(known_error, 9_999).expect("known error must select");
        assert_eq!(
            before_deadline.primary,
            TerminalOutcome::StartFailedBeforeHeadCommitExactZero
        );

        let cleanup_crossed_deadline =
            select(known_error, 10_000).expect("deadline equality must select timeout");
        assert_eq!(
            cleanup_crossed_deadline.primary,
            TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero
        );
        assert_eq!(
            cleanup_crossed_deadline.raw.callback,
            CallbackOutcome::KnownError
        );
        assert_eq!(
            cleanup_crossed_deadline.raw.callback_reason_digest,
            known_error.callback_reason_digest
        );

        let mut interrupted = known_error;
        interrupted.deadline = DeadlineOutcome::TimedOut;
        interrupted.observed_clock_generation = 5;
        interrupted.observed_at_nanos = 10_000;
        interrupted.host_interrupted = true;
        let interrupted_selection =
            select(interrupted, 10_000).expect("host interruption must dominate timeout");
        assert_eq!(
            interrupted_selection.primary,
            TerminalOutcome::AbortedBeforeHeadCommitExactZero
        );
        assert_eq!(interrupted_selection.raw, interrupted);

        let mut superseded = interrupted;
        superseded.higher_tenure_takeover = true;
        let superseded_selection =
            select(superseded, 10_000).expect("takeover must dominate interruption");
        assert_eq!(
            superseded_selection.primary,
            TerminalOutcome::SupersededAfterIntentExactZero
        );
        assert_eq!(superseded_selection.raw, superseded);

        let mut panicked = known_error;
        panicked.callback = CallbackOutcome::Panicked;
        assert_eq!(
            select(panicked, 9_999),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut uncertain = known_error;
        uncertain.cleanup = CleanupOutcome::Uncertain;
        assert_eq!(
            select(uncertain, 9_999),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );
    }

    #[test]
    fn progress_transactions_cannot_mint_owner_event_facts() {
        let idle = initialized_idle_state();
        let tenure = tenure_successor_state(&idle);
        let admitted = admitted_one_source_state(&tenure);
        let intent = one_source_intent_state(&admitted);
        let observed = observed_operation_outcome_state(
            &intent,
            TerminalOutcome::StartFailedBeforeHeadCommitExactZero,
        );
        let intent_snapshot = snapshot(10, intent);
        let observed_snapshot = snapshot(11, observed.clone());
        assert_eq!(
            observed_snapshot.validate_successor_of(&intent_snapshot),
            Ok(())
        );

        for host_interrupted in [true, false] {
            let mut forged = observed.clone();
            forged.last_transaction = RuntimeJournalTransaction::PreparedProgress;
            if host_interrupted {
                forged.host.runtime_host_epoch_high_water += 1;
                forged.host.clock_generation_high_water += 1;
            }
            let prepared = forged
                .prepared
                .as_mut()
                .expect("fixture prepared operation must exist");
            prepared.phase = if host_interrupted {
                PreparedPhase::StartupReconcileRequired
            } else {
                PreparedPhase::SupersededReconcileRequired
            };
            let raw = prepared
                .raw_outcome
                .as_mut()
                .expect("fixture prepared raw outcome must exist");
            if host_interrupted {
                raw.host_interrupted = true;
            } else {
                raw.higher_tenure_takeover = true;
            }
            assert_eq!(
                snapshot(12, forged).validate_successor_of(&observed_snapshot),
                Err(RuntimeJournalError::NonMonotonicTransition)
            );
        }

        let active = active_state();
        let startup = startup_successor_state(&active);
        let cleanup = cleanup_old_live_resources_state(&startup);
        let tombstoned = tombstone_old_live_resources_state(&cleanup);
        let recovery_plan = recovery_plan_state(&tombstoned);
        let recovery_intent = recovery_intent_state(&recovery_plan);
        let recovery_observed = recovery_known_success_state(&recovery_intent);
        let recovery_intent_snapshot = snapshot(12, recovery_intent);
        let recovery_observed_snapshot = snapshot(13, recovery_observed.clone());
        assert_eq!(
            recovery_observed_snapshot.validate_successor_of(&recovery_intent_snapshot),
            Ok(())
        );

        for host_interrupted in [true, false] {
            let mut forged = recovery_observed.clone();
            forged.last_transaction = RuntimeJournalTransaction::RecoveryProgress;
            if host_interrupted {
                forged.host.runtime_host_epoch_high_water += 1;
                forged.host.clock_generation_high_water += 1;
            }
            let recovery = forged
                .recovery_action
                .as_mut()
                .expect("fixture recovery action must exist");
            if host_interrupted {
                recovery.phase = RecoveryPhase::StartupReconcileRequired;
            }
            let raw = recovery
                .raw_outcome
                .as_mut()
                .expect("fixture recovery raw outcome must exist");
            if host_interrupted {
                raw.host_interrupted = true;
            } else {
                raw.higher_tenure_takeover = true;
            }
            assert_eq!(
                snapshot(14, forged).validate_successor_of(&recovery_observed_snapshot),
                Err(RuntimeJournalError::NonMonotonicTransition)
            );
        }
    }

    #[test]
    fn cancelled_observation_requires_a_preexisting_owner_event() {
        let unproven_cancellation = RawActionOutcomeLatch {
            callback: CallbackOutcome::UnknownAfterIntent,
            callback_reason_digest: None,
            deadline: DeadlineOutcome::Cancelled,
            observed_clock_generation: 5,
            observed_at_nanos: 9_000,
            host_interrupted: false,
            higher_tenure_takeover: false,
            cleanup: CleanupOutcome::NotObserved,
            cleanup_evidence_digest: None,
        };
        assert_eq!(
            unproven_cancellation.validate(),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let idle = initialized_idle_state();
        let tenure = tenure_successor_state(&idle);
        let admitted = admitted_one_source_state(&tenure);
        let intent = one_source_intent_state(&admitted);
        let superseded = superseding_tenure_state(&intent);
        let superseded_snapshot = snapshot(11, superseded.clone());
        assert_eq!(
            superseded_snapshot.validate_successor_of(&snapshot(10, intent)),
            Ok(())
        );

        let mut cancelled = superseded;
        cancelled.last_transaction = RuntimeJournalTransaction::PreparedProgress;
        let prepared = cancelled
            .prepared
            .as_mut()
            .expect("fixture superseded prepared operation must exist");
        let installed_clock_generation = prepared.installed_clock_generation;
        let raw = prepared
            .raw_outcome
            .as_mut()
            .expect("fixture takeover raw outcome must exist");
        raw.deadline = DeadlineOutcome::Cancelled;
        raw.observed_clock_generation = installed_clock_generation;
        raw.observed_at_nanos = 9_000;
        assert_eq!(
            snapshot(12, cancelled).validate_successor_of(&superseded_snapshot),
            Ok(())
        );
    }

    #[test]
    fn envelope_identity_and_sequence_are_mandatory() {
        assert_eq!(
            RuntimeJournalSnapshot::try_new([0; 32], digest(1), 1, sequence_one_state()),
            Err(RuntimeJournalError::ZeroStoreInstanceId)
        );
        assert_eq!(
            RuntimeJournalSnapshot::try_new(
                [1; 32],
                Digest32::from_bytes([0; 32]),
                1,
                sequence_one_state(),
            ),
            Err(RuntimeJournalError::ZeroDigest)
        );
        assert_eq!(
            RuntimeJournalSnapshot::try_new([1; 32], digest(1), 0, sequence_one_state()),
            Err(RuntimeJournalError::InvalidSequence)
        );

        let mut initialized_with_used_generation = sequence_one_state();
        initialized_with_used_generation
            .host
            .runtime_host_epoch_high_water = 1;
        initialized_with_used_generation
            .host
            .clock_generation_high_water = 1;
        assert_eq!(
            RuntimeJournalSnapshot::try_new(
                [1; 32],
                digest(1),
                1,
                initialized_with_used_generation,
            ),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let mut later_without_startup = sequence_one_state();
        later_without_startup.last_transaction = RuntimeJournalTransaction::StartupInvalidation;
        assert_eq!(
            RuntimeJournalSnapshot::try_new([1; 32], digest(1), 2, later_without_startup),
            Err(RuntimeJournalError::InvalidStateInvariant)
        );

        let previous = snapshot(u64::MAX, active_state());
        let current = snapshot(1, sequence_one_state());
        assert_eq!(
            current.validate_successor_of(&previous),
            Err(RuntimeJournalError::SequenceOverflow)
        );
    }
}
