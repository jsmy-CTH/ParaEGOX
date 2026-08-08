#![cfg(unix)]

//! Durable PXAR-v8 state retained by the existing Runtime successor owner.
//!
//! The codec has its own wire magic, but it is not a second filesystem owner:
//! `ManagedFabricStore` publishes these bytes while retaining the original
//! Runtime writer lock. Nested PXAR-v8 requests and PXDS terminals are decoded
//! strictly on every restart.

use core::fmt;

use paraegox_evidence::{
    EvidenceCommitReceiptV1, EvidenceKindV1, EvidenceOwnerRefV1, EvidenceRecordIdV1,
    EvidenceRecordV1, EvidenceStoreEpochV1, EvidenceStoredRecordV1, MAX_EVIDENCE_RECORD_BYTES,
};
use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::ClockGeneration;
use paraegox_runtime_contracts::apply::{ApplyOperationId, PlanWriterRef};
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DISTRIBUTED_FABRIC_TRANSPORT_PROOF_BYTES, DistributedAgentStackApplyRequestV1,
    DistributedAgentStackLocalBindingEvidenceFieldsV1, DistributedAgentStackProjectionV1,
    DistributedAgentStackTargetModeV1, DistributedAgentStackTerminalEvidenceFieldsV1,
    DistributedAgentStackTerminalFactsV1, DistributedAgentStackTerminalOutcomeV1,
    DistributedAgentStackTerminalReceiptV1, DistributedFabricObservedTransportProofV1,
    DistributedFabricSessionEpochV1, MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES,
    MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_BYTES,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
use paraegox_runtime_contracts::provenance::{SourcePlanDigest, SourceScopeRef};
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
use sha2::{Digest as ShaDigest, Sha256};

const SNAPSHOT_MAGIC: &[u8; 4] = b"PXDA";
const SNAPSHOT_VERSION_V1: u16 = 1;
const SNAPSHOT_VERSION_V2: u16 = 2;
const SNAPSHOT_HEADER_BYTES: usize = 192;
const SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES: usize = 160;
const SNAPSHOT_CHECKSUM_DOMAIN_V1: &[u8] =
    b"paraegox.runtime.distributed-agent-stack-snapshot.sha256.v1";
const SNAPSHOT_CHECKSUM_DOMAIN_V2: &[u8] =
    b"paraegox.runtime.distributed-agent-stack-snapshot.sha256.v2";
const MAX_TERMINALS: usize = 256;
const MAX_REPLAY_ENTRIES: usize = 256;
const MAX_EVIDENCE_BATCH_RECORDS: usize = 8;
pub(crate) const MAX_DISTRIBUTED_AGENT_STACK_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum DistributedAgentStackSnapshotWireVersion {
    V1 = SNAPSHOT_VERSION_V1,
    V2 = SNAPSHOT_VERSION_V2,
}

impl DistributedAgentStackSnapshotWireVersion {
    fn decode(value: u16) -> Result<Self, DistributedAgentStackStateError> {
        match value {
            SNAPSHOT_VERSION_V1 => Ok(Self::V1),
            SNAPSHOT_VERSION_V2 => Ok(Self::V2),
            _ => Err(DistributedAgentStackStateError::UnsupportedFrame),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum DistributedAgentStackDurablePhase {
    ExactZero = 1,
    PreparedNoEffects = 2,
    StartIntent = 3,
    AgentStartIntent = 4,
    ActiveReady = 5,
    AgentRetireIntent = 6,
    FabricStopIntent = 7,
    RecoveryIntent = 8,
    Uncertain = 9,
    Quarantined = 10,
    EvidenceCommitIntent = 11,
}

impl DistributedAgentStackDurablePhase {
    fn decode(
        value: u8,
        wire_version: DistributedAgentStackSnapshotWireVersion,
    ) -> Result<Self, DistributedAgentStackStateError> {
        let phase = match value {
            1 => Ok(Self::ExactZero),
            2 => Ok(Self::PreparedNoEffects),
            3 => Ok(Self::StartIntent),
            4 => Ok(Self::AgentStartIntent),
            5 => Ok(Self::ActiveReady),
            6 => Ok(Self::AgentRetireIntent),
            7 => Ok(Self::FabricStopIntent),
            8 => Ok(Self::RecoveryIntent),
            9 => Ok(Self::Uncertain),
            10 => Ok(Self::Quarantined),
            11 => Ok(Self::EvidenceCommitIntent),
            _ => Err(DistributedAgentStackStateError::UnknownEnumValue),
        }?;
        if wire_version == DistributedAgentStackSnapshotWireVersion::V1
            && phase == Self::EvidenceCommitIntent
        {
            return Err(DistributedAgentStackStateError::UnknownEnumValue);
        }
        Ok(phase)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum DistributedAgentStackPendingKind {
    ActivateDistributedStack = 1,
    DeactivateStack = 2,
    RecoverActive = 3,
}

impl DistributedAgentStackPendingKind {
    fn decode(value: u8) -> Result<Self, DistributedAgentStackStateError> {
        match value {
            1 => Ok(Self::ActivateDistributedStack),
            2 => Ok(Self::DeactivateStack),
            3 => Ok(Self::RecoverActive),
            _ => Err(DistributedAgentStackStateError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackWriterFence {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) writer: PlanWriterRef,
    pub(crate) principal: PrincipalRef,
    pub(crate) epoch: u64,
    pub(crate) proof_envelope_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackRevisionHighWater {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) revision: u64,
    pub(crate) source_plan_digest: SourcePlanDigest,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DistributedAgentStackReplayRecord {
    pub(crate) identity: Digest32,
    pub(crate) value_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackDurableActive {
    pub(crate) fabric_generation: ManagedServiceGeneration,
    pub(crate) agent_generation: ManagedServiceGeneration,
    pub(crate) response_channel: ReferenceChannelBindingV1,
    pub(crate) request: DistributedAgentStackApplyRequestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackDurablePending {
    pub(crate) kind: DistributedAgentStackPendingKind,
    pub(crate) fabric_generation: Option<ManagedServiceGeneration>,
    pub(crate) agent_generation: Option<ManagedServiceGeneration>,
    pub(crate) admitted_clock_generation: ClockGeneration,
    pub(crate) admitted_at_nanos: u64,
    pub(crate) deadline_nanos: u64,
    pub(crate) response_channel: ReferenceChannelBindingV1,
    pub(crate) request: DistributedAgentStackApplyRequestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackTerminalRecord {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) operation_id: ApplyOperationId,
    pub(crate) request_digest: Digest32,
    pub(crate) receipt: DistributedAgentStackTerminalReceiptV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackEvidenceBindingV2 {
    store_epoch: EvidenceStoreEpochV1,
    owner_ref: EvidenceOwnerRefV1,
}

impl DistributedAgentStackEvidenceBindingV2 {
    pub(crate) const fn new(
        store_epoch: EvidenceStoreEpochV1,
        owner_ref: EvidenceOwnerRefV1,
    ) -> Self {
        Self {
            store_epoch,
            owner_ref,
        }
    }

    #[must_use]
    pub(crate) const fn store_epoch(self) -> EvidenceStoreEpochV1 {
        self.store_epoch
    }

    #[must_use]
    pub(crate) const fn owner_ref(self) -> EvidenceOwnerRefV1 {
        self.owner_ref
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackEvidenceOwnerHeadV2 {
    producer_sequence: u64,
    record_id: EvidenceRecordIdV1,
    record_digest: Digest32,
}

impl DistributedAgentStackEvidenceOwnerHeadV2 {
    pub(crate) fn try_new(
        producer_sequence: u64,
        record_id: EvidenceRecordIdV1,
        record_digest: Digest32,
    ) -> Result<Self, DistributedAgentStackStateError> {
        if producer_sequence == 0 || digest_is_zero(record_digest) {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        Ok(Self {
            producer_sequence,
            record_id,
            record_digest,
        })
    }

    #[must_use]
    pub(crate) const fn producer_sequence(self) -> u64 {
        self.producer_sequence
    }

    #[must_use]
    pub(crate) const fn record_id(self) -> EvidenceRecordIdV1 {
        self.record_id
    }

    #[must_use]
    pub(crate) const fn record_digest(self) -> Digest32 {
        self.record_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackEvidenceBatchV2 {
    request_digest: Digest32,
    fabric_generation: ManagedServiceGeneration,
    session_epoch: DistributedFabricSessionEpochV1,
    base_head: Option<DistributedAgentStackEvidenceOwnerHeadV2>,
    records: Box<[EvidenceRecordV1]>,
}

impl DistributedAgentStackEvidenceBatchV2 {
    /// Admits only canonical RuntimeFact records whose inline payload is one
    /// exact PXTP v1 frame and whose opaque transport reference is the record
    /// id. Evidence-store head/readback and Fabric-origin authentication are
    /// deliberately left to the Runtime handoff owner.
    pub(crate) fn try_new(
        request_digest: Digest32,
        fabric_generation: ManagedServiceGeneration,
        session_epoch: DistributedFabricSessionEpochV1,
        base_head: Option<DistributedAgentStackEvidenceOwnerHeadV2>,
        records: Vec<EvidenceRecordV1>,
    ) -> Result<Self, DistributedAgentStackStateError> {
        if digest_is_zero(request_digest)
            || records.is_empty()
            || records.len() > MAX_EVIDENCE_BATCH_RECORDS
        {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        validate_evidence_record_chain(base_head, &records)?;
        validate_evidence_record_payloads(session_epoch, &records)?;
        Ok(Self {
            request_digest,
            fabric_generation,
            session_epoch,
            base_head,
            records: records.into_boxed_slice(),
        })
    }

    #[must_use]
    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub(crate) const fn fabric_generation(&self) -> ManagedServiceGeneration {
        self.fabric_generation
    }

    #[must_use]
    pub(crate) const fn session_epoch(&self) -> DistributedFabricSessionEpochV1 {
        self.session_epoch
    }

    #[must_use]
    pub(crate) const fn base_head(&self) -> Option<DistributedAgentStackEvidenceOwnerHeadV2> {
        self.base_head
    }

    #[must_use]
    pub(crate) fn records(&self) -> &[EvidenceRecordV1] {
        &self.records
    }

    fn tail_head(
        &self,
    ) -> Result<DistributedAgentStackEvidenceOwnerHeadV2, DistributedAgentStackStateError> {
        let record = self
            .records
            .last()
            .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
        Ok(DistributedAgentStackEvidenceOwnerHeadV2 {
            producer_sequence: record.producer_sequence(),
            record_id: record.record_id(),
            record_digest: record.record_digest(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DistributedAgentStackEvidenceHandoffV2 {
    None,
    CommitIntent(DistributedAgentStackEvidenceBatchV2),
    Committed(DistributedAgentStackVerifiedEvidenceCommitV2),
}

/// Exact Evidence-store acknowledgement and readback for one durable batch.
///
/// Runtime code cannot construct this marker from unsigned PXTP/PXEV bytes
/// alone. The durable decoder may restore a previously verified marker, while
/// a live transition must present every append receipt and its exact readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackVerifiedEvidenceCommitV2 {
    batch: DistributedAgentStackEvidenceBatchV2,
}

impl DistributedAgentStackVerifiedEvidenceCommitV2 {
    pub(crate) fn try_new(
        binding: DistributedAgentStackEvidenceBindingV2,
        batch: DistributedAgentStackEvidenceBatchV2,
        append_receipts: &[EvidenceCommitReceiptV1],
        readback: &[EvidenceStoredRecordV1],
    ) -> Result<Self, DistributedAgentStackStateError> {
        if append_receipts.len() != batch.records().len() || readback.len() != batch.records().len()
        {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        validate_evidence_record_chain(batch.base_head(), batch.records())?;
        validate_evidence_record_payloads(batch.session_epoch(), batch.records())?;
        for ((record, receipt), stored) in batch.records().iter().zip(append_receipts).zip(readback)
        {
            let evidence_ref = receipt.evidence_ref();
            if record.owner_ref() != binding.owner_ref()
                || evidence_ref.store_epoch() != binding.store_epoch()
                || evidence_ref.record_id() != record.record_id()
                || evidence_ref.record_digest() != record.record_digest()
                || stored.evidence_ref() != evidence_ref
                || stored.record() != record
                || stored.record().canonical_wire() != record.canonical_wire()
            {
                return Err(DistributedAgentStackStateError::InvalidEvidenceState);
            }
        }
        Ok(Self { batch })
    }

    /// Restores a marker whose enclosing canonical PXDA-v2 frame already
    /// durably recorded the verified transition. This constructor is private
    /// to the state codec and is unavailable to live Runtime callers.
    fn from_durable_decode(batch: DistributedAgentStackEvidenceBatchV2) -> Self {
        Self { batch }
    }

    #[must_use]
    pub(crate) const fn batch(&self) -> &DistributedAgentStackEvidenceBatchV2 {
        &self.batch
    }

    pub(crate) fn owner_head(
        &self,
    ) -> Result<DistributedAgentStackEvidenceOwnerHeadV2, DistributedAgentStackStateError> {
        self.batch.tail_head()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackEvidenceStateV2 {
    binding: Option<DistributedAgentStackEvidenceBindingV2>,
    owner_head: Option<DistributedAgentStackEvidenceOwnerHeadV2>,
    handoff: DistributedAgentStackEvidenceHandoffV2,
}

impl DistributedAgentStackEvidenceStateV2 {
    pub(crate) const fn empty() -> Self {
        Self {
            binding: None,
            owner_head: None,
            handoff: DistributedAgentStackEvidenceHandoffV2::None,
        }
    }

    pub(crate) fn try_new(
        binding: Option<DistributedAgentStackEvidenceBindingV2>,
        owner_head: Option<DistributedAgentStackEvidenceOwnerHeadV2>,
        handoff: DistributedAgentStackEvidenceHandoffV2,
    ) -> Result<Self, DistributedAgentStackStateError> {
        let state = Self {
            binding,
            owner_head,
            handoff,
        };
        validate_evidence_state(&state)?;
        Ok(state)
    }

    /// Converts the exact current commit intent only after the Evidence owner
    /// proves every append through its typed receipt and exact store readback.
    pub(crate) fn try_mark_committed(
        &self,
        append_receipts: &[EvidenceCommitReceiptV1],
        readback: &[EvidenceStoredRecordV1],
    ) -> Result<Self, DistributedAgentStackStateError> {
        let binding = self
            .binding
            .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
        let batch = match &self.handoff {
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch) => batch.clone(),
            DistributedAgentStackEvidenceHandoffV2::None
            | DistributedAgentStackEvidenceHandoffV2::Committed(_) => {
                return Err(DistributedAgentStackStateError::InvalidEvidenceState);
            }
        };
        let committed = DistributedAgentStackVerifiedEvidenceCommitV2::try_new(
            binding,
            batch,
            append_receipts,
            readback,
        )?;
        let owner_head = committed.owner_head()?;
        Self::try_new(
            Some(binding),
            Some(owner_head),
            DistributedAgentStackEvidenceHandoffV2::Committed(committed),
        )
    }

    /// Clears one verified handoff while retaining the immutable Evidence
    /// binding and owner head. A later intent is legal only from this state.
    pub(crate) fn try_clear_committed(&self) -> Result<Self, DistributedAgentStackStateError> {
        if !matches!(
            &self.handoff,
            DistributedAgentStackEvidenceHandoffV2::Committed(_)
        ) {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        Self::try_new(
            self.binding,
            self.owner_head,
            DistributedAgentStackEvidenceHandoffV2::None,
        )
    }

    #[must_use]
    pub(crate) const fn binding(&self) -> Option<DistributedAgentStackEvidenceBindingV2> {
        self.binding
    }

    #[must_use]
    pub(crate) const fn owner_head(&self) -> Option<DistributedAgentStackEvidenceOwnerHeadV2> {
        self.owner_head
    }

    #[must_use]
    pub(crate) const fn handoff(&self) -> &DistributedAgentStackEvidenceHandoffV2 {
        &self.handoff
    }

    fn is_empty(&self) -> bool {
        self.binding.is_none()
            && self.owner_head.is_none()
            && matches!(&self.handoff, DistributedAgentStackEvidenceHandoffV2::None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackSnapshotTransition {
    pub(crate) fabric_generation_high_water: u64,
    pub(crate) agent_generation_high_water: u64,
    pub(crate) phase: DistributedAgentStackDurablePhase,
    pub(crate) writer_fence: Option<DistributedAgentStackWriterFence>,
    pub(crate) revision_high_water: Option<DistributedAgentStackRevisionHighWater>,
    pub(crate) active: Option<DistributedAgentStackDurableActive>,
    pub(crate) pending: Option<DistributedAgentStackDurablePending>,
    pub(crate) tenure_nonces: Vec<DistributedAgentStackReplayRecord>,
    pub(crate) request_nonces: Vec<DistributedAgentStackReplayRecord>,
    pub(crate) temporal_lineages: Vec<DistributedAgentStackReplayRecord>,
    pub(crate) terminals: Vec<DistributedAgentStackTerminalRecord>,
    pub(crate) physical_binding_census: u16,
    pub(crate) census_complete: bool,
    pub(crate) fabric_ready: bool,
    pub(crate) agent_ready: bool,
    pub(crate) dependency_satisfied: bool,
    pub(crate) exact_zero: bool,
    pub(crate) quarantined: bool,
    pub(crate) installed_binding_set_digest: Option<Digest32>,
    pub(crate) raw_outcome_digest: Option<Digest32>,
    pub(crate) quarantine_reason: Option<Digest32>,
}

#[derive(Clone, Copy)]
struct SnapshotIdentity {
    store_instance_id: [u8; 32],
    owner_target_fingerprint: Digest32,
    transition_projection_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackSnapshot {
    wire_version: DistributedAgentStackSnapshotWireVersion,
    store_instance_id: [u8; 32],
    owner_target_fingerprint: Digest32,
    transition_projection_digest: Digest32,
    sequence: u64,
    runtime_host_epoch: u64,
    pub(crate) fabric_generation_high_water: u64,
    pub(crate) agent_generation_high_water: u64,
    pub(crate) phase: DistributedAgentStackDurablePhase,
    pub(crate) writer_fence: Option<DistributedAgentStackWriterFence>,
    pub(crate) revision_high_water: Option<DistributedAgentStackRevisionHighWater>,
    pub(crate) active: Option<DistributedAgentStackDurableActive>,
    pub(crate) pending: Option<DistributedAgentStackDurablePending>,
    pub(crate) tenure_nonces: Vec<DistributedAgentStackReplayRecord>,
    pub(crate) request_nonces: Vec<DistributedAgentStackReplayRecord>,
    pub(crate) temporal_lineages: Vec<DistributedAgentStackReplayRecord>,
    pub(crate) terminals: Vec<DistributedAgentStackTerminalRecord>,
    pub(crate) physical_binding_census: u16,
    pub(crate) census_complete: bool,
    pub(crate) fabric_ready: bool,
    pub(crate) agent_ready: bool,
    pub(crate) dependency_satisfied: bool,
    pub(crate) exact_zero: bool,
    pub(crate) quarantined: bool,
    pub(crate) installed_binding_set_digest: Option<Digest32>,
    pub(crate) raw_outcome_digest: Option<Digest32>,
    pub(crate) quarantine_reason: Option<Digest32>,
    evidence_state: DistributedAgentStackEvidenceStateV2,
    canonical_wire: Box<[u8]>,
}

impl DistributedAgentStackSnapshot {
    pub(crate) fn try_initial(
        store_instance_id: [u8; 32],
        owner_target_fingerprint: Digest32,
        transition_projection_digest: Digest32,
        runtime_host_epoch: u64,
        transition: DistributedAgentStackSnapshotTransition,
        projection: &DistributedAgentStackProjectionV1,
    ) -> Result<Self, DistributedAgentStackStateError> {
        Self::try_build(
            DistributedAgentStackSnapshotWireVersion::V1,
            SnapshotIdentity {
                store_instance_id,
                owner_target_fingerprint,
                transition_projection_digest,
            },
            1,
            runtime_host_epoch,
            transition,
            DistributedAgentStackEvidenceStateV2::empty(),
            projection,
        )
    }

    pub(crate) fn try_successor_at_epoch(
        &self,
        runtime_host_epoch: u64,
        transition: DistributedAgentStackSnapshotTransition,
        projection: &DistributedAgentStackProjectionV1,
    ) -> Result<Self, DistributedAgentStackStateError> {
        if runtime_host_epoch < self.runtime_host_epoch {
            return Err(DistributedAgentStackStateError::InvalidState);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(DistributedAgentStackStateError::SequenceOverflow)?;
        let successor = Self::try_build(
            self.wire_version,
            SnapshotIdentity {
                store_instance_id: self.store_instance_id,
                owner_target_fingerprint: self.owner_target_fingerprint,
                transition_projection_digest: self.transition_projection_digest,
            },
            sequence,
            runtime_host_epoch,
            transition,
            self.evidence_state.clone(),
            projection,
        )?;
        validate_evidence_successor(&self.evidence_state, &successor.evidence_state)?;
        validate_evidence_snapshot_successor(self, &successor)?;
        Ok(successor)
    }

    pub(crate) fn try_upgrade_v1_to_v2_at_epoch(
        &self,
        runtime_host_epoch: u64,
        projection: &DistributedAgentStackProjectionV1,
    ) -> Result<Self, DistributedAgentStackStateError> {
        if self.wire_version != DistributedAgentStackSnapshotWireVersion::V1 {
            return Err(DistributedAgentStackStateError::InvalidVersionTransition);
        }
        if runtime_host_epoch < self.runtime_host_epoch {
            return Err(DistributedAgentStackStateError::InvalidState);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(DistributedAgentStackStateError::SequenceOverflow)?;
        Self::try_build(
            DistributedAgentStackSnapshotWireVersion::V2,
            SnapshotIdentity {
                store_instance_id: self.store_instance_id,
                owner_target_fingerprint: self.owner_target_fingerprint,
                transition_projection_digest: self.transition_projection_digest,
            },
            sequence,
            runtime_host_epoch,
            self.transition(),
            DistributedAgentStackEvidenceStateV2::empty(),
            projection,
        )
    }

    pub(crate) fn try_v2_successor_at_epoch(
        &self,
        runtime_host_epoch: u64,
        transition: DistributedAgentStackSnapshotTransition,
        evidence_state: DistributedAgentStackEvidenceStateV2,
        projection: &DistributedAgentStackProjectionV1,
    ) -> Result<Self, DistributedAgentStackStateError> {
        if self.wire_version != DistributedAgentStackSnapshotWireVersion::V2 {
            return Err(DistributedAgentStackStateError::InvalidVersionTransition);
        }
        if runtime_host_epoch < self.runtime_host_epoch {
            return Err(DistributedAgentStackStateError::InvalidState);
        }
        validate_evidence_successor(&self.evidence_state, &evidence_state)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(DistributedAgentStackStateError::SequenceOverflow)?;
        let successor = Self::try_build(
            DistributedAgentStackSnapshotWireVersion::V2,
            SnapshotIdentity {
                store_instance_id: self.store_instance_id,
                owner_target_fingerprint: self.owner_target_fingerprint,
                transition_projection_digest: self.transition_projection_digest,
            },
            sequence,
            runtime_host_epoch,
            transition,
            evidence_state,
            projection,
        )?;
        validate_evidence_snapshot_successor(self, &successor)?;
        Ok(successor)
    }

    fn try_build(
        wire_version: DistributedAgentStackSnapshotWireVersion,
        identity: SnapshotIdentity,
        sequence: u64,
        runtime_host_epoch: u64,
        transition: DistributedAgentStackSnapshotTransition,
        evidence_state: DistributedAgentStackEvidenceStateV2,
        projection: &DistributedAgentStackProjectionV1,
    ) -> Result<Self, DistributedAgentStackStateError> {
        let mut snapshot = Self {
            wire_version,
            store_instance_id: identity.store_instance_id,
            owner_target_fingerprint: identity.owner_target_fingerprint,
            transition_projection_digest: identity.transition_projection_digest,
            sequence,
            runtime_host_epoch,
            fabric_generation_high_water: transition.fabric_generation_high_water,
            agent_generation_high_water: transition.agent_generation_high_water,
            phase: transition.phase,
            writer_fence: transition.writer_fence,
            revision_high_water: transition.revision_high_water,
            active: transition.active,
            pending: transition.pending,
            tenure_nonces: transition.tenure_nonces,
            request_nonces: transition.request_nonces,
            temporal_lineages: transition.temporal_lineages,
            terminals: transition.terminals,
            physical_binding_census: transition.physical_binding_census,
            census_complete: transition.census_complete,
            fabric_ready: transition.fabric_ready,
            agent_ready: transition.agent_ready,
            dependency_satisfied: transition.dependency_satisfied,
            exact_zero: transition.exact_zero,
            quarantined: transition.quarantined,
            installed_binding_set_digest: transition.installed_binding_set_digest,
            raw_outcome_digest: transition.raw_outcome_digest,
            quarantine_reason: transition.quarantine_reason,
            evidence_state,
            canonical_wire: Box::new([]),
        };
        snapshot.validate(projection)?;
        snapshot.canonical_wire = snapshot.encode()?.into_boxed_slice();
        Ok(snapshot)
    }

    pub(crate) fn decode(
        frame: &[u8],
        expected_store_instance_id: [u8; 32],
        expected_owner_target_fingerprint: Digest32,
        expected_transition_projection_digest: Digest32,
        projection: &DistributedAgentStackProjectionV1,
    ) -> Result<Self, DistributedAgentStackStateError> {
        if frame.len() < SNAPSHOT_HEADER_BYTES {
            return Err(DistributedAgentStackStateError::Truncated);
        }
        if frame.len() > MAX_DISTRIBUTED_AGENT_STACK_SNAPSHOT_BYTES {
            return Err(DistributedAgentStackStateError::FrameTooLarge);
        }
        if &frame[..4] != SNAPSHOT_MAGIC
            || usize::from(read_u16(&frame[6..8])) != SNAPSHOT_HEADER_BYTES
        {
            return Err(DistributedAgentStackStateError::UnsupportedFrame);
        }
        let wire_version =
            DistributedAgentStackSnapshotWireVersion::decode(read_u16(&frame[4..6]))?;
        let total = read_u32(&frame[8..12]) as usize;
        let payload_length = read_u32(&frame[152..156]) as usize;
        if total != frame.len()
            || SNAPSHOT_HEADER_BYTES.checked_add(payload_length) != Some(frame.len())
            || frame[141..152].iter().any(|byte| *byte != 0)
            || frame[156..160].iter().any(|byte| *byte != 0)
        {
            return Err(DistributedAgentStackStateError::InvalidLength);
        }
        let expected_checksum = snapshot_checksum(
            wire_version,
            &frame[..SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES],
            &frame[SNAPSHOT_HEADER_BYTES..],
        );
        if frame[160..192] != *expected_checksum.as_bytes() {
            return Err(DistributedAgentStackStateError::ChecksumMismatch);
        }
        let store_instance_id = read_array(&frame[20..52]);
        let owner_target_fingerprint = Digest32::from_bytes(read_array(&frame[52..84]));
        let transition_projection_digest = Digest32::from_bytes(read_array(&frame[84..116]));
        if store_instance_id != expected_store_instance_id
            || owner_target_fingerprint != expected_owner_target_fingerprint
            || transition_projection_digest != expected_transition_projection_digest
        {
            return Err(DistributedAgentStackStateError::IdentityMismatch);
        }
        let mut cursor = Cursor::new(&frame[SNAPSHOT_HEADER_BYTES..]);
        let runtime_host_epoch = cursor.u64()?;
        let writer_fence = decode_writer_fence(&mut cursor)?;
        let revision_high_water = decode_revision_high_water(&mut cursor)?;
        let active = decode_active(&mut cursor)?;
        let pending = decode_pending(&mut cursor)?;
        let tenure_nonces = decode_replay_records(&mut cursor)?;
        let request_nonces = decode_replay_records(&mut cursor)?;
        let temporal_lineages = decode_replay_records(&mut cursor)?;
        let terminals = decode_terminals(&mut cursor)?;
        let installed_binding_set_digest = decode_optional_digest(&mut cursor)?;
        let raw_outcome_digest = decode_optional_digest(&mut cursor)?;
        let quarantine_reason = decode_optional_digest(&mut cursor)?;
        let evidence_state = match wire_version {
            DistributedAgentStackSnapshotWireVersion::V1 => {
                DistributedAgentStackEvidenceStateV2::empty()
            }
            DistributedAgentStackSnapshotWireVersion::V2 => decode_evidence_state(&mut cursor)?,
        };
        if !cursor.done() {
            return Err(DistributedAgentStackStateError::TrailingBytes);
        }
        let snapshot = Self::try_build(
            wire_version,
            SnapshotIdentity {
                store_instance_id,
                owner_target_fingerprint,
                transition_projection_digest,
            },
            read_u64(&frame[12..20]),
            runtime_host_epoch,
            DistributedAgentStackSnapshotTransition {
                fabric_generation_high_water: read_u64(&frame[116..124]),
                agent_generation_high_water: read_u64(&frame[124..132]),
                phase: DistributedAgentStackDurablePhase::decode(frame[132], wire_version)?,
                physical_binding_census: read_u16(&frame[133..135]),
                census_complete: decode_bool(frame[135])?,
                fabric_ready: decode_bool(frame[136])?,
                agent_ready: decode_bool(frame[137])?,
                dependency_satisfied: decode_bool(frame[138])?,
                exact_zero: decode_bool(frame[139])?,
                quarantined: decode_bool(frame[140])?,
                writer_fence,
                revision_high_water,
                active,
                pending,
                tenure_nonces,
                request_nonces,
                temporal_lineages,
                terminals,
                installed_binding_set_digest,
                raw_outcome_digest,
                quarantine_reason,
            },
            evidence_state,
            projection,
        )?;
        if snapshot.canonical_wire() != frame {
            return Err(DistributedAgentStackStateError::NonCanonicalEncoding);
        }
        Ok(snapshot)
    }

    fn validate(
        &self,
        projection: &DistributedAgentStackProjectionV1,
    ) -> Result<(), DistributedAgentStackStateError> {
        if (self.wire_version == DistributedAgentStackSnapshotWireVersion::V1
            && (self.phase == DistributedAgentStackDurablePhase::EvidenceCommitIntent
                || !self.evidence_state.is_empty()))
            || self.store_instance_id.iter().all(|byte| *byte == 0)
            || digest_is_zero(self.owner_target_fingerprint)
            || digest_is_zero(self.transition_projection_digest)
            || self.sequence == 0
            || self.runtime_host_epoch == 0
            || self.physical_binding_census > 2
            || self.tenure_nonces.len() > MAX_REPLAY_ENTRIES
            || self.request_nonces.len() > MAX_REPLAY_ENTRIES
            || self.temporal_lineages.len() > MAX_REPLAY_ENTRIES
            || self.terminals.len() > MAX_TERMINALS
            || self
                .installed_binding_set_digest
                .is_some_and(digest_is_zero)
            || self.raw_outcome_digest.is_some_and(digest_is_zero)
            || self.quarantine_reason.is_some_and(digest_is_zero)
        {
            return Err(DistributedAgentStackStateError::InvalidState);
        }
        validate_evidence_state(&self.evidence_state)?;
        validate_evidence_snapshot_shape(self)?;
        validate_sorted_replays(&self.tenure_nonces)?;
        validate_sorted_replays(&self.request_nonces)?;
        validate_sorted_replays(&self.temporal_lineages)?;
        if let Some(fence) = self.writer_fence
            && (fence.source_scope.as_bytes().iter().all(|byte| *byte == 0)
                || fence.writer.as_bytes().iter().all(|byte| *byte == 0)
                || fence.principal.as_bytes().iter().all(|byte| *byte == 0)
                || fence.epoch == 0
                || digest_is_zero(fence.proof_envelope_digest))
        {
            return Err(DistributedAgentStackStateError::InvalidState);
        }
        if let Some(revision) = self.revision_high_water
            && (revision
                .source_scope
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
                || revision.revision == 0
                || digest_is_zero(*revision.source_plan_digest.value()))
        {
            return Err(DistributedAgentStackStateError::InvalidState);
        }
        if let Some(active) = &self.active {
            validate_request(&active.request, self, projection)?;
            if active.request.target_execution().mode()
                != DistributedAgentStackTargetModeV1::DistributedFabricAndAgent
                || active.response_channel.target() != active.request.target()
                || active.fabric_generation.value() > self.fabric_generation_high_water
                || active.agent_generation.value() > self.agent_generation_high_water
            {
                return Err(DistributedAgentStackStateError::InvalidState);
            }
        }
        if let Some(pending) = &self.pending {
            validate_request(&pending.request, self, projection)?;
            if pending.admitted_at_nanos == 0
                || pending.deadline_nanos < pending.admitted_at_nanos
                || pending.response_channel.target() != pending.request.target()
            {
                return Err(DistributedAgentStackStateError::InvalidState);
            }
            match (
                pending.kind,
                pending.fabric_generation,
                pending.agent_generation,
                pending.request.target_execution().mode(),
            ) {
                (
                    DistributedAgentStackPendingKind::ActivateDistributedStack
                    | DistributedAgentStackPendingKind::RecoverActive,
                    Some(fabric),
                    Some(agent),
                    DistributedAgentStackTargetModeV1::DistributedFabricAndAgent,
                ) if fabric.value() <= self.fabric_generation_high_water
                    && agent.value() <= self.agent_generation_high_water => {}
                (
                    DistributedAgentStackPendingKind::DeactivateStack,
                    _,
                    _,
                    DistributedAgentStackTargetModeV1::EmptyDeactivate,
                ) => {}
                _ => return Err(DistributedAgentStackStateError::InvalidState),
            }
        }
        validate_phase_shape(self)?;
        let mut prior_key = None;
        for terminal in &self.terminals {
            let key = (
                *terminal.source_scope.as_bytes(),
                *terminal.operation_id.as_bytes(),
            );
            let facts = terminal.receipt.facts();
            let evidence = facts.evidence();
            if prior_key.is_some_and(|prior| prior >= key)
                || facts.operation_id() != terminal.operation_id
                || facts.request_digest() != terminal.request_digest
                || facts.runtime_store_instance_id() != self.store_instance_id
                || facts.target() != projection.target()
                || evidence.completion_snapshot_sequence > self.sequence
                || evidence.runtime_host_epoch > self.runtime_host_epoch
                || evidence.fabric_generation.is_some_and(|generation| {
                    generation.value() > self.fabric_generation_high_water
                })
                || evidence
                    .agent_generation
                    .is_some_and(|generation| generation.value() > self.agent_generation_high_water)
            {
                return Err(DistributedAgentStackStateError::InvalidState);
            }
            prior_key = Some(key);
        }
        if self.phase == DistributedAgentStackDurablePhase::ActiveReady {
            validate_active_ready_snapshot(self)?;
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, DistributedAgentStackStateError> {
        let mut payload = Encoder::new();
        payload.u64(self.runtime_host_epoch);
        encode_writer_fence(&mut payload, self.writer_fence);
        encode_revision_high_water(&mut payload, self.revision_high_water);
        encode_active(&mut payload, self.active.as_ref())?;
        encode_pending(&mut payload, self.pending.as_ref())?;
        encode_replay_records(&mut payload, &self.tenure_nonces)?;
        encode_replay_records(&mut payload, &self.request_nonces)?;
        encode_replay_records(&mut payload, &self.temporal_lineages)?;
        encode_terminals(&mut payload, &self.terminals)?;
        encode_optional_digest(&mut payload, self.installed_binding_set_digest);
        encode_optional_digest(&mut payload, self.raw_outcome_digest);
        encode_optional_digest(&mut payload, self.quarantine_reason);
        if self.wire_version == DistributedAgentStackSnapshotWireVersion::V2 {
            encode_evidence_state(&mut payload, &self.evidence_state)?;
        }
        let payload = payload.finish();
        let total = SNAPSHOT_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(DistributedAgentStackStateError::FrameTooLarge)?;
        if total > MAX_DISTRIBUTED_AGENT_STACK_SNAPSHOT_BYTES {
            return Err(DistributedAgentStackStateError::FrameTooLarge);
        }
        let mut frame = vec![0_u8; SNAPSHOT_HEADER_BYTES];
        frame[..4].copy_from_slice(SNAPSHOT_MAGIC);
        frame[4..6].copy_from_slice(&(self.wire_version as u16).to_be_bytes());
        frame[6..8].copy_from_slice(&(SNAPSHOT_HEADER_BYTES as u16).to_be_bytes());
        frame[8..12].copy_from_slice(&(total as u32).to_be_bytes());
        frame[12..20].copy_from_slice(&self.sequence.to_be_bytes());
        frame[20..52].copy_from_slice(&self.store_instance_id);
        frame[52..84].copy_from_slice(self.owner_target_fingerprint.as_bytes());
        frame[84..116].copy_from_slice(self.transition_projection_digest.as_bytes());
        frame[116..124].copy_from_slice(&self.fabric_generation_high_water.to_be_bytes());
        frame[124..132].copy_from_slice(&self.agent_generation_high_water.to_be_bytes());
        frame[132] = self.phase as u8;
        frame[133..135].copy_from_slice(&self.physical_binding_census.to_be_bytes());
        frame[135] = u8::from(self.census_complete);
        frame[136] = u8::from(self.fabric_ready);
        frame[137] = u8::from(self.agent_ready);
        frame[138] = u8::from(self.dependency_satisfied);
        frame[139] = u8::from(self.exact_zero);
        frame[140] = u8::from(self.quarantined);
        frame[152..156].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        let checksum = snapshot_checksum(
            self.wire_version,
            &frame[..SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES],
            &payload,
        );
        frame[160..192].copy_from_slice(checksum.as_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    #[must_use]
    pub(crate) const fn wire_version(&self) -> DistributedAgentStackSnapshotWireVersion {
        self.wire_version
    }

    #[must_use]
    pub(crate) const fn evidence_state(&self) -> &DistributedAgentStackEvidenceStateV2 {
        &self.evidence_state
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn runtime_host_epoch(&self) -> u64 {
        self.runtime_host_epoch
    }

    pub(crate) fn transition(&self) -> DistributedAgentStackSnapshotTransition {
        DistributedAgentStackSnapshotTransition {
            fabric_generation_high_water: self.fabric_generation_high_water,
            agent_generation_high_water: self.agent_generation_high_water,
            phase: self.phase,
            writer_fence: self.writer_fence,
            revision_high_water: self.revision_high_water,
            active: self.active.clone(),
            pending: self.pending.clone(),
            tenure_nonces: self.tenure_nonces.clone(),
            request_nonces: self.request_nonces.clone(),
            temporal_lineages: self.temporal_lineages.clone(),
            terminals: self.terminals.clone(),
            physical_binding_census: self.physical_binding_census,
            census_complete: self.census_complete,
            fabric_ready: self.fabric_ready,
            agent_ready: self.agent_ready,
            dependency_satisfied: self.dependency_satisfied,
            exact_zero: self.exact_zero,
            quarantined: self.quarantined,
            installed_binding_set_digest: self.installed_binding_set_digest,
            raw_outcome_digest: self.raw_outcome_digest,
            quarantine_reason: self.quarantine_reason,
        }
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

fn validate_request(
    request: &DistributedAgentStackApplyRequestV1,
    snapshot: &DistributedAgentStackSnapshot,
    projection: &DistributedAgentStackProjectionV1,
) -> Result<(), DistributedAgentStackStateError> {
    request
        .validate_expected_store(snapshot.store_instance_id)
        .map_err(|_| DistributedAgentStackStateError::InvalidState)?;
    request
        .validate_projection(projection)
        .map_err(|_| DistributedAgentStackStateError::InvalidState)?;
    if request.target() != projection.target() {
        return Err(DistributedAgentStackStateError::InvalidState);
    }
    Ok(())
}

fn validate_phase_shape(
    snapshot: &DistributedAgentStackSnapshot,
) -> Result<(), DistributedAgentStackStateError> {
    let pending_activate = || {
        snapshot.pending.as_ref().is_some_and(|pending| {
            matches!(
                pending.kind,
                DistributedAgentStackPendingKind::ActivateDistributedStack
                    | DistributedAgentStackPendingKind::RecoverActive
            )
        })
    };
    let valid = match snapshot.phase {
        DistributedAgentStackDurablePhase::ExactZero => {
            snapshot.active.is_none()
                && snapshot.pending.is_none()
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && !snapshot.fabric_ready
                && !snapshot.agent_ready
                && !snapshot.dependency_satisfied
                && snapshot.exact_zero
                && !snapshot.quarantined
                && snapshot.quarantine_reason.is_none()
        }
        DistributedAgentStackDurablePhase::PreparedNoEffects
        | DistributedAgentStackDurablePhase::StartIntent => {
            snapshot.active.is_none()
                && pending_activate()
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && !snapshot.fabric_ready
                && !snapshot.agent_ready
                && !snapshot.dependency_satisfied
                && !snapshot.exact_zero
                && !snapshot.quarantined
                && snapshot.quarantine_reason.is_none()
        }
        DistributedAgentStackDurablePhase::AgentStartIntent => {
            snapshot.active.is_none()
                && pending_activate()
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && !snapshot.agent_ready
                && snapshot.dependency_satisfied
                && !snapshot.exact_zero
                && !snapshot.quarantined
                && snapshot.quarantine_reason.is_none()
        }
        DistributedAgentStackDurablePhase::EvidenceCommitIntent => {
            snapshot.active.is_none()
                && pending_activate()
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && !snapshot.agent_ready
                && snapshot.dependency_satisfied
                && !snapshot.exact_zero
                && !snapshot.quarantined
                && snapshot.quarantine_reason.is_none()
        }
        DistributedAgentStackDurablePhase::ActiveReady => {
            snapshot.active.is_some()
                && snapshot.pending.is_none()
                && snapshot.physical_binding_census == 2
                && snapshot.census_complete
                && snapshot.fabric_ready
                && snapshot.agent_ready
                && snapshot.dependency_satisfied
                && !snapshot.exact_zero
                && !snapshot.quarantined
                && snapshot.installed_binding_set_digest.is_some()
                && snapshot.raw_outcome_digest.is_some()
                && snapshot.quarantine_reason.is_none()
        }
        DistributedAgentStackDurablePhase::AgentRetireIntent => {
            snapshot.active.is_some()
                && snapshot.pending.as_ref().is_some_and(|pending| {
                    pending.kind == DistributedAgentStackPendingKind::DeactivateStack
                })
                && snapshot.physical_binding_census == 2
                && snapshot.census_complete
                && snapshot.fabric_ready
                && snapshot.agent_ready
                && snapshot.dependency_satisfied
                && !snapshot.exact_zero
                && !snapshot.quarantined
        }
        DistributedAgentStackDurablePhase::FabricStopIntent => {
            snapshot.active.is_some()
                && snapshot.pending.as_ref().is_some_and(|pending| {
                    pending.kind == DistributedAgentStackPendingKind::DeactivateStack
                })
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && !snapshot.agent_ready
                && !snapshot.dependency_satisfied
                && !snapshot.exact_zero
                && !snapshot.quarantined
        }
        DistributedAgentStackDurablePhase::RecoveryIntent => {
            pending_activate()
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && !snapshot.fabric_ready
                && !snapshot.agent_ready
                && !snapshot.dependency_satisfied
                && !snapshot.exact_zero
                && !snapshot.quarantined
        }
        DistributedAgentStackDurablePhase::Uncertain => {
            (snapshot.pending.is_some() || snapshot.active.is_some())
                && !snapshot.census_complete
                && !snapshot.exact_zero
                && !snapshot.quarantined
                && snapshot.raw_outcome_digest.is_some()
        }
        DistributedAgentStackDurablePhase::Quarantined => {
            !snapshot.agent_ready
                && !snapshot.dependency_satisfied
                && !snapshot.exact_zero
                && snapshot.quarantined
                && snapshot.quarantine_reason.is_some()
                && snapshot.raw_outcome_digest.is_some()
        }
    };
    valid
        .then_some(())
        .ok_or(DistributedAgentStackStateError::InvalidState)
}

fn validate_sorted_replays(
    records: &[DistributedAgentStackReplayRecord],
) -> Result<(), DistributedAgentStackStateError> {
    let mut prior = None;
    for record in records {
        if digest_is_zero(record.identity)
            || digest_is_zero(record.value_digest)
            || prior.is_some_and(|value| value >= record.identity)
        {
            return Err(DistributedAgentStackStateError::InvalidState);
        }
        prior = Some(record.identity);
    }
    Ok(())
}

fn validate_evidence_record_chain(
    base_head: Option<DistributedAgentStackEvidenceOwnerHeadV2>,
    records: &[EvidenceRecordV1],
) -> Result<(), DistributedAgentStackStateError> {
    if records.is_empty() || records.len() > MAX_EVIDENCE_BATCH_RECORDS {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    let mut expected_sequence = match base_head {
        Some(head) => head
            .producer_sequence()
            .checked_add(1)
            .ok_or(DistributedAgentStackStateError::SequenceOverflow)?,
        None => 1,
    };
    let mut expected_previous = base_head.map(DistributedAgentStackEvidenceOwnerHeadV2::record_id);
    let mut record_ids = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        if record.producer_sequence() != expected_sequence
            || record.previous_evidence_ref() != expected_previous
            || record_ids.contains(&record.record_id())
        {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        record_ids.push(record.record_id());
        expected_previous = Some(record.record_id());
        if index + 1 < records.len() {
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(DistributedAgentStackStateError::SequenceOverflow)?;
        }
    }
    Ok(())
}

fn decode_evidence_transport_proof(
    record: &EvidenceRecordV1,
) -> Result<DistributedFabricObservedTransportProofV1, DistributedAgentStackStateError> {
    if record.kind() != EvidenceKindV1::RuntimeFact {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    let payload = record
        .payload()
        .inline_bytes()
        .filter(|bytes| bytes.len() == DISTRIBUTED_FABRIC_TRANSPORT_PROOF_BYTES)
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
    let proof = DistributedFabricObservedTransportProofV1::decode(payload)
        .map_err(|_| DistributedAgentStackStateError::InvalidNestedContract)?;
    if proof.canonical_wire() != payload
        || proof.fields().transport_evidence_ref.as_bytes() != record.record_id().as_bytes()
    {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    Ok(proof)
}

fn validate_evidence_record_payloads(
    session_epoch: DistributedFabricSessionEpochV1,
    records: &[EvidenceRecordV1],
) -> Result<(), DistributedAgentStackStateError> {
    let mut observation_sequences = Vec::with_capacity(records.len());
    for record in records {
        let proof = decode_evidence_transport_proof(record)?;
        let fields = proof.fields();
        if fields.session_epoch != session_epoch
            || observation_sequences.contains(&fields.observation_sequence)
        {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        observation_sequences.push(fields.observation_sequence);
    }
    Ok(())
}

fn validate_evidence_state(
    state: &DistributedAgentStackEvidenceStateV2,
) -> Result<(), DistributedAgentStackStateError> {
    let Some(binding) = state.binding else {
        return if state.owner_head.is_none()
            && matches!(&state.handoff, DistributedAgentStackEvidenceHandoffV2::None)
        {
            Ok(())
        } else {
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        };
    };
    let batch = match &state.handoff {
        DistributedAgentStackEvidenceHandoffV2::None => return Ok(()),
        DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch) => batch,
        DistributedAgentStackEvidenceHandoffV2::Committed(committed) => committed.batch(),
    };
    validate_evidence_record_chain(batch.base_head(), batch.records())?;
    validate_evidence_record_payloads(batch.session_epoch(), batch.records())?;
    if batch
        .records()
        .iter()
        .any(|record| record.owner_ref() != binding.owner_ref())
    {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    match &state.handoff {
        DistributedAgentStackEvidenceHandoffV2::CommitIntent(_) => {
            if state.owner_head != batch.base_head() {
                return Err(DistributedAgentStackStateError::InvalidEvidenceState);
            }
        }
        DistributedAgentStackEvidenceHandoffV2::Committed(_) => {
            if state.owner_head != Some(batch.tail_head()?) {
                return Err(DistributedAgentStackStateError::InvalidEvidenceState);
            }
        }
        DistributedAgentStackEvidenceHandoffV2::None => {}
    }
    Ok(())
}

fn validate_evidence_snapshot_shape(
    snapshot: &DistributedAgentStackSnapshot,
) -> Result<(), DistributedAgentStackStateError> {
    let batch = match snapshot.evidence_state.handoff() {
        DistributedAgentStackEvidenceHandoffV2::None => {
            if snapshot.phase == DistributedAgentStackDurablePhase::EvidenceCommitIntent {
                return Err(DistributedAgentStackStateError::InvalidEvidenceState);
            }
            None
        }
        DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch) => {
            if snapshot.phase != DistributedAgentStackDurablePhase::EvidenceCommitIntent {
                return Err(DistributedAgentStackStateError::InvalidEvidenceState);
            }
            Some(batch)
        }
        DistributedAgentStackEvidenceHandoffV2::Committed(committed) => {
            if snapshot.phase != DistributedAgentStackDurablePhase::AgentStartIntent {
                return Err(DistributedAgentStackStateError::InvalidEvidenceState);
            }
            Some(committed.batch())
        }
    };
    if let Some(batch) = batch {
        if batch.fabric_generation().value() > snapshot.fabric_generation_high_water {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        let pending = snapshot
            .pending
            .as_ref()
            .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
        if !matches!(
            pending.kind,
            DistributedAgentStackPendingKind::ActivateDistributedStack
                | DistributedAgentStackPendingKind::RecoverActive
        ) || pending.request.envelope_request_digest() != batch.request_digest()
            || pending.fabric_generation != Some(batch.fabric_generation())
        {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        let request = &pending.request;
        let topology = request
            .target_execution()
            .topology()
            .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
        if batch.records().len() != topology.peers().len() {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        for (record, peer) in batch.records().iter().zip(topology.peers()) {
            decode_evidence_transport_proof(record)?
                .validate_against(request.target(), peer)
                .map_err(|_| DistributedAgentStackStateError::InvalidEvidenceState)?;
        }
    }
    Ok(())
}

fn validate_evidence_successor(
    prior: &DistributedAgentStackEvidenceStateV2,
    next: &DistributedAgentStackEvidenceStateV2,
) -> Result<(), DistributedAgentStackStateError> {
    if prior.binding.is_some() && prior.binding != next.binding {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    let valid = match (&prior.handoff, &next.handoff) {
        (
            DistributedAgentStackEvidenceHandoffV2::None,
            DistributedAgentStackEvidenceHandoffV2::None,
        ) => prior.owner_head == next.owner_head,
        (
            DistributedAgentStackEvidenceHandoffV2::None,
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(_),
        ) => prior.owner_head == next.owner_head,
        (
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(prior_batch),
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(next_batch),
        ) => prior.owner_head == next.owner_head && prior_batch == next_batch,
        (
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(prior_batch),
            DistributedAgentStackEvidenceHandoffV2::Committed(next_commit),
        ) => prior_batch == next_commit.batch(),
        (
            DistributedAgentStackEvidenceHandoffV2::Committed(prior_batch),
            DistributedAgentStackEvidenceHandoffV2::Committed(next_batch),
        ) => prior.owner_head == next.owner_head && prior_batch == next_batch,
        (
            DistributedAgentStackEvidenceHandoffV2::Committed(_),
            DistributedAgentStackEvidenceHandoffV2::None,
        ) => prior.owner_head == next.owner_head,
        _ => false,
    };
    valid
        .then_some(())
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)
}

fn validate_active_ready_snapshot(
    snapshot: &DistributedAgentStackSnapshot,
) -> Result<(), DistributedAgentStackStateError> {
    let active = snapshot
        .active
        .as_ref()
        .ok_or(DistributedAgentStackStateError::InvalidState)?;
    if active.fabric_generation.value() != snapshot.fabric_generation_high_water
        || active.agent_generation.value() != snapshot.agent_generation_high_water
    {
        return Err(DistributedAgentStackStateError::InvalidState);
    }
    let (_, facts) = terminal_for_request(
        snapshot,
        &active.request,
        active.response_channel,
        DistributedAgentStackStateError::InvalidState,
    )?;
    let evidence = facts.evidence();
    let terminal_is_current = evidence.fabric_generation == Some(active.fabric_generation)
        && evidence.agent_generation == Some(active.agent_generation);
    let terminal_is_historical = terminal_generations_precede_active(evidence, active);
    if facts.outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady
        || !terminal_is_current && !terminal_is_historical
        || terminal_is_current
            && !terminal_local_bindings_match_snapshot(evidence.local_bindings, snapshot)
    {
        return Err(DistributedAgentStackStateError::InvalidState);
    }
    Ok(())
}

fn terminal_for_request<'a>(
    snapshot: &'a DistributedAgentStackSnapshot,
    request: &DistributedAgentStackApplyRequestV1,
    response_channel: ReferenceChannelBindingV1,
    error: DistributedAgentStackStateError,
) -> Result<
    (
        &'a DistributedAgentStackTerminalRecord,
        &'a DistributedAgentStackTerminalFactsV1,
    ),
    DistributedAgentStackStateError,
> {
    let source_scope = request.provenance().source_scope();
    let operation_id = request.operation_id();
    let terminal = snapshot
        .terminals
        .iter()
        .find(|terminal| {
            terminal.source_scope == source_scope && terminal.operation_id == operation_id
        })
        .ok_or(error)?;
    if terminal.request_digest != request.envelope_request_digest() {
        return Err(error);
    }
    let facts = terminal
        .receipt
        .validate_against_request(request, response_channel)
        .map_err(|_| error)?;
    Ok((terminal, facts))
}

fn terminal_local_bindings_match_snapshot(
    local: DistributedAgentStackLocalBindingEvidenceFieldsV1,
    snapshot: &DistributedAgentStackSnapshot,
) -> bool {
    local.physical_binding_census == snapshot.physical_binding_census
        && local.census_complete == snapshot.census_complete
        && local.fabric_ready == snapshot.fabric_ready
        && local.agent_ready == snapshot.agent_ready
        && local.dependency_satisfied == snapshot.dependency_satisfied
        && local.exact_zero == snapshot.exact_zero
        && local.quarantined == snapshot.quarantined
        && snapshot.installed_binding_set_digest == Some(local.installed_binding_set_digest)
        && snapshot.raw_outcome_digest == Some(local.raw_outcome_digest)
}

fn validate_evidence_snapshot_successor(
    prior: &DistributedAgentStackSnapshot,
    next: &DistributedAgentStackSnapshot,
) -> Result<(), DistributedAgentStackStateError> {
    if next.wire_version != DistributedAgentStackSnapshotWireVersion::V2 {
        return Ok(());
    }
    match (
        prior.evidence_state.handoff(),
        next.evidence_state.handoff(),
        next.phase,
    ) {
        (
            DistributedAgentStackEvidenceHandoffV2::Committed(_),
            DistributedAgentStackEvidenceHandoffV2::Committed(_),
            _,
        ) => {
            if prior.transition() != next.transition() {
                return Err(DistributedAgentStackStateError::InvalidEvidenceState);
            }
        }
        (
            DistributedAgentStackEvidenceHandoffV2::Committed(prior_commit),
            DistributedAgentStackEvidenceHandoffV2::None,
            DistributedAgentStackDurablePhase::ActiveReady,
        ) => {
            validate_committed_active_ready_successor(prior, next, prior_commit.batch())?;
        }
        (
            DistributedAgentStackEvidenceHandoffV2::Committed(prior_commit),
            DistributedAgentStackEvidenceHandoffV2::None,
            DistributedAgentStackDurablePhase::RecoveryIntent,
        ) => {
            validate_committed_recovery_successor(prior, next, prior_commit.batch())?;
        }
        (
            DistributedAgentStackEvidenceHandoffV2::Committed(prior_commit),
            DistributedAgentStackEvidenceHandoffV2::None,
            DistributedAgentStackDurablePhase::ExactZero,
        ) => {
            validate_committed_exact_zero_successor(prior, next, prior_commit.batch())?;
        }
        (
            DistributedAgentStackEvidenceHandoffV2::Committed(prior_commit),
            DistributedAgentStackEvidenceHandoffV2::None,
            DistributedAgentStackDurablePhase::Quarantined,
        ) => {
            validate_committed_quarantined_successor(prior, next, prior_commit.batch())?;
        }
        (
            DistributedAgentStackEvidenceHandoffV2::Committed(_),
            DistributedAgentStackEvidenceHandoffV2::None,
            _,
        ) => return Err(DistributedAgentStackStateError::InvalidEvidenceState),
        (_, _, DistributedAgentStackDurablePhase::ActiveReady)
            if prior.phase != DistributedAgentStackDurablePhase::ActiveReady
                || prior.transition() != next.transition() =>
        {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        _ => {}
    }
    Ok(())
}

fn validate_committed_active_ready_successor(
    prior: &DistributedAgentStackSnapshot,
    next: &DistributedAgentStackSnapshot,
    batch: &DistributedAgentStackEvidenceBatchV2,
) -> Result<(), DistributedAgentStackStateError> {
    let pending = committed_pending(prior, batch)?;
    let active = next
        .active
        .as_ref()
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
    let fabric_generation = pending
        .fabric_generation
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
    let agent_generation = pending
        .agent_generation
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
    if active.fabric_generation != fabric_generation
        || active.agent_generation != agent_generation
        || active.response_channel != pending.response_channel
        || active.request != pending.request
        || next.pending.is_some()
        || next.fabric_generation_high_water != prior.fabric_generation_high_water
        || next.agent_generation_high_water != prior.agent_generation_high_water
        || fabric_generation.value() != next.fabric_generation_high_water
        || agent_generation.value() != next.agent_generation_high_water
        || !durable_history_unchanged(prior, next)
    {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    validate_active_ready_snapshot(next)
        .map_err(|_| DistributedAgentStackStateError::InvalidEvidenceState)?;
    let (terminal, facts) = terminal_for_request(
        next,
        &active.request,
        active.response_channel,
        DistributedAgentStackStateError::InvalidEvidenceState,
    )?;
    let inserted = validate_terminal_history_for_request(prior, next, &active.request)?;
    if inserted {
        if facts.evidence().completion_snapshot_sequence != next.sequence
            || facts.evidence().runtime_host_epoch != next.runtime_host_epoch
        {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        return validate_terminal_proofs_match_batch(terminal, batch);
    }
    if !terminal_generations_precede_active(facts.evidence(), active) {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    Ok(())
}

fn terminal_generations_precede_active(
    evidence: DistributedAgentStackTerminalEvidenceFieldsV1,
    active: &DistributedAgentStackDurableActive,
) -> bool {
    evidence
        .fabric_generation
        .is_some_and(|generation| generation.value() < active.fabric_generation.value())
        && evidence
            .agent_generation
            .is_some_and(|generation| generation.value() < active.agent_generation.value())
}

fn validate_committed_recovery_successor(
    prior: &DistributedAgentStackSnapshot,
    next: &DistributedAgentStackSnapshot,
    batch: &DistributedAgentStackEvidenceBatchV2,
) -> Result<(), DistributedAgentStackStateError> {
    let prior_pending = committed_pending(prior, batch)?;
    let next_pending = next
        .pending
        .as_ref()
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
    let fabric_generation = next_pending
        .fabric_generation
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
    let agent_generation = next_pending
        .agent_generation
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
    if next_pending.kind != DistributedAgentStackPendingKind::RecoverActive
        || next_pending.request != prior_pending.request
        || next_pending.response_channel != prior_pending.response_channel
        || next.active.is_some()
        || fabric_generation.value() != next.fabric_generation_high_water
        || agent_generation.value() != next.agent_generation_high_water
        || fabric_generation.value() <= prior.fabric_generation_high_water
        || agent_generation.value() <= prior.agent_generation_high_water
        || fabric_generation.value() <= batch.fabric_generation().value()
        || next.physical_binding_census != 0
        || !next.census_complete
        || next.fabric_ready
        || next.agent_ready
        || next.dependency_satisfied
        || next.exact_zero
        || next.quarantined
        || next.installed_binding_set_digest.is_some()
        || next.raw_outcome_digest.is_some()
        || next.quarantine_reason.is_some()
        || next.terminals != prior.terminals
        || !durable_history_unchanged(prior, next)
    {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    Ok(())
}

fn validate_committed_exact_zero_successor(
    prior: &DistributedAgentStackSnapshot,
    next: &DistributedAgentStackSnapshot,
    batch: &DistributedAgentStackEvidenceBatchV2,
) -> Result<(), DistributedAgentStackStateError> {
    let pending = committed_pending(prior, batch)?;
    if next.fabric_generation_high_water != prior.fabric_generation_high_water
        || next.agent_generation_high_water != prior.agent_generation_high_water
        || !durable_history_unchanged(prior, next)
    {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    let inserted = validate_terminal_history_for_request(prior, next, &pending.request)?;
    if !inserted {
        validate_historical_active_terminal(next, pending)?;
        return Ok(());
    }
    let (terminal, facts) = terminal_for_request(
        next,
        &pending.request,
        pending.response_channel,
        DistributedAgentStackStateError::InvalidEvidenceState,
    )?;
    let evidence = facts.evidence();
    let local = evidence.local_bindings;
    if facts.outcome() != DistributedAgentStackTerminalOutcomeV1::TerminalNonReady
        || evidence.runtime_host_epoch != next.runtime_host_epoch
        || evidence.completion_snapshot_sequence != next.sequence
        || evidence.fabric_generation.is_some()
        || evidence.agent_generation.is_some()
        || local.physical_binding_census != 0
        || local.census_complete
        || local.fabric_ready
        || local.agent_ready
        || local.dependency_satisfied
        || local.exact_zero
        || local.quarantined
        || next.installed_binding_set_digest != Some(local.installed_binding_set_digest)
        || next.raw_outcome_digest != Some(local.raw_outcome_digest)
    {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    validate_terminal_proofs_match_batch(terminal, batch)
}

fn validate_committed_quarantined_successor(
    prior: &DistributedAgentStackSnapshot,
    next: &DistributedAgentStackSnapshot,
    batch: &DistributedAgentStackEvidenceBatchV2,
) -> Result<(), DistributedAgentStackStateError> {
    let pending = committed_pending(prior, batch)?;
    if next.active.is_some()
        || next.pending.as_ref() != Some(pending)
        || next.fabric_generation_high_water != prior.fabric_generation_high_water
        || next.agent_generation_high_water != prior.agent_generation_high_water
        || next.physical_binding_census != 0
        || next.census_complete
        || next.fabric_ready
        || next.agent_ready
        || next.dependency_satisfied
        || next.exact_zero
        || !next.quarantined
        || !durable_history_unchanged(prior, next)
    {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    let inserted = validate_terminal_history_for_request(prior, next, &pending.request)?;
    if !inserted {
        validate_historical_active_terminal(next, pending)?;
        return Ok(());
    }
    let (terminal, facts) = terminal_for_request(
        next,
        &pending.request,
        pending.response_channel,
        DistributedAgentStackStateError::InvalidEvidenceState,
    )?;
    let evidence = facts.evidence();
    if facts.outcome() != DistributedAgentStackTerminalOutcomeV1::IndeterminateUncertain
        || evidence.runtime_host_epoch != next.runtime_host_epoch
        || evidence.completion_snapshot_sequence != next.sequence
        || evidence.fabric_generation != pending.fabric_generation
        || evidence.agent_generation != pending.agent_generation
        || !terminal_local_bindings_match_snapshot(evidence.local_bindings, next)
    {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    validate_terminal_proofs_match_batch(terminal, batch)
}

fn committed_pending<'a>(
    snapshot: &'a DistributedAgentStackSnapshot,
    batch: &DistributedAgentStackEvidenceBatchV2,
) -> Result<&'a DistributedAgentStackDurablePending, DistributedAgentStackStateError> {
    let pending = snapshot
        .pending
        .as_ref()
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
    if snapshot.phase != DistributedAgentStackDurablePhase::AgentStartIntent
        || !matches!(
            pending.kind,
            DistributedAgentStackPendingKind::ActivateDistributedStack
                | DistributedAgentStackPendingKind::RecoverActive
        )
        || pending.request.envelope_request_digest() != batch.request_digest()
        || pending.fabric_generation != Some(batch.fabric_generation())
        || pending.agent_generation.is_none()
    {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    Ok(pending)
}

fn validate_historical_active_terminal(
    snapshot: &DistributedAgentStackSnapshot,
    pending: &DistributedAgentStackDurablePending,
) -> Result<(), DistributedAgentStackStateError> {
    let (_, facts) = terminal_for_request(
        snapshot,
        &pending.request,
        pending.response_channel,
        DistributedAgentStackStateError::InvalidEvidenceState,
    )?;
    if facts.outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady
        || facts.evidence().fabric_generation.is_none()
        || facts.evidence().agent_generation.is_none()
    {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    Ok(())
}

fn durable_history_unchanged(
    prior: &DistributedAgentStackSnapshot,
    next: &DistributedAgentStackSnapshot,
) -> bool {
    prior.writer_fence == next.writer_fence
        && prior.revision_high_water == next.revision_high_water
        && prior.tenure_nonces == next.tenure_nonces
        && prior.request_nonces == next.request_nonces
        && prior.temporal_lineages == next.temporal_lineages
}

fn validate_terminal_history_for_request(
    prior: &DistributedAgentStackSnapshot,
    next: &DistributedAgentStackSnapshot,
    request: &DistributedAgentStackApplyRequestV1,
) -> Result<bool, DistributedAgentStackStateError> {
    let source_scope = request.provenance().source_scope();
    let operation_id = request.operation_id();
    let next_index = next
        .terminals
        .iter()
        .position(|terminal| {
            terminal.source_scope == source_scope && terminal.operation_id == operation_id
        })
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
    if let Some(prior_index) = prior.terminals.iter().position(|terminal| {
        terminal.source_scope == source_scope && terminal.operation_id == operation_id
    }) {
        if prior.terminals != next.terminals
            || prior.terminals[prior_index] != next.terminals[next_index]
        {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
        return Ok(false);
    }
    if next.terminals.len() != prior.terminals.len() + 1 {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    let mut without_inserted = next.terminals.clone();
    without_inserted.remove(next_index);
    if without_inserted != prior.terminals {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    Ok(true)
}

fn validate_terminal_proofs_match_batch(
    terminal: &DistributedAgentStackTerminalRecord,
    batch: &DistributedAgentStackEvidenceBatchV2,
) -> Result<(), DistributedAgentStackStateError> {
    let observations = terminal
        .receipt
        .facts()
        .observations()
        .ok_or(DistributedAgentStackStateError::InvalidEvidenceState)?;
    if observations.proofs().len() != batch.records().len() {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    for (actual, record) in observations.proofs().iter().zip(batch.records()) {
        let expected = decode_evidence_transport_proof(record)
            .map_err(|_| DistributedAgentStackStateError::InvalidEvidenceState)?;
        if actual != &expected {
            return Err(DistributedAgentStackStateError::InvalidEvidenceState);
        }
    }
    Ok(())
}

fn encode_writer_fence(encoder: &mut Encoder, value: Option<DistributedAgentStackWriterFence>) {
    let Some(value) = value else {
        encoder.u8(0);
        return;
    };
    encoder.u8(1);
    encoder.bytes(value.source_scope.as_bytes());
    encoder.bytes(value.writer.as_bytes());
    encoder.bytes(value.principal.as_bytes());
    encoder.u64(value.epoch);
    encoder.digest(value.proof_envelope_digest);
}

fn decode_writer_fence(
    cursor: &mut Cursor<'_>,
) -> Result<Option<DistributedAgentStackWriterFence>, DistributedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(DistributedAgentStackWriterFence {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            writer: PlanWriterRef::from_bytes(cursor.array()?),
            principal: PrincipalRef::from_bytes(cursor.array()?),
            epoch: cursor.u64()?,
            proof_envelope_digest: cursor.digest()?,
        })),
        _ => Err(DistributedAgentStackStateError::InvalidPresence),
    }
}

fn encode_revision_high_water(
    encoder: &mut Encoder,
    value: Option<DistributedAgentStackRevisionHighWater>,
) {
    let Some(value) = value else {
        encoder.u8(0);
        return;
    };
    encoder.u8(1);
    encoder.bytes(value.source_scope.as_bytes());
    encoder.u64(value.revision);
    encoder.digest(*value.source_plan_digest.value());
}

fn decode_revision_high_water(
    cursor: &mut Cursor<'_>,
) -> Result<Option<DistributedAgentStackRevisionHighWater>, DistributedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(DistributedAgentStackRevisionHighWater {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            revision: cursor.u64()?,
            source_plan_digest: SourcePlanDigest::new(cursor.digest()?),
        })),
        _ => Err(DistributedAgentStackStateError::InvalidPresence),
    }
}

fn encode_active(
    encoder: &mut Encoder,
    value: Option<&DistributedAgentStackDurableActive>,
) -> Result<(), DistributedAgentStackStateError> {
    let Some(value) = value else {
        encoder.u8(0);
        return Ok(());
    };
    encoder.u8(1);
    encoder.u64(value.fabric_generation.value());
    encoder.u64(value.agent_generation.value());
    encode_channel(encoder, value.response_channel);
    encoder.bounded(value.request.canonical_wire())?;
    Ok(())
}

fn decode_active(
    cursor: &mut Cursor<'_>,
) -> Result<Option<DistributedAgentStackDurableActive>, DistributedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(DistributedAgentStackDurableActive {
            fabric_generation: decode_generation(cursor)?,
            agent_generation: decode_generation(cursor)?,
            response_channel: decode_channel(cursor)?,
            request: DistributedAgentStackApplyRequestV1::decode(
                cursor.bounded(MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES)?,
            )
            .map_err(|_| DistributedAgentStackStateError::InvalidNestedContract)?,
        })),
        _ => Err(DistributedAgentStackStateError::InvalidPresence),
    }
}

fn encode_pending(
    encoder: &mut Encoder,
    value: Option<&DistributedAgentStackDurablePending>,
) -> Result<(), DistributedAgentStackStateError> {
    let Some(value) = value else {
        encoder.u8(0);
        return Ok(());
    };
    encoder.u8(1);
    encoder.u8(value.kind as u8);
    encoder.u64(
        value
            .fabric_generation
            .map_or(0, ManagedServiceGeneration::value),
    );
    encoder.u64(
        value
            .agent_generation
            .map_or(0, ManagedServiceGeneration::value),
    );
    encoder.u64(value.admitted_clock_generation.value());
    encoder.u64(value.admitted_at_nanos);
    encoder.u64(value.deadline_nanos);
    encode_channel(encoder, value.response_channel);
    encoder.bounded(value.request.canonical_wire())?;
    Ok(())
}

fn decode_pending(
    cursor: &mut Cursor<'_>,
) -> Result<Option<DistributedAgentStackDurablePending>, DistributedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(DistributedAgentStackDurablePending {
            kind: DistributedAgentStackPendingKind::decode(cursor.u8()?)?,
            fabric_generation: decode_optional_generation(cursor)?,
            agent_generation: decode_optional_generation(cursor)?,
            admitted_clock_generation: ClockGeneration::try_new(cursor.u64()?)
                .map_err(|_| DistributedAgentStackStateError::InvalidState)?,
            admitted_at_nanos: cursor.u64()?,
            deadline_nanos: cursor.u64()?,
            response_channel: decode_channel(cursor)?,
            request: DistributedAgentStackApplyRequestV1::decode(
                cursor.bounded(MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES)?,
            )
            .map_err(|_| DistributedAgentStackStateError::InvalidNestedContract)?,
        })),
        _ => Err(DistributedAgentStackStateError::InvalidPresence),
    }
}

fn encode_channel(encoder: &mut Encoder, channel: ReferenceChannelBindingV1) {
    encoder.bytes(channel.target().as_bytes());
    encoder.bytes(channel.runtime_peer().as_bytes());
    encoder.digest(channel.local_endpoint_identity_digest());
    encoder.digest(channel.peer_credentials_digest());
}

fn decode_channel(
    cursor: &mut Cursor<'_>,
) -> Result<ReferenceChannelBindingV1, DistributedAgentStackStateError> {
    ReferenceChannelBindingV1::try_new(
        RuntimeHostId::from_bytes(cursor.array()?),
        PrincipalRef::from_bytes(cursor.array()?),
        cursor.digest()?,
        cursor.digest()?,
    )
    .map_err(|_| DistributedAgentStackStateError::InvalidNestedContract)
}

fn encode_replay_records(
    encoder: &mut Encoder,
    records: &[DistributedAgentStackReplayRecord],
) -> Result<(), DistributedAgentStackStateError> {
    encoder.count(records.len())?;
    for record in records {
        encoder.digest(record.identity);
        encoder.digest(record.value_digest);
    }
    Ok(())
}

fn decode_replay_records(
    cursor: &mut Cursor<'_>,
) -> Result<Vec<DistributedAgentStackReplayRecord>, DistributedAgentStackStateError> {
    let count = cursor.count(MAX_REPLAY_ENTRIES)?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(DistributedAgentStackReplayRecord {
            identity: cursor.digest()?,
            value_digest: cursor.digest()?,
        });
    }
    Ok(records)
}

fn encode_terminals(
    encoder: &mut Encoder,
    terminals: &[DistributedAgentStackTerminalRecord],
) -> Result<(), DistributedAgentStackStateError> {
    encoder.count(terminals.len())?;
    for terminal in terminals {
        encoder.bytes(terminal.source_scope.as_bytes());
        encoder.bytes(terminal.operation_id.as_bytes());
        encoder.digest(terminal.request_digest);
        encoder.bounded(terminal.receipt.canonical_wire())?;
    }
    Ok(())
}

fn decode_terminals(
    cursor: &mut Cursor<'_>,
) -> Result<Vec<DistributedAgentStackTerminalRecord>, DistributedAgentStackStateError> {
    let count = cursor.count(MAX_TERMINALS)?;
    let mut terminals = Vec::with_capacity(count);
    for _ in 0..count {
        terminals.push(DistributedAgentStackTerminalRecord {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            operation_id: ApplyOperationId::from_bytes(cursor.array()?),
            request_digest: cursor.digest()?,
            receipt: DistributedAgentStackTerminalReceiptV1::decode(
                cursor.bounded(MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_BYTES)?,
            )
            .map_err(|_| DistributedAgentStackStateError::InvalidNestedContract)?,
        });
    }
    Ok(terminals)
}

fn encode_optional_digest(encoder: &mut Encoder, value: Option<Digest32>) {
    match value {
        Some(value) => {
            encoder.u8(1);
            encoder.digest(value);
        }
        None => encoder.u8(0),
    }
}

fn decode_optional_digest(
    cursor: &mut Cursor<'_>,
) -> Result<Option<Digest32>, DistributedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(cursor.digest()?)),
        _ => Err(DistributedAgentStackStateError::InvalidPresence),
    }
}

fn encode_evidence_state(
    encoder: &mut Encoder,
    state: &DistributedAgentStackEvidenceStateV2,
) -> Result<(), DistributedAgentStackStateError> {
    match state.binding() {
        Some(binding) => {
            encoder.u8(1);
            encoder.bytes(binding.store_epoch().as_bytes());
            encoder.bytes(binding.owner_ref().as_bytes());
        }
        None => encoder.u8(0),
    }
    encode_evidence_owner_head(encoder, state.owner_head());
    match state.handoff() {
        DistributedAgentStackEvidenceHandoffV2::None => encoder.u8(0),
        DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch) => {
            encoder.u8(1);
            encode_evidence_batch(encoder, batch)?;
        }
        DistributedAgentStackEvidenceHandoffV2::Committed(committed) => {
            encoder.u8(2);
            encode_evidence_batch(encoder, committed.batch())?;
        }
    }
    Ok(())
}

fn decode_evidence_state(
    cursor: &mut Cursor<'_>,
) -> Result<DistributedAgentStackEvidenceStateV2, DistributedAgentStackStateError> {
    let binding = match cursor.u8()? {
        0 => None,
        1 => Some(DistributedAgentStackEvidenceBindingV2::new(
            EvidenceStoreEpochV1::try_from_bytes(cursor.array()?)
                .map_err(|_| DistributedAgentStackStateError::InvalidEvidenceState)?,
            EvidenceOwnerRefV1::try_from_bytes(cursor.array()?)
                .map_err(|_| DistributedAgentStackStateError::InvalidEvidenceState)?,
        )),
        _ => return Err(DistributedAgentStackStateError::InvalidPresence),
    };
    let owner_head = decode_evidence_owner_head(cursor)?;
    let handoff = match cursor.u8()? {
        0 => DistributedAgentStackEvidenceHandoffV2::None,
        1 => DistributedAgentStackEvidenceHandoffV2::CommitIntent(decode_evidence_batch(cursor)?),
        2 => DistributedAgentStackEvidenceHandoffV2::Committed(
            DistributedAgentStackVerifiedEvidenceCommitV2::from_durable_decode(
                decode_evidence_batch(cursor)?,
            ),
        ),
        _ => return Err(DistributedAgentStackStateError::UnknownEnumValue),
    };
    DistributedAgentStackEvidenceStateV2::try_new(binding, owner_head, handoff)
}

fn encode_evidence_owner_head(
    encoder: &mut Encoder,
    head: Option<DistributedAgentStackEvidenceOwnerHeadV2>,
) {
    match head {
        Some(head) => {
            encoder.u8(1);
            encoder.u64(head.producer_sequence());
            encoder.bytes(head.record_id().as_bytes());
            encoder.digest(head.record_digest());
        }
        None => encoder.u8(0),
    }
}

fn decode_evidence_owner_head(
    cursor: &mut Cursor<'_>,
) -> Result<Option<DistributedAgentStackEvidenceOwnerHeadV2>, DistributedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => DistributedAgentStackEvidenceOwnerHeadV2::try_new(
            cursor.u64()?,
            EvidenceRecordIdV1::try_from_bytes(cursor.array()?)
                .map_err(|_| DistributedAgentStackStateError::InvalidEvidenceState)?,
            cursor.digest()?,
        )
        .map(Some),
        _ => Err(DistributedAgentStackStateError::InvalidPresence),
    }
}

fn encode_evidence_batch(
    encoder: &mut Encoder,
    batch: &DistributedAgentStackEvidenceBatchV2,
) -> Result<(), DistributedAgentStackStateError> {
    encoder.digest(batch.request_digest());
    encoder.u64(batch.fabric_generation().value());
    encoder.bytes(batch.session_epoch().as_bytes());
    encode_evidence_owner_head(encoder, batch.base_head());
    encoder.count(batch.records().len())?;
    for record in batch.records() {
        encoder.bounded(record.canonical_wire())?;
    }
    Ok(())
}

fn decode_evidence_batch(
    cursor: &mut Cursor<'_>,
) -> Result<DistributedAgentStackEvidenceBatchV2, DistributedAgentStackStateError> {
    let request_digest = cursor.digest()?;
    let fabric_generation = decode_generation(cursor)?;
    let session_epoch = DistributedFabricSessionEpochV1::try_from_bytes(cursor.array()?)
        .map_err(|_| DistributedAgentStackStateError::InvalidEvidenceState)?;
    let base_head = decode_evidence_owner_head(cursor)?;
    let count = cursor.count(MAX_EVIDENCE_BATCH_RECORDS)?;
    if count == 0 {
        return Err(DistributedAgentStackStateError::InvalidEvidenceState);
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(
            EvidenceRecordV1::decode(cursor.bounded(MAX_EVIDENCE_RECORD_BYTES)?)
                .map_err(|_| DistributedAgentStackStateError::InvalidNestedContract)?,
        );
    }
    DistributedAgentStackEvidenceBatchV2::try_new(
        request_digest,
        fabric_generation,
        session_epoch,
        base_head,
        records,
    )
}

fn decode_generation(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedServiceGeneration, DistributedAgentStackStateError> {
    ManagedServiceGeneration::try_new(cursor.u64()?)
        .map_err(|_| DistributedAgentStackStateError::InvalidState)
}

fn decode_optional_generation(
    cursor: &mut Cursor<'_>,
) -> Result<Option<ManagedServiceGeneration>, DistributedAgentStackStateError> {
    let value = cursor.u64()?;
    if value == 0 {
        Ok(None)
    } else {
        ManagedServiceGeneration::try_new(value)
            .map(Some)
            .map_err(|_| DistributedAgentStackStateError::InvalidState)
    }
}

fn snapshot_checksum(
    wire_version: DistributedAgentStackSnapshotWireVersion,
    header: &[u8],
    payload: &[u8],
) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(match wire_version {
        DistributedAgentStackSnapshotWireVersion::V1 => SNAPSHOT_CHECKSUM_DOMAIN_V1,
        DistributedAgentStackSnapshotWireVersion::V2 => SNAPSHOT_CHECKSUM_DOMAIN_V2,
    });
    hasher.update((header.len() as u64).to_be_bytes());
    hasher.update(header);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    Digest32::from_bytes(hasher.finalize().into())
}

fn digest_is_zero(value: Digest32) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

fn decode_bool(value: u8) -> Result<bool, DistributedAgentStackStateError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DistributedAgentStackStateError::NonCanonicalEncoding),
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn read_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut value = [0_u8; N];
    value.copy_from_slice(&bytes[..N]);
    value
}

struct Encoder(Vec<u8>);

impl Encoder {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    fn digest(&mut self, value: Digest32) {
        self.bytes(value.as_bytes());
    }

    fn count(&mut self, value: usize) -> Result<(), DistributedAgentStackStateError> {
        let value =
            u16::try_from(value).map_err(|_| DistributedAgentStackStateError::FrameTooLarge)?;
        self.0.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn bounded(&mut self, value: &[u8]) -> Result<(), DistributedAgentStackStateError> {
        let length = u32::try_from(value.len())
            .map_err(|_| DistributedAgentStackStateError::FrameTooLarge)?;
        self.0.extend_from_slice(&length.to_be_bytes());
        self.0.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DistributedAgentStackStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DistributedAgentStackStateError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DistributedAgentStackStateError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, DistributedAgentStackStateError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DistributedAgentStackStateError> {
        Ok(read_u16(self.take(2)?))
    }

    fn u32(&mut self) -> Result<u32, DistributedAgentStackStateError> {
        Ok(read_u32(self.take(4)?))
    }

    fn u64(&mut self) -> Result<u64, DistributedAgentStackStateError> {
        Ok(read_u64(self.take(8)?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DistributedAgentStackStateError> {
        Ok(read_array(self.take(N)?))
    }

    fn digest(&mut self) -> Result<Digest32, DistributedAgentStackStateError> {
        Ok(Digest32::from_bytes(self.array()?))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, DistributedAgentStackStateError> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            return Err(DistributedAgentStackStateError::FrameTooLarge);
        }
        Ok(count)
    }

    fn bounded(&mut self, maximum: usize) -> Result<&'a [u8], DistributedAgentStackStateError> {
        let length = self.u32()? as usize;
        if length == 0 || length > maximum {
            return Err(DistributedAgentStackStateError::FrameTooLarge);
        }
        self.take(length)
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DistributedAgentStackStateError {
    Truncated,
    FrameTooLarge,
    UnsupportedFrame,
    InvalidLength,
    ChecksumMismatch,
    IdentityMismatch,
    NonCanonicalEncoding,
    InvalidPresence,
    UnknownEnumValue,
    InvalidNestedContract,
    InvalidState,
    InvalidEvidenceState,
    InvalidVersionTransition,
    SequenceOverflow,
    TrailingBytes,
}

impl fmt::Display for DistributedAgentStackStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "distributed Agent-stack state failed: {self:?}")
    }
}

impl std::error::Error for DistributedAgentStackStateError {}

#[cfg(test)]
mod tests {
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_evidence::{
        EvidencePayloadV1, EvidenceRecordInputV1, EvidenceRetentionPolicyV1, LocalEvidenceStoreV1,
    };
    use paraegox_runtime_contracts::distributed_agent_stack_plan::{
        DistributedAgentStackTerminalAuthClaimV1, DistributedAgentStackTerminalObservationsV1,
        DistributedAgentStackTerminalReceiptDraftV1,
        DistributedFabricObservedTransportProofFieldsV1, DistributedFabricTransportEvidenceRefV1,
        distributed_agent_stack_installed_binding_set_digest_v1,
    };
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

    const FIXTURE: &str = include_str!(
        "../../paraegox-runtime-contracts/tests/fixtures/distributed_agent_stack_v1.hex"
    );
    // The shared PXAR-v8 fixture pins the Runtime store to 0x44. Keep this
    // state-owner test aligned with that canonical request instead of using
    // an unrelated local marker, otherwise strict store validation correctly
    // rejects the would-be "valid" initial snapshot.
    const STORE: [u8; 32] = [0x44; 32];
    const OWNER: Digest32 = Digest32::from_bytes([0x32; 32]);
    const PROJECTION_DIGEST: Digest32 = Digest32::from_bytes([0x33; 32]);
    const PXDA_V1_CANONICAL_SHA256: [u8; 32] = [
        0x1f, 0x15, 0xe6, 0xda, 0x2b, 0xde, 0xcc, 0xad, 0x88, 0x66, 0xf2, 0xbe, 0x32, 0xf7, 0x2f,
        0xbf, 0x2e, 0xf1, 0x7d, 0xb1, 0x4b, 0xc8, 0xe3, 0xb6, 0x57, 0xed, 0x69, 0x72, 0x08, 0xb9,
        0x86, 0x80,
    ];

    static NEXT_EVIDENCE_ROOT: AtomicU64 = AtomicU64::new(1);

    struct EvidenceTestRoot(PathBuf);

    impl EvidenceTestRoot {
        fn new() -> Self {
            let unique = NEXT_EVIDENCE_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "paraegox-pxda-evidence-{}-{unique}",
                std::process::id()
            ));
            let mut builder = DirBuilder::new();
            builder
                .mode(0o700)
                .create(&path)
                .unwrap_or_else(|error| panic!("create PXDA Evidence test root: {error}"));
            Self(path)
        }

        fn store(&self) -> PathBuf {
            self.0.join("store")
        }
    }

    impl Drop for EvidenceTestRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0)
                .unwrap_or_else(|error| panic!("remove PXDA Evidence test root: {error}"));
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("fixture contains non-hex byte"),
            }
        }
        assert_eq!(value.len() % 2, 0, "fixture hex length");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn fixture_hex(key: &str) -> Vec<u8> {
        let prefix = format!("{key}=");
        let value = FIXTURE
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("missing fixture key {key}"));
        decode_hex(value)
    }

    fn projection() -> DistributedAgentStackProjectionV1 {
        DistributedAgentStackProjectionV1::decode(&fixture_hex("projection"))
            .unwrap_or_else(|error| panic!("fixture projection rejected: {error:?}"))
    }

    fn request() -> DistributedAgentStackApplyRequestV1 {
        DistributedAgentStackApplyRequestV1::decode(&fixture_hex("request"))
            .unwrap_or_else(|error| panic!("fixture request rejected: {error:?}"))
    }

    fn transition() -> DistributedAgentStackSnapshotTransition {
        let request = request();
        let channel = ReferenceChannelBindingV1::try_new(
            request.target(),
            PrincipalRef::from_bytes([0x41; 16]),
            Digest32::from_bytes([0x42; 32]),
            Digest32::from_bytes([0x43; 32]),
        )
        .unwrap_or_else(|error| panic!("fixture channel rejected: {error}"));
        DistributedAgentStackSnapshotTransition {
            fabric_generation_high_water: 8,
            agent_generation_high_water: 9,
            phase: DistributedAgentStackDurablePhase::PreparedNoEffects,
            writer_fence: None,
            revision_high_water: None,
            active: None,
            pending: Some(DistributedAgentStackDurablePending {
                kind: DistributedAgentStackPendingKind::ActivateDistributedStack,
                fabric_generation: Some(
                    ManagedServiceGeneration::try_new(8)
                        .unwrap_or_else(|error| panic!("fabric generation rejected: {error}")),
                ),
                agent_generation: Some(
                    ManagedServiceGeneration::try_new(9)
                        .unwrap_or_else(|error| panic!("agent generation rejected: {error}")),
                ),
                admitted_clock_generation: request.temporal().target_clock_generation(),
                admitted_at_nanos: 10,
                deadline_nanos: 20,
                response_channel: channel,
                request,
            }),
            tenure_nonces: Vec::new(),
            request_nonces: Vec::new(),
            temporal_lineages: Vec::new(),
            terminals: Vec::new(),
            physical_binding_census: 0,
            census_complete: true,
            fabric_ready: false,
            agent_ready: false,
            dependency_satisfied: false,
            exact_zero: false,
            quarantined: false,
            installed_binding_set_digest: None,
            raw_outcome_digest: None,
            quarantine_reason: None,
        }
    }

    fn evidence_record(
        id: u8,
        owner: u8,
        producer_sequence: u64,
        previous: Option<u8>,
        peer_index: usize,
    ) -> EvidenceRecordV1 {
        let request = request();
        let topology = request
            .target_execution()
            .topology()
            .unwrap_or_else(|| panic!("fixture request lacks distributed topology"));
        let peer = topology
            .peers()
            .get(peer_index)
            .unwrap_or_else(|| panic!("fixture peer index {peer_index} is absent"));
        let proof = DistributedFabricObservedTransportProofV1::try_new(
            request.target(),
            peer,
            DistributedFabricObservedTransportProofFieldsV1 {
                local_runtime_host: request.target(),
                peer_runtime_host: peer.peer_runtime_host(),
                session_epoch: DistributedFabricSessionEpochV1::try_from_bytes([0x52; 16])
                    .unwrap_or_else(|error| panic!("session epoch rejected: {error:?}")),
                authenticated_peer_identity_ref: peer.authentication().expected_peer_identity_ref(),
                selected_local_credential_ref: peer.authentication().local_credential_ref(),
                transport_evidence_ref: DistributedFabricTransportEvidenceRefV1::try_from_bytes(
                    [id; 16],
                )
                .unwrap_or_else(|error| panic!("transport Evidence ref rejected: {error:?}")),
                observation_sequence: producer_sequence,
            },
        )
        .unwrap_or_else(|error| panic!("transport proof rejected: {error:?}"));
        EvidenceRecordV1::try_new(EvidenceRecordInputV1 {
            record_id: EvidenceRecordIdV1::try_from_bytes([id; 16])
                .unwrap_or_else(|error| panic!("record id rejected: {error}")),
            owner_ref: EvidenceOwnerRefV1::try_from_bytes([owner; 16])
                .unwrap_or_else(|error| panic!("owner ref rejected: {error}")),
            producer_sequence,
            causality_ref: None,
            previous_evidence_ref: previous.map(|value| {
                EvidenceRecordIdV1::try_from_bytes([value; 16])
                    .unwrap_or_else(|error| panic!("previous record id rejected: {error}"))
            }),
            kind: EvidenceKindV1::RuntimeFact,
            payload: EvidencePayloadV1::try_public_safe_inline(proof.canonical_wire())
                .unwrap_or_else(|error| panic!("Evidence payload rejected: {error}")),
        })
        .unwrap_or_else(|error| panic!("Evidence record rejected: {error}"))
    }

    fn evidence_binding(owner: u8) -> DistributedAgentStackEvidenceBindingV2 {
        DistributedAgentStackEvidenceBindingV2::new(
            EvidenceStoreEpochV1::try_from_bytes([0x51; 16])
                .unwrap_or_else(|error| panic!("store epoch rejected: {error}")),
            EvidenceOwnerRefV1::try_from_bytes([owner; 16])
                .unwrap_or_else(|error| panic!("owner ref rejected: {error}")),
        )
    }

    fn evidence_batch(records: Vec<EvidenceRecordV1>) -> DistributedAgentStackEvidenceBatchV2 {
        DistributedAgentStackEvidenceBatchV2::try_new(
            request().envelope_request_digest(),
            ManagedServiceGeneration::try_new(8)
                .unwrap_or_else(|error| panic!("fabric generation rejected: {error}")),
            DistributedFabricSessionEpochV1::try_from_bytes([0x52; 16])
                .unwrap_or_else(|error| panic!("session epoch rejected: {error:?}")),
            None,
            records,
        )
        .unwrap_or_else(|error| panic!("Evidence batch rejected: {error}"))
    }

    fn evidence_commit_material(
        binding: DistributedAgentStackEvidenceBindingV2,
        batch: &DistributedAgentStackEvidenceBatchV2,
    ) -> (Vec<EvidenceCommitReceiptV1>, Vec<EvidenceStoredRecordV1>) {
        let root = EvidenceTestRoot::new();
        let policy = EvidenceRetentionPolicyV1::try_new(64, 1024 * 1024)
            .unwrap_or_else(|error| panic!("Evidence retention policy rejected: {error}"));
        let mut store = LocalEvidenceStoreV1::open(&root.store(), binding.store_epoch(), policy)
            .unwrap_or_else(|error| panic!("open PXDA Evidence test store: {error}"));
        let mut append_receipts = Vec::with_capacity(batch.records().len());
        let mut readback = Vec::with_capacity(batch.records().len());
        for record in batch.records() {
            let receipt = store
                .append(record.clone())
                .unwrap_or_else(|error| panic!("append PXDA Evidence record: {error}"))
                .commit_receipt();
            let stored = store
                .read_ref(receipt.evidence_ref())
                .unwrap_or_else(|error| panic!("read back PXDA Evidence record: {error}"));
            append_receipts.push(receipt);
            readback.push(stored);
        }
        (append_receipts, readback)
    }

    fn verified_committed_state(
        intent: &DistributedAgentStackEvidenceStateV2,
    ) -> DistributedAgentStackEvidenceStateV2 {
        let binding = intent
            .binding()
            .unwrap_or_else(|| panic!("Evidence intent lacks its store binding"));
        let batch = match intent.handoff() {
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch) => batch,
            DistributedAgentStackEvidenceHandoffV2::None
            | DistributedAgentStackEvidenceHandoffV2::Committed(_) => {
                panic!("expected Evidence commit intent")
            }
        };
        let (append_receipts, readback) = evidence_commit_material(binding, batch);
        intent
            .try_mark_committed(&append_receipts, &readback)
            .unwrap_or_else(|error| panic!("mark verified Evidence commit: {error}"))
    }

    fn committed_snapshot_fixture() -> (
        DistributedAgentStackSnapshot,
        DistributedAgentStackSnapshot,
        DistributedAgentStackEvidenceBatchV2,
    ) {
        let v1 = DistributedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            7,
            transition(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("valid PXDA rejected: {error}"));
        let v2 = v1
            .try_upgrade_v1_to_v2_at_epoch(7, &projection())
            .unwrap_or_else(|error| panic!("explicit PXDA v2 upgrade rejected: {error}"));
        let batch = evidence_batch(vec![evidence_record(1, 0x61, 1, None, 0)]);
        let intent_state = DistributedAgentStackEvidenceStateV2::try_new(
            Some(evidence_binding(0x61)),
            None,
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch.clone()),
        )
        .unwrap_or_else(|error| panic!("Evidence intent state rejected: {error}"));
        let mut intent_transition = v2.transition();
        intent_transition.phase = DistributedAgentStackDurablePhase::EvidenceCommitIntent;
        intent_transition.fabric_ready = true;
        intent_transition.dependency_satisfied = true;
        let intent = v2
            .try_v2_successor_at_epoch(7, intent_transition, intent_state, &projection())
            .unwrap_or_else(|error| panic!("Evidence intent successor rejected: {error}"));
        let committed_state = verified_committed_state(intent.evidence_state());
        let mut committed_transition = intent.transition();
        committed_transition.phase = DistributedAgentStackDurablePhase::AgentStartIntent;
        let committed = intent
            .try_v2_successor_at_epoch(7, committed_transition, committed_state, &projection())
            .unwrap_or_else(|error| panic!("Evidence committed successor rejected: {error}"));
        (intent, committed, batch)
    }

    struct SignedActiveReadyTerminalInput<'a> {
        request: &'a DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        proofs: Vec<DistributedFabricObservedTransportProofV1>,
        fabric_generation: ManagedServiceGeneration,
        agent_generation: ManagedServiceGeneration,
        runtime_host_epoch: u64,
        completion_snapshot_sequence: u64,
        installed_binding_set_digest: Digest32,
        raw_outcome_digest: Digest32,
    }

    fn signed_active_ready_terminal(
        input: SignedActiveReadyTerminalInput<'_>,
    ) -> DistributedAgentStackTerminalReceiptV1 {
        let SignedActiveReadyTerminalInput {
            request,
            response_channel,
            proofs,
            fabric_generation,
            agent_generation,
            runtime_host_epoch,
            completion_snapshot_sequence,
            installed_binding_set_digest,
            raw_outcome_digest,
        } = input;
        let observations = DistributedAgentStackTerminalObservationsV1::try_new(request, proofs)
            .unwrap_or_else(|error| panic!("terminal observations rejected: {error}"));
        let facts = DistributedAgentStackTerminalFactsV1::try_new(
            request,
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            DistributedAgentStackTerminalEvidenceFieldsV1 {
                runtime_host_epoch,
                completion_snapshot_sequence,
                selection_clock_generation: request.temporal().target_clock_generation(),
                selection_observed_at_nanos: 21,
                fabric_generation: Some(fabric_generation),
                agent_generation: Some(agent_generation),
                local_bindings: DistributedAgentStackLocalBindingEvidenceFieldsV1 {
                    physical_binding_census: 2,
                    census_complete: true,
                    fabric_ready: true,
                    agent_ready: true,
                    dependency_satisfied: true,
                    exact_zero: false,
                    quarantined: false,
                    installed_binding_set_digest,
                    raw_outcome_digest,
                },
            },
            observations,
        )
        .unwrap_or_else(|error| panic!("terminal facts rejected: {error}"));
        let auth_claim = DistributedAgentStackTerminalAuthClaimV1::try_new(
            response_channel,
            ApplyAuthKeyRef::from_bytes([0x76; 16]),
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("terminal algorithm rejected: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("terminal auth claim rejected: {error}"));
        let draft = DistributedAgentStackTerminalReceiptDraftV1::try_new(
            request,
            facts,
            response_channel,
            auth_claim,
        )
        .unwrap_or_else(|error| panic!("terminal draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&[0x77; 32])
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("terminal transcript rejected: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("terminal signature rejected: {error}"))
    }

    fn active_ready_transition(
        committed: &DistributedAgentStackSnapshot,
        receipt: DistributedAgentStackTerminalReceiptV1,
        installed_binding_set_digest: Digest32,
        raw_outcome_digest: Digest32,
    ) -> DistributedAgentStackSnapshotTransition {
        let pending = committed
            .pending
            .as_ref()
            .unwrap_or_else(|| panic!("committed state lacks pending activation"));
        let mut ready = committed.transition();
        ready.phase = DistributedAgentStackDurablePhase::ActiveReady;
        ready.active = Some(DistributedAgentStackDurableActive {
            fabric_generation: pending
                .fabric_generation
                .unwrap_or_else(|| panic!("pending state lacks fabric generation")),
            agent_generation: pending
                .agent_generation
                .unwrap_or_else(|| panic!("pending state lacks Agent generation")),
            response_channel: pending.response_channel,
            request: pending.request.clone(),
        });
        ready.pending = None;
        ready.terminals.push(DistributedAgentStackTerminalRecord {
            source_scope: pending.request.provenance().source_scope(),
            operation_id: pending.request.operation_id(),
            request_digest: pending.request.envelope_request_digest(),
            receipt,
        });
        ready.terminals.sort_by_key(|terminal| {
            (
                *terminal.source_scope.as_bytes(),
                *terminal.operation_id.as_bytes(),
            )
        });
        ready.physical_binding_census = 2;
        ready.census_complete = true;
        ready.fabric_ready = true;
        ready.agent_ready = true;
        ready.dependency_satisfied = true;
        ready.exact_zero = false;
        ready.quarantined = false;
        ready.installed_binding_set_digest = Some(installed_binding_set_digest);
        ready.raw_outcome_digest = Some(raw_outcome_digest);
        ready.quarantine_reason = None;
        ready
    }

    fn rewrite_lengths_and_checksum(
        frame: &mut [u8],
        wire_version: DistributedAgentStackSnapshotWireVersion,
    ) {
        let total =
            u32::try_from(frame.len()).unwrap_or_else(|_| panic!("fixture frame too large"));
        let payload_length = u32::try_from(frame.len() - SNAPSHOT_HEADER_BYTES)
            .unwrap_or_else(|_| panic!("fixture payload too large"));
        frame[8..12].copy_from_slice(&total.to_be_bytes());
        frame[152..156].copy_from_slice(&payload_length.to_be_bytes());
        let checksum = snapshot_checksum(
            wire_version,
            &frame[..SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES],
            &frame[SNAPSHOT_HEADER_BYTES..],
        );
        frame[160..192].copy_from_slice(checksum.as_bytes());
    }

    #[test]
    fn pxda_v1_roundtrip_restart_decode_and_corruption_are_strict() {
        let snapshot = DistributedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            7,
            transition(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("valid PXDA rejected: {error}"));
        assert_eq!(
            snapshot.wire_version(),
            DistributedAgentStackSnapshotWireVersion::V1
        );
        let decoded = DistributedAgentStackSnapshot::decode(
            snapshot.canonical_wire(),
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            &projection(),
        )
        .unwrap_or_else(|error| panic!("PXDA restart decode rejected: {error}"));
        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.canonical_wire(), snapshot.canonical_wire());
        let canonical_digest: [u8; 32] = Sha256::digest(snapshot.canonical_wire()).into();
        assert_eq!(canonical_digest, PXDA_V1_CANONICAL_SHA256);

        let mut corrupt = snapshot.canonical_wire().to_vec();
        *corrupt
            .last_mut()
            .unwrap_or_else(|| panic!("PXDA must be nonempty")) ^= 1;
        assert_eq!(
            DistributedAgentStackSnapshot::decode(
                &corrupt,
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                &projection(),
            ),
            Err(DistributedAgentStackStateError::ChecksumMismatch)
        );
        assert_eq!(
            DistributedAgentStackSnapshot::decode(
                &snapshot.canonical_wire()[..SNAPSHOT_HEADER_BYTES - 1],
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                &projection(),
            ),
            Err(DistributedAgentStackStateError::Truncated)
        );
    }

    #[test]
    fn pxda_upgrade_is_explicit_once_and_preserves_the_v1_payload_prefix() {
        let initial = DistributedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            7,
            transition(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("valid PXDA rejected: {error}"));
        let v1_successor = initial
            .try_successor_at_epoch(7, initial.transition(), &projection())
            .unwrap_or_else(|error| panic!("PXDA v1 successor rejected: {error}"));
        assert_eq!(
            v1_successor.wire_version(),
            DistributedAgentStackSnapshotWireVersion::V1
        );
        let v1_payload = &v1_successor.canonical_wire()[SNAPSHOT_HEADER_BYTES..];

        let upgraded = v1_successor
            .try_upgrade_v1_to_v2_at_epoch(7, &projection())
            .unwrap_or_else(|error| panic!("explicit PXDA v2 upgrade rejected: {error}"));
        assert_eq!(
            upgraded.wire_version(),
            DistributedAgentStackSnapshotWireVersion::V2
        );
        assert_eq!(upgraded.sequence(), v1_successor.sequence() + 1);
        assert!(upgraded.evidence_state().is_empty());
        assert_eq!(
            &upgraded.canonical_wire()
                [SNAPSHOT_HEADER_BYTES..SNAPSHOT_HEADER_BYTES + v1_payload.len()],
            v1_payload
        );
        let decoded = DistributedAgentStackSnapshot::decode(
            upgraded.canonical_wire(),
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            &projection(),
        )
        .unwrap_or_else(|error| panic!("PXDA v2 restart decode rejected: {error}"));
        assert_eq!(decoded, upgraded);
        assert_eq!(decoded.canonical_wire(), upgraded.canonical_wire());
        assert_eq!(
            upgraded.try_upgrade_v1_to_v2_at_epoch(7, &projection()),
            Err(DistributedAgentStackStateError::InvalidVersionTransition)
        );
    }

    #[test]
    fn pxda_v2_evidence_intent_and_commit_roundtrip_bit_exact() {
        let v1 = DistributedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            7,
            transition(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("valid PXDA rejected: {error}"));
        let v2 = v1
            .try_upgrade_v1_to_v2_at_epoch(7, &projection())
            .unwrap_or_else(|error| panic!("explicit PXDA v2 upgrade rejected: {error}"));
        let binding = evidence_binding(0x61);
        let batch = evidence_batch(vec![evidence_record(1, 0x61, 1, None, 0)]);
        let intent_state = DistributedAgentStackEvidenceStateV2::try_new(
            Some(binding),
            None,
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch.clone()),
        )
        .unwrap_or_else(|error| panic!("Evidence intent state rejected: {error}"));
        let mut intent_transition = v2.transition();
        intent_transition.phase = DistributedAgentStackDurablePhase::EvidenceCommitIntent;
        intent_transition.fabric_ready = true;
        intent_transition.dependency_satisfied = true;
        let intent = v2
            .try_v2_successor_at_epoch(7, intent_transition, intent_state, &projection())
            .unwrap_or_else(|error| panic!("Evidence intent successor rejected: {error}"));
        let decoded_intent = DistributedAgentStackSnapshot::decode(
            intent.canonical_wire(),
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            &projection(),
        )
        .unwrap_or_else(|error| panic!("Evidence intent restart decode rejected: {error}"));
        assert_eq!(decoded_intent, intent);
        assert_eq!(decoded_intent.canonical_wire(), intent.canonical_wire());

        let committed_state = verified_committed_state(intent.evidence_state());
        let mut committed_transition = intent.transition();
        committed_transition.phase = DistributedAgentStackDurablePhase::AgentStartIntent;
        let committed = intent
            .try_v2_successor_at_epoch(7, committed_transition, committed_state, &projection())
            .unwrap_or_else(|error| panic!("Evidence committed successor rejected: {error}"));
        let decoded_committed = DistributedAgentStackSnapshot::decode(
            committed.canonical_wire(),
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            &projection(),
        )
        .unwrap_or_else(|error| panic!("Evidence committed restart decode rejected: {error}"));
        assert_eq!(decoded_committed, committed);
        assert_eq!(
            decoded_committed.canonical_wire(),
            committed.canonical_wire()
        );
        let ordinary_successor = committed
            .try_successor_at_epoch(8, committed.transition(), &projection())
            .unwrap_or_else(|error| panic!("PXDA v2 ordinary successor rejected: {error}"));
        assert_eq!(
            ordinary_successor.wire_version(),
            DistributedAgentStackSnapshotWireVersion::V2
        );

        let committed_head = committed.evidence_state().owner_head();
        let next_batch = DistributedAgentStackEvidenceBatchV2::try_new(
            request().envelope_request_digest(),
            ManagedServiceGeneration::try_new(9)
                .unwrap_or_else(|error| panic!("fabric generation rejected: {error}")),
            DistributedFabricSessionEpochV1::try_from_bytes([0x52; 16])
                .unwrap_or_else(|error| panic!("session epoch rejected: {error:?}")),
            committed_head,
            vec![evidence_record(2, 0x61, 2, Some(1), 0)],
        )
        .unwrap_or_else(|error| panic!("next Evidence batch rejected: {error}"));
        let next_intent_state = DistributedAgentStackEvidenceStateV2::try_new(
            Some(binding),
            committed_head,
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(next_batch),
        )
        .unwrap_or_else(|error| panic!("next Evidence intent state rejected: {error}"));
        let mut illegal_direct_transition = committed.transition();
        illegal_direct_transition.phase = DistributedAgentStackDurablePhase::EvidenceCommitIntent;
        assert_eq!(
            committed.try_v2_successor_at_epoch(
                8,
                illegal_direct_transition,
                next_intent_state.clone(),
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let cleared_state = committed
            .evidence_state()
            .try_clear_committed()
            .unwrap_or_else(|error| panic!("clear verified Evidence handoff: {error}"));
        assert_eq!(
            committed.try_v2_successor_at_epoch(
                8,
                committed.transition(),
                cleared_state.clone(),
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );
        let mut recovery_transition = committed.transition();
        recovery_transition.fabric_generation_high_water = 9;
        recovery_transition.agent_generation_high_water = 10;
        recovery_transition.phase = DistributedAgentStackDurablePhase::RecoveryIntent;
        recovery_transition.fabric_ready = false;
        recovery_transition.dependency_satisfied = false;
        let recovery_pending = recovery_transition
            .pending
            .as_mut()
            .unwrap_or_else(|| panic!("committed state lacks pending activation"));
        recovery_pending.kind = DistributedAgentStackPendingKind::RecoverActive;
        recovery_pending.fabric_generation = Some(
            ManagedServiceGeneration::try_new(9)
                .unwrap_or_else(|error| panic!("recovery fabric generation rejected: {error}")),
        );
        recovery_pending.agent_generation = Some(
            ManagedServiceGeneration::try_new(10)
                .unwrap_or_else(|error| panic!("recovery Agent generation rejected: {error}")),
        );
        let mut stale_recovery = recovery_transition.clone();
        stale_recovery.fabric_generation_high_water = 8;
        stale_recovery.agent_generation_high_water = 9;
        let stale_pending = stale_recovery
            .pending
            .as_mut()
            .unwrap_or_else(|| panic!("stale recovery lacks pending activation"));
        stale_pending.fabric_generation = Some(
            ManagedServiceGeneration::try_new(8)
                .unwrap_or_else(|error| panic!("stale fabric generation rejected: {error}")),
        );
        stale_pending.agent_generation = Some(
            ManagedServiceGeneration::try_new(9)
                .unwrap_or_else(|error| panic!("stale Agent generation rejected: {error}")),
        );
        assert_eq!(
            committed.try_v2_successor_at_epoch(
                8,
                stale_recovery,
                cleared_state.clone(),
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );
        let recovered = committed
            .try_v2_successor_at_epoch(8, recovery_transition, cleared_state, &projection())
            .unwrap_or_else(|error| panic!("atomic Evidence recovery clear rejected: {error}"));
        assert_eq!(recovered.evidence_state().binding(), Some(binding));
        assert_eq!(recovered.evidence_state().owner_head(), committed_head);
        assert!(matches!(
            recovered.evidence_state().handoff(),
            DistributedAgentStackEvidenceHandoffV2::None
        ));
        let mut next_intent_transition = recovered.transition();
        next_intent_transition.phase = DistributedAgentStackDurablePhase::EvidenceCommitIntent;
        next_intent_transition.fabric_ready = true;
        next_intent_transition.dependency_satisfied = true;
        let next_intent = recovered
            .try_v2_successor_at_epoch(8, next_intent_transition, next_intent_state, &projection())
            .unwrap_or_else(|error| panic!("next Evidence intent successor rejected: {error}"));
        assert!(matches!(
            next_intent.evidence_state().handoff(),
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(_)
        ));
    }

    #[test]
    fn pxda_v2_first_ready_is_atomic_current_generation_and_exact_batch_bound() {
        let (intent, committed, batch) = committed_snapshot_fixture();
        let pending = committed
            .pending
            .as_ref()
            .unwrap_or_else(|| panic!("committed state lacks pending activation"));
        let fabric_generation = pending
            .fabric_generation
            .unwrap_or_else(|| panic!("pending state lacks fabric generation"));
        let agent_generation = pending
            .agent_generation
            .unwrap_or_else(|| panic!("pending state lacks Agent generation"));
        let proofs = batch
            .records()
            .iter()
            .map(|record| {
                decode_evidence_transport_proof(record)
                    .unwrap_or_else(|error| panic!("batch PXTP rejected: {error}"))
            })
            .collect::<Vec<_>>();
        let installed_binding_set_digest = distributed_agent_stack_installed_binding_set_digest_v1(
            Digest32::from_bytes([0x72; 32]),
            Digest32::from_bytes([0x73; 32]),
        )
        .unwrap_or_else(|error| panic!("binding-set digest rejected: {error}"));
        let raw_outcome_digest = Digest32::from_bytes([0x74; 32]);
        let receipt = signed_active_ready_terminal(SignedActiveReadyTerminalInput {
            request: &pending.request,
            response_channel: pending.response_channel,
            proofs,
            fabric_generation,
            agent_generation,
            runtime_host_epoch: 8,
            completion_snapshot_sequence: committed.sequence() + 1,
            installed_binding_set_digest,
            raw_outcome_digest,
        });
        let ready_transition = active_ready_transition(
            &committed,
            receipt,
            installed_binding_set_digest,
            raw_outcome_digest,
        );
        let cleared = committed
            .evidence_state()
            .try_clear_committed()
            .unwrap_or_else(|error| panic!("clear verified Evidence handoff: {error}"));
        let ready = committed
            .try_v2_successor_at_epoch(8, ready_transition.clone(), cleared.clone(), &projection())
            .unwrap_or_else(|error| panic!("atomic ActiveReady successor rejected: {error}"));
        assert_eq!(ready.phase, DistributedAgentStackDurablePhase::ActiveReady);
        assert!(ready.pending.is_none());
        assert_eq!(
            ready.evidence_state().binding(),
            committed.evidence_state().binding()
        );
        assert_eq!(
            ready.evidence_state().owner_head(),
            committed.evidence_state().owner_head()
        );
        assert!(matches!(
            ready.evidence_state().handoff(),
            DistributedAgentStackEvidenceHandoffV2::None
        ));

        let mut wrong_generation = ready_transition.clone();
        wrong_generation
            .active
            .as_mut()
            .unwrap_or_else(|| panic!("Ready transition lacks active state"))
            .agent_generation = ManagedServiceGeneration::try_new(8)
            .unwrap_or_else(|error| panic!("wrong Agent generation rejected early: {error}"));
        assert_eq!(
            committed.try_v2_successor_at_epoch(
                8,
                wrong_generation,
                cleared.clone(),
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidState)
        );

        let wrong_proof = decode_evidence_transport_proof(&evidence_record(2, 0x61, 1, None, 0))
            .unwrap_or_else(|error| panic!("alternate PXTP rejected: {error}"));
        let wrong_proof_receipt = signed_active_ready_terminal(SignedActiveReadyTerminalInput {
            request: &pending.request,
            response_channel: pending.response_channel,
            proofs: vec![wrong_proof],
            fabric_generation,
            agent_generation,
            runtime_host_epoch: 8,
            completion_snapshot_sequence: committed.sequence() + 1,
            installed_binding_set_digest,
            raw_outcome_digest,
        });
        let wrong_proof_transition = active_ready_transition(
            &committed,
            wrong_proof_receipt,
            installed_binding_set_digest,
            raw_outcome_digest,
        );
        assert_eq!(
            committed.try_v2_successor_at_epoch(
                8,
                wrong_proof_transition,
                cleared.clone(),
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let mut wrong_binding_digest = ready_transition.clone();
        wrong_binding_digest.installed_binding_set_digest = Some(Digest32::from_bytes([0x75; 32]));
        assert_eq!(
            committed.try_v2_successor_at_epoch(8, wrong_binding_digest, cleared, &projection(),),
            Err(DistributedAgentStackStateError::InvalidState)
        );

        let mut phase_eleven_direct_ready = ready_transition;
        phase_eleven_direct_ready.terminals[0].receipt =
            signed_active_ready_terminal(SignedActiveReadyTerminalInput {
                request: &pending.request,
                response_channel: pending.response_channel,
                proofs: batch
                    .records()
                    .iter()
                    .map(|record| {
                        decode_evidence_transport_proof(record)
                            .unwrap_or_else(|error| panic!("batch PXTP rejected: {error}"))
                    })
                    .collect(),
                fabric_generation,
                agent_generation,
                runtime_host_epoch: 7,
                completion_snapshot_sequence: intent.sequence() + 1,
                installed_binding_set_digest,
                raw_outcome_digest,
            });
        assert_eq!(
            intent.try_v2_successor_at_epoch(
                7,
                phase_eleven_direct_ready,
                intent.evidence_state().clone(),
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let bare_v1 = DistributedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            7,
            transition(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("bare PXDA v1 rejected: {error}"));
        let bare_v2 = bare_v1
            .try_upgrade_v1_to_v2_at_epoch(7, &projection())
            .unwrap_or_else(|error| panic!("bare PXDA v2 upgrade rejected: {error}"));
        let bare_pending = bare_v2
            .pending
            .as_ref()
            .unwrap_or_else(|| panic!("bare PXDA v2 lacks pending activation"));
        let bare_receipt = signed_active_ready_terminal(SignedActiveReadyTerminalInput {
            request: &bare_pending.request,
            response_channel: bare_pending.response_channel,
            proofs: batch
                .records()
                .iter()
                .map(|record| {
                    decode_evidence_transport_proof(record)
                        .unwrap_or_else(|error| panic!("batch PXTP rejected: {error}"))
                })
                .collect(),
            fabric_generation,
            agent_generation,
            runtime_host_epoch: 7,
            completion_snapshot_sequence: bare_v2.sequence() + 1,
            installed_binding_set_digest,
            raw_outcome_digest,
        });
        let bare_ready = active_ready_transition(
            &bare_v2,
            bare_receipt,
            installed_binding_set_digest,
            raw_outcome_digest,
        );
        assert_eq!(
            bare_v2.try_v2_successor_at_epoch(
                7,
                bare_ready,
                bare_v2.evidence_state().clone(),
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );
    }

    #[test]
    fn pxda_v2_historical_ready_is_byte_exact_but_fresh_generations_advance() {
        let (_, committed, batch) = committed_snapshot_fixture();
        let pending = committed
            .pending
            .as_ref()
            .unwrap_or_else(|| panic!("committed state lacks pending activation"));
        let historical_installed = distributed_agent_stack_installed_binding_set_digest_v1(
            Digest32::from_bytes([0x81; 32]),
            Digest32::from_bytes([0x82; 32]),
        )
        .unwrap_or_else(|error| panic!("historical binding-set digest rejected: {error}"));
        let historical_receipt = signed_active_ready_terminal(SignedActiveReadyTerminalInput {
            request: &pending.request,
            response_channel: pending.response_channel,
            proofs: vec![
                decode_evidence_transport_proof(&evidence_record(2, 0x61, 1, None, 0))
                    .unwrap_or_else(|error| panic!("historical PXTP rejected: {error}")),
            ],
            fabric_generation: ManagedServiceGeneration::try_new(7)
                .unwrap_or_else(|error| panic!("historical fabric generation rejected: {error}")),
            agent_generation: ManagedServiceGeneration::try_new(8)
                .unwrap_or_else(|error| panic!("historical Agent generation rejected: {error}")),
            runtime_host_epoch: 7,
            completion_snapshot_sequence: 1,
            installed_binding_set_digest: historical_installed,
            raw_outcome_digest: Digest32::from_bytes([0x83; 32]),
        });
        let mut historical_transition = committed.transition();
        historical_transition
            .terminals
            .push(DistributedAgentStackTerminalRecord {
                source_scope: pending.request.provenance().source_scope(),
                operation_id: pending.request.operation_id(),
                request_digest: pending.request.envelope_request_digest(),
                receipt: historical_receipt.clone(),
            });
        let historical_committed = DistributedAgentStackSnapshot::try_build(
            DistributedAgentStackSnapshotWireVersion::V2,
            SnapshotIdentity {
                store_instance_id: STORE,
                owner_target_fingerprint: OWNER,
                transition_projection_digest: PROJECTION_DIGEST,
            },
            committed.sequence(),
            7,
            historical_transition,
            committed.evidence_state().clone(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("historical committed fixture rejected: {error}"));
        let current_installed = distributed_agent_stack_installed_binding_set_digest_v1(
            Digest32::from_bytes([0x84; 32]),
            Digest32::from_bytes([0x85; 32]),
        )
        .unwrap_or_else(|error| panic!("current binding-set digest rejected: {error}"));
        let current_raw = Digest32::from_bytes([0x86; 32]);
        let mut ready_transition = active_ready_transition(
            &historical_committed,
            historical_receipt.clone(),
            current_installed,
            current_raw,
        );
        ready_transition.terminals = historical_committed.terminals.clone();
        let cleared = historical_committed
            .evidence_state()
            .try_clear_committed()
            .unwrap_or_else(|error| panic!("clear verified Evidence handoff: {error}"));
        let ready = historical_committed
            .try_v2_successor_at_epoch(8, ready_transition.clone(), cleared.clone(), &projection())
            .unwrap_or_else(|error| panic!("historical ActiveReady successor rejected: {error}"));
        assert_eq!(
            ready.terminals[0].receipt.canonical_wire(),
            historical_receipt.canonical_wire()
        );
        assert_eq!(
            ready
                .active
                .as_ref()
                .unwrap_or_else(|| panic!("Ready state lacks active generations"))
                .fabric_generation,
            batch.fabric_generation()
        );

        let mut mutated_ready = ready.transition();
        mutated_ready.raw_outcome_digest = Some(Digest32::from_bytes([0x87; 32]));
        assert_eq!(
            ready.try_v2_successor_at_epoch(
                9,
                mutated_ready,
                ready.evidence_state().clone(),
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let mut non_fresh = ready_transition;
        non_fresh
            .active
            .as_mut()
            .unwrap_or_else(|| panic!("Ready transition lacks active state"))
            .fabric_generation = ManagedServiceGeneration::try_new(7)
            .unwrap_or_else(|error| panic!("non-fresh fabric generation rejected early: {error}"));
        non_fresh.fabric_generation_high_water = 7;
        assert!(
            historical_committed
                .try_v2_successor_at_epoch(8, non_fresh, cleared, &projection())
                .is_err()
        );
    }

    #[test]
    fn pxda_v2_committed_shape_rejects_stale_generation_request_and_phase() {
        let v1 = DistributedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            7,
            transition(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("valid PXDA rejected: {error}"));
        let v2 = v1
            .try_upgrade_v1_to_v2_at_epoch(7, &projection())
            .unwrap_or_else(|error| panic!("explicit PXDA v2 upgrade rejected: {error}"));
        let binding = evidence_binding(0x61);
        let batch = evidence_batch(vec![evidence_record(1, 0x61, 1, None, 0)]);
        let intent_state = DistributedAgentStackEvidenceStateV2::try_new(
            Some(binding),
            None,
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch.clone()),
        )
        .unwrap_or_else(|error| panic!("Evidence intent state rejected: {error}"));
        let mut intent_transition = v2.transition();
        intent_transition.phase = DistributedAgentStackDurablePhase::EvidenceCommitIntent;
        intent_transition.fabric_ready = true;
        intent_transition.dependency_satisfied = true;
        let intent = v2
            .try_v2_successor_at_epoch(7, intent_transition, intent_state, &projection())
            .unwrap_or_else(|error| panic!("Evidence intent successor rejected: {error}"));
        let committed_state = verified_committed_state(intent.evidence_state());

        let mut stale_generation = intent.transition();
        stale_generation.phase = DistributedAgentStackDurablePhase::AgentStartIntent;
        stale_generation
            .pending
            .as_mut()
            .unwrap_or_else(|| panic!("Evidence intent lacks pending request"))
            .fabric_generation = Some(
            ManagedServiceGeneration::try_new(7)
                .unwrap_or_else(|error| panic!("stale generation rejected early: {error}")),
        );
        assert_eq!(
            intent.try_v2_successor_at_epoch(
                7,
                stale_generation,
                committed_state.clone(),
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let mut rolled_back_phase = intent.transition();
        rolled_back_phase.phase = DistributedAgentStackDurablePhase::PreparedNoEffects;
        rolled_back_phase.fabric_ready = false;
        rolled_back_phase.dependency_satisfied = false;
        assert_eq!(
            intent.try_v2_successor_at_epoch(7, rolled_back_phase, committed_state, &projection(),),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let wrong_request_batch = DistributedAgentStackEvidenceBatchV2::try_new(
            Digest32::from_bytes([0x99; 32]),
            ManagedServiceGeneration::try_new(8)
                .unwrap_or_else(|error| panic!("fabric generation rejected: {error}")),
            DistributedFabricSessionEpochV1::try_from_bytes([0x52; 16])
                .unwrap_or_else(|error| panic!("session epoch rejected: {error:?}")),
            None,
            vec![evidence_record(1, 0x61, 1, None, 0)],
        )
        .unwrap_or_else(|error| panic!("wrong-request Evidence batch rejected early: {error}"));
        let wrong_request_intent = DistributedAgentStackEvidenceStateV2::try_new(
            Some(binding),
            None,
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(wrong_request_batch),
        )
        .unwrap_or_else(|error| panic!("wrong-request intent rejected early: {error}"));
        let wrong_request_committed = verified_committed_state(&wrong_request_intent);
        let mut agent_start = transition();
        agent_start.phase = DistributedAgentStackDurablePhase::AgentStartIntent;
        agent_start.fabric_ready = true;
        agent_start.dependency_satisfied = true;
        assert_eq!(
            DistributedAgentStackSnapshot::try_build(
                DistributedAgentStackSnapshotWireVersion::V2,
                SnapshotIdentity {
                    store_instance_id: STORE,
                    owner_target_fingerprint: OWNER,
                    transition_projection_digest: PROJECTION_DIGEST,
                },
                2,
                7,
                agent_start,
                wrong_request_committed,
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let (append_receipts, readback) = evidence_commit_material(binding, &batch);
        let wrong_store_binding = DistributedAgentStackEvidenceBindingV2::new(
            EvidenceStoreEpochV1::try_from_bytes([0x53; 16])
                .unwrap_or_else(|error| panic!("wrong store epoch rejected early: {error}")),
            binding.owner_ref(),
        );
        assert_eq!(
            DistributedAgentStackVerifiedEvidenceCommitV2::try_new(
                wrong_store_binding,
                batch,
                &append_receipts,
                &readback,
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );
    }

    #[test]
    fn pxda_versions_tamper_and_illegal_evidence_shapes_fail_closed() {
        let v1 = DistributedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            7,
            transition(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("valid PXDA rejected: {error}"));

        let mut v1_with_evidence_suffix = v1.canonical_wire().to_vec();
        v1_with_evidence_suffix.extend_from_slice(&[0, 0, 0]);
        rewrite_lengths_and_checksum(
            &mut v1_with_evidence_suffix,
            DistributedAgentStackSnapshotWireVersion::V1,
        );
        assert_eq!(
            DistributedAgentStackSnapshot::decode(
                &v1_with_evidence_suffix,
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                &projection(),
            ),
            Err(DistributedAgentStackStateError::TrailingBytes)
        );

        let mut v1_phase_eleven = v1.canonical_wire().to_vec();
        v1_phase_eleven[132] = DistributedAgentStackDurablePhase::EvidenceCommitIntent as u8;
        rewrite_lengths_and_checksum(
            &mut v1_phase_eleven,
            DistributedAgentStackSnapshotWireVersion::V1,
        );
        assert_eq!(
            DistributedAgentStackSnapshot::decode(
                &v1_phase_eleven,
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                &projection(),
            ),
            Err(DistributedAgentStackStateError::UnknownEnumValue)
        );

        assert_eq!(
            DistributedAgentStackEvidenceBatchV2::try_new(
                request().envelope_request_digest(),
                ManagedServiceGeneration::try_new(8)
                    .unwrap_or_else(|error| panic!("fabric generation rejected: {error}")),
                DistributedFabricSessionEpochV1::try_from_bytes([0x52; 16])
                    .unwrap_or_else(|error| panic!("session epoch rejected: {error:?}")),
                None,
                vec![
                    evidence_record(1, 0x61, 1, None, 0),
                    evidence_record(2, 0x61, 3, Some(1), 0),
                ],
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        assert_eq!(
            DistributedAgentStackEvidenceBatchV2::try_new(
                request().envelope_request_digest(),
                ManagedServiceGeneration::try_new(8)
                    .unwrap_or_else(|error| panic!("fabric generation rejected: {error}")),
                DistributedFabricSessionEpochV1::try_from_bytes([0x52; 16])
                    .unwrap_or_else(|error| panic!("session epoch rejected: {error:?}")),
                None,
                vec![
                    evidence_record(1, 0x61, 1, None, 0),
                    evidence_record(2, 0x61, 2, Some(1), 0),
                    evidence_record(1, 0x61, 3, Some(2), 0),
                ],
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        assert_eq!(
            DistributedAgentStackEvidenceBatchV2::try_new(
                request().envelope_request_digest(),
                ManagedServiceGeneration::try_new(8)
                    .unwrap_or_else(|error| panic!("fabric generation rejected: {error}")),
                DistributedFabricSessionEpochV1::try_from_bytes([0x53; 16])
                    .unwrap_or_else(|error| panic!("session epoch rejected: {error:?}")),
                None,
                vec![evidence_record(1, 0x61, 1, None, 0)],
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let arbitrary_record = EvidenceRecordV1::try_new(EvidenceRecordInputV1 {
            record_id: EvidenceRecordIdV1::try_from_bytes([0x71; 16])
                .unwrap_or_else(|error| panic!("record id rejected: {error}")),
            owner_ref: EvidenceOwnerRefV1::try_from_bytes([0x61; 16])
                .unwrap_or_else(|error| panic!("owner ref rejected: {error}")),
            producer_sequence: 1,
            causality_ref: None,
            previous_evidence_ref: None,
            kind: EvidenceKindV1::SecurityAudit,
            payload: EvidencePayloadV1::try_digest_only(Digest32::from_bytes([0x72; 32]))
                .unwrap_or_else(|error| panic!("Evidence payload rejected: {error}")),
        })
        .unwrap_or_else(|error| panic!("arbitrary Evidence record rejected: {error}"));
        assert_eq!(
            DistributedAgentStackEvidenceBatchV2::try_new(
                request().envelope_request_digest(),
                ManagedServiceGeneration::try_new(8)
                    .unwrap_or_else(|error| panic!("fabric generation rejected: {error}")),
                DistributedFabricSessionEpochV1::try_from_bytes([0x52; 16])
                    .unwrap_or_else(|error| panic!("session epoch rejected: {error:?}")),
                None,
                vec![arbitrary_record],
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let v2 = v1
            .try_upgrade_v1_to_v2_at_epoch(7, &projection())
            .unwrap_or_else(|error| panic!("explicit PXDA v2 upgrade rejected: {error}"));
        let mut invalid_intent_transition = v2.transition();
        invalid_intent_transition.phase = DistributedAgentStackDurablePhase::EvidenceCommitIntent;
        invalid_intent_transition.fabric_ready = true;
        invalid_intent_transition.dependency_satisfied = true;
        assert_eq!(
            v2.try_v2_successor_at_epoch(
                7,
                invalid_intent_transition,
                DistributedAgentStackEvidenceStateV2::empty(),
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        assert_eq!(
            request()
                .target_execution()
                .topology()
                .unwrap_or_else(|| panic!("fixture request lacks distributed topology"))
                .peers()
                .len(),
            1
        );
        let oversized_for_topology = evidence_batch(vec![
            evidence_record(1, 0x61, 1, None, 0),
            evidence_record(2, 0x61, 2, Some(1), 0),
        ]);
        let oversized_state = DistributedAgentStackEvidenceStateV2::try_new(
            Some(evidence_binding(0x61)),
            None,
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(oversized_for_topology),
        )
        .unwrap_or_else(|error| panic!("oversized topology state shape rejected early: {error}"));
        let mut oversized_transition = v2.transition();
        oversized_transition.phase = DistributedAgentStackDurablePhase::EvidenceCommitIntent;
        oversized_transition.fabric_ready = true;
        oversized_transition.dependency_satisfied = true;
        assert_eq!(
            v2.try_v2_successor_at_epoch(7, oversized_transition, oversized_state, &projection(),),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let batch = evidence_batch(vec![evidence_record(1, 0x61, 1, None, 0)]);
        assert_eq!(
            DistributedAgentStackEvidenceStateV2::try_new(
                Some(evidence_binding(0x62)),
                None,
                DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch),
            ),
            Err(DistributedAgentStackStateError::InvalidEvidenceState)
        );

        let mut wrong_checksum_domain = v2.canonical_wire().to_vec();
        let v1_domain_checksum = snapshot_checksum(
            DistributedAgentStackSnapshotWireVersion::V1,
            &wrong_checksum_domain[..SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES],
            &wrong_checksum_domain[SNAPSHOT_HEADER_BYTES..],
        );
        wrong_checksum_domain[160..192].copy_from_slice(v1_domain_checksum.as_bytes());
        assert_eq!(
            DistributedAgentStackSnapshot::decode(
                &wrong_checksum_domain,
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                &projection(),
            ),
            Err(DistributedAgentStackStateError::ChecksumMismatch)
        );

        let mut v2_tamper = v2.canonical_wire().to_vec();
        *v2_tamper
            .last_mut()
            .unwrap_or_else(|| panic!("PXDA v2 must be nonempty")) ^= 1;
        assert_eq!(
            DistributedAgentStackSnapshot::decode(
                &v2_tamper,
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                &projection(),
            ),
            Err(DistributedAgentStackStateError::ChecksumMismatch)
        );
    }

    #[test]
    fn pxda_phase_shape_generation_and_epoch_regression_fail_closed() {
        let snapshot = DistributedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            7,
            transition(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("valid PXDA rejected: {error}"));
        assert_eq!(
            snapshot.try_successor_at_epoch(6, snapshot.transition(), &projection()),
            Err(DistributedAgentStackStateError::InvalidState)
        );

        let mut bad_generation = transition();
        bad_generation.fabric_generation_high_water = 7;
        assert_eq!(
            DistributedAgentStackSnapshot::try_initial(
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                7,
                bad_generation,
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidState)
        );

        let mut false_ready = transition();
        false_ready.phase = DistributedAgentStackDurablePhase::ActiveReady;
        false_ready.fabric_ready = true;
        false_ready.agent_ready = true;
        false_ready.dependency_satisfied = true;
        false_ready.physical_binding_census = 2;
        assert_eq!(
            DistributedAgentStackSnapshot::try_initial(
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                7,
                false_ready,
                &projection(),
            ),
            Err(DistributedAgentStackStateError::InvalidState)
        );
    }
}
