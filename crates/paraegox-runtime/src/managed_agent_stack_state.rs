#![cfg(unix)]

//! Independent PXAR-v7 durable stack state.
//!
//! This codec is intentionally neither a payload-v5 journal variant nor a
//! mutation of the PXMS-v1 managed-Fabric snapshot. Every retained PXAR-v7 and
//! PXST-v1 frame is strictly decoded again during recovery.

use core::fmt;

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::ClockGeneration;
use paraegox_runtime_contracts::apply::{ApplyOperationId, PlanWriterRef};
use paraegox_runtime_contracts::managed_agent_stack_plan::{
    MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES, MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES,
    ManagedAgentStackApplyRequestV1, ManagedAgentStackProjectionV1, ManagedAgentStackTargetModeV1,
    ManagedAgentStackTerminalReceiptV1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
use paraegox_runtime_contracts::provenance::{SourcePlanDigest, SourceScopeRef};
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
use sha2::{Digest as ShaDigest, Sha256};

const SNAPSHOT_MAGIC: &[u8; 4] = b"PXAS";
const SNAPSHOT_VERSION: u16 = 1;
const SNAPSHOT_HEADER_BYTES: usize = 192;
const SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES: usize = 160;
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"paraegox.runtime.managed-agent-stack-snapshot.sha256.v1";
const MAX_TERMINALS: usize = 256;
const MAX_REPLAY_ENTRIES: usize = 256;
pub(crate) const MAX_MANAGED_AGENT_STACK_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ManagedAgentStackDurablePhase {
    ExactZero = 1,
    AgentStartIntent = 2,
    ActiveReady = 3,
    AgentRetireIntent = 4,
    FabricStopIntent = 5,
    RecoveryIntent = 6,
    Uncertain = 7,
    Quarantined = 8,
}

impl ManagedAgentStackDurablePhase {
    fn decode(value: u8) -> Result<Self, ManagedAgentStackStateError> {
        match value {
            1 => Ok(Self::ExactZero),
            2 => Ok(Self::AgentStartIntent),
            3 => Ok(Self::ActiveReady),
            4 => Ok(Self::AgentRetireIntent),
            5 => Ok(Self::FabricStopIntent),
            6 => Ok(Self::RecoveryIntent),
            7 => Ok(Self::Uncertain),
            8 => Ok(Self::Quarantined),
            _ => Err(ManagedAgentStackStateError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ManagedAgentStackPendingKind {
    ActivateAgent = 1,
    DeactivateStack = 2,
    RecoverActive = 3,
}

impl ManagedAgentStackPendingKind {
    fn decode(value: u8) -> Result<Self, ManagedAgentStackStateError> {
        match value {
            1 => Ok(Self::ActivateAgent),
            2 => Ok(Self::DeactivateStack),
            3 => Ok(Self::RecoverActive),
            _ => Err(ManagedAgentStackStateError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackWriterFence {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) writer: PlanWriterRef,
    pub(crate) principal: PrincipalRef,
    pub(crate) epoch: u64,
    pub(crate) proof_envelope_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackRevisionHighWater {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) revision: u64,
    pub(crate) source_plan_digest: SourcePlanDigest,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ManagedAgentStackReplayRecord {
    pub(crate) identity: Digest32,
    pub(crate) value_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackDurableActive {
    pub(crate) fabric_generation: ManagedServiceGeneration,
    pub(crate) agent_generation: ManagedServiceGeneration,
    pub(crate) response_channel: ReferenceChannelBindingV1,
    pub(crate) request: ManagedAgentStackApplyRequestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackDurablePending {
    pub(crate) kind: ManagedAgentStackPendingKind,
    pub(crate) fabric_generation: Option<ManagedServiceGeneration>,
    pub(crate) agent_generation: Option<ManagedServiceGeneration>,
    pub(crate) admitted_clock_generation: ClockGeneration,
    pub(crate) admitted_at_nanos: u64,
    pub(crate) deadline_nanos: u64,
    pub(crate) response_channel: ReferenceChannelBindingV1,
    pub(crate) request: ManagedAgentStackApplyRequestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackTerminalRecord {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) operation_id: ApplyOperationId,
    pub(crate) request_digest: Digest32,
    pub(crate) receipt: ManagedAgentStackTerminalReceiptV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackSnapshotTransition {
    pub(crate) fabric_generation_high_water: u64,
    pub(crate) agent_generation_high_water: u64,
    pub(crate) phase: ManagedAgentStackDurablePhase,
    pub(crate) writer_fence: Option<ManagedAgentStackWriterFence>,
    pub(crate) revision_high_water: Option<ManagedAgentStackRevisionHighWater>,
    pub(crate) active: Option<ManagedAgentStackDurableActive>,
    pub(crate) pending: Option<ManagedAgentStackDurablePending>,
    pub(crate) tenure_nonces: Vec<ManagedAgentStackReplayRecord>,
    pub(crate) request_nonces: Vec<ManagedAgentStackReplayRecord>,
    pub(crate) temporal_lineages: Vec<ManagedAgentStackReplayRecord>,
    pub(crate) terminals: Vec<ManagedAgentStackTerminalRecord>,
    pub(crate) physical_binding_census: u16,
    pub(crate) census_complete: bool,
    pub(crate) fabric_ready: bool,
    pub(crate) agent_ready: bool,
    pub(crate) dependency_satisfied: bool,
    pub(crate) quarantine_reason: Option<Digest32>,
}

#[derive(Clone, Copy)]
struct SnapshotIdentity {
    store_instance_id: [u8; 32],
    owner_target_fingerprint: Digest32,
    transition_projection_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackSnapshot {
    store_instance_id: [u8; 32],
    owner_target_fingerprint: Digest32,
    transition_projection_digest: Digest32,
    sequence: u64,
    runtime_host_epoch: u64,
    pub(crate) fabric_generation_high_water: u64,
    pub(crate) agent_generation_high_water: u64,
    pub(crate) phase: ManagedAgentStackDurablePhase,
    pub(crate) writer_fence: Option<ManagedAgentStackWriterFence>,
    pub(crate) revision_high_water: Option<ManagedAgentStackRevisionHighWater>,
    pub(crate) active: Option<ManagedAgentStackDurableActive>,
    pub(crate) pending: Option<ManagedAgentStackDurablePending>,
    pub(crate) tenure_nonces: Vec<ManagedAgentStackReplayRecord>,
    pub(crate) request_nonces: Vec<ManagedAgentStackReplayRecord>,
    pub(crate) temporal_lineages: Vec<ManagedAgentStackReplayRecord>,
    pub(crate) terminals: Vec<ManagedAgentStackTerminalRecord>,
    pub(crate) physical_binding_census: u16,
    pub(crate) census_complete: bool,
    pub(crate) fabric_ready: bool,
    pub(crate) agent_ready: bool,
    pub(crate) dependency_satisfied: bool,
    pub(crate) quarantine_reason: Option<Digest32>,
    canonical_wire: Box<[u8]>,
}

impl ManagedAgentStackSnapshot {
    pub(crate) fn try_initial(
        store_instance_id: [u8; 32],
        owner_target_fingerprint: Digest32,
        transition_projection_digest: Digest32,
        runtime_host_epoch: u64,
        transition: ManagedAgentStackSnapshotTransition,
        projection: &ManagedAgentStackProjectionV1,
    ) -> Result<Self, ManagedAgentStackStateError> {
        Self::try_build(
            SnapshotIdentity {
                store_instance_id,
                owner_target_fingerprint,
                transition_projection_digest,
            },
            1,
            runtime_host_epoch,
            transition,
            projection,
        )
    }

    pub(crate) fn try_successor(
        &self,
        transition: ManagedAgentStackSnapshotTransition,
        projection: &ManagedAgentStackProjectionV1,
    ) -> Result<Self, ManagedAgentStackStateError> {
        self.try_successor_at_epoch(self.runtime_host_epoch, transition, projection)
    }

    pub(crate) fn try_successor_at_epoch(
        &self,
        runtime_host_epoch: u64,
        transition: ManagedAgentStackSnapshotTransition,
        projection: &ManagedAgentStackProjectionV1,
    ) -> Result<Self, ManagedAgentStackStateError> {
        if runtime_host_epoch < self.runtime_host_epoch {
            return Err(ManagedAgentStackStateError::InvalidState);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ManagedAgentStackStateError::SequenceOverflow)?;
        Self::try_build(
            SnapshotIdentity {
                store_instance_id: self.store_instance_id,
                owner_target_fingerprint: self.owner_target_fingerprint,
                transition_projection_digest: self.transition_projection_digest,
            },
            sequence,
            runtime_host_epoch,
            transition,
            projection,
        )
    }

    fn try_build(
        identity: SnapshotIdentity,
        sequence: u64,
        runtime_host_epoch: u64,
        transition: ManagedAgentStackSnapshotTransition,
        projection: &ManagedAgentStackProjectionV1,
    ) -> Result<Self, ManagedAgentStackStateError> {
        let mut snapshot = Self {
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
            quarantine_reason: transition.quarantine_reason,
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
        projection: &ManagedAgentStackProjectionV1,
    ) -> Result<Self, ManagedAgentStackStateError> {
        if frame.len() < SNAPSHOT_HEADER_BYTES {
            return Err(ManagedAgentStackStateError::Truncated);
        }
        if frame.len() > MAX_MANAGED_AGENT_STACK_SNAPSHOT_BYTES {
            return Err(ManagedAgentStackStateError::FrameTooLarge);
        }
        if &frame[..4] != SNAPSHOT_MAGIC
            || read_u16(&frame[4..6]) != SNAPSHOT_VERSION
            || usize::from(read_u16(&frame[6..8])) != SNAPSHOT_HEADER_BYTES
        {
            return Err(ManagedAgentStackStateError::UnsupportedFrame);
        }
        let total = read_u32(&frame[8..12]) as usize;
        let payload_length = read_u32(&frame[152..156]) as usize;
        if total != frame.len()
            || SNAPSHOT_HEADER_BYTES.checked_add(payload_length) != Some(frame.len())
            || frame[139..152].iter().any(|byte| *byte != 0)
            || frame[156..160].iter().any(|byte| *byte != 0)
        {
            return Err(ManagedAgentStackStateError::InvalidLength);
        }
        let expected_checksum = snapshot_checksum(
            &frame[..SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES],
            &frame[SNAPSHOT_HEADER_BYTES..],
        );
        if frame[160..192] != *expected_checksum.as_bytes() {
            return Err(ManagedAgentStackStateError::ChecksumMismatch);
        }
        let store_instance_id = read_array(&frame[20..52]);
        let owner_target_fingerprint = Digest32::from_bytes(read_array(&frame[52..84]));
        let transition_projection_digest = Digest32::from_bytes(read_array(&frame[84..116]));
        if store_instance_id != expected_store_instance_id
            || owner_target_fingerprint != expected_owner_target_fingerprint
            || transition_projection_digest != expected_transition_projection_digest
        {
            return Err(ManagedAgentStackStateError::IdentityMismatch);
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
        let quarantine_reason = decode_optional_digest(&mut cursor)?;
        if !cursor.done() {
            return Err(ManagedAgentStackStateError::TrailingBytes);
        }
        let snapshot = Self::try_build(
            SnapshotIdentity {
                store_instance_id,
                owner_target_fingerprint,
                transition_projection_digest,
            },
            read_u64(&frame[12..20]),
            runtime_host_epoch,
            ManagedAgentStackSnapshotTransition {
                fabric_generation_high_water: read_u64(&frame[116..124]),
                agent_generation_high_water: read_u64(&frame[124..132]),
                phase: ManagedAgentStackDurablePhase::decode(frame[132])?,
                physical_binding_census: read_u16(&frame[133..135]),
                census_complete: decode_bool(frame[135])?,
                fabric_ready: decode_bool(frame[136])?,
                agent_ready: decode_bool(frame[137])?,
                dependency_satisfied: decode_bool(frame[138])?,
                writer_fence,
                revision_high_water,
                active,
                pending,
                tenure_nonces,
                request_nonces,
                temporal_lineages,
                terminals,
                quarantine_reason,
            },
            projection,
        )?;
        if snapshot.canonical_wire() != frame {
            return Err(ManagedAgentStackStateError::NonCanonicalEncoding);
        }
        Ok(snapshot)
    }

    fn validate(
        &self,
        projection: &ManagedAgentStackProjectionV1,
    ) -> Result<(), ManagedAgentStackStateError> {
        if self.store_instance_id.iter().all(|byte| *byte == 0)
            || digest_is_zero(self.owner_target_fingerprint)
            || digest_is_zero(self.transition_projection_digest)
            || self.sequence == 0
            || self.runtime_host_epoch == 0
            || self.physical_binding_census > 2
            || self.tenure_nonces.len() > MAX_REPLAY_ENTRIES
            || self.request_nonces.len() > MAX_REPLAY_ENTRIES
            || self.temporal_lineages.len() > MAX_REPLAY_ENTRIES
            || self.terminals.len() > MAX_TERMINALS
        {
            return Err(ManagedAgentStackStateError::InvalidState);
        }
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
            return Err(ManagedAgentStackStateError::InvalidState);
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
            return Err(ManagedAgentStackStateError::InvalidState);
        }
        if let Some(active) = &self.active {
            validate_request(&active.request, self, projection)?;
            if active.request.target_execution().mode()
                != ManagedAgentStackTargetModeV1::FabricAndAgent
                || active.response_channel.target() != active.request.target()
                || active.fabric_generation.value() > self.fabric_generation_high_water
                || active.agent_generation.value() > self.agent_generation_high_water
            {
                return Err(ManagedAgentStackStateError::InvalidState);
            }
        }
        if let Some(pending) = &self.pending {
            validate_request(&pending.request, self, projection)?;
            if pending.deadline_nanos < pending.admitted_at_nanos
                || pending.admitted_at_nanos == 0
                || pending.response_channel.target() != pending.request.target()
            {
                return Err(ManagedAgentStackStateError::InvalidState);
            }
            match (
                pending.kind,
                pending.fabric_generation,
                pending.agent_generation,
                pending.request.target_execution().mode(),
            ) {
                (
                    ManagedAgentStackPendingKind::ActivateAgent
                    | ManagedAgentStackPendingKind::RecoverActive,
                    Some(fabric),
                    Some(agent),
                    ManagedAgentStackTargetModeV1::FabricAndAgent,
                ) if fabric.value() <= self.fabric_generation_high_water
                    && agent.value() <= self.agent_generation_high_water => {}
                (
                    ManagedAgentStackPendingKind::DeactivateStack,
                    _,
                    _,
                    ManagedAgentStackTargetModeV1::EmptyDeactivate,
                ) => {}
                _ => return Err(ManagedAgentStackStateError::InvalidState),
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
            let evidence = facts.evidence().fields();
            let terminal_state = facts.state();
            if prior_key.is_some_and(|prior| prior >= key)
                || facts.source_scope() != terminal.source_scope
                || facts.operation_id() != terminal.operation_id
                || facts.request_digest() != terminal.request_digest
                || facts.runtime_store_instance_id() != self.store_instance_id
                || facts.target() != projection.target()
                || evidence.completion_snapshot_sequence > self.sequence
                || evidence.completion_runtime_host_epoch > self.runtime_host_epoch
                || terminal_state
                    .fabric_generation()
                    .is_some_and(|generation| {
                        generation.value() > self.fabric_generation_high_water
                    })
                || terminal_state
                    .agent_generation()
                    .is_some_and(|generation| generation.value() > self.agent_generation_high_water)
            {
                return Err(ManagedAgentStackStateError::InvalidState);
            }
            prior_key = Some(key);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, ManagedAgentStackStateError> {
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
        encode_optional_digest(&mut payload, self.quarantine_reason);
        let payload = payload.finish();
        let total = SNAPSHOT_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(ManagedAgentStackStateError::FrameTooLarge)?;
        if total > MAX_MANAGED_AGENT_STACK_SNAPSHOT_BYTES {
            return Err(ManagedAgentStackStateError::FrameTooLarge);
        }
        let mut frame = vec![0_u8; SNAPSHOT_HEADER_BYTES];
        frame[..4].copy_from_slice(SNAPSHOT_MAGIC);
        frame[4..6].copy_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
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
        frame[152..156].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        let checksum =
            snapshot_checksum(&frame[..SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES], &payload);
        frame[160..192].copy_from_slice(checksum.as_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn runtime_host_epoch(&self) -> u64 {
        self.runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn store_instance_id(&self) -> [u8; 32] {
        self.store_instance_id
    }

    pub(crate) fn transition(&self) -> ManagedAgentStackSnapshotTransition {
        ManagedAgentStackSnapshotTransition {
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
            quarantine_reason: self.quarantine_reason,
        }
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

fn validate_request(
    request: &ManagedAgentStackApplyRequestV1,
    snapshot: &ManagedAgentStackSnapshot,
    projection: &ManagedAgentStackProjectionV1,
) -> Result<(), ManagedAgentStackStateError> {
    request
        .validate_expected_store(snapshot.store_instance_id)
        .map_err(|_| ManagedAgentStackStateError::InvalidState)?;
    request
        .validate_projection(projection)
        .map_err(|_| ManagedAgentStackStateError::InvalidState)?;
    if request.target() != projection.target() {
        return Err(ManagedAgentStackStateError::InvalidState);
    }
    Ok(())
}

fn validate_phase_shape(
    snapshot: &ManagedAgentStackSnapshot,
) -> Result<(), ManagedAgentStackStateError> {
    let valid = match snapshot.phase {
        ManagedAgentStackDurablePhase::ExactZero => {
            snapshot.active.is_none()
                && snapshot.pending.is_none()
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && !snapshot.fabric_ready
                && !snapshot.agent_ready
                && !snapshot.dependency_satisfied
                && snapshot.quarantine_reason.is_none()
        }
        ManagedAgentStackDurablePhase::AgentStartIntent => {
            snapshot.active.is_none()
                && snapshot.pending.as_ref().is_some_and(|pending| {
                    pending.kind == ManagedAgentStackPendingKind::ActivateAgent
                })
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && !snapshot.agent_ready
                && snapshot.dependency_satisfied
                && snapshot.quarantine_reason.is_none()
        }
        ManagedAgentStackDurablePhase::ActiveReady => {
            snapshot.active.is_some()
                && snapshot.pending.is_none()
                && snapshot.physical_binding_census == 2
                && snapshot.census_complete
                && snapshot.fabric_ready
                && snapshot.agent_ready
                && snapshot.dependency_satisfied
                && snapshot.quarantine_reason.is_none()
        }
        ManagedAgentStackDurablePhase::AgentRetireIntent => {
            snapshot.active.is_some()
                && snapshot.pending.as_ref().is_some_and(|pending| {
                    pending.kind == ManagedAgentStackPendingKind::DeactivateStack
                })
                && snapshot.physical_binding_census == 2
                && snapshot.census_complete
                && snapshot.fabric_ready
                && snapshot.agent_ready
                && snapshot.dependency_satisfied
                && snapshot.quarantine_reason.is_none()
        }
        ManagedAgentStackDurablePhase::FabricStopIntent => {
            snapshot.active.is_some()
                && snapshot.pending.as_ref().is_some_and(|pending| {
                    pending.kind == ManagedAgentStackPendingKind::DeactivateStack
                })
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && !snapshot.agent_ready
                && !snapshot.dependency_satisfied
                && snapshot.quarantine_reason.is_none()
        }
        ManagedAgentStackDurablePhase::RecoveryIntent => {
            snapshot.pending.as_ref().is_some_and(|pending| {
                pending.kind == ManagedAgentStackPendingKind::RecoverActive
                    && pending.fabric_generation.is_some()
                    && pending.agent_generation.is_some()
                    && pending.request.target_execution().mode()
                        == ManagedAgentStackTargetModeV1::FabricAndAgent
            }) && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && !snapshot.agent_ready
                && snapshot.dependency_satisfied
                && snapshot.quarantine_reason.is_none()
        }
        ManagedAgentStackDurablePhase::Uncertain => {
            snapshot.pending.is_some() && !snapshot.census_complete
        }
        ManagedAgentStackDurablePhase::Quarantined => {
            snapshot.quarantine_reason.is_some()
                && !snapshot.agent_ready
                && !snapshot.dependency_satisfied
        }
    };
    valid
        .then_some(())
        .ok_or(ManagedAgentStackStateError::InvalidState)
}

fn validate_sorted_replays(
    records: &[ManagedAgentStackReplayRecord],
) -> Result<(), ManagedAgentStackStateError> {
    let mut prior = None;
    for record in records {
        if digest_is_zero(record.identity)
            || digest_is_zero(record.value_digest)
            || prior.is_some_and(|value| value >= record.identity)
        {
            return Err(ManagedAgentStackStateError::InvalidState);
        }
        prior = Some(record.identity);
    }
    Ok(())
}

fn encode_writer_fence(encoder: &mut Encoder, value: Option<ManagedAgentStackWriterFence>) {
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
) -> Result<Option<ManagedAgentStackWriterFence>, ManagedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ManagedAgentStackWriterFence {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            writer: PlanWriterRef::from_bytes(cursor.array()?),
            principal: PrincipalRef::from_bytes(cursor.array()?),
            epoch: cursor.u64()?,
            proof_envelope_digest: cursor.digest()?,
        })),
        _ => Err(ManagedAgentStackStateError::InvalidPresence),
    }
}

fn encode_revision_high_water(
    encoder: &mut Encoder,
    value: Option<ManagedAgentStackRevisionHighWater>,
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
) -> Result<Option<ManagedAgentStackRevisionHighWater>, ManagedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ManagedAgentStackRevisionHighWater {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            revision: cursor.u64()?,
            source_plan_digest: SourcePlanDigest::new(cursor.digest()?),
        })),
        _ => Err(ManagedAgentStackStateError::InvalidPresence),
    }
}

fn encode_active(
    encoder: &mut Encoder,
    value: Option<&ManagedAgentStackDurableActive>,
) -> Result<(), ManagedAgentStackStateError> {
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
) -> Result<Option<ManagedAgentStackDurableActive>, ManagedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ManagedAgentStackDurableActive {
            fabric_generation: decode_generation(cursor)?,
            agent_generation: decode_generation(cursor)?,
            response_channel: decode_channel(cursor)?,
            request: ManagedAgentStackApplyRequestV1::decode(
                cursor.bounded(MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES)?,
            )
            .map_err(|_| ManagedAgentStackStateError::InvalidNestedContract)?,
        })),
        _ => Err(ManagedAgentStackStateError::InvalidPresence),
    }
}

fn encode_pending(
    encoder: &mut Encoder,
    value: Option<&ManagedAgentStackDurablePending>,
) -> Result<(), ManagedAgentStackStateError> {
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
) -> Result<Option<ManagedAgentStackDurablePending>, ManagedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => {
            let kind = ManagedAgentStackPendingKind::decode(cursor.u8()?)?;
            let fabric_generation = decode_optional_generation(cursor)?;
            let agent_generation = decode_optional_generation(cursor)?;
            let admitted_clock_generation = ClockGeneration::try_new(cursor.u64()?)
                .map_err(|_| ManagedAgentStackStateError::InvalidState)?;
            let admitted_at_nanos = cursor.u64()?;
            let deadline_nanos = cursor.u64()?;
            let response_channel = decode_channel(cursor)?;
            let request = ManagedAgentStackApplyRequestV1::decode(
                cursor.bounded(MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES)?,
            )
            .map_err(|_| ManagedAgentStackStateError::InvalidNestedContract)?;
            Ok(Some(ManagedAgentStackDurablePending {
                kind,
                fabric_generation,
                agent_generation,
                admitted_clock_generation,
                admitted_at_nanos,
                deadline_nanos,
                response_channel,
                request,
            }))
        }
        _ => Err(ManagedAgentStackStateError::InvalidPresence),
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
) -> Result<ReferenceChannelBindingV1, ManagedAgentStackStateError> {
    ReferenceChannelBindingV1::try_new(
        RuntimeHostId::from_bytes(cursor.array()?),
        PrincipalRef::from_bytes(cursor.array()?),
        cursor.digest()?,
        cursor.digest()?,
    )
    .map_err(|_| ManagedAgentStackStateError::InvalidNestedContract)
}

fn encode_replay_records(
    encoder: &mut Encoder,
    records: &[ManagedAgentStackReplayRecord],
) -> Result<(), ManagedAgentStackStateError> {
    encoder.count(records.len())?;
    for record in records {
        encoder.digest(record.identity);
        encoder.digest(record.value_digest);
    }
    Ok(())
}

fn decode_replay_records(
    cursor: &mut Cursor<'_>,
) -> Result<Vec<ManagedAgentStackReplayRecord>, ManagedAgentStackStateError> {
    let count = cursor.count(MAX_REPLAY_ENTRIES)?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(ManagedAgentStackReplayRecord {
            identity: cursor.digest()?,
            value_digest: cursor.digest()?,
        });
    }
    Ok(records)
}

fn encode_terminals(
    encoder: &mut Encoder,
    terminals: &[ManagedAgentStackTerminalRecord],
) -> Result<(), ManagedAgentStackStateError> {
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
) -> Result<Vec<ManagedAgentStackTerminalRecord>, ManagedAgentStackStateError> {
    let count = cursor.count(MAX_TERMINALS)?;
    let mut terminals = Vec::with_capacity(count);
    for _ in 0..count {
        terminals.push(ManagedAgentStackTerminalRecord {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            operation_id: ApplyOperationId::from_bytes(cursor.array()?),
            request_digest: cursor.digest()?,
            receipt: ManagedAgentStackTerminalReceiptV1::decode(
                cursor.bounded(MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES)?,
            )
            .map_err(|_| ManagedAgentStackStateError::InvalidNestedContract)?,
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
) -> Result<Option<Digest32>, ManagedAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(cursor.digest()?)),
        _ => Err(ManagedAgentStackStateError::InvalidPresence),
    }
}

fn decode_generation(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedServiceGeneration, ManagedAgentStackStateError> {
    ManagedServiceGeneration::try_new(cursor.u64()?)
        .map_err(|_| ManagedAgentStackStateError::InvalidState)
}

fn decode_optional_generation(
    cursor: &mut Cursor<'_>,
) -> Result<Option<ManagedServiceGeneration>, ManagedAgentStackStateError> {
    let value = cursor.u64()?;
    if value == 0 {
        Ok(None)
    } else {
        ManagedServiceGeneration::try_new(value)
            .map(Some)
            .map_err(|_| ManagedAgentStackStateError::InvalidState)
    }
}

fn snapshot_checksum(header: &[u8], payload: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_CHECKSUM_DOMAIN);
    hasher.update((header.len() as u64).to_be_bytes());
    hasher.update(header);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    Digest32::from_bytes(hasher.finalize().into())
}

fn digest_is_zero(value: Digest32) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

fn decode_bool(value: u8) -> Result<bool, ManagedAgentStackStateError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ManagedAgentStackStateError::NonCanonicalEncoding),
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

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn digest(&mut self, value: Digest32) {
        self.bytes(value.as_bytes());
    }

    fn count(&mut self, value: usize) -> Result<(), ManagedAgentStackStateError> {
        let value = u16::try_from(value).map_err(|_| ManagedAgentStackStateError::FrameTooLarge)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn bounded(&mut self, value: &[u8]) -> Result<(), ManagedAgentStackStateError> {
        let length =
            u32::try_from(value.len()).map_err(|_| ManagedAgentStackStateError::FrameTooLarge)?;
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], ManagedAgentStackStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ManagedAgentStackStateError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ManagedAgentStackStateError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ManagedAgentStackStateError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ManagedAgentStackStateError> {
        Ok(read_u16(self.take(2)?))
    }

    fn u32(&mut self) -> Result<u32, ManagedAgentStackStateError> {
        Ok(read_u32(self.take(4)?))
    }

    fn u64(&mut self) -> Result<u64, ManagedAgentStackStateError> {
        Ok(read_u64(self.take(8)?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManagedAgentStackStateError> {
        Ok(read_array(self.take(N)?))
    }

    fn digest(&mut self) -> Result<Digest32, ManagedAgentStackStateError> {
        Ok(Digest32::from_bytes(self.array()?))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, ManagedAgentStackStateError> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            return Err(ManagedAgentStackStateError::FrameTooLarge);
        }
        Ok(count)
    }

    fn bounded(&mut self, maximum: usize) -> Result<&'a [u8], ManagedAgentStackStateError> {
        let length = self.u32()? as usize;
        if length == 0 || length > maximum {
            return Err(ManagedAgentStackStateError::FrameTooLarge);
        }
        self.take(length)
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedAgentStackStateError {
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
    SequenceOverflow,
    TrailingBytes,
}

impl fmt::Display for ManagedAgentStackStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "managed Agent-stack state failed: {self:?}")
    }
}

impl std::error::Error for ManagedAgentStackStateError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::PrincipalRef;
    use paraegox_runtime_contracts::managed_agent_stack_plan::{
        ManagedAgentStackApplyRequestV1, ManagedAgentStackProjectionV1,
        ManagedAgentStackTerminalReceiptV1,
    };
    use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
    use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;

    use super::*;

    const FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_agent_stack_successor_v1.json");
    const STORE: [u8; 32] = [0x44; 32];
    const OWNER: Digest32 = Digest32::from_bytes([0x55; 32]);
    const PROJECTION_DIGEST: Digest32 = Digest32::from_bytes([0x66; 32]);
    const RUNTIME_EPOCH: u64 = 9;

    fn decode_hex(value: &str) -> Vec<u8> {
        fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("fixture contains non-hex byte"),
            }
        }
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn top_level_hex(field: &str) -> Vec<u8> {
        let needle = format!("\"{field}\": \"");
        let start = FIXTURE
            .find(&needle)
            .map(|offset| offset + needle.len())
            .unwrap_or_else(|| panic!("missing fixture field {field}"));
        let end = FIXTURE[start..]
            .find('"')
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("unterminated fixture field {field}"));
        decode_hex(&FIXTURE[start..end])
    }

    fn object_hex(object: &str, field: &str) -> Vec<u8> {
        let object_needle = format!("\"{object}\": {{");
        let object_start = FIXTURE
            .find(&object_needle)
            .unwrap_or_else(|| panic!("missing fixture object {object}"));
        let field_needle = format!("\"{field}\": \"");
        let start = FIXTURE[object_start..]
            .find(&field_needle)
            .map(|offset| object_start + offset + field_needle.len())
            .unwrap_or_else(|| panic!("missing fixture field {object}.{field}"));
        let end = FIXTURE[start..]
            .find('"')
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("unterminated fixture field {object}.{field}"));
        decode_hex(&FIXTURE[start..end])
    }

    fn projection() -> ManagedAgentStackProjectionV1 {
        ManagedAgentStackProjectionV1::decode(&top_level_hex("projection_pxsp_hex"))
            .unwrap_or_else(|error| panic!("fixture projection rejected: {error}"))
    }

    fn active_request() -> ManagedAgentStackApplyRequestV1 {
        ManagedAgentStackApplyRequestV1::decode(&object_hex("fabric_and_agent", "outer_v7_hex"))
            .unwrap_or_else(|error| panic!("fixture active request rejected: {error}"))
    }

    fn active_terminal() -> ManagedAgentStackTerminalReceiptV1 {
        let object = "\"fabric_and_agent\": {";
        let object_start = FIXTURE
            .find(object)
            .unwrap_or_else(|| panic!("missing active fixture object"));
        let terminal_start = FIXTURE[object_start..]
            .find("\"terminal\": {")
            .map(|offset| object_start + offset)
            .unwrap_or_else(|| panic!("missing active terminal object"));
        let needle = "\"wire_hex\": \"";
        let start = FIXTURE[terminal_start..]
            .find(needle)
            .map(|offset| terminal_start + offset + needle.len())
            .unwrap_or_else(|| panic!("missing active terminal wire"));
        let end = FIXTURE[start..]
            .find('"')
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("unterminated active terminal wire"));
        ManagedAgentStackTerminalReceiptV1::decode(&decode_hex(&FIXTURE[start..end]))
            .unwrap_or_else(|error| panic!("fixture terminal rejected: {error}"))
    }

    fn channel(request: &ManagedAgentStackApplyRequestV1) -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            request.target(),
            PrincipalRef::from_bytes([0x71; 16]),
            Digest32::from_bytes([0x72; 32]),
            Digest32::from_bytes([0x73; 32]),
        )
        .unwrap_or_else(|error| panic!("fixture channel rejected: {error}"))
    }

    fn start_intent_transition() -> ManagedAgentStackSnapshotTransition {
        let request = active_request();
        ManagedAgentStackSnapshotTransition {
            fabric_generation_high_water: 7,
            agent_generation_high_water: 8,
            phase: ManagedAgentStackDurablePhase::AgentStartIntent,
            writer_fence: None,
            revision_high_water: None,
            active: None,
            pending: Some(ManagedAgentStackDurablePending {
                kind: ManagedAgentStackPendingKind::ActivateAgent,
                fabric_generation: Some(
                    ManagedServiceGeneration::try_new(7)
                        .unwrap_or_else(|error| panic!("fabric generation rejected: {error}")),
                ),
                agent_generation: Some(
                    ManagedServiceGeneration::try_new(8)
                        .unwrap_or_else(|error| panic!("agent generation rejected: {error}")),
                ),
                admitted_clock_generation: request.temporal().target_clock_generation(),
                admitted_at_nanos: 1,
                deadline_nanos: 2,
                response_channel: channel(&request),
                request,
            }),
            tenure_nonces: Vec::new(),
            request_nonces: Vec::new(),
            temporal_lineages: Vec::new(),
            terminals: Vec::new(),
            physical_binding_census: 0,
            census_complete: true,
            fabric_ready: true,
            agent_ready: false,
            dependency_satisfied: true,
            quarantine_reason: None,
        }
    }

    fn initial_start_intent() -> ManagedAgentStackSnapshot {
        ManagedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            RUNTIME_EPOCH,
            start_intent_transition(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("valid start intent rejected: {error}"))
    }

    #[test]
    fn snapshot_roundtrip_restart_decode_and_corruption_are_strict() {
        let snapshot = initial_start_intent();
        let decoded = ManagedAgentStackSnapshot::decode(
            snapshot.canonical_wire(),
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            &projection(),
        )
        .unwrap_or_else(|error| panic!("restart decode rejected: {error}"));
        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.canonical_wire(), snapshot.canonical_wire());

        let mut corrupt = snapshot.canonical_wire().to_vec();
        *corrupt
            .last_mut()
            .unwrap_or_else(|| panic!("snapshot must be nonempty")) ^= 1;
        assert_eq!(
            ManagedAgentStackSnapshot::decode(
                &corrupt,
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                &projection(),
            ),
            Err(ManagedAgentStackStateError::ChecksumMismatch)
        );
        assert_eq!(
            ManagedAgentStackSnapshot::decode(
                &snapshot.canonical_wire()[..SNAPSHOT_HEADER_BYTES - 1],
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                &projection(),
            ),
            Err(ManagedAgentStackStateError::Truncated)
        );
    }

    #[test]
    fn phase_shapes_and_generation_high_waters_fail_closed() {
        let mut recovery = start_intent_transition();
        recovery.phase = ManagedAgentStackDurablePhase::RecoveryIntent;
        assert_eq!(
            ManagedAgentStackSnapshot::try_initial(
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                RUNTIME_EPOCH,
                recovery.clone(),
                &projection(),
            ),
            Err(ManagedAgentStackStateError::InvalidState)
        );
        recovery
            .pending
            .as_mut()
            .unwrap_or_else(|| panic!("recovery fixture needs pending"))
            .kind = ManagedAgentStackPendingKind::RecoverActive;
        ManagedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            RUNTIME_EPOCH,
            recovery,
            &projection(),
        )
        .unwrap_or_else(|error| panic!("valid recovery intent rejected: {error}"));

        let mut bad_high_water = start_intent_transition();
        bad_high_water.fabric_generation_high_water = 6;
        assert_eq!(
            ManagedAgentStackSnapshot::try_initial(
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                RUNTIME_EPOCH,
                bad_high_water,
                &projection(),
            ),
            Err(ManagedAgentStackStateError::InvalidState)
        );

        let mut quarantined = start_intent_transition();
        quarantined.phase = ManagedAgentStackDurablePhase::Quarantined;
        quarantined.quarantine_reason = Some(Digest32::from_bytes([0x91; 32]));
        quarantined.agent_ready = true;
        assert_eq!(
            ManagedAgentStackSnapshot::try_initial(
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                RUNTIME_EPOCH,
                quarantined,
                &projection(),
            ),
            Err(ManagedAgentStackStateError::InvalidState)
        );
    }

    #[test]
    fn terminal_sequence_and_order_are_validated_during_restart_decode() {
        let request = active_request();
        let response_channel = channel(&request);
        let mut active = start_intent_transition();
        active.phase = ManagedAgentStackDurablePhase::ActiveReady;
        active.active = Some(ManagedAgentStackDurableActive {
            fabric_generation: ManagedServiceGeneration::try_new(7)
                .unwrap_or_else(|error| panic!("fabric generation rejected: {error}")),
            agent_generation: ManagedServiceGeneration::try_new(8)
                .unwrap_or_else(|error| panic!("agent generation rejected: {error}")),
            response_channel,
            request: request.clone(),
        });
        active.pending = None;
        active.physical_binding_census = 2;
        active.agent_ready = true;
        active.dependency_satisfied = true;
        let mut snapshot = ManagedAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            RUNTIME_EPOCH,
            active,
            &projection(),
        )
        .unwrap_or_else(|error| panic!("active snapshot rejected: {error}"));
        while snapshot.sequence() < 10 {
            snapshot = snapshot
                .try_successor(snapshot.transition(), &projection())
                .unwrap_or_else(|error| panic!("sequence advance rejected: {error}"));
        }
        let terminal = ManagedAgentStackTerminalRecord {
            source_scope: request.provenance().source_scope(),
            operation_id: request.operation_id(),
            request_digest: request.envelope_request_digest(),
            receipt: active_terminal(),
        };
        let mut with_terminal = snapshot.transition();
        with_terminal.terminals.push(terminal.clone());
        let terminal_snapshot = snapshot
            .try_successor(with_terminal, &projection())
            .unwrap_or_else(|error| panic!("ordered terminal rejected: {error}"));
        assert_eq!(terminal_snapshot.sequence(), 11);
        ManagedAgentStackSnapshot::decode(
            terminal_snapshot.canonical_wire(),
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            &projection(),
        )
        .unwrap_or_else(|error| panic!("terminal restart decode rejected: {error}"));

        let mut duplicate = snapshot.transition();
        duplicate.terminals = vec![terminal.clone(), terminal];
        assert_eq!(
            snapshot.try_successor(duplicate, &projection()),
            Err(ManagedAgentStackStateError::InvalidState)
        );
    }
}
