#![cfg(unix)]

//! Independent PXAR-v9 durable Fabric/Model/Agent stack state.
//!
//! `PXMA` v1 is intentionally unused by every predecessor snapshot codec. It
//! is neither `PXAS` v1 nor a new interpretation of `PXMS`/`PXDA`; recovery
//! rejects those magics before reading any payload. Every retained PXAR-v9 and
//! PXMT-v1 value is strictly decoded again and re-encoded canonically.

use core::fmt;

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::ClockGeneration;
use paraegox_runtime_contracts::apply::{ApplyOperationId, PlanWriterRef};
use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
    MAX_MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_BYTES,
    MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_BYTES, ManagedModelAgentStackApplyRequestV1,
    ManagedModelAgentStackProjectionV1, ManagedModelAgentStackTargetModeV1,
    ManagedModelAgentStackTerminalReceiptV1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
use paraegox_runtime_contracts::provenance::{SourcePlanDigest, SourceScopeRef};
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
use sha2::{Digest as ShaDigest, Sha256};

const SNAPSHOT_MAGIC: &[u8; 4] = b"PXMA";
const SNAPSHOT_VERSION: u16 = 1;
const SNAPSHOT_HEADER_BYTES: usize = 208;
const SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES: usize = 176;
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-model-agent-stack-snapshot.sha256.v1";
const MAX_TERMINALS: usize = 256;
const MAX_REPLAY_ENTRIES: usize = 256;
pub(crate) const MAX_MANAGED_MODEL_AGENT_STACK_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ManagedModelAgentStackDurablePhase {
    ExactZero = 1,
    ModelStartIntent = 2,
    AgentStartIntent = 3,
    ActiveReady = 4,
    AgentRetireIntent = 5,
    ModelRetireIntent = 6,
    FabricStopIntent = 7,
    RecoveryIntent = 8,
    Uncertain = 9,
    Quarantined = 10,
}

impl ManagedModelAgentStackDurablePhase {
    fn decode(value: u8) -> Result<Self, ManagedModelAgentStackStateError> {
        match value {
            1 => Ok(Self::ExactZero),
            2 => Ok(Self::ModelStartIntent),
            3 => Ok(Self::AgentStartIntent),
            4 => Ok(Self::ActiveReady),
            5 => Ok(Self::AgentRetireIntent),
            6 => Ok(Self::ModelRetireIntent),
            7 => Ok(Self::FabricStopIntent),
            8 => Ok(Self::RecoveryIntent),
            9 => Ok(Self::Uncertain),
            10 => Ok(Self::Quarantined),
            _ => Err(ManagedModelAgentStackStateError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ManagedModelAgentStackPendingKind {
    ActivateStack = 1,
    DeactivateStack = 2,
    RecoverActive = 3,
}

impl ManagedModelAgentStackPendingKind {
    fn decode(value: u8) -> Result<Self, ManagedModelAgentStackStateError> {
        match value {
            1 => Ok(Self::ActivateStack),
            2 => Ok(Self::DeactivateStack),
            3 => Ok(Self::RecoverActive),
            _ => Err(ManagedModelAgentStackStateError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackWriterFence {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) writer: PlanWriterRef,
    pub(crate) principal: PrincipalRef,
    pub(crate) epoch: u64,
    pub(crate) proof_envelope_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackRevisionHighWater {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) revision: u64,
    pub(crate) source_plan_digest: SourcePlanDigest,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ManagedModelAgentStackReplayRecord {
    pub(crate) identity: Digest32,
    pub(crate) value_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackDurableActive {
    pub(crate) fabric_generation: ManagedServiceGeneration,
    pub(crate) model_generation: ManagedServiceGeneration,
    pub(crate) agent_generation: ManagedServiceGeneration,
    pub(crate) response_channel: ReferenceChannelBindingV1,
    pub(crate) request: ManagedModelAgentStackApplyRequestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackDurablePending {
    pub(crate) kind: ManagedModelAgentStackPendingKind,
    pub(crate) fabric_generation: Option<ManagedServiceGeneration>,
    pub(crate) model_generation: Option<ManagedServiceGeneration>,
    pub(crate) agent_generation: Option<ManagedServiceGeneration>,
    pub(crate) admitted_clock_generation: ClockGeneration,
    pub(crate) admitted_at_nanos: u64,
    pub(crate) deadline_nanos: u64,
    pub(crate) response_channel: ReferenceChannelBindingV1,
    pub(crate) request: ManagedModelAgentStackApplyRequestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackTerminalRecord {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) operation_id: ApplyOperationId,
    pub(crate) request_digest: Digest32,
    pub(crate) receipt: ManagedModelAgentStackTerminalReceiptV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackSnapshotTransition {
    pub(crate) fabric_generation_high_water: u64,
    pub(crate) model_generation_high_water: u64,
    pub(crate) agent_generation_high_water: u64,
    pub(crate) phase: ManagedModelAgentStackDurablePhase,
    pub(crate) writer_fence: Option<ManagedModelAgentStackWriterFence>,
    pub(crate) revision_high_water: Option<ManagedModelAgentStackRevisionHighWater>,
    pub(crate) active: Option<ManagedModelAgentStackDurableActive>,
    pub(crate) pending: Option<ManagedModelAgentStackDurablePending>,
    pub(crate) tenure_nonces: Vec<ManagedModelAgentStackReplayRecord>,
    pub(crate) request_nonces: Vec<ManagedModelAgentStackReplayRecord>,
    pub(crate) temporal_lineages: Vec<ManagedModelAgentStackReplayRecord>,
    pub(crate) terminals: Vec<ManagedModelAgentStackTerminalRecord>,
    pub(crate) physical_binding_census: u16,
    pub(crate) census_complete: bool,
    pub(crate) fabric_ready: bool,
    pub(crate) model_ready: bool,
    pub(crate) agent_ready: bool,
    pub(crate) fabric_to_agent_dependency_ready: bool,
    pub(crate) model_to_agent_dependency_ready: bool,
    pub(crate) quarantine_reason: Option<Digest32>,
}

#[derive(Clone, Copy)]
struct SnapshotIdentity {
    store_instance_id: [u8; 32],
    owner_target_fingerprint: Digest32,
    transition_projection_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackSnapshot {
    store_instance_id: [u8; 32],
    owner_target_fingerprint: Digest32,
    transition_projection_digest: Digest32,
    sequence: u64,
    runtime_host_epoch: u64,
    pub(crate) fabric_generation_high_water: u64,
    pub(crate) model_generation_high_water: u64,
    pub(crate) agent_generation_high_water: u64,
    pub(crate) phase: ManagedModelAgentStackDurablePhase,
    pub(crate) writer_fence: Option<ManagedModelAgentStackWriterFence>,
    pub(crate) revision_high_water: Option<ManagedModelAgentStackRevisionHighWater>,
    pub(crate) active: Option<ManagedModelAgentStackDurableActive>,
    pub(crate) pending: Option<ManagedModelAgentStackDurablePending>,
    pub(crate) tenure_nonces: Vec<ManagedModelAgentStackReplayRecord>,
    pub(crate) request_nonces: Vec<ManagedModelAgentStackReplayRecord>,
    pub(crate) temporal_lineages: Vec<ManagedModelAgentStackReplayRecord>,
    pub(crate) terminals: Vec<ManagedModelAgentStackTerminalRecord>,
    pub(crate) physical_binding_census: u16,
    pub(crate) census_complete: bool,
    pub(crate) fabric_ready: bool,
    pub(crate) model_ready: bool,
    pub(crate) agent_ready: bool,
    pub(crate) fabric_to_agent_dependency_ready: bool,
    pub(crate) model_to_agent_dependency_ready: bool,
    pub(crate) quarantine_reason: Option<Digest32>,
    canonical_wire: Box<[u8]>,
}

impl ManagedModelAgentStackSnapshot {
    pub(crate) fn try_initial(
        store_instance_id: [u8; 32],
        owner_target_fingerprint: Digest32,
        transition_projection_digest: Digest32,
        runtime_host_epoch: u64,
        transition: ManagedModelAgentStackSnapshotTransition,
        projection: &ManagedModelAgentStackProjectionV1,
    ) -> Result<Self, ManagedModelAgentStackStateError> {
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

    pub(crate) fn try_successor_at_epoch(
        &self,
        runtime_host_epoch: u64,
        transition: ManagedModelAgentStackSnapshotTransition,
        projection: &ManagedModelAgentStackProjectionV1,
    ) -> Result<Self, ManagedModelAgentStackStateError> {
        if runtime_host_epoch < self.runtime_host_epoch
            || transition.fabric_generation_high_water < self.fabric_generation_high_water
            || transition.model_generation_high_water < self.model_generation_high_water
            || transition.agent_generation_high_water < self.agent_generation_high_water
            || !writer_fence_advances(self.writer_fence, transition.writer_fence)
            || !revision_advances(self.revision_high_water, transition.revision_high_water)
            || !retains_replays(&self.tenure_nonces, &transition.tenure_nonces)
            || !retains_replays(&self.request_nonces, &transition.request_nonces)
            || !retains_replays(&self.temporal_lineages, &transition.temporal_lineages)
            || !retains_terminals(&self.terminals, &transition.terminals)
        {
            return Err(ManagedModelAgentStackStateError::FenceRegression);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ManagedModelAgentStackStateError::SequenceOverflow)?;
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
        transition: ManagedModelAgentStackSnapshotTransition,
        projection: &ManagedModelAgentStackProjectionV1,
    ) -> Result<Self, ManagedModelAgentStackStateError> {
        let mut snapshot = Self {
            store_instance_id: identity.store_instance_id,
            owner_target_fingerprint: identity.owner_target_fingerprint,
            transition_projection_digest: identity.transition_projection_digest,
            sequence,
            runtime_host_epoch,
            fabric_generation_high_water: transition.fabric_generation_high_water,
            model_generation_high_water: transition.model_generation_high_water,
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
            model_ready: transition.model_ready,
            agent_ready: transition.agent_ready,
            fabric_to_agent_dependency_ready: transition.fabric_to_agent_dependency_ready,
            model_to_agent_dependency_ready: transition.model_to_agent_dependency_ready,
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
        projection: &ManagedModelAgentStackProjectionV1,
    ) -> Result<Self, ManagedModelAgentStackStateError> {
        if frame.len() < SNAPSHOT_HEADER_BYTES {
            return Err(ManagedModelAgentStackStateError::Truncated);
        }
        if frame.len() > MAX_MANAGED_MODEL_AGENT_STACK_SNAPSHOT_BYTES {
            return Err(ManagedModelAgentStackStateError::FrameTooLarge);
        }
        if &frame[..4] != SNAPSHOT_MAGIC
            || read_u16(&frame[4..6]) != SNAPSHOT_VERSION
            || usize::from(read_u16(&frame[6..8])) != SNAPSHOT_HEADER_BYTES
        {
            return Err(ManagedModelAgentStackStateError::UnsupportedFrame);
        }
        let total = read_u32(&frame[8..12]) as usize;
        let payload_length = read_u32(&frame[168..172]) as usize;
        if total != frame.len()
            || SNAPSHOT_HEADER_BYTES.checked_add(payload_length) != Some(frame.len())
            || frame[149..168].iter().any(|byte| *byte != 0)
            || frame[172..176].iter().any(|byte| *byte != 0)
        {
            return Err(ManagedModelAgentStackStateError::InvalidLength);
        }
        let expected_checksum = snapshot_checksum(
            &frame[..SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES],
            &frame[SNAPSHOT_HEADER_BYTES..],
        );
        if frame[176..208] != *expected_checksum.as_bytes() {
            return Err(ManagedModelAgentStackStateError::ChecksumMismatch);
        }
        let store_instance_id = read_array(&frame[20..52]);
        let owner_target_fingerprint = Digest32::from_bytes(read_array(&frame[52..84]));
        let transition_projection_digest = Digest32::from_bytes(read_array(&frame[84..116]));
        if store_instance_id != expected_store_instance_id
            || owner_target_fingerprint != expected_owner_target_fingerprint
            || transition_projection_digest != expected_transition_projection_digest
        {
            return Err(ManagedModelAgentStackStateError::IdentityMismatch);
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
            return Err(ManagedModelAgentStackStateError::TrailingBytes);
        }
        let snapshot = Self::try_build(
            SnapshotIdentity {
                store_instance_id,
                owner_target_fingerprint,
                transition_projection_digest,
            },
            read_u64(&frame[12..20]),
            runtime_host_epoch,
            ManagedModelAgentStackSnapshotTransition {
                fabric_generation_high_water: read_u64(&frame[116..124]),
                model_generation_high_water: read_u64(&frame[124..132]),
                agent_generation_high_water: read_u64(&frame[132..140]),
                phase: ManagedModelAgentStackDurablePhase::decode(frame[140])?,
                physical_binding_census: read_u16(&frame[141..143]),
                census_complete: decode_bool(frame[143])?,
                fabric_ready: decode_bool(frame[144])?,
                model_ready: decode_bool(frame[145])?,
                agent_ready: decode_bool(frame[146])?,
                fabric_to_agent_dependency_ready: decode_bool(frame[147])?,
                model_to_agent_dependency_ready: decode_bool(frame[148])?,
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
            return Err(ManagedModelAgentStackStateError::NonCanonicalEncoding);
        }
        Ok(snapshot)
    }

    fn validate(
        &self,
        projection: &ManagedModelAgentStackProjectionV1,
    ) -> Result<(), ManagedModelAgentStackStateError> {
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
            || self.quarantine_reason.is_some_and(digest_is_zero)
            || (self.fabric_to_agent_dependency_ready && !self.fabric_ready)
            || (self.model_to_agent_dependency_ready && !self.model_ready)
            || (self.agent_ready
                && (!self.fabric_ready
                    || !self.model_ready
                    || !self.fabric_to_agent_dependency_ready
                    || !self.model_to_agent_dependency_ready))
        {
            return Err(ManagedModelAgentStackStateError::InvalidState);
        }
        validate_sorted_replays(&self.tenure_nonces)?;
        validate_sorted_replays(&self.request_nonces)?;
        validate_sorted_replays(&self.temporal_lineages)?;
        validate_fence_values(self.writer_fence, self.revision_high_water)?;

        if let Some(active) = &self.active {
            validate_request(&active.request, self, projection, false)?;
            if active.request.target_execution().mode()
                != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
                || active.response_channel.target() != active.request.target()
                || active.fabric_generation.value() > self.fabric_generation_high_water
                || active.model_generation.value() > self.model_generation_high_water
                || active.agent_generation.value() > self.agent_generation_high_water
            {
                return Err(ManagedModelAgentStackStateError::InvalidState);
            }
        }
        if let Some(pending) = &self.pending {
            validate_request(
                &pending.request,
                self,
                projection,
                pending.kind != ManagedModelAgentStackPendingKind::RecoverActive,
            )?;
            if pending.deadline_nanos < pending.admitted_at_nanos
                || pending.admitted_at_nanos == 0
                || pending.response_channel.target() != pending.request.target()
                || !optional_generation_within(
                    pending.fabric_generation,
                    self.fabric_generation_high_water,
                )
                || !optional_generation_within(
                    pending.model_generation,
                    self.model_generation_high_water,
                )
                || !optional_generation_within(
                    pending.agent_generation,
                    self.agent_generation_high_water,
                )
            {
                return Err(ManagedModelAgentStackStateError::InvalidState);
            }
            let mode = pending.request.target_execution().mode();
            if !matches!(
                (pending.kind, mode),
                (
                    ManagedModelAgentStackPendingKind::ActivateStack
                        | ManagedModelAgentStackPendingKind::RecoverActive,
                    ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
                ) | (
                    ManagedModelAgentStackPendingKind::DeactivateStack,
                    ManagedModelAgentStackTargetModeV1::EmptyDeactivate
                )
            ) {
                return Err(ManagedModelAgentStackStateError::InvalidState);
            }
            // The complete signed request preserves its exact CAS input. This
            // codec cannot compare that input: initial PXAR-v9 targets the
            // independently owned PXAR-v6 predecessor, whose slice digest is
            // intentionally absent here. The Runtime cutover owner performs
            // that comparison before publishing this snapshot.
        }
        validate_phase_shape(self)?;
        validate_terminals(self, projection)?;
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, ManagedModelAgentStackStateError> {
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
            .ok_or(ManagedModelAgentStackStateError::FrameTooLarge)?;
        if total > MAX_MANAGED_MODEL_AGENT_STACK_SNAPSHOT_BYTES {
            return Err(ManagedModelAgentStackStateError::FrameTooLarge);
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
        frame[124..132].copy_from_slice(&self.model_generation_high_water.to_be_bytes());
        frame[132..140].copy_from_slice(&self.agent_generation_high_water.to_be_bytes());
        frame[140] = self.phase as u8;
        frame[141..143].copy_from_slice(&self.physical_binding_census.to_be_bytes());
        frame[143] = u8::from(self.census_complete);
        frame[144] = u8::from(self.fabric_ready);
        frame[145] = u8::from(self.model_ready);
        frame[146] = u8::from(self.agent_ready);
        frame[147] = u8::from(self.fabric_to_agent_dependency_ready);
        frame[148] = u8::from(self.model_to_agent_dependency_ready);
        frame[168..172].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        let checksum =
            snapshot_checksum(&frame[..SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES], &payload);
        frame[176..208].copy_from_slice(checksum.as_bytes());
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

    pub(crate) fn transition(&self) -> ManagedModelAgentStackSnapshotTransition {
        ManagedModelAgentStackSnapshotTransition {
            fabric_generation_high_water: self.fabric_generation_high_water,
            model_generation_high_water: self.model_generation_high_water,
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
            model_ready: self.model_ready,
            agent_ready: self.agent_ready,
            fabric_to_agent_dependency_ready: self.fabric_to_agent_dependency_ready,
            model_to_agent_dependency_ready: self.model_to_agent_dependency_ready,
            quarantine_reason: self.quarantine_reason,
        }
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

fn validate_request(
    request: &ManagedModelAgentStackApplyRequestV1,
    snapshot: &ManagedModelAgentStackSnapshot,
    projection: &ManagedModelAgentStackProjectionV1,
    pending: bool,
) -> Result<(), ManagedModelAgentStackStateError> {
    request
        .validate_expected_store(snapshot.store_instance_id)
        .map_err(|_| ManagedModelAgentStackStateError::InvalidState)?;
    request
        .validate_projection(projection)
        .map_err(|_| ManagedModelAgentStackStateError::InvalidState)?;
    if request.target() != projection.target() {
        return Err(ManagedModelAgentStackStateError::InvalidState);
    }
    let provenance = request.provenance();
    if let Some(revision) = snapshot.revision_high_water {
        let request_revision = provenance.source_revision().value();
        if revision.source_scope != provenance.source_scope()
            || request_revision > revision.revision
            || (request_revision == revision.revision
                && revision.source_plan_digest != provenance.source_plan_digest())
            || (pending && request_revision != revision.revision)
        {
            return Err(ManagedModelAgentStackStateError::FenceMismatch);
        }
    }
    if let Some(fence) = snapshot.writer_fence {
        let context = request.control_commitment().control().writer_context();
        let request_epoch = context.epoch().value();
        let proof_digest = context
            .proof()
            .envelope_digest()
            .map_err(|_| ManagedModelAgentStackStateError::FenceMismatch)?;
        if fence.source_scope != provenance.source_scope()
            || request_epoch > fence.epoch
            || (request_epoch == fence.epoch
                && (fence.writer != context.writer()
                    || fence.principal != request.authentication().claim().principal()
                    || fence.proof_envelope_digest != proof_digest))
            || (pending && request_epoch != fence.epoch)
        {
            return Err(ManagedModelAgentStackStateError::FenceMismatch);
        }
    }
    Ok(())
}

fn validate_fence_values(
    writer: Option<ManagedModelAgentStackWriterFence>,
    revision: Option<ManagedModelAgentStackRevisionHighWater>,
) -> Result<(), ManagedModelAgentStackStateError> {
    if let Some(fence) = writer
        && (fence.source_scope.as_bytes().iter().all(|byte| *byte == 0)
            || fence.writer.as_bytes().iter().all(|byte| *byte == 0)
            || fence.principal.as_bytes().iter().all(|byte| *byte == 0)
            || fence.epoch == 0
            || digest_is_zero(fence.proof_envelope_digest))
    {
        return Err(ManagedModelAgentStackStateError::InvalidState);
    }
    if let Some(high_water) = revision
        && (high_water
            .source_scope
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || high_water.revision == 0
            || digest_is_zero(*high_water.source_plan_digest.value()))
    {
        return Err(ManagedModelAgentStackStateError::InvalidState);
    }
    if let (Some(writer), Some(revision)) = (writer, revision)
        && writer.source_scope != revision.source_scope
    {
        return Err(ManagedModelAgentStackStateError::FenceMismatch);
    }
    Ok(())
}

fn validate_terminals(
    snapshot: &ManagedModelAgentStackSnapshot,
    projection: &ManagedModelAgentStackProjectionV1,
) -> Result<(), ManagedModelAgentStackStateError> {
    let mut prior_key = None;
    for terminal in &snapshot.terminals {
        let key = (
            *terminal.source_scope.as_bytes(),
            *terminal.operation_id.as_bytes(),
        );
        let facts = terminal.receipt.facts();
        let evidence = facts.evidence().fields();
        let state = facts.state();
        if prior_key.is_some_and(|prior| prior >= key)
            || facts.source_scope() != terminal.source_scope
            || facts.operation_id() != terminal.operation_id
            || facts.request_digest() != terminal.request_digest
            || facts.runtime_store_instance_id() != snapshot.store_instance_id
            || facts.target() != projection.target()
            || evidence.completion_snapshot_sequence > snapshot.sequence
            || evidence.completion_runtime_host_epoch > snapshot.runtime_host_epoch
            || state.fabric_generation().is_some_and(|generation| {
                generation.value() > snapshot.fabric_generation_high_water
            })
            || state
                .model_generation()
                .is_some_and(|generation| generation.value() > snapshot.model_generation_high_water)
            || state
                .agent_generation()
                .is_some_and(|generation| generation.value() > snapshot.agent_generation_high_water)
        {
            return Err(ManagedModelAgentStackStateError::InvalidState);
        }
        prior_key = Some(key);
    }
    Ok(())
}

fn validate_phase_shape(
    snapshot: &ManagedModelAgentStackSnapshot,
) -> Result<(), ManagedModelAgentStackStateError> {
    let pending = snapshot.pending.as_ref();
    let valid = match snapshot.phase {
        ManagedModelAgentStackDurablePhase::ExactZero => {
            snapshot.active.is_none()
                && pending.is_none()
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && !snapshot.fabric_ready
                && !snapshot.model_ready
                && !snapshot.agent_ready
                && !snapshot.fabric_to_agent_dependency_ready
                && !snapshot.model_to_agent_dependency_ready
                && snapshot.quarantine_reason.is_none()
        }
        ManagedModelAgentStackDurablePhase::ModelStartIntent => {
            snapshot.active.is_none()
                && pending.is_some_and(|pending| {
                    pending.kind == ManagedModelAgentStackPendingKind::ActivateStack
                        && pending.fabric_generation.is_some()
                        && pending.model_generation.is_some()
                        && pending.agent_generation.is_none()
                })
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && !snapshot.model_ready
                && !snapshot.agent_ready
                && snapshot.fabric_to_agent_dependency_ready
                && !snapshot.model_to_agent_dependency_ready
                && snapshot.quarantine_reason.is_none()
        }
        ManagedModelAgentStackDurablePhase::AgentStartIntent => {
            snapshot.active.is_none()
                && pending.is_some_and(|pending| {
                    pending.kind == ManagedModelAgentStackPendingKind::ActivateStack
                        && pending.fabric_generation.is_some()
                        && pending.model_generation.is_some()
                        && pending.agent_generation.is_some()
                })
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && snapshot.model_ready
                && !snapshot.agent_ready
                && snapshot.fabric_to_agent_dependency_ready
                && snapshot.model_to_agent_dependency_ready
                && snapshot.quarantine_reason.is_none()
        }
        ManagedModelAgentStackDurablePhase::ActiveReady => {
            snapshot.active.is_some()
                && pending.is_none()
                && snapshot.physical_binding_census == 2
                && snapshot.census_complete
                && snapshot.fabric_ready
                && snapshot.model_ready
                && snapshot.agent_ready
                && snapshot.fabric_to_agent_dependency_ready
                && snapshot.model_to_agent_dependency_ready
                && snapshot.quarantine_reason.is_none()
        }
        ManagedModelAgentStackDurablePhase::AgentRetireIntent => {
            deactivation_matches_active(snapshot)
                && snapshot.physical_binding_census == 2
                && snapshot.census_complete
                && snapshot.fabric_ready
                && snapshot.model_ready
                && snapshot.agent_ready
                && snapshot.fabric_to_agent_dependency_ready
                && snapshot.model_to_agent_dependency_ready
                && snapshot.quarantine_reason.is_none()
        }
        ManagedModelAgentStackDurablePhase::ModelRetireIntent => {
            deactivation_matches_active(snapshot)
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && snapshot.model_ready
                && !snapshot.agent_ready
                && !snapshot.fabric_to_agent_dependency_ready
                && !snapshot.model_to_agent_dependency_ready
                && snapshot.quarantine_reason.is_none()
        }
        ManagedModelAgentStackDurablePhase::FabricStopIntent => {
            deactivation_matches_active(snapshot)
                && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && !snapshot.model_ready
                && !snapshot.agent_ready
                && !snapshot.fabric_to_agent_dependency_ready
                && !snapshot.model_to_agent_dependency_ready
                && snapshot.quarantine_reason.is_none()
        }
        ManagedModelAgentStackDurablePhase::RecoveryIntent => {
            pending.is_some_and(|pending| {
                pending.kind == ManagedModelAgentStackPendingKind::RecoverActive
                    && pending.fabric_generation.is_some()
                    && pending.model_generation.is_some()
                    && pending.agent_generation.is_some()
                    && recovery_matches_active(snapshot, pending)
            }) && snapshot.physical_binding_census == 0
                && snapshot.census_complete
                && snapshot.fabric_ready
                && snapshot.model_ready
                && !snapshot.agent_ready
                && snapshot.fabric_to_agent_dependency_ready
                && snapshot.model_to_agent_dependency_ready
                && snapshot.quarantine_reason.is_none()
        }
        ManagedModelAgentStackDurablePhase::Uncertain => {
            pending.is_some() && !snapshot.census_complete && snapshot.quarantine_reason.is_none()
        }
        ManagedModelAgentStackDurablePhase::Quarantined => {
            snapshot.quarantine_reason.is_some()
                && !snapshot.agent_ready
                && !snapshot.fabric_to_agent_dependency_ready
                && !snapshot.model_to_agent_dependency_ready
        }
    };
    valid
        .then_some(())
        .ok_or(ManagedModelAgentStackStateError::InvalidState)
}

fn deactivation_matches_active(snapshot: &ManagedModelAgentStackSnapshot) -> bool {
    let (Some(active), Some(pending)) = (&snapshot.active, &snapshot.pending) else {
        return false;
    };
    pending.kind == ManagedModelAgentStackPendingKind::DeactivateStack
        && pending.fabric_generation == Some(active.fabric_generation)
        && pending.model_generation == Some(active.model_generation)
        && pending.agent_generation == Some(active.agent_generation)
}

fn recovery_matches_active(
    snapshot: &ManagedModelAgentStackSnapshot,
    pending: &ManagedModelAgentStackDurablePending,
) -> bool {
    let Some(active) = &snapshot.active else {
        return true;
    };
    pending.fabric_generation == Some(active.fabric_generation)
        && pending.model_generation == Some(active.model_generation)
        && pending.agent_generation == Some(active.agent_generation)
        && pending.response_channel == active.response_channel
        && pending.request == active.request
}

fn optional_generation_within(
    generation: Option<ManagedServiceGeneration>,
    high_water: u64,
) -> bool {
    generation.is_none_or(|generation| generation.value() <= high_water)
}

fn writer_fence_advances(
    current: Option<ManagedModelAgentStackWriterFence>,
    next: Option<ManagedModelAgentStackWriterFence>,
) -> bool {
    match (current, next) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(current), Some(next)) => {
            current.source_scope == next.source_scope
                && (next.epoch > current.epoch || (next.epoch == current.epoch && next == current))
        }
    }
}

fn revision_advances(
    current: Option<ManagedModelAgentStackRevisionHighWater>,
    next: Option<ManagedModelAgentStackRevisionHighWater>,
) -> bool {
    match (current, next) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(current), Some(next)) => {
            current.source_scope == next.source_scope
                && (next.revision > current.revision
                    || (next.revision == current.revision && next == current))
        }
    }
}

fn retains_replays(
    current: &[ManagedModelAgentStackReplayRecord],
    next: &[ManagedModelAgentStackReplayRecord],
) -> bool {
    current
        .iter()
        .all(|record| next.binary_search(record).is_ok())
}

fn retains_terminals(
    current: &[ManagedModelAgentStackTerminalRecord],
    next: &[ManagedModelAgentStackTerminalRecord],
) -> bool {
    current.iter().all(|record| {
        next.iter().any(|candidate| {
            candidate.source_scope == record.source_scope
                && candidate.operation_id == record.operation_id
                && candidate == record
        })
    })
}

fn validate_sorted_replays(
    records: &[ManagedModelAgentStackReplayRecord],
) -> Result<(), ManagedModelAgentStackStateError> {
    let mut prior = None;
    for record in records {
        if digest_is_zero(record.identity)
            || digest_is_zero(record.value_digest)
            || prior.is_some_and(|value| value >= record.identity)
        {
            return Err(ManagedModelAgentStackStateError::InvalidState);
        }
        prior = Some(record.identity);
    }
    Ok(())
}

fn encode_writer_fence(encoder: &mut Encoder, value: Option<ManagedModelAgentStackWriterFence>) {
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
) -> Result<Option<ManagedModelAgentStackWriterFence>, ManagedModelAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ManagedModelAgentStackWriterFence {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            writer: PlanWriterRef::from_bytes(cursor.array()?),
            principal: PrincipalRef::from_bytes(cursor.array()?),
            epoch: cursor.u64()?,
            proof_envelope_digest: cursor.digest()?,
        })),
        _ => Err(ManagedModelAgentStackStateError::InvalidPresence),
    }
}

fn encode_revision_high_water(
    encoder: &mut Encoder,
    value: Option<ManagedModelAgentStackRevisionHighWater>,
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
) -> Result<Option<ManagedModelAgentStackRevisionHighWater>, ManagedModelAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ManagedModelAgentStackRevisionHighWater {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            revision: cursor.u64()?,
            source_plan_digest: SourcePlanDigest::new(cursor.digest()?),
        })),
        _ => Err(ManagedModelAgentStackStateError::InvalidPresence),
    }
}

fn encode_active(
    encoder: &mut Encoder,
    value: Option<&ManagedModelAgentStackDurableActive>,
) -> Result<(), ManagedModelAgentStackStateError> {
    let Some(value) = value else {
        encoder.u8(0);
        return Ok(());
    };
    encoder.u8(1);
    encoder.u64(value.fabric_generation.value());
    encoder.u64(value.model_generation.value());
    encoder.u64(value.agent_generation.value());
    encode_channel(encoder, value.response_channel);
    encoder.bounded(value.request.canonical_wire())?;
    Ok(())
}

fn decode_active(
    cursor: &mut Cursor<'_>,
) -> Result<Option<ManagedModelAgentStackDurableActive>, ManagedModelAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ManagedModelAgentStackDurableActive {
            fabric_generation: decode_generation(cursor)?,
            model_generation: decode_generation(cursor)?,
            agent_generation: decode_generation(cursor)?,
            response_channel: decode_channel(cursor)?,
            request: ManagedModelAgentStackApplyRequestV1::decode(
                cursor.bounded(MAX_MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_BYTES)?,
            )
            .map_err(|_| ManagedModelAgentStackStateError::InvalidNestedContract)?,
        })),
        _ => Err(ManagedModelAgentStackStateError::InvalidPresence),
    }
}

fn encode_pending(
    encoder: &mut Encoder,
    value: Option<&ManagedModelAgentStackDurablePending>,
) -> Result<(), ManagedModelAgentStackStateError> {
    let Some(value) = value else {
        encoder.u8(0);
        return Ok(());
    };
    encoder.u8(1);
    encoder.u8(value.kind as u8);
    encode_optional_generation(encoder, value.fabric_generation);
    encode_optional_generation(encoder, value.model_generation);
    encode_optional_generation(encoder, value.agent_generation);
    encoder.u64(value.admitted_clock_generation.value());
    encoder.u64(value.admitted_at_nanos);
    encoder.u64(value.deadline_nanos);
    encode_channel(encoder, value.response_channel);
    encoder.bounded(value.request.canonical_wire())?;
    Ok(())
}

fn decode_pending(
    cursor: &mut Cursor<'_>,
) -> Result<Option<ManagedModelAgentStackDurablePending>, ManagedModelAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ManagedModelAgentStackDurablePending {
            kind: ManagedModelAgentStackPendingKind::decode(cursor.u8()?)?,
            fabric_generation: decode_optional_generation(cursor)?,
            model_generation: decode_optional_generation(cursor)?,
            agent_generation: decode_optional_generation(cursor)?,
            admitted_clock_generation: ClockGeneration::try_new(cursor.u64()?)
                .map_err(|_| ManagedModelAgentStackStateError::InvalidState)?,
            admitted_at_nanos: cursor.u64()?,
            deadline_nanos: cursor.u64()?,
            response_channel: decode_channel(cursor)?,
            request: ManagedModelAgentStackApplyRequestV1::decode(
                cursor.bounded(MAX_MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_BYTES)?,
            )
            .map_err(|_| ManagedModelAgentStackStateError::InvalidNestedContract)?,
        })),
        _ => Err(ManagedModelAgentStackStateError::InvalidPresence),
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
) -> Result<ReferenceChannelBindingV1, ManagedModelAgentStackStateError> {
    ReferenceChannelBindingV1::try_new(
        RuntimeHostId::from_bytes(cursor.array()?),
        PrincipalRef::from_bytes(cursor.array()?),
        cursor.digest()?,
        cursor.digest()?,
    )
    .map_err(|_| ManagedModelAgentStackStateError::InvalidNestedContract)
}

fn encode_replay_records(
    encoder: &mut Encoder,
    records: &[ManagedModelAgentStackReplayRecord],
) -> Result<(), ManagedModelAgentStackStateError> {
    encoder.count(records.len())?;
    for record in records {
        encoder.digest(record.identity);
        encoder.digest(record.value_digest);
    }
    Ok(())
}

fn decode_replay_records(
    cursor: &mut Cursor<'_>,
) -> Result<Vec<ManagedModelAgentStackReplayRecord>, ManagedModelAgentStackStateError> {
    let count = cursor.count(MAX_REPLAY_ENTRIES)?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(ManagedModelAgentStackReplayRecord {
            identity: cursor.digest()?,
            value_digest: cursor.digest()?,
        });
    }
    Ok(records)
}

fn encode_terminals(
    encoder: &mut Encoder,
    terminals: &[ManagedModelAgentStackTerminalRecord],
) -> Result<(), ManagedModelAgentStackStateError> {
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
) -> Result<Vec<ManagedModelAgentStackTerminalRecord>, ManagedModelAgentStackStateError> {
    let count = cursor.count(MAX_TERMINALS)?;
    let mut terminals = Vec::with_capacity(count);
    for _ in 0..count {
        terminals.push(ManagedModelAgentStackTerminalRecord {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            operation_id: ApplyOperationId::from_bytes(cursor.array()?),
            request_digest: cursor.digest()?,
            receipt: ManagedModelAgentStackTerminalReceiptV1::decode(
                cursor.bounded(MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_BYTES)?,
            )
            .map_err(|_| ManagedModelAgentStackStateError::InvalidNestedContract)?,
        });
    }
    Ok(terminals)
}

fn encode_optional_generation(encoder: &mut Encoder, generation: Option<ManagedServiceGeneration>) {
    encoder.u64(generation.map_or(0, ManagedServiceGeneration::value));
}

fn decode_generation(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedServiceGeneration, ManagedModelAgentStackStateError> {
    ManagedServiceGeneration::try_new(cursor.u64()?)
        .map_err(|_| ManagedModelAgentStackStateError::InvalidState)
}

fn decode_optional_generation(
    cursor: &mut Cursor<'_>,
) -> Result<Option<ManagedServiceGeneration>, ManagedModelAgentStackStateError> {
    let value = cursor.u64()?;
    if value == 0 {
        Ok(None)
    } else {
        ManagedServiceGeneration::try_new(value)
            .map(Some)
            .map_err(|_| ManagedModelAgentStackStateError::InvalidState)
    }
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
) -> Result<Option<Digest32>, ManagedModelAgentStackStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(cursor.digest()?)),
        _ => Err(ManagedModelAgentStackStateError::InvalidPresence),
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

fn decode_bool(value: u8) -> Result<bool, ManagedModelAgentStackStateError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ManagedModelAgentStackStateError::NonCanonicalEncoding),
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

    fn count(&mut self, value: usize) -> Result<(), ManagedModelAgentStackStateError> {
        let value =
            u16::try_from(value).map_err(|_| ManagedModelAgentStackStateError::FrameTooLarge)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn bounded(&mut self, value: &[u8]) -> Result<(), ManagedModelAgentStackStateError> {
        let length = u32::try_from(value.len())
            .map_err(|_| ManagedModelAgentStackStateError::FrameTooLarge)?;
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], ManagedModelAgentStackStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ManagedModelAgentStackStateError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ManagedModelAgentStackStateError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ManagedModelAgentStackStateError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ManagedModelAgentStackStateError> {
        Ok(read_u16(self.take(2)?))
    }

    fn u32(&mut self) -> Result<u32, ManagedModelAgentStackStateError> {
        Ok(read_u32(self.take(4)?))
    }

    fn u64(&mut self) -> Result<u64, ManagedModelAgentStackStateError> {
        Ok(read_u64(self.take(8)?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManagedModelAgentStackStateError> {
        Ok(read_array(self.take(N)?))
    }

    fn digest(&mut self) -> Result<Digest32, ManagedModelAgentStackStateError> {
        Ok(Digest32::from_bytes(self.array()?))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, ManagedModelAgentStackStateError> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            return Err(ManagedModelAgentStackStateError::FrameTooLarge);
        }
        Ok(count)
    }

    fn bounded(&mut self, maximum: usize) -> Result<&'a [u8], ManagedModelAgentStackStateError> {
        let length = self.u32()? as usize;
        if length == 0 || length > maximum {
            return Err(ManagedModelAgentStackStateError::FrameTooLarge);
        }
        self.take(length)
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedModelAgentStackStateError {
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
    FenceMismatch,
    FenceRegression,
    SequenceOverflow,
    TrailingBytes,
}

impl fmt::Display for ManagedModelAgentStackStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed Model/Agent-stack state failed: {self:?}"
        )
    }
}

impl std::error::Error for ManagedModelAgentStackStateError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentStackProjectionV1;
    use paraegox_runtime_contracts::managed_model_agent_stack_plan::ManagedModelAgentStackProjectionV1;

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

    fn projection() -> ManagedModelAgentStackProjectionV1 {
        let needle = "\"projection_pxsp_hex\": \"";
        let start = FIXTURE
            .find(needle)
            .map(|offset| offset + needle.len())
            .unwrap_or_else(|| panic!("fixture projection is missing"));
        let end = FIXTURE[start..]
            .find('"')
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("fixture projection is unterminated"));
        let predecessor = ManagedAgentStackProjectionV1::decode(&decode_hex(&FIXTURE[start..end]))
            .unwrap_or_else(|error| panic!("predecessor projection rejected: {error}"));
        ManagedModelAgentStackProjectionV1::try_from_managed_agent_stack_projection(predecessor)
            .unwrap_or_else(|error| panic!("Model/Agent projection rejected: {error}"))
    }

    fn exact_zero_transition() -> ManagedModelAgentStackSnapshotTransition {
        ManagedModelAgentStackSnapshotTransition {
            fabric_generation_high_water: 7,
            model_generation_high_water: 8,
            agent_generation_high_water: 9,
            phase: ManagedModelAgentStackDurablePhase::ExactZero,
            writer_fence: None,
            revision_high_water: None,
            active: None,
            pending: None,
            tenure_nonces: Vec::new(),
            request_nonces: Vec::new(),
            temporal_lineages: Vec::new(),
            terminals: Vec::new(),
            physical_binding_census: 0,
            census_complete: true,
            fabric_ready: false,
            model_ready: false,
            agent_ready: false,
            fabric_to_agent_dependency_ready: false,
            model_to_agent_dependency_ready: false,
            quarantine_reason: None,
        }
    }

    fn initial_exact_zero() -> ManagedModelAgentStackSnapshot {
        ManagedModelAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            RUNTIME_EPOCH,
            exact_zero_transition(),
            &projection(),
        )
        .unwrap_or_else(|error| panic!("valid exact-zero snapshot rejected: {error}"))
    }

    #[test]
    fn snapshot_roundtrip_identity_and_old_wire_rejection_are_strict() {
        let snapshot = initial_exact_zero();
        let decoded = ManagedModelAgentStackSnapshot::decode(
            snapshot.canonical_wire(),
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            &projection(),
        )
        .unwrap_or_else(|error| panic!("restart decode rejected: {error}"));
        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.canonical_wire(), snapshot.canonical_wire());

        for (store, owner, projection_digest) in [
            ([0x45; 32], OWNER, PROJECTION_DIGEST),
            (STORE, Digest32::from_bytes([0x56; 32]), PROJECTION_DIGEST),
            (STORE, OWNER, Digest32::from_bytes([0x67; 32])),
        ] {
            assert_eq!(
                ManagedModelAgentStackSnapshot::decode(
                    snapshot.canonical_wire(),
                    store,
                    owner,
                    projection_digest,
                    &projection(),
                ),
                Err(ManagedModelAgentStackStateError::IdentityMismatch)
            );
        }

        for predecessor in [b"PXAS", b"PXMS", b"PXDA"] {
            let mut predecessor_magic = snapshot.canonical_wire().to_vec();
            predecessor_magic[..4].copy_from_slice(predecessor);
            assert_eq!(
                ManagedModelAgentStackSnapshot::decode(
                    &predecessor_magic,
                    STORE,
                    OWNER,
                    PROJECTION_DIGEST,
                    &projection(),
                ),
                Err(ManagedModelAgentStackStateError::UnsupportedFrame)
            );
        }
    }

    #[test]
    fn checksum_tamper_and_truncation_fail_before_state_is_admitted() {
        let snapshot = initial_exact_zero();
        let mut corrupt = snapshot.canonical_wire().to_vec();
        *corrupt
            .last_mut()
            .unwrap_or_else(|| panic!("snapshot must be nonempty")) ^= 1;
        assert_eq!(
            ManagedModelAgentStackSnapshot::decode(
                &corrupt,
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                &projection(),
            ),
            Err(ManagedModelAgentStackStateError::ChecksumMismatch)
        );
        assert_eq!(
            ManagedModelAgentStackSnapshot::decode(
                &snapshot.canonical_wire()[..SNAPSHOT_HEADER_BYTES - 1],
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                &projection(),
            ),
            Err(ManagedModelAgentStackStateError::Truncated)
        );
    }

    #[test]
    fn phase_readiness_dependency_and_quarantine_facts_fail_closed() {
        let mut missing_pending = exact_zero_transition();
        missing_pending.phase = ManagedModelAgentStackDurablePhase::ModelStartIntent;
        missing_pending.fabric_ready = true;
        missing_pending.fabric_to_agent_dependency_ready = true;
        assert_eq!(
            ManagedModelAgentStackSnapshot::try_initial(
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                RUNTIME_EPOCH,
                missing_pending,
                &projection(),
            ),
            Err(ManagedModelAgentStackStateError::InvalidState)
        );

        let mut impossible_dependency = exact_zero_transition();
        impossible_dependency.fabric_to_agent_dependency_ready = true;
        assert_eq!(
            ManagedModelAgentStackSnapshot::try_initial(
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                RUNTIME_EPOCH,
                impossible_dependency,
                &projection(),
            ),
            Err(ManagedModelAgentStackStateError::InvalidState)
        );

        let mut zero_quarantine = exact_zero_transition();
        zero_quarantine.phase = ManagedModelAgentStackDurablePhase::Quarantined;
        zero_quarantine.quarantine_reason = Some(Digest32::from_bytes([0; 32]));
        assert_eq!(
            ManagedModelAgentStackSnapshot::try_initial(
                STORE,
                OWNER,
                PROJECTION_DIGEST,
                RUNTIME_EPOCH,
                zero_quarantine,
                &projection(),
            ),
            Err(ManagedModelAgentStackStateError::InvalidState)
        );
    }

    #[test]
    fn successor_generation_and_replay_fences_cannot_regress() {
        let mut transition = exact_zero_transition();
        let source_scope = SourceScopeRef::from_bytes([0x78; 16]);
        transition.writer_fence = Some(ManagedModelAgentStackWriterFence {
            source_scope,
            writer: PlanWriterRef::from_bytes([0x79; 16]),
            principal: PrincipalRef::from_bytes([0x7a; 16]),
            epoch: 5,
            proof_envelope_digest: Digest32::from_bytes([0x7b; 32]),
        });
        transition.revision_high_water = Some(ManagedModelAgentStackRevisionHighWater {
            source_scope,
            revision: 7,
            source_plan_digest: SourcePlanDigest::new(Digest32::from_bytes([0x7c; 32])),
        });
        transition
            .request_nonces
            .push(ManagedModelAgentStackReplayRecord {
                identity: Digest32::from_bytes([0x81; 32]),
                value_digest: Digest32::from_bytes([0x82; 32]),
            });
        let snapshot = ManagedModelAgentStackSnapshot::try_initial(
            STORE,
            OWNER,
            PROJECTION_DIGEST,
            RUNTIME_EPOCH,
            transition,
            &projection(),
        )
        .unwrap_or_else(|error| panic!("fenced snapshot rejected: {error}"));

        let mut dropped_replay = snapshot.transition();
        dropped_replay.request_nonces.clear();
        assert_eq!(
            snapshot.try_successor_at_epoch(
                snapshot.runtime_host_epoch,
                dropped_replay,
                &projection(),
            ),
            Err(ManagedModelAgentStackStateError::FenceRegression)
        );

        let mut regressed_generation = snapshot.transition();
        regressed_generation.model_generation_high_water = 7;
        assert_eq!(
            snapshot.try_successor_at_epoch(
                snapshot.runtime_host_epoch,
                regressed_generation,
                &projection(),
            ),
            Err(ManagedModelAgentStackStateError::FenceRegression)
        );

        let mut regressed_writer = snapshot.transition();
        regressed_writer
            .writer_fence
            .as_mut()
            .unwrap_or_else(|| panic!("fixture writer fence must exist"))
            .epoch = 4;
        assert_eq!(
            snapshot.try_successor_at_epoch(
                snapshot.runtime_host_epoch,
                regressed_writer,
                &projection(),
            ),
            Err(ManagedModelAgentStackStateError::FenceRegression)
        );

        let mut regressed_revision = snapshot.transition();
        regressed_revision
            .revision_high_water
            .as_mut()
            .unwrap_or_else(|| panic!("fixture revision high-water must exist"))
            .revision = 6;
        assert_eq!(
            snapshot.try_successor_at_epoch(
                snapshot.runtime_host_epoch,
                regressed_revision,
                &projection(),
            ),
            Err(ManagedModelAgentStackStateError::FenceRegression)
        );
    }
}
