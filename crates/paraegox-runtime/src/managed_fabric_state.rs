#![cfg(unix)]

//! Independent durable state codec for the Runtime-managed Fabric successor.
//!
//! It is intentionally not a payload-v5 journal variant. Every retained PXAR
//! and PXFT value is re-decoded by its strict successor facade during recovery.

use core::fmt;

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::ClockGeneration;
use paraegox_runtime_contracts::apply::{ApplyOperationId, PlanWriterRef};
use paraegox_runtime_contracts::managed_fabric_plan::{
    MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES, MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES,
    ManagedFabricApplyRequestV1, ManagedFabricApplyTerminalReceiptV1,
    ManagedFabricManifestProjectionV1, ManagedFabricTargetModeV1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
use paraegox_runtime_contracts::provenance::{SourcePlanDigest, SourceScopeRef};
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
use sha2::{Digest as ShaDigest, Sha256};

const SNAPSHOT_MAGIC: &[u8; 4] = b"PXMS";
const SNAPSHOT_VERSION: u16 = 1;
const SNAPSHOT_HEADER_BYTES: usize = 168;
const SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES: usize = 136;
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"paraegox.runtime.managed-fabric-snapshot.sha256.v1";
const MAX_TERMINALS: usize = 256;
const MAX_REPLAY_ENTRIES: usize = 256;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ManagedFabricDurablePhase {
    ExactZero = 1,
    ActiveReady = 2,
    StartIntent = 3,
    ReplaceIntent = 4,
    ReplaceOldStopped = 5,
    DeactivateIntent = 6,
    RecoveryIntent = 7,
    Uncertain = 8,
    Quarantined = 9,
}

impl ManagedFabricDurablePhase {
    fn decode(value: u8) -> Result<Self, ManagedFabricStateError> {
        match value {
            1 => Ok(Self::ExactZero),
            2 => Ok(Self::ActiveReady),
            3 => Ok(Self::StartIntent),
            4 => Ok(Self::ReplaceIntent),
            5 => Ok(Self::ReplaceOldStopped),
            6 => Ok(Self::DeactivateIntent),
            7 => Ok(Self::RecoveryIntent),
            8 => Ok(Self::Uncertain),
            9 => Ok(Self::Quarantined),
            _ => Err(ManagedFabricStateError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ManagedFabricPendingKind {
    Start = 1,
    Replace = 2,
    Deactivate = 3,
    RecoverActive = 4,
}

impl ManagedFabricPendingKind {
    fn decode(value: u8) -> Result<Self, ManagedFabricStateError> {
        match value {
            1 => Ok(Self::Start),
            2 => Ok(Self::Replace),
            3 => Ok(Self::Deactivate),
            4 => Ok(Self::RecoverActive),
            _ => Err(ManagedFabricStateError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricWriterFence {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) writer: PlanWriterRef,
    pub(crate) principal: PrincipalRef,
    pub(crate) epoch: u64,
    pub(crate) proof_envelope_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricRevisionHighWater {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) revision: u64,
    pub(crate) source_plan_digest: SourcePlanDigest,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ManagedFabricReplayRecord {
    pub(crate) identity: Digest32,
    pub(crate) value_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricDurableActive {
    pub(crate) generation: ManagedServiceGeneration,
    pub(crate) response_channel: ReferenceChannelBindingV1,
    pub(crate) request: ManagedFabricApplyRequestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricDurablePending {
    pub(crate) kind: ManagedFabricPendingKind,
    pub(crate) generation: Option<ManagedServiceGeneration>,
    pub(crate) admitted_clock_generation: ClockGeneration,
    pub(crate) admitted_at_nanos: u64,
    pub(crate) deadline_nanos: u64,
    pub(crate) response_channel: ReferenceChannelBindingV1,
    pub(crate) request: ManagedFabricApplyRequestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricTerminalRecord {
    pub(crate) source_scope: SourceScopeRef,
    pub(crate) operation_id: ApplyOperationId,
    pub(crate) request_digest: Digest32,
    pub(crate) receipt: ManagedFabricApplyTerminalReceiptV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricSnapshotTransition {
    pub(crate) generation_high_water: u64,
    pub(crate) phase: ManagedFabricDurablePhase,
    pub(crate) writer_fence: Option<ManagedFabricWriterFence>,
    pub(crate) revision_high_water: Option<ManagedFabricRevisionHighWater>,
    pub(crate) active: Option<ManagedFabricDurableActive>,
    pub(crate) pending: Option<ManagedFabricDurablePending>,
    pub(crate) tenure_nonces: Vec<ManagedFabricReplayRecord>,
    pub(crate) request_nonces: Vec<ManagedFabricReplayRecord>,
    pub(crate) temporal_lineages: Vec<ManagedFabricReplayRecord>,
    pub(crate) terminals: Vec<ManagedFabricTerminalRecord>,
    pub(crate) quarantine_reason: Option<Digest32>,
}

#[derive(Clone, Copy)]
struct ManagedFabricSnapshotIdentity {
    store_instance_id: [u8; 32],
    owner_target_fingerprint: Digest32,
    transition_projection_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricSnapshot {
    store_instance_id: [u8; 32],
    owner_target_fingerprint: Digest32,
    transition_projection_digest: Digest32,
    sequence: u64,
    generation_high_water: u64,
    runtime_host_epoch: u64,
    pub(crate) phase: ManagedFabricDurablePhase,
    pub(crate) writer_fence: Option<ManagedFabricWriterFence>,
    pub(crate) revision_high_water: Option<ManagedFabricRevisionHighWater>,
    pub(crate) active: Option<ManagedFabricDurableActive>,
    pub(crate) pending: Option<ManagedFabricDurablePending>,
    pub(crate) tenure_nonces: Vec<ManagedFabricReplayRecord>,
    pub(crate) request_nonces: Vec<ManagedFabricReplayRecord>,
    pub(crate) temporal_lineages: Vec<ManagedFabricReplayRecord>,
    pub(crate) terminals: Vec<ManagedFabricTerminalRecord>,
    pub(crate) quarantine_reason: Option<Digest32>,
    canonical_wire: Box<[u8]>,
}

impl ManagedFabricSnapshot {
    pub(crate) fn try_initial(
        store_instance_id: [u8; 32],
        owner_target_fingerprint: Digest32,
        transition_projection_digest: Digest32,
        runtime_host_epoch: u64,
        projection: &ManagedFabricManifestProjectionV1,
    ) -> Result<Self, ManagedFabricStateError> {
        Self::try_build(
            ManagedFabricSnapshotIdentity {
                store_instance_id,
                owner_target_fingerprint,
                transition_projection_digest,
            },
            1,
            runtime_host_epoch,
            ManagedFabricSnapshotTransition {
                generation_high_water: 0,
                phase: ManagedFabricDurablePhase::ExactZero,
                writer_fence: None,
                revision_high_water: None,
                active: None,
                pending: None,
                tenure_nonces: Vec::new(),
                request_nonces: Vec::new(),
                temporal_lineages: Vec::new(),
                terminals: Vec::new(),
                quarantine_reason: None,
            },
            projection,
        )
    }

    pub(crate) fn try_successor(
        &self,
        transition: ManagedFabricSnapshotTransition,
        projection: &ManagedFabricManifestProjectionV1,
    ) -> Result<Self, ManagedFabricStateError> {
        self.try_successor_at_epoch(self.runtime_host_epoch, transition, projection)
    }

    pub(crate) fn try_successor_at_epoch(
        &self,
        runtime_host_epoch: u64,
        transition: ManagedFabricSnapshotTransition,
        projection: &ManagedFabricManifestProjectionV1,
    ) -> Result<Self, ManagedFabricStateError> {
        if runtime_host_epoch < self.runtime_host_epoch {
            return Err(ManagedFabricStateError::InvalidState);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ManagedFabricStateError::SequenceOverflow)?;
        Self::try_build(
            ManagedFabricSnapshotIdentity {
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
        identity: ManagedFabricSnapshotIdentity,
        sequence: u64,
        runtime_host_epoch: u64,
        transition: ManagedFabricSnapshotTransition,
        projection: &ManagedFabricManifestProjectionV1,
    ) -> Result<Self, ManagedFabricStateError> {
        let mut snapshot = Self {
            store_instance_id: identity.store_instance_id,
            owner_target_fingerprint: identity.owner_target_fingerprint,
            transition_projection_digest: identity.transition_projection_digest,
            sequence,
            generation_high_water: transition.generation_high_water,
            runtime_host_epoch,
            phase: transition.phase,
            writer_fence: transition.writer_fence,
            revision_high_water: transition.revision_high_water,
            active: transition.active,
            pending: transition.pending,
            tenure_nonces: transition.tenure_nonces,
            request_nonces: transition.request_nonces,
            temporal_lineages: transition.temporal_lineages,
            terminals: transition.terminals,
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
        projection: &ManagedFabricManifestProjectionV1,
    ) -> Result<Self, ManagedFabricStateError> {
        if frame.len() < SNAPSHOT_HEADER_BYTES {
            return Err(ManagedFabricStateError::Truncated);
        }
        if frame.len() > MAX_SNAPSHOT_BYTES {
            return Err(ManagedFabricStateError::FrameTooLarge);
        }
        if &frame[..4] != SNAPSHOT_MAGIC
            || read_u16(&frame[4..6]) != SNAPSHOT_VERSION
            || usize::from(read_u16(&frame[6..8])) != SNAPSHOT_HEADER_BYTES
        {
            return Err(ManagedFabricStateError::UnsupportedFrame);
        }
        let total = read_u32(&frame[8..12]) as usize;
        let payload_len = read_u32(&frame[132..136]) as usize;
        if total != frame.len()
            || SNAPSHOT_HEADER_BYTES.checked_add(payload_len) != Some(frame.len())
        {
            return Err(ManagedFabricStateError::InvalidLength);
        }
        let checksum = snapshot_checksum(
            &frame[..SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES],
            &frame[SNAPSHOT_HEADER_BYTES..],
        );
        if frame[136..168] != *checksum.as_bytes() {
            return Err(ManagedFabricStateError::ChecksumMismatch);
        }
        let store_instance_id = read_array(&frame[20..52]);
        let owner_target_fingerprint = Digest32::from_bytes(read_array(&frame[52..84]));
        let transition_projection_digest = Digest32::from_bytes(read_array(&frame[84..116]));
        if store_instance_id != expected_store_instance_id
            || owner_target_fingerprint != expected_owner_target_fingerprint
            || transition_projection_digest != expected_transition_projection_digest
        {
            return Err(ManagedFabricStateError::IdentityMismatch);
        }
        if frame[125..132].iter().any(|byte| *byte != 0) {
            return Err(ManagedFabricStateError::NonCanonicalEncoding);
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
            return Err(ManagedFabricStateError::TrailingBytes);
        }
        let snapshot = Self::try_build(
            ManagedFabricSnapshotIdentity {
                store_instance_id,
                owner_target_fingerprint,
                transition_projection_digest,
            },
            read_u64(&frame[12..20]),
            runtime_host_epoch,
            ManagedFabricSnapshotTransition {
                generation_high_water: read_u64(&frame[116..124]),
                phase: ManagedFabricDurablePhase::decode(frame[124])?,
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
            return Err(ManagedFabricStateError::NonCanonicalEncoding);
        }
        Ok(snapshot)
    }

    fn validate(
        &self,
        projection: &ManagedFabricManifestProjectionV1,
    ) -> Result<(), ManagedFabricStateError> {
        if self.store_instance_id.iter().all(|byte| *byte == 0)
            || digest_is_zero(self.owner_target_fingerprint)
            || digest_is_zero(self.transition_projection_digest)
            || self.sequence == 0
            || self.runtime_host_epoch == 0
            || self.tenure_nonces.len() > MAX_REPLAY_ENTRIES
            || self.request_nonces.len() > MAX_REPLAY_ENTRIES
            || self.temporal_lineages.len() > MAX_REPLAY_ENTRIES
            || self.terminals.len() > MAX_TERMINALS
        {
            return Err(ManagedFabricStateError::InvalidState);
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
            return Err(ManagedFabricStateError::InvalidState);
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
            return Err(ManagedFabricStateError::InvalidState);
        }
        if let Some(active) = &self.active {
            validate_request(&active.request, self, projection)?;
            if active.request.target_execution().mode()
                != ManagedFabricTargetModeV1::OneManagedFabricService
                || active.response_channel.target() != active.request.target()
                || active.generation.value() > self.generation_high_water
            {
                return Err(ManagedFabricStateError::InvalidState);
            }
        }
        if let Some(pending) = &self.pending {
            validate_request(&pending.request, self, projection)?;
            if pending.deadline_nanos < pending.admitted_at_nanos
                || pending.response_channel.target() != pending.request.target()
            {
                return Err(ManagedFabricStateError::InvalidState);
            }
            match (
                pending.kind,
                pending.generation,
                pending.request.target_execution().mode(),
            ) {
                (
                    ManagedFabricPendingKind::Start
                    | ManagedFabricPendingKind::Replace
                    | ManagedFabricPendingKind::RecoverActive,
                    Some(generation),
                    ManagedFabricTargetModeV1::OneManagedFabricService,
                ) if generation.value() <= self.generation_high_water => {}
                (
                    ManagedFabricPendingKind::Deactivate,
                    None,
                    ManagedFabricTargetModeV1::EmptyDeactivate,
                ) => {}
                _ => return Err(ManagedFabricStateError::InvalidState),
            }
        }
        validate_phase_shape(self)?;
        let mut prior_key = None;
        for terminal in &self.terminals {
            let key = (
                *terminal.source_scope.as_bytes(),
                *terminal.operation_id.as_bytes(),
            );
            if prior_key.is_some_and(|prior| prior >= key)
                || terminal.receipt.source_scope() != terminal.source_scope
                || terminal.receipt.operation_id() != terminal.operation_id
                || terminal.receipt.request_digest() != terminal.request_digest
                || terminal.receipt.runtime_store_instance_id() != self.store_instance_id
                || terminal.receipt.target() != projection.target()
            {
                return Err(ManagedFabricStateError::InvalidState);
            }
            prior_key = Some(key);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, ManagedFabricStateError> {
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
            .ok_or(ManagedFabricStateError::FrameTooLarge)?;
        if total > MAX_SNAPSHOT_BYTES {
            return Err(ManagedFabricStateError::FrameTooLarge);
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
        frame[116..124].copy_from_slice(&self.generation_high_water.to_be_bytes());
        frame[124] = self.phase as u8;
        frame[132..136].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        let checksum =
            snapshot_checksum(&frame[..SNAPSHOT_HEADER_WITHOUT_CHECKSUM_BYTES], &payload);
        frame[136..168].copy_from_slice(checksum.as_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn generation_high_water(&self) -> u64 {
        self.generation_high_water
    }

    #[must_use]
    pub(crate) const fn runtime_host_epoch(&self) -> u64 {
        self.runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn store_instance_id(&self) -> [u8; 32] {
        self.store_instance_id
    }

    #[must_use]
    pub(crate) const fn owner_target_fingerprint(&self) -> Digest32 {
        self.owner_target_fingerprint
    }

    pub(crate) fn transition(&self) -> ManagedFabricSnapshotTransition {
        ManagedFabricSnapshotTransition {
            generation_high_water: self.generation_high_water,
            phase: self.phase,
            writer_fence: self.writer_fence,
            revision_high_water: self.revision_high_water,
            active: self.active.clone(),
            pending: self.pending.clone(),
            tenure_nonces: self.tenure_nonces.clone(),
            request_nonces: self.request_nonces.clone(),
            temporal_lineages: self.temporal_lineages.clone(),
            terminals: self.terminals.clone(),
            quarantine_reason: self.quarantine_reason,
        }
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

fn validate_request(
    request: &ManagedFabricApplyRequestV1,
    snapshot: &ManagedFabricSnapshot,
    projection: &ManagedFabricManifestProjectionV1,
) -> Result<(), ManagedFabricStateError> {
    request
        .validate_expected_store(snapshot.store_instance_id)
        .map_err(|_| ManagedFabricStateError::InvalidState)?;
    request
        .validate_projection(projection)
        .map_err(|_| ManagedFabricStateError::InvalidState)?;
    if request.target() != projection.target() {
        return Err(ManagedFabricStateError::InvalidState);
    }
    Ok(())
}

fn validate_phase_shape(snapshot: &ManagedFabricSnapshot) -> Result<(), ManagedFabricStateError> {
    let valid = match snapshot.phase {
        ManagedFabricDurablePhase::ExactZero => {
            snapshot.active.is_none()
                && snapshot.pending.is_none()
                && snapshot.quarantine_reason.is_none()
        }
        ManagedFabricDurablePhase::ActiveReady => {
            snapshot.active.is_some()
                && snapshot.pending.is_none()
                && snapshot.quarantine_reason.is_none()
        }
        ManagedFabricDurablePhase::StartIntent => {
            snapshot.active.is_none()
                && snapshot
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.kind == ManagedFabricPendingKind::Start)
                && snapshot.quarantine_reason.is_none()
        }
        ManagedFabricDurablePhase::ReplaceIntent => {
            snapshot.active.is_some()
                && snapshot
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.kind == ManagedFabricPendingKind::Replace)
                && snapshot.quarantine_reason.is_none()
        }
        ManagedFabricDurablePhase::ReplaceOldStopped => {
            snapshot.active.is_some()
                && snapshot
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.kind == ManagedFabricPendingKind::Replace)
                && snapshot.quarantine_reason.is_none()
        }
        ManagedFabricDurablePhase::DeactivateIntent => {
            snapshot.active.is_some()
                && snapshot
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.kind == ManagedFabricPendingKind::Deactivate)
                && snapshot.quarantine_reason.is_none()
        }
        ManagedFabricDurablePhase::RecoveryIntent => snapshot
            .pending
            .as_ref()
            .is_some_and(|pending| pending.kind == ManagedFabricPendingKind::RecoverActive),
        ManagedFabricDurablePhase::Uncertain => snapshot.pending.is_some(),
        ManagedFabricDurablePhase::Quarantined => snapshot.quarantine_reason.is_some(),
    };
    valid
        .then_some(())
        .ok_or(ManagedFabricStateError::InvalidState)
}

fn validate_sorted_replays(
    records: &[ManagedFabricReplayRecord],
) -> Result<(), ManagedFabricStateError> {
    let mut prior = None;
    for record in records {
        if digest_is_zero(record.identity)
            || digest_is_zero(record.value_digest)
            || prior.is_some_and(|value| value >= record.identity)
        {
            return Err(ManagedFabricStateError::InvalidState);
        }
        prior = Some(record.identity);
    }
    Ok(())
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

fn encode_writer_fence(encoder: &mut Encoder, value: Option<ManagedFabricWriterFence>) {
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
) -> Result<Option<ManagedFabricWriterFence>, ManagedFabricStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ManagedFabricWriterFence {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            writer: PlanWriterRef::from_bytes(cursor.array()?),
            principal: PrincipalRef::from_bytes(cursor.array()?),
            epoch: cursor.u64()?,
            proof_envelope_digest: cursor.digest()?,
        })),
        _ => Err(ManagedFabricStateError::InvalidPresence),
    }
}

fn encode_revision_high_water(
    encoder: &mut Encoder,
    value: Option<ManagedFabricRevisionHighWater>,
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
) -> Result<Option<ManagedFabricRevisionHighWater>, ManagedFabricStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ManagedFabricRevisionHighWater {
            source_scope: SourceScopeRef::from_bytes(cursor.array()?),
            revision: cursor.u64()?,
            source_plan_digest: SourcePlanDigest::new(cursor.digest()?),
        })),
        _ => Err(ManagedFabricStateError::InvalidPresence),
    }
}

fn encode_active(
    encoder: &mut Encoder,
    value: Option<&ManagedFabricDurableActive>,
) -> Result<(), ManagedFabricStateError> {
    let Some(value) = value else {
        encoder.u8(0);
        return Ok(());
    };
    encoder.u8(1);
    encoder.u64(value.generation.value());
    encode_channel(encoder, value.response_channel);
    encoder.bounded(value.request.canonical_wire())?;
    Ok(())
}

fn decode_active(
    cursor: &mut Cursor<'_>,
) -> Result<Option<ManagedFabricDurableActive>, ManagedFabricStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => {
            let generation = ManagedServiceGeneration::try_new(cursor.u64()?)
                .map_err(|_| ManagedFabricStateError::InvalidState)?;
            let response_channel = decode_channel(cursor)?;
            let wire = cursor.bounded(MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES)?;
            let request = ManagedFabricApplyRequestV1::decode(wire)
                .map_err(|_| ManagedFabricStateError::InvalidNestedContract)?;
            Ok(Some(ManagedFabricDurableActive {
                generation,
                response_channel,
                request,
            }))
        }
        _ => Err(ManagedFabricStateError::InvalidPresence),
    }
}

fn encode_pending(
    encoder: &mut Encoder,
    value: Option<&ManagedFabricDurablePending>,
) -> Result<(), ManagedFabricStateError> {
    let Some(value) = value else {
        encoder.u8(0);
        return Ok(());
    };
    encoder.u8(1);
    encoder.u8(value.kind as u8);
    encoder.u64(value.generation.map_or(0, ManagedServiceGeneration::value));
    encoder.u64(value.admitted_clock_generation.value());
    encoder.u64(value.admitted_at_nanos);
    encoder.u64(value.deadline_nanos);
    encode_channel(encoder, value.response_channel);
    encoder.bounded(value.request.canonical_wire())?;
    Ok(())
}

fn encode_channel(encoder: &mut Encoder, channel: ReferenceChannelBindingV1) {
    encoder.bytes(channel.target().as_bytes());
    encoder.bytes(channel.runtime_peer().as_bytes());
    encoder.digest(channel.local_endpoint_identity_digest());
    encoder.digest(channel.peer_credentials_digest());
}

fn decode_channel(
    cursor: &mut Cursor<'_>,
) -> Result<ReferenceChannelBindingV1, ManagedFabricStateError> {
    ReferenceChannelBindingV1::try_new(
        RuntimeHostId::from_bytes(cursor.array()?),
        PrincipalRef::from_bytes(cursor.array()?),
        cursor.digest()?,
        cursor.digest()?,
    )
    .map_err(|_| ManagedFabricStateError::InvalidNestedContract)
}

fn decode_pending(
    cursor: &mut Cursor<'_>,
) -> Result<Option<ManagedFabricDurablePending>, ManagedFabricStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => {
            let kind = ManagedFabricPendingKind::decode(cursor.u8()?)?;
            let generation_value = cursor.u64()?;
            let generation = if generation_value == 0 {
                None
            } else {
                Some(
                    ManagedServiceGeneration::try_new(generation_value)
                        .map_err(|_| ManagedFabricStateError::InvalidState)?,
                )
            };
            let admitted_clock_generation = ClockGeneration::try_new(cursor.u64()?)
                .map_err(|_| ManagedFabricStateError::InvalidState)?;
            let admitted_at_nanos = cursor.u64()?;
            let deadline_nanos = cursor.u64()?;
            let response_channel = decode_channel(cursor)?;
            let request = ManagedFabricApplyRequestV1::decode(
                cursor.bounded(MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES)?,
            )
            .map_err(|_| ManagedFabricStateError::InvalidNestedContract)?;
            Ok(Some(ManagedFabricDurablePending {
                kind,
                generation,
                admitted_clock_generation,
                admitted_at_nanos,
                deadline_nanos,
                response_channel,
                request,
            }))
        }
        _ => Err(ManagedFabricStateError::InvalidPresence),
    }
}

fn encode_replay_records(
    encoder: &mut Encoder,
    records: &[ManagedFabricReplayRecord],
) -> Result<(), ManagedFabricStateError> {
    encoder.u16(u16::try_from(records.len()).map_err(|_| ManagedFabricStateError::FrameTooLarge)?);
    for record in records {
        encoder.digest(record.identity);
        encoder.digest(record.value_digest);
    }
    Ok(())
}

fn decode_replay_records(
    cursor: &mut Cursor<'_>,
) -> Result<Vec<ManagedFabricReplayRecord>, ManagedFabricStateError> {
    let count = usize::from(cursor.u16()?);
    if count > MAX_REPLAY_ENTRIES {
        return Err(ManagedFabricStateError::FrameTooLarge);
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(ManagedFabricReplayRecord {
            identity: cursor.digest()?,
            value_digest: cursor.digest()?,
        });
    }
    Ok(records)
}

fn encode_terminals(
    encoder: &mut Encoder,
    terminals: &[ManagedFabricTerminalRecord],
) -> Result<(), ManagedFabricStateError> {
    encoder
        .u16(u16::try_from(terminals.len()).map_err(|_| ManagedFabricStateError::FrameTooLarge)?);
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
) -> Result<Vec<ManagedFabricTerminalRecord>, ManagedFabricStateError> {
    let count = usize::from(cursor.u16()?);
    if count > MAX_TERMINALS {
        return Err(ManagedFabricStateError::FrameTooLarge);
    }
    let mut terminals = Vec::with_capacity(count);
    for _ in 0..count {
        let source_scope = SourceScopeRef::from_bytes(cursor.array()?);
        let operation_id = ApplyOperationId::from_bytes(cursor.array()?);
        let request_digest = cursor.digest()?;
        let receipt = ManagedFabricApplyTerminalReceiptV1::decode(
            cursor.bounded(MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES)?,
        )
        .map_err(|_| ManagedFabricStateError::InvalidNestedContract)?;
        terminals.push(ManagedFabricTerminalRecord {
            source_scope,
            operation_id,
            request_digest,
            receipt,
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
) -> Result<Option<Digest32>, ManagedFabricStateError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(cursor.digest()?)),
        _ => Err(ManagedFabricStateError::InvalidPresence),
    }
}

struct Encoder(Vec<u8>);

impl Encoder {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
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

    fn bounded(&mut self, value: &[u8]) -> Result<(), ManagedFabricStateError> {
        let length =
            u32::try_from(value.len()).map_err(|_| ManagedFabricStateError::FrameTooLarge)?;
        self.0.extend_from_slice(&length.to_be_bytes());
        self.bytes(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

struct Cursor<'a> {
    frame: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ManagedFabricStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ManagedFabricStateError::InvalidLength)?;
        let value = self
            .frame
            .get(self.offset..end)
            .ok_or(ManagedFabricStateError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ManagedFabricStateError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ManagedFabricStateError> {
        Ok(read_u16(self.take(2)?))
    }

    fn u64(&mut self) -> Result<u64, ManagedFabricStateError> {
        Ok(read_u64(self.take(8)?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManagedFabricStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ManagedFabricStateError::Truncated)
    }

    fn digest(&mut self) -> Result<Digest32, ManagedFabricStateError> {
        Ok(Digest32::from_bytes(self.array()?))
    }

    fn bounded(&mut self, maximum: usize) -> Result<&'a [u8], ManagedFabricStateError> {
        let length = read_u32(self.take(4)?) as usize;
        if length == 0 || length > maximum {
            return Err(ManagedFabricStateError::InvalidLength);
        }
        self.take(length)
    }

    fn done(&self) -> bool {
        self.offset == self.frame.len()
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
    bytes
        .try_into()
        .expect("fixed snapshot range must match its array width")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedFabricStateError {
    FrameTooLarge,
    Truncated,
    UnsupportedFrame,
    InvalidLength,
    ChecksumMismatch,
    IdentityMismatch,
    UnknownEnumValue,
    InvalidPresence,
    InvalidNestedContract,
    InvalidState,
    SequenceOverflow,
    NonCanonicalEncoding,
    TrailingBytes,
}

impl fmt::Display for ManagedFabricStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FrameTooLarge => "managed-fabric snapshot is too large",
            Self::Truncated => "managed-fabric snapshot is truncated",
            Self::UnsupportedFrame => "unsupported managed-fabric snapshot",
            Self::InvalidLength => "invalid managed-fabric snapshot length",
            Self::ChecksumMismatch => "managed-fabric snapshot checksum mismatch",
            Self::IdentityMismatch => "managed-fabric snapshot identity mismatch",
            Self::UnknownEnumValue => "unknown managed-fabric snapshot enum",
            Self::InvalidPresence => "invalid managed-fabric snapshot presence",
            Self::InvalidNestedContract => "invalid nested managed-fabric contract",
            Self::InvalidState => "invalid managed-fabric durable state",
            Self::SequenceOverflow => "managed-fabric snapshot sequence overflow",
            Self::NonCanonicalEncoding => "non-canonical managed-fabric snapshot",
            Self::TrailingBytes => "managed-fabric snapshot has trailing bytes",
        })
    }
}

impl std::error::Error for ManagedFabricStateError {}
