//! Canonical Controller extension state for a two-target distributed rollout.
//!
//! This is not a second filesystem owner. The caller places every encoded
//! snapshot inside the existing Controller atomic-replace and fsync boundary;
//! this module publishes no in-memory successor until that callback succeeds.
//!
//! PXDJ v2 remains the exact local PXAR/PXDS v1 layout. The additive PXDJ v3
//! layout exists only after an atomic two-target restricted claim and stores
//! exact PXRC/PXDS v2 values. Reopen accepts and reauthenticates both versions;
//! the only cross-version successor is v2 PendingNotSent -> v3 pair-Uncertain.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DistributedAgentStackApplyRequestV1, DistributedAgentStackPlanError,
    DistributedAgentStackRestrictedApplyRequestV1, DistributedAgentStackTerminalFactsV1,
    DistributedAgentStackTerminalOutcomeV1, DistributedAgentStackTerminalReceiptV1,
    DistributedAgentStackTerminalReceiptV2,
};

use crate::distributed_agent_stack_producer::{
    DistributedAgentStackProducerError, DistributedAgentStackRolloutIdV1,
    DistributedAgentStackRolloutV1, VerifiedDistributedAgentStackPredecessorV1,
    VerifiedDistributedAgentStackRestrictedApplyV1, VerifiedDistributedAgentStackTerminalV1,
    VerifiedDistributedAgentStackTerminalV2, validate_distributed_agent_stack_restricted_apply_v1,
    validate_distributed_agent_stack_terminal_v1, validate_distributed_agent_stack_terminal_v2,
};

const STATE_MAGIC: &[u8; 4] = b"PXDJ";
const STATE_VERSION_V2: u16 = 2;
const STATE_VERSION_V3: u16 = 3;
const STATE_HEADER_BYTES: usize = 74;
const TARGET_HEADER_V2_BYTES: usize = 28;
const TARGET_HEADER_V3_BYTES: usize = 36;
const STATE_CHECKSUM_BYTES: usize = 32;
const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
const STATE_CHECKSUM_DOMAIN_V2: &[u8] =
    b"paraegox.deployment.distributed-agent-stack.state.checksum.sha256.v2";
const STATE_CHECKSUM_DOMAIN_V3: &[u8] =
    b"paraegox.deployment.distributed-agent-stack.state.checksum.sha256.v3";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DistributedAgentStackTargetPhaseV1 {
    RequestDurableNotSent,
    Uncertain,
    ReceiptDurable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DistributedAgentStackRolloutStatusV1 {
    PendingNotSent,
    Uncertain,
    TerminalNonReady,
    IndeterminateUncertain,
    ActiveReady,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackTargetStateV1 {
    target: RuntimeHostId,
    phase: DistributedAgentStackTargetPhaseV1,
    request: DistributedAgentStackApplyRequestV1,
    receipt: Option<DistributedAgentStackTerminalReceiptV1>,
    restricted_request: Option<DistributedAgentStackRestrictedApplyRequestV1>,
    restricted_receipt: Option<DistributedAgentStackTerminalReceiptV2>,
}

/// Predecessor-independent structural view used only by the enclosing
/// Controller journal. Full reopen still reauthenticates both PXAR/PXDS rows
/// against their committed predecessors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackStateWireCoordinateV1 {
    wire_version: u16,
    sequence: u64,
    owner_anchor: Digest32,
    rollout_id: DistributedAgentStackRolloutIdV1,
    revision: u64,
    targets: [DistributedAgentStackTargetStateV1; 2],
}

impl DistributedAgentStackStateWireCoordinateV1 {
    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn owner_anchor(&self) -> Digest32 {
        self.owner_anchor
    }

    #[must_use]
    pub(crate) const fn rollout_id(&self) -> DistributedAgentStackRolloutIdV1 {
        self.rollout_id
    }

    #[must_use]
    pub(crate) const fn targets(&self) -> [RuntimeHostId; 2] {
        [self.targets[0].target, self.targets[1].target]
    }
}

impl DistributedAgentStackTargetStateV1 {
    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> DistributedAgentStackTargetPhaseV1 {
        self.phase
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &DistributedAgentStackApplyRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> Option<&DistributedAgentStackTerminalReceiptV1> {
        self.receipt.as_ref()
    }

    #[must_use]
    pub(crate) const fn restricted_request(
        &self,
    ) -> Option<&DistributedAgentStackRestrictedApplyRequestV1> {
        self.restricted_request.as_ref()
    }

    #[must_use]
    pub(crate) const fn restricted_receipt(
        &self,
    ) -> Option<&DistributedAgentStackTerminalReceiptV2> {
        self.restricted_receipt.as_ref()
    }

    #[must_use]
    pub(crate) const fn terminal_facts(&self) -> Option<&DistributedAgentStackTerminalFactsV1> {
        match (&self.receipt, &self.restricted_receipt) {
            (Some(receipt), None) => Some(receipt.facts()),
            (None, Some(receipt)) => Some(receipt.facts()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackControllerStateV1 {
    sequence: u64,
    owner_anchor: Digest32,
    rollout: DistributedAgentStackRolloutV1,
    targets: [DistributedAgentStackTargetStateV1; 2],
}

impl DistributedAgentStackControllerStateV1 {
    pub(crate) fn try_new(
        owner_anchor: Digest32,
        rollout: DistributedAgentStackRolloutV1,
    ) -> Result<Self, DistributedAgentStackStoreError> {
        if digest_is_zero(owner_anchor) {
            return Err(DistributedAgentStackStoreError::OwnerMismatch);
        }
        let targets =
            rollout
                .requests()
                .clone()
                .map(|request| DistributedAgentStackTargetStateV1 {
                    target: request.target(),
                    phase: DistributedAgentStackTargetPhaseV1::RequestDurableNotSent,
                    request,
                    receipt: None,
                    restricted_request: None,
                    restricted_receipt: None,
                });
        let state = Self {
            sequence: 1,
            owner_anchor,
            rollout,
            targets,
        };
        validate_state_shape(&state)?;
        Ok(state)
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn owner_anchor(&self) -> Digest32 {
        self.owner_anchor
    }

    #[must_use]
    pub(crate) const fn rollout(&self) -> &DistributedAgentStackRolloutV1 {
        &self.rollout
    }

    #[must_use]
    pub(crate) const fn targets(&self) -> &[DistributedAgentStackTargetStateV1; 2] {
        &self.targets
    }

    #[must_use]
    pub(crate) fn target(
        &self,
        target: RuntimeHostId,
    ) -> Option<&DistributedAgentStackTargetStateV1> {
        self.targets.iter().find(|row| row.target == target)
    }

    #[must_use]
    pub(crate) fn status(&self) -> DistributedAgentStackRolloutStatusV1 {
        if self.targets.iter().any(|row| {
            row.terminal_facts().is_some_and(|facts| {
                facts.outcome() == DistributedAgentStackTerminalOutcomeV1::TerminalNonReady
            })
        }) {
            DistributedAgentStackRolloutStatusV1::TerminalNonReady
        } else if self.targets.iter().any(|row| {
            row.terminal_facts().is_some_and(|facts| {
                facts.outcome() == DistributedAgentStackTerminalOutcomeV1::IndeterminateUncertain
            })
        }) {
            DistributedAgentStackRolloutStatusV1::IndeterminateUncertain
        } else if active_ready_pair_is_reciprocal(self) {
            DistributedAgentStackRolloutStatusV1::ActiveReady
        } else if self
            .targets
            .iter()
            .any(|row| row.phase != DistributedAgentStackTargetPhaseV1::RequestDurableNotSent)
        {
            DistributedAgentStackRolloutStatusV1::Uncertain
        } else {
            DistributedAgentStackRolloutStatusV1::PendingNotSent
        }
    }

    pub(crate) fn try_claim_target(
        &self,
        target: RuntimeHostId,
    ) -> Result<Self, DistributedAgentStackStoreError> {
        let index = self.target_index(target)?;
        if self.targets[index].phase != DistributedAgentStackTargetPhaseV1::RequestDurableNotSent
            || self.targets[index].receipt.is_some()
            || self
                .targets
                .iter()
                .any(|row| row.restricted_request.is_some() || row.restricted_receipt.is_some())
        {
            return Err(DistributedAgentStackStoreError::InvalidPhase);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.targets[index].phase = DistributedAgentStackTargetPhaseV1::Uncertain;
        validate_state_shape(&next)?;
        Ok(next)
    }

    /// Atomically claims both restricted sends. Both exact PXRC values become
    /// durable in the same successor; there is no one-target restricted claim.
    pub(crate) fn try_claim_restricted_pair(
        &self,
        requests: [VerifiedDistributedAgentStackRestrictedApplyV1; 2],
    ) -> Result<Self, DistributedAgentStackStoreError> {
        if self.targets.iter().any(|row| {
            row.phase != DistributedAgentStackTargetPhaseV1::RequestDurableNotSent
                || row.receipt.is_some()
                || row.restricted_request.is_some()
                || row.restricted_receipt.is_some()
        }) {
            return Err(DistributedAgentStackStoreError::InvalidPhase);
        }
        for (row, restricted) in self.targets.iter().zip(requests.iter()) {
            if restricted.request().carrier().target() != row.target {
                return Err(DistributedAgentStackStoreError::TargetMismatch);
            }
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        for (row, restricted) in next.targets.iter_mut().zip(requests) {
            row.phase = DistributedAgentStackTargetPhaseV1::Uncertain;
            row.restricted_request = Some(restricted.into_request());
        }
        validate_state_shape(&next)?;
        Ok(next)
    }

    pub(crate) fn try_terminal(
        &self,
        target: RuntimeHostId,
        terminal: VerifiedDistributedAgentStackTerminalV1,
    ) -> Result<Self, DistributedAgentStackStoreError> {
        let index = self.target_index(target)?;
        if self.targets[index].phase != DistributedAgentStackTargetPhaseV1::Uncertain
            || self.targets[index].receipt.is_some()
            || self.targets[index].restricted_request.is_some()
            || self.targets[index].restricted_receipt.is_some()
        {
            return Err(DistributedAgentStackStoreError::InvalidPhase);
        }
        let receipt = terminal.into_receipt();
        let facts = receipt.facts();
        if facts.target() != target
            || facts.operation_id() != self.targets[index].request.operation_id()
            || facts.request_digest() != self.targets[index].request.envelope_request_digest()
            || facts.target_slice_digest() != self.targets[index].request.target_slice_digest()
        {
            return Err(DistributedAgentStackStoreError::TerminalMismatch);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.targets[index].phase = DistributedAgentStackTargetPhaseV1::ReceiptDurable;
        next.targets[index].receipt = Some(receipt);
        validate_state_shape(&next)?;
        if next.targets.iter().all(|row| {
            row.receipt().is_some_and(|receipt| {
                receipt.facts().outcome() == DistributedAgentStackTerminalOutcomeV1::ActiveReady
            })
        }) && !active_ready_pair_is_reciprocal(&next)
        {
            return Err(DistributedAgentStackStoreError::ReciprocalTerminalMismatch);
        }
        Ok(next)
    }

    pub(crate) fn try_restricted_terminal(
        &self,
        target: RuntimeHostId,
        terminal: VerifiedDistributedAgentStackTerminalV2,
    ) -> Result<Self, DistributedAgentStackStoreError> {
        let index = self.target_index(target)?;
        let Some(restricted_request) = self.targets[index].restricted_request.as_ref() else {
            return Err(DistributedAgentStackStoreError::InvalidPhase);
        };
        if self.targets[index].phase != DistributedAgentStackTargetPhaseV1::Uncertain
            || self.targets[index].receipt.is_some()
            || self.targets[index].restricted_receipt.is_some()
        {
            return Err(DistributedAgentStackStoreError::InvalidPhase);
        }
        let receipt = terminal.into_receipt();
        let facts = receipt.facts();
        if facts.target() != target
            || facts.operation_id() != self.targets[index].request.operation_id()
            || facts.request_digest() != self.targets[index].request.envelope_request_digest()
            || facts.target_slice_digest() != self.targets[index].request.target_slice_digest()
            || receipt.restricted_request_digest() != restricted_request.restricted_request_digest()
            || receipt.carrier() != restricted_request.carrier()
        {
            return Err(DistributedAgentStackStoreError::TerminalMismatch);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.targets[index].phase = DistributedAgentStackTargetPhaseV1::ReceiptDurable;
        next.targets[index].restricted_receipt = Some(receipt);
        validate_state_shape(&next)?;
        if next.targets.iter().all(|row| {
            row.terminal_facts().is_some_and(|facts| {
                facts.outcome() == DistributedAgentStackTerminalOutcomeV1::ActiveReady
            })
        }) && !active_ready_pair_is_reciprocal(&next)
        {
            return Err(DistributedAgentStackStoreError::ReciprocalTerminalMismatch);
        }
        Ok(next)
    }

    pub(crate) fn encode(&self) -> Result<Box<[u8]>, DistributedAgentStackStoreError> {
        validate_state_shape(self)?;
        let version = state_wire_version(&self.targets);
        let mut payload_bytes = 0_usize;
        for row in &self.targets {
            payload_bytes = payload_bytes
                .checked_add(row.request.canonical_wire().len())
                .and_then(|value| {
                    value.checked_add(
                        row.receipt()
                            .map_or(0, |receipt| receipt.canonical_wire().len()),
                    )
                })
                .and_then(|value| {
                    value.checked_add(
                        row.restricted_request()
                            .map_or(0, |request| request.canonical_wire().len()),
                    )
                })
                .and_then(|value| {
                    value.checked_add(
                        row.restricted_receipt()
                            .map_or(0, |receipt| receipt.canonical_wire().len()),
                    )
                })
                .ok_or(DistributedAgentStackStoreError::StateTooLarge)?;
        }
        let total = STATE_HEADER_BYTES
            .checked_add(target_header_bytes(version)? * 2)
            .and_then(|value| value.checked_add(payload_bytes))
            .and_then(|value| value.checked_add(STATE_CHECKSUM_BYTES))
            .ok_or(DistributedAgentStackStoreError::StateTooLarge)?;
        if total > MAX_STATE_BYTES {
            return Err(DistributedAgentStackStoreError::StateTooLarge);
        }

        let mut wire = Vec::with_capacity(total);
        wire.extend_from_slice(STATE_MAGIC);
        wire.extend_from_slice(&version.to_be_bytes());
        wire.extend_from_slice(&self.sequence.to_be_bytes());
        wire.extend_from_slice(self.owner_anchor.as_bytes());
        wire.extend_from_slice(self.rollout.rollout_id().as_bytes());
        wire.extend_from_slice(&self.rollout.revision().value().to_be_bytes());
        wire.extend_from_slice(&2_u16.to_be_bytes());
        wire.extend_from_slice(&0_u16.to_be_bytes());
        for row in &self.targets {
            wire.extend_from_slice(row.target.as_bytes());
            wire.push(match row.phase {
                DistributedAgentStackTargetPhaseV1::RequestDurableNotSent => 1,
                DistributedAgentStackTargetPhaseV1::Uncertain => 2,
                DistributedAgentStackTargetPhaseV1::ReceiptDurable => 3,
            });
            wire.push(0);
            wire.extend_from_slice(&0_u16.to_be_bytes());
            let request_length = u32::try_from(row.request.canonical_wire().len())
                .map_err(|_| DistributedAgentStackStoreError::StateTooLarge)?;
            let receipt_length = u32::try_from(
                row.receipt()
                    .map_or(0, |receipt| receipt.canonical_wire().len()),
            )
            .map_err(|_| DistributedAgentStackStoreError::StateTooLarge)?;
            wire.extend_from_slice(&request_length.to_be_bytes());
            wire.extend_from_slice(&receipt_length.to_be_bytes());
            if version == STATE_VERSION_V3 {
                wire.extend_from_slice(
                    &u32::try_from(
                        row.restricted_request()
                            .map_or(0, |request| request.canonical_wire().len()),
                    )
                    .map_err(|_| DistributedAgentStackStoreError::StateTooLarge)?
                    .to_be_bytes(),
                );
                wire.extend_from_slice(
                    &u32::try_from(
                        row.restricted_receipt()
                            .map_or(0, |receipt| receipt.canonical_wire().len()),
                    )
                    .map_err(|_| DistributedAgentStackStoreError::StateTooLarge)?
                    .to_be_bytes(),
                );
            }
            wire.extend_from_slice(row.request.canonical_wire());
            if let Some(receipt) = row.receipt() {
                wire.extend_from_slice(receipt.canonical_wire());
            }
            if let Some(request) = row.restricted_request() {
                wire.extend_from_slice(request.canonical_wire());
            }
            if let Some(receipt) = row.restricted_receipt() {
                wire.extend_from_slice(receipt.canonical_wire());
            }
        }
        let checksum = checksum(version, &wire)?;
        wire.extend_from_slice(checksum.as_bytes());
        Ok(wire.into_boxed_slice())
    }

    pub(crate) fn decode(
        frame: &[u8],
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> Result<Self, DistributedAgentStackStoreError> {
        let version = read_state_version(frame)?;
        if frame.len()
            < STATE_HEADER_BYTES + (target_header_bytes(version)? * 2) + STATE_CHECKSUM_BYTES
        {
            return Err(DistributedAgentStackStoreError::StateTruncated);
        }
        if frame.len() > MAX_STATE_BYTES {
            return Err(DistributedAgentStackStoreError::StateTooLarge);
        }
        let checksum_offset = frame.len() - STATE_CHECKSUM_BYTES;
        let stored_checksum = Digest32::from_bytes(
            frame[checksum_offset..]
                .try_into()
                .map_err(|_| DistributedAgentStackStoreError::StateTruncated)?,
        );
        if checksum(version, &frame[..checksum_offset])? != stored_checksum {
            return Err(DistributedAgentStackStoreError::StateChecksumMismatch);
        }

        let mut cursor = Cursor::new(&frame[..checksum_offset]);
        if cursor.array::<4>()? != *STATE_MAGIC || cursor.u16()? != version {
            return Err(DistributedAgentStackStoreError::InvalidState);
        }
        let sequence = cursor.u64()?;
        let owner_anchor = Digest32::from_bytes(cursor.array()?);
        let rollout_id = DistributedAgentStackRolloutIdV1::try_from_bytes(cursor.array()?)?;
        let revision = cursor.u64()?;
        if cursor.u16()? != 2 || cursor.u16()? != 0 {
            return Err(DistributedAgentStackStoreError::InvalidState);
        }
        if owner_anchor != expected_owner_anchor || digest_is_zero(owner_anchor) {
            return Err(DistributedAgentStackStoreError::OwnerMismatch);
        }
        let first = decode_target(&mut cursor, version)?;
        let second = decode_target(&mut cursor, version)?;
        cursor.finish()?;
        let rollout = DistributedAgentStackRolloutV1::try_restore(
            rollout_id,
            predecessors,
            [first.request.clone(), second.request.clone()],
        )?;
        if rollout.revision().value() != revision {
            return Err(DistributedAgentStackStoreError::InvalidState);
        }
        let decoded = Self {
            sequence,
            owner_anchor,
            rollout,
            targets: [first, second],
        };
        validate_state_shape(&decoded)?;
        for (index, row) in decoded.targets.iter().enumerate() {
            if let Some(receipt) = row.receipt() {
                validate_distributed_agent_stack_terminal_v1(
                    predecessors[index],
                    &row.request,
                    receipt.clone(),
                )?;
            }
            if let Some(restricted) = row.restricted_request() {
                validate_distributed_agent_stack_restricted_apply_v1(
                    predecessors[index],
                    &row.request,
                    restricted.clone(),
                )?;
                if let Some(receipt) = row.restricted_receipt() {
                    validate_distributed_agent_stack_terminal_v2(
                        predecessors[index],
                        &row.request,
                        restricted,
                        receipt.clone(),
                    )?;
                }
            }
        }
        if decoded.targets.iter().all(|row| {
            row.terminal_facts().is_some_and(|facts| {
                facts.outcome() == DistributedAgentStackTerminalOutcomeV1::ActiveReady
            })
        }) && !active_ready_pair_is_reciprocal(&decoded)
        {
            return Err(DistributedAgentStackStoreError::ReciprocalTerminalMismatch);
        }
        if decoded.encode()?.as_ref() != frame {
            return Err(DistributedAgentStackStoreError::NonCanonicalState);
        }
        Ok(decoded)
    }

    fn target_index(
        &self,
        target: RuntimeHostId,
    ) -> Result<usize, DistributedAgentStackStoreError> {
        self.targets
            .iter()
            .position(|row| row.target == target)
            .ok_or(DistributedAgentStackStoreError::TargetMismatch)
    }
}

/// Move-only view of the Controller-owned durable state. It creates no lock,
/// file, retry loop, or second desired-state authority.
#[derive(Debug)]
pub(crate) struct DistributedAgentStackDurableStoreV1 {
    state: Option<DistributedAgentStackControllerStateV1>,
    durable_wire: Option<Box<[u8]>>,
}

impl DistributedAgentStackDurableStoreV1 {
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self {
            state: None,
            durable_wire: None,
        }
    }

    pub(crate) fn try_reopen(
        frame: &[u8],
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> Result<Self, DistributedAgentStackStoreError> {
        Ok(Self {
            state: Some(DistributedAgentStackControllerStateV1::decode(
                frame,
                expected_owner_anchor,
                predecessors,
            )?),
            durable_wire: Some(frame.into()),
        })
    }

    #[must_use]
    pub(crate) const fn state(&self) -> Option<&DistributedAgentStackControllerStateV1> {
        self.state.as_ref()
    }

    #[must_use]
    pub(crate) fn durable_wire(&self) -> Option<&[u8]> {
        self.durable_wire.as_deref()
    }

    pub(crate) fn initialize_with<Commit>(
        &mut self,
        next: DistributedAgentStackControllerStateV1,
        commit: Commit,
    ) -> Result<(), DistributedAgentStackStoreError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        if self.state.is_some() || next.sequence() != 1 {
            return Err(DistributedAgentStackStoreError::InvalidSequence);
        }
        self.install_after_commit(next, commit)
    }

    pub(crate) fn commit_with<Commit>(
        &mut self,
        next: DistributedAgentStackControllerStateV1,
        commit: Commit,
    ) -> Result<(), DistributedAgentStackStoreError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let current = self
            .state
            .as_ref()
            .ok_or(DistributedAgentStackStoreError::InvalidSequence)?;
        if next.sequence() != next_sequence(current.sequence())?
            || next.owner_anchor() != current.owner_anchor()
            || next.rollout().rollout_id() != current.rollout().rollout_id()
            || next.rollout().requests() != current.rollout().requests()
        {
            return Err(DistributedAgentStackStoreError::InvalidSequence);
        }
        self.install_after_commit(next, commit)
    }

    fn install_after_commit<Commit>(
        &mut self,
        next: DistributedAgentStackControllerStateV1,
        commit: Commit,
    ) -> Result<(), DistributedAgentStackStoreError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let wire = next.encode()?;
        commit(&wire)?;
        self.state = Some(next);
        self.durable_wire = Some(wire);
        Ok(())
    }
}

fn decode_target(
    cursor: &mut Cursor<'_>,
    version: u16,
) -> Result<DistributedAgentStackTargetStateV1, DistributedAgentStackStoreError> {
    let target = RuntimeHostId::from_bytes(cursor.array()?);
    let phase = match cursor.u8()? {
        1 => DistributedAgentStackTargetPhaseV1::RequestDurableNotSent,
        2 => DistributedAgentStackTargetPhaseV1::Uncertain,
        3 => DistributedAgentStackTargetPhaseV1::ReceiptDurable,
        _ => return Err(DistributedAgentStackStoreError::InvalidState),
    };
    if cursor.u8()? != 0 || cursor.u16()? != 0 {
        return Err(DistributedAgentStackStoreError::InvalidState);
    }
    let request_length = cursor.usize_u32()?;
    let receipt_length = cursor.usize_u32()?;
    let (restricted_request_length, restricted_receipt_length) = if version == STATE_VERSION_V3 {
        (cursor.usize_u32()?, cursor.usize_u32()?)
    } else {
        (0, 0)
    };
    let request = DistributedAgentStackApplyRequestV1::decode(cursor.take(request_length)?)?;
    let receipt = if receipt_length == 0 {
        None
    } else {
        Some(DistributedAgentStackTerminalReceiptV1::decode(
            cursor.take(receipt_length)?,
        )?)
    };
    let restricted_request = if restricted_request_length == 0 {
        None
    } else {
        Some(DistributedAgentStackRestrictedApplyRequestV1::decode(
            cursor.take(restricted_request_length)?,
        )?)
    };
    let restricted_receipt = if restricted_receipt_length == 0 {
        None
    } else {
        Some(DistributedAgentStackTerminalReceiptV2::decode(
            cursor.take(restricted_receipt_length)?,
        )?)
    };
    Ok(DistributedAgentStackTargetStateV1 {
        target,
        phase,
        request,
        receipt,
        restricted_request,
        restricted_receipt,
    })
}

/// Strictly validates PXDJ framing, checksum, canonical embedded contracts,
/// and phase shape without treating those checks as predecessor authentication.
pub(crate) fn validate_distributed_agent_stack_state_wire_v1(
    frame: &[u8],
) -> Result<DistributedAgentStackStateWireCoordinateV1, DistributedAgentStackStoreError> {
    let version = read_state_version(frame)?;
    if frame.len() < STATE_HEADER_BYTES + (target_header_bytes(version)? * 2) + STATE_CHECKSUM_BYTES
    {
        return Err(DistributedAgentStackStoreError::StateTruncated);
    }
    if frame.len() > MAX_STATE_BYTES {
        return Err(DistributedAgentStackStoreError::StateTooLarge);
    }
    let checksum_offset = frame.len() - STATE_CHECKSUM_BYTES;
    let stored_checksum = Digest32::from_bytes(
        frame[checksum_offset..]
            .try_into()
            .map_err(|_| DistributedAgentStackStoreError::StateTruncated)?,
    );
    if checksum(version, &frame[..checksum_offset])? != stored_checksum {
        return Err(DistributedAgentStackStoreError::StateChecksumMismatch);
    }
    let mut cursor = Cursor::new(&frame[..checksum_offset]);
    if cursor.array::<4>()? != *STATE_MAGIC || cursor.u16()? != version {
        return Err(DistributedAgentStackStoreError::InvalidState);
    }
    let sequence = cursor.u64()?;
    let owner_anchor = Digest32::from_bytes(cursor.array()?);
    let rollout_id = DistributedAgentStackRolloutIdV1::try_from_bytes(cursor.array()?)?;
    let revision = cursor.u64()?;
    if cursor.u16()? != 2 || cursor.u16()? != 0 {
        return Err(DistributedAgentStackStoreError::InvalidState);
    }
    let first = decode_target(&mut cursor, version)?;
    let second = decode_target(&mut cursor, version)?;
    cursor.finish()?;
    let coordinate = DistributedAgentStackStateWireCoordinateV1 {
        wire_version: version,
        sequence,
        owner_anchor,
        rollout_id,
        revision,
        targets: [first, second],
    };
    validate_wire_coordinate_shape(&coordinate)?;
    if encode_wire_coordinate(&coordinate)?.as_ref() != frame {
        return Err(DistributedAgentStackStoreError::NonCanonicalState);
    }
    Ok(coordinate)
}

pub(crate) fn validate_distributed_agent_stack_initial_state_wire_v1(
    frame: &[u8],
) -> Result<(), DistributedAgentStackStoreError> {
    let coordinate = validate_distributed_agent_stack_state_wire_v1(frame)?;
    if coordinate.sequence != 1
        || coordinate.wire_version != STATE_VERSION_V2
        || coordinate.targets.iter().any(|row| {
            row.phase != DistributedAgentStackTargetPhaseV1::RequestDurableNotSent
                || row.receipt.is_some()
                || row.restricted_request.is_some()
                || row.restricted_receipt.is_some()
        })
    {
        return Err(DistributedAgentStackStoreError::InvalidSequence);
    }
    Ok(())
}

pub(crate) fn validate_distributed_agent_stack_state_wire_successor_v1(
    previous: &[u8],
    next: &[u8],
) -> Result<(), DistributedAgentStackStoreError> {
    let previous = validate_distributed_agent_stack_state_wire_v1(previous)?;
    let next = validate_distributed_agent_stack_state_wire_v1(next)?;
    if next.sequence != next_sequence(previous.sequence)?
        || next.owner_anchor != previous.owner_anchor
        || next.rollout_id != previous.rollout_id
        || next.revision != previous.revision
    {
        return Err(DistributedAgentStackStoreError::InvalidSequence);
    }
    for (old, new) in previous.targets.iter().zip(next.targets.iter()) {
        if old.target != new.target || old.request != new.request {
            return Err(DistributedAgentStackStoreError::InvalidState);
        }
    }
    if previous.wire_version == STATE_VERSION_V2 && next.wire_version == STATE_VERSION_V3 {
        let valid_pair_claim =
            previous
                .targets
                .iter()
                .zip(next.targets.iter())
                .all(|(old, new)| {
                    old.phase == DistributedAgentStackTargetPhaseV1::RequestDurableNotSent
                        && old.receipt.is_none()
                        && old.restricted_request.is_none()
                        && old.restricted_receipt.is_none()
                        && new.phase == DistributedAgentStackTargetPhaseV1::Uncertain
                        && new.receipt.is_none()
                        && new.restricted_request.is_some()
                        && new.restricted_receipt.is_none()
                });
        return if valid_pair_claim {
            Ok(())
        } else {
            Err(DistributedAgentStackStoreError::InvalidPhase)
        };
    }
    if previous.wire_version != next.wire_version {
        return Err(DistributedAgentStackStoreError::InvalidStateVersionTransition);
    }
    let mut transitions = 0_u8;
    for (old, new) in previous.targets.iter().zip(next.targets.iter()) {
        if old == new {
            continue;
        }
        let valid = if previous.wire_version == STATE_VERSION_V2 {
            matches!(
                (
                    old.phase,
                    new.phase,
                    old.receipt.as_ref(),
                    new.receipt.as_ref()
                ),
                (
                    DistributedAgentStackTargetPhaseV1::RequestDurableNotSent,
                    DistributedAgentStackTargetPhaseV1::Uncertain,
                    None,
                    None,
                ) | (
                    DistributedAgentStackTargetPhaseV1::Uncertain,
                    DistributedAgentStackTargetPhaseV1::ReceiptDurable,
                    None,
                    Some(_),
                )
            ) && old.restricted_request.is_none()
                && new.restricted_request.is_none()
                && old.restricted_receipt.is_none()
                && new.restricted_receipt.is_none()
        } else {
            old.phase == DistributedAgentStackTargetPhaseV1::Uncertain
                && new.phase == DistributedAgentStackTargetPhaseV1::ReceiptDurable
                && old.receipt.is_none()
                && new.receipt.is_none()
                && old.restricted_request == new.restricted_request
                && old.restricted_request.is_some()
                && old.restricted_receipt.is_none()
                && new.restricted_receipt.is_some()
        };
        if !valid {
            return Err(DistributedAgentStackStoreError::InvalidPhase);
        }
        transitions = transitions
            .checked_add(1)
            .ok_or(DistributedAgentStackStoreError::InvalidSequence)?;
    }
    if transitions != 1 {
        return Err(DistributedAgentStackStoreError::InvalidSequence);
    }
    Ok(())
}

fn validate_wire_coordinate_shape(
    coordinate: &DistributedAgentStackStateWireCoordinateV1,
) -> Result<(), DistributedAgentStackStoreError> {
    if !matches!(coordinate.wire_version, STATE_VERSION_V2 | STATE_VERSION_V3)
        || coordinate.sequence == 0
        || digest_is_zero(coordinate.owner_anchor)
        || coordinate.revision == 0
        || coordinate.targets[0].target.as_bytes() >= coordinate.targets[1].target.as_bytes()
    {
        return Err(DistributedAgentStackStoreError::InvalidState);
    }
    let expected_sequence = if coordinate.wire_version == STATE_VERSION_V2 {
        coordinate.targets.iter().try_fold(1_u64, |sequence, row| {
            let transitions = match row.phase {
                DistributedAgentStackTargetPhaseV1::RequestDurableNotSent => 0,
                DistributedAgentStackTargetPhaseV1::Uncertain => 1,
                DistributedAgentStackTargetPhaseV1::ReceiptDurable => 2,
            };
            sequence
                .checked_add(transitions)
                .ok_or(DistributedAgentStackStoreError::SequenceExhausted)
        })?
    } else {
        2_u64
            .checked_add(
                u64::try_from(
                    coordinate
                        .targets
                        .iter()
                        .filter(|row| row.restricted_receipt.is_some())
                        .count(),
                )
                .map_err(|_| DistributedAgentStackStoreError::SequenceExhausted)?,
            )
            .ok_or(DistributedAgentStackStoreError::SequenceExhausted)?
    };
    if coordinate.sequence != expected_sequence {
        return Err(DistributedAgentStackStoreError::InvalidSequence);
    }
    for row in &coordinate.targets {
        if row.request.target() != row.target {
            return Err(DistributedAgentStackStoreError::TargetMismatch);
        }
        let valid = if coordinate.wire_version == STATE_VERSION_V2 {
            row.restricted_request.is_none()
                && row.restricted_receipt.is_none()
                && match row.phase {
                    DistributedAgentStackTargetPhaseV1::RequestDurableNotSent
                    | DistributedAgentStackTargetPhaseV1::Uncertain => row.receipt.is_none(),
                    DistributedAgentStackTargetPhaseV1::ReceiptDurable => row
                        .receipt
                        .as_ref()
                        .is_some_and(|receipt| terminal_facts_match_request(receipt.facts(), row)),
                }
        } else {
            row.receipt.is_none()
                && row.restricted_request.as_ref().is_some_and(|restricted| {
                    restricted.carrier().target() == row.target
                        && match row.phase {
                            DistributedAgentStackTargetPhaseV1::Uncertain => {
                                row.restricted_receipt.is_none()
                            }
                            DistributedAgentStackTargetPhaseV1::ReceiptDurable => {
                                row.restricted_receipt.as_ref().is_some_and(|receipt| {
                                    terminal_facts_match_request(receipt.facts(), row)
                                        && receipt.restricted_request_digest()
                                            == restricted.restricted_request_digest()
                                        && receipt.carrier() == restricted.carrier()
                                })
                            }
                            DistributedAgentStackTargetPhaseV1::RequestDurableNotSent => false,
                        }
                })
        };
        if !valid {
            return Err(DistributedAgentStackStoreError::InvalidState);
        }
    }
    Ok(())
}

fn encode_wire_coordinate(
    coordinate: &DistributedAgentStackStateWireCoordinateV1,
) -> Result<Box<[u8]>, DistributedAgentStackStoreError> {
    let mut wire = Vec::new();
    wire.extend_from_slice(STATE_MAGIC);
    wire.extend_from_slice(&coordinate.wire_version.to_be_bytes());
    wire.extend_from_slice(&coordinate.sequence.to_be_bytes());
    wire.extend_from_slice(coordinate.owner_anchor.as_bytes());
    wire.extend_from_slice(coordinate.rollout_id.as_bytes());
    wire.extend_from_slice(&coordinate.revision.to_be_bytes());
    wire.extend_from_slice(&2_u16.to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    for row in &coordinate.targets {
        wire.extend_from_slice(row.target.as_bytes());
        wire.push(match row.phase {
            DistributedAgentStackTargetPhaseV1::RequestDurableNotSent => 1,
            DistributedAgentStackTargetPhaseV1::Uncertain => 2,
            DistributedAgentStackTargetPhaseV1::ReceiptDurable => 3,
        });
        wire.push(0);
        wire.extend_from_slice(&0_u16.to_be_bytes());
        wire.extend_from_slice(
            &u32::try_from(row.request.canonical_wire().len())
                .map_err(|_| DistributedAgentStackStoreError::StateTooLarge)?
                .to_be_bytes(),
        );
        wire.extend_from_slice(
            &u32::try_from(
                row.receipt
                    .as_ref()
                    .map_or(0, |receipt| receipt.canonical_wire().len()),
            )
            .map_err(|_| DistributedAgentStackStoreError::StateTooLarge)?
            .to_be_bytes(),
        );
        if coordinate.wire_version == STATE_VERSION_V3 {
            wire.extend_from_slice(
                &u32::try_from(
                    row.restricted_request
                        .as_ref()
                        .map_or(0, |request| request.canonical_wire().len()),
                )
                .map_err(|_| DistributedAgentStackStoreError::StateTooLarge)?
                .to_be_bytes(),
            );
            wire.extend_from_slice(
                &u32::try_from(
                    row.restricted_receipt
                        .as_ref()
                        .map_or(0, |receipt| receipt.canonical_wire().len()),
                )
                .map_err(|_| DistributedAgentStackStoreError::StateTooLarge)?
                .to_be_bytes(),
            );
        }
        wire.extend_from_slice(row.request.canonical_wire());
        if let Some(receipt) = &row.receipt {
            wire.extend_from_slice(receipt.canonical_wire());
        }
        if let Some(request) = &row.restricted_request {
            wire.extend_from_slice(request.canonical_wire());
        }
        if let Some(receipt) = &row.restricted_receipt {
            wire.extend_from_slice(receipt.canonical_wire());
        }
    }
    let state_checksum = checksum(coordinate.wire_version, &wire)?;
    wire.extend_from_slice(state_checksum.as_bytes());
    if wire.len() > MAX_STATE_BYTES {
        return Err(DistributedAgentStackStoreError::StateTooLarge);
    }
    Ok(wire.into_boxed_slice())
}

fn validate_state_shape(
    state: &DistributedAgentStackControllerStateV1,
) -> Result<(), DistributedAgentStackStoreError> {
    if state.sequence == 0
        || digest_is_zero(state.owner_anchor)
        || state.rollout.revision().value() == 0
        || state.targets[0].target.as_bytes() >= state.targets[1].target.as_bytes()
        || state.rollout.requests()[0] != state.targets[0].request
        || state.rollout.requests()[1] != state.targets[1].request
        || state.targets[0].request.target() != state.targets[0].target
        || state.targets[1].request.target() != state.targets[1].target
    {
        return Err(DistributedAgentStackStoreError::InvalidState);
    }
    let restricted = state
        .targets
        .iter()
        .any(|row| row.restricted_request.is_some() || row.restricted_receipt.is_some());
    let expected_sequence = if restricted {
        2_u64
            .checked_add(
                u64::try_from(
                    state
                        .targets
                        .iter()
                        .filter(|row| row.restricted_receipt.is_some())
                        .count(),
                )
                .map_err(|_| DistributedAgentStackStoreError::SequenceExhausted)?,
            )
            .ok_or(DistributedAgentStackStoreError::SequenceExhausted)?
    } else {
        state.targets.iter().try_fold(1_u64, |sequence, row| {
            let transitions = match row.phase {
                DistributedAgentStackTargetPhaseV1::RequestDurableNotSent => 0,
                DistributedAgentStackTargetPhaseV1::Uncertain => 1,
                DistributedAgentStackTargetPhaseV1::ReceiptDurable => 2,
            };
            sequence
                .checked_add(transitions)
                .ok_or(DistributedAgentStackStoreError::SequenceExhausted)
        })?
    };
    if expected_sequence != state.sequence {
        return Err(DistributedAgentStackStoreError::InvalidSequence);
    }
    for row in &state.targets {
        let valid = if restricted {
            row.receipt.is_none()
                && row.restricted_request.as_ref().is_some_and(|request| {
                    request.carrier().target() == row.target
                        && match row.phase {
                            DistributedAgentStackTargetPhaseV1::Uncertain => {
                                row.restricted_receipt.is_none()
                            }
                            DistributedAgentStackTargetPhaseV1::ReceiptDurable => {
                                row.restricted_receipt.as_ref().is_some_and(|receipt| {
                                    terminal_facts_match_request(receipt.facts(), row)
                                        && receipt.restricted_request_digest()
                                            == request.restricted_request_digest()
                                        && receipt.carrier() == request.carrier()
                                })
                            }
                            DistributedAgentStackTargetPhaseV1::RequestDurableNotSent => false,
                        }
                })
        } else {
            row.restricted_request.is_none()
                && row.restricted_receipt.is_none()
                && match row.phase {
                    DistributedAgentStackTargetPhaseV1::RequestDurableNotSent
                    | DistributedAgentStackTargetPhaseV1::Uncertain => row.receipt.is_none(),
                    DistributedAgentStackTargetPhaseV1::ReceiptDurable => row.receipt.is_some(),
                }
        };
        if !valid {
            return Err(DistributedAgentStackStoreError::InvalidState);
        }
    }
    Ok(())
}

fn active_ready_pair_is_reciprocal(state: &DistributedAgentStackControllerStateV1) -> bool {
    let Some(first_facts) = state.targets[0].terminal_facts() else {
        return false;
    };
    let Some(second_facts) = state.targets[1].terminal_facts() else {
        return false;
    };
    if first_facts.outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady
        || second_facts.outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady
    {
        return false;
    }
    let first_request = &state.targets[0].request;
    let second_request = &state.targets[1].request;
    let Some(first_topology) = first_request.target_execution().topology() else {
        return false;
    };
    let Some(second_topology) = second_request.target_execution().topology() else {
        return false;
    };
    let Some(first_to_second) = first_topology
        .peers()
        .iter()
        .find(|peer| peer.peer_runtime_host() == second_request.target())
    else {
        return false;
    };
    let Some(second_to_first) = second_topology
        .peers()
        .iter()
        .find(|peer| peer.peer_runtime_host() == first_request.target())
    else {
        return false;
    };
    let Some(first_observations) = first_facts.observations() else {
        return false;
    };
    let Some(second_observations) = second_facts.observations() else {
        return false;
    };
    first_to_second.connect_endpoint() == second_observations.remote_listen_endpoint()
        && second_to_first.connect_endpoint() == first_observations.remote_listen_endpoint()
        && first_observations.remote_observation_digest()
            != second_observations.remote_observation_digest()
        && first_facts
            .evidence()
            .local_bindings
            .installed_binding_set_digest
            != second_facts
                .evidence()
                .local_bindings
                .installed_binding_set_digest
        && first_observations.proofs().len() == first_topology.peers().len()
        && second_observations.proofs().len() == second_topology.peers().len()
        && first_observations
            .proofs()
            .iter()
            .any(|proof| proof.fields().peer_runtime_host == second_request.target())
        && second_observations
            .proofs()
            .iter()
            .any(|proof| proof.fields().peer_runtime_host == first_request.target())
}

fn terminal_facts_match_request(
    facts: &DistributedAgentStackTerminalFactsV1,
    row: &DistributedAgentStackTargetStateV1,
) -> bool {
    facts.target() == row.target
        && facts.operation_id() == row.request.operation_id()
        && facts.request_digest() == row.request.envelope_request_digest()
        && facts.target_slice_digest() == row.request.target_slice_digest()
}

fn state_wire_version(targets: &[DistributedAgentStackTargetStateV1; 2]) -> u16 {
    if targets
        .iter()
        .any(|row| row.restricted_request.is_some() || row.restricted_receipt.is_some())
    {
        STATE_VERSION_V3
    } else {
        STATE_VERSION_V2
    }
}

fn read_state_version(frame: &[u8]) -> Result<u16, DistributedAgentStackStoreError> {
    let prefix = frame
        .get(..6)
        .ok_or(DistributedAgentStackStoreError::StateTruncated)?;
    if &prefix[..4] != STATE_MAGIC {
        return Err(DistributedAgentStackStoreError::InvalidState);
    }
    let version = u16::from_be_bytes(
        prefix[4..6]
            .try_into()
            .map_err(|_| DistributedAgentStackStoreError::StateTruncated)?,
    );
    target_header_bytes(version)?;
    Ok(version)
}

const fn target_header_bytes(version: u16) -> Result<usize, DistributedAgentStackStoreError> {
    match version {
        STATE_VERSION_V2 => Ok(TARGET_HEADER_V2_BYTES),
        STATE_VERSION_V3 => Ok(TARGET_HEADER_V3_BYTES),
        _ => Err(DistributedAgentStackStoreError::UnsupportedStateVersion),
    }
}

fn checksum(version: u16, bytes: &[u8]) -> Result<Digest32, DigestBuildError> {
    let domain = if version == STATE_VERSION_V3 {
        STATE_CHECKSUM_DOMAIN_V3
    } else {
        STATE_CHECKSUM_DOMAIN_V2
    };
    let mut builder = Digest32Builder::try_new(domain)?;
    builder.field_bytes(bytes)?;
    Ok(builder.finish())
}

fn digest_is_zero(value: Digest32) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

fn next_sequence(value: u64) -> Result<u64, DistributedAgentStackStoreError> {
    value
        .checked_add(1)
        .ok_or(DistributedAgentStackStoreError::SequenceExhausted)
}

struct Cursor<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DistributedAgentStackStoreError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DistributedAgentStackStoreError::StateTooLarge)?;
        let value = self
            .frame
            .get(self.position..end)
            .ok_or(DistributedAgentStackStoreError::StateTruncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DistributedAgentStackStoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DistributedAgentStackStoreError::StateTruncated)
    }

    fn u8(&mut self) -> Result<u8, DistributedAgentStackStoreError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, DistributedAgentStackStoreError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DistributedAgentStackStoreError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize_u32(&mut self) -> Result<usize, DistributedAgentStackStoreError> {
        usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| DistributedAgentStackStoreError::StateTooLarge)
    }

    fn finish(self) -> Result<(), DistributedAgentStackStoreError> {
        if self.position == self.frame.len() {
            Ok(())
        } else {
            Err(DistributedAgentStackStoreError::InvalidState)
        }
    }
}

#[derive(Debug)]
pub(crate) enum DistributedAgentStackStoreError {
    Contract,
    Producer(DistributedAgentStackProducerError),
    Digest(DigestBuildError),
    StateTruncated,
    StateTooLarge,
    StateChecksumMismatch,
    NonCanonicalState,
    UnsupportedStateVersion,
    InvalidStateVersionTransition,
    InvalidState,
    InvalidPhase,
    InvalidSequence,
    SequenceExhausted,
    OwnerMismatch,
    TargetMismatch,
    TerminalMismatch,
    ReciprocalTerminalMismatch,
    DurabilityRejected,
}

impl From<DistributedAgentStackPlanError> for DistributedAgentStackStoreError {
    fn from(_value: DistributedAgentStackPlanError) -> Self {
        Self::Contract
    }
}

impl From<DistributedAgentStackProducerError> for DistributedAgentStackStoreError {
    fn from(value: DistributedAgentStackProducerError) -> Self {
        Self::Producer(value)
    }
}

impl From<DigestBuildError> for DistributedAgentStackStoreError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for DistributedAgentStackStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "distributed Agent stack store rejected: {self:?}"
        )
    }
}

impl std::error::Error for DistributedAgentStackStoreError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;

    use super::{
        DistributedAgentStackControllerStateV1, DistributedAgentStackDurableStoreV1,
        DistributedAgentStackRolloutStatusV1, DistributedAgentStackStoreError,
        DistributedAgentStackTargetPhaseV1,
    };
    use crate::distributed_agent_stack_producer::tests::fixture_bundle;

    fn owner_anchor() -> Digest32 {
        Digest32::from_bytes([0xd1; 32])
    }

    #[test]
    fn canonical_state_round_trips_and_reauthenticates_both_requests() {
        let fixture = fixture_bundle();
        let state = DistributedAgentStackControllerStateV1::try_new(
            owner_anchor(),
            fixture.rollout.clone(),
        )
        .expect("initial distributed state");
        let wire = state.encode().expect("canonical PXDJ v2");
        assert_eq!(&wire[..6], b"PXDJ\0\x02");
        let reopened = DistributedAgentStackControllerStateV1::decode(
            &wire,
            owner_anchor(),
            [&fixture.predecessors[0], &fixture.predecessors[1]],
        )
        .expect("authenticated state reopen");
        assert_eq!(reopened, state);
        assert_eq!(
            reopened.status(),
            DistributedAgentStackRolloutStatusV1::PendingNotSent
        );

        let mut corrupt = wire.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(matches!(
            DistributedAgentStackControllerStateV1::decode(
                &corrupt,
                owner_anchor(),
                [&fixture.predecessors[0], &fixture.predecessors[1]],
            ),
            Err(DistributedAgentStackStoreError::StateChecksumMismatch)
        ));
    }

    #[test]
    fn uncertain_commit_is_visible_only_after_owner_durability_and_survives_restart() {
        let fixture = fixture_bundle();
        let initial = DistributedAgentStackControllerStateV1::try_new(
            owner_anchor(),
            fixture.rollout.clone(),
        )
        .expect("initial state");
        let next = initial
            .try_claim_target(initial.targets()[0].target())
            .expect("uncertain successor");
        let mut store = DistributedAgentStackDurableStoreV1::empty();
        store
            .initialize_with(initial.clone(), |_| Ok(()))
            .expect("owner committed initial state");
        let before = store.durable_wire().expect("initial bytes").to_vec();
        assert!(matches!(
            store.commit_with(next.clone(), |_| {
                Err(DistributedAgentStackStoreError::DurabilityRejected)
            }),
            Err(DistributedAgentStackStoreError::DurabilityRejected)
        ));
        assert_eq!(store.durable_wire(), Some(before.as_slice()));
        store
            .commit_with(next, |_| Ok(()))
            .expect("owner committed uncertain state");
        let durable = store.durable_wire().expect("uncertain bytes").to_vec();
        let reopened = DistributedAgentStackDurableStoreV1::try_reopen(
            &durable,
            owner_anchor(),
            [&fixture.predecessors[0], &fixture.predecessors[1]],
        )
        .expect("restart uncertain state");
        assert_eq!(reopened.durable_wire(), Some(durable.as_slice()));
        assert_eq!(
            reopened.state().expect("state").targets()[0].phase(),
            DistributedAgentStackTargetPhaseV1::Uncertain
        );
    }
}
