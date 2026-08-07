//! Durable Controller state for the PXAR v9 Fabric/Model/Agent sibling.
//!
//! PXMJ v1 retains the exact PXAR v6 predecessor without claiming PXAR v7
//! executed. Every valid, authenticated PXMT is durable, including uncertain,
//! quarantined, and no-effect outcomes. Only `ActiveReady` opens the explicit
//! empty transition and only `EmptyExactZero` is deactivation success.

use core::fmt;

use ed25519_dalek::Signature;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_runtime_contracts::managed_fabric_plan::{
    ManagedFabricApplyTerminalOutcomeV1, ManagedFabricTargetExecutionV1, ManagedFabricTargetModeV1,
};
use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
    ManagedModelAgentStackApplyRequestV1, ManagedModelAgentStackPlanError,
    ManagedModelAgentStackTargetModeV1, ManagedModelAgentStackTerminalOutcomeV1,
    ManagedModelAgentStackTerminalReceiptV1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;

use crate::managed_fabric_apply::{
    ManagedFabricApplyControllerError, ManagedFabricApplyPhaseV1, ManagedFabricControllerStateV1,
};
use crate::managed_fabric_producer::{
    ManagedFabricControllerProvisioningV1, VerifiedManagedFabricProducerContextV1,
};
use crate::managed_model_agent_stack_producer::{
    FreshManagedModelAgentStackApplyV1, ManagedModelAgentStackActivationV1,
    ManagedModelAgentStackDesiredPlanV1, ManagedModelAgentStackProducerError,
    produce_managed_model_agent_stack_empty_request_v1,
    produce_managed_model_agent_stack_request_v1,
    validate_managed_model_agent_stack_empty_request_v1,
    validate_managed_model_agent_stack_request_v1,
};

const STATE_MAGIC: &[u8; 4] = b"PXMJ";
const STATE_VERSION: u16 = 1;
const STATE_FIXED_BYTES: usize = 79;
const STATE_CHECKSUM_BYTES: usize = 32;
const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;
const STATE_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.deployment.managed-model-agent-stack-state.sha256.v1";
const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedModelAgentStackApplyPhaseV1 {
    RequestDurableNotSent,
    Uncertain,
    ReceiptDurable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackControllerStateV1 {
    phase: ManagedModelAgentStackApplyPhaseV1,
    desired: ManagedModelAgentStackDesiredPlanV1,
    request: ManagedModelAgentStackApplyRequestV1,
    receipt: Option<ManagedModelAgentStackTerminalReceiptV1>,
    archived_active: Option<CompletedManagedModelAgentStackApplyV1>,
}

pub(crate) struct ManagedModelAgentStackDecodeContextV1<'a> {
    pub(crate) fabric: &'a VerifiedManagedFabricProducerContextV1,
    pub(crate) cutover_marker_digest: Digest32,
    pub(crate) predecessor_revision: SourcePlanRevision,
    pub(crate) predecessor_execution: &'a ManagedFabricTargetExecutionV1,
    pub(crate) predecessor_slice_digest: TargetSliceDigest,
    pub(crate) predecessor_generation: ManagedServiceGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompletedManagedModelAgentStackApplyV1 {
    desired: ManagedModelAgentStackDesiredPlanV1,
    request: ManagedModelAgentStackApplyRequestV1,
    receipt: ManagedModelAgentStackTerminalReceiptV1,
}

impl CompletedManagedModelAgentStackApplyV1 {
    #[must_use]
    pub(crate) const fn desired(&self) -> &ManagedModelAgentStackDesiredPlanV1 {
        &self.desired
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ManagedModelAgentStackApplyRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> &ManagedModelAgentStackTerminalReceiptV1 {
        &self.receipt
    }
}

impl ManagedModelAgentStackControllerStateV1 {
    #[must_use]
    pub(crate) const fn phase(&self) -> ManagedModelAgentStackApplyPhaseV1 {
        self.phase
    }

    #[must_use]
    pub(crate) const fn desired(&self) -> &ManagedModelAgentStackDesiredPlanV1 {
        &self.desired
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ManagedModelAgentStackApplyRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> Option<&ManagedModelAgentStackTerminalReceiptV1> {
        self.receipt.as_ref()
    }

    #[must_use]
    pub(crate) const fn archived_active(&self) -> Option<&CompletedManagedModelAgentStackApplyV1> {
        self.archived_active.as_ref()
    }

    pub(crate) fn try_prepared(
        desired: ManagedModelAgentStackDesiredPlanV1,
        request: ManagedModelAgentStackApplyRequestV1,
    ) -> Result<Self, ManagedModelAgentStackApplyControllerError> {
        if desired.execution().mode() != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
            || request.target_execution() != desired.execution()
            || request.provenance() != desired.provenance()
        {
            return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
        }
        Ok(Self {
            phase: ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent,
            desired,
            request,
            receipt: None,
            archived_active: None,
        })
    }

    pub(crate) fn try_prepare_empty(
        &self,
        desired: ManagedModelAgentStackDesiredPlanV1,
        request: ManagedModelAgentStackApplyRequestV1,
    ) -> Result<Self, ManagedModelAgentStackApplyControllerError> {
        let active_receipt = self
            .receipt
            .as_ref()
            .ok_or(ManagedModelAgentStackApplyControllerError::ModelAgentNotActive)?;
        if self.phase != ManagedModelAgentStackApplyPhaseV1::ReceiptDurable
            || self.archived_active.is_some()
            || self.desired.execution().mode()
                != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
            || active_receipt.facts().state().outcome()
                != ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
            || desired.execution().mode() != ManagedModelAgentStackTargetModeV1::EmptyDeactivate
            || desired.predecessor_slice_digest() != self.request.target_slice_digest()
            || request.target_execution() != desired.execution()
            || request.provenance() != desired.provenance()
        {
            return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
        }
        Ok(Self {
            phase: ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent,
            desired,
            request,
            receipt: None,
            archived_active: Some(CompletedManagedModelAgentStackApplyV1 {
                desired: self.desired.clone(),
                request: self.request.clone(),
                receipt: active_receipt.clone(),
            }),
        })
    }

    pub(crate) fn try_claim(&self) -> Result<Self, ManagedModelAgentStackApplyControllerError> {
        if self.phase != ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent
            || self.receipt.is_some()
        {
            return Err(ManagedModelAgentStackApplyControllerError::OpaqueReplayForbidden);
        }
        let mut next = self.clone();
        next.phase = ManagedModelAgentStackApplyPhaseV1::Uncertain;
        Ok(next)
    }

    /// Retains every already-authenticated legal PXMT, not only success.
    pub(crate) fn try_terminal(
        &self,
        receipt: ManagedModelAgentStackTerminalReceiptV1,
    ) -> Result<Self, ManagedModelAgentStackApplyControllerError> {
        if self.phase != ManagedModelAgentStackApplyPhaseV1::Uncertain || self.receipt.is_some() {
            return Err(ManagedModelAgentStackApplyControllerError::InvalidPhase);
        }
        let mut next = self.clone();
        next.phase = ManagedModelAgentStackApplyPhaseV1::ReceiptDurable;
        next.receipt = Some(receipt);
        Ok(next)
    }

    /// Pure transition predicate used by the outer PXFJ owner.
    #[must_use]
    pub(crate) fn is_valid_transition_from(&self, current: Option<&Self>) -> bool {
        match current {
            None => {
                self.phase == ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent
                    && self.receipt.is_none()
                    && self.archived_active.is_none()
                    && self.desired.execution().mode()
                        == ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
            }
            Some(current) => {
                let same_request = current.desired == self.desired
                    && current.request == self.request
                    && current.archived_active == self.archived_active;
                let starts_empty = current.phase
                    == ManagedModelAgentStackApplyPhaseV1::ReceiptDurable
                    && current.archived_active.is_none()
                    && current.receipt.as_ref().is_some_and(|receipt| {
                        receipt.facts().state().outcome()
                            == ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
                    })
                    && self.phase == ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent
                    && self.receipt.is_none()
                    && self.desired.execution().mode()
                        == ManagedModelAgentStackTargetModeV1::EmptyDeactivate
                    && self.desired.predecessor_slice_digest()
                        == current.request.target_slice_digest()
                    && self.desired.revision().value()
                        == current
                            .desired
                            .revision()
                            .value()
                            .checked_add(1)
                            .unwrap_or(0)
                    && self.request.target_execution() == self.desired.execution()
                    && self.request.provenance() == self.desired.provenance()
                    && self.archived_active.as_ref().is_some_and(|archived| {
                        archived.desired == current.desired
                            && archived.request == current.request
                            && current
                                .receipt
                                .as_ref()
                                .is_some_and(|receipt| archived.receipt == *receipt)
                    });
                starts_empty
                    || same_request
                        && match (current.phase, self.phase) {
                            (
                                ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent,
                                ManagedModelAgentStackApplyPhaseV1::Uncertain,
                            ) => self.receipt.is_none(),
                            (
                                ManagedModelAgentStackApplyPhaseV1::Uncertain,
                                ManagedModelAgentStackApplyPhaseV1::ReceiptDurable,
                            ) => self.receipt.is_some(),
                            _ => false,
                        }
            }
        }
    }

    #[must_use]
    pub(crate) fn deactivation_succeeded(&self) -> bool {
        self.phase == ManagedModelAgentStackApplyPhaseV1::ReceiptDurable
            && self.desired.execution().mode()
                == ManagedModelAgentStackTargetModeV1::EmptyDeactivate
            && self.receipt.as_ref().is_some_and(|receipt| {
                receipt.facts().state().outcome()
                    == ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero
            })
    }

    pub(crate) fn encode(&self) -> Result<Box<[u8]>, ManagedModelAgentStackApplyControllerError> {
        let execution = self.desired.execution().canonical_wire();
        let request = self.request.canonical_wire();
        let receipt = self
            .receipt
            .as_ref()
            .map_or(&[][..], |value| value.canonical_wire());
        let (archived_revision, archived_execution, archived_request, archived_receipt) = self
            .archived_active
            .as_ref()
            .map_or((0, &[][..], &[][..], &[][..]), |archived| {
                (
                    archived.desired.revision().value(),
                    archived.desired.execution().canonical_wire(),
                    archived.request.canonical_wire(),
                    archived.receipt.canonical_wire(),
                )
            });
        let execution_length = wire_length(execution)?;
        let request_length = wire_length(request)?;
        let receipt_length = wire_length(receipt)?;
        let archived_execution_length = wire_length(archived_execution)?;
        let archived_request_length = wire_length(archived_request)?;
        let archived_receipt_length = wire_length(archived_receipt)?;
        let total = STATE_FIXED_BYTES
            .checked_add(execution.len())
            .and_then(|value| value.checked_add(request.len()))
            .and_then(|value| value.checked_add(receipt.len()))
            .and_then(|value| value.checked_add(archived_execution.len()))
            .and_then(|value| value.checked_add(archived_request.len()))
            .and_then(|value| value.checked_add(archived_receipt.len()))
            .and_then(|value| value.checked_add(STATE_CHECKSUM_BYTES))
            .ok_or(ManagedModelAgentStackApplyControllerError::StateTooLarge)?;
        if total > MAX_STATE_BYTES {
            return Err(ManagedModelAgentStackApplyControllerError::StateTooLarge);
        }
        let mut wire = Vec::with_capacity(total);
        wire.extend_from_slice(STATE_MAGIC);
        wire.extend_from_slice(&STATE_VERSION.to_be_bytes());
        wire.push(match self.phase {
            ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent => 1,
            ManagedModelAgentStackApplyPhaseV1::Uncertain => 2,
            ManagedModelAgentStackApplyPhaseV1::ReceiptDurable => 3,
        });
        wire.extend_from_slice(&self.desired.revision().value().to_be_bytes());
        wire.extend_from_slice(self.desired.predecessor_slice_digest().value().as_bytes());
        wire.extend_from_slice(&execution_length.to_be_bytes());
        wire.extend_from_slice(&request_length.to_be_bytes());
        wire.extend_from_slice(&receipt_length.to_be_bytes());
        wire.extend_from_slice(&archived_revision.to_be_bytes());
        wire.extend_from_slice(&archived_execution_length.to_be_bytes());
        wire.extend_from_slice(&archived_request_length.to_be_bytes());
        wire.extend_from_slice(&archived_receipt_length.to_be_bytes());
        wire.extend_from_slice(execution);
        wire.extend_from_slice(request);
        wire.extend_from_slice(receipt);
        wire.extend_from_slice(archived_execution);
        wire.extend_from_slice(archived_request);
        wire.extend_from_slice(archived_receipt);
        let checksum = state_checksum(&wire)?;
        wire.extend_from_slice(checksum.as_bytes());
        Ok(wire.into_boxed_slice())
    }

    pub(crate) fn decode(
        frame: &[u8],
        decode: ManagedModelAgentStackDecodeContextV1<'_>,
    ) -> Result<Self, ManagedModelAgentStackApplyControllerError> {
        let ManagedModelAgentStackDecodeContextV1 {
            fabric: context,
            cutover_marker_digest,
            predecessor_revision,
            predecessor_execution,
            predecessor_slice_digest,
            predecessor_generation,
        } = decode;
        if frame.len() < STATE_FIXED_BYTES + STATE_CHECKSUM_BYTES {
            return Err(ManagedModelAgentStackApplyControllerError::StateTruncated);
        }
        if frame.len() > MAX_STATE_BYTES {
            return Err(ManagedModelAgentStackApplyControllerError::StateTooLarge);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.array::<4>()? != *STATE_MAGIC || cursor.u16()? != STATE_VERSION {
            return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
        }
        let phase = match cursor.u8()? {
            1 => ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent,
            2 => ManagedModelAgentStackApplyPhaseV1::Uncertain,
            3 => ManagedModelAgentStackApplyPhaseV1::ReceiptDurable,
            _ => return Err(ManagedModelAgentStackApplyControllerError::InvalidState),
        };
        let revision = cursor.u64()?;
        let encoded_predecessor = TargetSliceDigest::new(Digest32::from_bytes(cursor.array()?));
        let execution_length = cursor.usize_u32()?;
        let request_length = cursor.usize_u32()?;
        let receipt_length = cursor.usize_u32()?;
        let archived_revision = cursor.u64()?;
        let archived_execution_length = cursor.usize_u32()?;
        let archived_request_length = cursor.usize_u32()?;
        let archived_receipt_length = cursor.usize_u32()?;
        let expected = STATE_FIXED_BYTES
            .checked_add(execution_length)
            .and_then(|value| value.checked_add(request_length))
            .and_then(|value| value.checked_add(receipt_length))
            .and_then(|value| value.checked_add(archived_execution_length))
            .and_then(|value| value.checked_add(archived_request_length))
            .and_then(|value| value.checked_add(archived_receipt_length))
            .and_then(|value| value.checked_add(STATE_CHECKSUM_BYTES))
            .ok_or(ManagedModelAgentStackApplyControllerError::StateTooLarge)?;
        if expected != frame.len() {
            return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
        }
        let execution_wire = cursor.take(execution_length)?;
        let request_wire = cursor.take(request_length)?;
        let receipt_wire = cursor.take(receipt_length)?;
        let archived_execution_wire = cursor.take(archived_execution_length)?;
        let archived_request_wire = cursor.take(archived_request_length)?;
        let archived_receipt_wire = cursor.take(archived_receipt_length)?;
        let checksum = Digest32::from_bytes(cursor.array()?);
        cursor.finish()?;
        if state_checksum(&frame[..frame.len() - STATE_CHECKSUM_BYTES])? != checksum {
            return Err(ManagedModelAgentStackApplyControllerError::StateChecksumMismatch);
        }

        let archived_active = if archived_revision == 0
            && archived_execution_wire.is_empty()
            && archived_request_wire.is_empty()
            && archived_receipt_wire.is_empty()
        {
            None
        } else {
            if archived_revision == 0
                || archived_execution_wire.is_empty()
                || archived_request_wire.is_empty()
                || archived_receipt_wire.is_empty()
            {
                return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
            }
            let desired = ManagedModelAgentStackDesiredPlanV1::try_restore(
                context,
                cutover_marker_digest,
                predecessor_slice_digest,
                archived_revision,
                archived_execution_wire,
            )?;
            if desired.revision().value() != successor(predecessor_revision.value())?
                || desired.execution().mode()
                    != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
                || desired.execution().managed_agent_stack().fabric() != predecessor_execution
            {
                return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
            }
            let request = ManagedModelAgentStackApplyRequestV1::decode(archived_request_wire)?;
            validate_managed_model_agent_stack_request_v1(context, &desired, &request)?;
            let receipt = ManagedModelAgentStackTerminalReceiptV1::decode(archived_receipt_wire)?;
            verify_terminal(&receipt, &request, context, predecessor_generation)?;
            if receipt.facts().state().outcome()
                != ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
            {
                return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
            }
            Some(CompletedManagedModelAgentStackApplyV1 {
                desired,
                request,
                receipt,
            })
        };
        let expected_predecessor = archived_active
            .as_ref()
            .map_or(predecessor_slice_digest, |archived| {
                archived.request.target_slice_digest()
            });
        if encoded_predecessor != expected_predecessor {
            return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
        }
        let desired = ManagedModelAgentStackDesiredPlanV1::try_restore(
            context,
            cutover_marker_digest,
            expected_predecessor,
            revision,
            execution_wire,
        )?;
        let request = ManagedModelAgentStackApplyRequestV1::decode(request_wire)?;
        match archived_active.as_ref() {
            None => {
                if desired.revision().value() != successor(predecessor_revision.value())?
                    || desired.execution().mode()
                        != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
                    || desired.execution().managed_agent_stack().fabric() != predecessor_execution
                {
                    return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
                }
                validate_managed_model_agent_stack_request_v1(context, &desired, &request)?;
            }
            Some(archived) => {
                if desired.revision().value() != successor(archived.desired.revision().value())?
                    || desired.execution().mode()
                        != ManagedModelAgentStackTargetModeV1::EmptyDeactivate
                {
                    return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
                }
                validate_managed_model_agent_stack_empty_request_v1(
                    context,
                    &desired,
                    archived.desired.execution(),
                    &request,
                )?;
            }
        }
        let receipt = match phase {
            ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent
            | ManagedModelAgentStackApplyPhaseV1::Uncertain => {
                if !receipt_wire.is_empty() {
                    return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
                }
                None
            }
            ManagedModelAgentStackApplyPhaseV1::ReceiptDurable => {
                if receipt_wire.is_empty() {
                    return Err(ManagedModelAgentStackApplyControllerError::InvalidState);
                }
                let receipt = ManagedModelAgentStackTerminalReceiptV1::decode(receipt_wire)?;
                verify_terminal(&receipt, &request, context, predecessor_generation)?;
                Some(receipt)
            }
        };
        Ok(Self {
            phase,
            desired,
            request,
            receipt,
            archived_active,
        })
    }
}

/// Proof that PXAR v9 bytes are durable and have never reached transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedManagedModelAgentStackApplyV1 {
    outer_sequence: u64,
    cutover_marker_digest: Digest32,
    request_digest: Digest32,
}

impl PreparedManagedModelAgentStackApplyV1 {
    #[must_use]
    pub(crate) const fn outer_sequence(self) -> u64 {
        self.outer_sequence
    }

    #[must_use]
    pub(crate) const fn request_digest(self) -> Digest32 {
        self.request_digest
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackSendActionV1 {
    outer_sequence: u64,
    cutover_marker_digest: Digest32,
    request: ManagedModelAgentStackApplyRequestV1,
    channel: ReferenceChannelBindingV1,
}

impl ManagedModelAgentStackSendActionV1 {
    #[must_use]
    pub(crate) const fn request(&self) -> &ManagedModelAgentStackApplyRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) fn canonical_request_bytes(&self) -> &[u8] {
        self.request.canonical_wire()
    }

    #[must_use]
    pub(crate) const fn channel(&self) -> ReferenceChannelBindingV1 {
        self.channel
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackTerminalCommitV1 {
    outer_sequence: u64,
    receipt: ManagedModelAgentStackTerminalReceiptV1,
    replayed_from_journal: bool,
}

impl ManagedModelAgentStackTerminalCommitV1 {
    #[must_use]
    pub(crate) const fn receipt(&self) -> &ManagedModelAgentStackTerminalReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub(crate) const fn replayed_from_journal(&self) -> bool {
        self.replayed_from_journal
    }

    #[must_use]
    pub(crate) fn is_active_success(&self) -> bool {
        self.receipt.facts().state().outcome()
            == ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
    }

    #[must_use]
    pub(crate) fn is_deactivation_success(&self) -> bool {
        self.receipt.facts().state().outcome()
            == ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackApplyJournalV1 {
    state: ManagedFabricControllerStateV1,
}

impl ManagedModelAgentStackApplyJournalV1 {
    #[must_use]
    pub(crate) const fn new(state: ManagedFabricControllerStateV1) -> Self {
        Self { state }
    }

    #[must_use]
    pub(crate) const fn state(&self) -> &ManagedFabricControllerStateV1 {
        &self.state
    }

    pub(crate) fn prepared(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<PreparedManagedModelAgentStackApplyV1, ManagedModelAgentStackApplyControllerError>
    {
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let stack = self
            .state
            .model_agent_stack_state()
            .ok_or(ManagedModelAgentStackApplyControllerError::InvalidPhase)?;
        validate_stack_request(&context, stack)?;
        prepared_token(&self.state, stack)
    }

    pub(crate) fn prepare_activate_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        activation: &ManagedModelAgentStackActivationV1,
        fresh: FreshManagedModelAgentStackApplyV1,
        commit: Commit,
    ) -> Result<PreparedManagedModelAgentStackApplyV1, ManagedModelAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedModelAgentStackApplyControllerError>,
    {
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let (predecessor_desired, predecessor_request, predecessor_receipt) =
            active_predecessor(&self.state)?;
        if let Some(stack) = self.state.model_agent_stack_state() {
            if stack.phase() != ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent
                || stack.archived_active().is_some()
            {
                return Err(match stack.phase() {
                    ManagedModelAgentStackApplyPhaseV1::Uncertain => {
                        ManagedModelAgentStackApplyControllerError::OpaqueReplayForbidden
                    }
                    ManagedModelAgentStackApplyPhaseV1::ReceiptDurable => {
                        ManagedModelAgentStackApplyControllerError::AlreadyTerminal
                    }
                    ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent => {
                        ManagedModelAgentStackApplyControllerError::InvalidPhase
                    }
                });
            }
            let expected = ManagedModelAgentStackDesiredPlanV1::try_activate(
                &context,
                self.state.cutover_marker_digest(),
                predecessor_desired.revision(),
                predecessor_desired.execution(),
                predecessor_request.target_slice_digest(),
                activation,
            )?;
            if stack.desired() != &expected {
                return Err(ManagedModelAgentStackApplyControllerError::DesiredConflict);
            }
            validate_managed_model_agent_stack_request_v1(
                &context,
                stack.desired(),
                stack.request(),
            )?;
            return prepared_token(&self.state, stack);
        }
        if predecessor_receipt.facts().outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        {
            return Err(ManagedModelAgentStackApplyControllerError::FabricNotActive);
        }
        let desired = ManagedModelAgentStackDesiredPlanV1::try_activate(
            &context,
            self.state.cutover_marker_digest(),
            predecessor_desired.revision(),
            predecessor_desired.execution(),
            predecessor_request.target_slice_digest(),
            activation,
        )?;
        let request = produce_managed_model_agent_stack_request_v1(
            &context,
            &desired,
            fresh,
            controller_signer,
        )?;
        let stack = ManagedModelAgentStackControllerStateV1::try_prepared(desired, request)?;
        let next = self.state.try_with_model_agent_stack_state(stack)?;
        commit(&next)?;
        self.state = next;
        prepared_token(
            &self.state,
            self.state
                .model_agent_stack_state()
                .ok_or(ManagedModelAgentStackApplyControllerError::InvalidState)?,
        )
    }

    pub(crate) fn prepare_empty_deactivate_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        fresh: FreshManagedModelAgentStackApplyV1,
        commit: Commit,
    ) -> Result<PreparedManagedModelAgentStackApplyV1, ManagedModelAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedModelAgentStackApplyControllerError>,
    {
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let (_, _, predecessor_receipt) = active_predecessor(&self.state)?;
        let predecessor_generation = predecessor_receipt
            .facts()
            .generation()
            .ok_or(ManagedModelAgentStackApplyControllerError::FabricNotActive)?;
        let current = self
            .state
            .model_agent_stack_state()
            .ok_or(ManagedModelAgentStackApplyControllerError::ModelAgentNotActive)?;
        match current.phase() {
            ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent => {
                let archived = current
                    .archived_active()
                    .ok_or(ManagedModelAgentStackApplyControllerError::ModelAgentNotActive)?;
                let expected = ManagedModelAgentStackDesiredPlanV1::try_empty_deactivate(
                    &context,
                    self.state.cutover_marker_digest(),
                    archived.desired(),
                    archived.request(),
                )?;
                if current.desired() != &expected {
                    return Err(ManagedModelAgentStackApplyControllerError::DesiredConflict);
                }
                validate_managed_model_agent_stack_empty_request_v1(
                    &context,
                    current.desired(),
                    archived.desired().execution(),
                    current.request(),
                )?;
                return prepared_token(&self.state, current);
            }
            ManagedModelAgentStackApplyPhaseV1::Uncertain => {
                return Err(ManagedModelAgentStackApplyControllerError::OpaqueReplayForbidden);
            }
            ManagedModelAgentStackApplyPhaseV1::ReceiptDurable
                if current.archived_active().is_some() =>
            {
                return Err(ManagedModelAgentStackApplyControllerError::AlreadyTerminal);
            }
            ManagedModelAgentStackApplyPhaseV1::ReceiptDurable => {}
        }
        let active_receipt = current
            .receipt()
            .ok_or(ManagedModelAgentStackApplyControllerError::ModelAgentNotActive)?;
        verify_terminal(
            active_receipt,
            current.request(),
            &context,
            predecessor_generation,
        )?;
        if active_receipt.facts().state().outcome()
            != ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
        {
            return Err(ManagedModelAgentStackApplyControllerError::ModelAgentNotActive);
        }
        let desired = ManagedModelAgentStackDesiredPlanV1::try_empty_deactivate(
            &context,
            self.state.cutover_marker_digest(),
            current.desired(),
            current.request(),
        )?;
        let request = produce_managed_model_agent_stack_empty_request_v1(
            &context,
            &desired,
            current.desired().execution(),
            fresh,
            controller_signer,
        )?;
        let stack = current.try_prepare_empty(desired, request)?;
        let next = self.state.try_with_model_agent_stack_state(stack)?;
        commit(&next)?;
        self.state = next;
        prepared_token(
            &self.state,
            self.state
                .model_agent_stack_state()
                .ok_or(ManagedModelAgentStackApplyControllerError::InvalidState)?,
        )
    }

    pub(crate) fn claim_send_with<Commit>(
        &mut self,
        prepared: PreparedManagedModelAgentStackApplyV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        commit: Commit,
    ) -> Result<ManagedModelAgentStackSendActionV1, ManagedModelAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedModelAgentStackApplyControllerError>,
    {
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let stack = self
            .state
            .model_agent_stack_state()
            .ok_or(ManagedModelAgentStackApplyControllerError::InvalidPhase)?;
        validate_prepared(&self.state, stack, prepared)?;
        validate_stack_request(&context, stack)?;
        let request = stack.request().clone();
        let next = self
            .state
            .try_with_model_agent_stack_state(stack.try_claim()?)?;
        commit(&next)?;
        self.state = next;
        Ok(ManagedModelAgentStackSendActionV1 {
            outer_sequence: self.state.sequence(),
            cutover_marker_digest: self.state.cutover_marker_digest(),
            request,
            channel: context.channel(),
        })
    }

    /// Validates and durably commits every legal PXMT classification.
    pub(crate) fn consume_pxmt_with<Commit>(
        &mut self,
        action: ManagedModelAgentStackSendActionV1,
        receipt_wire: &[u8],
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        commit: Commit,
    ) -> Result<ManagedModelAgentStackTerminalCommitV1, ManagedModelAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedModelAgentStackApplyControllerError>,
    {
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let (_, _, predecessor_receipt) = active_predecessor(&self.state)?;
        let predecessor_generation = predecessor_receipt
            .facts()
            .generation()
            .ok_or(ManagedModelAgentStackApplyControllerError::FabricNotActive)?;
        let stack = self
            .state
            .model_agent_stack_state()
            .ok_or(ManagedModelAgentStackApplyControllerError::InvalidPhase)?;
        if stack.phase() != ManagedModelAgentStackApplyPhaseV1::Uncertain
            || action.outer_sequence != self.state.sequence()
            || action.cutover_marker_digest != self.state.cutover_marker_digest()
            || action.request != *stack.request()
            || action.channel != context.channel()
        {
            return Err(ManagedModelAgentStackApplyControllerError::SendActionMismatch);
        }
        let receipt = ManagedModelAgentStackTerminalReceiptV1::decode(receipt_wire)?;
        verify_terminal(&receipt, stack.request(), &context, predecessor_generation)?;
        let next = self
            .state
            .try_with_model_agent_stack_state(stack.try_terminal(receipt.clone())?)?;
        commit(&next)?;
        self.state = next;
        Ok(ManagedModelAgentStackTerminalCommitV1 {
            outer_sequence: self.state.sequence(),
            receipt,
            replayed_from_journal: false,
        })
    }

    pub(crate) fn terminal(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<
        Option<ManagedModelAgentStackTerminalCommitV1>,
        ManagedModelAgentStackApplyControllerError,
    > {
        let Some(stack) = self.state.model_agent_stack_state() else {
            return Ok(None);
        };
        if stack.phase() != ManagedModelAgentStackApplyPhaseV1::ReceiptDurable {
            return Ok(None);
        }
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let (_, _, predecessor_receipt) = active_predecessor(&self.state)?;
        let predecessor_generation = predecessor_receipt
            .facts()
            .generation()
            .ok_or(ManagedModelAgentStackApplyControllerError::FabricNotActive)?;
        let receipt = stack
            .receipt()
            .ok_or(ManagedModelAgentStackApplyControllerError::InvalidState)?;
        verify_terminal(receipt, stack.request(), &context, predecessor_generation)?;
        Ok(Some(ManagedModelAgentStackTerminalCommitV1 {
            outer_sequence: self.state.sequence(),
            receipt: receipt.clone(),
            replayed_from_journal: true,
        }))
    }
}

fn validate_stack_request(
    context: &VerifiedManagedFabricProducerContextV1,
    stack: &ManagedModelAgentStackControllerStateV1,
) -> Result<(), ManagedModelAgentStackApplyControllerError> {
    match stack.archived_active() {
        None => validate_managed_model_agent_stack_request_v1(
            context,
            stack.desired(),
            stack.request(),
        )?,
        Some(archived) => validate_managed_model_agent_stack_empty_request_v1(
            context,
            stack.desired(),
            archived.desired().execution(),
            stack.request(),
        )?,
    }
    Ok(())
}

fn active_predecessor(
    state: &ManagedFabricControllerStateV1,
) -> Result<
    (
        &crate::managed_fabric_producer::ManagedFabricDesiredPlanV1,
        &paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricApplyRequestV1,
        &paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricApplyTerminalReceiptV1,
    ),
    ManagedModelAgentStackApplyControllerError,
> {
    if state.phase() != ManagedFabricApplyPhaseV1::ReceiptDurable
        || state.archived_active().is_some()
    {
        return Err(ManagedModelAgentStackApplyControllerError::FabricNotActive);
    }
    let desired = state
        .desired()
        .ok_or(ManagedModelAgentStackApplyControllerError::FabricNotActive)?;
    let request = state
        .request()
        .ok_or(ManagedModelAgentStackApplyControllerError::FabricNotActive)?;
    let receipt = state
        .receipt()
        .ok_or(ManagedModelAgentStackApplyControllerError::FabricNotActive)?;
    if desired.execution().mode() != ManagedFabricTargetModeV1::OneManagedFabricService
        || receipt.facts().outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        || receipt.facts().generation().is_none()
    {
        return Err(ManagedModelAgentStackApplyControllerError::FabricNotActive);
    }
    Ok((desired, request, receipt))
}

fn prepared_token(
    state: &ManagedFabricControllerStateV1,
    stack: &ManagedModelAgentStackControllerStateV1,
) -> Result<PreparedManagedModelAgentStackApplyV1, ManagedModelAgentStackApplyControllerError> {
    if stack.phase() != ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent {
        return Err(ManagedModelAgentStackApplyControllerError::InvalidPhase);
    }
    Ok(PreparedManagedModelAgentStackApplyV1 {
        outer_sequence: state.sequence(),
        cutover_marker_digest: state.cutover_marker_digest(),
        request_digest: stack.request().envelope_request_digest(),
    })
}

fn validate_prepared(
    state: &ManagedFabricControllerStateV1,
    stack: &ManagedModelAgentStackControllerStateV1,
    prepared: PreparedManagedModelAgentStackApplyV1,
) -> Result<(), ManagedModelAgentStackApplyControllerError> {
    if stack.phase() != ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent
        || prepared.outer_sequence != state.sequence()
        || prepared.cutover_marker_digest != state.cutover_marker_digest()
        || prepared.request_digest != stack.request().envelope_request_digest()
    {
        return Err(ManagedModelAgentStackApplyControllerError::PreparedTokenMismatch);
    }
    Ok(())
}

fn verify_terminal(
    receipt: &ManagedModelAgentStackTerminalReceiptV1,
    request: &ManagedModelAgentStackApplyRequestV1,
    context: &VerifiedManagedFabricProducerContextV1,
    predecessor_generation: ManagedServiceGeneration,
) -> Result<(), ManagedModelAgentStackApplyControllerError> {
    let facts = receipt.validate_against_request(request, context.channel())?;
    let state = facts.state();
    if state
        .fabric_generation()
        .is_some_and(|generation| generation != predecessor_generation)
        || receipt.authentication_key() != context.runtime_response_key()
        || receipt.authentication_algorithm().value() != ED25519_ALGORITHM
        || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
        || receipt.authentication_signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(ManagedModelAgentStackApplyControllerError::ReceiptMismatch);
    }
    let signature: [u8; ED25519_SIGNATURE_BYTES] = receipt
        .authentication_signature()
        .try_into()
        .map_err(|_| ManagedModelAgentStackApplyControllerError::ReceiptMismatch)?;
    context
        .runtime_response_public_key()
        .verify_strict(
            receipt.signing_transcript()?.as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| ManagedModelAgentStackApplyControllerError::ReceiptMismatch)
}

fn wire_length(bytes: &[u8]) -> Result<u32, ManagedModelAgentStackApplyControllerError> {
    u32::try_from(bytes.len())
        .map_err(|_| ManagedModelAgentStackApplyControllerError::StateTooLarge)
}

fn successor(value: u64) -> Result<u64, ManagedModelAgentStackApplyControllerError> {
    value
        .checked_add(1)
        .ok_or(ManagedModelAgentStackApplyControllerError::SequenceExhausted)
}

fn state_checksum(bytes: &[u8]) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(STATE_CHECKSUM_DOMAIN)?;
    builder.field_bytes(bytes)?;
    Ok(builder.finish())
}

struct Cursor<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn take(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], ManagedModelAgentStackApplyControllerError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ManagedModelAgentStackApplyControllerError::StateTooLarge)?;
        let bytes = self
            .frame
            .get(self.position..end)
            .ok_or(ManagedModelAgentStackApplyControllerError::StateTruncated)?;
        self.position = end;
        Ok(bytes)
    }

    fn array<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], ManagedModelAgentStackApplyControllerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ManagedModelAgentStackApplyControllerError::StateTruncated)
    }

    fn u8(&mut self) -> Result<u8, ManagedModelAgentStackApplyControllerError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ManagedModelAgentStackApplyControllerError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ManagedModelAgentStackApplyControllerError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize_u32(&mut self) -> Result<usize, ManagedModelAgentStackApplyControllerError> {
        usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| ManagedModelAgentStackApplyControllerError::StateTooLarge)
    }

    fn finish(self) -> Result<(), ManagedModelAgentStackApplyControllerError> {
        if self.position == self.frame.len() {
            Ok(())
        } else {
            Err(ManagedModelAgentStackApplyControllerError::InvalidState)
        }
    }
}

#[derive(Debug)]
pub(crate) enum ManagedModelAgentStackApplyControllerError {
    Contract,
    Producer(ManagedModelAgentStackProducerError),
    Fabric(ManagedFabricApplyControllerError),
    Digest(DigestBuildError),
    InvalidPhase,
    InvalidState,
    StateTruncated,
    StateTooLarge,
    StateChecksumMismatch,
    SequenceExhausted,
    FabricNotActive,
    ModelAgentNotActive,
    DesiredConflict,
    DurabilityRejected,
    PreparedTokenMismatch,
    SendActionMismatch,
    OpaqueReplayForbidden,
    ReceiptMismatch,
    AlreadyTerminal,
}

impl From<ManagedModelAgentStackPlanError> for ManagedModelAgentStackApplyControllerError {
    fn from(_value: ManagedModelAgentStackPlanError) -> Self {
        Self::Contract
    }
}

impl From<ManagedModelAgentStackProducerError> for ManagedModelAgentStackApplyControllerError {
    fn from(value: ManagedModelAgentStackProducerError) -> Self {
        Self::Producer(value)
    }
}

impl From<ManagedFabricApplyControllerError> for ManagedModelAgentStackApplyControllerError {
    fn from(value: ManagedFabricApplyControllerError) -> Self {
        Self::Fabric(value)
    }
}

impl From<DigestBuildError> for ManagedModelAgentStackApplyControllerError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ManagedModelAgentStackApplyControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed Model+Agent stack apply failed: {self:?}"
        )
    }
}

impl std::error::Error for ManagedModelAgentStackApplyControllerError {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::time::BoundedDuration;
    use paraegox_runtime_contracts::apply::ExpectedActive;
    use paraegox_runtime_contracts::assignment::BindingId;
    use paraegox_runtime_contracts::managed_agent_stack_plan::{
        ManagedAgentIngressLimitsV1, ManagedAgentPortPlanV1, ManagedAgentProviderRefV1,
        ManagedAgentProviderSelectionV1, ManagedAgentSemanticLimitsV1, ManagedAgentServicePlanV1,
    };
    use paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricListenEndpointV1;
    use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
        MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION,
        MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_VERSION, ManagedModelAdapterBindingV1,
        ManagedModelAdapterVersionV1, ManagedModelAgentStackTerminalAuthClaimV1,
        ManagedModelAgentStackTerminalEvidenceFieldsV1, ManagedModelAgentStackTerminalEvidenceV1,
        ManagedModelAgentStackTerminalFactsV1, ManagedModelAgentStackTerminalHeadV1,
        ManagedModelAgentStackTerminalLifecycleEffectV1, ManagedModelAgentStackTerminalOutcomeV1,
        ManagedModelAgentStackTerminalReceiptDraftV1, ManagedModelAgentStackTerminalReceiptV1,
        ManagedModelAgentStackTerminalStateV1, ManagedModelCapabilityIdV1,
        ManagedModelServicePlanV1,
    };
    use paraegox_runtime_contracts::managed_service::{
        ManagedServiceGeneration, ManagedServiceId, ManagedServiceLifecycleBudgetsV1,
        ManagedServiceSpecV1,
    };
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

    use super::*;
    use crate::managed_fabric_apply::{
        ManagedFabricApplyJournalV1, ManagedFabricControllerStateV1, tests as fabric_tests,
    };

    const RUNTIME_KEY: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x38; 16]);

    fn budgets(values: [u64; 5]) -> ManagedServiceLifecycleBudgetsV1 {
        ManagedServiceLifecycleBudgetsV1::try_new(
            BoundedDuration::from_nanos(values[0]),
            BoundedDuration::from_nanos(values[1]),
            BoundedDuration::from_nanos(values[2]),
            BoundedDuration::from_nanos(values[3]),
            BoundedDuration::from_nanos(values[4]),
        )
        .expect("fixture lifecycle budgets")
    }

    fn provider(seed: u8) -> ManagedAgentProviderSelectionV1 {
        ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            ManagedAgentProviderRefV1::try_from_bytes([seed; 16]).expect("provider ref"),
            Digest32::from_bytes([seed.wrapping_add(1); 32]),
        )
        .expect("provider selection")
    }

    fn agent_plan(selection: ManagedAgentProviderSelectionV1) -> ManagedAgentServicePlanV1 {
        let ingress = ManagedAgentIngressLimitsV1::try_new(
            64,
            512 * 1024,
            128 * 1024,
            128 * 1024,
            5_000_000_000,
        )
        .expect("bounded ingress");
        ManagedAgentServicePlanV1::try_new(
            ManagedServiceSpecV1::new(
                ManagedServiceId::from_bytes([0x88; 16]),
                budgets([7, 11, 13, 17, 19]),
            ),
            ManagedAgentSemanticLimitsV1::try_new(16, 64, 64, 64).expect("semantic limits"),
            ManagedAgentPortPlanV1::try_new(
                BindingId::from_bytes([0x81; 16]),
                BindingId::from_bytes([0x82; 16]),
                "paraegox/agent/v1/submit",
                "paraegox/agent/v1/control",
                ingress,
            )
            .expect("Agent port"),
            selection,
        )
        .expect("Agent plan")
    }

    fn model_plan(selection: ManagedAgentProviderSelectionV1) -> ManagedModelServicePlanV1 {
        ManagedModelServicePlanV1::try_new(
            ManagedServiceSpecV1::new(
                ManagedServiceId::from_bytes([0x89; 16]),
                budgets([23, 29, 31, 37, 41]),
            ),
            8,
            selection,
            ManagedModelAdapterBindingV1::try_new(
                [0x90; 16],
                ManagedModelAdapterVersionV1::try_new(7).expect("adapter version"),
                ManagedModelCapabilityIdV1::bounded_text_v1(),
            )
            .expect("adapter binding"),
        )
        .expect("Model plan")
    }

    fn activation(
        selection: ManagedAgentProviderSelectionV1,
        state: &ManagedFabricControllerStateV1,
    ) -> ManagedModelAgentStackActivationV1 {
        ManagedModelAgentStackActivationV1::try_new(
            state
                .desired()
                .expect("active Fabric desired")
                .execution()
                .clone(),
            agent_plan(selection),
            model_plan(selection),
        )
        .expect("A2 activation")
    }

    fn fresh(marker: u8) -> FreshManagedModelAgentStackApplyV1 {
        FreshManagedModelAgentStackApplyV1::try_new(
            [marker; 16],
            [marker.wrapping_add(1); 16],
            [marker.wrapping_add(2); 32],
        )
        .expect("fresh A2 identities")
    }

    fn active_fabric_state() -> ManagedFabricControllerStateV1 {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let mut journal: ManagedFabricApplyJournalV1 = fabric_tests::journal();
        let prepared = journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                fabric_tests::service(),
                ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                    .expect("Fabric endpoint"),
                fabric_tests::fresh(0x91),
                |_| Ok(()),
            )
            .expect("prepare Fabric");
        let action = journal
            .claim_send_with(prepared, &controller, &provisioning, |_| Ok(()))
            .expect("claim Fabric send");
        let receipt = fabric_tests::active_receipt(action.request());
        journal
            .consume_pxft_with(
                action,
                receipt.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            )
            .expect("commit active Fabric");
        journal.state().clone()
    }

    fn prepared_journal() -> (
        ManagedModelAgentStackApplyJournalV1,
        PreparedManagedModelAgentStackApplyV1,
    ) {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let state = active_fabric_state();
        let requested = activation(provider(0x83), &state);
        let mut journal = ManagedModelAgentStackApplyJournalV1::new(state);
        let prepared = journal
            .prepare_activate_with(&controller, &provisioning, &requested, fresh(0x92), |_| {
                Ok(())
            })
            .expect("prepare PXAR9");
        (journal, prepared)
    }

    fn uncertain_journal() -> (
        ManagedModelAgentStackApplyJournalV1,
        ManagedModelAgentStackSendActionV1,
    ) {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let (mut journal, prepared) = prepared_journal();
        let action = journal
            .claim_send_with(prepared, &controller, &provisioning, |_| Ok(()))
            .expect("claim PXAR9");
        (journal, action)
    }

    fn signed_receipt(
        request: &ManagedModelAgentStackApplyRequestV1,
        outcome: ManagedModelAgentStackTerminalOutcomeV1,
        fabric_generation: u64,
    ) -> ManagedModelAgentStackTerminalReceiptV1 {
        let generation =
            |value| Some(ManagedServiceGeneration::try_new(value).expect("service generation"));
        let (lifecycle, head, fabric, model, agent) = match outcome {
            ManagedModelAgentStackTerminalOutcomeV1::ActiveReady => (
                ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                generation(fabric_generation),
                generation(2),
                generation(3),
            ),
            ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero => (
                ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                None,
                None,
                None,
            ),
            ManagedModelAgentStackTerminalOutcomeV1::NoEffectRejected => (
                ManagedModelAgentStackTerminalLifecycleEffectV1::ProvenNotStarted,
                ManagedModelAgentStackTerminalHeadV1::PreservedNone,
                None,
                None,
                None,
            ),
            ManagedModelAgentStackTerminalOutcomeV1::Uncertain => (
                ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                generation(fabric_generation),
                None,
                None,
            ),
            ManagedModelAgentStackTerminalOutcomeV1::Quarantined => (
                ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                generation(fabric_generation),
                generation(2),
                None,
            ),
        };
        let state = ManagedModelAgentStackTerminalStateV1::try_new(
            outcome, lifecycle, head, fabric, model, agent,
        )
        .expect("terminal state");
        let (
            physical_binding_census,
            census_complete,
            fabric_ready,
            model_ready,
            agent_ready,
            fabric_dependency,
            model_dependency,
            exact_zero,
            quarantined,
        ) = match outcome {
            ManagedModelAgentStackTerminalOutcomeV1::ActiveReady => {
                (2, true, true, true, true, true, true, false, false)
            }
            ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero
            | ManagedModelAgentStackTerminalOutcomeV1::NoEffectRejected => {
                (0, true, false, false, false, false, false, true, false)
            }
            ManagedModelAgentStackTerminalOutcomeV1::Uncertain => {
                (1, false, true, false, false, false, false, false, false)
            }
            ManagedModelAgentStackTerminalOutcomeV1::Quarantined => {
                (1, true, true, false, false, false, false, false, true)
            }
        };
        let evidence = ManagedModelAgentStackTerminalEvidenceV1::try_new(
            ManagedModelAgentStackTerminalEvidenceFieldsV1 {
                physical_binding_census,
                census_complete,
                fabric_ready,
                model_ready,
                agent_ready,
                fabric_to_agent_dependency_ready: fabric_dependency,
                model_to_agent_dependency_ready: model_dependency,
                exact_zero,
                quarantined,
                resource_census_digest: Digest32::from_bytes([0xa1; 32]),
                raw_outcome_digest: Digest32::from_bytes([0xa2; 32]),
                completion_runtime_host_epoch: 12,
                completion_snapshot_sequence: 13,
                selection_clock_generation: request.temporal().target_clock_generation(),
                selection_observed_at_nanos: 14,
            },
        )
        .expect("terminal evidence");
        let facts = ManagedModelAgentStackTerminalFactsV1::try_new(request, state, evidence)
            .expect("terminal facts");
        let channel = fabric_tests::channel();
        let auth = ManagedModelAgentStackTerminalAuthClaimV1::try_new(
            channel,
            RUNTIME_KEY,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("terminal auth");
        let draft =
            ManagedModelAgentStackTerminalReceiptDraftV1::try_new(request, facts, channel, auth)
                .expect("PXMT draft");
        let runtime: SigningKey = fabric_tests::runtime_signer();
        let signature = runtime.sign(
            draft
                .signing_transcript()
                .expect("PXMT transcript")
                .as_bytes(),
        );
        draft.finalize(&signature.to_bytes()).expect("signed PXMT")
    }

    fn reopen_stack(
        state: &ManagedFabricControllerStateV1,
    ) -> ManagedModelAgentStackControllerStateV1 {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let context = state
            .verified_current_context(&controller, &provisioning)
            .expect("verified context");
        let desired = state.desired().expect("Fabric desired");
        let request = state.request().expect("Fabric request");
        let generation = state
            .receipt()
            .and_then(|receipt| receipt.facts().generation())
            .expect("Fabric generation");
        let stack = state.model_agent_stack_state().expect("A2 state");
        let wire = stack.encode().expect("PXMJ encode");
        ManagedModelAgentStackControllerStateV1::decode(
            &wire,
            ManagedModelAgentStackDecodeContextV1 {
                fabric: &context,
                cutover_marker_digest: state.cutover_marker_digest(),
                predecessor_revision: desired.revision(),
                predecessor_execution: desired.execution(),
                predecessor_slice_digest: request.target_slice_digest(),
                predecessor_generation: generation,
            },
        )
        .expect("PXMJ reopen")
    }

    #[test]
    fn producer_commits_pxte8_pxar9_revision_cas_budget_provider_and_adapter() {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let state = active_fabric_state();
        let predecessor_revision = state.desired().expect("Fabric desired").revision();
        let predecessor_slice = state
            .request()
            .expect("Fabric request")
            .target_slice_digest();
        let selection = provider(0x83);
        let requested = activation(selection, &state);
        let mut journal = ManagedModelAgentStackApplyJournalV1::new(state);
        let crossed = Cell::new(false);
        let _prepared = journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                &requested,
                fresh(0x92),
                |next| {
                    let stack = next.model_agent_stack_state().expect("durable A2");
                    assert_eq!(
                        stack.phase(),
                        ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent
                    );
                    crossed.set(true);
                    Ok(())
                },
            )
            .expect("prepare A2");
        assert!(crossed.get());
        let stack = journal.state().model_agent_stack_state().expect("A2 state");
        assert_eq!(
            stack.desired().revision().value(),
            predecessor_revision.value() + 1
        );
        assert_eq!(
            stack.desired().predecessor_slice_digest(),
            predecessor_slice
        );
        assert_eq!(
            stack
                .request()
                .control_commitment()
                .control()
                .expected_active(),
            ExpectedActive::Exact(predecessor_slice)
        );
        assert_eq!(&stack.desired().execution().canonical_wire()[..4], b"PXTE");
        assert_eq!(
            u16::from_be_bytes(
                stack.desired().execution().canonical_wire()[4..6]
                    .try_into()
                    .expect("PXTE version")
            ),
            MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_VERSION
        );
        assert_eq!(&stack.request().canonical_wire()[..4], b"PXAR");
        assert_eq!(
            u16::from_be_bytes(
                stack.request().canonical_wire()[4..6]
                    .try_into()
                    .expect("PXAR version")
            ),
            MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION
        );
        assert_eq!(stack.request().temporal().original_budget().value(), 114);
        let model = stack.desired().execution().model().expect("Model plan");
        assert_eq!(model.provider(), selection);
        assert_eq!(model.adapter_binding().adapter_id(), &[0x90; 16]);
        assert_eq!(model.adapter_binding().adapter_version().value(), 7);

        let mismatch = ManagedModelAgentStackActivationV1::try_new(
            requested.expected_fabric().clone(),
            requested.agent().clone(),
            model_plan(provider(0x93)),
        )
        .expect("shape-only activation");
        let mut other = ManagedModelAgentStackApplyJournalV1::new(active_fabric_state());
        assert!(
            other
                .prepare_activate_with(&controller, &provisioning, &mismatch, fresh(0x96), |_| Ok(
                    ()
                ),)
                .is_err()
        );
    }

    #[test]
    fn send_token_exists_only_after_uncertain_is_durable() {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let (mut journal, prepared) = prepared_journal();
        let failed = journal.claim_send_with(prepared, &controller, &provisioning, |_| {
            Err(ManagedModelAgentStackApplyControllerError::DurabilityRejected)
        });
        assert!(failed.is_err());
        assert_eq!(
            journal
                .state()
                .model_agent_stack_state()
                .expect("A2 state")
                .phase(),
            ManagedModelAgentStackApplyPhaseV1::RequestDurableNotSent
        );

        let crossed = Cell::new(false);
        let action = journal
            .claim_send_with(prepared, &controller, &provisioning, |next| {
                assert_eq!(
                    next.model_agent_stack_state().expect("A2 state").phase(),
                    ManagedModelAgentStackApplyPhaseV1::Uncertain
                );
                crossed.set(true);
                Ok(())
            })
            .expect("send action");
        assert!(crossed.get());
        assert_eq!(
            action.request().canonical_wire(),
            action.canonical_request_bytes()
        );
    }

    #[test]
    fn pxmj_roundtrip_checksum_lengths_and_predecessor_magic_are_strict() {
        let (journal, _) = uncertain_journal();
        let stack = journal.state().model_agent_stack_state().expect("A2 state");
        let wire = stack.encode().expect("PXMJ");
        assert_eq!(&wire[..4], b"PXMJ");
        assert_eq!(reopen_stack(journal.state()), *stack);

        for corrupted in [
            {
                let mut value = wire.to_vec();
                value[4] = 0;
                value[5] = 2;
                value
            },
            {
                let mut value = wire.to_vec();
                value[..4].copy_from_slice(b"PXAJ");
                value
            },
            {
                let mut value = wire.to_vec();
                let last = value.len() - 1;
                value[last] ^= 1;
                value
            },
            wire[..wire.len() - 1].to_vec(),
            {
                let mut value = wire.to_vec();
                value.push(0);
                value
            },
        ] {
            let controller = fabric_tests::controller_signer();
            let provisioning = fabric_tests::provisioning();
            let context = journal
                .state()
                .verified_current_context(&controller, &provisioning)
                .expect("context");
            let fabric = journal.state().desired().expect("Fabric desired");
            let request = journal.state().request().expect("Fabric request");
            let generation = journal
                .state()
                .receipt()
                .and_then(|receipt| receipt.facts().generation())
                .expect("Fabric generation");
            assert!(
                ManagedModelAgentStackControllerStateV1::decode(
                    &corrupted,
                    ManagedModelAgentStackDecodeContextV1 {
                        fabric: &context,
                        cutover_marker_digest: journal.state().cutover_marker_digest(),
                        predecessor_revision: fabric.revision(),
                        predecessor_execution: fabric.execution(),
                        predecessor_slice_digest: request.target_slice_digest(),
                        predecessor_generation: generation,
                    },
                )
                .is_err()
            );
        }
    }

    #[test]
    fn every_legal_active_pxmt_is_durable_but_only_active_ready_opens_empty() {
        for (index, outcome) in [
            ManagedModelAgentStackTerminalOutcomeV1::ActiveReady,
            ManagedModelAgentStackTerminalOutcomeV1::Quarantined,
            ManagedModelAgentStackTerminalOutcomeV1::NoEffectRejected,
            ManagedModelAgentStackTerminalOutcomeV1::Uncertain,
        ]
        .into_iter()
        .enumerate()
        {
            let controller = fabric_tests::controller_signer();
            let provisioning = fabric_tests::provisioning();
            let (mut journal, action) = uncertain_journal();
            let receipt = signed_receipt(action.request(), outcome, 1);
            journal
                .consume_pxmt_with(
                    action,
                    receipt.canonical_wire(),
                    &controller,
                    &provisioning,
                    |_| Ok(()),
                )
                .expect("durable legal PXMT");
            let reopened = reopen_stack(journal.state());
            assert_eq!(
                reopened
                    .receipt()
                    .expect("receipt")
                    .facts()
                    .state()
                    .outcome(),
                outcome
            );
            assert!(!reopened.deactivation_succeeded());
            let empty = journal.prepare_empty_deactivate_with(
                &controller,
                &provisioning,
                fresh(0xb0 + index as u8 * 3),
                |_| Ok(()),
            );
            assert_eq!(
                empty.is_ok(),
                outcome == ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
            );
        }
    }

    #[test]
    fn empty_exact_zero_reopens_as_only_deactivation_success_and_uses_next_cas() {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let (mut journal, action) = uncertain_journal();
        let active = signed_receipt(
            action.request(),
            ManagedModelAgentStackTerminalOutcomeV1::ActiveReady,
            1,
        );
        journal
            .consume_pxmt_with(
                action,
                active.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            )
            .expect("active PXMT");
        let active_stack = journal
            .state()
            .model_agent_stack_state()
            .expect("active A2")
            .clone();
        let prepared = journal
            .prepare_empty_deactivate_with(&controller, &provisioning, fresh(0xc0), |_| Ok(()))
            .expect("prepare empty");
        let empty_stack = journal.state().model_agent_stack_state().expect("empty A2");
        assert_eq!(
            empty_stack.desired().revision().value(),
            active_stack.desired().revision().value() + 1
        );
        assert_eq!(
            empty_stack
                .request()
                .control_commitment()
                .control()
                .expected_active(),
            ExpectedActive::Exact(active_stack.request().target_slice_digest())
        );
        assert_eq!(
            empty_stack.request().temporal().original_budget().value(),
            9_000_000_114
        );
        let action = journal
            .claim_send_with(prepared, &controller, &provisioning, |_| Ok(()))
            .expect("claim empty");
        let empty = signed_receipt(
            action.request(),
            ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero,
            1,
        );
        let terminal = journal
            .consume_pxmt_with(
                action,
                empty.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            )
            .expect("empty PXMT");
        assert!(terminal.is_deactivation_success());
        assert!(
            journal
                .state()
                .model_agent_stack_state()
                .expect("empty A2")
                .deactivation_succeeded()
        );
        assert!(reopen_stack(journal.state()).deactivation_succeeded());
    }

    #[test]
    fn terminal_fabric_generation_must_match_pxar6_predecessor() {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let (mut journal, action) = uncertain_journal();
        let mismatch = signed_receipt(
            action.request(),
            ManagedModelAgentStackTerminalOutcomeV1::ActiveReady,
            99,
        );
        assert!(matches!(
            journal.consume_pxmt_with(
                action,
                mismatch.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            ),
            Err(ManagedModelAgentStackApplyControllerError::ReceiptMismatch)
        ));
        assert_eq!(
            journal
                .state()
                .model_agent_stack_state()
                .expect("A2 state")
                .phase(),
            ManagedModelAgentStackApplyPhaseV1::Uncertain
        );
    }
}
