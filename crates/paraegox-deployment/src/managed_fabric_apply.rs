//! Durable-boundary state machine for one managed-fabric activation.
//!
//! No transport send action exists until exact signed PXAR v6 and desired PXTE
//! v5 bytes cross the caller-owned durable commit boundary. The state then
//! enters `Uncertain` durably before exposing one move-only send action, so a
//! timeout, disconnect, cancellation, or process loss cannot authorize replay.

use core::fmt;

use ed25519_dalek::Signature;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_runtime_contracts::apply::ExpectedActive;
use paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentStackTargetModeV1;
use paraegox_runtime_contracts::managed_fabric_plan::{
    ManagedFabricApplyRequestV1, ManagedFabricApplyTerminalFactsV1,
    ManagedFabricApplyTerminalHeadV1, ManagedFabricApplyTerminalOutcomeV1,
    ManagedFabricApplyTerminalReceiptV1, ManagedFabricListenEndpointV1, ManagedFabricPlanError,
    ManagedFabricTargetModeV1,
};
use paraegox_runtime_contracts::managed_model_agent_stack_plan::ManagedModelAgentStackTargetModeV1;
use paraegox_runtime_contracts::managed_service::ManagedServiceSpecV1;
use paraegox_runtime_contracts::managed_serving_bootstrap::ManagedServingBootstrapRequestV1;
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;

use crate::controller_journal::{ControllerJournalError, ControllerJournalSnapshot};
use crate::managed_agent_stack_apply::{
    ManagedAgentStackControllerStateV1, ManagedAgentStackDecodeContextV1,
};
use crate::managed_fabric_producer::{
    FreshManagedFabricApplyV1, ManagedFabricControllerProvisioningV1,
    ManagedFabricControllerRequestDraftV1, ManagedFabricDesiredPlanV1, ManagedFabricProducerError,
    VerifiedManagedFabricProducerContextV1,
};
use crate::managed_model_agent_stack_apply::{
    ManagedModelAgentStackControllerStateV1, ManagedModelAgentStackDecodeContextV1,
};
use crate::managed_serving_client::{
    FreshManagedServingBootstrapV1, ManagedServingBootstrapPhaseV1, ManagedServingBootstrapStateV1,
    ManagedServingControllerError, VerifiedManagedServingPinV1,
};

const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;
const STATE_MAGIC: &[u8; 4] = b"PXFJ";
const LEGACY_STATE_VERSION: u16 = 2;
const LEGACY_STATE_FIXED_BYTES: usize = 100;
const AGENT_STACK_STATE_VERSION: u16 = 3;
const AGENT_STACK_STATE_FIXED_BYTES: usize = 104;
const STATE_VERSION: u16 = 4;
const STATE_FIXED_BYTES: usize = 108;
const STATE_CHECKSUM_BYTES: usize = 32;
const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;
const STATE_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.deployment.managed-fabric-controller-state.sha256.v1";

/// Successor activation phase. `Uncertain` has no replay transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedFabricApplyPhaseV1 {
    CutoverReady,
    RequestDurableNotSent,
    Uncertain,
    ReceiptDurable,
}

/// Exact Controller-owned successor state for the first Fabric activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricControllerStateV1 {
    sequence: u64,
    cutover_marker_digest: Digest32,
    legacy_snapshot: ControllerJournalSnapshot,
    phase: ManagedFabricApplyPhaseV1,
    serving: ManagedServingBootstrapStateV1,
    desired: Option<ManagedFabricDesiredPlanV1>,
    request: Option<ManagedFabricApplyRequestV1>,
    receipt: Option<ManagedFabricApplyTerminalReceiptV1>,
    archived_active: Option<CompletedManagedFabricApplyV1>,
    agent_stack: Option<ManagedAgentStackControllerStateV1>,
    model_stack: Option<ManagedModelAgentStackControllerStateV1>,
}

/// Exact active request triplet retained while the later empty request runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompletedManagedFabricApplyV1 {
    desired: ManagedFabricDesiredPlanV1,
    request: ManagedFabricApplyRequestV1,
    receipt: ManagedFabricApplyTerminalReceiptV1,
}

impl ManagedFabricControllerStateV1 {
    pub(crate) fn try_from_cutover(
        cutover_marker_digest: Digest32,
        legacy_snapshot: ControllerJournalSnapshot,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if digest_is_zero(cutover_marker_digest)
            || legacy_snapshot.snapshot_sequence() == 0
            || legacy_snapshot.state().target_binding().is_none()
            || legacy_snapshot
                .distributed_agent_stack_journal_wire()
                .is_some()
            || legacy_snapshot
                .distributed_agent_stack_node_discovery_wire()
                .is_some()
        {
            return Err(ManagedFabricApplyControllerError::InvalidCutoverState);
        }
        let encoded = legacy_snapshot.encode()?;
        if ControllerJournalSnapshot::decode(&encoded)? != legacy_snapshot {
            return Err(ManagedFabricApplyControllerError::InvalidCutoverState);
        }
        Ok(Self {
            sequence: 1,
            cutover_marker_digest,
            legacy_snapshot,
            phase: ManagedFabricApplyPhaseV1::CutoverReady,
            serving: ManagedServingBootstrapStateV1::initial(),
            desired: None,
            request: None,
            receipt: None,
            archived_active: None,
            agent_stack: None,
            model_stack: None,
        })
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> ManagedFabricApplyPhaseV1 {
        self.phase
    }

    #[must_use]
    pub(crate) const fn serving_phase(&self) -> ManagedServingBootstrapPhaseV1 {
        self.serving.phase()
    }

    #[must_use]
    pub(crate) const fn cutover_marker_digest(&self) -> Digest32 {
        self.cutover_marker_digest
    }

    #[must_use]
    pub(crate) const fn legacy_snapshot(&self) -> &ControllerJournalSnapshot {
        &self.legacy_snapshot
    }

    #[must_use]
    pub(crate) const fn desired(&self) -> Option<&ManagedFabricDesiredPlanV1> {
        self.desired.as_ref()
    }

    #[must_use]
    pub(crate) const fn request(&self) -> Option<&ManagedFabricApplyRequestV1> {
        self.request.as_ref()
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> Option<&ManagedFabricApplyTerminalReceiptV1> {
        self.receipt.as_ref()
    }

    #[must_use]
    pub(crate) const fn archived_active(&self) -> Option<&CompletedManagedFabricApplyV1> {
        self.archived_active.as_ref()
    }

    #[must_use]
    pub(crate) const fn agent_stack_state(&self) -> Option<&ManagedAgentStackControllerStateV1> {
        self.agent_stack.as_ref()
    }

    #[must_use]
    pub(crate) const fn model_agent_stack_state(
        &self,
    ) -> Option<&ManagedModelAgentStackControllerStateV1> {
        self.model_stack.as_ref()
    }

    pub(crate) fn encode(&self) -> Result<Box<[u8]>, ManagedFabricApplyControllerError> {
        if self.agent_stack.is_some() && self.model_stack.is_some() {
            return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
        }
        let legacy = self.legacy_snapshot.encode()?;
        let serving_request = self.serving.request_wire();
        let serving_response = self.serving.response_wire();
        let (revision, execution) = self.desired.as_ref().map_or((0, &[][..]), |desired| {
            (
                desired.revision().value(),
                desired.execution().canonical_wire(),
            )
        });
        let request = self
            .request
            .as_ref()
            .map_or(&[][..], ManagedFabricApplyRequestV1::canonical_wire);
        let receipt = self
            .receipt
            .as_ref()
            .map_or(&[][..], |receipt| receipt.canonical_wire());
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
        let agent_stack = self.agent_stack.as_ref().map_or_else(
            || Ok::<Box<[u8]>, ManagedFabricApplyControllerError>(Box::default()),
            |state| {
                state
                    .encode()
                    .map_err(|_| ManagedFabricApplyControllerError::InvalidStateEncoding)
            },
        )?;
        let model_stack = self.model_stack.as_ref().map_or_else(
            || Ok::<Box<[u8]>, ManagedFabricApplyControllerError>(Box::default()),
            |state| {
                state
                    .encode()
                    .map_err(|_| ManagedFabricApplyControllerError::InvalidStateEncoding)
            },
        )?;
        let legacy_length = u32::try_from(legacy.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let serving_request_length = u32::try_from(serving_request.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let serving_response_length = u32::try_from(serving_response.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let execution_length = u32::try_from(execution.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let request_length = u32::try_from(request.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let receipt_length = u32::try_from(receipt.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let archived_execution_length = u32::try_from(archived_execution.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let archived_request_length = u32::try_from(archived_request.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let archived_receipt_length = u32::try_from(archived_receipt.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let agent_stack_length = u32::try_from(agent_stack.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let model_stack_length = u32::try_from(model_stack.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let total = STATE_FIXED_BYTES
            .checked_add(legacy.len())
            .and_then(|value| value.checked_add(serving_request.len()))
            .and_then(|value| value.checked_add(serving_response.len()))
            .and_then(|value| value.checked_add(execution.len()))
            .and_then(|value| value.checked_add(request.len()))
            .and_then(|value| value.checked_add(receipt.len()))
            .and_then(|value| value.checked_add(archived_execution.len()))
            .and_then(|value| value.checked_add(archived_request.len()))
            .and_then(|value| value.checked_add(archived_receipt.len()))
            .and_then(|value| value.checked_add(agent_stack.len()))
            .and_then(|value| value.checked_add(model_stack.len()))
            .and_then(|value| value.checked_add(STATE_CHECKSUM_BYTES))
            .ok_or(ManagedFabricApplyControllerError::StateTooLarge)?;
        if total > MAX_STATE_BYTES {
            return Err(ManagedFabricApplyControllerError::StateTooLarge);
        }
        let mut encoded = Vec::with_capacity(total);
        encoded.extend_from_slice(STATE_MAGIC);
        encoded.extend_from_slice(&STATE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.sequence.to_be_bytes());
        encoded.extend_from_slice(self.cutover_marker_digest.as_bytes());
        encoded.push(match self.phase {
            ManagedFabricApplyPhaseV1::CutoverReady => 1,
            ManagedFabricApplyPhaseV1::RequestDurableNotSent => 2,
            ManagedFabricApplyPhaseV1::Uncertain => 3,
            ManagedFabricApplyPhaseV1::ReceiptDurable => 4,
        });
        encoded.push(self.serving.phase().wire_value());
        encoded.extend_from_slice(&revision.to_be_bytes());
        encoded.extend_from_slice(&legacy_length.to_be_bytes());
        encoded.extend_from_slice(&serving_request_length.to_be_bytes());
        encoded.extend_from_slice(&serving_response_length.to_be_bytes());
        encoded.extend_from_slice(&execution_length.to_be_bytes());
        encoded.extend_from_slice(&request_length.to_be_bytes());
        encoded.extend_from_slice(&receipt_length.to_be_bytes());
        encoded.extend_from_slice(&archived_revision.to_be_bytes());
        encoded.extend_from_slice(&archived_execution_length.to_be_bytes());
        encoded.extend_from_slice(&archived_request_length.to_be_bytes());
        encoded.extend_from_slice(&archived_receipt_length.to_be_bytes());
        encoded.extend_from_slice(&agent_stack_length.to_be_bytes());
        encoded.extend_from_slice(&model_stack_length.to_be_bytes());
        encoded.extend_from_slice(&legacy);
        encoded.extend_from_slice(serving_request);
        encoded.extend_from_slice(serving_response);
        encoded.extend_from_slice(execution);
        encoded.extend_from_slice(request);
        encoded.extend_from_slice(receipt);
        encoded.extend_from_slice(archived_execution);
        encoded.extend_from_slice(archived_request);
        encoded.extend_from_slice(archived_receipt);
        encoded.extend_from_slice(&agent_stack);
        encoded.extend_from_slice(&model_stack);
        let checksum = state_checksum(&encoded)?;
        encoded.extend_from_slice(checksum.as_bytes());
        Ok(encoded.into_boxed_slice())
    }

    pub(crate) fn decode(
        frame: &[u8],
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if frame.len() < LEGACY_STATE_FIXED_BYTES + STATE_CHECKSUM_BYTES {
            return Err(ManagedFabricApplyControllerError::StateTruncated);
        }
        if frame.len() > MAX_STATE_BYTES {
            return Err(ManagedFabricApplyControllerError::StateTooLarge);
        }
        let mut cursor = StateCursor::new(frame);
        if cursor.array::<4>()? != *STATE_MAGIC {
            return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
        }
        let state_version = cursor.u16()?;
        if !matches!(
            state_version,
            LEGACY_STATE_VERSION | AGENT_STACK_STATE_VERSION | STATE_VERSION
        ) {
            return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
        }
        let sequence = cursor.u64()?;
        let cutover_marker_digest = Digest32::from_bytes(cursor.array::<32>()?);
        let phase = match cursor.u8()? {
            1 => ManagedFabricApplyPhaseV1::CutoverReady,
            2 => ManagedFabricApplyPhaseV1::RequestDurableNotSent,
            3 => ManagedFabricApplyPhaseV1::Uncertain,
            4 => ManagedFabricApplyPhaseV1::ReceiptDurable,
            _ => return Err(ManagedFabricApplyControllerError::InvalidStateEncoding),
        };
        let serving_phase = ManagedServingBootstrapPhaseV1::try_from_wire(cursor.u8()?)?;
        let revision = cursor.u64()?;
        let legacy_length = cursor.usize_u32()?;
        let serving_request_length = cursor.usize_u32()?;
        let serving_response_length = cursor.usize_u32()?;
        let execution_length = cursor.usize_u32()?;
        let request_length = cursor.usize_u32()?;
        let receipt_length = cursor.usize_u32()?;
        let archived_revision = cursor.u64()?;
        let archived_execution_length = cursor.usize_u32()?;
        let archived_request_length = cursor.usize_u32()?;
        let archived_receipt_length = cursor.usize_u32()?;
        let (agent_stack_length, model_stack_length, fixed_bytes) = match state_version {
            LEGACY_STATE_VERSION => (0, 0, LEGACY_STATE_FIXED_BYTES),
            AGENT_STACK_STATE_VERSION => (cursor.usize_u32()?, 0, AGENT_STACK_STATE_FIXED_BYTES),
            STATE_VERSION => (cursor.usize_u32()?, cursor.usize_u32()?, STATE_FIXED_BYTES),
            _ => return Err(ManagedFabricApplyControllerError::InvalidStateEncoding),
        };
        let variable_length = legacy_length
            .checked_add(serving_request_length)
            .and_then(|value| value.checked_add(serving_response_length))
            .and_then(|value| value.checked_add(execution_length))
            .and_then(|value| value.checked_add(request_length))
            .and_then(|value| value.checked_add(receipt_length))
            .and_then(|value| value.checked_add(archived_execution_length))
            .and_then(|value| value.checked_add(archived_request_length))
            .and_then(|value| value.checked_add(archived_receipt_length))
            .and_then(|value| value.checked_add(agent_stack_length))
            .and_then(|value| value.checked_add(model_stack_length))
            .ok_or(ManagedFabricApplyControllerError::StateTooLarge)?;
        let expected_length = fixed_bytes
            .checked_add(variable_length)
            .and_then(|value| value.checked_add(STATE_CHECKSUM_BYTES))
            .ok_or(ManagedFabricApplyControllerError::StateTooLarge)?;
        if expected_length != frame.len() {
            return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
        }
        let legacy = cursor.take(legacy_length)?;
        let serving_request = cursor.take(serving_request_length)?;
        let serving_response = cursor.take(serving_response_length)?;
        let execution = cursor.take(execution_length)?;
        let request = cursor.take(request_length)?;
        let receipt = cursor.take(receipt_length)?;
        let archived_execution = cursor.take(archived_execution_length)?;
        let archived_request = cursor.take(archived_request_length)?;
        let archived_receipt = cursor.take(archived_receipt_length)?;
        let agent_stack = cursor.take(agent_stack_length)?;
        let model_stack = cursor.take(model_stack_length)?;
        let checksum = Digest32::from_bytes(cursor.array::<32>()?);
        cursor.finish()?;
        if state_checksum(&frame[..frame.len() - STATE_CHECKSUM_BYTES])? != checksum {
            return Err(ManagedFabricApplyControllerError::StateChecksumMismatch);
        }
        let legacy_snapshot = ControllerJournalSnapshot::decode(legacy)?;
        let base = Self::try_from_cutover(cutover_marker_digest, legacy_snapshot)?;
        let base_context = VerifiedManagedFabricProducerContextV1::try_from_provisioning(
            base.legacy_snapshot.state(),
            controller_signer,
            provisioning,
        )?;
        let serving = ManagedServingBootstrapStateV1::decode(
            serving_phase,
            serving_request,
            serving_response,
            &base_context,
        )?;
        if phase == ManagedFabricApplyPhaseV1::CutoverReady {
            if sequence == 0
                || (serving_phase == ManagedServingBootstrapPhaseV1::ReadyForRequest
                    && sequence != 1)
                || revision != 0
                || !execution.is_empty()
                || !request.is_empty()
                || !receipt.is_empty()
                || archived_revision != 0
                || !archived_execution.is_empty()
                || !archived_request.is_empty()
                || !archived_receipt.is_empty()
                || !agent_stack.is_empty()
                || !model_stack.is_empty()
            {
                return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
            }
            return Ok(Self {
                sequence,
                cutover_marker_digest,
                legacy_snapshot: base.legacy_snapshot,
                phase,
                serving,
                desired: None,
                request: None,
                receipt: None,
                archived_active: None,
                agent_stack: None,
                model_stack: None,
            });
        }
        if sequence < 2 || revision == 0 || execution.is_empty() || request.is_empty() {
            return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
        }
        let context = serving
            .verified_pin(&base_context)?
            .apply_context(&base_context)?;
        let archived_active = decode_archived_active(
            &context,
            cutover_marker_digest,
            archived_revision,
            archived_execution,
            archived_request,
            archived_receipt,
        )?;
        let desired = ManagedFabricDesiredPlanV1::try_restore(
            &context,
            cutover_marker_digest,
            revision,
            execution,
        )?;
        let request = ManagedFabricApplyRequestV1::decode(request)?;
        let expected_active = archived_active
            .as_ref()
            .map_or(ExpectedActive::None, |archived| {
                ExpectedActive::Exact(archived.request.target_slice_digest())
            });
        context.validate_stored_request(&desired, expected_active, &request)?;
        validate_current_shape(&desired, archived_active.as_ref())?;
        let receipt = match phase {
            ManagedFabricApplyPhaseV1::RequestDurableNotSent
            | ManagedFabricApplyPhaseV1::Uncertain => {
                if !receipt.is_empty() {
                    return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
                }
                None
            }
            ManagedFabricApplyPhaseV1::ReceiptDurable => {
                if receipt.is_empty() {
                    return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
                }
                let receipt = ManagedFabricApplyTerminalReceiptV1::decode(receipt)?;
                receipt.validate_against_request(&request, context.channel())?;
                verify_receipt_signature(&receipt, &context)?;
                Some(receipt)
            }
            ManagedFabricApplyPhaseV1::CutoverReady => {
                return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
            }
        };
        if !agent_stack.is_empty() && !model_stack.is_empty() {
            return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
        }
        let (agent_stack, model_stack) = if agent_stack.is_empty() && model_stack.is_empty() {
            (None, None)
        } else {
            if phase != ManagedFabricApplyPhaseV1::ReceiptDurable
                || archived_active.is_some()
                || desired.execution().mode() != ManagedFabricTargetModeV1::OneManagedFabricService
            {
                return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
            }
            let predecessor_generation = receipt
                .as_ref()
                .and_then(|value| value.facts().generation())
                .ok_or(ManagedFabricApplyControllerError::InvalidStateEncoding)?;
            if model_stack.is_empty() {
                (
                    Some(
                        ManagedAgentStackControllerStateV1::decode(
                            agent_stack,
                            ManagedAgentStackDecodeContextV1 {
                                fabric: &context,
                                cutover_marker_digest,
                                predecessor_revision: desired.revision(),
                                predecessor_execution: desired.execution(),
                                predecessor_slice_digest: request.target_slice_digest(),
                                predecessor_generation,
                            },
                        )
                        .map_err(|_| ManagedFabricApplyControllerError::InvalidStateEncoding)?,
                    ),
                    None,
                )
            } else {
                (
                    None,
                    Some(
                        ManagedModelAgentStackControllerStateV1::decode(
                            model_stack,
                            ManagedModelAgentStackDecodeContextV1 {
                                fabric: &context,
                                cutover_marker_digest,
                                predecessor_revision: desired.revision(),
                                predecessor_execution: desired.execution(),
                                predecessor_slice_digest: request.target_slice_digest(),
                                predecessor_generation,
                            },
                        )
                        .map_err(|_| ManagedFabricApplyControllerError::InvalidStateEncoding)?,
                    ),
                )
            }
        };
        Ok(Self {
            sequence,
            cutover_marker_digest,
            legacy_snapshot: base.legacy_snapshot,
            phase,
            serving,
            desired: Some(desired),
            request: Some(request),
            receipt,
            archived_active,
            agent_stack,
            model_stack,
        })
    }

    fn try_with_prepared_request(
        &self,
        desired: ManagedFabricDesiredPlanV1,
        request: ManagedFabricApplyRequestV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if self.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || self.desired.is_some()
            || self.request.is_some()
            || self.receipt.is_some()
            || self.archived_active.is_some()
        {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        Ok(Self {
            sequence: next_sequence(self.sequence)?,
            cutover_marker_digest: self.cutover_marker_digest,
            legacy_snapshot: self.legacy_snapshot.clone(),
            phase: ManagedFabricApplyPhaseV1::RequestDurableNotSent,
            serving: self.serving.clone(),
            desired: Some(desired),
            request: Some(request),
            receipt: None,
            archived_active: None,
            agent_stack: None,
            model_stack: None,
        })
    }

    fn try_with_prepared_empty_request(
        &self,
        desired: ManagedFabricDesiredPlanV1,
        request: ManagedFabricApplyRequestV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if self.phase != ManagedFabricApplyPhaseV1::ReceiptDurable
            || self.archived_active.is_some()
            || self.agent_stack.is_some()
            || self.model_stack.is_some()
        {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        let archived_active = CompletedManagedFabricApplyV1 {
            desired: self
                .desired
                .clone()
                .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?,
            request: self
                .request
                .clone()
                .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?,
            receipt: self
                .receipt
                .clone()
                .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?,
        };
        validate_archived_active_shape(&archived_active)?;
        validate_current_shape(&desired, Some(&archived_active))?;
        Ok(Self {
            sequence: next_sequence(self.sequence)?,
            cutover_marker_digest: self.cutover_marker_digest,
            legacy_snapshot: self.legacy_snapshot.clone(),
            phase: ManagedFabricApplyPhaseV1::RequestDurableNotSent,
            serving: self.serving.clone(),
            desired: Some(desired),
            request: Some(request),
            receipt: None,
            archived_active: Some(archived_active),
            agent_stack: None,
            model_stack: None,
        })
    }

    fn try_claim_send(&self) -> Result<Self, ManagedFabricApplyControllerError> {
        if self.phase != ManagedFabricApplyPhaseV1::RequestDurableNotSent
            || self.desired.is_none()
            || self.request.is_none()
            || self.receipt.is_some()
        {
            return Err(ManagedFabricApplyControllerError::OpaqueReplayForbidden);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.phase = ManagedFabricApplyPhaseV1::Uncertain;
        Ok(next)
    }

    fn expected_active(&self) -> ExpectedActive {
        self.archived_active
            .as_ref()
            .map_or(ExpectedActive::None, |archived| {
                ExpectedActive::Exact(archived.request.target_slice_digest())
            })
    }

    fn try_with_terminal_receipt(
        &self,
        receipt: ManagedFabricApplyTerminalReceiptV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if self.phase != ManagedFabricApplyPhaseV1::Uncertain
            || self.desired.is_none()
            || self.request.is_none()
            || self.receipt.is_some()
        {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.phase = ManagedFabricApplyPhaseV1::ReceiptDurable;
        next.receipt = Some(receipt);
        Ok(next)
    }

    pub(crate) fn try_with_agent_stack_state(
        &self,
        agent_stack: ManagedAgentStackControllerStateV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        let predecessor_desired = self
            .desired
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        let predecessor_request = self
            .request
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        let predecessor_revision = predecessor_desired
            .revision()
            .value()
            .checked_add(1)
            .ok_or(ManagedFabricApplyControllerError::SequenceExhausted)?;
        let stack_shape_valid = match agent_stack.archived_active() {
            None => {
                agent_stack.desired().execution().mode()
                    == ManagedAgentStackTargetModeV1::FabricAndAgent
                    && agent_stack.desired().predecessor_slice_digest()
                        == predecessor_request.target_slice_digest()
                    && agent_stack.desired().execution().fabric() == predecessor_desired.execution()
                    && agent_stack.desired().revision().value() == predecessor_revision
            }
            Some(archived) => {
                archived.desired().execution().mode()
                    == ManagedAgentStackTargetModeV1::FabricAndAgent
                    && archived.desired().predecessor_slice_digest()
                        == predecessor_request.target_slice_digest()
                    && archived.desired().execution().fabric() == predecessor_desired.execution()
                    && archived.desired().revision().value() == predecessor_revision
                    && agent_stack.desired().execution().mode()
                        == ManagedAgentStackTargetModeV1::EmptyDeactivate
                    && agent_stack.desired().predecessor_slice_digest()
                        == archived.request().target_slice_digest()
                    && agent_stack.desired().revision().value()
                        == predecessor_revision
                            .checked_add(1)
                            .ok_or(ManagedFabricApplyControllerError::SequenceExhausted)?
            }
        };
        if self.phase != ManagedFabricApplyPhaseV1::ReceiptDurable
            || self.archived_active.is_some()
            || self.model_stack.is_some()
            || predecessor_desired.execution().mode()
                != ManagedFabricTargetModeV1::OneManagedFabricService
            || self.receipt.as_ref().is_none_or(|value| {
                value.facts().outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady
                    || value.facts().generation().is_none()
            })
            || agent_stack.desired().cutover_marker_digest() != self.cutover_marker_digest
            || !stack_shape_valid
        {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        let valid_transition = match self.agent_stack.as_ref() {
            None => {
                agent_stack.phase()
                    == crate::managed_agent_stack_apply::ManagedAgentStackApplyPhaseV1::RequestDurableNotSent
                    && agent_stack.receipt().is_none()
            }
            Some(current) => {
                let same_request = current.desired() == agent_stack.desired()
                    && current.request() == agent_stack.request()
                    && current.archived_active() == agent_stack.archived_active();
                let starts_empty = current.phase()
                    == crate::managed_agent_stack_apply::ManagedAgentStackApplyPhaseV1::ReceiptDurable
                    && current.archived_active().is_none()
                    && agent_stack.phase()
                        == crate::managed_agent_stack_apply::ManagedAgentStackApplyPhaseV1::RequestDurableNotSent
                    && agent_stack.receipt().is_none()
                    && agent_stack.archived_active().is_some_and(|archived| {
                        archived.desired() == current.desired()
                            && archived.request() == current.request()
                            && current.receipt().is_some_and(|receipt| archived.receipt() == receipt)
                    });
                starts_empty
                    || same_request
                        && match (current.phase(), agent_stack.phase()) {
                        (
                            crate::managed_agent_stack_apply::ManagedAgentStackApplyPhaseV1::RequestDurableNotSent,
                            crate::managed_agent_stack_apply::ManagedAgentStackApplyPhaseV1::Uncertain,
                        ) => agent_stack.receipt().is_none(),
                        (
                            crate::managed_agent_stack_apply::ManagedAgentStackApplyPhaseV1::Uncertain,
                            crate::managed_agent_stack_apply::ManagedAgentStackApplyPhaseV1::ReceiptDurable,
                        ) => agent_stack.receipt().is_some(),
                        _ => false,
                    }
            }
        };
        if !valid_transition {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.agent_stack = Some(agent_stack);
        Ok(next)
    }

    pub(crate) fn try_with_model_agent_stack_state(
        &self,
        model_stack: ManagedModelAgentStackControllerStateV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        let predecessor_desired = self
            .desired
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        let predecessor_request = self
            .request
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        let predecessor_revision = predecessor_desired
            .revision()
            .value()
            .checked_add(1)
            .ok_or(ManagedFabricApplyControllerError::SequenceExhausted)?;
        let stack_shape_valid = match model_stack.archived_active() {
            None => {
                model_stack.desired().execution().mode()
                    == ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
                    && model_stack.desired().predecessor_slice_digest()
                        == predecessor_request.target_slice_digest()
                    && model_stack
                        .desired()
                        .execution()
                        .managed_agent_stack()
                        .fabric()
                        == predecessor_desired.execution()
                    && model_stack.desired().revision().value() == predecessor_revision
            }
            Some(archived) => {
                archived.desired().execution().mode()
                    == ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
                    && archived.desired().predecessor_slice_digest()
                        == predecessor_request.target_slice_digest()
                    && archived
                        .desired()
                        .execution()
                        .managed_agent_stack()
                        .fabric()
                        == predecessor_desired.execution()
                    && archived.desired().revision().value() == predecessor_revision
                    && model_stack.desired().execution().mode()
                        == ManagedModelAgentStackTargetModeV1::EmptyDeactivate
                    && model_stack.desired().predecessor_slice_digest()
                        == archived.request().target_slice_digest()
                    && model_stack.desired().revision().value()
                        == predecessor_revision
                            .checked_add(1)
                            .ok_or(ManagedFabricApplyControllerError::SequenceExhausted)?
            }
        };
        if self.phase != ManagedFabricApplyPhaseV1::ReceiptDurable
            || self.archived_active.is_some()
            || self.agent_stack.is_some()
            || predecessor_desired.execution().mode()
                != ManagedFabricTargetModeV1::OneManagedFabricService
            || self.receipt.as_ref().is_none_or(|value| {
                value.facts().outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady
                    || value.facts().generation().is_none()
            })
            || model_stack.desired().cutover_marker_digest() != self.cutover_marker_digest
            || !stack_shape_valid
        {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        if !model_stack.is_valid_transition_from(self.model_stack.as_ref()) {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.model_stack = Some(model_stack);
        Ok(next)
    }

    pub(crate) fn verified_current_context(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<VerifiedManagedFabricProducerContextV1, ManagedFabricApplyControllerError> {
        let base = VerifiedManagedFabricProducerContextV1::try_from_provisioning(
            self.legacy_snapshot.state(),
            controller_signer,
            provisioning,
        )?;
        Ok(self.serving.verified_pin(&base)?.apply_context(&base)?)
    }
}

/// Proof that PXAR bytes are durable but have never been exposed to transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedManagedFabricApplyV1 {
    state_sequence: u64,
    cutover_marker_digest: Digest32,
    request_digest: Digest32,
}

/// The only owner-private value that permits one PXAR transport call.
///
/// It is deliberately not `Clone`; the Controller persists `Uncertain` before
/// constructing it and never reconstructs it from an uncertain snapshot.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricSendActionV1 {
    state_sequence: u64,
    cutover_marker_digest: Digest32,
    request: ManagedFabricApplyRequestV1,
    channel: ReferenceChannelBindingV1,
}

impl ManagedFabricSendActionV1 {
    #[must_use]
    pub(crate) const fn request(&self) -> &ManagedFabricApplyRequestV1 {
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

/// Proof that one exact PXFB is durable and has not entered transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedManagedServingBootstrapV1 {
    state_sequence: u64,
    cutover_marker_digest: Digest32,
    request_digest: Digest32,
}

/// Move-only authorization for one PXFB transport exchange.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ManagedServingBootstrapSendActionV1 {
    state_sequence: u64,
    cutover_marker_digest: Digest32,
    request: ManagedServingBootstrapRequestV1,
}

impl ManagedServingBootstrapSendActionV1 {
    #[cfg(test)]
    pub(crate) fn from_contract_fixture(request: ManagedServingBootstrapRequestV1) -> Self {
        Self {
            state_sequence: 1,
            cutover_marker_digest: Digest32::from_bytes([0x7f; 32]),
            request,
        }
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ManagedServingBootstrapRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) fn canonical_request_bytes(&self) -> &[u8] {
        self.request.canonical_wire()
    }
}

/// Durable authenticated terminal result. Outcome interpretation remains explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricTerminalCommitV1 {
    state_sequence: u64,
    receipt: ManagedFabricApplyTerminalReceiptV1,
    replayed_from_journal: bool,
}

impl ManagedFabricTerminalCommitV1 {
    #[must_use]
    pub(crate) const fn state_sequence(&self) -> u64 {
        self.state_sequence
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> &ManagedFabricApplyTerminalReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub(crate) const fn facts(&self) -> ManagedFabricApplyTerminalFactsV1 {
        self.receipt.facts()
    }

    #[must_use]
    pub(crate) const fn replayed_from_journal(&self) -> bool {
        self.replayed_from_journal
    }
}

/// Mutable owner facade. Every transition receives its exact durable publisher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricApplyJournalV1 {
    state: ManagedFabricControllerStateV1,
}

impl ManagedFabricApplyJournalV1 {
    #[must_use]
    pub(crate) const fn new(state: ManagedFabricControllerStateV1) -> Self {
        Self { state }
    }

    #[must_use]
    pub(crate) const fn state(&self) -> &ManagedFabricControllerStateV1 {
        &self.state
    }

    /// Creates and commits one fresh signed PXFB before any transport action
    /// exists. Refresh is intentionally limited to the pre-PXAR state.
    pub(crate) fn prepare_serving_bootstrap_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        fresh: FreshManagedServingBootstrapV1,
        commit: Commit,
    ) -> Result<PreparedManagedServingBootstrapV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || self.state.desired.is_some()
            || self.state.request.is_some()
            || self.state.receipt.is_some()
            || self.state.archived_active.is_some()
        {
            return Err(ManagedFabricApplyControllerError::ServingRefreshForbidden);
        }
        let base = VerifiedManagedFabricProducerContextV1::try_from_provisioning(
            self.state.legacy_snapshot.state(),
            controller_signer,
            provisioning,
        )?;
        let serving = self
            .state
            .serving
            .try_prepare(&base, fresh, controller_signer)?;
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        self.prepared_serving_bootstrap()
    }

    /// Reconstructs only the local durable token for a PXFB that never crossed
    /// the in-flight fence. It allocates no identity and signs no new bytes.
    pub(crate) fn prepared_serving_bootstrap(
        &self,
    ) -> Result<PreparedManagedServingBootstrapV1, ManagedFabricApplyControllerError> {
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || self.state.serving.phase() != ManagedServingBootstrapPhaseV1::RequestDurable
        {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        let request = self
            .state
            .serving
            .request()
            .ok_or(ManagedFabricApplyControllerError::InvalidStateEncoding)?;
        Ok(PreparedManagedServingBootstrapV1 {
            state_sequence: self.state.sequence,
            cutover_marker_digest: self.state.cutover_marker_digest,
            request_digest: request.request_digest(),
        })
    }

    pub(crate) fn current_serving_pin(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<VerifiedManagedServingPinV1, ManagedFabricApplyControllerError> {
        let base = VerifiedManagedFabricProducerContextV1::try_from_provisioning(
            self.state.legacy_snapshot.state(),
            controller_signer,
            provisioning,
        )?;
        Ok(self.state.serving.verified_pin(&base)?)
    }

    /// Commits `AttemptInFlight` before returning the sole send authorization.
    pub(crate) fn claim_serving_bootstrap_with<Commit>(
        &mut self,
        prepared: PreparedManagedServingBootstrapV1,
        commit: Commit,
    ) -> Result<ManagedServingBootstrapSendActionV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        let request = self
            .state
            .serving
            .request()
            .ok_or(ManagedFabricApplyControllerError::InvalidStateEncoding)?;
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || self.state.serving.phase() != ManagedServingBootstrapPhaseV1::RequestDurable
            || prepared.state_sequence != self.state.sequence
            || prepared.cutover_marker_digest != self.state.cutover_marker_digest
            || prepared.request_digest != request.request_digest()
        {
            return Err(ManagedFabricApplyControllerError::PreparedServingTokenMismatch);
        }
        let (serving, request) = self.state.serving.try_claim()?;
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        Ok(ManagedServingBootstrapSendActionV1 {
            state_sequence: self.state.sequence,
            cutover_marker_digest: self.state.cutover_marker_digest,
            request,
        })
    }

    /// Durably closes timeout/EOF/no-response without claiming a Runtime-side
    /// effect. A retry requires a later explicit call with fresh entropy.
    pub(crate) fn close_serving_bootstrap_no_response_with<Commit>(
        &mut self,
        action: ManagedServingBootstrapSendActionV1,
        commit: Commit,
    ) -> Result<(), ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        self.validate_serving_action(&action)?;
        let serving = self.state.serving.try_close_no_response()?;
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        Ok(())
    }

    /// Closes a read-only observation attempt recovered in-flight after local
    /// process loss. PXFB cannot mutate Runtime, so this records only that the
    /// Controller no longer owns a live transport exchange.
    pub(crate) fn close_recovered_serving_bootstrap_with<Commit>(
        &mut self,
        commit: Commit,
    ) -> Result<(), ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || self.state.serving.phase() != ManagedServingBootstrapPhaseV1::AttemptInFlight
        {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        let serving = self.state.serving.try_close_no_response()?;
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        Ok(())
    }

    /// Verifies and commits one exact correlated PXFR. Only the resulting
    /// durable pin unlocks managed Fabric request production.
    pub(crate) fn consume_serving_bootstrap_response_with<Commit>(
        &mut self,
        action: ManagedServingBootstrapSendActionV1,
        response_wire: &[u8],
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        commit: Commit,
    ) -> Result<VerifiedManagedServingPinV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        self.validate_serving_action(&action)?;
        let base = VerifiedManagedFabricProducerContextV1::try_from_provisioning(
            self.state.legacy_snapshot.state(),
            controller_signer,
            provisioning,
        )?;
        let (serving, pin) = self
            .state
            .serving
            .try_accept_response(&base, response_wire)?;
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        Ok(pin)
    }

    fn validate_serving_action(
        &self,
        action: &ManagedServingBootstrapSendActionV1,
    ) -> Result<(), ManagedFabricApplyControllerError> {
        let request = self
            .state
            .serving
            .request()
            .ok_or(ManagedFabricApplyControllerError::InvalidStateEncoding)?;
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || self.state.serving.phase() != ManagedServingBootstrapPhaseV1::AttemptInFlight
            || action.state_sequence != self.state.sequence
            || action.cutover_marker_digest != self.state.cutover_marker_digest
            || action.request != *request
        {
            return Err(ManagedFabricApplyControllerError::ServingSendActionMismatch);
        }
        Ok(())
    }

    pub(crate) fn prepare_activate_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        service: ManagedServiceSpecV1,
        endpoint: ManagedFabricListenEndpointV1,
        fresh: FreshManagedFabricApplyV1,
        commit: Commit,
    ) -> Result<PreparedManagedFabricApplyV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        let context = self.verified_context(controller_signer, provisioning)?;
        if self.state.phase == ManagedFabricApplyPhaseV1::RequestDurableNotSent {
            if self.state.archived_active.is_some() {
                return Err(ManagedFabricApplyControllerError::InvalidPhase);
            }
            let desired = self
                .state
                .desired
                .as_ref()
                .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
            let request = self
                .state
                .request
                .as_ref()
                .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
            let requested = ManagedFabricDesiredPlanV1::try_activate(
                &context,
                self.state.cutover_marker_digest,
                desired.revision().value(),
                service,
                endpoint,
            )?;
            if &requested != desired {
                return Err(ManagedFabricApplyControllerError::DesiredConflict);
            }
            context.validate_stored_request(desired, ExpectedActive::None, request)?;
            return prepared_token(&self.state);
        }
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady {
            return Err(match self.state.phase {
                ManagedFabricApplyPhaseV1::Uncertain => {
                    ManagedFabricApplyControllerError::OpaqueReplayForbidden
                }
                ManagedFabricApplyPhaseV1::ReceiptDurable => {
                    ManagedFabricApplyControllerError::AlreadyTerminal
                }
                _ => ManagedFabricApplyControllerError::InvalidPhase,
            });
        }
        let revision = context
            .legacy_revision()
            .checked_add(1)
            .ok_or(ManagedFabricApplyControllerError::SequenceExhausted)?;
        let desired = ManagedFabricDesiredPlanV1::try_activate(
            &context,
            self.state.cutover_marker_digest,
            revision,
            service,
            endpoint,
        )?;
        let draft = ManagedFabricControllerRequestDraftV1::try_new(
            &context,
            &desired,
            ExpectedActive::None,
            fresh,
            controller_signer,
        )?;
        let _ = draft.signing_transcript()?;
        let request = draft.finalize(controller_signer)?;
        context.validate_stored_request(&desired, ExpectedActive::None, &request)?;
        let next = self.state.try_with_prepared_request(desired, request)?;
        commit(&next)?;
        self.state = next;
        prepared_token(&self.state)
    }

    pub(crate) fn prepare_empty_deactivate_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        fresh: FreshManagedFabricApplyV1,
        commit: Commit,
    ) -> Result<PreparedManagedFabricApplyV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        let context = self.verified_context(controller_signer, provisioning)?;
        if self.state.phase == ManagedFabricApplyPhaseV1::RequestDurableNotSent {
            let archived = self
                .state
                .archived_active
                .as_ref()
                .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
            validate_archived_active_shape(archived)?;
            let desired = self
                .state
                .desired
                .as_ref()
                .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
            let requested = ManagedFabricDesiredPlanV1::try_empty_deactivate(
                &context,
                self.state.cutover_marker_digest,
                desired.revision().value(),
            )?;
            if &requested != desired {
                return Err(ManagedFabricApplyControllerError::DesiredConflict);
            }
            let request = self
                .state
                .request
                .as_ref()
                .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
            context.validate_stored_request(
                desired,
                ExpectedActive::Exact(archived.request.target_slice_digest()),
                request,
            )?;
            return prepared_token(&self.state);
        }
        if self.state.phase != ManagedFabricApplyPhaseV1::ReceiptDurable
            || self.state.archived_active.is_some()
        {
            return Err(match self.state.phase {
                ManagedFabricApplyPhaseV1::Uncertain => {
                    ManagedFabricApplyControllerError::OpaqueReplayForbidden
                }
                ManagedFabricApplyPhaseV1::ReceiptDurable => {
                    ManagedFabricApplyControllerError::AlreadyTerminal
                }
                _ => ManagedFabricApplyControllerError::InvalidPhase,
            });
        }
        let active_desired = self
            .state
            .desired
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        let active_request = self
            .state
            .request
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        let active_receipt = self
            .state
            .receipt
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        let active = CompletedManagedFabricApplyV1 {
            desired: active_desired.clone(),
            request: active_request.clone(),
            receipt: active_receipt.clone(),
        };
        validate_archived_active_shape(&active)?;
        context.validate_stored_request(active_desired, ExpectedActive::None, active_request)?;
        active_receipt.validate_against_request(active_request, context.channel())?;
        verify_receipt_signature(active_receipt, &context)?;
        let revision = active_desired
            .revision()
            .value()
            .checked_add(1)
            .ok_or(ManagedFabricApplyControllerError::SequenceExhausted)?;
        let desired = ManagedFabricDesiredPlanV1::try_empty_deactivate(
            &context,
            self.state.cutover_marker_digest,
            revision,
        )?;
        let expected_active = ExpectedActive::Exact(active_request.target_slice_digest());
        let draft = ManagedFabricControllerRequestDraftV1::try_new(
            &context,
            &desired,
            expected_active,
            fresh,
            controller_signer,
        )?;
        let _ = draft.signing_transcript()?;
        let request = draft.finalize(controller_signer)?;
        context.validate_stored_request(&desired, expected_active, &request)?;
        let next = self
            .state
            .try_with_prepared_empty_request(desired, request)?;
        commit(&next)?;
        self.state = next;
        prepared_token(&self.state)
    }

    pub(crate) fn claim_send_with<Commit>(
        &mut self,
        prepared: PreparedManagedFabricApplyV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        commit: Commit,
    ) -> Result<ManagedFabricSendActionV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        validate_prepared_token(&self.state, prepared)?;
        let context = self.verified_context(controller_signer, provisioning)?;
        let desired = self
            .state
            .desired
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        let request = self
            .state
            .request
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        context.validate_stored_request(desired, self.state.expected_active(), request)?;
        let request = request.clone();
        let next = self.state.try_claim_send()?;
        commit(&next)?;
        self.state = next;
        Ok(ManagedFabricSendActionV1 {
            state_sequence: self.state.sequence,
            cutover_marker_digest: self.state.cutover_marker_digest,
            request,
            channel: context.channel(),
        })
    }

    pub(crate) fn consume_pxft_with<Commit>(
        &mut self,
        action: ManagedFabricSendActionV1,
        canonical_receipt: &[u8],
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        commit: Commit,
    ) -> Result<ManagedFabricTerminalCommitV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        if self.state.phase != ManagedFabricApplyPhaseV1::Uncertain
            || action.state_sequence != self.state.sequence
            || action.cutover_marker_digest != self.state.cutover_marker_digest
        {
            return Err(ManagedFabricApplyControllerError::SendActionMismatch);
        }
        let context = self.verified_context(controller_signer, provisioning)?;
        let durable_request = self
            .state
            .request
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        if action.request != *durable_request || action.channel != context.channel() {
            return Err(ManagedFabricApplyControllerError::SendActionMismatch);
        }
        let receipt = ManagedFabricApplyTerminalReceiptV1::decode(canonical_receipt)?;
        let facts = receipt.validate_against_request(durable_request, context.channel())?;
        if receipt.authentication_runtime_peer() != context.channel().runtime_peer()
            || receipt.authentication_channel_binding_digest() != context.channel().binding_digest()
            || receipt.authentication_key() != context.runtime_response_key()
            || receipt.authentication_algorithm().value() != ED25519_ALGORITHM
            || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
            || receipt.authentication_signature().len() != ED25519_SIGNATURE_BYTES
        {
            return Err(ManagedFabricApplyControllerError::ReceiptAuthenticationMismatch);
        }
        let signature = Signature::from_slice(receipt.authentication_signature())
            .map_err(|_| ManagedFabricApplyControllerError::ReceiptAuthenticationMismatch)?;
        let transcript = receipt.signing_transcript()?;
        context
            .runtime_response_public_key()
            .verify_strict(transcript.as_bytes(), &signature)
            .map_err(|_| ManagedFabricApplyControllerError::ReceiptAuthenticationMismatch)?;
        if facts != receipt.facts() {
            return Err(ManagedFabricApplyControllerError::ReceiptCorrelationMismatch);
        }
        let next = self.state.try_with_terminal_receipt(receipt.clone())?;
        commit(&next)?;
        self.state = next;
        Ok(ManagedFabricTerminalCommitV1 {
            state_sequence: self.state.sequence,
            receipt,
            replayed_from_journal: false,
        })
    }

    pub(crate) fn terminal(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<Option<ManagedFabricTerminalCommitV1>, ManagedFabricApplyControllerError> {
        if self.state.phase != ManagedFabricApplyPhaseV1::ReceiptDurable {
            return Ok(None);
        }
        let context = self.verified_context(controller_signer, provisioning)?;
        let request = self
            .state
            .request
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        let receipt = self
            .state
            .receipt
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        receipt.validate_against_request(request, context.channel())?;
        verify_receipt_signature(receipt, &context)?;
        Ok(Some(ManagedFabricTerminalCommitV1 {
            state_sequence: self.state.sequence,
            receipt: receipt.clone(),
            replayed_from_journal: true,
        }))
    }

    fn verified_context(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<VerifiedManagedFabricProducerContextV1, ManagedFabricApplyControllerError> {
        self.state
            .verified_current_context(controller_signer, provisioning)
    }
}

fn decode_archived_active(
    context: &VerifiedManagedFabricProducerContextV1,
    cutover_marker_digest: Digest32,
    revision: u64,
    execution: &[u8],
    request: &[u8],
    receipt: &[u8],
) -> Result<Option<CompletedManagedFabricApplyV1>, ManagedFabricApplyControllerError> {
    if revision == 0 && execution.is_empty() && request.is_empty() && receipt.is_empty() {
        return Ok(None);
    }
    if revision == 0 || execution.is_empty() || request.is_empty() || receipt.is_empty() {
        return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
    }
    let desired = ManagedFabricDesiredPlanV1::try_restore(
        context,
        cutover_marker_digest,
        revision,
        execution,
    )?;
    let request = ManagedFabricApplyRequestV1::decode(request)?;
    context.validate_stored_request(&desired, ExpectedActive::None, &request)?;
    let receipt = ManagedFabricApplyTerminalReceiptV1::decode(receipt)?;
    receipt.validate_against_request(&request, context.channel())?;
    verify_receipt_signature(&receipt, context)?;
    let archived = CompletedManagedFabricApplyV1 {
        desired,
        request,
        receipt,
    };
    validate_archived_active_shape(&archived)?;
    Ok(Some(archived))
}

fn validate_archived_active_shape(
    archived: &CompletedManagedFabricApplyV1,
) -> Result<(), ManagedFabricApplyControllerError> {
    let facts = archived.receipt.facts();
    if archived.desired.execution().mode() != ManagedFabricTargetModeV1::OneManagedFabricService
        || archived.request.target_execution() != archived.desired.execution()
        || facts.outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        || facts.head() != ManagedFabricApplyTerminalHeadV1::CommittedIncoming
        || facts.generation().is_none()
    {
        return Err(ManagedFabricApplyControllerError::ActiveNotReady);
    }
    Ok(())
}

fn validate_current_shape(
    desired: &ManagedFabricDesiredPlanV1,
    archived_active: Option<&CompletedManagedFabricApplyV1>,
) -> Result<(), ManagedFabricApplyControllerError> {
    match archived_active {
        None if desired.execution().mode()
            == ManagedFabricTargetModeV1::OneManagedFabricService =>
        {
            Ok(())
        }
        Some(archived)
            if desired.execution().mode() == ManagedFabricTargetModeV1::EmptyDeactivate
                && desired.revision().value()
                    == archived
                        .desired
                        .revision()
                        .value()
                        .checked_add(1)
                        .ok_or(ManagedFabricApplyControllerError::SequenceExhausted)? =>
        {
            Ok(())
        }
        _ => Err(ManagedFabricApplyControllerError::InvalidStateEncoding),
    }
}

fn verify_receipt_signature(
    receipt: &ManagedFabricApplyTerminalReceiptV1,
    context: &VerifiedManagedFabricProducerContextV1,
) -> Result<(), ManagedFabricApplyControllerError> {
    if receipt.authentication_runtime_peer() != context.channel().runtime_peer()
        || receipt.authentication_channel_binding_digest() != context.channel().binding_digest()
        || receipt.authentication_key() != context.runtime_response_key()
        || receipt.authentication_algorithm().value() != ED25519_ALGORITHM
        || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
        || receipt.authentication_signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(ManagedFabricApplyControllerError::ReceiptAuthenticationMismatch);
    }
    let signature = Signature::from_slice(receipt.authentication_signature())
        .map_err(|_| ManagedFabricApplyControllerError::ReceiptAuthenticationMismatch)?;
    let transcript = receipt.signing_transcript()?;
    context
        .runtime_response_public_key()
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| ManagedFabricApplyControllerError::ReceiptAuthenticationMismatch)
}

fn prepared_token(
    state: &ManagedFabricControllerStateV1,
) -> Result<PreparedManagedFabricApplyV1, ManagedFabricApplyControllerError> {
    let request = state
        .request
        .as_ref()
        .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
    Ok(PreparedManagedFabricApplyV1 {
        state_sequence: state.sequence,
        cutover_marker_digest: state.cutover_marker_digest,
        request_digest: request.envelope_request_digest(),
    })
}

fn validate_prepared_token(
    state: &ManagedFabricControllerStateV1,
    token: PreparedManagedFabricApplyV1,
) -> Result<(), ManagedFabricApplyControllerError> {
    let request = state
        .request
        .as_ref()
        .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
    if state.phase != ManagedFabricApplyPhaseV1::RequestDurableNotSent
        || token.state_sequence != state.sequence
        || token.cutover_marker_digest != state.cutover_marker_digest
        || token.request_digest != request.envelope_request_digest()
    {
        return Err(ManagedFabricApplyControllerError::PreparedTokenMismatch);
    }
    Ok(())
}

fn next_sequence(value: u64) -> Result<u64, ManagedFabricApplyControllerError> {
    value
        .checked_add(1)
        .ok_or(ManagedFabricApplyControllerError::SequenceExhausted)
}

fn digest_is_zero(value: Digest32) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

fn state_checksum(frame: &[u8]) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(STATE_CHECKSUM_DOMAIN)?;
    builder.field_bytes(frame)?;
    Ok(builder.finish())
}

struct StateCursor<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> StateCursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ManagedFabricApplyControllerError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ManagedFabricApplyControllerError::StateTooLarge)?;
        let value = self
            .frame
            .get(self.position..end)
            .ok_or(ManagedFabricApplyControllerError::StateTruncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManagedFabricApplyControllerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ManagedFabricApplyControllerError::StateTruncated)
    }

    fn u8(&mut self) -> Result<u8, ManagedFabricApplyControllerError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ManagedFabricApplyControllerError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ManagedFabricApplyControllerError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize_u32(&mut self) -> Result<usize, ManagedFabricApplyControllerError> {
        usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)
    }

    fn finish(self) -> Result<(), ManagedFabricApplyControllerError> {
        if self.position != self.frame.len() {
            return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
        }
        Ok(())
    }
}

/// Fail-closed Controller errors. Only `ManagedFabricSendActionV1` authorizes send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedFabricApplyControllerError {
    Journal(ControllerJournalError),
    Producer(ManagedFabricProducerError),
    Contract(ManagedFabricPlanError),
    Serving(ManagedServingControllerError),
    Digest(DigestBuildError),
    InvalidCutoverState,
    InvalidPhase,
    SequenceExhausted,
    DesiredConflict,
    DurabilityRejected,
    PreparedTokenMismatch,
    PreparedServingTokenMismatch,
    SendActionMismatch,
    ServingSendActionMismatch,
    ServingRefreshForbidden,
    OpaqueReplayForbidden,
    ReceiptCorrelationMismatch,
    ReceiptAuthenticationMismatch,
    AlreadyTerminal,
    ActiveNotReady,
    StateTruncated,
    StateTooLarge,
    StateChecksumMismatch,
    InvalidStateEncoding,
}

impl From<ControllerJournalError> for ManagedFabricApplyControllerError {
    fn from(value: ControllerJournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<ManagedFabricProducerError> for ManagedFabricApplyControllerError {
    fn from(value: ManagedFabricProducerError) -> Self {
        Self::Producer(value)
    }
}

impl From<ManagedFabricPlanError> for ManagedFabricApplyControllerError {
    fn from(value: ManagedFabricPlanError) -> Self {
        Self::Contract(value)
    }
}

impl From<ManagedServingControllerError> for ManagedFabricApplyControllerError {
    fn from(value: ManagedServingControllerError) -> Self {
        Self::Serving(value)
    }
}

impl From<DigestBuildError> for ManagedFabricApplyControllerError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ManagedFabricApplyControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed-fabric apply controller failed: {self:?}"
        )
    }
}

impl std::error::Error for ManagedFabricApplyControllerError {}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{
        BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant,
    };
    use paraegox_runtime_contracts::apply::{
        ExpectedActive, PlanWriterEpoch, PlanWriterRef, TenureAuthorityRef, TenureKeyRef,
        TenureProofAlgorithm, TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
        WriterTenureSigningTranscript,
    };
    use paraegox_runtime_contracts::execution::{CardDefinitionRef, CardImplementationRef};
    use paraegox_runtime_contracts::installation::{
        InstalledRuntimeArtifactObservationV1, RuntimeCompiledInstallationFactsV1,
        VerifiedRuntimeInstallationV1, generate_build_descriptor, generate_manifest,
    };
    use paraegox_runtime_contracts::managed_fabric_plan::{
        ManagedFabricApplyTerminalEvidenceV1, ManagedFabricApplyTerminalHeadV1,
        ManagedFabricApplyTerminalLifecycleEffectV1, ManagedFabricApplyTerminalOutcomeV1,
        ManagedFabricApplyTerminalReceiptAuthClaimV1, ManagedFabricApplyTerminalReceiptDraftV1,
        ManagedFabricApplyTerminalStateV1, ManagedFabricListenEndpointV1,
    };
    use paraegox_runtime_contracts::managed_service::{
        ManagedServiceGeneration, ManagedServiceId, ManagedServiceLifecycleBudgetsV1,
        ManagedServiceSpecV1,
    };
    use paraegox_runtime_contracts::managed_serving_bootstrap::{
        ManagedServingBootstrapFactsV1, ManagedServingBootstrapResponseAuthClaimV1,
        ManagedServingBootstrapResponseDraftV1,
    };
    use paraegox_runtime_contracts::provenance::SourceScopeRef;
    use paraegox_runtime_contracts::reference_control::{
        MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES, ReferenceAdmissionPolicyInputV1,
        ReferenceBootstrapChannelPolicyInputV1, ReferenceBootstrapCompatibilityV1,
        ReferenceBootstrapFactsV1, ReferenceBootstrapRequestDraftV1, ReferenceBootstrapRequestIdV1,
        ReferenceBootstrapResponseAuthClaimV1, ReferenceBootstrapResponseDraftV1,
        ReferenceBootstrapServingIdentityV1, ReferenceBootstrapStateV1, ReferenceChannelBindingV1,
        ed25519_control_key_fingerprint, reference_admission_policy_fingerprint_v1,
        reference_bootstrap_channel_policy_fingerprint_v1,
    };
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim,
    };

    use crate::controller_journal::{
        ControllerAuthKeyFingerprint, ControllerBootstrapResponseDigest,
        ControllerChannelAuthFingerprint, ControllerJournalSnapshot, ControllerJournalState,
        ControllerOperationId, ControllerOwnerIdentityFingerprint, ControllerRequestAuthPin,
        ControllerRuntimeResponseAuthPin, ControllerTargetBinding, ControllerTargetBindingInput,
        ControllerTenureAuthorityDomainFingerprint,
    };
    use crate::manifest_ingress::ControllerInstalledManifestPin;
    use crate::plan::{DeploymentId, DeploymentScopeId, DeploymentWriterRef};
    use crate::planner::{PlanManifestDigest, StableAllocationSnapshot, journal_test_candidate};
    use crate::tenure_protocol::{
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        AcquireTenureResponseV1, ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };

    use super::{
        AGENT_STACK_STATE_VERSION, LEGACY_STATE_VERSION, ManagedFabricApplyControllerError,
        ManagedFabricApplyJournalV1, ManagedFabricApplyPhaseV1, ManagedFabricControllerStateV1,
        STATE_CHECKSUM_BYTES, STATE_VERSION, state_checksum,
    };
    use crate::managed_fabric_producer::{
        FreshManagedFabricApplyV1, ManagedFabricControllerIdentityV1,
        ManagedFabricControllerProvisioningV1, ManagedFabricRuntimeChannelPinV1,
        ManagedFabricServiceAccountsV1, ManagedFabricTenureAuthorityPinV1,
    };
    use crate::managed_serving_client::FreshManagedServingBootstrapV1;

    const TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x31; 16]);
    const SCOPE: DeploymentScopeId = DeploymentScopeId::from_bytes([0x32; 16]);
    const PLAN: DeploymentId = DeploymentId::from_bytes([0x33; 16]);
    const WRITER: DeploymentWriterRef = DeploymentWriterRef::from_bytes([0x34; 16]);
    const CONTROLLER_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x35; 16]);
    const RUNTIME_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x36; 16]);
    const AUTHORITY_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x50; 16]);
    const CONTROLLER_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x37; 16]);
    const RUNTIME_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x38; 16]);
    const STORE_ID: [u8; 32] = [0x39; 32];
    const RUNTIME_STORE_ID: [u8; 32] = [0x3a; 32];
    const CONTROLLER_SEED: [u8; 32] = [0x3b; 32];
    const AUTHORITY_SEED: [u8; 32] = [0x3c; 32];
    const RUNTIME_SEED: [u8; 32] = [0x3d; 32];
    const CLOCK_DOMAIN: ClockDomainRef = ClockDomainRef::from_bytes([0x3e; 16]);
    const TENURE_AUTHORITY_REF: TenureAuthorityRef = TenureAuthorityRef::from_bytes([0x49; 16]);
    const TENURE_KEY_REF: TenureKeyRef = TenureKeyRef::from_bytes([0x4a; 16]);
    const AUTHORITY_UID: u32 = 3_001;
    const AUTHORITY_GID: u32 = 3_002;
    const RUNTIME_UID: u32 = 3_101;
    const RUNTIME_GID: u32 = 3_102;
    const CONTROLLER_UID: u32 = 3_201;
    const CONTROLLER_GID: u32 = 3_202;
    const SOCKET_PATH: &[u8] = b"/run/paraegox-test/runtime.sock";

    fn installation() -> (
        VerifiedRuntimeInstallationV1,
        RuntimeCompiledInstallationFactsV1,
    ) {
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            Digest32::from_bytes([0x22; 32]),
            "aarch64-unknown-linux-gnu",
        )
        .expect("artifact facts");
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
        .expect("manifest");
        (installation, compiled)
    }

    pub(crate) fn channel() -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            Digest32::from_bytes([0x44; 32]),
            Digest32::from_bytes([0x45; 32]),
        )
        .expect("Runtime channel")
    }

    fn admission_policy(controller: &SigningKey, authority: &SigningKey) -> Digest32 {
        reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
            target: TARGET,
            source_scope: SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            writer: PlanWriterRef::from_bytes(*WRITER.as_bytes()),
            controller_principal: CONTROLLER_PRINCIPAL,
            controller_key_ref: CONTROLLER_KEY_REF,
            controller_public_key: controller.verifying_key().as_bytes(),
            authority_principal: AUTHORITY_PRINCIPAL,
            authority_uid: AUTHORITY_UID,
            authority_gid: AUTHORITY_GID,
            tenure_authority_ref: TENURE_AUTHORITY_REF,
            tenure_key_ref: TENURE_KEY_REF,
            tenure_public_key: authority.verifying_key().as_bytes(),
        })
        .expect("admission policy")
        .digest()
    }

    fn bootstrap_response(
        installation: &VerifiedRuntimeInstallationV1,
        compiled: RuntimeCompiledInstallationFactsV1,
    ) -> paraegox_runtime_contracts::reference_control::ReferenceBootstrapResponseV1 {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let runtime = SigningKey::from_bytes(&RUNTIME_SEED);
        let authority = SigningKey::from_bytes(&AUTHORITY_SEED);
        let request_claim = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
            &[0x41; 32],
        )
        .expect("bootstrap request claim");
        let request_draft = ReferenceBootstrapRequestDraftV1::try_new(
            ReferenceBootstrapRequestIdV1::from_bytes([0x42; 16]),
            TARGET,
            SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            request_claim,
            u32::try_from(MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES).expect("response bound"),
        )
        .expect("bootstrap request draft");
        let request_signature = controller.sign(
            request_draft
                .signing_transcript()
                .expect("request transcript")
                .as_bytes(),
        );
        let request = request_draft
            .finalize(&request_signature.to_bytes())
            .expect("bootstrap request");
        let compatibility = ReferenceBootstrapCompatibilityV1::try_from_verified_installation(
            installation,
            compiled,
            admission_policy(&controller, &authority),
        )
        .expect("bootstrap compatibility");
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            RUNTIME_STORE_ID,
            11,
            2,
            CLOCK_DOMAIN,
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
        let claim = ReferenceBootstrapResponseAuthClaimV1::try_new(
            channel(),
            RUNTIME_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("bootstrap response claim");
        let draft = ReferenceBootstrapResponseDraftV1::try_new(&request, facts, channel(), claim)
            .expect("bootstrap response draft");
        let signature = runtime.sign(
            draft
                .signing_transcript()
                .expect("response transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("bootstrap response")
    }

    fn tenure_request() -> crate::tenure_protocol::AcquireTenureRequestV1 {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let fingerprint =
            ControllerPublicKeyFingerprint::for_ed25519_key(controller.verifying_key().as_bytes())
                .expect("Controller acquire key fingerprint");
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                SCOPE,
                WRITER,
                AcquireTenureOperationId::from_bytes([0x46; 16]),
            ),
            CONTROLLER_PRINCIPAL,
            ControllerAcquireKeyRef::from_bytes([0x47; 16]),
            fingerprint,
            &[0x48; 32],
            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES).expect("response bound"),
        )
        .expect("tenure request draft");
        let signature = controller.sign(
            draft
                .signing_transcript()
                .expect("tenure request transcript")
                .as_bytes(),
        );
        draft
            .finalize_ed25519(&signature.to_bytes())
            .expect("tenure request")
    }

    fn tenure_response(
        request: &crate::tenure_protocol::AcquireTenureRequestV1,
    ) -> AcquireTenureResponseV1 {
        let authority = TenureProofAuthority::try_new(
            TENURE_AUTHORITY_REF,
            TENURE_KEY_REF,
            TenureProofAlgorithm::try_new(1).expect("proof algorithm"),
            1,
        )
        .expect("proof authority");
        let claim = WriterTenureClaim::try_new(
            request.proof_source_scope(),
            request.proof_writer(),
            PlanWriterEpoch::new(1),
            PlanWriterEpoch::new(0),
        )
        .expect("writer claim");
        let transcript =
            WriterTenureSigningTranscript::try_new(authority, claim, request.client_nonce())
                .expect("proof transcript");
        let signature = SigningKey::from_bytes(&AUTHORITY_SEED).sign(transcript.as_bytes());
        let proof = WriterTenureProof::try_new(
            authority,
            claim,
            request.client_nonce(),
            &signature.to_bytes(),
        )
        .expect("writer proof");
        AcquireTenureResponseV1::try_new(request, proof).expect("tenure response")
    }

    pub(crate) fn ready_snapshot() -> ControllerJournalSnapshot {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let (installation, compiled) = installation();
        let fingerprint = ed25519_control_key_fingerprint(controller.verifying_key().as_bytes())
            .expect("Controller key fingerprint");
        let request_auth = ControllerRequestAuthPin::try_new(
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
            ControllerAuthKeyFingerprint::from_stored(fingerprint),
            1,
        )
        .expect("request auth pin");
        let allocation =
            StableAllocationSnapshot::try_new(TARGET, 0, 0, Vec::new()).expect("allocation");
        let state = ControllerJournalState::try_initialize(
            SCOPE,
            PLAN,
            allocation,
            ControllerInstalledManifestPin::from_verified_installation(&installation)
                .expect("manifest pin"),
            request_auth,
        )
        .expect("initial state");
        let initial = ControllerJournalSnapshot::try_initialize(
            STORE_ID,
            ControllerOwnerIdentityFingerprint::from_stored(Digest32::from_bytes([0x40; 32])),
            state,
        )
        .expect("initial snapshot");
        let candidate = journal_test_candidate(
            TARGET,
            initial.state().installed_manifest().projection(),
            initial.state().allocation(),
            Some([0x4b; 16]),
            0x4c,
        )
        .expect("plan candidate");
        let operation = ControllerOperationId::from_bytes([0x4d; 16]);
        let prepared = initial
            .try_successor(
                initial
                    .state()
                    .prepare_plan_candidate(operation, &candidate)
                    .expect("prepare plan"),
            )
            .expect("prepared successor");
        let planned = prepared
            .try_successor(
                prepared
                    .state()
                    .commit_plan_candidate(operation, &candidate)
                    .expect("commit plan"),
            )
            .expect("planned successor");
        let tenure_request = tenure_request();
        let tenure_prepared = planned
            .try_successor(
                planned
                    .state()
                    .prepare_tenure_acquisition(
                        &tenure_request,
                        ControllerTenureAuthorityDomainFingerprint::from_stored(
                            Digest32::from_bytes([0xa5; 32]),
                        ),
                    )
                    .expect("prepare tenure"),
            )
            .expect("tenure prepared successor");
        let tenure_response = tenure_response(&tenure_request);
        let tenured = tenure_prepared
            .try_successor(
                tenure_prepared
                    .state()
                    .commit_tenure_response(&tenure_request, &tenure_response)
                    .expect("commit tenure"),
            )
            .expect("tenure committed successor");
        let bootstrap = bootstrap_response(&installation, compiled);
        let runtime = SigningKey::from_bytes(&RUNTIME_SEED);
        let channel_policy = reference_bootstrap_channel_policy_fingerprint_v1(
            ReferenceBootstrapChannelPolicyInputV1 {
                canonical_socket_path: SOCKET_PATH,
                target: TARGET,
                source_scope: SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
                controller_principal: CONTROLLER_PRINCIPAL,
                controller_key_ref: CONTROLLER_KEY_REF,
                controller_public_key: controller.verifying_key().as_bytes(),
                runtime_uid: RUNTIME_UID,
                runtime_gid: RUNTIME_GID,
                controller_uid: CONTROLLER_UID,
                controller_gid: CONTROLLER_GID,
                runtime_principal: RUNTIME_PRINCIPAL,
                response_key_ref: RUNTIME_KEY_REF,
                response_public_key: runtime.verifying_key().as_bytes(),
            },
        )
        .expect("channel policy");
        let binding = ControllerTargetBinding::try_new(ControllerTargetBindingInput {
            target: TARGET,
            runtime_store_instance_id: RUNTIME_STORE_ID,
            channel_auth_fingerprint: ControllerChannelAuthFingerprint::from_stored(channel_policy),
            manifest_digest: PlanManifestDigest::try_new(
                tenured.state().installed_manifest().manifest_digest(),
            )
            .expect("manifest digest"),
            first_runtime_host_epoch: 2,
            last_runtime_host_epoch: 2,
            bootstrap_response: bootstrap.canonical_wire(),
            bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(
                bootstrap.response_digest(),
            ),
            runtime_response_auth: ControllerRuntimeResponseAuthPin::try_from_bootstrap_response(
                &bootstrap,
                channel(),
            )
            .expect("Runtime response auth pin"),
        })
        .expect("target binding");
        tenured
            .try_successor(
                tenured
                    .state()
                    .record_target_binding(binding)
                    .expect("record target binding"),
            )
            .expect("bound successor")
    }

    pub(crate) fn provisioning() -> ManagedFabricControllerProvisioningV1 {
        let controller = ManagedFabricControllerIdentityV1::try_new(CONTROLLER_PRINCIPAL, WRITER)
            .expect("controller identity");
        let authority = ManagedFabricTenureAuthorityPinV1::try_new(
            AUTHORITY_PRINCIPAL,
            AUTHORITY_UID,
            AUTHORITY_GID,
            TENURE_AUTHORITY_REF,
            TENURE_KEY_REF,
            SigningKey::from_bytes(&AUTHORITY_SEED)
                .verifying_key()
                .to_bytes(),
        )
        .expect("authority pin");
        let accounts = ManagedFabricServiceAccountsV1::try_new(
            RUNTIME_UID,
            RUNTIME_GID,
            CONTROLLER_UID,
            CONTROLLER_GID,
        )
        .expect("service accounts");
        let runtime = ManagedFabricRuntimeChannelPinV1::try_new(
            SOCKET_PATH,
            RUNTIME_PRINCIPAL,
            RUNTIME_KEY_REF,
            SigningKey::from_bytes(&RUNTIME_SEED)
                .verifying_key()
                .to_bytes(),
            accounts,
        )
        .expect("Runtime channel pin");
        ManagedFabricControllerProvisioningV1::new(controller, authority, runtime)
    }

    pub(crate) fn service() -> ManagedServiceSpecV1 {
        let budgets = ManagedServiceLifecycleBudgetsV1::try_new(
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(2_000_000_000),
            BoundedDuration::from_nanos(3_000_000_000),
            BoundedDuration::from_nanos(4_000_000_000),
            BoundedDuration::from_nanos(5_000_000_000),
        )
        .expect("service budgets");
        ManagedServiceSpecV1::new(ManagedServiceId::from_bytes([0x51; 16]), budgets)
    }

    pub(crate) fn fresh(marker: u8) -> FreshManagedFabricApplyV1 {
        FreshManagedFabricApplyV1::try_new(
            [marker; 16],
            [marker.wrapping_add(1); 16],
            [marker.wrapping_add(2); 32],
        )
        .expect("fresh request identities")
    }

    pub(crate) fn active_receipt(
        request: &paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricApplyRequestV1,
    ) -> paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricApplyTerminalReceiptV1 {
        let state = ManagedFabricApplyTerminalStateV1::try_new(
            ManagedFabricApplyTerminalOutcomeV1::ActiveReady,
            ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
            Some(ManagedServiceGeneration::try_new(1).expect("generation")),
        )
        .expect("terminal state");
        let evidence = ManagedFabricApplyTerminalEvidenceV1::try_new(
            Digest32::from_bytes([0xb1; 32]),
            Digest32::from_bytes([0xb2; 32]),
            2,
            12,
            ClockGeneration::try_new(4).expect("clock generation"),
            100,
        )
        .expect("terminal evidence");
        let facts =
            paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricApplyTerminalFactsV1::try_new(
                request, state, evidence,
            )
            .expect("terminal facts");
        let auth = ManagedFabricApplyTerminalReceiptAuthClaimV1::try_new(
            channel(),
            RUNTIME_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("terminal auth");
        let draft =
            ManagedFabricApplyTerminalReceiptDraftV1::try_new(request, facts, channel(), auth)
                .expect("terminal draft");
        let signature = SigningKey::from_bytes(&RUNTIME_SEED).sign(
            draft
                .signing_transcript()
                .expect("terminal transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("terminal receipt")
    }

    pub(crate) fn empty_receipt(
        request: &paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricApplyRequestV1,
    ) -> paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricApplyTerminalReceiptV1 {
        let state = ManagedFabricApplyTerminalStateV1::try_new(
            ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero,
            ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
            None,
        )
        .expect("empty terminal state");
        let evidence = ManagedFabricApplyTerminalEvidenceV1::try_new(
            Digest32::from_bytes([0xc1; 32]),
            Digest32::from_bytes([0xc2; 32]),
            2,
            13,
            ClockGeneration::try_new(4).expect("clock generation"),
            101,
        )
        .expect("empty terminal evidence");
        let facts =
            paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricApplyTerminalFactsV1::try_new(
                request, state, evidence,
            )
            .expect("empty terminal facts");
        let auth = ManagedFabricApplyTerminalReceiptAuthClaimV1::try_new(
            channel(),
            RUNTIME_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("empty terminal auth");
        let draft =
            ManagedFabricApplyTerminalReceiptDraftV1::try_new(request, facts, channel(), auth)
                .expect("empty terminal draft");
        let signature = SigningKey::from_bytes(&RUNTIME_SEED).sign(
            draft
                .signing_transcript()
                .expect("empty terminal transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("empty terminal receipt")
    }

    pub(crate) fn current_serving_response(
        request: &paraegox_runtime_contracts::managed_serving_bootstrap::ManagedServingBootstrapRequestV1,
    ) -> paraegox_runtime_contracts::managed_serving_bootstrap::ManagedServingBootstrapResponseV1
    {
        let facts = ManagedServingBootstrapFactsV1::try_recovered_ready(
            TARGET,
            RUNTIME_STORE_ID,
            request.projection().clone(),
            12,
            1,
            ClockReading::new(
                CLOCK_DOMAIN,
                ClockGeneration::try_new(4).expect("current clock generation"),
                MonotonicInstant::from_ticks(101),
            ),
        )
        .expect("current serving facts");
        let auth = ManagedServingBootstrapResponseAuthClaimV1::try_new(
            channel(),
            RUNTIME_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("current serving auth");
        let draft =
            ManagedServingBootstrapResponseDraftV1::try_new(request, facts, channel(), auth)
                .expect("current serving response draft");
        let signature = SigningKey::from_bytes(&RUNTIME_SEED).sign(
            draft
                .signing_transcript()
                .expect("current serving response transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("current serving response")
    }

    fn unobserved_journal() -> ManagedFabricApplyJournalV1 {
        ManagedFabricApplyJournalV1::new(
            ManagedFabricControllerStateV1::try_from_cutover(
                Digest32::from_bytes([0x61; 32]),
                ready_snapshot(),
            )
            .expect("cutover state"),
        )
    }

    pub(crate) fn journal() -> ManagedFabricApplyJournalV1 {
        let controller = controller_signer();
        let provisioning = provisioning();
        let mut journal = unobserved_journal();
        let prepared = journal
            .prepare_serving_bootstrap_with(
                &controller,
                &provisioning,
                FreshManagedServingBootstrapV1::try_new([0x5d; 16], [0x5e; 32])
                    .expect("fresh serving observation"),
                |_| Ok(()),
            )
            .expect("durable serving request");
        let action = journal
            .claim_serving_bootstrap_with(prepared, |_| Ok(()))
            .expect("serving attempt in flight");
        let response = current_serving_response(action.request());
        journal
            .consume_serving_bootstrap_response_with(
                action,
                response.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            )
            .expect("durable serving pin");
        journal
    }

    pub(crate) fn controller_signer() -> SigningKey {
        SigningKey::from_bytes(&CONTROLLER_SEED)
    }

    pub(crate) fn runtime_signer() -> SigningKey {
        SigningKey::from_bytes(&RUNTIME_SEED)
    }

    fn downgrade_pxfj_without_siblings(frame: &[u8], version: u16) -> Box<[u8]> {
        assert_eq!(&frame[..4], b"PXFJ");
        assert_eq!(u16::from_be_bytes([frame[4], frame[5]]), STATE_VERSION);
        assert_eq!(
            u32::from_be_bytes(frame[100..104].try_into().expect("agent length")),
            0
        );
        assert_eq!(
            u32::from_be_bytes(frame[104..108].try_into().expect("model length")),
            0
        );
        let mut body = frame[..frame.len() - STATE_CHECKSUM_BYTES].to_vec();
        match version {
            LEGACY_STATE_VERSION => {
                body.drain(100..108);
            }
            AGENT_STACK_STATE_VERSION => {
                body.drain(104..108);
            }
            _ => panic!("unsupported downgrade fixture version"),
        }
        body[4..6].copy_from_slice(&version.to_be_bytes());
        let checksum = state_checksum(&body).expect("legacy fixture checksum");
        body.extend_from_slice(checksum.as_bytes());
        body.into_boxed_slice()
    }

    #[test]
    fn pxfj_v4_roundtrips_and_strictly_reopens_v2_v3_without_siblings() {
        let controller = controller_signer();
        let provisioning = provisioning();
        let journal = journal();
        let encoded = journal.state().encode().expect("PXFJ v4 state");
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), STATE_VERSION);
        let decoded = ManagedFabricControllerStateV1::decode(&encoded, &controller, &provisioning)
            .expect("PXFJ v4 reopens");
        assert_eq!(&decoded, journal.state());

        for version in [LEGACY_STATE_VERSION, AGENT_STACK_STATE_VERSION] {
            let legacy = downgrade_pxfj_without_siblings(&encoded, version);
            let decoded =
                ManagedFabricControllerStateV1::decode(&legacy, &controller, &provisioning)
                    .expect("legacy PXFJ reopens");
            assert_eq!(&decoded, journal.state());
            let migrated = decoded.encode().expect("legacy state migrates on write");
            assert_eq!(
                u16::from_be_bytes([migrated[4], migrated[5]]),
                STATE_VERSION,
                "migration-on-write must emit only PXFJ v4"
            );
        }
    }

    #[test]
    fn pxfj_v4_rejects_dual_sibling_payloads() {
        let controller = controller_signer();
        let provisioning = provisioning();
        let mut journal = journal();
        let prepared = journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                service(),
                ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                    .expect("listen endpoint"),
                fresh(0x5a),
                |_| Ok(()),
            )
            .expect("prepare active Fabric");
        let action = journal
            .claim_send_with(prepared, &controller, &provisioning, |_| Ok(()))
            .expect("claim active Fabric send");
        let receipt = active_receipt(action.request());
        journal
            .consume_pxft_with(
                action,
                receipt.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            )
            .expect("commit active Fabric terminal");

        let encoded = journal.state().encode().expect("PXFJ v4 state");
        let mut body = encoded[..encoded.len() - STATE_CHECKSUM_BYTES].to_vec();
        body[100..104].copy_from_slice(&1_u32.to_be_bytes());
        body[104..108].copy_from_slice(&1_u32.to_be_bytes());
        body.extend_from_slice(&[0xa1, 0xb1]);
        let checksum = state_checksum(&body).expect("dual sibling checksum");
        body.extend_from_slice(checksum.as_bytes());
        assert_eq!(
            ManagedFabricControllerStateV1::decode(&body, &controller, &provisioning)
                .expect_err("Agent and Model sibling branches are mutually exclusive"),
            ManagedFabricApplyControllerError::InvalidStateEncoding
        );
    }

    #[test]
    fn managed_apply_is_locked_until_current_serving_response_is_durable() {
        let controller = controller_signer();
        let provisioning = provisioning();
        let mut journal = unobserved_journal();
        let error = journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                service(),
                ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                    .expect("listen endpoint"),
                fresh(0x60),
                |_| Ok(()),
            )
            .expect_err("PXAR must require the durable current serving pin");
        assert_eq!(
            error,
            ManagedFabricApplyControllerError::Serving(
                crate::managed_serving_client::ManagedServingControllerError::ServingPinRequired,
            )
        );
    }

    #[test]
    fn serving_observation_is_durable_before_send_and_closes_without_implicit_retry() {
        let controller = controller_signer();
        let provisioning = provisioning();
        let mut journal = unobserved_journal();
        let request_commit = RefCell::new(None);
        let prepared = journal
            .prepare_serving_bootstrap_with(
                &controller,
                &provisioning,
                FreshManagedServingBootstrapV1::try_new([0x66; 16], [0x67; 32])
                    .expect("fresh serving observation"),
                |next| {
                    *request_commit.borrow_mut() = Some(next.clone());
                    Ok(())
                },
            )
            .expect("prepare serving observation");
        assert_eq!(
            request_commit
                .into_inner()
                .expect("request crossed durable boundary")
                .serving_phase(),
            crate::managed_serving_client::ManagedServingBootstrapPhaseV1::RequestDurable
        );
        let in_flight_commit = RefCell::new(None);
        let action = journal
            .claim_serving_bootstrap_with(prepared, |next| {
                *in_flight_commit.borrow_mut() = Some(next.clone());
                Ok(())
            })
            .expect("claim serving send");
        assert_eq!(&action.canonical_request_bytes()[..4], b"PXFB");
        assert_eq!(
            in_flight_commit
                .into_inner()
                .expect("in-flight fence crossed durable boundary")
                .serving_phase(),
            crate::managed_serving_client::ManagedServingBootstrapPhaseV1::AttemptInFlight
        );
        journal
            .close_serving_bootstrap_no_response_with(action, |_| Ok(()))
            .expect("durably close no response");
        assert_eq!(
            journal.state().serving_phase(),
            crate::managed_serving_client::ManagedServingBootstrapPhaseV1::AttemptClosedNoResponse
        );
        assert!(journal.prepared_serving_bootstrap().is_err());

        let prepared = journal
            .prepare_serving_bootstrap_with(
                &controller,
                &provisioning,
                FreshManagedServingBootstrapV1::try_new([0x68; 16], [0x69; 32])
                    .expect("fresh retry observation"),
                |_| Ok(()),
            )
            .expect("explicit fresh retry");
        let action = journal
            .claim_serving_bootstrap_with(prepared, |_| Ok(()))
            .expect("claim retry send");
        let response = current_serving_response(action.request());
        let response_commit = RefCell::new(None);
        let pin = journal
            .consume_serving_bootstrap_response_with(
                action,
                response.canonical_wire(),
                &controller,
                &provisioning,
                |next| {
                    *response_commit.borrow_mut() = Some(next.clone());
                    Ok(())
                },
            )
            .expect("commit authenticated serving response");
        assert!(
            pin.request_digest()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );
        assert!(
            pin.response_digest()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );
        assert_eq!(
            response_commit
                .into_inner()
                .expect("response crossed durable boundary")
                .serving_phase(),
            crate::managed_serving_client::ManagedServingBootstrapPhaseV1::ResponseDurable
        );
        let encoded = journal.state().encode().expect("serving pin state encodes");
        let decoded = ManagedFabricControllerStateV1::decode(&encoded, &controller, &provisioning)
            .expect("serving pin reopens exactly");
        assert_eq!(&decoded, journal.state());
    }

    #[test]
    fn active_request_is_durable_before_send_and_exact_pxft_is_terminal() {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning();
        let mut journal = journal();
        let prepared_commit = RefCell::new(None);
        let prepared = journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                service(),
                ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                    .expect("listen endpoint"),
                fresh(0x62),
                |next| {
                    *prepared_commit.borrow_mut() = Some(next.clone());
                    Ok(())
                },
            )
            .expect("prepare active request");
        let durable_prepared = prepared_commit
            .into_inner()
            .expect("prepared state crossed commit boundary");
        assert_eq!(
            durable_prepared.phase(),
            ManagedFabricApplyPhaseV1::RequestDurableNotSent
        );
        assert_eq!(journal.state(), &durable_prepared);
        assert_eq!(
            journal
                .state()
                .request()
                .expect("durable request")
                .canonical_wire()[4..6],
            [0, 6]
        );

        let uncertain_commit = RefCell::new(None);
        let action = journal
            .claim_send_with(prepared, &controller, &provisioning, |next| {
                *uncertain_commit.borrow_mut() = Some(next.clone());
                Ok(())
            })
            .expect("claim one send");
        let durable_uncertain = uncertain_commit
            .into_inner()
            .expect("uncertain fence crossed commit boundary");
        assert_eq!(
            durable_uncertain.phase(),
            ManagedFabricApplyPhaseV1::Uncertain
        );
        assert_eq!(journal.state(), &durable_uncertain);
        assert_eq!(&action.canonical_request_bytes()[..4], b"PXAR");
        assert_eq!(action.channel(), channel());

        let receipt = active_receipt(action.request());
        let terminal_commit = RefCell::new(None);
        let terminal = journal
            .consume_pxft_with(
                action,
                receipt.canonical_wire(),
                &controller,
                &provisioning,
                |next| {
                    *terminal_commit.borrow_mut() = Some(next.clone());
                    Ok(())
                },
            )
            .expect("consume exact PXFT");
        assert_eq!(
            terminal.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        );
        assert_eq!(
            terminal_commit
                .into_inner()
                .expect("terminal crossed commit boundary")
                .phase(),
            ManagedFabricApplyPhaseV1::ReceiptDurable
        );
        let replay = journal
            .terminal(&controller, &provisioning)
            .expect("terminal replay validation")
            .expect("terminal receipt");
        assert!(replay.replayed_from_journal());
        assert_eq!(replay.receipt(), terminal.receipt());
    }

    #[test]
    fn active_terminal_is_archived_before_exact_cas_empty_deactivate() {
        let controller = controller_signer();
        let provisioning = provisioning();
        let mut journal = journal();
        let prepared = journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                service(),
                ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                    .expect("listen endpoint"),
                fresh(0x70),
                |_| Ok(()),
            )
            .expect("prepare active");
        let active_action = journal
            .claim_send_with(prepared, &controller, &provisioning, |_| Ok(()))
            .expect("claim active send");
        let active_receipt = active_receipt(active_action.request());
        journal
            .consume_pxft_with(
                active_action,
                active_receipt.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            )
            .expect("active terminal");
        let active_slice = journal
            .state()
            .request()
            .expect("active request")
            .target_slice_digest();

        let empty_prepared = journal
            .prepare_empty_deactivate_with(&controller, &provisioning, fresh(0x73), |_| Ok(()))
            .expect("prepare empty");
        let archived = journal
            .state()
            .archived_active()
            .expect("active triplet archived");
        assert_eq!(archived.request.target_slice_digest(), active_slice);
        assert_eq!(
            journal
                .state()
                .request()
                .expect("empty request")
                .control_commitment()
                .control()
                .expected_active(),
            ExpectedActive::Exact(active_slice)
        );
        let empty_action = journal
            .claim_send_with(empty_prepared, &controller, &provisioning, |_| Ok(()))
            .expect("claim empty send");
        let empty_receipt = empty_receipt(empty_action.request());
        let terminal = journal
            .consume_pxft_with(
                empty_action,
                empty_receipt.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            )
            .expect("empty terminal");
        assert_eq!(
            terminal.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero
        );
        let encoded = journal.state().encode().expect("state encodes");
        let decoded = ManagedFabricControllerStateV1::decode(&encoded, &controller, &provisioning)
            .expect("active archive and empty terminal reopen");
        assert_eq!(&decoded, journal.state());
    }

    #[test]
    fn failed_durability_and_uncertain_transport_never_authorize_opaque_replay() {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning();
        let mut journal = journal();
        let error = journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                service(),
                ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                    .expect("listen endpoint"),
                fresh(0x63),
                |_| Err(ManagedFabricApplyControllerError::DurabilityRejected),
            )
            .expect_err("failed persistence must return no prepared token");
        assert_eq!(error, ManagedFabricApplyControllerError::DurabilityRejected);
        assert_eq!(
            journal.state().phase(),
            ManagedFabricApplyPhaseV1::CutoverReady
        );

        let prepared = journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                service(),
                ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                    .expect("listen endpoint"),
                fresh(0x64),
                |_| Ok(()),
            )
            .expect("prepare durable request");
        assert_eq!(
            journal
                .claim_send_with(prepared, &controller, &provisioning, |_| Err(
                    ManagedFabricApplyControllerError::DurabilityRejected
                ))
                .expect_err("failed uncertain fence must return no send action"),
            ManagedFabricApplyControllerError::DurabilityRejected
        );
        assert_eq!(
            journal.state().phase(),
            ManagedFabricApplyPhaseV1::RequestDurableNotSent
        );
        let _action = journal
            .claim_send_with(prepared, &controller, &provisioning, |_| Ok(()))
            .expect("uncertain fence permits one send action");
        assert_eq!(
            journal.state().phase(),
            ManagedFabricApplyPhaseV1::Uncertain
        );
        assert_eq!(
            journal
                .prepare_activate_with(
                    &controller,
                    &provisioning,
                    service(),
                    ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                        .expect("listen endpoint"),
                    fresh(0x65),
                    |_| Ok(()),
                )
                .expect_err("uncertain request must never become an implicit replay"),
            ManagedFabricApplyControllerError::OpaqueReplayForbidden
        );
    }
}
