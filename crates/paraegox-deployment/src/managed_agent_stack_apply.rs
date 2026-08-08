//! Durable Controller state machine for the fixed Fabric→Agent PXAR v7 apply.
//!
//! The predecessor PXAR v6 terminal remains byte-for-byte in the successor
//! snapshot. This additive state owns only PXTE v6/PXAR v7/PXST and therefore
//! cannot reinterpret or rewrite the already committed Fabric activation.

use core::fmt;

use ed25519_dalek::Signature;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::PrincipalRef;
use paraegox_runtime_contracts::managed_agent_stack_plan::{
    ManagedAgentStackApplyRequestV1, ManagedAgentStackPlanError, ManagedAgentStackTargetModeV1,
    ManagedAgentStackTerminalHeadV1, ManagedAgentStackTerminalOutcomeV1,
    ManagedAgentStackTerminalReceiptV1,
};
use paraegox_runtime_contracts::managed_fabric_plan::{
    ManagedFabricApplyTerminalOutcomeV1, ManagedFabricTargetModeV1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
use paraegox_runtime_contracts::managed_serving_bootstrap::{
    RuntimeAgentControlKindV1, RuntimeAgentControlReceiptV1, RuntimeAgentControlRequestV1,
};
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;

use crate::managed_agent_stack_producer::{
    FreshManagedAgentStackApplyV1, ManagedAgentStackActivationV1, ManagedAgentStackDesiredPlanV1,
    ManagedAgentStackProducerError, produce_managed_agent_stack_empty_request_v1,
    produce_managed_agent_stack_request_v1, validate_managed_agent_stack_empty_request_v1,
    validate_managed_agent_stack_request_v1,
};
use crate::managed_fabric_apply::{
    ManagedFabricApplyControllerError, ManagedFabricApplyPhaseV1, ManagedFabricControllerStateV1,
};
use crate::managed_fabric_producer::{
    ManagedFabricControllerProvisioningV1, ManagedFabricRemoteControllerProvisioningV1,
    VerifiedManagedFabricProducerContextV1,
};
use crate::managed_serving_client::{
    FreshRuntimeAgentControlV1, ManagedServingControllerError, ManagedServingDescribeIngressV1,
    RuntimeAgentControlDurablePhaseV1, RuntimeAgentControlMtlsExchangeSuccessV1,
};

const STATE_MAGIC: &[u8; 4] = b"PXAJ";
const LEGACY_STATE_VERSION: u16 = 1;
const LEGACY_STATE_FIXED_BYTES: usize = 59;
const STATE_VERSION: u16 = 2;
const STATE_FIXED_BYTES: usize = 79;
const STATE_CHECKSUM_BYTES: usize = 32;
const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;
const STATE_CHECKSUM_DOMAIN: &[u8] = b"paraegox.deployment.managed-agent-stack-state.sha256.v1";
const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedAgentStackApplyPhaseV1 {
    RequestDurableNotSent,
    Uncertain,
    ReceiptDurable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackControllerStateV1 {
    phase: ManagedAgentStackApplyPhaseV1,
    desired: ManagedAgentStackDesiredPlanV1,
    request: ManagedAgentStackApplyRequestV1,
    receipt: Option<ManagedAgentStackTerminalReceiptV1>,
    archived_active: Option<CompletedManagedAgentStackApplyV1>,
}

pub(crate) struct ManagedAgentStackDecodeContextV1<'a> {
    pub(crate) fabric: &'a VerifiedManagedFabricProducerContextV1,
    pub(crate) cutover_marker_digest: Digest32,
    pub(crate) predecessor_revision: paraegox_runtime_contracts::provenance::SourcePlanRevision,
    pub(crate) predecessor_execution:
        &'a paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricTargetExecutionV1,
    pub(crate) predecessor_slice_digest: paraegox_runtime_contracts::provenance::TargetSliceDigest,
    pub(crate) predecessor_generation: ManagedServiceGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompletedManagedAgentStackApplyV1 {
    desired: ManagedAgentStackDesiredPlanV1,
    request: ManagedAgentStackApplyRequestV1,
    receipt: ManagedAgentStackTerminalReceiptV1,
}

impl CompletedManagedAgentStackApplyV1 {
    #[must_use]
    pub(crate) const fn desired(&self) -> &ManagedAgentStackDesiredPlanV1 {
        &self.desired
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ManagedAgentStackApplyRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> &ManagedAgentStackTerminalReceiptV1 {
        &self.receipt
    }
}

impl ManagedAgentStackControllerStateV1 {
    #[must_use]
    pub(crate) const fn phase(&self) -> ManagedAgentStackApplyPhaseV1 {
        self.phase
    }

    #[must_use]
    pub(crate) const fn desired(&self) -> &ManagedAgentStackDesiredPlanV1 {
        &self.desired
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ManagedAgentStackApplyRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> Option<&ManagedAgentStackTerminalReceiptV1> {
        self.receipt.as_ref()
    }

    #[must_use]
    pub(crate) const fn archived_active(&self) -> Option<&CompletedManagedAgentStackApplyV1> {
        self.archived_active.as_ref()
    }

    pub(crate) fn try_prepared(
        desired: ManagedAgentStackDesiredPlanV1,
        request: ManagedAgentStackApplyRequestV1,
    ) -> Result<Self, ManagedAgentStackApplyControllerError> {
        if desired.execution().mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
            || request.target_execution() != desired.execution()
            || request.provenance() != desired.provenance()
        {
            return Err(ManagedAgentStackApplyControllerError::InvalidState);
        }
        Ok(Self {
            phase: ManagedAgentStackApplyPhaseV1::RequestDurableNotSent,
            desired,
            request,
            receipt: None,
            archived_active: None,
        })
    }

    pub(crate) fn try_prepare_empty(
        &self,
        desired: ManagedAgentStackDesiredPlanV1,
        request: ManagedAgentStackApplyRequestV1,
    ) -> Result<Self, ManagedAgentStackApplyControllerError> {
        if self.phase != ManagedAgentStackApplyPhaseV1::ReceiptDurable
            || self.archived_active.is_some()
            || self.desired.execution().mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
            || self.receipt.is_none()
            || desired.execution().mode() != ManagedAgentStackTargetModeV1::EmptyDeactivate
            || desired.predecessor_slice_digest() != self.request.target_slice_digest()
            || request.target_execution() != desired.execution()
            || request.provenance() != desired.provenance()
        {
            return Err(ManagedAgentStackApplyControllerError::InvalidState);
        }
        Ok(Self {
            phase: ManagedAgentStackApplyPhaseV1::RequestDurableNotSent,
            desired,
            request,
            receipt: None,
            archived_active: Some(CompletedManagedAgentStackApplyV1 {
                desired: self.desired.clone(),
                request: self.request.clone(),
                receipt: self
                    .receipt
                    .clone()
                    .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?,
            }),
        })
    }

    pub(crate) fn try_claim(&self) -> Result<Self, ManagedAgentStackApplyControllerError> {
        if self.phase != ManagedAgentStackApplyPhaseV1::RequestDurableNotSent
            || self.receipt.is_some()
        {
            return Err(ManagedAgentStackApplyControllerError::OpaqueReplayForbidden);
        }
        let mut next = self.clone();
        next.phase = ManagedAgentStackApplyPhaseV1::Uncertain;
        Ok(next)
    }

    pub(crate) fn try_terminal(
        &self,
        receipt: ManagedAgentStackTerminalReceiptV1,
    ) -> Result<Self, ManagedAgentStackApplyControllerError> {
        if self.phase != ManagedAgentStackApplyPhaseV1::Uncertain || self.receipt.is_some() {
            return Err(ManagedAgentStackApplyControllerError::InvalidPhase);
        }
        let mut next = self.clone();
        next.phase = ManagedAgentStackApplyPhaseV1::ReceiptDurable;
        next.receipt = Some(receipt);
        Ok(next)
    }

    pub(crate) fn encode(&self) -> Result<Box<[u8]>, ManagedAgentStackApplyControllerError> {
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
        let execution_length = u32::try_from(execution.len())
            .map_err(|_| ManagedAgentStackApplyControllerError::StateTooLarge)?;
        let request_length = u32::try_from(request.len())
            .map_err(|_| ManagedAgentStackApplyControllerError::StateTooLarge)?;
        let receipt_length = u32::try_from(receipt.len())
            .map_err(|_| ManagedAgentStackApplyControllerError::StateTooLarge)?;
        let archived_execution_length = u32::try_from(archived_execution.len())
            .map_err(|_| ManagedAgentStackApplyControllerError::StateTooLarge)?;
        let archived_request_length = u32::try_from(archived_request.len())
            .map_err(|_| ManagedAgentStackApplyControllerError::StateTooLarge)?;
        let archived_receipt_length = u32::try_from(archived_receipt.len())
            .map_err(|_| ManagedAgentStackApplyControllerError::StateTooLarge)?;
        let total = STATE_FIXED_BYTES
            .checked_add(execution.len())
            .and_then(|value| value.checked_add(request.len()))
            .and_then(|value| value.checked_add(receipt.len()))
            .and_then(|value| value.checked_add(archived_execution.len()))
            .and_then(|value| value.checked_add(archived_request.len()))
            .and_then(|value| value.checked_add(archived_receipt.len()))
            .and_then(|value| value.checked_add(STATE_CHECKSUM_BYTES))
            .ok_or(ManagedAgentStackApplyControllerError::StateTooLarge)?;
        if total > MAX_STATE_BYTES {
            return Err(ManagedAgentStackApplyControllerError::StateTooLarge);
        }
        let mut wire = Vec::with_capacity(total);
        wire.extend_from_slice(STATE_MAGIC);
        wire.extend_from_slice(&STATE_VERSION.to_be_bytes());
        wire.push(match self.phase {
            ManagedAgentStackApplyPhaseV1::RequestDurableNotSent => 1,
            ManagedAgentStackApplyPhaseV1::Uncertain => 2,
            ManagedAgentStackApplyPhaseV1::ReceiptDurable => 3,
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
        decode: ManagedAgentStackDecodeContextV1<'_>,
    ) -> Result<Self, ManagedAgentStackApplyControllerError> {
        let ManagedAgentStackDecodeContextV1 {
            fabric: context,
            cutover_marker_digest,
            predecessor_revision,
            predecessor_execution,
            predecessor_slice_digest,
            predecessor_generation,
        } = decode;
        if frame.len() < LEGACY_STATE_FIXED_BYTES + STATE_CHECKSUM_BYTES {
            return Err(ManagedAgentStackApplyControllerError::StateTruncated);
        }
        if frame.len() > MAX_STATE_BYTES {
            return Err(ManagedAgentStackApplyControllerError::StateTooLarge);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.array::<4>()? != *STATE_MAGIC {
            return Err(ManagedAgentStackApplyControllerError::InvalidState);
        }
        let state_version = cursor.u16()?;
        if state_version != LEGACY_STATE_VERSION && state_version != STATE_VERSION {
            return Err(ManagedAgentStackApplyControllerError::InvalidState);
        }
        let phase = match cursor.u8()? {
            1 => ManagedAgentStackApplyPhaseV1::RequestDurableNotSent,
            2 => ManagedAgentStackApplyPhaseV1::Uncertain,
            3 => ManagedAgentStackApplyPhaseV1::ReceiptDurable,
            _ => return Err(ManagedAgentStackApplyControllerError::InvalidState),
        };
        let revision = cursor.u64()?;
        let encoded_predecessor = paraegox_runtime_contracts::provenance::TargetSliceDigest::new(
            Digest32::from_bytes(cursor.array()?),
        );
        let execution_length = cursor.usize_u32()?;
        let request_length = cursor.usize_u32()?;
        let receipt_length = cursor.usize_u32()?;
        let (
            archived_revision,
            archived_execution_length,
            archived_request_length,
            archived_receipt_length,
        ) = if state_version == STATE_VERSION {
            (
                cursor.u64()?,
                cursor.usize_u32()?,
                cursor.usize_u32()?,
                cursor.usize_u32()?,
            )
        } else {
            (0, 0, 0, 0)
        };
        let fixed_bytes = if state_version == STATE_VERSION {
            STATE_FIXED_BYTES
        } else {
            LEGACY_STATE_FIXED_BYTES
        };
        let expected = fixed_bytes
            .checked_add(execution_length)
            .and_then(|value| value.checked_add(request_length))
            .and_then(|value| value.checked_add(receipt_length))
            .and_then(|value| value.checked_add(archived_execution_length))
            .and_then(|value| value.checked_add(archived_request_length))
            .and_then(|value| value.checked_add(archived_receipt_length))
            .and_then(|value| value.checked_add(STATE_CHECKSUM_BYTES))
            .ok_or(ManagedAgentStackApplyControllerError::StateTooLarge)?;
        if expected != frame.len() {
            return Err(ManagedAgentStackApplyControllerError::InvalidState);
        }
        let execution = cursor.take(execution_length)?;
        let request_wire = cursor.take(request_length)?;
        let receipt_wire = cursor.take(receipt_length)?;
        let archived_execution = cursor.take(archived_execution_length)?;
        let archived_request = cursor.take(archived_request_length)?;
        let archived_receipt = cursor.take(archived_receipt_length)?;
        let checksum = Digest32::from_bytes(cursor.array()?);
        cursor.finish()?;
        if state_checksum(&frame[..frame.len() - STATE_CHECKSUM_BYTES])? != checksum {
            return Err(ManagedAgentStackApplyControllerError::StateChecksumMismatch);
        }
        let archived_active = if archived_revision == 0
            && archived_execution.is_empty()
            && archived_request.is_empty()
            && archived_receipt.is_empty()
        {
            None
        } else {
            if archived_revision == 0
                || archived_execution.is_empty()
                || archived_request.is_empty()
                || archived_receipt.is_empty()
            {
                return Err(ManagedAgentStackApplyControllerError::InvalidState);
            }
            let desired = ManagedAgentStackDesiredPlanV1::try_restore(
                context,
                cutover_marker_digest,
                predecessor_slice_digest,
                archived_revision,
                archived_execution,
            )?;
            if desired.revision().value()
                != predecessor_revision
                    .value()
                    .checked_add(1)
                    .ok_or(ManagedAgentStackApplyControllerError::SequenceExhausted)?
                || desired.execution().mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
                || desired.execution().fabric() != predecessor_execution
            {
                return Err(ManagedAgentStackApplyControllerError::InvalidState);
            }
            let request = ManagedAgentStackApplyRequestV1::decode(archived_request)?;
            validate_managed_agent_stack_request_v1(context, &desired, &request)?;
            let receipt = ManagedAgentStackTerminalReceiptV1::decode(archived_receipt)?;
            verify_terminal(&receipt, &request, context, predecessor_generation)?;
            Some(CompletedManagedAgentStackApplyV1 {
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
            return Err(ManagedAgentStackApplyControllerError::InvalidState);
        }
        let desired = ManagedAgentStackDesiredPlanV1::try_restore(
            context,
            cutover_marker_digest,
            expected_predecessor,
            revision,
            execution,
        )?;
        let request = ManagedAgentStackApplyRequestV1::decode(request_wire)?;
        match archived_active.as_ref() {
            None => {
                if desired.revision().value()
                    != predecessor_revision
                        .value()
                        .checked_add(1)
                        .ok_or(ManagedAgentStackApplyControllerError::SequenceExhausted)?
                    || desired.execution().mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
                    || desired.execution().fabric() != predecessor_execution
                {
                    return Err(ManagedAgentStackApplyControllerError::InvalidState);
                }
                validate_managed_agent_stack_request_v1(context, &desired, &request)?;
            }
            Some(archived) => {
                if desired.revision().value()
                    != archived
                        .desired
                        .revision()
                        .value()
                        .checked_add(1)
                        .ok_or(ManagedAgentStackApplyControllerError::SequenceExhausted)?
                    || desired.execution().mode() != ManagedAgentStackTargetModeV1::EmptyDeactivate
                {
                    return Err(ManagedAgentStackApplyControllerError::InvalidState);
                }
                validate_managed_agent_stack_empty_request_v1(
                    context,
                    &desired,
                    archived.desired.execution(),
                    &request,
                )?;
            }
        }
        let receipt = match phase {
            ManagedAgentStackApplyPhaseV1::RequestDurableNotSent
            | ManagedAgentStackApplyPhaseV1::Uncertain => {
                if !receipt_wire.is_empty() {
                    return Err(ManagedAgentStackApplyControllerError::InvalidState);
                }
                None
            }
            ManagedAgentStackApplyPhaseV1::ReceiptDurable => {
                if receipt_wire.is_empty() {
                    return Err(ManagedAgentStackApplyControllerError::InvalidState);
                }
                let receipt = ManagedAgentStackTerminalReceiptV1::decode(receipt_wire)?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedManagedAgentStackApplyV1 {
    outer_sequence: u64,
    cutover_marker_digest: Digest32,
    request_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedManagedAgentStackAgentControlApplyV1 {
    outer_sequence: u64,
    cutover_marker_digest: Digest32,
    inner_request_digest: Digest32,
    outer_request_digest: Digest32,
}

/// Explicit inputs for one remote Agent-stack Agent-control prepare.
pub(crate) struct ManagedAgentStackRemoteAgentControlActivateInputV1<'a> {
    pub(crate) controller_signer: &'a ed25519_dalek::SigningKey,
    pub(crate) provisioning: &'a ManagedFabricRemoteControllerProvisioningV1,
    pub(crate) previous: &'a ManagedServingDescribeIngressV1,
    pub(crate) activation: &'a ManagedAgentStackActivationV1,
    pub(crate) inner_fresh: FreshManagedAgentStackApplyV1,
    pub(crate) outer_fresh: FreshRuntimeAgentControlV1,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackAgentControlSendActionV1 {
    outer_sequence: u64,
    cutover_marker_digest: Digest32,
    request: RuntimeAgentControlRequestV1,
    channel: ReferenceChannelBindingV1,
}

impl ManagedAgentStackAgentControlSendActionV1 {
    #[must_use]
    pub(crate) const fn request(&self) -> &RuntimeAgentControlRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) fn canonical_request_bytes(&self) -> &[u8] {
        self.request.canonical_wire()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackAgentControlTerminalCommitV1 {
    outer_sequence: u64,
    inner: ManagedAgentStackTerminalReceiptV1,
    outer: RuntimeAgentControlReceiptV1,
    replayed_from_journal: bool,
}

impl ManagedAgentStackAgentControlTerminalCommitV1 {
    #[must_use]
    pub(crate) const fn inner(&self) -> &ManagedAgentStackTerminalReceiptV1 {
        &self.inner
    }

    #[must_use]
    pub(crate) const fn outer(&self) -> &RuntimeAgentControlReceiptV1 {
        &self.outer
    }

    #[must_use]
    pub(crate) const fn replayed_from_journal(&self) -> bool {
        self.replayed_from_journal
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedConversationPortDescriptorV1 {
    outer_sequence: u64,
    cutover_marker_digest: Digest32,
    request_digest: Digest32,
    expected_pxst_digest: Digest32,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ConversationPortDescriptorSendActionV1 {
    outer_sequence: u64,
    cutover_marker_digest: Digest32,
    request: RuntimeAgentControlRequestV1,
}

impl ConversationPortDescriptorSendActionV1 {
    #[must_use]
    pub(crate) const fn request(&self) -> &RuntimeAgentControlRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) fn canonical_request_bytes(&self) -> &[u8] {
        self.request.canonical_wire()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConversationPortDescriptorTerminalCommitV1 {
    outer_sequence: u64,
    receipt: RuntimeAgentControlReceiptV1,
    replayed_from_journal: bool,
}

impl ConversationPortDescriptorTerminalCommitV1 {
    #[must_use]
    pub(crate) fn descriptor(&self) -> Option<&[u8]> {
        self.receipt.conversation_port_descriptor()
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> &RuntimeAgentControlReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub(crate) const fn replayed_from_journal(&self) -> bool {
        self.replayed_from_journal
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackSendActionV1 {
    outer_sequence: u64,
    cutover_marker_digest: Digest32,
    request: ManagedAgentStackApplyRequestV1,
    channel: ReferenceChannelBindingV1,
}

impl ManagedAgentStackSendActionV1 {
    #[cfg(test)]
    pub(crate) fn from_contract_fixture(
        request: ManagedAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> Self {
        Self {
            outer_sequence: 1,
            cutover_marker_digest: Digest32::from_bytes([0x7e; 32]),
            request,
            channel,
        }
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ManagedAgentStackApplyRequestV1 {
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
pub(crate) struct ManagedAgentStackTerminalCommitV1 {
    outer_sequence: u64,
    receipt: ManagedAgentStackTerminalReceiptV1,
    replayed_from_journal: bool,
}

impl ManagedAgentStackTerminalCommitV1 {
    #[must_use]
    pub(crate) const fn receipt(&self) -> &ManagedAgentStackTerminalReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub(crate) const fn replayed_from_journal(&self) -> bool {
        self.replayed_from_journal
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackApplyJournalV1 {
    state: ManagedFabricControllerStateV1,
}

impl ManagedAgentStackApplyJournalV1 {
    #[must_use]
    pub(crate) const fn new(state: ManagedFabricControllerStateV1) -> Self {
        Self { state }
    }

    #[must_use]
    pub(crate) const fn state(&self) -> &ManagedFabricControllerStateV1 {
        &self.state
    }

    pub(crate) fn prepare_remote_agent_control_activate_with<Commit>(
        &mut self,
        input: ManagedAgentStackRemoteAgentControlActivateInputV1<'_>,
        commit: Commit,
    ) -> Result<PreparedManagedAgentStackAgentControlApplyV1, ManagedAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedAgentStackApplyControllerError>,
    {
        let ManagedAgentStackRemoteAgentControlActivateInputV1 {
            controller_signer,
            provisioning,
            previous,
            activation,
            inner_fresh,
            outer_fresh,
        } = input;
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        self.state
            .revalidate_runtime_agent_control_slots(provisioning, &ready, &context)?;
        let (predecessor_desired, predecessor_request, predecessor_receipt) =
            active_predecessor(&self.state)?;
        if let Some(stack) = self.state.agent_stack_state() {
            if stack.phase() != ManagedAgentStackApplyPhaseV1::RequestDurableNotSent
                || self.state.agent_stack_agent_control().phase()
                    != RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
                || stack.archived_active().is_some()
            {
                return Err(match stack.phase() {
                    ManagedAgentStackApplyPhaseV1::Uncertain => {
                        ManagedAgentStackApplyControllerError::OpaqueReplayForbidden
                    }
                    ManagedAgentStackApplyPhaseV1::ReceiptDurable => {
                        ManagedAgentStackApplyControllerError::AlreadyTerminal
                    }
                    ManagedAgentStackApplyPhaseV1::RequestDurableNotSent => {
                        ManagedAgentStackApplyControllerError::InvalidPhase
                    }
                });
            }
            let expected = ManagedAgentStackDesiredPlanV1::try_activate(
                &context,
                self.state.cutover_marker_digest(),
                predecessor_desired.revision(),
                predecessor_desired.execution(),
                predecessor_request.target_slice_digest(),
                activation,
            )?;
            if stack.desired() != &expected {
                return Err(ManagedAgentStackApplyControllerError::DesiredConflict);
            }
            return self.prepared_remote_agent_control(controller_signer, provisioning, previous);
        }
        if predecessor_receipt.facts().outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        {
            return Err(ManagedAgentStackApplyControllerError::FabricNotActive);
        }
        let desired = ManagedAgentStackDesiredPlanV1::try_activate(
            &context,
            self.state.cutover_marker_digest(),
            predecessor_desired.revision(),
            predecessor_desired.execution(),
            predecessor_request.target_slice_digest(),
            activation,
        )?;
        let inner = produce_managed_agent_stack_request_v1(
            &context,
            &desired,
            inner_fresh,
            controller_signer,
        )?;
        let outer = provisioning
            .describe()
            .try_build_managed_agent_stack_agent_control(
                &ready,
                &inner,
                outer_fresh,
                controller_signer,
            )?;
        let stack = ManagedAgentStackControllerStateV1::try_prepared(desired, inner)?;
        let slot = self.state.agent_stack_agent_control().try_prepare(outer)?;
        let next = self.state.try_with_agent_stack_and_control(stack, slot)?;
        commit(&next)?;
        self.state = next;
        self.prepared_remote_agent_control(controller_signer, provisioning, previous)
    }

    pub(crate) fn prepared_remote_agent_control(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
    ) -> Result<PreparedManagedAgentStackAgentControlApplyV1, ManagedAgentStackApplyControllerError>
    {
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        self.state
            .revalidate_runtime_agent_control_slots(provisioning, &ready, &context)?;
        let stack = self
            .state
            .agent_stack_state()
            .ok_or(ManagedAgentStackApplyControllerError::InvalidPhase)?;
        if stack.phase() != ManagedAgentStackApplyPhaseV1::RequestDurableNotSent
            || self.state.agent_stack_agent_control().phase()
                != RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
        {
            return Err(match stack.phase() {
                ManagedAgentStackApplyPhaseV1::Uncertain => {
                    ManagedAgentStackApplyControllerError::OpaqueReplayForbidden
                }
                ManagedAgentStackApplyPhaseV1::ReceiptDurable => {
                    ManagedAgentStackApplyControllerError::AlreadyTerminal
                }
                ManagedAgentStackApplyPhaseV1::RequestDurableNotSent => {
                    ManagedAgentStackApplyControllerError::InvalidPhase
                }
            });
        }
        validate_stack_request(&context, stack)?;
        let outer = self
            .state
            .agent_stack_agent_control()
            .request()
            .ok_or(ManagedAgentStackApplyControllerError::AgentControlMismatch)?;
        if outer.managed_agent_stack_apply_request() != Some(stack.request()) {
            return Err(ManagedAgentStackApplyControllerError::AgentControlMismatch);
        }
        Ok(PreparedManagedAgentStackAgentControlApplyV1 {
            outer_sequence: self.state.sequence(),
            cutover_marker_digest: self.state.cutover_marker_digest(),
            inner_request_digest: stack.request().envelope_request_digest(),
            outer_request_digest: outer.request_digest(),
        })
    }

    pub(crate) fn claim_remote_agent_control_send_with<Commit>(
        &mut self,
        prepared: PreparedManagedAgentStackAgentControlApplyV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        commit: Commit,
    ) -> Result<ManagedAgentStackAgentControlSendActionV1, ManagedAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedAgentStackApplyControllerError>,
    {
        let expected =
            self.prepared_remote_agent_control(controller_signer, provisioning, previous)?;
        if prepared != expected {
            return Err(ManagedAgentStackApplyControllerError::PreparedTokenMismatch);
        }
        let (context, _) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        let stack = self
            .state
            .agent_stack_state()
            .ok_or(ManagedAgentStackApplyControllerError::InvalidPhase)?;
        let request = self
            .state
            .agent_stack_agent_control()
            .request()
            .cloned()
            .ok_or(ManagedAgentStackApplyControllerError::AgentControlMismatch)?;
        let next_stack = stack.try_claim()?;
        let next_slot = self.state.agent_stack_agent_control().try_claim()?;
        let next = self
            .state
            .try_with_agent_stack_and_control(next_stack, next_slot)?;
        commit(&next)?;
        self.state = next;
        Ok(ManagedAgentStackAgentControlSendActionV1 {
            outer_sequence: self.state.sequence(),
            cutover_marker_digest: self.state.cutover_marker_digest(),
            request,
            channel: context.channel(),
        })
    }

    pub(crate) fn consume_remote_agent_control_pxah_with<Commit>(
        &mut self,
        action: ManagedAgentStackAgentControlSendActionV1,
        transport: RuntimeAgentControlMtlsExchangeSuccessV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        commit: Commit,
    ) -> Result<ManagedAgentStackAgentControlTerminalCommitV1, ManagedAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedAgentStackApplyControllerError>,
    {
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        self.state
            .revalidate_runtime_agent_control_slots(provisioning, &ready, &context)?;
        let (_, _, predecessor_receipt) = active_predecessor(&self.state)?;
        let predecessor_generation = predecessor_receipt
            .facts()
            .generation()
            .ok_or(ManagedAgentStackApplyControllerError::FabricNotActive)?;
        let stack = self
            .state
            .agent_stack_state()
            .ok_or(ManagedAgentStackApplyControllerError::InvalidPhase)?;
        if stack.phase() != ManagedAgentStackApplyPhaseV1::Uncertain
            || self.state.agent_stack_agent_control().phase()
                != RuntimeAgentControlDurablePhaseV1::Uncertain
            || action.outer_sequence != self.state.sequence()
            || action.cutover_marker_digest != self.state.cutover_marker_digest()
            || self.state.agent_stack_agent_control().request() != Some(&action.request)
            || action.channel != context.channel()
        {
            return Err(ManagedAgentStackApplyControllerError::SendActionMismatch);
        }
        let outer = provisioning
            .describe()
            .try_accept_runtime_agent_apply_receipt(
                &ready,
                &action.request,
                context.channel(),
                &transport,
            )?;
        let inner = outer
            .managed_agent_stack_receipt()
            .cloned()
            .ok_or(ManagedAgentStackApplyControllerError::AgentControlMismatch)?;
        verify_terminal(&inner, stack.request(), &context, predecessor_generation)?;
        let next_stack = stack.try_terminal(inner.clone())?;
        let next_slot = self
            .state
            .agent_stack_agent_control()
            .try_terminal(outer.clone())?;
        let next = self
            .state
            .try_with_agent_stack_and_control(next_stack, next_slot)?;
        commit(&next)?;
        self.state = next;
        Ok(ManagedAgentStackAgentControlTerminalCommitV1 {
            outer_sequence: self.state.sequence(),
            inner,
            outer,
            replayed_from_journal: false,
        })
    }

    pub(crate) fn remote_agent_control_terminal(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
    ) -> Result<
        Option<ManagedAgentStackAgentControlTerminalCommitV1>,
        ManagedAgentStackApplyControllerError,
    > {
        if self.state.agent_stack_agent_control().phase()
            != RuntimeAgentControlDurablePhaseV1::ReceiptDurable
        {
            return Ok(None);
        }
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        self.state
            .revalidate_runtime_agent_control_slots(provisioning, &ready, &context)?;
        let stack = self
            .state
            .agent_stack_state()
            .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?;
        Ok(Some(ManagedAgentStackAgentControlTerminalCommitV1 {
            outer_sequence: self.state.sequence(),
            inner: stack
                .receipt()
                .cloned()
                .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?,
            outer: self
                .state
                .agent_stack_agent_control()
                .receipt()
                .cloned()
                .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?,
            replayed_from_journal: true,
        }))
    }

    pub(crate) fn prepare_conversation_port_descriptor_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        intended_client: PrincipalRef,
        fresh: FreshRuntimeAgentControlV1,
        commit: Commit,
    ) -> Result<PreparedConversationPortDescriptorV1, ManagedAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedAgentStackApplyControllerError>,
    {
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        self.state
            .revalidate_runtime_agent_control_slots(provisioning, &ready, &context)?;
        let (_, _, predecessor_receipt) = active_predecessor(&self.state)?;
        let predecessor_generation = predecessor_receipt
            .facts()
            .generation()
            .ok_or(ManagedAgentStackApplyControllerError::FabricNotActive)?;
        let stack = self
            .state
            .agent_stack_state()
            .ok_or(ManagedAgentStackApplyControllerError::AgentNotActive)?;
        let stack_receipt = stack
            .receipt()
            .ok_or(ManagedAgentStackApplyControllerError::AgentNotActive)?;
        verify_terminal(
            stack_receipt,
            stack.request(),
            &context,
            predecessor_generation,
        )?;
        if stack.archived_active().is_some()
            || stack_receipt.facts().state().outcome()
                != ManagedAgentStackTerminalOutcomeV1::ActiveReady
            || stack_receipt.facts().state().agent_generation().is_none()
        {
            return Err(ManagedAgentStackApplyControllerError::AgentNotActive);
        }
        match self.state.conversation_port_descriptor().phase() {
            RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent => {
                let request = self
                    .state
                    .conversation_port_descriptor()
                    .request()
                    .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?;
                if request.intended_client() != intended_client {
                    return Err(ManagedAgentStackApplyControllerError::DesiredConflict);
                }
                return self.prepared_conversation_port_descriptor(
                    controller_signer,
                    provisioning,
                    previous,
                );
            }
            RuntimeAgentControlDurablePhaseV1::Uncertain => {
                return Err(ManagedAgentStackApplyControllerError::OpaqueReplayForbidden);
            }
            RuntimeAgentControlDurablePhaseV1::ReceiptDurable => {
                return Err(ManagedAgentStackApplyControllerError::AlreadyTerminal);
            }
            RuntimeAgentControlDurablePhaseV1::Idle => {}
        }
        let request = provisioning
            .describe()
            .try_build_conversation_port_agent_control(
                &ready,
                stack_receipt.receipt_digest(),
                intended_client,
                fresh,
                controller_signer,
            )?;
        let descriptor = self
            .state
            .conversation_port_descriptor()
            .try_prepare(request)?;
        let next = self.state.try_with_descriptor_control(descriptor)?;
        commit(&next)?;
        self.state = next;
        self.prepared_conversation_port_descriptor(controller_signer, provisioning, previous)
    }

    pub(crate) fn prepared_conversation_port_descriptor(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
    ) -> Result<PreparedConversationPortDescriptorV1, ManagedAgentStackApplyControllerError> {
        if self.state.conversation_port_descriptor().phase()
            != RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
        {
            return Err(match self.state.conversation_port_descriptor().phase() {
                RuntimeAgentControlDurablePhaseV1::Uncertain => {
                    ManagedAgentStackApplyControllerError::OpaqueReplayForbidden
                }
                RuntimeAgentControlDurablePhaseV1::ReceiptDurable => {
                    ManagedAgentStackApplyControllerError::AlreadyTerminal
                }
                _ => ManagedAgentStackApplyControllerError::InvalidPhase,
            });
        }
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        self.state
            .revalidate_runtime_agent_control_slots(provisioning, &ready, &context)?;
        let stack_receipt = self
            .state
            .agent_stack_state()
            .and_then(ManagedAgentStackControllerStateV1::receipt)
            .ok_or(ManagedAgentStackApplyControllerError::AgentNotActive)?;
        let request = self
            .state
            .conversation_port_descriptor()
            .request()
            .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?;
        if request.kind() != RuntimeAgentControlKindV1::DescribeConversationPort
            || request.expected_active_pxst_digest() != stack_receipt.receipt_digest()
        {
            return Err(ManagedAgentStackApplyControllerError::AgentControlMismatch);
        }
        Ok(PreparedConversationPortDescriptorV1 {
            outer_sequence: self.state.sequence(),
            cutover_marker_digest: self.state.cutover_marker_digest(),
            request_digest: request.request_digest(),
            expected_pxst_digest: stack_receipt.receipt_digest(),
        })
    }

    pub(crate) fn claim_conversation_port_descriptor_with<Commit>(
        &mut self,
        prepared: PreparedConversationPortDescriptorV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        commit: Commit,
    ) -> Result<ConversationPortDescriptorSendActionV1, ManagedAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedAgentStackApplyControllerError>,
    {
        let expected =
            self.prepared_conversation_port_descriptor(controller_signer, provisioning, previous)?;
        if prepared != expected {
            return Err(ManagedAgentStackApplyControllerError::PreparedTokenMismatch);
        }
        let request = self
            .state
            .conversation_port_descriptor()
            .request()
            .cloned()
            .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?;
        let descriptor = self.state.conversation_port_descriptor().try_claim()?;
        let next = self.state.try_with_descriptor_control(descriptor)?;
        commit(&next)?;
        self.state = next;
        Ok(ConversationPortDescriptorSendActionV1 {
            outer_sequence: self.state.sequence(),
            cutover_marker_digest: self.state.cutover_marker_digest(),
            request,
        })
    }

    pub(crate) fn consume_conversation_port_descriptor_pxah_with<Commit>(
        &mut self,
        action: ConversationPortDescriptorSendActionV1,
        transport: RuntimeAgentControlMtlsExchangeSuccessV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        commit: Commit,
    ) -> Result<ConversationPortDescriptorTerminalCommitV1, ManagedAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedAgentStackApplyControllerError>,
    {
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        self.state
            .revalidate_runtime_agent_control_slots(provisioning, &ready, &context)?;
        if self.state.conversation_port_descriptor().phase()
            != RuntimeAgentControlDurablePhaseV1::Uncertain
            || action.outer_sequence != self.state.sequence()
            || action.cutover_marker_digest != self.state.cutover_marker_digest()
            || self.state.conversation_port_descriptor().request() != Some(&action.request)
        {
            return Err(ManagedAgentStackApplyControllerError::SendActionMismatch);
        }
        let receipt = provisioning
            .describe()
            .try_accept_runtime_agent_descriptor_receipt(&ready, &action.request, &transport)?;
        let fabric_generation = self
            .state
            .receipt()
            .and_then(|value| value.facts().generation());
        let agent_generation = self
            .state
            .agent_stack_state()
            .and_then(ManagedAgentStackControllerStateV1::receipt)
            .and_then(|value| value.facts().state().agent_generation());
        if receipt.conversation_port_descriptor().is_none()
            || receipt.fabric_generation() != fabric_generation
            || receipt.agent_generation() != agent_generation
        {
            return Err(ManagedAgentStackApplyControllerError::AgentControlMismatch);
        }
        let descriptor = self
            .state
            .conversation_port_descriptor()
            .try_terminal(receipt.clone())?;
        let next = self.state.try_with_descriptor_control(descriptor)?;
        commit(&next)?;
        self.state = next;
        Ok(ConversationPortDescriptorTerminalCommitV1 {
            outer_sequence: self.state.sequence(),
            receipt,
            replayed_from_journal: false,
        })
    }

    pub(crate) fn conversation_port_descriptor_terminal(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
    ) -> Result<
        Option<ConversationPortDescriptorTerminalCommitV1>,
        ManagedAgentStackApplyControllerError,
    > {
        if self.state.conversation_port_descriptor().phase()
            != RuntimeAgentControlDurablePhaseV1::ReceiptDurable
        {
            return Ok(None);
        }
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        self.state
            .revalidate_runtime_agent_control_slots(provisioning, &ready, &context)?;
        Ok(Some(ConversationPortDescriptorTerminalCommitV1 {
            outer_sequence: self.state.sequence(),
            receipt: self
                .state
                .conversation_port_descriptor()
                .receipt()
                .cloned()
                .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?,
            replayed_from_journal: true,
        }))
    }

    pub(crate) fn prepared(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<PreparedManagedAgentStackApplyV1, ManagedAgentStackApplyControllerError> {
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let stack = self
            .state
            .agent_stack_state()
            .ok_or(ManagedAgentStackApplyControllerError::InvalidPhase)?;
        validate_stack_request(&context, stack)?;
        prepared_token(&self.state, stack)
    }

    pub(crate) fn prepare_activate_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        activation: &ManagedAgentStackActivationV1,
        fresh: FreshManagedAgentStackApplyV1,
        commit: Commit,
    ) -> Result<PreparedManagedAgentStackApplyV1, ManagedAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedAgentStackApplyControllerError>,
    {
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let (predecessor_desired, predecessor_request, predecessor_receipt) =
            active_predecessor(&self.state)?;
        if let Some(stack) = self.state.agent_stack_state() {
            if stack.phase() != ManagedAgentStackApplyPhaseV1::RequestDurableNotSent
                || stack.archived_active().is_some()
            {
                return Err(match stack.phase() {
                    ManagedAgentStackApplyPhaseV1::Uncertain => {
                        ManagedAgentStackApplyControllerError::OpaqueReplayForbidden
                    }
                    ManagedAgentStackApplyPhaseV1::ReceiptDurable => {
                        ManagedAgentStackApplyControllerError::AlreadyTerminal
                    }
                    ManagedAgentStackApplyPhaseV1::RequestDurableNotSent => {
                        ManagedAgentStackApplyControllerError::InvalidPhase
                    }
                });
            }
            let expected = ManagedAgentStackDesiredPlanV1::try_activate(
                &context,
                self.state.cutover_marker_digest(),
                predecessor_desired.revision(),
                predecessor_desired.execution(),
                predecessor_request.target_slice_digest(),
                activation,
            )?;
            if stack.desired() != &expected {
                return Err(ManagedAgentStackApplyControllerError::DesiredConflict);
            }
            validate_managed_agent_stack_request_v1(&context, stack.desired(), stack.request())?;
            return prepared_token(&self.state, stack);
        }
        if predecessor_receipt.facts().outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        {
            return Err(ManagedAgentStackApplyControllerError::FabricNotActive);
        }
        let desired = ManagedAgentStackDesiredPlanV1::try_activate(
            &context,
            self.state.cutover_marker_digest(),
            predecessor_desired.revision(),
            predecessor_desired.execution(),
            predecessor_request.target_slice_digest(),
            activation,
        )?;
        let request =
            produce_managed_agent_stack_request_v1(&context, &desired, fresh, controller_signer)?;
        let stack = ManagedAgentStackControllerStateV1::try_prepared(desired, request)?;
        let next = self.state.try_with_agent_stack_state(stack)?;
        commit(&next)?;
        self.state = next;
        prepared_token(
            &self.state,
            self.state
                .agent_stack_state()
                .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?,
        )
    }

    pub(crate) fn prepare_empty_deactivate_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        fresh: FreshManagedAgentStackApplyV1,
        commit: Commit,
    ) -> Result<PreparedManagedAgentStackApplyV1, ManagedAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedAgentStackApplyControllerError>,
    {
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let (_, _, predecessor_receipt) = active_predecessor(&self.state)?;
        let predecessor_generation = predecessor_receipt
            .facts()
            .generation()
            .ok_or(ManagedAgentStackApplyControllerError::FabricNotActive)?;
        let current = self
            .state
            .agent_stack_state()
            .ok_or(ManagedAgentStackApplyControllerError::AgentNotActive)?;
        match current.phase() {
            ManagedAgentStackApplyPhaseV1::RequestDurableNotSent => {
                let archived = current
                    .archived_active()
                    .ok_or(ManagedAgentStackApplyControllerError::AgentNotActive)?;
                let expected = ManagedAgentStackDesiredPlanV1::try_empty_deactivate(
                    &context,
                    self.state.cutover_marker_digest(),
                    &archived.desired,
                    &archived.request,
                )?;
                if current.desired() != &expected {
                    return Err(ManagedAgentStackApplyControllerError::DesiredConflict);
                }
                validate_managed_agent_stack_empty_request_v1(
                    &context,
                    current.desired(),
                    archived.desired.execution(),
                    current.request(),
                )?;
                return prepared_token(&self.state, current);
            }
            ManagedAgentStackApplyPhaseV1::Uncertain => {
                return Err(ManagedAgentStackApplyControllerError::OpaqueReplayForbidden);
            }
            ManagedAgentStackApplyPhaseV1::ReceiptDurable
                if current.archived_active().is_some() =>
            {
                return Err(ManagedAgentStackApplyControllerError::AlreadyTerminal);
            }
            ManagedAgentStackApplyPhaseV1::ReceiptDurable => {}
        }
        let active_receipt = current
            .receipt()
            .ok_or(ManagedAgentStackApplyControllerError::AgentNotActive)?;
        verify_terminal(
            active_receipt,
            current.request(),
            &context,
            predecessor_generation,
        )?;
        let desired = ManagedAgentStackDesiredPlanV1::try_empty_deactivate(
            &context,
            self.state.cutover_marker_digest(),
            current.desired(),
            current.request(),
        )?;
        let request = produce_managed_agent_stack_empty_request_v1(
            &context,
            &desired,
            current.desired().execution(),
            fresh,
            controller_signer,
        )?;
        let stack = current.try_prepare_empty(desired, request)?;
        let next = self.state.try_with_agent_stack_state(stack)?;
        commit(&next)?;
        self.state = next;
        prepared_token(
            &self.state,
            self.state
                .agent_stack_state()
                .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?,
        )
    }

    pub(crate) fn claim_send_with<Commit>(
        &mut self,
        prepared: PreparedManagedAgentStackApplyV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        commit: Commit,
    ) -> Result<ManagedAgentStackSendActionV1, ManagedAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedAgentStackApplyControllerError>,
    {
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let stack = self
            .state
            .agent_stack_state()
            .ok_or(ManagedAgentStackApplyControllerError::InvalidPhase)?;
        validate_prepared(&self.state, stack, prepared)?;
        validate_stack_request(&context, stack)?;
        let request = stack.request().clone();
        let next = self.state.try_with_agent_stack_state(stack.try_claim()?)?;
        commit(&next)?;
        self.state = next;
        Ok(ManagedAgentStackSendActionV1 {
            outer_sequence: self.state.sequence(),
            cutover_marker_digest: self.state.cutover_marker_digest(),
            request,
            channel: context.channel(),
        })
    }

    pub(crate) fn consume_pxst_with<Commit>(
        &mut self,
        action: ManagedAgentStackSendActionV1,
        receipt_wire: &[u8],
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        commit: Commit,
    ) -> Result<ManagedAgentStackTerminalCommitV1, ManagedAgentStackApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedAgentStackApplyControllerError>,
    {
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let (_, _, predecessor_receipt) = active_predecessor(&self.state)?;
        let predecessor_generation = predecessor_receipt
            .facts()
            .generation()
            .ok_or(ManagedAgentStackApplyControllerError::FabricNotActive)?;
        let stack = self
            .state
            .agent_stack_state()
            .ok_or(ManagedAgentStackApplyControllerError::InvalidPhase)?;
        if stack.phase() != ManagedAgentStackApplyPhaseV1::Uncertain
            || action.outer_sequence != self.state.sequence()
            || action.cutover_marker_digest != self.state.cutover_marker_digest()
            || action.request != *stack.request()
            || action.channel != context.channel()
        {
            return Err(ManagedAgentStackApplyControllerError::SendActionMismatch);
        }
        let receipt = ManagedAgentStackTerminalReceiptV1::decode(receipt_wire)?;
        verify_terminal(&receipt, stack.request(), &context, predecessor_generation)?;
        let next = self
            .state
            .try_with_agent_stack_state(stack.try_terminal(receipt.clone())?)?;
        commit(&next)?;
        self.state = next;
        Ok(ManagedAgentStackTerminalCommitV1 {
            outer_sequence: self.state.sequence(),
            receipt,
            replayed_from_journal: false,
        })
    }

    pub(crate) fn terminal(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<Option<ManagedAgentStackTerminalCommitV1>, ManagedAgentStackApplyControllerError>
    {
        let Some(stack) = self.state.agent_stack_state() else {
            return Ok(None);
        };
        if stack.phase() != ManagedAgentStackApplyPhaseV1::ReceiptDurable {
            return Ok(None);
        }
        let context = self
            .state
            .verified_current_context(controller_signer, provisioning)?;
        let (_, _, predecessor_receipt) = active_predecessor(&self.state)?;
        let predecessor_generation = predecessor_receipt
            .facts()
            .generation()
            .ok_or(ManagedAgentStackApplyControllerError::FabricNotActive)?;
        let receipt = stack
            .receipt()
            .ok_or(ManagedAgentStackApplyControllerError::InvalidState)?;
        verify_terminal(receipt, stack.request(), &context, predecessor_generation)?;
        Ok(Some(ManagedAgentStackTerminalCommitV1 {
            outer_sequence: self.state.sequence(),
            receipt: receipt.clone(),
            replayed_from_journal: true,
        }))
    }
}

fn validate_stack_request(
    context: &VerifiedManagedFabricProducerContextV1,
    stack: &ManagedAgentStackControllerStateV1,
) -> Result<(), ManagedAgentStackApplyControllerError> {
    match stack.archived_active() {
        None => validate_managed_agent_stack_request_v1(context, stack.desired(), stack.request())?,
        Some(archived) => validate_managed_agent_stack_empty_request_v1(
            context,
            stack.desired(),
            archived.desired.execution(),
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
    ManagedAgentStackApplyControllerError,
> {
    if state.phase() != ManagedFabricApplyPhaseV1::ReceiptDurable
        || state.archived_active().is_some()
    {
        return Err(ManagedAgentStackApplyControllerError::FabricNotActive);
    }
    let desired = state
        .desired()
        .ok_or(ManagedAgentStackApplyControllerError::FabricNotActive)?;
    let request = state
        .request()
        .ok_or(ManagedAgentStackApplyControllerError::FabricNotActive)?;
    let receipt = state
        .receipt()
        .ok_or(ManagedAgentStackApplyControllerError::FabricNotActive)?;
    if desired.execution().mode() != ManagedFabricTargetModeV1::OneManagedFabricService
        || receipt.facts().outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        || receipt.facts().generation().is_none()
    {
        return Err(ManagedAgentStackApplyControllerError::FabricNotActive);
    }
    Ok((desired, request, receipt))
}

fn verify_terminal(
    receipt: &ManagedAgentStackTerminalReceiptV1,
    request: &ManagedAgentStackApplyRequestV1,
    context: &VerifiedManagedFabricProducerContextV1,
    predecessor_generation: ManagedServiceGeneration,
) -> Result<(), ManagedAgentStackApplyControllerError> {
    let facts = receipt.validate_against_request(request, context.channel())?;
    let state = facts.state();
    let outcome_matches_mode = match facts.request_mode() {
        ManagedAgentStackTargetModeV1::FabricAndAgent => {
            state.outcome() == ManagedAgentStackTerminalOutcomeV1::ActiveReady
                && state.head() == ManagedAgentStackTerminalHeadV1::CommittedIncoming
                && state.fabric_generation() == Some(predecessor_generation)
                && state.agent_generation().is_some()
        }
        ManagedAgentStackTargetModeV1::EmptyDeactivate => {
            state.outcome() == ManagedAgentStackTerminalOutcomeV1::EmptyExactZero
                && state.head() == ManagedAgentStackTerminalHeadV1::CommittedIncoming
                && state.fabric_generation().is_none()
                && state.agent_generation().is_none()
        }
    };
    if receipt.authentication_key() != context.runtime_response_key()
        || receipt.authentication_algorithm().value() != ED25519_ALGORITHM
        || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
        || receipt.authentication_signature().len() != ED25519_SIGNATURE_BYTES
        || !outcome_matches_mode
    {
        return Err(ManagedAgentStackApplyControllerError::ReceiptMismatch);
    }
    let signature: [u8; ED25519_SIGNATURE_BYTES] = receipt
        .authentication_signature()
        .try_into()
        .map_err(|_| ManagedAgentStackApplyControllerError::ReceiptMismatch)?;
    context
        .runtime_response_public_key()
        .verify_strict(
            receipt.signing_transcript()?.as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| ManagedAgentStackApplyControllerError::ReceiptMismatch)
}

fn prepared_token(
    state: &ManagedFabricControllerStateV1,
    stack: &ManagedAgentStackControllerStateV1,
) -> Result<PreparedManagedAgentStackApplyV1, ManagedAgentStackApplyControllerError> {
    if stack.phase() != ManagedAgentStackApplyPhaseV1::RequestDurableNotSent {
        return Err(ManagedAgentStackApplyControllerError::InvalidPhase);
    }
    Ok(PreparedManagedAgentStackApplyV1 {
        outer_sequence: state.sequence(),
        cutover_marker_digest: state.cutover_marker_digest(),
        request_digest: stack.request().envelope_request_digest(),
    })
}

fn validate_prepared(
    state: &ManagedFabricControllerStateV1,
    stack: &ManagedAgentStackControllerStateV1,
    prepared: PreparedManagedAgentStackApplyV1,
) -> Result<(), ManagedAgentStackApplyControllerError> {
    if stack.phase() != ManagedAgentStackApplyPhaseV1::RequestDurableNotSent
        || prepared.outer_sequence != state.sequence()
        || prepared.cutover_marker_digest != state.cutover_marker_digest()
        || prepared.request_digest != stack.request().envelope_request_digest()
    {
        return Err(ManagedAgentStackApplyControllerError::PreparedTokenMismatch);
    }
    Ok(())
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], ManagedAgentStackApplyControllerError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ManagedAgentStackApplyControllerError::StateTooLarge)?;
        let bytes = self
            .frame
            .get(self.position..end)
            .ok_or(ManagedAgentStackApplyControllerError::StateTruncated)?;
        self.position = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManagedAgentStackApplyControllerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ManagedAgentStackApplyControllerError::StateTruncated)
    }

    fn u8(&mut self) -> Result<u8, ManagedAgentStackApplyControllerError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ManagedAgentStackApplyControllerError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ManagedAgentStackApplyControllerError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize_u32(&mut self) -> Result<usize, ManagedAgentStackApplyControllerError> {
        usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| ManagedAgentStackApplyControllerError::StateTooLarge)
    }

    fn finish(self) -> Result<(), ManagedAgentStackApplyControllerError> {
        if self.position != self.frame.len() {
            return Err(ManagedAgentStackApplyControllerError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum ManagedAgentStackApplyControllerError {
    Contract,
    Producer(ManagedAgentStackProducerError),
    Fabric(ManagedFabricApplyControllerError),
    Serving(ManagedServingControllerError),
    Digest(DigestBuildError),
    InvalidPhase,
    InvalidState,
    StateTruncated,
    StateTooLarge,
    StateChecksumMismatch,
    SequenceExhausted,
    FabricNotActive,
    AgentNotActive,
    DesiredConflict,
    DurabilityRejected,
    PreparedTokenMismatch,
    SendActionMismatch,
    OpaqueReplayForbidden,
    AgentControlMismatch,
    ReceiptMismatch,
    AlreadyTerminal,
}

impl From<ManagedAgentStackPlanError> for ManagedAgentStackApplyControllerError {
    fn from(_value: ManagedAgentStackPlanError) -> Self {
        Self::Contract
    }
}

impl From<ManagedAgentStackProducerError> for ManagedAgentStackApplyControllerError {
    fn from(value: ManagedAgentStackProducerError) -> Self {
        Self::Producer(value)
    }
}

impl From<ManagedFabricApplyControllerError> for ManagedAgentStackApplyControllerError {
    fn from(value: ManagedFabricApplyControllerError) -> Self {
        Self::Fabric(value)
    }
}

impl From<ManagedServingControllerError> for ManagedAgentStackApplyControllerError {
    fn from(value: ManagedServingControllerError) -> Self {
        Self::Serving(value)
    }
}

impl From<DigestBuildError> for ManagedAgentStackApplyControllerError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ManagedAgentStackApplyControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "managed Agent stack apply failed: {self:?}")
    }
}

impl std::error::Error for ManagedAgentStackApplyControllerError {}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::time::BoundedDuration;
    use paraegox_runtime_contracts::apply::ExpectedActive;
    use paraegox_runtime_contracts::assignment::BindingId;
    use paraegox_runtime_contracts::managed_agent_stack_plan::{
        ManagedAgentIngressLimitsV1, ManagedAgentPortPlanV1, ManagedAgentProviderProfileV1,
        ManagedAgentProviderRefV1, ManagedAgentProviderSelectionV1, ManagedAgentSecretRefV1,
        ManagedAgentSemanticLimitsV1, ManagedAgentServicePlanV1, ManagedAgentStackTargetModeV1,
        ManagedAgentStackTerminalAuthClaimV1, ManagedAgentStackTerminalEvidenceFieldsV1,
        ManagedAgentStackTerminalEvidenceV1, ManagedAgentStackTerminalFactsV1,
        ManagedAgentStackTerminalHeadV1, ManagedAgentStackTerminalLifecycleEffectV1,
        ManagedAgentStackTerminalOutcomeV1, ManagedAgentStackTerminalReceiptDraftV1,
        ManagedAgentStackTerminalReceiptV1, ManagedAgentStackTerminalStateV1,
    };
    use paraegox_runtime_contracts::managed_fabric_plan::{
        MAX_MANAGED_FABRIC_LIFECYCLE_NANOS, ManagedFabricListenEndpointV1,
        ManagedFabricTargetExecutionV1,
    };
    use paraegox_runtime_contracts::managed_service::{
        ManagedServiceGeneration, ManagedServiceId, ManagedServiceLifecycleBudgetsV1,
        ManagedServiceSpecV1,
    };
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

    use super::{
        FreshManagedAgentStackApplyV1, ManagedAgentStackActivationV1,
        ManagedAgentStackApplyControllerError, ManagedAgentStackApplyJournalV1,
        ManagedAgentStackApplyPhaseV1,
    };
    use crate::managed_agent_stack_producer::ManagedAgentStackProducerError;
    use crate::managed_fabric_apply::{
        ManagedFabricApplyJournalV1, ManagedFabricControllerStateV1, tests as fabric_tests,
    };

    fn lifecycle_budgets(values: [u64; 5]) -> ManagedServiceLifecycleBudgetsV1 {
        ManagedServiceLifecycleBudgetsV1::try_new(
            BoundedDuration::from_nanos(values[0]),
            BoundedDuration::from_nanos(values[1]),
            BoundedDuration::from_nanos(values[2]),
            BoundedDuration::from_nanos(values[3]),
            BoundedDuration::from_nanos(values[4]),
        )
        .expect("Agent lifecycle budgets")
    }

    fn deterministic_provider() -> ManagedAgentProviderSelectionV1 {
        ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            ManagedAgentProviderRefV1::try_from_bytes([0x83; 16]).expect("provider ref"),
            Digest32::from_bytes([0x84; 32]),
        )
        .expect("explicit deterministic provider")
    }

    fn provisioned_provider() -> ManagedAgentProviderSelectionV1 {
        ManagedAgentProviderSelectionV1::try_provisioned(
            ManagedAgentProviderRefV1::try_from_bytes([0x85; 16]).expect("provider ref"),
            Digest32::from_bytes([0x86; 32]),
            ManagedAgentSecretRefV1::try_from_bytes([0x87; 16]).expect("secret ref"),
        )
        .expect("explicit provisioned provider")
    }

    fn agent_plan(
        provider: ManagedAgentProviderSelectionV1,
        budgets: ManagedServiceLifecycleBudgetsV1,
    ) -> ManagedAgentServicePlanV1 {
        let ingress = ManagedAgentIngressLimitsV1::try_new(
            64,
            512 * 1024,
            128 * 1024,
            128 * 1024,
            5_000_000_000,
        )
        .expect("bounded ingress");
        let port = ManagedAgentPortPlanV1::try_new(
            BindingId::from_bytes([0x81; 16]),
            BindingId::from_bytes([0x82; 16]),
            "paraegox/agent/v1/submit",
            "paraegox/agent/v1/control",
            ingress,
        )
        .expect("fixed two-lane Agent port");
        ManagedAgentServicePlanV1::try_new(
            ManagedServiceSpecV1::new(ManagedServiceId::from_bytes([0x88; 16]), budgets),
            ManagedAgentSemanticLimitsV1::try_new(16, 64, 64, 64).expect("semantic limits"),
            port,
            provider,
        )
        .expect("Agent plan")
    }

    fn fresh(marker: u8) -> FreshManagedAgentStackApplyV1 {
        FreshManagedAgentStackApplyV1::try_new(
            [marker; 16],
            [marker.wrapping_add(1); 16],
            [marker.wrapping_add(2); 32],
        )
        .expect("fresh stack identities")
    }

    fn active_fabric_journal() -> ManagedFabricApplyJournalV1 {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let mut journal = fabric_tests::journal();
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
        journal
    }

    fn activation(
        state: &ManagedFabricControllerStateV1,
        provider: ManagedAgentProviderSelectionV1,
        budgets: ManagedServiceLifecycleBudgetsV1,
    ) -> ManagedAgentStackActivationV1 {
        ManagedAgentStackActivationV1::try_new(
            state
                .desired()
                .expect("active Fabric desired")
                .execution()
                .clone(),
            agent_plan(provider, budgets),
        )
        .expect("stack activation")
    }

    fn active_stack_receipt(
        request: &paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentStackApplyRequestV1,
        runtime: &SigningKey,
        runtime_key: ApplyAuthKeyRef,
    ) -> ManagedAgentStackTerminalReceiptV1 {
        let state = ManagedAgentStackTerminalStateV1::try_new(
            ManagedAgentStackTerminalOutcomeV1::ActiveReady,
            ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
            ManagedAgentStackTerminalHeadV1::CommittedIncoming,
            Some(ManagedServiceGeneration::try_new(1).expect("Fabric generation")),
            Some(ManagedServiceGeneration::try_new(2).expect("Agent generation")),
        )
        .expect("active stack terminal state");
        let evidence = ManagedAgentStackTerminalEvidenceV1::try_new(
            ManagedAgentStackTerminalEvidenceFieldsV1 {
                physical_binding_census: 2,
                census_complete: true,
                fabric_ready: true,
                agent_ready: true,
                dependency_satisfied: true,
                exact_zero: false,
                quarantined: false,
                resource_census_digest: Digest32::from_bytes([0xa1; 32]),
                raw_outcome_digest: Digest32::from_bytes([0xa2; 32]),
                completion_runtime_host_epoch: 12,
                completion_snapshot_sequence: 13,
                selection_clock_generation: request.temporal().target_clock_generation(),
                selection_observed_at_nanos: 14,
            },
        )
        .expect("active stack evidence");
        let facts = ManagedAgentStackTerminalFactsV1::try_new(request, state, evidence)
            .expect("active stack facts");
        let channel = fabric_tests::channel();
        let auth = ManagedAgentStackTerminalAuthClaimV1::try_new(
            channel,
            runtime_key,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("Runtime stack auth");
        let draft = ManagedAgentStackTerminalReceiptDraftV1::try_new(request, facts, channel, auth)
            .expect("PXST draft");
        let signature = runtime.sign(
            draft
                .signing_transcript()
                .expect("PXST transcript")
                .as_bytes(),
        );
        draft.finalize(&signature.to_bytes()).expect("signed PXST")
    }

    fn empty_stack_receipt(
        request: &paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentStackApplyRequestV1,
        runtime: &SigningKey,
        runtime_key: ApplyAuthKeyRef,
    ) -> ManagedAgentStackTerminalReceiptV1 {
        let state = ManagedAgentStackTerminalStateV1::try_new(
            ManagedAgentStackTerminalOutcomeV1::EmptyExactZero,
            ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
            ManagedAgentStackTerminalHeadV1::CommittedIncoming,
            None,
            None,
        )
        .expect("empty stack terminal state");
        let evidence = ManagedAgentStackTerminalEvidenceV1::try_new(
            ManagedAgentStackTerminalEvidenceFieldsV1 {
                physical_binding_census: 0,
                census_complete: true,
                fabric_ready: false,
                agent_ready: false,
                dependency_satisfied: false,
                exact_zero: true,
                quarantined: false,
                resource_census_digest: Digest32::from_bytes([0xa3; 32]),
                raw_outcome_digest: Digest32::from_bytes([0xa4; 32]),
                completion_runtime_host_epoch: 15,
                completion_snapshot_sequence: 16,
                selection_clock_generation: request.temporal().target_clock_generation(),
                selection_observed_at_nanos: 17,
            },
        )
        .expect("empty stack evidence");
        let facts = ManagedAgentStackTerminalFactsV1::try_new(request, state, evidence)
            .expect("empty stack facts");
        let channel = fabric_tests::channel();
        let auth = ManagedAgentStackTerminalAuthClaimV1::try_new(
            channel,
            runtime_key,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("Runtime stack auth");
        let draft = ManagedAgentStackTerminalReceiptDraftV1::try_new(request, facts, channel, auth)
            .expect("empty PXST draft");
        let signature = runtime.sign(
            draft
                .signing_transcript()
                .expect("empty PXST transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("signed empty PXST")
    }

    #[test]
    fn pxar7_is_commit_before_send_and_pxst_replays_without_rewriting_pxar6() {
        let controller = fabric_tests::controller_signer();
        let runtime = fabric_tests::runtime_signer();
        let provisioning = fabric_tests::provisioning();
        let fabric = active_fabric_journal();
        let predecessor_pxar = fabric
            .state()
            .request()
            .expect("active PXAR6")
            .canonical_wire()
            .to_vec();
        let activation = activation(
            fabric.state(),
            deterministic_provider(),
            lifecycle_budgets([7, 11, 13, 17, 19]),
        );
        let mut journal = ManagedAgentStackApplyJournalV1::new(fabric.state().clone());
        let durable_prepare = RefCell::new(None);
        let prepared = journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                &activation,
                fresh(0x92),
                |next| {
                    *durable_prepare.borrow_mut() = Some(next.clone());
                    Ok(())
                },
            )
            .expect("durably prepare PXAR7");
        let prepared_state = durable_prepare
            .into_inner()
            .expect("PXAR7 crossed durable boundary");
        let stack = prepared_state.agent_stack_state().expect("stack state");
        assert_eq!(
            stack.phase(),
            ManagedAgentStackApplyPhaseV1::RequestDurableNotSent
        );
        assert_eq!(&stack.request().canonical_wire()[..6], b"PXAR\0\x07");
        assert_eq!(stack.request().temporal().original_budget().value(), 31);
        assert_eq!(
            prepared_state
                .request()
                .expect("retained PXAR6")
                .canonical_wire(),
            predecessor_pxar
        );
        let encoded = prepared_state.encode().expect("prepared PXFJ v3");
        let reopened = ManagedFabricControllerStateV1::decode(&encoded, &controller, &provisioning)
            .expect("reopen exact prepared stack");
        assert_eq!(reopened, prepared_state);
        journal = ManagedAgentStackApplyJournalV1::new(reopened);

        let durable_uncertain = RefCell::new(None);
        let action = journal
            .claim_send_with(prepared, &controller, &provisioning, |next| {
                *durable_uncertain.borrow_mut() = Some(next.clone());
                Ok(())
            })
            .expect("claim sole PXAR7 send");
        assert_eq!(&action.canonical_request_bytes()[..6], b"PXAR\0\x07");
        assert_eq!(action.channel(), fabric_tests::channel());
        assert_eq!(
            durable_uncertain
                .into_inner()
                .expect("uncertain fence durable")
                .agent_stack_state()
                .expect("stack state")
                .phase(),
            ManagedAgentStackApplyPhaseV1::Uncertain
        );

        let context = journal
            .state()
            .verified_current_context(&controller, &provisioning)
            .expect("current PXFB pin");
        let receipt =
            active_stack_receipt(action.request(), &runtime, context.runtime_response_key());
        let terminal = journal
            .consume_pxst_with(
                action,
                receipt.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            )
            .expect("commit exact PXST");
        assert!(!terminal.replayed_from_journal());
        let replay = journal
            .terminal(&controller, &provisioning)
            .expect("validate durable terminal")
            .expect("terminal exists");
        assert!(replay.replayed_from_journal());
        assert_eq!(replay.receipt(), terminal.receipt());
        assert_eq!(
            journal
                .state()
                .request()
                .expect("retained PXAR6")
                .canonical_wire(),
            predecessor_pxar
        );
        let encoded = journal.state().encode().expect("terminal PXFJ v3");
        let reopened = ManagedFabricControllerStateV1::decode(&encoded, &controller, &provisioning)
            .expect("reopen exact terminal stack");
        assert_eq!(&reopened, journal.state());
    }

    #[test]
    fn rejected_durability_does_not_install_or_authorize_stack_send() {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let fabric = active_fabric_journal();
        let initial = fabric.state().clone();
        let activation = activation(
            &initial,
            deterministic_provider(),
            lifecycle_budgets([1, 2, 3, 4, 5]),
        );
        let mut journal = ManagedAgentStackApplyJournalV1::new(initial.clone());
        let error = journal
            .prepare_activate_with(&controller, &provisioning, &activation, fresh(0x93), |_| {
                Err(ManagedAgentStackApplyControllerError::DurabilityRejected)
            })
            .expect_err("failed commit must fail closed");
        assert!(matches!(
            error,
            ManagedAgentStackApplyControllerError::DurabilityRejected
        ));
        assert_eq!(journal.state(), &initial);
        assert!(journal.state().agent_stack_state().is_none());
    }

    #[test]
    fn provider_is_always_explicit_and_fabric_replacement_is_rejected() {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let fabric = active_fabric_journal();
        let provisioned = activation(
            fabric.state(),
            provisioned_provider(),
            lifecycle_budgets([1, 2, 3, 4, 5]),
        );
        let mut journal = ManagedAgentStackApplyJournalV1::new(fabric.state().clone());
        journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                &provisioned,
                fresh(0x94),
                |_| Ok(()),
            )
            .expect("explicit provisioned provider accepted");
        let provider = journal
            .state()
            .agent_stack_state()
            .expect("stack state")
            .desired()
            .execution()
            .agent()
            .expect("Agent plan")
            .provider();
        assert_eq!(
            provider.profile(),
            ManagedAgentProviderProfileV1::Provisioned
        );
        assert!(provider.secret_ref().is_some());

        let fabric = active_fabric_journal();
        let current = fabric
            .state()
            .desired()
            .expect("active Fabric desired")
            .execution();
        let changed_fabric = ManagedFabricTargetExecutionV1::try_one_managed_fabric_service(
            current.projection().clone(),
            current.service().expect("Fabric service"),
            ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7557").expect("changed endpoint"),
        )
        .expect("independently valid changed Fabric");
        let changed = ManagedAgentStackActivationV1::try_new(
            changed_fabric,
            agent_plan(deterministic_provider(), lifecycle_budgets([1, 2, 3, 4, 5])),
        )
        .expect("requested stack shape");
        let mut journal = ManagedAgentStackApplyJournalV1::new(fabric.state().clone());
        let error = journal
            .prepare_activate_with(
                &controller,
                &provisioning,
                &changed,
                fresh(0x95),
                |_| Ok(()),
            )
            .expect_err("Fabric replacement requires exact zero first");
        assert!(matches!(
            error,
            ManagedAgentStackApplyControllerError::Producer(
                ManagedAgentStackProducerError::FabricChangeRequiresEmpty
            )
        ));
    }

    #[test]
    fn active_stack_archives_exactly_before_budgeted_empty_and_replays_exact_zero() {
        let controller = fabric_tests::controller_signer();
        let runtime = fabric_tests::runtime_signer();
        let provisioning = fabric_tests::provisioning();
        let fabric = active_fabric_journal();
        let activation = activation(
            fabric.state(),
            deterministic_provider(),
            lifecycle_budgets([7, 11, 13, 17, 19]),
        );
        let mut journal = ManagedAgentStackApplyJournalV1::new(fabric.state().clone());
        let prepared = journal
            .prepare_activate_with(&controller, &provisioning, &activation, fresh(0x97), |_| {
                Ok(())
            })
            .expect("prepare active stack");
        let action = journal
            .claim_send_with(prepared, &controller, &provisioning, |_| Ok(()))
            .expect("claim active stack send");
        let context = journal
            .state()
            .verified_current_context(&controller, &provisioning)
            .expect("current PXFB pin");
        let receipt =
            active_stack_receipt(action.request(), &runtime, context.runtime_response_key());
        journal
            .consume_pxst_with(
                action,
                receipt.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            )
            .expect("commit active stack");
        let active = journal
            .state()
            .agent_stack_state()
            .expect("active stack state");
        let active_execution = active.desired().execution().canonical_wire().to_vec();
        let active_request = active.request().canonical_wire().to_vec();
        let active_receipt = active
            .receipt()
            .expect("active PXST")
            .canonical_wire()
            .to_vec();
        let active_slice = active.request().target_slice_digest();

        let durable_empty = RefCell::new(None);
        let prepared = journal
            .prepare_empty_deactivate_with(&controller, &provisioning, fresh(0x98), |next| {
                *durable_empty.borrow_mut() = Some(next.clone());
                Ok(())
            })
            .expect("durably prepare exact-zero stack");
        let prepared_state = durable_empty
            .into_inner()
            .expect("empty PXAR7 crossed durable boundary");
        let empty = prepared_state
            .agent_stack_state()
            .expect("empty request state");
        assert_eq!(
            empty.desired().execution().mode(),
            ManagedAgentStackTargetModeV1::EmptyDeactivate
        );
        assert_eq!(
            empty
                .request()
                .control_commitment()
                .control()
                .expected_active(),
            ExpectedActive::Exact(active_slice)
        );
        assert_eq!(
            empty.request().temporal().original_budget().value(),
            9_000_000_036
        );
        let archived = empty.archived_active().expect("archived active stack");
        assert_eq!(
            archived.desired().execution().canonical_wire(),
            active_execution
        );
        assert_eq!(archived.request().canonical_wire(), active_request);
        assert_eq!(archived.receipt().canonical_wire(), active_receipt);
        let encoded = prepared_state.encode().expect("prepared empty PXFJ");
        let reopened = ManagedFabricControllerStateV1::decode(&encoded, &controller, &provisioning)
            .expect("reopen prepared empty stack");
        assert_eq!(reopened, prepared_state);
        journal = ManagedAgentStackApplyJournalV1::new(reopened);

        let action = journal
            .claim_send_with(prepared, &controller, &provisioning, |_| Ok(()))
            .expect("claim empty stack send");
        assert_eq!(&action.canonical_request_bytes()[..6], b"PXAR\0\x07");
        let receipt =
            empty_stack_receipt(action.request(), &runtime, context.runtime_response_key());
        let terminal = journal
            .consume_pxst_with(
                action,
                receipt.canonical_wire(),
                &controller,
                &provisioning,
                |_| Ok(()),
            )
            .expect("commit exact-zero PXST");
        assert_eq!(
            terminal.receipt().facts().state().outcome(),
            ManagedAgentStackTerminalOutcomeV1::EmptyExactZero
        );
        let replay = journal
            .terminal(&controller, &provisioning)
            .expect("validate empty terminal")
            .expect("empty terminal exists");
        assert!(replay.replayed_from_journal());
        assert_eq!(replay.receipt(), terminal.receipt());
        let encoded = journal.state().encode().expect("terminal empty PXFJ");
        let reopened = ManagedFabricControllerStateV1::decode(&encoded, &controller, &provisioning)
            .expect("reopen exact-zero terminal");
        assert_eq!(&reopened, journal.state());
        let error = journal
            .prepare_empty_deactivate_with(&controller, &provisioning, fresh(0x99), |_| Ok(()))
            .expect_err("terminal empty cannot be replayed as a send");
        assert!(matches!(
            error,
            ManagedAgentStackApplyControllerError::AlreadyTerminal
        ));
    }

    #[test]
    fn temporal_budget_checked_sum_accepts_three_maximal_activation_stages() {
        let controller = fabric_tests::controller_signer();
        let provisioning = fabric_tests::provisioning();
        let fabric = active_fabric_journal();
        let maximum = MAX_MANAGED_FABRIC_LIFECYCLE_NANOS;
        let activation = activation(
            fabric.state(),
            deterministic_provider(),
            lifecycle_budgets([maximum, maximum, maximum, maximum, maximum]),
        );
        let mut journal = ManagedAgentStackApplyJournalV1::new(fabric.state().clone());
        journal
            .prepare_activate_with(&controller, &provisioning, &activation, fresh(0x96), |_| {
                Ok(())
            })
            .expect("maximal signed activation budgets remain representable");
        let temporal = journal
            .state()
            .agent_stack_state()
            .expect("stack state")
            .request()
            .temporal();
        assert_eq!(temporal.original_budget().value(), maximum * 3);
        assert_eq!(temporal.remaining_budget().value(), maximum * 3);
    }
}
