//! Durable-boundary state machine for one managed-fabric activation.
//!
//! No transport send action exists until exact signed PXAR v6 and desired PXTE
//! v5 bytes cross the caller-owned durable commit boundary. The state then
//! enters `Uncertain` durably before exposing one move-only send action, so a
//! timeout, disconnect, cancellation, or process loss cannot authorize replay.

use core::fmt;
use core::future::Future;

use ed25519_dalek::Signature;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_runtime_contracts::apply::ExpectedActive;
use paraegox_runtime_contracts::managed_agent_stack_plan::{
    ManagedAgentStackTargetModeV1, ManagedAgentStackTerminalOutcomeV1,
};
use paraegox_runtime_contracts::managed_fabric_plan::{
    ManagedFabricApplyRequestV1, ManagedFabricApplyTerminalFactsV1,
    ManagedFabricApplyTerminalHeadV1, ManagedFabricApplyTerminalOutcomeV1,
    ManagedFabricApplyTerminalReceiptV1, ManagedFabricListenEndpointV1, ManagedFabricPlanError,
    ManagedFabricTargetModeV1,
};
use paraegox_runtime_contracts::managed_model_agent_stack_plan::ManagedModelAgentStackTargetModeV1;
use paraegox_runtime_contracts::managed_service::ManagedServiceSpecV1;
use paraegox_runtime_contracts::managed_serving_bootstrap::{
    ManagedServingBootstrapRequestV1, RuntimeAgentControlKindV1, RuntimeAgentControlReceiptV1,
    RuntimeAgentControlRequestV1, RuntimeControlCarrierRequestV1,
};
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;

use crate::controller_journal::{ControllerJournalError, ControllerJournalSnapshot};
use crate::managed_agent_stack_apply::{
    ManagedAgentStackApplyPhaseV1, ManagedAgentStackControllerStateV1,
    ManagedAgentStackDecodeContextV1,
};
use crate::managed_fabric_producer::{
    FreshManagedFabricApplyV1, ManagedFabricControllerProvisioningV1,
    ManagedFabricControllerRequestDraftV1, ManagedFabricDesiredPlanV1, ManagedFabricProducerError,
    ManagedFabricRemoteControllerProvisioningV1, VerifiedManagedFabricProducerContextV1,
};
use crate::managed_model_agent_stack_apply::{
    ManagedModelAgentStackControllerStateV1, ManagedModelAgentStackDecodeContextV1,
};
use crate::managed_serving_client::{
    FreshManagedServingBootstrapV1, FreshRuntimeAgentControlV1, ManagedServingBootstrapPhaseV1,
    ManagedServingBootstrapStateV1, ManagedServingControllerError, ManagedServingDescribeIngressV1,
    ManagedServingDescribeReconcileDecodeV1, ManagedServingDescribeReconcilePhaseV1,
    RuntimeAgentControlDurablePhaseV1, RuntimeAgentControlDurableSlotV1,
    RuntimeAgentControlMtlsExchangeSuccessV1, RuntimeManagedServingDescribeMtlsExchangeSuccessV1,
    RuntimeManagedServingDescribeTransportErrorV1, RuntimeManagedServingMtlsExchangeSuccessV1,
    RuntimeManagedServingTransportErrorV1, VerifiedManagedServingPinV1,
    VerifiedManagedServingReadyV1, VerifiedRuntimeManagedServingResponseV1,
};

const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;
const STATE_MAGIC: &[u8; 4] = b"PXFJ";
const LEGACY_STATE_VERSION: u16 = 2;
const LEGACY_STATE_FIXED_BYTES: usize = 100;
const AGENT_STACK_STATE_VERSION: u16 = 3;
const AGENT_STACK_STATE_FIXED_BYTES: usize = 104;
const MODEL_STACK_STATE_VERSION: u16 = 4;
const MODEL_STACK_STATE_FIXED_BYTES: usize = 108;
const REMOTE_CARRIER_STATE_VERSION: u16 = 5;
const REMOTE_CARRIER_STATE_FIXED_BYTES: usize = 112;
const MANAGED_READY_STATE_VERSION: u16 = 6;
const MANAGED_READY_STATE_FIXED_BYTES: usize = 121;
const STATE_VERSION: u16 = 7;
const STATE_FIXED_BYTES: usize = 148;
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
    fabric_agent_control: RuntimeAgentControlDurableSlotV1,
    agent_stack_agent_control: RuntimeAgentControlDurableSlotV1,
    conversation_port_descriptor: RuntimeAgentControlDurableSlotV1,
}

/// Exact active request triplet retained while the later empty request runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompletedManagedFabricApplyV1 {
    desired: ManagedFabricDesiredPlanV1,
    request: ManagedFabricApplyRequestV1,
    receipt: ManagedFabricApplyTerminalReceiptV1,
}

#[derive(Clone, Copy)]
enum ManagedFabricDecodeProvisioningV1<'a> {
    Local(&'a ManagedFabricControllerProvisioningV1),
    Remote {
        provisioning: &'a ManagedFabricRemoteControllerProvisioningV1,
        ingress: &'a ManagedServingDescribeIngressV1,
    },
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
            fabric_agent_control: RuntimeAgentControlDurableSlotV1::idle(),
            agent_stack_agent_control: RuntimeAgentControlDurableSlotV1::idle(),
            conversation_port_descriptor: RuntimeAgentControlDurableSlotV1::idle(),
        })
    }

    /// Initializes PXFJ only from the durable terminal of the single-target
    /// remote PXJR workflow. A verified PXDR alone is insufficient: the
    /// predecessor snapshot must also prove PXNA and the post-publish PXNS.
    pub(crate) fn try_from_remote_connector_cutover(
        cutover_marker_digest: Digest32,
        predecessor_snapshot: ControllerJournalSnapshot,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if digest_is_zero(cutover_marker_digest) || predecessor_snapshot.snapshot_sequence() == 0 {
            return Err(ManagedFabricApplyControllerError::InvalidCutoverState);
        }
        let facts = predecessor_snapshot
            .remote_connector_cutover_ready_facts()?
            .ok_or(ManagedFabricApplyControllerError::RemoteCutoverNotReady)?;
        if facts.successor_store_instance_id() == [0; 32]
            || facts.successor_store_instance_id() == *predecessor_snapshot.store_instance_id()
        {
            return Err(ManagedFabricApplyControllerError::InvalidCutoverState);
        }
        let encoded = predecessor_snapshot.encode()?;
        if ControllerJournalSnapshot::decode(&encoded)? != predecessor_snapshot {
            return Err(ManagedFabricApplyControllerError::InvalidCutoverState);
        }
        Ok(Self {
            sequence: 1,
            cutover_marker_digest,
            legacy_snapshot: predecessor_snapshot,
            phase: ManagedFabricApplyPhaseV1::CutoverReady,
            serving: ManagedServingBootstrapStateV1::initial(),
            desired: None,
            request: None,
            receipt: None,
            archived_active: None,
            agent_stack: None,
            model_stack: None,
            fabric_agent_control: RuntimeAgentControlDurableSlotV1::idle(),
            agent_stack_agent_control: RuntimeAgentControlDurableSlotV1::idle(),
            conversation_port_descriptor: RuntimeAgentControlDurableSlotV1::idle(),
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
    pub(crate) const fn serving_describe_reconcile_phase(
        &self,
    ) -> ManagedServingDescribeReconcilePhaseV1 {
        self.serving.describe_reconcile_phase()
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

    #[must_use]
    pub(crate) const fn fabric_agent_control(&self) -> &RuntimeAgentControlDurableSlotV1 {
        &self.fabric_agent_control
    }

    #[must_use]
    pub(crate) const fn agent_stack_agent_control(&self) -> &RuntimeAgentControlDurableSlotV1 {
        &self.agent_stack_agent_control
    }

    #[must_use]
    pub(crate) const fn conversation_port_descriptor(&self) -> &RuntimeAgentControlDurableSlotV1 {
        &self.conversation_port_descriptor
    }

    pub(crate) fn encode(&self) -> Result<Box<[u8]>, ManagedFabricApplyControllerError> {
        if self.agent_stack.is_some() && self.model_stack.is_some() {
            return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
        }
        let legacy = self.legacy_snapshot.encode()?;
        let serving_request = self.serving.request_wire();
        let serving_response = self.serving.response_wire();
        let serving_carrier_request = self.serving.carrier_request_wire();
        let serving_describe_request = self.serving.describe_request_wire();
        let serving_describe_response = self.serving.describe_response_wire();
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
        let fabric_agent_request = self.fabric_agent_control.request_wire();
        let fabric_agent_receipt = self.fabric_agent_control.receipt_wire();
        let agent_stack_agent_request = self.agent_stack_agent_control.request_wire();
        let agent_stack_agent_receipt = self.agent_stack_agent_control.receipt_wire();
        let descriptor_request = self.conversation_port_descriptor.request_wire();
        let descriptor_receipt = self.conversation_port_descriptor.receipt_wire();
        let legacy_length = u32::try_from(legacy.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let serving_request_length = u32::try_from(serving_request.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let serving_response_length = u32::try_from(serving_response.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let serving_carrier_request_length = u32::try_from(serving_carrier_request.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let serving_describe_request_length = u32::try_from(serving_describe_request.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let serving_describe_response_length = u32::try_from(serving_describe_response.len())
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
        let fabric_agent_request_length = u32::try_from(fabric_agent_request.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let fabric_agent_receipt_length = u32::try_from(fabric_agent_receipt.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let agent_stack_agent_request_length = u32::try_from(agent_stack_agent_request.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let agent_stack_agent_receipt_length = u32::try_from(agent_stack_agent_receipt.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let descriptor_request_length = u32::try_from(descriptor_request.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let descriptor_receipt_length = u32::try_from(descriptor_receipt.len())
            .map_err(|_| ManagedFabricApplyControllerError::StateTooLarge)?;
        let total = STATE_FIXED_BYTES
            .checked_add(legacy.len())
            .and_then(|value| value.checked_add(serving_request.len()))
            .and_then(|value| value.checked_add(serving_response.len()))
            .and_then(|value| value.checked_add(serving_carrier_request.len()))
            .and_then(|value| value.checked_add(execution.len()))
            .and_then(|value| value.checked_add(request.len()))
            .and_then(|value| value.checked_add(receipt.len()))
            .and_then(|value| value.checked_add(archived_execution.len()))
            .and_then(|value| value.checked_add(archived_request.len()))
            .and_then(|value| value.checked_add(archived_receipt.len()))
            .and_then(|value| value.checked_add(agent_stack.len()))
            .and_then(|value| value.checked_add(model_stack.len()))
            .and_then(|value| value.checked_add(serving_describe_request.len()))
            .and_then(|value| value.checked_add(serving_describe_response.len()))
            .and_then(|value| value.checked_add(fabric_agent_request.len()))
            .and_then(|value| value.checked_add(fabric_agent_receipt.len()))
            .and_then(|value| value.checked_add(agent_stack_agent_request.len()))
            .and_then(|value| value.checked_add(agent_stack_agent_receipt.len()))
            .and_then(|value| value.checked_add(descriptor_request.len()))
            .and_then(|value| value.checked_add(descriptor_receipt.len()))
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
        encoded.extend_from_slice(&serving_carrier_request_length.to_be_bytes());
        encoded.push(self.serving.describe_reconcile_phase().wire_value());
        encoded.extend_from_slice(&serving_describe_request_length.to_be_bytes());
        encoded.extend_from_slice(&serving_describe_response_length.to_be_bytes());
        encoded.push(self.fabric_agent_control.phase().wire_value());
        encoded.extend_from_slice(&fabric_agent_request_length.to_be_bytes());
        encoded.extend_from_slice(&fabric_agent_receipt_length.to_be_bytes());
        encoded.push(self.agent_stack_agent_control.phase().wire_value());
        encoded.extend_from_slice(&agent_stack_agent_request_length.to_be_bytes());
        encoded.extend_from_slice(&agent_stack_agent_receipt_length.to_be_bytes());
        encoded.push(self.conversation_port_descriptor.phase().wire_value());
        encoded.extend_from_slice(&descriptor_request_length.to_be_bytes());
        encoded.extend_from_slice(&descriptor_receipt_length.to_be_bytes());
        encoded.extend_from_slice(&legacy);
        encoded.extend_from_slice(serving_request);
        encoded.extend_from_slice(serving_response);
        encoded.extend_from_slice(serving_carrier_request);
        encoded.extend_from_slice(execution);
        encoded.extend_from_slice(request);
        encoded.extend_from_slice(receipt);
        encoded.extend_from_slice(archived_execution);
        encoded.extend_from_slice(archived_request);
        encoded.extend_from_slice(archived_receipt);
        encoded.extend_from_slice(&agent_stack);
        encoded.extend_from_slice(&model_stack);
        encoded.extend_from_slice(serving_describe_request);
        encoded.extend_from_slice(serving_describe_response);
        encoded.extend_from_slice(fabric_agent_request);
        encoded.extend_from_slice(fabric_agent_receipt);
        encoded.extend_from_slice(agent_stack_agent_request);
        encoded.extend_from_slice(agent_stack_agent_receipt);
        encoded.extend_from_slice(descriptor_request);
        encoded.extend_from_slice(descriptor_receipt);
        let checksum = state_checksum(&encoded)?;
        encoded.extend_from_slice(checksum.as_bytes());
        Ok(encoded.into_boxed_slice())
    }

    pub(crate) fn decode(
        frame: &[u8],
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        Self::decode_with_provisioning(
            frame,
            controller_signer,
            ManagedFabricDecodeProvisioningV1::Local(provisioning),
        )
    }

    pub(crate) fn decode_remote(
        frame: &[u8],
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        ingress: &ManagedServingDescribeIngressV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        Self::decode_with_provisioning(
            frame,
            controller_signer,
            ManagedFabricDecodeProvisioningV1::Remote {
                provisioning,
                ingress,
            },
        )
    }

    fn decode_with_provisioning(
        frame: &[u8],
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: ManagedFabricDecodeProvisioningV1<'_>,
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
            LEGACY_STATE_VERSION
                | AGENT_STACK_STATE_VERSION
                | MODEL_STACK_STATE_VERSION
                | REMOTE_CARRIER_STATE_VERSION
                | MANAGED_READY_STATE_VERSION
                | STATE_VERSION
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
        let (
            agent_stack_length,
            model_stack_length,
            serving_carrier_request_length,
            serving_describe_phase,
            serving_describe_request_length,
            serving_describe_response_length,
            prior_fixed_bytes,
        ) = match state_version {
            LEGACY_STATE_VERSION => (
                0,
                0,
                0,
                ManagedServingDescribeReconcilePhaseV1::Idle,
                0,
                0,
                LEGACY_STATE_FIXED_BYTES,
            ),
            AGENT_STACK_STATE_VERSION => (
                cursor.usize_u32()?,
                0,
                0,
                ManagedServingDescribeReconcilePhaseV1::Idle,
                0,
                0,
                AGENT_STACK_STATE_FIXED_BYTES,
            ),
            MODEL_STACK_STATE_VERSION => (
                cursor.usize_u32()?,
                cursor.usize_u32()?,
                0,
                ManagedServingDescribeReconcilePhaseV1::Idle,
                0,
                0,
                MODEL_STACK_STATE_FIXED_BYTES,
            ),
            REMOTE_CARRIER_STATE_VERSION => (
                cursor.usize_u32()?,
                cursor.usize_u32()?,
                cursor.usize_u32()?,
                ManagedServingDescribeReconcilePhaseV1::Idle,
                0,
                0,
                REMOTE_CARRIER_STATE_FIXED_BYTES,
            ),
            MANAGED_READY_STATE_VERSION | STATE_VERSION => (
                cursor.usize_u32()?,
                cursor.usize_u32()?,
                cursor.usize_u32()?,
                ManagedServingDescribeReconcilePhaseV1::try_from_wire(cursor.u8()?)?,
                cursor.usize_u32()?,
                cursor.usize_u32()?,
                MANAGED_READY_STATE_FIXED_BYTES,
            ),
            _ => return Err(ManagedFabricApplyControllerError::InvalidStateEncoding),
        };
        let (
            fabric_agent_phase,
            fabric_agent_request_length,
            fabric_agent_receipt_length,
            agent_stack_agent_phase,
            agent_stack_agent_request_length,
            agent_stack_agent_receipt_length,
            descriptor_phase,
            descriptor_request_length,
            descriptor_receipt_length,
            fixed_bytes,
        ) = if state_version == STATE_VERSION {
            (
                RuntimeAgentControlDurablePhaseV1::try_from_wire(cursor.u8()?)?,
                cursor.usize_u32()?,
                cursor.usize_u32()?,
                RuntimeAgentControlDurablePhaseV1::try_from_wire(cursor.u8()?)?,
                cursor.usize_u32()?,
                cursor.usize_u32()?,
                RuntimeAgentControlDurablePhaseV1::try_from_wire(cursor.u8()?)?,
                cursor.usize_u32()?,
                cursor.usize_u32()?,
                STATE_FIXED_BYTES,
            )
        } else {
            (
                RuntimeAgentControlDurablePhaseV1::Idle,
                0,
                0,
                RuntimeAgentControlDurablePhaseV1::Idle,
                0,
                0,
                RuntimeAgentControlDurablePhaseV1::Idle,
                0,
                0,
                prior_fixed_bytes,
            )
        };
        let variable_length = legacy_length
            .checked_add(serving_request_length)
            .and_then(|value| value.checked_add(serving_response_length))
            .and_then(|value| value.checked_add(serving_carrier_request_length))
            .and_then(|value| value.checked_add(execution_length))
            .and_then(|value| value.checked_add(request_length))
            .and_then(|value| value.checked_add(receipt_length))
            .and_then(|value| value.checked_add(archived_execution_length))
            .and_then(|value| value.checked_add(archived_request_length))
            .and_then(|value| value.checked_add(archived_receipt_length))
            .and_then(|value| value.checked_add(agent_stack_length))
            .and_then(|value| value.checked_add(model_stack_length))
            .and_then(|value| value.checked_add(serving_describe_request_length))
            .and_then(|value| value.checked_add(serving_describe_response_length))
            .and_then(|value| value.checked_add(fabric_agent_request_length))
            .and_then(|value| value.checked_add(fabric_agent_receipt_length))
            .and_then(|value| value.checked_add(agent_stack_agent_request_length))
            .and_then(|value| value.checked_add(agent_stack_agent_receipt_length))
            .and_then(|value| value.checked_add(descriptor_request_length))
            .and_then(|value| value.checked_add(descriptor_receipt_length))
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
        let serving_carrier_request = cursor.take(serving_carrier_request_length)?;
        let execution = cursor.take(execution_length)?;
        let request = cursor.take(request_length)?;
        let receipt = cursor.take(receipt_length)?;
        let archived_execution = cursor.take(archived_execution_length)?;
        let archived_request = cursor.take(archived_request_length)?;
        let archived_receipt = cursor.take(archived_receipt_length)?;
        let agent_stack = cursor.take(agent_stack_length)?;
        let model_stack = cursor.take(model_stack_length)?;
        let serving_describe_request = cursor.take(serving_describe_request_length)?;
        let serving_describe_response = cursor.take(serving_describe_response_length)?;
        let fabric_agent_request = cursor.take(fabric_agent_request_length)?;
        let fabric_agent_receipt = cursor.take(fabric_agent_receipt_length)?;
        let agent_stack_agent_request = cursor.take(agent_stack_agent_request_length)?;
        let agent_stack_agent_receipt = cursor.take(agent_stack_agent_receipt_length)?;
        let descriptor_request = cursor.take(descriptor_request_length)?;
        let descriptor_receipt = cursor.take(descriptor_receipt_length)?;
        let checksum = Digest32::from_bytes(cursor.array::<32>()?);
        cursor.finish()?;
        if state_checksum(&frame[..frame.len() - STATE_CHECKSUM_BYTES])? != checksum {
            return Err(ManagedFabricApplyControllerError::StateChecksumMismatch);
        }
        let fabric_agent_control = RuntimeAgentControlDurableSlotV1::decode(
            fabric_agent_phase,
            fabric_agent_request,
            fabric_agent_receipt,
        )?;
        let agent_stack_agent_control = RuntimeAgentControlDurableSlotV1::decode(
            agent_stack_agent_phase,
            agent_stack_agent_request,
            agent_stack_agent_receipt,
        )?;
        let conversation_port_descriptor = RuntimeAgentControlDurableSlotV1::decode(
            descriptor_phase,
            descriptor_request,
            descriptor_receipt,
        )?;
        let legacy_snapshot = ControllerJournalSnapshot::decode(legacy)?;
        let base = match provisioning {
            ManagedFabricDecodeProvisioningV1::Local(_) => {
                Self::try_from_cutover(cutover_marker_digest, legacy_snapshot)?
            }
            ManagedFabricDecodeProvisioningV1::Remote { .. } => {
                Self::try_from_remote_connector_cutover(cutover_marker_digest, legacy_snapshot)?
            }
        };
        let (base_context, describe_verifier, previous_ingress) = match provisioning {
            ManagedFabricDecodeProvisioningV1::Local(provisioning) => (
                VerifiedManagedFabricProducerContextV1::try_from_provisioning(
                    base.legacy_snapshot.state(),
                    controller_signer,
                    provisioning,
                )?,
                None,
                None,
            ),
            ManagedFabricDecodeProvisioningV1::Remote {
                provisioning,
                ingress,
            } => (
                VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
                    base.legacy_snapshot.state(),
                    controller_signer,
                    provisioning,
                    ingress,
                )?,
                Some(provisioning.describe()),
                Some(ingress),
            ),
        };
        let serving = ManagedServingBootstrapStateV1::decode_with_remote_reconcile(
            serving_phase,
            serving_request,
            serving_response,
            serving_carrier_request,
            &base_context,
            describe_verifier,
            ManagedServingDescribeReconcileDecodeV1 {
                phase: serving_describe_phase,
                request_wire: serving_describe_request,
                response_wire: serving_describe_response,
                previous: previous_ingress,
            },
        )?;
        let has_runtime_agent_control = fabric_agent_control.phase()
            != RuntimeAgentControlDurablePhaseV1::Idle
            || agent_stack_agent_control.phase() != RuntimeAgentControlDurablePhaseV1::Idle
            || conversation_port_descriptor.phase() != RuntimeAgentControlDurablePhaseV1::Idle;
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
                || has_runtime_agent_control
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
                fabric_agent_control,
                agent_stack_agent_control,
                conversation_port_descriptor,
            });
        }
        if sequence < 2 || revision == 0 || execution.is_empty() || request.is_empty() {
            return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
        }
        let pinned_context = serving
            .verified_pin(&base_context)?
            .apply_context(&base_context)?;
        let (context, managed_ready) = if has_runtime_agent_control {
            let ManagedFabricDecodeProvisioningV1::Remote {
                provisioning,
                ingress,
            } = provisioning
            else {
                return Err(ManagedFabricApplyControllerError::InvalidStateEncoding);
            };
            let ready = serving.verified_managed_ready(provisioning.describe(), ingress)?;
            let current = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
                base.legacy_snapshot.state(),
                controller_signer,
                provisioning,
                ready.ingress(),
            )?;
            (current, Some(ready))
        } else {
            (pinned_context, None)
        };
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
        let state = Self {
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
            fabric_agent_control,
            agent_stack_agent_control,
            conversation_port_descriptor,
        };
        validate_runtime_agent_control_slots(
            &state,
            describe_verifier,
            managed_ready.as_ref(),
            &context,
        )?;
        Ok(state)
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
            || !self.runtime_agent_control_slots_idle()
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
            fabric_agent_control: self.fabric_agent_control.clone(),
            agent_stack_agent_control: self.agent_stack_agent_control.clone(),
            conversation_port_descriptor: self.conversation_port_descriptor.clone(),
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
            || !self.runtime_agent_control_slots_idle()
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
            fabric_agent_control: self.fabric_agent_control.clone(),
            agent_stack_agent_control: self.agent_stack_agent_control.clone(),
            conversation_port_descriptor: self.conversation_port_descriptor.clone(),
        })
    }

    fn try_claim_send(&self) -> Result<Self, ManagedFabricApplyControllerError> {
        if self.phase != ManagedFabricApplyPhaseV1::RequestDurableNotSent
            || self.desired.is_none()
            || self.request.is_none()
            || self.receipt.is_some()
            || !self.runtime_agent_control_slots_idle()
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
            || !self.runtime_agent_control_slots_idle()
        {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.phase = ManagedFabricApplyPhaseV1::ReceiptDurable;
        next.receipt = Some(receipt);
        Ok(next)
    }

    fn runtime_agent_control_slots_idle(&self) -> bool {
        self.fabric_agent_control.phase() == RuntimeAgentControlDurablePhaseV1::Idle
            && self.agent_stack_agent_control.phase() == RuntimeAgentControlDurablePhaseV1::Idle
            && self.conversation_port_descriptor.phase() == RuntimeAgentControlDurablePhaseV1::Idle
    }

    fn try_with_remote_fabric_prepared(
        &self,
        desired: ManagedFabricDesiredPlanV1,
        request: ManagedFabricApplyRequestV1,
        outer: RuntimeAgentControlRequestV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if outer.kind() != RuntimeAgentControlKindV1::ApplyManagedFabric
            || outer.managed_fabric_apply_request() != Some(&request)
        {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        let mut next = self.try_with_prepared_request(desired, request)?;
        next.fabric_agent_control = self.fabric_agent_control.try_prepare(outer)?;
        Ok(next)
    }

    fn try_claim_remote_fabric(&self) -> Result<Self, ManagedFabricApplyControllerError> {
        if self.phase != ManagedFabricApplyPhaseV1::RequestDurableNotSent
            || self.desired.is_none()
            || self.request.is_none()
            || self.receipt.is_some()
            || self.fabric_agent_control.phase()
                != RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
            || self.agent_stack_agent_control.phase() != RuntimeAgentControlDurablePhaseV1::Idle
            || self.conversation_port_descriptor.phase() != RuntimeAgentControlDurablePhaseV1::Idle
        {
            return Err(ManagedFabricApplyControllerError::OpaqueReplayForbidden);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.phase = ManagedFabricApplyPhaseV1::Uncertain;
        next.fabric_agent_control = self.fabric_agent_control.try_claim()?;
        Ok(next)
    }

    fn try_with_remote_fabric_terminal(
        &self,
        inner: ManagedFabricApplyTerminalReceiptV1,
        outer: RuntimeAgentControlReceiptV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if self.phase != ManagedFabricApplyPhaseV1::Uncertain
            || self.request.is_none()
            || self.receipt.is_some()
            || self.fabric_agent_control.phase() != RuntimeAgentControlDurablePhaseV1::Uncertain
            || outer.kind() != RuntimeAgentControlKindV1::ApplyManagedFabric
            || outer.managed_fabric_receipt() != Some(&inner)
        {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.phase = ManagedFabricApplyPhaseV1::ReceiptDurable;
        next.receipt = Some(inner);
        next.fabric_agent_control = self.fabric_agent_control.try_terminal(outer)?;
        Ok(next)
    }

    pub(crate) fn try_with_agent_stack_state(
        &self,
        agent_stack: ManagedAgentStackControllerStateV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if !self.runtime_agent_control_slots_idle() {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        self.try_with_agent_stack_state_inner(agent_stack)
    }

    fn try_with_agent_stack_state_inner(
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

    pub(crate) fn try_with_agent_stack_and_control(
        &self,
        agent_stack: ManagedAgentStackControllerStateV1,
        outer: RuntimeAgentControlDurableSlotV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if self.fabric_agent_control.phase() != RuntimeAgentControlDurablePhaseV1::ReceiptDurable
            || self.model_stack.is_some()
            || self.conversation_port_descriptor.phase() != RuntimeAgentControlDurablePhaseV1::Idle
            || !agent_control_slot_matches_stack(&outer, &agent_stack)
        {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        let valid_outer_transition = match self.agent_stack_agent_control.phase() {
            RuntimeAgentControlDurablePhaseV1::Idle => {
                outer.phase() == RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
            }
            RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent => {
                outer.phase() == RuntimeAgentControlDurablePhaseV1::Uncertain
                    && outer.request() == self.agent_stack_agent_control.request()
            }
            RuntimeAgentControlDurablePhaseV1::Uncertain => {
                outer.phase() == RuntimeAgentControlDurablePhaseV1::ReceiptDurable
                    && outer.request() == self.agent_stack_agent_control.request()
            }
            RuntimeAgentControlDurablePhaseV1::ReceiptDurable => false,
        };
        if !valid_outer_transition {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        let mut next = self.try_with_agent_stack_state_inner(agent_stack)?;
        next.agent_stack_agent_control = outer;
        Ok(next)
    }

    pub(crate) fn try_with_descriptor_control(
        &self,
        descriptor: RuntimeAgentControlDurableSlotV1,
    ) -> Result<Self, ManagedFabricApplyControllerError> {
        if self.fabric_agent_control.phase() != RuntimeAgentControlDurablePhaseV1::ReceiptDurable
            || self.agent_stack_agent_control.phase()
                != RuntimeAgentControlDurablePhaseV1::ReceiptDurable
            || self.model_stack.is_some()
        {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        let valid_transition = match self.conversation_port_descriptor.phase() {
            RuntimeAgentControlDurablePhaseV1::Idle => {
                descriptor.phase() == RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
            }
            RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent => {
                descriptor.phase() == RuntimeAgentControlDurablePhaseV1::Uncertain
                    && descriptor.request() == self.conversation_port_descriptor.request()
            }
            RuntimeAgentControlDurablePhaseV1::Uncertain => {
                descriptor.phase() == RuntimeAgentControlDurablePhaseV1::ReceiptDurable
                    && descriptor.request() == self.conversation_port_descriptor.request()
            }
            RuntimeAgentControlDurablePhaseV1::ReceiptDurable => false,
        };
        if !valid_transition {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        let mut next = self.clone();
        next.sequence = next_sequence(self.sequence)?;
        next.conversation_port_descriptor = descriptor;
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
            || !self.runtime_agent_control_slots_idle()
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

    pub(crate) fn verified_current_remote_context(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        ingress: &ManagedServingDescribeIngressV1,
    ) -> Result<VerifiedManagedFabricProducerContextV1, ManagedFabricApplyControllerError> {
        let base = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            self.legacy_snapshot.state(),
            controller_signer,
            provisioning,
            ingress,
        )?;
        Ok(self.serving.verified_pin(&base)?.apply_context(&base)?)
    }

    pub(crate) fn verified_current_remote_agent_context(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
    ) -> Result<
        (
            VerifiedManagedFabricProducerContextV1,
            VerifiedManagedServingReadyV1,
        ),
        ManagedFabricApplyControllerError,
    > {
        let ready = self
            .serving
            .verified_managed_ready(provisioning.describe(), previous)?;
        let context = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            self.legacy_snapshot.state(),
            controller_signer,
            provisioning,
            ready.ingress(),
        )?;
        Ok((context, ready))
    }

    pub(crate) fn revalidate_runtime_agent_control_slots(
        &self,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        ready: &VerifiedManagedServingReadyV1,
        context: &VerifiedManagedFabricProducerContextV1,
    ) -> Result<(), ManagedFabricApplyControllerError> {
        validate_runtime_agent_control_slots(
            self,
            Some(provisioning.describe()),
            Some(ready),
            context,
        )
    }
}

fn agent_control_slot_matches_stack(
    slot: &RuntimeAgentControlDurableSlotV1,
    stack: &ManagedAgentStackControllerStateV1,
) -> bool {
    let expected_phase = match stack.phase() {
        ManagedAgentStackApplyPhaseV1::RequestDurableNotSent => {
            RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
        }
        ManagedAgentStackApplyPhaseV1::Uncertain => RuntimeAgentControlDurablePhaseV1::Uncertain,
        ManagedAgentStackApplyPhaseV1::ReceiptDurable => {
            RuntimeAgentControlDurablePhaseV1::ReceiptDurable
        }
    };
    if slot.phase() != expected_phase {
        return false;
    }
    let Some(request) = slot.request() else {
        return false;
    };
    if request.kind() != RuntimeAgentControlKindV1::ApplyManagedAgentStack
        || request.managed_agent_stack_apply_request() != Some(stack.request())
    {
        return false;
    }
    match slot.phase() {
        RuntimeAgentControlDurablePhaseV1::ReceiptDurable => {
            slot.receipt()
                .and_then(RuntimeAgentControlReceiptV1::managed_agent_stack_receipt)
                == stack.receipt()
        }
        RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
        | RuntimeAgentControlDurablePhaseV1::Uncertain => {
            slot.receipt().is_none() && stack.receipt().is_none()
        }
        RuntimeAgentControlDurablePhaseV1::Idle => false,
    }
}

fn validate_runtime_agent_control_slots(
    state: &ManagedFabricControllerStateV1,
    verifier: Option<&crate::managed_serving_client::ManagedServingDescribeVerifierV1>,
    ready: Option<&VerifiedManagedServingReadyV1>,
    context: &VerifiedManagedFabricProducerContextV1,
) -> Result<(), ManagedFabricApplyControllerError> {
    if state.runtime_agent_control_slots_idle() {
        return Ok(());
    }
    let verifier = verifier.ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
    let ready = ready.ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;

    let fabric_request = state
        .fabric_agent_control
        .request()
        .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
    let inner_fabric_request = state
        .request
        .as_ref()
        .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
    let expected_fabric_phase = match state.phase {
        ManagedFabricApplyPhaseV1::RequestDurableNotSent => {
            RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
        }
        ManagedFabricApplyPhaseV1::Uncertain => RuntimeAgentControlDurablePhaseV1::Uncertain,
        ManagedFabricApplyPhaseV1::ReceiptDurable => {
            RuntimeAgentControlDurablePhaseV1::ReceiptDurable
        }
        ManagedFabricApplyPhaseV1::CutoverReady => {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
    };
    if state.fabric_agent_control.phase() != expected_fabric_phase
        || fabric_request.kind() != RuntimeAgentControlKindV1::ApplyManagedFabric
        || fabric_request.managed_fabric_apply_request() != Some(inner_fabric_request)
    {
        return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
    }
    verifier.revalidate_runtime_agent_control_request(
        ready,
        RuntimeAgentControlKindV1::ApplyManagedFabric,
        fabric_request,
    )?;
    if state.fabric_agent_control.phase() == RuntimeAgentControlDurablePhaseV1::ReceiptDurable {
        let outer = state
            .fabric_agent_control
            .receipt()
            .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
        if outer.managed_fabric_receipt() != state.receipt.as_ref() {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        verifier.revalidate_runtime_agent_apply_receipt(
            ready,
            fabric_request,
            context.channel(),
            outer,
        )?;
    }

    if state.agent_stack_agent_control.phase() != RuntimeAgentControlDurablePhaseV1::Idle {
        if state.fabric_agent_control.phase() != RuntimeAgentControlDurablePhaseV1::ReceiptDurable
            || state.receipt.as_ref().is_none_or(|receipt| {
                receipt.facts().outcome() != ManagedFabricApplyTerminalOutcomeV1::ActiveReady
                    || receipt.facts().generation().is_none()
            })
            || state.model_stack.is_some()
        {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        let stack = state
            .agent_stack
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
        if !agent_control_slot_matches_stack(&state.agent_stack_agent_control, stack) {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        let outer_request = state
            .agent_stack_agent_control
            .request()
            .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
        verifier.revalidate_runtime_agent_control_request(
            ready,
            RuntimeAgentControlKindV1::ApplyManagedAgentStack,
            outer_request,
        )?;
        if state.agent_stack_agent_control.phase()
            == RuntimeAgentControlDurablePhaseV1::ReceiptDurable
        {
            verifier.revalidate_runtime_agent_apply_receipt(
                ready,
                outer_request,
                context.channel(),
                state
                    .agent_stack_agent_control
                    .receipt()
                    .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?,
            )?;
        }
    }

    if state.conversation_port_descriptor.phase() != RuntimeAgentControlDurablePhaseV1::Idle {
        if state.agent_stack_agent_control.phase()
            != RuntimeAgentControlDurablePhaseV1::ReceiptDurable
            || state.model_stack.is_some()
        {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        let stack = state
            .agent_stack
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
        let stack_receipt = stack
            .receipt()
            .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
        if stack_receipt.facts().state().outcome()
            != ManagedAgentStackTerminalOutcomeV1::ActiveReady
        {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        let descriptor_request = state
            .conversation_port_descriptor
            .request()
            .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
        if descriptor_request.kind() != RuntimeAgentControlKindV1::DescribeConversationPort
            || descriptor_request.expected_active_pxst_digest() != stack_receipt.receipt_digest()
        {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        verifier.revalidate_runtime_agent_control_request(
            ready,
            RuntimeAgentControlKindV1::DescribeConversationPort,
            descriptor_request,
        )?;
        if state.conversation_port_descriptor.phase()
            == RuntimeAgentControlDurablePhaseV1::ReceiptDurable
        {
            let descriptor_receipt = state
                .conversation_port_descriptor
                .receipt()
                .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
            verifier.revalidate_runtime_agent_descriptor_receipt(
                ready,
                descriptor_request,
                descriptor_receipt,
            )?;
            if descriptor_receipt.conversation_port_descriptor().is_none()
                || descriptor_receipt.fabric_generation()
                    != state
                        .receipt
                        .as_ref()
                        .and_then(|receipt| receipt.facts().generation())
                || descriptor_receipt.agent_generation()
                    != stack_receipt.facts().state().agent_generation()
            {
                return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
            }
        }
    }
    Ok(())
}

/// Proof that PXAR bytes are durable but have never been exposed to transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedManagedFabricApplyV1 {
    state_sequence: u64,
    cutover_marker_digest: Digest32,
    request_digest: Digest32,
}

/// Proof that byte-identical inner PXAR v6 and outer PXAG bytes crossed one
/// PXFJ durable boundary and have never entered transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedManagedFabricAgentControlApplyV1 {
    state_sequence: u64,
    cutover_marker_digest: Digest32,
    inner_request_digest: Digest32,
    outer_request_digest: Digest32,
}

/// Sole move-only authority for one public Runtime Agent-control Fabric send.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricAgentControlSendActionV1 {
    state_sequence: u64,
    cutover_marker_digest: Digest32,
    request: RuntimeAgentControlRequestV1,
    channel: ReferenceChannelBindingV1,
}

impl ManagedFabricAgentControlSendActionV1 {
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
pub(crate) struct ManagedFabricAgentControlTerminalCommitV1 {
    state_sequence: u64,
    inner: ManagedFabricApplyTerminalReceiptV1,
    outer: RuntimeAgentControlReceiptV1,
    replayed_from_journal: bool,
}

impl ManagedFabricAgentControlTerminalCommitV1 {
    #[must_use]
    pub(crate) const fn inner(&self) -> &ManagedFabricApplyTerminalReceiptV1 {
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
    request_id: [u8; 16],
}

impl PreparedManagedServingBootstrapV1 {
    #[must_use]
    pub(crate) const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
}

/// Proof that one exact post-PXFB Describe PXCC is durable and unsent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedManagedServingDescribeV1 {
    state_sequence: u64,
    cutover_marker_digest: Digest32,
    request_digest: Digest32,
}

/// Move-only authorization for exactly one read-only post-PXFB Describe.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ManagedServingDescribeSendActionV1 {
    state_sequence: u64,
    cutover_marker_digest: Digest32,
    request: RuntimeControlCarrierRequestV1,
    remote_send_available: bool,
}

impl ManagedServingDescribeSendActionV1 {
    #[must_use]
    pub(crate) const fn request(&self) -> &RuntimeControlCarrierRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) fn canonical_request_bytes(&self) -> &[u8] {
        self.request.canonical_wire()
    }

    /// Spends this action across one `FnOnce` transport boundary. The spent
    /// action is returned so the journal can durably accept PXDR or close the
    /// attempt without ever recreating the same send authority.
    pub(crate) async fn exchange_remote_once<Exchange, ExchangeFuture>(
        self,
        exchange: Exchange,
    ) -> ManagedServingDescribeRemoteExchangeOutcomeV1
    where
        Exchange: FnOnce(Box<[u8]>) -> ExchangeFuture,
        ExchangeFuture: Future<
            Output = Result<
                RuntimeManagedServingDescribeMtlsExchangeSuccessV1,
                RuntimeManagedServingDescribeTransportErrorV1,
            >,
        >,
    {
        let mut action = self;
        let response = if action.remote_send_available {
            action.remote_send_available = false;
            exchange(action.request.canonical_wire().into())
                .await
                .map_err(ManagedServingControllerError::from)
        } else {
            Err(ManagedServingControllerError::ManagedReadyDescribeTransportAuthoritySpent)
        };
        ManagedServingDescribeRemoteExchangeOutcomeV1 { action, response }
    }
}

/// Result of one and only one post-PXFB Describe transport invocation.
#[derive(Debug)]
pub(crate) struct ManagedServingDescribeRemoteExchangeOutcomeV1 {
    action: ManagedServingDescribeSendActionV1,
    response:
        Result<RuntimeManagedServingDescribeMtlsExchangeSuccessV1, ManagedServingControllerError>,
}

impl ManagedServingDescribeRemoteExchangeOutcomeV1 {
    pub(crate) fn into_parts(
        self,
    ) -> (
        ManagedServingDescribeSendActionV1,
        Result<RuntimeManagedServingDescribeMtlsExchangeSuccessV1, ManagedServingControllerError>,
    ) {
        (self.action, self.response)
    }
}

/// Move-only authorization for one PXFB transport exchange.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ManagedServingBootstrapSendActionV1 {
    state_sequence: u64,
    cutover_marker_digest: Digest32,
    request: ManagedServingBootstrapRequestV1,
    carrier_request: Option<RuntimeControlCarrierRequestV1>,
    remote_send_available: bool,
}

impl ManagedServingBootstrapSendActionV1 {
    #[cfg(test)]
    pub(crate) fn from_contract_fixture(request: ManagedServingBootstrapRequestV1) -> Self {
        Self {
            state_sequence: 1,
            cutover_marker_digest: Digest32::from_bytes([0x7f; 32]),
            request,
            carrier_request: None,
            remote_send_available: false,
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

    #[must_use]
    pub(crate) const fn carrier_request(&self) -> Option<&RuntimeControlCarrierRequestV1> {
        self.carrier_request.as_ref()
    }

    /// Consumes the sole durable remote send authority and invokes exactly one
    /// transport closure with the persisted outer PXCC bytes. The action is
    /// returned on every path so its owner can commit PXFR or close uncertain.
    pub(crate) async fn exchange_remote_once<Exchange, ExchangeFuture>(
        self,
        verifier: &crate::managed_serving_client::ManagedServingDescribeVerifierV1,
        ingress: &ManagedServingDescribeIngressV1,
        context: &VerifiedManagedFabricProducerContextV1,
        exchange: Exchange,
    ) -> ManagedServingBootstrapRemoteExchangeOutcomeV1
    where
        Exchange: FnOnce(Box<[u8]>) -> ExchangeFuture,
        ExchangeFuture: Future<
            Output = Result<
                RuntimeManagedServingMtlsExchangeSuccessV1,
                RuntimeManagedServingTransportErrorV1,
            >,
        >,
    {
        let mut action = self;
        let response = if action.remote_send_available {
            action.remote_send_available = false;
            match action.carrier_request.as_ref() {
                Some(carrier_request) => match verifier.revalidate_managed_serving_carrier(
                    ingress,
                    context,
                    carrier_request,
                ) {
                    Ok(()) => match exchange(carrier_request.canonical_wire().into()).await {
                        Ok(transport) => verifier.try_accept_managed_serving_response(
                            ingress,
                            context,
                            carrier_request,
                            &transport,
                        ),
                        Err(error) => Err(error.into()),
                    },
                    Err(error) => Err(error),
                },
                None => Err(ManagedServingControllerError::ManagedServingCarrierRequestMismatch),
            }
        } else {
            Err(ManagedServingControllerError::ManagedServingTransportAuthoritySpent)
        };
        ManagedServingBootstrapRemoteExchangeOutcomeV1 { action, response }
    }
}

/// Result of one and only one remote PXCC/PXFR transport invocation.
#[derive(Debug)]
pub(crate) struct ManagedServingBootstrapRemoteExchangeOutcomeV1 {
    action: ManagedServingBootstrapSendActionV1,
    response: Result<VerifiedRuntimeManagedServingResponseV1, ManagedServingControllerError>,
}

impl ManagedServingBootstrapRemoteExchangeOutcomeV1 {
    pub(crate) fn into_parts(
        self,
    ) -> (
        ManagedServingBootstrapSendActionV1,
        Result<VerifiedRuntimeManagedServingResponseV1, ManagedServingControllerError>,
    ) {
        (self.action, self.response)
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

    /// Remote counterpart of `prepare_serving_bootstrap_with`. The inner PXFB
    /// is derived solely from the authenticated PXDR facts and is committed
    /// before any outer carrier or send authority exists.
    pub(crate) fn prepare_remote_serving_bootstrap_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        ingress: &ManagedServingDescribeIngressV1,
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
        self.state.serving.require_remote_prepare_ready()?;
        let base = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            self.state.legacy_snapshot.state(),
            controller_signer,
            provisioning,
            ingress,
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
            request_id: *request.request_id().as_bytes(),
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

    pub(crate) fn current_remote_serving_pin(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        ingress: &ManagedServingDescribeIngressV1,
    ) -> Result<VerifiedManagedServingPinV1, ManagedFabricApplyControllerError> {
        let base = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            self.state.legacy_snapshot.state(),
            controller_signer,
            provisioning,
            ingress,
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
            carrier_request: None,
            remote_send_available: false,
        })
    }

    /// Builds the outer PXCC from the already-durable inner PXFB, commits both
    /// the exact carrier and `AttemptInFlight`, then releases one move-only
    /// action. A restart can observe the bytes but cannot recreate this action.
    pub(crate) fn claim_remote_serving_bootstrap_with<Commit>(
        &mut self,
        prepared: PreparedManagedServingBootstrapV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        ingress: &ManagedServingDescribeIngressV1,
        carrier_fresh: FreshManagedServingBootstrapV1,
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
        let base = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            self.state.legacy_snapshot.state(),
            controller_signer,
            provisioning,
            ingress,
        )?;
        let carrier_request = provisioning
            .describe()
            .try_build_managed_serving_bootstrap_carrier(
                ingress,
                &base,
                carrier_fresh,
                controller_signer,
                request,
            )?;
        let (serving, request) = self
            .state
            .serving
            .try_claim_remote(provisioning.describe(), carrier_request.clone())?;
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        Ok(ManagedServingBootstrapSendActionV1 {
            state_sequence: self.state.sequence,
            cutover_marker_digest: self.state.cutover_marker_digest,
            request,
            carrier_request: Some(carrier_request),
            remote_send_available: true,
        })
    }

    /// Durably closes timeout/EOF/no-response without claiming a Runtime-side
    /// effect. The local UDS path may later start a fresh observation; the
    /// remote path remains blocked pending a fresh Describe reconciliation.
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

    /// Closes resident transport authority recovered in-flight after local
    /// process loss. It deliberately makes no claim about Runtime effect. A
    /// remote PXCC retained in this state prevents another PXFB until a fresh
    /// Describe reconciliation transition is explicitly admitted.
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

    /// Commits a PXFR that was already verified against the exact persisted
    /// outer PXCC, inner PXFB, TLS peer pins and Runtime response signature.
    pub(crate) fn consume_remote_serving_bootstrap_response_with<Commit>(
        &mut self,
        action: ManagedServingBootstrapSendActionV1,
        response: VerifiedRuntimeManagedServingResponseV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        ingress: &ManagedServingDescribeIngressV1,
        commit: Commit,
    ) -> Result<VerifiedManagedServingPinV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        self.validate_serving_action(&action)?;
        let carrier_request = action
            .carrier_request
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::ServingSendActionMismatch)?;
        if response.carrier_request_digest() != carrier_request.request_digest()
            || response.inner_request_digest() != action.request.request_digest()
        {
            return Err(ManagedFabricApplyControllerError::ServingResponseCorrelationMismatch);
        }
        let base = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            self.state.legacy_snapshot.state(),
            controller_signer,
            provisioning,
            ingress,
        )?;
        let (serving, pin) = self
            .state
            .serving
            .try_accept_response(&base, response.response().canonical_wire())?;
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        Ok(pin)
    }

    /// Builds and commits one exact fresh post-PXFB Describe PXCC before any
    /// transport authority exists. A closed prior Describe may be replaced
    /// only by another explicitly fresh read-only request.
    pub(crate) fn prepare_remote_managed_ready_describe_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        fresh: FreshManagedServingBootstrapV1,
        commit: Commit,
    ) -> Result<PreparedManagedServingDescribeV1, ManagedFabricApplyControllerError>
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
        let _ = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            self.state.legacy_snapshot.state(),
            controller_signer,
            provisioning,
            previous,
        )?;
        let serving = self.state.serving.try_prepare_managed_ready_describe(
            provisioning.describe(),
            previous,
            fresh,
            controller_signer,
        )?;
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        self.prepared_remote_managed_ready_describe()
    }

    pub(crate) fn prepared_remote_managed_ready_describe(
        &self,
    ) -> Result<PreparedManagedServingDescribeV1, ManagedFabricApplyControllerError> {
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || self.state.serving.describe_reconcile_phase()
                != ManagedServingDescribeReconcilePhaseV1::RequestDurable
        {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        let request = self
            .state
            .serving
            .describe_request()
            .ok_or(ManagedFabricApplyControllerError::InvalidStateEncoding)?;
        Ok(PreparedManagedServingDescribeV1 {
            state_sequence: self.state.sequence,
            cutover_marker_digest: self.state.cutover_marker_digest,
            request_digest: request.request_digest(),
        })
    }

    /// Commits the Describe `AttemptInFlight` fence before releasing its sole
    /// move-only `FnOnce` transport action.
    pub(crate) fn claim_remote_managed_ready_describe_with<Commit>(
        &mut self,
        prepared: PreparedManagedServingDescribeV1,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        commit: Commit,
    ) -> Result<ManagedServingDescribeSendActionV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        let request = self
            .state
            .serving
            .describe_request()
            .ok_or(ManagedFabricApplyControllerError::InvalidStateEncoding)?;
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || self.state.serving.describe_reconcile_phase()
                != ManagedServingDescribeReconcilePhaseV1::RequestDurable
            || prepared.state_sequence != self.state.sequence
            || prepared.cutover_marker_digest != self.state.cutover_marker_digest
            || prepared.request_digest != request.request_digest()
        {
            return Err(ManagedFabricApplyControllerError::PreparedServingDescribeTokenMismatch);
        }
        provisioning
            .describe()
            .revalidate_fresh_request(previous, request)?;
        let (serving, request) = self.state.serving.try_claim_managed_ready_describe()?;
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        Ok(ManagedServingDescribeSendActionV1 {
            state_sequence: self.state.sequence,
            cutover_marker_digest: self.state.cutover_marker_digest,
            request,
            remote_send_available: true,
        })
    }

    pub(crate) fn close_remote_managed_ready_describe_no_response_with<Commit>(
        &mut self,
        action: ManagedServingDescribeSendActionV1,
        commit: Commit,
    ) -> Result<(), ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        self.validate_serving_describe_action(&action)?;
        self.close_recovered_remote_managed_ready_describe_with(commit)
    }

    /// Restart recovery closes the resident in-flight authority without
    /// reconstructing its action. A later explicit prepare must use fresh
    /// Describe identity and never obtains authority for the old PXFB/PXCC.
    pub(crate) fn close_recovered_remote_managed_ready_describe_with<Commit>(
        &mut self,
        commit: Commit,
    ) -> Result<(), ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || self.state.serving.describe_reconcile_phase()
                != ManagedServingDescribeReconcilePhaseV1::AttemptInFlight
        {
            return Err(ManagedFabricApplyControllerError::InvalidPhase);
        }
        let serving = self
            .state
            .serving
            .try_close_managed_ready_describe_no_response()?;
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        Ok(())
    }

    /// Verifies pinned transport plus the exact current request and commits the
    /// correlated signed `ManagedReady` PXDR. Invalid or LegacyReady responses
    /// consume no state transition; the spent action must be durably closed.
    pub(crate) fn consume_remote_managed_ready_describe_response_with<Commit>(
        &mut self,
        action: ManagedServingDescribeSendActionV1,
        transport: RuntimeManagedServingDescribeMtlsExchangeSuccessV1,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        commit: Commit,
    ) -> Result<VerifiedManagedServingReadyV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        self.validate_serving_describe_action(&action)?;
        provisioning
            .describe()
            .revalidate_fresh_request(previous, &action.request)?;
        let (serving, ready) = self
            .state
            .serving
            .try_accept_managed_ready_describe_response(
                provisioning.describe(),
                previous,
                &transport,
            )?;
        if ready.ingress().request_wire() != action.request.canonical_wire() {
            return Err(
                ManagedFabricApplyControllerError::ServingDescribeResponseCorrelationMismatch,
            );
        }
        let mut next = self.state.clone();
        next.sequence = next_sequence(next.sequence)?;
        next.serving = serving;
        commit(&next)?;
        self.state = next;
        Ok(ready)
    }

    /// Strictly reconstructs Ready facts from the exact durable PXCC/PXDR and
    /// repeats all pin, signature, correlation, succession and phase checks.
    pub(crate) fn current_remote_managed_ready_facts(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
    ) -> Result<VerifiedManagedServingReadyV1, ManagedFabricApplyControllerError> {
        let _ = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            self.state.legacy_snapshot.state(),
            controller_signer,
            provisioning,
            previous,
        )?;
        Ok(self
            .state
            .serving
            .verified_managed_ready(provisioning.describe(), previous)?)
    }

    fn validate_serving_describe_action(
        &self,
        action: &ManagedServingDescribeSendActionV1,
    ) -> Result<(), ManagedFabricApplyControllerError> {
        let request = self
            .state
            .serving
            .describe_request()
            .ok_or(ManagedFabricApplyControllerError::InvalidStateEncoding)?;
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || self.state.serving.describe_reconcile_phase()
                != ManagedServingDescribeReconcilePhaseV1::AttemptInFlight
            || action.state_sequence != self.state.sequence
            || action.cutover_marker_digest != self.state.cutover_marker_digest
            || action.request != *request
            || action.remote_send_available
        {
            return Err(ManagedFabricApplyControllerError::ServingDescribeSendActionMismatch);
        }
        Ok(())
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
            || action.carrier_request.as_ref() != self.state.serving.carrier_request()
        {
            return Err(ManagedFabricApplyControllerError::ServingSendActionMismatch);
        }
        Ok(())
    }

    /// Atomically commits the independently signed inner PXAR v6 and outer
    /// PXAG before any public Runtime transport authority exists.
    pub(crate) fn prepare_remote_agent_control_activate_with<Commit>(
        &mut self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        service: ManagedServiceSpecV1,
        endpoint: ManagedFabricListenEndpointV1,
        inner_fresh: FreshManagedFabricApplyV1,
        outer_fresh: FreshRuntimeAgentControlV1,
        commit: Commit,
    ) -> Result<PreparedManagedFabricAgentControlApplyV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        if self.state.phase == ManagedFabricApplyPhaseV1::RequestDurableNotSent
            && self.state.fabric_agent_control.phase()
                == RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
        {
            let desired = self
                .state
                .desired
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
            return self.prepared_remote_agent_control(controller_signer, provisioning, previous);
        }
        if self.state.phase != ManagedFabricApplyPhaseV1::CutoverReady
            || !self.state.runtime_agent_control_slots_idle()
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
            inner_fresh,
            controller_signer,
        )?;
        let inner = draft.finalize(controller_signer)?;
        context.validate_stored_request(&desired, ExpectedActive::None, &inner)?;
        let outer = provisioning
            .describe()
            .try_build_managed_fabric_agent_control(
                &ready,
                &inner,
                outer_fresh,
                controller_signer,
            )?;
        let next = self
            .state
            .try_with_remote_fabric_prepared(desired, inner, outer)?;
        commit(&next)?;
        self.state = next;
        self.prepared_remote_agent_control(controller_signer, provisioning, previous)
    }

    /// Reconstructs only a prepared proof. No proof or action exists for an
    /// `Uncertain` snapshot.
    pub(crate) fn prepared_remote_agent_control(
        &self,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
    ) -> Result<PreparedManagedFabricAgentControlApplyV1, ManagedFabricApplyControllerError> {
        if self.state.phase != ManagedFabricApplyPhaseV1::RequestDurableNotSent
            || self.state.fabric_agent_control.phase()
                != RuntimeAgentControlDurablePhaseV1::RequestDurableNotSent
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
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        let desired = self
            .state
            .desired
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        let inner = self
            .state
            .request
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        context.validate_stored_request(desired, ExpectedActive::None, inner)?;
        let outer = self
            .state
            .fabric_agent_control
            .request()
            .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
        provisioning
            .describe()
            .revalidate_runtime_agent_control_request(
                &ready,
                RuntimeAgentControlKindV1::ApplyManagedFabric,
                outer,
            )?;
        if outer.managed_fabric_apply_request() != Some(inner) {
            return Err(ManagedFabricApplyControllerError::AgentControlMismatch);
        }
        Ok(PreparedManagedFabricAgentControlApplyV1 {
            state_sequence: self.state.sequence,
            cutover_marker_digest: self.state.cutover_marker_digest,
            inner_request_digest: inner.envelope_request_digest(),
            outer_request_digest: outer.request_digest(),
        })
    }

    /// Commits both inner and outer `Uncertain` fences before releasing one
    /// move-only PXAG send action.
    pub(crate) fn claim_remote_agent_control_send_with<Commit>(
        &mut self,
        prepared: PreparedManagedFabricAgentControlApplyV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        commit: Commit,
    ) -> Result<ManagedFabricAgentControlSendActionV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        let expected =
            self.prepared_remote_agent_control(controller_signer, provisioning, previous)?;
        if prepared != expected {
            return Err(ManagedFabricApplyControllerError::PreparedTokenMismatch);
        }
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        let request = self
            .state
            .fabric_agent_control
            .request()
            .cloned()
            .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
        provisioning
            .describe()
            .revalidate_runtime_agent_control_request(
                &ready,
                RuntimeAgentControlKindV1::ApplyManagedFabric,
                &request,
            )?;
        let next = self.state.try_claim_remote_fabric()?;
        commit(&next)?;
        self.state = next;
        Ok(ManagedFabricAgentControlSendActionV1 {
            state_sequence: self.state.sequence,
            cutover_marker_digest: self.state.cutover_marker_digest,
            request,
            channel: context.channel(),
        })
    }

    /// Verifies pinned transport, outer PXAH and independent inner PXFT, then
    /// commits both terminal values in one PXFJ transition.
    pub(crate) fn consume_remote_agent_control_pxah_with<Commit>(
        &mut self,
        action: ManagedFabricAgentControlSendActionV1,
        transport: RuntimeAgentControlMtlsExchangeSuccessV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricRemoteControllerProvisioningV1,
        previous: &ManagedServingDescribeIngressV1,
        commit: Commit,
    ) -> Result<ManagedFabricAgentControlTerminalCommitV1, ManagedFabricApplyControllerError>
    where
        Commit: FnOnce(
            &ManagedFabricControllerStateV1,
        ) -> Result<(), ManagedFabricApplyControllerError>,
    {
        if self.state.phase != ManagedFabricApplyPhaseV1::Uncertain
            || self.state.fabric_agent_control.phase()
                != RuntimeAgentControlDurablePhaseV1::Uncertain
            || action.state_sequence != self.state.sequence
            || action.cutover_marker_digest != self.state.cutover_marker_digest
            || self.state.fabric_agent_control.request() != Some(&action.request)
        {
            return Err(ManagedFabricApplyControllerError::SendActionMismatch);
        }
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        if action.channel != context.channel() {
            return Err(ManagedFabricApplyControllerError::SendActionMismatch);
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
            .managed_fabric_receipt()
            .cloned()
            .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?;
        let durable_inner = self
            .state
            .request
            .as_ref()
            .ok_or(ManagedFabricApplyControllerError::InvalidPhase)?;
        inner.validate_against_request(durable_inner, context.channel())?;
        verify_receipt_signature(&inner, &context)?;
        let next = self
            .state
            .try_with_remote_fabric_terminal(inner.clone(), outer.clone())?;
        commit(&next)?;
        self.state = next;
        Ok(ManagedFabricAgentControlTerminalCommitV1 {
            state_sequence: self.state.sequence,
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
    ) -> Result<Option<ManagedFabricAgentControlTerminalCommitV1>, ManagedFabricApplyControllerError>
    {
        if self.state.fabric_agent_control.phase()
            != RuntimeAgentControlDurablePhaseV1::ReceiptDurable
        {
            return Ok(None);
        }
        let (context, ready) = self.state.verified_current_remote_agent_context(
            controller_signer,
            provisioning,
            previous,
        )?;
        validate_runtime_agent_control_slots(
            &self.state,
            Some(provisioning.describe()),
            Some(&ready),
            &context,
        )?;
        Ok(Some(ManagedFabricAgentControlTerminalCommitV1 {
            state_sequence: self.state.sequence,
            inner: self
                .state
                .receipt
                .clone()
                .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?,
            outer: self
                .state
                .fabric_agent_control
                .receipt()
                .cloned()
                .ok_or(ManagedFabricApplyControllerError::AgentControlMismatch)?,
            replayed_from_journal: true,
        }))
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
    RemoteCutoverNotReady,
    InvalidPhase,
    SequenceExhausted,
    DesiredConflict,
    DurabilityRejected,
    PreparedTokenMismatch,
    PreparedServingTokenMismatch,
    PreparedServingDescribeTokenMismatch,
    SendActionMismatch,
    ServingSendActionMismatch,
    ServingResponseCorrelationMismatch,
    ServingDescribeSendActionMismatch,
    ServingDescribeResponseCorrelationMismatch,
    ServingRefreshForbidden,
    OpaqueReplayForbidden,
    AgentControlMismatch,
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
    use paraegox_runtime_contracts::distributed_agent_stack_plan::{
        RestrictedRuntimeApplyCarrierBindingFieldsV1, RestrictedRuntimeApplyCarrierBindingV1,
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
        ManagedServingBootstrapFactsV1, ManagedServingBootstrapRequestDraftV1,
        ManagedServingBootstrapRequestIdV1, ManagedServingBootstrapResponseAuthClaimV1,
        ManagedServingBootstrapResponseDraftV1, RuntimeControlDescribeReadyFactsV1,
        RuntimeControlDescribeReadyPhaseV1, RuntimeControlDescribeReadyResponseDraftV1,
        RuntimeControlDescribeReadyResponseV1,
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
        AGENT_STACK_STATE_FIXED_BYTES, AGENT_STACK_STATE_VERSION, LEGACY_STATE_FIXED_BYTES,
        LEGACY_STATE_VERSION, MANAGED_READY_STATE_FIXED_BYTES, MANAGED_READY_STATE_VERSION,
        MODEL_STACK_STATE_FIXED_BYTES, MODEL_STACK_STATE_VERSION,
        ManagedFabricApplyControllerError, ManagedFabricApplyJournalV1, ManagedFabricApplyPhaseV1,
        ManagedFabricControllerStateV1, ManagedServingDescribeSendActionV1,
        REMOTE_CARRIER_STATE_FIXED_BYTES, REMOTE_CARRIER_STATE_VERSION, STATE_CHECKSUM_BYTES,
        STATE_FIXED_BYTES, STATE_VERSION, state_checksum,
    };
    use crate::managed_fabric_producer::{
        FreshManagedFabricApplyV1, ManagedFabricControllerIdentityV1,
        ManagedFabricControllerProvisioningV1, ManagedFabricProducerError,
        ManagedFabricRemoteControllerProvisioningV1, ManagedFabricRuntimeChannelPinV1,
        ManagedFabricServiceAccountsV1, ManagedFabricTenureAuthorityPinV1,
        VerifiedManagedFabricProducerContextV1,
    };
    use crate::managed_serving_client::{
        FreshManagedServingBootstrapV1, ManagedServingBootstrapStateV1,
        ManagedServingControllerError, ManagedServingDescribeIngressV1,
        ManagedServingDescribeReconcileDecodeV1, ManagedServingDescribeReconcilePhaseV1,
        ManagedServingDescribeVerifierV1, RuntimeManagedServingDescribeMtlsExchangeSuccessV1,
        RuntimeManagedServingDescribeTransportErrorV1, RuntimeManagedServingMtlsExchangeSuccessV1,
        RuntimeManagedServingTransportErrorV1,
    };

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

    fn managed_controller_identity() -> ManagedFabricControllerIdentityV1 {
        ManagedFabricControllerIdentityV1::try_new(CONTROLLER_PRINCIPAL, WRITER)
            .expect("controller identity")
    }

    fn managed_authority_pin() -> ManagedFabricTenureAuthorityPinV1 {
        ManagedFabricTenureAuthorityPinV1::try_new(
            AUTHORITY_PRINCIPAL,
            AUTHORITY_UID,
            AUTHORITY_GID,
            TENURE_AUTHORITY_REF,
            TENURE_KEY_REF,
            SigningKey::from_bytes(&AUTHORITY_SEED)
                .verifying_key()
                .to_bytes(),
        )
        .expect("authority pin")
    }

    pub(crate) fn provisioning() -> ManagedFabricControllerProvisioningV1 {
        let controller = managed_controller_identity();
        let authority = managed_authority_pin();
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

    fn remote_provisioning_and_ingress() -> (
        ManagedFabricRemoteControllerProvisioningV1,
        ManagedServingDescribeIngressV1,
    ) {
        remote_provisioning_and_ingress_with_phase(RuntimeControlDescribeReadyPhaseV1::LegacyReady)
    }

    fn remote_provisioning_and_ingress_with_phase(
        phase: RuntimeControlDescribeReadyPhaseV1,
    ) -> (
        ManagedFabricRemoteControllerProvisioningV1,
        ManagedServingDescribeIngressV1,
    ) {
        let snapshot = ready_snapshot();
        let controller = controller_signer();
        let runtime = runtime_signer();
        let projection =
            paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricManifestProjectionV1::
                try_from_verified_legacy_manifest(
                    snapshot.state().installed_manifest().verified_manifest(),
                )
                .expect("managed projection");
        let carrier = RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: TARGET,
                runtime_principal: RUNTIME_PRINCIPAL,
                controller_principal: CONTROLLER_PRINCIPAL,
                endpoint_ref: [0x81; 16],
                endpoint_generation: 1,
                route: "paraegox/runtime-fixture/apply",
                controller_request_key: CONTROLLER_KEY_REF,
                controller_request_key_fingerprint: ed25519_control_key_fingerprint(
                    controller.verifying_key().as_bytes(),
                )
                .expect("Controller fingerprint"),
                runtime_response_key: RUNTIME_KEY_REF,
                runtime_response_key_fingerprint: ed25519_control_key_fingerprint(
                    runtime.verifying_key().as_bytes(),
                )
                .expect("Runtime fingerprint"),
                control_transport_profile_ref: [0x82; 16],
                control_transport_profile_digest: Digest32::from_bytes([0x83; 32]),
            },
        )
        .expect("remote carrier");
        let verifier = ManagedServingDescribeVerifierV1::try_new(
            TARGET,
            carrier,
            controller.verifying_key().to_bytes(),
            runtime.verifying_key().to_bytes(),
            snapshot.state().installed_manifest().manifest_digest(),
        )
        .expect("Describe verifier");
        let request = verifier
            .try_build_request(
                None,
                FreshManagedServingBootstrapV1::try_new([0x84; 16], [0x85; 32])
                    .expect("fresh Describe"),
                &controller,
            )
            .expect("Describe request");
        let serving = ManagedServingBootstrapFactsV1::try_recovered_ready(
            TARGET,
            RUNTIME_STORE_ID,
            projection,
            2,
            1,
            ClockReading::new(
                CLOCK_DOMAIN,
                ClockGeneration::try_new(3).expect("Describe clock generation"),
                MonotonicInstant::from_ticks(91),
            ),
        )
        .expect("Describe serving facts");
        let ready = RuntimeControlDescribeReadyFactsV1::try_new(phase, serving, channel())
            .expect("Describe ready facts");
        let auth = ManagedServingBootstrapResponseAuthClaimV1::try_new(
            channel(),
            RUNTIME_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("Describe response claim");
        let draft = RuntimeControlDescribeReadyResponseDraftV1::try_new(&request, ready, auth)
            .expect("Describe response draft");
        let signature = runtime.sign(
            draft
                .signing_transcript()
                .expect("Describe response transcript")
                .as_bytes(),
        );
        let response = draft
            .finalize(&signature.to_bytes())
            .expect("Describe response");
        let ingress = ManagedServingDescribeIngressV1::try_accept(
            &verifier,
            None,
            request,
            response.canonical_wire(),
        )
        .expect("Describe ingress");
        (
            ManagedFabricRemoteControllerProvisioningV1::new(
                managed_controller_identity(),
                managed_authority_pin(),
                verifier,
            ),
            ingress,
        )
    }

    fn post_bootstrap_describe_response(
        request: &paraegox_runtime_contracts::managed_serving_bootstrap::RuntimeControlCarrierRequestV1,
        phase: RuntimeControlDescribeReadyPhaseV1,
        snapshot_sequence: u64,
    ) -> RuntimeControlDescribeReadyResponseV1 {
        let snapshot = ready_snapshot();
        let projection =
            paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricManifestProjectionV1::
                try_from_verified_legacy_manifest(
                    snapshot.state().installed_manifest().verified_manifest(),
                )
                .expect("managed projection");
        let serving = ManagedServingBootstrapFactsV1::try_recovered_ready(
            TARGET,
            RUNTIME_STORE_ID,
            projection,
            12,
            snapshot_sequence,
            ClockReading::new(
                CLOCK_DOMAIN,
                ClockGeneration::try_new(3).expect("Describe clock generation"),
                MonotonicInstant::from_ticks(91 + snapshot_sequence),
            ),
        )
        .expect("post-bootstrap serving facts");
        let ready = RuntimeControlDescribeReadyFactsV1::try_new(phase, serving, channel())
            .expect("post-bootstrap Describe facts");
        let auth = ManagedServingBootstrapResponseAuthClaimV1::try_new(
            channel(),
            RUNTIME_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("Describe response claim");
        let draft = RuntimeControlDescribeReadyResponseDraftV1::try_new(request, ready, auth)
            .expect("Describe response draft");
        let signature = runtime_signer().sign(
            draft
                .signing_transcript()
                .expect("Describe response transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("Describe response")
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
        assert_eq!(
            u32::from_be_bytes(frame[108..112].try_into().expect("carrier length")),
            0
        );
        assert_eq!(
            frame[112],
            ManagedServingDescribeReconcilePhaseV1::Idle.wire_value()
        );
        assert_eq!(
            u32::from_be_bytes(frame[113..117].try_into().expect("Describe request length")),
            0
        );
        assert_eq!(
            u32::from_be_bytes(
                frame[117..121]
                    .try_into()
                    .expect("Describe response length")
            ),
            0
        );
        for (phase_offset, request_length_offset, receipt_length_offset) in
            [(121, 122, 126), (130, 131, 135), (139, 140, 144)]
        {
            assert_eq!(
                frame[phase_offset],
                RuntimeAgentControlDurablePhaseV1::Idle.wire_value()
            );
            assert_eq!(
                u32::from_be_bytes(
                    frame[request_length_offset..request_length_offset + 4]
                        .try_into()
                        .expect("PXAG length")
                ),
                0
            );
            assert_eq!(
                u32::from_be_bytes(
                    frame[receipt_length_offset..receipt_length_offset + 4]
                        .try_into()
                        .expect("PXAH length")
                ),
                0
            );
        }
        let mut body = frame[..frame.len() - STATE_CHECKSUM_BYTES].to_vec();
        body.drain(MANAGED_READY_STATE_FIXED_BYTES..STATE_FIXED_BYTES);
        match version {
            LEGACY_STATE_VERSION => {
                body.drain(LEGACY_STATE_FIXED_BYTES..MANAGED_READY_STATE_FIXED_BYTES);
            }
            AGENT_STACK_STATE_VERSION => {
                body.drain(AGENT_STACK_STATE_FIXED_BYTES..MANAGED_READY_STATE_FIXED_BYTES);
            }
            MODEL_STACK_STATE_VERSION => {
                body.drain(MODEL_STACK_STATE_FIXED_BYTES..MANAGED_READY_STATE_FIXED_BYTES);
            }
            REMOTE_CARRIER_STATE_VERSION => {
                body.drain(REMOTE_CARRIER_STATE_FIXED_BYTES..MANAGED_READY_STATE_FIXED_BYTES);
            }
            MANAGED_READY_STATE_VERSION => {}
            _ => panic!("unsupported downgrade fixture version"),
        }
        body[4..6].copy_from_slice(&version.to_be_bytes());
        let checksum = state_checksum(&body).expect("legacy fixture checksum");
        body.extend_from_slice(checksum.as_bytes());
        body.into_boxed_slice()
    }

    #[test]
    fn pxfj_v7_roundtrips_and_strictly_reopens_v2_through_v6_with_idle_agent_control_slots() {
        let controller = controller_signer();
        let provisioning = provisioning();
        let journal = journal();
        let encoded = journal.state().encode().expect("PXFJ v7 state");
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), STATE_VERSION);
        let decoded = ManagedFabricControllerStateV1::decode(&encoded, &controller, &provisioning)
            .expect("PXFJ v7 reopens");
        assert_eq!(&decoded, journal.state());

        for version in [
            LEGACY_STATE_VERSION,
            AGENT_STACK_STATE_VERSION,
            MODEL_STACK_STATE_VERSION,
            REMOTE_CARRIER_STATE_VERSION,
            MANAGED_READY_STATE_VERSION,
        ] {
            let legacy = downgrade_pxfj_without_siblings(&encoded, version);
            let decoded =
                ManagedFabricControllerStateV1::decode(&legacy, &controller, &provisioning)
                    .expect("legacy PXFJ reopens");
            assert_eq!(&decoded, journal.state());
            let migrated = decoded.encode().expect("legacy state migrates on write");
            assert_eq!(
                u16::from_be_bytes([migrated[4], migrated[5]]),
                STATE_VERSION,
                "migration-on-write must emit only PXFJ v7"
            );
        }
    }

    #[test]
    fn remote_cutover_rejects_a_predecessor_without_px_j_r_terminal_facts() {
        assert_eq!(
            ManagedFabricControllerStateV1::try_from_remote_connector_cutover(
                Digest32::from_bytes([0xd7; 32]),
                ready_snapshot(),
            ),
            Err(ManagedFabricApplyControllerError::RemoteCutoverNotReady)
        );
    }

    #[test]
    fn managed_ready_px_d_r_requires_a_fresh_px_f_b_and_never_synthesizes_px_f_r() {
        let controller = controller_signer();
        let (remote, ingress) = remote_provisioning_and_ingress_with_phase(
            RuntimeControlDescribeReadyPhaseV1::ManagedReady,
        );
        let mut journal = ManagedFabricApplyJournalV1::new(
            ManagedFabricControllerStateV1::try_from_cutover(
                Digest32::from_bytes([0xda; 32]),
                ready_snapshot(),
            )
            .expect("cutover state"),
        );
        assert_eq!(
            journal.current_remote_serving_pin(&controller, &remote, &ingress),
            Err(ManagedFabricApplyControllerError::Serving(
                ManagedServingControllerError::ServingPinRequired
            ))
        );
        let prepared = journal
            .prepare_remote_serving_bootstrap_with(
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xdb; 16], [0xdc; 32])
                    .expect("fresh inner PXFB"),
                |_| Ok(()),
            )
            .expect("fresh ManagedReady Describe may authorize a new idempotent PXFB");
        let action = journal
            .claim_remote_serving_bootstrap_with(
                prepared,
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xdb; 16], [0xde; 32])
                    .expect("fresh outer PXCC"),
                |_| Ok(()),
            )
            .expect("new PXFB/PXCC attempt");
        assert!(action.carrier_request().is_some());
        assert_eq!(
            journal.current_remote_serving_pin(&controller, &remote, &ingress),
            Err(ManagedFabricApplyControllerError::Serving(
                ManagedServingControllerError::ServingPinRequired
            ))
        );
    }

    #[test]
    fn remote_producer_context_rejects_manifest_and_tenure_pin_drift() {
        let snapshot = ready_snapshot();
        let controller = controller_signer();
        let runtime = runtime_signer();
        let (remote, ingress) = remote_provisioning_and_ingress();
        VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            snapshot.state(),
            &controller,
            &remote,
            &ingress,
        )
        .expect("matching remote context");

        let wrong_authority = ManagedFabricTenureAuthorityPinV1::try_new(
            AUTHORITY_PRINCIPAL,
            AUTHORITY_UID,
            AUTHORITY_GID,
            TENURE_AUTHORITY_REF,
            TENURE_KEY_REF,
            SigningKey::from_bytes(&[0xd8; 32])
                .verifying_key()
                .to_bytes(),
        )
        .expect("well-shaped wrong authority pin");
        let wrong_tenure = ManagedFabricRemoteControllerProvisioningV1::new(
            managed_controller_identity(),
            wrong_authority,
            remote.describe().clone(),
        );
        assert_eq!(
            VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
                snapshot.state(),
                &controller,
                &wrong_tenure,
                &ingress,
            ),
            Err(ManagedFabricProducerError::InvalidTenureAuthority)
        );

        let wrong_manifest_verifier = ManagedServingDescribeVerifierV1::try_new(
            TARGET,
            remote.describe().carrier().clone(),
            controller.verifying_key().to_bytes(),
            runtime.verifying_key().to_bytes(),
            Digest32::from_bytes([0xd9; 32]),
        )
        .expect("well-shaped wrong manifest pin");
        let wrong_manifest = ManagedFabricRemoteControllerProvisioningV1::new(
            managed_controller_identity(),
            managed_authority_pin(),
            wrong_manifest_verifier,
        );
        assert_eq!(
            VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
                snapshot.state(),
                &controller,
                &wrong_manifest,
                &ingress,
            ),
            Err(ManagedFabricProducerError::RemoteDescribeMismatch)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remote_px_f_r_terminal_durably_reconciles_one_fresh_managed_ready_describe() {
        let controller = controller_signer();
        let (remote, ingress) = remote_provisioning_and_ingress();
        let mut journal = ManagedFabricApplyJournalV1::new(
            ManagedFabricControllerStateV1::try_from_cutover(
                Digest32::from_bytes([0x91; 32]),
                ready_snapshot(),
            )
            .expect("cutover state"),
        );
        let prepared = journal
            .prepare_remote_serving_bootstrap_with(
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0x92; 16], [0x93; 32])
                    .expect("fresh inner PXFB"),
                |_| Ok(()),
            )
            .expect("inner PXFB durable");
        assert_eq!(prepared.request_id(), [0x92; 16]);
        let action = journal
            .claim_remote_serving_bootstrap_with(
                prepared,
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0x92; 16], [0x95; 32])
                    .expect("fresh outer PXCC"),
                |_| Ok(()),
            )
            .expect("outer PXCC durable before action");
        let outer = action
            .carrier_request()
            .expect("remote action retains outer PXCC")
            .clone();
        assert_eq!(outer.request_id(), action.request().request_id());
        assert_ne!(
            outer.authentication().claim().nonce(),
            action.request().authentication().claim().nonce(),
        );
        assert_eq!(
            outer.managed_serving_bootstrap_request(),
            Some(action.request()),
            "PXCC must embed the byte-identical durable PXFB"
        );
        assert_eq!(
            outer
                .managed_serving_bootstrap_request()
                .expect("PXCC inner PXFB")
                .canonical_wire(),
            action.canonical_request_bytes(),
        );
        assert_eq!(
            journal.state().serving.carrier_request_wire(),
            outer.canonical_wire(),
            "PXFJ must retain the exact signed outer PXCC"
        );
        let encoded = journal.state().encode().expect("PXFJ v6 encodes");
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), STATE_VERSION);
        assert!(
            encoded
                .windows(outer.canonical_wire().len())
                .any(|window| window == outer.canonical_wire())
        );
        let context = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            journal.state().legacy_snapshot().state(),
            &controller,
            &remote,
            &ingress,
        )
        .expect("remote producer context");
        let response = current_serving_response(action.request());
        let expected_outer = outer.canonical_wire().to_vec();
        let wrong_transport = RuntimeManagedServingMtlsExchangeSuccessV1::try_new(
            PrincipalRef::from_bytes([0xee; 16]),
            remote.describe().carrier().binding_digest(),
            response.canonical_wire().into(),
        )
        .expect("well-shaped wrong TLS observation");
        assert_eq!(
            remote.describe().try_accept_managed_serving_response(
                &ingress,
                &context,
                &outer,
                &wrong_transport,
            ),
            Err(ManagedServingControllerError::ManagedServingTransportPinMismatch)
        );
        let other_claim = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
            &[0x97; 32],
        )
        .expect("other inner claim");
        let other_draft = ManagedServingBootstrapRequestDraftV1::try_new(
            ManagedServingBootstrapRequestIdV1::try_from_bytes([0x96; 16]).expect("other inner id"),
            context.target(),
            context.source_scope(),
            context.runtime_store_instance_id(),
            context.projection().clone(),
            context.channel(),
            other_claim,
        )
        .expect("other inner draft");
        let other_signature = controller.sign(
            other_draft
                .signing_transcript()
                .expect("other inner transcript")
                .as_bytes(),
        );
        let other_request = other_draft
            .finalize(&other_signature.to_bytes())
            .expect("other inner request");
        let other_response = current_serving_response(&other_request);
        let wrong_correlation = RuntimeManagedServingMtlsExchangeSuccessV1::try_new(
            RUNTIME_PRINCIPAL,
            remote.describe().carrier().binding_digest(),
            other_response.canonical_wire().into(),
        )
        .expect("well-shaped wrong response correlation");
        assert!(
            remote
                .describe()
                .try_accept_managed_serving_response(
                    &ingress,
                    &context,
                    &outer,
                    &wrong_correlation,
                )
                .is_err()
        );
        let transport = RuntimeManagedServingMtlsExchangeSuccessV1::try_new(
            RUNTIME_PRINCIPAL,
            remote.describe().carrier().binding_digest(),
            response.canonical_wire().into(),
        )
        .expect("authenticated transport result");
        let outcome = action
            .exchange_remote_once(remote.describe(), &ingress, &context, |wire| async move {
                assert_eq!(wire.as_ref(), expected_outer.as_slice());
                Ok(transport)
            })
            .await;
        let (action, response) = outcome.into_parts();
        let verified = response.expect("PXFR verifies");
        journal
            .consume_remote_serving_bootstrap_response_with(
                action,
                verified,
                &controller,
                &remote,
                &ingress,
                |_| Ok(()),
            )
            .expect("verified PXFR durable");
        assert_eq!(
            journal.state().serving_phase(),
            crate::managed_serving_client::ManagedServingBootstrapPhaseV1::ResponseDurable
        );
        assert_eq!(journal.state().serving.carrier_request(), Some(&outer));

        let describe_request_commit = RefCell::new(None);
        let prepared_describe = journal
            .prepare_remote_managed_ready_describe_with(
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xb1; 16], [0xb2; 32])
                    .expect("fresh post-PXFR Describe"),
                |next| {
                    *describe_request_commit.borrow_mut() = Some(next.clone());
                    Ok(())
                },
            )
            .expect("fresh Describe request durable");
        let durable_describe = describe_request_commit
            .into_inner()
            .expect("Describe crossed request-durable boundary");
        assert_eq!(
            durable_describe.serving_describe_reconcile_phase(),
            ManagedServingDescribeReconcilePhaseV1::RequestDurable
        );
        let exact_describe_request = durable_describe.serving.describe_request_wire().to_vec();
        assert_eq!(&exact_describe_request[..4], b"PXCC");

        let action = journal
            .claim_remote_managed_ready_describe_with(prepared_describe, &remote, &ingress, |_| {
                Ok(())
            })
            .expect("Describe one-shot action");
        assert_eq!(
            journal.state().serving_describe_reconcile_phase(),
            ManagedServingDescribeReconcilePhaseV1::AttemptInFlight
        );
        assert_eq!(action.canonical_request_bytes(), exact_describe_request);
        let persisted_in_flight = &journal.state().serving;
        let reopened_in_flight = ManagedServingBootstrapStateV1::decode_with_remote_reconcile(
            persisted_in_flight.phase(),
            persisted_in_flight.request_wire(),
            persisted_in_flight.response_wire(),
            persisted_in_flight.carrier_request_wire(),
            &context,
            Some(remote.describe()),
            ManagedServingDescribeReconcileDecodeV1 {
                phase: persisted_in_flight.describe_reconcile_phase(),
                request_wire: persisted_in_flight.describe_request_wire(),
                response_wire: persisted_in_flight.describe_response_wire(),
                previous: Some(&ingress),
            },
        )
        .expect("in-flight Describe strictly reopens without an action");
        let mut restarted_state = journal.state().clone();
        restarted_state.serving = reopened_in_flight;
        let mut restarted = ManagedFabricApplyJournalV1::new(restarted_state);
        restarted
            .close_recovered_remote_managed_ready_describe_with(|_| Ok(()))
            .expect("restart closes resident Describe authority");
        assert_eq!(
            restarted.state().serving_describe_reconcile_phase(),
            ManagedServingDescribeReconcilePhaseV1::AttemptClosedNoResponse
        );
        assert_eq!(
            restarted.prepare_remote_managed_ready_describe_with(
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xb1; 16], [0xb2; 32])
                    .expect("reused post-restart identity"),
                |_| Ok(()),
            ),
            Err(ManagedFabricApplyControllerError::Serving(
                ManagedServingControllerError::FreshIdentityReused
            ))
        );
        restarted
            .prepare_remote_managed_ready_describe_with(
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xb3; 16], [0xb4; 32])
                    .expect("fresh post-restart Describe"),
                |_| Ok(()),
            )
            .expect("restart permits only explicit fresh read-only Describe");
        let describe_response = post_bootstrap_describe_response(
            action.request(),
            RuntimeControlDescribeReadyPhaseV1::ManagedReady,
            2,
        );
        let exact_describe_response = describe_response.canonical_wire().to_vec();
        let wrong_peer = RuntimeManagedServingDescribeMtlsExchangeSuccessV1::try_new(
            PrincipalRef::from_bytes([0xee; 16]),
            remote.describe().carrier().binding_digest(),
            exact_describe_response.clone().into_boxed_slice(),
        )
        .expect("well-shaped wrong Describe peer");
        assert_eq!(
            remote
                .describe()
                .try_accept_managed_ready_describe_response(
                    &ingress,
                    action.request().clone(),
                    &wrong_peer,
                ),
            Err(ManagedServingControllerError::ManagedReadyDescribeTransportPinMismatch)
        );
        let legacy_response = post_bootstrap_describe_response(
            action.request(),
            RuntimeControlDescribeReadyPhaseV1::LegacyReady,
            2,
        );
        let legacy_transport = RuntimeManagedServingDescribeMtlsExchangeSuccessV1::try_new(
            RUNTIME_PRINCIPAL,
            remote.describe().carrier().binding_digest(),
            legacy_response.canonical_wire().into(),
        )
        .expect("authenticated LegacyReady PXDR");
        assert_eq!(
            remote
                .describe()
                .try_accept_managed_ready_describe_response(
                    &ingress,
                    action.request().clone(),
                    &legacy_transport,
                ),
            Err(ManagedServingControllerError::ManagedReadyDescribeRequired)
        );
        let mut forged_response = exact_describe_response.clone();
        *forged_response.last_mut().expect("PXDR signature") ^= 1;
        let forged_transport = RuntimeManagedServingDescribeMtlsExchangeSuccessV1::try_new(
            RUNTIME_PRINCIPAL,
            remote.describe().carrier().binding_digest(),
            forged_response.into_boxed_slice(),
        )
        .expect("well-shaped forged PXDR transport");
        assert!(
            remote
                .describe()
                .try_accept_managed_ready_describe_response(
                    &ingress,
                    action.request().clone(),
                    &forged_transport,
                )
                .is_err()
        );
        let other_describe_request = remote
            .describe()
            .try_build_request(
                Some(&ingress),
                FreshManagedServingBootstrapV1::try_new([0xb5; 16], [0xb6; 32])
                    .expect("other Describe identity"),
                &controller,
            )
            .expect("other signed Describe");
        let other_describe_response = post_bootstrap_describe_response(
            &other_describe_request,
            RuntimeControlDescribeReadyPhaseV1::ManagedReady,
            2,
        );
        let wrong_correlation = RuntimeManagedServingDescribeMtlsExchangeSuccessV1::try_new(
            RUNTIME_PRINCIPAL,
            remote.describe().carrier().binding_digest(),
            other_describe_response.canonical_wire().into(),
        )
        .expect("well-shaped wrong Describe correlation");
        assert!(
            remote
                .describe()
                .try_accept_managed_ready_describe_response(
                    &ingress,
                    action.request().clone(),
                    &wrong_correlation,
                )
                .is_err()
        );
        let describe_transport = RuntimeManagedServingDescribeMtlsExchangeSuccessV1::try_new(
            RUNTIME_PRINCIPAL,
            remote.describe().carrier().binding_digest(),
            exact_describe_response.clone().into_boxed_slice(),
        )
        .expect("authenticated Describe transport");
        let unspent_for_consume = ManagedServingDescribeSendActionV1 {
            state_sequence: action.state_sequence,
            cutover_marker_digest: action.cutover_marker_digest,
            request: action.request.clone(),
            remote_send_available: true,
        };
        assert_eq!(
            journal.consume_remote_managed_ready_describe_response_with(
                unspent_for_consume,
                describe_transport.clone(),
                &remote,
                &ingress,
                |_| Ok(()),
            ),
            Err(ManagedFabricApplyControllerError::ServingDescribeSendActionMismatch)
        );
        let unspent_for_close = ManagedServingDescribeSendActionV1 {
            state_sequence: action.state_sequence,
            cutover_marker_digest: action.cutover_marker_digest,
            request: action.request.clone(),
            remote_send_available: true,
        };
        assert_eq!(
            journal.close_remote_managed_ready_describe_no_response_with(
                unspent_for_close,
                |_| Ok(()),
            ),
            Err(ManagedFabricApplyControllerError::ServingDescribeSendActionMismatch)
        );
        let outcome = action
            .exchange_remote_once(|wire| async move {
                assert_eq!(wire.as_ref(), exact_describe_request.as_slice());
                Ok(describe_transport)
            })
            .await;
        let (action, transport) = outcome.into_parts();
        let ready = journal
            .consume_remote_managed_ready_describe_response_with(
                action,
                transport.expect("one raw PXDR"),
                &remote,
                &ingress,
                |_| Ok(()),
            )
            .expect("ManagedReady PXDR durable");
        assert_eq!(
            ready.request_wire(),
            journal.state().serving.describe_request_wire()
        );
        assert_eq!(ready.response_wire(), exact_describe_response);
        assert_eq!(
            journal.state().serving_describe_reconcile_phase(),
            ManagedServingDescribeReconcilePhaseV1::ResponseDurable
        );
        assert_eq!(
            journal
                .current_remote_managed_ready_facts(&controller, &remote, &ingress)
                .expect("durable Ready facts strictly revalidate"),
            ready
        );

        let persisted = &journal.state().serving;
        let reopened = ManagedServingBootstrapStateV1::decode_with_remote_reconcile(
            persisted.phase(),
            persisted.request_wire(),
            persisted.response_wire(),
            persisted.carrier_request_wire(),
            &context,
            Some(remote.describe()),
            ManagedServingDescribeReconcileDecodeV1 {
                phase: persisted.describe_reconcile_phase(),
                request_wire: persisted.describe_request_wire(),
                response_wire: persisted.describe_response_wire(),
                previous: Some(&ingress),
            },
        )
        .expect("exact PXFB/PXFR/PXCC/PXDR state reopens");
        assert_eq!(&reopened, persisted);
        let encoded = journal
            .state()
            .encode()
            .expect("PXFJ v6 encodes Ready facts");
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), STATE_VERSION);
        assert!(
            encoded
                .windows(exact_describe_response.len())
                .any(|window| window == exact_describe_response)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remote_uncertain_px_f_b_never_replays_and_only_fresh_describe_can_reconcile() {
        let controller = controller_signer();
        let (remote, ingress) = remote_provisioning_and_ingress();
        let mut journal = ManagedFabricApplyJournalV1::new(
            ManagedFabricControllerStateV1::try_from_cutover(
                Digest32::from_bytes([0xa1; 32]),
                ready_snapshot(),
            )
            .expect("cutover state"),
        );
        let prepared = journal
            .prepare_remote_serving_bootstrap_with(
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xa2; 16], [0xa3; 32])
                    .expect("fresh inner PXFB"),
                |_| Ok(()),
            )
            .expect("inner PXFB durable");
        let action = journal
            .claim_remote_serving_bootstrap_with(
                prepared,
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xa2; 16], [0xa5; 32])
                    .expect("fresh outer PXCC"),
                |_| Ok(()),
            )
            .expect("remote action");
        let context = VerifiedManagedFabricProducerContextV1::try_from_remote_describe(
            journal.state().legacy_snapshot().state(),
            &controller,
            &remote,
            &ingress,
        )
        .expect("remote context");
        let outcome = action
            .exchange_remote_once(remote.describe(), &ingress, &context, |_| async {
                Err(RuntimeManagedServingTransportErrorV1::Uncertain)
            })
            .await;
        let (action, response) = outcome.into_parts();
        assert_eq!(
            response,
            Err(ManagedServingControllerError::ManagedServingTransport(
                RuntimeManagedServingTransportErrorV1::Uncertain
            ))
        );
        let spent_outcome = action
            .exchange_remote_once(remote.describe(), &ingress, &context, |_| async {
                Err(RuntimeManagedServingTransportErrorV1::Rejected)
            })
            .await;
        let (action, response) = spent_outcome.into_parts();
        assert_eq!(
            response,
            Err(ManagedServingControllerError::ManagedServingTransportAuthoritySpent)
        );
        journal
            .close_serving_bootstrap_no_response_with(action, |_| Ok(()))
            .expect("uncertain attempt closes durably");
        let persisted = &journal.state().serving;
        let reopened = ManagedServingBootstrapStateV1::decode_with_remote_carrier(
            persisted.phase(),
            persisted.request_wire(),
            persisted.response_wire(),
            persisted.carrier_request_wire(),
            &context,
            Some(remote.describe()),
        )
        .expect("closed remote serving state reopens from exact durable bytes");
        assert_eq!(&reopened, persisted);
        assert_eq!(
            ManagedServingBootstrapStateV1::decode_with_remote_carrier(
                persisted.phase(),
                persisted.request_wire(),
                persisted.response_wire(),
                &[],
                &context,
                Some(remote.describe()),
            ),
            Err(ManagedServingControllerError::InvalidStateEncoding)
        );
        let mut forged_outer = persisted.carrier_request_wire().to_vec();
        *forged_outer.last_mut().expect("outer PXCC signature") ^= 1;
        assert!(
            ManagedServingBootstrapStateV1::decode_with_remote_carrier(
                persisted.phase(),
                persisted.request_wire(),
                persisted.response_wire(),
                &forged_outer,
                &context,
                Some(remote.describe()),
            )
            .is_err()
        );
        assert_eq!(
            reopened.require_remote_prepare_ready(),
            Err(ManagedServingControllerError::RemoteDescribeReconcileRequired)
        );
        let error = journal
            .prepare_remote_serving_bootstrap_with(
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xa6; 16], [0xa7; 32])
                    .expect("fresh values cannot bypass reconciliation"),
                |_| Ok(()),
            )
            .expect_err("old Describe must not authorize another remote PXFB");
        assert_eq!(
            error,
            ManagedFabricApplyControllerError::Serving(
                ManagedServingControllerError::RemoteDescribeReconcileRequired
            )
        );
        assert!(journal.prepared_serving_bootstrap().is_err());

        let prepared_describe = journal
            .prepare_remote_managed_ready_describe_with(
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xc1; 16], [0xc2; 32])
                    .expect("fresh read-only Describe"),
                |_| Ok(()),
            )
            .expect("uncertain PXFB permits only fresh Describe reconciliation");
        let describe_action = journal
            .claim_remote_managed_ready_describe_with(prepared_describe, &remote, &ingress, |_| {
                Ok(())
            })
            .expect("claim one read-only Describe");
        let first_describe_wire = describe_action.canonical_request_bytes().to_vec();
        let outcome = describe_action
            .exchange_remote_once(|wire| async move {
                assert_eq!(wire.as_ref(), first_describe_wire.as_slice());
                Err(RuntimeManagedServingDescribeTransportErrorV1::Uncertain)
            })
            .await;
        let (describe_action, response) = outcome.into_parts();
        assert_eq!(
            response,
            Err(
                ManagedServingControllerError::ManagedReadyDescribeTransport(
                    RuntimeManagedServingDescribeTransportErrorV1::Uncertain
                )
            )
        );
        let spent = describe_action
            .exchange_remote_once(|_| async {
                Err(RuntimeManagedServingDescribeTransportErrorV1::Rejected)
            })
            .await;
        let (describe_action, response) = spent.into_parts();
        assert_eq!(
            response,
            Err(ManagedServingControllerError::ManagedReadyDescribeTransportAuthoritySpent)
        );
        journal
            .close_remote_managed_ready_describe_no_response_with(describe_action, |_| Ok(()))
            .expect("uncertain Describe closes without replay");
        assert_eq!(
            journal.state().serving_describe_reconcile_phase(),
            ManagedServingDescribeReconcilePhaseV1::AttemptClosedNoResponse
        );
        assert!(journal.prepared_remote_managed_ready_describe().is_err());
        assert_eq!(
            journal.prepare_remote_managed_ready_describe_with(
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xc1; 16], [0xc2; 32])
                    .expect("reused Describe identity"),
                |_| Ok(()),
            ),
            Err(ManagedFabricApplyControllerError::Serving(
                ManagedServingControllerError::FreshIdentityReused
            ))
        );

        let prepared_describe = journal
            .prepare_remote_managed_ready_describe_with(
                &controller,
                &remote,
                &ingress,
                FreshManagedServingBootstrapV1::try_new([0xc3; 16], [0xc4; 32])
                    .expect("second fresh Describe"),
                |_| Ok(()),
            )
            .expect("explicit fresh read-only reconciliation");
        let describe_action = journal
            .claim_remote_managed_ready_describe_with(prepared_describe, &remote, &ingress, |_| {
                Ok(())
            })
            .expect("claim second fresh Describe");
        let describe_response = post_bootstrap_describe_response(
            describe_action.request(),
            RuntimeControlDescribeReadyPhaseV1::ManagedReady,
            2,
        );
        let transport = RuntimeManagedServingDescribeMtlsExchangeSuccessV1::try_new(
            RUNTIME_PRINCIPAL,
            remote.describe().carrier().binding_digest(),
            describe_response.canonical_wire().into(),
        )
        .expect("authenticated ManagedReady PXDR");
        let outcome = describe_action
            .exchange_remote_once(|_| async { Ok(transport) })
            .await;
        let (describe_action, transport) = outcome.into_parts();
        let ready = journal
            .consume_remote_managed_ready_describe_response_with(
                describe_action,
                transport.expect("one PXDR"),
                &remote,
                &ingress,
                |_| Ok(()),
            )
            .expect("ManagedReady state is durable");
        assert_eq!(
            journal.state().serving_phase(),
            crate::managed_serving_client::ManagedServingBootstrapPhaseV1::AttemptClosedNoResponse,
            "fresh Describe must not synthesize a missing PXFR"
        );
        assert_eq!(
            journal.current_remote_serving_pin(&controller, &remote, &ingress),
            Err(ManagedFabricApplyControllerError::Serving(
                ManagedServingControllerError::ServingPinRequired
            ))
        );
        assert_eq!(
            journal
                .current_remote_managed_ready_facts(&controller, &remote, &ingress)
                .expect("current ManagedReady facts"),
            ready
        );
    }

    #[test]
    fn pxfj_v6_rejects_dual_sibling_payloads() {
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

        let encoded = journal.state().encode().expect("PXFJ v6 state");
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
