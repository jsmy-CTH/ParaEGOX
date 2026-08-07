//! Deployment-owned producer for the two-target PXTE v7/PXAR v8 rollout.
//!
//! This module consumes an already committed and authenticated PXAR v7
//! Fabric→Agent predecessor for each RuntimeHost.  It does not treat the
//! contract golden signature as authority: every PXAR v8 is signed again over
//! its own signing transcript with the currently pinned Controller key. The
//! restricted path additionally signs PXRC and verifies PXDS v2 with concrete
//! predecessor-pinned Ed25519 keys; contract verifier callbacks never escape
//! as caller-defined authentication policy.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use paraegox_kernel::digest::{Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};
use paraegox_runtime_contracts::apply::{
    ApplyOperationId, ExpectedActive, PlanWriterContext, RuntimeApplyControl,
};
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DistributedAgentStackApplyRequestDraftV1, DistributedAgentStackApplyRequestV1,
    DistributedAgentStackPlanError, DistributedAgentStackProjectionV1,
    DistributedAgentStackRestrictedApplyRequestDraftV1,
    DistributedAgentStackRestrictedApplyRequestV1, DistributedAgentStackTargetExecutionV1,
    DistributedAgentStackTargetModeV1, DistributedAgentStackTerminalFactsV1,
    DistributedAgentStackTerminalOutcomeV1, DistributedAgentStackTerminalReceiptV1,
    DistributedAgentStackTerminalReceiptV2, DistributedFabricTopologyV1,
    RestrictedRuntimeApplyCarrierBindingV1,
};
use paraegox_runtime_contracts::managed_agent_stack_plan::{
    ManagedAgentStackApplyRequestV1, ManagedAgentStackTargetModeV1,
    ManagedAgentStackTerminalHeadV1, ManagedAgentStackTerminalOutcomeV1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
use paraegox_runtime_contracts::provenance::{
    PlanProvenance, SourcePlanDigest, SourcePlanRef, SourcePlanRevision, SourceScopeRef,
};
use paraegox_runtime_contracts::reference_control::{
    ReferenceChannelBindingV1, ed25519_control_key_fingerprint,
};
use paraegox_runtime_contracts::temporal::{
    ApplyTemporalConstraint, TemporalConstraintId, TemporalContractError,
};
use paraegox_runtime_contracts::wire::{
    ApplyAuthAlgorithm, ApplyAuthError, ApplyAuthKeyRef, ApplyRequestAuthClaim,
};

use crate::managed_agent_stack_apply::{
    ManagedAgentStackApplyPhaseV1, ManagedAgentStackControllerStateV1,
};
use crate::managed_agent_stack_producer::{
    ManagedAgentStackProducerError, validate_managed_agent_stack_request_v1,
};
use crate::managed_fabric_producer::VerifiedManagedFabricProducerContextV1;

const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;
const TWO_TARGET_DESIRED_DIGEST_DOMAIN: &[u8] =
    b"paraegox.deployment.distributed-agent-stack.two-target-desired.sha256.v1";

/// Stable nonzero identity of one exact two-target rollout.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct DistributedAgentStackRolloutIdV1([u8; 16]);

impl DistributedAgentStackRolloutIdV1 {
    pub(crate) fn try_from_bytes(
        bytes: [u8; 16],
    ) -> Result<Self, DistributedAgentStackProducerError> {
        if bytes_are_zero(&bytes) {
            return Err(DistributedAgentStackProducerError::InvalidRolloutIdentity);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Fresh request-only identities for one target.  They are not desired state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreshDistributedAgentStackApplyV1 {
    operation_id: [u8; 16],
    temporal_constraint_id: [u8; 16],
    authentication_nonce: [u8; 32],
    lifecycle_budget: BoundedDuration,
}

impl FreshDistributedAgentStackApplyV1 {
    pub(crate) fn try_new(
        operation_id: [u8; 16],
        temporal_constraint_id: [u8; 16],
        authentication_nonce: [u8; 32],
        lifecycle_budget: BoundedDuration,
    ) -> Result<Self, DistributedAgentStackProducerError> {
        if bytes_are_zero(&operation_id)
            || bytes_are_zero(&temporal_constraint_id)
            || bytes_are_zero(&authentication_nonce)
            || operation_id == temporal_constraint_id
            || lifecycle_budget.value() == 0
        {
            return Err(DistributedAgentStackProducerError::InvalidFreshIdentity);
        }
        Ok(Self {
            operation_id,
            temporal_constraint_id,
            authentication_nonce,
            lifecycle_budget,
        })
    }
}

/// Facts copied only after the existing Controller state has verified a
/// committed ActiveReady PXAR v7/PXST predecessor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedDistributedAgentStackPredecessorV1 {
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    source_plan: SourcePlanRef,
    writer_context: PlanWriterContext,
    controller_principal: PrincipalRef,
    request_key: ApplyAuthKeyRef,
    controller_verifying_key: [u8; 32],
    clock_domain: ClockDomainRef,
    clock_generation: ClockGeneration,
    runtime_store_instance_id: [u8; 32],
    runtime_channel: ReferenceChannelBindingV1,
    runtime_response_key: ApplyAuthKeyRef,
    runtime_response_public_key: VerifyingKey,
    predecessor_runtime_host_epoch: u64,
    predecessor_completion_snapshot_sequence: u64,
    predecessor_fabric_generation: ManagedServiceGeneration,
    predecessor_agent_generation: ManagedServiceGeneration,
    request: ManagedAgentStackApplyRequestV1,
}

impl VerifiedDistributedAgentStackPredecessorV1 {
    /// Seals one predecessor from the existing single-owner Controller state.
    pub(crate) fn try_from_committed(
        context: &VerifiedManagedFabricProducerContextV1,
        state: &ManagedAgentStackControllerStateV1,
    ) -> Result<Self, DistributedAgentStackProducerError> {
        if state.phase() != ManagedAgentStackApplyPhaseV1::ReceiptDurable
            || state.archived_active().is_some()
            || state.desired().execution().mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
        {
            return Err(DistributedAgentStackProducerError::PredecessorNotCommittedActive);
        }
        validate_managed_agent_stack_request_v1(context, state.desired(), state.request())?;
        let receipt = state
            .receipt()
            .ok_or(DistributedAgentStackProducerError::PredecessorNotCommittedActive)?;
        let facts = receipt
            .validate_against_request(state.request(), context.channel())
            .map_err(|_| DistributedAgentStackProducerError::PredecessorNotCommittedActive)?;
        let terminal = facts.state();
        let predecessor_fabric_generation = terminal.fabric_generation();
        let predecessor_agent_generation = terminal.agent_generation();
        if terminal.outcome() != ManagedAgentStackTerminalOutcomeV1::ActiveReady
            || terminal.head() != ManagedAgentStackTerminalHeadV1::CommittedIncoming
            || predecessor_fabric_generation.is_none()
            || predecessor_agent_generation.is_none()
            || receipt.authentication_key() != context.runtime_response_key()
            || receipt.authentication_algorithm().value() != ED25519_ALGORITHM
            || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
            || receipt.authentication_signature().len() != ED25519_SIGNATURE_BYTES
        {
            return Err(DistributedAgentStackProducerError::PredecessorNotCommittedActive);
        }
        let signature = Signature::from_slice(receipt.authentication_signature())
            .map_err(|_| DistributedAgentStackProducerError::PredecessorNotCommittedActive)?;
        context
            .runtime_response_public_key()
            .verify_strict(
                receipt
                    .signing_transcript()
                    .map_err(|_| DistributedAgentStackProducerError::PredecessorNotCommittedActive)?
                    .as_bytes(),
                &signature,
            )
            .map_err(|_| DistributedAgentStackProducerError::PredecessorNotCommittedActive)?;
        Ok(Self {
            target: context.target(),
            source_scope: context.source_scope(),
            source_plan: context.source_plan(),
            writer_context: context.writer_context().clone(),
            controller_principal: context.controller_principal(),
            request_key: context.request_key(),
            controller_verifying_key: context.controller_verifying_key(),
            clock_domain: context.clock_domain(),
            clock_generation: context.clock_generation(),
            runtime_store_instance_id: context.runtime_store_instance_id(),
            runtime_channel: context.channel(),
            runtime_response_key: context.runtime_response_key(),
            runtime_response_public_key: *context.runtime_response_public_key(),
            predecessor_runtime_host_epoch: facts.evidence().fields().completion_runtime_host_epoch,
            predecessor_completion_snapshot_sequence: facts
                .evidence()
                .fields()
                .completion_snapshot_sequence,
            predecessor_fabric_generation: predecessor_fabric_generation
                .ok_or(DistributedAgentStackProducerError::PredecessorNotCommittedActive)?,
            predecessor_agent_generation: predecessor_agent_generation
                .ok_or(DistributedAgentStackProducerError::PredecessorNotCommittedActive)?,
            request: state.request().clone(),
        })
    }

    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ManagedAgentStackApplyRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) const fn source_scope(&self) -> SourceScopeRef {
        self.source_scope
    }

    #[must_use]
    pub(crate) const fn source_plan(&self) -> SourcePlanRef {
        self.source_plan
    }

    #[must_use]
    pub(crate) const fn request_key(&self) -> ApplyAuthKeyRef {
        self.request_key
    }

    #[must_use]
    pub(crate) const fn controller_principal(&self) -> PrincipalRef {
        self.controller_principal
    }

    #[must_use]
    pub(crate) const fn controller_verifying_key(&self) -> &[u8; 32] {
        &self.controller_verifying_key
    }

    #[must_use]
    pub(crate) const fn runtime_channel(&self) -> ReferenceChannelBindingV1 {
        self.runtime_channel
    }

    #[must_use]
    pub(crate) const fn runtime_response_key(&self) -> ApplyAuthKeyRef {
        self.runtime_response_key
    }

    #[must_use]
    pub(crate) const fn runtime_response_public_key(&self) -> &VerifyingKey {
        &self.runtime_response_public_key
    }

    #[must_use]
    pub(crate) const fn runtime_principal(&self) -> PrincipalRef {
        self.runtime_channel.runtime_peer()
    }

    #[must_use]
    pub(crate) const fn predecessor_runtime_host_epoch(&self) -> u64 {
        self.predecessor_runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn predecessor_completion_snapshot_sequence(&self) -> u64 {
        self.predecessor_completion_snapshot_sequence
    }
}

/// Receipt that crossed the exact request-time Runtime authentication and
/// predecessor-freshness boundary. Callers cannot construct this token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedDistributedAgentStackTerminalV1 {
    receipt: DistributedAgentStackTerminalReceiptV1,
}

impl VerifiedDistributedAgentStackTerminalV1 {
    #[must_use]
    pub(crate) const fn receipt(&self) -> &DistributedAgentStackTerminalReceiptV1 {
        &self.receipt
    }

    pub(crate) fn into_receipt(self) -> DistributedAgentStackTerminalReceiptV1 {
        self.receipt
    }
}

pub(crate) fn validate_distributed_agent_stack_terminal_v1(
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    request: &DistributedAgentStackApplyRequestV1,
    receipt: DistributedAgentStackTerminalReceiptV1,
) -> Result<VerifiedDistributedAgentStackTerminalV1, DistributedAgentStackProducerError> {
    if request.target() != predecessor.target
        || request.expected_runtime_store_instance_id() != predecessor.runtime_store_instance_id
    {
        return Err(DistributedAgentStackProducerError::TerminalMismatch);
    }
    let facts = receipt
        .validate_against_request(request, predecessor.runtime_channel)
        .map_err(|_| DistributedAgentStackProducerError::TerminalMismatch)?;
    if receipt.authentication_key() != predecessor.runtime_response_key
        || receipt.authentication_algorithm().value() != ED25519_ALGORITHM
        || receipt.authentication_algorithm_version() != ED25519_ALGORITHM_VERSION
        || receipt.authentication_signature().len() != ED25519_SIGNATURE_BYTES
        || facts.evidence().runtime_host_epoch < predecessor.predecessor_runtime_host_epoch
        || facts.evidence().runtime_host_epoch == predecessor.predecessor_runtime_host_epoch
            && facts.evidence().completion_snapshot_sequence
                <= predecessor.predecessor_completion_snapshot_sequence
    {
        return Err(DistributedAgentStackProducerError::TerminalMismatch);
    }
    let evidence = facts.evidence();
    if evidence.fabric_generation.is_some_and(|generation| {
        generation.value() <= predecessor.predecessor_fabric_generation.value()
    }) || evidence.agent_generation.is_some_and(|generation| {
        generation.value() <= predecessor.predecessor_agent_generation.value()
    }) || facts.outcome() == DistributedAgentStackTerminalOutcomeV1::ActiveReady
        && (evidence.fabric_generation.is_none() || evidence.agent_generation.is_none())
    {
        return Err(DistributedAgentStackProducerError::TerminalMismatch);
    }
    let signature = Signature::from_slice(receipt.authentication_signature())
        .map_err(|_| DistributedAgentStackProducerError::TerminalMismatch)?;
    predecessor
        .runtime_response_public_key
        .verify_strict(
            receipt
                .signing_transcript()
                .map_err(|_| DistributedAgentStackProducerError::TerminalMismatch)?
                .as_bytes(),
            &signature,
        )
        .map_err(|_| DistributedAgentStackProducerError::TerminalMismatch)?;
    Ok(VerifiedDistributedAgentStackTerminalV1 { receipt })
}

/// PXRC that crossed deployment's concrete pinned-key verification boundary.
/// The contract callback is never delegated to an arbitrary caller here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedDistributedAgentStackRestrictedApplyV1 {
    request: DistributedAgentStackRestrictedApplyRequestV1,
}

impl VerifiedDistributedAgentStackRestrictedApplyV1 {
    #[must_use]
    pub(crate) const fn request(&self) -> &DistributedAgentStackRestrictedApplyRequestV1 {
        &self.request
    }

    pub(crate) fn into_request(self) -> DistributedAgentStackRestrictedApplyRequestV1 {
        self.request
    }
}

/// PXDS v2 that crossed deployment's concrete pinned Runtime response-key
/// verification and predecessor-freshness boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedDistributedAgentStackTerminalV2 {
    receipt: DistributedAgentStackTerminalReceiptV2,
}

impl VerifiedDistributedAgentStackTerminalV2 {
    #[must_use]
    pub(crate) const fn receipt(&self) -> &DistributedAgentStackTerminalReceiptV2 {
        &self.receipt
    }

    pub(crate) fn into_receipt(self) -> DistributedAgentStackTerminalReceiptV2 {
        self.receipt
    }
}

/// Produces one Controller-signed PXRC for an exact already-signed PXAR v8.
/// Endpoint selection remains the caller's Node-discovery responsibility;
/// every identity and key asserted by the carrier is pinned here before sign.
pub(crate) fn produce_distributed_agent_stack_restricted_apply_v1(
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    request: &DistributedAgentStackApplyRequestV1,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    controller_signer: &SigningKey,
) -> Result<VerifiedDistributedAgentStackRestrictedApplyV1, DistributedAgentStackProducerError> {
    if controller_signer.verifying_key().to_bytes() != predecessor.controller_verifying_key {
        return Err(DistributedAgentStackProducerError::ControllerKeyMismatch);
    }
    validate_request(
        predecessor,
        request,
        request.provenance(),
        request.provenance().source_revision(),
    )?;
    validate_restricted_carrier_pins(predecessor, request, &carrier)?;
    let draft =
        DistributedAgentStackRestrictedApplyRequestDraftV1::try_new(request.clone(), carrier)?;
    let signature = controller_signer.sign(draft.signing_transcript()?.as_bytes());
    validate_distributed_agent_stack_restricted_apply_v1(
        predecessor,
        request,
        draft.finalize(&signature.to_bytes())?,
    )
}

/// Reauthenticates a decoded PXRC using the exact predecessor-pinned
/// Controller Ed25519 key. No caller-supplied boolean verifier is trusted.
pub(crate) fn validate_distributed_agent_stack_restricted_apply_v1(
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    request: &DistributedAgentStackApplyRequestV1,
    restricted: DistributedAgentStackRestrictedApplyRequestV1,
) -> Result<VerifiedDistributedAgentStackRestrictedApplyV1, DistributedAgentStackProducerError> {
    validate_request(
        predecessor,
        request,
        request.provenance(),
        request.provenance().source_revision(),
    )?;
    validate_restricted_carrier_pins(predecessor, request, restricted.carrier())?;
    let controller_key = VerifyingKey::from_bytes(&predecessor.controller_verifying_key)
        .map_err(|_| DistributedAgentStackProducerError::RestrictedCarrierMismatch)?;
    let expected_fingerprint = ed25519_control_key_fingerprint(controller_key.as_bytes())
        .map_err(|_| DistributedAgentStackProducerError::RestrictedCarrierMismatch)?;
    let authenticated = restricted
        .verify_controller_carrier_before_mutation(
            restricted.carrier(),
            |principal, key, fingerprint, transcript, signature| {
                if principal != predecessor.controller_principal
                    || key != predecessor.request_key
                    || fingerprint != expected_fingerprint
                {
                    return false;
                }
                let Ok(signature) = Signature::from_slice(signature) else {
                    return false;
                };
                controller_key.verify_strict(transcript, &signature).is_ok()
            },
        )
        .map_err(|_| DistributedAgentStackProducerError::RestrictedCarrierMismatch)?;
    if authenticated.request() != request {
        return Err(DistributedAgentStackProducerError::RestrictedCarrierMismatch);
    }
    Ok(VerifiedDistributedAgentStackRestrictedApplyV1 {
        request: restricted,
    })
}

/// Reauthenticates a PXDS v2 against the exact durable PXRC/PXCB and the
/// predecessor-pinned Runtime response key, then applies the same freshness
/// and generation floors as the frozen PXDS v1 path.
pub(crate) fn validate_distributed_agent_stack_terminal_v2(
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    request: &DistributedAgentStackApplyRequestV1,
    restricted: &DistributedAgentStackRestrictedApplyRequestV1,
    receipt: DistributedAgentStackTerminalReceiptV2,
) -> Result<VerifiedDistributedAgentStackTerminalV2, DistributedAgentStackProducerError> {
    let verified_restricted = validate_distributed_agent_stack_restricted_apply_v1(
        predecessor,
        request,
        restricted.clone(),
    )?;
    let controller_key = VerifyingKey::from_bytes(&predecessor.controller_verifying_key)
        .map_err(|_| DistributedAgentStackProducerError::RestrictedCarrierMismatch)?;
    let controller_fingerprint = ed25519_control_key_fingerprint(controller_key.as_bytes())
        .map_err(|_| DistributedAgentStackProducerError::RestrictedCarrierMismatch)?;
    let runtime_key = &predecessor.runtime_response_public_key;
    let expected_fingerprint = ed25519_control_key_fingerprint(runtime_key.as_bytes())
        .map_err(|_| DistributedAgentStackProducerError::RestrictedCarrierMismatch)?;
    let authenticated_restricted = verified_restricted
        .request()
        .verify_controller_carrier_before_mutation(
            verified_restricted.request().carrier(),
            |principal, key, fingerprint, transcript, signature| {
                if principal != predecessor.controller_principal
                    || key != predecessor.request_key
                    || fingerprint != controller_fingerprint
                {
                    return false;
                }
                let Ok(signature) = Signature::from_slice(signature) else {
                    return false;
                };
                controller_key.verify_strict(transcript, &signature).is_ok()
            },
        )
        .map_err(|_| DistributedAgentStackProducerError::RestrictedCarrierMismatch)?;
    let facts = receipt
        .verify_runtime_response(
            authenticated_restricted,
            |principal, key, fingerprint, transcript, signature| {
                if principal != predecessor.runtime_principal()
                    || key != predecessor.runtime_response_key
                    || fingerprint != expected_fingerprint
                {
                    return false;
                }
                let Ok(signature) = Signature::from_slice(signature) else {
                    return false;
                };
                runtime_key.verify_strict(transcript, &signature).is_ok()
            },
        )
        .map_err(|_| DistributedAgentStackProducerError::TerminalMismatch)?;
    validate_terminal_freshness_and_generation(predecessor, facts)?;
    Ok(VerifiedDistributedAgentStackTerminalV2 { receipt })
}

fn validate_restricted_carrier_pins(
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    request: &DistributedAgentStackApplyRequestV1,
    carrier: &RestrictedRuntimeApplyCarrierBindingV1,
) -> Result<(), DistributedAgentStackProducerError> {
    let controller_fingerprint =
        ed25519_control_key_fingerprint(&predecessor.controller_verifying_key)
            .map_err(|_| DistributedAgentStackProducerError::RestrictedCarrierMismatch)?;
    let runtime_fingerprint =
        ed25519_control_key_fingerprint(predecessor.runtime_response_public_key.as_bytes())
            .map_err(|_| DistributedAgentStackProducerError::RestrictedCarrierMismatch)?;
    if carrier.target() != request.target()
        || carrier.target() != predecessor.target
        || carrier.runtime_principal() != predecessor.runtime_principal()
        || carrier.controller_principal() != predecessor.controller_principal
        || carrier.controller_request_key() != predecessor.request_key
        || carrier.controller_request_key_fingerprint() != controller_fingerprint
        || carrier.runtime_response_key() != predecessor.runtime_response_key
        || carrier.runtime_response_key_fingerprint() != runtime_fingerprint
    {
        return Err(DistributedAgentStackProducerError::RestrictedCarrierMismatch);
    }
    Ok(())
}

fn validate_terminal_freshness_and_generation(
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    facts: &DistributedAgentStackTerminalFactsV1,
) -> Result<(), DistributedAgentStackProducerError> {
    let evidence = facts.evidence();
    if evidence.runtime_host_epoch < predecessor.predecessor_runtime_host_epoch
        || evidence.runtime_host_epoch == predecessor.predecessor_runtime_host_epoch
            && evidence.completion_snapshot_sequence
                <= predecessor.predecessor_completion_snapshot_sequence
        || evidence.fabric_generation.is_some_and(|generation| {
            generation.value() <= predecessor.predecessor_fabric_generation.value()
        })
        || evidence.agent_generation.is_some_and(|generation| {
            generation.value() <= predecessor.predecessor_agent_generation.value()
        })
        || facts.outcome() == DistributedAgentStackTerminalOutcomeV1::ActiveReady
            && (evidence.fabric_generation.is_none() || evidence.agent_generation.is_none())
    {
        return Err(DistributedAgentStackProducerError::TerminalMismatch);
    }
    Ok(())
}

/// One target-specific desired topology and fresh apply identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackTargetRolloutInputV1 {
    predecessor: VerifiedDistributedAgentStackPredecessorV1,
    topology: DistributedFabricTopologyV1,
    fresh: FreshDistributedAgentStackApplyV1,
}

impl DistributedAgentStackTargetRolloutInputV1 {
    pub(crate) fn new(
        predecessor: VerifiedDistributedAgentStackPredecessorV1,
        topology: DistributedFabricTopologyV1,
        fresh: FreshDistributedAgentStackApplyV1,
    ) -> Self {
        Self {
            predecessor,
            topology,
            fresh,
        }
    }
}

/// Fully signed, strictly ordered two-target desired rollout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackRolloutV1 {
    rollout_id: DistributedAgentStackRolloutIdV1,
    revision: SourcePlanRevision,
    provenance: PlanProvenance,
    requests: [DistributedAgentStackApplyRequestV1; 2],
}

impl DistributedAgentStackRolloutV1 {
    #[must_use]
    pub(crate) const fn rollout_id(&self) -> DistributedAgentStackRolloutIdV1 {
        self.rollout_id
    }

    #[must_use]
    pub(crate) const fn revision(&self) -> SourcePlanRevision {
        self.revision
    }

    #[must_use]
    pub(crate) const fn provenance(&self) -> PlanProvenance {
        self.provenance
    }

    #[must_use]
    pub(crate) const fn requests(&self) -> &[DistributedAgentStackApplyRequestV1; 2] {
        &self.requests
    }

    /// Restores and revalidates exact durable PXAR v8 rows against the two
    /// committed PXAR v7 predecessors.
    pub(crate) fn try_restore(
        rollout_id: DistributedAgentStackRolloutIdV1,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        requests: [DistributedAgentStackApplyRequestV1; 2],
    ) -> Result<Self, DistributedAgentStackProducerError> {
        validate_predecessor_pair(predecessors)?;
        validate_request_pair_shape(&requests)?;
        let revision = next_shared_revision(predecessors)?;
        let provenance = desired_provenance(rollout_id, revision, predecessors, &requests)?;
        for index in 0..2 {
            validate_request(predecessors[index], &requests[index], provenance, revision)?;
        }
        validate_fresh_request_pair(&requests)?;
        validate_cross_target_topology(&requests)?;
        Ok(Self {
            rollout_id,
            revision,
            provenance,
            requests,
        })
    }
}

/// Produces and independently signs exactly two PXAR v8 target rows.
pub(crate) fn produce_distributed_agent_stack_rollout_v1(
    rollout_id: DistributedAgentStackRolloutIdV1,
    inputs: [DistributedAgentStackTargetRolloutInputV1; 2],
    controller_signer: &SigningKey,
) -> Result<DistributedAgentStackRolloutV1, DistributedAgentStackProducerError> {
    let [first, second] = inputs;
    let predecessors = [&first.predecessor, &second.predecessor];
    validate_predecessor_pair(predecessors)?;
    validate_fresh_pair(first.fresh, second.fresh)?;
    if predecessors
        .iter()
        .any(|value| value.controller_verifying_key != controller_signer.verifying_key().to_bytes())
    {
        return Err(DistributedAgentStackProducerError::ControllerKeyMismatch);
    }

    let first_execution = desired_execution(&first)?;
    let second_execution = desired_execution(&second)?;
    let revision = next_shared_revision(predecessors)?;
    let provisional = [
        ProvisionalRequestV1 {
            target: first.predecessor.target,
            predecessor_slice: first.predecessor.request.target_slice_digest(),
            execution: first_execution,
        },
        ProvisionalRequestV1 {
            target: second.predecessor.target,
            predecessor_slice: second.predecessor.request.target_slice_digest(),
            execution: second_execution,
        },
    ];
    let provenance = desired_provenance_from_executions(
        rollout_id,
        revision,
        first.predecessor.source_scope,
        first.predecessor.source_plan,
        &provisional,
    )?;
    let first_request = produce_request(
        &first.predecessor,
        provisional[0].execution.clone(),
        provenance,
        first.fresh,
        controller_signer,
    )?;
    let second_request = produce_request(
        &second.predecessor,
        provisional[1].execution.clone(),
        provenance,
        second.fresh,
        controller_signer,
    )?;
    DistributedAgentStackRolloutV1::try_restore(
        rollout_id,
        predecessors,
        [first_request, second_request],
    )
}

#[derive(Clone)]
struct ProvisionalRequestV1 {
    target: RuntimeHostId,
    predecessor_slice: paraegox_runtime_contracts::provenance::TargetSliceDigest,
    execution: DistributedAgentStackTargetExecutionV1,
}

fn desired_execution(
    input: &DistributedAgentStackTargetRolloutInputV1,
) -> Result<DistributedAgentStackTargetExecutionV1, DistributedAgentStackProducerError> {
    let predecessor_execution = input.predecessor.request.target_execution();
    if predecessor_execution.mode() != ManagedAgentStackTargetModeV1::FabricAndAgent {
        return Err(DistributedAgentStackProducerError::PredecessorNotCommittedActive);
    }
    let topology = DistributedFabricTopologyV1::decode(
        input.predecessor.target,
        input.topology.canonical_wire(),
    )?;
    let projection = DistributedAgentStackProjectionV1::try_from_managed_agent_stack_projection(
        predecessor_execution.projection().clone(),
    )?;
    Ok(
        DistributedAgentStackTargetExecutionV1::try_distributed_fabric_and_agent(
            projection,
            predecessor_execution.clone(),
            topology,
        )?,
    )
}

fn produce_request(
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    execution: DistributedAgentStackTargetExecutionV1,
    provenance: PlanProvenance,
    fresh: FreshDistributedAgentStackApplyV1,
    controller_signer: &SigningKey,
) -> Result<DistributedAgentStackApplyRequestV1, DistributedAgentStackProducerError> {
    let control = RuntimeApplyControl::new(
        predecessor.writer_context.clone(),
        ExpectedActive::Exact(predecessor.request.target_slice_digest()),
        ApplyOperationId::from_bytes(fresh.operation_id),
    );
    let temporal = ApplyTemporalConstraint::try_new(
        TemporalConstraintId::from_bytes(fresh.temporal_constraint_id),
        predecessor.clock_domain,
        predecessor.clock_generation,
        fresh.lifecycle_budget,
        fresh.lifecycle_budget,
    )?;
    let claim = ApplyRequestAuthClaim::try_new(
        predecessor.controller_principal,
        predecessor.request_key,
        ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)?,
        ED25519_ALGORITHM_VERSION,
        &fresh.authentication_nonce,
    )?;
    let draft = DistributedAgentStackApplyRequestDraftV1::try_new(
        execution,
        provenance,
        control,
        temporal,
        predecessor.runtime_store_instance_id,
        claim,
    )?;
    let signature = controller_signer.sign(draft.signing_transcript()?.as_bytes());
    Ok(draft.finalize(&signature.to_bytes())?)
}

pub(crate) fn validate_predecessor_pair(
    predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
) -> Result<(), DistributedAgentStackProducerError> {
    let [first, second] = predecessors;
    let first_provenance = first.request.provenance();
    let second_provenance = second.request.provenance();
    if first.target.as_bytes() >= second.target.as_bytes() {
        return Err(DistributedAgentStackProducerError::TargetsNotStrictlyOrdered);
    }
    if first.request.target() != first.target
        || second.request.target() != second.target
        || first.request.target_execution().mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
        || second.request.target_execution().mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
        || first.source_scope != second.source_scope
        || first.source_plan != second.source_plan
        || first_provenance.source_scope() != first.source_scope
        || first_provenance.source_plan() != first.source_plan
        || second_provenance.source_scope() != second.source_scope
        || second_provenance.source_plan() != second.source_plan
        || first_provenance.source_revision() != second_provenance.source_revision()
        || first.writer_context != second.writer_context
        || first.controller_principal != second.controller_principal
        || first.request_key != second.request_key
        || first.controller_verifying_key != second.controller_verifying_key
    {
        return Err(DistributedAgentStackProducerError::PredecessorPairMismatch);
    }
    Ok(())
}

fn next_shared_revision(
    predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
) -> Result<SourcePlanRevision, DistributedAgentStackProducerError> {
    let revision = predecessors[0]
        .request
        .provenance()
        .source_revision()
        .value()
        .checked_add(1)
        .ok_or(DistributedAgentStackProducerError::RevisionExhausted)?;
    Ok(SourcePlanRevision::new(revision))
}

fn desired_provenance(
    rollout_id: DistributedAgentStackRolloutIdV1,
    revision: SourcePlanRevision,
    predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
    requests: &[DistributedAgentStackApplyRequestV1; 2],
) -> Result<PlanProvenance, DistributedAgentStackProducerError> {
    let provisional = [
        ProvisionalRequestV1 {
            target: requests[0].target(),
            predecessor_slice: predecessors[0].request.target_slice_digest(),
            execution: requests[0].target_execution().clone(),
        },
        ProvisionalRequestV1 {
            target: requests[1].target(),
            predecessor_slice: predecessors[1].request.target_slice_digest(),
            execution: requests[1].target_execution().clone(),
        },
    ];
    desired_provenance_from_executions(
        rollout_id,
        revision,
        predecessors[0].source_scope,
        predecessors[0].source_plan,
        &provisional,
    )
}

fn desired_provenance_from_executions(
    rollout_id: DistributedAgentStackRolloutIdV1,
    revision: SourcePlanRevision,
    source_scope: SourceScopeRef,
    source_plan: SourcePlanRef,
    rows: &[ProvisionalRequestV1; 2],
) -> Result<PlanProvenance, DistributedAgentStackProducerError> {
    let mut digest = Digest32Builder::try_new(TWO_TARGET_DESIRED_DIGEST_DOMAIN)?;
    digest.field_bytes(rollout_id.as_bytes())?;
    digest.field_bytes(source_scope.as_bytes())?;
    digest.field_bytes(source_plan.as_bytes())?;
    digest.field_u64(revision.value())?;
    for row in rows {
        digest.field_bytes(row.target.as_bytes())?;
        digest.field_digest(row.predecessor_slice.value())?;
        digest.field_bytes(row.execution.canonical_wire())?;
    }
    Ok(PlanProvenance::new(
        source_scope,
        source_plan,
        revision,
        SourcePlanDigest::new(digest.finish()),
    ))
}

fn validate_request_pair_shape(
    requests: &[DistributedAgentStackApplyRequestV1; 2],
) -> Result<(), DistributedAgentStackProducerError> {
    if requests[0].target().as_bytes() >= requests[1].target().as_bytes()
        || requests[0].provenance() != requests[1].provenance()
        || requests[0].target_execution().mode()
            != DistributedAgentStackTargetModeV1::DistributedFabricAndAgent
        || requests[1].target_execution().mode()
            != DistributedAgentStackTargetModeV1::DistributedFabricAndAgent
    {
        return Err(DistributedAgentStackProducerError::RequestPairMismatch);
    }
    Ok(())
}

fn validate_request(
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
    request: &DistributedAgentStackApplyRequestV1,
    provenance: PlanProvenance,
    revision: SourcePlanRevision,
) -> Result<(), DistributedAgentStackProducerError> {
    let control = request.control_commitment().control();
    let temporal = request.temporal();
    let authentication = request.authentication();
    let claim = authentication.claim();
    if request.target() != predecessor.target
        || request.provenance() != provenance
        || request.provenance().source_revision() != revision
        || request.expected_runtime_store_instance_id() != predecessor.runtime_store_instance_id
        || control.expected_active()
            != ExpectedActive::Exact(predecessor.request.target_slice_digest())
        || control.writer_context() != &predecessor.writer_context
        || temporal.target_clock_domain() != predecessor.clock_domain
        || temporal.target_clock_generation() != predecessor.clock_generation
        || temporal.original_budget().value() == 0
        || temporal.remaining_budget() != temporal.original_budget()
        || claim.principal() != predecessor.controller_principal
        || claim.key() != predecessor.request_key
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
        || authentication.signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(DistributedAgentStackProducerError::RequestMismatch);
    }
    let projection = DistributedAgentStackProjectionV1::try_from_managed_agent_stack_projection(
        predecessor.request.target_execution().projection().clone(),
    )?;
    request.validate_projection(&projection)?;
    if request.target_execution().predecessor() != predecessor.request.target_execution() {
        return Err(DistributedAgentStackProducerError::RequestMismatch);
    }
    let signature = Signature::from_slice(authentication.signature())
        .map_err(|_| DistributedAgentStackProducerError::RequestMismatch)?;
    VerifyingKey::from_bytes(&predecessor.controller_verifying_key)
        .map_err(|_| DistributedAgentStackProducerError::RequestMismatch)?
        .verify_strict(request.signing_transcript()?.as_bytes(), &signature)
        .map_err(|_| DistributedAgentStackProducerError::RequestMismatch)
}

fn validate_fresh_pair(
    first: FreshDistributedAgentStackApplyV1,
    second: FreshDistributedAgentStackApplyV1,
) -> Result<(), DistributedAgentStackProducerError> {
    if first.operation_id == second.operation_id
        || first.temporal_constraint_id == second.temporal_constraint_id
        || first.authentication_nonce == second.authentication_nonce
    {
        return Err(DistributedAgentStackProducerError::FreshIdentityConflict);
    }
    Ok(())
}

fn validate_fresh_request_pair(
    requests: &[DistributedAgentStackApplyRequestV1; 2],
) -> Result<(), DistributedAgentStackProducerError> {
    if requests[0].operation_id() == requests[1].operation_id()
        || requests[0].temporal().constraint_id() == requests[1].temporal().constraint_id()
        || requests[0].authentication().claim().nonce()
            == requests[1].authentication().claim().nonce()
    {
        return Err(DistributedAgentStackProducerError::FreshIdentityConflict);
    }
    Ok(())
}

fn validate_cross_target_topology(
    requests: &[DistributedAgentStackApplyRequestV1; 2],
) -> Result<(), DistributedAgentStackProducerError> {
    let first = requests[0]
        .target_execution()
        .topology()
        .ok_or(DistributedAgentStackProducerError::RequestPairMismatch)?;
    let second = requests[1]
        .target_execution()
        .topology()
        .ok_or(DistributedAgentStackProducerError::RequestPairMismatch)?;
    let first_to_second = first
        .peers()
        .iter()
        .find(|peer| peer.peer_runtime_host() == requests[1].target())
        .ok_or(DistributedAgentStackProducerError::CrossTargetTopologyMismatch)?;
    let second_to_first = second
        .peers()
        .iter()
        .find(|peer| peer.peer_runtime_host() == requests[0].target())
        .ok_or(DistributedAgentStackProducerError::CrossTargetTopologyMismatch)?;
    let first_auth = first_to_second.authentication();
    let second_auth = second_to_first.authentication();
    if first_to_second.connect_endpoint() != second.remote_listen_endpoint()
        || second_to_first.connect_endpoint() != first.remote_listen_endpoint()
        || first_auth.profile() != second_auth.profile()
        || first_auth.trust_domain_ref() != second_auth.trust_domain_ref()
        || first_auth.trust_anchor_ref() != second_auth.trust_anchor_ref()
    {
        return Err(DistributedAgentStackProducerError::CrossTargetTopologyMismatch);
    }
    Ok(())
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Fail-closed producer and restore failures.
#[derive(Debug)]
pub(crate) enum DistributedAgentStackProducerError {
    Contract,
    ManagedPredecessor(ManagedAgentStackProducerError),
    Digest(DigestBuildError),
    Authentication(ApplyAuthError),
    Temporal(TemporalContractError),
    InvalidRolloutIdentity,
    InvalidFreshIdentity,
    FreshIdentityConflict,
    PredecessorNotCommittedActive,
    TargetsNotStrictlyOrdered,
    PredecessorPairMismatch,
    ControllerKeyMismatch,
    RevisionExhausted,
    RequestPairMismatch,
    CrossTargetTopologyMismatch,
    RequestMismatch,
    RestrictedCarrierMismatch,
    TerminalMismatch,
}

impl From<DistributedAgentStackPlanError> for DistributedAgentStackProducerError {
    fn from(_value: DistributedAgentStackPlanError) -> Self {
        Self::Contract
    }
}

impl From<ManagedAgentStackProducerError> for DistributedAgentStackProducerError {
    fn from(value: ManagedAgentStackProducerError) -> Self {
        Self::ManagedPredecessor(value)
    }
}

impl From<DigestBuildError> for DistributedAgentStackProducerError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ApplyAuthError> for DistributedAgentStackProducerError {
    fn from(value: ApplyAuthError) -> Self {
        Self::Authentication(value)
    }
}

impl From<TemporalContractError> for DistributedAgentStackProducerError {
    fn from(value: TemporalContractError) -> Self {
        Self::Temporal(value)
    }
}

impl fmt::Display for DistributedAgentStackProducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "distributed Agent stack producer rejected: {self:?}"
        )
    }
}

impl std::error::Error for DistributedAgentStackProducerError {}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use paraegox_kernel::digest::{Digest32, Digest32Builder};
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::BoundedDuration;
    use paraegox_runtime_contracts::apply::{PlanWriterContext, WriterTenureProof};
    use paraegox_runtime_contracts::distributed_agent_stack_plan::{
        DistributedFabricCredentialRefV1, DistributedFabricPeerAuthenticationRequirementV1,
        DistributedFabricPeerIdentityRefV1, DistributedFabricPeerPlanV1,
        DistributedFabricTlsEndpointV1, DistributedFabricTopologyV1,
        DistributedFabricTrustAnchorRefV1, DistributedFabricTrustDomainRefV1,
    };
    use paraegox_runtime_contracts::managed_agent_stack_plan::{
        ManagedAgentStackApplyRequestDraftV1, ManagedAgentStackApplyRequestV1,
        ManagedAgentStackProjectionV1, ManagedAgentStackTargetExecutionV1,
    };
    use paraegox_runtime_contracts::managed_fabric_plan::{
        ManagedFabricListenEndpointV1, ManagedFabricManifestProjectionV1,
        ManagedFabricTargetExecutionV1,
    };
    use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
    use paraegox_runtime_contracts::provenance::{
        PlanProvenance, SourcePlanDigest, SourcePlanRef, SourcePlanRevision, SourceScopeRef,
    };
    use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
    use paraegox_runtime_contracts::wire::ApplyAuthKeyRef;

    use super::{
        DistributedAgentStackApplyRequestDraftV1, DistributedAgentStackProducerError,
        DistributedAgentStackRolloutIdV1, DistributedAgentStackRolloutV1,
        DistributedAgentStackTargetRolloutInputV1, FreshDistributedAgentStackApplyV1,
        VerifiedDistributedAgentStackPredecessorV1, produce_distributed_agent_stack_rollout_v1,
        validate_predecessor_pair,
    };

    const STACK_FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_agent_stack_successor_v1.json");

    pub(crate) struct FixtureBundle {
        pub(crate) predecessors: [VerifiedDistributedAgentStackPredecessorV1; 2],
        pub(crate) rollout: DistributedAgentStackRolloutV1,
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("fixture contains non-hex byte"),
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn fixture_hex_after(section: &str, key: &str) -> Vec<u8> {
        let section_start = STACK_FIXTURE
            .find(section)
            .unwrap_or_else(|| panic!("missing fixture section {section}"));
        let key_start = STACK_FIXTURE[section_start..]
            .find(key)
            .map(|offset| section_start + offset + key.len())
            .unwrap_or_else(|| panic!("missing fixture key {key}"));
        let quote_start = STACK_FIXTURE[key_start..]
            .find('"')
            .map(|offset| key_start + offset + 1)
            .unwrap_or_else(|| panic!("missing fixture value for {key}"));
        let quote_end = STACK_FIXTURE[quote_start..]
            .find('"')
            .map(|offset| quote_start + offset)
            .unwrap_or_else(|| panic!("unterminated fixture value for {key}"));
        decode_hex(&STACK_FIXTURE[quote_start..quote_end])
    }

    fn original_request() -> ManagedAgentStackApplyRequestV1 {
        ManagedAgentStackApplyRequestV1::decode(&fixture_hex_after(
            "\"fabric_and_agent\"",
            "\"outer_v7_hex\"",
        ))
        .expect("PXAR v7 fixture")
    }

    fn controller_signer() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    pub(crate) fn runtime_signer(target: RuntimeHostId) -> SigningKey {
        SigningKey::from_bytes(
            &[target.as_bytes()[0]
                .checked_add(0x40)
                .expect("bounded target seed"); 32],
        )
    }

    fn runtime_channel(target: RuntimeHostId) -> ReferenceChannelBindingV1 {
        let seed = target.as_bytes()[0];
        ReferenceChannelBindingV1::try_new(
            target,
            PrincipalRef::from_bytes([seed + 0x50; 16]),
            Digest32::from_bytes([seed + 0x51; 32]),
            Digest32::from_bytes([seed + 0x52; 32]),
        )
        .expect("Runtime terminal channel")
    }

    fn target_execution(target_seed: u8, loopback_port: u16) -> ManagedAgentStackTargetExecutionV1 {
        let original = original_request();
        let original_execution = original.target_execution();
        let mut projection_wire = original_execution
            .fabric()
            .projection()
            .canonical_wire()
            .to_vec();
        projection_wire[38..54].copy_from_slice(&[target_seed; 16]);
        let fabric_projection = ManagedFabricManifestProjectionV1::decode(&projection_wire)
            .expect("retargeted Fabric projection");
        let fabric = ManagedFabricTargetExecutionV1::try_one_managed_fabric_service(
            fabric_projection.clone(),
            original_execution
                .fabric()
                .service()
                .expect("Fabric service"),
            ManagedFabricListenEndpointV1::try_new(&format!("tcp/127.0.0.1:{loopback_port}"))
                .expect("loopback endpoint"),
        )
        .expect("retargeted Fabric execution");
        let projection =
            ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(fabric_projection)
                .expect("retargeted Agent projection");
        ManagedAgentStackTargetExecutionV1::try_fabric_and_agent(
            projection,
            fabric,
            original_execution.agent().expect("Agent service").clone(),
        )
        .expect("retargeted Agent stack execution")
    }

    fn target_specific_predecessor_provenance(
        target: RuntimeHostId,
        source_scope: SourceScopeRef,
        source_plan: SourcePlanRef,
        source_revision: SourcePlanRevision,
    ) -> PlanProvenance {
        let mut digest = Digest32Builder::try_new(
            b"paraegox.deployment.tests.target-specific-predecessor.sha256.v1",
        )
        .expect("predecessor provenance digest domain");
        digest
            .field_bytes(target.as_bytes())
            .and_then(|builder| builder.field_bytes(source_scope.as_bytes()))
            .and_then(|builder| builder.field_bytes(source_plan.as_bytes()))
            .and_then(|builder| builder.field_u64(source_revision.value()))
            .expect("target-specific predecessor provenance");
        PlanProvenance::new(
            source_scope,
            source_plan,
            source_revision,
            SourcePlanDigest::new(digest.finish()),
        )
    }

    fn with_predecessor_provenance(
        mut predecessor: VerifiedDistributedAgentStackPredecessorV1,
        provenance: PlanProvenance,
    ) -> VerifiedDistributedAgentStackPredecessorV1 {
        let request = predecessor.request();
        let draft = ManagedAgentStackApplyRequestDraftV1::try_new(
            request.target_execution().clone(),
            provenance,
            request.control_commitment().control().clone(),
            request.temporal(),
            request.expected_runtime_store_instance_id(),
            request.authentication().claim().clone(),
        )
        .expect("replacement predecessor provenance");
        let signature = controller_signer().sign(
            draft
                .signing_transcript()
                .expect("replacement predecessor transcript")
                .as_bytes(),
        );
        predecessor.request = draft
            .finalize(&signature.to_bytes())
            .expect("replacement signed predecessor");
        predecessor.source_scope = provenance.source_scope();
        predecessor.source_plan = provenance.source_plan();
        predecessor
    }

    fn distinct_writer_context(context: &PlanWriterContext) -> PlanWriterContext {
        let proof = context.proof();
        let replacement = WriterTenureProof::try_new(
            proof.authority(),
            proof.claim(),
            &[0xed; 32],
            proof.signature(),
        )
        .expect("replacement writer proof");
        PlanWriterContext::try_new(context.writer(), context.epoch(), replacement)
            .expect("replacement writer context")
    }

    fn predecessor(
        target_seed: u8,
        loopback_port: u16,
        operation_seed: u8,
    ) -> VerifiedDistributedAgentStackPredecessorV1 {
        let original = original_request();
        let signer = controller_signer();
        let execution = target_execution(target_seed, loopback_port);
        let target = RuntimeHostId::from_bytes([target_seed; 16]);
        let original_provenance = original.provenance();
        let provenance = target_specific_predecessor_provenance(
            target,
            original_provenance.source_scope(),
            original_provenance.source_plan(),
            original_provenance.source_revision(),
        );
        let control = paraegox_runtime_contracts::apply::RuntimeApplyControl::new(
            original
                .control_commitment()
                .control()
                .writer_context()
                .clone(),
            original.control_commitment().control().expected_active(),
            paraegox_runtime_contracts::apply::ApplyOperationId::from_bytes([operation_seed; 16]),
        );
        let draft = ManagedAgentStackApplyRequestDraftV1::try_new(
            execution,
            provenance,
            control,
            original.temporal(),
            original.expected_runtime_store_instance_id(),
            original.authentication().claim().clone(),
        )
        .expect("retargeted PXAR v7 draft");
        let signature = signer.sign(
            draft
                .signing_transcript()
                .expect("PXAR v7 transcript")
                .as_bytes(),
        );
        let request = draft
            .finalize(&signature.to_bytes())
            .expect("signed PXAR v7 predecessor");
        VerifiedDistributedAgentStackPredecessorV1 {
            target,
            source_scope: request.provenance().source_scope(),
            source_plan: request.provenance().source_plan(),
            writer_context: request
                .control_commitment()
                .control()
                .writer_context()
                .clone(),
            controller_principal: request.authentication().claim().principal(),
            request_key: request.authentication().claim().key(),
            controller_verifying_key: signer.verifying_key().to_bytes(),
            clock_domain: request.temporal().target_clock_domain(),
            clock_generation: request.temporal().target_clock_generation(),
            runtime_store_instance_id: request.expected_runtime_store_instance_id(),
            runtime_channel: runtime_channel(request.target()),
            runtime_response_key: ApplyAuthKeyRef::from_bytes([target_seed + 0x60; 16]),
            runtime_response_public_key: runtime_signer(request.target()).verifying_key(),
            predecessor_runtime_host_epoch: 5,
            predecessor_completion_snapshot_sequence: 7,
            predecessor_fabric_generation: ManagedServiceGeneration::try_new(1)
                .expect("predecessor Fabric generation"),
            predecessor_agent_generation: ManagedServiceGeneration::try_new(2)
                .expect("predecessor Agent generation"),
            request,
        }
    }

    fn authentication(
        local_credential_seed: u8,
        expected_peer_seed: u8,
    ) -> DistributedFabricPeerAuthenticationRequirementV1 {
        DistributedFabricPeerAuthenticationRequirementV1::try_mutual_tls(
            DistributedFabricTrustDomainRefV1::try_from_bytes([0x91; 16]).expect("trust domain"),
            DistributedFabricCredentialRefV1::try_from_bytes([local_credential_seed; 16])
                .expect("local credential"),
            DistributedFabricTrustAnchorRefV1::try_from_bytes([0x93; 16]).expect("trust anchor"),
            DistributedFabricPeerIdentityRefV1::try_from_bytes([expected_peer_seed; 16])
                .expect("expected peer"),
        )
        .expect("mTLS requirement")
    }

    fn topology(
        local: &VerifiedDistributedAgentStackPredecessorV1,
        local_listener: &str,
        remote: RuntimeHostId,
        remote_listener: &str,
        local_credential_seed: u8,
        expected_peer_seed: u8,
    ) -> DistributedFabricTopologyV1 {
        DistributedFabricTopologyV1::try_new(
            local.target(),
            local
                .request()
                .target_execution()
                .fabric()
                .listen_endpoint()
                .expect("predecessor loopback")
                .clone(),
            DistributedFabricTlsEndpointV1::try_new(local_listener).expect("TLS listener"),
            vec![
                DistributedFabricPeerPlanV1::try_new(
                    remote,
                    DistributedFabricTlsEndpointV1::try_new(remote_listener)
                        .expect("TLS connect endpoint"),
                    authentication(local_credential_seed, expected_peer_seed),
                )
                .expect("peer row"),
            ],
        )
        .expect("distributed topology")
    }

    fn fresh(seed: u8) -> FreshDistributedAgentStackApplyV1 {
        FreshDistributedAgentStackApplyV1::try_new(
            [seed; 16],
            [seed + 1; 16],
            [seed + 2; 32],
            BoundedDuration::from_nanos(30_000_000_000),
        )
        .expect("fresh distributed apply")
    }

    fn inputs(
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> [DistributedAgentStackTargetRolloutInputV1; 2] {
        let first_listener = "tls/192.0.2.11:7447";
        let second_listener = "tls/192.0.2.22:7447";
        [
            DistributedAgentStackTargetRolloutInputV1::new(
                predecessors[0].clone(),
                topology(
                    &predecessors[0],
                    first_listener,
                    predecessors[1].target(),
                    second_listener,
                    0xa1,
                    0xb2,
                ),
                fresh(0x61),
            ),
            DistributedAgentStackTargetRolloutInputV1::new(
                predecessors[1].clone(),
                topology(
                    &predecessors[1],
                    second_listener,
                    predecessors[0].target(),
                    first_listener,
                    0xa2,
                    0xb1,
                ),
                fresh(0x71),
            ),
        ]
    }

    pub(crate) fn fixture_bundle() -> FixtureBundle {
        let predecessors = [predecessor(0x11, 7447, 0x31), predecessor(0x22, 7448, 0x32)];
        let rollout = produce_distributed_agent_stack_rollout_v1(
            DistributedAgentStackRolloutIdV1::try_from_bytes([0x51; 16]).expect("rollout id"),
            inputs(&predecessors),
            &controller_signer(),
        )
        .expect("signed two-target rollout");
        FixtureBundle {
            predecessors,
            rollout,
        }
    }

    pub(crate) fn conflicting_rollout_same_id(
        predecessors: &[VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> DistributedAgentStackRolloutV1 {
        let [first, second] = inputs(predecessors);
        produce_distributed_agent_stack_rollout_v1(
            DistributedAgentStackRolloutIdV1::try_from_bytes([0x51; 16]).expect("same rollout id"),
            [
                DistributedAgentStackTargetRolloutInputV1::new(
                    first.predecessor,
                    first.topology,
                    fresh(0x62),
                ),
                DistributedAgentStackTargetRolloutInputV1::new(
                    second.predecessor,
                    second.topology,
                    fresh(0x72),
                ),
            ],
            &controller_signer(),
        )
        .expect("conflicting requests under same rollout id")
    }

    #[test]
    fn producer_resigns_two_sorted_pxar8_rows_and_restore_reverifies_them() {
        let fixture = fixture_bundle();
        let requests = fixture.rollout.requests();
        assert_eq!(&requests[0].canonical_wire()[..6], b"PXAR\0\x08");
        assert_eq!(&requests[1].canonical_wire()[..6], b"PXAR\0\x08");
        assert!(requests[0].target().as_bytes() < requests[1].target().as_bytes());
        assert_eq!(requests[0].provenance(), requests[1].provenance());
        assert_eq!(
            fixture.rollout.revision().value(),
            fixture.predecessors[0]
                .request()
                .provenance()
                .source_revision()
                .value()
                + 1
        );
        for request in requests {
            let signature =
                ed25519_dalek::Signature::from_slice(request.authentication().signature())
                    .expect("Ed25519 signature");
            VerifyingKey::from_bytes(&controller_signer().verifying_key().to_bytes())
                .expect("Controller verifying key")
                .verify_strict(
                    request
                        .signing_transcript()
                        .expect("PXAR v8 transcript")
                        .as_bytes(),
                    &signature,
                )
                .expect("fresh PXAR v8 signature");
        }
        assert_ne!(
            requests[0].authentication().signature(),
            fixture.predecessors[0]
                .request()
                .authentication()
                .signature()
        );
        let restored = DistributedAgentStackRolloutV1::try_restore(
            fixture.rollout.rollout_id(),
            [&fixture.predecessors[0], &fixture.predecessors[1]],
            requests.clone(),
        )
        .expect("authenticated durable restore");
        assert_eq!(restored, fixture.rollout);
    }

    #[test]
    fn predecessor_pair_accepts_distinct_target_specific_source_plan_digests() {
        let predecessors = [predecessor(0x11, 7447, 0x31), predecessor(0x22, 7448, 0x32)];
        let first = predecessors[0].request().provenance();
        let second = predecessors[1].request().provenance();
        assert_eq!(first.source_scope(), second.source_scope());
        assert_eq!(first.source_plan(), second.source_plan());
        assert_eq!(first.source_revision(), second.source_revision());
        assert_ne!(first.source_plan_digest(), second.source_plan_digest());
        validate_predecessor_pair([&predecessors[0], &predecessors[1]])
            .expect("target-specific predecessor plan digests are admitted");

        let rollout = produce_distributed_agent_stack_rollout_v1(
            DistributedAgentStackRolloutIdV1::try_from_bytes([0x57; 16]).expect("rollout id"),
            inputs(&predecessors),
            &controller_signer(),
        )
        .expect("two genuine target-specific predecessor rows");
        assert_ne!(
            rollout.provenance().source_plan_digest(),
            first.source_plan_digest()
        );
        assert_ne!(
            rollout.provenance().source_plan_digest(),
            second.source_plan_digest()
        );
    }

    #[test]
    fn predecessor_pair_rejects_different_source_revisions() {
        let mut predecessors = [predecessor(0x11, 7447, 0x31), predecessor(0x22, 7448, 0x32)];
        let current = predecessors[1].request().provenance();
        let mismatched_revision = SourcePlanRevision::new(
            current
                .source_revision()
                .value()
                .checked_add(1)
                .expect("fixture revision has successor"),
        );
        let mismatched = target_specific_predecessor_provenance(
            predecessors[1].target(),
            current.source_scope(),
            current.source_plan(),
            mismatched_revision,
        );
        predecessors[1] = with_predecessor_provenance(predecessors[1].clone(), mismatched);

        let error = produce_distributed_agent_stack_rollout_v1(
            DistributedAgentStackRolloutIdV1::try_from_bytes([0x58; 16]).expect("rollout id"),
            inputs(&predecessors),
            &controller_signer(),
        )
        .expect_err("predecessor revisions must match");
        assert!(matches!(
            error,
            DistributedAgentStackProducerError::PredecessorPairMismatch
        ));
    }

    #[test]
    fn predecessor_pair_rejects_every_other_shared_owner_pin_mismatch() {
        let predecessors = [predecessor(0x11, 7447, 0x31), predecessor(0x22, 7448, 0x32)];
        let second_provenance = predecessors[1].request().provenance();

        let mut scope_mismatch = predecessors[1].clone();
        scope_mismatch.source_scope = SourceScopeRef::from_bytes([0xd1; 16]);
        let plan_mismatch = with_predecessor_provenance(
            predecessors[1].clone(),
            target_specific_predecessor_provenance(
                predecessors[1].target(),
                second_provenance.source_scope(),
                SourcePlanRef::from_bytes([0xd2; 16]),
                second_provenance.source_revision(),
            ),
        );
        let mut writer_mismatch = predecessors[1].clone();
        writer_mismatch.writer_context = distinct_writer_context(&writer_mismatch.writer_context);
        let mut principal_mismatch = predecessors[1].clone();
        principal_mismatch.controller_principal = PrincipalRef::from_bytes([0xd3; 16]);
        let mut request_key_mismatch = predecessors[1].clone();
        request_key_mismatch.request_key = ApplyAuthKeyRef::from_bytes([0xd4; 16]);
        let mut verifying_key_mismatch = predecessors[1].clone();
        verifying_key_mismatch.controller_verifying_key = SigningKey::from_bytes(&[0xd5; 32])
            .verifying_key()
            .to_bytes();

        for mismatch in [
            scope_mismatch,
            plan_mismatch,
            writer_mismatch,
            principal_mismatch,
            request_key_mismatch,
            verifying_key_mismatch,
        ] {
            assert!(matches!(
                validate_predecessor_pair([&predecessors[0], &mismatch]),
                Err(DistributedAgentStackProducerError::PredecessorPairMismatch)
            ));
        }
    }

    #[test]
    fn contract_valid_but_wrongly_signed_pxar8_is_not_authenticated() {
        let fixture = fixture_bundle();
        let valid = &fixture.rollout.requests()[0];
        let draft = DistributedAgentStackApplyRequestDraftV1::try_new(
            valid.target_execution().clone(),
            valid.provenance(),
            valid.control_commitment().control().clone(),
            valid.temporal(),
            valid.expected_runtime_store_instance_id(),
            valid.authentication().claim().clone(),
        )
        .expect("contract-valid PXAR v8 draft");
        let wrong = draft
            .finalize(&[0x99; 64])
            .expect("opaque signature bytes are framing-valid");
        let error = DistributedAgentStackRolloutV1::try_restore(
            fixture.rollout.rollout_id(),
            [&fixture.predecessors[0], &fixture.predecessors[1]],
            [wrong, fixture.rollout.requests()[1].clone()],
        )
        .expect_err("framing-valid signature must fail authentication");
        assert!(matches!(
            error,
            DistributedAgentStackProducerError::RequestMismatch
        ));
    }

    #[test]
    fn producer_rejects_reversed_targets_and_cross_target_endpoint_drift() {
        let predecessors = [predecessor(0x11, 7447, 0x31), predecessor(0x22, 7448, 0x32)];
        let [first, second] = inputs(&predecessors);
        let reversed = produce_distributed_agent_stack_rollout_v1(
            DistributedAgentStackRolloutIdV1::try_from_bytes([0x52; 16]).expect("rollout id"),
            [second.clone(), first.clone()],
            &controller_signer(),
        )
        .expect_err("target rows must arrive in canonical order");
        assert!(matches!(
            reversed,
            DistributedAgentStackProducerError::TargetsNotStrictlyOrdered
        ));

        let mismatched_topology = topology(
            &predecessors[1],
            "tls/192.0.2.22:7447",
            predecessors[0].target(),
            "tls/192.0.2.33:7447",
            0xa2,
            0xb1,
        );
        let drifted = produce_distributed_agent_stack_rollout_v1(
            DistributedAgentStackRolloutIdV1::try_from_bytes([0x53; 16]).expect("rollout id"),
            [
                first,
                DistributedAgentStackTargetRolloutInputV1::new(
                    predecessors[1].clone(),
                    mismatched_topology,
                    fresh(0x71),
                ),
            ],
            &controller_signer(),
        )
        .expect_err("cross-target endpoints must be reciprocal");
        assert!(matches!(
            drifted,
            DistributedAgentStackProducerError::CrossTargetTopologyMismatch
        ));
    }

    #[test]
    fn producer_rejects_wrong_controller_key_and_duplicate_fresh_identities() {
        let predecessors = [predecessor(0x11, 7447, 0x31), predecessor(0x22, 7448, 0x32)];
        let wrong_key = produce_distributed_agent_stack_rollout_v1(
            DistributedAgentStackRolloutIdV1::try_from_bytes([0x54; 16]).expect("rollout id"),
            inputs(&predecessors),
            &SigningKey::from_bytes(&[0x42; 32]),
        )
        .expect_err("wrong Controller signer must fail closed");
        assert!(matches!(
            wrong_key,
            DistributedAgentStackProducerError::ControllerKeyMismatch
        ));

        let [first, second] = inputs(&predecessors);
        let duplicate = DistributedAgentStackTargetRolloutInputV1::new(
            second.predecessor,
            second.topology,
            first.fresh,
        );
        let error = produce_distributed_agent_stack_rollout_v1(
            DistributedAgentStackRolloutIdV1::try_from_bytes([0x55; 16]).expect("rollout id"),
            [first, duplicate],
            &controller_signer(),
        )
        .expect_err("fresh identities must be target-unique");
        assert!(matches!(
            error,
            DistributedAgentStackProducerError::FreshIdentityConflict
        ));
    }

    #[test]
    fn desired_digest_changes_when_rollout_identity_changes() {
        let fixture = fixture_bundle();
        let inputs = inputs(&fixture.predecessors);
        let other = produce_distributed_agent_stack_rollout_v1(
            DistributedAgentStackRolloutIdV1::try_from_bytes([0x56; 16]).expect("rollout id"),
            inputs,
            &controller_signer(),
        )
        .expect("second rollout identity");
        assert_ne!(
            fixture.rollout.provenance().source_plan_digest(),
            other.provenance().source_plan_digest()
        );
        assert_ne!(
            Digest32::from_bytes([0; 32]),
            *fixture.rollout.provenance().source_plan_digest().value()
        );
    }
}
