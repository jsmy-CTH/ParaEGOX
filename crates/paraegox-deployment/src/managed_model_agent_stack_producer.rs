//! Owner-private Deployment producer for the fixed PXTE v8/PXAR v9
//! Fabric/Model/Agent successor.
//!
//! PXAR v6 remains the predecessor authority. The embedded PXTE v6 value is
//! desired structure assembled here; its presence never claims that PXAR v7
//! executed. Provider, Agent, Model, and adapter selections are all explicit.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::time::BoundedDuration;
use paraegox_runtime_contracts::apply::{ApplyOperationId, ExpectedActive, RuntimeApplyControl};
use paraegox_runtime_contracts::managed_agent_stack_plan::{
    ManagedAgentServicePlanV1, ManagedAgentStackProjectionV1, ManagedAgentStackTargetExecutionV1,
};
use paraegox_runtime_contracts::managed_fabric_plan::{
    ManagedFabricTargetExecutionV1, ManagedFabricTargetModeV1,
};
use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
    ManagedModelAgentStackApplyRequestDraftV1, ManagedModelAgentStackApplyRequestV1,
    ManagedModelAgentStackPlanError, ManagedModelAgentStackProjectionV1,
    ManagedModelAgentStackTargetExecutionV1, ManagedModelAgentStackTargetModeV1,
    ManagedModelServicePlanV1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceLifecycleStage;
use paraegox_runtime_contracts::provenance::{
    PlanProvenance, SourcePlanDigest, SourcePlanRevision, TargetSliceDigest,
};
use paraegox_runtime_contracts::temporal::{
    ApplyTemporalConstraint, TemporalConstraintId, TemporalContractError,
};
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthError, ApplyRequestAuthClaim};

use crate::managed_fabric_producer::{
    ManagedFabricProducerError, VerifiedManagedFabricProducerContextV1,
};

const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;
const STACK_DESIRED_DIGEST_DOMAIN: &[u8] =
    b"paraegox.deployment.managed-model-agent-stack-desired.sha256.v1";

/// Explicit requested sibling stack assembled over active PXAR v6 authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackActivationV1 {
    expected_fabric: ManagedFabricTargetExecutionV1,
    agent: ManagedAgentServicePlanV1,
    model: ManagedModelServicePlanV1,
}

impl ManagedModelAgentStackActivationV1 {
    pub(crate) fn try_new(
        expected_fabric: ManagedFabricTargetExecutionV1,
        agent: ManagedAgentServicePlanV1,
        model: ManagedModelServicePlanV1,
    ) -> Result<Self, ManagedModelAgentStackProducerError> {
        if expected_fabric.mode() != ManagedFabricTargetModeV1::OneManagedFabricService {
            return Err(ManagedModelAgentStackProducerError::FabricChangeRequiresEmpty);
        }
        Ok(Self {
            expected_fabric,
            agent,
            model,
        })
    }

    #[must_use]
    pub(crate) const fn expected_fabric(&self) -> &ManagedFabricTargetExecutionV1 {
        &self.expected_fabric
    }

    #[must_use]
    pub(crate) const fn agent(&self) -> &ManagedAgentServicePlanV1 {
        &self.agent
    }

    #[must_use]
    pub(crate) const fn model(&self) -> &ManagedModelServicePlanV1 {
        &self.model
    }
}

/// Fresh request identities consumed only if no PXAR v9 is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreshManagedModelAgentStackApplyV1 {
    operation_id: [u8; 16],
    temporal_constraint_id: [u8; 16],
    authentication_nonce: [u8; 32],
}

impl FreshManagedModelAgentStackApplyV1 {
    pub(crate) fn try_new(
        operation_id: [u8; 16],
        temporal_constraint_id: [u8; 16],
        authentication_nonce: [u8; 32],
    ) -> Result<Self, ManagedModelAgentStackProducerError> {
        if bytes_are_zero(&operation_id)
            || bytes_are_zero(&temporal_constraint_id)
            || bytes_are_zero(&authentication_nonce)
            || operation_id == temporal_constraint_id
        {
            return Err(ManagedModelAgentStackProducerError::InvalidFreshIdentity);
        }
        Ok(Self {
            operation_id,
            temporal_constraint_id,
            authentication_nonce,
        })
    }
}

/// Exact desired A2 stack derived from the current pin and active PXAR v6.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelAgentStackDesiredPlanV1 {
    cutover_marker_digest: Digest32,
    predecessor_slice_digest: TargetSliceDigest,
    revision: SourcePlanRevision,
    provenance: PlanProvenance,
    execution: ManagedModelAgentStackTargetExecutionV1,
}

impl ManagedModelAgentStackDesiredPlanV1 {
    pub(crate) fn try_activate(
        context: &VerifiedManagedFabricProducerContextV1,
        cutover_marker_digest: Digest32,
        predecessor_revision: SourcePlanRevision,
        predecessor_execution: &ManagedFabricTargetExecutionV1,
        predecessor_slice_digest: TargetSliceDigest,
        activation: &ManagedModelAgentStackActivationV1,
    ) -> Result<Self, ManagedModelAgentStackProducerError> {
        if activation.expected_fabric != *predecessor_execution
            || predecessor_execution.mode() != ManagedFabricTargetModeV1::OneManagedFabricService
            || predecessor_execution.projection() != context.projection()
        {
            return Err(ManagedModelAgentStackProducerError::FabricChangeRequiresEmpty);
        }
        let agent_projection = ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(
            context.projection().clone(),
        )?;
        let embedded = ManagedAgentStackTargetExecutionV1::try_fabric_and_agent(
            agent_projection.clone(),
            predecessor_execution.clone(),
            activation.agent.clone(),
        )?;
        let projection =
            ManagedModelAgentStackProjectionV1::try_from_managed_agent_stack_projection(
                agent_projection,
            )?;
        let execution = ManagedModelAgentStackTargetExecutionV1::try_fabric_model_and_agent(
            projection,
            embedded,
            activation.model,
        )?;
        let revision = predecessor_revision
            .value()
            .checked_add(1)
            .ok_or(ManagedModelAgentStackProducerError::RevisionExhausted)?;
        Self::try_restore(
            context,
            cutover_marker_digest,
            predecessor_slice_digest,
            revision,
            execution.canonical_wire(),
        )
    }

    pub(crate) fn try_restore(
        context: &VerifiedManagedFabricProducerContextV1,
        cutover_marker_digest: Digest32,
        predecessor_slice_digest: TargetSliceDigest,
        revision: u64,
        execution_wire: &[u8],
    ) -> Result<Self, ManagedModelAgentStackProducerError> {
        if digest_is_zero(cutover_marker_digest)
            || digest_is_zero(*predecessor_slice_digest.value())
            || revision == 0
        {
            return Err(ManagedModelAgentStackProducerError::InvalidDesiredPlan);
        }
        let execution = ManagedModelAgentStackTargetExecutionV1::decode(execution_wire)?;
        let agent_projection = ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(
            context.projection().clone(),
        )?;
        let projection =
            ManagedModelAgentStackProjectionV1::try_from_managed_agent_stack_projection(
                agent_projection,
            )?;
        if execution.projection() != &projection {
            return Err(ManagedModelAgentStackProducerError::ProjectionMismatch);
        }
        let revision = SourcePlanRevision::new(revision);
        let mut digest = Digest32Builder::try_new(STACK_DESIRED_DIGEST_DOMAIN)?;
        digest.field_digest(&cutover_marker_digest)?;
        digest.field_bytes(context.target().as_bytes())?;
        digest.field_bytes(context.source_scope().as_bytes())?;
        digest.field_bytes(context.source_plan().as_bytes())?;
        digest.field_u64(revision.value())?;
        digest.field_bytes(predecessor_slice_digest.value().as_bytes())?;
        digest.field_bytes(execution.canonical_wire())?;
        let provenance = PlanProvenance::new(
            context.source_scope(),
            context.source_plan(),
            revision,
            SourcePlanDigest::new(digest.finish()),
        );
        Ok(Self {
            cutover_marker_digest,
            predecessor_slice_digest,
            revision,
            provenance,
            execution,
        })
    }

    pub(crate) fn try_empty_deactivate(
        context: &VerifiedManagedFabricProducerContextV1,
        cutover_marker_digest: Digest32,
        active_desired: &Self,
        active_request: &ManagedModelAgentStackApplyRequestV1,
    ) -> Result<Self, ManagedModelAgentStackProducerError> {
        if active_desired.execution().mode()
            != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
            || active_request.target_execution() != active_desired.execution()
            || active_request.provenance() != active_desired.provenance()
        {
            return Err(ManagedModelAgentStackProducerError::InvalidDesiredPlan);
        }
        let agent_projection = ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(
            context.projection().clone(),
        )?;
        let projection =
            ManagedModelAgentStackProjectionV1::try_from_managed_agent_stack_projection(
                agent_projection,
            )?;
        let execution = ManagedModelAgentStackTargetExecutionV1::try_empty_deactivate(projection)?;
        let revision = active_desired
            .revision()
            .value()
            .checked_add(1)
            .ok_or(ManagedModelAgentStackProducerError::RevisionExhausted)?;
        Self::try_restore(
            context,
            cutover_marker_digest,
            active_request.target_slice_digest(),
            revision,
            execution.canonical_wire(),
        )
    }

    #[must_use]
    pub(crate) const fn cutover_marker_digest(&self) -> Digest32 {
        self.cutover_marker_digest
    }

    #[must_use]
    pub(crate) const fn predecessor_slice_digest(&self) -> TargetSliceDigest {
        self.predecessor_slice_digest
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
    pub(crate) const fn execution(&self) -> &ManagedModelAgentStackTargetExecutionV1 {
        &self.execution
    }
}

pub(crate) fn produce_managed_model_agent_stack_request_v1(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedModelAgentStackDesiredPlanV1,
    fresh: FreshManagedModelAgentStackApplyV1,
    controller_signer: &SigningKey,
) -> Result<ManagedModelAgentStackApplyRequestV1, ManagedModelAgentStackProducerError> {
    let budget = active_stack_lifecycle_budget(desired)?;
    produce_request_with_budget(context, desired, fresh, controller_signer, budget)
}

pub(crate) fn produce_managed_model_agent_stack_empty_request_v1(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedModelAgentStackDesiredPlanV1,
    archived_active_execution: &ManagedModelAgentStackTargetExecutionV1,
    fresh: FreshManagedModelAgentStackApplyV1,
    controller_signer: &SigningKey,
) -> Result<ManagedModelAgentStackApplyRequestV1, ManagedModelAgentStackProducerError> {
    if desired.execution().mode() != ManagedModelAgentStackTargetModeV1::EmptyDeactivate {
        return Err(ManagedModelAgentStackProducerError::InvalidDesiredPlan);
    }
    let budget = empty_stack_lifecycle_budget(archived_active_execution)?;
    produce_request_with_budget(context, desired, fresh, controller_signer, budget)
}

fn produce_request_with_budget(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedModelAgentStackDesiredPlanV1,
    fresh: FreshManagedModelAgentStackApplyV1,
    controller_signer: &SigningKey,
    budget: BoundedDuration,
) -> Result<ManagedModelAgentStackApplyRequestV1, ManagedModelAgentStackProducerError> {
    if controller_signer.verifying_key().to_bytes() != context.controller_verifying_key()
        || desired
            .execution()
            .projection()
            .managed_agent_stack_projection()
            .managed_fabric_projection()
            != context.projection()
        || desired.provenance().source_scope() != context.source_scope()
        || desired.provenance().source_plan() != context.source_plan()
    {
        return Err(ManagedModelAgentStackProducerError::ControllerOrDesiredMismatch);
    }
    let control = RuntimeApplyControl::new(
        context.writer_context().clone(),
        ExpectedActive::Exact(desired.predecessor_slice_digest()),
        ApplyOperationId::from_bytes(fresh.operation_id),
    );
    let temporal = ApplyTemporalConstraint::try_new(
        TemporalConstraintId::from_bytes(fresh.temporal_constraint_id),
        context.clock_domain(),
        context.clock_generation(),
        budget,
        budget,
    )?;
    let claim = ApplyRequestAuthClaim::try_new(
        context.controller_principal(),
        context.request_key(),
        ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)?,
        ED25519_ALGORITHM_VERSION,
        &fresh.authentication_nonce,
    )?;
    let draft = ManagedModelAgentStackApplyRequestDraftV1::try_new(
        desired.execution().clone(),
        desired.provenance(),
        control,
        temporal,
        context.runtime_store_instance_id(),
        claim,
    )?;
    let signature = controller_signer.sign(draft.signing_transcript()?.as_bytes());
    let request = draft.finalize(&signature.to_bytes())?;
    validate_request_with_budget(context, desired, &request, budget)?;
    Ok(request)
}

pub(crate) fn validate_managed_model_agent_stack_request_v1(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedModelAgentStackDesiredPlanV1,
    request: &ManagedModelAgentStackApplyRequestV1,
) -> Result<(), ManagedModelAgentStackProducerError> {
    validate_request_with_budget(
        context,
        desired,
        request,
        active_stack_lifecycle_budget(desired)?,
    )
}

pub(crate) fn validate_managed_model_agent_stack_empty_request_v1(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedModelAgentStackDesiredPlanV1,
    archived_active_execution: &ManagedModelAgentStackTargetExecutionV1,
    request: &ManagedModelAgentStackApplyRequestV1,
) -> Result<(), ManagedModelAgentStackProducerError> {
    if desired.execution().mode() != ManagedModelAgentStackTargetModeV1::EmptyDeactivate {
        return Err(ManagedModelAgentStackProducerError::InvalidDesiredPlan);
    }
    validate_request_with_budget(
        context,
        desired,
        request,
        empty_stack_lifecycle_budget(archived_active_execution)?,
    )
}

fn validate_request_with_budget(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedModelAgentStackDesiredPlanV1,
    request: &ManagedModelAgentStackApplyRequestV1,
    lifecycle_budget: BoundedDuration,
) -> Result<(), ManagedModelAgentStackProducerError> {
    let control = request.control_commitment().control();
    let temporal = request.temporal();
    let authentication = request.authentication();
    let claim = authentication.claim();
    if request.target() != context.target()
        || request.target_execution() != desired.execution()
        || request.provenance() != desired.provenance()
        || request.expected_runtime_store_instance_id() != context.runtime_store_instance_id()
        || control.expected_active() != ExpectedActive::Exact(desired.predecessor_slice_digest())
        || control.writer_context() != context.writer_context()
        || temporal.target_clock_domain() != context.clock_domain()
        || temporal.target_clock_generation() != context.clock_generation()
        || temporal.original_budget() != lifecycle_budget
        || temporal.remaining_budget() != lifecycle_budget
        || claim.principal() != context.controller_principal()
        || claim.key() != context.request_key()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
        || authentication.signature().len() != ED25519_SIGNATURE_BYTES
    {
        return Err(ManagedModelAgentStackProducerError::RequestMismatch);
    }
    let agent_projection = ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(
        context.projection().clone(),
    )?;
    let projection = ManagedModelAgentStackProjectionV1::try_from_managed_agent_stack_projection(
        agent_projection,
    )?;
    request.validate_projection(&projection)?;
    let signature: [u8; ED25519_SIGNATURE_BYTES] = authentication
        .signature()
        .try_into()
        .map_err(|_| ManagedModelAgentStackProducerError::RequestMismatch)?;
    VerifyingKey::from_bytes(&context.controller_verifying_key())
        .map_err(|_| ManagedModelAgentStackProducerError::RequestMismatch)?
        .verify_strict(
            request.signing_transcript()?.as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| ManagedModelAgentStackProducerError::RequestMismatch)
}

fn active_stack_lifecycle_budget(
    desired: &ManagedModelAgentStackDesiredPlanV1,
) -> Result<BoundedDuration, ManagedModelAgentStackProducerError> {
    if desired.execution().mode() != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent {
        return Err(ManagedModelAgentStackProducerError::InvalidDesiredPlan);
    }
    let agent = desired
        .execution()
        .managed_agent_stack()
        .agent()
        .ok_or(ManagedModelAgentStackProducerError::InvalidDesiredPlan)?;
    let model = desired
        .execution()
        .model()
        .ok_or(ManagedModelAgentStackProducerError::InvalidDesiredPlan)?;
    let mut total = 0_u64;
    for service in [model.service(), agent.service()] {
        for stage in [
            ManagedServiceLifecycleStage::Prepare,
            ManagedServiceLifecycleStage::Start,
            ManagedServiceLifecycleStage::Readiness,
        ] {
            total = total
                .checked_add(service.lifecycle_budgets().for_stage(stage).value())
                .ok_or(ManagedModelAgentStackProducerError::LifecycleBudgetOverflow)?;
        }
    }
    bounded_nonzero(total)
}

fn empty_stack_lifecycle_budget(
    archived: &ManagedModelAgentStackTargetExecutionV1,
) -> Result<BoundedDuration, ManagedModelAgentStackProducerError> {
    if archived.mode() != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent {
        return Err(ManagedModelAgentStackProducerError::InvalidDesiredPlan);
    }
    let agent = archived
        .managed_agent_stack()
        .agent()
        .ok_or(ManagedModelAgentStackProducerError::InvalidDesiredPlan)?;
    let fabric = archived
        .managed_agent_stack()
        .fabric()
        .service()
        .ok_or(ManagedModelAgentStackProducerError::InvalidDesiredPlan)?;
    let model = archived
        .model()
        .ok_or(ManagedModelAgentStackProducerError::InvalidDesiredPlan)?;
    let mut total = 0_u64;
    for service in [agent.service(), model.service(), fabric] {
        for stage in [
            ManagedServiceLifecycleStage::Drain,
            ManagedServiceLifecycleStage::Stop,
        ] {
            total = total
                .checked_add(service.lifecycle_budgets().for_stage(stage).value())
                .ok_or(ManagedModelAgentStackProducerError::LifecycleBudgetOverflow)?;
        }
    }
    bounded_nonzero(total)
}

fn bounded_nonzero(value: u64) -> Result<BoundedDuration, ManagedModelAgentStackProducerError> {
    if value == 0 {
        return Err(ManagedModelAgentStackProducerError::InvalidDesiredPlan);
    }
    Ok(BoundedDuration::from_nanos(value))
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn digest_is_zero(value: Digest32) -> bool {
    bytes_are_zero(value.as_bytes())
}

#[derive(Debug)]
pub(crate) enum ManagedModelAgentStackProducerError {
    Contract,
    Fabric(ManagedFabricProducerError),
    Digest(DigestBuildError),
    Authentication(ApplyAuthError),
    Temporal(TemporalContractError),
    InvalidFreshIdentity,
    FabricChangeRequiresEmpty,
    InvalidDesiredPlan,
    RevisionExhausted,
    LifecycleBudgetOverflow,
    ProjectionMismatch,
    ControllerOrDesiredMismatch,
    RequestMismatch,
}

impl From<ManagedModelAgentStackPlanError> for ManagedModelAgentStackProducerError {
    fn from(_value: ManagedModelAgentStackPlanError) -> Self {
        Self::Contract
    }
}

impl From<paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentStackPlanError>
    for ManagedModelAgentStackProducerError
{
    fn from(
        _value: paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentStackPlanError,
    ) -> Self {
        Self::Contract
    }
}

impl From<ManagedFabricProducerError> for ManagedModelAgentStackProducerError {
    fn from(value: ManagedFabricProducerError) -> Self {
        Self::Fabric(value)
    }
}

impl From<DigestBuildError> for ManagedModelAgentStackProducerError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ApplyAuthError> for ManagedModelAgentStackProducerError {
    fn from(value: ApplyAuthError) -> Self {
        Self::Authentication(value)
    }
}

impl From<TemporalContractError> for ManagedModelAgentStackProducerError {
    fn from(value: TemporalContractError) -> Self {
        Self::Temporal(value)
    }
}

impl fmt::Display for ManagedModelAgentStackProducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed Model+Agent stack producer rejected: {self:?}"
        )
    }
}

impl std::error::Error for ManagedModelAgentStackProducerError {}
