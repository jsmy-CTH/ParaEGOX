//! Owner-private Deployment producer for the fixed PXTE v6/PXAR v7
//! Fabric→Agent successor.
//!
//! The producer never invents an Agent provider and never accepts a replacement
//! Fabric service. It preserves the exact active PXTE v5 Fabric execution and
//! requires every Agent service, lane, bound, provider reference, configuration
//! digest, and optional secret reference to be explicit contract values.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::time::BoundedDuration;
use paraegox_runtime_contracts::apply::{ApplyOperationId, ExpectedActive, RuntimeApplyControl};
use paraegox_runtime_contracts::managed_agent_stack_plan::{
    ManagedAgentServicePlanV1, ManagedAgentStackApplyRequestDraftV1,
    ManagedAgentStackApplyRequestV1, ManagedAgentStackPlanError, ManagedAgentStackProjectionV1,
    ManagedAgentStackTargetExecutionV1, ManagedAgentStackTargetModeV1,
};
use paraegox_runtime_contracts::managed_fabric_plan::{
    ManagedFabricTargetExecutionV1, ManagedFabricTargetModeV1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceLifecycleStage;
use paraegox_runtime_contracts::provenance::{
    PlanProvenance, SourcePlanDigest, SourcePlanRevision,
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
    b"paraegox.deployment.managed-agent-stack-desired.sha256.v1";

/// Explicit requested stack. The Fabric half is an equality expectation, not a
/// replacement value; any difference requires an earlier exact-zero transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackActivationV1 {
    expected_fabric: ManagedFabricTargetExecutionV1,
    agent: ManagedAgentServicePlanV1,
}

impl ManagedAgentStackActivationV1 {
    pub(crate) fn try_new(
        expected_fabric: ManagedFabricTargetExecutionV1,
        agent: ManagedAgentServicePlanV1,
    ) -> Result<Self, ManagedAgentStackProducerError> {
        if expected_fabric.mode() != ManagedFabricTargetModeV1::OneManagedFabricService {
            return Err(ManagedAgentStackProducerError::FabricChangeRequiresEmpty);
        }
        Ok(Self {
            expected_fabric,
            agent,
        })
    }
}

/// Fresh request identities consumed only if no PXAR v7 is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreshManagedAgentStackApplyV1 {
    operation_id: [u8; 16],
    temporal_constraint_id: [u8; 16],
    authentication_nonce: [u8; 32],
}

impl FreshManagedAgentStackApplyV1 {
    pub(crate) fn try_new(
        operation_id: [u8; 16],
        temporal_constraint_id: [u8; 16],
        authentication_nonce: [u8; 32],
    ) -> Result<Self, ManagedAgentStackProducerError> {
        if bytes_are_zero(&operation_id)
            || bytes_are_zero(&temporal_constraint_id)
            || bytes_are_zero(&authentication_nonce)
            || operation_id == temporal_constraint_id
        {
            return Err(ManagedAgentStackProducerError::InvalidFreshIdentity);
        }
        Ok(Self {
            operation_id,
            temporal_constraint_id,
            authentication_nonce,
        })
    }
}

/// Exact desired stack derived from current pin and active PXAR v6 authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackDesiredPlanV1 {
    cutover_marker_digest: Digest32,
    predecessor_slice_digest: paraegox_runtime_contracts::provenance::TargetSliceDigest,
    revision: SourcePlanRevision,
    provenance: PlanProvenance,
    execution: ManagedAgentStackTargetExecutionV1,
}

impl ManagedAgentStackDesiredPlanV1 {
    pub(crate) fn try_activate(
        context: &VerifiedManagedFabricProducerContextV1,
        cutover_marker_digest: Digest32,
        predecessor_revision: SourcePlanRevision,
        predecessor_execution: &ManagedFabricTargetExecutionV1,
        predecessor_slice_digest: paraegox_runtime_contracts::provenance::TargetSliceDigest,
        activation: &ManagedAgentStackActivationV1,
    ) -> Result<Self, ManagedAgentStackProducerError> {
        if activation.expected_fabric != *predecessor_execution
            || predecessor_execution.mode() != ManagedFabricTargetModeV1::OneManagedFabricService
            || predecessor_execution.projection() != context.projection()
        {
            return Err(ManagedAgentStackProducerError::FabricChangeRequiresEmpty);
        }
        let projection = ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(
            context.projection().clone(),
        )?;
        let execution = ManagedAgentStackTargetExecutionV1::try_fabric_and_agent(
            projection,
            predecessor_execution.clone(),
            activation.agent.clone(),
        )?;
        let revision = predecessor_revision
            .value()
            .checked_add(1)
            .ok_or(ManagedAgentStackProducerError::RevisionExhausted)?;
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
        predecessor_slice_digest: paraegox_runtime_contracts::provenance::TargetSliceDigest,
        revision: u64,
        execution_wire: &[u8],
    ) -> Result<Self, ManagedAgentStackProducerError> {
        if digest_is_zero(cutover_marker_digest) || revision == 0 {
            return Err(ManagedAgentStackProducerError::InvalidDesiredPlan);
        }
        let execution = ManagedAgentStackTargetExecutionV1::decode(execution_wire)?;
        let projection = ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(
            context.projection().clone(),
        )?;
        if execution.projection() != &projection {
            return Err(ManagedAgentStackProducerError::ProjectionMismatch);
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
        active_request: &ManagedAgentStackApplyRequestV1,
    ) -> Result<Self, ManagedAgentStackProducerError> {
        if active_desired.execution().mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
            || active_request.target_execution() != active_desired.execution()
            || active_request.provenance() != active_desired.provenance()
        {
            return Err(ManagedAgentStackProducerError::InvalidDesiredPlan);
        }
        let projection = ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(
            context.projection().clone(),
        )?;
        let execution = ManagedAgentStackTargetExecutionV1::try_empty_deactivate(projection)?;
        let revision = active_desired
            .revision()
            .value()
            .checked_add(1)
            .ok_or(ManagedAgentStackProducerError::RevisionExhausted)?;
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
    pub(crate) const fn predecessor_slice_digest(
        &self,
    ) -> paraegox_runtime_contracts::provenance::TargetSliceDigest {
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
    pub(crate) const fn execution(&self) -> &ManagedAgentStackTargetExecutionV1 {
        &self.execution
    }
}

pub(crate) fn produce_managed_agent_stack_request_v1(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedAgentStackDesiredPlanV1,
    fresh: FreshManagedAgentStackApplyV1,
    controller_signer: &SigningKey,
) -> Result<ManagedAgentStackApplyRequestV1, ManagedAgentStackProducerError> {
    let budget = active_stack_lifecycle_budget(desired)?;
    produce_request_with_budget(context, desired, fresh, controller_signer, budget)
}

pub(crate) fn produce_managed_agent_stack_empty_request_v1(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedAgentStackDesiredPlanV1,
    archived_active_execution: &ManagedAgentStackTargetExecutionV1,
    fresh: FreshManagedAgentStackApplyV1,
    controller_signer: &SigningKey,
) -> Result<ManagedAgentStackApplyRequestV1, ManagedAgentStackProducerError> {
    if desired.execution().mode() != ManagedAgentStackTargetModeV1::EmptyDeactivate {
        return Err(ManagedAgentStackProducerError::InvalidDesiredPlan);
    }
    let budget = empty_stack_lifecycle_budget(archived_active_execution)?;
    produce_request_with_budget(context, desired, fresh, controller_signer, budget)
}

fn produce_request_with_budget(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedAgentStackDesiredPlanV1,
    fresh: FreshManagedAgentStackApplyV1,
    controller_signer: &SigningKey,
    budget: BoundedDuration,
) -> Result<ManagedAgentStackApplyRequestV1, ManagedAgentStackProducerError> {
    if controller_signer.verifying_key().to_bytes() != context.controller_verifying_key()
        || desired.execution().projection().managed_fabric_projection() != context.projection()
        || desired.provenance().source_scope() != context.source_scope()
        || desired.provenance().source_plan() != context.source_plan()
    {
        return Err(ManagedAgentStackProducerError::ControllerOrDesiredMismatch);
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
    let draft = ManagedAgentStackApplyRequestDraftV1::try_new(
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

pub(crate) fn validate_managed_agent_stack_request_v1(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedAgentStackDesiredPlanV1,
    request: &ManagedAgentStackApplyRequestV1,
) -> Result<(), ManagedAgentStackProducerError> {
    let budget = active_stack_lifecycle_budget(desired)?;
    validate_request_with_budget(context, desired, request, budget)
}

pub(crate) fn validate_managed_agent_stack_empty_request_v1(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedAgentStackDesiredPlanV1,
    archived_active_execution: &ManagedAgentStackTargetExecutionV1,
    request: &ManagedAgentStackApplyRequestV1,
) -> Result<(), ManagedAgentStackProducerError> {
    if desired.execution().mode() != ManagedAgentStackTargetModeV1::EmptyDeactivate {
        return Err(ManagedAgentStackProducerError::InvalidDesiredPlan);
    }
    let budget = empty_stack_lifecycle_budget(archived_active_execution)?;
    validate_request_with_budget(context, desired, request, budget)
}

fn validate_request_with_budget(
    context: &VerifiedManagedFabricProducerContextV1,
    desired: &ManagedAgentStackDesiredPlanV1,
    request: &ManagedAgentStackApplyRequestV1,
    lifecycle_budget: BoundedDuration,
) -> Result<(), ManagedAgentStackProducerError> {
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
        return Err(ManagedAgentStackProducerError::RequestMismatch);
    }
    let projection = ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(
        context.projection().clone(),
    )?;
    request.validate_projection(&projection)?;
    let signature: [u8; ED25519_SIGNATURE_BYTES] = authentication
        .signature()
        .try_into()
        .map_err(|_| ManagedAgentStackProducerError::RequestMismatch)?;
    VerifyingKey::from_bytes(&context.controller_verifying_key())
        .map_err(|_| ManagedAgentStackProducerError::RequestMismatch)?
        .verify_strict(
            request.signing_transcript()?.as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| ManagedAgentStackProducerError::RequestMismatch)
}

fn active_stack_lifecycle_budget(
    desired: &ManagedAgentStackDesiredPlanV1,
) -> Result<BoundedDuration, ManagedAgentStackProducerError> {
    if desired.execution().mode() != ManagedAgentStackTargetModeV1::FabricAndAgent {
        return Err(ManagedAgentStackProducerError::InvalidDesiredPlan);
    }
    let agent = desired
        .execution()
        .agent()
        .ok_or(ManagedAgentStackProducerError::InvalidDesiredPlan)?;
    let budgets = agent.service().lifecycle_budgets();
    let mut total = 0_u64;
    for stage in [
        ManagedServiceLifecycleStage::Prepare,
        ManagedServiceLifecycleStage::Start,
        ManagedServiceLifecycleStage::Readiness,
    ] {
        total = total
            .checked_add(budgets.for_stage(stage).value())
            .ok_or(ManagedAgentStackProducerError::LifecycleBudgetOverflow)?;
    }
    if total == 0 {
        return Err(ManagedAgentStackProducerError::InvalidDesiredPlan);
    }
    Ok(BoundedDuration::from_nanos(total))
}

fn empty_stack_lifecycle_budget(
    archived_active_execution: &ManagedAgentStackTargetExecutionV1,
) -> Result<BoundedDuration, ManagedAgentStackProducerError> {
    if archived_active_execution.mode() != ManagedAgentStackTargetModeV1::FabricAndAgent {
        return Err(ManagedAgentStackProducerError::InvalidDesiredPlan);
    }
    let agent = archived_active_execution
        .agent()
        .ok_or(ManagedAgentStackProducerError::InvalidDesiredPlan)?;
    let fabric = archived_active_execution
        .fabric()
        .service()
        .ok_or(ManagedAgentStackProducerError::InvalidDesiredPlan)?;
    let mut total = 0_u64;
    for budget in [
        agent
            .service()
            .lifecycle_budgets()
            .for_stage(ManagedServiceLifecycleStage::Drain),
        agent
            .service()
            .lifecycle_budgets()
            .for_stage(ManagedServiceLifecycleStage::Stop),
        fabric
            .lifecycle_budgets()
            .for_stage(ManagedServiceLifecycleStage::Drain),
        fabric
            .lifecycle_budgets()
            .for_stage(ManagedServiceLifecycleStage::Stop),
    ] {
        total = total
            .checked_add(budget.value())
            .ok_or(ManagedAgentStackProducerError::LifecycleBudgetOverflow)?;
    }
    if total == 0 {
        return Err(ManagedAgentStackProducerError::InvalidDesiredPlan);
    }
    Ok(BoundedDuration::from_nanos(total))
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn digest_is_zero(value: Digest32) -> bool {
    bytes_are_zero(value.as_bytes())
}

#[derive(Debug)]
pub(crate) enum ManagedAgentStackProducerError {
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

impl From<ManagedAgentStackPlanError> for ManagedAgentStackProducerError {
    fn from(_value: ManagedAgentStackPlanError) -> Self {
        Self::Contract
    }
}

impl From<ManagedFabricProducerError> for ManagedAgentStackProducerError {
    fn from(value: ManagedFabricProducerError) -> Self {
        Self::Fabric(value)
    }
}

impl From<DigestBuildError> for ManagedAgentStackProducerError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ApplyAuthError> for ManagedAgentStackProducerError {
    fn from(value: ApplyAuthError) -> Self {
        Self::Authentication(value)
    }
}

impl From<TemporalContractError> for ManagedAgentStackProducerError {
    fn from(value: TemporalContractError) -> Self {
        Self::Temporal(value)
    }
}

impl fmt::Display for ManagedAgentStackProducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "managed Agent stack producer rejected: {self:?}")
    }
}

impl std::error::Error for ManagedAgentStackProducerError {}
