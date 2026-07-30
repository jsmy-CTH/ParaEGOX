//! Pure deployment-to-runtime commitment projection.

use core::fmt;
use paraegox_runtime_contracts::apply::{
    ApplyContractError, ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterEpoch,
    PlanWriterRef, RuntimeApplyControl, RuntimeApplyControlCommitment,
};
use paraegox_runtime_contracts::assignment::{AssignmentContractError, RuntimePlanSlice};
use paraegox_runtime_contracts::provenance::RuntimeSliceCommitment;
use paraegox_runtime_contracts::provenance::{
    PlanProvenance, ProvenanceContractError, RuntimeSliceHeader, SourcePlanRef, SourcePlanRevision,
    SourceScopeRef,
};

use crate::plan::{CommittedTargetProjection, DeploymentWriterTenure};

/// Projects a target-specific, tenure-neutral Runtime slice commitment.
#[cfg(test)]
pub fn project_runtime_slice_commitment(
    projection: &CommittedTargetProjection,
) -> Result<RuntimeSliceCommitment, ProjectionError> {
    Ok(project_runtime_plan_slice(projection)?.commitment())
}

/// Projects the complete target-specific Runtime slice from canonical assignments.
pub fn project_runtime_plan_slice(
    projection: &CommittedTargetProjection,
) -> Result<RuntimePlanSlice, ProjectionError> {
    let plan = projection.plan();
    let provenance = PlanProvenance::new(
        SourceScopeRef::from_bytes(*plan.scope().as_bytes()),
        SourcePlanRef::from_bytes(*plan.plan().as_bytes()),
        SourcePlanRevision::new(plan.revision().value()),
        plan.digest(),
    );
    let header = RuntimeSliceHeader::new(
        projection.target(),
        provenance,
        projection.assignment_digest(),
    );
    let commitment =
        RuntimeSliceCommitment::try_new(header).map_err(ProjectionError::Provenance)?;
    RuntimePlanSlice::try_new(commitment, projection.assignments().clone())
        .map_err(ProjectionError::Assignment)
}

/// Maps deployment writer ownership into a Runtime-owned apply-control commitment.
pub fn build_runtime_apply_control_commitment(
    slice: RuntimeSliceCommitment,
    tenure: DeploymentWriterTenure,
    expected_active: ExpectedActive,
    operation_id: ApplyOperationId,
) -> Result<RuntimeApplyControlCommitment, ProjectionError> {
    let (deployment_writer, deployment_epoch, proof) = tenure.into_parts();
    let runtime_writer = PlanWriterRef::from_bytes(*deployment_writer.as_bytes());
    let runtime_epoch = PlanWriterEpoch::new(deployment_epoch.value());

    let writer_context = PlanWriterContext::try_new(runtime_writer, runtime_epoch, proof)?;
    let control = RuntimeApplyControl::new(writer_context, expected_active, operation_id);
    RuntimeApplyControlCommitment::try_new(slice, control).map_err(ProjectionError::Apply)
}

/// Fail-closed projection and writer-mapping errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    /// Slice commitment construction failed.
    Provenance(ProvenanceContractError),
    /// Canonical assignment body did not match the projected commitment.
    Assignment(AssignmentContractError),
    /// Runtime apply-control construction failed.
    Apply(ApplyContractError),
}

impl From<ApplyContractError> for ProjectionError {
    fn from(value: ApplyContractError) -> Self {
        Self::Apply(value)
    }
}

impl From<AssignmentContractError> for ProjectionError {
    fn from(value: AssignmentContractError) -> Self {
        Self::Assignment(value)
    }
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provenance(error) => write!(formatter, "slice projection failed: {error}"),
            Self::Assignment(error) => write!(formatter, "assignment projection failed: {error}"),
            Self::Apply(error) => write!(formatter, "apply-control mapping failed: {error}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::BoundedDuration;
    use paraegox_runtime_contracts::apply::{
        ApplyOperationId, ExpectedActive, PlanWriterEpoch, PlanWriterRef, TenureAuthorityRef,
        TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority, WriterTenureClaim,
        WriterTenureProof,
    };
    use paraegox_runtime_contracts::assignment::{
        BindingAssignment, BindingId, DeliveryProfile, InstanceRef, InteractionKind, MailboxRef,
        MailboxSpec, OverflowPolicy, PortCardinality, PortDirection, PortEndpoint, PortRef,
        PortSpec, SchemaRef, TargetAssignments,
    };
    use paraegox_runtime_contracts::provenance::{SourcePlanDigest, SourceScopeRef};

    use crate::plan::{
        CommittedPlanIdentity, CommittedTargetProjection, DeploymentId, DeploymentRevision,
        DeploymentScopeId, DeploymentWriterEpoch, DeploymentWriterRef, DeploymentWriterTenure,
    };

    use super::{
        ProjectionError, build_runtime_apply_control_commitment, project_runtime_plan_slice,
        project_runtime_slice_commitment,
    };

    fn assignments(seed: u8) -> TargetAssignments {
        let Ok(schema) = SchemaRef::try_new(
            [seed; 16],
            1,
            Digest32::from_bytes([seed.wrapping_add(1); 32]),
        ) else {
            panic!("fixture schema must be valid");
        };
        let source = PortEndpoint::new(
            InstanceRef::from_bytes([seed.wrapping_add(2); 16]),
            PortRef::from_bytes([seed.wrapping_add(3); 16]),
            PortSpec::new(
                PortDirection::Out,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let target = PortEndpoint::new(
            InstanceRef::from_bytes([seed.wrapping_add(4); 16]),
            PortRef::from_bytes([seed.wrapping_add(5); 16]),
            PortSpec::new(
                PortDirection::In,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let Ok(delivery) = DeliveryProfile::try_new(
            64,
            BoundedDuration::from_nanos(100),
            OverflowPolicy::RejectNew,
        ) else {
            panic!("fixture delivery profile must be valid");
        };
        let Ok(mailbox) = MailboxSpec::try_new(
            4,
            256,
            BoundedDuration::from_nanos(80),
            2,
            384,
            OverflowPolicy::RejectNew,
        ) else {
            panic!("fixture mailbox spec must be valid");
        };
        let Ok(assignment) = BindingAssignment::try_new(
            BindingId::from_bytes([seed.wrapping_add(6); 16]),
            source,
            target,
            MailboxRef::from_bytes([seed.wrapping_add(7); 16]),
            delivery,
            mailbox,
        ) else {
            panic!("fixture binding assignment must be valid");
        };
        let Ok(assignments) = TargetAssignments::try_new(vec![assignment]) else {
            panic!("fixture target assignments must be valid");
        };
        assignments
    }

    fn projection(target_byte: u8, assignment_byte: u8) -> CommittedTargetProjection {
        let plan = CommittedPlanIdentity::new(
            DeploymentScopeId::from_bytes([1; 16]),
            DeploymentId::from_bytes([2; 16]),
            DeploymentRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([4; 32])),
        );
        CommittedTargetProjection::new(
            plan,
            RuntimeHostId::from_bytes([target_byte; 16]),
            assignments(assignment_byte),
        )
    }

    fn tenure(scope_byte: u8, writer_byte: u8, epoch: u64) -> DeploymentWriterTenure {
        let runtime_writer = PlanWriterRef::from_bytes([writer_byte; 16]);
        let Ok(algorithm) = TenureProofAlgorithm::try_new(1) else {
            panic!("test algorithm must be valid");
        };
        let Ok(authority) = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([6; 16]),
            TenureKeyRef::from_bytes([7; 16]),
            algorithm,
            1,
        ) else {
            panic!("test authority must be valid");
        };
        let Ok(claim) = WriterTenureClaim::try_new(
            SourceScopeRef::from_bytes([scope_byte; 16]),
            runtime_writer,
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(epoch - 1),
        ) else {
            panic!("test claim must be valid");
        };
        let Ok(proof) = WriterTenureProof::try_new(authority, claim, b"nonce", b"signature") else {
            panic!("test proof must be valid");
        };
        DeploymentWriterTenure::new(
            DeploymentWriterRef::from_bytes([writer_byte; 16]),
            DeploymentWriterEpoch::new(epoch),
            proof,
        )
    }

    #[test]
    fn projection_is_stable_target_specific_and_tenure_neutral() {
        let Ok(complete) = project_runtime_plan_slice(&projection(9, 10)) else {
            panic!("valid complete projection must succeed");
        };
        let Ok(first) = project_runtime_slice_commitment(&projection(9, 10)) else {
            panic!("valid projection must succeed");
        };
        let Ok(second) = project_runtime_slice_commitment(&projection(9, 10)) else {
            panic!("valid projection must succeed");
        };
        let Ok(changed_target) = project_runtime_slice_commitment(&projection(11, 10)) else {
            panic!("valid projection must succeed");
        };
        let Ok(changed_assignment) = project_runtime_slice_commitment(&projection(9, 12)) else {
            panic!("valid projection must succeed");
        };

        assert_eq!(complete.commitment(), first);
        assert_eq!(
            complete.assignments().assignment_digest(),
            first.header().assignment_digest()
        );
        assert_eq!(first, second);
        assert_ne!(first, changed_target);
        assert_ne!(first, changed_assignment);
    }

    #[test]
    fn writer_change_only_changes_apply_control_commitment() {
        let Ok(slice) = project_runtime_slice_commitment(&projection(9, 10)) else {
            panic!("valid projection must succeed");
        };
        let Ok(first) = build_runtime_apply_control_commitment(
            slice,
            tenure(1, 13, 1),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([14; 16]),
        ) else {
            panic!("valid writer mapping must succeed");
        };
        let Ok(second) = build_runtime_apply_control_commitment(
            slice,
            tenure(1, 13, 2),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([14; 16]),
        ) else {
            panic!("valid writer mapping must succeed");
        };

        assert_eq!(first.slice(), second.slice());
        assert_ne!(first.commitment_digest(), second.commitment_digest());
    }

    #[test]
    fn exact_active_expectation_is_preserved() {
        let Ok(slice) = project_runtime_slice_commitment(&projection(9, 10)) else {
            panic!("valid projection must succeed");
        };
        let expected_active = ExpectedActive::Exact(slice.target_slice_digest());
        let Ok(commitment) = build_runtime_apply_control_commitment(
            slice,
            tenure(1, 13, 1),
            expected_active,
            ApplyOperationId::from_bytes([14; 16]),
        ) else {
            panic!("valid writer mapping must succeed");
        };

        assert_eq!(commitment.control().expected_active(), expected_active);
    }

    #[test]
    fn invalid_proof_scope_fails_closed() {
        let Ok(slice) = project_runtime_slice_commitment(&projection(9, 10)) else {
            panic!("valid projection must succeed");
        };
        let result = build_runtime_apply_control_commitment(
            slice,
            tenure(99, 13, 1),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([14; 16]),
        );

        assert_eq!(
            result.err(),
            Some(ProjectionError::Apply(
                paraegox_runtime_contracts::apply::ApplyContractError::WriterScopeMismatch
            ))
        );
    }
}
