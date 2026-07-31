//! Pure deployment-side producer for complete signed Runtime apply requests.

use core::fmt;

use paraegox_runtime_contracts::apply::{ApplyOperationId, ExpectedActive};
use paraegox_runtime_contracts::assignment::{
    AssignmentContractError, RuntimeApplyRequest, RuntimePlanSlice,
};
use paraegox_runtime_contracts::execution::{
    RuntimeApplyRequestV2, RuntimePlanSliceV2, TargetPlanContractError,
};
use paraegox_runtime_contracts::process_execution::{
    RuntimeApplyRequestV4, RuntimePlanSliceV4, TargetExecutionPlanV3, TargetPlanAssignmentsV4,
    TargetPlanV4ContractError,
};
use paraegox_runtime_contracts::provenance::{
    PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanRef, SourcePlanRevision,
    SourceScopeRef,
};
use paraegox_runtime_contracts::temporal::ApplyTemporalConstraint;
use paraegox_runtime_contracts::thread_execution::{
    RuntimeApplyRequestV3, RuntimePlanSliceV3, TargetPlanV3ContractError,
};
use paraegox_runtime_contracts::wire::{
    ApplyRequestAuthClaim, ApplyRequestSigningTranscript, EnvelopeContractError,
    RuntimeApplyEnvelopeDraft,
};

use crate::plan::{
    CommittedTargetPlanProjection, CommittedTargetPlanProjectionV3, CommittedTargetProjection,
    DeploymentWriterTenure,
};
use crate::projection::{
    ProjectionError, build_runtime_apply_control_commitment, project_runtime_plan_slice,
    project_runtime_plan_slice_v2, project_runtime_plan_slice_v3,
};

/// Signature-independent complete request paired with its canonical Slice body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyRequestDraft {
    slice: RuntimePlanSlice,
    envelope: RuntimeApplyEnvelopeDraft,
}

impl RuntimeApplyRequestDraft {
    /// Returns the exact canonical bytes the external writer must sign.
    pub fn signing_transcript(&self) -> Result<ApplyRequestSigningTranscript, EnvelopeBuildError> {
        self.envelope
            .signing_transcript()
            .map_err(EnvelopeBuildError::Envelope)
    }

    /// Finalizes the existing B2 envelope and binds it to the complete Slice body.
    pub fn finalize(self, signature: &[u8]) -> Result<RuntimeApplyRequest, EnvelopeBuildError> {
        let envelope = self
            .envelope
            .finalize(signature)
            .map_err(EnvelopeBuildError::Envelope)?;
        RuntimeApplyRequest::try_new(envelope, self.slice).map_err(EnvelopeBuildError::Request)
    }
}

/// Signature-independent PXAR v2 request paired with complete PXTA and PXTE bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyRequestV2Draft {
    slice: RuntimePlanSliceV2,
    envelope: RuntimeApplyEnvelopeDraft,
}

impl RuntimeApplyRequestV2Draft {
    /// Returns the exact unchanged envelope transcript the external writer signs.
    pub fn signing_transcript(&self) -> Result<ApplyRequestSigningTranscript, EnvelopeBuildError> {
        self.envelope
            .signing_transcript()
            .map_err(EnvelopeBuildError::Envelope)
    }

    /// Finalizes the envelope and binds it to both canonical v2 plan bodies.
    pub fn finalize(self, signature: &[u8]) -> Result<RuntimeApplyRequestV2, EnvelopeBuildError> {
        let envelope = self
            .envelope
            .finalize(signature)
            .map_err(EnvelopeBuildError::Envelope)?;
        RuntimeApplyRequestV2::try_new(envelope, self.slice)
            .map_err(EnvelopeBuildError::TargetPlanRequest)
    }
}

/// Signature-independent PXAR v3 request paired with complete PXTA and additive PXTE v2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyRequestV3Draft {
    slice: RuntimePlanSliceV3,
    envelope: RuntimeApplyEnvelopeDraft,
}

impl RuntimeApplyRequestV3Draft {
    /// Returns the exact unchanged envelope transcript the external writer signs.
    pub fn signing_transcript(&self) -> Result<ApplyRequestSigningTranscript, EnvelopeBuildError> {
        self.envelope
            .signing_transcript()
            .map_err(EnvelopeBuildError::Envelope)
    }

    /// Finalizes the envelope and binds it to complete PXTA and additive PXTE v2.
    pub fn finalize(self, signature: &[u8]) -> Result<RuntimeApplyRequestV3, EnvelopeBuildError> {
        let envelope = self
            .envelope
            .finalize(signature)
            .map_err(EnvelopeBuildError::Envelope)?;
        RuntimeApplyRequestV3::try_new(envelope, self.slice)
            .map_err(EnvelopeBuildError::TargetPlanV3Request)
    }
}

/// Signature-independent PXAR v4 request paired with complete PXTA and additive PXTE v3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyRequestV4Draft {
    slice: RuntimePlanSliceV4,
    envelope: RuntimeApplyEnvelopeDraft,
}

impl RuntimeApplyRequestV4Draft {
    /// Returns the unchanged envelope transcript the external writer must sign.
    pub fn signing_transcript(&self) -> Result<ApplyRequestSigningTranscript, EnvelopeBuildError> {
        self.envelope
            .signing_transcript()
            .map_err(EnvelopeBuildError::Envelope)
    }

    /// Finalizes the envelope and binds it to complete PXTA and additive PXTE v3.
    pub fn finalize(self, signature: &[u8]) -> Result<RuntimeApplyRequestV4, EnvelopeBuildError> {
        let envelope = self
            .envelope
            .finalize(signature)
            .map_err(EnvelopeBuildError::Envelope)?;
        RuntimeApplyRequestV4::try_new(envelope, self.slice)
            .map_err(EnvelopeBuildError::TargetPlanV4Request)
    }
}

/// Builds the complete signature-independent Runtime apply request.
pub fn build_runtime_apply_request_draft(
    projection: &CommittedTargetProjection,
    tenure: DeploymentWriterTenure,
    expected_active: ExpectedActive,
    operation_id: ApplyOperationId,
    temporal: ApplyTemporalConstraint,
    auth_claim: ApplyRequestAuthClaim,
) -> Result<RuntimeApplyRequestDraft, EnvelopeBuildError> {
    let slice = project_runtime_plan_slice(projection)?;
    let control_commitment = build_runtime_apply_control_commitment(
        slice.commitment(),
        tenure,
        expected_active,
        operation_id,
    )?;
    let envelope = RuntimeApplyEnvelopeDraft::try_new(control_commitment, temporal, auth_claim)
        .map_err(EnvelopeBuildError::Envelope)?;
    Ok(RuntimeApplyRequestDraft { slice, envelope })
}

/// Builds the complete signature-independent PXAR v2 Runtime apply request.
pub fn build_runtime_apply_request_v2_draft(
    projection: &CommittedTargetPlanProjection,
    tenure: DeploymentWriterTenure,
    expected_active: ExpectedActive,
    operation_id: ApplyOperationId,
    temporal: ApplyTemporalConstraint,
    auth_claim: ApplyRequestAuthClaim,
) -> Result<RuntimeApplyRequestV2Draft, EnvelopeBuildError> {
    let slice = project_runtime_plan_slice_v2(projection)?;
    let control_commitment = build_runtime_apply_control_commitment(
        slice.commitment(),
        tenure,
        expected_active,
        operation_id,
    )?;
    let envelope = RuntimeApplyEnvelopeDraft::try_new(control_commitment, temporal, auth_claim)
        .map_err(EnvelopeBuildError::Envelope)?;
    Ok(RuntimeApplyRequestV2Draft { slice, envelope })
}

/// Builds the complete signature-independent PXAR v3 Runtime apply request.
pub fn build_runtime_apply_request_v3_draft(
    projection: &CommittedTargetPlanProjectionV3,
    tenure: DeploymentWriterTenure,
    expected_active: ExpectedActive,
    operation_id: ApplyOperationId,
    temporal: ApplyTemporalConstraint,
    auth_claim: ApplyRequestAuthClaim,
) -> Result<RuntimeApplyRequestV3Draft, EnvelopeBuildError> {
    let slice = project_runtime_plan_slice_v3(projection)?;
    let control_commitment = build_runtime_apply_control_commitment(
        slice.commitment(),
        tenure,
        expected_active,
        operation_id,
    )?;
    let envelope = RuntimeApplyEnvelopeDraft::try_new(control_commitment, temporal, auth_claim)
        .map_err(EnvelopeBuildError::Envelope)?;
    Ok(RuntimeApplyRequestV3Draft { slice, envelope })
}

/// Builds a complete signature-independent PXAR v4 Runtime apply request.
///
/// `projection` remains tenure-neutral and owns the committed plan identity,
/// target, and complete PXTA body. `execution` is the exact additive PXTE v3
/// body selected for that projection. This function owns neither signing keys
/// nor clock authority and performs no ProcessDomain or worker construction.
pub fn build_runtime_apply_request_v4_draft(
    projection: &CommittedTargetProjection,
    execution: TargetExecutionPlanV3,
    tenure: DeploymentWriterTenure,
    expected_active: ExpectedActive,
    operation_id: ApplyOperationId,
    temporal: ApplyTemporalConstraint,
    auth_claim: ApplyRequestAuthClaim,
) -> Result<RuntimeApplyRequestV4Draft, EnvelopeBuildError> {
    let assignments = TargetPlanAssignmentsV4::try_new(projection.assignments().clone(), execution)
        .map_err(EnvelopeBuildError::TargetPlanV4Request)?;
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
        assignments.assignment_digest(),
    );
    let commitment = RuntimeSliceCommitment::try_new(header)
        .map_err(TargetPlanV4ContractError::Provenance)
        .map_err(EnvelopeBuildError::TargetPlanV4Request)?;
    let slice = RuntimePlanSliceV4::try_new(commitment, assignments)
        .map_err(EnvelopeBuildError::TargetPlanV4Request)?;
    let control_commitment = build_runtime_apply_control_commitment(
        slice.commitment(),
        tenure,
        expected_active,
        operation_id,
    )?;
    let envelope = RuntimeApplyEnvelopeDraft::try_new(control_commitment, temporal, auth_claim)
        .map_err(EnvelopeBuildError::Envelope)?;
    Ok(RuntimeApplyRequestV4Draft { slice, envelope })
}

/// Builds the signature-independent form of one canonical B2 apply envelope.
///
/// The returned draft exposes the complete request-authentication transcript.
/// Its caller owns signing that transcript outside this pure producer and then
/// finalizing the draft with the resulting signature bytes. This function does
/// not hold a signing key, choose a signer, perform I/O, or access a clock.
#[cfg(test)]
fn build_runtime_apply_envelope_draft(
    projection: &CommittedTargetProjection,
    tenure: DeploymentWriterTenure,
    expected_active: ExpectedActive,
    operation_id: ApplyOperationId,
    temporal: ApplyTemporalConstraint,
    auth_claim: ApplyRequestAuthClaim,
) -> Result<RuntimeApplyEnvelopeDraft, EnvelopeBuildError> {
    let slice = project_runtime_plan_slice(projection)?;
    let control_commitment = build_runtime_apply_control_commitment(
        slice.commitment(),
        tenure,
        expected_active,
        operation_id,
    )?;
    RuntimeApplyEnvelopeDraft::try_new(control_commitment, temporal, auth_claim)
        .map_err(EnvelopeBuildError::Envelope)
}

/// Fail-closed errors raised before a B2 apply envelope can be signed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeBuildError {
    /// Deployment projection or writer-tenure mapping failed.
    Projection(ProjectionError),
    /// Runtime-owned B2 draft validation failed.
    Envelope(EnvelopeContractError),
    /// Complete request and canonical assignment binding failed validation.
    Request(AssignmentContractError),
    /// PXAR v2 and its complete composite target plan failed validation.
    TargetPlanRequest(TargetPlanContractError),
    /// PXAR v3 and its additive Loop/Thread target plan failed validation.
    TargetPlanV3Request(TargetPlanV3ContractError),
    /// PXAR v4 and its additive Loop/Thread/Process plan failed validation.
    TargetPlanV4Request(TargetPlanV4ContractError),
}

impl From<ProjectionError> for EnvelopeBuildError {
    fn from(value: ProjectionError) -> Self {
        Self::Projection(value)
    }
}

impl fmt::Display for EnvelopeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Projection(error) => write!(formatter, "apply projection failed: {error}"),
            Self::Envelope(error) => write!(formatter, "apply envelope draft failed: {error}"),
            Self::Request(error) => write!(formatter, "complete apply request failed: {error}"),
            Self::TargetPlanRequest(error) => {
                write!(formatter, "complete v2 apply request failed: {error}")
            }
            Self::TargetPlanV3Request(error) => {
                write!(formatter, "complete v3 apply request failed: {error}")
            }
            Self::TargetPlanV4Request(error) => {
                write!(formatter, "complete v4 apply request failed: {error}")
            }
        }
    }
}

impl std::error::Error for EnvelopeBuildError {}

#[cfg(test)]
mod tests {
    use core::ops::Range;

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::apply::{
        ApplyContractError, ApplyOperationId, ExpectedActive, PlanWriterEpoch, PlanWriterRef,
        TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
        WriterTenureClaim, WriterTenureProof, WriterTenureSigningTranscript,
    };
    use paraegox_runtime_contracts::assignment::{
        BindingAssignment, BindingId, DeliveryProfile, InstanceRef, InteractionKind, MailboxRef,
        MailboxSpec, OverflowPolicy, PortCardinality, PortDirection, PortEndpoint, PortRef,
        PortSpec, RuntimeApplyRequest, SchemaRef, TargetAssignments,
    };
    use paraegox_runtime_contracts::execution::{
        BlockingRisk, CallModel, CallbackBudgets, CardDefinitionRef, CardImplementationRef,
        CardSubjectSpec, DispatchClass, DomainRef, LoopDomainCapacity, LoopDomainSpec,
        LoopExecutionRequirements, LoopLifecycleBudgets, MailboxDispatchPolicy,
        MailboxExecutionSpec, OverrunAction, RequestV2WireErrorCode, RunBoundProvenance,
        RuntimeApplyRequestV2, TargetExecutionPlan, TargetPlanAssignments, WorkloadKind,
    };
    use paraegox_runtime_contracts::process_execution::{
        FailureContainmentPolicy, InvocationReplayPolicy, ProcessAccessPolicy, ProcessCapacitySpec,
        ProcessDomainPolicies, ProcessDomainRef, ProcessDomainSpec, ProcessEntrypointRef,
        ProcessExecutionRequirements, ProcessInvocationBudgets, ProcessLaunchProfileRef,
        ProcessLaunchSpec, ProcessLifecycleBudgets, ProcessLivenessBudgets,
        ProcessMailboxExecutionSpec, ProcessProfileSelections, ProcessResourceLimits,
        ProcessRestartPolicy, ProcessSandboxProfileRef, ProcessShutdownBudgets,
        ProcessTargetProfileRef, ProcessWorkloadSelection, RuntimeApplyRequestV4,
        RuntimeVersionRange, SideEffectClass, TargetExecutionPlanV3, TargetPlanV4ContractError,
        WorkerRuntimeKind, WorkspacePolicy,
    };
    use paraegox_runtime_contracts::provenance::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest,
    };
    use paraegox_runtime_contracts::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
    use paraegox_runtime_contracts::thread_execution::{
        ExecutorBudgetSpec, RuntimeApplyRequestV3, TargetExecutionPlanV2, TargetPlanAssignmentsV3,
        ThreadDispatchPolicy, ThreadDomainRef, ThreadDomainSpec, ThreadExecutionRequirements,
        ThreadInvocationBudgets, ThreadMailboxExecutionSpec,
    };
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim, RuntimeApplyEnvelope,
        RuntimeApplyEnvelopeDraft, WireErrorCode,
    };

    use crate::plan::{
        CommittedPlanIdentity, CommittedTargetPlanProjection, CommittedTargetPlanProjectionV3,
        CommittedTargetProjection, DeploymentId, DeploymentRevision, DeploymentScopeId,
        DeploymentWriterEpoch, DeploymentWriterRef, DeploymentWriterTenure,
    };
    use crate::projection::{ProjectionError, build_runtime_apply_control_commitment};

    use super::{
        EnvelopeBuildError, RuntimeApplyRequestDraft, RuntimeApplyRequestV2Draft,
        RuntimeApplyRequestV3Draft, RuntimeApplyRequestV4Draft, build_runtime_apply_envelope_draft,
        build_runtime_apply_request_draft, build_runtime_apply_request_v2_draft,
        build_runtime_apply_request_v3_draft, build_runtime_apply_request_v4_draft,
    };

    // TEST-ONLY fixed seed. Production code never holds a tenure-authority signing key.
    const TEST_ONLY_TENURE_AUTHORITY_SEED: [u8; 32] = [0x11; 32];
    // TEST-ONLY fixed seed. Production code delegates request signing to its caller.
    const TEST_ONLY_WRITER_SEED: [u8; 32] = [0x22; 32];
    const S2_APPLY_VECTOR_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s2_apply_envelope_v1.json");
    const S3_APPLY_VECTOR_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s3_runtime_apply_request_v1.json");
    const S4_APPLY_VECTOR_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s4_runtime_apply_request_v2.json");
    const S5_APPLY_VECTOR_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s5_runtime_apply_request_v3.json");
    const S6_APPLY_VECTOR_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s6_runtime_apply_request_v4.json");
    const APPLY_ENVELOPE_MAGIC: &[u8] = b"ParaEGOX\0runtime-apply-envelope";

    struct TlvLocation {
        tag_offset: usize,
        value: Range<usize>,
        whole: Range<usize>,
    }

    fn fixture_hex(name: &str) -> Vec<u8> {
        fixture_document_hex(S2_APPLY_VECTOR_JSON, name)
    }

    fn s3_fixture_hex(name: &str) -> Vec<u8> {
        fixture_document_hex(S3_APPLY_VECTOR_JSON, name)
    }

    fn s4_fixture_hex(name: &str) -> Vec<u8> {
        fixture_document_hex(S4_APPLY_VECTOR_JSON, name)
    }

    fn s5_fixture_hex(name: &str) -> Vec<u8> {
        fixture_document_hex(S5_APPLY_VECTOR_JSON, name)
    }

    fn s6_fixture_hex(name: &str) -> Vec<u8> {
        fixture_document_hex(S6_APPLY_VECTOR_JSON, name)
    }

    fn assert_v2_rejection(
        frame: &[u8],
        expected_code: RequestV2WireErrorCode,
        expected_detail: Option<u16>,
    ) {
        let Err(error) = RuntimeApplyRequestV2::decode(frame) else {
            panic!("mutated S4 fixture must be rejected");
        };
        assert_eq!(error.code(), expected_code);
        assert_eq!(error.detail_code(), expected_detail);
    }

    fn fixture_document_hex(document: &str, name: &str) -> Vec<u8> {
        let marker = format!("\"{name}\": \"");
        let Some(value_start) = document.find(&marker).map(|offset| offset + marker.len()) else {
            panic!("contract fixture must contain {name}");
        };
        let Some(value_length) = document[value_start..].find('"') else {
            panic!("contract fixture value {name} must be terminated");
        };
        let value = &document[value_start..value_start + value_length];
        assert!(
            value.len().is_multiple_of(2),
            "contract fixture hex must have byte pairs"
        );
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|digits| (hex_digit(digits[0]) << 4) | hex_digit(digits[1]))
            .collect()
    }

    const fn hex_digit(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => panic!("S2 fixture contains non-hex data"),
        }
    }

    fn tlv_location(frame: &[u8], wanted_tag: u16) -> TlvLocation {
        assert!(frame.starts_with(APPLY_ENVELOPE_MAGIC));
        let count_offset = APPLY_ENVELOPE_MAGIC.len() + 2;
        let declared_count = u16::from_be_bytes([frame[count_offset], frame[count_offset + 1]]);
        let mut cursor = count_offset + 2;
        for _ in 0..declared_count {
            let whole_start = cursor;
            let tag = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]);
            let value_length = u32::from_be_bytes([
                frame[cursor + 2],
                frame[cursor + 3],
                frame[cursor + 4],
                frame[cursor + 5],
            ]) as usize;
            cursor += 6;
            let value = cursor..cursor + value_length;
            cursor = value.end;
            if tag == wanted_tag {
                return TlvLocation {
                    tag_offset: whole_start,
                    value,
                    whole: whole_start..cursor,
                };
            }
        }
        panic!("canonical S2 fixture must contain tag {wanted_tag}");
    }

    fn replace_fixture_value(frame: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
        let location = tlv_location(frame, tag);
        assert_eq!(location.value.len(), value.len());
        let mut changed = frame.to_vec();
        changed[location.value].copy_from_slice(value);
        changed
    }

    fn assert_fixture_rejection(
        frame: &[u8],
        expected_code: WireErrorCode,
        expected_field: Option<u16>,
    ) {
        let Err(error) = RuntimeApplyEnvelope::decode(frame) else {
            panic!("mutated S2 fixture must be rejected");
        };
        assert_eq!(error.code(), expected_code);
        assert_eq!(error.field_tag(), expected_field);
    }

    fn projection() -> CommittedTargetProjection {
        let plan = CommittedPlanIdentity::new(
            DeploymentScopeId::from_bytes([1; 16]),
            DeploymentId::from_bytes([2; 16]),
            DeploymentRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([4; 32])),
        );
        let Ok(schema) = SchemaRef::try_new([6; 16], 1, Digest32::from_bytes([7; 32])) else {
            panic!("test schema must be valid");
        };
        let source = PortEndpoint::new(
            InstanceRef::from_bytes([8; 16]),
            PortRef::from_bytes([9; 16]),
            PortSpec::new(
                PortDirection::Out,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let target = PortEndpoint::new(
            InstanceRef::from_bytes([10; 16]),
            PortRef::from_bytes([11; 16]),
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
            panic!("test delivery must be valid");
        };
        let Ok(mailbox) = MailboxSpec::try_new(
            4,
            256,
            BoundedDuration::from_nanos(80),
            2,
            384,
            OverflowPolicy::RejectNew,
        ) else {
            panic!("test mailbox must be valid");
        };
        let Ok(binding) = BindingAssignment::try_new(
            BindingId::from_bytes([12; 16]),
            source,
            target,
            MailboxRef::from_bytes([13; 16]),
            delivery,
            mailbox,
        ) else {
            panic!("test binding must be valid");
        };
        let Ok(assignments) = TargetAssignments::try_new(vec![binding]) else {
            panic!("test assignments must be valid");
        };
        CommittedTargetProjection::new(plan, RuntimeHostId::from_bytes([5; 16]), assignments)
    }

    fn s3_fixture_projection() -> CommittedTargetProjection {
        let plan = CommittedPlanIdentity::new(
            DeploymentScopeId::from_bytes([0x01; 16]),
            DeploymentId::from_bytes([0x02; 16]),
            DeploymentRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([0x04; 32])),
        );
        let Ok(schema) = SchemaRef::try_new([0x21; 16], 1, Digest32::from_bytes([0x22; 32])) else {
            panic!("S3 fixture schema must be valid");
        };
        let Ok(delivery) = DeliveryProfile::try_new(
            128,
            BoundedDuration::from_nanos(1_000),
            OverflowPolicy::Latest,
        ) else {
            panic!("S3 fixture delivery profile must be valid");
        };
        let Ok(mailbox) = MailboxSpec::try_new(
            2,
            256,
            BoundedDuration::from_nanos(500),
            1,
            256,
            OverflowPolicy::Latest,
        ) else {
            panic!("S3 fixture mailbox must be valid");
        };
        let mut assignments = Vec::new();
        for (binding, source_instance, source_port, target_instance, target_port, mailbox_ref) in [
            (0x32, 0x42, 0x52, 0x62, 0x72, 0x82),
            (0x31, 0x41, 0x51, 0x61, 0x71, 0x81),
        ] {
            let source = PortEndpoint::new(
                InstanceRef::from_bytes([source_instance; 16]),
                PortRef::from_bytes([source_port; 16]),
                PortSpec::new(
                    PortDirection::Out,
                    schema,
                    InteractionKind::Signal,
                    PortCardinality::One,
                ),
            );
            let target = PortEndpoint::new(
                InstanceRef::from_bytes([target_instance; 16]),
                PortRef::from_bytes([target_port; 16]),
                PortSpec::new(
                    PortDirection::In,
                    schema,
                    InteractionKind::Signal,
                    PortCardinality::One,
                ),
            );
            let Ok(assignment) = BindingAssignment::try_new(
                BindingId::from_bytes([binding; 16]),
                source,
                target,
                MailboxRef::from_bytes([mailbox_ref; 16]),
                delivery,
                mailbox,
            ) else {
                panic!("S3 fixture binding must be valid");
            };
            assignments.push(assignment);
        }
        let Ok(assignments) = TargetAssignments::try_new(assignments) else {
            panic!("S3 fixture assignments must be valid");
        };
        CommittedTargetProjection::new(plan, RuntimeHostId::from_bytes([0x05; 16]), assignments)
    }

    fn s4_fixture_projection() -> CommittedTargetPlanProjection {
        let s3_projection = s3_fixture_projection();
        let Ok(delivery) = DeliveryProfile::try_new(
            128,
            BoundedDuration::from_nanos(5_000_000_000),
            OverflowPolicy::Latest,
        ) else {
            panic!("S4 fixture delivery profile must be valid");
        };
        let Ok(mailbox) = MailboxSpec::try_new(
            2,
            256,
            BoundedDuration::from_nanos(5_000_000_000),
            1,
            256,
            OverflowPolicy::Latest,
        ) else {
            panic!("S4 fixture mailbox must be valid");
        };
        let mut bindings = Vec::new();
        for assignment in s3_projection.assignments().as_slice().iter().copied() {
            let source = PortEndpoint::new(
                assignment.source_instance(),
                assignment.source_port(),
                assignment.source_spec(),
            );
            let target = PortEndpoint::new(
                assignment.target_instance(),
                assignment.target_port(),
                assignment.target_spec(),
            );
            let Ok(binding) = BindingAssignment::try_new(
                assignment.binding_id(),
                source,
                target,
                assignment.mailbox(),
                delivery,
                mailbox,
            ) else {
                panic!("S4 fixture binding must be valid");
            };
            bindings.push(binding);
        }
        let Ok(bindings) = TargetAssignments::try_new(bindings) else {
            panic!("S4 fixture assignments must be valid");
        };
        let binding_projection =
            CommittedTargetProjection::new(s3_projection.plan(), s3_projection.target(), bindings);
        let Ok(capacity) = LoopDomainCapacity::try_new(
            2,
            1,
            BoundedDuration::from_nanos(4_000_000_000),
            BoundedDuration::from_nanos(4_000_000_000),
        ) else {
            panic!("S4 fixture LoopDomain capacity must be valid");
        };
        let Ok(lifecycle) = LoopLifecycleBudgets::try_new(
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
        ) else {
            panic!("S4 fixture LoopDomain lifecycle must be valid");
        };
        let domain = LoopDomainSpec::new(DomainRef::from_bytes([0x91; 16]), capacity, lifecycle);
        let subject = CardSubjectSpec::new(
            CardDefinitionRef::from_bytes([0xa1; 16]),
            CardImplementationRef::from_bytes([0xa2; 16]),
            Digest32::from_bytes([0xa3; 32]),
            Digest32::from_bytes([0xa4; 32]),
            Digest32::from_bytes([0xa5; 32]),
        );
        let Ok(requirements) = LoopExecutionRequirements::try_new(
            CallModel::CooperativeAsync,
            WorkloadKind::Io,
            BlockingRisk::None,
            RunBoundProvenance::Measured,
            BoundedDuration::from_nanos(1_000_000_000),
        ) else {
            panic!("S4 fixture execution requirements must be valid");
        };
        let Ok(budgets) = CallbackBudgets::try_new(
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            OverrunAction::CooperativeCancel,
        ) else {
            panic!("S4 fixture callback budgets must be valid");
        };
        let Ok(dispatch) =
            MailboxDispatchPolicy::try_new(DispatchClass::Control, 2, 4, 2, 2, budgets)
        else {
            panic!("S4 fixture dispatch policy must be valid");
        };
        let Ok(mailbox_execution) = MailboxExecutionSpec::try_new(
            BindingId::from_bytes([0x31; 16]),
            MailboxRef::from_bytes([0x81; 16]),
            InstanceRef::from_bytes([0x61; 16]),
            DomainRef::from_bytes([0x91; 16]),
            subject,
            requirements,
            dispatch,
        ) else {
            panic!("S4 fixture Mailbox execution must be valid");
        };
        let Ok(execution) = TargetExecutionPlan::try_new(vec![domain], vec![mailbox_execution])
        else {
            panic!("S4 fixture PXTE body must be valid");
        };
        let Ok(assignments) =
            TargetPlanAssignments::try_new(binding_projection.assignments().clone(), execution)
        else {
            panic!("S4 fixture composite assignments must be valid");
        };
        CommittedTargetPlanProjection::new(
            binding_projection.plan(),
            binding_projection.target(),
            assignments,
        )
    }

    fn s5_projection(
        drain_budget_nanos: u64,
        native_threads: u32,
        max_total_threads: u32,
    ) -> CommittedTargetPlanProjectionV3 {
        let s4_projection = s4_fixture_projection();
        let Ok(domain) = ThreadDomainSpec::try_new(
            ThreadDomainRef::from_bytes([0x92; 16]),
            1,
            BoundedDuration::from_nanos(2_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(drain_budget_nanos),
        ) else {
            panic!("S5 ThreadDomain fixture must be valid");
        };
        let subject = CardSubjectSpec::new(
            CardDefinitionRef::from_bytes([0xb1; 16]),
            CardImplementationRef::from_bytes([0xb2; 16]),
            Digest32::from_bytes([0xb3; 32]),
            Digest32::from_bytes([0xb4; 32]),
            Digest32::from_bytes([0xb5; 32]),
        );
        let Ok(invocation_budgets) = ThreadInvocationBudgets::try_new(
            BoundedDuration::from_nanos(500_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(500_000_000),
            native_threads,
        ) else {
            panic!("S5 Thread invocation budgets must be valid");
        };
        let Ok(requirements) = ThreadExecutionRequirements::try_new(
            CallModel::Synchronous,
            WorkloadKind::Native,
            BlockingRisk::Bounded,
            RunBoundProvenance::Certified,
            invocation_budgets,
        ) else {
            panic!("S5 Thread execution requirements must be valid");
        };
        let Ok(dispatch) = ThreadDispatchPolicy::try_new(DispatchClass::Stream, 3, 5, 2, 1) else {
            panic!("S5 Thread dispatch policy must be valid");
        };
        let thread_mailbox = ThreadMailboxExecutionSpec::new(
            BindingId::from_bytes([0x32; 16]),
            MailboxRef::from_bytes([0x82; 16]),
            InstanceRef::from_bytes([0x62; 16]),
            ThreadDomainRef::from_bytes([0x92; 16]),
            subject,
            requirements,
            dispatch,
        );
        let Ok(executor_budget) = ExecutorBudgetSpec::try_new(max_total_threads, 2) else {
            panic!("S5 executor budget must be valid");
        };
        let Ok(execution) = TargetExecutionPlanV2::try_new(
            Some(s4_projection.assignments().execution().clone()),
            executor_budget,
            vec![domain],
            vec![thread_mailbox],
        ) else {
            panic!("S5 additive execution plan must be valid");
        };
        let Ok(assignments) = TargetPlanAssignmentsV3::try_new(
            s4_projection.assignments().bindings().clone(),
            execution,
        ) else {
            panic!("S5 composite target assignments must be valid");
        };
        CommittedTargetPlanProjectionV3::new(
            s4_projection.plan(),
            s4_projection.target(),
            assignments,
        )
    }

    fn s6_projection(
        heartbeat_timeout_nanos: u64,
        entrypoint_digest_byte: u8,
    ) -> (CommittedTargetProjection, TargetExecutionPlanV3) {
        let prior = s5_projection(1_000_000_000, 0, 3);
        let Ok(schema) = SchemaRef::try_new([0x21; 16], 1, Digest32::from_bytes([0x22; 32])) else {
            panic!("S6 fixture schema must be valid");
        };
        let source = PortEndpoint::new(
            InstanceRef::from_bytes([0x43; 16]),
            PortRef::from_bytes([0x53; 16]),
            PortSpec::new(
                PortDirection::Out,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let target = PortEndpoint::new(
            InstanceRef::from_bytes([0x63; 16]),
            PortRef::from_bytes([0x73; 16]),
            PortSpec::new(
                PortDirection::In,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let Ok(delivery) = DeliveryProfile::try_new(
            128,
            BoundedDuration::from_nanos(5_000_000_000),
            OverflowPolicy::Latest,
        ) else {
            panic!("S6 fixture delivery must be valid");
        };
        let Ok(mailbox) = MailboxSpec::try_new(
            2,
            256,
            BoundedDuration::from_nanos(5_000_000_000),
            1,
            256,
            OverflowPolicy::Latest,
        ) else {
            panic!("S6 fixture Mailbox must be valid");
        };
        let Ok(process_binding) = BindingAssignment::try_new(
            BindingId::from_bytes([0x33; 16]),
            source,
            target,
            MailboxRef::from_bytes([0x83; 16]),
            delivery,
            mailbox,
        ) else {
            panic!("S6 fixture process binding must be valid");
        };
        let mut binding_records = prior.assignments().bindings().as_slice().to_vec();
        binding_records.push(process_binding);
        let Ok(bindings) = TargetAssignments::try_new(binding_records) else {
            panic!("S6 complete PXTA must be valid");
        };

        let Ok(runtime_versions) = RuntimeVersionRange::try_new(3, 11, 3, 13) else {
            panic!("S6 runtime version range must be valid");
        };
        let profiles = ProcessProfileSelections::new(
            ProcessLaunchProfileRef::from_bytes([0xd2; 16]),
            Digest32::from_bytes([0xd3; 32]),
            ProcessTargetProfileRef::from_bytes([0xd4; 16]),
            Digest32::from_bytes([0xd5; 32]),
            ProcessSandboxProfileRef::from_bytes([0xd6; 16]),
            Digest32::from_bytes([0xd7; 32]),
        );
        let Ok(launch) =
            ProcessLaunchSpec::try_new(profiles, 1, WorkerRuntimeKind::Python, runtime_versions)
        else {
            panic!("S6 launch spec must be valid");
        };
        let Ok(capacity) = ProcessCapacitySpec::try_new(
            8,
            2,
            BoundedDuration::from_nanos(2_000_000_000),
            8,
            4_096,
            8_192,
        ) else {
            panic!("S6 process capacity must be valid");
        };
        let Ok(liveness) = ProcessLivenessBudgets::try_new(
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(100_000_000),
            BoundedDuration::from_nanos(heartbeat_timeout_nanos),
            BoundedDuration::from_nanos(1_000_000_000),
        ) else {
            panic!("S6 process liveness must be valid");
        };
        let Ok(shutdown) = ProcessShutdownBudgets::try_new(
            BoundedDuration::from_nanos(2_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
        ) else {
            panic!("S6 process shutdown must be valid");
        };
        let lifecycle = ProcessLifecycleBudgets::new(liveness, shutdown);
        let Ok(resources) = ProcessResourceLimits::try_new(
            65_536,
            32,
            4,
            BoundedDuration::from_nanos(2_000_000_000),
        ) else {
            panic!("S6 process resource limits must be valid");
        };
        let Ok(restart) = ProcessRestartPolicy::try_new(
            3,
            BoundedDuration::from_nanos(60_000_000_000),
            BoundedDuration::from_nanos(100_000_000),
            BoundedDuration::from_nanos(5_000_000_000),
            50,
        ) else {
            panic!("S6 restart policy must be valid");
        };
        let policies = ProcessDomainPolicies::new(
            WorkspacePolicy::EphemeralPerInstanceGeneration,
            ProcessAccessPolicy::NoRawHostAccess,
            FailureContainmentPolicy::WholeProcessDomain,
        );
        let Ok(domain) = ProcessDomainSpec::try_new(
            ProcessDomainRef::from_bytes([0xd1; 16]),
            launch,
            capacity,
            lifecycle,
            resources,
            restart,
            policies,
        ) else {
            panic!("S6 ProcessDomain must be valid");
        };
        let subject = CardSubjectSpec::new(
            CardDefinitionRef::from_bytes([0xc1; 16]),
            CardImplementationRef::from_bytes([0xc2; 16]),
            Digest32::from_bytes([0xc3; 32]),
            Digest32::from_bytes([0xc4; 32]),
            Digest32::from_bytes([0xc5; 32]),
        );
        let Ok(invocation_budgets) = ProcessInvocationBudgets::try_new(
            BoundedDuration::from_nanos(100_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(500_000_000),
            128,
        ) else {
            panic!("S6 invocation budgets must be valid");
        };
        let requirements = ProcessExecutionRequirements::new(
            CallModel::Synchronous,
            WorkloadKind::Device,
            BlockingRisk::Unknown,
            RunBoundProvenance::Unknown,
            SideEffectClass::External,
            InvocationReplayPolicy::NoReplay,
            invocation_budgets,
        );
        let Ok(dispatch) = ThreadDispatchPolicy::try_new(DispatchClass::Background, 7, 9, 2, 1)
        else {
            panic!("S6 process dispatch must be valid");
        };
        let workload = ProcessWorkloadSelection::new(
            subject,
            ProcessEntrypointRef::from_bytes([0xc6; 16]),
            Digest32::from_bytes([entrypoint_digest_byte; 32]),
        );
        let process_execution = ProcessMailboxExecutionSpec::new(
            BindingId::from_bytes([0x33; 16]),
            MailboxRef::from_bytes([0x83; 16]),
            InstanceRef::from_bytes([0x63; 16]),
            ProcessDomainRef::from_bytes([0xd1; 16]),
            workload,
            requirements,
            dispatch,
        );
        let Ok(execution) = TargetExecutionPlanV3::try_new(
            Some(prior.assignments().execution().clone()),
            vec![domain],
            vec![process_execution],
        ) else {
            panic!("S6 additive execution plan must be valid");
        };
        (
            CommittedTargetProjection::new(prior.plan(), prior.target(), bindings),
            execution,
        )
    }

    fn tenure(scope_byte: u8, epoch: u64) -> DeploymentWriterTenure {
        let writer = PlanWriterRef::from_bytes([9; 16]);
        let Ok(algorithm) = TenureProofAlgorithm::try_new(1) else {
            panic!("test tenure algorithm must be valid");
        };
        let Ok(authority) = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([7; 16]),
            TenureKeyRef::from_bytes([8; 16]),
            algorithm,
            1,
        ) else {
            panic!("test tenure authority must be valid");
        };
        let Ok(claim) = WriterTenureClaim::try_new(
            SourceScopeRef::from_bytes([scope_byte; 16]),
            writer,
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(epoch - 1),
        ) else {
            panic!("test tenure claim must be valid");
        };
        let nonce = b"test-only-tenure-nonce";
        let Ok(transcript) = WriterTenureSigningTranscript::try_new(authority, claim, nonce) else {
            panic!("test tenure transcript must be valid");
        };
        let authority_signing_key = SigningKey::from_bytes(&TEST_ONLY_TENURE_AUTHORITY_SEED);
        let signature = authority_signing_key.sign(transcript.as_bytes());
        assert!(
            authority_signing_key
                .verifying_key()
                .verify_strict(transcript.as_bytes(), &signature)
                .is_ok()
        );
        let Ok(proof) = WriterTenureProof::try_new(authority, claim, nonce, &signature.to_bytes())
        else {
            panic!("signed test tenure proof must be valid");
        };

        DeploymentWriterTenure::new(
            DeploymentWriterRef::from_bytes([9; 16]),
            DeploymentWriterEpoch::new(epoch),
            proof,
        )
    }

    fn temporal(remaining_nanos: u64) -> ApplyTemporalConstraint {
        let Ok(generation) = ClockGeneration::try_new(3) else {
            panic!("test clock generation must be valid");
        };
        let Ok(temporal) = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([10; 16]),
            ClockDomainRef::from_bytes([11; 16]),
            generation,
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(remaining_nanos),
        ) else {
            panic!("test temporal constraint must be valid");
        };
        temporal
    }

    fn auth_claim(nonce: &[u8]) -> ApplyRequestAuthClaim {
        let Ok(algorithm) = ApplyAuthAlgorithm::try_new(1) else {
            panic!("test request-auth algorithm must be valid");
        };
        let Ok(claim) = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([9; 16]),
            ApplyAuthKeyRef::from_bytes([12; 16]),
            algorithm,
            1,
            nonce,
        ) else {
            panic!("test request-auth claim must be valid");
        };
        claim
    }

    fn draft(epoch: u64, remaining_nanos: u64, auth_nonce: &[u8]) -> RuntimeApplyEnvelopeDraft {
        let Ok(draft) = build_runtime_apply_envelope_draft(
            &projection(),
            tenure(1, epoch),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([13; 16]),
            temporal(remaining_nanos),
            auth_claim(auth_nonce),
        ) else {
            panic!("test envelope draft must be valid");
        };
        draft
    }

    fn historical_s2_draft(
        epoch: u64,
        remaining_nanos: u64,
        auth_nonce: &[u8],
    ) -> RuntimeApplyEnvelopeDraft {
        let provenance = PlanProvenance::new(
            SourceScopeRef::from_bytes([1; 16]),
            SourcePlanRef::from_bytes([2; 16]),
            SourcePlanRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([4; 32])),
        );
        let header = RuntimeSliceHeader::new(
            RuntimeHostId::from_bytes([5; 16]),
            provenance,
            TargetAssignmentDigest::new(Digest32::from_bytes([6; 32])),
        );
        let Ok(commitment) = RuntimeSliceCommitment::try_new(header) else {
            panic!("historical S2 commitment must be valid");
        };
        let Ok(control) = build_runtime_apply_control_commitment(
            commitment,
            tenure(1, epoch),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([13; 16]),
        ) else {
            panic!("historical S2 control must be valid");
        };
        let Ok(draft) = RuntimeApplyEnvelopeDraft::try_new(
            control,
            temporal(remaining_nanos),
            auth_claim(auth_nonce),
        ) else {
            panic!("historical S2 draft must be valid");
        };
        draft
    }

    fn complete_draft(
        epoch: u64,
        remaining_nanos: u64,
        auth_nonce: &[u8],
    ) -> RuntimeApplyRequestDraft {
        let Ok(draft) = build_runtime_apply_request_draft(
            &projection(),
            tenure(1, epoch),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([13; 16]),
            temporal(remaining_nanos),
            auth_claim(auth_nonce),
        ) else {
            panic!("test complete request draft must be valid");
        };
        draft
    }

    fn s3_fixture_complete_draft() -> RuntimeApplyRequestDraft {
        let Ok(draft) = build_runtime_apply_request_draft(
            &s3_fixture_projection(),
            tenure(0x01, 1),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([0x0d; 16]),
            temporal(60),
            auth_claim(b"test-only-request-nonce"),
        ) else {
            panic!("production producer must build the independent S3 fixture request");
        };
        draft
    }

    fn s4_fixture_complete_draft() -> RuntimeApplyRequestV2Draft {
        let Ok(draft) = build_runtime_apply_request_v2_draft(
            &s4_fixture_projection(),
            tenure(0x01, 1),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([0x0d; 16]),
            temporal(60),
            auth_claim(b"test-only-request-nonce"),
        ) else {
            panic!("production producer must build the independent S4 fixture request");
        };
        draft
    }

    fn s5_complete_draft(
        drain_budget_nanos: u64,
        native_threads: u32,
        max_total_threads: u32,
    ) -> RuntimeApplyRequestV3Draft {
        let Ok(draft) = build_runtime_apply_request_v3_draft(
            &s5_projection(drain_budget_nanos, native_threads, max_total_threads),
            tenure(0x01, 1),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([0x0d; 16]),
            temporal(60),
            auth_claim(b"test-only-request-nonce"),
        ) else {
            panic!("production producer must build the S5 v3 request");
        };
        draft
    }

    fn s6_complete_draft(
        heartbeat_timeout_nanos: u64,
        entrypoint_digest_byte: u8,
    ) -> RuntimeApplyRequestV4Draft {
        let (projection, execution) =
            s6_projection(heartbeat_timeout_nanos, entrypoint_digest_byte);
        let Ok(draft) = build_runtime_apply_request_v4_draft(
            &projection,
            execution,
            tenure(0x01, 1),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([0x0d; 16]),
            temporal(60),
            auth_claim(b"test-only-request-nonce"),
        ) else {
            panic!("production producer must build the S6 v4 request");
        };
        draft
    }

    fn sign_and_finalize(draft: RuntimeApplyEnvelopeDraft) -> RuntimeApplyEnvelope {
        let Ok(transcript) = draft.signing_transcript() else {
            panic!("test request transcript must be valid");
        };
        let writer_signing_key = SigningKey::from_bytes(&TEST_ONLY_WRITER_SEED);
        let signature = writer_signing_key.sign(transcript.as_bytes());
        assert!(
            writer_signing_key
                .verifying_key()
                .verify_strict(transcript.as_bytes(), &signature)
                .is_ok()
        );
        let Ok(envelope) = draft.finalize(&signature.to_bytes()) else {
            panic!("signed test envelope must finalize");
        };
        envelope
    }

    fn sign_complete(draft: RuntimeApplyRequestDraft) -> RuntimeApplyRequest {
        let Ok(transcript) = draft.signing_transcript() else {
            panic!("complete request transcript must be valid");
        };
        let signature = SigningKey::from_bytes(&TEST_ONLY_WRITER_SEED).sign(transcript.as_bytes());
        let Ok(request) = draft.finalize(&signature.to_bytes()) else {
            panic!("complete signed request must finalize");
        };
        request
    }

    fn sign_complete_v2(draft: RuntimeApplyRequestV2Draft) -> RuntimeApplyRequestV2 {
        let Ok(transcript) = draft.signing_transcript() else {
            panic!("complete v2 request transcript must be valid");
        };
        let signature = SigningKey::from_bytes(&TEST_ONLY_WRITER_SEED).sign(transcript.as_bytes());
        let Ok(request) = draft.finalize(&signature.to_bytes()) else {
            panic!("complete signed v2 request must finalize");
        };
        request
    }

    fn sign_complete_v3(draft: RuntimeApplyRequestV3Draft) -> RuntimeApplyRequestV3 {
        let Ok(transcript) = draft.signing_transcript() else {
            panic!("complete v3 request transcript must be valid");
        };
        let writer_signing_key = SigningKey::from_bytes(&TEST_ONLY_WRITER_SEED);
        let signature = writer_signing_key.sign(transcript.as_bytes());
        assert!(
            writer_signing_key
                .verifying_key()
                .verify_strict(transcript.as_bytes(), &signature)
                .is_ok()
        );
        let Ok(request) = draft.finalize(&signature.to_bytes()) else {
            panic!("complete signed v3 request must finalize");
        };
        request
    }

    fn sign_complete_v4(draft: RuntimeApplyRequestV4Draft) -> RuntimeApplyRequestV4 {
        let Ok(transcript) = draft.signing_transcript() else {
            panic!("complete v4 request transcript must be valid");
        };
        let writer_signing_key = SigningKey::from_bytes(&TEST_ONLY_WRITER_SEED);
        let signature = writer_signing_key.sign(transcript.as_bytes());
        assert!(
            writer_signing_key
                .verifying_key()
                .verify_strict(transcript.as_bytes(), &signature)
                .is_ok()
        );
        let Ok(request) = draft.finalize(&signature.to_bytes()) else {
            panic!("complete signed v4 request must finalize");
        };
        request
    }

    #[test]
    fn historical_s2_signed_fixture_remains_stable_and_round_trips() {
        let fixture_wire = fixture_hex("canonical_wire_hex");
        let fixture_request_digest = fixture_hex("request_digest_hex");
        let fixture_request_transcript = fixture_hex("request_transcript_hex");
        let fixture_request_signature = fixture_hex("request_signature_hex");
        let fixture_tenure_transcript = fixture_hex("tenure_transcript_hex");
        let fixture_tenure_signature = fixture_hex("tenure_signature_hex");
        let first_draft = historical_s2_draft(1, 60, b"test-only-request-nonce");
        let second_draft = historical_s2_draft(1, 60, b"test-only-request-nonce");
        let Ok(first_transcript) = first_draft.signing_transcript() else {
            panic!("test request transcript must be valid");
        };
        let Ok(second_transcript) = second_draft.signing_transcript() else {
            panic!("test request transcript must be valid");
        };
        assert_eq!(first_transcript, second_transcript);
        assert_eq!(
            first_transcript.as_bytes(),
            fixture_request_transcript.as_slice()
        );

        let proof = first_draft
            .control_commitment()
            .control()
            .writer_context()
            .proof();
        let Ok(tenure_transcript) = proof.signing_transcript() else {
            panic!("test tenure transcript must be valid");
        };
        assert_eq!(
            tenure_transcript.as_bytes(),
            fixture_tenure_transcript.as_slice()
        );
        assert_eq!(proof.signature(), fixture_tenure_signature);

        let first = sign_and_finalize(first_draft);
        let second = sign_and_finalize(second_draft);
        assert_eq!(first.canonical_wire(), second.canonical_wire());
        assert_eq!(first.request_digest(), second.request_digest());
        assert_eq!(first.canonical_wire(), fixture_wire);
        assert_eq!(
            first.request_digest().as_bytes(),
            fixture_request_digest.as_slice()
        );
        assert_eq!(
            first.authentication().signature(),
            fixture_request_signature
        );

        let Ok(decoded) = RuntimeApplyEnvelope::decode(&fixture_wire) else {
            panic!("independent canonical fixture must decode");
        };
        assert_eq!(decoded, first);
        let Ok(decoded_transcript) = decoded.signing_transcript() else {
            panic!("decoded fixture transcript must rebuild");
        };
        assert_eq!(decoded_transcript.as_bytes(), fixture_request_transcript);
    }

    #[test]
    fn complete_request_producer_binds_real_assignments_and_round_trips() {
        let first = sign_complete(complete_draft(1, 60, b"complete-request-nonce"));
        let second = sign_complete(complete_draft(1, 60, b"complete-request-nonce"));

        assert_eq!(first, second);
        assert_eq!(
            first.slice().assignments().assignment_digest(),
            first
                .envelope()
                .control_commitment()
                .slice()
                .header()
                .assignment_digest()
        );
        let Ok(decoded) = RuntimeApplyRequest::decode(first.canonical_wire()) else {
            panic!("complete canonical request must decode");
        };
        assert_eq!(decoded, first);
        assert_eq!(
            decoded.request_digest(),
            decoded.envelope().request_digest()
        );
    }

    #[test]
    fn production_producer_exactly_matches_independent_s3_complete_fixture() {
        let expected_outer = s3_fixture_hex("outer_wire_hex");
        let expected_assignments = s3_fixture_hex("assignment_body_hex");
        let expected_assignment_digest = s3_fixture_hex("assignment_digest_hex");
        let expected_request_digest = s3_fixture_hex("request_digest_hex");

        let request = sign_complete(s3_fixture_complete_draft());
        assert_eq!(request.canonical_wire(), expected_outer);
        assert_eq!(
            request.slice().assignments().canonical_wire(),
            expected_assignments
        );
        assert_eq!(
            request
                .slice()
                .assignments()
                .assignment_digest()
                .value()
                .as_bytes()
                .as_slice(),
            expected_assignment_digest.as_slice()
        );
        assert_eq!(
            request.request_digest().as_bytes().as_slice(),
            expected_request_digest.as_slice()
        );
    }

    #[test]
    fn production_v2_producer_exactly_matches_independent_s4_fixture() {
        let expected_outer = s4_fixture_hex("outer_wire_hex");
        let expected_bindings = s4_fixture_hex("pxta_body_hex");
        let expected_execution = s4_fixture_hex("pxte_body_hex");
        let expected_execution_digest = s4_fixture_hex("pxte_digest_hex");
        let expected_composite_digest = s4_fixture_hex("composite_digest_hex");
        let expected_request_digest = s4_fixture_hex("request_digest_hex");

        let request = sign_complete_v2(s4_fixture_complete_draft());
        // PXTA is the complete binding body; PXTE authorizes only the one Card
        // Mailbox that may enter this LoopDomain. Binding 0x32 remains a passive
        // L2 source/sink boundary and grants no callback, dispatcher, or Task authority.
        assert_eq!(request.slice().assignments().bindings().len(), 2);
        assert_eq!(
            request
                .slice()
                .assignments()
                .execution()
                .mailbox_executions()
                .len(),
            1
        );
        assert_eq!(request.canonical_wire(), expected_outer);
        assert_eq!(
            request.slice().assignments().bindings().canonical_wire(),
            expected_bindings
        );
        assert_eq!(
            request.slice().assignments().execution().canonical_wire(),
            expected_execution
        );
        assert_eq!(
            request
                .slice()
                .assignments()
                .execution()
                .execution_digest()
                .value()
                .as_bytes()
                .as_slice(),
            expected_execution_digest.as_slice()
        );
        assert_eq!(
            request
                .slice()
                .assignments()
                .assignment_digest()
                .value()
                .as_bytes()
                .as_slice(),
            expected_composite_digest.as_slice()
        );
        assert_eq!(
            request.request_digest().as_bytes().as_slice(),
            expected_request_digest.as_slice()
        );
        let Ok(decoded) = RuntimeApplyRequestV2::decode(request.canonical_wire()) else {
            panic!("independent canonical S4 fixture must decode through Rust");
        };
        assert_eq!(decoded, request);
    }

    #[test]
    fn production_v3_producer_exactly_matches_independent_s5_fixture() {
        let expected_outer = s5_fixture_hex("outer_wire_hex");
        let expected_bindings = s5_fixture_hex("pxta_body_hex");
        let expected_loop = s5_fixture_hex("embedded_pxte_v1_body_hex");
        let expected_execution = s5_fixture_hex("pxte_v2_body_hex");
        let expected_execution_digest = s5_fixture_hex("pxte_v2_digest_hex");
        let expected_composite_digest = s5_fixture_hex("composite_v3_digest_hex");
        let expected_request_digest = s5_fixture_hex("request_digest_hex");
        let first = sign_complete_v3(s5_complete_draft(1_000_000_000, 0, 3));
        let second = sign_complete_v3(s5_complete_draft(1_000_000_000, 0, 3));

        assert_eq!(first, second);
        assert_eq!(first.canonical_wire(), expected_outer);
        assert_eq!(
            first.slice().assignments().bindings().canonical_wire(),
            expected_bindings
        );
        assert_eq!(first.slice().assignments().bindings().len(), 2);
        let Some(loop_plan) = first.slice().assignments().execution().loop_plan() else {
            panic!("S5 additive execution must retain the unchanged Loop plan");
        };
        assert_eq!(loop_plan.canonical_wire(), expected_loop);
        assert_eq!(loop_plan.mailbox_executions().len(), 1);
        assert_eq!(
            first.slice().assignments().execution().canonical_wire(),
            expected_execution
        );
        assert_eq!(
            first
                .slice()
                .assignments()
                .execution()
                .execution_digest()
                .value()
                .as_bytes()
                .as_slice(),
            expected_execution_digest.as_slice()
        );
        assert_eq!(
            first
                .slice()
                .assignments()
                .execution()
                .thread_domains()
                .len(),
            1
        );
        assert_eq!(
            first
                .slice()
                .assignments()
                .execution()
                .thread_mailbox_executions()
                .len(),
            1
        );
        assert_eq!(
            first.slice().assignments().assignment_digest(),
            first
                .envelope()
                .control_commitment()
                .slice()
                .header()
                .assignment_digest()
        );
        assert_eq!(
            first
                .slice()
                .assignments()
                .assignment_digest()
                .value()
                .as_bytes()
                .as_slice(),
            expected_composite_digest.as_slice()
        );
        assert_eq!(
            first.request_digest().as_bytes().as_slice(),
            expected_request_digest.as_slice()
        );
        let Ok(decoded) = RuntimeApplyRequestV3::decode(first.canonical_wire()) else {
            panic!("production v3 canonical request must decode");
        };
        assert_eq!(decoded, first);
        assert_eq!(
            decoded.request_digest(),
            decoded.envelope().request_digest()
        );
    }

    #[test]
    fn production_v4_producer_exactly_matches_independent_s6_fixture() {
        let expected_outer = s6_fixture_hex("outer_wire_hex");
        let expected_bindings = s6_fixture_hex("pxta_body_hex");
        let expected_prior = s6_fixture_hex("embedded_pxte_v2_body_hex");
        let expected_execution = s6_fixture_hex("pxte_v3_body_hex");
        let expected_execution_digest = s6_fixture_hex("pxte_v3_digest_hex");
        let expected_composite_digest = s6_fixture_hex("composite_v4_digest_hex");
        let expected_request_digest = s6_fixture_hex("request_digest_hex");
        let first = sign_complete_v4(s6_complete_draft(500_000_000, 0xc7));
        let second = sign_complete_v4(s6_complete_draft(500_000_000, 0xc7));

        assert_eq!(first, second);
        assert_eq!(first.canonical_wire(), expected_outer);
        assert_eq!(first.canonical_wire().len(), 2_962);
        assert_eq!(
            first.slice().assignments().bindings().canonical_wire(),
            expected_bindings
        );
        assert_eq!(first.slice().assignments().bindings().len(), 3);
        let execution = first.slice().assignments().execution();
        assert_eq!(execution.canonical_wire(), expected_execution);
        assert_eq!(
            execution
                .thread_plan()
                .unwrap_or_else(|| panic!("S6 must retain byte-exact PXTE v2"))
                .canonical_wire(),
            expected_prior
        );
        assert_eq!(execution.process_domains().len(), 1);
        assert_eq!(execution.process_mailbox_executions().len(), 1);
        assert_eq!(
            execution.execution_digest().value().as_bytes().as_slice(),
            expected_execution_digest
        );
        assert_eq!(
            first
                .slice()
                .assignments()
                .assignment_digest()
                .value()
                .as_bytes()
                .as_slice(),
            expected_composite_digest
        );
        assert_eq!(
            first.request_digest().as_bytes().as_slice(),
            expected_request_digest
        );
        let decoded = RuntimeApplyRequestV4::decode(first.canonical_wire())
            .unwrap_or_else(|error| panic!("production v4 request must decode: {error}"));
        assert_eq!(decoded, first);
    }

    #[test]
    fn v4_process_fields_rebind_execution_slice_request_and_signature() {
        let baseline = sign_complete_v4(s6_complete_draft(500_000_000, 0xc7));
        let heartbeat_changed = sign_complete_v4(s6_complete_draft(600_000_000, 0xc7));
        let entrypoint_changed = sign_complete_v4(s6_complete_draft(500_000_000, 0xc8));

        for changed in [&heartbeat_changed, &entrypoint_changed] {
            assert_ne!(
                baseline
                    .slice()
                    .assignments()
                    .execution()
                    .execution_digest(),
                changed.slice().assignments().execution().execution_digest()
            );
            assert_ne!(
                baseline.slice().assignments().assignment_digest(),
                changed.slice().assignments().assignment_digest()
            );
            assert_ne!(
                baseline.slice().commitment().target_slice_digest(),
                changed.slice().commitment().target_slice_digest()
            );
            assert_ne!(baseline.request_digest(), changed.request_digest());
            assert_ne!(
                baseline.envelope().authentication().signature(),
                changed.envelope().authentication().signature()
            );
        }
    }

    #[test]
    fn v4_builder_rejects_process_execution_without_exact_pxta_binding_before_signing() {
        let (projection, execution) = s6_projection(500_000_000, 0xc7);
        let bindings = projection.assignments().as_slice()[..2].to_vec();
        let Ok(bindings) = TargetAssignments::try_new(bindings) else {
            panic!("truncated fixture PXTA remains structurally valid");
        };
        let incomplete =
            CommittedTargetProjection::new(projection.plan(), projection.target(), bindings);
        let error = build_runtime_apply_request_v4_draft(
            &incomplete,
            execution,
            tenure(0x01, 1),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([0x0d; 16]),
            temporal(60),
            auth_claim(b"test-only-request-nonce"),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            EnvelopeBuildError::TargetPlanV4Request(TargetPlanV4ContractError::OrphanBinding)
        ));
    }

    #[test]
    fn v3_thread_plan_field_changes_rebind_digest_transcript_and_signature() {
        let baseline = sign_complete_v3(s5_complete_draft(1_000_000_000, 0, 4));
        let drain_changed = sign_complete_v3(s5_complete_draft(2_000_000_000, 0, 4));
        let native_changed = sign_complete_v3(s5_complete_draft(1_000_000_000, 1, 4));

        for changed in [&drain_changed, &native_changed] {
            assert_ne!(
                baseline
                    .slice()
                    .assignments()
                    .execution()
                    .execution_digest(),
                changed.slice().assignments().execution().execution_digest()
            );
            assert_ne!(
                baseline.slice().assignments().assignment_digest(),
                changed.slice().assignments().assignment_digest()
            );
            assert_ne!(
                baseline.slice().commitment().target_slice_digest(),
                changed.slice().commitment().target_slice_digest()
            );
            assert_ne!(baseline.request_digest(), changed.request_digest());
            assert_ne!(
                baseline.envelope().authentication().signature(),
                changed.envelope().authentication().signature()
            );
        }
    }

    #[test]
    fn rust_v2_decoder_reports_nested_rejections_and_body_tamper() {
        let wire = s4_fixture_hex("outer_wire_hex");
        let envelope_length = u32::from_be_bytes([wire[6], wire[7], wire[8], wire[9]]) as usize;
        let bindings_length = u32::from_be_bytes([wire[10], wire[11], wire[12], wire[13]]) as usize;
        let envelope_start = 18;
        let bindings_start = envelope_start + envelope_length;
        let execution_start = bindings_start + bindings_length;

        let mut invalid_envelope = wire.clone();
        invalid_envelope[envelope_start] ^= 0xff;
        assert_v2_rejection(
            &invalid_envelope,
            RequestV2WireErrorCode::EnvelopeRejected,
            Some(3),
        );

        let mut invalid_bindings = wire.clone();
        invalid_bindings[bindings_start] ^= 0xff;
        assert_v2_rejection(
            &invalid_bindings,
            RequestV2WireErrorCode::BindingsRejected,
            Some(3),
        );

        let mut invalid_execution = wire.clone();
        invalid_execution[execution_start] ^= 0xff;
        assert_v2_rejection(
            &invalid_execution,
            RequestV2WireErrorCode::ExecutionRejected,
            Some(3),
        );

        let mut unsafe_overrun = wire.clone();
        let mailbox_record = execution_start + 14 + 64;
        unsafe_overrun[mailbox_record + 235] = 1;
        assert_v2_rejection(
            &unsafe_overrun,
            RequestV2WireErrorCode::ExecutionRejected,
            Some(22),
        );

        let mut target_mismatch = wire.clone();
        let first_binding_record = bindings_start + 10;
        target_mismatch[first_binding_record + 103] ^= 0xff;
        assert_v2_rejection(
            &target_mismatch,
            RequestV2WireErrorCode::TargetPlanRejected,
            Some(3),
        );

        let mut forbidden_block = wire.clone();
        forbidden_block[first_binding_record + 222] = 5;
        forbidden_block[first_binding_record + 255] = 5;
        assert_v2_rejection(
            &forbidden_block,
            RequestV2WireErrorCode::TargetPlanRejected,
            Some(4),
        );

        let mut body_tamper = wire;
        body_tamper[mailbox_record + 160] ^= 0xff;
        assert_v2_rejection(
            &body_tamper,
            RequestV2WireErrorCode::CommitmentMismatch,
            None,
        );
    }

    #[test]
    fn fixed_wire_rejections_have_stable_codes_and_fields() {
        let wire = fixture_hex("canonical_wire_hex");

        for (tag, value, expected_code) in [
            (35, vec![0; 2], WireErrorCode::InvalidFieldValue),
            (8, vec![0xff; 32], WireErrorCode::DerivedDigestMismatch),
            (21, vec![0xff; 32], WireErrorCode::DerivedDigestMismatch),
            (25, vec![0xff; 32], WireErrorCode::DerivedDigestMismatch),
            (30, vec![0; 8], WireErrorCode::InvalidFieldValue),
            (
                31,
                101_u64.to_be_bytes().to_vec(),
                WireErrorCode::InvalidFieldValue,
            ),
            (
                22,
                2_u16.to_be_bytes().to_vec(),
                WireErrorCode::InvalidFieldValue,
            ),
        ] {
            let changed = replace_fixture_value(&wire, tag, &value);
            assert_fixture_rejection(&changed, expected_code, Some(tag));
        }

        let mut duplicate = wire.clone();
        let tag_two = tlv_location(&duplicate, 2);
        duplicate[tag_two.tag_offset..tag_two.tag_offset + 2].copy_from_slice(&1_u16.to_be_bytes());
        assert_fixture_rejection(&duplicate, WireErrorCode::DuplicateField, Some(1));

        let tag_37 = tlv_location(&wire, 37);
        assert_eq!(tag_37.whole.end, wire.len());
        let mut missing = wire[..tag_37.whole.start].to_vec();
        let count_offset = APPLY_ENVELOPE_MAGIC.len() + 2;
        missing[count_offset..count_offset + 2].copy_from_slice(&36_u16.to_be_bytes());
        assert_fixture_rejection(&missing, WireErrorCode::MissingField, Some(37));

        let mut out_of_order = wire.clone();
        let tag_one = tlv_location(&out_of_order, 1);
        out_of_order[tag_one.tag_offset..tag_one.tag_offset + 2]
            .copy_from_slice(&2_u16.to_be_bytes());
        assert_fixture_rejection(&out_of_order, WireErrorCode::OutOfOrderField, Some(2));

        assert_fixture_rejection(&wire[..wire.len() - 1], WireErrorCode::Truncated, Some(37));

        let mut trailing = wire;
        trailing.push(0);
        assert_fixture_rejection(&trailing, WireErrorCode::TrailingBytes, None);
    }

    #[test]
    fn writer_tenure_change_does_not_change_slice() {
        let first = draft(1, 60, b"test-only-request-nonce");
        let second = draft(2, 60, b"test-only-request-nonce");

        assert_eq!(
            first.control_commitment().slice(),
            second.control_commitment().slice()
        );
        assert_eq!(
            first.control_commitment().slice().target_slice_digest(),
            second.control_commitment().slice().target_slice_digest()
        );
        assert_ne!(
            first.control_commitment().commitment_digest(),
            second.control_commitment().commitment_digest()
        );
    }

    #[test]
    fn temporal_and_auth_changes_change_request_digest_and_signature() {
        let baseline = sign_and_finalize(draft(1, 60, b"test-only-request-nonce"));
        let temporal_changed = sign_and_finalize(draft(1, 59, b"test-only-request-nonce"));
        let auth_changed = sign_and_finalize(draft(1, 60, b"test-only-request-noncf"));

        for changed in [&temporal_changed, &auth_changed] {
            assert_eq!(
                baseline.control_commitment().slice(),
                changed.control_commitment().slice()
            );
            assert_ne!(baseline.request_digest(), changed.request_digest());
            assert_ne!(
                baseline.authentication().signature(),
                changed.authentication().signature()
            );
        }
    }

    #[test]
    fn mismatched_tenure_scope_fails_before_signing() {
        let result = build_runtime_apply_envelope_draft(
            &projection(),
            tenure(99, 1),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([13; 16]),
            temporal(60),
            auth_claim(b"test-only-request-nonce"),
        );

        assert_eq!(
            result.err(),
            Some(EnvelopeBuildError::Projection(ProjectionError::Apply(
                ApplyContractError::WriterScopeMismatch
            )))
        );
    }
}
