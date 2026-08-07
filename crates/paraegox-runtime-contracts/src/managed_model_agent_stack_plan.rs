//! Canonical fixed successor for one managed Fabric, Model, and Agent stack.
//!
//! This is deliberately not a general service graph. The only active shape
//! retains one exact PXTE v6 `FabricAndAgent` value, adds one bounded Model
//! service, and fixes the two readiness edges consumed by Agent. Empty is the
//! exact embedded PXTE v6 empty value with no Model plan or dependency bytes.

use core::{fmt, num::NonZeroU32};

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{BoundedDuration, ClockGeneration};

use crate::apply::{ApplyOperationId, RuntimeApplyControl, RuntimeApplyControlCommitment};
use crate::assignment::TargetAssignments;
use crate::managed_agent_stack_plan::{
    MANAGED_AGENT_PROVIDER_SELECTION_VERSION, MANAGED_AGENT_STACK_PROJECTION_BYTES,
    MAX_MANAGED_AGENT_HANDLER_TIMEOUT_NANOS, MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES,
    ManagedAgentProviderProfileV1, ManagedAgentProviderRefV1, ManagedAgentProviderSelectionV1,
    ManagedAgentSecretRefV1, ManagedAgentStackPlanError, ManagedAgentStackProjectionV1,
    ManagedAgentStackTargetExecutionV1, ManagedAgentStackTargetModeV1,
};
use crate::managed_service::{
    MANAGED_SERVICE_CONTRACT_VERSION, ManagedServiceGeneration, ManagedServiceId,
    ManagedServiceLifecycleBudgetsV1, ManagedServiceLifecycleStage, ManagedServiceSpecV1,
};
use crate::provenance::{
    PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, TargetAssignmentDigest,
    TargetSliceDigest,
};
use crate::reference_assembly::{
    ApplyRequestSigningTranscriptV2, MAX_CONTROL_READ_SIGNATURE_BYTES,
    MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES, RuntimeApplyEnvelopeV2, RuntimeApplyEnvelopeV2Draft,
    RuntimeStoreInstanceId,
};
use crate::reference_control::ReferenceChannelBindingV1;
use crate::temporal::ApplyTemporalConstraint;
use crate::wire::{
    ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim, ApplyRequestAuthentication,
};

const STACK_PROJECTION_MAGIC: &[u8; 4] = b"PXMM";
const TARGET_EXECUTION_MAGIC: &[u8; 4] = b"PXTE";
const APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const TERMINAL_RECEIPT_MAGIC: &[u8; 4] = b"PXMT";
const EMPTY_PXTA: [u8; 10] = [b'P', b'X', b'T', b'A', 0, 1, 0, 0, 0, 0];
const APPLY_REQUEST_HEADER_BYTES: usize = 18;
const BASE_PROJECTION_BYTES: usize = MANAGED_AGENT_STACK_PROJECTION_BYTES;
const STACK_PROJECTION_BYTES: usize = 4 + 2 + BASE_PROJECTION_BYTES + 32 + 2 + 2;
const TARGET_EXECUTION_FIXED_BYTES: usize = 4 + 2 + STACK_PROJECTION_BYTES + 2 + 1 + 1 + 1 + 1 + 4;
const MODEL_SERVICE_FIXED_BYTES: usize = 2 + 16 + (5 * 8);
const PROVIDER_SELECTION_FIXED_BYTES: usize = 2 + 1 + 1 + 16 + 32 + 1 + 16;
const ADAPTER_BINDING_FIXED_BYTES: usize = 2 + 16 + 4 + 16;
const MODEL_PLAN_FIXED_BYTES: usize =
    MODEL_SERVICE_FIXED_BYTES + 2 + PROVIDER_SELECTION_FIXED_BYTES + ADAPTER_BINDING_FIXED_BYTES;
const DEPENDENCY_FIXED_BYTES: usize = 2 + 1 + 1 + 1 + 1 + 16 + 16;

const STACK_COMPATIBILITY_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.compiled-managed-model-agent-stack-compatibility.sha256.v1";
const TARGET_EXECUTION_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.target-execution.sha256.v8";
const TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.target-plan-assignments.sha256.v9";
const TERMINAL_RESULT_REF_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-model-agent-stack-terminal-result.sha256.v1";
const TERMINAL_RECEIPT_SIGNING_MAGIC: &[u8] =
    b"ParaEGOX\0managed-model-agent-stack-terminal-signing";
const TERMINAL_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-model-agent-stack-terminal-receipt.sha256.v1";

/// Exact projection version for the fixed Fabric/Model/Agent successor.
pub const MANAGED_MODEL_AGENT_STACK_PROJECTION_VERSION: u16 = 1;
/// Exact outer apply-request version for this sibling successor.
pub const MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION: u16 = 9;
/// Exact target-execution version for this sibling successor.
pub const MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_VERSION: u16 = 8;
/// Exact fixed-profile version. It is not a general graph schema.
pub const MANAGED_MODEL_AGENT_STACK_PROFILE_VERSION: u16 = 1;
/// Exact Model adapter-binding version.
pub const MANAGED_MODEL_ADAPTER_BINDING_VERSION: u16 = 1;
/// The only Model capability admitted by the fixed A2 profile.
pub const MANAGED_MODEL_BOUNDED_TEXT_CAPABILITY_ID: [u8; 16] = *b"px-bounded-text1";
/// Exact fixed dependency-record version.
pub const MANAGED_MODEL_AGENT_DEPENDENCY_VERSION: u16 = 1;
/// Largest Model concurrency admitted by this first contract.
pub const MAX_MANAGED_MODEL_IN_FLIGHT: u16 = 256;
/// Exact fixed-width projection size.
pub const MANAGED_MODEL_AGENT_STACK_PROJECTION_BYTES: usize = STACK_PROJECTION_BYTES;
/// Maximum canonical PXTE v8 size.
pub const MAX_MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_BYTES: usize = TARGET_EXECUTION_FIXED_BYTES
    + MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES
    + MODEL_PLAN_FIXED_BYTES
    + (2 * DEPENDENCY_FIXED_BYTES);
/// Maximum durable `PXTA-zero || PXTE-v8` bytes.
pub const MAX_MANAGED_MODEL_AGENT_STACK_PLAN_SLICE_BYTES: usize =
    EMPTY_PXTA.len() + MAX_MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_BYTES;
/// Maximum canonical PXAR v9 request size.
pub const MAX_MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_BYTES: usize = APPLY_REQUEST_HEADER_BYTES
    + MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES
    + EMPTY_PXTA.len()
    + MAX_MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_BYTES;
/// Exact independent PXMT terminal receipt version.
pub const MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_VERSION: u16 = 1;
/// Exact PXMT signing-transcript version.
pub const MANAGED_MODEL_AGENT_STACK_TERMINAL_SIGNING_VERSION: u16 = 1;
/// Maximum canonical PXMT receipt bytes.
pub const MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_BYTES: usize = 2_048;
/// Maximum opaque Runtime response signature retained by PXMT.
pub const MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_SIGNATURE_BYTES: usize =
    MAX_CONTROL_READ_SIGNATURE_BYTES;

/// Nonzero adapter ABI/implementation version selected by desired state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedModelAdapterVersionV1(NonZeroU32);

impl ManagedModelAdapterVersionV1 {
    pub const fn try_new(value: u32) -> Result<Self, ManagedModelAgentStackPlanError> {
        match NonZeroU32::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(ManagedModelAgentStackPlanError::InvalidAdapterBinding),
        }
    }

    #[must_use]
    pub const fn value(self) -> u32 {
        self.0.get()
    }
}

/// Nonzero fixed-width capability identity retained by an adapter binding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedModelCapabilityIdV1([u8; 16]);

impl ManagedModelCapabilityIdV1 {
    pub const fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, ManagedModelAgentStackPlanError> {
        if bytes_are_zero(&bytes) {
            return Err(ManagedModelAgentStackPlanError::InvalidAdapterBinding);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn bounded_text_v1() -> Self {
        Self(MANAGED_MODEL_BOUNDED_TEXT_CAPABILITY_ID)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Exact adapter implementation selected for one Model service.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManagedModelAdapterBindingV1 {
    adapter_id: [u8; 16],
    adapter_version: ManagedModelAdapterVersionV1,
    capability_id: ManagedModelCapabilityIdV1,
}

impl ManagedModelAdapterBindingV1 {
    pub const fn try_new(
        adapter_id: [u8; 16],
        adapter_version: ManagedModelAdapterVersionV1,
        capability_id: ManagedModelCapabilityIdV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        if bytes_are_zero(&adapter_id)
            || !bytes_equal(
                capability_id.as_bytes(),
                &MANAGED_MODEL_BOUNDED_TEXT_CAPABILITY_ID,
            )
        {
            return Err(ManagedModelAgentStackPlanError::InvalidAdapterBinding);
        }
        Ok(Self {
            adapter_id,
            adapter_version,
            capability_id,
        })
    }

    #[must_use]
    pub const fn adapter_id(&self) -> &[u8; 16] {
        &self.adapter_id
    }

    #[must_use]
    pub const fn adapter_version(self) -> ManagedModelAdapterVersionV1 {
        self.adapter_version
    }

    #[must_use]
    pub const fn capability_id(self) -> ManagedModelCapabilityIdV1 {
        self.capability_id
    }
}

/// Complete bounded Model desired fields added beside the retained stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedModelServicePlanV1 {
    service: ManagedServiceSpecV1,
    max_in_flight: u16,
    provider: ManagedAgentProviderSelectionV1,
    adapter_binding: ManagedModelAdapterBindingV1,
}

impl ManagedModelServicePlanV1 {
    pub fn try_new(
        service: ManagedServiceSpecV1,
        max_in_flight: u16,
        provider: ManagedAgentProviderSelectionV1,
        adapter_binding: ManagedModelAdapterBindingV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        validate_service(service)?;
        if max_in_flight == 0 || max_in_flight > MAX_MANAGED_MODEL_IN_FLIGHT {
            return Err(ManagedModelAgentStackPlanError::InvalidModelPlan);
        }
        Ok(Self {
            service,
            max_in_flight,
            provider,
            adapter_binding,
        })
    }

    #[must_use]
    pub const fn service(&self) -> ManagedServiceSpecV1 {
        self.service
    }

    #[must_use]
    pub const fn max_in_flight(&self) -> u16 {
        self.max_in_flight
    }

    #[must_use]
    pub const fn provider(&self) -> ManagedAgentProviderSelectionV1 {
        self.provider
    }

    #[must_use]
    pub const fn adapter_binding(&self) -> ManagedModelAdapterBindingV1 {
        self.adapter_binding
    }
}

/// Exact fixed desired shape admitted by PXTE v8.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedModelAgentStackTargetModeV1 {
    /// One exact retained Fabric+Agent plan plus one Model service.
    FabricModelAndAgent = 1,
    /// Authoritative exact-zero stack.
    EmptyDeactivate = 2,
}

/// Identity of one of the only two admitted dependency edges.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedModelAgentDependencyKindV1 {
    FabricToAgent = 1,
    ModelToAgent = 2,
}

/// Fixed startup gate for both dependency edges.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedModelAgentDependencyReadinessV1 {
    RequireReady = 1,
}

/// Fixed consumer action when either dependency loses readiness.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedModelAgentDependencyLossPolicyV1 {
    StopConsumer = 1,
}

/// One derived edge in the fixed two-edge dependency profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManagedModelAgentServiceDependencyV1 {
    kind: ManagedModelAgentDependencyKindV1,
    provider_service_id: ManagedServiceId,
    consumer_service_id: ManagedServiceId,
}

impl ManagedModelAgentServiceDependencyV1 {
    const fn derived(
        kind: ManagedModelAgentDependencyKindV1,
        provider_service_id: ManagedServiceId,
        consumer_service_id: ManagedServiceId,
    ) -> Self {
        Self {
            kind,
            provider_service_id,
            consumer_service_id,
        }
    }

    #[must_use]
    pub const fn kind(self) -> ManagedModelAgentDependencyKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn provider_service_id(self) -> ManagedServiceId {
        self.provider_service_id
    }

    #[must_use]
    pub const fn consumer_service_id(self) -> ManagedServiceId {
        self.consumer_service_id
    }

    #[must_use]
    pub const fn readiness(self) -> ManagedModelAgentDependencyReadinessV1 {
        ManagedModelAgentDependencyReadinessV1::RequireReady
    }

    #[must_use]
    pub const fn loss_policy(self) -> ManagedModelAgentDependencyLossPolicyV1 {
        ManagedModelAgentDependencyLossPolicyV1::StopConsumer
    }
}

/// Additive installation projection retaining the exact PXSP v1 value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackProjectionV1 {
    managed_agent_stack: ManagedAgentStackProjectionV1,
    compatibility_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl ManagedModelAgentStackProjectionV1 {
    pub fn try_from_managed_agent_stack_projection(
        managed_agent_stack: ManagedAgentStackProjectionV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        let compatibility_digest = managed_model_agent_stack_compatibility_digest_v1()?;
        let canonical_wire = build_projection_wire(&managed_agent_stack, compatibility_digest);
        Ok(Self {
            managed_agent_stack,
            compatibility_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes PXMM v1 and never treats PXSP as this projection.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedModelAgentStackPlanError> {
        if frame.len() > STACK_PROJECTION_BYTES {
            return Err(ManagedModelAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < STACK_PROJECTION_BYTES {
            return Err(ManagedModelAgentStackPlanError::Truncated);
        }
        if &frame[..4] != STACK_PROJECTION_MAGIC
            || read_u16(&frame[4..6]) != MANAGED_MODEL_AGENT_STACK_PROJECTION_VERSION
        {
            return Err(ManagedModelAgentStackPlanError::UnsupportedWire);
        }
        let base_end = 6 + BASE_PROJECTION_BYTES;
        let managed_agent_stack = ManagedAgentStackProjectionV1::decode(&frame[6..base_end])?;
        let compatibility_digest =
            Digest32::from_bytes(read_array(&frame[base_end..base_end + 32]));
        if compatibility_digest != managed_model_agent_stack_compatibility_digest_v1()?
            || read_u16(&frame[base_end + 32..base_end + 34])
                != MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION
            || read_u16(&frame[base_end + 34..base_end + 36])
                != MANAGED_MODEL_AGENT_STACK_PROFILE_VERSION
        {
            return Err(ManagedModelAgentStackPlanError::CompatibilityMismatch);
        }
        let decoded = Self::try_from_managed_agent_stack_projection(managed_agent_stack)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedModelAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    #[must_use]
    pub const fn managed_agent_stack_projection(&self) -> &ManagedAgentStackProjectionV1 {
        &self.managed_agent_stack
    }

    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.managed_agent_stack.target()
    }

    #[must_use]
    pub const fn compatibility_digest(&self) -> Digest32 {
        self.compatibility_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// Canonical PXTE v8 fixed Fabric/Model/Agent desired value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackTargetExecutionV1 {
    projection: ManagedModelAgentStackProjectionV1,
    mode: ManagedModelAgentStackTargetModeV1,
    managed_agent_stack: ManagedAgentStackTargetExecutionV1,
    model: Option<ManagedModelServicePlanV1>,
    dependencies: Option<[ManagedModelAgentServiceDependencyV1; 2]>,
    canonical_wire: Box<[u8]>,
    execution_digest: Digest32,
}

impl ManagedModelAgentStackTargetExecutionV1 {
    pub fn try_fabric_model_and_agent(
        projection: ManagedModelAgentStackProjectionV1,
        managed_agent_stack: ManagedAgentStackTargetExecutionV1,
        model: ManagedModelServicePlanV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        Self::try_new(projection, managed_agent_stack, Some(model))
    }

    pub fn try_empty_deactivate(
        projection: ManagedModelAgentStackProjectionV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        let embedded = ManagedAgentStackTargetExecutionV1::try_empty_deactivate(
            projection.managed_agent_stack_projection().clone(),
        )?;
        Self::try_new(projection, embedded, None)
    }

    fn try_new(
        projection: ManagedModelAgentStackProjectionV1,
        managed_agent_stack: ManagedAgentStackTargetExecutionV1,
        model: Option<ManagedModelServicePlanV1>,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        if managed_agent_stack.projection() != projection.managed_agent_stack_projection() {
            return Err(ManagedModelAgentStackPlanError::ProjectionMismatch);
        }
        let (mode, dependencies) = match (managed_agent_stack.mode(), model.as_ref()) {
            (ManagedAgentStackTargetModeV1::FabricAndAgent, Some(model)) => {
                let fabric = managed_agent_stack
                    .fabric()
                    .service()
                    .ok_or(ManagedModelAgentStackPlanError::InvalidShape)?;
                let agent = managed_agent_stack
                    .agent()
                    .ok_or(ManagedModelAgentStackPlanError::InvalidShape)?;
                if model.provider() != agent.provider() {
                    return Err(ManagedModelAgentStackPlanError::ProviderMismatch);
                }
                let fabric_id = fabric.service_id();
                let model_id = model.service().service_id();
                let agent_id = agent.service().service_id();
                if fabric_id == model_id || fabric_id == agent_id || model_id == agent_id {
                    return Err(ManagedModelAgentStackPlanError::DuplicateServiceId);
                }
                (
                    ManagedModelAgentStackTargetModeV1::FabricModelAndAgent,
                    Some([
                        ManagedModelAgentServiceDependencyV1::derived(
                            ManagedModelAgentDependencyKindV1::FabricToAgent,
                            fabric_id,
                            agent_id,
                        ),
                        ManagedModelAgentServiceDependencyV1::derived(
                            ManagedModelAgentDependencyKindV1::ModelToAgent,
                            model_id,
                            agent_id,
                        ),
                    ]),
                )
            }
            (ManagedAgentStackTargetModeV1::EmptyDeactivate, None) => {
                (ManagedModelAgentStackTargetModeV1::EmptyDeactivate, None)
            }
            _ => return Err(ManagedModelAgentStackPlanError::InvalidShape),
        };
        let canonical_wire = build_target_execution_wire(
            &projection,
            mode,
            &managed_agent_stack,
            model.as_ref(),
            dependencies.as_ref(),
        )?;
        if canonical_wire.len() > MAX_MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_BYTES {
            return Err(ManagedModelAgentStackPlanError::FrameTooLarge);
        }
        let execution_digest = digest_wire(TARGET_EXECUTION_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            projection,
            mode,
            managed_agent_stack,
            model,
            dependencies,
            canonical_wire: canonical_wire.into_boxed_slice(),
            execution_digest,
        })
    }

    /// Strictly decodes exactly PXTE v8 and cross-rejects predecessor versions.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedModelAgentStackPlanError> {
        if frame.len() > MAX_MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_BYTES {
            return Err(ManagedModelAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < TARGET_EXECUTION_FIXED_BYTES {
            return Err(ManagedModelAgentStackPlanError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.take(4)? != TARGET_EXECUTION_MAGIC
            || cursor.u16()? != MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_VERSION
        {
            return Err(ManagedModelAgentStackPlanError::UnsupportedWire);
        }
        let projection =
            ManagedModelAgentStackProjectionV1::decode(cursor.take(STACK_PROJECTION_BYTES)?)?;
        if cursor.u16()? != MANAGED_MODEL_AGENT_STACK_PROFILE_VERSION {
            return Err(ManagedModelAgentStackPlanError::UnsupportedWire);
        }
        let mode = match cursor.u8()? {
            1 => ManagedModelAgentStackTargetModeV1::FabricModelAndAgent,
            2 => ManagedModelAgentStackTargetModeV1::EmptyDeactivate,
            _ => return Err(ManagedModelAgentStackPlanError::InvalidShape),
        };
        let model_present = cursor.u8()?;
        let dependency_count = cursor.u8()?;
        if cursor.u8()? != 0 {
            return Err(ManagedModelAgentStackPlanError::NonCanonicalFrame);
        }
        let embedded_length = cursor.usize_u32()?;
        if embedded_length == 0 || embedded_length > MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES
        {
            return Err(ManagedModelAgentStackPlanError::InvalidLength);
        }
        let embedded = ManagedAgentStackTargetExecutionV1::decode(cursor.take(embedded_length)?)?;
        let decoded = match (mode, model_present, dependency_count) {
            (ManagedModelAgentStackTargetModeV1::FabricModelAndAgent, 1, 2) => {
                let model = decode_model_plan(&mut cursor)?;
                let encoded_dependencies = [
                    decode_dependency(&mut cursor)?,
                    decode_dependency(&mut cursor)?,
                ];
                cursor.finish()?;
                let decoded = Self::try_fabric_model_and_agent(projection, embedded, model)?;
                if decoded.dependencies != Some(encoded_dependencies) {
                    return Err(ManagedModelAgentStackPlanError::InvalidDependencyProfile);
                }
                decoded
            }
            (ManagedModelAgentStackTargetModeV1::EmptyDeactivate, 0, 0) => {
                cursor.finish()?;
                let decoded = Self::try_empty_deactivate(projection)?;
                if decoded.managed_agent_stack != embedded {
                    return Err(ManagedModelAgentStackPlanError::NonCanonicalFrame);
                }
                decoded
            }
            _ => return Err(ManagedModelAgentStackPlanError::InvalidShape),
        };
        if decoded.canonical_wire() != frame {
            return Err(ManagedModelAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    #[must_use]
    pub const fn projection(&self) -> &ManagedModelAgentStackProjectionV1 {
        &self.projection
    }

    #[must_use]
    pub const fn mode(&self) -> ManagedModelAgentStackTargetModeV1 {
        self.mode
    }

    #[must_use]
    pub const fn managed_agent_stack(&self) -> &ManagedAgentStackTargetExecutionV1 {
        &self.managed_agent_stack
    }

    #[must_use]
    pub const fn model(&self) -> Option<&ManagedModelServicePlanV1> {
        self.model.as_ref()
    }

    #[must_use]
    pub const fn dependencies(&self) -> Option<&[ManagedModelAgentServiceDependencyV1; 2]> {
        self.dependencies.as_ref()
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub const fn execution_digest(&self) -> Digest32 {
        self.execution_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedModelAgentStackAssignmentsV1 {
    bindings: TargetAssignments,
    execution: ManagedModelAgentStackTargetExecutionV1,
    assignment_digest: TargetAssignmentDigest,
}

impl ManagedModelAgentStackAssignmentsV1 {
    fn try_from_execution(
        execution: ManagedModelAgentStackTargetExecutionV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        let bindings = TargetAssignments::try_new(Vec::new())
            .map_err(|_| ManagedModelAgentStackPlanError::BindingNotAllowed)?;
        Self::try_new(bindings, execution)
    }

    fn try_new(
        bindings: TargetAssignments,
        execution: ManagedModelAgentStackTargetExecutionV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        bindings
            .validate()
            .map_err(|_| ManagedModelAgentStackPlanError::BindingNotAllowed)?;
        if !bindings.is_empty() || bindings.canonical_wire() != EMPTY_PXTA {
            return Err(ManagedModelAgentStackPlanError::BindingNotAllowed);
        }
        let mut builder = Digest32Builder::try_new(TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN)?;
        builder.field_digest(bindings.assignment_digest().value())?;
        builder.field_digest(&execution.execution_digest())?;
        Ok(Self {
            bindings,
            execution,
            assignment_digest: TargetAssignmentDigest::new(builder.finish()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedModelAgentStackPlanSliceV1 {
    commitment: RuntimeSliceCommitment,
    assignments: ManagedModelAgentStackAssignmentsV1,
}

impl ManagedModelAgentStackPlanSliceV1 {
    fn try_new(
        commitment: RuntimeSliceCommitment,
        assignments: ManagedModelAgentStackAssignmentsV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        commitment.validate()?;
        if commitment.header().assignment_digest() != assignments.assignment_digest {
            return Err(ManagedModelAgentStackPlanError::CommitmentMismatch);
        }
        if commitment.header().target() != assignments.execution.projection().target() {
            return Err(ManagedModelAgentStackPlanError::TargetMismatch);
        }
        Ok(Self {
            commitment,
            assignments,
        })
    }
}

/// Canonical envelope-v2 signing transcript used by PXAR v9.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackApplySigningTranscriptV2(ApplyRequestSigningTranscriptV2);

impl ManagedModelAgentStackApplySigningTranscriptV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Signature-independent PXAR v9 producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackApplyRequestDraftV1 {
    envelope: RuntimeApplyEnvelopeV2Draft,
    slice: ManagedModelAgentStackPlanSliceV1,
}

impl ManagedModelAgentStackApplyRequestDraftV1 {
    pub fn try_new(
        execution: ManagedModelAgentStackTargetExecutionV1,
        provenance: PlanProvenance,
        control: RuntimeApplyControl,
        temporal: ApplyTemporalConstraint,
        expected_runtime_store_instance_id: [u8; 32],
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        let assignments = ManagedModelAgentStackAssignmentsV1::try_from_execution(execution)?;
        let header = RuntimeSliceHeader::new(
            assignments.execution.projection().target(),
            provenance,
            assignments.assignment_digest,
        );
        let commitment = RuntimeSliceCommitment::try_new(header)?;
        let slice = ManagedModelAgentStackPlanSliceV1::try_new(commitment, assignments)?;
        let control_commitment = RuntimeApplyControlCommitment::try_new(commitment, control)?;
        let store = RuntimeStoreInstanceId::try_from_bytes(expected_runtime_store_instance_id)?;
        let envelope =
            RuntimeApplyEnvelopeV2Draft::try_new(control_commitment, temporal, store, auth_claim)?;
        Ok(Self { envelope, slice })
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedModelAgentStackApplySigningTranscriptV2, ManagedModelAgentStackPlanError>
    {
        Ok(ManagedModelAgentStackApplySigningTranscriptV2(
            self.envelope.signing_transcript()?,
        ))
    }

    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ManagedModelAgentStackApplyRequestV1, ManagedModelAgentStackPlanError> {
        let envelope = self.envelope.finalize(signature)?;
        ManagedModelAgentStackApplyRequestV1::try_new(envelope, self.slice)
    }
}

/// Signed strict PXAR v9 carrying envelope v2, PXTA-zero, and PXTE v8.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackApplyRequestV1 {
    envelope: RuntimeApplyEnvelopeV2,
    slice: ManagedModelAgentStackPlanSliceV1,
    canonical_wire: Box<[u8]>,
}

impl ManagedModelAgentStackApplyRequestV1 {
    fn try_new(
        envelope: RuntimeApplyEnvelopeV2,
        slice: ManagedModelAgentStackPlanSliceV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        if envelope.control_commitment().slice() != slice.commitment {
            return Err(ManagedModelAgentStackPlanError::CommitmentMismatch);
        }
        let canonical_wire = build_apply_request_wire(&envelope, &slice)?;
        if canonical_wire.len() > MAX_MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_BYTES {
            return Err(ManagedModelAgentStackPlanError::FrameTooLarge);
        }
        Ok(Self {
            envelope,
            slice,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes PXAR v9 and cross-rejects all predecessor versions.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedModelAgentStackPlanError> {
        if frame.len() > MAX_MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_BYTES {
            return Err(ManagedModelAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < APPLY_REQUEST_HEADER_BYTES {
            return Err(ManagedModelAgentStackPlanError::Truncated);
        }
        if &frame[..4] != APPLY_REQUEST_MAGIC
            || read_u16(&frame[4..6]) != MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION
        {
            return Err(ManagedModelAgentStackPlanError::UnsupportedWire);
        }
        let envelope_length = read_u32(&frame[6..10]) as usize;
        let bindings_length = read_u32(&frame[10..14]) as usize;
        let execution_length = read_u32(&frame[14..18]) as usize;
        if envelope_length > MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES
            || bindings_length != EMPTY_PXTA.len()
            || execution_length > MAX_MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_BYTES
        {
            return Err(ManagedModelAgentStackPlanError::InvalidLength);
        }
        let expected_length = APPLY_REQUEST_HEADER_BYTES
            .checked_add(envelope_length)
            .and_then(|value| value.checked_add(bindings_length))
            .and_then(|value| value.checked_add(execution_length))
            .ok_or(ManagedModelAgentStackPlanError::FrameTooLarge)?;
        if frame.len() < expected_length {
            return Err(ManagedModelAgentStackPlanError::Truncated);
        }
        if frame.len() > expected_length {
            return Err(ManagedModelAgentStackPlanError::TrailingBytes);
        }
        let envelope_start = APPLY_REQUEST_HEADER_BYTES;
        let envelope_end = envelope_start + envelope_length;
        let bindings_end = envelope_end + bindings_length;
        let envelope = RuntimeApplyEnvelopeV2::decode(&frame[envelope_start..envelope_end])?;
        let binding_frame = &frame[envelope_end..bindings_end];
        if binding_frame != EMPTY_PXTA {
            return Err(ManagedModelAgentStackPlanError::BindingNotAllowed);
        }
        let bindings = TargetAssignments::decode(binding_frame)
            .map_err(|_| ManagedModelAgentStackPlanError::BindingNotAllowed)?;
        let execution = ManagedModelAgentStackTargetExecutionV1::decode(&frame[bindings_end..])?;
        let assignments = ManagedModelAgentStackAssignmentsV1::try_new(bindings, execution)?;
        let slice = ManagedModelAgentStackPlanSliceV1::try_new(
            envelope.control_commitment().slice(),
            assignments,
        )?;
        let decoded = Self::try_new(envelope, slice)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedModelAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub fn canonical_slice_wire(&self) -> &[u8] {
        let offset = APPLY_REQUEST_HEADER_BYTES + self.envelope.canonical_wire().len();
        &self.canonical_wire[offset..]
    }

    #[must_use]
    pub const fn target_execution(&self) -> &ManagedModelAgentStackTargetExecutionV1 {
        &self.slice.assignments.execution
    }

    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.slice.commitment.header().target()
    }

    #[must_use]
    pub const fn provenance(&self) -> PlanProvenance {
        self.slice.commitment.header().provenance()
    }

    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.slice.commitment.header().assignment_digest()
    }

    #[must_use]
    pub const fn target_slice_digest(&self) -> TargetSliceDigest {
        self.slice.commitment.target_slice_digest()
    }

    #[must_use]
    pub const fn control_commitment(&self) -> &RuntimeApplyControlCommitment {
        self.envelope.control_commitment()
    }

    #[must_use]
    pub const fn operation_id(&self) -> ApplyOperationId {
        self.envelope.control_commitment().control().operation_id()
    }

    #[must_use]
    pub const fn temporal(&self) -> ApplyTemporalConstraint {
        self.envelope.temporal()
    }

    #[must_use]
    pub const fn expected_runtime_store_instance_id(&self) -> [u8; 32] {
        *self
            .envelope
            .expected_runtime_store_instance_id()
            .as_bytes()
    }

    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        self.envelope.authentication()
    }

    #[must_use]
    pub const fn envelope_request_digest(&self) -> Digest32 {
        self.envelope.request_digest()
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedModelAgentStackApplySigningTranscriptV2, ManagedModelAgentStackPlanError>
    {
        Ok(ManagedModelAgentStackApplySigningTranscriptV2(
            self.envelope.signing_transcript()?,
        ))
    }

    pub fn validate_expected_store(
        &self,
        local_runtime_store_instance_id: [u8; 32],
    ) -> Result<(), ManagedModelAgentStackPlanError> {
        let local = RuntimeStoreInstanceId::try_from_bytes(local_runtime_store_instance_id)?;
        self.envelope.validate_expected_store(local)?;
        Ok(())
    }

    pub fn validate_projection(
        &self,
        projection: &ManagedModelAgentStackProjectionV1,
    ) -> Result<(), ManagedModelAgentStackPlanError> {
        if self.target_execution().projection() != projection {
            return Err(ManagedModelAgentStackPlanError::ProjectionMismatch);
        }
        Ok(())
    }
}

/// Reconstructs one durable `PXTA-zero || PXTE-v8` value from journal authority.
pub fn verify_managed_model_agent_stack_durable_slice_v1(
    canonical_slice_wire: &[u8],
    target: RuntimeHostId,
    provenance: PlanProvenance,
    expected_target_slice_digest: TargetSliceDigest,
    projection: &ManagedModelAgentStackProjectionV1,
) -> Result<ManagedModelAgentStackTargetExecutionV1, ManagedModelAgentStackPlanError> {
    if canonical_slice_wire.len() > MAX_MANAGED_MODEL_AGENT_STACK_PLAN_SLICE_BYTES {
        return Err(ManagedModelAgentStackPlanError::FrameTooLarge);
    }
    if canonical_slice_wire.len() < EMPTY_PXTA.len() {
        return Err(ManagedModelAgentStackPlanError::Truncated);
    }
    let (binding_frame, execution_frame) = canonical_slice_wire.split_at(EMPTY_PXTA.len());
    if binding_frame != EMPTY_PXTA {
        return Err(ManagedModelAgentStackPlanError::BindingNotAllowed);
    }
    let bindings = TargetAssignments::decode(binding_frame)
        .map_err(|_| ManagedModelAgentStackPlanError::BindingNotAllowed)?;
    let execution = ManagedModelAgentStackTargetExecutionV1::decode(execution_frame)?;
    if execution.projection() != projection || execution.projection().target() != target {
        return Err(ManagedModelAgentStackPlanError::ProjectionMismatch);
    }
    let assignments = ManagedModelAgentStackAssignmentsV1::try_new(bindings, execution)?;
    let commitment = RuntimeSliceCommitment::try_new(RuntimeSliceHeader::new(
        target,
        provenance,
        assignments.assignment_digest,
    ))?;
    if commitment.target_slice_digest() != expected_target_slice_digest {
        return Err(ManagedModelAgentStackPlanError::CommitmentMismatch);
    }
    let slice = ManagedModelAgentStackPlanSliceV1::try_new(commitment, assignments)?;
    Ok(slice.assignments.execution)
}

/// Runtime terminal classification for one exact PXAR v9 operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedModelAgentStackTerminalOutcomeV1 {
    ActiveReady = 1,
    EmptyExactZero = 2,
    NoEffectRejected = 3,
    Uncertain = 4,
    Quarantined = 5,
}

/// Strongest lifecycle-effect claim made by one terminal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedModelAgentStackTerminalLifecycleEffectV1 {
    ProvenNotStarted = 1,
    MayHaveStarted = 2,
}

/// Runtime-observed desired head after the exact operation completed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ManagedModelAgentStackTerminalHeadV1 {
    PreservedNone,
    PreservedExisting(TargetSliceDigest),
    CommittedIncoming,
}

/// Derived nonzero identity of one PXMT result.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedModelAgentStackTerminalResultRefV1([u8; 16]);

impl ManagedModelAgentStackTerminalResultRefV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Lifecycle, desired-head, and all three observed generation facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackTerminalStateV1 {
    outcome: ManagedModelAgentStackTerminalOutcomeV1,
    lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1,
    head: ManagedModelAgentStackTerminalHeadV1,
    fabric_generation: Option<ManagedServiceGeneration>,
    model_generation: Option<ManagedServiceGeneration>,
    agent_generation: Option<ManagedServiceGeneration>,
}

impl ManagedModelAgentStackTerminalStateV1 {
    pub fn try_new(
        outcome: ManagedModelAgentStackTerminalOutcomeV1,
        lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1,
        head: ManagedModelAgentStackTerminalHeadV1,
        fabric_generation: Option<ManagedServiceGeneration>,
        model_generation: Option<ManagedServiceGeneration>,
        agent_generation: Option<ManagedServiceGeneration>,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        if agent_generation.is_some() && (fabric_generation.is_none() || model_generation.is_none())
        {
            return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
        }
        let state = Self {
            outcome,
            lifecycle_effect,
            head,
            fabric_generation,
            model_generation,
            agent_generation,
        };
        validate_terminal_state(state)?;
        Ok(state)
    }

    #[must_use]
    pub const fn outcome(self) -> ManagedModelAgentStackTerminalOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub const fn lifecycle_effect(self) -> ManagedModelAgentStackTerminalLifecycleEffectV1 {
        self.lifecycle_effect
    }

    #[must_use]
    pub const fn head(self) -> ManagedModelAgentStackTerminalHeadV1 {
        self.head
    }

    #[must_use]
    pub const fn fabric_generation(self) -> Option<ManagedServiceGeneration> {
        self.fabric_generation
    }

    #[must_use]
    pub const fn model_generation(self) -> Option<ManagedServiceGeneration> {
        self.model_generation
    }

    #[must_use]
    pub const fn agent_generation(self) -> Option<ManagedServiceGeneration> {
        self.agent_generation
    }
}

/// Caller-supplied observations signed into one bounded terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackTerminalEvidenceFieldsV1 {
    pub physical_binding_census: u16,
    pub census_complete: bool,
    pub fabric_ready: bool,
    pub model_ready: bool,
    pub agent_ready: bool,
    pub fabric_to_agent_dependency_ready: bool,
    pub model_to_agent_dependency_ready: bool,
    pub exact_zero: bool,
    pub quarantined: bool,
    pub resource_census_digest: Digest32,
    pub raw_outcome_digest: Digest32,
    pub completion_runtime_host_epoch: u64,
    pub completion_snapshot_sequence: u64,
    pub selection_clock_generation: ClockGeneration,
    pub selection_observed_at_nanos: u64,
}

/// Validated census, three readiness facts, and two dependency-ready facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackTerminalEvidenceV1(ManagedModelAgentStackTerminalEvidenceFieldsV1);

impl ManagedModelAgentStackTerminalEvidenceV1 {
    pub fn try_new(
        fields: ManagedModelAgentStackTerminalEvidenceFieldsV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        if fields.physical_binding_census > 2
            || (fields.fabric_to_agent_dependency_ready && !fields.fabric_ready)
            || (fields.model_to_agent_dependency_ready && !fields.model_ready)
            || (fields.agent_ready
                && (!fields.fabric_ready
                    || !fields.model_ready
                    || !fields.fabric_to_agent_dependency_ready
                    || !fields.model_to_agent_dependency_ready))
            || fields.exact_zero
                && (fields.physical_binding_census != 0
                    || fields.fabric_ready
                    || fields.model_ready
                    || fields.agent_ready
                    || fields.fabric_to_agent_dependency_ready
                    || fields.model_to_agent_dependency_ready
                    || fields.quarantined)
            || digest_is_zero(fields.resource_census_digest)
            || digest_is_zero(fields.raw_outcome_digest)
            || fields.completion_runtime_host_epoch == 0
            || fields.completion_snapshot_sequence == 0
            || fields.selection_observed_at_nanos == 0
        {
            return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
        }
        Ok(Self(fields))
    }

    #[must_use]
    pub const fn fields(self) -> ManagedModelAgentStackTerminalEvidenceFieldsV1 {
        self.0
    }
}

/// Complete request-correlated Runtime facts signed into PXMT v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackTerminalFactsV1 {
    target: RuntimeHostId,
    runtime_store_instance_id: [u8; 32],
    source_scope: crate::provenance::SourceScopeRef,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    target_slice_digest: TargetSliceDigest,
    assignment_digest: TargetAssignmentDigest,
    terminal_result_ref: ManagedModelAgentStackTerminalResultRefV1,
    request_mode: ManagedModelAgentStackTargetModeV1,
    state: ManagedModelAgentStackTerminalStateV1,
    desired_head_digest: Option<TargetSliceDigest>,
    evidence: ManagedModelAgentStackTerminalEvidenceV1,
}

impl ManagedModelAgentStackTerminalFactsV1 {
    pub fn try_new(
        request: &ManagedModelAgentStackApplyRequestV1,
        state: ManagedModelAgentStackTerminalStateV1,
        evidence: ManagedModelAgentStackTerminalEvidenceV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        validate_terminal_state_evidence(state, evidence)?;
        validate_terminal_outcome_mode(state.outcome(), request.target_execution().mode())?;
        let desired_head_digest = resolve_terminal_head(request, state.head())?;
        Ok(Self {
            target: request.target(),
            runtime_store_instance_id: request.expected_runtime_store_instance_id(),
            source_scope: request.provenance().source_scope(),
            operation_id: request.operation_id(),
            request_digest: request.envelope_request_digest(),
            target_slice_digest: request.target_slice_digest(),
            assignment_digest: request.assignment_digest(),
            terminal_result_ref: derive_terminal_result_ref(request)?,
            request_mode: request.target_execution().mode(),
            state,
            desired_head_digest,
            evidence,
        })
    }

    fn validate_against_request(
        self,
        request: &ManagedModelAgentStackApplyRequestV1,
    ) -> Result<(), ManagedModelAgentStackPlanError> {
        validate_terminal_state_evidence(self.state, self.evidence)?;
        validate_terminal_outcome_mode(self.state.outcome(), request.target_execution().mode())?;
        if self.target != request.target()
            || self.runtime_store_instance_id != request.expected_runtime_store_instance_id()
            || self.source_scope != request.provenance().source_scope()
            || self.operation_id != request.operation_id()
            || self.request_digest != request.envelope_request_digest()
            || self.target_slice_digest != request.target_slice_digest()
            || self.assignment_digest != request.assignment_digest()
            || self.terminal_result_ref != derive_terminal_result_ref(request)?
            || self.request_mode != request.target_execution().mode()
            || self.desired_head_digest != resolve_terminal_head(request, self.state.head())?
            || self.evidence.fields().selection_clock_generation.value()
                < request.temporal().target_clock_generation().value()
        {
            return Err(ManagedModelAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn target(self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub const fn runtime_store_instance_id(self) -> [u8; 32] {
        self.runtime_store_instance_id
    }

    #[must_use]
    pub const fn source_scope(self) -> crate::provenance::SourceScopeRef {
        self.source_scope
    }

    #[must_use]
    pub const fn operation_id(self) -> ApplyOperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn request_digest(self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub const fn target_slice_digest(self) -> TargetSliceDigest {
        self.target_slice_digest
    }

    #[must_use]
    pub const fn assignment_digest(self) -> TargetAssignmentDigest {
        self.assignment_digest
    }

    #[must_use]
    pub const fn terminal_result_ref(self) -> ManagedModelAgentStackTerminalResultRefV1 {
        self.terminal_result_ref
    }

    #[must_use]
    pub const fn request_mode(self) -> ManagedModelAgentStackTargetModeV1 {
        self.request_mode
    }

    #[must_use]
    pub const fn state(self) -> ManagedModelAgentStackTerminalStateV1 {
        self.state
    }

    #[must_use]
    pub const fn desired_head_digest(self) -> Option<TargetSliceDigest> {
        self.desired_head_digest
    }

    #[must_use]
    pub const fn evidence(self) -> ManagedModelAgentStackTerminalEvidenceV1 {
        self.evidence
    }
}

/// Runtime signer selection bound to the exact local control channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackTerminalAuthClaimV1 {
    runtime_peer: PrincipalRef,
    channel_binding_digest: Digest32,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

impl ManagedModelAgentStackTerminalAuthClaimV1 {
    pub fn try_new(
        channel: ReferenceChannelBindingV1,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        if bytes_are_zero(key.as_bytes()) || algorithm_version == 0 {
            return Err(ManagedModelAgentStackPlanError::InvalidResponseAuthentication);
        }
        Ok(Self {
            runtime_peer: channel.runtime_peer(),
            channel_binding_digest: channel.binding_digest(),
            key,
            algorithm,
            algorithm_version,
        })
    }

    #[must_use]
    pub const fn runtime_peer(self) -> PrincipalRef {
        self.runtime_peer
    }

    #[must_use]
    pub const fn channel_binding_digest(self) -> Digest32 {
        self.channel_binding_digest
    }

    #[must_use]
    pub const fn key(self) -> ApplyAuthKeyRef {
        self.key
    }

    #[must_use]
    pub const fn algorithm(self) -> ApplyAuthAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub const fn algorithm_version(self) -> u16 {
        self.algorithm_version
    }
}

/// Exact bytes supplied to the independent Runtime response signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackTerminalSigningTranscriptV1(Box<[u8]>);

impl ManagedModelAgentStackTerminalSigningTranscriptV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent PXMT v1 producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackTerminalReceiptDraftV1 {
    facts: ManagedModelAgentStackTerminalFactsV1,
    channel: ReferenceChannelBindingV1,
    auth_claim: ManagedModelAgentStackTerminalAuthClaimV1,
}

impl ManagedModelAgentStackTerminalReceiptDraftV1 {
    pub fn try_new(
        request: &ManagedModelAgentStackApplyRequestV1,
        facts: ManagedModelAgentStackTerminalFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: ManagedModelAgentStackTerminalAuthClaimV1,
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        facts.validate_against_request(request)?;
        if channel.target() != request.target()
            || auth_claim.runtime_peer() != channel.runtime_peer()
            || auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(ManagedModelAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(Self {
            facts,
            channel,
            auth_claim,
        })
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedModelAgentStackTerminalSigningTranscriptV1, ManagedModelAgentStackPlanError>
    {
        Ok(ManagedModelAgentStackTerminalSigningTranscriptV1(
            build_terminal_fields(
                TERMINAL_RECEIPT_SIGNING_MAGIC,
                MANAGED_MODEL_AGENT_STACK_TERMINAL_SIGNING_VERSION,
                self.facts,
                self.channel,
                self.auth_claim,
            )?
            .into_boxed_slice(),
        ))
    }

    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ManagedModelAgentStackTerminalReceiptV1, ManagedModelAgentStackPlanError> {
        if signature.is_empty()
            || signature.len() > MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_SIGNATURE_BYTES
        {
            return Err(ManagedModelAgentStackPlanError::InvalidResponseAuthentication);
        }
        ManagedModelAgentStackTerminalReceiptV1::try_new(
            self.facts,
            self.channel,
            self.auth_claim,
            signature,
        )
    }
}

/// Signed strict independent PXMT v1 Runtime terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedModelAgentStackTerminalReceiptV1 {
    facts: ManagedModelAgentStackTerminalFactsV1,
    channel: ReferenceChannelBindingV1,
    auth_claim: ManagedModelAgentStackTerminalAuthClaimV1,
    signature: Box<[u8]>,
    canonical_wire: Box<[u8]>,
    receipt_digest: Digest32,
}

impl ManagedModelAgentStackTerminalReceiptV1 {
    fn try_new(
        facts: ManagedModelAgentStackTerminalFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: ManagedModelAgentStackTerminalAuthClaimV1,
        signature: &[u8],
    ) -> Result<Self, ManagedModelAgentStackPlanError> {
        validate_terminal_state_evidence(facts.state(), facts.evidence())?;
        validate_terminal_outcome_mode(facts.state().outcome(), facts.request_mode())?;
        if signature.is_empty()
            || signature.len() > MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_SIGNATURE_BYTES
            || channel.target() != facts.target()
            || auth_claim.runtime_peer() != channel.runtime_peer()
            || auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(ManagedModelAgentStackPlanError::InvalidResponseAuthentication);
        }
        let mut canonical_wire = build_terminal_fields(
            TERMINAL_RECEIPT_MAGIC,
            MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_VERSION,
            facts,
            channel,
            auth_claim,
        )?;
        let signature_length = u16::try_from(signature.len())
            .map_err(|_| ManagedModelAgentStackPlanError::InvalidLength)?;
        canonical_wire.extend_from_slice(&signature_length.to_be_bytes());
        canonical_wire.extend_from_slice(signature);
        if canonical_wire.len() > MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_BYTES {
            return Err(ManagedModelAgentStackPlanError::FrameTooLarge);
        }
        let receipt_digest = digest_wire(TERMINAL_RECEIPT_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            facts,
            channel,
            auth_claim,
            signature: signature.into(),
            canonical_wire: canonical_wire.into_boxed_slice(),
            receipt_digest,
        })
    }

    pub fn decode(frame: &[u8]) -> Result<Self, ManagedModelAgentStackPlanError> {
        if frame.len() > MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_BYTES {
            return Err(ManagedModelAgentStackPlanError::FrameTooLarge);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.array::<4>()? != *TERMINAL_RECEIPT_MAGIC
            || cursor.u16()? != MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_VERSION
        {
            return Err(ManagedModelAgentStackPlanError::UnsupportedWire);
        }
        let facts = decode_terminal_facts(&mut cursor)?;
        let channel = decode_terminal_channel(&mut cursor)?;
        let auth_claim = decode_terminal_auth_claim(&mut cursor)?;
        let signature_length = cursor.usize_u16()?;
        if signature_length == 0
            || signature_length > MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_SIGNATURE_BYTES
        {
            return Err(ManagedModelAgentStackPlanError::InvalidLength);
        }
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let decoded = Self::try_new(facts, channel, auth_claim, signature)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedModelAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    pub fn validate_against_request(
        &self,
        request: &ManagedModelAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<ManagedModelAgentStackTerminalFactsV1, ManagedModelAgentStackPlanError> {
        self.facts.validate_against_request(request)?;
        if self.channel != channel
            || channel.target() != request.target()
            || self.auth_claim.runtime_peer() != channel.runtime_peer()
            || self.auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(ManagedModelAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(self.facts)
    }

    #[must_use]
    pub const fn facts(&self) -> ManagedModelAgentStackTerminalFactsV1 {
        self.facts
    }

    #[must_use]
    pub const fn authentication_key(&self) -> ApplyAuthKeyRef {
        self.auth_claim.key()
    }

    #[must_use]
    pub const fn authentication_algorithm(&self) -> ApplyAuthAlgorithm {
        self.auth_claim.algorithm()
    }

    #[must_use]
    pub const fn authentication_algorithm_version(&self) -> u16 {
        self.auth_claim.algorithm_version()
    }

    #[must_use]
    pub fn authentication_signature(&self) -> &[u8] {
        &self.signature
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub const fn receipt_digest(&self) -> Digest32 {
        self.receipt_digest
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedModelAgentStackTerminalSigningTranscriptV1, ManagedModelAgentStackPlanError>
    {
        ManagedModelAgentStackTerminalReceiptDraftV1 {
            facts: self.facts,
            channel: self.channel,
            auth_claim: self.auth_claim,
        }
        .signing_transcript()
    }
}

fn validate_terminal_state(
    state: ManagedModelAgentStackTerminalStateV1,
) -> Result<(), ManagedModelAgentStackPlanError> {
    let committed = matches!(
        state.head(),
        ManagedModelAgentStackTerminalHeadV1::CommittedIncoming
    );
    let all_generations = state.fabric_generation().is_some()
        && state.model_generation().is_some()
        && state.agent_generation().is_some();
    match state.outcome() {
        ManagedModelAgentStackTerminalOutcomeV1::ActiveReady => {
            if state.lifecycle_effect()
                != ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted
                || !committed
                || !all_generations
            {
                return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
            }
        }
        ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero => {
            if !committed
                || state.fabric_generation().is_some()
                || state.model_generation().is_some()
                || state.agent_generation().is_some()
            {
                return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
            }
        }
        ManagedModelAgentStackTerminalOutcomeV1::NoEffectRejected => {
            if state.lifecycle_effect()
                != ManagedModelAgentStackTerminalLifecycleEffectV1::ProvenNotStarted
                || committed
            {
                return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
            }
        }
        ManagedModelAgentStackTerminalOutcomeV1::Uncertain => {
            if state.lifecycle_effect()
                != ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted
            {
                return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
            }
        }
        ManagedModelAgentStackTerminalOutcomeV1::Quarantined => {
            if state.lifecycle_effect()
                != ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted
                || !committed
            {
                return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
            }
        }
    }
    Ok(())
}

fn validate_terminal_state_evidence(
    state: ManagedModelAgentStackTerminalStateV1,
    evidence: ManagedModelAgentStackTerminalEvidenceV1,
) -> Result<(), ManagedModelAgentStackPlanError> {
    validate_terminal_state(state)?;
    let facts = evidence.fields();
    let all_generations = state.fabric_generation().is_some()
        && state.model_generation().is_some()
        && state.agent_generation().is_some();
    let all_ready = facts.fabric_ready
        && facts.model_ready
        && facts.agent_ready
        && facts.fabric_to_agent_dependency_ready
        && facts.model_to_agent_dependency_ready;
    let valid = match state.outcome() {
        ManagedModelAgentStackTerminalOutcomeV1::ActiveReady => {
            all_generations
                && facts.census_complete
                && facts.physical_binding_census == 2
                && all_ready
                && !facts.exact_zero
                && !facts.quarantined
        }
        ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero => {
            facts.census_complete && facts.exact_zero && !facts.quarantined
        }
        ManagedModelAgentStackTerminalOutcomeV1::NoEffectRejected => {
            let preserved_fabric_baseline = !facts.exact_zero
                && state.fabric_generation().is_some()
                && state.model_generation().is_none()
                && state.agent_generation().is_none()
                && facts.physical_binding_census == 0
                && facts.fabric_ready
                && !facts.model_ready
                && !facts.agent_ready
                && !facts.fabric_to_agent_dependency_ready
                && !facts.model_to_agent_dependency_ready;
            facts.census_complete
                && !facts.quarantined
                && ((facts.exact_zero
                    && state.fabric_generation().is_none()
                    && state.model_generation().is_none()
                    && state.agent_generation().is_none())
                    || preserved_fabric_baseline
                    || (!facts.exact_zero
                        && all_generations
                        && facts.physical_binding_census == 2
                        && all_ready))
        }
        ManagedModelAgentStackTerminalOutcomeV1::Uncertain => {
            !facts.exact_zero && !facts.quarantined
        }
        ManagedModelAgentStackTerminalOutcomeV1::Quarantined => {
            facts.quarantined
                && !facts.exact_zero
                && !facts.agent_ready
                && !facts.fabric_to_agent_dependency_ready
                && !facts.model_to_agent_dependency_ready
        }
    };
    if !valid {
        return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(())
}

fn validate_terminal_outcome_mode(
    outcome: ManagedModelAgentStackTerminalOutcomeV1,
    mode: ManagedModelAgentStackTargetModeV1,
) -> Result<(), ManagedModelAgentStackPlanError> {
    if matches!(
        outcome,
        ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
    ) && mode != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
        || matches!(
            outcome,
            ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero
        ) && mode != ManagedModelAgentStackTargetModeV1::EmptyDeactivate
    {
        return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(())
}

fn resolve_terminal_head(
    request: &ManagedModelAgentStackApplyRequestV1,
    head: ManagedModelAgentStackTerminalHeadV1,
) -> Result<Option<TargetSliceDigest>, ManagedModelAgentStackPlanError> {
    match head {
        ManagedModelAgentStackTerminalHeadV1::PreservedNone => Ok(None),
        ManagedModelAgentStackTerminalHeadV1::PreservedExisting(value)
            if !digest_is_zero(*value.value()) =>
        {
            Ok(Some(value))
        }
        ManagedModelAgentStackTerminalHeadV1::PreservedExisting(_) => {
            Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts)
        }
        ManagedModelAgentStackTerminalHeadV1::CommittedIncoming => {
            Ok(Some(request.target_slice_digest()))
        }
    }
}

fn derive_terminal_result_ref(
    request: &ManagedModelAgentStackApplyRequestV1,
) -> Result<ManagedModelAgentStackTerminalResultRefV1, ManagedModelAgentStackPlanError> {
    let mut builder = Digest32Builder::try_new(TERMINAL_RESULT_REF_DOMAIN)?;
    builder.field_bytes(TERMINAL_RECEIPT_MAGIC)?;
    builder.field_u16(MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_VERSION)?;
    builder.field_bytes(request.target().as_bytes())?;
    builder.field_bytes(&request.expected_runtime_store_instance_id())?;
    builder.field_bytes(request.provenance().source_scope().as_bytes())?;
    builder.field_bytes(request.operation_id().as_bytes())?;
    builder.field_digest(&request.envelope_request_digest())?;
    let digest = builder.finish();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes_are_zero(&bytes) {
        return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(ManagedModelAgentStackTerminalResultRefV1(bytes))
}

fn build_terminal_fields(
    magic: &[u8],
    version: u16,
    facts: ManagedModelAgentStackTerminalFactsV1,
    channel: ReferenceChannelBindingV1,
    auth: ManagedModelAgentStackTerminalAuthClaimV1,
) -> Result<Vec<u8>, ManagedModelAgentStackPlanError> {
    let state = facts.state();
    let evidence = facts.evidence().fields();
    let mut wire = Vec::new();
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&version.to_be_bytes());
    wire.extend_from_slice(facts.target().as_bytes());
    wire.extend_from_slice(&facts.runtime_store_instance_id());
    wire.extend_from_slice(facts.source_scope().as_bytes());
    wire.extend_from_slice(facts.operation_id().as_bytes());
    wire.extend_from_slice(facts.request_digest().as_bytes());
    wire.extend_from_slice(facts.target_slice_digest().value().as_bytes());
    wire.extend_from_slice(facts.assignment_digest().value().as_bytes());
    wire.extend_from_slice(facts.terminal_result_ref().as_bytes());
    wire.push(facts.request_mode() as u8);
    wire.push(state.outcome() as u8);
    wire.push(state.lifecycle_effect() as u8);
    wire.push(match state.head() {
        ManagedModelAgentStackTerminalHeadV1::PreservedNone => 1,
        ManagedModelAgentStackTerminalHeadV1::PreservedExisting(_) => 2,
        ManagedModelAgentStackTerminalHeadV1::CommittedIncoming => 3,
    });
    wire.push(u8::from(facts.desired_head_digest().is_some()));
    let desired_head_bytes = facts
        .desired_head_digest()
        .map_or([0; 32], |value| *value.value().as_bytes());
    wire.extend_from_slice(&desired_head_bytes);
    encode_generation(&mut wire, state.fabric_generation());
    encode_generation(&mut wire, state.model_generation());
    encode_generation(&mut wire, state.agent_generation());
    wire.extend_from_slice(&evidence.physical_binding_census.to_be_bytes());
    wire.push(terminal_evidence_flags(evidence));
    wire.extend_from_slice(evidence.resource_census_digest.as_bytes());
    wire.extend_from_slice(evidence.raw_outcome_digest.as_bytes());
    wire.extend_from_slice(&evidence.completion_runtime_host_epoch.to_be_bytes());
    wire.extend_from_slice(&evidence.completion_snapshot_sequence.to_be_bytes());
    wire.extend_from_slice(&evidence.selection_clock_generation.value().to_be_bytes());
    wire.extend_from_slice(&evidence.selection_observed_at_nanos.to_be_bytes());
    encode_terminal_channel(&mut wire, channel);
    encode_terminal_auth_claim(&mut wire, auth);
    Ok(wire)
}

fn encode_generation(wire: &mut Vec<u8>, generation: Option<ManagedServiceGeneration>) {
    wire.push(u8::from(generation.is_some()));
    wire.extend_from_slice(
        &generation
            .map_or(0, ManagedServiceGeneration::value)
            .to_be_bytes(),
    );
}

fn terminal_evidence_flags(fields: ManagedModelAgentStackTerminalEvidenceFieldsV1) -> u8 {
    u8::from(fields.census_complete)
        | (u8::from(fields.fabric_ready) << 1)
        | (u8::from(fields.model_ready) << 2)
        | (u8::from(fields.agent_ready) << 3)
        | (u8::from(fields.fabric_to_agent_dependency_ready) << 4)
        | (u8::from(fields.model_to_agent_dependency_ready) << 5)
        | (u8::from(fields.exact_zero) << 6)
        | (u8::from(fields.quarantined) << 7)
}

fn decode_terminal_facts(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedModelAgentStackTerminalFactsV1, ManagedModelAgentStackPlanError> {
    let target = RuntimeHostId::from_bytes(cursor.array()?);
    let runtime_store_instance_id = cursor.array()?;
    let source_scope = crate::provenance::SourceScopeRef::from_bytes(cursor.array()?);
    let operation_id = ApplyOperationId::from_bytes(cursor.array()?);
    let request_digest = Digest32::from_bytes(cursor.array()?);
    let target_slice_digest = TargetSliceDigest::new(Digest32::from_bytes(cursor.array()?));
    let assignment_digest = TargetAssignmentDigest::new(Digest32::from_bytes(cursor.array()?));
    let terminal_result_ref = ManagedModelAgentStackTerminalResultRefV1(cursor.array()?);
    let request_mode = match cursor.u8()? {
        1 => ManagedModelAgentStackTargetModeV1::FabricModelAndAgent,
        2 => ManagedModelAgentStackTargetModeV1::EmptyDeactivate,
        _ => return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts),
    };
    let outcome = match cursor.u8()? {
        1 => ManagedModelAgentStackTerminalOutcomeV1::ActiveReady,
        2 => ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero,
        3 => ManagedModelAgentStackTerminalOutcomeV1::NoEffectRejected,
        4 => ManagedModelAgentStackTerminalOutcomeV1::Uncertain,
        5 => ManagedModelAgentStackTerminalOutcomeV1::Quarantined,
        _ => return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts),
    };
    let lifecycle_effect = match cursor.u8()? {
        1 => ManagedModelAgentStackTerminalLifecycleEffectV1::ProvenNotStarted,
        2 => ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
        _ => return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts),
    };
    let head_tag = cursor.u8()?;
    let desired_present = cursor.u8()?;
    let desired_bytes: [u8; 32] = cursor.array()?;
    let desired_head_digest = match desired_present {
        0 if bytes_are_zero(&desired_bytes) => None,
        1 => Some(TargetSliceDigest::new(Digest32::from_bytes(desired_bytes))),
        _ => return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts),
    };
    let head = match (head_tag, desired_head_digest) {
        (1, None) => ManagedModelAgentStackTerminalHeadV1::PreservedNone,
        (2, Some(value)) => ManagedModelAgentStackTerminalHeadV1::PreservedExisting(value),
        (3, Some(_)) => ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
        _ => return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts),
    };
    let fabric_generation = decode_generation(cursor)?;
    let model_generation = decode_generation(cursor)?;
    let agent_generation = decode_generation(cursor)?;
    let state = ManagedModelAgentStackTerminalStateV1::try_new(
        outcome,
        lifecycle_effect,
        head,
        fabric_generation,
        model_generation,
        agent_generation,
    )?;
    let physical_binding_census = cursor.u16()?;
    let flags = cursor.u8()?;
    let evidence = ManagedModelAgentStackTerminalEvidenceV1::try_new(
        ManagedModelAgentStackTerminalEvidenceFieldsV1 {
            physical_binding_census,
            census_complete: flags & 1 != 0,
            fabric_ready: flags & 2 != 0,
            model_ready: flags & 4 != 0,
            agent_ready: flags & 8 != 0,
            fabric_to_agent_dependency_ready: flags & 16 != 0,
            model_to_agent_dependency_ready: flags & 32 != 0,
            exact_zero: flags & 64 != 0,
            quarantined: flags & 128 != 0,
            resource_census_digest: Digest32::from_bytes(cursor.array()?),
            raw_outcome_digest: Digest32::from_bytes(cursor.array()?),
            completion_runtime_host_epoch: cursor.u64()?,
            completion_snapshot_sequence: cursor.u64()?,
            selection_clock_generation: ClockGeneration::try_new(cursor.u64()?)
                .map_err(|_| ManagedModelAgentStackPlanError::InvalidTerminalFacts)?,
            selection_observed_at_nanos: cursor.u64()?,
        },
    )?;
    validate_terminal_state_evidence(state, evidence)?;
    validate_terminal_outcome_mode(outcome, request_mode)?;
    if bytes_are_zero(target.as_bytes())
        || bytes_are_zero(&runtime_store_instance_id)
        || bytes_are_zero(source_scope.as_bytes())
        || bytes_are_zero(operation_id.as_bytes())
        || digest_is_zero(request_digest)
        || digest_is_zero(*target_slice_digest.value())
        || digest_is_zero(*assignment_digest.value())
        || bytes_are_zero(terminal_result_ref.as_bytes())
    {
        return Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(ManagedModelAgentStackTerminalFactsV1 {
        target,
        runtime_store_instance_id,
        source_scope,
        operation_id,
        request_digest,
        target_slice_digest,
        assignment_digest,
        terminal_result_ref,
        request_mode,
        state,
        desired_head_digest,
        evidence,
    })
}

fn decode_generation(
    cursor: &mut Cursor<'_>,
) -> Result<Option<ManagedServiceGeneration>, ManagedModelAgentStackPlanError> {
    let present = cursor.u8()?;
    let value = cursor.u64()?;
    match (present, value) {
        (0, 0) => Ok(None),
        (1, value) => ManagedServiceGeneration::try_new(value)
            .map(Some)
            .map_err(|_| ManagedModelAgentStackPlanError::InvalidTerminalFacts),
        _ => Err(ManagedModelAgentStackPlanError::InvalidTerminalFacts),
    }
}

fn encode_terminal_channel(wire: &mut Vec<u8>, channel: ReferenceChannelBindingV1) {
    wire.extend_from_slice(channel.target().as_bytes());
    wire.extend_from_slice(channel.runtime_peer().as_bytes());
    wire.extend_from_slice(channel.local_endpoint_identity_digest().as_bytes());
    wire.extend_from_slice(channel.peer_credentials_digest().as_bytes());
}

fn decode_terminal_channel(
    cursor: &mut Cursor<'_>,
) -> Result<ReferenceChannelBindingV1, ManagedModelAgentStackPlanError> {
    ReferenceChannelBindingV1::try_new(
        RuntimeHostId::from_bytes(cursor.array()?),
        PrincipalRef::from_bytes(cursor.array()?),
        Digest32::from_bytes(cursor.array()?),
        Digest32::from_bytes(cursor.array()?),
    )
    .map_err(|_| ManagedModelAgentStackPlanError::InvalidResponseAuthentication)
}

fn encode_terminal_auth_claim(wire: &mut Vec<u8>, auth: ManagedModelAgentStackTerminalAuthClaimV1) {
    wire.extend_from_slice(auth.runtime_peer().as_bytes());
    wire.extend_from_slice(auth.channel_binding_digest().as_bytes());
    wire.extend_from_slice(auth.key().as_bytes());
    wire.extend_from_slice(&auth.algorithm().value().to_be_bytes());
    wire.extend_from_slice(&auth.algorithm_version().to_be_bytes());
}

fn decode_terminal_auth_claim(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedModelAgentStackTerminalAuthClaimV1, ManagedModelAgentStackPlanError> {
    let runtime_peer = PrincipalRef::from_bytes(cursor.array()?);
    let channel_binding_digest = Digest32::from_bytes(cursor.array()?);
    let key = ApplyAuthKeyRef::from_bytes(cursor.array()?);
    let algorithm = ApplyAuthAlgorithm::try_new(cursor.u16()?)
        .map_err(|_| ManagedModelAgentStackPlanError::InvalidResponseAuthentication)?;
    let algorithm_version = cursor.u16()?;
    if bytes_are_zero(runtime_peer.as_bytes())
        || digest_is_zero(channel_binding_digest)
        || bytes_are_zero(key.as_bytes())
        || algorithm_version == 0
    {
        return Err(ManagedModelAgentStackPlanError::InvalidResponseAuthentication);
    }
    Ok(ManagedModelAgentStackTerminalAuthClaimV1 {
        runtime_peer,
        channel_binding_digest,
        key,
        algorithm,
        algorithm_version,
    })
}

fn build_projection_wire(
    managed_agent_stack: &ManagedAgentStackProjectionV1,
    compatibility_digest: Digest32,
) -> Vec<u8> {
    let mut wire = Vec::with_capacity(STACK_PROJECTION_BYTES);
    wire.extend_from_slice(STACK_PROJECTION_MAGIC);
    wire.extend_from_slice(&MANAGED_MODEL_AGENT_STACK_PROJECTION_VERSION.to_be_bytes());
    wire.extend_from_slice(managed_agent_stack.canonical_wire());
    wire.extend_from_slice(compatibility_digest.as_bytes());
    wire.extend_from_slice(&MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION.to_be_bytes());
    wire.extend_from_slice(&MANAGED_MODEL_AGENT_STACK_PROFILE_VERSION.to_be_bytes());
    wire
}

fn build_target_execution_wire(
    projection: &ManagedModelAgentStackProjectionV1,
    mode: ManagedModelAgentStackTargetModeV1,
    managed_agent_stack: &ManagedAgentStackTargetExecutionV1,
    model: Option<&ManagedModelServicePlanV1>,
    dependencies: Option<&[ManagedModelAgentServiceDependencyV1; 2]>,
) -> Result<Vec<u8>, ManagedModelAgentStackPlanError> {
    let embedded_length = u32::try_from(managed_agent_stack.canonical_wire().len())
        .map_err(|_| ManagedModelAgentStackPlanError::InvalidLength)?;
    let dependency_count = dependencies.map_or(0, |_| 2);
    let mut wire = Vec::new();
    wire.extend_from_slice(TARGET_EXECUTION_MAGIC);
    wire.extend_from_slice(&MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_VERSION.to_be_bytes());
    wire.extend_from_slice(projection.canonical_wire());
    wire.extend_from_slice(&MANAGED_MODEL_AGENT_STACK_PROFILE_VERSION.to_be_bytes());
    wire.push(mode as u8);
    wire.push(u8::from(model.is_some()));
    wire.push(dependency_count);
    wire.push(0);
    wire.extend_from_slice(&embedded_length.to_be_bytes());
    wire.extend_from_slice(managed_agent_stack.canonical_wire());
    if let Some(model) = model {
        encode_model_plan(&mut wire, model);
    }
    if let Some(dependencies) = dependencies {
        for dependency in dependencies {
            encode_dependency(&mut wire, *dependency);
        }
    }
    Ok(wire)
}

fn encode_model_plan(wire: &mut Vec<u8>, model: &ManagedModelServicePlanV1) {
    let service = model.service();
    wire.extend_from_slice(&MANAGED_SERVICE_CONTRACT_VERSION.to_be_bytes());
    wire.extend_from_slice(service.service_id().as_bytes());
    encode_budgets(wire, service.lifecycle_budgets());
    wire.extend_from_slice(&model.max_in_flight().to_be_bytes());
    encode_provider(wire, model.provider());
    let adapter = model.adapter_binding();
    wire.extend_from_slice(&MANAGED_MODEL_ADAPTER_BINDING_VERSION.to_be_bytes());
    wire.extend_from_slice(adapter.adapter_id());
    wire.extend_from_slice(&adapter.adapter_version().value().to_be_bytes());
    wire.extend_from_slice(adapter.capability_id().as_bytes());
}

fn decode_model_plan(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedModelServicePlanV1, ManagedModelAgentStackPlanError> {
    if cursor.u16()? != MANAGED_SERVICE_CONTRACT_VERSION {
        return Err(ManagedModelAgentStackPlanError::UnsupportedWire);
    }
    let service_id = ManagedServiceId::from_bytes(cursor.array()?);
    let budgets = ManagedServiceLifecycleBudgetsV1::try_new(
        BoundedDuration::from_nanos(cursor.u64()?),
        BoundedDuration::from_nanos(cursor.u64()?),
        BoundedDuration::from_nanos(cursor.u64()?),
        BoundedDuration::from_nanos(cursor.u64()?),
        BoundedDuration::from_nanos(cursor.u64()?),
    )
    .map_err(|_| ManagedModelAgentStackPlanError::InvalidModelPlan)?;
    let service = ManagedServiceSpecV1::new(service_id, budgets);
    let max_in_flight = cursor.u16()?;
    let provider = decode_provider(cursor)?;
    if cursor.u16()? != MANAGED_MODEL_ADAPTER_BINDING_VERSION {
        return Err(ManagedModelAgentStackPlanError::UnsupportedWire);
    }
    let adapter = ManagedModelAdapterBindingV1::try_new(
        cursor.array()?,
        ManagedModelAdapterVersionV1::try_new(cursor.u32()?)?,
        ManagedModelCapabilityIdV1::try_from_bytes(cursor.array()?)?,
    )?;
    ManagedModelServicePlanV1::try_new(service, max_in_flight, provider, adapter)
}

fn encode_provider(wire: &mut Vec<u8>, provider: ManagedAgentProviderSelectionV1) {
    wire.extend_from_slice(&MANAGED_AGENT_PROVIDER_SELECTION_VERSION.to_be_bytes());
    wire.push(provider.profile() as u8);
    wire.push(0);
    wire.extend_from_slice(provider.provider_ref().as_bytes());
    wire.extend_from_slice(provider.config_digest().as_bytes());
    wire.push(u8::from(provider.secret_ref().is_some()));
    match provider.secret_ref() {
        Some(secret) => wire.extend_from_slice(secret.as_bytes()),
        None => wire.extend_from_slice(&[0; 16]),
    }
}

fn decode_provider(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedAgentProviderSelectionV1, ManagedModelAgentStackPlanError> {
    if cursor.u16()? != MANAGED_AGENT_PROVIDER_SELECTION_VERSION {
        return Err(ManagedModelAgentStackPlanError::UnsupportedWire);
    }
    let profile = match cursor.u8()? {
        1 => ManagedAgentProviderProfileV1::Provisioned,
        2 => ManagedAgentProviderProfileV1::DeterministicFixture,
        _ => return Err(ManagedModelAgentStackPlanError::InvalidModelPlan),
    };
    if cursor.u8()? != 0 {
        return Err(ManagedModelAgentStackPlanError::NonCanonicalFrame);
    }
    let provider_ref = ManagedAgentProviderRefV1::try_from_bytes(cursor.array()?)?;
    let config_digest = Digest32::from_bytes(cursor.array()?);
    let secret_present = cursor.u8()?;
    let secret_bytes: [u8; 16] = cursor.array()?;
    match (profile, secret_present) {
        (ManagedAgentProviderProfileV1::Provisioned, 1) => {
            Ok(ManagedAgentProviderSelectionV1::try_provisioned(
                provider_ref,
                config_digest,
                ManagedAgentSecretRefV1::try_from_bytes(secret_bytes)?,
            )?)
        }
        (ManagedAgentProviderProfileV1::DeterministicFixture, 0)
            if bytes_are_zero(&secret_bytes) =>
        {
            Ok(ManagedAgentProviderSelectionV1::try_deterministic_fixture(
                provider_ref,
                config_digest,
            )?)
        }
        _ => Err(ManagedModelAgentStackPlanError::InvalidModelPlan),
    }
}

fn encode_dependency(wire: &mut Vec<u8>, dependency: ManagedModelAgentServiceDependencyV1) {
    wire.extend_from_slice(&MANAGED_MODEL_AGENT_DEPENDENCY_VERSION.to_be_bytes());
    wire.push(dependency.kind() as u8);
    wire.push(dependency.readiness() as u8);
    wire.push(dependency.loss_policy() as u8);
    wire.push(0);
    wire.extend_from_slice(dependency.provider_service_id().as_bytes());
    wire.extend_from_slice(dependency.consumer_service_id().as_bytes());
}

fn decode_dependency(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedModelAgentServiceDependencyV1, ManagedModelAgentStackPlanError> {
    if cursor.u16()? != MANAGED_MODEL_AGENT_DEPENDENCY_VERSION {
        return Err(ManagedModelAgentStackPlanError::UnsupportedWire);
    }
    let kind = match cursor.u8()? {
        1 => ManagedModelAgentDependencyKindV1::FabricToAgent,
        2 => ManagedModelAgentDependencyKindV1::ModelToAgent,
        _ => return Err(ManagedModelAgentStackPlanError::InvalidDependencyProfile),
    };
    if cursor.u8()? != ManagedModelAgentDependencyReadinessV1::RequireReady as u8
        || cursor.u8()? != ManagedModelAgentDependencyLossPolicyV1::StopConsumer as u8
        || cursor.u8()? != 0
    {
        return Err(ManagedModelAgentStackPlanError::InvalidDependencyProfile);
    }
    Ok(ManagedModelAgentServiceDependencyV1::derived(
        kind,
        ManagedServiceId::from_bytes(cursor.array()?),
        ManagedServiceId::from_bytes(cursor.array()?),
    ))
}

fn encode_budgets(wire: &mut Vec<u8>, budgets: ManagedServiceLifecycleBudgetsV1) {
    for value in [
        budgets.for_stage(ManagedServiceLifecycleStage::Prepare),
        budgets.for_stage(ManagedServiceLifecycleStage::Start),
        budgets.for_stage(ManagedServiceLifecycleStage::Readiness),
        budgets.for_stage(ManagedServiceLifecycleStage::Drain),
        budgets.for_stage(ManagedServiceLifecycleStage::Stop),
    ] {
        wire.extend_from_slice(&value.value().to_be_bytes());
    }
}

fn validate_service(service: ManagedServiceSpecV1) -> Result<(), ManagedModelAgentStackPlanError> {
    if bytes_are_zero(service.service_id().as_bytes())
        || [
            ManagedServiceLifecycleStage::Prepare,
            ManagedServiceLifecycleStage::Start,
            ManagedServiceLifecycleStage::Readiness,
            ManagedServiceLifecycleStage::Drain,
            ManagedServiceLifecycleStage::Stop,
        ]
        .into_iter()
        .any(|stage| {
            let value = service.lifecycle_budgets().for_stage(stage).value();
            value == 0 || value > MAX_MANAGED_AGENT_HANDLER_TIMEOUT_NANOS
        })
    {
        return Err(ManagedModelAgentStackPlanError::InvalidModelPlan);
    }
    Ok(())
}

fn build_apply_request_wire(
    envelope: &RuntimeApplyEnvelopeV2,
    slice: &ManagedModelAgentStackPlanSliceV1,
) -> Result<Vec<u8>, ManagedModelAgentStackPlanError> {
    let envelope_length = u32::try_from(envelope.canonical_wire().len())
        .map_err(|_| ManagedModelAgentStackPlanError::InvalidLength)?;
    let bindings_length = u32::try_from(slice.assignments.bindings.canonical_wire().len())
        .map_err(|_| ManagedModelAgentStackPlanError::InvalidLength)?;
    let execution_length = u32::try_from(slice.assignments.execution.canonical_wire().len())
        .map_err(|_| ManagedModelAgentStackPlanError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(APPLY_REQUEST_MAGIC);
    wire.extend_from_slice(&MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION.to_be_bytes());
    wire.extend_from_slice(&envelope_length.to_be_bytes());
    wire.extend_from_slice(&bindings_length.to_be_bytes());
    wire.extend_from_slice(&execution_length.to_be_bytes());
    wire.extend_from_slice(envelope.canonical_wire());
    wire.extend_from_slice(slice.assignments.bindings.canonical_wire());
    wire.extend_from_slice(slice.assignments.execution.canonical_wire());
    Ok(wire)
}

/// Computes the exact contract fingerprint embedded in PXMM v1.
pub fn managed_model_agent_stack_compatibility_digest_v1() -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(STACK_COMPATIBILITY_DIGEST_DOMAIN)?;
    builder.field_bytes(STACK_PROJECTION_MAGIC)?;
    builder.field_u16(MANAGED_MODEL_AGENT_STACK_PROJECTION_VERSION)?;
    builder.field_u16(STACK_PROJECTION_BYTES as u16)?;
    builder.field_bytes(APPLY_REQUEST_MAGIC)?;
    builder.field_u16(MANAGED_MODEL_AGENT_STACK_APPLY_REQUEST_VERSION)?;
    builder.field_bytes(TARGET_EXECUTION_MAGIC)?;
    builder.field_u16(MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_VERSION)?;
    builder.field_bytes(
        &(MAX_MANAGED_MODEL_AGENT_STACK_TARGET_EXECUTION_BYTES as u32).to_be_bytes(),
    )?;
    builder.field_u16(MANAGED_MODEL_AGENT_STACK_PROFILE_VERSION)?;
    builder.field_u16(MANAGED_MODEL_ADAPTER_BINDING_VERSION)?;
    builder.field_u16(MANAGED_MODEL_AGENT_DEPENDENCY_VERSION)?;
    builder.field_u16(MANAGED_SERVICE_CONTRACT_VERSION)?;
    builder.field_u16(MAX_MANAGED_MODEL_IN_FLIGHT)?;
    builder.field_bytes(&MANAGED_MODEL_BOUNDED_TEXT_CAPABILITY_ID)?;
    builder.field_bytes(TARGET_EXECUTION_DIGEST_DOMAIN)?;
    builder.field_u16(ManagedModelAgentStackTargetModeV1::FabricModelAndAgent as u16)?;
    builder.field_u16(ManagedModelAgentStackTargetModeV1::EmptyDeactivate as u16)?;
    builder.field_u16(ManagedModelAgentDependencyKindV1::FabricToAgent as u16)?;
    builder.field_u16(ManagedModelAgentDependencyKindV1::ModelToAgent as u16)?;
    builder.field_u16(ManagedModelAgentDependencyReadinessV1::RequireReady as u16)?;
    builder.field_u16(ManagedModelAgentDependencyLossPolicyV1::StopConsumer as u16)?;
    builder.field_bytes(TERMINAL_RECEIPT_MAGIC)?;
    builder.field_u16(MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_VERSION)?;
    builder.field_u16(MANAGED_MODEL_AGENT_STACK_TERMINAL_SIGNING_VERSION)?;
    builder.field_u16(MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_RECEIPT_BYTES as u16)?;
    builder.field_u16(MAX_MANAGED_MODEL_AGENT_STACK_TERMINAL_SIGNATURE_BYTES as u16)?;
    builder.field_bytes(TERMINAL_RESULT_REF_DOMAIN)?;
    builder.field_bytes(TERMINAL_RECEIPT_SIGNING_MAGIC)?;
    builder.field_bytes(TERMINAL_RECEIPT_DIGEST_DOMAIN)?;
    builder.field_bytes(TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN)?;
    builder.field_bytes(&EMPTY_PXTA)?;
    Ok(builder.finish())
}

fn digest_wire(domain: &[u8], wire: &[u8]) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(domain)?;
    builder.field_bytes(wire)?;
    Ok(builder.finish())
}

fn digest_is_zero(value: Digest32) -> bool {
    bytes_are_zero(value.as_bytes())
}

const fn bytes_are_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

const fn bytes_equal<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(read_array(bytes))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(read_array(bytes))
}

fn read_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap_or([0; N])
}

struct Cursor<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ManagedModelAgentStackPlanError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ManagedModelAgentStackPlanError::FrameTooLarge)?;
        let value = self
            .frame
            .get(self.position..end)
            .ok_or(ManagedModelAgentStackPlanError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManagedModelAgentStackPlanError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ManagedModelAgentStackPlanError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, ManagedModelAgentStackPlanError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ManagedModelAgentStackPlanError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ManagedModelAgentStackPlanError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ManagedModelAgentStackPlanError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize_u32(&mut self) -> Result<usize, ManagedModelAgentStackPlanError> {
        usize::try_from(self.u32()?).map_err(|_| ManagedModelAgentStackPlanError::InvalidLength)
    }

    fn usize_u16(&mut self) -> Result<usize, ManagedModelAgentStackPlanError> {
        Ok(usize::from(self.u16()?))
    }

    fn finish(self) -> Result<(), ManagedModelAgentStackPlanError> {
        if self.position == self.frame.len() {
            Ok(())
        } else {
            Err(ManagedModelAgentStackPlanError::TrailingBytes)
        }
    }
}

/// Stable construction, codec, and cross-reference failures for this profile.
#[derive(Debug)]
pub enum ManagedModelAgentStackPlanError {
    InvalidShape,
    InvalidModelPlan,
    InvalidAdapterBinding,
    InvalidDependencyProfile,
    ProviderMismatch,
    DuplicateServiceId,
    InvalidTerminalFacts,
    TerminalCorrelationMismatch,
    InvalidResponseAuthentication,
    BindingNotAllowed,
    CommitmentMismatch,
    TargetMismatch,
    InvalidLength,
    ProjectionMismatch,
    CompatibilityMismatch,
    UnsupportedWire,
    Truncated,
    TrailingBytes,
    FrameTooLarge,
    NonCanonicalFrame,
    Digest(DigestBuildError),
    AgentStack(ManagedAgentStackPlanError),
    Provenance(crate::provenance::ProvenanceContractError),
    Apply(crate::apply::ApplyContractError),
    ReferenceContract,
    ReferenceWire,
}

impl From<DigestBuildError> for ManagedModelAgentStackPlanError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ManagedAgentStackPlanError> for ManagedModelAgentStackPlanError {
    fn from(value: ManagedAgentStackPlanError) -> Self {
        Self::AgentStack(value)
    }
}

impl From<crate::provenance::ProvenanceContractError> for ManagedModelAgentStackPlanError {
    fn from(value: crate::provenance::ProvenanceContractError) -> Self {
        Self::Provenance(value)
    }
}

impl From<crate::apply::ApplyContractError> for ManagedModelAgentStackPlanError {
    fn from(value: crate::apply::ApplyContractError) -> Self {
        Self::Apply(value)
    }
}

impl From<crate::reference_assembly::ReferenceContractError> for ManagedModelAgentStackPlanError {
    fn from(_value: crate::reference_assembly::ReferenceContractError) -> Self {
        Self::ReferenceContract
    }
}

impl From<crate::reference_assembly::ReferenceWireError> for ManagedModelAgentStackPlanError {
    fn from(_value: crate::reference_assembly::ReferenceWireError) -> Self {
        Self::ReferenceWire
    }
}

impl fmt::Display for ManagedModelAgentStackPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed Model+Agent stack plan rejected: {self:?}"
        )
    }
}

impl std::error::Error for ManagedModelAgentStackPlanError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_binding_requires_u32_version_and_fixed_bounded_text_capability() {
        assert!(ManagedModelAdapterVersionV1::try_new(0).is_err());
        let version = ManagedModelAdapterVersionV1::try_new(u32::MAX)
            .unwrap_or_else(|error| panic!("nonzero u32 version must be valid: {error}"));
        assert_eq!(version.value(), u32::MAX);

        let capability = ManagedModelCapabilityIdV1::bounded_text_v1();
        assert_eq!(capability.as_bytes(), b"px-bounded-text1");
        let binding = ManagedModelAdapterBindingV1::try_new([0x41; 16], version, capability)
            .unwrap_or_else(|error| panic!("fixed binding must be valid: {error}"));
        assert_eq!(binding.adapter_id(), &[0x41; 16]);
        assert_eq!(binding.adapter_version(), version);
        assert_eq!(binding.capability_id(), capability);

        let other = ManagedModelCapabilityIdV1::try_from_bytes([0x42; 16])
            .unwrap_or_else(|error| panic!("nonzero capability identity must parse: {error}"));
        assert!(ManagedModelAdapterBindingV1::try_new([0x41; 16], version, other).is_err());
        assert!(ManagedModelAdapterBindingV1::try_new([0; 16], version, capability).is_err());
    }

    #[test]
    fn active_terminal_state_requires_three_distinct_generation_facts() {
        let generation = ManagedServiceGeneration::try_new(1)
            .unwrap_or_else(|error| panic!("fixture generation must be valid: {error}"));
        assert!(
            ManagedModelAgentStackTerminalStateV1::try_new(
                ManagedModelAgentStackTerminalOutcomeV1::ActiveReady,
                ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                Some(generation),
                None,
                Some(generation),
            )
            .is_err()
        );
        assert!(
            ManagedModelAgentStackTerminalStateV1::try_new(
                ManagedModelAgentStackTerminalOutcomeV1::ActiveReady,
                ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                Some(generation),
                Some(generation),
                Some(generation),
            )
            .is_ok()
        );
    }

    #[test]
    fn evidence_keeps_three_readiness_and_two_dependency_facts_separate() {
        let clock = ClockGeneration::try_new(1)
            .unwrap_or_else(|error| panic!("fixture clock must be valid: {error}"));
        let fields = ManagedModelAgentStackTerminalEvidenceFieldsV1 {
            physical_binding_census: 2,
            census_complete: true,
            fabric_ready: true,
            model_ready: true,
            agent_ready: true,
            fabric_to_agent_dependency_ready: true,
            model_to_agent_dependency_ready: false,
            exact_zero: false,
            quarantined: false,
            resource_census_digest: Digest32::from_bytes([1; 32]),
            raw_outcome_digest: Digest32::from_bytes([2; 32]),
            completion_runtime_host_epoch: 1,
            completion_snapshot_sequence: 1,
            selection_clock_generation: clock,
            selection_observed_at_nanos: 1,
        };
        assert!(ManagedModelAgentStackTerminalEvidenceV1::try_new(fields).is_err());
        assert!(
            ManagedModelAgentStackTerminalEvidenceV1::try_new(
                ManagedModelAgentStackTerminalEvidenceFieldsV1 {
                    model_to_agent_dependency_ready: true,
                    ..fields
                }
            )
            .is_ok()
        );
    }

    #[test]
    fn no_effect_terminal_can_preserve_only_the_pxar6_fabric_baseline() {
        let generation = ManagedServiceGeneration::try_new(7)
            .unwrap_or_else(|error| panic!("fixture generation must be valid: {error}"));
        let state = ManagedModelAgentStackTerminalStateV1::try_new(
            ManagedModelAgentStackTerminalOutcomeV1::NoEffectRejected,
            ManagedModelAgentStackTerminalLifecycleEffectV1::ProvenNotStarted,
            ManagedModelAgentStackTerminalHeadV1::PreservedNone,
            Some(generation),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("Fabric-only state must be valid: {error}"));
        let clock = ClockGeneration::try_new(1)
            .unwrap_or_else(|error| panic!("fixture clock must be valid: {error}"));
        let evidence = ManagedModelAgentStackTerminalEvidenceV1::try_new(
            ManagedModelAgentStackTerminalEvidenceFieldsV1 {
                physical_binding_census: 0,
                census_complete: true,
                fabric_ready: true,
                model_ready: false,
                agent_ready: false,
                fabric_to_agent_dependency_ready: false,
                model_to_agent_dependency_ready: false,
                exact_zero: false,
                quarantined: false,
                resource_census_digest: Digest32::from_bytes([1; 32]),
                raw_outcome_digest: Digest32::from_bytes([2; 32]),
                completion_runtime_host_epoch: 1,
                completion_snapshot_sequence: 1,
                selection_clock_generation: clock,
                selection_observed_at_nanos: 1,
            },
        )
        .unwrap_or_else(|error| panic!("Fabric-only evidence must be valid: {error}"));
        assert!(validate_terminal_state_evidence(state, evidence).is_ok());
    }

    #[test]
    fn strict_codecs_cross_reject_predecessor_magic_or_versions() {
        let mut projection = vec![0; STACK_PROJECTION_BYTES];
        projection[..4].copy_from_slice(b"PXSP");
        projection[4..6].copy_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(
            ManagedModelAgentStackProjectionV1::decode(&projection),
            Err(ManagedModelAgentStackPlanError::UnsupportedWire)
        ));

        let mut target = vec![0; TARGET_EXECUTION_FIXED_BYTES];
        target[..4].copy_from_slice(TARGET_EXECUTION_MAGIC);
        target[4..6].copy_from_slice(&6_u16.to_be_bytes());
        assert!(matches!(
            ManagedModelAgentStackTargetExecutionV1::decode(&target),
            Err(ManagedModelAgentStackPlanError::UnsupportedWire)
        ));

        let mut apply = vec![0; APPLY_REQUEST_HEADER_BYTES];
        apply[..4].copy_from_slice(APPLY_REQUEST_MAGIC);
        apply[4..6].copy_from_slice(&7_u16.to_be_bytes());
        assert!(matches!(
            ManagedModelAgentStackApplyRequestV1::decode(&apply),
            Err(ManagedModelAgentStackPlanError::UnsupportedWire)
        ));

        assert!(matches!(
            ManagedModelAgentStackTerminalReceiptV1::decode(b"PXST\0\x01"),
            Err(ManagedModelAgentStackPlanError::UnsupportedWire)
        ));
    }

    #[test]
    fn fixed_profile_sizes_leave_no_arbitrary_dependency_vector() {
        assert_eq!(MODEL_SERVICE_FIXED_BYTES, 58);
        assert_eq!(PROVIDER_SELECTION_FIXED_BYTES, 69);
        assert_eq!(ADAPTER_BINDING_FIXED_BYTES, 38);
        assert_eq!(MODEL_PLAN_FIXED_BYTES, 167);
        assert_eq!(DEPENDENCY_FIXED_BYTES, 38);
    }
}
