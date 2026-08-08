//! Canonical fixed successor for one managed Fabric service followed by one Agent service.
//!
//! This is deliberately not a general service graph. The only active shape is
//! `FabricAndAgent`: the exact PXTE v5 managed-Fabric desired value is retained
//! byte-for-byte and one Agent service is added with two explicit typed-route
//! bindings, bounded ingress, and an explicit model-provider selection. The
//! only other shape is authoritative exact-zero. Runtime generations, journal
//! paths, credentials, Zenoh values, and arbitrary dependency edges are not
//! desired-state fields.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{BoundedDuration, ClockGeneration};

use crate::apply::{ApplyOperationId, RuntimeApplyControl, RuntimeApplyControlCommitment};
use crate::assignment::{BindingId, TargetAssignments};
use crate::managed_fabric_plan::{
    MANAGED_FABRIC_APPLY_ENVELOPE_VERSION, MANAGED_FABRIC_APPLY_SIGNING_TRANSCRIPT_VERSION,
    MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES, ManagedFabricManifestProjectionV1,
    ManagedFabricPlanError, ManagedFabricTargetExecutionV1, ManagedFabricTargetModeV1,
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

const STACK_PROJECTION_MAGIC: &[u8; 4] = b"PXSP";
const TARGET_EXECUTION_MAGIC: &[u8; 4] = b"PXTE";
const APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const TERMINAL_RECEIPT_MAGIC: &[u8; 4] = b"PXST";
const EMPTY_PXTA: [u8; 10] = [b'P', b'X', b'T', b'A', 0, 1, 0, 0, 0, 0];
const APPLY_REQUEST_HEADER_BYTES: usize = 18;
const BASE_PROJECTION_BYTES: usize = 186;
const STACK_PROJECTION_BYTES: usize = 4 + 2 + BASE_PROJECTION_BYTES + 32 + 2 + 2;
const TARGET_EXECUTION_FIXED_BYTES: usize = 4 + 2 + STACK_PROJECTION_BYTES + 2 + 1 + 1 + 4;
const AGENT_SERVICE_FIXED_BYTES: usize = 2 + 16 + (5 * 8);
const AGENT_PORT_FIXED_BYTES: usize = (2 * 16) + (2 * 2) + 4 + 8 + 4 + 4 + 8;
const AGENT_PROVIDER_FIXED_BYTES: usize = 2 + 1 + 1 + 16 + 32 + 1 + 16;
const AGENT_SEMANTIC_LIMITS_BYTES: usize = 4 * 2;
const AGENT_PLAN_FIXED_BYTES: usize = AGENT_SERVICE_FIXED_BYTES
    + AGENT_SEMANTIC_LIMITS_BYTES
    + AGENT_PORT_FIXED_BYTES
    + AGENT_PROVIDER_FIXED_BYTES;

const STACK_COMPATIBILITY_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.compiled-managed-agent-stack-compatibility.sha256.v1";
const TARGET_EXECUTION_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.target-execution.sha256.v6";
const TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.target-plan-assignments.sha256.v7";
const TERMINAL_RESULT_REF_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-agent-stack-terminal-result.sha256.v1";
const TERMINAL_RECEIPT_SIGNING_MAGIC: &[u8] = b"ParaEGOX\0managed-agent-stack-terminal-signing";
const TERMINAL_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-agent-stack-terminal-receipt.sha256.v1";
const TARGET_SCOPED_SUBMIT_BINDING_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-agent-port.submit-binding.sha256.v1";
const TARGET_SCOPED_CONTROL_BINDING_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-agent-port.control-binding.sha256.v1";
const TARGET_SCOPED_AGENT_ROUTE_PREFIX: &[u8] = b"paraegox/agent/v1/";

/// Exact projection version for the fixed Fabric→Agent successor.
pub const MANAGED_AGENT_STACK_PROJECTION_VERSION: u16 = 1;
/// Exact outer apply-request version for the fixed stack successor.
pub const MANAGED_AGENT_STACK_APPLY_REQUEST_VERSION: u16 = 7;
/// Exact target-execution version for the fixed stack successor.
pub const MANAGED_AGENT_STACK_TARGET_EXECUTION_VERSION: u16 = 6;
/// Exact fixed-profile version. It does not identify a general graph schema.
pub const MANAGED_AGENT_STACK_PROFILE_VERSION: u16 = 1;
/// Exact provider-selection contract version.
pub const MANAGED_AGENT_PROVIDER_SELECTION_VERSION: u16 = 1;
/// Maximum canonical bytes in either signed Agent key expression.
pub const MAX_MANAGED_AGENT_KEY_EXPRESSION_BYTES: usize = 256;
/// Maximum ingress items admitted by the fixed stack contract.
pub const MAX_MANAGED_AGENT_INGRESS_ITEMS: u32 = 4_096;
/// Maximum retained ingress bytes admitted by the fixed stack contract.
pub const MAX_MANAGED_AGENT_INGRESS_BYTES: u64 = 64 * 1024 * 1024;
/// Smallest Fabric frame that can carry one header-only PXAC v1 value.
pub const MIN_MANAGED_AGENT_FRAME_BYTES: u32 = 104 + 128;
/// Maximum request-envelope bytes accepted by the underlying Fabric v1 owner.
pub const MAX_MANAGED_AGENT_FRAME_BYTES: u32 = 1_048_680;
/// Smallest response body that can carry one header-only PXAC v1 terminal.
pub const MIN_MANAGED_AGENT_RESPONSE_BODY_BYTES: u32 = 128;
/// Maximum response body bytes accepted by the underlying Fabric v1 owner.
pub const MAX_MANAGED_AGENT_RESPONSE_BODY_BYTES: u32 = 1_048_576;
/// Maximum finite handler timeout encoded by this contract.
pub const MAX_MANAGED_AGENT_HANDLER_TIMEOUT_NANOS: u64 =
    crate::managed_fabric_plan::MAX_MANAGED_FABRIC_LIFECYCLE_NANOS;
/// Maximum Session owners admitted by one Agent service plan.
pub const MAX_MANAGED_AGENT_SESSIONS: u16 = 256;
/// Maximum Turns retained by one Session.
pub const MAX_MANAGED_AGENT_TURNS_PER_SESSION: u16 = 1_024;
/// Maximum request identities retained by one Session.
pub const MAX_MANAGED_AGENT_REQUESTS_PER_SESSION: u16 = 1_024;
/// Maximum events returned by one bounded Agent query.
pub const MAX_MANAGED_AGENT_EVENT_BATCH: u16 = 1_024;
/// Exact fixed-width stack projection size.
pub const MANAGED_AGENT_STACK_PROJECTION_BYTES: usize = STACK_PROJECTION_BYTES;
/// Maximum canonical PXTE v6 size.
pub const MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES: usize = TARGET_EXECUTION_FIXED_BYTES
    + MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES
    + AGENT_PLAN_FIXED_BYTES
    + (2 * MAX_MANAGED_AGENT_KEY_EXPRESSION_BYTES);
/// Maximum durable `PXTA-zero || PXTE-v6` bytes.
pub const MAX_MANAGED_AGENT_STACK_PLAN_SLICE_BYTES: usize =
    EMPTY_PXTA.len() + MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES;
/// Maximum canonical PXAR v7 request size.
pub const MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES: usize = APPLY_REQUEST_HEADER_BYTES
    + MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES
    + EMPTY_PXTA.len()
    + MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES;
/// Exact signed Runtime terminal version carried by PXST.
pub const MANAGED_AGENT_STACK_TERMINAL_RECEIPT_VERSION: u16 = 1;
/// Exact PXST signing-transcript version.
pub const MANAGED_AGENT_STACK_TERMINAL_SIGNING_VERSION: u16 = 1;
/// Maximum canonical PXST receipt bytes.
pub const MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES: usize = 2_048;
/// Maximum opaque Runtime signature retained by PXST.
pub const MAX_MANAGED_AGENT_STACK_TERMINAL_SIGNATURE_BYTES: usize =
    MAX_CONTROL_READ_SIGNATURE_BYTES;

macro_rules! nonzero_ref {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates one nonzero opaque reference.
            pub const fn try_from_bytes(
                bytes: [u8; 16],
            ) -> Result<Self, ManagedAgentStackPlanError> {
                if bytes_are_zero(&bytes) {
                    return Err(ManagedAgentStackPlanError::InvalidProvider);
                }
                Ok(Self(bytes))
            }

            /// Returns exact reference bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

nonzero_ref!(
    ManagedAgentProviderRefV1,
    "Opaque identity of one explicitly provisioned model-provider configuration."
);
nonzero_ref!(
    ManagedAgentSecretRefV1,
    "Opaque reference resolved only by the model-provider owner."
);

/// Additive installation projection for the fixed Fabric→Agent successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackProjectionV1 {
    managed_fabric: ManagedFabricManifestProjectionV1,
    compatibility_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl ManagedAgentStackProjectionV1 {
    /// Derives the successor projection from the independently verified PXMP value.
    pub fn try_from_managed_fabric_projection(
        managed_fabric: ManagedFabricManifestProjectionV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        let compatibility_digest = managed_agent_stack_compatibility_digest_v1()?;
        let canonical_wire = build_projection_wire(&managed_fabric, compatibility_digest);
        Ok(Self {
            managed_fabric,
            compatibility_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes exactly PXSP v1 without treating PXMP as this projection.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedAgentStackPlanError> {
        if frame.len() > STACK_PROJECTION_BYTES {
            return Err(ManagedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < STACK_PROJECTION_BYTES {
            return Err(ManagedAgentStackPlanError::Truncated);
        }
        if &frame[..4] != STACK_PROJECTION_MAGIC
            || read_u16(&frame[4..6]) != MANAGED_AGENT_STACK_PROJECTION_VERSION
        {
            return Err(ManagedAgentStackPlanError::UnsupportedWire);
        }
        let managed_fabric =
            ManagedFabricManifestProjectionV1::decode(&frame[6..6 + BASE_PROJECTION_BYTES])?;
        let compatibility_offset = 6 + BASE_PROJECTION_BYTES;
        let compatibility_digest = Digest32::from_bytes(read_array(
            &frame[compatibility_offset..compatibility_offset + 32],
        ));
        if compatibility_digest != managed_agent_stack_compatibility_digest_v1()?
            || read_u16(&frame[compatibility_offset + 32..compatibility_offset + 34])
                != MANAGED_AGENT_STACK_APPLY_REQUEST_VERSION
            || read_u16(&frame[compatibility_offset + 34..compatibility_offset + 36])
                != MANAGED_AGENT_STACK_PROFILE_VERSION
        {
            return Err(ManagedAgentStackPlanError::CompatibilityMismatch);
        }
        let decoded = Self::try_from_managed_fabric_projection(managed_fabric)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Returns the exact predecessor projection retained by this successor.
    #[must_use]
    pub const fn managed_fabric_projection(&self) -> &ManagedFabricManifestProjectionV1 {
        &self.managed_fabric
    }

    /// Returns the selected Runtime target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.managed_fabric.target()
    }

    /// Returns the stack compatibility commitment.
    #[must_use]
    pub const fn compatibility_digest(&self) -> Digest32 {
        self.compatibility_digest
    }

    /// Returns exact canonical PXSP v1 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// Exact fixed desired shape admitted by PXTE v6.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedAgentStackTargetModeV1 {
    /// One preserved managed Fabric service followed by one Agent service.
    FabricAndAgent = 1,
    /// Authoritative exact-zero stack.
    EmptyDeactivate = 2,
}

/// Model-provider mode selected by committed desired state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedAgentProviderProfileV1 {
    /// A provisioned provider whose secret is resolved outside this contract.
    Provisioned = 1,
    /// An explicit offline deterministic fixture; never a production default.
    DeterministicFixture = 2,
}

/// Bounded ingress settings mapped exactly into the Agent two-lane port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedAgentIngressLimitsV1 {
    max_items: u32,
    max_bytes: u64,
    max_frame_bytes: u32,
    max_response_body_bytes: u32,
    handler_timeout_nanos: u64,
}

/// Exact semantic ledger limits mapped into `AgentServiceConfigV1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedAgentSemanticLimitsV1 {
    max_sessions: u16,
    max_turns_per_session: u16,
    max_requests_per_session: u16,
    max_event_batch: u16,
}

impl ManagedAgentSemanticLimitsV1 {
    pub const fn try_new(
        max_sessions: u16,
        max_turns_per_session: u16,
        max_requests_per_session: u16,
        max_event_batch: u16,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        if max_sessions == 0
            || max_sessions > MAX_MANAGED_AGENT_SESSIONS
            || max_turns_per_session == 0
            || max_turns_per_session > MAX_MANAGED_AGENT_TURNS_PER_SESSION
            || max_requests_per_session == 0
            || max_requests_per_session > MAX_MANAGED_AGENT_REQUESTS_PER_SESSION
            || max_event_batch == 0
            || max_event_batch > MAX_MANAGED_AGENT_EVENT_BATCH
        {
            return Err(ManagedAgentStackPlanError::InvalidSemanticLimits);
        }
        Ok(Self {
            max_sessions,
            max_turns_per_session,
            max_requests_per_session,
            max_event_batch,
        })
    }

    #[must_use]
    pub const fn max_sessions(self) -> u16 {
        self.max_sessions
    }

    #[must_use]
    pub const fn max_turns_per_session(self) -> u16 {
        self.max_turns_per_session
    }

    #[must_use]
    pub const fn max_requests_per_session(self) -> u16 {
        self.max_requests_per_session
    }

    #[must_use]
    pub const fn max_event_batch(self) -> u16 {
        self.max_event_batch
    }
}

impl ManagedAgentIngressLimitsV1 {
    /// Validates every finite bound before any Runtime mutation can begin.
    pub const fn try_new(
        max_items: u32,
        max_bytes: u64,
        max_frame_bytes: u32,
        max_response_body_bytes: u32,
        handler_timeout_nanos: u64,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        if max_items == 0
            || max_items > MAX_MANAGED_AGENT_INGRESS_ITEMS
            || max_bytes == 0
            || max_bytes > MAX_MANAGED_AGENT_INGRESS_BYTES
            || max_frame_bytes < MIN_MANAGED_AGENT_FRAME_BYTES
            || max_frame_bytes > MAX_MANAGED_AGENT_FRAME_BYTES
            || max_frame_bytes as u64 > max_bytes
            || max_response_body_bytes < MIN_MANAGED_AGENT_RESPONSE_BODY_BYTES
            || max_response_body_bytes > MAX_MANAGED_AGENT_RESPONSE_BODY_BYTES
            || handler_timeout_nanos == 0
            || handler_timeout_nanos > MAX_MANAGED_AGENT_HANDLER_TIMEOUT_NANOS
        {
            return Err(ManagedAgentStackPlanError::InvalidIngressLimits);
        }
        Ok(Self {
            max_items,
            max_bytes,
            max_frame_bytes,
            max_response_body_bytes,
            handler_timeout_nanos,
        })
    }

    #[must_use]
    pub const fn max_items(self) -> u32 {
        self.max_items
    }

    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    #[must_use]
    pub const fn max_frame_bytes(self) -> u32 {
        self.max_frame_bytes
    }

    #[must_use]
    pub const fn max_response_body_bytes(self) -> u32 {
        self.max_response_body_bytes
    }

    #[must_use]
    pub const fn handler_timeout_nanos(self) -> u64 {
        self.handler_timeout_nanos
    }
}

/// Signed two-lane Agent conversation route and ingress bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentPortPlanV1 {
    submit_binding_id: BindingId,
    control_binding_id: BindingId,
    submit_key_expression: Box<str>,
    control_key_expression: Box<str>,
    ingress_limits: ManagedAgentIngressLimitsV1,
}

impl ManagedAgentPortPlanV1 {
    /// Deterministically derives the two target-local binding identities and
    /// canonical routes for one Agent service.
    ///
    /// The lane-specific digest domains prevent submit/control identity reuse.
    /// The legacy [`Self::try_new`] constructor remains the only entry point for
    /// callers that intentionally carry pre-existing binding IDs or routes.
    pub fn try_new_target_scoped(
        target: RuntimeHostId,
        service_id: ManagedServiceId,
        ingress_limits: ManagedAgentIngressLimitsV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        if bytes_are_zero(target.as_bytes()) || bytes_are_zero(service_id.as_bytes()) {
            return Err(ManagedAgentStackPlanError::InvalidBinding);
        }
        let submit_binding_id = derive_target_scoped_binding_id(
            TARGET_SCOPED_SUBMIT_BINDING_DOMAIN,
            target,
            service_id,
        )?;
        let control_binding_id = derive_target_scoped_binding_id(
            TARGET_SCOPED_CONTROL_BINDING_DOMAIN,
            target,
            service_id,
        )?;
        let submit_key_expression = target_scoped_agent_route(target, service_id, b"submit")?;
        let control_key_expression = target_scoped_agent_route(target, service_id, b"control")?;
        Self::try_new(
            submit_binding_id,
            control_binding_id,
            &submit_key_expression,
            &control_key_expression,
            ingress_limits,
        )
    }

    /// Validates both physical lanes as one atomic logical desired value.
    pub fn try_new(
        submit_binding_id: BindingId,
        control_binding_id: BindingId,
        submit_key_expression: &str,
        control_key_expression: &str,
        ingress_limits: ManagedAgentIngressLimitsV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        if bytes_are_zero(submit_binding_id.as_bytes())
            || bytes_are_zero(control_binding_id.as_bytes())
            || submit_binding_id == control_binding_id
        {
            return Err(ManagedAgentStackPlanError::InvalidBinding);
        }
        validate_key_expression(submit_key_expression)?;
        validate_key_expression(control_key_expression)?;
        if submit_key_expression == control_key_expression {
            return Err(ManagedAgentStackPlanError::InvalidBinding);
        }
        Ok(Self {
            submit_binding_id,
            control_binding_id,
            submit_key_expression: submit_key_expression.into(),
            control_key_expression: control_key_expression.into(),
            ingress_limits,
        })
    }

    #[must_use]
    pub const fn submit_binding_id(&self) -> BindingId {
        self.submit_binding_id
    }

    #[must_use]
    pub const fn control_binding_id(&self) -> BindingId {
        self.control_binding_id
    }

    #[must_use]
    pub fn submit_key_expression(&self) -> &str {
        &self.submit_key_expression
    }

    #[must_use]
    pub fn control_key_expression(&self) -> &str {
        &self.control_key_expression
    }

    #[must_use]
    pub const fn ingress_limits(&self) -> ManagedAgentIngressLimitsV1 {
        self.ingress_limits
    }
}

fn derive_target_scoped_binding_id(
    domain: &[u8],
    target: RuntimeHostId,
    service_id: ManagedServiceId,
) -> Result<BindingId, ManagedAgentStackPlanError> {
    let mut builder = Digest32Builder::try_new(domain)?;
    builder.field_bytes(target.as_bytes())?;
    builder.field_bytes(service_id.as_bytes())?;
    let digest = builder.finish();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes_are_zero(&bytes) {
        return Err(ManagedAgentStackPlanError::InvalidBinding);
    }
    Ok(BindingId::from_bytes(bytes))
}

fn target_scoped_agent_route(
    target: RuntimeHostId,
    service_id: ManagedServiceId,
    lane: &[u8],
) -> Result<String, ManagedAgentStackPlanError> {
    let mut route =
        Vec::with_capacity(TARGET_SCOPED_AGENT_ROUTE_PREFIX.len() + 32 + 1 + 32 + 1 + lane.len());
    route.extend_from_slice(TARGET_SCOPED_AGENT_ROUTE_PREFIX);
    append_lower_hex(&mut route, target.as_bytes());
    route.push(b'/');
    append_lower_hex(&mut route, service_id.as_bytes());
    route.push(b'/');
    route.extend_from_slice(lane);
    String::from_utf8(route).map_err(|_| ManagedAgentStackPlanError::InvalidKeyExpression)
}

fn append_lower_hex(output: &mut Vec<u8>, bytes: &[u8]) {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(LOWER_HEX[usize::from(byte >> 4)]);
        output.push(LOWER_HEX[usize::from(byte & 0x0f)]);
    }
}

/// Explicit provider selection retained by the committed Agent plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedAgentProviderSelectionV1 {
    profile: ManagedAgentProviderProfileV1,
    provider_ref: ManagedAgentProviderRefV1,
    config_digest: Digest32,
    secret_ref: Option<ManagedAgentSecretRefV1>,
}

impl ManagedAgentProviderSelectionV1 {
    /// Selects one provisioned provider and its owner-resolved secret reference.
    pub fn try_provisioned(
        provider_ref: ManagedAgentProviderRefV1,
        config_digest: Digest32,
        secret_ref: ManagedAgentSecretRefV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        Self::try_new(
            ManagedAgentProviderProfileV1::Provisioned,
            provider_ref,
            config_digest,
            Some(secret_ref),
        )
    }

    /// Selects the explicit deterministic offline fixture with no secret.
    pub fn try_deterministic_fixture(
        provider_ref: ManagedAgentProviderRefV1,
        config_digest: Digest32,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        Self::try_new(
            ManagedAgentProviderProfileV1::DeterministicFixture,
            provider_ref,
            config_digest,
            None,
        )
    }

    fn try_new(
        profile: ManagedAgentProviderProfileV1,
        provider_ref: ManagedAgentProviderRefV1,
        config_digest: Digest32,
        secret_ref: Option<ManagedAgentSecretRefV1>,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        if digest_is_zero(config_digest)
            || matches!(profile, ManagedAgentProviderProfileV1::Provisioned) != secret_ref.is_some()
        {
            return Err(ManagedAgentStackPlanError::InvalidProvider);
        }
        Ok(Self {
            profile,
            provider_ref,
            config_digest,
            secret_ref,
        })
    }

    #[must_use]
    pub const fn profile(self) -> ManagedAgentProviderProfileV1 {
        self.profile
    }

    #[must_use]
    pub const fn provider_ref(self) -> ManagedAgentProviderRefV1 {
        self.provider_ref
    }

    #[must_use]
    pub const fn config_digest(self) -> Digest32 {
        self.config_digest
    }

    #[must_use]
    pub const fn secret_ref(self) -> Option<ManagedAgentSecretRefV1> {
        self.secret_ref
    }
}

/// Complete Agent desired fields added after the retained Fabric service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentServicePlanV1 {
    service: ManagedServiceSpecV1,
    semantic_limits: ManagedAgentSemanticLimitsV1,
    port: ManagedAgentPortPlanV1,
    provider: ManagedAgentProviderSelectionV1,
}

impl ManagedAgentServicePlanV1 {
    pub fn try_new(
        service: ManagedServiceSpecV1,
        semantic_limits: ManagedAgentSemanticLimitsV1,
        port: ManagedAgentPortPlanV1,
        provider: ManagedAgentProviderSelectionV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        validate_service(service)?;
        Ok(Self {
            service,
            semantic_limits,
            port,
            provider,
        })
    }

    #[must_use]
    pub const fn service(&self) -> ManagedServiceSpecV1 {
        self.service
    }

    #[must_use]
    pub const fn semantic_limits(&self) -> ManagedAgentSemanticLimitsV1 {
        self.semantic_limits
    }

    #[must_use]
    pub const fn port(&self) -> &ManagedAgentPortPlanV1 {
        &self.port
    }

    #[must_use]
    pub const fn provider(&self) -> ManagedAgentProviderSelectionV1 {
        self.provider
    }
}

/// Canonical PXTE v6 fixed Fabric→Agent desired value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackTargetExecutionV1 {
    projection: ManagedAgentStackProjectionV1,
    mode: ManagedAgentStackTargetModeV1,
    fabric: ManagedFabricTargetExecutionV1,
    agent: Option<ManagedAgentServicePlanV1>,
    canonical_wire: Box<[u8]>,
    execution_digest: Digest32,
}

impl ManagedAgentStackTargetExecutionV1 {
    /// Creates the only active dependency shape: retained Fabric then Agent.
    pub fn try_fabric_and_agent(
        projection: ManagedAgentStackProjectionV1,
        fabric: ManagedFabricTargetExecutionV1,
        agent: ManagedAgentServicePlanV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        Self::try_new(
            projection,
            ManagedAgentStackTargetModeV1::FabricAndAgent,
            fabric,
            Some(agent),
        )
    }

    /// Creates authoritative exact-zero while retaining the verified projection.
    pub fn try_empty_deactivate(
        projection: ManagedAgentStackProjectionV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        let fabric = ManagedFabricTargetExecutionV1::try_empty_deactivate(
            projection.managed_fabric_projection().clone(),
        )?;
        Self::try_new(
            projection,
            ManagedAgentStackTargetModeV1::EmptyDeactivate,
            fabric,
            None,
        )
    }

    fn try_new(
        projection: ManagedAgentStackProjectionV1,
        mode: ManagedAgentStackTargetModeV1,
        fabric: ManagedFabricTargetExecutionV1,
        agent: Option<ManagedAgentServicePlanV1>,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        if fabric.projection() != projection.managed_fabric_projection() {
            return Err(ManagedAgentStackPlanError::ProjectionMismatch);
        }
        match (mode, fabric.mode(), agent.as_ref()) {
            (
                ManagedAgentStackTargetModeV1::FabricAndAgent,
                ManagedFabricTargetModeV1::OneManagedFabricService,
                Some(agent),
            ) => {
                if fabric
                    .service()
                    .is_some_and(|service| service.service_id() == agent.service().service_id())
                {
                    return Err(ManagedAgentStackPlanError::InvalidService);
                }
            }
            (
                ManagedAgentStackTargetModeV1::EmptyDeactivate,
                ManagedFabricTargetModeV1::EmptyDeactivate,
                None,
            ) => {}
            _ => return Err(ManagedAgentStackPlanError::InvalidShape),
        }
        let canonical_wire =
            build_target_execution_wire(&projection, mode, &fabric, agent.as_ref())?;
        if canonical_wire.len() > MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES {
            return Err(ManagedAgentStackPlanError::FrameTooLarge);
        }
        let execution_digest = digest_wire(TARGET_EXECUTION_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            projection,
            mode,
            fabric,
            agent,
            canonical_wire: canonical_wire.into_boxed_slice(),
            execution_digest,
        })
    }

    /// Strictly decodes exactly PXTE v6 without accepting PXTE v5 directly.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedAgentStackPlanError> {
        if frame.len() > MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES {
            return Err(ManagedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < TARGET_EXECUTION_FIXED_BYTES {
            return Err(ManagedAgentStackPlanError::Truncated);
        }
        if &frame[..4] != TARGET_EXECUTION_MAGIC
            || read_u16(&frame[4..6]) != MANAGED_AGENT_STACK_TARGET_EXECUTION_VERSION
        {
            return Err(ManagedAgentStackPlanError::UnsupportedWire);
        }
        let projection_end = 6 + STACK_PROJECTION_BYTES;
        let projection = ManagedAgentStackProjectionV1::decode(&frame[6..projection_end])?;
        if read_u16(&frame[projection_end..projection_end + 2])
            != MANAGED_AGENT_STACK_PROFILE_VERSION
        {
            return Err(ManagedAgentStackPlanError::UnsupportedWire);
        }
        let mode = match frame[projection_end + 2] {
            1 => ManagedAgentStackTargetModeV1::FabricAndAgent,
            2 => ManagedAgentStackTargetModeV1::EmptyDeactivate,
            _ => return Err(ManagedAgentStackPlanError::InvalidShape),
        };
        let present = frame[projection_end + 3];
        let fabric_length = read_u32(&frame[projection_end + 4..projection_end + 8]) as usize;
        if fabric_length == 0 || fabric_length > MAX_MANAGED_FABRIC_TARGET_EXECUTION_BYTES {
            return Err(ManagedAgentStackPlanError::InvalidLength);
        }
        let fabric_end = TARGET_EXECUTION_FIXED_BYTES
            .checked_add(fabric_length)
            .ok_or(ManagedAgentStackPlanError::FrameTooLarge)?;
        if frame.len() < fabric_end {
            return Err(ManagedAgentStackPlanError::Truncated);
        }
        let fabric = ManagedFabricTargetExecutionV1::decode(
            &frame[TARGET_EXECUTION_FIXED_BYTES..fabric_end],
        )?;
        let agent_frame = &frame[fabric_end..];
        let decoded = match (mode, present) {
            (ManagedAgentStackTargetModeV1::FabricAndAgent, 1) => {
                let agent = decode_agent_plan(agent_frame)?;
                Self::try_fabric_and_agent(projection, fabric, agent)
            }
            (ManagedAgentStackTargetModeV1::EmptyDeactivate, 0) if agent_frame.is_empty() => {
                let decoded = Self::try_empty_deactivate(projection)?;
                if decoded.fabric != fabric {
                    return Err(ManagedAgentStackPlanError::NonCanonicalFrame);
                }
                Ok(decoded)
            }
            (ManagedAgentStackTargetModeV1::EmptyDeactivate, 0) => {
                Err(ManagedAgentStackPlanError::TrailingBytes)
            }
            _ => Err(ManagedAgentStackPlanError::InvalidShape),
        }?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    #[must_use]
    pub const fn projection(&self) -> &ManagedAgentStackProjectionV1 {
        &self.projection
    }

    #[must_use]
    pub const fn mode(&self) -> ManagedAgentStackTargetModeV1 {
        self.mode
    }

    #[must_use]
    pub const fn fabric(&self) -> &ManagedFabricTargetExecutionV1 {
        &self.fabric
    }

    #[must_use]
    pub const fn agent(&self) -> Option<&ManagedAgentServicePlanV1> {
        self.agent.as_ref()
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
struct ManagedAgentStackAssignmentsV1 {
    bindings: TargetAssignments,
    execution: ManagedAgentStackTargetExecutionV1,
    assignment_digest: TargetAssignmentDigest,
}

impl ManagedAgentStackAssignmentsV1 {
    fn try_from_execution(
        execution: ManagedAgentStackTargetExecutionV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        let bindings = TargetAssignments::try_new(Vec::new())
            .map_err(|_| ManagedAgentStackPlanError::BindingNotAllowed)?;
        Self::try_new(bindings, execution)
    }

    fn try_new(
        bindings: TargetAssignments,
        execution: ManagedAgentStackTargetExecutionV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        bindings
            .validate()
            .map_err(|_| ManagedAgentStackPlanError::BindingNotAllowed)?;
        if !bindings.is_empty() || bindings.canonical_wire() != EMPTY_PXTA {
            return Err(ManagedAgentStackPlanError::BindingNotAllowed);
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
struct ManagedAgentStackPlanSliceV1 {
    commitment: RuntimeSliceCommitment,
    assignments: ManagedAgentStackAssignmentsV1,
}

impl ManagedAgentStackPlanSliceV1 {
    fn try_new(
        commitment: RuntimeSliceCommitment,
        assignments: ManagedAgentStackAssignmentsV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        commitment.validate()?;
        if commitment.header().assignment_digest() != assignments.assignment_digest {
            return Err(ManagedAgentStackPlanError::CommitmentMismatch);
        }
        if commitment.header().target() != assignments.execution.projection().target() {
            return Err(ManagedAgentStackPlanError::TargetMismatch);
        }
        Ok(Self {
            commitment,
            assignments,
        })
    }
}

/// Canonical envelope-v2 signing transcript used by PXAR v7.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackApplySigningTranscriptV2(ApplyRequestSigningTranscriptV2);

impl ManagedAgentStackApplySigningTranscriptV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Signature-independent PXAR v7 producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackApplyRequestDraftV1 {
    envelope: RuntimeApplyEnvelopeV2Draft,
    slice: ManagedAgentStackPlanSliceV1,
}

impl ManagedAgentStackApplyRequestDraftV1 {
    pub fn try_new(
        execution: ManagedAgentStackTargetExecutionV1,
        provenance: PlanProvenance,
        control: RuntimeApplyControl,
        temporal: ApplyTemporalConstraint,
        expected_runtime_store_instance_id: [u8; 32],
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        let assignments = ManagedAgentStackAssignmentsV1::try_from_execution(execution)?;
        let header = RuntimeSliceHeader::new(
            assignments.execution.projection().target(),
            provenance,
            assignments.assignment_digest,
        );
        let commitment = RuntimeSliceCommitment::try_new(header)?;
        let slice = ManagedAgentStackPlanSliceV1::try_new(commitment, assignments)?;
        let control_commitment = RuntimeApplyControlCommitment::try_new(commitment, control)?;
        let store = RuntimeStoreInstanceId::try_from_bytes(expected_runtime_store_instance_id)?;
        let envelope =
            RuntimeApplyEnvelopeV2Draft::try_new(control_commitment, temporal, store, auth_claim)?;
        Ok(Self { envelope, slice })
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedAgentStackApplySigningTranscriptV2, ManagedAgentStackPlanError> {
        Ok(ManagedAgentStackApplySigningTranscriptV2(
            self.envelope.signing_transcript()?,
        ))
    }

    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ManagedAgentStackApplyRequestV1, ManagedAgentStackPlanError> {
        let envelope = self.envelope.finalize(signature)?;
        ManagedAgentStackApplyRequestV1::try_new(envelope, self.slice)
    }
}

/// Signed strict PXAR v7 carrying envelope v2, PXTA-zero, and PXTE v6.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackApplyRequestV1 {
    envelope: RuntimeApplyEnvelopeV2,
    slice: ManagedAgentStackPlanSliceV1,
    canonical_wire: Box<[u8]>,
}

impl ManagedAgentStackApplyRequestV1 {
    fn try_new(
        envelope: RuntimeApplyEnvelopeV2,
        slice: ManagedAgentStackPlanSliceV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        if envelope.control_commitment().slice() != slice.commitment {
            return Err(ManagedAgentStackPlanError::CommitmentMismatch);
        }
        let canonical_wire = build_apply_request_wire(&envelope, &slice)?;
        if canonical_wire.len() > MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES {
            return Err(ManagedAgentStackPlanError::FrameTooLarge);
        }
        Ok(Self {
            envelope,
            slice,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes PXAR v7 and cross-rejects all predecessor versions.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedAgentStackPlanError> {
        if frame.len() > MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES {
            return Err(ManagedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < APPLY_REQUEST_HEADER_BYTES {
            return Err(ManagedAgentStackPlanError::Truncated);
        }
        if &frame[..4] != APPLY_REQUEST_MAGIC
            || read_u16(&frame[4..6]) != MANAGED_AGENT_STACK_APPLY_REQUEST_VERSION
        {
            return Err(ManagedAgentStackPlanError::UnsupportedWire);
        }
        let envelope_length = read_u32(&frame[6..10]) as usize;
        let bindings_length = read_u32(&frame[10..14]) as usize;
        let execution_length = read_u32(&frame[14..18]) as usize;
        if envelope_length > MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES
            || bindings_length != EMPTY_PXTA.len()
            || execution_length > MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES
        {
            return Err(ManagedAgentStackPlanError::InvalidLength);
        }
        let expected_length = APPLY_REQUEST_HEADER_BYTES
            .checked_add(envelope_length)
            .and_then(|value| value.checked_add(bindings_length))
            .and_then(|value| value.checked_add(execution_length))
            .ok_or(ManagedAgentStackPlanError::FrameTooLarge)?;
        if frame.len() < expected_length {
            return Err(ManagedAgentStackPlanError::Truncated);
        }
        if frame.len() > expected_length {
            return Err(ManagedAgentStackPlanError::TrailingBytes);
        }
        let envelope_start = APPLY_REQUEST_HEADER_BYTES;
        let envelope_end = envelope_start + envelope_length;
        let bindings_end = envelope_end + bindings_length;
        let envelope = RuntimeApplyEnvelopeV2::decode(&frame[envelope_start..envelope_end])?;
        let binding_frame = &frame[envelope_end..bindings_end];
        if binding_frame != EMPTY_PXTA {
            return Err(ManagedAgentStackPlanError::BindingNotAllowed);
        }
        let bindings = TargetAssignments::decode(binding_frame)
            .map_err(|_| ManagedAgentStackPlanError::BindingNotAllowed)?;
        let execution = ManagedAgentStackTargetExecutionV1::decode(&frame[bindings_end..])?;
        let assignments = ManagedAgentStackAssignmentsV1::try_new(bindings, execution)?;
        let commitment = envelope.control_commitment().slice();
        let slice = ManagedAgentStackPlanSliceV1::try_new(commitment, assignments)?;
        let decoded = Self::try_new(envelope, slice)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedAgentStackPlanError::NonCanonicalFrame);
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
    pub const fn target_execution(&self) -> &ManagedAgentStackTargetExecutionV1 {
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
    ) -> Result<ManagedAgentStackApplySigningTranscriptV2, ManagedAgentStackPlanError> {
        Ok(ManagedAgentStackApplySigningTranscriptV2(
            self.envelope.signing_transcript()?,
        ))
    }

    pub fn validate_expected_store(
        &self,
        local_runtime_store_instance_id: [u8; 32],
    ) -> Result<(), ManagedAgentStackPlanError> {
        let local = RuntimeStoreInstanceId::try_from_bytes(local_runtime_store_instance_id)?;
        self.envelope.validate_expected_store(local)?;
        Ok(())
    }

    pub fn validate_projection(
        &self,
        projection: &ManagedAgentStackProjectionV1,
    ) -> Result<(), ManagedAgentStackPlanError> {
        if self.target_execution().projection() != projection {
            return Err(ManagedAgentStackPlanError::ProjectionMismatch);
        }
        Ok(())
    }
}

/// Reconstructs one durable `PXTA-zero || PXTE-v6` value from journal authority.
pub fn verify_managed_agent_stack_durable_slice_v1(
    canonical_slice_wire: &[u8],
    target: RuntimeHostId,
    provenance: PlanProvenance,
    expected_target_slice_digest: TargetSliceDigest,
    projection: &ManagedAgentStackProjectionV1,
) -> Result<ManagedAgentStackTargetExecutionV1, ManagedAgentStackPlanError> {
    if canonical_slice_wire.len() > MAX_MANAGED_AGENT_STACK_PLAN_SLICE_BYTES {
        return Err(ManagedAgentStackPlanError::FrameTooLarge);
    }
    if canonical_slice_wire.len() < EMPTY_PXTA.len() {
        return Err(ManagedAgentStackPlanError::Truncated);
    }
    let (binding_frame, execution_frame) = canonical_slice_wire.split_at(EMPTY_PXTA.len());
    if binding_frame != EMPTY_PXTA {
        return Err(ManagedAgentStackPlanError::BindingNotAllowed);
    }
    let bindings = TargetAssignments::decode(binding_frame)
        .map_err(|_| ManagedAgentStackPlanError::BindingNotAllowed)?;
    let execution = ManagedAgentStackTargetExecutionV1::decode(execution_frame)?;
    if execution.projection() != projection || execution.projection().target() != target {
        return Err(ManagedAgentStackPlanError::ProjectionMismatch);
    }
    let assignments = ManagedAgentStackAssignmentsV1::try_new(bindings, execution)?;
    let commitment = RuntimeSliceCommitment::try_new(RuntimeSliceHeader::new(
        target,
        provenance,
        assignments.assignment_digest,
    ))?;
    if commitment.target_slice_digest() != expected_target_slice_digest {
        return Err(ManagedAgentStackPlanError::CommitmentMismatch);
    }
    let slice = ManagedAgentStackPlanSliceV1::try_new(commitment, assignments)?;
    Ok(slice.assignments.execution)
}

/// Computes the exact contract fingerprint embedded in PXSP v1.
pub fn managed_agent_stack_compatibility_digest_v1() -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(STACK_COMPATIBILITY_DIGEST_DOMAIN)?;
    builder.field_bytes(STACK_PROJECTION_MAGIC)?;
    builder.field_u16(MANAGED_AGENT_STACK_PROJECTION_VERSION)?;
    builder.field_u16(STACK_PROJECTION_BYTES as u16)?;
    builder.field_bytes(APPLY_REQUEST_MAGIC)?;
    builder.field_u16(MANAGED_AGENT_STACK_APPLY_REQUEST_VERSION)?;
    builder.field_u16(APPLY_REQUEST_HEADER_BYTES as u16)?;
    builder.field_bytes(&(MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES as u32).to_be_bytes())?;
    builder.field_bytes(TARGET_EXECUTION_MAGIC)?;
    builder.field_u16(MANAGED_AGENT_STACK_TARGET_EXECUTION_VERSION)?;
    builder.field_bytes(&(MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES as u32).to_be_bytes())?;
    builder.field_u16(MANAGED_AGENT_STACK_PROFILE_VERSION)?;
    builder.field_u16(MANAGED_AGENT_PROVIDER_SELECTION_VERSION)?;
    builder.field_u16(MANAGED_SERVICE_CONTRACT_VERSION)?;
    builder.field_u16(MANAGED_FABRIC_APPLY_ENVELOPE_VERSION)?;
    builder.field_u16(MANAGED_FABRIC_APPLY_SIGNING_TRANSCRIPT_VERSION)?;
    builder.field_bytes(&EMPTY_PXTA)?;
    builder.field_u16(MAX_MANAGED_AGENT_KEY_EXPRESSION_BYTES as u16)?;
    builder.field_bytes(&MAX_MANAGED_AGENT_INGRESS_ITEMS.to_be_bytes())?;
    builder.field_u64(MAX_MANAGED_AGENT_INGRESS_BYTES)?;
    builder.field_bytes(&MIN_MANAGED_AGENT_FRAME_BYTES.to_be_bytes())?;
    builder.field_bytes(&MAX_MANAGED_AGENT_FRAME_BYTES.to_be_bytes())?;
    builder.field_bytes(&MIN_MANAGED_AGENT_RESPONSE_BODY_BYTES.to_be_bytes())?;
    builder.field_bytes(&MAX_MANAGED_AGENT_RESPONSE_BODY_BYTES.to_be_bytes())?;
    builder.field_u64(MAX_MANAGED_AGENT_HANDLER_TIMEOUT_NANOS)?;
    builder.field_u16(MAX_MANAGED_AGENT_SESSIONS)?;
    builder.field_u16(MAX_MANAGED_AGENT_TURNS_PER_SESSION)?;
    builder.field_u16(MAX_MANAGED_AGENT_REQUESTS_PER_SESSION)?;
    builder.field_u16(MAX_MANAGED_AGENT_EVENT_BATCH)?;
    builder.field_bytes(TARGET_EXECUTION_DIGEST_DOMAIN)?;
    builder.field_bytes(TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN)?;
    builder.field_u16(ManagedAgentStackTargetModeV1::FabricAndAgent as u16)?;
    builder.field_u16(ManagedAgentStackTargetModeV1::EmptyDeactivate as u16)?;
    builder.field_u16(ManagedAgentProviderProfileV1::Provisioned as u16)?;
    builder.field_u16(ManagedAgentProviderProfileV1::DeterministicFixture as u16)?;
    builder.field_bytes(TERMINAL_RECEIPT_MAGIC)?;
    builder.field_u16(MANAGED_AGENT_STACK_TERMINAL_RECEIPT_VERSION)?;
    builder.field_u16(MANAGED_AGENT_STACK_TERMINAL_SIGNING_VERSION)?;
    builder.field_u16(MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES as u16)?;
    builder.field_u16(MAX_MANAGED_AGENT_STACK_TERMINAL_SIGNATURE_BYTES as u16)?;
    builder.field_bytes(TERMINAL_RESULT_REF_DOMAIN)?;
    builder.field_bytes(TERMINAL_RECEIPT_SIGNING_MAGIC)?;
    builder.field_bytes(TERMINAL_RECEIPT_DIGEST_DOMAIN)?;
    Ok(builder.finish())
}

/// Runtime terminal classification for one exact PXAR v7 operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedAgentStackTerminalOutcomeV1 {
    ActiveReady = 1,
    EmptyExactZero = 2,
    NoEffectRejected = 3,
    Uncertain = 4,
    Quarantined = 5,
}

/// Strongest lifecycle-effect claim made by one terminal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedAgentStackTerminalLifecycleEffectV1 {
    ProvenNotStarted = 1,
    MayHaveStarted = 2,
}

/// Runtime-observed desired head after the exact operation completed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ManagedAgentStackTerminalHeadV1 {
    PreservedNone,
    PreservedExisting(TargetSliceDigest),
    CommittedIncoming,
}

/// Derived nonzero identity of one PXST result.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedAgentStackTerminalResultRefV1([u8; 16]);

impl ManagedAgentStackTerminalResultRefV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Lifecycle and desired-head facts for one terminal outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackTerminalStateV1 {
    outcome: ManagedAgentStackTerminalOutcomeV1,
    lifecycle_effect: ManagedAgentStackTerminalLifecycleEffectV1,
    head: ManagedAgentStackTerminalHeadV1,
    fabric_generation: Option<ManagedServiceGeneration>,
    agent_generation: Option<ManagedServiceGeneration>,
}

impl ManagedAgentStackTerminalStateV1 {
    pub fn try_new(
        outcome: ManagedAgentStackTerminalOutcomeV1,
        lifecycle_effect: ManagedAgentStackTerminalLifecycleEffectV1,
        head: ManagedAgentStackTerminalHeadV1,
        fabric_generation: Option<ManagedServiceGeneration>,
        agent_generation: Option<ManagedServiceGeneration>,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        if agent_generation.is_some() && fabric_generation.is_none() {
            return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
        }
        let state = Self {
            outcome,
            lifecycle_effect,
            head,
            fabric_generation,
            agent_generation,
        };
        validate_terminal_state(state)?;
        Ok(state)
    }

    #[must_use]
    pub const fn outcome(self) -> ManagedAgentStackTerminalOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub const fn lifecycle_effect(self) -> ManagedAgentStackTerminalLifecycleEffectV1 {
        self.lifecycle_effect
    }

    #[must_use]
    pub const fn head(self) -> ManagedAgentStackTerminalHeadV1 {
        self.head
    }

    #[must_use]
    pub const fn fabric_generation(self) -> Option<ManagedServiceGeneration> {
        self.fabric_generation
    }

    #[must_use]
    pub const fn agent_generation(self) -> Option<ManagedServiceGeneration> {
        self.agent_generation
    }
}

/// Caller-supplied Runtime observations used to construct bounded terminal evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackTerminalEvidenceFieldsV1 {
    pub physical_binding_census: u16,
    pub census_complete: bool,
    pub fabric_ready: bool,
    pub agent_ready: bool,
    pub dependency_satisfied: bool,
    pub exact_zero: bool,
    pub quarantined: bool,
    pub resource_census_digest: Digest32,
    pub raw_outcome_digest: Digest32,
    pub completion_runtime_host_epoch: u64,
    pub completion_snapshot_sequence: u64,
    pub selection_clock_generation: ClockGeneration,
    pub selection_observed_at_nanos: u64,
}

/// Validated physical census, dependency, readiness, and temporal evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackTerminalEvidenceV1(ManagedAgentStackTerminalEvidenceFieldsV1);

impl ManagedAgentStackTerminalEvidenceV1 {
    pub fn try_new(
        fields: ManagedAgentStackTerminalEvidenceFieldsV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        if fields.physical_binding_census > 2
            || (fields.agent_ready && (!fields.fabric_ready || !fields.dependency_satisfied))
            || fields.exact_zero
                && (fields.physical_binding_census != 0
                    || fields.fabric_ready
                    || fields.agent_ready
                    || fields.dependency_satisfied
                    || fields.quarantined)
            || digest_is_zero(fields.resource_census_digest)
            || digest_is_zero(fields.raw_outcome_digest)
            || fields.completion_runtime_host_epoch == 0
            || fields.completion_snapshot_sequence == 0
            || fields.selection_observed_at_nanos == 0
        {
            return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
        }
        Ok(Self(fields))
    }

    #[must_use]
    pub const fn fields(self) -> ManagedAgentStackTerminalEvidenceFieldsV1 {
        self.0
    }
}

/// Complete request-correlated Runtime facts signed into PXST v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackTerminalFactsV1 {
    target: RuntimeHostId,
    runtime_store_instance_id: [u8; 32],
    source_scope: crate::provenance::SourceScopeRef,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    target_slice_digest: TargetSliceDigest,
    assignment_digest: TargetAssignmentDigest,
    terminal_result_ref: ManagedAgentStackTerminalResultRefV1,
    request_mode: ManagedAgentStackTargetModeV1,
    state: ManagedAgentStackTerminalStateV1,
    desired_head_digest: Option<TargetSliceDigest>,
    evidence: ManagedAgentStackTerminalEvidenceV1,
}

impl ManagedAgentStackTerminalFactsV1 {
    pub fn try_new(
        request: &ManagedAgentStackApplyRequestV1,
        state: ManagedAgentStackTerminalStateV1,
        evidence: ManagedAgentStackTerminalEvidenceV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
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
        request: &ManagedAgentStackApplyRequestV1,
    ) -> Result<(), ManagedAgentStackPlanError> {
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
            return Err(ManagedAgentStackPlanError::TerminalCorrelationMismatch);
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
    pub const fn terminal_result_ref(self) -> ManagedAgentStackTerminalResultRefV1 {
        self.terminal_result_ref
    }

    #[must_use]
    pub const fn request_mode(self) -> ManagedAgentStackTargetModeV1 {
        self.request_mode
    }

    #[must_use]
    pub const fn state(self) -> ManagedAgentStackTerminalStateV1 {
        self.state
    }

    #[must_use]
    pub const fn desired_head_digest(self) -> Option<TargetSliceDigest> {
        self.desired_head_digest
    }

    #[must_use]
    pub const fn evidence(self) -> ManagedAgentStackTerminalEvidenceV1 {
        self.evidence
    }
}

/// Runtime signer selection bound to the exact local control channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackTerminalAuthClaimV1 {
    runtime_peer: PrincipalRef,
    channel_binding_digest: Digest32,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

impl ManagedAgentStackTerminalAuthClaimV1 {
    pub fn try_new(
        channel: ReferenceChannelBindingV1,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        if bytes_are_zero(key.as_bytes()) || algorithm_version == 0 {
            return Err(ManagedAgentStackPlanError::InvalidResponseAuthentication);
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

/// Exact bytes supplied to the Runtime response signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackTerminalSigningTranscriptV1(Box<[u8]>);

impl ManagedAgentStackTerminalSigningTranscriptV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent PXST v1 producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackTerminalReceiptDraftV1 {
    facts: ManagedAgentStackTerminalFactsV1,
    channel: ReferenceChannelBindingV1,
    auth_claim: ManagedAgentStackTerminalAuthClaimV1,
}

impl ManagedAgentStackTerminalReceiptDraftV1 {
    pub fn try_new(
        request: &ManagedAgentStackApplyRequestV1,
        facts: ManagedAgentStackTerminalFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: ManagedAgentStackTerminalAuthClaimV1,
    ) -> Result<Self, ManagedAgentStackPlanError> {
        facts.validate_against_request(request)?;
        if channel.target() != request.target()
            || auth_claim.runtime_peer() != channel.runtime_peer()
            || auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(ManagedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(Self {
            facts,
            channel,
            auth_claim,
        })
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedAgentStackTerminalSigningTranscriptV1, ManagedAgentStackPlanError> {
        Ok(ManagedAgentStackTerminalSigningTranscriptV1(
            build_terminal_fields(
                TERMINAL_RECEIPT_SIGNING_MAGIC,
                MANAGED_AGENT_STACK_TERMINAL_SIGNING_VERSION,
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
    ) -> Result<ManagedAgentStackTerminalReceiptV1, ManagedAgentStackPlanError> {
        if signature.is_empty()
            || signature.len() > MAX_MANAGED_AGENT_STACK_TERMINAL_SIGNATURE_BYTES
        {
            return Err(ManagedAgentStackPlanError::InvalidResponseAuthentication);
        }
        ManagedAgentStackTerminalReceiptV1::try_new(
            self.facts,
            self.channel,
            self.auth_claim,
            signature,
        )
    }
}

/// Signed strict PXST v1 Runtime terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentStackTerminalReceiptV1 {
    facts: ManagedAgentStackTerminalFactsV1,
    channel: ReferenceChannelBindingV1,
    auth_claim: ManagedAgentStackTerminalAuthClaimV1,
    signature: Box<[u8]>,
    canonical_wire: Box<[u8]>,
    receipt_digest: Digest32,
}

impl ManagedAgentStackTerminalReceiptV1 {
    fn try_new(
        facts: ManagedAgentStackTerminalFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: ManagedAgentStackTerminalAuthClaimV1,
        signature: &[u8],
    ) -> Result<Self, ManagedAgentStackPlanError> {
        let mut canonical_wire = build_terminal_fields(
            TERMINAL_RECEIPT_MAGIC,
            MANAGED_AGENT_STACK_TERMINAL_RECEIPT_VERSION,
            facts,
            channel,
            auth_claim,
        )?;
        let signature_length = u16::try_from(signature.len())
            .map_err(|_| ManagedAgentStackPlanError::InvalidLength)?;
        canonical_wire.extend_from_slice(&signature_length.to_be_bytes());
        canonical_wire.extend_from_slice(signature);
        if canonical_wire.len() > MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES {
            return Err(ManagedAgentStackPlanError::FrameTooLarge);
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

    pub fn decode(frame: &[u8]) -> Result<Self, ManagedAgentStackPlanError> {
        if frame.len() > MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES {
            return Err(ManagedAgentStackPlanError::FrameTooLarge);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.array::<4>()? != *TERMINAL_RECEIPT_MAGIC
            || cursor.u16()? != MANAGED_AGENT_STACK_TERMINAL_RECEIPT_VERSION
        {
            return Err(ManagedAgentStackPlanError::UnsupportedWire);
        }
        let facts = decode_terminal_facts(&mut cursor)?;
        let channel = decode_terminal_channel(&mut cursor)?;
        let auth_claim = decode_terminal_auth_claim(&mut cursor)?;
        let signature_length = cursor.usize_u16()?;
        if signature_length == 0
            || signature_length > MAX_MANAGED_AGENT_STACK_TERMINAL_SIGNATURE_BYTES
        {
            return Err(ManagedAgentStackPlanError::InvalidLength);
        }
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let decoded = Self::try_new(facts, channel, auth_claim, signature)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    pub fn validate_against_request(
        &self,
        request: &ManagedAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<ManagedAgentStackTerminalFactsV1, ManagedAgentStackPlanError> {
        self.facts.validate_against_request(request)?;
        if self.channel != channel
            || channel.target() != request.target()
            || self.auth_claim.runtime_peer() != channel.runtime_peer()
            || self.auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(ManagedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(self.facts)
    }

    #[must_use]
    pub const fn facts(&self) -> ManagedAgentStackTerminalFactsV1 {
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
    ) -> Result<ManagedAgentStackTerminalSigningTranscriptV1, ManagedAgentStackPlanError> {
        ManagedAgentStackTerminalReceiptDraftV1 {
            facts: self.facts,
            channel: self.channel,
            auth_claim: self.auth_claim,
        }
        .signing_transcript()
    }
}

fn validate_terminal_state(
    state: ManagedAgentStackTerminalStateV1,
) -> Result<(), ManagedAgentStackPlanError> {
    let committed = matches!(
        state.head(),
        ManagedAgentStackTerminalHeadV1::CommittedIncoming
    );
    match state.outcome() {
        ManagedAgentStackTerminalOutcomeV1::ActiveReady => {
            if state.lifecycle_effect()
                != ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted
                || !committed
                || state.fabric_generation().is_none()
                || state.agent_generation().is_none()
            {
                return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
            }
        }
        ManagedAgentStackTerminalOutcomeV1::EmptyExactZero => {
            if !committed
                || state.fabric_generation().is_some()
                || state.agent_generation().is_some()
            {
                return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
            }
        }
        ManagedAgentStackTerminalOutcomeV1::NoEffectRejected => {
            if state.lifecycle_effect()
                != ManagedAgentStackTerminalLifecycleEffectV1::ProvenNotStarted
                || committed
            {
                return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
            }
        }
        ManagedAgentStackTerminalOutcomeV1::Uncertain => {
            if state.lifecycle_effect()
                != ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted
            {
                return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
            }
        }
        ManagedAgentStackTerminalOutcomeV1::Quarantined => {
            if state.lifecycle_effect()
                != ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted
                || !committed
                || state.fabric_generation().is_none()
            {
                return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
            }
        }
    }
    Ok(())
}

fn validate_terminal_state_evidence(
    state: ManagedAgentStackTerminalStateV1,
    evidence: ManagedAgentStackTerminalEvidenceV1,
) -> Result<(), ManagedAgentStackPlanError> {
    validate_terminal_state(state)?;
    let facts = evidence.fields();
    let generations_ready =
        state.fabric_generation().is_some() && state.agent_generation().is_some();
    let valid = match state.outcome() {
        ManagedAgentStackTerminalOutcomeV1::ActiveReady => {
            generations_ready
                && facts.census_complete
                && facts.physical_binding_census == 2
                && facts.fabric_ready
                && facts.agent_ready
                && facts.dependency_satisfied
                && !facts.exact_zero
                && !facts.quarantined
        }
        ManagedAgentStackTerminalOutcomeV1::EmptyExactZero => {
            facts.census_complete && facts.exact_zero && !facts.quarantined
        }
        ManagedAgentStackTerminalOutcomeV1::NoEffectRejected => {
            facts.census_complete
                && !facts.quarantined
                && ((facts.exact_zero
                    && state.fabric_generation().is_none()
                    && state.agent_generation().is_none())
                    || (!facts.exact_zero
                        && generations_ready
                        && facts.physical_binding_census == 2
                        && facts.fabric_ready
                        && facts.agent_ready
                        && facts.dependency_satisfied))
        }
        ManagedAgentStackTerminalOutcomeV1::Uncertain => !facts.exact_zero && !facts.quarantined,
        ManagedAgentStackTerminalOutcomeV1::Quarantined => {
            facts.quarantined
                && !facts.exact_zero
                && !facts.agent_ready
                && !facts.dependency_satisfied
        }
    };
    if !valid {
        return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(())
}

fn validate_terminal_outcome_mode(
    outcome: ManagedAgentStackTerminalOutcomeV1,
    mode: ManagedAgentStackTargetModeV1,
) -> Result<(), ManagedAgentStackPlanError> {
    if matches!(outcome, ManagedAgentStackTerminalOutcomeV1::ActiveReady)
        && mode != ManagedAgentStackTargetModeV1::FabricAndAgent
        || matches!(outcome, ManagedAgentStackTerminalOutcomeV1::EmptyExactZero)
            && mode != ManagedAgentStackTargetModeV1::EmptyDeactivate
    {
        return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(())
}

fn resolve_terminal_head(
    request: &ManagedAgentStackApplyRequestV1,
    head: ManagedAgentStackTerminalHeadV1,
) -> Result<Option<TargetSliceDigest>, ManagedAgentStackPlanError> {
    match head {
        ManagedAgentStackTerminalHeadV1::PreservedNone => Ok(None),
        ManagedAgentStackTerminalHeadV1::PreservedExisting(value)
            if !digest_is_zero(*value.value()) =>
        {
            Ok(Some(value))
        }
        ManagedAgentStackTerminalHeadV1::PreservedExisting(_) => {
            Err(ManagedAgentStackPlanError::InvalidTerminalFacts)
        }
        ManagedAgentStackTerminalHeadV1::CommittedIncoming => {
            Ok(Some(request.target_slice_digest()))
        }
    }
}

fn derive_terminal_result_ref(
    request: &ManagedAgentStackApplyRequestV1,
) -> Result<ManagedAgentStackTerminalResultRefV1, ManagedAgentStackPlanError> {
    let mut builder = Digest32Builder::try_new(TERMINAL_RESULT_REF_DOMAIN)?;
    builder.field_bytes(TERMINAL_RECEIPT_MAGIC)?;
    builder.field_u16(MANAGED_AGENT_STACK_TERMINAL_RECEIPT_VERSION)?;
    builder.field_bytes(request.target().as_bytes())?;
    builder.field_bytes(&request.expected_runtime_store_instance_id())?;
    builder.field_bytes(request.provenance().source_scope().as_bytes())?;
    builder.field_bytes(request.operation_id().as_bytes())?;
    builder.field_digest(&request.envelope_request_digest())?;
    let digest = builder.finish();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes_are_zero(&bytes) {
        return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(ManagedAgentStackTerminalResultRefV1(bytes))
}

fn build_terminal_fields(
    magic: &[u8],
    version: u16,
    facts: ManagedAgentStackTerminalFactsV1,
    channel: ReferenceChannelBindingV1,
    auth: ManagedAgentStackTerminalAuthClaimV1,
) -> Result<Vec<u8>, ManagedAgentStackPlanError> {
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
        ManagedAgentStackTerminalHeadV1::PreservedNone => 1,
        ManagedAgentStackTerminalHeadV1::PreservedExisting(_) => 2,
        ManagedAgentStackTerminalHeadV1::CommittedIncoming => 3,
    });
    wire.push(u8::from(facts.desired_head_digest().is_some()));
    let desired_head_bytes = facts
        .desired_head_digest()
        .map_or([0; 32], |value| *value.value().as_bytes());
    wire.extend_from_slice(&desired_head_bytes);
    encode_generation(&mut wire, state.fabric_generation());
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

fn terminal_evidence_flags(fields: ManagedAgentStackTerminalEvidenceFieldsV1) -> u8 {
    u8::from(fields.census_complete)
        | (u8::from(fields.fabric_ready) << 1)
        | (u8::from(fields.agent_ready) << 2)
        | (u8::from(fields.dependency_satisfied) << 3)
        | (u8::from(fields.exact_zero) << 4)
        | (u8::from(fields.quarantined) << 5)
}

fn decode_terminal_facts(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedAgentStackTerminalFactsV1, ManagedAgentStackPlanError> {
    let target = RuntimeHostId::from_bytes(cursor.array()?);
    let runtime_store_instance_id = cursor.array()?;
    let source_scope = crate::provenance::SourceScopeRef::from_bytes(cursor.array()?);
    let operation_id = ApplyOperationId::from_bytes(cursor.array()?);
    let request_digest = Digest32::from_bytes(cursor.array()?);
    let target_slice_digest = TargetSliceDigest::new(Digest32::from_bytes(cursor.array()?));
    let assignment_digest = TargetAssignmentDigest::new(Digest32::from_bytes(cursor.array()?));
    let terminal_result_ref = ManagedAgentStackTerminalResultRefV1(cursor.array()?);
    let request_mode = match cursor.u8()? {
        1 => ManagedAgentStackTargetModeV1::FabricAndAgent,
        2 => ManagedAgentStackTargetModeV1::EmptyDeactivate,
        _ => return Err(ManagedAgentStackPlanError::InvalidTerminalFacts),
    };
    let outcome = match cursor.u8()? {
        1 => ManagedAgentStackTerminalOutcomeV1::ActiveReady,
        2 => ManagedAgentStackTerminalOutcomeV1::EmptyExactZero,
        3 => ManagedAgentStackTerminalOutcomeV1::NoEffectRejected,
        4 => ManagedAgentStackTerminalOutcomeV1::Uncertain,
        5 => ManagedAgentStackTerminalOutcomeV1::Quarantined,
        _ => return Err(ManagedAgentStackPlanError::InvalidTerminalFacts),
    };
    let lifecycle_effect = match cursor.u8()? {
        1 => ManagedAgentStackTerminalLifecycleEffectV1::ProvenNotStarted,
        2 => ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
        _ => return Err(ManagedAgentStackPlanError::InvalidTerminalFacts),
    };
    let head_tag = cursor.u8()?;
    let desired_present = cursor.u8()?;
    let desired_bytes: [u8; 32] = cursor.array()?;
    let desired_head_digest = match desired_present {
        0 if bytes_are_zero(&desired_bytes) => None,
        1 => Some(TargetSliceDigest::new(Digest32::from_bytes(desired_bytes))),
        _ => return Err(ManagedAgentStackPlanError::InvalidTerminalFacts),
    };
    let head = match (head_tag, desired_head_digest) {
        (1, None) => ManagedAgentStackTerminalHeadV1::PreservedNone,
        (2, Some(value)) => ManagedAgentStackTerminalHeadV1::PreservedExisting(value),
        (3, Some(_)) => ManagedAgentStackTerminalHeadV1::CommittedIncoming,
        _ => return Err(ManagedAgentStackPlanError::InvalidTerminalFacts),
    };
    let fabric_generation = decode_generation(cursor)?;
    let agent_generation = decode_generation(cursor)?;
    let state = ManagedAgentStackTerminalStateV1::try_new(
        outcome,
        lifecycle_effect,
        head,
        fabric_generation,
        agent_generation,
    )?;
    let physical_binding_census = cursor.u16()?;
    let flags = cursor.u8()?;
    if flags & 0b1100_0000 != 0 {
        return Err(ManagedAgentStackPlanError::NonCanonicalFrame);
    }
    let evidence =
        ManagedAgentStackTerminalEvidenceV1::try_new(ManagedAgentStackTerminalEvidenceFieldsV1 {
            physical_binding_census,
            census_complete: flags & 1 != 0,
            fabric_ready: flags & 2 != 0,
            agent_ready: flags & 4 != 0,
            dependency_satisfied: flags & 8 != 0,
            exact_zero: flags & 16 != 0,
            quarantined: flags & 32 != 0,
            resource_census_digest: Digest32::from_bytes(cursor.array()?),
            raw_outcome_digest: Digest32::from_bytes(cursor.array()?),
            completion_runtime_host_epoch: cursor.u64()?,
            completion_snapshot_sequence: cursor.u64()?,
            selection_clock_generation: ClockGeneration::try_new(cursor.u64()?)
                .map_err(|_| ManagedAgentStackPlanError::InvalidTerminalFacts)?,
            selection_observed_at_nanos: cursor.u64()?,
        })?;
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
        return Err(ManagedAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(ManagedAgentStackTerminalFactsV1 {
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
) -> Result<Option<ManagedServiceGeneration>, ManagedAgentStackPlanError> {
    let present = cursor.u8()?;
    let value = cursor.u64()?;
    match (present, value) {
        (0, 0) => Ok(None),
        (1, value) => ManagedServiceGeneration::try_new(value)
            .map(Some)
            .map_err(|_| ManagedAgentStackPlanError::InvalidTerminalFacts),
        _ => Err(ManagedAgentStackPlanError::InvalidTerminalFacts),
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
) -> Result<ReferenceChannelBindingV1, ManagedAgentStackPlanError> {
    ReferenceChannelBindingV1::try_new(
        RuntimeHostId::from_bytes(cursor.array()?),
        PrincipalRef::from_bytes(cursor.array()?),
        Digest32::from_bytes(cursor.array()?),
        Digest32::from_bytes(cursor.array()?),
    )
    .map_err(|_| ManagedAgentStackPlanError::InvalidResponseAuthentication)
}

fn encode_terminal_auth_claim(wire: &mut Vec<u8>, auth: ManagedAgentStackTerminalAuthClaimV1) {
    wire.extend_from_slice(auth.runtime_peer().as_bytes());
    wire.extend_from_slice(auth.channel_binding_digest().as_bytes());
    wire.extend_from_slice(auth.key().as_bytes());
    wire.extend_from_slice(&auth.algorithm().value().to_be_bytes());
    wire.extend_from_slice(&auth.algorithm_version().to_be_bytes());
}

fn decode_terminal_auth_claim(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedAgentStackTerminalAuthClaimV1, ManagedAgentStackPlanError> {
    let runtime_peer = PrincipalRef::from_bytes(cursor.array()?);
    let channel_binding_digest = Digest32::from_bytes(cursor.array()?);
    let key = ApplyAuthKeyRef::from_bytes(cursor.array()?);
    let algorithm = ApplyAuthAlgorithm::try_new(cursor.u16()?)
        .map_err(|_| ManagedAgentStackPlanError::InvalidResponseAuthentication)?;
    let algorithm_version = cursor.u16()?;
    if bytes_are_zero(runtime_peer.as_bytes())
        || digest_is_zero(channel_binding_digest)
        || bytes_are_zero(key.as_bytes())
        || algorithm_version == 0
    {
        return Err(ManagedAgentStackPlanError::InvalidResponseAuthentication);
    }
    Ok(ManagedAgentStackTerminalAuthClaimV1 {
        runtime_peer,
        channel_binding_digest,
        key,
        algorithm,
        algorithm_version,
    })
}

fn build_projection_wire(
    managed_fabric: &ManagedFabricManifestProjectionV1,
    compatibility_digest: Digest32,
) -> Vec<u8> {
    let mut wire = Vec::with_capacity(STACK_PROJECTION_BYTES);
    wire.extend_from_slice(STACK_PROJECTION_MAGIC);
    wire.extend_from_slice(&MANAGED_AGENT_STACK_PROJECTION_VERSION.to_be_bytes());
    wire.extend_from_slice(managed_fabric.canonical_wire());
    wire.extend_from_slice(compatibility_digest.as_bytes());
    wire.extend_from_slice(&MANAGED_AGENT_STACK_APPLY_REQUEST_VERSION.to_be_bytes());
    wire.extend_from_slice(&MANAGED_AGENT_STACK_PROFILE_VERSION.to_be_bytes());
    wire
}

fn build_target_execution_wire(
    projection: &ManagedAgentStackProjectionV1,
    mode: ManagedAgentStackTargetModeV1,
    fabric: &ManagedFabricTargetExecutionV1,
    agent: Option<&ManagedAgentServicePlanV1>,
) -> Result<Vec<u8>, ManagedAgentStackPlanError> {
    let fabric_length = u32::try_from(fabric.canonical_wire().len())
        .map_err(|_| ManagedAgentStackPlanError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(TARGET_EXECUTION_MAGIC);
    wire.extend_from_slice(&MANAGED_AGENT_STACK_TARGET_EXECUTION_VERSION.to_be_bytes());
    wire.extend_from_slice(projection.canonical_wire());
    wire.extend_from_slice(&MANAGED_AGENT_STACK_PROFILE_VERSION.to_be_bytes());
    wire.push(mode as u8);
    wire.push(u8::from(agent.is_some()));
    wire.extend_from_slice(&fabric_length.to_be_bytes());
    wire.extend_from_slice(fabric.canonical_wire());
    if let Some(agent) = agent {
        encode_agent_plan(&mut wire, agent)?;
    }
    Ok(wire)
}

fn encode_agent_plan(
    wire: &mut Vec<u8>,
    agent: &ManagedAgentServicePlanV1,
) -> Result<(), ManagedAgentStackPlanError> {
    let service = agent.service();
    wire.extend_from_slice(&MANAGED_SERVICE_CONTRACT_VERSION.to_be_bytes());
    wire.extend_from_slice(service.service_id().as_bytes());
    encode_budgets(wire, service.lifecycle_budgets());
    let semantic = agent.semantic_limits();
    wire.extend_from_slice(&semantic.max_sessions().to_be_bytes());
    wire.extend_from_slice(&semantic.max_turns_per_session().to_be_bytes());
    wire.extend_from_slice(&semantic.max_requests_per_session().to_be_bytes());
    wire.extend_from_slice(&semantic.max_event_batch().to_be_bytes());

    let port = agent.port();
    let submit_length = u16::try_from(port.submit_key_expression().len())
        .map_err(|_| ManagedAgentStackPlanError::InvalidLength)?;
    let control_length = u16::try_from(port.control_key_expression().len())
        .map_err(|_| ManagedAgentStackPlanError::InvalidLength)?;
    wire.extend_from_slice(port.submit_binding_id().as_bytes());
    wire.extend_from_slice(port.control_binding_id().as_bytes());
    wire.extend_from_slice(&submit_length.to_be_bytes());
    wire.extend_from_slice(&control_length.to_be_bytes());
    let limits = port.ingress_limits();
    wire.extend_from_slice(&limits.max_items().to_be_bytes());
    wire.extend_from_slice(&limits.max_bytes().to_be_bytes());
    wire.extend_from_slice(&limits.max_frame_bytes().to_be_bytes());
    wire.extend_from_slice(&limits.max_response_body_bytes().to_be_bytes());
    wire.extend_from_slice(&limits.handler_timeout_nanos().to_be_bytes());

    let provider = agent.provider();
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
    wire.extend_from_slice(port.submit_key_expression().as_bytes());
    wire.extend_from_slice(port.control_key_expression().as_bytes());
    Ok(())
}

fn decode_agent_plan(
    frame: &[u8],
) -> Result<ManagedAgentServicePlanV1, ManagedAgentStackPlanError> {
    if frame.len() < AGENT_PLAN_FIXED_BYTES {
        return Err(ManagedAgentStackPlanError::Truncated);
    }
    let mut cursor = Cursor::new(frame);
    if cursor.u16()? != MANAGED_SERVICE_CONTRACT_VERSION {
        return Err(ManagedAgentStackPlanError::UnsupportedWire);
    }
    let service_id = ManagedServiceId::from_bytes(cursor.array()?);
    let budgets = ManagedServiceLifecycleBudgetsV1::try_new(
        BoundedDuration::from_nanos(cursor.u64()?),
        BoundedDuration::from_nanos(cursor.u64()?),
        BoundedDuration::from_nanos(cursor.u64()?),
        BoundedDuration::from_nanos(cursor.u64()?),
        BoundedDuration::from_nanos(cursor.u64()?),
    )
    .map_err(|_| ManagedAgentStackPlanError::InvalidService)?;
    let service = ManagedServiceSpecV1::new(service_id, budgets);
    let semantic_limits = ManagedAgentSemanticLimitsV1::try_new(
        cursor.u16()?,
        cursor.u16()?,
        cursor.u16()?,
        cursor.u16()?,
    )?;
    let submit_binding_id = BindingId::from_bytes(cursor.array()?);
    let control_binding_id = BindingId::from_bytes(cursor.array()?);
    let submit_length = cursor.usize_u16()?;
    let control_length = cursor.usize_u16()?;
    let limits = ManagedAgentIngressLimitsV1::try_new(
        cursor.u32()?,
        cursor.u64()?,
        cursor.u32()?,
        cursor.u32()?,
        cursor.u64()?,
    )?;
    if cursor.u16()? != MANAGED_AGENT_PROVIDER_SELECTION_VERSION {
        return Err(ManagedAgentStackPlanError::UnsupportedWire);
    }
    let profile = match cursor.u8()? {
        1 => ManagedAgentProviderProfileV1::Provisioned,
        2 => ManagedAgentProviderProfileV1::DeterministicFixture,
        _ => return Err(ManagedAgentStackPlanError::InvalidProvider),
    };
    if cursor.u8()? != 0 {
        return Err(ManagedAgentStackPlanError::NonCanonicalFrame);
    }
    let provider_ref = ManagedAgentProviderRefV1::try_from_bytes(cursor.array()?)?;
    let config_digest = Digest32::from_bytes(cursor.array()?);
    let secret_present = cursor.u8()?;
    let secret_bytes: [u8; 16] = cursor.array()?;
    let provider = match (profile, secret_present) {
        (ManagedAgentProviderProfileV1::Provisioned, 1) => {
            ManagedAgentProviderSelectionV1::try_provisioned(
                provider_ref,
                config_digest,
                ManagedAgentSecretRefV1::try_from_bytes(secret_bytes)?,
            )?
        }
        (ManagedAgentProviderProfileV1::DeterministicFixture, 0)
            if bytes_are_zero(&secret_bytes) =>
        {
            ManagedAgentProviderSelectionV1::try_deterministic_fixture(provider_ref, config_digest)?
        }
        _ => return Err(ManagedAgentStackPlanError::InvalidProvider),
    };
    let submit = core::str::from_utf8(cursor.take(submit_length)?)
        .map_err(|_| ManagedAgentStackPlanError::InvalidKeyExpression)?;
    let control = core::str::from_utf8(cursor.take(control_length)?)
        .map_err(|_| ManagedAgentStackPlanError::InvalidKeyExpression)?;
    cursor.finish()?;
    ManagedAgentServicePlanV1::try_new(
        service,
        semantic_limits,
        ManagedAgentPortPlanV1::try_new(
            submit_binding_id,
            control_binding_id,
            submit,
            control,
            limits,
        )?,
        provider,
    )
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

fn validate_service(service: ManagedServiceSpecV1) -> Result<(), ManagedAgentStackPlanError> {
    if bytes_are_zero(service.service_id().as_bytes())
        || [
            service
                .lifecycle_budgets()
                .for_stage(ManagedServiceLifecycleStage::Prepare),
            service
                .lifecycle_budgets()
                .for_stage(ManagedServiceLifecycleStage::Start),
            service
                .lifecycle_budgets()
                .for_stage(ManagedServiceLifecycleStage::Readiness),
            service
                .lifecycle_budgets()
                .for_stage(ManagedServiceLifecycleStage::Drain),
            service
                .lifecycle_budgets()
                .for_stage(ManagedServiceLifecycleStage::Stop),
        ]
        .into_iter()
        .any(|budget| {
            budget.value() == 0 || budget.value() > MAX_MANAGED_AGENT_HANDLER_TIMEOUT_NANOS
        })
    {
        return Err(ManagedAgentStackPlanError::InvalidService);
    }
    Ok(())
}

fn validate_key_expression(value: &str) -> Result<(), ManagedAgentStackPlanError> {
    if value.is_empty()
        || value.len() > MAX_MANAGED_AGENT_KEY_EXPRESSION_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(ManagedAgentStackPlanError::InvalidKeyExpression);
    }
    Ok(())
}

fn build_apply_request_wire(
    envelope: &RuntimeApplyEnvelopeV2,
    slice: &ManagedAgentStackPlanSliceV1,
) -> Result<Vec<u8>, ManagedAgentStackPlanError> {
    let envelope_length = u32::try_from(envelope.canonical_wire().len())
        .map_err(|_| ManagedAgentStackPlanError::InvalidLength)?;
    let bindings_length = u32::try_from(slice.assignments.bindings.canonical_wire().len())
        .map_err(|_| ManagedAgentStackPlanError::InvalidLength)?;
    let execution_length = u32::try_from(slice.assignments.execution.canonical_wire().len())
        .map_err(|_| ManagedAgentStackPlanError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(APPLY_REQUEST_MAGIC);
    wire.extend_from_slice(&MANAGED_AGENT_STACK_APPLY_REQUEST_VERSION.to_be_bytes());
    wire.extend_from_slice(&envelope_length.to_be_bytes());
    wire.extend_from_slice(&bindings_length.to_be_bytes());
    wire.extend_from_slice(&execution_length.to_be_bytes());
    wire.extend_from_slice(envelope.canonical_wire());
    wire.extend_from_slice(slice.assignments.bindings.canonical_wire());
    wire.extend_from_slice(slice.assignments.execution.canonical_wire());
    Ok(wire)
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], ManagedAgentStackPlanError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ManagedAgentStackPlanError::FrameTooLarge)?;
        let value = self
            .frame
            .get(self.position..end)
            .ok_or(ManagedAgentStackPlanError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManagedAgentStackPlanError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ManagedAgentStackPlanError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, ManagedAgentStackPlanError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ManagedAgentStackPlanError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ManagedAgentStackPlanError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ManagedAgentStackPlanError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize_u16(&mut self) -> Result<usize, ManagedAgentStackPlanError> {
        Ok(usize::from(self.u16()?))
    }

    fn finish(self) -> Result<(), ManagedAgentStackPlanError> {
        if self.position == self.frame.len() {
            Ok(())
        } else {
            Err(ManagedAgentStackPlanError::TrailingBytes)
        }
    }
}

/// Stable construction, codec, and cross-reference failures for PXSP/PXTE6/PXAR7.
#[derive(Debug)]
pub enum ManagedAgentStackPlanError {
    InvalidShape,
    InvalidService,
    InvalidBinding,
    InvalidKeyExpression,
    InvalidIngressLimits,
    InvalidSemanticLimits,
    InvalidProvider,
    InvalidTerminalFacts,
    TerminalCorrelationMismatch,
    InvalidResponseAuthentication,
    InvalidLength,
    ProjectionMismatch,
    CompatibilityMismatch,
    CommitmentMismatch,
    TargetMismatch,
    BindingNotAllowed,
    UnsupportedWire,
    Truncated,
    TrailingBytes,
    FrameTooLarge,
    NonCanonicalFrame,
    Digest(DigestBuildError),
    Fabric(ManagedFabricPlanError),
    Provenance(crate::provenance::ProvenanceContractError),
    Apply(crate::apply::ApplyContractError),
    ReferenceContract,
    ReferenceWire,
}

impl From<DigestBuildError> for ManagedAgentStackPlanError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ManagedFabricPlanError> for ManagedAgentStackPlanError {
    fn from(value: ManagedFabricPlanError) -> Self {
        Self::Fabric(value)
    }
}

impl From<crate::provenance::ProvenanceContractError> for ManagedAgentStackPlanError {
    fn from(value: crate::provenance::ProvenanceContractError) -> Self {
        Self::Provenance(value)
    }
}

impl From<crate::apply::ApplyContractError> for ManagedAgentStackPlanError {
    fn from(value: crate::apply::ApplyContractError) -> Self {
        Self::Apply(value)
    }
}

impl From<crate::reference_assembly::ReferenceContractError> for ManagedAgentStackPlanError {
    fn from(_value: crate::reference_assembly::ReferenceContractError) -> Self {
        Self::ReferenceContract
    }
}

impl From<crate::reference_assembly::ReferenceWireError> for ManagedAgentStackPlanError {
    fn from(_value: crate::reference_assembly::ReferenceWireError) -> Self {
        Self::ReferenceWire
    }
}

impl fmt::Display for ManagedAgentStackPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "managed Agent stack plan rejected: {self:?}")
    }
}

impl std::error::Error for ManagedAgentStackPlanError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_fabric_plan::{
        ManagedFabricApplyRequestV1, ManagedFabricApplyTerminalReceiptV1,
        ManagedFabricListenEndpointV1,
    };

    const FABRIC_FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_fabric_successor_v1.json");
    const STACK_FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_agent_stack_successor_v1.json");

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("fixture contains non-hex byte"),
        }
    }

    fn fixture_hex_after_in(fixture: &str, section: &str, key: &str) -> Vec<u8> {
        let section_start = fixture
            .find(section)
            .unwrap_or_else(|| panic!("missing fixture section {section}"));
        let key_start = fixture[section_start..]
            .find(key)
            .map(|offset| section_start + offset + key.len())
            .unwrap_or_else(|| panic!("missing fixture key {key}"));
        let quote_start = fixture[key_start..]
            .find('"')
            .map(|offset| key_start + offset + 1)
            .unwrap_or_else(|| panic!("missing fixture value for {key}"));
        let quote_end = fixture[quote_start..]
            .find('"')
            .map(|offset| quote_start + offset)
            .unwrap_or_else(|| panic!("unterminated fixture value for {key}"));
        fixture.as_bytes()[quote_start..quote_end]
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn fixture_hex_after(section: &str, key: &str) -> Vec<u8> {
        fixture_hex_after_in(FABRIC_FIXTURE, section, key)
    }

    fn stack_fixture_hex_after(section: &str, key: &str) -> Vec<u8> {
        fixture_hex_after_in(STACK_FIXTURE, section, key)
    }

    fn fabric_projection() -> ManagedFabricManifestProjectionV1 {
        ManagedFabricManifestProjectionV1::decode(&fixture_hex_after(
            "\"expected\"",
            "\"projection_hex\"",
        ))
        .expect("managed Fabric projection fixture must decode")
    }

    fn budgets() -> ManagedServiceLifecycleBudgetsV1 {
        ManagedServiceLifecycleBudgetsV1::try_new(
            BoundedDuration::from_nanos(1_000_000),
            BoundedDuration::from_nanos(2_000_000),
            BoundedDuration::from_nanos(3_000_000),
            BoundedDuration::from_nanos(4_000_000),
            BoundedDuration::from_nanos(5_000_000),
        )
        .expect("fixture budgets must be valid")
    }

    fn fabric_execution() -> ManagedFabricTargetExecutionV1 {
        ManagedFabricTargetExecutionV1::try_one_managed_fabric_service(
            fabric_projection(),
            ManagedServiceSpecV1::new(ManagedServiceId::from_bytes([0x51; 16]), budgets()),
            ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447")
                .expect("fixture endpoint must be valid"),
        )
        .expect("fixture Fabric execution must be valid")
    }

    fn ingress() -> ManagedAgentIngressLimitsV1 {
        ManagedAgentIngressLimitsV1::try_new(8, 256 * 1024, 64 * 1024, 64 * 1024, 5_000_000_000)
            .expect("fixture ingress must be valid")
    }

    fn semantic_limits() -> ManagedAgentSemanticLimitsV1 {
        ManagedAgentSemanticLimitsV1::try_new(16, 64, 64, 64)
            .expect("fixture semantic limits must be valid")
    }

    fn agent_plan() -> ManagedAgentServicePlanV1 {
        let port = ManagedAgentPortPlanV1::try_new(
            BindingId::from_bytes([0x61; 16]),
            BindingId::from_bytes([0x62; 16]),
            "paraegox/agent/v1/submit",
            "paraegox/agent/v1/control",
            ingress(),
        )
        .expect("fixture port must be valid");
        let provider = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            ManagedAgentProviderRefV1::try_from_bytes([0x63; 16])
                .expect("fixture provider ref must be valid"),
            Digest32::from_bytes([0x64; 32]),
        )
        .expect("fixture provider must be valid");
        ManagedAgentServicePlanV1::try_new(
            ManagedServiceSpecV1::new(ManagedServiceId::from_bytes([0x65; 16]), budgets()),
            semantic_limits(),
            port,
            provider,
        )
        .expect("fixture Agent service must be valid")
    }

    fn stack_projection() -> ManagedAgentStackProjectionV1 {
        ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(fabric_projection())
            .expect("fixture stack projection must be valid")
    }

    fn active_execution() -> ManagedAgentStackTargetExecutionV1 {
        ManagedAgentStackTargetExecutionV1::try_fabric_and_agent(
            stack_projection(),
            fabric_execution(),
            agent_plan(),
        )
        .expect("fixture stack must be valid")
    }

    fn stack_request() -> ManagedAgentStackApplyRequestV1 {
        let predecessor_wire =
            fixture_hex_after("\"one_managed_fabric_service\"", "\"outer_v6_hex\"");
        let predecessor = ManagedFabricApplyRequestV1::decode(&predecessor_wire)
            .expect("predecessor fixture must decode");
        ManagedAgentStackApplyRequestDraftV1::try_new(
            active_execution(),
            predecessor.provenance(),
            predecessor.control_commitment().control().clone(),
            predecessor.temporal(),
            predecessor.expected_runtime_store_instance_id(),
            predecessor.authentication().claim().clone(),
        )
        .expect("stack request draft must build")
        .finalize(predecessor.authentication().signature())
        .expect("stack request must finalize")
    }

    #[test]
    fn target_scoped_agent_port_derives_exact_distinct_bounded_lanes() {
        let target = RuntimeHostId::from_bytes([0x11; 16]);
        let service_id = ManagedServiceId::from_bytes([0x22; 16]);
        let first = ManagedAgentPortPlanV1::try_new_target_scoped(target, service_id, ingress())
            .expect("target-scoped port");
        let second = ManagedAgentPortPlanV1::try_new_target_scoped(target, service_id, ingress())
            .expect("deterministic target-scoped port");
        assert_eq!(first, second);
        assert_eq!(
            first.submit_binding_id().as_bytes(),
            &[
                0x57, 0x22, 0xf7, 0xae, 0xdf, 0xf8, 0x94, 0x82, 0x53, 0x5d, 0xe7, 0x7a, 0x0d, 0x37,
                0x9b, 0x58,
            ]
        );
        assert_eq!(
            first.control_binding_id().as_bytes(),
            &[
                0x17, 0x27, 0x45, 0xe5, 0xa0, 0x41, 0xec, 0x64, 0x81, 0x7d, 0x41, 0xde, 0x25, 0x2d,
                0x0a, 0xe0,
            ]
        );
        assert_ne!(first.submit_binding_id(), first.control_binding_id());
        assert_eq!(
            first.submit_key_expression(),
            "paraegox/agent/v1/11111111111111111111111111111111/22222222222222222222222222222222/submit"
        );
        assert_eq!(
            first.control_key_expression(),
            "paraegox/agent/v1/11111111111111111111111111111111/22222222222222222222222222222222/control"
        );
        assert_eq!(first.submit_key_expression().len(), 90);
        assert_eq!(first.control_key_expression().len(), 91);
        assert!(first.submit_key_expression().len() <= MAX_MANAGED_AGENT_KEY_EXPRESSION_BYTES);
        assert!(first.control_key_expression().len() <= MAX_MANAGED_AGENT_KEY_EXPRESSION_BYTES);
        assert!(matches!(
            ManagedAgentPortPlanV1::try_new_target_scoped(
                RuntimeHostId::from_bytes([0; 16]),
                service_id,
                ingress(),
            ),
            Err(ManagedAgentStackPlanError::InvalidBinding)
        ));
        assert!(matches!(
            ManagedAgentPortPlanV1::try_new_target_scoped(
                target,
                ManagedServiceId::from_bytes([0; 16]),
                ingress(),
            ),
            Err(ManagedAgentStackPlanError::InvalidBinding)
        ));
    }

    #[test]
    fn fixed_projection_active_and_empty_round_trip_without_predecessor_fallback() {
        let projection = stack_projection();
        assert_eq!(&projection.canonical_wire()[..6], b"PXSP\0\x01");
        assert_eq!(
            ManagedAgentStackProjectionV1::decode(projection.canonical_wire())
                .expect("projection must round trip"),
            projection
        );

        let active = active_execution();
        let decoded = ManagedAgentStackTargetExecutionV1::decode(active.canonical_wire())
            .expect("active stack must round trip");
        assert_eq!(decoded, active);
        assert_eq!(
            decoded.mode(),
            ManagedAgentStackTargetModeV1::FabricAndAgent
        );
        assert_eq!(
            decoded.fabric().mode(),
            ManagedFabricTargetModeV1::OneManagedFabricService
        );
        assert_eq!(
            decoded
                .agent()
                .expect("active stack has Agent")
                .port()
                .submit_binding_id(),
            BindingId::from_bytes([0x61; 16])
        );
        assert!(
            ManagedAgentStackTargetExecutionV1::decode(fabric_execution().canonical_wire())
                .is_err(),
            "PXTE v6 must not reinterpret PXTE v5"
        );

        let empty = ManagedAgentStackTargetExecutionV1::try_empty_deactivate(stack_projection())
            .expect("empty stack must build");
        assert_eq!(empty.mode(), ManagedAgentStackTargetModeV1::EmptyDeactivate);
        assert_eq!(
            empty.fabric().mode(),
            ManagedFabricTargetModeV1::EmptyDeactivate
        );
        assert!(empty.agent().is_none());
        assert_eq!(
            ManagedAgentStackTargetExecutionV1::decode(empty.canonical_wire())
                .expect("empty stack must round trip"),
            empty
        );
    }

    #[test]
    fn two_lanes_ingress_and_provider_selection_fail_closed_before_wire() {
        assert!(matches!(
            ManagedAgentPortPlanV1::try_new(
                BindingId::from_bytes([0x61; 16]),
                BindingId::from_bytes([0x61; 16]),
                "paraegox/agent/v1/submit",
                "paraegox/agent/v1/control",
                ingress(),
            ),
            Err(ManagedAgentStackPlanError::InvalidBinding)
        ));
        assert!(matches!(
            ManagedAgentPortPlanV1::try_new(
                BindingId::from_bytes([0x61; 16]),
                BindingId::from_bytes([0x62; 16]),
                "paraegox/*/submit",
                "paraegox/agent/v1/control",
                ingress(),
            ),
            Err(ManagedAgentStackPlanError::InvalidKeyExpression)
        ));
        assert!(matches!(
            ManagedAgentIngressLimitsV1::try_new(8, 1, 2, 0, 1),
            Err(ManagedAgentStackPlanError::InvalidIngressLimits)
        ));
        assert!(
            ManagedAgentIngressLimitsV1::try_new(
                1,
                u64::from(MIN_MANAGED_AGENT_FRAME_BYTES),
                MIN_MANAGED_AGENT_FRAME_BYTES,
                MIN_MANAGED_AGENT_RESPONSE_BODY_BYTES,
                1,
            )
            .is_ok()
        );
        assert!(matches!(
            ManagedAgentIngressLimitsV1::try_new(
                1,
                u64::from(MIN_MANAGED_AGENT_FRAME_BYTES),
                MIN_MANAGED_AGENT_FRAME_BYTES - 1,
                MIN_MANAGED_AGENT_RESPONSE_BODY_BYTES,
                1,
            ),
            Err(ManagedAgentStackPlanError::InvalidIngressLimits)
        ));
        assert!(matches!(
            ManagedAgentIngressLimitsV1::try_new(
                1,
                u64::from(MIN_MANAGED_AGENT_FRAME_BYTES),
                MIN_MANAGED_AGENT_FRAME_BYTES,
                MIN_MANAGED_AGENT_RESPONSE_BODY_BYTES - 1,
                1,
            ),
            Err(ManagedAgentStackPlanError::InvalidIngressLimits)
        ));
        assert!(matches!(
            ManagedAgentProviderSelectionV1::try_deterministic_fixture(
                ManagedAgentProviderRefV1::try_from_bytes([0x63; 16]).expect("provider ref"),
                Digest32::from_bytes([0; 32]),
            ),
            Err(ManagedAgentStackPlanError::InvalidProvider)
        ));

        let fabric = fabric_execution();
        let duplicate_service = ManagedAgentServicePlanV1::try_new(
            fabric.service().expect("active Fabric service"),
            semantic_limits(),
            agent_plan().port().clone(),
            agent_plan().provider(),
        )
        .expect("Agent shape is independently valid");
        assert!(matches!(
            ManagedAgentStackTargetExecutionV1::try_fabric_and_agent(
                stack_projection(),
                fabric,
                duplicate_service,
            ),
            Err(ManagedAgentStackPlanError::InvalidService)
        ));
    }

    #[test]
    fn pxar7_round_trip_binds_stack_slice_and_rejects_pxar6() {
        let predecessor_wire =
            fixture_hex_after("\"one_managed_fabric_service\"", "\"outer_v6_hex\"");
        let predecessor = ManagedFabricApplyRequestV1::decode(&predecessor_wire)
            .expect("predecessor fixture must decode");
        let request = stack_request();
        assert!(
            !request
                .signing_transcript()
                .expect("transcript")
                .as_bytes()
                .is_empty()
        );
        assert_eq!(&request.canonical_wire()[..6], b"PXAR\0\x07");
        let decoded = ManagedAgentStackApplyRequestV1::decode(request.canonical_wire())
            .expect("stack request must round trip");
        assert_eq!(decoded, request);
        assert_eq!(decoded.target_execution(), &active_execution());
        decoded
            .validate_expected_store(predecessor.expected_runtime_store_instance_id())
            .expect("exact store must validate");
        let restored = verify_managed_agent_stack_durable_slice_v1(
            decoded.canonical_slice_wire(),
            decoded.target(),
            decoded.provenance(),
            decoded.target_slice_digest(),
            &stack_projection(),
        )
        .expect("durable stack slice must restore");
        assert_eq!(restored, active_execution());
        assert!(ManagedAgentStackApplyRequestV1::decode(&predecessor_wire).is_err());
        assert!(ManagedFabricApplyRequestV1::decode(request.canonical_wire()).is_err());
    }

    #[test]
    fn pxst_reports_two_generations_dependency_readiness_and_exact_binding_census() {
        let request = stack_request();
        let channel = ReferenceChannelBindingV1::try_new(
            request.target(),
            PrincipalRef::from_bytes([0x71; 16]),
            Digest32::from_bytes([0x72; 32]),
            Digest32::from_bytes([0x73; 32]),
        )
        .expect("fixture channel must be valid");
        let state = ManagedAgentStackTerminalStateV1::try_new(
            ManagedAgentStackTerminalOutcomeV1::ActiveReady,
            ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
            ManagedAgentStackTerminalHeadV1::CommittedIncoming,
            Some(ManagedServiceGeneration::try_new(7).expect("Fabric generation")),
            Some(ManagedServiceGeneration::try_new(8).expect("Agent generation")),
        )
        .expect("active terminal state must be valid");
        let evidence = ManagedAgentStackTerminalEvidenceV1::try_new(
            ManagedAgentStackTerminalEvidenceFieldsV1 {
                physical_binding_census: 2,
                census_complete: true,
                fabric_ready: true,
                agent_ready: true,
                dependency_satisfied: true,
                exact_zero: false,
                quarantined: false,
                resource_census_digest: Digest32::from_bytes([0x74; 32]),
                raw_outcome_digest: Digest32::from_bytes([0x75; 32]),
                completion_runtime_host_epoch: 9,
                completion_snapshot_sequence: 11,
                selection_clock_generation: request.temporal().target_clock_generation(),
                selection_observed_at_nanos: 13,
            },
        )
        .expect("active evidence must be valid");
        let facts = ManagedAgentStackTerminalFactsV1::try_new(&request, state, evidence)
            .expect("active facts must correlate");
        let auth = ManagedAgentStackTerminalAuthClaimV1::try_new(
            channel,
            ApplyAuthKeyRef::from_bytes([0x76; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("terminal auth must be valid");
        let draft =
            ManagedAgentStackTerminalReceiptDraftV1::try_new(&request, facts, channel, auth)
                .expect("terminal draft must be valid");
        assert!(
            !draft
                .signing_transcript()
                .expect("transcript")
                .as_bytes()
                .is_empty()
        );
        let receipt = draft.finalize(&[0x77; 64]).expect("terminal must finalize");
        assert_eq!(&receipt.canonical_wire()[..6], b"PXST\0\x01");
        let decoded = ManagedAgentStackTerminalReceiptV1::decode(receipt.canonical_wire())
            .expect("PXST must round trip");
        assert_eq!(decoded, receipt);
        let validated = decoded
            .validate_against_request(&request, channel)
            .expect("PXST must correlate");
        assert_eq!(
            validated
                .state()
                .fabric_generation()
                .map(ManagedServiceGeneration::value),
            Some(7)
        );
        assert_eq!(
            validated
                .state()
                .agent_generation()
                .map(ManagedServiceGeneration::value),
            Some(8)
        );
        assert_eq!(validated.evidence().fields().physical_binding_census, 2);
        assert!(validated.evidence().fields().dependency_satisfied);
        assert!(ManagedFabricApplyTerminalReceiptV1::decode(receipt.canonical_wire()).is_err());

        let invalid = ManagedAgentStackTerminalEvidenceV1::try_new(
            ManagedAgentStackTerminalEvidenceFieldsV1 {
                physical_binding_census: 1,
                ..evidence.fields()
            },
        )
        .expect("generic census may be structurally valid before outcome correlation");
        assert!(matches!(
            ManagedAgentStackTerminalFactsV1::try_new(&request, state, invalid),
            Err(ManagedAgentStackPlanError::InvalidTerminalFacts)
        ));
    }

    #[test]
    fn python_golden_is_consumed_by_rust_for_pxsp_pxte6_pxar7_and_pxst() {
        let expected_compatibility =
            stack_fixture_hex_after("\"expected\"", "\"compatibility_digest_hex\"");
        assert_eq!(
            managed_agent_stack_compatibility_digest_v1()
                .expect("compatibility digest must build")
                .as_bytes()
                .as_slice(),
            expected_compatibility.as_slice()
        );

        let projection_wire = stack_fixture_hex_after("\"expected\"", "\"projection_pxsp_hex\"");
        let projection = ManagedAgentStackProjectionV1::decode(&projection_wire)
            .expect("Python PXSP golden must decode in Rust");
        assert_eq!(projection.canonical_wire(), projection_wire);
        assert_eq!(
            projection.compatibility_digest().as_bytes().as_slice(),
            expected_compatibility.as_slice()
        );

        for section in ["\"fabric_and_agent\"", "\"empty_deactivate\""] {
            let execution_wire = stack_fixture_hex_after(section, "\"pxte_v6_hex\"");
            let execution = ManagedAgentStackTargetExecutionV1::decode(&execution_wire)
                .expect("Python PXTE v6 golden must decode in Rust");
            assert_eq!(execution.canonical_wire(), execution_wire);
            assert_eq!(
                execution.execution_digest().as_bytes().as_slice(),
                stack_fixture_hex_after(section, "\"pxte_v6_digest_hex\"").as_slice()
            );

            let request_wire = stack_fixture_hex_after(section, "\"outer_v7_hex\"");
            let request = ManagedAgentStackApplyRequestV1::decode(&request_wire)
                .expect("Python PXAR v7 golden must decode in Rust");
            assert_eq!(request.canonical_wire(), request_wire);
            assert_eq!(request.target_execution(), &execution);
            assert_eq!(
                request.assignment_digest().value().as_bytes().as_slice(),
                stack_fixture_hex_after(section, "\"assignment_v7_digest_hex\"").as_slice()
            );
            assert_eq!(
                request.envelope_request_digest().as_bytes().as_slice(),
                stack_fixture_hex_after(section, "\"request_digest_hex\"").as_slice()
            );

            let receipt_wire = stack_fixture_hex_after(section, "\"wire_hex\"");
            let receipt = ManagedAgentStackTerminalReceiptV1::decode(&receipt_wire)
                .expect("Python PXST golden must decode in Rust");
            assert_eq!(receipt.canonical_wire(), receipt_wire);
            assert_eq!(
                receipt.receipt_digest().as_bytes().as_slice(),
                stack_fixture_hex_after(section, "\"receipt_digest_hex\"").as_slice()
            );
        }
    }
}
