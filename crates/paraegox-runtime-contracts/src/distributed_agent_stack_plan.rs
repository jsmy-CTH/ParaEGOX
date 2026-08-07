//! Additive two-host desired-state contract for the fixed Fabric→Agent stack.
//!
//! PXTE v5/v6 and PXAR v6/v7 remain frozen. This module defines strict PXTE
//! v7/PXAR v8 successors that retain one exact PXTE v6 fixed stack and add one
//! bounded, explicit Fabric topology for a single RuntimeHost: the predecessor
//! loopback TCP listener, one non-loopback IPv4 TLS-over-TCP listener, and one
//! to eight explicit non-loopback TLS-over-TCP peer connect endpoints. PXAR v8
//! itself also remains byte-frozen: the additive PXRC v1 carrier wrapper binds
//! its exact bytes to one Runtime-owned restricted control endpoint before a
//! Runtime is allowed to hand the inner request to its mutation path.
//!
//! Those endpoints configure one FabricService-owned Zenoh Session. They are
//! not PortBinding routes, do not create local-plus-wire double delivery, and
//! do not authorize transport fallback. PXTA remains exact-empty and the
//! retained PXTE v6 value remains the only fixed Fabric→Agent binding shape.
//!
//! Authentication fields are desired requirements only. Credential, trust,
//! and peer-identity values are opaque owner-resolved references, never secret
//! bytes. A digest only correlates an observation with desired state; it never
//! authenticates a transport peer. [`DistributedFabricObservedTransportProofV1`]
//! is consequently an unsigned canonical payload. It becomes evidence only
//! when an actual Fabric owner binds it into an authenticated terminal or
//! Inspection record. No TLS transport adapter is implemented by this crate.
//!
//! PXRC and PXDS v2 are canonical signed-message contracts, not a Zenoh client,
//! key resolver, signature implementation, discovery owner, or admission
//! shortcut. The Runtime must authenticate PXRC before mutation and must still
//! execute every existing PXAR v8 admission check. PXDS v1 stays a separate,
//! frozen local-channel receipt and cross-rejects the restricted v2 successor.
//!
//! This successor is not a general service graph, placement engine, generic
//! bus/backend, discovery protocol, credential issuer, or reconnect owner.

use core::fmt;
use std::net::Ipv4Addr;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::ClockGeneration;

use crate::apply::{ApplyOperationId, RuntimeApplyControl, RuntimeApplyControlCommitment};
use crate::assignment::TargetAssignments;
use crate::managed_agent_stack_plan::{
    MANAGED_AGENT_STACK_PROJECTION_BYTES, MANAGED_AGENT_STACK_TARGET_EXECUTION_VERSION,
    MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES, ManagedAgentStackPlanError,
    ManagedAgentStackProjectionV1, ManagedAgentStackTargetExecutionV1,
    ManagedAgentStackTargetModeV1,
};
use crate::managed_fabric_plan::{
    MANAGED_FABRIC_APPLY_ENVELOPE_VERSION, MANAGED_FABRIC_APPLY_SIGNING_TRANSCRIPT_VERSION,
    ManagedFabricListenEndpointV1,
};
use crate::managed_service::ManagedServiceGeneration;
use crate::provenance::{
    PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, TargetAssignmentDigest,
    TargetSliceDigest,
};
use crate::reference_assembly::{
    ApplyRequestSigningTranscriptV2, MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES, RuntimeApplyEnvelopeV2,
    RuntimeApplyEnvelopeV2Draft, RuntimeStoreInstanceId,
};
use crate::reference_control::ReferenceChannelBindingV1;
use crate::temporal::ApplyTemporalConstraint;
use crate::wire::{
    ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim, ApplyRequestAuthentication,
};

const PROJECTION_MAGIC: &[u8; 4] = b"PXDP";
const TARGET_EXECUTION_MAGIC: &[u8; 4] = b"PXTE";
const APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const TOPOLOGY_MAGIC: &[u8; 4] = b"PXDT";
const TRANSPORT_PROOF_MAGIC: &[u8; 4] = b"PXTP";
const TERMINAL_RECEIPT_MAGIC: &[u8; 4] = b"PXDS";
const TERMINAL_RECEIPT_SIGNING_MAGIC: &[u8] = b"ParaEGOX\0distributed-agent-stack-terminal-signing";
const RESTRICTED_CARRIER_BINDING_MAGIC: &[u8; 4] = b"PXCB";
const RESTRICTED_TRANSPORT_PROFILE_MAGIC: &[u8; 4] = b"PXRP";
const RESTRICTED_APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXRC";
const RESTRICTED_APPLY_REQUEST_SIGNING_MAGIC: &[u8] =
    b"ParaEGOX\0distributed-agent-stack-restricted-carrier-signing";
const RESTRICTED_TERMINAL_RECEIPT_SIGNING_MAGIC: &[u8] =
    b"ParaEGOX\0distributed-agent-stack-restricted-terminal-signing";
const EMPTY_PXTA: [u8; 10] = [b'P', b'X', b'T', b'A', 0, 1, 0, 0, 0, 0];
const APPLY_REQUEST_HEADER_BYTES: usize = 18;
const PROJECTION_BYTES: usize = 4 + 2 + MANAGED_AGENT_STACK_PROJECTION_BYTES + 32 + 2 + 2;
const TARGET_EXECUTION_FIXED_BYTES: usize = 4 + 2 + PROJECTION_BYTES + 2 + 1 + 1 + 4 + 4;
const TOPOLOGY_FIXED_BYTES: usize = 4 + 2 + 2 + 2 + 2 + 2;
const PEER_FIXED_BYTES: usize = 16 + 2 + 2 + (4 * 16);
const TRANSPORT_PROOF_BYTES: usize = 4 + 2 + (6 * 16) + 2 + 32 + 8;
const MAX_BASE_LOOPBACK_ENDPOINT_BYTES: usize = 19;
const TLS_PREFIX: &str = "tls/";
const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;
const RESTRICTED_ZENOH_QUERY_CARRIER_KIND: u16 = 1;
const RESTRICTED_ZENOH_TLS_QUERY_PROFILE_KIND: u16 = 1;
const RESTRICTED_CARRIER_BINDING_FIXED_BYTES: usize =
    4 + 2 + 2 + 2 + 2 + (4 * 16) + 8 + 16 + 32 + 16 + 32 + 16 + 32;
const RESTRICTED_TRANSPORT_PROFILE_FIXED_BYTES: usize = 4 + 2 + 2 + 2 + 2 + 2 + (8 * 16) + 8 + 8;
const RESTRICTED_APPLY_REQUEST_FIXED_BYTES: usize = 4 + 2 + 2 + 4 + 32 + 32;
const RESTRICTED_TERMINAL_RECEIPT_V2_TRAILER_FIXED_BYTES: usize = 32 + 32 + 2 + 2;

const COMPATIBILITY_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.compiled-distributed-agent-stack-compatibility.sha256.v1";
const TARGET_EXECUTION_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.target-execution.sha256.v7";
const TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.target-plan-assignments.sha256.v8";
const PEER_REQUIREMENT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.fabric.distributed-peer-auth-requirement.sha256.v1";
const TERMINAL_TOPOLOGY_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-agent-stack-terminal.topology.sha256.v1";
const TERMINAL_REMOTE_OBSERVATION_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-agent-stack-terminal.remote-observation.sha256.v1";
const TERMINAL_INSTALLED_BINDING_SET_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-agent-stack-terminal.installed-binding-set.sha256.v1";
const TERMINAL_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-agent-stack-terminal.receipt.sha256.v1";
const RESTRICTED_CARRIER_BINDING_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.restricted-apply-carrier-binding.sha256.v1";
const RESTRICTED_TRANSPORT_PROFILE_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.restricted-apply-transport-profile.sha256.v1";
const DISTRIBUTED_APPLY_REQUEST_WIRE_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-agent-stack.pxar8-wire.sha256.v1";
const RESTRICTED_APPLY_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-agent-stack.pxrc.sha256.v1";
const RESTRICTED_TERMINAL_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-agent-stack-terminal.receipt.sha256.v2";

/// Version of the installation projection for the distributed fixed stack.
pub const DISTRIBUTED_AGENT_STACK_PROJECTION_VERSION: u16 = 1;
/// Strict apply-request successor version carried by PXAR.
pub const DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_VERSION: u16 = 8;
/// Strict target-execution successor version carried by PXTE.
pub const DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_VERSION: u16 = 7;
/// Fixed distributed Fabric→Agent desired profile version.
pub const DISTRIBUTED_AGENT_STACK_PROFILE_VERSION: u16 = 1;
/// Exact topology value version carried by PXDT.
pub const DISTRIBUTED_FABRIC_TOPOLOGY_VERSION: u16 = 1;
/// Desired peer-authentication requirement version.
pub const DISTRIBUTED_FABRIC_AUTHENTICATION_REQUIREMENT_VERSION: u16 = 1;
/// Canonical observed transport-proof payload version.
pub const DISTRIBUTED_FABRIC_TRANSPORT_PROOF_VERSION: u16 = 1;
/// Signed RuntimeHost terminal Receipt version carried by PXDS.
pub const DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_VERSION: u16 = 1;
/// Domain-separated PXDS signing-transcript version.
pub const DISTRIBUTED_AGENT_STACK_TERMINAL_SIGNING_VERSION: u16 = 1;
/// Canonical restricted Runtime apply-carrier binding version.
pub const RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_VERSION: u16 = 1;
/// Canonical restricted Runtime apply transport-profile version.
pub const RESTRICTED_RUNTIME_APPLY_TRANSPORT_PROFILE_VERSION: u16 = 1;
/// Controller-signed PXRC wrapper version. PXAR v8 remains its exact inner value.
pub const DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_VERSION: u16 = 1;
/// Restricted-carrier Runtime terminal Receipt version carried by PXDS.
pub const DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_VERSION: u16 = 2;
/// Domain-separated restricted PXDS signing-transcript version.
pub const DISTRIBUTED_AGENT_STACK_TERMINAL_SIGNING_V2_VERSION: u16 = 2;
/// Maximum remote peers admitted for one RuntimeHost target.
pub const MAX_DISTRIBUTED_FABRIC_PEERS: usize = 8;
/// Maximum bytes in one canonical non-loopback IPv4 TLS-over-TCP endpoint.
pub const MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES: usize = 25;
/// Exact fixed projection width.
pub const DISTRIBUTED_AGENT_STACK_PROJECTION_BYTES: usize = PROJECTION_BYTES;
/// Maximum canonical topology size.
pub const MAX_DISTRIBUTED_FABRIC_TOPOLOGY_BYTES: usize = TOPOLOGY_FIXED_BYTES
    + MAX_BASE_LOOPBACK_ENDPOINT_BYTES
    + MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES
    + (MAX_DISTRIBUTED_FABRIC_PEERS * (PEER_FIXED_BYTES + MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES));
/// Maximum canonical PXTE v7 size.
pub const MAX_DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_BYTES: usize = TARGET_EXECUTION_FIXED_BYTES
    + MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES
    + MAX_DISTRIBUTED_FABRIC_TOPOLOGY_BYTES;
/// Maximum canonical durable `PXTA-zero || PXTE-v7` size.
pub const MAX_DISTRIBUTED_AGENT_STACK_PLAN_SLICE_BYTES: usize =
    EMPTY_PXTA.len() + MAX_DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_BYTES;
/// Maximum canonical PXAR v8 size.
pub const MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES: usize = APPLY_REQUEST_HEADER_BYTES
    + MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES
    + EMPTY_PXTA.len()
    + MAX_DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_BYTES;
/// Exact width of the unsigned PXTP v1 observation payload.
pub const DISTRIBUTED_FABRIC_TRANSPORT_PROOF_BYTES: usize = TRANSPORT_PROOF_BYTES;
/// Maximum canonical PXDS receipt bytes.
pub const MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_BYTES: usize = 8 * 1024;
/// Maximum opaque RuntimeHost signature retained by PXDS.
pub const MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_SIGNATURE_BYTES: usize = ED25519_SIGNATURE_BYTES;
/// Maximum canonical restricted Zenoh query route width.
pub const MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES: usize = 255;
/// Maximum one-shot restricted Runtime apply operation duration budget.
pub const MAX_RESTRICTED_RUNTIME_APPLY_OPERATION_TIMEOUT_NANOS: u64 = 30_000_000_000;
/// Maximum canonical PXRP transport-profile bytes.
pub const MAX_RESTRICTED_RUNTIME_APPLY_TRANSPORT_PROFILE_BYTES: usize =
    RESTRICTED_TRANSPORT_PROFILE_FIXED_BYTES
        + MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES
        + MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES;
/// Maximum canonical PXCB carrier-binding bytes.
pub const MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES: usize =
    RESTRICTED_CARRIER_BINDING_FIXED_BYTES + MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES;
/// Maximum canonical Controller-signed PXRC v1 bytes.
pub const MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES: usize =
    RESTRICTED_APPLY_REQUEST_FIXED_BYTES
        + MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
        + MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES
        + 2
        + ED25519_SIGNATURE_BYTES;
/// Maximum canonical restricted PXDS v2 Receipt bytes.
pub const MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES: usize =
    MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_BYTES
        + RESTRICTED_TERMINAL_RECEIPT_V2_TRAILER_FIXED_BYTES
        + MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES;

macro_rules! nonzero_ref {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates one nonzero opaque owner-resolved reference.
            pub const fn try_from_bytes(
                bytes: [u8; 16],
            ) -> Result<Self, DistributedAgentStackPlanError> {
                if bytes_are_zero(&bytes) {
                    return Err(DistributedAgentStackPlanError::InvalidAuthenticationRequirement);
                }
                Ok(Self(bytes))
            }

            /// Returns the exact opaque reference bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

nonzero_ref!(
    DistributedFabricTrustDomainRefV1,
    "Opaque identity of the enrolled trust domain; it is not a certificate or digest."
);
nonzero_ref!(
    DistributedFabricCredentialRefV1,
    "Opaque reference resolved by the credential owner; it never contains secret material."
);
nonzero_ref!(
    DistributedFabricTrustAnchorRefV1,
    "Opaque reference to the trust-anchor set resolved by the credential owner."
);
nonzero_ref!(
    DistributedFabricPeerIdentityRefV1,
    "Opaque enrolled identity expected from one authenticated remote peer."
);
nonzero_ref!(
    DistributedFabricSessionEpochV1,
    "Opaque nonzero epoch of one Fabric-owner-observed transport session."
);
nonzero_ref!(
    DistributedFabricTransportEvidenceRefV1,
    "Opaque reference to Fabric-owner transport evidence; not a self-authenticating digest."
);

/// Strict canonical non-loopback unicast IPv4 TLS-over-TCP endpoint.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DistributedFabricTlsEndpointV1(Box<str>);

impl DistributedFabricTlsEndpointV1 {
    /// Accepts only `tls/A.B.C.D:PORT` in the address and port's shortest form.
    pub fn try_new(value: &str) -> Result<Self, DistributedAgentStackPlanError> {
        if value.is_empty() || value.len() > MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES {
            return Err(DistributedAgentStackPlanError::InvalidEndpoint);
        }
        let Some(authority) = value.strip_prefix(TLS_PREFIX) else {
            return Err(DistributedAgentStackPlanError::InvalidEndpoint);
        };
        let Some((address_text, port_text)) = authority.split_once(':') else {
            return Err(DistributedAgentStackPlanError::InvalidEndpoint);
        };
        if address_text.is_empty()
            || port_text.is_empty()
            || authority.matches(':').count() != 1
            || port_text.len() > 5
            || !port_text.bytes().all(|byte| byte.is_ascii_digit())
            || (port_text.len() > 1 && port_text.starts_with('0'))
        {
            return Err(DistributedAgentStackPlanError::InvalidEndpoint);
        }
        let address = address_text
            .parse::<Ipv4Addr>()
            .map_err(|_| DistributedAgentStackPlanError::InvalidEndpoint)?;
        let port = port_text
            .parse::<u16>()
            .map_err(|_| DistributedAgentStackPlanError::InvalidEndpoint)?;
        if port == 0
            || address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || address == Ipv4Addr::BROADCAST
            || format!("{TLS_PREFIX}{address}:{port}") != value
        {
            return Err(DistributedAgentStackPlanError::InvalidEndpoint);
        }
        Ok(Self(value.into()))
    }

    /// Returns exact canonical endpoint text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Inputs for one exact restricted Controller-to-Runtime transport profile.
///
/// Credential and trust values are opaque owner-resolved references. This
/// contract never carries a certificate, private key, filesystem path, or
/// bearer secret.
#[derive(Clone, Copy, Debug)]
pub struct RestrictedRuntimeApplyTransportProfileFieldsV1<'a> {
    /// RuntimeHost that owns the selected listener.
    pub target: RuntimeHostId,
    /// Opaque Runtime-owned endpoint identity also published through Node facts.
    pub endpoint_ref: [u8; 16],
    /// Nonzero generation of that exact endpoint identity.
    pub endpoint_generation: u64,
    /// Canonical non-loopback IPv4 TLS listener locator.
    pub tls_listener_locator: &'a str,
    /// Sole concrete restricted Zenoh query route.
    pub route: &'a str,
    /// Enrolled trust domain shared by both mTLS roles.
    pub trust_domain_ref: DistributedFabricTrustDomainRefV1,
    /// Trust-anchor set shared by both mTLS roles.
    pub trust_anchor_ref: DistributedFabricTrustAnchorRefV1,
    /// Opaque credential requirement for the Controller connector role.
    pub controller_connector_credential_ref: DistributedFabricCredentialRefV1,
    /// Distinct opaque credential requirement for the Runtime listener role.
    pub runtime_listener_credential_ref: DistributedFabricCredentialRefV1,
    /// Certificate principal admitted for the Controller connector.
    pub controller_principal: PrincipalRef,
    /// Certificate principal admitted for the Runtime listener.
    pub runtime_principal: PrincipalRef,
    /// Duration budget converted once at operation start to one monotonic
    /// absolute deadline; it is neither a wall-clock timestamp nor a per-step
    /// timeout that may be reset between preflight, query, and response.
    pub operation_timeout_nanos: u64,
}

/// Exact bounded restricted Runtime apply transport profile.
///
/// PXRP v1 is additive: its digest can satisfy the opaque profile commitment
/// already carried by PXCB v1 without changing the frozen Node endpoint
/// descriptor or PXCB bytes. Its fixed kind means one mTLS Controller connector
/// targeting the same canonical locator served by one Runtime listener, one
/// exact query route, certificate Common Names in the deterministic
/// `paraegox-principal-<lowercase-principal-hex>` form, disabled discovery, and
/// no protocol fallback. Each side derives its one monotonic absolute deadline
/// once from the shared duration budget. The value is only a non-secret
/// requirement: it does not resolve or prove credential selection, open a
/// session, authenticate a peer, or authorize one apply attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictedRuntimeApplyTransportProfileV1 {
    target: RuntimeHostId,
    endpoint_ref: [u8; 16],
    endpoint_generation: u64,
    tls_listener_locator: DistributedFabricTlsEndpointV1,
    route: Box<str>,
    trust_domain_ref: DistributedFabricTrustDomainRefV1,
    trust_anchor_ref: DistributedFabricTrustAnchorRefV1,
    controller_connector_credential_ref: DistributedFabricCredentialRefV1,
    runtime_listener_credential_ref: DistributedFabricCredentialRefV1,
    controller_principal: PrincipalRef,
    runtime_principal: PrincipalRef,
    operation_timeout_nanos: u64,
    canonical_wire: Box<[u8]>,
    profile_digest: Digest32,
}

impl RestrictedRuntimeApplyTransportProfileV1 {
    /// Constructs the fixed mTLS, connector/listener-role-separated profile.
    pub fn try_new(
        fields: RestrictedRuntimeApplyTransportProfileFieldsV1<'_>,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        let tls_listener_locator =
            DistributedFabricTlsEndpointV1::try_new(fields.tls_listener_locator)
                .map_err(|_| DistributedAgentStackPlanError::InvalidTransportProfile)?;
        validate_restricted_runtime_apply_route(fields.route)
            .map_err(|_| DistributedAgentStackPlanError::InvalidTransportProfile)?;
        if bytes_are_zero(fields.target.as_bytes())
            || bytes_are_zero(&fields.endpoint_ref)
            || fields.endpoint_generation == 0
            || bytes_are_zero(fields.controller_principal.as_bytes())
            || bytes_are_zero(fields.runtime_principal.as_bytes())
            || fields.controller_principal == fields.runtime_principal
            || fields.controller_connector_credential_ref == fields.runtime_listener_credential_ref
            || fields.operation_timeout_nanos == 0
            || fields.operation_timeout_nanos > MAX_RESTRICTED_RUNTIME_APPLY_OPERATION_TIMEOUT_NANOS
        {
            return Err(DistributedAgentStackPlanError::InvalidTransportProfile);
        }
        let canonical_wire = build_restricted_transport_profile_wire(fields)?;
        if canonical_wire.len() > MAX_RESTRICTED_RUNTIME_APPLY_TRANSPORT_PROFILE_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        let profile_digest =
            digest_wire(RESTRICTED_TRANSPORT_PROFILE_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            target: fields.target,
            endpoint_ref: fields.endpoint_ref,
            endpoint_generation: fields.endpoint_generation,
            tls_listener_locator,
            route: fields.route.into(),
            trust_domain_ref: fields.trust_domain_ref,
            trust_anchor_ref: fields.trust_anchor_ref,
            controller_connector_credential_ref: fields.controller_connector_credential_ref,
            runtime_listener_credential_ref: fields.runtime_listener_credential_ref,
            controller_principal: fields.controller_principal,
            runtime_principal: fields.runtime_principal,
            operation_timeout_nanos: fields.operation_timeout_nanos,
            canonical_wire: canonical_wire.into_boxed_slice(),
            profile_digest,
        })
    }

    /// Strictly decodes exactly one canonical PXRP v1 value.
    pub fn decode(frame: &[u8]) -> Result<Self, DistributedAgentStackPlanError> {
        if frame.len() > MAX_RESTRICTED_RUNTIME_APPLY_TRANSPORT_PROFILE_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < RESTRICTED_TRANSPORT_PROFILE_FIXED_BYTES {
            return Err(DistributedAgentStackPlanError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.take(4)? != RESTRICTED_TRANSPORT_PROFILE_MAGIC
            || cursor.u16()? != RESTRICTED_RUNTIME_APPLY_TRANSPORT_PROFILE_VERSION
            || cursor.u16()? != RESTRICTED_ZENOH_TLS_QUERY_PROFILE_KIND
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let locator_length = cursor.usize_u16()?;
        let route_length = cursor.usize_u16()?;
        if cursor.u16()? != 0
            || locator_length == 0
            || locator_length > MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES
            || route_length == 0
            || route_length > MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES
        {
            return Err(DistributedAgentStackPlanError::InvalidLength);
        }
        let target = RuntimeHostId::from_bytes(cursor.array()?);
        let endpoint_ref = cursor.array()?;
        let endpoint_generation = cursor.u64()?;
        let controller_principal = PrincipalRef::from_bytes(cursor.array()?);
        let runtime_principal = PrincipalRef::from_bytes(cursor.array()?);
        let trust_domain_ref =
            DistributedFabricTrustDomainRefV1::try_from_bytes(cursor.array()?)
                .map_err(|_| DistributedAgentStackPlanError::InvalidTransportProfile)?;
        let trust_anchor_ref =
            DistributedFabricTrustAnchorRefV1::try_from_bytes(cursor.array()?)
                .map_err(|_| DistributedAgentStackPlanError::InvalidTransportProfile)?;
        let controller_connector_credential_ref =
            DistributedFabricCredentialRefV1::try_from_bytes(cursor.array()?)
                .map_err(|_| DistributedAgentStackPlanError::InvalidTransportProfile)?;
        let runtime_listener_credential_ref =
            DistributedFabricCredentialRefV1::try_from_bytes(cursor.array()?)
                .map_err(|_| DistributedAgentStackPlanError::InvalidTransportProfile)?;
        let operation_timeout_nanos = cursor.u64()?;
        let tls_listener_locator = core::str::from_utf8(cursor.take(locator_length)?)
            .map_err(|_| DistributedAgentStackPlanError::InvalidTransportProfile)?;
        let route = core::str::from_utf8(cursor.take(route_length)?)
            .map_err(|_| DistributedAgentStackPlanError::InvalidTransportProfile)?;
        cursor.finish()?;
        let decoded = Self::try_new(RestrictedRuntimeApplyTransportProfileFieldsV1 {
            target,
            endpoint_ref,
            endpoint_generation,
            tls_listener_locator,
            route,
            trust_domain_ref,
            trust_anchor_ref,
            controller_connector_credential_ref,
            runtime_listener_credential_ref,
            controller_principal,
            runtime_principal,
            operation_timeout_nanos,
        })?;
        if decoded.canonical_wire() != frame {
            return Err(DistributedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub const fn endpoint_ref(&self) -> [u8; 16] {
        self.endpoint_ref
    }

    #[must_use]
    pub const fn endpoint_generation(&self) -> u64 {
        self.endpoint_generation
    }

    #[must_use]
    pub const fn tls_listener_locator(&self) -> &DistributedFabricTlsEndpointV1 {
        &self.tls_listener_locator
    }

    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    #[must_use]
    pub const fn trust_domain_ref(&self) -> DistributedFabricTrustDomainRefV1 {
        self.trust_domain_ref
    }

    #[must_use]
    pub const fn trust_anchor_ref(&self) -> DistributedFabricTrustAnchorRefV1 {
        self.trust_anchor_ref
    }

    #[must_use]
    pub const fn controller_connector_credential_ref(&self) -> DistributedFabricCredentialRefV1 {
        self.controller_connector_credential_ref
    }

    #[must_use]
    pub const fn runtime_listener_credential_ref(&self) -> DistributedFabricCredentialRefV1 {
        self.runtime_listener_credential_ref
    }

    #[must_use]
    pub const fn controller_principal(&self) -> PrincipalRef {
        self.controller_principal
    }

    #[must_use]
    pub const fn runtime_principal(&self) -> PrincipalRef {
        self.runtime_principal
    }

    #[must_use]
    pub const fn operation_timeout_nanos(&self) -> u64 {
        self.operation_timeout_nanos
    }

    /// Returns exact canonical PXRP v1 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the domain-separated digest committed by PXCB.
    #[must_use]
    pub const fn profile_digest(&self) -> Digest32 {
        self.profile_digest
    }

    /// Verifies the exact transport facts duplicated by one PXCB commitment.
    ///
    /// This comparison has no authentication or send-authority meaning. PXRP
    /// intentionally contains no profile reference, so the profile owner must
    /// supply its independently resolved nonzero selector for comparison with
    /// PXCB's opaque `control_transport_profile_ref`.
    pub fn validate_carrier_binding(
        &self,
        resolved_profile_ref: [u8; 16],
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
    ) -> Result<(), DistributedAgentStackPlanError> {
        if bytes_are_zero(&resolved_profile_ref)
            || resolved_profile_ref != carrier.control_transport_profile_ref()
            || self.target != carrier.target()
            || self.endpoint_ref != carrier.endpoint_ref()
            || self.endpoint_generation != carrier.endpoint_generation()
            || self.route() != carrier.route()
            || self.controller_principal != carrier.controller_principal()
            || self.runtime_principal != carrier.runtime_principal()
            || self.profile_digest != carrier.control_transport_profile_digest()
        {
            return Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch);
        }
        Ok(())
    }
}

/// Desired authentication profile for one remote Fabric peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum DistributedFabricAuthenticationProfileV1 {
    /// Mutual TLS with certificate-chain and enrolled peer-identity validation.
    MutualTlsPeerIdentity = 1,
}

/// Desired authentication references for one explicit remote peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DistributedFabricPeerAuthenticationRequirementV1 {
    profile: DistributedFabricAuthenticationProfileV1,
    trust_domain_ref: DistributedFabricTrustDomainRefV1,
    local_credential_ref: DistributedFabricCredentialRefV1,
    trust_anchor_ref: DistributedFabricTrustAnchorRefV1,
    expected_peer_identity_ref: DistributedFabricPeerIdentityRefV1,
}

impl DistributedFabricPeerAuthenticationRequirementV1 {
    /// Requires mutual TLS and owner-resolved credential/trust references.
    pub const fn try_mutual_tls(
        trust_domain_ref: DistributedFabricTrustDomainRefV1,
        local_credential_ref: DistributedFabricCredentialRefV1,
        trust_anchor_ref: DistributedFabricTrustAnchorRefV1,
        expected_peer_identity_ref: DistributedFabricPeerIdentityRefV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        Ok(Self {
            profile: DistributedFabricAuthenticationProfileV1::MutualTlsPeerIdentity,
            trust_domain_ref,
            local_credential_ref,
            trust_anchor_ref,
            expected_peer_identity_ref,
        })
    }

    /// Returns the desired authentication profile.
    #[must_use]
    pub const fn profile(self) -> DistributedFabricAuthenticationProfileV1 {
        self.profile
    }

    /// Returns the enrolled trust-domain reference.
    #[must_use]
    pub const fn trust_domain_ref(self) -> DistributedFabricTrustDomainRefV1 {
        self.trust_domain_ref
    }

    /// Returns the owner-resolved local credential reference.
    #[must_use]
    pub const fn local_credential_ref(self) -> DistributedFabricCredentialRefV1 {
        self.local_credential_ref
    }

    /// Returns the owner-resolved trust-anchor reference.
    #[must_use]
    pub const fn trust_anchor_ref(self) -> DistributedFabricTrustAnchorRefV1 {
        self.trust_anchor_ref
    }

    /// Returns the exact enrolled remote peer identity requirement.
    #[must_use]
    pub const fn expected_peer_identity_ref(self) -> DistributedFabricPeerIdentityRefV1 {
        self.expected_peer_identity_ref
    }
}

/// One explicit RuntimeHost peer connect target and authentication requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedFabricPeerPlanV1 {
    peer_runtime_host: RuntimeHostId,
    connect_endpoint: DistributedFabricTlsEndpointV1,
    authentication: DistributedFabricPeerAuthenticationRequirementV1,
    requirement_digest: Digest32,
}

impl DistributedFabricPeerPlanV1 {
    /// Creates one bounded peer row. The digest is correlation only, not authentication.
    pub fn try_new(
        peer_runtime_host: RuntimeHostId,
        connect_endpoint: DistributedFabricTlsEndpointV1,
        authentication: DistributedFabricPeerAuthenticationRequirementV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        if bytes_are_zero(peer_runtime_host.as_bytes()) {
            return Err(DistributedAgentStackPlanError::InvalidPeer);
        }
        let requirement_digest =
            peer_requirement_digest(peer_runtime_host, &connect_endpoint, authentication)?;
        Ok(Self {
            peer_runtime_host,
            connect_endpoint,
            authentication,
            requirement_digest,
        })
    }

    /// Returns the remote RuntimeHost identity.
    #[must_use]
    pub const fn peer_runtime_host(&self) -> RuntimeHostId {
        self.peer_runtime_host
    }

    /// Returns the exact remote connect endpoint.
    #[must_use]
    pub const fn connect_endpoint(&self) -> &DistributedFabricTlsEndpointV1 {
        &self.connect_endpoint
    }

    /// Returns the desired authentication requirement.
    #[must_use]
    pub const fn authentication(&self) -> DistributedFabricPeerAuthenticationRequirementV1 {
        self.authentication
    }

    /// Returns a desired-row correlation digest. It never proves peer identity.
    #[must_use]
    pub const fn requirement_digest(&self) -> Digest32 {
        self.requirement_digest
    }
}

/// Complete single-Zenoh-Session topology for one active fixed-stack RuntimeHost.
///
/// Listen/connect endpoints do not install an application Binding, select a
/// second route, or authorize fallback. The surrounding PXAR keeps PXTA empty.
/// Every peer shares one session authentication profile, trust domain, local
/// credential, and trust-anchor set while retaining a distinct expected peer
/// identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedFabricTopologyV1 {
    base_loopback_listen_endpoint: ManagedFabricListenEndpointV1,
    remote_listen_endpoint: DistributedFabricTlsEndpointV1,
    peers: Box<[DistributedFabricPeerPlanV1]>,
    canonical_wire: Box<[u8]>,
}

impl DistributedFabricTopologyV1 {
    /// Creates one canonical topology. Peer rows must already be strictly sorted by RuntimeHostId.
    pub fn try_new(
        local_runtime_host: RuntimeHostId,
        base_loopback_listen_endpoint: ManagedFabricListenEndpointV1,
        remote_listen_endpoint: DistributedFabricTlsEndpointV1,
        peers: Vec<DistributedFabricPeerPlanV1>,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        validate_topology(local_runtime_host, &remote_listen_endpoint, &peers)?;
        let canonical_wire = build_topology_wire(
            &base_loopback_listen_endpoint,
            &remote_listen_endpoint,
            &peers,
        )?;
        if canonical_wire.len() > MAX_DISTRIBUTED_FABRIC_TOPOLOGY_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        Ok(Self {
            base_loopback_listen_endpoint,
            remote_listen_endpoint,
            peers: peers.into_boxed_slice(),
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes exactly PXDT v1 for the supplied local RuntimeHost.
    pub fn decode(
        local_runtime_host: RuntimeHostId,
        frame: &[u8],
    ) -> Result<Self, DistributedAgentStackPlanError> {
        if frame.len() > MAX_DISTRIBUTED_FABRIC_TOPOLOGY_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < TOPOLOGY_FIXED_BYTES {
            return Err(DistributedAgentStackPlanError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.take(4)? != TOPOLOGY_MAGIC || cursor.u16()? != DISTRIBUTED_FABRIC_TOPOLOGY_VERSION
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let base_length = cursor.usize_u16()?;
        let listen_length = cursor.usize_u16()?;
        let peer_count = cursor.usize_u16()?;
        if cursor.u16()? != 0
            || base_length == 0
            || base_length > MAX_BASE_LOOPBACK_ENDPOINT_BYTES
            || listen_length == 0
            || listen_length > MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES
            || peer_count == 0
            || peer_count > MAX_DISTRIBUTED_FABRIC_PEERS
        {
            return Err(DistributedAgentStackPlanError::InvalidLength);
        }
        let base = core::str::from_utf8(cursor.take(base_length)?)
            .map_err(|_| DistributedAgentStackPlanError::InvalidEndpoint)?;
        let base_loopback_listen_endpoint = ManagedFabricListenEndpointV1::try_new(base)?;
        let listen = core::str::from_utf8(cursor.take(listen_length)?)
            .map_err(|_| DistributedAgentStackPlanError::InvalidEndpoint)?;
        let remote_listen_endpoint = DistributedFabricTlsEndpointV1::try_new(listen)?;
        let mut peers = Vec::with_capacity(peer_count);
        for _ in 0..peer_count {
            let peer_runtime_host = RuntimeHostId::from_bytes(cursor.array()?);
            let endpoint_length = cursor.usize_u16()?;
            let profile = decode_authentication_profile(cursor.u16()?)?;
            let trust_domain_ref =
                DistributedFabricTrustDomainRefV1::try_from_bytes(cursor.array()?)?;
            let local_credential_ref =
                DistributedFabricCredentialRefV1::try_from_bytes(cursor.array()?)?;
            let trust_anchor_ref =
                DistributedFabricTrustAnchorRefV1::try_from_bytes(cursor.array()?)?;
            let expected_peer_identity_ref =
                DistributedFabricPeerIdentityRefV1::try_from_bytes(cursor.array()?)?;
            if endpoint_length == 0 || endpoint_length > MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES {
                return Err(DistributedAgentStackPlanError::InvalidLength);
            }
            let endpoint = core::str::from_utf8(cursor.take(endpoint_length)?)
                .map_err(|_| DistributedAgentStackPlanError::InvalidEndpoint)?;
            let authentication = match profile {
                DistributedFabricAuthenticationProfileV1::MutualTlsPeerIdentity => {
                    DistributedFabricPeerAuthenticationRequirementV1::try_mutual_tls(
                        trust_domain_ref,
                        local_credential_ref,
                        trust_anchor_ref,
                        expected_peer_identity_ref,
                    )?
                }
            };
            peers.push(DistributedFabricPeerPlanV1::try_new(
                peer_runtime_host,
                DistributedFabricTlsEndpointV1::try_new(endpoint)?,
                authentication,
            )?);
        }
        cursor.finish()?;
        let decoded = Self::try_new(
            local_runtime_host,
            base_loopback_listen_endpoint,
            remote_listen_endpoint,
            peers,
        )?;
        if decoded.canonical_wire() != frame {
            return Err(DistributedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Returns the predecessor's exact loopback listener.
    #[must_use]
    pub const fn base_loopback_listen_endpoint(&self) -> &ManagedFabricListenEndpointV1 {
        &self.base_loopback_listen_endpoint
    }

    /// Returns the explicit non-loopback listener.
    #[must_use]
    pub const fn remote_listen_endpoint(&self) -> &DistributedFabricTlsEndpointV1 {
        &self.remote_listen_endpoint
    }

    /// Returns strictly ordered explicit connect peers.
    #[must_use]
    pub fn peers(&self) -> &[DistributedFabricPeerPlanV1] {
        &self.peers
    }

    /// Returns exact canonical PXDT v1 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// Additive projection for PXTE v7/PXAR v8.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackProjectionV1 {
    managed_agent_stack: ManagedAgentStackProjectionV1,
    compatibility_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl DistributedAgentStackProjectionV1 {
    /// Derives this successor from an independently verified fixed-stack projection.
    pub fn try_from_managed_agent_stack_projection(
        managed_agent_stack: ManagedAgentStackProjectionV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        let compatibility_digest = distributed_agent_stack_compatibility_digest_v1()?;
        let canonical_wire = build_projection_wire(&managed_agent_stack, compatibility_digest);
        Ok(Self {
            managed_agent_stack,
            compatibility_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes PXDP v1 and never accepts PXSP directly.
    pub fn decode(frame: &[u8]) -> Result<Self, DistributedAgentStackPlanError> {
        if frame.len() > PROJECTION_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < PROJECTION_BYTES {
            return Err(DistributedAgentStackPlanError::Truncated);
        }
        if &frame[..4] != PROJECTION_MAGIC
            || read_u16(&frame[4..6]) != DISTRIBUTED_AGENT_STACK_PROJECTION_VERSION
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let predecessor_end = 6 + MANAGED_AGENT_STACK_PROJECTION_BYTES;
        let managed_agent_stack =
            ManagedAgentStackProjectionV1::decode(&frame[6..predecessor_end])?;
        let compatibility_digest =
            Digest32::from_bytes(read_array(&frame[predecessor_end..predecessor_end + 32]));
        if compatibility_digest != distributed_agent_stack_compatibility_digest_v1()?
            || read_u16(&frame[predecessor_end + 32..predecessor_end + 34])
                != DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_VERSION
            || read_u16(&frame[predecessor_end + 34..predecessor_end + 36])
                != DISTRIBUTED_AGENT_STACK_PROFILE_VERSION
        {
            return Err(DistributedAgentStackPlanError::CompatibilityMismatch);
        }
        let decoded = Self::try_from_managed_agent_stack_projection(managed_agent_stack)?;
        if decoded.canonical_wire() != frame {
            return Err(DistributedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Returns the exact fixed-stack predecessor projection.
    #[must_use]
    pub const fn managed_agent_stack_projection(&self) -> &ManagedAgentStackProjectionV1 {
        &self.managed_agent_stack
    }

    /// Returns the selected local RuntimeHost target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.managed_agent_stack.target()
    }

    /// Returns the compiled successor compatibility digest.
    #[must_use]
    pub const fn compatibility_digest(&self) -> Digest32 {
        self.compatibility_digest
    }

    /// Returns exact canonical PXDP v1 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// Exact fixed desired shape admitted by PXTE v7.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DistributedAgentStackTargetModeV1 {
    /// One retained fixed Fabric→Agent stack plus explicit remote topology.
    DistributedFabricAndAgent = 1,
    /// Authoritative exact-zero target.
    EmptyDeactivate = 2,
}

/// Canonical PXTE v7 desired value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTargetExecutionV1 {
    projection: DistributedAgentStackProjectionV1,
    mode: DistributedAgentStackTargetModeV1,
    predecessor: ManagedAgentStackTargetExecutionV1,
    topology: Option<DistributedFabricTopologyV1>,
    canonical_wire: Box<[u8]>,
    execution_digest: Digest32,
}

impl DistributedAgentStackTargetExecutionV1 {
    /// Creates the only active shape: fixed Fabric→Agent plus explicit topology.
    pub fn try_distributed_fabric_and_agent(
        projection: DistributedAgentStackProjectionV1,
        predecessor: ManagedAgentStackTargetExecutionV1,
        topology: DistributedFabricTopologyV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        Self::try_new(
            projection,
            DistributedAgentStackTargetModeV1::DistributedFabricAndAgent,
            predecessor,
            Some(topology),
        )
    }

    /// Creates authoritative exact-zero while retaining the verified projection.
    pub fn try_empty_deactivate(
        projection: DistributedAgentStackProjectionV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        let predecessor = ManagedAgentStackTargetExecutionV1::try_empty_deactivate(
            projection.managed_agent_stack_projection().clone(),
        )?;
        Self::try_new(
            projection,
            DistributedAgentStackTargetModeV1::EmptyDeactivate,
            predecessor,
            None,
        )
    }

    fn try_new(
        projection: DistributedAgentStackProjectionV1,
        mode: DistributedAgentStackTargetModeV1,
        predecessor: ManagedAgentStackTargetExecutionV1,
        topology: Option<DistributedFabricTopologyV1>,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        if predecessor.projection() != projection.managed_agent_stack_projection() {
            return Err(DistributedAgentStackPlanError::ProjectionMismatch);
        }
        match (mode, predecessor.mode(), topology.as_ref()) {
            (
                DistributedAgentStackTargetModeV1::DistributedFabricAndAgent,
                ManagedAgentStackTargetModeV1::FabricAndAgent,
                Some(topology),
            ) => {
                let predecessor_loopback = predecessor
                    .fabric()
                    .listen_endpoint()
                    .ok_or(DistributedAgentStackPlanError::InvalidShape)?;
                if predecessor_loopback != topology.base_loopback_listen_endpoint() {
                    return Err(DistributedAgentStackPlanError::InvalidTopology);
                }
            }
            (
                DistributedAgentStackTargetModeV1::EmptyDeactivate,
                ManagedAgentStackTargetModeV1::EmptyDeactivate,
                None,
            ) => {}
            _ => return Err(DistributedAgentStackPlanError::InvalidShape),
        }
        let canonical_wire =
            build_target_execution_wire(&projection, mode, &predecessor, topology.as_ref())?;
        if canonical_wire.len() > MAX_DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        let execution_digest = digest_wire(TARGET_EXECUTION_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            projection,
            mode,
            predecessor,
            topology,
            canonical_wire: canonical_wire.into_boxed_slice(),
            execution_digest,
        })
    }

    /// Strictly decodes exactly PXTE v7 without predecessor fallback.
    pub fn decode(frame: &[u8]) -> Result<Self, DistributedAgentStackPlanError> {
        if frame.len() > MAX_DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < TARGET_EXECUTION_FIXED_BYTES {
            return Err(DistributedAgentStackPlanError::Truncated);
        }
        if &frame[..4] != TARGET_EXECUTION_MAGIC
            || read_u16(&frame[4..6]) != DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_VERSION
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let projection_end = 6 + PROJECTION_BYTES;
        let projection = DistributedAgentStackProjectionV1::decode(&frame[6..projection_end])?;
        if read_u16(&frame[projection_end..projection_end + 2])
            != DISTRIBUTED_AGENT_STACK_PROFILE_VERSION
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let mode = match frame[projection_end + 2] {
            1 => DistributedAgentStackTargetModeV1::DistributedFabricAndAgent,
            2 => DistributedAgentStackTargetModeV1::EmptyDeactivate,
            _ => return Err(DistributedAgentStackPlanError::InvalidShape),
        };
        let topology_present = frame[projection_end + 3];
        let predecessor_length = read_u32(&frame[projection_end + 4..projection_end + 8]) as usize;
        let topology_length = read_u32(&frame[projection_end + 8..projection_end + 12]) as usize;
        if predecessor_length == 0
            || predecessor_length > MAX_MANAGED_AGENT_STACK_TARGET_EXECUTION_BYTES
            || topology_length > MAX_DISTRIBUTED_FABRIC_TOPOLOGY_BYTES
        {
            return Err(DistributedAgentStackPlanError::InvalidLength);
        }
        let predecessor_end = TARGET_EXECUTION_FIXED_BYTES
            .checked_add(predecessor_length)
            .ok_or(DistributedAgentStackPlanError::FrameTooLarge)?;
        let expected_end = predecessor_end
            .checked_add(topology_length)
            .ok_or(DistributedAgentStackPlanError::FrameTooLarge)?;
        if frame.len() < expected_end {
            return Err(DistributedAgentStackPlanError::Truncated);
        }
        if frame.len() > expected_end {
            return Err(DistributedAgentStackPlanError::TrailingBytes);
        }
        let predecessor = ManagedAgentStackTargetExecutionV1::decode(
            &frame[TARGET_EXECUTION_FIXED_BYTES..predecessor_end],
        )?;
        let decoded = match (mode, topology_present, topology_length) {
            (DistributedAgentStackTargetModeV1::DistributedFabricAndAgent, 1, 1..) => {
                let topology = DistributedFabricTopologyV1::decode(
                    projection.target(),
                    &frame[predecessor_end..expected_end],
                )?;
                Self::try_distributed_fabric_and_agent(projection, predecessor, topology)
            }
            (DistributedAgentStackTargetModeV1::EmptyDeactivate, 0, 0) => {
                Self::try_new(projection, mode, predecessor, None)
            }
            _ => Err(DistributedAgentStackPlanError::InvalidShape),
        }?;
        if decoded.canonical_wire() != frame {
            return Err(DistributedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Returns the successor projection.
    #[must_use]
    pub const fn projection(&self) -> &DistributedAgentStackProjectionV1 {
        &self.projection
    }

    /// Returns the exact target mode.
    #[must_use]
    pub const fn mode(&self) -> DistributedAgentStackTargetModeV1 {
        self.mode
    }

    /// Returns the exact retained PXTE v6 value.
    #[must_use]
    pub const fn predecessor(&self) -> &ManagedAgentStackTargetExecutionV1 {
        &self.predecessor
    }

    /// Returns the explicit topology, absent only for empty/deactivate.
    #[must_use]
    pub const fn topology(&self) -> Option<&DistributedFabricTopologyV1> {
        self.topology.as_ref()
    }

    /// Returns exact canonical PXTE v7 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the domain-separated digest of exact PXTE v7 bytes.
    #[must_use]
    pub const fn execution_digest(&self) -> Digest32 {
        self.execution_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DistributedAgentStackAssignmentsV1 {
    bindings: TargetAssignments,
    execution: DistributedAgentStackTargetExecutionV1,
    assignment_digest: TargetAssignmentDigest,
}

impl DistributedAgentStackAssignmentsV1 {
    fn try_from_execution(
        execution: DistributedAgentStackTargetExecutionV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        let bindings = TargetAssignments::try_new(Vec::new())
            .map_err(|_| DistributedAgentStackPlanError::BindingNotAllowed)?;
        Self::try_new(bindings, execution)
    }

    fn try_new(
        bindings: TargetAssignments,
        execution: DistributedAgentStackTargetExecutionV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        bindings
            .validate()
            .map_err(|_| DistributedAgentStackPlanError::BindingNotAllowed)?;
        if !bindings.is_empty() || bindings.canonical_wire() != EMPTY_PXTA {
            return Err(DistributedAgentStackPlanError::BindingNotAllowed);
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
struct DistributedAgentStackPlanSliceV1 {
    commitment: RuntimeSliceCommitment,
    assignments: DistributedAgentStackAssignmentsV1,
}

impl DistributedAgentStackPlanSliceV1 {
    fn try_new(
        commitment: RuntimeSliceCommitment,
        assignments: DistributedAgentStackAssignmentsV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        commitment.validate()?;
        if commitment.header().assignment_digest() != assignments.assignment_digest {
            return Err(DistributedAgentStackPlanError::CommitmentMismatch);
        }
        if commitment.header().target() != assignments.execution.projection().target() {
            return Err(DistributedAgentStackPlanError::TargetMismatch);
        }
        Ok(Self {
            commitment,
            assignments,
        })
    }
}

/// Canonical envelope-v2 signing transcript used by PXAR v8.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackApplySigningTranscriptV2(ApplyRequestSigningTranscriptV2);

impl DistributedAgentStackApplySigningTranscriptV2 {
    /// Returns exact canonical signing bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Signature-independent PXAR v8 producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackApplyRequestDraftV1 {
    envelope: RuntimeApplyEnvelopeV2Draft,
    slice: DistributedAgentStackPlanSliceV1,
}

impl DistributedAgentStackApplyRequestDraftV1 {
    /// Builds one canonical v8 draft committed to exact PXTA-zero and PXTE v7 bytes.
    pub fn try_new(
        execution: DistributedAgentStackTargetExecutionV1,
        provenance: PlanProvenance,
        control: RuntimeApplyControl,
        temporal: ApplyTemporalConstraint,
        expected_runtime_store_instance_id: [u8; 32],
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        let assignments = DistributedAgentStackAssignmentsV1::try_from_execution(execution)?;
        let header = RuntimeSliceHeader::new(
            assignments.execution.projection().target(),
            provenance,
            assignments.assignment_digest,
        );
        let commitment = RuntimeSliceCommitment::try_new(header)?;
        let slice = DistributedAgentStackPlanSliceV1::try_new(commitment, assignments)?;
        let control_commitment = RuntimeApplyControlCommitment::try_new(commitment, control)?;
        let store = RuntimeStoreInstanceId::try_from_bytes(expected_runtime_store_instance_id)?;
        let envelope =
            RuntimeApplyEnvelopeV2Draft::try_new(control_commitment, temporal, store, auth_claim)?;
        Ok(Self { envelope, slice })
    }

    /// Returns the signature-independent exact envelope transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<DistributedAgentStackApplySigningTranscriptV2, DistributedAgentStackPlanError> {
        Ok(DistributedAgentStackApplySigningTranscriptV2(
            self.envelope.signing_transcript()?,
        ))
    }

    /// Attaches an opaque request signature and creates strict PXAR v8.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<DistributedAgentStackApplyRequestV1, DistributedAgentStackPlanError> {
        let envelope = self.envelope.finalize(signature)?;
        DistributedAgentStackApplyRequestV1::try_new(envelope, self.slice)
    }
}

/// Signed strict PXAR v8 carrying envelope v2, PXTA-zero, and PXTE v7.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackApplyRequestV1 {
    envelope: RuntimeApplyEnvelopeV2,
    slice: DistributedAgentStackPlanSliceV1,
    canonical_wire: Box<[u8]>,
}

impl DistributedAgentStackApplyRequestV1 {
    fn try_new(
        envelope: RuntimeApplyEnvelopeV2,
        slice: DistributedAgentStackPlanSliceV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        if envelope.control_commitment().slice() != slice.commitment {
            return Err(DistributedAgentStackPlanError::CommitmentMismatch);
        }
        let canonical_wire = build_apply_request_wire(&envelope, &slice)?;
        if canonical_wire.len() > MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        Ok(Self {
            envelope,
            slice,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes PXAR v8 and cross-rejects every predecessor version.
    pub fn decode(frame: &[u8]) -> Result<Self, DistributedAgentStackPlanError> {
        if frame.len() > MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < APPLY_REQUEST_HEADER_BYTES {
            return Err(DistributedAgentStackPlanError::Truncated);
        }
        if &frame[..4] != APPLY_REQUEST_MAGIC
            || read_u16(&frame[4..6]) != DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_VERSION
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let envelope_length = read_u32(&frame[6..10]) as usize;
        let bindings_length = read_u32(&frame[10..14]) as usize;
        let execution_length = read_u32(&frame[14..18]) as usize;
        if envelope_length > MAX_RUNTIME_APPLY_ENVELOPE_V2_BYTES
            || bindings_length != EMPTY_PXTA.len()
            || execution_length > MAX_DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_BYTES
        {
            return Err(DistributedAgentStackPlanError::InvalidLength);
        }
        let expected_length = APPLY_REQUEST_HEADER_BYTES
            .checked_add(envelope_length)
            .and_then(|value| value.checked_add(bindings_length))
            .and_then(|value| value.checked_add(execution_length))
            .ok_or(DistributedAgentStackPlanError::FrameTooLarge)?;
        if frame.len() < expected_length {
            return Err(DistributedAgentStackPlanError::Truncated);
        }
        if frame.len() > expected_length {
            return Err(DistributedAgentStackPlanError::TrailingBytes);
        }
        let envelope_start = APPLY_REQUEST_HEADER_BYTES;
        let envelope_end = envelope_start + envelope_length;
        let bindings_end = envelope_end + bindings_length;
        let envelope = RuntimeApplyEnvelopeV2::decode(&frame[envelope_start..envelope_end])?;
        let binding_frame = &frame[envelope_end..bindings_end];
        if binding_frame != EMPTY_PXTA {
            return Err(DistributedAgentStackPlanError::BindingNotAllowed);
        }
        let bindings = TargetAssignments::decode(binding_frame)
            .map_err(|_| DistributedAgentStackPlanError::BindingNotAllowed)?;
        let execution = DistributedAgentStackTargetExecutionV1::decode(&frame[bindings_end..])?;
        let assignments = DistributedAgentStackAssignmentsV1::try_new(bindings, execution)?;
        let commitment = envelope.control_commitment().slice();
        let slice = DistributedAgentStackPlanSliceV1::try_new(commitment, assignments)?;
        let decoded = Self::try_new(envelope, slice)?;
        if decoded.canonical_wire() != frame {
            return Err(DistributedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Returns exact canonical PXAR v8 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns exact durable `PXTA-zero || PXTE-v7` bytes.
    #[must_use]
    pub fn canonical_slice_wire(&self) -> &[u8] {
        let offset = APPLY_REQUEST_HEADER_BYTES + self.envelope.canonical_wire().len();
        &self.canonical_wire[offset..]
    }

    /// Returns the exact distributed target execution.
    #[must_use]
    pub const fn target_execution(&self) -> &DistributedAgentStackTargetExecutionV1 {
        &self.slice.assignments.execution
    }

    /// Returns the selected RuntimeHost target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.slice.commitment.header().target()
    }

    /// Returns committed source-plan provenance.
    #[must_use]
    pub const fn provenance(&self) -> PlanProvenance {
        self.slice.commitment.header().provenance()
    }

    /// Returns the canonical assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.slice.commitment.header().assignment_digest()
    }

    /// Returns the canonical target-slice digest.
    #[must_use]
    pub const fn target_slice_digest(&self) -> TargetSliceDigest {
        self.slice.commitment.target_slice_digest()
    }

    /// Returns the authenticated apply-control commitment.
    #[must_use]
    pub const fn control_commitment(&self) -> &RuntimeApplyControlCommitment {
        self.envelope.control_commitment()
    }

    /// Returns the apply operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> ApplyOperationId {
        self.envelope.control_commitment().control().operation_id()
    }

    /// Returns the exact temporal constraint.
    #[must_use]
    pub const fn temporal(&self) -> ApplyTemporalConstraint {
        self.envelope.temporal()
    }

    /// Returns the exact expected Runtime store identity.
    #[must_use]
    pub const fn expected_runtime_store_instance_id(&self) -> [u8; 32] {
        *self
            .envelope
            .expected_runtime_store_instance_id()
            .as_bytes()
    }

    /// Returns request authentication material inherited from envelope v2.
    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        self.envelope.authentication()
    }

    /// Returns the envelope request digest.
    #[must_use]
    pub const fn envelope_request_digest(&self) -> Digest32 {
        self.envelope.request_digest()
    }

    /// Reconstructs the envelope signing transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<DistributedAgentStackApplySigningTranscriptV2, DistributedAgentStackPlanError> {
        Ok(DistributedAgentStackApplySigningTranscriptV2(
            self.envelope.signing_transcript()?,
        ))
    }

    /// Verifies exact Runtime store correlation before any apply mutation.
    pub fn validate_expected_store(
        &self,
        local_runtime_store_instance_id: [u8; 32],
    ) -> Result<(), DistributedAgentStackPlanError> {
        let local = RuntimeStoreInstanceId::try_from_bytes(local_runtime_store_instance_id)?;
        self.envelope.validate_expected_store(local)?;
        Ok(())
    }

    /// Verifies exact locally derived installation projection equality.
    pub fn validate_projection(
        &self,
        projection: &DistributedAgentStackProjectionV1,
    ) -> Result<(), DistributedAgentStackPlanError> {
        if self.target_execution().projection() != projection {
            return Err(DistributedAgentStackPlanError::ProjectionMismatch);
        }
        Ok(())
    }
}

/// Inputs used to construct one exact Runtime-owned restricted apply carrier.
///
/// Public keys stay outside the wire value. Their canonical fingerprints bind
/// the exact Controller request and Runtime response keys that each endpoint
/// must resolve from its independently protected provisioning state.
#[derive(Clone, Copy, Debug)]
pub struct RestrictedRuntimeApplyCarrierBindingFieldsV1<'a> {
    /// RuntimeHost selected by the exact PXAR v8 request and endpoint.
    pub target: RuntimeHostId,
    /// Runtime principal that owns the endpoint and response key.
    pub runtime_principal: PrincipalRef,
    /// Controller principal admitted to sign PXAR and the outer PXRC.
    pub controller_principal: PrincipalRef,
    /// Opaque Runtime-owned endpoint identity discovered through Node facts.
    pub endpoint_ref: [u8; 16],
    /// Nonzero Runtime-owned endpoint generation.
    pub endpoint_generation: u64,
    /// Canonical restricted Zenoh query route.
    pub route: &'a str,
    /// Controller request-key selector already asserted by inner PXAR v8.
    pub controller_request_key: ApplyAuthKeyRef,
    /// Fingerprint of the exact Controller Ed25519 public key, derived with
    /// [`crate::reference_control::ed25519_control_key_fingerprint`].
    pub controller_request_key_fingerprint: Digest32,
    /// Runtime response-key selector published with the endpoint.
    pub runtime_response_key: ApplyAuthKeyRef,
    /// Fingerprint of the exact Runtime Ed25519 response public key, derived
    /// with [`crate::reference_control::ed25519_control_key_fingerprint`].
    pub runtime_response_key_fingerprint: Digest32,
    /// Opaque owner-resolved restricted control-transport profile reference.
    pub control_transport_profile_ref: [u8; 16],
    /// Digest of the exact restricted control-transport profile.
    pub control_transport_profile_digest: Digest32,
}

/// Canonical selection of one Runtime-owned restricted Zenoh query carrier.
///
/// This value is transport evidence only after a Controller signature covers
/// it in PXRC. A decoded binding never proves discovery freshness, endpoint
/// ownership, key possession, or successful transport authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictedRuntimeApplyCarrierBindingV1 {
    target: RuntimeHostId,
    runtime_principal: PrincipalRef,
    controller_principal: PrincipalRef,
    endpoint_ref: [u8; 16],
    endpoint_generation: u64,
    route: Box<str>,
    controller_request_key: ApplyAuthKeyRef,
    controller_request_key_fingerprint: Digest32,
    runtime_response_key: ApplyAuthKeyRef,
    runtime_response_key_fingerprint: Digest32,
    control_transport_profile_ref: [u8; 16],
    control_transport_profile_digest: Digest32,
    canonical_wire: Box<[u8]>,
    binding_digest: Digest32,
}

impl RestrictedRuntimeApplyCarrierBindingV1 {
    /// Constructs the fixed restricted-Zenoh carrier from independently owned facts.
    pub fn try_new(
        fields: RestrictedRuntimeApplyCarrierBindingFieldsV1<'_>,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        validate_restricted_runtime_apply_route(fields.route)?;
        if bytes_are_zero(fields.target.as_bytes())
            || bytes_are_zero(fields.runtime_principal.as_bytes())
            || bytes_are_zero(fields.controller_principal.as_bytes())
            || fields.runtime_principal == fields.controller_principal
            || bytes_are_zero(&fields.endpoint_ref)
            || fields.endpoint_generation == 0
            || bytes_are_zero(fields.controller_request_key.as_bytes())
            || digest_is_zero(fields.controller_request_key_fingerprint)
            || bytes_are_zero(fields.runtime_response_key.as_bytes())
            || digest_is_zero(fields.runtime_response_key_fingerprint)
            || fields.controller_request_key == fields.runtime_response_key
            || fields.controller_request_key_fingerprint == fields.runtime_response_key_fingerprint
            || bytes_are_zero(&fields.control_transport_profile_ref)
            || digest_is_zero(fields.control_transport_profile_digest)
        {
            return Err(DistributedAgentStackPlanError::InvalidCarrierBinding);
        }
        let canonical_wire = build_restricted_carrier_binding_wire(fields)?;
        if canonical_wire.len() > MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        let binding_digest =
            digest_wire(RESTRICTED_CARRIER_BINDING_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            target: fields.target,
            runtime_principal: fields.runtime_principal,
            controller_principal: fields.controller_principal,
            endpoint_ref: fields.endpoint_ref,
            endpoint_generation: fields.endpoint_generation,
            route: fields.route.into(),
            controller_request_key: fields.controller_request_key,
            controller_request_key_fingerprint: fields.controller_request_key_fingerprint,
            runtime_response_key: fields.runtime_response_key,
            runtime_response_key_fingerprint: fields.runtime_response_key_fingerprint,
            control_transport_profile_ref: fields.control_transport_profile_ref,
            control_transport_profile_digest: fields.control_transport_profile_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
            binding_digest,
        })
    }

    /// Strictly decodes one PXCB v1 restricted carrier binding.
    pub fn decode(frame: &[u8]) -> Result<Self, DistributedAgentStackPlanError> {
        if frame.len() > MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < RESTRICTED_CARRIER_BINDING_FIXED_BYTES {
            return Err(DistributedAgentStackPlanError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.take(4)? != RESTRICTED_CARRIER_BINDING_MAGIC
            || cursor.u16()? != RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_VERSION
            || cursor.u16()? != RESTRICTED_ZENOH_QUERY_CARRIER_KIND
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let route_length = cursor.usize_u16()?;
        if cursor.u16()? != 0
            || route_length == 0
            || route_length > MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES
        {
            return Err(DistributedAgentStackPlanError::InvalidLength);
        }
        let target = RuntimeHostId::from_bytes(cursor.array()?);
        let runtime_principal = PrincipalRef::from_bytes(cursor.array()?);
        let controller_principal = PrincipalRef::from_bytes(cursor.array()?);
        let endpoint_ref = cursor.array()?;
        let endpoint_generation = cursor.u64()?;
        let controller_request_key = ApplyAuthKeyRef::from_bytes(cursor.array()?);
        let controller_request_key_fingerprint = Digest32::from_bytes(cursor.array()?);
        let runtime_response_key = ApplyAuthKeyRef::from_bytes(cursor.array()?);
        let runtime_response_key_fingerprint = Digest32::from_bytes(cursor.array()?);
        let control_transport_profile_ref = cursor.array()?;
        let control_transport_profile_digest = Digest32::from_bytes(cursor.array()?);
        let route = core::str::from_utf8(cursor.take(route_length)?)
            .map_err(|_| DistributedAgentStackPlanError::InvalidCarrierBinding)?;
        cursor.finish()?;
        let decoded = Self::try_new(RestrictedRuntimeApplyCarrierBindingFieldsV1 {
            target,
            runtime_principal,
            controller_principal,
            endpoint_ref,
            endpoint_generation,
            route,
            controller_request_key,
            controller_request_key_fingerprint,
            runtime_response_key,
            runtime_response_key_fingerprint,
            control_transport_profile_ref,
            control_transport_profile_digest,
        })?;
        if decoded.canonical_wire() != frame {
            return Err(DistributedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub const fn runtime_principal(&self) -> PrincipalRef {
        self.runtime_principal
    }

    #[must_use]
    pub const fn controller_principal(&self) -> PrincipalRef {
        self.controller_principal
    }

    #[must_use]
    pub const fn endpoint_ref(&self) -> [u8; 16] {
        self.endpoint_ref
    }

    #[must_use]
    pub const fn endpoint_generation(&self) -> u64 {
        self.endpoint_generation
    }

    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    #[must_use]
    pub const fn controller_request_key(&self) -> ApplyAuthKeyRef {
        self.controller_request_key
    }

    #[must_use]
    pub const fn controller_request_key_fingerprint(&self) -> Digest32 {
        self.controller_request_key_fingerprint
    }

    #[must_use]
    pub const fn runtime_response_key(&self) -> ApplyAuthKeyRef {
        self.runtime_response_key
    }

    #[must_use]
    pub const fn runtime_response_key_fingerprint(&self) -> Digest32 {
        self.runtime_response_key_fingerprint
    }

    #[must_use]
    pub const fn control_transport_profile_ref(&self) -> [u8; 16] {
        self.control_transport_profile_ref
    }

    #[must_use]
    pub const fn control_transport_profile_digest(&self) -> Digest32 {
        self.control_transport_profile_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub const fn binding_digest(&self) -> Digest32 {
        self.binding_digest
    }
}

/// Exact domain-separated bytes supplied to the PXRC Controller signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackRestrictedApplySigningTranscriptV1(Box<[u8]>);

impl DistributedAgentStackRestrictedApplySigningTranscriptV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent Controller PXRC v1 producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackRestrictedApplyRequestDraftV1 {
    request: DistributedAgentStackApplyRequestV1,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    request_wire_digest: Digest32,
}

impl DistributedAgentStackRestrictedApplyRequestDraftV1 {
    /// Binds exact frozen PXAR v8 bytes to one selected restricted carrier.
    pub fn try_new(
        request: DistributedAgentStackApplyRequestV1,
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        validate_restricted_request_carrier(&request, &carrier)?;
        let request_wire_digest = digest_wire(
            DISTRIBUTED_APPLY_REQUEST_WIRE_DIGEST_DOMAIN,
            request.canonical_wire(),
        )?;
        Ok(Self {
            request,
            carrier,
            request_wire_digest,
        })
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<
        DistributedAgentStackRestrictedApplySigningTranscriptV1,
        DistributedAgentStackPlanError,
    > {
        Ok(DistributedAgentStackRestrictedApplySigningTranscriptV1(
            build_restricted_apply_request_fields(
                RESTRICTED_APPLY_REQUEST_SIGNING_MAGIC,
                DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_VERSION,
                &self.carrier,
                &self.request,
                self.request_wire_digest,
            )?
            .into_boxed_slice(),
        ))
    }

    /// Attaches the fixed-width Ed25519 Controller signature.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<DistributedAgentStackRestrictedApplyRequestV1, DistributedAgentStackPlanError> {
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(DistributedAgentStackPlanError::InvalidCarrierAuthentication);
        }
        DistributedAgentStackRestrictedApplyRequestV1::try_new(
            self.request,
            self.carrier,
            self.request_wire_digest,
            signature,
        )
    }
}

/// Controller-signed PXRC v1 containing exact PXAR v8 and carrier bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackRestrictedApplyRequestV1 {
    request: DistributedAgentStackApplyRequestV1,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    request_wire_digest: Digest32,
    signature: Box<[u8]>,
    canonical_wire: Box<[u8]>,
    restricted_request_digest: Digest32,
}

impl DistributedAgentStackRestrictedApplyRequestV1 {
    fn try_new(
        request: DistributedAgentStackApplyRequestV1,
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        request_wire_digest: Digest32,
        signature: &[u8],
    ) -> Result<Self, DistributedAgentStackPlanError> {
        validate_restricted_request_carrier(&request, &carrier)?;
        if request_wire_digest
            != digest_wire(
                DISTRIBUTED_APPLY_REQUEST_WIRE_DIGEST_DOMAIN,
                request.canonical_wire(),
            )?
            || signature.len() != ED25519_SIGNATURE_BYTES
        {
            return Err(DistributedAgentStackPlanError::InvalidCarrierAuthentication);
        }
        let mut canonical_wire = build_restricted_apply_request_fields(
            RESTRICTED_APPLY_REQUEST_MAGIC,
            DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_VERSION,
            &carrier,
            &request,
            request_wire_digest,
        )?;
        canonical_wire.extend_from_slice(&(ED25519_SIGNATURE_BYTES as u16).to_be_bytes());
        canonical_wire.extend_from_slice(signature);
        if canonical_wire.len() > MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        let restricted_request_digest =
            digest_wire(RESTRICTED_APPLY_REQUEST_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            request,
            carrier,
            request_wire_digest,
            signature: signature.into(),
            canonical_wire: canonical_wire.into_boxed_slice(),
            restricted_request_digest,
        })
    }

    /// Strictly decodes PXRC v1. The Controller signature is still untrusted.
    pub fn decode(frame: &[u8]) -> Result<Self, DistributedAgentStackPlanError> {
        if frame.len() > MAX_DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < RESTRICTED_APPLY_REQUEST_FIXED_BYTES + 2 + ED25519_SIGNATURE_BYTES {
            return Err(DistributedAgentStackPlanError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.take(4)? != RESTRICTED_APPLY_REQUEST_MAGIC
            || cursor.u16()? != DISTRIBUTED_AGENT_STACK_RESTRICTED_APPLY_REQUEST_VERSION
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let carrier_length = cursor.usize_u16()?;
        let request_length = cursor.usize_u32()?;
        let carrier_digest = Digest32::from_bytes(cursor.array()?);
        let request_wire_digest = Digest32::from_bytes(cursor.array()?);
        if carrier_length == 0
            || carrier_length > MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
            || request_length == 0
            || request_length > MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES
            || digest_is_zero(carrier_digest)
            || digest_is_zero(request_wire_digest)
        {
            return Err(DistributedAgentStackPlanError::InvalidLength);
        }
        let carrier = RestrictedRuntimeApplyCarrierBindingV1::decode(cursor.take(carrier_length)?)?;
        if carrier.binding_digest() != carrier_digest {
            return Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch);
        }
        let request = DistributedAgentStackApplyRequestV1::decode(cursor.take(request_length)?)?;
        let signature_length = cursor.usize_u16()?;
        if signature_length != ED25519_SIGNATURE_BYTES {
            return Err(DistributedAgentStackPlanError::InvalidCarrierAuthentication);
        }
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let decoded = Self::try_new(request, carrier, request_wire_digest, signature)?;
        if decoded.canonical_wire() != frame {
            return Err(DistributedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Verifies the selected carrier and its Controller signature before any mutation.
    ///
    /// The verifier callback is part of the caller's trusted computing base:
    /// it must resolve the supplied key reference to an Ed25519 key, check its
    /// exact fingerprint, and verify `signature` over `transcript`. This pure
    /// contract crate does not implement that cryptography. Success authenticates
    /// the outer carrier binding only; the Runtime must still run all frozen
    /// PXAR v8 authentication, temporal, store, tenure, replay, preflight, and
    /// commit checks before applying the inner request.
    pub fn verify_controller_carrier_before_mutation<Verify>(
        &self,
        expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        verify: Verify,
    ) -> Result<
        ControllerAuthenticatedDistributedAgentStackApplyRequestV1<'_>,
        DistributedAgentStackPlanError,
    >
    where
        Verify: FnOnce(PrincipalRef, ApplyAuthKeyRef, Digest32, &[u8], &[u8]) -> bool,
    {
        if &self.carrier != expected_carrier {
            return Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch);
        }
        let transcript = self.signing_transcript()?;
        if !verify(
            self.carrier.controller_principal(),
            self.carrier.controller_request_key(),
            self.carrier.controller_request_key_fingerprint(),
            transcript.as_bytes(),
            &self.signature,
        ) {
            return Err(DistributedAgentStackPlanError::InvalidCarrierAuthentication);
        }
        Ok(ControllerAuthenticatedDistributedAgentStackApplyRequestV1 { request: self })
    }

    /// Internal correlation access only. Untrusted PXRC consumers must obtain
    /// the inner request through the verifier-accepted marker below.
    #[must_use]
    pub(crate) const fn request(&self) -> &DistributedAgentStackApplyRequestV1 {
        &self.request
    }

    #[must_use]
    pub const fn carrier(&self) -> &RestrictedRuntimeApplyCarrierBindingV1 {
        &self.carrier
    }

    #[must_use]
    pub const fn request_wire_digest(&self) -> Digest32 {
        self.request_wire_digest
    }

    #[must_use]
    pub fn controller_signature(&self) -> &[u8] {
        &self.signature
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub const fn restricted_request_digest(&self) -> Digest32 {
        self.restricted_request_digest
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<
        DistributedAgentStackRestrictedApplySigningTranscriptV1,
        DistributedAgentStackPlanError,
    > {
        DistributedAgentStackRestrictedApplyRequestDraftV1 {
            request: self.request.clone(),
            carrier: self.carrier.clone(),
            request_wire_digest: self.request_wire_digest,
        }
        .signing_transcript()
    }
}

/// Marker that a caller-supplied trusted verifier accepted PXRC carrier
/// correlation and the outer Controller signature.
///
/// Construction is private, but the verifier callback remains part of the
/// caller's trusted computing base; this pure contract type does not itself
/// prove cryptographic correctness. Runtime's concrete ingress must keep its
/// mutation API private and issue this marker only through its pinned Ed25519
/// verifier. The marker never bypasses the independent frozen PXAR v8
/// admission decision.
#[derive(Clone, Copy, Debug)]
pub struct ControllerAuthenticatedDistributedAgentStackApplyRequestV1<'a> {
    request: &'a DistributedAgentStackRestrictedApplyRequestV1,
}

impl<'a> ControllerAuthenticatedDistributedAgentStackApplyRequestV1<'a> {
    #[must_use]
    pub const fn restricted_request(self) -> &'a DistributedAgentStackRestrictedApplyRequestV1 {
        self.request
    }

    #[must_use]
    pub const fn request(self) -> &'a DistributedAgentStackApplyRequestV1 {
        self.request.request()
    }

    #[must_use]
    pub const fn carrier(self) -> &'a RestrictedRuntimeApplyCarrierBindingV1 {
        self.request.carrier()
    }

    #[must_use]
    pub const fn restricted_request_digest(self) -> Digest32 {
        self.request.restricted_request_digest()
    }
}

/// Canonical fields asserted by a real Fabric owner's transport observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DistributedFabricObservedTransportProofFieldsV1 {
    /// RuntimeHost that owns the observed session.
    pub local_runtime_host: RuntimeHostId,
    /// Remote RuntimeHost correlated with the desired peer row.
    pub peer_runtime_host: RuntimeHostId,
    /// Nonzero Fabric session epoch observed by the actual owner.
    pub session_epoch: DistributedFabricSessionEpochV1,
    /// Peer identity actually returned by authenticated transport validation.
    pub authenticated_peer_identity_ref: DistributedFabricPeerIdentityRefV1,
    /// Local credential reference actually selected by the transport owner.
    pub selected_local_credential_ref: DistributedFabricCredentialRefV1,
    /// Opaque reference to owner-retained transport evidence.
    pub transport_evidence_ref: DistributedFabricTransportEvidenceRefV1,
    /// Nonzero owner-monotonic observation sequence.
    pub observation_sequence: u64,
}

/// Unsigned canonical PXTP v1 payload, distinct from desired authentication requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedFabricObservedTransportProofV1 {
    fields: DistributedFabricObservedTransportProofFieldsV1,
    profile: DistributedFabricAuthenticationProfileV1,
    requirement_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl DistributedFabricObservedTransportProofV1 {
    /// Builds a correlated observation; bytes alone do not authenticate this statement.
    pub fn try_new(
        expected_local_runtime_host: RuntimeHostId,
        desired_peer: &DistributedFabricPeerPlanV1,
        fields: DistributedFabricObservedTransportProofFieldsV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        let authentication = desired_peer.authentication();
        if bytes_are_zero(expected_local_runtime_host.as_bytes())
            || fields.local_runtime_host != expected_local_runtime_host
            || fields.local_runtime_host == fields.peer_runtime_host
            || fields.peer_runtime_host != desired_peer.peer_runtime_host()
            || fields.authenticated_peer_identity_ref != authentication.expected_peer_identity_ref()
            || fields.selected_local_credential_ref != authentication.local_credential_ref()
            || fields.observation_sequence == 0
        {
            return Err(DistributedAgentStackPlanError::TransportProofMismatch);
        }
        let profile = authentication.profile();
        let requirement_digest = desired_peer.requirement_digest();
        let canonical_wire = build_transport_proof_wire(fields, profile, requirement_digest);
        Ok(Self {
            fields,
            profile,
            requirement_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes the unsigned payload without claiming transport authentication.
    pub fn decode(frame: &[u8]) -> Result<Self, DistributedAgentStackPlanError> {
        if frame.len() > TRANSPORT_PROOF_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        if frame.len() < TRANSPORT_PROOF_BYTES {
            return Err(DistributedAgentStackPlanError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.take(4)? != TRANSPORT_PROOF_MAGIC
            || cursor.u16()? != DISTRIBUTED_FABRIC_TRANSPORT_PROOF_VERSION
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let fields = DistributedFabricObservedTransportProofFieldsV1 {
            local_runtime_host: RuntimeHostId::from_bytes(cursor.array()?),
            peer_runtime_host: RuntimeHostId::from_bytes(cursor.array()?),
            session_epoch: DistributedFabricSessionEpochV1::try_from_bytes(cursor.array()?)?,
            authenticated_peer_identity_ref: DistributedFabricPeerIdentityRefV1::try_from_bytes(
                cursor.array()?,
            )?,
            selected_local_credential_ref: DistributedFabricCredentialRefV1::try_from_bytes(
                cursor.array()?,
            )?,
            transport_evidence_ref: DistributedFabricTransportEvidenceRefV1::try_from_bytes(
                cursor.array()?,
            )?,
            observation_sequence: 0,
        };
        let profile = decode_authentication_profile(cursor.u16()?)?;
        let requirement_digest = Digest32::from_bytes(cursor.array()?);
        let observation_sequence = cursor.u64()?;
        cursor.finish()?;
        let fields = DistributedFabricObservedTransportProofFieldsV1 {
            observation_sequence,
            ..fields
        };
        if bytes_are_zero(fields.local_runtime_host.as_bytes())
            || bytes_are_zero(fields.peer_runtime_host.as_bytes())
            || fields.local_runtime_host == fields.peer_runtime_host
            || digest_is_zero(requirement_digest)
            || observation_sequence == 0
        {
            return Err(DistributedAgentStackPlanError::InvalidTransportProof);
        }
        let canonical_wire = build_transport_proof_wire(fields, profile, requirement_digest);
        if canonical_wire != frame {
            return Err(DistributedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(Self {
            fields,
            profile,
            requirement_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Validates exact desired-row correlation; an authenticated carrier remains required.
    pub fn validate_against(
        &self,
        expected_local_runtime_host: RuntimeHostId,
        desired_peer: &DistributedFabricPeerPlanV1,
    ) -> Result<(), DistributedAgentStackPlanError> {
        let authentication = desired_peer.authentication();
        if self.fields.local_runtime_host != expected_local_runtime_host
            || self.fields.peer_runtime_host != desired_peer.peer_runtime_host()
            || self.profile != authentication.profile()
            || self.requirement_digest != desired_peer.requirement_digest()
            || self.fields.authenticated_peer_identity_ref
                != authentication.expected_peer_identity_ref()
            || self.fields.selected_local_credential_ref != authentication.local_credential_ref()
        {
            return Err(DistributedAgentStackPlanError::TransportProofMismatch);
        }
        Ok(())
    }

    /// Returns canonical observation fields.
    #[must_use]
    pub const fn fields(&self) -> DistributedFabricObservedTransportProofFieldsV1 {
        self.fields
    }

    /// Returns the correlated desired authentication profile.
    #[must_use]
    pub const fn profile(&self) -> DistributedFabricAuthenticationProfileV1 {
        self.profile
    }

    /// Returns the desired-row correlation digest; it is not authentication evidence.
    #[must_use]
    pub const fn requirement_digest(&self) -> Digest32 {
        self.requirement_digest
    }

    /// Returns exact unsigned canonical PXTP v1 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// RuntimeHost classification for one exact PXAR v8 operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DistributedAgentStackTerminalOutcomeV1 {
    /// The incoming distributed stack is committed and locally ready.
    ActiveReady = 1,
    /// The Runtime reached a definitive non-ready terminal.
    TerminalNonReady = 2,
    /// The Runtime cannot prove either readiness or a definitive non-ready result.
    IndeterminateUncertain = 3,
    /// The incoming EmptyDeactivate request committed an owner-proven exact-zero stack.
    EmptyExactZero = 4,
}

/// Runtime-owned census of the two local Agent request/event bindings.
///
/// `installed_binding_set_digest` commits to the exact owner-observed binding
/// descriptors and binding epochs.  It is distinct from the remote transport
/// observation digest and cannot be reconstructed from PXTP payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackLocalBindingEvidenceFieldsV1 {
    pub physical_binding_census: u16,
    pub census_complete: bool,
    pub fabric_ready: bool,
    pub agent_ready: bool,
    pub dependency_satisfied: bool,
    pub exact_zero: bool,
    pub quarantined: bool,
    pub installed_binding_set_digest: Digest32,
    pub raw_outcome_digest: Digest32,
}

/// Derives the sole contract-owned digest for the exact installed local
/// request/event PortBinding descriptors, in role order.
///
/// Each input is the descriptor digest emitted by the binding owner after
/// installation; that descriptor already commits to its BindingId and epoch.
pub fn distributed_agent_stack_installed_binding_set_digest_v1(
    request_binding_descriptor_digest: Digest32,
    event_binding_descriptor_digest: Digest32,
) -> Result<Digest32, DistributedAgentStackPlanError> {
    if digest_is_zero(request_binding_descriptor_digest)
        || digest_is_zero(event_binding_descriptor_digest)
        || request_binding_descriptor_digest == event_binding_descriptor_digest
    {
        return Err(DistributedAgentStackPlanError::InvalidTerminalFacts);
    }
    let mut builder = Digest32Builder::try_new(TERMINAL_INSTALLED_BINDING_SET_DIGEST_DOMAIN)?;
    builder.field_u16(2)?;
    builder.field_bytes(b"request")?;
    builder.field_digest(&request_binding_descriptor_digest)?;
    builder.field_bytes(b"event")?;
    builder.field_digest(&event_binding_descriptor_digest)?;
    Ok(builder.finish())
}

/// Derives the sole contract-owned digest for an owner-proven empty local
/// binding set. No placeholder descriptor digest is accepted or synthesized.
pub fn distributed_agent_stack_empty_binding_set_digest_v1()
-> Result<Digest32, DistributedAgentStackPlanError> {
    let mut builder = Digest32Builder::try_new(TERMINAL_INSTALLED_BINDING_SET_DIGEST_DOMAIN)?;
    builder.field_u16(0)?;
    Ok(builder.finish())
}

/// Runtime-owned completion fences and service generations signed into PXDS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTerminalEvidenceFieldsV1 {
    pub runtime_host_epoch: u64,
    pub completion_snapshot_sequence: u64,
    pub selection_clock_generation: ClockGeneration,
    pub selection_observed_at_nanos: u64,
    pub fabric_generation: Option<ManagedServiceGeneration>,
    pub agent_generation: Option<ManagedServiceGeneration>,
    pub local_bindings: DistributedAgentStackLocalBindingEvidenceFieldsV1,
}

/// Canonically ordered, request-correlated remote transport observations.
///
/// PXTP values remain unsigned payloads.  This set becomes authenticated only
/// because its exact bytes and derived binding digest are covered by PXDS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTerminalObservationsV1 {
    local_loopback_endpoint: ManagedFabricListenEndpointV1,
    remote_listen_endpoint: DistributedFabricTlsEndpointV1,
    topology_digest: Digest32,
    remote_observation_digest: Digest32,
    proofs: Box<[DistributedFabricObservedTransportProofV1]>,
}

impl DistributedAgentStackTerminalObservationsV1 {
    pub fn try_new(
        request: &DistributedAgentStackApplyRequestV1,
        proofs: Vec<DistributedFabricObservedTransportProofV1>,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        let topology = request
            .target_execution()
            .topology()
            .ok_or(DistributedAgentStackPlanError::InvalidTerminalFacts)?;
        if proofs.len() > topology.peers().len() {
            return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        let mut previous_peer = None;
        let mut session_epoch = None;
        let mut observation_sequences = Vec::with_capacity(proofs.len());
        for proof in &proofs {
            let fields = proof.fields();
            if previous_peer.is_some_and(|value: RuntimeHostId| {
                value.as_bytes() >= fields.peer_runtime_host.as_bytes()
            }) || session_epoch
                .is_some_and(|value: DistributedFabricSessionEpochV1| value != fields.session_epoch)
                || observation_sequences.contains(&fields.observation_sequence)
            {
                return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
            }
            let peer = topology
                .peers()
                .iter()
                .find(|peer| peer.peer_runtime_host() == fields.peer_runtime_host)
                .ok_or(DistributedAgentStackPlanError::TerminalCorrelationMismatch)?;
            proof.validate_against(request.target(), peer)?;
            previous_peer = Some(fields.peer_runtime_host);
            session_epoch = Some(fields.session_epoch);
            observation_sequences.push(fields.observation_sequence);
        }
        let local_loopback_endpoint = topology.base_loopback_listen_endpoint().clone();
        let remote_listen_endpoint = topology.remote_listen_endpoint().clone();
        let topology_digest = terminal_topology_digest(topology)?;
        let remote_observation_digest = terminal_remote_observation_digest(
            request.target(),
            &local_loopback_endpoint,
            &remote_listen_endpoint,
            topology_digest,
            &proofs,
        )?;
        Ok(Self {
            local_loopback_endpoint,
            remote_listen_endpoint,
            topology_digest,
            remote_observation_digest,
            proofs: proofs.into_boxed_slice(),
        })
    }

    fn try_from_decoded_parts(
        target: RuntimeHostId,
        local_loopback_endpoint: ManagedFabricListenEndpointV1,
        remote_listen_endpoint: DistributedFabricTlsEndpointV1,
        topology_digest: Digest32,
        remote_observation_digest: Digest32,
        proofs: Vec<DistributedFabricObservedTransportProofV1>,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        if bytes_are_zero(target.as_bytes())
            || digest_is_zero(topology_digest)
            || proofs.len() > MAX_DISTRIBUTED_FABRIC_PEERS
        {
            return Err(DistributedAgentStackPlanError::InvalidTerminalFacts);
        }
        let mut previous = None;
        let mut session_epoch = None;
        let mut observation_sequences = Vec::with_capacity(proofs.len());
        for proof in &proofs {
            let fields = proof.fields();
            if fields.local_runtime_host != target
                || previous.is_some_and(|value: RuntimeHostId| {
                    value.as_bytes() >= fields.peer_runtime_host.as_bytes()
                })
                || session_epoch.is_some_and(|value: DistributedFabricSessionEpochV1| {
                    value != fields.session_epoch
                })
                || observation_sequences.contains(&fields.observation_sequence)
            {
                return Err(DistributedAgentStackPlanError::InvalidTerminalFacts);
            }
            previous = Some(fields.peer_runtime_host);
            session_epoch = Some(fields.session_epoch);
            observation_sequences.push(fields.observation_sequence);
        }
        let expected_remote_observation = terminal_remote_observation_digest(
            target,
            &local_loopback_endpoint,
            &remote_listen_endpoint,
            topology_digest,
            &proofs,
        )?;
        if expected_remote_observation != remote_observation_digest {
            return Err(DistributedAgentStackPlanError::InvalidTerminalFacts);
        }
        Ok(Self {
            local_loopback_endpoint,
            remote_listen_endpoint,
            topology_digest,
            remote_observation_digest,
            proofs: proofs.into_boxed_slice(),
        })
    }

    fn validate_against_request(
        &self,
        request: &DistributedAgentStackApplyRequestV1,
    ) -> Result<(), DistributedAgentStackPlanError> {
        let expected = Self::try_new(request, self.proofs.to_vec())?;
        if self != &expected {
            return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn local_loopback_endpoint(&self) -> &ManagedFabricListenEndpointV1 {
        &self.local_loopback_endpoint
    }

    #[must_use]
    pub const fn remote_listen_endpoint(&self) -> &DistributedFabricTlsEndpointV1 {
        &self.remote_listen_endpoint
    }

    #[must_use]
    pub const fn topology_digest(&self) -> Digest32 {
        self.topology_digest
    }

    #[must_use]
    pub const fn remote_observation_digest(&self) -> Digest32 {
        self.remote_observation_digest
    }

    #[must_use]
    pub fn proofs(&self) -> &[DistributedFabricObservedTransportProofV1] {
        &self.proofs
    }
}

/// Complete request and transport facts covered by one PXDS signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTerminalFactsV1 {
    target: RuntimeHostId,
    runtime_store_instance_id: [u8; 32],
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    target_slice_digest: TargetSliceDigest,
    outcome: DistributedAgentStackTerminalOutcomeV1,
    evidence: DistributedAgentStackTerminalEvidenceFieldsV1,
    observations: Option<DistributedAgentStackTerminalObservationsV1>,
}

impl DistributedAgentStackTerminalFactsV1 {
    pub fn try_new(
        request: &DistributedAgentStackApplyRequestV1,
        outcome: DistributedAgentStackTerminalOutcomeV1,
        evidence: DistributedAgentStackTerminalEvidenceFieldsV1,
        observations: DistributedAgentStackTerminalObservationsV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        if outcome == DistributedAgentStackTerminalOutcomeV1::EmptyExactZero {
            return Err(DistributedAgentStackPlanError::InvalidTerminalFacts);
        }
        validate_terminal_outcome(outcome, evidence)?;
        observations.validate_against_request(request)?;
        let topology = request
            .target_execution()
            .topology()
            .ok_or(DistributedAgentStackPlanError::InvalidTerminalFacts)?;
        if request.target_execution().mode()
            != DistributedAgentStackTargetModeV1::DistributedFabricAndAgent
            || evidence.selection_clock_generation.value()
                < request.temporal().target_clock_generation().value()
            || outcome == DistributedAgentStackTerminalOutcomeV1::ActiveReady
                && observations.proofs().len() != topology.peers().len()
        {
            return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(Self {
            target: request.target(),
            runtime_store_instance_id: request.expected_runtime_store_instance_id(),
            operation_id: request.operation_id(),
            request_digest: request.envelope_request_digest(),
            target_slice_digest: request.target_slice_digest(),
            outcome,
            evidence,
            observations: Some(observations),
        })
    }

    /// Constructs the sole PXDS exact-zero terminal for PXTE v7 EmptyDeactivate.
    pub fn try_empty_exact_zero(
        request: &DistributedAgentStackApplyRequestV1,
        evidence: DistributedAgentStackTerminalEvidenceFieldsV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        let outcome = DistributedAgentStackTerminalOutcomeV1::EmptyExactZero;
        validate_terminal_outcome(outcome, evidence)?;
        if request.target_execution().mode() != DistributedAgentStackTargetModeV1::EmptyDeactivate
            || request.target_execution().topology().is_some()
            || evidence.selection_clock_generation.value()
                < request.temporal().target_clock_generation().value()
        {
            return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(Self {
            target: request.target(),
            runtime_store_instance_id: request.expected_runtime_store_instance_id(),
            operation_id: request.operation_id(),
            request_digest: request.envelope_request_digest(),
            target_slice_digest: request.target_slice_digest(),
            outcome,
            evidence,
            observations: None,
        })
    }

    fn validate_against_request(
        &self,
        request: &DistributedAgentStackApplyRequestV1,
    ) -> Result<(), DistributedAgentStackPlanError> {
        validate_terminal_outcome(self.outcome, self.evidence)?;
        let active_observations = self.observations.as_ref();
        if let Some(observations) = active_observations {
            observations.validate_against_request(request)?;
        }
        let topology = request.target_execution().topology();
        if self.target != request.target()
            || self.runtime_store_instance_id != request.expected_runtime_store_instance_id()
            || self.operation_id != request.operation_id()
            || self.request_digest != request.envelope_request_digest()
            || self.target_slice_digest != request.target_slice_digest()
            || self.evidence.selection_clock_generation.value()
                < request.temporal().target_clock_generation().value()
            || match self.outcome {
                DistributedAgentStackTerminalOutcomeV1::EmptyExactZero => {
                    request.target_execution().mode()
                        != DistributedAgentStackTargetModeV1::EmptyDeactivate
                        || topology.is_some()
                        || active_observations.is_some()
                }
                DistributedAgentStackTerminalOutcomeV1::ActiveReady => {
                    request.target_execution().mode()
                        != DistributedAgentStackTargetModeV1::DistributedFabricAndAgent
                        || topology.is_none_or(|topology| {
                            active_observations.is_none_or(|observations| {
                                observations.proofs().len() != topology.peers().len()
                            })
                        })
                }
                DistributedAgentStackTerminalOutcomeV1::TerminalNonReady
                | DistributedAgentStackTerminalOutcomeV1::IndeterminateUncertain => {
                    request.target_execution().mode()
                        != DistributedAgentStackTargetModeV1::DistributedFabricAndAgent
                        || topology.is_none()
                        || active_observations.is_none()
                }
            }
        {
            return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub const fn runtime_store_instance_id(&self) -> [u8; 32] {
        self.runtime_store_instance_id
    }

    #[must_use]
    pub const fn operation_id(&self) -> ApplyOperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub const fn target_slice_digest(&self) -> TargetSliceDigest {
        self.target_slice_digest
    }

    #[must_use]
    pub const fn outcome(&self) -> DistributedAgentStackTerminalOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub const fn evidence(&self) -> DistributedAgentStackTerminalEvidenceFieldsV1 {
        self.evidence
    }

    #[must_use]
    pub const fn observations(&self) -> Option<&DistributedAgentStackTerminalObservationsV1> {
        self.observations.as_ref()
    }
}

/// RuntimeHost signer selection bound to the exact local control channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTerminalAuthClaimV1 {
    runtime_peer: PrincipalRef,
    channel_binding_digest: Digest32,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

impl DistributedAgentStackTerminalAuthClaimV1 {
    pub fn try_new(
        channel: ReferenceChannelBindingV1,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        if bytes_are_zero(key.as_bytes())
            || algorithm.value() != ED25519_ALGORITHM
            || algorithm_version != ED25519_ALGORITHM_VERSION
        {
            return Err(DistributedAgentStackPlanError::InvalidResponseAuthentication);
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

/// Exact domain-separated bytes supplied to the RuntimeHost response signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTerminalSigningTranscriptV1(Box<[u8]>);

impl DistributedAgentStackTerminalSigningTranscriptV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent PXDS v1 producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTerminalReceiptDraftV1 {
    facts: DistributedAgentStackTerminalFactsV1,
    channel: ReferenceChannelBindingV1,
    auth_claim: DistributedAgentStackTerminalAuthClaimV1,
}

impl DistributedAgentStackTerminalReceiptDraftV1 {
    pub fn try_new(
        request: &DistributedAgentStackApplyRequestV1,
        facts: DistributedAgentStackTerminalFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: DistributedAgentStackTerminalAuthClaimV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        facts.validate_against_request(request)?;
        if channel.target() != request.target()
            || auth_claim.runtime_peer() != channel.runtime_peer()
            || auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(Self {
            facts,
            channel,
            auth_claim,
        })
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<DistributedAgentStackTerminalSigningTranscriptV1, DistributedAgentStackPlanError>
    {
        Ok(DistributedAgentStackTerminalSigningTranscriptV1(
            build_distributed_terminal_fields(
                TERMINAL_RECEIPT_SIGNING_MAGIC,
                DISTRIBUTED_AGENT_STACK_TERMINAL_SIGNING_VERSION,
                &self.facts,
                self.channel,
                self.auth_claim,
            )?
            .into_boxed_slice(),
        ))
    }

    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackPlanError> {
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(DistributedAgentStackPlanError::InvalidResponseAuthentication);
        }
        DistributedAgentStackTerminalReceiptV1::try_new(
            self.facts,
            self.channel,
            self.auth_claim,
            signature,
        )
    }
}

/// Signed strict PXDS v1 RuntimeHost terminal Receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTerminalReceiptV1 {
    facts: DistributedAgentStackTerminalFactsV1,
    channel: ReferenceChannelBindingV1,
    auth_claim: DistributedAgentStackTerminalAuthClaimV1,
    signature: Box<[u8]>,
    canonical_wire: Box<[u8]>,
    receipt_digest: Digest32,
}

impl DistributedAgentStackTerminalReceiptV1 {
    fn try_new(
        facts: DistributedAgentStackTerminalFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: DistributedAgentStackTerminalAuthClaimV1,
        signature: &[u8],
    ) -> Result<Self, DistributedAgentStackPlanError> {
        let mut canonical_wire = build_distributed_terminal_fields(
            TERMINAL_RECEIPT_MAGIC,
            DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_VERSION,
            &facts,
            channel,
            auth_claim,
        )?;
        let signature_length = u16::try_from(signature.len())
            .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
        canonical_wire.extend_from_slice(&signature_length.to_be_bytes());
        canonical_wire.extend_from_slice(signature);
        if canonical_wire.len() > MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
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

    pub fn decode(frame: &[u8]) -> Result<Self, DistributedAgentStackPlanError> {
        if frame.len() > MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.take(4)? != TERMINAL_RECEIPT_MAGIC
            || cursor.u16()? != DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_VERSION
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let facts = decode_distributed_terminal_facts(&mut cursor)?;
        let channel = decode_distributed_terminal_channel(&mut cursor)?;
        let auth_claim = decode_distributed_terminal_auth_claim(&mut cursor)?;
        let signature_length = cursor.usize_u16()?;
        if signature_length != ED25519_SIGNATURE_BYTES {
            return Err(DistributedAgentStackPlanError::InvalidLength);
        }
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let decoded = Self::try_new(facts, channel, auth_claim, signature)?;
        if decoded.canonical_wire() != frame {
            return Err(DistributedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    pub fn validate_against_request(
        &self,
        request: &DistributedAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<&DistributedAgentStackTerminalFactsV1, DistributedAgentStackPlanError> {
        self.facts.validate_against_request(request)?;
        if self.channel != channel
            || channel.target() != request.target()
            || self.auth_claim.runtime_peer() != channel.runtime_peer()
            || self.auth_claim.channel_binding_digest() != channel.binding_digest()
        {
            return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(&self.facts)
    }

    #[must_use]
    pub const fn facts(&self) -> &DistributedAgentStackTerminalFactsV1 {
        &self.facts
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
    ) -> Result<DistributedAgentStackTerminalSigningTranscriptV1, DistributedAgentStackPlanError>
    {
        DistributedAgentStackTerminalReceiptDraftV1 {
            facts: self.facts.clone(),
            channel: self.channel,
            auth_claim: self.auth_claim,
        }
        .signing_transcript()
    }
}

/// Exact domain-separated bytes supplied to the restricted PXDS v2 signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTerminalSigningTranscriptV2(Box<[u8]>);

impl DistributedAgentStackTerminalSigningTranscriptV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent PXDS v2 producer for one authenticated PXRC request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTerminalReceiptDraftV2 {
    facts: DistributedAgentStackTerminalFactsV1,
    restricted_request_digest: Digest32,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
}

impl DistributedAgentStackTerminalReceiptDraftV2 {
    /// Creates a response draft only after the outer PXRC carrier was authenticated.
    pub fn try_new(
        authenticated_request: ControllerAuthenticatedDistributedAgentStackApplyRequestV1<'_>,
        facts: DistributedAgentStackTerminalFactsV1,
    ) -> Result<Self, DistributedAgentStackPlanError> {
        facts.validate_against_request(authenticated_request.request())?;
        Ok(Self {
            facts,
            restricted_request_digest: authenticated_request.restricted_request_digest(),
            carrier: authenticated_request.carrier().clone(),
        })
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<DistributedAgentStackTerminalSigningTranscriptV2, DistributedAgentStackPlanError>
    {
        Ok(DistributedAgentStackTerminalSigningTranscriptV2(
            build_restricted_terminal_receipt_fields(
                RESTRICTED_TERMINAL_RECEIPT_SIGNING_MAGIC,
                DISTRIBUTED_AGENT_STACK_TERMINAL_SIGNING_V2_VERSION,
                &self.facts,
                self.restricted_request_digest,
                &self.carrier,
            )?
            .into_boxed_slice(),
        ))
    }

    /// Attaches the fixed-width Ed25519 Runtime response-key signature.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<DistributedAgentStackTerminalReceiptV2, DistributedAgentStackPlanError> {
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(DistributedAgentStackPlanError::InvalidResponseAuthentication);
        }
        DistributedAgentStackTerminalReceiptV2::try_new(
            self.facts,
            self.restricted_request_digest,
            self.carrier,
            signature,
        )
    }
}

/// Runtime-response-key-signed PXDS v2 bound to exact PXRC and PXCB bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgentStackTerminalReceiptV2 {
    facts: DistributedAgentStackTerminalFactsV1,
    restricted_request_digest: Digest32,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    signature: Box<[u8]>,
    canonical_wire: Box<[u8]>,
    receipt_digest: Digest32,
}

impl DistributedAgentStackTerminalReceiptV2 {
    fn try_new(
        facts: DistributedAgentStackTerminalFactsV1,
        restricted_request_digest: Digest32,
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        signature: &[u8],
    ) -> Result<Self, DistributedAgentStackPlanError> {
        if facts.target() != carrier.target() || digest_is_zero(restricted_request_digest) {
            return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(DistributedAgentStackPlanError::InvalidResponseAuthentication);
        }
        let mut canonical_wire = build_restricted_terminal_receipt_fields(
            TERMINAL_RECEIPT_MAGIC,
            DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_VERSION,
            &facts,
            restricted_request_digest,
            &carrier,
        )?;
        canonical_wire.extend_from_slice(&(ED25519_SIGNATURE_BYTES as u16).to_be_bytes());
        canonical_wire.extend_from_slice(signature);
        if canonical_wire.len() > MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        let receipt_digest =
            digest_wire(RESTRICTED_TERMINAL_RECEIPT_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            facts,
            restricted_request_digest,
            carrier,
            signature: signature.into(),
            canonical_wire: canonical_wire.into_boxed_slice(),
            receipt_digest,
        })
    }

    /// Strictly decodes PXDS v2 and cross-rejects the frozen PXDS v1 format.
    pub fn decode(frame: &[u8]) -> Result<Self, DistributedAgentStackPlanError> {
        if frame.len() > MAX_DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_BYTES {
            return Err(DistributedAgentStackPlanError::FrameTooLarge);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.take(4)? != TERMINAL_RECEIPT_MAGIC
            || cursor.u16()? != DISTRIBUTED_AGENT_STACK_TERMINAL_RECEIPT_V2_VERSION
        {
            return Err(DistributedAgentStackPlanError::UnsupportedWire);
        }
        let facts = decode_distributed_terminal_facts(&mut cursor)?;
        let restricted_request_digest = Digest32::from_bytes(cursor.array()?);
        let carrier_digest = Digest32::from_bytes(cursor.array()?);
        let carrier_length = cursor.usize_u16()?;
        if cursor.u16()? != 0
            || digest_is_zero(restricted_request_digest)
            || digest_is_zero(carrier_digest)
            || carrier_length == 0
            || carrier_length > MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
        {
            return Err(DistributedAgentStackPlanError::InvalidLength);
        }
        let carrier = RestrictedRuntimeApplyCarrierBindingV1::decode(cursor.take(carrier_length)?)?;
        if carrier.binding_digest() != carrier_digest {
            return Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch);
        }
        let signature_length = cursor.usize_u16()?;
        if signature_length != ED25519_SIGNATURE_BYTES {
            return Err(DistributedAgentStackPlanError::InvalidResponseAuthentication);
        }
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let decoded = Self::try_new(facts, restricted_request_digest, carrier, signature)?;
        if decoded.canonical_wire() != frame {
            return Err(DistributedAgentStackPlanError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Verifies request/carrier correlation and the Runtime response signature.
    ///
    /// The verifier callback is part of the caller's trusted computing base.
    /// It must resolve the exact Runtime response key selected by the
    /// authenticated carrier, check its fingerprint, and verify Ed25519 over
    /// the supplied transcript; this pure contract crate does not implement
    /// that cryptography. A PXDS v2 is not accepted on PXDS v1's local channel
    /// path and cannot be validated against an unauthenticated PXRC.
    pub fn verify_runtime_response<Verify>(
        &self,
        authenticated_request: ControllerAuthenticatedDistributedAgentStackApplyRequestV1<'_>,
        verify: Verify,
    ) -> Result<&DistributedAgentStackTerminalFactsV1, DistributedAgentStackPlanError>
    where
        Verify: FnOnce(PrincipalRef, ApplyAuthKeyRef, Digest32, &[u8], &[u8]) -> bool,
    {
        self.validate_against_authenticated_request(authenticated_request)?;
        let transcript = self.signing_transcript()?;
        if !verify(
            self.carrier.runtime_principal(),
            self.carrier.runtime_response_key(),
            self.carrier.runtime_response_key_fingerprint(),
            transcript.as_bytes(),
            &self.signature,
        ) {
            return Err(DistributedAgentStackPlanError::InvalidResponseAuthentication);
        }
        Ok(&self.facts)
    }

    fn validate_against_authenticated_request(
        &self,
        authenticated_request: ControllerAuthenticatedDistributedAgentStackApplyRequestV1<'_>,
    ) -> Result<(), DistributedAgentStackPlanError> {
        self.facts
            .validate_against_request(authenticated_request.request())?;
        if self.restricted_request_digest != authenticated_request.restricted_request_digest()
            || &self.carrier != authenticated_request.carrier()
        {
            return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn facts(&self) -> &DistributedAgentStackTerminalFactsV1 {
        &self.facts
    }

    #[must_use]
    pub const fn restricted_request_digest(&self) -> Digest32 {
        self.restricted_request_digest
    }

    #[must_use]
    pub const fn carrier(&self) -> &RestrictedRuntimeApplyCarrierBindingV1 {
        &self.carrier
    }

    #[must_use]
    pub const fn authentication_key(&self) -> ApplyAuthKeyRef {
        self.carrier.runtime_response_key()
    }

    #[must_use]
    pub const fn authentication_key_fingerprint(&self) -> Digest32 {
        self.carrier.runtime_response_key_fingerprint()
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
    ) -> Result<DistributedAgentStackTerminalSigningTranscriptV2, DistributedAgentStackPlanError>
    {
        DistributedAgentStackTerminalReceiptDraftV2 {
            facts: self.facts.clone(),
            restricted_request_digest: self.restricted_request_digest,
            carrier: self.carrier.clone(),
        }
        .signing_transcript()
    }
}

/// Reconstructs one durable `PXTA-zero || PXTE-v7` value from journal authority.
pub fn verify_distributed_agent_stack_durable_slice_v1(
    canonical_slice_wire: &[u8],
    target: RuntimeHostId,
    provenance: PlanProvenance,
    expected_target_slice_digest: TargetSliceDigest,
    projection: &DistributedAgentStackProjectionV1,
) -> Result<DistributedAgentStackTargetExecutionV1, DistributedAgentStackPlanError> {
    if canonical_slice_wire.len() > MAX_DISTRIBUTED_AGENT_STACK_PLAN_SLICE_BYTES {
        return Err(DistributedAgentStackPlanError::FrameTooLarge);
    }
    if canonical_slice_wire.len() < EMPTY_PXTA.len() {
        return Err(DistributedAgentStackPlanError::Truncated);
    }
    let (binding_frame, execution_frame) = canonical_slice_wire.split_at(EMPTY_PXTA.len());
    if binding_frame != EMPTY_PXTA {
        return Err(DistributedAgentStackPlanError::BindingNotAllowed);
    }
    let bindings = TargetAssignments::decode(binding_frame)
        .map_err(|_| DistributedAgentStackPlanError::BindingNotAllowed)?;
    let execution = DistributedAgentStackTargetExecutionV1::decode(execution_frame)?;
    if execution.projection() != projection || execution.projection().target() != target {
        return Err(DistributedAgentStackPlanError::ProjectionMismatch);
    }
    let assignments = DistributedAgentStackAssignmentsV1::try_new(bindings, execution)?;
    let commitment = RuntimeSliceCommitment::try_new(RuntimeSliceHeader::new(
        target,
        provenance,
        assignments.assignment_digest,
    ))?;
    if commitment.target_slice_digest() != expected_target_slice_digest {
        return Err(DistributedAgentStackPlanError::CommitmentMismatch);
    }
    let slice = DistributedAgentStackPlanSliceV1::try_new(commitment, assignments)?;
    Ok(slice.assignments.execution)
}

/// Computes the exact compiled fingerprint embedded in PXDP v1.
///
/// PXRP/PXRC/PXDS v2 are intentionally absent: adding them here would rewrite
/// PXDP, PXTE v7, and PXAR v8 bytes instead of remaining an additive carrier
/// layer.
pub fn distributed_agent_stack_compatibility_digest_v1() -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(COMPATIBILITY_DIGEST_DOMAIN)?;
    builder.field_bytes(PROJECTION_MAGIC)?;
    builder.field_u16(DISTRIBUTED_AGENT_STACK_PROJECTION_VERSION)?;
    builder.field_u16(PROJECTION_BYTES as u16)?;
    builder.field_bytes(TARGET_EXECUTION_MAGIC)?;
    builder.field_u16(DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_VERSION)?;
    builder
        .field_bytes(&(MAX_DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_BYTES as u32).to_be_bytes())?;
    builder.field_bytes(APPLY_REQUEST_MAGIC)?;
    builder.field_u16(DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_VERSION)?;
    builder.field_u16(APPLY_REQUEST_HEADER_BYTES as u16)?;
    builder.field_bytes(&(MAX_DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_BYTES as u32).to_be_bytes())?;
    builder.field_u16(DISTRIBUTED_AGENT_STACK_PROFILE_VERSION)?;
    builder.field_u16(MANAGED_AGENT_STACK_TARGET_EXECUTION_VERSION)?;
    builder.field_u16(MANAGED_FABRIC_APPLY_ENVELOPE_VERSION)?;
    builder.field_u16(MANAGED_FABRIC_APPLY_SIGNING_TRANSCRIPT_VERSION)?;
    builder.field_bytes(TARGET_EXECUTION_DIGEST_DOMAIN)?;
    builder.field_bytes(TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN)?;
    builder.field_bytes(TOPOLOGY_MAGIC)?;
    builder.field_u16(DISTRIBUTED_FABRIC_TOPOLOGY_VERSION)?;
    builder.field_bytes(&(MAX_DISTRIBUTED_FABRIC_TOPOLOGY_BYTES as u32).to_be_bytes())?;
    builder.field_u16(DISTRIBUTED_FABRIC_AUTHENTICATION_REQUIREMENT_VERSION)?;
    builder.field_bytes(PEER_REQUIREMENT_DIGEST_DOMAIN)?;
    builder.field_u16(MAX_DISTRIBUTED_FABRIC_PEERS as u16)?;
    builder.field_u16(MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES as u16)?;
    builder.field_bytes(TLS_PREFIX.as_bytes())?;
    builder.field_u16(DistributedFabricAuthenticationProfileV1::MutualTlsPeerIdentity as u16)?;
    builder.field_bytes(TRANSPORT_PROOF_MAGIC)?;
    builder.field_u16(DISTRIBUTED_FABRIC_TRANSPORT_PROOF_VERSION)?;
    builder.field_u16(TRANSPORT_PROOF_BYTES as u16)?;
    builder.field_bytes(&EMPTY_PXTA)?;
    Ok(builder.finish())
}

fn build_projection_wire(
    predecessor: &ManagedAgentStackProjectionV1,
    compatibility_digest: Digest32,
) -> Vec<u8> {
    let mut wire = Vec::with_capacity(PROJECTION_BYTES);
    wire.extend_from_slice(PROJECTION_MAGIC);
    wire.extend_from_slice(&DISTRIBUTED_AGENT_STACK_PROJECTION_VERSION.to_be_bytes());
    wire.extend_from_slice(predecessor.canonical_wire());
    wire.extend_from_slice(compatibility_digest.as_bytes());
    wire.extend_from_slice(&DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_VERSION.to_be_bytes());
    wire.extend_from_slice(&DISTRIBUTED_AGENT_STACK_PROFILE_VERSION.to_be_bytes());
    wire
}

fn build_topology_wire(
    base_loopback: &ManagedFabricListenEndpointV1,
    remote_listen: &DistributedFabricTlsEndpointV1,
    peers: &[DistributedFabricPeerPlanV1],
) -> Result<Vec<u8>, DistributedAgentStackPlanError> {
    let base_length = u16::try_from(base_loopback.as_str().len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let listen_length = u16::try_from(remote_listen.as_str().len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let peer_count =
        u16::try_from(peers.len()).map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(TOPOLOGY_MAGIC);
    wire.extend_from_slice(&DISTRIBUTED_FABRIC_TOPOLOGY_VERSION.to_be_bytes());
    wire.extend_from_slice(&base_length.to_be_bytes());
    wire.extend_from_slice(&listen_length.to_be_bytes());
    wire.extend_from_slice(&peer_count.to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(base_loopback.as_str().as_bytes());
    wire.extend_from_slice(remote_listen.as_str().as_bytes());
    for peer in peers {
        let endpoint_length = u16::try_from(peer.connect_endpoint().as_str().len())
            .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
        let authentication = peer.authentication();
        wire.extend_from_slice(peer.peer_runtime_host().as_bytes());
        wire.extend_from_slice(&endpoint_length.to_be_bytes());
        wire.extend_from_slice(&(authentication.profile() as u16).to_be_bytes());
        wire.extend_from_slice(authentication.trust_domain_ref().as_bytes());
        wire.extend_from_slice(authentication.local_credential_ref().as_bytes());
        wire.extend_from_slice(authentication.trust_anchor_ref().as_bytes());
        wire.extend_from_slice(authentication.expected_peer_identity_ref().as_bytes());
        wire.extend_from_slice(peer.connect_endpoint().as_str().as_bytes());
    }
    Ok(wire)
}

fn build_target_execution_wire(
    projection: &DistributedAgentStackProjectionV1,
    mode: DistributedAgentStackTargetModeV1,
    predecessor: &ManagedAgentStackTargetExecutionV1,
    topology: Option<&DistributedFabricTopologyV1>,
) -> Result<Vec<u8>, DistributedAgentStackPlanError> {
    let predecessor_length = u32::try_from(predecessor.canonical_wire().len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let topology_length = u32::try_from(topology.map_or(0, |value| value.canonical_wire().len()))
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(TARGET_EXECUTION_MAGIC);
    wire.extend_from_slice(&DISTRIBUTED_AGENT_STACK_TARGET_EXECUTION_VERSION.to_be_bytes());
    wire.extend_from_slice(projection.canonical_wire());
    wire.extend_from_slice(&DISTRIBUTED_AGENT_STACK_PROFILE_VERSION.to_be_bytes());
    wire.push(mode as u8);
    wire.push(u8::from(topology.is_some()));
    wire.extend_from_slice(&predecessor_length.to_be_bytes());
    wire.extend_from_slice(&topology_length.to_be_bytes());
    wire.extend_from_slice(predecessor.canonical_wire());
    if let Some(topology) = topology {
        wire.extend_from_slice(topology.canonical_wire());
    }
    Ok(wire)
}

fn build_apply_request_wire(
    envelope: &RuntimeApplyEnvelopeV2,
    slice: &DistributedAgentStackPlanSliceV1,
) -> Result<Vec<u8>, DistributedAgentStackPlanError> {
    let envelope_length = u32::try_from(envelope.canonical_wire().len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let bindings_length = u32::try_from(slice.assignments.bindings.canonical_wire().len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let execution_length = u32::try_from(slice.assignments.execution.canonical_wire().len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(APPLY_REQUEST_MAGIC);
    wire.extend_from_slice(&DISTRIBUTED_AGENT_STACK_APPLY_REQUEST_VERSION.to_be_bytes());
    wire.extend_from_slice(&envelope_length.to_be_bytes());
    wire.extend_from_slice(&bindings_length.to_be_bytes());
    wire.extend_from_slice(&execution_length.to_be_bytes());
    wire.extend_from_slice(envelope.canonical_wire());
    wire.extend_from_slice(slice.assignments.bindings.canonical_wire());
    wire.extend_from_slice(slice.assignments.execution.canonical_wire());
    Ok(wire)
}

fn validate_restricted_runtime_apply_route(
    route: &str,
) -> Result<(), DistributedAgentStackPlanError> {
    if route.is_empty()
        || route.len() > MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES
        || !route.is_ascii()
        || route.starts_with('/')
        || route.ends_with('/')
        || route.contains("//")
        || !route.starts_with("paraegox/")
        || !route.ends_with("/apply")
        || route
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        || route.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        })
    {
        return Err(DistributedAgentStackPlanError::InvalidCarrierBinding);
    }
    Ok(())
}

fn build_restricted_transport_profile_wire(
    fields: RestrictedRuntimeApplyTransportProfileFieldsV1<'_>,
) -> Result<Vec<u8>, DistributedAgentStackPlanError> {
    let locator_length = u16::try_from(fields.tls_listener_locator.len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let route_length = u16::try_from(fields.route.len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let mut wire = Vec::with_capacity(
        RESTRICTED_TRANSPORT_PROFILE_FIXED_BYTES
            + fields.tls_listener_locator.len()
            + fields.route.len(),
    );
    wire.extend_from_slice(RESTRICTED_TRANSPORT_PROFILE_MAGIC);
    wire.extend_from_slice(&RESTRICTED_RUNTIME_APPLY_TRANSPORT_PROFILE_VERSION.to_be_bytes());
    wire.extend_from_slice(&RESTRICTED_ZENOH_TLS_QUERY_PROFILE_KIND.to_be_bytes());
    wire.extend_from_slice(&locator_length.to_be_bytes());
    wire.extend_from_slice(&route_length.to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(fields.target.as_bytes());
    wire.extend_from_slice(&fields.endpoint_ref);
    wire.extend_from_slice(&fields.endpoint_generation.to_be_bytes());
    wire.extend_from_slice(fields.controller_principal.as_bytes());
    wire.extend_from_slice(fields.runtime_principal.as_bytes());
    wire.extend_from_slice(fields.trust_domain_ref.as_bytes());
    wire.extend_from_slice(fields.trust_anchor_ref.as_bytes());
    wire.extend_from_slice(fields.controller_connector_credential_ref.as_bytes());
    wire.extend_from_slice(fields.runtime_listener_credential_ref.as_bytes());
    wire.extend_from_slice(&fields.operation_timeout_nanos.to_be_bytes());
    wire.extend_from_slice(fields.tls_listener_locator.as_bytes());
    wire.extend_from_slice(fields.route.as_bytes());
    Ok(wire)
}

fn build_restricted_carrier_binding_wire(
    fields: RestrictedRuntimeApplyCarrierBindingFieldsV1<'_>,
) -> Result<Vec<u8>, DistributedAgentStackPlanError> {
    let route_length = u16::try_from(fields.route.len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let mut wire = Vec::with_capacity(RESTRICTED_CARRIER_BINDING_FIXED_BYTES + fields.route.len());
    wire.extend_from_slice(RESTRICTED_CARRIER_BINDING_MAGIC);
    wire.extend_from_slice(&RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_VERSION.to_be_bytes());
    wire.extend_from_slice(&RESTRICTED_ZENOH_QUERY_CARRIER_KIND.to_be_bytes());
    wire.extend_from_slice(&route_length.to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(fields.target.as_bytes());
    wire.extend_from_slice(fields.runtime_principal.as_bytes());
    wire.extend_from_slice(fields.controller_principal.as_bytes());
    wire.extend_from_slice(&fields.endpoint_ref);
    wire.extend_from_slice(&fields.endpoint_generation.to_be_bytes());
    wire.extend_from_slice(fields.controller_request_key.as_bytes());
    wire.extend_from_slice(fields.controller_request_key_fingerprint.as_bytes());
    wire.extend_from_slice(fields.runtime_response_key.as_bytes());
    wire.extend_from_slice(fields.runtime_response_key_fingerprint.as_bytes());
    wire.extend_from_slice(&fields.control_transport_profile_ref);
    wire.extend_from_slice(fields.control_transport_profile_digest.as_bytes());
    wire.extend_from_slice(fields.route.as_bytes());
    Ok(wire)
}

fn validate_restricted_request_carrier(
    request: &DistributedAgentStackApplyRequestV1,
    carrier: &RestrictedRuntimeApplyCarrierBindingV1,
) -> Result<(), DistributedAgentStackPlanError> {
    let claim = request.authentication().claim();
    if request.target() != carrier.target()
        || claim.principal() != carrier.controller_principal()
        || claim.key() != carrier.controller_request_key()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
    {
        return Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch);
    }
    Ok(())
}

fn build_restricted_apply_request_fields(
    magic: &[u8],
    version: u16,
    carrier: &RestrictedRuntimeApplyCarrierBindingV1,
    request: &DistributedAgentStackApplyRequestV1,
    request_wire_digest: Digest32,
) -> Result<Vec<u8>, DistributedAgentStackPlanError> {
    validate_restricted_request_carrier(request, carrier)?;
    let expected_request_wire_digest = digest_wire(
        DISTRIBUTED_APPLY_REQUEST_WIRE_DIGEST_DOMAIN,
        request.canonical_wire(),
    )?;
    if request_wire_digest != expected_request_wire_digest {
        return Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch);
    }
    let carrier_length = u16::try_from(carrier.canonical_wire().len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let request_length = u32::try_from(request.canonical_wire().len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&version.to_be_bytes());
    wire.extend_from_slice(&carrier_length.to_be_bytes());
    wire.extend_from_slice(&request_length.to_be_bytes());
    wire.extend_from_slice(carrier.binding_digest().as_bytes());
    wire.extend_from_slice(request_wire_digest.as_bytes());
    wire.extend_from_slice(carrier.canonical_wire());
    wire.extend_from_slice(request.canonical_wire());
    Ok(wire)
}

fn build_transport_proof_wire(
    fields: DistributedFabricObservedTransportProofFieldsV1,
    profile: DistributedFabricAuthenticationProfileV1,
    requirement_digest: Digest32,
) -> Vec<u8> {
    let mut wire = Vec::with_capacity(TRANSPORT_PROOF_BYTES);
    wire.extend_from_slice(TRANSPORT_PROOF_MAGIC);
    wire.extend_from_slice(&DISTRIBUTED_FABRIC_TRANSPORT_PROOF_VERSION.to_be_bytes());
    wire.extend_from_slice(fields.local_runtime_host.as_bytes());
    wire.extend_from_slice(fields.peer_runtime_host.as_bytes());
    wire.extend_from_slice(fields.session_epoch.as_bytes());
    wire.extend_from_slice(fields.authenticated_peer_identity_ref.as_bytes());
    wire.extend_from_slice(fields.selected_local_credential_ref.as_bytes());
    wire.extend_from_slice(fields.transport_evidence_ref.as_bytes());
    wire.extend_from_slice(&(profile as u16).to_be_bytes());
    wire.extend_from_slice(requirement_digest.as_bytes());
    wire.extend_from_slice(&fields.observation_sequence.to_be_bytes());
    wire
}

fn terminal_topology_digest(
    topology: &DistributedFabricTopologyV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TERMINAL_TOPOLOGY_DIGEST_DOMAIN)?;
    builder.field_bytes(topology.canonical_wire())?;
    Ok(builder.finish())
}

fn terminal_remote_observation_digest(
    target: RuntimeHostId,
    local_loopback_endpoint: &ManagedFabricListenEndpointV1,
    remote_listen_endpoint: &DistributedFabricTlsEndpointV1,
    topology_digest: Digest32,
    proofs: &[DistributedFabricObservedTransportProofV1],
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TERMINAL_REMOTE_OBSERVATION_DIGEST_DOMAIN)?;
    builder.field_bytes(target.as_bytes())?;
    builder.field_bytes(local_loopback_endpoint.as_str().as_bytes())?;
    builder.field_bytes(remote_listen_endpoint.as_str().as_bytes())?;
    builder.field_digest(&topology_digest)?;
    builder.field_u16(u16::try_from(proofs.len()).map_err(|_| DigestBuildError::FieldTooLong)?)?;
    for proof in proofs {
        builder.field_bytes(proof.canonical_wire())?;
    }
    Ok(builder.finish())
}

fn validate_terminal_outcome(
    outcome: DistributedAgentStackTerminalOutcomeV1,
    evidence: DistributedAgentStackTerminalEvidenceFieldsV1,
) -> Result<(), DistributedAgentStackPlanError> {
    let local = evidence.local_bindings;
    let empty_binding_set_digest = distributed_agent_stack_empty_binding_set_digest_v1()?;
    if evidence.runtime_host_epoch == 0
        || evidence.completion_snapshot_sequence == 0
        || evidence.selection_observed_at_nanos == 0
        || evidence.agent_generation.is_some() && evidence.fabric_generation.is_none()
        || local.physical_binding_census > 2
        || local.agent_ready && (!local.fabric_ready || !local.dependency_satisfied)
        || local.exact_zero
            && (local.physical_binding_census != 0
                || !local.census_complete
                || local.fabric_ready
                || local.agent_ready
                || local.dependency_satisfied
                || local.quarantined
                || evidence.fabric_generation.is_some()
                || evidence.agent_generation.is_some())
        || local.census_complete && local.physical_binding_census == 0 && !local.exact_zero
        || local.exact_zero && local.installed_binding_set_digest != empty_binding_set_digest
        || local.physical_binding_census > 0
            && local.installed_binding_set_digest == empty_binding_set_digest
        || digest_is_zero(local.installed_binding_set_digest)
        || digest_is_zero(local.raw_outcome_digest)
        || outcome == DistributedAgentStackTerminalOutcomeV1::EmptyExactZero
            && (!local.exact_zero
                || !local.census_complete
                || local.physical_binding_census != 0
                || local.fabric_ready
                || local.agent_ready
                || local.dependency_satisfied
                || local.quarantined
                || evidence.fabric_generation.is_some()
                || evidence.agent_generation.is_some())
        || outcome != DistributedAgentStackTerminalOutcomeV1::EmptyExactZero && local.exact_zero
        || outcome == DistributedAgentStackTerminalOutcomeV1::ActiveReady
            && (evidence.fabric_generation.is_none()
                || evidence.agent_generation.is_none()
                || local.physical_binding_census != 2
                || !local.census_complete
                || !local.fabric_ready
                || !local.agent_ready
                || !local.dependency_satisfied
                || local.exact_zero
                || local.quarantined)
        || outcome == DistributedAgentStackTerminalOutcomeV1::ActiveReady
            && local.installed_binding_set_digest == empty_binding_set_digest
    {
        return Err(DistributedAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(())
}

fn build_distributed_terminal_fields(
    magic: &[u8],
    version: u16,
    facts: &DistributedAgentStackTerminalFactsV1,
    channel: ReferenceChannelBindingV1,
    auth: DistributedAgentStackTerminalAuthClaimV1,
) -> Result<Vec<u8>, DistributedAgentStackPlanError> {
    let mut wire = Vec::new();
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&version.to_be_bytes());
    append_distributed_terminal_facts(&mut wire, facts)?;
    encode_distributed_terminal_channel(&mut wire, channel);
    encode_distributed_terminal_auth_claim(&mut wire, auth);
    Ok(wire)
}

fn build_restricted_terminal_receipt_fields(
    magic: &[u8],
    version: u16,
    facts: &DistributedAgentStackTerminalFactsV1,
    restricted_request_digest: Digest32,
    carrier: &RestrictedRuntimeApplyCarrierBindingV1,
) -> Result<Vec<u8>, DistributedAgentStackPlanError> {
    if digest_is_zero(restricted_request_digest) || facts.target() != carrier.target() {
        return Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch);
    }
    let carrier_length = u16::try_from(carrier.canonical_wire().len())
        .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&version.to_be_bytes());
    append_distributed_terminal_facts(&mut wire, facts)?;
    wire.extend_from_slice(restricted_request_digest.as_bytes());
    wire.extend_from_slice(carrier.binding_digest().as_bytes());
    wire.extend_from_slice(&carrier_length.to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(carrier.canonical_wire());
    Ok(wire)
}

fn append_distributed_terminal_facts(
    wire: &mut Vec<u8>,
    facts: &DistributedAgentStackTerminalFactsV1,
) -> Result<(), DistributedAgentStackPlanError> {
    validate_terminal_outcome(facts.outcome, facts.evidence)?;
    if (facts.outcome == DistributedAgentStackTerminalOutcomeV1::EmptyExactZero)
        != facts.observations.is_none()
    {
        return Err(DistributedAgentStackPlanError::InvalidTerminalFacts);
    }
    let (local_length, remote_length, proof_count) = match facts.observations.as_ref() {
        Some(observations) => (
            u16::try_from(observations.local_loopback_endpoint().as_str().len())
                .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?,
            u16::try_from(observations.remote_listen_endpoint().as_str().len())
                .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?,
            u16::try_from(observations.proofs().len())
                .map_err(|_| DistributedAgentStackPlanError::InvalidLength)?,
        ),
        None => (0, 0, 0),
    };
    wire.extend_from_slice(facts.target.as_bytes());
    wire.extend_from_slice(&facts.runtime_store_instance_id);
    wire.extend_from_slice(facts.operation_id.as_bytes());
    wire.extend_from_slice(facts.request_digest.as_bytes());
    wire.extend_from_slice(facts.target_slice_digest.value().as_bytes());
    wire.push(facts.outcome as u8);
    wire.extend_from_slice(&facts.evidence.runtime_host_epoch.to_be_bytes());
    wire.extend_from_slice(&facts.evidence.completion_snapshot_sequence.to_be_bytes());
    wire.extend_from_slice(
        &facts
            .evidence
            .selection_clock_generation
            .value()
            .to_be_bytes(),
    );
    wire.extend_from_slice(&facts.evidence.selection_observed_at_nanos.to_be_bytes());
    encode_distributed_generation(wire, facts.evidence.fabric_generation);
    encode_distributed_generation(wire, facts.evidence.agent_generation);
    encode_distributed_local_binding_evidence(wire, facts.evidence.local_bindings);
    wire.extend_from_slice(&local_length.to_be_bytes());
    wire.extend_from_slice(&remote_length.to_be_bytes());
    wire.extend_from_slice(&proof_count.to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    match facts.observations.as_ref() {
        Some(observations) => {
            wire.extend_from_slice(observations.topology_digest().as_bytes());
            wire.extend_from_slice(observations.remote_observation_digest().as_bytes());
            wire.extend_from_slice(observations.local_loopback_endpoint().as_str().as_bytes());
            wire.extend_from_slice(observations.remote_listen_endpoint().as_str().as_bytes());
            for proof in observations.proofs() {
                wire.extend_from_slice(proof.canonical_wire());
            }
        }
        None => {
            wire.extend_from_slice(&[0; 32]);
            wire.extend_from_slice(&[0; 32]);
        }
    }
    Ok(())
}

fn encode_distributed_generation(wire: &mut Vec<u8>, generation: Option<ManagedServiceGeneration>) {
    wire.push(u8::from(generation.is_some()));
    wire.extend_from_slice(
        &generation
            .map_or(0, ManagedServiceGeneration::value)
            .to_be_bytes(),
    );
}

fn decode_distributed_generation(
    cursor: &mut Cursor<'_>,
) -> Result<Option<ManagedServiceGeneration>, DistributedAgentStackPlanError> {
    match (cursor.u8()?, cursor.u64()?) {
        (0, 0) => Ok(None),
        (1, value) => ManagedServiceGeneration::try_new(value)
            .map(Some)
            .map_err(|_| DistributedAgentStackPlanError::InvalidTerminalFacts),
        _ => Err(DistributedAgentStackPlanError::InvalidTerminalFacts),
    }
}

fn encode_distributed_local_binding_evidence(
    wire: &mut Vec<u8>,
    fields: DistributedAgentStackLocalBindingEvidenceFieldsV1,
) {
    wire.extend_from_slice(&fields.physical_binding_census.to_be_bytes());
    let flags = u8::from(fields.census_complete)
        | (u8::from(fields.fabric_ready) << 1)
        | (u8::from(fields.agent_ready) << 2)
        | (u8::from(fields.dependency_satisfied) << 3)
        | (u8::from(fields.exact_zero) << 4)
        | (u8::from(fields.quarantined) << 5);
    wire.push(flags);
    wire.push(0);
    wire.extend_from_slice(fields.installed_binding_set_digest.as_bytes());
    wire.extend_from_slice(fields.raw_outcome_digest.as_bytes());
}

fn decode_distributed_local_binding_evidence(
    cursor: &mut Cursor<'_>,
) -> Result<DistributedAgentStackLocalBindingEvidenceFieldsV1, DistributedAgentStackPlanError> {
    let physical_binding_census = cursor.u16()?;
    let flags = cursor.u8()?;
    if flags & !0x3f != 0 || cursor.u8()? != 0 {
        return Err(DistributedAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(DistributedAgentStackLocalBindingEvidenceFieldsV1 {
        physical_binding_census,
        census_complete: flags & 1 != 0,
        fabric_ready: flags & 2 != 0,
        agent_ready: flags & 4 != 0,
        dependency_satisfied: flags & 8 != 0,
        exact_zero: flags & 16 != 0,
        quarantined: flags & 32 != 0,
        installed_binding_set_digest: Digest32::from_bytes(cursor.array()?),
        raw_outcome_digest: Digest32::from_bytes(cursor.array()?),
    })
}

fn decode_distributed_terminal_facts(
    cursor: &mut Cursor<'_>,
) -> Result<DistributedAgentStackTerminalFactsV1, DistributedAgentStackPlanError> {
    let target = RuntimeHostId::from_bytes(cursor.array()?);
    let runtime_store_instance_id = cursor.array()?;
    let operation_id = ApplyOperationId::from_bytes(cursor.array()?);
    let request_digest = Digest32::from_bytes(cursor.array()?);
    let target_slice_digest = TargetSliceDigest::new(Digest32::from_bytes(cursor.array()?));
    let outcome = match cursor.u8()? {
        1 => DistributedAgentStackTerminalOutcomeV1::ActiveReady,
        2 => DistributedAgentStackTerminalOutcomeV1::TerminalNonReady,
        3 => DistributedAgentStackTerminalOutcomeV1::IndeterminateUncertain,
        4 => DistributedAgentStackTerminalOutcomeV1::EmptyExactZero,
        _ => return Err(DistributedAgentStackPlanError::InvalidTerminalFacts),
    };
    let evidence = DistributedAgentStackTerminalEvidenceFieldsV1 {
        runtime_host_epoch: cursor.u64()?,
        completion_snapshot_sequence: cursor.u64()?,
        selection_clock_generation: ClockGeneration::try_new(cursor.u64()?)
            .map_err(|_| DistributedAgentStackPlanError::InvalidTerminalFacts)?,
        selection_observed_at_nanos: cursor.u64()?,
        fabric_generation: decode_distributed_generation(cursor)?,
        agent_generation: decode_distributed_generation(cursor)?,
        local_bindings: decode_distributed_local_binding_evidence(cursor)?,
    };
    let local_length = cursor.usize_u16()?;
    let remote_length = cursor.usize_u16()?;
    let proof_count = cursor.usize_u16()?;
    if cursor.u16()? != 0 || proof_count > MAX_DISTRIBUTED_FABRIC_PEERS {
        return Err(DistributedAgentStackPlanError::InvalidLength);
    }
    let topology_digest = Digest32::from_bytes(cursor.array()?);
    let remote_observation_digest = Digest32::from_bytes(cursor.array()?);
    let observations = if outcome == DistributedAgentStackTerminalOutcomeV1::EmptyExactZero {
        if local_length != 0
            || remote_length != 0
            || proof_count != 0
            || !digest_is_zero(topology_digest)
            || !digest_is_zero(remote_observation_digest)
        {
            return Err(DistributedAgentStackPlanError::InvalidTerminalFacts);
        }
        None
    } else {
        if local_length == 0
            || local_length > MAX_BASE_LOOPBACK_ENDPOINT_BYTES
            || remote_length == 0
            || remote_length > MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES
        {
            return Err(DistributedAgentStackPlanError::InvalidLength);
        }
        let local_loopback_endpoint = ManagedFabricListenEndpointV1::try_new(
            core::str::from_utf8(cursor.take(local_length)?)
                .map_err(|_| DistributedAgentStackPlanError::InvalidEndpoint)?,
        )?;
        let remote_listen_endpoint = DistributedFabricTlsEndpointV1::try_new(
            core::str::from_utf8(cursor.take(remote_length)?)
                .map_err(|_| DistributedAgentStackPlanError::InvalidEndpoint)?,
        )?;
        let mut proofs = Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            proofs.push(DistributedFabricObservedTransportProofV1::decode(
                cursor.take(TRANSPORT_PROOF_BYTES)?,
            )?);
        }
        Some(
            DistributedAgentStackTerminalObservationsV1::try_from_decoded_parts(
                target,
                local_loopback_endpoint,
                remote_listen_endpoint,
                topology_digest,
                remote_observation_digest,
                proofs,
            )?,
        )
    };
    validate_terminal_outcome(outcome, evidence)?;
    if bytes_are_zero(target.as_bytes())
        || bytes_are_zero(&runtime_store_instance_id)
        || bytes_are_zero(operation_id.as_bytes())
        || digest_is_zero(request_digest)
        || digest_is_zero(*target_slice_digest.value())
    {
        return Err(DistributedAgentStackPlanError::InvalidTerminalFacts);
    }
    Ok(DistributedAgentStackTerminalFactsV1 {
        target,
        runtime_store_instance_id,
        operation_id,
        request_digest,
        target_slice_digest,
        outcome,
        evidence,
        observations,
    })
}

fn encode_distributed_terminal_channel(wire: &mut Vec<u8>, channel: ReferenceChannelBindingV1) {
    wire.extend_from_slice(channel.target().as_bytes());
    wire.extend_from_slice(channel.runtime_peer().as_bytes());
    wire.extend_from_slice(channel.local_endpoint_identity_digest().as_bytes());
    wire.extend_from_slice(channel.peer_credentials_digest().as_bytes());
}

fn decode_distributed_terminal_channel(
    cursor: &mut Cursor<'_>,
) -> Result<ReferenceChannelBindingV1, DistributedAgentStackPlanError> {
    ReferenceChannelBindingV1::try_new(
        RuntimeHostId::from_bytes(cursor.array()?),
        PrincipalRef::from_bytes(cursor.array()?),
        Digest32::from_bytes(cursor.array()?),
        Digest32::from_bytes(cursor.array()?),
    )
    .map_err(|_| DistributedAgentStackPlanError::InvalidResponseAuthentication)
}

fn encode_distributed_terminal_auth_claim(
    wire: &mut Vec<u8>,
    auth: DistributedAgentStackTerminalAuthClaimV1,
) {
    wire.extend_from_slice(auth.runtime_peer().as_bytes());
    wire.extend_from_slice(auth.channel_binding_digest().as_bytes());
    wire.extend_from_slice(auth.key().as_bytes());
    wire.extend_from_slice(&auth.algorithm().value().to_be_bytes());
    wire.extend_from_slice(&auth.algorithm_version().to_be_bytes());
}

fn decode_distributed_terminal_auth_claim(
    cursor: &mut Cursor<'_>,
) -> Result<DistributedAgentStackTerminalAuthClaimV1, DistributedAgentStackPlanError> {
    let runtime_peer = PrincipalRef::from_bytes(cursor.array()?);
    let channel_binding_digest = Digest32::from_bytes(cursor.array()?);
    let key = ApplyAuthKeyRef::from_bytes(cursor.array()?);
    let algorithm = ApplyAuthAlgorithm::try_new(cursor.u16()?)
        .map_err(|_| DistributedAgentStackPlanError::InvalidResponseAuthentication)?;
    let algorithm_version = cursor.u16()?;
    if bytes_are_zero(runtime_peer.as_bytes())
        || digest_is_zero(channel_binding_digest)
        || bytes_are_zero(key.as_bytes())
        || algorithm.value() != ED25519_ALGORITHM
        || algorithm_version != ED25519_ALGORITHM_VERSION
    {
        return Err(DistributedAgentStackPlanError::InvalidResponseAuthentication);
    }
    Ok(DistributedAgentStackTerminalAuthClaimV1 {
        runtime_peer,
        channel_binding_digest,
        key,
        algorithm,
        algorithm_version,
    })
}

fn validate_topology(
    local_runtime_host: RuntimeHostId,
    remote_listen: &DistributedFabricTlsEndpointV1,
    peers: &[DistributedFabricPeerPlanV1],
) -> Result<(), DistributedAgentStackPlanError> {
    if bytes_are_zero(local_runtime_host.as_bytes())
        || peers.is_empty()
        || peers.len() > MAX_DISTRIBUTED_FABRIC_PEERS
    {
        return Err(DistributedAgentStackPlanError::InvalidTopology);
    }
    let session_authentication = peers[0].authentication();
    for (index, peer) in peers.iter().enumerate() {
        let authentication = peer.authentication();
        if peer.peer_runtime_host() == local_runtime_host
            || peer.connect_endpoint() == remote_listen
            || authentication.profile() != session_authentication.profile()
            || authentication.trust_domain_ref() != session_authentication.trust_domain_ref()
            || authentication.local_credential_ref()
                != session_authentication.local_credential_ref()
            || authentication.trust_anchor_ref() != session_authentication.trust_anchor_ref()
        {
            return Err(DistributedAgentStackPlanError::InvalidTopology);
        }
        if let Some(previous) = index.checked_sub(1).and_then(|value| peers.get(value))
            && (previous.peer_runtime_host().as_bytes() >= peer.peer_runtime_host().as_bytes()
                || previous.connect_endpoint() == peer.connect_endpoint()
                || previous.authentication().expected_peer_identity_ref()
                    == authentication.expected_peer_identity_ref())
        {
            return Err(DistributedAgentStackPlanError::NonCanonicalTopology);
        }
        for earlier in &peers[..index] {
            if earlier.connect_endpoint() == peer.connect_endpoint()
                || earlier.authentication().expected_peer_identity_ref()
                    == authentication.expected_peer_identity_ref()
            {
                return Err(DistributedAgentStackPlanError::InvalidTopology);
            }
        }
    }
    Ok(())
}

fn peer_requirement_digest(
    peer_runtime_host: RuntimeHostId,
    connect_endpoint: &DistributedFabricTlsEndpointV1,
    authentication: DistributedFabricPeerAuthenticationRequirementV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(PEER_REQUIREMENT_DIGEST_DOMAIN)?;
    builder.field_u16(DISTRIBUTED_FABRIC_AUTHENTICATION_REQUIREMENT_VERSION)?;
    builder.field_bytes(peer_runtime_host.as_bytes())?;
    builder.field_bytes(connect_endpoint.as_str().as_bytes())?;
    builder.field_u16(authentication.profile() as u16)?;
    builder.field_bytes(authentication.trust_domain_ref().as_bytes())?;
    builder.field_bytes(authentication.local_credential_ref().as_bytes())?;
    builder.field_bytes(authentication.trust_anchor_ref().as_bytes())?;
    builder.field_bytes(authentication.expected_peer_identity_ref().as_bytes())?;
    Ok(builder.finish())
}

fn decode_authentication_profile(
    value: u16,
) -> Result<DistributedFabricAuthenticationProfileV1, DistributedAgentStackPlanError> {
    match value {
        1 => Ok(DistributedFabricAuthenticationProfileV1::MutualTlsPeerIdentity),
        _ => Err(DistributedAgentStackPlanError::InvalidAuthenticationRequirement),
    }
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
    let mut output = [0; N];
    output.copy_from_slice(bytes);
    output
}

struct Cursor<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DistributedAgentStackPlanError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DistributedAgentStackPlanError::FrameTooLarge)?;
        let value = self
            .frame
            .get(self.position..end)
            .ok_or(DistributedAgentStackPlanError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DistributedAgentStackPlanError> {
        Ok(read_array(self.take(N)?))
    }

    fn u8(&mut self) -> Result<u8, DistributedAgentStackPlanError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, DistributedAgentStackPlanError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, DistributedAgentStackPlanError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DistributedAgentStackPlanError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize_u16(&mut self) -> Result<usize, DistributedAgentStackPlanError> {
        Ok(usize::from(self.u16()?))
    }

    fn usize_u32(&mut self) -> Result<usize, DistributedAgentStackPlanError> {
        usize::try_from(self.u32()?).map_err(|_| DistributedAgentStackPlanError::FrameTooLarge)
    }

    fn finish(self) -> Result<(), DistributedAgentStackPlanError> {
        if self.position == self.frame.len() {
            Ok(())
        } else {
            Err(DistributedAgentStackPlanError::TrailingBytes)
        }
    }
}

/// Stable construction and codec failures for the distributed stack protocols.
#[derive(Debug)]
pub enum DistributedAgentStackPlanError {
    /// The fixed active-or-empty shape was violated.
    InvalidShape,
    /// Endpoint text was not canonical non-loopback IPv4 TLS-over-TCP.
    InvalidEndpoint,
    /// A remote peer row was invalid.
    InvalidPeer,
    /// Desired authentication references or profile were invalid.
    InvalidAuthenticationRequirement,
    /// The explicit topology was internally inconsistent.
    InvalidTopology,
    /// Peer rows were not in strict canonical order.
    NonCanonicalTopology,
    /// An observed proof payload contained invalid fields.
    InvalidTransportProof,
    /// An observed proof did not match the desired peer row.
    TransportProofMismatch,
    /// The restricted Runtime apply-carrier binding was malformed.
    InvalidCarrierBinding,
    /// The restricted Runtime apply transport profile was malformed.
    InvalidTransportProfile,
    /// PXAR, PXRC, or PXDS selected different carrier/request facts.
    CarrierCorrelationMismatch,
    /// The outer PXRC Controller signature was malformed or rejected.
    InvalidCarrierAuthentication,
    /// Signed terminal facts were internally inconsistent.
    InvalidTerminalFacts,
    /// Signed terminal facts did not match the exact PXAR v8 request or channel.
    TerminalCorrelationMismatch,
    /// RuntimeHost response authentication fields were invalid.
    InvalidResponseAuthentication,
    /// A variable-length field or frame length was invalid.
    InvalidLength,
    /// The locally derived projection did not match desired bytes.
    ProjectionMismatch,
    /// Compiled compatibility fields did not match this implementation.
    CompatibilityMismatch,
    /// Slice or control commitment correlation failed.
    CommitmentMismatch,
    /// Target identity did not match the slice target.
    TargetMismatch,
    /// Nonempty PXTA bindings are not admitted by this successor.
    BindingNotAllowed,
    /// Magic, version, or fixed profile was unsupported.
    UnsupportedWire,
    /// The frame ended before all declared fields.
    Truncated,
    /// Bytes remained after the canonical value.
    TrailingBytes,
    /// The frame exceeded a contract-owned hard bound.
    FrameTooLarge,
    /// Decoded bytes were not the unique canonical encoding.
    NonCanonicalFrame,
    /// Digest construction failed.
    Digest(DigestBuildError),
    /// The frozen fixed-stack predecessor rejected a value.
    Stack(ManagedAgentStackPlanError),
    /// Provenance validation failed.
    Provenance(crate::provenance::ProvenanceContractError),
    /// Apply-control validation failed.
    Apply(crate::apply::ApplyContractError),
    /// The shared envelope contract rejected a value.
    ReferenceContract,
    /// The shared envelope wire codec rejected a value.
    ReferenceWire,
}

impl From<DigestBuildError> for DistributedAgentStackPlanError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ManagedAgentStackPlanError> for DistributedAgentStackPlanError {
    fn from(value: ManagedAgentStackPlanError) -> Self {
        Self::Stack(value)
    }
}

impl From<crate::managed_fabric_plan::ManagedFabricPlanError> for DistributedAgentStackPlanError {
    fn from(value: crate::managed_fabric_plan::ManagedFabricPlanError) -> Self {
        Self::Stack(ManagedAgentStackPlanError::Fabric(value))
    }
}

impl From<crate::provenance::ProvenanceContractError> for DistributedAgentStackPlanError {
    fn from(value: crate::provenance::ProvenanceContractError) -> Self {
        Self::Provenance(value)
    }
}

impl From<crate::apply::ApplyContractError> for DistributedAgentStackPlanError {
    fn from(value: crate::apply::ApplyContractError) -> Self {
        Self::Apply(value)
    }
}

impl From<crate::reference_assembly::ReferenceContractError> for DistributedAgentStackPlanError {
    fn from(_value: crate::reference_assembly::ReferenceContractError) -> Self {
        Self::ReferenceContract
    }
}

impl From<crate::reference_assembly::ReferenceWireError> for DistributedAgentStackPlanError {
    fn from(_value: crate::reference_assembly::ReferenceWireError) -> Self {
        Self::ReferenceWire
    }
}

impl fmt::Display for DistributedAgentStackPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "distributed Agent stack plan rejected: {self:?}")
    }
}

impl std::error::Error for DistributedAgentStackPlanError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_agent_stack_plan::ManagedAgentStackApplyRequestV1;

    const STACK_FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_agent_stack_successor_v1.json");
    const DISTRIBUTED_GOLDEN: &str =
        include_str!("../tests/fixtures/distributed_agent_stack_v1.hex");

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("fixture contains non-hex byte"),
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "hex fixture must have even width");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn stack_fixture_hex_after(section: &str, key: &str) -> Vec<u8> {
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

    fn golden(key: &str) -> Vec<u8> {
        let prefix = format!("{key}=");
        let value = DISTRIBUTED_GOLDEN
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("missing distributed golden {key}"));
        decode_hex(value)
    }

    fn stack_projection() -> ManagedAgentStackProjectionV1 {
        ManagedAgentStackProjectionV1::decode(&stack_fixture_hex_after(
            "\"expected\"",
            "\"projection_pxsp_hex\"",
        ))
        .expect("fixed-stack projection fixture must decode")
    }

    fn predecessor_execution() -> ManagedAgentStackTargetExecutionV1 {
        ManagedAgentStackTargetExecutionV1::decode(&stack_fixture_hex_after(
            "\"fabric_and_agent\"",
            "\"pxte_v6_hex\"",
        ))
        .expect("fixed-stack PXTE v6 fixture must decode")
    }

    fn predecessor_request() -> ManagedAgentStackApplyRequestV1 {
        ManagedAgentStackApplyRequestV1::decode(&stack_fixture_hex_after(
            "\"fabric_and_agent\"",
            "\"outer_v7_hex\"",
        ))
        .expect("fixed-stack PXAR v7 fixture must decode")
    }

    fn projection() -> DistributedAgentStackProjectionV1 {
        DistributedAgentStackProjectionV1::try_from_managed_agent_stack_projection(
            stack_projection(),
        )
        .expect("distributed projection must build")
    }

    fn authentication(seed: u8) -> DistributedFabricPeerAuthenticationRequirementV1 {
        DistributedFabricPeerAuthenticationRequirementV1::try_mutual_tls(
            DistributedFabricTrustDomainRefV1::try_from_bytes([seed; 16]).expect("trust domain"),
            DistributedFabricCredentialRefV1::try_from_bytes([seed + 1; 16]).expect("credential"),
            DistributedFabricTrustAnchorRefV1::try_from_bytes([seed + 2; 16])
                .expect("trust anchor"),
            DistributedFabricPeerIdentityRefV1::try_from_bytes([seed + 3; 16])
                .expect("peer identity"),
        )
        .expect("authentication requirement")
    }

    fn peer(host_seed: u8, endpoint: &str, authentication_seed: u8) -> DistributedFabricPeerPlanV1 {
        DistributedFabricPeerPlanV1::try_new(
            RuntimeHostId::from_bytes([host_seed; 16]),
            DistributedFabricTlsEndpointV1::try_new(endpoint).expect("peer endpoint"),
            authentication(authentication_seed),
        )
        .expect("peer plan")
    }

    fn shared_session_peer(
        host_seed: u8,
        endpoint: &str,
        peer_identity_seed: u8,
    ) -> DistributedFabricPeerPlanV1 {
        let authentication = DistributedFabricPeerAuthenticationRequirementV1::try_mutual_tls(
            DistributedFabricTrustDomainRefV1::try_from_bytes([0x91; 16]).expect("trust domain"),
            DistributedFabricCredentialRefV1::try_from_bytes([0x92; 16]).expect("credential"),
            DistributedFabricTrustAnchorRefV1::try_from_bytes([0x93; 16]).expect("trust anchor"),
            DistributedFabricPeerIdentityRefV1::try_from_bytes([peer_identity_seed; 16])
                .expect("peer identity"),
        )
        .expect("shared session authentication");
        DistributedFabricPeerPlanV1::try_new(
            RuntimeHostId::from_bytes([host_seed; 16]),
            DistributedFabricTlsEndpointV1::try_new(endpoint).expect("peer endpoint"),
            authentication,
        )
        .expect("shared session peer")
    }

    fn topology() -> DistributedFabricTopologyV1 {
        let predecessor = predecessor_execution();
        DistributedFabricTopologyV1::try_new(
            projection().target(),
            predecessor
                .fabric()
                .listen_endpoint()
                .expect("active predecessor loopback")
                .clone(),
            DistributedFabricTlsEndpointV1::try_new("tls/192.0.2.10:7447").expect("remote listen"),
            vec![peer(0x81, "tls/192.0.2.11:7447", 0x91)],
        )
        .expect("distributed topology")
    }

    fn active_execution_for(
        topology: DistributedFabricTopologyV1,
    ) -> DistributedAgentStackTargetExecutionV1 {
        DistributedAgentStackTargetExecutionV1::try_distributed_fabric_and_agent(
            projection(),
            predecessor_execution(),
            topology,
        )
        .expect("distributed active target")
    }

    fn active_execution() -> DistributedAgentStackTargetExecutionV1 {
        active_execution_for(topology())
    }

    fn distributed_request_for(
        topology: DistributedFabricTopologyV1,
    ) -> DistributedAgentStackApplyRequestV1 {
        let predecessor = predecessor_request();
        DistributedAgentStackApplyRequestDraftV1::try_new(
            active_execution_for(topology),
            predecessor.provenance(),
            predecessor.control_commitment().control().clone(),
            predecessor.temporal(),
            predecessor.expected_runtime_store_instance_id(),
            predecessor.authentication().claim().clone(),
        )
        .expect("PXAR v8 draft")
        .finalize(predecessor.authentication().signature())
        .expect("PXAR v8")
    }

    fn distributed_request() -> DistributedAgentStackApplyRequestV1 {
        distributed_request_for(topology())
    }

    fn restricted_transport_profile_fields()
    -> RestrictedRuntimeApplyTransportProfileFieldsV1<'static> {
        RestrictedRuntimeApplyTransportProfileFieldsV1 {
            target: RuntimeHostId::from_bytes([0x11; 16]),
            endpoint_ref: [0x22; 16],
            endpoint_generation: 3,
            tls_listener_locator: "tls/192.0.2.40:7447",
            route: "paraegox/runtime-a/apply",
            trust_domain_ref: DistributedFabricTrustDomainRefV1::try_from_bytes([0x55; 16])
                .expect("trust domain"),
            trust_anchor_ref: DistributedFabricTrustAnchorRefV1::try_from_bytes([0x66; 16])
                .expect("trust anchor"),
            controller_connector_credential_ref: DistributedFabricCredentialRefV1::try_from_bytes(
                [0x77; 16],
            )
            .expect("Controller connector credential"),
            runtime_listener_credential_ref: DistributedFabricCredentialRefV1::try_from_bytes(
                [0x88; 16],
            )
            .expect("Runtime listener credential"),
            controller_principal: PrincipalRef::from_bytes([0x33; 16]),
            runtime_principal: PrincipalRef::from_bytes([0x44; 16]),
            operation_timeout_nanos: 5_000_000_000,
        }
    }

    fn golden_restricted_transport_profile() -> RestrictedRuntimeApplyTransportProfileV1 {
        RestrictedRuntimeApplyTransportProfileV1::try_new(restricted_transport_profile_fields())
            .expect("restricted transport profile golden")
    }

    fn restricted_carrier_for_transport_profile(
        profile: &RestrictedRuntimeApplyTransportProfileV1,
        endpoint_generation: u64,
        profile_digest: Digest32,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: profile.target(),
                runtime_principal: profile.runtime_principal(),
                controller_principal: profile.controller_principal(),
                endpoint_ref: profile.endpoint_ref(),
                endpoint_generation,
                route: profile.route(),
                controller_request_key: ApplyAuthKeyRef::from_bytes([0x91; 16]),
                controller_request_key_fingerprint: Digest32::from_bytes([0x92; 32]),
                runtime_response_key: ApplyAuthKeyRef::from_bytes([0x93; 16]),
                runtime_response_key_fingerprint: Digest32::from_bytes([0x94; 32]),
                control_transport_profile_ref: [0x95; 16],
                control_transport_profile_digest: profile_digest,
            },
        )
        .expect("profile-correlated restricted carrier")
    }

    fn golden_restricted_carrier() -> RestrictedRuntimeApplyCarrierBindingV1 {
        RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: RuntimeHostId::from_bytes([0x11; 16]),
                runtime_principal: PrincipalRef::from_bytes([0x22; 16]),
                controller_principal: PrincipalRef::from_bytes([0x33; 16]),
                endpoint_ref: [0x44; 16],
                endpoint_generation: 5,
                route: "paraegox/runtime-a/apply",
                controller_request_key: ApplyAuthKeyRef::from_bytes([0x55; 16]),
                controller_request_key_fingerprint: Digest32::from_bytes([0x66; 32]),
                runtime_response_key: ApplyAuthKeyRef::from_bytes([0x77; 16]),
                runtime_response_key_fingerprint: Digest32::from_bytes([0x88; 32]),
                control_transport_profile_ref: [0x99; 16],
                control_transport_profile_digest: Digest32::from_bytes([0xaa; 32]),
            },
        )
        .expect("restricted carrier golden")
    }

    fn restricted_carrier_for_route(
        request: &DistributedAgentStackApplyRequestV1,
        route: &str,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        let claim = request.authentication().claim();
        RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: request.target(),
                runtime_principal: PrincipalRef::from_bytes([0xd1; 16]),
                controller_principal: claim.principal(),
                endpoint_ref: [0xd2; 16],
                endpoint_generation: 7,
                route,
                controller_request_key: claim.key(),
                controller_request_key_fingerprint: Digest32::from_bytes([0xd3; 32]),
                runtime_response_key: ApplyAuthKeyRef::from_bytes([0xd4; 16]),
                runtime_response_key_fingerprint: Digest32::from_bytes([0xd5; 32]),
                control_transport_profile_ref: [0xd6; 16],
                control_transport_profile_digest: Digest32::from_bytes([0xd7; 32]),
            },
        )
        .expect("request-correlated restricted carrier")
    }

    fn restricted_carrier_for(
        request: &DistributedAgentStackApplyRequestV1,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        restricted_carrier_for_route(request, "paraegox/runtime-a/apply")
    }

    fn restricted_request() -> DistributedAgentStackRestrictedApplyRequestV1 {
        let request = distributed_request();
        let carrier = restricted_carrier_for(&request);
        DistributedAgentStackRestrictedApplyRequestDraftV1::try_new(request, carrier)
            .expect("PXRC draft")
            .finalize(&[0xd8; 64])
            .expect("PXRC")
    }

    fn empty_request() -> DistributedAgentStackApplyRequestV1 {
        let predecessor = predecessor_request();
        DistributedAgentStackApplyRequestDraftV1::try_new(
            DistributedAgentStackTargetExecutionV1::try_empty_deactivate(projection())
                .expect("empty target"),
            predecessor.provenance(),
            predecessor.control_commitment().control().clone(),
            predecessor.temporal(),
            predecessor.expected_runtime_store_instance_id(),
            predecessor.authentication().claim().clone(),
        )
        .expect("empty PXAR v8 draft")
        .finalize(predecessor.authentication().signature())
        .expect("empty PXAR v8")
    }

    fn two_peer_topology() -> DistributedFabricTopologyV1 {
        let predecessor = predecessor_execution();
        DistributedFabricTopologyV1::try_new(
            projection().target(),
            predecessor
                .fabric()
                .listen_endpoint()
                .expect("active predecessor loopback")
                .clone(),
            DistributedFabricTlsEndpointV1::try_new("tls/192.0.2.10:7447").expect("remote listen"),
            vec![
                shared_session_peer(0x81, "tls/192.0.2.11:7447", 0x94),
                shared_session_peer(0x82, "tls/192.0.2.12:7447", 0x95),
            ],
        )
        .expect("two-peer distributed topology")
    }

    fn transport_proof_for(
        request: &DistributedAgentStackApplyRequestV1,
        peer_index: usize,
        session_epoch_seed: u8,
        evidence_ref_seed: u8,
        observation_sequence: u64,
    ) -> DistributedFabricObservedTransportProofV1 {
        let desired_peer = &request
            .target_execution()
            .topology()
            .expect("distributed topology")
            .peers()[peer_index];
        DistributedFabricObservedTransportProofV1::try_new(
            request.target(),
            desired_peer,
            DistributedFabricObservedTransportProofFieldsV1 {
                local_runtime_host: request.target(),
                peer_runtime_host: desired_peer.peer_runtime_host(),
                session_epoch: DistributedFabricSessionEpochV1::try_from_bytes(
                    [session_epoch_seed; 16],
                )
                .expect("session epoch"),
                authenticated_peer_identity_ref: desired_peer
                    .authentication()
                    .expected_peer_identity_ref(),
                selected_local_credential_ref: desired_peer.authentication().local_credential_ref(),
                transport_evidence_ref: DistributedFabricTransportEvidenceRefV1::try_from_bytes(
                    [evidence_ref_seed; 16],
                )
                .expect("evidence ref"),
                observation_sequence,
            },
        )
        .expect("transport proof payload")
    }

    fn transport_proof() -> DistributedFabricObservedTransportProofV1 {
        transport_proof_for(&distributed_request(), 0, 0xa1, 0xa2, 7)
    }

    fn local_binding_evidence(ready: bool) -> DistributedAgentStackLocalBindingEvidenceFieldsV1 {
        DistributedAgentStackLocalBindingEvidenceFieldsV1 {
            physical_binding_census: if ready { 2 } else { 0 },
            census_complete: ready,
            fabric_ready: ready,
            agent_ready: ready,
            dependency_satisfied: ready,
            exact_zero: false,
            quarantined: false,
            installed_binding_set_digest: distributed_agent_stack_installed_binding_set_digest_v1(
                Digest32::from_bytes([0xa6; 32]),
                Digest32::from_bytes([0xa8; 32]),
            )
            .expect("installed request/event binding set digest"),
            raw_outcome_digest: Digest32::from_bytes([0xa7; 32]),
        }
    }

    fn terminal_channel() -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            projection().target(),
            PrincipalRef::from_bytes([0xb1; 16]),
            Digest32::from_bytes([0xb2; 32]),
            Digest32::from_bytes([0xb3; 32]),
        )
        .expect("Runtime terminal channel")
    }

    fn terminal_receipt(
        outcome: DistributedAgentStackTerminalOutcomeV1,
    ) -> DistributedAgentStackTerminalReceiptV1 {
        let request = distributed_request();
        let facts = terminal_facts_for(&request, outcome);
        let channel = terminal_channel();
        let auth = DistributedAgentStackTerminalAuthClaimV1::try_new(
            channel,
            ApplyAuthKeyRef::from_bytes([0xb4; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("Ed25519 algorithm"),
            1,
        )
        .expect("terminal auth claim");
        DistributedAgentStackTerminalReceiptDraftV1::try_new(&request, facts, channel, auth)
            .expect("PXDS draft")
            .finalize(&[0xb5; 64])
            .expect("opaque Ed25519 signature")
    }

    fn terminal_facts_for(
        request: &DistributedAgentStackApplyRequestV1,
        outcome: DistributedAgentStackTerminalOutcomeV1,
    ) -> DistributedAgentStackTerminalFactsV1 {
        let generations = if outcome == DistributedAgentStackTerminalOutcomeV1::ActiveReady {
            (
                Some(ManagedServiceGeneration::try_new(3).expect("Fabric generation")),
                Some(ManagedServiceGeneration::try_new(4).expect("Agent generation")),
            )
        } else {
            (None, None)
        };
        let observations = DistributedAgentStackTerminalObservationsV1::try_new(
            request,
            vec![transport_proof_for(request, 0, 0xa1, 0xa2, 7)],
        )
        .expect("complete transport observations");
        DistributedAgentStackTerminalFactsV1::try_new(
            request,
            outcome,
            DistributedAgentStackTerminalEvidenceFieldsV1 {
                runtime_host_epoch: 11,
                completion_snapshot_sequence: 12,
                selection_clock_generation: request.temporal().target_clock_generation(),
                selection_observed_at_nanos: 13,
                fabric_generation: generations.0,
                agent_generation: generations.1,
                local_bindings: local_binding_evidence(
                    outcome == DistributedAgentStackTerminalOutcomeV1::ActiveReady,
                ),
            },
            observations,
        )
        .expect("distributed terminal facts")
    }

    fn restricted_terminal_receipt() -> DistributedAgentStackTerminalReceiptV2 {
        let request = restricted_request();
        let expected_carrier = request.carrier().clone();
        let authenticated = request
            .verify_controller_carrier_before_mutation(
                &expected_carrier,
                |_principal, _key, _fingerprint, _transcript, _signature| true,
            )
            .expect("authenticated PXRC");
        let facts = terminal_facts_for(
            authenticated.request(),
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
        );
        DistributedAgentStackTerminalReceiptDraftV2::try_new(authenticated, facts)
            .expect("PXDS v2 draft")
            .finalize(&[0xd9; 64])
            .expect("PXDS v2")
    }

    #[test]
    fn endpoints_are_explicit_canonical_non_loopback_unicast_ipv4() {
        for valid in [
            "tls/192.0.2.10:1",
            "tls/10.20.30.40:7447",
            "tls/169.254.1.2:65535",
        ] {
            assert_eq!(
                DistributedFabricTlsEndpointV1::try_new(valid)
                    .expect("canonical endpoint")
                    .as_str(),
                valid
            );
        }
        for invalid in [
            "tls/127.0.0.1:7447",
            "tls/0.0.0.0:7447",
            "tls/224.0.0.1:7447",
            "tls/255.255.255.255:7447",
            "tls/192.0.2.10:0",
            "tls/192.0.2.10:07447",
            "tls/192.000.2.10:7447",
            "tls/example.test:7447",
            "tls/[2001:db8::1]:7447",
            "tcp/192.0.2.10:7447",
            "udp/192.0.2.10:7447",
        ] {
            assert!(
                DistributedFabricTlsEndpointV1::try_new(invalid).is_err(),
                "{invalid} must fail closed"
            );
        }
    }

    #[test]
    fn topology_enforces_bounds_order_uniqueness_and_local_peer_separation() {
        let base = predecessor_execution()
            .fabric()
            .listen_endpoint()
            .expect("loopback")
            .clone();
        let listen =
            DistributedFabricTlsEndpointV1::try_new("tls/192.0.2.10:7447").expect("listen");
        let local = projection().target();
        assert!(matches!(
            DistributedFabricTopologyV1::try_new(local, base.clone(), listen.clone(), Vec::new(),),
            Err(DistributedAgentStackPlanError::InvalidTopology)
        ));
        assert!(matches!(
            DistributedFabricTopologyV1::try_new(
                local,
                base.clone(),
                listen.clone(),
                vec![
                    shared_session_peer(0x82, "tls/192.0.2.12:7447", 0x96),
                    shared_session_peer(0x81, "tls/192.0.2.11:7447", 0x94),
                ],
            ),
            Err(DistributedAgentStackPlanError::NonCanonicalTopology)
        ));
        assert!(matches!(
            DistributedFabricTopologyV1::try_new(
                local,
                base.clone(),
                listen.clone(),
                vec![
                    peer(0x81, "tls/192.0.2.11:7447", 0x91),
                    peer(0x82, "tls/192.0.2.12:7447", 0x95),
                ],
            ),
            Err(DistributedAgentStackPlanError::InvalidTopology)
        ));
        let mut too_many = Vec::new();
        for index in 0..=MAX_DISTRIBUTED_FABRIC_PEERS {
            let octet = 20 + u8::try_from(index).expect("bounded index");
            too_many.push(peer(
                0x80 + u8::try_from(index).expect("bounded index"),
                &format!("tls/192.0.2.{octet}:7447"),
                0xb0 + u8::try_from(index * 4).expect("bounded auth seed"),
            ));
        }
        assert!(matches!(
            DistributedFabricTopologyV1::try_new(local, base, listen, too_many),
            Err(DistributedAgentStackPlanError::InvalidTopology)
        ));
    }

    #[test]
    fn pxdp_pxdt_pxte7_round_trip_and_cross_reject_frozen_pxte6() {
        let projection = projection();
        assert_eq!(&projection.canonical_wire()[..6], b"PXDP\0\x01");
        assert_eq!(
            DistributedAgentStackProjectionV1::decode(projection.canonical_wire())
                .expect("projection round trip"),
            projection
        );
        assert!(
            DistributedAgentStackProjectionV1::decode(stack_projection().canonical_wire()).is_err()
        );

        let topology = topology();
        assert_eq!(&topology.canonical_wire()[..6], b"PXDT\0\x01");
        assert_eq!(
            DistributedFabricTopologyV1::decode(projection.target(), topology.canonical_wire())
                .expect("topology round trip"),
            topology
        );

        let active = active_execution();
        assert_eq!(&active.canonical_wire()[..6], b"PXTE\0\x07");
        assert_eq!(
            DistributedAgentStackTargetExecutionV1::decode(active.canonical_wire())
                .expect("PXTE v7 round trip"),
            active
        );
        assert!(
            DistributedAgentStackTargetExecutionV1::decode(
                predecessor_execution().canonical_wire()
            )
            .is_err()
        );
        assert!(ManagedAgentStackTargetExecutionV1::decode(active.canonical_wire()).is_err());

        let empty = DistributedAgentStackTargetExecutionV1::try_empty_deactivate(projection)
            .expect("empty target");
        assert_eq!(
            empty.mode(),
            DistributedAgentStackTargetModeV1::EmptyDeactivate
        );
        assert!(empty.topology().is_none());
        assert_eq!(
            DistributedAgentStackTargetExecutionV1::decode(empty.canonical_wire())
                .expect("empty round trip"),
            empty
        );
    }

    #[test]
    fn pxar8_binds_exact_topology_and_cross_rejects_pxar7() {
        let predecessor = predecessor_request();
        let request = distributed_request();
        assert_eq!(&request.canonical_wire()[..6], b"PXAR\0\x08");
        assert!(
            !request
                .signing_transcript()
                .expect("signing transcript")
                .as_bytes()
                .is_empty()
        );
        let decoded = DistributedAgentStackApplyRequestV1::decode(request.canonical_wire())
            .expect("PXAR v8 round trip");
        assert_eq!(decoded, request);
        decoded
            .validate_expected_store(predecessor.expected_runtime_store_instance_id())
            .expect("store correlation");
        let restored = verify_distributed_agent_stack_durable_slice_v1(
            decoded.canonical_slice_wire(),
            decoded.target(),
            decoded.provenance(),
            decoded.target_slice_digest(),
            &projection(),
        )
        .expect("durable PXTE v7 restore");
        assert_eq!(restored, active_execution());
        assert!(DistributedAgentStackApplyRequestV1::decode(predecessor.canonical_wire()).is_err());
        assert!(ManagedAgentStackApplyRequestV1::decode(request.canonical_wire()).is_err());
    }

    #[test]
    fn restricted_transport_profile_has_an_exact_golden_and_strict_codec() {
        let profile = golden_restricted_transport_profile();
        let expected = decode_hex(concat!(
            "5058525000010001001300180000",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "0000000000000003",
            "33333333333333333333333333333333",
            "44444444444444444444444444444444",
            "55555555555555555555555555555555",
            "66666666666666666666666666666666",
            "77777777777777777777777777777777",
            "88888888888888888888888888888888",
            "000000012a05f200",
            "746c732f3139322e302e322e34303a37343437",
            "7061726165676f782f72756e74696d652d612f6170706c79",
        ));
        assert_eq!(profile.canonical_wire(), expected);
        assert_eq!(
            profile.profile_digest().as_bytes().as_slice(),
            decode_hex("8d93ee1ddd98979072f311b9d2b9de6cf97914183f6eb53da2bec7570404ecbf")
                .as_slice()
        );
        assert_eq!(
            RestrictedRuntimeApplyTransportProfileV1::decode(profile.canonical_wire())
                .expect("PXRP round trip"),
            profile
        );
        assert_eq!(profile.target(), RuntimeHostId::from_bytes([0x11; 16]));
        assert_eq!(profile.endpoint_ref(), [0x22; 16]);
        assert_eq!(profile.endpoint_generation(), 3);
        assert_eq!(
            profile.tls_listener_locator().as_str(),
            "tls/192.0.2.40:7447"
        );
        assert_eq!(profile.route(), "paraegox/runtime-a/apply");
        assert_eq!(profile.trust_domain_ref().as_bytes(), &[0x55; 16]);
        assert_eq!(profile.trust_anchor_ref().as_bytes(), &[0x66; 16]);
        assert_eq!(
            profile.controller_connector_credential_ref().as_bytes(),
            &[0x77; 16]
        );
        assert_eq!(
            profile.runtime_listener_credential_ref().as_bytes(),
            &[0x88; 16]
        );
        assert_eq!(
            profile.controller_principal(),
            PrincipalRef::from_bytes([0x33; 16])
        );
        assert_eq!(
            profile.runtime_principal(),
            PrincipalRef::from_bytes([0x44; 16])
        );
        assert_eq!(profile.operation_timeout_nanos(), 5_000_000_000);
    }

    #[test]
    fn restricted_transport_profile_correlates_exact_pxcb_facts_without_authorizing() {
        let profile = golden_restricted_transport_profile();
        let carrier = restricted_carrier_for_transport_profile(
            &profile,
            profile.endpoint_generation(),
            profile.profile_digest(),
        );
        profile
            .validate_carrier_binding([0x95; 16], &carrier)
            .expect("exact PXRP/PXCB correlation");

        for wrong_ref in [[0; 16], [0x96; 16]] {
            assert!(matches!(
                profile.validate_carrier_binding(wrong_ref, &carrier),
                Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch)
            ));
        }

        let wrong_generation = restricted_carrier_for_transport_profile(
            &profile,
            profile.endpoint_generation() + 1,
            profile.profile_digest(),
        );
        assert!(matches!(
            profile.validate_carrier_binding([0x95; 16], &wrong_generation),
            Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch)
        ));

        let wrong_digest = restricted_carrier_for_transport_profile(
            &profile,
            profile.endpoint_generation(),
            Digest32::from_bytes([0xaa; 32]),
        );
        assert!(matches!(
            profile.validate_carrier_binding([0x95; 16], &wrong_digest),
            Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch)
        ));
    }

    #[test]
    fn restricted_transport_profile_rejects_unsafe_or_malformed_values() {
        let fields = restricted_transport_profile_fields();
        let duplicate_credential = fields.controller_connector_credential_ref;
        for invalid in [
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                target: RuntimeHostId::from_bytes([0; 16]),
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                endpoint_ref: [0; 16],
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                endpoint_generation: 0,
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                tls_listener_locator: "tcp/192.0.2.40:7447",
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                tls_listener_locator: "tls/*:7447",
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                route: "paraegox/*/apply",
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                controller_principal: PrincipalRef::from_bytes([0; 16]),
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                runtime_principal: PrincipalRef::from_bytes([0; 16]),
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                runtime_principal: fields.controller_principal,
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                runtime_listener_credential_ref: duplicate_credential,
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                operation_timeout_nanos: 0,
                ..fields
            },
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                operation_timeout_nanos: MAX_RESTRICTED_RUNTIME_APPLY_OPERATION_TIMEOUT_NANOS + 1,
                ..fields
            },
        ] {
            assert!(matches!(
                RestrictedRuntimeApplyTransportProfileV1::try_new(invalid),
                Err(DistributedAgentStackPlanError::InvalidTransportProfile)
            ));
        }

        let overlong_route = format!(
            "paraegox/{}/apply",
            "a".repeat(MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES)
        );
        assert!(matches!(
            RestrictedRuntimeApplyTransportProfileV1::try_new(
                RestrictedRuntimeApplyTransportProfileFieldsV1 {
                    route: &overlong_route,
                    ..fields
                }
            ),
            Err(DistributedAgentStackPlanError::InvalidTransportProfile)
        ));
        RestrictedRuntimeApplyTransportProfileV1::try_new(
            RestrictedRuntimeApplyTransportProfileFieldsV1 {
                operation_timeout_nanos: MAX_RESTRICTED_RUNTIME_APPLY_OPERATION_TIMEOUT_NANOS,
                ..fields
            },
        )
        .expect("inclusive operation-timeout bound");

        let profile = golden_restricted_transport_profile();
        let mut unsupported_kind = profile.canonical_wire().to_vec();
        unsupported_kind[7] = 2;
        assert!(matches!(
            RestrictedRuntimeApplyTransportProfileV1::decode(&unsupported_kind),
            Err(DistributedAgentStackPlanError::UnsupportedWire)
        ));

        let mut nonzero_reserved = profile.canonical_wire().to_vec();
        nonzero_reserved[13] = 1;
        assert!(matches!(
            RestrictedRuntimeApplyTransportProfileV1::decode(&nonzero_reserved),
            Err(DistributedAgentStackPlanError::InvalidLength)
        ));

        let mut invalid_length = profile.canonical_wire().to_vec();
        invalid_length[8..10].copy_from_slice(
            &u16::try_from(MAX_DISTRIBUTED_FABRIC_ENDPOINT_BYTES + 1)
                .expect("bounded endpoint length")
                .to_be_bytes(),
        );
        assert!(matches!(
            RestrictedRuntimeApplyTransportProfileV1::decode(&invalid_length),
            Err(DistributedAgentStackPlanError::InvalidLength)
        ));

        let mut zero_trust_domain = profile.canonical_wire().to_vec();
        zero_trust_domain[86..102].fill(0);
        assert!(matches!(
            RestrictedRuntimeApplyTransportProfileV1::decode(&zero_trust_domain),
            Err(DistributedAgentStackPlanError::InvalidTransportProfile)
        ));

        let mut duplicate_credentials = profile.canonical_wire().to_vec();
        duplicate_credentials[134..150].copy_from_slice(&[0x77; 16]);
        assert!(matches!(
            RestrictedRuntimeApplyTransportProfileV1::decode(&duplicate_credentials),
            Err(DistributedAgentStackPlanError::InvalidTransportProfile)
        ));

        let mut non_tls_locator = profile.canonical_wire().to_vec();
        non_tls_locator[158..161].copy_from_slice(b"tcp");
        assert!(matches!(
            RestrictedRuntimeApplyTransportProfileV1::decode(&non_tls_locator),
            Err(DistributedAgentStackPlanError::InvalidTransportProfile)
        ));

        assert!(matches!(
            RestrictedRuntimeApplyTransportProfileV1::decode(
                &profile.canonical_wire()[..RESTRICTED_TRANSPORT_PROFILE_FIXED_BYTES - 1]
            ),
            Err(DistributedAgentStackPlanError::Truncated)
        ));
        let mut trailing = profile.canonical_wire().to_vec();
        trailing.push(0);
        assert!(matches!(
            RestrictedRuntimeApplyTransportProfileV1::decode(&trailing),
            Err(DistributedAgentStackPlanError::TrailingBytes)
        ));
        assert!(matches!(
            RestrictedRuntimeApplyTransportProfileV1::decode(&vec![
                0;
                MAX_RESTRICTED_RUNTIME_APPLY_TRANSPORT_PROFILE_BYTES
                    + 1
            ]),
            Err(DistributedAgentStackPlanError::FrameTooLarge)
        ));
    }

    #[test]
    fn restricted_carrier_binding_has_an_exact_golden_and_strict_codec() {
        let carrier = golden_restricted_carrier();
        let expected = decode_hex(concat!(
            "505843420001000100180000",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "33333333333333333333333333333333",
            "44444444444444444444444444444444",
            "0000000000000005",
            "55555555555555555555555555555555",
            "6666666666666666666666666666666666666666666666666666666666666666",
            "77777777777777777777777777777777",
            "8888888888888888888888888888888888888888888888888888888888888888",
            "99999999999999999999999999999999",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "7061726165676f782f72756e74696d652d612f6170706c79",
        ));
        assert_eq!(carrier.canonical_wire(), expected);
        assert_eq!(
            carrier.binding_digest().as_bytes().as_slice(),
            decode_hex("678c5b6276dcb5215a0b7214febb24588721e75c438f85734c4e51fb5581beaa")
                .as_slice()
        );
        assert_eq!(
            RestrictedRuntimeApplyCarrierBindingV1::decode(carrier.canonical_wire())
                .expect("PXCB round trip"),
            carrier
        );
        assert_eq!(carrier.endpoint_generation(), 5);
        assert_eq!(carrier.route(), "paraegox/runtime-a/apply");

        let mut unsupported_kind = carrier.canonical_wire().to_vec();
        unsupported_kind[7] = 2;
        assert!(matches!(
            RestrictedRuntimeApplyCarrierBindingV1::decode(&unsupported_kind),
            Err(DistributedAgentStackPlanError::UnsupportedWire)
        ));
        let mut invalid_route = carrier.canonical_wire().to_vec();
        *invalid_route.last_mut().expect("route byte") = b'/';
        assert!(matches!(
            RestrictedRuntimeApplyCarrierBindingV1::decode(&invalid_route),
            Err(DistributedAgentStackPlanError::InvalidCarrierBinding)
        ));
        assert!(matches!(
            RestrictedRuntimeApplyCarrierBindingV1::try_new(
                RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                    endpoint_generation: 0,
                    ..RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                        target: RuntimeHostId::from_bytes([0x11; 16]),
                        runtime_principal: PrincipalRef::from_bytes([0x22; 16]),
                        controller_principal: PrincipalRef::from_bytes([0x33; 16]),
                        endpoint_ref: [0x44; 16],
                        endpoint_generation: 5,
                        route: "paraegox/runtime-a/apply",
                        controller_request_key: ApplyAuthKeyRef::from_bytes([0x55; 16]),
                        controller_request_key_fingerprint: Digest32::from_bytes([0x66; 32]),
                        runtime_response_key: ApplyAuthKeyRef::from_bytes([0x77; 16]),
                        runtime_response_key_fingerprint: Digest32::from_bytes([0x88; 32]),
                        control_transport_profile_ref: [0x99; 16],
                        control_transport_profile_digest: Digest32::from_bytes([0xaa; 32]),
                    }
                }
            ),
            Err(DistributedAgentStackPlanError::InvalidCarrierBinding)
        ));
    }

    #[test]
    fn pxrc_authenticates_exact_pxar8_and_selected_carrier_before_mutation() {
        let restricted = restricted_request();
        assert_eq!(&restricted.canonical_wire()[..6], b"PXRC\0\x01");
        assert_eq!(&restricted.request().canonical_wire()[..6], b"PXAR\0\x08");
        assert_eq!(restricted.controller_signature(), &[0xd8; 64]);
        let decoded =
            DistributedAgentStackRestrictedApplyRequestV1::decode(restricted.canonical_wire())
                .expect("PXRC round trip");
        assert_eq!(decoded, restricted);
        assert_eq!(
            decoded.request().canonical_wire(),
            distributed_request().canonical_wire(),
            "PXRC must retain exact frozen PXAR v8 bytes"
        );

        let expected_carrier = decoded.carrier().clone();
        let authenticated = decoded
            .verify_controller_carrier_before_mutation(
                &expected_carrier,
                |principal, key, fingerprint, transcript, signature| {
                    assert_eq!(principal, expected_carrier.controller_principal());
                    assert_eq!(key, expected_carrier.controller_request_key());
                    assert_eq!(
                        fingerprint,
                        expected_carrier.controller_request_key_fingerprint()
                    );
                    assert!(transcript.starts_with(RESTRICTED_APPLY_REQUEST_SIGNING_MAGIC));
                    assert_eq!(signature, &[0xd8; 64]);
                    true
                },
            )
            .expect("outer Controller signature and carrier accepted");
        assert_eq!(authenticated.request(), decoded.request());

        let request = distributed_request();
        let mismatched_target = RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: RuntimeHostId::from_bytes([0xee; 16]),
                ..RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                    target: request.target(),
                    runtime_principal: PrincipalRef::from_bytes([0xd1; 16]),
                    controller_principal: request.authentication().claim().principal(),
                    endpoint_ref: [0xd2; 16],
                    endpoint_generation: 7,
                    route: "paraegox/runtime-a/apply",
                    controller_request_key: request.authentication().claim().key(),
                    controller_request_key_fingerprint: Digest32::from_bytes([0xd3; 32]),
                    runtime_response_key: ApplyAuthKeyRef::from_bytes([0xd4; 16]),
                    runtime_response_key_fingerprint: Digest32::from_bytes([0xd5; 32]),
                    control_transport_profile_ref: [0xd6; 16],
                    control_transport_profile_digest: Digest32::from_bytes([0xd7; 32]),
                }
            },
        )
        .expect("structurally valid carrier for another target");
        assert!(matches!(
            DistributedAgentStackRestrictedApplyRequestDraftV1::try_new(request, mismatched_target,),
            Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch)
        ));
        let width_request = distributed_request();
        let width_carrier = restricted_carrier_for(&width_request);
        let width_draft = DistributedAgentStackRestrictedApplyRequestDraftV1::try_new(
            width_request,
            width_carrier,
        )
        .expect("PXRC width draft");
        assert!(matches!(
            width_draft.finalize(&[0xd8; 63]),
            Err(DistributedAgentStackPlanError::InvalidCarrierAuthentication)
        ));

        let other_carrier =
            restricted_carrier_for_route(decoded.request(), "paraegox/runtime-b/apply");
        let mut verifier_called = false;
        assert!(matches!(
            decoded.verify_controller_carrier_before_mutation(
                &other_carrier,
                |_principal, _key, _fingerprint, _transcript, _signature| {
                    verifier_called = true;
                    true
                },
            ),
            Err(DistributedAgentStackPlanError::CarrierCorrelationMismatch)
        ));
        assert!(
            !verifier_called,
            "mismatched carrier must fail before crypto"
        );

        let mut tampered_signature = decoded.canonical_wire().to_vec();
        *tampered_signature.last_mut().expect("signature byte") ^= 1;
        let structurally_valid =
            DistributedAgentStackRestrictedApplyRequestV1::decode(&tampered_signature)
                .expect("signature bytes are opaque to the codec");
        assert!(matches!(
            structurally_valid.verify_controller_carrier_before_mutation(
                structurally_valid.carrier(),
                |_principal, _key, _fingerprint, _transcript, _signature| false,
            ),
            Err(DistributedAgentStackPlanError::InvalidCarrierAuthentication)
        ));

        let mut tampered_carrier = decoded.canonical_wire().to_vec();
        let carrier_offset = RESTRICTED_APPLY_REQUEST_FIXED_BYTES;
        tampered_carrier[carrier_offset + 12] ^= 1;
        assert!(DistributedAgentStackRestrictedApplyRequestV1::decode(&tampered_carrier).is_err());
        let mut tampered_request_digest = decoded.canonical_wire().to_vec();
        tampered_request_digest[44] ^= 1;
        assert!(
            DistributedAgentStackRestrictedApplyRequestV1::decode(&tampered_request_digest)
                .is_err()
        );
        assert!(
            DistributedAgentStackRestrictedApplyRequestV1::decode(
                decoded.request().canonical_wire()
            )
            .is_err()
        );
        assert!(DistributedAgentStackApplyRequestV1::decode(decoded.canonical_wire()).is_err());
    }

    #[test]
    fn pxds_v2_binds_authenticated_pxrc_and_runtime_response_key() {
        let restricted = restricted_request();
        let expected_carrier = restricted.carrier().clone();
        let authenticated = restricted
            .verify_controller_carrier_before_mutation(
                &expected_carrier,
                |_principal, _key, _fingerprint, _transcript, _signature| true,
            )
            .expect("PXRC authentication");
        let width_facts = terminal_facts_for(
            authenticated.request(),
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
        );
        let width_draft =
            DistributedAgentStackTerminalReceiptDraftV2::try_new(authenticated, width_facts)
                .expect("PXDS v2 width draft");
        assert!(matches!(
            width_draft.finalize(&[0xd9; 63]),
            Err(DistributedAgentStackPlanError::InvalidResponseAuthentication)
        ));
        let receipt = restricted_terminal_receipt();
        assert_eq!(&receipt.canonical_wire()[..6], b"PXDS\0\x02");
        assert_eq!(receipt.authentication_signature(), &[0xd9; 64]);
        assert_eq!(
            receipt.restricted_request_digest(),
            restricted.restricted_request_digest()
        );
        assert_eq!(receipt.carrier(), restricted.carrier());
        let decoded = DistributedAgentStackTerminalReceiptV2::decode(receipt.canonical_wire())
            .expect("PXDS v2 round trip");
        assert_eq!(decoded, receipt);
        let facts = decoded
            .verify_runtime_response(
                authenticated,
                |principal, key, fingerprint, transcript, signature| {
                    assert_eq!(principal, expected_carrier.runtime_principal());
                    assert_eq!(key, expected_carrier.runtime_response_key());
                    assert_eq!(
                        fingerprint,
                        expected_carrier.runtime_response_key_fingerprint()
                    );
                    assert!(transcript.starts_with(RESTRICTED_TERMINAL_RECEIPT_SIGNING_MAGIC));
                    assert_eq!(signature, &[0xd9; 64]);
                    true
                },
            )
            .expect("Runtime response signature and exact PXRC correlation");
        assert_eq!(facts.target(), restricted.request().target());
        assert_eq!(
            facts.request_digest(),
            restricted.request().envelope_request_digest()
        );

        let v1 = terminal_receipt(DistributedAgentStackTerminalOutcomeV1::ActiveReady);
        assert!(DistributedAgentStackTerminalReceiptV1::decode(receipt.canonical_wire()).is_err());
        assert!(DistributedAgentStackTerminalReceiptV2::decode(v1.canonical_wire()).is_err());

        let mut tampered_signature = decoded.canonical_wire().to_vec();
        *tampered_signature.last_mut().expect("signature byte") ^= 1;
        let structurally_valid =
            DistributedAgentStackTerminalReceiptV2::decode(&tampered_signature)
                .expect("response signature remains opaque to codec");
        assert!(matches!(
            structurally_valid.verify_runtime_response(
                authenticated,
                |_principal, _key, _fingerprint, _transcript, _signature| false,
            ),
            Err(DistributedAgentStackPlanError::InvalidResponseAuthentication)
        ));

        let other_inner = distributed_request();
        let other_carrier = restricted_carrier_for(&other_inner);
        let other_restricted =
            DistributedAgentStackRestrictedApplyRequestDraftV1::try_new(other_inner, other_carrier)
                .expect("other PXRC draft")
                .finalize(&[0xda; 64])
                .expect("other PXRC");
        let other_expected = other_restricted.carrier().clone();
        let other_authenticated = other_restricted
            .verify_controller_carrier_before_mutation(
                &other_expected,
                |_principal, _key, _fingerprint, _transcript, _signature| true,
            )
            .expect("other PXRC authentication");
        assert!(matches!(
            decoded.verify_runtime_response(
                other_authenticated,
                |_principal, _key, _fingerprint, _transcript, _signature| true,
            ),
            Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch)
        ));

        let mut tampered_carrier = decoded.canonical_wire().to_vec();
        let carrier_offset = tampered_carrier
            .windows(RESTRICTED_CARRIER_BINDING_MAGIC.len())
            .position(|window| window == RESTRICTED_CARRIER_BINDING_MAGIC)
            .expect("embedded PXCB");
        tampered_carrier[carrier_offset + 12] ^= 1;
        assert!(DistributedAgentStackTerminalReceiptV2::decode(&tampered_carrier).is_err());
    }

    #[test]
    fn observed_transport_proof_is_separate_correlated_and_not_self_authenticating() {
        let proof = transport_proof();
        assert_eq!(&proof.canonical_wire()[..6], b"PXTP\0\x01");
        assert_eq!(proof.canonical_wire().len(), TRANSPORT_PROOF_BYTES);
        let decoded = DistributedFabricObservedTransportProofV1::decode(proof.canonical_wire())
            .expect("proof payload round trip");
        assert_eq!(decoded, proof);
        decoded
            .validate_against(projection().target(), &topology().peers()[0])
            .expect("exact desired correlation");

        let other = peer(0x82, "tls/192.0.2.12:7447", 0x95);
        assert!(matches!(
            decoded.validate_against(projection().target(), &other),
            Err(DistributedAgentStackPlanError::TransportProofMismatch)
        ));
        assert!(matches!(
            decoded.validate_against(
                RuntimeHostId::from_bytes([0xfe; 16]),
                &topology().peers()[0]
            ),
            Err(DistributedAgentStackPlanError::TransportProofMismatch)
        ));
        assert!(matches!(
            DistributedFabricObservedTransportProofV1::try_new(
                RuntimeHostId::from_bytes([0xfe; 16]),
                &topology().peers()[0],
                decoded.fields(),
            ),
            Err(DistributedAgentStackPlanError::TransportProofMismatch)
        ));
        assert!(
            DistributedAgentStackTargetExecutionV1::decode(proof.canonical_wire()).is_err(),
            "observed bytes cannot be interpreted as desired state"
        );
    }

    #[test]
    fn pxds_is_strict_request_correlated_and_domain_separated_from_pxtp() {
        let request = distributed_request();
        let receipt = terminal_receipt(DistributedAgentStackTerminalOutcomeV1::ActiveReady);
        assert_eq!(&receipt.canonical_wire()[..6], b"PXDS\0\x01");
        assert_eq!(receipt.authentication_signature().len(), 64);
        let decoded = DistributedAgentStackTerminalReceiptV1::decode(receipt.canonical_wire())
            .expect("PXDS round trip");
        assert_eq!(decoded, receipt);
        let facts = decoded
            .validate_against_request(&request, terminal_channel())
            .expect("exact request/channel correlation");
        assert_eq!(
            facts.outcome(),
            DistributedAgentStackTerminalOutcomeV1::ActiveReady
        );
        assert_eq!(facts.target(), request.target());
        assert_eq!(
            facts.runtime_store_instance_id(),
            request.expected_runtime_store_instance_id()
        );
        assert_eq!(facts.operation_id(), request.operation_id());
        assert_eq!(facts.request_digest(), request.envelope_request_digest());
        assert_eq!(
            facts
                .observations()
                .expect("active terminal observations")
                .proofs(),
            &[transport_proof()]
        );
        assert!(
            receipt
                .signing_transcript()
                .expect("terminal transcript")
                .as_bytes()
                .starts_with(TERMINAL_RECEIPT_SIGNING_MAGIC)
        );
        assert!(
            DistributedFabricObservedTransportProofV1::decode(receipt.canonical_wire()).is_err()
        );
        assert!(
            DistributedAgentStackTerminalReceiptV1::decode(transport_proof().canonical_wire())
                .is_err()
        );
    }

    #[test]
    fn terminal_facts_require_complete_ready_and_monotonic_clock() {
        let request = distributed_request();
        let no_handshake =
            DistributedAgentStackTerminalObservationsV1::try_new(&request, Vec::new())
                .expect("non-ready can truthfully report no handshake");
        let observations =
            DistributedAgentStackTerminalObservationsV1::try_new(&request, vec![transport_proof()])
                .expect("complete observations");
        let no_generations = DistributedAgentStackTerminalEvidenceFieldsV1 {
            runtime_host_epoch: 11,
            completion_snapshot_sequence: 12,
            selection_clock_generation: request.temporal().target_clock_generation(),
            selection_observed_at_nanos: 13,
            fabric_generation: None,
            agent_generation: None,
            local_bindings: local_binding_evidence(false),
        };
        assert!(matches!(
            DistributedAgentStackTerminalFactsV1::try_new(
                &request,
                DistributedAgentStackTerminalOutcomeV1::ActiveReady,
                no_generations,
                no_handshake.clone(),
            ),
            Err(DistributedAgentStackPlanError::InvalidTerminalFacts)
        ));
        let next_clock = ClockGeneration::try_new(
            request
                .temporal()
                .target_clock_generation()
                .value()
                .checked_add(1)
                .expect("clock successor"),
        )
        .expect("clock generation");
        DistributedAgentStackTerminalFactsV1::try_new(
            &request,
            DistributedAgentStackTerminalOutcomeV1::TerminalNonReady,
            DistributedAgentStackTerminalEvidenceFieldsV1 {
                selection_clock_generation: next_clock,
                ..no_generations
            },
            no_handshake,
        )
        .expect("newer Runtime clock can terminalize after restart");
        let previous_clock = ClockGeneration::try_new(
            request
                .temporal()
                .target_clock_generation()
                .value()
                .checked_sub(1)
                .expect("fixture has older valid generation"),
        )
        .expect("older clock generation");
        assert!(matches!(
            DistributedAgentStackTerminalFactsV1::try_new(
                &request,
                DistributedAgentStackTerminalOutcomeV1::TerminalNonReady,
                DistributedAgentStackTerminalEvidenceFieldsV1 {
                    selection_clock_generation: previous_clock,
                    ..no_generations
                },
                observations,
            ),
            Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch)
        ));
        for outcome in [
            DistributedAgentStackTerminalOutcomeV1::TerminalNonReady,
            DistributedAgentStackTerminalOutcomeV1::IndeterminateUncertain,
        ] {
            let receipt = terminal_receipt(outcome);
            assert_eq!(
                DistributedAgentStackTerminalReceiptV1::decode(receipt.canonical_wire())
                    .expect("non-ready PXDS")
                    .facts()
                    .outcome(),
                outcome
            );
        }
    }

    #[test]
    fn partial_non_ready_observations_never_promote_and_cannot_mix_sessions() {
        let request = distributed_request_for(two_peer_topology());
        let first = transport_proof_for(&request, 0, 0xc1, 0xd1, 21);
        let second_same_session = transport_proof_for(&request, 1, 0xc1, 0xd2, 22);
        let second_other_session = transport_proof_for(&request, 1, 0xc2, 0xd3, 23);
        let duplicate_sequence = transport_proof_for(&request, 1, 0xc1, 0xd4, 21);

        let partial =
            DistributedAgentStackTerminalObservationsV1::try_new(&request, vec![first.clone()])
                .expect("uncertain can retain a correlated partial observation");
        DistributedAgentStackTerminalFactsV1::try_new(
            &request,
            DistributedAgentStackTerminalOutcomeV1::IndeterminateUncertain,
            DistributedAgentStackTerminalEvidenceFieldsV1 {
                runtime_host_epoch: 11,
                completion_snapshot_sequence: 12,
                selection_clock_generation: request.temporal().target_clock_generation(),
                selection_observed_at_nanos: 13,
                fabric_generation: None,
                agent_generation: None,
                local_bindings: local_binding_evidence(false),
            },
            partial.clone(),
        )
        .expect("partial observations are signed uncertainty facts");
        assert!(matches!(
            DistributedAgentStackTerminalFactsV1::try_new(
                &request,
                DistributedAgentStackTerminalOutcomeV1::ActiveReady,
                DistributedAgentStackTerminalEvidenceFieldsV1 {
                    runtime_host_epoch: 11,
                    completion_snapshot_sequence: 12,
                    selection_clock_generation: request.temporal().target_clock_generation(),
                    selection_observed_at_nanos: 13,
                    fabric_generation: Some(
                        ManagedServiceGeneration::try_new(3).expect("Fabric generation")
                    ),
                    agent_generation: Some(
                        ManagedServiceGeneration::try_new(4).expect("Agent generation")
                    ),
                    local_bindings: local_binding_evidence(true),
                },
                partial,
            ),
            Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch)
        ));
        assert!(matches!(
            DistributedAgentStackTerminalObservationsV1::try_new(
                &request,
                vec![first.clone(), second_other_session],
            ),
            Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch)
        ));
        assert!(matches!(
            DistributedAgentStackTerminalObservationsV1::try_new(
                &request,
                vec![first.clone(), duplicate_sequence],
            ),
            Err(DistributedAgentStackPlanError::TerminalCorrelationMismatch)
        ));
        DistributedAgentStackTerminalObservationsV1::try_new(
            &request,
            vec![first, second_same_session],
        )
        .expect("complete observations from one session are canonical");
    }

    #[test]
    fn exact_zero_local_evidence_excludes_live_generations() {
        let request = empty_request();
        let mut exact_zero = local_binding_evidence(false);
        exact_zero.census_complete = true;
        exact_zero.exact_zero = true;
        exact_zero.installed_binding_set_digest =
            distributed_agent_stack_empty_binding_set_digest_v1().expect("empty binding set");
        let evidence = DistributedAgentStackTerminalEvidenceFieldsV1 {
            runtime_host_epoch: 11,
            completion_snapshot_sequence: 12,
            selection_clock_generation: request.temporal().target_clock_generation(),
            selection_observed_at_nanos: 13,
            fabric_generation: Some(
                ManagedServiceGeneration::try_new(3).expect("contradictory Fabric generation"),
            ),
            agent_generation: None,
            local_bindings: exact_zero,
        };
        assert!(matches!(
            DistributedAgentStackTerminalFactsV1::try_empty_exact_zero(&request, evidence,),
            Err(DistributedAgentStackPlanError::InvalidTerminalFacts)
        ));
        DistributedAgentStackTerminalFactsV1::try_empty_exact_zero(
            &request,
            DistributedAgentStackTerminalEvidenceFieldsV1 {
                fabric_generation: None,
                ..evidence
            },
        )
        .expect("owner-proven exact-zero uses the canonical empty binding set");
    }

    #[test]
    fn empty_exact_zero_pxds_round_trips_without_topology_or_transport_observations() {
        let request = empty_request();
        let evidence = DistributedAgentStackTerminalEvidenceFieldsV1 {
            runtime_host_epoch: 11,
            completion_snapshot_sequence: 12,
            selection_clock_generation: request.temporal().target_clock_generation(),
            selection_observed_at_nanos: 13,
            fabric_generation: None,
            agent_generation: None,
            local_bindings: DistributedAgentStackLocalBindingEvidenceFieldsV1 {
                physical_binding_census: 0,
                census_complete: true,
                fabric_ready: false,
                agent_ready: false,
                dependency_satisfied: false,
                exact_zero: true,
                quarantined: false,
                installed_binding_set_digest: distributed_agent_stack_empty_binding_set_digest_v1()
                    .expect("empty binding set"),
                raw_outcome_digest: Digest32::from_bytes([0xc1; 32]),
            },
        };
        let facts = DistributedAgentStackTerminalFactsV1::try_empty_exact_zero(&request, evidence)
            .expect("empty exact-zero facts");
        let channel = terminal_channel();
        let auth = DistributedAgentStackTerminalAuthClaimV1::try_new(
            channel,
            ApplyAuthKeyRef::from_bytes([0xb4; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("Ed25519 algorithm"),
            1,
        )
        .expect("terminal auth claim");
        let receipt =
            DistributedAgentStackTerminalReceiptDraftV1::try_new(&request, facts, channel, auth)
                .expect("empty PXDS draft")
                .finalize(&[0xb5; 64])
                .expect("empty PXDS");

        assert!(
            !receipt
                .canonical_wire()
                .windows(TRANSPORT_PROOF_MAGIC.len())
                .any(|window| window == TRANSPORT_PROOF_MAGIC),
            "exact-zero PXDS cannot carry a PXTP observation"
        );
        let decoded = DistributedAgentStackTerminalReceiptV1::decode(receipt.canonical_wire())
            .expect("empty PXDS round trip");
        let decoded_facts = decoded
            .validate_against_request(&request, channel)
            .expect("empty PXDS request correlation");
        assert_eq!(
            decoded_facts.outcome(),
            DistributedAgentStackTerminalOutcomeV1::EmptyExactZero
        );
        assert!(decoded_facts.observations().is_none());

        let active_request = distributed_request();
        let active_observations = DistributedAgentStackTerminalObservationsV1::try_new(
            &active_request,
            vec![transport_proof()],
        )
        .expect("active observations");
        assert!(matches!(
            DistributedAgentStackTerminalFactsV1::try_new(
                &active_request,
                DistributedAgentStackTerminalOutcomeV1::EmptyExactZero,
                evidence,
                active_observations,
            ),
            Err(DistributedAgentStackPlanError::InvalidTerminalFacts)
        ));

        let mut nonempty_evidence = evidence;
        nonempty_evidence
            .local_bindings
            .installed_binding_set_digest =
            distributed_agent_stack_installed_binding_set_digest_v1(
                Digest32::from_bytes([0xd1; 32]),
                Digest32::from_bytes([0xd2; 32]),
            )
            .expect("nonempty binding set");
        assert!(matches!(
            DistributedAgentStackTerminalFactsV1::try_empty_exact_zero(&request, nonempty_evidence,),
            Err(DistributedAgentStackPlanError::InvalidTerminalFacts)
        ));
    }

    #[test]
    fn installed_binding_set_digest_is_role_ordered_and_rejects_missing_or_duplicate_rows() {
        let request = Digest32::from_bytes([0x31; 32]);
        let event = Digest32::from_bytes([0x32; 32]);
        let baseline = distributed_agent_stack_installed_binding_set_digest_v1(request, event)
            .expect("ordered installed binding set");
        assert_ne!(
            baseline,
            distributed_agent_stack_empty_binding_set_digest_v1().expect("empty binding set")
        );
        assert_ne!(
            baseline,
            distributed_agent_stack_installed_binding_set_digest_v1(event, request)
                .expect("opposite role assignment is a distinct set")
        );
        assert_ne!(
            baseline,
            distributed_agent_stack_installed_binding_set_digest_v1(
                request,
                Digest32::from_bytes([0x33; 32]),
            )
            .expect("tampered event descriptor produces a distinct set")
        );
        assert!(
            distributed_agent_stack_installed_binding_set_digest_v1(
                Digest32::from_bytes([0; 32]),
                event,
            )
            .is_err()
        );
        assert!(distributed_agent_stack_installed_binding_set_digest_v1(request, request).is_err());
    }

    #[test]
    fn pxds_decode_rejects_tampered_binding_and_non_ed25519_width() {
        let receipt = terminal_receipt(DistributedAgentStackTerminalOutcomeV1::ActiveReady);
        let mut tampered = receipt.canonical_wire().to_vec();
        let proof_offset = tampered
            .windows(TRANSPORT_PROOF_MAGIC.len())
            .position(|window| window == TRANSPORT_PROOF_MAGIC)
            .expect("embedded PXTP");
        tampered[proof_offset + 10] ^= 1;
        assert!(DistributedAgentStackTerminalReceiptV1::decode(&tampered).is_err());

        let request = distributed_request();
        let observations =
            DistributedAgentStackTerminalObservationsV1::try_new(&request, vec![transport_proof()])
                .expect("observations");
        let facts = DistributedAgentStackTerminalFactsV1::try_new(
            &request,
            DistributedAgentStackTerminalOutcomeV1::TerminalNonReady,
            DistributedAgentStackTerminalEvidenceFieldsV1 {
                runtime_host_epoch: 11,
                completion_snapshot_sequence: 12,
                selection_clock_generation: request.temporal().target_clock_generation(),
                selection_observed_at_nanos: 13,
                fabric_generation: None,
                agent_generation: None,
                local_bindings: local_binding_evidence(false),
            },
            observations,
        )
        .expect("facts");
        let channel = terminal_channel();
        let auth = DistributedAgentStackTerminalAuthClaimV1::try_new(
            channel,
            ApplyAuthKeyRef::from_bytes([0xb4; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("Ed25519"),
            1,
        )
        .expect("auth");
        let draft =
            DistributedAgentStackTerminalReceiptDraftV1::try_new(&request, facts, channel, auth)
                .expect("draft");
        assert!(matches!(
            draft.finalize(&[0xb5; 63]),
            Err(DistributedAgentStackPlanError::InvalidResponseAuthentication)
        ));
    }

    #[test]
    fn exact_rust_goldens_freeze_projection_topology_execution_request_and_proof() {
        assert_eq!(
            distributed_agent_stack_compatibility_digest_v1()
                .expect("compatibility digest")
                .as_bytes()
                .as_slice(),
            golden("compatibility_digest").as_slice()
        );
        assert_eq!(projection().canonical_wire(), golden("projection"));
        assert_eq!(topology().canonical_wire(), golden("topology"));
        assert_eq!(active_execution().canonical_wire(), golden("execution"));
        assert_eq!(distributed_request().canonical_wire(), golden("request"));
        assert_eq!(
            transport_proof().canonical_wire(),
            golden("transport_proof")
        );
    }
}
