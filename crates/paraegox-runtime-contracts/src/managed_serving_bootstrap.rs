//! Authenticated Runtime-control bootstrap contracts.
//!
//! PXFB/PXFR v1 is additive to, and semantically distinct from, the legacy
//! PXBR/PXBS compatibility bootstrap. It proves current successor projection,
//! journal, process epoch, clock generation, and live channel facts without
//! mutating Runtime state. Only a recovered-ready response exists in v1.
//!
//! PXAG/PXAH v1 is an independent additive target-scoped Agent-control carrier.
//! It can transport exact frozen PXAR/PXFT/PXST bytes and a bounded opaque PXAP
//! bootstrap descriptor over the public PXCB binding. PXCC/PXDR v1 bytes,
//! kinds, and semantics remain frozen. A descriptor receipt is not a TLS
//! authorization, access grant, live session, capability, or retry authority.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant};

use crate::distributed_agent_stack_plan::{
    MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES, RestrictedRuntimeApplyCarrierBindingV1,
};
use crate::managed_agent_stack_plan::{
    MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES, MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES,
    ManagedAgentStackApplyRequestV1, ManagedAgentStackTerminalReceiptV1,
};
use crate::managed_fabric_plan::{
    MANAGED_FABRIC_PROJECTION_BYTES, MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES,
    MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES, ManagedFabricApplyRequestV1,
    ManagedFabricApplyTerminalReceiptV1, ManagedFabricManifestProjectionV1, ManagedFabricPlanError,
};
use crate::managed_service::ManagedServiceGeneration;
use crate::provenance::SourceScopeRef;
use crate::reference_control::{
    MAX_REFERENCE_QUERY_REQUEST_BYTES, ReferenceChannelBindingV1, ReferenceControlError,
    ReferenceQueryRequestV1,
};
use crate::wire::{
    ApplyAuthAlgorithm, ApplyAuthError, ApplyAuthKeyRef, ApplyRequestAuthClaim,
    ApplyRequestAuthentication, MAX_APPLY_AUTH_NONCE_BYTES, MAX_APPLY_AUTH_SIGNATURE_BYTES,
};

const REQUEST_MAGIC: &[u8; 4] = b"PXFB";
const RESPONSE_MAGIC: &[u8; 4] = b"PXFR";
const REQUEST_TRANSCRIPT_MAGIC: &[u8] = b"ParaEGOX\0managed-serving-bootstrap-request-signing";
const RESPONSE_TRANSCRIPT_MAGIC: &[u8] = b"ParaEGOX\0managed-serving-bootstrap-response-signing";
const REQUEST_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-serving-bootstrap.request.sha256.v1";
const RESPONSE_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-serving-bootstrap.response.sha256.v1";
const CONTROL_CARRIER_REQUEST_MAGIC: &[u8; 4] = b"PXCC";
const CONTROL_DESCRIBE_READY_MAGIC: &[u8; 4] = b"PXDR";
const CONTROL_CARRIER_REQUEST_TRANSCRIPT_MAGIC: &[u8] =
    b"ParaEGOX\0runtime-control-carrier-request-signing";
const CONTROL_DESCRIBE_READY_TRANSCRIPT_MAGIC: &[u8] =
    b"ParaEGOX\0runtime-control-describe-ready-signing";
const CONTROL_CARRIER_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.control-carrier.payload.sha256.v1";
const CONTROL_CARRIER_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.control-carrier.request.sha256.v1";
const CONTROL_DESCRIBE_READY_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.control-describe-ready.sha256.v1";
/// Exact independent Runtime Agent-control request magic.
pub const RUNTIME_AGENT_CONTROL_REQUEST_MAGIC: &[u8; 4] = b"PXAG";
/// Exact independent Runtime Agent-control receipt magic.
pub const RUNTIME_AGENT_CONTROL_RECEIPT_MAGIC: &[u8; 4] = b"PXAH";
const AGENT_CONTROL_REQUEST_TRANSCRIPT_MAGIC: &[u8] =
    b"ParaEGOX\0runtime-agent-control-request-signing";
const AGENT_CONTROL_RECEIPT_TRANSCRIPT_MAGIC: &[u8] =
    b"ParaEGOX\0runtime-agent-control-receipt-signing";
const AGENT_CONTROL_REQUEST_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.agent-control.request-payload.sha256.v1";
const AGENT_CONTROL_RECEIPT_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.agent-control.receipt-payload.sha256.v1";
const AGENT_CONTROL_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.agent-control.request.sha256.v1";
const AGENT_CONTROL_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.agent-control.receipt.sha256.v1";
const REQUEST_FIXED_BYTES: usize = 226;
const RESPONSE_FIXED_BYTES: usize = 324;
const CONTROL_CARRIER_REQUEST_FIXED_BYTES: usize = 136;
const CONTROL_DESCRIBE_READY_FIXED_BYTES: usize = 362;
const AGENT_CONTROL_REQUEST_FIXED_BYTES: usize = 240;
const AGENT_CONTROL_RECEIPT_FIXED_BYTES: usize = 320;
const MAX_RUNTIME_CONTROL_CARRIER_PAYLOAD_BYTES: usize =
    if MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES > MAX_REFERENCE_QUERY_REQUEST_BYTES {
        MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES
    } else {
        MAX_REFERENCE_QUERY_REQUEST_BYTES
    };

/// Exact PXFB/PXFR protocol version.
pub const MANAGED_SERVING_BOOTSTRAP_VERSION: u16 = 1;
/// Exact request signing transcript version.
pub const MANAGED_SERVING_BOOTSTRAP_REQUEST_SIGNING_VERSION: u16 = 1;
/// Exact response signing transcript version.
pub const MANAGED_SERVING_BOOTSTRAP_RESPONSE_SIGNING_VERSION: u16 = 1;
/// Maximum canonical PXFB request size.
pub const MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES: usize = 2_048;
/// Maximum canonical PXFR response size.
pub const MAX_MANAGED_SERVING_BOOTSTRAP_RESPONSE_BYTES: usize = 2_048;
/// Additive PXCC/PXDR control-carrier protocol version.
pub const RUNTIME_CONTROL_CARRIER_VERSION: u16 = 1;
/// Exact PXCC Controller signing-transcript version.
pub const RUNTIME_CONTROL_CARRIER_REQUEST_SIGNING_VERSION: u16 = 1;
/// Exact PXDR Runtime signing-transcript version.
pub const RUNTIME_CONTROL_DESCRIBE_READY_SIGNING_VERSION: u16 = 1;
/// Maximum canonical PXCC request size.
pub const MAX_RUNTIME_CONTROL_CARRIER_REQUEST_BYTES: usize = CONTROL_CARRIER_REQUEST_FIXED_BYTES
    + MAX_APPLY_AUTH_NONCE_BYTES
    + MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
    + MAX_RUNTIME_CONTROL_CARRIER_PAYLOAD_BYTES
    + MAX_APPLY_AUTH_SIGNATURE_BYTES;
/// Maximum canonical PXDR response size.
pub const MAX_RUNTIME_CONTROL_DESCRIBE_READY_RESPONSE_BYTES: usize =
    CONTROL_DESCRIBE_READY_FIXED_BYTES
        + MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
        + MANAGED_FABRIC_PROJECTION_BYTES
        + MAX_APPLY_AUTH_NONCE_BYTES
        + MAX_APPLY_AUTH_SIGNATURE_BYTES;
/// Independent additive PXAG/PXAH Agent-control protocol version.
pub const RUNTIME_AGENT_CONTROL_VERSION: u16 = 1;
/// Exact PXAG Controller signing-transcript version.
pub const RUNTIME_AGENT_CONTROL_REQUEST_SIGNING_VERSION: u16 = 1;
/// Exact PXAH Runtime signing-transcript version.
pub const RUNTIME_AGENT_CONTROL_RECEIPT_SIGNING_VERSION: u16 = 1;
/// Maximum opaque PXAP bootstrap descriptor bytes carried by PXAH.
pub const MAX_RUNTIME_AGENT_PORT_DESCRIPTOR_BYTES: usize = 2_048;
const MAX_RUNTIME_AGENT_CONTROL_REQUEST_PAYLOAD_BYTES: usize =
    if MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES > MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES {
        MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES
    } else {
        MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES
    };
const MAX_RUNTIME_AGENT_CONTROL_RECEIPT_PAYLOAD_BYTES: usize =
    if MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES
        > MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES
    {
        if MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES > MAX_RUNTIME_AGENT_PORT_DESCRIPTOR_BYTES
        {
            MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES
        } else {
            MAX_RUNTIME_AGENT_PORT_DESCRIPTOR_BYTES
        }
    } else if MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES
        > MAX_RUNTIME_AGENT_PORT_DESCRIPTOR_BYTES
    {
        MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES
    } else {
        MAX_RUNTIME_AGENT_PORT_DESCRIPTOR_BYTES
    };
/// Maximum canonical PXAG request bytes.
pub const MAX_RUNTIME_AGENT_CONTROL_REQUEST_BYTES: usize = AGENT_CONTROL_REQUEST_FIXED_BYTES
    + MAX_APPLY_AUTH_NONCE_BYTES
    + MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
    + MAX_RUNTIME_AGENT_CONTROL_REQUEST_PAYLOAD_BYTES
    + MAX_APPLY_AUTH_SIGNATURE_BYTES;
/// Maximum canonical PXAH receipt bytes.
pub const MAX_RUNTIME_AGENT_CONTROL_RECEIPT_BYTES: usize = AGENT_CONTROL_RECEIPT_FIXED_BYTES
    + MAX_APPLY_AUTH_NONCE_BYTES
    + MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
    + MAX_RUNTIME_AGENT_CONTROL_RECEIPT_PAYLOAD_BYTES
    + MAX_APPLY_AUTH_SIGNATURE_BYTES;

/// Nonzero identity of one explicit Controller observation invocation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedServingBootstrapRequestIdV1([u8; 16]);

impl ManagedServingBootstrapRequestIdV1 {
    /// Constructs a nonzero request identity.
    pub const fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, ManagedServingBootstrapError> {
        if bytes_are_zero(&bytes) {
            return Err(ManagedServingBootstrapError::InvalidIdentity);
        }
        Ok(Self(bytes))
    }

    /// Returns exact identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Only readiness fact that a v1 Runtime may publish.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum ManagedServingReadinessV1 {
    /// Recovery completed before the control listener was published.
    RecoveredReady = 1,
}

/// Exact current Runtime observation signed into PXFR v1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedServingBootstrapFactsV1 {
    target: RuntimeHostId,
    runtime_store_instance_id: [u8; 32],
    projection: ManagedFabricManifestProjectionV1,
    runtime_host_epoch: u64,
    snapshot_sequence: u64,
    clock_domain: ClockDomainRef,
    clock_generation: ClockGeneration,
    observed_at_nanos: u64,
    readiness: ManagedServingReadinessV1,
}

impl ManagedServingBootstrapFactsV1 {
    /// Creates one recovered-ready observation from Runtime-owned current facts.
    pub fn try_recovered_ready(
        target: RuntimeHostId,
        runtime_store_instance_id: [u8; 32],
        projection: ManagedFabricManifestProjectionV1,
        runtime_host_epoch: u64,
        snapshot_sequence: u64,
        reading: ClockReading,
    ) -> Result<Self, ManagedServingBootstrapError> {
        if bytes_are_zero(target.as_bytes())
            || bytes_are_zero(&runtime_store_instance_id)
            || projection.target() != target
            || runtime_host_epoch == 0
            || snapshot_sequence == 0
            || bytes_are_zero(reading.domain().as_bytes())
            || reading.now().value() == 0
        {
            return Err(ManagedServingBootstrapError::InvalidFacts);
        }
        Ok(Self {
            target,
            runtime_store_instance_id,
            projection,
            runtime_host_epoch,
            snapshot_sequence,
            clock_domain: reading.domain(),
            clock_generation: reading.generation(),
            observed_at_nanos: reading.now().value(),
            readiness: ManagedServingReadinessV1::RecoveredReady,
        })
    }

    /// Returns the observed Runtime target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    /// Returns the exact successor Runtime journal identity.
    #[must_use]
    pub const fn runtime_store_instance_id(&self) -> [u8; 32] {
        self.runtime_store_instance_id
    }

    /// Returns the Runtime-locally derived managed projection.
    #[must_use]
    pub const fn projection(&self) -> &ManagedFabricManifestProjectionV1 {
        &self.projection
    }

    /// Returns the current nonzero Runtime process epoch.
    #[must_use]
    pub const fn runtime_host_epoch(&self) -> u64 {
        self.runtime_host_epoch
    }

    /// Returns the current nonzero successor snapshot sequence.
    #[must_use]
    pub const fn snapshot_sequence(&self) -> u64 {
        self.snapshot_sequence
    }

    /// Returns the current target-local clock domain.
    #[must_use]
    pub const fn clock_domain(&self) -> ClockDomainRef {
        self.clock_domain
    }

    /// Returns the current target-local clock generation.
    #[must_use]
    pub const fn clock_generation(&self) -> ClockGeneration {
        self.clock_generation
    }

    /// Returns the Runtime-local observation reading.
    #[must_use]
    pub const fn observed_at_nanos(&self) -> u64 {
        self.observed_at_nanos
    }

    /// Returns recovered-ready; no not-ready response exists in v1.
    #[must_use]
    pub const fn readiness(&self) -> ManagedServingReadinessV1 {
        self.readiness
    }
}

/// Exact request or response bytes supplied to the selected signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedServingBootstrapSigningTranscriptV1(Box<[u8]>);

impl ManagedServingBootstrapSigningTranscriptV1 {
    /// Returns exact signing bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent PXFB v1 producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedServingBootstrapRequestDraftV1 {
    request_id: ManagedServingBootstrapRequestIdV1,
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    expected_runtime_store_instance_id: [u8; 32],
    projection: ManagedFabricManifestProjectionV1,
    channel: ReferenceChannelBindingV1,
    auth_claim: ApplyRequestAuthClaim,
}

impl ManagedServingBootstrapRequestDraftV1 {
    /// Builds an observation request bound to exact store, projection and channel facts.
    pub fn try_new(
        request_id: ManagedServingBootstrapRequestIdV1,
        target: RuntimeHostId,
        source_scope: SourceScopeRef,
        expected_runtime_store_instance_id: [u8; 32],
        projection: ManagedFabricManifestProjectionV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, ManagedServingBootstrapError> {
        validate_request_fields(
            request_id,
            target,
            source_scope,
            expected_runtime_store_instance_id,
            &projection,
            channel,
            &auth_claim,
        )?;
        Ok(Self {
            request_id,
            target,
            source_scope,
            expected_runtime_store_instance_id,
            projection,
            channel,
            auth_claim,
        })
    }

    /// Builds exact Controller signing bytes.
    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedServingBootstrapSigningTranscriptV1, ManagedServingBootstrapError> {
        Ok(ManagedServingBootstrapSigningTranscriptV1(
            build_request_transcript(self)?.into_boxed_slice(),
        ))
    }

    /// Freezes a signed canonical PXFB request.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ManagedServingBootstrapRequestV1, ManagedServingBootstrapError> {
        let authentication =
            ApplyRequestAuthentication::try_new(self.auth_claim.clone(), signature)?;
        ManagedServingBootstrapRequestV1::try_new(self, authentication)
    }
}

/// Signed strict PXFB v1 read-only observation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedServingBootstrapRequestV1 {
    request_id: ManagedServingBootstrapRequestIdV1,
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    expected_runtime_store_instance_id: [u8; 32],
    projection: ManagedFabricManifestProjectionV1,
    channel: ReferenceChannelBindingV1,
    authentication: ApplyRequestAuthentication,
    canonical_wire: Box<[u8]>,
    request_digest: Digest32,
}

impl ManagedServingBootstrapRequestV1 {
    fn try_new(
        draft: ManagedServingBootstrapRequestDraftV1,
        authentication: ApplyRequestAuthentication,
    ) -> Result<Self, ManagedServingBootstrapError> {
        if authentication.claim() != &draft.auth_claim {
            return Err(ManagedServingBootstrapError::AuthenticationMismatch);
        }
        let canonical_wire = build_request_wire(&draft, &authentication)?;
        if canonical_wire.len() > MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        let request_digest = digest(REQUEST_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            request_id: draft.request_id,
            target: draft.target,
            source_scope: draft.source_scope,
            expected_runtime_store_instance_id: draft.expected_runtime_store_instance_id,
            projection: draft.projection,
            channel: draft.channel,
            authentication,
            canonical_wire: canonical_wire.into_boxed_slice(),
            request_digest,
        })
    }

    /// Strictly decodes exactly PXFB v1 without fallback.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedServingBootstrapError> {
        if frame.len() > MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        if frame.len() < REQUEST_FIXED_BYTES + MANAGED_FABRIC_PROJECTION_BYTES {
            return Err(ManagedServingBootstrapError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.array::<4>()? != *REQUEST_MAGIC
            || cursor.u16()? != MANAGED_SERVING_BOOTSTRAP_VERSION
        {
            return Err(ManagedServingBootstrapError::UnsupportedWire);
        }
        let request_id = ManagedServingBootstrapRequestIdV1::try_from_bytes(cursor.array()?)?;
        let target = RuntimeHostId::from_bytes(cursor.array()?);
        let source_scope = SourceScopeRef::from_bytes(cursor.array()?);
        let expected_runtime_store_instance_id = cursor.array()?;
        let projection_length = cursor.usize_u32()?;
        let channel = decode_channel(&mut cursor)?;
        let auth_claim = decode_request_claim(&mut cursor)?;
        let signature_length = cursor.usize_u16()?;
        if projection_length != MANAGED_FABRIC_PROJECTION_BYTES
            || signature_length == 0
            || signature_length > MAX_APPLY_AUTH_SIGNATURE_BYTES
        {
            return Err(ManagedServingBootstrapError::InvalidLength);
        }
        let projection =
            ManagedFabricManifestProjectionV1::decode(cursor.take(projection_length)?)?;
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let draft = ManagedServingBootstrapRequestDraftV1::try_new(
            request_id,
            target,
            source_scope,
            expected_runtime_store_instance_id,
            projection,
            channel,
            auth_claim,
        )?;
        let decoded = draft.finalize(signature)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedServingBootstrapError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Returns the request identity.
    #[must_use]
    pub const fn request_id(&self) -> ManagedServingBootstrapRequestIdV1 {
        self.request_id
    }

    /// Returns the requested Runtime target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    /// Returns the Controller source scope.
    #[must_use]
    pub const fn source_scope(&self) -> SourceScopeRef {
        self.source_scope
    }

    /// Returns the exact expected successor Runtime store.
    #[must_use]
    pub const fn expected_runtime_store_instance_id(&self) -> [u8; 32] {
        self.expected_runtime_store_instance_id
    }

    /// Returns the exact Controller-derived expected projection.
    #[must_use]
    pub const fn projection(&self) -> &ManagedFabricManifestProjectionV1 {
        &self.projection
    }

    /// Returns the exact live channel binding.
    #[must_use]
    pub const fn channel(&self) -> ReferenceChannelBindingV1 {
        self.channel
    }

    /// Returns request authentication.
    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        &self.authentication
    }

    /// Returns exact canonical request bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the domain-separated digest of the complete signed request.
    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    /// Reconstructs exact Controller signing bytes.
    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedServingBootstrapSigningTranscriptV1, ManagedServingBootstrapError> {
        ManagedServingBootstrapRequestDraftV1::try_new(
            self.request_id,
            self.target,
            self.source_scope,
            self.expected_runtime_store_instance_id,
            self.projection.clone(),
            self.channel,
            self.authentication.claim().clone(),
        )?
        .signing_transcript()
    }
}

/// Runtime response signer selection bound to the observed live channel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManagedServingBootstrapResponseAuthClaimV1 {
    runtime_peer: PrincipalRef,
    channel_binding_digest: Digest32,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

impl ManagedServingBootstrapResponseAuthClaimV1 {
    /// Selects one Runtime response key for the exact channel.
    pub fn try_new(
        channel: ReferenceChannelBindingV1,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, ManagedServingBootstrapError> {
        if algorithm_version == 0 || bytes_are_zero(key.as_bytes()) {
            return Err(ManagedServingBootstrapError::InvalidAuthentication);
        }
        Ok(Self {
            runtime_peer: channel.runtime_peer(),
            channel_binding_digest: channel.binding_digest(),
            key,
            algorithm,
            algorithm_version,
        })
    }

    /// Returns the authenticated Runtime peer.
    #[must_use]
    pub const fn runtime_peer(self) -> PrincipalRef {
        self.runtime_peer
    }

    /// Returns the exact channel-binding digest.
    #[must_use]
    pub const fn channel_binding_digest(self) -> Digest32 {
        self.channel_binding_digest
    }

    /// Returns the response key reference.
    #[must_use]
    pub const fn key(self) -> ApplyAuthKeyRef {
        self.key
    }

    /// Returns the response algorithm.
    #[must_use]
    pub const fn algorithm(self) -> ApplyAuthAlgorithm {
        self.algorithm
    }

    /// Returns the response algorithm version.
    #[must_use]
    pub const fn algorithm_version(self) -> u16 {
        self.algorithm_version
    }
}

/// Signature-independent PXFR v1 producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedServingBootstrapResponseDraftV1 {
    request_id: ManagedServingBootstrapRequestIdV1,
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    facts: ManagedServingBootstrapFactsV1,
    channel: ReferenceChannelBindingV1,
    auth_claim: ManagedServingBootstrapResponseAuthClaimV1,
}

impl ManagedServingBootstrapResponseDraftV1 {
    /// Binds recovered-ready current facts to one exact PXFB request.
    pub fn try_new(
        request: &ManagedServingBootstrapRequestV1,
        facts: ManagedServingBootstrapFactsV1,
        channel: ReferenceChannelBindingV1,
        auth_claim: ManagedServingBootstrapResponseAuthClaimV1,
    ) -> Result<Self, ManagedServingBootstrapError> {
        if request.target != facts.target
            || request.expected_runtime_store_instance_id != facts.runtime_store_instance_id
            || request.projection != facts.projection
            || request.channel != channel
            || channel.target() != facts.target
            || auth_claim.runtime_peer != channel.runtime_peer()
            || auth_claim.channel_binding_digest != channel.binding_digest()
        {
            return Err(ManagedServingBootstrapError::CorrelationMismatch);
        }
        Ok(Self {
            request_id: request.request_id,
            request_digest: request.request_digest,
            request_nonce: request.authentication.claim().nonce().into(),
            facts,
            channel,
            auth_claim,
        })
    }

    /// Builds exact Runtime signing bytes.
    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedServingBootstrapSigningTranscriptV1, ManagedServingBootstrapError> {
        Ok(ManagedServingBootstrapSigningTranscriptV1(
            build_response_transcript(self)?.into_boxed_slice(),
        ))
    }

    /// Freezes a signed canonical PXFR response.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<ManagedServingBootstrapResponseV1, ManagedServingBootstrapError> {
        if signature.is_empty() || signature.len() > MAX_APPLY_AUTH_SIGNATURE_BYTES {
            return Err(ManagedServingBootstrapError::InvalidAuthentication);
        }
        ManagedServingBootstrapResponseV1::try_new(self, signature)
    }
}

/// Signed strict PXFR v1 recovered-ready observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedServingBootstrapResponseV1 {
    request_id: ManagedServingBootstrapRequestIdV1,
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    facts: ManagedServingBootstrapFactsV1,
    channel: ReferenceChannelBindingV1,
    auth_claim: ManagedServingBootstrapResponseAuthClaimV1,
    signature: Box<[u8]>,
    canonical_wire: Box<[u8]>,
    response_digest: Digest32,
}

impl ManagedServingBootstrapResponseV1 {
    fn try_new(
        draft: ManagedServingBootstrapResponseDraftV1,
        signature: &[u8],
    ) -> Result<Self, ManagedServingBootstrapError> {
        let canonical_wire = build_response_wire(&draft, signature)?;
        if canonical_wire.len() > MAX_MANAGED_SERVING_BOOTSTRAP_RESPONSE_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        let response_digest = digest(RESPONSE_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            request_id: draft.request_id,
            request_digest: draft.request_digest,
            request_nonce: draft.request_nonce,
            facts: draft.facts,
            channel: draft.channel,
            auth_claim: draft.auth_claim,
            signature: signature.into(),
            canonical_wire: canonical_wire.into_boxed_slice(),
            response_digest,
        })
    }

    /// Strictly decodes exactly PXFR v1 without fallback.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedServingBootstrapError> {
        if frame.len() > MAX_MANAGED_SERVING_BOOTSTRAP_RESPONSE_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        if frame.len() < RESPONSE_FIXED_BYTES + MANAGED_FABRIC_PROJECTION_BYTES {
            return Err(ManagedServingBootstrapError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.array::<4>()? != *RESPONSE_MAGIC
            || cursor.u16()? != MANAGED_SERVING_BOOTSTRAP_VERSION
        {
            return Err(ManagedServingBootstrapError::UnsupportedWire);
        }
        let request_id = ManagedServingBootstrapRequestIdV1::try_from_bytes(cursor.array()?)?;
        let request_digest = Digest32::from_bytes(cursor.array()?);
        let nonce_length = cursor.usize_u16()?;
        let target = RuntimeHostId::from_bytes(cursor.array()?);
        let runtime_store_instance_id = cursor.array()?;
        let projection_length = cursor.usize_u32()?;
        let runtime_host_epoch = cursor.u64()?;
        let snapshot_sequence = cursor.u64()?;
        let clock_domain = ClockDomainRef::from_bytes(cursor.array()?);
        let clock_generation = ClockGeneration::try_new(cursor.u64()?)
            .map_err(|_| ManagedServingBootstrapError::InvalidFacts)?;
        let observed_at_nanos = cursor.u64()?;
        if cursor.u16()? != ManagedServingReadinessV1::RecoveredReady as u16 {
            return Err(ManagedServingBootstrapError::UnsupportedReadiness);
        }
        let channel = decode_channel(&mut cursor)?;
        let auth_claim = decode_response_claim(&mut cursor)?;
        let signature_length = cursor.usize_u16()?;
        if nonce_length == 0
            || nonce_length > MAX_APPLY_AUTH_NONCE_BYTES
            || projection_length != MANAGED_FABRIC_PROJECTION_BYTES
            || signature_length == 0
            || signature_length > MAX_APPLY_AUTH_SIGNATURE_BYTES
        {
            return Err(ManagedServingBootstrapError::InvalidLength);
        }
        let projection =
            ManagedFabricManifestProjectionV1::decode(cursor.take(projection_length)?)?;
        let request_nonce: Box<[u8]> = cursor.take(nonce_length)?.into();
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let facts = ManagedServingBootstrapFactsV1::try_recovered_ready(
            target,
            runtime_store_instance_id,
            projection,
            runtime_host_epoch,
            snapshot_sequence,
            ClockReading::new(
                clock_domain,
                clock_generation,
                MonotonicInstant::from_ticks(observed_at_nanos),
            ),
        )?;
        let draft = ManagedServingBootstrapResponseDraftV1 {
            request_id,
            request_digest,
            request_nonce,
            facts,
            channel,
            auth_claim,
        };
        let decoded = draft.finalize(signature)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedServingBootstrapError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Validates every request echo, current store/projection and live channel fact.
    pub fn validate_against_request(
        &self,
        request: &ManagedServingBootstrapRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<&ManagedServingBootstrapFactsV1, ManagedServingBootstrapError> {
        if self.request_id != request.request_id
            || self.request_digest != request.request_digest
            || self.request_nonce.as_ref() != request.authentication.claim().nonce()
            || self.facts.target != request.target
            || self.facts.runtime_store_instance_id != request.expected_runtime_store_instance_id
            || self.facts.projection != request.projection
            || self.channel != request.channel
            || self.channel != channel
            || self.auth_claim.runtime_peer != channel.runtime_peer()
            || self.auth_claim.channel_binding_digest != channel.binding_digest()
            || self.facts.readiness != ManagedServingReadinessV1::RecoveredReady
        {
            return Err(ManagedServingBootstrapError::CorrelationMismatch);
        }
        Ok(&self.facts)
    }

    /// Returns the echoed request identity.
    #[must_use]
    pub const fn request_id(&self) -> ManagedServingBootstrapRequestIdV1 {
        self.request_id
    }

    /// Returns the echoed complete request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    /// Returns the echoed Controller nonce.
    #[must_use]
    pub fn request_nonce(&self) -> &[u8] {
        &self.request_nonce
    }

    /// Returns untrusted facts until correlation and signature checks succeed.
    #[must_use]
    pub const fn facts(&self) -> &ManagedServingBootstrapFactsV1 {
        &self.facts
    }

    /// Returns the authenticated Runtime peer.
    #[must_use]
    pub const fn authentication_runtime_peer(&self) -> PrincipalRef {
        self.auth_claim.runtime_peer
    }

    /// Returns the response channel-binding digest.
    #[must_use]
    pub const fn authentication_channel_binding_digest(&self) -> Digest32 {
        self.auth_claim.channel_binding_digest
    }

    /// Returns the Runtime response key reference.
    #[must_use]
    pub const fn authentication_key(&self) -> ApplyAuthKeyRef {
        self.auth_claim.key
    }

    /// Returns the response authentication algorithm.
    #[must_use]
    pub const fn authentication_algorithm(&self) -> ApplyAuthAlgorithm {
        self.auth_claim.algorithm
    }

    /// Returns the response authentication algorithm version.
    #[must_use]
    pub const fn authentication_algorithm_version(&self) -> u16 {
        self.auth_claim.algorithm_version
    }

    /// Returns the opaque Runtime response signature.
    #[must_use]
    pub fn authentication_signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns exact canonical response bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the domain-separated complete response digest.
    #[must_use]
    pub const fn response_digest(&self) -> Digest32 {
        self.response_digest
    }

    /// Reconstructs exact Runtime signing bytes.
    pub fn signing_transcript(
        &self,
    ) -> Result<ManagedServingBootstrapSigningTranscriptV1, ManagedServingBootstrapError> {
        ManagedServingBootstrapResponseDraftV1 {
            request_id: self.request_id,
            request_digest: self.request_digest,
            request_nonce: self.request_nonce.clone(),
            facts: self.facts.clone(),
            channel: self.channel,
            auth_claim: self.auth_claim,
        }
        .signing_transcript()
    }
}

/// Nonzero identity of one target-scoped Agent-control invocation.
///
/// Apply requests additionally require these bytes to equal the wrapped PXAR
/// operation identity, avoiding two independently meaningful request IDs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeAgentControlRequestIdV1([u8; 16]);

impl RuntimeAgentControlRequestIdV1 {
    pub const fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, ManagedServingBootstrapError> {
        if bytes_are_zero(&bytes) {
            return Err(ManagedServingBootstrapError::InvalidIdentity);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Operation admitted by the independent Controller-signed PXAG carrier.
///
/// This is deliberately not a PXCC v1 extension. Apply kinds preserve one
/// byte-identical independently signed PXAR request; Describe carries no
/// payload and only requests a target-scoped bootstrap descriptor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum RuntimeAgentControlKindV1 {
    ApplyManagedFabric = 1,
    ApplyManagedAgentStack = 2,
    DescribeConversationPort = 3,
}

impl RuntimeAgentControlKindV1 {
    fn decode(value: u16) -> Result<Self, ManagedServingBootstrapError> {
        match value {
            1 => Ok(Self::ApplyManagedFabric),
            2 => Ok(Self::ApplyManagedAgentStack),
            3 => Ok(Self::DescribeConversationPort),
            _ => Err(ManagedServingBootstrapError::UnsupportedAgentControlKind),
        }
    }
}

/// Shared target and signer fields used to construct one PXAG request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAgentControlRequestFieldsV1 {
    pub request_id: RuntimeAgentControlRequestIdV1,
    pub carrier: RestrictedRuntimeApplyCarrierBindingV1,
    pub target: RuntimeHostId,
    pub expected_runtime_store_instance_id: [u8; 32],
    pub expected_runtime_host_epoch: u64,
    pub auth_claim: ApplyRequestAuthClaim,
}

/// Exact Controller or Runtime signing bytes for PXAG/PXAH.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAgentControlSigningTranscriptV1(Box<[u8]>);

impl RuntimeAgentControlSigningTranscriptV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent producer for one Controller PXAG request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAgentControlRequestDraftV1 {
    request_id: RuntimeAgentControlRequestIdV1,
    kind: RuntimeAgentControlKindV1,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    target: RuntimeHostId,
    expected_runtime_store_instance_id: [u8; 32],
    expected_runtime_host_epoch: u64,
    expected_active_pxst_digest: Digest32,
    intended_client: PrincipalRef,
    managed_fabric_apply_request: Option<ManagedFabricApplyRequestV1>,
    managed_agent_stack_apply_request: Option<ManagedAgentStackApplyRequestV1>,
    payload_wire_digest: Digest32,
    auth_claim: ApplyRequestAuthClaim,
}

impl RuntimeAgentControlRequestDraftV1 {
    /// Wraps one byte-identical PXAR v6 request.
    pub fn try_apply_managed_fabric(
        fields: RuntimeAgentControlRequestFieldsV1,
        request: ManagedFabricApplyRequestV1,
    ) -> Result<Self, ManagedServingBootstrapError> {
        Self::try_new(
            fields,
            RuntimeAgentControlKindV1::ApplyManagedFabric,
            Digest32::from_bytes([0; 32]),
            PrincipalRef::from_bytes([0; 16]),
            Some(request),
            None,
        )
    }

    /// Wraps one byte-identical PXAR v7 request.
    pub fn try_apply_managed_agent_stack(
        fields: RuntimeAgentControlRequestFieldsV1,
        request: ManagedAgentStackApplyRequestV1,
    ) -> Result<Self, ManagedServingBootstrapError> {
        Self::try_new(
            fields,
            RuntimeAgentControlKindV1::ApplyManagedAgentStack,
            Digest32::from_bytes([0; 32]),
            PrincipalRef::from_bytes([0; 16]),
            None,
            Some(request),
        )
    }

    /// Requests a PXAP bootstrap descriptor for the current exact PXST root.
    ///
    /// The intended client is an audience binding, not an access grant. This
    /// request creates no TLS authorization, session, capability, or retry
    /// authority and has no inner payload.
    pub fn try_describe_conversation_port(
        fields: RuntimeAgentControlRequestFieldsV1,
        expected_active_pxst_digest: Digest32,
        intended_client: PrincipalRef,
    ) -> Result<Self, ManagedServingBootstrapError> {
        Self::try_new(
            fields,
            RuntimeAgentControlKindV1::DescribeConversationPort,
            expected_active_pxst_digest,
            intended_client,
            None,
            None,
        )
    }

    fn try_new(
        fields: RuntimeAgentControlRequestFieldsV1,
        kind: RuntimeAgentControlKindV1,
        expected_active_pxst_digest: Digest32,
        intended_client: PrincipalRef,
        managed_fabric_apply_request: Option<ManagedFabricApplyRequestV1>,
        managed_agent_stack_apply_request: Option<ManagedAgentStackApplyRequestV1>,
    ) -> Result<Self, ManagedServingBootstrapError> {
        validate_runtime_agent_control_request_fields(
            &fields,
            kind,
            expected_active_pxst_digest,
            intended_client,
            managed_fabric_apply_request.as_ref(),
            managed_agent_stack_apply_request.as_ref(),
        )?;
        let payload_wire_digest = match (
            managed_fabric_apply_request.as_ref(),
            managed_agent_stack_apply_request.as_ref(),
        ) {
            (Some(request), None) => digest(
                AGENT_CONTROL_REQUEST_PAYLOAD_DIGEST_DOMAIN,
                request.canonical_wire(),
            )?,
            (None, Some(request)) => digest(
                AGENT_CONTROL_REQUEST_PAYLOAD_DIGEST_DOMAIN,
                request.canonical_wire(),
            )?,
            (None, None) => Digest32::from_bytes([0; 32]),
            (Some(_), Some(_)) => {
                return Err(ManagedServingBootstrapError::InvalidAgentControlPayload);
            }
        };
        Ok(Self {
            request_id: fields.request_id,
            kind,
            carrier: fields.carrier,
            target: fields.target,
            expected_runtime_store_instance_id: fields.expected_runtime_store_instance_id,
            expected_runtime_host_epoch: fields.expected_runtime_host_epoch,
            expected_active_pxst_digest,
            intended_client,
            managed_fabric_apply_request,
            managed_agent_stack_apply_request,
            payload_wire_digest,
            auth_claim: fields.auth_claim,
        })
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<RuntimeAgentControlSigningTranscriptV1, ManagedServingBootstrapError> {
        let mut transcript = build_runtime_agent_control_request_base(
            self,
            AGENT_CONTROL_REQUEST_TRANSCRIPT_MAGIC,
            RUNTIME_AGENT_CONTROL_REQUEST_SIGNING_VERSION,
        )?;
        append_runtime_agent_control_request_values(&mut transcript, self);
        Ok(RuntimeAgentControlSigningTranscriptV1(
            transcript.into_boxed_slice(),
        ))
    }

    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<RuntimeAgentControlRequestV1, ManagedServingBootstrapError> {
        let authentication =
            ApplyRequestAuthentication::try_new(self.auth_claim.clone(), signature)?;
        RuntimeAgentControlRequestV1::try_new(self, authentication)
    }
}

/// Strict Controller-signed PXAG request on one exact PXCB binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAgentControlRequestV1 {
    request_id: RuntimeAgentControlRequestIdV1,
    kind: RuntimeAgentControlKindV1,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    target: RuntimeHostId,
    expected_runtime_store_instance_id: [u8; 32],
    expected_runtime_host_epoch: u64,
    expected_active_pxst_digest: Digest32,
    intended_client: PrincipalRef,
    managed_fabric_apply_request: Option<ManagedFabricApplyRequestV1>,
    managed_agent_stack_apply_request: Option<ManagedAgentStackApplyRequestV1>,
    payload_wire_digest: Digest32,
    authentication: ApplyRequestAuthentication,
    canonical_wire: Box<[u8]>,
    request_digest: Digest32,
}

impl RuntimeAgentControlRequestV1 {
    fn try_new(
        draft: RuntimeAgentControlRequestDraftV1,
        authentication: ApplyRequestAuthentication,
    ) -> Result<Self, ManagedServingBootstrapError> {
        if authentication.claim() != &draft.auth_claim {
            return Err(ManagedServingBootstrapError::AuthenticationMismatch);
        }
        let canonical_wire = build_runtime_agent_control_request_wire(&draft, &authentication)?;
        if canonical_wire.len() > MAX_RUNTIME_AGENT_CONTROL_REQUEST_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        let request_digest = digest(AGENT_CONTROL_REQUEST_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            request_id: draft.request_id,
            kind: draft.kind,
            carrier: draft.carrier,
            target: draft.target,
            expected_runtime_store_instance_id: draft.expected_runtime_store_instance_id,
            expected_runtime_host_epoch: draft.expected_runtime_host_epoch,
            expected_active_pxst_digest: draft.expected_active_pxst_digest,
            intended_client: draft.intended_client,
            managed_fabric_apply_request: draft.managed_fabric_apply_request,
            managed_agent_stack_apply_request: draft.managed_agent_stack_apply_request,
            payload_wire_digest: draft.payload_wire_digest,
            authentication,
            canonical_wire: canonical_wire.into_boxed_slice(),
            request_digest,
        })
    }

    /// Strictly decodes one bounded canonical PXAG v1 frame.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedServingBootstrapError> {
        if frame.len() > MAX_RUNTIME_AGENT_CONTROL_REQUEST_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        if frame.len() < AGENT_CONTROL_REQUEST_FIXED_BYTES {
            return Err(ManagedServingBootstrapError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.array::<4>()? != *RUNTIME_AGENT_CONTROL_REQUEST_MAGIC
            || cursor.u16()? != RUNTIME_AGENT_CONTROL_VERSION
        {
            return Err(ManagedServingBootstrapError::UnsupportedWire);
        }
        let kind = RuntimeAgentControlKindV1::decode(cursor.u16()?)?;
        if cursor.u16()? != 0 {
            return Err(ManagedServingBootstrapError::NonCanonicalFrame);
        }
        let carrier_length = cursor.usize_u16()?;
        let payload_length = cursor.usize_u32()?;
        let request_id = RuntimeAgentControlRequestIdV1::try_from_bytes(cursor.array()?)?;
        let carrier_digest = Digest32::from_bytes(cursor.array()?);
        let target = RuntimeHostId::from_bytes(cursor.array()?);
        let expected_runtime_store_instance_id = cursor.array()?;
        let expected_runtime_host_epoch = cursor.u64()?;
        let expected_active_pxst_digest = Digest32::from_bytes(cursor.array()?);
        let intended_client = PrincipalRef::from_bytes(cursor.array()?);
        let payload_wire_digest = Digest32::from_bytes(cursor.array()?);
        let auth_claim = decode_request_claim(&mut cursor)?;
        let signature_length = cursor.usize_u16()?;
        validate_runtime_agent_control_request_lengths(
            kind,
            carrier_length,
            payload_length,
            signature_length,
            expected_active_pxst_digest,
            intended_client,
        )?;
        let carrier = RestrictedRuntimeApplyCarrierBindingV1::decode(cursor.take(carrier_length)?)
            .map_err(|_| ManagedServingBootstrapError::InvalidAgentControlBinding)?;
        if carrier.binding_digest() != carrier_digest {
            return Err(ManagedServingBootstrapError::InvalidAgentControlBinding);
        }
        let payload = cursor.take(payload_length)?;
        let (managed_fabric_apply_request, managed_agent_stack_apply_request) = match kind {
            RuntimeAgentControlKindV1::ApplyManagedFabric => (
                Some(
                    ManagedFabricApplyRequestV1::decode(payload)
                        .map_err(|_| ManagedServingBootstrapError::InvalidAgentControlPayload)?,
                ),
                None,
            ),
            RuntimeAgentControlKindV1::ApplyManagedAgentStack => (
                None,
                Some(
                    ManagedAgentStackApplyRequestV1::decode(payload)
                        .map_err(|_| ManagedServingBootstrapError::InvalidAgentControlPayload)?,
                ),
            ),
            RuntimeAgentControlKindV1::DescribeConversationPort => (None, None),
        };
        if (payload.is_empty() && !digest_is_zero(payload_wire_digest))
            || (!payload.is_empty()
                && digest(AGENT_CONTROL_REQUEST_PAYLOAD_DIGEST_DOMAIN, payload)?
                    != payload_wire_digest)
        {
            return Err(ManagedServingBootstrapError::InvalidAgentControlPayload);
        }
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let fields = RuntimeAgentControlRequestFieldsV1 {
            request_id,
            carrier,
            target,
            expected_runtime_store_instance_id,
            expected_runtime_host_epoch,
            auth_claim,
        };
        let draft = RuntimeAgentControlRequestDraftV1::try_new(
            fields,
            kind,
            expected_active_pxst_digest,
            intended_client,
            managed_fabric_apply_request,
            managed_agent_stack_apply_request,
        )?;
        if draft.payload_wire_digest != payload_wire_digest {
            return Err(ManagedServingBootstrapError::InvalidAgentControlPayload);
        }
        let decoded = draft.finalize(signature)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedServingBootstrapError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Verifies the outer Controller signature against the exact PXCB pins.
    pub fn verify_controller_request<Verify>(
        &self,
        expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        verify: Verify,
    ) -> Result<ControllerAuthenticatedRuntimeAgentControlRequestV1<'_>, ManagedServingBootstrapError>
    where
        Verify: FnOnce(PrincipalRef, ApplyAuthKeyRef, Digest32, &[u8], &[u8]) -> bool,
    {
        if &self.carrier != expected_carrier {
            return Err(ManagedServingBootstrapError::InvalidAgentControlBinding);
        }
        let transcript = self.signing_transcript()?;
        if !verify(
            self.carrier.controller_principal(),
            self.carrier.controller_request_key(),
            self.carrier.controller_request_key_fingerprint(),
            transcript.as_bytes(),
            self.authentication.signature(),
        ) {
            return Err(ManagedServingBootstrapError::InvalidAgentControlAuthentication);
        }
        Ok(ControllerAuthenticatedRuntimeAgentControlRequestV1 { request: self })
    }

    #[must_use]
    pub const fn request_id(&self) -> RuntimeAgentControlRequestIdV1 {
        self.request_id
    }

    #[must_use]
    pub const fn kind(&self) -> RuntimeAgentControlKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn carrier(&self) -> &RestrictedRuntimeApplyCarrierBindingV1 {
        &self.carrier
    }

    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub const fn expected_runtime_store_instance_id(&self) -> [u8; 32] {
        self.expected_runtime_store_instance_id
    }

    #[must_use]
    pub const fn expected_runtime_host_epoch(&self) -> u64 {
        self.expected_runtime_host_epoch
    }

    #[must_use]
    pub const fn expected_active_pxst_digest(&self) -> Digest32 {
        self.expected_active_pxst_digest
    }

    #[must_use]
    pub const fn intended_client(&self) -> PrincipalRef {
        self.intended_client
    }

    #[must_use]
    pub const fn managed_fabric_apply_request(&self) -> Option<&ManagedFabricApplyRequestV1> {
        self.managed_fabric_apply_request.as_ref()
    }

    #[must_use]
    pub const fn managed_agent_stack_apply_request(
        &self,
    ) -> Option<&ManagedAgentStackApplyRequestV1> {
        self.managed_agent_stack_apply_request.as_ref()
    }

    #[must_use]
    pub const fn payload_wire_digest(&self) -> Digest32 {
        self.payload_wire_digest
    }

    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        &self.authentication
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<RuntimeAgentControlSigningTranscriptV1, ManagedServingBootstrapError> {
        RuntimeAgentControlRequestDraftV1 {
            request_id: self.request_id,
            kind: self.kind,
            carrier: self.carrier.clone(),
            target: self.target,
            expected_runtime_store_instance_id: self.expected_runtime_store_instance_id,
            expected_runtime_host_epoch: self.expected_runtime_host_epoch,
            expected_active_pxst_digest: self.expected_active_pxst_digest,
            intended_client: self.intended_client,
            managed_fabric_apply_request: self.managed_fabric_apply_request.clone(),
            managed_agent_stack_apply_request: self.managed_agent_stack_apply_request.clone(),
            payload_wire_digest: self.payload_wire_digest,
            auth_claim: self.authentication.claim().clone(),
        }
        .signing_transcript()
    }
}

/// Marker issued only after caller-owned verification accepts PXAG and PXCB.
#[derive(Clone, Copy, Debug)]
pub struct ControllerAuthenticatedRuntimeAgentControlRequestV1<'a> {
    request: &'a RuntimeAgentControlRequestV1,
}

impl<'a> ControllerAuthenticatedRuntimeAgentControlRequestV1<'a> {
    #[must_use]
    pub const fn request(self) -> &'a RuntimeAgentControlRequestV1 {
        self.request
    }

    #[must_use]
    pub const fn kind(self) -> RuntimeAgentControlKindV1 {
        self.request.kind()
    }
}

/// Runtime response signer bound to the exact public PXCB, not to the inner
/// Runtime-local UDS channel carried by PXFT/PXST.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeAgentControlResponseAuthClaimV1 {
    runtime_principal: PrincipalRef,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
    carrier_binding_digest: Digest32,
}

impl RuntimeAgentControlResponseAuthClaimV1 {
    pub fn try_new(
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, ManagedServingBootstrapError> {
        let claim = Self {
            runtime_principal: carrier.runtime_principal(),
            key,
            algorithm,
            algorithm_version,
            carrier_binding_digest: carrier.binding_digest(),
        };
        validate_runtime_agent_control_response_auth(claim, carrier)?;
        Ok(claim)
    }

    #[must_use]
    pub const fn runtime_principal(self) -> PrincipalRef {
        self.runtime_principal
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

    #[must_use]
    pub const fn carrier_binding_digest(self) -> Digest32 {
        self.carrier_binding_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RuntimeAgentControlReceiptPayloadV1 {
    ManagedFabric(Box<ManagedFabricApplyTerminalReceiptV1>),
    ManagedAgentStack(Box<ManagedAgentStackTerminalReceiptV1>),
    ConversationPortDescriptor(Box<[u8]>),
}

impl RuntimeAgentControlReceiptPayloadV1 {
    fn canonical_wire(&self) -> &[u8] {
        match self {
            Self::ManagedFabric(receipt) => receipt.canonical_wire(),
            Self::ManagedAgentStack(receipt) => receipt.canonical_wire(),
            Self::ConversationPortDescriptor(descriptor) => descriptor,
        }
    }
}

/// Signature-independent Runtime producer for one PXAH receipt.
///
/// Every public producer constructor requires a marker issued by
/// [`RuntimeAgentControlRequestV1::verify_controller_request`], so Runtime
/// code cannot mint a PXAH from a merely decoded, unauthenticated PXAG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAgentControlReceiptDraftV1 {
    request_id: RuntimeAgentControlRequestIdV1,
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    kind: RuntimeAgentControlKindV1,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    target: RuntimeHostId,
    runtime_store_instance_id: [u8; 32],
    runtime_host_epoch: u64,
    expected_active_pxst_digest: Digest32,
    intended_client: PrincipalRef,
    payload: RuntimeAgentControlReceiptPayloadV1,
    payload_wire_digest: Digest32,
    fabric_generation: Option<ManagedServiceGeneration>,
    agent_generation: Option<ManagedServiceGeneration>,
    auth_claim: RuntimeAgentControlResponseAuthClaimV1,
}

impl RuntimeAgentControlReceiptDraftV1 {
    /// Wraps one byte-identical PXFT after validating it against the exact
    /// inner PXAR v6 and its current Runtime-local channel.
    ///
    /// `current_channel` is used only by PXFT correlation. It is not encoded
    /// into PXAH and is never interpreted as the PXCB/TLS binding.
    pub fn try_managed_fabric_apply(
        authenticated_request: ControllerAuthenticatedRuntimeAgentControlRequestV1<'_>,
        receipt: ManagedFabricApplyTerminalReceiptV1,
        current_channel: ReferenceChannelBindingV1,
        auth_claim: RuntimeAgentControlResponseAuthClaimV1,
    ) -> Result<Self, ManagedServingBootstrapError> {
        let request = authenticated_request.request();
        let inner = request
            .managed_fabric_apply_request()
            .ok_or(ManagedServingBootstrapError::InvalidAgentControlReceipt)?;
        receipt
            .validate_against_request(inner, current_channel)
            .map_err(|_| ManagedServingBootstrapError::InvalidAgentControlReceipt)?;
        Self::try_new(
            request,
            RuntimeAgentControlReceiptPayloadV1::ManagedFabric(Box::new(receipt)),
            None,
            None,
            auth_claim,
        )
    }

    /// Wraps one byte-identical PXST after validating it against the exact
    /// inner PXAR v7 and its current Runtime-local channel.
    ///
    /// `current_channel` is correlation input only and never becomes a public
    /// transport or access claim.
    pub fn try_managed_agent_stack_apply(
        authenticated_request: ControllerAuthenticatedRuntimeAgentControlRequestV1<'_>,
        receipt: ManagedAgentStackTerminalReceiptV1,
        current_channel: ReferenceChannelBindingV1,
        auth_claim: RuntimeAgentControlResponseAuthClaimV1,
    ) -> Result<Self, ManagedServingBootstrapError> {
        let request = authenticated_request.request();
        let inner = request
            .managed_agent_stack_apply_request()
            .ok_or(ManagedServingBootstrapError::InvalidAgentControlReceipt)?;
        receipt
            .validate_against_request(inner, current_channel)
            .map_err(|_| ManagedServingBootstrapError::InvalidAgentControlReceipt)?;
        Self::try_new(
            request,
            RuntimeAgentControlReceiptPayloadV1::ManagedAgentStack(Box::new(receipt)),
            None,
            None,
            auth_claim,
        )
    }

    /// Binds one opaque PXAP bootstrap descriptor to the current live owner.
    ///
    /// The expected PXST digest is the broker's current byte-exact capability
    /// root. Fabric/Agent generations are separate current live facts, so a
    /// normal Runtime recovery may retain PXST bytes while advancing either
    /// physical generation. This receipt is not a TLS authorization, access
    /// grant, session, capability, discovery result, or retry authority.
    pub fn try_conversation_port_descriptor(
        authenticated_request: ControllerAuthenticatedRuntimeAgentControlRequestV1<'_>,
        descriptor: &[u8],
        fabric_generation: ManagedServiceGeneration,
        agent_generation: ManagedServiceGeneration,
        auth_claim: RuntimeAgentControlResponseAuthClaimV1,
    ) -> Result<Self, ManagedServingBootstrapError> {
        let request = authenticated_request.request();
        Self::try_new(
            request,
            RuntimeAgentControlReceiptPayloadV1::ConversationPortDescriptor(descriptor.into()),
            Some(fabric_generation),
            Some(agent_generation),
            auth_claim,
        )
    }

    fn try_new(
        request: &RuntimeAgentControlRequestV1,
        payload: RuntimeAgentControlReceiptPayloadV1,
        fabric_generation: Option<ManagedServiceGeneration>,
        agent_generation: Option<ManagedServiceGeneration>,
        auth_claim: RuntimeAgentControlResponseAuthClaimV1,
    ) -> Result<Self, ManagedServingBootstrapError> {
        let payload_wire_digest = digest(
            AGENT_CONTROL_RECEIPT_PAYLOAD_DIGEST_DOMAIN,
            payload.canonical_wire(),
        )?;
        let draft = Self {
            request_id: request.request_id,
            request_digest: request.request_digest,
            request_nonce: request.authentication.claim().nonce().into(),
            kind: request.kind,
            carrier: request.carrier.clone(),
            target: request.target,
            runtime_store_instance_id: request.expected_runtime_store_instance_id,
            runtime_host_epoch: request.expected_runtime_host_epoch,
            expected_active_pxst_digest: request.expected_active_pxst_digest,
            intended_client: request.intended_client,
            payload,
            payload_wire_digest,
            fabric_generation,
            agent_generation,
            auth_claim,
        };
        validate_runtime_agent_control_receipt_draft(&draft)?;
        validate_runtime_agent_control_receipt_against_request(&draft, request)?;
        Ok(draft)
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<RuntimeAgentControlSigningTranscriptV1, ManagedServingBootstrapError> {
        let mut transcript = build_runtime_agent_control_receipt_base(
            self,
            AGENT_CONTROL_RECEIPT_TRANSCRIPT_MAGIC,
            RUNTIME_AGENT_CONTROL_RECEIPT_SIGNING_VERSION,
        )?;
        append_runtime_agent_control_receipt_values(&mut transcript, self);
        Ok(RuntimeAgentControlSigningTranscriptV1(
            transcript.into_boxed_slice(),
        ))
    }

    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<RuntimeAgentControlReceiptV1, ManagedServingBootstrapError> {
        if signature.is_empty() || signature.len() > MAX_APPLY_AUTH_SIGNATURE_BYTES {
            return Err(ManagedServingBootstrapError::InvalidAgentControlAuthentication);
        }
        RuntimeAgentControlReceiptV1::try_new(self, signature)
    }
}

/// Strict Runtime-signed PXAH response to one exact PXAG request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAgentControlReceiptV1 {
    request_id: RuntimeAgentControlRequestIdV1,
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    kind: RuntimeAgentControlKindV1,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    target: RuntimeHostId,
    runtime_store_instance_id: [u8; 32],
    runtime_host_epoch: u64,
    expected_active_pxst_digest: Digest32,
    intended_client: PrincipalRef,
    payload: RuntimeAgentControlReceiptPayloadV1,
    payload_wire_digest: Digest32,
    fabric_generation: Option<ManagedServiceGeneration>,
    agent_generation: Option<ManagedServiceGeneration>,
    auth_claim: RuntimeAgentControlResponseAuthClaimV1,
    signature: Box<[u8]>,
    canonical_wire: Box<[u8]>,
    receipt_digest: Digest32,
}

impl RuntimeAgentControlReceiptV1 {
    fn try_new(
        draft: RuntimeAgentControlReceiptDraftV1,
        signature: &[u8],
    ) -> Result<Self, ManagedServingBootstrapError> {
        let canonical_wire = build_runtime_agent_control_receipt_wire(&draft, signature)?;
        if canonical_wire.len() > MAX_RUNTIME_AGENT_CONTROL_RECEIPT_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        let receipt_digest = digest(AGENT_CONTROL_RECEIPT_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            request_id: draft.request_id,
            request_digest: draft.request_digest,
            request_nonce: draft.request_nonce,
            kind: draft.kind,
            carrier: draft.carrier,
            target: draft.target,
            runtime_store_instance_id: draft.runtime_store_instance_id,
            runtime_host_epoch: draft.runtime_host_epoch,
            expected_active_pxst_digest: draft.expected_active_pxst_digest,
            intended_client: draft.intended_client,
            payload: draft.payload,
            payload_wire_digest: draft.payload_wire_digest,
            fabric_generation: draft.fabric_generation,
            agent_generation: draft.agent_generation,
            auth_claim: draft.auth_claim,
            signature: signature.into(),
            canonical_wire: canonical_wire.into_boxed_slice(),
            receipt_digest,
        })
    }

    /// Strictly decodes one bounded canonical PXAH v1 frame.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedServingBootstrapError> {
        if frame.len() > MAX_RUNTIME_AGENT_CONTROL_RECEIPT_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        if frame.len() < AGENT_CONTROL_RECEIPT_FIXED_BYTES {
            return Err(ManagedServingBootstrapError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.array::<4>()? != *RUNTIME_AGENT_CONTROL_RECEIPT_MAGIC
            || cursor.u16()? != RUNTIME_AGENT_CONTROL_VERSION
        {
            return Err(ManagedServingBootstrapError::UnsupportedWire);
        }
        let kind = RuntimeAgentControlKindV1::decode(cursor.u16()?)?;
        if cursor.u16()? != 0 {
            return Err(ManagedServingBootstrapError::NonCanonicalFrame);
        }
        let carrier_length = cursor.usize_u16()?;
        let payload_length = cursor.usize_u32()?;
        let nonce_length = cursor.usize_u16()?;
        let request_id = RuntimeAgentControlRequestIdV1::try_from_bytes(cursor.array()?)?;
        let request_digest = Digest32::from_bytes(cursor.array()?);
        let carrier_digest = Digest32::from_bytes(cursor.array()?);
        let target = RuntimeHostId::from_bytes(cursor.array()?);
        let runtime_store_instance_id = cursor.array()?;
        let runtime_host_epoch = cursor.u64()?;
        let expected_active_pxst_digest = Digest32::from_bytes(cursor.array()?);
        let intended_client = PrincipalRef::from_bytes(cursor.array()?);
        let payload_wire_digest = Digest32::from_bytes(cursor.array()?);
        let fabric_generation = decode_optional_managed_generation(cursor.u64()?)?;
        let agent_generation = decode_optional_managed_generation(cursor.u64()?)?;
        let auth_claim = decode_runtime_agent_control_response_auth(&mut cursor)?;
        let signature_length = cursor.usize_u16()?;
        validate_runtime_agent_control_receipt_lengths(
            kind,
            carrier_length,
            payload_length,
            nonce_length,
            signature_length,
        )?;
        let request_nonce: Box<[u8]> = cursor.take(nonce_length)?.into();
        let carrier = RestrictedRuntimeApplyCarrierBindingV1::decode(cursor.take(carrier_length)?)
            .map_err(|_| ManagedServingBootstrapError::InvalidAgentControlBinding)?;
        if carrier.binding_digest() != carrier_digest {
            return Err(ManagedServingBootstrapError::InvalidAgentControlBinding);
        }
        let payload_wire = cursor.take(payload_length)?;
        if digest(AGENT_CONTROL_RECEIPT_PAYLOAD_DIGEST_DOMAIN, payload_wire)? != payload_wire_digest
        {
            return Err(ManagedServingBootstrapError::InvalidAgentControlPayload);
        }
        let payload = match kind {
            RuntimeAgentControlKindV1::ApplyManagedFabric => {
                RuntimeAgentControlReceiptPayloadV1::ManagedFabric(Box::new(
                    ManagedFabricApplyTerminalReceiptV1::decode(payload_wire)
                        .map_err(|_| ManagedServingBootstrapError::InvalidAgentControlPayload)?,
                ))
            }
            RuntimeAgentControlKindV1::ApplyManagedAgentStack => {
                RuntimeAgentControlReceiptPayloadV1::ManagedAgentStack(Box::new(
                    ManagedAgentStackTerminalReceiptV1::decode(payload_wire)
                        .map_err(|_| ManagedServingBootstrapError::InvalidAgentControlPayload)?,
                ))
            }
            RuntimeAgentControlKindV1::DescribeConversationPort => {
                validate_runtime_agent_port_descriptor(payload_wire)?;
                RuntimeAgentControlReceiptPayloadV1::ConversationPortDescriptor(payload_wire.into())
            }
        };
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let draft = RuntimeAgentControlReceiptDraftV1 {
            request_id,
            request_digest,
            request_nonce,
            kind,
            carrier,
            target,
            runtime_store_instance_id,
            runtime_host_epoch,
            expected_active_pxst_digest,
            intended_client,
            payload,
            payload_wire_digest,
            fabric_generation,
            agent_generation,
            auth_claim,
        };
        validate_runtime_agent_control_receipt_draft(&draft)?;
        let decoded = draft.finalize(signature)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedServingBootstrapError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    fn validate_common_against_request(
        &self,
        request: &RuntimeAgentControlRequestV1,
    ) -> Result<(), ManagedServingBootstrapError> {
        let draft = RuntimeAgentControlReceiptDraftV1 {
            request_id: self.request_id,
            request_digest: self.request_digest,
            request_nonce: self.request_nonce.clone(),
            kind: self.kind,
            carrier: self.carrier.clone(),
            target: self.target,
            runtime_store_instance_id: self.runtime_store_instance_id,
            runtime_host_epoch: self.runtime_host_epoch,
            expected_active_pxst_digest: self.expected_active_pxst_digest,
            intended_client: self.intended_client,
            payload: self.payload.clone(),
            payload_wire_digest: self.payload_wire_digest,
            fabric_generation: self.fabric_generation,
            agent_generation: self.agent_generation,
            auth_claim: self.auth_claim,
        };
        validate_runtime_agent_control_receipt_against_request(&draft, request)
    }

    /// Revalidates an Apply receipt against the exact inner request and the
    /// supplied current Runtime-local channel. The channel is never compared
    /// with, or reinterpreted as, the public PXCB/TLS binding.
    pub fn validate_apply_against_request(
        &self,
        request: &RuntimeAgentControlRequestV1,
        current_channel: ReferenceChannelBindingV1,
    ) -> Result<(), ManagedServingBootstrapError> {
        self.validate_common_against_request(request)?;
        match (&self.payload, request.kind) {
            (
                RuntimeAgentControlReceiptPayloadV1::ManagedFabric(receipt),
                RuntimeAgentControlKindV1::ApplyManagedFabric,
            ) => {
                let inner = request
                    .managed_fabric_apply_request()
                    .ok_or(ManagedServingBootstrapError::AgentControlCorrelationMismatch)?;
                receipt
                    .validate_against_request(inner, current_channel)
                    .map_err(|_| ManagedServingBootstrapError::AgentControlCorrelationMismatch)?;
            }
            (
                RuntimeAgentControlReceiptPayloadV1::ManagedAgentStack(receipt),
                RuntimeAgentControlKindV1::ApplyManagedAgentStack,
            ) => {
                let inner = request
                    .managed_agent_stack_apply_request()
                    .ok_or(ManagedServingBootstrapError::AgentControlCorrelationMismatch)?;
                receipt
                    .validate_against_request(inner, current_channel)
                    .map_err(|_| ManagedServingBootstrapError::AgentControlCorrelationMismatch)?;
            }
            _ => return Err(ManagedServingBootstrapError::AgentControlCorrelationMismatch),
        }
        Ok(())
    }

    /// Validates one bootstrap-only Describe receipt with no local channel.
    pub fn validate_descriptor_against_request(
        &self,
        request: &RuntimeAgentControlRequestV1,
    ) -> Result<(), ManagedServingBootstrapError> {
        self.validate_common_against_request(request)?;
        if self.kind != RuntimeAgentControlKindV1::DescribeConversationPort
            || self.conversation_port_descriptor().is_none()
        {
            return Err(ManagedServingBootstrapError::AgentControlCorrelationMismatch);
        }
        Ok(())
    }

    /// Verifies an Apply PXAH outer signature after revalidating the inner
    /// receipt's exact request and current-channel correlation.
    ///
    /// This method does not cryptographically verify the independently signed
    /// PXFT/PXST payload. A caller that relies on the inner signature must also
    /// verify its signing transcript and authentication signature against the
    /// applicable inner response-key policy.
    pub fn verify_runtime_apply_receipt<'a, Verify>(
        &'a self,
        request: &RuntimeAgentControlRequestV1,
        current_channel: ReferenceChannelBindingV1,
        expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        verify: Verify,
    ) -> Result<RuntimeAuthenticatedAgentControlReceiptV1<'a>, ManagedServingBootstrapError>
    where
        Verify: FnOnce(PrincipalRef, ApplyAuthKeyRef, Digest32, &[u8], &[u8]) -> bool,
    {
        self.validate_apply_against_request(request, current_channel)?;
        if &self.carrier != expected_carrier {
            return Err(ManagedServingBootstrapError::InvalidAgentControlBinding);
        }
        let transcript = self.signing_transcript()?;
        if !verify(
            self.carrier.runtime_principal(),
            self.carrier.runtime_response_key(),
            self.carrier.runtime_response_key_fingerprint(),
            transcript.as_bytes(),
            &self.signature,
        ) {
            return Err(ManagedServingBootstrapError::InvalidAgentControlAuthentication);
        }
        Ok(RuntimeAuthenticatedAgentControlReceiptV1 { receipt: self })
    }

    /// Verifies a bootstrap-only descriptor PXAH without a local-channel input.
    pub fn verify_runtime_descriptor_receipt<'a, Verify>(
        &'a self,
        request: &RuntimeAgentControlRequestV1,
        expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        verify: Verify,
    ) -> Result<RuntimeAuthenticatedAgentControlReceiptV1<'a>, ManagedServingBootstrapError>
    where
        Verify: FnOnce(PrincipalRef, ApplyAuthKeyRef, Digest32, &[u8], &[u8]) -> bool,
    {
        self.validate_descriptor_against_request(request)?;
        if &self.carrier != expected_carrier {
            return Err(ManagedServingBootstrapError::InvalidAgentControlBinding);
        }
        let transcript = self.signing_transcript()?;
        if !verify(
            self.carrier.runtime_principal(),
            self.carrier.runtime_response_key(),
            self.carrier.runtime_response_key_fingerprint(),
            transcript.as_bytes(),
            &self.signature,
        ) {
            return Err(ManagedServingBootstrapError::InvalidAgentControlAuthentication);
        }
        Ok(RuntimeAuthenticatedAgentControlReceiptV1 { receipt: self })
    }

    #[must_use]
    pub const fn request_id(&self) -> RuntimeAgentControlRequestIdV1 {
        self.request_id
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub fn request_nonce(&self) -> &[u8] {
        &self.request_nonce
    }

    #[must_use]
    pub const fn kind(&self) -> RuntimeAgentControlKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn carrier(&self) -> &RestrictedRuntimeApplyCarrierBindingV1 {
        &self.carrier
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
    pub const fn runtime_host_epoch(&self) -> u64 {
        self.runtime_host_epoch
    }

    #[must_use]
    pub const fn expected_active_pxst_digest(&self) -> Digest32 {
        self.expected_active_pxst_digest
    }

    #[must_use]
    pub const fn intended_client(&self) -> PrincipalRef {
        self.intended_client
    }

    #[must_use]
    pub fn managed_fabric_receipt(&self) -> Option<&ManagedFabricApplyTerminalReceiptV1> {
        match &self.payload {
            RuntimeAgentControlReceiptPayloadV1::ManagedFabric(receipt) => Some(receipt.as_ref()),
            _ => None,
        }
    }

    #[must_use]
    pub fn managed_agent_stack_receipt(&self) -> Option<&ManagedAgentStackTerminalReceiptV1> {
        match &self.payload {
            RuntimeAgentControlReceiptPayloadV1::ManagedAgentStack(receipt) => {
                Some(receipt.as_ref())
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn conversation_port_descriptor(&self) -> Option<&[u8]> {
        match &self.payload {
            RuntimeAgentControlReceiptPayloadV1::ConversationPortDescriptor(descriptor) => {
                Some(descriptor)
            }
            _ => None,
        }
    }

    #[must_use]
    pub const fn payload_wire_digest(&self) -> Digest32 {
        self.payload_wire_digest
    }

    #[must_use]
    pub const fn fabric_generation(&self) -> Option<ManagedServiceGeneration> {
        self.fabric_generation
    }

    #[must_use]
    pub const fn agent_generation(&self) -> Option<ManagedServiceGeneration> {
        self.agent_generation
    }

    #[must_use]
    pub const fn authentication(&self) -> RuntimeAgentControlResponseAuthClaimV1 {
        self.auth_claim
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
    ) -> Result<RuntimeAgentControlSigningTranscriptV1, ManagedServingBootstrapError> {
        RuntimeAgentControlReceiptDraftV1 {
            request_id: self.request_id,
            request_digest: self.request_digest,
            request_nonce: self.request_nonce.clone(),
            kind: self.kind,
            carrier: self.carrier.clone(),
            target: self.target,
            runtime_store_instance_id: self.runtime_store_instance_id,
            runtime_host_epoch: self.runtime_host_epoch,
            expected_active_pxst_digest: self.expected_active_pxst_digest,
            intended_client: self.intended_client,
            payload: self.payload.clone(),
            payload_wire_digest: self.payload_wire_digest,
            fabric_generation: self.fabric_generation,
            agent_generation: self.agent_generation,
            auth_claim: self.auth_claim,
        }
        .signing_transcript()
    }
}

/// Marker issued after exact PXAH correlation and Runtime signature checks.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeAuthenticatedAgentControlReceiptV1<'a> {
    receipt: &'a RuntimeAgentControlReceiptV1,
}

impl<'a> RuntimeAuthenticatedAgentControlReceiptV1<'a> {
    #[must_use]
    pub const fn receipt(self) -> &'a RuntimeAgentControlReceiptV1 {
        self.receipt
    }
}

/// Operation admitted by the additive Controller-signed PXCC carrier.
///
/// `Describe` has no inner payload. `ManagedServingBootstrap` and
/// `ReferenceQuery` carry one byte-identical, independently authenticated
/// PXFB v1 or PXQR v1 request. No apply or Agent payload kind is admitted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum RuntimeControlCarrierKindV1 {
    /// Read the Runtime-owned channel and current recovered serving facts.
    Describe = 1,
    /// Deliver one strict frozen PXFB v1 request after Describe correlation.
    ManagedServingBootstrap = 2,
    /// Deliver one strict frozen PXQR v1 request; the response remains PXQS.
    ReferenceQuery = 3,
}

impl RuntimeControlCarrierKindV1 {
    fn decode(value: u16) -> Result<Self, ManagedServingBootstrapError> {
        match value {
            1 => Ok(Self::Describe),
            2 => Ok(Self::ManagedServingBootstrap),
            3 => Ok(Self::ReferenceQuery),
            _ => Err(ManagedServingBootstrapError::UnsupportedControlCarrierKind),
        }
    }
}

/// Exact bytes supplied to the Controller or Runtime carrier signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeControlCarrierSigningTranscriptV1(Box<[u8]>);

impl RuntimeControlCarrierSigningTranscriptV1 {
    /// Returns the exact domain-separated signing bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent producer for one Controller PXCC request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeControlCarrierRequestDraftV1 {
    request_id: ManagedServingBootstrapRequestIdV1,
    kind: RuntimeControlCarrierKindV1,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    managed_serving_bootstrap_request: Option<ManagedServingBootstrapRequestV1>,
    reference_query_request: Option<ReferenceQueryRequestV1>,
    payload_wire_digest: Digest32,
    auth_claim: ApplyRequestAuthClaim,
}

impl RuntimeControlCarrierRequestDraftV1 {
    /// Builds an empty-payload Describe request for one exact PXCB binding.
    pub fn try_describe(
        request_id: ManagedServingBootstrapRequestIdV1,
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, ManagedServingBootstrapError> {
        Self::try_new(
            request_id,
            RuntimeControlCarrierKindV1::Describe,
            carrier,
            None,
            None,
            auth_claim,
        )
    }

    /// Wraps one byte-identical frozen PXFB v1 request for the same PXCB.
    pub fn try_managed_serving_bootstrap(
        request_id: ManagedServingBootstrapRequestIdV1,
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        request: ManagedServingBootstrapRequestV1,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, ManagedServingBootstrapError> {
        Self::try_new(
            request_id,
            RuntimeControlCarrierKindV1::ManagedServingBootstrap,
            carrier,
            Some(request),
            None,
            auth_claim,
        )
    }

    /// Wraps one byte-identical frozen PXQR v1 request for the same PXCB.
    pub fn try_reference_query(
        request_id: ManagedServingBootstrapRequestIdV1,
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        request: ReferenceQueryRequestV1,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, ManagedServingBootstrapError> {
        Self::try_new(
            request_id,
            RuntimeControlCarrierKindV1::ReferenceQuery,
            carrier,
            None,
            Some(request),
            auth_claim,
        )
    }

    fn try_new(
        request_id: ManagedServingBootstrapRequestIdV1,
        kind: RuntimeControlCarrierKindV1,
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        managed_serving_bootstrap_request: Option<ManagedServingBootstrapRequestV1>,
        reference_query_request: Option<ReferenceQueryRequestV1>,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, ManagedServingBootstrapError> {
        validate_runtime_control_carrier_fields(
            request_id,
            kind,
            &carrier,
            managed_serving_bootstrap_request.as_ref(),
            reference_query_request.as_ref(),
            &auth_claim,
        )?;
        let payload_wire_digest = match (
            managed_serving_bootstrap_request.as_ref(),
            reference_query_request.as_ref(),
        ) {
            (Some(request), None) => digest(
                CONTROL_CARRIER_PAYLOAD_DIGEST_DOMAIN,
                request.canonical_wire(),
            )?,
            (None, Some(request)) => digest(
                CONTROL_CARRIER_PAYLOAD_DIGEST_DOMAIN,
                request.canonical_wire(),
            )?,
            (None, None) => Digest32::from_bytes([0; 32]),
            (Some(_), Some(_)) => {
                return Err(ManagedServingBootstrapError::InvalidControlCarrierPayload);
            }
        };
        Ok(Self {
            request_id,
            kind,
            carrier,
            managed_serving_bootstrap_request,
            reference_query_request,
            payload_wire_digest,
            auth_claim,
        })
    }

    /// Builds exact Controller signing bytes, including the complete PXCB and
    /// optional complete PXFB or PXQR bytes.
    pub fn signing_transcript(
        &self,
    ) -> Result<RuntimeControlCarrierSigningTranscriptV1, ManagedServingBootstrapError> {
        let mut transcript = build_runtime_control_carrier_request_base(
            self,
            CONTROL_CARRIER_REQUEST_TRANSCRIPT_MAGIC,
            RUNTIME_CONTROL_CARRIER_REQUEST_SIGNING_VERSION,
        )?;
        transcript.extend_from_slice(self.carrier.canonical_wire());
        if let Some(request) = self.managed_serving_bootstrap_request.as_ref() {
            transcript.extend_from_slice(request.canonical_wire());
        }
        if let Some(request) = self.reference_query_request.as_ref() {
            transcript.extend_from_slice(request.canonical_wire());
        }
        Ok(RuntimeControlCarrierSigningTranscriptV1(
            transcript.into_boxed_slice(),
        ))
    }

    /// Attaches one bounded opaque Controller signature.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<RuntimeControlCarrierRequestV1, ManagedServingBootstrapError> {
        let authentication =
            ApplyRequestAuthentication::try_new(self.auth_claim.clone(), signature)?;
        RuntimeControlCarrierRequestV1::try_new(self, authentication)
    }
}

/// Strict Controller-signed PXCC request containing one exact PXCB and an
/// allowlisted empty or frozen-PXFB payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeControlCarrierRequestV1 {
    request_id: ManagedServingBootstrapRequestIdV1,
    kind: RuntimeControlCarrierKindV1,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    managed_serving_bootstrap_request: Option<ManagedServingBootstrapRequestV1>,
    reference_query_request: Option<ReferenceQueryRequestV1>,
    payload_wire_digest: Digest32,
    authentication: ApplyRequestAuthentication,
    canonical_wire: Box<[u8]>,
    request_digest: Digest32,
}

impl RuntimeControlCarrierRequestV1 {
    fn try_new(
        draft: RuntimeControlCarrierRequestDraftV1,
        authentication: ApplyRequestAuthentication,
    ) -> Result<Self, ManagedServingBootstrapError> {
        if authentication.claim() != &draft.auth_claim {
            return Err(ManagedServingBootstrapError::AuthenticationMismatch);
        }
        let canonical_wire = build_runtime_control_carrier_request_wire(&draft, &authentication)?;
        if canonical_wire.len() > MAX_RUNTIME_CONTROL_CARRIER_REQUEST_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        let request_digest = digest(CONTROL_CARRIER_REQUEST_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            request_id: draft.request_id,
            kind: draft.kind,
            carrier: draft.carrier,
            managed_serving_bootstrap_request: draft.managed_serving_bootstrap_request,
            reference_query_request: draft.reference_query_request,
            payload_wire_digest: draft.payload_wire_digest,
            authentication,
            canonical_wire: canonical_wire.into_boxed_slice(),
            request_digest,
        })
    }

    /// Strictly decodes exactly one bounded canonical PXCC v1 frame.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedServingBootstrapError> {
        if frame.len() > MAX_RUNTIME_CONTROL_CARRIER_REQUEST_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        if frame.len() < CONTROL_CARRIER_REQUEST_FIXED_BYTES {
            return Err(ManagedServingBootstrapError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.array::<4>()? != *CONTROL_CARRIER_REQUEST_MAGIC
            || cursor.u16()? != RUNTIME_CONTROL_CARRIER_VERSION
        {
            return Err(ManagedServingBootstrapError::UnsupportedWire);
        }
        let kind = RuntimeControlCarrierKindV1::decode(cursor.u16()?)?;
        if cursor.u16()? != 0 {
            return Err(ManagedServingBootstrapError::NonCanonicalFrame);
        }
        let carrier_length = cursor.usize_u16()?;
        let payload_length = cursor.usize_u32()?;
        let request_id = ManagedServingBootstrapRequestIdV1::try_from_bytes(cursor.array()?)?;
        let carrier_digest = Digest32::from_bytes(cursor.array()?);
        let payload_wire_digest = Digest32::from_bytes(cursor.array()?);
        let auth_claim = decode_request_claim(&mut cursor)?;
        let signature_length = cursor.usize_u16()?;
        if carrier_length == 0
            || carrier_length > MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
            || signature_length == 0
            || signature_length > MAX_APPLY_AUTH_SIGNATURE_BYTES
        {
            return Err(ManagedServingBootstrapError::InvalidLength);
        }
        match kind {
            RuntimeControlCarrierKindV1::Describe
                if payload_length != 0 || !digest_is_zero(payload_wire_digest) =>
            {
                return Err(ManagedServingBootstrapError::InvalidControlCarrierPayload);
            }
            RuntimeControlCarrierKindV1::ManagedServingBootstrap
                if payload_length == 0
                    || payload_length > MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES
                    || digest_is_zero(payload_wire_digest) =>
            {
                return Err(ManagedServingBootstrapError::InvalidControlCarrierPayload);
            }
            RuntimeControlCarrierKindV1::ReferenceQuery
                if payload_length == 0
                    || payload_length > MAX_REFERENCE_QUERY_REQUEST_BYTES
                    || digest_is_zero(payload_wire_digest) =>
            {
                return Err(ManagedServingBootstrapError::InvalidControlCarrierPayload);
            }
            _ => {}
        }
        let carrier = RestrictedRuntimeApplyCarrierBindingV1::decode(cursor.take(carrier_length)?)
            .map_err(|_| ManagedServingBootstrapError::InvalidControlCarrierBinding)?;
        if carrier.binding_digest() != carrier_digest {
            return Err(ManagedServingBootstrapError::InvalidControlCarrierBinding);
        }
        let payload = cursor.take(payload_length)?;
        let (managed_serving_bootstrap_request, reference_query_request) = match kind {
            RuntimeControlCarrierKindV1::Describe => (None, None),
            RuntimeControlCarrierKindV1::ManagedServingBootstrap => {
                if digest(CONTROL_CARRIER_PAYLOAD_DIGEST_DOMAIN, payload)? != payload_wire_digest {
                    return Err(ManagedServingBootstrapError::InvalidControlCarrierPayload);
                }
                (
                    Some(ManagedServingBootstrapRequestV1::decode(payload)?),
                    None,
                )
            }
            RuntimeControlCarrierKindV1::ReferenceQuery => {
                if digest(CONTROL_CARRIER_PAYLOAD_DIGEST_DOMAIN, payload)? != payload_wire_digest {
                    return Err(ManagedServingBootstrapError::InvalidControlCarrierPayload);
                }
                (None, Some(ReferenceQueryRequestV1::decode(payload)?))
            }
        };
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let draft = RuntimeControlCarrierRequestDraftV1::try_new(
            request_id,
            kind,
            carrier,
            managed_serving_bootstrap_request,
            reference_query_request,
            auth_claim,
        )?;
        if draft.payload_wire_digest != payload_wire_digest {
            return Err(ManagedServingBootstrapError::InvalidControlCarrierPayload);
        }
        let decoded = draft.finalize(signature)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedServingBootstrapError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Authenticates the exact selected PXCB before dispatching either kind.
    ///
    /// The callback must resolve the key reference, enforce the configured
    /// algorithm policy and fingerprint, and verify the signature. This pure
    /// contract performs no cryptography itself.
    pub fn verify_controller_carrier<Verify>(
        &self,
        expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        verify: Verify,
    ) -> Result<ControllerAuthenticatedRuntimeControlCarrierV1<'_>, ManagedServingBootstrapError>
    where
        Verify: FnOnce(PrincipalRef, ApplyAuthKeyRef, Digest32, &[u8], &[u8]) -> bool,
    {
        if &self.carrier != expected_carrier {
            return Err(ManagedServingBootstrapError::InvalidControlCarrierBinding);
        }
        let transcript = self.signing_transcript()?;
        if !verify(
            self.carrier.controller_principal(),
            self.carrier.controller_request_key(),
            self.carrier.controller_request_key_fingerprint(),
            transcript.as_bytes(),
            self.authentication.signature(),
        ) {
            return Err(ManagedServingBootstrapError::InvalidControlCarrierAuthentication);
        }
        Ok(ControllerAuthenticatedRuntimeControlCarrierV1 { request: self })
    }

    #[must_use]
    pub const fn request_id(&self) -> ManagedServingBootstrapRequestIdV1 {
        self.request_id
    }

    #[must_use]
    pub const fn kind(&self) -> RuntimeControlCarrierKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn carrier(&self) -> &RestrictedRuntimeApplyCarrierBindingV1 {
        &self.carrier
    }

    #[must_use]
    pub const fn managed_serving_bootstrap_request(
        &self,
    ) -> Option<&ManagedServingBootstrapRequestV1> {
        self.managed_serving_bootstrap_request.as_ref()
    }

    #[must_use]
    pub const fn reference_query_request(&self) -> Option<&ReferenceQueryRequestV1> {
        self.reference_query_request.as_ref()
    }

    #[must_use]
    pub const fn payload_wire_digest(&self) -> Digest32 {
        self.payload_wire_digest
    }

    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        &self.authentication
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<RuntimeControlCarrierSigningTranscriptV1, ManagedServingBootstrapError> {
        RuntimeControlCarrierRequestDraftV1 {
            request_id: self.request_id,
            kind: self.kind,
            carrier: self.carrier.clone(),
            managed_serving_bootstrap_request: self.managed_serving_bootstrap_request.clone(),
            reference_query_request: self.reference_query_request.clone(),
            payload_wire_digest: self.payload_wire_digest,
            auth_claim: self.authentication.claim().clone(),
        }
        .signing_transcript()
    }
}

/// Marker issued only after caller-supplied verification accepted the exact
/// Controller signature and expected PXCB binding.
#[derive(Clone, Copy, Debug)]
pub struct ControllerAuthenticatedRuntimeControlCarrierV1<'a> {
    request: &'a RuntimeControlCarrierRequestV1,
}

impl<'a> ControllerAuthenticatedRuntimeControlCarrierV1<'a> {
    #[must_use]
    pub const fn request(self) -> &'a RuntimeControlCarrierRequestV1 {
        self.request
    }

    #[must_use]
    pub const fn kind(self) -> RuntimeControlCarrierKindV1 {
        self.request.kind()
    }

    #[must_use]
    pub const fn carrier(self) -> &'a RestrictedRuntimeApplyCarrierBindingV1 {
        self.request.carrier()
    }

    #[must_use]
    pub const fn managed_serving_bootstrap_request(
        self,
    ) -> Option<&'a ManagedServingBootstrapRequestV1> {
        self.request.managed_serving_bootstrap_request()
    }

    #[must_use]
    pub const fn reference_query_request(self) -> Option<&'a ReferenceQueryRequestV1> {
        self.request.reference_query_request()
    }
}

/// Runtime control-listener phase observed by PXDR.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum RuntimeControlDescribeReadyPhaseV1 {
    /// The owner still admits only the legacy bootstrap transition.
    LegacyReady = 1,
    /// The owner has durably cut over to managed serving.
    ManagedReady = 2,
}

impl RuntimeControlDescribeReadyPhaseV1 {
    fn decode(value: u16) -> Result<Self, ManagedServingBootstrapError> {
        match value {
            1 => Ok(Self::LegacyReady),
            2 => Ok(Self::ManagedReady),
            _ => Err(ManagedServingBootstrapError::UnsupportedControlReadyPhase),
        }
    }
}

/// Current recovered Runtime serving facts returned by Describe.
///
/// `channel` is the complete Runtime-local owner/UDS binding used by the
/// existing PXFB/PXFR contract. It is deliberately not a TLS session binding,
/// mTLS identity, certificate digest, or transport authorization statement.
/// Manifest and build pins are retained by the exact managed projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeControlDescribeReadyFactsV1 {
    phase: RuntimeControlDescribeReadyPhaseV1,
    serving: ManagedServingBootstrapFactsV1,
    channel: ReferenceChannelBindingV1,
}

impl RuntimeControlDescribeReadyFactsV1 {
    pub fn try_new(
        phase: RuntimeControlDescribeReadyPhaseV1,
        serving: ManagedServingBootstrapFactsV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<Self, ManagedServingBootstrapError> {
        if serving.target() != channel.target()
            || serving.readiness() != ManagedServingReadinessV1::RecoveredReady
        {
            return Err(ManagedServingBootstrapError::InvalidControlReadyFacts);
        }
        Ok(Self {
            phase,
            serving,
            channel,
        })
    }

    #[must_use]
    pub const fn phase(&self) -> RuntimeControlDescribeReadyPhaseV1 {
        self.phase
    }

    #[must_use]
    pub const fn serving(&self) -> &ManagedServingBootstrapFactsV1 {
        &self.serving
    }

    /// Returns the Runtime-local owner binding; this is not a TLS binding.
    #[must_use]
    pub const fn channel(&self) -> ReferenceChannelBindingV1 {
        self.channel
    }

    #[must_use]
    pub const fn manifest_digest(&self) -> Digest32 {
        self.serving.projection().fields().manifest_digest
    }

    #[must_use]
    pub const fn build_instance_id(&self) -> [u8; 32] {
        self.serving.projection().fields().build_instance_id
    }

    #[must_use]
    pub const fn build_descriptor_digest(&self) -> Digest32 {
        self.serving.projection().fields().build_descriptor_digest
    }

    #[must_use]
    pub const fn runtime_artifact_sha256(&self) -> Digest32 {
        self.serving.projection().fields().runtime_artifact_sha256
    }

    #[must_use]
    pub const fn compatibility_digest(&self) -> Digest32 {
        self.serving.projection().fields().compatibility_digest
    }
}

/// Signature-independent Runtime producer for one PXDR Describe response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeControlDescribeReadyResponseDraftV1 {
    request_id: ManagedServingBootstrapRequestIdV1,
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    facts: RuntimeControlDescribeReadyFactsV1,
    auth_claim: ManagedServingBootstrapResponseAuthClaimV1,
}

impl RuntimeControlDescribeReadyResponseDraftV1 {
    pub fn try_new(
        request: &RuntimeControlCarrierRequestV1,
        facts: RuntimeControlDescribeReadyFactsV1,
        auth_claim: ManagedServingBootstrapResponseAuthClaimV1,
    ) -> Result<Self, ManagedServingBootstrapError> {
        validate_runtime_control_describe_ready(request, &facts, auth_claim)?;
        Ok(Self {
            request_id: request.request_id,
            request_digest: request.request_digest,
            request_nonce: request.authentication.claim().nonce().into(),
            carrier: request.carrier.clone(),
            facts,
            auth_claim,
        })
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<RuntimeControlCarrierSigningTranscriptV1, ManagedServingBootstrapError> {
        let mut transcript = build_runtime_control_describe_ready_base(
            self,
            CONTROL_DESCRIBE_READY_TRANSCRIPT_MAGIC,
            RUNTIME_CONTROL_DESCRIBE_READY_SIGNING_VERSION,
        )?;
        append_runtime_control_describe_ready_values(&mut transcript, self);
        Ok(RuntimeControlCarrierSigningTranscriptV1(
            transcript.into_boxed_slice(),
        ))
    }

    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<RuntimeControlDescribeReadyResponseV1, ManagedServingBootstrapError> {
        if signature.is_empty() || signature.len() > MAX_APPLY_AUTH_SIGNATURE_BYTES {
            return Err(ManagedServingBootstrapError::InvalidControlCarrierAuthentication);
        }
        RuntimeControlDescribeReadyResponseV1::try_new(self, signature)
    }
}

/// Strict Runtime-signed PXDR response to PXCC Describe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeControlDescribeReadyResponseV1 {
    request_id: ManagedServingBootstrapRequestIdV1,
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    carrier: RestrictedRuntimeApplyCarrierBindingV1,
    facts: RuntimeControlDescribeReadyFactsV1,
    auth_claim: ManagedServingBootstrapResponseAuthClaimV1,
    signature: Box<[u8]>,
    canonical_wire: Box<[u8]>,
    response_digest: Digest32,
}

impl RuntimeControlDescribeReadyResponseV1 {
    fn try_new(
        draft: RuntimeControlDescribeReadyResponseDraftV1,
        signature: &[u8],
    ) -> Result<Self, ManagedServingBootstrapError> {
        let canonical_wire = build_runtime_control_describe_ready_wire(&draft, signature)?;
        if canonical_wire.len() > MAX_RUNTIME_CONTROL_DESCRIBE_READY_RESPONSE_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        let response_digest = digest(CONTROL_DESCRIBE_READY_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            request_id: draft.request_id,
            request_digest: draft.request_digest,
            request_nonce: draft.request_nonce,
            carrier: draft.carrier,
            facts: draft.facts,
            auth_claim: draft.auth_claim,
            signature: signature.into(),
            canonical_wire: canonical_wire.into_boxed_slice(),
            response_digest,
        })
    }

    /// Strictly decodes one bounded canonical PXDR v1 response.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagedServingBootstrapError> {
        if frame.len() > MAX_RUNTIME_CONTROL_DESCRIBE_READY_RESPONSE_BYTES {
            return Err(ManagedServingBootstrapError::FrameTooLarge);
        }
        if frame.len() < CONTROL_DESCRIBE_READY_FIXED_BYTES {
            return Err(ManagedServingBootstrapError::Truncated);
        }
        let mut cursor = Cursor::new(frame);
        if cursor.array::<4>()? != *CONTROL_DESCRIBE_READY_MAGIC
            || cursor.u16()? != RUNTIME_CONTROL_CARRIER_VERSION
        {
            return Err(ManagedServingBootstrapError::UnsupportedWire);
        }
        let phase = RuntimeControlDescribeReadyPhaseV1::decode(cursor.u16()?)?;
        if cursor.u16()? != 0 {
            return Err(ManagedServingBootstrapError::NonCanonicalFrame);
        }
        let carrier_length = cursor.usize_u16()?;
        let projection_length = cursor.usize_u32()?;
        let nonce_length = cursor.usize_u16()?;
        if carrier_length == 0
            || carrier_length > MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
            || projection_length != MANAGED_FABRIC_PROJECTION_BYTES
            || nonce_length == 0
            || nonce_length > MAX_APPLY_AUTH_NONCE_BYTES
        {
            return Err(ManagedServingBootstrapError::InvalidLength);
        }
        let request_id = ManagedServingBootstrapRequestIdV1::try_from_bytes(cursor.array()?)?;
        let request_digest = Digest32::from_bytes(cursor.array()?);
        let carrier_digest = Digest32::from_bytes(cursor.array()?);
        if digest_is_zero(request_digest) || digest_is_zero(carrier_digest) {
            return Err(ManagedServingBootstrapError::InvalidControlReadyFacts);
        }
        let target = RuntimeHostId::from_bytes(cursor.array()?);
        let runtime_store_instance_id = cursor.array()?;
        let runtime_host_epoch = cursor.u64()?;
        let snapshot_sequence = cursor.u64()?;
        let clock_domain = ClockDomainRef::from_bytes(cursor.array()?);
        let clock_generation = ClockGeneration::try_new(cursor.u64()?)
            .map_err(|_| ManagedServingBootstrapError::InvalidControlReadyFacts)?;
        let observed_at_nanos = cursor.u64()?;
        if cursor.u16()? != ManagedServingReadinessV1::RecoveredReady as u16 {
            return Err(ManagedServingBootstrapError::UnsupportedReadiness);
        }
        let channel = decode_channel(&mut cursor)?;
        let auth_claim = decode_response_claim(&mut cursor)?;
        let signature_length = cursor.usize_u16()?;
        if signature_length == 0 || signature_length > MAX_APPLY_AUTH_SIGNATURE_BYTES {
            return Err(ManagedServingBootstrapError::InvalidLength);
        }
        let carrier = RestrictedRuntimeApplyCarrierBindingV1::decode(cursor.take(carrier_length)?)
            .map_err(|_| ManagedServingBootstrapError::InvalidControlCarrierBinding)?;
        if carrier.binding_digest() != carrier_digest {
            return Err(ManagedServingBootstrapError::InvalidControlCarrierBinding);
        }
        let projection =
            ManagedFabricManifestProjectionV1::decode(cursor.take(projection_length)?)?;
        let request_nonce: Box<[u8]> = cursor.take(nonce_length)?.into();
        let signature = cursor.take(signature_length)?;
        cursor.finish()?;
        let serving = ManagedServingBootstrapFactsV1::try_recovered_ready(
            target,
            runtime_store_instance_id,
            projection,
            runtime_host_epoch,
            snapshot_sequence,
            ClockReading::new(
                clock_domain,
                clock_generation,
                MonotonicInstant::from_ticks(observed_at_nanos),
            ),
        )?;
        let facts = RuntimeControlDescribeReadyFactsV1::try_new(phase, serving, channel)?;
        let draft = RuntimeControlDescribeReadyResponseDraftV1 {
            request_id,
            request_digest,
            request_nonce,
            carrier,
            facts,
            auth_claim,
        };
        validate_runtime_control_describe_ready_draft(&draft)?;
        let decoded = draft.finalize(signature)?;
        if decoded.canonical_wire() != frame {
            return Err(ManagedServingBootstrapError::NonCanonicalFrame);
        }
        Ok(decoded)
    }

    /// Checks every request, nonce, exact-PXCB, target and local-channel echo.
    pub fn validate_against_request(
        &self,
        request: &RuntimeControlCarrierRequestV1,
    ) -> Result<&RuntimeControlDescribeReadyFactsV1, ManagedServingBootstrapError> {
        if request.kind != RuntimeControlCarrierKindV1::Describe
            || self.request_id != request.request_id
            || self.request_digest != request.request_digest
            || self.request_nonce.as_ref() != request.authentication.claim().nonce()
            || self.carrier != request.carrier
            || self.facts.serving.target() != self.carrier.target()
            || self.facts.channel.target() != self.carrier.target()
            || self.facts.channel.runtime_peer() != self.carrier.runtime_principal()
            || self.auth_claim.runtime_peer() != self.carrier.runtime_principal()
            || self.auth_claim.channel_binding_digest() != self.facts.channel.binding_digest()
            || self.auth_claim.key() != self.carrier.runtime_response_key()
        {
            return Err(ManagedServingBootstrapError::CorrelationMismatch);
        }
        Ok(&self.facts)
    }

    /// Authenticates PXDR with the exact Runtime response key selected by PXCB.
    pub fn verify_runtime_response<'a, Verify>(
        &'a self,
        request: &RuntimeControlCarrierRequestV1,
        expected_carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        verify: Verify,
    ) -> Result<RuntimeAuthenticatedControlDescribeReadyV1<'a>, ManagedServingBootstrapError>
    where
        Verify: FnOnce(PrincipalRef, ApplyAuthKeyRef, Digest32, &[u8], &[u8]) -> bool,
    {
        self.validate_against_request(request)?;
        if &self.carrier != expected_carrier {
            return Err(ManagedServingBootstrapError::InvalidControlCarrierBinding);
        }
        let transcript = self.signing_transcript()?;
        if !verify(
            self.carrier.runtime_principal(),
            self.carrier.runtime_response_key(),
            self.carrier.runtime_response_key_fingerprint(),
            transcript.as_bytes(),
            &self.signature,
        ) {
            return Err(ManagedServingBootstrapError::InvalidControlCarrierAuthentication);
        }
        Ok(RuntimeAuthenticatedControlDescribeReadyV1 { response: self })
    }

    #[must_use]
    pub const fn request_id(&self) -> ManagedServingBootstrapRequestIdV1 {
        self.request_id
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub fn request_nonce(&self) -> &[u8] {
        &self.request_nonce
    }

    #[must_use]
    pub const fn carrier(&self) -> &RestrictedRuntimeApplyCarrierBindingV1 {
        &self.carrier
    }

    #[must_use]
    pub const fn facts(&self) -> &RuntimeControlDescribeReadyFactsV1 {
        &self.facts
    }

    #[must_use]
    pub const fn authentication(&self) -> ManagedServingBootstrapResponseAuthClaimV1 {
        self.auth_claim
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
    pub const fn response_digest(&self) -> Digest32 {
        self.response_digest
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<RuntimeControlCarrierSigningTranscriptV1, ManagedServingBootstrapError> {
        RuntimeControlDescribeReadyResponseDraftV1 {
            request_id: self.request_id,
            request_digest: self.request_digest,
            request_nonce: self.request_nonce.clone(),
            carrier: self.carrier.clone(),
            facts: self.facts.clone(),
            auth_claim: self.auth_claim,
        }
        .signing_transcript()
    }
}

/// Marker issued after exact PXDR correlation and Runtime signature checks.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeAuthenticatedControlDescribeReadyV1<'a> {
    response: &'a RuntimeControlDescribeReadyResponseV1,
}

impl<'a> RuntimeAuthenticatedControlDescribeReadyV1<'a> {
    #[must_use]
    pub const fn response(self) -> &'a RuntimeControlDescribeReadyResponseV1 {
        self.response
    }

    #[must_use]
    pub const fn facts(self) -> &'a RuntimeControlDescribeReadyFactsV1 {
        self.response.facts()
    }

    #[must_use]
    pub const fn carrier(self) -> &'a RestrictedRuntimeApplyCarrierBindingV1 {
        self.response.carrier()
    }
}

fn validate_runtime_agent_control_request_fields(
    fields: &RuntimeAgentControlRequestFieldsV1,
    kind: RuntimeAgentControlKindV1,
    expected_active_pxst_digest: Digest32,
    intended_client: PrincipalRef,
    managed_fabric_apply_request: Option<&ManagedFabricApplyRequestV1>,
    managed_agent_stack_apply_request: Option<&ManagedAgentStackApplyRequestV1>,
) -> Result<(), ManagedServingBootstrapError> {
    if bytes_are_zero(fields.request_id.as_bytes())
        || bytes_are_zero(fields.target.as_bytes())
        || bytes_are_zero(&fields.expected_runtime_store_instance_id)
        || fields.expected_runtime_host_epoch == 0
        || fields.carrier.target() != fields.target
        || fields.auth_claim.principal() != fields.carrier.controller_principal()
        || fields.auth_claim.key() != fields.carrier.controller_request_key()
        || fields.auth_claim.algorithm_version() == 0
        || fields.auth_claim.nonce().is_empty()
        || fields.auth_claim.nonce().iter().all(|byte| *byte == 0)
    {
        return Err(ManagedServingBootstrapError::InvalidAgentControlRequest);
    }
    match (
        kind,
        managed_fabric_apply_request,
        managed_agent_stack_apply_request,
    ) {
        (RuntimeAgentControlKindV1::ApplyManagedFabric, Some(request), None) => {
            if !digest_is_zero(expected_active_pxst_digest)
                || !bytes_are_zero(intended_client.as_bytes())
                || fields.request_id.as_bytes() != request.operation_id().as_bytes()
                || request.target() != fields.target
                || request.expected_runtime_store_instance_id()
                    != fields.expected_runtime_store_instance_id
                || request.authentication().claim().principal()
                    != fields.carrier.controller_principal()
                || request.authentication().claim().key() != fields.carrier.controller_request_key()
                || request.authentication().claim().nonce() == fields.auth_claim.nonce()
            {
                return Err(ManagedServingBootstrapError::InvalidAgentControlPayload);
            }
        }
        (RuntimeAgentControlKindV1::ApplyManagedAgentStack, None, Some(request)) => {
            if !digest_is_zero(expected_active_pxst_digest)
                || !bytes_are_zero(intended_client.as_bytes())
                || fields.request_id.as_bytes() != request.operation_id().as_bytes()
                || request.target() != fields.target
                || request.expected_runtime_store_instance_id()
                    != fields.expected_runtime_store_instance_id
                || request.authentication().claim().principal()
                    != fields.carrier.controller_principal()
                || request.authentication().claim().key() != fields.carrier.controller_request_key()
                || request.authentication().claim().nonce() == fields.auth_claim.nonce()
            {
                return Err(ManagedServingBootstrapError::InvalidAgentControlPayload);
            }
        }
        (RuntimeAgentControlKindV1::DescribeConversationPort, None, None) => {
            if digest_is_zero(expected_active_pxst_digest)
                || bytes_are_zero(intended_client.as_bytes())
            {
                return Err(ManagedServingBootstrapError::InvalidAgentControlPayload);
            }
        }
        _ => return Err(ManagedServingBootstrapError::InvalidAgentControlPayload),
    }
    Ok(())
}

fn validate_runtime_agent_control_request_lengths(
    kind: RuntimeAgentControlKindV1,
    carrier_length: usize,
    payload_length: usize,
    signature_length: usize,
    expected_active_pxst_digest: Digest32,
    intended_client: PrincipalRef,
) -> Result<(), ManagedServingBootstrapError> {
    if carrier_length == 0
        || carrier_length > MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
        || signature_length == 0
        || signature_length > MAX_APPLY_AUTH_SIGNATURE_BYTES
    {
        return Err(ManagedServingBootstrapError::InvalidLength);
    }
    let valid = match kind {
        RuntimeAgentControlKindV1::ApplyManagedFabric => {
            payload_length != 0
                && payload_length <= MAX_MANAGED_FABRIC_APPLY_REQUEST_BYTES
                && digest_is_zero(expected_active_pxst_digest)
                && bytes_are_zero(intended_client.as_bytes())
        }
        RuntimeAgentControlKindV1::ApplyManagedAgentStack => {
            payload_length != 0
                && payload_length <= MAX_MANAGED_AGENT_STACK_APPLY_REQUEST_BYTES
                && digest_is_zero(expected_active_pxst_digest)
                && bytes_are_zero(intended_client.as_bytes())
        }
        RuntimeAgentControlKindV1::DescribeConversationPort => {
            payload_length == 0
                && !digest_is_zero(expected_active_pxst_digest)
                && !bytes_are_zero(intended_client.as_bytes())
        }
    };
    if !valid {
        return Err(ManagedServingBootstrapError::InvalidAgentControlPayload);
    }
    Ok(())
}

fn build_runtime_agent_control_request_base(
    draft: &RuntimeAgentControlRequestDraftV1,
    magic: &[u8],
    version: u16,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let carrier_length = u16::try_from(draft.carrier.canonical_wire().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let payload_length = u32::try_from(
        draft
            .managed_fabric_apply_request
            .as_ref()
            .map(|request| request.canonical_wire().len())
            .or_else(|| {
                draft
                    .managed_agent_stack_apply_request
                    .as_ref()
                    .map(|request| request.canonical_wire().len())
            })
            .unwrap_or(0),
    )
    .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let nonce_length = u16::try_from(draft.auth_claim.nonce().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&version.to_be_bytes());
    wire.extend_from_slice(&(draft.kind as u16).to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(&carrier_length.to_be_bytes());
    wire.extend_from_slice(&payload_length.to_be_bytes());
    wire.extend_from_slice(draft.request_id.as_bytes());
    wire.extend_from_slice(draft.carrier.binding_digest().as_bytes());
    wire.extend_from_slice(draft.target.as_bytes());
    wire.extend_from_slice(&draft.expected_runtime_store_instance_id);
    wire.extend_from_slice(&draft.expected_runtime_host_epoch.to_be_bytes());
    wire.extend_from_slice(draft.expected_active_pxst_digest.as_bytes());
    wire.extend_from_slice(draft.intended_client.as_bytes());
    wire.extend_from_slice(draft.payload_wire_digest.as_bytes());
    encode_request_claim(&mut wire, &draft.auth_claim, nonce_length);
    Ok(wire)
}

fn append_runtime_agent_control_request_values(
    wire: &mut Vec<u8>,
    draft: &RuntimeAgentControlRequestDraftV1,
) {
    wire.extend_from_slice(draft.carrier.canonical_wire());
    if let Some(request) = draft.managed_fabric_apply_request.as_ref() {
        wire.extend_from_slice(request.canonical_wire());
    }
    if let Some(request) = draft.managed_agent_stack_apply_request.as_ref() {
        wire.extend_from_slice(request.canonical_wire());
    }
}

fn build_runtime_agent_control_request_wire(
    draft: &RuntimeAgentControlRequestDraftV1,
    authentication: &ApplyRequestAuthentication,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let signature_length = u16::try_from(authentication.signature().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = build_runtime_agent_control_request_base(
        draft,
        RUNTIME_AGENT_CONTROL_REQUEST_MAGIC,
        RUNTIME_AGENT_CONTROL_VERSION,
    )?;
    wire.extend_from_slice(&signature_length.to_be_bytes());
    append_runtime_agent_control_request_values(&mut wire, draft);
    wire.extend_from_slice(authentication.signature());
    Ok(wire)
}

fn validate_runtime_agent_control_response_auth(
    claim: RuntimeAgentControlResponseAuthClaimV1,
    carrier: &RestrictedRuntimeApplyCarrierBindingV1,
) -> Result<(), ManagedServingBootstrapError> {
    if bytes_are_zero(claim.runtime_principal.as_bytes())
        || bytes_are_zero(claim.key.as_bytes())
        || claim.algorithm_version == 0
        || digest_is_zero(claim.carrier_binding_digest)
        || claim.runtime_principal != carrier.runtime_principal()
        || claim.key != carrier.runtime_response_key()
        || claim.carrier_binding_digest != carrier.binding_digest()
    {
        return Err(ManagedServingBootstrapError::InvalidAgentControlAuthentication);
    }
    Ok(())
}

fn decode_runtime_agent_control_response_auth(
    cursor: &mut Cursor<'_>,
) -> Result<RuntimeAgentControlResponseAuthClaimV1, ManagedServingBootstrapError> {
    let claim = RuntimeAgentControlResponseAuthClaimV1 {
        runtime_principal: PrincipalRef::from_bytes(cursor.array()?),
        key: ApplyAuthKeyRef::from_bytes(cursor.array()?),
        algorithm: ApplyAuthAlgorithm::try_new(cursor.u16()?)?,
        algorithm_version: cursor.u16()?,
        carrier_binding_digest: Digest32::from_bytes(cursor.array()?),
    };
    if bytes_are_zero(claim.runtime_principal.as_bytes())
        || bytes_are_zero(claim.key.as_bytes())
        || claim.algorithm_version == 0
        || digest_is_zero(claim.carrier_binding_digest)
    {
        return Err(ManagedServingBootstrapError::InvalidAgentControlAuthentication);
    }
    Ok(claim)
}

fn decode_optional_managed_generation(
    value: u64,
) -> Result<Option<ManagedServiceGeneration>, ManagedServingBootstrapError> {
    if value == 0 {
        Ok(None)
    } else {
        ManagedServiceGeneration::try_new(value)
            .map(Some)
            .map_err(|_| ManagedServingBootstrapError::InvalidAgentControlReceipt)
    }
}

fn validate_runtime_agent_port_descriptor(
    descriptor: &[u8],
) -> Result<(), ManagedServingBootstrapError> {
    if descriptor.len() < 6
        || descriptor.len() > MAX_RUNTIME_AGENT_PORT_DESCRIPTOR_BYTES
        || &descriptor[..4] != b"PXAP"
        || u16::from_be_bytes([descriptor[4], descriptor[5]]) != 1
    {
        return Err(ManagedServingBootstrapError::InvalidAgentControlDescriptor);
    }
    Ok(())
}

fn validate_runtime_agent_control_receipt_draft(
    draft: &RuntimeAgentControlReceiptDraftV1,
) -> Result<(), ManagedServingBootstrapError> {
    if digest_is_zero(draft.request_digest)
        || draft.request_nonce.is_empty()
        || draft.request_nonce.len() > MAX_APPLY_AUTH_NONCE_BYTES
        || draft.request_nonce.iter().all(|byte| *byte == 0)
        || draft.carrier.target() != draft.target
        || bytes_are_zero(draft.target.as_bytes())
        || bytes_are_zero(&draft.runtime_store_instance_id)
        || draft.runtime_host_epoch == 0
        || digest_is_zero(draft.payload_wire_digest)
    {
        return Err(ManagedServingBootstrapError::InvalidAgentControlReceipt);
    }
    validate_runtime_agent_control_response_auth(draft.auth_claim, &draft.carrier)?;
    let valid = match (&draft.payload, draft.kind) {
        (
            RuntimeAgentControlReceiptPayloadV1::ManagedFabric(receipt),
            RuntimeAgentControlKindV1::ApplyManagedFabric,
        ) => {
            receipt.target() == draft.target
                && receipt.runtime_store_instance_id() == draft.runtime_store_instance_id
                && receipt.facts().completion_runtime_host_epoch() == draft.runtime_host_epoch
                && digest_is_zero(draft.expected_active_pxst_digest)
                && bytes_are_zero(draft.intended_client.as_bytes())
                && draft.fabric_generation.is_none()
                && draft.agent_generation.is_none()
        }
        (
            RuntimeAgentControlReceiptPayloadV1::ManagedAgentStack(receipt),
            RuntimeAgentControlKindV1::ApplyManagedAgentStack,
        ) => {
            let facts = receipt.facts();
            facts.target() == draft.target
                && facts.runtime_store_instance_id() == draft.runtime_store_instance_id
                && facts.evidence().fields().completion_runtime_host_epoch
                    == draft.runtime_host_epoch
                && digest_is_zero(draft.expected_active_pxst_digest)
                && bytes_are_zero(draft.intended_client.as_bytes())
                && draft.fabric_generation.is_none()
                && draft.agent_generation.is_none()
        }
        (
            RuntimeAgentControlReceiptPayloadV1::ConversationPortDescriptor(descriptor),
            RuntimeAgentControlKindV1::DescribeConversationPort,
        ) => {
            !digest_is_zero(draft.expected_active_pxst_digest)
                && !bytes_are_zero(draft.intended_client.as_bytes())
                && draft.fabric_generation.is_some()
                && draft.agent_generation.is_some()
                && validate_runtime_agent_port_descriptor(descriptor).is_ok()
        }
        _ => false,
    };
    if !valid
        || digest(
            AGENT_CONTROL_RECEIPT_PAYLOAD_DIGEST_DOMAIN,
            draft.payload.canonical_wire(),
        )? != draft.payload_wire_digest
    {
        return Err(ManagedServingBootstrapError::InvalidAgentControlReceipt);
    }
    Ok(())
}

fn validate_runtime_agent_control_receipt_against_request(
    draft: &RuntimeAgentControlReceiptDraftV1,
    request: &RuntimeAgentControlRequestV1,
) -> Result<(), ManagedServingBootstrapError> {
    if draft.request_id != request.request_id
        || draft.request_digest != request.request_digest
        || draft.request_nonce.as_ref() != request.authentication.claim().nonce()
        || draft.kind != request.kind
        || draft.carrier != request.carrier
        || draft.target != request.target
        || draft.runtime_store_instance_id != request.expected_runtime_store_instance_id
        || draft.runtime_host_epoch != request.expected_runtime_host_epoch
        || draft.expected_active_pxst_digest != request.expected_active_pxst_digest
        || draft.intended_client != request.intended_client
    {
        return Err(ManagedServingBootstrapError::AgentControlCorrelationMismatch);
    }
    let correlated = match (&draft.payload, request.kind) {
        (
            RuntimeAgentControlReceiptPayloadV1::ManagedFabric(receipt),
            RuntimeAgentControlKindV1::ApplyManagedFabric,
        ) => request
            .managed_fabric_apply_request
            .as_ref()
            .is_some_and(|inner| {
                receipt.target() == inner.target()
                    && receipt.runtime_store_instance_id()
                        == inner.expected_runtime_store_instance_id()
                    && receipt.provenance() == inner.provenance()
                    && receipt.operation_id() == inner.operation_id()
                    && receipt.request_digest() == inner.envelope_request_digest()
                    && receipt.request_nonce() == inner.authentication().claim().nonce()
                    && receipt.target_slice_digest() == inner.target_slice_digest()
                    && receipt.assignment_digest() == inner.assignment_digest()
            }),
        (
            RuntimeAgentControlReceiptPayloadV1::ManagedAgentStack(receipt),
            RuntimeAgentControlKindV1::ApplyManagedAgentStack,
        ) => request
            .managed_agent_stack_apply_request
            .as_ref()
            .is_some_and(|inner| {
                let facts = receipt.facts();
                facts.target() == inner.target()
                    && facts.runtime_store_instance_id()
                        == inner.expected_runtime_store_instance_id()
                    && facts.source_scope() == inner.provenance().source_scope()
                    && facts.operation_id() == inner.operation_id()
                    && facts.request_digest() == inner.envelope_request_digest()
                    && facts.target_slice_digest() == inner.target_slice_digest()
                    && facts.assignment_digest() == inner.assignment_digest()
                    && facts.request_mode() == inner.target_execution().mode()
            }),
        (
            RuntimeAgentControlReceiptPayloadV1::ConversationPortDescriptor(_),
            RuntimeAgentControlKindV1::DescribeConversationPort,
        ) => {
            request.managed_fabric_apply_request.is_none()
                && request.managed_agent_stack_apply_request.is_none()
        }
        _ => false,
    };
    if !correlated {
        return Err(ManagedServingBootstrapError::AgentControlCorrelationMismatch);
    }
    Ok(())
}

fn validate_runtime_agent_control_receipt_lengths(
    kind: RuntimeAgentControlKindV1,
    carrier_length: usize,
    payload_length: usize,
    nonce_length: usize,
    signature_length: usize,
) -> Result<(), ManagedServingBootstrapError> {
    if carrier_length == 0
        || carrier_length > MAX_RESTRICTED_RUNTIME_APPLY_CARRIER_BINDING_BYTES
        || nonce_length == 0
        || nonce_length > MAX_APPLY_AUTH_NONCE_BYTES
        || signature_length == 0
        || signature_length > MAX_APPLY_AUTH_SIGNATURE_BYTES
    {
        return Err(ManagedServingBootstrapError::InvalidLength);
    }
    let valid = match kind {
        RuntimeAgentControlKindV1::ApplyManagedFabric => {
            payload_length != 0 && payload_length <= MAX_MANAGED_FABRIC_APPLY_TERMINAL_RECEIPT_BYTES
        }
        RuntimeAgentControlKindV1::ApplyManagedAgentStack => {
            payload_length != 0 && payload_length <= MAX_MANAGED_AGENT_STACK_TERMINAL_RECEIPT_BYTES
        }
        RuntimeAgentControlKindV1::DescribeConversationPort => {
            (6..=MAX_RUNTIME_AGENT_PORT_DESCRIPTOR_BYTES).contains(&payload_length)
        }
    };
    if !valid {
        return Err(ManagedServingBootstrapError::InvalidAgentControlPayload);
    }
    Ok(())
}

fn build_runtime_agent_control_receipt_base(
    draft: &RuntimeAgentControlReceiptDraftV1,
    magic: &[u8],
    version: u16,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    validate_runtime_agent_control_receipt_draft(draft)?;
    let carrier_length = u16::try_from(draft.carrier.canonical_wire().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let payload_length = u32::try_from(draft.payload.canonical_wire().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let nonce_length = u16::try_from(draft.request_nonce.len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&version.to_be_bytes());
    wire.extend_from_slice(&(draft.kind as u16).to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(&carrier_length.to_be_bytes());
    wire.extend_from_slice(&payload_length.to_be_bytes());
    wire.extend_from_slice(&nonce_length.to_be_bytes());
    wire.extend_from_slice(draft.request_id.as_bytes());
    wire.extend_from_slice(draft.request_digest.as_bytes());
    wire.extend_from_slice(draft.carrier.binding_digest().as_bytes());
    wire.extend_from_slice(draft.target.as_bytes());
    wire.extend_from_slice(&draft.runtime_store_instance_id);
    wire.extend_from_slice(&draft.runtime_host_epoch.to_be_bytes());
    wire.extend_from_slice(draft.expected_active_pxst_digest.as_bytes());
    wire.extend_from_slice(draft.intended_client.as_bytes());
    wire.extend_from_slice(draft.payload_wire_digest.as_bytes());
    wire.extend_from_slice(
        &draft
            .fabric_generation
            .map_or(0, ManagedServiceGeneration::value)
            .to_be_bytes(),
    );
    wire.extend_from_slice(
        &draft
            .agent_generation
            .map_or(0, ManagedServiceGeneration::value)
            .to_be_bytes(),
    );
    wire.extend_from_slice(draft.auth_claim.runtime_principal.as_bytes());
    wire.extend_from_slice(draft.auth_claim.key.as_bytes());
    wire.extend_from_slice(&draft.auth_claim.algorithm.value().to_be_bytes());
    wire.extend_from_slice(&draft.auth_claim.algorithm_version.to_be_bytes());
    wire.extend_from_slice(draft.auth_claim.carrier_binding_digest.as_bytes());
    Ok(wire)
}

fn append_runtime_agent_control_receipt_values(
    wire: &mut Vec<u8>,
    draft: &RuntimeAgentControlReceiptDraftV1,
) {
    wire.extend_from_slice(&draft.request_nonce);
    wire.extend_from_slice(draft.carrier.canonical_wire());
    wire.extend_from_slice(draft.payload.canonical_wire());
}

fn build_runtime_agent_control_receipt_wire(
    draft: &RuntimeAgentControlReceiptDraftV1,
    signature: &[u8],
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let signature_length =
        u16::try_from(signature.len()).map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = build_runtime_agent_control_receipt_base(
        draft,
        RUNTIME_AGENT_CONTROL_RECEIPT_MAGIC,
        RUNTIME_AGENT_CONTROL_VERSION,
    )?;
    wire.extend_from_slice(&signature_length.to_be_bytes());
    append_runtime_agent_control_receipt_values(&mut wire, draft);
    wire.extend_from_slice(signature);
    Ok(wire)
}

fn validate_runtime_control_carrier_fields(
    request_id: ManagedServingBootstrapRequestIdV1,
    kind: RuntimeControlCarrierKindV1,
    carrier: &RestrictedRuntimeApplyCarrierBindingV1,
    request: Option<&ManagedServingBootstrapRequestV1>,
    query: Option<&ReferenceQueryRequestV1>,
    auth_claim: &ApplyRequestAuthClaim,
) -> Result<(), ManagedServingBootstrapError> {
    if bytes_are_zero(request_id.as_bytes())
        || auth_claim.principal() != carrier.controller_principal()
        || auth_claim.key() != carrier.controller_request_key()
        || auth_claim.algorithm_version() == 0
        || auth_claim.nonce().iter().all(|byte| *byte == 0)
    {
        return Err(ManagedServingBootstrapError::InvalidControlCarrierAuthentication);
    }
    match (kind, request, query) {
        (RuntimeControlCarrierKindV1::Describe, None, None) => Ok(()),
        (RuntimeControlCarrierKindV1::ManagedServingBootstrap, Some(request), None)
            if request.request_id() == request_id
                && request.target() == carrier.target()
                && request.channel().target() == carrier.target()
                && request.channel().runtime_peer() == carrier.runtime_principal()
                && request.authentication().claim().principal()
                    == carrier.controller_principal()
                && request.authentication().claim().key() == carrier.controller_request_key() =>
        {
            Ok(())
        }
        (RuntimeControlCarrierKindV1::ReferenceQuery, None, Some(query))
            if query.target() == carrier.target()
                && query.authentication().claim().principal() == carrier.controller_principal()
                && query.authentication().claim().key() == carrier.controller_request_key() =>
        {
            Ok(())
        }
        _ => Err(ManagedServingBootstrapError::InvalidControlCarrierPayload),
    }
}

fn build_runtime_control_carrier_request_base(
    draft: &RuntimeControlCarrierRequestDraftV1,
    magic: &[u8],
    version: u16,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let carrier_length = u16::try_from(draft.carrier.canonical_wire().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let payload_length = u32::try_from(
        draft
            .managed_serving_bootstrap_request
            .as_ref()
            .map(|request| request.canonical_wire().len())
            .or_else(|| {
                draft
                    .reference_query_request
                    .as_ref()
                    .map(|request| request.canonical_wire().len())
            })
            .unwrap_or(0),
    )
    .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let nonce_length = u16::try_from(draft.auth_claim.nonce().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&version.to_be_bytes());
    wire.extend_from_slice(&(draft.kind as u16).to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(&carrier_length.to_be_bytes());
    wire.extend_from_slice(&payload_length.to_be_bytes());
    wire.extend_from_slice(draft.request_id.as_bytes());
    wire.extend_from_slice(draft.carrier.binding_digest().as_bytes());
    wire.extend_from_slice(draft.payload_wire_digest.as_bytes());
    wire.extend_from_slice(draft.auth_claim.principal().as_bytes());
    wire.extend_from_slice(draft.auth_claim.key().as_bytes());
    wire.extend_from_slice(&draft.auth_claim.algorithm().value().to_be_bytes());
    wire.extend_from_slice(&draft.auth_claim.algorithm_version().to_be_bytes());
    wire.extend_from_slice(&nonce_length.to_be_bytes());
    wire.extend_from_slice(draft.auth_claim.nonce());
    Ok(wire)
}

fn build_runtime_control_carrier_request_wire(
    draft: &RuntimeControlCarrierRequestDraftV1,
    authentication: &ApplyRequestAuthentication,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let signature_length = u16::try_from(authentication.signature().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = build_runtime_control_carrier_request_base(
        draft,
        CONTROL_CARRIER_REQUEST_MAGIC,
        RUNTIME_CONTROL_CARRIER_VERSION,
    )?;
    wire.extend_from_slice(&signature_length.to_be_bytes());
    wire.extend_from_slice(draft.carrier.canonical_wire());
    if let Some(request) = draft.managed_serving_bootstrap_request.as_ref() {
        wire.extend_from_slice(request.canonical_wire());
    }
    if let Some(request) = draft.reference_query_request.as_ref() {
        wire.extend_from_slice(request.canonical_wire());
    }
    wire.extend_from_slice(authentication.signature());
    Ok(wire)
}

fn validate_runtime_control_describe_ready(
    request: &RuntimeControlCarrierRequestV1,
    facts: &RuntimeControlDescribeReadyFactsV1,
    auth_claim: ManagedServingBootstrapResponseAuthClaimV1,
) -> Result<(), ManagedServingBootstrapError> {
    if request.kind != RuntimeControlCarrierKindV1::Describe
        || request.managed_serving_bootstrap_request.is_some()
        || request.reference_query_request.is_some()
        || facts.serving.target() != request.carrier.target()
        || facts.channel.target() != request.carrier.target()
        || facts.channel.runtime_peer() != request.carrier.runtime_principal()
        || auth_claim.runtime_peer() != request.carrier.runtime_principal()
        || auth_claim.channel_binding_digest() != facts.channel.binding_digest()
        || auth_claim.key() != request.carrier.runtime_response_key()
    {
        return Err(ManagedServingBootstrapError::InvalidControlReadyFacts);
    }
    Ok(())
}

fn validate_runtime_control_describe_ready_draft(
    draft: &RuntimeControlDescribeReadyResponseDraftV1,
) -> Result<(), ManagedServingBootstrapError> {
    if digest_is_zero(draft.request_digest)
        || draft.request_nonce.is_empty()
        || draft.request_nonce.len() > MAX_APPLY_AUTH_NONCE_BYTES
        || draft.request_nonce.iter().all(|byte| *byte == 0)
        || draft.facts.serving.target() != draft.carrier.target()
        || draft.facts.channel.target() != draft.carrier.target()
        || draft.facts.channel.runtime_peer() != draft.carrier.runtime_principal()
        || draft.auth_claim.runtime_peer() != draft.carrier.runtime_principal()
        || draft.auth_claim.channel_binding_digest() != draft.facts.channel.binding_digest()
        || draft.auth_claim.key() != draft.carrier.runtime_response_key()
    {
        return Err(ManagedServingBootstrapError::InvalidControlReadyFacts);
    }
    Ok(())
}

fn build_runtime_control_describe_ready_base(
    draft: &RuntimeControlDescribeReadyResponseDraftV1,
    magic: &[u8],
    version: u16,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    validate_runtime_control_describe_ready_draft(draft)?;
    let carrier_length = u16::try_from(draft.carrier.canonical_wire().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let projection_length = u32::try_from(draft.facts.serving.projection().canonical_wire().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let nonce_length = u16::try_from(draft.request_nonce.len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&version.to_be_bytes());
    wire.extend_from_slice(&(draft.facts.phase as u16).to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(&carrier_length.to_be_bytes());
    wire.extend_from_slice(&projection_length.to_be_bytes());
    wire.extend_from_slice(&nonce_length.to_be_bytes());
    wire.extend_from_slice(draft.request_id.as_bytes());
    wire.extend_from_slice(draft.request_digest.as_bytes());
    wire.extend_from_slice(draft.carrier.binding_digest().as_bytes());
    wire.extend_from_slice(draft.facts.serving.target().as_bytes());
    wire.extend_from_slice(&draft.facts.serving.runtime_store_instance_id());
    wire.extend_from_slice(&draft.facts.serving.runtime_host_epoch().to_be_bytes());
    wire.extend_from_slice(&draft.facts.serving.snapshot_sequence().to_be_bytes());
    wire.extend_from_slice(draft.facts.serving.clock_domain().as_bytes());
    wire.extend_from_slice(&draft.facts.serving.clock_generation().value().to_be_bytes());
    wire.extend_from_slice(&draft.facts.serving.observed_at_nanos().to_be_bytes());
    wire.extend_from_slice(&(draft.facts.serving.readiness() as u16).to_be_bytes());
    encode_channel(&mut wire, draft.facts.channel);
    encode_response_claim(&mut wire, draft.auth_claim);
    Ok(wire)
}

fn append_runtime_control_describe_ready_values(
    wire: &mut Vec<u8>,
    draft: &RuntimeControlDescribeReadyResponseDraftV1,
) {
    wire.extend_from_slice(draft.carrier.canonical_wire());
    wire.extend_from_slice(draft.facts.serving.projection().canonical_wire());
    wire.extend_from_slice(&draft.request_nonce);
}

fn build_runtime_control_describe_ready_wire(
    draft: &RuntimeControlDescribeReadyResponseDraftV1,
    signature: &[u8],
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let signature_length =
        u16::try_from(signature.len()).map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = build_runtime_control_describe_ready_base(
        draft,
        CONTROL_DESCRIBE_READY_MAGIC,
        RUNTIME_CONTROL_CARRIER_VERSION,
    )?;
    wire.extend_from_slice(&signature_length.to_be_bytes());
    append_runtime_control_describe_ready_values(&mut wire, draft);
    wire.extend_from_slice(signature);
    Ok(wire)
}

fn validate_request_fields(
    _request_id: ManagedServingBootstrapRequestIdV1,
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    expected_runtime_store_instance_id: [u8; 32],
    projection: &ManagedFabricManifestProjectionV1,
    channel: ReferenceChannelBindingV1,
    auth_claim: &ApplyRequestAuthClaim,
) -> Result<(), ManagedServingBootstrapError> {
    if bytes_are_zero(target.as_bytes())
        || bytes_are_zero(source_scope.as_bytes())
        || bytes_are_zero(&expected_runtime_store_instance_id)
        || projection.target() != target
        || channel.target() != target
        || bytes_are_zero(auth_claim.principal().as_bytes())
        || bytes_are_zero(auth_claim.key().as_bytes())
        || auth_claim.algorithm_version() == 0
        || auth_claim.nonce().iter().all(|byte| *byte == 0)
    {
        return Err(ManagedServingBootstrapError::InvalidRequest);
    }
    Ok(())
}

fn build_request_wire(
    draft: &ManagedServingBootstrapRequestDraftV1,
    authentication: &ApplyRequestAuthentication,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let signature_length = u16::try_from(authentication.signature().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = build_request_fields(draft, REQUEST_MAGIC, MANAGED_SERVING_BOOTSTRAP_VERSION)?;
    wire.extend_from_slice(&signature_length.to_be_bytes());
    wire.extend_from_slice(draft.projection.canonical_wire());
    wire.extend_from_slice(authentication.signature());
    Ok(wire)
}

fn build_request_transcript(
    draft: &ManagedServingBootstrapRequestDraftV1,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let mut transcript = build_request_fields(
        draft,
        REQUEST_TRANSCRIPT_MAGIC,
        MANAGED_SERVING_BOOTSTRAP_REQUEST_SIGNING_VERSION,
    )?;
    transcript.extend_from_slice(draft.projection.canonical_wire());
    Ok(transcript)
}

fn build_request_fields(
    draft: &ManagedServingBootstrapRequestDraftV1,
    magic: &[u8],
    version: u16,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let projection_length = u32::try_from(draft.projection.canonical_wire().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let nonce_length = u16::try_from(draft.auth_claim.nonce().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&version.to_be_bytes());
    wire.extend_from_slice(draft.request_id.as_bytes());
    wire.extend_from_slice(draft.target.as_bytes());
    wire.extend_from_slice(draft.source_scope.as_bytes());
    wire.extend_from_slice(&draft.expected_runtime_store_instance_id);
    wire.extend_from_slice(&projection_length.to_be_bytes());
    encode_channel(&mut wire, draft.channel);
    encode_request_claim(&mut wire, &draft.auth_claim, nonce_length);
    Ok(wire)
}

fn build_response_wire(
    draft: &ManagedServingBootstrapResponseDraftV1,
    signature: &[u8],
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let signature_length =
        u16::try_from(signature.len()).map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = build_response_fields(draft, RESPONSE_MAGIC, MANAGED_SERVING_BOOTSTRAP_VERSION)?;
    wire.extend_from_slice(&signature_length.to_be_bytes());
    wire.extend_from_slice(draft.facts.projection.canonical_wire());
    wire.extend_from_slice(&draft.request_nonce);
    wire.extend_from_slice(signature);
    Ok(wire)
}

fn build_response_transcript(
    draft: &ManagedServingBootstrapResponseDraftV1,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let mut transcript = build_response_fields(
        draft,
        RESPONSE_TRANSCRIPT_MAGIC,
        MANAGED_SERVING_BOOTSTRAP_RESPONSE_SIGNING_VERSION,
    )?;
    transcript.extend_from_slice(draft.facts.projection.canonical_wire());
    transcript.extend_from_slice(&draft.request_nonce);
    Ok(transcript)
}

fn build_response_fields(
    draft: &ManagedServingBootstrapResponseDraftV1,
    magic: &[u8],
    version: u16,
) -> Result<Vec<u8>, ManagedServingBootstrapError> {
    let nonce_length = u16::try_from(draft.request_nonce.len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let projection_length = u32::try_from(draft.facts.projection.canonical_wire().len())
        .map_err(|_| ManagedServingBootstrapError::InvalidLength)?;
    let mut wire = Vec::new();
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&version.to_be_bytes());
    wire.extend_from_slice(draft.request_id.as_bytes());
    wire.extend_from_slice(draft.request_digest.as_bytes());
    wire.extend_from_slice(&nonce_length.to_be_bytes());
    wire.extend_from_slice(draft.facts.target.as_bytes());
    wire.extend_from_slice(&draft.facts.runtime_store_instance_id);
    wire.extend_from_slice(&projection_length.to_be_bytes());
    wire.extend_from_slice(&draft.facts.runtime_host_epoch.to_be_bytes());
    wire.extend_from_slice(&draft.facts.snapshot_sequence.to_be_bytes());
    wire.extend_from_slice(draft.facts.clock_domain.as_bytes());
    wire.extend_from_slice(&draft.facts.clock_generation.value().to_be_bytes());
    wire.extend_from_slice(&draft.facts.observed_at_nanos.to_be_bytes());
    wire.extend_from_slice(&(draft.facts.readiness as u16).to_be_bytes());
    encode_channel(&mut wire, draft.channel);
    encode_response_claim(&mut wire, draft.auth_claim);
    Ok(wire)
}

fn encode_channel(wire: &mut Vec<u8>, channel: ReferenceChannelBindingV1) {
    wire.extend_from_slice(channel.target().as_bytes());
    wire.extend_from_slice(channel.runtime_peer().as_bytes());
    wire.extend_from_slice(channel.local_endpoint_identity_digest().as_bytes());
    wire.extend_from_slice(channel.peer_credentials_digest().as_bytes());
}

fn decode_channel(
    cursor: &mut Cursor<'_>,
) -> Result<ReferenceChannelBindingV1, ManagedServingBootstrapError> {
    Ok(ReferenceChannelBindingV1::try_new(
        RuntimeHostId::from_bytes(cursor.array()?),
        PrincipalRef::from_bytes(cursor.array()?),
        Digest32::from_bytes(cursor.array()?),
        Digest32::from_bytes(cursor.array()?),
    )?)
}

fn encode_request_claim(wire: &mut Vec<u8>, claim: &ApplyRequestAuthClaim, nonce_length: u16) {
    wire.extend_from_slice(claim.principal().as_bytes());
    wire.extend_from_slice(claim.key().as_bytes());
    wire.extend_from_slice(&claim.algorithm().value().to_be_bytes());
    wire.extend_from_slice(&claim.algorithm_version().to_be_bytes());
    wire.extend_from_slice(&nonce_length.to_be_bytes());
    wire.extend_from_slice(claim.nonce());
}

fn decode_request_claim(
    cursor: &mut Cursor<'_>,
) -> Result<ApplyRequestAuthClaim, ManagedServingBootstrapError> {
    let principal = PrincipalRef::from_bytes(cursor.array()?);
    let key = ApplyAuthKeyRef::from_bytes(cursor.array()?);
    let algorithm = ApplyAuthAlgorithm::try_new(cursor.u16()?)?;
    let algorithm_version = cursor.u16()?;
    let nonce_length = cursor.usize_u16()?;
    if nonce_length == 0 || nonce_length > MAX_APPLY_AUTH_NONCE_BYTES {
        return Err(ManagedServingBootstrapError::InvalidLength);
    }
    Ok(ApplyRequestAuthClaim::try_new(
        principal,
        key,
        algorithm,
        algorithm_version,
        cursor.take(nonce_length)?,
    )?)
}

fn encode_response_claim(wire: &mut Vec<u8>, claim: ManagedServingBootstrapResponseAuthClaimV1) {
    wire.extend_from_slice(claim.runtime_peer.as_bytes());
    wire.extend_from_slice(claim.channel_binding_digest.as_bytes());
    wire.extend_from_slice(claim.key.as_bytes());
    wire.extend_from_slice(&claim.algorithm.value().to_be_bytes());
    wire.extend_from_slice(&claim.algorithm_version.to_be_bytes());
}

fn decode_response_claim(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedServingBootstrapResponseAuthClaimV1, ManagedServingBootstrapError> {
    let claim = ManagedServingBootstrapResponseAuthClaimV1 {
        runtime_peer: PrincipalRef::from_bytes(cursor.array()?),
        channel_binding_digest: Digest32::from_bytes(cursor.array()?),
        key: ApplyAuthKeyRef::from_bytes(cursor.array()?),
        algorithm: ApplyAuthAlgorithm::try_new(cursor.u16()?)?,
        algorithm_version: cursor.u16()?,
    };
    if bytes_are_zero(claim.runtime_peer.as_bytes())
        || digest_is_zero(claim.channel_binding_digest)
        || bytes_are_zero(claim.key.as_bytes())
        || claim.algorithm_version == 0
    {
        return Err(ManagedServingBootstrapError::InvalidAuthentication);
    }
    Ok(claim)
}

fn digest(domain: &[u8], wire: &[u8]) -> Result<Digest32, DigestBuildError> {
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

struct Cursor<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ManagedServingBootstrapError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ManagedServingBootstrapError::FrameTooLarge)?;
        let value = self
            .frame
            .get(self.position..end)
            .ok_or(ManagedServingBootstrapError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManagedServingBootstrapError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ManagedServingBootstrapError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, ManagedServingBootstrapError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ManagedServingBootstrapError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize_u16(&mut self) -> Result<usize, ManagedServingBootstrapError> {
        Ok(usize::from(self.u16()?))
    }

    fn usize_u32(&mut self) -> Result<usize, ManagedServingBootstrapError> {
        usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| ManagedServingBootstrapError::FrameTooLarge)
    }

    fn finish(self) -> Result<(), ManagedServingBootstrapError> {
        if self.position == self.frame.len() {
            Ok(())
        } else {
            Err(ManagedServingBootstrapError::TrailingBytes)
        }
    }
}

/// Strict PXFB/PXFR, PXCC/PXDR, and PXAG/PXAH contract failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedServingBootstrapError {
    /// A required opaque identity is zero.
    InvalidIdentity,
    /// Request target/store/projection/channel/auth facts conflict.
    InvalidRequest,
    /// Runtime serving facts are invalid.
    InvalidFacts,
    /// Authentication selection or signature is invalid.
    InvalidAuthentication,
    /// Authentication claim and completed authentication differ.
    AuthenticationMismatch,
    /// Request/response/store/projection/channel facts do not correlate exactly.
    CorrelationMismatch,
    /// PXCC carried an unknown or reserved operation kind.
    UnsupportedControlCarrierKind,
    /// PXCC/PXDR did not carry the exact selected canonical PXCB value.
    InvalidControlCarrierBinding,
    /// The kind-specific PXCC payload was absent, unexpected or invalid.
    InvalidControlCarrierPayload,
    /// PXCC/PXDR signer selection, nonce or signature verification failed.
    InvalidControlCarrierAuthentication,
    /// PXAG carried an unknown or reserved operation kind.
    UnsupportedAgentControlKind,
    /// PXAG target/store/epoch/request identity or nonce facts conflict.
    InvalidAgentControlRequest,
    /// PXAG/PXAH did not retain the exact selected PXCB value.
    InvalidAgentControlBinding,
    /// The kind-specific PXAG/PXAH payload is absent, unexpected or invalid.
    InvalidAgentControlPayload,
    /// PXAH outer facts or inner terminal shape are invalid.
    InvalidAgentControlReceipt,
    /// PXAP bootstrap bytes are absent, oversized or use another wire.
    InvalidAgentControlDescriptor,
    /// PXAG/PXAH request, payload, target/store/epoch or audience facts differ.
    AgentControlCorrelationMismatch,
    /// PXAG/PXAH signer selection, PXCB pins, nonce or signature are invalid.
    InvalidAgentControlAuthentication,
    /// PXDR carried an unknown or reserved Runtime serving phase.
    UnsupportedControlReadyPhase,
    /// PXDR serving, channel, projection or phase facts conflict.
    InvalidControlReadyFacts,
    /// V1 admits only recovered-ready responses.
    UnsupportedReadiness,
    /// Magic or version is not the exact v1 protocol.
    UnsupportedWire,
    /// A length field is invalid.
    InvalidLength,
    /// Input ends before the declared frame.
    Truncated,
    /// Input contains bytes beyond the declared frame.
    TrailingBytes,
    /// Input exceeds the fixed protocol bound.
    FrameTooLarge,
    /// Strict decode did not reconstruct byte-identical canonical wire.
    NonCanonicalFrame,
    /// Request authentication failed construction.
    Authentication(ApplyAuthError),
    /// Projection validation failed.
    Projection(ManagedFabricPlanError),
    /// Channel binding validation failed.
    Channel(ReferenceControlError),
    /// Digest construction failed.
    Digest(DigestBuildError),
}

impl From<ApplyAuthError> for ManagedServingBootstrapError {
    fn from(value: ApplyAuthError) -> Self {
        Self::Authentication(value)
    }
}

impl From<ManagedFabricPlanError> for ManagedServingBootstrapError {
    fn from(value: ManagedFabricPlanError) -> Self {
        Self::Projection(value)
    }
}

impl From<ReferenceControlError> for ManagedServingBootstrapError {
    fn from(value: ReferenceControlError) -> Self {
        Self::Channel(value)
    }
}

impl From<DigestBuildError> for ManagedServingBootstrapError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ManagedServingBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "managed serving bootstrap rejected: {self:?}")
    }
}

impl std::error::Error for ManagedServingBootstrapError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::PrincipalRef;

    use crate::apply::ApplyOperationId;
    use crate::distributed_agent_stack_plan::RestrictedRuntimeApplyCarrierBindingFieldsV1;
    use crate::reference_control::{
        MAX_REFERENCE_QUERY_RESPONSE_BYTES, ReferenceQueryIdV1, ReferenceQueryRequestDraftV1,
        ReferenceQuerySelectorV1,
    };

    use super::*;

    const FABRIC_FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_fabric_successor_v1.json");
    const AGENT_STACK_FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_agent_stack_successor_v1.json");

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("non-hex fixture byte"),
        }
    }

    fn projection() -> ManagedFabricManifestProjectionV1 {
        let marker = "\"projection_hex\": \"";
        let start = FABRIC_FIXTURE.find(marker).expect("projection fixture") + marker.len();
        let end = start
            + FABRIC_FIXTURE[start..]
                .find('"')
                .expect("projection fixture terminator");
        let hex = &FABRIC_FIXTURE.as_bytes()[start..end];
        let bytes: Vec<u8> = hex
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect();
        ManagedFabricManifestProjectionV1::decode(&bytes).expect("projection decodes")
    }

    fn fixture_hex_after(fixture: &str, section: &str, key: &str) -> Vec<u8> {
        let section_start = fixture.find(section).expect("fixture section");
        let key_start = fixture[section_start..]
            .find(key)
            .map(|offset| section_start + offset + key.len())
            .expect("fixture key");
        let quote_start = fixture[key_start..]
            .find('"')
            .map(|offset| key_start + offset + 1)
            .expect("fixture quote");
        let quote_end = fixture[quote_start..]
            .find('"')
            .map(|offset| quote_start + offset)
            .expect("fixture quote end");
        fixture.as_bytes()[quote_start..quote_end]
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn managed_fabric_apply_fixture() -> (
        ManagedFabricApplyRequestV1,
        ManagedFabricApplyTerminalReceiptV1,
        ReferenceChannelBindingV1,
    ) {
        let request = ManagedFabricApplyRequestV1::decode(&fixture_hex_after(
            FABRIC_FIXTURE,
            "\"one_managed_fabric_service\"",
            "\"outer_v6_hex\"",
        ))
        .expect("PXAR v6 fixture");
        let receipt = ManagedFabricApplyTerminalReceiptV1::decode(&fixture_hex_after(
            FABRIC_FIXTURE,
            "\"active_ready\"",
            "\"wire_hex\"",
        ))
        .expect("PXFT fixture");
        let channel = ReferenceChannelBindingV1::try_new(
            request.target(),
            PrincipalRef::from_bytes([0xe1; 16]),
            Digest32::from_bytes([0xe3; 32]),
            Digest32::from_bytes([0xe4; 32]),
        )
        .expect("PXFT fixture channel");
        (request, receipt, channel)
    }

    fn managed_agent_apply_fixture() -> (
        ManagedAgentStackApplyRequestV1,
        ManagedAgentStackTerminalReceiptV1,
        ReferenceChannelBindingV1,
    ) {
        let request = ManagedAgentStackApplyRequestV1::decode(&fixture_hex_after(
            AGENT_STACK_FIXTURE,
            "\"fabric_and_agent\"",
            "\"outer_v7_hex\"",
        ))
        .expect("PXAR v7 fixture");
        let receipt = ManagedAgentStackTerminalReceiptV1::decode(&fixture_hex_after(
            AGENT_STACK_FIXTURE,
            "\"fabric_and_agent\"",
            "\"wire_hex\"",
        ))
        .expect("PXST fixture");
        let channel = ReferenceChannelBindingV1::try_new(
            request.target(),
            PrincipalRef::from_bytes([0x71; 16]),
            Digest32::from_bytes([0x72; 32]),
            Digest32::from_bytes([0x73; 32]),
        )
        .expect("PXST fixture channel");
        (request, receipt, channel)
    }

    fn agent_control_carrier(
        target: RuntimeHostId,
        controller_principal: PrincipalRef,
        controller_key: ApplyAuthKeyRef,
        runtime_principal: PrincipalRef,
        runtime_key: ApplyAuthKeyRef,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target,
                runtime_principal,
                controller_principal,
                endpoint_ref: [0x81; 16],
                endpoint_generation: 7,
                route: "paraegox/runtime/control/v1/apply",
                controller_request_key: controller_key,
                controller_request_key_fingerprint: Digest32::from_bytes([0x82; 32]),
                runtime_response_key: runtime_key,
                runtime_response_key_fingerprint: Digest32::from_bytes([0x83; 32]),
                control_transport_profile_ref: [0x84; 16],
                control_transport_profile_digest: Digest32::from_bytes([0x85; 32]),
            },
        )
        .expect("Agent-control PXCB")
    }

    fn agent_control_fields(
        request_id: [u8; 16],
        target: RuntimeHostId,
        store: [u8; 32],
        epoch: u64,
        carrier: RestrictedRuntimeApplyCarrierBindingV1,
        nonce: &[u8],
    ) -> RuntimeAgentControlRequestFieldsV1 {
        RuntimeAgentControlRequestFieldsV1 {
            request_id: RuntimeAgentControlRequestIdV1::try_from_bytes(request_id)
                .expect("Agent-control request id"),
            target,
            expected_runtime_store_instance_id: store,
            expected_runtime_host_epoch: epoch,
            auth_claim: ApplyRequestAuthClaim::try_new(
                carrier.controller_principal(),
                carrier.controller_request_key(),
                ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
                1,
                nonce,
            )
            .expect("Agent-control auth"),
            carrier,
        }
    }

    fn agent_control_response_auth(
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
    ) -> RuntimeAgentControlResponseAuthClaimV1 {
        RuntimeAgentControlResponseAuthClaimV1::try_new(
            carrier,
            carrier.runtime_response_key(),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("Agent-control response auth")
    }

    fn authenticate_agent_control_request<'a>(
        request: &'a RuntimeAgentControlRequestV1,
        carrier: &RestrictedRuntimeApplyCarrierBindingV1,
        expected_signature: &[u8],
    ) -> ControllerAuthenticatedRuntimeAgentControlRequestV1<'a> {
        request
            .verify_controller_request(
                carrier,
                |principal, key, fingerprint, transcript, signature| {
                    principal == carrier.controller_principal()
                        && key == carrier.controller_request_key()
                        && fingerprint == carrier.controller_request_key_fingerprint()
                        && !transcript.is_empty()
                        && signature == expected_signature
                },
            )
            .expect("Controller-authenticated PXAG")
    }

    fn channel(target: RuntimeHostId) -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            target,
            PrincipalRef::from_bytes([0x31; 16]),
            Digest32::from_bytes([0x32; 32]),
            Digest32::from_bytes([0x33; 32]),
        )
        .expect("channel")
    }

    fn request() -> ManagedServingBootstrapRequestV1 {
        let projection = projection();
        let target = projection.target();
        let claim = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([0x34; 16]),
            ApplyAuthKeyRef::from_bytes([0x35; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
            &[0x36; 32],
        )
        .expect("claim");
        ManagedServingBootstrapRequestDraftV1::try_new(
            ManagedServingBootstrapRequestIdV1::try_from_bytes([0x37; 16]).expect("request id"),
            target,
            SourceScopeRef::from_bytes([0x38; 16]),
            [0x39; 32],
            projection,
            channel(target),
            claim,
        )
        .expect("request draft")
        .finalize(&[0x3a; 64])
        .expect("request")
    }

    fn response(request: &ManagedServingBootstrapRequestV1) -> ManagedServingBootstrapResponseV1 {
        let facts = ManagedServingBootstrapFactsV1::try_recovered_ready(
            request.target(),
            request.expected_runtime_store_instance_id(),
            request.projection().clone(),
            7,
            11,
            ClockReading::new(
                ClockDomainRef::from_bytes([0x3b; 16]),
                ClockGeneration::try_new(13).expect("clock generation"),
                MonotonicInstant::from_ticks(17),
            ),
        )
        .expect("facts");
        let auth = ManagedServingBootstrapResponseAuthClaimV1::try_new(
            request.channel(),
            ApplyAuthKeyRef::from_bytes([0x3c; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("response claim");
        ManagedServingBootstrapResponseDraftV1::try_new(request, facts, request.channel(), auth)
            .expect("response draft")
            .finalize(&[0x3d; 64])
            .expect("response")
    }

    fn control_carrier(target: RuntimeHostId) -> RestrictedRuntimeApplyCarrierBindingV1 {
        RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target,
                runtime_principal: PrincipalRef::from_bytes([0x31; 16]),
                controller_principal: PrincipalRef::from_bytes([0x34; 16]),
                endpoint_ref: [0x40; 16],
                endpoint_generation: 3,
                route: "paraegox/runtime/control/v1/apply",
                controller_request_key: ApplyAuthKeyRef::from_bytes([0x35; 16]),
                controller_request_key_fingerprint: Digest32::from_bytes([0x41; 32]),
                runtime_response_key: ApplyAuthKeyRef::from_bytes([0x3c; 16]),
                runtime_response_key_fingerprint: Digest32::from_bytes([0x42; 32]),
                control_transport_profile_ref: [0x43; 16],
                control_transport_profile_digest: Digest32::from_bytes([0x44; 32]),
            },
        )
        .expect("control carrier")
    }

    fn control_auth(nonce: &[u8]) -> ApplyRequestAuthClaim {
        ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([0x34; 16]),
            ApplyAuthKeyRef::from_bytes([0x35; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
            nonce,
        )
        .expect("control auth")
    }

    fn control_describe() -> RuntimeControlCarrierRequestV1 {
        let target = projection().target();
        RuntimeControlCarrierRequestDraftV1::try_describe(
            ManagedServingBootstrapRequestIdV1::try_from_bytes([0x45; 16])
                .expect("control request id"),
            control_carrier(target),
            control_auth(&[0x46; 32]),
        )
        .expect("Describe draft")
        .finalize(&[0x47; 64])
        .expect("Describe")
    }

    fn reference_query(target: RuntimeHostId) -> ReferenceQueryRequestV1 {
        let selector = ReferenceQuerySelectorV1::try_new(
            ReferenceQueryIdV1::from_bytes([0x48; 16]),
            target,
            SourceScopeRef::from_bytes([0x49; 16]),
            [0x4a; 32],
            ApplyOperationId::from_bytes([0x4b; 16]),
            None,
        )
        .expect("query selector");
        ReferenceQueryRequestDraftV1::try_new(
            selector,
            control_auth(&[0x4c; 32]),
            MAX_REFERENCE_QUERY_RESPONSE_BYTES as u32,
        )
        .expect("query draft")
        .finalize(&[0x4d; 64])
        .expect("query")
    }

    #[test]
    fn exact_request_and_recovered_ready_response_round_trip() {
        let request = request();
        let response = response(&request);
        assert_eq!(&request.canonical_wire()[..6], b"PXFB\0\x01");
        assert_eq!(&response.canonical_wire()[..6], b"PXFR\0\x01");
        assert_eq!(
            ManagedServingBootstrapRequestV1::decode(request.canonical_wire())
                .expect("request round trip"),
            request
        );
        let decoded = ManagedServingBootstrapResponseV1::decode(response.canonical_wire())
            .expect("response round trip");
        assert_eq!(decoded, response);
        assert_eq!(
            decoded
                .validate_against_request(&request, request.channel())
                .expect("exact response correlation")
                .readiness(),
            ManagedServingReadinessV1::RecoveredReady
        );
        assert!(
            !request
                .signing_transcript()
                .expect("request transcript")
                .as_bytes()
                .is_empty()
        );
        assert!(
            !response
                .signing_transcript()
                .expect("response transcript")
                .as_bytes()
                .is_empty()
        );
        assert_eq!(request.canonical_wire().len(), 508);
        assert_eq!(
            request.request_digest().as_bytes(),
            &[
                0xb0, 0xa3, 0x71, 0x46, 0xd0, 0x8b, 0xcc, 0x8a, 0xed, 0x0b, 0x21, 0x78, 0xe1, 0x7a,
                0x3f, 0xc6, 0x61, 0x4f, 0x79, 0xc9, 0x9f, 0x7b, 0xd3, 0x53, 0xd5, 0x27, 0xe6, 0x15,
                0x70, 0xed, 0xe3, 0x7e,
            ]
        );
        assert_eq!(response.canonical_wire().len(), 606);
        assert_eq!(
            response.response_digest().as_bytes(),
            &[
                0xcd, 0xb3, 0xce, 0xfa, 0x7e, 0x95, 0x79, 0xb7, 0xd3, 0x02, 0x8d, 0x0b, 0x3f, 0xb4,
                0x49, 0xa2, 0x65, 0xf5, 0x4c, 0x66, 0xe8, 0xbc, 0x65, 0xd0, 0x67, 0x6b, 0x8c, 0xd1,
                0x35, 0xd5, 0xf2, 0x18,
            ]
        );
    }

    #[test]
    fn v1_rejects_zero_observation_and_cross_request_response() {
        let request = request();
        assert_eq!(
            ManagedServingBootstrapFactsV1::try_recovered_ready(
                request.target(),
                request.expected_runtime_store_instance_id(),
                request.projection().clone(),
                7,
                11,
                ClockReading::new(
                    ClockDomainRef::from_bytes([0x3b; 16]),
                    ClockGeneration::try_new(13).expect("clock generation"),
                    MonotonicInstant::from_ticks(0),
                ),
            ),
            Err(ManagedServingBootstrapError::InvalidFacts)
        );
        let response = response(&request);
        let mut conflicting_wire = request.canonical_wire().to_vec();
        conflicting_wire[6..22].copy_from_slice(&[0x7f; 16]);
        let conflicting = ManagedServingBootstrapRequestV1::decode(&conflicting_wire)
            .expect("opaque signature permits strict decode before cryptographic verification");
        assert_eq!(
            response.validate_against_request(&conflicting, conflicting.channel()),
            Err(ManagedServingBootstrapError::CorrelationMismatch)
        );
    }

    #[test]
    fn v1_rejects_legacy_magic_oversize_and_zero_nonce() {
        let request = request();
        let response = response(&request);
        let mut legacy_request_magic = request.canonical_wire().to_vec();
        legacy_request_magic[..4].copy_from_slice(b"PXBR");
        assert_eq!(
            ManagedServingBootstrapRequestV1::decode(&legacy_request_magic),
            Err(ManagedServingBootstrapError::UnsupportedWire)
        );
        let mut legacy_response_magic = response.canonical_wire().to_vec();
        legacy_response_magic[..4].copy_from_slice(b"PXBS");
        assert_eq!(
            ManagedServingBootstrapResponseV1::decode(&legacy_response_magic),
            Err(ManagedServingBootstrapError::UnsupportedWire)
        );
        assert_eq!(
            ManagedServingBootstrapRequestV1::decode(&vec![
                0;
                MAX_MANAGED_SERVING_BOOTSTRAP_REQUEST_BYTES
                    + 1
            ]),
            Err(ManagedServingBootstrapError::FrameTooLarge)
        );
        let projection = projection();
        let target = projection.target();
        let zero_nonce = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([0x34; 16]),
            ApplyAuthKeyRef::from_bytes([0x35; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
            &[0; 32],
        )
        .expect("generic auth permits opaque zero nonce");
        assert_eq!(
            ManagedServingBootstrapRequestDraftV1::try_new(
                ManagedServingBootstrapRequestIdV1::try_from_bytes([0x37; 16]).expect("request id"),
                target,
                SourceScopeRef::from_bytes([0x38; 16]),
                [0x39; 32],
                projection,
                channel(target),
                zero_nonce,
            ),
            Err(ManagedServingBootstrapError::InvalidRequest)
        );
    }

    #[test]
    fn pxcc_describe_and_runtime_signed_pxdr_round_trip_and_verify() {
        let describe = control_describe();
        assert_eq!(&describe.canonical_wire()[..6], b"PXCC\0\x01");
        assert_eq!(describe.canonical_wire().len(), 493);
        assert_eq!(describe.kind(), RuntimeControlCarrierKindV1::Describe);
        assert!(describe.managed_serving_bootstrap_request().is_none());
        assert!(describe.reference_query_request().is_none());
        let decoded = RuntimeControlCarrierRequestV1::decode(describe.canonical_wire())
            .expect("strict PXCC Describe");
        assert_eq!(decoded, describe);
        let expected_carrier = describe.carrier().clone();
        let authenticated = describe
            .verify_controller_carrier(
                &expected_carrier,
                |principal, key, fingerprint, transcript, signature| {
                    assert_eq!(principal, expected_carrier.controller_principal());
                    assert_eq!(key, expected_carrier.controller_request_key());
                    assert_eq!(
                        fingerprint,
                        expected_carrier.controller_request_key_fingerprint()
                    );
                    assert!(!transcript.is_empty());
                    signature == [0x47; 64]
                },
            )
            .expect("Controller-authenticated Describe");
        assert_eq!(authenticated.kind(), RuntimeControlCarrierKindV1::Describe);

        let bootstrap = request();
        let serving = response(&bootstrap).facts().clone();
        let ready_facts = RuntimeControlDescribeReadyFactsV1::try_new(
            RuntimeControlDescribeReadyPhaseV1::LegacyReady,
            serving,
            bootstrap.channel(),
        )
        .expect("ready facts");
        assert_eq!(
            ready_facts.manifest_digest(),
            ready_facts.serving().projection().fields().manifest_digest
        );
        let response_auth = ManagedServingBootstrapResponseAuthClaimV1::try_new(
            ready_facts.channel(),
            expected_carrier.runtime_response_key(),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("Runtime response auth");
        let ready = RuntimeControlDescribeReadyResponseDraftV1::try_new(
            &describe,
            ready_facts,
            response_auth,
        )
        .expect("PXDR draft")
        .finalize(&[0x4e; 64])
        .expect("PXDR");
        assert_eq!(&ready.canonical_wire()[..6], b"PXDR\0\x01");
        assert_eq!(ready.canonical_wire().len(), 905);
        let decoded_ready = RuntimeControlDescribeReadyResponseV1::decode(ready.canonical_wire())
            .expect("strict PXDR");
        assert_eq!(decoded_ready, ready);
        let verified = ready
            .verify_runtime_response(
                &describe,
                &expected_carrier,
                |principal, key, fingerprint, transcript, signature| {
                    assert_eq!(principal, expected_carrier.runtime_principal());
                    assert_eq!(key, expected_carrier.runtime_response_key());
                    assert_eq!(
                        fingerprint,
                        expected_carrier.runtime_response_key_fingerprint()
                    );
                    assert!(!transcript.is_empty());
                    signature == [0x4e; 64]
                },
            )
            .expect("Runtime-authenticated PXDR");
        assert_eq!(verified.carrier(), &expected_carrier);
        assert_eq!(
            verified.facts().phase(),
            RuntimeControlDescribeReadyPhaseV1::LegacyReady
        );
    }

    #[test]
    fn pxcc_preserves_strict_pxfb_and_pxqr_and_rejects_cross_kind_bytes() {
        let bootstrap = request();
        let carrier = control_carrier(bootstrap.target());
        let managed = RuntimeControlCarrierRequestDraftV1::try_managed_serving_bootstrap(
            bootstrap.request_id(),
            carrier.clone(),
            bootstrap.clone(),
            control_auth(&[0x50; 32]),
        )
        .expect("managed carrier draft")
        .finalize(&[0x51; 64])
        .expect("managed carrier");
        assert_eq!(
            managed
                .managed_serving_bootstrap_request()
                .expect("PXFB payload")
                .canonical_wire(),
            bootstrap.canonical_wire()
        );
        assert_eq!(
            RuntimeControlCarrierRequestV1::decode(managed.canonical_wire())
                .expect("managed round trip"),
            managed
        );

        let query = reference_query(bootstrap.target());
        let query_carrier = RuntimeControlCarrierRequestDraftV1::try_reference_query(
            ManagedServingBootstrapRequestIdV1::try_from_bytes([0x52; 16])
                .expect("query carrier id"),
            carrier,
            query.clone(),
            control_auth(&[0x53; 32]),
        )
        .expect("query carrier draft")
        .finalize(&[0x54; 64])
        .expect("query carrier");
        assert_eq!(
            query_carrier
                .reference_query_request()
                .expect("PXQR payload")
                .canonical_wire(),
            query.canonical_wire()
        );
        assert_eq!(
            RuntimeControlCarrierRequestV1::decode(query_carrier.canonical_wire())
                .expect("query round trip"),
            query_carrier
        );

        let mut cross_kind = managed.canonical_wire().to_vec();
        cross_kind[6..8]
            .copy_from_slice(&(RuntimeControlCarrierKindV1::ReferenceQuery as u16).to_be_bytes());
        assert!(RuntimeControlCarrierRequestV1::decode(&cross_kind).is_err());
        let mut payload_tamper = managed.canonical_wire().to_vec();
        let payload_offset = CONTROL_CARRIER_REQUEST_FIXED_BYTES
            + managed.authentication().claim().nonce().len()
            + managed.carrier().canonical_wire().len();
        payload_tamper[payload_offset] ^= 1;
        assert_eq!(
            RuntimeControlCarrierRequestV1::decode(&payload_tamper),
            Err(ManagedServingBootstrapError::InvalidControlCarrierPayload)
        );
        let mut reserved = control_describe().canonical_wire().to_vec();
        reserved[8] = 1;
        assert_eq!(
            RuntimeControlCarrierRequestV1::decode(&reserved),
            Err(ManagedServingBootstrapError::NonCanonicalFrame)
        );
        let mut unknown = control_describe().canonical_wire().to_vec();
        unknown[6..8].copy_from_slice(&99_u16.to_be_bytes());
        assert_eq!(
            RuntimeControlCarrierRequestV1::decode(&unknown),
            Err(ManagedServingBootstrapError::UnsupportedControlCarrierKind)
        );
        let mut apply_magic = control_describe().canonical_wire().to_vec();
        apply_magic[..4].copy_from_slice(b"PXRC");
        assert_eq!(
            RuntimeControlCarrierRequestV1::decode(&apply_magic),
            Err(ManagedServingBootstrapError::UnsupportedWire)
        );
    }

    #[test]
    fn pxag_describe_and_pxah_descriptor_round_trip_verify_and_lock_lengths() {
        let target = projection().target();
        let carrier = control_carrier(target);
        let request = RuntimeAgentControlRequestDraftV1::try_describe_conversation_port(
            agent_control_fields(
                [0x90; 16],
                target,
                [0x39; 32],
                9,
                carrier.clone(),
                &[0x91; 32],
            ),
            Digest32::from_bytes([0x92; 32]),
            PrincipalRef::from_bytes([0x93; 16]),
        )
        .expect("PXAG Describe draft")
        .finalize(&[0x94; 64])
        .expect("PXAG Describe");
        assert_eq!(&request.canonical_wire()[..6], b"PXAG\0\x01");
        assert_eq!(request.canonical_wire().len(), 597);
        assert_eq!(
            RuntimeAgentControlRequestV1::decode(request.canonical_wire())
                .expect("strict PXAG Describe"),
            request
        );
        let mut controller_signature_tamper = request.canonical_wire().to_vec();
        *controller_signature_tamper
            .last_mut()
            .expect("Controller signature byte") ^= 1;
        let opaque_controller_signature =
            RuntimeAgentControlRequestV1::decode(&controller_signature_tamper)
                .expect("opaque Controller signature remains structurally canonical");
        assert_eq!(
            opaque_controller_signature
                .verify_controller_request(&carrier, |_, _, _, _, _| false)
                .err(),
            Some(ManagedServingBootstrapError::InvalidAgentControlAuthentication)
        );
        let authenticated = request
            .verify_controller_request(
                &carrier,
                |principal, key, fingerprint, transcript, signature| {
                    assert_eq!(principal, carrier.controller_principal());
                    assert_eq!(key, carrier.controller_request_key());
                    assert_eq!(fingerprint, carrier.controller_request_key_fingerprint());
                    assert!(!transcript.is_empty());
                    signature == [0x94; 64]
                },
            )
            .expect("Controller-authenticated PXAG");
        assert_eq!(
            authenticated.kind(),
            RuntimeAgentControlKindV1::DescribeConversationPort
        );

        let descriptor = b"PXAP\0\x01opaque";
        let receipt = RuntimeAgentControlReceiptDraftV1::try_conversation_port_descriptor(
            authenticated,
            descriptor,
            ManagedServiceGeneration::try_new(17).expect("Fabric generation"),
            ManagedServiceGeneration::try_new(19).expect("Agent generation"),
            agent_control_response_auth(&carrier),
        )
        .expect("PXAH descriptor draft")
        .finalize(&[0x95; 64])
        .expect("PXAH descriptor");
        assert_eq!(&receipt.canonical_wire()[..6], b"PXAH\0\x01");
        assert_eq!(receipt.canonical_wire().len(), 689);
        assert_eq!(
            receipt.conversation_port_descriptor(),
            Some(&descriptor[..])
        );
        assert_eq!(
            receipt
                .fabric_generation()
                .map(ManagedServiceGeneration::value),
            Some(17)
        );
        assert_eq!(
            receipt
                .agent_generation()
                .map(ManagedServiceGeneration::value),
            Some(19)
        );
        assert_eq!(
            receipt.expected_active_pxst_digest(),
            request.expected_active_pxst_digest()
        );
        assert_eq!(receipt.intended_client(), request.intended_client());
        let decoded = RuntimeAgentControlReceiptV1::decode(receipt.canonical_wire())
            .expect("strict PXAH descriptor");
        assert_eq!(decoded, receipt);
        decoded
            .verify_runtime_descriptor_receipt(
                &request,
                &carrier,
                |principal, key, fingerprint, transcript, signature| {
                    assert_eq!(principal, carrier.runtime_principal());
                    assert_eq!(key, carrier.runtime_response_key());
                    assert_eq!(fingerprint, carrier.runtime_response_key_fingerprint());
                    assert!(!transcript.is_empty());
                    signature == [0x95; 64]
                },
            )
            .expect("Runtime-authenticated PXAH descriptor");

        let mut runtime_signature_tamper = receipt.canonical_wire().to_vec();
        *runtime_signature_tamper
            .last_mut()
            .expect("Runtime signature byte") ^= 1;
        let opaque_runtime_signature =
            RuntimeAgentControlReceiptV1::decode(&runtime_signature_tamper)
                .expect("opaque Runtime signature remains structurally canonical");
        assert_eq!(
            opaque_runtime_signature
                .verify_runtime_descriptor_receipt(&request, &carrier, |_, _, _, _, _| false)
                .err(),
            Some(ManagedServingBootstrapError::InvalidAgentControlAuthentication)
        );

        let mut request_digest_tamper = receipt.canonical_wire().to_vec();
        request_digest_tamper[34] ^= 1;
        let wrong_request_digest = RuntimeAgentControlReceiptV1::decode(&request_digest_tamper)
            .expect("opaque signature permits correlation check after decode");
        assert_eq!(
            wrong_request_digest
                .validate_descriptor_against_request(&request)
                .err(),
            Some(ManagedServingBootstrapError::AgentControlCorrelationMismatch)
        );
        let mut request_nonce_tamper = receipt.canonical_wire().to_vec();
        request_nonce_tamper[AGENT_CONTROL_RECEIPT_FIXED_BYTES] ^= 1;
        let wrong_request_nonce = RuntimeAgentControlReceiptV1::decode(&request_nonce_tamper)
            .expect("opaque signature permits nonce correlation check after decode");
        assert_eq!(
            wrong_request_nonce
                .validate_descriptor_against_request(&request)
                .err(),
            Some(ManagedServingBootstrapError::AgentControlCorrelationMismatch)
        );

        let mut payload_tamper = receipt.canonical_wire().to_vec();
        let payload_offset = AGENT_CONTROL_RECEIPT_FIXED_BYTES
            + receipt.request_nonce().len()
            + receipt.carrier().canonical_wire().len();
        payload_tamper[payload_offset + 6] ^= 1;
        assert_eq!(
            RuntimeAgentControlReceiptV1::decode(&payload_tamper),
            Err(ManagedServingBootstrapError::InvalidAgentControlPayload)
        );
        let mut cross_kind = receipt.canonical_wire().to_vec();
        cross_kind[6..8]
            .copy_from_slice(&(RuntimeAgentControlKindV1::ApplyManagedFabric as u16).to_be_bytes());
        assert!(RuntimeAgentControlReceiptV1::decode(&cross_kind).is_err());
        let mut unknown = receipt.canonical_wire().to_vec();
        unknown[6..8].copy_from_slice(&99_u16.to_be_bytes());
        assert_eq!(
            RuntimeAgentControlReceiptV1::decode(&unknown),
            Err(ManagedServingBootstrapError::UnsupportedAgentControlKind)
        );
        let mut old_magic = receipt.canonical_wire().to_vec();
        old_magic[..4].copy_from_slice(b"PXDR");
        assert_eq!(
            RuntimeAgentControlReceiptV1::decode(&old_magic),
            Err(ManagedServingBootstrapError::UnsupportedWire)
        );
    }

    #[test]
    fn pxag_apply_kinds_preserve_exact_inner_bytes_and_pxah_revalidates_channel() {
        let (fabric_request, fabric_terminal, fabric_channel) = managed_fabric_apply_fixture();
        let fabric_epoch = fabric_terminal.facts().completion_runtime_host_epoch();
        let fabric_carrier = agent_control_carrier(
            fabric_request.target(),
            fabric_request.authentication().claim().principal(),
            fabric_request.authentication().claim().key(),
            fabric_channel.runtime_peer(),
            fabric_terminal.authentication_key(),
        );
        let fabric_outer = RuntimeAgentControlRequestDraftV1::try_apply_managed_fabric(
            agent_control_fields(
                *fabric_request.operation_id().as_bytes(),
                fabric_request.target(),
                fabric_request.expected_runtime_store_instance_id(),
                fabric_epoch,
                fabric_carrier.clone(),
                &[0xa1; 32],
            ),
            fabric_request.clone(),
        )
        .expect("PXAG PXAR6 draft")
        .finalize(&[0xa2; 64])
        .expect("PXAG PXAR6");
        assert_eq!(
            fabric_outer
                .managed_fabric_apply_request()
                .expect("PXAR6")
                .canonical_wire(),
            fabric_request.canonical_wire()
        );
        assert_eq!(
            fabric_outer.canonical_wire().len(),
            AGENT_CONTROL_REQUEST_FIXED_BYTES
                + 32
                + fabric_carrier.canonical_wire().len()
                + fabric_request.canonical_wire().len()
                + 64
        );
        let authenticated_fabric_outer = authenticate_agent_control_request(
            &fabric_outer,
            &fabric_carrier,
            &[0xa2; 64],
        );
        let fabric_pxah = RuntimeAgentControlReceiptDraftV1::try_managed_fabric_apply(
            authenticated_fabric_outer,
            fabric_terminal.clone(),
            fabric_channel,
            agent_control_response_auth(&fabric_carrier),
        )
        .expect("PXAH PXFT draft")
        .finalize(&[0xa3; 64])
        .expect("PXAH PXFT");
        assert_eq!(
            fabric_pxah
                .managed_fabric_receipt()
                .expect("PXFT")
                .canonical_wire(),
            fabric_terminal.canonical_wire()
        );
        assert_eq!(
            RuntimeAgentControlReceiptV1::decode(fabric_pxah.canonical_wire())
                .expect("PXAH PXFT round trip"),
            fabric_pxah
        );
        fabric_pxah
            .verify_runtime_apply_receipt(
                &fabric_outer,
                fabric_channel,
                &fabric_carrier,
                |_, _, _, transcript, signature| !transcript.is_empty() && signature == [0xa3; 64],
            )
            .expect("PXFT outer and inner correlation");
        let wrong_fabric_channel = ReferenceChannelBindingV1::try_new(
            fabric_outer.target(),
            fabric_channel.runtime_peer(),
            Digest32::from_bytes([0xcc; 32]),
            Digest32::from_bytes([0xcd; 32]),
        )
        .expect("wrong local channel");
        assert_eq!(
            fabric_pxah
                .validate_apply_against_request(&fabric_outer, wrong_fabric_channel)
                .err(),
            Some(ManagedServingBootstrapError::AgentControlCorrelationMismatch)
        );

        let (agent_request, agent_terminal, agent_channel) = managed_agent_apply_fixture();
        let agent_epoch = agent_terminal
            .facts()
            .evidence()
            .fields()
            .completion_runtime_host_epoch;
        let agent_carrier = agent_control_carrier(
            agent_request.target(),
            agent_request.authentication().claim().principal(),
            agent_request.authentication().claim().key(),
            agent_channel.runtime_peer(),
            agent_terminal.authentication_key(),
        );
        let agent_outer = RuntimeAgentControlRequestDraftV1::try_apply_managed_agent_stack(
            agent_control_fields(
                *agent_request.operation_id().as_bytes(),
                agent_request.target(),
                agent_request.expected_runtime_store_instance_id(),
                agent_epoch,
                agent_carrier.clone(),
                &[0xa4; 32],
            ),
            agent_request.clone(),
        )
        .expect("PXAG PXAR7 draft")
        .finalize(&[0xa5; 64])
        .expect("PXAG PXAR7");
        assert_eq!(
            agent_outer
                .managed_agent_stack_apply_request()
                .expect("PXAR7")
                .canonical_wire(),
            agent_request.canonical_wire()
        );
        let authenticated_agent_outer = authenticate_agent_control_request(
            &agent_outer,
            &agent_carrier,
            &[0xa5; 64],
        );
        let agent_pxah = RuntimeAgentControlReceiptDraftV1::try_managed_agent_stack_apply(
            authenticated_agent_outer,
            agent_terminal.clone(),
            agent_channel,
            agent_control_response_auth(&agent_carrier),
        )
        .expect("PXAH PXST draft")
        .finalize(&[0xa6; 64])
        .expect("PXAH PXST");
        assert_eq!(
            agent_pxah
                .managed_agent_stack_receipt()
                .expect("PXST")
                .canonical_wire(),
            agent_terminal.canonical_wire()
        );
        agent_pxah
            .verify_runtime_apply_receipt(
                &agent_outer,
                agent_channel,
                &agent_carrier,
                |_, _, _, transcript, signature| !transcript.is_empty() && signature == [0xa6; 64],
            )
            .expect("PXST outer and inner correlation");

        let mut cross_kind = fabric_outer.canonical_wire().to_vec();
        cross_kind[6..8].copy_from_slice(
            &(RuntimeAgentControlKindV1::ApplyManagedAgentStack as u16).to_be_bytes(),
        );
        assert!(RuntimeAgentControlRequestV1::decode(&cross_kind).is_err());
        let mut inner_tamper = agent_outer.canonical_wire().to_vec();
        let payload_offset = AGENT_CONTROL_REQUEST_FIXED_BYTES
            + agent_outer.authentication().claim().nonce().len()
            + agent_outer.carrier().canonical_wire().len();
        inner_tamper[payload_offset + 10] ^= 1;
        assert_eq!(
            RuntimeAgentControlRequestV1::decode(&inner_tamper),
            Err(ManagedServingBootstrapError::InvalidAgentControlPayload)
        );
    }

    #[test]
    fn agent_control_rejects_dual_identity_nonce_epoch_auth_and_descriptor_weakening() {
        let (inner, terminal, channel) = managed_agent_apply_fixture();
        let epoch = terminal
            .facts()
            .evidence()
            .fields()
            .completion_runtime_host_epoch;
        let carrier = agent_control_carrier(
            inner.target(),
            inner.authentication().claim().principal(),
            inner.authentication().claim().key(),
            channel.runtime_peer(),
            terminal.authentication_key(),
        );
        let wrong_id = RuntimeAgentControlRequestDraftV1::try_apply_managed_agent_stack(
            agent_control_fields(
                [0xfe; 16],
                inner.target(),
                inner.expected_runtime_store_instance_id(),
                epoch,
                carrier.clone(),
                &[0xb1; 32],
            ),
            inner.clone(),
        );
        assert_eq!(
            wrong_id.err(),
            Some(ManagedServingBootstrapError::InvalidAgentControlPayload)
        );
        let same_nonce = RuntimeAgentControlRequestDraftV1::try_apply_managed_agent_stack(
            agent_control_fields(
                *inner.operation_id().as_bytes(),
                inner.target(),
                inner.expected_runtime_store_instance_id(),
                epoch,
                carrier.clone(),
                inner.authentication().claim().nonce(),
            ),
            inner.clone(),
        );
        assert_eq!(
            same_nonce.err(),
            Some(ManagedServingBootstrapError::InvalidAgentControlPayload)
        );
        let outer = RuntimeAgentControlRequestDraftV1::try_apply_managed_agent_stack(
            agent_control_fields(
                *inner.operation_id().as_bytes(),
                inner.target(),
                inner.expected_runtime_store_instance_id(),
                epoch + 1,
                carrier.clone(),
                &[0xb2; 32],
            ),
            inner,
        )
        .expect("epoch is an outer expectation")
        .finalize(&[0xb3; 64])
        .expect("PXAG");
        let authenticated_outer =
            authenticate_agent_control_request(&outer, &carrier, &[0xb3; 64]);
        assert_eq!(
            RuntimeAgentControlReceiptDraftV1::try_managed_agent_stack_apply(
                authenticated_outer,
                terminal,
                channel,
                agent_control_response_auth(&carrier),
            )
            .err(),
            Some(ManagedServingBootstrapError::InvalidAgentControlReceipt)
        );

        let target = projection().target();
        let describe_carrier = control_carrier(target);
        let fields = || {
            agent_control_fields(
                [0xb4; 16],
                target,
                [0xb5; 32],
                23,
                describe_carrier.clone(),
                &[0xb6; 32],
            )
        };
        assert_eq!(
            RuntimeAgentControlRequestDraftV1::try_describe_conversation_port(
                fields(),
                Digest32::from_bytes([0; 32]),
                PrincipalRef::from_bytes([0xb7; 16]),
            )
            .err(),
            Some(ManagedServingBootstrapError::InvalidAgentControlPayload)
        );
        assert_eq!(
            RuntimeAgentControlRequestDraftV1::try_describe_conversation_port(
                fields(),
                Digest32::from_bytes([0xb8; 32]),
                PrincipalRef::from_bytes([0; 16]),
            )
            .err(),
            Some(ManagedServingBootstrapError::InvalidAgentControlPayload)
        );
        let describe = RuntimeAgentControlRequestDraftV1::try_describe_conversation_port(
            fields(),
            Digest32::from_bytes([0xb8; 32]),
            PrincipalRef::from_bytes([0xb7; 16]),
        )
        .expect("Describe")
        .finalize(&[0xb9; 64])
        .expect("PXAG Describe");
        let authenticated_describe = authenticate_agent_control_request(
            &describe,
            &describe_carrier,
            &[0xb9; 64],
        );
        assert_eq!(
            RuntimeAgentControlReceiptDraftV1::try_conversation_port_descriptor(
                authenticated_describe,
                &vec![0; MAX_RUNTIME_AGENT_PORT_DESCRIPTOR_BYTES + 1],
                ManagedServiceGeneration::try_new(1).expect("generation"),
                ManagedServiceGeneration::try_new(2).expect("generation"),
                agent_control_response_auth(&describe_carrier),
            )
            .err(),
            Some(ManagedServingBootstrapError::InvalidAgentControlReceipt)
        );
        assert_eq!(
            RuntimeAgentControlResponseAuthClaimV1::try_new(
                &describe_carrier,
                ApplyAuthKeyRef::from_bytes([0xff; 16]),
                ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
                1,
            ),
            Err(ManagedServingBootstrapError::InvalidAgentControlAuthentication)
        );
    }
}
