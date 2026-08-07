//! Authenticated read-only observation of one recovered managed Runtime serving epoch.
//!
//! PXFB/PXFR v1 is additive to, and semantically distinct from, the legacy
//! PXBR/PXBS compatibility bootstrap. It proves current successor projection,
//! journal, process epoch, clock generation, and live channel facts without
//! mutating Runtime state. Only a recovered-ready response exists in v1.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant};

use crate::managed_fabric_plan::{
    MANAGED_FABRIC_PROJECTION_BYTES, ManagedFabricManifestProjectionV1, ManagedFabricPlanError,
};
use crate::provenance::SourceScopeRef;
use crate::reference_control::{ReferenceChannelBindingV1, ReferenceControlError};
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
const REQUEST_FIXED_BYTES: usize = 226;
const RESPONSE_FIXED_BYTES: usize = 324;

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

/// Strict PXFB/PXFR construction and decoding failures.
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

    use super::*;

    const FABRIC_FIXTURE: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_fabric_successor_v1.json");

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
}
