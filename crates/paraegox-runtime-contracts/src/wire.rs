//! Canonical B2 apply envelope and request-authentication transcript.
//!
//! The encoding is independent of Rust layout and serializer defaults. A fixed
//! magic and version are followed by an ordered sequence of big-endian TLV
//! fields. Unknown, missing, duplicate, out-of-order, malformed, and oversized
//! inputs are rejected before an envelope value is constructed.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};

use crate::apply::{
    ApplyContractError, ApplyOperationId, ExpectedActive, MAX_TENURE_NONCE_BYTES,
    MAX_TENURE_SIGNATURE_BYTES, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
    RuntimeApplyControl, RuntimeApplyControlCommitment, TenureAuthorityRef, TenureKeyRef,
    TenureProofAlgorithm, TenureProofAuthority, TenureProofError, WriterTenureClaim,
    WriterTenureProof,
};
use crate::provenance::{
    PlanProvenance, RUNTIME_SLICE_HEADER_VERSION, RuntimeSliceCommitment, RuntimeSliceHeader,
    SourcePlanDigest, SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest,
    TargetSliceDigest,
};
use crate::temporal::{ApplyTemporalConstraint, TemporalConstraintId, TemporalContractError};

const APPLY_ENVELOPE_MAGIC: &[u8] = b"ParaEGOX\0runtime-apply-envelope";
const APPLY_AUTH_SIGNING_MAGIC: &[u8] = b"ParaEGOX\0canonical-signing-transcript";
const APPLY_AUTH_SIGNING_DOMAIN: &[u8] = b"paraegox.runtime.apply-envelope-auth.signing.v1";
const APPLY_ENVELOPE_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.apply-envelope.request.sha256.v1";
const APPLY_ENVELOPE_FIELD_COUNT: u16 = 37;
const APPLY_AUTH_SIGNING_FIELD_COUNT: u16 = APPLY_ENVELOPE_FIELD_COUNT - 1;
const TLV_HEADER_BYTES: usize = 6;

/// The first canonical B2 apply-envelope protocol version.
pub const RUNTIME_APPLY_ENVELOPE_VERSION: u16 = 1;
/// Canonical version of the request-authentication signing transcript.
pub const APPLY_REQUEST_SIGNING_TRANSCRIPT_VERSION: u16 = 1;
/// Maximum canonical frame size accepted before any field parsing.
pub const MAX_RUNTIME_APPLY_ENVELOPE_BYTES: usize = 4096;
/// Maximum request-authentication nonce size.
pub const MAX_APPLY_AUTH_NONCE_BYTES: usize = 64;
/// Maximum request-authentication signature size.
pub const MAX_APPLY_AUTH_SIGNATURE_BYTES: usize = 512;

/// Selects one request-authentication verification key independently of tenure keys.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApplyAuthKeyRef([u8; 16]);

impl ApplyAuthKeyRef {
    /// Creates an opaque request-authentication key reference.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical key-reference bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Stable registry value for a request-authentication signature algorithm.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApplyAuthAlgorithm(u16);

impl ApplyAuthAlgorithm {
    /// Creates a nonzero algorithm registry value.
    pub const fn try_new(value: u16) -> Result<Self, ApplyAuthError> {
        if value == 0 {
            return Err(ApplyAuthError::InvalidAlgorithm);
        }
        Ok(Self(value))
    }

    /// Returns the algorithm registry value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Signature-independent claim covered by request authentication.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApplyRequestAuthClaim {
    principal: PrincipalRef,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
    nonce: Box<[u8]>,
}

impl ApplyRequestAuthClaim {
    /// Creates a bounded authentication claim with a nonzero algorithm version.
    pub fn try_new(
        principal: PrincipalRef,
        key: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
        nonce: &[u8],
    ) -> Result<Self, ApplyAuthError> {
        if algorithm_version == 0 {
            return Err(ApplyAuthError::InvalidAlgorithmVersion);
        }
        validate_auth_nonce(nonce)?;
        Ok(Self {
            principal,
            key,
            algorithm,
            algorithm_version,
            nonce: nonce.into(),
        })
    }

    /// Returns the principal asserted by the request signer.
    #[must_use]
    pub const fn principal(&self) -> PrincipalRef {
        self.principal
    }

    /// Returns the selected request-authentication key.
    #[must_use]
    pub const fn key(&self) -> ApplyAuthKeyRef {
        self.key
    }

    /// Returns the request-authentication algorithm selector.
    #[must_use]
    pub const fn algorithm(&self) -> ApplyAuthAlgorithm {
        self.algorithm
    }

    /// Returns the selected algorithm version.
    #[must_use]
    pub const fn algorithm_version(&self) -> u16 {
        self.algorithm_version
    }

    /// Returns the bounded request-authentication nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
}

/// Complete request-authentication claim and opaque signature value.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApplyRequestAuthentication {
    claim: ApplyRequestAuthClaim,
    signature: Box<[u8]>,
}

impl ApplyRequestAuthentication {
    /// Pairs a claim with a bounded signature value.
    pub fn try_new(claim: ApplyRequestAuthClaim, signature: &[u8]) -> Result<Self, ApplyAuthError> {
        validate_auth_signature(signature)?;
        Ok(Self {
            claim,
            signature: signature.into(),
        })
    }

    /// Returns the signature-independent authentication claim.
    #[must_use]
    pub const fn claim(&self) -> &ApplyRequestAuthClaim {
        &self.claim
    }

    /// Returns the opaque signature bytes interpreted by the owning verifier.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Canonical bytes signed by the request principal.
///
/// The transcript has a domain and version independent of tenure signing. It
/// uses the same ordered fields as the canonical envelope through the auth
/// nonce, including all B1 derived digests and the tenure-proof signature and
/// fingerprint. Only the request-authentication signature field is excluded.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApplyRequestSigningTranscript(Box<[u8]>);

impl ApplyRequestSigningTranscript {
    /// Returns the exact canonical bytes supplied to the signature algorithm.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Producer-side value used to obtain a signing transcript before finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyEnvelopeDraft {
    control_commitment: RuntimeApplyControlCommitment,
    temporal: ApplyTemporalConstraint,
    auth_claim: ApplyRequestAuthClaim,
}

impl RuntimeApplyEnvelopeDraft {
    /// Builds a validated signature-independent envelope draft.
    pub fn try_new(
        control_commitment: RuntimeApplyControlCommitment,
        temporal: ApplyTemporalConstraint,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, EnvelopeContractError> {
        control_commitment.validate()?;
        Ok(Self {
            control_commitment,
            temporal,
            auth_claim,
        })
    }

    /// Returns the B1 slice and apply-control commitment.
    #[must_use]
    pub const fn control_commitment(&self) -> &RuntimeApplyControlCommitment {
        &self.control_commitment
    }

    /// Returns the authenticated temporal constraint.
    #[must_use]
    pub const fn temporal(&self) -> ApplyTemporalConstraint {
        self.temporal
    }

    /// Returns the signature-independent request-authentication claim.
    #[must_use]
    pub const fn auth_claim(&self) -> &ApplyRequestAuthClaim {
        &self.auth_claim
    }

    /// Builds the independent request-authentication signing transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ApplyRequestSigningTranscript, EnvelopeContractError> {
        build_apply_signing_transcript(&self.control_commitment, self.temporal, &self.auth_claim)
    }

    /// Finalizes the envelope with the signature produced over `signing_transcript`.
    pub fn finalize(self, signature: &[u8]) -> Result<RuntimeApplyEnvelope, EnvelopeContractError> {
        let authentication = ApplyRequestAuthentication::try_new(self.auth_claim, signature)?;
        RuntimeApplyEnvelope::try_new(self.control_commitment, self.temporal, authentication)
    }
}

/// Canonical signed B2 envelope consumed by Runtime authentication admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyEnvelope {
    control_commitment: RuntimeApplyControlCommitment,
    temporal: ApplyTemporalConstraint,
    authentication: ApplyRequestAuthentication,
    canonical_wire: Box<[u8]>,
    request_digest: Digest32,
}

impl RuntimeApplyEnvelope {
    /// Builds and canonically encodes a complete signed envelope.
    pub fn try_new(
        control_commitment: RuntimeApplyControlCommitment,
        temporal: ApplyTemporalConstraint,
        authentication: ApplyRequestAuthentication,
    ) -> Result<Self, EnvelopeContractError> {
        control_commitment.validate()?;
        let canonical_wire =
            build_apply_envelope_wire(&control_commitment, temporal, &authentication)?;
        if canonical_wire.len() > MAX_RUNTIME_APPLY_ENVELOPE_BYTES {
            return Err(EnvelopeContractError::FrameTooLarge);
        }
        let mut digest_builder = Digest32Builder::try_new(APPLY_ENVELOPE_REQUEST_DIGEST_DOMAIN)?;
        digest_builder.field_bytes(&canonical_wire)?;
        let request_digest = digest_builder.finish();

        Ok(Self {
            control_commitment,
            temporal,
            authentication,
            canonical_wire: canonical_wire.into_boxed_slice(),
            request_digest,
        })
    }

    /// Strictly decodes and revalidates a canonical signed envelope.
    pub fn decode(frame: &[u8]) -> Result<Self, WireError> {
        decode_apply_envelope(frame)
    }

    /// Returns the B1 slice and apply-control commitment.
    #[must_use]
    pub const fn control_commitment(&self) -> &RuntimeApplyControlCommitment {
        &self.control_commitment
    }

    /// Returns the authenticated temporal constraint.
    #[must_use]
    pub const fn temporal(&self) -> ApplyTemporalConstraint {
        self.temporal
    }

    /// Returns the complete request-authentication value.
    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        &self.authentication
    }

    /// Returns the exact canonical signed wire bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the canonical digest of the complete signed wire, including signature.
    #[must_use]
    pub const fn request_digest(&self) -> &Digest32 {
        &self.request_digest
    }

    /// Revalidates the B1 commitments, canonical frame, and complete request digest.
    pub fn validate(&self) -> Result<(), EnvelopeContractError> {
        self.control_commitment.validate()?;
        let canonical_wire = build_apply_envelope_wire(
            &self.control_commitment,
            self.temporal,
            &self.authentication,
        )?;
        if canonical_wire.as_slice() != self.canonical_wire() {
            return Err(EnvelopeContractError::CanonicalWireMismatch);
        }
        let mut digest_builder = Digest32Builder::try_new(APPLY_ENVELOPE_REQUEST_DIGEST_DOMAIN)?;
        digest_builder.field_bytes(&canonical_wire)?;
        if digest_builder.finish() != self.request_digest {
            return Err(EnvelopeContractError::RequestDigestMismatch);
        }
        Ok(())
    }

    /// Rebuilds the signature-independent request-authentication transcript.
    pub fn signing_transcript(
        &self,
    ) -> Result<ApplyRequestSigningTranscript, EnvelopeContractError> {
        build_apply_signing_transcript(
            &self.control_commitment,
            self.temporal,
            self.authentication.claim(),
        )
    }
}

/// Fail-closed construction errors for request authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyAuthError {
    /// Algorithm registry value zero is reserved.
    InvalidAlgorithm,
    /// Algorithm version zero is reserved.
    InvalidAlgorithmVersion,
    /// Authentication requires a nonce.
    EmptyNonce,
    /// Authentication nonce exceeds its protocol bound.
    NonceTooLong,
    /// Authentication requires a signature.
    EmptySignature,
    /// Authentication signature exceeds its protocol bound.
    SignatureTooLong,
}

impl fmt::Display for ApplyAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAlgorithm => formatter.write_str("invalid apply-auth algorithm"),
            Self::InvalidAlgorithmVersion => {
                formatter.write_str("invalid apply-auth algorithm version")
            }
            Self::EmptyNonce => formatter.write_str("apply-auth nonce must not be empty"),
            Self::NonceTooLong => formatter.write_str("apply-auth nonce is too long"),
            Self::EmptySignature => formatter.write_str("apply-auth signature must not be empty"),
            Self::SignatureTooLong => formatter.write_str("apply-auth signature is too long"),
        }
    }
}

impl std::error::Error for ApplyAuthError {}

/// Construction failures before a canonical envelope can be admitted to wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeContractError {
    /// B1 control commitment validation failed.
    Apply(ApplyContractError),
    /// Request-authentication construction failed.
    Authentication(ApplyAuthError),
    /// Canonical digest construction failed.
    Digest(DigestBuildError),
    /// The canonical envelope exceeded its fixed protocol bound.
    FrameTooLarge,
    /// Stored canonical wire does not match the envelope fields.
    CanonicalWireMismatch,
    /// Stored complete-request digest does not match the signed wire.
    RequestDigestMismatch,
}

impl From<ApplyContractError> for EnvelopeContractError {
    fn from(value: ApplyContractError) -> Self {
        Self::Apply(value)
    }
}

impl From<ApplyAuthError> for EnvelopeContractError {
    fn from(value: ApplyAuthError) -> Self {
        Self::Authentication(value)
    }
}

impl From<DigestBuildError> for EnvelopeContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for EnvelopeContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Apply(error) => write!(formatter, "apply commitment rejected: {error}"),
            Self::Authentication(error) => write!(formatter, "request auth rejected: {error}"),
            Self::Digest(error) => write!(formatter, "canonical digest failed: {error}"),
            Self::FrameTooLarge => formatter.write_str("canonical apply envelope is too large"),
            Self::CanonicalWireMismatch => {
                formatter.write_str("canonical apply wire does not match envelope fields")
            }
            Self::RequestDigestMismatch => {
                formatter.write_str("apply request digest does not match signed wire")
            }
        }
    }
}

impl std::error::Error for EnvelopeContractError {}

/// Stable machine-readable reason for canonical wire rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum WireErrorCode {
    /// The frame exceeds the pre-parse size bound.
    FrameTooLarge = 1,
    /// The frame ended before a declared value was complete.
    Truncated = 2,
    /// The fixed protocol magic did not match.
    InvalidMagic = 3,
    /// The frame or an embedded contract version is unsupported.
    UnsupportedVersion = 4,
    /// A field tag is not defined by this protocol version.
    UnknownField = 5,
    /// One or more required fields are absent.
    MissingField = 6,
    /// A field tag appeared more than once.
    DuplicateField = 7,
    /// A known field did not appear in canonical order.
    OutOfOrderField = 8,
    /// A field length violated its fixed or bounded contract.
    InvalidFieldLength = 9,
    /// A structurally sized field carried an invalid semantic value.
    InvalidFieldValue = 10,
    /// A carried B1 derived digest did not match recomputation.
    DerivedDigestMismatch = 11,
    /// Re-encoding decoded values did not reproduce the exact input frame.
    NonCanonicalFrame = 12,
    /// Bytes remained after the declared field sequence.
    TrailingBytes = 13,
}

/// Canonical wire rejection with an optional offending TLV tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireError {
    code: WireErrorCode,
    field_tag: Option<u16>,
}

impl WireError {
    const fn new(code: WireErrorCode) -> Self {
        Self {
            code,
            field_tag: None,
        }
    }

    const fn at(code: WireErrorCode, field_tag: u16) -> Self {
        Self {
            code,
            field_tag: Some(field_tag),
        }
    }

    /// Returns the stable wire reason code.
    #[must_use]
    pub const fn code(self) -> WireErrorCode {
        self.code
    }

    /// Returns the offending field tag when rejection is field-specific.
    #[must_use]
    pub const fn field_tag(self) -> Option<u16> {
        self.field_tag
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(tag) = self.field_tag {
            write!(
                formatter,
                "apply envelope wire error {:?} at field {tag}",
                self.code
            )
        } else {
            write!(formatter, "apply envelope wire error {:?}", self.code)
        }
    }
}

impl std::error::Error for WireError {}

fn validate_auth_nonce(nonce: &[u8]) -> Result<(), ApplyAuthError> {
    if nonce.is_empty() {
        return Err(ApplyAuthError::EmptyNonce);
    }
    if nonce.len() > MAX_APPLY_AUTH_NONCE_BYTES {
        return Err(ApplyAuthError::NonceTooLong);
    }
    Ok(())
}

fn validate_auth_signature(signature: &[u8]) -> Result<(), ApplyAuthError> {
    if signature.is_empty() {
        return Err(ApplyAuthError::EmptySignature);
    }
    if signature.len() > MAX_APPLY_AUTH_SIGNATURE_BYTES {
        return Err(ApplyAuthError::SignatureTooLong);
    }
    Ok(())
}

fn build_apply_signing_transcript(
    control_commitment: &RuntimeApplyControlCommitment,
    temporal: ApplyTemporalConstraint,
    auth_claim: &ApplyRequestAuthClaim,
) -> Result<ApplyRequestSigningTranscript, EnvelopeContractError> {
    let mut encoded = Vec::with_capacity(MAX_RUNTIME_APPLY_ENVELOPE_BYTES);
    encoded.extend_from_slice(APPLY_AUTH_SIGNING_MAGIC);
    encoded.extend_from_slice(&APPLY_REQUEST_SIGNING_TRANSCRIPT_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(APPLY_AUTH_SIGNING_DOMAIN.len() as u16).to_be_bytes());
    encoded.extend_from_slice(APPLY_AUTH_SIGNING_DOMAIN);
    encoded.extend_from_slice(&APPLY_AUTH_SIGNING_FIELD_COUNT.to_be_bytes());
    append_apply_fields(&mut encoded, control_commitment, temporal, auth_claim, None)?;
    if encoded.len() > MAX_RUNTIME_APPLY_ENVELOPE_BYTES {
        return Err(EnvelopeContractError::FrameTooLarge);
    }
    Ok(ApplyRequestSigningTranscript(encoded.into_boxed_slice()))
}

fn build_apply_envelope_wire(
    control_commitment: &RuntimeApplyControlCommitment,
    temporal: ApplyTemporalConstraint,
    authentication: &ApplyRequestAuthentication,
) -> Result<Vec<u8>, EnvelopeContractError> {
    let mut encoded = Vec::with_capacity(MAX_RUNTIME_APPLY_ENVELOPE_BYTES);
    encoded.extend_from_slice(APPLY_ENVELOPE_MAGIC);
    encoded.extend_from_slice(&RUNTIME_APPLY_ENVELOPE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&APPLY_ENVELOPE_FIELD_COUNT.to_be_bytes());
    append_apply_fields(
        &mut encoded,
        control_commitment,
        temporal,
        authentication.claim(),
        Some(authentication.signature()),
    )?;
    Ok(encoded)
}

fn append_apply_fields(
    encoded: &mut Vec<u8>,
    control_commitment: &RuntimeApplyControlCommitment,
    temporal: ApplyTemporalConstraint,
    auth_claim: &ApplyRequestAuthClaim,
    auth_signature: Option<&[u8]>,
) -> Result<(), EnvelopeContractError> {
    let slice = control_commitment.slice();
    let header = slice.header();
    let provenance = header.provenance();
    let control = control_commitment.control();
    let writer = control.writer_context();
    let proof = writer.proof();
    let proof_authority = proof.authority();
    let proof_claim = proof.claim();
    let proof_envelope_digest = proof.envelope_digest()?;
    let (expected_tag, expected_digest) = match control.expected_active() {
        ExpectedActive::None => (0_u16, Digest32::from_bytes([0; 32])),
        ExpectedActive::Exact(digest) => (1_u16, *digest.value()),
    };

    append_tlv(encoded, 1, &header.contract_version().to_be_bytes());
    append_tlv(encoded, 2, header.target().as_bytes());
    append_tlv(encoded, 3, provenance.source_scope().as_bytes());
    append_tlv(encoded, 4, provenance.source_plan().as_bytes());
    append_tlv(
        encoded,
        5,
        &provenance.source_revision().value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        6,
        provenance.source_plan_digest().value().as_bytes(),
    );
    append_tlv(encoded, 7, header.assignment_digest().value().as_bytes());
    append_tlv(encoded, 8, slice.target_slice_digest().value().as_bytes());
    append_tlv(encoded, 9, writer.writer().as_bytes());
    append_tlv(encoded, 10, &writer.epoch().value().to_be_bytes());
    append_tlv(encoded, 11, proof_authority.authority().as_bytes());
    append_tlv(encoded, 12, proof_authority.key().as_bytes());
    append_tlv(
        encoded,
        13,
        &proof_authority.algorithm().value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        14,
        &proof_authority.algorithm_version().to_be_bytes(),
    );
    append_tlv(encoded, 15, proof_claim.source_scope().as_bytes());
    append_tlv(encoded, 16, proof_claim.writer().as_bytes());
    append_tlv(encoded, 17, &proof_claim.epoch().value().to_be_bytes());
    append_tlv(
        encoded,
        18,
        &proof_claim.supersedes_through_epoch().value().to_be_bytes(),
    );
    append_tlv(encoded, 19, proof.nonce());
    append_tlv(encoded, 20, proof.signature());
    append_tlv(encoded, 21, proof_envelope_digest.as_bytes());
    append_tlv(encoded, 22, &expected_tag.to_be_bytes());
    append_tlv(encoded, 23, expected_digest.as_bytes());
    append_tlv(encoded, 24, control.operation_id().as_bytes());
    append_tlv(
        encoded,
        25,
        control_commitment.commitment_digest().as_bytes(),
    );
    append_tlv(encoded, 26, &temporal.version().to_be_bytes());
    append_tlv(encoded, 27, temporal.constraint_id().as_bytes());
    append_tlv(encoded, 28, temporal.target_clock_domain().as_bytes());
    append_tlv(
        encoded,
        29,
        &temporal.target_clock_generation().value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        30,
        &temporal.original_budget().value().to_be_bytes(),
    );
    append_tlv(
        encoded,
        31,
        &temporal.remaining_budget().value().to_be_bytes(),
    );
    append_tlv(encoded, 32, auth_claim.principal().as_bytes());
    append_tlv(encoded, 33, auth_claim.key().as_bytes());
    append_tlv(encoded, 34, &auth_claim.algorithm().value().to_be_bytes());
    append_tlv(encoded, 35, &auth_claim.algorithm_version().to_be_bytes());
    append_tlv(encoded, 36, auth_claim.nonce());
    if let Some(signature) = auth_signature {
        append_tlv(encoded, 37, signature);
    }
    Ok(())
}

fn append_tlv(encoded: &mut Vec<u8>, tag: u16, value: &[u8]) {
    encoded.extend_from_slice(&tag.to_be_bytes());
    encoded.extend_from_slice(&(value.len() as u32).to_be_bytes());
    encoded.extend_from_slice(value);
}

struct ParsedFields<'a> {
    values: Vec<&'a [u8]>,
}

impl ParsedFields<'_> {
    fn get(&self, tag: u16) -> &[u8] {
        self.values[usize::from(tag - 1)]
    }
}

fn parse_apply_frame(frame: &[u8]) -> Result<ParsedFields<'_>, WireError> {
    if frame.len() > MAX_RUNTIME_APPLY_ENVELOPE_BYTES {
        return Err(WireError::new(WireErrorCode::FrameTooLarge));
    }
    let header_length = APPLY_ENVELOPE_MAGIC.len() + 4;
    if frame.len() < header_length {
        return Err(WireError::new(WireErrorCode::Truncated));
    }
    if &frame[..APPLY_ENVELOPE_MAGIC.len()] != APPLY_ENVELOPE_MAGIC {
        return Err(WireError::new(WireErrorCode::InvalidMagic));
    }

    let mut cursor = APPLY_ENVELOPE_MAGIC.len();
    let version = read_u16(&frame[cursor..cursor + 2]);
    cursor += 2;
    if version != RUNTIME_APPLY_ENVELOPE_VERSION {
        return Err(WireError::new(WireErrorCode::UnsupportedVersion));
    }
    let declared_count = read_u16(&frame[cursor..cursor + 2]);
    cursor += 2;

    let mut values =
        Vec::with_capacity(usize::from(declared_count.min(APPLY_ENVELOPE_FIELD_COUNT)));
    for index in 0..declared_count {
        let expected_tag = index + 1;
        let Some(tlv_header_end) = cursor.checked_add(TLV_HEADER_BYTES) else {
            return Err(WireError::new(WireErrorCode::Truncated));
        };
        if tlv_header_end > frame.len() {
            return Err(WireError::new(WireErrorCode::Truncated));
        }
        let tag = read_u16(&frame[cursor..cursor + 2]);
        let value_length = read_u32(&frame[cursor + 2..tlv_header_end]) as usize;
        cursor = tlv_header_end;

        if tag == 0 || tag > APPLY_ENVELOPE_FIELD_COUNT {
            return Err(WireError::at(WireErrorCode::UnknownField, tag));
        }
        if tag < expected_tag {
            return Err(WireError::at(WireErrorCode::DuplicateField, tag));
        }
        if tag > expected_tag {
            return Err(WireError::at(WireErrorCode::OutOfOrderField, tag));
        }
        if !valid_field_length(tag, value_length) {
            return Err(WireError::at(WireErrorCode::InvalidFieldLength, tag));
        }

        let Some(value_end) = cursor.checked_add(value_length) else {
            return Err(WireError::at(WireErrorCode::Truncated, tag));
        };
        if value_end > frame.len() {
            return Err(WireError::at(WireErrorCode::Truncated, tag));
        }
        values.push(&frame[cursor..value_end]);
        cursor = value_end;
    }

    if declared_count < APPLY_ENVELOPE_FIELD_COUNT {
        return Err(WireError::at(
            WireErrorCode::MissingField,
            declared_count + 1,
        ));
    }
    if cursor != frame.len() {
        return Err(WireError::new(WireErrorCode::TrailingBytes));
    }
    Ok(ParsedFields { values })
}

fn valid_field_length(tag: u16, length: usize) -> bool {
    match tag {
        1 | 13 | 14 | 22 | 26 | 34 | 35 => length == 2,
        5 | 10 | 17 | 18 | 29 | 30 | 31 => length == 8,
        2 | 3 | 4 | 9 | 11 | 12 | 15 | 16 | 24 | 27 | 28 | 32 | 33 => length == 16,
        6 | 7 | 8 | 21 | 23 | 25 => length == 32,
        19 => (1..=MAX_TENURE_NONCE_BYTES).contains(&length),
        20 => (1..=MAX_TENURE_SIGNATURE_BYTES).contains(&length),
        36 => (1..=MAX_APPLY_AUTH_NONCE_BYTES).contains(&length),
        37 => (1..=MAX_APPLY_AUTH_SIGNATURE_BYTES).contains(&length),
        _ => false,
    }
}

fn decode_apply_envelope(frame: &[u8]) -> Result<RuntimeApplyEnvelope, WireError> {
    let fields = parse_apply_frame(frame)?;

    if field_u16(&fields, 1) != RUNTIME_SLICE_HEADER_VERSION {
        return Err(WireError::at(WireErrorCode::UnsupportedVersion, 1));
    }
    let provenance = PlanProvenance::new(
        SourceScopeRef::from_bytes(field_array(&fields, 3)),
        SourcePlanRef::from_bytes(field_array(&fields, 4)),
        SourcePlanRevision::new(field_u64(&fields, 5)),
        SourcePlanDigest::new(Digest32::from_bytes(field_array(&fields, 6))),
    );
    let header = RuntimeSliceHeader::new(
        RuntimeHostId::from_bytes(field_array(&fields, 2)),
        provenance,
        TargetAssignmentDigest::new(Digest32::from_bytes(field_array(&fields, 7))),
    );
    let slice = RuntimeSliceCommitment::try_new(header)
        .map_err(|_| WireError::at(WireErrorCode::InvalidFieldValue, 8))?;
    if slice.target_slice_digest().value().as_bytes() != fields.get(8) {
        return Err(WireError::at(WireErrorCode::DerivedDigestMismatch, 8));
    }

    let tenure_algorithm =
        TenureProofAlgorithm::try_new(field_u16(&fields, 13)).map_err(tenure_wire_error)?;
    let tenure_authority = TenureProofAuthority::try_new(
        TenureAuthorityRef::from_bytes(field_array(&fields, 11)),
        TenureKeyRef::from_bytes(field_array(&fields, 12)),
        tenure_algorithm,
        field_u16(&fields, 14),
    )
    .map_err(tenure_wire_error)?;
    let tenure_claim = WriterTenureClaim::try_new(
        SourceScopeRef::from_bytes(field_array(&fields, 15)),
        PlanWriterRef::from_bytes(field_array(&fields, 16)),
        PlanWriterEpoch::new(field_u64(&fields, 17)),
        PlanWriterEpoch::new(field_u64(&fields, 18)),
    )
    .map_err(tenure_wire_error)?;
    let proof = WriterTenureProof::try_new(
        tenure_authority,
        tenure_claim,
        fields.get(19),
        fields.get(20),
    )
    .map_err(tenure_wire_error)?;
    let proof_envelope_digest = proof
        .envelope_digest()
        .map_err(|_| WireError::at(WireErrorCode::InvalidFieldValue, 21))?;
    if proof_envelope_digest.as_bytes() != fields.get(21) {
        return Err(WireError::at(WireErrorCode::DerivedDigestMismatch, 21));
    }
    let writer_context = PlanWriterContext::try_new(
        PlanWriterRef::from_bytes(field_array(&fields, 9)),
        PlanWriterEpoch::new(field_u64(&fields, 10)),
        proof,
    )
    .map_err(apply_wire_error)?;

    let expected_digest = Digest32::from_bytes(field_array(&fields, 23));
    let expected_active = match field_u16(&fields, 22) {
        0 if expected_digest.as_bytes() == &[0; 32] => ExpectedActive::None,
        1 => ExpectedActive::Exact(TargetSliceDigest::new(expected_digest)),
        _ => return Err(WireError::at(WireErrorCode::InvalidFieldValue, 22)),
    };
    let control = RuntimeApplyControl::new(
        writer_context,
        expected_active,
        ApplyOperationId::from_bytes(field_array(&fields, 24)),
    );
    let control_commitment =
        RuntimeApplyControlCommitment::try_new(slice, control).map_err(apply_wire_error)?;
    if control_commitment.commitment_digest().as_bytes() != fields.get(25) {
        return Err(WireError::at(WireErrorCode::DerivedDigestMismatch, 25));
    }

    let clock_generation = ClockGeneration::try_new(field_u64(&fields, 29))
        .map_err(|_| WireError::at(WireErrorCode::InvalidFieldValue, 29))?;
    let temporal = ApplyTemporalConstraint::try_from_parts(
        field_u16(&fields, 26),
        TemporalConstraintId::from_bytes(field_array(&fields, 27)),
        ClockDomainRef::from_bytes(field_array(&fields, 28)),
        clock_generation,
        BoundedDuration::from_nanos(field_u64(&fields, 30)),
        BoundedDuration::from_nanos(field_u64(&fields, 31)),
    )
    .map_err(temporal_wire_error)?;

    let auth_algorithm =
        ApplyAuthAlgorithm::try_new(field_u16(&fields, 34)).map_err(auth_wire_error)?;
    let auth_claim = ApplyRequestAuthClaim::try_new(
        PrincipalRef::from_bytes(field_array(&fields, 32)),
        ApplyAuthKeyRef::from_bytes(field_array(&fields, 33)),
        auth_algorithm,
        field_u16(&fields, 35),
        fields.get(36),
    )
    .map_err(auth_wire_error)?;
    let draft = RuntimeApplyEnvelopeDraft::try_new(control_commitment, temporal, auth_claim)
        .map_err(envelope_wire_error)?;
    let envelope = draft
        .finalize(fields.get(37))
        .map_err(envelope_wire_error)?;
    if envelope.canonical_wire() != frame {
        return Err(WireError::new(WireErrorCode::NonCanonicalFrame));
    }
    Ok(envelope)
}

fn tenure_wire_error(error: TenureProofError) -> WireError {
    let field_tag = match error {
        TenureProofError::InvalidAlgorithm => 13,
        TenureProofError::InvalidAlgorithmVersion => 14,
        TenureProofError::InvalidEpoch => 17,
        TenureProofError::InvalidSupersedesEpoch => 18,
        TenureProofError::EmptyNonce | TenureProofError::NonceTooLong => 19,
        TenureProofError::EmptySignature | TenureProofError::SignatureTooLong => 20,
    };
    WireError::at(WireErrorCode::InvalidFieldValue, field_tag)
}

fn apply_wire_error(error: ApplyContractError) -> WireError {
    let field_tag = match error {
        ApplyContractError::Provenance(_) => 8,
        ApplyContractError::WriterRefMismatch => 9,
        ApplyContractError::WriterEpochMismatch => 10,
        ApplyContractError::WriterScopeMismatch => 15,
        ApplyContractError::Digest(_) | ApplyContractError::ControlCommitmentDigestMismatch => 25,
    };
    WireError::at(WireErrorCode::InvalidFieldValue, field_tag)
}

fn auth_wire_error(error: ApplyAuthError) -> WireError {
    let field_tag = match error {
        ApplyAuthError::InvalidAlgorithm => 34,
        ApplyAuthError::InvalidAlgorithmVersion => 35,
        ApplyAuthError::EmptyNonce | ApplyAuthError::NonceTooLong => 36,
        ApplyAuthError::EmptySignature | ApplyAuthError::SignatureTooLong => 37,
    };
    WireError::at(WireErrorCode::InvalidFieldValue, field_tag)
}

fn envelope_wire_error(error: EnvelopeContractError) -> WireError {
    match error {
        EnvelopeContractError::Apply(error) => apply_wire_error(error),
        EnvelopeContractError::Authentication(error) => auth_wire_error(error),
        EnvelopeContractError::Digest(_) => WireError::at(WireErrorCode::InvalidFieldValue, 25),
        EnvelopeContractError::FrameTooLarge => WireError::new(WireErrorCode::FrameTooLarge),
        EnvelopeContractError::CanonicalWireMismatch
        | EnvelopeContractError::RequestDigestMismatch => {
            WireError::new(WireErrorCode::NonCanonicalFrame)
        }
    }
}

fn temporal_wire_error(error: TemporalContractError) -> WireError {
    match error {
        TemporalContractError::UnsupportedVersion => {
            WireError::at(WireErrorCode::UnsupportedVersion, 26)
        }
        TemporalContractError::ZeroOriginalBudget => {
            WireError::at(WireErrorCode::InvalidFieldValue, 30)
        }
        TemporalContractError::RemainingBudgetExceedsOriginal
        | TemporalContractError::RemainingBudgetExtended => {
            WireError::at(WireErrorCode::InvalidFieldValue, 31)
        }
    }
}

fn field_array<const N: usize>(fields: &ParsedFields<'_>, tag: u16) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(fields.get(tag));
    value
}

fn field_u16(fields: &ParsedFields<'_>, tag: u16) -> u16 {
    read_u16(fields.get(tag))
}

fn field_u64(fields: &ParsedFields<'_>, tag: u16) -> u64 {
    u64::from_be_bytes(field_array(fields, tag))
}

fn read_u16(value: &[u8]) -> u16 {
    u16::from_be_bytes([value[0], value[1]])
}

fn read_u32(value: &[u8]) -> u32 {
    u32::from_be_bytes([value[0], value[1], value[2], value[3]])
}

#[cfg(test)]
mod tests {
    use core::ops::Range;

    use paraegox_kernel::digest::{Digest32, Digest32Builder};
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};

    use crate::apply::{
        ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
        RuntimeApplyControl, RuntimeApplyControlCommitment, TenureAuthorityRef, TenureKeyRef,
        TenureProofAlgorithm, TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
    };
    use crate::provenance::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest,
        TargetSliceDigest,
    };
    use crate::temporal::{ApplyTemporalConstraint, TemporalConstraintId};

    use super::{
        APPLY_ENVELOPE_FIELD_COUNT, APPLY_ENVELOPE_MAGIC, ApplyAuthAlgorithm, ApplyAuthError,
        ApplyAuthKeyRef, ApplyRequestAuthClaim, ApplyRequestAuthentication, EnvelopeContractError,
        MAX_APPLY_AUTH_NONCE_BYTES, MAX_APPLY_AUTH_SIGNATURE_BYTES,
        MAX_RUNTIME_APPLY_ENVELOPE_BYTES, RuntimeApplyEnvelope, RuntimeApplyEnvelopeDraft,
        WireError, WireErrorCode,
    };

    #[derive(Clone, Debug)]
    struct TlvLocation {
        tag_offset: usize,
        length_offset: usize,
        value: Range<usize>,
    }

    fn generation(value: u64) -> ClockGeneration {
        let Ok(generation) = ClockGeneration::try_new(value) else {
            panic!("test clock generation must be valid");
        };
        generation
    }

    fn control_commitment(expected_active: ExpectedActive) -> RuntimeApplyControlCommitment {
        control_commitment_with_proof_bytes(expected_active, b"nonce", b"signature")
    }

    fn control_commitment_with_proof_bytes(
        expected_active: ExpectedActive,
        proof_nonce: &[u8],
        proof_signature: &[u8],
    ) -> RuntimeApplyControlCommitment {
        let scope = SourceScopeRef::from_bytes([1; 16]);
        let provenance = PlanProvenance::new(
            scope,
            SourcePlanRef::from_bytes([2; 16]),
            SourcePlanRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([4; 32])),
        );
        let header = RuntimeSliceHeader::new(
            RuntimeHostId::from_bytes([5; 16]),
            provenance,
            TargetAssignmentDigest::new(Digest32::from_bytes([6; 32])),
        );
        let Ok(slice) = RuntimeSliceCommitment::try_new(header) else {
            panic!("test slice must be valid");
        };
        let Ok(tenure_algorithm) = TenureProofAlgorithm::try_new(1) else {
            panic!("test tenure algorithm must be valid");
        };
        let Ok(tenure_authority) = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([7; 16]),
            TenureKeyRef::from_bytes([8; 16]),
            tenure_algorithm,
            1,
        ) else {
            panic!("test tenure authority must be valid");
        };
        let writer = PlanWriterRef::from_bytes([9; 16]);
        let Ok(tenure_claim) = WriterTenureClaim::try_new(
            scope,
            writer,
            PlanWriterEpoch::new(2),
            PlanWriterEpoch::new(1),
        ) else {
            panic!("test tenure claim must be valid");
        };
        let Ok(proof) = WriterTenureProof::try_new(
            tenure_authority,
            tenure_claim,
            proof_nonce,
            proof_signature,
        ) else {
            panic!("test tenure proof must be valid");
        };
        let Ok(writer_context) = PlanWriterContext::try_new(writer, PlanWriterEpoch::new(2), proof)
        else {
            panic!("test writer context must be valid");
        };
        let control = RuntimeApplyControl::new(
            writer_context,
            expected_active,
            ApplyOperationId::from_bytes([0x0b; 16]),
        );
        let Ok(commitment) = RuntimeApplyControlCommitment::try_new(slice, control) else {
            panic!("test control commitment must be valid");
        };
        commitment
    }

    fn temporal() -> ApplyTemporalConstraint {
        let Ok(value) = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([0x0c; 16]),
            ClockDomainRef::from_bytes([0x0d; 16]),
            generation(14),
            BoundedDuration::from_nanos(1_000_000),
            BoundedDuration::from_nanos(750_000),
        ) else {
            panic!("test temporal constraint must be valid");
        };
        value
    }

    fn auth_claim() -> ApplyRequestAuthClaim {
        auth_claim_with_nonce(b"apply-nonce")
    }

    fn auth_claim_with_nonce(nonce: &[u8]) -> ApplyRequestAuthClaim {
        let Ok(algorithm) = ApplyAuthAlgorithm::try_new(1) else {
            panic!("test apply-auth algorithm must be valid");
        };
        let Ok(claim) = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([9; 16]),
            ApplyAuthKeyRef::from_bytes([0x0e; 16]),
            algorithm,
            1,
            nonce,
        ) else {
            panic!("test apply-auth claim must be valid");
        };
        claim
    }

    fn draft_with_expected(expected_active: ExpectedActive) -> RuntimeApplyEnvelopeDraft {
        let Ok(draft) = RuntimeApplyEnvelopeDraft::try_new(
            control_commitment(expected_active),
            temporal(),
            auth_claim(),
        ) else {
            panic!("test envelope draft must be valid");
        };
        draft
    }

    fn envelope() -> RuntimeApplyEnvelope {
        let draft = draft_with_expected(ExpectedActive::Exact(TargetSliceDigest::new(
            Digest32::from_bytes([0x0a; 32]),
        )));
        let Ok(envelope) = draft.finalize(b"apply-signature") else {
            panic!("test envelope must be valid");
        };
        envelope
    }

    fn tlv_locations(frame: &[u8]) -> Vec<TlvLocation> {
        let mut locations = Vec::new();
        let mut cursor = APPLY_ENVELOPE_MAGIC.len() + 4;
        for _ in 0..APPLY_ENVELOPE_FIELD_COUNT {
            let tag_offset = cursor;
            let length_offset = cursor + 2;
            let value_length = u32::from_be_bytes([
                frame[length_offset],
                frame[length_offset + 1],
                frame[length_offset + 2],
                frame[length_offset + 3],
            ]) as usize;
            let value_start = cursor + 6;
            let value_end = value_start + value_length;
            locations.push(TlvLocation {
                tag_offset,
                length_offset,
                value: value_start..value_end,
            });
            cursor = value_end;
        }
        locations
    }

    fn error_code(result: Result<RuntimeApplyEnvelope, WireError>) -> WireErrorCode {
        let Some(error) = result.err() else {
            panic!("malformed frame must be rejected");
        };
        error.code()
    }

    #[test]
    fn canonical_envelope_round_trips_and_revalidates_b1_digests() {
        let original = envelope();
        let Ok(decoded) = RuntimeApplyEnvelope::decode(original.canonical_wire()) else {
            panic!("canonical envelope must decode");
        };
        let Ok(original_transcript) = original.signing_transcript() else {
            panic!("test auth transcript must build");
        };
        let Ok(decoded_transcript) = decoded.signing_transcript() else {
            panic!("decoded auth transcript must build");
        };

        assert_eq!(decoded, original);
        assert_eq!(decoded.canonical_wire(), original.canonical_wire());
        assert_eq!(decoded.request_digest(), original.request_digest());
        assert_eq!(decoded_transcript, original_transcript);
        assert_eq!(decoded.validate(), Ok(()));
        assert_eq!(
            decoded
                .control_commitment()
                .slice()
                .target_slice_digest()
                .value()
                .as_bytes(),
            &[
                0x78, 0x9d, 0x23, 0x48, 0x56, 0xf3, 0x17, 0x04, 0xa0, 0xa5, 0x8c, 0x49, 0x1c, 0xd3,
                0x69, 0x34, 0x69, 0xd4, 0xa9, 0xe3, 0x80, 0xe3, 0x3e, 0x85, 0x3e, 0xc0, 0x4a, 0x16,
                0xd5, 0x42, 0x29, 0x80,
            ]
        );
        assert_eq!(
            decoded.control_commitment().commitment_digest().as_bytes(),
            &[
                0x1b, 0x91, 0x7b, 0xa6, 0x83, 0x27, 0x58, 0xd2, 0x72, 0x99, 0xd3, 0xaa, 0x32, 0x4f,
                0x82, 0xb2, 0xca, 0xf3, 0x2c, 0x28, 0x41, 0x78, 0x10, 0x8e, 0x28, 0xd6, 0xaf, 0x97,
                0xc5, 0x9b, 0x77, 0xd8,
            ]
        );

        let none = draft_with_expected(ExpectedActive::None);
        let Ok(none) = none.finalize(b"apply-signature") else {
            panic!("none-CAS envelope must finalize");
        };
        assert!(RuntimeApplyEnvelope::decode(none.canonical_wire()).is_ok());
    }

    #[test]
    fn request_transcript_and_complete_request_digest_have_golden_vectors() {
        let value = envelope();
        let Ok(transcript) = value.signing_transcript() else {
            panic!("test auth transcript must build");
        };
        let Ok(mut transcript_digest) =
            Digest32Builder::try_new(b"paraegox.test.apply-auth-transcript-golden.v1")
        else {
            panic!("test digest domain must be valid");
        };
        assert!(transcript_digest.field_bytes(transcript.as_bytes()).is_ok());
        let transcript_digest = transcript_digest.finish();

        assert_eq!(value.canonical_wire().len(), 767);
        assert_eq!(transcript.as_bytes().len(), 801);
        assert_eq!(
            transcript_digest.as_bytes(),
            &[
                0x85, 0xbf, 0xb5, 0x23, 0x35, 0x4a, 0x45, 0xce, 0xe7, 0x78, 0x2f, 0xf6, 0x1f, 0x1d,
                0x6c, 0xc9, 0x75, 0xd0, 0xf2, 0x8d, 0x06, 0x29, 0x64, 0xdb, 0xb2, 0x2f, 0xd6, 0xb6,
                0x9e, 0x48, 0x41, 0x8a,
            ]
        );
        assert_eq!(
            value.request_digest().as_bytes(),
            &[
                0x9d, 0x0e, 0x92, 0x05, 0x26, 0x54, 0x5c, 0x4a, 0xca, 0xe6, 0x5c, 0x5e, 0x5b, 0x8f,
                0xda, 0xed, 0x06, 0x3e, 0x22, 0x31, 0x61, 0x45, 0x15, 0xc1, 0xa7, 0x6d, 0xdc, 0xff,
                0x63, 0xd4, 0x08, 0xaa,
            ]
        );
    }

    #[test]
    fn auth_signature_is_excluded_from_transcript_but_included_in_request_digest() {
        let first_draft = draft_with_expected(ExpectedActive::None);
        let second_draft = first_draft.clone();
        let Ok(first_transcript) = first_draft.signing_transcript() else {
            panic!("first transcript must build");
        };
        let Ok(second_transcript) = second_draft.signing_transcript() else {
            panic!("second transcript must build");
        };
        let Ok(first) = first_draft.finalize(b"apply-signature-a") else {
            panic!("first envelope must finalize");
        };
        let Ok(second) = second_draft.finalize(b"apply-signature-b") else {
            panic!("second envelope must finalize");
        };

        assert_eq!(first_transcript, second_transcript);
        assert_ne!(first.canonical_wire(), second.canonical_wire());
        assert_ne!(first.request_digest(), second.request_digest());
    }

    #[test]
    fn every_wire_field_is_authenticated_or_revalidated() {
        let baseline = envelope();
        let Ok(baseline_transcript) = baseline.signing_transcript() else {
            panic!("baseline transcript must build");
        };
        let locations = tlv_locations(baseline.canonical_wire());

        for (index, location) in locations.iter().enumerate() {
            let tag = (index + 1) as u16;
            let mut changed = baseline.canonical_wire().to_vec();
            let last_value_byte = location.value.end - 1;
            changed[last_value_byte] ^= 1;

            match RuntimeApplyEnvelope::decode(&changed) {
                Ok(decoded) => {
                    assert_ne!(decoded.request_digest(), baseline.request_digest());
                    let Ok(decoded_transcript) = decoded.signing_transcript() else {
                        panic!("changed transcript must build");
                    };
                    if tag == APPLY_ENVELOPE_FIELD_COUNT {
                        assert_eq!(decoded_transcript, baseline_transcript);
                    } else {
                        assert_ne!(decoded_transcript, baseline_transcript);
                    }
                }
                Err(error) => {
                    assert!(matches!(
                        error.code(),
                        WireErrorCode::UnsupportedVersion
                            | WireErrorCode::InvalidFieldValue
                            | WireErrorCode::DerivedDigestMismatch
                    ));
                }
            }
        }
    }

    #[test]
    fn malformed_frames_have_stable_reason_codes() {
        let baseline = envelope();
        let wire = baseline.canonical_wire();
        let locations = tlv_locations(wire);
        let version_offset = APPLY_ENVELOPE_MAGIC.len();
        let count_offset = version_offset + 2;

        let mut invalid_magic = wire.to_vec();
        invalid_magic[0] ^= 1;
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&invalid_magic)),
            WireErrorCode::InvalidMagic
        );

        let mut unsupported_version = wire.to_vec();
        unsupported_version[version_offset..version_offset + 2]
            .copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&unsupported_version)),
            WireErrorCode::UnsupportedVersion
        );

        let mut duplicate = wire.to_vec();
        duplicate[locations[1].tag_offset..locations[1].tag_offset + 2]
            .copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&duplicate)),
            WireErrorCode::DuplicateField
        );

        let mut out_of_order = wire.to_vec();
        out_of_order[locations[1].tag_offset..locations[1].tag_offset + 2]
            .copy_from_slice(&3_u16.to_be_bytes());
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&out_of_order)),
            WireErrorCode::OutOfOrderField
        );

        let mut invalid_length = wire.to_vec();
        invalid_length[locations[0].length_offset..locations[0].length_offset + 4]
            .copy_from_slice(&3_u32.to_be_bytes());
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&invalid_length)),
            WireErrorCode::InvalidFieldLength
        );

        let mut oversized_proof = wire.to_vec();
        oversized_proof[locations[19].length_offset..locations[19].length_offset + 4]
            .copy_from_slice(&513_u32.to_be_bytes());
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&oversized_proof)),
            WireErrorCode::InvalidFieldLength
        );

        let mut missing = wire[..locations[36].tag_offset].to_vec();
        missing[count_offset..count_offset + 2].copy_from_slice(&36_u16.to_be_bytes());
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&missing)),
            WireErrorCode::MissingField
        );

        let mut unknown = wire.to_vec();
        unknown[count_offset..count_offset + 2].copy_from_slice(&38_u16.to_be_bytes());
        unknown.extend_from_slice(&38_u16.to_be_bytes());
        unknown.extend_from_slice(&1_u32.to_be_bytes());
        unknown.push(0);
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&unknown)),
            WireErrorCode::UnknownField
        );

        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&trailing)),
            WireErrorCode::TrailingBytes
        );

        let truncated = &wire[..wire.len() - 1];
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(truncated)),
            WireErrorCode::Truncated
        );

        let oversized = vec![0; MAX_RUNTIME_APPLY_ENVELOPE_BYTES + 1];
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&oversized)),
            WireErrorCode::FrameTooLarge
        );

        let mut exact_limit = wire.to_vec();
        exact_limit.resize(MAX_RUNTIME_APPLY_ENVELOPE_BYTES, 0);
        assert_eq!(exact_limit.len(), MAX_RUNTIME_APPLY_ENVELOPE_BYTES);
        assert_eq!(
            error_code(RuntimeApplyEnvelope::decode(&exact_limit)),
            WireErrorCode::TrailingBytes
        );
    }

    #[test]
    fn wire_error_codes_have_stable_numeric_values() {
        assert_eq!(
            [
                WireErrorCode::FrameTooLarge as u16,
                WireErrorCode::Truncated as u16,
                WireErrorCode::InvalidMagic as u16,
                WireErrorCode::UnsupportedVersion as u16,
                WireErrorCode::UnknownField as u16,
                WireErrorCode::MissingField as u16,
                WireErrorCode::DuplicateField as u16,
                WireErrorCode::OutOfOrderField as u16,
                WireErrorCode::InvalidFieldLength as u16,
                WireErrorCode::InvalidFieldValue as u16,
                WireErrorCode::DerivedDigestMismatch as u16,
                WireErrorCode::NonCanonicalFrame as u16,
                WireErrorCode::TrailingBytes as u16,
            ],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        );
    }

    #[test]
    fn embedded_versions_and_b1_derived_digests_are_revalidated() {
        let baseline = envelope();
        let locations = tlv_locations(baseline.canonical_wire());

        let mut slice_version = baseline.canonical_wire().to_vec();
        slice_version[locations[0].value.clone()].copy_from_slice(&2_u16.to_be_bytes());
        let Some(error) = RuntimeApplyEnvelope::decode(&slice_version).err() else {
            panic!("unsupported slice version must fail");
        };
        assert_eq!(error.code(), WireErrorCode::UnsupportedVersion);
        assert_eq!(error.field_tag(), Some(1));

        let mut temporal_version = baseline.canonical_wire().to_vec();
        temporal_version[locations[25].value.clone()].copy_from_slice(&2_u16.to_be_bytes());
        let Some(error) = RuntimeApplyEnvelope::decode(&temporal_version).err() else {
            panic!("unsupported temporal version must fail");
        };
        assert_eq!(error.code(), WireErrorCode::UnsupportedVersion);
        assert_eq!(error.field_tag(), Some(26));

        for tag in [8_u16, 21, 25] {
            let mut changed = baseline.canonical_wire().to_vec();
            let location = &locations[usize::from(tag - 1)];
            changed[location.value.start] ^= 1;
            let Some(error) = RuntimeApplyEnvelope::decode(&changed).err() else {
                panic!("changed derived digest must fail");
            };
            assert_eq!(error.code(), WireErrorCode::DerivedDigestMismatch);
            assert_eq!(error.field_tag(), Some(tag));
        }
    }

    #[test]
    fn invalid_temporal_budgets_report_the_offending_wire_field() {
        let baseline = envelope();
        let locations = tlv_locations(baseline.canonical_wire());

        let mut zero_original = baseline.canonical_wire().to_vec();
        zero_original[locations[29].value.clone()].copy_from_slice(&0_u64.to_be_bytes());
        let Some(error) = RuntimeApplyEnvelope::decode(&zero_original).err() else {
            panic!("zero original budget must fail");
        };
        assert_eq!(error.code(), WireErrorCode::InvalidFieldValue);
        assert_eq!(error.field_tag(), Some(30));

        let mut extended_remaining = baseline.canonical_wire().to_vec();
        extended_remaining[locations[30].value.clone()]
            .copy_from_slice(&1_000_001_u64.to_be_bytes());
        let Some(error) = RuntimeApplyEnvelope::decode(&extended_remaining).err() else {
            panic!("remaining budget beyond original must fail");
        };
        assert_eq!(error.code(), WireErrorCode::InvalidFieldValue);
        assert_eq!(error.field_tag(), Some(31));
    }

    #[test]
    fn semantic_value_errors_report_the_offending_wire_field() {
        let baseline = envelope();
        let locations = tlv_locations(baseline.canonical_wire());

        let mut invalid_epoch = baseline.canonical_wire().to_vec();
        invalid_epoch[locations[16].value.clone()].copy_from_slice(&0_u64.to_be_bytes());
        let Some(error) = RuntimeApplyEnvelope::decode(&invalid_epoch).err() else {
            panic!("zero tenure epoch must fail");
        };
        assert_eq!(error.code(), WireErrorCode::InvalidFieldValue);
        assert_eq!(error.field_tag(), Some(17));

        let mut invalid_supersedes = baseline.canonical_wire().to_vec();
        invalid_supersedes[locations[17].value.clone()].copy_from_slice(&2_u64.to_be_bytes());
        let Some(error) = RuntimeApplyEnvelope::decode(&invalid_supersedes).err() else {
            panic!("non-strict supersedes epoch must fail");
        };
        assert_eq!(error.code(), WireErrorCode::InvalidFieldValue);
        assert_eq!(error.field_tag(), Some(18));

        let mut writer_mismatch = baseline.canonical_wire().to_vec();
        writer_mismatch[locations[8].value.start] ^= 1;
        let Some(error) = RuntimeApplyEnvelope::decode(&writer_mismatch).err() else {
            panic!("writer reference mismatch must fail");
        };
        assert_eq!(error.code(), WireErrorCode::InvalidFieldValue);
        assert_eq!(error.field_tag(), Some(9));

        let mut writer_epoch_mismatch = baseline.canonical_wire().to_vec();
        writer_epoch_mismatch[locations[9].value.clone()].copy_from_slice(&3_u64.to_be_bytes());
        let Some(error) = RuntimeApplyEnvelope::decode(&writer_epoch_mismatch).err() else {
            panic!("writer epoch mismatch must fail");
        };
        assert_eq!(error.code(), WireErrorCode::InvalidFieldValue);
        assert_eq!(error.field_tag(), Some(10));

        let mut scope_mismatch = baseline.canonical_wire().to_vec();
        scope_mismatch[locations[14].value.clone()].copy_from_slice(&[0x22; 16]);
        let Ok(tenure_algorithm) = TenureProofAlgorithm::try_new(1) else {
            panic!("test tenure algorithm must be valid");
        };
        let Ok(tenure_authority) = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([7; 16]),
            TenureKeyRef::from_bytes([8; 16]),
            tenure_algorithm,
            1,
        ) else {
            panic!("test tenure authority must be valid");
        };
        let Ok(tenure_claim) = WriterTenureClaim::try_new(
            SourceScopeRef::from_bytes([0x22; 16]),
            PlanWriterRef::from_bytes([9; 16]),
            PlanWriterEpoch::new(2),
            PlanWriterEpoch::new(1),
        ) else {
            panic!("test tenure claim must be valid");
        };
        let Ok(proof) =
            WriterTenureProof::try_new(tenure_authority, tenure_claim, b"nonce", b"signature")
        else {
            panic!("test tenure proof must be valid");
        };
        let Ok(proof_digest) = proof.envelope_digest() else {
            panic!("test proof digest must build");
        };
        scope_mismatch[locations[20].value.clone()].copy_from_slice(proof_digest.as_bytes());
        let Some(error) = RuntimeApplyEnvelope::decode(&scope_mismatch).err() else {
            panic!("writer scope mismatch must fail");
        };
        assert_eq!(error.code(), WireErrorCode::InvalidFieldValue);
        assert_eq!(error.field_tag(), Some(15));

        let mut auth_version = baseline.canonical_wire().to_vec();
        auth_version[locations[34].value.clone()].copy_from_slice(&0_u16.to_be_bytes());
        let Some(error) = RuntimeApplyEnvelope::decode(&auth_version).err() else {
            panic!("zero auth algorithm version must fail");
        };
        assert_eq!(error.code(), WireErrorCode::InvalidFieldValue);
        assert_eq!(error.field_tag(), Some(35));

        let mut empty_auth_nonce = baseline.canonical_wire().to_vec();
        empty_auth_nonce[locations[35].length_offset..locations[35].length_offset + 4]
            .copy_from_slice(&0_u32.to_be_bytes());
        let Some(error) = RuntimeApplyEnvelope::decode(&empty_auth_nonce).err() else {
            panic!("empty auth nonce must fail");
        };
        assert_eq!(error.code(), WireErrorCode::InvalidFieldLength);
        assert_eq!(error.field_tag(), Some(36));
    }

    #[test]
    fn request_auth_values_are_bounded() {
        assert_eq!(
            ApplyAuthAlgorithm::try_new(0),
            Err(ApplyAuthError::InvalidAlgorithm)
        );
        let Ok(algorithm) = ApplyAuthAlgorithm::try_new(1) else {
            panic!("test algorithm must be valid");
        };
        let principal = PrincipalRef::from_bytes([1; 16]);
        let key = ApplyAuthKeyRef::from_bytes([2; 16]);
        assert_eq!(
            ApplyRequestAuthClaim::try_new(principal, key, algorithm, 0, b"nonce").err(),
            Some(ApplyAuthError::InvalidAlgorithmVersion)
        );
        assert_eq!(
            ApplyRequestAuthClaim::try_new(principal, key, algorithm, 1, b"").err(),
            Some(ApplyAuthError::EmptyNonce)
        );
        assert_eq!(
            ApplyRequestAuthClaim::try_new(
                principal,
                key,
                algorithm,
                1,
                &[0; MAX_APPLY_AUTH_NONCE_BYTES + 1],
            )
            .err(),
            Some(ApplyAuthError::NonceTooLong)
        );

        let claim = auth_claim();
        assert_eq!(
            ApplyRequestAuthentication::try_new(claim.clone(), b"").err(),
            Some(ApplyAuthError::EmptySignature)
        );
        assert_eq!(
            ApplyRequestAuthentication::try_new(claim, &[0; MAX_APPLY_AUTH_SIGNATURE_BYTES + 1],)
                .err(),
            Some(ApplyAuthError::SignatureTooLong)
        );
    }

    #[test]
    fn exact_nonce_and_signature_limits_round_trip() {
        let tenure_nonce = [0x19; crate::apply::MAX_TENURE_NONCE_BYTES];
        let tenure_signature = [0x20; crate::apply::MAX_TENURE_SIGNATURE_BYTES];
        let auth_nonce = [0x36; MAX_APPLY_AUTH_NONCE_BYTES];
        let auth_signature = [0x37; MAX_APPLY_AUTH_SIGNATURE_BYTES];
        let Ok(draft) = RuntimeApplyEnvelopeDraft::try_new(
            control_commitment_with_proof_bytes(
                ExpectedActive::None,
                &tenure_nonce,
                &tenure_signature,
            ),
            temporal(),
            auth_claim_with_nonce(&auth_nonce),
        ) else {
            panic!("exact-limit envelope draft must build");
        };
        let Ok(envelope) = draft.finalize(&auth_signature) else {
            panic!("exact-limit envelope must finalize");
        };
        let Ok(decoded) = RuntimeApplyEnvelope::decode(envelope.canonical_wire()) else {
            panic!("exact-limit envelope must decode");
        };

        let proof = decoded
            .control_commitment()
            .control()
            .writer_context()
            .proof();
        assert_eq!(proof.nonce().len(), crate::apply::MAX_TENURE_NONCE_BYTES);
        assert_eq!(
            proof.signature().len(),
            crate::apply::MAX_TENURE_SIGNATURE_BYTES
        );
        assert_eq!(
            decoded.authentication().claim().nonce().len(),
            MAX_APPLY_AUTH_NONCE_BYTES
        );
        assert_eq!(
            decoded.authentication().signature().len(),
            MAX_APPLY_AUTH_SIGNATURE_BYTES
        );
        assert_eq!(decoded, envelope);
        assert!(decoded.canonical_wire().len() <= MAX_RUNTIME_APPLY_ENVELOPE_BYTES);
    }

    #[test]
    fn stored_wire_and_request_digest_fail_closed() {
        let mut corrupted_wire = envelope();
        corrupted_wire.canonical_wire[0] ^= 1;
        assert_eq!(
            corrupted_wire.validate(),
            Err(EnvelopeContractError::CanonicalWireMismatch)
        );

        let mut corrupted_digest = envelope();
        corrupted_digest.request_digest = Digest32::from_bytes([99; 32]);
        assert_eq!(
            corrupted_digest.validate(),
            Err(EnvelopeContractError::RequestDigestMismatch)
        );
    }
}
