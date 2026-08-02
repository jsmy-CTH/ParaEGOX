//! Internal, canonical local-IPC contract for acquiring deployment writer tenure.
//!
//! This module owns only the acquire request, response, request-authentication
//! transcript, and transport framing. The embedded writer-tenure claim,
//! authority selector, signing transcript, proof envelope, and proof digest stay
//! owned by `paraegox-runtime-contracts`.

use core::fmt;

use paraegox_kernel::{
    digest::{Digest32, Digest32Builder, DigestBuildError},
    identity::PrincipalRef,
};
use paraegox_runtime_contracts::{
    apply::{
        MAX_TENURE_NONCE_BYTES, MAX_TENURE_SIGNATURE_BYTES, PlanWriterEpoch, PlanWriterRef,
        TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
        WriterTenureClaim, WriterTenureProof,
    },
    provenance::SourceScopeRef,
};

use crate::plan::{DeploymentScopeId, DeploymentWriterRef};

const ACQUIRE_REQUEST_MAGIC: &[u8] = b"PXATREQ\0";
const ACQUIRE_RESPONSE_MAGIC: &[u8] = b"PXATRSP\0";
const ACQUIRE_FRAME_MAGIC: &[u8] = b"PXATFRM\0";
const REQUEST_AUTH_TRANSCRIPT_MAGIC: &[u8] = b"ParaEGOX\0acquire-tenure-request-auth";
const REQUEST_AUTH_TRANSCRIPT_DOMAIN: &[u8] =
    b"paraegox.deployment.acquire-tenure.request-auth.ed25519.v1";
const INTENT_DIGEST_DOMAIN: &[u8] = b"paraegox.deployment.acquire-tenure.intent.sha256.v1";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"paraegox.deployment.acquire-tenure.request.sha256.v1";
const RESPONSE_DIGEST_DOMAIN: &[u8] = b"paraegox.deployment.acquire-tenure.response.sha256.v1";
const CONTROLLER_KEY_FINGERPRINT_DOMAIN: &[u8] =
    b"paraegox.deployment.acquire-tenure.controller-key.sha256.v1";

pub(crate) const ACQUIRE_TENURE_PROTOCOL_VERSION: u16 = 1;
pub(crate) const ACQUIRE_TENURE_FRAME_VERSION: u16 = 1;
pub(crate) const ACQUIRE_TENURE_REQUEST_AUTH_TRANSCRIPT_VERSION: u16 = 1;
pub(crate) const ACQUIRE_TENURE_ED25519_ALGORITHM: u16 = 1;
pub(crate) const ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION: u16 = 1;
pub(crate) const ACQUIRE_TENURE_ED25519_SIGNATURE_BYTES: usize = 64;
pub(crate) const MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES: usize = 64;

const REQUEST_FIELD_COUNT: u16 = 12;
const REQUEST_UNSIGNED_FIELD_COUNT: u16 = REQUEST_FIELD_COUNT - 1;
const RESPONSE_FIELD_COUNT: u16 = 15;
const RESPONSE_UNSIGNED_FIELD_COUNT: u16 = RESPONSE_FIELD_COUNT - 1;
const TLV_HEADER_BYTES: usize = 6;
const VALUE_HEADER_BYTES: usize = 12;

const REQUEST_FIXED_VALUE_BYTES: usize =
    (5 * 16) + 32 + 2 + 2 + 4 + 32 + ACQUIRE_TENURE_ED25519_SIGNATURE_BYTES;
pub(crate) const MIN_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES: usize = VALUE_HEADER_BYTES
    + (REQUEST_FIELD_COUNT as usize * TLV_HEADER_BYTES)
    + REQUEST_FIXED_VALUE_BYTES
    + 1;
pub(crate) const MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES: usize = VALUE_HEADER_BYTES
    + (REQUEST_FIELD_COUNT as usize * TLV_HEADER_BYTES)
    + REQUEST_FIXED_VALUE_BYTES
    + MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES;
pub(crate) const MAX_ACQUIRE_TENURE_REQUEST_SIGNING_TRANSCRIPT_BYTES: usize =
    REQUEST_AUTH_TRANSCRIPT_MAGIC.len()
        + 2
        + 2
        + REQUEST_AUTH_TRANSCRIPT_DOMAIN.len()
        + 2
        + (REQUEST_UNSIGNED_FIELD_COUNT as usize * TLV_HEADER_BYTES)
        + (REQUEST_FIXED_VALUE_BYTES - ACQUIRE_TENURE_ED25519_SIGNATURE_BYTES)
        + MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES;

const RESPONSE_FIXED_VALUE_BYTES: usize = (5 * 16) + (2 * 32) + (2 * 2) + (2 * 8) + 32;
pub(crate) const MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES: usize = VALUE_HEADER_BYTES
    + (RESPONSE_FIELD_COUNT as usize * TLV_HEADER_BYTES)
    + RESPONSE_FIXED_VALUE_BYTES
    + 1
    + 1
    + 1;
pub(crate) const MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES: usize = VALUE_HEADER_BYTES
    + (RESPONSE_FIELD_COUNT as usize * TLV_HEADER_BYTES)
    + RESPONSE_FIXED_VALUE_BYTES
    + MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES
    + MAX_TENURE_NONCE_BYTES
    + MAX_TENURE_SIGNATURE_BYTES;

pub(crate) const ACQUIRE_TENURE_FRAME_HEADER_BYTES: usize = 16;
pub(crate) const MAX_ACQUIRE_TENURE_FRAME_BYTES: usize =
    ACQUIRE_TENURE_FRAME_HEADER_BYTES + MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES;

macro_rules! opaque_ref {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub(crate) struct $name([u8; 16]);

        impl $name {
            #[must_use]
            pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_ref!(AcquireTenureOperationId);
opaque_ref!(ControllerAcquireKeyRef);

macro_rules! typed_digest {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub(crate) struct $name(Digest32);

        impl $name {
            #[must_use]
            const fn new(value: Digest32) -> Self {
                Self(value)
            }

            #[must_use]
            pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            #[must_use]
            const fn value(self) -> Digest32 {
                self.0
            }
        }
    };
}

typed_digest!(ControllerPublicKeyFingerprint);
typed_digest!(AcquireTenureIntentDigest);
typed_digest!(AcquireTenureRequestDigest);
typed_digest!(AcquireTenureResponseDigest);

impl ControllerPublicKeyFingerprint {
    pub(crate) fn for_ed25519_key(
        public_key: &[u8; 32],
    ) -> Result<Self, AcquireTenureProtocolError> {
        let mut builder = digest_builder(CONTROLLER_KEY_FINGERPRINT_DOMAIN)?;
        digest_u16(&mut builder, ACQUIRE_TENURE_ED25519_ALGORITHM)?;
        digest_u16(&mut builder, ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION)?;
        digest_bytes(&mut builder, public_key)?;
        Self::try_from_digest(builder.finish())
    }

    #[must_use]
    const fn from_digest_unchecked(value: Digest32) -> Self {
        Self::new(value)
    }

    pub(crate) fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, AcquireTenureProtocolError> {
        Self::try_from_digest(Digest32::from_bytes(bytes))
    }

    fn try_from_digest(value: Digest32) -> Result<Self, AcquireTenureProtocolError> {
        validate_nonzero(value.as_bytes(), 6)?;
        Ok(Self::new(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct AcquireTenureIntentV1 {
    scope: DeploymentScopeId,
    writer: DeploymentWriterRef,
    operation_id: AcquireTenureOperationId,
}

impl AcquireTenureIntentV1 {
    #[must_use]
    pub(crate) const fn new(
        scope: DeploymentScopeId,
        writer: DeploymentWriterRef,
        operation_id: AcquireTenureOperationId,
    ) -> Self {
        Self {
            scope,
            writer,
            operation_id,
        }
    }

    #[must_use]
    pub(crate) const fn scope(self) -> DeploymentScopeId {
        self.scope
    }

    #[must_use]
    pub(crate) const fn writer(self) -> DeploymentWriterRef {
        self.writer
    }

    #[must_use]
    pub(crate) const fn operation_id(self) -> AcquireTenureOperationId {
        self.operation_id
    }

    pub(crate) fn digest(self) -> Result<AcquireTenureIntentDigest, AcquireTenureProtocolError> {
        let mut builder = digest_builder(INTENT_DIGEST_DOMAIN)?;
        digest_bytes(&mut builder, self.scope.as_bytes())?;
        digest_bytes(&mut builder, self.writer.as_bytes())?;
        digest_bytes(&mut builder, self.operation_id.as_bytes())?;
        Ok(AcquireTenureIntentDigest::new(builder.finish()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcquireTenureRequestSigningTranscriptV1(Box<[u8]>);

impl AcquireTenureRequestSigningTranscriptV1 {
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcquireTenureRequestDraftV1 {
    intent: AcquireTenureIntentV1,
    controller_principal: PrincipalRef,
    controller_key: ControllerAcquireKeyRef,
    controller_public_key_fingerprint: ControllerPublicKeyFingerprint,
    client_nonce: Box<[u8]>,
    max_response_payload_bytes: u32,
    intent_digest: AcquireTenureIntentDigest,
}

impl AcquireTenureRequestDraftV1 {
    pub(crate) fn try_new(
        intent: AcquireTenureIntentV1,
        controller_principal: PrincipalRef,
        controller_key: ControllerAcquireKeyRef,
        controller_public_key_fingerprint: ControllerPublicKeyFingerprint,
        client_nonce: &[u8],
        max_response_payload_bytes: u32,
    ) -> Result<Self, AcquireTenureProtocolError> {
        validate_nonzero(intent.scope.as_bytes(), 1)?;
        validate_nonzero(intent.writer.as_bytes(), 2)?;
        validate_nonzero(intent.operation_id.as_bytes(), 3)?;
        validate_nonzero(controller_principal.as_bytes(), 4)?;
        validate_nonzero(controller_key.as_bytes(), 5)?;
        validate_nonzero(controller_public_key_fingerprint.as_bytes(), 6)?;
        validate_client_nonce(client_nonce, 9)?;
        validate_response_bound(max_response_payload_bytes, 10)?;
        let intent_digest = intent.digest()?;
        Ok(Self {
            intent,
            controller_principal,
            controller_key,
            controller_public_key_fingerprint,
            client_nonce: client_nonce.into(),
            max_response_payload_bytes,
            intent_digest,
        })
    }

    #[must_use]
    pub(crate) const fn intent(&self) -> AcquireTenureIntentV1 {
        self.intent
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<AcquireTenureRequestSigningTranscriptV1, AcquireTenureProtocolError> {
        build_request_signing_transcript(self)
    }

    pub(crate) fn finalize_ed25519(
        self,
        signature: &[u8],
    ) -> Result<AcquireTenureRequestV1, AcquireTenureProtocolError> {
        validate_ed25519_signature(signature, 12)?;
        AcquireTenureRequestV1::from_draft(self, signature)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcquireTenureRequestV1 {
    draft: AcquireTenureRequestDraftV1,
    auth_signature: Box<[u8]>,
    canonical_bytes: Box<[u8]>,
    request_digest: AcquireTenureRequestDigest,
}

impl AcquireTenureRequestV1 {
    fn from_draft(
        draft: AcquireTenureRequestDraftV1,
        auth_signature: &[u8],
    ) -> Result<Self, AcquireTenureProtocolError> {
        let canonical_bytes = build_request_bytes(&draft, auth_signature);
        if canonical_bytes.len() > MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::MessageTooLarge,
            ));
        }
        let request_digest = digest_complete_request(&canonical_bytes)?;
        Ok(Self {
            draft,
            auth_signature: auth_signature.into(),
            canonical_bytes: canonical_bytes.into_boxed_slice(),
            request_digest,
        })
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, AcquireTenureProtocolError> {
        decode_request(bytes)
    }

    #[must_use]
    pub(crate) const fn intent(&self) -> AcquireTenureIntentV1 {
        self.draft.intent
    }

    #[must_use]
    pub(crate) const fn scope(&self) -> DeploymentScopeId {
        self.draft.intent.scope
    }

    #[must_use]
    pub(crate) const fn writer(&self) -> DeploymentWriterRef {
        self.draft.intent.writer
    }

    #[must_use]
    pub(crate) const fn operation_id(&self) -> AcquireTenureOperationId {
        self.draft.intent.operation_id
    }

    #[must_use]
    pub(crate) const fn controller_principal(&self) -> PrincipalRef {
        self.draft.controller_principal
    }

    #[must_use]
    pub(crate) const fn controller_key(&self) -> ControllerAcquireKeyRef {
        self.draft.controller_key
    }

    #[must_use]
    pub(crate) const fn controller_public_key_fingerprint(&self) -> ControllerPublicKeyFingerprint {
        self.draft.controller_public_key_fingerprint
    }

    #[must_use]
    pub(crate) const fn auth_algorithm(&self) -> u16 {
        ACQUIRE_TENURE_ED25519_ALGORITHM
    }

    #[must_use]
    pub(crate) const fn auth_algorithm_version(&self) -> u16 {
        ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION
    }

    #[must_use]
    pub(crate) fn client_nonce(&self) -> &[u8] {
        &self.draft.client_nonce
    }

    #[must_use]
    pub(crate) const fn max_response_payload_bytes(&self) -> u32 {
        self.draft.max_response_payload_bytes
    }

    #[must_use]
    pub(crate) const fn intent_digest(&self) -> AcquireTenureIntentDigest {
        self.draft.intent_digest
    }

    #[must_use]
    pub(crate) fn auth_signature(&self) -> &[u8] {
        &self.auth_signature
    }

    #[must_use]
    pub(crate) const fn request_digest(&self) -> AcquireTenureRequestDigest {
        self.request_digest
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub(crate) fn proof_source_scope(&self) -> SourceScopeRef {
        SourceScopeRef::from_bytes(*self.scope().as_bytes())
    }

    #[must_use]
    pub(crate) fn proof_writer(&self) -> PlanWriterRef {
        PlanWriterRef::from_bytes(*self.writer().as_bytes())
    }

    pub(crate) fn signing_transcript(
        &self,
    ) -> Result<AcquireTenureRequestSigningTranscriptV1, AcquireTenureProtocolError> {
        build_request_signing_transcript(&self.draft)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcquireTenureResponseV1 {
    operation_id: AcquireTenureOperationId,
    request_digest: AcquireTenureRequestDigest,
    client_nonce: Box<[u8]>,
    proof: WriterTenureProof,
    proof_digest: Digest32,
    response_digest: AcquireTenureResponseDigest,
    canonical_bytes: Box<[u8]>,
}

impl AcquireTenureResponseV1 {
    pub(crate) fn try_new(
        request: &AcquireTenureRequestV1,
        proof: WriterTenureProof,
    ) -> Result<Self, AcquireTenureProtocolError> {
        validate_proof_binding(request, &proof)?;
        let proof_digest = proof.envelope_digest().map_err(map_digest_error)?;
        let response_digest = build_response_digest(
            request.operation_id(),
            request.request_digest(),
            request.client_nonce(),
            &proof,
            proof_digest,
        )?;
        let canonical_bytes = build_response_bytes(
            request.operation_id(),
            request.request_digest(),
            request.client_nonce(),
            &proof,
            proof_digest,
            response_digest,
        );
        if canonical_bytes.len() > request.max_response_payload_bytes() as usize {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::ResponseBoundExceeded,
            ));
        }
        if canonical_bytes.len() > MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::MessageTooLarge,
            ));
        }
        Ok(Self {
            operation_id: request.operation_id(),
            request_digest: request.request_digest(),
            client_nonce: request.client_nonce().into(),
            proof,
            proof_digest,
            response_digest,
            canonical_bytes: canonical_bytes.into_boxed_slice(),
        })
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, AcquireTenureProtocolError> {
        decode_response(bytes)
    }

    pub(crate) fn decode_for_request(
        bytes: &[u8],
        request: &AcquireTenureRequestV1,
    ) -> Result<Self, AcquireTenureProtocolError> {
        let response = Self::decode(bytes)?;
        response.validate_request_binding(request)?;
        Ok(response)
    }

    #[must_use]
    pub(crate) const fn operation_id(&self) -> AcquireTenureOperationId {
        self.operation_id
    }

    #[must_use]
    pub(crate) const fn request_digest(&self) -> AcquireTenureRequestDigest {
        self.request_digest
    }

    #[must_use]
    pub(crate) fn client_nonce(&self) -> &[u8] {
        &self.client_nonce
    }

    #[must_use]
    pub(crate) const fn proof(&self) -> &WriterTenureProof {
        &self.proof
    }

    #[must_use]
    pub(crate) const fn proof_digest(&self) -> &Digest32 {
        &self.proof_digest
    }

    #[must_use]
    pub(crate) const fn response_digest(&self) -> AcquireTenureResponseDigest {
        self.response_digest
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub(crate) fn into_proof(self) -> WriterTenureProof {
        self.proof
    }

    fn validate_request_binding(
        &self,
        request: &AcquireTenureRequestV1,
    ) -> Result<(), AcquireTenureProtocolError> {
        if self.operation_id != request.operation_id()
            || self.request_digest != request.request_digest()
            || self.client_nonce() != request.client_nonce()
        {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::RequestBindingMismatch,
            ));
        }
        if self.canonical_bytes.len() > request.max_response_payload_bytes() as usize {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::ResponseBoundExceeded,
            ));
        }
        validate_proof_binding(request, &self.proof)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum AcquireTenureFrameKind {
    Request = 1,
    Response = 2,
}

impl AcquireTenureFrameKind {
    fn try_from_wire(value: u16) -> Result<Self, AcquireTenureProtocolError> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            _ => Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::InvalidFrameKind,
            )),
        }
    }

    const fn maximum_payload_bytes(self) -> usize {
        match self {
            Self::Request => MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES,
            Self::Response => MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AcquireTenureFrameHeaderV1 {
    kind: AcquireTenureFrameKind,
    payload_bytes: u32,
}

impl AcquireTenureFrameHeaderV1 {
    pub(crate) fn decode_prefix(bytes: &[u8]) -> Result<Self, AcquireTenureProtocolError> {
        if bytes.len() < ACQUIRE_TENURE_FRAME_HEADER_BYTES {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::Truncated,
            ));
        }
        if &bytes[..ACQUIRE_FRAME_MAGIC.len()] != ACQUIRE_FRAME_MAGIC {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::InvalidMagic,
            ));
        }
        let version = read_u16(&bytes[8..10]);
        if version != ACQUIRE_TENURE_FRAME_VERSION {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::UnsupportedVersion,
            ));
        }
        let kind = AcquireTenureFrameKind::try_from_wire(read_u16(&bytes[10..12]))?;
        let payload_bytes = read_u32(&bytes[12..16]);
        if payload_bytes as usize > kind.maximum_payload_bytes() {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::InvalidFieldLength,
            ));
        }
        Ok(Self {
            kind,
            payload_bytes,
        })
    }

    #[must_use]
    pub(crate) const fn kind(self) -> AcquireTenureFrameKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn payload_bytes(self) -> u32 {
        self.payload_bytes
    }

    pub(crate) fn frame_bytes(self) -> Result<usize, AcquireTenureProtocolError> {
        ACQUIRE_TENURE_FRAME_HEADER_BYTES
            .checked_add(self.payload_bytes as usize)
            .ok_or_else(|| {
                AcquireTenureProtocolError::new(AcquireTenureProtocolErrorCode::InvalidFieldLength)
            })
    }
}

pub(crate) fn encode_acquire_tenure_request_frame(request: &AcquireTenureRequestV1) -> Box<[u8]> {
    build_frame(AcquireTenureFrameKind::Request, request.canonical_bytes())
}

pub(crate) fn decode_acquire_tenure_request_frame(
    frame: &[u8],
) -> Result<AcquireTenureRequestV1, AcquireTenureProtocolError> {
    let payload = decode_frame(frame, AcquireTenureFrameKind::Request)?;
    AcquireTenureRequestV1::decode(payload)
}

pub(crate) fn encode_acquire_tenure_response_frame(
    response: &AcquireTenureResponseV1,
) -> Box<[u8]> {
    build_frame(AcquireTenureFrameKind::Response, response.canonical_bytes())
}

pub(crate) fn decode_acquire_tenure_response_frame_for_request(
    frame: &[u8],
    request: &AcquireTenureRequestV1,
) -> Result<AcquireTenureResponseV1, AcquireTenureProtocolError> {
    let payload = decode_frame(frame, AcquireTenureFrameKind::Response)?;
    AcquireTenureResponseV1::decode_for_request(payload, request)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum AcquireTenureProtocolErrorCode {
    MessageTooLarge = 1,
    Truncated = 2,
    InvalidMagic = 3,
    UnsupportedVersion = 4,
    UnknownField = 5,
    MissingField = 6,
    DuplicateField = 7,
    OutOfOrderField = 8,
    InvalidFieldLength = 9,
    InvalidFieldValue = 10,
    DerivedDigestMismatch = 11,
    NonCanonicalMessage = 12,
    TrailingBytes = 13,
    InvalidFrameKind = 14,
    ResponseBoundExceeded = 15,
    RequestBindingMismatch = 16,
    DigestFailure = 17,
    ProofContract = 18,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AcquireTenureProtocolError {
    code: AcquireTenureProtocolErrorCode,
    field_tag: Option<u16>,
}

impl AcquireTenureProtocolError {
    const fn new(code: AcquireTenureProtocolErrorCode) -> Self {
        Self {
            code,
            field_tag: None,
        }
    }

    const fn at(code: AcquireTenureProtocolErrorCode, field_tag: u16) -> Self {
        Self {
            code,
            field_tag: Some(field_tag),
        }
    }

    #[must_use]
    pub(crate) const fn code(self) -> AcquireTenureProtocolErrorCode {
        self.code
    }

    #[must_use]
    pub(crate) const fn field_tag(self) -> Option<u16> {
        self.field_tag
    }
}

impl fmt::Display for AcquireTenureProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self.code {
            AcquireTenureProtocolErrorCode::MessageTooLarge => "message exceeds protocol bound",
            AcquireTenureProtocolErrorCode::Truncated => "message is truncated",
            AcquireTenureProtocolErrorCode::InvalidMagic => "protocol magic is invalid",
            AcquireTenureProtocolErrorCode::UnsupportedVersion => "protocol version is unsupported",
            AcquireTenureProtocolErrorCode::UnknownField => "field tag is unknown",
            AcquireTenureProtocolErrorCode::MissingField => "required field is missing",
            AcquireTenureProtocolErrorCode::DuplicateField => "field is duplicated",
            AcquireTenureProtocolErrorCode::OutOfOrderField => "field is out of order",
            AcquireTenureProtocolErrorCode::InvalidFieldLength => "field length is invalid",
            AcquireTenureProtocolErrorCode::InvalidFieldValue => "field value is invalid",
            AcquireTenureProtocolErrorCode::DerivedDigestMismatch => {
                "derived digest does not match"
            }
            AcquireTenureProtocolErrorCode::NonCanonicalMessage => "message is not canonical",
            AcquireTenureProtocolErrorCode::TrailingBytes => "message has trailing bytes",
            AcquireTenureProtocolErrorCode::InvalidFrameKind => "frame kind is invalid",
            AcquireTenureProtocolErrorCode::ResponseBoundExceeded => {
                "response exceeds the authenticated request bound"
            }
            AcquireTenureProtocolErrorCode::RequestBindingMismatch => {
                "response is not bound to the request"
            }
            AcquireTenureProtocolErrorCode::DigestFailure => "canonical digest construction failed",
            AcquireTenureProtocolErrorCode::ProofContract => {
                "embedded writer-tenure proof is invalid"
            }
        };
        if let Some(tag) = self.field_tag {
            write!(formatter, "{description} at field {tag}")
        } else {
            formatter.write_str(description)
        }
    }
}

impl std::error::Error for AcquireTenureProtocolError {}

fn build_request_signing_transcript(
    draft: &AcquireTenureRequestDraftV1,
) -> Result<AcquireTenureRequestSigningTranscriptV1, AcquireTenureProtocolError> {
    let mut bytes = Vec::with_capacity(MAX_ACQUIRE_TENURE_REQUEST_SIGNING_TRANSCRIPT_BYTES);
    bytes.extend_from_slice(REQUEST_AUTH_TRANSCRIPT_MAGIC);
    bytes.extend_from_slice(&ACQUIRE_TENURE_REQUEST_AUTH_TRANSCRIPT_VERSION.to_be_bytes());
    let domain_length = u16::try_from(REQUEST_AUTH_TRANSCRIPT_DOMAIN.len()).map_err(|_| {
        AcquireTenureProtocolError::new(AcquireTenureProtocolErrorCode::InvalidFieldLength)
    })?;
    bytes.extend_from_slice(&domain_length.to_be_bytes());
    bytes.extend_from_slice(REQUEST_AUTH_TRANSCRIPT_DOMAIN);
    bytes.extend_from_slice(&REQUEST_UNSIGNED_FIELD_COUNT.to_be_bytes());
    append_request_unsigned_fields(&mut bytes, draft);
    debug_assert!(bytes.len() <= MAX_ACQUIRE_TENURE_REQUEST_SIGNING_TRANSCRIPT_BYTES);
    Ok(AcquireTenureRequestSigningTranscriptV1(
        bytes.into_boxed_slice(),
    ))
}

fn append_request_unsigned_fields(bytes: &mut Vec<u8>, draft: &AcquireTenureRequestDraftV1) {
    append_tlv(bytes, 1, draft.intent.scope.as_bytes());
    append_tlv(bytes, 2, draft.intent.writer.as_bytes());
    append_tlv(bytes, 3, draft.intent.operation_id.as_bytes());
    append_tlv(bytes, 4, draft.controller_principal.as_bytes());
    append_tlv(bytes, 5, draft.controller_key.as_bytes());
    append_tlv(bytes, 6, draft.controller_public_key_fingerprint.as_bytes());
    append_tlv(bytes, 7, &ACQUIRE_TENURE_ED25519_ALGORITHM.to_be_bytes());
    append_tlv(
        bytes,
        8,
        &ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION.to_be_bytes(),
    );
    append_tlv(bytes, 9, &draft.client_nonce);
    append_tlv(bytes, 10, &draft.max_response_payload_bytes.to_be_bytes());
    append_tlv(bytes, 11, draft.intent_digest.as_bytes());
}

fn build_request_bytes(draft: &AcquireTenureRequestDraftV1, signature: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES);
    append_value_header(
        &mut bytes,
        ACQUIRE_REQUEST_MAGIC,
        ACQUIRE_TENURE_PROTOCOL_VERSION,
        REQUEST_FIELD_COUNT,
    );
    append_request_unsigned_fields(&mut bytes, draft);
    append_tlv(&mut bytes, 12, signature);
    bytes
}

fn decode_request(bytes: &[u8]) -> Result<AcquireTenureRequestV1, AcquireTenureProtocolError> {
    let fields = parse_value(
        bytes,
        ACQUIRE_REQUEST_MAGIC,
        ACQUIRE_TENURE_PROTOCOL_VERSION,
        REQUEST_FIELD_COUNT,
        MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES,
        valid_request_field_length,
    )?;
    let scope = DeploymentScopeId::from_bytes(read_array(fields.get(1), 1)?);
    let writer = DeploymentWriterRef::from_bytes(read_array(fields.get(2), 2)?);
    let operation_id = AcquireTenureOperationId::from_bytes(read_array(fields.get(3), 3)?);
    let controller_principal = PrincipalRef::from_bytes(read_array(fields.get(4), 4)?);
    let controller_key = ControllerAcquireKeyRef::from_bytes(read_array(fields.get(5), 5)?);
    let controller_public_key_fingerprint = ControllerPublicKeyFingerprint::from_digest_unchecked(
        Digest32::from_bytes(read_array(fields.get(6), 6)?),
    );
    validate_nonzero(scope.as_bytes(), 1)?;
    validate_nonzero(writer.as_bytes(), 2)?;
    validate_nonzero(operation_id.as_bytes(), 3)?;
    validate_nonzero(controller_principal.as_bytes(), 4)?;
    validate_nonzero(controller_key.as_bytes(), 5)?;
    validate_nonzero(controller_public_key_fingerprint.as_bytes(), 6)?;
    if read_u16(fields.get(7)) != ACQUIRE_TENURE_ED25519_ALGORITHM {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::InvalidFieldValue,
            7,
        ));
    }
    if read_u16(fields.get(8)) != ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::InvalidFieldValue,
            8,
        ));
    }
    let max_response_payload_bytes = read_u32(fields.get(10));
    let draft = AcquireTenureRequestDraftV1::try_new(
        AcquireTenureIntentV1::new(scope, writer, operation_id),
        controller_principal,
        controller_key,
        controller_public_key_fingerprint,
        fields.get(9),
        max_response_payload_bytes,
    )?;
    let carried_intent_digest =
        AcquireTenureIntentDigest::new(Digest32::from_bytes(read_array(fields.get(11), 11)?));
    if carried_intent_digest != draft.intent_digest {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::DerivedDigestMismatch,
            11,
        ));
    }
    let request = draft.finalize_ed25519(fields.get(12))?;
    if request.canonical_bytes() != bytes {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::NonCanonicalMessage,
        ));
    }
    Ok(request)
}

fn build_response_digest(
    operation_id: AcquireTenureOperationId,
    request_digest: AcquireTenureRequestDigest,
    client_nonce: &[u8],
    proof: &WriterTenureProof,
    proof_digest: Digest32,
) -> Result<AcquireTenureResponseDigest, AcquireTenureProtocolError> {
    let unsigned = build_response_unsigned_bytes(
        operation_id,
        request_digest,
        client_nonce,
        proof,
        proof_digest,
    );
    let mut builder = digest_builder(RESPONSE_DIGEST_DOMAIN)?;
    digest_bytes(&mut builder, &unsigned)?;
    Ok(AcquireTenureResponseDigest::new(builder.finish()))
}

fn build_response_unsigned_bytes(
    operation_id: AcquireTenureOperationId,
    request_digest: AcquireTenureRequestDigest,
    client_nonce: &[u8],
    proof: &WriterTenureProof,
    proof_digest: Digest32,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES);
    append_value_header(
        &mut bytes,
        ACQUIRE_RESPONSE_MAGIC,
        ACQUIRE_TENURE_PROTOCOL_VERSION,
        RESPONSE_UNSIGNED_FIELD_COUNT,
    );
    append_response_unsigned_fields(
        &mut bytes,
        operation_id,
        request_digest,
        client_nonce,
        proof,
        proof_digest,
    );
    bytes
}

fn append_response_unsigned_fields(
    bytes: &mut Vec<u8>,
    operation_id: AcquireTenureOperationId,
    request_digest: AcquireTenureRequestDigest,
    client_nonce: &[u8],
    proof: &WriterTenureProof,
    proof_digest: Digest32,
) {
    let authority = proof.authority();
    let claim = proof.claim();
    append_tlv(bytes, 1, operation_id.as_bytes());
    append_tlv(bytes, 2, request_digest.as_bytes());
    append_tlv(bytes, 3, client_nonce);
    append_tlv(bytes, 4, authority.authority().as_bytes());
    append_tlv(bytes, 5, authority.key().as_bytes());
    append_tlv(bytes, 6, &authority.algorithm().value().to_be_bytes());
    append_tlv(bytes, 7, &authority.algorithm_version().to_be_bytes());
    append_tlv(bytes, 8, claim.source_scope().as_bytes());
    append_tlv(bytes, 9, claim.writer().as_bytes());
    append_tlv(bytes, 10, &claim.epoch().value().to_be_bytes());
    append_tlv(
        bytes,
        11,
        &claim.supersedes_through_epoch().value().to_be_bytes(),
    );
    append_tlv(bytes, 12, proof.nonce());
    append_tlv(bytes, 13, proof.signature());
    append_tlv(bytes, 14, proof_digest.as_bytes());
}

fn build_response_bytes(
    operation_id: AcquireTenureOperationId,
    request_digest: AcquireTenureRequestDigest,
    client_nonce: &[u8],
    proof: &WriterTenureProof,
    proof_digest: Digest32,
    response_digest: AcquireTenureResponseDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES);
    append_value_header(
        &mut bytes,
        ACQUIRE_RESPONSE_MAGIC,
        ACQUIRE_TENURE_PROTOCOL_VERSION,
        RESPONSE_FIELD_COUNT,
    );
    append_response_unsigned_fields(
        &mut bytes,
        operation_id,
        request_digest,
        client_nonce,
        proof,
        proof_digest,
    );
    append_tlv(&mut bytes, 15, response_digest.as_bytes());
    bytes
}

fn decode_response(bytes: &[u8]) -> Result<AcquireTenureResponseV1, AcquireTenureProtocolError> {
    let fields = parse_value(
        bytes,
        ACQUIRE_RESPONSE_MAGIC,
        ACQUIRE_TENURE_PROTOCOL_VERSION,
        RESPONSE_FIELD_COUNT,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        valid_response_field_length,
    )?;
    let operation_id = AcquireTenureOperationId::from_bytes(read_array(fields.get(1), 1)?);
    let request_digest =
        AcquireTenureRequestDigest::new(Digest32::from_bytes(read_array(fields.get(2), 2)?));
    let authority_ref = TenureAuthorityRef::from_bytes(read_array(fields.get(4), 4)?);
    let key_ref = TenureKeyRef::from_bytes(read_array(fields.get(5), 5)?);
    let algorithm = TenureProofAlgorithm::try_new(read_u16(fields.get(6))).map_err(|_| {
        AcquireTenureProtocolError::at(AcquireTenureProtocolErrorCode::ProofContract, 6)
    })?;
    let authority =
        TenureProofAuthority::try_new(authority_ref, key_ref, algorithm, read_u16(fields.get(7)))
            .map_err(|_| {
            AcquireTenureProtocolError::at(AcquireTenureProtocolErrorCode::ProofContract, 7)
        })?;
    let claim = WriterTenureClaim::try_new(
        SourceScopeRef::from_bytes(read_array(fields.get(8), 8)?),
        PlanWriterRef::from_bytes(read_array(fields.get(9), 9)?),
        PlanWriterEpoch::new(read_u64(fields.get(10))),
        PlanWriterEpoch::new(read_u64(fields.get(11))),
    )
    .map_err(|_| {
        AcquireTenureProtocolError::at(AcquireTenureProtocolErrorCode::ProofContract, 10)
    })?;
    let proof = WriterTenureProof::try_new(authority, claim, fields.get(12), fields.get(13))
        .map_err(|_| {
            AcquireTenureProtocolError::at(AcquireTenureProtocolErrorCode::ProofContract, 13)
        })?;
    if fields.get(3) != proof.nonce() {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::RequestBindingMismatch,
            3,
        ));
    }
    let proof_digest = proof.envelope_digest().map_err(map_digest_error)?;
    let carried_proof_digest = Digest32::from_bytes(read_array(fields.get(14), 14)?);
    if proof_digest != carried_proof_digest {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::DerivedDigestMismatch,
            14,
        ));
    }
    let response_digest = build_response_digest(
        operation_id,
        request_digest,
        fields.get(3),
        &proof,
        proof_digest,
    )?;
    let carried_response_digest =
        AcquireTenureResponseDigest::new(Digest32::from_bytes(read_array(fields.get(15), 15)?));
    if response_digest != carried_response_digest {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::DerivedDigestMismatch,
            15,
        ));
    }
    let canonical_bytes = build_response_bytes(
        operation_id,
        request_digest,
        fields.get(3),
        &proof,
        proof_digest,
        response_digest,
    );
    if canonical_bytes.as_slice() != bytes {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::NonCanonicalMessage,
        ));
    }
    Ok(AcquireTenureResponseV1 {
        operation_id,
        request_digest,
        client_nonce: fields.get(3).into(),
        proof,
        proof_digest,
        response_digest,
        canonical_bytes: canonical_bytes.into_boxed_slice(),
    })
}

fn validate_proof_binding(
    request: &AcquireTenureRequestV1,
    proof: &WriterTenureProof,
) -> Result<(), AcquireTenureProtocolError> {
    let claim = proof.claim();
    if claim.source_scope().as_bytes() != request.scope().as_bytes()
        || claim.writer().as_bytes() != request.writer().as_bytes()
        || proof.nonce() != request.client_nonce()
    {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::RequestBindingMismatch,
        ));
    }
    Ok(())
}

fn digest_complete_request(
    canonical_bytes: &[u8],
) -> Result<AcquireTenureRequestDigest, AcquireTenureProtocolError> {
    let mut builder = digest_builder(REQUEST_DIGEST_DOMAIN)?;
    digest_bytes(&mut builder, canonical_bytes)?;
    Ok(AcquireTenureRequestDigest::new(builder.finish()))
}

fn build_frame(kind: AcquireTenureFrameKind, payload: &[u8]) -> Box<[u8]> {
    debug_assert!(payload.len() <= kind.maximum_payload_bytes());
    let mut frame = Vec::with_capacity(ACQUIRE_TENURE_FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(ACQUIRE_FRAME_MAGIC);
    frame.extend_from_slice(&ACQUIRE_TENURE_FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&(kind as u16).to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame.into_boxed_slice()
}

fn decode_frame(
    frame: &[u8],
    expected_kind: AcquireTenureFrameKind,
) -> Result<&[u8], AcquireTenureProtocolError> {
    if frame.len() > MAX_ACQUIRE_TENURE_FRAME_BYTES {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::MessageTooLarge,
        ));
    }
    let header = AcquireTenureFrameHeaderV1::decode_prefix(frame)?;
    if header.kind() != expected_kind {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::InvalidFrameKind,
        ));
    }
    let expected_frame_bytes = header.frame_bytes()?;
    if frame.len() < expected_frame_bytes {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::Truncated,
        ));
    }
    if frame.len() > expected_frame_bytes {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::TrailingBytes,
        ));
    }
    Ok(&frame[ACQUIRE_TENURE_FRAME_HEADER_BYTES..])
}

struct ParsedFields<'a> {
    values: Vec<&'a [u8]>,
}

impl ParsedFields<'_> {
    fn get(&self, tag: u16) -> &[u8] {
        self.values[usize::from(tag - 1)]
    }
}

fn parse_value<'a>(
    bytes: &'a [u8],
    magic: &[u8],
    expected_version: u16,
    expected_field_count: u16,
    maximum_bytes: usize,
    valid_length: fn(u16, usize) -> bool,
) -> Result<ParsedFields<'a>, AcquireTenureProtocolError> {
    if bytes.len() > maximum_bytes {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::MessageTooLarge,
        ));
    }
    if bytes.len() < magic.len() + 4 {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::Truncated,
        ));
    }
    if &bytes[..magic.len()] != magic {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::InvalidMagic,
        ));
    }
    let mut cursor = magic.len();
    let version = read_u16(&bytes[cursor..cursor + 2]);
    cursor += 2;
    if version != expected_version {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::UnsupportedVersion,
        ));
    }
    let declared_count = read_u16(&bytes[cursor..cursor + 2]);
    cursor += 2;

    let mut values = Vec::with_capacity(usize::from(declared_count.min(expected_field_count)));
    for index in 0..declared_count {
        let expected_tag = index + 1;
        let Some(header_end) = cursor.checked_add(TLV_HEADER_BYTES) else {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::Truncated,
            ));
        };
        if header_end > bytes.len() {
            return Err(AcquireTenureProtocolError::new(
                AcquireTenureProtocolErrorCode::Truncated,
            ));
        }
        let tag = read_u16(&bytes[cursor..cursor + 2]);
        let value_length = read_u32(&bytes[cursor + 2..header_end]) as usize;
        cursor = header_end;
        if tag == 0 || tag > expected_field_count {
            return Err(AcquireTenureProtocolError::at(
                AcquireTenureProtocolErrorCode::UnknownField,
                tag,
            ));
        }
        if tag < expected_tag {
            return Err(AcquireTenureProtocolError::at(
                AcquireTenureProtocolErrorCode::DuplicateField,
                tag,
            ));
        }
        if tag > expected_tag {
            return Err(AcquireTenureProtocolError::at(
                AcquireTenureProtocolErrorCode::OutOfOrderField,
                tag,
            ));
        }
        if !valid_length(tag, value_length) {
            return Err(AcquireTenureProtocolError::at(
                AcquireTenureProtocolErrorCode::InvalidFieldLength,
                tag,
            ));
        }
        let Some(value_end) = cursor.checked_add(value_length) else {
            return Err(AcquireTenureProtocolError::at(
                AcquireTenureProtocolErrorCode::Truncated,
                tag,
            ));
        };
        if value_end > bytes.len() {
            return Err(AcquireTenureProtocolError::at(
                AcquireTenureProtocolErrorCode::Truncated,
                tag,
            ));
        }
        values.push(&bytes[cursor..value_end]);
        cursor = value_end;
    }
    if declared_count < expected_field_count {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::MissingField,
            declared_count + 1,
        ));
    }
    if cursor != bytes.len() {
        return Err(AcquireTenureProtocolError::new(
            AcquireTenureProtocolErrorCode::TrailingBytes,
        ));
    }
    Ok(ParsedFields { values })
}

fn valid_request_field_length(tag: u16, length: usize) -> bool {
    match tag {
        1..=5 => length == 16,
        6 | 11 => length == 32,
        7 | 8 => length == 2,
        9 => (1..=MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES).contains(&length),
        10 => length == 4,
        12 => length == ACQUIRE_TENURE_ED25519_SIGNATURE_BYTES,
        _ => false,
    }
}

fn valid_response_field_length(tag: u16, length: usize) -> bool {
    match tag {
        1 | 4 | 5 | 8 | 9 => length == 16,
        2 | 14 | 15 => length == 32,
        3 => (1..=MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES).contains(&length),
        6 | 7 => length == 2,
        10 | 11 => length == 8,
        12 => (1..=MAX_TENURE_NONCE_BYTES).contains(&length),
        13 => (1..=MAX_TENURE_SIGNATURE_BYTES).contains(&length),
        _ => false,
    }
}

fn validate_nonzero(bytes: &[u8], tag: u16) -> Result<(), AcquireTenureProtocolError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::InvalidFieldValue,
            tag,
        ));
    }
    Ok(())
}

fn validate_client_nonce(nonce: &[u8], tag: u16) -> Result<(), AcquireTenureProtocolError> {
    if !(1..=MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES).contains(&nonce.len()) {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::InvalidFieldLength,
            tag,
        ));
    }
    Ok(())
}

fn validate_response_bound(bound: u32, tag: u16) -> Result<(), AcquireTenureProtocolError> {
    let bound = bound as usize;
    if !(MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES..=MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
        .contains(&bound)
    {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::InvalidFieldValue,
            tag,
        ));
    }
    Ok(())
}

fn validate_ed25519_signature(
    signature: &[u8],
    tag: u16,
) -> Result<(), AcquireTenureProtocolError> {
    if signature.len() != ACQUIRE_TENURE_ED25519_SIGNATURE_BYTES {
        return Err(AcquireTenureProtocolError::at(
            AcquireTenureProtocolErrorCode::InvalidFieldLength,
            tag,
        ));
    }
    Ok(())
}

fn append_value_header(bytes: &mut Vec<u8>, magic: &[u8], version: u16, field_count: u16) {
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&field_count.to_be_bytes());
}

fn append_tlv(bytes: &mut Vec<u8>, tag: u16, value: &[u8]) {
    bytes.extend_from_slice(&tag.to_be_bytes());
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn read_array<const N: usize>(
    bytes: &[u8],
    tag: u16,
) -> Result<[u8; N], AcquireTenureProtocolError> {
    bytes.try_into().map_err(|_| {
        AcquireTenureProtocolError::at(AcquireTenureProtocolErrorCode::InvalidFieldLength, tag)
    })
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn digest_builder(domain: &[u8]) -> Result<Digest32Builder, AcquireTenureProtocolError> {
    Digest32Builder::try_new(domain).map_err(map_digest_error)
}

fn digest_bytes(
    builder: &mut Digest32Builder,
    bytes: &[u8],
) -> Result<(), AcquireTenureProtocolError> {
    builder
        .field_bytes(bytes)
        .map(|_| ())
        .map_err(map_digest_error)
}

fn digest_u16(builder: &mut Digest32Builder, value: u16) -> Result<(), AcquireTenureProtocolError> {
    builder
        .field_u16(value)
        .map(|_| ())
        .map_err(map_digest_error)
}

fn map_digest_error(_: DigestBuildError) -> AcquireTenureProtocolError {
    AcquireTenureProtocolError::new(AcquireTenureProtocolErrorCode::DigestFailure)
}

#[cfg(test)]
mod tests {
    use core::ops::Range;

    use ed25519_dalek::{Signature, Signer, SigningKey};
    use paraegox_kernel::{digest::Digest32Builder, identity::PrincipalRef};
    use paraegox_runtime_contracts::apply::{
        PlanWriterEpoch, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
        TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
    };

    use super::{
        ACQUIRE_FRAME_MAGIC, ACQUIRE_REQUEST_MAGIC, ACQUIRE_RESPONSE_MAGIC,
        ACQUIRE_TENURE_ED25519_ALGORITHM, ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION,
        ACQUIRE_TENURE_ED25519_SIGNATURE_BYTES, ACQUIRE_TENURE_FRAME_HEADER_BYTES,
        ACQUIRE_TENURE_FRAME_VERSION, ACQUIRE_TENURE_PROTOCOL_VERSION,
        ACQUIRE_TENURE_REQUEST_AUTH_TRANSCRIPT_VERSION, AcquireTenureFrameHeaderV1,
        AcquireTenureFrameKind, AcquireTenureOperationId, AcquireTenureProtocolErrorCode,
        AcquireTenureRequestDraftV1, AcquireTenureRequestV1, AcquireTenureResponseV1,
        ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES, MAX_ACQUIRE_TENURE_FRAME_BYTES,
        MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES,
        MAX_ACQUIRE_TENURE_REQUEST_SIGNING_TRANSCRIPT_BYTES,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES, MIN_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES,
        MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES, REQUEST_FIELD_COUNT, RESPONSE_FIELD_COUNT,
        TLV_HEADER_BYTES, decode_acquire_tenure_request_frame,
        decode_acquire_tenure_response_frame_for_request, encode_acquire_tenure_request_frame,
        encode_acquire_tenure_response_frame, read_u16, read_u32,
    };
    use crate::plan::{DeploymentScopeId, DeploymentWriterRef};

    const CONTROLLER_SEED: [u8; 32] = [0x21; 32];
    const AUTHORITY_SEED: [u8; 32] = [0x43; 32];
    const TEST_NONCE: &[u8] = b"s7-d-client-nonce";

    #[derive(Clone, Debug)]
    struct TlvLocation {
        tag_offset: usize,
        length_offset: usize,
        value: Range<usize>,
    }

    fn draft_with(
        scope_byte: u8,
        writer_byte: u8,
        operation_byte: u8,
        principal_byte: u8,
        key_byte: u8,
        nonce: &[u8],
        response_bound: usize,
    ) -> AcquireTenureRequestDraftV1 {
        let signing_key = SigningKey::from_bytes(&CONTROLLER_SEED);
        let Ok(fingerprint) = ControllerPublicKeyFingerprint::for_ed25519_key(
            &signing_key.verifying_key().to_bytes(),
        ) else {
            panic!("controller key fingerprint must build");
        };
        let Ok(response_bound) = u32::try_from(response_bound) else {
            panic!("test response bound must fit u32");
        };
        let Ok(draft) = AcquireTenureRequestDraftV1::try_new(
            super::AcquireTenureIntentV1::new(
                DeploymentScopeId::from_bytes([scope_byte; 16]),
                DeploymentWriterRef::from_bytes([writer_byte; 16]),
                AcquireTenureOperationId::from_bytes([operation_byte; 16]),
            ),
            PrincipalRef::from_bytes([principal_byte; 16]),
            ControllerAcquireKeyRef::from_bytes([key_byte; 16]),
            fingerprint,
            nonce,
            response_bound,
        ) else {
            panic!("test acquire request draft must build");
        };
        draft
    }

    fn draft() -> AcquireTenureRequestDraftV1 {
        draft_with(
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            TEST_NONCE,
            MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        )
    }

    fn fingerprint(byte: u8) -> ControllerPublicKeyFingerprint {
        let Ok(fingerprint) = ControllerPublicKeyFingerprint::try_from_bytes([byte; 32]) else {
            panic!("test fingerprint must be nonzero");
        };
        fingerprint
    }

    fn request_from_draft(draft: AcquireTenureRequestDraftV1) -> AcquireTenureRequestV1 {
        let Ok(transcript) = draft.signing_transcript() else {
            panic!("test acquire transcript must build");
        };
        let signing_key = SigningKey::from_bytes(&CONTROLLER_SEED);
        let signature = signing_key.sign(transcript.as_bytes());
        let Ok(request) = draft.finalize_ed25519(&signature.to_bytes()) else {
            panic!("signed test acquire request must build");
        };
        request
    }

    fn request() -> AcquireTenureRequestV1 {
        request_from_draft(draft())
    }

    fn proof_for(
        request: &AcquireTenureRequestV1,
        epoch: u64,
        signature_override: Option<&[u8]>,
    ) -> WriterTenureProof {
        let Ok(algorithm) = TenureProofAlgorithm::try_new(1) else {
            panic!("test proof algorithm must build");
        };
        let Ok(authority) = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([0x66; 16]),
            TenureKeyRef::from_bytes([0x77; 16]),
            algorithm,
            1,
        ) else {
            panic!("test proof authority must build");
        };
        let Ok(claim) = WriterTenureClaim::try_new(
            request.proof_source_scope(),
            request.proof_writer(),
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(epoch - 1),
        ) else {
            panic!("test proof claim must build");
        };
        let signature_storage;
        let signature = if let Some(signature) = signature_override {
            signature
        } else {
            let Ok(transcript) =
                paraegox_runtime_contracts::apply::WriterTenureSigningTranscript::try_new(
                    authority,
                    claim,
                    request.client_nonce(),
                )
            else {
                panic!("test proof transcript must build");
            };
            let signing_key = SigningKey::from_bytes(&AUTHORITY_SEED);
            signature_storage = signing_key.sign(transcript.as_bytes()).to_bytes();
            &signature_storage
        };
        let Ok(proof) =
            WriterTenureProof::try_new(authority, claim, request.client_nonce(), signature)
        else {
            panic!("test tenure proof must build");
        };
        proof
    }

    fn response_for(request: &AcquireTenureRequestV1) -> AcquireTenureResponseV1 {
        let proof = proof_for(request, 9, None);
        let Ok(response) = AcquireTenureResponseV1::try_new(request, proof) else {
            panic!("test acquire response must build");
        };
        response
    }

    fn tlv_locations(bytes: &[u8], magic_bytes: usize) -> Vec<TlvLocation> {
        let count_offset = magic_bytes + 2;
        let count = read_u16(&bytes[count_offset..count_offset + 2]);
        let mut cursor = magic_bytes + 4;
        let mut locations = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let tag_offset = cursor;
            let length_offset = cursor + 2;
            let length = read_u32(&bytes[length_offset..length_offset + 4]) as usize;
            let value_start = cursor + TLV_HEADER_BYTES;
            let value_end = value_start + length;
            locations.push(TlvLocation {
                tag_offset,
                length_offset,
                value: value_start..value_end,
            });
            cursor = value_end;
        }
        locations
    }

    fn error_code<T>(
        result: Result<T, super::AcquireTenureProtocolError>,
    ) -> AcquireTenureProtocolErrorCode {
        let Err(error) = result else {
            panic!("test input must be rejected");
        };
        error.code()
    }

    fn digest_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
        let Ok(mut builder) = Digest32Builder::try_new(domain) else {
            panic!("test digest domain must build");
        };
        assert!(builder.field_bytes(bytes).is_ok());
        builder.finish().into_bytes()
    }

    fn signature_from_slice(bytes: &[u8]) -> Signature {
        let Ok(bytes) = <&[u8; ACQUIRE_TENURE_ED25519_SIGNATURE_BYTES]>::try_from(bytes) else {
            panic!("test signature must be 64 bytes");
        };
        Signature::from_bytes(bytes)
    }

    #[test]
    fn request_and_response_round_trip_with_exact_owned_proof() {
        let request = request();
        let Ok(decoded_request) = AcquireTenureRequestV1::decode(request.canonical_bytes()) else {
            panic!("canonical request must decode");
        };
        assert_eq!(decoded_request, request);
        assert_eq!(decoded_request.scope().as_bytes(), &[0x11; 16]);
        assert_eq!(decoded_request.writer().as_bytes(), &[0x22; 16]);
        assert_eq!(decoded_request.operation_id().as_bytes(), &[0x33; 16]);
        assert_eq!(
            decoded_request.controller_principal().as_bytes(),
            &[0x44; 16]
        );
        assert_eq!(decoded_request.controller_key().as_bytes(), &[0x55; 16]);
        assert_eq!(decoded_request.client_nonce(), TEST_NONCE);
        assert_eq!(decoded_request.auth_algorithm(), 1);
        assert_eq!(decoded_request.auth_algorithm_version(), 1);

        let response = response_for(&request);
        let Ok(decoded_response) =
            AcquireTenureResponseV1::decode_for_request(response.canonical_bytes(), &request)
        else {
            panic!("canonical response must decode for its request");
        };
        assert_eq!(decoded_response, response);
        assert_eq!(decoded_response.operation_id(), request.operation_id());
        assert_eq!(decoded_response.request_digest(), request.request_digest());
        assert_eq!(decoded_response.client_nonce(), request.client_nonce());
        assert_eq!(decoded_response.proof(), response.proof());
        assert_eq!(
            decoded_response.proof_digest(),
            &decoded_response
                .proof()
                .envelope_digest()
                .unwrap_or_else(|error| panic!("proof digest must build: {error}"))
        );
        assert_eq!(decoded_response.clone().into_proof(), *response.proof());
    }

    #[test]
    fn independent_ed25519_signatures_verify_strictly() {
        let request = request();
        let Ok(request_transcript) = request.signing_transcript() else {
            panic!("request transcript must build");
        };
        let controller_key = SigningKey::from_bytes(&CONTROLLER_SEED);
        assert!(
            controller_key
                .verifying_key()
                .verify_strict(
                    request_transcript.as_bytes(),
                    &signature_from_slice(request.auth_signature()),
                )
                .is_ok()
        );

        let response = response_for(&request);
        let Ok(proof_transcript) = response.proof().signing_transcript() else {
            panic!("runtime-owned proof transcript must build");
        };
        let authority_key = SigningKey::from_bytes(&AUTHORITY_SEED);
        assert!(
            authority_key
                .verifying_key()
                .verify_strict(
                    proof_transcript.as_bytes(),
                    &signature_from_slice(response.proof().signature()),
                )
                .is_ok()
        );
        assert_ne!(request_transcript.as_bytes(), proof_transcript.as_bytes());
    }

    #[test]
    fn request_and_response_frames_round_trip() {
        let request = request();
        let request_frame = encode_acquire_tenure_request_frame(&request);
        let Ok(header) = AcquireTenureFrameHeaderV1::decode_prefix(&request_frame) else {
            panic!("request frame header must decode");
        };
        assert_eq!(header.kind(), AcquireTenureFrameKind::Request);
        assert_eq!(
            header.payload_bytes() as usize,
            request.canonical_bytes().len()
        );
        assert_eq!(header.frame_bytes().ok(), Some(request_frame.len()));
        assert_eq!(
            decode_acquire_tenure_request_frame(&request_frame).ok(),
            Some(request.clone())
        );

        let response = response_for(&request);
        let response_frame = encode_acquire_tenure_response_frame(&response);
        let Ok(header) = AcquireTenureFrameHeaderV1::decode_prefix(&response_frame) else {
            panic!("response frame header must decode");
        };
        assert_eq!(header.kind(), AcquireTenureFrameKind::Response);
        assert_eq!(
            header.payload_bytes() as usize,
            response.canonical_bytes().len()
        );
        assert_eq!(
            decode_acquire_tenure_response_frame_for_request(&response_frame, &request).ok(),
            Some(response)
        );
    }

    #[test]
    fn auth_signature_is_excluded_from_transcript_but_included_in_request_digest() {
        let first_draft = draft();
        let second_draft = first_draft.clone();
        let Ok(first_transcript) = first_draft.signing_transcript() else {
            panic!("first transcript must build");
        };
        let Ok(second_transcript) = second_draft.signing_transcript() else {
            panic!("second transcript must build");
        };
        let Ok(first) = first_draft.finalize_ed25519(&[0x81; 64]) else {
            panic!("first request must finalize");
        };
        let Ok(second) = second_draft.finalize_ed25519(&[0x82; 64]) else {
            panic!("second request must finalize");
        };
        assert_eq!(first_transcript, second_transcript);
        assert_ne!(first.canonical_bytes(), second.canonical_bytes());
        assert_ne!(first.request_digest(), second.request_digest());
    }

    #[test]
    fn same_operation_and_exact_request_have_stable_digest() {
        let first = request();
        let second = request();
        assert_eq!(first.operation_id(), second.operation_id());
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(first.request_digest(), second.request_digest());

        let proof = proof_for(&first, 3, None);
        let Ok(first_response) = AcquireTenureResponseV1::try_new(&first, proof.clone()) else {
            panic!("first deterministic response must build");
        };
        let Ok(second_response) = AcquireTenureResponseV1::try_new(&second, proof) else {
            panic!("second deterministic response must build");
        };
        assert_eq!(
            first_response.canonical_bytes(),
            second_response.canonical_bytes()
        );
        assert_eq!(
            first_response.response_digest(),
            second_response.response_digest()
        );

        let changed = request_from_draft(draft_with(
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            b"different-nonce",
            MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        ));
        assert_eq!(first.operation_id(), changed.operation_id());
        assert_ne!(first.canonical_bytes(), changed.canonical_bytes());
        assert_ne!(first.request_digest(), changed.request_digest());
    }

    #[test]
    fn every_unsigned_request_field_is_in_the_auth_transcript() {
        let baseline = draft();
        let Ok(baseline_transcript) = baseline.signing_transcript() else {
            panic!("baseline transcript must build");
        };

        let variants = [
            draft_with(
                0x12,
                0x22,
                0x33,
                0x44,
                0x55,
                TEST_NONCE,
                MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
            ),
            draft_with(
                0x11,
                0x23,
                0x33,
                0x44,
                0x55,
                TEST_NONCE,
                MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
            ),
            draft_with(
                0x11,
                0x22,
                0x34,
                0x44,
                0x55,
                TEST_NONCE,
                MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
            ),
            draft_with(
                0x11,
                0x22,
                0x33,
                0x45,
                0x55,
                TEST_NONCE,
                MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
            ),
            draft_with(
                0x11,
                0x22,
                0x33,
                0x44,
                0x56,
                TEST_NONCE,
                MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
            ),
            draft_with(
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                b"changed-nonce",
                MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
            ),
            draft_with(
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                TEST_NONCE,
                MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES - 1,
            ),
        ];
        for variant in variants {
            let Ok(transcript) = variant.signing_transcript() else {
                panic!("variant transcript must build");
            };
            assert_ne!(transcript, baseline_transcript);
        }

        let mut changed_fingerprint = baseline.clone();
        changed_fingerprint.controller_public_key_fingerprint = fingerprint(0x99);
        let Ok(changed_fingerprint_transcript) = changed_fingerprint.signing_transcript() else {
            panic!("changed fingerprint transcript must build");
        };
        assert_ne!(changed_fingerprint_transcript, baseline_transcript);

        let mut changed_intent_digest = baseline.clone();
        changed_intent_digest.intent_digest = super::AcquireTenureIntentDigest::new(
            paraegox_kernel::digest::Digest32::from_bytes([0xaa; 32]),
        );
        let Ok(changed_intent_transcript) = changed_intent_digest.signing_transcript() else {
            panic!("changed intent digest transcript must build");
        };
        assert_ne!(changed_intent_transcript, baseline_transcript);

        let transcript = baseline_transcript.as_bytes();
        assert!(transcript.starts_with(super::REQUEST_AUTH_TRANSCRIPT_MAGIC));
        assert!(
            transcript
                .windows(super::REQUEST_AUTH_TRANSCRIPT_DOMAIN.len())
                .any(|window| window == super::REQUEST_AUTH_TRANSCRIPT_DOMAIN)
        );
    }

    #[test]
    fn protocol_magics_domains_and_versions_are_independent() {
        assert_ne!(ACQUIRE_REQUEST_MAGIC, ACQUIRE_RESPONSE_MAGIC);
        assert_ne!(ACQUIRE_REQUEST_MAGIC, ACQUIRE_FRAME_MAGIC);
        assert_ne!(ACQUIRE_RESPONSE_MAGIC, ACQUIRE_FRAME_MAGIC);
        assert_ne!(super::INTENT_DIGEST_DOMAIN, super::REQUEST_DIGEST_DOMAIN);
        assert_ne!(super::REQUEST_DIGEST_DOMAIN, super::RESPONSE_DIGEST_DOMAIN);
        assert_ne!(
            super::REQUEST_AUTH_TRANSCRIPT_DOMAIN,
            paraegox_runtime_contracts::apply::WRITER_TENURE_SIGNING_TRANSCRIPT_VERSION
                .to_be_bytes()
                .as_slice()
        );
        assert_eq!(ACQUIRE_TENURE_PROTOCOL_VERSION, 1);
        assert_eq!(ACQUIRE_TENURE_FRAME_VERSION, 1);
        assert_eq!(ACQUIRE_TENURE_REQUEST_AUTH_TRANSCRIPT_VERSION, 1);
        assert_eq!(ACQUIRE_TENURE_ED25519_ALGORITHM, 1);
        assert_eq!(ACQUIRE_TENURE_ED25519_ALGORITHM_VERSION, 1);
    }

    #[test]
    fn golden_vectors_freeze_request_transcript_and_response() {
        let request = request();
        let Ok(transcript) = request.signing_transcript() else {
            panic!("golden request transcript must build");
        };
        let response = response_for(&request);
        let response_frame = encode_acquire_tenure_response_frame(&response);

        assert_eq!(request.canonical_bytes().len(), 317);
        assert_eq!(transcript.as_bytes().len(), 335);
        assert_eq!(response.canonical_bytes().len(), 396);
        assert_eq!(response_frame.len(), 412);
        assert_eq!(
            request.controller_public_key_fingerprint().as_bytes(),
            &[
                0xa1, 0x3c, 0x6e, 0x77, 0x91, 0x3b, 0x3b, 0x11, 0x5d, 0xfd, 0xfc, 0x72, 0x55, 0x0e,
                0x88, 0xaf, 0x12, 0xfe, 0x60, 0x79, 0xe7, 0xc8, 0xf8, 0x97, 0xf1, 0x5d, 0xaa, 0xaa,
                0xdf, 0xb7, 0x2e, 0xfa,
            ]
        );
        assert_eq!(
            request.intent_digest().as_bytes(),
            &[
                0x54, 0xc5, 0x0d, 0xbc, 0x7d, 0x32, 0xb6, 0xd6, 0x66, 0xdd, 0x1e, 0xb3, 0xb4, 0x66,
                0x7d, 0x54, 0x08, 0xc6, 0x66, 0xbd, 0xa0, 0xa9, 0xa9, 0xd5, 0x94, 0x4f, 0x69, 0x14,
                0x7c, 0xf1, 0x07, 0xb9,
            ]
        );
        assert_eq!(
            request.request_digest().as_bytes(),
            &[
                0xba, 0xf7, 0xfb, 0x6d, 0xa5, 0x76, 0x50, 0xa7, 0xb6, 0xd3, 0x42, 0xbb, 0x11, 0xfa,
                0x72, 0xf7, 0x03, 0x12, 0xe7, 0xe5, 0x25, 0xb7, 0xf4, 0x62, 0xc0, 0x07, 0x1a, 0x26,
                0x15, 0x20, 0xba, 0x18,
            ]
        );
        assert_eq!(
            response.proof_digest().as_bytes(),
            &[
                0xcc, 0x0f, 0x0f, 0x8c, 0xf5, 0xad, 0x3f, 0x46, 0xbd, 0x51, 0x86, 0xb2, 0x48, 0x78,
                0x1e, 0xb4, 0x77, 0xe3, 0xaa, 0x04, 0x1a, 0x03, 0xdf, 0xc4, 0xaa, 0xde, 0x82, 0xd9,
                0x08, 0xa7, 0x69, 0x38,
            ]
        );
        assert_eq!(
            response.response_digest().as_bytes(),
            &[
                0x35, 0x7e, 0xe2, 0xed, 0xab, 0xd0, 0xb6, 0x4e, 0x0b, 0x69, 0x3f, 0x88, 0x70, 0x42,
                0xab, 0x6c, 0x29, 0x5c, 0xac, 0x7d, 0x25, 0xf2, 0x1f, 0x2f, 0xda, 0xc1, 0x6c, 0xa9,
                0x99, 0x41, 0x49, 0x82,
            ]
        );
        assert_eq!(
            digest_bytes(
                b"paraegox.test.acquire-tenure-transcript-golden.v1",
                transcript.as_bytes(),
            ),
            [
                0x16, 0x0f, 0x3c, 0x85, 0x11, 0xfb, 0x3a, 0x08, 0x56, 0xf3, 0x9d, 0x82, 0x24, 0x85,
                0x76, 0x57, 0x13, 0x63, 0x94, 0xd5, 0xae, 0x6a, 0x80, 0xba, 0x09, 0xc4, 0x47, 0x5a,
                0x92, 0x5f, 0xcb, 0xcf,
            ]
        );
        assert_eq!(
            digest_bytes(
                b"paraegox.test.acquire-tenure-response-frame-golden.v1",
                &response_frame,
            ),
            [
                0x46, 0xc6, 0xee, 0xbe, 0x33, 0xd7, 0x60, 0xda, 0xc3, 0x9c, 0x82, 0x33, 0x42, 0xfc,
                0x0a, 0xbb, 0x79, 0x7a, 0xd9, 0xbf, 0xbe, 0x05, 0xab, 0x06, 0xa6, 0x0c, 0xd3, 0x98,
                0x45, 0x8c, 0x86, 0xe5,
            ]
        );
    }

    #[test]
    fn request_exact_and_plus_one_bounds_are_enforced() {
        let max_nonce = [0x91; MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES];
        let max_request = request_from_draft(draft_with(
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            &max_nonce,
            MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        ));
        assert_eq!(
            max_request.canonical_bytes().len(),
            MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES
        );
        let Ok(max_transcript) = max_request.signing_transcript() else {
            panic!("maximum bounded transcript must build");
        };
        assert_eq!(
            max_transcript.as_bytes().len(),
            MAX_ACQUIRE_TENURE_REQUEST_SIGNING_TRANSCRIPT_BYTES
        );
        assert!(AcquireTenureRequestV1::decode(max_request.canonical_bytes()).is_ok());
        let mut plus_one = max_request.canonical_bytes().to_vec();
        plus_one.push(0);
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&plus_one)),
            AcquireTenureProtocolErrorCode::MessageTooLarge
        );
        assert_eq!(
            error_code(AcquireTenureRequestDraftV1::try_new(
                super::AcquireTenureIntentV1::new(
                    DeploymentScopeId::from_bytes([1; 16]),
                    DeploymentWriterRef::from_bytes([2; 16]),
                    AcquireTenureOperationId::from_bytes([3; 16]),
                ),
                PrincipalRef::from_bytes([4; 16]),
                ControllerAcquireKeyRef::from_bytes([5; 16]),
                fingerprint(6),
                &[7; MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES + 1],
                MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES as u32,
            )),
            AcquireTenureProtocolErrorCode::InvalidFieldLength
        );
        assert_eq!(
            error_code(draft().finalize_ed25519(&[0; 63])),
            AcquireTenureProtocolErrorCode::InvalidFieldLength
        );
        assert_eq!(
            error_code(draft().finalize_ed25519(&[0; 65])),
            AcquireTenureProtocolErrorCode::InvalidFieldLength
        );
    }

    #[test]
    fn zero_identities_selectors_and_fingerprint_fail_in_field_order() {
        for field_tag in 1_u16..=6 {
            let scope_byte = if field_tag == 1 { 0 } else { 1 };
            let writer_byte = if field_tag == 2 { 0 } else { 2 };
            let operation_byte = if field_tag == 3 { 0 } else { 3 };
            let principal_byte = if field_tag == 4 { 0 } else { 4 };
            let key_byte = if field_tag == 5 { 0 } else { 5 };
            let fingerprint_byte = if field_tag == 6 { 0 } else { 6 };
            let result = AcquireTenureRequestDraftV1::try_new(
                super::AcquireTenureIntentV1::new(
                    DeploymentScopeId::from_bytes([scope_byte; 16]),
                    DeploymentWriterRef::from_bytes([writer_byte; 16]),
                    AcquireTenureOperationId::from_bytes([operation_byte; 16]),
                ),
                PrincipalRef::from_bytes([principal_byte; 16]),
                ControllerAcquireKeyRef::from_bytes([key_byte; 16]),
                ControllerPublicKeyFingerprint::from_digest_unchecked(
                    paraegox_kernel::digest::Digest32::from_bytes([fingerprint_byte; 32]),
                ),
                TEST_NONCE,
                MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES as u32,
            );
            let Err(error) = result else {
                panic!("zero request field {field_tag} must fail");
            };
            assert_eq!(
                error.code(),
                AcquireTenureProtocolErrorCode::InvalidFieldValue
            );
            assert_eq!(error.field_tag(), Some(field_tag));

            let request = request();
            let locations = tlv_locations(request.canonical_bytes(), ACQUIRE_REQUEST_MAGIC.len());
            let mut zero_wire = request.canonical_bytes().to_vec();
            zero_wire[locations[usize::from(field_tag - 1)].value.clone()].fill(0);
            let Err(error) = AcquireTenureRequestV1::decode(&zero_wire) else {
                panic!("zero wire field {field_tag} must fail");
            };
            assert_eq!(
                error.code(),
                AcquireTenureProtocolErrorCode::InvalidFieldValue
            );
            assert_eq!(error.field_tag(), Some(field_tag));
        }

        let Err(error) = ControllerPublicKeyFingerprint::try_from_bytes([0; 32]) else {
            panic!("zero controller key fingerprint must fail");
        };
        assert_eq!(
            error.code(),
            AcquireTenureProtocolErrorCode::InvalidFieldValue
        );
        assert_eq!(error.field_tag(), Some(6));

        let request = request();
        let locations = tlv_locations(request.canonical_bytes(), ACQUIRE_REQUEST_MAGIC.len());
        let mut two_semantic_errors = request.canonical_bytes().to_vec();
        two_semantic_errors[locations[0].value.clone()].fill(0);
        two_semantic_errors[locations[6].value.clone()].copy_from_slice(&2_u16.to_be_bytes());
        let Err(error) = AcquireTenureRequestV1::decode(&two_semantic_errors) else {
            panic!("combined semantic mutations must fail");
        };
        assert_eq!(
            error.code(),
            AcquireTenureProtocolErrorCode::InvalidFieldValue
        );
        assert_eq!(error.field_tag(), Some(1));
    }

    #[test]
    fn response_exact_and_plus_one_bounds_are_enforced() {
        let min_request = request_from_draft(draft_with(
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            b"n",
            MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        ));
        let min_proof = proof_for(&min_request, 1, Some(&[0x61; 1]));
        let Ok(min_response) = AcquireTenureResponseV1::try_new(&min_request, min_proof) else {
            panic!("minimum runtime-owned proof response must build");
        };
        assert_eq!(
            min_response.canonical_bytes().len(),
            MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES
        );

        let max_nonce = [0x71; MAX_ACQUIRE_TENURE_CLIENT_NONCE_BYTES];
        let max_request = request_from_draft(draft_with(
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            &max_nonce,
            MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        ));
        let max_signature = [0x72; paraegox_runtime_contracts::apply::MAX_TENURE_SIGNATURE_BYTES];
        let max_proof = proof_for(&max_request, 2, Some(&max_signature));
        let Ok(max_response) = AcquireTenureResponseV1::try_new(&max_request, max_proof) else {
            panic!("maximum bounded response must build");
        };
        assert_eq!(
            max_response.canonical_bytes().len(),
            MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES
        );
        assert!(AcquireTenureResponseV1::decode(max_response.canonical_bytes()).is_ok());
        let max_frame = encode_acquire_tenure_response_frame(&max_response);
        assert_eq!(max_frame.len(), MAX_ACQUIRE_TENURE_FRAME_BYTES);
        assert!(decode_acquire_tenure_response_frame_for_request(&max_frame, &max_request).is_ok());
        let mut plus_one_frame = max_frame.to_vec();
        plus_one_frame.push(0);
        assert_eq!(
            error_code(decode_acquire_tenure_response_frame_for_request(
                &plus_one_frame,
                &max_request,
            )),
            AcquireTenureProtocolErrorCode::MessageTooLarge
        );
        let mut plus_one = max_response.canonical_bytes().to_vec();
        plus_one.push(0);
        assert_eq!(
            error_code(AcquireTenureResponseV1::decode(&plus_one)),
            AcquireTenureProtocolErrorCode::MessageTooLarge
        );
    }

    #[test]
    fn signed_response_bound_is_checked_at_construction_and_decode() {
        assert_eq!(
            error_code(AcquireTenureRequestDraftV1::try_new(
                super::AcquireTenureIntentV1::new(
                    DeploymentScopeId::from_bytes([1; 16]),
                    DeploymentWriterRef::from_bytes([2; 16]),
                    AcquireTenureOperationId::from_bytes([3; 16]),
                ),
                PrincipalRef::from_bytes([4; 16]),
                ControllerAcquireKeyRef::from_bytes([5; 16]),
                fingerprint(6),
                b"n",
                (MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES - 1) as u32,
            )),
            AcquireTenureProtocolErrorCode::InvalidFieldValue
        );
        assert_eq!(
            error_code(AcquireTenureRequestDraftV1::try_new(
                super::AcquireTenureIntentV1::new(
                    DeploymentScopeId::from_bytes([1; 16]),
                    DeploymentWriterRef::from_bytes([2; 16]),
                    AcquireTenureOperationId::from_bytes([3; 16]),
                ),
                PrincipalRef::from_bytes([4; 16]),
                ControllerAcquireKeyRef::from_bytes([5; 16]),
                fingerprint(6),
                b"n",
                (MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES + 1) as u32,
            )),
            AcquireTenureProtocolErrorCode::InvalidFieldValue
        );

        let too_small_request = request_from_draft(draft_with(
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            b"n",
            MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        ));
        let large_proof = proof_for(&too_small_request, 2, Some(&[0x31; 65]));
        assert_eq!(
            error_code(AcquireTenureResponseV1::try_new(
                &too_small_request,
                large_proof,
            )),
            AcquireTenureProtocolErrorCode::ResponseBoundExceeded
        );
    }

    #[test]
    fn request_malformed_inputs_have_stable_precedence() {
        let request = request();
        let wire = request.canonical_bytes();
        let locations = tlv_locations(wire, ACQUIRE_REQUEST_MAGIC.len());
        let version_offset = ACQUIRE_REQUEST_MAGIC.len();
        let count_offset = version_offset + 2;

        let mut invalid_magic = wire.to_vec();
        invalid_magic[0] ^= 1;
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&invalid_magic)),
            AcquireTenureProtocolErrorCode::InvalidMagic
        );
        let mut unsupported_version = wire.to_vec();
        unsupported_version[version_offset..version_offset + 2]
            .copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&unsupported_version)),
            AcquireTenureProtocolErrorCode::UnsupportedVersion
        );
        let mut duplicate = wire.to_vec();
        duplicate[locations[1].tag_offset..locations[1].tag_offset + 2]
            .copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&duplicate)),
            AcquireTenureProtocolErrorCode::DuplicateField
        );
        let mut out_of_order = wire.to_vec();
        out_of_order[locations[1].tag_offset..locations[1].tag_offset + 2]
            .copy_from_slice(&3_u16.to_be_bytes());
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&out_of_order)),
            AcquireTenureProtocolErrorCode::OutOfOrderField
        );
        let mut length_bomb = wire.to_vec();
        length_bomb[locations[8].length_offset..locations[8].length_offset + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        length_bomb.truncate(locations[8].value.start);
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&length_bomb)),
            AcquireTenureProtocolErrorCode::InvalidFieldLength
        );
        let mut missing = wire[..locations[11].tag_offset].to_vec();
        missing[count_offset..count_offset + 2].copy_from_slice(&11_u16.to_be_bytes());
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&missing)),
            AcquireTenureProtocolErrorCode::MissingField
        );
        let mut unknown = wire.to_vec();
        unknown[count_offset..count_offset + 2].copy_from_slice(&13_u16.to_be_bytes());
        unknown.extend_from_slice(&13_u16.to_be_bytes());
        unknown.extend_from_slice(&1_u32.to_be_bytes());
        unknown.push(0);
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&unknown)),
            AcquireTenureProtocolErrorCode::UnknownField
        );
        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&trailing)),
            AcquireTenureProtocolErrorCode::TrailingBytes
        );
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&wire[..wire.len() - 1])),
            AcquireTenureProtocolErrorCode::Truncated
        );
        let oversized = vec![0; MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES + 1];
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&oversized)),
            AcquireTenureProtocolErrorCode::MessageTooLarge
        );
        assert_eq!(REQUEST_FIELD_COUNT as usize, locations.len());
    }

    #[test]
    fn request_derived_and_semantic_mutations_are_rejected() {
        let request = request();
        let locations = tlv_locations(request.canonical_bytes(), ACQUIRE_REQUEST_MAGIC.len());

        let mut intent_digest = request.canonical_bytes().to_vec();
        intent_digest[locations[10].value.start] ^= 1;
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&intent_digest)),
            AcquireTenureProtocolErrorCode::DerivedDigestMismatch
        );
        let mut algorithm = request.canonical_bytes().to_vec();
        algorithm[locations[6].value.clone()].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&algorithm)),
            AcquireTenureProtocolErrorCode::InvalidFieldValue
        );
        let mut algorithm_version = request.canonical_bytes().to_vec();
        algorithm_version[locations[7].value.clone()].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            error_code(AcquireTenureRequestV1::decode(&algorithm_version)),
            AcquireTenureProtocolErrorCode::InvalidFieldValue
        );
    }

    #[test]
    fn every_request_field_mutation_is_rejected_or_rebound() {
        let baseline = request();
        let Ok(baseline_transcript) = baseline.signing_transcript() else {
            panic!("baseline request transcript must build");
        };
        let locations = tlv_locations(baseline.canonical_bytes(), ACQUIRE_REQUEST_MAGIC.len());
        for (index, location) in locations.iter().enumerate() {
            let tag = index as u16 + 1;
            let mut changed = baseline.canonical_bytes().to_vec();
            let last_value_byte = location.value.end - 1;
            changed[last_value_byte] ^= 1;
            match AcquireTenureRequestV1::decode(&changed) {
                Ok(decoded) => {
                    assert_ne!(decoded.request_digest(), baseline.request_digest());
                    let Ok(decoded_transcript) = decoded.signing_transcript() else {
                        panic!("mutated request transcript must build");
                    };
                    if tag == REQUEST_FIELD_COUNT {
                        assert_eq!(decoded_transcript, baseline_transcript);
                    } else {
                        assert_ne!(decoded_transcript, baseline_transcript);
                    }
                }
                Err(error) => assert!(matches!(
                    error.code(),
                    AcquireTenureProtocolErrorCode::InvalidFieldValue
                        | AcquireTenureProtocolErrorCode::DerivedDigestMismatch
                )),
            }
        }
    }

    #[test]
    fn response_malformed_inputs_and_digest_precedence_are_stable() {
        let request = request();
        let response = response_for(&request);
        let wire = response.canonical_bytes();
        let locations = tlv_locations(wire, ACQUIRE_RESPONSE_MAGIC.len());
        let count_offset = ACQUIRE_RESPONSE_MAGIC.len() + 2;

        let mut duplicate = wire.to_vec();
        duplicate[locations[1].tag_offset..locations[1].tag_offset + 2]
            .copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            error_code(AcquireTenureResponseV1::decode(&duplicate)),
            AcquireTenureProtocolErrorCode::DuplicateField
        );
        let mut out_of_order = wire.to_vec();
        out_of_order[locations[1].tag_offset..locations[1].tag_offset + 2]
            .copy_from_slice(&3_u16.to_be_bytes());
        assert_eq!(
            error_code(AcquireTenureResponseV1::decode(&out_of_order)),
            AcquireTenureProtocolErrorCode::OutOfOrderField
        );
        let mut proof_digest_and_response_digest = wire.to_vec();
        proof_digest_and_response_digest[locations[13].value.start] ^= 1;
        proof_digest_and_response_digest[locations[14].value.start] ^= 1;
        let Err(error) = AcquireTenureResponseV1::decode(&proof_digest_and_response_digest) else {
            panic!("mutated digests must fail");
        };
        assert_eq!(
            error.code(),
            AcquireTenureProtocolErrorCode::DerivedDigestMismatch
        );
        assert_eq!(error.field_tag(), Some(14));
        let mut response_digest = wire.to_vec();
        response_digest[locations[14].value.start] ^= 1;
        let Err(error) = AcquireTenureResponseV1::decode(&response_digest) else {
            panic!("mutated response digest must fail");
        };
        assert_eq!(
            error.code(),
            AcquireTenureProtocolErrorCode::DerivedDigestMismatch
        );
        assert_eq!(error.field_tag(), Some(15));
        let mut length_bomb = wire.to_vec();
        length_bomb[locations[12].length_offset..locations[12].length_offset + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        length_bomb.truncate(locations[12].value.start);
        assert_eq!(
            error_code(AcquireTenureResponseV1::decode(&length_bomb)),
            AcquireTenureProtocolErrorCode::InvalidFieldLength
        );
        let mut missing = wire[..locations[14].tag_offset].to_vec();
        missing[count_offset..count_offset + 2].copy_from_slice(&14_u16.to_be_bytes());
        assert_eq!(
            error_code(AcquireTenureResponseV1::decode(&missing)),
            AcquireTenureProtocolErrorCode::MissingField
        );
        let mut unknown = wire.to_vec();
        unknown[count_offset..count_offset + 2].copy_from_slice(&16_u16.to_be_bytes());
        unknown.extend_from_slice(&16_u16.to_be_bytes());
        unknown.extend_from_slice(&1_u32.to_be_bytes());
        unknown.push(0);
        assert_eq!(
            error_code(AcquireTenureResponseV1::decode(&unknown)),
            AcquireTenureProtocolErrorCode::UnknownField
        );
        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert_eq!(
            error_code(AcquireTenureResponseV1::decode(&trailing)),
            AcquireTenureProtocolErrorCode::TrailingBytes
        );
        assert_eq!(RESPONSE_FIELD_COUNT as usize, locations.len());
    }

    #[test]
    fn every_response_field_mutation_fails_closed() {
        let request = request();
        let response = response_for(&request);
        let locations = tlv_locations(response.canonical_bytes(), ACQUIRE_RESPONSE_MAGIC.len());
        for location in locations {
            let mut changed = response.canonical_bytes().to_vec();
            changed[location.value.end - 1] ^= 1;
            assert!(AcquireTenureResponseV1::decode(&changed).is_err());
        }
    }

    #[test]
    fn response_rejects_wrong_scope_writer_nonce_and_request_echoes() {
        let request = request();
        let wrong_scope_request = request_from_draft(draft_with(
            0x12,
            0x22,
            0x33,
            0x44,
            0x55,
            TEST_NONCE,
            MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        ));
        let wrong_scope_proof = proof_for(&wrong_scope_request, 2, None);
        assert_eq!(
            error_code(AcquireTenureResponseV1::try_new(
                &request,
                wrong_scope_proof,
            )),
            AcquireTenureProtocolErrorCode::RequestBindingMismatch
        );

        let wrong_writer_request = request_from_draft(draft_with(
            0x11,
            0x23,
            0x33,
            0x44,
            0x55,
            TEST_NONCE,
            MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        ));
        let wrong_writer_proof = proof_for(&wrong_writer_request, 2, None);
        assert_eq!(
            error_code(AcquireTenureResponseV1::try_new(
                &request,
                wrong_writer_proof,
            )),
            AcquireTenureProtocolErrorCode::RequestBindingMismatch
        );

        let other_request = request_from_draft(draft_with(
            0x11,
            0x22,
            0x34,
            0x44,
            0x55,
            TEST_NONCE,
            MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        ));
        let response = response_for(&request);
        assert_eq!(
            error_code(AcquireTenureResponseV1::decode_for_request(
                response.canonical_bytes(),
                &other_request,
            )),
            AcquireTenureProtocolErrorCode::RequestBindingMismatch
        );
    }

    #[test]
    fn frame_malformed_inputs_and_length_bombs_have_stable_precedence() {
        let request = request();
        let frame = encode_acquire_tenure_request_frame(&request);

        let mut invalid_magic = frame.to_vec();
        invalid_magic[0] ^= 1;
        assert_eq!(
            error_code(decode_acquire_tenure_request_frame(&invalid_magic)),
            AcquireTenureProtocolErrorCode::InvalidMagic
        );
        let mut unsupported_version = frame.to_vec();
        unsupported_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            error_code(decode_acquire_tenure_request_frame(&unsupported_version)),
            AcquireTenureProtocolErrorCode::UnsupportedVersion
        );
        let mut invalid_kind = frame.to_vec();
        invalid_kind[10..12].copy_from_slice(&3_u16.to_be_bytes());
        assert_eq!(
            error_code(decode_acquire_tenure_request_frame(&invalid_kind)),
            AcquireTenureProtocolErrorCode::InvalidFrameKind
        );
        let mut wrong_kind = frame.to_vec();
        wrong_kind[10..12]
            .copy_from_slice(&(AcquireTenureFrameKind::Response as u16).to_be_bytes());
        assert_eq!(
            error_code(decode_acquire_tenure_request_frame(&wrong_kind)),
            AcquireTenureProtocolErrorCode::InvalidFrameKind
        );
        let mut length_bomb = frame[..ACQUIRE_TENURE_FRAME_HEADER_BYTES].to_vec();
        length_bomb[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            error_code(decode_acquire_tenure_request_frame(&length_bomb)),
            AcquireTenureProtocolErrorCode::InvalidFieldLength
        );
        let mut truncated = frame.to_vec();
        truncated.pop();
        assert_eq!(
            error_code(decode_acquire_tenure_request_frame(&truncated)),
            AcquireTenureProtocolErrorCode::Truncated
        );
        let mut trailing = frame.to_vec();
        trailing.push(0);
        assert_eq!(
            error_code(decode_acquire_tenure_request_frame(&trailing)),
            AcquireTenureProtocolErrorCode::TrailingBytes
        );
        assert_eq!(
            error_code(AcquireTenureFrameHeaderV1::decode_prefix(
                &frame[..ACQUIRE_TENURE_FRAME_HEADER_BYTES - 1],
            )),
            AcquireTenureProtocolErrorCode::Truncated
        );
        let oversized = vec![0; MAX_ACQUIRE_TENURE_FRAME_BYTES + 1];
        assert_eq!(
            error_code(decode_acquire_tenure_request_frame(&oversized)),
            AcquireTenureProtocolErrorCode::MessageTooLarge
        );
    }

    #[test]
    fn stable_error_codes_and_field_tags_are_frozen() {
        assert_eq!(
            [
                AcquireTenureProtocolErrorCode::MessageTooLarge as u16,
                AcquireTenureProtocolErrorCode::Truncated as u16,
                AcquireTenureProtocolErrorCode::InvalidMagic as u16,
                AcquireTenureProtocolErrorCode::UnsupportedVersion as u16,
                AcquireTenureProtocolErrorCode::UnknownField as u16,
                AcquireTenureProtocolErrorCode::MissingField as u16,
                AcquireTenureProtocolErrorCode::DuplicateField as u16,
                AcquireTenureProtocolErrorCode::OutOfOrderField as u16,
                AcquireTenureProtocolErrorCode::InvalidFieldLength as u16,
                AcquireTenureProtocolErrorCode::InvalidFieldValue as u16,
                AcquireTenureProtocolErrorCode::DerivedDigestMismatch as u16,
                AcquireTenureProtocolErrorCode::NonCanonicalMessage as u16,
                AcquireTenureProtocolErrorCode::TrailingBytes as u16,
                AcquireTenureProtocolErrorCode::InvalidFrameKind as u16,
                AcquireTenureProtocolErrorCode::ResponseBoundExceeded as u16,
                AcquireTenureProtocolErrorCode::RequestBindingMismatch as u16,
                AcquireTenureProtocolErrorCode::DigestFailure as u16,
                AcquireTenureProtocolErrorCode::ProofContract as u16,
            ],
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18
            ]
        );

        let request = request();
        let locations = tlv_locations(request.canonical_bytes(), ACQUIRE_REQUEST_MAGIC.len());
        let mut duplicate = request.canonical_bytes().to_vec();
        duplicate[locations[1].tag_offset..locations[1].tag_offset + 2]
            .copy_from_slice(&1_u16.to_be_bytes());
        let Err(error) = AcquireTenureRequestV1::decode(&duplicate) else {
            panic!("duplicate field must fail");
        };
        assert_eq!(error.field_tag(), Some(1));
    }

    #[test]
    fn encoded_minimum_and_header_constants_are_exact() {
        assert_eq!(MIN_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES, 301);
        assert_eq!(MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES, 364);
        assert_eq!(MAX_ACQUIRE_TENURE_REQUEST_SIGNING_TRANSCRIPT_BYTES, 382);
        assert_eq!(MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES, 301);
        assert_eq!(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES, 938);
        assert_eq!(MAX_ACQUIRE_TENURE_FRAME_BYTES, 954);
        let min_request = request_from_draft(draft_with(
            1,
            2,
            3,
            4,
            5,
            b"n",
            MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        ));
        assert_eq!(
            min_request.canonical_bytes().len(),
            MIN_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES
        );
        assert_eq!(
            ACQUIRE_FRAME_MAGIC.len() + 2 + 2 + 4,
            ACQUIRE_TENURE_FRAME_HEADER_BYTES
        );
        assert_eq!(
            ACQUIRE_REQUEST_MAGIC.len() + 2 + 2,
            super::VALUE_HEADER_BYTES
        );
        assert_eq!(
            ACQUIRE_RESPONSE_MAGIC.len() + 2 + 2,
            super::VALUE_HEADER_BYTES
        );
    }
}
