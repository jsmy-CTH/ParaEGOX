//! Strict transport-neutral InspectionProtocol v1 and explicit v2 successor.
//!
//! The protocol is a single bounded request/response exchange over a caller-
//! supplied endpoint. `Watch` means "return the current cached snapshot only
//! when it is newer than this revision"; it is not a stream, subscription,
//! heartbeat, discovery mechanism, retry policy, or history store.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder};

use crate::{
    InspectionContractError, LOCAL_INSPECTION_SNAPSHOT_BYTES, LOCAL_INSPECTION_SNAPSHOT_V2_BYTES,
    LocalInspectionServiceV1, LocalInspectionServiceV2, LocalInspectionSnapshotV1,
    LocalInspectionSnapshotV2,
};

/// Shared request/response protocol version.
pub const INSPECTION_PROTOCOL_VERSION: u16 = 1;
/// Fixed byte length of one PXIQ-v1 request.
pub const INSPECTION_REQUEST_BYTES: usize = REQUEST_HEADER_BYTES;
/// Largest valid PXIP-v1 response, including one complete PXIS snapshot.
pub const MAX_INSPECTION_RESPONSE_BYTES: usize =
    RESPONSE_HEADER_BYTES + LOCAL_INSPECTION_SNAPSHOT_BYTES;
/// Explicit PXIQ/PXIP successor version for PXIS-v2 composite snapshots.
pub const INSPECTION_PROTOCOL_V2_VERSION: u16 = 2;
/// Fixed byte length of one PXIQ-v2 request.
pub const INSPECTION_REQUEST_V2_BYTES: usize = REQUEST_HEADER_BYTES;
/// Largest valid PXIP-v2 response including one complete PXIS-v2 snapshot.
pub const MAX_INSPECTION_RESPONSE_V2_BYTES: usize =
    RESPONSE_HEADER_BYTES + LOCAL_INSPECTION_SNAPSHOT_V2_BYTES;

const REQUEST_MAGIC: &[u8; 4] = b"PXIQ";
const RESPONSE_MAGIC: &[u8; 4] = b"PXIP";
const REQUEST_HEADER_BYTES: usize = 96;
const REQUEST_DIGEST_OFFSET: usize = 64;
const RESPONSE_HEADER_BYTES: usize = 144;
const RESPONSE_DIGEST_OFFSET: usize = 112;
const REQUEST_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.protocol-request.v1";
const RESPONSE_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.protocol-response.v1";
const REQUEST_V2_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.protocol-request.v2";
const RESPONSE_V2_DIGEST_DOMAIN: &[u8] = b"paraegox.inspection.protocol-response.v2";

/// One-shot read operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InspectionRequestKindV1 {
    /// Return the last cached snapshot, if one exists.
    Latest = 1,
    /// Return the last cached snapshot only when its revision is greater than
    /// `after_revision`; otherwise return `NotModified`.
    Watch = 2,
}

impl InspectionRequestKindV1 {
    fn decode(value: u8) -> Result<Self, InspectionProtocolError> {
        match value {
            1 => Ok(Self::Latest),
            2 => Ok(Self::Watch),
            _ => Err(InspectionProtocolError::UnknownEnumValue),
        }
    }
}

/// Strict immutable PXIQ-v1 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectionRequestV1 {
    request_id: [u8; 16],
    projection_id: [u8; 16],
    kind: InspectionRequestKindV1,
    after_revision: u64,
    request_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl InspectionRequestV1 {
    /// Builds a request for the current cached snapshot.
    pub fn try_latest(
        request_id: [u8; 16],
        projection_id: [u8; 16],
    ) -> Result<Self, InspectionProtocolError> {
        Self::try_build(
            request_id,
            projection_id,
            InspectionRequestKindV1::Latest,
            0,
        )
    }

    /// Builds a one-shot request for a snapshot newer than a nonzero revision.
    pub fn try_watch(
        request_id: [u8; 16],
        projection_id: [u8; 16],
        after_revision: u64,
    ) -> Result<Self, InspectionProtocolError> {
        Self::try_build(
            request_id,
            projection_id,
            InspectionRequestKindV1::Watch,
            after_revision,
        )
    }

    /// Strictly decodes one fixed-length PXIQ-v1 request.
    pub fn decode(frame: &[u8]) -> Result<Self, InspectionProtocolError> {
        if frame.len() != INSPECTION_REQUEST_BYTES {
            return Err(InspectionProtocolError::InvalidFrameLength);
        }
        if &frame[..4] != REQUEST_MAGIC
            || read_u16(&frame[4..6]) != INSPECTION_PROTOCOL_VERSION
            || usize::from(read_u16(&frame[6..8])) != REQUEST_HEADER_BYTES
        {
            return Err(InspectionProtocolError::UnsupportedFrame);
        }
        if read_u32(&frame[8..12]) as usize != frame.len()
            || frame[13..16].iter().any(|byte| *byte != 0)
            || frame[56..64].iter().any(|byte| *byte != 0)
        {
            return Err(InspectionProtocolError::NonCanonicalEncoding);
        }
        let declared_digest = Digest32::from_bytes(read_array::<32>(
            &frame[REQUEST_DIGEST_OFFSET..REQUEST_HEADER_BYTES],
        ));
        let computed_digest = request_digest(&frame[..REQUEST_DIGEST_OFFSET])?;
        if declared_digest != computed_digest {
            return Err(InspectionProtocolError::DigestMismatch);
        }
        let request = Self::try_build(
            read_array::<16>(&frame[16..32]),
            read_array::<16>(&frame[32..48]),
            InspectionRequestKindV1::decode(frame[12])?,
            read_u64(&frame[48..56]),
        )?;
        if request.canonical_wire() != frame {
            return Err(InspectionProtocolError::NonCanonicalEncoding);
        }
        Ok(request)
    }

    fn try_build(
        request_id: [u8; 16],
        projection_id: [u8; 16],
        kind: InspectionRequestKindV1,
        after_revision: u64,
    ) -> Result<Self, InspectionProtocolError> {
        if bytes_are_zero(&request_id) {
            return Err(InspectionProtocolError::ZeroRequestId);
        }
        if bytes_are_zero(&projection_id) {
            return Err(InspectionProtocolError::ZeroProjectionId);
        }
        match kind {
            InspectionRequestKindV1::Latest if after_revision != 0 => {
                return Err(InspectionProtocolError::InvalidRequestShape);
            }
            InspectionRequestKindV1::Watch if after_revision == 0 => {
                return Err(InspectionProtocolError::InvalidRequestShape);
            }
            InspectionRequestKindV1::Latest | InspectionRequestKindV1::Watch => {}
        }
        let canonical_wire = encode_request(request_id, projection_id, kind, after_revision)?;
        let request_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire[REQUEST_DIGEST_OFFSET..REQUEST_HEADER_BYTES],
        ));
        Ok(Self {
            request_id,
            projection_id,
            kind,
            after_revision,
            request_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    #[must_use]
    pub const fn projection_id(&self) -> [u8; 16] {
        self.projection_id
    }

    #[must_use]
    pub const fn kind(&self) -> InspectionRequestKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn after_revision(&self) -> u64 {
        self.after_revision
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// One exact terminal result of a one-shot read.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InspectionResponseOutcomeV1 {
    /// The payload is one complete strictly validated PXIS snapshot.
    Snapshot = 1,
    /// A Watch request's current cached revision is not newer than its cursor.
    NotModified = 2,
    /// The requested projection has no local cached snapshot.
    NotFound = 3,
}

impl InspectionResponseOutcomeV1 {
    fn decode(value: u8) -> Result<Self, InspectionProtocolError> {
        match value {
            1 => Ok(Self::Snapshot),
            2 => Ok(Self::NotModified),
            3 => Ok(Self::NotFound),
            _ => Err(InspectionProtocolError::UnknownEnumValue),
        }
    }
}

/// Strict immutable PXIP-v1 response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectionResponseV1 {
    request_id: [u8; 16],
    projection_id: [u8; 16],
    request_kind: InspectionRequestKindV1,
    after_revision: u64,
    request_digest: Digest32,
    outcome: InspectionResponseOutcomeV1,
    current_revision: u64,
    snapshot: Option<LocalInspectionSnapshotV1>,
    response_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

#[derive(Clone, Copy)]
struct ResponseBuildFields {
    request_id: [u8; 16],
    projection_id: [u8; 16],
    request_kind: InspectionRequestKindV1,
    after_revision: u64,
    request_digest: Digest32,
    outcome: InspectionResponseOutcomeV1,
    current_revision: u64,
}

impl InspectionResponseV1 {
    /// Strictly decodes one bounded PXIP-v1 response and, when present, the
    /// complete nested PXIS snapshot.
    pub fn decode(frame: &[u8]) -> Result<Self, InspectionProtocolError> {
        if frame.len() < RESPONSE_HEADER_BYTES || frame.len() > MAX_INSPECTION_RESPONSE_BYTES {
            return Err(InspectionProtocolError::InvalidFrameLength);
        }
        if &frame[..4] != RESPONSE_MAGIC
            || read_u16(&frame[4..6]) != INSPECTION_PROTOCOL_VERSION
            || usize::from(read_u16(&frame[6..8])) != RESPONSE_HEADER_BYTES
        {
            return Err(InspectionProtocolError::UnsupportedFrame);
        }
        let payload_length = read_u32(&frame[12..16]) as usize;
        if read_u32(&frame[8..12]) as usize != frame.len()
            || RESPONSE_HEADER_BYTES.checked_add(payload_length) != Some(frame.len())
            || frame[18..24].iter().any(|byte| *byte != 0)
            || frame[104..112].iter().any(|byte| *byte != 0)
        {
            return Err(InspectionProtocolError::NonCanonicalEncoding);
        }
        let declared_digest = Digest32::from_bytes(read_array::<32>(
            &frame[RESPONSE_DIGEST_OFFSET..RESPONSE_HEADER_BYTES],
        ));
        let computed_digest = response_digest(
            &frame[..RESPONSE_DIGEST_OFFSET],
            &frame[RESPONSE_HEADER_BYTES..],
        )?;
        if declared_digest != computed_digest {
            return Err(InspectionProtocolError::DigestMismatch);
        }
        let request_id = read_array::<16>(&frame[24..40]);
        let projection_id = read_array::<16>(&frame[40..56]);
        if bytes_are_zero(&request_id) {
            return Err(InspectionProtocolError::ZeroRequestId);
        }
        if bytes_are_zero(&projection_id) {
            return Err(InspectionProtocolError::ZeroProjectionId);
        }
        let request_kind = InspectionRequestKindV1::decode(frame[17])?;
        let after_revision = read_u64(&frame[56..64]);
        validate_request_shape(request_kind, after_revision)?;
        let outcome = InspectionResponseOutcomeV1::decode(frame[16])?;
        let current_revision = read_u64(&frame[64..72]);
        let request_digest = Digest32::from_bytes(read_array::<32>(&frame[72..104]));
        if bytes_are_zero(request_digest.as_bytes()) {
            return Err(InspectionProtocolError::DigestMismatch);
        }
        let snapshot = match outcome {
            InspectionResponseOutcomeV1::Snapshot => {
                if payload_length != LOCAL_INSPECTION_SNAPSHOT_BYTES {
                    return Err(InspectionProtocolError::InvalidResponseShape);
                }
                let snapshot = LocalInspectionSnapshotV1::decode(&frame[RESPONSE_HEADER_BYTES..])
                    .map_err(InspectionProtocolError::SnapshotRejected)?;
                if snapshot.projection_id() != projection_id
                    || snapshot.projection_revision() != current_revision
                    || request_kind == InspectionRequestKindV1::Watch
                        && current_revision <= after_revision
                {
                    return Err(InspectionProtocolError::CorrelationMismatch);
                }
                Some(snapshot)
            }
            InspectionResponseOutcomeV1::NotModified => {
                if payload_length != 0
                    || request_kind != InspectionRequestKindV1::Watch
                    || current_revision == 0
                    || current_revision > after_revision
                {
                    return Err(InspectionProtocolError::InvalidResponseShape);
                }
                None
            }
            InspectionResponseOutcomeV1::NotFound => {
                if payload_length != 0 || current_revision != 0 {
                    return Err(InspectionProtocolError::InvalidResponseShape);
                }
                None
            }
        };
        let response = Self::try_build(
            ResponseBuildFields {
                request_id,
                projection_id,
                request_kind,
                after_revision,
                request_digest,
                outcome,
                current_revision,
            },
            snapshot,
        )?;
        if response.canonical_wire() != frame {
            return Err(InspectionProtocolError::NonCanonicalEncoding);
        }
        Ok(response)
    }

    fn snapshot(
        request: &InspectionRequestV1,
        snapshot: LocalInspectionSnapshotV1,
    ) -> Result<Self, InspectionProtocolError> {
        let current_revision = snapshot.projection_revision();
        Self::try_build(
            ResponseBuildFields {
                request_id: request.request_id,
                projection_id: request.projection_id,
                request_kind: request.kind,
                after_revision: request.after_revision,
                request_digest: request.request_digest,
                outcome: InspectionResponseOutcomeV1::Snapshot,
                current_revision,
            },
            Some(snapshot),
        )
    }

    fn not_modified(
        request: &InspectionRequestV1,
        current_revision: u64,
    ) -> Result<Self, InspectionProtocolError> {
        Self::try_build(
            ResponseBuildFields {
                request_id: request.request_id,
                projection_id: request.projection_id,
                request_kind: request.kind,
                after_revision: request.after_revision,
                request_digest: request.request_digest,
                outcome: InspectionResponseOutcomeV1::NotModified,
                current_revision,
            },
            None,
        )
    }

    fn not_found(request: &InspectionRequestV1) -> Result<Self, InspectionProtocolError> {
        Self::try_build(
            ResponseBuildFields {
                request_id: request.request_id,
                projection_id: request.projection_id,
                request_kind: request.kind,
                after_revision: request.after_revision,
                request_digest: request.request_digest,
                outcome: InspectionResponseOutcomeV1::NotFound,
                current_revision: 0,
            },
            None,
        )
    }

    fn try_build(
        fields: ResponseBuildFields,
        snapshot: Option<LocalInspectionSnapshotV1>,
    ) -> Result<Self, InspectionProtocolError> {
        if bytes_are_zero(&fields.request_id) {
            return Err(InspectionProtocolError::ZeroRequestId);
        }
        if bytes_are_zero(&fields.projection_id) {
            return Err(InspectionProtocolError::ZeroProjectionId);
        }
        if bytes_are_zero(fields.request_digest.as_bytes()) {
            return Err(InspectionProtocolError::DigestMismatch);
        }
        validate_request_shape(fields.request_kind, fields.after_revision)?;
        match fields.outcome {
            InspectionResponseOutcomeV1::Snapshot => {
                let value = snapshot
                    .as_ref()
                    .ok_or(InspectionProtocolError::InvalidResponseShape)?;
                if fields.current_revision == 0
                    || value.projection_id() != fields.projection_id
                    || value.projection_revision() != fields.current_revision
                    || fields.request_kind == InspectionRequestKindV1::Watch
                        && fields.current_revision <= fields.after_revision
                {
                    return Err(InspectionProtocolError::CorrelationMismatch);
                }
            }
            InspectionResponseOutcomeV1::NotModified => {
                if snapshot.is_some()
                    || fields.request_kind != InspectionRequestKindV1::Watch
                    || fields.current_revision == 0
                    || fields.current_revision > fields.after_revision
                {
                    return Err(InspectionProtocolError::InvalidResponseShape);
                }
            }
            InspectionResponseOutcomeV1::NotFound => {
                if snapshot.is_some() || fields.current_revision != 0 {
                    return Err(InspectionProtocolError::InvalidResponseShape);
                }
            }
        }
        let payload = snapshot
            .as_ref()
            .map_or(&[][..], LocalInspectionSnapshotV1::canonical_wire);
        let canonical_wire = encode_response(fields, payload)?;
        let response_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire[RESPONSE_DIGEST_OFFSET..RESPONSE_HEADER_BYTES],
        ));
        Ok(Self {
            request_id: fields.request_id,
            projection_id: fields.projection_id,
            request_kind: fields.request_kind,
            after_revision: fields.after_revision,
            request_digest: fields.request_digest,
            outcome: fields.outcome,
            current_revision: fields.current_revision,
            snapshot,
            response_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Verifies exact request identity, projection, operation, cursor, and
    /// complete canonical request digest correlation.
    pub fn validate_for(
        &self,
        request: &InspectionRequestV1,
    ) -> Result<(), InspectionProtocolError> {
        if self.request_id != request.request_id
            || self.projection_id != request.projection_id
            || self.request_kind != request.kind
            || self.after_revision != request.after_revision
            || self.request_digest != request.request_digest
        {
            return Err(InspectionProtocolError::CorrelationMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    #[must_use]
    pub const fn projection_id(&self) -> [u8; 16] {
        self.projection_id
    }

    #[must_use]
    pub const fn request_kind(&self) -> InspectionRequestKindV1 {
        self.request_kind
    }

    #[must_use]
    pub const fn after_revision(&self) -> u64 {
        self.after_revision
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub const fn outcome(&self) -> InspectionResponseOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub const fn current_revision(&self) -> u64 {
        self.current_revision
    }

    #[must_use]
    pub const fn snapshot_value(&self) -> Option<&LocalInspectionSnapshotV1> {
        self.snapshot.as_ref()
    }

    #[must_use]
    pub const fn response_digest(&self) -> Digest32 {
        self.response_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

impl LocalInspectionServiceV1 {
    /// Answers only from the last immutable cache. This method never projects,
    /// advances a revision, records a cursor, creates history, or mutates the
    /// cached snapshot.
    pub fn answer_read_only_v1(
        &self,
        request: &InspectionRequestV1,
    ) -> Result<InspectionResponseV1, InspectionProtocolError> {
        if request.projection_id != self.projection_id {
            return InspectionResponseV1::not_found(request);
        }
        let Some(snapshot) = self.snapshot() else {
            return InspectionResponseV1::not_found(request);
        };
        match request.kind {
            InspectionRequestKindV1::Latest => {
                InspectionResponseV1::snapshot(request, snapshot.clone())
            }
            InspectionRequestKindV1::Watch
                if snapshot.projection_revision() <= request.after_revision =>
            {
                InspectionResponseV1::not_modified(request, snapshot.projection_revision())
            }
            InspectionRequestKindV1::Watch => {
                InspectionResponseV1::snapshot(request, snapshot.clone())
            }
        }
    }
}

/// Transport-facing endpoint failure. The protocol does not prescribe a
/// transport, discovery, authentication, retry, or logging implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionEndpointErrorV1 {
    MalformedRequest,
    Unavailable,
    ResponseUnavailable,
}

impl fmt::Display for InspectionEndpointErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedRequest => "Inspection endpoint rejected a malformed request",
            Self::Unavailable => "Inspection endpoint is unavailable",
            Self::ResponseUnavailable => "Inspection endpoint could not produce a response",
        })
    }
}

impl std::error::Error for InspectionEndpointErrorV1 {}

/// One transport-neutral, single-exchange endpoint.
pub trait InspectionEndpointV1 {
    /// Performs exactly one exchange. Implementations must not retry or turn a
    /// Watch request into a background stream.
    fn exchange(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, InspectionEndpointErrorV1>;
}

impl InspectionEndpointV1 for LocalInspectionServiceV1 {
    fn exchange(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, InspectionEndpointErrorV1> {
        let request = InspectionRequestV1::decode(canonical_request)
            .map_err(|_| InspectionEndpointErrorV1::MalformedRequest)?;
        self.answer_read_only_v1(&request)
            .map(|response| response.canonical_wire)
            .map_err(|_| InspectionEndpointErrorV1::ResponseUnavailable)
    }
}

/// Typed client-side failure for one non-retrying exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionClientErrorV1 {
    InvalidRequest(InspectionProtocolError),
    Endpoint(InspectionEndpointErrorV1),
    InvalidResponse(InspectionProtocolError),
    CorrelationMismatch,
}

impl fmt::Display for InspectionClientErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(error) => write!(formatter, "invalid Inspection request: {error}"),
            Self::Endpoint(error) => write!(formatter, "Inspection endpoint failed: {error}"),
            Self::InvalidResponse(error) => {
                write!(formatter, "invalid Inspection response: {error}")
            }
            Self::CorrelationMismatch => {
                formatter.write_str("Inspection response correlation mismatch")
            }
        }
    }
}

impl std::error::Error for InspectionClientErrorV1 {}

/// Minimal typed client over one injected endpoint.
///
/// Each method performs at most one exchange. The client owns no retry,
/// discovery, authentication, cache, history, watch loop, or background work.
#[derive(Debug)]
pub struct InspectionClientV1<E> {
    endpoint: E,
}

impl<E> InspectionClientV1<E>
where
    E: InspectionEndpointV1,
{
    #[must_use]
    pub const fn new(endpoint: E) -> Self {
        Self { endpoint }
    }

    /// Performs one Latest exchange.
    pub fn latest(
        &mut self,
        request_id: [u8; 16],
        projection_id: [u8; 16],
    ) -> Result<InspectionResponseV1, InspectionClientErrorV1> {
        let request = InspectionRequestV1::try_latest(request_id, projection_id)
            .map_err(InspectionClientErrorV1::InvalidRequest)?;
        self.execute(&request)
    }

    /// Performs one one-shot Watch exchange; it does not wait or subscribe.
    pub fn watch(
        &mut self,
        request_id: [u8; 16],
        projection_id: [u8; 16],
        after_revision: u64,
    ) -> Result<InspectionResponseV1, InspectionClientErrorV1> {
        let request = InspectionRequestV1::try_watch(request_id, projection_id, after_revision)
            .map_err(InspectionClientErrorV1::InvalidRequest)?;
        self.execute(&request)
    }

    fn execute(
        &mut self,
        request: &InspectionRequestV1,
    ) -> Result<InspectionResponseV1, InspectionClientErrorV1> {
        let response_wire = self
            .endpoint
            .exchange(request.canonical_wire())
            .map_err(InspectionClientErrorV1::Endpoint)?;
        let response = InspectionResponseV1::decode(&response_wire)
            .map_err(InspectionClientErrorV1::InvalidResponse)?;
        response
            .validate_for(request)
            .map_err(|_| InspectionClientErrorV1::CorrelationMismatch)?;
        Ok(response)
    }

    /// Returns the injected endpoint after all caller-owned exchanges finish.
    #[must_use]
    pub fn into_endpoint(self) -> E {
        self.endpoint
    }
}

fn validate_request_shape(
    kind: InspectionRequestKindV1,
    after_revision: u64,
) -> Result<(), InspectionProtocolError> {
    match kind {
        InspectionRequestKindV1::Latest if after_revision == 0 => Ok(()),
        InspectionRequestKindV1::Watch if after_revision != 0 => Ok(()),
        InspectionRequestKindV1::Latest | InspectionRequestKindV1::Watch => {
            Err(InspectionProtocolError::InvalidRequestShape)
        }
    }
}

fn encode_request(
    request_id: [u8; 16],
    projection_id: [u8; 16],
    kind: InspectionRequestKindV1,
    after_revision: u64,
) -> Result<Vec<u8>, InspectionProtocolError> {
    let mut frame = vec![0; REQUEST_HEADER_BYTES];
    frame[..4].copy_from_slice(REQUEST_MAGIC);
    frame[4..6].copy_from_slice(&INSPECTION_PROTOCOL_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(&(REQUEST_HEADER_BYTES as u16).to_be_bytes());
    frame[8..12].copy_from_slice(&(REQUEST_HEADER_BYTES as u32).to_be_bytes());
    frame[12] = kind as u8;
    frame[16..32].copy_from_slice(&request_id);
    frame[32..48].copy_from_slice(&projection_id);
    frame[48..56].copy_from_slice(&after_revision.to_be_bytes());
    let digest = request_digest(&frame[..REQUEST_DIGEST_OFFSET])?;
    frame[REQUEST_DIGEST_OFFSET..REQUEST_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    Ok(frame)
}

fn encode_response(
    fields: ResponseBuildFields,
    payload: &[u8],
) -> Result<Vec<u8>, InspectionProtocolError> {
    let total_length = RESPONSE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(InspectionProtocolError::InvalidFrameLength)?;
    if total_length > MAX_INSPECTION_RESPONSE_BYTES {
        return Err(InspectionProtocolError::InvalidFrameLength);
    }
    let mut frame = vec![0; total_length];
    frame[..4].copy_from_slice(RESPONSE_MAGIC);
    frame[4..6].copy_from_slice(&INSPECTION_PROTOCOL_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(&(RESPONSE_HEADER_BYTES as u16).to_be_bytes());
    frame[8..12].copy_from_slice(&(total_length as u32).to_be_bytes());
    frame[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    frame[16] = fields.outcome as u8;
    frame[17] = fields.request_kind as u8;
    frame[24..40].copy_from_slice(&fields.request_id);
    frame[40..56].copy_from_slice(&fields.projection_id);
    frame[56..64].copy_from_slice(&fields.after_revision.to_be_bytes());
    frame[64..72].copy_from_slice(&fields.current_revision.to_be_bytes());
    frame[72..104].copy_from_slice(fields.request_digest.as_bytes());
    frame[RESPONSE_HEADER_BYTES..].copy_from_slice(payload);
    let digest = response_digest(
        &frame[..RESPONSE_DIGEST_OFFSET],
        &frame[RESPONSE_HEADER_BYTES..],
    )?;
    frame[RESPONSE_DIGEST_OFFSET..RESPONSE_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    Ok(frame)
}

fn request_digest(header: &[u8]) -> Result<Digest32, InspectionProtocolError> {
    let mut builder = Digest32Builder::try_new(REQUEST_DIGEST_DOMAIN)
        .map_err(|_| InspectionProtocolError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .map_err(|_| InspectionProtocolError::DigestEncodingFailed)?;
    Ok(builder.finish())
}

fn response_digest(header: &[u8], payload: &[u8]) -> Result<Digest32, InspectionProtocolError> {
    let mut builder = Digest32Builder::try_new(RESPONSE_DIGEST_DOMAIN)
        .map_err(|_| InspectionProtocolError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .and_then(|builder| builder.field_bytes(payload))
        .map_err(|_| InspectionProtocolError::DigestEncodingFailed)?;
    Ok(builder.finish())
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(read_array(bytes))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(read_array(bytes))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(read_array(bytes))
}

fn read_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut output = [0; N];
    output.copy_from_slice(bytes);
    output
}

fn bytes_are_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Stable strict-codec and correlation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionProtocolError {
    ZeroRequestId,
    ZeroProjectionId,
    InvalidRequestShape,
    InvalidResponseShape,
    InvalidFrameLength,
    UnsupportedFrame,
    UnknownEnumValue,
    DigestMismatch,
    CorrelationMismatch,
    NonCanonicalEncoding,
    SnapshotRejected(InspectionContractError),
    DigestEncodingFailed,
}

impl fmt::Display for InspectionProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRequestId => formatter.write_str("Inspection request identity is zero"),
            Self::ZeroProjectionId => formatter.write_str("Inspection projection identity is zero"),
            Self::InvalidRequestShape => formatter.write_str("invalid Inspection request shape"),
            Self::InvalidResponseShape => formatter.write_str("invalid Inspection response shape"),
            Self::InvalidFrameLength => {
                formatter.write_str("invalid Inspection protocol frame length")
            }
            Self::UnsupportedFrame => formatter.write_str("unsupported Inspection protocol frame"),
            Self::UnknownEnumValue => formatter.write_str("unknown Inspection protocol enum value"),
            Self::DigestMismatch => formatter.write_str("Inspection protocol digest mismatch"),
            Self::CorrelationMismatch => {
                formatter.write_str("Inspection protocol correlation mismatch")
            }
            Self::NonCanonicalEncoding => {
                formatter.write_str("non-canonical Inspection protocol encoding")
            }
            Self::SnapshotRejected(error) => {
                write!(formatter, "nested PXIS snapshot rejected: {error}")
            }
            Self::DigestEncodingFailed => {
                formatter.write_str("Inspection protocol digest encoding failed")
            }
        }
    }
}

impl std::error::Error for InspectionProtocolError {}

/// PXIQ-v2 keeps the v1 one-shot operation vocabulary unchanged.
pub type InspectionRequestKindV2 = InspectionRequestKindV1;
/// PXIP-v2 keeps the v1 terminal outcome vocabulary unchanged.
pub type InspectionResponseOutcomeV2 = InspectionResponseOutcomeV1;
/// PXIQ/PXIP-v2 uses the same transport-facing failure vocabulary.
pub type InspectionEndpointErrorV2 = InspectionEndpointErrorV1;

/// Strict immutable PXIQ-v2 request selecting a PXIS-v2 projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectionRequestV2 {
    request_id: [u8; 16],
    projection_id: [u8; 16],
    kind: InspectionRequestKindV2,
    after_revision: u64,
    request_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl InspectionRequestV2 {
    pub fn try_latest(
        request_id: [u8; 16],
        projection_id: [u8; 16],
    ) -> Result<Self, InspectionProtocolError> {
        Self::try_build(
            request_id,
            projection_id,
            InspectionRequestKindV2::Latest,
            0,
        )
    }

    pub fn try_watch(
        request_id: [u8; 16],
        projection_id: [u8; 16],
        after_revision: u64,
    ) -> Result<Self, InspectionProtocolError> {
        Self::try_build(
            request_id,
            projection_id,
            InspectionRequestKindV2::Watch,
            after_revision,
        )
    }

    pub fn decode(frame: &[u8]) -> Result<Self, InspectionProtocolError> {
        if frame.len() != INSPECTION_REQUEST_V2_BYTES {
            return Err(InspectionProtocolError::InvalidFrameLength);
        }
        if &frame[..4] != REQUEST_MAGIC
            || read_u16(&frame[4..6]) != INSPECTION_PROTOCOL_V2_VERSION
            || usize::from(read_u16(&frame[6..8])) != REQUEST_HEADER_BYTES
        {
            return Err(InspectionProtocolError::UnsupportedFrame);
        }
        if read_u32(&frame[8..12]) as usize != frame.len()
            || frame[13..16].iter().any(|byte| *byte != 0)
            || frame[56..64].iter().any(|byte| *byte != 0)
        {
            return Err(InspectionProtocolError::NonCanonicalEncoding);
        }
        let declared_digest = Digest32::from_bytes(read_array::<32>(
            &frame[REQUEST_DIGEST_OFFSET..REQUEST_HEADER_BYTES],
        ));
        if declared_digest != request_v2_digest(&frame[..REQUEST_DIGEST_OFFSET])? {
            return Err(InspectionProtocolError::DigestMismatch);
        }
        let request = Self::try_build(
            read_array::<16>(&frame[16..32]),
            read_array::<16>(&frame[32..48]),
            InspectionRequestKindV2::decode(frame[12])?,
            read_u64(&frame[48..56]),
        )?;
        if request.canonical_wire() != frame {
            return Err(InspectionProtocolError::NonCanonicalEncoding);
        }
        Ok(request)
    }

    fn try_build(
        request_id: [u8; 16],
        projection_id: [u8; 16],
        kind: InspectionRequestKindV2,
        after_revision: u64,
    ) -> Result<Self, InspectionProtocolError> {
        if bytes_are_zero(&request_id) {
            return Err(InspectionProtocolError::ZeroRequestId);
        }
        if bytes_are_zero(&projection_id) {
            return Err(InspectionProtocolError::ZeroProjectionId);
        }
        validate_request_shape(kind, after_revision)?;
        let canonical_wire = encode_request_v2(request_id, projection_id, kind, after_revision)?;
        let request_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire[REQUEST_DIGEST_OFFSET..REQUEST_HEADER_BYTES],
        ));
        Ok(Self {
            request_id,
            projection_id,
            kind,
            after_revision,
            request_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    #[must_use]
    pub const fn projection_id(&self) -> [u8; 16] {
        self.projection_id
    }

    #[must_use]
    pub const fn kind(&self) -> InspectionRequestKindV2 {
        self.kind
    }

    #[must_use]
    pub const fn after_revision(&self) -> u64 {
        self.after_revision
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

#[derive(Clone, Copy)]
struct ResponseBuildFieldsV2 {
    request_id: [u8; 16],
    projection_id: [u8; 16],
    request_kind: InspectionRequestKindV2,
    after_revision: u64,
    request_digest: Digest32,
    outcome: InspectionResponseOutcomeV2,
    current_revision: u64,
}

/// Strict immutable PXIP-v2 response containing at most one complete PXIS-v2
/// composite snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectionResponseV2 {
    request_id: [u8; 16],
    projection_id: [u8; 16],
    request_kind: InspectionRequestKindV2,
    after_revision: u64,
    request_digest: Digest32,
    outcome: InspectionResponseOutcomeV2,
    current_revision: u64,
    snapshot: Option<LocalInspectionSnapshotV2>,
    response_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl InspectionResponseV2 {
    pub fn decode(frame: &[u8]) -> Result<Self, InspectionProtocolError> {
        if frame.len() < RESPONSE_HEADER_BYTES || frame.len() > MAX_INSPECTION_RESPONSE_V2_BYTES {
            return Err(InspectionProtocolError::InvalidFrameLength);
        }
        if &frame[..4] != RESPONSE_MAGIC
            || read_u16(&frame[4..6]) != INSPECTION_PROTOCOL_V2_VERSION
            || usize::from(read_u16(&frame[6..8])) != RESPONSE_HEADER_BYTES
        {
            return Err(InspectionProtocolError::UnsupportedFrame);
        }
        let payload_length = read_u32(&frame[12..16]) as usize;
        if read_u32(&frame[8..12]) as usize != frame.len()
            || RESPONSE_HEADER_BYTES.checked_add(payload_length) != Some(frame.len())
            || frame[18..24].iter().any(|byte| *byte != 0)
            || frame[104..112].iter().any(|byte| *byte != 0)
        {
            return Err(InspectionProtocolError::NonCanonicalEncoding);
        }
        let declared_digest = Digest32::from_bytes(read_array::<32>(
            &frame[RESPONSE_DIGEST_OFFSET..RESPONSE_HEADER_BYTES],
        ));
        if declared_digest
            != response_v2_digest(
                &frame[..RESPONSE_DIGEST_OFFSET],
                &frame[RESPONSE_HEADER_BYTES..],
            )?
        {
            return Err(InspectionProtocolError::DigestMismatch);
        }
        let request_id = read_array::<16>(&frame[24..40]);
        let projection_id = read_array::<16>(&frame[40..56]);
        if bytes_are_zero(&request_id) {
            return Err(InspectionProtocolError::ZeroRequestId);
        }
        if bytes_are_zero(&projection_id) {
            return Err(InspectionProtocolError::ZeroProjectionId);
        }
        let request_kind = InspectionRequestKindV2::decode(frame[17])?;
        let after_revision = read_u64(&frame[56..64]);
        validate_request_shape(request_kind, after_revision)?;
        let outcome = InspectionResponseOutcomeV2::decode(frame[16])?;
        let current_revision = read_u64(&frame[64..72]);
        let request_digest = Digest32::from_bytes(read_array::<32>(&frame[72..104]));
        if bytes_are_zero(request_digest.as_bytes()) {
            return Err(InspectionProtocolError::DigestMismatch);
        }
        let snapshot = match outcome {
            InspectionResponseOutcomeV2::Snapshot => {
                if payload_length != LOCAL_INSPECTION_SNAPSHOT_V2_BYTES {
                    return Err(InspectionProtocolError::InvalidResponseShape);
                }
                let snapshot = LocalInspectionSnapshotV2::decode(&frame[RESPONSE_HEADER_BYTES..])
                    .map_err(InspectionProtocolError::SnapshotRejected)?;
                if snapshot.projection_id() != projection_id
                    || snapshot.projection_revision() != current_revision
                    || request_kind == InspectionRequestKindV2::Watch
                        && current_revision <= after_revision
                {
                    return Err(InspectionProtocolError::CorrelationMismatch);
                }
                Some(snapshot)
            }
            InspectionResponseOutcomeV2::NotModified => {
                if payload_length != 0
                    || request_kind != InspectionRequestKindV2::Watch
                    || current_revision == 0
                    || current_revision > after_revision
                {
                    return Err(InspectionProtocolError::InvalidResponseShape);
                }
                None
            }
            InspectionResponseOutcomeV2::NotFound => {
                if payload_length != 0 || current_revision != 0 {
                    return Err(InspectionProtocolError::InvalidResponseShape);
                }
                None
            }
        };
        let response = Self::try_build(
            ResponseBuildFieldsV2 {
                request_id,
                projection_id,
                request_kind,
                after_revision,
                request_digest,
                outcome,
                current_revision,
            },
            snapshot,
        )?;
        if response.canonical_wire() != frame {
            return Err(InspectionProtocolError::NonCanonicalEncoding);
        }
        Ok(response)
    }

    fn snapshot(
        request: &InspectionRequestV2,
        snapshot: LocalInspectionSnapshotV2,
    ) -> Result<Self, InspectionProtocolError> {
        let current_revision = snapshot.projection_revision();
        Self::try_build(
            ResponseBuildFieldsV2 {
                request_id: request.request_id,
                projection_id: request.projection_id,
                request_kind: request.kind,
                after_revision: request.after_revision,
                request_digest: request.request_digest,
                outcome: InspectionResponseOutcomeV2::Snapshot,
                current_revision,
            },
            Some(snapshot),
        )
    }

    fn not_modified(
        request: &InspectionRequestV2,
        current_revision: u64,
    ) -> Result<Self, InspectionProtocolError> {
        Self::try_build(
            ResponseBuildFieldsV2 {
                request_id: request.request_id,
                projection_id: request.projection_id,
                request_kind: request.kind,
                after_revision: request.after_revision,
                request_digest: request.request_digest,
                outcome: InspectionResponseOutcomeV2::NotModified,
                current_revision,
            },
            None,
        )
    }

    fn not_found(request: &InspectionRequestV2) -> Result<Self, InspectionProtocolError> {
        Self::try_build(
            ResponseBuildFieldsV2 {
                request_id: request.request_id,
                projection_id: request.projection_id,
                request_kind: request.kind,
                after_revision: request.after_revision,
                request_digest: request.request_digest,
                outcome: InspectionResponseOutcomeV2::NotFound,
                current_revision: 0,
            },
            None,
        )
    }

    fn try_build(
        fields: ResponseBuildFieldsV2,
        snapshot: Option<LocalInspectionSnapshotV2>,
    ) -> Result<Self, InspectionProtocolError> {
        if bytes_are_zero(&fields.request_id) {
            return Err(InspectionProtocolError::ZeroRequestId);
        }
        if bytes_are_zero(&fields.projection_id) {
            return Err(InspectionProtocolError::ZeroProjectionId);
        }
        if bytes_are_zero(fields.request_digest.as_bytes()) {
            return Err(InspectionProtocolError::DigestMismatch);
        }
        validate_request_shape(fields.request_kind, fields.after_revision)?;
        match fields.outcome {
            InspectionResponseOutcomeV2::Snapshot => {
                let value = snapshot
                    .as_ref()
                    .ok_or(InspectionProtocolError::InvalidResponseShape)?;
                if fields.current_revision == 0
                    || value.projection_id() != fields.projection_id
                    || value.projection_revision() != fields.current_revision
                    || fields.request_kind == InspectionRequestKindV2::Watch
                        && fields.current_revision <= fields.after_revision
                {
                    return Err(InspectionProtocolError::CorrelationMismatch);
                }
            }
            InspectionResponseOutcomeV2::NotModified => {
                if snapshot.is_some()
                    || fields.request_kind != InspectionRequestKindV2::Watch
                    || fields.current_revision == 0
                    || fields.current_revision > fields.after_revision
                {
                    return Err(InspectionProtocolError::InvalidResponseShape);
                }
            }
            InspectionResponseOutcomeV2::NotFound => {
                if snapshot.is_some() || fields.current_revision != 0 {
                    return Err(InspectionProtocolError::InvalidResponseShape);
                }
            }
        }
        let payload = snapshot
            .as_ref()
            .map_or(&[][..], LocalInspectionSnapshotV2::canonical_wire);
        let canonical_wire = encode_response_v2(fields, payload)?;
        let response_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire[RESPONSE_DIGEST_OFFSET..RESPONSE_HEADER_BYTES],
        ));
        Ok(Self {
            request_id: fields.request_id,
            projection_id: fields.projection_id,
            request_kind: fields.request_kind,
            after_revision: fields.after_revision,
            request_digest: fields.request_digest,
            outcome: fields.outcome,
            current_revision: fields.current_revision,
            snapshot,
            response_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    pub fn validate_for(
        &self,
        request: &InspectionRequestV2,
    ) -> Result<(), InspectionProtocolError> {
        if self.request_id != request.request_id
            || self.projection_id != request.projection_id
            || self.request_kind != request.kind
            || self.after_revision != request.after_revision
            || self.request_digest != request.request_digest
        {
            return Err(InspectionProtocolError::CorrelationMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    #[must_use]
    pub const fn projection_id(&self) -> [u8; 16] {
        self.projection_id
    }

    #[must_use]
    pub const fn request_kind(&self) -> InspectionRequestKindV2 {
        self.request_kind
    }

    #[must_use]
    pub const fn after_revision(&self) -> u64 {
        self.after_revision
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub const fn outcome(&self) -> InspectionResponseOutcomeV2 {
        self.outcome
    }

    #[must_use]
    pub const fn current_revision(&self) -> u64 {
        self.current_revision
    }

    #[must_use]
    pub const fn snapshot_value(&self) -> Option<&LocalInspectionSnapshotV2> {
        self.snapshot.as_ref()
    }

    #[must_use]
    pub const fn response_digest(&self) -> Digest32 {
        self.response_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

impl LocalInspectionServiceV2 {
    /// Answers one PXIQ-v2 request only from the last immutable PXIS-v2 cache.
    pub fn answer_read_only_v2(
        &self,
        request: &InspectionRequestV2,
    ) -> Result<InspectionResponseV2, InspectionProtocolError> {
        if request.projection_id != self.projection_id {
            return InspectionResponseV2::not_found(request);
        }
        let Some(snapshot) = self.snapshot() else {
            return InspectionResponseV2::not_found(request);
        };
        match request.kind {
            InspectionRequestKindV2::Latest => {
                InspectionResponseV2::snapshot(request, snapshot.clone())
            }
            InspectionRequestKindV2::Watch
                if snapshot.projection_revision() <= request.after_revision =>
            {
                InspectionResponseV2::not_modified(request, snapshot.projection_revision())
            }
            InspectionRequestKindV2::Watch => {
                InspectionResponseV2::snapshot(request, snapshot.clone())
            }
        }
    }
}

/// One transport-neutral, single-exchange PXIQ/PXIP-v2 endpoint.
pub trait InspectionEndpointV2 {
    fn exchange(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, InspectionEndpointErrorV2>;
}

impl InspectionEndpointV2 for LocalInspectionServiceV2 {
    fn exchange(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, InspectionEndpointErrorV2> {
        let request = InspectionRequestV2::decode(canonical_request)
            .map_err(|_| InspectionEndpointErrorV2::MalformedRequest)?;
        self.answer_read_only_v2(&request)
            .map(|response| response.canonical_wire)
            .map_err(|_| InspectionEndpointErrorV2::ResponseUnavailable)
    }
}

/// Typed client-side failure for one non-retrying PXIQ/PXIP-v2 exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionClientErrorV2 {
    InvalidRequest(InspectionProtocolError),
    Endpoint(InspectionEndpointErrorV2),
    InvalidResponse(InspectionProtocolError),
    CorrelationMismatch,
}

impl fmt::Display for InspectionClientErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(error) => {
                write!(formatter, "invalid Inspection v2 request: {error}")
            }
            Self::Endpoint(error) => write!(formatter, "Inspection v2 endpoint failed: {error}"),
            Self::InvalidResponse(error) => {
                write!(formatter, "invalid Inspection v2 response: {error}")
            }
            Self::CorrelationMismatch => {
                formatter.write_str("Inspection v2 response correlation mismatch")
            }
        }
    }
}

impl std::error::Error for InspectionClientErrorV2 {}

/// Minimal typed client for one-shot PXIS-v2 reads.
#[derive(Debug)]
pub struct InspectionClientV2<E> {
    endpoint: E,
}

impl<E> InspectionClientV2<E>
where
    E: InspectionEndpointV2,
{
    #[must_use]
    pub const fn new(endpoint: E) -> Self {
        Self { endpoint }
    }

    pub fn latest(
        &mut self,
        request_id: [u8; 16],
        projection_id: [u8; 16],
    ) -> Result<InspectionResponseV2, InspectionClientErrorV2> {
        let request = InspectionRequestV2::try_latest(request_id, projection_id)
            .map_err(InspectionClientErrorV2::InvalidRequest)?;
        self.execute(&request)
    }

    pub fn watch(
        &mut self,
        request_id: [u8; 16],
        projection_id: [u8; 16],
        after_revision: u64,
    ) -> Result<InspectionResponseV2, InspectionClientErrorV2> {
        let request = InspectionRequestV2::try_watch(request_id, projection_id, after_revision)
            .map_err(InspectionClientErrorV2::InvalidRequest)?;
        self.execute(&request)
    }

    fn execute(
        &mut self,
        request: &InspectionRequestV2,
    ) -> Result<InspectionResponseV2, InspectionClientErrorV2> {
        let response_wire = self
            .endpoint
            .exchange(request.canonical_wire())
            .map_err(InspectionClientErrorV2::Endpoint)?;
        let response = InspectionResponseV2::decode(&response_wire)
            .map_err(InspectionClientErrorV2::InvalidResponse)?;
        response
            .validate_for(request)
            .map_err(|_| InspectionClientErrorV2::CorrelationMismatch)?;
        Ok(response)
    }

    #[must_use]
    pub fn into_endpoint(self) -> E {
        self.endpoint
    }
}

fn encode_request_v2(
    request_id: [u8; 16],
    projection_id: [u8; 16],
    kind: InspectionRequestKindV2,
    after_revision: u64,
) -> Result<Vec<u8>, InspectionProtocolError> {
    let mut frame = vec![0_u8; REQUEST_HEADER_BYTES];
    frame[..4].copy_from_slice(REQUEST_MAGIC);
    frame[4..6].copy_from_slice(&INSPECTION_PROTOCOL_V2_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(&(REQUEST_HEADER_BYTES as u16).to_be_bytes());
    frame[8..12].copy_from_slice(&(REQUEST_HEADER_BYTES as u32).to_be_bytes());
    frame[12] = kind as u8;
    frame[16..32].copy_from_slice(&request_id);
    frame[32..48].copy_from_slice(&projection_id);
    frame[48..56].copy_from_slice(&after_revision.to_be_bytes());
    let digest = request_v2_digest(&frame[..REQUEST_DIGEST_OFFSET])?;
    frame[REQUEST_DIGEST_OFFSET..REQUEST_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    Ok(frame)
}

fn encode_response_v2(
    fields: ResponseBuildFieldsV2,
    payload: &[u8],
) -> Result<Vec<u8>, InspectionProtocolError> {
    let total_length = RESPONSE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(InspectionProtocolError::InvalidFrameLength)?;
    if total_length > MAX_INSPECTION_RESPONSE_V2_BYTES {
        return Err(InspectionProtocolError::InvalidFrameLength);
    }
    let mut frame = vec![0_u8; total_length];
    frame[..4].copy_from_slice(RESPONSE_MAGIC);
    frame[4..6].copy_from_slice(&INSPECTION_PROTOCOL_V2_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(&(RESPONSE_HEADER_BYTES as u16).to_be_bytes());
    frame[8..12].copy_from_slice(&(total_length as u32).to_be_bytes());
    frame[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    frame[16] = fields.outcome as u8;
    frame[17] = fields.request_kind as u8;
    frame[24..40].copy_from_slice(&fields.request_id);
    frame[40..56].copy_from_slice(&fields.projection_id);
    frame[56..64].copy_from_slice(&fields.after_revision.to_be_bytes());
    frame[64..72].copy_from_slice(&fields.current_revision.to_be_bytes());
    frame[72..104].copy_from_slice(fields.request_digest.as_bytes());
    frame[RESPONSE_HEADER_BYTES..].copy_from_slice(payload);
    let digest = response_v2_digest(
        &frame[..RESPONSE_DIGEST_OFFSET],
        &frame[RESPONSE_HEADER_BYTES..],
    )?;
    frame[RESPONSE_DIGEST_OFFSET..RESPONSE_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    Ok(frame)
}

fn request_v2_digest(header: &[u8]) -> Result<Digest32, InspectionProtocolError> {
    let mut builder = Digest32Builder::try_new(REQUEST_V2_DIGEST_DOMAIN)
        .map_err(|_| InspectionProtocolError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .map_err(|_| InspectionProtocolError::DigestEncodingFailed)?;
    Ok(builder.finish())
}

fn response_v2_digest(header: &[u8], payload: &[u8]) -> Result<Digest32, InspectionProtocolError> {
    let mut builder = Digest32Builder::try_new(RESPONSE_V2_DIGEST_DOMAIN)
        .map_err(|_| InspectionProtocolError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .and_then(|builder| builder.field_bytes(payload))
        .map_err(|_| InspectionProtocolError::DigestEncodingFailed)?;
    Ok(builder.finish())
}
