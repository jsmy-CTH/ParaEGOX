//! Strict experimental request/response envelopes owned by the Fabric service.

use core::{fmt, num::NonZeroU64};

use paraegox_kernel::digest::Digest32;
use paraegox_runtime_contracts::assignment::{BindingId, SchemaRef};

/// Version shared by the request and response binding envelopes.
pub const REQUEST_RESPONSE_ENVELOPE_VERSION: u16 = 1;
/// Hard upper bound independent of deployment-selected ingress limits.
pub const MAX_ENVELOPE_BODY_BYTES: usize = 1_048_576;

const REQUEST_MAGIC: &[u8; 4] = b"PXFQ";
const RESPONSE_MAGIC: &[u8; 4] = b"PXFP";
pub(crate) const REQUEST_HEADER_BYTES: usize = 104;
const RESPONSE_HEADER_BYTES: usize = 108;

/// Runtime/Fabric-owned generation of one installed logical binding.
///
/// Epochs are only comparable after the [`BindingId`] is known to match.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BindingEpoch(NonZeroU64);

impl BindingEpoch {
    /// Creates a nonzero binding epoch.
    pub const fn try_new(value: u64) -> Result<Self, FabricContractError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(FabricContractError::ZeroBindingEpoch),
        }
    }

    /// Returns the canonical integer value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn next(self) -> Result<Self, FabricContractError> {
        let Some(next) = self.value().checked_add(1) else {
            return Err(FabricContractError::BindingEpochExhausted);
        };
        Self::try_new(next)
    }
}

/// Caller-owned identity of one request attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId([u8; 16]);

impl RequestId {
    /// Creates a nonzero request identity.
    pub const fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, FabricContractError> {
        if all_zero(&bytes) {
            return Err(FabricContractError::ZeroRequestId);
        }
        Ok(Self(bytes))
    }

    /// Returns the canonical identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Stable response outcome carried inside a successful Zenoh query reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ResponseStatus {
    /// The typed handler produced a response body.
    Ok = 0,
    /// The fixed request frame or exact schema was invalid.
    MalformedRequest = 1,
    /// The request named an inactive BindingEpoch; the reply identifies the
    /// current generation that rejected it.
    StaleBinding = 2,
    /// A bounded ingress or handler boundary had no capacity.
    IngressOverloaded = 3,
    /// No typed handler was available for this binding.
    HandlerUnavailable = 4,
    /// The typed handler did not answer before its owner-local timeout.
    HandlerTimeout = 5,
    /// The typed handler explicitly rejected the request.
    HandlerRejected = 6,
    /// The typed handler returned a body above the binding response bound.
    ResponseTooLarge = 7,
}

impl TryFrom<u16> for ResponseStatus {
    type Error = FabricContractError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::MalformedRequest),
            2 => Ok(Self::StaleBinding),
            3 => Ok(Self::IngressOverloaded),
            4 => Ok(Self::HandlerUnavailable),
            5 => Ok(Self::HandlerTimeout),
            6 => Ok(Self::HandlerRejected),
            7 => Ok(Self::ResponseTooLarge),
            _ => Err(FabricContractError::UnknownResponseStatus),
        }
    }
}

/// Immutable request carried by one query on an installed [`crate::PortBinding`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingRequestEnvelopeV1 {
    binding_id: BindingId,
    binding_epoch: BindingEpoch,
    request_id: RequestId,
    schema: SchemaRef,
    body: Box<[u8]>,
}

impl BindingRequestEnvelopeV1 {
    /// Constructs a request after applying the protocol-wide body bound.
    pub fn try_new(
        binding_id: BindingId,
        binding_epoch: BindingEpoch,
        request_id: RequestId,
        schema: SchemaRef,
        body: Vec<u8>,
    ) -> Result<Self, FabricContractError> {
        validate_binding_id(binding_id)?;
        validate_body_length(body.len(), MAX_ENVELOPE_BODY_BYTES)?;
        Ok(Self {
            binding_id,
            binding_epoch,
            request_id,
            schema,
            body: body.into_boxed_slice(),
        })
    }

    /// Returns the logical binding identity.
    #[must_use]
    pub const fn binding_id(&self) -> BindingId {
        self.binding_id
    }

    /// Returns the exact live binding generation.
    #[must_use]
    pub const fn binding_epoch(&self) -> BindingEpoch {
        self.binding_epoch
    }

    /// Returns the caller-owned request identity.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the exact request schema.
    #[must_use]
    pub const fn schema(&self) -> SchemaRef {
        self.schema
    }

    /// Returns the immutable request body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Encodes the unique canonical v1 request frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(REQUEST_HEADER_BYTES + self.body.len());
        encoded.extend_from_slice(REQUEST_MAGIC);
        encoded.extend_from_slice(&REQUEST_RESPONSE_ENVELOPE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&(REQUEST_HEADER_BYTES as u16).to_be_bytes());
        encoded.extend_from_slice(self.binding_id.as_bytes());
        encoded.extend_from_slice(&self.binding_epoch.value().to_be_bytes());
        encoded.extend_from_slice(self.request_id.as_bytes());
        encode_schema(self.schema, &mut encoded);
        encoded.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.body);
        encoded
    }

    /// Strictly decodes one canonical v1 request frame.
    pub fn decode(bytes: &[u8], max_body_bytes: usize) -> Result<Self, FabricContractError> {
        let header = decode_common_header(bytes, REQUEST_MAGIC, REQUEST_HEADER_BYTES)?;
        let body = decode_body(
            bytes,
            REQUEST_HEADER_BYTES,
            header.body_length,
            max_body_bytes,
        )?;
        Self::try_new(
            header.binding_id,
            header.binding_epoch,
            header.request_id,
            header.schema,
            body.to_vec(),
        )
    }
}

/// Immutable response paired to one exact request attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingResponseEnvelopeV1 {
    binding_id: BindingId,
    binding_epoch: BindingEpoch,
    request_id: RequestId,
    schema: SchemaRef,
    status: ResponseStatus,
    body: Box<[u8]>,
}

impl BindingResponseEnvelopeV1 {
    /// Constructs a response after applying the protocol-wide body bound.
    pub fn try_new(
        binding_id: BindingId,
        binding_epoch: BindingEpoch,
        request_id: RequestId,
        schema: SchemaRef,
        status: ResponseStatus,
        body: Vec<u8>,
    ) -> Result<Self, FabricContractError> {
        validate_binding_id(binding_id)?;
        validate_body_length(body.len(), MAX_ENVELOPE_BODY_BYTES)?;
        Ok(Self {
            binding_id,
            binding_epoch,
            request_id,
            schema,
            status,
            body: body.into_boxed_slice(),
        })
    }

    /// Returns the logical binding identity.
    #[must_use]
    pub const fn binding_id(&self) -> BindingId {
        self.binding_id
    }

    /// Returns the exact live binding generation.
    #[must_use]
    pub const fn binding_epoch(&self) -> BindingEpoch {
        self.binding_epoch
    }

    /// Returns the exact request being answered.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the exact response schema.
    #[must_use]
    pub const fn schema(&self) -> SchemaRef {
        self.schema
    }

    /// Returns the stable response status.
    #[must_use]
    pub const fn status(&self) -> ResponseStatus {
        self.status
    }

    /// Returns the immutable response body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Encodes the unique canonical v1 response frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(RESPONSE_HEADER_BYTES + self.body.len());
        encoded.extend_from_slice(RESPONSE_MAGIC);
        encoded.extend_from_slice(&REQUEST_RESPONSE_ENVELOPE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&(RESPONSE_HEADER_BYTES as u16).to_be_bytes());
        encoded.extend_from_slice(self.binding_id.as_bytes());
        encoded.extend_from_slice(&self.binding_epoch.value().to_be_bytes());
        encoded.extend_from_slice(self.request_id.as_bytes());
        encode_schema(self.schema, &mut encoded);
        encoded.extend_from_slice(&(self.status as u16).to_be_bytes());
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.body);
        encoded
    }

    /// Strictly decodes one canonical v1 response frame.
    pub fn decode(bytes: &[u8], max_body_bytes: usize) -> Result<Self, FabricContractError> {
        if bytes.len() < RESPONSE_HEADER_BYTES {
            return Err(FabricContractError::TruncatedFrame);
        }
        if &bytes[..4] != RESPONSE_MAGIC {
            return Err(FabricContractError::WrongMagic);
        }
        let mut cursor = Cursor::new(bytes);
        cursor.skip(4)?;
        let version = cursor.u16()?;
        if version != REQUEST_RESPONSE_ENVELOPE_VERSION {
            return Err(FabricContractError::UnsupportedVersion);
        }
        let header_length = usize::from(cursor.u16()?);
        if header_length != RESPONSE_HEADER_BYTES {
            return Err(FabricContractError::WrongHeaderLength);
        }
        let binding_id = BindingId::from_bytes(cursor.array()?);
        validate_binding_id(binding_id)?;
        let binding_epoch = BindingEpoch::try_new(cursor.u64()?)?;
        let request_id = RequestId::try_from_bytes(cursor.array()?)?;
        let schema = decode_schema(&mut cursor)?;
        let status = ResponseStatus::try_from(cursor.u16()?)?;
        if cursor.u16()? != 0 {
            return Err(FabricContractError::NonzeroReservedField);
        }
        let body_length = cursor.u32()? as usize;
        let body = decode_body(bytes, RESPONSE_HEADER_BYTES, body_length, max_body_bytes)?;
        Self::try_new(
            binding_id,
            binding_epoch,
            request_id,
            schema,
            status,
            body.to_vec(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestHeaderDisposition {
    Valid {
        request_id: RequestId,
    },
    Reject {
        request_id: RequestId,
        status: ResponseStatus,
    },
    Drop,
}

pub(crate) fn prevalidate_request_header(
    bytes: &[u8],
    total_length: usize,
    expected_binding_id: BindingId,
    expected_epoch: BindingEpoch,
    expected_schema: SchemaRef,
) -> RequestHeaderDisposition {
    let Ok(header) = decode_common_header(bytes, REQUEST_MAGIC, REQUEST_HEADER_BYTES) else {
        return RequestHeaderDisposition::Drop;
    };
    let Some(expected_total) = REQUEST_HEADER_BYTES.checked_add(header.body_length) else {
        return RequestHeaderDisposition::Reject {
            request_id: header.request_id,
            status: ResponseStatus::MalformedRequest,
        };
    };
    if expected_total != total_length || header.schema != expected_schema {
        return RequestHeaderDisposition::Reject {
            request_id: header.request_id,
            status: ResponseStatus::MalformedRequest,
        };
    }
    if header.binding_id != expected_binding_id || header.binding_epoch != expected_epoch {
        return RequestHeaderDisposition::Reject {
            request_id: header.request_id,
            status: ResponseStatus::StaleBinding,
        };
    }
    RequestHeaderDisposition::Valid {
        request_id: header.request_id,
    }
}

#[derive(Clone, Copy)]
struct CommonHeader {
    binding_id: BindingId,
    binding_epoch: BindingEpoch,
    request_id: RequestId,
    schema: SchemaRef,
    body_length: usize,
}

fn decode_common_header(
    bytes: &[u8],
    magic: &[u8; 4],
    expected_header_length: usize,
) -> Result<CommonHeader, FabricContractError> {
    if bytes.len() < expected_header_length {
        return Err(FabricContractError::TruncatedFrame);
    }
    if &bytes[..4] != magic {
        return Err(FabricContractError::WrongMagic);
    }
    let mut cursor = Cursor::new(bytes);
    cursor.skip(4)?;
    if cursor.u16()? != REQUEST_RESPONSE_ENVELOPE_VERSION {
        return Err(FabricContractError::UnsupportedVersion);
    }
    if usize::from(cursor.u16()?) != expected_header_length {
        return Err(FabricContractError::WrongHeaderLength);
    }
    let binding_id = BindingId::from_bytes(cursor.array()?);
    validate_binding_id(binding_id)?;
    let binding_epoch = BindingEpoch::try_new(cursor.u64()?)?;
    let request_id = RequestId::try_from_bytes(cursor.array()?)?;
    let schema = decode_schema(&mut cursor)?;
    let body_length = cursor.u32()? as usize;
    Ok(CommonHeader {
        binding_id,
        binding_epoch,
        request_id,
        schema,
        body_length,
    })
}

fn encode_schema(schema: SchemaRef, encoded: &mut Vec<u8>) {
    encoded.extend_from_slice(schema.id_bytes());
    encoded.extend_from_slice(&schema.version().to_be_bytes());
    encoded.extend_from_slice(schema.content_digest().as_bytes());
}

fn decode_schema(cursor: &mut Cursor<'_>) -> Result<SchemaRef, FabricContractError> {
    let id = cursor.array()?;
    let version = cursor.u32()?;
    let digest = Digest32::from_bytes(cursor.array()?);
    SchemaRef::try_new(id, version, digest).map_err(|_| FabricContractError::InvalidSchema)
}

fn decode_body(
    bytes: &[u8],
    header_length: usize,
    declared_length: usize,
    configured_max: usize,
) -> Result<&[u8], FabricContractError> {
    let max = configured_max.min(MAX_ENVELOPE_BODY_BYTES);
    validate_body_length(declared_length, max)?;
    let expected = header_length
        .checked_add(declared_length)
        .ok_or(FabricContractError::FrameLengthOverflow)?;
    if bytes.len() != expected {
        return Err(FabricContractError::BodyLengthMismatch);
    }
    Ok(&bytes[header_length..])
}

fn validate_body_length(length: usize, max: usize) -> Result<(), FabricContractError> {
    if length > max || u32::try_from(length).is_err() {
        return Err(FabricContractError::BodyTooLarge);
    }
    Ok(())
}

pub(crate) fn validate_binding_id(binding_id: BindingId) -> Result<(), FabricContractError> {
    if all_zero(binding_id.as_bytes()) {
        return Err(FabricContractError::ZeroBindingId);
    }
    Ok(())
}

const fn all_zero<const N: usize>(bytes: &[u8; N]) -> bool {
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
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn skip(&mut self, count: usize) -> Result<(), FabricContractError> {
        self.take(count).map(|_| ())
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], FabricContractError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(FabricContractError::FrameLengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FabricContractError::TruncatedFrame)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FabricContractError> {
        self.take(N)?
            .try_into()
            .map_err(|_| FabricContractError::TruncatedFrame)
    }

    fn u16(&mut self) -> Result<u16, FabricContractError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, FabricContractError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, FabricContractError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

/// Stable request/response contract rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FabricContractError {
    ZeroBindingId,
    ZeroBindingEpoch,
    BindingEpochExhausted,
    ZeroRequestId,
    InvalidSchema,
    WrongMagic,
    UnsupportedVersion,
    WrongHeaderLength,
    TruncatedFrame,
    FrameLengthOverflow,
    BodyLengthMismatch,
    BodyTooLarge,
    UnknownResponseStatus,
    NonzeroReservedField,
}

impl fmt::Display for FabricContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroBindingId => "BindingId must be nonzero",
            Self::ZeroBindingEpoch => "BindingEpoch must be nonzero",
            Self::BindingEpochExhausted => "BindingEpoch is exhausted",
            Self::ZeroRequestId => "RequestId must be nonzero",
            Self::InvalidSchema => "schema reference is invalid",
            Self::WrongMagic => "envelope magic does not match",
            Self::UnsupportedVersion => "envelope version is unsupported",
            Self::WrongHeaderLength => "envelope header length does not match",
            Self::TruncatedFrame => "envelope is truncated",
            Self::FrameLengthOverflow => "envelope length arithmetic overflowed",
            Self::BodyLengthMismatch => "declared body length does not match the frame",
            Self::BodyTooLarge => "envelope body exceeds its hard bound",
            Self::UnknownResponseStatus => "response status is unknown",
            Self::NonzeroReservedField => "reserved response field must be zero",
        })
    }
}

impl std::error::Error for FabricContractError {}

#[cfg(test)]
mod tests {
    use super::{
        BindingEpoch, BindingRequestEnvelopeV1, BindingResponseEnvelopeV1, FabricContractError,
        RequestId, ResponseStatus,
    };
    use paraegox_kernel::digest::Digest32;
    use paraegox_runtime_contracts::assignment::{BindingId, SchemaRef};

    fn schema(marker: u8) -> SchemaRef {
        SchemaRef::try_new([marker; 16], 1, Digest32::from_bytes([marker; 32])).unwrap()
    }

    #[test]
    fn request_and_response_have_strict_canonical_round_trips() {
        const REQUEST_GOLDEN: &[u8; 109] = b"PXFQ\x00\x01\x00\x68\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x00\x00\x00\x00\x00\x00\x00\x07\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x00\x00\x00\x01\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x00\x00\x00\x05hello";
        const RESPONSE_GOLDEN: &[u8; 113] = b"PXFP\x00\x01\x00\x6c\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x00\x00\x00\x00\x00\x00\x00\x07\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x00\x00\x00\x01\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x00\x06\x00\x00\x00\x00\x00\x05world";
        let binding = BindingId::from_bytes([0x11; 16]);
        let epoch = BindingEpoch::try_new(7).unwrap();
        let request_id = RequestId::try_from_bytes([0x22; 16]).unwrap();
        let request = BindingRequestEnvelopeV1::try_new(
            binding,
            epoch,
            request_id,
            schema(0x33),
            b"hello".to_vec(),
        )
        .unwrap();
        let request_bytes = request.encode();
        assert_eq!(request_bytes.as_slice(), REQUEST_GOLDEN);
        assert_eq!(
            BindingRequestEnvelopeV1::decode(&request_bytes, 32).unwrap(),
            request
        );

        let response = BindingResponseEnvelopeV1::try_new(
            binding,
            epoch,
            request_id,
            schema(0x44),
            ResponseStatus::HandlerRejected,
            b"world".to_vec(),
        )
        .unwrap();
        let response_bytes = response.encode();
        assert_eq!(response_bytes.as_slice(), RESPONSE_GOLDEN);
        assert_eq!(
            BindingResponseEnvelopeV1::decode(&response_bytes, 32).unwrap(),
            response
        );
    }

    #[test]
    fn alternate_or_oversized_frames_fail_closed() {
        let request = BindingRequestEnvelopeV1::try_new(
            BindingId::from_bytes([1; 16]),
            BindingEpoch::try_new(1).unwrap(),
            RequestId::try_from_bytes([2; 16]).unwrap(),
            schema(3),
            vec![4; 8],
        )
        .unwrap();
        let mut bytes = request.encode();
        bytes.push(0);
        assert_eq!(
            BindingRequestEnvelopeV1::decode(&bytes, 8),
            Err(FabricContractError::BodyLengthMismatch)
        );
        assert_eq!(
            BindingRequestEnvelopeV1::decode(&request.encode(), 7),
            Err(FabricContractError::BodyTooLarge)
        );

        let canonical = request.encode();
        for (offset, value, expected) in [
            (0, b'X', FabricContractError::WrongMagic),
            (5, 2, FabricContractError::UnsupportedVersion),
            (7, 103, FabricContractError::WrongHeaderLength),
        ] {
            let mut alternate = canonical.clone();
            alternate[offset] = value;
            assert_eq!(
                BindingRequestEnvelopeV1::decode(&alternate, 8),
                Err(expected)
            );
        }
        let mut zero_binding = canonical.clone();
        zero_binding[8..24].fill(0);
        assert_eq!(
            BindingRequestEnvelopeV1::decode(&zero_binding, 8),
            Err(FabricContractError::ZeroBindingId)
        );
        let mut zero_request = canonical.clone();
        zero_request[32..48].fill(0);
        assert_eq!(
            BindingRequestEnvelopeV1::decode(&zero_request, 8),
            Err(FabricContractError::ZeroRequestId)
        );

        let response = BindingResponseEnvelopeV1::try_new(
            BindingId::from_bytes([1; 16]),
            BindingEpoch::try_new(1).unwrap(),
            RequestId::try_from_bytes([2; 16]).unwrap(),
            schema(3),
            ResponseStatus::Ok,
            Vec::new(),
        )
        .unwrap();
        let mut unknown_status = response.encode();
        unknown_status[101] = 8;
        assert_eq!(
            BindingResponseEnvelopeV1::decode(&unknown_status, 0),
            Err(FabricContractError::UnknownResponseStatus)
        );
        let mut nonzero_reserved = response.encode();
        nonzero_reserved[103] = 1;
        assert_eq!(
            BindingResponseEnvelopeV1::decode(&nonzero_reserved, 0),
            Err(FabricContractError::NonzeroReservedField)
        );
    }
}
