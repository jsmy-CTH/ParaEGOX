//! Local durable Evidence contract and typed store.
//!
//! Receipt/Evidence records are authoritative and therefore are not log or
//! trace events. The first version accepts either bounded public-safe inline
//! bytes or a digest-only redacted representation. It has no exporter,
//! replication, global ordering, generic object resolver, or authority to
//! infer a domain operation's success.

use core::{fmt, num::NonZeroU64};

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};

#[cfg(unix)]
mod store;
#[cfg(unix)]
pub use store::{
    EvidenceAppendOutcomeV1, EvidenceListCursorV1, EvidenceListPageV1, EvidenceRetentionPolicyV1,
    EvidenceStoreError, EvidenceStoredRecordV1, LocalEvidenceStoreV1, MAX_EVIDENCE_QUERY_RECORDS,
    MAX_EVIDENCE_STORE_BYTES, MAX_EVIDENCE_STORE_RECORDS,
};

/// Strict canonical Evidence record version.
pub const EVIDENCE_RECORD_VERSION: u16 = 1;
/// Exact fixed record header bytes.
pub const EVIDENCE_RECORD_HEADER_BYTES: usize = 160;
/// Largest public-safe inline payload admitted by the v1 contract.
pub const MAX_EVIDENCE_INLINE_PAYLOAD_BYTES: usize = 32 * 1024;
/// Largest complete canonical record frame.
pub const MAX_EVIDENCE_RECORD_BYTES: usize =
    EVIDENCE_RECORD_HEADER_BYTES + MAX_EVIDENCE_INLINE_PAYLOAD_BYTES;

const RECORD_MAGIC: &[u8; 4] = b"PXEV";
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"paraegox.evidence.payload.v1";
const RECORD_DIGEST_DOMAIN: &[u8] = b"paraegox.evidence.record.v1";
const RECORD_DIGEST_OFFSET: usize = 128;

macro_rules! opaque_id {
    ($name:ident, $error:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Constructs a nonzero owner-scoped identity.
            pub const fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, EvidenceContractError> {
                let mut index = 0;
                while index < bytes.len() {
                    if bytes[index] != 0 {
                        return Ok(Self(bytes));
                    }
                    index += 1;
                }
                Err(EvidenceContractError::$error)
            }

            /// Returns the canonical bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_id!(EvidenceRecordIdV1, ZeroRecordId);
opaque_id!(EvidenceOwnerRefV1, ZeroOwnerRef);
opaque_id!(EvidenceCausalityRefV1, ZeroCausalityRef);
opaque_id!(EvidenceStoreEpochV1, ZeroStoreEpoch);

/// Bounded authority category retained with one owner-issued record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EvidenceKindV1 {
    OwnerReceipt = 1,
    RuntimeFact = 2,
    SecurityAudit = 3,
    IncidentSnapshot = 4,
}

impl EvidenceKindV1 {
    fn decode(value: u8) -> Result<Self, EvidenceContractError> {
        match value {
            1 => Ok(Self::OwnerReceipt),
            2 => Ok(Self::RuntimeFact),
            3 => Ok(Self::SecurityAudit),
            4 => Ok(Self::IncidentSnapshot),
            _ => Err(EvidenceContractError::UnknownEvidenceKind),
        }
    }
}

/// Redaction representation admitted at the durable boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EvidenceRedactionV1 {
    /// Payload bytes have already been classified as safe for this store.
    PublicSafeInline = 1,
    /// Sensitive source bytes are absent; only their owner-issued digest stays.
    DigestOnly = 2,
}

impl EvidenceRedactionV1 {
    fn decode(value: u8) -> Result<Self, EvidenceContractError> {
        match value {
            1 => Ok(Self::PublicSafeInline),
            2 => Ok(Self::DigestOnly),
            _ => Err(EvidenceContractError::UnknownRedaction),
        }
    }
}

/// Payload accepted by the first local Evidence sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidencePayloadV1 {
    PublicSafeInline(Box<[u8]>),
    DigestOnly(Digest32),
}

impl EvidencePayloadV1 {
    /// Validates and copies bounded public-safe bytes.
    pub fn try_public_safe_inline(bytes: &[u8]) -> Result<Self, EvidenceContractError> {
        if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_INLINE_PAYLOAD_BYTES {
            return Err(EvidenceContractError::InvalidInlinePayloadLength);
        }
        Ok(Self::PublicSafeInline(bytes.into()))
    }

    /// Retains only a nonzero digest of bytes redacted before this boundary.
    pub fn try_digest_only(digest: Digest32) -> Result<Self, EvidenceContractError> {
        if bytes_are_zero(digest.as_bytes()) {
            return Err(EvidenceContractError::ZeroPayloadDigest);
        }
        Ok(Self::DigestOnly(digest))
    }

    #[must_use]
    pub const fn redaction(&self) -> EvidenceRedactionV1 {
        match self {
            Self::PublicSafeInline(_) => EvidenceRedactionV1::PublicSafeInline,
            Self::DigestOnly(_) => EvidenceRedactionV1::DigestOnly,
        }
    }

    #[must_use]
    pub fn inline_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::PublicSafeInline(bytes) => Some(bytes),
            Self::DigestOnly(_) => None,
        }
    }

    fn digest(&self) -> Result<Digest32, EvidenceContractError> {
        match self {
            Self::PublicSafeInline(bytes) => {
                let mut builder = Digest32Builder::try_new(PAYLOAD_DIGEST_DOMAIN)?;
                builder.field_bytes(bytes)?;
                Ok(builder.finish())
            }
            Self::DigestOnly(digest) => Ok(*digest),
        }
    }
}

/// Complete immutable input to one owner-issued Evidence record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecordInputV1 {
    pub record_id: EvidenceRecordIdV1,
    pub owner_ref: EvidenceOwnerRefV1,
    pub producer_sequence: u64,
    pub causality_ref: Option<EvidenceCausalityRefV1>,
    pub previous_evidence_ref: Option<EvidenceRecordIdV1>,
    pub kind: EvidenceKindV1,
    pub payload: EvidencePayloadV1,
}

/// Strict canonical owner-issued Evidence record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecordV1 {
    record_id: EvidenceRecordIdV1,
    owner_ref: EvidenceOwnerRefV1,
    producer_sequence: NonZeroU64,
    causality_ref: Option<EvidenceCausalityRefV1>,
    previous_evidence_ref: Option<EvidenceRecordIdV1>,
    kind: EvidenceKindV1,
    payload: EvidencePayloadV1,
    payload_digest: Digest32,
    record_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl EvidenceRecordV1 {
    /// Constructs one canonical record. This does not claim it is durable.
    pub fn try_new(input: EvidenceRecordInputV1) -> Result<Self, EvidenceContractError> {
        let producer_sequence = NonZeroU64::new(input.producer_sequence)
            .ok_or(EvidenceContractError::ZeroProducerSequence)?;
        if input.previous_evidence_ref == Some(input.record_id) {
            return Err(EvidenceContractError::SelfPreviousReference);
        }
        let payload_digest = input.payload.digest()?;
        if bytes_are_zero(payload_digest.as_bytes()) {
            return Err(EvidenceContractError::ZeroPayloadDigest);
        }
        let record_digest = record_digest(&input, payload_digest)?;
        if bytes_are_zero(record_digest.as_bytes()) {
            return Err(EvidenceContractError::ZeroRecordDigest);
        }
        let canonical_wire = encode_record(&input, payload_digest, record_digest)?;
        Ok(Self {
            record_id: input.record_id,
            owner_ref: input.owner_ref,
            producer_sequence,
            causality_ref: input.causality_ref,
            previous_evidence_ref: input.previous_evidence_ref,
            kind: input.kind,
            payload: input.payload,
            payload_digest,
            record_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes one complete canonical PXEV-v1 frame.
    pub fn decode(wire: &[u8]) -> Result<Self, EvidenceContractError> {
        if wire.len() < EVIDENCE_RECORD_HEADER_BYTES || wire.len() > MAX_EVIDENCE_RECORD_BYTES {
            return Err(EvidenceContractError::InvalidRecordLength);
        }
        if &wire[..4] != RECORD_MAGIC
            || read_u16(&wire[4..6]) != EVIDENCE_RECORD_VERSION
            || usize::from(read_u16(&wire[6..8])) != EVIDENCE_RECORD_HEADER_BYTES
        {
            return Err(EvidenceContractError::UnsupportedRecordFrame);
        }
        if usize::try_from(read_u32(&wire[8..12]))
            .map_err(|_| EvidenceContractError::InvalidRecordLength)?
            != wire.len()
            || wire[14..16].iter().any(|byte| *byte != 0)
            || wire[92..96].iter().any(|byte| *byte != 0)
        {
            return Err(EvidenceContractError::NonCanonicalEncoding);
        }
        let kind = EvidenceKindV1::decode(wire[12])?;
        let redaction = EvidenceRedactionV1::decode(wire[13])?;
        let record_id = EvidenceRecordIdV1::try_from_bytes(read_array(&wire[16..32]))?;
        let owner_ref = EvidenceOwnerRefV1::try_from_bytes(read_array(&wire[32..48]))?;
        let causality_ref =
            decode_optional_id(&wire[48..64], EvidenceCausalityRefV1::try_from_bytes)?;
        let previous_evidence_ref =
            decode_optional_id(&wire[64..80], EvidenceRecordIdV1::try_from_bytes)?;
        let producer_sequence = read_u64(&wire[80..88]);
        let payload_length = usize::try_from(read_u32(&wire[88..92]))
            .map_err(|_| EvidenceContractError::InvalidInlinePayloadLength)?;
        if EVIDENCE_RECORD_HEADER_BYTES
            .checked_add(payload_length)
            .ok_or(EvidenceContractError::InvalidRecordLength)?
            != wire.len()
        {
            return Err(EvidenceContractError::InvalidRecordLength);
        }
        let declared_payload_digest = Digest32::from_bytes(read_array(&wire[96..128]));
        let declared_record_digest =
            Digest32::from_bytes(read_array(&wire[RECORD_DIGEST_OFFSET..160]));
        let payload = match redaction {
            EvidenceRedactionV1::PublicSafeInline => {
                EvidencePayloadV1::try_public_safe_inline(&wire[160..])?
            }
            EvidenceRedactionV1::DigestOnly => {
                if payload_length != 0 {
                    return Err(EvidenceContractError::NonCanonicalEncoding);
                }
                EvidencePayloadV1::try_digest_only(declared_payload_digest)?
            }
        };
        if payload.digest()? != declared_payload_digest {
            return Err(EvidenceContractError::PayloadDigestMismatch);
        }
        let record = Self::try_new(EvidenceRecordInputV1 {
            record_id,
            owner_ref,
            producer_sequence,
            causality_ref,
            previous_evidence_ref,
            kind,
            payload,
        })?;
        if record.record_digest != declared_record_digest {
            return Err(EvidenceContractError::RecordDigestMismatch);
        }
        if record.canonical_wire() != wire {
            return Err(EvidenceContractError::NonCanonicalEncoding);
        }
        Ok(record)
    }

    #[must_use]
    pub const fn record_id(&self) -> EvidenceRecordIdV1 {
        self.record_id
    }

    #[must_use]
    pub const fn owner_ref(&self) -> EvidenceOwnerRefV1 {
        self.owner_ref
    }

    #[must_use]
    pub const fn producer_sequence(&self) -> u64 {
        self.producer_sequence.get()
    }

    #[must_use]
    pub const fn causality_ref(&self) -> Option<EvidenceCausalityRefV1> {
        self.causality_ref
    }

    #[must_use]
    pub const fn previous_evidence_ref(&self) -> Option<EvidenceRecordIdV1> {
        self.previous_evidence_ref
    }

    #[must_use]
    pub const fn kind(&self) -> EvidenceKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn payload(&self) -> &EvidencePayloadV1 {
        &self.payload
    }

    #[must_use]
    pub const fn payload_digest(&self) -> Digest32 {
        self.payload_digest
    }

    #[must_use]
    pub const fn record_digest(&self) -> Digest32 {
        self.record_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// Stable typed reference to one locally committed record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EvidenceRefV1 {
    store_epoch: EvidenceStoreEpochV1,
    local_sequence: NonZeroU64,
    record_id: EvidenceRecordIdV1,
    record_digest: Digest32,
}

impl EvidenceRefV1 {
    pub(crate) fn try_new(
        store_epoch: EvidenceStoreEpochV1,
        local_sequence: u64,
        record_id: EvidenceRecordIdV1,
        record_digest: Digest32,
    ) -> Result<Self, EvidenceContractError> {
        let local_sequence =
            NonZeroU64::new(local_sequence).ok_or(EvidenceContractError::ZeroLocalSequence)?;
        if bytes_are_zero(record_digest.as_bytes()) {
            return Err(EvidenceContractError::ZeroRecordDigest);
        }
        Ok(Self {
            store_epoch,
            local_sequence,
            record_id,
            record_digest,
        })
    }

    #[must_use]
    pub const fn store_epoch(self) -> EvidenceStoreEpochV1 {
        self.store_epoch
    }

    #[must_use]
    pub const fn local_sequence(self) -> u64 {
        self.local_sequence.get()
    }

    #[must_use]
    pub const fn record_id(self) -> EvidenceRecordIdV1 {
        self.record_id
    }

    #[must_use]
    pub const fn record_digest(self) -> Digest32 {
        self.record_digest
    }
}

/// Local durable handoff acknowledgement. It does not reinterpret the owner's
/// receipt and does not claim an external effect succeeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceCommitReceiptV1 {
    evidence_ref: EvidenceRefV1,
    replayed: bool,
}

impl EvidenceCommitReceiptV1 {
    pub(crate) const fn new(evidence_ref: EvidenceRefV1, replayed: bool) -> Self {
        Self {
            evidence_ref,
            replayed,
        }
    }

    #[must_use]
    pub const fn evidence_ref(self) -> EvidenceRefV1 {
        self.evidence_ref
    }

    #[must_use]
    pub const fn replayed(self) -> bool {
        self.replayed
    }
}

/// Stable strict contract failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceContractError {
    ZeroRecordId,
    ZeroOwnerRef,
    ZeroCausalityRef,
    ZeroStoreEpoch,
    ZeroProducerSequence,
    ZeroLocalSequence,
    ZeroPayloadDigest,
    ZeroRecordDigest,
    SelfPreviousReference,
    InvalidInlinePayloadLength,
    InvalidRecordLength,
    UnsupportedRecordFrame,
    UnknownEvidenceKind,
    UnknownRedaction,
    PayloadDigestMismatch,
    RecordDigestMismatch,
    NonCanonicalEncoding,
    Digest(DigestBuildError),
}

impl fmt::Display for EvidenceContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Evidence contract rejected: {self:?}")
    }
}

impl std::error::Error for EvidenceContractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Digest(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DigestBuildError> for EvidenceContractError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

fn record_digest(
    input: &EvidenceRecordInputV1,
    payload_digest: Digest32,
) -> Result<Digest32, EvidenceContractError> {
    let mut builder = Digest32Builder::try_new(RECORD_DIGEST_DOMAIN)?;
    builder
        .field_bytes(input.record_id.as_bytes())?
        .field_bytes(input.owner_ref.as_bytes())?
        .field_u64(input.producer_sequence)?
        .field_bytes(&optional_id_bytes(input.causality_ref))?
        .field_bytes(&optional_id_bytes(input.previous_evidence_ref))?
        .field_bytes(&[input.kind as u8])?
        .field_bytes(&[input.payload.redaction() as u8])?
        .field_digest(&payload_digest)?;
    Ok(builder.finish())
}

fn encode_record(
    input: &EvidenceRecordInputV1,
    payload_digest: Digest32,
    record_digest: Digest32,
) -> Result<Vec<u8>, EvidenceContractError> {
    let inline = input.payload.inline_bytes().unwrap_or_default();
    let total_length = EVIDENCE_RECORD_HEADER_BYTES
        .checked_add(inline.len())
        .ok_or(EvidenceContractError::InvalidRecordLength)?;
    let total_length_u32 =
        u32::try_from(total_length).map_err(|_| EvidenceContractError::InvalidRecordLength)?;
    let payload_length = u32::try_from(inline.len())
        .map_err(|_| EvidenceContractError::InvalidInlinePayloadLength)?;
    let mut wire = vec![0_u8; total_length];
    wire[..4].copy_from_slice(RECORD_MAGIC);
    wire[4..6].copy_from_slice(&EVIDENCE_RECORD_VERSION.to_be_bytes());
    wire[6..8].copy_from_slice(
        &u16::try_from(EVIDENCE_RECORD_HEADER_BYTES)
            .map_err(|_| EvidenceContractError::InvalidRecordLength)?
            .to_be_bytes(),
    );
    wire[8..12].copy_from_slice(&total_length_u32.to_be_bytes());
    wire[12] = input.kind as u8;
    wire[13] = input.payload.redaction() as u8;
    wire[16..32].copy_from_slice(input.record_id.as_bytes());
    wire[32..48].copy_from_slice(input.owner_ref.as_bytes());
    wire[48..64].copy_from_slice(&optional_id_bytes(input.causality_ref));
    wire[64..80].copy_from_slice(&optional_id_bytes(input.previous_evidence_ref));
    wire[80..88].copy_from_slice(&input.producer_sequence.to_be_bytes());
    wire[88..92].copy_from_slice(&payload_length.to_be_bytes());
    wire[96..128].copy_from_slice(payload_digest.as_bytes());
    wire[RECORD_DIGEST_OFFSET..160].copy_from_slice(record_digest.as_bytes());
    wire[160..].copy_from_slice(inline);
    Ok(wire)
}

trait OptionalOpaqueId: Copy {
    fn bytes(self) -> [u8; 16];
}

impl OptionalOpaqueId for EvidenceCausalityRefV1 {
    fn bytes(self) -> [u8; 16] {
        *self.as_bytes()
    }
}

impl OptionalOpaqueId for EvidenceRecordIdV1 {
    fn bytes(self) -> [u8; 16] {
        *self.as_bytes()
    }
}

fn optional_id_bytes<T: OptionalOpaqueId>(value: Option<T>) -> [u8; 16] {
    value.map_or([0; 16], OptionalOpaqueId::bytes)
}

fn decode_optional_id<T>(
    bytes: &[u8],
    constructor: fn([u8; 16]) -> Result<T, EvidenceContractError>,
) -> Result<Option<T>, EvidenceContractError> {
    let bytes = read_array(bytes);
    if bytes_are_zero(&bytes) {
        Ok(None)
    } else {
        constructor(bytes).map(Some)
    }
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
    let mut array = [0_u8; N];
    array.copy_from_slice(bytes);
    array
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(payload: EvidencePayloadV1) -> EvidenceRecordV1 {
        EvidenceRecordV1::try_new(EvidenceRecordInputV1 {
            record_id: EvidenceRecordIdV1::try_from_bytes([1; 16])
                .unwrap_or_else(|error| panic!("record id: {error}")),
            owner_ref: EvidenceOwnerRefV1::try_from_bytes([2; 16])
                .unwrap_or_else(|error| panic!("owner: {error}")),
            producer_sequence: 1,
            causality_ref: Some(
                EvidenceCausalityRefV1::try_from_bytes([3; 16])
                    .unwrap_or_else(|error| panic!("causality: {error}")),
            ),
            previous_evidence_ref: None,
            kind: EvidenceKindV1::OwnerReceipt,
            payload,
        })
        .unwrap_or_else(|error| panic!("record: {error}"))
    }

    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    #[test]
    fn canonical_record_matches_exact_pxev_v1_golden() {
        let record = record(
            EvidencePayloadV1::try_public_safe_inline(b"owner receipt: accepted")
                .unwrap_or_else(|error| panic!("payload: {error}")),
        );
        assert_eq!(
            lower_hex(record.canonical_wire()),
            "50584556000100a0000000b7010100000101010101010101010101010101010102020202020202020202020202020202030303030303030303030303030303030000000000000000000000000000000000000000000000010000001700000000c11eee0120cde020ae53f4955b552cd34278c4b429e8e6c17cbed9864c40f89da5cd84eeb8465cc78a108fc0f6c74e50d917b1ae512c466fcfb6622b4e341fb76f776e657220726563656970743a206163636570746564"
        );
    }

    #[test]
    fn public_safe_record_round_trips_strictly() {
        let record = record(
            EvidencePayloadV1::try_public_safe_inline(b"owner receipt: accepted")
                .unwrap_or_else(|error| panic!("payload: {error}")),
        );
        let decoded = EvidenceRecordV1::decode(record.canonical_wire())
            .unwrap_or_else(|error| panic!("decode: {error}"));
        assert_eq!(decoded, record);
        assert_eq!(
            decoded.payload().inline_bytes(),
            Some(b"owner receipt: accepted".as_slice())
        );
    }

    #[test]
    fn digest_only_record_retains_no_source_bytes() {
        let record = record(
            EvidencePayloadV1::try_digest_only(Digest32::from_bytes([9; 32]))
                .unwrap_or_else(|error| panic!("payload: {error}")),
        );
        assert_eq!(record.canonical_wire().len(), EVIDENCE_RECORD_HEADER_BYTES);
        assert_eq!(record.payload().inline_bytes(), None);
        assert_eq!(record.payload_digest(), Digest32::from_bytes([9; 32]));
        assert_eq!(
            EvidenceRecordV1::decode(record.canonical_wire()),
            Ok(record)
        );
    }

    #[test]
    fn tampering_and_noncanonical_redaction_fail_closed() {
        let record = record(
            EvidencePayloadV1::try_public_safe_inline(b"safe")
                .unwrap_or_else(|error| panic!("payload: {error}")),
        );
        let mut payload_tamper = record.canonical_wire().to_vec();
        *payload_tamper
            .last_mut()
            .unwrap_or_else(|| panic!("record has payload")) ^= 1;
        assert_eq!(
            EvidenceRecordV1::decode(&payload_tamper),
            Err(EvidenceContractError::PayloadDigestMismatch)
        );

        let mut false_digest_only = record.canonical_wire().to_vec();
        false_digest_only[13] = EvidenceRedactionV1::DigestOnly as u8;
        assert_eq!(
            EvidenceRecordV1::decode(&false_digest_only),
            Err(EvidenceContractError::NonCanonicalEncoding)
        );
    }
}
