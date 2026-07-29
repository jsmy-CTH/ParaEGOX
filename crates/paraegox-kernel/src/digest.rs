//! Canonical, domain-separated SHA-256 digests.

use core::fmt;
use sha2::{Digest as _, Sha256};

const FORMAT_MAGIC: &[u8] = b"ParaEGOX\0canonical-digest";
const FORMAT_VERSION: u16 = 1;
const FIELD_MARKER: u8 = 1;
const END_MARKER: u8 = u8::MAX;

/// A SHA-256 digest whose semantic type is supplied by its owning contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// Creates a digest value from canonical bytes produced by a trusted source.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical 32-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the value and returns its canonical bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Errors raised before any digest bytes are accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestBuildError {
    /// A digest domain must distinguish the owning contract and version.
    EmptyDomain,
    /// The domain cannot be represented by the canonical v1 prefix.
    DomainTooLong,
    /// The number of fields cannot be represented by the canonical v1 format.
    TooManyFields,
    /// A field cannot be represented by the canonical v1 length prefix.
    FieldTooLong,
}

impl fmt::Display for DigestBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDomain => formatter.write_str("digest domain must not be empty"),
            Self::DomainTooLong => formatter.write_str("digest domain is too long"),
            Self::TooManyFields => formatter.write_str("canonical digest has too many fields"),
            Self::FieldTooLong => formatter.write_str("canonical digest field is too long"),
        }
    }
}

impl std::error::Error for DigestBuildError {}

/// Builds a SHA-256-v1 digest from an ordered sequence of length-prefixed fields.
///
/// The format hashes a fixed magic value, format version, length-prefixed domain,
/// and then every field with its ordinal and byte length. The terminator commits
/// the final field count. Callers must use a contract-specific, versioned domain
/// and append fields in their contract-defined order.
#[derive(Clone)]
pub struct Digest32Builder {
    hasher: Sha256,
    field_count: u32,
}

impl Digest32Builder {
    /// Starts a canonical SHA-256-v1 digest in `domain`.
    pub fn try_new(domain: &[u8]) -> Result<Self, DigestBuildError> {
        if domain.is_empty() {
            return Err(DigestBuildError::EmptyDomain);
        }

        let domain_length =
            u32::try_from(domain.len()).map_err(|_| DigestBuildError::DomainTooLong)?;
        let mut hasher = Sha256::new();
        hasher.update(FORMAT_MAGIC);
        hasher.update(FORMAT_VERSION.to_be_bytes());
        hasher.update(domain_length.to_be_bytes());
        hasher.update(domain);

        Ok(Self {
            hasher,
            field_count: 0,
        })
    }

    /// Appends one field in the owning contract's fixed field order.
    pub fn field_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self, DigestBuildError> {
        let ordinal = self
            .field_count
            .checked_add(1)
            .ok_or(DigestBuildError::TooManyFields)?;
        let length = u64::try_from(bytes.len()).map_err(|_| DigestBuildError::FieldTooLong)?;

        self.hasher.update([FIELD_MARKER]);
        self.hasher.update(ordinal.to_be_bytes());
        self.hasher.update(length.to_be_bytes());
        self.hasher.update(bytes);
        self.field_count = ordinal;
        Ok(self)
    }

    /// Appends a canonical unsigned 16-bit integer.
    pub fn field_u16(&mut self, value: u16) -> Result<&mut Self, DigestBuildError> {
        self.field_bytes(&value.to_be_bytes())
    }

    /// Appends a canonical unsigned 64-bit integer.
    pub fn field_u64(&mut self, value: u64) -> Result<&mut Self, DigestBuildError> {
        self.field_bytes(&value.to_be_bytes())
    }

    /// Appends another typed digest as a fixed-size field.
    pub fn field_digest(&mut self, value: &Digest32) -> Result<&mut Self, DigestBuildError> {
        self.field_bytes(value.as_bytes())
    }

    /// Finalizes the canonical field sequence.
    #[must_use]
    pub fn finish(mut self) -> Digest32 {
        self.hasher.update([END_MARKER]);
        self.hasher.update(self.field_count.to_be_bytes());
        Digest32::from_bytes(self.hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest32Builder, DigestBuildError};

    fn digest(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
        let Ok(mut builder) = Digest32Builder::try_new(domain) else {
            panic!("test domain must be valid");
        };
        for field in fields {
            assert!(builder.field_bytes(field).is_ok());
        }
        builder.finish().into_bytes()
    }

    #[test]
    fn domain_is_required() {
        assert_eq!(
            Digest32Builder::try_new(b"").err(),
            Some(DigestBuildError::EmptyDomain)
        );
    }

    #[test]
    fn domain_order_and_length_are_committed() {
        let left = digest(b"contract-a/v1", &[b"ab", b"c"]);
        let changed_domain = digest(b"contract-b/v1", &[b"ab", b"c"]);
        let changed_order = digest(b"contract-a/v1", &[b"c", b"ab"]);
        let changed_boundaries = digest(b"contract-a/v1", &[b"a", b"bc"]);

        assert_ne!(left, changed_domain);
        assert_ne!(left, changed_order);
        assert_ne!(left, changed_boundaries);
    }

    #[test]
    fn identical_inputs_are_byte_stable() {
        let first = digest(b"paraegox.test/v1", &[b"alpha", b"beta"]);
        let second = digest(b"paraegox.test/v1", &[b"alpha", b"beta"]);
        let expected = [
            0x96, 0xf0, 0x17, 0xd3, 0x31, 0x73, 0x04, 0x8e, 0x8f, 0x4a, 0x01, 0xc9, 0xbf, 0x57,
            0x90, 0x78, 0x6e, 0xa3, 0x3c, 0xb6, 0xfc, 0xd8, 0xec, 0xa1, 0xe8, 0xbc, 0x59, 0xd2,
            0x55, 0x8d, 0x76, 0x96,
        ];

        assert_eq!(first, second);
        assert_eq!(first, expected);
    }
}
