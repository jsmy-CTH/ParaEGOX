//! Canonical bootstrap descriptor for one already-installed Fabric binding.
//!
//! A descriptor carries only immutable route facts required by another
//! Runtime-owned [`crate::FabricService`] session to issue typed requests. It
//! owns no Zenoh entity, discovery, retry, authorization, or lifecycle right.
//! Any future distribution must place it inside a separately authenticated
//! owner-to-owner bootstrap channel. This crate implements no such channel;
//! the descriptor digest detects corruption but is not an authorization
//! signature.

use core::{fmt, time::Duration};

use paraegox_kernel::digest::{Digest32, Digest32Builder};
use paraegox_runtime_contracts::assignment::{BindingId, SchemaRef};

use crate::ingress::{
    MAX_INGRESS_BYTES, MAX_INGRESS_FRAME_BYTES, MAX_INGRESS_ITEMS, MAX_INGRESS_RESPONSE_BODY_BYTES,
};
use crate::{
    BindingEpoch, ClientPortBindingV1, FabricConfigError, IngressLimitError, IngressLimits,
    PortBinding, RequestResponseBindingSpec,
};

/// Version of the canonical PXBD bootstrap descriptor.
pub const PORT_BINDING_DESCRIPTOR_VERSION: u16 = 1;
/// Fixed PXBD header length before the bounded key expression.
pub const PORT_BINDING_DESCRIPTOR_HEADER_BYTES: usize = 224;
/// Largest canonical PXBD frame.
pub const MAX_PORT_BINDING_DESCRIPTOR_BYTES: usize =
    PORT_BINDING_DESCRIPTOR_HEADER_BYTES + MAX_DESCRIPTOR_KEY_EXPRESSION_BYTES;

const DESCRIPTOR_MAGIC: &[u8; 4] = b"PXBD";
const DESCRIPTOR_FLAGS: u16 = 0;
const DESCRIPTOR_DIGEST_OFFSET: usize = 192;
const MAX_DESCRIPTOR_KEY_EXPRESSION_BYTES: usize = 256;
const DESCRIPTOR_DIGEST_DOMAIN: &[u8] = b"paraegox.fabric.port-binding-descriptor.sha256.v1";

/// Immutable, transport-neutral bootstrap facts for one binding generation.
///
/// This value is intentionally distinct from a live binding owner. Calling
/// [`Self::into_client_binding`] only constructs a request-side route value;
/// it does not declare a queryable, open a session, or prove the descriptor's
/// sender was authorized.
#[derive(Clone, Eq, PartialEq)]
pub struct PortBindingDescriptorV1 {
    binding_id: BindingId,
    binding_epoch: BindingEpoch,
    key_expression: Box<str>,
    request_schema: SchemaRef,
    response_schema: SchemaRef,
    ingress_limits: IngressLimits,
    descriptor_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl PortBindingDescriptorV1 {
    /// Validates exact route facts and creates their unique canonical frame.
    pub fn try_new(
        binding_id: BindingId,
        binding_epoch: BindingEpoch,
        key_expression: impl Into<String>,
        request_schema: SchemaRef,
        response_schema: SchemaRef,
        ingress_limits: IngressLimits,
    ) -> Result<Self, PortBindingDescriptorError> {
        let key_expression = key_expression.into();
        RequestResponseBindingSpec::try_new(
            binding_id,
            Some(binding_epoch),
            key_expression.clone(),
            request_schema,
            response_schema,
            ingress_limits,
        )
        .map_err(PortBindingDescriptorError::InvalidBinding)?;
        if key_expression.len() > MAX_DESCRIPTOR_KEY_EXPRESSION_BYTES {
            return Err(PortBindingDescriptorError::InvalidBinding(
                FabricConfigError::KeyExpressionTooLong,
            ));
        }
        let handler_timeout_nanos = u64::try_from(ingress_limits.handler_timeout().as_nanos())
            .map_err(|_| PortBindingDescriptorError::IntegerOutOfRange)?;
        let canonical_wire = encode_descriptor(
            binding_id,
            binding_epoch,
            &key_expression,
            request_schema,
            response_schema,
            ingress_limits,
            handler_timeout_nanos,
        )?;
        let descriptor_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire[DESCRIPTOR_DIGEST_OFFSET..PORT_BINDING_DESCRIPTOR_HEADER_BYTES],
        ));
        Ok(Self {
            binding_id,
            binding_epoch,
            key_expression: key_expression.into_boxed_str(),
            request_schema,
            response_schema,
            ingress_limits,
            descriptor_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Exports immutable facts from one installed or already-validated route.
    pub fn try_from_binding(binding: &PortBinding) -> Result<Self, PortBindingDescriptorError> {
        Self::try_new(
            binding.binding_id(),
            binding.binding_epoch(),
            binding.key_expression(),
            binding.request_schema(),
            binding.response_schema(),
            binding.ingress_limits(),
        )
    }

    /// Strictly decodes one canonical PXBD frame.
    pub fn decode(frame: &[u8]) -> Result<Self, PortBindingDescriptorError> {
        if !(PORT_BINDING_DESCRIPTOR_HEADER_BYTES..=MAX_PORT_BINDING_DESCRIPTOR_BYTES)
            .contains(&frame.len())
        {
            return Err(PortBindingDescriptorError::InvalidFrameLength);
        }
        if &frame[..4] != DESCRIPTOR_MAGIC
            || read_u16(&frame[4..6]) != PORT_BINDING_DESCRIPTOR_VERSION
            || usize::from(read_u16(&frame[6..8])) != PORT_BINDING_DESCRIPTOR_HEADER_BYTES
        {
            return Err(PortBindingDescriptorError::UnsupportedFrame);
        }
        let key_length = usize::from(read_u16(&frame[12..14]));
        if usize::try_from(read_u32(&frame[8..12])).ok() != Some(frame.len())
            || read_u16(&frame[14..16]) != DESCRIPTOR_FLAGS
            || key_length == 0
            || key_length > MAX_DESCRIPTOR_KEY_EXPRESSION_BYTES
            || PORT_BINDING_DESCRIPTOR_HEADER_BYTES.checked_add(key_length) != Some(frame.len())
            || frame[184..192].iter().any(|byte| *byte != 0)
        {
            return Err(PortBindingDescriptorError::NonCanonicalEncoding);
        }
        let key_bytes = &frame[PORT_BINDING_DESCRIPTOR_HEADER_BYTES..];
        let declared_digest = Digest32::from_bytes(read_array::<32>(
            &frame[DESCRIPTOR_DIGEST_OFFSET..PORT_BINDING_DESCRIPTOR_HEADER_BYTES],
        ));
        let expected_digest = descriptor_digest(&frame[..DESCRIPTOR_DIGEST_OFFSET], key_bytes)?;
        if declared_digest != expected_digest {
            return Err(PortBindingDescriptorError::DigestMismatch);
        }
        let key_expression = core::str::from_utf8(key_bytes)
            .map_err(|_| PortBindingDescriptorError::NonCanonicalEncoding)?;
        let binding_id = BindingId::from_bytes(read_array(&frame[16..32]));
        let binding_epoch = BindingEpoch::try_new(read_u64(&frame[32..40]))
            .map_err(|_| PortBindingDescriptorError::NonCanonicalEncoding)?;
        let request_schema = decode_schema(&frame[40..92])?;
        let response_schema = decode_schema(&frame[92..144])?;
        let max_items = decode_bounded_usize(read_u64(&frame[144..152]), MAX_INGRESS_ITEMS)?;
        let max_bytes = decode_bounded_usize(read_u64(&frame[152..160]), MAX_INGRESS_BYTES)?;
        let max_frame_bytes =
            decode_bounded_usize(read_u64(&frame[160..168]), MAX_INGRESS_FRAME_BYTES)?;
        let max_response_body_bytes =
            decode_bounded_usize(read_u64(&frame[168..176]), MAX_INGRESS_RESPONSE_BODY_BYTES)?;
        let handler_timeout_nanos = read_u64(&frame[176..184]);
        let ingress_limits = IngressLimits::try_new(
            max_items,
            max_bytes,
            max_frame_bytes,
            max_response_body_bytes,
            Duration::from_nanos(handler_timeout_nanos),
        )
        .map_err(PortBindingDescriptorError::InvalidIngress)?;
        let descriptor = Self::try_new(
            binding_id,
            binding_epoch,
            key_expression,
            request_schema,
            response_schema,
            ingress_limits,
        )?;
        if descriptor.canonical_wire() != frame {
            return Err(PortBindingDescriptorError::NonCanonicalEncoding);
        }
        Ok(descriptor)
    }

    #[must_use]
    pub const fn binding_id(&self) -> BindingId {
        self.binding_id
    }

    #[must_use]
    pub const fn binding_epoch(&self) -> BindingEpoch {
        self.binding_epoch
    }

    #[must_use]
    pub fn key_expression(&self) -> &str {
        &self.key_expression
    }

    #[must_use]
    pub const fn request_schema(&self) -> SchemaRef {
        self.request_schema
    }

    #[must_use]
    pub const fn response_schema(&self) -> SchemaRef {
        self.response_schema
    }

    #[must_use]
    pub const fn ingress_limits(&self) -> IngressLimits {
        self.ingress_limits
    }

    #[must_use]
    pub const fn descriptor_digest(&self) -> Digest32 {
        self.descriptor_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Converts validated immutable facts into a request-side binding value.
    /// This performs no I/O and acquires no server-side lifecycle authority.
    #[must_use]
    pub fn into_client_binding(self) -> ClientPortBindingV1 {
        ClientPortBindingV1::from_descriptor_parts(
            self.binding_id,
            self.binding_epoch,
            self.key_expression.into_string(),
            self.request_schema,
            self.response_schema,
            self.ingress_limits,
        )
    }
}

impl fmt::Debug for PortBindingDescriptorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortBindingDescriptorV1")
            .field("binding_id", &self.binding_id)
            .field("binding_epoch", &self.binding_epoch)
            .field("key_expression", &"<owner-private-route>")
            .field("request_schema", &self.request_schema)
            .field("response_schema", &self.response_schema)
            .field("ingress_limits", &self.ingress_limits)
            .field("descriptor_digest", &self.descriptor_digest)
            .finish()
    }
}

impl PortBinding {
    /// Produces the canonical owner-to-owner bootstrap descriptor for this
    /// exact binding generation.
    pub fn export_descriptor_v1(
        &self,
    ) -> Result<PortBindingDescriptorV1, PortBindingDescriptorError> {
        PortBindingDescriptorV1::try_from_binding(self)
    }
}

fn encode_descriptor(
    binding_id: BindingId,
    binding_epoch: BindingEpoch,
    key_expression: &str,
    request_schema: SchemaRef,
    response_schema: SchemaRef,
    ingress_limits: IngressLimits,
    handler_timeout_nanos: u64,
) -> Result<Vec<u8>, PortBindingDescriptorError> {
    let total_length = PORT_BINDING_DESCRIPTOR_HEADER_BYTES
        .checked_add(key_expression.len())
        .ok_or(PortBindingDescriptorError::IntegerOutOfRange)?;
    let mut frame = vec![0_u8; total_length];
    frame[..4].copy_from_slice(DESCRIPTOR_MAGIC);
    frame[4..6].copy_from_slice(&PORT_BINDING_DESCRIPTOR_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(
        &u16::try_from(PORT_BINDING_DESCRIPTOR_HEADER_BYTES)
            .expect("fixed PXBD header fits u16")
            .to_be_bytes(),
    );
    frame[8..12].copy_from_slice(
        &u32::try_from(total_length)
            .map_err(|_| PortBindingDescriptorError::IntegerOutOfRange)?
            .to_be_bytes(),
    );
    frame[12..14].copy_from_slice(
        &u16::try_from(key_expression.len())
            .map_err(|_| PortBindingDescriptorError::IntegerOutOfRange)?
            .to_be_bytes(),
    );
    frame[14..16].copy_from_slice(&DESCRIPTOR_FLAGS.to_be_bytes());
    frame[16..32].copy_from_slice(binding_id.as_bytes());
    frame[32..40].copy_from_slice(&binding_epoch.value().to_be_bytes());
    encode_schema(request_schema, &mut frame[40..92]);
    encode_schema(response_schema, &mut frame[92..144]);
    encode_usize(ingress_limits.max_items(), &mut frame[144..152])?;
    encode_usize(ingress_limits.max_bytes(), &mut frame[152..160])?;
    encode_usize(ingress_limits.max_frame_bytes(), &mut frame[160..168])?;
    encode_usize(
        ingress_limits.max_response_body_bytes(),
        &mut frame[168..176],
    )?;
    frame[176..184].copy_from_slice(&handler_timeout_nanos.to_be_bytes());
    frame[PORT_BINDING_DESCRIPTOR_HEADER_BYTES..].copy_from_slice(key_expression.as_bytes());
    let digest = descriptor_digest(
        &frame[..DESCRIPTOR_DIGEST_OFFSET],
        key_expression.as_bytes(),
    )?;
    frame[DESCRIPTOR_DIGEST_OFFSET..PORT_BINDING_DESCRIPTOR_HEADER_BYTES]
        .copy_from_slice(digest.as_bytes());
    Ok(frame)
}

fn descriptor_digest(
    header: &[u8],
    key_expression: &[u8],
) -> Result<Digest32, PortBindingDescriptorError> {
    let mut builder = Digest32Builder::try_new(DESCRIPTOR_DIGEST_DOMAIN)
        .map_err(|_| PortBindingDescriptorError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .and_then(|builder| builder.field_bytes(key_expression))
        .map_err(|_| PortBindingDescriptorError::DigestEncodingFailed)?;
    Ok(builder.finish())
}

fn encode_schema(schema: SchemaRef, destination: &mut [u8]) {
    destination[..16].copy_from_slice(schema.id_bytes());
    destination[16..20].copy_from_slice(&schema.version().to_be_bytes());
    destination[20..52].copy_from_slice(schema.content_digest().as_bytes());
}

fn decode_schema(frame: &[u8]) -> Result<SchemaRef, PortBindingDescriptorError> {
    SchemaRef::try_new(
        read_array(&frame[..16]),
        read_u32(&frame[16..20]),
        Digest32::from_bytes(read_array(&frame[20..52])),
    )
    .map_err(|_| PortBindingDescriptorError::InvalidSchema)
}

fn encode_usize(value: usize, destination: &mut [u8]) -> Result<(), PortBindingDescriptorError> {
    destination.copy_from_slice(
        &u64::try_from(value)
            .map_err(|_| PortBindingDescriptorError::IntegerOutOfRange)?
            .to_be_bytes(),
    );
    Ok(())
}

fn decode_bounded_usize(
    value: u64,
    protocol_maximum: usize,
) -> Result<usize, PortBindingDescriptorError> {
    if value > protocol_maximum as u64 {
        return Err(PortBindingDescriptorError::IntegerOutOfRange);
    }
    Ok(value as usize)
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
    let mut value = [0_u8; N];
    value.copy_from_slice(bytes);
    value
}

/// Strict PXBD construction and decoding failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortBindingDescriptorError {
    InvalidFrameLength,
    UnsupportedFrame,
    NonCanonicalEncoding,
    DigestMismatch,
    IntegerOutOfRange,
    InvalidSchema,
    DigestEncodingFailed,
    InvalidIngress(IngressLimitError),
    InvalidBinding(FabricConfigError),
}

impl fmt::Display for PortBindingDescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIngress(error) => write!(formatter, "invalid ingress limits: {error}"),
            Self::InvalidBinding(error) => write!(formatter, "invalid binding facts: {error}"),
            other => formatter.write_str(match other {
                Self::InvalidFrameLength => "PXBD frame length is invalid",
                Self::UnsupportedFrame => "PXBD frame version or header is unsupported",
                Self::NonCanonicalEncoding => "PXBD frame is not canonical",
                Self::DigestMismatch => "PXBD descriptor digest mismatched",
                Self::IntegerOutOfRange => {
                    "PXBD integer is outside the platform-independent protocol representation"
                }
                Self::InvalidSchema => "PXBD schema is invalid",
                Self::DigestEncodingFailed => "PXBD descriptor digest encoding failed",
                Self::InvalidIngress(_) | Self::InvalidBinding(_) => unreachable!(),
            }),
        }
    }
}

impl std::error::Error for PortBindingDescriptorError {}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_HEX: &str = include_str!("../tests/fixtures/port_binding_descriptor_v1.hex");

    fn schema(marker: u8) -> SchemaRef {
        SchemaRef::try_new([marker; 16], 1, Digest32::from_bytes([marker; 32])).unwrap()
    }

    fn descriptor() -> PortBindingDescriptorV1 {
        PortBindingDescriptorV1::try_new(
            BindingId::from_bytes([0x31; 16]),
            BindingEpoch::try_new(7).unwrap(),
            "paraegox/agent/node-a/submit",
            schema(0x41),
            schema(0x42),
            IngressLimits::try_new(8, 32_768, 8_192, 16_384, Duration::from_secs(3)).unwrap(),
        )
        .unwrap()
    }

    fn decode_hex_fixture(value: &str) -> Vec<u8> {
        let value = value.trim();
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }

    fn resign(frame: &mut [u8]) {
        let mut builder = Digest32Builder::try_new(DESCRIPTOR_DIGEST_DOMAIN).unwrap();
        builder
            .field_bytes(&frame[..DESCRIPTOR_DIGEST_OFFSET])
            .unwrap();
        builder
            .field_bytes(&frame[PORT_BINDING_DESCRIPTOR_HEADER_BYTES..])
            .unwrap();
        frame[DESCRIPTOR_DIGEST_OFFSET..PORT_BINDING_DESCRIPTOR_HEADER_BYTES]
            .copy_from_slice(builder.finish().as_bytes());
    }

    #[test]
    fn exact_golden_locks_every_header_field_route_field_and_digest() {
        let wire = decode_hex_fixture(GOLDEN_HEX);
        assert_eq!(&wire[..4], b"PXBD");
        assert_eq!(read_u16(&wire[4..6]), PORT_BINDING_DESCRIPTOR_VERSION);
        assert_eq!(
            usize::from(read_u16(&wire[6..8])),
            PORT_BINDING_DESCRIPTOR_HEADER_BYTES
        );
        assert_eq!(usize::try_from(read_u32(&wire[8..12])).unwrap(), wire.len());
        assert_eq!(read_u16(&wire[12..14]), 28);
        assert_eq!(read_u16(&wire[14..16]), 0);
        assert_eq!(&wire[16..32], &[0x31; 16]);
        assert_eq!(read_u64(&wire[32..40]), 7);
        assert_eq!(&wire[40..56], &[0x41; 16]);
        assert_eq!(read_u32(&wire[56..60]), 1);
        assert_eq!(&wire[60..92], &[0x41; 32]);
        assert_eq!(&wire[92..108], &[0x42; 16]);
        assert_eq!(read_u32(&wire[108..112]), 1);
        assert_eq!(&wire[112..144], &[0x42; 32]);
        assert_eq!(read_u64(&wire[144..152]), 8);
        assert_eq!(read_u64(&wire[152..160]), 32_768);
        assert_eq!(read_u64(&wire[160..168]), 8_192);
        assert_eq!(read_u64(&wire[168..176]), 16_384);
        assert_eq!(read_u64(&wire[176..184]), 3_000_000_000);
        assert_eq!(&wire[184..192], &[0; 8]);
        assert_eq!(
            &wire[PORT_BINDING_DESCRIPTOR_HEADER_BYTES..],
            b"paraegox/agent/node-a/submit"
        );

        let mut builder = Digest32Builder::try_new(DESCRIPTOR_DIGEST_DOMAIN).unwrap();
        builder
            .field_bytes(&wire[..DESCRIPTOR_DIGEST_OFFSET])
            .unwrap();
        builder
            .field_bytes(&wire[PORT_BINDING_DESCRIPTOR_HEADER_BYTES..])
            .unwrap();
        assert_eq!(
            &wire[DESCRIPTOR_DIGEST_OFFSET..PORT_BINDING_DESCRIPTOR_HEADER_BYTES],
            builder.finish().as_bytes()
        );
        assert_eq!(descriptor().canonical_wire(), wire);
        assert_eq!(
            PortBindingDescriptorV1::decode(&wire).unwrap(),
            descriptor()
        );
    }

    #[test]
    fn descriptor_round_trips_bit_exactly_and_rebuilds_client_route() {
        let expected = descriptor();
        let decoded = PortBindingDescriptorV1::decode(expected.canonical_wire()).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.canonical_wire(), expected.canonical_wire());
        let binding = decoded.into_client_binding();
        assert_eq!(binding.binding_id(), expected.binding_id());
        assert_eq!(binding.binding_epoch(), expected.binding_epoch());
        assert_eq!(binding.key_expression(), expected.key_expression());
        assert_eq!(binding.request_schema(), expected.request_schema());
        assert_eq!(binding.response_schema(), expected.response_schema());
        assert_eq!(binding.ingress_limits(), expected.ingress_limits());
        let debug = format!("{binding:?}");
        assert!(!debug.contains(expected.key_expression()));
        assert!(debug.contains("ClientPortBindingV1"));
    }

    #[test]
    fn descriptor_rejects_header_and_route_tampering() {
        let descriptor = descriptor();
        let mut header = descriptor.canonical_wire().to_vec();
        header[144] ^= 1;
        assert_eq!(
            PortBindingDescriptorV1::decode(&header),
            Err(PortBindingDescriptorError::DigestMismatch)
        );

        let mut route = descriptor.canonical_wire().to_vec();
        *route.last_mut().unwrap() ^= 1;
        assert_eq!(
            PortBindingDescriptorV1::decode(&route),
            Err(PortBindingDescriptorError::DigestMismatch)
        );
    }

    #[test]
    fn descriptor_rejects_zero_binding_before_producing_wire() {
        assert!(matches!(
            PortBindingDescriptorV1::try_new(
                BindingId::from_bytes([0; 16]),
                BindingEpoch::try_new(1).unwrap(),
                "paraegox/agent/invalid",
                schema(0x41),
                schema(0x42),
                IngressLimits::try_new(1, 512, 256, 256, Duration::from_secs(1)).unwrap(),
            ),
            Err(PortBindingDescriptorError::InvalidBinding(
                FabricConfigError::Contract(_)
            ))
        ));
    }

    #[test]
    fn strict_precedence_rejects_resigned_noncanonical_zero_unknown_and_bounds() {
        let original = descriptor().canonical_wire().to_vec();

        let mut unknown_version = original.clone();
        unknown_version[5] = 2;
        assert_eq!(
            PortBindingDescriptorV1::decode(&unknown_version),
            Err(PortBindingDescriptorError::UnsupportedFrame)
        );

        let mut unknown_flags = original.clone();
        unknown_flags[15] = 1;
        resign(&mut unknown_flags);
        assert_eq!(
            PortBindingDescriptorV1::decode(&unknown_flags),
            Err(PortBindingDescriptorError::NonCanonicalEncoding)
        );

        let mut nonzero_reserved = original.clone();
        nonzero_reserved[191] = 1;
        resign(&mut nonzero_reserved);
        assert_eq!(
            PortBindingDescriptorV1::decode(&nonzero_reserved),
            Err(PortBindingDescriptorError::NonCanonicalEncoding)
        );

        let mut zero_epoch = original.clone();
        zero_epoch[32..40].fill(0);
        resign(&mut zero_epoch);
        assert_eq!(
            PortBindingDescriptorV1::decode(&zero_epoch),
            Err(PortBindingDescriptorError::NonCanonicalEncoding)
        );

        let mut zero_binding = original.clone();
        zero_binding[16..32].fill(0);
        resign(&mut zero_binding);
        assert!(matches!(
            PortBindingDescriptorV1::decode(&zero_binding),
            Err(PortBindingDescriptorError::InvalidBinding(
                FabricConfigError::Contract(_)
            ))
        ));

        let mut unknown_schema = original.clone();
        unknown_schema[56..60].fill(0);
        resign(&mut unknown_schema);
        assert_eq!(
            PortBindingDescriptorV1::decode(&unknown_schema),
            Err(PortBindingDescriptorError::InvalidSchema)
        );

        let mut out_of_bounds = original;
        out_of_bounds[144..152].copy_from_slice(&4_097_u64.to_be_bytes());
        resign(&mut out_of_bounds);
        assert_eq!(
            PortBindingDescriptorV1::decode(&out_of_bounds),
            Err(PortBindingDescriptorError::IntegerOutOfRange)
        );
    }

    #[test]
    fn debug_does_not_disclose_route_expression() {
        let descriptor = descriptor();
        let debug = format!("{descriptor:?}");
        assert!(!debug.contains(descriptor.key_expression()));
        assert!(debug.contains("owner-private-route"));
    }
}
