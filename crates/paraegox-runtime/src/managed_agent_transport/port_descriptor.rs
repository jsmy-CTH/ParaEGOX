//! Canonical owner-to-owner bootstrap for one two-lane Agent port.
//!
//! The descriptor nests exactly two validated Fabric binding descriptors. A
//! future remote Runtime-owned Fabric session may consume it only through a
//! separately authenticated distribution channel; this module implements no
//! such channel. The descriptor never owns a session, discovery, retry,
//! authorization, or Agent lifecycle. Its digest is an integrity commitment,
//! not a signature or access grant.

use core::fmt;

use paraegox_fabric::{
    MAX_PORT_BINDING_DESCRIPTOR_BYTES, PortBindingDescriptorError, PortBindingDescriptorV1,
};
use paraegox_kernel::digest::{Digest32, Digest32Builder};

#[cfg(test)]
use super::AgentConversationClientPortV1;
use super::{
    AGENT_CONVERSATION_PORT_PHYSICAL_BINDINGS, AgentConversationPort, command_schema, result_schema,
};

/// Version of the canonical PXAP Agent conversation-port descriptor.
pub const AGENT_CONVERSATION_PORT_DESCRIPTOR_VERSION: u16 = 1;
/// Fixed PXAP header before the two nested PXBD frames.
pub const AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES: usize = 64;
/// Largest canonical PXAP descriptor.
pub const MAX_AGENT_CONVERSATION_PORT_DESCRIPTOR_BYTES: usize =
    AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES + 2 * MAX_PORT_BINDING_DESCRIPTOR_BYTES;

const DESCRIPTOR_MAGIC: &[u8; 4] = b"PXAP";
const DESCRIPTOR_FLAGS: u16 = 0;
const SUBMIT_LANE_ROLE: u16 = 1;
const CONTROL_LANE_ROLE: u16 = 2;
const DESCRIPTOR_DIGEST_OFFSET: usize = 32;
const DESCRIPTOR_DIGEST_DOMAIN: &[u8] = b"paraegox.agent.conversation.port-descriptor.sha256.v1";

/// Exact two-lane route facts for a remote typed Agent client.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentConversationPortDescriptorV1 {
    submit: PortBindingDescriptorV1,
    control: PortBindingDescriptorV1,
    descriptor_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl AgentConversationPortDescriptorV1 {
    /// Validates lane identity, schemas, bounds, and the unique lane order.
    pub fn try_new(
        submit: PortBindingDescriptorV1,
        control: PortBindingDescriptorV1,
    ) -> Result<Self, AgentConversationPortDescriptorError> {
        validate_lanes(&submit, &control)?;
        let canonical_wire = encode_descriptor(&submit, &control)?;
        let descriptor_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire
                [DESCRIPTOR_DIGEST_OFFSET..AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES],
        ));
        Ok(Self {
            submit,
            control,
            descriptor_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Exports one exact active port without exposing either lane to a UI.
    pub fn try_from_port(
        port: &AgentConversationPort,
    ) -> Result<Self, AgentConversationPortDescriptorError> {
        Self::try_new(
            port.submit_binding
                .export_descriptor_v1()
                .map_err(AgentConversationPortDescriptorError::FabricDescriptor)?,
            port.control_binding
                .export_descriptor_v1()
                .map_err(AgentConversationPortDescriptorError::FabricDescriptor)?,
        )
    }

    /// Strictly decodes one canonical PXAP frame and both nested PXBD frames.
    #[cfg(test)]
    pub fn decode(frame: &[u8]) -> Result<Self, AgentConversationPortDescriptorError> {
        if !(AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES
            ..=MAX_AGENT_CONVERSATION_PORT_DESCRIPTOR_BYTES)
            .contains(&frame.len())
        {
            return Err(AgentConversationPortDescriptorError::InvalidFrameLength);
        }
        if &frame[..4] != DESCRIPTOR_MAGIC
            || read_u16(&frame[4..6]) != AGENT_CONVERSATION_PORT_DESCRIPTOR_VERSION
            || usize::from(read_u16(&frame[6..8]))
                != AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES
        {
            return Err(AgentConversationPortDescriptorError::UnsupportedFrame);
        }
        let submit_length = usize::try_from(read_u32(&frame[12..16]))
            .map_err(|_| AgentConversationPortDescriptorError::InvalidFrameLength)?;
        let control_length = usize::try_from(read_u32(&frame[16..20]))
            .map_err(|_| AgentConversationPortDescriptorError::InvalidFrameLength)?;
        let expected_length = AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES
            .checked_add(submit_length)
            .and_then(|length| length.checked_add(control_length))
            .ok_or(AgentConversationPortDescriptorError::InvalidFrameLength)?;
        if usize::try_from(read_u32(&frame[8..12])).ok() != Some(frame.len())
            || expected_length != frame.len()
            || submit_length == 0
            || submit_length > MAX_PORT_BINDING_DESCRIPTOR_BYTES
            || control_length == 0
            || control_length > MAX_PORT_BINDING_DESCRIPTOR_BYTES
            || usize::from(read_u16(&frame[20..22])) != AGENT_CONVERSATION_PORT_PHYSICAL_BINDINGS
            || read_u16(&frame[22..24]) != DESCRIPTOR_FLAGS
            || read_u16(&frame[24..26]) != SUBMIT_LANE_ROLE
            || read_u16(&frame[26..28]) != CONTROL_LANE_ROLE
            || frame[28..32].iter().any(|byte| *byte != 0)
        {
            return Err(AgentConversationPortDescriptorError::NonCanonicalEncoding);
        }
        let payload = &frame[AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES..];
        let declared_digest = Digest32::from_bytes(read_array::<32>(
            &frame[DESCRIPTOR_DIGEST_OFFSET..AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES],
        ));
        let expected_digest = descriptor_digest(&frame[..DESCRIPTOR_DIGEST_OFFSET], payload)?;
        if declared_digest != expected_digest {
            return Err(AgentConversationPortDescriptorError::DigestMismatch);
        }
        let (submit_wire, control_wire) = payload.split_at(submit_length);
        let submit = PortBindingDescriptorV1::decode(submit_wire)
            .map_err(AgentConversationPortDescriptorError::FabricDescriptor)?;
        let control = PortBindingDescriptorV1::decode(control_wire)
            .map_err(AgentConversationPortDescriptorError::FabricDescriptor)?;
        let descriptor = Self::try_new(submit, control)?;
        if descriptor.canonical_wire() != frame {
            return Err(AgentConversationPortDescriptorError::NonCanonicalEncoding);
        }
        Ok(descriptor)
    }

    /// Returns the complete canonical owner-private bootstrap frame.
    #[must_use]
    #[cfg(test)]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the exact request/submit lane descriptor digest observed at
    /// installation, including its `BindingId` and binding epoch.
    #[must_use]
    pub const fn request_binding_descriptor_digest(&self) -> Digest32 {
        self.submit.descriptor_digest()
    }

    /// Returns the exact event/control lane descriptor digest observed at
    /// installation, including its `BindingId` and binding epoch.
    #[must_use]
    pub const fn event_binding_descriptor_digest(&self) -> Digest32 {
        self.control.descriptor_digest()
    }

    /// Consumes validated route facts into the opaque typed client port.
    /// No Fabric session or server entity is created by this operation.
    #[must_use]
    #[cfg(test)]
    pub fn into_client_port(self) -> AgentConversationClientPortV1 {
        AgentConversationClientPortV1 {
            submit_binding: self.submit.into_client_binding(),
            control_binding: self.control.into_client_binding(),
        }
    }
}

impl fmt::Debug for AgentConversationPortDescriptorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentConversationPortDescriptorV1")
            .field("submit", &self.submit)
            .field("control", &self.control)
            .field("descriptor_digest", &self.descriptor_digest)
            .finish()
    }
}

impl AgentConversationPort {
    /// Produces the canonical Runtime-to-Runtime bootstrap for this exact
    /// two-lane generation.
    pub fn export_descriptor_v1(
        &self,
    ) -> Result<AgentConversationPortDescriptorV1, AgentConversationPortDescriptorError> {
        AgentConversationPortDescriptorV1::try_from_port(self)
    }

    /// Copies the canonical owner-private PXAP bootstrap without exposing
    /// either Fabric lane or constructing a client/session.
    pub(crate) fn export_descriptor_wire_v1(
        &self,
    ) -> Result<Box<[u8]>, AgentConversationPortDescriptorError> {
        Ok(self.export_descriptor_v1()?.canonical_wire.clone())
    }
}

fn validate_lanes(
    submit: &PortBindingDescriptorV1,
    control: &PortBindingDescriptorV1,
) -> Result<(), AgentConversationPortDescriptorError> {
    if submit.binding_id() == control.binding_id() {
        return Err(AgentConversationPortDescriptorError::DuplicateBindingId);
    }
    if submit.key_expression() == control.key_expression() {
        return Err(AgentConversationPortDescriptorError::DuplicateKeyExpression);
    }
    if submit.request_schema() != command_schema()
        || control.request_schema() != command_schema()
        || submit.response_schema() != result_schema()
        || control.response_schema() != result_schema()
    {
        return Err(AgentConversationPortDescriptorError::SchemaMismatch);
    }
    if submit.ingress_limits() != control.ingress_limits() {
        return Err(AgentConversationPortDescriptorError::LaneLimitMismatch);
    }
    Ok(())
}

fn encode_descriptor(
    submit: &PortBindingDescriptorV1,
    control: &PortBindingDescriptorV1,
) -> Result<Vec<u8>, AgentConversationPortDescriptorError> {
    let total_length = AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES
        .checked_add(submit.canonical_wire().len())
        .and_then(|length| length.checked_add(control.canonical_wire().len()))
        .ok_or(AgentConversationPortDescriptorError::InvalidFrameLength)?;
    if total_length > MAX_AGENT_CONVERSATION_PORT_DESCRIPTOR_BYTES {
        return Err(AgentConversationPortDescriptorError::InvalidFrameLength);
    }
    let mut frame = vec![0_u8; total_length];
    frame[..4].copy_from_slice(DESCRIPTOR_MAGIC);
    frame[4..6].copy_from_slice(&AGENT_CONVERSATION_PORT_DESCRIPTOR_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(
        &u16::try_from(AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES)
            .expect("fixed PXAP header fits u16")
            .to_be_bytes(),
    );
    frame[8..12].copy_from_slice(
        &u32::try_from(total_length)
            .map_err(|_| AgentConversationPortDescriptorError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    frame[12..16].copy_from_slice(
        &u32::try_from(submit.canonical_wire().len())
            .map_err(|_| AgentConversationPortDescriptorError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    frame[16..20].copy_from_slice(
        &u32::try_from(control.canonical_wire().len())
            .map_err(|_| AgentConversationPortDescriptorError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    frame[20..22].copy_from_slice(
        &u16::try_from(AGENT_CONVERSATION_PORT_PHYSICAL_BINDINGS)
            .expect("fixed lane count fits u16")
            .to_be_bytes(),
    );
    frame[22..24].copy_from_slice(&DESCRIPTOR_FLAGS.to_be_bytes());
    frame[24..26].copy_from_slice(&SUBMIT_LANE_ROLE.to_be_bytes());
    frame[26..28].copy_from_slice(&CONTROL_LANE_ROLE.to_be_bytes());
    let submit_offset = AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES;
    let control_offset = submit_offset + submit.canonical_wire().len();
    frame[submit_offset..control_offset].copy_from_slice(submit.canonical_wire());
    frame[control_offset..].copy_from_slice(control.canonical_wire());
    let digest = descriptor_digest(
        &frame[..DESCRIPTOR_DIGEST_OFFSET],
        &frame[AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES..],
    )?;
    frame[DESCRIPTOR_DIGEST_OFFSET..AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES]
        .copy_from_slice(digest.as_bytes());
    Ok(frame)
}

fn descriptor_digest(
    header: &[u8],
    payload: &[u8],
) -> Result<Digest32, AgentConversationPortDescriptorError> {
    let mut builder = Digest32Builder::try_new(DESCRIPTOR_DIGEST_DOMAIN)
        .map_err(|_| AgentConversationPortDescriptorError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .and_then(|builder| builder.field_bytes(payload))
        .map_err(|_| AgentConversationPortDescriptorError::DigestEncodingFailed)?;
    Ok(builder.finish())
}

#[cfg(test)]
fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(read_array(bytes))
}

#[cfg(test)]
fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(read_array(bytes))
}

fn read_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut value = [0_u8; N];
    value.copy_from_slice(bytes);
    value
}

/// Strict PXAP construction and decoding failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentConversationPortDescriptorError {
    InvalidFrameLength,
    #[cfg(test)]
    UnsupportedFrame,
    #[cfg(test)]
    NonCanonicalEncoding,
    #[cfg(test)]
    DigestMismatch,
    DigestEncodingFailed,
    DuplicateBindingId,
    DuplicateKeyExpression,
    SchemaMismatch,
    LaneLimitMismatch,
    FabricDescriptor(PortBindingDescriptorError),
}

impl fmt::Display for AgentConversationPortDescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FabricDescriptor(error) => write!(formatter, "invalid Fabric lane: {error}"),
            other => formatter.write_str(match other {
                Self::InvalidFrameLength => "PXAP frame length is invalid",
                #[cfg(test)]
                Self::UnsupportedFrame => "PXAP frame version or header is unsupported",
                #[cfg(test)]
                Self::NonCanonicalEncoding => "PXAP frame is not canonical",
                #[cfg(test)]
                Self::DigestMismatch => "PXAP descriptor digest mismatched",
                Self::DigestEncodingFailed => "PXAP descriptor digest encoding failed",
                Self::DuplicateBindingId => "PXAP lane BindingIds must differ",
                Self::DuplicateKeyExpression => "PXAP lane key expressions must differ",
                Self::SchemaMismatch => "PXAP lane schemas do not match PXAC",
                Self::LaneLimitMismatch => "PXAP lane ingress limits must match",
                Self::FabricDescriptor(_) => unreachable!(),
            }),
        }
    }
}

impl std::error::Error for AgentConversationPortDescriptorError {}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use paraegox_fabric::{BindingEpoch, IngressLimits};
    use paraegox_runtime_contracts::assignment::BindingId;

    use super::*;

    const GOLDEN_HEX: &str =
        include_str!("../../tests/fixtures/agent_conversation_port_descriptor_v1.hex");

    fn descriptor() -> AgentConversationPortDescriptorV1 {
        let limits =
            IngressLimits::try_new(4, 16_384, 4_096, 4_096, Duration::from_secs(2)).unwrap();
        AgentConversationPortDescriptorV1::try_new(
            PortBindingDescriptorV1::try_new(
                BindingId::from_bytes([0x31; 16]),
                BindingEpoch::try_new(3).unwrap(),
                "paraegox/agent/node-a/submit",
                command_schema(),
                result_schema(),
                limits,
            )
            .unwrap(),
            PortBindingDescriptorV1::try_new(
                BindingId::from_bytes([0x32; 16]),
                BindingEpoch::try_new(4).unwrap(),
                "paraegox/agent/node-a/control",
                command_schema(),
                result_schema(),
                limits,
            )
            .unwrap(),
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

    fn resign_outer(frame: &mut [u8]) {
        let mut builder = Digest32Builder::try_new(DESCRIPTOR_DIGEST_DOMAIN).unwrap();
        builder
            .field_bytes(&frame[..DESCRIPTOR_DIGEST_OFFSET])
            .unwrap();
        builder
            .field_bytes(&frame[AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES..])
            .unwrap();
        frame[DESCRIPTOR_DIGEST_OFFSET..AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES]
            .copy_from_slice(builder.finish().as_bytes());
    }

    #[test]
    fn exact_golden_locks_header_roles_ordered_nested_frames_and_digest() {
        let wire = decode_hex_fixture(GOLDEN_HEX);
        assert_eq!(&wire[..4], b"PXAP");
        assert_eq!(
            read_u16(&wire[4..6]),
            AGENT_CONVERSATION_PORT_DESCRIPTOR_VERSION
        );
        assert_eq!(
            usize::from(read_u16(&wire[6..8])),
            AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES
        );
        assert_eq!(usize::try_from(read_u32(&wire[8..12])).unwrap(), wire.len());
        let submit_length = usize::try_from(read_u32(&wire[12..16])).unwrap();
        let control_length = usize::try_from(read_u32(&wire[16..20])).unwrap();
        assert_eq!(submit_length, 252);
        assert_eq!(control_length, 253);
        assert_eq!(read_u16(&wire[20..22]), 2);
        assert_eq!(read_u16(&wire[22..24]), 0);
        assert_eq!(read_u16(&wire[24..26]), SUBMIT_LANE_ROLE);
        assert_eq!(read_u16(&wire[26..28]), CONTROL_LANE_ROLE);
        assert_eq!(&wire[28..32], &[0; 4]);

        let submit_offset = AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES;
        let control_offset = submit_offset + submit_length;
        assert_eq!(wire.len(), control_offset + control_length);
        let submit = PortBindingDescriptorV1::decode(&wire[submit_offset..control_offset]).unwrap();
        let control = PortBindingDescriptorV1::decode(&wire[control_offset..]).unwrap();
        assert_eq!(submit.binding_id(), BindingId::from_bytes([0x31; 16]));
        assert_eq!(control.binding_id(), BindingId::from_bytes([0x32; 16]));
        assert_eq!(submit.key_expression(), "paraegox/agent/node-a/submit");
        assert_eq!(control.key_expression(), "paraegox/agent/node-a/control");

        let mut builder = Digest32Builder::try_new(DESCRIPTOR_DIGEST_DOMAIN).unwrap();
        builder
            .field_bytes(&wire[..DESCRIPTOR_DIGEST_OFFSET])
            .unwrap();
        builder
            .field_bytes(&wire[AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES..])
            .unwrap();
        assert_eq!(
            &wire[DESCRIPTOR_DIGEST_OFFSET..AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES],
            builder.finish().as_bytes()
        );
        assert_eq!(descriptor().canonical_wire(), wire);
        assert_eq!(
            AgentConversationPortDescriptorV1::decode(&wire).unwrap(),
            descriptor()
        );
    }

    #[test]
    fn two_lane_descriptor_round_trips_and_rebuilds_opaque_port() {
        let expected = descriptor();
        let decoded = AgentConversationPortDescriptorV1::decode(expected.canonical_wire()).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.canonical_wire(), expected.canonical_wire());
        assert_eq!(
            decoded.request_binding_descriptor_digest(),
            decoded.submit.descriptor_digest()
        );
        assert_eq!(
            decoded.event_binding_descriptor_digest(),
            decoded.control.descriptor_digest()
        );
        assert_ne!(
            decoded.request_binding_descriptor_digest(),
            decoded.event_binding_descriptor_digest()
        );
        let debug = format!("{decoded:?}");
        assert!(!debug.contains("node-a/submit"));
        assert!(!debug.contains("node-a/control"));
        let port = decoded.into_client_port();
        assert_eq!(port.submit_binding.binding_epoch().value(), 3);
        assert_eq!(port.control_binding.binding_epoch().value(), 4);
        assert_eq!(format!("{port:?}"), "AgentConversationClientPortV1 { .. }");
    }

    #[test]
    fn outer_descriptor_rejects_tampered_nested_payload() {
        let expected = descriptor();
        let mut wire = expected.canonical_wire().to_vec();
        *wire.last_mut().unwrap() ^= 1;
        assert_eq!(
            AgentConversationPortDescriptorV1::decode(&wire),
            Err(AgentConversationPortDescriptorError::DigestMismatch)
        );
    }

    #[test]
    fn lane_roles_cannot_alias() {
        let expected = descriptor();
        assert_eq!(
            AgentConversationPortDescriptorV1::try_new(
                expected.submit.clone(),
                expected.submit.clone(),
            ),
            Err(AgentConversationPortDescriptorError::DuplicateBindingId)
        );
    }

    #[test]
    fn resigned_unknown_roles_zero_lengths_and_reserved_bytes_fail_canonically() {
        let original = descriptor().canonical_wire().to_vec();

        let mut unknown_role = original.clone();
        unknown_role[24..26].copy_from_slice(&9_u16.to_be_bytes());
        resign_outer(&mut unknown_role);
        assert_eq!(
            AgentConversationPortDescriptorV1::decode(&unknown_role),
            Err(AgentConversationPortDescriptorError::NonCanonicalEncoding)
        );

        let mut zero_submit_length = original.clone();
        zero_submit_length[12..16].fill(0);
        resign_outer(&mut zero_submit_length);
        assert_eq!(
            AgentConversationPortDescriptorV1::decode(&zero_submit_length),
            Err(AgentConversationPortDescriptorError::NonCanonicalEncoding)
        );

        let mut oversized_submit = original.clone();
        oversized_submit[12..16].copy_from_slice(
            &u32::try_from(MAX_PORT_BINDING_DESCRIPTOR_BYTES + 1)
                .unwrap()
                .to_be_bytes(),
        );
        resign_outer(&mut oversized_submit);
        assert_eq!(
            AgentConversationPortDescriptorV1::decode(&oversized_submit),
            Err(AgentConversationPortDescriptorError::NonCanonicalEncoding)
        );

        let mut nonzero_reserved = original;
        nonzero_reserved[31] = 1;
        resign_outer(&mut nonzero_reserved);
        assert_eq!(
            AgentConversationPortDescriptorV1::decode(&nonzero_reserved),
            Err(AgentConversationPortDescriptorError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn whole_lane_swap_is_rejected_by_committed_role_discriminators() {
        let original = descriptor().canonical_wire().to_vec();
        let submit_length = usize::try_from(read_u32(&original[12..16])).unwrap();
        let control_length = usize::try_from(read_u32(&original[16..20])).unwrap();
        let submit_offset = AGENT_CONVERSATION_PORT_DESCRIPTOR_HEADER_BYTES;
        let control_offset = submit_offset + submit_length;
        let submit = original[submit_offset..control_offset].to_vec();
        let control = original[control_offset..].to_vec();

        let mut swapped = original;
        swapped[12..16].copy_from_slice(&u32::try_from(control_length).unwrap().to_be_bytes());
        swapped[16..20].copy_from_slice(&u32::try_from(submit_length).unwrap().to_be_bytes());
        swapped[24..26].copy_from_slice(&CONTROL_LANE_ROLE.to_be_bytes());
        swapped[26..28].copy_from_slice(&SUBMIT_LANE_ROLE.to_be_bytes());
        swapped[submit_offset..submit_offset + control_length].copy_from_slice(&control);
        swapped[submit_offset + control_length..].copy_from_slice(&submit);
        resign_outer(&mut swapped);

        assert_eq!(
            AgentConversationPortDescriptorV1::decode(&swapped),
            Err(AgentConversationPortDescriptorError::NonCanonicalEncoding)
        );
    }
}
