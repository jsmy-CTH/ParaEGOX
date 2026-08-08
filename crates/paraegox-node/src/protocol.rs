//! Strict transport-neutral read-only NodeManagement protocol v1.
//!
//! PXNQ/PXNS is one bounded request/response exchange. `Watch` is a
//! conditional read of the last immutable [`NodeStatusV1`] publication; it is
//! not a stream, heartbeat, discovery loop, retry policy, partition detector,
//! Runtime apply proxy, or Deployment desired-state mutation path.
//! Observation-backed status payloads use the v1 reserved extension to carry
//! a digest-bound absolute Unix-nanosecond validity fence. Consumers must
//! enforce it in addition to the legacy relative freshness budget.

use core::{fmt, num::NonZeroU64};

use paraegox_kernel::{
    digest::{Digest32, Digest32Builder},
    identity::{PrincipalRef, RuntimeHostId},
};
use paraegox_runtime_contracts::wire::{
    ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim, ApplyRequestAuthentication,
    MAX_APPLY_AUTH_NONCE_BYTES, MAX_APPLY_AUTH_SIGNATURE_BYTES,
};

#[cfg(unix)]
use crate::observation::{
    MAX_RUNTIME_OBSERVATION_REQUEST_BYTES, RuntimeObservationEndpointRefV1,
    RuntimeObservationError, RuntimeObservationRequestV1,
};

use crate::{
    MAX_RUNTIME_HOSTS_PER_NODE, NodeArchitectureV1, NodeContractError, NodeDaemonV1,
    NodeFeatureReportInputV1, NodeFeatureReportV1, NodeId, NodeIncarnation,
    NodeManagementEndpointRefV1, NodeOperatingSystemV1, NodeRegistrationTenureV1,
    NodeStatusInputV1, NodeStatusTrackerV1, NodeStatusV1, RuntimeApplyEndpointDescriptorV1,
    RuntimeApplyEndpointRefV1, RuntimeApplyTransportV1, RuntimeHostLivenessV1, RuntimeHostStatusV1,
};

/// Fixed byte length of one PXNQ-v1 request.
pub const NODE_MANAGEMENT_REQUEST_BYTES: usize = REQUEST_HEADER_BYTES;
/// Largest accepted PXNS-v1 response including eight maximum-length routes.
pub const MAX_NODE_MANAGEMENT_RESPONSE_BYTES: usize =
    RESPONSE_HEADER_BYTES + MAX_NODE_STATUS_PAYLOAD_BYTES;

const REQUEST_MAGIC: &[u8; 4] = b"PXNQ";
const RESPONSE_MAGIC: &[u8; 4] = b"PXNS";
const CONTROL_CARRIER_REQUEST_MAGIC: &[u8; 4] = b"PXNR";
const CONTROL_DESCRIBE_RESPONSE_MAGIC: &[u8; 4] = b"PXNE";
const CONTROL_CARRIER_SIGNING_MAGIC: &[u8] = b"ParaEGOX\0node-control-carrier-signing";
const CONTROL_CARRIER_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"paraegox.node.control-carrier.request.sha256.v1";
const CONTROL_CARRIER_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"paraegox.node.control-carrier.payload.sha256.v1";
const CONTROL_DESCRIBE_RESPONSE_DIGEST_DOMAIN: &[u8] =
    b"paraegox.node.control-describe-response.sha256.v1";
const REQUEST_HEADER_BYTES: usize = 160;
const REQUEST_DIGEST_OFFSET: usize = 128;
const RESPONSE_HEADER_BYTES: usize = 264;
const RESPONSE_DIGEST_OFFSET: usize = 232;
const STATUS_FIXED_BYTES: usize = 128;
const RUNTIME_STATUS_FIXED_BYTES: usize = 108;
const MAX_RUNTIME_ROUTE_BYTES: usize = 255;
const MAX_NODE_STATUS_PAYLOAD_BYTES: usize = STATUS_FIXED_BYTES
    + MAX_RUNTIME_HOSTS_PER_NODE * (RUNTIME_STATUS_FIXED_BYTES + MAX_RUNTIME_ROUTE_BYTES);
const REQUEST_DIGEST_DOMAIN: &[u8] = b"paraegox.node.management-request.v1";
const RESPONSE_DIGEST_DOMAIN: &[u8] = b"paraegox.node.management-response.v1";
const CONTROL_CARRIER_REQUEST_FIXED_BYTES: usize = 184;
const CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES: usize = 288;

#[cfg(unix)]
const MAX_NODE_CONTROL_CARRIER_PAYLOAD_BYTES: usize =
    if MAX_RUNTIME_OBSERVATION_REQUEST_BYTES > NODE_MANAGEMENT_REQUEST_BYTES {
        MAX_RUNTIME_OBSERVATION_REQUEST_BYTES
    } else {
        NODE_MANAGEMENT_REQUEST_BYTES
    };
#[cfg(not(unix))]
const MAX_NODE_CONTROL_CARRIER_PAYLOAD_BYTES: usize = NODE_MANAGEMENT_REQUEST_BYTES;

/// Additive PXNR/PXNE control-carrier protocol version.
pub const NODE_CONTROL_CARRIER_VERSION: u16 = 1;
/// Exact PXNR Controller signing-transcript version.
pub const NODE_CONTROL_CARRIER_SIGNING_VERSION: u16 = 1;
/// Maximum canonical PXNR request size on this admitted platform.
pub const MAX_NODE_CONTROL_CARRIER_REQUEST_BYTES: usize = CONTROL_CARRIER_REQUEST_FIXED_BYTES
    + MAX_APPLY_AUTH_NONCE_BYTES
    + MAX_NODE_CONTROL_CARRIER_PAYLOAD_BYTES
    + MAX_APPLY_AUTH_SIGNATURE_BYTES;
/// Maximum canonical PXNE Describe/challenge response size.
pub const MAX_NODE_CONTROL_DESCRIBE_RESPONSE_BYTES: usize =
    CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES + MAX_APPLY_AUTH_NONCE_BYTES;

/// Exact Node publication coordinate and management endpoint selected by a
/// caller from authenticated discovery facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeManagementTargetV1 {
    node_id: NodeId,
    management_endpoint_ref: NodeManagementEndpointRefV1,
    node_incarnation: NodeIncarnation,
    registration_epoch: NonZeroU64,
}

impl NodeManagementTargetV1 {
    pub fn try_new(
        node_id: NodeId,
        management_endpoint_ref: NodeManagementEndpointRefV1,
        node_incarnation: NodeIncarnation,
        registration_epoch: u64,
    ) -> Result<Self, NodeManagementProtocolError> {
        let registration_epoch = NonZeroU64::new(registration_epoch)
            .ok_or(NodeManagementProtocolError::ZeroRegistrationEpoch)?;
        Ok(Self {
            node_id,
            management_endpoint_ref,
            node_incarnation,
            registration_epoch,
        })
    }

    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.node_id
    }

    #[must_use]
    pub const fn management_endpoint_ref(self) -> NodeManagementEndpointRefV1 {
        self.management_endpoint_ref
    }

    #[must_use]
    pub const fn node_incarnation(self) -> NodeIncarnation {
        self.node_incarnation
    }

    #[must_use]
    pub const fn registration_epoch(self) -> u64 {
        self.registration_epoch.get()
    }
}

/// Exact cursor for a previously authenticated NodeStatus publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeStatusCursorV1 {
    status_sequence: NonZeroU64,
    status_digest: Digest32,
}

impl NodeStatusCursorV1 {
    pub fn try_new(
        status_sequence: u64,
        status_digest: Digest32,
    ) -> Result<Self, NodeManagementProtocolError> {
        let status_sequence = NonZeroU64::new(status_sequence)
            .ok_or(NodeManagementProtocolError::InvalidRequestShape)?;
        if bytes_are_zero(status_digest.as_bytes()) {
            return Err(NodeManagementProtocolError::ZeroStatusDigest);
        }
        Ok(Self {
            status_sequence,
            status_digest,
        })
    }

    #[must_use]
    pub const fn status_sequence(self) -> u64 {
        self.status_sequence.get()
    }

    #[must_use]
    pub const fn status_digest(self) -> Digest32 {
        self.status_digest
    }
}

impl TryFrom<&NodeStatusV1> for NodeStatusCursorV1 {
    type Error = NodeManagementProtocolError;

    fn try_from(status: &NodeStatusV1) -> Result<Self, Self::Error> {
        Self::try_new(status.status_sequence(), status.status_digest())
    }
}

/// One-shot read operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum NodeManagementRequestKindV1 {
    /// Return the last publication, if one exists.
    Latest = 1,
    /// Return the last publication only when newer than an exact cursor.
    Watch = 2,
}

impl NodeManagementRequestKindV1 {
    fn decode(value: u8) -> Result<Self, NodeManagementProtocolError> {
        match value {
            1 => Ok(Self::Latest),
            2 => Ok(Self::Watch),
            _ => Err(NodeManagementProtocolError::UnknownEnumValue),
        }
    }
}

/// Strict immutable PXNQ-v1 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeManagementRequestV1 {
    request_id: [u8; 16],
    target: NodeManagementTargetV1,
    kind: NodeManagementRequestKindV1,
    cursor: Option<NodeStatusCursorV1>,
    request_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl NodeManagementRequestV1 {
    pub fn try_latest(
        request_id: [u8; 16],
        target: NodeManagementTargetV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_build(
            request_id,
            target,
            NodeManagementRequestKindV1::Latest,
            None,
        )
    }

    pub fn try_watch(
        request_id: [u8; 16],
        target: NodeManagementTargetV1,
        cursor: NodeStatusCursorV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_build(
            request_id,
            target,
            NodeManagementRequestKindV1::Watch,
            Some(cursor),
        )
    }

    /// Strictly decodes one fixed-length PXNQ-v1 frame.
    pub fn decode(frame: &[u8]) -> Result<Self, NodeManagementProtocolError> {
        if frame.len() != NODE_MANAGEMENT_REQUEST_BYTES {
            return Err(NodeManagementProtocolError::InvalidFrameLength);
        }
        if &frame[..4] != REQUEST_MAGIC
            || read_u16(&frame[4..6]) != crate::NODE_MANAGEMENT_PROTOCOL_VERSION
            || usize::from(read_u16(&frame[6..8])) != REQUEST_HEADER_BYTES
        {
            return Err(NodeManagementProtocolError::UnsupportedFrame);
        }
        if usize::try_from(read_u32(&frame[8..12])).ok() != Some(frame.len())
            || frame[13..16].iter().any(|byte| *byte != 0)
        {
            return Err(NodeManagementProtocolError::NonCanonicalEncoding);
        }
        let declared_digest = Digest32::from_bytes(read_array::<32>(
            &frame[REQUEST_DIGEST_OFFSET..REQUEST_HEADER_BYTES],
        ));
        if declared_digest != request_digest(&frame[..REQUEST_DIGEST_OFFSET])? {
            return Err(NodeManagementProtocolError::DigestMismatch);
        }
        let target = NodeManagementTargetV1::try_new(
            NodeId::try_from_bytes(read_array::<16>(&frame[32..48]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            NodeManagementEndpointRefV1::try_from_bytes(read_array::<16>(&frame[48..64]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            NodeIncarnation::try_from_bytes(read_array::<16>(&frame[64..80]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            read_u64(&frame[80..88]),
        )?;
        let kind = NodeManagementRequestKindV1::decode(frame[12])?;
        let after_sequence = read_u64(&frame[88..96]);
        let after_digest = Digest32::from_bytes(read_array::<32>(&frame[96..128]));
        let cursor = match kind {
            NodeManagementRequestKindV1::Latest => {
                if after_sequence != 0 || !bytes_are_zero(after_digest.as_bytes()) {
                    return Err(NodeManagementProtocolError::InvalidRequestShape);
                }
                None
            }
            NodeManagementRequestKindV1::Watch => {
                Some(NodeStatusCursorV1::try_new(after_sequence, after_digest)?)
            }
        };
        let request = Self::try_build(read_array::<16>(&frame[16..32]), target, kind, cursor)?;
        if request.canonical_wire() != frame {
            return Err(NodeManagementProtocolError::NonCanonicalEncoding);
        }
        Ok(request)
    }

    fn try_build(
        request_id: [u8; 16],
        target: NodeManagementTargetV1,
        kind: NodeManagementRequestKindV1,
        cursor: Option<NodeStatusCursorV1>,
    ) -> Result<Self, NodeManagementProtocolError> {
        if bytes_are_zero(&request_id) {
            return Err(NodeManagementProtocolError::ZeroRequestId);
        }
        validate_request_shape(kind, cursor)?;
        let canonical_wire = encode_request(request_id, target, kind, cursor)?;
        let request_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire[REQUEST_DIGEST_OFFSET..REQUEST_HEADER_BYTES],
        ));
        Ok(Self {
            request_id,
            target,
            kind,
            cursor,
            request_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    #[must_use]
    pub const fn target(&self) -> NodeManagementTargetV1 {
        self.target
    }

    #[must_use]
    pub const fn kind(&self) -> NodeManagementRequestKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn cursor(&self) -> Option<NodeStatusCursorV1> {
        self.cursor
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

/// Terminal outcome of one read-only exchange.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum NodeManagementResponseOutcomeV1 {
    /// Payload contains one complete current NodeStatus.
    Status = 1,
    /// A Watch cursor exactly equals the current publication.
    NotModified = 2,
    /// The selected current tenure has not published a status yet.
    NotFound = 3,
    /// The selected registration epoch/incarnation is no longer current.
    Fenced = 4,
    /// The cursor is ahead of, or conflicts with, the current publication.
    CursorConflict = 5,
}

impl NodeManagementResponseOutcomeV1 {
    fn decode(value: u8) -> Result<Self, NodeManagementProtocolError> {
        match value {
            1 => Ok(Self::Status),
            2 => Ok(Self::NotModified),
            3 => Ok(Self::NotFound),
            4 => Ok(Self::Fenced),
            5 => Ok(Self::CursorConflict),
            _ => Err(NodeManagementProtocolError::UnknownEnumValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CurrentCoordinateV1 {
    node_incarnation: NodeIncarnation,
    registration_epoch: NonZeroU64,
    status_cursor: Option<NodeStatusCursorV1>,
}

impl CurrentCoordinateV1 {
    fn try_new(
        node_incarnation: NodeIncarnation,
        registration_epoch: u64,
        status_sequence: u64,
        status_digest: Digest32,
    ) -> Result<Self, NodeManagementProtocolError> {
        let registration_epoch = NonZeroU64::new(registration_epoch)
            .ok_or(NodeManagementProtocolError::InvalidResponseShape)?;
        let status_cursor = match (status_sequence, bytes_are_zero(status_digest.as_bytes())) {
            (0, true) => None,
            (0, false) | (_, true) => {
                return Err(NodeManagementProtocolError::InvalidResponseShape);
            }
            (sequence, false) => Some(NodeStatusCursorV1::try_new(sequence, status_digest)?),
        };
        Ok(Self {
            node_incarnation,
            registration_epoch,
            status_cursor,
        })
    }

    fn try_from_daemon(daemon: &NodeDaemonV1) -> Result<Self, NodeManagementProtocolError> {
        let status_cursor = daemon
            .current_status()
            .map(NodeStatusCursorV1::try_from)
            .transpose()?;
        Ok(Self {
            node_incarnation: daemon.tenure().node_incarnation(),
            registration_epoch: NonZeroU64::new(daemon.tenure().registration_epoch())
                .ok_or(NodeManagementProtocolError::InvalidResponseShape)?,
            status_cursor,
        })
    }
}

/// Strict immutable PXNS-v1 response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeManagementResponseV1 {
    request_id: [u8; 16],
    target: NodeManagementTargetV1,
    request_kind: NodeManagementRequestKindV1,
    request_cursor: Option<NodeStatusCursorV1>,
    request_digest: Digest32,
    outcome: NodeManagementResponseOutcomeV1,
    current: CurrentCoordinateV1,
    status: Option<NodeStatusV1>,
    response_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

#[derive(Clone, Copy)]
struct ResponseBuildFields {
    request_id: [u8; 16],
    target: NodeManagementTargetV1,
    request_kind: NodeManagementRequestKindV1,
    request_cursor: Option<NodeStatusCursorV1>,
    request_digest: Digest32,
    outcome: NodeManagementResponseOutcomeV1,
    current: CurrentCoordinateV1,
}

impl NodeManagementResponseV1 {
    /// Strictly decodes one bounded PXNS-v1 response and its optional complete
    /// NodeStatus payload.
    pub fn decode(frame: &[u8]) -> Result<Self, NodeManagementProtocolError> {
        if frame.len() < RESPONSE_HEADER_BYTES || frame.len() > MAX_NODE_MANAGEMENT_RESPONSE_BYTES {
            return Err(NodeManagementProtocolError::InvalidFrameLength);
        }
        if &frame[..4] != RESPONSE_MAGIC
            || read_u16(&frame[4..6]) != crate::NODE_MANAGEMENT_PROTOCOL_VERSION
            || usize::from(read_u16(&frame[6..8])) != RESPONSE_HEADER_BYTES
        {
            return Err(NodeManagementProtocolError::UnsupportedFrame);
        }
        let payload_length = usize::try_from(read_u32(&frame[12..16]))
            .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?;
        if usize::try_from(read_u32(&frame[8..12])).ok() != Some(frame.len())
            || RESPONSE_HEADER_BYTES.checked_add(payload_length) != Some(frame.len())
            || frame[18..24].iter().any(|byte| *byte != 0)
        {
            return Err(NodeManagementProtocolError::NonCanonicalEncoding);
        }
        let declared_digest = Digest32::from_bytes(read_array::<32>(
            &frame[RESPONSE_DIGEST_OFFSET..RESPONSE_HEADER_BYTES],
        ));
        if declared_digest
            != response_digest(
                &frame[..RESPONSE_DIGEST_OFFSET],
                &frame[RESPONSE_HEADER_BYTES..],
            )?
        {
            return Err(NodeManagementProtocolError::DigestMismatch);
        }
        let target = NodeManagementTargetV1::try_new(
            NodeId::try_from_bytes(read_array::<16>(&frame[40..56]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            NodeManagementEndpointRefV1::try_from_bytes(read_array::<16>(&frame[56..72]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            NodeIncarnation::try_from_bytes(read_array::<16>(&frame[72..88]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            read_u64(&frame[88..96]),
        )?;
        let request_kind = NodeManagementRequestKindV1::decode(frame[17])?;
        let request_sequence = read_u64(&frame[96..104]);
        let request_status_digest = Digest32::from_bytes(read_array::<32>(&frame[104..136]));
        let request_cursor =
            decode_request_cursor(request_kind, request_sequence, request_status_digest)?;
        let request_digest = Digest32::from_bytes(read_array::<32>(&frame[136..168]));
        if bytes_are_zero(request_digest.as_bytes()) {
            return Err(NodeManagementProtocolError::DigestMismatch);
        }
        let current = CurrentCoordinateV1::try_new(
            NodeIncarnation::try_from_bytes(read_array::<16>(&frame[168..184]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            read_u64(&frame[184..192]),
            read_u64(&frame[192..200]),
            Digest32::from_bytes(read_array::<32>(&frame[200..232])),
        )?;
        let outcome = NodeManagementResponseOutcomeV1::decode(frame[16])?;
        let status = if payload_length == 0 {
            None
        } else {
            Some(decode_status_payload(&frame[RESPONSE_HEADER_BYTES..])?)
        };
        let response = Self::try_build(
            ResponseBuildFields {
                request_id: read_array::<16>(&frame[24..40]),
                target,
                request_kind,
                request_cursor,
                request_digest,
                outcome,
                current,
            },
            status,
        )?;
        if response.canonical_wire() != frame {
            return Err(NodeManagementProtocolError::NonCanonicalEncoding);
        }
        Ok(response)
    }

    fn with_status(
        request: &NodeManagementRequestV1,
        status: NodeStatusV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        let current = CurrentCoordinateV1::try_new(
            status.node_incarnation(),
            status.registration_epoch(),
            status.status_sequence(),
            status.status_digest(),
        )?;
        Self::try_build(
            fields_from_request(request, NodeManagementResponseOutcomeV1::Status, current),
            Some(status),
        )
    }

    fn not_modified(
        request: &NodeManagementRequestV1,
        current: CurrentCoordinateV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_build(
            fields_from_request(
                request,
                NodeManagementResponseOutcomeV1::NotModified,
                current,
            ),
            None,
        )
    }

    fn not_found(
        request: &NodeManagementRequestV1,
        current: CurrentCoordinateV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_build(
            fields_from_request(request, NodeManagementResponseOutcomeV1::NotFound, current),
            None,
        )
    }

    fn fenced(
        request: &NodeManagementRequestV1,
        current: CurrentCoordinateV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_build(
            fields_from_request(request, NodeManagementResponseOutcomeV1::Fenced, current),
            None,
        )
    }

    fn cursor_conflict(
        request: &NodeManagementRequestV1,
        current: CurrentCoordinateV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_build(
            fields_from_request(
                request,
                NodeManagementResponseOutcomeV1::CursorConflict,
                current,
            ),
            None,
        )
    }

    fn try_build(
        fields: ResponseBuildFields,
        status: Option<NodeStatusV1>,
    ) -> Result<Self, NodeManagementProtocolError> {
        if bytes_are_zero(&fields.request_id) {
            return Err(NodeManagementProtocolError::ZeroRequestId);
        }
        if bytes_are_zero(fields.request_digest.as_bytes()) {
            return Err(NodeManagementProtocolError::DigestMismatch);
        }
        validate_request_shape(fields.request_kind, fields.request_cursor)?;
        validate_response_shape(fields, status.as_ref())?;
        let payload = status
            .as_ref()
            .map(encode_status_payload)
            .transpose()?
            .unwrap_or_default();
        let canonical_wire = encode_response(fields, &payload)?;
        let response_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire[RESPONSE_DIGEST_OFFSET..RESPONSE_HEADER_BYTES],
        ));
        Ok(Self {
            request_id: fields.request_id,
            target: fields.target,
            request_kind: fields.request_kind,
            request_cursor: fields.request_cursor,
            request_digest: fields.request_digest,
            outcome: fields.outcome,
            current: fields.current,
            status,
            response_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Verifies exact request identity, target tenure, cursor, operation, and
    /// complete request digest correlation.
    pub fn validate_for(
        &self,
        request: &NodeManagementRequestV1,
    ) -> Result<(), NodeManagementProtocolError> {
        if self.request_id != request.request_id
            || self.target != request.target
            || self.request_kind != request.kind
            || self.request_cursor != request.cursor
            || self.request_digest != request.request_digest
        {
            return Err(NodeManagementProtocolError::CorrelationMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    #[must_use]
    pub const fn target(&self) -> NodeManagementTargetV1 {
        self.target
    }

    #[must_use]
    pub const fn request_kind(&self) -> NodeManagementRequestKindV1 {
        self.request_kind
    }

    #[must_use]
    pub const fn request_cursor(&self) -> Option<NodeStatusCursorV1> {
        self.request_cursor
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub const fn outcome(&self) -> NodeManagementResponseOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub const fn current_node_incarnation(&self) -> NodeIncarnation {
        self.current.node_incarnation
    }

    #[must_use]
    pub const fn current_registration_epoch(&self) -> u64 {
        self.current.registration_epoch.get()
    }

    #[must_use]
    pub const fn current_cursor(&self) -> Option<NodeStatusCursorV1> {
        self.current.status_cursor
    }

    #[must_use]
    pub const fn status_value(&self) -> Option<&NodeStatusV1> {
        self.status.as_ref()
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

impl NodeDaemonV1 {
    /// Answers only from the last immutable publication cache.
    ///
    /// This method never publishes a heartbeat, changes observations, waits,
    /// retries, infers a partition, or forwards a Runtime apply request.
    pub fn answer_read_only_v1(
        &self,
        request: &NodeManagementRequestV1,
    ) -> Result<NodeManagementResponseV1, NodeManagementProtocolError> {
        if request.target.node_id() != self.identity().node_id()
            || request.target.management_endpoint_ref() != self.management_endpoint_ref()
        {
            return Err(NodeManagementProtocolError::TargetMismatch);
        }
        let current = CurrentCoordinateV1::try_from_daemon(self)?;
        if request.target.node_incarnation() != current.node_incarnation
            || request.target.registration_epoch() != current.registration_epoch.get()
        {
            return NodeManagementResponseV1::fenced(request, current);
        }
        let Some(status) = self.current_status() else {
            return NodeManagementResponseV1::not_found(request, current);
        };
        match request.kind {
            NodeManagementRequestKindV1::Latest => {
                NodeManagementResponseV1::with_status(request, status.clone())
            }
            NodeManagementRequestKindV1::Watch => {
                let request_cursor = request
                    .cursor
                    .ok_or(NodeManagementProtocolError::InvalidRequestShape)?;
                let current_cursor = current
                    .status_cursor
                    .ok_or(NodeManagementProtocolError::InvalidResponseShape)?;
                match current_cursor
                    .status_sequence()
                    .cmp(&request_cursor.status_sequence())
                {
                    core::cmp::Ordering::Greater => {
                        NodeManagementResponseV1::with_status(request, status.clone())
                    }
                    core::cmp::Ordering::Equal
                        if current_cursor.status_digest() == request_cursor.status_digest() =>
                    {
                        NodeManagementResponseV1::not_modified(request, current)
                    }
                    core::cmp::Ordering::Equal | core::cmp::Ordering::Less => {
                        NodeManagementResponseV1::cursor_conflict(request, current)
                    }
                }
            }
        }
    }
}

/// Transport-facing endpoint failure. Authentication, addressing, scheduling,
/// and availability remain properties of the injected transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeManagementEndpointErrorV1 {
    MalformedRequest,
    Unavailable,
    ResponseUnavailable,
}

impl fmt::Display for NodeManagementEndpointErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedRequest => "Node management endpoint rejected a malformed request",
            Self::Unavailable => "Node management endpoint is unavailable for this target",
            Self::ResponseUnavailable => "Node management endpoint could not produce a response",
        })
    }
}

impl std::error::Error for NodeManagementEndpointErrorV1 {}

/// One transport-neutral, single-exchange read endpoint.
pub trait NodeManagementEndpointV1 {
    /// Performs exactly one exchange. Implementations must not retry, wait for
    /// a Watch update, or dispatch Runtime/Deployment mutations.
    fn exchange(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, NodeManagementEndpointErrorV1>;
}

impl NodeManagementEndpointV1 for NodeDaemonV1 {
    fn exchange(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, NodeManagementEndpointErrorV1> {
        let request = NodeManagementRequestV1::decode(canonical_request)
            .map_err(|_| NodeManagementEndpointErrorV1::MalformedRequest)?;
        self.answer_read_only_v1(&request)
            .map(|response| response.canonical_wire)
            .map_err(|error| match error {
                NodeManagementProtocolError::TargetMismatch => {
                    NodeManagementEndpointErrorV1::Unavailable
                }
                _ => NodeManagementEndpointErrorV1::ResponseUnavailable,
            })
    }
}

/// Typed client-side failure for one non-retrying exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeManagementClientErrorV1 {
    InvalidRequest(NodeManagementProtocolError),
    Endpoint(NodeManagementEndpointErrorV1),
    InvalidResponse(NodeManagementProtocolError),
    CorrelationMismatch,
    StatusRejected(NodeContractError),
}

impl fmt::Display for NodeManagementClientErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(error) => write!(formatter, "invalid Node request: {error}"),
            Self::Endpoint(error) => write!(formatter, "Node endpoint failed: {error}"),
            Self::InvalidResponse(error) => write!(formatter, "invalid Node response: {error}"),
            Self::CorrelationMismatch => formatter.write_str("Node response correlation mismatch"),
            Self::StatusRejected(error) => write!(formatter, "Node status rejected: {error}"),
        }
    }
}

impl std::error::Error for NodeManagementClientErrorV1 {}

/// Minimal typed client for one NodeId over a caller-supplied authenticated
/// endpoint.
///
/// The client performs one exchange per method and applies the monotonic
/// [`NodeStatusTrackerV1`] only to `Status` payloads. Supplying an
/// unauthenticated transport does not make its bytes authenticated; transport
/// authentication remains a caller obligation. A separate client (and
/// tracker) is required for each NodeId.
#[derive(Debug)]
pub struct NodeManagementClientV1<E> {
    endpoint: E,
    node_id: NodeId,
    tracker: NodeStatusTrackerV1,
}

impl<E> NodeManagementClientV1<E>
where
    E: NodeManagementEndpointV1,
{
    #[must_use]
    pub fn new(endpoint: E, node_id: NodeId) -> Self {
        Self {
            endpoint,
            node_id,
            tracker: NodeStatusTrackerV1::default(),
        }
    }

    /// Performs exactly one Latest exchange.
    pub fn latest(
        &mut self,
        request_id: [u8; 16],
        target: NodeManagementTargetV1,
    ) -> Result<NodeManagementResponseV1, NodeManagementClientErrorV1> {
        let request = NodeManagementRequestV1::try_latest(request_id, target)
            .map_err(NodeManagementClientErrorV1::InvalidRequest)?;
        self.execute(&request)
    }

    /// Performs exactly one conditional Watch exchange. It never blocks for a
    /// future publication and never retries.
    pub fn watch(
        &mut self,
        request_id: [u8; 16],
        target: NodeManagementTargetV1,
        cursor: NodeStatusCursorV1,
    ) -> Result<NodeManagementResponseV1, NodeManagementClientErrorV1> {
        let request = NodeManagementRequestV1::try_watch(request_id, target, cursor)
            .map_err(NodeManagementClientErrorV1::InvalidRequest)?;
        self.execute(&request)
    }

    fn execute(
        &mut self,
        request: &NodeManagementRequestV1,
    ) -> Result<NodeManagementResponseV1, NodeManagementClientErrorV1> {
        if request.target.node_id() != self.node_id {
            return Err(NodeManagementClientErrorV1::InvalidRequest(
                NodeManagementProtocolError::TargetMismatch,
            ));
        }
        let response_wire = self
            .endpoint
            .exchange(request.canonical_wire())
            .map_err(NodeManagementClientErrorV1::Endpoint)?;
        let response = NodeManagementResponseV1::decode(&response_wire)
            .map_err(NodeManagementClientErrorV1::InvalidResponse)?;
        response
            .validate_for(request)
            .map_err(|_| NodeManagementClientErrorV1::CorrelationMismatch)?;
        if let Some(status) = response.status_value() {
            self.tracker
                .observe_authenticated(status.clone())
                .map_err(NodeManagementClientErrorV1::StatusRejected)?;
        }
        Ok(response)
    }

    /// Returns the last accepted status after caller-owned transport
    /// authentication and local monotonic fencing.
    #[must_use]
    pub const fn current_status(&self) -> Option<&NodeStatusV1> {
        self.tracker.current()
    }

    #[must_use]
    pub fn into_endpoint(self) -> E {
        self.endpoint
    }
}

/// Operation admitted by the Controller-signed PXNR carrier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum NodeControlCarrierKindV1 {
    /// Discover the current target through the pinned transport peer/route.
    Describe = 1,
    /// Carry one exact frozen PXNQ Latest request; the response remains PXNS.
    Latest = 2,
    /// Carry one exact frozen PXNQ Watch request; the response remains PXNS.
    Watch = 3,
    /// Ask the Node owner to derive one short-lived PXQR nonce from local PXOB.
    ObservationChallenge = 4,
    /// Carry one exact frozen PXNO; the response remains PXNA.
    PublishRuntimeObservation = 5,
}

impl NodeControlCarrierKindV1 {
    fn decode(value: u16) -> Result<Self, NodeManagementProtocolError> {
        match value {
            1 => Ok(Self::Describe),
            2 => Ok(Self::Latest),
            3 => Ok(Self::Watch),
            4 => Ok(Self::ObservationChallenge),
            5 => Ok(Self::PublishRuntimeObservation),
            _ => Err(NodeManagementProtocolError::UnsupportedCarrierKind),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NodeControlCarrierPayloadV1 {
    Empty,
    Management(Box<NodeManagementRequestV1>),
    #[cfg(unix)]
    RuntimeObservation(Box<RuntimeObservationRequestV1>),
}

impl NodeControlCarrierPayloadV1 {
    fn canonical_wire(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Management(request) => request.canonical_wire(),
            #[cfg(unix)]
            Self::RuntimeObservation(request) => request.canonical_wire(),
        }
    }
}

/// Exact domain-separated bytes supplied to the PXNR Controller signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeControlCarrierSigningTranscriptV1(Box<[u8]>);

impl NodeControlCarrierSigningTranscriptV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signature-independent producer for one typed PXNR request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeControlCarrierRequestDraftV1 {
    request_id: [u8; 16],
    target: Option<NodeManagementTargetV1>,
    kind: NodeControlCarrierKindV1,
    runtime_host_id: Option<RuntimeHostId>,
    freshness_budget_nanos: u64,
    payload: NodeControlCarrierPayloadV1,
    payload_digest: Digest32,
    auth_claim: ApplyRequestAuthClaim,
}

impl NodeControlCarrierRequestDraftV1 {
    /// Builds an empty Describe request. The pinned transport route and peer
    /// identity select the Node; no unknown Node identity is fabricated.
    pub fn try_describe(
        request_id: [u8; 16],
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_new(
            request_id,
            None,
            NodeControlCarrierKindV1::Describe,
            None,
            0,
            NodeControlCarrierPayloadV1::Empty,
            auth_claim,
        )
    }

    /// Carries one exact PXNQ Latest request for the same target and request ID.
    pub fn try_latest(
        request_id: [u8; 16],
        target: NodeManagementTargetV1,
        request: NodeManagementRequestV1,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_new(
            request_id,
            Some(target),
            NodeControlCarrierKindV1::Latest,
            None,
            0,
            NodeControlCarrierPayloadV1::Management(Box::new(request)),
            auth_claim,
        )
    }

    /// Carries one exact PXNQ Watch request for the same target and request ID.
    pub fn try_watch(
        request_id: [u8; 16],
        target: NodeManagementTargetV1,
        request: NodeManagementRequestV1,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_new(
            request_id,
            Some(target),
            NodeControlCarrierKindV1::Watch,
            None,
            0,
            NodeControlCarrierPayloadV1::Management(Box::new(request)),
            auth_claim,
        )
    }

    /// Requests a Node-local short-lived observation challenge for one exact
    /// current Node target and Runtime authority.
    pub fn try_observation_challenge(
        request_id: [u8; 16],
        target: NodeManagementTargetV1,
        runtime_host_id: RuntimeHostId,
        freshness_budget_nanos: u64,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_new(
            request_id,
            Some(target),
            NodeControlCarrierKindV1::ObservationChallenge,
            Some(runtime_host_id),
            freshness_budget_nanos,
            NodeControlCarrierPayloadV1::Empty,
            auth_claim,
        )
    }

    /// Carries one strict frozen PXNO without exposing the local PXOB token.
    #[cfg(unix)]
    pub fn try_publish_runtime_observation(
        request_id: [u8; 16],
        target: NodeManagementTargetV1,
        request: RuntimeObservationRequestV1,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, NodeManagementProtocolError> {
        Self::try_new(
            request_id,
            Some(target),
            NodeControlCarrierKindV1::PublishRuntimeObservation,
            Some(request.runtime_host_id()),
            request.freshness_budget_nanos(),
            NodeControlCarrierPayloadV1::RuntimeObservation(Box::new(request)),
            auth_claim,
        )
    }

    fn try_new(
        request_id: [u8; 16],
        target: Option<NodeManagementTargetV1>,
        kind: NodeControlCarrierKindV1,
        runtime_host_id: Option<RuntimeHostId>,
        freshness_budget_nanos: u64,
        payload: NodeControlCarrierPayloadV1,
        auth_claim: ApplyRequestAuthClaim,
    ) -> Result<Self, NodeManagementProtocolError> {
        if bytes_are_zero(&request_id)
            || bytes_are_zero(auth_claim.principal().as_bytes())
            || bytes_are_zero(auth_claim.key().as_bytes())
            || auth_claim.algorithm_version() == 0
            || auth_claim.nonce().iter().all(|byte| *byte == 0)
        {
            return Err(NodeManagementProtocolError::InvalidCarrierAuthentication);
        }
        validate_node_control_carrier_shape(
            request_id,
            target,
            kind,
            runtime_host_id,
            freshness_budget_nanos,
            &payload,
        )?;
        let payload_digest = if payload.canonical_wire().is_empty() {
            Digest32::from_bytes([0; 32])
        } else {
            node_control_digest(
                CONTROL_CARRIER_PAYLOAD_DIGEST_DOMAIN,
                payload.canonical_wire(),
            )?
        };
        Ok(Self {
            request_id,
            target,
            kind,
            runtime_host_id,
            freshness_budget_nanos,
            payload,
            payload_digest,
            auth_claim,
        })
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<NodeControlCarrierSigningTranscriptV1, NodeManagementProtocolError> {
        let mut transcript = build_node_control_carrier_transcript(self)?;
        transcript.extend_from_slice(self.payload.canonical_wire());
        Ok(NodeControlCarrierSigningTranscriptV1(
            transcript.into_boxed_slice(),
        ))
    }

    /// Attaches one bounded opaque Controller signature.
    pub fn finalize(
        self,
        signature: &[u8],
    ) -> Result<NodeControlCarrierRequestV1, NodeManagementProtocolError> {
        let authentication =
            ApplyRequestAuthentication::try_new(self.auth_claim.clone(), signature)
                .map_err(|_| NodeManagementProtocolError::InvalidCarrierAuthentication)?;
        NodeControlCarrierRequestV1::try_new(self, authentication)
    }
}

/// Strict Controller-signed PXNR request with a kind-allowlisted payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeControlCarrierRequestV1 {
    request_id: [u8; 16],
    target: Option<NodeManagementTargetV1>,
    kind: NodeControlCarrierKindV1,
    runtime_host_id: Option<RuntimeHostId>,
    freshness_budget_nanos: u64,
    payload: NodeControlCarrierPayloadV1,
    payload_digest: Digest32,
    authentication: ApplyRequestAuthentication,
    request_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl NodeControlCarrierRequestV1 {
    fn try_new(
        draft: NodeControlCarrierRequestDraftV1,
        authentication: ApplyRequestAuthentication,
    ) -> Result<Self, NodeManagementProtocolError> {
        if authentication.claim() != &draft.auth_claim {
            return Err(NodeManagementProtocolError::InvalidCarrierAuthentication);
        }
        let canonical_wire = build_node_control_carrier_wire(&draft, &authentication)?;
        if canonical_wire.len() > MAX_NODE_CONTROL_CARRIER_REQUEST_BYTES {
            return Err(NodeManagementProtocolError::InvalidFrameLength);
        }
        let request_digest =
            node_control_digest(CONTROL_CARRIER_REQUEST_DIGEST_DOMAIN, &canonical_wire)?;
        Ok(Self {
            request_id: draft.request_id,
            target: draft.target,
            kind: draft.kind,
            runtime_host_id: draft.runtime_host_id,
            freshness_budget_nanos: draft.freshness_budget_nanos,
            payload: draft.payload,
            payload_digest: draft.payload_digest,
            authentication,
            request_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes one bounded canonical PXNR v1 frame.
    pub fn decode(frame: &[u8]) -> Result<Self, NodeManagementProtocolError> {
        if frame.len() < CONTROL_CARRIER_REQUEST_FIXED_BYTES
            || frame.len() > MAX_NODE_CONTROL_CARRIER_REQUEST_BYTES
        {
            return Err(NodeManagementProtocolError::InvalidFrameLength);
        }
        if &frame[..4] != CONTROL_CARRIER_REQUEST_MAGIC
            || read_u16(&frame[4..6]) != NODE_CONTROL_CARRIER_VERSION
            || read_u16(&frame[10..12]) != 0
        {
            return Err(NodeManagementProtocolError::UnsupportedFrame);
        }
        let kind = NodeControlCarrierKindV1::decode(read_u16(&frame[6..8]))?;
        let flags = read_u16(&frame[8..10]);
        if flags & !1 != 0 {
            return Err(NodeManagementProtocolError::NonCanonicalEncoding);
        }
        let payload_length = usize::try_from(read_u32(&frame[12..16]))
            .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?;
        if payload_length > MAX_NODE_CONTROL_CARRIER_PAYLOAD_BYTES {
            return Err(NodeManagementProtocolError::InvalidFrameLength);
        }
        let nonce_length = usize::from(read_u16(&frame[180..182]));
        let signature_length = usize::from(read_u16(&frame[182..184]));
        let payload_offset = CONTROL_CARRIER_REQUEST_FIXED_BYTES
            .checked_add(nonce_length)
            .ok_or(NodeManagementProtocolError::InvalidFrameLength)?;
        let signature_offset = payload_offset
            .checked_add(payload_length)
            .ok_or(NodeManagementProtocolError::InvalidFrameLength)?;
        if nonce_length == 0
            || nonce_length > MAX_APPLY_AUTH_NONCE_BYTES
            || signature_length == 0
            || signature_length > MAX_APPLY_AUTH_SIGNATURE_BYTES
            || signature_offset.checked_add(signature_length) != Some(frame.len())
        {
            return Err(NodeManagementProtocolError::InvalidFrameLength);
        }
        let request_id = read_array::<16>(&frame[16..32]);
        let target = if flags == 1 {
            let node_id = NodeId::try_from_bytes(read_array::<16>(&frame[32..48]))
                .map_err(NodeManagementProtocolError::StatusRejected)?;
            Some(NodeManagementTargetV1::try_new(
                node_id,
                NodeManagementEndpointRefV1::try_from_bytes(read_array::<16>(&frame[48..64]))
                    .map_err(NodeManagementProtocolError::StatusRejected)?,
                NodeIncarnation::try_from_bytes(read_array::<16>(&frame[64..80]))
                    .map_err(NodeManagementProtocolError::StatusRejected)?,
                read_u64(&frame[80..88]),
            )?)
        } else {
            if frame[32..88].iter().any(|byte| *byte != 0) {
                return Err(NodeManagementProtocolError::NonCanonicalEncoding);
            }
            None
        };
        let runtime_host_bytes = read_array::<16>(&frame[88..104]);
        let runtime_host_id = if bytes_are_zero(&runtime_host_bytes) {
            None
        } else {
            Some(RuntimeHostId::from_bytes(runtime_host_bytes))
        };
        let freshness_budget_nanos = read_u64(&frame[104..112]);
        let payload_digest = Digest32::from_bytes(read_array::<32>(&frame[112..144]));
        let nonce = &frame[CONTROL_CARRIER_REQUEST_FIXED_BYTES..payload_offset];
        let auth_claim = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes(read_array::<16>(&frame[144..160])),
            ApplyAuthKeyRef::from_bytes(read_array::<16>(&frame[160..176])),
            ApplyAuthAlgorithm::try_new(read_u16(&frame[176..178]))
                .map_err(|_| NodeManagementProtocolError::InvalidCarrierAuthentication)?,
            read_u16(&frame[178..180]),
            nonce,
        )
        .map_err(|_| NodeManagementProtocolError::InvalidCarrierAuthentication)?;
        let payload_wire = &frame[payload_offset..signature_offset];
        let payload = decode_node_control_carrier_payload(kind, payload_wire)?;
        let expected_payload_digest = if payload_wire.is_empty() {
            Digest32::from_bytes([0; 32])
        } else {
            node_control_digest(CONTROL_CARRIER_PAYLOAD_DIGEST_DOMAIN, payload_wire)?
        };
        if payload_digest != expected_payload_digest {
            return Err(NodeManagementProtocolError::DigestMismatch);
        }
        let draft = NodeControlCarrierRequestDraftV1::try_new(
            request_id,
            target,
            kind,
            runtime_host_id,
            freshness_budget_nanos,
            payload,
            auth_claim,
        )?;
        if draft.payload_digest != payload_digest {
            return Err(NodeManagementProtocolError::DigestMismatch);
        }
        let decoded = draft.finalize(&frame[signature_offset..])?;
        if decoded.canonical_wire() != frame {
            return Err(NodeManagementProtocolError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    /// Authenticates the outer Controller request before dispatch.
    pub fn verify_controller_carrier<Verify>(
        &self,
        expected_principal: PrincipalRef,
        expected_key: ApplyAuthKeyRef,
        expected_key_fingerprint: Digest32,
        verify: Verify,
    ) -> Result<ControllerAuthenticatedNodeControlCarrierV1<'_>, NodeManagementProtocolError>
    where
        Verify: FnOnce(PrincipalRef, ApplyAuthKeyRef, Digest32, &[u8], &[u8]) -> bool,
    {
        let claim = self.authentication.claim();
        if bytes_are_zero(expected_key_fingerprint.as_bytes())
            || claim.principal() != expected_principal
            || claim.key() != expected_key
        {
            return Err(NodeManagementProtocolError::InvalidCarrierAuthentication);
        }
        let transcript = self.signing_transcript()?;
        if !verify(
            expected_principal,
            expected_key,
            expected_key_fingerprint,
            transcript.as_bytes(),
            self.authentication.signature(),
        ) {
            return Err(NodeManagementProtocolError::InvalidCarrierAuthentication);
        }
        Ok(ControllerAuthenticatedNodeControlCarrierV1 { request: self })
    }

    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    #[must_use]
    pub const fn target(&self) -> Option<NodeManagementTargetV1> {
        self.target
    }

    #[must_use]
    pub const fn node_id(&self) -> Option<NodeId> {
        match self.target {
            Some(target) => Some(target.node_id()),
            None => None,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> NodeControlCarrierKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn runtime_host_id(&self) -> Option<RuntimeHostId> {
        self.runtime_host_id
    }

    #[must_use]
    pub const fn freshness_budget_nanos(&self) -> u64 {
        self.freshness_budget_nanos
    }

    #[must_use]
    pub fn management_request(&self) -> Option<&NodeManagementRequestV1> {
        match &self.payload {
            NodeControlCarrierPayloadV1::Management(request) => Some(request.as_ref()),
            _ => None,
        }
    }

    #[cfg(unix)]
    #[must_use]
    pub fn runtime_observation_request(&self) -> Option<&RuntimeObservationRequestV1> {
        match &self.payload {
            NodeControlCarrierPayloadV1::RuntimeObservation(request) => Some(request.as_ref()),
            _ => None,
        }
    }

    #[must_use]
    pub const fn payload_digest(&self) -> Digest32 {
        self.payload_digest
    }

    #[must_use]
    pub const fn authentication(&self) -> &ApplyRequestAuthentication {
        &self.authentication
    }

    #[must_use]
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    pub fn signing_transcript(
        &self,
    ) -> Result<NodeControlCarrierSigningTranscriptV1, NodeManagementProtocolError> {
        NodeControlCarrierRequestDraftV1 {
            request_id: self.request_id,
            target: self.target,
            kind: self.kind,
            runtime_host_id: self.runtime_host_id,
            freshness_budget_nanos: self.freshness_budget_nanos,
            payload: self.payload.clone(),
            payload_digest: self.payload_digest,
            auth_claim: self.authentication.claim().clone(),
        }
        .signing_transcript()
    }
}

/// Marker issued after the caller's pinned Controller verifier accepts PXNR.
#[derive(Clone, Copy, Debug)]
pub struct ControllerAuthenticatedNodeControlCarrierV1<'a> {
    request: &'a NodeControlCarrierRequestV1,
}

impl<'a> ControllerAuthenticatedNodeControlCarrierV1<'a> {
    #[must_use]
    pub const fn request(self) -> &'a NodeControlCarrierRequestV1 {
        self.request
    }

    #[must_use]
    pub const fn kind(self) -> NodeControlCarrierKindV1 {
        self.request.kind()
    }

    #[must_use]
    pub fn management_request(self) -> Option<&'a NodeManagementRequestV1> {
        self.request.management_request()
    }

    #[cfg(unix)]
    #[must_use]
    pub fn runtime_observation_request(self) -> Option<&'a RuntimeObservationRequestV1> {
        self.request.runtime_observation_request()
    }
}

/// Tagged PXNE response kind. Latest/Watch/PXNO responses never use PXNE.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum NodeControlDescribeResponseKindV1 {
    Describe = 1,
    ObservationChallenge = 4,
}

impl NodeControlDescribeResponseKindV1 {
    fn decode(value: u16) -> Result<Self, NodeManagementProtocolError> {
        match value {
            1 => Ok(Self::Describe),
            4 => Ok(Self::ObservationChallenge),
            _ => Err(NodeManagementProtocolError::UnsupportedCarrierKind),
        }
    }
}

/// Node-local PXOB-derived challenge facts. The generation token is absent.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeControlObservationChallengeV1 {
    observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    runtime_host_id: RuntimeHostId,
    authority_digest: Digest32,
    intended_status_sequence: NonZeroU64,
    freshness_budget_nanos: NonZeroU64,
    issued_at_unix_nanos: NonZeroU64,
    expires_at_unix_nanos: NonZeroU64,
    query_nonce: Digest32,
}

/// Complete non-secret Node-local facts used to build one challenge response.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeControlObservationChallengeFieldsV1 {
    /// Existing Node-local PXOB observation endpoint used for derivation.
    pub observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    /// Runtime authority that must answer the derived PXQR challenge.
    pub runtime_host_id: RuntimeHostId,
    /// Digest of the Runtime observation authority pinned by the Node owner.
    pub authority_digest: Digest32,
    /// Next durable Node-status sequence the resulting PXNO must publish.
    pub intended_status_sequence: u64,
    /// Controller-requested bounded freshness budget.
    pub freshness_budget_nanos: u64,
    /// Node-owner wall-clock issuance time.
    pub issued_at_unix_nanos: u64,
    /// Node-owner wall-clock expiry time.
    pub expires_at_unix_nanos: u64,
    /// Non-zero PXOB-derived nonce delivered to the Runtime in PXQR.
    pub query_nonce: Digest32,
}

#[cfg(unix)]
impl NodeControlObservationChallengeV1 {
    pub fn try_new(
        fields: NodeControlObservationChallengeFieldsV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        let intended_status_sequence = NonZeroU64::new(fields.intended_status_sequence)
            .ok_or(NodeManagementProtocolError::InvalidCarrierShape)?;
        let freshness_budget_nanos = NonZeroU64::new(fields.freshness_budget_nanos)
            .filter(|value| value.get() <= crate::MAX_NODE_STATUS_FRESHNESS_NANOS)
            .ok_or(NodeManagementProtocolError::InvalidCarrierShape)?;
        let issued_at_unix_nanos = NonZeroU64::new(fields.issued_at_unix_nanos)
            .ok_or(NodeManagementProtocolError::InvalidCarrierShape)?;
        let expires_at_unix_nanos = NonZeroU64::new(fields.expires_at_unix_nanos)
            .ok_or(NodeManagementProtocolError::InvalidCarrierShape)?;
        expires_at_unix_nanos
            .get()
            .checked_sub(issued_at_unix_nanos.get())
            .filter(|window| *window != 0 && *window <= freshness_budget_nanos.get())
            .ok_or(NodeManagementProtocolError::InvalidCarrierShape)?;
        if bytes_are_zero(fields.runtime_host_id.as_bytes())
            || bytes_are_zero(fields.authority_digest.as_bytes())
            || bytes_are_zero(fields.query_nonce.as_bytes())
        {
            return Err(NodeManagementProtocolError::InvalidCarrierShape);
        }
        Ok(Self {
            observation_endpoint_ref: fields.observation_endpoint_ref,
            runtime_host_id: fields.runtime_host_id,
            authority_digest: fields.authority_digest,
            intended_status_sequence,
            freshness_budget_nanos,
            issued_at_unix_nanos,
            expires_at_unix_nanos,
            query_nonce: fields.query_nonce,
        })
    }

    #[must_use]
    pub const fn observation_endpoint_ref(self) -> RuntimeObservationEndpointRefV1 {
        self.observation_endpoint_ref
    }

    #[must_use]
    pub const fn runtime_host_id(self) -> RuntimeHostId {
        self.runtime_host_id
    }

    #[must_use]
    pub const fn authority_digest(self) -> Digest32 {
        self.authority_digest
    }

    #[must_use]
    pub const fn intended_status_sequence(self) -> u64 {
        self.intended_status_sequence.get()
    }

    #[must_use]
    pub const fn freshness_budget_nanos(self) -> u64 {
        self.freshness_budget_nanos.get()
    }

    #[must_use]
    pub const fn issued_at_unix_nanos(self) -> u64 {
        self.issued_at_unix_nanos.get()
    }

    #[must_use]
    pub const fn expires_at_unix_nanos(self) -> u64 {
        self.expires_at_unix_nanos.get()
    }

    #[must_use]
    pub const fn query_nonce(self) -> Digest32 {
        self.query_nonce
    }
}

/// Producer for one digest-correlated, unsigned PXNE Describe/challenge reply.
///
/// PXNE is valid only on the same pinned mTLS one-shot exchange. It is not a
/// durable capability and carries no Node signing claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeControlDescribeResponseDraftV1 {
    request_id: [u8; 16],
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    kind: NodeControlDescribeResponseKindV1,
    target: NodeManagementTargetV1,
    #[cfg(unix)]
    challenge: Option<NodeControlObservationChallengeV1>,
}

impl NodeControlDescribeResponseDraftV1 {
    pub fn try_describe(
        request: &NodeControlCarrierRequestV1,
        target: NodeManagementTargetV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        if request.kind != NodeControlCarrierKindV1::Describe || request.target.is_some() {
            return Err(NodeManagementProtocolError::CorrelationMismatch);
        }
        Ok(Self {
            request_id: request.request_id,
            request_digest: request.request_digest,
            request_nonce: request.authentication.claim().nonce().into(),
            kind: NodeControlDescribeResponseKindV1::Describe,
            target,
            #[cfg(unix)]
            challenge: None,
        })
    }

    #[cfg(unix)]
    pub fn try_observation_challenge(
        request: &NodeControlCarrierRequestV1,
        challenge: NodeControlObservationChallengeV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        let target = request
            .target
            .ok_or(NodeManagementProtocolError::CorrelationMismatch)?;
        if request.kind != NodeControlCarrierKindV1::ObservationChallenge
            || request.runtime_host_id != Some(challenge.runtime_host_id())
            || request.freshness_budget_nanos != challenge.freshness_budget_nanos()
        {
            return Err(NodeManagementProtocolError::CorrelationMismatch);
        }
        Ok(Self {
            request_id: request.request_id,
            request_digest: request.request_digest,
            request_nonce: request.authentication.claim().nonce().into(),
            kind: NodeControlDescribeResponseKindV1::ObservationChallenge,
            target,
            challenge: Some(challenge),
        })
    }

    pub fn finalize(self) -> Result<NodeControlDescribeResponseV1, NodeManagementProtocolError> {
        NodeControlDescribeResponseV1::try_new(self)
    }
}

/// Strict tagged PXNE response for Describe or ObservationChallenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeControlDescribeResponseV1 {
    request_id: [u8; 16],
    request_digest: Digest32,
    request_nonce: Box<[u8]>,
    kind: NodeControlDescribeResponseKindV1,
    target: NodeManagementTargetV1,
    #[cfg(unix)]
    challenge: Option<NodeControlObservationChallengeV1>,
    response_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl NodeControlDescribeResponseV1 {
    fn try_new(
        draft: NodeControlDescribeResponseDraftV1,
    ) -> Result<Self, NodeManagementProtocolError> {
        let canonical_wire = build_node_control_describe_response_wire(&draft)?;
        let response_digest = Digest32::from_bytes(read_array::<32>(
            &canonical_wire[256..CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES],
        ));
        Ok(Self {
            request_id: draft.request_id,
            request_digest: draft.request_digest,
            request_nonce: draft.request_nonce,
            kind: draft.kind,
            target: draft.target,
            #[cfg(unix)]
            challenge: draft.challenge,
            response_digest,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    pub fn decode(frame: &[u8]) -> Result<Self, NodeManagementProtocolError> {
        if frame.len() < CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES
            || frame.len() > MAX_NODE_CONTROL_DESCRIBE_RESPONSE_BYTES
            || &frame[..4] != CONTROL_DESCRIBE_RESPONSE_MAGIC
            || read_u16(&frame[4..6]) != NODE_CONTROL_CARRIER_VERSION
            || usize::from(read_u16(&frame[6..8])) != CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES
            || usize::try_from(read_u32(&frame[8..12])).ok() != Some(frame.len())
            || read_u16(&frame[14..16]) != 0
            || frame[66..72].iter().any(|byte| *byte != 0)
        {
            return Err(NodeManagementProtocolError::UnsupportedFrame);
        }
        let nonce_length = usize::from(read_u16(&frame[64..66]));
        if nonce_length == 0
            || nonce_length > MAX_APPLY_AUTH_NONCE_BYTES
            || CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES.checked_add(nonce_length) != Some(frame.len())
        {
            return Err(NodeManagementProtocolError::InvalidFrameLength);
        }
        let declared_digest = Digest32::from_bytes(read_array::<32>(&frame[256..288]));
        if declared_digest
            != node_control_response_digest(
                &frame[..256],
                &frame[CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES..],
            )?
        {
            return Err(NodeManagementProtocolError::DigestMismatch);
        }
        let kind = NodeControlDescribeResponseKindV1::decode(read_u16(&frame[12..14]))?;
        let target = NodeManagementTargetV1::try_new(
            NodeId::try_from_bytes(read_array::<16>(&frame[72..88]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            NodeManagementEndpointRefV1::try_from_bytes(read_array::<16>(&frame[88..104]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            NodeIncarnation::try_from_bytes(read_array::<16>(&frame[104..120]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            read_u64(&frame[120..128]),
        )?;
        #[cfg(unix)]
        let challenge = match kind {
            NodeControlDescribeResponseKindV1::Describe => {
                if frame[128..256].iter().any(|byte| *byte != 0) {
                    return Err(NodeManagementProtocolError::NonCanonicalEncoding);
                }
                None
            }
            NodeControlDescribeResponseKindV1::ObservationChallenge => {
                Some(NodeControlObservationChallengeV1::try_new(
                    NodeControlObservationChallengeFieldsV1 {
                        observation_endpoint_ref: RuntimeObservationEndpointRefV1::try_from_bytes(
                            read_array::<16>(&frame[128..144]),
                        )
                        .map_err(NodeManagementProtocolError::ObservationRejected)?,
                        runtime_host_id: RuntimeHostId::from_bytes(read_array::<16>(
                            &frame[144..160],
                        )),
                        authority_digest: Digest32::from_bytes(read_array::<32>(&frame[160..192])),
                        intended_status_sequence: read_u64(&frame[192..200]),
                        freshness_budget_nanos: read_u64(&frame[200..208]),
                        issued_at_unix_nanos: read_u64(&frame[208..216]),
                        expires_at_unix_nanos: read_u64(&frame[216..224]),
                        query_nonce: Digest32::from_bytes(read_array::<32>(&frame[224..256])),
                    },
                )?)
            }
        };
        #[cfg(not(unix))]
        if kind == NodeControlDescribeResponseKindV1::ObservationChallenge {
            return Err(NodeManagementProtocolError::UnsupportedCarrierKind);
        }
        let draft = NodeControlDescribeResponseDraftV1 {
            request_id: read_array::<16>(&frame[16..32]),
            request_digest: Digest32::from_bytes(read_array::<32>(&frame[32..64])),
            request_nonce: frame[CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES..].into(),
            kind,
            target,
            #[cfg(unix)]
            challenge,
        };
        let decoded = draft.finalize()?;
        if decoded.canonical_wire() != frame {
            return Err(NodeManagementProtocolError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    pub fn validate_for(
        &self,
        request: &NodeControlCarrierRequestV1,
    ) -> Result<(), NodeManagementProtocolError> {
        if self.request_id != request.request_id
            || self.request_digest != request.request_digest
            || self.request_nonce.as_ref() != request.authentication.claim().nonce()
        {
            return Err(NodeManagementProtocolError::CorrelationMismatch);
        }
        match self.kind {
            NodeControlDescribeResponseKindV1::Describe => {
                if request.kind != NodeControlCarrierKindV1::Describe || request.target.is_some() {
                    return Err(NodeManagementProtocolError::CorrelationMismatch);
                }
            }
            NodeControlDescribeResponseKindV1::ObservationChallenge => {
                #[cfg(unix)]
                {
                    let challenge = self
                        .challenge
                        .ok_or(NodeManagementProtocolError::CorrelationMismatch)?;
                    if request.kind != NodeControlCarrierKindV1::ObservationChallenge
                        || request.target != Some(self.target)
                        || request.runtime_host_id != Some(challenge.runtime_host_id())
                        || request.freshness_budget_nanos != challenge.freshness_budget_nanos()
                    {
                        return Err(NodeManagementProtocolError::CorrelationMismatch);
                    }
                }
                #[cfg(not(unix))]
                return Err(NodeManagementProtocolError::UnsupportedCarrierKind);
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
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
    pub const fn kind(&self) -> NodeControlDescribeResponseKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn target(&self) -> NodeManagementTargetV1 {
        self.target
    }

    #[cfg(unix)]
    #[must_use]
    pub const fn observation_challenge(&self) -> Option<NodeControlObservationChallengeV1> {
        self.challenge
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

fn validate_node_control_carrier_shape(
    request_id: [u8; 16],
    target: Option<NodeManagementTargetV1>,
    kind: NodeControlCarrierKindV1,
    runtime_host_id: Option<RuntimeHostId>,
    freshness_budget_nanos: u64,
    payload: &NodeControlCarrierPayloadV1,
) -> Result<(), NodeManagementProtocolError> {
    if bytes_are_zero(&request_id) {
        return Err(NodeManagementProtocolError::InvalidCarrierShape);
    }
    match (
        kind,
        target,
        runtime_host_id,
        freshness_budget_nanos,
        payload,
    ) {
        (NodeControlCarrierKindV1::Describe, None, None, 0, NodeControlCarrierPayloadV1::Empty) => {
            Ok(())
        }
        (
            NodeControlCarrierKindV1::Latest,
            Some(target),
            None,
            0,
            NodeControlCarrierPayloadV1::Management(request),
        ) if request.request_id() == request_id
            && request.target() == target
            && request.kind() == NodeManagementRequestKindV1::Latest =>
        {
            Ok(())
        }
        (
            NodeControlCarrierKindV1::Watch,
            Some(target),
            None,
            0,
            NodeControlCarrierPayloadV1::Management(request),
        ) if request.request_id() == request_id
            && request.target() == target
            && request.kind() == NodeManagementRequestKindV1::Watch =>
        {
            Ok(())
        }
        (
            NodeControlCarrierKindV1::ObservationChallenge,
            Some(_),
            Some(runtime_host_id),
            freshness_budget_nanos,
            NodeControlCarrierPayloadV1::Empty,
        ) if !bytes_are_zero(runtime_host_id.as_bytes())
            && freshness_budget_nanos != 0
            && freshness_budget_nanos <= crate::MAX_NODE_STATUS_FRESHNESS_NANOS =>
        {
            Ok(())
        }
        #[cfg(unix)]
        (
            NodeControlCarrierKindV1::PublishRuntimeObservation,
            Some(_),
            Some(runtime_host_id),
            freshness_budget_nanos,
            NodeControlCarrierPayloadV1::RuntimeObservation(request),
        ) if request.runtime_host_id() == runtime_host_id
            && request.freshness_budget_nanos() == freshness_budget_nanos =>
        {
            Ok(())
        }
        _ => Err(NodeManagementProtocolError::InvalidCarrierShape),
    }
}

fn decode_node_control_carrier_payload(
    kind: NodeControlCarrierKindV1,
    payload: &[u8],
) -> Result<NodeControlCarrierPayloadV1, NodeManagementProtocolError> {
    match kind {
        NodeControlCarrierKindV1::Describe | NodeControlCarrierKindV1::ObservationChallenge => {
            if !payload.is_empty() {
                return Err(NodeManagementProtocolError::InvalidCarrierPayload);
            }
            Ok(NodeControlCarrierPayloadV1::Empty)
        }
        NodeControlCarrierKindV1::Latest | NodeControlCarrierKindV1::Watch => {
            NodeManagementRequestV1::decode(payload)
                .map(Box::new)
                .map(NodeControlCarrierPayloadV1::Management)
                .map_err(|_| NodeManagementProtocolError::InvalidCarrierPayload)
        }
        NodeControlCarrierKindV1::PublishRuntimeObservation => {
            #[cfg(unix)]
            {
                RuntimeObservationRequestV1::decode(payload)
                    .map(Box::new)
                    .map(NodeControlCarrierPayloadV1::RuntimeObservation)
                    .map_err(NodeManagementProtocolError::ObservationRejected)
            }
            #[cfg(not(unix))]
            {
                let _ = payload;
                Err(NodeManagementProtocolError::UnsupportedCarrierKind)
            }
        }
    }
}

fn build_node_control_carrier_transcript(
    draft: &NodeControlCarrierRequestDraftV1,
) -> Result<Vec<u8>, NodeManagementProtocolError> {
    let payload_length = u32::try_from(draft.payload.canonical_wire().len())
        .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?;
    let nonce_length = u16::try_from(draft.auth_claim.nonce().len())
        .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?;
    let mut transcript = Vec::new();
    transcript.extend_from_slice(CONTROL_CARRIER_SIGNING_MAGIC);
    transcript.extend_from_slice(&NODE_CONTROL_CARRIER_SIGNING_VERSION.to_be_bytes());
    append_node_control_carrier_fields(&mut transcript, draft, payload_length, nonce_length);
    transcript.extend_from_slice(draft.auth_claim.nonce());
    Ok(transcript)
}

fn append_node_control_carrier_fields(
    wire: &mut Vec<u8>,
    draft: &NodeControlCarrierRequestDraftV1,
    payload_length: u32,
    nonce_length: u16,
) {
    wire.extend_from_slice(&(draft.kind as u16).to_be_bytes());
    let target_flag = if draft.target.is_some() { 1_u16 } else { 0_u16 };
    wire.extend_from_slice(&target_flag.to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(&payload_length.to_be_bytes());
    wire.extend_from_slice(&draft.request_id);
    match draft.target {
        Some(target) => {
            wire.extend_from_slice(target.node_id().as_bytes());
            wire.extend_from_slice(target.management_endpoint_ref().as_bytes());
            wire.extend_from_slice(target.node_incarnation().as_bytes());
            wire.extend_from_slice(&target.registration_epoch().to_be_bytes());
        }
        None => wire.extend_from_slice(&[0; 56]),
    }
    match draft.runtime_host_id {
        Some(runtime_host_id) => wire.extend_from_slice(runtime_host_id.as_bytes()),
        None => wire.extend_from_slice(&[0; 16]),
    }
    wire.extend_from_slice(&draft.freshness_budget_nanos.to_be_bytes());
    wire.extend_from_slice(draft.payload_digest.as_bytes());
    wire.extend_from_slice(draft.auth_claim.principal().as_bytes());
    wire.extend_from_slice(draft.auth_claim.key().as_bytes());
    wire.extend_from_slice(&draft.auth_claim.algorithm().value().to_be_bytes());
    wire.extend_from_slice(&draft.auth_claim.algorithm_version().to_be_bytes());
    wire.extend_from_slice(&nonce_length.to_be_bytes());
}

fn build_node_control_carrier_wire(
    draft: &NodeControlCarrierRequestDraftV1,
    authentication: &ApplyRequestAuthentication,
) -> Result<Vec<u8>, NodeManagementProtocolError> {
    let payload_length = u32::try_from(draft.payload.canonical_wire().len())
        .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?;
    let nonce_length = u16::try_from(draft.auth_claim.nonce().len())
        .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?;
    let signature_length = u16::try_from(authentication.signature().len())
        .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?;
    let mut wire = Vec::with_capacity(
        CONTROL_CARRIER_REQUEST_FIXED_BYTES
            + usize::from(nonce_length)
            + draft.payload.canonical_wire().len()
            + authentication.signature().len(),
    );
    wire.extend_from_slice(CONTROL_CARRIER_REQUEST_MAGIC);
    wire.extend_from_slice(&NODE_CONTROL_CARRIER_VERSION.to_be_bytes());
    append_node_control_carrier_fields(&mut wire, draft, payload_length, nonce_length);
    wire.extend_from_slice(&signature_length.to_be_bytes());
    wire.extend_from_slice(draft.auth_claim.nonce());
    wire.extend_from_slice(draft.payload.canonical_wire());
    wire.extend_from_slice(authentication.signature());
    Ok(wire)
}

fn build_node_control_describe_response_wire(
    draft: &NodeControlDescribeResponseDraftV1,
) -> Result<Vec<u8>, NodeManagementProtocolError> {
    if bytes_are_zero(&draft.request_id)
        || bytes_are_zero(draft.request_digest.as_bytes())
        || draft.request_nonce.is_empty()
        || draft.request_nonce.len() > MAX_APPLY_AUTH_NONCE_BYTES
        || draft.request_nonce.iter().all(|byte| *byte == 0)
    {
        return Err(NodeManagementProtocolError::InvalidResponseShape);
    }
    #[cfg(unix)]
    match (draft.kind, draft.challenge) {
        (NodeControlDescribeResponseKindV1::Describe, None)
        | (NodeControlDescribeResponseKindV1::ObservationChallenge, Some(_)) => {}
        _ => return Err(NodeManagementProtocolError::InvalidResponseShape),
    }
    let total_length = CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES
        .checked_add(draft.request_nonce.len())
        .ok_or(NodeManagementProtocolError::InvalidFrameLength)?;
    let mut wire = vec![0; total_length];
    wire[..4].copy_from_slice(CONTROL_DESCRIBE_RESPONSE_MAGIC);
    wire[4..6].copy_from_slice(&NODE_CONTROL_CARRIER_VERSION.to_be_bytes());
    wire[6..8].copy_from_slice(
        &u16::try_from(CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES)
            .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    wire[8..12].copy_from_slice(
        &u32::try_from(total_length)
            .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    wire[12..14].copy_from_slice(&(draft.kind as u16).to_be_bytes());
    wire[16..32].copy_from_slice(&draft.request_id);
    wire[32..64].copy_from_slice(draft.request_digest.as_bytes());
    wire[64..66].copy_from_slice(
        &u16::try_from(draft.request_nonce.len())
            .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    wire[72..88].copy_from_slice(draft.target.node_id().as_bytes());
    wire[88..104].copy_from_slice(draft.target.management_endpoint_ref().as_bytes());
    wire[104..120].copy_from_slice(draft.target.node_incarnation().as_bytes());
    wire[120..128].copy_from_slice(&draft.target.registration_epoch().to_be_bytes());
    #[cfg(unix)]
    if let Some(challenge) = draft.challenge {
        wire[128..144].copy_from_slice(challenge.observation_endpoint_ref().as_bytes());
        wire[144..160].copy_from_slice(challenge.runtime_host_id().as_bytes());
        wire[160..192].copy_from_slice(challenge.authority_digest().as_bytes());
        wire[192..200].copy_from_slice(&challenge.intended_status_sequence().to_be_bytes());
        wire[200..208].copy_from_slice(&challenge.freshness_budget_nanos().to_be_bytes());
        wire[208..216].copy_from_slice(&challenge.issued_at_unix_nanos().to_be_bytes());
        wire[216..224].copy_from_slice(&challenge.expires_at_unix_nanos().to_be_bytes());
        wire[224..256].copy_from_slice(challenge.query_nonce().as_bytes());
    }
    wire[CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES..].copy_from_slice(&draft.request_nonce);
    let digest =
        node_control_response_digest(&wire[..256], &wire[CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES..])?;
    wire[256..CONTROL_DESCRIBE_RESPONSE_FIXED_BYTES].copy_from_slice(digest.as_bytes());
    Ok(wire)
}

fn node_control_digest(
    domain: &[u8],
    wire: &[u8],
) -> Result<Digest32, NodeManagementProtocolError> {
    let mut builder = Digest32Builder::try_new(domain)
        .map_err(|_| NodeManagementProtocolError::DigestEncodingFailed)?;
    builder
        .field_bytes(wire)
        .map_err(|_| NodeManagementProtocolError::DigestEncodingFailed)?;
    Ok(builder.finish())
}

fn node_control_response_digest(
    header: &[u8],
    nonce: &[u8],
) -> Result<Digest32, NodeManagementProtocolError> {
    let mut builder = Digest32Builder::try_new(CONTROL_DESCRIBE_RESPONSE_DIGEST_DOMAIN)
        .map_err(|_| NodeManagementProtocolError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .and_then(|value| value.field_bytes(nonce))
        .map_err(|_| NodeManagementProtocolError::DigestEncodingFailed)?;
    Ok(builder.finish())
}

fn fields_from_request(
    request: &NodeManagementRequestV1,
    outcome: NodeManagementResponseOutcomeV1,
    current: CurrentCoordinateV1,
) -> ResponseBuildFields {
    ResponseBuildFields {
        request_id: request.request_id,
        target: request.target,
        request_kind: request.kind,
        request_cursor: request.cursor,
        request_digest: request.request_digest,
        outcome,
        current,
    }
}

fn validate_request_shape(
    kind: NodeManagementRequestKindV1,
    cursor: Option<NodeStatusCursorV1>,
) -> Result<(), NodeManagementProtocolError> {
    match (kind, cursor) {
        (NodeManagementRequestKindV1::Latest, None)
        | (NodeManagementRequestKindV1::Watch, Some(_)) => Ok(()),
        (NodeManagementRequestKindV1::Latest, Some(_))
        | (NodeManagementRequestKindV1::Watch, None) => {
            Err(NodeManagementProtocolError::InvalidRequestShape)
        }
    }
}

fn decode_request_cursor(
    kind: NodeManagementRequestKindV1,
    sequence: u64,
    digest: Digest32,
) -> Result<Option<NodeStatusCursorV1>, NodeManagementProtocolError> {
    match kind {
        NodeManagementRequestKindV1::Latest => {
            if sequence != 0 || !bytes_are_zero(digest.as_bytes()) {
                return Err(NodeManagementProtocolError::InvalidRequestShape);
            }
            Ok(None)
        }
        NodeManagementRequestKindV1::Watch => {
            Ok(Some(NodeStatusCursorV1::try_new(sequence, digest)?))
        }
    }
}

fn validate_response_shape(
    fields: ResponseBuildFields,
    status: Option<&NodeStatusV1>,
) -> Result<(), NodeManagementProtocolError> {
    let target_is_current = fields.current.node_incarnation == fields.target.node_incarnation()
        && fields.current.registration_epoch.get() == fields.target.registration_epoch();
    match fields.outcome {
        NodeManagementResponseOutcomeV1::Status => {
            let status = status.ok_or(NodeManagementProtocolError::InvalidResponseShape)?;
            let current_cursor = fields
                .current
                .status_cursor
                .ok_or(NodeManagementProtocolError::InvalidResponseShape)?;
            if !target_is_current
                || status.node_id() != fields.target.node_id()
                || status.management_endpoint_ref() != fields.target.management_endpoint_ref()
                || status.node_incarnation() != fields.current.node_incarnation
                || status.registration_epoch() != fields.current.registration_epoch.get()
                || status.status_sequence() != current_cursor.status_sequence()
                || status.status_digest() != current_cursor.status_digest()
                || fields.request_kind == NodeManagementRequestKindV1::Watch
                    && status.status_sequence()
                        <= fields
                            .request_cursor
                            .ok_or(NodeManagementProtocolError::InvalidRequestShape)?
                            .status_sequence()
            {
                return Err(NodeManagementProtocolError::CorrelationMismatch);
            }
        }
        NodeManagementResponseOutcomeV1::NotModified => {
            let request_cursor = fields
                .request_cursor
                .ok_or(NodeManagementProtocolError::InvalidResponseShape)?;
            if status.is_some()
                || fields.request_kind != NodeManagementRequestKindV1::Watch
                || !target_is_current
                || fields.current.status_cursor != Some(request_cursor)
            {
                return Err(NodeManagementProtocolError::InvalidResponseShape);
            }
        }
        NodeManagementResponseOutcomeV1::NotFound => {
            if status.is_some() || !target_is_current || fields.current.status_cursor.is_some() {
                return Err(NodeManagementProtocolError::InvalidResponseShape);
            }
        }
        NodeManagementResponseOutcomeV1::Fenced => {
            if status.is_some() || target_is_current {
                return Err(NodeManagementProtocolError::InvalidResponseShape);
            }
        }
        NodeManagementResponseOutcomeV1::CursorConflict => {
            let request_cursor = fields
                .request_cursor
                .ok_or(NodeManagementProtocolError::InvalidResponseShape)?;
            let current_cursor = fields
                .current
                .status_cursor
                .ok_or(NodeManagementProtocolError::InvalidResponseShape)?;
            let conflicts = current_cursor.status_sequence() < request_cursor.status_sequence()
                || current_cursor.status_sequence() == request_cursor.status_sequence()
                    && current_cursor.status_digest() != request_cursor.status_digest();
            if status.is_some()
                || fields.request_kind != NodeManagementRequestKindV1::Watch
                || !target_is_current
                || !conflicts
            {
                return Err(NodeManagementProtocolError::InvalidResponseShape);
            }
        }
    }
    Ok(())
}

fn encode_request(
    request_id: [u8; 16],
    target: NodeManagementTargetV1,
    kind: NodeManagementRequestKindV1,
    cursor: Option<NodeStatusCursorV1>,
) -> Result<Vec<u8>, NodeManagementProtocolError> {
    let mut frame = vec![0; REQUEST_HEADER_BYTES];
    frame[..4].copy_from_slice(REQUEST_MAGIC);
    frame[4..6].copy_from_slice(&crate::NODE_MANAGEMENT_PROTOCOL_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(
        &u16::try_from(REQUEST_HEADER_BYTES)
            .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    frame[8..12].copy_from_slice(
        &u32::try_from(REQUEST_HEADER_BYTES)
            .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    frame[12] = kind as u8;
    frame[16..32].copy_from_slice(&request_id);
    frame[32..48].copy_from_slice(target.node_id().as_bytes());
    frame[48..64].copy_from_slice(target.management_endpoint_ref().as_bytes());
    frame[64..80].copy_from_slice(target.node_incarnation().as_bytes());
    frame[80..88].copy_from_slice(&target.registration_epoch().to_be_bytes());
    if let Some(cursor) = cursor {
        frame[88..96].copy_from_slice(&cursor.status_sequence().to_be_bytes());
        frame[96..128].copy_from_slice(cursor.status_digest().as_bytes());
    }
    let digest = request_digest(&frame[..REQUEST_DIGEST_OFFSET])?;
    frame[REQUEST_DIGEST_OFFSET..REQUEST_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    Ok(frame)
}

fn encode_response(
    fields: ResponseBuildFields,
    payload: &[u8],
) -> Result<Vec<u8>, NodeManagementProtocolError> {
    let total_length = RESPONSE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(NodeManagementProtocolError::InvalidFrameLength)?;
    if total_length > MAX_NODE_MANAGEMENT_RESPONSE_BYTES {
        return Err(NodeManagementProtocolError::InvalidFrameLength);
    }
    let mut frame = vec![0; total_length];
    frame[..4].copy_from_slice(RESPONSE_MAGIC);
    frame[4..6].copy_from_slice(&crate::NODE_MANAGEMENT_PROTOCOL_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(
        &u16::try_from(RESPONSE_HEADER_BYTES)
            .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    frame[8..12].copy_from_slice(
        &u32::try_from(total_length)
            .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    frame[12..16].copy_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| NodeManagementProtocolError::InvalidFrameLength)?
            .to_be_bytes(),
    );
    frame[16] = fields.outcome as u8;
    frame[17] = fields.request_kind as u8;
    frame[24..40].copy_from_slice(&fields.request_id);
    frame[40..56].copy_from_slice(fields.target.node_id().as_bytes());
    frame[56..72].copy_from_slice(fields.target.management_endpoint_ref().as_bytes());
    frame[72..88].copy_from_slice(fields.target.node_incarnation().as_bytes());
    frame[88..96].copy_from_slice(&fields.target.registration_epoch().to_be_bytes());
    if let Some(cursor) = fields.request_cursor {
        frame[96..104].copy_from_slice(&cursor.status_sequence().to_be_bytes());
        frame[104..136].copy_from_slice(cursor.status_digest().as_bytes());
    }
    frame[136..168].copy_from_slice(fields.request_digest.as_bytes());
    frame[168..184].copy_from_slice(fields.current.node_incarnation.as_bytes());
    frame[184..192].copy_from_slice(&fields.current.registration_epoch.get().to_be_bytes());
    if let Some(cursor) = fields.current.status_cursor {
        frame[192..200].copy_from_slice(&cursor.status_sequence().to_be_bytes());
        frame[200..232].copy_from_slice(cursor.status_digest().as_bytes());
    }
    frame[RESPONSE_HEADER_BYTES..].copy_from_slice(payload);
    let digest = response_digest(
        &frame[..RESPONSE_DIGEST_OFFSET],
        &frame[RESPONSE_HEADER_BYTES..],
    )?;
    frame[RESPONSE_DIGEST_OFFSET..RESPONSE_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    Ok(frame)
}

pub(crate) fn encode_status_payload(
    status: &NodeStatusV1,
) -> Result<Vec<u8>, NodeManagementProtocolError> {
    if status.runtime_hosts().len() > MAX_RUNTIME_HOSTS_PER_NODE {
        return Err(NodeManagementProtocolError::InvalidResponseShape);
    }
    let route_bytes = status.runtime_hosts().iter().try_fold(
        0usize,
        |total, runtime| -> Result<usize, NodeManagementProtocolError> {
            let length = runtime.apply_endpoint().route().len();
            if length > MAX_RUNTIME_ROUTE_BYTES {
                return Err(NodeManagementProtocolError::InvalidResponseShape);
            }
            total
                .checked_add(length)
                .ok_or(NodeManagementProtocolError::InvalidFrameLength)
        },
    )?;
    let fixed_runtime_bytes = RUNTIME_STATUS_FIXED_BYTES
        .checked_mul(status.runtime_hosts().len())
        .ok_or(NodeManagementProtocolError::InvalidFrameLength)?;
    let total = STATUS_FIXED_BYTES
        .checked_add(fixed_runtime_bytes)
        .and_then(|length| length.checked_add(route_bytes))
        .ok_or(NodeManagementProtocolError::InvalidFrameLength)?;
    if total > MAX_NODE_STATUS_PAYLOAD_BYTES {
        return Err(NodeManagementProtocolError::InvalidFrameLength);
    }
    let mut payload = vec![0; STATUS_FIXED_BYTES];
    payload[..16].copy_from_slice(status.node_id().as_bytes());
    payload[16..32].copy_from_slice(status.node_incarnation().as_bytes());
    payload[32..40].copy_from_slice(&status.registration_epoch().to_be_bytes());
    payload[40..48].copy_from_slice(&status.status_sequence().to_be_bytes());
    payload[48..56].copy_from_slice(&status.freshness_budget_nanos().to_be_bytes());
    payload[56..72].copy_from_slice(status.management_endpoint_ref().as_bytes());
    let feature = status.feature_report();
    payload[72..80].copy_from_slice(&feature.report_sequence().to_be_bytes());
    payload[80] = feature.operating_system() as u8;
    payload[81] = feature.architecture() as u8;
    payload[82..84].copy_from_slice(&feature.runtime_contract_version().to_be_bytes());
    payload[84..86].copy_from_slice(&feature.fabric_contract_version().to_be_bytes());
    payload[86] = u8::try_from(status.runtime_hosts().len())
        .map_err(|_| NodeManagementProtocolError::InvalidResponseShape)?;
    if let Some(valid_until_unix_nanos) = status.valid_until_unix_nanos() {
        payload[87] = 1;
        payload[88..96].copy_from_slice(&valid_until_unix_nanos.to_be_bytes());
    }
    payload[96..128].copy_from_slice(feature.platform_profile_digest().as_bytes());
    for runtime in status.runtime_hosts() {
        let endpoint = runtime.apply_endpoint();
        let route = endpoint.route().as_bytes();
        let mut record = vec![0; RUNTIME_STATUS_FIXED_BYTES];
        record[..16].copy_from_slice(runtime.runtime_host_id().as_bytes());
        record[16..24].copy_from_slice(&runtime.runtime_host_epoch().to_be_bytes());
        record[24..32].copy_from_slice(&runtime.observation_sequence().to_be_bytes());
        record[32] = runtime.liveness() as u8;
        record[33] = endpoint.transport() as u8;
        record[34..36].copy_from_slice(
            &u16::try_from(route.len())
                .map_err(|_| NodeManagementProtocolError::InvalidResponseShape)?
                .to_be_bytes(),
        );
        record[36..52].copy_from_slice(endpoint.endpoint_ref().as_bytes());
        record[52..60].copy_from_slice(&endpoint.endpoint_generation().to_be_bytes());
        record[60..76].copy_from_slice(&endpoint.runtime_response_key_ref());
        record[76..108].copy_from_slice(&endpoint.runtime_response_public_key());
        payload.extend_from_slice(&record);
        payload.extend_from_slice(route);
    }
    debug_assert_eq!(payload.len(), total);
    Ok(payload)
}

pub(crate) fn decode_status_payload(
    payload: &[u8],
) -> Result<NodeStatusV1, NodeManagementProtocolError> {
    if payload.len() < STATUS_FIXED_BYTES || payload.len() > MAX_NODE_STATUS_PAYLOAD_BYTES {
        return Err(NodeManagementProtocolError::InvalidFrameLength);
    }
    if payload[87] > 1
        || (payload[87] == 0 && payload[88..96].iter().any(|byte| *byte != 0))
        || (payload[87] == 1 && read_u64(&payload[88..96]) == 0)
    {
        return Err(NodeManagementProtocolError::NonCanonicalEncoding);
    }
    let node_id = NodeId::try_from_bytes(read_array::<16>(&payload[..16]))
        .map_err(NodeManagementProtocolError::StatusRejected)?;
    let node_incarnation = NodeIncarnation::try_from_bytes(read_array::<16>(&payload[16..32]))
        .map_err(NodeManagementProtocolError::StatusRejected)?;
    let tenure =
        NodeRegistrationTenureV1::try_new(node_id, read_u64(&payload[32..40]), node_incarnation)
            .map_err(NodeManagementProtocolError::StatusRejected)?;
    let feature_report = NodeFeatureReportV1::try_new(NodeFeatureReportInputV1 {
        node_id,
        node_incarnation,
        report_sequence: read_u64(&payload[72..80]),
        operating_system: decode_operating_system(payload[80])?,
        architecture: decode_architecture(payload[81])?,
        platform_profile_digest: Digest32::from_bytes(read_array::<32>(&payload[96..128])),
        runtime_contract_version: read_u16(&payload[82..84]),
        fabric_contract_version: read_u16(&payload[84..86]),
    })
    .map_err(NodeManagementProtocolError::StatusRejected)?;
    let runtime_count = usize::from(payload[86]);
    if runtime_count > MAX_RUNTIME_HOSTS_PER_NODE {
        return Err(NodeManagementProtocolError::InvalidResponseShape);
    }
    let mut runtime_hosts = Vec::with_capacity(runtime_count);
    let mut offset = STATUS_FIXED_BYTES;
    for _ in 0..runtime_count {
        let record_end = offset
            .checked_add(RUNTIME_STATUS_FIXED_BYTES)
            .ok_or(NodeManagementProtocolError::InvalidFrameLength)?;
        let record = payload
            .get(offset..record_end)
            .ok_or(NodeManagementProtocolError::InvalidFrameLength)?;
        let route_length = usize::from(read_u16(&record[34..36]));
        if route_length > MAX_RUNTIME_ROUTE_BYTES {
            return Err(NodeManagementProtocolError::InvalidResponseShape);
        }
        let route_end = record_end
            .checked_add(route_length)
            .ok_or(NodeManagementProtocolError::InvalidFrameLength)?;
        let route_bytes = payload
            .get(record_end..route_end)
            .ok_or(NodeManagementProtocolError::InvalidFrameLength)?;
        let route = core::str::from_utf8(route_bytes)
            .map_err(|_| NodeManagementProtocolError::NonCanonicalEncoding)?;
        let runtime_host_id = RuntimeHostId::from_bytes(read_array::<16>(&record[..16]));
        let transport = decode_apply_transport(record[33])?;
        if transport != RuntimeApplyTransportV1::RestrictedZenohQuery {
            return Err(NodeManagementProtocolError::UnknownEnumValue);
        }
        let endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
            RuntimeApplyEndpointRefV1::try_from_bytes(read_array::<16>(&record[36..52]))
                .map_err(NodeManagementProtocolError::StatusRejected)?,
            runtime_host_id,
            read_u64(&record[52..60]),
            route,
            read_array::<16>(&record[60..76]),
            read_array::<32>(&record[76..108]),
        )
        .map_err(NodeManagementProtocolError::StatusRejected)?;
        runtime_hosts.push(
            RuntimeHostStatusV1::try_new(
                read_u64(&record[16..24]),
                read_u64(&record[24..32]),
                decode_runtime_liveness(record[32])?,
                endpoint,
            )
            .map_err(NodeManagementProtocolError::StatusRejected)?,
        );
        offset = route_end;
    }
    if offset != payload.len() {
        return Err(NodeManagementProtocolError::NonCanonicalEncoding);
    }
    let input = NodeStatusInputV1 {
        tenure,
        status_sequence: read_u64(&payload[40..48]),
        freshness_budget_nanos: read_u64(&payload[48..56]),
        management_endpoint_ref: NodeManagementEndpointRefV1::try_from_bytes(read_array::<16>(
            &payload[56..72],
        ))
        .map_err(NodeManagementProtocolError::StatusRejected)?,
        feature_report,
        runtime_hosts,
    };
    if payload[87] == 1 {
        NodeStatusV1::try_new_with_valid_until_unix_nanos(input, read_u64(&payload[88..96]))
    } else {
        NodeStatusV1::try_new(input)
    }
    .map_err(NodeManagementProtocolError::StatusRejected)
}

fn decode_operating_system(
    value: u8,
) -> Result<NodeOperatingSystemV1, NodeManagementProtocolError> {
    match value {
        1 => Ok(NodeOperatingSystemV1::Linux),
        2 => Ok(NodeOperatingSystemV1::MacOs),
        3 => Ok(NodeOperatingSystemV1::Windows),
        _ => Err(NodeManagementProtocolError::UnknownEnumValue),
    }
}

fn decode_architecture(value: u8) -> Result<NodeArchitectureV1, NodeManagementProtocolError> {
    match value {
        1 => Ok(NodeArchitectureV1::X86_64),
        2 => Ok(NodeArchitectureV1::Aarch64),
        _ => Err(NodeManagementProtocolError::UnknownEnumValue),
    }
}

fn decode_apply_transport(
    value: u8,
) -> Result<RuntimeApplyTransportV1, NodeManagementProtocolError> {
    match value {
        1 => Ok(RuntimeApplyTransportV1::RestrictedZenohQuery),
        _ => Err(NodeManagementProtocolError::UnknownEnumValue),
    }
}

fn decode_runtime_liveness(
    value: u8,
) -> Result<RuntimeHostLivenessV1, NodeManagementProtocolError> {
    match value {
        1 => Ok(RuntimeHostLivenessV1::Bootstrapping),
        2 => Ok(RuntimeHostLivenessV1::Live),
        3 => Ok(RuntimeHostLivenessV1::Unresponsive),
        4 => Ok(RuntimeHostLivenessV1::Exited),
        5 => Ok(RuntimeHostLivenessV1::Quarantined),
        _ => Err(NodeManagementProtocolError::UnknownEnumValue),
    }
}

fn request_digest(header: &[u8]) -> Result<Digest32, NodeManagementProtocolError> {
    let mut builder = Digest32Builder::try_new(REQUEST_DIGEST_DOMAIN)
        .map_err(|_| NodeManagementProtocolError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .map_err(|_| NodeManagementProtocolError::DigestEncodingFailed)?;
    Ok(builder.finish())
}

fn response_digest(header: &[u8], payload: &[u8]) -> Result<Digest32, NodeManagementProtocolError> {
    let mut builder = Digest32Builder::try_new(RESPONSE_DIGEST_DOMAIN)
        .map_err(|_| NodeManagementProtocolError::DigestEncodingFailed)?;
    builder
        .field_bytes(header)
        .and_then(|value| value.field_bytes(payload))
        .map_err(|_| NodeManagementProtocolError::DigestEncodingFailed)?;
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

/// Stable strict-codec, correlation, and nested-contract failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeManagementProtocolError {
    ZeroRequestId,
    ZeroRegistrationEpoch,
    ZeroStatusDigest,
    InvalidRequestShape,
    InvalidResponseShape,
    InvalidFrameLength,
    UnsupportedFrame,
    UnknownEnumValue,
    DigestMismatch,
    CorrelationMismatch,
    NonCanonicalEncoding,
    TargetMismatch,
    UnsupportedCarrierKind,
    InvalidCarrierShape,
    InvalidCarrierPayload,
    InvalidCarrierAuthentication,
    #[cfg(unix)]
    ObservationRejected(RuntimeObservationError),
    StatusRejected(NodeContractError),
    DigestEncodingFailed,
}

impl fmt::Display for NodeManagementProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRequestId => formatter.write_str("Node request identity is zero"),
            Self::ZeroRegistrationEpoch => formatter.write_str("Node registration epoch is zero"),
            Self::ZeroStatusDigest => formatter.write_str("Node status digest is zero"),
            Self::InvalidRequestShape => formatter.write_str("invalid Node request shape"),
            Self::InvalidResponseShape => formatter.write_str("invalid Node response shape"),
            Self::InvalidFrameLength => formatter.write_str("invalid Node management frame length"),
            Self::UnsupportedFrame => formatter.write_str("unsupported Node management frame"),
            Self::UnknownEnumValue => formatter.write_str("unknown Node management enum value"),
            Self::DigestMismatch => formatter.write_str("Node management digest mismatch"),
            Self::CorrelationMismatch => {
                formatter.write_str("Node management correlation mismatch")
            }
            Self::NonCanonicalEncoding => {
                formatter.write_str("non-canonical Node management encoding")
            }
            Self::TargetMismatch => formatter.write_str("Node management target mismatch"),
            Self::UnsupportedCarrierKind => {
                formatter.write_str("unsupported Node control carrier kind")
            }
            Self::InvalidCarrierShape => formatter.write_str("invalid Node control carrier shape"),
            Self::InvalidCarrierPayload => {
                formatter.write_str("invalid Node control carrier payload")
            }
            Self::InvalidCarrierAuthentication => {
                formatter.write_str("invalid Node control carrier authentication")
            }
            #[cfg(unix)]
            Self::ObservationRejected(error) => {
                write!(formatter, "Runtime observation rejected: {error}")
            }
            Self::StatusRejected(error) => write!(formatter, "NodeStatus rejected: {error}"),
            Self::DigestEncodingFailed => {
                formatter.write_str("Node management digest encoding failed")
            }
        }
    }
}

impl std::error::Error for NodeManagementProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StatusRejected(error) => Some(error),
            #[cfg(unix)]
            Self::ObservationRejected(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod control_carrier_tests {
    use super::*;

    fn target() -> NodeManagementTargetV1 {
        NodeManagementTargetV1::try_new(
            NodeId::try_from_bytes([0x11; 16]).expect("NodeId"),
            NodeManagementEndpointRefV1::try_from_bytes([0x12; 16]).expect("management endpoint"),
            NodeIncarnation::try_from_bytes([0x13; 16]).expect("incarnation"),
            7,
        )
        .expect("target")
    }

    fn auth(nonce: &[u8]) -> ApplyRequestAuthClaim {
        ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([0x21; 16]),
            ApplyAuthKeyRef::from_bytes([0x22; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
            nonce,
        )
        .expect("auth")
    }

    fn describe() -> NodeControlCarrierRequestV1 {
        NodeControlCarrierRequestDraftV1::try_describe([0x31; 16], auth(&[0x32; 32]))
            .expect("Describe draft")
            .finalize(&[0x33; 64])
            .expect("Describe")
    }

    #[test]
    fn pxnr_describe_has_no_fabricated_target_and_pxne_returns_the_current_target() {
        let request = describe();
        assert_eq!(&request.canonical_wire()[..6], b"PXNR\0\x01");
        assert_eq!(request.canonical_wire().len(), 280);
        assert_eq!(request.kind(), NodeControlCarrierKindV1::Describe);
        assert_eq!(request.target(), None);
        assert_eq!(request.node_id(), None);
        assert_eq!(&request.canonical_wire()[8..10], &[0, 0]);
        assert!(
            request.canonical_wire()[32..88]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            NodeControlCarrierRequestV1::decode(request.canonical_wire())
                .expect("strict Describe round trip"),
            request
        );
        let authenticated = request
            .verify_controller_carrier(
                PrincipalRef::from_bytes([0x21; 16]),
                ApplyAuthKeyRef::from_bytes([0x22; 16]),
                Digest32::from_bytes([0x23; 32]),
                |principal, key, fingerprint, transcript, signature| {
                    assert_eq!(principal, PrincipalRef::from_bytes([0x21; 16]));
                    assert_eq!(key, ApplyAuthKeyRef::from_bytes([0x22; 16]));
                    assert_eq!(fingerprint, Digest32::from_bytes([0x23; 32]));
                    assert!(!transcript.is_empty());
                    signature == [0x33; 64]
                },
            )
            .expect("authenticated Describe");
        assert_eq!(authenticated.kind(), NodeControlCarrierKindV1::Describe);

        let response = NodeControlDescribeResponseDraftV1::try_describe(&request, target())
            .expect("Describe response draft")
            .finalize()
            .expect("Describe response");
        assert_eq!(&response.canonical_wire()[..6], b"PXNE\0\x01");
        assert_eq!(response.canonical_wire().len(), 320);
        assert_eq!(response.kind(), NodeControlDescribeResponseKindV1::Describe);
        response.validate_for(&request).expect("exact correlation");
        assert_eq!(
            NodeControlDescribeResponseV1::decode(response.canonical_wire())
                .expect("strict PXNE round trip"),
            response
        );

        let mut nonzero_absent_target = request.canonical_wire().to_vec();
        nonzero_absent_target[32] = 1;
        assert_eq!(
            NodeControlCarrierRequestV1::decode(&nonzero_absent_target),
            Err(NodeManagementProtocolError::NonCanonicalEncoding)
        );
        let mut payload_digest_tamper = request.canonical_wire().to_vec();
        payload_digest_tamper[112] = 1;
        assert_eq!(
            NodeControlCarrierRequestV1::decode(&payload_digest_tamper),
            Err(NodeManagementProtocolError::DigestMismatch)
        );
    }

    #[test]
    fn pxnr_latest_and_watch_retain_exact_frozen_pxnq_and_reject_cross_kind() {
        let target = target();
        let latest_inner =
            NodeManagementRequestV1::try_latest([0x41; 16], target).expect("Latest PXNQ");
        let latest = NodeControlCarrierRequestDraftV1::try_latest(
            [0x41; 16],
            target,
            latest_inner.clone(),
            auth(&[0x42; 32]),
        )
        .expect("Latest carrier draft")
        .finalize(&[0x43; 64])
        .expect("Latest carrier");
        assert_eq!(
            latest
                .management_request()
                .expect("PXNQ payload")
                .canonical_wire(),
            latest_inner.canonical_wire()
        );
        assert_eq!(
            NodeControlCarrierRequestV1::decode(latest.canonical_wire())
                .expect("Latest round trip"),
            latest
        );

        let cursor =
            NodeStatusCursorV1::try_new(5, Digest32::from_bytes([0x44; 32])).expect("cursor");
        let watch_inner =
            NodeManagementRequestV1::try_watch([0x45; 16], target, cursor).expect("Watch PXNQ");
        let watch = NodeControlCarrierRequestDraftV1::try_watch(
            [0x45; 16],
            target,
            watch_inner.clone(),
            auth(&[0x46; 32]),
        )
        .expect("Watch carrier draft")
        .finalize(&[0x47; 64])
        .expect("Watch carrier");
        assert_eq!(
            watch
                .management_request()
                .expect("Watch payload")
                .canonical_wire(),
            watch_inner.canonical_wire()
        );

        assert_eq!(
            NodeControlCarrierRequestDraftV1::try_watch(
                [0x41; 16],
                target,
                latest_inner,
                auth(&[0x48; 32]),
            ),
            Err(NodeManagementProtocolError::InvalidCarrierShape)
        );
        let mut cross_kind = latest.canonical_wire().to_vec();
        cross_kind[6..8].copy_from_slice(&(NodeControlCarrierKindV1::Watch as u16).to_be_bytes());
        assert!(NodeControlCarrierRequestV1::decode(&cross_kind).is_err());
        let mut publish_kind = latest.canonical_wire().to_vec();
        publish_kind[6..8].copy_from_slice(
            &(NodeControlCarrierKindV1::PublishRuntimeObservation as u16).to_be_bytes(),
        );
        assert!(NodeControlCarrierRequestV1::decode(&publish_kind).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn pxnr_observation_challenge_and_pxne_echo_all_ephemeral_facts() {
        let target = target();
        let request = NodeControlCarrierRequestDraftV1::try_observation_challenge(
            [0x51; 16],
            target,
            RuntimeHostId::from_bytes([0x52; 16]),
            5_000_000_000,
            auth(&[0x53; 32]),
        )
        .expect("challenge request draft")
        .finalize(&[0x54; 64])
        .expect("challenge request");
        assert_eq!(
            request.kind(),
            NodeControlCarrierKindV1::ObservationChallenge
        );
        assert_eq!(
            NodeControlCarrierRequestV1::decode(request.canonical_wire())
                .expect("challenge request round trip"),
            request
        );
        let challenge =
            NodeControlObservationChallengeV1::try_new(NodeControlObservationChallengeFieldsV1 {
                observation_endpoint_ref: RuntimeObservationEndpointRefV1::try_from_bytes(
                    [0x55; 16],
                )
                .expect("observation endpoint"),
                runtime_host_id: RuntimeHostId::from_bytes([0x52; 16]),
                authority_digest: Digest32::from_bytes([0x56; 32]),
                intended_status_sequence: 9,
                freshness_budget_nanos: 5_000_000_000,
                issued_at_unix_nanos: 10_000_000_000,
                expires_at_unix_nanos: 15_000_000_000,
                query_nonce: Digest32::from_bytes([0x57; 32]),
            })
            .expect("challenge facts");
        let response =
            NodeControlDescribeResponseDraftV1::try_observation_challenge(&request, challenge)
                .expect("challenge response draft")
                .finalize()
                .expect("challenge response");
        response
            .validate_for(&request)
            .expect("challenge correlation");
        let decoded = NodeControlDescribeResponseV1::decode(response.canonical_wire())
            .expect("strict challenge PXNE");
        assert_eq!(decoded, response);
        assert_eq!(decoded.observation_challenge(), Some(challenge));
        assert_eq!(
            decoded.request_nonce(),
            request.authentication().claim().nonce()
        );

        let mut tampered = response.canonical_wire().to_vec();
        tampered[224] ^= 1;
        assert_eq!(
            NodeControlDescribeResponseV1::decode(&tampered),
            Err(NodeManagementProtocolError::DigestMismatch)
        );
    }

    #[test]
    fn pxnr_rejects_reserved_unknown_apply_and_agent_frames() {
        let request = describe();
        let mut reserved = request.canonical_wire().to_vec();
        reserved[10] = 1;
        assert_eq!(
            NodeControlCarrierRequestV1::decode(&reserved),
            Err(NodeManagementProtocolError::UnsupportedFrame)
        );
        let mut unknown = request.canonical_wire().to_vec();
        unknown[6..8].copy_from_slice(&99_u16.to_be_bytes());
        assert_eq!(
            NodeControlCarrierRequestV1::decode(&unknown),
            Err(NodeManagementProtocolError::UnsupportedCarrierKind)
        );
        for magic in [b"PXRC", b"PXAR", b"PXAI"] {
            let mut forbidden = request.canonical_wire().to_vec();
            forbidden[..4].copy_from_slice(magic);
            assert_eq!(
                NodeControlCarrierRequestV1::decode(&forbidden),
                Err(NodeManagementProtocolError::UnsupportedFrame)
            );
        }
    }
}
