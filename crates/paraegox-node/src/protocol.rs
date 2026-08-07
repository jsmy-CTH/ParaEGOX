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
    identity::RuntimeHostId,
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
            _ => None,
        }
    }
}
