//! Canonical target assignments carried beside the authenticated apply envelope.
//!
//! The existing B2 envelope authenticates the target-assignment digest. This
//! module supplies the canonical assignment body committed by that digest and
//! a strict outer request frame. It does not define a live binding, payload
//! queue, transport, clock reader, or RuntimeHost.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::time::BoundedDuration;

use crate::provenance::{ProvenanceContractError, RuntimeSliceCommitment, TargetAssignmentDigest};
use crate::wire::{
    EnvelopeContractError, MAX_RUNTIME_APPLY_ENVELOPE_BYTES, RuntimeApplyEnvelope, WireError,
};

/// Version of the canonical target-assignment body.
pub const TARGET_ASSIGNMENTS_VERSION: u16 = 1;
/// Maximum number of binding assignments in one target body.
pub const MAX_TARGET_ASSIGNMENTS: usize = 256;
/// Version of the complete apply-request outer frame.
pub const RUNTIME_APPLY_REQUEST_VERSION: u16 = 1;

const TARGET_ASSIGNMENTS_MAGIC: &[u8; 4] = b"PXTA";
const RUNTIME_APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const TARGET_ASSIGNMENTS_HEADER_BYTES: usize = 10;
const APPLY_REQUEST_HEADER_BYTES: usize = 14;
const TARGET_ASSIGNMENT_RECORD_BYTES: usize = 256;
const TARGET_ASSIGNMENTS_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.target-assignments.sha256.v1";

/// Maximum canonical byte length of one target-assignment body.
pub const MAX_TARGET_ASSIGNMENTS_BYTES: usize =
    TARGET_ASSIGNMENTS_HEADER_BYTES + MAX_TARGET_ASSIGNMENTS * TARGET_ASSIGNMENT_RECORD_BYTES;
/// Maximum canonical byte length of a complete apply request.
pub const MAX_RUNTIME_APPLY_REQUEST_BYTES: usize =
    APPLY_REQUEST_HEADER_BYTES + MAX_RUNTIME_APPLY_ENVELOPE_BYTES + MAX_TARGET_ASSIGNMENTS_BYTES;

macro_rules! opaque_ref {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates an opaque reference from its canonical bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Returns the canonical reference bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_ref!(
    BindingId,
    "Stable identity of one compiled logical binding."
);
opaque_ref!(
    InstanceRef,
    "Runtime-consumer-owned reference to one assigned instance."
);
opaque_ref!(PortRef, "Opaque reference to one assigned instance port.");
opaque_ref!(
    MailboxRef,
    "Opaque reference to the target semantic admission boundary."
);

/// Exact resolved schema identity, version, and content commitment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SchemaRef {
    id: [u8; 16],
    version: u32,
    content_digest: Digest32,
}

impl SchemaRef {
    /// Creates an exact resolved schema reference with a nonzero version.
    pub const fn try_new(
        id: [u8; 16],
        version: u32,
        content_digest: Digest32,
    ) -> Result<Self, AssignmentContractError> {
        if version == 0 {
            return Err(AssignmentContractError::InvalidSchemaVersion);
        }
        Ok(Self {
            id,
            version,
            content_digest,
        })
    }

    /// Returns the opaque schema identity bytes.
    #[must_use]
    pub const fn id_bytes(&self) -> &[u8; 16] {
        &self.id
    }

    /// Returns the nonzero resolved schema version.
    #[must_use]
    pub const fn version(self) -> u32 {
        self.version
    }

    /// Returns the exact schema-content digest.
    #[must_use]
    pub const fn content_digest(&self) -> &Digest32 {
        &self.content_digest
    }
}

/// Direction of data relative to an assigned instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PortDirection {
    /// Data leaves the source instance.
    Out = 1,
    /// Data enters the target instance.
    In = 2,
}

/// Interaction kinds admitted by the first static 1:1 assignment contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InteractionKind {
    /// Replaceable sampled or reference-value delivery.
    Signal = 1,
    /// Immutable fact delivery.
    Event = 2,
}

/// Cardinality admitted by the first assignment contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PortCardinality {
    /// Exactly one peer endpoint.
    One = 1,
}

/// Immutable resolved contract for one assignment endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PortSpec {
    direction: PortDirection,
    schema: SchemaRef,
    interaction: InteractionKind,
    cardinality: PortCardinality,
}

impl PortSpec {
    /// Creates an exact, transport-neutral endpoint contract.
    #[must_use]
    pub const fn new(
        direction: PortDirection,
        schema: SchemaRef,
        interaction: InteractionKind,
        cardinality: PortCardinality,
    ) -> Self {
        Self {
            direction,
            schema,
            interaction,
            cardinality,
        }
    }

    /// Returns the endpoint direction.
    #[must_use]
    pub const fn direction(self) -> PortDirection {
        self.direction
    }

    /// Returns the exact resolved schema.
    #[must_use]
    pub const fn schema(self) -> SchemaRef {
        self.schema
    }

    /// Returns the interaction kind.
    #[must_use]
    pub const fn interaction(self) -> InteractionKind {
        self.interaction
    }

    /// Returns the only admitted cardinality.
    #[must_use]
    pub const fn cardinality(self) -> PortCardinality {
        self.cardinality
    }
}

/// Explicit pressure behavior requested by a compiled delivery assignment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum OverflowPolicy {
    /// Reject the arriving message without displacing admitted work.
    RejectNew = 1,
    /// Admit the arriving message and terminate the oldest queued message.
    DropOldest = 2,
    /// Keep only the latest queued Signal for this static binding.
    Latest = 3,
    /// Coalesce queued Signals by a validated, bounded semantic key.
    CoalesceByKey = 4,
    /// Wait only within an explicit caller-owned deadline.
    BlockUntilDeadline = 5,
}

/// Link-owned delivery intent retained in the compiled assignment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeliveryProfile {
    max_payload_bytes: u64,
    max_message_age: BoundedDuration,
    overflow_policy: OverflowPolicy,
}

impl DeliveryProfile {
    /// Builds a bounded delivery profile.
    pub fn try_new(
        max_payload_bytes: u64,
        max_message_age: BoundedDuration,
        overflow_policy: OverflowPolicy,
    ) -> Result<Self, AssignmentContractError> {
        if max_payload_bytes == 0 {
            return Err(AssignmentContractError::InvalidMaxPayloadBytes);
        }
        if max_message_age.value() == 0 {
            return Err(AssignmentContractError::InvalidMaxMessageAge);
        }
        Ok(Self {
            max_payload_bytes,
            max_message_age,
            overflow_policy,
        })
    }

    /// Returns the maximum immutable payload size admitted by the link.
    #[must_use]
    pub const fn max_payload_bytes(self) -> u64 {
        self.max_payload_bytes
    }

    /// Returns the maximum age admitted by the delivery contract.
    #[must_use]
    pub const fn max_message_age(self) -> BoundedDuration {
        self.max_message_age
    }

    /// Returns the explicit pressure behavior.
    #[must_use]
    pub const fn overflow_policy(self) -> OverflowPolicy {
        self.overflow_policy
    }
}

/// Compiled bounds for the target Mailbox and its adjacent ownership budgets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MailboxSpec {
    capacity_items: u32,
    capacity_bytes: u64,
    max_queue_age: BoundedDuration,
    max_inflight: u32,
    max_retained_bytes: u64,
    overflow_policy: OverflowPolicy,
}

impl MailboxSpec {
    /// Builds an items/bytes/age/inflight/retained-byte bounded specification.
    pub const fn try_new(
        capacity_items: u32,
        capacity_bytes: u64,
        max_queue_age: BoundedDuration,
        max_inflight: u32,
        max_retained_bytes: u64,
        overflow_policy: OverflowPolicy,
    ) -> Result<Self, AssignmentContractError> {
        if capacity_items == 0 {
            return Err(AssignmentContractError::InvalidMailboxItemCapacity);
        }
        if capacity_bytes == 0 {
            return Err(AssignmentContractError::InvalidMailboxByteCapacity);
        }
        if max_queue_age.value() == 0 {
            return Err(AssignmentContractError::InvalidMailboxAge);
        }
        if max_inflight == 0 {
            return Err(AssignmentContractError::InvalidMailboxInflightCapacity);
        }
        if max_retained_bytes == 0 {
            return Err(AssignmentContractError::InvalidMailboxRetainedByteCapacity);
        }
        Ok(Self {
            capacity_items,
            capacity_bytes,
            max_queue_age,
            max_inflight,
            max_retained_bytes,
            overflow_policy,
        })
    }

    /// Returns the queued-item limit encoded as `u32` on wire.
    #[must_use]
    pub const fn capacity_items(self) -> u32 {
        self.capacity_items
    }

    /// Returns the queued-payload-byte limit encoded as `u64` on wire.
    #[must_use]
    pub const fn capacity_bytes(self) -> u64 {
        self.capacity_bytes
    }

    /// Returns the target-local maximum queue age.
    #[must_use]
    pub const fn max_queue_age(self) -> BoundedDuration {
        self.max_queue_age
    }

    /// Returns the adjacent execution outstanding limit encoded as `u32`.
    #[must_use]
    pub const fn max_inflight(self) -> u32 {
        self.max_inflight
    }

    /// Returns the retained-payload-byte limit encoded as `u64`.
    #[must_use]
    pub const fn max_retained_bytes(self) -> u64 {
        self.max_retained_bytes
    }

    /// Returns the compiled pressure behavior.
    #[must_use]
    pub const fn overflow_policy(self) -> OverflowPolicy {
        self.overflow_policy
    }
}

/// One resolved endpoint identity paired with its immutable Port contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PortEndpoint {
    instance: InstanceRef,
    port: PortRef,
    spec: PortSpec,
}

impl PortEndpoint {
    /// Creates a resolved assignment endpoint.
    #[must_use]
    pub const fn new(instance: InstanceRef, port: PortRef, spec: PortSpec) -> Self {
        Self {
            instance,
            port,
            spec,
        }
    }

    /// Returns the owning instance reference.
    #[must_use]
    pub const fn instance(self) -> InstanceRef {
        self.instance
    }

    /// Returns the instance-local port reference.
    #[must_use]
    pub const fn port(self) -> PortRef {
        self.port
    }

    /// Returns the exact resolved Port contract.
    #[must_use]
    pub const fn spec(self) -> PortSpec {
        self.spec
    }
}

/// One resolved static 1:1 binding assignment for a target RuntimeHost.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BindingAssignment {
    binding_id: BindingId,
    source_instance: InstanceRef,
    source_port: PortRef,
    source_spec: PortSpec,
    target_instance: InstanceRef,
    target_port: PortRef,
    target_spec: PortSpec,
    mailbox: MailboxRef,
    delivery: DeliveryProfile,
    mailbox_spec: MailboxSpec,
}

impl BindingAssignment {
    /// Validates the resolved endpoints and compiled Mailbox assignment.
    pub fn try_new(
        binding_id: BindingId,
        source: PortEndpoint,
        target: PortEndpoint,
        mailbox: MailboxRef,
        delivery: DeliveryProfile,
        mailbox_spec: MailboxSpec,
    ) -> Result<Self, AssignmentContractError> {
        let source_spec = source.spec();
        let target_spec = target.spec();
        if !matches!(source_spec.direction(), PortDirection::Out) {
            return Err(AssignmentContractError::InvalidSourceDirection);
        }
        if !matches!(target_spec.direction(), PortDirection::In) {
            return Err(AssignmentContractError::InvalidTargetDirection);
        }
        if source_spec.schema() != target_spec.schema() {
            return Err(AssignmentContractError::SchemaMismatch);
        }
        if source_spec.interaction() != target_spec.interaction() {
            return Err(AssignmentContractError::InteractionMismatch);
        }
        if delivery.overflow_policy() != mailbox_spec.overflow_policy() {
            return Err(AssignmentContractError::OverflowPolicyMismatch);
        }
        if mailbox_spec.max_queue_age().value() > delivery.max_message_age().value() {
            return Err(AssignmentContractError::QueueAgeExceedsDeliveryAge);
        }
        if mailbox_spec.capacity_bytes() < delivery.max_payload_bytes() {
            return Err(AssignmentContractError::MailboxCannotHoldPayload);
        }
        if mailbox_spec.max_retained_bytes() < mailbox_spec.capacity_bytes() {
            return Err(AssignmentContractError::MailboxCannotRetainCapacity);
        }
        if matches!(source_spec.interaction(), InteractionKind::Event)
            && !matches!(
                delivery.overflow_policy(),
                OverflowPolicy::RejectNew | OverflowPolicy::BlockUntilDeadline
            )
        {
            return Err(AssignmentContractError::EventCannotUseLossyOverflow);
        }
        Ok(Self {
            binding_id,
            source_instance: source.instance(),
            source_port: source.port(),
            source_spec,
            target_instance: target.instance(),
            target_port: target.port(),
            target_spec,
            mailbox,
            delivery,
            mailbox_spec,
        })
    }

    /// Returns the stable logical binding identity.
    #[must_use]
    pub const fn binding_id(self) -> BindingId {
        self.binding_id
    }

    /// Returns the source instance reference.
    #[must_use]
    pub const fn source_instance(self) -> InstanceRef {
        self.source_instance
    }

    /// Returns the source port reference.
    #[must_use]
    pub const fn source_port(self) -> PortRef {
        self.source_port
    }

    /// Returns the resolved source endpoint contract.
    #[must_use]
    pub const fn source_spec(self) -> PortSpec {
        self.source_spec
    }

    /// Returns the target instance reference.
    #[must_use]
    pub const fn target_instance(self) -> InstanceRef {
        self.target_instance
    }

    /// Returns the target port reference.
    #[must_use]
    pub const fn target_port(self) -> PortRef {
        self.target_port
    }

    /// Returns the resolved target endpoint contract.
    #[must_use]
    pub const fn target_spec(self) -> PortSpec {
        self.target_spec
    }

    /// Returns the target semantic Mailbox reference.
    #[must_use]
    pub const fn mailbox(self) -> MailboxRef {
        self.mailbox
    }

    /// Returns the Link-owned delivery profile.
    #[must_use]
    pub const fn delivery(self) -> DeliveryProfile {
        self.delivery
    }

    /// Returns the compiled target Mailbox specification.
    #[must_use]
    pub const fn mailbox_spec(self) -> MailboxSpec {
        self.mailbox_spec
    }
}

/// Canonically ordered, duplicate-free target assignment body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetAssignments {
    assignments: Box<[BindingAssignment]>,
    canonical_wire: Box<[u8]>,
    assignment_digest: TargetAssignmentDigest,
}

impl TargetAssignments {
    /// Sorts records by BindingId, rejects static 1:1 conflicts, and commits the body.
    pub fn try_new(
        mut assignments: Vec<BindingAssignment>,
    ) -> Result<Self, AssignmentContractError> {
        if assignments.len() > MAX_TARGET_ASSIGNMENTS {
            return Err(AssignmentContractError::AssignmentCountExceeded);
        }
        assignments.sort_by_key(|assignment| assignment.binding_id());
        ensure_assignment_uniqueness(&assignments)?;
        let canonical_wire = build_target_assignments_wire(&assignments);
        let assignment_digest = digest_target_assignments(&canonical_wire)?;
        Ok(Self {
            assignments: assignments.into_boxed_slice(),
            canonical_wire: canonical_wire.into_boxed_slice(),
            assignment_digest,
        })
    }

    /// Strictly decodes a canonical fixed-record assignment body.
    pub fn decode(frame: &[u8]) -> Result<Self, AssignmentWireError> {
        decode_target_assignments(frame)
    }

    /// Returns canonically BindingId-ordered assignments.
    #[must_use]
    pub fn as_slice(&self) -> &[BindingAssignment] {
        &self.assignments
    }

    /// Returns the number of assignments in the complete target body.
    #[must_use]
    pub fn len(&self) -> usize {
        self.assignments.len()
    }

    /// Reports whether the complete target body contains no Port binding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assignments.is_empty()
    }

    /// Returns the exact canonical assignment bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the digest authenticated by the surrounding Slice commitment.
    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.assignment_digest
    }

    /// Revalidates records, ordering, canonical bytes, and the stored digest.
    pub fn validate(&self) -> Result<(), AssignmentContractError> {
        let rebuilt = Self::try_new(self.assignments.to_vec())?;
        if rebuilt.assignments != self.assignments {
            return Err(AssignmentContractError::CanonicalWireMismatch);
        }
        if rebuilt.canonical_wire != self.canonical_wire {
            return Err(AssignmentContractError::CanonicalWireMismatch);
        }
        if rebuilt.assignment_digest != self.assignment_digest {
            return Err(AssignmentContractError::AssignmentDigestMismatch);
        }
        Ok(())
    }
}

/// Complete target Slice: the existing B1 commitment and its canonical body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePlanSlice {
    commitment: RuntimeSliceCommitment,
    assignments: TargetAssignments,
}

impl RuntimePlanSlice {
    /// Binds canonical target assignments to the exact digest in a B1 commitment.
    pub fn try_new(
        commitment: RuntimeSliceCommitment,
        assignments: TargetAssignments,
    ) -> Result<Self, AssignmentContractError> {
        commitment.validate()?;
        assignments.validate()?;
        if commitment.header().assignment_digest() != assignments.assignment_digest() {
            return Err(AssignmentContractError::SliceAssignmentDigestMismatch);
        }
        Ok(Self {
            commitment,
            assignments,
        })
    }

    /// Returns the B1 target-slice commitment.
    #[must_use]
    pub const fn commitment(&self) -> RuntimeSliceCommitment {
        self.commitment
    }

    /// Returns the canonical target assignment body.
    #[must_use]
    pub const fn assignments(&self) -> &TargetAssignments {
        &self.assignments
    }

    /// Revalidates the B1 commitment and exact assignment-digest binding.
    pub fn validate(&self) -> Result<(), AssignmentContractError> {
        self.commitment.validate()?;
        self.assignments.validate()?;
        if self.commitment.header().assignment_digest() != self.assignments.assignment_digest() {
            return Err(AssignmentContractError::SliceAssignmentDigestMismatch);
        }
        Ok(())
    }
}

/// Complete apply request containing the existing signed envelope and Slice body.
///
/// The existing envelope request digest remains the operation identity. This
/// outer frame adds no signature or second request digest because the envelope
/// already authenticates the exact assignment digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyRequest {
    envelope: RuntimeApplyEnvelope,
    slice: RuntimePlanSlice,
    canonical_wire: Box<[u8]>,
}

impl RuntimeApplyRequest {
    /// Builds a complete request without modifying the S2 envelope wire.
    pub fn try_new(
        envelope: RuntimeApplyEnvelope,
        slice: RuntimePlanSlice,
    ) -> Result<Self, AssignmentContractError> {
        envelope.validate()?;
        slice.validate()?;
        if envelope.control_commitment().slice() != slice.commitment() {
            return Err(AssignmentContractError::EnvelopeSliceMismatch);
        }
        let canonical_wire = build_runtime_apply_request_wire(&envelope, &slice);
        if canonical_wire.len() > MAX_RUNTIME_APPLY_REQUEST_BYTES {
            return Err(AssignmentContractError::RequestFrameTooLarge);
        }
        Ok(Self {
            envelope,
            slice,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes the complete request outer frame and both components.
    pub fn decode(frame: &[u8]) -> Result<Self, RequestWireError> {
        decode_runtime_apply_request(frame)
    }

    /// Returns the unchanged signed B2 envelope.
    #[must_use]
    pub const fn envelope(&self) -> &RuntimeApplyEnvelope {
        &self.envelope
    }

    /// Returns the complete target Slice.
    #[must_use]
    pub const fn slice(&self) -> &RuntimePlanSlice {
        &self.slice
    }

    /// Returns the existing complete signed-envelope digest used by apply replay.
    #[must_use]
    pub const fn request_digest(&self) -> &Digest32 {
        self.envelope.request_digest()
    }

    /// Returns canonical outer bytes containing envelope bytes and assignment bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Revalidates both components, their exact match, and stored outer bytes.
    pub fn validate(&self) -> Result<(), AssignmentContractError> {
        self.envelope.validate()?;
        self.slice.validate()?;
        if self.envelope.control_commitment().slice() != self.slice.commitment() {
            return Err(AssignmentContractError::EnvelopeSliceMismatch);
        }
        let rebuilt = build_runtime_apply_request_wire(&self.envelope, &self.slice);
        if rebuilt.as_slice() != self.canonical_wire() {
            return Err(AssignmentContractError::RequestCanonicalWireMismatch);
        }
        Ok(())
    }
}

/// Stable construction and semantic validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentContractError {
    /// Schema version zero is reserved.
    InvalidSchemaVersion,
    /// A link must declare a positive payload bound.
    InvalidMaxPayloadBytes,
    /// A link must declare a positive age bound.
    InvalidMaxMessageAge,
    /// Mailbox item capacity must be positive.
    InvalidMailboxItemCapacity,
    /// Mailbox byte capacity must be positive.
    InvalidMailboxByteCapacity,
    /// Mailbox queue age must be positive.
    InvalidMailboxAge,
    /// Mailbox inflight capacity must be positive.
    InvalidMailboxInflightCapacity,
    /// Retained-payload byte capacity must be positive.
    InvalidMailboxRetainedByteCapacity,
    /// The source endpoint is not an Out port.
    InvalidSourceDirection,
    /// The target endpoint is not an In port.
    InvalidTargetDirection,
    /// Source and target resolved schemas differ.
    SchemaMismatch,
    /// Source and target interaction kinds differ.
    InteractionMismatch,
    /// Link and Mailbox pressure semantics differ.
    OverflowPolicyMismatch,
    /// The Mailbox could retain a message beyond the Link age bound.
    QueueAgeExceedsDeliveryAge,
    /// The Mailbox byte capacity cannot hold one maximum-size payload.
    MailboxCannotHoldPayload,
    /// The retained-byte budget cannot account for all queued payload bytes.
    MailboxCannotRetainCapacity,
    /// Immutable Event delivery cannot use a lossy Signal pressure policy.
    EventCannotUseLossyOverflow,
    /// The target body exceeds its fixed assignment-count limit.
    AssignmentCountExceeded,
    /// Two records use the same logical BindingId.
    DuplicateBindingId,
    /// Static 1:1 assignments reuse one source endpoint.
    DuplicateSourceEndpoint,
    /// Static 1:1 assignments reuse one target endpoint.
    DuplicateTargetEndpoint,
    /// Static 1:1 assignments reuse one target Mailbox identity.
    DuplicateMailboxRef,
    /// Canonical digest construction failed.
    Digest(DigestBuildError),
    /// Stored canonical assignment bytes do not match the records.
    CanonicalWireMismatch,
    /// Stored assignment digest does not match canonical bytes.
    AssignmentDigestMismatch,
    /// The assignment body does not match the digest committed by the Slice.
    SliceAssignmentDigestMismatch,
    /// The Slice commitment stored inside a complete request differs from the envelope.
    EnvelopeSliceMismatch,
    /// A stored Slice commitment failed its B1 validation.
    Provenance(ProvenanceContractError),
    /// A stored envelope failed B2 validation.
    Envelope(EnvelopeContractError),
    /// The complete request exceeded its fixed wire bound.
    RequestFrameTooLarge,
    /// Stored complete-request wire does not match its values.
    RequestCanonicalWireMismatch,
}

impl From<DigestBuildError> for AssignmentContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ProvenanceContractError> for AssignmentContractError {
    fn from(value: ProvenanceContractError) -> Self {
        Self::Provenance(value)
    }
}

impl From<EnvelopeContractError> for AssignmentContractError {
    fn from(value: EnvelopeContractError) -> Self {
        Self::Envelope(value)
    }
}

impl fmt::Display for AssignmentContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSchemaVersion => "schema version must be nonzero",
            Self::InvalidMaxPayloadBytes => "maximum payload bytes must be positive",
            Self::InvalidMaxMessageAge => "maximum message age must be positive",
            Self::InvalidMailboxItemCapacity => "Mailbox item capacity must be positive",
            Self::InvalidMailboxByteCapacity => "Mailbox byte capacity must be positive",
            Self::InvalidMailboxAge => "Mailbox maximum queue age must be positive",
            Self::InvalidMailboxInflightCapacity => "Mailbox inflight capacity must be positive",
            Self::InvalidMailboxRetainedByteCapacity => {
                "Mailbox retained-byte capacity must be positive"
            }
            Self::InvalidSourceDirection => "binding source must be an Out port",
            Self::InvalidTargetDirection => "binding target must be an In port",
            Self::SchemaMismatch => "binding endpoint schemas do not match exactly",
            Self::InteractionMismatch => "binding endpoint interaction kinds do not match",
            Self::OverflowPolicyMismatch => "delivery and Mailbox overflow policies differ",
            Self::QueueAgeExceedsDeliveryAge => "Mailbox queue age exceeds the delivery age bound",
            Self::MailboxCannotHoldPayload => {
                "Mailbox byte capacity cannot hold one maximum payload"
            }
            Self::MailboxCannotRetainCapacity => {
                "Mailbox retained-byte budget is below its queued-byte capacity"
            }
            Self::EventCannotUseLossyOverflow => {
                "Event delivery cannot use a lossy Signal overflow policy"
            }
            Self::AssignmentCountExceeded => "target assignment count exceeds its fixed bound",
            Self::DuplicateBindingId => "target assignments contain a duplicate BindingId",
            Self::DuplicateSourceEndpoint => "static 1:1 assignments reuse a source endpoint",
            Self::DuplicateTargetEndpoint => "static 1:1 assignments reuse a target endpoint",
            Self::DuplicateMailboxRef => "static 1:1 assignments reuse a target Mailbox reference",
            Self::Digest(error) => return write!(formatter, "canonical digest failed: {error}"),
            Self::CanonicalWireMismatch => {
                "canonical assignment bytes do not match assignment records"
            }
            Self::AssignmentDigestMismatch => {
                "target-assignment digest does not match canonical bytes"
            }
            Self::SliceAssignmentDigestMismatch => {
                "target assignments do not match the Slice assignment digest"
            }
            Self::EnvelopeSliceMismatch => {
                "complete request Slice does not match its signed envelope"
            }
            Self::Provenance(error) => {
                return write!(formatter, "Slice commitment rejected: {error}");
            }
            Self::Envelope(error) => return write!(formatter, "apply envelope rejected: {error}"),
            Self::RequestFrameTooLarge => "complete apply request exceeds its fixed wire bound",
            Self::RequestCanonicalWireMismatch => {
                "complete apply request wire does not match its values"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AssignmentContractError {}

/// Stable machine-readable reason for target-assignment wire rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AssignmentWireErrorCode {
    /// The frame exceeds the pre-parse size bound.
    FrameTooLarge = 1,
    /// The frame ended before its fixed header or records were complete.
    Truncated = 2,
    /// The fixed assignment magic did not match.
    InvalidMagic = 3,
    /// The assignment-body version is unsupported.
    UnsupportedVersion = 4,
    /// The declared assignment count exceeds the protocol bound.
    AssignmentCountExceeded = 5,
    /// The declared fixed-record length does not equal the frame length.
    InvalidFrameLength = 6,
    /// A fixed enum field carried an unknown value.
    InvalidEnumValue = 7,
    /// A structurally valid record violates assignment semantics.
    InvalidAssignment = 8,
    /// Two records use the same BindingId.
    DuplicateBindingId = 9,
    /// Two records reuse one source endpoint.
    DuplicateSourceEndpoint = 10,
    /// Two records reuse one target endpoint.
    DuplicateTargetEndpoint = 11,
    /// Re-encoding decoded records did not reproduce the frame.
    NonCanonicalFrame = 12,
    /// Two records reuse one target Mailbox reference.
    DuplicateMailboxRef = 13,
}

/// Canonical assignment-wire rejection with an optional record index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignmentWireError {
    code: AssignmentWireErrorCode,
    record_index: Option<u32>,
}

impl AssignmentWireError {
    const fn new(code: AssignmentWireErrorCode) -> Self {
        Self {
            code,
            record_index: None,
        }
    }

    const fn at(code: AssignmentWireErrorCode, record_index: u32) -> Self {
        Self {
            code,
            record_index: Some(record_index),
        }
    }

    /// Returns the stable wire reason code.
    #[must_use]
    pub const fn code(self) -> AssignmentWireErrorCode {
        self.code
    }

    /// Returns the zero-based offending record index when available.
    #[must_use]
    pub const fn record_index(self) -> Option<u32> {
        self.record_index
    }
}

impl fmt::Display for AssignmentWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(index) = self.record_index {
            write!(
                formatter,
                "target-assignment wire error {:?} at record {index}",
                self.code
            )
        } else {
            write!(formatter, "target-assignment wire error {:?}", self.code)
        }
    }
}

impl std::error::Error for AssignmentWireError {}

/// Stable machine-readable reason for complete apply-request wire rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RequestWireErrorCode {
    /// The outer frame exceeds the pre-parse size bound.
    FrameTooLarge = 1,
    /// The outer frame ended before its header or components were complete.
    Truncated = 2,
    /// The fixed outer magic did not match.
    InvalidMagic = 3,
    /// The complete-request version is unsupported.
    UnsupportedVersion = 4,
    /// Component lengths do not exactly cover the outer frame.
    InvalidFrameLength = 5,
    /// The embedded S2 envelope was rejected.
    EnvelopeRejected = 6,
    /// The embedded target-assignment body was rejected.
    AssignmentsRejected = 7,
    /// The assignment body does not match the authenticated Slice commitment.
    CommitmentMismatch = 8,
}

/// Complete-request wire rejection with an optional nested stable reason code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestWireError {
    code: RequestWireErrorCode,
    detail_code: Option<u16>,
}

impl RequestWireError {
    const fn new(code: RequestWireErrorCode) -> Self {
        Self {
            code,
            detail_code: None,
        }
    }

    const fn with_detail(code: RequestWireErrorCode, detail_code: u16) -> Self {
        Self {
            code,
            detail_code: Some(detail_code),
        }
    }

    /// Returns the stable outer-frame reason code.
    #[must_use]
    pub const fn code(self) -> RequestWireErrorCode {
        self.code
    }

    /// Returns an embedded envelope or assignment reason code when available.
    #[must_use]
    pub const fn detail_code(self) -> Option<u16> {
        self.detail_code
    }
}

impl fmt::Display for RequestWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(detail) = self.detail_code {
            write!(
                formatter,
                "complete apply-request wire error {:?} ({detail})",
                self.code
            )
        } else {
            write!(
                formatter,
                "complete apply-request wire error {:?}",
                self.code
            )
        }
    }
}

impl std::error::Error for RequestWireError {}

fn ensure_assignment_uniqueness(
    assignments: &[BindingAssignment],
) -> Result<(), AssignmentContractError> {
    for (index, assignment) in assignments.iter().enumerate() {
        for previous in assignments.iter().take(index) {
            if previous.binding_id() == assignment.binding_id() {
                return Err(AssignmentContractError::DuplicateBindingId);
            }
            if previous.source_instance() == assignment.source_instance()
                && previous.source_port() == assignment.source_port()
            {
                return Err(AssignmentContractError::DuplicateSourceEndpoint);
            }
            if previous.target_instance() == assignment.target_instance()
                && previous.target_port() == assignment.target_port()
            {
                return Err(AssignmentContractError::DuplicateTargetEndpoint);
            }
            if previous.mailbox() == assignment.mailbox() {
                return Err(AssignmentContractError::DuplicateMailboxRef);
            }
        }
    }
    Ok(())
}

fn digest_target_assignments(
    canonical_wire: &[u8],
) -> Result<TargetAssignmentDigest, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TARGET_ASSIGNMENTS_DIGEST_DOMAIN)?;
    builder.field_bytes(canonical_wire)?;
    Ok(TargetAssignmentDigest::new(builder.finish()))
}

fn build_target_assignments_wire(assignments: &[BindingAssignment]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(
        TARGET_ASSIGNMENTS_HEADER_BYTES + assignments.len() * TARGET_ASSIGNMENT_RECORD_BYTES,
    );
    encoded.extend_from_slice(TARGET_ASSIGNMENTS_MAGIC);
    encoded.extend_from_slice(&TARGET_ASSIGNMENTS_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(assignments.len() as u32).to_be_bytes());
    for assignment in assignments {
        append_assignment_record(&mut encoded, *assignment);
    }
    encoded
}

fn append_assignment_record(encoded: &mut Vec<u8>, assignment: BindingAssignment) {
    encoded.extend_from_slice(assignment.binding_id().as_bytes());
    append_endpoint(
        encoded,
        assignment.source_instance(),
        assignment.source_port(),
        assignment.source_spec(),
    );
    append_endpoint(
        encoded,
        assignment.target_instance(),
        assignment.target_port(),
        assignment.target_spec(),
    );
    encoded.extend_from_slice(assignment.mailbox().as_bytes());
    let delivery = assignment.delivery();
    encoded.extend_from_slice(&delivery.max_payload_bytes().to_be_bytes());
    encoded.extend_from_slice(&delivery.max_message_age().value().to_be_bytes());
    encoded.push(delivery.overflow_policy() as u8);
    let mailbox = assignment.mailbox_spec();
    encoded.extend_from_slice(&mailbox.capacity_items().to_be_bytes());
    encoded.extend_from_slice(&mailbox.capacity_bytes().to_be_bytes());
    encoded.extend_from_slice(&mailbox.max_queue_age().value().to_be_bytes());
    encoded.extend_from_slice(&mailbox.max_inflight().to_be_bytes());
    encoded.extend_from_slice(&mailbox.max_retained_bytes().to_be_bytes());
    encoded.push(mailbox.overflow_policy() as u8);
}

fn append_endpoint(encoded: &mut Vec<u8>, instance: InstanceRef, port: PortRef, spec: PortSpec) {
    encoded.extend_from_slice(instance.as_bytes());
    encoded.extend_from_slice(port.as_bytes());
    encoded.push(spec.direction() as u8);
    encoded.extend_from_slice(spec.schema().id_bytes());
    encoded.extend_from_slice(&spec.schema().version().to_be_bytes());
    encoded.extend_from_slice(spec.schema().content_digest().as_bytes());
    encoded.push(spec.interaction() as u8);
    encoded.push(spec.cardinality() as u8);
}

fn build_runtime_apply_request_wire(
    envelope: &RuntimeApplyEnvelope,
    slice: &RuntimePlanSlice,
) -> Vec<u8> {
    let assignment_wire = slice.assignments().canonical_wire();
    let mut encoded = Vec::with_capacity(
        APPLY_REQUEST_HEADER_BYTES + envelope.canonical_wire().len() + assignment_wire.len(),
    );
    encoded.extend_from_slice(RUNTIME_APPLY_REQUEST_MAGIC);
    encoded.extend_from_slice(&RUNTIME_APPLY_REQUEST_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(envelope.canonical_wire().len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(assignment_wire.len() as u32).to_be_bytes());
    encoded.extend_from_slice(envelope.canonical_wire());
    encoded.extend_from_slice(assignment_wire);
    encoded
}

fn decode_target_assignments(frame: &[u8]) -> Result<TargetAssignments, AssignmentWireError> {
    if frame.len() > MAX_TARGET_ASSIGNMENTS_BYTES {
        return Err(AssignmentWireError::new(
            AssignmentWireErrorCode::FrameTooLarge,
        ));
    }
    if frame.len() < TARGET_ASSIGNMENTS_HEADER_BYTES {
        return Err(AssignmentWireError::new(AssignmentWireErrorCode::Truncated));
    }
    if &frame[..TARGET_ASSIGNMENTS_MAGIC.len()] != TARGET_ASSIGNMENTS_MAGIC {
        return Err(AssignmentWireError::new(
            AssignmentWireErrorCode::InvalidMagic,
        ));
    }
    let version = read_u16(&frame[4..6]);
    if version != TARGET_ASSIGNMENTS_VERSION {
        return Err(AssignmentWireError::new(
            AssignmentWireErrorCode::UnsupportedVersion,
        ));
    }
    let declared_count = read_u32(&frame[6..10]) as usize;
    if declared_count > MAX_TARGET_ASSIGNMENTS {
        return Err(AssignmentWireError::new(
            AssignmentWireErrorCode::AssignmentCountExceeded,
        ));
    }
    let Some(records_bytes) = declared_count.checked_mul(TARGET_ASSIGNMENT_RECORD_BYTES) else {
        return Err(AssignmentWireError::new(
            AssignmentWireErrorCode::InvalidFrameLength,
        ));
    };
    let Some(expected_length) = TARGET_ASSIGNMENTS_HEADER_BYTES.checked_add(records_bytes) else {
        return Err(AssignmentWireError::new(
            AssignmentWireErrorCode::InvalidFrameLength,
        ));
    };
    if frame.len() < expected_length {
        return Err(AssignmentWireError::new(AssignmentWireErrorCode::Truncated));
    }
    if frame.len() != expected_length {
        return Err(AssignmentWireError::new(
            AssignmentWireErrorCode::InvalidFrameLength,
        ));
    }

    let mut assignments = Vec::with_capacity(declared_count);
    for (index, record) in frame[TARGET_ASSIGNMENTS_HEADER_BYTES..]
        .chunks_exact(TARGET_ASSIGNMENT_RECORD_BYTES)
        .enumerate()
    {
        assignments.push(decode_assignment_record(record, index as u32)?);
    }
    let decoded =
        TargetAssignments::try_new(assignments).map_err(assignment_contract_wire_error)?;
    if decoded.canonical_wire() != frame {
        return Err(AssignmentWireError::new(
            AssignmentWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn decode_assignment_record(
    record: &[u8],
    record_index: u32,
) -> Result<BindingAssignment, AssignmentWireError> {
    let mut cursor = RecordCursor::new(record);
    let binding_id = BindingId::from_bytes(cursor.array());
    let source = decode_endpoint(&mut cursor, record_index)?;
    let target = decode_endpoint(&mut cursor, record_index)?;
    let mailbox = MailboxRef::from_bytes(cursor.array());
    let max_payload_bytes = cursor.u64();
    let max_message_age = BoundedDuration::from_nanos(cursor.u64());
    let delivery_overflow = decode_overflow(cursor.u8(), record_index)?;
    let capacity_items = cursor.u32();
    let capacity_bytes = cursor.u64();
    let max_queue_age = BoundedDuration::from_nanos(cursor.u64());
    let max_inflight = cursor.u32();
    let max_retained_bytes = cursor.u64();
    let mailbox_overflow = decode_overflow(cursor.u8(), record_index)?;

    let delivery = DeliveryProfile::try_new(max_payload_bytes, max_message_age, delivery_overflow)
        .map_err(|_| {
            AssignmentWireError::at(AssignmentWireErrorCode::InvalidAssignment, record_index)
        })?;
    let mailbox_spec = MailboxSpec::try_new(
        capacity_items,
        capacity_bytes,
        max_queue_age,
        max_inflight,
        max_retained_bytes,
        mailbox_overflow,
    )
    .map_err(|_| {
        AssignmentWireError::at(AssignmentWireErrorCode::InvalidAssignment, record_index)
    })?;
    BindingAssignment::try_new(binding_id, source, target, mailbox, delivery, mailbox_spec).map_err(
        |_| AssignmentWireError::at(AssignmentWireErrorCode::InvalidAssignment, record_index),
    )
}

fn decode_endpoint(
    cursor: &mut RecordCursor<'_>,
    record_index: u32,
) -> Result<PortEndpoint, AssignmentWireError> {
    let instance = InstanceRef::from_bytes(cursor.array());
    let port = PortRef::from_bytes(cursor.array());
    let direction = decode_direction(cursor.u8(), record_index)?;
    let schema_id = cursor.array();
    let schema_version = cursor.u32();
    let schema_digest = Digest32::from_bytes(cursor.array());
    let schema = SchemaRef::try_new(schema_id, schema_version, schema_digest).map_err(|_| {
        AssignmentWireError::at(AssignmentWireErrorCode::InvalidAssignment, record_index)
    })?;
    let interaction = decode_interaction(cursor.u8(), record_index)?;
    let cardinality = decode_cardinality(cursor.u8(), record_index)?;
    Ok(PortEndpoint::new(
        instance,
        port,
        PortSpec::new(direction, schema, interaction, cardinality),
    ))
}

fn decode_direction(value: u8, record_index: u32) -> Result<PortDirection, AssignmentWireError> {
    match value {
        1 => Ok(PortDirection::Out),
        2 => Ok(PortDirection::In),
        _ => Err(AssignmentWireError::at(
            AssignmentWireErrorCode::InvalidEnumValue,
            record_index,
        )),
    }
}

fn decode_interaction(
    value: u8,
    record_index: u32,
) -> Result<InteractionKind, AssignmentWireError> {
    match value {
        1 => Ok(InteractionKind::Signal),
        2 => Ok(InteractionKind::Event),
        _ => Err(AssignmentWireError::at(
            AssignmentWireErrorCode::InvalidEnumValue,
            record_index,
        )),
    }
}

fn decode_cardinality(
    value: u8,
    record_index: u32,
) -> Result<PortCardinality, AssignmentWireError> {
    match value {
        1 => Ok(PortCardinality::One),
        _ => Err(AssignmentWireError::at(
            AssignmentWireErrorCode::InvalidEnumValue,
            record_index,
        )),
    }
}

fn decode_overflow(value: u8, record_index: u32) -> Result<OverflowPolicy, AssignmentWireError> {
    match value {
        1 => Ok(OverflowPolicy::RejectNew),
        2 => Ok(OverflowPolicy::DropOldest),
        3 => Ok(OverflowPolicy::Latest),
        4 => Ok(OverflowPolicy::CoalesceByKey),
        5 => Ok(OverflowPolicy::BlockUntilDeadline),
        _ => Err(AssignmentWireError::at(
            AssignmentWireErrorCode::InvalidEnumValue,
            record_index,
        )),
    }
}

fn assignment_contract_wire_error(error: AssignmentContractError) -> AssignmentWireError {
    let code = match error {
        AssignmentContractError::AssignmentCountExceeded => {
            AssignmentWireErrorCode::AssignmentCountExceeded
        }
        AssignmentContractError::DuplicateBindingId => AssignmentWireErrorCode::DuplicateBindingId,
        AssignmentContractError::DuplicateSourceEndpoint => {
            AssignmentWireErrorCode::DuplicateSourceEndpoint
        }
        AssignmentContractError::DuplicateTargetEndpoint => {
            AssignmentWireErrorCode::DuplicateTargetEndpoint
        }
        AssignmentContractError::DuplicateMailboxRef => {
            AssignmentWireErrorCode::DuplicateMailboxRef
        }
        _ => AssignmentWireErrorCode::InvalidAssignment,
    };
    AssignmentWireError::new(code)
}

fn decode_runtime_apply_request(frame: &[u8]) -> Result<RuntimeApplyRequest, RequestWireError> {
    if frame.len() > MAX_RUNTIME_APPLY_REQUEST_BYTES {
        return Err(RequestWireError::new(RequestWireErrorCode::FrameTooLarge));
    }
    if frame.len() < APPLY_REQUEST_HEADER_BYTES {
        return Err(RequestWireError::new(RequestWireErrorCode::Truncated));
    }
    if &frame[..RUNTIME_APPLY_REQUEST_MAGIC.len()] != RUNTIME_APPLY_REQUEST_MAGIC {
        return Err(RequestWireError::new(RequestWireErrorCode::InvalidMagic));
    }
    if read_u16(&frame[4..6]) != RUNTIME_APPLY_REQUEST_VERSION {
        return Err(RequestWireError::new(
            RequestWireErrorCode::UnsupportedVersion,
        ));
    }
    let envelope_length = read_u32(&frame[6..10]) as usize;
    let assignments_length = read_u32(&frame[10..14]) as usize;
    let Some(component_length) = envelope_length.checked_add(assignments_length) else {
        return Err(RequestWireError::new(
            RequestWireErrorCode::InvalidFrameLength,
        ));
    };
    let Some(expected_length) = APPLY_REQUEST_HEADER_BYTES.checked_add(component_length) else {
        return Err(RequestWireError::new(
            RequestWireErrorCode::InvalidFrameLength,
        ));
    };
    if frame.len() < expected_length {
        return Err(RequestWireError::new(RequestWireErrorCode::Truncated));
    }
    if frame.len() != expected_length {
        return Err(RequestWireError::new(
            RequestWireErrorCode::InvalidFrameLength,
        ));
    }
    let envelope_start = APPLY_REQUEST_HEADER_BYTES;
    let envelope_end = envelope_start + envelope_length;
    let envelope = RuntimeApplyEnvelope::decode(&frame[envelope_start..envelope_end])
        .map_err(request_envelope_wire_error)?;
    let assignments =
        TargetAssignments::decode(&frame[envelope_end..]).map_err(request_assignment_wire_error)?;
    let slice = RuntimePlanSlice::try_new(envelope.control_commitment().slice(), assignments)
        .map_err(|_| RequestWireError::new(RequestWireErrorCode::CommitmentMismatch))?;
    RuntimeApplyRequest::try_new(envelope, slice)
        .map_err(|_| RequestWireError::new(RequestWireErrorCode::CommitmentMismatch))
}

fn request_envelope_wire_error(error: WireError) -> RequestWireError {
    RequestWireError::with_detail(RequestWireErrorCode::EnvelopeRejected, error.code() as u16)
}

fn request_assignment_wire_error(error: AssignmentWireError) -> RequestWireError {
    RequestWireError::with_detail(
        RequestWireErrorCode::AssignmentsRejected,
        error.code() as u16,
    )
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

struct RecordCursor<'a> {
    record: &'a [u8],
    offset: usize,
}

impl<'a> RecordCursor<'a> {
    const fn new(record: &'a [u8]) -> Self {
        Self { record, offset: 0 }
    }

    fn array<const LENGTH: usize>(&mut self) -> [u8; LENGTH] {
        let end = self.offset + LENGTH;
        let mut value = [0; LENGTH];
        value.copy_from_slice(&self.record[self.offset..end]);
        self.offset = end;
        value
    }

    fn u8(&mut self) -> u8 {
        let value = self.record[self.offset];
        self.offset += 1;
        value
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
    }
}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
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
    };
    use crate::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
    use crate::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim, RuntimeApplyEnvelope,
        RuntimeApplyEnvelopeDraft,
    };

    use super::{
        APPLY_REQUEST_HEADER_BYTES, AssignmentContractError, AssignmentWireErrorCode,
        BindingAssignment, BindingId, DeliveryProfile, InstanceRef, InteractionKind,
        MAX_RUNTIME_APPLY_REQUEST_BYTES, MAX_TARGET_ASSIGNMENTS, MAX_TARGET_ASSIGNMENTS_BYTES,
        MailboxRef, MailboxSpec, OverflowPolicy, PortCardinality, PortDirection, PortEndpoint,
        PortRef, PortSpec, RUNTIME_APPLY_REQUEST_VERSION, RequestWireErrorCode,
        RuntimeApplyRequest, RuntimePlanSlice, SchemaRef, TARGET_ASSIGNMENT_RECORD_BYTES,
        TARGET_ASSIGNMENTS_HEADER_BYTES, TARGET_ASSIGNMENTS_VERSION, TargetAssignments,
    };

    fn identity_bytes(prefix: u8, value: u16) -> [u8; 16] {
        let mut bytes = [prefix; 16];
        let suffix = value.to_be_bytes();
        bytes[14] = suffix[0];
        bytes[15] = suffix[1];
        bytes
    }

    fn schema(byte: u8) -> SchemaRef {
        let Ok(schema) = SchemaRef::try_new(
            [byte; 16],
            1,
            Digest32::from_bytes([byte.wrapping_add(1); 32]),
        ) else {
            panic!("test schema must be valid");
        };
        schema
    }

    fn assignment_with_endpoints(
        binding_value: u16,
        source_value: u16,
        target_value: u16,
        interaction: InteractionKind,
        overflow: OverflowPolicy,
    ) -> BindingAssignment {
        let resolved_schema = schema(7);
        let source = PortEndpoint::new(
            InstanceRef::from_bytes(identity_bytes(1, source_value)),
            PortRef::from_bytes(identity_bytes(2, source_value)),
            PortSpec::new(
                PortDirection::Out,
                resolved_schema,
                interaction,
                PortCardinality::One,
            ),
        );
        let target = PortEndpoint::new(
            InstanceRef::from_bytes(identity_bytes(3, target_value)),
            PortRef::from_bytes(identity_bytes(4, target_value)),
            PortSpec::new(
                PortDirection::In,
                resolved_schema,
                interaction,
                PortCardinality::One,
            ),
        );
        let Ok(delivery) =
            DeliveryProfile::try_new(128, BoundedDuration::from_nanos(1_000), overflow)
        else {
            panic!("test delivery profile must be valid");
        };
        let Ok(mailbox) =
            MailboxSpec::try_new(2, 256, BoundedDuration::from_nanos(500), 1, 256, overflow)
        else {
            panic!("test Mailbox specification must be valid");
        };
        let Ok(assignment) = BindingAssignment::try_new(
            BindingId::from_bytes(identity_bytes(5, binding_value)),
            source,
            target,
            MailboxRef::from_bytes(identity_bytes(6, target_value)),
            delivery,
            mailbox,
        ) else {
            panic!("test binding assignment must be valid");
        };
        assignment
    }

    fn assignment(binding_value: u16) -> BindingAssignment {
        assignment_with_endpoints(
            binding_value,
            binding_value,
            binding_value,
            InteractionKind::Signal,
            OverflowPolicy::Latest,
        )
    }

    fn target_assignments(values: &[u16]) -> TargetAssignments {
        let records = values.iter().map(|value| assignment(*value)).collect();
        let Ok(assignments) = TargetAssignments::try_new(records) else {
            panic!("test target assignments must be valid");
        };
        assignments
    }

    fn slice_commitment(assignment_digest: TargetAssignmentDigest) -> RuntimeSliceCommitment {
        let provenance = PlanProvenance::new(
            SourceScopeRef::from_bytes([1; 16]),
            SourcePlanRef::from_bytes([2; 16]),
            SourcePlanRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([4; 32])),
        );
        let header = RuntimeSliceHeader::new(
            RuntimeHostId::from_bytes([5; 16]),
            provenance,
            assignment_digest,
        );
        let Ok(commitment) = RuntimeSliceCommitment::try_new(header) else {
            panic!("test Slice commitment must be valid");
        };
        commitment
    }

    fn clock_generation(value: u64) -> ClockGeneration {
        let Ok(generation) = ClockGeneration::try_new(value) else {
            panic!("test clock generation must be valid");
        };
        generation
    }

    fn envelope(commitment: RuntimeSliceCommitment) -> RuntimeApplyEnvelope {
        let scope = commitment.header().provenance().source_scope();
        let Ok(algorithm) = TenureProofAlgorithm::try_new(1) else {
            panic!("test tenure algorithm must be valid");
        };
        let Ok(authority) = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([7; 16]),
            TenureKeyRef::from_bytes([8; 16]),
            algorithm,
            1,
        ) else {
            panic!("test tenure authority must be valid");
        };
        let writer = PlanWriterRef::from_bytes([9; 16]);
        let Ok(claim) = WriterTenureClaim::try_new(
            scope,
            writer,
            PlanWriterEpoch::new(2),
            PlanWriterEpoch::new(1),
        ) else {
            panic!("test tenure claim must be valid");
        };
        let Ok(proof) = WriterTenureProof::try_new(authority, claim, b"nonce", b"signature") else {
            panic!("test tenure proof must be valid");
        };
        let Ok(writer_context) = PlanWriterContext::try_new(writer, PlanWriterEpoch::new(2), proof)
        else {
            panic!("test writer context must be valid");
        };
        let control = RuntimeApplyControl::new(
            writer_context,
            ExpectedActive::None,
            ApplyOperationId::from_bytes([10; 16]),
        );
        let Ok(control_commitment) = RuntimeApplyControlCommitment::try_new(commitment, control)
        else {
            panic!("test control commitment must be valid");
        };
        let Ok(temporal) = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([11; 16]),
            ClockDomainRef::from_bytes([12; 16]),
            clock_generation(13),
            BoundedDuration::from_nanos(1_000),
            BoundedDuration::from_nanos(750),
        ) else {
            panic!("test temporal constraint must be valid");
        };
        let Ok(auth_algorithm) = ApplyAuthAlgorithm::try_new(1) else {
            panic!("test auth algorithm must be valid");
        };
        let Ok(auth_claim) = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([14; 16]),
            ApplyAuthKeyRef::from_bytes([15; 16]),
            auth_algorithm,
            1,
            b"apply-nonce",
        ) else {
            panic!("test auth claim must be valid");
        };
        let Ok(draft) =
            RuntimeApplyEnvelopeDraft::try_new(control_commitment, temporal, auth_claim)
        else {
            panic!("test envelope draft must be valid");
        };
        let Ok(envelope) = draft.finalize(b"apply-signature") else {
            panic!("test envelope must be valid");
        };
        envelope
    }

    fn complete_request(values: &[u16]) -> RuntimeApplyRequest {
        let assignments = target_assignments(values);
        let commitment = slice_commitment(assignments.assignment_digest());
        let signed_envelope = envelope(commitment);
        let Ok(slice) = RuntimePlanSlice::try_new(commitment, assignments) else {
            panic!("test RuntimePlanSlice must be valid");
        };
        let Ok(request) = RuntimeApplyRequest::try_new(signed_envelope, slice) else {
            panic!("test complete request must be valid");
        };
        request
    }

    #[test]
    fn schema_and_capacity_bounds_fail_closed() {
        assert_eq!(
            SchemaRef::try_new([1; 16], 0, Digest32::from_bytes([2; 32])),
            Err(AssignmentContractError::InvalidSchemaVersion)
        );
        assert_eq!(
            DeliveryProfile::try_new(0, BoundedDuration::from_nanos(1), OverflowPolicy::RejectNew),
            Err(AssignmentContractError::InvalidMaxPayloadBytes)
        );
        assert_eq!(
            MailboxSpec::try_new(
                0,
                1,
                BoundedDuration::from_nanos(1),
                1,
                1,
                OverflowPolicy::RejectNew
            ),
            Err(AssignmentContractError::InvalidMailboxItemCapacity)
        );
    }

    #[test]
    fn binding_rejects_direction_schema_interaction_and_pressure_mismatch() {
        let resolved_schema = schema(1);
        let other_schema = schema(2);
        let out = |schema, interaction| {
            PortEndpoint::new(
                InstanceRef::from_bytes([1; 16]),
                PortRef::from_bytes([2; 16]),
                PortSpec::new(
                    PortDirection::Out,
                    schema,
                    interaction,
                    PortCardinality::One,
                ),
            )
        };
        let incoming = |schema, interaction| {
            PortEndpoint::new(
                InstanceRef::from_bytes([3; 16]),
                PortRef::from_bytes([4; 16]),
                PortSpec::new(PortDirection::In, schema, interaction, PortCardinality::One),
            )
        };
        let Ok(delivery) = DeliveryProfile::try_new(
            1,
            BoundedDuration::from_nanos(10),
            OverflowPolicy::RejectNew,
        ) else {
            panic!("test delivery must be valid");
        };
        let Ok(mailbox) = MailboxSpec::try_new(
            1,
            1,
            BoundedDuration::from_nanos(10),
            1,
            1,
            OverflowPolicy::RejectNew,
        ) else {
            panic!("test Mailbox must be valid");
        };
        let build = |source, target| {
            BindingAssignment::try_new(
                BindingId::from_bytes([5; 16]),
                source,
                target,
                MailboxRef::from_bytes([6; 16]),
                delivery,
                mailbox,
            )
        };

        assert_eq!(
            build(
                incoming(resolved_schema, InteractionKind::Signal),
                incoming(resolved_schema, InteractionKind::Signal)
            ),
            Err(AssignmentContractError::InvalidSourceDirection)
        );
        assert_eq!(
            build(
                out(resolved_schema, InteractionKind::Signal),
                out(resolved_schema, InteractionKind::Signal)
            ),
            Err(AssignmentContractError::InvalidTargetDirection)
        );
        assert_eq!(
            build(
                out(resolved_schema, InteractionKind::Signal),
                incoming(other_schema, InteractionKind::Signal)
            ),
            Err(AssignmentContractError::SchemaMismatch)
        );
        assert_eq!(
            build(
                out(resolved_schema, InteractionKind::Signal),
                incoming(resolved_schema, InteractionKind::Event)
            ),
            Err(AssignmentContractError::InteractionMismatch)
        );
    }

    #[test]
    fn event_rejects_lossy_signal_policies_but_keeps_explicit_block_contract() {
        for overflow in [
            OverflowPolicy::DropOldest,
            OverflowPolicy::Latest,
            OverflowPolicy::CoalesceByKey,
        ] {
            let source = assignment_with_endpoints(1, 1, 1, InteractionKind::Signal, overflow);
            assert_eq!(source.delivery().overflow_policy(), overflow);

            let resolved_schema = schema(7);
            let out = PortEndpoint::new(
                InstanceRef::from_bytes([1; 16]),
                PortRef::from_bytes([2; 16]),
                PortSpec::new(
                    PortDirection::Out,
                    resolved_schema,
                    InteractionKind::Event,
                    PortCardinality::One,
                ),
            );
            let incoming = PortEndpoint::new(
                InstanceRef::from_bytes([3; 16]),
                PortRef::from_bytes([4; 16]),
                PortSpec::new(
                    PortDirection::In,
                    resolved_schema,
                    InteractionKind::Event,
                    PortCardinality::One,
                ),
            );
            let Ok(delivery) =
                DeliveryProfile::try_new(1, BoundedDuration::from_nanos(1), overflow)
            else {
                panic!("test delivery must be structurally valid");
            };
            let Ok(mailbox) =
                MailboxSpec::try_new(1, 1, BoundedDuration::from_nanos(1), 1, 1, overflow)
            else {
                panic!("test Mailbox must be structurally valid");
            };
            assert_eq!(
                BindingAssignment::try_new(
                    BindingId::from_bytes([5; 16]),
                    out,
                    incoming,
                    MailboxRef::from_bytes([6; 16]),
                    delivery,
                    mailbox,
                ),
                Err(AssignmentContractError::EventCannotUseLossyOverflow)
            );
        }
        let block = assignment_with_endpoints(
            2,
            2,
            2,
            InteractionKind::Event,
            OverflowPolicy::BlockUntilDeadline,
        );
        assert_eq!(
            block.delivery().overflow_policy(),
            OverflowPolicy::BlockUntilDeadline
        );
    }

    #[test]
    fn target_assignments_sort_and_have_a_stable_golden_digest() {
        let sorted = target_assignments(&[1, 2]);
        let reversed = target_assignments(&[2, 1]);

        assert_eq!(sorted, reversed);
        assert_eq!(sorted.canonical_wire().len(), 522);
        assert_eq!(
            sorted.assignment_digest().value().as_bytes(),
            &[
                0x25, 0x8b, 0x02, 0xd5, 0x81, 0xe2, 0x9f, 0x6c, 0xa1, 0x43, 0x76, 0x13, 0xcc, 0x54,
                0xaa, 0x14, 0xc7, 0x0e, 0xa3, 0x5b, 0x63, 0xc6, 0xc8, 0x2b, 0x06, 0x95, 0x92, 0x15,
                0x2b, 0xd0, 0x3a, 0x78,
            ]
        );
        assert_eq!(sorted.validate(), Ok(()));
    }

    #[test]
    fn static_one_to_one_duplicates_fail_closed() {
        assert_eq!(
            TargetAssignments::try_new(vec![
                assignment(1),
                assignment_with_endpoints(1, 2, 2, InteractionKind::Signal, OverflowPolicy::Latest,)
            ]),
            Err(AssignmentContractError::DuplicateBindingId)
        );
        assert_eq!(
            TargetAssignments::try_new(vec![
                assignment(1),
                assignment_with_endpoints(2, 1, 2, InteractionKind::Signal, OverflowPolicy::Latest,)
            ]),
            Err(AssignmentContractError::DuplicateSourceEndpoint)
        );
        assert_eq!(
            TargetAssignments::try_new(vec![
                assignment(1),
                assignment_with_endpoints(2, 2, 1, InteractionKind::Signal, OverflowPolicy::Latest,)
            ]),
            Err(AssignmentContractError::DuplicateTargetEndpoint)
        );
        let first = assignment(1);
        let mut reused_mailbox = assignment(2);
        reused_mailbox.mailbox = first.mailbox();
        assert_eq!(
            TargetAssignments::try_new(vec![first, reused_mailbox]),
            Err(AssignmentContractError::DuplicateMailboxRef)
        );
    }

    #[test]
    fn target_assignment_count_is_bounded_before_wire() {
        let records = (0..=MAX_TARGET_ASSIGNMENTS)
            .map(|value| assignment(value as u16))
            .collect();
        assert_eq!(
            TargetAssignments::try_new(records),
            Err(AssignmentContractError::AssignmentCountExceeded)
        );
        assert_eq!(
            MAX_TARGET_ASSIGNMENTS_BYTES,
            TARGET_ASSIGNMENTS_HEADER_BYTES
                + MAX_TARGET_ASSIGNMENTS * TARGET_ASSIGNMENT_RECORD_BYTES
        );
    }

    #[test]
    fn assignment_wire_round_trips_and_rejects_noncanonical_or_invalid_frames() {
        let assignments = target_assignments(&[1, 2]);
        let Ok(decoded) = TargetAssignments::decode(assignments.canonical_wire()) else {
            panic!("canonical assignments must decode");
        };
        assert_eq!(decoded, assignments);

        let mut unsupported = assignments.canonical_wire().to_vec();
        unsupported[4..6].copy_from_slice(&(TARGET_ASSIGNMENTS_VERSION + 1).to_be_bytes());
        assert_eq!(
            TargetAssignments::decode(&unsupported).map_err(|error| error.code()),
            Err(AssignmentWireErrorCode::UnsupportedVersion)
        );

        let mut invalid_enum = assignments.canonical_wire().to_vec();
        invalid_enum[TARGET_ASSIGNMENTS_HEADER_BYTES + 48] = 99;
        let error = TargetAssignments::decode(&invalid_enum).err();
        assert_eq!(
            error.map(|value| (value.code(), value.record_index())),
            Some((AssignmentWireErrorCode::InvalidEnumValue, Some(0)))
        );

        let mut reversed = assignments.canonical_wire().to_vec();
        let first_start = TARGET_ASSIGNMENTS_HEADER_BYTES;
        let second_start = first_start + TARGET_ASSIGNMENT_RECORD_BYTES;
        let (prefix_and_first, second) = reversed.split_at_mut(second_start);
        prefix_and_first[first_start..].swap_with_slice(second);
        assert_eq!(
            TargetAssignments::decode(&reversed).map_err(|error| error.code()),
            Err(AssignmentWireErrorCode::NonCanonicalFrame)
        );

        let mut duplicate_mailbox = assignments.canonical_wire().to_vec();
        let first_mailbox = TARGET_ASSIGNMENTS_HEADER_BYTES + 190;
        let second_mailbox = TARGET_ASSIGNMENTS_HEADER_BYTES + TARGET_ASSIGNMENT_RECORD_BYTES + 190;
        let mut mailbox_bytes = [0; 16];
        mailbox_bytes.copy_from_slice(&duplicate_mailbox[first_mailbox..first_mailbox + 16]);
        duplicate_mailbox[second_mailbox..second_mailbox + 16].copy_from_slice(&mailbox_bytes);
        assert_eq!(
            TargetAssignments::decode(&duplicate_mailbox).map_err(|error| error.code()),
            Err(AssignmentWireErrorCode::DuplicateMailboxRef)
        );

        let mut trailing = assignments.canonical_wire().to_vec();
        trailing.push(0);
        assert_eq!(
            TargetAssignments::decode(&trailing).map_err(|error| error.code()),
            Err(AssignmentWireErrorCode::InvalidFrameLength)
        );
        assert_eq!(
            TargetAssignments::decode(&vec![0; MAX_TARGET_ASSIGNMENTS_BYTES + 1])
                .map_err(|error| error.code()),
            Err(AssignmentWireErrorCode::FrameTooLarge)
        );
    }

    #[test]
    fn runtime_plan_slice_requires_exact_assignment_digest() {
        let assignments = target_assignments(&[1]);
        let wrong = slice_commitment(TargetAssignmentDigest::new(Digest32::from_bytes([99; 32])));

        assert_eq!(
            RuntimePlanSlice::try_new(wrong, assignments),
            Err(AssignmentContractError::SliceAssignmentDigestMismatch)
        );
    }

    #[test]
    fn complete_request_round_trips_without_changing_s2_request_identity() {
        let request = complete_request(&[1, 2]);
        let Ok(decoded) = RuntimeApplyRequest::decode(request.canonical_wire()) else {
            panic!("canonical complete request must decode");
        };

        assert_eq!(decoded, request);
        assert_eq!(
            request.request_digest(),
            request.envelope().request_digest()
        );
        assert_eq!(
            request.canonical_wire().len(),
            APPLY_REQUEST_HEADER_BYTES
                + request.envelope().canonical_wire().len()
                + request.slice().assignments().canonical_wire().len()
        );
        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn complete_request_rejects_body_tamper_outer_errors_and_mismatched_slice() {
        let request = complete_request(&[1]);
        let mut body_tamper = request.canonical_wire().to_vec();
        let assignment_start = APPLY_REQUEST_HEADER_BYTES
            + request.envelope().canonical_wire().len()
            + TARGET_ASSIGNMENTS_HEADER_BYTES;
        body_tamper[assignment_start] ^= 1;
        assert_eq!(
            RuntimeApplyRequest::decode(&body_tamper).map_err(|error| error.code()),
            Err(RequestWireErrorCode::CommitmentMismatch)
        );

        let mut unsupported = request.canonical_wire().to_vec();
        unsupported[4..6].copy_from_slice(&(RUNTIME_APPLY_REQUEST_VERSION + 1).to_be_bytes());
        assert_eq!(
            RuntimeApplyRequest::decode(&unsupported).map_err(|error| error.code()),
            Err(RequestWireErrorCode::UnsupportedVersion)
        );

        let mut trailing = request.canonical_wire().to_vec();
        trailing.push(0);
        assert_eq!(
            RuntimeApplyRequest::decode(&trailing).map_err(|error| error.code()),
            Err(RequestWireErrorCode::InvalidFrameLength)
        );
        assert_eq!(
            RuntimeApplyRequest::decode(&vec![0; MAX_RUNTIME_APPLY_REQUEST_BYTES + 1])
                .map_err(|error| error.code()),
            Err(RequestWireErrorCode::FrameTooLarge)
        );

        let other_assignments = target_assignments(&[2]);
        let other_commitment = slice_commitment(other_assignments.assignment_digest());
        let Ok(other_slice) = RuntimePlanSlice::try_new(other_commitment, other_assignments) else {
            panic!("other Slice must be valid");
        };
        assert_eq!(
            RuntimeApplyRequest::try_new(request.envelope().clone(), other_slice),
            Err(AssignmentContractError::EnvelopeSliceMismatch)
        );
    }

    #[test]
    fn wire_reason_codes_are_stable() {
        assert_eq!(
            [
                AssignmentWireErrorCode::FrameTooLarge as u16,
                AssignmentWireErrorCode::Truncated as u16,
                AssignmentWireErrorCode::InvalidMagic as u16,
                AssignmentWireErrorCode::UnsupportedVersion as u16,
                AssignmentWireErrorCode::AssignmentCountExceeded as u16,
                AssignmentWireErrorCode::InvalidFrameLength as u16,
                AssignmentWireErrorCode::InvalidEnumValue as u16,
                AssignmentWireErrorCode::InvalidAssignment as u16,
                AssignmentWireErrorCode::DuplicateBindingId as u16,
                AssignmentWireErrorCode::DuplicateSourceEndpoint as u16,
                AssignmentWireErrorCode::DuplicateTargetEndpoint as u16,
                AssignmentWireErrorCode::NonCanonicalFrame as u16,
                AssignmentWireErrorCode::DuplicateMailboxRef as u16,
            ],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        );
        assert_eq!(
            [
                RequestWireErrorCode::FrameTooLarge as u16,
                RequestWireErrorCode::Truncated as u16,
                RequestWireErrorCode::InvalidMagic as u16,
                RequestWireErrorCode::UnsupportedVersion as u16,
                RequestWireErrorCode::InvalidFrameLength as u16,
                RequestWireErrorCode::EnvelopeRejected as u16,
                RequestWireErrorCode::AssignmentsRejected as u16,
                RequestWireErrorCode::CommitmentMismatch as u16,
            ],
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
    }
}
