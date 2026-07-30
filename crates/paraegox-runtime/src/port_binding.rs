//! Deterministic live-binding lifecycle used by the P2a contract fixture.
//!
//! A binding owns no payload storage and no fallback route. It records one
//! prepared route, at most one route accepting new messages, and at most one
//! older drain-only route. The target [`crate::mailbox::Mailbox`] remains the
//! only semantic backlog owner.

use core::{fmt, num::NonZeroU64};

use paraegox_kernel::time::ClockReading;

use paraegox_runtime_contracts::assignment::{
    BindingAssignment, BindingId, InteractionKind, OverflowPolicy, PortCardinality, PortDirection,
};

use crate::mailbox::{
    Mailbox, MailboxError, MailboxLifecycle, OfferFailure, OfferReport, ValidatedMessage,
};

/// Runtime-owned generation of one installed logical binding.
///
/// Epochs are comparable only when their [`BindingId`] is already known to be
/// identical. Canonical assignment compilation never constructs or advances
/// this value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct BindingEpoch(NonZeroU64);

impl BindingEpoch {
    /// Returns the nonzero runtime-owned generation.
    #[must_use]
    pub(crate) const fn value(self) -> u64 {
        self.0.get()
    }

    fn next_after(last_epoch: u64) -> Result<Self, PortBindingError> {
        let Some(next) = last_epoch.checked_add(1).and_then(NonZeroU64::new) else {
            return Err(PortBindingError::BindingEpochExhausted);
        };
        Ok(Self(next))
    }
}

/// One assignment paired with the runtime epoch at which it became live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BindingRoute {
    assignment: BindingAssignment,
    epoch: BindingEpoch,
}

impl BindingRoute {
    /// Returns the canonical assignment installed for this route.
    #[must_use]
    pub(crate) const fn assignment(self) -> BindingAssignment {
        self.assignment
    }

    /// Returns the route's binding-scoped runtime epoch.
    #[must_use]
    pub(crate) const fn epoch(self) -> BindingEpoch {
        self.epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedBindingRoute {
    route: BindingRoute,
    expected_active: Option<BindingEpoch>,
}

/// Pure single-binding lifecycle state for the deterministic PortBinding fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PortBinding {
    binding_id: BindingId,
    last_live_epoch: u64,
    prepared: Option<PreparedBindingRoute>,
    active: Option<BindingRoute>,
    draining: Option<BindingRoute>,
}

impl PortBinding {
    /// Creates an uninstalled slot for one stable logical binding identity.
    ///
    /// Creating the slot and compiling assignments do not advance a live epoch.
    #[must_use]
    pub(crate) const fn new(binding_id: BindingId) -> Self {
        Self {
            binding_id,
            last_live_epoch: 0,
            prepared: None,
            active: None,
            draining: None,
        }
    }

    /// Returns the one logical binding identity owned by this state machine.
    #[must_use]
    pub(crate) const fn binding_id(&self) -> BindingId {
        self.binding_id
    }

    /// Returns the only route allowed to accept new messages.
    #[must_use]
    pub(crate) const fn active(&self) -> Option<BindingRoute> {
        self.active
    }

    /// Returns the older route retained only for explicit draining and retirement.
    #[must_use]
    pub(crate) const fn draining(&self) -> Option<BindingRoute> {
        self.draining
    }

    /// Returns the prepared, inactive candidate epoch.
    #[must_use]
    pub(crate) const fn prepared_epoch(&self) -> Option<BindingEpoch> {
        match self.prepared {
            Some(prepared) => Some(prepared.route.epoch),
            None => None,
        }
    }

    /// Returns the highest epoch committed by activation or revocation.
    #[must_use]
    pub(crate) const fn last_live_epoch(&self) -> u64 {
        self.last_live_epoch
    }

    /// Validates and prepares an inactive assignment against the exact active route.
    ///
    /// No live epoch advances until [`Self::activate`] succeeds. Failed validation
    /// and rollback therefore leave both the active route and epoch unchanged.
    pub(crate) fn prepare(
        &mut self,
        assignment: BindingAssignment,
        mailbox: &Mailbox,
        expected_active: Option<BindingEpoch>,
    ) -> Result<BindingEpoch, PortBindingError> {
        validate_fixture_assignment(assignment)?;
        if assignment.binding_id() != self.binding_id {
            return Err(PortBindingError::BindingIdentityMismatch);
        }
        if self.prepared.is_some() {
            return Err(PortBindingError::CandidateAlreadyPrepared);
        }
        if self.active.map(BindingRoute::epoch) != expected_active {
            return Err(PortBindingError::ExpectedActiveEpochMismatch);
        }

        validate_mailbox_identity(assignment, mailbox)?;
        let mailbox_snapshot = mailbox.snapshot().map_err(PortBindingError::Mailbox)?;
        if mailbox_snapshot.lifecycle() != MailboxLifecycle::Accepting {
            return Err(PortBindingError::CandidateMailboxNotAccepting);
        }

        if let Some(active) = self.active {
            if active.assignment == assignment {
                return Ok(active.epoch);
            }
            if active.assignment.mailbox() == assignment.mailbox() {
                return Err(PortBindingError::ReplacementMailboxIdentityReused);
            }
        }
        if self.draining.is_some() {
            return Err(PortBindingError::DrainMustRetireBeforePrepare);
        }
        if mailbox_snapshot.queued_items() != 0
            || mailbox_snapshot.inflight_items() != 0
            || mailbox_snapshot.retained_bytes() != 0
        {
            return Err(PortBindingError::CandidateMailboxNotEmpty);
        }

        let epoch = BindingEpoch::next_after(self.last_live_epoch)?;
        self.prepared = Some(PreparedBindingRoute {
            route: BindingRoute { assignment, epoch },
            expected_active,
        });
        Ok(epoch)
    }

    /// Atomically switches new-message admission to the exact prepared route.
    ///
    /// The prior active route becomes drain-only in the same transition. There
    /// is never an intermediate state with two routes accepting new messages.
    pub(crate) fn activate(
        &mut self,
        prepared_epoch: BindingEpoch,
        candidate_mailbox: &Mailbox,
        previous_mailbox: Option<&mut Mailbox>,
    ) -> Result<BindingRoute, PortBindingError> {
        let Some(prepared) = self.prepared else {
            let Some(active) = self.active else {
                return Err(PortBindingError::NoPreparedCandidate);
            };
            if active.epoch != prepared_epoch {
                return Err(PortBindingError::ActiveEpochMismatch);
            }
            if previous_mailbox.is_some() {
                return Err(PortBindingError::UnexpectedPreviousMailbox);
            }
            validate_mailbox_identity(active.assignment, candidate_mailbox)?;
            return Ok(active);
        };
        if prepared.route.epoch != prepared_epoch {
            return Err(PortBindingError::PreparedEpochMismatch);
        }
        if self.active.map(BindingRoute::epoch) != prepared.expected_active {
            return Err(PortBindingError::ExpectedActiveEpochMismatch);
        }
        if self.draining.is_some() {
            return Err(PortBindingError::DrainMustRetireBeforeActivate);
        }

        validate_mailbox_identity(prepared.route.assignment, candidate_mailbox)?;
        let candidate_snapshot = candidate_mailbox
            .snapshot()
            .map_err(PortBindingError::Mailbox)?;
        if candidate_snapshot.lifecycle() != MailboxLifecycle::Accepting {
            return Err(PortBindingError::CandidateMailboxNotAccepting);
        }
        if candidate_snapshot.queued_items() != 0
            || candidate_snapshot.inflight_items() != 0
            || candidate_snapshot.retained_bytes() != 0
        {
            return Err(PortBindingError::CandidateMailboxNotEmpty);
        }

        let previous_active = self.active;
        match (previous_active, previous_mailbox) {
            (Some(previous), Some(mailbox)) => {
                validate_mailbox_identity(previous.assignment, mailbox)?;
                mailbox
                    .stop_accepting()
                    .map_err(PortBindingError::Mailbox)?;
            }
            (Some(_), None) => return Err(PortBindingError::PreviousMailboxRequired),
            (None, Some(_)) => return Err(PortBindingError::UnexpectedPreviousMailbox),
            (None, None) => {}
        }
        self.active = Some(prepared.route);
        self.draining = previous_active;
        self.prepared = None;
        self.last_live_epoch = prepared.route.epoch.value();
        Ok(prepared.route)
    }

    /// Discards the exact inactive candidate without changing the active route.
    pub(crate) fn rollback(
        &mut self,
        prepared_epoch: BindingEpoch,
    ) -> Result<(), PortBindingError> {
        let Some(prepared) = self.prepared else {
            return Err(PortBindingError::NoPreparedCandidate);
        };
        if prepared.route.epoch != prepared_epoch {
            return Err(PortBindingError::PreparedEpochMismatch);
        }
        self.prepared = None;
        Ok(())
    }

    /// Revokes exact active admission and advances this BindingId's live epoch.
    ///
    /// The revoked route becomes drain-only. A later installation receives an
    /// epoch strictly greater than the revocation epoch.
    pub(crate) fn revoke(
        &mut self,
        expected_active: BindingEpoch,
        active_mailbox: &mut Mailbox,
    ) -> Result<BindingEpoch, PortBindingError> {
        if self.prepared.is_some() {
            return Err(PortBindingError::CandidateAlreadyPrepared);
        }
        if self.draining.is_some() {
            return Err(PortBindingError::DrainMustRetireBeforeRevoke);
        }
        let Some(active) = self.active else {
            return Err(PortBindingError::NoActiveRoute);
        };
        if active.epoch != expected_active {
            return Err(PortBindingError::ActiveEpochMismatch);
        }

        validate_mailbox_identity(active.assignment, active_mailbox)?;

        let revocation_epoch = BindingEpoch::next_after(self.last_live_epoch)?;
        active_mailbox
            .stop_accepting()
            .map_err(PortBindingError::Mailbox)?;
        self.active = None;
        self.draining = Some(active);
        self.last_live_epoch = revocation_epoch.value();
        Ok(revocation_epoch)
    }

    /// Retires the exact old route only after its matching Mailbox is closed.
    pub(crate) fn retire_draining(
        &mut self,
        expected_draining: BindingEpoch,
        mailbox: &Mailbox,
    ) -> Result<BindingRoute, PortBindingError> {
        let Some(draining) = self.draining else {
            return Err(PortBindingError::NoDrainingRoute);
        };
        if draining.epoch != expected_draining {
            return Err(PortBindingError::DrainingEpochMismatch);
        }
        validate_mailbox_identity(draining.assignment, mailbox)?;
        let snapshot = mailbox.snapshot().map_err(PortBindingError::Mailbox)?;
        if snapshot.lifecycle() != MailboxLifecycle::Closed {
            return Err(PortBindingError::DrainingMailboxNotClosed);
        }

        self.draining = None;
        Ok(draining)
    }

    /// Offers directly to the exact active route's sole target Mailbox.
    ///
    /// Binding validation retains no payload and performs no fallback, retry,
    /// deduplication, or secondary enqueue. A structural rejection returns the
    /// still-owned Message to the caller.
    pub(crate) fn offer(
        &self,
        binding_id: BindingId,
        binding_epoch: BindingEpoch,
        message: ValidatedMessage,
        mailbox: &mut Mailbox,
        reading: ClockReading,
    ) -> Result<OfferReport, BindingOfferFailure> {
        if binding_id != self.binding_id {
            return Err(BindingOfferFailure::new(
                PortBindingError::BindingIdentityMismatch,
                message,
            ));
        }
        let Some(active) = self.active else {
            return Err(BindingOfferFailure::new(
                PortBindingError::NoActiveRoute,
                message,
            ));
        };
        if active.epoch != binding_epoch {
            return Err(BindingOfferFailure::new(
                PortBindingError::ActiveEpochMismatch,
                message,
            ));
        }
        if let Err(error) = validate_mailbox_identity(active.assignment, mailbox) {
            return Err(BindingOfferFailure::new(error, message));
        }

        mailbox
            .try_offer(message, reading)
            .map_err(BindingOfferFailure::from_mailbox)
    }
}

fn validate_fixture_assignment(assignment: BindingAssignment) -> Result<(), PortBindingError> {
    let source = assignment.source_spec();
    let target = assignment.target_spec();
    if source.direction() != PortDirection::Out {
        return Err(PortBindingError::InvalidSourceDirection);
    }
    if target.direction() != PortDirection::In {
        return Err(PortBindingError::InvalidTargetDirection);
    }
    if source.schema() != target.schema() {
        return Err(PortBindingError::SchemaMismatch);
    }
    if source.interaction() != target.interaction() {
        return Err(PortBindingError::InteractionMismatch);
    }
    if source.cardinality() != PortCardinality::One || target.cardinality() != PortCardinality::One
    {
        return Err(PortBindingError::UnsupportedCardinality);
    }

    let delivery = assignment.delivery();
    let mailbox = assignment.mailbox_spec();
    if delivery.overflow_policy() != mailbox.overflow_policy() {
        return Err(PortBindingError::OverflowPolicyMismatch);
    }
    if mailbox.max_queue_age().value() > delivery.max_message_age().value() {
        return Err(PortBindingError::QueueAgeExceedsDeliveryAge);
    }
    if mailbox.capacity_bytes() < delivery.max_payload_bytes() {
        return Err(PortBindingError::MailboxCannotHoldPayload);
    }
    if mailbox.max_retained_bytes() < mailbox.capacity_bytes() {
        return Err(PortBindingError::MailboxCannotRetainCapacity);
    }
    if source.interaction() == InteractionKind::Event
        && !matches!(
            delivery.overflow_policy(),
            OverflowPolicy::RejectNew | OverflowPolicy::BlockUntilDeadline
        )
    {
        return Err(PortBindingError::EventCannotUseLossyOverflow);
    }
    if delivery.overflow_policy() == OverflowPolicy::BlockUntilDeadline {
        return Err(PortBindingError::BlockingOverflowUnsupportedByFixture);
    }
    Ok(())
}

fn validate_mailbox_identity(
    assignment: BindingAssignment,
    mailbox: &Mailbox,
) -> Result<(), PortBindingError> {
    if mailbox.reference() != assignment.mailbox() {
        return Err(PortBindingError::MailboxIdentityMismatch);
    }
    if mailbox.schema() != assignment.target_spec().schema() {
        return Err(PortBindingError::MailboxSchemaMismatch);
    }
    if mailbox.interaction() != assignment.target_spec().interaction() {
        return Err(PortBindingError::MailboxInteractionMismatch);
    }
    if mailbox.spec() != assignment.mailbox_spec() {
        return Err(PortBindingError::MailboxSpecMismatch);
    }
    Ok(())
}

/// Returns an offered Message when binding validation fails before admission.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct BindingOfferFailure {
    error: PortBindingError,
    message: Box<ValidatedMessage>,
}

impl BindingOfferFailure {
    fn new(error: PortBindingError, message: ValidatedMessage) -> Self {
        Self {
            error,
            message: Box::new(message),
        }
    }

    fn from_mailbox(failure: OfferFailure) -> Self {
        Self {
            error: PortBindingError::Mailbox(failure.error()),
            message: Box::new(failure.into_message()),
        }
    }

    #[must_use]
    pub(crate) const fn error(&self) -> PortBindingError {
        self.error
    }

    #[must_use]
    pub(crate) fn into_message(self) -> ValidatedMessage {
        *self.message
    }
}

/// Stable fail-closed errors for deterministic binding installation and lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PortBindingError {
    BindingIdentityMismatch,
    InvalidSourceDirection,
    InvalidTargetDirection,
    SchemaMismatch,
    InteractionMismatch,
    UnsupportedCardinality,
    OverflowPolicyMismatch,
    QueueAgeExceedsDeliveryAge,
    MailboxCannotHoldPayload,
    MailboxCannotRetainCapacity,
    EventCannotUseLossyOverflow,
    BlockingOverflowUnsupportedByFixture,
    MailboxIdentityMismatch,
    MailboxSchemaMismatch,
    MailboxInteractionMismatch,
    MailboxSpecMismatch,
    CandidateMailboxNotAccepting,
    CandidateMailboxNotEmpty,
    ReplacementMailboxIdentityReused,
    CandidateAlreadyPrepared,
    NoPreparedCandidate,
    PreparedEpochMismatch,
    ExpectedActiveEpochMismatch,
    ActiveEpochMismatch,
    NoActiveRoute,
    DrainMustRetireBeforePrepare,
    DrainMustRetireBeforeActivate,
    DrainMustRetireBeforeRevoke,
    PreviousMailboxRequired,
    UnexpectedPreviousMailbox,
    NoDrainingRoute,
    DrainingEpochMismatch,
    DrainingMailboxNotClosed,
    BindingEpochExhausted,
    Mailbox(MailboxError),
}

impl fmt::Display for PortBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BindingIdentityMismatch => "assignment belongs to a different binding",
            Self::InvalidSourceDirection => "binding source must be an Out port",
            Self::InvalidTargetDirection => "binding target must be an In port",
            Self::SchemaMismatch => "binding endpoint schemas differ",
            Self::InteractionMismatch => "binding endpoint interactions differ",
            Self::UnsupportedCardinality => "binding cardinality is not static one-to-one",
            Self::OverflowPolicyMismatch => "delivery and mailbox overflow policies differ",
            Self::QueueAgeExceedsDeliveryAge => "mailbox age exceeds delivery age",
            Self::MailboxCannotHoldPayload => "mailbox cannot hold one maximum payload",
            Self::MailboxCannotRetainCapacity => "retained-byte budget is below queue capacity",
            Self::EventCannotUseLossyOverflow => "Event assignment uses a lossy overflow policy",
            Self::BlockingOverflowUnsupportedByFixture => {
                "deterministic binding fixture cannot block an offer"
            }
            Self::MailboxIdentityMismatch => "mailbox identity differs from the assignment",
            Self::MailboxSchemaMismatch => "mailbox schema differs from the assignment",
            Self::MailboxInteractionMismatch => "mailbox interaction differs from the assignment",
            Self::MailboxSpecMismatch => "mailbox specification differs from the assignment",
            Self::CandidateMailboxNotAccepting => "candidate mailbox is not accepting",
            Self::CandidateMailboxNotEmpty => "candidate mailbox is not empty",
            Self::ReplacementMailboxIdentityReused => {
                "replacement assignment reuses the active mailbox identity"
            }
            Self::CandidateAlreadyPrepared => "a binding candidate is already prepared",
            Self::NoPreparedCandidate => "no binding candidate is prepared",
            Self::PreparedEpochMismatch => "prepared binding epoch does not match",
            Self::ExpectedActiveEpochMismatch => "expected active binding epoch does not match",
            Self::ActiveEpochMismatch => "active binding epoch does not match",
            Self::NoActiveRoute => "no binding route accepts new messages",
            Self::DrainMustRetireBeforePrepare => {
                "drain-only binding must retire before another prepare"
            }
            Self::DrainMustRetireBeforeActivate => {
                "drain-only binding must retire before activation"
            }
            Self::DrainMustRetireBeforeRevoke => "drain-only binding must retire before revocation",
            Self::PreviousMailboxRequired => "replacement activation requires the old mailbox",
            Self::UnexpectedPreviousMailbox => {
                "initial activation cannot receive a previous mailbox"
            }
            Self::NoDrainingRoute => "no drain-only binding route exists",
            Self::DrainingEpochMismatch => "draining binding epoch does not match",
            Self::DrainingMailboxNotClosed => "draining mailbox has not closed",
            Self::BindingEpochExhausted => "binding epoch is exhausted",
            Self::Mailbox(error) => return write!(formatter, "mailbox transition failed: {error}"),
        })
    }
}

impl std::error::Error for PortBindingError {}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::time::{
        BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant,
    };
    use paraegox_runtime_contracts::assignment::{
        AssignmentContractError, BindingAssignment, BindingId, DeliveryProfile, InstanceRef,
        InteractionKind, MailboxRef, MailboxSpec, OverflowPolicy, PortCardinality, PortDirection,
        PortEndpoint, PortRef, PortSpec, SchemaRef,
    };

    use crate::mailbox::{
        DispatchOutcome, EnqueueOutcome, Mailbox, MailboxLifecycle, MessageId, PayloadHandle,
        TerminalReason, ValidatedMessage,
    };

    use super::{BindingEpoch, PortBinding, PortBindingError};

    fn generation() -> ClockGeneration {
        let Ok(generation) = ClockGeneration::try_new(1) else {
            panic!("test clock generation must be valid");
        };
        generation
    }

    fn reading(now: u64) -> ClockReading {
        ClockReading::new(
            ClockDomainRef::from_bytes([41; 16]),
            generation(),
            MonotonicInstant::from_ticks(now),
        )
    }

    fn schema_with(value: u8) -> SchemaRef {
        let Ok(schema) = SchemaRef::try_new(
            [value; 16],
            1,
            Digest32::from_bytes([value.wrapping_add(1); 32]),
        ) else {
            panic!("test schema must be valid");
        };
        schema
    }

    fn schema() -> SchemaRef {
        schema_with(51)
    }

    fn assignment(
        binding_byte: u8,
        source_port_byte: u8,
        target_instance_byte: u8,
        mailbox_byte: u8,
        overflow: OverflowPolicy,
    ) -> BindingAssignment {
        let port_spec_out = PortSpec::new(
            PortDirection::Out,
            schema(),
            InteractionKind::Signal,
            PortCardinality::One,
        );
        let port_spec_in = PortSpec::new(
            PortDirection::In,
            schema(),
            InteractionKind::Signal,
            PortCardinality::One,
        );
        let Ok(delivery) = DeliveryProfile::try_new(16, BoundedDuration::from_nanos(100), overflow)
        else {
            panic!("test delivery profile must be valid");
        };
        let Ok(mailbox_spec) =
            MailboxSpec::try_new(2, 16, BoundedDuration::from_nanos(50), 1, 32, overflow)
        else {
            panic!("test mailbox spec must be valid");
        };
        let Ok(assignment) = BindingAssignment::try_new(
            BindingId::from_bytes([binding_byte; 16]),
            PortEndpoint::new(
                InstanceRef::from_bytes([61; 16]),
                PortRef::from_bytes([source_port_byte; 16]),
                port_spec_out,
            ),
            PortEndpoint::new(
                InstanceRef::from_bytes([target_instance_byte; 16]),
                PortRef::from_bytes([63; 16]),
                port_spec_in,
            ),
            MailboxRef::from_bytes([mailbox_byte; 16]),
            delivery,
            mailbox_spec,
        ) else {
            panic!("test assignment must be valid");
        };
        assignment
    }

    fn mailbox_for(assignment: BindingAssignment) -> Mailbox {
        let Ok(mailbox) = Mailbox::try_new(
            assignment.mailbox(),
            assignment.target_spec().schema(),
            assignment.target_spec().interaction(),
            assignment.mailbox_spec(),
            reading(0).domain(),
            generation(),
        ) else {
            panic!("test mailbox must be valid");
        };
        mailbox
    }

    fn message(id: u8, assignment: BindingAssignment) -> ValidatedMessage {
        let Ok(deadline) = reading(0).try_deadline_after(BoundedDuration::from_nanos(100)) else {
            panic!("test deadline must be representable");
        };
        let Ok(payload) = PayloadHandle::try_from_vec(vec![id; 4]) else {
            panic!("test payload must be representable");
        };
        ValidatedMessage::new(
            MessageId::from_bytes([id; 16]),
            assignment.target_spec().schema(),
            assignment.target_spec().interaction(),
            None,
            deadline,
            payload,
        )
    }

    fn explicit_epoch(value: u64) -> BindingEpoch {
        let Some(value) = NonZeroU64::new(value) else {
            panic!("test epoch must be nonzero");
        };
        BindingEpoch(value)
    }

    #[test]
    fn prepare_is_inactive_and_exact_active_install_is_idempotent() {
        let assignment = assignment(1, 2, 3, 4, OverflowPolicy::RejectNew);
        let mailbox = mailbox_for(assignment);
        let mut binding = PortBinding::new(assignment.binding_id());

        let Ok(first_epoch) = binding.prepare(assignment, &mailbox, None) else {
            panic!("valid initial assignment must prepare");
        };
        assert_eq!(first_epoch.value(), 1);
        assert_eq!(binding.last_live_epoch(), 0);
        assert_eq!(binding.active(), None);
        assert_eq!(binding.prepared_epoch(), Some(first_epoch));

        let Ok(active) = binding.activate(first_epoch, &mailbox, None) else {
            panic!("prepared initial route must activate");
        };
        assert_eq!(active.epoch(), first_epoch);
        assert_eq!(active.assignment(), assignment);
        assert_eq!(binding.last_live_epoch(), 1);

        let Ok(same_epoch) = binding.prepare(assignment, &mailbox, Some(first_epoch)) else {
            panic!("exact active assignment must be idempotent");
        };
        assert_eq!(same_epoch, first_epoch);
        assert_eq!(binding.prepared_epoch(), None);
        assert_eq!(binding.last_live_epoch(), 1);

        let Ok(replayed) = binding.activate(first_epoch, &mailbox, None) else {
            panic!("exact activation replay must return the existing route");
        };
        assert_eq!(replayed, active);
        assert_eq!(binding.last_live_epoch(), 1);
    }

    #[test]
    fn invalid_assignments_and_mailbox_mismatches_have_zero_binding_side_effects() {
        let base_assignment = assignment(10, 11, 12, 13, OverflowPolicy::RejectNew);
        let mut binding = PortBinding::new(base_assignment.binding_id());
        let initial = binding.clone();

        let foreign = assignment(20, 11, 12, 13, OverflowPolicy::RejectNew);
        let foreign_mailbox = mailbox_for(foreign);
        assert_eq!(
            binding.prepare(foreign, &foreign_mailbox, None),
            Err(PortBindingError::BindingIdentityMismatch)
        );
        assert_eq!(binding, initial);

        let wrong_mailbox_assignment = assignment(10, 11, 12, 14, OverflowPolicy::RejectNew);
        let wrong_mailbox = mailbox_for(wrong_mailbox_assignment);
        assert_eq!(
            binding.prepare(base_assignment, &wrong_mailbox, None),
            Err(PortBindingError::MailboxIdentityMismatch)
        );
        assert_eq!(binding, initial);

        let Ok(wrong_schema_mailbox) = Mailbox::try_new(
            base_assignment.mailbox(),
            schema_with(53),
            InteractionKind::Signal,
            base_assignment.mailbox_spec(),
            reading(0).domain(),
            generation(),
        ) else {
            panic!("wrong-schema test mailbox must still be structurally valid");
        };
        assert_eq!(
            binding.prepare(base_assignment, &wrong_schema_mailbox, None),
            Err(PortBindingError::MailboxSchemaMismatch)
        );
        assert_eq!(binding, initial);

        let Ok(wrong_interaction_mailbox) = Mailbox::try_new(
            base_assignment.mailbox(),
            base_assignment.target_spec().schema(),
            InteractionKind::Event,
            base_assignment.mailbox_spec(),
            reading(0).domain(),
            generation(),
        ) else {
            panic!("wrong-interaction test mailbox must still be structurally valid");
        };
        assert_eq!(
            binding.prepare(base_assignment, &wrong_interaction_mailbox, None),
            Err(PortBindingError::MailboxInteractionMismatch)
        );
        assert_eq!(binding, initial);

        let Ok(wrong_spec) = MailboxSpec::try_new(
            3,
            16,
            BoundedDuration::from_nanos(50),
            1,
            32,
            OverflowPolicy::RejectNew,
        ) else {
            panic!("wrong-spec test value must be structurally valid");
        };
        let Ok(wrong_spec_mailbox) = Mailbox::try_new(
            base_assignment.mailbox(),
            base_assignment.target_spec().schema(),
            base_assignment.target_spec().interaction(),
            wrong_spec,
            reading(0).domain(),
            generation(),
        ) else {
            panic!("wrong-spec test mailbox must still be structurally valid");
        };
        assert_eq!(
            binding.prepare(base_assignment, &wrong_spec_mailbox, None),
            Err(PortBindingError::MailboxSpecMismatch)
        );
        assert_eq!(binding, initial);

        let blocking = assignment(10, 11, 12, 13, OverflowPolicy::BlockUntilDeadline);
        let blocking_mailbox = mailbox_for(blocking);
        assert_eq!(
            binding.prepare(blocking, &blocking_mailbox, None),
            Err(PortBindingError::BlockingOverflowUnsupportedByFixture)
        );
        assert_eq!(binding, initial);

        let invalid_source = PortSpec::new(
            PortDirection::In,
            schema(),
            InteractionKind::Signal,
            PortCardinality::One,
        );
        let valid_target = PortSpec::new(
            PortDirection::In,
            schema(),
            InteractionKind::Signal,
            PortCardinality::One,
        );
        let Ok(delivery) = DeliveryProfile::try_new(
            16,
            BoundedDuration::from_nanos(100),
            OverflowPolicy::RejectNew,
        ) else {
            panic!("test delivery must be valid");
        };
        let Ok(spec) = MailboxSpec::try_new(
            1,
            16,
            BoundedDuration::from_nanos(50),
            1,
            16,
            OverflowPolicy::RejectNew,
        ) else {
            panic!("test mailbox spec must be valid");
        };
        let invalid = BindingAssignment::try_new(
            base_assignment.binding_id(),
            PortEndpoint::new(
                InstanceRef::from_bytes([1; 16]),
                PortRef::from_bytes([2; 16]),
                invalid_source,
            ),
            PortEndpoint::new(
                InstanceRef::from_bytes([3; 16]),
                PortRef::from_bytes([4; 16]),
                valid_target,
            ),
            MailboxRef::from_bytes([5; 16]),
            delivery,
            spec,
        );
        assert_eq!(
            invalid.err(),
            Some(AssignmentContractError::InvalidSourceDirection)
        );
        assert_eq!(binding, initial);
    }

    #[test]
    fn replacement_rolls_back_or_switches_once_then_drains_and_retires_old_route() {
        let first = assignment(30, 31, 32, 33, OverflowPolicy::RejectNew);
        let second = assignment(30, 34, 35, 36, OverflowPolicy::RejectNew);
        let mut first_mailbox = mailbox_for(first);
        let mut second_mailbox = mailbox_for(second);
        let mut binding = PortBinding::new(first.binding_id());

        let Ok(first_epoch) = binding.prepare(first, &first_mailbox, None) else {
            panic!("first assignment must prepare");
        };
        let Ok(_) = binding.activate(first_epoch, &first_mailbox, None) else {
            panic!("first assignment must activate");
        };
        let Ok(report) = binding.offer(
            first.binding_id(),
            first_epoch,
            message(1, first),
            &mut first_mailbox,
            reading(0),
        ) else {
            panic!("active route must offer to its mailbox");
        };
        assert!(report.outcome().is_admitted());

        let Ok(second_epoch) = binding.prepare(second, &second_mailbox, Some(first_epoch)) else {
            panic!("replacement assignment must prepare");
        };
        assert_eq!(second_epoch.value(), 2);
        assert_eq!(binding.last_live_epoch(), 1);
        let Ok(()) = binding.rollback(second_epoch) else {
            panic!("prepared replacement must roll back");
        };
        assert_eq!(
            binding.active().map(|route| route.epoch()),
            Some(first_epoch)
        );
        assert_eq!(binding.last_live_epoch(), 1);
        let Ok(first_snapshot) = first_mailbox.snapshot() else {
            panic!("mailbox snapshot must be valid");
        };
        assert_eq!(first_snapshot.lifecycle(), MailboxLifecycle::Accepting);

        let Ok(second_epoch) = binding.prepare(second, &second_mailbox, Some(first_epoch)) else {
            panic!("replacement assignment must prepare again");
        };
        let Ok(active) = binding.activate(second_epoch, &second_mailbox, Some(&mut first_mailbox))
        else {
            panic!("replacement activation must switch admission once");
        };
        assert_eq!(active.epoch(), second_epoch);
        assert_eq!(
            binding.active().map(|route| route.epoch()),
            Some(second_epoch)
        );
        assert_eq!(
            binding.draining().map(|route| route.epoch()),
            Some(first_epoch)
        );
        let Ok(replayed_epoch) = binding.prepare(second, &second_mailbox, Some(second_epoch))
        else {
            panic!("exact active replacement must replay while its predecessor drains");
        };
        assert_eq!(replayed_epoch, second_epoch);
        let Ok(replayed_route) = binding.activate(second_epoch, &second_mailbox, None) else {
            panic!("exact active replacement activation must replay");
        };
        assert_eq!(replayed_route, active);
        let Ok(first_snapshot) = first_mailbox.snapshot() else {
            panic!("old mailbox snapshot must be valid");
        };
        assert_eq!(first_snapshot.lifecycle(), MailboxLifecycle::Draining);

        let first_before_stale = first_mailbox.snapshot();
        let second_before = second_mailbox.snapshot();
        let stale = binding.offer(
            first.binding_id(),
            first_epoch,
            message(2, first),
            &mut first_mailbox,
            reading(0),
        );
        let Err(stale) = stale else {
            panic!("old route epoch must not accept new messages");
        };
        assert_eq!(stale.error(), PortBindingError::ActiveEpochMismatch);
        assert_eq!(stale.into_message().id(), MessageId::from_bytes([2; 16]));
        assert_eq!(first_mailbox.snapshot(), first_before_stale);
        assert_eq!(second_mailbox.snapshot(), second_before);
        assert_eq!(
            binding.retire_draining(first_epoch, &first_mailbox),
            Err(PortBindingError::DrainingMailboxNotClosed)
        );

        let Ok(dispatch) = first_mailbox.try_begin_inflight(reading(1)) else {
            panic!("old mailbox must drain its admitted message");
        };
        let (outcome, expired) = dispatch.into_parts();
        assert!(expired.is_empty());
        let DispatchOutcome::Started(token) = outcome else {
            panic!("old admitted message must become in-flight");
        };
        let Ok(record) = first_mailbox.finish(token, TerminalReason::Completed) else {
            panic!("old in-flight message must reach terminal");
        };
        assert_eq!(record.reason(), TerminalReason::Completed);
        let Ok(retired) = binding.retire_draining(first_epoch, &first_mailbox) else {
            panic!("closed old mailbox must retire");
        };
        assert_eq!(retired.epoch(), first_epoch);
        assert_eq!(binding.draining(), None);

        let reused = assignment(30, 37, 38, 36, OverflowPolicy::RejectNew);
        let reused_mailbox = mailbox_for(reused);
        let before_reused = binding.clone();
        assert_eq!(
            binding.prepare(reused, &reused_mailbox, Some(second_epoch)),
            Err(PortBindingError::ReplacementMailboxIdentityReused)
        );
        assert_eq!(binding, before_reused);

        let Ok(()) = second_mailbox.stop_accepting() else {
            panic!("active mailbox must close cleanly");
        };
        let Ok(closed) = binding.offer(
            second.binding_id(),
            second_epoch,
            message(3, second),
            &mut second_mailbox,
            reading(1),
        ) else {
            panic!("active binding must propagate its mailbox outcome");
        };
        assert!(matches!(closed.outcome(), EnqueueOutcome::Closed { .. }));
    }

    #[test]
    fn revoke_advances_epoch_and_requires_closed_drain_before_reinstall() {
        let first = assignment(40, 41, 42, 43, OverflowPolicy::RejectNew);
        let next = assignment(40, 44, 45, 46, OverflowPolicy::RejectNew);
        let mut first_mailbox = mailbox_for(first);
        let next_mailbox = mailbox_for(next);
        let mut binding = PortBinding::new(first.binding_id());

        let Ok(first_epoch) = binding.prepare(first, &first_mailbox, None) else {
            panic!("first assignment must prepare");
        };
        let Ok(_) = binding.activate(first_epoch, &first_mailbox, None) else {
            panic!("first assignment must activate");
        };
        let Ok(revocation_epoch) = binding.revoke(first_epoch, &mut first_mailbox) else {
            panic!("exact active route must revoke");
        };
        assert_eq!(revocation_epoch.value(), 2);
        assert_eq!(binding.active(), None);
        assert_eq!(
            binding.draining().map(|route| route.epoch()),
            Some(first_epoch)
        );
        assert_eq!(
            first_mailbox
                .snapshot()
                .map(|snapshot| snapshot.lifecycle()),
            Ok(MailboxLifecycle::Closed)
        );

        let Ok(_) = binding.retire_draining(first_epoch, &first_mailbox) else {
            panic!("empty revoked mailbox must retire");
        };
        let Ok(next_epoch) = binding.prepare(next, &next_mailbox, None) else {
            panic!("post-revocation replacement must prepare");
        };
        assert_eq!(next_epoch.value(), 3);
        assert_eq!(binding.last_live_epoch(), 2);
    }

    #[test]
    fn equal_epoch_numbers_are_isolated_by_binding_and_instance() {
        let first = assignment(70, 71, 72, 73, OverflowPolicy::RejectNew);
        let second = assignment(80, 81, 82, 83, OverflowPolicy::RejectNew);
        let mut first_mailbox = mailbox_for(first);
        let mut second_mailbox = mailbox_for(second);
        let mut first_binding = PortBinding::new(first.binding_id());
        let mut second_binding = PortBinding::new(second.binding_id());

        let Ok(first_epoch) = first_binding.prepare(first, &first_mailbox, None) else {
            panic!("first binding must prepare");
        };
        let Ok(second_epoch) = second_binding.prepare(second, &second_mailbox, None) else {
            panic!("second binding must prepare");
        };
        assert_eq!(first_epoch.value(), second_epoch.value());
        let Ok(_) = first_binding.activate(first_epoch, &first_mailbox, None) else {
            panic!("first binding must activate");
        };
        let Ok(_) = second_binding.activate(second_epoch, &second_mailbox, None) else {
            panic!("second binding must activate");
        };

        let Ok(first_report) = first_binding.offer(
            first.binding_id(),
            first_epoch,
            message(1, first),
            &mut first_mailbox,
            reading(0),
        ) else {
            panic!("first binding must offer independently");
        };
        let Ok(second_report) = second_binding.offer(
            second.binding_id(),
            second_epoch,
            message(2, second),
            &mut second_mailbox,
            reading(0),
        ) else {
            panic!("second binding must offer independently");
        };
        assert!(first_report.outcome().is_admitted());
        assert!(second_report.outcome().is_admitted());
        assert_eq!(
            first_mailbox
                .snapshot()
                .map(|snapshot| snapshot.queued_items()),
            Ok(1)
        );
        assert_eq!(
            second_mailbox
                .snapshot()
                .map(|snapshot| snapshot.queued_items()),
            Ok(1)
        );

        let first_before = first_mailbox.snapshot();
        let second_before = second_mailbox.snapshot();
        let wrong_binding = first_binding.offer(
            second.binding_id(),
            first_epoch,
            message(3, first),
            &mut first_mailbox,
            reading(0),
        );
        let Err(wrong_binding) = wrong_binding else {
            panic!("foreign BindingId must be rejected");
        };
        assert_eq!(
            wrong_binding.error(),
            PortBindingError::BindingIdentityMismatch
        );
        assert_eq!(first_mailbox.snapshot(), first_before);
        assert_eq!(second_mailbox.snapshot(), second_before);

        let Ok(()) = first_mailbox.stop_accepting() else {
            panic!("first mailbox must enter drain");
        };
        assert_eq!(
            first_mailbox
                .snapshot()
                .map(|snapshot| snapshot.lifecycle()),
            Ok(MailboxLifecycle::Draining)
        );
        assert_eq!(
            second_mailbox
                .snapshot()
                .map(|snapshot| snapshot.lifecycle()),
            Ok(MailboxLifecycle::Accepting)
        );
        assert_ne!(first.target_instance(), second.target_instance());
        assert_eq!(explicit_epoch(1), first_epoch);
    }
}
