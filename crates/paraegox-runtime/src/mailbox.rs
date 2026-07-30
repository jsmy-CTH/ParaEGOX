//! Pure, bounded target-mailbox state transitions.
//!
//! This module deliberately has no waiting, task, thread, clock-reading, or
//! I/O owner. Callers supply target-local [`ClockReading`] values. The mailbox
//! owns the only semantic queue and moves a payload into an explicit in-flight
//! token only after an outstanding permit is available.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use paraegox_kernel::time::{
    BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicDeadline, TimeError,
};
use paraegox_runtime_contracts::assignment::{
    InteractionKind, MailboxRef, MailboxSpec, OverflowPolicy, SchemaRef,
};

/// Identifies one immutable logical message within an active mailbox cohort.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct MessageId([u8; 16]);

impl MessageId {
    /// Creates a message identity from opaque canonical bytes.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical identity bytes.
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Identifies a producer-validated equivalence class for coalescing Signals.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct CoalesceKey([u8; 16]);

impl CoalesceKey {
    /// Creates a coalescing key from opaque canonical bytes.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// A single-owner immutable payload and its exact retained-byte charge.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PayloadHandle {
    bytes: Box<[u8]>,
    charged_bytes: u64,
}

impl PayloadHandle {
    /// Takes ownership of payload bytes and fixes their retained-byte charge.
    pub(crate) fn try_from_vec(bytes: Vec<u8>) -> Result<Self, MailboxError> {
        let charged_bytes =
            u64::try_from(bytes.len()).map_err(|_| MailboxError::PayloadSizeOverflow)?;
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            charged_bytes,
        })
    }

    /// Returns an immutable payload view.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the exact retained-byte charge.
    #[must_use]
    pub(crate) const fn charged_bytes(&self) -> u64 {
        self.charged_bytes
    }
}

/// A fully validated logical Message ready for target-mailbox admission.
///
/// Constructing this value does not authenticate transport bytes. Its caller
/// is the validation owner and supplies temporal bounds already installed in
/// the target clock domain and generation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ValidatedMessage {
    id: MessageId,
    schema: SchemaRef,
    class: MessageClass,
    coalesce_key: Option<CoalesceKey>,
    fresh_until: MonotonicDeadline,
    run_deadline: MonotonicDeadline,
    payload: PayloadHandle,
}

impl ValidatedMessage {
    /// Creates one immutable, target-local validated Message using the legacy
    /// single deadline for both freshness and latest-run-start enforcement.
    #[must_use]
    pub(crate) const fn new(
        id: MessageId,
        schema: SchemaRef,
        interaction: InteractionKind,
        coalesce_key: Option<CoalesceKey>,
        deadline: MonotonicDeadline,
        payload: PayloadHandle,
    ) -> Self {
        Self {
            id,
            schema,
            class: MessageClass::from_interaction(interaction),
            coalesce_key,
            fresh_until: deadline,
            run_deadline: deadline,
            payload,
        }
    }

    /// Creates one immutable Message with independent freshness and run bounds.
    #[must_use]
    pub(crate) const fn new_with_deadlines(
        id: MessageId,
        schema: SchemaRef,
        interaction: InteractionKind,
        coalesce_key: Option<CoalesceKey>,
        fresh_until: MonotonicDeadline,
        run_deadline: MonotonicDeadline,
        payload: PayloadHandle,
    ) -> Self {
        Self {
            id,
            schema,
            class: MessageClass::from_interaction(interaction),
            coalesce_key,
            fresh_until,
            run_deadline,
            payload,
        }
    }

    /// Returns the Message identity.
    #[must_use]
    pub(crate) const fn id(&self) -> MessageId {
        self.id
    }

    /// Returns the payload schema.
    #[must_use]
    pub(crate) const fn schema(&self) -> SchemaRef {
        self.schema
    }

    /// Returns the interaction kind.
    #[must_use]
    pub(crate) const fn interaction(&self) -> Option<InteractionKind> {
        self.class.assignment_interaction()
    }

    /// Returns the optional producer-validated coalescing key.
    #[must_use]
    pub(crate) const fn coalesce_key(&self) -> Option<CoalesceKey> {
        self.coalesce_key
    }

    /// Returns the target-local freshness boundary.
    #[must_use]
    pub(crate) const fn fresh_until(&self) -> MonotonicDeadline {
        self.fresh_until
    }

    /// Returns the target-local latest run-start boundary.
    #[must_use]
    pub(crate) const fn run_deadline(&self) -> MonotonicDeadline {
        self.run_deadline
    }

    /// Returns the legacy Message deadline alias (the run deadline).
    #[must_use]
    pub(crate) const fn deadline(&self) -> MonotonicDeadline {
        self.run_deadline
    }

    /// Returns the immutable payload.
    #[must_use]
    pub(crate) const fn payload(&self) -> &PayloadHandle {
        &self.payload
    }
}

/// Internal pressure class. `Command` exists only for the standalone P2a
/// mailbox conformance fixture; it is not a public assignment interaction or
/// a claim that a Command endpoint/Receipt owner exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageClass {
    Signal,
    Event,
    Command,
}

impl MessageClass {
    const fn from_interaction(interaction: InteractionKind) -> Self {
        match interaction {
            InteractionKind::Signal => Self::Signal,
            InteractionKind::Event => Self::Event,
        }
    }

    const fn assignment_interaction(self) -> Option<InteractionKind> {
        match self {
            Self::Signal => Some(InteractionKind::Signal),
            Self::Event => Some(InteractionKind::Event),
            Self::Command => None,
        }
    }
}

#[cfg(test)]
impl ValidatedMessage {
    fn new_command_fixture(
        id: MessageId,
        schema: SchemaRef,
        deadline: MonotonicDeadline,
        payload: PayloadHandle,
    ) -> Self {
        Self {
            id,
            schema,
            class: MessageClass::Command,
            coalesce_key: None,
            fresh_until: deadline,
            run_deadline: deadline,
            payload,
        }
    }
}

/// Mailbox admission rejection before a Message joins the admitted cohort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectionReason {
    SchemaMismatch,
    InteractionMismatch,
    DuplicateActiveMessage,
    PayloadTooLarge,
    MissingCoalesceKey,
    CapacityFull,
    RetainedCapacityFull,
}

/// Terminal reason for a Message that had already been admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalReason {
    Completed,
    Failed,
    Cancelled,
    ExpiredAfterAdmission,
    StaleBeforeRun,
    RunDeadlineExpired,
    QueueAgeExpired,
    Evicted,
    Coalesced,
    Uncertain,
}

impl TerminalReason {
    const fn is_inflight_completion(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Failed
                | Self::Cancelled
                | Self::ExpiredAfterAdmission
                | Self::StaleBeforeRun
                | Self::RunDeadlineExpired
                | Self::Uncertain
        )
    }
}

/// Immediate evidence for one admitted Message reaching a terminal state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TerminalRecord {
    message_id: MessageId,
    reason: TerminalReason,
    released_bytes: u64,
}

impl TerminalRecord {
    const fn new(message_id: MessageId, reason: TerminalReason, released_bytes: u64) -> Self {
        Self {
            message_id,
            reason,
            released_bytes,
        }
    }

    /// Returns the terminal Message identity.
    #[must_use]
    pub(crate) const fn message_id(self) -> MessageId {
        self.message_id
    }

    /// Returns the terminal reason.
    #[must_use]
    pub(crate) const fn reason(self) -> TerminalReason {
        self.reason
    }

    /// Returns the payload bytes released by the mailbox cohort.
    #[must_use]
    pub(crate) const fn released_bytes(self) -> u64 {
        self.released_bytes
    }
}

/// The terminal result of one non-blocking enqueue attempt.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum EnqueueOutcome {
    /// The new Message joined the admitted cohort.
    Admitted,
    /// The Message was rejected and remains owned by the caller.
    Rejected {
        reason: RejectionReason,
        message: ValidatedMessage,
    },
    /// The Message expired before admission and remains caller-owned.
    ExpiredBeforeAdmission { message: ValidatedMessage },
    /// Admission is closed and the Message remains caller-owned.
    Closed { message: ValidatedMessage },
    /// Capacity is unavailable for a policy requiring an execution owner.
    ///
    /// P2a never waits and never retains a waiter. The Message is returned to
    /// its caller together with the latest deadline at which a later owner may
    /// choose to retry. This immediate refusal counts as `rejected` in offer
    /// conservation even though its structured outcome remains distinct.
    WouldBlock {
        message: ValidatedMessage,
        deadline: MonotonicDeadline,
    },
}

impl EnqueueOutcome {
    /// Reports whether this attempt admitted the new Message.
    #[must_use]
    pub(crate) const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted)
    }
}

/// One enqueue outcome plus terminals caused atomically by expiry/replacement.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OfferReport {
    outcome: EnqueueOutcome,
    terminals: Vec<TerminalRecord>,
}

impl OfferReport {
    /// Returns the immediate enqueue outcome.
    #[must_use]
    pub(crate) const fn outcome(&self) -> &EnqueueOutcome {
        &self.outcome
    }

    /// Returns terminal records emitted during the same atomic transition.
    #[must_use]
    pub(crate) fn terminals(&self) -> &[TerminalRecord] {
        &self.terminals
    }
}

/// Returns ownership of a Message when structural mailbox validation fails.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OfferFailure {
    error: MailboxError,
    message: Box<ValidatedMessage>,
}

impl OfferFailure {
    fn new(error: MailboxError, message: ValidatedMessage) -> Self {
        Self {
            error,
            message: Box::new(message),
        }
    }

    /// Returns the fail-closed structural error.
    #[must_use]
    pub(crate) const fn error(&self) -> MailboxError {
        self.error
    }

    /// Recovers the Message that was not admitted.
    #[must_use]
    pub(crate) fn into_message(self) -> ValidatedMessage {
        *self.message
    }
}

/// Mailbox lifecycle. Draining accepts no new Messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MailboxLifecycle {
    Accepting,
    Draining,
    Closed,
}

/// Cumulative terminal-offer counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OfferCounters {
    offered: u64,
    admitted: u64,
    rejected: u64,
    closed: u64,
    expired_before_admission: u64,
}

impl OfferCounters {
    /// Returns structured offer decisions, including explicit pressure refusal.
    #[must_use]
    pub(crate) const fn offered(self) -> u64 {
        self.offered
    }

    #[must_use]
    pub(crate) const fn admitted(self) -> u64 {
        self.admitted
    }

    #[must_use]
    pub(crate) const fn rejected(self) -> u64 {
        self.rejected
    }

    #[must_use]
    pub(crate) const fn closed(self) -> u64 {
        self.closed
    }

    #[must_use]
    pub(crate) const fn expired_before_admission(self) -> u64 {
        self.expired_before_admission
    }

    fn checked_terminal(self, category: OfferCategory) -> Result<Self, MailboxError> {
        let mut next = self;
        next.offered = next
            .offered
            .checked_add(1)
            .ok_or(MailboxError::CounterOverflow)?;
        match category {
            OfferCategory::Admitted => {
                next.admitted = next
                    .admitted
                    .checked_add(1)
                    .ok_or(MailboxError::CounterOverflow)?;
            }
            OfferCategory::Rejected => {
                next.rejected = next
                    .rejected
                    .checked_add(1)
                    .ok_or(MailboxError::CounterOverflow)?;
            }
            OfferCategory::Closed => {
                next.closed = next
                    .closed
                    .checked_add(1)
                    .ok_or(MailboxError::CounterOverflow)?;
            }
            OfferCategory::ExpiredBeforeAdmission => {
                next.expired_before_admission = next
                    .expired_before_admission
                    .checked_add(1)
                    .ok_or(MailboxError::CounterOverflow)?;
            }
        }
        Ok(next)
    }

    fn validate(self) -> Result<(), MailboxError> {
        let terminal_total = self
            .admitted
            .checked_add(self.rejected)
            .and_then(|value| value.checked_add(self.closed))
            .and_then(|value| value.checked_add(self.expired_before_admission))
            .ok_or(MailboxError::StateInconsistent)?;
        if terminal_total != self.offered {
            return Err(MailboxError::StateInconsistent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OfferCategory {
    Admitted,
    Rejected,
    Closed,
    ExpiredBeforeAdmission,
}

/// Cumulative fixed-width counters for admitted-cohort terminals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TerminalCounters {
    completed: u64,
    failed: u64,
    cancelled: u64,
    expired_after_admission: u64,
    stale_before_run: u64,
    run_deadline_expired: u64,
    queue_age_expired: u64,
    evicted: u64,
    coalesced: u64,
    uncertain: u64,
}

impl TerminalCounters {
    #[must_use]
    pub(crate) const fn completed(self) -> u64 {
        self.completed
    }

    #[must_use]
    pub(crate) const fn failed(self) -> u64 {
        self.failed
    }

    #[must_use]
    pub(crate) const fn cancelled(self) -> u64 {
        self.cancelled
    }

    #[must_use]
    pub(crate) const fn expired_after_admission(self) -> u64 {
        self.expired_after_admission
    }

    #[must_use]
    pub(crate) const fn stale_before_run(self) -> u64 {
        self.stale_before_run
    }

    #[must_use]
    pub(crate) const fn run_deadline_expired(self) -> u64 {
        self.run_deadline_expired
    }

    #[must_use]
    pub(crate) const fn queue_age_expired(self) -> u64 {
        self.queue_age_expired
    }

    #[must_use]
    pub(crate) const fn evicted(self) -> u64 {
        self.evicted
    }

    #[must_use]
    pub(crate) const fn coalesced(self) -> u64 {
        self.coalesced
    }

    #[must_use]
    pub(crate) const fn uncertain(self) -> u64 {
        self.uncertain
    }

    fn checked_increment(self, reason: TerminalReason) -> Result<Self, MailboxError> {
        let mut next = self;
        let counter = match reason {
            TerminalReason::Completed => &mut next.completed,
            TerminalReason::Failed => &mut next.failed,
            TerminalReason::Cancelled => &mut next.cancelled,
            TerminalReason::ExpiredAfterAdmission => &mut next.expired_after_admission,
            TerminalReason::StaleBeforeRun => &mut next.stale_before_run,
            TerminalReason::RunDeadlineExpired => &mut next.run_deadline_expired,
            TerminalReason::QueueAgeExpired => &mut next.queue_age_expired,
            TerminalReason::Evicted => &mut next.evicted,
            TerminalReason::Coalesced => &mut next.coalesced,
            TerminalReason::Uncertain => &mut next.uncertain,
        };
        *counter = counter
            .checked_add(1)
            .ok_or(MailboxError::CounterOverflow)?;
        Ok(next)
    }

    fn checked_increment_records(self, records: &[TerminalRecord]) -> Result<Self, MailboxError> {
        records.iter().try_fold(self, |counters, record| {
            counters.checked_increment(record.reason)
        })
    }

    fn total(self) -> Result<u64, MailboxError> {
        self.completed
            .checked_add(self.failed)
            .and_then(|value| value.checked_add(self.cancelled))
            .and_then(|value| value.checked_add(self.expired_after_admission))
            .and_then(|value| value.checked_add(self.stale_before_run))
            .and_then(|value| value.checked_add(self.run_deadline_expired))
            .and_then(|value| value.checked_add(self.queue_age_expired))
            .and_then(|value| value.checked_add(self.evicted))
            .and_then(|value| value.checked_add(self.coalesced))
            .and_then(|value| value.checked_add(self.uncertain))
            .ok_or(MailboxError::StateInconsistent)
    }
}

/// A bounded, read-only snapshot; it contains no payload or unbounded labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MailboxSnapshot {
    lifecycle: MailboxLifecycle,
    queued_items: u32,
    queued_bytes: u64,
    inflight_items: u32,
    inflight_bytes: u64,
    retained_bytes: u64,
    offers: OfferCounters,
    terminals: TerminalCounters,
}

impl MailboxSnapshot {
    #[must_use]
    pub(crate) const fn lifecycle(self) -> MailboxLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub(crate) const fn queued_items(self) -> u32 {
        self.queued_items
    }

    #[must_use]
    pub(crate) const fn queued_bytes(self) -> u64 {
        self.queued_bytes
    }

    #[must_use]
    pub(crate) const fn inflight_items(self) -> u32 {
        self.inflight_items
    }

    #[must_use]
    pub(crate) const fn inflight_bytes(self) -> u64 {
        self.inflight_bytes
    }

    #[must_use]
    pub(crate) const fn retained_bytes(self) -> u64 {
        self.retained_bytes
    }

    #[must_use]
    pub(crate) const fn offers(self) -> OfferCounters {
        self.offers
    }

    #[must_use]
    pub(crate) const fn terminals(self) -> TerminalCounters {
        self.terminals
    }
}

struct QueuedMessage {
    message: ValidatedMessage,
    queue_age_deadline: MonotonicDeadline,
}

/// A fixed-size, payload-free view of the current FIFO head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MailboxHeadHint {
    mailbox: MailboxRef,
    message_id: MessageId,
    charged_bytes: u64,
    fresh_until: MonotonicDeadline,
    run_deadline: MonotonicDeadline,
    queue_age_deadline: MonotonicDeadline,
}

impl MailboxHeadHint {
    #[must_use]
    pub(crate) const fn mailbox(self) -> MailboxRef {
        self.mailbox
    }

    #[must_use]
    pub(crate) const fn message_id(self) -> MessageId {
        self.message_id
    }

    #[must_use]
    pub(crate) const fn charged_bytes(self) -> u64 {
        self.charged_bytes
    }

    #[must_use]
    pub(crate) const fn fresh_until(self) -> MonotonicDeadline {
        self.fresh_until
    }

    #[must_use]
    pub(crate) const fn run_deadline(self) -> MonotonicDeadline {
        self.run_deadline
    }

    #[must_use]
    pub(crate) const fn queue_age_deadline(self) -> MonotonicDeadline {
        self.queue_age_deadline
    }
}

/// Read-only bounded readiness for the single-owner dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MailboxHeadReadiness {
    Ready(MailboxHeadHint),
    Expired {
        hint: MailboxHeadHint,
        reason: TerminalReason,
    },
    Empty,
    NoPermit(MailboxHeadHint),
    Closed,
}

impl MailboxHeadReadiness {
    #[must_use]
    pub(crate) const fn is_dispatchable(self) -> bool {
        matches!(self, Self::Ready(_))
    }

    #[must_use]
    pub(crate) const fn hint(self) -> Option<MailboxHeadHint> {
        match self {
            Self::Ready(hint) | Self::Expired { hint, .. } | Self::NoPermit(hint) => Some(hint),
            Self::Empty | Self::Closed => None,
        }
    }
}

struct InflightAccounting {
    token_generation: u64,
    payload_bytes: u64,
}

/// The unique owner of one in-flight payload.
///
/// The token is intentionally not `Clone`. Dropping it before `finish` leaves
/// the mailbox's bounded accounting conservatively occupied until the runtime
/// owner explicitly declares abandoned in-flight work uncertain.
#[must_use = "an in-flight token must be finished or explicitly abandoned by its runtime owner"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InflightToken {
    mailbox: MailboxRef,
    token_generation: u64,
    message: ValidatedMessage,
}

impl InflightToken {
    /// Returns the in-flight Message without transferring payload ownership.
    #[must_use]
    pub(crate) const fn message(&self) -> &ValidatedMessage {
        &self.message
    }
}

/// Dispatch decision after expiry and outstanding-permit evaluation.
#[must_use = "a dispatch decision can contain the sole owner of an in-flight payload"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DispatchOutcome {
    Started(InflightToken),
    NoQueuedMessage,
    NoPermit,
    Closed,
}

/// One dispatch decision plus Message terminals caused by queue-age expiry.
#[must_use = "a dispatch report can contain the sole owner of an in-flight payload"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DispatchReport {
    outcome: DispatchOutcome,
    expired: Vec<TerminalRecord>,
}

impl DispatchReport {
    pub(crate) const fn outcome(&self) -> &DispatchOutcome {
        &self.outcome
    }

    #[must_use]
    pub(crate) fn expired(&self) -> &[TerminalRecord] {
        &self.expired
    }

    /// Splits the report so an in-flight token can be moved to its owner.
    pub(crate) fn into_parts(self) -> (DispatchOutcome, Vec<TerminalRecord>) {
        (self.outcome, self.expired)
    }
}

/// Returns an in-flight payload token when a terminal transition is rejected.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FinishFailure {
    error: MailboxError,
    token: Box<InflightToken>,
}

impl FinishFailure {
    fn new(error: MailboxError, token: InflightToken) -> Self {
        Self {
            error,
            token: Box::new(token),
        }
    }

    #[must_use]
    pub(crate) const fn error(&self) -> MailboxError {
        self.error
    }

    pub(crate) fn into_token(self) -> InflightToken {
        *self.token
    }
}

#[derive(Clone, Copy)]
struct MailboxLimits {
    capacity_items: u32,
    capacity_bytes: u64,
    max_queue_age: BoundedDuration,
    max_inflight: u32,
    max_retained_bytes: u64,
    overflow: OverflowPolicy,
}

/// Pure, single-owner mailbox state.
pub(crate) struct Mailbox {
    reference: MailboxRef,
    schema: SchemaRef,
    interaction: InteractionKind,
    message_class: MessageClass,
    spec: MailboxSpec,
    clock_domain: ClockDomainRef,
    clock_generation: ClockGeneration,
    limits: MailboxLimits,
    lifecycle: MailboxLifecycle,
    queue: VecDeque<QueuedMessage>,
    inflight: BTreeMap<MessageId, InflightAccounting>,
    queued_bytes: u64,
    inflight_bytes: u64,
    next_token_generation: u64,
    offers: OfferCounters,
    terminals: TerminalCounters,
}

impl Mailbox {
    /// Creates an empty mailbox from one compiled assignment.
    pub(crate) fn try_new(
        reference: MailboxRef,
        schema: SchemaRef,
        interaction: InteractionKind,
        spec: MailboxSpec,
        clock_domain: ClockDomainRef,
        clock_generation: ClockGeneration,
    ) -> Result<Self, MailboxError> {
        Self::try_new_with_class(
            reference,
            schema,
            interaction,
            MessageClass::from_interaction(interaction),
            spec,
            clock_domain,
            clock_generation,
        )
    }

    fn try_new_with_class(
        reference: MailboxRef,
        schema: SchemaRef,
        interaction: InteractionKind,
        message_class: MessageClass,
        spec: MailboxSpec,
        clock_domain: ClockDomainRef,
        clock_generation: ClockGeneration,
    ) -> Result<Self, MailboxError> {
        let limits = MailboxLimits {
            capacity_items: spec.capacity_items(),
            capacity_bytes: spec.capacity_bytes(),
            max_queue_age: spec.max_queue_age(),
            max_inflight: spec.max_inflight(),
            max_retained_bytes: spec.max_retained_bytes(),
            overflow: spec.overflow_policy(),
        };
        if limits.capacity_items == 0
            || limits.capacity_bytes == 0
            || limits.max_inflight == 0
            || limits.max_retained_bytes == 0
        {
            return Err(MailboxError::InvalidMailboxSpec);
        }
        match (message_class, limits.overflow) {
            (MessageClass::Signal, _)
            | (
                MessageClass::Event,
                OverflowPolicy::RejectNew | OverflowPolicy::BlockUntilDeadline,
            )
            | (MessageClass::Command, OverflowPolicy::RejectNew) => {}
            (MessageClass::Event | MessageClass::Command, _) => {
                return Err(MailboxError::UnsupportedInteractionPolicy);
            }
        }

        Ok(Self {
            reference,
            schema,
            interaction,
            message_class,
            spec,
            clock_domain,
            clock_generation,
            limits,
            lifecycle: MailboxLifecycle::Accepting,
            queue: VecDeque::new(),
            inflight: BTreeMap::new(),
            queued_bytes: 0,
            inflight_bytes: 0,
            next_token_generation: 0,
            offers: OfferCounters::default(),
            terminals: TerminalCounters::default(),
        })
    }

    #[cfg(test)]
    fn try_new_command_fixture(
        reference: MailboxRef,
        schema: SchemaRef,
        spec: MailboxSpec,
        clock_domain: ClockDomainRef,
        clock_generation: ClockGeneration,
    ) -> Result<Self, MailboxError> {
        Self::try_new_with_class(
            reference,
            schema,
            InteractionKind::Event,
            MessageClass::Command,
            spec,
            clock_domain,
            clock_generation,
        )
    }

    /// Returns the exact assigned mailbox identity.
    #[must_use]
    pub(crate) const fn reference(&self) -> MailboxRef {
        self.reference
    }

    /// Returns the exact assigned payload schema.
    #[must_use]
    pub(crate) const fn schema(&self) -> SchemaRef {
        self.schema
    }

    /// Returns the public Signal/Event interaction for an assigned mailbox.
    #[must_use]
    pub(crate) const fn interaction(&self) -> InteractionKind {
        self.interaction
    }

    /// Returns the exact compiled mailbox specification.
    #[must_use]
    pub(crate) const fn spec(&self) -> MailboxSpec {
        self.spec
    }

    /// Offers one already-validated Message without waiting or spawning work.
    pub(crate) fn try_offer(
        &mut self,
        message: ValidatedMessage,
        reading: ClockReading,
    ) -> Result<OfferReport, OfferFailure> {
        if let Err(error) = self.validate_state() {
            return Err(OfferFailure::new(error, message));
        }

        if self.lifecycle != MailboxLifecycle::Accepting {
            let next_offers = match self.offers.checked_terminal(OfferCategory::Closed) {
                Ok(counters) => counters,
                Err(error) => return Err(OfferFailure::new(error, message)),
            };
            self.offers = next_offers;
            return Ok(OfferReport {
                outcome: EnqueueOutcome::Closed { message },
                terminals: Vec::new(),
            });
        }

        if let Err(error) = self.ensure_reading(reading) {
            return Err(OfferFailure::new(error, message));
        }
        let freshness_expired = match message.fresh_until.is_expired_at(reading) {
            Ok(expired) => expired,
            Err(error) => {
                return Err(OfferFailure::new(mailbox_time_error(error), message));
            }
        };
        let run_deadline_expired = match message.run_deadline.is_expired_at(reading) {
            Ok(expired) => expired,
            Err(error) => {
                return Err(OfferFailure::new(mailbox_time_error(error), message));
            }
        };
        let queue_age_deadline = match reading.try_deadline_after(self.limits.max_queue_age) {
            Ok(deadline) => deadline,
            Err(error) => {
                return Err(OfferFailure::new(mailbox_time_error(error), message));
            }
        };
        let queue_age_immediately_expired = match queue_age_deadline.is_expired_at(reading) {
            Ok(expired) => expired,
            Err(error) => {
                return Err(OfferFailure::new(mailbox_time_error(error), message));
            }
        };

        let expired_items = match self.expired_items(reading) {
            Ok(items) => items,
            Err(error) => return Err(OfferFailure::new(error, message)),
        };
        let expired_indices = Self::indices_for_expired_items(&expired_items);
        let expired_records = self.records_for_expired_items(&expired_items);
        let mut next_terminals = match self.terminals.checked_increment_records(&expired_records) {
            Ok(counters) => counters,
            Err(error) => return Err(OfferFailure::new(error, message)),
        };

        let live_indices = self.live_indices_excluding(&expired_indices);
        let duplicate = self.inflight.contains_key(&message.id)
            || live_indices
                .iter()
                .any(|index| self.queue[*index].message.id == message.id);

        let mut displaced_indices = Vec::new();
        let mut displaced_reason = TerminalReason::Evicted;
        let mut decision =
            if freshness_expired || run_deadline_expired || queue_age_immediately_expired {
                PlannedOffer::ExpiredBeforeAdmission
            } else if message.schema != self.schema {
                PlannedOffer::Rejected(RejectionReason::SchemaMismatch)
            } else if message.class != self.message_class {
                PlannedOffer::Rejected(RejectionReason::InteractionMismatch)
            } else if duplicate {
                PlannedOffer::Rejected(RejectionReason::DuplicateActiveMessage)
            } else if message.payload.charged_bytes > self.limits.capacity_bytes
                || message.payload.charged_bytes > self.limits.max_retained_bytes
            {
                PlannedOffer::Rejected(RejectionReason::PayloadTooLarge)
            } else if self.limits.overflow == OverflowPolicy::CoalesceByKey
                && message.coalesce_key.is_none()
            {
                PlannedOffer::Rejected(RejectionReason::MissingCoalesceKey)
            } else {
                PlannedOffer::Admit
            };

        if decision == PlannedOffer::Admit {
            match self.limits.overflow {
                OverflowPolicy::Latest => {
                    displaced_indices.extend(live_indices.iter().copied());
                }
                OverflowPolicy::CoalesceByKey => {
                    let key = message.coalesce_key;
                    if let Some(index) = live_indices
                        .iter()
                        .rev()
                        .find(|index| self.queue[**index].message.coalesce_key == key)
                    {
                        displaced_indices.push(*index);
                        displaced_reason = TerminalReason::Coalesced;
                    }
                }
                OverflowPolicy::RejectNew
                | OverflowPolicy::DropOldest
                | OverflowPolicy::BlockUntilDeadline => {}
            }
            let initial_fit = match self.fit_after_removing(
                &expired_indices,
                &displaced_indices,
                message.payload.charged_bytes,
            ) {
                Ok(fit) => fit,
                Err(error) => return Err(OfferFailure::new(error, message)),
            };
            if !initial_fit.is_full_fit() {
                match self.limits.overflow {
                    OverflowPolicy::RejectNew => {
                        decision = PlannedOffer::Rejected(initial_fit.rejection_reason());
                    }
                    OverflowPolicy::BlockUntilDeadline => {
                        decision = PlannedOffer::WouldBlock;
                    }
                    OverflowPolicy::DropOldest => {
                        for index in &live_indices {
                            if displaced_indices.binary_search(index).is_ok() {
                                continue;
                            }
                            displaced_indices.push(*index);
                            displaced_indices.sort_unstable();
                            let fit = match self.fit_after_removing(
                                &expired_indices,
                                &displaced_indices,
                                message.payload.charged_bytes,
                            ) {
                                Ok(fit) => fit,
                                Err(error) => {
                                    return Err(OfferFailure::new(error, message));
                                }
                            };
                            if fit.is_full_fit() {
                                break;
                            }
                        }
                    }
                    OverflowPolicy::Latest | OverflowPolicy::CoalesceByKey => {}
                }

                if decision == PlannedOffer::Admit {
                    let final_fit = match self.fit_after_removing(
                        &expired_indices,
                        &displaced_indices,
                        message.payload.charged_bytes,
                    ) {
                        Ok(fit) => fit,
                        Err(error) => return Err(OfferFailure::new(error, message)),
                    };
                    if !final_fit.is_full_fit() {
                        displaced_indices.clear();
                        decision = PlannedOffer::Rejected(final_fit.rejection_reason());
                    }
                }
            }
        }

        let displaced_records = self.records_for_indices(&displaced_indices, displaced_reason);
        next_terminals = match next_terminals.checked_increment_records(&displaced_records) {
            Ok(counters) => counters,
            Err(error) => return Err(OfferFailure::new(error, message)),
        };

        let next_offers = match decision.offer_category() {
            Some(category) => match self.offers.checked_terminal(category) {
                Ok(counters) => counters,
                Err(error) => return Err(OfferFailure::new(error, message)),
            },
            None => self.offers,
        };

        let mut remove_indices = expired_indices;
        remove_indices.extend(displaced_indices);
        remove_indices.sort_unstable();
        remove_indices.dedup();
        let removed_bytes = match self.bytes_for_indices(&remove_indices) {
            Ok(bytes) => bytes,
            Err(error) => return Err(OfferFailure::new(error, message)),
        };
        let mut next_queued_bytes = match self.queued_bytes.checked_sub(removed_bytes) {
            Some(bytes) => bytes,
            None => {
                return Err(OfferFailure::new(MailboxError::StateInconsistent, message));
            }
        };
        if decision == PlannedOffer::Admit {
            next_queued_bytes = match next_queued_bytes.checked_add(message.payload.charged_bytes) {
                Some(bytes) => bytes,
                None => {
                    return Err(OfferFailure::new(MailboxError::CounterOverflow, message));
                }
            };
        }

        self.remove_queue_indices(&remove_indices);
        self.queued_bytes = next_queued_bytes;
        self.offers = next_offers;
        self.terminals = next_terminals;

        let mut terminals = expired_records;
        terminals.extend(displaced_records);
        let outcome = match decision {
            PlannedOffer::Admit => {
                self.queue.push_back(QueuedMessage {
                    message,
                    queue_age_deadline,
                });
                EnqueueOutcome::Admitted
            }
            PlannedOffer::Rejected(reason) => EnqueueOutcome::Rejected { reason, message },
            PlannedOffer::ExpiredBeforeAdmission => {
                EnqueueOutcome::ExpiredBeforeAdmission { message }
            }
            PlannedOffer::WouldBlock => {
                let deadline = if message.fresh_until.deadline().value()
                    <= message.run_deadline.deadline().value()
                {
                    message.fresh_until
                } else {
                    message.run_deadline
                };
                EnqueueOutcome::WouldBlock { message, deadline }
            }
        };

        Ok(OfferReport { outcome, terminals })
    }

    /// Returns a payload-free view of the FIFO head without changing ownership.
    pub(crate) fn head_readiness(
        &self,
        reading: ClockReading,
    ) -> Result<MailboxHeadReadiness, MailboxError> {
        self.validate_state()?;
        if self.lifecycle == MailboxLifecycle::Closed {
            return Ok(MailboxHeadReadiness::Closed);
        }
        self.ensure_reading(reading)?;
        let Some(item) = self.queue.front() else {
            return Ok(MailboxHeadReadiness::Empty);
        };
        let hint = MailboxHeadHint {
            mailbox: self.reference,
            message_id: item.message.id,
            charged_bytes: item.message.payload.charged_bytes,
            fresh_until: item.message.fresh_until,
            run_deadline: item.message.run_deadline,
            queue_age_deadline: item.queue_age_deadline,
        };
        if let Some(reason) = Self::expiration_reason(item, reading)? {
            return Ok(MailboxHeadReadiness::Expired { hint, reason });
        }
        let inflight_items =
            u32::try_from(self.inflight.len()).map_err(|_| MailboxError::StateInconsistent)?;
        if inflight_items >= self.limits.max_inflight {
            return Ok(MailboxHeadReadiness::NoPermit(hint));
        }
        Ok(MailboxHeadReadiness::Ready(hint))
    }

    /// Moves the FIFO head to in-flight only when a permit is available.
    pub(crate) fn try_begin_inflight(
        &mut self,
        reading: ClockReading,
    ) -> Result<DispatchReport, MailboxError> {
        self.validate_state()?;
        if self.lifecycle == MailboxLifecycle::Closed {
            return Ok(DispatchReport {
                outcome: DispatchOutcome::Closed,
                expired: Vec::new(),
            });
        }
        self.ensure_reading(reading)?;

        let expired_items = self.expired_items(reading)?;
        let expired_indices = Self::indices_for_expired_items(&expired_items);
        let expired_records = self.records_for_expired_items(&expired_items);
        let next_terminals = self.terminals.checked_increment_records(&expired_records)?;
        let removed_bytes = self.bytes_for_indices(&expired_indices)?;
        let mut next_queued_bytes = self
            .queued_bytes
            .checked_sub(removed_bytes)
            .ok_or(MailboxError::StateInconsistent)?;
        let remaining_items = self
            .queue
            .len()
            .checked_sub(expired_indices.len())
            .ok_or(MailboxError::StateInconsistent)?;
        let inflight_items =
            u32::try_from(self.inflight.len()).map_err(|_| MailboxError::StateInconsistent)?;

        let can_dispatch = remaining_items > 0 && inflight_items < self.limits.max_inflight;
        let next_token_generation = if can_dispatch {
            Some(
                self.next_token_generation
                    .checked_add(1)
                    .ok_or(MailboxError::CounterOverflow)?,
            )
        } else {
            None
        };

        self.remove_queue_indices(&expired_indices);
        self.queued_bytes = next_queued_bytes;
        self.terminals = next_terminals;

        let outcome = if let Some(token_generation) = next_token_generation {
            let Some(item) = self.queue.pop_front() else {
                return Err(MailboxError::StateInconsistent);
            };
            let payload_bytes = item.message.payload.charged_bytes;
            next_queued_bytes = self
                .queued_bytes
                .checked_sub(payload_bytes)
                .ok_or(MailboxError::StateInconsistent)?;
            let next_inflight_bytes = self
                .inflight_bytes
                .checked_add(payload_bytes)
                .ok_or(MailboxError::CounterOverflow)?;
            if self.inflight.contains_key(&item.message.id) {
                return Err(MailboxError::StateInconsistent);
            }
            self.queued_bytes = next_queued_bytes;
            self.inflight_bytes = next_inflight_bytes;
            self.next_token_generation = token_generation;
            self.inflight.insert(
                item.message.id,
                InflightAccounting {
                    token_generation,
                    payload_bytes,
                },
            );
            DispatchOutcome::Started(InflightToken {
                mailbox: self.reference,
                token_generation,
                message: item.message,
            })
        } else if remaining_items == 0 {
            self.close_if_drained_internal();
            if self.lifecycle == MailboxLifecycle::Closed {
                DispatchOutcome::Closed
            } else {
                DispatchOutcome::NoQueuedMessage
            }
        } else {
            DispatchOutcome::NoPermit
        };

        Ok(DispatchReport {
            outcome,
            expired: expired_records,
        })
    }

    /// Records an explicit terminal for one exact in-flight token.
    pub(crate) fn finish(
        &mut self,
        token: InflightToken,
        reason: TerminalReason,
    ) -> Result<TerminalRecord, FinishFailure> {
        if let Err(error) = self.validate_state() {
            return Err(FinishFailure::new(error, token));
        }
        if !reason.is_inflight_completion() {
            return Err(FinishFailure::new(
                MailboxError::InvalidTerminalReason,
                token,
            ));
        }
        if token.mailbox != self.reference {
            return Err(FinishFailure::new(
                MailboxError::InflightTokenMismatch,
                token,
            ));
        }
        let Some(accounting) = self.inflight.get(&token.message.id) else {
            return Err(FinishFailure::new(
                MailboxError::InflightTokenMismatch,
                token,
            ));
        };
        if accounting.token_generation != token.token_generation
            || accounting.payload_bytes != token.message.payload.charged_bytes
        {
            return Err(FinishFailure::new(
                MailboxError::InflightTokenMismatch,
                token,
            ));
        }

        let next_terminals = match self.terminals.checked_increment(reason) {
            Ok(counters) => counters,
            Err(error) => return Err(FinishFailure::new(error, token)),
        };
        let next_inflight_bytes = match self.inflight_bytes.checked_sub(accounting.payload_bytes) {
            Some(bytes) => bytes,
            None => {
                return Err(FinishFailure::new(MailboxError::StateInconsistent, token));
            }
        };
        let record = TerminalRecord::new(
            token.message.id,
            reason,
            token.message.payload.charged_bytes,
        );

        self.inflight.remove(&token.message.id);
        self.inflight_bytes = next_inflight_bytes;
        self.terminals = next_terminals;
        self.close_if_drained_internal();
        Ok(record)
    }

    /// Marks released in-flight payload owners as an explicit uncertain terminal.
    ///
    /// A later RuntimeHost may call this only after its structured task owner has
    /// joined, cancelled, or otherwise released every corresponding token. P2a
    /// has no task owner and therefore cannot infer completion from a dropped
    /// token. S4 must use a separate, non-payload-owning completion fence for
    /// late-generation output rather than treating a live payload token as
    /// already released.
    pub(crate) fn abandon_all_inflight_uncertain(
        &mut self,
    ) -> Result<Vec<TerminalRecord>, MailboxError> {
        self.validate_state()?;
        if self.lifecycle == MailboxLifecycle::Accepting {
            return Err(MailboxError::AbandonRequiresDraining);
        }
        let records = self
            .inflight
            .iter()
            .map(|(message_id, accounting)| {
                TerminalRecord::new(
                    *message_id,
                    TerminalReason::Uncertain,
                    accounting.payload_bytes,
                )
            })
            .collect::<Vec<_>>();
        let next_terminals = self.terminals.checked_increment_records(&records)?;

        self.inflight.clear();
        self.inflight_bytes = 0;
        self.terminals = next_terminals;
        self.close_if_drained_internal();
        Ok(records)
    }

    /// Stops new admission and begins bounded drain/expiry.
    pub(crate) fn stop_accepting(&mut self) -> Result<(), MailboxError> {
        self.validate_state()?;
        if self.lifecycle == MailboxLifecycle::Accepting {
            self.lifecycle = MailboxLifecycle::Draining;
        }
        self.close_if_drained_internal();
        Ok(())
    }

    /// Cancels every queued Message after admission has stopped.
    ///
    /// A closed mailbox is already empty, so repeated calls are idempotent.
    /// In-flight ownership and its explicit abandonment preconditions are not
    /// changed by this queue-only transition.
    pub(crate) fn cancel_all_queued(&mut self) -> Result<Vec<TerminalRecord>, MailboxError> {
        self.validate_state()?;
        if self.lifecycle == MailboxLifecycle::Accepting {
            return Err(MailboxError::CancelRequiresDraining);
        }
        if self.queue.is_empty() {
            self.close_if_drained_internal();
            return Ok(Vec::new());
        }

        let indices = (0..self.queue.len()).collect::<Vec<_>>();
        let records = self.records_for_indices(&indices, TerminalReason::Cancelled);
        let next_terminals = self.terminals.checked_increment_records(&records)?;

        self.queue.clear();
        self.queued_bytes = 0;
        self.terminals = next_terminals;
        self.close_if_drained_internal();
        Ok(records)
    }

    /// Expires queued Messages at one caller-supplied target-local reading.
    pub(crate) fn expire_queued(
        &mut self,
        reading: ClockReading,
    ) -> Result<Vec<TerminalRecord>, MailboxError> {
        self.validate_state()?;
        if self.lifecycle == MailboxLifecycle::Closed {
            return Ok(Vec::new());
        }
        self.ensure_reading(reading)?;
        let expired_items = self.expired_items(reading)?;
        let expired_indices = Self::indices_for_expired_items(&expired_items);
        let records = self.records_for_expired_items(&expired_items);
        let next_terminals = self.terminals.checked_increment_records(&records)?;
        let removed_bytes = self.bytes_for_indices(&expired_indices)?;
        let next_queued_bytes = self
            .queued_bytes
            .checked_sub(removed_bytes)
            .ok_or(MailboxError::StateInconsistent)?;

        self.remove_queue_indices(&expired_indices);
        self.queued_bytes = next_queued_bytes;
        self.terminals = next_terminals;
        self.close_if_drained_internal();
        Ok(records)
    }

    /// Closes a non-accepting mailbox once queued and in-flight cohorts empty.
    pub(crate) fn close_if_drained(&mut self) -> Result<bool, MailboxError> {
        self.validate_state()?;
        self.close_if_drained_internal();
        Ok(self.lifecycle == MailboxLifecycle::Closed)
    }

    /// Returns a bounded snapshot after checking all accounting invariants.
    pub(crate) fn snapshot(&self) -> Result<MailboxSnapshot, MailboxError> {
        self.validate_state()?;
        let queued_items =
            u32::try_from(self.queue.len()).map_err(|_| MailboxError::StateInconsistent)?;
        let inflight_items =
            u32::try_from(self.inflight.len()).map_err(|_| MailboxError::StateInconsistent)?;
        let retained_bytes = self
            .queued_bytes
            .checked_add(self.inflight_bytes)
            .ok_or(MailboxError::StateInconsistent)?;
        Ok(MailboxSnapshot {
            lifecycle: self.lifecycle,
            queued_items,
            queued_bytes: self.queued_bytes,
            inflight_items,
            inflight_bytes: self.inflight_bytes,
            retained_bytes,
            offers: self.offers,
            terminals: self.terminals,
        })
    }

    fn close_if_drained_internal(&mut self) {
        if self.lifecycle == MailboxLifecycle::Draining
            && self.queue.is_empty()
            && self.inflight.is_empty()
        {
            self.lifecycle = MailboxLifecycle::Closed;
        }
    }

    fn ensure_reading(&self, reading: ClockReading) -> Result<(), MailboxError> {
        if reading.domain() != self.clock_domain {
            return Err(MailboxError::ClockDomainMismatch);
        }
        if reading.generation() != self.clock_generation {
            return Err(MailboxError::ClockGenerationMismatch);
        }
        Ok(())
    }

    fn expired_items(
        &self,
        reading: ClockReading,
    ) -> Result<Vec<(usize, TerminalReason)>, MailboxError> {
        self.queue
            .iter()
            .enumerate()
            .try_fold(Vec::new(), |mut items, (index, item)| {
                if let Some(reason) = Self::expiration_reason(item, reading)? {
                    items.push((index, reason));
                }
                Ok(items)
            })
    }

    fn expiration_reason(
        item: &QueuedMessage,
        reading: ClockReading,
    ) -> Result<Option<TerminalReason>, MailboxError> {
        let run = item.message.run_deadline.deadline().value();
        let fresh = item.message.fresh_until.deadline().value();
        let queue_age = item.queue_age_deadline.deadline().value();
        let (deadline, reason) = if run <= fresh && run <= queue_age {
            // Latest-run-start is the stronger reason at an equal boundary.
            (
                item.message.run_deadline,
                TerminalReason::RunDeadlineExpired,
            )
        } else if fresh <= queue_age {
            (item.message.fresh_until, TerminalReason::StaleBeforeRun)
        } else {
            (item.queue_age_deadline, TerminalReason::QueueAgeExpired)
        };
        deadline
            .is_expired_at(reading)
            .map(|expired| expired.then_some(reason))
            .map_err(mailbox_time_error)
    }

    fn indices_for_expired_items(items: &[(usize, TerminalReason)]) -> Vec<usize> {
        items.iter().map(|(index, _)| *index).collect()
    }

    fn records_for_expired_items(&self, items: &[(usize, TerminalReason)]) -> Vec<TerminalRecord> {
        items
            .iter()
            .map(|(index, reason)| {
                let item = &self.queue[*index];
                TerminalRecord::new(item.message.id, *reason, item.message.payload.charged_bytes)
            })
            .collect()
    }

    fn live_indices_excluding(&self, excluded: &[usize]) -> Vec<usize> {
        (0..self.queue.len())
            .filter(|index| excluded.binary_search(index).is_err())
            .collect()
    }

    fn records_for_indices(
        &self,
        indices: &[usize],
        reason: TerminalReason,
    ) -> Vec<TerminalRecord> {
        self.queue
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                indices.binary_search(&index).ok().map(|_| {
                    TerminalRecord::new(item.message.id, reason, item.message.payload.charged_bytes)
                })
            })
            .collect()
    }

    fn bytes_for_indices(&self, indices: &[usize]) -> Result<u64, MailboxError> {
        self.queue
            .iter()
            .enumerate()
            .filter(|(index, _)| indices.binary_search(index).is_ok())
            .try_fold(0_u64, |total, (_, item)| {
                total
                    .checked_add(item.message.payload.charged_bytes)
                    .ok_or(MailboxError::CounterOverflow)
            })
    }

    fn remove_queue_indices(&mut self, indices: &[usize]) {
        let original_len = self.queue.len();
        for index in 0..original_len {
            let Some(item) = self.queue.pop_front() else {
                unreachable!("validated queue length changed during pure removal");
            };
            if indices.binary_search(&index).is_err() {
                self.queue.push_back(item);
            }
        }
    }

    fn fit_after_removing(
        &self,
        expired: &[usize],
        displaced: &[usize],
        incoming_bytes: u64,
    ) -> Result<CapacityFit, MailboxError> {
        let mut removed = expired.to_vec();
        removed.extend_from_slice(displaced);
        removed.sort_unstable();
        removed.dedup();
        let removed_bytes = self.bytes_for_indices(&removed)?;
        let queued_items = self
            .queue
            .len()
            .checked_sub(removed.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(MailboxError::CounterOverflow)?;
        let queued_items =
            u32::try_from(queued_items).map_err(|_| MailboxError::CounterOverflow)?;
        let queued_bytes = self
            .queued_bytes
            .checked_sub(removed_bytes)
            .and_then(|value| value.checked_add(incoming_bytes))
            .ok_or(MailboxError::CounterOverflow)?;
        let retained_bytes = queued_bytes
            .checked_add(self.inflight_bytes)
            .ok_or(MailboxError::CounterOverflow)?;
        Ok(CapacityFit {
            items: queued_items <= self.limits.capacity_items,
            queued_bytes: queued_bytes <= self.limits.capacity_bytes,
            retained_bytes: retained_bytes <= self.limits.max_retained_bytes,
        })
    }

    fn validate_state(&self) -> Result<(), MailboxError> {
        self.offers.validate()?;
        let queued_items =
            u32::try_from(self.queue.len()).map_err(|_| MailboxError::StateInconsistent)?;
        let inflight_items =
            u32::try_from(self.inflight.len()).map_err(|_| MailboxError::StateInconsistent)?;
        if queued_items > self.limits.capacity_items
            || inflight_items > self.limits.max_inflight
            || self.queued_bytes > self.limits.capacity_bytes
        {
            return Err(MailboxError::StateInconsistent);
        }

        let recomputed_queued = self.queue.iter().try_fold(0_u64, |total, item| {
            total
                .checked_add(item.message.payload.charged_bytes)
                .ok_or(MailboxError::StateInconsistent)
        })?;
        let recomputed_inflight = self.inflight.values().try_fold(0_u64, |total, item| {
            total
                .checked_add(item.payload_bytes)
                .ok_or(MailboxError::StateInconsistent)
        })?;
        if recomputed_queued != self.queued_bytes || recomputed_inflight != self.inflight_bytes {
            return Err(MailboxError::StateInconsistent);
        }
        let retained = self
            .queued_bytes
            .checked_add(self.inflight_bytes)
            .ok_or(MailboxError::StateInconsistent)?;
        if retained > self.limits.max_retained_bytes {
            return Err(MailboxError::StateInconsistent);
        }

        let mut active = BTreeSet::new();
        for item in &self.queue {
            if item.queue_age_deadline.domain() != self.clock_domain
                || item.queue_age_deadline.generation() != self.clock_generation
                || item.message.fresh_until.domain() != self.clock_domain
                || item.message.fresh_until.generation() != self.clock_generation
                || item.message.run_deadline.domain() != self.clock_domain
                || item.message.run_deadline.generation() != self.clock_generation
                || !active.insert(item.message.id)
            {
                return Err(MailboxError::StateInconsistent);
            }
        }
        for message_id in self.inflight.keys() {
            if !active.insert(*message_id) {
                return Err(MailboxError::StateInconsistent);
            }
        }

        let active_count = u64::from(queued_items)
            .checked_add(u64::from(inflight_items))
            .ok_or(MailboxError::StateInconsistent)?;
        let admitted_accounted = active_count
            .checked_add(self.terminals.total()?)
            .ok_or(MailboxError::StateInconsistent)?;
        if admitted_accounted != self.offers.admitted {
            return Err(MailboxError::StateInconsistent);
        }
        if self.lifecycle == MailboxLifecycle::Closed && active_count != 0 {
            return Err(MailboxError::StateInconsistent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedOffer {
    Admit,
    Rejected(RejectionReason),
    ExpiredBeforeAdmission,
    WouldBlock,
}

impl PlannedOffer {
    const fn offer_category(self) -> Option<OfferCategory> {
        match self {
            Self::Admit => Some(OfferCategory::Admitted),
            Self::Rejected(_) => Some(OfferCategory::Rejected),
            Self::ExpiredBeforeAdmission => Some(OfferCategory::ExpiredBeforeAdmission),
            Self::WouldBlock => Some(OfferCategory::Rejected),
        }
    }
}

#[derive(Clone, Copy)]
struct CapacityFit {
    items: bool,
    queued_bytes: bool,
    retained_bytes: bool,
}

impl CapacityFit {
    const fn is_full_fit(self) -> bool {
        self.items && self.queued_bytes && self.retained_bytes
    }

    const fn rejection_reason(self) -> RejectionReason {
        if !self.items || !self.queued_bytes {
            RejectionReason::CapacityFull
        } else {
            RejectionReason::RetainedCapacityFull
        }
    }
}

const fn mailbox_time_error(error: TimeError) -> MailboxError {
    match error {
        TimeError::ClockDomainMismatch => MailboxError::ClockDomainMismatch,
        TimeError::ClockGenerationMismatch => MailboxError::ClockGenerationMismatch,
        TimeError::DeadlineOverflow => MailboxError::DeadlineOverflow,
        TimeError::InvalidClockGeneration => MailboxError::StateInconsistent,
    }
}

/// Fail-closed mailbox construction, accounting, and state errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MailboxError {
    InvalidMailboxSpec,
    UnsupportedInteractionPolicy,
    PayloadSizeOverflow,
    ClockDomainMismatch,
    ClockGenerationMismatch,
    DeadlineOverflow,
    CounterOverflow,
    StateInconsistent,
    InvalidTerminalReason,
    InflightTokenMismatch,
    AbandonRequiresDraining,
    CancelRequiresDraining,
}

impl fmt::Display for MailboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidMailboxSpec => "invalid mailbox specification",
            Self::UnsupportedInteractionPolicy => "unsupported interaction overflow policy",
            Self::PayloadSizeOverflow => "payload size exceeds the accounting representation",
            Self::ClockDomainMismatch => "mailbox clock domain mismatch",
            Self::ClockGenerationMismatch => "mailbox clock generation mismatch",
            Self::DeadlineOverflow => "mailbox queue deadline overflow",
            Self::CounterOverflow => "mailbox counter overflow",
            Self::StateInconsistent => "mailbox state is inconsistent",
            Self::InvalidTerminalReason => "invalid in-flight terminal reason",
            Self::InflightTokenMismatch => "in-flight token does not match mailbox state",
            Self::AbandonRequiresDraining => {
                "in-flight abandonment requires a non-accepting mailbox"
            }
            Self::CancelRequiresDraining => "queued cancellation requires a non-accepting mailbox",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MailboxError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::time::{
        BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant,
    };
    use paraegox_runtime_contracts::assignment::{
        InteractionKind, MailboxRef, MailboxSpec, OverflowPolicy, SchemaRef,
    };

    use super::{
        CoalesceKey, DispatchOutcome, EnqueueOutcome, Mailbox, MailboxError, MailboxLifecycle,
        MessageId, PayloadHandle, RejectionReason, TerminalReason, ValidatedMessage,
    };

    const CLOCK_DOMAIN: u8 = 0x31;
    const CLOCK_GENERATION: u64 = 7;

    fn generation(value: u64) -> ClockGeneration {
        let Ok(generation) = ClockGeneration::try_new(value) else {
            panic!("test generation must be nonzero");
        };
        generation
    }

    fn reading_at(domain: u8, generation_value: u64, now: u64) -> ClockReading {
        ClockReading::new(
            ClockDomainRef::from_bytes([domain; 16]),
            generation(generation_value),
            MonotonicInstant::from_ticks(now),
        )
    }

    fn reading(now: u64) -> ClockReading {
        reading_at(CLOCK_DOMAIN, CLOCK_GENERATION, now)
    }

    fn schema(value: u8) -> SchemaRef {
        let Ok(schema) = SchemaRef::try_new(
            [value; 16],
            1,
            Digest32::from_bytes([value.wrapping_add(1); 32]),
        ) else {
            panic!("test schema must be valid");
        };
        schema
    }

    fn spec(
        capacity_items: u32,
        capacity_bytes: u64,
        max_queue_age: u64,
        max_inflight: u32,
        max_retained_bytes: u64,
        overflow: OverflowPolicy,
    ) -> MailboxSpec {
        let Ok(spec) = MailboxSpec::try_new(
            capacity_items,
            capacity_bytes,
            BoundedDuration::from_nanos(max_queue_age),
            max_inflight,
            max_retained_bytes,
            overflow,
        ) else {
            panic!("test mailbox specification must be valid");
        };
        spec
    }

    fn mailbox_with(reference: u8, interaction: InteractionKind, spec: MailboxSpec) -> Mailbox {
        let Ok(mailbox) = Mailbox::try_new(
            MailboxRef::from_bytes([reference; 16]),
            schema(0x41),
            interaction,
            spec,
            ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16]),
            generation(CLOCK_GENERATION),
        ) else {
            panic!("test mailbox must be valid");
        };
        mailbox
    }

    fn mailbox(overflow: OverflowPolicy) -> Mailbox {
        mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(3, 12, 20, 1, 12, overflow),
        )
    }

    fn payload(size: usize, fill: u8) -> PayloadHandle {
        let Ok(payload) = PayloadHandle::try_from_vec(vec![fill; size]) else {
            panic!("test payload must be representable");
        };
        payload
    }

    fn deadline_at(ticks: u64) -> paraegox_kernel::time::MonotonicDeadline {
        let Ok(deadline) = reading(0).try_deadline_after(BoundedDuration::from_nanos(ticks)) else {
            panic!("test deadline must be representable");
        };
        deadline
    }

    fn message_with(
        id: u8,
        size: usize,
        deadline: u64,
        message_schema: SchemaRef,
        interaction: InteractionKind,
        key: Option<u8>,
    ) -> ValidatedMessage {
        ValidatedMessage::new(
            MessageId::from_bytes([id; 16]),
            message_schema,
            interaction,
            key.map(|value| CoalesceKey::from_bytes([value; 16])),
            deadline_at(deadline),
            payload(size, id),
        )
    }

    fn message(id: u8, size: usize, deadline: u64) -> ValidatedMessage {
        message_with(
            id,
            size,
            deadline,
            schema(0x41),
            InteractionKind::Signal,
            None,
        )
    }

    fn message_with_deadlines(
        id: u8,
        size: usize,
        fresh_until: u64,
        run_deadline: u64,
    ) -> ValidatedMessage {
        ValidatedMessage::new_with_deadlines(
            MessageId::from_bytes([id; 16]),
            schema(0x41),
            InteractionKind::Signal,
            None,
            deadline_at(fresh_until),
            deadline_at(run_deadline),
            payload(size, id),
        )
    }

    fn keyed_message(id: u8, size: usize, deadline: u64, key: u8) -> ValidatedMessage {
        message_with(
            id,
            size,
            deadline,
            schema(0x41),
            InteractionKind::Signal,
            Some(key),
        )
    }

    fn offer(mailbox: &mut Mailbox, message: ValidatedMessage, now: u64) -> super::OfferReport {
        let Ok(report) = mailbox.try_offer(message, reading(now)) else {
            panic!("test offer must not raise a structural error");
        };
        report
    }

    fn snapshot(mailbox: &Mailbox) -> super::MailboxSnapshot {
        let Ok(snapshot) = mailbox.snapshot() else {
            panic!("test mailbox must remain internally consistent");
        };
        snapshot
    }

    fn begin(mailbox: &mut Mailbox, now: u64) -> super::DispatchReport {
        let Ok(report) = mailbox.try_begin_inflight(reading(now)) else {
            panic!("test dispatch must not raise a structural error");
        };
        report
    }

    fn started_token(report: super::DispatchReport) -> super::InflightToken {
        let (outcome, expired) = report.into_parts();
        assert!(expired.is_empty());
        let DispatchOutcome::Started(token) = outcome else {
            panic!("test dispatch must start one Message");
        };
        token
    }

    #[test]
    fn reject_new_enforces_items_and_offer_conservation() {
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(2, 6, 20, 1, 6, OverflowPolicy::RejectNew),
        );

        assert!(
            offer(&mut mailbox, message(1, 3, 100), 0)
                .outcome()
                .is_admitted()
        );
        assert!(
            offer(&mut mailbox, message(2, 3, 100), 0)
                .outcome()
                .is_admitted()
        );
        let rejected = offer(&mut mailbox, message(3, 1, 100), 0);
        assert!(matches!(
            rejected.outcome(),
            EnqueueOutcome::Rejected {
                reason: RejectionReason::CapacityFull,
                ..
            }
        ));

        let state = snapshot(&mailbox);
        assert_eq!(state.queued_items(), 2);
        assert_eq!(state.queued_bytes(), 6);
        assert_eq!(state.retained_bytes(), 6);
        assert_eq!(state.offers().offered(), 3);
        assert_eq!(state.offers().admitted(), 2);
        assert_eq!(state.offers().rejected(), 1);
        assert_eq!(
            state.offers().offered(),
            state.offers().admitted()
                + state.offers().rejected()
                + state.offers().closed()
                + state.offers().expired_before_admission()
        );
    }

    #[test]
    fn drop_oldest_atomically_evicts_enough_messages_for_bytes() {
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(3, 6, 20, 1, 6, OverflowPolicy::DropOldest),
        );
        for id in 1..=3 {
            assert!(
                offer(&mut mailbox, message(id, 2, 100), 0)
                    .outcome()
                    .is_admitted()
            );
        }

        let report = offer(&mut mailbox, message(4, 5, 100), 0);
        assert!(report.outcome().is_admitted());
        assert_eq!(report.terminals().len(), 3);
        assert!(
            report
                .terminals()
                .iter()
                .all(|record| record.reason() == TerminalReason::Evicted)
        );
        assert_eq!(
            report
                .terminals()
                .iter()
                .map(|record| record.released_bytes())
                .sum::<u64>(),
            6
        );

        let state = snapshot(&mailbox);
        assert_eq!(state.queued_items(), 1);
        assert_eq!(state.queued_bytes(), 5);
        assert_eq!(state.offers().admitted(), 4);
        assert_eq!(state.terminals().evicted(), 3);
    }

    #[test]
    fn drop_oldest_does_not_evict_when_incoming_payload_can_never_fit() {
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(2, 4, 20, 1, 4, OverflowPolicy::DropOldest),
        );
        assert!(
            offer(&mut mailbox, message(1, 2, 100), 0)
                .outcome()
                .is_admitted()
        );
        let before = snapshot(&mailbox);

        let report = offer(&mut mailbox, message(2, 5, 100), 0);
        assert!(matches!(
            report.outcome(),
            EnqueueOutcome::Rejected {
                reason: RejectionReason::PayloadTooLarge,
                ..
            }
        ));
        assert!(report.terminals().is_empty());
        let after = snapshot(&mailbox);
        assert_eq!(after.queued_items(), before.queued_items());
        assert_eq!(after.queued_bytes(), before.queued_bytes());
        assert_eq!(after.terminals(), before.terminals());
    }

    #[test]
    fn latest_replaces_all_queued_signals_even_before_capacity_pressure() {
        let mut mailbox = mailbox(OverflowPolicy::Latest);
        assert!(
            offer(&mut mailbox, message(1, 2, 100), 0)
                .outcome()
                .is_admitted()
        );
        let report = offer(&mut mailbox, message(2, 3, 100), 0);

        assert!(report.outcome().is_admitted());
        assert_eq!(report.terminals().len(), 1);
        assert_eq!(
            report.terminals()[0].message_id(),
            MessageId::from_bytes([1; 16])
        );
        assert_eq!(report.terminals()[0].reason(), TerminalReason::Evicted);
        let state = snapshot(&mailbox);
        assert_eq!(state.queued_items(), 1);
        assert_eq!(state.queued_bytes(), 3);
    }

    #[test]
    fn coalesce_replaces_only_the_matching_queued_key() {
        let mut mailbox = mailbox(OverflowPolicy::CoalesceByKey);
        assert!(
            offer(&mut mailbox, keyed_message(1, 2, 100, 7), 0)
                .outcome()
                .is_admitted()
        );
        assert!(
            offer(&mut mailbox, keyed_message(2, 2, 100, 8), 0)
                .outcome()
                .is_admitted()
        );
        let report = offer(&mut mailbox, keyed_message(3, 3, 100, 7), 0);

        assert!(report.outcome().is_admitted());
        assert_eq!(report.terminals().len(), 1);
        assert_eq!(
            report.terminals()[0].message_id(),
            MessageId::from_bytes([1; 16])
        );
        assert_eq!(report.terminals()[0].reason(), TerminalReason::Coalesced);
        let state = snapshot(&mailbox);
        assert_eq!(state.queued_items(), 2);
        assert_eq!(state.queued_bytes(), 5);
        assert_eq!(state.terminals().coalesced(), 1);
    }

    #[test]
    fn coalesce_requires_a_bounded_validated_key() {
        let mut mailbox = mailbox(OverflowPolicy::CoalesceByKey);
        let report = offer(&mut mailbox, message(1, 2, 100), 0);
        assert!(matches!(
            report.outcome(),
            EnqueueOutcome::Rejected {
                reason: RejectionReason::MissingCoalesceKey,
                ..
            }
        ));
        assert_eq!(snapshot(&mailbox).queued_items(), 0);
    }

    #[test]
    fn block_until_deadline_returns_message_without_waiter_and_counts_refusal() {
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(1, 3, 20, 1, 3, OverflowPolicy::BlockUntilDeadline),
        );
        assert!(
            offer(&mut mailbox, message(1, 3, 100), 0)
                .outcome()
                .is_admitted()
        );
        let before = snapshot(&mailbox);

        let report = offer(&mut mailbox, message_with_deadlines(2, 1, 20, 50), 0);
        let EnqueueOutcome::WouldBlock { message, deadline } = report.outcome() else {
            panic!("full block policy must return a pure would-block decision");
        };
        assert_eq!(message.id(), MessageId::from_bytes([2; 16]));
        assert_eq!(*deadline, deadline_at(20));
        assert!(report.terminals().is_empty());
        let after = snapshot(&mailbox);
        assert_eq!(after.queued_items(), before.queued_items());
        assert_eq!(after.queued_bytes(), before.queued_bytes());
        assert_eq!(after.retained_bytes(), before.retained_bytes());
        assert_eq!(after.terminals(), before.terminals());
        assert_eq!(after.offers().offered(), before.offers().offered() + 1);
        assert_eq!(after.offers().rejected(), before.offers().rejected() + 1);
    }

    #[test]
    fn exact_deadlines_distinguish_before_and_after_admission_expiry() {
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(2, 8, 10, 1, 8, OverflowPolicy::RejectNew),
        );
        assert!(
            offer(&mut mailbox, message(1, 2, 100), 0)
                .outcome()
                .is_admitted()
        );
        let Ok(before) = mailbox.expire_queued(reading(9)) else {
            panic!("compatible expiry must succeed");
        };
        assert!(before.is_empty());
        let Ok(at_deadline) = mailbox.expire_queued(reading(10)) else {
            panic!("compatible expiry must succeed");
        };
        assert_eq!(at_deadline.len(), 1);
        assert_eq!(at_deadline[0].reason(), TerminalReason::QueueAgeExpired);

        let already_expired = offer(&mut mailbox, message(2, 2, 10), 10);
        assert!(matches!(
            already_expired.outcome(),
            EnqueueOutcome::ExpiredBeforeAdmission { .. }
        ));
        let state = snapshot(&mailbox);
        assert_eq!(state.offers().admitted(), 1);
        assert_eq!(state.offers().expired_before_admission(), 1);
        assert_eq!(state.terminals().queue_age_expired(), 1);
        assert_eq!(state.queued_items(), 0);
    }

    #[test]
    fn dispatch_distinguishes_all_three_exact_pre_run_boundaries() {
        let bounds = [
            (5, 50, 50, TerminalReason::StaleBeforeRun),
            (50, 5, 50, TerminalReason::RunDeadlineExpired),
            (50, 50, 5, TerminalReason::QueueAgeExpired),
        ];

        for (offset, (fresh_until, run_deadline, queue_age, expected)) in
            bounds.into_iter().enumerate()
        {
            let mut mailbox = mailbox_with(
                u8::try_from(0x60 + offset).expect("test mailbox identity must fit"),
                InteractionKind::Signal,
                spec(1, 4, queue_age, 1, 4, OverflowPolicy::RejectNew),
            );
            assert!(
                offer(
                    &mut mailbox,
                    message_with_deadlines(1, 2, fresh_until, run_deadline),
                    0,
                )
                .outcome()
                .is_admitted()
            );

            let before = mailbox
                .head_readiness(reading(4))
                .expect("compatible readiness must succeed");
            let super::MailboxHeadReadiness::Ready(hint) = before else {
                panic!("head must be ready one tick before its first boundary");
            };
            assert_eq!(hint.mailbox(), mailbox.reference());
            assert_eq!(hint.message_id(), MessageId::from_bytes([1; 16]));
            assert_eq!(hint.charged_bytes(), 2);
            assert_eq!(hint.fresh_until(), deadline_at(fresh_until));
            assert_eq!(hint.run_deadline(), deadline_at(run_deadline));
            assert_eq!(hint.queue_age_deadline(), deadline_at(queue_age));

            let at_boundary = mailbox
                .head_readiness(reading(5))
                .expect("compatible readiness must succeed");
            assert!(matches!(
                at_boundary,
                super::MailboxHeadReadiness::Expired { reason, .. } if reason == expected
            ));
            let state_before_dispatch = snapshot(&mailbox);
            let report = begin(&mut mailbox, 5);
            assert_eq!(report.expired().len(), 1);
            assert_eq!(report.expired()[0].reason(), expected);
            assert!(matches!(report.outcome(), DispatchOutcome::NoQueuedMessage));
            let after = snapshot(&mailbox);
            assert_eq!(after.queued_items(), 0);
            assert_eq!(after.retained_bytes(), 0);
            assert_eq!(after.offers(), state_before_dispatch.offers());
        }
    }

    #[test]
    fn delayed_dispatch_reports_the_first_expired_boundary_with_stable_ties() {
        let cases = [
            (5, 10, 20, TerminalReason::StaleBeforeRun),
            (10, 20, 5, TerminalReason::QueueAgeExpired),
            (10, 5, 20, TerminalReason::RunDeadlineExpired),
            (5, 5, 5, TerminalReason::RunDeadlineExpired),
            (5, 10, 5, TerminalReason::StaleBeforeRun),
        ];

        for (offset, (fresh_until, run_deadline, queue_age, expected)) in
            cases.into_iter().enumerate()
        {
            let mut mailbox = mailbox_with(
                u8::try_from(0x70 + offset).expect("test mailbox identity must fit"),
                InteractionKind::Signal,
                spec(1, 4, queue_age, 1, 4, OverflowPolicy::RejectNew),
            );
            assert!(
                offer(
                    &mut mailbox,
                    message_with_deadlines(1, 2, fresh_until, run_deadline),
                    0,
                )
                .outcome()
                .is_admitted()
            );

            let observed = mailbox
                .head_readiness(reading(30))
                .expect("delayed readiness must remain structurally valid");
            assert!(matches!(
                observed,
                super::MailboxHeadReadiness::Expired { reason, .. } if reason == expected
            ));
            let report = begin(&mut mailbox, 30);
            assert_eq!(report.expired().len(), 1);
            assert_eq!(report.expired()[0].reason(), expected);
            assert!(matches!(report.outcome(), DispatchOutcome::NoQueuedMessage));
            assert_eq!(snapshot(&mailbox).retained_bytes(), 0);
        }
    }

    #[test]
    fn clock_mismatch_returns_ownership_and_changes_no_state() {
        let mut mailbox = mailbox(OverflowPolicy::RejectNew);
        let before = snapshot(&mailbox);
        let result = mailbox.try_offer(
            message(1, 2, 100),
            reading_at(CLOCK_DOMAIN.wrapping_add(1), CLOCK_GENERATION, 0),
        );
        let Err(failure) = result else {
            panic!("wrong clock domain must fail closed");
        };
        assert_eq!(failure.error(), MailboxError::ClockDomainMismatch);
        assert_eq!(failure.into_message().id(), MessageId::from_bytes([1; 16]));
        assert_eq!(snapshot(&mailbox), before);

        let result = mailbox.try_offer(
            message(2, 2, 100),
            reading_at(CLOCK_DOMAIN, CLOCK_GENERATION + 1, 0),
        );
        let Err(failure) = result else {
            panic!("wrong clock generation must fail closed");
        };
        assert_eq!(failure.error(), MailboxError::ClockGenerationMismatch);
        assert_eq!(snapshot(&mailbox), before);
    }

    #[test]
    fn active_message_identity_is_unique_but_terminal_identity_is_not_retained() {
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(2, 8, 5, 1, 8, OverflowPolicy::RejectNew),
        );
        assert!(
            offer(&mut mailbox, message(1, 2, 100), 0)
                .outcome()
                .is_admitted()
        );
        let duplicate = offer(&mut mailbox, message(1, 2, 100), 0);
        assert!(matches!(
            duplicate.outcome(),
            EnqueueOutcome::Rejected {
                reason: RejectionReason::DuplicateActiveMessage,
                ..
            }
        ));

        let Ok(expired) = mailbox.expire_queued(reading(5)) else {
            panic!("expiry must succeed");
        };
        assert_eq!(expired.len(), 1);
        assert!(
            offer(&mut mailbox, message(1, 2, 100), 5)
                .outcome()
                .is_admitted()
        );
        assert_eq!(snapshot(&mailbox).queued_items(), 1);
    }

    #[test]
    fn outstanding_permit_precedes_dequeue_and_retained_bytes_stay_bounded() {
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(3, 9, 50, 1, 6, OverflowPolicy::RejectNew),
        );
        assert!(
            offer(&mut mailbox, message(1, 3, 100), 0)
                .outcome()
                .is_admitted()
        );
        assert!(
            offer(&mut mailbox, message(2, 3, 100), 0)
                .outcome()
                .is_admitted()
        );

        let first = started_token(begin(&mut mailbox, 0));
        let after_start = snapshot(&mailbox);
        assert_eq!(after_start.queued_items(), 1);
        assert_eq!(after_start.inflight_items(), 1);
        assert_eq!(after_start.queued_bytes(), 3);
        assert_eq!(after_start.inflight_bytes(), 3);
        assert_eq!(after_start.retained_bytes(), 6);

        let no_permit = begin(&mut mailbox, 0);
        assert!(matches!(no_permit.outcome(), DispatchOutcome::NoPermit));
        assert_eq!(snapshot(&mailbox), after_start);

        let rejected = offer(&mut mailbox, message(3, 1, 100), 0);
        assert!(matches!(
            rejected.outcome(),
            EnqueueOutcome::Rejected {
                reason: RejectionReason::RetainedCapacityFull,
                ..
            }
        ));
        assert_eq!(snapshot(&mailbox).retained_bytes(), 6);

        let Ok(terminal) = mailbox.finish(first, TerminalReason::Completed) else {
            panic!("matching in-flight token must finish");
        };
        assert_eq!(terminal.reason(), TerminalReason::Completed);
        assert_eq!(terminal.released_bytes(), 3);
        let after_finish = snapshot(&mailbox);
        assert_eq!(after_finish.inflight_items(), 0);
        assert_eq!(after_finish.retained_bytes(), 3);
        assert_eq!(after_finish.terminals().completed(), 1);
    }

    #[test]
    fn abandoned_inflight_is_explicitly_fenced_uncertain_and_can_close() {
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(2, 8, 50, 1, 8, OverflowPolicy::RejectNew),
        );
        assert!(
            offer(&mut mailbox, message(1, 3, 100), 0)
                .outcome()
                .is_admitted()
        );
        assert!(
            offer(&mut mailbox, message(2, 3, 100), 0)
                .outcome()
                .is_admitted()
        );

        let abandoned = started_token(begin(&mut mailbox, 0));
        drop(abandoned);
        let accepting = snapshot(&mailbox);
        assert_eq!(
            mailbox.abandon_all_inflight_uncertain().err(),
            Some(MailboxError::AbandonRequiresDraining)
        );
        assert_eq!(snapshot(&mailbox), accepting);
        assert!(matches!(
            begin(&mut mailbox, 0).outcome(),
            DispatchOutcome::NoPermit
        ));
        let Ok(()) = mailbox.stop_accepting() else {
            panic!("consistent mailbox must begin draining");
        };
        assert!(!mailbox.close_if_drained().unwrap_or(false));

        let Ok(records) = mailbox.abandon_all_inflight_uncertain() else {
            panic!("released in-flight owner must have an explicit uncertain cleanup path");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message_id(), MessageId::from_bytes([1; 16]));
        assert_eq!(records[0].reason(), TerminalReason::Uncertain);
        assert_eq!(records[0].released_bytes(), 3);
        let after_abandon = snapshot(&mailbox);
        assert_eq!(after_abandon.inflight_items(), 0);
        assert_eq!(after_abandon.retained_bytes(), 3);
        assert_eq!(after_abandon.terminals().uncertain(), 1);
        let Ok(repeated) = mailbox.abandon_all_inflight_uncertain() else {
            panic!("repeated abandonment fence must remain queryable");
        };
        assert!(repeated.is_empty());
        assert_eq!(snapshot(&mailbox), after_abandon);

        let remaining = started_token(begin(&mut mailbox, 0));
        let Ok(record) = mailbox.finish(remaining, TerminalReason::Cancelled) else {
            panic!("remaining queued payload must still dispatch and finish");
        };
        assert_eq!(record.message_id(), MessageId::from_bytes([2; 16]));
        let closed = snapshot(&mailbox);
        assert_eq!(closed.lifecycle(), MailboxLifecycle::Closed);
        assert_eq!(closed.retained_bytes(), 0);
        assert_eq!(closed.inflight_items(), 0);
        assert_eq!(closed.queued_items(), 0);
    }

    #[test]
    fn draining_queue_cancellation_is_atomic_idempotent_and_queue_only() {
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(3, 9, 50, 1, 9, OverflowPolicy::RejectNew),
        );
        for id in 1..=3 {
            assert!(
                offer(&mut mailbox, message(id, 3, 100), 0)
                    .outcome()
                    .is_admitted()
            );
        }
        let token = started_token(begin(&mut mailbox, 0));
        let accepting = snapshot(&mailbox);
        assert_eq!(
            mailbox.cancel_all_queued().err(),
            Some(MailboxError::CancelRequiresDraining)
        );
        assert_eq!(snapshot(&mailbox), accepting);

        assert!(mailbox.stop_accepting().is_ok());
        let records = mailbox
            .cancel_all_queued()
            .unwrap_or_else(|error| panic!("draining cancellation failed: {error}"));
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message_id(), MessageId::from_bytes([2; 16]));
        assert_eq!(records[1].message_id(), MessageId::from_bytes([3; 16]));
        assert!(
            records
                .iter()
                .all(|record| record.reason() == TerminalReason::Cancelled)
        );
        assert_eq!(
            records
                .iter()
                .map(|record| record.released_bytes())
                .sum::<u64>(),
            6
        );
        let draining = snapshot(&mailbox);
        assert_eq!(draining.lifecycle(), MailboxLifecycle::Draining);
        assert_eq!(draining.queued_items(), 0);
        assert_eq!(draining.queued_bytes(), 0);
        assert_eq!(draining.inflight_items(), 1);
        assert_eq!(draining.retained_bytes(), 3);
        assert_eq!(draining.terminals().cancelled(), 2);

        assert!(
            mailbox
                .cancel_all_queued()
                .unwrap_or_else(|error| panic!("repeated cancellation failed: {error}"))
                .is_empty()
        );
        assert_eq!(snapshot(&mailbox), draining);

        assert!(mailbox.finish(token, TerminalReason::Completed).is_ok());
        assert_eq!(snapshot(&mailbox).lifecycle(), MailboxLifecycle::Closed);
        assert!(
            mailbox
                .cancel_all_queued()
                .unwrap_or_else(|error| panic!("closed cancellation failed: {error}"))
                .is_empty()
        );
    }

    #[test]
    fn invalid_inflight_terminal_returns_token_and_preserves_state() {
        let mut mailbox = mailbox(OverflowPolicy::RejectNew);
        assert!(
            offer(&mut mailbox, message(1, 2, 100), 0)
                .outcome()
                .is_admitted()
        );
        let token = started_token(begin(&mut mailbox, 0));
        let before = snapshot(&mailbox);

        let Err(failure) = mailbox.finish(token, TerminalReason::Evicted) else {
            panic!("queued-only terminal must be rejected for in-flight work");
        };
        assert_eq!(failure.error(), MailboxError::InvalidTerminalReason);
        assert_eq!(snapshot(&mailbox), before);
        let token = failure.into_token();
        let Ok(record) = mailbox.finish(token, TerminalReason::Cancelled) else {
            panic!("returned exact token must remain usable");
        };
        assert_eq!(record.reason(), TerminalReason::Cancelled);
        assert_eq!(snapshot(&mailbox).terminals().cancelled(), 1);
    }

    #[test]
    fn a_token_cannot_finish_another_mailbox() {
        let mut first = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(2, 8, 20, 1, 8, OverflowPolicy::RejectNew),
        );
        let mut second = mailbox_with(
            0x52,
            InteractionKind::Signal,
            spec(2, 8, 20, 1, 8, OverflowPolicy::RejectNew),
        );
        assert!(
            offer(&mut first, message(1, 2, 100), 0)
                .outcome()
                .is_admitted()
        );
        let token = started_token(begin(&mut first, 0));
        let first_before = snapshot(&first);
        let second_before = snapshot(&second);

        let Err(failure) = second.finish(token, TerminalReason::Completed) else {
            panic!("foreign mailbox token must fail closed");
        };
        assert_eq!(failure.error(), MailboxError::InflightTokenMismatch);
        assert_eq!(snapshot(&first), first_before);
        assert_eq!(snapshot(&second), second_before);
        let token = failure.into_token();
        let Ok(_) = first.finish(token, TerminalReason::Completed) else {
            panic!("token must remain owned after foreign-mailbox rejection");
        };
    }

    #[test]
    fn stop_drain_expire_finish_and_close_are_structured() {
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(3, 9, 5, 1, 9, OverflowPolicy::RejectNew),
        );
        assert!(
            offer(&mut mailbox, message(1, 3, 100), 0)
                .outcome()
                .is_admitted()
        );
        assert!(
            offer(&mut mailbox, message(2, 3, 100), 0)
                .outcome()
                .is_admitted()
        );
        let token = started_token(begin(&mut mailbox, 0));
        let Ok(()) = mailbox.stop_accepting() else {
            panic!("valid mailbox must stop accepting");
        };
        assert_eq!(snapshot(&mailbox).lifecycle(), MailboxLifecycle::Draining);

        let closed_offer = offer(&mut mailbox, message(3, 1, 0), 1);
        assert!(matches!(
            closed_offer.outcome(),
            EnqueueOutcome::Closed { .. }
        ));
        assert_eq!(snapshot(&mailbox).offers().closed(), 1);

        let Ok(expired) = mailbox.expire_queued(reading(5)) else {
            panic!("draining mailbox must expire queued work");
        };
        assert_eq!(expired.len(), 1);
        assert_eq!(snapshot(&mailbox).lifecycle(), MailboxLifecycle::Draining);

        let Ok(_) = mailbox.finish(token, TerminalReason::Completed) else {
            panic!("last in-flight Message must finish");
        };
        assert_eq!(snapshot(&mailbox).lifecycle(), MailboxLifecycle::Closed);
        let Ok(closed) = mailbox.close_if_drained() else {
            panic!("closed mailbox must remain valid");
        };
        assert!(closed);

        let wrong_clock = reading_at(CLOCK_DOMAIN.wrapping_add(1), CLOCK_GENERATION + 1, 99);
        let Ok(report) = mailbox.try_offer(message(4, 1, 0), wrong_clock) else {
            panic!("Closed outcome must take priority over Message and clock validation");
        };
        assert!(matches!(report.outcome(), EnqueueOutcome::Closed { .. }));
    }

    #[test]
    fn invalid_schema_and_interaction_are_explicit_rejections() {
        let mut mailbox = mailbox(OverflowPolicy::RejectNew);
        let schema_rejection = offer(
            &mut mailbox,
            message_with(1, 1, 100, schema(0x42), InteractionKind::Signal, None),
            0,
        );
        assert!(matches!(
            schema_rejection.outcome(),
            EnqueueOutcome::Rejected {
                reason: RejectionReason::SchemaMismatch,
                ..
            }
        ));
        let interaction_rejection = offer(
            &mut mailbox,
            message_with(2, 1, 100, schema(0x41), InteractionKind::Event, None),
            0,
        );
        assert!(matches!(
            interaction_rejection.outcome(),
            EnqueueOutcome::Rejected {
                reason: RejectionReason::InteractionMismatch,
                ..
            }
        ));
        assert_eq!(snapshot(&mailbox).offers().rejected(), 2);
    }

    #[test]
    fn event_mailbox_rejects_lossy_replacement_policies() {
        for overflow in [
            OverflowPolicy::DropOldest,
            OverflowPolicy::Latest,
            OverflowPolicy::CoalesceByKey,
        ] {
            let result = Mailbox::try_new(
                MailboxRef::from_bytes([0x51; 16]),
                schema(0x41),
                InteractionKind::Event,
                spec(2, 8, 20, 1, 8, overflow),
                ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16]),
                generation(CLOCK_GENERATION),
            );
            assert!(matches!(
                result,
                Err(MailboxError::UnsupportedInteractionPolicy)
            ));
        }
    }

    #[test]
    fn standalone_command_fixture_rejects_full_and_expired_without_replacement() {
        let command_spec = spec(1, 4, 20, 1, 4, OverflowPolicy::RejectNew);
        let Ok(mut mailbox) = Mailbox::try_new_command_fixture(
            MailboxRef::from_bytes([0x61; 16]),
            schema(0x41),
            command_spec,
            ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16]),
            generation(CLOCK_GENERATION),
        ) else {
            panic!("standalone Command conformance mailbox must be valid");
        };
        let first = ValidatedMessage::new_command_fixture(
            MessageId::from_bytes([1; 16]),
            schema(0x41),
            deadline_at(100),
            payload(4, 1),
        );
        assert!(offer(&mut mailbox, first, 0).outcome().is_admitted());

        let full = ValidatedMessage::new_command_fixture(
            MessageId::from_bytes([2; 16]),
            schema(0x41),
            deadline_at(100),
            payload(1, 2),
        );
        let full_report = offer(&mut mailbox, full, 0);
        assert!(matches!(
            full_report.outcome(),
            EnqueueOutcome::Rejected {
                reason: RejectionReason::CapacityFull,
                ..
            }
        ));
        assert!(full_report.terminals().is_empty());

        let expired = ValidatedMessage::new_command_fixture(
            MessageId::from_bytes([3; 16]),
            schema(0x41),
            deadline_at(0),
            payload(1, 3),
        );
        let expired_report = offer(&mut mailbox, expired, 0);
        assert!(matches!(
            expired_report.outcome(),
            EnqueueOutcome::ExpiredBeforeAdmission { .. }
        ));
        assert!(expired_report.terminals().is_empty());

        let state = snapshot(&mailbox);
        assert_eq!(state.queued_items(), 1);
        assert_eq!(state.offers().admitted(), 1);
        assert_eq!(state.offers().rejected(), 1);
        assert_eq!(state.offers().expired_before_admission(), 1);
        assert_eq!(state.terminals().evicted(), 0);
        assert_eq!(state.terminals().coalesced(), 0);
    }

    #[test]
    fn counter_overflow_is_fail_closed_and_atomic() {
        let mut mailbox = mailbox(OverflowPolicy::RejectNew);
        mailbox.offers.offered = u64::MAX;
        mailbox.offers.admitted = u64::MAX;
        mailbox.terminals.completed = u64::MAX;
        let before = snapshot(&mailbox);

        let result = mailbox.try_offer(message(1, 1, 100), reading(0));
        let Err(failure) = result else {
            panic!("terminal offer counter overflow must fail closed");
        };
        assert_eq!(failure.error(), MailboxError::CounterOverflow);
        assert_eq!(snapshot(&mailbox), before);
    }

    #[test]
    fn torn_byte_accounting_fails_before_any_mutation() {
        let mut mailbox = mailbox(OverflowPolicy::RejectNew);
        assert!(
            offer(&mut mailbox, message(1, 2, 100), 0)
                .outcome()
                .is_admitted()
        );
        mailbox.queued_bytes = 3;
        let queue_len_before = mailbox.queue.len();
        let result = mailbox.try_offer(message(2, 1, 100), reading(0));
        let Err(failure) = result else {
            panic!("torn accounting must fail closed");
        };
        assert_eq!(failure.error(), MailboxError::StateInconsistent);
        assert_eq!(mailbox.queue.len(), queue_len_before);
        assert_eq!(mailbox.queued_bytes, 3);
    }

    #[test]
    fn empty_draining_mailbox_closes_without_a_clock_or_background_task() {
        let mut mailbox = mailbox(OverflowPolicy::RejectNew);
        let Ok(()) = mailbox.stop_accepting() else {
            panic!("empty mailbox must stop accepting");
        };
        assert_eq!(snapshot(&mailbox).lifecycle(), MailboxLifecycle::Closed);
        let report = begin(&mut mailbox, u64::MAX);
        assert!(matches!(report.outcome(), DispatchOutcome::Closed));
    }

    #[test]
    fn payload_handle_is_immutable_and_exactly_charged() {
        let payload = payload(4, 0xAB);
        assert_eq!(payload.as_bytes(), &[0xAB; 4]);
        assert_eq!(payload.charged_bytes(), 4);
        let message = ValidatedMessage::new(
            MessageId::from_bytes([9; 16]),
            schema(0x41),
            InteractionKind::Signal,
            Some(CoalesceKey::from_bytes([8; 16])),
            deadline_at(50),
            payload,
        );
        assert_eq!(message.id().as_bytes(), &[9; 16]);
        assert_eq!(message.schema(), schema(0x41));
        assert_eq!(message.interaction(), Some(InteractionKind::Signal));
        assert_eq!(
            message.coalesce_key(),
            Some(CoalesceKey::from_bytes([8; 16]))
        );
        assert_eq!(message.deadline(), deadline_at(50));
        assert_eq!(message.fresh_until(), deadline_at(50));
        assert_eq!(message.run_deadline(), deadline_at(50));
        assert_eq!(message.payload().charged_bytes(), 4);

        let explicit = message_with_deadlines(10, 1, 20, 40);
        assert_eq!(explicit.fresh_until(), deadline_at(20));
        assert_eq!(explicit.run_deadline(), deadline_at(40));
        assert_eq!(explicit.deadline(), deadline_at(40));
    }

    #[test]
    fn all_inflight_completion_counters_are_fixed_width_and_conservative() {
        let completions = [
            TerminalReason::Completed,
            TerminalReason::Failed,
            TerminalReason::Cancelled,
            TerminalReason::ExpiredAfterAdmission,
            TerminalReason::Uncertain,
        ];
        let mut mailbox = mailbox_with(
            0x51,
            InteractionKind::Signal,
            spec(5, 10, 100, 1, 10, OverflowPolicy::RejectNew),
        );
        for (offset, reason) in completions.into_iter().enumerate() {
            let Ok(id) = u8::try_from(offset + 1) else {
                panic!("test completion index must fit in one byte");
            };
            assert!(
                offer(&mut mailbox, message(id, 1, 100), 0)
                    .outcome()
                    .is_admitted()
            );
            let token = started_token(begin(&mut mailbox, 0));
            let Ok(record) = mailbox.finish(token, reason) else {
                panic!("valid completion must reach a terminal");
            };
            assert_eq!(record.reason(), reason);
        }
        let state = snapshot(&mailbox);
        assert_eq!(state.terminals().completed(), 1);
        assert_eq!(state.terminals().failed(), 1);
        assert_eq!(state.terminals().cancelled(), 1);
        assert_eq!(state.terminals().expired_after_admission(), 1);
        assert_eq!(state.terminals().uncertain(), 1);
        assert_eq!(state.queued_items(), 0);
        assert_eq!(state.inflight_items(), 0);
        assert_eq!(state.retained_bytes(), 0);
    }
}
