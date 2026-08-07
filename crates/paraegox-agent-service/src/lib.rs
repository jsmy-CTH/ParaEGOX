//! Semantic owner for DeckRun-bound Agent conversation sessions.
//!
//! This crate owns bounded Session, Turn, request, terminal, and event semantics.
//! It has no transport, Runtime, process, credential, Tool, or Memory authority.
//! On POSIX, its optional owner-private journal persists immutable semantic events
//! and rebuilds the same in-memory projection after restart. Snapshot and event
//! exports remain read-only values, not a second persistence authority.

#[cfg(unix)]
mod journal;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
#[cfg(unix)]
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(unix)]
pub use journal::AgentSessionJournalError;
#[cfg(unix)]
use journal::{DurableAgentSessionJournal, JournalEvent, JournalRecord};
use paraegox_agent_contracts::control::{
    AgentConversationCancelStateV1, AgentConversationControlBodyV1, AgentConversationControlError,
    AgentConversationControlV1, AgentConversationGetStateV1, AgentConversationOpenOutcomeV1,
    AgentConversationWatchBatchV1, AgentConversationWatchEventKindV1,
    AgentConversationWatchEventV1, MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES,
    MAX_AGENT_CONVERSATION_WATCH_EVENTS,
};
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalFailureV1,
    AgentConversationTerminalResultV1, AgentConversationTerminalV1, AgentConversationTurnId,
    MAX_AGENT_CONVERSATION_REQUESTS,
};
use paraegox_kernel::time::BoundedDuration;
use paraegox_model::{
    ModelBackendV1, ModelCancellationSourceV1, ModelCancellationViewV1, ModelInvocationIdV1,
    ModelInvocationOutcomeV1, ModelInvocationRequestV1, ModelServiceV1,
};

/// Hard implementation ceiling for simultaneously retained in-memory sessions.
pub const MAX_AGENT_SERVICE_SESSIONS: usize = 256;
/// Hard implementation ceiling for turns retained by one in-memory session.
pub const MAX_AGENT_SERVICE_TURNS_PER_SESSION: usize = 1_024;
/// Hard ceiling for one event export call; retained events are bounded by ledgers.
pub const MAX_AGENT_SERVICE_EVENT_BATCH: usize = 1_024;

/// Explicit bounds for one in-memory AgentService owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentServiceConfigV1 {
    max_sessions: usize,
    max_turns_per_session: usize,
    max_requests_per_session: usize,
    max_event_batch: usize,
}

impl AgentServiceConfigV1 {
    pub fn try_new(
        max_sessions: usize,
        max_turns_per_session: usize,
        max_requests_per_session: usize,
        max_event_batch: usize,
    ) -> Result<Self, AgentServiceError> {
        if !(1..=MAX_AGENT_SERVICE_SESSIONS).contains(&max_sessions)
            || !(1..=MAX_AGENT_SERVICE_TURNS_PER_SESSION).contains(&max_turns_per_session)
            || !(1..=MAX_AGENT_CONVERSATION_REQUESTS).contains(&max_requests_per_session)
            || !(1..=MAX_AGENT_SERVICE_EVENT_BATCH).contains(&max_event_batch)
        {
            return Err(AgentServiceError::ConfigOutOfRange);
        }
        Ok(Self {
            max_sessions,
            max_turns_per_session,
            max_requests_per_session,
            max_event_batch,
        })
    }

    #[must_use]
    pub const fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    #[must_use]
    pub const fn max_turns_per_session(&self) -> usize {
        self.max_turns_per_session
    }

    #[must_use]
    pub const fn max_requests_per_session(&self) -> usize {
        self.max_requests_per_session
    }

    #[must_use]
    pub const fn max_event_batch(&self) -> usize {
        self.max_event_batch
    }

    fn max_journal_records(&self) -> usize {
        let admitted_per_session = self
            .max_turns_per_session
            .min(self.max_requests_per_session);
        // One SessionOpened and at most acceptance, model handoff, cancel
        // intent, and terminal records per admitted request, plus one
        // DeckRunSealed per DeckRun.
        (2 * self.max_sessions) + (4 * self.max_sessions * admitted_per_session)
    }
}

impl Default for AgentServiceConfigV1 {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            max_turns_per_session: 256,
            max_requests_per_session: 256,
            max_event_batch: 256,
        }
    }
}

/// Stable service-level failures that do not fabricate a protocol terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentServiceError {
    ConfigOutOfRange,
    SessionCapacityExhausted,
    UnknownSession,
    DeckRunSealed,
    SessionSealed,
    EventLimitOutOfRange,
    EventCursorAhead,
    DeckRunCapacityExhausted,
    DurableRecoveryRequired,
    InvalidControlRequest,
    Control(AgentConversationControlError),
    #[cfg(unix)]
    Journal(AgentSessionJournalError),
}

impl fmt::Display for AgentServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ConfigOutOfRange => "AgentService configuration is out of range",
            Self::SessionCapacityExhausted => "AgentService session capacity is exhausted",
            Self::UnknownSession => "AgentService session is unknown",
            Self::DeckRunSealed => "AgentService DeckRun is sealed",
            Self::SessionSealed => "AgentService session is sealed",
            Self::EventLimitOutOfRange => "AgentService event export limit is out of range",
            Self::EventCursorAhead => "AgentService event cursor is ahead of the session",
            Self::DeckRunCapacityExhausted => "AgentService DeckRun capacity is exhausted",
            Self::DurableRecoveryRequired => {
                "AgentService has an accepted request that requires durable reopen"
            }
            Self::InvalidControlRequest => "AgentService expected a control request frame",
            Self::Control(error) => return error.fmt(formatter),
            #[cfg(unix)]
            Self::Journal(error) => return error.fmt(formatter),
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AgentServiceError {}

impl From<AgentConversationControlError> for AgentServiceError {
    fn from(error: AgentConversationControlError) -> Self {
        Self::Control(error)
    }
}

#[cfg(unix)]
impl From<AgentSessionJournalError> for AgentServiceError {
    fn from(error: AgentSessionJournalError) -> Self {
        Self::Journal(error)
    }
}

/// One owned, non-borrowing model operation.
///
/// The future must not borrow its provider. This lets the caller continue
/// driving AgentService controls while the model operation is pending.
pub type AgentConversationModelFuture =
    Pin<Box<dyn Future<Output = AgentConversationModelOutcomeV1> + Send + 'static>>;

/// Read-only cooperative cancellation observation passed to one provider call.
///
/// Only AgentService can request cancellation, and it does so only after the
/// cancellation intent has been durably recorded when journaling is enabled.
#[derive(Clone, Debug)]
pub struct AgentConversationModelCancellation {
    view: ModelCancellationViewV1,
}

impl AgentConversationModelCancellation {
    fn model_view(&self) -> ModelCancellationViewV1 {
        self.view.clone()
    }

    #[must_use]
    pub fn is_cancellation_requested(&self) -> bool {
        self.view.is_cancellation_requested()
    }
}

fn new_model_cancellation() -> (
    ModelCancellationSourceV1,
    AgentConversationModelCancellation,
) {
    let source = ModelCancellationSourceV1::new();
    let cancellation = AgentConversationModelCancellation {
        view: source.view(),
    };
    (source, cancellation)
}

/// Provider-reported completion admitted by the AgentService semantic owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentConversationModelOutcomeV1 {
    Success(Box<str>),
    Failed,
    DeadlineExceeded,
    CancelledBeforeHandoff,
    OutcomeUncertain,
    CapacityExhausted,
}

/// Linear proof that AgentService durably committed model handoff.
///
/// This value is intentionally non-Clone and cannot be constructed outside
/// this crate. Consuming it is the only way to commit a provider outcome.
#[derive(Debug)]
pub struct AgentServiceModelInvocationV1 {
    request: AgentConversationRequestV1,
    cancellation: AgentConversationModelCancellation,
}

impl AgentServiceModelInvocationV1 {
    #[must_use]
    pub const fn request(&self) -> &AgentConversationRequestV1 {
        &self.request
    }

    #[must_use]
    pub fn cancellation(&self) -> AgentConversationModelCancellation {
        self.cancellation.clone()
    }
}

/// One text-only model invocation. It owns no AgentSession or event state.
pub trait AgentConversationModelProvider: Send {
    fn complete(
        &mut self,
        request: AgentConversationRequestV1,
        cancellation: AgentConversationModelCancellation,
    ) -> AgentConversationModelFuture;
}

/// Agent-facing adapter around one provider-neutral [`ModelServiceV1`].
///
/// AgentService retains Session, Turn, durable handoff, cancellation-intent,
/// and terminal authority. This adapter only translates one already-admitted
/// Agent request into a model invocation and maps its provider-neutral result.
pub struct AgentConversationModelServiceProviderV1<B: ModelBackendV1> {
    service: ModelServiceV1<B>,
}

impl<B: ModelBackendV1> AgentConversationModelServiceProviderV1<B> {
    /// Installs an embedded ModelService without transferring Agent semantics.
    #[must_use]
    pub fn new(service: ModelServiceV1<B>) -> Self {
        Self { service }
    }

    /// Returns the shared ModelService for read-only snapshots or composition.
    #[must_use]
    pub const fn model_service(&self) -> &ModelServiceV1<B> {
        &self.service
    }
}

impl<B: ModelBackendV1> AgentConversationModelProvider
    for AgentConversationModelServiceProviderV1<B>
{
    fn complete(
        &mut self,
        request: AgentConversationRequestV1,
        cancellation: AgentConversationModelCancellation,
    ) -> AgentConversationModelFuture {
        let invocation_id = ModelInvocationIdV1::try_from_bytes(*request.request_id().as_bytes());
        let Ok(invocation_id) = invocation_id else {
            return Box::pin(std::future::ready(AgentConversationModelOutcomeV1::Failed));
        };
        let model_request = ModelInvocationRequestV1::try_new(
            invocation_id,
            request.request_digest(),
            BoundedDuration::from_nanos(request.deadline_budget_nanos()),
            request.input(),
        );
        let Ok(model_request) = model_request else {
            return Box::pin(std::future::ready(AgentConversationModelOutcomeV1::Failed));
        };
        let operation = self
            .service
            .invoke(model_request, cancellation.model_view());
        Box::pin(async move {
            match operation.await {
                ModelInvocationOutcomeV1::Success(output) => {
                    AgentConversationModelOutcomeV1::Success(output)
                }
                ModelInvocationOutcomeV1::Failed => AgentConversationModelOutcomeV1::Failed,
                ModelInvocationOutcomeV1::DeadlineExceeded => {
                    AgentConversationModelOutcomeV1::DeadlineExceeded
                }
                ModelInvocationOutcomeV1::CancelledBeforeHandoff => {
                    AgentConversationModelOutcomeV1::CancelledBeforeHandoff
                }
                ModelInvocationOutcomeV1::OutcomeUncertain => {
                    AgentConversationModelOutcomeV1::OutcomeUncertain
                }
                ModelInvocationOutcomeV1::CapacityExhausted => {
                    AgentConversationModelOutcomeV1::CapacityExhausted
                }
            }
        })
    }
}

/// Offline deterministic provider fixture; it is not evidence of a real model.
#[derive(Clone, Debug, Default)]
pub struct DeterministicEchoModelProvider {
    calls: Arc<AtomicUsize>,
}

impl DeterministicEchoModelProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl AgentConversationModelProvider for DeterministicEchoModelProvider {
    fn complete(
        &mut self,
        request: AgentConversationRequestV1,
        _cancellation: AgentConversationModelCancellation,
    ) -> AgentConversationModelFuture {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move {
            AgentConversationModelOutcomeV1::Success(
                format!("echo: {}", request.input()).into_boxed_str(),
            )
        })
    }
}

/// Idempotent result of opening the same DeckRun-bound Session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentSessionOpenOutcomeV1 {
    Opened,
    Existing,
}

/// Observable result of one synchronous request submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentServiceSubmitOutcomeV1 {
    TerminalCommitted(AgentConversationTerminalV1),
    TerminalReplay(AgentConversationTerminalV1),
    Rejected(AgentConversationTerminalV1),
}

/// Result of durably admitting a request without entering the model provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentServiceAcceptOutcomeV1 {
    Accepted,
    PendingReplay,
    TerminalReplay(AgentConversationTerminalV1),
    Rejected(AgentConversationTerminalV1),
}

impl AgentServiceSubmitOutcomeV1 {
    #[must_use]
    pub const fn terminal(&self) -> &AgentConversationTerminalV1 {
        match self {
            Self::TerminalCommitted(terminal)
            | Self::TerminalReplay(terminal)
            | Self::Rejected(terminal) => terminal,
        }
    }
}

/// Append-only event kinds retained by one live in-memory Session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentServiceEventKindV1 {
    SessionOpened,
    RequestAccepted(AgentConversationRequestV1),
    TerminalCommitted(AgentConversationTerminalV1),
    CancelIntentRecorded(AgentConversationRequestId),
    SessionSealed,
}

/// One monotonically sequenced in-memory Session event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentServiceEventV1 {
    sequence: u64,
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    kind: AgentServiceEventKindV1,
}

impl AgentServiceEventV1 {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn deck_run_id(&self) -> AgentConversationDeckRunId {
        self.deck_run_id
    }

    #[must_use]
    pub const fn session_id(&self) -> AgentConversationSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn kind(&self) -> &AgentServiceEventKindV1 {
        &self.kind
    }
}

/// Explicit cursor batch exported from the retained in-memory event sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentServiceEventBatchV1 {
    events: Box<[AgentServiceEventV1]>,
    next_cursor: u64,
    high_watermark: u64,
    has_more: bool,
    sealed: bool,
}

impl AgentServiceEventBatchV1 {
    #[must_use]
    pub fn events(&self) -> &[AgentServiceEventV1] {
        &self.events
    }

    #[must_use]
    pub const fn next_cursor(&self) -> u64 {
        self.next_cursor
    }

    #[must_use]
    pub const fn high_watermark(&self) -> u64 {
        self.high_watermark
    }

    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }
}

/// Turn-to-request binding exported in a Session snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentServiceTurnSnapshotV1 {
    turn_id: AgentConversationTurnId,
    request_id: AgentConversationRequestId,
}

impl AgentServiceTurnSnapshotV1 {
    #[must_use]
    pub const fn turn_id(&self) -> AgentConversationTurnId {
        self.turn_id
    }

    #[must_use]
    pub const fn request_id(&self) -> AgentConversationRequestId {
        self.request_id
    }
}

/// Request and its optional terminal exported in a Session snapshot.
///
/// `None` is a live, durably accepted request that has not committed a terminal.
/// A healthy durable reopen resolves every such historical pending request to
/// `ModelOutcomeUncertain` rather than replaying the provider implicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentServiceRequestSnapshotV1 {
    request: AgentConversationRequestV1,
    terminal: Option<AgentConversationTerminalV1>,
    cancel_requested: bool,
    model_handoff_committed: bool,
}

impl AgentServiceRequestSnapshotV1 {
    #[must_use]
    pub const fn request(&self) -> &AgentConversationRequestV1 {
        &self.request
    }

    #[must_use]
    pub const fn terminal(&self) -> Option<&AgentConversationTerminalV1> {
        self.terminal.as_ref()
    }

    #[must_use]
    pub const fn cancel_requested(&self) -> bool {
        self.cancel_requested
    }

    #[must_use]
    pub const fn model_handoff_committed(&self) -> bool {
        self.model_handoff_committed
    }
}

/// Complete read-only value snapshot of one retained in-memory Session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentServiceSessionSnapshotV1 {
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    sealed: bool,
    event_high_watermark: u64,
    turns: Box<[AgentServiceTurnSnapshotV1]>,
    requests: Box<[AgentServiceRequestSnapshotV1]>,
}

impl AgentServiceSessionSnapshotV1 {
    #[must_use]
    pub const fn deck_run_id(&self) -> AgentConversationDeckRunId {
        self.deck_run_id
    }

    #[must_use]
    pub const fn session_id(&self) -> AgentConversationSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    #[must_use]
    pub const fn event_high_watermark(&self) -> u64 {
        self.event_high_watermark
    }

    #[must_use]
    pub fn turns(&self) -> &[AgentServiceTurnSnapshotV1] {
        &self.turns
    }

    #[must_use]
    pub fn requests(&self) -> &[AgentServiceRequestSnapshotV1] {
        &self.requests
    }
}

/// Result of sealing every Session owned by one DeckRun.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentDeckRunSealReportV1 {
    deck_run_id: AgentConversationDeckRunId,
    already_sealed: bool,
    newly_sealed_sessions: usize,
    retained_sessions: usize,
    retained_requests: usize,
}

impl AgentDeckRunSealReportV1 {
    #[must_use]
    pub const fn deck_run_id(&self) -> AgentConversationDeckRunId {
        self.deck_run_id
    }

    #[must_use]
    pub const fn already_sealed(&self) -> bool {
        self.already_sealed
    }

    #[must_use]
    pub const fn newly_sealed_sessions(&self) -> usize {
        self.newly_sealed_sessions
    }

    #[must_use]
    pub const fn retained_sessions(&self) -> usize {
        self.retained_sessions
    }

    #[must_use]
    pub const fn retained_requests(&self) -> usize {
        self.retained_requests
    }
}

#[derive(Debug)]
struct TurnRecord {
    request_id: AgentConversationRequestId,
}

#[derive(Debug)]
struct RequestRecord {
    request: AgentConversationRequestV1,
    terminal: Option<AgentConversationTerminalV1>,
    cancel_requested: bool,
    model_handoff_committed: bool,
    cancellation_source: ModelCancellationSourceV1,
    cancellation: AgentConversationModelCancellation,
}

#[derive(Debug)]
struct SessionRecord {
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    sealed: bool,
    turns: BTreeMap<AgentConversationTurnId, TurnRecord>,
    requests: BTreeMap<AgentConversationRequestId, RequestRecord>,
    events: Vec<AgentServiceEventV1>,
    next_event_sequence: u64,
}

impl SessionRecord {
    fn new(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
    ) -> Self {
        let mut session = Self {
            deck_run_id,
            session_id,
            sealed: false,
            turns: BTreeMap::new(),
            requests: BTreeMap::new(),
            events: Vec::new(),
            next_event_sequence: 1,
        };
        session.append_event(AgentServiceEventKindV1::SessionOpened);
        session
    }

    fn append_event(&mut self, kind: AgentServiceEventKindV1) {
        let sequence = self.next_event_sequence;
        self.next_event_sequence = self
            .next_event_sequence
            .checked_add(1)
            .expect("bounded Session event sequence cannot exhaust u64");
        self.events.push(AgentServiceEventV1 {
            sequence,
            deck_run_id: self.deck_run_id,
            session_id: self.session_id,
            kind,
        });
    }

    fn high_watermark(&self) -> u64 {
        self.next_event_sequence - 1
    }
}

type SessionKey = (AgentConversationDeckRunId, AgentConversationSessionId);

/// Single in-memory owner for AgentSession and Turn semantics.
#[derive(Debug)]
pub struct AgentService {
    config: AgentServiceConfigV1,
    sessions: BTreeMap<SessionKey, SessionRecord>,
    sealed_deck_runs: BTreeSet<AgentConversationDeckRunId>,
    #[cfg(unix)]
    journal: Option<DurableAgentSessionJournal>,
}

impl AgentService {
    #[must_use]
    pub fn new(config: AgentServiceConfigV1) -> Self {
        Self {
            config,
            sessions: BTreeMap::new(),
            sealed_deck_runs: BTreeSet::new(),
            #[cfg(unix)]
            journal: None,
        }
    }

    /// Opens the single-writer owner-private POSIX journal and rebuilds state.
    #[cfg(unix)]
    pub fn open_durable(
        config: AgentServiceConfigV1,
        journal_root: &Path,
    ) -> Result<Self, AgentServiceError> {
        let (journal, records) =
            DurableAgentSessionJournal::open(journal_root, config.max_journal_records())?;
        let mut service = Self {
            config,
            sessions: BTreeMap::new(),
            sealed_deck_runs: BTreeSet::new(),
            journal: Some(journal),
        };
        for record in records {
            service.apply_recovered_record(record)?;
        }
        service.resolve_recovered_pending_requests()?;
        Ok(service)
    }

    pub fn open_session(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
    ) -> Result<AgentSessionOpenOutcomeV1, AgentServiceError> {
        if self.sealed_deck_runs.contains(&deck_run_id) {
            return Err(AgentServiceError::DeckRunSealed);
        }
        let key = (deck_run_id, session_id);
        if self.sessions.contains_key(&key) {
            return Ok(AgentSessionOpenOutcomeV1::Existing);
        }
        if self.sessions.len() >= self.config.max_sessions {
            return Err(AgentServiceError::SessionCapacityExhausted);
        }
        self.persist_session_opened(deck_run_id, session_id)?;
        self.sessions
            .insert(key, SessionRecord::new(deck_run_id, session_id));
        Ok(AgentSessionOpenOutcomeV1::Opened)
    }

    /// Durably admits a request without entering the model provider.
    pub fn accept_request(
        &mut self,
        request: AgentConversationRequestV1,
    ) -> Result<AgentServiceAcceptOutcomeV1, AgentServiceError> {
        let key = (request.deck_run_id(), request.session_id());
        {
            let session = self
                .sessions
                .get(&key)
                .ok_or(AgentServiceError::UnknownSession)?;
            if session.sealed {
                return Err(AgentServiceError::SessionSealed);
            }
            if let Some(record) = session.requests.get(&request.request_id()) {
                if record.request == request {
                    return match &record.terminal {
                        Some(terminal) => Ok(AgentServiceAcceptOutcomeV1::TerminalReplay(
                            terminal.clone(),
                        )),
                        None => Ok(AgentServiceAcceptOutcomeV1::PendingReplay),
                    };
                }
                return Ok(AgentServiceAcceptOutcomeV1::Rejected(rejection_terminal(
                    &request,
                    AgentConversationTerminalFailureV1::RequestConflict,
                )));
            }
            if session.turns.contains_key(&request.turn_id()) {
                return Ok(AgentServiceAcceptOutcomeV1::Rejected(rejection_terminal(
                    &request,
                    AgentConversationTerminalFailureV1::RequestConflict,
                )));
            }
            if session.requests.len() >= self.config.max_requests_per_session
                || session.turns.len() >= self.config.max_turns_per_session
            {
                return Ok(AgentServiceAcceptOutcomeV1::Rejected(rejection_terminal(
                    &request,
                    AgentConversationTerminalFailureV1::CapacityExhausted,
                )));
            }
        }

        // This immutable acceptance is synced before the provider can observe
        // the request. A crash after this point is recovered as uncertain and
        // never causes an implicit provider replay.
        self.persist_request_accepted(&request)?;
        {
            let session = self
                .sessions
                .get_mut(&key)
                .expect("validated Session remains owned during synchronous submit");
            session.turns.insert(
                request.turn_id(),
                TurnRecord {
                    request_id: request.request_id(),
                },
            );
            let (cancellation_source, cancellation) = new_model_cancellation();
            session.requests.insert(
                request.request_id(),
                RequestRecord {
                    request: request.clone(),
                    terminal: None,
                    cancel_requested: false,
                    model_handoff_committed: false,
                    cancellation_source,
                    cancellation,
                },
            );
            session.append_event(AgentServiceEventKindV1::RequestAccepted(request.clone()));
        }
        Ok(AgentServiceAcceptOutcomeV1::Accepted)
    }

    /// Durably commits provider handoff for one already accepted request.
    ///
    /// The returned proof is linear. Provider code must not observe the
    /// request before this method succeeds.
    pub fn begin_execution(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
    ) -> Result<AgentServiceModelInvocationV1, AgentServiceError> {
        let key = (deck_run_id, session_id);
        let (request, cancellation) = {
            let session = self
                .sessions
                .get(&key)
                .ok_or(AgentServiceError::UnknownSession)?;
            let record = session
                .requests
                .get(&request_id)
                .ok_or(AgentServiceError::DurableRecoveryRequired)?;
            if record.terminal.is_some()
                || record.cancel_requested
                || record.model_handoff_committed
            {
                return Err(AgentServiceError::DurableRecoveryRequired);
            }
            (record.request.clone(), record.cancellation.clone())
        };

        self.persist_model_handoff_committed(deck_run_id, session_id, request_id)?;
        self.sessions
            .get_mut(&key)
            .expect("accepted Session remains owned")
            .requests
            .get_mut(&request_id)
            .expect("accepted request remains owned")
            .model_handoff_committed = true;
        Ok(AgentServiceModelInvocationV1 {
            request,
            cancellation,
        })
    }

    /// Consumes one linear invocation proof and durably commits its terminal.
    pub fn complete_execution(
        &mut self,
        invocation: AgentServiceModelInvocationV1,
        outcome: AgentConversationModelOutcomeV1,
    ) -> Result<AgentServiceSubmitOutcomeV1, AgentServiceError> {
        let request = invocation.request;
        let key = (request.deck_run_id(), request.session_id());
        let record = self
            .sessions
            .get(&key)
            .and_then(|session| session.requests.get(&request.request_id()))
            .ok_or(AgentServiceError::DurableRecoveryRequired)?;
        if record.request != request || !record.model_handoff_committed || record.terminal.is_some()
        {
            return Err(AgentServiceError::DurableRecoveryRequired);
        }

        let terminal = match outcome {
            AgentConversationModelOutcomeV1::Success(output) => {
                AgentConversationTerminalV1::try_success(&request, &output).unwrap_or_else(|_| {
                    AgentConversationTerminalV1::failure(
                        &request,
                        AgentConversationTerminalFailureV1::ModelFailed,
                    )
                })
            }
            AgentConversationModelOutcomeV1::Failed => AgentConversationTerminalV1::failure(
                &request,
                AgentConversationTerminalFailureV1::ModelFailed,
            ),
            AgentConversationModelOutcomeV1::DeadlineExceeded => {
                AgentConversationTerminalV1::failure(
                    &request,
                    AgentConversationTerminalFailureV1::DeadlineExceeded,
                )
            }
            AgentConversationModelOutcomeV1::CapacityExhausted => {
                AgentConversationTerminalV1::failure(
                    &request,
                    AgentConversationTerminalFailureV1::CapacityExhausted,
                )
            }
            // Once this linear token exists, AgentService has already durably
            // recorded handoff. A provider's narrower pre-network-handoff
            // observation therefore cannot prove CancelledBeforeModel.
            AgentConversationModelOutcomeV1::CancelledBeforeHandoff
            | AgentConversationModelOutcomeV1::OutcomeUncertain => {
                AgentConversationTerminalV1::failure(
                    &request,
                    AgentConversationTerminalFailureV1::ModelOutcomeUncertain,
                )
            }
        };
        self.commit_admitted_terminal(terminal.clone())?;
        Ok(AgentServiceSubmitOutcomeV1::TerminalCommitted(terminal))
    }

    /// Seals a DeckRun once while retaining its Sessions for explicit queries.
    pub fn seal_deck_run(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
    ) -> Result<AgentDeckRunSealReportV1, AgentServiceError> {
        if self.sealed_deck_runs.contains(&deck_run_id) {
            return Ok(self.deck_run_seal_report(deck_run_id, true, 0));
        }
        if self.sealed_deck_runs.len() >= self.config.max_sessions {
            return Err(AgentServiceError::DeckRunCapacityExhausted);
        }
        self.persist_deck_run_sealed(deck_run_id)?;
        self.sealed_deck_runs.insert(deck_run_id);
        let mut newly_sealed_sessions = 0;
        for ((candidate_deck_run_id, _), session) in &mut self.sessions {
            if *candidate_deck_run_id != deck_run_id {
                continue;
            }
            if !session.sealed {
                session.sealed = true;
                session.append_event(AgentServiceEventKindV1::SessionSealed);
                newly_sealed_sessions += 1;
            }
        }
        Ok(self.deck_run_seal_report(deck_run_id, false, newly_sealed_sessions))
    }

    /// Exports the full retained Session value without defining a storage format.
    pub fn export_session_snapshot(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
    ) -> Result<AgentServiceSessionSnapshotV1, AgentServiceError> {
        let session = self
            .sessions
            .get(&(deck_run_id, session_id))
            .ok_or(AgentServiceError::UnknownSession)?;
        let turns = session
            .turns
            .iter()
            .map(|(turn_id, record)| AgentServiceTurnSnapshotV1 {
                turn_id: *turn_id,
                request_id: record.request_id,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let requests = session
            .requests
            .values()
            .map(|record| AgentServiceRequestSnapshotV1 {
                request: record.request.clone(),
                terminal: record.terminal.clone(),
                cancel_requested: record.cancel_requested,
                model_handoff_committed: record.model_handoff_committed,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(AgentServiceSessionSnapshotV1 {
            deck_run_id,
            session_id,
            sealed: session.sealed,
            event_high_watermark: session.high_watermark(),
            turns,
            requests,
        })
    }

    /// Exports events strictly after `cursor`; zero starts at SessionOpened.
    pub fn export_session_events(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        cursor: u64,
        limit: usize,
    ) -> Result<AgentServiceEventBatchV1, AgentServiceError> {
        if limit == 0 || limit > self.config.max_event_batch {
            return Err(AgentServiceError::EventLimitOutOfRange);
        }
        let session = self
            .sessions
            .get(&(deck_run_id, session_id))
            .ok_or(AgentServiceError::UnknownSession)?;
        let high_watermark = session.high_watermark();
        if cursor > high_watermark {
            return Err(AgentServiceError::EventCursorAhead);
        }
        let events = session
            .events
            .iter()
            .filter(|event| event.sequence > cursor)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = events.last().map_or(cursor, AgentServiceEventV1::sequence);
        Ok(AgentServiceEventBatchV1 {
            has_more: next_cursor < high_watermark,
            events: events.into_boxed_slice(),
            next_cursor,
            high_watermark,
            sealed: session.sealed,
        })
    }

    /// Queries a committed terminal even after the owning Session is sealed.
    pub fn terminal(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
    ) -> Result<Option<&AgentConversationTerminalV1>, AgentServiceError> {
        let session = self
            .sessions
            .get(&(deck_run_id, session_id))
            .ok_or(AgentServiceError::UnknownSession)?;
        Ok(session
            .requests
            .get(&request_id)
            .and_then(|record| record.terminal.as_ref()))
    }

    /// Handles one typed open/get/watch/cancel request. Query and cancellation
    /// endpoints never create a missing Session implicitly.
    pub fn handle_control(
        &mut self,
        control: &AgentConversationControlV1,
    ) -> Result<AgentConversationControlV1, AgentServiceError> {
        let deck_run_id = control.deck_run_id();
        let session_id = control.session_id();
        match control.body() {
            AgentConversationControlBodyV1::OpenRequest => {
                let outcome = match self.open_session(deck_run_id, session_id) {
                    Ok(AgentSessionOpenOutcomeV1::Opened) => AgentConversationOpenOutcomeV1::Opened,
                    Ok(AgentSessionOpenOutcomeV1::Existing) => {
                        AgentConversationOpenOutcomeV1::Existing
                    }
                    Err(AgentServiceError::DeckRunSealed) => {
                        AgentConversationOpenOutcomeV1::DeckRunSealed
                    }
                    Err(AgentServiceError::SessionCapacityExhausted) => {
                        AgentConversationOpenOutcomeV1::CapacityExhausted
                    }
                    Err(error) => return Err(error),
                };
                Ok(AgentConversationControlV1::open_result(
                    deck_run_id,
                    session_id,
                    outcome,
                ))
            }
            AgentConversationControlBodyV1::GetRequest => {
                let request_id = control
                    .request_id()
                    .ok_or(AgentServiceError::InvalidControlRequest)?;
                AgentConversationControlV1::get_result(
                    deck_run_id,
                    session_id,
                    request_id,
                    self.get_state(deck_run_id, session_id, request_id),
                )
                .map_err(Into::into)
            }
            AgentConversationControlBodyV1::WatchRequest { cursor, limit } => {
                self.watch_control(deck_run_id, session_id, *cursor, *limit)
            }
            AgentConversationControlBodyV1::CancelRequest => {
                let request_id = control
                    .request_id()
                    .ok_or(AgentServiceError::InvalidControlRequest)?;
                let state = self.cancel_request(deck_run_id, session_id, request_id)?;
                AgentConversationControlV1::cancel_result(
                    deck_run_id,
                    session_id,
                    request_id,
                    state,
                )
                .map_err(Into::into)
            }
            _ => Err(AgentServiceError::InvalidControlRequest),
        }
    }

    /// Records cancellation intent and commits a cancelled terminal only when
    /// this owner can prove that provider execution has not started.
    pub fn cancel_request(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
    ) -> Result<AgentConversationCancelStateV1, AgentServiceError> {
        let key = (deck_run_id, session_id);
        let (request, model_handoff_committed) = {
            let Some(session) = self.sessions.get(&key) else {
                return Ok(AgentConversationCancelStateV1::NotFound);
            };
            let Some(record) = session.requests.get(&request_id) else {
                return Ok(AgentConversationCancelStateV1::NotFound);
            };
            if let Some(terminal) = &record.terminal {
                return Ok(AgentConversationCancelStateV1::Terminal(terminal.clone()));
            }
            if session.sealed {
                return Ok(AgentConversationCancelStateV1::SessionSealed);
            }
            if record.cancel_requested {
                return Ok(AgentConversationCancelStateV1::IntentAlreadyRecorded);
            }
            (record.request.clone(), record.model_handoff_committed)
        };

        self.persist_cancel_intent(deck_run_id, session_id, request_id)?;
        {
            let session = self
                .sessions
                .get_mut(&key)
                .expect("validated Session remains owned");
            session
                .requests
                .get_mut(&request_id)
                .expect("validated request remains owned")
                .cancel_requested = true;
            session.append_event(AgentServiceEventKindV1::CancelIntentRecorded(request_id));
            session
                .requests
                .get(&request_id)
                .expect("validated request remains owned")
                .cancellation_source
                .request_cancellation();
        }
        // The provider cannot observe this signal until the durable journal
        // append and in-memory projection above have both succeeded.
        if model_handoff_committed {
            return Ok(AgentConversationCancelStateV1::IntentRecorded);
        }

        let terminal = AgentConversationTerminalV1::failure(
            &request,
            AgentConversationTerminalFailureV1::CancelledBeforeModel,
        );
        self.commit_admitted_terminal(terminal.clone())?;
        Ok(AgentConversationCancelStateV1::Terminal(terminal))
    }

    fn get_state(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
    ) -> AgentConversationGetStateV1 {
        self.sessions
            .get(&(deck_run_id, session_id))
            .and_then(|session| session.requests.get(&request_id))
            .map_or(AgentConversationGetStateV1::NotFound, |record| {
                record.terminal.as_ref().map_or(
                    AgentConversationGetStateV1::Pending {
                        cancel_requested: record.cancel_requested,
                    },
                    |terminal| AgentConversationGetStateV1::Terminal(terminal.clone()),
                )
            })
    }

    fn watch_control(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        cursor: u64,
        limit: u32,
    ) -> Result<AgentConversationControlV1, AgentServiceError> {
        if !self.sessions.contains_key(&(deck_run_id, session_id)) {
            return Ok(AgentConversationControlV1::watch_result_not_found(
                deck_run_id,
                session_id,
            ));
        }
        let requested = usize::try_from(limit)
            .map_err(|_| AgentServiceError::EventLimitOutOfRange)?
            .min(self.config.max_event_batch)
            .min(MAX_AGENT_CONVERSATION_WATCH_EVENTS);
        let source = self.export_session_events(deck_run_id, session_id, cursor, requested)?;
        let mut encoded_bytes = 24_usize;
        let mut events = Vec::new();
        for event in source.events() {
            let (kind, payload_bytes) = match event.kind() {
                AgentServiceEventKindV1::SessionOpened => {
                    (AgentConversationWatchEventKindV1::SessionOpened, 0)
                }
                AgentServiceEventKindV1::RequestAccepted(request) => (
                    AgentConversationWatchEventKindV1::RequestAccepted(request.clone()),
                    request.canonical_wire().len(),
                ),
                AgentServiceEventKindV1::TerminalCommitted(terminal) => (
                    AgentConversationWatchEventKindV1::TerminalCommitted(terminal.clone()),
                    terminal.canonical_wire().len(),
                ),
                AgentServiceEventKindV1::CancelIntentRecorded(request_id) => (
                    AgentConversationWatchEventKindV1::CancelIntentRecorded(*request_id),
                    16,
                ),
                AgentServiceEventKindV1::SessionSealed => {
                    (AgentConversationWatchEventKindV1::SessionSealed, 0)
                }
            };
            let next_bytes = encoded_bytes
                .checked_add(16 + payload_bytes)
                .ok_or(AgentServiceError::EventLimitOutOfRange)?;
            if next_bytes > MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES {
                break;
            }
            events.push(AgentConversationWatchEventV1::try_new(
                event.sequence(),
                kind,
            )?);
            encoded_bytes = next_bytes;
        }
        let next_cursor = events
            .last()
            .map_or(cursor, AgentConversationWatchEventV1::sequence);
        let batch = AgentConversationWatchBatchV1::try_new(
            events.into_boxed_slice(),
            next_cursor,
            source.high_watermark(),
            next_cursor < source.high_watermark(),
            source.is_sealed(),
        )?;
        batch.validate_for_request(cursor, limit)?;
        AgentConversationControlV1::watch_result(deck_run_id, session_id, batch).map_err(Into::into)
    }

    fn commit_admitted_terminal(
        &mut self,
        terminal: AgentConversationTerminalV1,
    ) -> Result<(), AgentServiceError> {
        let key = (terminal.deck_run_id(), terminal.session_id());
        self.persist_terminal_committed(&terminal)?;
        let session = self
            .sessions
            .get_mut(&key)
            .expect("terminal Session remains owned");
        session
            .requests
            .get_mut(&terminal.request_id())
            .expect("terminal request remains owned")
            .terminal = Some(terminal.clone());
        session.append_event(AgentServiceEventKindV1::TerminalCommitted(terminal));
        Ok(())
    }

    fn deck_run_seal_report(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        already_sealed: bool,
        newly_sealed_sessions: usize,
    ) -> AgentDeckRunSealReportV1 {
        let mut retained_sessions = 0;
        let mut retained_requests = 0;
        for ((candidate_deck_run_id, _), session) in &self.sessions {
            if *candidate_deck_run_id == deck_run_id {
                retained_sessions += 1;
                retained_requests += session.requests.len();
            }
        }
        AgentDeckRunSealReportV1 {
            deck_run_id,
            already_sealed,
            newly_sealed_sessions,
            retained_sessions,
            retained_requests,
        }
    }

    fn persist_session_opened(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
    ) -> Result<(), AgentServiceError> {
        #[cfg(unix)]
        if let Some(journal) = &mut self.journal {
            journal.append(&JournalEvent::SessionOpened {
                deck_run_id,
                session_id,
            })?;
        }
        #[cfg(not(unix))]
        let _ = (deck_run_id, session_id);
        Ok(())
    }

    fn persist_request_accepted(
        &mut self,
        request: &AgentConversationRequestV1,
    ) -> Result<(), AgentServiceError> {
        #[cfg(unix)]
        if let Some(journal) = &mut self.journal {
            journal.append(&JournalEvent::RequestAccepted(request.clone()))?;
        }
        #[cfg(not(unix))]
        let _ = request;
        Ok(())
    }

    fn persist_terminal_committed(
        &mut self,
        terminal: &AgentConversationTerminalV1,
    ) -> Result<(), AgentServiceError> {
        #[cfg(unix)]
        if let Some(journal) = &mut self.journal {
            journal.append(&JournalEvent::TerminalCommitted(terminal.clone()))?;
        }
        #[cfg(not(unix))]
        let _ = terminal;
        Ok(())
    }

    fn persist_model_handoff_committed(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
    ) -> Result<(), AgentServiceError> {
        #[cfg(unix)]
        if let Some(journal) = &mut self.journal {
            journal.append(&JournalEvent::ModelHandoffCommitted {
                deck_run_id,
                session_id,
                request_id,
            })?;
        }
        #[cfg(not(unix))]
        let _ = (deck_run_id, session_id, request_id);
        Ok(())
    }

    fn persist_cancel_intent(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
    ) -> Result<(), AgentServiceError> {
        #[cfg(unix)]
        if let Some(journal) = &mut self.journal {
            journal.append(&JournalEvent::CancelIntentRecorded {
                deck_run_id,
                session_id,
                request_id,
            })?;
        }
        #[cfg(not(unix))]
        let _ = (deck_run_id, session_id, request_id);
        Ok(())
    }

    fn persist_deck_run_sealed(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
    ) -> Result<(), AgentServiceError> {
        #[cfg(unix)]
        if let Some(journal) = &mut self.journal {
            journal.append(&JournalEvent::DeckRunSealed(deck_run_id))?;
        }
        #[cfg(not(unix))]
        let _ = deck_run_id;
        Ok(())
    }

    #[cfg(unix)]
    fn apply_recovered_record(&mut self, record: JournalRecord) -> Result<(), AgentServiceError> {
        let JournalRecord { sequence: _, event } = record;
        self.apply_recovered_event(event)
    }

    #[cfg(unix)]
    fn apply_recovered_event(&mut self, event: JournalEvent) -> Result<(), AgentServiceError> {
        match event {
            JournalEvent::SessionOpened {
                deck_run_id,
                session_id,
            } => {
                let key = (deck_run_id, session_id);
                if self.sealed_deck_runs.contains(&deck_run_id)
                    || self.sessions.contains_key(&key)
                    || self.sessions.len() >= self.config.max_sessions
                {
                    return Err(AgentSessionJournalError::StateConflict.into());
                }
                self.sessions
                    .insert(key, SessionRecord::new(deck_run_id, session_id));
            }
            JournalEvent::RequestAccepted(request) => {
                let key = (request.deck_run_id(), request.session_id());
                let session = self
                    .sessions
                    .get_mut(&key)
                    .ok_or(AgentSessionJournalError::StateConflict)?;
                if session.sealed
                    || session.requests.contains_key(&request.request_id())
                    || session.turns.contains_key(&request.turn_id())
                    || session.requests.len() >= self.config.max_requests_per_session
                    || session.turns.len() >= self.config.max_turns_per_session
                {
                    return Err(AgentSessionJournalError::StateConflict.into());
                }
                session.turns.insert(
                    request.turn_id(),
                    TurnRecord {
                        request_id: request.request_id(),
                    },
                );
                let (cancellation_source, cancellation) = new_model_cancellation();
                session.requests.insert(
                    request.request_id(),
                    RequestRecord {
                        request: request.clone(),
                        terminal: None,
                        cancel_requested: false,
                        model_handoff_committed: false,
                        cancellation_source,
                        cancellation,
                    },
                );
                session.append_event(AgentServiceEventKindV1::RequestAccepted(request));
            }
            JournalEvent::ModelHandoffCommitted {
                deck_run_id,
                session_id,
                request_id,
            } => {
                let session = self
                    .sessions
                    .get_mut(&(deck_run_id, session_id))
                    .ok_or(AgentSessionJournalError::StateConflict)?;
                let request = session
                    .requests
                    .get_mut(&request_id)
                    .ok_or(AgentSessionJournalError::StateConflict)?;
                if session.sealed
                    || request.terminal.is_some()
                    || request.cancel_requested
                    || request.model_handoff_committed
                {
                    return Err(AgentSessionJournalError::StateConflict.into());
                }
                request.model_handoff_committed = true;
            }
            JournalEvent::CancelIntentRecorded {
                deck_run_id,
                session_id,
                request_id,
            } => {
                let session = self
                    .sessions
                    .get_mut(&(deck_run_id, session_id))
                    .ok_or(AgentSessionJournalError::StateConflict)?;
                let request = session
                    .requests
                    .get_mut(&request_id)
                    .ok_or(AgentSessionJournalError::StateConflict)?;
                if session.sealed || request.terminal.is_some() || request.cancel_requested {
                    return Err(AgentSessionJournalError::StateConflict.into());
                }
                request.cancel_requested = true;
                session.append_event(AgentServiceEventKindV1::CancelIntentRecorded(request_id));
                session
                    .requests
                    .get(&request_id)
                    .expect("recovered request remains owned")
                    .cancellation_source
                    .request_cancellation();
            }
            JournalEvent::TerminalCommitted(terminal) => {
                if !is_admitted_terminal(&terminal) {
                    return Err(AgentSessionJournalError::StateConflict.into());
                }
                let key = (terminal.deck_run_id(), terminal.session_id());
                let session = self
                    .sessions
                    .get_mut(&key)
                    .ok_or(AgentSessionJournalError::StateConflict)?;
                let request = session
                    .requests
                    .get_mut(&terminal.request_id())
                    .ok_or(AgentSessionJournalError::StateConflict)?;
                let cancelled_before_model = matches!(
                    terminal.result(),
                    AgentConversationTerminalResultV1::Failure(
                        AgentConversationTerminalFailureV1::CancelledBeforeModel
                    )
                );
                if request.terminal.is_some()
                    || !terminal.correlates(&request.request)
                    || (cancelled_before_model
                        && (!request.cancel_requested || request.model_handoff_committed))
                {
                    return Err(AgentSessionJournalError::StateConflict.into());
                }
                request.terminal = Some(terminal.clone());
                session.append_event(AgentServiceEventKindV1::TerminalCommitted(terminal));
            }
            JournalEvent::DeckRunSealed(deck_run_id) => {
                if self.sealed_deck_runs.contains(&deck_run_id)
                    || self.sealed_deck_runs.len() >= self.config.max_sessions
                {
                    return Err(AgentSessionJournalError::StateConflict.into());
                }
                self.sealed_deck_runs.insert(deck_run_id);
                for ((candidate_deck_run_id, _), session) in &mut self.sessions {
                    if *candidate_deck_run_id == deck_run_id {
                        session.sealed = true;
                        session.append_event(AgentServiceEventKindV1::SessionSealed);
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn resolve_recovered_pending_requests(&mut self) -> Result<(), AgentServiceError> {
        let pending = self
            .sessions
            .values()
            .flat_map(|session| session.requests.values())
            .filter(|record| record.terminal.is_none())
            .map(|record| {
                (
                    record.request.clone(),
                    record.cancel_requested && !record.model_handoff_committed,
                )
            })
            .collect::<Vec<_>>();
        for (request, cancelled_before_model) in pending {
            let terminal = AgentConversationTerminalV1::failure(
                &request,
                if cancelled_before_model {
                    AgentConversationTerminalFailureV1::CancelledBeforeModel
                } else {
                    AgentConversationTerminalFailureV1::ModelOutcomeUncertain
                },
            );
            self.persist_terminal_committed(&terminal)?;
            self.apply_recovered_event(JournalEvent::TerminalCommitted(terminal))?;
        }
        Ok(())
    }

    #[must_use]
    pub fn retained_sessions(&self) -> usize {
        self.sessions.len()
    }
}

fn is_admitted_terminal(terminal: &AgentConversationTerminalV1) -> bool {
    match terminal.result() {
        AgentConversationTerminalResultV1::Success(_) => true,
        AgentConversationTerminalResultV1::Failure(failure) => matches!(
            failure,
            AgentConversationTerminalFailureV1::ModelFailed
                | AgentConversationTerminalFailureV1::DeadlineExceeded
                | AgentConversationTerminalFailureV1::CapacityExhausted
                | AgentConversationTerminalFailureV1::ModelOutcomeUncertain
                | AgentConversationTerminalFailureV1::CancelledBeforeModel
        ),
    }
}

fn rejection_terminal(
    request: &AgentConversationRequestV1,
    failure: AgentConversationTerminalFailureV1,
) -> AgentConversationTerminalV1 {
    AgentConversationTerminalV1::failure(request, failure)
}
