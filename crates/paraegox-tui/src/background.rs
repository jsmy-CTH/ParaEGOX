use core::{fmt, future::Future, pin::Pin, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};

use paraegox_agent_contracts::control::{
    AgentConversationCancelStateV1, AgentConversationOpenOutcomeV1,
};
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestV1, AgentConversationSessionId,
    AgentConversationTerminalV1,
};
use tokio::sync::mpsc;

use crate::{
    ConversationClient, ConversationClientError, ConversationClientEvent,
    ConversationConnectionState,
};

/// Hard ceiling for UI-to-worker commands retained by one local chat adapter.
pub const MAX_BACKGROUND_CONVERSATION_COMMANDS: usize = 32;
const MAX_BACKGROUND_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);

/// One owned operation issued through a Runtime-provided typed capability.
pub type AgentConversationCapabilityFuture<T> =
    Pin<Box<dyn Future<Output = Result<T, ConversationClientError>> + Send + 'static>>;

/// Runtime-provided Agent conversation capability consumed by the TUI adapter.
///
/// Implementations may wrap the production AgentConversationClient and its
/// managed Fabric handle, but must never expose raw Fabric, key expressions,
/// RuntimeHost internals, journals, or credentials to this crate. Every future
/// must be cancellation-safe and honor the supplied finite operation timeout.
/// The adapter also wraps every future in its own timeout and never retries it.
/// Calling any trait method must itself be finite, non-blocking, and
/// non-panicking: it may validate, clone, or take already-owned handles while
/// constructing the future, but must not wait for I/O, timers, externally
/// controlled locks, or lifecycle completion. The supplied timeout and the
/// adapter's timeout supervise only the returned future, not its constructor.
/// An implementation that violates this rule is incompatible because it can
/// prevent the adapter's joined shutdown from completing.
pub trait AgentConversationCapability: Send + 'static {
    fn open_session(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        timeout: Duration,
    ) -> AgentConversationCapabilityFuture<AgentConversationOpenOutcomeV1>;

    fn submit(
        &mut self,
        request: AgentConversationRequestV1,
        timeout: Duration,
    ) -> AgentConversationCapabilityFuture<AgentConversationTerminalV1>;

    fn cancel(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request: paraegox_agent_contracts::AgentConversationRequestId,
        timeout: Duration,
    ) -> AgentConversationCapabilityFuture<AgentConversationCancelStateV1>;

    fn close(&mut self, timeout: Duration) -> AgentConversationCapabilityFuture<()>;
}

/// Synchronous identity allocator used before a command is admitted.
///
/// A production composition supplies a restart-safe client-instance nonce or
/// another owner-approved allocator. Advancing an identity after queue
/// rejection is allowed; reusing an identity is not.
pub trait AgentConversationRequestFactory: Send + 'static {
    fn create_request(
        &mut self,
        input: &str,
        deadline_budget_nanos: u64,
    ) -> Result<AgentConversationRequestV1, ConversationClientError>;
}

/// Bounded local-chat composition inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackgroundConversationClientConfig {
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    command_capacity: usize,
    operation_timeout: Duration,
}

impl BackgroundConversationClientConfig {
    pub fn try_new(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        command_capacity: usize,
        operation_timeout: Duration,
    ) -> Result<Self, BackgroundConversationClientConfigError> {
        if !(1..=MAX_BACKGROUND_CONVERSATION_COMMANDS).contains(&command_capacity) {
            return Err(BackgroundConversationClientConfigError::CommandCapacityOutOfRange);
        }
        if operation_timeout.is_zero() || operation_timeout > MAX_BACKGROUND_OPERATION_TIMEOUT {
            return Err(BackgroundConversationClientConfigError::OperationTimeoutOutOfRange);
        }
        Ok(Self {
            deck_run_id,
            session_id,
            command_capacity,
            operation_timeout,
        })
    }

    #[must_use]
    pub const fn deck_run_id(self) -> AgentConversationDeckRunId {
        self.deck_run_id
    }

    #[must_use]
    pub const fn session_id(self) -> AgentConversationSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn command_capacity(self) -> usize {
        self.command_capacity
    }

    #[must_use]
    pub const fn operation_timeout(self) -> Duration {
        self.operation_timeout
    }
}

/// Invalid background adapter bounds rejected before a worker is spawned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackgroundConversationClientConfigError {
    CommandCapacityOutOfRange,
    OperationTimeoutOutOfRange,
}

impl fmt::Display for BackgroundConversationClientConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CommandCapacityOutOfRange => {
                "background conversation command capacity is out of range"
            }
            Self::OperationTimeoutOutOfRange => {
                "background conversation operation timeout is out of range"
            }
        })
    }
}

impl std::error::Error for BackgroundConversationClientConfigError {}

enum WorkerCommand {
    Connect,
    Submit(AgentConversationRequestV1),
    Cancel(AgentConversationRequestV1),
}

#[derive(Default)]
struct WorkerEventSlots {
    connection: Option<ConversationConnectionState>,
    terminal: Option<AgentConversationTerminalV1>,
    failure: Option<ConversationClientError>,
}

struct PendingOperation {
    request: AgentConversationRequestV1,
    future: AgentConversationCapabilityFuture<AgentConversationTerminalV1>,
    cancel_attempted: bool,
}

/// Synchronous TUI facade backed by one owned, joined async worker.
pub struct BackgroundConversationClient {
    config: BackgroundConversationClientConfig,
    request_factory: Box<dyn AgentConversationRequestFactory>,
    commands: Option<mpsc::Sender<WorkerCommand>>,
    events: Arc<Mutex<WorkerEventSlots>>,
    close_requested: Arc<AtomicBool>,
    close_deadline: Arc<OnceLock<tokio::time::Instant>>,
    worker: Option<JoinHandle<Result<(), ConversationClientError>>>,
    connection: ConversationConnectionState,
    connect_started: bool,
    pending: Option<AgentConversationRequestV1>,
    cancellation_queued: bool,
    closed: bool,
}

impl BackgroundConversationClient {
    /// Composes the local TUI facade from a typed capability and request owner.
    pub fn spawn(
        config: BackgroundConversationClientConfig,
        request_factory: impl AgentConversationRequestFactory,
        capability: impl AgentConversationCapability,
    ) -> Result<Self, ConversationClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ConversationClientError::new("background runtime creation failed"))?;
        let (command_sender, command_receiver) = mpsc::channel(config.command_capacity);
        let events = Arc::new(Mutex::new(WorkerEventSlots::default()));
        let close_requested = Arc::new(AtomicBool::new(false));
        let close_deadline = Arc::new(OnceLock::new());
        let worker_events = Arc::clone(&events);
        let worker_close = Arc::clone(&close_requested);
        let worker_close_deadline = Arc::clone(&close_deadline);
        let worker = thread::Builder::new()
            .name("paraegox-tui-conversation".to_owned())
            .spawn(move || {
                runtime.block_on(run_worker(
                    config,
                    Box::new(capability),
                    command_receiver,
                    worker_events,
                    worker_close,
                    worker_close_deadline,
                ))
            })
            .map_err(|_| ConversationClientError::new("background worker spawn failed"))?;
        Ok(Self {
            config,
            request_factory: Box::new(request_factory),
            commands: Some(command_sender),
            events,
            close_requested,
            close_deadline,
            worker: Some(worker),
            connection: ConversationConnectionState::Disconnected,
            connect_started: false,
            pending: None,
            cancellation_queued: false,
            closed: false,
        })
    }

    fn send_command(&self, command: WorkerCommand) -> Result<(), ConversationClientError> {
        let sender = self
            .commands
            .as_ref()
            .ok_or_else(|| ConversationClientError::new("conversation adapter is closed"))?;
        sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                ConversationClientError::new("conversation command queue is full")
            }
            mpsc::error::TrySendError::Closed(_) => {
                ConversationClientError::new("conversation background worker is unavailable")
            }
        })
    }

    fn close_inner(&mut self) -> Result<(), ConversationClientError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let _ = self
            .close_deadline
            .set(tokio::time::Instant::now() + self.config.operation_timeout);
        self.close_requested.store(true, Ordering::Release);
        self.commands.take();
        let worker_result = self.worker.take().map_or(Ok(()), |worker| {
            worker
                .join()
                .map_err(|_| ConversationClientError::new("conversation worker panicked"))?
        });
        self.pending = None;
        self.cancellation_queued = false;
        self.connection = ConversationConnectionState::Disconnected;
        worker_result
    }
}

impl ConversationClient for BackgroundConversationClient {
    fn begin_connect(&mut self) -> Result<(), ConversationClientError> {
        if self.closed {
            return Err(ConversationClientError::new(
                "conversation adapter is closed",
            ));
        }
        if self.connect_started {
            return Err(ConversationClientError::new(
                "conversation connection was already started",
            ));
        }
        self.send_command(WorkerCommand::Connect)?;
        self.connect_started = true;
        self.connection = ConversationConnectionState::Connecting;
        Ok(())
    }

    fn poll_event(&mut self) -> Result<Option<ConversationClientEvent>, ConversationClientError> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| ConversationClientError::new("conversation event slots are poisoned"))?;
        if let Some(error) = events.failure.take() {
            self.connection = ConversationConnectionState::Disconnected;
            return Err(error);
        }
        if let Some(connection) = events.connection.take() {
            self.connection = connection;
            return Ok(Some(ConversationClientEvent::ConnectionChanged(connection)));
        }
        if let Some(terminal) = events.terminal.take() {
            let pending = self.pending.as_ref().ok_or_else(|| {
                ConversationClientError::new("terminal arrived without a pending TUI request")
            })?;
            if !terminal.correlates(pending) {
                self.connection = ConversationConnectionState::Disconnected;
                return Err(ConversationClientError::new(
                    "terminal does not correlate to the pending TUI request",
                ));
            }
            self.pending = None;
            self.cancellation_queued = false;
            return Ok(Some(ConversationClientEvent::Terminal(terminal)));
        }
        Ok(None)
    }

    fn submit_turn(
        &mut self,
        input: &str,
        deadline_budget_nanos: u64,
    ) -> Result<AgentConversationRequestV1, ConversationClientError> {
        if self.closed || self.connection != ConversationConnectionState::Connected {
            return Err(ConversationClientError::new(
                "conversation service is not connected",
            ));
        }
        if self.pending.is_some() {
            return Err(ConversationClientError::new(
                "one conversation request is already pending",
            ));
        }
        let request = self
            .request_factory
            .create_request(input, deadline_budget_nanos)?;
        if request.deck_run_id() != self.config.deck_run_id
            || request.session_id() != self.config.session_id
            || request.input() != input
            || request.deadline_budget_nanos() != deadline_budget_nanos
        {
            return Err(ConversationClientError::new(
                "request factory returned a mismatched conversation request",
            ));
        }
        self.send_command(WorkerCommand::Submit(request.clone()))?;
        self.pending = Some(request.clone());
        self.cancellation_queued = false;
        Ok(request)
    }

    fn request_cancel(
        &mut self,
        request: &AgentConversationRequestV1,
    ) -> Result<(), ConversationClientError> {
        let pending = self.pending.as_ref().ok_or_else(|| {
            ConversationClientError::new("conversation adapter has no pending request")
        })?;
        if pending != request {
            return Err(ConversationClientError::new(
                "cancellation does not match the pending request",
            ));
        }
        if self.cancellation_queued {
            return Ok(());
        }
        self.send_command(WorkerCommand::Cancel(request.clone()))?;
        self.cancellation_queued = true;
        Ok(())
    }

    fn close(&mut self) -> Result<(), ConversationClientError> {
        self.close_inner()
    }
}

impl Drop for BackgroundConversationClient {
    fn drop(&mut self) {
        let _ = self.close_inner();
    }
}

async fn run_worker(
    config: BackgroundConversationClientConfig,
    mut capability: Box<dyn AgentConversationCapability>,
    mut commands: mpsc::Receiver<WorkerCommand>,
    events: Arc<Mutex<WorkerEventSlots>>,
    close_requested: Arc<AtomicBool>,
    close_deadline: Arc<OnceLock<tokio::time::Instant>>,
) -> Result<(), ConversationClientError> {
    let mut connected = false;
    let mut pending: Option<PendingOperation> = None;
    let mut completed_request_identity = None;
    let mut first_error = None;

    loop {
        if close_requested.load(Ordering::Acquire) {
            break;
        }
        if let Some(mut operation) = pending.take() {
            tokio::select! {
                result = operation.future.as_mut() => {
                    match result.and_then(|terminal| validate_terminal(&operation.request, terminal)) {
                        Ok(terminal) => {
                            let request_identity = (
                                operation.request.deck_run_id(),
                                operation.request.session_id(),
                                operation.request.request_id(),
                            );
                            if let Err(error) = publish_terminal(&events, terminal) {
                                publish_failure(&events, error.clone());
                                first_error = Some(error);
                                break;
                            }
                            completed_request_identity = Some(request_identity);
                        }
                        Err(error) => {
                            publish_connection(&events, ConversationConnectionState::Disconnected);
                            publish_failure(&events, error.clone());
                            first_error = Some(error);
                            // A client-side timeout or invalid terminal does
                            // not prove that the handed-off semantic request
                            // stopped. Preserve its exact identity so shutdown
                            // records cancellation intent once before close.
                            pending = Some(operation);
                            break;
                        }
                    }
                }
                command = commands.recv() => {
                    if close_requested.load(Ordering::Acquire) || command.is_none() {
                        pending = Some(operation);
                        break;
                    }
                    let Some(command) = command else {
                        pending = Some(operation);
                        break;
                    };
                    match command {
                        WorkerCommand::Cancel(request) if request == operation.request => {
                            operation.cancel_attempted = true;
                            let operation_deadline =
                                worker_operation_deadline(config.operation_timeout);
                            let cancel = bounded_worker_operation(
                                capability.cancel(
                                    request.deck_run_id(),
                                    request.session_id(),
                                    request.request_id(),
                                    config.operation_timeout,
                                ),
                                operation_deadline,
                                &close_deadline,
                                "cancel",
                            )
                            .await;
                            match cancel {
                                Ok(AgentConversationCancelStateV1::Terminal(terminal)) => {
                                    match validate_terminal(&operation.request, terminal)
                                        .and_then(|terminal| publish_terminal(&events, terminal))
                                    {
                                        Ok(()) => {
                                            completed_request_identity = Some((
                                                operation.request.deck_run_id(),
                                                operation.request.session_id(),
                                                operation.request.request_id(),
                                            ));
                                        }
                                        Err(error) => {
                                            publish_failure(&events, error.clone());
                                            first_error = Some(error);
                                            break;
                                        }
                                    }
                                }
                                Ok(AgentConversationCancelStateV1::IntentRecorded
                                    | AgentConversationCancelStateV1::IntentAlreadyRecorded) => {
                                    pending = Some(operation);
                                }
                                Ok(AgentConversationCancelStateV1::NotFound) => {
                                    let error = ConversationClientError::new(
                                        "cancel target was not found by AgentService",
                                    );
                                    publish_failure(&events, error.clone());
                                    first_error = Some(error);
                                    break;
                                }
                                Ok(AgentConversationCancelStateV1::SessionSealed) => {
                                    let error = ConversationClientError::new(
                                        "cancel target Session is sealed",
                                    );
                                    publish_failure(&events, error.clone());
                                    first_error = Some(error);
                                    break;
                                }
                                Err(error) => {
                                    publish_connection(
                                        &events,
                                        ConversationConnectionState::Disconnected,
                                    );
                                    publish_failure(&events, error.clone());
                                    first_error = Some(error);
                                    pending = Some(operation);
                                    break;
                                }
                            }
                        }
                        WorkerCommand::Cancel(_) => {
                            let error = ConversationClientError::new(
                                "worker received cancellation for a different request",
                            );
                            publish_failure(&events, error.clone());
                            first_error = Some(error);
                            pending = Some(operation);
                            break;
                        }
                        WorkerCommand::Submit(_) => {
                            let error = ConversationClientError::new(
                                "worker received a second concurrent submit",
                            );
                            publish_failure(&events, error.clone());
                            first_error = Some(error);
                            pending = Some(operation);
                            break;
                        }
                        WorkerCommand::Connect => {
                            let error = ConversationClientError::new(
                                "worker received a duplicate connect command",
                            );
                            publish_failure(&events, error.clone());
                            first_error = Some(error);
                            pending = Some(operation);
                            break;
                        }
                    }
                }
            }
            continue;
        }

        let Some(command) = commands.recv().await else {
            break;
        };
        if close_requested.load(Ordering::Acquire) {
            break;
        }
        match command {
            WorkerCommand::Connect if !connected => {
                publish_connection(&events, ConversationConnectionState::Connecting);
                let operation_deadline = worker_operation_deadline(config.operation_timeout);
                let opened = bounded_worker_operation(
                    capability.open_session(
                        config.deck_run_id,
                        config.session_id,
                        config.operation_timeout,
                    ),
                    operation_deadline,
                    &close_deadline,
                    "open Session",
                )
                .await;
                match opened {
                    Ok(
                        AgentConversationOpenOutcomeV1::Opened
                        | AgentConversationOpenOutcomeV1::Existing,
                    ) => {
                        connected = true;
                        publish_connection(&events, ConversationConnectionState::Connected);
                    }
                    Ok(AgentConversationOpenOutcomeV1::DeckRunSealed) => {
                        let error = ConversationClientError::new("conversation DeckRun is sealed");
                        publish_connection(&events, ConversationConnectionState::Disconnected);
                        publish_failure(&events, error.clone());
                        first_error = Some(error);
                        break;
                    }
                    Ok(AgentConversationOpenOutcomeV1::CapacityExhausted) => {
                        let error = ConversationClientError::new(
                            "AgentService Session capacity is exhausted",
                        );
                        publish_connection(&events, ConversationConnectionState::Disconnected);
                        publish_failure(&events, error.clone());
                        first_error = Some(error);
                        break;
                    }
                    Err(error) => {
                        publish_connection(&events, ConversationConnectionState::Disconnected);
                        publish_failure(&events, error.clone());
                        first_error = Some(error);
                        break;
                    }
                }
            }
            WorkerCommand::Submit(request) if connected => {
                completed_request_identity = None;
                let operation_deadline = worker_operation_deadline(config.operation_timeout);
                let future = bounded_worker_operation(
                    capability.submit(request.clone(), config.operation_timeout),
                    operation_deadline,
                    &close_deadline,
                    "submit",
                );
                pending = Some(PendingOperation {
                    request,
                    future,
                    cancel_attempted: false,
                });
            }
            WorkerCommand::Cancel(request)
                if completed_request_identity
                    == Some((
                        request.deck_run_id(),
                        request.session_id(),
                        request.request_id(),
                    )) =>
            {
                // The facade can enqueue cancellation after the worker has
                // published a terminal but before the UI drains it. Preserve
                // that terminal and treat its exact late cancellation as the
                // same idempotent intent, without calling the capability again.
            }
            WorkerCommand::Cancel(_) => {
                let error = ConversationClientError::new(
                    "worker received cancellation without a pending request",
                );
                publish_failure(&events, error.clone());
                first_error = Some(error);
                break;
            }
            WorkerCommand::Connect | WorkerCommand::Submit(_) => {
                let error = ConversationClientError::new(
                    "worker received a command before a usable connection",
                );
                publish_failure(&events, error.clone());
                first_error = Some(error);
                break;
            }
        }
    }

    let shutdown_error = shutdown_worker(
        config,
        capability.as_mut(),
        pending,
        &events,
        close_deadline.get().copied(),
    )
    .await;
    match (first_error, shutdown_error) {
        (Some(error), _) | (None, Some(error)) => Err(error),
        (None, None) => Ok(()),
    }
}

async fn shutdown_worker(
    config: BackgroundConversationClientConfig,
    capability: &mut dyn AgentConversationCapability,
    pending: Option<PendingOperation>,
    events: &Arc<Mutex<WorkerEventSlots>>,
    requested_deadline: Option<tokio::time::Instant>,
) -> Option<ConversationClientError> {
    // Cancellation and capability close are one shutdown operation. Reusing
    // the per-operation timeout for each step would let a joined close block
    // for twice the configured bound when both futures remain pending.
    let shutdown_deadline = requested_deadline
        .unwrap_or_else(|| tokio::time::Instant::now() + config.operation_timeout);
    let mut first_error = None;
    if let Some(operation) = pending {
        if !operation.cancel_attempted {
            let cancellation_timeout = remaining_until(shutdown_deadline);
            let cancellation = bounded_operation_until(
                capability.cancel(
                    operation.request.deck_run_id(),
                    operation.request.session_id(),
                    operation.request.request_id(),
                    cancellation_timeout,
                ),
                shutdown_deadline,
                "shutdown cancel",
            )
            .await;
            match cancellation {
                Ok(AgentConversationCancelStateV1::Terminal(terminal)) => {
                    if let Err(error) = validate_terminal(&operation.request, terminal)
                        .and_then(|terminal| publish_terminal(events, terminal))
                    {
                        first_error = Some(error);
                    }
                }
                Ok(
                    AgentConversationCancelStateV1::IntentRecorded
                    | AgentConversationCancelStateV1::IntentAlreadyRecorded
                    | AgentConversationCancelStateV1::NotFound
                    | AgentConversationCancelStateV1::SessionSealed,
                ) => {}
                Err(error) => first_error = Some(error),
            }
        }
        drop(operation);
    }
    let close_timeout = remaining_until(shutdown_deadline);
    let close = bounded_operation_until(
        capability.close(close_timeout),
        shutdown_deadline,
        "capability close",
    )
    .await;
    if let Err(error) = close
        && first_error.is_none()
    {
        first_error = Some(error);
    }
    publish_connection(events, ConversationConnectionState::Disconnected);
    if let Some(error) = &first_error {
        publish_failure(events, error.clone());
    }
    first_error
}

fn worker_operation_deadline(timeout: Duration) -> tokio::time::Instant {
    tokio::time::Instant::now() + timeout
}

fn bounded_worker_operation<T: Send + 'static>(
    future: AgentConversationCapabilityFuture<T>,
    operation_deadline: tokio::time::Instant,
    close_deadline: &OnceLock<tokio::time::Instant>,
    operation: &'static str,
) -> AgentConversationCapabilityFuture<T> {
    // The operation deadline is captured before invoking the capability's
    // synchronous method. If close wins while that method is returning its
    // future, the published close deadline is selected here. If close wins
    // after this read, the already-captured operation deadline is necessarily
    // no later because both budgets have the same configured duration.
    let effective_deadline =
        select_worker_operation_deadline(operation_deadline, close_deadline.get().copied());
    bounded_operation_until(future, effective_deadline, operation)
}

fn select_worker_operation_deadline(
    operation_deadline: tokio::time::Instant,
    close_deadline: Option<tokio::time::Instant>,
) -> tokio::time::Instant {
    close_deadline.map_or(operation_deadline, |deadline| {
        deadline.min(operation_deadline)
    })
}

fn bounded_operation_until<T: Send + 'static>(
    future: AgentConversationCapabilityFuture<T>,
    deadline: tokio::time::Instant,
    operation: &'static str,
) -> AgentConversationCapabilityFuture<T> {
    Box::pin(async move {
        tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| {
                ConversationClientError::new(
                    format!("{operation} exceeded its operation timeout").into_boxed_str(),
                )
            })?
    })
}

fn remaining_until(deadline: tokio::time::Instant) -> Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}

fn validate_terminal(
    request: &AgentConversationRequestV1,
    terminal: AgentConversationTerminalV1,
) -> Result<AgentConversationTerminalV1, ConversationClientError> {
    if terminal.correlates(request) {
        Ok(terminal)
    } else {
        Err(ConversationClientError::new(
            "capability returned a terminal for a different request",
        ))
    }
}

fn publish_connection(
    events: &Arc<Mutex<WorkerEventSlots>>,
    connection: ConversationConnectionState,
) {
    if let Ok(mut events) = events.lock() {
        events.connection = Some(connection);
    }
}

fn publish_terminal(
    events: &Arc<Mutex<WorkerEventSlots>>,
    terminal: AgentConversationTerminalV1,
) -> Result<(), ConversationClientError> {
    let mut events = events
        .lock()
        .map_err(|_| ConversationClientError::new("conversation event slots are poisoned"))?;
    if events.terminal.is_some() {
        return Err(ConversationClientError::new(
            "conversation terminal slot is already occupied",
        ));
    }
    events.terminal = Some(terminal);
    Ok(())
}

fn publish_failure(events: &Arc<Mutex<WorkerEventSlots>>, error: ConversationClientError) {
    if let Ok(mut events) = events.lock()
        && events.failure.is_none()
    {
        events.failure = Some(error);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::Instant;

    use paraegox_agent_contracts::{
        AgentConversationRequestId, AgentConversationTerminalResultV1, AgentConversationTurnId,
    };
    use tokio::sync::oneshot;

    use super::*;

    const TEST_DEADLINE_BUDGET_NANOS: u64 = 1_000_000_000;
    const TEST_WAIT: Duration = Duration::from_secs(2);

    #[derive(Debug, Default)]
    struct FixtureState {
        opens: Vec<(AgentConversationDeckRunId, AgentConversationSessionId)>,
        submissions: Vec<AgentConversationRequestV1>,
        cancellations: Vec<(
            AgentConversationDeckRunId,
            AgentConversationSessionId,
            AgentConversationRequestId,
        )>,
        cancellation_timeouts: Vec<Duration>,
        closes: usize,
        close_timeouts: Vec<Duration>,
    }

    enum OpenBehavior {
        Ready,
        Gated(oneshot::Receiver<()>),
    }

    enum SubmitBehavior {
        Ready,
        Pending,
        Gated(oneshot::Receiver<()>),
    }

    #[derive(Clone, Copy)]
    enum ShutdownBehavior {
        Ready,
        Pending,
    }

    struct FixtureCapability {
        state: Arc<Mutex<FixtureState>>,
        open_behavior: Option<OpenBehavior>,
        submit_behaviors: VecDeque<SubmitBehavior>,
        cancel_behavior: ShutdownBehavior,
        close_behavior: ShutdownBehavior,
    }

    impl FixtureCapability {
        fn new(
            state: Arc<Mutex<FixtureState>>,
            open_behavior: OpenBehavior,
            submit_behavior: SubmitBehavior,
        ) -> Self {
            Self {
                state,
                open_behavior: Some(open_behavior),
                submit_behaviors: VecDeque::from([submit_behavior]),
                cancel_behavior: ShutdownBehavior::Ready,
                close_behavior: ShutdownBehavior::Ready,
            }
        }

        fn with_shutdown_behavior(
            mut self,
            cancel_behavior: ShutdownBehavior,
            close_behavior: ShutdownBehavior,
        ) -> Self {
            self.cancel_behavior = cancel_behavior;
            self.close_behavior = close_behavior;
            self
        }

        fn with_followup_submit_behavior(mut self, behavior: SubmitBehavior) -> Self {
            self.submit_behaviors.push_back(behavior);
            self
        }
    }

    impl AgentConversationCapability for FixtureCapability {
        fn open_session(
            &mut self,
            deck_run_id: AgentConversationDeckRunId,
            session_id: AgentConversationSessionId,
            _timeout: Duration,
        ) -> AgentConversationCapabilityFuture<AgentConversationOpenOutcomeV1> {
            self.state
                .lock()
                .expect("fixture state")
                .opens
                .push((deck_run_id, session_id));
            match self.open_behavior.take().expect("one open operation") {
                OpenBehavior::Ready => {
                    Box::pin(async { Ok(AgentConversationOpenOutcomeV1::Opened) })
                }
                OpenBehavior::Gated(release) => Box::pin(async move {
                    release.await.map_err(|_| {
                        ConversationClientError::new("fixture open gate was dropped")
                    })?;
                    Ok(AgentConversationOpenOutcomeV1::Opened)
                }),
            }
        }

        fn submit(
            &mut self,
            request: AgentConversationRequestV1,
            _timeout: Duration,
        ) -> AgentConversationCapabilityFuture<AgentConversationTerminalV1> {
            self.state
                .lock()
                .expect("fixture state")
                .submissions
                .push(request.clone());
            let terminal = AgentConversationTerminalV1::try_success(&request, "fixture answer")
                .expect("fixture terminal");
            match self
                .submit_behaviors
                .pop_front()
                .expect("configured submit operation")
            {
                SubmitBehavior::Ready => Box::pin(async move { Ok(terminal) }),
                SubmitBehavior::Pending => Box::pin(std::future::pending()),
                SubmitBehavior::Gated(release) => Box::pin(async move {
                    release.await.map_err(|_| {
                        ConversationClientError::new("fixture submit gate was dropped")
                    })?;
                    Ok(terminal)
                }),
            }
        }

        fn cancel(
            &mut self,
            deck_run_id: AgentConversationDeckRunId,
            session_id: AgentConversationSessionId,
            request_id: AgentConversationRequestId,
            timeout: Duration,
        ) -> AgentConversationCapabilityFuture<AgentConversationCancelStateV1> {
            let mut state = self.state.lock().expect("fixture state");
            state
                .cancellations
                .push((deck_run_id, session_id, request_id));
            state.cancellation_timeouts.push(timeout);
            drop(state);
            match self.cancel_behavior {
                ShutdownBehavior::Ready => {
                    Box::pin(async { Ok(AgentConversationCancelStateV1::IntentRecorded) })
                }
                ShutdownBehavior::Pending => Box::pin(std::future::pending()),
            }
        }

        fn close(&mut self, timeout: Duration) -> AgentConversationCapabilityFuture<()> {
            let mut state = self.state.lock().expect("fixture state");
            state.closes += 1;
            state.close_timeouts.push(timeout);
            drop(state);
            match self.close_behavior {
                ShutdownBehavior::Ready => Box::pin(async { Ok(()) }),
                ShutdownBehavior::Pending => Box::pin(std::future::pending()),
            }
        }
    }

    struct FixtureRequestFactory {
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        next_identity: u8,
    }

    impl AgentConversationRequestFactory for FixtureRequestFactory {
        fn create_request(
            &mut self,
            input: &str,
            deadline_budget_nanos: u64,
        ) -> Result<AgentConversationRequestV1, ConversationClientError> {
            let identity = self.next_identity;
            self.next_identity = self
                .next_identity
                .checked_add(1)
                .ok_or_else(|| ConversationClientError::new("fixture identity exhausted"))?;
            AgentConversationRequestV1::try_new(
                self.deck_run_id,
                self.session_id,
                AgentConversationTurnId::try_from_bytes([identity; 16])
                    .expect("fixture Turn identity"),
                AgentConversationRequestId::try_from_bytes([identity.wrapping_add(64); 16])
                    .expect("fixture Request identity"),
                deadline_budget_nanos,
                input,
            )
            .map_err(|_| ConversationClientError::new("fixture request construction failed"))
        }
    }

    fn test_scope() -> (AgentConversationDeckRunId, AgentConversationSessionId) {
        (
            AgentConversationDeckRunId::try_from_bytes([0x31; 16]).expect("fixture DeckRun"),
            AgentConversationSessionId::try_from_bytes([0x32; 16]).expect("fixture Session"),
        )
    }

    fn test_config(
        command_capacity: usize,
        operation_timeout: Duration,
    ) -> BackgroundConversationClientConfig {
        let (deck_run_id, session_id) = test_scope();
        BackgroundConversationClientConfig::try_new(
            deck_run_id,
            session_id,
            command_capacity,
            operation_timeout,
        )
        .expect("fixture background config")
    }

    fn test_factory() -> FixtureRequestFactory {
        let (deck_run_id, session_id) = test_scope();
        FixtureRequestFactory {
            deck_run_id,
            session_id,
            next_identity: 1,
        }
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + TEST_WAIT;
        while !condition() {
            assert!(Instant::now() < deadline, "fixture wait timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn wait_for_connected(client: &mut BackgroundConversationClient) {
        let deadline = Instant::now() + TEST_WAIT;
        loop {
            match client.poll_event() {
                Ok(Some(ConversationClientEvent::ConnectionChanged(
                    ConversationConnectionState::Connected,
                ))) => return,
                Ok(Some(_) | None) => {}
                Err(error) => panic!("connection failed: {error}"),
            }
            assert!(Instant::now() < deadline, "connection wait timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn wait_for_terminal(client: &mut BackgroundConversationClient) -> AgentConversationTerminalV1 {
        let deadline = Instant::now() + TEST_WAIT;
        loop {
            match client.poll_event() {
                Ok(Some(ConversationClientEvent::Terminal(terminal))) => return terminal,
                Ok(Some(_) | None) => {}
                Err(error) => panic!("terminal failed: {error}"),
            }
            assert!(Instant::now() < deadline, "terminal wait timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn ready_capability_connects_submits_terminal_and_joins_close() {
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let capability = FixtureCapability::new(
            Arc::clone(&state),
            OpenBehavior::Ready,
            SubmitBehavior::Ready,
        );
        let mut client = BackgroundConversationClient::spawn(
            test_config(4, Duration::from_secs(1)),
            test_factory(),
            capability,
        )
        .expect("spawn adapter");

        client.begin_connect().expect("begin connect");
        wait_for_connected(&mut client);
        let request = client
            .submit_turn("hello", TEST_DEADLINE_BUDGET_NANOS)
            .expect("submit turn");
        let terminal = wait_for_terminal(&mut client);
        assert!(terminal.correlates(&request));
        assert_eq!(
            terminal.result(),
            &AgentConversationTerminalResultV1::Success("fixture answer".into())
        );
        client.close().expect("joined close");

        let state = state.lock().expect("fixture state");
        assert_eq!(
            state.opens,
            vec![(request.deck_run_id(), request.session_id())]
        );
        assert_eq!(state.submissions, vec![request]);
        assert!(state.cancellations.is_empty());
        assert_eq!(state.closes, 1);
    }

    #[test]
    fn retained_terminal_never_blocks_joined_close() {
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let capability = FixtureCapability::new(
            Arc::clone(&state),
            OpenBehavior::Ready,
            SubmitBehavior::Ready,
        );
        let mut client = BackgroundConversationClient::spawn(
            test_config(4, Duration::from_secs(1)),
            test_factory(),
            capability,
        )
        .expect("spawn adapter");

        client.begin_connect().expect("begin connect");
        wait_for_connected(&mut client);
        client
            .submit_turn("do not drain", TEST_DEADLINE_BUDGET_NANOS)
            .expect("submit turn");
        wait_until(|| {
            client
                .events
                .lock()
                .expect("event slots")
                .terminal
                .is_some()
        });
        client.close().expect("joined close");

        let state = state.lock().expect("fixture state");
        assert_eq!(state.submissions.len(), 1);
        assert!(state.cancellations.is_empty());
        assert_eq!(state.closes, 1);
    }

    #[test]
    fn exact_cancel_queued_after_terminal_is_idempotent_and_preserves_terminal() {
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let capability = FixtureCapability::new(
            Arc::clone(&state),
            OpenBehavior::Ready,
            SubmitBehavior::Ready,
        )
        .with_followup_submit_behavior(SubmitBehavior::Ready);
        let mut client = BackgroundConversationClient::spawn(
            test_config(4, Duration::from_secs(1)),
            test_factory(),
            capability,
        )
        .expect("spawn adapter");

        client.begin_connect().expect("begin connect");
        wait_for_connected(&mut client);
        let completed_request = client
            .submit_turn("complete before cancel", TEST_DEADLINE_BUDGET_NANOS)
            .expect("submit completed turn");
        wait_until(|| {
            client
                .events
                .lock()
                .expect("event slots")
                .terminal
                .is_some()
        });

        client
            .request_cancel(&completed_request)
            .expect("queue exact late cancellation");
        let completed_terminal = wait_for_terminal(&mut client);
        assert!(completed_terminal.correlates(&completed_request));

        // This submit is queued after the late cancellation on the same FIFO
        // sender. Receiving its terminal proves the worker consumed the late
        // cancellation without converting the retained terminal into failure.
        let followup_request = client
            .submit_turn("worker remains usable", TEST_DEADLINE_BUDGET_NANOS)
            .expect("submit follow-up turn");
        let followup_terminal = wait_for_terminal(&mut client);
        assert!(followup_terminal.correlates(&followup_request));
        client.close().expect("joined close");

        let state = state.lock().expect("fixture state");
        assert_eq!(state.submissions, vec![completed_request, followup_request]);
        assert!(state.cancellations.is_empty());
        assert_eq!(state.closes, 1);
    }

    #[test]
    fn unknown_cancel_after_terminal_remains_a_worker_protocol_error() {
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let capability = FixtureCapability::new(
            Arc::clone(&state),
            OpenBehavior::Ready,
            SubmitBehavior::Ready,
        );
        let mut client = BackgroundConversationClient::spawn(
            test_config(4, Duration::from_secs(1)),
            test_factory(),
            capability,
        )
        .expect("spawn adapter");

        client.begin_connect().expect("begin connect");
        wait_for_connected(&mut client);
        let completed_request = client
            .submit_turn("complete before unknown cancel", TEST_DEADLINE_BUDGET_NANOS)
            .expect("submit completed turn");
        let terminal = wait_for_terminal(&mut client);
        assert!(terminal.correlates(&completed_request));

        let mut unknown_factory = test_factory();
        unknown_factory.next_identity = 99;
        let unknown_request = unknown_factory
            .create_request("unknown cancel", TEST_DEADLINE_BUDGET_NANOS)
            .expect("unknown fixture request");
        client
            .send_command(WorkerCommand::Cancel(unknown_request))
            .expect("queue unknown cancellation");

        let deadline = Instant::now() + TEST_WAIT;
        let failure = loop {
            if let Err(error) = client.poll_event() {
                break error;
            }
            assert!(
                Instant::now() < deadline,
                "unknown cancellation failure was not published"
            );
            std::thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(
            failure.message(),
            "worker received cancellation without a pending request"
        );
        let close_error = client.close().expect_err("worker must fail closed");
        assert_eq!(close_error, failure);

        let state = state.lock().expect("fixture state");
        assert!(state.cancellations.is_empty());
        assert_eq!(state.closes, 1);
    }

    #[test]
    fn close_with_pending_submit_cancels_exact_request_and_drops_future() {
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let (release_sender, release_receiver) = oneshot::channel();
        let capability = FixtureCapability::new(
            Arc::clone(&state),
            OpenBehavior::Ready,
            SubmitBehavior::Gated(release_receiver),
        );
        let mut client = BackgroundConversationClient::spawn(
            test_config(4, Duration::from_secs(1)),
            test_factory(),
            capability,
        )
        .expect("spawn adapter");

        client.begin_connect().expect("begin connect");
        wait_for_connected(&mut client);
        let request = client
            .submit_turn("stay pending", TEST_DEADLINE_BUDGET_NANOS)
            .expect("submit turn");
        wait_until(|| state.lock().expect("fixture state").submissions.len() == 1);
        client.close().expect("joined close");
        assert!(release_sender.send(()).is_err());

        let state = state.lock().expect("fixture state");
        assert_eq!(
            state.cancellations,
            vec![(
                request.deck_run_id(),
                request.session_id(),
                request.request_id()
            )]
        );
        assert_eq!(state.closes, 1);
    }

    #[test]
    fn worker_deadline_selection_uses_the_earliest_absolute_deadline() {
        let operation_started = tokio::time::Instant::now();
        let operation_timeout = Duration::from_millis(300);
        let operation_deadline = operation_started + operation_timeout;
        let close_started_later = operation_started + Duration::from_millis(100);
        let later_close_deadline = close_started_later + operation_timeout;
        let previously_requested_close_deadline = operation_started + Duration::from_millis(100);

        assert_eq!(
            select_worker_operation_deadline(operation_deadline, None),
            operation_deadline
        );
        assert_eq!(
            select_worker_operation_deadline(operation_deadline, Some(later_close_deadline)),
            operation_deadline,
            "a later close must not renew an operation's existing budget"
        );
        assert_eq!(
            select_worker_operation_deadline(
                operation_deadline,
                Some(previously_requested_close_deadline),
            ),
            previously_requested_close_deadline,
            "an already-requested close must attenuate the operation budget"
        );
    }

    #[test]
    fn pending_cancel_racing_close_joins_within_the_test_watchdog() {
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let operation_timeout = Duration::from_millis(100);
        let capability = FixtureCapability::new(
            Arc::clone(&state),
            OpenBehavior::Ready,
            SubmitBehavior::Pending,
        )
        .with_shutdown_behavior(ShutdownBehavior::Pending, ShutdownBehavior::Pending);
        let mut client = BackgroundConversationClient::spawn(
            test_config(4, operation_timeout),
            test_factory(),
            capability,
        )
        .expect("spawn adapter");

        client.begin_connect().expect("begin connect");
        wait_for_connected(&mut client);
        let request = client
            .submit_turn("stay pending through shutdown", TEST_DEADLINE_BUDGET_NANOS)
            .expect("submit turn");
        wait_until(|| state.lock().expect("fixture state").submissions.len() == 1);
        client
            .request_cancel(&request)
            .expect("request cancellation");
        wait_until(|| state.lock().expect("fixture state").cancellations.len() == 1);

        let close_started = Instant::now();
        let error = client
            .close()
            .expect_err("pending cancellation must fail closed");
        let close_elapsed = close_started.elapsed();
        assert_eq!(error.message(), "cancel exceeded its operation timeout");
        assert!(
            close_elapsed < TEST_WAIT,
            "joined close exceeded the test hang watchdog: {close_elapsed:?}"
        );

        let state = state.lock().expect("fixture state");
        assert_eq!(
            state.cancellations,
            vec![(
                request.deck_run_id(),
                request.session_id(),
                request.request_id()
            )]
        );
        assert_eq!(state.cancellation_timeouts, vec![operation_timeout]);
        assert_eq!(state.closes, 1);
        assert_eq!(state.close_timeouts.len(), 1);
        assert!(state.close_timeouts[0] <= operation_timeout);
    }

    #[test]
    fn submit_timeout_cancels_exact_request_before_joined_fail_stop() {
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let capability = FixtureCapability::new(
            Arc::clone(&state),
            OpenBehavior::Ready,
            SubmitBehavior::Pending,
        );
        let mut client = BackgroundConversationClient::spawn(
            test_config(4, Duration::from_millis(30)),
            test_factory(),
            capability,
        )
        .expect("spawn adapter");

        client.begin_connect().expect("begin connect");
        wait_for_connected(&mut client);
        let request = client
            .submit_turn("time out", TEST_DEADLINE_BUDGET_NANOS)
            .expect("submit turn");
        let deadline = Instant::now() + TEST_WAIT;
        let failure = loop {
            if let Err(error) = client.poll_event() {
                break error;
            }
            assert!(
                Instant::now() < deadline,
                "timeout failure was not published"
            );
            std::thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(failure.message(), "submit exceeded its operation timeout");
        assert_eq!(client.connection, ConversationConnectionState::Disconnected);
        let close_error = client.close().expect_err("worker must fail closed");
        assert_eq!(
            close_error.message(),
            "submit exceeded its operation timeout"
        );

        let state = state.lock().expect("fixture state");
        assert_eq!(
            state.cancellations,
            vec![(
                request.deck_run_id(),
                request.session_id(),
                request.request_id()
            )]
        );
        assert_eq!(state.closes, 1);
    }

    #[test]
    fn full_command_queue_rejects_submit_without_claiming_it() {
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let (release_sender, release_receiver) = oneshot::channel();
        let capability = FixtureCapability::new(
            Arc::clone(&state),
            OpenBehavior::Gated(release_receiver),
            SubmitBehavior::Ready,
        );
        let mut client = BackgroundConversationClient::spawn(
            test_config(1, Duration::from_secs(1)),
            test_factory(),
            capability,
        )
        .expect("spawn adapter");

        client.begin_connect().expect("begin connect");
        wait_until(|| state.lock().expect("fixture state").opens.len() == 1);
        publish_connection(&client.events, ConversationConnectionState::Connected);
        wait_for_connected(&mut client);
        client
            .send_command(WorkerCommand::Connect)
            .expect("fill command queue");
        let error = client
            .submit_turn("queue full", TEST_DEADLINE_BUDGET_NANOS)
            .expect_err("full queue must reject synchronously");
        assert_eq!(error.message(), "conversation command queue is full");
        assert!(client.pending.is_none());
        assert!(!client.cancellation_queued);
        assert!(state.lock().expect("fixture state").submissions.is_empty());

        release_sender.send(()).expect("release open");
        let _ = client.close();
    }

    #[test]
    fn config_rejects_unbounded_command_and_operation_limits() {
        let (deck_run_id, session_id) = test_scope();
        assert_eq!(
            BackgroundConversationClientConfig::try_new(
                deck_run_id,
                session_id,
                0,
                Duration::from_secs(1),
            ),
            Err(BackgroundConversationClientConfigError::CommandCapacityOutOfRange)
        );
        assert_eq!(
            BackgroundConversationClientConfig::try_new(
                deck_run_id,
                session_id,
                MAX_BACKGROUND_CONVERSATION_COMMANDS + 1,
                Duration::from_secs(1),
            ),
            Err(BackgroundConversationClientConfigError::CommandCapacityOutOfRange)
        );
        assert_eq!(
            BackgroundConversationClientConfig::try_new(deck_run_id, session_id, 1, Duration::ZERO,),
            Err(BackgroundConversationClientConfigError::OperationTimeoutOutOfRange)
        );
        assert_eq!(
            BackgroundConversationClientConfig::try_new(
                deck_run_id,
                session_id,
                1,
                MAX_BACKGROUND_OPERATION_TIMEOUT + Duration::from_nanos(1),
            ),
            Err(BackgroundConversationClientConfigError::OperationTimeoutOutOfRange)
        );
    }

    #[test]
    fn close_is_joined_even_when_called_while_open_is_pending() {
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let (release_sender, release_receiver) = oneshot::channel();
        let capability = FixtureCapability::new(
            Arc::clone(&state),
            OpenBehavior::Gated(release_receiver),
            SubmitBehavior::Ready,
        );
        let mut client = BackgroundConversationClient::spawn(
            test_config(1, Duration::from_millis(30)),
            test_factory(),
            capability,
        )
        .expect("spawn adapter");

        client.begin_connect().expect("begin connect");
        wait_until(|| state.lock().expect("fixture state").opens.len() == 1);
        let error = client.close().expect_err("open timeout must fail closed");
        assert_eq!(
            error.message(),
            "open Session exceeded its operation timeout"
        );
        assert!(release_sender.send(()).is_err());
        assert_eq!(state.lock().expect("fixture state").closes, 1);
    }
}
