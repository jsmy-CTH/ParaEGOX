use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalFailureV1,
    AgentConversationTerminalResultV1, AgentConversationTurnId,
};
use paraegox_agent_service::{
    AgentConversationModelCancellation, AgentConversationModelFuture,
    AgentConversationModelOutcomeV1, AgentConversationModelProvider,
    AgentConversationModelServiceProviderV1, AgentService, AgentServiceAcceptOutcomeV1,
    AgentServiceConfigV1, AgentServiceError, AgentServiceEventKindV1, AgentServiceSubmitOutcomeV1,
    AgentSessionOpenOutcomeV1, DeterministicEchoModelProvider,
};
use paraegox_kernel::digest::Digest32;
use paraegox_model::{
    ModelBackendFuture, ModelBackendIdentityV1, ModelBackendV1, ModelCancellationViewV1,
    ModelInvocationOutcomeV1, ModelInvocationRequestV1, ModelServiceConfigV1, ModelServiceV1,
};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

fn deck(byte: u8) -> AgentConversationDeckRunId {
    AgentConversationDeckRunId::try_from_bytes([byte; 16]).expect("deck run id")
}

fn session(byte: u8) -> AgentConversationSessionId {
    AgentConversationSessionId::try_from_bytes([byte; 16]).expect("session id")
}

fn turn(byte: u8) -> AgentConversationTurnId {
    AgentConversationTurnId::try_from_bytes([byte; 16]).expect("turn id")
}

fn request_id(byte: u8) -> AgentConversationRequestId {
    AgentConversationRequestId::try_from_bytes([byte; 16]).expect("request id")
}

fn request(
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    turn_byte: u8,
    request_byte: u8,
    input: &str,
) -> AgentConversationRequestV1 {
    AgentConversationRequestV1::try_new(
        deck_run_id,
        session_id,
        turn(turn_byte),
        request_id(request_byte),
        5_000_000_000,
        input,
    )
    .expect("request")
}

fn config(max_sessions: usize, max_turns: usize, max_requests: usize) -> AgentServiceConfigV1 {
    AgentServiceConfigV1::try_new(max_sessions, max_turns, max_requests, 16).expect("config")
}

fn submit_ready<P: AgentConversationModelProvider>(
    service: &mut AgentService,
    provider: &mut P,
    request: AgentConversationRequestV1,
) -> Result<AgentServiceSubmitOutcomeV1, AgentServiceError> {
    let deck_run_id = request.deck_run_id();
    let session_id = request.session_id();
    let request_id = request.request_id();
    match service.accept_request(request)? {
        AgentServiceAcceptOutcomeV1::Accepted => {
            let invocation = service.begin_execution(deck_run_id, session_id, request_id)?;
            let mut future =
                provider.complete(invocation.request().clone(), invocation.cancellation());
            let mut context = Context::from_waker(Waker::noop());
            let Poll::Ready(outcome) = future.as_mut().poll(&mut context) else {
                panic!("semantic fixture provider must complete immediately");
            };
            service.complete_execution(invocation, outcome)
        }
        AgentServiceAcceptOutcomeV1::PendingReplay => {
            Err(AgentServiceError::DurableRecoveryRequired)
        }
        AgentServiceAcceptOutcomeV1::TerminalReplay(terminal) => {
            Ok(AgentServiceSubmitOutcomeV1::TerminalReplay(terminal))
        }
        AgentServiceAcceptOutcomeV1::Rejected(terminal) => {
            Ok(AgentServiceSubmitOutcomeV1::Rejected(terminal))
        }
    }
}

#[test]
fn reconnect_preserves_session_and_exact_request_replays_one_terminal() {
    let deck_run_id = deck(1);
    let session_id = session(2);
    let mut service = AgentService::new(config(4, 4, 4));
    let mut provider = DeterministicEchoModelProvider::new();
    assert_eq!(
        service.open_session(deck_run_id, session_id),
        Ok(AgentSessionOpenOutcomeV1::Opened)
    );

    let first_request = request(deck_run_id, session_id, 3, 4, "first");
    let first =
        submit_ready(&mut service, &mut provider, first_request.clone()).expect("first terminal");
    assert!(matches!(
        first,
        AgentServiceSubmitOutcomeV1::TerminalCommitted(_)
    ));
    let replay =
        submit_ready(&mut service, &mut provider, first_request.clone()).expect("terminal replay");
    assert_eq!(first.terminal(), replay.terminal());
    assert!(matches!(
        replay,
        AgentServiceSubmitOutcomeV1::TerminalReplay(_)
    ));
    assert_eq!(provider.calls(), 1);

    // Opening an existing Session models a new client/TUI attachment. It does
    // not reset or end the service-owned Session ledger.
    assert_eq!(
        service.open_session(deck_run_id, session_id),
        Ok(AgentSessionOpenOutcomeV1::Existing)
    );
    let second_request = request(deck_run_id, session_id, 5, 6, "second");
    submit_ready(&mut service, &mut provider, second_request).expect("second terminal");
    assert_eq!(provider.calls(), 2);

    let snapshot = service
        .export_session_snapshot(deck_run_id, session_id)
        .expect("snapshot");
    assert_eq!(snapshot.turns().len(), 2);
    assert_eq!(snapshot.requests().len(), 2);
    assert_eq!(snapshot.event_high_watermark(), 5);

    let first_batch = service
        .export_session_events(deck_run_id, session_id, 0, 2)
        .expect("first event batch");
    assert_eq!(
        first_batch
            .events()
            .iter()
            .map(|event| event.sequence())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(matches!(
        first_batch.events()[0].kind(),
        AgentServiceEventKindV1::SessionOpened
    ));
    assert!(first_batch.has_more());
    let second_batch = service
        .export_session_events(deck_run_id, session_id, first_batch.next_cursor(), 16)
        .expect("second event batch");
    assert_eq!(second_batch.events().len(), 3);
    assert_eq!(second_batch.next_cursor(), 5);
    assert!(!second_batch.has_more());
}

#[test]
fn request_and_turn_conflicts_are_rejected_without_mutating_the_ledger() {
    let deck_run_id = deck(1);
    let session_id = session(2);
    let mut service = AgentService::new(config(2, 4, 4));
    let mut provider = DeterministicEchoModelProvider::new();
    service
        .open_session(deck_run_id, session_id)
        .expect("open session");
    let admitted = request(deck_run_id, session_id, 3, 4, "original");
    submit_ready(&mut service, &mut provider, admitted.clone()).expect("admitted request");

    let same_request_id = request(deck_run_id, session_id, 3, 4, "different");
    let rejected =
        submit_ready(&mut service, &mut provider, same_request_id).expect("typed conflict");
    assert_eq!(
        rejected.terminal().result(),
        &AgentConversationTerminalResultV1::Failure(
            AgentConversationTerminalFailureV1::RequestConflict
        )
    );
    assert!(matches!(rejected, AgentServiceSubmitOutcomeV1::Rejected(_)));

    let same_turn = request(deck_run_id, session_id, 3, 5, "another request id");
    let turn_conflict =
        submit_ready(&mut service, &mut provider, same_turn).expect("typed turn conflict");
    assert_eq!(
        turn_conflict.terminal().result(),
        &AgentConversationTerminalResultV1::Failure(
            AgentConversationTerminalFailureV1::RequestConflict
        )
    );
    assert_eq!(provider.calls(), 1);
    let snapshot = service
        .export_session_snapshot(deck_run_id, session_id)
        .expect("snapshot");
    assert_eq!(snapshot.turns().len(), 1);
    assert_eq!(snapshot.requests().len(), 1);
    assert_eq!(snapshot.event_high_watermark(), 3);
    assert_eq!(
        service
            .terminal(deck_run_id, session_id, admitted.request_id())
            .expect("terminal query"),
        Some(admitted_terminal(
            &service,
            deck_run_id,
            session_id,
            &admitted
        ))
    );
}

fn admitted_terminal<'a>(
    service: &'a AgentService,
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    request: &AgentConversationRequestV1,
) -> &'a paraegox_agent_contracts::AgentConversationTerminalV1 {
    service
        .terminal(deck_run_id, session_id, request.request_id())
        .expect("terminal query")
        .expect("committed terminal")
}

#[test]
fn deck_run_and_session_scope_same_request_identity_independently() {
    let first_deck = deck(1);
    let second_deck = deck(2);
    let shared_session = session(3);
    let second_session = session(9);
    let mut service = AgentService::new(config(4, 2, 2));
    let mut provider = DeterministicEchoModelProvider::new();
    assert_eq!(
        service.open_session(first_deck, shared_session),
        Ok(AgentSessionOpenOutcomeV1::Opened)
    );
    assert_eq!(
        service.open_session(second_deck, shared_session),
        Ok(AgentSessionOpenOutcomeV1::Opened)
    );
    assert_eq!(
        service.open_session(first_deck, second_session),
        Ok(AgentSessionOpenOutcomeV1::Opened)
    );
    let first = request(first_deck, shared_session, 4, 5, "same bytes");
    let second = request(second_deck, shared_session, 4, 5, "same bytes");
    let third = request(first_deck, second_session, 4, 5, "same bytes");
    submit_ready(&mut service, &mut provider, first).expect("first DeckRun terminal");
    submit_ready(&mut service, &mut provider, second).expect("second DeckRun terminal");
    submit_ready(&mut service, &mut provider, third).expect("second Session terminal");
    assert_eq!(provider.calls(), 3);
    assert_eq!(
        service
            .export_session_snapshot(first_deck, shared_session)
            .expect("first snapshot")
            .requests()
            .len(),
        1
    );
    assert_eq!(
        service
            .export_session_snapshot(second_deck, shared_session)
            .expect("second snapshot")
            .requests()
            .len(),
        1
    );
    assert_eq!(
        service
            .export_session_snapshot(first_deck, second_session)
            .expect("second Session snapshot")
            .requests()
            .len(),
        1
    );
}

#[test]
fn bounded_ledgers_reject_capacity_without_eviction_or_provider_call() {
    let deck_run_id = deck(1);
    let session_id = session(2);
    let mut service = AgentService::new(config(1, 1, 1));
    let mut provider = DeterministicEchoModelProvider::new();
    service
        .open_session(deck_run_id, session_id)
        .expect("open session");
    let first = request(deck_run_id, session_id, 3, 4, "first");
    let first_terminal = submit_ready(&mut service, &mut provider, first.clone())
        .expect("first terminal")
        .terminal()
        .clone();
    let second = request(deck_run_id, session_id, 5, 6, "second");
    let capacity =
        submit_ready(&mut service, &mut provider, second).expect("typed capacity failure");
    assert_eq!(
        capacity.terminal().result(),
        &AgentConversationTerminalResultV1::Failure(
            AgentConversationTerminalFailureV1::CapacityExhausted
        )
    );
    assert_eq!(provider.calls(), 1);
    assert_eq!(
        service
            .terminal(deck_run_id, session_id, first.request_id())
            .expect("terminal query"),
        Some(&first_terminal)
    );
    assert_eq!(
        service.open_session(deck_run_id, session(9)),
        Err(AgentServiceError::SessionCapacityExhausted)
    );
}

#[derive(Clone)]
enum TestModelBackendBehavior {
    Outcome(ModelInvocationOutcomeV1),
    Pending,
}

struct TestModelBackend {
    captured_request: Arc<Mutex<Option<ModelInvocationRequestV1>>>,
    behavior: TestModelBackendBehavior,
}

impl ModelBackendV1 for TestModelBackend {
    fn identity(&self) -> ModelBackendIdentityV1 {
        ModelBackendIdentityV1::try_new([21; 16], Digest32::from_bytes([22; 32]))
            .expect("test backend identity")
    }

    fn invoke(
        &self,
        request: ModelInvocationRequestV1,
        cancellation: ModelCancellationViewV1,
    ) -> ModelBackendFuture {
        *self.captured_request.lock().expect("captured request lock") = Some(request);
        match &self.behavior {
            TestModelBackendBehavior::Outcome(outcome) => {
                Box::pin(std::future::ready(outcome.clone()))
            }
            TestModelBackendBehavior::Pending => {
                let _ = cancellation;
                Box::pin(std::future::pending())
            }
        }
    }
}

fn model_provider(
    capacity: usize,
    behavior: TestModelBackendBehavior,
) -> (
    AgentConversationModelServiceProviderV1<TestModelBackend>,
    Arc<Mutex<Option<ModelInvocationRequestV1>>>,
) {
    let captured_request = Arc::new(Mutex::new(None));
    let backend = TestModelBackend {
        captured_request: Arc::clone(&captured_request),
        behavior,
    };
    let model_service = ModelServiceV1::new(
        ModelServiceConfigV1::try_new(capacity).expect("test model capacity"),
        backend,
    );
    (
        AgentConversationModelServiceProviderV1::new(model_service),
        captured_request,
    )
}

#[test]
fn model_service_adapter_preserves_exact_agent_request_identity_and_fields() {
    let deck_run_id = deck(1);
    let session_id = session(2);
    let request = request(deck_run_id, session_id, 3, 4, "model input");
    let mut agent_service = AgentService::new(config(2, 2, 2));
    agent_service
        .open_session(deck_run_id, session_id)
        .expect("open Session");
    assert_eq!(
        agent_service
            .accept_request(request.clone())
            .expect("accept request"),
        AgentServiceAcceptOutcomeV1::Accepted
    );
    let invocation = agent_service
        .begin_execution(deck_run_id, session_id, request.request_id())
        .expect("commit model handoff");
    let (mut provider, captured_request) = model_provider(
        1,
        TestModelBackendBehavior::Outcome(ModelInvocationOutcomeV1::Success("model output".into())),
    );
    let mut operation = provider.complete(invocation.request().clone(), invocation.cancellation());

    let captured = captured_request
        .lock()
        .expect("captured request lock")
        .clone()
        .expect("backend must receive request");
    assert_eq!(
        captured.invocation_id().as_bytes(),
        request.request_id().as_bytes()
    );
    assert_eq!(captured.source_request_digest(), request.request_digest());
    assert_eq!(
        captured.deadline_budget().value(),
        request.deadline_budget_nanos()
    );
    assert_eq!(captured.prompt(), request.input());

    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(outcome) = operation.as_mut().poll(&mut context) else {
        panic!("test backend must complete immediately");
    };
    assert_eq!(
        outcome,
        AgentConversationModelOutcomeV1::Success("model output".into())
    );
    let terminal = agent_service
        .complete_execution(invocation, outcome)
        .expect("commit model terminal");
    assert_eq!(
        terminal.terminal().result(),
        &AgentConversationTerminalResultV1::Success("model output".into())
    );
    let counters = provider.model_service().snapshot().counters();
    assert_eq!(counters.admitted(), 1);
    assert_eq!(counters.completed(), 1);
    assert_eq!(counters.in_flight(), 0);
}

#[test]
fn model_service_capacity_maps_to_agent_capacity_terminal_without_backend_queueing() {
    let deck_run_id = deck(1);
    let session_id = session(2);
    let first = request(deck_run_id, session_id, 3, 4, "first pending model");
    let second = request(deck_run_id, session_id, 5, 6, "second refused model");
    let mut agent_service = AgentService::new(config(2, 4, 4));
    agent_service
        .open_session(deck_run_id, session_id)
        .expect("open Session");
    let (mut provider, captured_request) = model_provider(1, TestModelBackendBehavior::Pending);

    agent_service
        .accept_request(first.clone())
        .expect("accept first request");
    let first_invocation = agent_service
        .begin_execution(deck_run_id, session_id, first.request_id())
        .expect("commit first model handoff");
    let first_operation = provider.complete(
        first_invocation.request().clone(),
        first_invocation.cancellation(),
    );

    agent_service
        .accept_request(second.clone())
        .expect("accept second request");
    let second_invocation = agent_service
        .begin_execution(deck_run_id, session_id, second.request_id())
        .expect("commit second model handoff");
    let mut second_operation = provider.complete(
        second_invocation.request().clone(),
        second_invocation.cancellation(),
    );
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(second_outcome) = second_operation.as_mut().poll(&mut context) else {
        panic!("capacity refusal must be immediate");
    };
    assert_eq!(
        second_outcome,
        AgentConversationModelOutcomeV1::CapacityExhausted
    );
    let terminal = agent_service
        .complete_execution(second_invocation, second_outcome)
        .expect("commit capacity terminal");
    assert_eq!(
        terminal.terminal().result(),
        &AgentConversationTerminalResultV1::Failure(
            AgentConversationTerminalFailureV1::CapacityExhausted
        )
    );
    assert_eq!(
        captured_request
            .lock()
            .expect("captured request lock")
            .as_ref()
            .expect("first request reached backend")
            .invocation_id()
            .as_bytes(),
        first.request_id().as_bytes()
    );
    let before_drop = provider.model_service().snapshot().counters();
    assert_eq!(before_drop.admitted(), 1);
    assert_eq!(before_drop.in_flight(), 1);
    drop(first_operation);
    drop(first_invocation);
    let after_drop = provider.model_service().snapshot().counters();
    assert_eq!(after_drop.abandoned(), 1);
    assert_eq!(after_drop.in_flight(), 0);
}

#[derive(Debug)]
struct FailingProvider {
    outcome: AgentConversationModelOutcomeV1,
    calls: usize,
}

impl AgentConversationModelProvider for FailingProvider {
    fn complete(
        &mut self,
        _request: AgentConversationRequestV1,
        _cancellation: AgentConversationModelCancellation,
    ) -> AgentConversationModelFuture {
        self.calls += 1;
        let outcome = self.outcome.clone();
        Box::pin(async move { outcome })
    }
}

#[test]
fn provider_failure_is_one_queryable_terminal_and_never_reexecuted() {
    for (outcome, expected) in [
        (
            AgentConversationModelOutcomeV1::Failed,
            AgentConversationTerminalFailureV1::ModelFailed,
        ),
        (
            AgentConversationModelOutcomeV1::DeadlineExceeded,
            AgentConversationTerminalFailureV1::DeadlineExceeded,
        ),
        (
            AgentConversationModelOutcomeV1::CapacityExhausted,
            AgentConversationTerminalFailureV1::CapacityExhausted,
        ),
    ] {
        let deck_run_id = deck(1);
        let session_id = session(2);
        let mut service = AgentService::new(config(2, 2, 2));
        let mut provider = FailingProvider { outcome, calls: 0 };
        service
            .open_session(deck_run_id, session_id)
            .expect("open session");
        let request = request(deck_run_id, session_id, 3, 4, "hello");
        let committed =
            submit_ready(&mut service, &mut provider, request.clone()).expect("failed terminal");
        let replay = submit_ready(&mut service, &mut provider, request).expect("replayed failure");
        assert_eq!(committed.terminal(), replay.terminal());
        assert_eq!(
            committed.terminal().result(),
            &AgentConversationTerminalResultV1::Failure(expected)
        );
        assert_eq!(provider.calls, 1);
    }
}

#[test]
fn sealing_deck_run_rejects_submit_and_open_but_keeps_queries() {
    let deck_run_id = deck(1);
    let session_id = session(2);
    let mut service = AgentService::new(config(4, 4, 4));
    let mut provider = DeterministicEchoModelProvider::new();
    service
        .open_session(deck_run_id, session_id)
        .expect("open session");
    let request = request(deck_run_id, session_id, 3, 4, "retained");
    let terminal = submit_ready(&mut service, &mut provider, request.clone())
        .expect("terminal")
        .terminal()
        .clone();

    let report = service.seal_deck_run(deck_run_id).expect("seal DeckRun");
    assert!(!report.already_sealed());
    assert_eq!(report.newly_sealed_sessions(), 1);
    assert_eq!(report.retained_sessions(), 1);
    assert_eq!(report.retained_requests(), 1);
    assert_eq!(
        service.accept_request(request.clone()),
        Err(AgentServiceError::SessionSealed)
    );
    assert_eq!(
        service.open_session(deck_run_id, session(9)),
        Err(AgentServiceError::DeckRunSealed)
    );
    assert_eq!(
        service
            .terminal(deck_run_id, session_id, request.request_id())
            .expect("terminal after seal"),
        Some(&terminal)
    );
    let snapshot = service
        .export_session_snapshot(deck_run_id, session_id)
        .expect("snapshot after seal");
    assert!(snapshot.is_sealed());
    assert_eq!(snapshot.event_high_watermark(), 4);
    let repeated = service
        .seal_deck_run(deck_run_id)
        .expect("repeat DeckRun seal");
    assert!(repeated.already_sealed());
    assert_eq!(repeated.newly_sealed_sessions(), 0);
    assert_eq!(
        service
            .export_session_snapshot(deck_run_id, session_id)
            .expect("stable snapshot")
            .event_high_watermark(),
        4
    );

    let successor_deck = deck(8);
    assert_eq!(
        service.open_session(successor_deck, session_id),
        Ok(AgentSessionOpenOutcomeV1::Opened)
    );
    assert!(
        service
            .export_session_snapshot(successor_deck, session_id)
            .expect("fresh DeckRun Session")
            .requests()
            .is_empty()
    );
}
