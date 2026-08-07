use paraegox_agent_contracts::control::{
    AgentConversationCancelStateV1, AgentConversationControlBodyV1, AgentConversationControlV1,
    AgentConversationGetStateV1, AgentConversationOpenOutcomeV1, AgentConversationWatchEventKindV1,
};
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalFailureV1,
    AgentConversationTerminalResultV1, AgentConversationTurnId,
};
use paraegox_agent_service::{
    AgentConversationModelProvider, AgentService, AgentServiceAcceptOutcomeV1,
    AgentServiceConfigV1, AgentServiceError, AgentServiceSubmitOutcomeV1,
    DeterministicEchoModelProvider,
};
use std::task::{Context, Poll, Waker};

fn deck() -> AgentConversationDeckRunId {
    AgentConversationDeckRunId::try_from_bytes([1; 16]).expect("DeckRun id")
}

fn session() -> AgentConversationSessionId {
    AgentConversationSessionId::try_from_bytes([2; 16]).expect("Session id")
}

fn request_id() -> AgentConversationRequestId {
    AgentConversationRequestId::try_from_bytes([4; 16]).expect("Request id")
}

fn request() -> AgentConversationRequestV1 {
    AgentConversationRequestV1::try_new(
        deck(),
        session(),
        AgentConversationTurnId::try_from_bytes([3; 16]).expect("Turn id"),
        request_id(),
        5_000_000_000,
        "first real chat",
    )
    .expect("request")
}

fn service() -> AgentService {
    AgentService::new(AgentServiceConfigV1::try_new(4, 8, 8, 2).expect("config"))
}

#[test]
fn explicit_controls_open_query_watch_and_cancel_without_implicit_session_creation() {
    let mut service = service();

    let get_missing = service
        .handle_control(&AgentConversationControlV1::get_request(
            deck(),
            session(),
            request_id(),
        ))
        .expect("get missing");
    assert!(matches!(
        get_missing.body(),
        AgentConversationControlBodyV1::GetResult(AgentConversationGetStateV1::NotFound)
    ));
    let watch_missing = service
        .handle_control(
            &AgentConversationControlV1::watch_request(deck(), session(), 0, 2)
                .expect("watch request"),
        )
        .expect("watch missing");
    assert!(matches!(
        watch_missing.body(),
        AgentConversationControlBodyV1::WatchResultNotFound
    ));
    let cancel_missing = service
        .handle_control(&AgentConversationControlV1::cancel_request(
            deck(),
            session(),
            request_id(),
        ))
        .expect("cancel missing");
    assert!(matches!(
        cancel_missing.body(),
        AgentConversationControlBodyV1::CancelResult(AgentConversationCancelStateV1::NotFound)
    ));
    assert_eq!(service.retained_sessions(), 0);

    let opened = service
        .handle_control(&AgentConversationControlV1::open_request(deck(), session()))
        .expect("open Session");
    assert!(matches!(
        opened.body(),
        AgentConversationControlBodyV1::OpenResult(AgentConversationOpenOutcomeV1::Opened)
    ));

    assert_eq!(
        service.accept_request(request()).expect("accept request"),
        AgentServiceAcceptOutcomeV1::Accepted
    );
    let pending = service
        .handle_control(&AgentConversationControlV1::get_request(
            deck(),
            session(),
            request_id(),
        ))
        .expect("get pending");
    assert!(matches!(
        pending.body(),
        AgentConversationControlBodyV1::GetResult(AgentConversationGetStateV1::Pending {
            cancel_requested: false
        })
    ));

    let first_watch = service
        .handle_control(
            &AgentConversationControlV1::watch_request(deck(), session(), 0, 2)
                .expect("watch request"),
        )
        .expect("first watch");
    let AgentConversationControlBodyV1::WatchResult(first_batch) = first_watch.body() else {
        panic!("expected watch batch");
    };
    first_batch
        .validate_for_request(0, 2)
        .expect("request-relative watch validation");
    assert_eq!(first_batch.next_cursor(), 2);
    assert_eq!(first_batch.events().len(), 2);
    assert!(matches!(
        first_batch.events()[0].kind(),
        AgentConversationWatchEventKindV1::SessionOpened
    ));
    assert!(matches!(
        first_batch.events()[1].kind(),
        AgentConversationWatchEventKindV1::RequestAccepted(_)
    ));

    let cancelled = service
        .handle_control(&AgentConversationControlV1::cancel_request(
            deck(),
            session(),
            request_id(),
        ))
        .expect("cancel before provider");
    let AgentConversationControlBodyV1::CancelResult(AgentConversationCancelStateV1::Terminal(
        cancelled_terminal,
    )) = cancelled.body()
    else {
        panic!("expected cancelled terminal");
    };
    assert_eq!(
        cancelled_terminal.result(),
        &AgentConversationTerminalResultV1::Failure(
            AgentConversationTerminalFailureV1::CancelledBeforeModel
        )
    );

    let exact_get = service
        .handle_control(&AgentConversationControlV1::get_request(
            deck(),
            session(),
            request_id(),
        ))
        .expect("get cancelled terminal");
    let AgentConversationControlBodyV1::GetResult(AgentConversationGetStateV1::Terminal(
        get_terminal,
    )) = exact_get.body()
    else {
        panic!("expected exact terminal");
    };
    assert_eq!(
        get_terminal.canonical_wire(),
        cancelled_terminal.canonical_wire()
    );

    assert!(matches!(
        service.begin_execution(deck(), session(), request_id()),
        Err(AgentServiceError::DurableRecoveryRequired)
    ));

    let second_watch = service
        .handle_control(
            &AgentConversationControlV1::watch_request(deck(), session(), 2, 2)
                .expect("watch request"),
        )
        .expect("second watch");
    let AgentConversationControlBodyV1::WatchResult(second_batch) = second_watch.body() else {
        panic!("expected second watch batch");
    };
    second_batch
        .validate_for_request(2, 2)
        .expect("request-relative watch validation");
    assert_eq!(second_batch.next_cursor(), 4);
    assert!(matches!(
        second_batch.events()[0].kind(),
        AgentConversationWatchEventKindV1::CancelIntentRecorded(id) if *id == request_id()
    ));
    assert!(matches!(
        second_batch.events()[1].kind(),
        AgentConversationWatchEventKindV1::TerminalCommitted(_)
    ));
}

#[test]
fn explicit_accept_begin_complete_composes_and_control_results_are_not_requests() {
    let mut service = service();
    let mut provider = DeterministicEchoModelProvider::new();
    service
        .handle_control(&AgentConversationControlV1::open_request(deck(), session()))
        .expect("open");
    assert_eq!(
        service.accept_request(request()).expect("accept"),
        AgentServiceAcceptOutcomeV1::Accepted
    );
    let invocation = service
        .begin_execution(deck(), session(), request_id())
        .expect("begin");
    let mut future = provider.complete(invocation.request().clone(), invocation.cancellation());
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(outcome) = future.as_mut().poll(&mut context) else {
        panic!("echo fixture must complete immediately");
    };
    let terminal = service
        .complete_execution(invocation, outcome)
        .expect("complete");
    assert!(matches!(
        terminal,
        AgentServiceSubmitOutcomeV1::TerminalCommitted(_)
    ));
    assert_eq!(provider.calls(), 1);

    let result = AgentConversationControlV1::open_result(
        deck(),
        session(),
        AgentConversationOpenOutcomeV1::Existing,
    );
    assert_eq!(
        service.handle_control(&result),
        Err(AgentServiceError::InvalidControlRequest)
    );
}
