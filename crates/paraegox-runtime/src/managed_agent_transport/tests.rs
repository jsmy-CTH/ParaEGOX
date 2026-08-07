use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{net::TcpListener, time::Duration};

use paraegox_agent_contracts::control::{
    AgentConversationCancelStateV1, AgentConversationControlError, AgentConversationControlV1,
    AgentConversationGetStateV1, AgentConversationOpenOutcomeV1, AgentConversationWatchBatchV1,
    AgentConversationWatchEventKindV1, AgentConversationWatchEventV1,
};
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalFailureV1,
    AgentConversationTerminalResultV1, AgentConversationTurnId,
};
use paraegox_agent_service::{
    AgentConversationModelCancellation, AgentConversationModelFuture,
    AgentConversationModelOutcomeV1, AgentConversationModelProvider, AgentService,
    AgentServiceAcceptOutcomeV1, AgentServiceConfigV1, DeterministicEchoModelProvider,
};
use paraegox_fabric::{
    FabricService, FabricServiceConfig, HandlerResponse, IngressLimits,
    RequestId as FabricRequestId, RequestResponseBindingSpec, ResponseStatus, SessionEndpoint,
};
use paraegox_runtime_contracts::assignment::BindingId;
use tokio::sync::oneshot;

use super::port_descriptor::AgentConversationPortDescriptorV1;
use super::{
    AGENT_CONVERSATION_PORT_PHYSICAL_BINDINGS, AgentConversationClient,
    AgentConversationClientError, AgentConversationPort,
    AgentConversationPortMutationDispositionV1, AgentConversationPortSpec,
    AgentConversationServeOutcome, InstalledAgentConversationPort, control_fabric_request_id,
    install_agent_conversation_port as install_two_lane_port, retire_agent_conversation_port,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

fn available_tcp_endpoint() -> SessionEndpoint {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    SessionEndpoint::try_new(format!("tcp/{address}")).unwrap()
}

fn ingress_limits(handler_timeout: Duration) -> IngressLimits {
    IngressLimits::try_new(8, 512 * 1024, 64 * 1024, 64 * 1024, handler_timeout).unwrap()
}

fn id<T>(
    marker: u8,
    constructor: fn(
        [u8; 16],
    ) -> Result<T, paraegox_agent_contracts::AgentConversationProtocolError>,
) -> T {
    constructor([marker; 16]).unwrap()
}

fn request(
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    turn_marker: u8,
    request_marker: u8,
    input: &str,
) -> AgentConversationRequestV1 {
    AgentConversationRequestV1::try_new(
        deck_run_id,
        session_id,
        id(turn_marker, AgentConversationTurnId::try_from_bytes),
        id(request_marker, AgentConversationRequestId::try_from_bytes),
        2_000_000_000,
        input,
    )
    .unwrap()
}

async fn fabric_pair() -> (FabricService, FabricService) {
    let endpoint = available_tcp_endpoint();
    let server_config = FabricServiceConfig::try_peer(vec![endpoint.clone()], Vec::new()).unwrap();
    let server = FabricService::start(server_config).await.unwrap();
    let client_config = FabricServiceConfig::try_peer(Vec::new(), vec![endpoint]).unwrap();
    let client = FabricService::start(client_config).await.unwrap();
    (server, client)
}

async fn install_agent_conversation_port(
    fabric: &mut FabricService,
    binding_id: BindingId,
    expected_active: Option<&AgentConversationPort>,
    key_expression: impl Into<String>,
    ingress_limits: IngressLimits,
) -> Result<InstalledAgentConversationPort, super::AgentConversationPortError> {
    let mut control_id = *binding_id.as_bytes();
    control_id[0] ^= 0x80;
    let key_expression = key_expression.into();
    let spec = AgentConversationPortSpec::try_new(
        binding_id,
        BindingId::from_bytes(control_id),
        format!("{key_expression}/submit"),
        format!("{key_expression}/control"),
        ingress_limits,
    )?;
    install_two_lane_port(fabric, &spec, expected_active).await
}

struct GatedProvider {
    calls: Arc<AtomicUsize>,
    started: Option<oneshot::Sender<AgentConversationModelCancellation>>,
    release: Option<oneshot::Receiver<()>>,
}

impl AgentConversationModelProvider for GatedProvider {
    fn complete(
        &mut self,
        request: AgentConversationRequestV1,
        cancellation: AgentConversationModelCancellation,
    ) -> AgentConversationModelFuture {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.started
            .take()
            .expect("gated provider is invoked once")
            .send(cancellation.clone())
            .ok();
        let release = self.release.take().expect("one release gate");
        Box::pin(async move {
            let _ = release.await;
            if cancellation.is_cancellation_requested() {
                AgentConversationModelOutcomeV1::OutcomeUncertain
            } else {
                AgentConversationModelOutcomeV1::Success(
                    format!("gated: {}", request.input()).into_boxed_str(),
                )
            }
        })
    }
}

#[test]
fn control_transport_identity_is_replay_stable_and_commits_kind_and_cursor() {
    let deck_run_id = id(0xa1, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0xa2, AgentConversationSessionId::try_from_bytes);
    let open = AgentConversationControlV1::open_request(deck_run_id, session_id)
        .canonical_wire()
        .unwrap();
    let watch_seven = AgentConversationControlV1::watch_request(deck_run_id, session_id, 7, 8)
        .unwrap()
        .canonical_wire()
        .unwrap();
    let watch_eight = AgentConversationControlV1::watch_request(deck_run_id, session_id, 8, 8)
        .unwrap()
        .canonical_wire()
        .unwrap();

    assert_eq!(
        control_fabric_request_id(&open).unwrap(),
        control_fabric_request_id(&open).unwrap()
    );
    assert_ne!(
        control_fabric_request_id(&open).unwrap(),
        control_fabric_request_id(&watch_seven).unwrap()
    );
    assert_ne!(
        control_fabric_request_id(&watch_seven).unwrap(),
        control_fabric_request_id(&watch_eight).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_initial_install_rolls_back_submit_lane_with_proven_no_effect() {
    assert_eq!(AGENT_CONVERSATION_PORT_PHYSICAL_BINDINGS, 2);
    let endpoint = available_tcp_endpoint();
    let config = FabricServiceConfig::try_peer(vec![endpoint], Vec::new()).unwrap();
    let mut fabric = FabricService::start(config).await.unwrap();
    let limits = ingress_limits(Duration::from_secs(2));
    let submit_id = BindingId::from_bytes([0xb1; 16]);
    let control_id = BindingId::from_bytes([0xb2; 16]);
    let submit_key = "paraegox/agent/conversation/partial/submit";
    let control_key = "paraegox/agent/conversation/partial/control";
    let port_spec =
        AgentConversationPortSpec::try_new(submit_id, control_id, submit_key, control_key, limits)
            .unwrap();

    let blocker_spec = RequestResponseBindingSpec::try_new(
        control_id,
        None,
        control_key,
        super::command_schema(),
        super::result_schema(),
        limits,
    )
    .unwrap();
    let blocker = fabric
        .install_request_response_binding(blocker_spec)
        .await
        .unwrap();
    let (blocker_binding, mut blocker_receiver) = blocker.into_parts();

    let error = match install_two_lane_port(&mut fabric, &port_spec, None).await {
        Err(error) => error,
        Ok(_) => panic!("occupied control lane must force second-install failure"),
    };
    assert_eq!(
        error.mutation_disposition(),
        AgentConversationPortMutationDispositionV1::ProvenNoEffect
    );

    // Installing the same submit BindingId with expected-none proves that the
    // candidate first lane was retired and joined during rollback.
    let submit_probe_spec = RequestResponseBindingSpec::try_new(
        submit_id,
        None,
        submit_key,
        super::command_schema(),
        super::result_schema(),
        limits,
    )
    .unwrap();
    let submit_probe = fabric
        .install_request_response_binding(submit_probe_spec)
        .await
        .expect("rolled-back submit BindingId is inactive");
    let (submit_probe_binding, mut submit_probe_receiver) = submit_probe.into_parts();
    fabric
        .retire_port_binding(&submit_probe_binding)
        .await
        .unwrap();
    fabric.retire_port_binding(&blocker_binding).await.unwrap();
    assert!(submit_probe_receiver.recv().await.is_none());
    assert!(blocker_receiver.recv().await.is_none());
    fabric.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_local_agent_turn_uses_one_fabric_owner() {
    let deck_run_id = id(0x01, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0x02, AgentConversationSessionId::try_from_bytes);
    let endpoint = available_tcp_endpoint();
    let config = FabricServiceConfig::try_peer(vec![endpoint], Vec::new()).unwrap();
    let mut fabric = FabricService::start(config).await.unwrap();
    let installed = install_agent_conversation_port(
        &mut fabric,
        BindingId::from_bytes([0x03; 16]),
        None,
        "paraegox/agent/conversation/session-local",
        ingress_limits(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let (port, mut endpoint) = installed.into_parts();
    let server = tokio::spawn(async move {
        let mut service = AgentService::new(AgentServiceConfigV1::default());
        let mut provider = DeterministicEchoModelProvider::new();
        service.open_session(deck_run_id, session_id).unwrap();
        let outcome = endpoint
            .serve_one(&mut service, &mut provider)
            .await
            .unwrap();
        assert_eq!(outcome, AgentConversationServeOutcome::TerminalCommitted);
        let retired = endpoint
            .serve_one(&mut service, &mut provider)
            .await
            .unwrap();
        assert_eq!(retired, AgentConversationServeOutcome::PortRetired);
        (service, provider)
    });
    let request = request(deck_run_id, session_id, 0x04, 0x05, "one owner");
    let client = AgentConversationClient::new(&fabric, port);

    let terminal = client.submit(&request, REQUEST_TIMEOUT).await.unwrap();

    assert_eq!(
        terminal.result(),
        &AgentConversationTerminalResultV1::Success("echo: one owner".into())
    );
    drop(client);
    fabric.shutdown().await.unwrap();
    let (_service, provider) = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(provider.calls(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_descriptor_opens_submits_gets_and_watches_one_service() {
    let deck_run_id = id(0x06, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0x07, AgentConversationSessionId::try_from_bytes);
    let (mut server_fabric, client_fabric) = fabric_pair().await;
    let installed = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0x08; 16]),
        None,
        "paraegox/agent/conversation/control-round-trip",
        ingress_limits(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let (port, mut endpoint) = installed.into_parts();
    let descriptor_wire = port
        .export_descriptor_v1()
        .unwrap()
        .canonical_wire()
        .to_vec();
    let remote_port = AgentConversationPortDescriptorV1::decode(&descriptor_wire)
        .unwrap()
        .into_client_port();
    let server_task = tokio::spawn(async move {
        let mut service = AgentService::new(AgentServiceConfigV1::default());
        let mut provider = DeterministicEchoModelProvider::new();
        let mut outcomes = Vec::new();
        loop {
            let outcome = endpoint
                .serve_one(&mut service, &mut provider)
                .await
                .unwrap();
            if outcome == AgentConversationServeOutcome::PortRetired {
                return (service, provider, outcomes);
            }
            outcomes.push(outcome);
        }
    });
    let client = AgentConversationClient::from_client_port_v1(&client_fabric, remote_port);

    assert_eq!(
        client
            .open_session(deck_run_id, session_id, REQUEST_TIMEOUT)
            .await
            .unwrap(),
        AgentConversationOpenOutcomeV1::Opened
    );
    let submitted = request(deck_run_id, session_id, 0x09, 0x0a, "typed controls");
    let terminal = client.submit(&submitted, REQUEST_TIMEOUT).await.unwrap();
    assert_eq!(
        terminal.result(),
        &AgentConversationTerminalResultV1::Success("echo: typed controls".into())
    );
    assert_eq!(
        client
            .get(
                deck_run_id,
                session_id,
                submitted.request_id(),
                REQUEST_TIMEOUT,
            )
            .await
            .unwrap(),
        AgentConversationGetStateV1::Terminal(terminal.clone())
    );
    let batch = client
        .watch(deck_run_id, session_id, 0, 8, REQUEST_TIMEOUT)
        .await
        .unwrap()
        .expect("opened Session has events");
    assert_eq!(batch.next_cursor(), 3);
    assert!(!batch.has_more());
    assert!(matches!(
        batch.events()[0].kind(),
        AgentConversationWatchEventKindV1::SessionOpened
    ));
    assert!(matches!(
        batch.events()[1].kind(),
        AgentConversationWatchEventKindV1::RequestAccepted(value) if value == &submitted
    ));
    assert!(matches!(
        batch.events()[2].kind(),
        AgentConversationWatchEventKindV1::TerminalCommitted(value) if value == &terminal
    ));

    drop(client);
    client_fabric.shutdown().await.unwrap();
    server_fabric.shutdown().await.unwrap();
    let (_service, provider, outcomes) = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("shutdown must join the sole Fabric receiver")
        .unwrap();
    assert_eq!(provider.calls(), 1);
    assert_eq!(
        outcomes,
        vec![
            AgentConversationServeOutcome::ControlHandled,
            AgentConversationServeOutcome::TerminalCommitted,
            AgentConversationServeOutcome::ControlHandled,
            AgentConversationServeOutcome::ControlHandled,
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_provider_does_not_block_tcp_cancel_get_or_watch() {
    let deck_run_id = id(0xa1, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0xa2, AgentConversationSessionId::try_from_bytes);
    let submitted = request(deck_run_id, session_id, 0xa3, 0xa4, "gated model");
    let (mut server_fabric, client_fabric) = fabric_pair().await;
    let installed = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0xa5; 16]),
        None,
        "paraegox/agent/conversation/gated-control",
        ingress_limits(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let (port, mut endpoint) = installed.into_parts();
    let calls = Arc::new(AtomicUsize::new(0));
    let (started_sender, started_receiver) = oneshot::channel();
    let (release_sender, release_receiver) = oneshot::channel();
    let provider = GatedProvider {
        calls: Arc::clone(&calls),
        started: Some(started_sender),
        release: Some(release_receiver),
    };
    let server_task = tokio::spawn(async move {
        let mut service = AgentService::new(AgentServiceConfigV1::default());
        let mut provider = provider;
        let mut outcomes = Vec::new();
        loop {
            let outcome = endpoint
                .serve_one(&mut service, &mut provider)
                .await
                .unwrap();
            if outcome == AgentConversationServeOutcome::PortRetired {
                return (service, outcomes);
            }
            outcomes.push(outcome);
        }
    });
    let control_client = AgentConversationClient::new(&client_fabric, port.clone());
    let submit_client = AgentConversationClient::new(&client_fabric, port);
    assert_eq!(
        control_client
            .open_session(deck_run_id, session_id, REQUEST_TIMEOUT)
            .await
            .unwrap(),
        AgentConversationOpenOutcomeV1::Opened
    );

    let terminal = {
        let submit = submit_client.submit(&submitted, REQUEST_TIMEOUT);
        tokio::pin!(submit);
        let cancellation = tokio::select! {
        started = started_receiver => started.expect("provider start observation"),
        terminal = &mut submit => panic!("provider completed before its release gate: {terminal:?}"),
        };
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(!cancellation.is_cancellation_requested());

        assert_eq!(
            control_client
                .cancel(
                    deck_run_id,
                    session_id,
                    submitted.request_id(),
                    REQUEST_TIMEOUT,
                )
                .await
                .unwrap(),
            AgentConversationCancelStateV1::IntentRecorded
        );
        assert!(cancellation.is_cancellation_requested());
        assert_eq!(
            control_client
                .get(
                    deck_run_id,
                    session_id,
                    submitted.request_id(),
                    REQUEST_TIMEOUT,
                )
                .await
                .unwrap(),
            AgentConversationGetStateV1::Pending {
                cancel_requested: true,
            }
        );
        let batch = control_client
            .watch(deck_run_id, session_id, 0, 8, REQUEST_TIMEOUT)
            .await
            .unwrap()
            .expect("pending Session has observable events");
        assert!(matches!(
            batch.events().last().expect("cancel intent event").kind(),
            AgentConversationWatchEventKindV1::CancelIntentRecorded(request_id)
                if *request_id == submitted.request_id()
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(40), submit.as_mut())
                .await
                .is_err(),
            "cancel/get/watch must return before provider release"
        );

        release_sender.send(()).expect("release provider");
        submit.await.expect("uncertain terminal response")
    };
    assert_eq!(
        terminal.result(),
        &AgentConversationTerminalResultV1::Failure(
            AgentConversationTerminalFailureV1::ModelOutcomeUncertain
        )
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);

    drop(submit_client);
    drop(control_client);
    client_fabric.shutdown().await.unwrap();
    server_fabric.shutdown().await.unwrap();
    let (_service, outcomes) = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("both Fabric lane workers must join")
        .unwrap();
    assert_eq!(
        outcomes,
        vec![
            AgentConversationServeOutcome::ControlHandled,
            AgentConversationServeOutcome::TerminalCommitted,
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_two_lane_retire_settles_pending_handoff_as_uncertain() {
    let deck_run_id = id(0xc1, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0xc2, AgentConversationSessionId::try_from_bytes);
    let submitted = request(deck_run_id, session_id, 0xc3, 0xc4, "retire pending model");
    let (mut server_fabric, client_fabric) = fabric_pair().await;
    let installed = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0xc5; 16]),
        None,
        "paraegox/agent/conversation/graceful-retire",
        ingress_limits(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let (port, mut endpoint) = installed.into_parts();
    let retire_capability = port.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let (started_sender, started_receiver) = oneshot::channel();
    let (release_sender, release_receiver) = oneshot::channel();
    let provider = GatedProvider {
        calls: Arc::clone(&calls),
        started: Some(started_sender),
        release: Some(release_receiver),
    };
    let server_task = tokio::spawn(async move {
        let mut service = AgentService::new(AgentServiceConfigV1::default());
        service.open_session(deck_run_id, session_id).unwrap();
        let mut provider = provider;
        let outcome = endpoint
            .serve_one(&mut service, &mut provider)
            .await
            .unwrap();
        assert_eq!(outcome, AgentConversationServeOutcome::PortRetired);
        service
    });
    let client = AgentConversationClient::new(&client_fabric, port);
    let service = {
        let submit = client.submit(&submitted, REQUEST_TIMEOUT);
        tokio::pin!(submit);
        let cancellation = tokio::select! {
        started = started_receiver => started.expect("provider start observation"),
        terminal = &mut submit => panic!("provider completed before retire: {terminal:?}"),
        };
        assert!(!cancellation.is_cancellation_requested());
        assert_eq!(calls.load(Ordering::Acquire), 1);

        retire_agent_conversation_port(&mut server_fabric, &retire_capability)
            .await
            .expect("both private lane workers retire and join");
        let submit_result = submit.await;
        assert!(
            matches!(
                submit_result,
                Err(AgentConversationClientError::HandlerUnavailable)
            ),
            "retired submit transport must fail explicitly: {submit_result:?}"
        );
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("caller-driven endpoint settles before join")
            .unwrap()
    };
    assert!(
        release_sender.send(()).is_err(),
        "provider future is dropped only after uncertain settlement"
    );
    let snapshot = service
        .export_session_snapshot(deck_run_id, session_id)
        .expect("settled Session snapshot");
    assert!(snapshot.requests()[0].model_handoff_committed());
    assert_eq!(
        snapshot.requests()[0]
            .terminal()
            .expect("graceful uncertain terminal")
            .result(),
        &AgentConversationTerminalResultV1::Failure(
            AgentConversationTerminalFailureV1::ModelOutcomeUncertain
        )
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);

    drop(client);
    client_fabric.shutdown().await.unwrap();
    server_fabric.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_pending_handoff_rejects_extra_submit_before_service_acceptance() {
    let deck_run_id = id(0xd1, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0xd2, AgentConversationSessionId::try_from_bytes);
    let first = request(deck_run_id, session_id, 0xd3, 0xd4, "first gated submit");
    let second = request(deck_run_id, session_id, 0xd5, 0xd6, "extra submit");
    let (mut server_fabric, client_fabric) = fabric_pair().await;
    let installed = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0xd7; 16]),
        None,
        "paraegox/agent/conversation/single-handoff",
        ingress_limits(Duration::from_millis(80)),
    )
    .await
    .unwrap();
    let (port, mut endpoint) = installed.into_parts();
    let calls = Arc::new(AtomicUsize::new(0));
    let (started_sender, started_receiver) = oneshot::channel();
    let (release_sender, release_receiver) = oneshot::channel();
    let provider = GatedProvider {
        calls: Arc::clone(&calls),
        started: Some(started_sender),
        release: Some(release_receiver),
    };
    let server_task = tokio::spawn(async move {
        let mut service = AgentService::new(AgentServiceConfigV1::default());
        service.open_session(deck_run_id, session_id).unwrap();
        let mut provider = provider;
        assert_eq!(
            endpoint.serve_one(&mut service, &mut provider).await,
            Err(super::AgentConversationServeError::ResponseAbandoned)
        );
        service
    });
    let first_client = AgentConversationClient::new(&client_fabric, port.clone());
    let extra_client = AgentConversationClient::new(&client_fabric, port.clone());
    let control_client = AgentConversationClient::new(&client_fabric, port);

    {
        let first_submit = first_client.submit(&first, REQUEST_TIMEOUT);
        tokio::pin!(first_submit);
        tokio::select! {
            started = started_receiver => started.expect("provider start observation"),
            result = &mut first_submit => panic!("first submit ended before provider start: {result:?}"),
        };
        assert!(matches!(
            first_submit.await,
            Err(AgentConversationClientError::HandlerTimeout)
        ));
    }
    assert!(matches!(
        extra_client.submit(&second, REQUEST_TIMEOUT).await,
        Err(AgentConversationClientError::RequestRejected)
    ));
    assert_eq!(
        control_client
            .get(
                deck_run_id,
                session_id,
                second.request_id(),
                REQUEST_TIMEOUT,
            )
            .await
            .unwrap(),
        AgentConversationGetStateV1::NotFound
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);

    release_sender.send(()).expect("release first provider");
    let service = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("abandoned first response still commits semantic terminal")
        .unwrap();
    let snapshot = service
        .export_session_snapshot(deck_run_id, session_id)
        .expect("single-handoff snapshot");
    assert_eq!(snapshot.requests().len(), 1);
    assert_eq!(snapshot.requests()[0].request(), &first);
    assert_eq!(calls.load(Ordering::Acquire), 1);

    drop(control_client);
    drop(extra_client);
    drop(first_client);
    client_fabric.shutdown().await.unwrap();
    server_fabric.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_before_model_crosses_fabric_and_never_calls_provider() {
    let deck_run_id = id(0x0b, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0x0c, AgentConversationSessionId::try_from_bytes);
    let pending = request(deck_run_id, session_id, 0x0d, 0x0e, "cancel before model");
    let server_pending = pending.clone();
    let (mut server_fabric, client_fabric) = fabric_pair().await;
    let installed = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0x0f; 16]),
        None,
        "paraegox/agent/conversation/control-cancel",
        ingress_limits(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let (port, mut endpoint) = installed.into_parts();
    let server_task = tokio::spawn(async move {
        let mut service = AgentService::new(AgentServiceConfigV1::default());
        let mut provider = DeterministicEchoModelProvider::new();
        assert_eq!(
            endpoint
                .serve_one(&mut service, &mut provider)
                .await
                .unwrap(),
            AgentConversationServeOutcome::ControlHandled
        );
        assert_eq!(
            service.accept_request(server_pending).unwrap(),
            AgentServiceAcceptOutcomeV1::Accepted
        );
        let mut outcomes = Vec::new();
        loop {
            let outcome = endpoint
                .serve_one(&mut service, &mut provider)
                .await
                .unwrap();
            if outcome == AgentConversationServeOutcome::PortRetired {
                return (service, provider, outcomes);
            }
            outcomes.push(outcome);
        }
    });
    let client = AgentConversationClient::new(&client_fabric, port);
    assert_eq!(
        client
            .open_session(deck_run_id, session_id, REQUEST_TIMEOUT)
            .await
            .unwrap(),
        AgentConversationOpenOutcomeV1::Opened
    );

    let cancelled = client
        .cancel(
            deck_run_id,
            session_id,
            pending.request_id(),
            REQUEST_TIMEOUT,
        )
        .await
        .unwrap();
    let AgentConversationCancelStateV1::Terminal(cancelled_terminal) = cancelled else {
        panic!("pre-provider cancellation must return its exact terminal");
    };
    assert_eq!(
        cancelled_terminal.result(),
        &AgentConversationTerminalResultV1::Failure(
            AgentConversationTerminalFailureV1::CancelledBeforeModel
        )
    );
    assert_eq!(
        client
            .get(
                deck_run_id,
                session_id,
                pending.request_id(),
                REQUEST_TIMEOUT,
            )
            .await
            .unwrap(),
        AgentConversationGetStateV1::Terminal(cancelled_terminal)
    );
    let batch = client
        .watch(deck_run_id, session_id, 0, 8, REQUEST_TIMEOUT)
        .await
        .unwrap()
        .expect("opened Session has events");
    assert_eq!(batch.next_cursor(), 4);
    assert!(matches!(
        batch.events()[2].kind(),
        AgentConversationWatchEventKindV1::CancelIntentRecorded(value)
            if *value == pending.request_id()
    ));

    drop(client);
    client_fabric.shutdown().await.unwrap();
    server_fabric.shutdown().await.unwrap();
    let (_service, provider, outcomes) = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("shutdown must join the sole Fabric receiver")
        .unwrap();
    assert_eq!(provider.calls(), 0);
    assert_eq!(
        outcomes,
        vec![
            AgentConversationServeOutcome::ControlHandled,
            AgentConversationServeOutcome::ControlHandled,
            AgentConversationServeOutcome::ControlHandled,
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn true_tcp_submit_replays_exactly_and_conflicts_without_calling_provider() {
    let deck_run_id = id(0x11, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0x12, AgentConversationSessionId::try_from_bytes);
    let (mut server_fabric, client_fabric) = fabric_pair().await;
    let installed = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0x21; 16]),
        None,
        "paraegox/agent/conversation/test-main",
        ingress_limits(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let (port, mut endpoint) = installed.into_parts();
    let server_task = tokio::spawn(async move {
        let mut provider = DeterministicEchoModelProvider::new();
        let mut service = AgentService::new(AgentServiceConfigV1::default());
        service.open_session(deck_run_id, session_id).unwrap();
        let mut outcomes = Vec::new();
        loop {
            let outcome = endpoint
                .serve_one(&mut service, &mut provider)
                .await
                .unwrap();
            if outcome == AgentConversationServeOutcome::PortRetired {
                return (service, provider, outcomes);
            }
            outcomes.push(outcome);
        }
    });
    let client = AgentConversationClient::new(&client_fabric, port);

    let first = request(deck_run_id, session_id, 0x31, 0x41, "first");
    let first_terminal = client.submit(&first, REQUEST_TIMEOUT).await.unwrap();
    assert_eq!(
        first_terminal.result(),
        &AgentConversationTerminalResultV1::Success("echo: first".into())
    );
    let duplicate = client.submit(&first, REQUEST_TIMEOUT).await.unwrap();
    assert_eq!(duplicate, first_terminal);

    let conflict = request(deck_run_id, session_id, 0x32, 0x41, "conflict");
    let conflict_terminal = client.submit(&conflict, REQUEST_TIMEOUT).await.unwrap();
    assert_eq!(
        conflict_terminal.result(),
        &AgentConversationTerminalResultV1::Failure(
            AgentConversationTerminalFailureV1::RequestConflict
        )
    );

    let second = request(deck_run_id, session_id, 0x33, 0x42, "second");
    let second_terminal = client.submit(&second, REQUEST_TIMEOUT).await.unwrap();
    assert_eq!(
        second_terminal.result(),
        &AgentConversationTerminalResultV1::Success("echo: second".into())
    );

    drop(client);
    client_fabric.shutdown().await.unwrap();
    server_fabric.shutdown().await.unwrap();
    let (_service, provider, outcomes) = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("server receiver must close after exact Fabric shutdown join")
        .unwrap();
    assert_eq!(provider.calls(), 2);
    assert_eq!(
        outcomes,
        vec![
            AgentConversationServeOutcome::TerminalCommitted,
            AgentConversationServeOutcome::TerminalReplay,
            AgentConversationServeOutcome::SemanticRejected,
            AgentConversationServeOutcome::TerminalCommitted,
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_and_unknown_session_are_rejected_without_implicit_open() {
    let (mut server_fabric, client_fabric) = fabric_pair().await;
    let installed = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0x22; 16]),
        None,
        "paraegox/agent/conversation/test-malformed",
        ingress_limits(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let (port, mut endpoint) = installed.into_parts();
    let server_task = tokio::spawn(async move {
        let mut service = AgentService::new(AgentServiceConfigV1::default());
        let mut provider = DeterministicEchoModelProvider::new();
        let malformed = endpoint
            .serve_one(&mut service, &mut provider)
            .await
            .unwrap();
        let malformed_control = endpoint
            .serve_one(&mut service, &mut provider)
            .await
            .unwrap();
        let unknown_session = endpoint
            .serve_one(&mut service, &mut provider)
            .await
            .unwrap();
        (
            service,
            provider,
            malformed,
            malformed_control,
            unknown_session,
        )
    });

    let response = client_fabric
        .request(
            &port.submit_binding,
            FabricRequestId::try_from_bytes([0x51; 16]).unwrap(),
            b"not-a-pxac-frame".to_vec(),
            REQUEST_TIMEOUT,
        )
        .await
        .unwrap();
    assert_eq!(response.status(), ResponseStatus::HandlerRejected);
    assert!(response.body().is_empty());

    let mut corrupt_control = AgentConversationControlV1::open_request(
        id(0x52, AgentConversationDeckRunId::try_from_bytes),
        id(0x53, AgentConversationSessionId::try_from_bytes),
    )
    .canonical_wire()
    .unwrap()
    .into_vec();
    corrupt_control[84] ^= 1;
    let response = client_fabric
        .request(
            &port.control_binding,
            FabricRequestId::try_from_bytes([0x52; 16]).unwrap(),
            corrupt_control,
            REQUEST_TIMEOUT,
        )
        .await
        .unwrap();
    assert_eq!(response.status(), ResponseStatus::HandlerRejected);
    assert!(response.body().is_empty());

    let unknown = request(
        id(0x53, AgentConversationDeckRunId::try_from_bytes),
        id(0x54, AgentConversationSessionId::try_from_bytes),
        0x55,
        0x56,
        "must not auto-open",
    );
    let typed_client = AgentConversationClient::new(&client_fabric, port);
    assert!(matches!(
        typed_client.submit(&unknown, REQUEST_TIMEOUT).await,
        Err(AgentConversationClientError::RequestRejected)
    ));

    let (service, provider, malformed, malformed_control, unknown_session) =
        server_task.await.unwrap();
    assert!(matches!(
        malformed,
        AgentConversationServeOutcome::MalformedRequest(_)
    ));
    assert_eq!(
        malformed_control,
        AgentConversationServeOutcome::MalformedControl(
            AgentConversationControlError::DigestMismatch
        )
    );
    assert_eq!(
        unknown_session,
        AgentConversationServeOutcome::ServiceRejected(
            paraegox_agent_service::AgentServiceError::UnknownSession
        )
    );
    assert_eq!(service.retained_sessions(), 0);
    assert_eq!(provider.calls(), 0);

    drop(typed_client);
    client_fabric.shutdown().await.unwrap();
    server_fabric.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_client_maps_stale_generation_and_handler_timeout_without_retry() {
    let deck_run_id = id(0x61, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0x62, AgentConversationSessionId::try_from_bytes);
    let (mut server_fabric, client_fabric) = fabric_pair().await;
    let installed_v1 = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0x23; 16]),
        None,
        "paraegox/agent/conversation/test-fencing",
        ingress_limits(Duration::from_millis(60)),
    )
    .await
    .unwrap();
    let (port_v1, mut endpoint_v1) = installed_v1.into_parts();
    let installed_v2 = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0x23; 16]),
        Some(&port_v1),
        "paraegox/agent/conversation/test-fencing",
        ingress_limits(Duration::from_millis(60)),
    )
    .await
    .unwrap();
    let (port_v2, endpoint_v2) = installed_v2.into_parts();

    let mut retired_service = AgentService::new(AgentServiceConfigV1::default());
    let mut retired_provider = DeterministicEchoModelProvider::new();
    assert_eq!(
        endpoint_v1
            .serve_one(&mut retired_service, &mut retired_provider)
            .await
            .unwrap(),
        AgentConversationServeOutcome::PortRetired
    );

    let stale_request = request(deck_run_id, session_id, 0x71, 0x72, "stale");
    let stale_client = AgentConversationClient::new(&client_fabric, port_v1);
    let stale_open = stale_client
        .open_session(deck_run_id, session_id, REQUEST_TIMEOUT)
        .await;
    assert!(
        matches!(stale_open, Err(AgentConversationClientError::StalePort)),
        "unexpected stale open result: {stale_open:?}"
    );
    assert!(matches!(
        stale_client.submit(&stale_request, REQUEST_TIMEOUT).await,
        Err(AgentConversationClientError::StalePort)
    ));

    // Keep the sole receiver alive but deliberately do not serve it. Fabric's
    // bounded handler timeout must become one typed error, with no retry.
    let timeout_request = request(deck_run_id, session_id, 0x73, 0x74, "timeout");
    let timeout_client = AgentConversationClient::new(&client_fabric, port_v2);
    let timeout_submit = timeout_client
        .submit(&timeout_request, REQUEST_TIMEOUT)
        .await;
    assert!(
        matches!(
            timeout_submit,
            Err(AgentConversationClientError::HandlerTimeout)
        ),
        "unexpected submit timeout result: {timeout_submit:?}"
    );

    drop(endpoint_v2);
    drop(timeout_client);
    drop(stale_client);
    client_fabric.shutdown().await.unwrap();
    server_fabric.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_client_rejects_a_valid_but_wrongly_correlated_terminal() {
    let deck_run_id = id(0x81, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0x82, AgentConversationSessionId::try_from_bytes);
    let (mut server_fabric, client_fabric) = fabric_pair().await;
    let installed = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0x24; 16]),
        None,
        "paraegox/agent/conversation/test-correlation",
        ingress_limits(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let (port, mut endpoint) = installed.into_parts();
    let wrong_request = request(deck_run_id, session_id, 0x83, 0x84, "wrong terminal");
    let wrong_terminal =
        paraegox_agent_contracts::AgentConversationTerminalV1::try_success(&wrong_request, "wrong")
            .unwrap();
    let handler = tokio::spawn(async move {
        let inbound = endpoint.submit_receiver.recv().await.unwrap();
        inbound
            .respond(HandlerResponse::Ok(
                wrong_terminal.canonical_wire().into_vec(),
            ))
            .unwrap();
    });

    let submitted = request(deck_run_id, session_id, 0x85, 0x86, "submitted");
    let client = AgentConversationClient::new(&client_fabric, port);
    assert!(matches!(
        client.submit(&submitted, REQUEST_TIMEOUT).await,
        Err(AgentConversationClientError::TerminalCorrelationMismatch)
    ));

    handler.await.unwrap();
    drop(client);
    client_fabric.shutdown().await.unwrap();
    server_fabric.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_control_client_rejects_wrong_correlation_kind_and_watch_cursor() {
    let deck_run_id = id(0x91, AgentConversationDeckRunId::try_from_bytes);
    let session_id = id(0x92, AgentConversationSessionId::try_from_bytes);
    let other_session = id(0x93, AgentConversationSessionId::try_from_bytes);
    let (mut server_fabric, client_fabric) = fabric_pair().await;
    let installed = install_agent_conversation_port(
        &mut server_fabric,
        BindingId::from_bytes([0x25; 16]),
        None,
        "paraegox/agent/conversation/test-control-correlation",
        ingress_limits(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let (port, mut endpoint) = installed.into_parts();

    let wrong_correlation = AgentConversationControlV1::open_result(
        deck_run_id,
        other_session,
        AgentConversationOpenOutcomeV1::Opened,
    )
    .canonical_wire()
    .unwrap();
    let wrong_kind = AgentConversationControlV1::watch_result_not_found(deck_run_id, session_id)
        .canonical_wire()
        .unwrap();
    let standalone_bad_cursor = AgentConversationWatchBatchV1::try_new(
        vec![
            AgentConversationWatchEventV1::try_new(
                2,
                AgentConversationWatchEventKindV1::SessionOpened,
            )
            .unwrap(),
        ]
        .into_boxed_slice(),
        2,
        2,
        false,
        false,
    )
    .unwrap();
    let wrong_cursor =
        AgentConversationControlV1::watch_result(deck_run_id, session_id, standalone_bad_cursor)
            .unwrap()
            .canonical_wire()
            .unwrap();
    let handler = tokio::spawn(async move {
        for response in [wrong_correlation, wrong_kind, wrong_cursor] {
            let inbound = endpoint.control_receiver.recv().await.unwrap();
            inbound
                .respond(HandlerResponse::Ok(response.into_vec()))
                .unwrap();
        }
    });

    let client = AgentConversationClient::new(&client_fabric, port);
    assert!(matches!(
        client
            .open_session(deck_run_id, session_id, REQUEST_TIMEOUT)
            .await,
        Err(AgentConversationClientError::ControlResponseCorrelationMismatch)
    ));
    assert!(matches!(
        client
            .open_session(deck_run_id, session_id, REQUEST_TIMEOUT)
            .await,
        Err(AgentConversationClientError::ControlResponseKindMismatch)
    ));
    assert!(matches!(
        client
            .watch(deck_run_id, session_id, 0, 1, REQUEST_TIMEOUT)
            .await,
        Err(AgentConversationClientError::Control(
            AgentConversationControlError::InvalidWatchSequence
        ))
    ));

    handler.await.unwrap();
    drop(client);
    client_fabric.shutdown().await.unwrap();
    server_fabric.shutdown().await.unwrap();
}
