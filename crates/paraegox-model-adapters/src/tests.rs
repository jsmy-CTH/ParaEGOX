use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::time::BoundedDuration;
use paraegox_model::{
    ModelAdapterFactoryV1, ModelAdapterRegistryErrorV1, ModelAdapterRegistryV1,
    ModelAdapterSelectionV1, ModelBackendIdentityV1, ModelBackendV1, ModelCancellationSourceV1,
    ModelCancellationViewV1, ModelInvocationIdV1, ModelInvocationOutcomeV1,
    ModelInvocationRequestV1,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::{
    DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_CAPABILITY_ID_V1,
    DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_DESCRIPTOR_V1, DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_ID_V1,
    DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_VERSION_V1, DEEPSEEK_CHAT_COMPLETIONS_API_ENDPOINT,
    DeepSeekChatCompletionsProviderConfigV1, DeepSeekChatCompletionsProviderError,
    DeepSeekChatCompletionsProviderFactoryV1, DeepSeekChatModelV1, DeepSeekResolvedApiKeyV1,
    InvocationFailure, MAX_DEEPSEEK_CHAT_COMPLETIONS_HTTP_BODY_BYTES,
    MAX_DEEPSEEK_CHAT_COMPLETIONS_OUTPUT_TOKENS, MAX_OPENAI_RESPONSES_HTTP_BODY_BYTES,
    OPENAI_RESPONSES_ADAPTER_CAPABILITY_ID_V1, OPENAI_RESPONSES_ADAPTER_DESCRIPTOR_V1,
    OPENAI_RESPONSES_ADAPTER_ID_V1, OPENAI_RESPONSES_ADAPTER_VERSION_V1,
    OPENAI_RESPONSES_API_ENDPOINT, OpenAiResolvedApiKeyV1, OpenAiResponsesProviderConfigV1,
    OpenAiResponsesProviderError, OpenAiResponsesProviderFactoryV1, arbitrate_invocation,
};

const TEST_API_KEY: &[u8] = b"test-secret-api-key";
const TEST_DEEPSEEK_API_KEY: &[u8] = b"test-deepseek-secret-api-key";

struct TestServer {
    endpoint: String,
    calls: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl TestServer {
    async fn spawn(
        status: &str,
        response_body: Vec<u8>,
        response_delay: Duration,
        observe_second_request: bool,
    ) -> Self {
        Self::spawn_at(
            "/v1/responses",
            status,
            response_body,
            response_delay,
            observe_second_request,
        )
        .await
    }

    async fn spawn_deepseek(
        status: &str,
        response_body: Vec<u8>,
        response_delay: Duration,
        observe_second_request: bool,
    ) -> Self {
        Self::spawn_at(
            "/chat/completions",
            status,
            response_body,
            response_delay,
            observe_second_request,
        )
        .await
    }

    async fn spawn_at(
        path: &str,
        status: &str,
        response_body: Vec<u8>,
        response_delay: Duration,
        observe_second_request: bool,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener must bind");
        let address = listener
            .local_addr()
            .expect("test listener must have a local address");
        let calls = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task_calls = Arc::clone(&calls);
        let task_requests = Arc::clone(&requests);
        let status = status.to_owned();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("request must connect");
            let request = read_http_request(&mut stream).await;
            task_calls.fetch_add(1, Ordering::AcqRel);
            task_requests
                .lock()
                .expect("request capture lock must be healthy")
                .push(request);
            tokio::time::sleep(response_delay).await;
            write_http_response(&mut stream, &status, &response_body).await;

            if observe_second_request
                && let Ok(Ok((mut second, _))) =
                    tokio::time::timeout(Duration::from_millis(150), listener.accept()).await
            {
                let request = read_http_request(&mut second).await;
                task_calls.fetch_add(1, Ordering::AcqRel);
                task_requests
                    .lock()
                    .expect("request capture lock must be healthy")
                    .push(request);
                write_http_response(&mut second, &status, &response_body).await;
            }
        });
        Self {
            endpoint: format!("http://{address}{path}"),
            calls,
            requests,
            task,
        }
    }

    async fn join(self) -> (usize, Vec<Vec<u8>>) {
        self.task.await.expect("test server task must join");
        let calls = self.calls.load(Ordering::Acquire);
        let requests = self
            .requests
            .lock()
            .expect("request capture lock must be healthy")
            .clone();
        (calls, requests)
    }
}

fn provider_ref(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn config(
    provider_ref: [u8; 16],
    timeout_nanos: u64,
    max_response_body_bytes: usize,
    max_output_text_bytes: usize,
) -> OpenAiResponsesProviderConfigV1 {
    OpenAiResponsesProviderConfigV1::try_new(
        provider_ref,
        "gpt-test-model",
        timeout_nanos,
        128,
        max_response_body_bytes,
        max_output_text_bytes,
    )
    .expect("test provider configuration must be valid")
}

fn loopback_factory(
    endpoint: &str,
    timeout_nanos: u64,
    max_response_body_bytes: usize,
    max_output_text_bytes: usize,
) -> OpenAiResponsesProviderFactoryV1 {
    let config = config(
        provider_ref(1),
        timeout_nanos,
        max_response_body_bytes,
        max_output_text_bytes,
    );
    let key =
        OpenAiResolvedApiKeyV1::try_new(TEST_API_KEY.to_vec()).expect("test API key must be valid");
    OpenAiResponsesProviderFactoryV1::try_new_for_loopback(config, key, endpoint)
        .expect("test loopback endpoint must be valid")
}

fn deepseek_config(
    provider_ref: [u8; 16],
    timeout_nanos: u64,
    max_response_body_bytes: usize,
    max_output_text_bytes: usize,
) -> DeepSeekChatCompletionsProviderConfigV1 {
    DeepSeekChatCompletionsProviderConfigV1::try_new(
        provider_ref,
        DeepSeekChatModelV1::V4Pro,
        timeout_nanos,
        128,
        max_response_body_bytes,
        max_output_text_bytes,
    )
    .expect("test DeepSeek provider configuration must be valid")
}

fn deepseek_loopback_factory(
    endpoint: &str,
    timeout_nanos: u64,
    max_response_body_bytes: usize,
    max_output_text_bytes: usize,
) -> DeepSeekChatCompletionsProviderFactoryV1 {
    let config = deepseek_config(
        provider_ref(2),
        timeout_nanos,
        max_response_body_bytes,
        max_output_text_bytes,
    );
    let key = DeepSeekResolvedApiKeyV1::try_new(TEST_DEEPSEEK_API_KEY.to_vec())
        .expect("test DeepSeek API key must be valid");
    DeepSeekChatCompletionsProviderFactoryV1::try_new_for_loopback(config, key, endpoint)
        .expect("test DeepSeek loopback endpoint must be valid")
}

fn request_and_cancellation(
    deadline_budget_nanos: u64,
    input: &str,
) -> (ModelInvocationRequestV1, ModelCancellationViewV1) {
    let (_, request, cancellation) = cancellable_request(deadline_budget_nanos, input);
    (request, cancellation)
}

fn cancellable_request(
    deadline_budget_nanos: u64,
    input: &str,
) -> (
    ModelCancellationSourceV1,
    ModelInvocationRequestV1,
    ModelCancellationViewV1,
) {
    let request = ModelInvocationRequestV1::try_new(
        ModelInvocationIdV1::try_from_bytes([1; 16]).expect("test invocation id must be nonzero"),
        Digest32::from_bytes([14; 32]),
        BoundedDuration::from_nanos(deadline_budget_nanos),
        input,
    )
    .expect("test request must be valid");
    let source = ModelCancellationSourceV1::new();
    let cancellation = source.view();
    (source, request, cancellation)
}

#[test]
fn config_and_secret_validation_fail_closed() {
    let reference = provider_ref(1);
    assert_eq!(
        OpenAiResponsesProviderConfigV1::try_new(reference, "", 1, 1, 1, 1),
        Err(OpenAiResponsesProviderError::InvalidModel)
    );
    assert_eq!(
        OpenAiResponsesProviderConfigV1::try_new(reference, "bad model", 1, 1, 1, 1),
        Err(OpenAiResponsesProviderError::InvalidModel)
    );
    assert_eq!(
        OpenAiResponsesProviderConfigV1::try_new(reference, "gpt-test", 0, 1, 1, 1),
        Err(OpenAiResponsesProviderError::TimeoutOutOfRange)
    );
    assert_eq!(
        OpenAiResponsesProviderConfigV1::try_new(reference, "gpt-test", 1, 0, 1, 1,),
        Err(OpenAiResponsesProviderError::OutputTokenLimitOutOfRange)
    );
    assert_eq!(
        OpenAiResponsesProviderConfigV1::try_new(
            reference,
            "gpt-test",
            1,
            1,
            MAX_OPENAI_RESPONSES_HTTP_BODY_BYTES + 1,
            1,
        ),
        Err(OpenAiResponsesProviderError::ResponseLimitOutOfRange)
    );
    assert_eq!(
        OpenAiResponsesProviderConfigV1::try_new(reference, "gpt-test", 1, 1, 8, 9),
        Err(OpenAiResponsesProviderError::OutputLimitOutOfRange)
    );
    assert_eq!(
        OpenAiResolvedApiKeyV1::try_new(b"bad key".to_vec()).err(),
        Some(OpenAiResponsesProviderError::InvalidApiKey)
    );
    assert_eq!(
        OpenAiResolvedApiKeyV1::try_new(Vec::new()).err(),
        Some(OpenAiResponsesProviderError::InvalidApiKey)
    );
    assert_eq!(
        OpenAiResponsesProviderConfigV1::try_new([0; 16], "gpt-test", 1, 1, 1, 1),
        Err(OpenAiResponsesProviderError::BackendIdentity(
            paraegox_model::ModelBackendIdentityErrorV1::ZeroProviderRef
        ))
    );
}

#[test]
fn resolved_api_key_redacts_debug_without_exposure() {
    let resolved =
        OpenAiResolvedApiKeyV1::try_new(TEST_API_KEY.to_vec()).expect("test API key must be valid");
    let rendered = format!("{resolved:?}");
    assert_eq!(rendered, "OpenAiResolvedApiKeyV1(<redacted>)");
    assert!(!rendered.contains("test-secret-api-key"));
}

#[test]
fn production_factory_is_fixed_and_debug_redacts_secret() {
    let config = config(provider_ref(1), 1_000_000_000, 4_096, 1_024);
    let key =
        OpenAiResolvedApiKeyV1::try_new(TEST_API_KEY.to_vec()).expect("test API key must be valid");
    let key_debug = format!("{key:?}");
    assert!(!key_debug.contains("test-secret-api-key"));
    assert!(key_debug.contains("<redacted>"));

    let factory = OpenAiResponsesProviderFactoryV1::new(config.clone(), key);
    assert_eq!(factory.endpoint.url(), OPENAI_RESPONSES_API_ENDPOINT);
    let factory_debug = format!("{factory:?}");
    assert!(!factory_debug.contains("test-secret-api-key"));
    let backend = factory.build().expect("backend must build");
    let backend_debug = format!("{backend:?}");
    assert!(!backend_debug.contains("test-secret-api-key"));
    assert!(backend_debug.contains("[REDACTED]"));
    assert_eq!(backend.identity().provider_ref(), config.provider_ref());
    assert_eq!(backend.identity().config_digest(), config.config_digest());
}

#[test]
fn every_build_is_repeatable_for_the_exact_immutable_config_and_secret() {
    let config = config(provider_ref(1), 1_000_000_000, 4_096, 1_024);
    let key =
        OpenAiResolvedApiKeyV1::try_new(TEST_API_KEY.to_vec()).expect("test API key must be valid");
    let factory = OpenAiResponsesProviderFactoryV1::new(config.clone(), key);
    let first = factory.build().expect("first backend must build");
    let second = factory.build().expect("second backend must build");
    assert_eq!(first.identity(), second.identity());
    assert_eq!(first.identity().provider_ref(), config.provider_ref());
    assert_eq!(first.identity().config_digest(), config.config_digest());
}

#[test]
fn exact_adapter_registration_resolves_the_configured_openai_backend() {
    let config = config(provider_ref(7), 1_000_000_000, 4_096, 1_024);
    let expected_identity = paraegox_model::ModelBackendIdentityV1::try_new(
        *config.provider_ref(),
        config.config_digest(),
    )
    .expect("test backend identity must be valid");
    let key =
        OpenAiResolvedApiKeyV1::try_new(TEST_API_KEY.to_vec()).expect("test API key must be valid");
    let factory = OpenAiResponsesProviderFactoryV1::new(config, key);
    let metadata = ModelAdapterFactoryV1::metadata(&factory);
    assert_eq!(
        metadata.descriptor(),
        OPENAI_RESPONSES_ADAPTER_DESCRIPTOR_V1
    );
    assert_eq!(metadata.adapter_id(), OPENAI_RESPONSES_ADAPTER_ID_V1);
    assert_eq!(
        metadata.adapter_version(),
        OPENAI_RESPONSES_ADAPTER_VERSION_V1
    );
    assert_eq!(
        metadata.capability_id(),
        OPENAI_RESPONSES_ADAPTER_CAPABILITY_ID_V1
    );
    assert_eq!(metadata.backend_identity(), expected_identity);
    let rendered = format!("{factory:?}");
    assert!(!rendered.contains("test-secret-api-key"));
    assert!(rendered.contains("[REDACTED]"));

    let mut registry = ModelAdapterRegistryV1::new();
    registry
        .register(factory)
        .expect("OpenAI adapter registration must succeed");
    let backend = registry
        .resolve(ModelAdapterSelectionV1::new(
            OPENAI_RESPONSES_ADAPTER_DESCRIPTOR_V1,
            expected_identity,
        ))
        .expect("exact OpenAI adapter selection must resolve");
    assert_eq!(backend.identity(), expected_identity);
}

#[tokio::test]
async fn successful_call_uses_bearer_and_aggregates_all_output_text() {
    let response = json!({
        "output": [
            {"type": "reasoning", "summary": []},
            {
                "type": "message",
                "role": "assistant",
                "content": [
                    {"type": "output_text", "text": "hello", "annotations": []},
                    {"type": "refusal", "refusal": "ignored"},
                    {"type": "output_text", "text": " world", "annotations": []}
                ]
            },
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "!", "annotations": []}]
            }
        ]
    });
    let server = TestServer::spawn(
        "200 OK",
        serde_json::to_vec(&response).expect("test response must serialize"),
        Duration::ZERO,
        false,
    )
    .await;
    let factory = loopback_factory(&server.endpoint, 1_000_000_000, 8_192, 1_024);
    let backend = factory.build().expect("backend must build");
    let (request, cancellation) = request_and_cancellation(1_000_000_000, "hello provider");

    assert_eq!(
        backend.invoke(request, cancellation).await,
        ModelInvocationOutcomeV1::Success("hello world!".into())
    );
    let (calls, requests) = server.join().await;
    assert_eq!(calls, 1);
    assert_eq!(requests.len(), 1);
    let request = String::from_utf8(requests[0].clone()).expect("test request must be UTF-8");
    assert!(request.starts_with("POST /v1/responses HTTP/1.1\r\n"));
    assert!(request.contains("authorization: Bearer test-secret-api-key\r\n"));
    let body = request
        .split_once("\r\n\r\n")
        .expect("test request must contain a body")
        .1;
    let body: Value = serde_json::from_str(body).expect("request body must be JSON");
    assert_eq!(
        body,
        json!({
            "model": "gpt-test-model",
            "input": "hello provider",
            "max_output_tokens": 128,
            "store": false
        })
    );
}

#[tokio::test]
async fn non_success_status_is_failed_and_never_retried() {
    let server = TestServer::spawn(
        "500 Internal Server Error",
        br#"{"error":{"message":"unavailable"}}"#.to_vec(),
        Duration::ZERO,
        true,
    )
    .await;
    let factory = loopback_factory(&server.endpoint, 1_000_000_000, 4_096, 1_024);
    let backend = factory.build().expect("backend must build");
    let (request, cancellation) = request_and_cancellation(1_000_000_000, "one attempt");

    assert_eq!(
        backend.invoke(request, cancellation).await,
        ModelInvocationOutcomeV1::Failed
    );
    let (calls, _) = server.join().await;
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn malformed_and_oversized_success_responses_fail_closed() {
    for response_body in [
        b"not-json".to_vec(),
        br#"{"output":[{"type":"message","content":[]}]}"#.to_vec(),
        vec![b' '; 512],
    ] {
        let server = TestServer::spawn("200 OK", response_body, Duration::ZERO, false).await;
        let factory = loopback_factory(&server.endpoint, 1_000_000_000, 128, 64);
        let backend = factory.build().expect("backend must build");
        let (request, cancellation) = request_and_cancellation(1_000_000_000, "bounded response");
        assert_eq!(
            backend.invoke(request, cancellation).await,
            ModelInvocationOutcomeV1::Failed
        );
        let (calls, _) = server.join().await;
        assert_eq!(calls, 1);
    }
}

#[tokio::test]
async fn oversized_aggregated_output_fails_closed() {
    let response = json!({
        "output": [{
            "type": "message",
            "content": [
                {"type": "output_text", "text": "1234"},
                {"type": "output_text", "text": "5678"}
            ]
        }]
    });
    let server = TestServer::spawn(
        "200 OK",
        serde_json::to_vec(&response).expect("test response must serialize"),
        Duration::ZERO,
        false,
    )
    .await;
    let factory = loopback_factory(&server.endpoint, 1_000_000_000, 4_096, 7);
    let backend = factory.build().expect("backend must build");
    let (request, cancellation) = request_and_cancellation(1_000_000_000, "bounded output");
    assert_eq!(
        backend.invoke(request, cancellation).await,
        ModelInvocationOutcomeV1::Failed
    );
    let (calls, _) = server.join().await;
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn protocol_deadline_is_tighter_than_provider_timeout() {
    let response = json!({
        "output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": "too late"}]
        }]
    });
    let server = TestServer::spawn(
        "200 OK",
        serde_json::to_vec(&response).expect("test response must serialize"),
        Duration::from_millis(80),
        false,
    )
    .await;
    let factory = loopback_factory(&server.endpoint, 250_000_000, 4_096, 1_024);
    let backend = factory.build().expect("backend must build");
    let (request, cancellation) = request_and_cancellation(20_000_000, "short deadline");
    assert_eq!(
        backend.invoke(request, cancellation).await,
        ModelInvocationOutcomeV1::DeadlineExceeded
    );
    let (calls, _) = server.join().await;
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn cancellation_requested_before_provider_entry_sends_no_http() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener must bind");
    let address = listener
        .local_addr()
        .expect("test listener must have a local address");
    let endpoint = format!("http://{address}/v1/responses");
    let watcher = tokio::spawn(async move {
        matches!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept()).await,
            Ok(Ok(_))
        )
    });
    let factory = loopback_factory(&endpoint, 1_000_000_000, 4_096, 1_024);
    let backend = factory.build().expect("backend must build");
    let (source, request, cancellation) =
        cancellable_request(1_000_000_000, "cancel before provider entry");
    source.request_cancellation();

    assert_eq!(
        backend.invoke(request, cancellation).await,
        ModelInvocationOutcomeV1::CancelledBeforeHandoff
    );
    assert!(!watcher.await.expect("request watcher must join"));
}

#[tokio::test]
async fn cancellation_after_http_handoff_is_uncertain_and_sends_once() {
    let response = json!({
        "output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": "late output"}]
        }]
    });
    let server = TestServer::spawn(
        "200 OK",
        serde_json::to_vec(&response).expect("test response must serialize"),
        Duration::from_millis(100),
        true,
    )
    .await;
    let calls = Arc::clone(&server.calls);
    let factory = loopback_factory(&server.endpoint, 1_000_000_000, 4_096, 1_024);
    let backend = factory.build().expect("backend must build");
    let (source, request, cancellation) = cancellable_request(1_000_000_000, "cancel in flight");
    let backend_task = tokio::spawn(backend.invoke(request, cancellation));
    tokio::time::timeout(Duration::from_millis(250), async {
        while calls.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("provider must hand one request to HTTP");
    source.request_cancellation();
    assert_eq!(
        backend_task.await.expect("backend task must join"),
        ModelInvocationOutcomeV1::OutcomeUncertain
    );
    let (calls, _) = server.join().await;
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn known_provider_terminal_wins_a_simultaneously_ready_cancel() {
    let (source, _request, cancellation) = cancellable_request(1_000_000_000, "known result race");
    source.request_cancellation();
    let invocation = async { Ok::<Box<str>, InvocationFailure>("known".into()) };
    assert_eq!(
        arbitrate_invocation(invocation, Duration::from_secs(1), cancellation).await,
        ModelInvocationOutcomeV1::Success("known".into())
    );
}

#[tokio::test]
async fn transport_failure_after_handoff_is_outcome_uncertain() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener must bind");
    let address = listener
        .local_addr()
        .expect("test listener must have a local address");
    drop(listener);
    let endpoint = format!("http://{address}/v1/responses");
    let factory = loopback_factory(&endpoint, 1_000_000_000, 4_096, 1_024);
    let backend = factory.build().expect("backend must build");
    let (request, cancellation) = request_and_cancellation(1_000_000_000, "uncertain transport");
    assert_eq!(
        backend.invoke(request, cancellation).await,
        ModelInvocationOutcomeV1::OutcomeUncertain
    );
}

#[test]
fn deepseek_factory_is_exact_fixed_and_secret_safe() {
    assert_eq!(
        DeepSeekChatModelV1::try_from_id("deepseek-v4-flash"),
        Ok(DeepSeekChatModelV1::V4Flash)
    );
    assert_eq!(
        DeepSeekChatModelV1::try_from_id("deepseek-v4-pro"),
        Ok(DeepSeekChatModelV1::V4Pro)
    );
    assert_eq!(
        DeepSeekChatModelV1::try_from_id("deepseek-chat"),
        Err(DeepSeekChatCompletionsProviderError::InvalidModel)
    );
    assert_eq!(
        DeepSeekChatModelV1::try_from_id("deepseek-v4-pro "),
        Err(DeepSeekChatCompletionsProviderError::InvalidModel)
    );
    assert_eq!(
        DeepSeekResolvedApiKeyV1::try_new(b"bad key".to_vec()).err(),
        Some(DeepSeekChatCompletionsProviderError::InvalidApiKey)
    );

    let config = deepseek_config(provider_ref(2), 1_000_000_000, 4_096, 1_024);
    let key = DeepSeekResolvedApiKeyV1::try_new(TEST_DEEPSEEK_API_KEY.to_vec())
        .expect("test DeepSeek API key must be valid");
    assert_eq!(format!("{key:?}"), "DeepSeekResolvedApiKeyV1(<redacted>)");
    let factory = DeepSeekChatCompletionsProviderFactoryV1::new(config.clone(), key);
    assert_eq!(
        factory.endpoint.url(),
        DEEPSEEK_CHAT_COMPLETIONS_API_ENDPOINT
    );
    assert!(!format!("{factory:?}").contains("test-deepseek-secret-api-key"));
    let metadata = ModelAdapterFactoryV1::metadata(&factory);
    assert_eq!(
        metadata.descriptor(),
        DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_DESCRIPTOR_V1
    );
    assert_eq!(
        metadata.adapter_id(),
        DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_ID_V1
    );
    assert_eq!(
        metadata.adapter_version(),
        DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_VERSION_V1
    );
    assert_eq!(
        metadata.capability_id(),
        DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_CAPABILITY_ID_V1
    );
    let expected_identity = metadata.backend_identity();
    assert_eq!(expected_identity.config_digest(), config.config_digest());
    let mut registry = ModelAdapterRegistryV1::new();
    registry
        .register(factory)
        .expect("DeepSeek adapter registration must succeed");
    let backend = registry
        .resolve(ModelAdapterSelectionV1::new(
            DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_DESCRIPTOR_V1,
            expected_identity,
        ))
        .expect("exact DeepSeek adapter selection must resolve");
    assert_eq!(backend.identity(), expected_identity);
    let wrong_provider_identity =
        ModelBackendIdentityV1::try_new(provider_ref(3), expected_identity.config_digest())
            .expect("mismatched test provider identity must still be structurally valid");
    assert!(matches!(
        registry.resolve(ModelAdapterSelectionV1::new(
            DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_DESCRIPTOR_V1,
            wrong_provider_identity,
        )),
        Err(ModelAdapterRegistryErrorV1::SelectionProviderRefMismatch)
    ));
    let wrong_config_identity = ModelBackendIdentityV1::try_new(
        *expected_identity.provider_ref(),
        Digest32::from_bytes([99; 32]),
    )
    .expect("mismatched test config identity must still be structurally valid");
    assert!(matches!(
        registry.resolve(ModelAdapterSelectionV1::new(
            DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_DESCRIPTOR_V1,
            wrong_config_identity,
        )),
        Err(ModelAdapterRegistryErrorV1::SelectionConfigDigestMismatch)
    ));
    assert!(matches!(
        registry.resolve(ModelAdapterSelectionV1::new(
            OPENAI_RESPONSES_ADAPTER_DESCRIPTOR_V1,
            expected_identity,
        )),
        Err(ModelAdapterRegistryErrorV1::UnknownAdapterDescriptor)
    ));

    for endpoint in [
        "https://127.0.0.1:9443/chat/completions",
        "http://localhost:9443/chat/completions",
        "http://127.0.0.1:9443/v1/chat/completions",
        "http://127.0.0.1:9443/chat/completions?redirect=1",
    ] {
        let config = deepseek_config(provider_ref(2), 1_000_000_000, 4_096, 1_024);
        let key = DeepSeekResolvedApiKeyV1::try_new(TEST_DEEPSEEK_API_KEY.to_vec())
            .expect("test DeepSeek API key must be valid");
        assert!(matches!(
            DeepSeekChatCompletionsProviderFactoryV1::try_new_for_loopback(config, key, endpoint),
            Err(DeepSeekChatCompletionsProviderError::InvalidEndpoint)
        ));
    }
}

#[test]
fn deepseek_config_bounds_and_model_commitment_fail_closed() {
    let reference = provider_ref(2);
    assert_eq!(
        DeepSeekChatCompletionsProviderConfigV1::try_new(
            reference,
            DeepSeekChatModelV1::V4Flash,
            0,
            1,
            1,
            1,
        ),
        Err(DeepSeekChatCompletionsProviderError::TimeoutOutOfRange)
    );
    assert_eq!(
        DeepSeekChatCompletionsProviderConfigV1::try_new(
            reference,
            DeepSeekChatModelV1::V4Flash,
            1,
            MAX_DEEPSEEK_CHAT_COMPLETIONS_OUTPUT_TOKENS + 1,
            1,
            1,
        ),
        Err(DeepSeekChatCompletionsProviderError::OutputTokenLimitOutOfRange)
    );
    assert_eq!(
        DeepSeekChatCompletionsProviderConfigV1::try_new(
            reference,
            DeepSeekChatModelV1::V4Flash,
            1,
            1,
            MAX_DEEPSEEK_CHAT_COMPLETIONS_HTTP_BODY_BYTES + 1,
            1,
        ),
        Err(DeepSeekChatCompletionsProviderError::ResponseLimitOutOfRange)
    );
    assert_eq!(
        DeepSeekChatCompletionsProviderConfigV1::try_new(
            reference,
            DeepSeekChatModelV1::V4Flash,
            1,
            1,
            8,
            9,
        ),
        Err(DeepSeekChatCompletionsProviderError::OutputLimitOutOfRange)
    );

    let flash = DeepSeekChatCompletionsProviderConfigV1::try_new(
        reference,
        DeepSeekChatModelV1::V4Flash,
        1_000_000_000,
        128,
        4_096,
        1_024,
    )
    .expect("DeepSeek V4 Flash test config must be valid");
    let pro = DeepSeekChatCompletionsProviderConfigV1::try_new(
        reference,
        DeepSeekChatModelV1::V4Pro,
        1_000_000_000,
        128,
        4_096,
        1_024,
    )
    .expect("DeepSeek V4 Pro test config must be valid");
    assert_ne!(flash.config_digest(), pro.config_digest());
}

#[tokio::test]
async fn deepseek_loopback_contract_is_exact_and_returns_bounded_content() {
    let response = json!({
        "id": "test-completion",
        "choices": [{
            "finish_reason": "stop",
            "index": 0,
            "message": {"content": "hello DeepSeek", "role": "assistant"}
        }],
        "created": 1,
        "model": "deepseek-v4-pro",
        "object": "chat.completion"
    });
    let server = TestServer::spawn_deepseek(
        "200 OK",
        serde_json::to_vec(&response).expect("test response must serialize"),
        Duration::ZERO,
        false,
    )
    .await;
    let factory = deepseek_loopback_factory(&server.endpoint, 1_000_000_000, 8_192, 1_024);
    let backend = factory.build().expect("DeepSeek backend must build");
    let (request, cancellation) = request_and_cancellation(1_000_000_000, "hello provider");
    assert_eq!(
        backend.invoke(request, cancellation).await,
        ModelInvocationOutcomeV1::Success("hello DeepSeek".into())
    );

    let (calls, requests) = server.join().await;
    assert_eq!(calls, 1);
    let request = String::from_utf8(requests[0].clone()).expect("request must be UTF-8");
    assert!(request.starts_with("POST /chat/completions HTTP/1.1\r\n"));
    assert!(request.contains("authorization: Bearer test-deepseek-secret-api-key\r\n"));
    let body: Value = serde_json::from_str(
        request
            .split_once("\r\n\r\n")
            .expect("request must contain a body")
            .1,
    )
    .expect("request body must be JSON");
    assert_eq!(
        body,
        json!({
            "model": "deepseek-v4-pro",
            "messages": [{"role": "user", "content": "hello provider"}],
            "max_tokens": 128,
            "thinking": {"type": "disabled"},
            "stream": false
        })
    );
}

#[tokio::test]
async fn deepseek_malformed_truncated_or_oversized_success_fails_closed() {
    for response_body in [
        br#"{"object":"chat.completion","model":"deepseek-v4-pro","choices":[]}"#.to_vec(),
        br#"{"object":"chat.completion","model":"deepseek-v4-pro","choices":[{"index":0,"finish_reason":"length","message":{"role":"assistant","content":"partial"}}]}"#.to_vec(),
        br#"{"object":"chat.completion","model":"deepseek-v4-pro","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"answer","reasoning_content":"unexpected"}}]}"#.to_vec(),
        br#"{"object":"chat.completion","model":"deepseek-v4-flash","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"wrong model"}}]}"#.to_vec(),
        br#"{"object":"chat.completion","model":"deepseek-v4-pro","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"tool output","tool_calls":[]}}]}"#.to_vec(),
        vec![b' '; 512],
    ] {
        let server = TestServer::spawn_deepseek(
            "200 OK",
            response_body,
            Duration::ZERO,
            false,
        )
        .await;
        let factory = deepseek_loopback_factory(&server.endpoint, 1_000_000_000, 256, 64);
        let backend = factory.build().expect("DeepSeek backend must build");
        let (request, cancellation) = request_and_cancellation(1_000_000_000, "bounded response");
        assert_eq!(
            backend.invoke(request, cancellation).await,
            ModelInvocationOutcomeV1::Failed
        );
        assert_eq!(server.join().await.0, 1);
    }
}

#[tokio::test]
async fn deepseek_non_success_is_failed_and_never_retried() {
    let server = TestServer::spawn_deepseek(
        "429 Too Many Requests",
        br#"{"error":{"message":"rate limited"}}"#.to_vec(),
        Duration::ZERO,
        true,
    )
    .await;
    let factory = deepseek_loopback_factory(&server.endpoint, 1_000_000_000, 4_096, 1_024);
    let backend = factory.build().expect("DeepSeek backend must build");
    let (request, cancellation) = request_and_cancellation(1_000_000_000, "one attempt");
    assert_eq!(
        backend.invoke(request, cancellation).await,
        ModelInvocationOutcomeV1::Failed
    );
    assert_eq!(server.join().await.0, 1);
}

async fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 2_048];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .expect("test request read must succeed");
        assert!(read > 0, "test request closed before its body was complete");
        request.extend_from_slice(&buffer[..read]);
        assert!(
            request.len() <= 256 * 1024,
            "test request exceeded its harness bound"
        );
        if let Some(header_end) = find_bytes(&request, b"\r\n\r\n") {
            let header_end = header_end + 4;
            let headers = std::str::from_utf8(&request[..header_end])
                .expect("test request headers must be UTF-8");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .expect("test request must have Content-Length");
            if request.len() >= header_end + content_length {
                request.truncate(header_end + content_length);
                return request;
            }
        }
    }
}

async fn write_http_response(stream: &mut TcpStream, status: &str, body: &[u8]) {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(headers.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.shutdown().await;
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}
