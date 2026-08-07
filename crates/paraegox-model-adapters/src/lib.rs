//! Provisioned HTTP model adapters for bounded text model calls.
//!
//! This crate owns provider-specific HTTP, response parsing, bounded buffers,
//! and resolved API-key use. It does not read environment variables, interpret
//! Runtime provider selections, retry a request, or own Agent or ModelService
//! state. Production construction always targets a compiled-in official HTTPS
//! endpoint; arbitrary endpoints exist only inside loopback contract tests.

use core::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_model::{
    BOUNDED_TEXT_MODEL_CAPABILITY_ID_V1, MAX_MODEL_INVOCATION_DEADLINE_NANOS,
    MAX_MODEL_INVOCATION_OUTPUT_BYTES, ModelAdapterBuildErrorV1, ModelAdapterDescriptorV1,
    ModelAdapterFactoryV1, ModelAdapterIdV1, ModelAdapterMetadataV1, ModelAdapterVersionV1,
    ModelBackendFuture, ModelBackendIdentityErrorV1, ModelBackendIdentityV1, ModelBackendV1,
    ModelCancellationViewV1, ModelCapabilityIdV1, ModelInvocationOutcomeV1,
    ModelInvocationRequestV1,
};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde_json::{Value, json};
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

const OPENAI_CONFIG_DIGEST_DOMAIN: &[u8] = b"paraegox.model.openai.responses.config.sha256.v1";
const DEEPSEEK_CONFIG_DIGEST_DOMAIN: &[u8] =
    b"paraegox.model.deepseek.chat-completions.config.sha256.v1";
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Exact version of the provisioned OpenAI Responses provider configuration.
pub const OPENAI_RESPONSES_PROVIDER_CONFIG_VERSION: u16 = 1;
/// Fixed compiled-in implementation identity for the OpenAI Responses adapter.
pub const OPENAI_RESPONSES_ADAPTER_ID_V1: ModelAdapterIdV1 =
    match ModelAdapterIdV1::try_from_bytes(*b"px-openai-rsp-v1") {
        Ok(adapter_id) => adapter_id,
        Err(_) => panic!("fixed OpenAI adapter identity must be nonzero"),
    };
/// Fixed implementation version for the OpenAI Responses adapter.
pub const OPENAI_RESPONSES_ADAPTER_VERSION_V1: ModelAdapterVersionV1 =
    match ModelAdapterVersionV1::try_new(1) {
        Ok(version) => version,
        Err(_) => panic!("fixed OpenAI adapter version must be nonzero"),
    };
/// Exact provider-neutral capability implemented by this adapter.
pub const OPENAI_RESPONSES_ADAPTER_CAPABILITY_ID_V1: ModelCapabilityIdV1 =
    BOUNDED_TEXT_MODEL_CAPABILITY_ID_V1;
/// Complete compiled-in identity of the OpenAI Responses bounded-text adapter.
pub const OPENAI_RESPONSES_ADAPTER_DESCRIPTOR_V1: ModelAdapterDescriptorV1 =
    ModelAdapterDescriptorV1::new(
        OPENAI_RESPONSES_ADAPTER_ID_V1,
        OPENAI_RESPONSES_ADAPTER_VERSION_V1,
        OPENAI_RESPONSES_ADAPTER_CAPABILITY_ID_V1,
    );
/// The only production endpoint this adapter can target.
pub const OPENAI_RESPONSES_API_ENDPOINT: &str = "https://api.openai.com/v1/responses";
/// Maximum UTF-8 bytes in one explicitly provisioned OpenAI model identifier.
pub const MAX_OPENAI_RESPONSES_MODEL_BYTES: usize = 256;
/// Maximum bytes accepted from a Secret resolver for one API key.
pub const MAX_OPENAI_API_KEY_BYTES: usize = 8 * 1024;
/// Maximum serialized JSON request body retained for one call.
pub const MAX_OPENAI_RESPONSES_REQUEST_BYTES: usize = 128 * 1024;
/// Hard provisioning ceiling for generated output tokens, including reasoning tokens.
pub const MAX_OPENAI_RESPONSES_OUTPUT_TOKENS: u32 = 32 * 1024;
/// Hard implementation ceiling for one retained HTTP response body.
pub const MAX_OPENAI_RESPONSES_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Maximum provider timeout; the protocol request may impose a smaller budget.
pub const MAX_OPENAI_RESPONSES_TIMEOUT_NANOS: u64 = MAX_MODEL_INVOCATION_DEADLINE_NANOS;

/// Exact version of the provisioned DeepSeek Chat Completions configuration.
pub const DEEPSEEK_CHAT_COMPLETIONS_PROVIDER_CONFIG_VERSION: u16 = 1;
/// Fixed compiled-in identity for the DeepSeek Chat Completions adapter.
pub const DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_ID_V1: ModelAdapterIdV1 =
    match ModelAdapterIdV1::try_from_bytes(*b"px-deepseek-ccv1") {
        Ok(adapter_id) => adapter_id,
        Err(_) => panic!("fixed DeepSeek adapter identity must be nonzero"),
    };
/// Fixed implementation version for the DeepSeek Chat Completions adapter.
pub const DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_VERSION_V1: ModelAdapterVersionV1 =
    match ModelAdapterVersionV1::try_new(1) {
        Ok(version) => version,
        Err(_) => panic!("fixed DeepSeek adapter version must be nonzero"),
    };
/// Exact provider-neutral capability implemented by this adapter.
pub const DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_CAPABILITY_ID_V1: ModelCapabilityIdV1 =
    BOUNDED_TEXT_MODEL_CAPABILITY_ID_V1;
/// Complete compiled-in identity of the DeepSeek bounded-text adapter.
pub const DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_DESCRIPTOR_V1: ModelAdapterDescriptorV1 =
    ModelAdapterDescriptorV1::new(
        DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_ID_V1,
        DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_VERSION_V1,
        DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_CAPABILITY_ID_V1,
    );
/// The only production DeepSeek API base URL admitted by this adapter.
pub const DEEPSEEK_API_BASE_URL: &str = "https://api.deepseek.com";
/// The only complete production endpoint this adapter can target.
pub const DEEPSEEK_CHAT_COMPLETIONS_API_ENDPOINT: &str =
    "https://api.deepseek.com/chat/completions";
/// Maximum bytes accepted from a Secret resolver for one DeepSeek API key.
pub const MAX_DEEPSEEK_API_KEY_BYTES: usize = 8 * 1024;
/// Maximum serialized JSON request body retained for one DeepSeek call.
pub const MAX_DEEPSEEK_CHAT_COMPLETIONS_REQUEST_BYTES: usize = 128 * 1024;
/// Hard provisioning ceiling for generated DeepSeek output tokens.
pub const MAX_DEEPSEEK_CHAT_COMPLETIONS_OUTPUT_TOKENS: u32 = 32 * 1024;
/// Hard implementation ceiling for one retained DeepSeek HTTP response body.
pub const MAX_DEEPSEEK_CHAT_COMPLETIONS_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Maximum DeepSeek provider timeout; a request may impose a smaller budget.
pub const MAX_DEEPSEEK_CHAT_COMPLETIONS_TIMEOUT_NANOS: u64 = MAX_MODEL_INVOCATION_DEADLINE_NANOS;

/// Immutable, digest-bound provisioning configuration for one OpenAI provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiResponsesProviderConfigV1 {
    backend_identity: ModelBackendIdentityV1,
    model: Box<str>,
    timeout_nanos: u64,
    max_output_tokens: u32,
    max_response_body_bytes: usize,
    max_output_text_bytes: usize,
}

impl OpenAiResponsesProviderConfigV1 {
    /// Constructs a bounded configuration and its canonical commitment.
    pub fn try_new(
        provider_ref: [u8; 16],
        model: &str,
        timeout_nanos: u64,
        max_output_tokens: u32,
        max_response_body_bytes: usize,
        max_output_text_bytes: usize,
    ) -> Result<Self, OpenAiResponsesProviderError> {
        validate_model(model)?;
        if timeout_nanos == 0 || timeout_nanos > MAX_OPENAI_RESPONSES_TIMEOUT_NANOS {
            return Err(OpenAiResponsesProviderError::TimeoutOutOfRange);
        }
        if max_output_tokens == 0 || max_output_tokens > MAX_OPENAI_RESPONSES_OUTPUT_TOKENS {
            return Err(OpenAiResponsesProviderError::OutputTokenLimitOutOfRange);
        }
        if max_response_body_bytes == 0
            || max_response_body_bytes > MAX_OPENAI_RESPONSES_HTTP_BODY_BYTES
        {
            return Err(OpenAiResponsesProviderError::ResponseLimitOutOfRange);
        }
        if max_output_text_bytes == 0
            || max_output_text_bytes > MAX_MODEL_INVOCATION_OUTPUT_BYTES
            || max_output_text_bytes > max_response_body_bytes
        {
            return Err(OpenAiResponsesProviderError::OutputLimitOutOfRange);
        }

        let config_digest = openai_config_digest(
            provider_ref,
            model,
            timeout_nanos,
            max_output_tokens,
            max_response_body_bytes,
            max_output_text_bytes,
        )?;
        let backend_identity = ModelBackendIdentityV1::try_new(provider_ref, config_digest)?;
        Ok(Self {
            backend_identity,
            model: model.into(),
            timeout_nanos,
            max_output_tokens,
            max_response_body_bytes,
            max_output_text_bytes,
        })
    }

    #[must_use]
    pub const fn provider_ref(&self) -> &[u8; 16] {
        self.backend_identity.provider_ref()
    }

    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    #[must_use]
    pub const fn timeout_nanos(&self) -> u64 {
        self.timeout_nanos
    }

    #[must_use]
    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    #[must_use]
    pub const fn max_response_body_bytes(&self) -> usize {
        self.max_response_body_bytes
    }

    #[must_use]
    pub const fn max_output_text_bytes(&self) -> usize {
        self.max_output_text_bytes
    }

    /// Exact digest that a composition owner may commit into its selection.
    #[must_use]
    pub const fn config_digest(&self) -> Digest32 {
        self.backend_identity.config_digest()
    }
}

/// The complete set of DeepSeek models admitted by this adapter version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeepSeekChatModelV1 {
    /// DeepSeek V4 Flash.
    V4Flash,
    /// DeepSeek V4 Pro.
    V4Pro,
}

impl DeepSeekChatModelV1 {
    /// Parses only an exact current DeepSeek V4 model identifier.
    pub fn try_from_id(model: &str) -> Result<Self, DeepSeekChatCompletionsProviderError> {
        match model {
            "deepseek-v4-flash" => Ok(Self::V4Flash),
            "deepseek-v4-pro" => Ok(Self::V4Pro),
            _ => Err(DeepSeekChatCompletionsProviderError::InvalidModel),
        }
    }

    /// Returns the exact provider model identifier committed by the config.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V4Flash => "deepseek-v4-flash",
            Self::V4Pro => "deepseek-v4-pro",
        }
    }
}

/// Immutable, digest-bound provisioning configuration for one DeepSeek backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeepSeekChatCompletionsProviderConfigV1 {
    backend_identity: ModelBackendIdentityV1,
    model: DeepSeekChatModelV1,
    timeout_nanos: u64,
    max_output_tokens: u32,
    max_response_body_bytes: usize,
    max_output_text_bytes: usize,
}

impl DeepSeekChatCompletionsProviderConfigV1 {
    /// Constructs a bounded config fixed to non-streaming, non-thinking chat.
    pub fn try_new(
        provider_ref: [u8; 16],
        model: DeepSeekChatModelV1,
        timeout_nanos: u64,
        max_output_tokens: u32,
        max_response_body_bytes: usize,
        max_output_text_bytes: usize,
    ) -> Result<Self, DeepSeekChatCompletionsProviderError> {
        if timeout_nanos == 0 || timeout_nanos > MAX_DEEPSEEK_CHAT_COMPLETIONS_TIMEOUT_NANOS {
            return Err(DeepSeekChatCompletionsProviderError::TimeoutOutOfRange);
        }
        if max_output_tokens == 0 || max_output_tokens > MAX_DEEPSEEK_CHAT_COMPLETIONS_OUTPUT_TOKENS
        {
            return Err(DeepSeekChatCompletionsProviderError::OutputTokenLimitOutOfRange);
        }
        if max_response_body_bytes == 0
            || max_response_body_bytes > MAX_DEEPSEEK_CHAT_COMPLETIONS_HTTP_BODY_BYTES
        {
            return Err(DeepSeekChatCompletionsProviderError::ResponseLimitOutOfRange);
        }
        if max_output_text_bytes == 0
            || max_output_text_bytes > MAX_MODEL_INVOCATION_OUTPUT_BYTES
            || max_output_text_bytes > max_response_body_bytes
        {
            return Err(DeepSeekChatCompletionsProviderError::OutputLimitOutOfRange);
        }

        let config_digest = deepseek_config_digest(
            provider_ref,
            model,
            timeout_nanos,
            max_output_tokens,
            max_response_body_bytes,
            max_output_text_bytes,
        )?;
        let backend_identity = ModelBackendIdentityV1::try_new(provider_ref, config_digest)?;
        Ok(Self {
            backend_identity,
            model,
            timeout_nanos,
            max_output_tokens,
            max_response_body_bytes,
            max_output_text_bytes,
        })
    }

    #[must_use]
    pub const fn provider_ref(&self) -> &[u8; 16] {
        self.backend_identity.provider_ref()
    }

    #[must_use]
    pub const fn model(&self) -> DeepSeekChatModelV1 {
        self.model
    }

    #[must_use]
    pub const fn timeout_nanos(&self) -> u64 {
        self.timeout_nanos
    }

    #[must_use]
    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    #[must_use]
    pub const fn max_response_body_bytes(&self) -> usize {
        self.max_response_body_bytes
    }

    #[must_use]
    pub const fn max_output_text_bytes(&self) -> usize {
        self.max_output_text_bytes
    }

    /// Exact non-secret config digest committed into provider selection.
    #[must_use]
    pub const fn config_digest(&self) -> Digest32 {
        self.backend_identity.config_digest()
    }
}

/// One externally resolved OpenAI API key.
///
/// The key is never exposed by a getter or `Debug` and is zeroized on final drop.
pub struct OpenAiResolvedApiKeyV1 {
    api_key: ResolvedBearerApiKey,
}

impl OpenAiResolvedApiKeyV1 {
    /// Validates and immediately takes zeroizing ownership of resolver bytes.
    pub fn try_new(api_key: Vec<u8>) -> Result<Self, OpenAiResponsesProviderError> {
        ResolvedBearerApiKey::try_new(api_key, MAX_OPENAI_API_KEY_BYTES)
            .map(|api_key| Self { api_key })
            .ok_or(OpenAiResponsesProviderError::InvalidApiKey)
    }
}

impl fmt::Debug for OpenAiResolvedApiKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAiResolvedApiKeyV1(<redacted>)")
    }
}

/// One externally resolved DeepSeek API key.
///
/// The key is never exposed by a getter or `Debug` and is zeroized on final drop.
pub struct DeepSeekResolvedApiKeyV1 {
    api_key: ResolvedBearerApiKey,
}

impl DeepSeekResolvedApiKeyV1 {
    /// Validates and immediately takes zeroizing ownership of resolver bytes.
    pub fn try_new(api_key: Vec<u8>) -> Result<Self, DeepSeekChatCompletionsProviderError> {
        ResolvedBearerApiKey::try_new(api_key, MAX_DEEPSEEK_API_KEY_BYTES)
            .map(|api_key| Self { api_key })
            .ok_or(DeepSeekChatCompletionsProviderError::InvalidApiKey)
    }
}

impl fmt::Debug for DeepSeekResolvedApiKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeepSeekResolvedApiKeyV1(<redacted>)")
    }
}

struct ResolvedBearerApiKey {
    bytes: Zeroizing<Vec<u8>>,
}

impl ResolvedBearerApiKey {
    fn try_new(bytes: Vec<u8>, max_bytes: usize) -> Option<Self> {
        let bytes = Zeroizing::new(bytes);
        (!bytes.is_empty()
            && bytes.len() <= max_bytes
            && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte)))
        .then_some(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Repeatable factory for one exact provider configuration and resolved key.
///
/// Runtime selection validation belongs to the composition owner before this
/// provider-specific factory is entered.
pub struct OpenAiResponsesProviderFactoryV1 {
    config: OpenAiResponsesProviderConfigV1,
    api_key: Arc<OpenAiResolvedApiKeyV1>,
    endpoint: ProviderEndpoint,
}

impl OpenAiResponsesProviderFactoryV1 {
    /// Creates a production factory fixed to the official OpenAI HTTPS endpoint.
    pub fn new(config: OpenAiResponsesProviderConfigV1, api_key: OpenAiResolvedApiKeyV1) -> Self {
        Self {
            config,
            api_key: Arc::new(api_key),
            endpoint: ProviderEndpoint::Production(ProductionEndpoint::OpenAiResponses),
        }
    }

    #[must_use]
    pub const fn config(&self) -> &OpenAiResponsesProviderConfigV1 {
        &self.config
    }

    /// Creates a fresh backend for the factory's exact immutable configuration.
    pub fn build(&self) -> Result<OpenAiResponsesModelBackendV1, OpenAiResponsesProviderError> {
        let client = build_http_client(
            self.config.timeout_nanos,
            self.endpoint.is_production(),
            OpenAiResponsesProviderError::HttpClientConfiguration,
        )?;
        Ok(OpenAiResponsesModelBackendV1 {
            client,
            config: self.config.clone(),
            api_key: Arc::clone(&self.api_key),
            endpoint: self.endpoint.clone(),
            identity: self.config.backend_identity,
        })
    }

    #[cfg(test)]
    fn try_new_for_loopback(
        config: OpenAiResponsesProviderConfigV1,
        api_key: OpenAiResolvedApiKeyV1,
        endpoint: &str,
    ) -> Result<Self, OpenAiResponsesProviderError> {
        if !is_exact_loopback_endpoint(endpoint, "/v1/responses") {
            return Err(OpenAiResponsesProviderError::InvalidEndpoint);
        }
        Ok(Self {
            config,
            api_key: Arc::new(api_key),
            endpoint: ProviderEndpoint::Loopback(endpoint.into()),
        })
    }
}

impl fmt::Debug for OpenAiResponsesProviderFactoryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiResponsesProviderFactoryV1")
            .field("config", &self.config)
            .field("api_key", &"[REDACTED]")
            .field("endpoint", &self.endpoint.label())
            .finish()
    }
}

impl ModelAdapterFactoryV1 for OpenAiResponsesProviderFactoryV1 {
    fn metadata(&self) -> ModelAdapterMetadataV1 {
        ModelAdapterMetadataV1::new(
            OPENAI_RESPONSES_ADAPTER_DESCRIPTOR_V1,
            self.config.backend_identity,
        )
    }

    fn build(&self) -> Result<Arc<dyn ModelBackendV1>, ModelAdapterBuildErrorV1> {
        OpenAiResponsesProviderFactoryV1::build(self)
            .map(|backend| Arc::new(backend) as Arc<dyn ModelBackendV1>)
            .map_err(|_| ModelAdapterBuildErrorV1::Rejected)
    }
}

/// One no-retry OpenAI Responses backend instance.
pub struct OpenAiResponsesModelBackendV1 {
    client: reqwest::Client,
    config: OpenAiResponsesProviderConfigV1,
    api_key: Arc<OpenAiResolvedApiKeyV1>,
    endpoint: ProviderEndpoint,
    identity: ModelBackendIdentityV1,
}

impl fmt::Debug for OpenAiResponsesModelBackendV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiResponsesModelBackendV1")
            .field("config", &self.config)
            .field("api_key", &"[REDACTED]")
            .field("endpoint", &self.endpoint.label())
            .finish_non_exhaustive()
    }
}

impl ModelBackendV1 for OpenAiResponsesModelBackendV1 {
    fn identity(&self) -> ModelBackendIdentityV1 {
        self.identity
    }

    fn invoke(
        &self,
        request: ModelInvocationRequestV1,
        cancellation: ModelCancellationViewV1,
    ) -> ModelBackendFuture {
        let client = self.client.clone();
        let config = self.config.clone();
        let api_key = Arc::clone(&self.api_key);
        let endpoint = self.endpoint.clone();
        Box::pin(async move {
            if cancellation.is_cancellation_requested() {
                return ModelInvocationOutcomeV1::CancelledBeforeHandoff;
            }

            let timeout_nanos = config.timeout_nanos.min(request.deadline_budget().value());
            let timeout = Duration::from_nanos(timeout_nanos);
            let invocation = invoke_openai_once(client, endpoint, config, api_key, request);
            arbitrate_invocation(invocation, timeout, cancellation).await
        })
    }
}

/// Repeatable factory for one exact DeepSeek configuration and resolved key.
pub struct DeepSeekChatCompletionsProviderFactoryV1 {
    config: DeepSeekChatCompletionsProviderConfigV1,
    api_key: Arc<DeepSeekResolvedApiKeyV1>,
    endpoint: ProviderEndpoint,
}

impl DeepSeekChatCompletionsProviderFactoryV1 {
    /// Creates a production factory fixed to the official DeepSeek HTTPS endpoint.
    pub fn new(
        config: DeepSeekChatCompletionsProviderConfigV1,
        api_key: DeepSeekResolvedApiKeyV1,
    ) -> Self {
        Self {
            config,
            api_key: Arc::new(api_key),
            endpoint: ProviderEndpoint::Production(ProductionEndpoint::DeepSeekChatCompletions),
        }
    }

    #[must_use]
    pub const fn config(&self) -> &DeepSeekChatCompletionsProviderConfigV1 {
        &self.config
    }

    /// Creates a fresh backend for the exact immutable configuration.
    pub fn build(
        &self,
    ) -> Result<DeepSeekChatCompletionsModelBackendV1, DeepSeekChatCompletionsProviderError> {
        let client = build_http_client(
            self.config.timeout_nanos,
            self.endpoint.is_production(),
            DeepSeekChatCompletionsProviderError::HttpClientConfiguration,
        )?;
        Ok(DeepSeekChatCompletionsModelBackendV1 {
            client,
            config: self.config.clone(),
            api_key: Arc::clone(&self.api_key),
            endpoint: self.endpoint.clone(),
            identity: self.config.backend_identity,
        })
    }

    #[cfg(test)]
    fn try_new_for_loopback(
        config: DeepSeekChatCompletionsProviderConfigV1,
        api_key: DeepSeekResolvedApiKeyV1,
        endpoint: &str,
    ) -> Result<Self, DeepSeekChatCompletionsProviderError> {
        if !is_exact_loopback_endpoint(endpoint, "/chat/completions") {
            return Err(DeepSeekChatCompletionsProviderError::InvalidEndpoint);
        }
        Ok(Self {
            config,
            api_key: Arc::new(api_key),
            endpoint: ProviderEndpoint::Loopback(endpoint.into()),
        })
    }
}

impl fmt::Debug for DeepSeekChatCompletionsProviderFactoryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeepSeekChatCompletionsProviderFactoryV1")
            .field("config", &self.config)
            .field("api_key", &"[REDACTED]")
            .field("endpoint", &self.endpoint.label())
            .finish()
    }
}

impl ModelAdapterFactoryV1 for DeepSeekChatCompletionsProviderFactoryV1 {
    fn metadata(&self) -> ModelAdapterMetadataV1 {
        ModelAdapterMetadataV1::new(
            DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_DESCRIPTOR_V1,
            self.config.backend_identity,
        )
    }

    fn build(&self) -> Result<Arc<dyn ModelBackendV1>, ModelAdapterBuildErrorV1> {
        DeepSeekChatCompletionsProviderFactoryV1::build(self)
            .map(|backend| Arc::new(backend) as Arc<dyn ModelBackendV1>)
            .map_err(|_| ModelAdapterBuildErrorV1::Rejected)
    }
}

/// One no-retry DeepSeek Chat Completions backend instance.
pub struct DeepSeekChatCompletionsModelBackendV1 {
    client: reqwest::Client,
    config: DeepSeekChatCompletionsProviderConfigV1,
    api_key: Arc<DeepSeekResolvedApiKeyV1>,
    endpoint: ProviderEndpoint,
    identity: ModelBackendIdentityV1,
}

impl fmt::Debug for DeepSeekChatCompletionsModelBackendV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeepSeekChatCompletionsModelBackendV1")
            .field("config", &self.config)
            .field("api_key", &"[REDACTED]")
            .field("endpoint", &self.endpoint.label())
            .finish_non_exhaustive()
    }
}

impl ModelBackendV1 for DeepSeekChatCompletionsModelBackendV1 {
    fn identity(&self) -> ModelBackendIdentityV1 {
        self.identity
    }

    fn invoke(
        &self,
        request: ModelInvocationRequestV1,
        cancellation: ModelCancellationViewV1,
    ) -> ModelBackendFuture {
        let client = self.client.clone();
        let config = self.config.clone();
        let api_key = Arc::clone(&self.api_key);
        let endpoint = self.endpoint.clone();
        Box::pin(async move {
            if cancellation.is_cancellation_requested() {
                return ModelInvocationOutcomeV1::CancelledBeforeHandoff;
            }

            let timeout_nanos = config.timeout_nanos.min(request.deadline_budget().value());
            let timeout = Duration::from_nanos(timeout_nanos);
            let invocation = invoke_deepseek_once(client, endpoint, config, api_key, request);
            arbitrate_invocation(invocation, timeout, cancellation).await
        })
    }
}

/// Stable DeepSeek construction failures that retain no response or Secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeepSeekChatCompletionsProviderError {
    InvalidModel,
    TimeoutOutOfRange,
    OutputTokenLimitOutOfRange,
    ResponseLimitOutOfRange,
    OutputLimitOutOfRange,
    InvalidApiKey,
    InvalidEndpoint,
    HttpClientConfiguration,
    BackendIdentity(ModelBackendIdentityErrorV1),
    Digest(DigestBuildError),
}

impl fmt::Display for DeepSeekChatCompletionsProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidModel => "DeepSeek model identifier is invalid",
            Self::TimeoutOutOfRange => "DeepSeek provider timeout is out of range",
            Self::OutputTokenLimitOutOfRange => {
                "DeepSeek provider output-token limit is out of range"
            }
            Self::ResponseLimitOutOfRange => "DeepSeek HTTP response limit is out of range",
            Self::OutputLimitOutOfRange => "DeepSeek output text limit is out of range",
            Self::InvalidApiKey => "resolved DeepSeek API key is invalid",
            Self::InvalidEndpoint => "DeepSeek provider endpoint is invalid",
            Self::HttpClientConfiguration => "DeepSeek HTTP client configuration failed",
            Self::BackendIdentity(_) => "DeepSeek backend identity is invalid",
            Self::Digest(_) => "DeepSeek provider configuration digest failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DeepSeekChatCompletionsProviderError {}

impl From<DigestBuildError> for DeepSeekChatCompletionsProviderError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

impl From<ModelBackendIdentityErrorV1> for DeepSeekChatCompletionsProviderError {
    fn from(error: ModelBackendIdentityErrorV1) -> Self {
        Self::BackendIdentity(error)
    }
}

/// Stable construction failures that never retain provider response or Secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenAiResponsesProviderError {
    InvalidModel,
    TimeoutOutOfRange,
    OutputTokenLimitOutOfRange,
    ResponseLimitOutOfRange,
    OutputLimitOutOfRange,
    InvalidApiKey,
    InvalidEndpoint,
    HttpClientConfiguration,
    BackendIdentity(ModelBackendIdentityErrorV1),
    Digest(DigestBuildError),
}

impl fmt::Display for OpenAiResponsesProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidModel => "OpenAI model identifier is invalid",
            Self::TimeoutOutOfRange => "OpenAI provider timeout is out of range",
            Self::OutputTokenLimitOutOfRange => {
                "OpenAI provider output-token limit is out of range"
            }
            Self::ResponseLimitOutOfRange => "OpenAI HTTP response limit is out of range",
            Self::OutputLimitOutOfRange => "OpenAI output text limit is out of range",
            Self::InvalidApiKey => "resolved OpenAI API key is invalid",
            Self::InvalidEndpoint => "OpenAI provider endpoint is invalid",
            Self::HttpClientConfiguration => "OpenAI HTTP client configuration failed",
            Self::BackendIdentity(_) => "OpenAI backend identity is invalid",
            Self::Digest(_) => "OpenAI provider configuration digest failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OpenAiResponsesProviderError {}

impl From<DigestBuildError> for OpenAiResponsesProviderError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

impl From<ModelBackendIdentityErrorV1> for OpenAiResponsesProviderError {
    fn from(error: ModelBackendIdentityErrorV1) -> Self {
        Self::BackendIdentity(error)
    }
}

#[derive(Clone)]
enum ProviderEndpoint {
    Production(ProductionEndpoint),
    #[cfg(test)]
    Loopback(Box<str>),
}

#[derive(Clone, Copy)]
enum ProductionEndpoint {
    OpenAiResponses,
    DeepSeekChatCompletions,
}

impl ProviderEndpoint {
    fn url(&self) -> &str {
        match self {
            Self::Production(ProductionEndpoint::OpenAiResponses) => OPENAI_RESPONSES_API_ENDPOINT,
            Self::Production(ProductionEndpoint::DeepSeekChatCompletions) => {
                DEEPSEEK_CHAT_COMPLETIONS_API_ENDPOINT
            }
            #[cfg(test)]
            Self::Loopback(endpoint) => endpoint,
        }
    }

    const fn label(&self) -> &str {
        match self {
            Self::Production(ProductionEndpoint::OpenAiResponses) => "official-openai-https",
            Self::Production(ProductionEndpoint::DeepSeekChatCompletions) => {
                "official-deepseek-https"
            }
            #[cfg(test)]
            Self::Loopback(_) => "test-loopback-http",
        }
    }

    const fn is_production(&self) -> bool {
        matches!(self, Self::Production(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvocationFailure {
    Definitive,
    DeadlineExceeded,
    TransportUncertain,
}

fn validate_model(model: &str) -> Result<(), OpenAiResponsesProviderError> {
    if model.is_empty()
        || model.len() > MAX_OPENAI_RESPONSES_MODEL_BYTES
        || !model.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(OpenAiResponsesProviderError::InvalidModel);
    }
    Ok(())
}

fn openai_config_digest(
    provider_ref: [u8; 16],
    model: &str,
    timeout_nanos: u64,
    max_output_tokens: u32,
    max_response_body_bytes: usize,
    max_output_text_bytes: usize,
) -> Result<Digest32, OpenAiResponsesProviderError> {
    let mut builder = Digest32Builder::try_new(OPENAI_CONFIG_DIGEST_DOMAIN)?;
    builder
        .field_u16(OPENAI_RESPONSES_PROVIDER_CONFIG_VERSION)?
        .field_bytes(&provider_ref)?
        .field_bytes(OPENAI_RESPONSES_API_ENDPOINT.as_bytes())?
        .field_bytes(model.as_bytes())?
        .field_u64(timeout_nanos)?
        .field_u64(u64::from(max_output_tokens))?
        .field_u64(max_response_body_bytes as u64)?
        .field_u64(max_output_text_bytes as u64)?;
    Ok(builder.finish())
}

fn deepseek_config_digest(
    provider_ref: [u8; 16],
    model: DeepSeekChatModelV1,
    timeout_nanos: u64,
    max_output_tokens: u32,
    max_response_body_bytes: usize,
    max_output_text_bytes: usize,
) -> Result<Digest32, DeepSeekChatCompletionsProviderError> {
    let mut builder = Digest32Builder::try_new(DEEPSEEK_CONFIG_DIGEST_DOMAIN)?;
    builder
        .field_u16(DEEPSEEK_CHAT_COMPLETIONS_PROVIDER_CONFIG_VERSION)?
        .field_bytes(&provider_ref)?
        .field_bytes(DEEPSEEK_CHAT_COMPLETIONS_API_ENDPOINT.as_bytes())?
        .field_bytes(model.as_str().as_bytes())?
        .field_bytes(b"thinking=disabled")?
        .field_bytes(b"stream=false")?
        .field_u64(timeout_nanos)?
        .field_u64(u64::from(max_output_tokens))?
        .field_u64(max_response_body_bytes as u64)?
        .field_u64(max_output_text_bytes as u64)?;
    Ok(builder.finish())
}

fn build_http_client<E>(
    connect_timeout_nanos: u64,
    production_https_only: bool,
    configuration_error: E,
) -> Result<reqwest::Client, E> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_nanos(connect_timeout_nanos))
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .no_proxy()
        .https_only(production_https_only)
        .build()
        .map_err(|_| configuration_error)
}

#[cfg(test)]
fn is_exact_loopback_endpoint(endpoint: &str, exact_path: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    let is_loopback = parsed
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    parsed.scheme() == "http"
        && is_loopback
        && parsed.port().is_some()
        && parsed.path() == exact_path
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.username().is_empty()
        && parsed.password().is_none()
}

async fn wait_for_cancellation(cancellation: ModelCancellationViewV1) {
    loop {
        if cancellation.is_cancellation_requested() {
            return;
        }
        tokio::time::sleep(CANCELLATION_POLL_INTERVAL).await;
    }
}

async fn arbitrate_invocation<F>(
    invocation: F,
    timeout: Duration,
    cancellation: ModelCancellationViewV1,
) -> ModelInvocationOutcomeV1
where
    F: Future<Output = Result<Box<str>, InvocationFailure>>,
{
    tokio::select! {
        biased;
        result = tokio::time::timeout(timeout, invocation) => {
            match result {
                Err(_) => ModelInvocationOutcomeV1::DeadlineExceeded,
                Ok(Ok(output)) => ModelInvocationOutcomeV1::Success(output),
                Ok(Err(InvocationFailure::Definitive)) => {
                    ModelInvocationOutcomeV1::Failed
                }
                Ok(Err(InvocationFailure::DeadlineExceeded)) => {
                    ModelInvocationOutcomeV1::DeadlineExceeded
                }
                Ok(Err(InvocationFailure::TransportUncertain)) => {
                    ModelInvocationOutcomeV1::OutcomeUncertain
                }
            }
        }
        () = wait_for_cancellation(cancellation) => {
            ModelInvocationOutcomeV1::OutcomeUncertain
        }
    }
}

async fn invoke_openai_once(
    client: reqwest::Client,
    endpoint: ProviderEndpoint,
    config: OpenAiResponsesProviderConfigV1,
    api_key: Arc<OpenAiResolvedApiKeyV1>,
    request: ModelInvocationRequestV1,
) -> Result<Box<str>, InvocationFailure> {
    let request_body = json!({
        "model": config.model(),
        "input": request.prompt(),
        "max_output_tokens": config.max_output_tokens(),
        "store": false,
    });
    let request_body =
        serde_json::to_vec(&request_body).map_err(|_| InvocationFailure::Definitive)?;
    if request_body.len() > MAX_OPENAI_RESPONSES_REQUEST_BYTES {
        return Err(InvocationFailure::Definitive);
    }

    let authorization = bearer_authorization(api_key.api_key.as_bytes())?;

    let response = client
        .post(endpoint.url())
        .header(AUTHORIZATION, authorization)
        .header(CONTENT_TYPE, "application/json")
        .body(request_body)
        .send()
        .await
        .map_err(classify_transport_error)?;

    if !response.status().is_success() {
        return Err(InvocationFailure::Definitive);
    }
    let response_body = read_bounded_response(response, config.max_response_body_bytes).await?;
    parse_openai_output_text(&response_body, config.max_output_text_bytes)
}

async fn invoke_deepseek_once(
    client: reqwest::Client,
    endpoint: ProviderEndpoint,
    config: DeepSeekChatCompletionsProviderConfigV1,
    api_key: Arc<DeepSeekResolvedApiKeyV1>,
    request: ModelInvocationRequestV1,
) -> Result<Box<str>, InvocationFailure> {
    let request_body = json!({
        "model": config.model().as_str(),
        "messages": [{"role": "user", "content": request.prompt()}],
        "max_tokens": config.max_output_tokens(),
        "thinking": {"type": "disabled"},
        "stream": false,
    });
    let request_body =
        serde_json::to_vec(&request_body).map_err(|_| InvocationFailure::Definitive)?;
    if request_body.len() > MAX_DEEPSEEK_CHAT_COMPLETIONS_REQUEST_BYTES {
        return Err(InvocationFailure::Definitive);
    }

    let authorization = bearer_authorization(api_key.api_key.as_bytes())?;
    let response = client
        .post(endpoint.url())
        .header(AUTHORIZATION, authorization)
        .header(CONTENT_TYPE, "application/json")
        .body(request_body)
        .send()
        .await
        .map_err(classify_transport_error)?;

    if !response.status().is_success() {
        return Err(InvocationFailure::Definitive);
    }
    let response_body = read_bounded_response(response, config.max_response_body_bytes).await?;
    parse_deepseek_output_text(&response_body, config.model(), config.max_output_text_bytes)
}

fn bearer_authorization(api_key: &[u8]) -> Result<HeaderValue, InvocationFailure> {
    let mut authorization_bytes = Zeroizing::new(Vec::with_capacity(7 + api_key.len()));
    authorization_bytes.extend_from_slice(b"Bearer ");
    authorization_bytes.extend_from_slice(api_key);
    let mut authorization =
        HeaderValue::from_bytes(&authorization_bytes).map_err(|_| InvocationFailure::Definitive)?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

fn classify_transport_error(error: reqwest::Error) -> InvocationFailure {
    if error.is_timeout() {
        InvocationFailure::DeadlineExceeded
    } else {
        InvocationFailure::TransportUncertain
    }
}

async fn read_bounded_response(
    mut response: reqwest::Response,
    max_response_body_bytes: usize,
) -> Result<Vec<u8>, InvocationFailure> {
    if response
        .content_length()
        .is_some_and(|length| length > max_response_body_bytes as u64)
    {
        return Err(InvocationFailure::Definitive);
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(max_response_body_bytes),
    );
    while let Some(chunk) = response.chunk().await.map_err(classify_transport_error)? {
        let retained = body
            .len()
            .checked_add(chunk.len())
            .ok_or(InvocationFailure::Definitive)?;
        if retained > max_response_body_bytes {
            return Err(InvocationFailure::Definitive);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_openai_output_text(
    response_body: &[u8],
    max_output_text_bytes: usize,
) -> Result<Box<str>, InvocationFailure> {
    let response: Value =
        serde_json::from_slice(response_body).map_err(|_| InvocationFailure::Definitive)?;
    let output = response
        .get("output")
        .and_then(Value::as_array)
        .ok_or(InvocationFailure::Definitive)?;
    let mut text = String::new();
    let mut found_output_text = false;
    for item in output {
        if item.get("type").and_then(Value::as_str) != Some("message") {
            continue;
        }
        let content = item
            .get("content")
            .and_then(Value::as_array)
            .ok_or(InvocationFailure::Definitive)?;
        for part in content {
            if part.get("type").and_then(Value::as_str) != Some("output_text") {
                continue;
            }
            let part_text = part
                .get("text")
                .and_then(Value::as_str)
                .ok_or(InvocationFailure::Definitive)?;
            let retained = text
                .len()
                .checked_add(part_text.len())
                .ok_or(InvocationFailure::Definitive)?;
            if retained > max_output_text_bytes {
                return Err(InvocationFailure::Definitive);
            }
            found_output_text = true;
            text.push_str(part_text);
        }
    }
    if !found_output_text || text.is_empty() {
        return Err(InvocationFailure::Definitive);
    }
    Ok(text.into_boxed_str())
}

fn parse_deepseek_output_text(
    response_body: &[u8],
    expected_model: DeepSeekChatModelV1,
    max_output_text_bytes: usize,
) -> Result<Box<str>, InvocationFailure> {
    let response: Value =
        serde_json::from_slice(response_body).map_err(|_| InvocationFailure::Definitive)?;
    if response.get("object").and_then(Value::as_str) != Some("chat.completion")
        || response.get("model").and_then(Value::as_str) != Some(expected_model.as_str())
    {
        return Err(InvocationFailure::Definitive);
    }
    let choices = response
        .get("choices")
        .and_then(Value::as_array)
        .filter(|choices| choices.len() == 1)
        .ok_or(InvocationFailure::Definitive)?;
    let choice = &choices[0];
    if choice.get("index").and_then(Value::as_u64) != Some(0)
        || choice.get("finish_reason").and_then(Value::as_str) != Some("stop")
    {
        return Err(InvocationFailure::Definitive);
    }
    let message = choice
        .get("message")
        .and_then(Value::as_object)
        .ok_or(InvocationFailure::Definitive)?;
    if message.get("role").and_then(Value::as_str) != Some("assistant")
        || message
            .get("reasoning_content")
            .is_some_and(|value| !value.is_null())
        || message
            .get("tool_calls")
            .is_some_and(|value| !value.is_null())
    {
        return Err(InvocationFailure::Definitive);
    }
    let text = message
        .get("content")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= max_output_text_bytes)
        .ok_or(InvocationFailure::Definitive)?;
    Ok(text.into())
}
