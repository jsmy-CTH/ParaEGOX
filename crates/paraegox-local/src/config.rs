use std::{
    ffi::OsString,
    fmt,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use paraegox_model_adapters::{
    DeepSeekChatCompletionsProviderConfigV1, DeepSeekChatModelV1, MAX_OPENAI_RESPONSES_MODEL_BYTES,
    OpenAiResponsesProviderConfigV1,
};
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DistributedFabricCredentialRefV1, DistributedFabricTlsEndpointV1,
    MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES,
};
use paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentProviderRefV1;
use serde::Deserialize;

const CHAT_COMMAND: &str = "chat";
const CONFIG_OPTION: &str = "--config";
const DETERMINISTIC_ECHO_PROVIDER: &str = "deterministic-echo-v1";
const OPENAI_RESPONSES_PROVIDER: &str = "openai-responses-v1";
const DEEPSEEK_CHAT_COMPLETIONS_PROVIDER: &str = "deepseek-chat-completions-v1";
const OPENAI_SECRET_REF: &str = "env:OPENAI_API_KEY";
const DEEPSEEK_SECRET_REF: &str = "env:DEEPSEEK_API_KEY";
const CHAT_CONFIG_SCHEMA_VERSION: u16 = 1;
const MAX_CHAT_CONFIG_BYTES: u64 = 64 * 1024;
// In-progress two-target composition is intentionally not a public CLI. Keep
// its parser reachable only through the same double-underscore convention as
// the existing process-child implementation modes until the real owner chain
// and its evidence are complete.
const INTERNAL_DISTRIBUTED_FIXTURE_MODE: &str = "__developer-distributed-fixture-v1";
const INTERNAL_DISTRIBUTED_IDENTITY_INIT_MODE: &str = "__developer-distributed-identity-init-v1";
const STATE_ROOT_OPTION: &str = "--state-root";
const FABRIC_LISTEN_A_OPTION: &str = "--fabric-listen-a";
const FABRIC_LISTEN_B_OPTION: &str = "--fabric-listen-b";
const PXRP_TLS_LISTENER_LOCATOR_A_OPTION: &str = "--pxrp-tls-listener-locator-a";
const PXRP_TLS_LISTENER_LOCATOR_B_OPTION: &str = "--pxrp-tls-listener-locator-b";
const PXRP_ROUTE_A_OPTION: &str = "--pxrp-route-a";
const PXRP_ROUTE_B_OPTION: &str = "--pxrp-route-b";
const PXRP_ROOT_CA_CERTIFICATE_FILE_A_OPTION: &str = "--pxrp-root-ca-certificate-file-a";
const PXRP_ROOT_CA_CERTIFICATE_FILE_B_OPTION: &str = "--pxrp-root-ca-certificate-file-b";
const PXRP_CONTROLLER_CLIENT_CERTIFICATE_FILE_A_OPTION: &str =
    "--pxrp-controller-client-certificate-file-a";
const PXRP_CONTROLLER_CLIENT_CERTIFICATE_FILE_B_OPTION: &str =
    "--pxrp-controller-client-certificate-file-b";
const PXRP_CONTROLLER_CLIENT_PRIVATE_KEY_FILE_A_OPTION: &str =
    "--pxrp-controller-client-private-key-file-a";
const PXRP_CONTROLLER_CLIENT_PRIVATE_KEY_FILE_B_OPTION: &str =
    "--pxrp-controller-client-private-key-file-b";
const PXRP_RUNTIME_SERVER_CERTIFICATE_FILE_A_OPTION: &str =
    "--pxrp-runtime-server-certificate-file-a";
const PXRP_RUNTIME_SERVER_CERTIFICATE_FILE_B_OPTION: &str =
    "--pxrp-runtime-server-certificate-file-b";
const PXRP_RUNTIME_SERVER_PRIVATE_KEY_FILE_A_OPTION: &str =
    "--pxrp-runtime-server-private-key-file-a";
const PXRP_RUNTIME_SERVER_PRIVATE_KEY_FILE_B_OPTION: &str =
    "--pxrp-runtime-server-private-key-file-b";
const FABRIC_TLS_LISTENER_LOCATOR_A_OPTION: &str = "--fabric-tls-listener-locator-a";
const FABRIC_TLS_LISTENER_LOCATOR_B_OPTION: &str = "--fabric-tls-listener-locator-b";
const FABRIC_LOCAL_CREDENTIAL_REF_A_OPTION: &str = "--fabric-local-credential-ref-a";
const FABRIC_LOCAL_CREDENTIAL_REF_B_OPTION: &str = "--fabric-local-credential-ref-b";
const FABRIC_EXPECTED_PEER_COMMON_NAME_A_OPTION: &str = "--fabric-expected-peer-common-name-a";
const FABRIC_EXPECTED_PEER_COMMON_NAME_B_OPTION: &str = "--fabric-expected-peer-common-name-b";
const FABRIC_ROOT_CA_CERTIFICATE_FILE_A_OPTION: &str = "--fabric-root-ca-certificate-file-a";
const FABRIC_ROOT_CA_CERTIFICATE_FILE_B_OPTION: &str = "--fabric-root-ca-certificate-file-b";
const FABRIC_LISTEN_CERTIFICATE_FILE_A_OPTION: &str = "--fabric-listen-certificate-file-a";
const FABRIC_LISTEN_CERTIFICATE_FILE_B_OPTION: &str = "--fabric-listen-certificate-file-b";
const FABRIC_LISTEN_PRIVATE_KEY_FILE_A_OPTION: &str = "--fabric-listen-private-key-file-a";
const FABRIC_LISTEN_PRIVATE_KEY_FILE_B_OPTION: &str = "--fabric-listen-private-key-file-b";
const FABRIC_CONNECT_CERTIFICATE_FILE_A_OPTION: &str = "--fabric-connect-certificate-file-a";
const FABRIC_CONNECT_CERTIFICATE_FILE_B_OPTION: &str = "--fabric-connect-certificate-file-b";
const FABRIC_CONNECT_PRIVATE_KEY_FILE_A_OPTION: &str = "--fabric-connect-private-key-file-a";
const FABRIC_CONNECT_PRIVATE_KEY_FILE_B_OPTION: &str = "--fabric-connect-private-key-file-b";
const LOOPBACK_TCP_PREFIX: &str = "tcp/127.0.0.1:";
const MAX_STATE_ROOT_BYTES: usize = 4_096;
const MAX_TLS_FILE_PATH_BYTES: usize = 4_096;
const MAX_EXPERIMENTAL_PEER_COMMON_NAME_BYTES: usize = 253;

const DEVELOPER_REQUEST_DEADLINE_BUDGET: Duration = Duration::from_secs(30);
const DEVELOPER_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const DEVELOPER_COMMAND_CAPACITY: usize = 4;
pub(crate) const DEVELOPER_PROVISIONED_PROVIDER_TIMEOUT_NANOS: u64 = 30_000_000_000;
pub(crate) const DEVELOPER_PROVISIONED_MAX_OUTPUT_TOKENS: u32 = 4_096;
pub(crate) const DEVELOPER_PROVISIONED_MAX_RESPONSE_BODY_BYTES: usize = 256 * 1024;
pub(crate) const DEVELOPER_PROVISIONED_MAX_OUTPUT_TEXT_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Command {
    Help,
    DeveloperFixtureV1(DeveloperFixtureConfigV1),
    DeveloperDistributedFixtureV1(DeveloperDistributedFixtureConfigV1),
    DeveloperProvisionedV1(DeveloperProvisionedConfigV1),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeveloperLocalConfigDocumentV1 {
    schema_version: u16,
    state_root: String,
    fabric_listen: String,
    model: DeveloperLocalModelDocumentV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeveloperLocalModelDocumentV1 {
    provider: String,
    model: Option<String>,
    secret_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeveloperDistributedFixtureConfigV1 {
    state_root: PathBuf,
    fabric_listen_a: FabricLoopbackListenV1,
    fabric_listen_b: FabricLoopbackListenV1,
    targets: Box<[DeveloperDistributedTargetConfigV1; 2]>,
    profile: DeveloperLocalProfileV1,
    action: DeveloperDistributedFixtureActionV1,
}

impl DeveloperDistributedFixtureConfigV1 {
    pub(crate) fn state_root(&self) -> &std::path::Path {
        &self.state_root
    }

    pub(crate) fn fabric_listen_a(&self) -> &str {
        self.fabric_listen_a.as_str()
    }

    pub(crate) fn fabric_listen_b(&self) -> &str {
        self.fabric_listen_b.as_str()
    }

    /// Returns the explicit PXRP and Fabric resolver inputs in the same
    /// canonical target order as the distributed identity and layout owners:
    /// target A first, then target B. In that exact two-target profile, each
    /// Fabric peer connect locator is the other row's explicit listener.
    pub(crate) fn targets(&self) -> &[DeveloperDistributedTargetConfigV1; 2] {
        self.targets.as_ref()
    }

    pub(crate) const fn profile(&self) -> DeveloperLocalProfileV1 {
        self.profile
    }

    pub(crate) const fn action(&self) -> DeveloperDistributedFixtureActionV1 {
        self.action
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeveloperDistributedFixtureActionV1 {
    Run,
    InitializeIdentity,
}

/// One fixed-order target's complete non-secret distributed transport input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeveloperDistributedTargetConfigV1 {
    pxrp: DeveloperDistributedPxrpTargetConfigV1,
    fabric: DeveloperDistributedFabricTargetConfigV1,
}

impl DeveloperDistributedTargetConfigV1 {
    pub(crate) const fn pxrp(&self) -> &DeveloperDistributedPxrpTargetConfigV1 {
        &self.pxrp
    }

    pub(crate) const fn fabric(&self) -> &DeveloperDistributedFabricTargetConfigV1 {
        &self.fabric
    }
}

/// Non-secret, process-local resolution input for one target's canonical PXRP
/// profile and its two role-specific mTLS identities.
///
/// This value carries only the exact locator, route, and normalized file paths.
/// It does not read certificate or private-key bytes, resolve identity refs,
/// discover an endpoint, or construct transport authority. The corresponding
/// trust/profile/credential refs remain owned by the distributed identity
/// manifest and are paired with these values by fixed target order.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DeveloperDistributedPxrpTargetConfigV1 {
    tls_listener_locator: DistributedFabricTlsEndpointV1,
    route: Box<str>,
    root_ca_certificate_file: PathBuf,
    controller_client_certificate_file: PathBuf,
    controller_client_private_key_file: PathBuf,
    runtime_server_certificate_file: PathBuf,
    runtime_server_private_key_file: PathBuf,
}

impl DeveloperDistributedPxrpTargetConfigV1 {
    pub(crate) fn tls_listener_locator(&self) -> &str {
        self.tls_listener_locator.as_str()
    }

    pub(crate) fn route(&self) -> &str {
        &self.route
    }

    pub(crate) fn root_ca_certificate_file(&self) -> &Path {
        &self.root_ca_certificate_file
    }

    pub(crate) fn controller_client_certificate_file(&self) -> &Path {
        &self.controller_client_certificate_file
    }

    pub(crate) fn controller_client_private_key_file(&self) -> &Path {
        &self.controller_client_private_key_file
    }

    pub(crate) fn runtime_server_certificate_file(&self) -> &Path {
        &self.runtime_server_certificate_file
    }

    pub(crate) fn runtime_server_private_key_file(&self) -> &Path {
        &self.runtime_server_private_key_file
    }
}

impl fmt::Debug for DeveloperDistributedPxrpTargetConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperDistributedPxrpTargetConfigV1")
            .field("tls_listener_locator", &self.tls_listener_locator)
            .field("route", &"<explicit-pxrp-route>")
            .field("root_ca_certificate_file", &"<redacted-path>")
            .field("controller_client_identity", &"<redacted-paths>")
            .field("runtime_server_identity", &"<redacted-paths>")
            .finish()
    }
}

/// Explicit PXDT/Fabric resolver input for one target's sole Zenoh session.
///
/// The peer connect locator is deliberately absent: in the exact two-target
/// profile it is the other fixed-order target's explicit listener locator.
/// The expected peer-identity ref remains in the identity manifest, while the
/// distinct local credential ref is supplied here because PXDI does not own
/// one and it must never be borrowed from a restricted PXRP role.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DeveloperDistributedFabricTargetConfigV1 {
    tls_listener_locator: DistributedFabricTlsEndpointV1,
    local_credential_ref: DistributedFabricCredentialRefV1,
    expected_peer_common_name: Box<str>,
    root_ca_certificate_file: PathBuf,
    listen_certificate_file: PathBuf,
    listen_private_key_file: PathBuf,
    connect_certificate_file: PathBuf,
    connect_private_key_file: PathBuf,
}

impl DeveloperDistributedFabricTargetConfigV1 {
    pub(crate) fn tls_listener_locator(&self) -> &str {
        self.tls_listener_locator.as_str()
    }

    pub(crate) const fn local_credential_ref(&self) -> DistributedFabricCredentialRefV1 {
        self.local_credential_ref
    }

    pub(crate) fn expected_peer_common_name(&self) -> &str {
        &self.expected_peer_common_name
    }

    pub(crate) fn root_ca_certificate_file(&self) -> &Path {
        &self.root_ca_certificate_file
    }

    pub(crate) fn listen_certificate_file(&self) -> &Path {
        &self.listen_certificate_file
    }

    pub(crate) fn listen_private_key_file(&self) -> &Path {
        &self.listen_private_key_file
    }

    pub(crate) fn connect_certificate_file(&self) -> &Path {
        &self.connect_certificate_file
    }

    pub(crate) fn connect_private_key_file(&self) -> &Path {
        &self.connect_private_key_file
    }
}

impl fmt::Debug for DeveloperDistributedFabricTargetConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperDistributedFabricTargetConfigV1")
            .field("tls_listener_locator", &self.tls_listener_locator)
            .field("local_credential_ref", &"<redacted-ref>")
            .field("expected_peer_common_name", &"<redacted-cn>")
            .field("root_ca_certificate_file", &"<redacted-path>")
            .field("listen_identity", &"<redacted-paths>")
            .field("connect_identity", &"<redacted-paths>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeveloperProvisionedConfigV1 {
    state_root: PathBuf,
    fabric_listen: FabricLoopbackListenV1,
    model: Box<str>,
    secret_ref: ProvisionedSecretRefV1,
    profile: DeveloperLocalProfileV1,
}

impl DeveloperProvisionedConfigV1 {
    pub(crate) fn state_root(&self) -> &std::path::Path {
        &self.state_root
    }

    pub(crate) fn fabric_listen(&self) -> &str {
        self.fabric_listen.as_str()
    }

    pub(crate) fn model(&self) -> &str {
        &self.model
    }

    pub(crate) const fn secret_ref(&self) -> ProvisionedSecretRefV1 {
        self.secret_ref
    }

    pub(crate) const fn profile(&self) -> DeveloperLocalProfileV1 {
        self.profile
    }

    pub(crate) fn provider_config(
        &self,
        provider_ref: ManagedAgentProviderRefV1,
    ) -> Result<ProvisionedProviderConfigV1, ProvisionedProviderConfigErrorV1> {
        match self.profile.provider() {
            ProviderProfileV1::OpenAiResponsesV1 => OpenAiResponsesProviderConfigV1::try_new(
                *provider_ref.as_bytes(),
                self.model(),
                DEVELOPER_PROVISIONED_PROVIDER_TIMEOUT_NANOS,
                DEVELOPER_PROVISIONED_MAX_OUTPUT_TOKENS,
                DEVELOPER_PROVISIONED_MAX_RESPONSE_BODY_BYTES,
                DEVELOPER_PROVISIONED_MAX_OUTPUT_TEXT_BYTES,
            )
            .map(ProvisionedProviderConfigV1::OpenAi)
            .map_err(|_| ProvisionedProviderConfigErrorV1::OpenAi),
            ProviderProfileV1::DeepSeekChatCompletionsV1 => {
                let model = DeepSeekChatModelV1::try_from_id(self.model())
                    .map_err(|_| ProvisionedProviderConfigErrorV1::DeepSeek)?;
                DeepSeekChatCompletionsProviderConfigV1::try_new(
                    *provider_ref.as_bytes(),
                    model,
                    DEVELOPER_PROVISIONED_PROVIDER_TIMEOUT_NANOS,
                    DEVELOPER_PROVISIONED_MAX_OUTPUT_TOKENS,
                    DEVELOPER_PROVISIONED_MAX_RESPONSE_BODY_BYTES,
                    DEVELOPER_PROVISIONED_MAX_OUTPUT_TEXT_BYTES,
                )
                .map(ProvisionedProviderConfigV1::DeepSeek)
                .map_err(|_| ProvisionedProviderConfigErrorV1::DeepSeek)
            }
            ProviderProfileV1::DeterministicFixtureV1 => {
                Err(ProvisionedProviderConfigErrorV1::NotProvisioned)
            }
        }
    }

    pub(crate) fn provider_configuration_digest(
        &self,
        provider_ref: ManagedAgentProviderRefV1,
    ) -> Result<[u8; 32], ProvisionedProviderConfigErrorV1> {
        Ok(*self
            .provider_config(provider_ref)?
            .config_digest()
            .as_bytes())
    }

    pub(crate) const fn provider_profile(&self) -> ProviderProfileV1 {
        self.profile.provider()
    }
}

/// One exact non-secret resolver reference admitted by config schema v1.
///
/// Keeping this value after parsing makes the configured SecretRef, rather
/// than a second provider-to-environment mapping, the authority used by the
/// composition root. The referenced environment value is never retained here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProvisionedSecretRefV1 {
    OpenAiApiKeyEnvironment,
    DeepSeekApiKeyEnvironment,
}

impl ProvisionedSecretRefV1 {
    fn parse_exact(value: &str) -> Option<Self> {
        match value {
            OPENAI_SECRET_REF => Some(Self::OpenAiApiKeyEnvironment),
            DEEPSEEK_SECRET_REF => Some(Self::DeepSeekApiKeyEnvironment),
            _ => None,
        }
    }

    pub(crate) const fn environment_variable(self) -> &'static str {
        match self {
            Self::OpenAiApiKeyEnvironment => "OPENAI_API_KEY",
            Self::DeepSeekApiKeyEnvironment => "DEEPSEEK_API_KEY",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProvisionedProviderConfigV1 {
    OpenAi(OpenAiResponsesProviderConfigV1),
    DeepSeek(DeepSeekChatCompletionsProviderConfigV1),
}

impl ProvisionedProviderConfigV1 {
    pub(crate) const fn config_digest(&self) -> paraegox_kernel::digest::Digest32 {
        match self {
            Self::OpenAi(config) => config.config_digest(),
            Self::DeepSeek(config) => config.config_digest(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProvisionedProviderConfigErrorV1 {
    NotProvisioned,
    OpenAi,
    DeepSeek,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeveloperFixtureConfigV1 {
    state_root: PathBuf,
    fabric_listen: FabricLoopbackListenV1,
    profile: DeveloperLocalProfileV1,
}

impl DeveloperFixtureConfigV1 {
    pub(crate) fn state_root(&self) -> &std::path::Path {
        &self.state_root
    }

    pub(crate) fn fabric_listen(&self) -> &str {
        self.fabric_listen.as_str()
    }

    pub(crate) const fn profile(&self) -> DeveloperLocalProfileV1 {
        self.profile
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FabricLoopbackListenV1 {
    canonical: Box<str>,
}

impl FabricLoopbackListenV1 {
    fn try_new(value: String) -> Result<Self, ConfigError> {
        let port_text = value
            .strip_prefix(LOOPBACK_TCP_PREFIX)
            .ok_or(ConfigError::InvalidFabricListen)?;
        parse_canonical_nonzero_u16(port_text).ok_or(ConfigError::InvalidFabricListen)?;
        Ok(Self {
            canonical: value.into_boxed_str(),
        })
    }

    fn as_str(&self) -> &str {
        &self.canonical
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeveloperLocalProfileV1 {
    provider: ProviderProfileV1,
    request_deadline_budget: Duration,
    operation_timeout: Duration,
    command_capacity: usize,
}

impl DeveloperLocalProfileV1 {
    const fn fixed_fixture() -> Self {
        Self {
            provider: ProviderProfileV1::DeterministicFixtureV1,
            request_deadline_budget: DEVELOPER_REQUEST_DEADLINE_BUDGET,
            operation_timeout: DEVELOPER_OPERATION_TIMEOUT,
            command_capacity: DEVELOPER_COMMAND_CAPACITY,
        }
    }

    const fn fixed_distributed_fixture() -> Self {
        Self {
            provider: ProviderProfileV1::DeterministicFixtureV1,
            request_deadline_budget: DEVELOPER_REQUEST_DEADLINE_BUDGET,
            operation_timeout: DEVELOPER_OPERATION_TIMEOUT,
            command_capacity: DEVELOPER_COMMAND_CAPACITY,
        }
    }

    const fn fixed_openai() -> Self {
        Self {
            provider: ProviderProfileV1::OpenAiResponsesV1,
            request_deadline_budget: DEVELOPER_REQUEST_DEADLINE_BUDGET,
            operation_timeout: DEVELOPER_OPERATION_TIMEOUT,
            command_capacity: DEVELOPER_COMMAND_CAPACITY,
        }
    }

    const fn fixed_deepseek() -> Self {
        Self {
            provider: ProviderProfileV1::DeepSeekChatCompletionsV1,
            request_deadline_budget: DEVELOPER_REQUEST_DEADLINE_BUDGET,
            operation_timeout: DEVELOPER_OPERATION_TIMEOUT,
            command_capacity: DEVELOPER_COMMAND_CAPACITY,
        }
    }

    pub(crate) const fn request_deadline_budget(self) -> Duration {
        self.request_deadline_budget
    }

    pub(crate) const fn operation_timeout(self) -> Duration {
        self.operation_timeout
    }

    pub(crate) const fn command_capacity(self) -> usize {
        self.command_capacity
    }

    pub(crate) const fn provider(self) -> ProviderProfileV1 {
        self.provider
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderProfileV1 {
    DeterministicFixtureV1,
    OpenAiResponsesV1,
    DeepSeekChatCompletionsV1,
}

#[derive(Clone, Copy)]
enum DistributedTargetOrderV1 {
    A,
    B,
}

#[derive(Default)]
struct DistributedPxrpTargetOptionSlotsV1 {
    tls_listener_locator: Option<String>,
    route: Option<String>,
    root_ca_certificate_file: Option<String>,
    controller_client_certificate_file: Option<String>,
    controller_client_private_key_file: Option<String>,
    runtime_server_certificate_file: Option<String>,
    runtime_server_private_key_file: Option<String>,
}

impl DistributedPxrpTargetOptionSlotsV1 {
    fn finish(
        self,
        target: DistributedTargetOrderV1,
    ) -> Result<DeveloperDistributedPxrpTargetConfigV1, ConfigError> {
        let (
            missing_locator,
            missing_route,
            missing_root_ca,
            missing_controller_certificate,
            missing_controller_private_key,
            missing_runtime_certificate,
            missing_runtime_private_key,
            invalid_locator,
            invalid_route,
        ) = match target {
            DistributedTargetOrderV1::A => (
                ConfigError::MissingPxrpTlsListenerLocatorA,
                ConfigError::MissingPxrpRouteA,
                ConfigError::MissingPxrpRootCaCertificateFileA,
                ConfigError::MissingPxrpControllerClientCertificateFileA,
                ConfigError::MissingPxrpControllerClientPrivateKeyFileA,
                ConfigError::MissingPxrpRuntimeServerCertificateFileA,
                ConfigError::MissingPxrpRuntimeServerPrivateKeyFileA,
                ConfigError::InvalidPxrpTlsListenerLocatorA,
                ConfigError::InvalidPxrpRouteA,
            ),
            DistributedTargetOrderV1::B => (
                ConfigError::MissingPxrpTlsListenerLocatorB,
                ConfigError::MissingPxrpRouteB,
                ConfigError::MissingPxrpRootCaCertificateFileB,
                ConfigError::MissingPxrpControllerClientCertificateFileB,
                ConfigError::MissingPxrpControllerClientPrivateKeyFileB,
                ConfigError::MissingPxrpRuntimeServerCertificateFileB,
                ConfigError::MissingPxrpRuntimeServerPrivateKeyFileB,
                ConfigError::InvalidPxrpTlsListenerLocatorB,
                ConfigError::InvalidPxrpRouteB,
            ),
        };
        let tls_listener_locator =
            self.tls_listener_locator
                .ok_or(missing_locator)
                .and_then(|value| {
                    DistributedFabricTlsEndpointV1::try_new(&value).map_err(|_| invalid_locator)
                })?;
        let route = self.route.ok_or(missing_route)?;
        if !is_canonical_pxrp_route(&route) {
            return Err(invalid_route);
        }
        Ok(DeveloperDistributedPxrpTargetConfigV1 {
            tls_listener_locator,
            route: route.into_boxed_str(),
            root_ca_certificate_file: parse_tls_file_path(
                self.root_ca_certificate_file.ok_or(missing_root_ca)?,
            )?,
            controller_client_certificate_file: parse_tls_file_path(
                self.controller_client_certificate_file
                    .ok_or(missing_controller_certificate)?,
            )?,
            controller_client_private_key_file: parse_tls_file_path(
                self.controller_client_private_key_file
                    .ok_or(missing_controller_private_key)?,
            )?,
            runtime_server_certificate_file: parse_tls_file_path(
                self.runtime_server_certificate_file
                    .ok_or(missing_runtime_certificate)?,
            )?,
            runtime_server_private_key_file: parse_tls_file_path(
                self.runtime_server_private_key_file
                    .ok_or(missing_runtime_private_key)?,
            )?,
        })
    }
}

#[derive(Default)]
struct DistributedFabricTargetOptionSlotsV1 {
    tls_listener_locator: Option<String>,
    local_credential_ref: Option<String>,
    expected_peer_common_name: Option<String>,
    root_ca_certificate_file: Option<String>,
    listen_certificate_file: Option<String>,
    listen_private_key_file: Option<String>,
    connect_certificate_file: Option<String>,
    connect_private_key_file: Option<String>,
}

impl DistributedFabricTargetOptionSlotsV1 {
    fn finish(
        self,
        target: DistributedTargetOrderV1,
    ) -> Result<DeveloperDistributedFabricTargetConfigV1, ConfigError> {
        let (
            missing_locator,
            missing_credential_ref,
            missing_common_name,
            missing_root_ca,
            missing_listen_certificate,
            missing_listen_private_key,
            missing_connect_certificate,
            missing_connect_private_key,
            invalid_locator,
            invalid_credential_ref,
            invalid_common_name,
        ) = match target {
            DistributedTargetOrderV1::A => (
                ConfigError::MissingFabricTlsListenerLocatorA,
                ConfigError::MissingFabricLocalCredentialRefA,
                ConfigError::MissingFabricExpectedPeerCommonNameA,
                ConfigError::MissingFabricRootCaCertificateFileA,
                ConfigError::MissingFabricListenCertificateFileA,
                ConfigError::MissingFabricListenPrivateKeyFileA,
                ConfigError::MissingFabricConnectCertificateFileA,
                ConfigError::MissingFabricConnectPrivateKeyFileA,
                ConfigError::InvalidFabricTlsListenerLocatorA,
                ConfigError::InvalidFabricLocalCredentialRefA,
                ConfigError::InvalidFabricExpectedPeerCommonNameA,
            ),
            DistributedTargetOrderV1::B => (
                ConfigError::MissingFabricTlsListenerLocatorB,
                ConfigError::MissingFabricLocalCredentialRefB,
                ConfigError::MissingFabricExpectedPeerCommonNameB,
                ConfigError::MissingFabricRootCaCertificateFileB,
                ConfigError::MissingFabricListenCertificateFileB,
                ConfigError::MissingFabricListenPrivateKeyFileB,
                ConfigError::MissingFabricConnectCertificateFileB,
                ConfigError::MissingFabricConnectPrivateKeyFileB,
                ConfigError::InvalidFabricTlsListenerLocatorB,
                ConfigError::InvalidFabricLocalCredentialRefB,
                ConfigError::InvalidFabricExpectedPeerCommonNameB,
            ),
        };
        let tls_listener_locator =
            self.tls_listener_locator
                .ok_or(missing_locator)
                .and_then(|value| {
                    DistributedFabricTlsEndpointV1::try_new(&value).map_err(|_| invalid_locator)
                })?;
        let local_credential_ref_bytes =
            parse_nonzero_ref(&self.local_credential_ref.ok_or(missing_credential_ref)?)
                .ok_or(invalid_credential_ref)?;
        let local_credential_ref =
            DistributedFabricCredentialRefV1::try_from_bytes(local_credential_ref_bytes)
                .map_err(|_| invalid_credential_ref)?;
        let expected_peer_common_name =
            self.expected_peer_common_name.ok_or(missing_common_name)?;
        if !is_canonical_experimental_peer_common_name(&expected_peer_common_name) {
            return Err(invalid_common_name);
        }
        Ok(DeveloperDistributedFabricTargetConfigV1 {
            tls_listener_locator,
            local_credential_ref,
            expected_peer_common_name: expected_peer_common_name.into_boxed_str(),
            root_ca_certificate_file: parse_tls_file_path(
                self.root_ca_certificate_file.ok_or(missing_root_ca)?,
            )?,
            listen_certificate_file: parse_tls_file_path(
                self.listen_certificate_file
                    .ok_or(missing_listen_certificate)?,
            )?,
            listen_private_key_file: parse_tls_file_path(
                self.listen_private_key_file
                    .ok_or(missing_listen_private_key)?,
            )?,
            connect_certificate_file: parse_tls_file_path(
                self.connect_certificate_file
                    .ok_or(missing_connect_certificate)?,
            )?,
            connect_private_key_file: parse_tls_file_path(
                self.connect_private_key_file
                    .ok_or(missing_connect_private_key)?,
            )?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigError {
    NonUtf8Argument,
    #[cfg(not(unix))]
    UnsupportedPlatform,
    MissingMode,
    UnknownMode,
    MissingConfigPath,
    InvalidConfigPath,
    ConfigFileTooLarge,
    ConfigFileRead,
    InvalidConfigDocument,
    UnsupportedConfigSchema,
    UnknownProvider,
    InvalidProviderConfiguration,
    UnexpectedHelpArgument,
    UnknownOption,
    MissingOptionValue,
    DuplicateOption,
    MissingStateRoot,
    MissingFabricListenA,
    MissingFabricListenB,
    MissingPxrpTlsListenerLocatorA,
    MissingPxrpTlsListenerLocatorB,
    MissingPxrpRouteA,
    MissingPxrpRouteB,
    MissingPxrpRootCaCertificateFileA,
    MissingPxrpRootCaCertificateFileB,
    MissingPxrpControllerClientCertificateFileA,
    MissingPxrpControllerClientCertificateFileB,
    MissingPxrpControllerClientPrivateKeyFileA,
    MissingPxrpControllerClientPrivateKeyFileB,
    MissingPxrpRuntimeServerCertificateFileA,
    MissingPxrpRuntimeServerCertificateFileB,
    MissingPxrpRuntimeServerPrivateKeyFileA,
    MissingPxrpRuntimeServerPrivateKeyFileB,
    MissingFabricTlsListenerLocatorA,
    MissingFabricTlsListenerLocatorB,
    MissingFabricLocalCredentialRefA,
    MissingFabricLocalCredentialRefB,
    MissingFabricExpectedPeerCommonNameA,
    MissingFabricExpectedPeerCommonNameB,
    MissingFabricRootCaCertificateFileA,
    MissingFabricRootCaCertificateFileB,
    MissingFabricListenCertificateFileA,
    MissingFabricListenCertificateFileB,
    MissingFabricListenPrivateKeyFileA,
    MissingFabricListenPrivateKeyFileB,
    MissingFabricConnectCertificateFileA,
    MissingFabricConnectCertificateFileB,
    MissingFabricConnectPrivateKeyFileA,
    MissingFabricConnectPrivateKeyFileB,
    MissingModel,
    InvalidStateRoot,
    StateRootTooLong,
    InvalidFabricListen,
    InvalidFabricListenA,
    InvalidFabricListenB,
    FabricListenCollision,
    InvalidPxrpTlsListenerLocatorA,
    InvalidPxrpTlsListenerLocatorB,
    InvalidPxrpRouteA,
    InvalidPxrpRouteB,
    InvalidTlsFilePath,
    InvalidFabricTlsListenerLocatorA,
    InvalidFabricTlsListenerLocatorB,
    InvalidFabricLocalCredentialRefA,
    InvalidFabricLocalCredentialRefB,
    InvalidFabricExpectedPeerCommonNameA,
    InvalidFabricExpectedPeerCommonNameB,
    DistributedTlsListenerLocatorCollision,
    FabricLocalCredentialRefCollision,
    FabricExpectedPeerCommonNameCollision,
    InvalidModel,
}

impl ConfigError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::NonUtf8Argument => "PXLC-ARG-NON-UTF8",
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => "PXLC-PLATFORM-UNSUPPORTED",
            Self::MissingMode => "PXLC-MODE-MISSING",
            Self::UnknownMode => "PXLC-MODE-UNKNOWN",
            Self::MissingConfigPath => "PXLC-CONFIG-PATH-MISSING",
            Self::InvalidConfigPath => "PXLC-CONFIG-PATH-INVALID",
            Self::ConfigFileTooLarge => "PXLC-CONFIG-FILE-TOO-LARGE",
            Self::ConfigFileRead => "PXLC-CONFIG-FILE-READ",
            Self::InvalidConfigDocument => "PXLC-CONFIG-DOCUMENT-INVALID",
            Self::UnsupportedConfigSchema => "PXLC-CONFIG-SCHEMA-UNSUPPORTED",
            Self::UnknownProvider => "PXLC-CONFIG-PROVIDER-UNKNOWN",
            Self::InvalidProviderConfiguration => "PXLC-CONFIG-PROVIDER-INVALID",
            Self::UnexpectedHelpArgument => "PXLC-HELP-EXTRA",
            Self::UnknownOption => "PXLC-OPTION-UNKNOWN",
            Self::MissingOptionValue => "PXLC-OPTION-VALUE-MISSING",
            Self::DuplicateOption => "PXLC-OPTION-DUPLICATE",
            Self::MissingStateRoot => "PXLC-STATE-ROOT-MISSING",
            Self::MissingFabricListenA => "PXLC-FABRIC-LISTEN-A-MISSING",
            Self::MissingFabricListenB => "PXLC-FABRIC-LISTEN-B-MISSING",
            Self::MissingPxrpTlsListenerLocatorA => "PXLC-PXRP-LOCATOR-A-MISSING",
            Self::MissingPxrpTlsListenerLocatorB => "PXLC-PXRP-LOCATOR-B-MISSING",
            Self::MissingPxrpRouteA => "PXLC-PXRP-ROUTE-A-MISSING",
            Self::MissingPxrpRouteB => "PXLC-PXRP-ROUTE-B-MISSING",
            Self::MissingPxrpRootCaCertificateFileA
            | Self::MissingPxrpRootCaCertificateFileB
            | Self::MissingPxrpControllerClientCertificateFileA
            | Self::MissingPxrpControllerClientCertificateFileB
            | Self::MissingPxrpControllerClientPrivateKeyFileA
            | Self::MissingPxrpControllerClientPrivateKeyFileB
            | Self::MissingPxrpRuntimeServerCertificateFileA
            | Self::MissingPxrpRuntimeServerCertificateFileB
            | Self::MissingPxrpRuntimeServerPrivateKeyFileA
            | Self::MissingPxrpRuntimeServerPrivateKeyFileB => "PXLC-PXRP-TLS-PATH-MISSING",
            Self::MissingFabricTlsListenerLocatorA => "PXLC-DIST-FABRIC-LOCATOR-A-MISSING",
            Self::MissingFabricTlsListenerLocatorB => "PXLC-DIST-FABRIC-LOCATOR-B-MISSING",
            Self::MissingFabricLocalCredentialRefA => "PXLC-DIST-FABRIC-CREDENTIAL-A-MISSING",
            Self::MissingFabricLocalCredentialRefB => "PXLC-DIST-FABRIC-CREDENTIAL-B-MISSING",
            Self::MissingFabricExpectedPeerCommonNameA => "PXLC-DIST-FABRIC-CN-A-MISSING",
            Self::MissingFabricExpectedPeerCommonNameB => "PXLC-DIST-FABRIC-CN-B-MISSING",
            Self::MissingFabricRootCaCertificateFileA
            | Self::MissingFabricRootCaCertificateFileB
            | Self::MissingFabricListenCertificateFileA
            | Self::MissingFabricListenCertificateFileB
            | Self::MissingFabricListenPrivateKeyFileA
            | Self::MissingFabricListenPrivateKeyFileB
            | Self::MissingFabricConnectCertificateFileA
            | Self::MissingFabricConnectCertificateFileB
            | Self::MissingFabricConnectPrivateKeyFileA
            | Self::MissingFabricConnectPrivateKeyFileB => "PXLC-DIST-FABRIC-TLS-PATH-MISSING",
            Self::MissingModel => "PXLC-MODEL-MISSING",
            Self::InvalidStateRoot => "PXLC-STATE-ROOT-INVALID",
            Self::StateRootTooLong => "PXLC-STATE-ROOT-TOO-LONG",
            Self::InvalidFabricListen => "PXLC-FABRIC-LISTEN-INVALID",
            Self::InvalidFabricListenA => "PXLC-FABRIC-LISTEN-A-INVALID",
            Self::InvalidFabricListenB => "PXLC-FABRIC-LISTEN-B-INVALID",
            Self::FabricListenCollision => "PXLC-FABRIC-LISTEN-COLLISION",
            Self::InvalidPxrpTlsListenerLocatorA => "PXLC-PXRP-LOCATOR-A-INVALID",
            Self::InvalidPxrpTlsListenerLocatorB => "PXLC-PXRP-LOCATOR-B-INVALID",
            Self::InvalidPxrpRouteA => "PXLC-PXRP-ROUTE-A-INVALID",
            Self::InvalidPxrpRouteB => "PXLC-PXRP-ROUTE-B-INVALID",
            Self::InvalidTlsFilePath => "PXLC-DIST-TLS-PATH-INVALID",
            Self::InvalidFabricTlsListenerLocatorA => "PXLC-DIST-FABRIC-LOCATOR-A-INVALID",
            Self::InvalidFabricTlsListenerLocatorB => "PXLC-DIST-FABRIC-LOCATOR-B-INVALID",
            Self::InvalidFabricLocalCredentialRefA => "PXLC-DIST-FABRIC-CREDENTIAL-A-INVALID",
            Self::InvalidFabricLocalCredentialRefB => "PXLC-DIST-FABRIC-CREDENTIAL-B-INVALID",
            Self::InvalidFabricExpectedPeerCommonNameA => "PXLC-DIST-FABRIC-CN-A-INVALID",
            Self::InvalidFabricExpectedPeerCommonNameB => "PXLC-DIST-FABRIC-CN-B-INVALID",
            Self::DistributedTlsListenerLocatorCollision => "PXLC-DIST-TLS-LISTENER-COLLISION",
            Self::FabricLocalCredentialRefCollision => "PXLC-DIST-FABRIC-CREDENTIAL-COLLISION",
            Self::FabricExpectedPeerCommonNameCollision => "PXLC-DIST-FABRIC-CN-COLLISION",
            Self::InvalidModel => "PXLC-MODEL-INVALID",
        }
    }

    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::NonUtf8Argument => "arguments must be valid UTF-8",
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => {
                "DeveloperLocal modes require the Unix DeveloperLocal platform"
            }
            Self::MissingMode => "an explicit mode is required",
            Self::UnknownMode => "the requested mode is not supported",
            Self::MissingConfigPath => "chat requires --config with one path",
            Self::InvalidConfigPath => {
                "config path must name an absolute lexically canonical regular file"
            }
            Self::ConfigFileTooLarge => "config file exceeds the 64 KiB limit",
            Self::ConfigFileRead => "config file could not be read",
            Self::InvalidConfigDocument => "config file is not a strict ParaEGOX TOML document",
            Self::UnsupportedConfigSchema => "config schema_version is not supported",
            Self::UnknownProvider => "config selects an unsupported model provider",
            Self::InvalidProviderConfiguration => {
                "config model fields do not match the selected provider"
            }
            Self::UnexpectedHelpArgument => "help accepts no additional arguments",
            Self::UnknownOption => "the mode contains an unknown or positional argument",
            Self::MissingOptionValue => "an option is missing its value",
            Self::DuplicateOption => "an option was supplied more than once",
            Self::MissingStateRoot => "the selected DeveloperLocal mode requires --state-root",
            Self::MissingFabricListenA => "internal distributed fixture requires --fabric-listen-a",
            Self::MissingFabricListenB => "internal distributed fixture requires --fabric-listen-b",
            Self::MissingPxrpTlsListenerLocatorA => {
                "internal distributed fixture requires the target-A PXRP TLS listener locator"
            }
            Self::MissingPxrpTlsListenerLocatorB => {
                "internal distributed fixture requires the target-B PXRP TLS listener locator"
            }
            Self::MissingPxrpRouteA => {
                "internal distributed fixture requires the target-A PXRP route"
            }
            Self::MissingPxrpRouteB => {
                "internal distributed fixture requires the target-B PXRP route"
            }
            Self::MissingPxrpRootCaCertificateFileA
            | Self::MissingPxrpRootCaCertificateFileB
            | Self::MissingPxrpControllerClientCertificateFileA
            | Self::MissingPxrpControllerClientCertificateFileB
            | Self::MissingPxrpControllerClientPrivateKeyFileA
            | Self::MissingPxrpControllerClientPrivateKeyFileB
            | Self::MissingPxrpRuntimeServerCertificateFileA
            | Self::MissingPxrpRuntimeServerCertificateFileB
            | Self::MissingPxrpRuntimeServerPrivateKeyFileA
            | Self::MissingPxrpRuntimeServerPrivateKeyFileB => {
                "internal distributed fixture requires every explicit PXRP mTLS file path"
            }
            Self::MissingFabricTlsListenerLocatorA => {
                "internal distributed fixture requires the target-A Fabric TLS listener locator"
            }
            Self::MissingFabricTlsListenerLocatorB => {
                "internal distributed fixture requires the target-B Fabric TLS listener locator"
            }
            Self::MissingFabricLocalCredentialRefA => {
                "internal distributed fixture requires the target-A Fabric credential ref"
            }
            Self::MissingFabricLocalCredentialRefB => {
                "internal distributed fixture requires the target-B Fabric credential ref"
            }
            Self::MissingFabricExpectedPeerCommonNameA => {
                "internal distributed fixture requires target A's expected Fabric peer CN"
            }
            Self::MissingFabricExpectedPeerCommonNameB => {
                "internal distributed fixture requires target B's expected Fabric peer CN"
            }
            Self::MissingFabricRootCaCertificateFileA
            | Self::MissingFabricRootCaCertificateFileB
            | Self::MissingFabricListenCertificateFileA
            | Self::MissingFabricListenCertificateFileB
            | Self::MissingFabricListenPrivateKeyFileA
            | Self::MissingFabricListenPrivateKeyFileB
            | Self::MissingFabricConnectCertificateFileA
            | Self::MissingFabricConnectCertificateFileB
            | Self::MissingFabricConnectPrivateKeyFileA
            | Self::MissingFabricConnectPrivateKeyFileB => {
                "internal distributed fixture requires every explicit Fabric mTLS file path"
            }
            Self::MissingModel => "the selected provisioned chat profile requires model in config",
            Self::InvalidStateRoot => {
                "state root must be a non-root, lexically canonical absolute Unix path"
            }
            Self::StateRootTooLong => "state root exceeds the bounded DeveloperLocal limit",
            Self::InvalidFabricListen => {
                "Fabric listen must be canonical tcp/127.0.0.1:PORT with PORT in 1..=65535"
            }
            Self::InvalidFabricListenA => {
                "Fabric listen A must be canonical tcp/127.0.0.1:PORT with PORT in 1..=65535"
            }
            Self::InvalidFabricListenB => {
                "Fabric listen B must be canonical tcp/127.0.0.1:PORT with PORT in 1..=65535"
            }
            Self::FabricListenCollision => {
                "distributed Fabric listen A and B must use distinct loopback locators"
            }
            Self::InvalidPxrpTlsListenerLocatorA => {
                "target-A PXRP locator must be a canonical non-loopback IPv4 TLS endpoint"
            }
            Self::InvalidPxrpTlsListenerLocatorB => {
                "target-B PXRP locator must be a canonical non-loopback IPv4 TLS endpoint"
            }
            Self::InvalidPxrpRouteA => "target-A PXRP route is not canonical and bounded",
            Self::InvalidPxrpRouteB => "target-B PXRP route is not canonical and bounded",
            Self::InvalidTlsFilePath => {
                "TLS file paths must be bounded normalized absolute UTF-8 paths"
            }
            Self::InvalidFabricTlsListenerLocatorA => {
                "target-A Fabric locator must be a canonical non-loopback IPv4 TLS endpoint"
            }
            Self::InvalidFabricTlsListenerLocatorB => {
                "target-B Fabric locator must be a canonical non-loopback IPv4 TLS endpoint"
            }
            Self::InvalidFabricLocalCredentialRefA => {
                "target-A Fabric credential ref must be nonzero canonical lower-case hex"
            }
            Self::InvalidFabricLocalCredentialRefB => {
                "target-B Fabric credential ref must be nonzero canonical lower-case hex"
            }
            Self::InvalidFabricExpectedPeerCommonNameA => {
                "target A's expected Fabric peer CN must be canonical bounded lower-case DNS form"
            }
            Self::InvalidFabricExpectedPeerCommonNameB => {
                "target B's expected Fabric peer CN must be canonical bounded lower-case DNS form"
            }
            Self::DistributedTlsListenerLocatorCollision => {
                "PXRP and Fabric TLS listener locators must be pairwise distinct"
            }
            Self::FabricLocalCredentialRefCollision => {
                "target A and B must use distinct Fabric local credential refs"
            }
            Self::FabricExpectedPeerCommonNameCollision => {
                "target A and B must expect distinct Fabric peer Common Names"
            }
            Self::InvalidModel => {
                "the model identifier is invalid for the selected provisioned chat profile"
            }
        }
    }
}

pub(crate) fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, ConfigError> {
    let arguments = arguments
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| ConfigError::NonUtf8Argument)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut arguments = arguments.into_iter();
    let mode = arguments.next().ok_or(ConfigError::MissingMode)?;

    match mode.as_str() {
        "--help" | "-h" => {
            if arguments.next().is_some() {
                return Err(ConfigError::UnexpectedHelpArgument);
            }
            Ok(Command::Help)
        }
        CHAT_COMMAND => parse_chat(arguments),
        INTERNAL_DISTRIBUTED_FIXTURE_MODE => parse_developer_distributed_fixture_v1(
            arguments,
            DeveloperDistributedFixtureActionV1::Run,
        ),
        INTERNAL_DISTRIBUTED_IDENTITY_INIT_MODE => parse_developer_distributed_fixture_v1(
            arguments,
            DeveloperDistributedFixtureActionV1::InitializeIdentity,
        ),
        _ => Err(ConfigError::UnknownMode),
    }
}

fn parse_chat(mut arguments: impl Iterator<Item = String>) -> Result<Command, ConfigError> {
    ensure_unix_developer_local()?;
    if arguments.next().as_deref() != Some(CONFIG_OPTION) {
        return Err(ConfigError::MissingConfigPath);
    }
    let path = arguments.next().ok_or(ConfigError::MissingConfigPath)?;
    if arguments.next().is_some() {
        return Err(ConfigError::UnknownOption);
    }
    parse_chat_config_file(path)
}

fn parse_chat_config_file(path: String) -> Result<Command, ConfigError> {
    let path = parse_config_path(path)?;
    let file = open_config_file(&path)?;
    let metadata = file.metadata().map_err(|_| ConfigError::ConfigFileRead)?;
    if metadata.len() > MAX_CHAT_CONFIG_BYTES {
        return Err(ConfigError::ConfigFileTooLarge);
    }
    let mut bytes = Vec::new();
    file.take(MAX_CHAT_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::ConfigFileRead)?;
    if bytes.len() as u64 > MAX_CHAT_CONFIG_BYTES {
        return Err(ConfigError::ConfigFileTooLarge);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ConfigError::InvalidConfigDocument)?;
    let document = toml::from_str::<DeveloperLocalConfigDocumentV1>(text)
        .map_err(|_| ConfigError::InvalidConfigDocument)?;
    parse_chat_config_document(document)
}

fn parse_config_path(value: String) -> Result<PathBuf, ConfigError> {
    let path = PathBuf::from(&value);
    if value.is_empty()
        || value.len() > MAX_STATE_ROOT_BYTES
        || !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(ConfigError::InvalidConfigPath);
    }
    let metadata = fs::symlink_metadata(&path).map_err(|_| ConfigError::ConfigFileRead)?;
    if !metadata.file_type().is_file() {
        return Err(ConfigError::InvalidConfigPath);
    }
    Ok(path)
}

#[cfg(unix)]
fn open_config_file(path: &Path) -> Result<File, ConfigError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let before = fs::symlink_metadata(path).map_err(|_| ConfigError::ConfigFileRead)?;
    if !before.file_type().is_file() {
        return Err(ConfigError::InvalidConfigPath);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ConfigError::ConfigFileRead)?;
    let opened = file.metadata().map_err(|_| ConfigError::ConfigFileRead)?;
    let after = fs::symlink_metadata(path).map_err(|_| ConfigError::ConfigFileRead)?;
    if !opened.is_file()
        || !after.file_type().is_file()
        || before.dev() != opened.dev()
        || before.ino() != opened.ino()
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
    {
        return Err(ConfigError::InvalidConfigPath);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_config_file(_path: &Path) -> Result<File, ConfigError> {
    Err(ConfigError::UnsupportedPlatform)
}

fn parse_chat_config_document(
    document: DeveloperLocalConfigDocumentV1,
) -> Result<Command, ConfigError> {
    if document.schema_version != CHAT_CONFIG_SCHEMA_VERSION {
        return Err(ConfigError::UnsupportedConfigSchema);
    }
    let state_root = parse_state_root(document.state_root)?;
    let fabric_listen = FabricLoopbackListenV1::try_new(document.fabric_listen)?;
    let DeveloperLocalModelDocumentV1 {
        provider,
        model,
        secret_ref,
    } = document.model;
    match provider.as_str() {
        DETERMINISTIC_ECHO_PROVIDER => {
            if model.is_some() || secret_ref.is_some() {
                return Err(ConfigError::InvalidProviderConfiguration);
            }
            Ok(Command::DeveloperFixtureV1(DeveloperFixtureConfigV1 {
                state_root,
                fabric_listen,
                profile: DeveloperLocalProfileV1::fixed_fixture(),
            }))
        }
        OPENAI_RESPONSES_PROVIDER => parse_provisioned_config_document(
            state_root,
            fabric_listen,
            model,
            secret_ref,
            ProvisionedSecretRefV1::OpenAiApiKeyEnvironment,
            DeveloperLocalProfileV1::fixed_openai(),
        ),
        DEEPSEEK_CHAT_COMPLETIONS_PROVIDER => parse_provisioned_config_document(
            state_root,
            fabric_listen,
            model,
            secret_ref,
            ProvisionedSecretRefV1::DeepSeekApiKeyEnvironment,
            DeveloperLocalProfileV1::fixed_deepseek(),
        ),
        _ => Err(ConfigError::UnknownProvider),
    }
}

#[cfg(test)]
pub(crate) fn parse_chat_config_toml_for_test(document: &str) -> Result<Command, ConfigError> {
    let document = toml::from_str::<DeveloperLocalConfigDocumentV1>(document)
        .map_err(|_| ConfigError::InvalidConfigDocument)?;
    parse_chat_config_document(document)
}

fn parse_provisioned_config_document(
    state_root: PathBuf,
    fabric_listen: FabricLoopbackListenV1,
    model: Option<String>,
    secret_ref: Option<String>,
    expected_secret_ref: ProvisionedSecretRefV1,
    profile: DeveloperLocalProfileV1,
) -> Result<Command, ConfigError> {
    let model = model.ok_or(ConfigError::MissingModel)?;
    let secret_ref = secret_ref
        .as_deref()
        .and_then(ProvisionedSecretRefV1::parse_exact)
        .filter(|secret_ref| *secret_ref == expected_secret_ref)
        .ok_or(ConfigError::InvalidProviderConfiguration)?;
    validate_model(profile.provider(), &model)?;
    Ok(Command::DeveloperProvisionedV1(
        DeveloperProvisionedConfigV1 {
            state_root,
            fabric_listen,
            model: model.into_boxed_str(),
            secret_ref,
            profile,
        },
    ))
}

fn parse_developer_distributed_fixture_v1(
    mut arguments: impl Iterator<Item = String>,
    action: DeveloperDistributedFixtureActionV1,
) -> Result<Command, ConfigError> {
    ensure_unix_developer_local()?;
    let mut state_root = None;
    let mut fabric_listen_a = None;
    let mut fabric_listen_b = None;
    let mut pxrp_a = DistributedPxrpTargetOptionSlotsV1::default();
    let mut pxrp_b = DistributedPxrpTargetOptionSlotsV1::default();
    let mut fabric_a = DistributedFabricTargetOptionSlotsV1::default();
    let mut fabric_b = DistributedFabricTargetOptionSlotsV1::default();

    while let Some(option) = arguments.next() {
        let slot = match option.as_str() {
            STATE_ROOT_OPTION => &mut state_root,
            FABRIC_LISTEN_A_OPTION => &mut fabric_listen_a,
            FABRIC_LISTEN_B_OPTION => &mut fabric_listen_b,
            PXRP_TLS_LISTENER_LOCATOR_A_OPTION => &mut pxrp_a.tls_listener_locator,
            PXRP_TLS_LISTENER_LOCATOR_B_OPTION => &mut pxrp_b.tls_listener_locator,
            PXRP_ROUTE_A_OPTION => &mut pxrp_a.route,
            PXRP_ROUTE_B_OPTION => &mut pxrp_b.route,
            PXRP_ROOT_CA_CERTIFICATE_FILE_A_OPTION => &mut pxrp_a.root_ca_certificate_file,
            PXRP_ROOT_CA_CERTIFICATE_FILE_B_OPTION => &mut pxrp_b.root_ca_certificate_file,
            PXRP_CONTROLLER_CLIENT_CERTIFICATE_FILE_A_OPTION => {
                &mut pxrp_a.controller_client_certificate_file
            }
            PXRP_CONTROLLER_CLIENT_CERTIFICATE_FILE_B_OPTION => {
                &mut pxrp_b.controller_client_certificate_file
            }
            PXRP_CONTROLLER_CLIENT_PRIVATE_KEY_FILE_A_OPTION => {
                &mut pxrp_a.controller_client_private_key_file
            }
            PXRP_CONTROLLER_CLIENT_PRIVATE_KEY_FILE_B_OPTION => {
                &mut pxrp_b.controller_client_private_key_file
            }
            PXRP_RUNTIME_SERVER_CERTIFICATE_FILE_A_OPTION => {
                &mut pxrp_a.runtime_server_certificate_file
            }
            PXRP_RUNTIME_SERVER_CERTIFICATE_FILE_B_OPTION => {
                &mut pxrp_b.runtime_server_certificate_file
            }
            PXRP_RUNTIME_SERVER_PRIVATE_KEY_FILE_A_OPTION => {
                &mut pxrp_a.runtime_server_private_key_file
            }
            PXRP_RUNTIME_SERVER_PRIVATE_KEY_FILE_B_OPTION => {
                &mut pxrp_b.runtime_server_private_key_file
            }
            FABRIC_TLS_LISTENER_LOCATOR_A_OPTION => &mut fabric_a.tls_listener_locator,
            FABRIC_TLS_LISTENER_LOCATOR_B_OPTION => &mut fabric_b.tls_listener_locator,
            FABRIC_LOCAL_CREDENTIAL_REF_A_OPTION => &mut fabric_a.local_credential_ref,
            FABRIC_LOCAL_CREDENTIAL_REF_B_OPTION => &mut fabric_b.local_credential_ref,
            FABRIC_EXPECTED_PEER_COMMON_NAME_A_OPTION => &mut fabric_a.expected_peer_common_name,
            FABRIC_EXPECTED_PEER_COMMON_NAME_B_OPTION => &mut fabric_b.expected_peer_common_name,
            FABRIC_ROOT_CA_CERTIFICATE_FILE_A_OPTION => &mut fabric_a.root_ca_certificate_file,
            FABRIC_ROOT_CA_CERTIFICATE_FILE_B_OPTION => &mut fabric_b.root_ca_certificate_file,
            FABRIC_LISTEN_CERTIFICATE_FILE_A_OPTION => &mut fabric_a.listen_certificate_file,
            FABRIC_LISTEN_CERTIFICATE_FILE_B_OPTION => &mut fabric_b.listen_certificate_file,
            FABRIC_LISTEN_PRIVATE_KEY_FILE_A_OPTION => &mut fabric_a.listen_private_key_file,
            FABRIC_LISTEN_PRIVATE_KEY_FILE_B_OPTION => &mut fabric_b.listen_private_key_file,
            FABRIC_CONNECT_CERTIFICATE_FILE_A_OPTION => &mut fabric_a.connect_certificate_file,
            FABRIC_CONNECT_CERTIFICATE_FILE_B_OPTION => &mut fabric_b.connect_certificate_file,
            FABRIC_CONNECT_PRIVATE_KEY_FILE_A_OPTION => &mut fabric_a.connect_private_key_file,
            FABRIC_CONNECT_PRIVATE_KEY_FILE_B_OPTION => &mut fabric_b.connect_private_key_file,
            _ => return Err(ConfigError::UnknownOption),
        };
        let value = arguments.next().ok_or(ConfigError::MissingOptionValue)?;
        if value.starts_with("--") {
            return Err(ConfigError::MissingOptionValue);
        }
        set_once(slot, value)?;
    }

    let state_root = parse_state_root(state_root.ok_or(ConfigError::MissingStateRoot)?)?;
    let fabric_listen_a =
        FabricLoopbackListenV1::try_new(fabric_listen_a.ok_or(ConfigError::MissingFabricListenA)?)
            .map_err(|_| ConfigError::InvalidFabricListenA)?;
    let fabric_listen_b =
        FabricLoopbackListenV1::try_new(fabric_listen_b.ok_or(ConfigError::MissingFabricListenB)?)
            .map_err(|_| ConfigError::InvalidFabricListenB)?;
    if fabric_listen_a == fabric_listen_b {
        return Err(ConfigError::FabricListenCollision);
    }
    let target_a = DeveloperDistributedTargetConfigV1 {
        pxrp: pxrp_a.finish(DistributedTargetOrderV1::A)?,
        fabric: fabric_a.finish(DistributedTargetOrderV1::A)?,
    };
    let target_b = DeveloperDistributedTargetConfigV1 {
        pxrp: pxrp_b.finish(DistributedTargetOrderV1::B)?,
        fabric: fabric_b.finish(DistributedTargetOrderV1::B)?,
    };
    let tls_listener_locators = [
        &target_a.pxrp.tls_listener_locator,
        &target_a.fabric.tls_listener_locator,
        &target_b.pxrp.tls_listener_locator,
        &target_b.fabric.tls_listener_locator,
    ];
    if tls_listener_locators
        .iter()
        .enumerate()
        .any(|(index, left)| {
            tls_listener_locators[index + 1..]
                .iter()
                .any(|right| left == right)
        })
    {
        return Err(ConfigError::DistributedTlsListenerLocatorCollision);
    }
    if target_a.fabric.local_credential_ref == target_b.fabric.local_credential_ref {
        return Err(ConfigError::FabricLocalCredentialRefCollision);
    }
    if target_a.fabric.expected_peer_common_name == target_b.fabric.expected_peer_common_name {
        return Err(ConfigError::FabricExpectedPeerCommonNameCollision);
    }

    Ok(Command::DeveloperDistributedFixtureV1(
        DeveloperDistributedFixtureConfigV1 {
            state_root,
            fabric_listen_a,
            fabric_listen_b,
            targets: Box::new([target_a, target_b]),
            profile: DeveloperLocalProfileV1::fixed_distributed_fixture(),
            action,
        },
    ))
}

fn validate_model(profile: ProviderProfileV1, model: &str) -> Result<(), ConfigError> {
    match profile {
        ProviderProfileV1::OpenAiResponsesV1 => {
            if model.is_empty()
                || model.len() > MAX_OPENAI_RESPONSES_MODEL_BYTES
                || !model.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            {
                return Err(ConfigError::InvalidModel);
            }
        }
        ProviderProfileV1::DeepSeekChatCompletionsV1 => {
            DeepSeekChatModelV1::try_from_id(model).map_err(|_| ConfigError::InvalidModel)?;
        }
        ProviderProfileV1::DeterministicFixtureV1 => return Err(ConfigError::InvalidModel),
    }
    Ok(())
}

#[cfg(unix)]
const fn ensure_unix_developer_local() -> Result<(), ConfigError> {
    Ok(())
}

#[cfg(not(unix))]
const fn ensure_unix_developer_local() -> Result<(), ConfigError> {
    Err(ConfigError::UnsupportedPlatform)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), ConfigError> {
    if slot.replace(value).is_some() {
        return Err(ConfigError::DuplicateOption);
    }
    Ok(())
}

fn parse_state_root(value: String) -> Result<PathBuf, ConfigError> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_STATE_ROOT_BYTES {
        return Err(ConfigError::StateRootTooLong);
    }
    if bytes.len() <= 1
        || bytes.first() != Some(&b'/')
        || bytes.last() == Some(&b'/')
        || bytes.contains(&0)
        || bytes.windows(2).any(|window| window == b"//")
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component == b"." || component == b"..")
    {
        return Err(ConfigError::InvalidStateRoot);
    }
    Ok(PathBuf::from(value))
}

fn parse_tls_file_path(value: String) -> Result<PathBuf, ConfigError> {
    let path = PathBuf::from(&value);
    let mut normalized = PathBuf::new();
    let mut has_normal_component = false;
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(_) => {
                has_normal_component = true;
                normalized.push(component.as_os_str());
            }
            _ => return Err(ConfigError::InvalidTlsFilePath),
        }
    }
    if !path.is_absolute()
        || !has_normal_component
        || normalized.as_os_str() != path.as_os_str()
        || value.len() > MAX_TLS_FILE_PATH_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ConfigError::InvalidTlsFilePath);
    }
    Ok(path)
}

fn is_canonical_pxrp_route(route: &str) -> bool {
    !route.is_empty()
        && route.len() <= MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES
        && route.is_ascii()
        && !route.starts_with('/')
        && !route.ends_with('/')
        && !route.contains("//")
        && route.starts_with("paraegox/")
        && route.ends_with("/apply")
        && !route
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        && route
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
}

fn parse_nonzero_ref(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut decoded = [0_u8; 16];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    (!decoded.iter().all(|byte| *byte == 0)).then_some(decoded)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn is_canonical_experimental_peer_common_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_EXPERIMENTAL_PEER_COMMON_NAME_BYTES
        || !value.is_ascii()
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn parse_canonical_nonzero_u16(value: &str) -> Option<u16> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes.first() == Some(&b'0'))
        || bytes.iter().any(|byte| !byte.is_ascii_digit())
    {
        return None;
    }
    let port = value.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_CONFIG_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn config_arguments(contents: impl AsRef<[u8]>) -> Vec<OsString> {
        let sequence = TEST_CONFIG_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = fs::canonicalize(std::env::temp_dir()).expect("canonical test temp dir");
        let path = directory.join(format!(
            "paraegox-chat-config-test-{}-{sequence}.toml",
            std::process::id()
        ));
        fs::write(&path, contents).expect("write test chat config");
        vec![
            OsString::from(CHAT_COMMAND),
            OsString::from(CONFIG_OPTION),
            path.into_os_string(),
        ]
    }

    fn fixture_document(state_root: &str, fabric_listen: &str) -> String {
        format!(
            "schema_version = 1\nstate_root = {state_root:?}\nfabric_listen = {fabric_listen:?}\n\n[model]\nprovider = \"deterministic-echo-v1\"\n"
        )
    }

    fn provisioned_document(
        state_root: &str,
        fabric_listen: &str,
        provider: &str,
        model: Option<&str>,
        secret_ref: Option<&str>,
    ) -> String {
        let model = model
            .map(|value| format!("model = {value:?}\n"))
            .unwrap_or_default();
        let secret_ref = secret_ref
            .map(|value| format!("secret_ref = {value:?}\n"))
            .unwrap_or_default();
        format!(
            "schema_version = 1\nstate_root = {state_root:?}\nfabric_listen = {fabric_listen:?}\n\n[model]\nprovider = {provider:?}\n{model}{secret_ref}"
        )
    }

    fn valid_arguments() -> Vec<OsString> {
        config_arguments(fixture_document(
            "/tmp/paraegox-local-test",
            "tcp/127.0.0.1:7447",
        ))
    }

    fn valid_openai_arguments() -> Vec<OsString> {
        config_arguments(provisioned_document(
            "/tmp/paraegox-local-openai-test",
            "tcp/127.0.0.1:7448",
            OPENAI_RESPONSES_PROVIDER,
            Some("gpt-test-model"),
            Some(OPENAI_SECRET_REF),
        ))
    }

    fn valid_deepseek_arguments() -> Vec<OsString> {
        config_arguments(provisioned_document(
            "/tmp/paraegox-local-deepseek-test",
            "tcp/127.0.0.1:7449",
            DEEPSEEK_CHAT_COMPLETIONS_PROVIDER,
            Some("deepseek-v4-flash"),
            Some(DEEPSEEK_SECRET_REF),
        ))
    }

    fn valid_distributed_arguments() -> Vec<OsString> {
        [
            INTERNAL_DISTRIBUTED_FIXTURE_MODE,
            STATE_ROOT_OPTION,
            "/tmp/paraegox-local-distributed-test",
            FABRIC_LISTEN_A_OPTION,
            "tcp/127.0.0.1:7451",
            FABRIC_LISTEN_B_OPTION,
            "tcp/127.0.0.1:7452",
            PXRP_TLS_LISTENER_LOCATOR_A_OPTION,
            "tls/192.0.2.10:7461",
            PXRP_ROUTE_A_OPTION,
            "paraegox/runtime/target-a/apply",
            PXRP_ROOT_CA_CERTIFICATE_FILE_A_OPTION,
            "/nonexistent/paraegox/pxrp-a/root-ca.pem",
            PXRP_CONTROLLER_CLIENT_CERTIFICATE_FILE_A_OPTION,
            "/nonexistent/paraegox/pxrp-a/controller-client.pem",
            PXRP_CONTROLLER_CLIENT_PRIVATE_KEY_FILE_A_OPTION,
            "/nonexistent/paraegox/pxrp-a/controller-client.key",
            PXRP_RUNTIME_SERVER_CERTIFICATE_FILE_A_OPTION,
            "/nonexistent/paraegox/pxrp-a/runtime-server.pem",
            PXRP_RUNTIME_SERVER_PRIVATE_KEY_FILE_A_OPTION,
            "/nonexistent/paraegox/pxrp-a/runtime-server.key",
            FABRIC_TLS_LISTENER_LOCATOR_A_OPTION,
            "tls/192.0.2.10:7462",
            FABRIC_LOCAL_CREDENTIAL_REF_A_OPTION,
            "91919191919191919191919191919191",
            FABRIC_EXPECTED_PEER_COMMON_NAME_A_OPTION,
            "fabric-b.example.test",
            FABRIC_ROOT_CA_CERTIFICATE_FILE_A_OPTION,
            "/nonexistent/paraegox/fabric-a/root-ca.pem",
            FABRIC_LISTEN_CERTIFICATE_FILE_A_OPTION,
            "/nonexistent/paraegox/fabric-a/listen.pem",
            FABRIC_LISTEN_PRIVATE_KEY_FILE_A_OPTION,
            "/nonexistent/paraegox/fabric-a/listen.key",
            FABRIC_CONNECT_CERTIFICATE_FILE_A_OPTION,
            "/nonexistent/paraegox/fabric-a/connect.pem",
            FABRIC_CONNECT_PRIVATE_KEY_FILE_A_OPTION,
            "/nonexistent/paraegox/fabric-a/connect.key",
            PXRP_TLS_LISTENER_LOCATOR_B_OPTION,
            "tls/192.0.2.20:7461",
            PXRP_ROUTE_B_OPTION,
            "paraegox/runtime/target-b/apply",
            PXRP_ROOT_CA_CERTIFICATE_FILE_B_OPTION,
            "/nonexistent/paraegox/pxrp-b/root-ca.pem",
            PXRP_CONTROLLER_CLIENT_CERTIFICATE_FILE_B_OPTION,
            "/nonexistent/paraegox/pxrp-b/controller-client.pem",
            PXRP_CONTROLLER_CLIENT_PRIVATE_KEY_FILE_B_OPTION,
            "/nonexistent/paraegox/pxrp-b/controller-client.key",
            PXRP_RUNTIME_SERVER_CERTIFICATE_FILE_B_OPTION,
            "/nonexistent/paraegox/pxrp-b/runtime-server.pem",
            PXRP_RUNTIME_SERVER_PRIVATE_KEY_FILE_B_OPTION,
            "/nonexistent/paraegox/pxrp-b/runtime-server.key",
            FABRIC_TLS_LISTENER_LOCATOR_B_OPTION,
            "tls/192.0.2.20:7462",
            FABRIC_LOCAL_CREDENTIAL_REF_B_OPTION,
            "92929292929292929292929292929292",
            FABRIC_EXPECTED_PEER_COMMON_NAME_B_OPTION,
            "fabric-a.example.test",
            FABRIC_ROOT_CA_CERTIFICATE_FILE_B_OPTION,
            "/nonexistent/paraegox/fabric-b/root-ca.pem",
            FABRIC_LISTEN_CERTIFICATE_FILE_B_OPTION,
            "/nonexistent/paraegox/fabric-b/listen.pem",
            FABRIC_LISTEN_PRIVATE_KEY_FILE_B_OPTION,
            "/nonexistent/paraegox/fabric-b/listen.key",
            FABRIC_CONNECT_CERTIFICATE_FILE_B_OPTION,
            "/nonexistent/paraegox/fabric-b/connect.pem",
            FABRIC_CONNECT_PRIVATE_KEY_FILE_B_OPTION,
            "/nonexistent/paraegox/fabric-b/connect.key",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    fn valid_distributed_identity_init_arguments() -> Vec<OsString> {
        let mut arguments = valid_distributed_arguments();
        arguments[0] = OsString::from(INTERNAL_DISTRIBUTED_IDENTITY_INIT_MODE);
        arguments
    }

    fn remove_option(arguments: &mut Vec<OsString>, option: &str) {
        let index = arguments
            .iter()
            .position(|argument| argument.to_str() == Some(option))
            .expect("test option must exist");
        arguments.drain(index..index + 2);
    }

    fn replace_option_value(arguments: &mut [OsString], option: &str, value: &str) {
        let index = arguments
            .iter()
            .position(|argument| argument.to_str() == Some(option))
            .expect("test option must exist");
        arguments[index + 1] = OsString::from(value);
    }

    fn parse_fixture(arguments: Vec<OsString>) -> DeveloperFixtureConfigV1 {
        match parse(arguments).expect("valid developer fixture arguments") {
            Command::DeveloperFixtureV1(config) => config,
            Command::DeveloperDistributedFixtureV1(_) => {
                panic!("unexpected distributed fixture command")
            }
            Command::DeveloperProvisionedV1(_) => panic!("unexpected provisioned command"),
            Command::Help => panic!("unexpected help command"),
        }
    }

    fn parse_provisioned(arguments: Vec<OsString>) -> DeveloperProvisionedConfigV1 {
        match parse(arguments).expect("valid developer provisioned arguments") {
            Command::DeveloperProvisionedV1(config) => config,
            Command::DeveloperFixtureV1(_) => panic!("unexpected fixture command"),
            Command::DeveloperDistributedFixtureV1(_) => {
                panic!("unexpected distributed fixture command")
            }
            Command::Help => panic!("unexpected help command"),
        }
    }

    fn parse_distributed(arguments: Vec<OsString>) -> DeveloperDistributedFixtureConfigV1 {
        match parse(arguments).expect("valid developer distributed fixture arguments") {
            Command::DeveloperDistributedFixtureV1(config) => config,
            Command::DeveloperFixtureV1(_) => panic!("unexpected fixture command"),
            Command::DeveloperProvisionedV1(_) => panic!("unexpected provisioned command"),
            Command::Help => panic!("unexpected help command"),
        }
    }

    #[test]
    fn exact_chat_config_selects_fixed_non_production_fixture() {
        let config = parse_fixture(valid_arguments());

        assert_eq!(
            config.state_root(),
            std::path::Path::new("/tmp/paraegox-local-test")
        );
        assert_eq!(config.fabric_listen(), "tcp/127.0.0.1:7447");
        assert_eq!(
            config.profile().request_deadline_budget(),
            Duration::from_secs(30)
        );
        assert_eq!(
            config.profile().operation_timeout(),
            Duration::from_secs(30)
        );
        assert_eq!(config.profile().command_capacity(), 4);
    }

    #[test]
    fn exact_internal_distributed_fixture_selects_two_distinct_logical_nodes() {
        let config = parse_distributed(valid_distributed_arguments());

        assert_eq!(config.action(), DeveloperDistributedFixtureActionV1::Run);
        assert_eq!(
            config.state_root(),
            std::path::Path::new("/tmp/paraegox-local-distributed-test")
        );
        assert_eq!(config.fabric_listen_a(), "tcp/127.0.0.1:7451");
        assert_eq!(config.fabric_listen_b(), "tcp/127.0.0.1:7452");
        let [target_a, target_b] = config.targets();
        assert_eq!(
            target_a.pxrp().tls_listener_locator(),
            "tls/192.0.2.10:7461"
        );
        assert_eq!(target_a.pxrp().route(), "paraegox/runtime/target-a/apply");
        assert_eq!(
            target_a.pxrp().root_ca_certificate_file(),
            Path::new("/nonexistent/paraegox/pxrp-a/root-ca.pem")
        );
        assert_eq!(
            target_a.pxrp().controller_client_certificate_file(),
            Path::new("/nonexistent/paraegox/pxrp-a/controller-client.pem")
        );
        assert_eq!(
            target_a.pxrp().controller_client_private_key_file(),
            Path::new("/nonexistent/paraegox/pxrp-a/controller-client.key")
        );
        assert_eq!(
            target_a.pxrp().runtime_server_certificate_file(),
            Path::new("/nonexistent/paraegox/pxrp-a/runtime-server.pem")
        );
        assert_eq!(
            target_a.pxrp().runtime_server_private_key_file(),
            Path::new("/nonexistent/paraegox/pxrp-a/runtime-server.key")
        );
        assert_eq!(
            target_a.fabric().tls_listener_locator(),
            "tls/192.0.2.10:7462"
        );
        assert_eq!(
            target_a.fabric().local_credential_ref().as_bytes(),
            &[0x91; 16]
        );
        assert_eq!(
            target_a.fabric().expected_peer_common_name(),
            "fabric-b.example.test"
        );
        assert_eq!(
            target_a.fabric().root_ca_certificate_file(),
            Path::new("/nonexistent/paraegox/fabric-a/root-ca.pem")
        );
        assert_eq!(
            target_a.fabric().listen_certificate_file(),
            Path::new("/nonexistent/paraegox/fabric-a/listen.pem")
        );
        assert_eq!(
            target_a.fabric().listen_private_key_file(),
            Path::new("/nonexistent/paraegox/fabric-a/listen.key")
        );
        assert_eq!(
            target_a.fabric().connect_certificate_file(),
            Path::new("/nonexistent/paraegox/fabric-a/connect.pem")
        );
        assert_eq!(
            target_a.fabric().connect_private_key_file(),
            Path::new("/nonexistent/paraegox/fabric-a/connect.key")
        );
        assert_eq!(
            target_b.pxrp().tls_listener_locator(),
            "tls/192.0.2.20:7461"
        );
        assert_eq!(target_b.pxrp().route(), "paraegox/runtime/target-b/apply");
        assert_eq!(
            target_b.pxrp().root_ca_certificate_file(),
            Path::new("/nonexistent/paraegox/pxrp-b/root-ca.pem")
        );
        assert_eq!(
            target_b.pxrp().controller_client_certificate_file(),
            Path::new("/nonexistent/paraegox/pxrp-b/controller-client.pem")
        );
        assert_eq!(
            target_b.pxrp().controller_client_private_key_file(),
            Path::new("/nonexistent/paraegox/pxrp-b/controller-client.key")
        );
        assert_eq!(
            target_b.pxrp().runtime_server_certificate_file(),
            Path::new("/nonexistent/paraegox/pxrp-b/runtime-server.pem")
        );
        assert_eq!(
            target_b.pxrp().runtime_server_private_key_file(),
            Path::new("/nonexistent/paraegox/pxrp-b/runtime-server.key")
        );
        assert_eq!(
            target_b.fabric().tls_listener_locator(),
            "tls/192.0.2.20:7462"
        );
        assert_eq!(
            target_b.fabric().local_credential_ref().as_bytes(),
            &[0x92; 16]
        );
        assert_eq!(
            target_b.fabric().expected_peer_common_name(),
            "fabric-a.example.test"
        );
        assert_eq!(
            target_b.fabric().root_ca_certificate_file(),
            Path::new("/nonexistent/paraegox/fabric-b/root-ca.pem")
        );
        assert_eq!(
            target_b.fabric().listen_certificate_file(),
            Path::new("/nonexistent/paraegox/fabric-b/listen.pem")
        );
        assert_eq!(
            target_b.fabric().listen_private_key_file(),
            Path::new("/nonexistent/paraegox/fabric-b/listen.key")
        );
        assert_eq!(
            target_b.fabric().connect_certificate_file(),
            Path::new("/nonexistent/paraegox/fabric-b/connect.pem")
        );
        assert_eq!(
            target_b.fabric().connect_private_key_file(),
            Path::new("/nonexistent/paraegox/fabric-b/connect.key")
        );
        assert_eq!(
            config.profile().request_deadline_budget(),
            Duration::from_secs(30)
        );
        assert_eq!(
            config.profile().operation_timeout(),
            Duration::from_secs(30)
        );
        assert_eq!(config.profile().command_capacity(), 4);
    }

    #[test]
    fn hidden_identity_init_reuses_the_exact_distributed_configuration_parser() {
        let run = parse_distributed(valid_distributed_arguments());
        let initialize = parse_distributed(valid_distributed_identity_init_arguments());

        assert_eq!(run.action(), DeveloperDistributedFixtureActionV1::Run);
        assert_eq!(
            initialize.action(),
            DeveloperDistributedFixtureActionV1::InitializeIdentity
        );
        assert_eq!(initialize.state_root, run.state_root);
        assert_eq!(initialize.fabric_listen_a, run.fabric_listen_a);
        assert_eq!(initialize.fabric_listen_b, run.fabric_listen_b);
        assert_eq!(initialize.targets, run.targets);
        assert_eq!(initialize.profile, run.profile);
    }

    #[test]
    fn distributed_run_and_identity_init_have_one_parser_owner() {
        let source = include_str!("config.rs");
        let parser_definition = ["fn parse_developer_", "distributed_fixture_v1("].concat();
        let run_action = ["DeveloperDistributedFixtureActionV1::", "Run"].concat();
        let initialize_action = [
            "DeveloperDistributedFixtureActionV1::",
            "InitializeIdentity",
        ]
        .concat();
        assert_eq!(source.matches(&parser_definition).count(), 1);
        assert!(source.matches(&run_action).count() >= 3);
        assert!(source.matches(&initialize_action).count() >= 2);
    }

    #[test]
    fn exact_chat_config_selects_openai_with_fixed_provisioned_limits() {
        let config = parse_provisioned(valid_openai_arguments());

        assert_eq!(
            config.state_root(),
            std::path::Path::new("/tmp/paraegox-local-openai-test")
        );
        assert_eq!(config.fabric_listen(), "tcp/127.0.0.1:7448");
        assert_eq!(config.model(), "gpt-test-model");
        assert_eq!(
            config.secret_ref(),
            ProvisionedSecretRefV1::OpenAiApiKeyEnvironment
        );
        assert_eq!(
            config.provider_profile(),
            ProviderProfileV1::OpenAiResponsesV1
        );

        let provider_ref =
            ManagedAgentProviderRefV1::try_from_bytes([0x51; 16]).expect("test provider reference");
        let provider = config
            .provider_config(provider_ref)
            .expect("fixed provider config");
        let ProvisionedProviderConfigV1::OpenAi(provider) = provider else {
            panic!("OpenAI profile must build the OpenAI adapter configuration")
        };
        assert_eq!(provider.provider_ref(), provider_ref.as_bytes());
        assert_eq!(provider.model(), "gpt-test-model");
        assert_eq!(
            provider.timeout_nanos(),
            DEVELOPER_PROVISIONED_PROVIDER_TIMEOUT_NANOS
        );
        assert_eq!(
            provider.max_output_tokens(),
            DEVELOPER_PROVISIONED_MAX_OUTPUT_TOKENS
        );
        assert_eq!(
            provider.max_response_body_bytes(),
            DEVELOPER_PROVISIONED_MAX_RESPONSE_BODY_BYTES
        );
        assert_eq!(
            provider.max_output_text_bytes(),
            DEVELOPER_PROVISIONED_MAX_OUTPUT_TEXT_BYTES
        );
    }

    #[test]
    fn exact_chat_config_selects_current_deepseek_flash_adapter() {
        let config = parse_provisioned(valid_deepseek_arguments());

        assert_eq!(
            config.state_root(),
            std::path::Path::new("/tmp/paraegox-local-deepseek-test")
        );
        assert_eq!(config.fabric_listen(), "tcp/127.0.0.1:7449");
        assert_eq!(config.model(), "deepseek-v4-flash");
        assert_eq!(
            config.secret_ref(),
            ProvisionedSecretRefV1::DeepSeekApiKeyEnvironment
        );
        assert_eq!(
            config.provider_profile(),
            ProviderProfileV1::DeepSeekChatCompletionsV1
        );

        let provider_ref =
            ManagedAgentProviderRefV1::try_from_bytes([0x52; 16]).expect("test provider reference");
        let provider = config
            .provider_config(provider_ref)
            .expect("fixed DeepSeek provider config");
        let ProvisionedProviderConfigV1::DeepSeek(provider) = provider else {
            panic!("DeepSeek profile must build the DeepSeek adapter configuration")
        };
        assert_eq!(provider.provider_ref(), provider_ref.as_bytes());
        assert_eq!(provider.model(), DeepSeekChatModelV1::V4Flash);
        assert_eq!(
            provider.timeout_nanos(),
            DEVELOPER_PROVISIONED_PROVIDER_TIMEOUT_NANOS
        );
        assert_eq!(
            provider.max_output_tokens(),
            DEVELOPER_PROVISIONED_MAX_OUTPUT_TOKENS
        );
    }

    #[test]
    fn provisioned_model_is_required_bounded_and_provider_specific() {
        assert_eq!(
            ConfigError::MissingModel.message(),
            "the selected provisioned chat profile requires model in config"
        );
        assert!(!ConfigError::MissingModel.message().contains("--model"));
        assert_eq!(
            parse(config_arguments(provisioned_document(
                "/tmp/paraegox-local-openai-test",
                "tcp/127.0.0.1:7448",
                OPENAI_RESPONSES_PROVIDER,
                None,
                Some(OPENAI_SECRET_REF),
            ))),
            Err(ConfigError::MissingModel)
        );

        for invalid in ["", "gpt model", "gpt\nmodel"] {
            assert_eq!(
                parse(config_arguments(provisioned_document(
                    "/tmp/paraegox-local-openai-test",
                    "tcp/127.0.0.1:7448",
                    OPENAI_RESPONSES_PROVIDER,
                    Some(invalid),
                    Some(OPENAI_SECRET_REF),
                ))),
                Err(ConfigError::InvalidModel)
            );
        }

        let too_long = "m".repeat(MAX_OPENAI_RESPONSES_MODEL_BYTES + 1);
        assert_eq!(
            parse(config_arguments(provisioned_document(
                "/tmp/paraegox-local-openai-test",
                "tcp/127.0.0.1:7448",
                OPENAI_RESPONSES_PROVIDER,
                Some(&too_long),
                Some(OPENAI_SECRET_REF),
            ))),
            Err(ConfigError::InvalidModel)
        );

        for retired_or_unknown in ["deepseek-chat", "deepseek-reasoner", "deepseek-v5"] {
            assert_eq!(
                parse(config_arguments(provisioned_document(
                    "/tmp/paraegox-local-deepseek-test",
                    "tcp/127.0.0.1:7449",
                    DEEPSEEK_CHAT_COMPLETIONS_PROVIDER,
                    Some(retired_or_unknown),
                    Some(DEEPSEEK_SECRET_REF),
                ))),
                Err(ConfigError::InvalidModel)
            );
        }

        let pro = config_arguments(provisioned_document(
            "/tmp/paraegox-local-deepseek-test",
            "tcp/127.0.0.1:7449",
            DEEPSEEK_CHAT_COMPLETIONS_PROVIDER,
            Some("deepseek-v4-pro"),
            Some(DEEPSEEK_SECRET_REF),
        ));
        assert!(matches!(parse(pro), Ok(Command::DeveloperProvisionedV1(_))));
    }

    #[test]
    fn provider_secret_refs_are_exact_and_never_contain_api_key_values() {
        for (provider, model, secret_ref) in [
            (
                OPENAI_RESPONSES_PROVIDER,
                "gpt-test-model",
                DEEPSEEK_SECRET_REF,
            ),
            (
                DEEPSEEK_CHAT_COMPLETIONS_PROVIDER,
                "deepseek-v4-flash",
                OPENAI_SECRET_REF,
            ),
            (
                OPENAI_RESPONSES_PROVIDER,
                "gpt-test-model",
                "sk-secret-value",
            ),
        ] {
            assert_eq!(
                parse(config_arguments(provisioned_document(
                    "/tmp/paraegox-local-secret-test",
                    "tcp/127.0.0.1:7448",
                    provider,
                    Some(model),
                    Some(secret_ref),
                ))),
                Err(ConfigError::InvalidProviderConfiguration)
            );
        }
        assert_eq!(
            parse(config_arguments(provisioned_document(
                "/tmp/paraegox-local-secret-test",
                "tcp/127.0.0.1:7448",
                OPENAI_RESPONSES_PROVIDER,
                Some("gpt-test-model"),
                None,
            ))),
            Err(ConfigError::InvalidProviderConfiguration)
        );
        let fixture_with_secret = format!(
            "{}secret_ref = \"env:OPENAI_API_KEY\"\n",
            fixture_document(
                "/tmp/paraegox-local-fixture-secret-test",
                "tcp/127.0.0.1:7447"
            )
        );
        assert_eq!(
            parse(config_arguments(fixture_with_secret)),
            Err(ConfigError::InvalidProviderConfiguration)
        );
    }

    #[test]
    fn single_node_profiles_do_not_admit_distributed_transport_options() {
        for option in [
            PXRP_TLS_LISTENER_LOCATOR_A_OPTION,
            PXRP_ROOT_CA_CERTIFICATE_FILE_A_OPTION,
            FABRIC_TLS_LISTENER_LOCATOR_A_OPTION,
            FABRIC_LOCAL_CREDENTIAL_REF_A_OPTION,
            FABRIC_LISTEN_PRIVATE_KEY_FILE_A_OPTION,
        ] {
            let mut fixture = valid_arguments();
            fixture.extend([OsString::from(option), OsString::from("explicit-value")]);
            assert_eq!(parse(fixture), Err(ConfigError::UnknownOption));

            let mut openai = valid_openai_arguments();
            openai.extend([OsString::from(option), OsString::from("explicit-value")]);
            assert_eq!(parse(openai), Err(ConfigError::UnknownOption));

            let mut deepseek = valid_deepseek_arguments();
            deepseek.extend([OsString::from(option), OsString::from("explicit-value")]);
            assert_eq!(parse(deepseek), Err(ConfigError::UnknownOption));
        }
    }

    #[test]
    fn config_fields_are_order_independent() {
        let arguments = config_arguments(
            "fabric_listen = \"tcp/127.0.0.1:1\"\nstate_root = \"/var/tmp/paraegox\"\nschema_version = 1\n\n[model]\nprovider = \"deterministic-echo-v1\"\n",
        );

        let config = parse_fixture(arguments);
        assert_eq!(config.fabric_listen(), "tcp/127.0.0.1:1");

        let mut distributed = valid_distributed_arguments();
        let state_and_loopback_options = distributed.drain(1..7).collect::<Vec<_>>();
        distributed.extend(state_and_loopback_options);
        let config = parse_distributed(distributed);
        assert_eq!(config.fabric_listen_a(), "tcp/127.0.0.1:7451");
        assert_eq!(config.fabric_listen_b(), "tcp/127.0.0.1:7452");
    }

    #[test]
    fn help_is_explicit_and_accepts_no_extra_arguments() {
        assert_eq!(parse([OsString::from("--help")]), Ok(Command::Help));
        assert_eq!(parse([OsString::from("-h")]), Ok(Command::Help));
        assert_eq!(
            parse([OsString::from("--help"), OsString::from("extra")]),
            Err(ConfigError::UnexpectedHelpArgument)
        );
    }

    #[test]
    fn missing_and_unknown_modes_never_select_a_fallback() {
        assert_eq!(parse(Vec::<OsString>::new()), Err(ConfigError::MissingMode));
        assert_eq!(
            parse([OsString::from("production")]),
            Err(ConfigError::UnknownMode)
        );
        assert_eq!(
            parse([OsString::from("fixture-v1")]),
            Err(ConfigError::UnknownMode)
        );
        assert_eq!(
            parse([OsString::from("developer-fixture-v1")]),
            Err(ConfigError::UnknownMode)
        );
        assert_eq!(
            parse([OsString::from("developer-openai-v1")]),
            Err(ConfigError::UnknownMode)
        );
        assert_eq!(
            parse([OsString::from("developer-distributed-fixture-v1")]),
            Err(ConfigError::UnknownMode)
        );
    }

    #[test]
    fn chat_requires_exactly_one_config_path() {
        assert_eq!(
            parse([OsString::from(CHAT_COMMAND)]),
            Err(ConfigError::MissingConfigPath)
        );
        assert_eq!(
            parse([OsString::from(CHAT_COMMAND), OsString::from("fixture-v1"),]),
            Err(ConfigError::MissingConfigPath)
        );
        let mut extra = valid_arguments();
        extra.push(OsString::from("extra"));
        assert_eq!(parse(extra), Err(ConfigError::UnknownOption));
        assert_eq!(
            parse([OsString::from(CHAT_COMMAND), OsString::from(CONFIG_OPTION)]),
            Err(ConfigError::MissingConfigPath)
        );
    }

    #[test]
    fn top_level_config_fields_are_mandatory() {
        assert_eq!(
            parse(config_arguments(
                "schema_version = 1\nfabric_listen = \"tcp/127.0.0.1:7447\"\n[model]\nprovider = \"deterministic-echo-v1\"\n"
            )),
            Err(ConfigError::InvalidConfigDocument)
        );
        assert_eq!(
            parse(config_arguments(
                "schema_version = 1\nstate_root = \"/tmp/paraegox\"\n[model]\nprovider = \"deterministic-echo-v1\"\n"
            )),
            Err(ConfigError::InvalidConfigDocument)
        );
    }

    #[test]
    fn internal_distributed_state_root_and_both_fabric_listens_are_mandatory() {
        assert_eq!(
            parse([
                OsString::from(INTERNAL_DISTRIBUTED_FIXTURE_MODE),
                OsString::from(FABRIC_LISTEN_A_OPTION),
                OsString::from("tcp/127.0.0.1:7451"),
                OsString::from(FABRIC_LISTEN_B_OPTION),
                OsString::from("tcp/127.0.0.1:7452"),
            ]),
            Err(ConfigError::MissingStateRoot)
        );

        let mut missing_a = valid_distributed_arguments();
        missing_a.drain(3..5);
        assert_eq!(parse(missing_a), Err(ConfigError::MissingFabricListenA));

        let mut missing_b = valid_distributed_arguments();
        missing_b.drain(5..7);
        assert_eq!(parse(missing_b), Err(ConfigError::MissingFabricListenB));
    }

    #[test]
    fn internal_distributed_fabric_listens_are_individually_validated_and_distinct() {
        for (index, expected) in [
            (4, ConfigError::InvalidFabricListenA),
            (6, ConfigError::InvalidFabricListenB),
        ] {
            let mut arguments = valid_distributed_arguments();
            arguments[index] = OsString::from("tcp/0.0.0.0:7451");
            assert_eq!(parse(arguments), Err(expected));
        }

        let mut collision = valid_distributed_arguments();
        collision[6] = collision[4].clone();
        assert_eq!(parse(collision), Err(ConfigError::FabricListenCollision));
    }

    #[test]
    fn internal_distributed_transport_inputs_are_all_explicit_and_mandatory() {
        for (option, expected) in [
            (
                PXRP_TLS_LISTENER_LOCATOR_A_OPTION,
                ConfigError::MissingPxrpTlsListenerLocatorA,
            ),
            (
                PXRP_TLS_LISTENER_LOCATOR_B_OPTION,
                ConfigError::MissingPxrpTlsListenerLocatorB,
            ),
            (PXRP_ROUTE_A_OPTION, ConfigError::MissingPxrpRouteA),
            (PXRP_ROUTE_B_OPTION, ConfigError::MissingPxrpRouteB),
            (
                PXRP_ROOT_CA_CERTIFICATE_FILE_A_OPTION,
                ConfigError::MissingPxrpRootCaCertificateFileA,
            ),
            (
                PXRP_ROOT_CA_CERTIFICATE_FILE_B_OPTION,
                ConfigError::MissingPxrpRootCaCertificateFileB,
            ),
            (
                PXRP_CONTROLLER_CLIENT_CERTIFICATE_FILE_A_OPTION,
                ConfigError::MissingPxrpControllerClientCertificateFileA,
            ),
            (
                PXRP_CONTROLLER_CLIENT_CERTIFICATE_FILE_B_OPTION,
                ConfigError::MissingPxrpControllerClientCertificateFileB,
            ),
            (
                PXRP_CONTROLLER_CLIENT_PRIVATE_KEY_FILE_A_OPTION,
                ConfigError::MissingPxrpControllerClientPrivateKeyFileA,
            ),
            (
                PXRP_CONTROLLER_CLIENT_PRIVATE_KEY_FILE_B_OPTION,
                ConfigError::MissingPxrpControllerClientPrivateKeyFileB,
            ),
            (
                PXRP_RUNTIME_SERVER_CERTIFICATE_FILE_A_OPTION,
                ConfigError::MissingPxrpRuntimeServerCertificateFileA,
            ),
            (
                PXRP_RUNTIME_SERVER_CERTIFICATE_FILE_B_OPTION,
                ConfigError::MissingPxrpRuntimeServerCertificateFileB,
            ),
            (
                PXRP_RUNTIME_SERVER_PRIVATE_KEY_FILE_A_OPTION,
                ConfigError::MissingPxrpRuntimeServerPrivateKeyFileA,
            ),
            (
                PXRP_RUNTIME_SERVER_PRIVATE_KEY_FILE_B_OPTION,
                ConfigError::MissingPxrpRuntimeServerPrivateKeyFileB,
            ),
            (
                FABRIC_TLS_LISTENER_LOCATOR_A_OPTION,
                ConfigError::MissingFabricTlsListenerLocatorA,
            ),
            (
                FABRIC_TLS_LISTENER_LOCATOR_B_OPTION,
                ConfigError::MissingFabricTlsListenerLocatorB,
            ),
            (
                FABRIC_LOCAL_CREDENTIAL_REF_A_OPTION,
                ConfigError::MissingFabricLocalCredentialRefA,
            ),
            (
                FABRIC_LOCAL_CREDENTIAL_REF_B_OPTION,
                ConfigError::MissingFabricLocalCredentialRefB,
            ),
            (
                FABRIC_EXPECTED_PEER_COMMON_NAME_A_OPTION,
                ConfigError::MissingFabricExpectedPeerCommonNameA,
            ),
            (
                FABRIC_EXPECTED_PEER_COMMON_NAME_B_OPTION,
                ConfigError::MissingFabricExpectedPeerCommonNameB,
            ),
            (
                FABRIC_ROOT_CA_CERTIFICATE_FILE_A_OPTION,
                ConfigError::MissingFabricRootCaCertificateFileA,
            ),
            (
                FABRIC_ROOT_CA_CERTIFICATE_FILE_B_OPTION,
                ConfigError::MissingFabricRootCaCertificateFileB,
            ),
            (
                FABRIC_LISTEN_CERTIFICATE_FILE_A_OPTION,
                ConfigError::MissingFabricListenCertificateFileA,
            ),
            (
                FABRIC_LISTEN_CERTIFICATE_FILE_B_OPTION,
                ConfigError::MissingFabricListenCertificateFileB,
            ),
            (
                FABRIC_LISTEN_PRIVATE_KEY_FILE_A_OPTION,
                ConfigError::MissingFabricListenPrivateKeyFileA,
            ),
            (
                FABRIC_LISTEN_PRIVATE_KEY_FILE_B_OPTION,
                ConfigError::MissingFabricListenPrivateKeyFileB,
            ),
            (
                FABRIC_CONNECT_CERTIFICATE_FILE_A_OPTION,
                ConfigError::MissingFabricConnectCertificateFileA,
            ),
            (
                FABRIC_CONNECT_CERTIFICATE_FILE_B_OPTION,
                ConfigError::MissingFabricConnectCertificateFileB,
            ),
            (
                FABRIC_CONNECT_PRIVATE_KEY_FILE_A_OPTION,
                ConfigError::MissingFabricConnectPrivateKeyFileA,
            ),
            (
                FABRIC_CONNECT_PRIVATE_KEY_FILE_B_OPTION,
                ConfigError::MissingFabricConnectPrivateKeyFileB,
            ),
        ] {
            let mut arguments = valid_distributed_arguments();
            remove_option(&mut arguments, option);
            assert_eq!(parse(arguments), Err(expected), "missing {option}");
        }
    }

    #[test]
    fn distributed_pxrp_and_fabric_locators_are_canonical_and_pairwise_distinct() {
        for (option, expected) in [
            (
                PXRP_TLS_LISTENER_LOCATOR_A_OPTION,
                ConfigError::InvalidPxrpTlsListenerLocatorA,
            ),
            (
                PXRP_TLS_LISTENER_LOCATOR_B_OPTION,
                ConfigError::InvalidPxrpTlsListenerLocatorB,
            ),
            (
                FABRIC_TLS_LISTENER_LOCATOR_A_OPTION,
                ConfigError::InvalidFabricTlsListenerLocatorA,
            ),
            (
                FABRIC_TLS_LISTENER_LOCATOR_B_OPTION,
                ConfigError::InvalidFabricTlsListenerLocatorB,
            ),
        ] {
            let mut arguments = valid_distributed_arguments();
            replace_option_value(&mut arguments, option, "tls/127.0.0.1:7461");
            assert_eq!(parse(arguments), Err(expected), "invalid {option}");
        }

        for (option, duplicate) in [
            (PXRP_TLS_LISTENER_LOCATOR_B_OPTION, "tls/192.0.2.10:7461"),
            (FABRIC_TLS_LISTENER_LOCATOR_A_OPTION, "tls/192.0.2.10:7461"),
            (FABRIC_TLS_LISTENER_LOCATOR_B_OPTION, "tls/192.0.2.10:7462"),
        ] {
            let mut arguments = valid_distributed_arguments();
            replace_option_value(&mut arguments, option, duplicate);
            assert_eq!(
                parse(arguments),
                Err(ConfigError::DistributedTlsListenerLocatorCollision),
                "duplicate {option}"
            );
        }
    }

    #[test]
    fn distributed_pxrp_routes_match_the_contract_grammar() {
        for (option, expected) in [
            (PXRP_ROUTE_A_OPTION, ConfigError::InvalidPxrpRouteA),
            (PXRP_ROUTE_B_OPTION, ConfigError::InvalidPxrpRouteB),
        ] {
            for invalid in [
                "runtime/target/apply",
                "paraegox//target/apply",
                "paraegox/target/../apply",
                "paraegox/target/query",
                "paraegox/target/apply#fallback",
            ] {
                let mut arguments = valid_distributed_arguments();
                replace_option_value(&mut arguments, option, invalid);
                assert_eq!(parse(arguments), Err(expected), "accepted {invalid:?}");
            }
        }
    }

    #[test]
    fn distributed_fabric_refs_and_peer_common_names_are_explicit_and_distinct() {
        for (option, expected) in [
            (
                FABRIC_LOCAL_CREDENTIAL_REF_A_OPTION,
                ConfigError::InvalidFabricLocalCredentialRefA,
            ),
            (
                FABRIC_LOCAL_CREDENTIAL_REF_B_OPTION,
                ConfigError::InvalidFabricLocalCredentialRefB,
            ),
        ] {
            for invalid in [
                "00000000000000000000000000000000",
                "9191919191919191919191919191919",
                "9191919191919191919191919191919A",
            ] {
                let mut arguments = valid_distributed_arguments();
                replace_option_value(&mut arguments, option, invalid);
                assert_eq!(parse(arguments), Err(expected), "accepted {invalid:?}");
            }
        }
        let mut duplicate_ref = valid_distributed_arguments();
        replace_option_value(
            &mut duplicate_ref,
            FABRIC_LOCAL_CREDENTIAL_REF_B_OPTION,
            "91919191919191919191919191919191",
        );
        assert_eq!(
            parse(duplicate_ref),
            Err(ConfigError::FabricLocalCredentialRefCollision)
        );

        for (option, expected) in [
            (
                FABRIC_EXPECTED_PEER_COMMON_NAME_A_OPTION,
                ConfigError::InvalidFabricExpectedPeerCommonNameA,
            ),
            (
                FABRIC_EXPECTED_PEER_COMMON_NAME_B_OPTION,
                ConfigError::InvalidFabricExpectedPeerCommonNameB,
            ),
        ] {
            for invalid in ["", "Fabric.example", "-fabric.example", "fabric..example"] {
                let mut arguments = valid_distributed_arguments();
                replace_option_value(&mut arguments, option, invalid);
                assert_eq!(parse(arguments), Err(expected), "accepted {invalid:?}");
            }
        }
        let mut duplicate_cn = valid_distributed_arguments();
        replace_option_value(
            &mut duplicate_cn,
            FABRIC_EXPECTED_PEER_COMMON_NAME_B_OPTION,
            "fabric-b.example.test",
        );
        assert_eq!(
            parse(duplicate_cn),
            Err(ConfigError::FabricExpectedPeerCommonNameCollision)
        );
    }

    #[test]
    fn distributed_tls_paths_are_lexical_only_and_never_implicitly_reused() {
        for option in [
            PXRP_ROOT_CA_CERTIFICATE_FILE_A_OPTION,
            PXRP_ROOT_CA_CERTIFICATE_FILE_B_OPTION,
            PXRP_CONTROLLER_CLIENT_CERTIFICATE_FILE_A_OPTION,
            PXRP_CONTROLLER_CLIENT_CERTIFICATE_FILE_B_OPTION,
            PXRP_CONTROLLER_CLIENT_PRIVATE_KEY_FILE_A_OPTION,
            PXRP_CONTROLLER_CLIENT_PRIVATE_KEY_FILE_B_OPTION,
            PXRP_RUNTIME_SERVER_CERTIFICATE_FILE_A_OPTION,
            PXRP_RUNTIME_SERVER_CERTIFICATE_FILE_B_OPTION,
            PXRP_RUNTIME_SERVER_PRIVATE_KEY_FILE_A_OPTION,
            PXRP_RUNTIME_SERVER_PRIVATE_KEY_FILE_B_OPTION,
            FABRIC_ROOT_CA_CERTIFICATE_FILE_A_OPTION,
            FABRIC_ROOT_CA_CERTIFICATE_FILE_B_OPTION,
            FABRIC_LISTEN_CERTIFICATE_FILE_A_OPTION,
            FABRIC_LISTEN_CERTIFICATE_FILE_B_OPTION,
            FABRIC_LISTEN_PRIVATE_KEY_FILE_A_OPTION,
            FABRIC_LISTEN_PRIVATE_KEY_FILE_B_OPTION,
            FABRIC_CONNECT_CERTIFICATE_FILE_A_OPTION,
            FABRIC_CONNECT_CERTIFICATE_FILE_B_OPTION,
            FABRIC_CONNECT_PRIVATE_KEY_FILE_A_OPTION,
            FABRIC_CONNECT_PRIVATE_KEY_FILE_B_OPTION,
        ] {
            let mut arguments = valid_distributed_arguments();
            replace_option_value(&mut arguments, option, "relative/secret.pem");
            assert_eq!(
                parse(arguments),
                Err(ConfigError::InvalidTlsFilePath),
                "accepted {option}"
            );
        }
        for invalid in [
            "/",
            "/nonexistent/paraegox/",
            "/nonexistent//paraegox/key.pem",
            "/nonexistent/./paraegox/key.pem",
            "/nonexistent/../paraegox/key.pem",
            "/nonexistent/paraegox/key\n.pem",
        ] {
            let mut arguments = valid_distributed_arguments();
            replace_option_value(
                &mut arguments,
                FABRIC_CONNECT_PRIVATE_KEY_FILE_A_OPTION,
                invalid,
            );
            assert_eq!(
                parse(arguments),
                Err(ConfigError::InvalidTlsFilePath),
                "accepted {invalid:?}"
            );
        }
        let mut too_long = valid_distributed_arguments();
        replace_option_value(
            &mut too_long,
            FABRIC_CONNECT_PRIVATE_KEY_FILE_A_OPTION,
            &format!("/{}", "a".repeat(MAX_TLS_FILE_PATH_BYTES)),
        );
        assert_eq!(parse(too_long), Err(ConfigError::InvalidTlsFilePath));

        let mut exact_limit = valid_distributed_arguments();
        replace_option_value(
            &mut exact_limit,
            FABRIC_CONNECT_PRIVATE_KEY_FILE_A_OPTION,
            &format!("/{}", "a".repeat(MAX_TLS_FILE_PATH_BYTES - 1)),
        );
        assert!(parse(exact_limit).is_ok());

        let config = parse_distributed(valid_distributed_arguments());
        for target in config.targets() {
            assert_ne!(
                target.pxrp().root_ca_certificate_file(),
                target.fabric().root_ca_certificate_file()
            );
            assert_ne!(
                target.pxrp().runtime_server_certificate_file(),
                target.fabric().listen_certificate_file()
            );
            assert_ne!(
                target.pxrp().controller_client_certificate_file(),
                target.fabric().connect_certificate_file()
            );
        }
    }

    #[test]
    fn distributed_transport_debug_redacts_routes_refs_common_names_and_paths() {
        let config = parse_distributed(valid_distributed_arguments());
        let debug = format!("{config:?}");
        assert!(debug.contains("tls/192.0.2.10:7461"));
        for hidden in [
            "paraegox/runtime/target-a/apply",
            "91919191919191919191919191919191",
            "fabric-b.example.test",
            "/nonexistent/paraegox",
        ] {
            assert!(!debug.contains(hidden), "Debug exposed {hidden}");
        }
    }

    #[test]
    fn internal_distributed_fixture_admits_no_secret_nonce_or_model_inputs() {
        for option in [
            "--fabric-listen",
            "--model",
            "--identity",
            "--runtime-target",
            "--controller-key",
            "--authority-key",
            "--pxnb-token",
            "--pxob-token",
            "--nonce",
            "--endpoint-generation",
            "--registration-epoch",
            "--api-key",
            "--fabric-private-key",
            "--pxrp-private-key",
        ] {
            let mut arguments = valid_distributed_arguments();
            arguments.extend([OsString::from(option), OsString::from("unsafe-value")]);
            assert_eq!(
                parse(arguments),
                Err(ConfigError::UnknownOption),
                "unexpectedly admitted {option}"
            );
        }
    }

    #[test]
    fn config_duplicates_and_cli_or_hidden_option_errors_fail_closed() {
        assert_eq!(
            parse(config_arguments(
                "schema_version = 1\nstate_root = \"/tmp/one\"\nstate_root = \"/tmp/two\"\nfabric_listen = \"tcp/127.0.0.1:7447\"\n[model]\nprovider = \"deterministic-echo-v1\"\n"
            )),
            Err(ConfigError::InvalidConfigDocument)
        );

        let mut distributed_duplicate = valid_distributed_arguments();
        distributed_duplicate.extend([
            OsString::from(FABRIC_LISTEN_A_OPTION),
            OsString::from("tcp/127.0.0.1:7453"),
        ]);
        assert_eq!(
            parse(distributed_duplicate),
            Err(ConfigError::DuplicateOption)
        );
        for (option, value) in [
            (PXRP_ROUTE_A_OPTION, "paraegox/runtime/replacement/apply"),
            (
                FABRIC_LOCAL_CREDENTIAL_REF_A_OPTION,
                "93939393939393939393939393939393",
            ),
            (
                FABRIC_LISTEN_PRIVATE_KEY_FILE_B_OPTION,
                "/nonexistent/paraegox/replacement.key",
            ),
        ] {
            let mut arguments = valid_distributed_arguments();
            arguments.extend([OsString::from(option), OsString::from(value)]);
            assert_eq!(
                parse(arguments),
                Err(ConfigError::DuplicateOption),
                "duplicate {option}"
            );
        }

        let mut distributed_missing_value = valid_distributed_arguments();
        distributed_missing_value.push(OsString::from(FABRIC_CONNECT_PRIVATE_KEY_FILE_A_OPTION));
        assert_eq!(
            parse(distributed_missing_value),
            Err(ConfigError::MissingOptionValue)
        );

        let mut unknown = valid_arguments();
        unknown.extend([OsString::from("--provider"), OsString::from("production")]);
        assert_eq!(parse(unknown), Err(ConfigError::UnknownOption));

        assert_eq!(
            parse([
                OsString::from(CHAT_COMMAND),
                OsString::from(CONFIG_OPTION),
                OsString::from("relative.toml"),
            ]),
            Err(ConfigError::InvalidConfigPath)
        );
    }

    #[test]
    fn state_root_must_be_canonical_absolute_and_non_root() {
        for invalid in [
            "relative/path",
            "/",
            "/tmp/paraegox/",
            "/tmp//paraegox",
            "/tmp/./paraegox",
            "/tmp/../paraegox",
        ] {
            assert_eq!(
                parse(config_arguments(fixture_document(
                    invalid,
                    "tcp/127.0.0.1:7447"
                ))),
                Err(ConfigError::InvalidStateRoot),
                "unexpectedly accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn state_root_length_is_bounded_without_a_socket_suffix() {
        let too_long = format!("/{}", "a".repeat(MAX_STATE_ROOT_BYTES));
        assert_eq!(
            parse(config_arguments(fixture_document(
                &too_long,
                "tcp/127.0.0.1:7447"
            ))),
            Err(ConfigError::StateRootTooLong)
        );

        let exact = format!("/{}", "a".repeat(MAX_STATE_ROOT_BYTES - 1));
        let config = parse_fixture(config_arguments(fixture_document(
            &exact,
            "tcp/127.0.0.1:7447",
        )));
        assert_eq!(config.state_root().as_os_str().len(), MAX_STATE_ROOT_BYTES);
    }

    #[test]
    fn fabric_listen_requires_canonical_ipv4_loopback_tcp() {
        for invalid in [
            "tcp/localhost:7447",
            "tcp/0.0.0.0:7447",
            "tcp/127.0.0.2:7447",
            "tcp/[::1]:7447",
            "udp/127.0.0.1:7447",
            "tcp/127.0.0.1:",
            "tcp/127.0.0.1:0",
            "tcp/127.0.0.1:07447",
            "tcp/127.0.0.1:65536",
            "tcp/127.0.0.1:+7447",
            "tcp/127.0.0.1:7447/route",
        ] {
            assert_eq!(
                parse(config_arguments(fixture_document(
                    "/tmp/paraegox-local-test",
                    invalid
                ))),
                Err(ConfigError::InvalidFabricListen),
                "unexpectedly accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn chat_config_schema_is_strict_bounded_and_provider_closed() {
        let unknown_top_level = format!(
            "{}unexpected = true\n",
            fixture_document("/tmp/paraegox-local-strict-test", "tcp/127.0.0.1:7447")
        );
        assert_eq!(
            parse(config_arguments(unknown_top_level)),
            Err(ConfigError::InvalidConfigDocument)
        );
        assert_eq!(
            parse(config_arguments(
                "schema_version = 1\nstate_root = \"/tmp/paraegox-local-strict-test\"\nfabric_listen = \"tcp/127.0.0.1:7447\"\n[model]\nprovider = \"deterministic-echo-v1\"\napi_key = \"forbidden\"\n"
            )),
            Err(ConfigError::InvalidConfigDocument)
        );
        assert_eq!(
            parse(config_arguments(
                "schema_version = 2\nstate_root = \"/tmp/paraegox-local-strict-test\"\nfabric_listen = \"tcp/127.0.0.1:7447\"\n[model]\nprovider = \"deterministic-echo-v1\"\n"
            )),
            Err(ConfigError::UnsupportedConfigSchema)
        );
        assert_eq!(
            parse(config_arguments(provisioned_document(
                "/tmp/paraegox-local-strict-test",
                "tcp/127.0.0.1:7447",
                "unknown-provider-v1",
                None,
                None,
            ))),
            Err(ConfigError::UnknownProvider)
        );
        let fixture_with_model = format!(
            "{}model = \"must-not-exist\"\n",
            fixture_document("/tmp/paraegox-local-strict-test", "tcp/127.0.0.1:7447")
        );
        assert_eq!(
            parse(config_arguments(fixture_with_model)),
            Err(ConfigError::InvalidProviderConfiguration)
        );
        assert_eq!(
            parse(config_arguments(vec![
                b'x';
                MAX_CHAT_CONFIG_BYTES as usize + 1
            ])),
            Err(ConfigError::ConfigFileTooLarge)
        );

        let directory = fs::canonicalize(std::env::temp_dir()).expect("canonical temp dir");
        assert_eq!(
            parse([
                OsString::from(CHAT_COMMAND),
                OsString::from(CONFIG_OPTION),
                directory.into_os_string(),
            ]),
            Err(ConfigError::InvalidConfigPath)
        );
        assert_eq!(
            parse([
                OsString::from(CHAT_COMMAND),
                OsString::from(CONFIG_OPTION),
                OsString::from("/tmp/../tmp/config.toml"),
            ]),
            Err(ConfigError::InvalidConfigPath)
        );
    }

    #[cfg(unix)]
    #[test]
    fn chat_config_path_rejects_a_final_component_symlink() {
        use std::os::unix::fs::symlink;

        let arguments = config_arguments(fixture_document(
            "/tmp/paraegox-local-symlink-test",
            "tcp/127.0.0.1:7447",
        ));
        let target = PathBuf::from(arguments[2].clone());
        let link = target.with_extension("symlink.toml");
        symlink(&target, &link).expect("create test config symlink");

        let result = parse([
            OsString::from(CHAT_COMMAND),
            OsString::from(CONFIG_OPTION),
            link.clone().into_os_string(),
        ]);
        fs::remove_file(&link).expect("remove test config symlink");

        assert_eq!(result, Err(ConfigError::InvalidConfigPath));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_arguments_fail_before_mode_selection() {
        use std::os::unix::ffi::OsStringExt;

        assert_eq!(
            parse([OsString::from_vec(vec![0xff])]),
            Err(ConfigError::NonUtf8Argument)
        );
    }

    #[test]
    fn error_codes_and_messages_are_stable_and_do_not_echo_values() {
        let errors = [
            ConfigError::NonUtf8Argument,
            ConfigError::MissingMode,
            ConfigError::UnknownMode,
            ConfigError::MissingConfigPath,
            ConfigError::InvalidConfigPath,
            ConfigError::ConfigFileTooLarge,
            ConfigError::ConfigFileRead,
            ConfigError::InvalidConfigDocument,
            ConfigError::UnsupportedConfigSchema,
            ConfigError::UnknownProvider,
            ConfigError::InvalidProviderConfiguration,
            ConfigError::UnexpectedHelpArgument,
            ConfigError::UnknownOption,
            ConfigError::MissingOptionValue,
            ConfigError::DuplicateOption,
            ConfigError::MissingStateRoot,
            ConfigError::MissingFabricListenA,
            ConfigError::MissingFabricListenB,
            ConfigError::MissingPxrpTlsListenerLocatorA,
            ConfigError::MissingPxrpTlsListenerLocatorB,
            ConfigError::MissingPxrpRouteA,
            ConfigError::MissingPxrpRouteB,
            ConfigError::MissingPxrpRootCaCertificateFileA,
            ConfigError::MissingPxrpRootCaCertificateFileB,
            ConfigError::MissingPxrpControllerClientCertificateFileA,
            ConfigError::MissingPxrpControllerClientCertificateFileB,
            ConfigError::MissingPxrpControllerClientPrivateKeyFileA,
            ConfigError::MissingPxrpControllerClientPrivateKeyFileB,
            ConfigError::MissingPxrpRuntimeServerCertificateFileA,
            ConfigError::MissingPxrpRuntimeServerCertificateFileB,
            ConfigError::MissingPxrpRuntimeServerPrivateKeyFileA,
            ConfigError::MissingPxrpRuntimeServerPrivateKeyFileB,
            ConfigError::MissingFabricTlsListenerLocatorA,
            ConfigError::MissingFabricTlsListenerLocatorB,
            ConfigError::MissingFabricLocalCredentialRefA,
            ConfigError::MissingFabricLocalCredentialRefB,
            ConfigError::MissingFabricExpectedPeerCommonNameA,
            ConfigError::MissingFabricExpectedPeerCommonNameB,
            ConfigError::MissingFabricRootCaCertificateFileA,
            ConfigError::MissingFabricRootCaCertificateFileB,
            ConfigError::MissingFabricListenCertificateFileA,
            ConfigError::MissingFabricListenCertificateFileB,
            ConfigError::MissingFabricListenPrivateKeyFileA,
            ConfigError::MissingFabricListenPrivateKeyFileB,
            ConfigError::MissingFabricConnectCertificateFileA,
            ConfigError::MissingFabricConnectCertificateFileB,
            ConfigError::MissingFabricConnectPrivateKeyFileA,
            ConfigError::MissingFabricConnectPrivateKeyFileB,
            ConfigError::MissingModel,
            ConfigError::InvalidStateRoot,
            ConfigError::StateRootTooLong,
            ConfigError::InvalidFabricListen,
            ConfigError::InvalidFabricListenA,
            ConfigError::InvalidFabricListenB,
            ConfigError::FabricListenCollision,
            ConfigError::InvalidPxrpTlsListenerLocatorA,
            ConfigError::InvalidPxrpTlsListenerLocatorB,
            ConfigError::InvalidPxrpRouteA,
            ConfigError::InvalidPxrpRouteB,
            ConfigError::InvalidTlsFilePath,
            ConfigError::InvalidFabricTlsListenerLocatorA,
            ConfigError::InvalidFabricTlsListenerLocatorB,
            ConfigError::InvalidFabricLocalCredentialRefA,
            ConfigError::InvalidFabricLocalCredentialRefB,
            ConfigError::InvalidFabricExpectedPeerCommonNameA,
            ConfigError::InvalidFabricExpectedPeerCommonNameB,
            ConfigError::DistributedTlsListenerLocatorCollision,
            ConfigError::FabricLocalCredentialRefCollision,
            ConfigError::FabricExpectedPeerCommonNameCollision,
            ConfigError::InvalidModel,
        ];
        for error in errors {
            assert!(error.code().starts_with("PXLC-"));
            assert!(!error.message().is_empty());
            assert!(!error.message().contains("/tmp"));
        }
    }
}
