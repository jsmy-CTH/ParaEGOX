#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    ffi::OsString,
    fmt,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use ed25519_dalek::VerifyingKey;
use paraegox_fabric::RemoteTlsEndpoint;
#[cfg(unix)]
use paraegox_fabric::{
    ResolvedRemoteMtlsIdentityFiles, RestrictedNodeControlEndpointConfigV1,
    RestrictedNodeControlTransportPinsV1,
};
use paraegox_kernel::{
    digest::Digest32,
    identity::{PrincipalRef, RuntimeHostId},
};
use paraegox_model_adapters::{
    DeepSeekChatCompletionsProviderConfigV1, DeepSeekChatModelV1, MAX_OPENAI_RESPONSES_MODEL_BYTES,
    OpenAiResponsesProviderConfigV1,
};
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DistributedFabricCredentialRefV1, DistributedFabricTlsEndpointV1,
    DistributedFabricTrustAnchorRefV1, DistributedFabricTrustDomainRefV1,
    MAX_RESTRICTED_RUNTIME_APPLY_ROUTE_BYTES, RestrictedRuntimeApplyTransportProfileFieldsV1,
    RestrictedRuntimeApplyTransportProfileV1,
};
use paraegox_runtime_contracts::{
    managed_agent_stack_plan::{
        ManagedAgentProviderProfileV1, ManagedAgentProviderRefV1,
        ManagedAgentProviderSelectionV1, ManagedAgentStackPlanError,
    },
    managed_fabric_plan::ManagedFabricListenEndpointV1,
    managed_service::ManagedServiceId,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const CHAT_COMMAND: &str = "chat";
const NODE_COMMAND: &str = "node";
const DEPLOYMENT_COMMAND: &str = "deployment";
const CONFIG_OPTION: &str = "--config";
const DETERMINISTIC_ECHO_PROVIDER: &str = "deterministic-echo-v1";
const OPENAI_RESPONSES_PROVIDER: &str = "openai-responses-v1";
const DEEPSEEK_CHAT_COMPLETIONS_PROVIDER: &str = "deepseek-chat-completions-v1";
const OPENAI_SECRET_REF: &str = "env:OPENAI_API_KEY";
const DEEPSEEK_SECRET_REF: &str = "env:DEEPSEEK_API_KEY";
const CHAT_CONFIG_SCHEMA_VERSION: u16 = 1;
const NODE_CONFIG_SCHEMA_V1: u16 = 1;
const NODE_CONFIG_SCHEMA_V2: u16 = 2;
const NODE_CONFIG_SCHEMA_V3: u16 = 3;
const DEVELOPER_DEPLOYMENT_CONFIG_SCHEMA_V1: u16 = 1;
const DEVELOPER_DEPLOYMENT_CONFIG_SCHEMA_V2: u16 = 2;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_DEVELOPER_DEPLOYMENT_ARTIFACT_BYTES: u64 = 1024 * 1024;
const DEVELOPER_DEPLOYMENT_SIGNING_SEED_BYTES: u64 = 32;
const NODE_CONFIG_COMMITMENT_V1_DOMAIN: &[u8] = b"paraegox.local.developer-node-config.sha256.v1";
const NODE_CONFIG_COMMITMENT_V2_DOMAIN: &[u8] = b"paraegox.local.developer-node-config.sha256.v2";
const NODE_CONFIG_COMMITMENT_V3_DOMAIN: &[u8] = b"paraegox.local.developer-node-config.sha256.v3";
const NODE_MANAGED_AGENT_PROVIDER_REF_DOMAIN: &[u8] =
    b"paraegox.local.developer-node-managed-agent-provider-ref.sha256.v1";
const DETERMINISTIC_PROVIDER_CONFIG_DOMAIN: &[u8] =
    b"paraegox.local.developer-fixture-provider.config.sha256.v1";
const DETERMINISTIC_PROVIDER_PROFILE: &[u8] = b"deterministic-fixture-v1";
const DEVELOPER_AGENT_BOOTSTRAP_LIMITS_PROFILE: &str = "developer-agent-bootstrap-v1";
const NODE_CONTROL_ROUTE_CONFIG_DOMAIN: &[u8] =
    b"paraegox.local.developer-node-control-route-config.sha256.v1";
const DEVELOPER_NODE_OPERATION_TIMEOUT_NANOS: u64 = 30_000_000_000;
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
    DeveloperNodeV1(Box<DeveloperNodeConfigV1>),
    DeveloperDeploymentV1(Box<DeveloperDeploymentConfigV1>),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeveloperNodeConfigDocumentV1 {
    schema_version: u16,
    state_root: String,
    control: DeveloperNodeControlDocumentV1,
    restricted_runtime_apply: DeveloperNodeRestrictedRuntimeApplyDocumentV1,
    node_control: Option<DeveloperNodeRemoteControlDocumentV2>,
    managed_agent_bootstrap: Option<ManagedAgentBootstrapFixtureDocumentV3>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeveloperNodeControlDocumentV1 {
    installation_id: String,
    target: String,
    source_scope: String,
    writer: String,
    runtime_principal: String,
    controller_principal: String,
    authority_principal: String,
    controller_request_key_ref: String,
    runtime_response_key_ref: String,
    tenure_authority_ref: String,
    tenure_key_ref: String,
    enrollment_issuer_ref: String,
    controller_request_verification_key: String,
    tenure_verification_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeveloperNodeRestrictedRuntimeApplyDocumentV1 {
    endpoint_ref: String,
    endpoint_generation: u64,
    tls_listener_locator: String,
    route: String,
    trust_domain_ref: String,
    trust_anchor_ref: String,
    controller_connector_credential_ref: String,
    runtime_listener_credential_ref: String,
    control_transport_profile_ref: String,
    root_ca_certificate_file: String,
    runtime_listener_certificate_file: String,
    runtime_listener_private_key_file: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeveloperNodeRemoteControlDocumentV2 {
    endpoint_ref: String,
    endpoint_generation: u64,
    tls_listener_locator: String,
    route: String,
    trust_domain_ref: String,
    trust_anchor_ref: String,
    controller_connector_credential_ref: String,
    node_listener_credential_ref: String,
    control_transport_profile_ref: String,
    node_certificate_principal: String,
    root_ca_certificate_file: String,
    node_listener_certificate_file: String,
    node_listener_private_key_file: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedAgentBootstrapFixtureDocumentV3 {
    provider: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeveloperDeploymentConfigDocumentV1 {
    schema_version: u16,
    state_root: String,
    enrollment_artifact_file: String,
    enrollment_artifact_sha256: String,
    controller_signing_seed_file: String,
    authority_signing_seed_file: String,
    authority_state_directory: String,
    authority_socket_path: String,
    runtime_connector: DeveloperDeploymentConnectorDocumentV1,
    node_connector: DeveloperDeploymentConnectorDocumentV1,
    managed_agent_bootstrap: Option<DeveloperDeploymentAgentBootstrapDocumentV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeveloperDeploymentConnectorDocumentV1 {
    root_ca_certificate_file: String,
    client_certificate_file: String,
    client_private_key_file: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeveloperDeploymentAgentBootstrapDocumentV2 {
    fabric_service_id: String,
    agent_service_id: String,
    fabric_listen: String,
    limits_profile: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeveloperNodeConfigSchemaV1 {
    HostLocalV1,
    RemoteControlV2,
    ManagedAgentBootstrapV3,
}

impl DeveloperNodeConfigSchemaV1 {
    pub(crate) const fn wire_value(self) -> u16 {
        match self {
            Self::HostLocalV1 => NODE_CONFIG_SCHEMA_V1,
            Self::RemoteControlV2 => NODE_CONFIG_SCHEMA_V2,
            Self::ManagedAgentBootstrapV3 => NODE_CONFIG_SCHEMA_V3,
        }
    }
}

/// Strict, non-secret input for one host-local Runtime + NodeDaemon process.
/// Controller and Authority private signing material can never be represented
/// by this schema.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DeveloperNodeConfigV1 {
    schema: DeveloperNodeConfigSchemaV1,
    state_root: PathBuf,
    control: DeveloperNodeControlConfigV1,
    restricted_runtime_apply: DeveloperNodeRestrictedRuntimeApplyConfigV1,
    node_control: Option<DeveloperNodeRemoteControlConfigV2>,
    managed_agent_bootstrap: Option<ManagedAgentBootstrapFixtureV3>,
    config_commitment: [u8; 32],
}

impl fmt::Debug for DeveloperNodeConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperNodeConfigV1")
            .field("schema", &self.schema)
            .field("state_root", &self.state_root)
            .field("control", &self.control)
            .field("restricted_runtime_apply", &self.restricted_runtime_apply)
            .field("node_control", &self.node_control)
            .field("managed_agent_bootstrap", &self.managed_agent_bootstrap)
            .field("config_commitment", &"<redacted-digest>")
            .finish()
    }
}

impl DeveloperNodeConfigV1 {
    pub(crate) const fn schema(&self) -> DeveloperNodeConfigSchemaV1 {
        self.schema
    }

    pub(crate) fn state_root(&self) -> &Path {
        &self.state_root
    }

    pub(crate) const fn control(&self) -> &DeveloperNodeControlConfigV1 {
        &self.control
    }

    pub(crate) const fn restricted_runtime_apply(
        &self,
    ) -> &DeveloperNodeRestrictedRuntimeApplyConfigV1 {
        &self.restricted_runtime_apply
    }

    pub(crate) const fn node_control(&self) -> Option<&DeveloperNodeRemoteControlConfigV2> {
        self.node_control.as_ref()
    }

    pub(crate) const fn managed_agent_bootstrap(
        &self,
    ) -> Option<&ManagedAgentBootstrapFixtureV3> {
        self.managed_agent_bootstrap.as_ref()
    }

    pub(crate) const fn config_commitment(&self) -> [u8; 32] {
        self.config_commitment
    }
}

/// Exact non-secret deterministic provider selection enabled only by Node
/// schema v3. Service identities, endpoints and limits remain Deployment-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentBootstrapFixtureV3 {
    selection: ManagedAgentProviderSelectionV1,
}

impl ManagedAgentBootstrapFixtureV3 {
    pub(crate) const fn selection(self) -> ManagedAgentProviderSelectionV1 {
        self.selection
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DeveloperNodeControlConfigV1 {
    installation_id: [u8; 16],
    target: [u8; 16],
    source_scope: [u8; 16],
    writer: [u8; 16],
    runtime_principal: [u8; 16],
    controller_principal: [u8; 16],
    authority_principal: [u8; 16],
    controller_request_key_ref: [u8; 16],
    runtime_response_key_ref: [u8; 16],
    tenure_authority_ref: [u8; 16],
    tenure_key_ref: [u8; 16],
    enrollment_issuer_ref: [u8; 16],
    controller_request_verification_key: [u8; 32],
    tenure_verification_key: [u8; 32],
}

impl fmt::Debug for DeveloperNodeControlConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeveloperNodeControlConfigV1(<non-secret-pins>)")
    }
}

impl DeveloperNodeControlConfigV1 {
    pub(crate) const fn installation_id(&self) -> [u8; 16] {
        self.installation_id
    }
    pub(crate) const fn target(&self) -> [u8; 16] {
        self.target
    }
    pub(crate) const fn source_scope(&self) -> [u8; 16] {
        self.source_scope
    }
    pub(crate) const fn writer(&self) -> [u8; 16] {
        self.writer
    }
    pub(crate) const fn runtime_principal(&self) -> [u8; 16] {
        self.runtime_principal
    }
    pub(crate) const fn controller_principal(&self) -> [u8; 16] {
        self.controller_principal
    }
    pub(crate) const fn authority_principal(&self) -> [u8; 16] {
        self.authority_principal
    }
    pub(crate) const fn controller_request_key_ref(&self) -> [u8; 16] {
        self.controller_request_key_ref
    }
    pub(crate) const fn runtime_response_key_ref(&self) -> [u8; 16] {
        self.runtime_response_key_ref
    }
    pub(crate) const fn tenure_authority_ref(&self) -> [u8; 16] {
        self.tenure_authority_ref
    }
    pub(crate) const fn tenure_key_ref(&self) -> [u8; 16] {
        self.tenure_key_ref
    }
    pub(crate) const fn enrollment_issuer_ref(&self) -> [u8; 16] {
        self.enrollment_issuer_ref
    }
    pub(crate) const fn controller_request_verification_key(&self) -> [u8; 32] {
        self.controller_request_verification_key
    }
    pub(crate) const fn tenure_verification_key(&self) -> [u8; 32] {
        self.tenure_verification_key
    }

    fn runtime_identity_refs(&self) -> [[u8; 16]; 11] {
        [
            self.installation_id,
            self.target,
            self.source_scope,
            self.writer,
            self.runtime_principal,
            self.controller_principal,
            self.authority_principal,
            self.controller_request_key_ref,
            self.runtime_response_key_ref,
            self.tenure_authority_ref,
            self.tenure_key_ref,
        ]
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DeveloperNodeRestrictedRuntimeApplyConfigV1 {
    transport_profile: RestrictedRuntimeApplyTransportProfileV1,
    control_transport_profile_ref: [u8; 16],
    root_ca_certificate_file: PathBuf,
    runtime_listener_certificate_file: PathBuf,
    runtime_listener_private_key_file: PathBuf,
}

impl fmt::Debug for DeveloperNodeRestrictedRuntimeApplyConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperNodeRestrictedRuntimeApplyConfigV1")
            .field("transport_profile", &self.transport_profile)
            .field("control_transport_profile_ref", &"<non-secret-ref>")
            .field("credential_paths", &"<redacted-paths>")
            .finish()
    }
}

impl DeveloperNodeRestrictedRuntimeApplyConfigV1 {
    pub(crate) const fn transport_profile(&self) -> &RestrictedRuntimeApplyTransportProfileV1 {
        &self.transport_profile
    }
    pub(crate) const fn control_transport_profile_ref(&self) -> [u8; 16] {
        self.control_transport_profile_ref
    }
    pub(crate) fn root_ca_certificate_file(&self) -> &Path {
        &self.root_ca_certificate_file
    }
    pub(crate) fn runtime_listener_certificate_file(&self) -> &Path {
        &self.runtime_listener_certificate_file
    }
    pub(crate) fn runtime_listener_private_key_file(&self) -> &Path {
        &self.runtime_listener_private_key_file
    }
}

/// Node-owned listener input for the additive remote PXNR/PXNE/PXNS/PXNA
/// control path.
///
/// The route/config digest is derived once from the cross-host semantic pins;
/// it is not caller-provided and deliberately excludes role-local file paths.
/// Certificate and private-key values cannot be represented by this type.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DeveloperNodeRemoteControlConfigV2 {
    endpoint_ref: [u8; 16],
    endpoint_generation: u64,
    tls_listener_locator: RemoteTlsEndpoint,
    route: Box<str>,
    trust_domain_ref: DistributedFabricTrustDomainRefV1,
    trust_anchor_ref: DistributedFabricTrustAnchorRefV1,
    controller_connector_credential_ref: DistributedFabricCredentialRefV1,
    node_listener_credential_ref: DistributedFabricCredentialRefV1,
    control_transport_profile_ref: [u8; 16],
    node_certificate_principal: PrincipalRef,
    route_config_carrier_digest: Digest32,
    root_ca_certificate_file: PathBuf,
    node_listener_certificate_file: PathBuf,
    node_listener_private_key_file: PathBuf,
}

impl fmt::Debug for DeveloperNodeRemoteControlConfigV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperNodeRemoteControlConfigV2")
            .field("endpoint", &self.tls_listener_locator)
            .field("route", &"<owner-selected-route>")
            .field("semantic_pins", &"<non-secret-pins>")
            .field("credential_paths", &"<redacted-paths>")
            .finish()
    }
}

impl DeveloperNodeRemoteControlConfigV2 {
    pub(crate) const fn endpoint_ref(&self) -> [u8; 16] {
        self.endpoint_ref
    }

    pub(crate) const fn endpoint_generation(&self) -> u64 {
        self.endpoint_generation
    }

    pub(crate) fn tls_listener_locator(&self) -> &str {
        self.tls_listener_locator.as_str()
    }

    pub(crate) fn route(&self) -> &str {
        &self.route
    }

    pub(crate) const fn trust_domain_ref(&self) -> DistributedFabricTrustDomainRefV1 {
        self.trust_domain_ref
    }

    pub(crate) const fn trust_anchor_ref(&self) -> DistributedFabricTrustAnchorRefV1 {
        self.trust_anchor_ref
    }

    pub(crate) const fn controller_connector_credential_ref(
        &self,
    ) -> DistributedFabricCredentialRefV1 {
        self.controller_connector_credential_ref
    }

    pub(crate) const fn node_listener_credential_ref(&self) -> DistributedFabricCredentialRefV1 {
        self.node_listener_credential_ref
    }

    pub(crate) const fn control_transport_profile_ref(&self) -> [u8; 16] {
        self.control_transport_profile_ref
    }

    pub(crate) const fn node_certificate_principal(&self) -> PrincipalRef {
        self.node_certificate_principal
    }

    pub(crate) const fn route_config_carrier_digest(&self) -> Digest32 {
        self.route_config_carrier_digest
    }

    pub(crate) fn root_ca_certificate_file(&self) -> &Path {
        &self.root_ca_certificate_file
    }

    pub(crate) fn node_listener_certificate_file(&self) -> &Path {
        &self.node_listener_certificate_file
    }

    pub(crate) fn node_listener_private_key_file(&self) -> &Path {
        &self.node_listener_private_key_file
    }

    /// Reconstructs the exact Fabric listener configuration from already
    /// parsed pins. Local's credential metadata gate must run before this
    /// value is handed to Fabric.
    #[cfg(unix)]
    pub(crate) fn try_listener_config(
        &self,
        controller_principal: PrincipalRef,
    ) -> Result<RestrictedNodeControlEndpointConfigV1, ConfigError> {
        let identity = ResolvedRemoteMtlsIdentityFiles::try_new(
            self.node_listener_certificate_file.clone(),
            self.node_listener_private_key_file.clone(),
        )
        .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
        let pins = RestrictedNodeControlTransportPinsV1::try_new(
            controller_principal,
            self.route_config_carrier_digest,
            DEVELOPER_OPERATION_TIMEOUT,
        )
        .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
        RestrictedNodeControlEndpointConfigV1::try_new(
            self.tls_listener_locator.clone(),
            self.route.to_string(),
            self.root_ca_certificate_file.clone(),
            identity,
            pins,
        )
        .map_err(|_| ConfigError::InvalidNodeConfiguration)
    }
}

/// Strict local-only input for the public Deployment composition.
///
/// It intentionally contains only filesystem ownership inputs. Runtime/Node
/// endpoint, route, principal, trust and credential selectors are accepted
/// solely from the separately SHA-256-pinned enrollment artifact.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DeveloperDeploymentConfigV1 {
    schema: DeveloperDeploymentConfigSchemaV1,
    state_root: PathBuf,
    enrollment_artifact_file: PathBuf,
    enrollment_artifact_sha256: [u8; 32],
    controller_signing_seed_file: PathBuf,
    authority_signing_seed_file: PathBuf,
    authority_state_directory: PathBuf,
    authority_socket_path: PathBuf,
    runtime_connector: DeveloperDeploymentConnectorConfigV1,
    node_connector: DeveloperDeploymentConnectorConfigV1,
    managed_agent_bootstrap: Option<DeveloperDeploymentAgentBootstrapConfigV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeveloperDeploymentConfigSchemaV1 {
    EnrollmentV1,
    ManagedAgentBootstrapV2,
}

impl DeveloperDeploymentConfigSchemaV1 {
    pub(crate) const fn wire_value(self) -> u16 {
        match self {
            Self::EnrollmentV1 => DEVELOPER_DEPLOYMENT_CONFIG_SCHEMA_V1,
            Self::ManagedAgentBootstrapV2 => DEVELOPER_DEPLOYMENT_CONFIG_SCHEMA_V2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeveloperDeploymentAgentBootstrapLimitsProfileV1 {
    DeveloperAgentBootstrapV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeveloperDeploymentAgentBootstrapConfigV2 {
    fabric_service_id: ManagedServiceId,
    agent_service_id: ManagedServiceId,
    fabric_listen: ManagedFabricListenEndpointV1,
    limits_profile: DeveloperDeploymentAgentBootstrapLimitsProfileV1,
}

impl DeveloperDeploymentAgentBootstrapConfigV2 {
    pub(crate) const fn fabric_service_id(&self) -> ManagedServiceId {
        self.fabric_service_id
    }

    pub(crate) const fn agent_service_id(&self) -> ManagedServiceId {
        self.agent_service_id
    }

    pub(crate) const fn fabric_listen(&self) -> &ManagedFabricListenEndpointV1 {
        &self.fabric_listen
    }

    pub(crate) const fn limits_profile(
        &self,
    ) -> DeveloperDeploymentAgentBootstrapLimitsProfileV1 {
        self.limits_profile
    }
}

pub(crate) struct DeveloperDeploymentResolvedInputsV1 {
    enrollment_artifact: Box<[u8]>,
    controller_signing_seed: Zeroizing<[u8; 32]>,
    authority_signing_seed: Zeroizing<[u8; 32]>,
}

pub(crate) struct DeveloperDeploymentResolvedPartsV1 {
    pub(crate) enrollment_artifact: Box<[u8]>,
    pub(crate) controller_signing_seed: Zeroizing<[u8; 32]>,
    pub(crate) authority_signing_seed: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for DeveloperDeploymentResolvedInputsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeveloperDeploymentResolvedInputsV1(<artifact-and-secrets-redacted>)")
    }
}

impl DeveloperDeploymentResolvedInputsV1 {
    pub(crate) fn into_parts(self) -> DeveloperDeploymentResolvedPartsV1 {
        DeveloperDeploymentResolvedPartsV1 {
            enrollment_artifact: self.enrollment_artifact,
            controller_signing_seed: self.controller_signing_seed,
            authority_signing_seed: self.authority_signing_seed,
        }
    }
}

impl fmt::Debug for DeveloperDeploymentConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperDeploymentConfigV1")
            .field("schema_version", &self.schema.wire_value())
            .field("state_root", &self.state_root)
            .field("enrollment_artifact_sha256", &"<non-secret-pin>")
            .field("managed_agent_bootstrap", &self.managed_agent_bootstrap)
            .field("secret_and_connector_paths", &"<redacted-paths>")
            .finish()
    }
}

impl DeveloperDeploymentConfigV1 {
    pub(crate) const fn schema(&self) -> DeveloperDeploymentConfigSchemaV1 {
        self.schema
    }

    pub(crate) fn state_root(&self) -> &Path {
        &self.state_root
    }

    pub(crate) fn enrollment_artifact_file(&self) -> &Path {
        &self.enrollment_artifact_file
    }

    pub(crate) const fn enrollment_artifact_sha256(&self) -> [u8; 32] {
        self.enrollment_artifact_sha256
    }

    pub(crate) fn controller_signing_seed_file(&self) -> &Path {
        &self.controller_signing_seed_file
    }

    pub(crate) fn authority_signing_seed_file(&self) -> &Path {
        &self.authority_signing_seed_file
    }

    pub(crate) fn authority_state_directory(&self) -> &Path {
        &self.authority_state_directory
    }

    pub(crate) fn authority_socket_path(&self) -> &Path {
        &self.authority_socket_path
    }

    pub(crate) const fn runtime_connector(&self) -> &DeveloperDeploymentConnectorConfigV1 {
        &self.runtime_connector
    }

    pub(crate) const fn node_connector(&self) -> &DeveloperDeploymentConnectorConfigV1 {
        &self.node_connector
    }

    pub(crate) const fn managed_agent_bootstrap(
        &self,
    ) -> Option<&DeveloperDeploymentAgentBootstrapConfigV2> {
        self.managed_agent_bootstrap.as_ref()
    }

    /// Revalidates owner, mode, inode and independently pinned artifact bytes
    /// immediately before a future composition resolves any Secret or opens a
    /// connector. Parsing alone never turns paths into authority.
    #[cfg(test)]
    #[cfg(unix)]
    pub(crate) fn validate_current_user_files(&self) -> Result<(), ConfigError> {
        self.resolve_current_user_inputs().map(drop)
    }

    /// Resolves the three inputs Local must consume itself through the same
    /// owner/mode/inode gate used by validation. Connector files intentionally
    /// remain paths for Fabric's role-specific resolver.
    #[cfg(unix)]
    pub(crate) fn resolve_current_user_inputs(
        &self,
    ) -> Result<DeveloperDeploymentResolvedInputsV1, ConfigError> {
        let uid = nix::unistd::Uid::effective().as_raw();
        let gid = nix::unistd::Gid::effective().as_raw();
        let state_root_identity =
            validate_deployment_owned_directory(self.state_root(), uid, gid, 0o700)?;
        let authority_state_identity =
            validate_deployment_owned_directory(self.authority_state_directory(), uid, gid, 0o700)?;
        validate_distinct_deployment_owner_directories(
            state_root_identity,
            authority_state_identity,
        )?;
        validate_deployment_authority_socket_parent(self.authority_socket_path(), uid, gid)?;

        let artifact = open_validated_deployment_file(
            self.enrollment_artifact_file(),
            uid,
            gid,
            DeploymentFilePolicyV1::PublicPinnedArtifact,
        )?;
        let artifact_metadata = artifact
            .metadata()
            .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
        if artifact_metadata.len() == 0
            || artifact_metadata.len() > MAX_DEVELOPER_DEPLOYMENT_ARTIFACT_BYTES
        {
            return Err(ConfigError::InvalidDeploymentConfiguration);
        }
        let mut bytes = Vec::new();
        artifact
            .take(MAX_DEVELOPER_DEPLOYMENT_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
        let observed: [u8; 32] = Sha256::digest(&bytes).into();
        if observed != self.enrollment_artifact_sha256 {
            return Err(ConfigError::InvalidDeploymentConfiguration);
        }

        let controller_signing_seed =
            read_deployment_signing_seed(self.controller_signing_seed_file(), uid, gid)?;
        let authority_signing_seed =
            read_deployment_signing_seed(self.authority_signing_seed_file(), uid, gid)?;
        for connector in [self.runtime_connector(), self.node_connector()] {
            for certificate in [
                connector.root_ca_certificate_file(),
                connector.client_certificate_file(),
            ] {
                open_validated_deployment_file(
                    certificate,
                    uid,
                    gid,
                    DeploymentFilePolicyV1::PublicCredential,
                )?;
            }
            open_validated_deployment_file(
                connector.client_private_key_file(),
                uid,
                gid,
                DeploymentFilePolicyV1::Secret,
            )?;
        }

        let files = self.all_file_paths();
        for (index, left) in files.iter().enumerate() {
            let left = fs::symlink_metadata(left)
                .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
            if files[index + 1..].iter().any(|right| {
                fs::symlink_metadata(right)
                    .is_ok_and(|right| left.dev() == right.dev() && left.ino() == right.ino())
            }) {
                return Err(ConfigError::InvalidDeploymentConfiguration);
            }
        }
        Ok(DeveloperDeploymentResolvedInputsV1 {
            enrollment_artifact: bytes.into_boxed_slice(),
            controller_signing_seed,
            authority_signing_seed,
        })
    }

    fn all_file_paths(&self) -> [&Path; 9] {
        [
            self.enrollment_artifact_file(),
            self.controller_signing_seed_file(),
            self.authority_signing_seed_file(),
            self.runtime_connector.root_ca_certificate_file(),
            self.runtime_connector.client_certificate_file(),
            self.runtime_connector.client_private_key_file(),
            self.node_connector.root_ca_certificate_file(),
            self.node_connector.client_certificate_file(),
            self.node_connector.client_private_key_file(),
        ]
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DeveloperDeploymentConnectorConfigV1 {
    root_ca_certificate_file: PathBuf,
    client_certificate_file: PathBuf,
    client_private_key_file: PathBuf,
}

impl fmt::Debug for DeveloperDeploymentConnectorConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeveloperDeploymentConnectorConfigV1(<redacted-paths>)")
    }
}

impl DeveloperDeploymentConnectorConfigV1 {
    pub(crate) fn root_ca_certificate_file(&self) -> &Path {
        &self.root_ca_certificate_file
    }

    pub(crate) fn client_certificate_file(&self) -> &Path {
        &self.client_certificate_file
    }

    pub(crate) fn client_private_key_file(&self) -> &Path {
        &self.client_private_key_file
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum DeploymentFilePolicyV1 {
    PublicPinnedArtifact,
    PublicCredential,
    Secret,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeploymentDirectoryIdentityV1 {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn validate_distinct_deployment_owner_directories(
    state_root: DeploymentDirectoryIdentityV1,
    authority_state: DeploymentDirectoryIdentityV1,
) -> Result<(), ConfigError> {
    if state_root == authority_state {
        return Err(ConfigError::InvalidDeploymentConfiguration);
    }
    Ok(())
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
    InvalidNodeConfiguration,
    InvalidDeploymentConfiguration,
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
            Self::InvalidNodeConfiguration => "PXLC-NODE-CONFIG-INVALID",
            Self::InvalidDeploymentConfiguration => "PXLC-DEPLOYMENT-CONFIG-INVALID",
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
            Self::MissingConfigPath => "chat, node, and deployment require --config with one path",
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
            Self::InvalidNodeConfiguration => {
                "node config contains invalid or conflicting identity or transport pins"
            }
            Self::InvalidDeploymentConfiguration => {
                "deployment config contains invalid, aliased, unpinned, or insecure paths"
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
        NODE_COMMAND => parse_node(arguments),
        DEPLOYMENT_COMMAND => parse_deployment(arguments),
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
    let text = read_config_file(path)?;
    let document = toml::from_str::<DeveloperLocalConfigDocumentV1>(&text)
        .map_err(|_| ConfigError::InvalidConfigDocument)?;
    parse_chat_config_document(document)
}

fn parse_node(mut arguments: impl Iterator<Item = String>) -> Result<Command, ConfigError> {
    ensure_unix_developer_local()?;
    if arguments.next().as_deref() != Some(CONFIG_OPTION) {
        return Err(ConfigError::MissingConfigPath);
    }
    let path = arguments.next().ok_or(ConfigError::MissingConfigPath)?;
    if arguments.next().is_some() {
        return Err(ConfigError::UnknownOption);
    }
    let text = read_config_file(path)?;
    let document = toml::from_str::<DeveloperNodeConfigDocumentV1>(&text)
        .map_err(|_| ConfigError::InvalidConfigDocument)?;
    parse_node_config_document(document)
}

fn parse_deployment(mut arguments: impl Iterator<Item = String>) -> Result<Command, ConfigError> {
    ensure_unix_developer_local()?;
    if arguments.next().as_deref() != Some(CONFIG_OPTION) {
        return Err(ConfigError::MissingConfigPath);
    }
    let path = arguments.next().ok_or(ConfigError::MissingConfigPath)?;
    if arguments.next().is_some() {
        return Err(ConfigError::UnknownOption);
    }
    let text = read_config_file(path)?;
    parse_developer_deployment_config_toml_v1(&text)
        .map(|config| Command::DeveloperDeploymentV1(Box::new(config)))
}

fn read_config_file(path: String) -> Result<String, ConfigError> {
    let path = parse_config_path(path)?;
    let file = open_config_file(&path)?;
    let metadata = file.metadata().map_err(|_| ConfigError::ConfigFileRead)?;
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::ConfigFileTooLarge);
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::ConfigFileRead)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError::ConfigFileTooLarge);
    }
    String::from_utf8(bytes).map_err(|_| ConfigError::InvalidConfigDocument)
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

#[cfg(test)]
pub(crate) fn parse_node_config_toml_for_test(document: &str) -> Result<Command, ConfigError> {
    let document = toml::from_str::<DeveloperNodeConfigDocumentV1>(document)
        .map_err(|_| ConfigError::InvalidConfigDocument)?;
    parse_node_config_document(document)
}

/// Parses the public Deployment configuration without starting any owner.
/// Composition must call `resolve_current_user_inputs` immediately before
/// consuming the paths.
pub(crate) fn parse_developer_deployment_config_toml_v1(
    document: &str,
) -> Result<DeveloperDeploymentConfigV1, ConfigError> {
    ensure_unix_developer_local()?;
    let document = toml::from_str::<DeveloperDeploymentConfigDocumentV1>(document)
        .map_err(|_| ConfigError::InvalidConfigDocument)?;
    let schema = match (
        document.schema_version,
        document.managed_agent_bootstrap.is_some(),
    ) {
        (DEVELOPER_DEPLOYMENT_CONFIG_SCHEMA_V1, false) => {
            DeveloperDeploymentConfigSchemaV1::EnrollmentV1
        }
        (DEVELOPER_DEPLOYMENT_CONFIG_SCHEMA_V2, true) => {
            DeveloperDeploymentConfigSchemaV1::ManagedAgentBootstrapV2
        }
        (
            DEVELOPER_DEPLOYMENT_CONFIG_SCHEMA_V1 | DEVELOPER_DEPLOYMENT_CONFIG_SCHEMA_V2,
            _,
        ) => return Err(ConfigError::InvalidDeploymentConfiguration),
        _ => return Err(ConfigError::UnsupportedConfigSchema),
    };
    let state_root = parse_deployment_path(document.state_root)?;
    let enrollment_artifact_file = parse_deployment_path(document.enrollment_artifact_file)?;
    let enrollment_artifact_sha256 =
        parse_deployment_sha256_pin(&document.enrollment_artifact_sha256)?;
    let controller_signing_seed_file =
        parse_deployment_path(document.controller_signing_seed_file)?;
    let authority_signing_seed_file = parse_deployment_path(document.authority_signing_seed_file)?;
    let authority_state_directory = parse_deployment_path(document.authority_state_directory)?;
    let authority_socket_path = parse_deployment_path(document.authority_socket_path)?;
    let runtime_connector = parse_deployment_connector(document.runtime_connector)?;
    let node_connector = parse_deployment_connector(document.node_connector)?;
    let managed_agent_bootstrap = document
        .managed_agent_bootstrap
        .map(parse_deployment_agent_bootstrap)
        .transpose()?;
    let config = DeveloperDeploymentConfigV1 {
        schema,
        state_root,
        enrollment_artifact_file,
        enrollment_artifact_sha256,
        controller_signing_seed_file,
        authority_signing_seed_file,
        authority_state_directory,
        authority_socket_path,
        runtime_connector,
        node_connector,
        managed_agent_bootstrap,
    };
    let files = config.all_file_paths();
    let authority_socket_parent = config
        .authority_socket_path
        .parent()
        .ok_or(ConfigError::InvalidDeploymentConfiguration)?;
    if deployment_paths_overlap(&config.state_root, &config.authority_state_directory)
        || deployment_paths_overlap(&config.state_root, authority_socket_parent)
        || deployment_paths_overlap(&config.authority_state_directory, authority_socket_parent)
        || files
            .iter()
            .enumerate()
            .any(|(index, path)| files[index + 1..].contains(path))
        || files.iter().any(|path| {
            *path == config.state_root
                || *path == config.authority_state_directory
                || *path == config.authority_socket_path
        })
        || files
            .iter()
            .any(|path| deployment_paths_overlap(&config.state_root, path))
        || files
            .iter()
            .any(|path| deployment_paths_overlap(&config.authority_state_directory, path))
        || files
            .iter()
            .any(|path| deployment_paths_overlap(authority_socket_parent, path))
    {
        return Err(ConfigError::InvalidDeploymentConfiguration);
    }
    Ok(config)
}

fn deployment_paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn parse_deployment_connector(
    document: DeveloperDeploymentConnectorDocumentV1,
) -> Result<DeveloperDeploymentConnectorConfigV1, ConfigError> {
    Ok(DeveloperDeploymentConnectorConfigV1 {
        root_ca_certificate_file: parse_deployment_path(document.root_ca_certificate_file)?,
        client_certificate_file: parse_deployment_path(document.client_certificate_file)?,
        client_private_key_file: parse_deployment_path(document.client_private_key_file)?,
    })
}

fn parse_deployment_agent_bootstrap(
    document: DeveloperDeploymentAgentBootstrapDocumentV2,
) -> Result<DeveloperDeploymentAgentBootstrapConfigV2, ConfigError> {
    let fabric_service_id = ManagedServiceId::from_bytes(
        parse_nonzero_ref(&document.fabric_service_id)
            .ok_or(ConfigError::InvalidDeploymentConfiguration)?,
    );
    let agent_service_id = ManagedServiceId::from_bytes(
        parse_nonzero_ref(&document.agent_service_id)
            .ok_or(ConfigError::InvalidDeploymentConfiguration)?,
    );
    if fabric_service_id == agent_service_id {
        return Err(ConfigError::InvalidDeploymentConfiguration);
    }
    let fabric_listen = ManagedFabricListenEndpointV1::try_new(&document.fabric_listen)
        .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
    let limits_profile = match document.limits_profile.as_str() {
        DEVELOPER_AGENT_BOOTSTRAP_LIMITS_PROFILE => {
            DeveloperDeploymentAgentBootstrapLimitsProfileV1::DeveloperAgentBootstrapV1
        }
        _ => return Err(ConfigError::InvalidDeploymentConfiguration),
    };
    Ok(DeveloperDeploymentAgentBootstrapConfigV2 {
        fabric_service_id,
        agent_service_id,
        fabric_listen,
        limits_profile,
    })
}

fn parse_deployment_path(value: String) -> Result<PathBuf, ConfigError> {
    parse_tls_file_path(value).map_err(|_| ConfigError::InvalidDeploymentConfiguration)
}

fn parse_deployment_sha256_pin(value: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 {
        return Err(ConfigError::InvalidDeploymentConfiguration);
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] =
            (hex_nibble(pair[0]).ok_or(ConfigError::InvalidDeploymentConfiguration)? << 4)
                | hex_nibble(pair[1]).ok_or(ConfigError::InvalidDeploymentConfiguration)?;
    }
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(ConfigError::InvalidDeploymentConfiguration);
    }
    Ok(decoded)
}

fn parse_node_config_document(
    document: DeveloperNodeConfigDocumentV1,
) -> Result<Command, ConfigError> {
    let schema = match (
        document.schema_version,
        document.node_control.is_some(),
        document.managed_agent_bootstrap.is_some(),
    ) {
        (NODE_CONFIG_SCHEMA_V1, false, false) => DeveloperNodeConfigSchemaV1::HostLocalV1,
        (NODE_CONFIG_SCHEMA_V2, true, false) => DeveloperNodeConfigSchemaV1::RemoteControlV2,
        (NODE_CONFIG_SCHEMA_V3, true, true) => {
            DeveloperNodeConfigSchemaV1::ManagedAgentBootstrapV3
        }
        (NODE_CONFIG_SCHEMA_V1 | NODE_CONFIG_SCHEMA_V2 | NODE_CONFIG_SCHEMA_V3, _, _) => {
            return Err(ConfigError::InvalidNodeConfiguration);
        }
        _ => return Err(ConfigError::UnsupportedConfigSchema),
    };
    if document
        .managed_agent_bootstrap
        .as_ref()
        .is_some_and(|fixture| fixture.provider != DETERMINISTIC_ECHO_PROVIDER)
    {
        return Err(ConfigError::InvalidNodeConfiguration);
    }
    let state_root = parse_state_root(document.state_root)?;
    let control_document = document.control;
    let control = DeveloperNodeControlConfigV1 {
        installation_id: parse_node_ref(&control_document.installation_id)?,
        target: parse_node_ref(&control_document.target)?,
        source_scope: parse_node_ref(&control_document.source_scope)?,
        writer: parse_node_ref(&control_document.writer)?,
        runtime_principal: parse_node_ref(&control_document.runtime_principal)?,
        controller_principal: parse_node_ref(&control_document.controller_principal)?,
        authority_principal: parse_node_ref(&control_document.authority_principal)?,
        controller_request_key_ref: parse_node_ref(&control_document.controller_request_key_ref)?,
        runtime_response_key_ref: parse_node_ref(&control_document.runtime_response_key_ref)?,
        tenure_authority_ref: parse_node_ref(&control_document.tenure_authority_ref)?,
        tenure_key_ref: parse_node_ref(&control_document.tenure_key_ref)?,
        enrollment_issuer_ref: parse_node_ref(&control_document.enrollment_issuer_ref)?,
        controller_request_verification_key: parse_verification_key(
            &control_document.controller_request_verification_key,
        )?,
        tenure_verification_key: parse_verification_key(&control_document.tenure_verification_key)?,
    };
    let runtime_refs = control.runtime_identity_refs();
    if runtime_refs
        .iter()
        .enumerate()
        .any(|(index, value)| runtime_refs[index + 1..].iter().any(|other| value == other))
        || control.controller_request_verification_key == control.tenure_verification_key
    {
        return Err(ConfigError::InvalidNodeConfiguration);
    }

    let restricted = document.restricted_runtime_apply;
    let endpoint_ref = parse_node_ref(&restricted.endpoint_ref)?;
    let trust_domain_ref = DistributedFabricTrustDomainRefV1::try_from_bytes(parse_node_ref(
        &restricted.trust_domain_ref,
    )?)
    .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    let trust_anchor_ref = DistributedFabricTrustAnchorRefV1::try_from_bytes(parse_node_ref(
        &restricted.trust_anchor_ref,
    )?)
    .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    let controller_connector_credential_ref = DistributedFabricCredentialRefV1::try_from_bytes(
        parse_node_ref(&restricted.controller_connector_credential_ref)?,
    )
    .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    let runtime_listener_credential_ref = DistributedFabricCredentialRefV1::try_from_bytes(
        parse_node_ref(&restricted.runtime_listener_credential_ref)?,
    )
    .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    let transport_profile = RestrictedRuntimeApplyTransportProfileV1::try_new(
        RestrictedRuntimeApplyTransportProfileFieldsV1 {
            target: RuntimeHostId::from_bytes(control.target),
            endpoint_ref,
            endpoint_generation: restricted.endpoint_generation,
            tls_listener_locator: &restricted.tls_listener_locator,
            route: &restricted.route,
            trust_domain_ref,
            trust_anchor_ref,
            controller_connector_credential_ref,
            runtime_listener_credential_ref,
            controller_principal: PrincipalRef::from_bytes(control.controller_principal),
            runtime_principal: PrincipalRef::from_bytes(control.runtime_principal),
            operation_timeout_nanos: DEVELOPER_NODE_OPERATION_TIMEOUT_NANOS,
        },
    )
    .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    let restricted_runtime_apply = DeveloperNodeRestrictedRuntimeApplyConfigV1 {
        transport_profile,
        control_transport_profile_ref: parse_node_ref(&restricted.control_transport_profile_ref)?,
        root_ca_certificate_file: parse_tls_file_path(restricted.root_ca_certificate_file)?,
        runtime_listener_certificate_file: parse_tls_file_path(
            restricted.runtime_listener_certificate_file,
        )?,
        runtime_listener_private_key_file: parse_tls_file_path(
            restricted.runtime_listener_private_key_file,
        )?,
    };
    let node_control = document
        .node_control
        .map(|remote| parse_node_remote_control(remote, &control, &restricted_runtime_apply))
        .transpose()?;
    let config_commitment = developer_node_config_commitment(
        schema,
        &state_root,
        &control,
        &restricted_runtime_apply,
        node_control.as_ref(),
        document.managed_agent_bootstrap.as_ref(),
    );
    let managed_agent_bootstrap = document
        .managed_agent_bootstrap
        .map(|_| {
            developer_node_managed_agent_provider_selection(
                RuntimeHostId::from_bytes(control.target()),
                Digest32::from_bytes(config_commitment),
            )
            .map(|selection| ManagedAgentBootstrapFixtureV3 { selection })
            .map_err(|_| ConfigError::InvalidNodeConfiguration)
        })
        .transpose()?;
    Ok(Command::DeveloperNodeV1(Box::new(DeveloperNodeConfigV1 {
        schema,
        state_root,
        control,
        restricted_runtime_apply,
        node_control,
        managed_agent_bootstrap,
        config_commitment,
    })))
}

fn parse_node_remote_control(
    document: DeveloperNodeRemoteControlDocumentV2,
    control: &DeveloperNodeControlConfigV1,
    runtime: &DeveloperNodeRestrictedRuntimeApplyConfigV1,
) -> Result<DeveloperNodeRemoteControlConfigV2, ConfigError> {
    let endpoint_ref = parse_node_ref(&document.endpoint_ref)?;
    if document.endpoint_generation == 0 {
        return Err(ConfigError::InvalidNodeConfiguration);
    }
    let tls_listener_locator = RemoteTlsEndpoint::try_new(document.tls_listener_locator)
        .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    let route = document.route.into_boxed_str();
    let trust_domain_ref = DistributedFabricTrustDomainRefV1::try_from_bytes(parse_node_ref(
        &document.trust_domain_ref,
    )?)
    .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    let trust_anchor_ref = DistributedFabricTrustAnchorRefV1::try_from_bytes(parse_node_ref(
        &document.trust_anchor_ref,
    )?)
    .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    let controller_connector_credential_ref = DistributedFabricCredentialRefV1::try_from_bytes(
        parse_node_ref(&document.controller_connector_credential_ref)?,
    )
    .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    let node_listener_credential_ref = DistributedFabricCredentialRefV1::try_from_bytes(
        parse_node_ref(&document.node_listener_credential_ref)?,
    )
    .map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    let control_transport_profile_ref = parse_node_ref(&document.control_transport_profile_ref)?;
    let node_certificate_principal =
        PrincipalRef::from_bytes(parse_node_ref(&document.node_certificate_principal)?);
    let root_ca_certificate_file = parse_tls_file_path(document.root_ca_certificate_file)?;
    let node_listener_certificate_file =
        parse_tls_file_path(document.node_listener_certificate_file)?;
    let node_listener_private_key_file =
        parse_tls_file_path(document.node_listener_private_key_file)?;
    let node_paths = [
        &root_ca_certificate_file,
        &node_listener_certificate_file,
        &node_listener_private_key_file,
    ];
    let runtime_paths = [
        runtime.root_ca_certificate_file(),
        runtime.runtime_listener_certificate_file(),
        runtime.runtime_listener_private_key_file(),
    ];
    let semantic_refs = [
        endpoint_ref,
        *trust_domain_ref.as_bytes(),
        *trust_anchor_ref.as_bytes(),
        *controller_connector_credential_ref.as_bytes(),
        *node_listener_credential_ref.as_bytes(),
        control_transport_profile_ref,
        *node_certificate_principal.as_bytes(),
    ];
    if semantic_refs.iter().enumerate().any(|(index, value)| {
        semantic_refs[index + 1..]
            .iter()
            .any(|other| value == other)
    }) || semantic_refs.iter().any(|value| {
        control
            .runtime_identity_refs()
            .iter()
            .any(|existing| value == existing)
    }) || semantic_refs
        .iter()
        .any(|value| value == &control.enrollment_issuer_ref)
        || tls_listener_locator.as_str()
            == runtime.transport_profile().tls_listener_locator().as_str()
        || route.as_ref() == runtime.transport_profile().route()
        || node_paths
            .iter()
            .enumerate()
            .any(|(index, value)| node_paths[index + 1..].contains(value))
        || node_paths
            .iter()
            .any(|path| runtime_paths.contains(&path.as_path()))
    {
        return Err(ConfigError::InvalidNodeConfiguration);
    }
    let route_config_carrier_digest =
        developer_node_control_route_config_digest(&DeveloperNodeControlRouteConfigDigestInputV2 {
            endpoint_ref,
            endpoint_generation: document.endpoint_generation,
            tls_listener_locator: &tls_listener_locator,
            route: route.as_ref(),
            trust_domain_ref,
            trust_anchor_ref,
            controller_connector_credential_ref,
            node_listener_credential_ref,
            control_transport_profile_ref,
            controller_principal: PrincipalRef::from_bytes(control.controller_principal),
            node_certificate_principal,
        });
    let config = DeveloperNodeRemoteControlConfigV2 {
        endpoint_ref,
        endpoint_generation: document.endpoint_generation,
        tls_listener_locator,
        route,
        trust_domain_ref,
        trust_anchor_ref,
        controller_connector_credential_ref,
        node_listener_credential_ref,
        control_transport_profile_ref,
        node_certificate_principal,
        route_config_carrier_digest,
        root_ca_certificate_file,
        node_listener_certificate_file,
        node_listener_private_key_file,
    };
    #[cfg(unix)]
    {
        let listener =
            config.try_listener_config(PrincipalRef::from_bytes(control.controller_principal))?;
        if !listener.matches_transport_pins(
            config.route(),
            PrincipalRef::from_bytes(control.controller_principal),
            config.route_config_carrier_digest(),
        ) {
            return Err(ConfigError::InvalidNodeConfiguration);
        }
    }
    Ok(config)
}

fn parse_node_ref(value: &str) -> Result<[u8; 16], ConfigError> {
    parse_nonzero_ref(value).ok_or(ConfigError::InvalidNodeConfiguration)
}

fn parse_verification_key(value: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 {
        return Err(ConfigError::InvalidNodeConfiguration);
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0]).ok_or(ConfigError::InvalidNodeConfiguration)? << 4)
            | hex_nibble(pair[1]).ok_or(ConfigError::InvalidNodeConfiguration)?;
    }
    let key =
        VerifyingKey::from_bytes(&decoded).map_err(|_| ConfigError::InvalidNodeConfiguration)?;
    if key.is_weak() {
        return Err(ConfigError::InvalidNodeConfiguration);
    }
    Ok(decoded)
}

fn developer_node_config_commitment(
    schema: DeveloperNodeConfigSchemaV1,
    state_root: &Path,
    control: &DeveloperNodeControlConfigV1,
    restricted: &DeveloperNodeRestrictedRuntimeApplyConfigV1,
    node_control: Option<&DeveloperNodeRemoteControlConfigV2>,
    managed_agent_bootstrap: Option<&ManagedAgentBootstrapFixtureDocumentV3>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(match schema {
        DeveloperNodeConfigSchemaV1::HostLocalV1 => NODE_CONFIG_COMMITMENT_V1_DOMAIN,
        DeveloperNodeConfigSchemaV1::RemoteControlV2 => NODE_CONFIG_COMMITMENT_V2_DOMAIN,
        DeveloperNodeConfigSchemaV1::ManagedAgentBootstrapV3 => {
            NODE_CONFIG_COMMITMENT_V3_DOMAIN
        }
    });
    digest.update(schema.wire_value().to_be_bytes());
    update_node_commitment_field(&mut digest, state_root.as_os_str().as_encoded_bytes());
    for field in control.runtime_identity_refs() {
        digest.update(field);
    }
    digest.update(control.enrollment_issuer_ref);
    digest.update(control.controller_request_verification_key);
    digest.update(control.tenure_verification_key);
    update_node_commitment_field(&mut digest, restricted.transport_profile.canonical_wire());
    digest.update(restricted.control_transport_profile_ref);
    for path in [
        &restricted.root_ca_certificate_file,
        &restricted.runtime_listener_certificate_file,
        &restricted.runtime_listener_private_key_file,
    ] {
        update_node_commitment_field(&mut digest, path.as_os_str().as_encoded_bytes());
    }
    if let Some(node_control) = node_control {
        digest.update(node_control.route_config_carrier_digest.as_bytes());
        for path in [
            &node_control.root_ca_certificate_file,
            &node_control.node_listener_certificate_file,
            &node_control.node_listener_private_key_file,
        ] {
            update_node_commitment_field(&mut digest, path.as_os_str().as_encoded_bytes());
        }
    }
    if let Some(managed_agent_bootstrap) = managed_agent_bootstrap {
        update_node_commitment_field(
            &mut digest,
            managed_agent_bootstrap.provider.as_bytes(),
        );
    }
    digest.finalize().into()
}

pub(crate) fn deterministic_fixture_provider_configuration_digest() -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(DETERMINISTIC_PROVIDER_CONFIG_DOMAIN);
    digest.update(DETERMINISTIC_PROVIDER_PROFILE);
    Digest32::from_bytes(digest.finalize().into())
}

pub(crate) fn derive_developer_node_managed_agent_provider_ref(
    target: RuntimeHostId,
    node_config_commitment: Digest32,
    provider_config_digest: Digest32,
) -> Result<ManagedAgentProviderRefV1, ManagedAgentStackPlanError> {
    let mut digest = Sha256::new();
    digest.update(NODE_MANAGED_AGENT_PROVIDER_REF_DOMAIN);
    digest.update(NODE_CONFIG_SCHEMA_V3.to_be_bytes());
    digest.update(
        (ManagedAgentProviderProfileV1::DeterministicFixture as u16).to_be_bytes(),
    );
    digest.update(target.as_bytes());
    digest.update(node_config_commitment.as_bytes());
    digest.update(provider_config_digest.as_bytes());
    let derived: [u8; 32] = digest.finalize().into();
    ManagedAgentProviderRefV1::try_from_bytes(
        derived[..16]
            .try_into()
            .map_err(|_| ManagedAgentStackPlanError::InvalidProvider)?,
    )
}

fn developer_node_managed_agent_provider_selection(
    target: RuntimeHostId,
    node_config_commitment: Digest32,
) -> Result<ManagedAgentProviderSelectionV1, ManagedAgentStackPlanError> {
    let provider_config_digest = deterministic_fixture_provider_configuration_digest();
    let provider_ref = derive_developer_node_managed_agent_provider_ref(
        target,
        node_config_commitment,
        provider_config_digest,
    )?;
    ManagedAgentProviderSelectionV1::try_deterministic_fixture(
        provider_ref,
        provider_config_digest,
    )
}

struct DeveloperNodeControlRouteConfigDigestInputV2<'a> {
    endpoint_ref: [u8; 16],
    endpoint_generation: u64,
    tls_listener_locator: &'a RemoteTlsEndpoint,
    route: &'a str,
    trust_domain_ref: DistributedFabricTrustDomainRefV1,
    trust_anchor_ref: DistributedFabricTrustAnchorRefV1,
    controller_connector_credential_ref: DistributedFabricCredentialRefV1,
    node_listener_credential_ref: DistributedFabricCredentialRefV1,
    control_transport_profile_ref: [u8; 16],
    controller_principal: PrincipalRef,
    node_certificate_principal: PrincipalRef,
}

fn developer_node_control_route_config_digest(
    input: &DeveloperNodeControlRouteConfigDigestInputV2<'_>,
) -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(NODE_CONTROL_ROUTE_CONFIG_DOMAIN);
    digest.update(NODE_CONFIG_SCHEMA_V2.to_be_bytes());
    digest.update(input.endpoint_ref);
    digest.update(input.endpoint_generation.to_be_bytes());
    update_node_commitment_field(&mut digest, input.tls_listener_locator.as_str().as_bytes());
    update_node_commitment_field(&mut digest, input.route.as_bytes());
    for value in [
        input.trust_domain_ref.as_bytes(),
        input.trust_anchor_ref.as_bytes(),
        input.controller_connector_credential_ref.as_bytes(),
        input.node_listener_credential_ref.as_bytes(),
        &input.control_transport_profile_ref,
        input.controller_principal.as_bytes(),
        input.node_certificate_principal.as_bytes(),
    ] {
        digest.update(value);
    }
    digest.update(DEVELOPER_NODE_OPERATION_TIMEOUT_NANOS.to_be_bytes());
    Digest32::from_bytes(digest.finalize().into())
}

fn update_node_commitment_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u32::try_from(value.len())
            .expect("bounded node config field length fits u32")
            .to_be_bytes(),
    );
    digest.update(value);
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

#[cfg(unix)]
fn validate_deployment_path_chain(path: &Path) -> Result<(), ConfigError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current)
                    .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
                if metadata.file_type().is_symlink() {
                    return Err(ConfigError::InvalidDeploymentConfiguration);
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ConfigError::InvalidDeploymentConfiguration);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_validated_deployment_file(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    policy: DeploymentFilePolicyV1,
) -> Result<File, ConfigError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    validate_deployment_owned_private_parent(path, expected_uid, expected_gid)?;
    validate_deployment_path_chain(path)?;
    let before =
        fs::symlink_metadata(path).map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
    let opened = file
        .metadata()
        .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
    let after =
        fs::symlink_metadata(path).map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
    let valid_metadata = |metadata: &fs::Metadata| {
        let mode = metadata.mode() & 0o7777;
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == expected_uid
            && metadata.gid() == expected_gid
            && metadata.nlink() == 1
            && metadata.len() != 0
            && match policy {
                DeploymentFilePolicyV1::PublicPinnedArtifact
                | DeploymentFilePolicyV1::PublicCredential => {
                    mode & 0o022 == 0 && mode & 0o111 == 0 && mode & 0o400 != 0
                }
                DeploymentFilePolicyV1::Secret => mode == 0o600,
            }
    };
    if !valid_metadata(&before)
        || !valid_metadata(&opened)
        || !valid_metadata(&after)
        || before.dev() != opened.dev()
        || before.ino() != opened.ino()
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
    {
        return Err(ConfigError::InvalidDeploymentConfiguration);
    }
    Ok(file)
}

#[cfg(unix)]
fn read_deployment_signing_seed(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
    let mut file = open_validated_deployment_file(
        path,
        expected_uid,
        expected_gid,
        DeploymentFilePolicyV1::Secret,
    )?;
    if file
        .metadata()
        .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?
        .len()
        != DEVELOPER_DEPLOYMENT_SIGNING_SEED_BYTES
    {
        return Err(ConfigError::InvalidDeploymentConfiguration);
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    file.read_exact(&mut *seed)
        .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?
        != 0
    {
        return Err(ConfigError::InvalidDeploymentConfiguration);
    }
    Ok(seed)
}

#[cfg(unix)]
fn validate_deployment_owned_private_parent(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), ConfigError> {
    validate_deployment_owned_parent(path, expected_uid, expected_gid, 0o700)
}

#[cfg(unix)]
fn validate_deployment_authority_socket_parent(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), ConfigError> {
    validate_deployment_owned_parent(path, expected_uid, expected_gid, 0o2750)
}

#[cfg(unix)]
fn validate_deployment_owned_parent(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), ConfigError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(ConfigError::InvalidDeploymentConfiguration)?;
    validate_deployment_owned_directory(parent, expected_uid, expected_gid, expected_mode).map(drop)
}

#[cfg(unix)]
fn validate_deployment_owned_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<DeploymentDirectoryIdentityV1, ConfigError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    validate_deployment_path_chain(path)?;
    let before =
        fs::symlink_metadata(path).map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(path)
        .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
    let opened = directory
        .metadata()
        .map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
    let after =
        fs::symlink_metadata(path).map_err(|_| ConfigError::InvalidDeploymentConfiguration)?;
    let valid = |metadata: &fs::Metadata| {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == expected_uid
            && metadata.gid() == expected_gid
            && metadata.mode() & 0o7777 == expected_mode
    };
    if !valid(&before)
        || !valid(&opened)
        || !valid(&after)
        || before.dev() != opened.dev()
        || before.ino() != opened.ino()
        || before.nlink() != opened.nlink()
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.nlink() != opened.nlink()
    {
        return Err(ConfigError::InvalidDeploymentConfiguration);
    }
    Ok(DeploymentDirectoryIdentityV1 {
        device: opened.dev(),
        inode: opened.ino(),
    })
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
pub(crate) fn developer_node_config_for_test(state_root: &Path) -> DeveloperNodeConfigV1 {
    let state_root = state_root.to_str().expect("UTF-8 test state root");
    match parse_node_config_toml_for_test(&developer_node_document_for_test(state_root))
        .expect("valid developer node test config")
    {
        Command::DeveloperNodeV1(config) => *config,
        Command::DeveloperDeploymentV1(_)
        | Command::DeveloperFixtureV1(_)
        | Command::DeveloperDistributedFixtureV1(_)
        | Command::DeveloperProvisionedV1(_)
        | Command::Help => panic!("unexpected developer node test command"),
    }
}

#[cfg(test)]
pub(crate) fn developer_node_config_v2_for_test(state_root: &Path) -> DeveloperNodeConfigV1 {
    let state_root = state_root.to_str().expect("UTF-8 test state root");
    match parse_node_config_toml_for_test(&developer_node_document_v2_for_test(state_root))
        .expect("valid developer node v2 test config")
    {
        Command::DeveloperNodeV1(config) => *config,
        Command::DeveloperDeploymentV1(_)
        | Command::DeveloperFixtureV1(_)
        | Command::DeveloperDistributedFixtureV1(_)
        | Command::DeveloperProvisionedV1(_)
        | Command::Help => panic!("unexpected developer node v2 test command"),
    }
}

#[cfg(test)]
pub(crate) fn developer_node_config_v3_for_test(state_root: &Path) -> DeveloperNodeConfigV1 {
    let state_root = state_root.to_str().expect("UTF-8 test state root");
    match parse_node_config_toml_for_test(&developer_node_document_v3_for_test(state_root))
        .expect("valid developer node v3 test config")
    {
        Command::DeveloperNodeV1(config) => *config,
        Command::DeveloperDeploymentV1(_)
        | Command::DeveloperFixtureV1(_)
        | Command::DeveloperDistributedFixtureV1(_)
        | Command::DeveloperProvisionedV1(_)
        | Command::Help => panic!("unexpected developer node v3 test command"),
    }
}

#[cfg(test)]
pub(crate) fn developer_deployment_config_for_test(
    state_root: &Path,
) -> DeveloperDeploymentConfigV1 {
    let state_root = state_root.to_str().expect("UTF-8 Deployment state root");
    let external = format!("{state_root}-external");
    let document = format!(
        r#"schema_version = 1
state_root = {state_root:?}
enrollment_artifact_file = "{external}/input/enrollment-v1.pxea"
enrollment_artifact_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
controller_signing_seed_file = "{external}/secrets/controller.seed"
authority_signing_seed_file = "{external}/secrets/authority.seed"
authority_state_directory = "{external}/authority"
authority_socket_path = "{external}/authority-socket/authority.sock"

[runtime_connector]
root_ca_certificate_file = "{external}/runtime/root-ca.pem"
client_certificate_file = "{external}/runtime/controller.pem"
client_private_key_file = "{external}/runtime/controller-key.pem"

[node_connector]
root_ca_certificate_file = "{external}/node/root-ca.pem"
client_certificate_file = "{external}/node/controller.pem"
client_private_key_file = "{external}/node/controller-key.pem"
"#,
    );
    parse_developer_deployment_config_toml_v1(&document)
        .expect("valid Deployment layout test config")
}

#[cfg(test)]
pub(crate) fn developer_node_document_for_test(state_root: &str) -> String {
    format!(
        r#"schema_version = 1
state_root = {state_root:?}

[control]
installation_id = "01010101010101010101010101010101"
target = "02020202020202020202020202020202"
source_scope = "03030303030303030303030303030303"
writer = "04040404040404040404040404040404"
runtime_principal = "05050505050505050505050505050505"
controller_principal = "06060606060606060606060606060606"
authority_principal = "07070707070707070707070707070707"
controller_request_key_ref = "08080808080808080808080808080808"
runtime_response_key_ref = "09090909090909090909090909090909"
tenure_authority_ref = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
tenure_key_ref = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
enrollment_issuer_ref = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
controller_request_verification_key = "884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b"
tenure_verification_key = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"

[restricted_runtime_apply]
endpoint_ref = "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"
endpoint_generation = 1
tls_listener_locator = "tls/192.0.2.10:7448"
route = "paraegox/runtime/target-a/apply"
trust_domain_ref = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"
trust_anchor_ref = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
controller_connector_credential_ref = "10101010101010101010101010101010"
runtime_listener_credential_ref = "11111111111111111111111111111111"
control_transport_profile_ref = "12121212121212121212121212121212"
root_ca_certificate_file = "{state_root}/credentials/root-ca.pem"
runtime_listener_certificate_file = "{state_root}/credentials/runtime.pem"
runtime_listener_private_key_file = "{state_root}/credentials/runtime-key.pem"
"#
    )
}

#[cfg(test)]
pub(crate) fn developer_node_document_v2_for_test(state_root: &str) -> String {
    let legacy = developer_node_document_for_test(state_root).replacen(
        "schema_version = 1",
        "schema_version = 2",
        1,
    );
    format!(
        r#"{legacy}
[node_control]
endpoint_ref = "13131313131313131313131313131313"
endpoint_generation = 1
tls_listener_locator = "tls/192.0.2.10:7449"
route = "paraegox/node/control/v1"
trust_domain_ref = "14141414141414141414141414141414"
trust_anchor_ref = "15151515151515151515151515151515"
controller_connector_credential_ref = "16161616161616161616161616161616"
node_listener_credential_ref = "17171717171717171717171717171717"
control_transport_profile_ref = "18181818181818181818181818181818"
node_certificate_principal = "19191919191919191919191919191919"
root_ca_certificate_file = "{state_root}/credentials/node-root-ca.pem"
node_listener_certificate_file = "{state_root}/credentials/node.pem"
node_listener_private_key_file = "{state_root}/credentials/node-key.pem"
"#
    )
}

#[cfg(test)]
pub(crate) fn developer_node_document_v3_for_test(state_root: &str) -> String {
    let remote = developer_node_document_v2_for_test(state_root).replacen(
        "schema_version = 2",
        "schema_version = 3",
        1,
    );
    format!(
        r#"{remote}
[managed_agent_bootstrap]
provider = "deterministic-echo-v1"
"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;

    static TEST_CONFIG_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[cfg(unix)]
    struct DeploymentConfigFixture {
        root: PathBuf,
        artifact: Box<[u8]>,
    }

    #[cfg(unix)]
    impl DeploymentConfigFixture {
        fn new() -> Self {
            let sequence = TEST_CONFIG_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temporary_root =
                fs::canonicalize(std::env::temp_dir()).expect("canonical test temp dir");
            let root = temporary_root.join(format!(
                "paraegox-deployment-config-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("Deployment config test root");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("Deployment config test root mode");
            for child in [
                "state",
                "authority",
                "authority-socket",
                "input",
                "secrets",
                "runtime",
                "node",
            ] {
                let path = root.join(child);
                fs::create_dir(&path).expect("Deployment private directory");
                let mode = if child == "authority-socket" {
                    0o2750
                } else {
                    0o700
                };
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                    .expect("Deployment private directory mode");
            }
            let fixture = Self {
                root,
                artifact: b"canonical-public-enrollment-artifact-v1".as_slice().into(),
            };
            fixture.write_file(&fixture.artifact_path(), &fixture.artifact, 0o644);
            fixture.write_file(&fixture.controller_seed_path(), &[0x31; 32], 0o600);
            fixture.write_file(&fixture.authority_seed_path(), &[0x32; 32], 0o600);
            for path in [
                fixture.runtime_root_ca_path(),
                fixture.runtime_client_certificate_path(),
                fixture.node_root_ca_path(),
                fixture.node_client_certificate_path(),
            ] {
                fixture.write_file(&path, b"public-certificate", 0o644);
            }
            for path in [
                fixture.runtime_client_key_path(),
                fixture.node_client_key_path(),
            ] {
                fixture.write_file(&path, b"private-key-material", 0o600);
            }
            fixture
        }

        fn write_file(&self, path: &Path, bytes: &[u8], mode: u32) {
            fs::write(path, bytes).expect("Deployment fixture file");
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .expect("Deployment fixture file mode");
        }

        fn state_root(&self) -> PathBuf {
            self.root.join("state")
        }

        fn authority_state(&self) -> PathBuf {
            self.root.join("authority")
        }

        fn authority_socket(&self) -> PathBuf {
            self.root.join("authority-socket/authority.sock")
        }

        fn artifact_path(&self) -> PathBuf {
            self.root.join("input/enrollment-v1.pxea")
        }

        fn controller_seed_path(&self) -> PathBuf {
            self.root.join("secrets/controller.seed")
        }

        fn authority_seed_path(&self) -> PathBuf {
            self.root.join("secrets/authority.seed")
        }

        fn runtime_root_ca_path(&self) -> PathBuf {
            self.root.join("runtime/root-ca.pem")
        }

        fn runtime_client_certificate_path(&self) -> PathBuf {
            self.root.join("runtime/controller.pem")
        }

        fn runtime_client_key_path(&self) -> PathBuf {
            self.root.join("runtime/controller-key.pem")
        }

        fn node_root_ca_path(&self) -> PathBuf {
            self.root.join("node/root-ca.pem")
        }

        fn node_client_certificate_path(&self) -> PathBuf {
            self.root.join("node/controller.pem")
        }

        fn node_client_key_path(&self) -> PathBuf {
            self.root.join("node/controller-key.pem")
        }

        fn document(&self) -> String {
            let pin = Sha256::digest(&self.artifact)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!(
                r#"schema_version = 1
state_root = {:?}
enrollment_artifact_file = {:?}
enrollment_artifact_sha256 = {pin:?}
controller_signing_seed_file = {:?}
authority_signing_seed_file = {:?}
authority_state_directory = {:?}
authority_socket_path = {:?}

[runtime_connector]
root_ca_certificate_file = {:?}
client_certificate_file = {:?}
client_private_key_file = {:?}

[node_connector]
root_ca_certificate_file = {:?}
client_certificate_file = {:?}
client_private_key_file = {:?}
"#,
                self.state_root().to_str().expect("UTF-8 state root"),
                self.artifact_path().to_str().expect("UTF-8 artifact"),
                self.controller_seed_path().to_str().expect("UTF-8 seed"),
                self.authority_seed_path().to_str().expect("UTF-8 seed"),
                self.authority_state()
                    .to_str()
                    .expect("UTF-8 Authority state"),
                self.authority_socket()
                    .to_str()
                    .expect("UTF-8 Authority socket"),
                self.runtime_root_ca_path().to_str().expect("UTF-8 root CA"),
                self.runtime_client_certificate_path()
                    .to_str()
                    .expect("UTF-8 certificate"),
                self.runtime_client_key_path().to_str().expect("UTF-8 key"),
                self.node_root_ca_path().to_str().expect("UTF-8 root CA"),
                self.node_client_certificate_path()
                    .to_str()
                    .expect("UTF-8 certificate"),
                self.node_client_key_path().to_str().expect("UTF-8 key"),
            )
        }

        fn document_v2(&self) -> String {
            let enrollment = self.document().replacen(
                "schema_version = 1",
                "schema_version = 2",
                1,
            );
            format!(
                r#"{enrollment}
[managed_agent_bootstrap]
fabric_service_id = "31313131313131313131313131313131"
agent_service_id = "32323232323232323232323232323232"
fabric_listen = "tcp/127.0.0.1:7447"
limits_profile = "developer-agent-bootstrap-v1"
"#,
            )
        }
    }

    #[cfg(unix)]
    impl Drop for DeploymentConfigFixture {
        fn drop(&mut self) {
            assert!(self.root.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("paraegox-deployment-config-test-")
            }));
            fs::remove_dir_all(&self.root).expect("remove Deployment config fixture");
        }
    }

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

    fn node_config_arguments(contents: impl AsRef<[u8]>) -> Vec<OsString> {
        let sequence = TEST_CONFIG_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = fs::canonicalize(std::env::temp_dir()).expect("canonical test temp dir");
        let path = directory.join(format!(
            "paraegox-node-config-test-{}-{sequence}.toml",
            std::process::id()
        ));
        fs::write(&path, contents).expect("write test node config");
        vec![
            OsString::from(NODE_COMMAND),
            OsString::from(CONFIG_OPTION),
            path.into_os_string(),
        ]
    }

    fn deployment_config_arguments(contents: impl AsRef<[u8]>) -> Vec<OsString> {
        let sequence = TEST_CONFIG_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = fs::canonicalize(std::env::temp_dir()).expect("canonical test temp dir");
        let path = directory.join(format!(
            "paraegox-deployment-config-input-test-{}-{sequence}.toml",
            std::process::id()
        ));
        fs::write(&path, contents).expect("write test Deployment config");
        vec![
            OsString::from(DEPLOYMENT_COMMAND),
            OsString::from(CONFIG_OPTION),
            path.into_os_string(),
        ]
    }

    fn node_document(state_root: &str) -> String {
        developer_node_document_for_test(state_root)
    }

    fn parse_node_fixture(document: &str) -> DeveloperNodeConfigV1 {
        match parse_node_config_toml_for_test(document).expect("valid developer node config") {
            Command::DeveloperNodeV1(config) => *config,
            Command::DeveloperDeploymentV1(_)
            | Command::DeveloperFixtureV1(_)
            | Command::DeveloperDistributedFixtureV1(_)
            | Command::DeveloperProvisionedV1(_)
            | Command::Help => panic!("unexpected node command"),
        }
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
            Command::DeveloperNodeV1(_)
            | Command::DeveloperDeploymentV1(_)
            | Command::DeveloperDistributedFixtureV1(_) => {
                panic!("unexpected distributed fixture command")
            }
            Command::DeveloperProvisionedV1(_) => panic!("unexpected provisioned command"),
            Command::Help => panic!("unexpected help command"),
        }
    }

    fn parse_provisioned(arguments: Vec<OsString>) -> DeveloperProvisionedConfigV1 {
        match parse(arguments).expect("valid developer provisioned arguments") {
            Command::DeveloperProvisionedV1(config) => config,
            Command::DeveloperNodeV1(_)
            | Command::DeveloperDeploymentV1(_)
            | Command::DeveloperFixtureV1(_) => {
                panic!("unexpected fixture command")
            }
            Command::DeveloperDistributedFixtureV1(_) => {
                panic!("unexpected distributed fixture command")
            }
            Command::Help => panic!("unexpected help command"),
        }
    }

    fn parse_distributed(arguments: Vec<OsString>) -> DeveloperDistributedFixtureConfigV1 {
        match parse(arguments).expect("valid developer distributed fixture arguments") {
            Command::DeveloperDistributedFixtureV1(config) => config,
            Command::DeveloperNodeV1(_)
            | Command::DeveloperDeploymentV1(_)
            | Command::DeveloperFixtureV1(_) => {
                panic!("unexpected fixture command")
            }
            Command::DeveloperProvisionedV1(_) => panic!("unexpected provisioned command"),
            Command::Help => panic!("unexpected help command"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn deployment_config_is_path_only_strict_and_resolves_pinned_inputs() {
        let fixture = DeploymentConfigFixture::new();
        let document = fixture.document();
        assert!(matches!(
            parse(deployment_config_arguments(&document)),
            Ok(Command::DeveloperDeploymentV1(_))
        ));
        let mut extra = deployment_config_arguments(&document);
        extra.push(OsString::from("extra"));
        assert_eq!(parse(extra), Err(ConfigError::UnknownOption));
        let config =
            parse_developer_deployment_config_toml_v1(&document).expect("strict Deployment config");
        assert_eq!(config.state_root(), fixture.state_root());
        assert_eq!(config.enrollment_artifact_file(), fixture.artifact_path());
        let expected_artifact_sha256: [u8; 32] = Sha256::digest(&fixture.artifact).into();
        assert_eq!(
            config.enrollment_artifact_sha256(),
            expected_artifact_sha256
        );
        assert_eq!(
            config.controller_signing_seed_file(),
            fixture.controller_seed_path()
        );
        assert_eq!(
            config.authority_signing_seed_file(),
            fixture.authority_seed_path()
        );
        assert_eq!(
            config.authority_state_directory(),
            fixture.authority_state()
        );
        assert_eq!(config.authority_socket_path(), fixture.authority_socket());
        assert_eq!(
            config.runtime_connector().root_ca_certificate_file(),
            fixture.runtime_root_ca_path()
        );
        assert_eq!(
            config.node_connector().client_private_key_file(),
            fixture.node_client_key_path()
        );
        config
            .validate_current_user_files()
            .expect("Deployment input metadata gate");
        let resolved = config
            .resolve_current_user_inputs()
            .expect("Deployment pinned input resolver");
        let debug = format!("{config:?} {resolved:?}");
        assert!(!debug.contains("controller.seed"));
        assert!(!debug.contains("authority.seed"));
        assert!(!debug.contains("canonical-public-enrollment"));
        let parts = resolved.into_parts();
        assert_eq!(
            parts.enrollment_artifact.as_ref(),
            fixture.artifact.as_ref()
        );
        assert_eq!(&*parts.controller_signing_seed, &[0x31; 32]);
        assert_eq!(&*parts.authority_signing_seed, &[0x32; 32]);

        let unknown = document.replacen(
            "[runtime_connector]",
            "endpoint = \"tls/192.0.2.10:7448\"\nroute = \"paraegox/runtime/apply\"\nprincipal = \"forbidden\"\n\n[runtime_connector]",
            1,
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&unknown).unwrap_err(),
            ConfigError::InvalidConfigDocument
        );
        let relative = document.replace(
            &format!(
                "state_root = {:?}",
                fixture.state_root().to_str().expect("UTF-8 state root")
            ),
            "state_root = \"relative/deployment\"",
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&relative).unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );
        let uppercase_pin = document
            .lines()
            .map(|line| {
                if line.starts_with("enrollment_artifact_sha256 = ") {
                    format!("enrollment_artifact_sha256 = {:?}", "AA".repeat(32))
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&uppercase_pin).unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );
        let alias = document.replace(
            &format!(
                "authority_signing_seed_file = {:?}",
                fixture.authority_seed_path().to_str().expect("UTF-8 seed")
            ),
            &format!(
                "authority_signing_seed_file = {:?}",
                fixture.controller_seed_path().to_str().expect("UTF-8 seed")
            ),
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&alias).unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_config_v2_owns_only_exact_agent_bootstrap_desired_inputs() {
        let fixture = DeploymentConfigFixture::new();
        let v1 = fixture.document();
        let v2 = fixture.document_v2();
        let config = parse_developer_deployment_config_toml_v1(&v2)
            .expect("strict Deployment v2 config");
        assert_eq!(
            config.schema(),
            DeveloperDeploymentConfigSchemaV1::ManagedAgentBootstrapV2
        );
        let desired = config
            .managed_agent_bootstrap()
            .expect("schema v2 managed Agent desired inputs");
        assert_eq!(desired.fabric_service_id().as_bytes(), &[0x31; 16]);
        assert_eq!(desired.agent_service_id().as_bytes(), &[0x32; 16]);
        assert_eq!(desired.fabric_listen().as_str(), "tcp/127.0.0.1:7447");
        assert_eq!(
            desired.limits_profile(),
            DeveloperDeploymentAgentBootstrapLimitsProfileV1::DeveloperAgentBootstrapV1
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&v1.replacen(
                "schema_version = 1",
                "schema_version = 2",
                1,
            )),
            Err(ConfigError::InvalidDeploymentConfiguration)
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&v2.replacen(
                "schema_version = 2",
                "schema_version = 1",
                1,
            )),
            Err(ConfigError::InvalidDeploymentConfiguration)
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&v2.replacen(
                "schema_version = 2",
                "schema_version = 3",
                1,
            )),
            Err(ConfigError::UnsupportedConfigSchema)
        );
        for invalid in [
            v2.replace(
                "fabric_service_id = \"31313131313131313131313131313131\"",
                "fabric_service_id = \"00000000000000000000000000000000\"",
            ),
            v2.replace(
                "fabric_service_id = \"31313131313131313131313131313131\"",
                "fabric_service_id = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
            ),
            v2.replace(
                "agent_service_id = \"32323232323232323232323232323232\"",
                "agent_service_id = \"31313131313131313131313131313131\"",
            ),
            v2.replace("tcp/127.0.0.1:7447", "tcp/0.0.0.0:7447"),
            v2.replace("tcp/127.0.0.1:7447", "tcp/127.0.0.1:07447"),
            v2.replace(
                "developer-agent-bootstrap-v1",
                "developer-agent-bootstrap-v2",
            ),
        ] {
            assert_eq!(
                parse_developer_deployment_config_toml_v1(&invalid),
                Err(ConfigError::InvalidDeploymentConfiguration)
            );
        }
        let provider_injection = v2.replace(
            "limits_profile = \"developer-agent-bootstrap-v1\"",
            "limits_profile = \"developer-agent-bootstrap-v1\"\nprovider = \"deterministic-echo-v1\"",
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&provider_injection),
            Err(ConfigError::InvalidConfigDocument)
        );
    }

    #[cfg(unix)]
    #[test]
    fn agent_bootstrap_examples_parse_to_exact_versioned_projections() {
        let node = parse_node_fixture(include_str!(
            "../../../configs/paraegox-node.agent-bootstrap.example.toml"
        ));
        assert_eq!(
            node.schema(),
            DeveloperNodeConfigSchemaV1::ManagedAgentBootstrapV3
        );
        let provider = node
            .managed_agent_bootstrap()
            .expect("Node v3 example provider")
            .selection();
        assert_eq!(
            provider.profile(),
            ManagedAgentProviderProfileV1::DeterministicFixture
        );
        assert_eq!(provider.secret_ref(), None);

        let deployment = parse_developer_deployment_config_toml_v1(include_str!(
            "../../../configs/paraegox-deployment.agent-bootstrap.example.toml"
        ))
        .expect("Deployment v2 example");
        assert_eq!(
            deployment.schema(),
            DeveloperDeploymentConfigSchemaV1::ManagedAgentBootstrapV2
        );
        let desired = deployment
            .managed_agent_bootstrap()
            .expect("Deployment v2 example desired inputs");
        assert_eq!(desired.fabric_service_id().as_bytes(), &[0x20; 16]);
        assert_eq!(desired.agent_service_id().as_bytes(), &[0x21; 16]);
        assert_eq!(desired.fabric_listen().as_str(), "tcp/127.0.0.1:7447");
        assert_eq!(
            desired.limits_profile(),
            DeveloperDeploymentAgentBootstrapLimitsProfileV1::DeveloperAgentBootstrapV1
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_resolver_defers_stale_authority_socket_to_authority_owner() {
        let fixture = DeploymentConfigFixture::new();
        let listener = UnixListener::bind(fixture.authority_socket())
            .expect("bind stale Deployment Authority socket");
        fs::set_permissions(
            fixture.authority_socket(),
            fs::Permissions::from_mode(0o600),
        )
        .expect("stale Deployment Authority socket mode");
        drop(listener);
        assert!(
            fs::symlink_metadata(fixture.authority_socket())
                .expect("stale Deployment Authority socket metadata")
                .file_type()
                .is_socket()
        );

        let config = parse_developer_deployment_config_toml_v1(&fixture.document())
            .expect("strict Deployment config with stale Authority socket");
        config
            .resolve_current_user_inputs()
            .expect("resolver must defer the stale socket to the Authority owner");
        assert!(fixture.authority_socket().exists());
    }

    #[cfg(unix)]
    #[test]
    fn deployment_owner_directory_identity_rejects_same_inode() {
        let state_root = DeploymentDirectoryIdentityV1 {
            device: 7,
            inode: 11,
        };
        assert_eq!(
            validate_distinct_deployment_owner_directories(state_root, state_root).unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );
        assert!(
            validate_distinct_deployment_owner_directories(
                state_root,
                DeploymentDirectoryIdentityV1 {
                    device: 7,
                    inode: 12,
                },
            )
            .is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_config_rejects_owner_tree_overlap_during_parse() {
        let fixture = DeploymentConfigFixture::new();
        let document = fixture.document();
        let nested_authority = document.replace(
            &format!(
                "authority_state_directory = {:?}",
                fixture
                    .authority_state()
                    .to_str()
                    .expect("UTF-8 Authority state")
            ),
            &format!(
                "authority_state_directory = {:?}",
                fixture
                    .state_root()
                    .join("authority")
                    .to_str()
                    .expect("UTF-8 nested Authority")
            ),
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&nested_authority).unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );

        let ancestor_authority = document.replace(
            &format!(
                "authority_state_directory = {:?}",
                fixture
                    .authority_state()
                    .to_str()
                    .expect("UTF-8 Authority state")
            ),
            &format!(
                "authority_state_directory = {:?}",
                fixture
                    .root
                    .parent()
                    .expect("fixture parent")
                    .to_str()
                    .expect("UTF-8 parent")
            ),
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&ancestor_authority).unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );

        let nested_socket = document.replace(
            &format!(
                "authority_socket_path = {:?}",
                fixture
                    .authority_socket()
                    .to_str()
                    .expect("UTF-8 Authority socket")
            ),
            &format!(
                "authority_socket_path = {:?}",
                fixture
                    .state_root()
                    .join("authority/authority.sock")
                    .to_str()
                    .expect("UTF-8 nested socket")
            ),
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&nested_socket).unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );

        let nested_secret = document.replace(
            &format!(
                "controller_signing_seed_file = {:?}",
                fixture.controller_seed_path().to_str().expect("UTF-8 seed")
            ),
            &format!(
                "controller_signing_seed_file = {:?}",
                fixture
                    .state_root()
                    .join("controller.seed")
                    .to_str()
                    .expect("UTF-8 nested seed")
            ),
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&nested_secret).unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );

        let authority_store_secret = document.replace(
            &format!(
                "controller_signing_seed_file = {:?}",
                fixture.controller_seed_path().to_str().expect("UTF-8 seed")
            ),
            &format!(
                "controller_signing_seed_file = {:?}",
                fixture
                    .authority_state()
                    .join("controller.seed")
                    .to_str()
                    .expect("UTF-8 Authority store seed")
            ),
        );
        assert_eq!(
            parse_developer_deployment_config_toml_v1(&authority_store_secret).unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_resolver_rejects_modes_writable_parents_digest_and_inode_aliases() {
        let fixture = DeploymentConfigFixture::new();
        let config = parse_developer_deployment_config_toml_v1(&fixture.document())
            .expect("strict Deployment config");

        fs::set_permissions(
            fixture.controller_seed_path(),
            fs::Permissions::from_mode(0o644),
        )
        .expect("broaden Controller seed");
        assert_eq!(
            config.resolve_current_user_inputs().unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );
        fs::set_permissions(
            fixture.controller_seed_path(),
            fs::Permissions::from_mode(0o600),
        )
        .expect("restore Controller seed");

        fs::set_permissions(
            fixture.root.join("secrets"),
            fs::Permissions::from_mode(0o770),
        )
        .expect("broaden secret parent");
        assert_eq!(
            config.resolve_current_user_inputs().unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );
        fs::set_permissions(
            fixture.root.join("secrets"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("restore secret parent");

        fs::set_permissions(
            fixture.root.join("runtime"),
            fs::Permissions::from_mode(0o707),
        )
        .expect("broaden connector parent");
        assert_eq!(
            config.resolve_current_user_inputs().unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );
        fs::set_permissions(
            fixture.root.join("runtime"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("restore connector parent");

        fs::set_permissions(
            fixture.root.join("authority-socket"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("remove Authority socket setgid/group-read contract");
        assert_eq!(
            config.resolve_current_user_inputs().unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );
        fs::set_permissions(
            fixture.root.join("authority-socket"),
            fs::Permissions::from_mode(0o2750),
        )
        .expect("restore Authority socket parent contract");

        fs::write(fixture.artifact_path(), b"field-tampered-public-artifact")
            .expect("tamper artifact");
        assert_eq!(
            config.resolve_current_user_inputs().unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );

        let alias_fixture = DeploymentConfigFixture::new();
        let alias_config = parse_developer_deployment_config_toml_v1(&alias_fixture.document())
            .expect("alias Deployment config");
        fs::remove_file(alias_fixture.authority_seed_path()).expect("remove Authority seed");
        fs::hard_link(
            alias_fixture.controller_seed_path(),
            alias_fixture.authority_seed_path(),
        )
        .expect("alias signing seeds");
        assert_eq!(
            alias_config.resolve_current_user_inputs().unwrap_err(),
            ConfigError::InvalidDeploymentConfiguration
        );
    }

    #[test]
    fn exact_node_config_selects_only_split_trust_host_local_inputs() {
        let document = node_document("/var/tmp/paraegox-node-test");
        let config = parse_node_fixture(&document);
        assert_eq!(
            config.state_root(),
            Path::new("/var/tmp/paraegox-node-test")
        );
        assert_eq!(config.control().target(), [0x02; 16]);
        assert_eq!(config.control().controller_request_key_ref(), [0x08; 16]);
        assert_eq!(config.control().runtime_response_key_ref(), [0x09; 16]);
        assert_eq!(config.control().enrollment_issuer_ref(), [0x0c; 16]);
        assert_ne!(config.config_commitment(), [0; 32]);
        assert_eq!(
            config
                .restricted_runtime_apply()
                .transport_profile()
                .tls_listener_locator()
                .as_str(),
            "tls/192.0.2.10:7448"
        );
        assert!(matches!(
            parse(node_config_arguments(document)),
            Ok(Command::DeveloperNodeV1(_))
        ));
    }

    #[test]
    fn node_config_v2_adds_only_typed_remote_control_listener_inputs() {
        let document = developer_node_document_v2_for_test("/var/tmp/paraegox-node-v2-test");
        let config = parse_node_fixture(&document);
        assert_eq!(
            config.schema(),
            DeveloperNodeConfigSchemaV1::RemoteControlV2
        );
        let remote = config.node_control().expect("schema v2 node control");
        assert_eq!(remote.endpoint_ref(), [0x13; 16]);
        assert_eq!(remote.endpoint_generation(), 1);
        assert_eq!(remote.tls_listener_locator(), "tls/192.0.2.10:7449");
        assert_eq!(remote.route(), "paraegox/node/control/v1");
        assert_eq!(remote.trust_domain_ref().as_bytes(), &[0x14; 16]);
        assert_eq!(remote.trust_anchor_ref().as_bytes(), &[0x15; 16]);
        assert_eq!(
            remote.controller_connector_credential_ref().as_bytes(),
            &[0x16; 16]
        );
        assert_eq!(
            remote.node_listener_credential_ref().as_bytes(),
            &[0x17; 16]
        );
        assert_eq!(remote.control_transport_profile_ref(), [0x18; 16]);
        assert_eq!(remote.node_certificate_principal().as_bytes(), &[0x19; 16]);
        assert_ne!(remote.route_config_carrier_digest().as_bytes(), &[0; 32]);
        #[cfg(unix)]
        {
            let listener = remote
                .try_listener_config(PrincipalRef::from_bytes(
                    config.control().controller_principal(),
                ))
                .expect("typed Node listener config");
            assert!(listener.matches_transport_pins(
                remote.route(),
                PrincipalRef::from_bytes(config.control().controller_principal()),
                remote.route_config_carrier_digest(),
            ));
        }
    }

    #[test]
    fn node_config_v3_pins_only_one_derived_deterministic_provider_selection() {
        let state_root = "/var/tmp/paraegox-node-v3-test";
        let document = developer_node_document_v3_for_test(state_root);
        let config = parse_node_fixture(&document);
        assert_eq!(
            config.schema(),
            DeveloperNodeConfigSchemaV1::ManagedAgentBootstrapV3
        );
        assert!(config.node_control().is_some());
        let selection = config
            .managed_agent_bootstrap()
            .expect("schema v3 provider selection")
            .selection();
        assert_eq!(
            selection.profile(),
            ManagedAgentProviderProfileV1::DeterministicFixture
        );
        assert_eq!(selection.secret_ref(), None);
        assert_eq!(
            selection.config_digest(),
            deterministic_fixture_provider_configuration_digest()
        );
        assert_eq!(
            selection.provider_ref(),
            derive_developer_node_managed_agent_provider_ref(
                RuntimeHostId::from_bytes(config.control().target()),
                Digest32::from_bytes(config.config_commitment()),
                selection.config_digest(),
            )
            .expect("derived provider ref")
        );
        assert_eq!(parse_node_fixture(&document), config);
        assert_ne!(
            config.config_commitment(),
            parse_node_fixture(&developer_node_document_v2_for_test(state_root))
                .config_commitment()
        );

        let missing = document
            .split_once("\n[managed_agent_bootstrap]")
            .expect("v3 managed Agent section")
            .0;
        assert_eq!(
            parse_node_config_toml_for_test(missing),
            Err(ConfigError::InvalidNodeConfiguration)
        );
        assert_eq!(
            parse_node_config_toml_for_test(&document.replace(
                "deterministic-echo-v1",
                "openai-responses-v1"
            )),
            Err(ConfigError::InvalidNodeConfiguration)
        );
        let desired_injection = document.replace(
            "provider = \"deterministic-echo-v1\"",
            "provider = \"deterministic-echo-v1\"\nfabric_service_id = \"31313131313131313131313131313131\"",
        );
        assert_eq!(
            parse_node_config_toml_for_test(&desired_injection),
            Err(ConfigError::InvalidConfigDocument)
        );
        let secret_injection = document.replace(
            "provider = \"deterministic-echo-v1\"",
            "provider = \"deterministic-echo-v1\"\nsecret_ref = \"env:OPENAI_API_KEY\"",
        );
        assert_eq!(
            parse_node_config_toml_for_test(&secret_injection),
            Err(ConfigError::InvalidConfigDocument)
        );
    }

    #[test]
    fn node_config_versions_and_secret_fields_fail_closed() {
        let v1 = developer_node_document_for_test("/var/tmp/paraegox-node-v1-test");
        let v2 = developer_node_document_v2_for_test("/var/tmp/paraegox-node-v2-test");
        let v3 = developer_node_document_v3_for_test("/var/tmp/paraegox-node-v3-test");
        assert_eq!(
            parse_node_fixture(&v1).schema(),
            DeveloperNodeConfigSchemaV1::HostLocalV1
        );
        assert!(parse_node_fixture(&v1).node_control().is_none());
        assert_eq!(
            parse_node_config_toml_for_test(&v1.replacen(
                "schema_version = 1",
                "schema_version = 2",
                1
            )),
            Err(ConfigError::InvalidNodeConfiguration)
        );
        assert_eq!(
            parse_node_config_toml_for_test(&v2.replacen(
                "schema_version = 2",
                "schema_version = 1",
                1
            )),
            Err(ConfigError::InvalidNodeConfiguration)
        );
        assert_eq!(
            parse_node_config_toml_for_test(&v2.replacen(
                "schema_version = 2",
                "schema_version = 3",
                1
            )),
            Err(ConfigError::InvalidNodeConfiguration)
        );
        assert_eq!(
            parse_node_config_toml_for_test(&v3.replacen(
                "schema_version = 3",
                "schema_version = 2",
                1
            )),
            Err(ConfigError::InvalidNodeConfiguration)
        );
        assert_eq!(
            parse_node_config_toml_for_test(&v3.replacen(
                "schema_version = 3",
                "schema_version = 4",
                1
            )),
            Err(ConfigError::UnsupportedConfigSchema)
        );
        for forbidden in [
            "pxob_token",
            "inline_token",
            "controller_signing_seed",
            "authority_signing_seed",
            "controller_client_private_key_file",
            "node_listener_private_key",
            "route_config_carrier_digest",
        ] {
            let injected = v2.replace(
                "endpoint_ref =",
                &format!(
                    "{forbidden} = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\nendpoint_ref ="
                ),
            );
            assert_eq!(
                parse_node_config_toml_for_test(&injected),
                Err(ConfigError::InvalidConfigDocument),
                "unexpectedly accepted {forbidden}"
            );
        }
    }

    #[test]
    fn node_control_digest_binds_shared_semantics_but_not_role_local_paths() {
        let valid = developer_node_document_v2_for_test("/var/tmp/paraegox-node-v2-test");
        let baseline = parse_node_fixture(&valid);
        let baseline_remote = baseline.node_control().expect("schema v2");
        for changed in [
            valid.replace(
                "endpoint_ref = \"13131313131313131313131313131313\"",
                "endpoint_ref = \"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a\"",
            ),
            valid.replace(
                "endpoint_ref = \"13131313131313131313131313131313\"\nendpoint_generation = 1",
                "endpoint_ref = \"13131313131313131313131313131313\"\nendpoint_generation = 2",
            ),
            valid.replace("tls/192.0.2.10:7449", "tls/192.0.2.10:7450"),
            valid.replace("paraegox/node/control/v1", "paraegox/node/control/v2"),
            valid.replace(
                "trust_domain_ref = \"14141414141414141414141414141414\"",
                "trust_domain_ref = \"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a\"",
            ),
            valid.replace(
                "trust_anchor_ref = \"15151515151515151515151515151515\"",
                "trust_anchor_ref = \"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a\"",
            ),
            valid.replace(
                "controller_connector_credential_ref = \"16161616161616161616161616161616\"",
                "controller_connector_credential_ref = \"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a\"",
            ),
            valid.replace(
                "node_listener_credential_ref = \"17171717171717171717171717171717\"",
                "node_listener_credential_ref = \"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a\"",
            ),
            valid.replace(
                "control_transport_profile_ref = \"18181818181818181818181818181818\"",
                "control_transport_profile_ref = \"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a\"",
            ),
            valid.replace(
                "controller_principal = \"06060606060606060606060606060606\"",
                "controller_principal = \"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a\"",
            ),
            valid.replace(
                "node_certificate_principal = \"19191919191919191919191919191919\"",
                "node_certificate_principal = \"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a\"",
            ),
        ] {
            let config = parse_node_fixture(&changed);
            assert_ne!(
                config
                    .node_control()
                    .expect("changed schema v2")
                    .route_config_carrier_digest(),
                baseline_remote.route_config_carrier_digest()
            );
        }

        for changed in [
            valid.replace(
                "/var/tmp/paraegox-node-v2-test",
                "/var/tmp/paraegox-node-v2-replacement",
            ),
            valid.replace("node-root-ca.pem", "replacement-node-root-ca.pem"),
            valid.replace("node.pem", "replacement-node.pem"),
            valid.replace("node-key.pem", "replacement-node-key.pem"),
        ] {
            let changed_path = parse_node_fixture(&changed);
            assert_eq!(
                changed_path
                    .node_control()
                    .expect("path-changed schema v2")
                    .route_config_carrier_digest(),
                baseline_remote.route_config_carrier_digest()
            );
            assert_ne!(
                changed_path.config_commitment(),
                baseline.config_commitment()
            );
        }
    }

    #[test]
    fn node_config_v2_rejects_route_endpoint_identity_and_credential_aliases() {
        let valid = developer_node_document_v2_for_test("/var/tmp/paraegox-node-v2-test");
        for changed in [
            valid.replace("tls/192.0.2.10:7449", "tls/192.0.2.10:7448"),
            valid.replace(
                "paraegox/node/control/v1",
                "paraegox/runtime/target-a/apply",
            ),
            valid.replace(
                "node_certificate_principal = \"19191919191919191919191919191919\"",
                "node_certificate_principal = \"06060606060606060606060606060606\"",
            ),
            valid.replace("node-key.pem", "runtime-key.pem"),
        ] {
            assert_eq!(
                parse_node_config_toml_for_test(&changed),
                Err(ConfigError::InvalidNodeConfiguration)
            );
        }
    }

    #[test]
    fn node_config_rejects_private_material_aliases_and_semantic_drift() {
        let valid = node_document("/var/tmp/paraegox-node-test");
        let with_seed = valid.replace(
            "installation_id =",
            "controller_signing_seed = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\ninstallation_id =",
        );
        assert_eq!(
            parse_node_config_toml_for_test(&with_seed),
            Err(ConfigError::InvalidConfigDocument)
        );

        let aliased_ref = valid.replace(
            "target = \"02020202020202020202020202020202\"",
            "target = \"01010101010101010101010101010101\"",
        );
        assert_eq!(
            parse_node_config_toml_for_test(&aliased_ref),
            Err(ConfigError::InvalidNodeConfiguration)
        );
        let aliased_key = valid.replace(
            "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0",
            "884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b",
        );
        assert_eq!(
            parse_node_config_toml_for_test(&aliased_key),
            Err(ConfigError::InvalidNodeConfiguration)
        );
        let weak_key = valid.replace(
            "884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b",
            &"00".repeat(32),
        );
        assert_eq!(
            parse_node_config_toml_for_test(&weak_key),
            Err(ConfigError::InvalidNodeConfiguration)
        );

        let first = parse_node_fixture(&valid);
        let changed = parse_node_fixture(
            &valid.replace("endpoint_generation = 1", "endpoint_generation = 2"),
        );
        assert_ne!(first.config_commitment(), changed.config_commitment());
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
        assert_eq!(
            parse([OsString::from("controller")]),
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
    fn deployment_requires_exactly_one_absolute_config_path() {
        assert_eq!(
            parse([OsString::from(DEPLOYMENT_COMMAND)]),
            Err(ConfigError::MissingConfigPath)
        );
        assert_eq!(
            parse([
                OsString::from(DEPLOYMENT_COMMAND),
                OsString::from("controller"),
            ]),
            Err(ConfigError::MissingConfigPath)
        );
        assert_eq!(
            parse([
                OsString::from(DEPLOYMENT_COMMAND),
                OsString::from(CONFIG_OPTION),
            ]),
            Err(ConfigError::MissingConfigPath)
        );
        assert_eq!(
            parse([
                OsString::from(DEPLOYMENT_COMMAND),
                OsString::from(CONFIG_OPTION),
                OsString::from("paraegox-deployment.toml"),
            ]),
            Err(ConfigError::InvalidConfigPath)
        );
        assert_eq!(
            parse(deployment_config_arguments(vec![
                b'x';
                MAX_CONFIG_BYTES as usize
                    + 1
            ])),
            Err(ConfigError::ConfigFileTooLarge)
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_config_path_rejects_a_final_component_symlink() {
        use std::os::unix::fs::symlink;

        let fixture = DeploymentConfigFixture::new();
        let arguments = deployment_config_arguments(fixture.document());
        let target = PathBuf::from(arguments[2].clone());
        let link = target.with_extension("symlink.toml");
        symlink(&target, &link).expect("create test Deployment config symlink");

        let result = parse([
            OsString::from(DEPLOYMENT_COMMAND),
            OsString::from(CONFIG_OPTION),
            link.clone().into_os_string(),
        ]);
        fs::remove_file(&link).expect("remove test Deployment config symlink");

        assert_eq!(result, Err(ConfigError::InvalidConfigPath));
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
            parse(config_arguments(vec![b'x'; MAX_CONFIG_BYTES as usize + 1])),
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
            ConfigError::InvalidNodeConfiguration,
            ConfigError::InvalidDeploymentConfiguration,
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
