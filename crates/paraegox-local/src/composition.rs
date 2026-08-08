//! One explicit DeveloperLocal composition of the real ParaEGOX owners.

use std::env;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use nix::sys::signal::{Signal, kill};
use nix::unistd::{Gid, Pid, Uid};
use paraegox_agent_contracts::{AgentConversationDeckRunId, AgentConversationSessionId};
use paraegox_agent_service::AgentConversationModelServiceProviderV1;
use paraegox_deployment::{
    DeveloperFixtureAgentStackInputV1, DeveloperFixtureControllerCredentialsV1,
    DeveloperFixtureDerivedIdentityV1, DeveloperFixtureDistributedAgentStackInputV1,
    DeveloperFixtureDistributedCoordinatorV1, DeveloperFixtureDistributedNodeV1,
    DeveloperFixtureDistributedTargetV1, DeveloperFixtureDistributedTransportV1,
    DeveloperFixtureFabricEndpointV1, DeveloperFixtureIdentitySeedV1,
    DeveloperFixtureModelAgentStackInputV1, DeveloperFixturePathsV1, DeveloperFixtureRuntimePinsV1,
    DeveloperLocalPeerIdentityV1, DeveloperLocalTenureAuthorityConfigV1,
    DeveloperLocalTenureAuthorityIdentityBytesV1, DeveloperLocalTenureAuthorityV1,
    DeveloperProvisionedAgentStackInputV1, DeveloperProvisionedModelAgentStackInputV1,
    complete_developer_fixture_distributed_agent_stack_v1,
    prepare_developer_fixture_distributed_agent_stack_v1,
    run_developer_fixture_model_agent_stack_v1, run_developer_provisioned_model_agent_stack_v1,
};
use paraegox_evidence::EvidenceRetentionPolicyV1;
use paraegox_evidence::{EvidenceOwnerRefV1, EvidenceStoreEpochV1};
use paraegox_fabric::{ResolvedRemoteMtlsCredentialFiles, ResolvedRemoteMtlsIdentityFiles};
use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::BoundedDuration;
use paraegox_model::{
    BOUNDED_TEXT_MODEL_CAPABILITY_ID_V1, ModelAdapterBuildErrorV1, ModelAdapterDescriptorV1,
    ModelAdapterFactoryV1, ModelAdapterIdV1, ModelAdapterMetadataV1, ModelAdapterRegistryV1,
    ModelAdapterSelectionV1, ModelAdapterVersionV1, ModelBackendFuture, ModelBackendIdentityV1,
    ModelBackendV1, ModelCancellationViewV1, ModelCapabilityIdV1, ModelInvocationOutcomeV1,
    ModelInvocationRequestV1, ModelServiceConfigV1, ModelServiceV1,
};
use paraegox_model_adapters::{
    DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_DESCRIPTOR_V1, DeepSeekChatCompletionsProviderFactoryV1,
    DeepSeekResolvedApiKeyV1, OPENAI_RESPONSES_ADAPTER_DESCRIPTOR_V1, OpenAiResolvedApiKeyV1,
    OpenAiResponsesProviderFactoryV1,
};
use paraegox_node::observation::{
    RuntimeObservationAuthorityV1, RuntimeObservationBootstrapInputV1,
    RuntimeObservationBootstrapV1, RuntimeObservationEndpointRefV1,
};
use paraegox_node::process::{
    DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES, DeveloperLocalNodeManagementEndpointV1,
    DeveloperLocalReferenceBootstrapInputV1, DeveloperLocalReferenceBootstrapV1,
};
use paraegox_node::protocol::{NodeManagementClientV1, NodeManagementTargetV1};
use paraegox_node::store::DurableNodeDaemonV1;
use paraegox_node::{
    EnrollmentIssuerRefV1, MAX_NODE_STATUS_FRESHNESS_NANOS, NodeArchitectureV1,
    NodeFeatureReportInputV1, NodeFeatureReportV1, NodeId, NodeIdentityV1, NodeIncarnation,
    NodeManagementEndpointRefV1, NodeOperatingSystemV1, NodeRegistrationTenureV1, NodeStatusV1,
};
use paraegox_runtime::{
    RuntimeAgentConversationHandle, RuntimeAgentDeveloperLocalConversationV1,
    RuntimeAgentDeveloperLocalIpcConfigV1, RuntimeAgentDeveloperLocalIpcLifecycleV1,
    RuntimeAgentDeveloperLocalIpcLimitsV1, RuntimeAgentDeveloperLocalIpcPathsV1,
    RuntimeAgentProviderResolveError, RuntimeAgentProviderResolverV1,
    RuntimeDeveloperLocalConfigV1, RuntimeDeveloperLocalDistributedAgentStackConfigV1,
    RuntimeDeveloperLocalIdentityRefsV1, RuntimeDeveloperLocalIdentityV1,
    RuntimeDeveloperLocalLifecycleV1, RuntimeDeveloperLocalSigningSeedsV1,
    RuntimeFabricCredentialRequirementV1, RuntimeFabricCredentialResolveErrorV2,
    RuntimeFabricCredentialResolverV2, RuntimeModelBackendResolveError,
    RuntimeModelBackendResolverV1, RuntimeResolvedAgentProviderV1,
    RuntimeResolvedFabricPeerCredentialV2, RuntimeResolvedModelBackendV1,
    start_runtime_agent_developer_local_ipc_v1, start_runtime_developer_local_v1,
};
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DistributedFabricCredentialRefV1, DistributedFabricPeerAuthenticationRequirementV1,
    DistributedFabricPeerIdentityRefV1, DistributedFabricPeerPlanV1,
    DistributedFabricTlsEndpointV1, DistributedFabricTopologyV1, DistributedFabricTrustAnchorRefV1,
    DistributedFabricTrustDomainRefV1, RestrictedRuntimeApplyTransportProfileFieldsV1,
    RestrictedRuntimeApplyTransportProfileV1,
};
use paraegox_runtime_contracts::managed_agent_stack_plan::{
    ManagedAgentProviderRefV1, ManagedAgentProviderSelectionV1, ManagedAgentSecretRefV1,
};
use paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricListenEndpointV1;
use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
    ManagedModelAdapterBindingV1, ManagedModelAdapterVersionV1, ManagedModelCapabilityIdV1,
    ManagedModelServicePlanV1,
};
use paraegox_runtime_contracts::managed_service::{
    ManagedServiceId, ManagedServiceLifecycleBudgetsV1, ManagedServiceSpecV1,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

#[cfg(test)]
use crate::config::{
    DEVELOPER_PROVISIONED_MAX_OUTPUT_TEXT_BYTES, DEVELOPER_PROVISIONED_MAX_OUTPUT_TOKENS,
    DEVELOPER_PROVISIONED_MAX_RESPONSE_BODY_BYTES, DEVELOPER_PROVISIONED_PROVIDER_TIMEOUT_NANOS,
};
use crate::config::{
    DeveloperDistributedFixtureConfigV1, DeveloperDistributedTargetConfigV1,
    DeveloperFixtureConfigV1, DeveloperLocalProfileV1, DeveloperProvisionedConfigV1,
    ProviderProfileV1, ProvisionedProviderConfigV1, ProvisionedSecretRefV1,
};
use crate::error::LocalProcessError;
use crate::inspection::{
    DeveloperLocalDeploymentOutcomeV1, DeveloperLocalInspectionSourcesV2,
    start_developer_local_inspection_v2,
};
#[cfg(not(test))]
use crate::{
    NODE_BOOTSTRAP_FILE_OPTION, NODE_DAEMON_CHILD_MODE, NODE_OBSERVATION_BOOTSTRAP_FILE_OPTION,
};
use crate::{identity, layout};

const CONSOLE_COMMAND: &str = "paraegox-console";
const RUNTIME_BOOTSTRAP_FILE_OPTION: &str = "--runtime-bootstrap-file";
const INSPECTION_BOOTSTRAP_FILE_OPTION: &str = "--inspection-bootstrap-file";
const OPENAI_SECRET_REF_DOMAIN: &[u8] = b"paraegox.local.developer-openai-secret-ref.sha256.v1";
const DEEPSEEK_SECRET_REF_DOMAIN: &[u8] = b"paraegox.local.developer-deepseek-secret-ref.sha256.v1";
const DEVELOPER_MODEL_SERVICE_MAX_IN_FLIGHT: usize = 1;
const DEVELOPER_MODEL_LIFECYCLE_NANOS: u64 = 3_000_000_000;
const DEVELOPER_NODE_REGISTRATION_EPOCH: u64 = 1;
const DEVELOPER_NODE_FEATURE_SEQUENCE: u64 = 1;
const DEVELOPER_NODE_RUNTIME_CONTRACT_VERSION: u16 = 1;
const DEVELOPER_NODE_FABRIC_CONTRACT_VERSION: u16 = 1;
const DEVELOPER_NODE_BOOTSTRAP_ENTROPY_BYTES: usize =
    DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES + 4 * 16;
const DEVELOPER_NODE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const DEVELOPER_NODE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);
const DEVELOPER_NODE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const DEVELOPER_NODE_POLL_INTERVAL: Duration = Duration::from_millis(20);
const DEVELOPER_DISTRIBUTED_EVIDENCE_MAX_RECORDS: u64 = 4_096;
const DEVELOPER_DISTRIBUTED_EVIDENCE_MAX_BYTES: u64 = 16 * 1024 * 1024;
const DEVELOPER_NODE_ENROLLMENT_DOMAIN: &[u8] =
    b"paraegox.local.developer-node-enrollment.sha256.v1";
const DEVELOPER_NODE_PLATFORM_DOMAIN: &[u8] = b"paraegox.local.developer-node-platform.sha256.v1";
#[cfg(test)]
const NODE_DAEMON_PROBE_BOOTSTRAP_ENVIRONMENT: &str = "PARAEGOX_TEST_NODE_BOOTSTRAP";
#[cfg(test)]
const NODE_DAEMON_PROBE_OBSERVATION_BOOTSTRAP_ENVIRONMENT: &str =
    "PARAEGOX_TEST_NODE_OBSERVATION_BOOTSTRAP";
#[cfg(test)]
const NODE_DAEMON_PROBE_TEST_NAME: &str = "composition::tests::node_daemon_subprocess_probe";
const LOCAL_DETERMINISTIC_ECHO_ADAPTER_ID_V1: ModelAdapterIdV1 =
    match ModelAdapterIdV1::try_from_bytes(*b"px-fixture-echo1") {
        Ok(adapter_id) => adapter_id,
        Err(_) => panic!("local deterministic echo adapter identity must be nonzero"),
    };
const LOCAL_DETERMINISTIC_ECHO_ADAPTER_VERSION_V1: ModelAdapterVersionV1 =
    match ModelAdapterVersionV1::try_new(1) {
        Ok(version) => version,
        Err(_) => panic!("local deterministic echo adapter version must be nonzero"),
    };
const LOCAL_DETERMINISTIC_ECHO_ADAPTER_CAPABILITY_ID_V1: ModelCapabilityIdV1 =
    BOUNDED_TEXT_MODEL_CAPABILITY_ID_V1;
const LOCAL_DETERMINISTIC_ECHO_ADAPTER_DESCRIPTOR_V1: ModelAdapterDescriptorV1 =
    ModelAdapterDescriptorV1::new(
        LOCAL_DETERMINISTIC_ECHO_ADAPTER_ID_V1,
        LOCAL_DETERMINISTIC_ECHO_ADAPTER_VERSION_V1,
        LOCAL_DETERMINISTIC_ECHO_ADAPTER_CAPABILITY_ID_V1,
    );

pub(crate) fn run(config: DeveloperFixtureConfigV1) -> Result<(), LocalProcessError> {
    let peer = current_developer_local_peer()?;
    run_with_runner(config, peer, &mut ChildProcessConversationRunner)
}

pub(crate) fn run_distributed(
    config: DeveloperDistributedFixtureConfigV1,
) -> Result<(), LocalProcessError> {
    // Validate the process identity before creating or opening durable state.
    let peer = DeveloperLocalPeerIdentityV1::current()
        .map_err(|_| LocalProcessError::DistributedAuthorityStartup)?;
    let manifest = identity::open_distributed(config.state_root())
        .map_err(|_| LocalProcessError::DistributedIdentityManifest)?;
    let layout = layout::prepare_distributed(config.state_root(), &manifest)
        .map_err(|_| LocalProcessError::DistributedLayoutPreparation)?;
    let target_a = identity::DistributedDeveloperLocalTargetV1::A;
    let target_b = identity::DistributedDeveloperLocalTargetV1::B;
    let identities_a = manifest
        .developer_fixture_derived_identity(target_a)
        .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let identities_b = manifest
        .developer_fixture_derived_identity(target_b)
        .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let controller_verification_key = signing_verification_key(manifest.controller_signing_seed());
    let authority_verification_key = signing_verification_key(manifest.authority_signing_seed());
    let operation_timeout = config.profile().operation_timeout();
    let target_configs = config.targets();
    let prepared_a = prepare_distributed_target_prestart_v1(
        &manifest,
        target_a,
        target_b,
        &target_configs[0],
        &target_configs[1],
        config.fabric_listen_a(),
        authority_verification_key,
        operation_timeout,
        LocalProcessError::DistributedRuntimeAStartup,
    )?;
    let prepared_b = prepare_distributed_target_prestart_v1(
        &manifest,
        target_b,
        target_a,
        &target_configs[1],
        &target_configs[0],
        config.fabric_listen_b(),
        authority_verification_key,
        operation_timeout,
        LocalProcessError::DistributedRuntimeBStartup,
    )?;
    let provider = prepare_distributed_fixture_provider(&manifest)
        .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let authority_config = DeveloperLocalTenureAuthorityConfigV1::try_new(
        layout
            .coordinator()
            .authority_state_directory()
            .to_path_buf(),
        layout.coordinator().authority_socket_path().to_path_buf(),
        authority_identities(identities_a),
        Zeroizing::new(*manifest.authority_signing_seed()),
        controller_verification_key,
        None,
        peer,
    )
    .map_err(|_| LocalProcessError::DistributedAuthorityStartup)?;
    let authority = DeveloperLocalTenureAuthorityV1::start(authority_config)
        .map_err(|_| LocalProcessError::DistributedAuthorityStartup)?;
    let mut owners = RunningOwners::new(authority);

    let run_result = (|| {
        let runtime_a_config = distributed_runtime_config_v1(
            &manifest,
            target_a,
            layout.target(target_a),
            &prepared_a,
            Arc::clone(&provider.agent_resolver),
            Arc::clone(&provider.model_backend_resolver),
            LocalProcessError::DistributedRuntimeAStartup,
        )?;
        owners.runtime_a = Some(
            start_runtime_developer_local_v1(runtime_a_config)
                .map_err(|_| LocalProcessError::DistributedRuntimeAStartup)?,
        );
        let runtime_b_config = distributed_runtime_config_v1(
            &manifest,
            target_b,
            layout.target(target_b),
            &prepared_b,
            Arc::clone(&provider.agent_resolver),
            Arc::clone(&provider.model_backend_resolver),
            LocalProcessError::DistributedRuntimeBStartup,
        )?;
        owners.runtime_b = Some(
            start_runtime_developer_local_v1(runtime_b_config)
                .map_err(|_| LocalProcessError::DistributedRuntimeBStartup)?,
        );

        let deployment_target_a = distributed_deployment_target_v1(
            prepared_a,
            owners
                .runtime_a
                .as_ref()
                .expect("Runtime A exists after successful startup"),
            layout.target(target_a),
            layout.coordinator().authority_socket_path(),
            owners.authority(),
            config.fabric_listen_a(),
        )?;
        let deployment_target_b = distributed_deployment_target_v1(
            prepared_b,
            owners
                .runtime_b
                .as_ref()
                .expect("Runtime B exists after successful startup"),
            layout.target(target_b),
            layout.coordinator().authority_socket_path(),
            owners.authority(),
            config.fabric_listen_b(),
        )?;
        let operation_timeout_nanos = u64::try_from(operation_timeout.as_nanos())
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
        let coordinator = DeveloperFixtureDistributedCoordinatorV1::try_new(
            layout
                .coordinator()
                .controller_state_directory()
                .to_path_buf(),
        )
        .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
        let prepared = prepare_developer_fixture_distributed_agent_stack_v1(
            DeveloperFixtureDistributedAgentStackInputV1::new(
                coordinator,
                BoundedDuration::from_nanos(operation_timeout_nanos),
                [deployment_target_a, deployment_target_b],
            ),
        )
        .inspect_err(|error| eprintln!("{error}"))
        .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
        let observation_authorities = prepared.runtime_observation_authorities();

        let node_a = prepare_distributed_node_reference_v1(
            &manifest,
            target_a,
            layout.target(target_a),
            identities_a,
        )
        .map_err(|_| LocalProcessError::DistributedNodeAStartup)?;
        write_distributed_runtime_observation_bootstrap_v1(
            &manifest,
            target_a,
            layout.target(target_a),
            node_a.management_target,
            observation_authorities[0].clone(),
        )
        .map_err(|_| LocalProcessError::DistributedNodeAStartup)?;
        owners.node_a = Some(
            RunningNodeDaemon::start_runtime_observation(
                layout.target(target_a).pxnb_bootstrap_path(),
                layout.target(target_a).pxob_bootstrap_path(),
                layout.target(target_a).node_observation_socket_path(),
                node_a.bootstrap,
                node_a.status,
            )
            .map_err(|_| LocalProcessError::DistributedNodeAStartup)?,
        );

        let node_b = prepare_distributed_node_reference_v1(
            &manifest,
            target_b,
            layout.target(target_b),
            identities_b,
        )
        .map_err(|_| LocalProcessError::DistributedNodeBStartup)?;
        write_distributed_runtime_observation_bootstrap_v1(
            &manifest,
            target_b,
            layout.target(target_b),
            node_b.management_target,
            observation_authorities[1].clone(),
        )
        .map_err(|_| LocalProcessError::DistributedNodeBStartup)?;
        owners.node_b = Some(
            RunningNodeDaemon::start_runtime_observation(
                layout.target(target_b).pxnb_bootstrap_path(),
                layout.target(target_b).pxob_bootstrap_path(),
                layout.target(target_b).node_observation_socket_path(),
                node_b.bootstrap,
                node_b.status,
            )
            .map_err(|_| LocalProcessError::DistributedNodeBStartup)?,
        );

        let target_a_identity = manifest.target(target_a);
        let target_b_identity = manifest.target(target_b);
        let complete_nodes = [
            DeveloperFixtureDistributedNodeV1::try_new(
                node_a.management_target,
                layout
                    .target(target_a)
                    .node_management_socket_path()
                    .to_path_buf(),
                Zeroizing::new(*target_a_identity.pxnb_reference_token()),
                RuntimeObservationEndpointRefV1::try_from_bytes(
                    *target_a_identity.runtime_observation_endpoint_ref(),
                )
                .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?,
                layout
                    .target(target_a)
                    .node_observation_socket_path()
                    .to_path_buf(),
                Zeroizing::new(*target_a_identity.pxob_observation_token()),
            )
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?,
            DeveloperFixtureDistributedNodeV1::try_new(
                node_b.management_target,
                layout
                    .target(target_b)
                    .node_management_socket_path()
                    .to_path_buf(),
                Zeroizing::new(*target_b_identity.pxnb_reference_token()),
                RuntimeObservationEndpointRefV1::try_from_bytes(
                    *target_b_identity.runtime_observation_endpoint_ref(),
                )
                .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?,
                layout
                    .target(target_b)
                    .node_observation_socket_path()
                    .to_path_buf(),
                Zeroizing::new(*target_b_identity.pxob_observation_token()),
            )
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?,
        ];
        let outcome =
            complete_developer_fixture_distributed_agent_stack_v1(prepared, complete_nodes)
                .inspect_err(|error| eprintln!("{error}"))
                .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
        let receipts = outcome.target_receipts();
        let handle = owners
            .runtime_a
            .as_ref()
            .expect("Runtime A exists through conversation")
            .claim_distributed_agent_handle(receipts[0])
            .map_err(|_| LocalProcessError::ConversationCapability)?;
        let conversation_config = LocalConversationBounds::try_new(
            AgentConversationDeckRunId::try_from_bytes(*target_a_identity.deck_run_id())
                .map_err(|_| LocalProcessError::ConversationConfiguration)?,
            AgentConversationSessionId::try_from_bytes(*target_a_identity.session_id())
                .map_err(|_| LocalProcessError::ConversationConfiguration)?,
            config.profile().request_deadline_budget(),
            config.profile().command_capacity(),
            operation_timeout,
        )?;
        let mut runner = ChildProcessConversationRunner;
        runner.run(ConversationRunInput {
            handle,
            config: conversation_config,
            ipc_socket_path: layout
                .target(target_a)
                .agent_ipc_socket_path()
                .to_path_buf(),
            ipc_bootstrap_path: layout
                .target(target_a)
                .agent_ipc_bootstrap_path()
                .to_path_buf(),
            inspection: None,
            expected_uid: Uid::effective().as_raw(),
            expected_gid: Gid::effective().as_raw(),
        })
    })();
    let cleanup_result = owners
        .shutdown()
        .map_err(|_| LocalProcessError::DistributedJoinedShutdown);
    run_result.and(cleanup_result)
}

pub(crate) fn run_provisioned(
    config: DeveloperProvisionedConfigV1,
) -> Result<(), LocalProcessError> {
    let peer = current_developer_local_peer()?;
    let api_key_environment = env::var_os(config.secret_ref().environment_variable());
    run_provisioned_with_environment_value(
        config,
        api_key_environment,
        peer,
        &mut ChildProcessConversationRunner,
    )
}

fn run_provisioned_with_environment_value(
    config: DeveloperProvisionedConfigV1,
    value: Option<std::ffi::OsString>,
    peer: DeveloperLocalPeerIdentityV1,
    runner: &mut impl ConversationRunner,
) -> Result<(), LocalProcessError> {
    // The caller has already validated the non-root execution identity without
    // touching durable state. Secret resolution remains ahead of every
    // identity, state, layout, or owner action, so malformed material cannot
    // create or modify the state root.
    let api_key = resolve_provisioned_api_key(config.provider_profile(), value)?;
    run_provisioned_with_runner_and_key(config, api_key, peer, runner)
}

fn run_with_runner(
    config: DeveloperFixtureConfigV1,
    peer: DeveloperLocalPeerIdentityV1,
    runner: &mut impl ConversationRunner,
) -> Result<(), LocalProcessError> {
    let manifest =
        identity::load_or_create(&config).map_err(|_| LocalProcessError::IdentityManifest)?;
    let provider = prepare_fixture_provider(&manifest)?;
    let layout =
        layout::prepare(&config, &manifest).map_err(|_| LocalProcessError::LayoutPreparation)?;
    run_prepared(
        CompositionConfigRef::Fixture(&config),
        manifest,
        layout,
        provider,
        peer,
        runner,
    )
}

fn run_provisioned_with_runner_and_key(
    config: DeveloperProvisionedConfigV1,
    api_key: ResolvedProviderApiKeyV1,
    peer: DeveloperLocalPeerIdentityV1,
    runner: &mut impl ConversationRunner,
) -> Result<(), LocalProcessError> {
    let manifest = identity::load_or_create_provisioned(&config)
        .map_err(|_| LocalProcessError::IdentityManifest)?;
    let provider = prepare_provisioned_provider(&config, &manifest, api_key)?;
    let layout = layout::prepare_provisioned(&config, &manifest)
        .map_err(|_| LocalProcessError::LayoutPreparation)?;
    run_prepared(
        CompositionConfigRef::Provisioned(&config),
        manifest,
        layout,
        provider,
        peer,
        runner,
    )
}

fn current_developer_local_peer() -> Result<DeveloperLocalPeerIdentityV1, LocalProcessError> {
    DeveloperLocalPeerIdentityV1::current().map_err(|_| LocalProcessError::AuthorityStartup)
}

fn run_prepared(
    config: CompositionConfigRef<'_>,
    manifest: identity::IdentityManifestV1,
    layout: layout::DeveloperLocalLayoutV1,
    provider: CompositionProvider,
    peer: DeveloperLocalPeerIdentityV1,
    runner: &mut impl ConversationRunner,
) -> Result<(), LocalProcessError> {
    let identities = derive_identities(&manifest)?;
    let controller_verification_key = signing_verification_key(manifest.controller_signing_seed());
    let authority_verification_key = signing_verification_key(manifest.authority_signing_seed());

    let authority_config = DeveloperLocalTenureAuthorityConfigV1::try_new(
        layout.authority_state_directory().to_path_buf(),
        layout.authority_socket_path().to_path_buf(),
        authority_identities(identities),
        Zeroizing::new(*manifest.authority_signing_seed()),
        controller_verification_key,
        None,
        peer,
    )
    .map_err(|_| LocalProcessError::AuthorityStartup)?;
    let authority = DeveloperLocalTenureAuthorityV1::start(authority_config)
        .map_err(|_| LocalProcessError::AuthorityStartup)?;
    let mut owners = RunningOwners::new(authority);

    let runtime_identity = runtime_developer_local_identity(
        identities,
        *manifest.controller_signing_seed(),
        *manifest.authority_signing_seed(),
        *manifest.runtime_signing_seed(),
    )?;
    let CompositionProvider {
        deployment: deployment_provider,
        adapter_descriptor,
        agent_resolver,
        model_backend_resolver,
    } = provider;
    let runtime_config = RuntimeDeveloperLocalConfigV1::try_new_with_agent_and_model_resolvers(
        layout.runtime_state_directory().to_path_buf(),
        layout.runtime_socket_path().to_path_buf(),
        runtime_identity,
        agent_resolver,
        model_backend_resolver,
    )
    .map_err(|_| LocalProcessError::RuntimeStartup)?;
    owners.runtime_a = Some(
        start_runtime_developer_local_v1(runtime_config)
            .map_err(|_| LocalProcessError::RuntimeStartup)?,
    );
    let (node_bootstrap, node_status) = prepare_developer_local_node_v1(&layout, identities)?;
    owners.node_a = Some(RunningNodeDaemon::start(
        layout.pxnb_bootstrap_path(),
        node_bootstrap,
        node_status,
    )?);

    let mut stack = RunningStack {
        config,
        manifest: &manifest,
        layout: &layout,
        identities,
        authority_verification_key,
        deployment_provider,
        adapter_descriptor,
        owners: Some(owners),
    };
    let deployment = match stack.activate() {
        Ok(deployment) => deployment,
        Err(primary) => {
            let _ = stack.cleanup();
            return Err(primary);
        }
    };
    let conversation_result = (|| {
        let conversation_handle = stack
            .runtime()
            .claim_model_agent_handle(deployment.agent_terminal_receipt())
            .map_err(|_| LocalProcessError::ConversationCapability)?;
        let conversation_config = LocalConversationBounds::try_new(
            AgentConversationDeckRunId::try_from_bytes(*manifest.deck_run_id())
                .map_err(|_| LocalProcessError::ConversationConfiguration)?,
            AgentConversationSessionId::try_from_bytes(*manifest.session_id())
                .map_err(|_| LocalProcessError::ConversationConfiguration)?,
            config.profile().request_deadline_budget(),
            config.profile().command_capacity(),
            config.profile().operation_timeout(),
        )?;
        runner.run(ConversationRunInput {
            handle: conversation_handle,
            config: conversation_config,
            ipc_socket_path: layout.agent_ipc_socket_path().to_path_buf(),
            ipc_bootstrap_path: layout.agent_ipc_bootstrap_path().to_path_buf(),
            inspection: Some(ConversationInspectionInput {
                sources: stack.inspection_sources(deployment),
                ipc_socket_path: layout.inspection_ipc_socket_path().to_path_buf(),
                ipc_bootstrap_path: layout.inspection_ipc_bootstrap_path().to_path_buf(),
            }),
            expected_uid: Uid::effective().as_raw(),
            expected_gid: Gid::effective().as_raw(),
        })
    })();
    let cleanup_result = stack.cleanup();
    conversation_result.and(cleanup_result)
}

fn runtime_developer_local_identity(
    identities: DeveloperFixtureDerivedIdentityV1,
    controller_signing_seed: [u8; 32],
    authority_signing_seed: [u8; 32],
    runtime_signing_seed: [u8; 32],
) -> Result<RuntimeDeveloperLocalIdentityV1, LocalProcessError> {
    RuntimeDeveloperLocalIdentityV1::try_new(
        RuntimeDeveloperLocalIdentityRefsV1 {
            installation_id: identities.installation_id(),
            target: identities.runtime_target(),
            source_scope: identities.source_scope(),
            writer: identities.writer(),
            runtime_principal: identities.runtime_principal(),
            controller_principal: identities.controller_principal(),
            authority_principal: identities.authority_principal(),
            controller_request_key_ref: identities.controller_key_ref(),
            runtime_response_key_ref: identities.runtime_response_key_ref(),
            tenure_authority_ref: identities.authority_ref(),
            tenure_key_ref: identities.authority_key_ref(),
        },
        RuntimeDeveloperLocalSigningSeedsV1::new(
            controller_signing_seed,
            authority_signing_seed,
            runtime_signing_seed,
        ),
    )
    .map_err(|_| LocalProcessError::RuntimeStartup)
}

struct PreparedDistributedTargetPrestartV1 {
    identities: DeveloperFixtureDerivedIdentityV1,
    topology: DistributedFabricTopologyV1,
    fabric_credential_resolver: Arc<dyn RuntimeFabricCredentialResolverV2>,
    transport: DeveloperFixtureDistributedTransportV1,
    restricted_root_ca_certificate_file: PathBuf,
    restricted_listener_identity: ResolvedRemoteMtlsIdentityFiles,
    controller_credentials: DeveloperFixtureControllerCredentialsV1,
}

fn prepare_distributed_target_prestart_v1(
    manifest: &identity::DistributedDeveloperLocalIdentityManifestV1,
    target: identity::DistributedDeveloperLocalTargetV1,
    peer_target: identity::DistributedDeveloperLocalTargetV1,
    target_config: &DeveloperDistributedTargetConfigV1,
    peer_config: &DeveloperDistributedTargetConfigV1,
    base_loopback_listen_endpoint: &str,
    authority_verification_key: [u8; 32],
    operation_timeout: Duration,
    runtime_startup_error: LocalProcessError,
) -> Result<PreparedDistributedTargetPrestartV1, LocalProcessError> {
    let target_identity = manifest.target(target);
    let peer_identity = manifest.target(peer_target);
    let identities = DeveloperFixtureDerivedIdentityV1::try_from_seed(
        manifest.developer_fixture_identity_seed(target),
    )
    .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let controller_credentials = DeveloperFixtureControllerCredentialsV1::try_new(
        Zeroizing::new(*manifest.controller_signing_seed()),
        authority_verification_key,
    )
    .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let trust_domain_ref =
        DistributedFabricTrustDomainRefV1::try_from_bytes(*manifest.transport_trust_domain_ref())
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let trust_anchor_ref =
        DistributedFabricTrustAnchorRefV1::try_from_bytes(*manifest.transport_trust_anchor_ref())
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let local_fabric_endpoint =
        DistributedFabricTlsEndpointV1::try_new(target_config.fabric().tls_listener_locator())
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let peer_fabric_endpoint =
        DistributedFabricTlsEndpointV1::try_new(peer_config.fabric().tls_listener_locator())
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let expected_peer_identity_ref = DistributedFabricPeerIdentityRefV1::try_from_bytes(
        *peer_identity.fabric_peer_identity_ref(),
    )
    .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let authentication = DistributedFabricPeerAuthenticationRequirementV1::try_mutual_tls(
        trust_domain_ref,
        target_config.fabric().local_credential_ref(),
        trust_anchor_ref,
        expected_peer_identity_ref,
    )
    .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let peer_plan = DistributedFabricPeerPlanV1::try_new(
        RuntimeHostId::from_bytes(*peer_identity.runtime_target()),
        peer_fabric_endpoint.clone(),
        authentication,
    )
    .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let topology = DistributedFabricTopologyV1::try_new(
        RuntimeHostId::from_bytes(*target_identity.runtime_target()),
        ManagedFabricListenEndpointV1::try_new(base_loopback_listen_endpoint)
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?,
        local_fabric_endpoint,
        vec![peer_plan],
    )
    .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let listen_identity = ResolvedRemoteMtlsIdentityFiles::try_new(
        target_config
            .fabric()
            .listen_certificate_file()
            .to_path_buf(),
        target_config
            .fabric()
            .listen_private_key_file()
            .to_path_buf(),
    )
    .map_err(|_| runtime_startup_error)?;
    let connect_identity = ResolvedRemoteMtlsIdentityFiles::try_new(
        target_config
            .fabric()
            .connect_certificate_file()
            .to_path_buf(),
        target_config
            .fabric()
            .connect_private_key_file()
            .to_path_buf(),
    )
    .map_err(|_| runtime_startup_error)?;
    let credential_files = ResolvedRemoteMtlsCredentialFiles::try_new(
        target_config
            .fabric()
            .root_ca_certificate_file()
            .to_path_buf(),
        listen_identity,
        connect_identity,
    )
    .map_err(|_| runtime_startup_error)?;
    let fabric_credential_resolver = Arc::new(DeveloperDistributedFabricCredentialResolverV2 {
        peer_runtime_host: RuntimeHostId::from_bytes(*peer_identity.runtime_target()),
        connect_endpoint: peer_fabric_endpoint,
        trust_domain_ref,
        local_credential_ref: target_config.fabric().local_credential_ref(),
        trust_anchor_ref,
        expected_peer_identity_ref,
        expected_peer_common_name: target_config.fabric().expected_peer_common_name().into(),
        credential_files,
    });
    let operation_timeout_nanos = u64::try_from(operation_timeout.as_nanos())
        .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let transport_profile = RestrictedRuntimeApplyTransportProfileV1::try_new(
        RestrictedRuntimeApplyTransportProfileFieldsV1 {
            target: RuntimeHostId::from_bytes(*target_identity.runtime_target()),
            endpoint_ref: *target_identity.runtime_apply_endpoint_ref(),
            endpoint_generation: target_identity.endpoint_generation(),
            tls_listener_locator: target_config.pxrp().tls_listener_locator(),
            route: target_config.pxrp().route(),
            trust_domain_ref,
            trust_anchor_ref,
            controller_connector_credential_ref: DistributedFabricCredentialRefV1::try_from_bytes(
                *target_identity.controller_connector_credential_ref(),
            )
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?,
            runtime_listener_credential_ref: DistributedFabricCredentialRefV1::try_from_bytes(
                *target_identity.runtime_listener_credential_ref(),
            )
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?,
            controller_principal: PrincipalRef::from_bytes(identities.controller_principal()),
            runtime_principal: PrincipalRef::from_bytes(identities.runtime_principal()),
            operation_timeout_nanos,
        },
    )
    .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let runtime_response_verification_key =
        SigningKey::from_bytes(target_identity.runtime_response_signing_seed())
            .verifying_key()
            .to_bytes();
    let transport = DeveloperFixtureDistributedTransportV1::try_new(
        identities,
        &controller_credentials,
        runtime_response_verification_key,
        *target_identity.transport_profile_ref(),
        transport_profile,
        target_config
            .pxrp()
            .root_ca_certificate_file()
            .to_path_buf(),
        target_config
            .pxrp()
            .controller_client_certificate_file()
            .to_path_buf(),
        target_config
            .pxrp()
            .controller_client_private_key_file()
            .to_path_buf(),
    )
    .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let restricted_listener_identity = ResolvedRemoteMtlsIdentityFiles::try_new(
        target_config
            .pxrp()
            .runtime_server_certificate_file()
            .to_path_buf(),
        target_config
            .pxrp()
            .runtime_server_private_key_file()
            .to_path_buf(),
    )
    .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    Ok(PreparedDistributedTargetPrestartV1 {
        identities,
        topology,
        fabric_credential_resolver,
        transport,
        restricted_root_ca_certificate_file: target_config
            .pxrp()
            .root_ca_certificate_file()
            .to_path_buf(),
        restricted_listener_identity,
        controller_credentials,
    })
}

fn distributed_runtime_config_v1(
    manifest: &identity::DistributedDeveloperLocalIdentityManifestV1,
    target: identity::DistributedDeveloperLocalTargetV1,
    target_layout: &layout::DistributedDeveloperLocalTargetLayoutV1,
    prepared: &PreparedDistributedTargetPrestartV1,
    agent_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
    model_backend_resolver: Arc<dyn RuntimeModelBackendResolverV1>,
    failure: LocalProcessError,
) -> Result<RuntimeDeveloperLocalConfigV1, LocalProcessError> {
    let target_identity = manifest.target(target);
    let identity = runtime_developer_local_identity(
        prepared.identities,
        *manifest.controller_signing_seed(),
        *manifest.authority_signing_seed(),
        *target_identity.runtime_response_signing_seed(),
    )
    .map_err(|_| failure)?;
    let evidence_store_epoch =
        EvidenceStoreEpochV1::try_from_bytes(*target_identity.evidence_store_epoch())
            .map_err(|_| failure)?;
    let evidence_owner_ref =
        EvidenceOwnerRefV1::try_from_bytes(*target_identity.evidence_owner_ref())
            .map_err(|_| failure)?;
    let evidence_retention_policy = EvidenceRetentionPolicyV1::try_new(
        DEVELOPER_DISTRIBUTED_EVIDENCE_MAX_RECORDS,
        DEVELOPER_DISTRIBUTED_EVIDENCE_MAX_BYTES,
    )
    .map_err(|_| failure)?;
    let distributed = RuntimeDeveloperLocalDistributedAgentStackConfigV1::try_new(
        Arc::clone(&prepared.fabric_credential_resolver),
        target_layout.evidence_state_directory().to_path_buf(),
        evidence_store_epoch,
        evidence_owner_ref,
        evidence_retention_policy,
    )
    .map_err(|_| failure)?;
    RuntimeDeveloperLocalConfigV1::try_new_with_agent_and_model_resolvers(
        target_layout.runtime_state_directory().to_path_buf(),
        target_layout.runtime_socket_path().to_path_buf(),
        identity,
        agent_resolver,
        model_backend_resolver,
    )
    .and_then(|config| config.try_with_distributed_agent_stack(distributed))
    .and_then(|config| {
        config.try_with_restricted_runtime_apply_endpoint(
            prepared.transport.transport_profile().clone(),
            prepared.transport.profile_ref(),
            prepared.transport.expected_carrier().clone(),
            prepared.restricted_root_ca_certificate_file.clone(),
            prepared.restricted_listener_identity.clone(),
        )
    })
    .map_err(|_| failure)
}

fn distributed_deployment_target_v1(
    prepared: PreparedDistributedTargetPrestartV1,
    runtime: &RuntimeDeveloperLocalLifecycleV1,
    target_layout: &layout::DistributedDeveloperLocalTargetLayoutV1,
    authority_socket_path: &Path,
    authority: &DeveloperLocalTenureAuthorityV1,
    base_loopback_listen_endpoint: &str,
) -> Result<DeveloperFixtureDistributedTargetV1, LocalProcessError> {
    let PreparedDistributedTargetPrestartV1 {
        identities,
        topology,
        transport,
        controller_credentials,
        ..
    } = prepared;
    let ready = runtime.ready();
    let runtime_pins = DeveloperFixtureRuntimePinsV1::try_new(
        ready.manifest_canonical_wire().to_vec().into_boxed_slice(),
        ready.manifest_digest(),
        ready.runtime_store_instance_id(),
        ready.runtime_response_public_key(),
    )
    .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?;
    let agent_stack = DeveloperFixtureAgentStackInputV1::new(
        DeveloperFixturePathsV1::try_new(
            target_layout
                .controller_base_state_directory()
                .to_path_buf(),
            target_layout
                .controller_successor_state_directory()
                .to_path_buf(),
            authority_socket_path.to_path_buf(),
            target_layout.runtime_socket_path().to_path_buf(),
        )
        .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?,
        identities,
        runtime_pins,
        controller_credentials,
        authority.facts().clone(),
        DeveloperFixtureFabricEndpointV1::try_new(base_loopback_listen_endpoint)
            .map_err(|_| LocalProcessError::DistributedDeploymentActivation)?,
    );
    Ok(DeveloperFixtureDistributedTargetV1::new(
        agent_stack,
        topology,
        transport,
    ))
}

#[derive(Clone, Copy)]
enum CompositionConfigRef<'a> {
    Fixture(&'a DeveloperFixtureConfigV1),
    Provisioned(&'a DeveloperProvisionedConfigV1),
}

impl CompositionConfigRef<'_> {
    fn fabric_listen(&self) -> &str {
        match self {
            Self::Fixture(config) => config.fabric_listen(),
            Self::Provisioned(config) => config.fabric_listen(),
        }
    }

    const fn profile(self) -> DeveloperLocalProfileV1 {
        match self {
            Self::Fixture(config) => config.profile(),
            Self::Provisioned(config) => config.profile(),
        }
    }
}

struct CompositionProvider {
    deployment: DeploymentProvider,
    adapter_descriptor: ModelAdapterDescriptorV1,
    agent_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
    model_backend_resolver: Arc<dyn RuntimeModelBackendResolverV1>,
}

#[derive(Clone, Copy)]
enum DeploymentProvider {
    Fixture(ManagedAgentProviderSelectionV1),
    Provisioned(ManagedAgentProviderSelectionV1),
}

enum ResolvedProviderApiKeyV1 {
    OpenAi(OpenAiResolvedApiKeyV1),
    DeepSeek(DeepSeekResolvedApiKeyV1),
}

fn resolve_provisioned_api_key(
    profile: ProviderProfileV1,
    value: Option<std::ffi::OsString>,
) -> Result<ResolvedProviderApiKeyV1, LocalProcessError> {
    let bytes = value.ok_or(LocalProcessError::ProviderSecret)?.into_vec();
    match profile {
        ProviderProfileV1::OpenAiResponsesV1 => OpenAiResolvedApiKeyV1::try_new(bytes)
            .map(ResolvedProviderApiKeyV1::OpenAi)
            .map_err(|_| LocalProcessError::ProviderSecret),
        ProviderProfileV1::DeepSeekChatCompletionsV1 => DeepSeekResolvedApiKeyV1::try_new(bytes)
            .map(ResolvedProviderApiKeyV1::DeepSeek)
            .map_err(|_| LocalProcessError::ProviderSecret),
        ProviderProfileV1::DeterministicFixtureV1 => Err(LocalProcessError::ProviderSecret),
    }
}

fn prepare_fixture_provider(
    manifest: &identity::IdentityManifestV1,
) -> Result<CompositionProvider, LocalProcessError> {
    prepare_fixture_provider_from_values(
        *manifest.provider_ref(),
        *manifest.provider_configuration_digest(),
    )
}

fn prepare_distributed_fixture_provider(
    manifest: &identity::DistributedDeveloperLocalIdentityManifestV1,
) -> Result<CompositionProvider, LocalProcessError> {
    prepare_fixture_provider_from_values(
        *manifest.provider_ref(),
        *manifest.provider_configuration_digest(),
    )
}

fn prepare_fixture_provider_from_values(
    provider_ref: [u8; 16],
    provider_configuration_digest: [u8; 32],
) -> Result<CompositionProvider, LocalProcessError> {
    let provider_ref = ManagedAgentProviderRefV1::try_from_bytes(provider_ref)
        .map_err(|_| LocalProcessError::ProviderConfiguration)?;
    let selection = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
        provider_ref,
        Digest32::from_bytes(provider_configuration_digest),
    )
    .map_err(|_| LocalProcessError::ProviderConfiguration)?;
    let backend_identity = model_backend_identity(selection)?;
    let factory = LocalDeterministicEchoAdapterFactoryV1 { backend_identity };
    let resolver = Arc::new(
        LocalModelResolver::try_new(selection, factory)
            .map_err(|_| LocalProcessError::ProviderConfiguration)?,
    );
    Ok(CompositionProvider {
        deployment: DeploymentProvider::Fixture(selection),
        adapter_descriptor: LOCAL_DETERMINISTIC_ECHO_ADAPTER_DESCRIPTOR_V1,
        agent_resolver: resolver.clone(),
        model_backend_resolver: resolver,
    })
}

fn prepare_provisioned_provider(
    config: &DeveloperProvisionedConfigV1,
    manifest: &identity::IdentityManifestV1,
    api_key: ResolvedProviderApiKeyV1,
) -> Result<CompositionProvider, LocalProcessError> {
    let provider_ref = ManagedAgentProviderRefV1::try_from_bytes(*manifest.provider_ref())
        .map_err(|_| LocalProcessError::ProviderConfiguration)?;
    let provider_config = config
        .provider_config(provider_ref)
        .map_err(|_| LocalProcessError::ProviderConfiguration)?;
    if provider_config.config_digest().as_bytes() != manifest.provider_configuration_digest() {
        return Err(LocalProcessError::ProviderConfiguration);
    }
    let secret_ref = provisioned_secret_ref(config.secret_ref(), manifest)?;
    let selection = ManagedAgentProviderSelectionV1::try_provisioned(
        provider_ref,
        provider_config.config_digest(),
        secret_ref,
    )
    .map_err(|_| LocalProcessError::ProviderConfiguration)?;
    match (provider_config, api_key) {
        (ProvisionedProviderConfigV1::OpenAi(config), ResolvedProviderApiKeyV1::OpenAi(key)) => {
            provisioned_composition_provider(
                selection,
                OPENAI_RESPONSES_ADAPTER_DESCRIPTOR_V1,
                OpenAiResponsesProviderFactoryV1::new(config, key),
            )
        }
        (
            ProvisionedProviderConfigV1::DeepSeek(config),
            ResolvedProviderApiKeyV1::DeepSeek(key),
        ) => provisioned_composition_provider(
            selection,
            DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_DESCRIPTOR_V1,
            DeepSeekChatCompletionsProviderFactoryV1::new(config, key),
        ),
        _ => Err(LocalProcessError::ProviderConfiguration),
    }
}

fn provisioned_composition_provider<F>(
    selection: ManagedAgentProviderSelectionV1,
    adapter_descriptor: ModelAdapterDescriptorV1,
    factory: F,
) -> Result<CompositionProvider, LocalProcessError>
where
    F: ModelAdapterFactoryV1,
{
    let resolver = Arc::new(
        LocalModelResolver::try_new(selection, factory)
            .map_err(|_| LocalProcessError::ProviderConfiguration)?,
    );
    Ok(CompositionProvider {
        deployment: DeploymentProvider::Provisioned(selection),
        adapter_descriptor,
        agent_resolver: resolver.clone(),
        model_backend_resolver: resolver,
    })
}

fn provisioned_secret_ref(
    configured_ref: ProvisionedSecretRefV1,
    manifest: &identity::IdentityManifestV1,
) -> Result<ManagedAgentSecretRefV1, LocalProcessError> {
    let mut digest = Sha256::new();
    digest.update(match configured_ref {
        ProvisionedSecretRefV1::OpenAiApiKeyEnvironment => OPENAI_SECRET_REF_DOMAIN,
        ProvisionedSecretRefV1::DeepSeekApiKeyEnvironment => DEEPSEEK_SECRET_REF_DOMAIN,
    });
    digest.update(manifest.manifest_instance_id());
    digest.update(manifest.provider_ref());
    let digest: [u8; 32] = digest.finalize().into();
    let mut secret_ref = [0_u8; 16];
    secret_ref.copy_from_slice(&digest[..16]);
    ManagedAgentSecretRefV1::try_from_bytes(secret_ref)
        .map_err(|_| LocalProcessError::ProviderConfiguration)
}

fn model_backend_identity(
    selection: ManagedAgentProviderSelectionV1,
) -> Result<ModelBackendIdentityV1, LocalProcessError> {
    ModelBackendIdentityV1::try_new(
        *selection.provider_ref().as_bytes(),
        selection.config_digest(),
    )
    .map_err(|_| LocalProcessError::ProviderConfiguration)
}

struct LocalModelResolver {
    registry: ModelAdapterRegistryV1,
    selection: ManagedAgentProviderSelectionV1,
    adapter_selection: ModelAdapterSelectionV1,
}

#[derive(Clone)]
struct DeveloperDistributedFabricCredentialResolverV2 {
    peer_runtime_host: RuntimeHostId,
    connect_endpoint: DistributedFabricTlsEndpointV1,
    trust_domain_ref: DistributedFabricTrustDomainRefV1,
    local_credential_ref: DistributedFabricCredentialRefV1,
    trust_anchor_ref: DistributedFabricTrustAnchorRefV1,
    expected_peer_identity_ref: DistributedFabricPeerIdentityRefV1,
    expected_peer_common_name: Box<str>,
    credential_files: ResolvedRemoteMtlsCredentialFiles,
}

impl RuntimeFabricCredentialResolverV2 for DeveloperDistributedFabricCredentialResolverV2 {
    fn resolve(
        &self,
        requirement: &RuntimeFabricCredentialRequirementV1,
    ) -> Result<RuntimeResolvedFabricPeerCredentialV2, RuntimeFabricCredentialResolveErrorV2> {
        if requirement.peer_runtime_host() != self.peer_runtime_host
            || requirement.connect_endpoint() != &self.connect_endpoint
            || requirement.trust_domain_ref() != self.trust_domain_ref
            || requirement.local_credential_ref() != self.local_credential_ref
            || requirement.trust_anchor_ref() != self.trust_anchor_ref
            || requirement.expected_peer_identity_ref() != self.expected_peer_identity_ref
        {
            return Err(RuntimeFabricCredentialResolveErrorV2::ResolutionFailed);
        }
        RuntimeResolvedFabricPeerCredentialV2::try_new(
            requirement.requirement_digest(),
            requirement.expected_peer_identity_ref(),
            self.expected_peer_common_name.to_string(),
            self.credential_files.clone(),
        )
    }
}

impl LocalModelResolver {
    fn try_new<F>(
        selection: ManagedAgentProviderSelectionV1,
        factory: F,
    ) -> Result<Self, RuntimeAgentProviderResolveError>
    where
        F: ModelAdapterFactoryV1,
    {
        let backend_identity = ModelBackendIdentityV1::try_new(
            *selection.provider_ref().as_bytes(),
            selection.config_digest(),
        )
        .map_err(|_| RuntimeAgentProviderResolveError::ResolutionFailed)?;
        let metadata = factory.metadata();
        if metadata.backend_identity() != backend_identity {
            return Err(RuntimeAgentProviderResolveError::ResolutionFailed);
        }
        let adapter_selection =
            ModelAdapterSelectionV1::new(metadata.descriptor(), backend_identity);
        let mut registry = ModelAdapterRegistryV1::new();
        registry
            .register(factory)
            .map_err(|_| RuntimeAgentProviderResolveError::ResolutionFailed)?;
        Ok(Self {
            registry,
            selection,
            adapter_selection,
        })
    }
}

impl RuntimeAgentProviderResolverV1 for LocalModelResolver {
    fn resolve(
        &self,
        selection: ManagedAgentProviderSelectionV1,
    ) -> Result<RuntimeResolvedAgentProviderV1, RuntimeAgentProviderResolveError> {
        if selection != self.selection {
            return Err(RuntimeAgentProviderResolveError::ResolutionFailed);
        }
        let backend = self
            .registry
            .resolve(self.adapter_selection)
            .map_err(|_| RuntimeAgentProviderResolveError::ResolutionFailed)?;
        let service_config = ModelServiceConfigV1::try_new(DEVELOPER_MODEL_SERVICE_MAX_IN_FLIGHT)
            .map_err(|_| RuntimeAgentProviderResolveError::ResolutionFailed)?;
        let service = ModelServiceV1::new(service_config, backend);
        let provider = AgentConversationModelServiceProviderV1::new(service);
        Ok(RuntimeResolvedAgentProviderV1::new(selection, provider))
    }
}

impl paraegox_runtime::RuntimeModelBackendResolverV1 for LocalModelResolver {
    fn resolve(
        &self,
        plan: &ManagedModelServicePlanV1,
    ) -> Result<RuntimeResolvedModelBackendV1, RuntimeModelBackendResolveError> {
        if plan.provider() != self.selection {
            return Err(RuntimeModelBackendResolveError::ResolutionFailed);
        }

        let binding = plan.adapter_binding();
        let adapter_id = ModelAdapterIdV1::try_from_bytes(*binding.adapter_id())
            .map_err(|_| RuntimeModelBackendResolveError::ResolutionFailed)?;
        let adapter_version = ModelAdapterVersionV1::try_new(binding.adapter_version().value())
            .map_err(|_| RuntimeModelBackendResolveError::ResolutionFailed)?;
        let capability_id =
            ModelCapabilityIdV1::try_from_bytes(*binding.capability_id().as_bytes())
                .map_err(|_| RuntimeModelBackendResolveError::ResolutionFailed)?;
        let descriptor = ModelAdapterDescriptorV1::new(adapter_id, adapter_version, capability_id);
        let backend_identity = ModelBackendIdentityV1::try_new(
            *plan.provider().provider_ref().as_bytes(),
            plan.provider().config_digest(),
        )
        .map_err(|_| RuntimeModelBackendResolveError::ResolutionFailed)?;
        let adapter_selection = ModelAdapterSelectionV1::new(descriptor, backend_identity);
        if adapter_selection != self.adapter_selection {
            return Err(RuntimeModelBackendResolveError::ResolutionFailed);
        }

        let backend = self
            .registry
            .resolve(adapter_selection)
            .map_err(|_| RuntimeModelBackendResolveError::ResolutionFailed)?;
        Ok(RuntimeResolvedModelBackendV1::from_shared(*plan, backend))
    }
}

struct LocalDeterministicEchoAdapterFactoryV1 {
    backend_identity: ModelBackendIdentityV1,
}

impl ModelAdapterFactoryV1 for LocalDeterministicEchoAdapterFactoryV1 {
    fn metadata(&self) -> ModelAdapterMetadataV1 {
        ModelAdapterMetadataV1::new(
            LOCAL_DETERMINISTIC_ECHO_ADAPTER_DESCRIPTOR_V1,
            self.backend_identity,
        )
    }

    fn build(&self) -> Result<Arc<dyn ModelBackendV1>, ModelAdapterBuildErrorV1> {
        Ok(Arc::new(LocalDeterministicEchoModelBackendV1 {
            identity: self.backend_identity,
        }))
    }
}

struct LocalDeterministicEchoModelBackendV1 {
    identity: ModelBackendIdentityV1,
}

impl ModelBackendV1 for LocalDeterministicEchoModelBackendV1 {
    fn identity(&self) -> ModelBackendIdentityV1 {
        self.identity
    }

    fn invoke(
        &self,
        request: ModelInvocationRequestV1,
        cancellation: ModelCancellationViewV1,
    ) -> ModelBackendFuture {
        let output = format!("echo: {}", request.prompt()).into_boxed_str();
        Box::pin(async move {
            if cancellation.is_cancellation_requested() {
                ModelInvocationOutcomeV1::CancelledBeforeHandoff
            } else {
                ModelInvocationOutcomeV1::Success(output)
            }
        })
    }
}

#[derive(Clone, Copy)]
struct LocalConversationBounds {
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    request_deadline_budget: Duration,
    command_capacity: usize,
    operation_timeout: Duration,
}

impl LocalConversationBounds {
    fn try_new(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_deadline_budget: Duration,
        command_capacity: usize,
        operation_timeout: Duration,
    ) -> Result<Self, LocalProcessError> {
        let command_capacity_wire = u16::try_from(command_capacity)
            .map_err(|_| LocalProcessError::ConversationConfiguration)?;
        RuntimeAgentDeveloperLocalConversationV1::try_new(
            deck_run_id,
            session_id,
            request_deadline_budget,
            operation_timeout,
        )
        .map_err(|_| LocalProcessError::ConversationConfiguration)?;
        RuntimeAgentDeveloperLocalIpcLimitsV1::try_new(
            operation_timeout,
            command_capacity_wire,
            command_capacity,
        )
        .map_err(|_| LocalProcessError::ConversationConfiguration)?;
        Ok(Self {
            deck_run_id,
            session_id,
            request_deadline_budget,
            command_capacity,
            operation_timeout,
        })
    }
}

struct ConversationRunInput {
    handle: RuntimeAgentConversationHandle,
    config: LocalConversationBounds,
    ipc_socket_path: PathBuf,
    ipc_bootstrap_path: PathBuf,
    inspection: Option<ConversationInspectionInput>,
    expected_uid: u32,
    expected_gid: u32,
}

struct ConversationInspectionInput {
    sources: DeveloperLocalInspectionSourcesV2,
    ipc_socket_path: PathBuf,
    ipc_bootstrap_path: PathBuf,
}

trait ConversationRunner {
    fn run(&mut self, input: ConversationRunInput) -> Result<(), LocalProcessError>;
}

struct ChildProcessConversationRunner;

impl ConversationRunner for ChildProcessConversationRunner {
    fn run(&mut self, input: ConversationRunInput) -> Result<(), LocalProcessError> {
        let conversation_endpoint = start_conversation_ipc(&input)?;
        let inspection_endpoint = input
            .inspection
            .as_ref()
            .map(|inspection| start_inspection_ipc(&input, inspection))
            .transpose()?;
        let child_result = spawn_and_join_console(
            &input.ipc_bootstrap_path,
            input
                .inspection
                .as_ref()
                .map(|inspection| inspection.ipc_bootstrap_path.as_path()),
        );
        let inspection_result = inspection_endpoint.map_or(Ok(()), |endpoint| {
            endpoint
                .shutdown_and_join()
                .map_err(|_| LocalProcessError::InspectionIpc)
        });
        let conversation_result = conversation_endpoint
            .shutdown_and_join()
            .map_err(|_| LocalProcessError::ConversationIpc);
        child_result.and(inspection_result).and(conversation_result)
    }
}

fn start_inspection_ipc(
    input: &ConversationRunInput,
    inspection: &ConversationInspectionInput,
) -> Result<crate::inspection::DeveloperLocalInspectionLifecycleV2, LocalProcessError> {
    start_developer_local_inspection_v2(
        inspection.sources.clone(),
        inspection.ipc_socket_path.clone(),
        inspection.ipc_bootstrap_path.clone(),
        input.expected_uid,
        input.expected_gid,
    )
    .map_err(|_| LocalProcessError::InspectionIpc)
}

fn start_conversation_ipc(
    input: &ConversationRunInput,
) -> Result<RuntimeAgentDeveloperLocalIpcLifecycleV1, LocalProcessError> {
    let command_capacity = u16::try_from(input.config.command_capacity)
        .map_err(|_| LocalProcessError::ConversationConfiguration)?;
    let paths = RuntimeAgentDeveloperLocalIpcPathsV1::try_new(
        input.ipc_socket_path.clone(),
        input.ipc_bootstrap_path.clone(),
        input.expected_uid,
        input.expected_gid,
    )
    .map_err(|_| LocalProcessError::ConversationIpc)?;
    let conversation = RuntimeAgentDeveloperLocalConversationV1::try_new(
        input.config.deck_run_id,
        input.config.session_id,
        input.config.request_deadline_budget,
        input.config.operation_timeout,
    )
    .map_err(|_| LocalProcessError::ConversationConfiguration)?;
    let limits = RuntimeAgentDeveloperLocalIpcLimitsV1::try_new(
        input.config.operation_timeout,
        command_capacity,
        input.config.command_capacity,
    )
    .map_err(|_| LocalProcessError::ConversationConfiguration)?;
    let config = RuntimeAgentDeveloperLocalIpcConfigV1::try_new(paths, conversation, limits)
        .map_err(|_| LocalProcessError::ConversationConfiguration)?;
    start_runtime_agent_developer_local_ipc_v1(input.handle.clone(), config)
        .map_err(|_| LocalProcessError::ConversationIpc)
}

fn spawn_and_join_console(
    runtime_bootstrap_path: &std::path::Path,
    inspection_bootstrap_path: Option<&std::path::Path>,
) -> Result<(), LocalProcessError> {
    let mut command = build_console_command(runtime_bootstrap_path, inspection_bootstrap_path);
    let status = JoinedChild::spawn(&mut command)?.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(LocalProcessError::ConversationChild)
    }
}

fn build_console_command(
    runtime_bootstrap_path: &std::path::Path,
    inspection_bootstrap_path: Option<&std::path::Path>,
) -> Command {
    let mut command = Command::new(resolve_console_program());
    command
        .arg(RUNTIME_BOOTSTRAP_FILE_OPTION)
        .arg(runtime_bootstrap_path);
    if let Some(inspection_bootstrap_path) = inspection_bootstrap_path {
        command
            .arg(INSPECTION_BOOTSTRAP_FILE_OPTION)
            .arg(inspection_bootstrap_path);
    }
    command
        .env_remove(ProvisionedSecretRefV1::OpenAiApiKeyEnvironment.environment_variable())
        .env_remove(ProvisionedSecretRefV1::DeepSeekApiKeyEnvironment.environment_variable())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
}

fn resolve_console_program() -> PathBuf {
    env::current_exe().map_or_else(
        |_| PathBuf::from(CONSOLE_COMMAND),
        |executable| console_program_for_executable(&executable),
    )
}

fn console_program_for_executable(executable: &Path) -> PathBuf {
    let Some(directory) = executable.parent() else {
        return PathBuf::from(CONSOLE_COMMAND);
    };
    let sibling = directory.join(CONSOLE_COMMAND);
    let Ok(metadata) = fs::symlink_metadata(&sibling) else {
        return PathBuf::from(CONSOLE_COMMAND);
    };
    if metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.permissions().mode() & 0o111 != 0
    {
        sibling
    } else {
        PathBuf::from(CONSOLE_COMMAND)
    }
}

struct JoinedChild {
    child: Option<Child>,
}

impl JoinedChild {
    fn spawn(command: &mut Command) -> Result<Self, LocalProcessError> {
        let child = command
            .spawn()
            .map_err(|_| LocalProcessError::ConversationChild)?;
        Ok(Self { child: Some(child) })
    }

    fn wait(mut self) -> Result<std::process::ExitStatus, LocalProcessError> {
        let result = self
            .child
            .as_mut()
            .expect("child exists until joined wait")
            .wait()
            .map_err(|_| LocalProcessError::ConversationChild);
        if result.is_ok() {
            self.child.take();
        }
        result
    }
}

impl Drop for JoinedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct RunningStack<'a> {
    config: CompositionConfigRef<'a>,
    manifest: &'a identity::IdentityManifestV1,
    layout: &'a layout::DeveloperLocalLayoutV1,
    identities: DeveloperFixtureDerivedIdentityV1,
    authority_verification_key: [u8; 32],
    deployment_provider: DeploymentProvider,
    adapter_descriptor: ModelAdapterDescriptorV1,
    owners: Option<RunningOwners>,
}

impl RunningStack<'_> {
    fn owners(&self) -> &RunningOwners {
        self.owners
            .as_ref()
            .expect("owners exist until joined shutdown")
    }

    fn runtime(&self) -> &RuntimeDeveloperLocalLifecycleV1 {
        self.owners().runtime()
    }

    fn deployment_input(
        &self,
        failure: LocalProcessError,
    ) -> Result<DeveloperFixtureAgentStackInputV1, LocalProcessError> {
        let runtime_ready = self.runtime().ready();
        Ok(DeveloperFixtureAgentStackInputV1::new(
            DeveloperFixturePathsV1::try_new(
                self.layout.controller_state_directory().to_path_buf(),
                self.layout.successor_state_directory().to_path_buf(),
                self.layout.authority_socket_path().to_path_buf(),
                self.layout.runtime_socket_path().to_path_buf(),
            )
            .map_err(|_| failure)?,
            self.identities,
            DeveloperFixtureRuntimePinsV1::try_new(
                runtime_ready
                    .manifest_canonical_wire()
                    .to_vec()
                    .into_boxed_slice(),
                runtime_ready.manifest_digest(),
                runtime_ready.runtime_store_instance_id(),
                runtime_ready.runtime_response_public_key(),
            )
            .map_err(|_| failure)?,
            DeveloperFixtureControllerCredentialsV1::try_new(
                Zeroizing::new(*self.manifest.controller_signing_seed()),
                self.authority_verification_key,
            )
            .map_err(|_| failure)?,
            self.owners().authority().facts().clone(),
            DeveloperFixtureFabricEndpointV1::try_new(self.config.fabric_listen())
                .map_err(|_| failure)?,
        ))
    }

    fn activate(&mut self) -> Result<DeveloperLocalDeploymentOutcomeV1, LocalProcessError> {
        let input = self.deployment_input(LocalProcessError::DeploymentActivation)?;
        match self.deployment_provider {
            DeploymentProvider::Fixture(selection) => {
                let model =
                    developer_model_plan(self.identities, selection, self.adapter_descriptor)?;
                let input = DeveloperFixtureModelAgentStackInputV1::try_new(input, model)
                    .map_err(|_| LocalProcessError::DeploymentActivation)?;
                run_developer_fixture_model_agent_stack_v1(input)
                    .map(DeveloperLocalDeploymentOutcomeV1::Fixture)
                    .map_err(|_| LocalProcessError::DeploymentActivation)
            }
            DeploymentProvider::Provisioned(selection) => {
                let model =
                    developer_model_plan(self.identities, selection, self.adapter_descriptor)?;
                let common = DeveloperProvisionedAgentStackInputV1::try_new(input, selection)
                    .map_err(|_| LocalProcessError::DeploymentActivation)?;
                let input = DeveloperProvisionedModelAgentStackInputV1::try_new(common, model)
                    .map_err(|_| LocalProcessError::DeploymentActivation)?;
                run_developer_provisioned_model_agent_stack_v1(input)
                    .map(DeveloperLocalDeploymentOutcomeV1::Provisioned)
                    .map_err(|_| LocalProcessError::DeploymentActivation)
            }
        }
    }

    fn inspection_sources(
        &self,
        deployment: DeveloperLocalDeploymentOutcomeV1,
    ) -> DeveloperLocalInspectionSourcesV2 {
        let runtime_ready = self.runtime().ready();
        DeveloperLocalInspectionSourcesV2 {
            authority_subject: self.identities.authority_ref(),
            deployment_subject: self.identities.controller_principal(),
            runtime_subject: runtime_ready.target(),
            runtime_store_instance_id: runtime_ready.runtime_store_instance_id(),
            runtime_response_key_ref: runtime_ready.runtime_response_key_ref(),
            runtime_response_public_key: runtime_ready.runtime_response_public_key(),
            fabric_subject: self.identities.fabric_service_id(),
            agent_subject: self.identities.agent_service_id(),
            node_status: self.owners().node().status().clone(),
            node_status_observed_at: self.owners().node().status_observed_at(),
            deployment,
        }
    }

    fn cleanup(&mut self) -> Result<(), LocalProcessError> {
        self.owners.take().map_or(Ok(()), RunningOwners::shutdown)
    }
}

fn developer_model_plan(
    identities: DeveloperFixtureDerivedIdentityV1,
    provider: ManagedAgentProviderSelectionV1,
    descriptor: ModelAdapterDescriptorV1,
) -> Result<ManagedModelServicePlanV1, LocalProcessError> {
    let budget = BoundedDuration::from_nanos(DEVELOPER_MODEL_LIFECYCLE_NANOS);
    let lifecycle =
        ManagedServiceLifecycleBudgetsV1::try_new(budget, budget, budget, budget, budget)
            .map_err(|_| LocalProcessError::DeploymentActivation)?;
    let binding = ManagedModelAdapterBindingV1::try_new(
        *descriptor.adapter_id().as_bytes(),
        ManagedModelAdapterVersionV1::try_new(descriptor.version().value())
            .map_err(|_| LocalProcessError::DeploymentActivation)?,
        ManagedModelCapabilityIdV1::try_from_bytes(*descriptor.capability_id().as_bytes())
            .map_err(|_| LocalProcessError::DeploymentActivation)?,
    )
    .map_err(|_| LocalProcessError::DeploymentActivation)?;
    ManagedModelServicePlanV1::try_new(
        ManagedServiceSpecV1::new(
            ManagedServiceId::from_bytes(identities.model_service_id()),
            lifecycle,
        ),
        u16::try_from(DEVELOPER_MODEL_SERVICE_MAX_IN_FLIGHT)
            .map_err(|_| LocalProcessError::DeploymentActivation)?,
        provider,
        binding,
    )
    .map_err(|_| LocalProcessError::DeploymentActivation)
}

impl Drop for RunningStack<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn derive_identities(
    manifest: &identity::IdentityManifestV1,
) -> Result<DeveloperFixtureDerivedIdentityV1, LocalProcessError> {
    DeveloperFixtureDerivedIdentityV1::try_from_seed(DeveloperFixtureIdentitySeedV1 {
        manifest_instance_id: *manifest.manifest_instance_id(),
        controller_instance_id: *manifest.controller_instance_id(),
        authority_instance_id: *manifest.authority_instance_id(),
        runtime_instance_id: *manifest.runtime_instance_id(),
        source_scope_id: *manifest.source_scope_id(),
        source_plan_id: *manifest.source_plan_id(),
        fabric_service_id: *manifest.fabric_service_id(),
        agent_service_id: *manifest.agent_service_id(),
        submit_binding_id: *manifest.submit_binding_id(),
        control_binding_id: *manifest.control_binding_id(),
        provider_ref: *manifest.provider_ref(),
        deck_run_id: *manifest.deck_run_id(),
        session_id: *manifest.session_id(),
        provider_configuration_digest: *manifest.provider_configuration_digest(),
    })
    .map_err(|_| LocalProcessError::IdentityDerivation)
}

fn authority_identities(
    identities: DeveloperFixtureDerivedIdentityV1,
) -> DeveloperLocalTenureAuthorityIdentityBytesV1 {
    DeveloperLocalTenureAuthorityIdentityBytesV1 {
        source_scope: identities.source_scope(),
        writer: identities.writer(),
        authority: identities.authority_ref(),
        authority_key: identities.authority_key_ref(),
        controller_principal: identities.controller_principal(),
        controller_key: identities.controller_key_ref(),
        service_principal: identities.authority_service_principal(),
        owner: identities.authority_owner(),
    }
}

fn signing_verification_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

struct PreparedDistributedNodeReferenceV1 {
    bootstrap: DeveloperLocalReferenceBootstrapV1,
    status: NodeStatusV1,
    management_target: NodeManagementTargetV1,
}

fn prepare_distributed_node_reference_v1(
    manifest: &identity::DistributedDeveloperLocalIdentityManifestV1,
    target: identity::DistributedDeveloperLocalTargetV1,
    target_layout: &layout::DistributedDeveloperLocalTargetLayoutV1,
    identities: DeveloperFixtureDerivedIdentityV1,
) -> Result<PreparedDistributedNodeReferenceV1, LocalProcessError> {
    let target_identity = manifest.target(target);
    let node_id = NodeId::try_from_bytes(*target_identity.node_id())
        .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let node_incarnation = NodeIncarnation::try_from_bytes(*target_identity.node_incarnation())
        .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let management_endpoint_ref = NodeManagementEndpointRefV1::try_from_bytes(
        *target_identity.node_management_endpoint_ref(),
    )
    .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let identity = NodeIdentityV1::try_new(
        node_id,
        PrincipalRef::from_bytes(*target_identity.node_principal()),
        EnrollmentIssuerRefV1::try_from_bytes(*manifest.enrollment_issuer_ref())
            .map_err(|_| LocalProcessError::NodeBootstrap)?,
    )
    .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let tenure = NodeRegistrationTenureV1::try_new(
        node_id,
        target_identity.registration_epoch(),
        node_incarnation,
    )
    .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let feature = developer_node_feature_report(node_id, node_incarnation, identities)?;
    let expected =
        DeveloperLocalReferenceBootstrapV1::try_new(DeveloperLocalReferenceBootstrapInputV1 {
            expected_uid: Uid::effective().as_raw(),
            expected_gid: Gid::effective().as_raw(),
            generation_token: *target_identity.pxnb_reference_token(),
            identity,
            tenure,
            management_endpoint_ref,
            initial_feature_report: feature,
            state_root: target_layout.node_state_directory().to_path_buf(),
            socket_path: target_layout.node_management_socket_path().to_path_buf(),
        })
        .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let bootstrap = match fs::symlink_metadata(target_layout.pxnb_bootstrap_path()) {
        Ok(_) => {
            let existing = DeveloperLocalReferenceBootstrapV1::read_owner_private_file(
                target_layout.pxnb_bootstrap_path(),
            )
            .map_err(|_| LocalProcessError::NodeBootstrap)?;
            let existing_wire = existing
                .canonical_wire()
                .map_err(|_| LocalProcessError::NodeBootstrap)?;
            let expected_wire = expected
                .canonical_wire()
                .map_err(|_| LocalProcessError::NodeBootstrap)?;
            if existing_wire.as_slice() != expected_wire.as_slice() {
                return Err(LocalProcessError::NodeBootstrap);
            }
            existing
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            expected
                .write_owner_private_file(target_layout.pxnb_bootstrap_path())
                .map_err(|_| LocalProcessError::NodeBootstrap)?;
            expected
        }
        Err(_) => return Err(LocalProcessError::NodeBootstrap),
    };
    let mut owner = DurableNodeDaemonV1::open(
        bootstrap.state_root(),
        bootstrap.identity(),
        bootstrap.tenure(),
        bootstrap.management_endpoint_ref(),
        bootstrap.initial_feature_report(),
    )
    .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let status = match owner.current_status().cloned() {
        Some(status) => status,
        None => owner
            .publish_status(MAX_NODE_STATUS_FRESHNESS_NANOS)
            .map_err(|_| LocalProcessError::NodeBootstrap)?,
    };
    drop(owner);
    let management_target = NodeManagementTargetV1::try_new(
        node_id,
        management_endpoint_ref,
        node_incarnation,
        target_identity.registration_epoch(),
    )
    .map_err(|_| LocalProcessError::NodeBootstrap)?;
    Ok(PreparedDistributedNodeReferenceV1 {
        bootstrap,
        status,
        management_target,
    })
}

fn write_distributed_runtime_observation_bootstrap_v1(
    manifest: &identity::DistributedDeveloperLocalIdentityManifestV1,
    target: identity::DistributedDeveloperLocalTargetV1,
    target_layout: &layout::DistributedDeveloperLocalTargetLayoutV1,
    management_target: NodeManagementTargetV1,
    authority: RuntimeObservationAuthorityV1,
) -> Result<(), LocalProcessError> {
    let target_identity = manifest.target(target);
    if authority.runtime_host_id() != RuntimeHostId::from_bytes(*target_identity.runtime_target()) {
        return Err(LocalProcessError::NodeBootstrap);
    }
    let bootstrap = RuntimeObservationBootstrapV1::try_new(RuntimeObservationBootstrapInputV1 {
        expected_uid: Uid::effective().as_raw(),
        expected_gid: Gid::effective().as_raw(),
        generation_token: *target_identity.pxob_observation_token(),
        node_target: management_target,
        observation_endpoint_ref: RuntimeObservationEndpointRefV1::try_from_bytes(
            *target_identity.runtime_observation_endpoint_ref(),
        )
        .map_err(|_| LocalProcessError::NodeBootstrap)?,
        socket_path: target_layout.node_observation_socket_path().to_path_buf(),
        authorities: vec![authority],
    })
    .map_err(|_| LocalProcessError::NodeBootstrap)?;
    bootstrap
        .write_owner_private_file(target_layout.pxob_bootstrap_path())
        .map_err(|_| LocalProcessError::NodeBootstrap)
}

fn prepare_developer_local_node_v1(
    layout: &layout::DeveloperLocalLayoutV1,
    identities: DeveloperFixtureDerivedIdentityV1,
) -> Result<(DeveloperLocalReferenceBootstrapV1, NodeStatusV1), LocalProcessError> {
    let bootstrap = match fs::symlink_metadata(layout.pxnb_bootstrap_path()) {
        Ok(_) => DeveloperLocalReferenceBootstrapV1::read_owner_private_file(
            layout.pxnb_bootstrap_path(),
        )
        .map_err(|_| LocalProcessError::NodeBootstrap)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let bootstrap = new_developer_local_node_bootstrap(layout, identities)?;
            bootstrap
                .write_owner_private_file(layout.pxnb_bootstrap_path())
                .map_err(|_| LocalProcessError::NodeBootstrap)?;
            bootstrap
        }
        Err(_) => return Err(LocalProcessError::NodeBootstrap),
    };
    validate_developer_local_node_bootstrap(&bootstrap, layout, identities)?;
    let mut owner = DurableNodeDaemonV1::open(
        bootstrap.state_root(),
        bootstrap.identity(),
        bootstrap.tenure(),
        bootstrap.management_endpoint_ref(),
        bootstrap.initial_feature_report(),
    )
    .map_err(|_| LocalProcessError::NodeBootstrap)?;
    if owner
        .current_status()
        .is_some_and(|status| !status.runtime_hosts().is_empty())
    {
        return Err(LocalProcessError::NodeBootstrap);
    }
    let status = owner
        .publish_status(MAX_NODE_STATUS_FRESHNESS_NANOS)
        .map_err(|_| LocalProcessError::NodeBootstrap)?;
    if !status.runtime_hosts().is_empty() {
        return Err(LocalProcessError::NodeBootstrap);
    }
    drop(owner);
    Ok((bootstrap, status))
}

fn new_developer_local_node_bootstrap(
    layout: &layout::DeveloperLocalLayoutV1,
    identities: DeveloperFixtureDerivedIdentityV1,
) -> Result<DeveloperLocalReferenceBootstrapV1, LocalProcessError> {
    let mut entropy = Zeroizing::new([0_u8; DEVELOPER_NODE_BOOTSTRAP_ENTROPY_BYTES]);
    getrandom::fill(entropy.as_mut()).map_err(|_| LocalProcessError::NodeBootstrap)?;
    let generation_token = Zeroizing::new(copy_array::<DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES>(
        entropy.as_ref(),
        0,
    )?);
    let node_id_bytes = copy_array::<16>(entropy.as_ref(), DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES)?;
    let node_principal_bytes =
        copy_array::<16>(entropy.as_ref(), DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES + 16)?;
    let node_incarnation_bytes =
        copy_array::<16>(entropy.as_ref(), DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES + 32)?;
    let management_endpoint_bytes =
        copy_array::<16>(entropy.as_ref(), DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES + 48)?;
    let identity_fields = [
        node_id_bytes,
        node_principal_bytes,
        node_incarnation_bytes,
        management_endpoint_bytes,
    ];
    if generation_token.iter().all(|byte| *byte == 0)
        || identity_fields
            .iter()
            .any(|field| field.iter().all(|byte| *byte == 0))
        || identity_fields
            .iter()
            .enumerate()
            .any(|(index, field)| identity_fields[index + 1..].contains(field))
    {
        return Err(LocalProcessError::NodeBootstrap);
    }

    let node_id =
        NodeId::try_from_bytes(node_id_bytes).map_err(|_| LocalProcessError::NodeBootstrap)?;
    let node_incarnation = NodeIncarnation::try_from_bytes(node_incarnation_bytes)
        .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let management_endpoint_ref =
        NodeManagementEndpointRefV1::try_from_bytes(management_endpoint_bytes)
            .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let identity = NodeIdentityV1::try_new(
        node_id,
        PrincipalRef::from_bytes(node_principal_bytes),
        developer_node_enrollment_issuer(identities)?,
    )
    .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let tenure = NodeRegistrationTenureV1::try_new(
        node_id,
        DEVELOPER_NODE_REGISTRATION_EPOCH,
        node_incarnation,
    )
    .map_err(|_| LocalProcessError::NodeBootstrap)?;
    let initial_feature_report =
        developer_node_feature_report(node_id, node_incarnation, identities)?;
    DeveloperLocalReferenceBootstrapV1::try_new(DeveloperLocalReferenceBootstrapInputV1 {
        expected_uid: Uid::effective().as_raw(),
        expected_gid: Gid::effective().as_raw(),
        generation_token: *generation_token,
        identity,
        tenure,
        management_endpoint_ref,
        initial_feature_report,
        state_root: layout.node_state_directory().to_path_buf(),
        socket_path: layout.node_management_socket_path().to_path_buf(),
    })
    .map_err(|_| LocalProcessError::NodeBootstrap)
}

fn validate_developer_local_node_bootstrap(
    bootstrap: &DeveloperLocalReferenceBootstrapV1,
    layout: &layout::DeveloperLocalLayoutV1,
    identities: DeveloperFixtureDerivedIdentityV1,
) -> Result<(), LocalProcessError> {
    let (operating_system, architecture) = developer_node_platform()?;
    let feature = bootstrap.initial_feature_report();
    if bootstrap.expected_uid() != Uid::effective().as_raw()
        || bootstrap.expected_gid() != Gid::effective().as_raw()
        || bootstrap.state_root() != layout.node_state_directory()
        || bootstrap.socket_path() != layout.node_management_socket_path()
        || bootstrap.identity().enrollment_issuer() != developer_node_enrollment_issuer(identities)?
        || bootstrap.tenure().registration_epoch() != DEVELOPER_NODE_REGISTRATION_EPOCH
        || feature.operating_system() != operating_system
        || feature.architecture() != architecture
        || feature.platform_profile_digest() != developer_node_platform_digest(identities)
        || feature.runtime_contract_version() != DEVELOPER_NODE_RUNTIME_CONTRACT_VERSION
        || feature.fabric_contract_version() != DEVELOPER_NODE_FABRIC_CONTRACT_VERSION
    {
        return Err(LocalProcessError::NodeBootstrap);
    }
    Ok(())
}

fn developer_node_enrollment_issuer(
    identities: DeveloperFixtureDerivedIdentityV1,
) -> Result<EnrollmentIssuerRefV1, LocalProcessError> {
    let mut digest = Sha256::new();
    digest.update(DEVELOPER_NODE_ENROLLMENT_DOMAIN);
    digest.update(identities.installation_id());
    digest.update(identities.authority_ref());
    let digest: [u8; 32] = digest.finalize().into();
    let mut value = [0_u8; 16];
    value.copy_from_slice(&digest[..16]);
    EnrollmentIssuerRefV1::try_from_bytes(value).map_err(|_| LocalProcessError::NodeBootstrap)
}

fn developer_node_feature_report(
    node_id: NodeId,
    node_incarnation: NodeIncarnation,
    identities: DeveloperFixtureDerivedIdentityV1,
) -> Result<NodeFeatureReportV1, LocalProcessError> {
    let (operating_system, architecture) = developer_node_platform()?;
    NodeFeatureReportV1::try_new(NodeFeatureReportInputV1 {
        node_id,
        node_incarnation,
        report_sequence: DEVELOPER_NODE_FEATURE_SEQUENCE,
        operating_system,
        architecture,
        platform_profile_digest: developer_node_platform_digest(identities),
        runtime_contract_version: DEVELOPER_NODE_RUNTIME_CONTRACT_VERSION,
        fabric_contract_version: DEVELOPER_NODE_FABRIC_CONTRACT_VERSION,
    })
    .map_err(|_| LocalProcessError::NodeBootstrap)
}

fn developer_node_platform_digest(identities: DeveloperFixtureDerivedIdentityV1) -> Digest32 {
    let (operating_system, architecture) = developer_node_platform()
        .expect("DeveloperLocal configuration already rejects unsupported platforms");
    let mut digest = Sha256::new();
    digest.update(DEVELOPER_NODE_PLATFORM_DOMAIN);
    digest.update(identities.installation_id());
    digest.update([operating_system as u8]);
    digest.update([architecture as u8]);
    digest.update(DEVELOPER_NODE_RUNTIME_CONTRACT_VERSION.to_be_bytes());
    digest.update(DEVELOPER_NODE_FABRIC_CONTRACT_VERSION.to_be_bytes());
    Digest32::from_bytes(digest.finalize().into())
}

fn developer_node_platform()
-> Result<(NodeOperatingSystemV1, NodeArchitectureV1), LocalProcessError> {
    #[cfg(target_os = "linux")]
    let operating_system = NodeOperatingSystemV1::Linux;
    #[cfg(target_os = "macos")]
    let operating_system = NodeOperatingSystemV1::MacOs;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(LocalProcessError::NodeBootstrap);

    #[cfg(target_arch = "x86_64")]
    let architecture = NodeArchitectureV1::X86_64;
    #[cfg(target_arch = "aarch64")]
    let architecture = NodeArchitectureV1::Aarch64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(LocalProcessError::NodeBootstrap);

    Ok((operating_system, architecture))
}

fn copy_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], LocalProcessError> {
    bytes
        .get(offset..offset.saturating_add(N))
        .and_then(|value| value.try_into().ok())
        .ok_or(LocalProcessError::NodeBootstrap)
}

struct RunningNodeDaemon {
    child: Option<Child>,
    status: NodeStatusV1,
    status_observed_at: Instant,
    observation_bootstrap_path: Option<PathBuf>,
}

impl RunningNodeDaemon {
    fn start(
        bootstrap_path: &Path,
        bootstrap: DeveloperLocalReferenceBootstrapV1,
        expected_status: NodeStatusV1,
    ) -> Result<Self, LocalProcessError> {
        Self::start_inner(bootstrap_path, None, None, bootstrap, expected_status)
    }

    fn start_runtime_observation(
        bootstrap_path: &Path,
        observation_bootstrap_path: &Path,
        observation_socket_path: &Path,
        bootstrap: DeveloperLocalReferenceBootstrapV1,
        expected_status: NodeStatusV1,
    ) -> Result<Self, LocalProcessError> {
        let result = Self::start_inner(
            bootstrap_path,
            Some(observation_bootstrap_path),
            Some(observation_socket_path),
            bootstrap,
            expected_status,
        );
        if result.is_err() {
            // This invocation wrote PXOB immediately before spawning the
            // child. If spawn itself fails there is no RunningNodeDaemon guard
            // to own that file, so remove only this exact no-replace bootstrap.
            let _ = fs::remove_file(observation_bootstrap_path);
        }
        result
    }

    fn start_inner(
        bootstrap_path: &Path,
        observation_bootstrap_path: Option<&Path>,
        observation_socket_path: Option<&Path>,
        bootstrap: DeveloperLocalReferenceBootstrapV1,
        expected_status: NodeStatusV1,
    ) -> Result<Self, LocalProcessError> {
        let executable = env::current_exe().map_err(|_| LocalProcessError::NodeStartup)?;
        let mut command = Command::new(executable);
        #[cfg(not(test))]
        command
            .arg(NODE_DAEMON_CHILD_MODE)
            .arg(NODE_BOOTSTRAP_FILE_OPTION)
            .arg(bootstrap_path);
        #[cfg(not(test))]
        if let Some(observation_bootstrap_path) = observation_bootstrap_path {
            command
                .arg(NODE_OBSERVATION_BOOTSTRAP_FILE_OPTION)
                .arg(observation_bootstrap_path);
        }
        #[cfg(test)]
        command
            .arg("--exact")
            .arg(NODE_DAEMON_PROBE_TEST_NAME)
            .arg("--nocapture")
            .env(NODE_DAEMON_PROBE_BOOTSTRAP_ENVIRONMENT, bootstrap_path);
        #[cfg(test)]
        if let Some(observation_bootstrap_path) = observation_bootstrap_path {
            command.env(
                NODE_DAEMON_PROBE_OBSERVATION_BOOTSTRAP_ENVIRONMENT,
                observation_bootstrap_path,
            );
        }
        command
            .env_remove(ProvisionedSecretRefV1::OpenAiApiKeyEnvironment.environment_variable())
            .env_remove(ProvisionedSecretRefV1::DeepSeekApiKeyEnvironment.environment_variable())
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let child = command
            .spawn()
            .map_err(|_| LocalProcessError::NodeStartup)?;
        let mut running = Self {
            child: Some(child),
            status: expected_status,
            status_observed_at: Instant::now(),
            observation_bootstrap_path: observation_bootstrap_path.map(Path::to_path_buf),
        };
        if let Err(error) = running.wait_until_ready(bootstrap, observation_socket_path) {
            let _ = running.shutdown_inner();
            return Err(error);
        }
        Ok(running)
    }

    fn status(&self) -> &NodeStatusV1 {
        &self.status
    }

    fn status_observed_at(&self) -> Instant {
        self.status_observed_at
    }

    fn wait_until_ready(
        &mut self,
        bootstrap: DeveloperLocalReferenceBootstrapV1,
        observation_socket_path: Option<&Path>,
    ) -> Result<(), LocalProcessError> {
        let deadline = Instant::now() + DEVELOPER_NODE_READY_TIMEOUT;
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .ok_or(LocalProcessError::NodeStartup)?
                .try_wait()
                .map_err(|_| LocalProcessError::NodeStartup)?
            {
                self.child.take();
                let _ = status;
                return Err(LocalProcessError::NodeStartup);
            }
            let management_ready =
                fs::symlink_metadata(bootstrap.socket_path()).is_ok_and(|metadata| {
                    metadata.file_type().is_socket()
                        && UnixStream::connect(bootstrap.socket_path()).is_ok()
                });
            let observation_ready = observation_socket_path.is_none_or(|path| {
                fs::symlink_metadata(path).is_ok_and(|metadata| {
                    metadata.file_type().is_socket() && UnixStream::connect(path).is_ok()
                })
            });
            if management_ready && observation_ready {
                break;
            }
            if Instant::now() >= deadline {
                return Err(LocalProcessError::NodeStartup);
            }
            thread::sleep(DEVELOPER_NODE_POLL_INTERVAL);
        }

        let endpoint = DeveloperLocalNodeManagementEndpointV1::try_from_bootstrap(
            &bootstrap,
            DEVELOPER_NODE_EXCHANGE_TIMEOUT,
        )
        .map_err(|_| LocalProcessError::NodeStartup)?;
        let target = NodeManagementTargetV1::try_new(
            bootstrap.identity().node_id(),
            bootstrap.management_endpoint_ref(),
            bootstrap.tenure().node_incarnation(),
            bootstrap.tenure().registration_epoch(),
        )
        .map_err(|_| LocalProcessError::NodeStartup)?;
        let mut request_id = [0_u8; 16];
        getrandom::fill(&mut request_id).map_err(|_| LocalProcessError::NodeStartup)?;
        if request_id.iter().all(|byte| *byte == 0) {
            return Err(LocalProcessError::NodeStartup);
        }
        let mut client = NodeManagementClientV1::new(endpoint, bootstrap.identity().node_id());
        let response = client
            .latest(request_id, target)
            .map_err(|_| LocalProcessError::NodeStartup)?;
        let status = response
            .status_value()
            .ok_or(LocalProcessError::NodeStartup)?;
        if status != &self.status {
            return Err(LocalProcessError::NodeStartup);
        }
        self.status = status.clone();
        self.status_observed_at = Instant::now();
        Ok(())
    }

    fn shutdown_and_join(mut self) -> Result<(), LocalProcessError> {
        let shutdown = self.shutdown_inner();
        let cleanup = self.cleanup_observation_bootstrap();
        shutdown.and(cleanup)
    }

    fn cleanup_observation_bootstrap(&mut self) -> Result<(), LocalProcessError> {
        let Some(path) = self.observation_bootstrap_path.take() else {
            return Ok(());
        };
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(LocalProcessError::JoinedShutdown),
        }
    }

    fn shutdown_inner(&mut self) -> Result<(), LocalProcessError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        if let Some(status) = child
            .try_wait()
            .map_err(|_| LocalProcessError::JoinedShutdown)?
        {
            self.child.take();
            return status
                .success()
                .then_some(())
                .ok_or(LocalProcessError::JoinedShutdown);
        }
        let pid = i32::try_from(child.id()).map_err(|_| LocalProcessError::JoinedShutdown)?;
        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
        let deadline = Instant::now() + DEVELOPER_NODE_SHUTDOWN_TIMEOUT;
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| LocalProcessError::JoinedShutdown)?
            {
                self.child.take();
                return status
                    .success()
                    .then_some(())
                    .ok_or(LocalProcessError::JoinedShutdown);
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(DEVELOPER_NODE_POLL_INTERVAL);
        }
        child
            .kill()
            .and_then(|()| child.wait())
            .map_err(|_| LocalProcessError::JoinedShutdown)?;
        self.child.take();
        Err(LocalProcessError::JoinedShutdown)
    }
}

impl Drop for RunningNodeDaemon {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
        let _ = self.cleanup_observation_bootstrap();
    }
}

struct RunningOwners {
    authority: Option<DeveloperLocalTenureAuthorityV1>,
    runtime_a: Option<RuntimeDeveloperLocalLifecycleV1>,
    runtime_b: Option<RuntimeDeveloperLocalLifecycleV1>,
    node_a: Option<RunningNodeDaemon>,
    node_b: Option<RunningNodeDaemon>,
}

impl RunningOwners {
    const fn new(authority: DeveloperLocalTenureAuthorityV1) -> Self {
        Self {
            authority: Some(authority),
            runtime_a: None,
            runtime_b: None,
            node_a: None,
            node_b: None,
        }
    }

    fn authority(&self) -> &DeveloperLocalTenureAuthorityV1 {
        self.authority
            .as_ref()
            .expect("Authority exists until joined shutdown")
    }

    fn runtime(&self) -> &RuntimeDeveloperLocalLifecycleV1 {
        self.runtime_a
            .as_ref()
            .expect("Runtime exists after successful startup")
    }

    fn node(&self) -> &RunningNodeDaemon {
        self.node_a
            .as_ref()
            .expect("NodeDaemon exists after successful startup")
    }

    fn shutdown(mut self) -> Result<(), LocalProcessError> {
        // Distributed composition starts Runtime A/B before Node A/B, so
        // joined teardown closes the later Node owners before their Runtime
        // authorities and always closes B before A.
        let node_b_result = self
            .node_b
            .take()
            .map_or(Ok(()), RunningNodeDaemon::shutdown_and_join);
        let node_a_result = self
            .node_a
            .take()
            .map_or(Ok(()), RunningNodeDaemon::shutdown_and_join);
        let runtime_b_result = self
            .runtime_b
            .take()
            .map_or(Ok(()), |runtime| runtime.shutdown_and_join())
            .map_err(|_| LocalProcessError::JoinedShutdown);
        let runtime_a_result = self
            .runtime_a
            .take()
            .map_or(Ok(()), |runtime| runtime.shutdown_and_join())
            .map_err(|_| LocalProcessError::JoinedShutdown);
        let authority_result = self
            .authority
            .take()
            .map_or(Ok(()), |authority| authority.shutdown())
            .map_err(|_| LocalProcessError::JoinedShutdown);
        node_b_result
            .and(node_a_result)
            .and(runtime_b_result)
            .and(runtime_a_result)
            .and(authority_result)
    }
}

impl Drop for RunningOwners {
    fn drop(&mut self) {
        if let Some(node) = self.node_b.take() {
            let _ = node.shutdown_and_join();
        }
        if let Some(node) = self.node_a.take() {
            let _ = node.shutdown_and_join();
        }
        if let Some(runtime) = self.runtime_b.take() {
            let _ = runtime.shutdown_and_join();
        }
        if let Some(runtime) = self.runtime_a.take() {
            let _ = runtime.shutdown_and_join();
        }
        if let Some(authority) = self.authority.take() {
            let _ = authority.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use paraegox_agent_contracts::{
        AgentConversationRequestId, AgentConversationRequestV1, AgentConversationTerminalResultV1,
        AgentConversationTurnId,
    };
    use paraegox_inspection::developer_local::{
        DeveloperLocalInspectionBootstrapV2, encode_authenticated_request_v2,
    };
    use paraegox_inspection::protocol::{
        InspectionClientV2, InspectionEndpointErrorV2, InspectionEndpointV2, InspectionRequestV2,
        InspectionResponseOutcomeV2, MAX_INSPECTION_RESPONSE_V2_BYTES,
    };
    use paraegox_inspection::{
        InspectionFreshnessV1, InspectionHealthV1, InspectionLivenessV1, InspectionReadinessV1,
        InspectionReasonV1, LocalInspectionOverallV1, LocalInspectionSnapshotV2,
    };
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::BoundedDuration;
    use paraegox_node::{
        RuntimeApplyEndpointDescriptorV1, RuntimeApplyEndpointRefV1, RuntimeHostLivenessV1,
        RuntimeHostStatusV1,
    };
    use paraegox_runtime::RuntimeAgentDeveloperLocalIpcClientV1;
    use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
        ManagedModelAdapterBindingV1, ManagedModelAdapterVersionV1, ManagedModelCapabilityIdV1,
    };
    use paraegox_runtime_contracts::managed_service::{
        ManagedServiceId, ManagedServiceLifecycleBudgetsV1, ManagedServiceSpecV1,
    };

    const TEST_LOOPBACK_ADAPTER_ID_V1: ModelAdapterIdV1 =
        match ModelAdapterIdV1::try_from_bytes(*b"px-test-loopback") {
            Ok(adapter_id) => adapter_id,
            Err(_) => panic!("test loopback adapter identity must be nonzero"),
        };
    const TEST_LOOPBACK_ADAPTER_VERSION_V1: ModelAdapterVersionV1 =
        match ModelAdapterVersionV1::try_new(1) {
            Ok(version) => version,
            Err(_) => panic!("test loopback adapter version must be nonzero"),
        };
    const TEST_LOOPBACK_ADAPTER_DESCRIPTOR_V1: ModelAdapterDescriptorV1 =
        ModelAdapterDescriptorV1::new(
            TEST_LOOPBACK_ADAPTER_ID_V1,
            TEST_LOOPBACK_ADAPTER_VERSION_V1,
            BOUNDED_TEXT_MODEL_CAPABILITY_ID_V1,
        );
    const IPC_PROBE_BOOTSTRAP_ENVIRONMENT: &str = "PARAEGOX_TEST_IPC_BOOTSTRAP";
    const INSPECTION_PROBE_BOOTSTRAP_ENVIRONMENT: &str = "PARAEGOX_TEST_INSPECTION_BOOTSTRAP";
    const IPC_PROBE_TEST_NAME: &str = "composition::tests::runtime_ipc_subprocess_probe";
    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn console_command_passes_private_bootstraps_and_removes_provider_secrets() {
        let runtime_bootstrap = Path::new("/private/tmp/paraegox/runtime.pxab");
        let inspection_bootstrap = Path::new("/private/tmp/paraegox/inspection.pxib");
        let command = build_console_command(runtime_bootstrap, Some(inspection_bootstrap));
        let expected_program = resolve_console_program();

        assert_eq!(command.get_program(), expected_program.as_os_str());
        assert_eq!(
            command.get_args().map(OsString::from).collect::<Vec<_>>(),
            vec![
                OsString::from(RUNTIME_BOOTSTRAP_FILE_OPTION),
                runtime_bootstrap.as_os_str().to_os_string(),
                OsString::from(INSPECTION_BOOTSTRAP_FILE_OPTION),
                inspection_bootstrap.as_os_str().to_os_string(),
            ]
        );
        for secret_name in ["OPENAI_API_KEY", "DEEPSEEK_API_KEY"] {
            assert!(
                command
                    .get_envs()
                    .any(|(name, value)| { name == OsStr::new(secret_name) && value.is_none() })
            );
        }
    }

    #[test]
    fn console_command_omits_inspection_argument_when_no_endpoint_exists() {
        let runtime_bootstrap = Path::new("/private/tmp/paraegox/runtime.pxab");
        let command = build_console_command(runtime_bootstrap, None);

        assert_eq!(
            command.get_args().map(OsString::from).collect::<Vec<_>>(),
            vec![
                OsString::from(RUNTIME_BOOTSTRAP_FILE_OPTION),
                runtime_bootstrap.as_os_str().to_os_string(),
            ]
        );
    }

    #[test]
    fn console_program_prefers_only_a_regular_executable_sibling() {
        let directory = fresh_state_root("console-sibling");
        fs::create_dir(&directory).expect("create launcher test directory");
        let _cleanup = TestCleanup {
            state_root: directory.clone(),
            socket_directory: None,
        };
        let executable = directory.join("paraegox");
        let sibling = directory.join(CONSOLE_COMMAND);
        fs::write(&sibling, b"#!/bin/sh\n").expect("write sibling launcher");
        fs::set_permissions(&sibling, fs::Permissions::from_mode(0o755))
            .expect("make sibling launcher executable");

        assert_eq!(console_program_for_executable(&executable), sibling);
    }

    #[test]
    fn console_program_falls_back_to_path_for_unsafe_siblings() {
        let directory = fresh_state_root("console-sibling-rejections");
        fs::create_dir(&directory).expect("create launcher test directory");
        let _cleanup = TestCleanup {
            state_root: directory.clone(),
            socket_directory: None,
        };
        let executable = directory.join("paraegox");
        let sibling = directory.join(CONSOLE_COMMAND);
        fs::write(&sibling, b"#!/bin/sh\n").expect("write sibling launcher");
        fs::set_permissions(&sibling, fs::Permissions::from_mode(0o644))
            .expect("keep sibling launcher non-executable");
        assert_eq!(
            console_program_for_executable(&executable),
            PathBuf::from(CONSOLE_COMMAND)
        );

        fs::remove_file(&sibling).expect("remove non-executable launcher");
        let target = directory.join("launcher-target");
        fs::write(&target, b"#!/bin/sh\n").expect("write executable launcher target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .expect("make launcher target executable");
        std::os::unix::fs::symlink(&target, &sibling).expect("symlink sibling launcher");
        assert_eq!(
            console_program_for_executable(&executable),
            PathBuf::from(CONSOLE_COMMAND)
        );
    }

    struct LoopbackModelFactory {
        descriptor: ModelAdapterDescriptorV1,
        backend_identity: ModelBackendIdentityV1,
        builds: Arc<AtomicUsize>,
    }

    impl ModelAdapterFactoryV1 for LoopbackModelFactory {
        fn metadata(&self) -> ModelAdapterMetadataV1 {
            ModelAdapterMetadataV1::new(self.descriptor, self.backend_identity)
        }

        fn build(&self) -> Result<Arc<dyn ModelBackendV1>, ModelAdapterBuildErrorV1> {
            self.builds.fetch_add(1, Ordering::AcqRel);
            Ok(Arc::new(LoopbackModelBackend {
                identity: self.backend_identity,
            }))
        }
    }

    struct LoopbackModelBackend {
        identity: ModelBackendIdentityV1,
    }

    impl ModelBackendV1 for LoopbackModelBackend {
        fn identity(&self) -> ModelBackendIdentityV1 {
            self.identity
        }

        fn invoke(
            &self,
            request: ModelInvocationRequestV1,
            cancellation: ModelCancellationViewV1,
        ) -> ModelBackendFuture {
            let output = format!("loopback: {}", request.prompt()).into_boxed_str();
            Box::pin(async move {
                if cancellation.is_cancellation_requested() {
                    ModelInvocationOutcomeV1::CancelledBeforeHandoff
                } else {
                    ModelInvocationOutcomeV1::Success(output)
                }
            })
        }
    }

    fn managed_model_plan(
        selection: ManagedAgentProviderSelectionV1,
        adapter_id: ModelAdapterIdV1,
        adapter_version: u32,
    ) -> ManagedModelServicePlanV1 {
        let budget = BoundedDuration::from_nanos(5_000_000_000);
        let lifecycle_budgets =
            ManagedServiceLifecycleBudgetsV1::try_new(budget, budget, budget, budget, budget)
                .expect("test lifecycle budgets must be valid");
        let service =
            ManagedServiceSpecV1::new(ManagedServiceId::from_bytes([65; 16]), lifecycle_budgets);
        let binding = ManagedModelAdapterBindingV1::try_new(
            *adapter_id.as_bytes(),
            ManagedModelAdapterVersionV1::try_new(adapter_version)
                .expect("test adapter version must be valid"),
            ManagedModelCapabilityIdV1::bounded_text_v1(),
        )
        .expect("test adapter binding must be valid");
        ManagedModelServicePlanV1::try_new(
            service,
            u16::try_from(DEVELOPER_MODEL_SERVICE_MAX_IN_FLIGHT)
                .expect("test Model capacity must fit the managed contract"),
            selection,
            binding,
        )
        .expect("test managed Model plan must be valid")
    }

    #[test]
    fn runtime_model_backend_resolver_requires_exact_plan_without_fallback() {
        let provider_ref =
            ManagedAgentProviderRefV1::try_from_bytes([71; 16]).expect("test provider reference");
        let selection = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            provider_ref,
            Digest32::from_bytes([72; 32]),
        )
        .expect("test provider selection");
        let backend_identity = model_backend_identity(selection).expect("test backend identity");
        let builds = Arc::new(AtomicUsize::new(0));
        let resolver = LocalModelResolver::try_new(
            selection,
            LoopbackModelFactory {
                descriptor: TEST_LOOPBACK_ADAPTER_DESCRIPTOR_V1,
                backend_identity,
                builds: Arc::clone(&builds),
            },
        )
        .expect("exact local registry resolver");
        let exact_plan = managed_model_plan(
            selection,
            TEST_LOOPBACK_ADAPTER_ID_V1,
            TEST_LOOPBACK_ADAPTER_VERSION_V1.value(),
        );

        let resolved =
            <LocalModelResolver as paraegox_runtime::RuntimeModelBackendResolverV1>::resolve(
                &resolver,
                &exact_plan,
            )
            .expect("exact managed Model plan must resolve");
        assert_eq!(resolved.plan(), &exact_plan);
        assert_eq!(builds.load(Ordering::Acquire), 1);

        let version_drift = managed_model_plan(selection, TEST_LOOPBACK_ADAPTER_ID_V1, 2);
        assert_eq!(
            <LocalModelResolver as paraegox_runtime::RuntimeModelBackendResolverV1>::resolve(
                &resolver,
                &version_drift,
            )
            .expect_err("adapter version drift must fail closed"),
            RuntimeModelBackendResolveError::ResolutionFailed
        );

        let other_provider_ref =
            ManagedAgentProviderRefV1::try_from_bytes([73; 16]).expect("other provider reference");
        let provider_drift = managed_model_plan(
            ManagedAgentProviderSelectionV1::try_deterministic_fixture(
                other_provider_ref,
                selection.config_digest(),
            )
            .expect("provider-drift selection"),
            TEST_LOOPBACK_ADAPTER_ID_V1,
            TEST_LOOPBACK_ADAPTER_VERSION_V1.value(),
        );
        assert_eq!(
            <LocalModelResolver as paraegox_runtime::RuntimeModelBackendResolverV1>::resolve(
                &resolver,
                &provider_drift,
            )
            .expect_err("provider drift must fail closed"),
            RuntimeModelBackendResolveError::ResolutionFailed
        );

        let other_capability = ModelCapabilityIdV1::try_from_bytes([74; 16])
            .expect("other capability identity must be valid");
        let capability_drift_resolver = LocalModelResolver::try_new(
            selection,
            LoopbackModelFactory {
                descriptor: ModelAdapterDescriptorV1::new(
                    TEST_LOOPBACK_ADAPTER_ID_V1,
                    TEST_LOOPBACK_ADAPTER_VERSION_V1,
                    other_capability,
                ),
                backend_identity,
                builds: Arc::clone(&builds),
            },
        )
        .expect("capability-drift registry resolver");
        assert_eq!(
            <LocalModelResolver as paraegox_runtime::RuntimeModelBackendResolverV1>::resolve(
                &capability_drift_resolver,
                &exact_plan,
            )
            .expect_err("adapter capability drift must fail closed"),
            RuntimeModelBackendResolveError::ResolutionFailed
        );
        assert_eq!(builds.load(Ordering::Acquire), 1);
    }

    #[test]
    fn local_model_resolver_rejects_provisioned_provider_config_or_secret_drift() {
        let provider_ref =
            ManagedAgentProviderRefV1::try_from_bytes([41; 16]).expect("test provider reference");
        let other_provider_ref =
            ManagedAgentProviderRefV1::try_from_bytes([42; 16]).expect("other provider reference");
        let secret_ref =
            ManagedAgentSecretRefV1::try_from_bytes([43; 16]).expect("test Secret reference");
        let other_secret_ref =
            ManagedAgentSecretRefV1::try_from_bytes([44; 16]).expect("other Secret reference");
        let config = paraegox_model_adapters::OpenAiResponsesProviderConfigV1::try_new(
            *provider_ref.as_bytes(),
            "gpt-test-model",
            DEVELOPER_PROVISIONED_PROVIDER_TIMEOUT_NANOS,
            DEVELOPER_PROVISIONED_MAX_OUTPUT_TOKENS,
            DEVELOPER_PROVISIONED_MAX_RESPONSE_BODY_BYTES,
            DEVELOPER_PROVISIONED_MAX_OUTPUT_TEXT_BYTES,
        )
        .expect("test provider config");
        let other_config = paraegox_model_adapters::OpenAiResponsesProviderConfigV1::try_new(
            *provider_ref.as_bytes(),
            "gpt-other-model",
            DEVELOPER_PROVISIONED_PROVIDER_TIMEOUT_NANOS,
            DEVELOPER_PROVISIONED_MAX_OUTPUT_TOKENS,
            DEVELOPER_PROVISIONED_MAX_RESPONSE_BODY_BYTES,
            DEVELOPER_PROVISIONED_MAX_OUTPUT_TEXT_BYTES,
        )
        .expect("other provider config");
        let selection = ManagedAgentProviderSelectionV1::try_provisioned(
            provider_ref,
            config.config_digest(),
            secret_ref,
        )
        .expect("expected selection");
        let resolver = LocalModelResolver::try_new(
            selection,
            OpenAiResponsesProviderFactoryV1::new(
                config,
                OpenAiResolvedApiKeyV1::try_new(b"test-api-key".to_vec()).expect("test API key"),
            ),
        )
        .expect("exact local OpenAI resolver");

        let mismatches = [
            ManagedAgentProviderSelectionV1::try_deterministic_fixture(
                provider_ref,
                selection.config_digest(),
            )
            .expect("profile mismatch"),
            ManagedAgentProviderSelectionV1::try_provisioned(
                other_provider_ref,
                selection.config_digest(),
                secret_ref,
            )
            .expect("provider mismatch"),
            ManagedAgentProviderSelectionV1::try_provisioned(
                provider_ref,
                other_config.config_digest(),
                secret_ref,
            )
            .expect("config mismatch"),
            ManagedAgentProviderSelectionV1::try_provisioned(
                provider_ref,
                selection.config_digest(),
                other_secret_ref,
            )
            .expect("Secret mismatch"),
        ];
        for mismatch in mismatches {
            assert_eq!(
                RuntimeAgentProviderResolverV1::resolve(&resolver, mismatch)
                    .expect_err("drift must fail closed"),
                RuntimeAgentProviderResolveError::ResolutionFailed
            );
        }
        assert!(RuntimeAgentProviderResolverV1::resolve(&resolver, selection).is_ok());
        assert!(RuntimeAgentProviderResolverV1::resolve(&resolver, selection).is_ok());
    }

    #[test]
    fn local_model_resolver_rejects_fixture_profile_provider_or_config_drift() {
        let provider_ref =
            ManagedAgentProviderRefV1::try_from_bytes([51; 16]).expect("test provider reference");
        let other_provider_ref =
            ManagedAgentProviderRefV1::try_from_bytes([52; 16]).expect("other provider reference");
        let selection = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            provider_ref,
            Digest32::from_bytes([54; 32]),
        )
        .expect("expected fixture selection");
        let backend_identity = model_backend_identity(selection).expect("fixture backend identity");
        let resolver = LocalModelResolver::try_new(
            selection,
            LocalDeterministicEchoAdapterFactoryV1 { backend_identity },
        )
        .expect("exact local fixture resolver");
        let profile_drift = ManagedAgentProviderSelectionV1::try_provisioned(
            provider_ref,
            selection.config_digest(),
            ManagedAgentSecretRefV1::try_from_bytes([53; 16]).expect("test Secret reference"),
        )
        .expect("profile drift");
        let provider_drift = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            other_provider_ref,
            selection.config_digest(),
        )
        .expect("provider drift");
        let config_drift = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            provider_ref,
            Digest32::from_bytes([55; 32]),
        )
        .expect("config drift");

        for mismatch in [profile_drift, provider_drift, config_drift] {
            assert_eq!(
                RuntimeAgentProviderResolverV1::resolve(&resolver, mismatch)
                    .expect_err("fixture drift must fail closed"),
                RuntimeAgentProviderResolveError::ResolutionFailed
            );
        }
        assert!(RuntimeAgentProviderResolverV1::resolve(&resolver, selection).is_ok());
        assert!(RuntimeAgentProviderResolverV1::resolve(&resolver, selection).is_ok());
    }

    #[test]
    fn local_model_resolver_rejects_unknown_adapter_descriptor_without_fallback() {
        let provider_ref =
            ManagedAgentProviderRefV1::try_from_bytes([61; 16]).expect("test provider reference");
        let selection = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            provider_ref,
            Digest32::from_bytes([62; 32]),
        )
        .expect("expected fixture selection");
        let backend_identity = model_backend_identity(selection).expect("test backend identity");
        let builds = Arc::new(AtomicUsize::new(0));
        let mut resolver = LocalModelResolver::try_new(
            selection,
            LoopbackModelFactory {
                descriptor: TEST_LOOPBACK_ADAPTER_DESCRIPTOR_V1,
                backend_identity,
                builds: Arc::clone(&builds),
            },
        )
        .expect("exact local registry resolver");
        let registered_selection = resolver.adapter_selection;
        assert_eq!(
            registered_selection.descriptor(),
            TEST_LOOPBACK_ADAPTER_DESCRIPTOR_V1
        );

        let other_adapter_id = ModelAdapterIdV1::try_from_bytes([63; 16])
            .expect("other adapter identity must be valid");
        let other_version =
            ModelAdapterVersionV1::try_new(2).expect("other adapter version must be valid");
        let other_capability = ModelCapabilityIdV1::try_from_bytes([64; 16])
            .expect("other capability identity must be valid");
        let unknown_descriptors = [
            ModelAdapterDescriptorV1::new(
                other_adapter_id,
                registered_selection.adapter_version(),
                registered_selection.capability_id(),
            ),
            ModelAdapterDescriptorV1::new(
                registered_selection.adapter_id(),
                other_version,
                registered_selection.capability_id(),
            ),
            ModelAdapterDescriptorV1::new(
                registered_selection.adapter_id(),
                registered_selection.adapter_version(),
                other_capability,
            ),
        ];
        for descriptor in unknown_descriptors {
            resolver.adapter_selection =
                ModelAdapterSelectionV1::new(descriptor, registered_selection.backend_identity());
            assert_eq!(
                RuntimeAgentProviderResolverV1::resolve(&resolver, selection)
                    .expect_err("unknown adapter descriptor must fail closed"),
                RuntimeAgentProviderResolveError::ResolutionFailed
            );
        }
        assert_eq!(builds.load(Ordering::Acquire), 0);
    }

    struct NonInteractiveConversationRunner {
        inputs: Vec<&'static str>,
        expected_prefix: &'static str,
        successful_turns: usize,
        retired_probe: Option<RuntimeAgentConversationHandle>,
        retired_config: Option<LocalConversationBounds>,
    }

    impl NonInteractiveConversationRunner {
        fn new(inputs: Vec<&'static str>) -> Self {
            Self {
                inputs,
                expected_prefix: "echo: ",
                successful_turns: 0,
                retired_probe: None,
                retired_config: None,
            }
        }

        fn provisioned(inputs: Vec<&'static str>) -> Self {
            Self {
                inputs,
                expected_prefix: "loopback: ",
                successful_turns: 0,
                retired_probe: None,
                retired_config: None,
            }
        }

        fn assert_old_handle_is_retired(&mut self) {
            let handle = self.retired_probe.take().expect("retirement probe");
            let config = self.retired_config.take().expect("retirement config");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("retirement probe runtime");
            let error = runtime
                .block_on(handle.open_session(
                    config.deck_run_id,
                    config.session_id,
                    config.operation_timeout,
                ))
                .expect_err("retired handle must fail closed");
            assert_eq!(
                error.to_string(),
                "Agent conversation generation is retired"
            );
        }
    }

    impl ConversationRunner for NonInteractiveConversationRunner {
        fn run(&mut self, launch: ConversationRunInput) -> Result<(), LocalProcessError> {
            self.retired_probe = Some(launch.handle.clone());
            self.retired_config = Some(launch.config);
            let mut handle = launch.handle;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| LocalProcessError::ConversationCapability)?;
            runtime.block_on(async {
                handle
                    .open_session(
                        launch.config.deck_run_id,
                        launch.config.session_id,
                        launch.config.operation_timeout,
                    )
                    .await
                    .map_err(|_| LocalProcessError::ConversationCapability)?;
                for input in &self.inputs {
                    let request = conversation_request(launch.config, input)?;
                    let terminal = handle
                        .submit(request.clone(), launch.config.operation_timeout)
                        .await
                        .map_err(|_| LocalProcessError::ConversationCapability)?;
                    let expected_output = format!("{}{input}", self.expected_prefix);
                    if !terminal.correlates(&request)
                        || !matches!(
                            terminal.result(),
                            AgentConversationTerminalResultV1::Success(output)
                                if output.as_ref() == expected_output.as_str()
                        )
                    {
                        return Err(LocalProcessError::ConversationCapability);
                    }
                    self.successful_turns += 1;
                }
                handle
                    .close()
                    .await
                    .map_err(|_| LocalProcessError::ConversationCapability)
            })
        }
    }

    fn conversation_request(
        config: LocalConversationBounds,
        input: &str,
    ) -> Result<AgentConversationRequestV1, LocalProcessError> {
        conversation_request_for_scope(
            config.deck_run_id,
            config.session_id,
            u64::try_from(config.request_deadline_budget.as_nanos())
                .map_err(|_| LocalProcessError::ConversationConfiguration)?,
            input,
        )
    }

    fn conversation_request_for_scope(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        deadline_budget_nanos: u64,
        input: &str,
    ) -> Result<AgentConversationRequestV1, LocalProcessError> {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::AcqRel);
        let mut turn_id = [0_u8; 16];
        turn_id[0] = 1;
        turn_id[8..].copy_from_slice(&sequence.to_be_bytes());
        let mut request_id = [0_u8; 16];
        request_id[0] = 2;
        request_id[8..].copy_from_slice(&sequence.to_be_bytes());
        AgentConversationRequestV1::try_new(
            deck_run_id,
            session_id,
            AgentConversationTurnId::try_from_bytes(turn_id)
                .map_err(|_| LocalProcessError::ConversationConfiguration)?,
            AgentConversationRequestId::try_from_bytes(request_id)
                .map_err(|_| LocalProcessError::ConversationConfiguration)?,
            deadline_budget_nanos,
            input,
        )
        .map_err(|_| LocalProcessError::ConversationConfiguration)
    }

    struct TestInspectionEndpointV2 {
        bootstrap: DeveloperLocalInspectionBootstrapV2,
    }

    impl InspectionEndpointV2 for TestInspectionEndpointV2 {
        fn exchange(
            &mut self,
            canonical_request: &[u8],
        ) -> Result<Box<[u8]>, InspectionEndpointErrorV2> {
            let request = InspectionRequestV2::decode(canonical_request)
                .map_err(|_| InspectionEndpointErrorV2::MalformedRequest)?;
            let wire = encode_authenticated_request_v2(self.bootstrap.generation_token(), &request)
                .map_err(|_| InspectionEndpointErrorV2::MalformedRequest)?;
            let mut stream = StdUnixStream::connect(self.bootstrap.socket_path())
                .map_err(|_| InspectionEndpointErrorV2::Unavailable)?;
            let operation_timeout = Some(self.bootstrap.operation_timeout());
            stream
                .set_read_timeout(operation_timeout)
                .map_err(|_| InspectionEndpointErrorV2::Unavailable)?;
            stream
                .set_write_timeout(operation_timeout)
                .map_err(|_| InspectionEndpointErrorV2::Unavailable)?;
            stream
                .write_all(&wire)
                .map_err(|_| InspectionEndpointErrorV2::Unavailable)?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|_| InspectionEndpointErrorV2::Unavailable)?;

            let mut response_length = [0_u8; 4];
            stream
                .read_exact(&mut response_length)
                .map_err(|_| InspectionEndpointErrorV2::Unavailable)?;
            let response_length = usize::try_from(u32::from_be_bytes(response_length))
                .map_err(|_| InspectionEndpointErrorV2::ResponseUnavailable)?;
            if !(1..=MAX_INSPECTION_RESPONSE_V2_BYTES).contains(&response_length) {
                return Err(InspectionEndpointErrorV2::ResponseUnavailable);
            }
            let mut response = vec![0_u8; response_length];
            stream
                .read_exact(&mut response)
                .map_err(|_| InspectionEndpointErrorV2::Unavailable)?;
            let mut trailing = [0_u8; 1];
            if stream
                .read(&mut trailing)
                .map_err(|_| InspectionEndpointErrorV2::Unavailable)?
                != 0
            {
                return Err(InspectionEndpointErrorV2::ResponseUnavailable);
            }
            Ok(response.into_boxed_slice())
        }
    }

    fn read_test_inspection_status_v2(
        bootstrap_path: &Path,
    ) -> Result<LocalInspectionSnapshotV2, &'static str> {
        let bootstrap = DeveloperLocalInspectionBootstrapV2::decode_owned(
            fs::read(bootstrap_path).map_err(|_| "Inspection bootstrap is unavailable")?,
        )
        .map_err(|_| "Inspection bootstrap is invalid")?;
        let request_id = bootstrap
            .request_id(1)
            .map_err(|_| "Inspection request identity is invalid")?;
        let projection_id = bootstrap.projection_id();
        let mut client = InspectionClientV2::new(TestInspectionEndpointV2 { bootstrap });
        let response = client
            .latest(request_id, projection_id)
            .map_err(|_| "Inspection exchange failed")?;
        if response.outcome() != InspectionResponseOutcomeV2::Snapshot {
            return Err("Inspection endpoint did not return a snapshot");
        }
        response
            .snapshot_value()
            .cloned()
            .ok_or("Inspection snapshot is absent")
    }

    #[derive(Default)]
    struct IpcSubprocessConversationRunner {
        completed: bool,
    }

    impl ConversationRunner for IpcSubprocessConversationRunner {
        fn run(&mut self, launch: ConversationRunInput) -> Result<(), LocalProcessError> {
            let inspection = launch
                .inspection
                .as_ref()
                .expect("single-target IPC test requires Inspection");
            let mut stale_sources = inspection.sources.clone();
            stale_sources.node_status_observed_at = Instant::now()
                .checked_sub(Duration::from_secs(11))
                .expect("test observation clock supports an eleven-second history");
            let stale_inspection_socket = inspection.ipc_socket_path.with_file_name("stale-i.sock");
            let stale_inspection_bootstrap =
                inspection.ipc_bootstrap_path.with_file_name("stale-i.pxib");
            let stale_endpoint = start_developer_local_inspection_v2(
                stale_sources,
                stale_inspection_socket,
                stale_inspection_bootstrap.clone(),
                launch.expected_uid,
                launch.expected_gid,
            )
            .expect("stale-source Inspection endpoint");
            let stale_snapshot = read_test_inspection_status_v2(&stale_inspection_bootstrap)
                .expect("stale-source Inspection snapshot");
            assert_eq!(stale_snapshot.projection_revision(), 1);
            assert_eq!(
                stale_snapshot.node().freshness(),
                InspectionFreshnessV1::Stale
            );
            assert!(
                stale_snapshot
                    .base_snapshot()
                    .records()
                    .iter()
                    .all(|record| record.freshness() == InspectionFreshnessV1::Stale)
            );
            std::thread::sleep(Duration::from_millis(250));
            let stable_stale_snapshot = read_test_inspection_status_v2(&stale_inspection_bootstrap)
                .expect("already-stale Inspection snapshot remains readable");
            assert_eq!(stable_stale_snapshot.projection_revision(), 1);
            assert_eq!(
                stable_stale_snapshot.node().freshness(),
                InspectionFreshnessV1::Stale
            );
            stale_endpoint
                .shutdown_and_join()
                .expect("stale-source Inspection joined shutdown");

            let delayed_inspection_socket =
                inspection.ipc_socket_path.with_file_name("delayed-i.sock");
            let delayed_inspection_bootstrap = inspection
                .ipc_bootstrap_path
                .with_file_name("delayed-i.pxib");
            let owner_gate = Arc::new(std::sync::Barrier::new(2));
            let worker_gate = Arc::clone(&owner_gate);
            let releaser = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(750));
                owner_gate.wait();
            });
            let startup_started = Instant::now();
            let delayed_endpoint =
                crate::inspection::start_developer_local_inspection_with_owner_preamble_for_test_v2(
                    inspection.sources.clone(),
                    delayed_inspection_socket.clone(),
                    delayed_inspection_bootstrap.clone(),
                    launch.expected_uid,
                    launch.expected_gid,
                    move || {
                        worker_gate.wait();
                    },
                )
                .expect("prepared Inspection endpoint does not wait for owner scheduling");
            let startup_elapsed = startup_started.elapsed();
            releaser.join().expect("release delayed Inspection owner");
            assert!(
                startup_elapsed < Duration::from_millis(500),
                "prepared Inspection startup waited for owner-thread progress: {startup_elapsed:?}"
            );
            delayed_endpoint
                .shutdown_and_join()
                .expect("delayed Inspection owner joined shutdown");
            assert!(!delayed_inspection_socket.exists());
            assert!(!delayed_inspection_bootstrap.exists());

            let conversation_endpoint = start_conversation_ipc(&launch)?;
            let inspection_endpoint = start_inspection_ipc(&launch, inspection)?;
            if !launch.ipc_socket_path.exists()
                || !launch.ipc_bootstrap_path.exists()
                || !inspection.ipc_socket_path.exists()
                || !inspection.ipc_bootstrap_path.exists()
            {
                return Err(LocalProcessError::ConversationIpc);
            }
            let executable =
                env::current_exe().map_err(|_| LocalProcessError::ConversationChild)?;
            let mut command = Command::new(executable);
            command
                .arg("--exact")
                .arg(IPC_PROBE_TEST_NAME)
                .arg("--nocapture")
                .env(IPC_PROBE_BOOTSTRAP_ENVIRONMENT, &launch.ipc_bootstrap_path)
                .env(
                    INSPECTION_PROBE_BOOTSTRAP_ENVIRONMENT,
                    &inspection.ipc_bootstrap_path,
                )
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let child_result = JoinedChild::spawn(&mut command)?.wait().and_then(|status| {
                status
                    .success()
                    .then_some(())
                    .ok_or(LocalProcessError::ConversationChild)
            });
            let inspection_result = inspection_endpoint
                .shutdown_and_join()
                .map_err(|_| LocalProcessError::InspectionIpc);
            let conversation_result = conversation_endpoint
                .shutdown_and_join()
                .map_err(|_| LocalProcessError::ConversationIpc);
            let result = child_result.and(inspection_result).and(conversation_result);
            if result.is_ok()
                && !launch.ipc_socket_path.exists()
                && !launch.ipc_bootstrap_path.exists()
                && !inspection.ipc_socket_path.exists()
                && !inspection.ipc_bootstrap_path.exists()
            {
                self.completed = true;
            }
            result
        }
    }

    #[test]
    fn node_daemon_subprocess_probe() {
        let Some(bootstrap_path) = env::var_os(NODE_DAEMON_PROBE_BOOTSTRAP_ENVIRONMENT) else {
            return;
        };
        match env::var_os(NODE_DAEMON_PROBE_OBSERVATION_BOOTSTRAP_ENVIRONMENT) {
            Some(observation_bootstrap_path) => {
                paraegox_node::process::serve_developer_local_runtime_observation_node_daemon_v1(
                    std::path::Path::new(&bootstrap_path),
                    std::path::Path::new(&observation_bootstrap_path),
                )
            }
            None => paraegox_node::process::serve_developer_local_reference_node_daemon_v1(
                std::path::Path::new(&bootstrap_path),
            ),
        }
        .expect("real NodeDaemon process");
    }

    #[test]
    fn runtime_ipc_subprocess_probe() {
        let Some(bootstrap_path) = env::var_os(IPC_PROBE_BOOTSTRAP_ENVIRONMENT) else {
            return;
        };
        let inspection_bootstrap_path = env::var_os(INSPECTION_PROBE_BOOTSTRAP_ENVIRONMENT)
            .expect("Inspection probe bootstrap environment");
        let inspection =
            read_test_inspection_status_v2(std::path::Path::new(&inspection_bootstrap_path))
                .expect("typed read-only Inspection exchange");
        assert_eq!(inspection.overall(), LocalInspectionOverallV1::Unknown);
        assert_eq!(inspection.projection_revision(), 1);
        let node = inspection.node();
        assert_eq!(node.freshness(), InspectionFreshnessV1::Fresh);
        assert_eq!(node.liveness(), InspectionLivenessV1::Live);
        assert_eq!(node.readiness(), InspectionReadinessV1::Unknown);
        assert_eq!(node.health(), InspectionHealthV1::Unknown);
        assert_eq!(node.reason(), InspectionReasonV1::SourceUnknown);
        assert_eq!(
            node.registration_epoch(),
            Some(DEVELOPER_NODE_REGISTRATION_EPOCH)
        );
        assert_eq!(node.status_sequence(), Some(1));
        let records = inspection.base_snapshot().records();
        assert!(
            records
                .iter()
                .all(|record| record.freshness() == InspectionFreshnessV1::Fresh)
        );
        assert_eq!(records[0].liveness(), InspectionLivenessV1::Unknown);
        assert_eq!(records[0].readiness(), InspectionReadinessV1::Unknown);
        assert_eq!(records[1].liveness(), InspectionLivenessV1::Unknown);
        assert_eq!(records[1].readiness(), InspectionReadinessV1::Unknown);
        for record in [records[2], records[3], records[4]] {
            assert_eq!(record.liveness(), InspectionLivenessV1::Unknown);
            assert_eq!(record.readiness(), InspectionReadinessV1::Ready);
        }
        assert!(
            records
                .iter()
                .all(|record| record.health() == InspectionHealthV1::Unknown)
        );
        let client = RuntimeAgentDeveloperLocalIpcClientV1::from_private_bootstrap_file(
            std::path::Path::new(&bootstrap_path),
        )
        .expect("private Runtime IPC bootstrap");
        let request = conversation_request_for_scope(
            client.deck_run_id(),
            client.session_id(),
            client.request_deadline_budget_nanos(),
            "process IPC turn",
        )
        .expect("typed IPC request");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("probe runtime");
        runtime.block_on(async {
            client
                .open_session(
                    client.deck_run_id(),
                    client.session_id(),
                    client.operation_timeout(),
                )
                .await
                .expect("typed IPC open");
            let terminal = client
                .submit(request.clone(), client.operation_timeout())
                .await
                .expect("typed IPC submit");
            assert!(terminal.correlates(&request));
            assert!(matches!(
                terminal.result(),
                AgentConversationTerminalResultV1::Success(output)
                    if output.as_ref() == "echo: process IPC turn"
            ));
            let _ = client
                .get(
                    client.deck_run_id(),
                    client.session_id(),
                    request.request_id(),
                    client.operation_timeout(),
                )
                .await
                .expect("typed IPC get");
            let _ = client
                .watch(
                    client.deck_run_id(),
                    client.session_id(),
                    0,
                    16,
                    client.operation_timeout(),
                )
                .await
                .expect("typed IPC watch");
            let _ = client
                .cancel(
                    client.deck_run_id(),
                    client.session_id(),
                    request.request_id(),
                    client.operation_timeout(),
                )
                .await
                .expect("typed IPC cancel");
        });
        client.close();
    }

    struct TestCleanup {
        state_root: PathBuf,
        socket_directory: Option<PathBuf>,
    }

    impl Drop for TestCleanup {
        fn drop(&mut self) {
            assert!(self.state_root.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("paraegox-local-composition-test-")
            }));
            let _ = fs::remove_dir_all(&self.state_root);
            if let Some(socket_directory) = &self.socket_directory {
                assert!(
                    socket_directory
                        .file_name()
                        .is_some_and(|name| { name.to_string_lossy().starts_with("pxl-") })
                );
                let _ = fs::remove_dir_all(socket_directory);
            }
        }
    }

    fn fresh_state_root(label: &str) -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        fs::canonicalize(std::env::temp_dir())
            .expect("canonical temporary root")
            .join(format!(
                "paraegox-local-composition-test-{}-{sequence}-{label}",
                std::process::id()
            ))
    }

    fn ephemeral_fabric_listen() -> (u16, String) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral loopback port");
        let port = listener.local_addr().expect("listener address").port();
        drop(listener);
        (port, format!("tcp/127.0.0.1:{port}"))
    }

    fn fixture_config(
        state_root: &std::path::Path,
        fabric_listen: &str,
    ) -> DeveloperFixtureConfigV1 {
        let document = format!(
            "schema_version = 1\nstate_root = \"{}\"\nfabric_listen = \"{fabric_listen}\"\n\n[model]\nprovider = \"deterministic-echo-v1\"\n",
            state_root.display()
        );
        match crate::config::parse_chat_config_toml_for_test(&document)
            .expect("fixture composition config")
        {
            crate::config::Command::DeveloperFixtureV1(config) => config,
            crate::config::Command::DeveloperDistributedFixtureV1(_)
            | crate::config::Command::DeveloperProvisionedV1(_)
            | crate::config::Command::Help => panic!("unexpected command"),
        }
    }

    fn provisioned_config(
        state_root: &std::path::Path,
        fabric_listen: &str,
        provider: &str,
        model: &str,
        secret_ref: &str,
    ) -> DeveloperProvisionedConfigV1 {
        let document = format!(
            "schema_version = 1\nstate_root = \"{}\"\nfabric_listen = \"{fabric_listen}\"\n\n[model]\nprovider = \"{provider}\"\nmodel = \"{model}\"\nsecret_ref = \"{secret_ref}\"\n",
            state_root.display()
        );
        match crate::config::parse_chat_config_toml_for_test(&document)
            .expect("provisioned composition config")
        {
            crate::config::Command::DeveloperProvisionedV1(config) => config,
            crate::config::Command::DeveloperFixtureV1(_)
            | crate::config::Command::DeveloperDistributedFixtureV1(_)
            | crate::config::Command::Help => panic!("unexpected command"),
        }
    }

    #[test]
    fn reference_node_reopen_rejects_a_persisted_runtime_host_observation() {
        let state_root = fresh_state_root("node-runtime-host-reopen");
        let (_, fabric_listen) = ephemeral_fabric_listen();
        let config = fixture_config(&state_root, &fabric_listen);
        let mut cleanup = TestCleanup {
            state_root,
            socket_directory: None,
        };
        let manifest = identity::load_or_create(&config).expect("identity manifest");
        let prepared_layout = layout::prepare(&config, &manifest).expect("prepared layout");
        cleanup.socket_directory = Some(prepared_layout.socket_directory().to_path_buf());
        let identities = derive_identities(&manifest).expect("derived identities");
        let bootstrap = new_developer_local_node_bootstrap(&prepared_layout, identities)
            .expect("reference Node bootstrap");
        bootstrap
            .write_owner_private_file(prepared_layout.pxnb_bootstrap_path())
            .expect("persist reference Node bootstrap");

        let runtime_host_id = RuntimeHostId::from_bytes([0x91; 16]);
        let endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
            RuntimeApplyEndpointRefV1::try_from_bytes([0x92; 16])
                .expect("Runtime endpoint reference"),
            runtime_host_id,
            1,
            "paraegox/v1/nodes/91/runtime/91/apply",
            [0x93; 16],
            [0x94; 32],
        )
        .expect("Runtime endpoint descriptor");
        let runtime_status =
            RuntimeHostStatusV1::try_new(1, 1, RuntimeHostLivenessV1::Live, endpoint)
                .expect("RuntimeHost status");
        let mut owner = DurableNodeDaemonV1::open(
            bootstrap.state_root(),
            bootstrap.identity(),
            bootstrap.tenure(),
            bootstrap.management_endpoint_ref(),
            bootstrap.initial_feature_report(),
        )
        .expect("reference Node store");
        owner
            .observe_runtime_host(runtime_status)
            .expect("persist RuntimeHost observation");
        let persisted = owner
            .publish_status(MAX_NODE_STATUS_FRESHNESS_NANOS)
            .expect("persist RuntimeHost status");
        assert_eq!(persisted.status_sequence(), 1);
        assert_eq!(persisted.runtime_hosts().len(), 1);
        drop(owner);
        drop(bootstrap);

        assert!(matches!(
            prepare_developer_local_node_v1(&prepared_layout, identities),
            Err(LocalProcessError::NodeBootstrap)
        ));
        let bootstrap = DeveloperLocalReferenceBootstrapV1::read_owner_private_file(
            prepared_layout.pxnb_bootstrap_path(),
        )
        .expect("reopen reference Node bootstrap after rejection");
        let owner = DurableNodeDaemonV1::open(
            bootstrap.state_root(),
            bootstrap.identity(),
            bootstrap.tenure(),
            bootstrap.management_endpoint_ref(),
            bootstrap.initial_feature_report(),
        )
        .expect("reopen rejected reference Node store");
        let persisted = owner
            .current_status()
            .expect("persisted RuntimeHost status");
        assert_eq!(persisted.status_sequence(), 1);
        assert_eq!(persisted.runtime_hosts().len(), 1);
    }

    fn loopback_composition_provider(
        config: &DeveloperProvisionedConfigV1,
        manifest: &identity::IdentityManifestV1,
        builds: Arc<AtomicUsize>,
    ) -> CompositionProvider {
        let provider_ref = ManagedAgentProviderRefV1::try_from_bytes(*manifest.provider_ref())
            .expect("manifest provider reference");
        let provider_config = config
            .provider_config(provider_ref)
            .expect("fixed provider configuration");
        assert_eq!(
            provider_config.config_digest().as_bytes(),
            manifest.provider_configuration_digest()
        );
        let selection = ManagedAgentProviderSelectionV1::try_provisioned(
            provider_ref,
            provider_config.config_digest(),
            provisioned_secret_ref(config.secret_ref(), manifest)
                .expect("derived Secret reference"),
        )
        .expect("Provisioned selection");
        let backend_identity =
            model_backend_identity(selection).expect("loopback backend identity");
        let resolver = Arc::new(
            LocalModelResolver::try_new(
                selection,
                LoopbackModelFactory {
                    descriptor: TEST_LOOPBACK_ADAPTER_DESCRIPTOR_V1,
                    backend_identity,
                    builds,
                },
            )
            .expect("loopback registry resolver"),
        );
        CompositionProvider {
            deployment: DeploymentProvider::Provisioned(selection),
            adapter_descriptor: TEST_LOOPBACK_ADAPTER_DESCRIPTOR_V1,
            agent_resolver: resolver.clone(),
            model_backend_resolver: resolver,
        }
    }

    #[test]
    fn missing_or_invalid_openai_secret_fails_before_state_root_creation() {
        let state_root = fresh_state_root("secret-first");
        let (_, fabric_listen) = ephemeral_fabric_listen();
        let config = provisioned_config(
            &state_root,
            &fabric_listen,
            "openai-responses-v1",
            "gpt-test-model",
            "env:OPENAI_API_KEY",
        );
        let _cleanup = TestCleanup {
            state_root: state_root.clone(),
            socket_directory: None,
        };
        let peer = current_developer_local_peer().expect("non-root test peer");

        let mut missing_runner = NonInteractiveConversationRunner::provisioned(Vec::new());
        assert_eq!(
            run_provisioned_with_environment_value(config.clone(), None, peer, &mut missing_runner),
            Err(LocalProcessError::ProviderSecret)
        );
        assert!(!state_root.exists());

        let mut invalid_runner = NonInteractiveConversationRunner::provisioned(Vec::new());
        assert_eq!(
            run_provisioned_with_environment_value(
                config,
                Some(OsString::from("invalid key with spaces")),
                peer,
                &mut invalid_runner,
            ),
            Err(LocalProcessError::ProviderSecret)
        );
        assert!(!state_root.exists());
    }

    #[test]
    fn deepseek_provider_selection_comes_from_config_without_a_cli_selector() {
        let state_root = fresh_state_root("deepseek-provider");
        let (_, fabric_listen) = ephemeral_fabric_listen();
        let config = provisioned_config(
            &state_root,
            &fabric_listen,
            "deepseek-chat-completions-v1",
            "deepseek-v4-flash",
            "env:DEEPSEEK_API_KEY",
        );
        let _cleanup = TestCleanup {
            state_root,
            socket_directory: None,
        };
        assert_eq!(
            config.provider_profile(),
            ProviderProfileV1::DeepSeekChatCompletionsV1
        );
        assert_eq!(config.model(), "deepseek-v4-flash");

        let manifest =
            identity::load_or_create_provisioned(&config).expect("DeepSeek identity manifest");
        let api_key = resolve_provisioned_api_key(
            config.provider_profile(),
            Some(OsString::from("test-deepseek-key")),
        )
        .expect("test DeepSeek Secret resolution");
        let provider = prepare_provisioned_provider(&config, &manifest, api_key)
            .expect("DeepSeek provisioned provider");

        assert_eq!(
            provider.adapter_descriptor,
            DEEPSEEK_CHAT_COMPLETIONS_ADAPTER_DESCRIPTOR_V1
        );
        assert!(matches!(
            provider.deployment,
            DeploymentProvider::Provisioned(_)
        ));
    }

    #[test]
    fn provisioned_loopback_composition_rebuilds_provider_on_restart() {
        let state_root = fresh_state_root("openai-loopback");
        let (port, fabric_listen) = ephemeral_fabric_listen();
        let config = provisioned_config(
            &state_root,
            &fabric_listen,
            "openai-responses-v1",
            "gpt-test-model",
            "env:OPENAI_API_KEY",
        );
        let mut cleanup = TestCleanup {
            state_root,
            socket_directory: None,
        };
        let manifest =
            identity::load_or_create_provisioned(&config).expect("OpenAI identity manifest");
        let prepared_layout =
            layout::prepare_provisioned(&config, &manifest).expect("OpenAI prepared layout");
        cleanup.socket_directory = Some(prepared_layout.socket_directory().to_path_buf());
        let authority_socket = prepared_layout.authority_socket_path().to_path_buf();
        let runtime_socket = prepared_layout.runtime_socket_path().to_path_buf();
        drop(prepared_layout);
        drop(manifest);

        let builds = Arc::new(AtomicUsize::new(0));
        let peer = current_developer_local_peer().expect("non-root test peer");
        for (launch, inputs) in [
            vec!["first provisioned turn"],
            vec!["restart provisioned turn"],
        ]
        .into_iter()
        .enumerate()
        {
            let manifest = identity::load_or_create_provisioned(&config)
                .expect("stable OpenAI identity manifest");
            let prepared_layout =
                layout::prepare_provisioned(&config, &manifest).expect("stable OpenAI layout");
            let provider = loopback_composition_provider(&config, &manifest, Arc::clone(&builds));
            let mut runner = NonInteractiveConversationRunner::provisioned(inputs);
            run_prepared(
                CompositionConfigRef::Provisioned(&config),
                manifest,
                prepared_layout,
                provider,
                peer,
                &mut runner,
            )
            .expect("provisioned loopback composition run");
            assert_eq!(runner.successful_turns, 1);
            assert_eq!(builds.load(Ordering::Acquire), launch + 1);
            runner.assert_old_handle_is_retired();
            assert!(!authority_socket.exists());
            assert!(!runtime_socket.exists());
            let rebound = TcpListener::bind(("127.0.0.1", port))
                .expect("Fabric port must be released after joined shutdown");
            drop(rebound);
        }
    }

    #[test]
    fn real_runtime_ipc_serves_a_separate_noninteractive_process_and_joins() {
        let state_root = fresh_state_root("ipc-process");
        let (port, fabric_listen) = ephemeral_fabric_listen();
        let config = fixture_config(&state_root, &fabric_listen);
        let mut cleanup = TestCleanup {
            state_root,
            socket_directory: None,
        };
        let manifest = identity::load_or_create(&config).expect("identity manifest");
        let prepared_layout = layout::prepare(&config, &manifest).expect("prepared layout");
        cleanup.socket_directory = Some(prepared_layout.socket_directory().to_path_buf());
        let authority_socket = prepared_layout.authority_socket_path().to_path_buf();
        let runtime_socket = prepared_layout.runtime_socket_path().to_path_buf();
        let ipc_socket = prepared_layout.agent_ipc_socket_path().to_path_buf();
        let ipc_bootstrap = prepared_layout.agent_ipc_bootstrap_path().to_path_buf();
        let inspection_socket = prepared_layout.inspection_ipc_socket_path().to_path_buf();
        let inspection_bootstrap = prepared_layout
            .inspection_ipc_bootstrap_path()
            .to_path_buf();
        drop(prepared_layout);
        drop(manifest);

        let mut runner = IpcSubprocessConversationRunner::default();
        let peer = current_developer_local_peer().expect("non-root test peer");
        run_with_runner(config, peer, &mut runner).expect("real separate-process IPC conversation");
        assert!(runner.completed);
        assert!(!authority_socket.exists());
        assert!(!runtime_socket.exists());
        assert!(!ipc_socket.exists());
        assert!(!ipc_bootstrap.exists());
        assert!(!inspection_socket.exists());
        assert!(!inspection_bootstrap.exists());
        let rebound = TcpListener::bind(("127.0.0.1", port))
            .expect("Fabric port must be released after joined shutdown");
        drop(rebound);
    }

    #[test]
    fn same_state_root_runs_two_real_typed_conversations_and_releases_resources() {
        let state_root = fresh_state_root("fixture");
        assert!(!state_root.exists());
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral loopback port");
        let port = listener.local_addr().expect("listener address").port();
        drop(listener);
        let config = fixture_config(&state_root, &format!("tcp/127.0.0.1:{port}"));
        let mut cleanup = TestCleanup {
            state_root,
            socket_directory: None,
        };
        let manifest = identity::load_or_create(&config).expect("identity manifest");
        let prepared_layout = layout::prepare(&config, &manifest).expect("prepared layout");
        cleanup.socket_directory = Some(prepared_layout.socket_directory().to_path_buf());
        let authority_socket = prepared_layout.authority_socket_path().to_path_buf();
        let runtime_socket = prepared_layout.runtime_socket_path().to_path_buf();
        drop(manifest);

        let launch_inputs = [
            vec!["first local turn", "second local turn"],
            vec!["restart local turn"],
        ];
        let mut successful_turns = 0;
        let peer = current_developer_local_peer().expect("non-root test peer");
        for inputs in launch_inputs {
            let expected_turns = inputs.len();
            let mut runner = NonInteractiveConversationRunner::new(inputs);
            run_with_runner(config.clone(), peer, &mut runner).expect("real local composition run");
            assert_eq!(runner.successful_turns, expected_turns);
            successful_turns += runner.successful_turns;
            runner.assert_old_handle_is_retired();
            assert!(!authority_socket.exists());
            assert!(!runtime_socket.exists());
            let rebound = TcpListener::bind(("127.0.0.1", port))
                .expect("Fabric port must be released after joined shutdown");
            drop(rebound);
        }
        assert_eq!(successful_turns, 3);
    }
}
