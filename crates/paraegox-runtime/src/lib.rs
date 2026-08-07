//! Runtime-owned request admission, bounded execution, and the narrow RuntimeHost process root.

#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod admission;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod apply_state;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod card_executor;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod card_instance;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod component_runtime;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod core_service;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod dispatcher;
#[cfg(unix)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Consumed by the PXAR-v8 control endpoint")
)] // GOV-WAIVER-0001
mod distributed_agent_stack_runtime;
#[cfg(unix)]
mod distributed_agent_stack_state;
#[cfg(unix)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Awaiting the PXAR-v8 durable Runtime owner")
)] // GOV-WAIVER-0001
mod distributed_fabric_runtime;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Awaiting admitted internal consumer")
)] // GOV-WAIVER-0001
mod executor_budget;
pub mod host_watchdog;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod liveness;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod loop_domain;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod mailbox;
#[cfg(unix)]
#[expect(dead_code, reason = "Awaiting admitted managed Agent stack consumer")] // GOV-WAIVER-0001
mod managed_agent_runtime;
#[cfg(unix)]
#[expect(dead_code, reason = "Consumed by the PXAR-v7 Runtime owner")] // GOV-WAIVER-0001
mod managed_agent_stack_runtime;
#[cfg(unix)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Consumed by the PXAR-v7 Runtime owner")
)] // GOV-WAIVER-0001
mod managed_agent_stack_state;
#[cfg(unix)]
mod managed_agent_transport;
#[cfg(unix)]
#[expect(dead_code, reason = "Awaiting PXAR-v6 endpoint dispatch consumer")] // GOV-WAIVER-0001
mod managed_fabric_runtime;
#[cfg(unix)]
#[expect(dead_code, reason = "Consumed with the PXAR-v6 Runtime owner")] // GOV-WAIVER-0001
mod managed_fabric_state;
#[cfg(unix)]
#[expect(dead_code, reason = "Consumed by the PXAR-v9 Runtime endpoint")] // GOV-WAIVER-0001
mod managed_model_agent_stack_runtime;
#[cfg(unix)]
mod managed_model_agent_stack_state;
#[cfg(unix)]
#[expect(dead_code, reason = "Consumed by the PXAR-v9 stack owner")] // GOV-WAIVER-0001
mod managed_model_runtime;
#[expect(dead_code, reason = "Awaiting plan-driven ProcessDomain consumer")] // GOV-WAIVER-0001
mod managed_service_assembly;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod port_binding;
#[cfg(unix)]
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod process_domain;
#[cfg(unix)]
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod process_platform;
#[cfg(unix)]
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod process_transport;
#[cfg(unix)]
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod process_workspace;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod recovery;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod request;
#[cfg(unix)]
mod runtime_agent_developer_local_ipc;
#[cfg(unix)]
mod runtime_agent_provider;
#[cfg(unix)]
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(
        dead_code,
        reason = "Installed-production observation awaits the admitted non-Linux backend"
    )
)] // GOV-WAIVER-0001
mod runtime_artifact;
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(
        dead_code,
        reason = "Production executable metadata remains Linux-only"
    )
)] // GOV-WAIVER-0001
mod runtime_build_metadata;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod runtime_clock;
#[cfg(unix)]
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(dead_code, reason = "Legacy production endpoint remains Linux-only")
)] // GOV-WAIVER-0001
mod runtime_control_endpoint;
#[expect(dead_code, reason = "Awaiting Runtime endpoint consumer")] // GOV-WAIVER-0001
mod runtime_control_state;
#[cfg(unix)]
mod runtime_developer_local;
mod runtime_host;
mod runtime_host_entrypoint;
#[cfg(unix)]
#[expect(dead_code, reason = "Receipt fields await startup/bootstrap consumers")] // GOV-WAIVER-0001
mod runtime_initializer;
#[cfg(unix)]
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(
        dead_code,
        reason = "Runtime installation is Linux-only until the platform capability admission"
    )
)] // GOV-WAIVER-0001
mod runtime_install_files;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod runtime_journal;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod runtime_ownership;
#[cfg(unix)]
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(
        dead_code,
        reason = "Protected-file production provisioning remains Linux-only"
    )
)] // GOV-WAIVER-0001
mod runtime_provisioning;
#[cfg(unix)]
#[expect(dead_code, reason = "Startup/apply store consumers pending")] // GOV-WAIVER-0001
mod runtime_store;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod task_registry;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod thread_component_runtime;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod thread_domain;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod thread_registry;

#[cfg(unix)]
pub use distributed_fabric_runtime::{
    RuntimeFabricCredentialRequirementV1, RuntimeFabricCredentialResolveError,
    RuntimeFabricCredentialResolveErrorV2, RuntimeFabricCredentialResolverV1,
    RuntimeFabricCredentialResolverV2, RuntimeResolvedFabricCredentialFilesV1,
    RuntimeResolvedFabricPeerCredentialV2,
};
#[cfg(unix)]
pub use managed_agent_runtime::{RuntimeAgentConversationError, RuntimeAgentConversationHandle};
#[cfg(unix)]
pub use managed_model_runtime::{
    RuntimeModelBackendResolveError, RuntimeModelBackendResolverV1, RuntimeResolvedModelBackendV1,
};
#[cfg(unix)]
pub use runtime_agent_developer_local_ipc::{
    RuntimeAgentDeveloperLocalBootstrapV1, RuntimeAgentDeveloperLocalConversationV1,
    RuntimeAgentDeveloperLocalIpcClientV1, RuntimeAgentDeveloperLocalIpcConfigV1,
    RuntimeAgentDeveloperLocalIpcError, RuntimeAgentDeveloperLocalIpcLifecycleV1,
    RuntimeAgentDeveloperLocalIpcLimitsV1, RuntimeAgentDeveloperLocalIpcPathsV1,
    start_runtime_agent_developer_local_ipc_v1,
};
#[cfg(unix)]
pub use runtime_agent_provider::{
    RuntimeAgentProviderResolveError, RuntimeAgentProviderResolverV1,
    RuntimeResolvedAgentProviderV1,
};
#[cfg(unix)]
pub use runtime_developer_local::{
    RuntimeDeveloperLocalConfigV1, RuntimeDeveloperLocalDistributedAgentStackConfigV1,
    RuntimeDeveloperLocalError, RuntimeDeveloperLocalIdentityRefsV1,
    RuntimeDeveloperLocalIdentityV1, RuntimeDeveloperLocalLifecycleV1,
    RuntimeDeveloperLocalReadyV1, RuntimeDeveloperLocalSigningSeedsV1,
    start_runtime_developer_local_v1,
};
pub use runtime_host::{RuntimeHostProcessError, run_runtime_host_process};
pub use runtime_host_entrypoint::{RuntimeHostEntrypointError, run_runtime_host_entrypoint};
