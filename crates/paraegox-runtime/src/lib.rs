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
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(
        dead_code,
        reason = "Installed-production observation awaits the admitted non-Linux backend"
    )
)] // GOV-WAIVER-0001
mod runtime_artifact;
mod runtime_build_metadata;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod runtime_clock;
#[cfg(any(target_os = "linux", all(test, unix)))]
mod runtime_control_endpoint;
#[expect(dead_code, reason = "Awaiting Runtime endpoint consumer")] // GOV-WAIVER-0001
mod runtime_control_state;
mod runtime_host;
mod runtime_host_entrypoint;
#[cfg(any(target_os = "linux", all(test, unix)))]
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
#[cfg(any(target_os = "linux", all(test, unix)))]
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

pub use runtime_host::{RuntimeHostProcessError, run_runtime_host_process};
pub use runtime_host_entrypoint::{RuntimeHostEntrypointError, run_runtime_host_entrypoint};
