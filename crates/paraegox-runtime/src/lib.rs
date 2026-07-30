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
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod loop_domain;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod mailbox;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod port_binding;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod request;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod runtime_clock;
mod runtime_host;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod task_registry;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod thread_component_runtime;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod thread_domain;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod thread_registry;

pub use runtime_host::{RuntimeHostProcessError, run_runtime_host_process};
