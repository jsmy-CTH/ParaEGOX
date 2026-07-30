//! Runtime-owned canonical request admission, bounded Mailbox, and pure binding/control state.

#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod admission;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod apply_state;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod mailbox;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod port_binding;
#[expect(dead_code, reason = "Awaiting admitted internal consumer")] // GOV-WAIVER-0001
mod request;
