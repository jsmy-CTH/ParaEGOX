//! Runtime-consumer-owned contracts shared with deployment producers.

mod reference_assembly;

const _: fn() = reference_assembly::compile_time_anchor;

pub mod apply;
pub mod assignment;
pub mod execution;
pub mod installation;
pub mod process_execution;
pub mod process_protocol;
pub mod provenance;
pub mod reference_control;
pub mod temporal;
pub mod thread_execution;
pub mod wire;
