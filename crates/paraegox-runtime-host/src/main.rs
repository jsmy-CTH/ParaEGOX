//! Minimal executable owner of the S4 RuntimeHost current-thread reactor.

use std::process::ExitCode;

fn main() -> ExitCode {
    match paraegox_runtime::run_runtime_host_process() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
