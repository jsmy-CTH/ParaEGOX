//! Thin synchronous owner for the local tenure-authority process facade.

use std::process::ExitCode;

fn main() -> ExitCode {
    match paraegox_deployment::run_tenure_authority_process() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
