//! Thin synchronous owner for the exact one-shot DeploymentController facade.

use std::process::ExitCode;

fn main() -> ExitCode {
    match paraegox_deployment::run_deploymentd_process() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
