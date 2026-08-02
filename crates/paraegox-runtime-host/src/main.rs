//! Minimal executable owner of the S4 RuntimeHost current-thread reactor.

use std::process::ExitCode;

include!(concat!(
    env!("OUT_DIR"),
    "/runtime_host_build_metadata_generated.rs"
));

fn main() -> ExitCode {
    match paraegox_runtime::run_runtime_host_entrypoint(
        RUNTIME_HOST_BUILD_INSTANCE_ID,
        RUNTIME_HOST_BUILD_TARGET_TRIPLE,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
