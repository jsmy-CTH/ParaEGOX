#[cfg(unix)]
fn main() {
    use std::ffi::OsStr;
    use std::path::PathBuf;

    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let command = arguments.next();
    let result = if command.as_deref() == Some(OsStr::new("developer-local-reference-v1")) {
        let flag = arguments.next();
        let bootstrap_path = arguments.next();
        if flag.as_deref() != Some(OsStr::new("--bootstrap-file"))
            || bootstrap_path.is_none()
            || arguments.next().is_some()
        {
            usage_and_exit()
        }
        let Some(bootstrap_path) = bootstrap_path else {
            usage_and_exit()
        };
        paraegox_node::process::serve_developer_local_reference_node_daemon_v1(&PathBuf::from(
            bootstrap_path,
        ))
    } else if command.as_deref() == Some(OsStr::new("developer-local-runtime-observation-v1")) {
        let bootstrap_flag = arguments.next();
        let bootstrap_path = arguments.next();
        let observation_flag = arguments.next();
        let observation_path = arguments.next();
        if bootstrap_flag.as_deref() != Some(OsStr::new("--bootstrap-file"))
            || observation_flag.as_deref() != Some(OsStr::new("--observation-bootstrap-file"))
            || bootstrap_path.is_none()
            || observation_path.is_none()
            || arguments.next().is_some()
        {
            usage_and_exit()
        }
        let (Some(bootstrap_path), Some(observation_path)) = (bootstrap_path, observation_path)
        else {
            usage_and_exit()
        };
        paraegox_node::process::serve_developer_local_runtime_observation_node_daemon_v1(
            &PathBuf::from(bootstrap_path),
            &PathBuf::from(observation_path),
        )
    } else {
        usage_and_exit()
    };
    if let Err(error) = result {
        eprintln!("paraegox-noded failed: {error}");
        std::process::exit(2);
    }
}

#[cfg(unix)]
fn usage_and_exit() -> ! {
    eprintln!(
        "usage: paraegox-noded developer-local-reference-v1 --bootstrap-file <path> | developer-local-runtime-observation-v1 --bootstrap-file <path> --observation-bootstrap-file <path>"
    );
    std::process::exit(2);
}

#[cfg(not(unix))]
fn main() {
    eprintln!("paraegox-noded is unavailable: the current reference process requires Unix");
    std::process::exit(2);
}
