use std::{
    env,
    ffi::{OsStr, OsString},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use config::{
    Command, DeveloperDeploymentConfigV1, DeveloperDistributedFixtureActionV1,
    DeveloperDistributedFixtureConfigV1, DeveloperFixtureConfigV1, DeveloperNodeConfigV1,
    DeveloperProvisionedConfigV1,
};
use error::LocalProcessError;

#[cfg(unix)]
mod composition;
mod config;
mod error;
#[cfg(unix)]
mod identity;
#[cfg(unix)]
mod inspection;
#[cfg(unix)]
mod layout;

pub(crate) const NODE_DAEMON_CHILD_MODE: &str = "__node-daemon-child-v1";
pub(crate) const NODE_BOOTSTRAP_FILE_OPTION: &str = "--node-bootstrap-file";
pub(crate) const NODE_OBSERVATION_BOOTSTRAP_FILE_OPTION: &str = "--node-observation-bootstrap-file";

fn main() -> ExitCode {
    match dispatch(env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "paraegox: code={} message={}",
                error.code(),
                error.message()
            );
            if matches!(error, LocalProcessError::Configuration(_)) {
                eprintln!();
                print_usage_to_stderr();
            }
            ExitCode::from(error.exit_code())
        }
    }
}

fn dispatch(arguments: impl IntoIterator<Item = OsString>) -> Result<(), LocalProcessError> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if let Some(paths) = parse_node_daemon_child(&arguments)? {
        return run_node_daemon_child(&paths);
    }
    match config::parse(arguments)? {
        Command::Help => {
            print_usage();
            Ok(())
        }
        Command::DeveloperNodeV1(config) => compose_real_node(*config),
        Command::DeveloperDeploymentV1(config) => compose_real_deployment(*config),
        Command::DeveloperFixtureV1(config) => compose_real_local_stack(config),
        Command::DeveloperDistributedFixtureV1(config) => match config.action() {
            DeveloperDistributedFixtureActionV1::Run => {
                compose_real_distributed_fixture_stack(config)
            }
            DeveloperDistributedFixtureActionV1::InitializeIdentity => {
                initialize_distributed_identity(config)
            }
        },
        Command::DeveloperProvisionedV1(config) => compose_real_provisioned_stack(config),
    }
}

fn compose_real_deployment(config: DeveloperDeploymentConfigV1) -> Result<(), LocalProcessError> {
    #[cfg(unix)]
    {
        composition::run_deployment(config)
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        unreachable!("configuration rejects DeveloperLocal before Deployment composition")
    }
}

fn compose_real_node(config: DeveloperNodeConfigV1) -> Result<(), LocalProcessError> {
    #[cfg(unix)]
    {
        composition::run_node(config)
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        unreachable!("configuration rejects DeveloperLocal before node composition on non-Unix")
    }
}

fn parse_node_daemon_child(
    arguments: &[OsString],
) -> Result<Option<NodeChildBootstrapPathsV1>, LocalProcessError> {
    if arguments.first().map(OsString::as_os_str) != Some(OsStr::new(NODE_DAEMON_CHILD_MODE)) {
        return Ok(None);
    }
    if !matches!(arguments.len(), 3 | 5)
        || arguments[1].as_os_str() != OsStr::new(NODE_BOOTSTRAP_FILE_OPTION)
        || arguments.len() == 5
            && arguments[3].as_os_str() != OsStr::new(NODE_OBSERVATION_BOOTSTRAP_FILE_OPTION)
    {
        return Err(LocalProcessError::NodeBootstrap);
    }
    let bootstrap_path = PathBuf::from(&arguments[2]);
    if !is_lexically_absolute_file(&bootstrap_path) {
        return Err(LocalProcessError::NodeBootstrap);
    }
    let observation_bootstrap_path = arguments.get(4).map(PathBuf::from);
    if observation_bootstrap_path
        .as_ref()
        .is_some_and(|path| !is_lexically_absolute_file(path) || path == &bootstrap_path)
    {
        return Err(LocalProcessError::NodeBootstrap);
    }
    Ok(Some(NodeChildBootstrapPathsV1 {
        bootstrap_path,
        observation_bootstrap_path,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeChildBootstrapPathsV1 {
    bootstrap_path: PathBuf,
    observation_bootstrap_path: Option<PathBuf>,
}

fn is_lexically_absolute_file(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn run_node_daemon_child(paths: &NodeChildBootstrapPathsV1) -> Result<(), LocalProcessError> {
    #[cfg(unix)]
    {
        match &paths.observation_bootstrap_path {
            Some(observation_bootstrap_path) => {
                paraegox_node::process::serve_developer_local_runtime_observation_node_daemon_v1(
                    &paths.bootstrap_path,
                    observation_bootstrap_path,
                )
            }
            None => paraegox_node::process::serve_developer_local_reference_node_daemon_v1(
                &paths.bootstrap_path,
            ),
        }
        .map_err(|_| LocalProcessError::NodeChild)
    }
    #[cfg(not(unix))]
    {
        let _ = paths;
        Err(LocalProcessError::NodeBootstrap)
    }
}

fn compose_real_provisioned_stack(
    config: DeveloperProvisionedConfigV1,
) -> Result<(), LocalProcessError> {
    #[cfg(unix)]
    {
        composition::run_provisioned(config)
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        unreachable!("configuration rejects DeveloperLocal before composition on non-Unix")
    }
}

fn compose_real_local_stack(config: DeveloperFixtureConfigV1) -> Result<(), LocalProcessError> {
    #[cfg(unix)]
    {
        composition::run(config)
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        unreachable!("configuration rejects DeveloperLocal before composition on non-Unix")
    }
}

fn compose_real_distributed_fixture_stack(
    config: DeveloperDistributedFixtureConfigV1,
) -> Result<(), LocalProcessError> {
    #[cfg(unix)]
    {
        composition::run_distributed(config)
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        unreachable!("configuration rejects DeveloperLocal before composition on non-Unix")
    }
}

fn initialize_distributed_identity(
    config: DeveloperDistributedFixtureConfigV1,
) -> Result<(), LocalProcessError> {
    #[cfg(unix)]
    {
        let manifest = identity::initialize_distributed(config.state_root())
            .map_err(|_| LocalProcessError::DistributedIdentityInitialization)?;
        let enrollment =
            identity::distributed_certificate_enrollment_plan_json_v1(&config, &manifest)
                .map_err(|_| LocalProcessError::DistributedEnrollmentPlan)?;
        write_distributed_enrollment_plan(&mut io::stdout().lock(), &enrollment)
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        unreachable!("configuration rejects DeveloperLocal before identity initialization")
    }
}

fn write_distributed_enrollment_plan(
    output: &mut impl Write,
    enrollment: &str,
) -> Result<(), LocalProcessError> {
    writeln!(output, "{enrollment}").map_err(|_| LocalProcessError::DistributedEnrollmentPlan)
}

fn print_usage() {
    println!("{}", usage());
}

fn print_usage_to_stderr() {
    eprintln!("{}", usage());
}

fn usage() -> &'static str {
    r"Usage: paraegox chat --config <absolute-paraegox.toml>
       paraegox node --config <absolute-paraegox-node.toml>
       paraegox deployment --config <absolute-paraegox-deployment.toml>
       paraegox --help

chat starts the configured ParaEGOX conversation owner chain and Textual console.
The absolute versioned configuration is the sole public input for provider and
model selection, Fabric settings, and durable state location. Secret fields
contain references only; Secret values are obtained from the configured
resolver and injected at the owning boundary. Secret values are neither CLI
inputs nor persisted in the versioned configuration.

node starts one split-trust local Runtime and one NodeDaemon. Node config
schema v1 retains the G1 host-local feature-only profile. Additive schema v2
starts the G2 host-side Runtime-control listener and authenticated Node-control
ingress/observation bridge. Additive schema v3 also installs the exact
deterministic Agent-provider projection without activating an Agent. All
schemas contain verification keys, opaque
references, and credential file paths, never Controller or Authority private
keys. This command does not run Controller, Authority, the managed Fabric
CoreService, Agent, Model, Inspection, or Textual.

deployment consumes one independently SHA-256-pinned enrollment artifact and
starts the single DeploymentController, tenure Authority, Runtime-control
connector, and Node-control connector owner graph. Config schema v1 prints its
original readiness marker only after the durable managed-successor
reconciliation reports ManagedReady. Schema v2 additionally consumes its
enrollment-pinned Agent-provider projection plus config-owned Fabric/Agent
service identities, loopback listener, and fixed limits profile. It prints a
distinct Agent-bootstrap readiness marker only after the complete durable
bootstrap facade reports Ready. This bounded command is not evidence of a
two-host system proof, remote Agent conversation, remote TUI, or reconnect
policy."
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BrokenEnrollmentOutput;

    impl std::io::Write for BrokenEnrollmentOutput {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn chat_rejects_a_non_absolute_config_path_before_composition() {
        let error = dispatch([
            OsString::from("chat"),
            OsString::from("--config"),
            OsString::from("paraegox.toml"),
        ])
        .expect_err("a relative config path must fail before composition");

        assert!(matches!(error, LocalProcessError::Configuration(_)));
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn node_rejects_a_non_absolute_config_path_before_composition() {
        let error = dispatch([
            OsString::from("node"),
            OsString::from("--config"),
            OsString::from("paraegox-node.toml"),
        ])
        .expect_err("a relative node config path must fail before composition");

        assert!(matches!(error, LocalProcessError::Configuration(_)));
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn deployment_rejects_a_non_absolute_config_path_before_composition() {
        let error = dispatch([
            OsString::from("deployment"),
            OsString::from("--config"),
            OsString::from("paraegox-deployment.toml"),
        ])
        .expect_err("a relative Deployment config path must fail before composition");

        assert!(matches!(error, LocalProcessError::Configuration(_)));
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn bare_controller_is_not_a_public_command() {
        let error = dispatch([OsString::from("controller")])
            .expect_err("bare controller must not select Deployment");

        assert_eq!(
            error,
            LocalProcessError::Configuration(config::ConfigError::UnknownMode)
        );
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn in_progress_distributed_fixture_is_not_a_public_command() {
        let error = dispatch([OsString::from("developer-distributed-fixture-v1")])
            .expect_err("the in-progress distributed fixture must not be public");

        assert_eq!(
            error,
            LocalProcessError::Configuration(config::ConfigError::UnknownMode)
        );
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn internal_distributed_fixture_still_validates_before_composition() {
        let error = dispatch([
            OsString::from("__developer-distributed-fixture-v1"),
            OsString::from("--state-root"),
            OsString::from("/tmp/paraegox-local-distributed"),
            OsString::from("--fabric-listen-a"),
            OsString::from("tcp/127.0.0.1:7451"),
        ])
        .expect_err("missing target B locator must fail before composition");

        assert_eq!(
            error,
            LocalProcessError::Configuration(config::ConfigError::MissingFabricListenB)
        );
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn hidden_distributed_identity_init_uses_the_same_complete_configuration_gate() {
        let error = dispatch([
            OsString::from("__developer-distributed-identity-init-v1"),
            OsString::from("--state-root"),
            OsString::from("/tmp/paraegox-local-distributed-init"),
            OsString::from("--fabric-listen-a"),
            OsString::from("tcp/127.0.0.1:7451"),
        ])
        .expect_err("identity init must require the complete distributed configuration");

        assert_eq!(
            error,
            LocalProcessError::Configuration(config::ConfigError::MissingFabricListenB)
        );
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn distributed_enrollment_output_failure_uses_the_stable_error_surface() {
        assert_eq!(
            write_distributed_enrollment_plan(&mut BrokenEnrollmentOutput, "{}"),
            Err(LocalProcessError::DistributedEnrollmentPlan)
        );
    }

    #[test]
    fn operational_distributed_composition_cannot_implicitly_initialize_pxdi() {
        let source = include_str!("composition.rs");
        assert!(source.contains("identity::open_distributed(config.state_root())"));
        assert!(!source.contains("identity::initialize_distributed(config.state_root())"));
    }

    #[test]
    fn help_paths_succeed_without_starting_the_composition() {
        assert_eq!(dispatch([OsString::from("--help")]), Ok(()));
        assert_eq!(dispatch([OsString::from("-h")]), Ok(()));
    }

    #[test]
    fn usage_exposes_exact_chat_node_and_deployment_config_commands_only() {
        let text = usage();
        assert_eq!(
            text.lines().take(4).collect::<Vec<_>>(),
            [
                "Usage: paraegox chat --config <absolute-paraegox.toml>",
                "       paraegox node --config <absolute-paraegox-node.toml>",
                "       paraegox deployment --config <absolute-paraegox-deployment.toml>",
                "       paraegox --help",
            ]
        );
        assert!(text.contains("paraegox chat --config <absolute-paraegox.toml>"));
        assert!(text.contains("paraegox node --config <absolute-paraegox-node.toml>"));
        assert!(text.contains("paraegox deployment --config <absolute-paraegox-deployment.toml>"));
        assert!(text.contains("split-trust local Runtime and one NodeDaemon"));
        assert!(text.contains("schema v1 retains the G1 host-local feature-only profile"));
        assert!(text.contains("schema v2\nstarts the G2 host-side Runtime-control listener"));
        assert!(text.contains("authenticated Node-control\ningress/observation bridge"));
        assert!(text.contains("schema v3 also installs the exact\ndeterministic Agent-provider"));
        assert!(text.contains("without activating an Agent"));
        assert!(text.contains("never Controller or Authority private\nkeys"));
        assert!(text.contains("does not run Controller, Authority"));
        assert!(text.contains("independently SHA-256-pinned enrollment artifact"));
        assert!(text.contains("single DeploymentController"));
        assert!(text.contains("Config schema v1 prints its\noriginal readiness marker only"));
        assert!(text.contains("reports ManagedReady"));
        assert!(
            text.contains("Schema v2 additionally consumes its\nenrollment-pinned Agent-provider")
        );
        assert!(text.contains("config-owned Fabric/Agent\nservice identities"));
        assert!(text.contains("distinct Agent-bootstrap readiness marker"));
        assert!(text.contains("complete durable\nbootstrap facade reports Ready"));
        assert!(text.contains("not evidence of a\ntwo-host system proof"));
        assert!(text.contains("remote Agent conversation, remote TUI"));
        assert!(text.contains("remote TUI"));
        assert!(text.contains("reconnect\npolicy"));
        assert!(text.contains("absolute versioned configuration"));
        assert!(text.contains("provider and\nmodel selection"));
        assert!(text.contains("Fabric settings"));
        assert!(text.contains("durable state location"));
        assert!(text.contains("Secret fields\ncontain references only"));
        assert!(text.contains("configured\nresolver"));
        assert!(text.contains("injected at the owning boundary"));
        assert!(text.contains("neither CLI\ninputs nor persisted"));
        assert!(!text.contains("chat fixture-v1"));
        assert!(!text.contains("chat openai-v1"));
        assert!(!text.contains("chat deepseek-v1"));
        assert!(!text.contains("paraegox controller"));
        assert!(!text.contains("developer-distributed-fixture-v1"));
        assert!(!text.contains("developer-fixture-v1"));
        assert!(!text.contains("developer-openai-v1"));
        assert!(!text.contains("__developer-distributed-fixture-v1"));
        assert!(!text.contains("__developer-distributed-identity-init-v1"));
        assert!(!text.contains("--state-root"));
        assert!(!text.contains("--fabric-listen"));
        assert!(!text.contains("--model"));
        assert!(!text.contains("--fabric-listen-a"));
        assert!(!text.contains("--fabric-listen-b"));
        assert!(!text.contains("--provider"));
        assert!(!text.contains("--api-key"));
        assert!(!text.contains("--endpoint"));
        assert!(!text.contains("--proxy"));
        assert!(!text.contains("--retry"));
        assert!(!text.contains("--nonce"));
        assert!(!text.contains("--identity"));
        assert!(!text.contains("paraegox-console"));
        assert!(!text.contains("--runtime-bootstrap-file"));
        assert!(!text.contains("--inspection-bootstrap-file"));
        assert!(!text.contains(NODE_DAEMON_CHILD_MODE));
        assert!(!text.contains(NODE_BOOTSTRAP_FILE_OPTION));
        assert!(!text.contains(NODE_OBSERVATION_BOOTSTRAP_FILE_OPTION));
    }

    #[test]
    fn hidden_node_child_accepts_reference_or_runtime_observation_bootstraps() {
        let bootstrap = OsString::from("/private/tmp/pxl-test/node/bootstrap/node.pxnb");
        assert_eq!(
            parse_node_daemon_child(&[
                OsString::from(NODE_DAEMON_CHILD_MODE),
                OsString::from(NODE_BOOTSTRAP_FILE_OPTION),
                bootstrap.clone(),
            ]),
            Ok(Some(NodeChildBootstrapPathsV1 {
                bootstrap_path: PathBuf::from(bootstrap),
                observation_bootstrap_path: None,
            }))
        );
        assert_eq!(
            parse_node_daemon_child(&[
                OsString::from(NODE_DAEMON_CHILD_MODE),
                OsString::from(NODE_BOOTSTRAP_FILE_OPTION),
                OsString::from("/private/tmp/pxl-test/node/bootstrap/node.pxnb"),
                OsString::from(NODE_OBSERVATION_BOOTSTRAP_FILE_OPTION),
                OsString::from("/private/tmp/pxl-test/node/bootstrap/observe.pxob"),
            ]),
            Ok(Some(NodeChildBootstrapPathsV1 {
                bootstrap_path: PathBuf::from("/private/tmp/pxl-test/node/bootstrap/node.pxnb"),
                observation_bootstrap_path: Some(PathBuf::from(
                    "/private/tmp/pxl-test/node/bootstrap/observe.pxob",
                )),
            }))
        );
        assert_eq!(
            parse_node_daemon_child(&[
                OsString::from(NODE_DAEMON_CHILD_MODE),
                OsString::from(NODE_BOOTSTRAP_FILE_OPTION),
                OsString::from("relative.pxnb"),
            ]),
            Err(LocalProcessError::NodeBootstrap)
        );
        assert_eq!(
            parse_node_daemon_child(&[
                OsString::from(NODE_DAEMON_CHILD_MODE),
                OsString::from("--wrong-option"),
                OsString::from("/private/tmp/pxl-test/node.pxnb"),
            ]),
            Err(LocalProcessError::NodeBootstrap)
        );
        assert_eq!(
            parse_node_daemon_child(&[
                OsString::from(NODE_DAEMON_CHILD_MODE),
                OsString::from(NODE_BOOTSTRAP_FILE_OPTION),
                OsString::from("/private/tmp/pxl-test/node/bootstrap/node.pxnb"),
                OsString::from(NODE_OBSERVATION_BOOTSTRAP_FILE_OPTION),
                OsString::from("relative.pxob"),
            ]),
            Err(LocalProcessError::NodeBootstrap)
        );
        assert_eq!(
            parse_node_daemon_child(&[
                OsString::from(NODE_DAEMON_CHILD_MODE),
                OsString::from(NODE_BOOTSTRAP_FILE_OPTION),
                OsString::from("/private/tmp/pxl-test/node/bootstrap/node.pxnb"),
                OsString::from(NODE_OBSERVATION_BOOTSTRAP_FILE_OPTION),
                OsString::from("/private/tmp/pxl-test/node/bootstrap/node.pxnb"),
            ]),
            Err(LocalProcessError::NodeBootstrap)
        );
        assert_eq!(parse_node_daemon_child(&[OsString::from("chat")]), Ok(None));
    }
}
