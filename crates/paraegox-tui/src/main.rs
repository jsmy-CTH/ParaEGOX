use std::{
    collections::VecDeque,
    env,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalFailureV1, AgentConversationTerminalV1,
    AgentConversationTurnId,
};
#[cfg(unix)]
use paraegox_tui::run_runtime_developer_local_ipc_chat;
use paraegox_tui::{
    ConversationClient, ConversationClientError, ConversationClientEvent,
    ConversationConnectionState, TuiOptions, run_conversation_tui,
};

const FIXTURE_DEADLINE_BUDGET_NANOS: u64 = 30_000_000_000;
const FIXTURE_RESPONSE_POLLS: u8 = 3;

fn main() -> ExitCode {
    match parse_mode(env::args().skip(1)) {
        Ok(CliMode::Help) => {
            print_usage();
            ExitCode::SUCCESS
        }
        Ok(CliMode::FixtureV1) => run_fixture_v1(),
        Ok(CliMode::LocalChatV1(options)) => run_local_chat_v1(options),
        Err(message) => {
            eprintln!("paraegox-tui: {message}");
            print_usage();
            ExitCode::from(2)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CliMode {
    Help,
    FixtureV1,
    LocalChatV1(LocalChatV1CliOptions),
}

fn parse_mode(arguments: impl IntoIterator<Item = String>) -> Result<CliMode, &'static str> {
    let mut arguments = arguments.into_iter();
    let Some(mode) = arguments.next() else {
        return Err("a mode is required; fixture mode is never selected implicitly");
    };
    match mode.as_str() {
        "fixture-v1" if arguments.next().is_none() => Ok(CliMode::FixtureV1),
        "--help" | "-h" if arguments.next().is_none() => Ok(CliMode::Help),
        "fixture-v1" | "--help" | "-h" => Err("unexpected extra arguments"),
        "local-chat-v1" => parse_local_chat_v1(arguments).map(CliMode::LocalChatV1),
        _ => Err("unknown mode"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalChatV1CliOptions {
    runtime_bootstrap_file: PathBuf,
}

fn parse_local_chat_v1(
    mut arguments: impl Iterator<Item = String>,
) -> Result<LocalChatV1CliOptions, &'static str> {
    let mut runtime_bootstrap_file = None;

    while let Some(option) = arguments.next() {
        if option != "--runtime-bootstrap-file" {
            return Err("unknown local-chat-v1 option");
        }
        let value = arguments
            .next()
            .ok_or("local-chat-v1 option is missing its value")?;
        let path = PathBuf::from(value);
        if !is_lexically_absolute(&path) {
            return Err("runtime bootstrap file path must be lexically absolute");
        }
        set_once(&mut runtime_bootstrap_file, path)?;
    }

    Ok(LocalChatV1CliOptions {
        runtime_bootstrap_file: runtime_bootstrap_file
            .ok_or("local-chat-v1 requires --runtime-bootstrap-file")?,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), &'static str> {
    if slot.replace(value).is_some() {
        return Err("duplicate local-chat-v1 option");
    }
    Ok(())
}

fn is_lexically_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

#[cfg(unix)]
fn run_local_chat_v1(options: LocalChatV1CliOptions) -> ExitCode {
    match run_runtime_developer_local_ipc_chat(&options.runtime_bootstrap_file) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("paraegox-tui: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn run_local_chat_v1(_options: LocalChatV1CliOptions) -> ExitCode {
    eprintln!("paraegox-tui: local-chat-v1 requires a Unix host-local IPC capability");
    ExitCode::FAILURE
}

fn print_usage() {
    println!("Usage: paraegox-tui fixture-v1");
    println!("       paraegox-tui local-chat-v1 --runtime-bootstrap-file <absolute-path>");
    println!("       paraegox-tui --help");
    println!();
    println!("fixture-v1 is an explicit local UI fixture; it is not a production Agent service.");
    println!(
        "local-chat-v1 accepts only an owner-private Runtime-issued capability file; it accepts no raw identity, route, transport address, or token."
    );
}

fn run_fixture_v1() -> ExitCode {
    let options = match TuiOptions::try_new(
        "ParaEGOX Agent Chat",
        "FIXTURE v1 — NOT PRODUCTION",
        FIXTURE_DEADLINE_BUDGET_NANOS,
    ) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("paraegox-tui: invalid fixture configuration: {error}");
            return ExitCode::FAILURE;
        }
    };
    match run_conversation_tui(FixtureV1Client::new(), options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("paraegox-tui: {error}");
            ExitCode::FAILURE
        }
    }
}

struct FixturePending {
    request: AgentConversationRequestV1,
    polls_remaining: u8,
    cancellation_requested: bool,
}

struct FixtureV1Client {
    events: VecDeque<ConversationClientEvent>,
    pending: Option<FixturePending>,
    next_turn: u64,
    connected: bool,
    closed: bool,
}

impl FixtureV1Client {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            pending: None,
            next_turn: 1,
            connected: false,
            closed: false,
        }
    }

    fn identity(prefix: u8, sequence: u64) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[0] = prefix;
        bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        bytes
    }

    fn fixture_terminal(request: &AgentConversationRequestV1) -> AgentConversationTerminalV1 {
        let failure = match request.input() {
            "/fail model" => Some(AgentConversationTerminalFailureV1::ModelFailed),
            "/fail deadline" => Some(AgentConversationTerminalFailureV1::DeadlineExceeded),
            "/fail conflict" => Some(AgentConversationTerminalFailureV1::RequestConflict),
            "/fail capacity" => Some(AgentConversationTerminalFailureV1::CapacityExhausted),
            "/fail uncertain" => Some(AgentConversationTerminalFailureV1::ModelOutcomeUncertain),
            "/fail cancelled" => Some(AgentConversationTerminalFailureV1::CancelledBeforeModel),
            _ => None,
        };
        if let Some(failure) = failure {
            AgentConversationTerminalV1::failure(request, failure)
        } else {
            AgentConversationTerminalV1::try_success(
                request,
                &format!("fixture-v1 echo: {}", request.input()),
            )
            .expect("bounded fixture input produces a bounded fixture response")
        }
    }
}

impl ConversationClient for FixtureV1Client {
    fn begin_connect(&mut self) -> Result<(), ConversationClientError> {
        if self.closed {
            return Err(ConversationClientError::new("fixture client is closed"));
        }
        self.events
            .push_back(ConversationClientEvent::ConnectionChanged(
                ConversationConnectionState::Connecting,
            ));
        self.events
            .push_back(ConversationClientEvent::ConnectionChanged(
                ConversationConnectionState::Connected,
            ));
        self.connected = true;
        Ok(())
    }

    fn poll_event(&mut self) -> Result<Option<ConversationClientEvent>, ConversationClientError> {
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        if pending.cancellation_requested {
            return Ok(None);
        }
        if pending.polls_remaining > 0 {
            pending.polls_remaining -= 1;
            return Ok(None);
        }
        let pending = self.pending.take().expect("fixture pending exists");
        Ok(Some(ConversationClientEvent::Terminal(
            Self::fixture_terminal(&pending.request),
        )))
    }

    fn submit_turn(
        &mut self,
        input: &str,
        deadline_budget_nanos: u64,
    ) -> Result<AgentConversationRequestV1, ConversationClientError> {
        if self.closed || !self.connected {
            return Err(ConversationClientError::new(
                "fixture client is not connected",
            ));
        }
        if self.pending.is_some() {
            return Err(ConversationClientError::new(
                "fixture client already has a pending request",
            ));
        }
        let sequence = self.next_turn;
        self.next_turn = self
            .next_turn
            .checked_add(1)
            .ok_or_else(|| ConversationClientError::new("fixture identity space exhausted"))?;
        let request = AgentConversationRequestV1::try_new(
            AgentConversationDeckRunId::try_from_bytes(Self::identity(0xf0, 1))
                .map_err(|error| ConversationClientError::new(error.to_string()))?,
            AgentConversationSessionId::try_from_bytes(Self::identity(0xf1, 1))
                .map_err(|error| ConversationClientError::new(error.to_string()))?,
            AgentConversationTurnId::try_from_bytes(Self::identity(0xf2, sequence))
                .map_err(|error| ConversationClientError::new(error.to_string()))?,
            AgentConversationRequestId::try_from_bytes(Self::identity(0xf3, sequence))
                .map_err(|error| ConversationClientError::new(error.to_string()))?,
            deadline_budget_nanos,
            input,
        )
        .map_err(|error| ConversationClientError::new(error.to_string()))?;
        self.pending = Some(FixturePending {
            request: request.clone(),
            polls_remaining: FIXTURE_RESPONSE_POLLS,
            cancellation_requested: false,
        });
        Ok(request)
    }

    fn request_cancel(
        &mut self,
        request: &AgentConversationRequestV1,
    ) -> Result<(), ConversationClientError> {
        let pending = self
            .pending
            .as_mut()
            .ok_or_else(|| ConversationClientError::new("fixture has no pending request"))?;
        if !same_request(&pending.request, request) {
            return Err(ConversationClientError::new(
                "fixture cancellation request does not match pending request",
            ));
        }
        pending.cancellation_requested = true;
        Ok(())
    }

    fn close(&mut self) -> Result<(), ConversationClientError> {
        self.pending = None;
        self.events.clear();
        self.connected = false;
        self.closed = true;
        Ok(())
    }
}

fn same_request(left: &AgentConversationRequestV1, right: &AgentConversationRequestV1) -> bool {
    left.deck_run_id() == right.deck_run_id()
        && left.session_id() == right.session_id()
        && left.turn_id() == right.turn_id()
        && left.request_id() == right.request_id()
        && left.request_digest() == right.request_digest()
        && left.deadline_budget_nanos() == right.deadline_budget_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_requires_an_explicit_mode() {
        assert_eq!(
            parse_mode(Vec::<String>::new()),
            Err("a mode is required; fixture mode is never selected implicitly")
        );
        assert_eq!(
            parse_mode(["fixture-v1".to_owned()]),
            Ok(CliMode::FixtureV1)
        );
        assert_eq!(parse_mode(["production".to_owned()]), Err("unknown mode"));
        assert_eq!(
            parse_mode(["local-chat-v1".to_owned()]),
            Err("local-chat-v1 requires --runtime-bootstrap-file")
        );
    }

    fn valid_local_chat_arguments() -> Vec<String> {
        [
            "local-chat-v1".to_owned(),
            "--runtime-bootstrap-file".to_owned(),
            "/private/tmp/pxl-test/c.pxab".to_owned(),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn local_chat_mode_accepts_only_the_private_capability_path() {
        let parsed = parse_mode(valid_local_chat_arguments()).expect("valid local-chat mode");
        let CliMode::LocalChatV1(options) = parsed else {
            panic!("local-chat mode must retain its validated handoff inputs")
        };
        assert_eq!(
            options.runtime_bootstrap_file,
            PathBuf::from("/private/tmp/pxl-test/c.pxab")
        );
    }

    #[test]
    fn local_chat_mode_rejects_implicit_identity_transport_and_defaults() {
        let mut duplicate = valid_local_chat_arguments();
        duplicate.extend([
            "--runtime-bootstrap-file".to_owned(),
            "/private/tmp/pxl-test/other.pxab".to_owned(),
        ]);
        assert_eq!(parse_mode(duplicate), Err("duplicate local-chat-v1 option"));

        let mut unknown_transport = valid_local_chat_arguments();
        unknown_transport.extend([
            "--zenoh-endpoint".to_owned(),
            "tcp/127.0.0.1:7447".to_owned(),
        ]);
        assert_eq!(
            parse_mode(unknown_transport),
            Err("unknown local-chat-v1 option")
        );

        let mut raw_identity = valid_local_chat_arguments();
        raw_identity.extend(["--deck-run-id".to_owned(), "11".repeat(16)]);
        assert_eq!(
            parse_mode(raw_identity),
            Err("unknown local-chat-v1 option")
        );

        let relative = [
            "local-chat-v1".to_owned(),
            "--runtime-bootstrap-file".to_owned(),
            "runtime.pxab".to_owned(),
        ];
        assert_eq!(
            parse_mode(relative),
            Err("runtime bootstrap file path must be lexically absolute")
        );

        let parent_component = [
            "local-chat-v1".to_owned(),
            "--runtime-bootstrap-file".to_owned(),
            "/private/tmp/../runtime.pxab".to_owned(),
        ];
        assert_eq!(
            parse_mode(parent_component),
            Err("runtime bootstrap file path must be lexically absolute")
        );
    }

    #[test]
    fn fixture_emits_typed_correlated_success_and_failure() {
        let mut client = FixtureV1Client::new();
        client.begin_connect().expect("connect");
        assert!(matches!(
            client.poll_event().expect("event"),
            Some(ConversationClientEvent::ConnectionChanged(
                ConversationConnectionState::Connecting
            ))
        ));
        assert!(matches!(
            client.poll_event().expect("event"),
            Some(ConversationClientEvent::ConnectionChanged(
                ConversationConnectionState::Connected
            ))
        ));

        let request = client
            .submit_turn("hello", FIXTURE_DEADLINE_BUDGET_NANOS)
            .expect("submit");
        for _ in 0..=FIXTURE_RESPONSE_POLLS {
            let event = client.poll_event().expect("poll");
            if let Some(ConversationClientEvent::Terminal(terminal)) = event {
                assert!(terminal.correlates(&request));
                return;
            }
        }
        panic!("fixture terminal was not emitted");
    }

    #[test]
    fn fixture_cancel_is_intent_only_until_close() {
        let mut client = FixtureV1Client::new();
        client.begin_connect().expect("connect");
        let _ = client.poll_event().expect("connecting");
        let _ = client.poll_event().expect("connected");
        let request = client
            .submit_turn("cancel", FIXTURE_DEADLINE_BUDGET_NANOS)
            .expect("submit");

        client.request_cancel(&request).expect("cancel intent");

        assert_eq!(client.poll_event().expect("poll"), None);
        client.close().expect("close");
        assert!(client.pending.is_none());
    }
}
