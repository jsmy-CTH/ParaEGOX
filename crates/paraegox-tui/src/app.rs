use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use paraegox_agent_contracts::{
    AgentConversationRequestV1, AgentConversationTerminalFailureV1,
    AgentConversationTerminalResultV1, AgentConversationTerminalV1,
    MAX_AGENT_CONVERSATION_INPUT_BYTES,
};
use paraegox_inspection::{LocalInspectionSnapshotV1, LocalInspectionSnapshotV2};

use crate::{
    ConversationClient, ConversationClientError, ConversationClientEvent,
    ConversationConnectionState, TuiOptions,
};

const MAX_HISTORY_MESSAGES: usize = 512;
const MAX_CLIENT_EVENTS_PER_TICK: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunDirective {
    Continue,
    Quit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalCommand {
    Help,
    Clear,
    Cancel,
    Quit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UiConnectionState {
    Connecting,
    Connected,
    Disconnected,
    Failed(Box<str>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageRole {
    User,
    Assistant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MessageDelivery {
    Sending,
    CancellationRequested,
    Delivered,
    TerminalFailure(AgentConversationTerminalFailureV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChatMessage {
    pub(crate) role: MessageRole,
    pub(crate) text: Box<str>,
    pub(crate) delivery: MessageDelivery,
}

#[derive(Clone, Debug)]
struct PendingTurn {
    request: AgentConversationRequestV1,
    message_index: usize,
    cancellation_requested: bool,
}

#[derive(Clone, Debug)]
enum InspectionStatus {
    V1(LocalInspectionSnapshotV1),
    V2(LocalInspectionSnapshotV2),
}

pub(crate) struct ChatApp {
    options: TuiOptions,
    connection: UiConnectionState,
    history: Vec<ChatMessage>,
    input: String,
    cursor: usize,
    pending: Option<PendingTurn>,
    notice: Option<Box<str>>,
    poll_client: bool,
    inspection_status: Option<InspectionStatus>,
}

impl ChatApp {
    pub(crate) fn new(options: TuiOptions) -> Self {
        Self::new_with_inspection_status(options, None)
    }

    pub(crate) fn new_with_inspection_status(
        options: TuiOptions,
        inspection_status: Option<LocalInspectionSnapshotV1>,
    ) -> Self {
        Self::new_with_inspection_status_value(options, inspection_status.map(InspectionStatus::V1))
    }

    pub(crate) fn new_with_inspection_status_v2(
        options: TuiOptions,
        inspection_status: LocalInspectionSnapshotV2,
    ) -> Self {
        Self::new_with_inspection_status_value(
            options,
            Some(InspectionStatus::V2(inspection_status)),
        )
    }

    fn new_with_inspection_status_value(
        options: TuiOptions,
        inspection_status: Option<InspectionStatus>,
    ) -> Self {
        Self {
            options,
            connection: UiConnectionState::Disconnected,
            history: Vec::new(),
            input: String::new(),
            cursor: 0,
            pending: None,
            notice: None,
            poll_client: true,
            inspection_status,
        }
    }

    pub(crate) fn start<C: ConversationClient>(&mut self, client: &mut C) {
        self.connection = UiConnectionState::Connecting;
        if let Err(error) = client.begin_connect() {
            self.record_client_failure(error);
        }
    }

    pub(crate) fn poll<C: ConversationClient>(&mut self, client: &mut C) {
        if !self.poll_client {
            return;
        }
        for _ in 0..MAX_CLIENT_EVENTS_PER_TICK {
            match client.poll_event() {
                Ok(Some(event)) => self.apply_client_event(event),
                Ok(None) => return,
                Err(error) => {
                    self.record_client_failure(error);
                    return;
                }
            }
        }
    }

    pub(crate) fn handle_key<C: ConversationClient>(
        &mut self,
        key: KeyEvent,
        client: &mut C,
    ) -> RunDirective {
        if key.kind == KeyEventKind::Release {
            return RunDirective::Continue;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'C' | 'q' | 'Q'))
        {
            self.request_cancel(client);
            return RunDirective::Quit;
        }

        match key.code {
            KeyCode::Esc => {
                if self.pending.is_some() {
                    self.request_cancel(client);
                    RunDirective::Continue
                } else {
                    RunDirective::Quit
                }
            }
            KeyCode::Enter => self.submit_or_run_command(client),
            KeyCode::Left => {
                self.move_cursor_left();
                RunDirective::Continue
            }
            KeyCode::Right => {
                self.move_cursor_right();
                RunDirective::Continue
            }
            KeyCode::Home => {
                self.cursor = 0;
                RunDirective::Continue
            }
            KeyCode::End => {
                self.cursor = self.input.len();
                RunDirective::Continue
            }
            KeyCode::Backspace => {
                self.backspace();
                RunDirective::Continue
            }
            KeyCode::Delete => {
                self.delete();
                RunDirective::Continue
            }
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.insert_character(character);
                RunDirective::Continue
            }
            _ => RunDirective::Continue,
        }
    }

    pub(crate) fn handle_paste(&mut self, text: &str) {
        for character in text.chars() {
            let character = if matches!(character, '\r' | '\n') {
                ' '
            } else {
                character
            };
            self.insert_character(character);
        }
    }

    fn submit_or_run_command<C: ConversationClient>(&mut self, client: &mut C) -> RunDirective {
        let Some(command) = parse_local_command(&self.input) else {
            self.submit(client);
            return RunDirective::Continue;
        };
        self.input.clear();
        self.cursor = 0;

        match command {
            LocalCommand::Help => {
                self.notice = Some(
                    "commands: /help · /clear (idle only) · /cancel (intent only) · /quit (waits for terminal if pending) | keys: Enter send/run · Esc cancel pending/exit idle · Ctrl-C/Ctrl-Q cancel pending then exit · arrows/Home/End/Backspace/Delete edit"
                        .into(),
                );
                RunDirective::Continue
            }
            LocalCommand::Clear => {
                if self.pending.is_some() {
                    self.notice = Some("cannot clear local history while a turn is pending".into());
                } else {
                    self.history.clear();
                    self.notice = Some("local chat history cleared".into());
                }
                RunDirective::Continue
            }
            LocalCommand::Cancel => {
                if self.pending.is_some() {
                    self.request_cancel(client);
                } else {
                    self.notice = Some("no turn is pending; no cancel intent was recorded".into());
                }
                RunDirective::Continue
            }
            LocalCommand::Quit => {
                if self.pending.is_some() {
                    self.request_cancel(client);
                    RunDirective::Continue
                } else {
                    RunDirective::Quit
                }
            }
        }
    }

    fn submit<C: ConversationClient>(&mut self, client: &mut C) {
        self.notice = None;
        if self.pending.is_some() {
            self.notice = Some("one turn is already sending".into());
            return;
        }
        if self.connection != UiConnectionState::Connected {
            self.notice = Some("conversation service is not connected".into());
            return;
        }
        if self.input.is_empty() {
            return;
        }

        let input = self.input.clone();
        match client.submit_turn(&input, self.options.deadline_budget_nanos()) {
            Ok(request) => {
                self.trim_history_for_new_message();
                let message_index = self.history.len();
                self.history.push(ChatMessage {
                    role: MessageRole::User,
                    text: input.into_boxed_str(),
                    delivery: MessageDelivery::Sending,
                });
                self.pending = Some(PendingTurn {
                    request,
                    message_index,
                    cancellation_requested: false,
                });
                self.input.clear();
                self.cursor = 0;
            }
            Err(error) => self.notice = Some(format!("send rejected: {error}").into_boxed_str()),
        }
    }

    fn request_cancel<C: ConversationClient>(&mut self, client: &mut C) {
        let Some(pending) = self.pending.as_mut() else {
            return;
        };
        if pending.cancellation_requested {
            self.notice =
                Some("cancel was already attempted; awaiting an authoritative terminal".into());
            return;
        }

        pending.cancellation_requested = true;
        if let Some(message) = self.history.get_mut(pending.message_index) {
            message.delivery = MessageDelivery::CancellationRequested;
        }
        if let Err(error) = client.request_cancel(&pending.request) {
            self.notice = Some(format!("cancel intent was not accepted: {error}").into_boxed_str());
        } else {
            self.notice = Some("cancel requested; awaiting an authoritative terminal".into());
        }
    }

    fn apply_client_event(&mut self, event: ConversationClientEvent) {
        match event {
            ConversationClientEvent::ConnectionChanged(state) => {
                self.connection = match state {
                    ConversationConnectionState::Connecting => UiConnectionState::Connecting,
                    ConversationConnectionState::Connected => UiConnectionState::Connected,
                    ConversationConnectionState::Disconnected => UiConnectionState::Disconnected,
                };
            }
            ConversationClientEvent::Terminal(terminal) => self.apply_terminal(terminal),
        }
    }

    fn apply_terminal(&mut self, terminal: AgentConversationTerminalV1) {
        let Some(pending) = self.pending.as_ref() else {
            self.protocol_violation("received a terminal without a pending request");
            return;
        };
        if !terminal.correlates(&pending.request) {
            self.protocol_violation("received a terminal for a different request");
            return;
        }

        let message_index = pending.message_index;
        match terminal.result() {
            AgentConversationTerminalResultV1::Success(output) => {
                if let Some(message) = self.history.get_mut(message_index) {
                    message.delivery = MessageDelivery::Delivered;
                }
                self.pending = None;
                self.trim_history_for_new_message();
                self.history.push(ChatMessage {
                    role: MessageRole::Assistant,
                    text: output.clone(),
                    delivery: MessageDelivery::Delivered,
                });
                self.notice = None;
            }
            AgentConversationTerminalResultV1::Failure(failure) => {
                if let Some(message) = self.history.get_mut(message_index) {
                    message.delivery = MessageDelivery::TerminalFailure(*failure);
                }
                self.pending = None;
                self.notice = Some(
                    format!("terminal failure: {}", terminal_failure_label(*failure))
                        .into_boxed_str(),
                );
            }
        }
    }

    fn protocol_violation(&mut self, message: &str) {
        self.connection = UiConnectionState::Failed(message.into());
        self.notice = Some(message.into());
        self.poll_client = false;
    }

    fn record_client_failure(&mut self, error: ConversationClientError) {
        let message = format!("conversation client failed: {error}").into_boxed_str();
        self.connection = UiConnectionState::Failed(message.clone());
        self.notice = Some(message);
        self.poll_client = false;
    }

    fn insert_character(&mut self, character: char) {
        if self.input.len() + character.len_utf8() > MAX_AGENT_CONVERSATION_INPUT_BYTES {
            self.notice = Some("input reached the protocol byte limit".into());
            return;
        }
        self.input.insert(self.cursor, character);
        self.cursor += character.len_utf8();
        self.notice = None;
    }

    fn move_cursor_left(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor = self.input[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(index, _)| index);
    }

    fn move_cursor_right(&mut self) {
        if self.cursor == self.input.len() {
            return;
        }
        let character_length = self.input[self.cursor..]
            .chars()
            .next()
            .map_or(0, char::len_utf8);
        self.cursor += character_length;
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let previous = self.input[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(index, _)| index);
        self.input.drain(previous..self.cursor);
        self.cursor = previous;
        self.notice = None;
    }

    fn delete(&mut self) {
        if self.cursor == self.input.len() {
            return;
        }
        let next = self.cursor
            + self.input[self.cursor..]
                .chars()
                .next()
                .map_or(0, char::len_utf8);
        self.input.drain(self.cursor..next);
        self.notice = None;
    }

    fn trim_history_for_new_message(&mut self) {
        while self.history.len() >= MAX_HISTORY_MESSAGES {
            self.history.remove(0);
            if let Some(pending) = self.pending.as_mut() {
                pending.message_index = pending.message_index.saturating_sub(1);
            }
        }
    }

    pub(crate) fn options(&self) -> &TuiOptions {
        &self.options
    }

    pub(crate) fn connection(&self) -> &UiConnectionState {
        &self.connection
    }

    pub(crate) fn history(&self) -> &[ChatMessage] {
        &self.history
    }

    pub(crate) fn input(&self) -> &str {
        &self.input
    }

    pub(crate) const fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub(crate) const fn inspection_status(&self) -> Option<&LocalInspectionSnapshotV1> {
        match self.inspection_status.as_ref() {
            Some(InspectionStatus::V1(snapshot)) => Some(snapshot),
            Some(InspectionStatus::V2(snapshot)) => Some(snapshot.base_snapshot()),
            None => None,
        }
    }

    pub(crate) const fn inspection_status_v2(&self) -> Option<&LocalInspectionSnapshotV2> {
        match self.inspection_status.as_ref() {
            Some(InspectionStatus::V2(snapshot)) => Some(snapshot),
            Some(InspectionStatus::V1(_)) | None => None,
        }
    }
}

fn parse_local_command(input: &str) -> Option<LocalCommand> {
    match input.trim() {
        "/help" => Some(LocalCommand::Help),
        "/clear" => Some(LocalCommand::Clear),
        "/cancel" => Some(LocalCommand::Cancel),
        "/quit" => Some(LocalCommand::Quit),
        _ => None,
    }
}

pub(crate) const fn terminal_failure_label(
    failure: AgentConversationTerminalFailureV1,
) -> &'static str {
    match failure {
        AgentConversationTerminalFailureV1::ModelFailed => "model failed",
        AgentConversationTerminalFailureV1::DeadlineExceeded => "deadline exceeded",
        AgentConversationTerminalFailureV1::RequestConflict => "request conflict",
        AgentConversationTerminalFailureV1::CapacityExhausted => "capacity exhausted",
        AgentConversationTerminalFailureV1::ModelOutcomeUncertain => "model outcome uncertain",
        AgentConversationTerminalFailureV1::CancelledBeforeModel => "cancelled before model start",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crossterm::event::KeyEventState;
    use paraegox_agent_contracts::{
        AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationSessionId,
        AgentConversationTurnId,
    };

    use super::*;

    #[derive(Default)]
    struct ScriptedClient {
        events: VecDeque<ConversationClientEvent>,
        submitted: Vec<AgentConversationRequestV1>,
        cancelled: Vec<AgentConversationRequestV1>,
        next_identity: u8,
        closed: bool,
    }

    impl ScriptedClient {
        fn connected() -> Self {
            Self {
                events: VecDeque::from([ConversationClientEvent::ConnectionChanged(
                    ConversationConnectionState::Connected,
                )]),
                next_identity: 1,
                ..Self::default()
            }
        }
    }

    impl ConversationClient for ScriptedClient {
        fn begin_connect(&mut self) -> Result<(), ConversationClientError> {
            Ok(())
        }

        fn poll_event(
            &mut self,
        ) -> Result<Option<ConversationClientEvent>, ConversationClientError> {
            Ok(self.events.pop_front())
        }

        fn submit_turn(
            &mut self,
            input: &str,
            deadline_budget_nanos: u64,
        ) -> Result<AgentConversationRequestV1, ConversationClientError> {
            let identity = self.next_identity;
            self.next_identity = self.next_identity.saturating_add(1);
            let request = AgentConversationRequestV1::try_new(
                AgentConversationDeckRunId::try_from_bytes([0x10; 16]).expect("DeckRun"),
                AgentConversationSessionId::try_from_bytes([0x11; 16]).expect("session"),
                AgentConversationTurnId::try_from_bytes([identity; 16]).expect("turn"),
                AgentConversationRequestId::try_from_bytes([identity; 16]).expect("request"),
                deadline_budget_nanos,
                input,
            )
            .expect("valid scripted request");
            self.submitted.push(request.clone());
            Ok(request)
        }

        fn request_cancel(
            &mut self,
            request: &AgentConversationRequestV1,
        ) -> Result<(), ConversationClientError> {
            self.cancelled.push(request.clone());
            Ok(())
        }

        fn close(&mut self) -> Result<(), ConversationClientError> {
            self.closed = true;
            Ok(())
        }
    }

    fn options() -> TuiOptions {
        TuiOptions::try_new("test chat", "TEST ADAPTER", 5_000_000_000).expect("options")
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn ctrl(character: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(character),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn connected_app(client: &mut ScriptedClient) -> ChatApp {
        let mut app = ChatApp::new(options());
        app.start(client);
        app.poll(client);
        assert_eq!(app.connection(), &UiConnectionState::Connected);
        app
    }

    fn type_text(app: &mut ChatApp, client: &mut ScriptedClient, text: &str) {
        for character in text.chars() {
            assert_eq!(
                app.handle_key(key(KeyCode::Char(character)), client),
                RunDirective::Continue
            );
        }
    }

    #[test]
    fn typed_client_drives_sending_and_terminal_success() {
        let mut client = ScriptedClient::connected();
        let mut app = connected_app(&mut client);
        type_text(&mut app, &mut client, "hello");
        app.handle_key(key(KeyCode::Enter), &mut client);

        assert!(app.is_pending());
        assert_eq!(client.submitted.len(), 1);
        assert_eq!(app.history()[0].delivery, MessageDelivery::Sending);

        client.events.push_back(ConversationClientEvent::Terminal(
            AgentConversationTerminalV1::try_success(&client.submitted[0], "world")
                .expect("terminal"),
        ));
        app.poll(&mut client);

        assert!(!app.is_pending());
        assert_eq!(app.history().len(), 2);
        assert_eq!(app.history()[0].delivery, MessageDelivery::Delivered);
        assert_eq!(app.history()[1].role, MessageRole::Assistant);
        assert_eq!(&*app.history()[1].text, "world");
    }

    #[test]
    fn terminal_failure_is_not_presented_as_success() {
        let mut client = ScriptedClient::connected();
        let mut app = connected_app(&mut client);
        type_text(&mut app, &mut client, "fail");
        app.handle_key(key(KeyCode::Enter), &mut client);
        client.events.push_back(ConversationClientEvent::Terminal(
            AgentConversationTerminalV1::failure(
                &client.submitted[0],
                AgentConversationTerminalFailureV1::DeadlineExceeded,
            ),
        ));

        app.poll(&mut client);

        assert!(!app.is_pending());
        assert_eq!(
            app.history()[0].delivery,
            MessageDelivery::TerminalFailure(AgentConversationTerminalFailureV1::DeadlineExceeded)
        );
        assert_eq!(app.notice(), Some("terminal failure: deadline exceeded"));
    }

    #[test]
    fn unrelated_terminal_is_fenced_and_pending_request_is_preserved() {
        let mut client = ScriptedClient::connected();
        let mut app = connected_app(&mut client);
        type_text(&mut app, &mut client, "expected");
        app.handle_key(key(KeyCode::Enter), &mut client);

        let unrelated = AgentConversationRequestV1::try_new(
            AgentConversationDeckRunId::try_from_bytes([0x43; 16]).expect("DeckRun"),
            AgentConversationSessionId::try_from_bytes([0x44; 16]).expect("session"),
            AgentConversationTurnId::try_from_bytes([0x55; 16]).expect("turn"),
            AgentConversationRequestId::try_from_bytes([0x66; 16]).expect("request"),
            5_000_000_000,
            "unrelated",
        )
        .expect("request");
        client.events.push_back(ConversationClientEvent::Terminal(
            AgentConversationTerminalV1::try_success(&unrelated, "wrong").expect("terminal"),
        ));

        app.poll(&mut client);

        assert!(app.is_pending());
        assert_eq!(app.history().len(), 1);
        assert!(matches!(app.connection(), UiConnectionState::Failed(_)));
    }

    #[test]
    fn escape_records_cancel_intent_but_does_not_invent_a_terminal() {
        let mut client = ScriptedClient::connected();
        let mut app = connected_app(&mut client);
        type_text(&mut app, &mut client, "cancel me");
        app.handle_key(key(KeyCode::Enter), &mut client);

        assert_eq!(
            app.handle_key(key(KeyCode::Esc), &mut client),
            RunDirective::Continue
        );
        assert_eq!(client.cancelled.len(), 1);
        assert!(app.is_pending());
        assert_eq!(
            app.history()[0].delivery,
            MessageDelivery::CancellationRequested
        );
        assert_eq!(
            app.notice(),
            Some("cancel requested; awaiting an authoritative terminal")
        );
    }

    #[test]
    fn help_is_local_and_reports_the_available_commands_and_keys() {
        let mut client = ScriptedClient::connected();
        let mut app = connected_app(&mut client);
        type_text(&mut app, &mut client, " /help ");

        assert_eq!(
            app.handle_key(key(KeyCode::Enter), &mut client),
            RunDirective::Continue
        );
        assert!(client.submitted.is_empty());
        assert!(app.input().is_empty());
        let notice = app.notice().expect("help notice");
        for expected in [
            "/help", "/clear", "/cancel", "/quit", "Enter", "Esc", "Ctrl-C", "Ctrl-Q",
        ] {
            assert!(notice.contains(expected), "missing {expected} from help");
        }
    }

    #[test]
    fn clear_is_local_and_only_clears_idle_history() {
        let mut client = ScriptedClient::connected();
        let mut app = connected_app(&mut client);
        app.history.push(ChatMessage {
            role: MessageRole::Assistant,
            text: "retained locally".into(),
            delivery: MessageDelivery::Delivered,
        });
        type_text(&mut app, &mut client, "/clear");

        assert_eq!(
            app.handle_key(key(KeyCode::Enter), &mut client),
            RunDirective::Continue
        );
        assert!(app.history().is_empty());
        assert!(client.submitted.is_empty());
        assert_eq!(app.notice(), Some("local chat history cleared"));

        type_text(&mut app, &mut client, "pending");
        app.handle_key(key(KeyCode::Enter), &mut client);
        type_text(&mut app, &mut client, "/clear");
        app.handle_key(key(KeyCode::Enter), &mut client);

        assert!(app.is_pending());
        assert_eq!(app.history().len(), 1);
        assert_eq!(client.submitted.len(), 1);
        assert_eq!(
            app.notice(),
            Some("cannot clear local history while a turn is pending")
        );
    }

    #[test]
    fn cancel_command_records_intent_without_inventing_a_terminal() {
        let mut client = ScriptedClient::connected();
        let mut app = connected_app(&mut client);
        type_text(&mut app, &mut client, "cancel through command");
        app.handle_key(key(KeyCode::Enter), &mut client);
        type_text(&mut app, &mut client, "/cancel");

        assert_eq!(
            app.handle_key(key(KeyCode::Enter), &mut client),
            RunDirective::Continue
        );
        assert_eq!(client.submitted.len(), 1);
        assert_eq!(client.cancelled, client.submitted);
        assert!(app.is_pending());
        assert_eq!(app.history().len(), 1);
        assert_eq!(
            app.history()[0].delivery,
            MessageDelivery::CancellationRequested
        );
        assert_eq!(
            app.notice(),
            Some("cancel requested; awaiting an authoritative terminal")
        );
    }

    #[test]
    fn quit_command_exits_only_after_no_turn_is_pending() {
        let mut client = ScriptedClient::connected();
        let mut app = connected_app(&mut client);
        type_text(&mut app, &mut client, "finish before quitting");
        app.handle_key(key(KeyCode::Enter), &mut client);
        type_text(&mut app, &mut client, "/quit");

        assert_eq!(
            app.handle_key(key(KeyCode::Enter), &mut client),
            RunDirective::Continue
        );
        assert_eq!(client.cancelled, client.submitted);
        assert!(app.is_pending());

        client.events.push_back(ConversationClientEvent::Terminal(
            AgentConversationTerminalV1::failure(
                &client.submitted[0],
                AgentConversationTerminalFailureV1::CancelledBeforeModel,
            ),
        ));
        app.poll(&mut client);
        assert!(!app.is_pending());

        type_text(&mut app, &mut client, "/quit");
        assert_eq!(
            app.handle_key(key(KeyCode::Enter), &mut client),
            RunDirective::Quit
        );
        assert_eq!(client.submitted.len(), 1);
    }

    #[test]
    fn control_c_cancels_exact_pending_request_and_exits() {
        let mut client = ScriptedClient::connected();
        let mut app = connected_app(&mut client);
        type_text(&mut app, &mut client, "cancel then quit");
        app.handle_key(key(KeyCode::Enter), &mut client);

        assert_eq!(app.handle_key(ctrl('c'), &mut client), RunDirective::Quit);
        assert_eq!(client.cancelled, client.submitted);
        assert!(app.is_pending());
    }

    #[test]
    fn utf8_editing_preserves_character_boundaries() {
        let mut client = ScriptedClient::connected();
        let mut app = connected_app(&mut client);
        type_text(&mut app, &mut client, "你a好");
        app.handle_key(key(KeyCode::Left), &mut client);
        app.handle_key(key(KeyCode::Backspace), &mut client);
        app.handle_key(key(KeyCode::Char('们')), &mut client);
        app.handle_key(key(KeyCode::Delete), &mut client);

        assert_eq!(app.input(), "你们");
        assert!(app.input().is_char_boundary(app.cursor()));
    }

    #[test]
    fn disconnected_state_rejects_send_without_losing_input() {
        let mut client = ScriptedClient::default();
        let mut app = ChatApp::new(options());
        app.start(&mut client);
        type_text(&mut app, &mut client, "keep me");
        app.handle_key(key(KeyCode::Enter), &mut client);

        assert_eq!(app.input(), "keep me");
        assert!(client.submitted.is_empty());
        assert_eq!(app.notice(), Some("conversation service is not connected"));
    }
}
