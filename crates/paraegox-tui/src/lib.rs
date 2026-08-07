//! Terminal chat frontend for a typed ParaEGOX Agent conversation adapter.
//!
//! This crate owns message editing, display state and terminal lifecycle only.
//! It does not own an Agent runtime, transport, journal, retry policy, model
//! provider, or credentials. A production integration must inject a bounded
//! [`ConversationClient`] implementation. No fixture is selected implicitly.

mod app;
mod background;
mod client;
#[cfg(unix)]
mod inspection;
mod local_chat;
mod render;
#[cfg(unix)]
mod runtime_capability;
#[cfg(unix)]
mod runtime_developer_local_ipc;
mod terminal;

use core::fmt;
use std::{io, time::Duration};

use crossterm::event::{self, Event};
use paraegox_agent_contracts::MAX_AGENT_CONVERSATION_DEADLINE_BUDGET_NANOS;
use paraegox_inspection::{LocalInspectionSnapshotV1, LocalInspectionSnapshotV2};

pub use background::{
    AgentConversationCapability, AgentConversationCapabilityFuture,
    AgentConversationRequestFactory, BackgroundConversationClient,
    BackgroundConversationClientConfig, BackgroundConversationClientConfigError,
    MAX_BACKGROUND_CONVERSATION_COMMANDS,
};
pub use client::{
    ConversationClient, ConversationClientError, ConversationClientEvent,
    ConversationConnectionState,
};
#[cfg(unix)]
pub use inspection::{
    DeveloperLocalInspectionClientErrorV1, DeveloperLocalInspectionClientErrorV2,
    read_developer_local_inspection_status_v1, read_developer_local_inspection_status_v2,
};
pub use local_chat::{
    LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES, LocalChatCompositionError,
    LocalChatRequestFactoryError, LocalChatRequestFactoryV1, compose_local_chat_client,
};
#[cfg(unix)]
pub use runtime_capability::{
    RuntimeLocalChatRunError, RuntimeManagedAgentConversationCapability,
    compose_runtime_local_chat_client, run_runtime_local_chat,
};
#[cfg(unix)]
pub use runtime_developer_local_ipc::{
    RuntimeDeveloperLocalIpcChatRunError, run_runtime_developer_local_ipc_chat,
    run_runtime_developer_local_ipc_chat_with_inspection,
};

use app::{ChatApp, RunDirective};
use terminal::TerminalSession;

const DEFAULT_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Validated presentation and request-budget configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuiOptions {
    title: Box<str>,
    mode_label: Box<str>,
    deadline_budget_nanos: u64,
    event_poll_interval: Duration,
}

impl TuiOptions {
    /// Creates explicit TUI options for one injected adapter.
    pub fn try_new(
        title: impl Into<Box<str>>,
        mode_label: impl Into<Box<str>>,
        deadline_budget_nanos: u64,
    ) -> Result<Self, TuiOptionsError> {
        let title = title.into();
        let mode_label = mode_label.into();
        if title.trim().is_empty() {
            return Err(TuiOptionsError::EmptyTitle);
        }
        if mode_label.trim().is_empty() {
            return Err(TuiOptionsError::EmptyModeLabel);
        }
        if deadline_budget_nanos == 0
            || deadline_budget_nanos > MAX_AGENT_CONVERSATION_DEADLINE_BUDGET_NANOS
        {
            return Err(TuiOptionsError::InvalidDeadlineBudget);
        }
        Ok(Self {
            title,
            mode_label,
            deadline_budget_nanos,
            event_poll_interval: DEFAULT_EVENT_POLL_INTERVAL,
        })
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[must_use]
    pub fn mode_label(&self) -> &str {
        &self.mode_label
    }

    #[must_use]
    pub const fn deadline_budget_nanos(&self) -> u64 {
        self.deadline_budget_nanos
    }
}

/// Fail-closed option validation errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TuiOptionsError {
    EmptyTitle,
    EmptyModeLabel,
    InvalidDeadlineBudget,
}

impl fmt::Display for TuiOptionsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyTitle => "TUI title is empty",
            Self::EmptyModeLabel => "TUI mode label is empty",
            Self::InvalidDeadlineBudget => "conversation deadline budget is out of range",
        })
    }
}

impl std::error::Error for TuiOptionsError {}

/// Runtime failures from terminal setup, event handling, or adapter shutdown.
#[derive(Debug)]
pub enum TuiError {
    Terminal(io::Error),
    ClientClose(ConversationClientError),
}

impl fmt::Display for TuiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal(error) => write!(formatter, "terminal failure: {error}"),
            Self::ClientClose(error) => {
                write!(formatter, "conversation client close failed: {error}")
            }
        }
    }
}

impl std::error::Error for TuiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Terminal(error) => Some(error),
            Self::ClientClose(error) => Some(error),
        }
    }
}

/// Runs the terminal frontend with one explicitly supplied conversation client.
///
/// The alternate screen and raw mode are restored before adapter shutdown is
/// awaited, and a drop guard repeats incomplete restoration during unwinding.
pub fn run_conversation_tui<C: ConversationClient>(
    client: C,
    options: TuiOptions,
) -> Result<(), TuiError> {
    run_conversation_tui_inner(client, options, None, None)
}

#[cfg(unix)]
fn run_conversation_tui_with_inspection_status_v2<C: ConversationClient>(
    client: C,
    options: TuiOptions,
    inspection_status: LocalInspectionSnapshotV2,
) -> Result<(), TuiError> {
    run_conversation_tui_inner(client, options, None, Some(inspection_status))
}

fn run_conversation_tui_inner<C: ConversationClient>(
    mut client: C,
    options: TuiOptions,
    inspection_status: Option<LocalInspectionSnapshotV1>,
    inspection_status_v2: Option<LocalInspectionSnapshotV2>,
) -> Result<(), TuiError> {
    let mut session = match TerminalSession::enter() {
        Ok(session) => session,
        Err(error) => {
            let close_result = client.close();
            return match close_result {
                Ok(()) => Err(TuiError::Terminal(error)),
                Err(close_error) => Err(TuiError::ClientClose(close_error)),
            };
        }
    };

    let active_result = run_active(
        &mut session,
        &mut client,
        options,
        inspection_status,
        inspection_status_v2,
    );
    let restore_result = session.restore();
    drop(session);
    let close_result = client.close();

    if let Err(error) = active_result {
        return Err(TuiError::Terminal(error));
    }
    if let Err(error) = restore_result {
        return Err(TuiError::Terminal(error));
    }
    close_result.map_err(TuiError::ClientClose)
}

fn run_active<C: ConversationClient>(
    session: &mut TerminalSession,
    client: &mut C,
    options: TuiOptions,
    inspection_status: Option<LocalInspectionSnapshotV1>,
    inspection_status_v2: Option<LocalInspectionSnapshotV2>,
) -> io::Result<()> {
    let event_poll_interval = options.event_poll_interval;
    let mut app = match (inspection_status, inspection_status_v2) {
        (_, Some(status)) => ChatApp::new_with_inspection_status_v2(options, status),
        (Some(status), None) => ChatApp::new_with_inspection_status(options, Some(status)),
        (None, None) => ChatApp::new(options),
    };
    app.start(client);

    loop {
        app.poll(client);
        session
            .terminal_mut()
            .draw(|frame| render::render(frame, &app))?;

        if !event::poll(event_poll_interval)? {
            continue;
        }
        match event::read()? {
            Event::Key(key) => {
                if app.handle_key(key, client) == RunDirective::Quit {
                    return Ok(());
                }
            }
            Event::Paste(text) => app.handle_paste(&text),
            Event::Resize(_, _) | Event::FocusGained | Event::FocusLost | Event::Mouse(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_reject_ambiguous_labels_and_invalid_protocol_budget() {
        assert_eq!(
            TuiOptions::try_new("", "PRODUCTION", 1),
            Err(TuiOptionsError::EmptyTitle)
        );
        assert_eq!(
            TuiOptions::try_new("chat", "", 1),
            Err(TuiOptionsError::EmptyModeLabel)
        );
        assert_eq!(
            TuiOptions::try_new("chat", "PRODUCTION", 0),
            Err(TuiOptionsError::InvalidDeadlineBudget)
        );
        assert_eq!(
            TuiOptions::try_new(
                "chat",
                "PRODUCTION",
                MAX_AGENT_CONVERSATION_DEADLINE_BUDGET_NANOS + 1,
            ),
            Err(TuiOptionsError::InvalidDeadlineBudget)
        );
    }
}
