use core::fmt;

use paraegox_agent_contracts::{AgentConversationRequestV1, AgentConversationTerminalV1};

/// Connection facts reported by an injected conversation adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationConnectionState {
    Connecting,
    Connected,
    Disconnected,
}

/// Typed events consumed by the TUI event loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConversationClientEvent {
    ConnectionChanged(ConversationConnectionState),
    Terminal(AgentConversationTerminalV1),
}

/// A display-safe adapter failure.
///
/// Implementations must not put credentials, model secrets, raw transport
/// payloads, or private journal content in this value because the TUI renders
/// it for the operator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationClientError {
    message: Box<str>,
}

impl ConversationClientError {
    #[must_use]
    pub fn new(message: impl Into<Box<str>>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ConversationClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ConversationClientError {}

/// The only production-facing dependency required by the chat TUI.
///
/// An adapter owns its target scope, session/request identity allocation and
/// transport. In particular, the TUI never opens raw Fabric/Zenoh, Runtime,
/// journal, or model-secret access. All methods are required to be bounded and
/// non-blocking; slow I/O belongs behind the adapter and is surfaced through
/// [`Self::poll_event`]. `submit_turn` returns the exact canonical request that
/// the adapter accepted, allowing the TUI to fence unrelated terminal values.
/// Cancellation is only an intent: it never fabricates a terminal result.
pub trait ConversationClient {
    /// Starts connection establishment without waiting for network I/O.
    fn begin_connect(&mut self) -> Result<(), ConversationClientError>;

    /// Returns at most one already-available connection or terminal event.
    fn poll_event(&mut self) -> Result<Option<ConversationClientEvent>, ConversationClientError>;

    /// Accepts one user turn and returns its canonical protocol request.
    fn submit_turn(
        &mut self,
        input: &str,
        deadline_budget_nanos: u64,
    ) -> Result<AgentConversationRequestV1, ConversationClientError>;

    /// Records cancellation intent for one exact pending request.
    fn request_cancel(
        &mut self,
        request: &AgentConversationRequestV1,
    ) -> Result<(), ConversationClientError>;

    /// Stops accepting work and releases adapter-owned resources.
    fn close(&mut self) -> Result<(), ConversationClientError>;
}
