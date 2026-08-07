use core::fmt;
use std::time::Duration;

use paraegox_agent_contracts::control::{
    AgentConversationCancelStateV1, AgentConversationOpenOutcomeV1,
};
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalV1,
};
use paraegox_runtime::{RuntimeAgentConversationError, RuntimeAgentConversationHandle};

use crate::{
    AgentConversationCapability, AgentConversationCapabilityFuture, BackgroundConversationClient,
    BackgroundConversationClientConfig, ConversationClientError,
    LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES, LocalChatCompositionError, TuiError, TuiOptions,
    compose_local_chat_client, run_conversation_tui,
};

/// TUI-owned lease wrapper for one Runtime-issued Agent conversation handle.
///
/// The wrapped value is already generation-fenced by Runtime. This adapter
/// exposes only typed conversation operations and cannot access the managed
/// Fabric session, opaque port, route, journal, provider, or credentials.
pub struct RuntimeManagedAgentConversationCapability {
    handle: Option<RuntimeAgentConversationHandle>,
}

impl RuntimeManagedAgentConversationCapability {
    #[must_use]
    pub const fn new(handle: RuntimeAgentConversationHandle) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn cloned_handle(&self) -> Result<RuntimeAgentConversationHandle, ConversationClientError> {
        self.handle
            .as_ref()
            .cloned()
            .ok_or_else(|| ConversationClientError::new("Runtime Agent capability is closed"))
    }
}

impl fmt::Debug for RuntimeManagedAgentConversationCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeManagedAgentConversationCapability")
            .field("closed", &self.handle.is_none())
            .finish_non_exhaustive()
    }
}

impl AgentConversationCapability for RuntimeManagedAgentConversationCapability {
    fn open_session(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        timeout: Duration,
    ) -> AgentConversationCapabilityFuture<AgentConversationOpenOutcomeV1> {
        let handle = self.cloned_handle();
        Box::pin(async move {
            handle?
                .open_session(deck_run_id, session_id, timeout)
                .await
                .map_err(display_safe_runtime_error)
        })
    }

    fn submit(
        &mut self,
        request: AgentConversationRequestV1,
        timeout: Duration,
    ) -> AgentConversationCapabilityFuture<AgentConversationTerminalV1> {
        let handle = self.cloned_handle();
        Box::pin(async move {
            handle?
                .submit(request, timeout)
                .await
                .map_err(display_safe_runtime_error)
        })
    }

    fn cancel(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        timeout: Duration,
    ) -> AgentConversationCapabilityFuture<AgentConversationCancelStateV1> {
        let handle = self.cloned_handle();
        Box::pin(async move {
            handle?
                .cancel(deck_run_id, session_id, request_id, timeout)
                .await
                .map_err(display_safe_runtime_error)
        })
    }

    fn close(&mut self, _timeout: Duration) -> AgentConversationCapabilityFuture<()> {
        let handle = self.handle.take();
        Box::pin(async move {
            let Some(mut handle) = handle else {
                return Ok(());
            };
            handle.close().await.map_err(display_safe_runtime_error)
        })
    }
}

/// Composes the local TUI client directly from a Runtime-issued typed lease.
///
/// This is the production in-process handoff. It neither opens another Fabric
/// session nor installs or retires an Agent route; Runtime remains the sole
/// lifecycle owner for both resources.
pub fn compose_runtime_local_chat_client(
    config: BackgroundConversationClientConfig,
    client_instance_nonce: [u8; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES],
    initial_sequence: u64,
    handle: RuntimeAgentConversationHandle,
) -> Result<BackgroundConversationClient, LocalChatCompositionError> {
    compose_local_chat_client(
        config,
        client_instance_nonce,
        initial_sequence,
        RuntimeManagedAgentConversationCapability::new(handle),
    )
}

/// Runs the terminal frontend from one already-issued Runtime client lease.
///
/// A launcher must first complete DeploymentController/Runtime admission and
/// obtain `handle` from the live managed Agent generation. This function owns
/// no desired state, bootstrap, retry, Fabric session, or fixture fallback.
pub fn run_runtime_local_chat(
    handle: RuntimeAgentConversationHandle,
    config: BackgroundConversationClientConfig,
    client_instance_nonce: [u8; LOCAL_CHAT_CLIENT_INSTANCE_NONCE_BYTES],
    initial_sequence: u64,
    options: TuiOptions,
) -> Result<(), RuntimeLocalChatRunError> {
    let client =
        compose_runtime_local_chat_client(config, client_instance_nonce, initial_sequence, handle)?;
    run_conversation_tui(client, options).map_err(Into::into)
}

/// Failure before or during one Runtime-backed local terminal session.
#[derive(Debug)]
pub enum RuntimeLocalChatRunError {
    Composition(LocalChatCompositionError),
    Tui(TuiError),
}

impl fmt::Display for RuntimeLocalChatRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Composition(error) => write!(formatter, "local-chat composition failed: {error}"),
            Self::Tui(error) => write!(formatter, "local-chat terminal failed: {error}"),
        }
    }
}

impl std::error::Error for RuntimeLocalChatRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Composition(error) => Some(error),
            Self::Tui(error) => Some(error),
        }
    }
}

impl From<LocalChatCompositionError> for RuntimeLocalChatRunError {
    fn from(value: LocalChatCompositionError) -> Self {
        Self::Composition(value)
    }
}

impl From<TuiError> for RuntimeLocalChatRunError {
    fn from(value: TuiError) -> Self {
        Self::Tui(value)
    }
}

fn display_safe_runtime_error(error: RuntimeAgentConversationError) -> ConversationClientError {
    ConversationClientError::new(match error {
        RuntimeAgentConversationError::Closed => "Runtime Agent capability is closed",
        RuntimeAgentConversationError::OwnerUnavailable => {
            "Runtime-managed Agent conversation owner is unavailable"
        }
        RuntimeAgentConversationError::OwnerRetired => {
            "Runtime-managed Agent conversation generation is retired"
        }
        // The nested transport error can contain backend diagnostics. It is
        // intentionally collapsed before reaching the operator-rendered UI.
        RuntimeAgentConversationError::OperationRejected => {
            "Runtime-managed Agent conversation operation failed"
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_failures_are_mapped_to_display_safe_categories() {
        assert_eq!(
            display_safe_runtime_error(RuntimeAgentConversationError::Closed).message(),
            "Runtime Agent capability is closed"
        );
        assert_eq!(
            display_safe_runtime_error(RuntimeAgentConversationError::OwnerUnavailable).message(),
            "Runtime-managed Agent conversation owner is unavailable"
        );
        assert_eq!(
            display_safe_runtime_error(RuntimeAgentConversationError::OwnerRetired).message(),
            "Runtime-managed Agent conversation generation is retired"
        );
    }

    #[test]
    fn runtime_capability_satisfies_owned_worker_boundary() {
        fn assert_send_static<T: Send + 'static>() {}
        assert_send_static::<RuntimeManagedAgentConversationCapability>();
    }
}
