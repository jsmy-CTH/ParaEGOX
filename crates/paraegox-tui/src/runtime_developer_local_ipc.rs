use core::fmt;
use std::{path::Path, time::Duration};

use paraegox_agent_contracts::control::{
    AgentConversationCancelStateV1, AgentConversationOpenOutcomeV1,
};
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalV1,
};
use paraegox_runtime::{RuntimeAgentDeveloperLocalIpcClientV1, RuntimeAgentDeveloperLocalIpcError};

use crate::{
    AgentConversationCapability, AgentConversationCapabilityFuture,
    BackgroundConversationClientConfig, BackgroundConversationClientConfigError,
    ConversationClientError, DeveloperLocalInspectionClientErrorV2, LocalChatCompositionError,
    TuiError, TuiOptions, TuiOptionsError, compose_local_chat_client,
    read_developer_local_inspection_status_v2, run_conversation_tui,
    run_conversation_tui_with_inspection_status_v2,
};

const LOCAL_CHAT_TITLE: &str = "ParaEGOX Agent Chat";
const LOCAL_CHAT_MODE_LABEL: &str = "RUNTIME-MANAGED LOCAL CHAT v1";

struct RuntimeDeveloperLocalIpcCapability {
    client: Option<RuntimeAgentDeveloperLocalIpcClientV1>,
}

impl RuntimeDeveloperLocalIpcCapability {
    const fn new(client: RuntimeAgentDeveloperLocalIpcClientV1) -> Self {
        Self {
            client: Some(client),
        }
    }

    fn cloned_client(
        &self,
    ) -> Result<RuntimeAgentDeveloperLocalIpcClientV1, ConversationClientError> {
        self.client
            .as_ref()
            .cloned()
            .ok_or_else(|| ConversationClientError::new("DeveloperLocal Agent IPC is closed"))
    }
}

impl fmt::Debug for RuntimeDeveloperLocalIpcCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDeveloperLocalIpcCapability")
            .field("closed", &self.client.is_none())
            .finish_non_exhaustive()
    }
}

impl AgentConversationCapability for RuntimeDeveloperLocalIpcCapability {
    fn open_session(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        timeout: Duration,
    ) -> AgentConversationCapabilityFuture<AgentConversationOpenOutcomeV1> {
        let client = self.cloned_client();
        Box::pin(async move {
            client?
                .open_session(deck_run_id, session_id, timeout)
                .await
                .map_err(display_safe_ipc_error)
        })
    }

    fn submit(
        &mut self,
        request: AgentConversationRequestV1,
        timeout: Duration,
    ) -> AgentConversationCapabilityFuture<AgentConversationTerminalV1> {
        let client = self.cloned_client();
        Box::pin(async move {
            client?
                .submit(request, timeout)
                .await
                .map_err(display_safe_ipc_error)
        })
    }

    fn cancel(
        &mut self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        timeout: Duration,
    ) -> AgentConversationCapabilityFuture<AgentConversationCancelStateV1> {
        let client = self.cloned_client();
        Box::pin(async move {
            client?
                .cancel(deck_run_id, session_id, request_id, timeout)
                .await
                .map_err(display_safe_ipc_error)
        })
    }

    fn close(&mut self, _timeout: Duration) -> AgentConversationCapabilityFuture<()> {
        let client = self.client.take();
        Box::pin(async move {
            if let Some(client) = client {
                client.close();
            }
            Ok(())
        })
    }
}

/// Runs the terminal frontend from one owner-private Runtime bootstrap file.
///
/// The file carries a generation-scoped typed IPC capability. The TUI neither
/// receives raw Fabric addressing nor owns Runtime, Agent, route, or model
/// lifecycle. The caller must keep the parent endpoint alive until this
/// function returns.
pub fn run_runtime_developer_local_ipc_chat(
    bootstrap_path: &Path,
) -> Result<(), RuntimeDeveloperLocalIpcChatRunError> {
    let client =
        RuntimeAgentDeveloperLocalIpcClientV1::from_private_bootstrap_file(bootstrap_path)?;
    let config = BackgroundConversationClientConfig::try_new(
        client.deck_run_id(),
        client.session_id(),
        usize::from(client.command_capacity()),
        client.operation_timeout(),
    )?;
    let options = TuiOptions::try_new(
        LOCAL_CHAT_TITLE,
        LOCAL_CHAT_MODE_LABEL,
        client.request_deadline_budget_nanos(),
    )?;
    let client_instance_nonce = client.client_instance_nonce();
    let initial_sequence = client.initial_request_sequence();
    let capability = RuntimeDeveloperLocalIpcCapability::new(client);
    let client =
        compose_local_chat_client(config, client_instance_nonce, initial_sequence, capability)?;
    run_conversation_tui(client, options).map_err(Into::into)
}

/// Runs the Runtime-backed chat while independently reading one node-local
/// PXIS-v2 startup snapshot through its separate capability and endpoint.
///
/// The immutable snapshot contains one public-safe NodeDaemon record and the
/// unchanged five-owner PXIS-v1 projection. It is not a live monitor and does
/// not grant the TUI a Node or Runtime lifecycle right.
pub fn run_runtime_developer_local_ipc_chat_with_inspection(
    runtime_bootstrap_path: &Path,
    inspection_bootstrap_path: &Path,
) -> Result<(), RuntimeDeveloperLocalIpcChatRunError> {
    let inspection_status = read_developer_local_inspection_status_v2(inspection_bootstrap_path)?;
    let client =
        RuntimeAgentDeveloperLocalIpcClientV1::from_private_bootstrap_file(runtime_bootstrap_path)?;
    let config = BackgroundConversationClientConfig::try_new(
        client.deck_run_id(),
        client.session_id(),
        usize::from(client.command_capacity()),
        client.operation_timeout(),
    )?;
    let options = TuiOptions::try_new(
        LOCAL_CHAT_TITLE,
        LOCAL_CHAT_MODE_LABEL,
        client.request_deadline_budget_nanos(),
    )?;
    let client_instance_nonce = client.client_instance_nonce();
    let initial_sequence = client.initial_request_sequence();
    let capability = RuntimeDeveloperLocalIpcCapability::new(client);
    let client =
        compose_local_chat_client(config, client_instance_nonce, initial_sequence, capability)?;
    run_conversation_tui_with_inspection_status_v2(client, options, inspection_status)
        .map_err(Into::into)
}

/// Failure while composing or running one DeveloperLocal IPC-backed chat.
#[derive(Debug)]
pub enum RuntimeDeveloperLocalIpcChatRunError {
    Ipc(RuntimeAgentDeveloperLocalIpcError),
    Inspection(DeveloperLocalInspectionClientErrorV2),
    Background(BackgroundConversationClientConfigError),
    Options(TuiOptionsError),
    Composition(LocalChatCompositionError),
    Tui(TuiError),
}

impl fmt::Display for RuntimeDeveloperLocalIpcChatRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipc(error) => write!(formatter, "DeveloperLocal Agent IPC setup failed: {error}"),
            Self::Inspection(error) => {
                write!(formatter, "DeveloperLocal Inspection setup failed: {error}")
            }
            Self::Background(error) => {
                write!(
                    formatter,
                    "DeveloperLocal conversation bounds are invalid: {error}"
                )
            }
            Self::Options(error) => {
                write!(formatter, "local-chat TUI options are invalid: {error}")
            }
            Self::Composition(error) => write!(formatter, "local-chat composition failed: {error}"),
            Self::Tui(error) => write!(formatter, "local-chat terminal failed: {error}"),
        }
    }
}

impl std::error::Error for RuntimeDeveloperLocalIpcChatRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ipc(error) => Some(error),
            Self::Inspection(error) => Some(error),
            Self::Background(error) => Some(error),
            Self::Options(error) => Some(error),
            Self::Composition(error) => Some(error),
            Self::Tui(error) => Some(error),
        }
    }
}

impl From<RuntimeAgentDeveloperLocalIpcError> for RuntimeDeveloperLocalIpcChatRunError {
    fn from(value: RuntimeAgentDeveloperLocalIpcError) -> Self {
        Self::Ipc(value)
    }
}

impl From<DeveloperLocalInspectionClientErrorV2> for RuntimeDeveloperLocalIpcChatRunError {
    fn from(value: DeveloperLocalInspectionClientErrorV2) -> Self {
        Self::Inspection(value)
    }
}

impl From<BackgroundConversationClientConfigError> for RuntimeDeveloperLocalIpcChatRunError {
    fn from(value: BackgroundConversationClientConfigError) -> Self {
        Self::Background(value)
    }
}

impl From<TuiOptionsError> for RuntimeDeveloperLocalIpcChatRunError {
    fn from(value: TuiOptionsError) -> Self {
        Self::Options(value)
    }
}

impl From<LocalChatCompositionError> for RuntimeDeveloperLocalIpcChatRunError {
    fn from(value: LocalChatCompositionError) -> Self {
        Self::Composition(value)
    }
}

impl From<TuiError> for RuntimeDeveloperLocalIpcChatRunError {
    fn from(value: TuiError) -> Self {
        Self::Tui(value)
    }
}

fn display_safe_ipc_error(error: RuntimeAgentDeveloperLocalIpcError) -> ConversationClientError {
    ConversationClientError::new(match error {
        RuntimeAgentDeveloperLocalIpcError::Closed => "DeveloperLocal Agent IPC is closed",
        RuntimeAgentDeveloperLocalIpcError::OwnerUnavailable => {
            "Runtime-managed Agent conversation owner is unavailable"
        }
        RuntimeAgentDeveloperLocalIpcError::GenerationRetired => {
            "Runtime-managed Agent conversation generation is retired"
        }
        RuntimeAgentDeveloperLocalIpcError::OperationTimedOut => {
            "Runtime-managed Agent conversation operation timed out"
        }
        RuntimeAgentDeveloperLocalIpcError::Overloaded => {
            "Runtime-managed Agent conversation endpoint is overloaded"
        }
        _ => "Runtime-managed Agent conversation operation failed",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_failures_are_mapped_to_display_safe_categories() {
        assert_eq!(
            display_safe_ipc_error(RuntimeAgentDeveloperLocalIpcError::GenerationRetired).message(),
            "Runtime-managed Agent conversation generation is retired"
        );
        assert_eq!(
            display_safe_ipc_error(RuntimeAgentDeveloperLocalIpcError::AuthenticationFailed)
                .message(),
            "Runtime-managed Agent conversation operation failed"
        );
    }

    #[test]
    fn ipc_capability_satisfies_owned_worker_boundary() {
        fn assert_send_static<T: Send + 'static>() {}
        assert_send_static::<RuntimeDeveloperLocalIpcCapability>();
    }
}
