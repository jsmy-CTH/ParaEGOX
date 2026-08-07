#![cfg(unix)]

//! Runtime-owned composition of one Agent semantic owner on the already-live
//! managed Fabric generation.
//!
//! This module deliberately has no default route, provider, secret, or service
//! configuration. Its crate-private assembly input is the exact seam a future
//! admitted `ManagedAgentStackTargetExecutionV1` consumer must populate. The
//! public client capability remains opaque and never exposes Fabric, binding,
//! journal, provider, or key-expression values.

use core::{fmt, time::Duration};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

use crate::managed_agent_transport::{
    AGENT_CONVERSATION_PORT_PHYSICAL_BINDINGS, AgentConversationClient,
    AgentConversationClientError, AgentConversationPort, AgentConversationPortDescriptorError,
    AgentConversationPortError, AgentConversationPortMutationDispositionV1,
    AgentConversationPortSpec, AgentConversationServeError, AgentConversationServeOutcome,
    install_agent_conversation_port, retire_agent_conversation_port,
};
use paraegox_agent_contracts::control::{
    AgentConversationCancelStateV1, AgentConversationGetStateV1, AgentConversationOpenOutcomeV1,
    AgentConversationWatchBatchV1,
};
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalV1,
};
use paraegox_agent_service::{
    AgentConversationModelProvider, AgentService, AgentServiceConfigV1, AgentServiceError,
};
use paraegox_fabric::{IngressLimitError, IngressLimits};
use paraegox_kernel::digest::Digest32;
use paraegox_runtime_contracts::managed_agent_stack_plan::{
    ManagedAgentProviderSelectionV1, ManagedAgentStackTargetExecutionV1,
    ManagedAgentStackTargetModeV1,
};
use paraegox_runtime_contracts::managed_service::{
    ManagedServiceLifecycleStage, ManagedServiceSpecV1,
};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::managed_fabric_runtime::{
    ManagedFabricBindingMutation, ManagedFabricControlError, ManagedFabricControlHandle,
    ManagedFabricMutationDisposition,
};
use crate::managed_model_runtime::ManagedModelDependencyHandle;
use crate::runtime_agent_provider::{
    RuntimeAgentProviderResolverV1, RuntimeResolvedAgentProviderV1,
};

const OWNER_STARTING: u8 = 1;
const OWNER_READY: u8 = 2;
const OWNER_STOPPING: u8 = 3;
const OWNER_RETIRED: u8 = 4;
const OWNER_FAILED: u8 = 5;
const AGENT_JOURNAL_PREFIX: &str = "managed-agent-service-";
const AGENT_JOURNAL_SUFFIX: &str = "-v1";

/// Fully resolved, already-admitted Runtime inputs for one Agent service.
///
/// No constructor derives values or supplies defaults. A production caller
/// must map every field from the committed Agent-stack successor plus the
/// Runtime-owned state root. The model-provider binding is validated by that
/// consumer before it supplies the concrete provider to `start`.
#[derive(Clone, Debug)]
pub(crate) struct ManagedAgentAssemblyConfig {
    service: ManagedServiceSpecV1,
    agent_service: AgentServiceConfigV1,
    port: AgentConversationPortSpec,
    provider: ManagedAgentProviderSelectionV1,
    runtime_state_root: PathBuf,
}

impl ManagedAgentAssemblyConfig {
    /// Maps every Agent-owned runtime value from one already-admitted PXTE-v6
    /// active execution. The Runtime state root is local installation truth and
    /// is intentionally never accepted from the wire contract.
    pub(crate) fn try_from_execution(
        execution: &ManagedAgentStackTargetExecutionV1,
        runtime_state_root: PathBuf,
    ) -> Result<Self, ManagedAgentAssemblyError> {
        if execution.mode() != ManagedAgentStackTargetModeV1::FabricAndAgent {
            return Err(ManagedAgentAssemblyError::ExpectedActiveExecution);
        }
        let agent = execution
            .agent()
            .ok_or(ManagedAgentAssemblyError::ExpectedActiveExecution)?;
        let service = agent.service();
        if service
            .service_id()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || !runtime_state_root.is_absolute()
        {
            return Err(ManagedAgentAssemblyError::InvalidResolvedInput);
        }
        let semantic = agent.semantic_limits();
        let agent_service = AgentServiceConfigV1::try_new(
            usize::from(semantic.max_sessions()),
            usize::from(semantic.max_turns_per_session()),
            usize::from(semantic.max_requests_per_session()),
            usize::from(semantic.max_event_batch()),
        )?;
        let planned_ingress = agent.port().ingress_limits();
        let ingress = IngressLimits::try_new(
            usize::try_from(planned_ingress.max_items())
                .map_err(|_| ManagedAgentAssemblyError::InvalidResolvedInput)?,
            usize::try_from(planned_ingress.max_bytes())
                .map_err(|_| ManagedAgentAssemblyError::InvalidResolvedInput)?,
            usize::try_from(planned_ingress.max_frame_bytes())
                .map_err(|_| ManagedAgentAssemblyError::InvalidResolvedInput)?,
            usize::try_from(planned_ingress.max_response_body_bytes())
                .map_err(|_| ManagedAgentAssemblyError::InvalidResolvedInput)?,
            Duration::from_nanos(planned_ingress.handler_timeout_nanos()),
        )?;
        let port = AgentConversationPortSpec::try_new(
            agent.port().submit_binding_id(),
            agent.port().control_binding_id(),
            agent.port().submit_key_expression(),
            agent.port().control_key_expression(),
            ingress,
        )
        .map_err(ManagedAgentAssemblyError::PortSpec)?;
        Ok(Self {
            service,
            agent_service,
            port,
            provider: agent.provider(),
            runtime_state_root,
        })
    }

    fn journal_path(&self) -> PathBuf {
        let identity = self.service.service_id();
        let mut name = String::with_capacity(
            AGENT_JOURNAL_PREFIX.len()
                + (identity.as_bytes().len() * 2)
                + AGENT_JOURNAL_SUFFIX.len(),
        );
        name.push_str(AGENT_JOURNAL_PREFIX);
        for byte in identity.as_bytes() {
            use core::fmt::Write as _;
            let _ = write!(name, "{byte:02x}");
        }
        name.push_str(AGENT_JOURNAL_SUFFIX);
        self.runtime_state_root.join(name)
    }

    fn budget(&self, stage: ManagedServiceLifecycleStage) -> Duration {
        Duration::from_nanos(self.service.lifecycle_budgets().for_stage(stage).value())
    }
}

/// Runtime lifecycle owner for one two-lane Agent port, semantic service,
/// provider, and caller-owned server task.
pub(crate) struct ManagedAgentAssembly {
    fabric: ManagedFabricControlHandle,
    port: Option<AgentConversationPort>,
    server: Option<JoinHandle<Result<(), AgentConversationServeError>>>,
    owner_state: Arc<AtomicU8>,
    drain_budget: Duration,
    stop_budget: Duration,
}

impl ManagedAgentAssembly {
    /// Maps and starts the exact admitted fixed Agent execution on an already
    /// live Fabric generation. Provider resolution remains repeatable and the
    /// resolver must echo the complete signed selection.
    pub(crate) async fn start_from_execution(
        fabric: ManagedFabricControlHandle,
        execution: &ManagedAgentStackTargetExecutionV1,
        runtime_state_root: PathBuf,
        provider_resolver: &dyn RuntimeAgentProviderResolverV1,
    ) -> Result<(Self, RuntimeAgentConversationHandle), ManagedAgentAssemblyError> {
        let config = ManagedAgentAssemblyConfig::try_from_execution(execution, runtime_state_root)?;
        let selection = config.provider;
        let resolved = provider_resolver
            .resolve(selection)
            .map_err(|_| ManagedAgentAssemblyError::ProviderResolutionFailed)?;
        Self::start_resolved_provider(fabric, config, resolved).await
    }

    /// Starts one provider only after its resolver repeats the exact signed
    /// selection it resolved. This binds the profile, provider ref,
    /// configuration digest, and optional secret ref without exposing any of
    /// them to the client lease.
    pub(crate) async fn start_resolved_provider(
        fabric: ManagedFabricControlHandle,
        config: ManagedAgentAssemblyConfig,
        provider: RuntimeResolvedAgentProviderV1,
    ) -> Result<(Self, RuntimeAgentConversationHandle), ManagedAgentAssemblyError> {
        if config.provider != provider.selection() {
            return Err(ManagedAgentAssemblyError::ProviderSelectionMismatch);
        }
        Self::start_with_provider(fabric, config, provider).await
    }

    /// Starts the Agent only from the exact Ready Model generation selected by
    /// the fixed managed Model+Agent stack. This path cannot resolve or embed a
    /// second provider: the generation-fenced dependency handle is the sole
    /// semantic provider supplied to the Agent server task.
    pub(crate) async fn start_with_model_dependency(
        fabric: ManagedFabricControlHandle,
        execution: &ManagedAgentStackTargetExecutionV1,
        runtime_state_root: PathBuf,
        expected_model_service_id: paraegox_runtime_contracts::managed_service::ManagedServiceId,
        expected_model_generation: paraegox_runtime_contracts::managed_service::ManagedServiceGeneration,
        provider: ManagedModelDependencyHandle,
    ) -> Result<(Self, RuntimeAgentConversationHandle), ManagedAgentAssemblyError> {
        let config = ManagedAgentAssemblyConfig::try_from_execution(execution, runtime_state_root)?;
        if provider.consumer_agent_service_id() != config.service.service_id()
            || provider.model_service_id() != expected_model_service_id
            || provider.model_generation() != expected_model_generation
        {
            return Err(ManagedAgentAssemblyError::ProviderSelectionMismatch);
        }
        Self::start_with_provider(fabric, config, provider).await
    }

    async fn start_with_provider<P>(
        fabric: ManagedFabricControlHandle,
        config: ManagedAgentAssemblyConfig,
        provider: P,
    ) -> Result<(Self, RuntimeAgentConversationHandle), ManagedAgentAssemblyError>
    where
        P: AgentConversationModelProvider + 'static,
    {
        let owner_state = Arc::new(AtomicU8::new(OWNER_STARTING));
        let prepare_started = Instant::now();
        let service = AgentService::open_durable(config.agent_service, &config.journal_path())?;
        if prepare_started.elapsed() >= config.budget(ManagedServiceLifecycleStage::Prepare) {
            return Err(ManagedAgentAssemblyError::PrepareDeadlineExceeded);
        }

        let port_spec = config.port.clone();
        let start_budget = config.budget(ManagedServiceLifecycleStage::Start);
        let installed = fabric
            .mutate_live_fabric(
                ManagedFabricBindingMutation::InstallNew {
                    physical_bindings: physical_binding_count()?,
                },
                start_budget,
                AgentPortMutationFailure::DeadlineExceeded,
                move |live| {
                    Box::pin(async move {
                        match install_agent_conversation_port(live, &port_spec, None).await {
                            Ok(installed) => ManagedFabricMutationDisposition::Committed(installed),
                            Err(error) => match error.mutation_disposition() {
                                AgentConversationPortMutationDispositionV1::ProvenNoEffect => {
                                    ManagedFabricMutationDisposition::RejectedNoEffect(
                                        AgentPortMutationFailure::Port(error),
                                    )
                                }
                                AgentConversationPortMutationDispositionV1::OutcomeUncertain => {
                                    ManagedFabricMutationDisposition::Uncertain(
                                        AgentPortMutationFailure::Port(error),
                                    )
                                }
                            },
                        }
                    })
                },
            )
            .await?;
        let installed = match installed {
            ManagedFabricMutationDisposition::Committed(installed) => installed,
            ManagedFabricMutationDisposition::RejectedNoEffect(error)
            | ManagedFabricMutationDisposition::RolledBackExact(error) => {
                return Err(error.into());
            }
            ManagedFabricMutationDisposition::Uncertain(error) => {
                owner_state.store(OWNER_FAILED, Ordering::Release);
                return Err(ManagedAgentAssemblyError::PortMutationUncertain(error));
            }
        };
        let (port, endpoint) = installed.into_parts();
        let server_state = Arc::clone(&owner_state);
        let (readiness_sender, readiness_receiver) = oneshot::channel();
        let server = tokio::spawn(async move {
            let _ = readiness_sender.send(());
            let result = drive_server(endpoint, service, provider).await;
            server_state.store(
                if result.is_ok() {
                    OWNER_RETIRED
                } else {
                    OWNER_FAILED
                },
                Ordering::Release,
            );
            result
        });
        let readiness_failure = match timeout(
            config.budget(ManagedServiceLifecycleStage::Readiness),
            readiness_receiver,
        )
        .await
        {
            Ok(Ok(())) => None,
            Ok(Err(_)) => Some(ManagedAgentAssemblyError::ServerStoppedBeforeReady),
            Err(_) => Some(ManagedAgentAssemblyError::ReadinessDeadlineExceeded),
        };
        if let Some(failure) = readiness_failure {
            let cleanup = cleanup_unready_server(
                &fabric,
                &port,
                config.budget(ManagedServiceLifecycleStage::Drain),
                config.budget(ManagedServiceLifecycleStage::Stop),
                server,
            )
            .await;
            owner_state.store(OWNER_FAILED, Ordering::Release);
            cleanup?;
            return Err(failure);
        }
        tokio::task::yield_now().await;
        if server.is_finished() {
            owner_state.store(OWNER_FAILED, Ordering::Release);
            let retirement = retire_port(
                &fabric,
                &port,
                config.budget(ManagedServiceLifecycleStage::Drain),
            )
            .await?;
            match retirement {
                ManagedFabricMutationDisposition::Committed(()) => {}
                ManagedFabricMutationDisposition::RejectedNoEffect(error)
                | ManagedFabricMutationDisposition::RolledBackExact(error) => {
                    return Err(error.into());
                }
                ManagedFabricMutationDisposition::Uncertain(error) => {
                    return Err(ManagedAgentAssemblyError::PortMutationUncertain(error));
                }
            }
            return match server.await {
                Ok(Err(error)) => Err(ManagedAgentAssemblyError::Server(error)),
                Ok(Ok(())) => Err(ManagedAgentAssemblyError::ServerStoppedBeforeReady),
                Err(_) => Err(ManagedAgentAssemblyError::ServerTaskFailed),
            };
        }
        owner_state.store(OWNER_READY, Ordering::Release);
        let handle = RuntimeAgentConversationHandle {
            fabric: fabric.clone(),
            port: port.clone(),
            owner_state: Arc::clone(&owner_state),
            closed: false,
        };
        Ok((
            Self {
                fabric,
                port: Some(port),
                server: Some(server),
                owner_state,
                drain_budget: config.budget(ManagedServiceLifecycleStage::Drain),
                stop_budget: config.budget(ManagedServiceLifecycleStage::Stop),
            },
            handle,
        ))
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), ManagedAgentAssemblyError> {
        self.owner_state.store(OWNER_STOPPING, Ordering::Release);
        if let Some(port) = self.port.as_ref() {
            match retire_port(&self.fabric, port, self.drain_budget).await? {
                ManagedFabricMutationDisposition::Committed(()) => {
                    self.port = None;
                }
                ManagedFabricMutationDisposition::RejectedNoEffect(error)
                | ManagedFabricMutationDisposition::RolledBackExact(error) => {
                    return Err(error.into());
                }
                ManagedFabricMutationDisposition::Uncertain(error) => {
                    self.owner_state.store(OWNER_FAILED, Ordering::Release);
                    return Err(ManagedAgentAssemblyError::PortMutationUncertain(error));
                }
            }
        }
        let Some(mut server) = self.server.take() else {
            self.owner_state.store(OWNER_RETIRED, Ordering::Release);
            return Ok(());
        };
        match timeout(self.stop_budget, &mut server).await {
            Ok(Ok(Ok(()))) => {
                self.owner_state.store(OWNER_RETIRED, Ordering::Release);
                Ok(())
            }
            Ok(Ok(Err(error))) => {
                self.owner_state.store(OWNER_FAILED, Ordering::Release);
                Err(ManagedAgentAssemblyError::Server(error))
            }
            Ok(Err(_)) => {
                self.owner_state.store(OWNER_FAILED, Ordering::Release);
                Err(ManagedAgentAssemblyError::ServerTaskFailed)
            }
            Err(_) => {
                self.server = Some(server);
                Err(ManagedAgentAssemblyError::ServerJoinDeadlineExceeded)
            }
        }
    }

    /// Returns the two exact owner-observed lane descriptor digests while the
    /// installed Agent port is still live.
    pub(crate) fn installed_binding_descriptor_digests(
        &self,
    ) -> Result<(Digest32, Digest32), ManagedAgentAssemblyError> {
        let port = self
            .port
            .as_ref()
            .ok_or(ManagedAgentAssemblyError::InstalledPortUnavailable)?;
        let descriptor = port.export_descriptor_v1()?;
        Ok((
            descriptor.request_binding_descriptor_digest(),
            descriptor.event_binding_descriptor_digest(),
        ))
    }
}

impl Drop for ManagedAgentAssembly {
    fn drop(&mut self) {
        if self.port.is_some() || self.server.is_some() {
            self.owner_state.store(OWNER_FAILED, Ordering::Release);
            if let Some(server) = self.server.as_ref() {
                server.abort();
            }
        }
    }
}

async fn drive_server<P>(
    mut endpoint: crate::managed_agent_transport::AgentConversationServerEndpoint,
    mut service: AgentService,
    mut provider: P,
) -> Result<(), AgentConversationServeError>
where
    P: AgentConversationModelProvider,
{
    loop {
        match endpoint.serve_one(&mut service, &mut provider).await {
            Ok(AgentConversationServeOutcome::PortRetired) => return Ok(()),
            Ok(_) | Err(AgentConversationServeError::ResponseAbandoned) => {}
            Err(error) => return Err(error),
        }
    }
}

async fn retire_port(
    fabric: &ManagedFabricControlHandle,
    port: &AgentConversationPort,
    budget: Duration,
) -> Result<ManagedFabricMutationDisposition<(), AgentPortMutationFailure>, ManagedFabricControlError>
{
    let port = port.clone();
    fabric
        .mutate_live_fabric(
            ManagedFabricBindingMutation::RetireExisting {
                physical_bindings: physical_binding_count()?,
            },
            budget,
            AgentPortMutationFailure::DeadlineExceeded,
            move |live| {
                Box::pin(async move {
                    match retire_agent_conversation_port(live, &port).await {
                        Ok(()) => ManagedFabricMutationDisposition::Committed(()),
                        Err(error) => match error.mutation_disposition() {
                            AgentConversationPortMutationDispositionV1::ProvenNoEffect => {
                                ManagedFabricMutationDisposition::RejectedNoEffect(
                                    AgentPortMutationFailure::Port(error),
                                )
                            }
                            AgentConversationPortMutationDispositionV1::OutcomeUncertain => {
                                ManagedFabricMutationDisposition::Uncertain(
                                    AgentPortMutationFailure::Port(error),
                                )
                            }
                        },
                    }
                })
            },
        )
        .await
}

async fn cleanup_unready_server(
    fabric: &ManagedFabricControlHandle,
    port: &AgentConversationPort,
    drain_budget: Duration,
    stop_budget: Duration,
    mut server: JoinHandle<Result<(), AgentConversationServeError>>,
) -> Result<(), ManagedAgentAssemblyError> {
    let retirement = retire_port(fabric, port, drain_budget).await?;
    match retirement {
        ManagedFabricMutationDisposition::Committed(()) => {}
        ManagedFabricMutationDisposition::RejectedNoEffect(error)
        | ManagedFabricMutationDisposition::RolledBackExact(error) => {
            server.abort();
            let _ = server.await;
            return Err(error.into());
        }
        ManagedFabricMutationDisposition::Uncertain(error) => {
            server.abort();
            let _ = server.await;
            return Err(ManagedAgentAssemblyError::PortMutationUncertain(error));
        }
    }
    match timeout(stop_budget, &mut server).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(ManagedAgentAssemblyError::Server(error)),
        Ok(Err(_)) => Err(ManagedAgentAssemblyError::ServerTaskFailed),
        Err(_) => {
            server.abort();
            let _ = server.await;
            Err(ManagedAgentAssemblyError::ServerJoinDeadlineExceeded)
        }
    }
}

fn physical_binding_count() -> Result<u32, ManagedFabricControlError> {
    u32::try_from(AGENT_CONVERSATION_PORT_PHYSICAL_BINDINGS)
        .ok()
        .filter(|count| *count == 2)
        .ok_or(ManagedFabricControlError::InvalidBindingMutation)
}

/// Cloneable typed client lease backed by the Runtime-owned Fabric generation.
/// Raw Fabric and opaque port values never cross this boundary.
pub struct RuntimeAgentConversationHandle {
    fabric: ManagedFabricControlHandle,
    port: AgentConversationPort,
    owner_state: Arc<AtomicU8>,
    closed: bool,
}

impl Clone for RuntimeAgentConversationHandle {
    fn clone(&self) -> Self {
        Self {
            fabric: self.fabric.clone(),
            port: self.port.clone(),
            owner_state: Arc::clone(&self.owner_state),
            closed: self.closed,
        }
    }
}

impl fmt::Debug for RuntimeAgentConversationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeAgentConversationHandle")
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl RuntimeAgentConversationHandle {
    pub async fn open_session(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        operation_timeout: Duration,
    ) -> Result<AgentConversationOpenOutcomeV1, RuntimeAgentConversationError> {
        self.ensure_ready()?;
        let port = self.port.clone();
        self.fabric
            .with_live_fabric(move |fabric| {
                Box::pin(async move {
                    AgentConversationClient::new(fabric, port)
                        .open_session(deck_run_id, session_id, operation_timeout)
                        .await
                })
            })
            .await
            .map_err(RuntimeAgentConversationError::from_control)?
            .map_err(Into::into)
    }

    pub async fn submit(
        &self,
        request: AgentConversationRequestV1,
        operation_timeout: Duration,
    ) -> Result<AgentConversationTerminalV1, RuntimeAgentConversationError> {
        self.ensure_ready()?;
        let port = self.port.clone();
        self.fabric
            .with_live_fabric(move |fabric| {
                Box::pin(async move {
                    AgentConversationClient::new(fabric, port)
                        .submit(&request, operation_timeout)
                        .await
                })
            })
            .await
            .map_err(RuntimeAgentConversationError::from_control)?
            .map_err(Into::into)
    }

    pub async fn get(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        operation_timeout: Duration,
    ) -> Result<AgentConversationGetStateV1, RuntimeAgentConversationError> {
        self.ensure_ready()?;
        let port = self.port.clone();
        self.fabric
            .with_live_fabric(move |fabric| {
                Box::pin(async move {
                    AgentConversationClient::new(fabric, port)
                        .get(deck_run_id, session_id, request_id, operation_timeout)
                        .await
                })
            })
            .await
            .map_err(RuntimeAgentConversationError::from_control)?
            .map_err(Into::into)
    }

    pub async fn watch(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        cursor: u64,
        limit: u32,
        operation_timeout: Duration,
    ) -> Result<Option<AgentConversationWatchBatchV1>, RuntimeAgentConversationError> {
        self.ensure_ready()?;
        let port = self.port.clone();
        self.fabric
            .with_live_fabric(move |fabric| {
                Box::pin(async move {
                    AgentConversationClient::new(fabric, port)
                        .watch(deck_run_id, session_id, cursor, limit, operation_timeout)
                        .await
                })
            })
            .await
            .map_err(RuntimeAgentConversationError::from_control)?
            .map_err(Into::into)
    }

    pub async fn cancel(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        operation_timeout: Duration,
    ) -> Result<AgentConversationCancelStateV1, RuntimeAgentConversationError> {
        self.ensure_ready()?;
        let port = self.port.clone();
        self.fabric
            .with_live_fabric(move |fabric| {
                Box::pin(async move {
                    AgentConversationClient::new(fabric, port)
                        .cancel(deck_run_id, session_id, request_id, operation_timeout)
                        .await
                })
            })
            .await
            .map_err(RuntimeAgentConversationError::from_control)?
            .map_err(Into::into)
    }

    /// Closes only this client lease. Runtime binding retirement remains the
    /// exclusive responsibility of `ManagedAgentAssembly`.
    pub async fn close(&mut self) -> Result<(), RuntimeAgentConversationError> {
        self.closed = true;
        Ok(())
    }

    fn ensure_ready(&self) -> Result<(), RuntimeAgentConversationError> {
        if self.closed {
            return Err(RuntimeAgentConversationError::Closed);
        }
        match self.owner_state.load(Ordering::Acquire) {
            OWNER_READY => Ok(()),
            OWNER_RETIRED => Err(RuntimeAgentConversationError::OwnerRetired),
            _ => Err(RuntimeAgentConversationError::OwnerUnavailable),
        }
    }
}

#[derive(Debug)]
pub(crate) enum AgentPortMutationFailure {
    DeadlineExceeded,
    Port(AgentConversationPortError),
}

#[derive(Debug)]
pub(crate) enum ManagedAgentAssemblyError {
    ExpectedActiveExecution,
    InvalidResolvedInput,
    ProviderSelectionMismatch,
    ProviderResolutionFailed,
    InstalledPortUnavailable,
    PrepareDeadlineExceeded,
    ReadinessDeadlineExceeded,
    PortMutationRejected(AgentPortMutationFailure),
    PortMutationUncertain(AgentPortMutationFailure),
    ServerStoppedBeforeReady,
    ServerJoinDeadlineExceeded,
    ServerTaskFailed,
    Service(AgentServiceError),
    Ingress(IngressLimitError),
    PortSpec(AgentConversationPortError),
    PortDescriptor(AgentConversationPortDescriptorError),
    FabricControl(ManagedFabricControlError),
    Server(AgentConversationServeError),
}

impl From<AgentPortMutationFailure> for ManagedAgentAssemblyError {
    fn from(value: AgentPortMutationFailure) -> Self {
        Self::PortMutationRejected(value)
    }
}

impl From<AgentServiceError> for ManagedAgentAssemblyError {
    fn from(value: AgentServiceError) -> Self {
        Self::Service(value)
    }
}

impl From<IngressLimitError> for ManagedAgentAssemblyError {
    fn from(value: IngressLimitError) -> Self {
        Self::Ingress(value)
    }
}

impl From<ManagedFabricControlError> for ManagedAgentAssemblyError {
    fn from(value: ManagedFabricControlError) -> Self {
        Self::FabricControl(value)
    }
}

impl From<AgentConversationPortDescriptorError> for ManagedAgentAssemblyError {
    fn from(value: AgentConversationPortDescriptorError) -> Self {
        Self::PortDescriptor(value)
    }
}

impl fmt::Display for ManagedAgentAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "managed Agent assembly failed: {self:?}")
    }
}

impl std::error::Error for ManagedAgentAssemblyError {}

/// Stable Runtime-facing failures for one opaque Agent client lease.
#[derive(Debug)]
pub enum RuntimeAgentConversationError {
    Closed,
    OwnerUnavailable,
    OwnerRetired,
    OperationRejected,
}

impl RuntimeAgentConversationError {
    fn from_control(error: ManagedFabricControlError) -> Self {
        match error {
            ManagedFabricControlError::OwnerRetired
            | ManagedFabricControlError::GenerationFenced => Self::OwnerRetired,
            _ => Self::OwnerUnavailable,
        }
    }
}

impl From<AgentConversationClientError> for RuntimeAgentConversationError {
    fn from(_value: AgentConversationClientError) -> Self {
        Self::OperationRejected
    }
}

impl fmt::Display for RuntimeAgentConversationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("Agent conversation client lease is closed"),
            Self::OwnerUnavailable => {
                formatter.write_str("Agent conversation owner is unavailable")
            }
            Self::OwnerRetired => formatter.write_str("Agent conversation generation is retired"),
            Self::OperationRejected => formatter.write_str("Agent conversation request failed"),
        }
    }
}

impl std::error::Error for RuntimeAgentConversationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Closed
            | Self::OwnerUnavailable
            | Self::OwnerRetired
            | Self::OperationRejected => None,
        }
    }
}
