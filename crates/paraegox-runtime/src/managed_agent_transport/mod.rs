//! Runtime-private typed PXAC adapter over one opaque two-lane Fabric port.
//!
//! This Runtime-private module does not own a Zenoh session: callers supply the sole
//! [`FabricService`] owner. Explicit open is the only operation that may create
//! an Agent Session; get/watch/cancel never do so. Submit kinds `1`/`2` and the
//! additive open/get/watch/cancel kinds `3` to `10` use separate private
//! submit and control bindings. This prevents a pending model operation from
//! head-of-line blocking cancellation and observation. The adapter starts no
//! task, owns no retry policy, and exposes no raw key, Zenoh value, or second
//! lifecycle owner.

#![forbid(unsafe_code)]

use core::{fmt, time::Duration};

use paraegox_agent_contracts::control::{
    AgentConversationCancelStateV1, AgentConversationControlBodyV1, AgentConversationControlError,
    AgentConversationControlV1, AgentConversationGetStateV1, AgentConversationOpenOutcomeV1,
    AgentConversationWatchBatchV1,
};
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationProtocolError, AgentConversationRequestId,
    AgentConversationRequestV1, AgentConversationSessionId, AgentConversationTerminalV1,
};
use paraegox_agent_service::{
    AgentConversationModelOutcomeV1, AgentConversationModelProvider, AgentService,
    AgentServiceAcceptOutcomeV1, AgentServiceError, AgentServiceSubmitOutcomeV1,
};
#[cfg(test)]
use paraegox_fabric::ClientPortBindingV1;
use paraegox_fabric::{
    FabricConfigError, FabricError, FabricService, HandlerResponse, InboundRequest, IngressLimits,
    PortBinding, RequestId as FabricRequestId, RequestReceiver, RequestResponseBindingSpec,
    ResponseStatus,
};
use paraegox_kernel::digest::{Digest32, Digest32Builder};
use paraegox_runtime_contracts::assignment::{BindingId, SchemaRef};

mod port_descriptor;

pub use port_descriptor::AgentConversationPortDescriptorError;

const PXAC_COMMAND_SCHEMA_ID: [u8; 16] = [
    0x50, 0x58, 0x41, 0x43, 0x2d, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x2d, 0x56, 0x31, 0x00,
];
const PXAC_RESULT_SCHEMA_ID: [u8; 16] = [
    0x50, 0x58, 0x41, 0x43, 0x2d, 0x52, 0x45, 0x53, 0x55, 0x4c, 0x54, 0x2d, 0x56, 0x31, 0x00, 0x00,
];
const PXAC_COMMAND_SCHEMA_DIGEST: [u8; 32] = [
    0x33, 0xe4, 0x47, 0x1d, 0x88, 0x93, 0x05, 0x94, 0xf2, 0x3d, 0xa3, 0x99, 0x9c, 0x3d, 0x52, 0x7d,
    0xf1, 0xb2, 0x20, 0x13, 0x3b, 0x40, 0xde, 0x78, 0xdd, 0xbd, 0xa9, 0x17, 0x69, 0xe5, 0x7e, 0x76,
];
const PXAC_RESULT_SCHEMA_DIGEST: [u8; 32] = [
    0x60, 0x13, 0x67, 0xec, 0x50, 0xbf, 0x9e, 0xbc, 0x7b, 0xc7, 0xbb, 0x94, 0xd0, 0x44, 0xc5, 0x4c,
    0x44, 0x06, 0x4b, 0xb9, 0x85, 0x93, 0xb7, 0xfc, 0xea, 0x0b, 0xd0, 0x29, 0x84, 0x4a, 0xd2, 0x64,
];
const CONTROL_FABRIC_REQUEST_ID_DOMAIN: &[u8] =
    b"paraegox.agent.conversation.fabric.request-id.sha256.v1";

/// One logical Agent conversation port always owns two physical Fabric bindings.
pub const AGENT_CONVERSATION_PORT_PHYSICAL_BINDINGS: usize = 2;

fn command_schema() -> SchemaRef {
    SchemaRef::try_new(
        PXAC_COMMAND_SCHEMA_ID,
        1,
        Digest32::from_bytes(PXAC_COMMAND_SCHEMA_DIGEST),
    )
    .expect("fixed PXAC command schema version is nonzero")
}

fn result_schema() -> SchemaRef {
    SchemaRef::try_new(
        PXAC_RESULT_SCHEMA_ID,
        1,
        Digest32::from_bytes(PXAC_RESULT_SCHEMA_DIGEST),
    )
    .expect("fixed PXAC result schema version is nonzero")
}

/// Opaque installed capability for the typed PXAC conversation route.
///
/// The key expression, SchemaRef values, binding epoch, and underlying
/// [`PortBinding`] remain adapter-private. A prior value can only be supplied
/// as an exact-CAS token to replacement or used by an already constructed
/// typed client.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentConversationPort {
    submit_binding: PortBinding,
    control_binding: PortBinding,
}

/// Descriptor-recoverable, request-only two-lane Agent route.
///
/// Unlike [`AgentConversationPort`], this value is never accepted by install,
/// exact-CAS replacement, or retirement. It carries no Agent or Fabric
/// lifecycle authority and exposes no raw route outside this adapter.
#[derive(Clone, Eq, PartialEq)]
#[cfg(test)]
pub struct AgentConversationClientPortV1 {
    submit_binding: ClientPortBindingV1,
    control_binding: ClientPortBindingV1,
}

/// Fully validated inputs for one opaque two-lane conversation port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentConversationPortSpec {
    submit_binding_id: BindingId,
    control_binding_id: BindingId,
    submit_key_expression: String,
    control_key_expression: String,
    ingress_limits: IngressLimits,
}

impl AgentConversationPortSpec {
    /// Validates both lane configurations before the first Fabric mutation.
    pub fn try_new(
        submit_binding_id: BindingId,
        control_binding_id: BindingId,
        submit_key_expression: impl Into<String>,
        control_key_expression: impl Into<String>,
        ingress_limits: IngressLimits,
    ) -> Result<Self, AgentConversationPortError> {
        if submit_binding_id == control_binding_id {
            return Err(AgentConversationPortError::DuplicateBindingId);
        }
        let submit_key_expression = submit_key_expression.into();
        let control_key_expression = control_key_expression.into();
        if submit_key_expression == control_key_expression {
            return Err(AgentConversationPortError::DuplicateKeyExpression);
        }
        RequestResponseBindingSpec::try_new(
            submit_binding_id,
            None,
            submit_key_expression.clone(),
            command_schema(),
            result_schema(),
            ingress_limits,
        )?;
        RequestResponseBindingSpec::try_new(
            control_binding_id,
            None,
            control_key_expression.clone(),
            command_schema(),
            result_schema(),
            ingress_limits,
        )?;
        Ok(Self {
            submit_binding_id,
            control_binding_id,
            submit_key_expression,
            control_key_expression,
            ingress_limits,
        })
    }

    fn binding_specs(
        &self,
        expected_active: Option<&AgentConversationPort>,
    ) -> Result<(RequestResponseBindingSpec, RequestResponseBindingSpec), AgentConversationPortError>
    {
        let (expected_submit_epoch, expected_control_epoch) = match expected_active {
            Some(expected)
                if expected.submit_binding.binding_id() == self.submit_binding_id
                    && expected.control_binding.binding_id() == self.control_binding_id =>
            {
                (
                    Some(expected.submit_binding.binding_epoch()),
                    Some(expected.control_binding.binding_epoch()),
                )
            }
            Some(_) => return Err(AgentConversationPortError::ExpectedPortMismatch),
            None => (None, None),
        };
        let submit = RequestResponseBindingSpec::try_new(
            self.submit_binding_id,
            expected_submit_epoch,
            self.submit_key_expression.clone(),
            command_schema(),
            result_schema(),
            self.ingress_limits,
        )?;
        let control = RequestResponseBindingSpec::try_new(
            self.control_binding_id,
            expected_control_epoch,
            self.control_key_expression.clone(),
            command_schema(),
            result_schema(),
            self.ingress_limits,
        )?;
        Ok((submit, control))
    }
}

impl fmt::Debug for AgentConversationPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgentConversationPort { .. }")
    }
}

#[cfg(test)]
impl fmt::Debug for AgentConversationClientPortV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgentConversationClientPortV1 { .. }")
    }
}

/// Installed opaque route and its only server-side request consumer.
pub struct InstalledAgentConversationPort {
    port: AgentConversationPort,
    endpoint: AgentConversationServerEndpoint,
}

impl InstalledAgentConversationPort {
    /// Transfers the opaque client capability and the sole server receiver.
    #[must_use]
    pub fn into_parts(self) -> (AgentConversationPort, AgentConversationServerEndpoint) {
        (self.port, self.endpoint)
    }
}

/// Installs or exact-CAS replaces the typed PXAC conversation adapter route.
///
/// `expected_active` must be the last live opaque capability for `binding_id`.
/// Passing `None` means that no active generation is expected. The function
/// creates no Session and starts no background task.
pub async fn install_agent_conversation_port(
    fabric: &mut FabricService,
    spec: &AgentConversationPortSpec,
    expected_active: Option<&AgentConversationPort>,
) -> Result<InstalledAgentConversationPort, AgentConversationPortError> {
    let replacement = expected_active.is_some();
    let (submit_spec, control_spec) = spec.binding_specs(expected_active)?;
    let submit_installed = fabric
        .install_request_response_binding(submit_spec)
        .await
        .map_err(|primary| AgentConversationPortError::FabricMutation {
            primary,
            cleanup: None,
            disposition: if replacement {
                AgentConversationPortMutationDispositionV1::OutcomeUncertain
            } else {
                AgentConversationPortMutationDispositionV1::ProvenNoEffect
            },
        })?;
    let (submit_binding, submit_receiver) = submit_installed.into_parts();
    let control_installed = match fabric.install_request_response_binding(control_spec).await {
        Ok(installed) => installed,
        Err(primary) => {
            let cleanup = fabric.retire_port_binding(&submit_binding).await.err();
            let disposition = if !replacement && cleanup.is_none() {
                AgentConversationPortMutationDispositionV1::ProvenNoEffect
            } else {
                AgentConversationPortMutationDispositionV1::OutcomeUncertain
            };
            return Err(AgentConversationPortError::FabricMutation {
                primary,
                cleanup,
                disposition,
            });
        }
    };
    let (control_binding, control_receiver) = control_installed.into_parts();
    Ok(InstalledAgentConversationPort {
        port: AgentConversationPort {
            submit_binding,
            control_binding,
        },
        endpoint: AgentConversationServerEndpoint {
            submit_receiver,
            control_receiver,
            submit_open: true,
            control_open: true,
        },
    })
}

/// Retires both exact private lanes and joins both Fabric workers.
pub async fn retire_agent_conversation_port(
    fabric: &mut FabricService,
    port: &AgentConversationPort,
) -> Result<(), AgentConversationPortError> {
    let submit_error = fabric.retire_port_binding(&port.submit_binding).await.err();
    let control_error = fabric
        .retire_port_binding(&port.control_binding)
        .await
        .err();
    match (submit_error, control_error) {
        (None, None) => Ok(()),
        (Some(primary), cleanup) => Err(AgentConversationPortError::FabricMutation {
            primary,
            cleanup,
            disposition: AgentConversationPortMutationDispositionV1::OutcomeUncertain,
        }),
        (None, Some(primary)) => Err(AgentConversationPortError::FabricMutation {
            primary,
            cleanup: None,
            disposition: AgentConversationPortMutationDispositionV1::OutcomeUncertain,
        }),
    }
}

/// Server-side outcome of one caller-driven receive/submit/respond step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentConversationServeOutcome {
    TerminalCommitted,
    TerminalReplay,
    SemanticRejected,
    ControlHandled,
    MalformedRequest(AgentConversationProtocolError),
    MalformedControl(AgentConversationControlError),
    ServiceRejected(AgentServiceError),
    PortRetired,
}

/// Sole server-side consumer for one installed binding generation.
///
/// `serve_one` is caller-driven and creates no unmanaged task. Explicit open
/// may create a DeckRun-bound Session; no other operation does so.
pub struct AgentConversationServerEndpoint {
    submit_receiver: RequestReceiver,
    control_receiver: RequestReceiver,
    submit_open: bool,
    control_open: bool,
}

impl AgentConversationServerEndpoint {
    /// Drives one submit to completion or handles one idle control request.
    ///
    /// While a provider future is pending, this method continues servicing the
    /// private control lane. One endpoint permits at most one handed-off model
    /// invocation at a time. If the submit worker delivers another request
    /// after the first requester's handler budget expires, that extra request
    /// is explicitly rejected before AgentService acceptance. A future bounded
    /// concurrent actor profile requires a separate admission design.
    /// This method creates no task and performs no retry.
    pub async fn serve_one<P>(
        &mut self,
        service: &mut AgentService,
        provider: &mut P,
    ) -> Result<AgentConversationServeOutcome, AgentConversationServeError>
    where
        P: AgentConversationModelProvider,
    {
        loop {
            if !self.submit_open && !self.control_open {
                return Ok(AgentConversationServeOutcome::PortRetired);
            }
            tokio::select! {
                control = self.control_receiver.recv(), if self.control_open => {
                    let Some(inbound) = control else {
                        self.control_open = false;
                        continue;
                    };
                    return handle_control_inbound(service, inbound);
                }
                submit = self.submit_receiver.recv(), if self.submit_open => {
                    let Some(inbound) = submit else {
                        self.submit_open = false;
                        continue;
                    };
                    return self.handle_submit(service, provider, inbound).await;
                }
            }
        }
    }

    async fn handle_submit<P>(
        &mut self,
        service: &mut AgentService,
        provider: &mut P,
        inbound: InboundRequest,
    ) -> Result<AgentConversationServeOutcome, AgentConversationServeError>
    where
        P: AgentConversationModelProvider,
    {
        let request = match AgentConversationRequestV1::decode(inbound.body()) {
            Ok(request) => request,
            Err(error) => {
                inbound
                    .respond(HandlerResponse::Rejected(Vec::new()))
                    .map_err(|_| AgentConversationServeError::ResponseAbandoned)?;
                return Ok(AgentConversationServeOutcome::MalformedRequest(error));
            }
        };
        let deck_run_id = request.deck_run_id();
        let session_id = request.session_id();
        let request_id = request.request_id();
        let accepted = match service.accept_request(request) {
            Ok(outcome) => outcome,
            Err(error) => {
                inbound
                    .respond(HandlerResponse::Rejected(Vec::new()))
                    .map_err(|_| AgentConversationServeError::ResponseAbandoned)?;
                return Ok(AgentConversationServeOutcome::ServiceRejected(error));
            }
        };
        let (invocation, mut provider_future) = match accepted {
            AgentServiceAcceptOutcomeV1::Accepted => {
                let invocation = match service.begin_execution(deck_run_id, session_id, request_id)
                {
                    Ok(invocation) => invocation,
                    Err(error) => {
                        inbound
                            .respond(HandlerResponse::Rejected(Vec::new()))
                            .map_err(|_| AgentConversationServeError::ResponseAbandoned)?;
                        return Ok(AgentConversationServeOutcome::ServiceRejected(error));
                    }
                };
                let provider_future =
                    provider.complete(invocation.request().clone(), invocation.cancellation());
                (invocation, provider_future)
            }
            AgentServiceAcceptOutcomeV1::PendingReplay => {
                inbound
                    .respond(HandlerResponse::Rejected(Vec::new()))
                    .map_err(|_| AgentConversationServeError::ResponseAbandoned)?;
                return Ok(AgentConversationServeOutcome::ServiceRejected(
                    AgentServiceError::DurableRecoveryRequired,
                ));
            }
            AgentServiceAcceptOutcomeV1::TerminalReplay(terminal) => {
                respond_terminal(inbound, &terminal)?;
                return Ok(AgentConversationServeOutcome::TerminalReplay);
            }
            AgentServiceAcceptOutcomeV1::Rejected(terminal) => {
                respond_terminal(inbound, &terminal)?;
                return Ok(AgentConversationServeOutcome::SemanticRejected);
            }
        };

        loop {
            if !self.submit_open && !self.control_open {
                service
                    .complete_execution(
                        invocation,
                        AgentConversationModelOutcomeV1::OutcomeUncertain,
                    )
                    .map_err(AgentConversationServeError::GracefulSettlementFailed)?;
                return Ok(AgentConversationServeOutcome::PortRetired);
            }
            tokio::select! {
                outcome = provider_future.as_mut() => {
                    let outcome = service
                        .complete_execution(invocation, outcome)
                        .map_err(AgentConversationServeError::GracefulSettlementFailed)?;
                    let AgentServiceSubmitOutcomeV1::TerminalCommitted(terminal) = outcome else {
                        unreachable!("linear invocation can only commit one new terminal");
                    };
                    respond_terminal(inbound, &terminal)?;
                    return Ok(AgentConversationServeOutcome::TerminalCommitted);
                }
                control = self.control_receiver.recv(), if self.control_open => {
                    match control {
                        Some(control) => {
                            // A timed-out control requester cannot be allowed to
                            // drop the already handed-off model invocation.
                            let _ = handle_control_inbound(service, control);
                        }
                        None => self.control_open = false,
                    }
                }
                submit = self.submit_receiver.recv(), if self.submit_open => {
                    match submit {
                        Some(unexpected) => {
                            let _ = unexpected.respond(HandlerResponse::Rejected(Vec::new()));
                        }
                        None => self.submit_open = false,
                    }
                }
            }
        }
    }
}

fn handle_control_inbound(
    service: &mut AgentService,
    inbound: InboundRequest,
) -> Result<AgentConversationServeOutcome, AgentConversationServeError> {
    let control = match AgentConversationControlV1::decode(inbound.body()) {
        Ok(control) => control,
        Err(error) => {
            inbound
                .respond(HandlerResponse::Rejected(Vec::new()))
                .map_err(|_| AgentConversationServeError::ResponseAbandoned)?;
            return Ok(AgentConversationServeOutcome::MalformedControl(error));
        }
    };
    let response = match service.handle_control(&control) {
        Ok(response) => response,
        Err(error) => {
            inbound
                .respond(HandlerResponse::Rejected(Vec::new()))
                .map_err(|_| AgentConversationServeError::ResponseAbandoned)?;
            return Ok(AgentConversationServeOutcome::ServiceRejected(error));
        }
    };
    let response_wire = match response.canonical_wire() {
        Ok(wire) => wire,
        Err(error) => {
            inbound
                .respond(HandlerResponse::Rejected(Vec::new()))
                .map_err(|_| AgentConversationServeError::ResponseAbandoned)?;
            return Ok(AgentConversationServeOutcome::ServiceRejected(error.into()));
        }
    };
    inbound
        .respond(HandlerResponse::Ok(response_wire.into_vec()))
        .map_err(|_| AgentConversationServeError::ResponseAbandoned)?;
    Ok(AgentConversationServeOutcome::ControlHandled)
}

fn respond_terminal(
    inbound: InboundRequest,
    terminal: &AgentConversationTerminalV1,
) -> Result<(), AgentConversationServeError> {
    inbound
        .respond(HandlerResponse::Ok(terminal.canonical_wire().into_vec()))
        .map_err(|_| AgentConversationServeError::ResponseAbandoned)
}

/// Typed no-retry client for submit and explicit conversation controls.
pub struct AgentConversationClient<'fabric> {
    fabric: &'fabric FabricService,
    port: AgentConversationClientRouteV1,
}

enum AgentConversationClientRouteV1 {
    Owner(AgentConversationPort),
    #[cfg(test)]
    Recovered(AgentConversationClientPortV1),
}

impl<'fabric> AgentConversationClient<'fabric> {
    /// Binds a Fabric owner reference to one opaque Agent conversation port.
    #[must_use]
    pub fn new(fabric: &'fabric FabricService, port: AgentConversationPort) -> Self {
        Self {
            fabric,
            port: AgentConversationClientRouteV1::Owner(port),
        }
    }

    /// Binds a Fabric owner reference to a descriptor-recovered request route.
    #[must_use]
    #[cfg(test)]
    pub fn from_client_port_v1(
        fabric: &'fabric FabricService,
        port: AgentConversationClientPortV1,
    ) -> Self {
        Self {
            fabric,
            port: AgentConversationClientRouteV1::Recovered(port),
        }
    }

    /// Sends one canonical PXAC request exactly once and validates its terminal.
    ///
    /// Neither Fabric-level nor semantic failures are retried. `timeout` is
    /// only the outer request budget; the canonical PXAC receiver budget stays
    /// in `request.deadline_budget_nanos()`.
    pub async fn submit(
        &self,
        request: &AgentConversationRequestV1,
        timeout: Duration,
    ) -> Result<AgentConversationTerminalV1, AgentConversationClientError> {
        let fabric_request_id = FabricRequestId::try_from_bytes(*request.request_id().as_bytes())?;
        let body = request.canonical_wire().into_vec();
        let response = match &self.port {
            AgentConversationClientRouteV1::Owner(port) => {
                self.fabric
                    .request(&port.submit_binding, fabric_request_id, body, timeout)
                    .await
            }
            #[cfg(test)]
            AgentConversationClientRouteV1::Recovered(port) => {
                self.fabric
                    .request_client_v1(&port.submit_binding, fabric_request_id, body, timeout)
                    .await
            }
        }
        .map_err(AgentConversationClientError::from_fabric)?;
        match response.status() {
            ResponseStatus::Ok => {
                let terminal = AgentConversationTerminalV1::decode(response.body())?;
                if !terminal.correlates(request) {
                    return Err(AgentConversationClientError::TerminalCorrelationMismatch);
                }
                Ok(terminal)
            }
            ResponseStatus::MalformedRequest => {
                Err(AgentConversationClientError::FabricEnvelopeMalformed)
            }
            ResponseStatus::StaleBinding => Err(AgentConversationClientError::StalePort),
            ResponseStatus::IngressOverloaded => {
                Err(AgentConversationClientError::IngressOverloaded)
            }
            ResponseStatus::HandlerUnavailable => {
                Err(AgentConversationClientError::HandlerUnavailable)
            }
            ResponseStatus::HandlerTimeout => Err(AgentConversationClientError::HandlerTimeout),
            ResponseStatus::HandlerRejected => Err(AgentConversationClientError::RequestRejected),
            ResponseStatus::ResponseTooLarge => Err(AgentConversationClientError::ResponseTooLarge),
        }
    }

    /// Explicitly opens one DeckRun-bound Session.
    pub async fn open_session(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        timeout: Duration,
    ) -> Result<AgentConversationOpenOutcomeV1, AgentConversationClientError> {
        let request = AgentConversationControlV1::open_request(deck_run_id, session_id);
        let response = self.send_control(&request, timeout).await?;
        match response.body() {
            AgentConversationControlBodyV1::OpenResult(outcome) => Ok(*outcome),
            _ => Err(AgentConversationClientError::ControlResponseKindMismatch),
        }
    }

    /// Gets the exact terminal, pending state, or not-found result for a request.
    pub async fn get(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        timeout: Duration,
    ) -> Result<AgentConversationGetStateV1, AgentConversationClientError> {
        let request = AgentConversationControlV1::get_request(deck_run_id, session_id, request_id);
        let response = self.send_control(&request, timeout).await?;
        match response.body() {
            AgentConversationControlBodyV1::GetResult(state) => Ok(state.clone()),
            _ => Err(AgentConversationClientError::ControlResponseKindMismatch),
        }
    }

    /// Fetches one finite event batch. `None` means the Session is not found.
    pub async fn watch(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        cursor: u64,
        limit: u32,
        timeout: Duration,
    ) -> Result<Option<AgentConversationWatchBatchV1>, AgentConversationClientError> {
        let request =
            AgentConversationControlV1::watch_request(deck_run_id, session_id, cursor, limit)?;
        let response = self.send_control(&request, timeout).await?;
        match response.body() {
            AgentConversationControlBodyV1::WatchResultNotFound => Ok(None),
            AgentConversationControlBodyV1::WatchResult(batch) => {
                batch.validate_for_request(cursor, limit)?;
                Ok(Some(batch.clone()))
            }
            _ => Err(AgentConversationClientError::ControlResponseKindMismatch),
        }
    }

    /// Records explicit cancellation intent for one request.
    pub async fn cancel(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        timeout: Duration,
    ) -> Result<AgentConversationCancelStateV1, AgentConversationClientError> {
        let request =
            AgentConversationControlV1::cancel_request(deck_run_id, session_id, request_id);
        let response = self.send_control(&request, timeout).await?;
        match response.body() {
            AgentConversationControlBodyV1::CancelResult(state) => Ok(state.clone()),
            _ => Err(AgentConversationClientError::ControlResponseKindMismatch),
        }
    }

    async fn send_control(
        &self,
        request: &AgentConversationControlV1,
        timeout: Duration,
    ) -> Result<AgentConversationControlV1, AgentConversationClientError> {
        let wire = request.canonical_wire()?;
        let fabric_request_id = control_fabric_request_id(&wire)?;
        let body = wire.into_vec();
        let response = match &self.port {
            AgentConversationClientRouteV1::Owner(port) => {
                self.fabric
                    .request(&port.control_binding, fabric_request_id, body, timeout)
                    .await
            }
            #[cfg(test)]
            AgentConversationClientRouteV1::Recovered(port) => {
                self.fabric
                    .request_client_v1(&port.control_binding, fabric_request_id, body, timeout)
                    .await
            }
        }
        .map_err(AgentConversationClientError::from_fabric)?;
        if response.status() != ResponseStatus::Ok {
            return Err(client_error_for_status(response.status()));
        }
        let control = AgentConversationControlV1::decode(response.body())?;
        if control.deck_run_id() != request.deck_run_id()
            || control.session_id() != request.session_id()
            || control.request_id() != request.request_id()
        {
            return Err(AgentConversationClientError::ControlResponseCorrelationMismatch);
        }
        Ok(control)
    }
}

fn control_fabric_request_id(wire: &[u8]) -> Result<FabricRequestId, AgentConversationClientError> {
    // This is an adapter-local correlation identity, not the semantic PXAC
    // RequestId. Hashing the complete canonical control frame distinguishes
    // kind, cursor, limit, and target request without exposing any raw route.
    let mut builder = Digest32Builder::try_new(CONTROL_FABRIC_REQUEST_ID_DOMAIN)
        .map_err(|_| AgentConversationClientError::ControlTransportIdentityInvalid)?;
    builder
        .field_bytes(wire)
        .map_err(|_| AgentConversationClientError::ControlTransportIdentityInvalid)?;
    let digest = builder.finish();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest.as_bytes()[..16]);
    if request_id.iter().all(|byte| *byte == 0) {
        return Err(AgentConversationClientError::ControlTransportIdentityInvalid);
    }
    FabricRequestId::try_from_bytes(request_id)
        .map_err(|_| AgentConversationClientError::ControlTransportIdentityInvalid)
}

fn client_error_for_status(status: ResponseStatus) -> AgentConversationClientError {
    match status {
        ResponseStatus::Ok => AgentConversationClientError::ControlResponseKindMismatch,
        ResponseStatus::MalformedRequest => AgentConversationClientError::FabricEnvelopeMalformed,
        ResponseStatus::StaleBinding => AgentConversationClientError::StalePort,
        ResponseStatus::IngressOverloaded => AgentConversationClientError::IngressOverloaded,
        ResponseStatus::HandlerUnavailable => AgentConversationClientError::HandlerUnavailable,
        ResponseStatus::HandlerTimeout => AgentConversationClientError::HandlerTimeout,
        ResponseStatus::HandlerRejected => AgentConversationClientError::RequestRejected,
        ResponseStatus::ResponseTooLarge => AgentConversationClientError::ResponseTooLarge,
    }
}

/// State proof attached to a failed two-lane port mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentConversationPortMutationDispositionV1 {
    /// The requested logical port mutation is proven to have no effect.
    ProvenNoEffect,
    /// The exact two-lane physical state cannot be proven after the failure.
    OutcomeUncertain,
}

/// Install or retirement failure for the opaque Agent conversation port.
#[derive(Debug)]
pub enum AgentConversationPortError {
    ExpectedPortMismatch,
    DuplicateBindingId,
    DuplicateKeyExpression,
    Config(FabricConfigError),
    FabricMutation {
        primary: FabricError,
        cleanup: Option<FabricError>,
        disposition: AgentConversationPortMutationDispositionV1,
    },
}

impl AgentConversationPortError {
    /// Returns the only state claim callers may make after this failure.
    #[must_use]
    pub const fn mutation_disposition(&self) -> AgentConversationPortMutationDispositionV1 {
        match self {
            Self::ExpectedPortMismatch
            | Self::DuplicateBindingId
            | Self::DuplicateKeyExpression
            | Self::Config(_) => AgentConversationPortMutationDispositionV1::ProvenNoEffect,
            Self::FabricMutation { disposition, .. } => *disposition,
        }
    }
}

impl From<FabricConfigError> for AgentConversationPortError {
    fn from(value: FabricConfigError) -> Self {
        Self::Config(value)
    }
}

impl fmt::Display for AgentConversationPortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedPortMismatch => {
                formatter.write_str("expected Agent conversation port does not match binding")
            }
            Self::DuplicateBindingId => {
                formatter.write_str("Agent conversation submit and control BindingIds must differ")
            }
            Self::DuplicateKeyExpression => formatter
                .write_str("Agent conversation submit and control key expressions must differ"),
            Self::Config(error) => write!(formatter, "Agent conversation port is invalid: {error}"),
            Self::FabricMutation {
                primary,
                cleanup,
                disposition,
            } => write!(
                formatter,
                "Agent conversation port mutation failed: primary={primary}, cleanup={cleanup:?}, disposition={disposition:?}"
            ),
        }
    }
}

impl std::error::Error for AgentConversationPortError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ExpectedPortMismatch
            | Self::DuplicateBindingId
            | Self::DuplicateKeyExpression => None,
            Self::Config(error) => Some(error),
            Self::FabricMutation { primary, .. } => Some(primary),
        }
    }
}

/// Failure of the caller-driven server step after a request was delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentConversationServeError {
    /// The requester left before the already-computed response was delivered.
    ResponseAbandoned,
    /// Graceful retirement could not durably settle a handed-off invocation.
    GracefulSettlementFailed(AgentServiceError),
}

impl fmt::Display for AgentConversationServeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResponseAbandoned => {
                formatter.write_str("Agent conversation requester abandoned its response")
            }
            Self::GracefulSettlementFailed(error) => {
                write!(
                    formatter,
                    "Agent conversation graceful settlement failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for AgentConversationServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ResponseAbandoned => None,
            Self::GracefulSettlementFailed(error) => Some(error),
        }
    }
}

/// Stable typed client failures. Raw Zenoh errors never cross this boundary.
#[derive(Debug)]
pub enum AgentConversationClientError {
    RequestTimedOut,
    FabricEnvelopeMalformed,
    StalePort,
    IngressOverloaded,
    HandlerUnavailable,
    HandlerTimeout,
    RequestRejected,
    ResponseTooLarge,
    TerminalCorrelationMismatch,
    ControlResponseCorrelationMismatch,
    ControlResponseKindMismatch,
    ControlTransportIdentityInvalid,
    FabricContract(paraegox_fabric::FabricContractError),
    Protocol(AgentConversationProtocolError),
    Control(AgentConversationControlError),
    Fabric(FabricError),
}

impl AgentConversationClientError {
    fn from_fabric(error: FabricError) -> Self {
        match error {
            FabricError::RequestTimedOut => Self::RequestTimedOut,
            other => Self::Fabric(other),
        }
    }
}

impl From<paraegox_fabric::FabricContractError> for AgentConversationClientError {
    fn from(value: paraegox_fabric::FabricContractError) -> Self {
        Self::FabricContract(value)
    }
}

impl From<AgentConversationProtocolError> for AgentConversationClientError {
    fn from(value: AgentConversationProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<AgentConversationControlError> for AgentConversationClientError {
    fn from(value: AgentConversationControlError) -> Self {
        Self::Control(value)
    }
}

impl fmt::Display for AgentConversationClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FabricContract(error) => {
                write!(formatter, "Fabric request identity failed: {error}")
            }
            Self::Protocol(error) => write!(formatter, "PXAC terminal failed validation: {error}"),
            Self::Control(error) => write!(formatter, "PXAC control failed validation: {error}"),
            Self::Fabric(error) => write!(formatter, "Fabric request failed: {error}"),
            other => formatter.write_str(match other {
                Self::RequestTimedOut => "Agent conversation request timed out",
                Self::FabricEnvelopeMalformed => "Fabric rejected the outer request envelope",
                Self::StalePort => "Agent conversation port generation is stale",
                Self::IngressOverloaded => "Agent conversation ingress is overloaded",
                Self::HandlerUnavailable => "Agent conversation handler is unavailable",
                Self::HandlerTimeout => "Agent conversation handler timed out",
                Self::RequestRejected => "Agent conversation request was rejected",
                Self::ResponseTooLarge => "Agent conversation terminal exceeded its port bound",
                Self::TerminalCorrelationMismatch => {
                    "PXAC terminal does not correlate to the exact request"
                }
                Self::ControlResponseCorrelationMismatch => {
                    "PXAC control response does not correlate to the exact request"
                }
                Self::ControlResponseKindMismatch => {
                    "PXAC control response kind does not match the request"
                }
                Self::ControlTransportIdentityInvalid => {
                    "PXAC control frame cannot produce a Fabric request identity"
                }
                Self::FabricContract(_)
                | Self::Protocol(_)
                | Self::Control(_)
                | Self::Fabric(_) => unreachable!(),
            }),
        }
    }
}

impl std::error::Error for AgentConversationClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FabricContract(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Control(error) => Some(error),
            Self::Fabric(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
