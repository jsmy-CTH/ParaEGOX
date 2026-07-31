//! Concrete single-instance ProcessDomain owner for the first local profile.
//!
//! The reference executable profile is intentionally narrow: one signed
//! ProcessDomain maps to one CardInstance and one concurrently executing
//! invocation. Wider desired values remain valid contracts but are rejected by
//! this owner until a correspondingly bounded implementation exists.

use core::fmt;
use core::time::Duration;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use paraegox_kernel::digest::Digest32;
use paraegox_runtime_contracts::assignment::InstanceRef;
use paraegox_runtime_contracts::process_execution::{
    ProcessDomainSpec, ProcessMailboxExecutionSpec, ProcessResourceLimits, SideEffectClass,
};
use paraegox_runtime_contracts::process_protocol::{
    ConstructOutcome, InvocationTerminalKind, PROCESS_WORKER_PROTOCOL_VERSION, ProcessFrameBody,
    ProcessFrameKind, ProcessProtocolPhase, ProcessSessionGenerations, ProcessSessionIdentity,
    ProcessWorkerState, StopReason, StoppedOutcome,
};
use tokio::time::{sleep, timeout};

use crate::card_instance::{InstanceGeneration, InvocationId};
use crate::liveness::{LivenessError, LivenessFailure, LivenessPhase, ProcessLivenessState};
use crate::process_platform::{ProcessPlatformError, ResolvedProcessProgram};
use crate::process_transport::{
    ProcessTransport, ProcessTransportError, ReceivedProcessFrame, ReceivedTerminal,
};
use crate::process_workspace::{ProcessWorkspace, ProcessWorkspaceError};
use crate::recovery::{
    ProcessInvocationFailure, ProcessOwnerInvariantFailure, ProcessProtocolFailure,
    ProcessResourceFailure, RecoveryAction, RecoveryActionOutcome, RecoveryDecision,
    RecoveryEngine, RecoveryError, RecoveryPhase, RecoveryState, RuntimeFailureFact,
    RuntimeFailureFactKind,
};
use crate::runtime_clock::{RuntimeClock, RuntimeClockError};
use crate::runtime_ownership::{
    ProcessAdmissionFence, ProcessAdmissionGate, ProcessCleanupAuthority, ProcessCleanupCensus,
    ProcessCleanupProof, ProcessDomainOwnership, ProcessGenerationIdentity,
    ProcessInstanceOwnership, ProcessInvocationOwnership, ProcessInvocationOwnershipStage,
    ProcessLossObservation, ProcessOwnershipLifecycle, ProcessOwnershipLimits,
    RuntimeOwnershipError,
};

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(1);
const PROCESS_DROP_SYNC_REAP_BUDGET: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessDomainPhase {
    Starting,
    Running,
    Draining,
    Recovering,
    Stopped,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessDomainMonitorEvent {
    Heartbeat,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveProcessInvocation {
    invocation: InvocationId,
    credit_id: u64,
    stage: ProcessInvocationOwnershipStage,
    side_effect: SideEffectClass,
    ipc_credit_held: bool,
    retained_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedProcessTerminal {
    invocation: InvocationId,
    side_effect: SideEffectClass,
    retained_bytes: u64,
}

/// Immutable launch inputs resolved by the RuntimeHost for one exact desired
/// process and instance generation.
#[derive(Debug)]
pub(crate) struct ProcessDomainStart {
    desired: ProcessDomainSpec,
    execution: ProcessMailboxExecutionSpec,
    identity: ProcessGenerationIdentity,
    instance_generation: InstanceGeneration,
    program: ResolvedProcessProgram,
    workspace_root: PathBuf,
    artifact_digest: Digest32,
    config_digest: Digest32,
    clock: RuntimeClock,
}

/// Sole owner of one child process group, protocol session, liveness state,
/// recovery ledger, and generation-specific workspace.
#[derive(Debug)]
pub(crate) struct ProcessDomain {
    desired: ProcessDomainSpec,
    execution: ProcessMailboxExecutionSpec,
    identity: ProcessGenerationIdentity,
    instance_generation: InstanceGeneration,
    program: ResolvedProcessProgram,
    workspace_root: PathBuf,
    artifact_digest: Digest32,
    config_digest: Digest32,
    transport: Option<ProcessTransport>,
    workspace: Option<ProcessWorkspace>,
    workspace_path: PathBuf,
    liveness: ProcessLivenessState,
    recovery: RecoveryState,
    admission_gate: Option<ProcessAdmissionGate>,
    admission_fence: Option<ProcessAdmissionFence>,
    cleanup_authority: Option<ProcessCleanupAuthority>,
    next_invocation_id: u64,
    next_credit_id: u64,
    active_invocation: Option<ActiveProcessInvocation>,
    retained_terminal: Option<RetainedProcessTerminal>,
    next_recovery_fact_sequence: u64,
    shutdown_expected_loss: Option<bool>,
    clock: RuntimeClock,
    phase: ProcessDomainPhase,
}

impl ProcessDomain {
    /// Spawns and completes Start/Ready plus Construct/Constructed under one
    /// total signed startup budget. This establishes liveness only; it does not
    /// publish P2e deployment readiness.
    pub(crate) async fn start(start: ProcessDomainStart) -> Result<Self, ProcessDomainError> {
        validate_start(&start)?;
        let observed_at = start.clock.reading()?;
        let mut liveness =
            ProcessLivenessState::try_new(start.identity, start.desired.lifecycle(), observed_at)?;
        let recovery = RecoveryState::try_new(
            start.identity,
            start.desired.lifecycle(),
            start.desired.restart(),
            start.execution.requirements().replay_policy(),
            observed_at,
        )?;
        let workspace = ProcessWorkspace::create(
            &start.workspace_root,
            start.identity,
            start.execution.target_instance(),
            start.instance_generation,
        )?;
        let launch = start.program.launch_in(workspace.path().to_path_buf())?;
        let generations = ProcessSessionGenerations::try_new(
            start.identity.runtime_host_epoch().value(),
            start.identity.domain_epoch().value(),
            start.instance_generation.value(),
        )
        .map_err(ProcessTransportError::from)?;
        let session_identity = ProcessSessionIdentity::try_new(
            start.identity.runtime_host(),
            start.identity.domain(),
            start.execution.target_instance(),
            generations,
            start.identity.source_revision(),
            start.identity.target_slice_digest(),
        )
        .map_err(ProcessTransportError::from)?;
        let mut transport = ProcessTransport::spawn(&launch, session_identity)?;
        let lifecycle = start.desired.lifecycle();
        let capacity = start.desired.capacity();
        let maximum_payload = u32::try_from(capacity.ipc_credit_bytes())
            .map_err(|_| ProcessDomainError::UnsupportedExecutableProfile)?;

        let handshake = async {
            transport
                .send_host_frame(
                    ProcessWorkerState::Starting,
                    0,
                    ProcessFrameBody::Start {
                        max_inflight: capacity.max_concurrent(),
                        max_retained_bytes: capacity.max_retained_bytes(),
                        max_payload_bytes: maximum_payload,
                        heartbeat_interval_nanos: lifecycle.heartbeat_interval().value(),
                        heartbeat_timeout_nanos: lifecycle.heartbeat_timeout().value(),
                    },
                )
                .await?;
            let ready = transport.receive_worker_frame().await?;
            enforce_process_resource_limits(&transport, start.desired.resources())?;
            match ready.ready_runtime_digest() {
                Some(worker_runtime_digest)
                    if worker_runtime_digest == start.program.worker_runtime_digest() => {}
                Some(_) => {
                    return Err(ProcessDomainError::WorkerRuntimeMismatch);
                }
                None => return Err(ProcessDomainError::UnexpectedWorkerFrame),
            }
            transport
                .send_host_frame(
                    ProcessWorkerState::Constructing,
                    0,
                    ProcessFrameBody::Construct {
                        artifact_digest: start.artifact_digest,
                        config_digest: start.config_digest,
                        entrypoint_ref: start.execution.entrypoint(),
                    },
                )
                .await?;
            let constructed = transport.receive_worker_frame().await?;
            enforce_process_resource_limits(&transport, start.desired.resources())?;
            match constructed.constructed_outcome() {
                Some(ConstructOutcome::Constructed) => Ok(constructed.sequence()),
                Some(_) => Err(ProcessDomainError::ConstructionRejected),
                None => Err(ProcessDomainError::UnexpectedWorkerFrame),
            }
        };
        let startup_sequence = timeout(bounded(lifecycle.start()), handshake)
            .await
            .map_err(|_| ProcessDomainError::StartupTimedOut)??;
        liveness.observe_startup_ack(start.identity, startup_sequence, start.clock.reading()?)?;
        if transport.phase() != ProcessProtocolPhase::Running {
            return Err(ProcessDomainError::UnexpectedWorkerFrame);
        }

        Ok(Self {
            desired: start.desired,
            execution: start.execution,
            identity: start.identity,
            instance_generation: start.instance_generation,
            program: start.program,
            workspace_root: start.workspace_root,
            artifact_digest: start.artifact_digest,
            config_digest: start.config_digest,
            transport: Some(transport),
            workspace_path: workspace.path().to_path_buf(),
            workspace: Some(workspace),
            liveness,
            recovery,
            admission_gate: Some(ProcessAdmissionGate::new(start.identity)),
            admission_fence: None,
            cleanup_authority: None,
            next_invocation_id: 0,
            next_credit_id: 0,
            active_invocation: None,
            retained_terminal: None,
            next_recovery_fact_sequence: 0,
            shutdown_expected_loss: None,
            clock: start.clock,
            phase: ProcessDomainPhase::Running,
        })
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> ProcessGenerationIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn instance(&self) -> InstanceRef {
        self.execution.target_instance()
    }

    #[must_use]
    pub(crate) const fn instance_generation(&self) -> InstanceGeneration {
        self.instance_generation
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> ProcessDomainPhase {
        self.phase
    }

    #[must_use]
    pub(crate) const fn liveness_phase(&self) -> LivenessPhase {
        self.liveness.phase()
    }

    #[must_use]
    pub(crate) const fn recovery(&self) -> &RecoveryState {
        &self.recovery
    }

    #[must_use]
    pub(crate) fn workspace(&self) -> &Path {
        &self.workspace_path
    }

    /// Waits for one idle liveness fact. A timeout, EOF, malformed frame, or
    /// unexpected worker message fences this generation before returning.
    pub(crate) async fn monitor_once(
        &mut self,
    ) -> Result<ProcessDomainMonitorEvent, ProcessDomainError> {
        if self.phase != ProcessDomainPhase::Running || self.active_invocation.is_some() {
            return Err(ProcessDomainError::MonitorNotIdle);
        }
        loop {
            let heartbeat_budget = match self.heartbeat_wait_budget() {
                Ok(budget) => budget,
                Err(ProcessDomainError::Liveness(LivenessError::DeadlineElapsed)) => {
                    if self.record_liveness_failure()? {
                        return Ok(ProcessDomainMonitorEvent::RecoveryRequired);
                    }
                    continue;
                }
                Err(ProcessDomainError::Liveness(error)) => {
                    return self.fail_liveness_invariant(error);
                }
                Err(error) => return Err(error),
            };
            let received = timeout(heartbeat_budget, self.receive_worker_frame()).await;
            let frame = match received {
                Ok(Ok(frame)) => frame,
                Ok(Err(error)) => {
                    let kind = resource_failure_fact(&error).unwrap_or(
                        RuntimeFailureFactKind::ProtocolViolation(
                            ProcessProtocolFailure::InvalidFrame,
                        ),
                    );
                    self.begin_unexpected_recovery(kind)?;
                    return Ok(ProcessDomainMonitorEvent::RecoveryRequired);
                }
                Err(_) => {
                    if self.record_liveness_failure()? {
                        return Ok(ProcessDomainMonitorEvent::RecoveryRequired);
                    }
                    continue;
                }
            };
            match self.observe_heartbeat(&frame) {
                Ok(true) => return Ok(ProcessDomainMonitorEvent::Heartbeat),
                Ok(false) => {
                    self.begin_unexpected_recovery(RuntimeFailureFactKind::ProtocolViolation(
                        ProcessProtocolFailure::SequenceViolation,
                    ))?;
                    return Ok(ProcessDomainMonitorEvent::RecoveryRequired);
                }
                Err(ProcessDomainError::Liveness(LivenessError::DeadlineElapsed)) => {
                    if self.record_liveness_failure()? {
                        return Ok(ProcessDomainMonitorEvent::RecoveryRequired);
                    }
                }
                Err(ProcessDomainError::Liveness(
                    LivenessError::StaleWorkerSequence | LivenessError::StaleHeartbeatSequence,
                )) => {
                    self.begin_unexpected_recovery(RuntimeFailureFactKind::ProtocolViolation(
                        ProcessProtocolFailure::SequenceViolation,
                    ))?;
                    return Ok(ProcessDomainMonitorEvent::RecoveryRequired);
                }
                Err(ProcessDomainError::Liveness(error)) => {
                    return self.fail_liveness_invariant(error);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Waits for the reducer's bounded restart backoff, starts a fresh process
    /// and workspace generation, then rolls the restart ledger into that exact
    /// DomainEpoch. This never replays the invocation lost with the old worker.
    pub(crate) async fn restart_after_backoff(&mut self) -> Result<(), ProcessDomainError> {
        if self.phase != ProcessDomainPhase::Recovering {
            return Err(ProcessDomainError::RestartNotReady);
        }
        let start_action = loop {
            let transition = RecoveryEngine::poll(&self.recovery, self.clock.reading()?)?;
            let decision = transition.decision();
            self.recovery = transition.into_state();
            match decision {
                RecoveryDecision::WaitUntil(at) => {
                    let now = self.clock.reading()?.now().value();
                    sleep(Duration::from_nanos(at.value().saturating_sub(now))).await;
                }
                RecoveryDecision::Execute(action)
                    if matches!(action.action(), RecoveryAction::StartFreshDomain { .. }) =>
                {
                    break action;
                }
                _ => return Err(ProcessDomainError::UnexpectedRecoveryDecision),
            }
        };
        let RecoveryAction::StartFreshDomain { next_epoch } = start_action.action() else {
            return Err(ProcessDomainError::UnexpectedRecoveryDecision);
        };
        let next_instance_generation = self
            .instance_generation
            .try_next()
            .map_err(|_| ProcessDomainError::RestartGenerationExhausted)?;
        let next_identity = ProcessGenerationIdentity::new(
            self.identity.runtime_host(),
            self.identity.runtime_host_epoch(),
            self.identity.source_revision(),
            self.identity.target_slice_digest(),
            self.identity.domain(),
            next_epoch,
        );
        let start = ProcessDomainStart {
            desired: self.desired,
            execution: self.execution,
            identity: next_identity,
            instance_generation: next_instance_generation,
            program: self.program.clone(),
            workspace_root: self.workspace_root.clone(),
            artifact_digest: self.artifact_digest,
            config_digest: self.config_digest,
            clock: self.clock,
        };
        let mut next = match ProcessDomain::start(start).await {
            Ok(next) => next,
            Err(_) => {
                self.fail_restart_action(start_action)?;
                return Err(ProcessDomainError::RestartFailed);
            }
        };
        let transition = RecoveryEngine::complete_action(
            &self.recovery,
            start_action.id(),
            RecoveryActionOutcome::Succeeded,
            self.clock.reading()?,
        )?;
        self.recovery = transition.into_state();
        next.recovery =
            RecoveryEngine::roll_generation(&self.recovery, next_identity, self.clock.reading()?)?;
        next.next_recovery_fact_sequence = 0;
        *self = next;
        Ok(())
    }

    /// Executes one bounded PXWP invocation. The first executable profile is
    /// deliberately single-concurrency, so this mutable owner is also the
    /// admission serialization point. Any failure after handoff fences the
    /// whole generation and leaves the invocation classified for no-replay
    /// process-loss cleanup.
    pub(crate) async fn invoke(
        &mut self,
        payload: Box<[u8]>,
    ) -> Result<ReceivedTerminal, ProcessDomainError> {
        if self.phase != ProcessDomainPhase::Running || self.admission_gate.is_none() {
            return Err(ProcessDomainError::AdmissionClosed);
        }
        self.refresh_retained_terminal()?;
        if self.active_invocation.is_some() {
            return Err(ProcessDomainError::InvocationCapacityExhausted);
        }
        if self.retained_terminal.is_some() {
            return Err(ProcessDomainError::InvocationCapacityExhausted);
        }

        let requirements = self.execution.requirements();
        let budgets = requirements.budgets();
        let response_reservation = budgets.max_terminal_payload_bytes();
        let request_bytes = u64::try_from(payload.len())
            .map_err(|_| ProcessDomainError::InvocationPayloadTooLarge)?;
        let retained_bytes = request_bytes
            .checked_add(u64::from(response_reservation))
            .ok_or(ProcessDomainError::InvocationPayloadTooLarge)?;
        if retained_bytes > self.desired.capacity().ipc_credit_bytes() {
            return Err(ProcessDomainError::InvocationPayloadTooLarge);
        }

        let invocation_value = self
            .next_invocation_id
            .checked_add(1)
            .ok_or(ProcessDomainError::InvocationIdentifierExhausted)?;
        let credit_id = self
            .next_credit_id
            .checked_add(1)
            .ok_or(ProcessDomainError::InvocationIdentifierExhausted)?;
        let invocation = InvocationId::try_new(invocation_value)
            .map_err(|_| ProcessDomainError::InvocationIdentifierExhausted)?;
        self.next_invocation_id = invocation_value;
        self.next_credit_id = credit_id;
        self.active_invocation = Some(ActiveProcessInvocation {
            invocation,
            credit_id,
            stage: ProcessInvocationOwnershipStage::Admitted,
            side_effect: requirements.side_effect_class(),
            ipc_credit_held: true,
            retained_bytes,
        });

        self.set_active_stage(ProcessInvocationOwnershipStage::HandoffStarted)?;
        let send = self
            .transport_mut()?
            .send_host_frame(
                ProcessWorkerState::Running,
                invocation_value,
                ProcessFrameBody::Invoke {
                    credit_id,
                    response_reservation_bytes: response_reservation,
                    remaining_budget_nanos: budgets.run().value(),
                    payload,
                },
            )
            .await;
        if let Err(error) = send {
            let error = ProcessDomainError::from(error);
            self.mark_active_uncertain_after(&error)?;
            return Err(error);
        }

        match timeout(
            bounded(budgets.invoke_ack()),
            self.await_invoked(invocation_value, credit_id),
        )
        .await
        {
            Ok(Ok(())) => self.set_active_stage(ProcessInvocationOwnershipStage::Started)?,
            Ok(Err(error)) => {
                self.mark_active_uncertain_after(&error)?;
                return Err(error);
            }
            Err(_) => {
                let error = ProcessDomainError::InvokeAckTimedOut;
                self.mark_active_uncertain_after(&error)?;
                return Err(error);
            }
        }

        match timeout(
            bounded(budgets.run()),
            self.await_terminal(invocation_value, credit_id),
        )
        .await
        {
            Ok(Ok(terminal)) => return self.finish_terminal(terminal),
            Ok(Err(error)) => {
                self.mark_active_uncertain_after(&error)?;
                return Err(error);
            }
            Err(_) => {}
        }

        self.set_active_stage(ProcessInvocationOwnershipStage::CancellationRequested)?;
        let cancel = self
            .transport_mut()?
            .send_host_frame(
                ProcessWorkerState::Running,
                invocation_value,
                ProcessFrameBody::Cancel {
                    credit_id,
                    grace_remaining_nanos: budgets.cancellation_grace().value(),
                },
            )
            .await;
        if let Err(error) = cancel {
            let error = ProcessDomainError::from(error);
            self.mark_active_uncertain_after(&error)?;
            return Err(error);
        }

        match timeout(
            bounded(budgets.cancellation_grace()),
            self.await_terminal(invocation_value, credit_id),
        )
        .await
        {
            Ok(Ok(terminal)) => self.finish_terminal(terminal),
            Ok(Err(error)) => {
                self.mark_active_uncertain_after(&error)?;
                Err(error)
            }
            Err(_) => {
                let error = ProcessDomainError::CancellationTimedOut;
                self.mark_active_uncertain_after(&error)?;
                Err(error)
            }
        }
    }

    /// Performs protocol drain/stop first, then TERM and KILL escalation as
    /// necessary. Cleanup evidence is consumed by the recovery reducer before
    /// this owner can report Stopped or Quarantined.
    pub(crate) async fn shutdown(&mut self, reason: StopReason) -> Result<(), ProcessDomainError> {
        if self.phase == ProcessDomainPhase::Stopped {
            return Err(ProcessDomainError::AlreadyStopped);
        }
        self.refresh_retained_terminal()?;
        self.shutdown_expected_loss.get_or_insert(
            self.phase == ProcessDomainPhase::Running && self.active_invocation.is_none(),
        );
        self.fence_admission()?;
        let lifecycle = self.desired.lifecycle();
        if self.cleanup_authority.is_none() {
            if self.recovery.phase() == RecoveryPhase::Healthy {
                self.phase = ProcessDomainPhase::Draining;
                if let Err(error) = self.graceful_stop(reason).await {
                    self.phase = ProcessDomainPhase::Recovering;
                    if matches!(error, ProcessDomainError::WorkerStopFailed) {
                        self.begin_unexpected_recovery(RuntimeFailureFactKind::ShutdownFailed)?;
                        self.drive_recovery_stop(reason).await?;
                    } else {
                        self.escalate_termination().await?;
                    }
                }
            } else {
                self.phase = ProcessDomainPhase::Recovering;
                self.drive_recovery_stop(reason).await?;
            }
        }

        let Some(mut transport) = self.transport.take() else {
            return Err(ProcessDomainError::MissingTransport);
        };
        transport.process_mut().close_stdin();
        transport.process_mut().close_stdout();
        if !wait_until_gone(&mut transport, bounded(lifecycle.cleanup())).await? {
            self.transport = Some(transport);
            self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
            return Err(ProcessDomainError::CleanupTimedOut);
        }
        // A cooperative stop can still return a non-clean outcome after shutdown
        // began. `begin_unexpected_recovery` makes that failure sticky by
        // clearing `shutdown_expected_loss`; consume the current value here
        // rather than the optimistic value captured before the stop dialogue.
        let expected_loss = self.shutdown_expected_loss.unwrap_or(false);
        if let Err(error) = self.observe_process_loss(&transport, expected_loss) {
            self.transport = Some(transport);
            self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
            return Err(error);
        }
        let workspace_cleanup = match self.workspace.as_mut() {
            Some(workspace) => workspace.cleanup(),
            None => return Err(ProcessDomainError::MissingWorkspace),
        };
        if let Err(error) = workspace_cleanup {
            self.transport = Some(transport);
            self.record_cleanup_incomplete(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 1, 0))?;
            self.phase = ProcessDomainPhase::Quarantined;
            self.liveness
                .mark_quarantined(self.identity, self.clock.reading()?)?;
            return Err(error.into());
        }
        if self
            .active_invocation
            .is_some_and(|active| active.stage.crossed_handoff())
        {
            let active = self
                .active_invocation
                .as_mut()
                .ok_or(ProcessDomainError::InvocationStateInconsistent)?;
            active.stage = ProcessInvocationOwnershipStage::Uncertain;
            active.ipc_credit_held = false;
            active.retained_bytes = 0;
        } else {
            self.active_invocation = None;
        }
        let observed_at = self.clock.reading()?;
        self.liveness.mark_exited(self.identity, observed_at)?;
        let mut retained_bytes = transport.delivered_payload_bytes();
        if retained_bytes != 0 {
            let RecoveryPhase::AwaitingCleanup { deadline } = self.recovery.phase() else {
                self.transport = Some(transport);
                self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
                return Err(ProcessDomainError::UnexpectedRecoveryDecision);
            };
            let now = self.clock.reading()?.now().value();
            let remaining = Duration::from_nanos(deadline.value().saturating_sub(now));
            if wait_until_payload_released(&transport, remaining).await {
                retained_bytes = 0;
                self.retained_terminal = None;
            } else {
                retained_bytes = transport.delivered_payload_bytes();
            }
        }
        if retained_bytes != 0 {
            self.transport = Some(transport);
            let census = ProcessCleanupCensus::new(true, 0, 0, 0, retained_bytes, 0, 0);
            self.record_cleanup_incomplete(census)?;
            self.phase = ProcessDomainPhase::Quarantined;
            self.liveness
                .mark_quarantined(self.identity, self.clock.reading()?)?;
            return Err(ProcessDomainError::CleanupTimedOut);
        }
        let post_cleanup_ownership = self.cleanup_ownership()?;
        let validation = self
            .cleanup_authority
            .as_ref()
            .ok_or(ProcessDomainError::MissingCleanupAuthority)?
            .validate_reconcile(&post_cleanup_ownership);
        if validation.is_err() {
            self.transport = Some(transport);
            self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
            return Err(ProcessDomainError::CleanupNotExactZero);
        }
        drop(transport);
        let census = ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0);
        let proof = self
            .cleanup_authority
            .take()
            .ok_or(ProcessDomainError::MissingCleanupAuthority)?
            .reconcile(post_cleanup_ownership)
            .map_err(|_| ProcessDomainError::CleanupNotExactZero)?
            .try_prove(census)
            .map_err(|_| ProcessDomainError::CleanupNotExactZero)?;
        self.active_invocation = None;
        self.retained_terminal = None;
        self.record_cleanup_completed(proof)?;
        self.shutdown_expected_loss = None;
        Ok(())
    }

    async fn await_invoked(
        &mut self,
        invocation_id: u64,
        credit_id: u64,
    ) -> Result<(), ProcessDomainError> {
        loop {
            let frame = self.receive_worker_frame().await?;
            if self.observe_heartbeat(&frame)? {
                continue;
            }
            if frame.invocation_id() == invocation_id && frame.invoked_credit() == Some(credit_id) {
                return Ok(());
            }
            return Err(ProcessDomainError::UnexpectedWorkerFrame);
        }
    }

    async fn await_terminal(
        &mut self,
        invocation_id: u64,
        credit_id: u64,
    ) -> Result<ReceivedTerminal, ProcessDomainError> {
        loop {
            let heartbeat_budget = self.heartbeat_wait_budget()?;
            let frame = match timeout(heartbeat_budget, self.receive_worker_frame()).await {
                Ok(result) => result?,
                Err(_) => {
                    if self.liveness.evaluate(self.clock.reading()?)?.is_some() {
                        return Err(ProcessDomainError::HeartbeatTimedOut);
                    }
                    continue;
                }
            };
            if self.observe_heartbeat(&frame)? {
                continue;
            }
            if frame.invocation_id() != invocation_id {
                return Err(ProcessDomainError::UnexpectedWorkerFrame);
            }
            let terminal = frame
                .into_terminal()
                .ok_or(ProcessDomainError::UnexpectedWorkerFrame)?;
            if terminal.credit_id() != credit_id {
                return Err(ProcessDomainError::UnexpectedWorkerFrame);
            }
            return Ok(terminal);
        }
    }

    fn observe_heartbeat(
        &mut self,
        frame: &ReceivedProcessFrame,
    ) -> Result<bool, ProcessDomainError> {
        let Some((heartbeat_sequence, _, _)) = frame.heartbeat() else {
            return Ok(false);
        };
        self.liveness.observe_heartbeat(
            self.identity,
            frame.sequence(),
            heartbeat_sequence,
            self.clock.reading()?,
        )?;
        Ok(true)
    }

    fn heartbeat_wait_budget(&self) -> Result<Duration, ProcessDomainError> {
        let reading = self.clock.reading()?;
        let deadline = self.liveness.heartbeat_deadline(self.identity, reading)?;
        Ok(bounded(deadline.remaining()))
    }

    fn finish_terminal(
        &mut self,
        terminal: ReceivedTerminal,
    ) -> Result<ReceivedTerminal, ProcessDomainError> {
        let Some(active) = self.active_invocation else {
            return Err(ProcessDomainError::InvocationStateInconsistent);
        };
        if terminal.invocation_id() != active.invocation.value()
            || terminal.credit_id() != active.credit_id
        {
            return Err(ProcessDomainError::InvocationStateInconsistent);
        }
        if terminal.kind() == InvocationTerminalKind::Uncertain {
            self.mark_active_uncertain()?;
        }
        let retained_bytes = u64::try_from(terminal.payload().len())
            .map_err(|_| ProcessDomainError::InvocationStateInconsistent)?;
        if retained_bytes != 0 {
            if self.retained_terminal.is_some() {
                return Err(ProcessDomainError::InvocationStateInconsistent);
            }
            self.retained_terminal = Some(RetainedProcessTerminal {
                invocation: active.invocation,
                side_effect: active.side_effect,
                retained_bytes,
            });
        }
        self.active_invocation = None;
        Ok(terminal)
    }

    async fn graceful_stop(&mut self, reason: StopReason) -> Result<(), ProcessDomainError> {
        timeout(bounded(self.desired.lifecycle().drain()), async {
            self.transport_mut()?
                .send_host_frame(
                    ProcessWorkerState::Draining,
                    0,
                    ProcessFrameBody::StopAccepting,
                )
                .await?;
            self.receive_until(ProcessFrameKind::Drained).await?;
            Ok::<(), ProcessDomainError>(())
        })
        .await
        .map_err(|_| ProcessDomainError::DrainTimedOut)??;
        self.transport_mut()?
            .send_host_frame(
                ProcessWorkerState::Stopping,
                0,
                ProcessFrameBody::Stop { reason },
            )
            .await?;
        self.transport_mut()?.process_mut().close_stdin();
        timeout(
            bounded(self.desired.lifecycle().cooperative_stop()),
            async {
                let stopped = self.receive_until(ProcessFrameKind::Stopped).await?;
                if stopped.stopped_outcome() != Some(StoppedOutcome::Clean) {
                    return Err(ProcessDomainError::WorkerStopFailed);
                }
                wait_for_process_exit(self.transport_mut()?).await
            },
        )
        .await
        .map_err(|_| ProcessDomainError::CooperativeStopTimedOut)??;
        Ok(())
    }

    async fn drive_recovery_stop(&mut self, reason: StopReason) -> Result<(), ProcessDomainError> {
        loop {
            match self.process_is_gone() {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) => {
                    self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
                    return Err(error);
                }
            }
            if let Some(action) = self.recovery.pending_action() {
                let outcome = match action.action() {
                    RecoveryAction::FenceAndStopAdmission => {
                        self.fence_admission()?;
                        RecoveryActionOutcome::Succeeded
                    }
                    RecoveryAction::RequestCooperativeStop => {
                        self.request_cooperative_stop(reason).await?
                    }
                    RecoveryAction::SendTerminate => {
                        match self.transport_mut()?.process().terminate_group() {
                            Ok(true) => RecoveryActionOutcome::Succeeded,
                            Ok(false) => RecoveryActionOutcome::ProcessAlreadyExited,
                            Err(_) => RecoveryActionOutcome::Failed,
                        }
                    }
                    RecoveryAction::SendKill => {
                        match self.transport_mut()?.process().kill_group() {
                            Ok(true) => RecoveryActionOutcome::Succeeded,
                            Ok(false) => RecoveryActionOutcome::ProcessAlreadyExited,
                            Err(_) => RecoveryActionOutcome::Failed,
                        }
                    }
                    RecoveryAction::EnterQuarantine { .. } => RecoveryActionOutcome::Succeeded,
                    RecoveryAction::CollectCleanup => return Ok(()),
                    RecoveryAction::StartFreshDomain { .. } => {
                        return Err(ProcessDomainError::UnexpectedRecoveryDecision);
                    }
                };
                let transition = RecoveryEngine::complete_action(
                    &self.recovery,
                    action.id(),
                    outcome,
                    self.clock.reading()?,
                )?;
                self.recovery = transition.into_state();
                continue;
            }

            let transition = RecoveryEngine::poll(&self.recovery, self.clock.reading()?)?;
            let decision = transition.decision();
            self.recovery = transition.into_state();
            match decision {
                RecoveryDecision::Execute(_) | RecoveryDecision::AwaitingAction(_) => continue,
                RecoveryDecision::WaitUntil(deadline) => {
                    let now = self.clock.reading()?.now().value();
                    let remaining = Duration::from_nanos(deadline.value().saturating_sub(now));
                    match wait_until_gone(self.transport_mut()?, remaining).await {
                        Ok(true) => return Ok(()),
                        Ok(false) => {}
                        Err(error) => {
                            self.fail_owner_invariant(
                                ProcessOwnerInvariantFailure::StateInconsistent,
                            )?;
                            return Err(error);
                        }
                    }
                }
                RecoveryDecision::NoAction
                    if matches!(self.recovery.phase(), RecoveryPhase::Quarantined { .. }) =>
                {
                    self.phase = ProcessDomainPhase::Quarantined;
                    self.liveness
                        .mark_quarantined(self.identity, self.clock.reading()?)?;
                    return Err(ProcessDomainError::KillTimedOut);
                }
                RecoveryDecision::NoAction => {
                    return Err(ProcessDomainError::UnexpectedRecoveryDecision);
                }
            }
        }
    }

    async fn request_cooperative_stop(
        &mut self,
        reason: StopReason,
    ) -> Result<RecoveryActionOutcome, ProcessDomainError> {
        if self
            .transport_mut()?
            .send_host_frame(
                ProcessWorkerState::Draining,
                0,
                ProcessFrameBody::StopAccepting,
            )
            .await
            .is_err()
        {
            return self.failed_stop_action_outcome();
        }
        let drained = timeout(
            bounded(self.desired.lifecycle().drain()),
            self.receive_until(ProcessFrameKind::Drained),
        )
        .await;
        if !matches!(drained, Ok(Ok(_))) {
            // The request itself crossed the transport boundary. A missing or
            // invalid response is handled by the reducer's signed escalation
            // deadlines; it is not rewritten as a failed signal syscall.
            return Ok(RecoveryActionOutcome::Succeeded);
        }
        if self
            .transport_mut()?
            .send_host_frame(
                ProcessWorkerState::Stopping,
                0,
                ProcessFrameBody::Stop { reason },
            )
            .await
            .is_err()
        {
            return self.failed_stop_action_outcome();
        }
        self.transport_mut()?.process_mut().close_stdin();
        Ok(RecoveryActionOutcome::Succeeded)
    }

    fn failed_stop_action_outcome(&mut self) -> Result<RecoveryActionOutcome, ProcessDomainError> {
        match self.process_is_gone() {
            Ok(true) => Ok(RecoveryActionOutcome::ProcessAlreadyExited),
            Ok(false) => Ok(RecoveryActionOutcome::Failed),
            Err(error) => {
                self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
                Err(error)
            }
        }
    }

    fn process_is_gone(&mut self) -> Result<bool, ProcessDomainError> {
        let transport = self.transport_mut()?;
        let leader_reaped = transport.process_mut().try_wait()?.is_some();
        let group_gone = !transport.process().group_exists()?;
        Ok(leader_reaped && group_gone)
    }

    async fn receive_until(
        &mut self,
        expected: ProcessFrameKind,
    ) -> Result<ReceivedProcessFrame, ProcessDomainError> {
        loop {
            let frame = self.receive_worker_frame().await?;
            if let Some((heartbeat_sequence, _, _)) = frame.heartbeat() {
                self.liveness.observe_heartbeat(
                    self.identity,
                    frame.sequence(),
                    heartbeat_sequence,
                    self.clock.reading()?,
                )?;
                continue;
            }
            if frame.kind() == ProcessFrameKind::Terminal {
                let terminal = frame
                    .into_terminal()
                    .ok_or(ProcessDomainError::UnexpectedWorkerFrame)?;
                let terminal = self.finish_terminal(terminal)?;
                drop(terminal);
                self.refresh_retained_terminal()?;
                continue;
            }
            if frame.kind() == expected {
                return Ok(frame);
            }
            return Err(ProcessDomainError::UnexpectedWorkerFrame);
        }
    }

    async fn escalate_termination(&mut self) -> Result<(), ProcessDomainError> {
        let lifecycle = self.desired.lifecycle();
        let terminate = self.transport_mut()?.process().terminate_group();
        if let Err(error) = terminate {
            self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
            return Err(error.into());
        }
        let terminated =
            wait_until_gone(self.transport_mut()?, bounded(lifecycle.terminate_grace())).await;
        match terminated {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => {
                self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
                return Err(error);
            }
        }
        let kill = self.transport_mut()?.process().kill_group();
        if let Err(error) = kill {
            self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
            return Err(error.into());
        }
        match wait_until_gone(self.transport_mut()?, bounded(lifecycle.kill_grace())).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
                Err(ProcessDomainError::KillTimedOut)
            }
            Err(error) => {
                self.fail_owner_invariant(ProcessOwnerInvariantFailure::StateInconsistent)?;
                Err(error)
            }
        }
    }

    fn transport_mut(&mut self) -> Result<&mut ProcessTransport, ProcessDomainError> {
        self.transport
            .as_mut()
            .ok_or(ProcessDomainError::MissingTransport)
    }

    async fn receive_worker_frame(&mut self) -> Result<ReceivedProcessFrame, ProcessDomainError> {
        let frame = self.transport_mut()?.receive_worker_frame().await?;
        let transport = self
            .transport
            .as_ref()
            .ok_or(ProcessDomainError::MissingTransport)?;
        if let Err(error) = enforce_process_resource_limits(transport, self.desired.resources()) {
            if frame.kind() == ProcessFrameKind::Terminal {
                let kind = resource_failure_fact(&error).unwrap_or(
                    RuntimeFailureFactKind::OwnerInvariantViolation(
                        ProcessOwnerInvariantFailure::StateInconsistent,
                    ),
                );
                self.begin_unexpected_recovery(kind)?;
                return Ok(frame);
            }
            return Err(error);
        }
        Ok(frame)
    }

    fn refresh_retained_terminal(&mut self) -> Result<(), ProcessDomainError> {
        let delivered = self
            .transport
            .as_ref()
            .ok_or(ProcessDomainError::MissingTransport)?
            .delivered_payload_bytes();
        match self.retained_terminal {
            Some(_) if delivered == 0 => {
                self.retained_terminal = None;
                Ok(())
            }
            Some(retained) if retained.retained_bytes == delivered => Ok(()),
            None if delivered == 0 => Ok(()),
            Some(_) | None => Err(ProcessDomainError::InvocationStateInconsistent),
        }
    }

    fn fence_admission(&mut self) -> Result<(), ProcessDomainError> {
        if let Some(gate) = self.admission_gate.take() {
            self.admission_fence = Some(gate.fence());
            return Ok(());
        }
        if self.admission_fence.is_some() || self.cleanup_authority.is_some() {
            Ok(())
        } else {
            Err(ProcessDomainError::MissingAdmissionCapability)
        }
    }

    fn set_active_stage(
        &mut self,
        stage: ProcessInvocationOwnershipStage,
    ) -> Result<(), ProcessDomainError> {
        let active = self
            .active_invocation
            .as_mut()
            .ok_or(ProcessDomainError::InvocationStateInconsistent)?;
        active.stage = stage;
        Ok(())
    }

    fn mark_active_uncertain(&mut self) -> Result<(), ProcessDomainError> {
        self.set_active_stage(ProcessInvocationOwnershipStage::Uncertain)?;
        let active = self
            .active_invocation
            .ok_or(ProcessDomainError::InvocationStateInconsistent)?;
        let failure = ProcessInvocationFailure::new(
            self.execution.target_instance(),
            self.instance_generation,
            active.invocation,
            active.side_effect,
        );
        self.begin_unexpected_recovery(RuntimeFailureFactKind::InvocationUncertain(failure))
    }

    fn mark_active_uncertain_after(
        &mut self,
        error: &ProcessDomainError,
    ) -> Result<(), ProcessDomainError> {
        self.mark_active_uncertain()?;
        if let Some(kind) = self.additional_failure_fact(error) {
            self.begin_unexpected_recovery(kind)?;
        }
        Ok(())
    }

    fn additional_failure_fact(
        &self,
        error: &ProcessDomainError,
    ) -> Option<RuntimeFailureFactKind> {
        if let Some(kind) = resource_failure_fact(error) {
            return Some(kind);
        }
        match error {
            ProcessDomainError::HeartbeatTimedOut
            | ProcessDomainError::Liveness(LivenessError::DeadlineElapsed) => {
                Some(RuntimeFailureFactKind::HeartbeatMissed {
                    last_sequence: self.liveness.last_heartbeat_sequence(),
                })
            }
            ProcessDomainError::UnexpectedWorkerFrame
            | ProcessDomainError::Transport(
                ProcessTransportError::InvalidFramePrefix
                | ProcessTransportError::InvalidFrameLength
                | ProcessTransportError::WrongEndpointDirection
                | ProcessTransportError::Protocol(_),
            ) => Some(RuntimeFailureFactKind::ProtocolViolation(
                ProcessProtocolFailure::InvalidFrame,
            )),
            ProcessDomainError::Transport(
                ProcessTransportError::Poisoned | ProcessTransportError::SequenceExhausted,
            ) => Some(RuntimeFailureFactKind::OwnerInvariantViolation(
                ProcessOwnerInvariantFailure::StateInconsistent,
            )),
            _ => None,
        }
    }

    fn record_liveness_failure(&mut self) -> Result<bool, ProcessDomainError> {
        let Some(failure) = self.liveness.evaluate(self.clock.reading()?)? else {
            return Ok(false);
        };
        let kind = match failure {
            LivenessFailure::StartupTimedOut => RuntimeFailureFactKind::LaunchFailed,
            LivenessFailure::HeartbeatMissed {
                last_heartbeat_sequence,
            } => RuntimeFailureFactKind::HeartbeatMissed {
                last_sequence: last_heartbeat_sequence,
            },
            LivenessFailure::ControlResponseMissed { probe } => {
                RuntimeFailureFactKind::ControlProbeMissed { probe }
            }
        };
        self.begin_unexpected_recovery(kind)?;
        Ok(true)
    }

    fn fail_liveness_invariant<T>(
        &mut self,
        error: LivenessError,
    ) -> Result<T, ProcessDomainError> {
        let failure = match error {
            LivenessError::GenerationMismatch => ProcessOwnerInvariantFailure::GenerationMismatch,
            LivenessError::ClockMismatch => ProcessOwnerInvariantFailure::ClockMismatch,
            LivenessError::ClockRegressed => ProcessOwnerInvariantFailure::ClockRegressed,
            LivenessError::DeadlineOverflow => ProcessOwnerInvariantFailure::DeadlineOverflow,
            LivenessError::DeadlineElapsed
            | LivenessError::StaleWorkerSequence
            | LivenessError::StaleHeartbeatSequence
            | LivenessError::StaleProbe
            | LivenessError::ProbeAlreadyOutstanding
            | LivenessError::NoProbeOutstanding
            | LivenessError::ProbeMismatch
            | LivenessError::TerminalState
            | LivenessError::StateInconsistent => ProcessOwnerInvariantFailure::StateInconsistent,
        };
        self.fail_owner_invariant(failure)?;
        Err(ProcessDomainError::Liveness(error))
    }

    fn fail_owner_invariant(
        &mut self,
        failure: ProcessOwnerInvariantFailure,
    ) -> Result<(), ProcessDomainError> {
        self.phase = ProcessDomainPhase::Recovering;
        self.shutdown_expected_loss = Some(false);
        self.fence_admission()?;
        let fact =
            self.next_recovery_fact(RuntimeFailureFactKind::OwnerInvariantViolation(failure))?;
        let transition = RecoveryEngine::observe_fact(&self.recovery, fact)?;
        let decision = transition.decision();
        self.recovery = transition.into_state();
        let entered_quarantine = self.complete_invariant_recovery(decision)?;
        self.phase = if entered_quarantine
            || matches!(self.recovery.phase(), RecoveryPhase::Quarantined { .. })
        {
            self.liveness
                .mark_quarantined(self.identity, self.clock.reading()?)?;
            ProcessDomainPhase::Quarantined
        } else {
            ProcessDomainPhase::Recovering
        };
        Ok(())
    }

    fn begin_unexpected_recovery(
        &mut self,
        kind: RuntimeFailureFactKind,
    ) -> Result<(), ProcessDomainError> {
        self.phase = ProcessDomainPhase::Recovering;
        self.shutdown_expected_loss = Some(false);
        let fact = self.next_recovery_fact(kind)?;
        let transition = RecoveryEngine::observe_fact(&self.recovery, fact)?;
        let decision = transition.decision();
        self.recovery = transition.into_state();
        self.complete_recovery_fence(decision)
    }

    fn complete_invariant_recovery(
        &mut self,
        mut decision: RecoveryDecision,
    ) -> Result<bool, ProcessDomainError> {
        let first = match decision {
            RecoveryDecision::Execute(action) => Some(action),
            RecoveryDecision::AwaitingAction(id) => {
                let action = self
                    .recovery
                    .pending_action()
                    .ok_or(ProcessDomainError::UnexpectedRecoveryDecision)?;
                if action.id() != id {
                    return Err(ProcessDomainError::UnexpectedRecoveryDecision);
                }
                Some(action)
            }
            RecoveryDecision::NoAction | RecoveryDecision::WaitUntil(_) => None,
        };
        if first.is_some_and(|action| action.action() == RecoveryAction::FenceAndStopAdmission) {
            self.complete_recovery_fence(decision)?;
            return Ok(false);
        }
        if !first
            .is_some_and(|action| matches!(action.action(), RecoveryAction::EnterQuarantine { .. }))
        {
            return Ok(false);
        }

        loop {
            let action = match decision {
                RecoveryDecision::Execute(action) => action,
                RecoveryDecision::AwaitingAction(id) => {
                    let action = self
                        .recovery
                        .pending_action()
                        .ok_or(ProcessDomainError::UnexpectedRecoveryDecision)?;
                    if action.id() != id {
                        return Err(ProcessDomainError::UnexpectedRecoveryDecision);
                    }
                    action
                }
                RecoveryDecision::NoAction | RecoveryDecision::WaitUntil(_) => return Ok(true),
            };
            if !matches!(
                action.action(),
                RecoveryAction::EnterQuarantine { .. } | RecoveryAction::CollectCleanup
            ) {
                return Err(ProcessDomainError::UnexpectedRecoveryDecision);
            }
            let collected = action.action() == RecoveryAction::CollectCleanup;
            let transition = RecoveryEngine::complete_action(
                &self.recovery,
                action.id(),
                RecoveryActionOutcome::Succeeded,
                self.clock.reading()?,
            )?;
            decision = transition.decision();
            self.recovery = transition.into_state();
            if collected {
                return Ok(true);
            }
        }
    }

    fn complete_recovery_fence(
        &mut self,
        decision: RecoveryDecision,
    ) -> Result<(), ProcessDomainError> {
        let action = match decision {
            RecoveryDecision::Execute(action)
                if action.action() == RecoveryAction::FenceAndStopAdmission =>
            {
                action
            }
            RecoveryDecision::AwaitingAction(id) => {
                let action = self
                    .recovery
                    .pending_action()
                    .ok_or(ProcessDomainError::UnexpectedRecoveryDecision)?;
                if action.id() != id || action.action() != RecoveryAction::FenceAndStopAdmission {
                    return Ok(());
                }
                action
            }
            RecoveryDecision::Execute(_)
            | RecoveryDecision::NoAction
            | RecoveryDecision::WaitUntil(_) => return Ok(()),
        };
        self.fence_admission()?;
        let transition = RecoveryEngine::complete_action(
            &self.recovery,
            action.id(),
            RecoveryActionOutcome::Succeeded,
            self.clock.reading()?,
        )?;
        if !matches!(
            transition.decision(),
            RecoveryDecision::Execute(next)
                if next.action() == RecoveryAction::RequestCooperativeStop
        ) {
            return Err(ProcessDomainError::UnexpectedRecoveryDecision);
        }
        self.recovery = transition.into_state();
        Ok(())
    }

    fn fail_restart_action(
        &mut self,
        action: crate::recovery::RecoveryActionEnvelope,
    ) -> Result<(), ProcessDomainError> {
        let transition = RecoveryEngine::complete_action(
            &self.recovery,
            action.id(),
            RecoveryActionOutcome::Failed,
            self.clock.reading()?,
        )?;
        let decision = transition.decision();
        self.recovery = transition.into_state();
        let RecoveryDecision::Execute(quarantine) = decision else {
            return Err(ProcessDomainError::UnexpectedRecoveryDecision);
        };
        if !matches!(quarantine.action(), RecoveryAction::EnterQuarantine { .. }) {
            return Err(ProcessDomainError::UnexpectedRecoveryDecision);
        }
        let transition = RecoveryEngine::complete_action(
            &self.recovery,
            quarantine.id(),
            RecoveryActionOutcome::Succeeded,
            self.clock.reading()?,
        )?;
        self.recovery = transition.into_state();
        self.phase = ProcessDomainPhase::Quarantined;
        self.liveness
            .mark_quarantined(self.identity, self.clock.reading()?)?;
        Ok(())
    }

    fn observe_process_loss(
        &mut self,
        transport: &ProcessTransport,
        expected: bool,
    ) -> Result<(), ProcessDomainError> {
        if self.cleanup_authority.is_some() {
            return Ok(());
        }
        let capacity = self.desired.capacity();
        let limits = ProcessOwnershipLimits::new(
            capacity.max_outstanding(),
            capacity.ipc_credit_items(),
            capacity.max_retained_bytes(),
            self.desired.resources().max_process_tree_members(),
        );
        let invocations = self.ownership_invocations();
        let retained_bytes = invocations.iter().try_fold(0_u64, |current, invocation| {
            current.checked_add(invocation.retained_bytes())
        });
        if transport.active_invocations() != usize::from(self.active_invocation.is_some())
            || retained_bytes != Some(transport.retained_bytes())
        {
            return Err(ProcessDomainError::ProcessLossSnapshotMismatch);
        }
        let instance = ProcessInstanceOwnership::try_new(
            self.execution.target_instance(),
            self.instance_generation,
            invocations,
        )?;
        let ownership = ProcessDomainOwnership::try_new(
            self.identity,
            ProcessOwnershipLifecycle::Closing,
            0,
            limits,
            vec![instance],
        )?;
        let fence = self
            .admission_fence
            .take()
            .ok_or(ProcessDomainError::MissingAdmissionCapability)?;
        let (observation, authority) = fence
            .observe_process_loss(expected, ownership)?
            .into_parts();
        self.cleanup_authority = Some(authority);
        self.record_process_loss(observation)
    }

    fn cleanup_ownership(&self) -> Result<ProcessDomainOwnership, ProcessDomainError> {
        let capacity = self.desired.capacity();
        let limits = ProcessOwnershipLimits::new(
            capacity.max_outstanding(),
            capacity.ipc_credit_items(),
            capacity.max_retained_bytes(),
            self.desired.resources().max_process_tree_members(),
        );
        let invocations = self.ownership_invocations();
        let instance = ProcessInstanceOwnership::try_new(
            self.execution.target_instance(),
            self.instance_generation,
            invocations,
        )?;
        Ok(ProcessDomainOwnership::try_new(
            self.identity,
            ProcessOwnershipLifecycle::Closing,
            0,
            limits,
            vec![instance],
        )?)
    }

    fn ownership_invocations(&self) -> Vec<ProcessInvocationOwnership> {
        let mut invocations = Vec::with_capacity(2);
        if let Some(active) = self.active_invocation {
            invocations.push(ProcessInvocationOwnership::new(
                active.invocation,
                active.stage,
                active.side_effect,
                active.ipc_credit_held,
                active.retained_bytes,
            ));
        }
        if let Some(retained) = self.retained_terminal {
            invocations.push(ProcessInvocationOwnership::new(
                retained.invocation,
                ProcessInvocationOwnershipStage::TerminalDelivered,
                retained.side_effect,
                false,
                retained.retained_bytes,
            ));
        }
        invocations
    }

    fn record_process_loss(
        &mut self,
        observation: ProcessLossObservation,
    ) -> Result<(), ProcessDomainError> {
        let fact = self.next_recovery_fact(RuntimeFailureFactKind::ProcessExited(observation))?;
        let transition = RecoveryEngine::observe_fact(&self.recovery, fact)?;
        let mut decision = transition.decision();
        self.recovery = transition.into_state();
        loop {
            let action = match decision {
                RecoveryDecision::Execute(action) => action,
                RecoveryDecision::AwaitingAction(id) => {
                    let action = self
                        .recovery
                        .pending_action()
                        .ok_or(ProcessDomainError::UnexpectedRecoveryDecision)?;
                    if action.id() != id {
                        return Err(ProcessDomainError::UnexpectedRecoveryDecision);
                    }
                    action
                }
                _ => return Err(ProcessDomainError::UnexpectedRecoveryDecision),
            };
            let outcome = match action.action() {
                RecoveryAction::FenceAndStopAdmission => {
                    self.fence_admission()?;
                    RecoveryActionOutcome::Succeeded
                }
                RecoveryAction::RequestCooperativeStop
                | RecoveryAction::SendTerminate
                | RecoveryAction::SendKill => RecoveryActionOutcome::ProcessAlreadyExited,
                RecoveryAction::CollectCleanup => RecoveryActionOutcome::Succeeded,
                RecoveryAction::EnterQuarantine { .. } => RecoveryActionOutcome::Succeeded,
                RecoveryAction::StartFreshDomain { .. } => {
                    return Err(ProcessDomainError::UnexpectedRecoveryDecision);
                }
            };
            let completed_cleanup = action.action() == RecoveryAction::CollectCleanup;
            let transition = RecoveryEngine::complete_action(
                &self.recovery,
                action.id(),
                outcome,
                self.clock.reading()?,
            )?;
            decision = transition.decision();
            self.recovery = transition.into_state();
            if completed_cleanup {
                if !matches!(decision, RecoveryDecision::WaitUntil(_))
                    || !matches!(self.recovery.phase(), RecoveryPhase::AwaitingCleanup { .. })
                {
                    return Err(ProcessDomainError::UnexpectedRecoveryDecision);
                }
                return Ok(());
            }
        }
    }

    fn record_cleanup_incomplete(
        &mut self,
        census: ProcessCleanupCensus,
    ) -> Result<(), ProcessDomainError> {
        let fact = self.next_recovery_fact(RuntimeFailureFactKind::CleanupIncomplete(census))?;
        let transition = RecoveryEngine::observe_fact(&self.recovery, fact)?;
        let mut decision = transition.decision();
        self.recovery = transition.into_state();
        loop {
            let action = match decision {
                RecoveryDecision::Execute(action) => action,
                RecoveryDecision::AwaitingAction(id) => {
                    let action = self
                        .recovery
                        .pending_action()
                        .ok_or(ProcessDomainError::UnexpectedRecoveryDecision)?;
                    if action.id() != id {
                        return Err(ProcessDomainError::UnexpectedRecoveryDecision);
                    }
                    action
                }
                RecoveryDecision::WaitUntil(_)
                    if matches!(self.recovery.phase(), RecoveryPhase::AwaitingCleanup { .. }) =>
                {
                    return Ok(());
                }
                RecoveryDecision::NoAction
                    if matches!(self.recovery.phase(), RecoveryPhase::Quarantined { .. }) =>
                {
                    let transition = RecoveryEngine::poll(&self.recovery, self.clock.reading()?)?;
                    decision = transition.decision();
                    self.recovery = transition.into_state();
                    continue;
                }
                _ => return Err(ProcessDomainError::UnexpectedRecoveryDecision),
            };
            if !matches!(
                action.action(),
                RecoveryAction::EnterQuarantine { .. } | RecoveryAction::CollectCleanup
            ) {
                return Err(ProcessDomainError::UnexpectedRecoveryDecision);
            }
            let completed_cleanup = action.action() == RecoveryAction::CollectCleanup;
            let transition = RecoveryEngine::complete_action(
                &self.recovery,
                action.id(),
                RecoveryActionOutcome::Succeeded,
                self.clock.reading()?,
            )?;
            decision = transition.decision();
            self.recovery = transition.into_state();
            if completed_cleanup
                && matches!(self.recovery.phase(), RecoveryPhase::AwaitingCleanup { .. })
            {
                return Ok(());
            }
        }
    }

    fn record_cleanup_completed(
        &mut self,
        proof: ProcessCleanupProof,
    ) -> Result<(), ProcessDomainError> {
        let fact = self.next_recovery_fact(RuntimeFailureFactKind::CleanupCompleted(proof))?;
        let transition = RecoveryEngine::observe_fact(&self.recovery, fact)?;
        let decision = transition.decision();
        self.recovery = transition.into_state();
        match decision {
            RecoveryDecision::NoAction if self.recovery.phase() == RecoveryPhase::Stopped => {
                self.phase = ProcessDomainPhase::Stopped;
                Ok(())
            }
            RecoveryDecision::NoAction
                if matches!(self.recovery.phase(), RecoveryPhase::Quarantined { .. }) =>
            {
                self.phase = ProcessDomainPhase::Quarantined;
                self.liveness
                    .mark_quarantined(self.identity, self.clock.reading()?)?;
                Ok(())
            }
            RecoveryDecision::Execute(action)
                if matches!(action.action(), RecoveryAction::EnterQuarantine { .. }) =>
            {
                let transition = RecoveryEngine::complete_action(
                    &self.recovery,
                    action.id(),
                    RecoveryActionOutcome::Succeeded,
                    self.clock.reading()?,
                )?;
                self.recovery = transition.into_state();
                if !matches!(self.recovery.phase(), RecoveryPhase::Quarantined { .. }) {
                    return Err(ProcessDomainError::UnexpectedRecoveryDecision);
                }
                self.phase = ProcessDomainPhase::Quarantined;
                self.liveness
                    .mark_quarantined(self.identity, self.clock.reading()?)?;
                Ok(())
            }
            RecoveryDecision::WaitUntil(_)
                if matches!(self.recovery.phase(), RecoveryPhase::Backoff { .. }) =>
            {
                self.phase = ProcessDomainPhase::Recovering;
                Ok(())
            }
            _ => Err(ProcessDomainError::UnexpectedRecoveryDecision),
        }
    }

    fn next_recovery_fact(
        &mut self,
        kind: RuntimeFailureFactKind,
    ) -> Result<RuntimeFailureFact, ProcessDomainError> {
        let sequence = self
            .next_recovery_fact_sequence
            .checked_add(1)
            .ok_or(ProcessDomainError::RecoveryFactSequenceExhausted)?;
        let fact =
            RuntimeFailureFact::try_new(self.identity, sequence, self.clock.reading()?, kind)?;
        self.next_recovery_fact_sequence = sequence;
        Ok(fact)
    }
}

impl Drop for ProcessDomain {
    fn drop(&mut self) {
        // Field drop ordering must not be the lifecycle contract: force child
        // process-group cleanup before the fallback workspace reclamation.
        if self.admission_fence.is_none() {
            self.admission_fence = self.admission_gate.take().map(ProcessAdmissionGate::fence);
        }
        let Some(mut transport) = self.transport.take() else {
            if let Some(mut workspace) = self.workspace.take() {
                let _ = workspace.cleanup();
            }
            return;
        };
        let Some(workspace) = self.workspace.take() else {
            // An inconsistent owner must still synchronously retain and reap
            // the child; there is no workspace left to hand off with it.
            transport.process_mut().reap_blocking();
            return;
        };
        if transport
            .process_mut()
            .reap_with_budget(PROCESS_DROP_SYNC_REAP_BUDGET)
        {
            drop(transport);
            let mut workspace = workspace;
            let _ = workspace.cleanup();
            return;
        }
        hand_off_process_drop_owner(ProcessDomainDropOwner {
            transport,
            workspace,
        });
    }
}

/// Single last-resort owner moved off the RuntimeHost reactor only after a
/// bounded synchronous KILL/reap attempt. Keeping the transport and workspace
/// inseparable prevents namespace reclamation while any owned process lives.
/// This exceptional path cannot issue cleanup proof and is not a structured
/// RuntimeHost child; P2e must replace it with a bounded registered/joined
/// reaper before ProcessDomain becomes part of production assembly.
struct ProcessDomainDropOwner {
    transport: ProcessTransport,
    workspace: ProcessWorkspace,
}

impl ProcessDomainDropOwner {
    fn reclaim(mut self) {
        self.transport.process_mut().reap_blocking();
        drop(self.transport);
        let _ = self.workspace.cleanup();
    }
}

fn hand_off_process_drop_owner(owner: ProcessDomainDropOwner) {
    let owner = Arc::new(Mutex::new(Some(owner)));
    let reaper_owner = Arc::clone(&owner);
    let spawn = thread::Builder::new()
        .name("paraegox-process-domain-reaper".to_owned())
        .spawn(move || {
            if let Some(owner) = take_process_drop_owner(&reaper_owner) {
                owner.reclaim();
            }
        });
    if spawn.is_err()
        && let Some(owner) = take_process_drop_owner(&owner)
    {
        // A failed thread spawn must not discard either half of the owner.
        owner.reclaim();
    }
}

fn take_process_drop_owner(
    owner: &Mutex<Option<ProcessDomainDropOwner>>,
) -> Option<ProcessDomainDropOwner> {
    match owner.lock() {
        Ok(mut owner) => owner.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    }
}

fn validate_start(start: &ProcessDomainStart) -> Result<(), ProcessDomainError> {
    if start.desired.domain() != start.identity.domain()
        || start.execution.domain() != start.identity.domain()
        || start.program.launch_spec() != start.desired.launch()
        || start.desired.launch().protocol_version() != PROCESS_WORKER_PROTOCOL_VERSION
        || start.desired.capacity().max_concurrent() != 1
    {
        return Err(ProcessDomainError::UnsupportedExecutableProfile);
    }
    Ok(())
}

fn resource_failure_fact(error: &ProcessDomainError) -> Option<RuntimeFailureFactKind> {
    let platform = match error {
        ProcessDomainError::Platform(error)
        | ProcessDomainError::Transport(ProcessTransportError::Platform(error)) => error,
        _ => return None,
    };
    let failure = match platform {
        ProcessPlatformError::MemoryLimitExceeded => ProcessResourceFailure::Memory,
        ProcessPlatformError::OpenFileLimitExceeded => ProcessResourceFailure::OpenFds,
        ProcessPlatformError::ProcessTreeLimitExceeded => ProcessResourceFailure::ProcessTree,
        ProcessPlatformError::CpuTimeLimitExceeded => ProcessResourceFailure::Cpu,
        _ => return None,
    };
    Some(RuntimeFailureFactKind::ResourceLimitExceeded(failure))
}

#[cfg(target_os = "linux")]
fn enforce_process_resource_limits(
    transport: &ProcessTransport,
    limits: ProcessResourceLimits,
) -> Result<(), ProcessDomainError> {
    let _observation = transport.process().enforce_resource_limits(limits)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enforce_process_resource_limits(
    _transport: &ProcessTransport,
    _limits: ProcessResourceLimits,
) -> Result<(), ProcessDomainError> {
    // Non-Linux Unix targets retain the trusted local harness profile but do
    // not claim production resource enforcement. No production program mint
    // exists until a target adapter supplies an equivalent bounded census.
    Ok(())
}

async fn wait_until_gone(
    transport: &mut ProcessTransport,
    budget: Duration,
) -> Result<bool, ProcessDomainError> {
    match timeout(budget, wait_for_process_exit(transport)).await {
        Ok(result) => {
            result?;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

async fn wait_until_payload_released(transport: &ProcessTransport, budget: Duration) -> bool {
    if transport.delivered_payload_bytes() == 0 {
        return true;
    }
    timeout(budget, async {
        while transport.delivered_payload_bytes() != 0 {
            sleep(PROCESS_POLL_INTERVAL).await;
        }
    })
    .await
    .is_ok()
}

async fn wait_for_process_exit(transport: &mut ProcessTransport) -> Result<(), ProcessDomainError> {
    loop {
        let leader_reaped = transport.process_mut().try_wait()?.is_some();
        let group_gone = !transport.process().group_exists()?;
        if leader_reaped && group_gone {
            return Ok(());
        }
        sleep(PROCESS_POLL_INTERVAL).await;
    }
}

const fn bounded(value: paraegox_kernel::time::BoundedDuration) -> Duration {
    Duration::from_nanos(value.value())
}

#[derive(Debug)]
pub(crate) enum ProcessDomainError {
    UnsupportedExecutableProfile,
    WorkerRuntimeMismatch,
    ConstructionRejected,
    UnexpectedWorkerFrame,
    AdmissionClosed,
    InvocationCapacityExhausted,
    InvocationPayloadTooLarge,
    InvocationIdentifierExhausted,
    InvocationStateInconsistent,
    InvokeAckTimedOut,
    HeartbeatTimedOut,
    CancellationTimedOut,
    ProcessLossSnapshotMismatch,
    UnexpectedRecoveryDecision,
    RecoveryFactSequenceExhausted,
    MonitorNotIdle,
    RestartNotReady,
    RestartGenerationExhausted,
    RestartFailed,
    StartupTimedOut,
    DrainTimedOut,
    CooperativeStopTimedOut,
    WorkerStopFailed,
    KillTimedOut,
    CleanupTimedOut,
    CleanupNotExactZero,
    MissingAdmissionCapability,
    MissingCleanupAuthority,
    MissingTransport,
    MissingWorkspace,
    AlreadyStopped,
    Platform(ProcessPlatformError),
    Transport(ProcessTransportError),
    Workspace(ProcessWorkspaceError),
    Liveness(LivenessError),
    Recovery(RecoveryError),
    Ownership(RuntimeOwnershipError),
    Clock(RuntimeClockError),
}

macro_rules! domain_error_from {
    ($source:ty, $variant:ident) => {
        impl From<$source> for ProcessDomainError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

domain_error_from!(ProcessPlatformError, Platform);
domain_error_from!(ProcessTransportError, Transport);
domain_error_from!(ProcessWorkspaceError, Workspace);
domain_error_from!(LivenessError, Liveness);
domain_error_from!(RecoveryError, Recovery);
domain_error_from!(RuntimeOwnershipError, Ownership);
domain_error_from!(RuntimeClockError, Clock);

impl fmt::Display for ProcessDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedExecutableProfile => {
                formatter.write_str("process executable profile is not implemented")
            }
            Self::WorkerRuntimeMismatch => formatter.write_str("worker runtime digest mismatched"),
            Self::ConstructionRejected => formatter.write_str("worker construction was rejected"),
            Self::UnexpectedWorkerFrame => formatter.write_str("worker sent an unexpected frame"),
            Self::AdmissionClosed => formatter.write_str("process admission is closed"),
            Self::InvocationCapacityExhausted => {
                formatter.write_str("process invocation capacity is exhausted")
            }
            Self::InvocationPayloadTooLarge => {
                formatter.write_str("process invocation payload exceeds its IPC credit")
            }
            Self::InvocationIdentifierExhausted => {
                formatter.write_str("process invocation identity is exhausted")
            }
            Self::InvocationStateInconsistent => {
                formatter.write_str("process invocation ownership is inconsistent")
            }
            Self::InvokeAckTimedOut => {
                formatter.write_str("process invoke acknowledgement timed out")
            }
            Self::HeartbeatTimedOut => formatter.write_str("process heartbeat timed out"),
            Self::CancellationTimedOut => {
                formatter.write_str("process invocation cancellation timed out")
            }
            Self::ProcessLossSnapshotMismatch => {
                formatter.write_str("process loss snapshot mismatches transport ownership")
            }
            Self::UnexpectedRecoveryDecision => {
                formatter.write_str("process recovery reducer returned an unexpected decision")
            }
            Self::RecoveryFactSequenceExhausted => {
                formatter.write_str("process recovery fact sequence is exhausted")
            }
            Self::MonitorNotIdle => {
                formatter.write_str("process liveness monitor requires an idle running domain")
            }
            Self::RestartNotReady => {
                formatter.write_str("process recovery is not ready to restart")
            }
            Self::RestartGenerationExhausted => {
                formatter.write_str("process restart generation is exhausted")
            }
            Self::RestartFailed => formatter.write_str("fresh process generation failed to start"),
            Self::StartupTimedOut => formatter.write_str("process startup timed out"),
            Self::DrainTimedOut => formatter.write_str("process drain timed out"),
            Self::CooperativeStopTimedOut => formatter.write_str("cooperative stop timed out"),
            Self::WorkerStopFailed => {
                formatter.write_str("worker reported a non-clean stop outcome")
            }
            Self::KillTimedOut => formatter.write_str("forced process kill timed out"),
            Self::CleanupTimedOut => formatter.write_str("process cleanup timed out"),
            Self::CleanupNotExactZero => formatter.write_str("process cleanup is not exact-zero"),
            Self::MissingAdmissionCapability => {
                formatter.write_str("process admission capability is missing")
            }
            Self::MissingCleanupAuthority => {
                formatter.write_str("process cleanup authority is missing")
            }
            Self::MissingTransport => formatter.write_str("process transport owner is missing"),
            Self::MissingWorkspace => formatter.write_str("process workspace owner is missing"),
            Self::AlreadyStopped => formatter.write_str("process domain is already stopped"),
            Self::Platform(error) => write!(formatter, "{error}"),
            Self::Transport(error) => write!(formatter, "{error}"),
            Self::Workspace(error) => write!(formatter, "{error}"),
            Self::Liveness(error) => write!(formatter, "{error}"),
            Self::Recovery(error) => write!(formatter, "{error}"),
            Self::Ownership(error) => write!(formatter, "{error}"),
            Self::Clock(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ProcessDomainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Workspace(error) => Some(error),
            Self::Liveness(error) => Some(error),
            Self::Recovery(error) => Some(error),
            Self::Ownership(error) => Some(error),
            Self::Clock(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};

    use nix::errno::Errno;
    use nix::sys::signal::killpg;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::assignment::{BindingId, MailboxRef};
    use paraegox_runtime_contracts::execution::{
        BlockingRisk, CallModel, CardDefinitionRef, CardImplementationRef, CardSubjectSpec,
        DispatchClass, RunBoundProvenance, WorkloadKind,
    };
    use paraegox_runtime_contracts::process_execution::{
        FailureContainmentPolicy, InvocationReplayPolicy, ProcessAccessPolicy, ProcessCapacitySpec,
        ProcessDomainPolicies, ProcessDomainRef, ProcessEntrypointRef,
        ProcessExecutionRequirements, ProcessInvocationBudgets, ProcessLaunchProfileRef,
        ProcessLaunchSpec, ProcessLifecycleBudgets, ProcessLivenessBudgets,
        ProcessProfileSelections, ProcessResourceLimits, ProcessRestartPolicy,
        ProcessSandboxProfileRef, ProcessShutdownBudgets, ProcessTargetProfileRef,
        ProcessWorkloadSelection, RuntimeVersionRange, WorkerRuntimeKind, WorkspacePolicy,
    };
    use paraegox_runtime_contracts::process_protocol::{
        InvocationTerminalKind, ProcessFrame, ProcessFrameDirection, StoppedOutcome,
    };
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};
    use paraegox_runtime_contracts::thread_execution::ThreadDispatchPolicy;

    use super::*;
    use crate::card_instance::{DomainEpoch, RuntimeHostEpoch};
    use crate::recovery::QuarantineReason;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestArea(PathBuf);

    impl TestArea {
        fn create() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "paraegox-process-domain-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test root should be unique");
            Self(path)
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).expect("worker response should be writable");
            path
        }
    }

    impl Drop for TestArea {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("test root should be removable");
        }
    }

    #[derive(Clone, Copy)]
    enum WorkerDialogue {
        Complete,
        Uncertain,
        FailedStop,
        BlockAfterInvoked,
        HeartbeatThenExit,
    }

    struct DomainFixture {
        desired: ProcessDomainSpec,
        execution: ProcessMailboxExecutionSpec,
        identity: ProcessGenerationIdentity,
        instance_generation: InstanceGeneration,
        worker_digest: Digest32,
        artifact_digest: Digest32,
        config_digest: Digest32,
        clock: RuntimeClock,
    }

    impl DomainFixture {
        fn new(side_effect: SideEffectClass) -> Self {
            Self::new_for_runtime(
                side_effect,
                WorkerRuntimeKind::Python,
                RuntimeVersionRange::try_new(3, 11, 3, 14).expect("runtime range"),
            )
        }

        fn new_for_runtime(
            side_effect: SideEffectClass,
            runtime_kind: WorkerRuntimeKind,
            runtime_versions: RuntimeVersionRange,
        ) -> Self {
            let domain = ProcessDomainRef::from_bytes([0x71; 16]);
            let profiles = ProcessProfileSelections::new(
                ProcessLaunchProfileRef::from_bytes([0x72; 16]),
                Digest32::from_bytes([0x73; 32]),
                ProcessTargetProfileRef::from_bytes([0x74; 16]),
                Digest32::from_bytes([0x75; 32]),
                ProcessSandboxProfileRef::from_bytes([0x76; 16]),
                Digest32::from_bytes([0x77; 32]),
            );
            let launch = ProcessLaunchSpec::try_new(
                profiles,
                PROCESS_WORKER_PROTOCOL_VERSION,
                runtime_kind,
                runtime_versions,
            )
            .expect("launch spec");
            let liveness = ProcessLivenessBudgets::try_new(
                duration_ms(1_000),
                duration_ms(50),
                duration_ms(200),
                duration_ms(100),
            )
            .expect("liveness budgets");
            let shutdown = ProcessShutdownBudgets::try_new(
                duration_ms(100),
                duration_ms(100),
                duration_ms(30),
                duration_ms(500),
                duration_ms(100),
            )
            .expect("shutdown budgets");
            let desired = ProcessDomainSpec::try_new(
                domain,
                launch,
                ProcessCapacitySpec::try_new(1, 1, duration_ms(500), 1, 4_096, 8_192)
                    .expect("capacity"),
                ProcessLifecycleBudgets::new(liveness, shutdown),
                ProcessResourceLimits::try_new(64 * 1024 * 1024, 64, 8, duration_ms(10_000))
                    .expect("resources"),
                ProcessRestartPolicy::try_new(
                    2,
                    duration_ms(5_000),
                    duration_ms(1),
                    duration_ms(10),
                    0,
                )
                .expect("restart"),
                ProcessDomainPolicies::new(
                    WorkspacePolicy::EphemeralPerInstanceGeneration,
                    ProcessAccessPolicy::NoRawHostAccess,
                    FailureContainmentPolicy::WholeProcessDomain,
                ),
            )
            .expect("domain spec");
            let subject = CardSubjectSpec::new(
                CardDefinitionRef::from_bytes([0x31; 16]),
                CardImplementationRef::from_bytes([0x32; 16]),
                Digest32::from_bytes([0x33; 32]),
                Digest32::from_bytes([0x34; 32]),
                Digest32::from_bytes([0x35; 32]),
            );
            let execution = ProcessMailboxExecutionSpec::new(
                BindingId::from_bytes([0x41; 16]),
                MailboxRef::from_bytes([0x42; 16]),
                InstanceRef::from_bytes([0x43; 16]),
                domain,
                ProcessWorkloadSelection::new(
                    subject,
                    ProcessEntrypointRef::from_bytes([0x44; 16]),
                    Digest32::from_bytes([0x45; 32]),
                ),
                ProcessExecutionRequirements::new(
                    CallModel::Synchronous,
                    WorkloadKind::Native,
                    BlockingRisk::Unknown,
                    RunBoundProvenance::Unknown,
                    side_effect,
                    InvocationReplayPolicy::NoReplay,
                    ProcessInvocationBudgets::try_new(
                        duration_ms(100),
                        duration_ms(30),
                        duration_ms(30),
                        128,
                    )
                    .expect("invocation budgets"),
                ),
                ThreadDispatchPolicy::try_new(DispatchClass::Background, 1, 1, 1, 1)
                    .expect("dispatch"),
            );
            let identity = ProcessGenerationIdentity::new(
                RuntimeHostId::from_bytes([0x51; 16]),
                RuntimeHostEpoch::try_new(1).expect("host epoch"),
                SourcePlanRevision::new(1),
                TargetSliceDigest::new(Digest32::from_bytes([0x52; 32])),
                domain,
                DomainEpoch::try_new(1).expect("domain epoch"),
            );
            Self {
                desired,
                execution,
                identity,
                instance_generation: InstanceGeneration::try_new(1).expect("instance generation"),
                worker_digest: Digest32::from_bytes([0x53; 32]),
                artifact_digest: Digest32::from_bytes([0x54; 32]),
                config_digest: Digest32::from_bytes([0x55; 32]),
                clock: RuntimeClock::new(
                    ClockDomainRef::from_bytes([0x56; 16]),
                    ClockGeneration::try_new(1).expect("clock generation"),
                    0,
                ),
            }
        }

        fn session_identity(
            &self,
            identity: ProcessGenerationIdentity,
            instance_generation: InstanceGeneration,
        ) -> ProcessSessionIdentity {
            ProcessSessionIdentity::try_new(
                identity.runtime_host(),
                identity.domain(),
                self.execution.target_instance(),
                ProcessSessionGenerations::try_new(
                    identity.runtime_host_epoch().value(),
                    identity.domain_epoch().value(),
                    instance_generation.value(),
                )
                .expect("session generations"),
                identity.source_revision(),
                identity.target_slice_digest(),
            )
            .expect("session identity")
        }

        fn start(&self, area: &TestArea, dialogue: WorkerDialogue) -> ProcessDomainStart {
            let response = area.write("worker.pxwp", &self.worker_wire(dialogue));
            let script = match dialogue {
                WorkerDialogue::Complete
                | WorkerDialogue::Uncertain
                | WorkerDialogue::FailedStop => "/bin/cat \"$RESPONSE\"; /bin/cat >/dev/null",
                WorkerDialogue::BlockAfterInvoked => {
                    "/bin/cat \"$RESPONSE\"; trap '' TERM; while :; do :; done"
                }
                WorkerDialogue::HeartbeatThenExit => {
                    "/bin/cat \"$RESPONSE\"; /bin/dd bs=1 count=\"$READ_BYTES\" of=/dev/null 2>/dev/null"
                }
            };
            let program = ResolvedProcessProgram::try_resolve_for_test(
                self.desired.launch(),
                self.worker_digest,
                PathBuf::from("/bin/sh"),
                vec![OsString::from("-c"), OsString::from(script)],
                vec![
                    (OsString::from("RESPONSE"), response.into_os_string()),
                    (OsString::from("READ_BYTES"), OsString::from("416")),
                ],
            )
            .expect("resolved worker");
            self.start_with_program(area, program)
        }

        fn start_with_program(
            &self,
            area: &TestArea,
            program: ResolvedProcessProgram,
        ) -> ProcessDomainStart {
            ProcessDomainStart {
                desired: self.desired,
                execution: self.execution,
                identity: self.identity,
                instance_generation: self.instance_generation,
                program,
                workspace_root: area.0.clone(),
                artifact_digest: self.artifact_digest,
                config_digest: self.config_digest,
                clock: self.clock,
            }
        }

        fn python_program(
            &self,
            repository: &Path,
            python: &OsString,
            worker_arguments: Vec<OsString>,
        ) -> ResolvedProcessProgram {
            let mut arguments = vec![OsString::from("-m"), OsString::from("paraegox_sdk.worker")];
            arguments.extend(worker_arguments);
            ResolvedProcessProgram::try_resolve_for_test(
                self.desired.launch(),
                self.worker_digest,
                PathBuf::from(python),
                arguments,
                python_environment(repository),
            )
            .expect("Python worker launch must be bounded and explicit")
        }

        fn blocking_python_program_ignoring_term(
            &self,
            repository: &Path,
            python: &OsString,
        ) -> ResolvedProcessProgram {
            let mut environment = python_environment(repository);
            environment.push((OsString::from("PYTHON"), python.clone()));
            ResolvedProcessProgram::try_resolve_for_test(
                self.desired.launch(),
                self.worker_digest,
                PathBuf::from("/bin/sh"),
                vec![
                    OsString::from("-c"),
                    OsString::from(
                        "trap '' TERM; exec \"$PYTHON\" -m paraegox_sdk.worker --fault block",
                    ),
                ],
                environment,
            )
            .expect("TERM-ignoring Python worker launch must be explicit")
        }

        fn rust_program(
            &self,
            executable: &OsString,
            fault: Option<&str>,
        ) -> ResolvedProcessProgram {
            let arguments = fault.map_or_else(Vec::new, |fault| {
                vec![OsString::from("--fault"), OsString::from(fault)]
            });
            ResolvedProcessProgram::try_resolve_for_test(
                self.desired.launch(),
                self.worker_digest,
                PathBuf::from(executable),
                arguments,
                Vec::new(),
            )
            .expect("Rust worker launch must be bounded and explicit")
        }

        fn worker_wire(&self, dialogue: WorkerDialogue) -> Vec<u8> {
            self.worker_wire_for(self.identity, self.instance_generation, dialogue)
        }

        fn worker_wire_for(
            &self,
            generation_identity: ProcessGenerationIdentity,
            instance_generation: InstanceGeneration,
            dialogue: WorkerDialogue,
        ) -> Vec<u8> {
            let identity = self.session_identity(generation_identity, instance_generation);
            let mut frames = vec![
                worker_frame(
                    identity,
                    1,
                    ProcessWorkerState::Starting,
                    0,
                    ProcessFrameBody::Ready {
                        worker_runtime_digest: self.worker_digest,
                    },
                ),
                worker_frame(
                    identity,
                    2,
                    ProcessWorkerState::Constructing,
                    0,
                    ProcessFrameBody::Constructed {
                        outcome: ConstructOutcome::Constructed,
                    },
                ),
            ];
            if !matches!(dialogue, WorkerDialogue::HeartbeatThenExit) {
                frames.push(worker_frame(
                    identity,
                    3,
                    ProcessWorkerState::Running,
                    1,
                    ProcessFrameBody::Invoked { credit_id: 1 },
                ));
            }
            if matches!(
                dialogue,
                WorkerDialogue::Complete | WorkerDialogue::Uncertain | WorkerDialogue::FailedStop
            ) {
                let terminal_kind = if matches!(dialogue, WorkerDialogue::Uncertain) {
                    InvocationTerminalKind::Uncertain
                } else {
                    InvocationTerminalKind::Completed
                };
                let stopped_outcome = if matches!(dialogue, WorkerDialogue::FailedStop) {
                    StoppedOutcome::Failed
                } else {
                    StoppedOutcome::Clean
                };
                frames.extend([
                    worker_frame(
                        identity,
                        4,
                        ProcessWorkerState::Running,
                        1,
                        ProcessFrameBody::Terminal {
                            credit_id: 1,
                            kind: terminal_kind,
                            payload: Box::from(&b"output"[..]),
                        },
                    ),
                    worker_frame(
                        identity,
                        5,
                        ProcessWorkerState::Draining,
                        0,
                        ProcessFrameBody::Drained,
                    ),
                    worker_frame(
                        identity,
                        6,
                        ProcessWorkerState::Stopped,
                        0,
                        ProcessFrameBody::Stopped {
                            outcome: stopped_outcome,
                        },
                    ),
                ]);
            } else if matches!(dialogue, WorkerDialogue::HeartbeatThenExit) {
                frames.push(worker_frame(
                    identity,
                    3,
                    ProcessWorkerState::Running,
                    0,
                    ProcessFrameBody::Heartbeat {
                        heartbeat_sequence: 1,
                        active_invocations: 0,
                        retained_bytes: 0,
                    },
                ));
            }
            let mut wire = Vec::new();
            for frame in frames {
                wire.extend_from_slice(
                    &u32::try_from(frame.canonical_wire().len())
                        .expect("frame length")
                        .to_be_bytes(),
                );
                wire.extend_from_slice(frame.canonical_wire());
            }
            wire
        }
    }

    fn duration_ms(milliseconds: u64) -> BoundedDuration {
        BoundedDuration::from_nanos(milliseconds * 1_000_000)
    }

    fn python_worker_fixture(side_effect: SideEffectClass) -> DomainFixture {
        let mut fixture = DomainFixture::new(side_effect);
        fixture.worker_digest = Digest32::from_bytes([
            0xf9, 0xd7, 0xed, 0x65, 0x17, 0xaa, 0x12, 0x60, 0xec, 0x94, 0x7e, 0xb0, 0xdb, 0x66,
            0x77, 0x1a, 0x99, 0x63, 0x2b, 0xe3, 0x9a, 0xb3, 0x7d, 0x52, 0x5a, 0x1f, 0xae, 0x37,
            0xa3, 0x2e, 0x93, 0xf4,
        ]);
        fixture
    }

    fn rust_worker_fixture(side_effect: SideEffectClass) -> DomainFixture {
        let mut fixture = DomainFixture::new_for_runtime(
            side_effect,
            WorkerRuntimeKind::NativeExecutable,
            RuntimeVersionRange::try_new(1, 0, 1, 0).expect("native runtime range"),
        );
        fixture.worker_digest = Digest32::from_bytes([0x52; 32]);
        fixture
    }

    fn python_environment(repository: &Path) -> Vec<(OsString, OsString)> {
        vec![
            (
                OsString::from("PYTHONPATH"),
                repository.join("src").into_os_string(),
            ),
            (OsString::from("PYTHONUNBUFFERED"), OsString::from("1")),
        ]
    }

    fn worker_frame(
        identity: ProcessSessionIdentity,
        sequence: u64,
        state: ProcessWorkerState,
        invocation_id: u64,
        body: ProcessFrameBody,
    ) -> ProcessFrame {
        ProcessFrame::try_new(
            identity,
            sequence,
            ProcessFrameDirection::WorkerToHost,
            state,
            invocation_id,
            body,
        )
        .expect("worker frame")
    }

    fn assert_group_and_workspace_reclaimed(process_group: nix::unistd::Pid, workspace: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let group_exists = !matches!(killpg(process_group, None), Err(Errno::ESRCH));
            let workspace_exists = workspace.exists();
            assert!(
                workspace_exists || !group_exists,
                "workspace was reclaimed while its process group remained live"
            );
            if !group_exists && !workspace_exists {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "fallback owner did not reclaim process group and workspace"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn complete_worker_runs_invocation_and_consumes_cleanup_proof() {
        let area = TestArea::create();
        let fixture = DomainFixture::new(SideEffectClass::EffectFree);
        let mut domain = ProcessDomain::start(fixture.start(&area, WorkerDialogue::Complete))
            .await
            .expect("domain should start");

        let terminal = domain
            .invoke(Box::from(&b"input"[..]))
            .await
            .expect("invocation should complete");
        assert_eq!(terminal.kind(), InvocationTerminalKind::Completed);
        assert_eq!(terminal.payload(), b"output");
        drop(terminal);

        domain
            .shutdown(StopReason::Planned)
            .await
            .expect("clean shutdown should settle recovery");
        assert_eq!(domain.phase(), ProcessDomainPhase::Stopped);
        assert_eq!(domain.recovery().phase(), RecoveryPhase::Stopped);
        assert!(!domain.workspace().exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drop_never_reclaims_workspace_before_owned_group() {
        let area = TestArea::create();
        let fixture = DomainFixture::new(SideEffectClass::EffectFree);
        let domain = ProcessDomain::start(fixture.start(&area, WorkerDialogue::BlockAfterInvoked))
            .await
            .expect("domain should start");
        let workspace = domain.workspace().to_path_buf();
        let process_group = domain
            .transport
            .as_ref()
            .expect("running domain owns transport")
            .process()
            .process_group();

        drop(domain);
        assert_group_and_workspace_reclaimed(process_group, &workspace);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn combined_fallback_owner_reaps_before_workspace_cleanup() {
        let area = TestArea::create();
        let fixture = DomainFixture::new(SideEffectClass::EffectFree);
        let mut domain =
            ProcessDomain::start(fixture.start(&area, WorkerDialogue::BlockAfterInvoked))
                .await
                .expect("domain should start");
        let workspace_path = domain.workspace().to_path_buf();
        let transport = domain
            .transport
            .take()
            .expect("running domain owns transport");
        let process_group = transport.process().process_group();
        let workspace = domain
            .workspace
            .take()
            .expect("running domain owns workspace");

        hand_off_process_drop_owner(ProcessDomainDropOwner {
            transport,
            workspace,
        });
        drop(domain);

        assert_group_and_workspace_reclaimed(process_group, &workspace_path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn uncertain_terminal_fences_external_effect_and_cannot_resume_admission() {
        let area = TestArea::create();
        let fixture = DomainFixture::new(SideEffectClass::External);
        let mut domain = ProcessDomain::start(fixture.start(&area, WorkerDialogue::Uncertain))
            .await
            .expect("domain should start");

        let terminal = domain
            .invoke(Box::from(&b"external-command"[..]))
            .await
            .expect("uncertain is an authoritative terminal classification");
        assert_eq!(terminal.kind(), InvocationTerminalKind::Uncertain);
        assert_eq!(domain.phase(), ProcessDomainPhase::Recovering);
        assert!(domain.recovery().external_effect_uncertain());
        assert!(matches!(
            domain.invoke(Box::from(&b"must-not-run"[..])).await,
            Err(ProcessDomainError::AdmissionClosed)
        ));
        drop(terminal);

        domain
            .shutdown(StopReason::ProtocolFailure)
            .await
            .expect("uncertain generation must still prove cleanup");
        assert!(matches!(
            domain.recovery().phase(),
            RecoveryPhase::Quarantined {
                reason: QuarantineReason::ExternalEffectUncertain
            }
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_clean_stopped_outcome_never_becomes_clean_stopped_state() {
        let area = TestArea::create();
        let fixture = DomainFixture::new(SideEffectClass::EffectFree);
        let mut domain = ProcessDomain::start(fixture.start(&area, WorkerDialogue::FailedStop))
            .await
            .expect("domain should start");
        let terminal = domain
            .invoke(Box::from(&b"input"[..]))
            .await
            .expect("invocation should complete before failed stop");
        drop(terminal);

        domain
            .shutdown(StopReason::Planned)
            .await
            .expect("failed stop still requires process-loss cleanup");
        assert_ne!(domain.phase(), ProcessDomainPhase::Stopped);
        assert_ne!(domain.recovery().phase(), RecoveryPhase::Stopped);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retained_terminal_rejects_the_next_invoke_before_handoff() {
        let area = TestArea::create();
        let fixture = DomainFixture::new(SideEffectClass::EffectFree);
        let mut domain = ProcessDomain::start(fixture.start(&area, WorkerDialogue::Complete))
            .await
            .expect("domain should start");
        let terminal = domain
            .invoke(Box::from(&b"input"[..]))
            .await
            .expect("first invocation should complete");
        assert_eq!(domain.next_invocation_id, 1);
        assert_eq!(domain.next_credit_id, 1);
        assert!(domain.active_invocation.is_none());
        assert!(domain.retained_terminal.is_some());

        let error = domain
            .invoke(Box::from(&b"second"[..]))
            .await
            .expect_err("a retained terminal must hold the single executable slot");
        assert!(matches!(
            error,
            ProcessDomainError::InvocationCapacityExhausted
        ));
        assert_eq!(domain.next_invocation_id, 1);
        assert_eq!(domain.next_credit_id, 1);
        assert!(domain.active_invocation.is_none());
        assert_eq!(domain.phase(), ProcessDomainPhase::Running);
        assert_eq!(domain.recovery().phase(), RecoveryPhase::Healthy);

        drop(terminal);
        domain
            .shutdown(StopReason::Planned)
            .await
            .expect("released terminal must permit exact-zero shutdown");
        assert_eq!(domain.phase(), ProcessDomainPhase::Stopped);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_payload_owner_blocks_exact_zero_until_dropped() {
        let area = TestArea::create();
        let fixture = DomainFixture::new(SideEffectClass::EffectFree);
        let mut domain = ProcessDomain::start(fixture.start(&area, WorkerDialogue::Complete))
            .await
            .expect("domain should start");
        let terminal = domain
            .invoke(Box::from(&b"input"[..]))
            .await
            .expect("invocation should complete");

        let error = domain
            .shutdown(StopReason::Planned)
            .await
            .expect_err("retained terminal bytes must block exact-zero");
        assert!(matches!(error, ProcessDomainError::CleanupTimedOut));
        assert_eq!(domain.phase(), ProcessDomainPhase::Quarantined);

        drop(terminal);
        domain
            .shutdown(StopReason::Planned)
            .await
            .expect("cleanup should resume after terminal drop");
        assert_eq!(domain.phase(), ProcessDomainPhase::Quarantined);
        assert!(matches!(
            domain.recovery().phase(),
            RecoveryPhase::Quarantined {
                reason: QuarantineReason::CleanupNotProven
            }
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn forced_kill_external_handoff_is_uncertain_and_quarantined() {
        let area = TestArea::create();
        let fixture = DomainFixture::new(SideEffectClass::External);
        let mut domain =
            ProcessDomain::start(fixture.start(&area, WorkerDialogue::BlockAfterInvoked))
                .await
                .expect("domain should start");

        let error = domain
            .invoke(Box::from(&b"command"[..]))
            .await
            .expect_err("ignored cancellation must become uncertain");
        assert!(matches!(error, ProcessDomainError::CancellationTimedOut));
        assert_eq!(domain.phase(), ProcessDomainPhase::Recovering);

        domain
            .shutdown(StopReason::ProtocolFailure)
            .await
            .expect("forced cleanup should be proven through recovery");
        assert_eq!(domain.phase(), ProcessDomainPhase::Quarantined);
        assert!(matches!(
            domain.recovery().phase(),
            RecoveryPhase::Quarantined {
                reason: QuarantineReason::ExternalEffectUncertain
            }
        ));
        assert!(domain.recovery().external_effect_uncertain());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_exit_is_detected_and_effect_free_domain_restarts_fresh() {
        let area = TestArea::create();
        let fixture = DomainFixture::new(SideEffectClass::EffectFree);
        let mut domain =
            ProcessDomain::start(fixture.start(&area, WorkerDialogue::HeartbeatThenExit))
                .await
                .expect("domain should start");

        assert_eq!(
            domain
                .monitor_once()
                .await
                .expect("heartbeat should validate"),
            ProcessDomainMonitorEvent::Heartbeat
        );
        assert_eq!(
            domain
                .monitor_once()
                .await
                .expect("exit should be isolated"),
            ProcessDomainMonitorEvent::RecoveryRequired
        );
        assert_eq!(domain.phase(), ProcessDomainPhase::Recovering);

        domain
            .shutdown(StopReason::ProtocolFailure)
            .await
            .expect("lost generation should clean before restart");
        assert!(matches!(
            domain.recovery().phase(),
            RecoveryPhase::Backoff { .. }
        ));

        let next_identity = ProcessGenerationIdentity::new(
            fixture.identity.runtime_host(),
            fixture.identity.runtime_host_epoch(),
            fixture.identity.source_revision(),
            fixture.identity.target_slice_digest(),
            fixture.identity.domain(),
            DomainEpoch::try_new(2).expect("next domain epoch"),
        );
        let next_instance = InstanceGeneration::try_new(2).expect("next instance generation");
        area.write(
            "worker.pxwp",
            &fixture.worker_wire_for(next_identity, next_instance, WorkerDialogue::Complete),
        );

        domain
            .restart_after_backoff()
            .await
            .expect("effect-free domain should restart within its budget");
        assert_eq!(domain.phase(), ProcessDomainPhase::Running);
        assert_eq!(domain.identity().domain_epoch().value(), 2);
        assert_eq!(domain.instance_generation().value(), 2);

        let terminal = domain
            .invoke(Box::from(&b"fresh"[..]))
            .await
            .expect("fresh generation should accept new work");
        assert_eq!(terminal.payload(), b"output");
        drop(terminal);
        domain
            .shutdown(StopReason::Planned)
            .await
            .expect("fresh generation should stop cleanly");
        assert_eq!(domain.phase(), ProcessDomainPhase::Stopped);
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires the uv-managed Python reference worker"] // GOV-WAIVER-0004
    async fn python_reference_worker_round_trips_through_rust_process_domain() {
        let python = std::env::var_os("PARAEGOX_PYTHON")
            .expect("PARAEGOX_PYTHON must name the uv-managed interpreter");
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("runtime crate must live below the repository root")
            .to_path_buf();
        let area = TestArea::create();
        let fixture = python_worker_fixture(SideEffectClass::EffectFree);
        let program = fixture.python_program(&repository, &python, Vec::new());
        let mut domain = ProcessDomain::start(fixture.start_with_program(&area, program))
            .await
            .expect("Rust ProcessDomain must complete Python handshake");

        let terminal = domain
            .invoke(Box::from(&b"python-round-trip"[..]))
            .await
            .expect("Python worker must acknowledge and complete the invocation");
        assert_eq!(terminal.kind(), InvocationTerminalKind::Completed);
        assert_eq!(terminal.payload(), b"python-round-trip");
        drop(terminal);
        domain
            .shutdown(StopReason::Planned)
            .await
            .expect("Rust owner must drain, stop, reap, and prove exact cleanup");
        assert_eq!(domain.phase(), ProcessDomainPhase::Stopped);
        assert_eq!(domain.recovery().phase(), RecoveryPhase::Stopped);
        assert!(!domain.workspace().exists());

        let crash_area = TestArea::create();
        let crash_fixture = python_worker_fixture(SideEffectClass::External);
        let crash_program = crash_fixture.python_program(
            &repository,
            &python,
            vec![OsString::from("--fault"), OsString::from("crash")],
        );
        let mut crashed =
            ProcessDomain::start(crash_fixture.start_with_program(&crash_area, crash_program))
                .await
                .expect("crash worker must complete startup before fault injection");
        crashed
            .invoke(Box::from(&b"external-effect"[..]))
            .await
            .expect_err("worker crash after handoff must not manufacture a terminal result");
        assert_eq!(crashed.phase(), ProcessDomainPhase::Recovering);
        assert!(crashed.recovery().external_effect_uncertain());
        crashed
            .shutdown(StopReason::ProtocolFailure)
            .await
            .expect("crashed generation must still prove cleanup");
        assert!(matches!(
            crashed.recovery().phase(),
            RecoveryPhase::Quarantined {
                reason: QuarantineReason::ExternalEffectUncertain
            }
        ));

        let blocked_area = TestArea::create();
        let blocked_fixture = python_worker_fixture(SideEffectClass::EffectFree);
        let blocked_program =
            blocked_fixture.blocking_python_program_ignoring_term(&repository, &python);
        let mut blocked = ProcessDomain::start(
            blocked_fixture.start_with_program(&blocked_area, blocked_program),
        )
        .await
        .expect("blocking worker must complete startup");
        assert!(matches!(
            blocked.invoke(Box::from(&b"block"[..])).await,
            Err(ProcessDomainError::CancellationTimedOut)
        ));
        blocked
            .shutdown(StopReason::ProtocolFailure)
            .await
            .expect("TERM-ignoring worker must be killed, reaped, and proven clean");
        assert!(matches!(
            blocked.recovery().phase(),
            RecoveryPhase::Backoff { .. }
        ));

        let grandchild_area = TestArea::create();
        let grandchild_fixture = python_worker_fixture(SideEffectClass::EffectFree);
        let grandchild_pid_file = grandchild_area.0.join("grandchild.pid");
        let grandchild_program = grandchild_fixture.python_program(
            &repository,
            &python,
            vec![
                OsString::from("--fault"),
                OsString::from("spawn-grandchild"),
                OsString::from("--grandchild-pid-file"),
                grandchild_pid_file.clone().into_os_string(),
            ],
        );
        let mut with_grandchild = ProcessDomain::start(
            grandchild_fixture.start_with_program(&grandchild_area, grandchild_program),
        )
        .await
        .expect("grandchild worker must complete startup");
        with_grandchild
            .shutdown(StopReason::Planned)
            .await
            .expect("same-group grandchild must be killed and reaped after parent stop");
        assert_eq!(with_grandchild.phase(), ProcessDomainPhase::Stopped);
        let grandchild_pid: i32 = fs::read_to_string(&grandchild_pid_file)
            .expect("grandchild PID must be reported")
            .trim()
            .parse()
            .expect("grandchild PID must be numeric");
        assert!(matches!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(grandchild_pid), None),
            Err(nix::errno::Errno::ESRCH)
        ));

        let partial_area = TestArea::create();
        let partial_fixture = python_worker_fixture(SideEffectClass::EffectFree);
        let partial_program = partial_fixture.python_program(
            &repository,
            &python,
            vec![OsString::from("--fault"), OsString::from("partial-frame")],
        );
        ProcessDomain::start(partial_fixture.start_with_program(&partial_area, partial_program))
            .await
            .expect_err("partial startup frame must fail closed and reap the worker");
        assert_eq!(
            fs::read_dir(&partial_area.0)
                .expect("test root must remain readable")
                .count(),
            0,
            "failed startup must reclaim its generation workspace",
        );

        let stale_area = TestArea::create();
        let stale_fixture = python_worker_fixture(SideEffectClass::EffectFree);
        let stale_program = stale_fixture.python_program(
            &repository,
            &python,
            vec![
                OsString::from("--fault"),
                OsString::from("stale-generation"),
            ],
        );
        ProcessDomain::start(stale_fixture.start_with_program(&stale_area, stale_program))
            .await
            .expect_err("a stale-generation Ready frame must fail closed");
        assert_eq!(
            fs::read_dir(&stale_area.0)
                .expect("stale-generation root must remain readable")
                .count(),
            0,
            "stale-generation startup must reclaim its workspace",
        );

        #[cfg(target_os = "linux")]
        {
            let pressure_area = TestArea::create();
            let pressure_fixture = python_worker_fixture(SideEffectClass::EffectFree);
            let pressure_program = pressure_fixture.python_program(
                &repository,
                &python,
                vec![OsString::from("--fault"), OsString::from("memory-pressure")],
            );
            match ProcessDomain::start(
                pressure_fixture.start_with_program(&pressure_area, pressure_program),
            )
            .await
            {
                Err(error) => assert!(matches!(
                    error,
                    ProcessDomainError::Platform(ProcessPlatformError::MemoryLimitExceeded)
                )),
                Ok(mut pressured) => {
                    timeout(Duration::from_secs(5), async {
                        loop {
                            if matches!(
                                pressured.monitor_once().await,
                                Ok(ProcessDomainMonitorEvent::RecoveryRequired)
                            ) {
                                break;
                            }
                        }
                    })
                    .await
                    .expect("Linux memory pressure must become a bounded recovery fact");
                    pressured
                        .shutdown(StopReason::ProtocolFailure)
                        .await
                        .expect("memory-pressure worker must be reaped and cleaned");
                    assert!(matches!(
                        pressured.recovery().phase(),
                        RecoveryPhase::Backoff { .. }
                    ));
                }
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires the separately built Rust reference-worker executable"] // GOV-WAIVER-0005
    async fn rust_reference_worker_faults_preserve_uncertain_ownership_and_cleanup() {
        let executable = std::env::var_os("PARAEGOX_RUST_REFERENCE_WORKER")
            .expect("PARAEGOX_RUST_REFERENCE_WORKER must name the reference-worker executable");

        let area = TestArea::create();
        let fixture = rust_worker_fixture(SideEffectClass::EffectFree);
        let program = fixture.rust_program(&executable, None);
        let mut domain = ProcessDomain::start(fixture.start_with_program(&area, program))
            .await
            .expect("Rust worker must complete the canonical handshake");
        let terminal = domain
            .invoke(Box::from(&b"rust-process-domain"[..]))
            .await
            .expect("Rust worker must acknowledge and complete the invocation");
        assert_eq!(terminal.kind(), InvocationTerminalKind::Completed);
        assert_eq!(terminal.payload(), b"rust-process-domain");
        drop(terminal);
        domain
            .shutdown(StopReason::Planned)
            .await
            .expect("normal Rust worker must stop with exact cleanup");
        assert_eq!(domain.phase(), ProcessDomainPhase::Stopped);
        assert_eq!(domain.recovery().phase(), RecoveryPhase::Stopped);
        assert!(domain.active_invocation.is_none());
        assert!(domain.transport.is_none());
        assert!(!domain.workspace().exists());

        for fault in ["partial-invoked", "partial-terminal"] {
            let fault_area = TestArea::create();
            let fault_fixture = rust_worker_fixture(SideEffectClass::External);
            let fault_program = fault_fixture.rust_program(&executable, Some(fault));
            let mut failed =
                ProcessDomain::start(fault_fixture.start_with_program(&fault_area, fault_program))
                    .await
                    .expect("fault worker must complete startup before its invocation fault");

            failed
                .invoke(Box::from(&b"external-effect"[..]))
                .await
                .expect_err("a partial worker frame must never manufacture a terminal result");
            assert_eq!(failed.phase(), ProcessDomainPhase::Recovering);
            assert!(failed.recovery().external_effect_uncertain());
            assert!(failed.active_invocation.is_some_and(|active| {
                active.stage == ProcessInvocationOwnershipStage::Uncertain && active.ipc_credit_held
            }));
            assert!(matches!(
                failed.invoke(Box::from(&b"must-not-run"[..])).await,
                Err(ProcessDomainError::AdmissionClosed)
            ));

            failed
                .shutdown(StopReason::ProtocolFailure)
                .await
                .expect("partial-frame worker loss must still prove process and workspace cleanup");
            assert!(matches!(
                failed.recovery().phase(),
                RecoveryPhase::Quarantined {
                    reason: QuarantineReason::ExternalEffectUncertain
                }
            ));
            assert!(failed.active_invocation.is_none());
            assert!(failed.transport.is_none());
            assert!(!failed.workspace().exists());
        }
    }
}
