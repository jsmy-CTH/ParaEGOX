//! Canonical S4 composition for one admitted in-process Card subject.
//!
//! This private owner consumes an already-authenticated [`RuntimePlanSliceV2`]
//! and composes only its single-subject, single-LoopDomain execution subset.
//! It is deliberately not an apply endpoint, readiness protocol, activation
//! transaction, journal, full AssemblyEngine, or standalone Card runner.
//!
//! Every input crosses the installed [`crate::port_binding::PortBinding`] held
//! by [`LoopDomainCore`]. A callback Future is created only after dispatch has
//! acquired a non-forgeable [`crate::loop_domain::LoopDomainGrant`]. The same
//! owner turn discards any S4 output proposal, closes its generation fence,
//! commits the Mailbox terminal, and releases the domain permit.

use core::fmt;
use core::time::Duration;

use paraegox_runtime_contracts::assignment::{BindingId, InstanceRef};
use paraegox_runtime_contracts::execution::{MailboxExecutionSpec, RuntimePlanSliceV2};

use crate::card_executor::{
    CardCallbackError, CardCallbackOwner, CardInvocationOutcome, CardStartOutcome, CardStopOutcome,
    TrustedCardImplementation,
};
use crate::card_instance::{
    CallbackFailure, CardInstanceIdentity, CardLifecycle, DomainEpoch, InstanceGeneration,
    RuntimeHostEpoch,
};
use crate::dispatcher::DispatchIdleReason;
use crate::loop_domain::{
    LoopDomainCore, LoopDomainDispatchOutcome, LoopDomainError, LoopDomainGrant, LoopDomainIngress,
    LoopDomainRelease, LoopDomainSnapshot,
};
use crate::mailbox::{OfferReport, TerminalReason, TerminalRecord, ValidatedMessage};
use crate::runtime_clock::{RuntimeClock, RuntimeClockError};
use crate::task_registry::CancellationSource;

/// Runtime-owned generation facts that are intentionally absent from PXTE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ComponentRuntimeEpochs {
    runtime_host: RuntimeHostEpoch,
    domain: DomainEpoch,
    instance: InstanceGeneration,
}

impl ComponentRuntimeEpochs {
    #[must_use]
    pub(crate) const fn new(
        runtime_host: RuntimeHostEpoch,
        domain: DomainEpoch,
        instance: InstanceGeneration,
    ) -> Self {
        Self {
            runtime_host,
            domain,
            instance,
        }
    }
}

/// Callback result retained after S4 has synchronously denied any output effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ComponentCallbackOutcome {
    Completed { output_discarded: bool },
    Failed(CallbackFailure),
    CancelledBeforeRun,
    NotRun(TerminalReason),
    TimedOutCooperative,
    TimedOutEscalated,
    Panicked,
}

/// One component dispatch decision and all Mailbox terminals from that turn.
#[must_use]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ComponentDispatchReport {
    outcome: ComponentDispatchOutcome,
    pre_run_terminals: Vec<TerminalRecord>,
}

impl ComponentDispatchReport {
    #[must_use]
    pub(crate) const fn outcome(&self) -> &ComponentDispatchOutcome {
        &self.outcome
    }

    #[must_use]
    pub(crate) fn pre_run_terminals(&self) -> &[TerminalRecord] {
        &self.pre_run_terminals
    }
}

/// Result of either starting a permitted callback or finding no dispatchable work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ComponentDispatchOutcome {
    Invoked {
        callback: ComponentCallbackOutcome,
        terminal: TerminalRecord,
    },
    Idle(DispatchIdleReason),
}

/// Payload-free evidence from one component-owned ready-queue drain.
///
/// This is not a second work queue: the component keeps sole ownership of the
/// installed Mailboxes and invokes
/// [`SingleSubjectComponentRuntime::dispatch_once`] until the exact
/// queue snapshot observed at entry has quiesced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ComponentDispatchBatchReport {
    invoked: u64,
    pre_run_terminals: u64,
    idle: DispatchIdleReason,
}

impl ComponentDispatchBatchReport {
    #[must_use]
    pub(crate) const fn invoked(self) -> u64 {
        self.invoked
    }

    #[must_use]
    pub(crate) const fn pre_run_terminals(self) -> u64 {
        self.pre_run_terminals
    }

    #[must_use]
    pub(crate) const fn idle(self) -> DispatchIdleReason {
        self.idle
    }
}

/// Honest cleanup evidence for the component-owned Card and LoopDomain.
#[must_use]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ComponentShutdownReport {
    reconciled: Vec<TerminalRecord>,
    cancelled: Vec<TerminalRecord>,
    card: CardStopOutcome,
    domain: LoopDomainSnapshot,
}

impl ComponentShutdownReport {
    #[must_use]
    pub(crate) fn reconciled(&self) -> &[TerminalRecord] {
        &self.reconciled
    }

    #[must_use]
    pub(crate) fn cancelled(&self) -> &[TerminalRecord] {
        &self.cancelled
    }

    #[must_use]
    pub(crate) const fn card(&self) -> CardStopOutcome {
        self.card
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> LoopDomainSnapshot {
        self.domain
    }

    #[must_use]
    pub(crate) const fn is_zero_cleanup(&self) -> bool {
        self.domain.is_zero_cleanup() && matches!(self.card, CardStopOutcome::Stopped)
    }
}

/// Preserves Message ownership when component ingress rejects before admission.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ComponentOfferFailure {
    error: ComponentRuntimeError,
    message: Box<ValidatedMessage>,
}

impl ComponentOfferFailure {
    fn new(error: ComponentRuntimeError, message: ValidatedMessage) -> Self {
        Self {
            error,
            message: Box::new(message),
        }
    }

    #[must_use]
    pub(crate) const fn error(&self) -> ComponentRuntimeError {
        self.error
    }

    pub(crate) fn into_message(self) -> ValidatedMessage {
        *self.message
    }
}

/// Sole S4 owner for one exact Card subject and one exact LoopDomain.
pub(crate) struct SingleSubjectComponentRuntime {
    clock: RuntimeClock,
    domain: LoopDomainCore,
    card: CardCallbackOwner,
    pending_grant: Option<LoopDomainGrant>,
    pending_release: Option<LoopDomainRelease>,
}

impl SingleSubjectComponentRuntime {
    /// Composes an already-admitted slice without creating any task or callback Future.
    ///
    /// PXTA bindings not referenced by PXTE are passed through only as immutable
    /// plan evidence. `LoopDomainCore` installs exactly the referenced subset,
    /// so a binding superset cannot synthesize an extra execution authority.
    pub(crate) fn try_new(
        slice: &RuntimePlanSliceV2,
        selected: TrustedCardImplementation,
        epochs: ComponentRuntimeEpochs,
        clock: RuntimeClock,
        parent_cancellation: &CancellationSource,
    ) -> Result<Self, ComponentRuntimeError> {
        slice
            .validate()
            .map_err(|_| ComponentRuntimeError::InvalidExecutionSlice)?;
        let assignments = slice.assignments();
        let execution_plan = assignments.execution();
        let [domain_spec] = execution_plan.domains() else {
            return Err(ComponentRuntimeError::RequiresOneLoopDomain);
        };
        let executions = execution_plan.mailbox_executions();
        let Some(first) = executions.first().copied() else {
            return Err(ComponentRuntimeError::MissingExecution);
        };
        if executions
            .iter()
            .copied()
            .any(|execution| !same_subject(first, execution))
        {
            return Err(ComponentRuntimeError::RequiresOneCardSubject);
        }

        let identity = CardInstanceIdentity::new(
            slice.commitment().header().target(),
            epochs.runtime_host,
            first.target_instance(),
            slice.commitment().header().provenance().source_revision(),
            slice.commitment().target_slice_digest(),
            epochs.domain,
            epochs.instance,
        );
        let domain = LoopDomainCore::try_new(
            *domain_spec,
            executions,
            assignments.bindings().as_slice(),
            epochs.domain,
            clock.domain(),
            clock.generation(),
        )?;
        let domain_owner = domain.owner_identity();
        let card = CardCallbackOwner::try_new(
            identity,
            *domain_spec,
            domain_owner,
            executions,
            selected,
            parent_cancellation,
        )?;

        Ok(Self {
            clock,
            domain,
            card,
            pending_grant: None,
            pending_release: None,
        })
    }

    #[must_use]
    pub(crate) const fn planned_instance(&self) -> InstanceRef {
        self.card.identity().planned_instance()
    }

    #[must_use]
    pub(crate) const fn lifecycle(&self) -> CardLifecycle {
        self.card.lifecycle()
    }

    #[must_use]
    pub(crate) fn active_ingress(&self, binding: BindingId) -> Option<LoopDomainIngress> {
        self.domain.active_ingress(binding)
    }

    pub(crate) fn snapshot(&self) -> Result<LoopDomainSnapshot, ComponentRuntimeError> {
        self.domain.snapshot().map_err(Into::into)
    }

    /// Runs only `on_start`; this is not a P2e readiness or activation claim.
    pub(crate) async fn start(&mut self) -> Result<CardStartOutcome, ComponentRuntimeError> {
        if self.card.lifecycle() != CardLifecycle::Created || self.has_pending_ownership() {
            return Err(ComponentRuntimeError::InvalidLifecycle);
        }
        let reading = self.clock.reading()?;
        self.card.start(reading).await.map_err(Into::into)
    }

    /// Offers a validated Message through the exact installed PortBinding route.
    pub(crate) fn try_offer(
        &mut self,
        ingress: &LoopDomainIngress,
        message: ValidatedMessage,
    ) -> Result<OfferReport, ComponentOfferFailure> {
        if self.card.lifecycle() != CardLifecycle::Started || self.has_pending_ownership() {
            return Err(ComponentOfferFailure::new(
                ComponentRuntimeError::InvalidLifecycle,
                message,
            ));
        }
        let reading = match self.clock.reading() {
            Ok(reading) => reading,
            Err(error) => {
                return Err(ComponentOfferFailure::new(error.into(), message));
            }
        };
        self.domain
            .try_offer(ingress, message, reading)
            .map_err(|failure| {
                ComponentOfferFailure::new(failure.error().into(), failure.into_message())
            })
    }

    /// Dispatches at most one Message and closes all payload/permit ownership
    /// before returning. No second semantic payload queue is introduced.
    pub(crate) async fn dispatch_once(
        &mut self,
    ) -> Result<ComponentDispatchReport, ComponentRuntimeError> {
        if self.card.lifecycle() != CardLifecycle::Started || self.has_pending_ownership() {
            return Err(ComponentRuntimeError::InvalidLifecycle);
        }
        let reading = self.clock.reading()?;
        let report = self.domain.try_dispatch(reading)?;
        let (outcome, pre_run_terminals) = report.into_parts();
        let grant = match outcome {
            LoopDomainDispatchOutcome::Started(grant) => grant,
            LoopDomainDispatchOutcome::Idle(reason) => {
                return Ok(ComponentDispatchReport {
                    outcome: ComponentDispatchOutcome::Idle(reason),
                    pre_run_terminals,
                });
            }
        };

        // Move the linear grant into surviving component state before the
        // first callback poll. If this Future is dropped, shutdown still owns
        // the payload and permit and can commit an Uncertain terminal.
        self.pending_grant = Some(*grant);
        let callback_reading = self.clock.reading()?;
        let outcome = match self
            .card
            .invoke(
                self.pending_grant
                    .as_mut()
                    .ok_or(ComponentRuntimeError::MissingPendingGrant)?,
                callback_reading,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                let grant = self.take_pending_grant()?;
                self.finish_grant(Box::new(grant), TerminalReason::Uncertain)?;
                return Err(error.into());
            }
        };
        let (callback, terminal_reason) = Self::classify_callback_outcome(outcome);
        let grant = self.take_pending_grant()?;
        let terminal = self.finish_grant(Box::new(grant), terminal_reason)?;
        Ok(ComponentDispatchReport {
            outcome: ComponentDispatchOutcome::Invoked { callback, terminal },
            pre_run_terminals,
        })
    }

    /// Runs the component-owned Dispatcher until the currently admitted work
    /// reaches an idle decision.
    ///
    /// The entry snapshot is a hard iteration bound. No producer can mutate
    /// this owner concurrently, and each non-idle turn consumes exactly one
    /// admitted Message, while an idle turn may additionally expire queued
    /// Messages. Reaching the bound without idling is therefore an invariant
    /// failure rather than an invitation to spin forever.
    pub(crate) async fn dispatch_ready_until_idle(
        &mut self,
    ) -> Result<ComponentDispatchBatchReport, ComponentRuntimeError> {
        let queued_at_entry = self.snapshot()?.queued_items();
        let mut invoked = 0_u64;
        let mut pre_run_terminals = 0_u64;
        for _ in 0..=queued_at_entry {
            let report = self.dispatch_once().await?;
            let terminal_count = u64::try_from(report.pre_run_terminals().len())
                .map_err(|_| ComponentRuntimeError::DispatchDidNotQuiesce)?;
            pre_run_terminals = pre_run_terminals
                .checked_add(terminal_count)
                .ok_or(ComponentRuntimeError::DispatchDidNotQuiesce)?;
            match report.outcome() {
                ComponentDispatchOutcome::Invoked { .. } => {
                    invoked = invoked
                        .checked_add(1)
                        .ok_or(ComponentRuntimeError::DispatchDidNotQuiesce)?;
                }
                ComponentDispatchOutcome::Idle(idle) => {
                    return Ok(ComponentDispatchBatchReport {
                        invoked,
                        pre_run_terminals,
                        idle: *idle,
                    });
                }
            }
        }
        Err(ComponentRuntimeError::DispatchDidNotQuiesce)
    }

    /// Stops ingress, cancels the remaining admitted queue, joins the Card's
    /// inline callback stack, and proves exact zero LoopDomain accounting.
    ///
    /// S4 deliberately chooses immediate cancellation for queued work during
    /// drain. There can be no concurrent callback here because this type is the
    /// sole mutable owner. The transition is still bounded by the signed domain
    /// drain budget; final Card cleanup is independently bounded by the signed
    /// domain cleanup budget. Per-execution cleanup budgets apply only after an
    /// invocation exceeds its run budget.
    pub(crate) async fn shutdown(
        &mut self,
    ) -> Result<ComponentShutdownReport, ComponentRuntimeError> {
        if !matches!(
            self.card.lifecycle(),
            CardLifecycle::Starting
                | CardLifecycle::Started
                | CardLifecycle::StartFailed
                | CardLifecycle::Stopping
                | CardLifecycle::Stopped
                | CardLifecycle::Poisoned
        ) {
            return Err(ComponentRuntimeError::InvalidLifecycle);
        }
        self.domain.stop_accepting()?;
        let reconciled = self.reconcile_pending_ownership()?;

        let drain_budget = duration(self.domain.spec().drain_budget().value());
        let drain_started = tokio::time::Instant::now();
        let cancelled = self.domain.cancel_all_queued()?;
        if tokio::time::Instant::now().saturating_duration_since(drain_started) >= drain_budget {
            return Err(ComponentRuntimeError::DrainTimedOut);
        }

        let reading = self.clock.reading()?;
        let card = self.card.stop(reading).await?;
        let domain = self.domain.snapshot()?;
        if !domain.is_zero_cleanup() {
            return Err(ComponentRuntimeError::NonZeroShutdown);
        }
        Ok(ComponentShutdownReport {
            reconciled,
            cancelled,
            card,
            domain,
        })
    }

    fn classify_callback_outcome(
        outcome: CardInvocationOutcome,
    ) -> (ComponentCallbackOutcome, TerminalReason) {
        match outcome {
            CardInvocationOutcome::Completed { output_discarded } => (
                ComponentCallbackOutcome::Completed { output_discarded },
                TerminalReason::Completed,
            ),
            CardInvocationOutcome::Failed(failure) => (
                ComponentCallbackOutcome::Failed(failure),
                TerminalReason::Failed,
            ),
            CardInvocationOutcome::CancelledBeforeRun => (
                ComponentCallbackOutcome::CancelledBeforeRun,
                TerminalReason::Cancelled,
            ),
            CardInvocationOutcome::NotRun(reason) => {
                (ComponentCallbackOutcome::NotRun(reason), reason)
            }
            CardInvocationOutcome::TimedOutCooperative => (
                ComponentCallbackOutcome::TimedOutCooperative,
                TerminalReason::Cancelled,
            ),
            CardInvocationOutcome::TimedOutEscalated => (
                ComponentCallbackOutcome::TimedOutEscalated,
                TerminalReason::Failed,
            ),
            CardInvocationOutcome::Panicked => {
                (ComponentCallbackOutcome::Panicked, TerminalReason::Failed)
            }
        }
    }

    fn finish_grant(
        &mut self,
        grant: Box<LoopDomainGrant>,
        reason: TerminalReason,
    ) -> Result<TerminalRecord, ComponentRuntimeError> {
        let release = match self.domain.finish(*grant, reason) {
            Ok(release) => release,
            Err(failure) => {
                let error = failure.error();
                self.pending_grant = Some(failure.into_grant());
                return Err(error.into());
            }
        };
        let terminal = release.terminal();
        self.release_permit(release)?;
        Ok(terminal)
    }

    fn release_permit(
        &mut self,
        mut release: LoopDomainRelease,
    ) -> Result<(), ComponentRuntimeError> {
        if let Err(error) = self.domain.release(&mut release) {
            self.pending_release = Some(release);
            return Err(error.into());
        }
        Ok(())
    }

    fn reconcile_pending_ownership(
        &mut self,
    ) -> Result<Vec<TerminalRecord>, ComponentRuntimeError> {
        let mut reconciled = Vec::new();
        if let Some(grant) = self.pending_grant.take() {
            match self.domain.abandon_after_caller_release(grant) {
                Ok(release) => self.pending_release = Some(release),
                Err(failure) => {
                    let error = failure.error();
                    self.pending_grant = Some(failure.into_grant());
                    return Err(error.into());
                }
            }
        }
        if let Some(release) = self.pending_release.take() {
            reconciled.push(release.terminal());
            self.release_permit(release)?;
        }
        Ok(reconciled)
    }

    fn has_pending_ownership(&self) -> bool {
        self.pending_grant.is_some() || self.pending_release.is_some()
    }

    fn take_pending_grant(&mut self) -> Result<LoopDomainGrant, ComponentRuntimeError> {
        self.pending_grant
            .take()
            .ok_or(ComponentRuntimeError::MissingPendingGrant)
    }
}

fn same_subject(first: MailboxExecutionSpec, candidate: MailboxExecutionSpec) -> bool {
    first.target_instance() == candidate.target_instance()
        && first.domain() == candidate.domain()
        && first.card_definition() == candidate.card_definition()
        && first.card_implementation() == candidate.card_implementation()
        && first.definition_digest() == candidate.definition_digest()
        && first.artifact_digest() == candidate.artifact_digest()
        && first.config_digest() == candidate.config_digest()
}

const fn duration(nanos: u64) -> Duration {
    Duration::from_nanos(nanos)
}

/// Fail-closed component construction, lifecycle, clock, and ownership errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ComponentRuntimeError {
    InvalidExecutionSlice,
    RequiresOneLoopDomain,
    MissingExecution,
    RequiresOneCardSubject,
    InvalidLifecycle,
    MissingPendingGrant,
    DispatchDidNotQuiesce,
    DrainTimedOut,
    NonZeroShutdown,
    Clock(RuntimeClockError),
    LoopDomain(LoopDomainError),
    Card(CardCallbackError),
}

impl From<RuntimeClockError> for ComponentRuntimeError {
    fn from(error: RuntimeClockError) -> Self {
        Self::Clock(error)
    }
}

impl From<LoopDomainError> for ComponentRuntimeError {
    fn from(error: LoopDomainError) -> Self {
        Self::LoopDomain(error)
    }
}

impl From<CardCallbackError> for ComponentRuntimeError {
    fn from(error: CardCallbackError) -> Self {
        Self::Card(error)
    }
}

impl fmt::Display for ComponentRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(error) => error.fmt(formatter),
            Self::LoopDomain(error) => error.fmt(formatter),
            Self::Card(error) => error.fmt(formatter),
            Self::InvalidExecutionSlice => {
                formatter.write_str("execution slice failed canonical revalidation")
            }
            Self::RequiresOneLoopDomain => {
                formatter.write_str("S4 component requires exactly one LoopDomain")
            }
            Self::MissingExecution => {
                formatter.write_str("S4 component requires a Mailbox execution")
            }
            Self::RequiresOneCardSubject => {
                formatter.write_str("S4 component requires exactly one Card subject")
            }
            Self::InvalidLifecycle => {
                formatter.write_str("S4 component lifecycle does not permit this operation")
            }
            Self::MissingPendingGrant => {
                formatter.write_str("S4 component lost its pending LoopDomain grant")
            }
            Self::DispatchDidNotQuiesce => {
                formatter.write_str("component Dispatcher exceeded its admitted drain bound")
            }
            Self::DrainTimedOut => formatter.write_str("signed LoopDomain drain budget elapsed"),
            Self::NonZeroShutdown => {
                formatter.write_str("LoopDomain cleanup accounting is not exactly zero")
            }
        }
    }
}

impl std::error::Error for ComponentRuntimeError {}

#[cfg(test)]
mod tests {
    use core::future::{Future, pending, poll_fn};
    use core::num::NonZeroUsize;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::Poll;
    use core::time::Duration;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use tokio::time::Instant;

    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::assignment::{
        BindingAssignment, BindingId, DeliveryProfile, InstanceRef, InteractionKind, MailboxRef,
        MailboxSpec, OverflowPolicy, PortCardinality, PortDirection, PortEndpoint, PortRef,
        PortSpec, SchemaRef, TargetAssignments,
    };
    use paraegox_runtime_contracts::execution::{
        BlockingRisk, CallModel, CallbackBudgets, CardDefinitionRef, CardImplementationRef,
        CardSubjectSpec, DispatchClass, LoopDomainCapacity, LoopDomainSpec,
        LoopExecutionRequirements, LoopLifecycleBudgets, MailboxDispatchPolicy,
        MailboxExecutionSpec, OverrunAction, RunBoundProvenance, RuntimeApplyRequestV2,
        RuntimePlanSliceV2, TargetExecutionPlan, TargetPlanAssignments, WorkloadKind,
    };
    use paraegox_runtime_contracts::provenance::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef,
    };

    use super::{
        ComponentCallbackOutcome, ComponentDispatchOutcome, ComponentRuntimeEpochs,
        ComponentRuntimeError, SingleSubjectComponentRuntime,
    };
    use crate::card_executor::{
        CardStartOutcome, CardStopOutcome, CooperativeLoopImplementation, TrustedCardImplementation,
    };
    use crate::card_instance::{
        CallbackFailure, CardContext, CardFuture, CardImplementation, DomainEpoch, InputView,
        InstanceGeneration, OutputProposal, RuntimeHostEpoch,
    };
    use crate::dispatcher::DispatchIdleReason;
    use crate::loop_domain::LoopDomainIngress;
    use crate::mailbox::{
        EnqueueOutcome, MessageId, PayloadHandle, TerminalReason, ValidatedMessage,
    };
    use crate::runtime_clock::RuntimeClock;
    use crate::task_registry::{CancellationSource, RuntimeTaskKind, TaskOutcome, TaskRegistry};

    const HOST: RuntimeHostId = RuntimeHostId::from_bytes([0x10; 16]);
    const CARD_DEFINITION: CardDefinitionRef = CardDefinitionRef::from_bytes([0x11; 16]);
    const CARD_IMPLEMENTATION: CardImplementationRef =
        CardImplementationRef::from_bytes([0x12; 16]);
    const DEFINITION_DIGEST: Digest32 = Digest32::from_bytes([0x13; 32]);
    const ARTIFACT_DIGEST: Digest32 = Digest32::from_bytes([0x14; 32]);
    const CONFIG_DIGEST: Digest32 = Digest32::from_bytes([0x15; 32]);
    const CLOCK_DOMAIN: ClockDomainRef = ClockDomainRef::from_bytes([0x16; 16]);
    const SIGNED_S4_EXECUTION_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s4_runtime_apply_request_v2.json");

    #[derive(Clone, Copy)]
    struct CardBehavior {
        emit_output: bool,
        panic_input: bool,
        pending_start: bool,
        pending_input: bool,
        fail_input_after_cancellation: bool,
        pending_stop: bool,
    }

    struct TestCard {
        behavior: CardBehavior,
        starts: Arc<AtomicUsize>,
        inputs: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
    }

    impl CardImplementation for TestCard {
        fn on_start<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            Box::pin(async move {
                self.starts.fetch_add(1, Ordering::SeqCst);
                if self.behavior.pending_start {
                    pending::<()>().await;
                }
                Ok(())
            })
        }

        fn on_input<'a>(
            &'a mut self,
            context: &'a CardContext,
            input: InputView<'a>,
        ) -> CardFuture<'a, Result<Option<OutputProposal>, CallbackFailure>> {
            Box::pin(async move {
                self.inputs.fetch_add(1, Ordering::SeqCst);
                assert!(!self.behavior.panic_input, "test callback panic");
                if self.behavior.fail_input_after_cancellation {
                    context.cancellation().cancelled().await;
                    return Err(CallbackFailure::Failed);
                }
                if self.behavior.pending_input {
                    pending::<()>().await;
                }
                if !self.behavior.emit_output {
                    return Ok(None);
                }
                let output = OutputProposal::try_new(
                    PortRef::from_bytes([0x7A; 16]),
                    input.schema(),
                    input.payload().to_vec(),
                    64,
                )
                .unwrap_or_else(|error| panic!("test output must fit: {error}"));
                Ok(Some(output))
            })
        }

        fn on_stop<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            Box::pin(async move {
                self.stops.fetch_add(1, Ordering::SeqCst);
                if self.behavior.pending_stop {
                    pending::<()>().await;
                }
                Ok(())
            })
        }
    }

    impl CooperativeLoopImplementation for TestCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = CARD_DEFINITION;
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef = CARD_IMPLEMENTATION;
        const BOUND_DEFINITION_DIGEST: Digest32 = DEFINITION_DIGEST;
        const BOUND_ARTIFACT_DIGEST: Digest32 = ARTIFACT_DIGEST;
    }

    #[derive(Clone)]
    struct LocalDiagnosticProbe {
        control_enqueued: Arc<Mutex<BTreeMap<MessageId, Instant>>>,
        control_latencies: Arc<Mutex<Vec<Duration>>>,
        callback_starts: Arc<AtomicUsize>,
        control_starts: Arc<AtomicUsize>,
        stream_starts: Arc<AtomicUsize>,
        background_starts: Arc<AtomicUsize>,
        background_ordinals: Arc<Mutex<Vec<usize>>>,
        card_starts: Arc<AtomicUsize>,
        card_stops: Arc<AtomicUsize>,
    }

    impl LocalDiagnosticProbe {
        fn new() -> Self {
            Self {
                control_enqueued: Arc::new(Mutex::new(BTreeMap::new())),
                control_latencies: Arc::new(Mutex::new(Vec::new())),
                callback_starts: Arc::new(AtomicUsize::new(0)),
                control_starts: Arc::new(AtomicUsize::new(0)),
                stream_starts: Arc::new(AtomicUsize::new(0)),
                background_starts: Arc::new(AtomicUsize::new(0)),
                background_ordinals: Arc::new(Mutex::new(Vec::new())),
                card_starts: Arc::new(AtomicUsize::new(0)),
                card_stops: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn record_control_enqueue(&self, message: MessageId) {
            let mut enqueued = self
                .control_enqueued
                .lock()
                .unwrap_or_else(|_| panic!("control timestamp map must remain usable"));
            assert!(
                enqueued.insert(message, Instant::now()).is_none(),
                "one active Control identity must have one enqueue timestamp"
            );
        }

        fn discard_control_enqueue(&self, message: MessageId) {
            let mut enqueued = self
                .control_enqueued
                .lock()
                .unwrap_or_else(|_| panic!("control timestamp map must remain usable"));
            let _ = enqueued.remove(&message);
        }

        fn record_callback_start(
            &self,
            input: InputView<'_>,
            control: BindingId,
            stream: BindingId,
            background: BindingId,
        ) {
            let ordinal = self.callback_starts.fetch_add(1, Ordering::SeqCst) + 1;
            if input.binding() == control {
                let enqueued_at = self
                    .control_enqueued
                    .lock()
                    .unwrap_or_else(|_| panic!("control timestamp map must remain usable"))
                    .remove(&input.message_id())
                    .unwrap_or_else(|| panic!("started Control input must have an enqueue sample"));
                self.control_latencies
                    .lock()
                    .unwrap_or_else(|_| panic!("control latency samples must remain usable"))
                    .push(Instant::now().saturating_duration_since(enqueued_at));
                self.control_starts.fetch_add(1, Ordering::SeqCst);
            } else if input.binding() == stream {
                self.stream_starts.fetch_add(1, Ordering::SeqCst);
            } else if input.binding() == background {
                self.background_starts.fetch_add(1, Ordering::SeqCst);
                self.background_ordinals
                    .lock()
                    .unwrap_or_else(|_| panic!("background ordinals must remain usable"))
                    .push(ordinal);
            } else {
                panic!("diagnostic Card received an unknown binding")
            }
        }

        fn control_latencies(&self) -> Vec<Duration> {
            self.control_latencies
                .lock()
                .unwrap_or_else(|_| panic!("control latency samples must remain usable"))
                .clone()
        }

        fn background_ordinals(&self) -> Vec<usize> {
            self.background_ordinals
                .lock()
                .unwrap_or_else(|_| panic!("background ordinals must remain usable"))
                .clone()
        }

        fn pending_control_samples(&self) -> usize {
            self.control_enqueued
                .lock()
                .unwrap_or_else(|_| panic!("control timestamp map must remain usable"))
                .len()
        }
    }

    struct LocalDiagnosticCard {
        probe: LocalDiagnosticProbe,
        control: BindingId,
        stream: BindingId,
        background: BindingId,
    }

    impl CardImplementation for LocalDiagnosticCard {
        fn on_start<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            self.probe.card_starts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }

        fn on_input<'a>(
            &'a mut self,
            _context: &'a CardContext,
            input: InputView<'a>,
        ) -> CardFuture<'a, Result<Option<OutputProposal>, CallbackFailure>> {
            self.probe
                .record_callback_start(input, self.control, self.stream, self.background);
            Box::pin(async {
                // Cross one real current-thread Tokio scheduling boundary. It
                // is intentionally not a sleep or simulated target-hardware
                // service time.
                tokio::task::yield_now().await;
                Ok(None)
            })
        }

        fn on_stop<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            self.probe.card_stops.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    impl CooperativeLoopImplementation for LocalDiagnosticCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = CardDefinitionRef::from_bytes([0xa1; 16]);
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef =
            CardImplementationRef::from_bytes([0xa2; 16]);
        const BOUND_DEFINITION_DIGEST: Digest32 = Digest32::from_bytes([0xa3; 32]);
        const BOUND_ARTIFACT_DIGEST: Digest32 = Digest32::from_bytes([0xa4; 32]);
    }

    #[derive(Clone)]
    struct LocalDiagnosticRoute {
        binding: BindingAssignment,
        ingress: LoopDomainIngress,
    }

    struct LocalDiagnosticL2SourceAdapter {
        clock: RuntimeClock,
        control: LocalDiagnosticRoute,
        stream: LocalDiagnosticRoute,
        background: LocalDiagnosticRoute,
        probe: LocalDiagnosticProbe,
        message_deadline_nanos: u64,
        next_message: u128,
        data_offer_attempts: u64,
        data_admitted: u64,
        control_admitted: u64,
    }

    impl LocalDiagnosticL2SourceAdapter {
        fn offer_data_overload_turn(&mut self, component: &mut SingleSubjectComponentRuntime) {
            let stream_id = self.next_message_id();
            let stream_admitted = offer_diagnostic_message(
                component,
                &self.stream,
                self.clock,
                self.message_deadline_nanos,
                stream_id,
            );
            let background_id = self.next_message_id();
            let background_admitted = offer_diagnostic_message(
                component,
                &self.background,
                self.clock,
                self.message_deadline_nanos,
                background_id,
            );
            self.data_offer_attempts += 2;
            self.data_admitted += u64::from(stream_admitted) + u64::from(background_admitted);
        }

        fn offer_control(&mut self, component: &mut SingleSubjectComponentRuntime) {
            let message = self.next_message_id();
            self.probe.record_control_enqueue(message);
            let report = component
                .try_offer(
                    &self.control.ingress,
                    diagnostic_message(
                        message,
                        self.control.binding,
                        self.clock,
                        self.message_deadline_nanos,
                    ),
                )
                .unwrap_or_else(|failure| {
                    panic!("diagnostic Control offer failed: {}", failure.error())
                });
            for terminal in report.terminals() {
                self.probe.discard_control_enqueue(terminal.message_id());
            }
            if report.outcome().is_admitted() {
                self.control_admitted += 1;
            } else {
                self.probe.discard_control_enqueue(message);
            }
        }

        fn next_message_id(&mut self) -> MessageId {
            let identity = MessageId::from_bytes(self.next_message.to_be_bytes());
            self.next_message = self
                .next_message
                .checked_add(1)
                .unwrap_or_else(|| panic!("diagnostic message identity must remain bounded"));
            identity
        }
    }

    #[derive(Clone, Copy)]
    struct SignedControlFixtureProfile {
        binding: BindingAssignment,
        execution: MailboxExecutionSpec,
        domain: LoopDomainSpec,
        message_deadline_nanos: u64,
        start_threshold: Duration,
    }

    struct LocalDiagnosticRunSummary {
        phase_dispatch_starts: u64,
        data_offer_attempts: u64,
        data_admitted: u64,
        control_admitted: u64,
        background_starts_during_phase: usize,
        last_background_ordinal: usize,
        maximum_background_gap_during_phase: usize,
        final_drain_invoked: u64,
        exact_zero_shutdown: bool,
    }

    struct CardCounters {
        starts: Arc<AtomicUsize>,
        inputs: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
    }

    fn selected(behavior: CardBehavior) -> (TrustedCardImplementation, CardCounters) {
        let counters = CardCounters {
            starts: Arc::new(AtomicUsize::new(0)),
            inputs: Arc::new(AtomicUsize::new(0)),
            stops: Arc::new(AtomicUsize::new(0)),
        };
        let starts = Arc::clone(&counters.starts);
        let inputs = Arc::clone(&counters.inputs);
        let stops = Arc::clone(&counters.stops);
        let fixture_execution = execution(binding(0x7f, 0x61));
        (
            TrustedCardImplementation::try_resolve_loop(&[fixture_execution], move || TestCard {
                behavior,
                starts,
                inputs,
                stops,
            })
            .unwrap_or_else(|error| panic!("eligible test implementation must resolve: {error}")),
            counters,
        )
    }

    fn generation() -> ClockGeneration {
        ClockGeneration::try_new(1)
            .unwrap_or_else(|error| panic!("test clock generation must be valid: {error}"))
    }

    fn clock() -> RuntimeClock {
        RuntimeClock::new(CLOCK_DOMAIN, generation(), 0)
    }

    fn epochs() -> ComponentRuntimeEpochs {
        let runtime_host = RuntimeHostEpoch::try_new(1)
            .unwrap_or_else(|error| panic!("test host epoch must be valid: {error}"));
        let domain = DomainEpoch::try_new(2)
            .unwrap_or_else(|error| panic!("test domain epoch must be valid: {error}"));
        let instance = InstanceGeneration::try_new(3)
            .unwrap_or_else(|error| panic!("test instance generation must be valid: {error}"));
        ComponentRuntimeEpochs::new(runtime_host, domain, instance)
    }

    fn schema() -> SchemaRef {
        SchemaRef::try_new([0x20; 16], 1, Digest32::from_bytes([0x21; 32]))
            .unwrap_or_else(|error| panic!("test schema must be valid: {error}"))
    }

    fn binding(identity: u8, target: u8) -> BindingAssignment {
        let source = PortSpec::new(
            PortDirection::Out,
            schema(),
            InteractionKind::Signal,
            PortCardinality::One,
        );
        let target_spec = PortSpec::new(
            PortDirection::In,
            schema(),
            InteractionKind::Signal,
            PortCardinality::One,
        );
        let delivery = DeliveryProfile::try_new(
            4,
            BoundedDuration::from_nanos(1_000_000),
            OverflowPolicy::RejectNew,
        )
        .unwrap_or_else(|error| panic!("test delivery must be valid: {error}"));
        let mailbox = MailboxSpec::try_new(
            8,
            1_024,
            BoundedDuration::from_nanos(1_000_000),
            8,
            1_024,
            OverflowPolicy::RejectNew,
        )
        .unwrap_or_else(|error| panic!("test Mailbox must be valid: {error}"));
        BindingAssignment::try_new(
            BindingId::from_bytes([identity; 16]),
            PortEndpoint::new(
                InstanceRef::from_bytes([identity.wrapping_add(0x40); 16]),
                PortRef::from_bytes([identity.wrapping_add(0x50); 16]),
                source,
            ),
            PortEndpoint::new(
                InstanceRef::from_bytes([target; 16]),
                PortRef::from_bytes([identity.wrapping_add(0x60); 16]),
                target_spec,
            ),
            MailboxRef::from_bytes([identity.wrapping_add(0x70); 16]),
            delivery,
            mailbox,
        )
        .unwrap_or_else(|error| panic!("test binding must be valid: {error}"))
    }

    fn domain() -> LoopDomainSpec {
        let capacity = LoopDomainCapacity::try_new(
            2,
            0,
            BoundedDuration::from_nanos(1_000_000),
            BoundedDuration::from_nanos(0),
        )
        .unwrap_or_else(|error| panic!("test capacity must be valid: {error}"));
        let lifecycle = LoopLifecycleBudgets::try_new(
            BoundedDuration::from_nanos(100_000),
            BoundedDuration::from_nanos(100_000),
            BoundedDuration::from_nanos(100_000),
        )
        .unwrap_or_else(|error| panic!("test lifecycle must be valid: {error}"));
        LoopDomainSpec::new(
            paraegox_runtime_contracts::execution::DomainRef::from_bytes([0x30; 16]),
            capacity,
            lifecycle,
        )
    }

    fn execution(binding: BindingAssignment) -> MailboxExecutionSpec {
        let requirements = LoopExecutionRequirements::try_new(
            CallModel::CooperativeAsync,
            WorkloadKind::Io,
            BlockingRisk::None,
            RunBoundProvenance::Measured,
            BoundedDuration::from_nanos(10_000),
        )
        .unwrap_or_else(|error| panic!("test requirements must be valid: {error}"));
        let callback = CallbackBudgets::try_new(
            BoundedDuration::from_nanos(50_000),
            BoundedDuration::from_nanos(50_000),
            OverrunAction::CooperativeCancel,
        )
        .unwrap_or_else(|error| panic!("test callback budget must be valid: {error}"));
        let dispatch =
            MailboxDispatchPolicy::try_new(DispatchClass::Interactive, 1, 1, 1, 1, callback)
                .unwrap_or_else(|error| panic!("test dispatch must be valid: {error}"));
        MailboxExecutionSpec::try_new(
            binding.binding_id(),
            binding.mailbox(),
            binding.target_instance(),
            domain().domain(),
            CardSubjectSpec::new(
                CARD_DEFINITION,
                CARD_IMPLEMENTATION,
                DEFINITION_DIGEST,
                ARTIFACT_DIGEST,
                CONFIG_DIGEST,
            ),
            requirements,
            dispatch,
        )
        .unwrap_or_else(|error| panic!("test execution must be valid: {error}"))
    }

    fn slice(
        bindings: Vec<BindingAssignment>,
        executions: Vec<MailboxExecutionSpec>,
    ) -> RuntimePlanSliceV2 {
        let bindings = TargetAssignments::try_new(bindings)
            .unwrap_or_else(|error| panic!("test assignments must be valid: {error}"));
        let execution = TargetExecutionPlan::try_new(vec![domain()], executions)
            .unwrap_or_else(|error| panic!("test execution plan must be valid: {error}"));
        let assignments = TargetPlanAssignments::try_new(bindings, execution)
            .unwrap_or_else(|error| panic!("test target plan must be valid: {error}"));
        let provenance = PlanProvenance::new(
            SourceScopeRef::from_bytes([0x31; 16]),
            SourcePlanRef::from_bytes([0x32; 16]),
            SourcePlanRevision::new(7),
            SourcePlanDigest::new(Digest32::from_bytes([0x33; 32])),
        );
        let header = RuntimeSliceHeader::new(HOST, provenance, assignments.assignment_digest());
        let commitment = RuntimeSliceCommitment::try_new(header)
            .unwrap_or_else(|error| panic!("test commitment must be valid: {error}"));
        RuntimePlanSliceV2::try_new(commitment, assignments)
            .unwrap_or_else(|error| panic!("test slice must be valid: {error}"))
    }

    fn message(identity: u8, binding: BindingAssignment, clock: RuntimeClock) -> ValidatedMessage {
        let deadline = clock
            .deadline_after(BoundedDuration::from_nanos(900_000))
            .unwrap_or_else(|error| panic!("test deadline must be valid: {error}"));
        let payload = PayloadHandle::try_from_vec(vec![identity, identity.wrapping_add(1)])
            .unwrap_or_else(|error| panic!("test payload must be valid: {error}"));
        ValidatedMessage::new(
            MessageId::from_bytes([identity; 16]),
            binding.target_spec().schema(),
            binding.target_spec().interaction(),
            None,
            deadline,
            payload,
        )
    }

    fn signed_control_fixture_profile() -> SignedControlFixtureProfile {
        let wire = fixture_hex_bytes("outer_wire_hex");
        let request = RuntimeApplyRequestV2::decode(&wire)
            .unwrap_or_else(|error| panic!("signed S4 fixture must decode: {error}"));
        let assignments = request.slice().assignments();
        let execution = assignments
            .execution()
            .mailbox_executions()
            .iter()
            .copied()
            .find(|execution| execution.dispatch_class() == DispatchClass::Control)
            .unwrap_or_else(|| panic!("signed S4 fixture must contain Control execution"));
        let binding = assignments
            .bindings()
            .as_slice()
            .iter()
            .copied()
            .find(|binding| binding.binding_id() == execution.binding_id())
            .unwrap_or_else(|| panic!("signed Control execution must reference one binding"));
        let domain = assignments
            .execution()
            .domains()
            .iter()
            .copied()
            .find(|domain| domain.domain() == execution.domain())
            .unwrap_or_else(|| panic!("signed Control execution must reference one domain"));
        let message_deadline_nanos = binding
            .delivery()
            .max_message_age()
            .value()
            .min(binding.mailbox_spec().max_queue_age().value());
        let start_threshold_nanos = message_deadline_nanos
            .checked_sub(execution.run_budget().value())
            .filter(|threshold| *threshold > 0)
            .unwrap_or_else(|| panic!("signed Control deadline must leave a positive start bound"));
        SignedControlFixtureProfile {
            binding,
            execution,
            domain,
            message_deadline_nanos,
            start_threshold: Duration::from_nanos(start_threshold_nanos),
        }
    }

    fn fixture_hex_bytes(field: &str) -> Vec<u8> {
        let marker = format!("\"{field}\": \"");
        let Some((_, tail)) = SIGNED_S4_EXECUTION_FIXTURE_JSON.split_once(&marker) else {
            panic!("fixture field must exist: {field}");
        };
        let Some((hex, _)) = tail.split_once('"') else {
            panic!("fixture hexadecimal field must terminate: {field}");
        };
        assert_eq!(hex.len() % 2, 0, "fixture field must contain full bytes");
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    const fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("fixture must contain hexadecimal digits"),
        }
    }

    fn diagnostic_peer_binding(
        identity: u8,
        control: BindingAssignment,
        message_deadline_nanos: u64,
    ) -> BindingAssignment {
        let source = PortSpec::new(
            PortDirection::Out,
            control.target_spec().schema(),
            control.target_spec().interaction(),
            PortCardinality::One,
        );
        let target = PortSpec::new(
            PortDirection::In,
            control.target_spec().schema(),
            control.target_spec().interaction(),
            PortCardinality::One,
        );
        let delivery = DeliveryProfile::try_new(
            128,
            BoundedDuration::from_nanos(message_deadline_nanos),
            OverflowPolicy::RejectNew,
        )
        .unwrap_or_else(|error| panic!("diagnostic delivery must be valid: {error}"));
        let mailbox = MailboxSpec::try_new(
            4,
            512,
            BoundedDuration::from_nanos(message_deadline_nanos),
            1,
            512,
            OverflowPolicy::RejectNew,
        )
        .unwrap_or_else(|error| panic!("diagnostic Mailbox must be valid: {error}"));
        BindingAssignment::try_new(
            BindingId::from_bytes([identity; 16]),
            PortEndpoint::new(
                InstanceRef::from_bytes([identity; 16]),
                PortRef::from_bytes([identity.wrapping_add(1); 16]),
                source,
            ),
            PortEndpoint::new(
                control.target_instance(),
                PortRef::from_bytes([identity.wrapping_add(2); 16]),
                target,
            ),
            MailboxRef::from_bytes([identity.wrapping_add(3); 16]),
            delivery,
            mailbox,
        )
        .unwrap_or_else(|error| panic!("diagnostic binding must be valid: {error}"))
    }

    fn diagnostic_domain(signed: LoopDomainSpec) -> LoopDomainSpec {
        let capacity_window = signed
            .capacity_window()
            .value()
            .checked_mul(3)
            .unwrap_or_else(|| panic!("diagnostic capacity window must fit"));
        let capacity = LoopDomainCapacity::try_new(
            signed.max_outstanding(),
            signed.control_reserved(),
            BoundedDuration::from_nanos(capacity_window),
            signed.control_reserved_run_budget(),
        )
        .unwrap_or_else(|error| panic!("diagnostic domain capacity must be valid: {error}"));
        LoopDomainSpec::new(signed.domain(), capacity, signed.lifecycle())
    }

    fn diagnostic_peer_execution(
        binding: BindingAssignment,
        control: MailboxExecutionSpec,
        domain: LoopDomainSpec,
        class: DispatchClass,
    ) -> MailboxExecutionSpec {
        const PEER_CALLBACK_BUDGET_NANOS: u64 = 20_000_000;
        let requirements = diagnostic_requirements();
        let callback = CallbackBudgets::try_new(
            BoundedDuration::from_nanos(PEER_CALLBACK_BUDGET_NANOS),
            BoundedDuration::from_nanos(PEER_CALLBACK_BUDGET_NANOS),
            OverrunAction::CooperativeCancel,
        )
        .unwrap_or_else(|error| panic!("diagnostic callback budget must be valid: {error}"));
        let dispatch = MailboxDispatchPolicy::try_new(class, 1, 1, 1, 1, callback)
            .unwrap_or_else(|error| panic!("diagnostic dispatch must be valid: {error}"));
        diagnostic_execution(binding, control, domain, requirements, dispatch)
    }

    fn diagnostic_requirements() -> LoopExecutionRequirements {
        LoopExecutionRequirements::try_new(
            CallModel::CooperativeAsync,
            WorkloadKind::Io,
            BlockingRisk::None,
            RunBoundProvenance::Measured,
            BoundedDuration::from_nanos(20_000_000),
        )
        .unwrap_or_else(|error| panic!("diagnostic requirements must be valid: {error}"))
    }

    fn diagnostic_control_execution(
        control_binding: BindingAssignment,
        signed: MailboxExecutionSpec,
        domain: LoopDomainSpec,
    ) -> MailboxExecutionSpec {
        let callback = CallbackBudgets::try_new(
            signed.run_budget(),
            signed.cleanup_budget(),
            signed.overrun_action(),
        )
        .unwrap_or_else(|error| panic!("signed callback budget must remain valid: {error}"));
        let dispatch = MailboxDispatchPolicy::try_new(
            signed.dispatch_class(),
            signed.service_cost_tokens(),
            signed.minimum_service_weight(),
            signed.max_burst(),
            signed.max_arrivals_per_window(),
            callback,
        )
        .unwrap_or_else(|error| panic!("signed Control dispatch must remain valid: {error}"));
        diagnostic_execution(
            control_binding,
            signed,
            domain,
            diagnostic_requirements(),
            dispatch,
        )
    }

    fn diagnostic_execution(
        binding: BindingAssignment,
        control: MailboxExecutionSpec,
        domain: LoopDomainSpec,
        requirements: LoopExecutionRequirements,
        dispatch: MailboxDispatchPolicy,
    ) -> MailboxExecutionSpec {
        MailboxExecutionSpec::try_new(
            binding.binding_id(),
            binding.mailbox(),
            binding.target_instance(),
            domain.domain(),
            CardSubjectSpec::new(
                control.card_definition(),
                control.card_implementation(),
                control.definition_digest(),
                control.artifact_digest(),
                control.config_digest(),
            ),
            requirements,
            dispatch,
        )
        .unwrap_or_else(|error| panic!("diagnostic execution must be valid: {error}"))
    }

    fn diagnostic_slice(
        bindings: Vec<BindingAssignment>,
        domain: LoopDomainSpec,
        executions: Vec<MailboxExecutionSpec>,
    ) -> RuntimePlanSliceV2 {
        let bindings = TargetAssignments::try_new(bindings)
            .unwrap_or_else(|error| panic!("diagnostic assignments must be valid: {error}"));
        let execution = TargetExecutionPlan::try_new(vec![domain], executions)
            .unwrap_or_else(|error| panic!("diagnostic execution plan must be valid: {error}"));
        let assignments = TargetPlanAssignments::try_new(bindings, execution)
            .unwrap_or_else(|error| panic!("diagnostic target plan must be valid: {error}"));
        let provenance = PlanProvenance::new(
            SourceScopeRef::from_bytes([0x51; 16]),
            SourcePlanRef::from_bytes([0x52; 16]),
            SourcePlanRevision::new(1),
            SourcePlanDigest::new(Digest32::from_bytes([0x53; 32])),
        );
        let header = RuntimeSliceHeader::new(HOST, provenance, assignments.assignment_digest());
        let commitment = RuntimeSliceCommitment::try_new(header)
            .unwrap_or_else(|error| panic!("diagnostic commitment must be valid: {error}"));
        RuntimePlanSliceV2::try_new(commitment, assignments)
            .unwrap_or_else(|error| panic!("diagnostic slice must be valid: {error}"))
    }

    fn diagnostic_message(
        identity: MessageId,
        binding: BindingAssignment,
        clock: RuntimeClock,
        message_deadline_nanos: u64,
    ) -> ValidatedMessage {
        let deadline = clock
            .deadline_after(BoundedDuration::from_nanos(message_deadline_nanos))
            .unwrap_or_else(|error| panic!("diagnostic deadline must be valid: {error}"));
        let payload = PayloadHandle::try_from_vec(identity.as_bytes().to_vec())
            .unwrap_or_else(|error| panic!("diagnostic payload must be valid: {error}"));
        ValidatedMessage::new(
            identity,
            binding.target_spec().schema(),
            binding.target_spec().interaction(),
            None,
            deadline,
            payload,
        )
    }

    fn offer_diagnostic_message(
        component: &mut SingleSubjectComponentRuntime,
        route: &LocalDiagnosticRoute,
        clock: RuntimeClock,
        message_deadline_nanos: u64,
        identity: MessageId,
    ) -> bool {
        component
            .try_offer(
                &route.ingress,
                diagnostic_message(identity, route.binding, clock, message_deadline_nanos),
            )
            .unwrap_or_else(|failure| panic!("diagnostic data offer failed: {}", failure.error()))
            .outcome()
            .is_admitted()
    }

    fn nearest_rank(samples: &mut [Duration], numerator: usize, denominator: usize) -> Duration {
        assert!(!samples.is_empty(), "latency samples must not be empty");
        assert!(numerator > 0 && numerator <= denominator);
        samples.sort_unstable();
        let rank = samples
            .len()
            .checked_mul(numerator)
            .and_then(|value| value.checked_add(denominator - 1))
            .and_then(|value| value.checked_div(denominator))
            .unwrap_or_else(|| panic!("latency percentile rank must fit"));
        samples[rank - 1]
    }

    fn maximum_service_gap(ordinals: &[usize], total_starts: usize) -> usize {
        let mut previous = 0;
        let mut maximum = 0;
        for ordinal in ordinals {
            maximum = maximum.max(ordinal.saturating_sub(previous).saturating_sub(1));
            previous = *ordinal;
        }
        maximum.max(total_starts.saturating_sub(previous))
    }

    #[tokio::test(start_paused = true)]
    async fn canonical_path_uses_real_binding_grant_fence_and_exact_zero_shutdown() {
        let active = binding(1, 0x41);
        let inert = binding(2, 0x42);
        let plan = slice(vec![active, inert], vec![execution(active)]);
        let runtime_clock = clock();
        let (selected, counters) = selected(CardBehavior {
            emit_output: true,
            panic_input: false,
            pending_start: false,
            pending_input: false,
            fail_input_after_cancellation: false,
            pending_stop: false,
        });
        let root = CancellationSource::root();
        let mut component =
            SingleSubjectComponentRuntime::try_new(&plan, selected, epochs(), runtime_clock, &root)
                .unwrap_or_else(|error| panic!("component must compose: {error}"));

        assert_eq!(component.planned_instance(), active.target_instance());
        assert!(component.active_ingress(active.binding_id()).is_some());
        assert!(component.active_ingress(inert.binding_id()).is_none());
        let initial = component
            .snapshot()
            .unwrap_or_else(|error| panic!("initial snapshot must hold: {error}"));
        assert_eq!(initial.mailbox_count(), 1);
        assert_eq!(initial.active_bindings(), 1);

        assert_eq!(component.start().await, Ok(CardStartOutcome::Started));
        let ingress = component
            .active_ingress(active.binding_id())
            .unwrap_or_else(|| panic!("referenced binding must be active"));
        let offer = component
            .try_offer(&ingress, message(1, active, runtime_clock))
            .unwrap_or_else(|failure| panic!("offer must succeed: {}", failure.error()));
        assert!(matches!(offer.outcome(), EnqueueOutcome::Admitted));

        let dispatch = component
            .dispatch_once()
            .await
            .unwrap_or_else(|error| panic!("dispatch must close ownership: {error}"));
        assert!(dispatch.pre_run_terminals().is_empty());
        assert!(matches!(
            dispatch.outcome(),
            ComponentDispatchOutcome::Invoked {
                callback: ComponentCallbackOutcome::Completed {
                    output_discarded: true
                },
                terminal,
            } if terminal.reason() == TerminalReason::Completed
        ));
        assert_eq!(counters.starts.load(Ordering::SeqCst), 1);
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 1);
        let after_dispatch = component
            .snapshot()
            .unwrap_or_else(|error| panic!("dispatch snapshot must hold: {error}"));
        assert_eq!(after_dispatch.queued_items(), 0);
        assert_eq!(after_dispatch.inflight_items(), 0);
        assert_eq!(after_dispatch.permits().in_use(), 0);

        let shutdown = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown must close exactly: {error}"));
        assert!(shutdown.cancelled().is_empty());
        assert!(shutdown.reconciled().is_empty());
        assert_eq!(shutdown.card(), CardStopOutcome::Stopped);
        assert!(shutdown.is_zero_cleanup());
        assert!(shutdown.domain().is_zero_cleanup());
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);

        let repeated = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("repeated shutdown must be idempotent: {error}"));
        assert!(repeated.reconciled().is_empty());
        assert!(repeated.cancelled().is_empty());
        assert_eq!(repeated.card(), CardStopOutcome::Stopped);
        assert!(repeated.is_zero_cleanup());
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn component_owned_dispatch_loop_drains_all_ready_work_without_manual_turns() {
        let active = binding(12, 0x4c);
        let plan = slice(vec![active], vec![execution(active)]);
        let runtime_clock = clock();
        let (selected, counters) = selected(CardBehavior {
            emit_output: false,
            panic_input: false,
            pending_start: false,
            pending_input: false,
            fail_input_after_cancellation: false,
            pending_stop: false,
        });
        let root = CancellationSource::root();
        let mut component =
            SingleSubjectComponentRuntime::try_new(&plan, selected, epochs(), runtime_clock, &root)
                .unwrap_or_else(|error| panic!("component must compose: {error}"));
        assert_eq!(component.start().await, Ok(CardStartOutcome::Started));
        let ingress = component
            .active_ingress(active.binding_id())
            .unwrap_or_else(|| panic!("referenced binding must be active"));
        for identity in [12, 13, 14] {
            component
                .try_offer(&ingress, message(identity, active, runtime_clock))
                .unwrap_or_else(|failure| panic!("queued offer must succeed: {}", failure.error()));
        }

        let batch = component
            .dispatch_ready_until_idle()
            .await
            .unwrap_or_else(|error| panic!("component dispatch loop must quiesce: {error}"));
        assert_eq!(batch.invoked(), 3);
        assert_eq!(batch.pre_run_terminals(), 0);
        assert_eq!(batch.idle(), DispatchIdleReason::NoReadyMailbox);
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 3);
        let quiescent = component
            .snapshot()
            .unwrap_or_else(|error| panic!("quiescent snapshot must hold: {error}"));
        assert_eq!(quiescent.queued_items(), 0);
        assert_eq!(quiescent.inflight_items(), 0);
        assert_eq!(quiescent.permits().in_use(), 0);
        assert_eq!(quiescent.retained_bytes(), 0);

        let shutdown = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("drained component must shut down: {error}"));
        assert!(shutdown.cancelled().is_empty());
        assert!(shutdown.reconciled().is_empty());
        assert!(shutdown.is_zero_cleanup());
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn manual_owner_turn_local_monotonic_diagnostic_measures_two_x_offer_pressure() {
        const PHASE_DISPATCH_STARTS: usize = 4_096;
        const DATA_OFFERS_PER_START: usize = 2;
        const CONTROL_INTERVAL: usize = 4;
        const EXPECTED_CONTROL_SAMPLES: usize = PHASE_DISPATCH_STARTS / CONTROL_INTERVAL;
        const LOCAL_BACKGROUND_MAXIMUM_GAP: usize = 64;

        // The current S4 component intentionally has one `&mut` owner and no
        // concurrent L2 ingress task/wakeup adapter. This local diagnostic
        // therefore interleaves two producer offer attempts with one real
        // component dispatch start in that owner task. It crosses the actual
        // PortBinding -> Mailbox -> LoopDomain -> Dispatcher -> Card callback
        // path on an unpaused current-thread Tokio reactor, but it is neither
        // target-platform evidence nor a post-idle ingress wakeup claim.
        let signed = signed_control_fixture_profile();
        let domain = diagnostic_domain(signed.domain);
        let stream = diagnostic_peer_binding(0xd1, signed.binding, signed.message_deadline_nanos);
        let background =
            diagnostic_peer_binding(0xd2, signed.binding, signed.message_deadline_nanos);
        let control_execution =
            diagnostic_control_execution(signed.binding, signed.execution, domain);
        let stream_execution =
            diagnostic_peer_execution(stream, control_execution, domain, DispatchClass::Stream);
        let background_execution = diagnostic_peer_execution(
            background,
            control_execution,
            domain,
            DispatchClass::Background,
        );
        let executions = [control_execution, stream_execution, background_execution];
        let plan = diagnostic_slice(
            vec![signed.binding, stream, background],
            domain,
            executions.to_vec(),
        );
        let probe = LocalDiagnosticProbe::new();
        let card_probe = probe.clone();
        let task_probe = probe.clone();
        let control_id = signed.binding.binding_id();
        let stream_id = stream.binding_id();
        let background_id = background.binding_id();
        let selected =
            TrustedCardImplementation::try_resolve_loop(&executions, move || LocalDiagnosticCard {
                probe: card_probe,
                control: control_id,
                stream: stream_id,
                background: background_id,
            })
            .unwrap_or_else(|error| panic!("diagnostic implementation must resolve: {error}"));

        let maximum = NonZeroUsize::new(1)
            .unwrap_or_else(|| panic!("diagnostic task capacity must be nonzero"));
        let mut tasks = TaskRegistry::new(maximum);
        let component_cancellation = tasks.root_cancellation().child();
        tasks
            .try_spawn(RuntimeTaskKind::ComponentLifecycle, move || async move {
                let runtime_clock = clock();
                let mut component = SingleSubjectComponentRuntime::try_new(
                    &plan,
                    selected,
                    epochs(),
                    runtime_clock,
                    &component_cancellation,
                )
                .unwrap_or_else(|error| panic!("diagnostic component must compose: {error}"));
                assert_eq!(component.start().await, Ok(CardStartOutcome::Started));
                let control_route = LocalDiagnosticRoute {
                    binding: signed.binding,
                    ingress: component
                        .active_ingress(signed.binding.binding_id())
                        .unwrap_or_else(|| panic!("diagnostic Control ingress must be active")),
                };
                let stream_route = LocalDiagnosticRoute {
                    binding: stream,
                    ingress: component
                        .active_ingress(stream.binding_id())
                        .unwrap_or_else(|| panic!("diagnostic Stream ingress must be active")),
                };
                let background_route = LocalDiagnosticRoute {
                    binding: background,
                    ingress: component
                        .active_ingress(background.binding_id())
                        .unwrap_or_else(|| panic!("diagnostic Background ingress must be active")),
                };
                let mut source = LocalDiagnosticL2SourceAdapter {
                    clock: runtime_clock,
                    control: control_route,
                    stream: stream_route,
                    background: background_route,
                    probe: task_probe.clone(),
                    message_deadline_nanos: signed.message_deadline_nanos,
                    next_message: 1,
                    data_offer_attempts: 0,
                    data_admitted: 0,
                    control_admitted: 0,
                };

                let mut phase_dispatch_starts = 0_u64;
                for turn in 0..PHASE_DISPATCH_STARTS {
                    source.offer_data_overload_turn(&mut component);
                    if turn % CONTROL_INTERVAL == 0 {
                        source.offer_control(&mut component);
                    }
                    tokio::task::yield_now().await;
                    let report = component.dispatch_once().await.unwrap_or_else(|error| {
                        panic!("diagnostic dispatch must retain ownership: {error}")
                    });
                    assert!(report.pre_run_terminals().is_empty());
                    assert!(matches!(
                        report.outcome(),
                        ComponentDispatchOutcome::Invoked {
                            callback: ComponentCallbackOutcome::Completed {
                                output_discarded: false
                            },
                            terminal,
                        } if terminal.reason() == TerminalReason::Completed
                    ));
                    phase_dispatch_starts += 1;
                }

                let background_ordinals = task_probe.background_ordinals();
                let background_starts_during_phase = background_ordinals.len();
                let last_background_ordinal = background_ordinals.last().copied().unwrap_or(0);
                let maximum_background_gap_during_phase =
                    maximum_service_gap(&background_ordinals, PHASE_DISPATCH_STARTS);
                let final_drain = component
                    .dispatch_ready_until_idle()
                    .await
                    .unwrap_or_else(|error| panic!("diagnostic final drain must quiesce: {error}"));
                assert_eq!(final_drain.idle(), DispatchIdleReason::NoReadyMailbox);
                let quiescent = component
                    .snapshot()
                    .unwrap_or_else(|error| panic!("diagnostic snapshot must hold: {error}"));
                assert_eq!(quiescent.queued_items(), 0);
                assert_eq!(quiescent.inflight_items(), 0);
                assert_eq!(quiescent.permits().in_use(), 0);
                assert_eq!(quiescent.retained_bytes(), 0);
                let shutdown = component
                    .shutdown()
                    .await
                    .unwrap_or_else(|error| panic!("diagnostic shutdown must close: {error}"));
                assert!(shutdown.reconciled().is_empty());
                assert!(shutdown.cancelled().is_empty());
                assert!(shutdown.domain().is_zero_cleanup());

                LocalDiagnosticRunSummary {
                    phase_dispatch_starts,
                    data_offer_attempts: source.data_offer_attempts,
                    data_admitted: source.data_admitted,
                    control_admitted: source.control_admitted,
                    background_starts_during_phase,
                    last_background_ordinal,
                    maximum_background_gap_during_phase,
                    final_drain_invoked: final_drain.invoked(),
                    exact_zero_shutdown: shutdown.is_zero_cleanup(),
                }
            })
            .unwrap_or_else(|error| panic!("diagnostic task must be admitted: {error}"));

        let completion = tokio::time::timeout(Duration::from_secs(30), tasks.join_next())
            .await
            .unwrap_or_else(|_| panic!("local diagnostic must finish within its harness bound"))
            .unwrap_or_else(|| panic!("diagnostic task completion must exist"));
        assert_eq!(completion.kind(), RuntimeTaskKind::ComponentLifecycle);
        let summary = match completion.into_outcome() {
            TaskOutcome::Completed(summary) => summary,
            TaskOutcome::Cancelled => panic!("diagnostic component task was cancelled"),
            TaskOutcome::Panicked => panic!("diagnostic component task panicked"),
        };
        assert!(tasks.is_empty(), "diagnostic Runtime task must be joined");
        assert_eq!(
            summary.phase_dispatch_starts,
            u64::try_from(PHASE_DISPATCH_STARTS)
                .unwrap_or_else(|_| panic!("phase dispatch count must fit"))
        );
        assert_eq!(
            summary.data_offer_attempts,
            summary.phase_dispatch_starts
                * u64::try_from(DATA_OFFERS_PER_START)
                    .unwrap_or_else(|_| panic!("offer ratio must fit"))
        );
        assert!(
            summary.data_admitted < summary.data_offer_attempts,
            "two-x offered pressure must exercise bounded refusal"
        );
        assert_eq!(
            summary.control_admitted,
            u64::try_from(EXPECTED_CONTROL_SAMPLES)
                .unwrap_or_else(|_| panic!("Control sample count must fit"))
        );
        assert!(summary.background_starts_during_phase > 0);
        assert!(
            summary.last_background_ordinal + LOCAL_BACKGROUND_MAXIMUM_GAP >= PHASE_DISPATCH_STARTS,
            "Background stopped too early: last ordinal={}",
            summary.last_background_ordinal
        );
        assert!(
            summary.maximum_background_gap_during_phase <= LOCAL_BACKGROUND_MAXIMUM_GAP,
            "Background service gap={} exceeds local diagnostic bound={LOCAL_BACKGROUND_MAXIMUM_GAP}",
            summary.maximum_background_gap_during_phase
        );
        assert!(summary.final_drain_invoked > 0);
        assert!(summary.exact_zero_shutdown);
        assert_eq!(probe.pending_control_samples(), 0);
        assert_eq!(probe.card_starts.load(Ordering::SeqCst), 1);
        assert_eq!(probe.card_stops.load(Ordering::SeqCst), 1);
        assert_eq!(
            probe.control_starts.load(Ordering::SeqCst),
            EXPECTED_CONTROL_SAMPLES
        );
        assert!(probe.stream_starts.load(Ordering::SeqCst) > 0);
        assert!(probe.background_starts.load(Ordering::SeqCst) > 0);

        let samples = probe.control_latencies();
        assert_eq!(samples.len(), EXPECTED_CONTROL_SAMPLES);
        let p99 = nearest_rank(&mut samples.clone(), 99, 100);
        let p999 = nearest_rank(&mut samples.clone(), 999, 1_000);
        assert!(
            p99 < signed.start_threshold,
            "local Control p99={p99:?}, signed-derived start threshold={:?}",
            signed.start_threshold
        );
        assert!(
            p999 < signed.start_threshold,
            "local Control p99.9={p999:?}, signed-derived start threshold={:?}",
            signed.start_threshold
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_cancels_queued_messages_without_constructing_input_callbacks() {
        let active = binding(3, 0x43);
        let plan = slice(vec![active], vec![execution(active)]);
        let runtime_clock = clock();
        let (selected, counters) = selected(CardBehavior {
            emit_output: false,
            panic_input: false,
            pending_start: false,
            pending_input: false,
            fail_input_after_cancellation: false,
            pending_stop: false,
        });
        let root = CancellationSource::root();
        let mut component =
            SingleSubjectComponentRuntime::try_new(&plan, selected, epochs(), runtime_clock, &root)
                .unwrap_or_else(|error| panic!("component must compose: {error}"));
        assert_eq!(component.start().await, Ok(CardStartOutcome::Started));
        let ingress = component
            .active_ingress(active.binding_id())
            .unwrap_or_else(|| panic!("referenced binding must be active"));
        for identity in [3, 4] {
            component
                .try_offer(&ingress, message(identity, active, runtime_clock))
                .unwrap_or_else(|failure| panic!("queued offer must succeed: {}", failure.error()));
        }

        let shutdown = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("queued shutdown must close: {error}"));
        assert_eq!(shutdown.cancelled().len(), 2);
        assert!(shutdown.reconciled().is_empty());
        assert!(
            shutdown
                .cancelled()
                .iter()
                .all(|terminal| terminal.reason() == TerminalReason::Cancelled)
        );
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 0);
        assert!(shutdown.is_zero_cleanup());
    }

    #[tokio::test(start_paused = true)]
    async fn callback_panic_still_returns_grant_and_reaches_exact_zero() {
        let active = binding(5, 0x45);
        let plan = slice(vec![active], vec![execution(active)]);
        let runtime_clock = clock();
        let (selected, counters) = selected(CardBehavior {
            emit_output: false,
            panic_input: true,
            pending_start: false,
            pending_input: false,
            fail_input_after_cancellation: false,
            pending_stop: false,
        });
        let root = CancellationSource::root();
        let mut component =
            SingleSubjectComponentRuntime::try_new(&plan, selected, epochs(), runtime_clock, &root)
                .unwrap_or_else(|error| panic!("component must compose: {error}"));
        assert_eq!(component.start().await, Ok(CardStartOutcome::Started));
        let ingress = component
            .active_ingress(active.binding_id())
            .unwrap_or_else(|| panic!("referenced binding must be active"));
        component
            .try_offer(&ingress, message(5, active, runtime_clock))
            .unwrap_or_else(|failure| panic!("panic input must enqueue: {}", failure.error()));

        let dispatch = component
            .dispatch_once()
            .await
            .unwrap_or_else(|error| panic!("panic must be an owned outcome: {error}"));
        assert!(matches!(
            dispatch.outcome(),
            ComponentDispatchOutcome::Invoked {
                callback: ComponentCallbackOutcome::Panicked,
                terminal,
            } if terminal.reason() == TerminalReason::Failed
        ));
        let reconciled = component
            .snapshot()
            .unwrap_or_else(|error| panic!("panic snapshot must reconcile: {error}"));
        assert_eq!(reconciled.inflight_items(), 0);
        assert_eq!(reconciled.permits().in_use(), 0);

        let shutdown = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("poisoned Card must still clean up: {error}"));
        assert!(shutdown.is_zero_cleanup());
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 1);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn root_cancellation_finishes_started_callback_and_shutdown_remains_exact_zero() {
        let active = binding(11, 0x4B);
        let plan = slice(vec![active], vec![execution(active)]);
        let runtime_clock = clock();
        let (selected, counters) = selected(CardBehavior {
            emit_output: false,
            panic_input: false,
            pending_start: false,
            pending_input: false,
            fail_input_after_cancellation: true,
            pending_stop: false,
        });
        let root = CancellationSource::root();
        let mut component =
            SingleSubjectComponentRuntime::try_new(&plan, selected, epochs(), runtime_clock, &root)
                .unwrap_or_else(|error| panic!("cancellable component must compose: {error}"));
        assert_eq!(component.start().await, Ok(CardStartOutcome::Started));
        let ingress = component
            .active_ingress(active.binding_id())
            .unwrap_or_else(|| panic!("cancellable binding must be active"));
        let offer = component
            .try_offer(&ingress, message(11, active, runtime_clock))
            .unwrap_or_else(|failure| {
                panic!("cancellable input must enqueue: {}", failure.error())
            });
        assert!(matches!(offer.outcome(), EnqueueOutcome::Admitted));

        let mut dispatch = Box::pin(component.dispatch_once());
        poll_fn(|context| {
            assert!(dispatch.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 1);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 0);

        root.cancel();
        let report = tokio::time::timeout(core::time::Duration::from_nanos(1), dispatch.as_mut())
            .await
            .unwrap_or_else(|_| panic!("root cancellation must wake the pending callback"))
            .unwrap_or_else(|error| panic!("cancelled dispatch must retain ownership: {error}"));
        assert!(report.pre_run_terminals().is_empty());
        assert!(matches!(
            report.outcome(),
            ComponentDispatchOutcome::Invoked {
                callback: ComponentCallbackOutcome::Failed(CallbackFailure::Failed),
                terminal,
            } if terminal.reason() == TerminalReason::Failed
        ));
        drop(dispatch);

        let after_dispatch = component
            .snapshot()
            .unwrap_or_else(|error| panic!("cancelled dispatch snapshot must hold: {error}"));
        assert_eq!(after_dispatch.queued_items(), 0);
        assert_eq!(after_dispatch.queued_bytes(), 0);
        assert_eq!(after_dispatch.inflight_items(), 0);
        assert_eq!(after_dispatch.inflight_bytes(), 0);
        assert_eq!(after_dispatch.permits().in_use(), 0);
        assert_eq!(after_dispatch.retained_bytes(), 0);

        let shutdown = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("cancelled component must shut down: {error}"));
        assert!(shutdown.reconciled().is_empty());
        assert!(shutdown.cancelled().is_empty());
        assert_eq!(shutdown.card(), CardStopOutcome::Stopped);
        assert!(shutdown.domain().is_zero_cleanup());
        assert!(shutdown.is_zero_cleanup());
        assert_eq!(counters.starts.load(Ordering::SeqCst), 1);
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 1);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);

        let repeated = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("repeated cancelled shutdown must stay zero: {error}"));
        assert_eq!(repeated.card(), CardStopOutcome::Stopped);
        assert!(repeated.domain().is_zero_cleanup());
        assert!(repeated.is_zero_cleanup());
        assert_eq!(repeated.domain().queued_items(), 0);
        assert_eq!(repeated.domain().inflight_items(), 0);
        assert_eq!(repeated.domain().permits().in_use(), 0);
        assert_eq!(repeated.domain().retained_bytes(), 0);
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 1);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_dispatch_future_is_reconciled_uncertain_before_card_cleanup() {
        let active = binding(8, 0x48);
        let plan = slice(vec![active], vec![execution(active)]);
        let runtime_clock = clock();
        let (selected, counters) = selected(CardBehavior {
            emit_output: false,
            panic_input: false,
            pending_start: false,
            pending_input: true,
            fail_input_after_cancellation: false,
            pending_stop: false,
        });
        let root = CancellationSource::root();
        let mut component =
            SingleSubjectComponentRuntime::try_new(&plan, selected, epochs(), runtime_clock, &root)
                .unwrap_or_else(|error| panic!("component must compose: {error}"));
        assert_eq!(component.start().await, Ok(CardStartOutcome::Started));
        let ingress = component
            .active_ingress(active.binding_id())
            .unwrap_or_else(|| panic!("referenced binding must be active"));
        component
            .try_offer(&ingress, message(8, active, runtime_clock))
            .unwrap_or_else(|failure| panic!("pending input must enqueue: {}", failure.error()));

        let mut dispatch = Box::pin(component.dispatch_once());
        poll_fn(|context| {
            assert!(dispatch.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(dispatch);

        let interrupted = component
            .snapshot()
            .unwrap_or_else(|error| panic!("interrupted snapshot must remain owned: {error}"));
        assert_eq!(interrupted.inflight_items(), 1);
        assert_eq!(interrupted.permits().in_use(), 1);
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 1);

        let shutdown = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("interrupted dispatch must reconcile: {error}"));
        assert_eq!(shutdown.reconciled().len(), 1);
        assert_eq!(shutdown.reconciled()[0].reason(), TerminalReason::Uncertain);
        assert!(shutdown.cancelled().is_empty());
        assert_eq!(shutdown.card(), CardStopOutcome::Stopped);
        assert!(shutdown.is_zero_cleanup());
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_start_future_is_poisoned_and_cleanup_still_reaches_zero() {
        let active = binding(9, 0x49);
        let plan = slice(vec![active], vec![execution(active)]);
        let (selected, counters) = selected(CardBehavior {
            emit_output: false,
            panic_input: false,
            pending_start: true,
            pending_input: false,
            fail_input_after_cancellation: false,
            pending_stop: false,
        });
        let root = CancellationSource::root();
        let mut component =
            SingleSubjectComponentRuntime::try_new(&plan, selected, epochs(), clock(), &root)
                .unwrap_or_else(|error| panic!("pending-start component must compose: {error}"));

        let mut start = Box::pin(component.start());
        poll_fn(|context| {
            assert!(start.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(start);
        assert_eq!(
            component.lifecycle(),
            crate::card_instance::CardLifecycle::Starting
        );

        let shutdown = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("interrupted start must clean up: {error}"));
        assert_eq!(shutdown.card(), CardStopOutcome::Stopped);
        assert!(shutdown.is_zero_cleanup());
        assert_eq!(counters.starts.load(Ordering::SeqCst), 1);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_stop_future_is_not_retried_or_laundered_by_later_shutdowns() {
        let active = binding(10, 0x4A);
        let plan = slice(vec![active], vec![execution(active)]);
        let (selected, counters) = selected(CardBehavior {
            emit_output: false,
            panic_input: false,
            pending_start: false,
            pending_input: false,
            fail_input_after_cancellation: false,
            pending_stop: true,
        });
        let root = CancellationSource::root();
        let mut component =
            SingleSubjectComponentRuntime::try_new(&plan, selected, epochs(), clock(), &root)
                .unwrap_or_else(|error| panic!("pending-stop component must compose: {error}"));
        assert_eq!(component.start().await, Ok(CardStartOutcome::Started));

        let mut first_shutdown = Box::pin(component.shutdown());
        poll_fn(|context| {
            assert!(first_shutdown.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first_shutdown);
        assert_eq!(
            component.lifecycle(),
            crate::card_instance::CardLifecycle::Stopping
        );

        let shutdown = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("interrupted stop must reconcile: {error}"));
        assert_eq!(shutdown.card(), CardStopOutcome::Interrupted);
        assert!(shutdown.domain().is_zero_cleanup());
        assert!(!shutdown.is_zero_cleanup());
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);

        let repeated = component
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("terminal interrupted stop must be stable: {error}"));
        assert_eq!(repeated.card(), CardStopOutcome::Interrupted);
        assert!(repeated.domain().is_zero_cleanup());
        assert!(!repeated.is_zero_cleanup());
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn constructor_rejects_multiple_planned_instances_before_installing_authority() {
        let first = binding(6, 0x46);
        let second = binding(7, 0x47);
        let plan = slice(
            vec![first, second],
            vec![execution(first), execution(second)],
        );
        let (selected, _) = selected(CardBehavior {
            emit_output: false,
            panic_input: false,
            pending_start: false,
            pending_input: false,
            fail_input_after_cancellation: false,
            pending_stop: false,
        });
        let root = CancellationSource::root();
        let result =
            SingleSubjectComponentRuntime::try_new(&plan, selected, epochs(), clock(), &root);
        assert!(matches!(
            result,
            Err(ComponentRuntimeError::RequiresOneCardSubject)
        ));
    }
}
