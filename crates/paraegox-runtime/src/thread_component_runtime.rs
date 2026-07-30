//! Crate-private local Harness joining one canonical Mailbox to ThreadDomain.
//!
//! This is not a Runtime apply endpoint, activation/readiness owner, public
//! Card runner, or process isolation boundary. It consumes one already-valid
//! PXTE v2 Thread subject, keeps `Mailbox` as the only semantic backlog, and
//! performs `queued -> inflight` only inside `ThreadDomain::try_submit`'s
//! post-reservation builder. A timeout or cancellation fences the returned
//! value and eventually records `Uncertain`; it never claims an OS thread was
//! terminated.

use core::fmt;
use core::time::Duration;
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::time::{ClockReading, MonotonicDeadline};
use paraegox_runtime_contracts::assignment::{
    BindingAssignment, BindingId, MailboxRef, PortRef, SchemaRef,
};
use paraegox_runtime_contracts::execution::{
    BlockingRisk, CallModel, CardDefinitionRef, CardImplementationRef, RunBoundProvenance,
    WorkloadKind,
};
use paraegox_runtime_contracts::thread_execution::{
    ExecutorBudgetSpec, RuntimePlanSliceV3, ThreadDomainSpec, ThreadExecutionRequirements,
    ThreadMailboxExecutionSpec,
};

use crate::card_instance::DomainEpoch;
use crate::executor_budget::ExecutorReservation;
use crate::mailbox::{
    DispatchOutcome, InflightToken, Mailbox, MailboxError, MailboxHeadReadiness, MailboxLifecycle,
    MailboxSnapshot, MessageId, OfferReport, TerminalReason, TerminalRecord, ValidatedMessage,
};
use crate::port_binding::{BindingEpoch, BindingOfferFailure, PortBinding, PortBindingError};
use crate::runtime_clock::{RuntimeClock, RuntimeClockError};
use crate::thread_domain::{
    LateResultReason, ThreadCancellation, ThreadCompletion, ThreadDomain, ThreadDomainBuildFailure,
    ThreadDomainConfig, ThreadDomainError, ThreadDomainJoinProof, ThreadDomainLifecycle,
    ThreadDomainShutdownReport, ThreadDomainSnapshot, ThreadInvocation,
    ThreadInvocationObservation,
};
use crate::thread_registry::{
    RuntimeThreadOwner, RuntimeThreadRegistry, ThreadOwnerHandle, ThreadOwnerShutdownError,
    ThreadRegistryError,
};

/// Trusted synchronous failure before any public Receipt/effect owner exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadCardFailure {
    Rejected,
    Failed,
}

/// Borrowed immutable input. It exposes no Mailbox, ThreadDomain, executor,
/// binding mutation, Tokio handle, or thread creation capability.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ThreadCardInputView<'a> {
    binding: BindingId,
    mailbox: MailboxRef,
    target_port: PortRef,
    message_id: MessageId,
    schema: SchemaRef,
    payload: &'a [u8],
}

impl<'a> ThreadCardInputView<'a> {
    fn new(
        binding: BindingId,
        mailbox: MailboxRef,
        target_port: PortRef,
        token: &'a InflightToken,
    ) -> Self {
        Self {
            binding,
            mailbox,
            target_port,
            message_id: token.message().id(),
            schema: token.message().schema(),
            payload: token.message().payload().as_bytes(),
        }
    }

    #[must_use]
    pub(crate) const fn binding(self) -> BindingId {
        self.binding
    }

    #[must_use]
    pub(crate) const fn mailbox(self) -> MailboxRef {
        self.mailbox
    }

    #[must_use]
    pub(crate) const fn target_port(self) -> PortRef {
        self.target_port
    }

    #[must_use]
    pub(crate) const fn message_id(self) -> MessageId {
        self.message_id
    }

    #[must_use]
    pub(crate) const fn schema(self) -> SchemaRef {
        self.schema
    }

    #[must_use]
    pub(crate) const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

/// Object-safe synchronous callback seam used only after trusted selection.
pub(crate) trait SynchronousThreadCard: Send {
    fn on_input(
        &mut self,
        cancellation: &ThreadCancellation,
        input: ThreadCardInputView<'_>,
    ) -> Result<(), ThreadCardFailure>;
}

/// Same-build review marker admitted only for one exact PXTE subject.
///
/// Implementations must not create threads, runtimes, detached work, hidden
/// queues, or retain the borrowed input. Unknown/native-unstable code belongs
/// in ProcessDomain even when it happens to implement this Rust trait.
pub(crate) trait TrustedSynchronousThreadCard: SynchronousThreadCard {
    const BOUND_CARD_DEFINITION: CardDefinitionRef;
    const BOUND_CARD_IMPLEMENTATION: CardImplementationRef;
    const BOUND_DEFINITION_DIGEST: Digest32;
    const BOUND_ARTIFACT_DIGEST: Digest32;
}

/// Exact trusted implementation selection. Construction is deferred until
/// all subject and Thread eligibility checks have passed.
pub(crate) struct TrustedThreadCardImplementation {
    execution: ThreadMailboxExecutionSpec,
    build: Box<dyn FnOnce() -> Box<dyn SynchronousThreadCard> + Send>,
}

impl TrustedThreadCardImplementation {
    pub(crate) fn try_resolve<Implementation, Build>(
        execution: ThreadMailboxExecutionSpec,
        build: Build,
    ) -> Result<Self, ThreadComponentRuntimeError>
    where
        Implementation: TrustedSynchronousThreadCard + 'static,
        Build: FnOnce() -> Implementation + Send + 'static,
    {
        let subject = execution.subject();
        if Implementation::BOUND_CARD_DEFINITION != subject.card_definition()
            || Implementation::BOUND_CARD_IMPLEMENTATION != subject.card_implementation()
            || Implementation::BOUND_DEFINITION_DIGEST != subject.definition_digest()
            || Implementation::BOUND_ARTIFACT_DIGEST != subject.artifact_digest()
        {
            return Err(ThreadComponentRuntimeError::ImplementationMismatch);
        }
        let requirements = execution.requirements();
        if requirements.call_model() != CallModel::Synchronous
            || !matches!(
                requirements.workload_kind(),
                WorkloadKind::Io | WorkloadKind::Native
            )
            || requirements.blocking_risk() != BlockingRisk::Bounded
            || !matches!(
                requirements.run_bound_provenance(),
                RunBoundProvenance::Measured | RunBoundProvenance::Certified
            )
        {
            return Err(ThreadComponentRuntimeError::IneligibleExecution);
        }
        Ok(Self {
            execution,
            build: Box::new(move || Box::new(build())),
        })
    }
}

/// Immutable canonical subset selected before any executor reservation exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ThreadComponentPlan {
    executor_budget: ExecutorBudgetSpec,
    domain: ThreadDomainSpec,
    execution: ThreadMailboxExecutionSpec,
    assignment: BindingAssignment,
}

impl ThreadComponentPlan {
    fn try_from_slice(slice: &RuntimePlanSliceV3) -> Result<Self, ThreadComponentRuntimeError> {
        slice
            .validate()
            .map_err(|_| ThreadComponentRuntimeError::InvalidExecutionSlice)?;
        let execution_plan = slice.assignments().execution();
        let [domain] = execution_plan.thread_domains() else {
            return Err(ThreadComponentRuntimeError::RequiresOneThreadDomain);
        };
        let [execution] = execution_plan.thread_mailbox_executions() else {
            return Err(ThreadComponentRuntimeError::RequiresOneThreadMailbox);
        };
        if execution.domain() != domain.domain() {
            return Err(ThreadComponentRuntimeError::ExecutionDomainMismatch);
        }
        let Some(assignment) = slice
            .assignments()
            .bindings()
            .as_slice()
            .iter()
            .copied()
            .find(|assignment| assignment.binding_id() == execution.binding_id())
        else {
            return Err(ThreadComponentRuntimeError::MissingBinding);
        };
        if assignment.mailbox() != execution.mailbox()
            || assignment.target_instance() != execution.target_instance()
        {
            return Err(ThreadComponentRuntimeError::ExecutionBindingMismatch);
        }
        if execution.requirements().native_thread_reservation() != 0 {
            return Err(ThreadComponentRuntimeError::NativeThreadsUnsupported);
        }
        Ok(Self {
            executor_budget: execution_plan.executor_budget(),
            domain: *domain,
            execution: *execution,
            assignment,
        })
    }
}

/// Fully prepared, thread-free component. The caller reserves global executor
/// capacity only after this phase succeeds.
pub(crate) struct PreparedThreadComponentRuntime {
    plan: ThreadComponentPlan,
    clock: RuntimeClock,
    mailbox: Mailbox,
    binding: PortBinding,
    binding_epoch: BindingEpoch,
    domain_config: ThreadDomainConfig,
    implementation: Box<dyn SynchronousThreadCard>,
}

impl PreparedThreadComponentRuntime {
    pub(crate) fn try_new(
        slice: &RuntimePlanSliceV3,
        selected: TrustedThreadCardImplementation,
        clock: RuntimeClock,
    ) -> Result<Self, ThreadComponentRuntimeError> {
        let plan = ThreadComponentPlan::try_from_slice(slice)?;
        if selected.execution != plan.execution {
            return Err(ThreadComponentRuntimeError::ImplementationMismatch);
        }
        // This first canonical seam moves one mutable implementation object
        // into at most one invocation. Accepting a wider domain would pretend
        // to satisfy utilization admitted against N-way parallel capacity.
        if plan.domain.worker_count() != 1 {
            return Err(ThreadComponentRuntimeError::UnsupportedTargetDomain);
        }
        let worker_count = usize::try_from(plan.domain.worker_count())
            .map_err(|_| ThreadComponentRuntimeError::UnsupportedTargetDomain)?;
        let domain_config =
            ThreadDomainConfig::try_new(worker_count, duration(plan.domain.start_budget().value()))
                .map_err(|_| ThreadComponentRuntimeError::UnsupportedTargetDomain)?;
        let target = plan.assignment.target_spec();
        let mailbox = Mailbox::try_new(
            plan.assignment.mailbox(),
            target.schema(),
            target.interaction(),
            plan.assignment.mailbox_spec(),
            clock.domain(),
            clock.generation(),
        )?;
        let mut binding = PortBinding::new(plan.assignment.binding_id());
        let prepared = binding.prepare(plan.assignment, &mailbox, None)?;
        let active = binding.activate(prepared, &mailbox, None)?;
        // P2e limitation: this trusted same-build factory, including a
        // rejected/pre-install value's Drop, still runs synchronously on the
        // assembly caller. It is therefore admitted only as finite,
        // nonblocking, and nonpanicking trusted code; it has no
        // ExecutorBudget or reactor-isolation claim. Unknown/native-unstable
        // construction belongs in ProcessDomain. Before production assembly,
        // P2e must move construction and rollback Drop behind a retained
        // Domain owner rather than treating this seam as full-lifecycle
        // constructor isolation.
        let implementation = catch_unwind(AssertUnwindSafe(selected.build))
            .map_err(|_| ThreadComponentRuntimeError::ImplementationConstructionPanicked)?;
        Ok(Self {
            plan,
            clock,
            mailbox,
            binding,
            binding_epoch: active.epoch(),
            domain_config,
            implementation,
        })
    }

    /// Internal fixed-worker construction used only by `install`; local tests
    /// call it directly to exercise linear rollback proofs.
    fn start(
        self,
        domain_epoch: DomainEpoch,
        reservation: ExecutorReservation,
    ) -> Result<ThreadComponentRuntime, ThreadDomainBuildFailure> {
        let domain = ThreadDomain::try_new(domain_epoch, self.domain_config, reservation)?;
        Ok(ThreadComponentRuntime::from_prepared(self, domain))
    }

    /// Installs the whole component as the registry's concrete lifecycle
    /// owner. No executor lease can escape this canonical path.
    pub(crate) fn install(
        self,
        registry: &mut RuntimeThreadRegistry,
        domain_epoch: DomainEpoch,
    ) -> Result<ThreadOwnerHandle<ThreadComponentRuntime>, ThreadRegistryError> {
        if registry.plan() != self.plan.executor_budget {
            return Err(ThreadRegistryError::ExecutorPlanMismatch);
        }
        let domain = self.plan.domain;
        let native_threads = self
            .plan
            .execution
            .requirements()
            .native_thread_reservation();
        registry.try_create_owner(domain, native_threads, move |reservation| {
            self.start(domain_epoch, reservation)
        })
    }
}

/// Exact ingress capability for this one active binding generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadComponentIngress {
    binding: BindingId,
    epoch: BindingEpoch,
}

/// Component-local lifecycle; `Accepting` is not a P2e readiness claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadComponentLifecycle {
    Accepting,
    Poisoned,
    Closing,
    Closed,
}

enum ThreadWorkerResult {
    Invoked {
        implementation: Box<dyn SynchronousThreadCard>,
        token: InflightToken,
        callback: Result<(), ThreadCardFailure>,
        expired: Vec<TerminalRecord>,
    },
    CallbackPanicked {
        implementation: Box<dyn SynchronousThreadCard>,
        token: InflightToken,
        expired: Vec<TerminalRecord>,
    },
    NoInvocation {
        implementation: Option<Box<dyn SynchronousThreadCard>>,
        expired: Vec<TerminalRecord>,
        error: Option<ThreadComponentRuntimeError>,
    },
    MissingImplementation {
        token: InflightToken,
        expired: Vec<TerminalRecord>,
    },
    DisposeImplementation {
        implementation: Option<Box<dyn SynchronousThreadCard>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingTimeoutPhase {
    Running,
    CancellationRequested,
    Uncertain,
    Wedged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingTiming {
    run_deadline: MonotonicDeadline,
    uncertain_deadline: MonotonicDeadline,
    phase: PendingTimeoutPhase,
}

/// One nonblocking dispatch admission decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ThreadComponentDispatchOutcome {
    Started,
    Idle(ThreadComponentIdleReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadComponentIdleReason {
    Empty,
    MailboxPermitUnavailable,
    Closed,
}

/// Owner observation for the one active synchronous invocation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ThreadComponentPollOutcome {
    Pending(ThreadInvocationObservation),
    Completed {
        callback: Result<(), ThreadCardFailure>,
        terminal: TerminalRecord,
        expired: Vec<TerminalRecord>,
    },
    NoInvocation {
        expired: Vec<TerminalRecord>,
    },
    LateRejected {
        reason: LateResultReason,
        uncertain: Vec<TerminalRecord>,
    },
    Panicked {
        uncertain: Vec<TerminalRecord>,
    },
}

/// Preserves Message ownership when the exact active ingress rejects it.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ThreadComponentOfferFailure {
    error: ThreadComponentRuntimeError,
    message: Box<ValidatedMessage>,
}

impl ThreadComponentOfferFailure {
    fn new(error: ThreadComponentRuntimeError, message: ValidatedMessage) -> Self {
        Self {
            error,
            message: Box::new(message),
        }
    }

    #[must_use]
    pub(crate) const fn error(&self) -> ThreadComponentRuntimeError {
        self.error
    }

    pub(crate) fn into_message(self) -> ValidatedMessage {
        *self.message
    }
}

/// Sole local owner for one canonical Thread Card, Mailbox, binding, and fixed
/// ThreadDomain generation.
pub(crate) struct ThreadComponentRuntime {
    plan: ThreadComponentPlan,
    clock: RuntimeClock,
    mailbox: Mailbox,
    binding: PortBinding,
    active_binding_epoch: Option<BindingEpoch>,
    lifecycle: ThreadComponentLifecycle,
    implementation: Option<Box<dyn SynchronousThreadCard>>,
    domain: ThreadDomain<ThreadWorkerResult>,
    pending: Option<ThreadInvocation<ThreadWorkerResult>>,
    pending_timing: Option<PendingTiming>,
}

impl ThreadComponentRuntime {
    fn from_prepared(
        prepared: PreparedThreadComponentRuntime,
        domain: ThreadDomain<ThreadWorkerResult>,
    ) -> Self {
        Self {
            plan: prepared.plan,
            clock: prepared.clock,
            mailbox: prepared.mailbox,
            binding: prepared.binding,
            active_binding_epoch: Some(prepared.binding_epoch),
            lifecycle: ThreadComponentLifecycle::Accepting,
            implementation: Some(prepared.implementation),
            domain,
            pending: None,
            pending_timing: None,
        }
    }

    #[must_use]
    pub(crate) const fn lifecycle(&self) -> ThreadComponentLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub(crate) fn active_ingress(&self) -> Option<ThreadComponentIngress> {
        self.active_binding_epoch
            .map(|epoch| ThreadComponentIngress {
                binding: self.plan.assignment.binding_id(),
                epoch,
            })
    }

    pub(crate) fn mailbox_snapshot(&self) -> Result<MailboxSnapshot, ThreadComponentRuntimeError> {
        self.mailbox.snapshot().map_err(Into::into)
    }

    #[must_use]
    pub(crate) fn domain_snapshot(&self) -> ThreadDomainSnapshot {
        self.domain.snapshot()
    }

    pub(crate) fn try_offer(
        &mut self,
        ingress: ThreadComponentIngress,
        message: ValidatedMessage,
    ) -> Result<OfferReport, ThreadComponentOfferFailure> {
        if self.lifecycle != ThreadComponentLifecycle::Accepting {
            return Err(ThreadComponentOfferFailure::new(
                ThreadComponentRuntimeError::InvalidLifecycle,
                message,
            ));
        }
        let reading = match self.clock.reading() {
            Ok(reading) => reading,
            Err(error) => {
                return Err(ThreadComponentOfferFailure::new(error.into(), message));
            }
        };
        self.binding
            .offer(
                ingress.binding,
                ingress.epoch,
                message,
                &mut self.mailbox,
                reading,
            )
            .map_err(|failure| {
                ThreadComponentOfferFailure::new(failure.error().into(), failure.into_message())
            })
    }

    /// Reserves a worker before the builder is called. Consequently every
    /// capacity rejection leaves the Mailbox head queued and never invokes or
    /// moves the implementation object.
    pub(crate) fn try_dispatch_once(
        &mut self,
    ) -> Result<ThreadComponentDispatchOutcome, ThreadComponentRuntimeError> {
        if self.lifecycle != ThreadComponentLifecycle::Accepting
            || self.pending.is_some()
            || self.pending_timing.is_some()
        {
            return Err(ThreadComponentRuntimeError::InvalidLifecycle);
        }
        let reading = self.clock.reading()?;
        match self.mailbox.head_readiness(reading)? {
            MailboxHeadReadiness::Empty => {
                return Ok(ThreadComponentDispatchOutcome::Idle(
                    ThreadComponentIdleReason::Empty,
                ));
            }
            MailboxHeadReadiness::NoPermit(_) => {
                return Ok(ThreadComponentDispatchOutcome::Idle(
                    ThreadComponentIdleReason::MailboxPermitUnavailable,
                ));
            }
            MailboxHeadReadiness::Closed => {
                return Ok(ThreadComponentDispatchOutcome::Idle(
                    ThreadComponentIdleReason::Closed,
                ));
            }
            MailboxHeadReadiness::Ready(_) | MailboxHeadReadiness::Expired { .. } => {}
        }

        let mailbox = &mut self.mailbox;
        let implementation_cell = Arc::new(Mutex::new(self.implementation.take()));
        let worker_cell = Arc::clone(&implementation_cell);
        let binding = self.plan.assignment.binding_id();
        let mailbox_ref = self.plan.assignment.mailbox();
        let target_port = self.plan.assignment.target_port();
        let clock = self.clock;
        let requirements = self.plan.execution.requirements();
        let pending_timing = &mut self.pending_timing;
        let invocation = self.domain.try_submit(|| {
            let (dispatch_reading, timing) = match build_pending_timing(clock, requirements) {
                Ok(value) => value,
                Err(error) => {
                    let callable: Box<dyn FnOnce(ThreadCancellation) -> ThreadWorkerResult + Send> =
                        Box::new(move |_| ThreadWorkerResult::NoInvocation {
                            implementation: take_thread_card(&worker_cell),
                            expired: Vec::new(),
                            error: Some(error),
                        });
                    return callable;
                }
            };
            let dispatch = mailbox.try_begin_inflight(dispatch_reading);
            let callable: Box<dyn FnOnce(ThreadCancellation) -> ThreadWorkerResult + Send> =
                match dispatch {
                    Ok(report) => {
                        let (outcome, expired) = report.into_parts();
                        match outcome {
                            DispatchOutcome::Started(token) => {
                                *pending_timing = Some(timing);
                                Box::new(move |cancellation| {
                                    let Some(mut implementation) = take_thread_card(&worker_cell)
                                    else {
                                        return ThreadWorkerResult::MissingImplementation {
                                            token,
                                            expired,
                                        };
                                    };
                                    let input = ThreadCardInputView::new(
                                        binding,
                                        mailbox_ref,
                                        target_port,
                                        &token,
                                    );
                                    // Catch the callback while the Card
                                    // remains owned outside the unwind. A
                                    // panicking Card destructor can then only
                                    // run later in ThreadDomain's charged
                                    // cleanup catch, never as a second panic
                                    // during callback unwind.
                                    match catch_unwind(AssertUnwindSafe(|| {
                                        implementation.on_input(&cancellation, input)
                                    })) {
                                        Ok(callback) => ThreadWorkerResult::Invoked {
                                            implementation,
                                            token,
                                            callback,
                                            expired,
                                        },
                                        Err(_) => ThreadWorkerResult::CallbackPanicked {
                                            implementation,
                                            token,
                                            expired,
                                        },
                                    }
                                })
                            }
                            DispatchOutcome::NoQueuedMessage
                            | DispatchOutcome::NoPermit
                            | DispatchOutcome::Closed => {
                                Box::new(move |_| ThreadWorkerResult::NoInvocation {
                                    implementation: take_thread_card(&worker_cell),
                                    expired,
                                    error: None,
                                })
                            }
                        }
                    }
                    Err(error) => Box::new(move |_| ThreadWorkerResult::NoInvocation {
                        implementation: take_thread_card(&worker_cell),
                        expired: Vec::new(),
                        error: Some(error.into()),
                    }),
                };
            callable
        });
        match invocation {
            Ok(invocation) => {
                self.pending = Some(invocation);
                Ok(ThreadComponentDispatchOutcome::Started)
            }
            Err(error) => {
                self.implementation = take_thread_card(&implementation_cell);
                if self.implementation.is_none() {
                    self.lifecycle = ThreadComponentLifecycle::Poisoned;
                    let _ = self.mailbox.stop_accepting();
                    return Err(ThreadComponentRuntimeError::ImplementationUnavailable);
                }
                if matches!(
                    error,
                    ThreadDomainError::CapacityExhausted
                        | ThreadDomainError::DomainDegraded
                        | ThreadDomainError::DomainClosing
                        | ThreadDomainError::DomainPoisoned
                ) {
                    return Err(error.into());
                }
                self.pending_timing = None;
                self.lifecycle = ThreadComponentLifecycle::Poisoned;
                let _ = self.mailbox.stop_accepting();
                Err(error.into())
            }
        }
    }

    pub(crate) fn request_pending_cancellation(
        &mut self,
    ) -> Result<(), ThreadComponentRuntimeError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(ThreadComponentRuntimeError::MissingPendingInvocation)?;
        if matches!(
            self.pending_timing.map(|timing| timing.phase),
            Some(
                PendingTimeoutPhase::CancellationRequested
                    | PendingTimeoutPhase::Uncertain
                    | PendingTimeoutPhase::Wedged
            )
        ) {
            return Ok(());
        }
        let reading = self.clock.reading()?;
        let uncertain_deadline = reading
            .try_deadline_after(self.plan.execution.requirements().cancellation_grace())
            .map_err(RuntimeClockError::Time)?;
        self.domain.request_cancellation(pending)?;
        if let Some(timing) = self.pending_timing.as_mut() {
            timing.uncertain_deadline = uncertain_deadline;
            timing.phase = PendingTimeoutPhase::CancellationRequested;
        } else {
            self.pending_timing = Some(PendingTiming {
                run_deadline: uncertain_deadline,
                uncertain_deadline,
                phase: PendingTimeoutPhase::CancellationRequested,
            });
        }
        self.lifecycle = ThreadComponentLifecycle::Poisoned;
        Ok(())
    }

    pub(crate) fn mark_pending_uncertain(&mut self) -> Result<(), ThreadComponentRuntimeError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(ThreadComponentRuntimeError::MissingPendingInvocation)?;
        if matches!(
            self.pending_timing.map(|timing| timing.phase),
            Some(PendingTimeoutPhase::Uncertain | PendingTimeoutPhase::Wedged)
        ) {
            return Ok(());
        }
        self.domain.mark_uncertain(pending)?;
        if let Some(timing) = self.pending_timing.as_mut() {
            timing.phase = PendingTimeoutPhase::Uncertain;
        }
        self.lifecycle = ThreadComponentLifecycle::Poisoned;
        Ok(())
    }

    pub(crate) fn mark_pending_wedged(&mut self) -> Result<(), ThreadComponentRuntimeError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(ThreadComponentRuntimeError::MissingPendingInvocation)?;
        if matches!(
            self.pending_timing.map(|timing| timing.phase),
            Some(PendingTimeoutPhase::Wedged)
        ) {
            return Ok(());
        }
        self.domain.mark_wedged(pending)?;
        if let Some(timing) = self.pending_timing.as_mut() {
            timing.phase = PendingTimeoutPhase::Wedged;
        }
        self.lifecycle = ThreadComponentLifecycle::Poisoned;
        Ok(())
    }

    pub(crate) fn poll_pending(
        &mut self,
    ) -> Result<ThreadComponentPollOutcome, ThreadComponentRuntimeError> {
        // ThreadDomain's ResultPending observation has no trusted completion
        // timestamp in this RuntimeClock generation. Advance the signed fence
        // first: accepting a result merely because the owner polled late could
        // otherwise launder a callback that actually returned after its bound.
        self.advance_signed_timeout()?;
        let pending = self
            .pending
            .as_mut()
            .ok_or(ThreadComponentRuntimeError::MissingPendingInvocation)?;
        match self.domain.try_take_completion(pending)? {
            ThreadCompletion::Pending(observation) => {
                Ok(ThreadComponentPollOutcome::Pending(observation))
            }
            ThreadCompletion::Returned(result) => {
                self.pending = None;
                self.pending_timing = None;
                self.finish_worker_result(result)
            }
            ThreadCompletion::Panicked => {
                self.pending = None;
                self.pending_timing = None;
                self.lifecycle = ThreadComponentLifecycle::Poisoned;
                let uncertain = self.abandon_inflight_uncertain()?;
                Ok(ThreadComponentPollOutcome::Panicked { uncertain })
            }
            ThreadCompletion::LateRejected(reason) => {
                self.pending = None;
                self.pending_timing = None;
                self.lifecycle = ThreadComponentLifecycle::Poisoned;
                let uncertain = self.abandon_inflight_uncertain()?;
                Ok(ThreadComponentPollOutcome::LateRejected { reason, uncertain })
            }
        }
    }

    /// Stops ingress and the fixed worker census. An incomplete report carries
    /// no join proof and the caller must retain this owner for a later retry or
    /// process-level recovery.
    pub(crate) fn shutdown_for(
        &mut self,
        budget: Duration,
    ) -> Result<ThreadComponentShutdownOutcome, ThreadComponentRuntimeError> {
        if self.lifecycle == ThreadComponentLifecycle::Closed {
            return Err(ThreadComponentRuntimeError::InvalidLifecycle);
        }
        self.lifecycle = ThreadComponentLifecycle::Closing;
        let mut terminals = Vec::new();
        if let Some(active) = self.active_binding_epoch.take() {
            self.binding.revoke(active, &mut self.mailbox)?;
        } else if self.mailbox.snapshot()?.lifecycle() == MailboxLifecycle::Accepting {
            self.mailbox.stop_accepting()?;
        }
        terminals.extend(self.mailbox.cancel_all_queued()?);
        if let Some(pending) = self.pending.as_ref()
            && !matches!(
                self.pending_timing.map(|timing| timing.phase),
                Some(PendingTimeoutPhase::Wedged)
            )
        {
            match self.domain.mark_uncertain(pending) {
                Ok(()) | Err(ThreadDomainError::InvocationNotActive) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.submit_final_implementation_cleanup()?;
        let signed_drain_budget = duration(self.plan.domain.drain_budget().value());
        let domain = self.domain.shutdown_for(budget.min(signed_drain_budget));
        if !domain.complete() {
            return Ok(ThreadComponentShutdownOutcome::Incomplete { domain, terminals });
        }
        self.pending = None;
        self.pending_timing = None;
        terminals.extend(self.mailbox.abandon_all_inflight_uncertain()?);
        if !self.mailbox.close_if_drained()? {
            return Err(ThreadComponentRuntimeError::NonZeroShutdown);
        }
        if let Some(draining) = self.binding.draining() {
            self.binding
                .retire_draining(draining.epoch(), &self.mailbox)?;
        }
        let mailbox = self.mailbox.snapshot()?;
        if mailbox.queued_items() != 0
            || mailbox.inflight_items() != 0
            || mailbox.retained_bytes() != 0
            || mailbox.lifecycle() != MailboxLifecycle::Closed
            || domain.snapshot().panicked_workers() != 0
            || domain.snapshot().cleanup_panics() != 0
            || self.implementation.is_some()
        {
            return Err(ThreadComponentRuntimeError::NonZeroShutdown);
        }
        let join_proof = self.domain.take_join_proof()?;
        self.lifecycle = ThreadComponentLifecycle::Closed;
        Ok(ThreadComponentShutdownOutcome::Complete(Box::new(
            ThreadComponentShutdownReport {
                terminals,
                mailbox,
                domain: domain.snapshot(),
                join_proof: Some(join_proof),
            },
        )))
    }

    fn submit_final_implementation_cleanup(&mut self) -> Result<(), ThreadComponentRuntimeError> {
        if self.pending.is_some() || self.implementation.is_none() {
            return Ok(());
        }

        // Keep a caller-side strong reference until direct dispatch succeeds.
        // A reservation or dispatch failure can therefore restore the Card to
        // this owner without running its destructor on the owner/reactor
        // thread. After success the worker closure is the remaining owner.
        let implementation = self
            .implementation
            .take()
            .ok_or(ThreadComponentRuntimeError::ImplementationUnavailable)?;
        let cell = Arc::new(Mutex::new(Some(implementation)));
        let worker_cell = Arc::clone(&cell);
        let submitted = self.domain.try_submit(|| {
            move |_| {
                let mut implementation = match worker_cell.lock() {
                    Ok(implementation) => implementation,
                    Err(poisoned) => poisoned.into_inner(),
                };
                ThreadWorkerResult::DisposeImplementation {
                    implementation: implementation.take(),
                }
            }
        });
        match submitted {
            Ok(invocation) => {
                self.pending = Some(invocation);
                self.pending_timing = None;
                Ok(())
            }
            Err(error) => {
                let mut implementation = match cell.lock() {
                    Ok(implementation) => implementation,
                    Err(poisoned) => poisoned.into_inner(),
                };
                self.implementation = implementation.take();
                Err(error.into())
            }
        }
    }

    fn finish_worker_result(
        &mut self,
        result: ThreadWorkerResult,
    ) -> Result<ThreadComponentPollOutcome, ThreadComponentRuntimeError> {
        match result {
            ThreadWorkerResult::Invoked {
                implementation,
                token,
                callback,
                expired,
            } => {
                self.implementation = Some(implementation);
                let reason = if callback.is_ok() {
                    TerminalReason::Completed
                } else {
                    TerminalReason::Failed
                };
                let terminal = self
                    .mailbox
                    .finish(token, reason)
                    .map_err(|failure| failure.error())?;
                Ok(ThreadComponentPollOutcome::Completed {
                    callback,
                    terminal,
                    expired,
                })
            }
            ThreadWorkerResult::CallbackPanicked {
                implementation,
                token,
                expired,
            } => {
                self.implementation = Some(implementation);
                self.lifecycle = ThreadComponentLifecycle::Poisoned;
                if self.mailbox.snapshot()?.lifecycle() == MailboxLifecycle::Accepting {
                    self.mailbox.stop_accepting()?;
                }
                let terminal = self
                    .mailbox
                    .finish(token, TerminalReason::Uncertain)
                    .map_err(|failure| failure.error())?;
                let mut uncertain = expired;
                uncertain.push(terminal);
                Ok(ThreadComponentPollOutcome::Panicked { uncertain })
            }
            ThreadWorkerResult::NoInvocation {
                implementation,
                expired,
                error,
            } => {
                let Some(implementation) = implementation else {
                    self.lifecycle = ThreadComponentLifecycle::Poisoned;
                    return Err(ThreadComponentRuntimeError::ImplementationUnavailable);
                };
                self.implementation = Some(implementation);
                if let Some(error) = error {
                    self.lifecycle = ThreadComponentLifecycle::Poisoned;
                    return Err(error);
                }
                Ok(ThreadComponentPollOutcome::NoInvocation { expired })
            }
            ThreadWorkerResult::MissingImplementation { token, expired } => {
                self.lifecycle = ThreadComponentLifecycle::Poisoned;
                let terminal = self
                    .mailbox
                    .finish(token, TerminalReason::Uncertain)
                    .map_err(|failure| failure.error())?;
                let mut uncertain = expired;
                uncertain.push(terminal);
                Ok(ThreadComponentPollOutcome::LateRejected {
                    reason: LateResultReason::Uncertain,
                    uncertain,
                })
            }
            ThreadWorkerResult::DisposeImplementation { implementation } => {
                // Shutdown fences this result, so normal polling must never
                // accept it. Restore ownership before failing closed rather
                // than destructing a Card on the owner/reactor thread.
                self.implementation = implementation;
                self.lifecycle = ThreadComponentLifecycle::Poisoned;
                Err(ThreadComponentRuntimeError::InvalidLifecycle)
            }
        }
    }

    fn advance_signed_timeout(&mut self) -> Result<(), ThreadComponentRuntimeError> {
        let Some(mut timing) = self.pending_timing else {
            return Ok(());
        };
        let reading = self.clock.reading()?;
        if timing.phase == PendingTimeoutPhase::Running
            && timing
                .run_deadline
                .is_expired_at(reading)
                .map_err(RuntimeClockError::Time)?
        {
            let pending = self
                .pending
                .as_ref()
                .ok_or(ThreadComponentRuntimeError::MissingPendingInvocation)?;
            self.domain.request_cancellation(pending)?;
            timing.phase = PendingTimeoutPhase::CancellationRequested;
            self.lifecycle = ThreadComponentLifecycle::Poisoned;
        }
        if timing.phase == PendingTimeoutPhase::CancellationRequested
            && timing
                .uncertain_deadline
                .is_expired_at(reading)
                .map_err(RuntimeClockError::Time)?
        {
            let pending = self
                .pending
                .as_ref()
                .ok_or(ThreadComponentRuntimeError::MissingPendingInvocation)?;
            match self.domain.mark_wedged(pending) {
                Ok(()) => {
                    timing.phase = PendingTimeoutPhase::Wedged;
                    self.lifecycle = ThreadComponentLifecycle::Poisoned;
                }
                // A result that became pending before the second fence has
                // already been rejected under the cancellation fence. Polling
                // below will consume that explicit late-result observation.
                Err(ThreadDomainError::InvocationNotActive) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.pending_timing = Some(timing);
        Ok(())
    }

    fn abandon_inflight_uncertain(
        &mut self,
    ) -> Result<Vec<TerminalRecord>, ThreadComponentRuntimeError> {
        if self.mailbox.snapshot()?.lifecycle() == MailboxLifecycle::Accepting {
            self.mailbox.stop_accepting()?;
        }
        self.mailbox
            .abandon_all_inflight_uncertain()
            .map_err(Into::into)
    }
}

impl Drop for ThreadComponentRuntime {
    fn drop(&mut self) {
        // Normal registry shutdown consumes a join proof before this fallback
        // runs. On abnormal scope/registry Drop, transfer an idle Card to the
        // direct worker cell first; ThreadDomain's own Drop then fences, joins,
        // and performs the destructor under the charged cleanup catch.
        if self.pending.is_none() && self.implementation.is_some() {
            let _ = self.submit_final_implementation_cleanup();
        }
        if let Some(implementation) = self.implementation.take() {
            // No worker accepted ownership. Running an unknown blocking or
            // panicking destructor on the owner/reactor would violate the
            // execution boundary. Leak is the explicit last-resort
            // process-recovery posture; the trusted factory limitation above
            // is the only pre-install exception.
            std::mem::forget(implementation);
        }
    }
}

impl RuntimeThreadOwner for ThreadComponentRuntime {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn domain_snapshot(&self) -> ThreadDomainSnapshot {
        ThreadComponentRuntime::domain_snapshot(self)
    }

    fn shutdown_and_prove(
        &mut self,
        budget: Duration,
    ) -> Result<ThreadDomainJoinProof, ThreadOwnerShutdownError> {
        let outcome = ThreadComponentRuntime::shutdown_for(self, budget)
            .map_err(|_| ThreadOwnerShutdownError::Failed)?;
        let mut report = match outcome {
            ThreadComponentShutdownOutcome::Complete(report) => report,
            ThreadComponentShutdownOutcome::Incomplete { domain, .. }
                if domain.snapshot().cleanup_panics() != 0
                    || domain.snapshot().panicked_workers() != 0 =>
            {
                return Err(ThreadOwnerShutdownError::Failed);
            }
            ThreadComponentShutdownOutcome::Incomplete { .. } => {
                return Err(ThreadOwnerShutdownError::Incomplete);
            }
        };
        if !report.is_zero_cleanup() {
            return Err(ThreadOwnerShutdownError::Failed);
        }
        report
            .take_join_proof()
            .map_err(|_| ThreadOwnerShutdownError::Failed)
    }
}

/// Shutdown result retaining the owner when any OS worker is still live.
pub(crate) enum ThreadComponentShutdownOutcome {
    Incomplete {
        domain: ThreadDomainShutdownReport,
        terminals: Vec<TerminalRecord>,
    },
    Complete(Box<ThreadComponentShutdownReport>),
}

/// Exact-zero Mailbox and joined-thread evidence. The join proof is linear and
/// must be transferred to the global ExecutorBudget owner.
pub(crate) struct ThreadComponentShutdownReport {
    terminals: Vec<TerminalRecord>,
    mailbox: MailboxSnapshot,
    domain: ThreadDomainSnapshot,
    join_proof: Option<ThreadDomainJoinProof>,
}

impl ThreadComponentShutdownReport {
    #[must_use]
    pub(crate) fn terminals(&self) -> &[TerminalRecord] {
        &self.terminals
    }

    #[must_use]
    pub(crate) const fn mailbox(&self) -> MailboxSnapshot {
        self.mailbox
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> ThreadDomainSnapshot {
        self.domain
    }

    pub(crate) fn take_join_proof(
        &mut self,
    ) -> Result<ThreadDomainJoinProof, ThreadComponentRuntimeError> {
        self.join_proof
            .take()
            .ok_or(ThreadComponentRuntimeError::JoinProofAlreadyTaken)
    }

    #[must_use]
    pub(crate) fn is_zero_cleanup(&self) -> bool {
        self.mailbox.lifecycle() == MailboxLifecycle::Closed
            && self.mailbox.queued_items() == 0
            && self.mailbox.inflight_items() == 0
            && self.mailbox.retained_bytes() == 0
            && self.domain.lifecycle() == ThreadDomainLifecycle::Closed
            && self.domain.live_workers() == 0
            && self.domain.active_invocations() == 0
            && self.domain.joined_workers() == self.domain.planned_workers()
            && self.domain.panicked_workers() == 0
            && self.domain.cleanup_panics() == 0
    }
}

/// Fail-closed local component errors. Public wire rejection remains owned by
/// the canonical contract/admission layer rather than this Harness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadComponentRuntimeError {
    InvalidExecutionSlice,
    RequiresOneThreadDomain,
    RequiresOneThreadMailbox,
    ExecutionDomainMismatch,
    MissingBinding,
    ExecutionBindingMismatch,
    NativeThreadsUnsupported,
    UnsupportedTargetDomain,
    ImplementationMismatch,
    ImplementationConstructionPanicked,
    IneligibleExecution,
    InvalidLifecycle,
    ImplementationUnavailable,
    MissingPendingInvocation,
    NonZeroShutdown,
    JoinProofAlreadyTaken,
    Clock(RuntimeClockError),
    Mailbox(MailboxError),
    Binding(PortBindingError),
    ThreadDomain(ThreadDomainError),
}

impl From<RuntimeClockError> for ThreadComponentRuntimeError {
    fn from(value: RuntimeClockError) -> Self {
        Self::Clock(value)
    }
}

impl From<MailboxError> for ThreadComponentRuntimeError {
    fn from(value: MailboxError) -> Self {
        Self::Mailbox(value)
    }
}

impl From<PortBindingError> for ThreadComponentRuntimeError {
    fn from(value: PortBindingError) -> Self {
        Self::Binding(value)
    }
}

impl From<ThreadDomainError> for ThreadComponentRuntimeError {
    fn from(value: ThreadDomainError) -> Self {
        Self::ThreadDomain(value)
    }
}

impl fmt::Display for ThreadComponentRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidExecutionSlice => formatter.write_str("invalid PXTE v2 Runtime slice"),
            Self::RequiresOneThreadDomain => {
                formatter.write_str("local Thread component requires exactly one ThreadDomain")
            }
            Self::RequiresOneThreadMailbox => formatter
                .write_str("local Thread component requires exactly one Thread Mailbox execution"),
            Self::ExecutionDomainMismatch => {
                formatter.write_str("Thread execution references another domain")
            }
            Self::MissingBinding => formatter.write_str("Thread execution binding is absent"),
            Self::ExecutionBindingMismatch => {
                formatter.write_str("Thread execution differs from its PXTA binding")
            }
            Self::NativeThreadsUnsupported => formatter
                .write_str("local Thread component has no native-library thread census owner"),
            Self::UnsupportedTargetDomain => formatter
                .write_str("PXTE ThreadDomain exceeds the local fixed-worker implementation"),
            Self::ImplementationMismatch => {
                formatter.write_str("trusted Thread implementation does not match PXTE subject")
            }
            Self::ImplementationConstructionPanicked => {
                formatter.write_str("trusted Thread implementation construction panicked")
            }
            Self::IneligibleExecution => {
                formatter.write_str("PXTE subject is not eligible for ThreadDomain")
            }
            Self::InvalidLifecycle => formatter.write_str("invalid Thread component lifecycle"),
            Self::ImplementationUnavailable => {
                formatter.write_str("Thread component implementation ownership is unavailable")
            }
            Self::MissingPendingInvocation => {
                formatter.write_str("Thread component has no pending invocation")
            }
            Self::NonZeroShutdown => formatter.write_str("Thread component shutdown is nonzero"),
            Self::JoinProofAlreadyTaken => {
                formatter.write_str("Thread component join proof was already transferred")
            }
            Self::Clock(error) => write!(formatter, "runtime clock failed: {error}"),
            Self::Mailbox(error) => write!(formatter, "Mailbox transition failed: {error}"),
            Self::Binding(error) => write!(formatter, "PortBinding transition failed: {error}"),
            Self::ThreadDomain(error) => {
                write!(formatter, "ThreadDomain transition failed: {error}")
            }
        }
    }
}

impl std::error::Error for ThreadComponentRuntimeError {}

impl From<BindingOfferFailure> for ThreadComponentOfferFailure {
    fn from(failure: BindingOfferFailure) -> Self {
        Self::new(failure.error().into(), failure.into_message())
    }
}

type ThreadCardSlot = Arc<Mutex<Option<Box<dyn SynchronousThreadCard>>>>;

fn take_thread_card(slot: &ThreadCardSlot) -> Option<Box<dyn SynchronousThreadCard>> {
    let mut implementation = match slot.lock() {
        Ok(implementation) => implementation,
        Err(poisoned) => poisoned.into_inner(),
    };
    implementation.take()
}

fn duration(nanos: u64) -> Duration {
    Duration::from_nanos(nanos)
}

fn build_pending_timing(
    clock: RuntimeClock,
    requirements: ThreadExecutionRequirements,
) -> Result<(ClockReading, PendingTiming), ThreadComponentRuntimeError> {
    let started = clock.reading()?;
    let run_deadline = started
        .try_deadline_after(requirements.run_budget())
        .map_err(RuntimeClockError::Time)?;
    let run_boundary = ClockReading::new(
        started.domain(),
        started.generation(),
        run_deadline.deadline(),
    );
    let uncertain_deadline = run_boundary
        .try_deadline_after(requirements.cancellation_grace())
        .map_err(RuntimeClockError::Time)?;
    Ok((
        started,
        PendingTiming {
            run_deadline,
            uncertain_deadline,
            phase: PendingTimeoutPhase::Running,
        },
    ))
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::time::Duration;
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;
    use std::time::Instant;

    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::{
        BoundedDuration, ClockDomainRef, ClockGeneration, MonotonicDeadline,
    };
    use paraegox_runtime_contracts::assignment::{
        BindingAssignment, BindingId, DeliveryProfile, InstanceRef, InteractionKind, MailboxRef,
        MailboxSpec, OverflowPolicy, PortCardinality, PortDirection, PortEndpoint, PortRef,
        PortSpec, SchemaRef, TargetAssignments,
    };
    use paraegox_runtime_contracts::execution::{
        BlockingRisk, CallModel, CardDefinitionRef, CardImplementationRef, CardSubjectSpec,
        DispatchClass, RunBoundProvenance, WorkloadKind,
    };
    use paraegox_runtime_contracts::provenance::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef,
    };
    use paraegox_runtime_contracts::thread_execution::{
        ExecutorBudgetSpec, RuntimePlanSliceV3, TargetExecutionPlanV2, TargetPlanAssignmentsV3,
        ThreadDispatchPolicy, ThreadDomainRef, ThreadDomainSpec, ThreadExecutionRequirements,
        ThreadInvocationBudgets, ThreadMailboxExecutionSpec,
    };

    use super::{
        LateResultReason, PreparedThreadComponentRuntime, SynchronousThreadCard, ThreadCardFailure,
        ThreadCardInputView, ThreadComponentDispatchOutcome, ThreadComponentIdleReason,
        ThreadComponentLifecycle, ThreadComponentPollOutcome, ThreadComponentRuntime,
        ThreadComponentRuntimeError, ThreadComponentShutdownOutcome, ThreadWorkerResult,
        TrustedSynchronousThreadCard, TrustedThreadCardImplementation,
    };
    use crate::card_instance::DomainEpoch;
    use crate::executor_budget::ExecutorBudget;
    use crate::mailbox::{
        EnqueueOutcome, MessageId, PayloadHandle, TerminalReason, ValidatedMessage,
    };
    use crate::runtime_clock::RuntimeClock;
    use crate::thread_domain::{
        ThreadCompletion, ThreadDomain, ThreadDomainConfig, ThreadDomainError,
        ThreadDomainLifecycle, ThreadInvocationObservation,
    };
    use crate::thread_registry::RuntimeThreadRegistry;

    const CLOCK_DOMAIN: ClockDomainRef = ClockDomainRef::from_bytes([0x44; 16]);
    const SUBJECT: CardSubjectSpec = CardSubjectSpec::new(
        CardDefinitionRef::from_bytes([0xa1; 16]),
        CardImplementationRef::from_bytes([0xa2; 16]),
        Digest32::from_bytes([0xa3; 32]),
        Digest32::from_bytes([0xa4; 32]),
        Digest32::from_bytes([0xa5; 32]),
    );

    #[derive(Debug)]
    struct ControlledLatch {
        open: Mutex<bool>,
        changed: Condvar,
    }

    impl ControlledLatch {
        fn new() -> Self {
            Self {
                open: Mutex::new(false),
                changed: Condvar::new(),
            }
        }

        fn wait(&self) {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut open = match self.open.lock() {
                Ok(open) => open,
                Err(poisoned) => poisoned.into_inner(),
            };
            while !*open {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return;
                }
                let waited = self.changed.wait_timeout(open, remaining);
                let (next, timeout) = match waited {
                    Ok(waited) => waited,
                    Err(poisoned) => poisoned.into_inner(),
                };
                open = next;
                if timeout.timed_out() {
                    return;
                }
            }
        }

        fn release(&self) {
            let mut open = match self.open.lock() {
                Ok(open) => open,
                Err(poisoned) => poisoned.into_inner(),
            };
            *open = true;
            self.changed.notify_all();
        }
    }

    #[derive(Clone)]
    struct Probe {
        calls: Arc<AtomicUsize>,
        saw_cancellation: Arc<AtomicBool>,
        payloads: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Probe {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                saw_cancellation: Arc::new(AtomicBool::new(false)),
                payloads: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    enum Behavior {
        Complete,
        Wait(Arc<ControlledLatch>),
        Panic,
    }

    struct ProbeCard {
        probe: Probe,
        behavior: Behavior,
    }

    impl SynchronousThreadCard for ProbeCard {
        fn on_input(
            &mut self,
            cancellation: &super::ThreadCancellation,
            input: ThreadCardInputView<'_>,
        ) -> Result<(), ThreadCardFailure> {
            self.probe.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(input.binding(), BindingId::from_bytes([0x31; 16]));
            assert_eq!(input.mailbox(), MailboxRef::from_bytes([0x81; 16]));
            assert_eq!(input.target_port(), PortRef::from_bytes([0x71; 16]));
            assert_eq!(input.schema(), schema());
            assert_ne!(input.message_id(), MessageId::from_bytes([0; 16]));
            match self.probe.payloads.lock() {
                Ok(mut payloads) => payloads.push(input.payload().to_vec()),
                Err(_) => panic!("probe payload lock must remain usable"),
            }
            match &self.behavior {
                Behavior::Complete => Ok(()),
                Behavior::Wait(latch) => {
                    latch.wait();
                    self.probe
                        .saw_cancellation
                        .store(cancellation.is_cancellation_requested(), Ordering::SeqCst);
                    Ok(())
                }
                Behavior::Panic => panic!("fixture synchronous callback panic"),
            }
        }
    }

    impl TrustedSynchronousThreadCard for ProbeCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = CardDefinitionRef::from_bytes([0xa1; 16]);
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef =
            CardImplementationRef::from_bytes([0xa2; 16]);
        const BOUND_DEFINITION_DIGEST: Digest32 = Digest32::from_bytes([0xa3; 32]);
        const BOUND_ARTIFACT_DIGEST: Digest32 = Digest32::from_bytes([0xa4; 32]);
    }

    enum CardDropBehavior {
        Return,
        Wait(Arc<ControlledLatch>),
        Panic,
    }

    struct DropProbeCard {
        callback_panics: bool,
        drop_behavior: CardDropBehavior,
        drop_events: std::sync::mpsc::Sender<String>,
    }

    impl SynchronousThreadCard for DropProbeCard {
        fn on_input(
            &mut self,
            _cancellation: &super::ThreadCancellation,
            _input: ThreadCardInputView<'_>,
        ) -> Result<(), ThreadCardFailure> {
            if self.callback_panics {
                panic!("fixture callback panic before Card cleanup");
            }
            Ok(())
        }
    }

    impl TrustedSynchronousThreadCard for DropProbeCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = CardDefinitionRef::from_bytes([0xa1; 16]);
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef =
            CardImplementationRef::from_bytes([0xa2; 16]);
        const BOUND_DEFINITION_DIGEST: Digest32 = Digest32::from_bytes([0xa3; 32]);
        const BOUND_ARTIFACT_DIGEST: Digest32 = Digest32::from_bytes([0xa4; 32]);
    }

    impl Drop for DropProbeCard {
        fn drop(&mut self) {
            let worker = thread::current().name().unwrap_or("<unnamed>").to_owned();
            let _ = self.drop_events.send(worker);
            match &self.drop_behavior {
                CardDropBehavior::Return => {}
                CardDropBehavior::Wait(latch) => latch.wait(),
                CardDropBehavior::Panic => panic!("fixture Card destructor panic"),
            }
        }
    }

    struct Harness {
        runtime: ThreadComponentRuntime,
        budget: ExecutorBudget,
        clock: RuntimeClock,
        probe: Probe,
    }

    impl Harness {
        fn finish_shutdown(&mut self) {
            let outcome = self
                .runtime
                .shutdown_for(Duration::from_secs(1))
                .unwrap_or_else(|error| panic!("component shutdown failed: {error}"));
            let ThreadComponentShutdownOutcome::Complete(mut report) = outcome else {
                panic!("released fixture must completely join");
            };
            assert!(report.is_zero_cleanup());
            let mut proof = report
                .take_join_proof()
                .unwrap_or_else(|error| panic!("complete report needs proof: {error}"));
            self.budget
                .release(&mut proof)
                .unwrap_or_else(|error| panic!("proof must settle budget: {error}"));
            assert_eq!(
                self.budget
                    .snapshot()
                    .unwrap_or_else(|error| panic!("budget snapshot failed: {error}"))
                    .active_reservations(),
                0
            );
        }
    }

    fn generation() -> ClockGeneration {
        ClockGeneration::try_new(1).unwrap_or_else(|_| panic!("fixture generation must be valid"))
    }

    fn epoch(value: u64) -> DomainEpoch {
        DomainEpoch::try_new(value).unwrap_or_else(|_| panic!("fixture epoch must be valid"))
    }

    fn schema() -> SchemaRef {
        SchemaRef::try_new([0x21; 16], 1, Digest32::from_bytes([0x22; 32]))
            .unwrap_or_else(|_| panic!("fixture schema must be valid"))
    }

    fn binding() -> BindingAssignment {
        let source = PortEndpoint::new(
            InstanceRef::from_bytes([0x41; 16]),
            PortRef::from_bytes([0x51; 16]),
            PortSpec::new(
                PortDirection::Out,
                schema(),
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let target = PortEndpoint::new(
            InstanceRef::from_bytes([0x61; 16]),
            PortRef::from_bytes([0x71; 16]),
            PortSpec::new(
                PortDirection::In,
                schema(),
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let delivery = DeliveryProfile::try_new(
            128,
            BoundedDuration::from_nanos(5_000_000_000),
            OverflowPolicy::RejectNew,
        )
        .unwrap_or_else(|_| panic!("fixture delivery must be valid"));
        let mailbox = MailboxSpec::try_new(
            4,
            512,
            BoundedDuration::from_nanos(4_000_000_000),
            1,
            512,
            OverflowPolicy::RejectNew,
        )
        .unwrap_or_else(|_| panic!("fixture Mailbox must be valid"));
        BindingAssignment::try_new(
            BindingId::from_bytes([0x31; 16]),
            source,
            target,
            MailboxRef::from_bytes([0x81; 16]),
            delivery,
            mailbox,
        )
        .unwrap_or_else(|_| panic!("fixture binding must be valid"))
    }

    fn execution() -> ThreadMailboxExecutionSpec {
        let budgets = ThreadInvocationBudgets::try_new(
            BoundedDuration::from_nanos(100_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            0,
        )
        .unwrap_or_else(|_| panic!("fixture invocation budgets must be valid"));
        let requirements = ThreadExecutionRequirements::try_new(
            CallModel::Synchronous,
            WorkloadKind::Io,
            BlockingRisk::Bounded,
            RunBoundProvenance::Measured,
            budgets,
        )
        .unwrap_or_else(|_| panic!("fixture requirements must be valid"));
        let dispatch = ThreadDispatchPolicy::try_new(DispatchClass::Interactive, 1, 1, 1, 1)
            .unwrap_or_else(|_| panic!("fixture dispatch must be valid"));
        ThreadMailboxExecutionSpec::new(
            BindingId::from_bytes([0x31; 16]),
            MailboxRef::from_bytes([0x81; 16]),
            InstanceRef::from_bytes([0x61; 16]),
            ThreadDomainRef::from_bytes([0x91; 16]),
            SUBJECT,
            requirements,
            dispatch,
        )
    }

    fn slice() -> RuntimePlanSliceV3 {
        let domain = ThreadDomainSpec::try_new(
            ThreadDomainRef::from_bytes([0x91; 16]),
            1,
            BoundedDuration::from_nanos(5_000_000_000),
            BoundedDuration::from_nanos(1_000_000_000),
            BoundedDuration::from_nanos(100_000_000),
        )
        .unwrap_or_else(|_| panic!("fixture domain must be valid"));
        let executor = ExecutorBudgetSpec::try_new(2, 1)
            .unwrap_or_else(|_| panic!("fixture executor budget must be valid"));
        let execution =
            TargetExecutionPlanV2::try_new(None, executor, vec![domain], vec![execution()])
                .unwrap_or_else(|error| panic!("fixture PXTE v2 must be valid: {error}"));
        let bindings = TargetAssignments::try_new(vec![binding()])
            .unwrap_or_else(|error| panic!("fixture PXTA must be valid: {error}"));
        let assignments = TargetPlanAssignmentsV3::try_new(bindings, execution)
            .unwrap_or_else(|error| panic!("fixture composite plan must be valid: {error}"));
        let provenance = PlanProvenance::new(
            SourceScopeRef::from_bytes([1; 16]),
            SourcePlanRef::from_bytes([2; 16]),
            SourcePlanRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([4; 32])),
        );
        let commitment = RuntimeSliceCommitment::try_new(RuntimeSliceHeader::new(
            RuntimeHostId::from_bytes([5; 16]),
            provenance,
            assignments.assignment_digest(),
        ))
        .unwrap_or_else(|error| panic!("fixture commitment must be valid: {error}"));
        RuntimePlanSliceV3::try_new(commitment, assignments)
            .unwrap_or_else(|error| panic!("fixture Slice must be valid: {error}"))
    }

    fn prepare(behavior: Behavior) -> (PreparedThreadComponentRuntime, RuntimeClock, Probe) {
        let slice = slice();
        let probe = Probe::new();
        let implementation_probe = probe.clone();
        let selected =
            TrustedThreadCardImplementation::try_resolve::<ProbeCard, _>(execution(), move || {
                ProbeCard {
                    probe: implementation_probe,
                    behavior,
                }
            })
            .unwrap_or_else(|error| panic!("fixture implementation must resolve: {error}"));
        let clock = RuntimeClock::new(CLOCK_DOMAIN, generation(), 0);
        let prepared = PreparedThreadComponentRuntime::try_new(&slice, selected, clock)
            .unwrap_or_else(|error| panic!("fixture component must prepare: {error}"));
        (prepared, clock, probe)
    }

    fn start_drop_probe(
        callback_panics: bool,
        drop_behavior: CardDropBehavior,
        drop_events: std::sync::mpsc::Sender<String>,
        epoch_value: u64,
    ) -> (ThreadComponentRuntime, ExecutorBudget, RuntimeClock) {
        let selected = TrustedThreadCardImplementation::try_resolve::<DropProbeCard, _>(
            execution(),
            move || DropProbeCard {
                callback_panics,
                drop_behavior,
                drop_events,
            },
        )
        .unwrap_or_else(|error| panic!("fixture implementation must resolve: {error}"));
        let clock = RuntimeClock::new(CLOCK_DOMAIN, generation(), 0);
        let prepared = PreparedThreadComponentRuntime::try_new(&slice(), selected, clock)
            .unwrap_or_else(|error| panic!("fixture component must prepare: {error}"));
        let mut budget = ExecutorBudget::try_new(2, 1)
            .unwrap_or_else(|error| panic!("fixture budget must build: {error}"));
        let reservation = budget
            .try_reserve(1, 0)
            .unwrap_or_else(|error| panic!("fixture worker must reserve: {error}"));
        let runtime = match prepared.start(epoch(epoch_value), reservation) {
            Ok(runtime) => runtime,
            Err(failure) => {
                let error = failure.error().to_string();
                let mut proof = failure.into_join_proof();
                budget
                    .release(&mut proof)
                    .unwrap_or_else(|release| panic!("build rollback failed: {release}"));
                panic!("fixture ThreadDomain failed: {error}");
            }
        };
        (runtime, budget, clock)
    }

    fn start(behavior: Behavior, epoch_value: u64) -> Harness {
        let (prepared, clock, probe) = prepare(behavior);
        let mut budget = ExecutorBudget::try_new(2, 1)
            .unwrap_or_else(|error| panic!("fixture budget must build: {error}"));
        let reservation = budget
            .try_reserve(1, 0)
            .unwrap_or_else(|error| panic!("fixture worker must reserve: {error}"));
        let runtime = match prepared.start(epoch(epoch_value), reservation) {
            Ok(runtime) => runtime,
            Err(failure) => {
                let error = failure.error().to_string();
                let mut proof = failure.into_join_proof();
                budget
                    .release(&mut proof)
                    .unwrap_or_else(|release| panic!("build rollback failed: {release}"));
                panic!("fixture ThreadDomain failed: {error}");
            }
        };
        Harness {
            runtime,
            budget,
            clock,
            probe,
        }
    }

    fn deadline(clock: RuntimeClock) -> MonotonicDeadline {
        clock
            .deadline_after(BoundedDuration::from_nanos(3_000_000_000))
            .unwrap_or_else(|error| panic!("fixture deadline must build: {error}"))
    }

    fn offer_runtime(
        runtime: &mut ThreadComponentRuntime,
        clock: RuntimeClock,
        id: u8,
        payload: &[u8],
    ) {
        let message = ValidatedMessage::new(
            MessageId::from_bytes([id; 16]),
            schema(),
            InteractionKind::Signal,
            None,
            deadline(clock),
            PayloadHandle::try_from_vec(payload.to_vec())
                .unwrap_or_else(|error| panic!("fixture payload must build: {error}")),
        );
        let ingress = runtime
            .active_ingress()
            .unwrap_or_else(|| panic!("fixture ingress must be active"));
        let report = runtime
            .try_offer(ingress, message)
            .unwrap_or_else(|failure| panic!("fixture offer failed: {}", failure.error()));
        assert!(matches!(report.outcome(), EnqueueOutcome::Admitted));
    }

    fn offer(harness: &mut Harness, id: u8, payload: &[u8]) {
        offer_runtime(&mut harness.runtime, harness.clock, id, payload);
    }

    fn wait_until_called(probe: &Probe) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while probe.calls.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "callback did not start");
            thread::yield_now();
        }
    }

    fn wait_for_terminal(runtime: &mut ThreadComponentRuntime) -> ThreadComponentPollOutcome {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let outcome = runtime
                .poll_pending()
                .unwrap_or_else(|error| panic!("pending poll failed: {error}"));
            if !matches!(outcome, ThreadComponentPollOutcome::Pending(_)) {
                return outcome;
            }
            assert!(Instant::now() < deadline, "callback did not complete");
            thread::yield_now();
        }
    }

    #[test]
    fn authenticated_execution_mismatch_never_constructs_the_card() {
        let canonical = execution();
        let mismatched = ThreadMailboxExecutionSpec::new(
            BindingId::from_bytes([0x32; 16]),
            canonical.mailbox(),
            canonical.target_instance(),
            canonical.domain(),
            canonical.subject(),
            canonical.requirements(),
            canonical.dispatch(),
        );
        let constructions = Arc::new(AtomicUsize::new(0));
        let construction_probe = Arc::clone(&constructions);
        let selected =
            TrustedThreadCardImplementation::try_resolve::<ProbeCard, _>(mismatched, move || {
                construction_probe.fetch_add(1, Ordering::SeqCst);
                ProbeCard {
                    probe: Probe::new(),
                    behavior: Behavior::Complete,
                }
            })
            .unwrap_or_else(|error| panic!("descriptor-only selection must resolve: {error}"));
        assert_eq!(constructions.load(Ordering::SeqCst), 0);

        let clock = RuntimeClock::new(CLOCK_DOMAIN, generation(), 0);
        assert!(matches!(
            PreparedThreadComponentRuntime::try_new(&slice(), selected, clock),
            Err(ThreadComponentRuntimeError::ImplementationMismatch)
        ));
        assert_eq!(constructions.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn registry_is_the_budget_and_shutdown_owner_for_the_component() {
        let (prepared, clock, probe) = prepare(Behavior::Complete);
        let budget_spec = ExecutorBudgetSpec::try_new(2, 1)
            .unwrap_or_else(|error| panic!("fixture budget spec must build: {error}"));
        let mut registry = RuntimeThreadRegistry::try_new(budget_spec)
            .unwrap_or_else(|error| panic!("fixture registry must build: {error}"));
        let handle = prepared
            .install(&mut registry, epoch(11))
            .unwrap_or_else(|error| panic!("component registry install failed: {error}"));
        assert_eq!(registry.domain_count(), 1);
        assert_eq!(
            registry
                .budget_snapshot()
                .unwrap_or_else(|error| panic!("registry budget snapshot failed: {error}"))
                .active_reservations(),
            1
        );

        let dispatch = registry
            .with_owner_mut(&handle, |runtime| {
                offer_runtime(runtime, clock, 11, b"registry-owned");
                runtime.try_dispatch_once()
            })
            .unwrap_or_else(|error| panic!("registry visit failed: {error}"))
            .unwrap_or_else(|error| panic!("component dispatch failed: {error}"));
        assert_eq!(dispatch, ThreadComponentDispatchOutcome::Started);
        let outcome = registry
            .with_owner_mut(&handle, wait_for_terminal)
            .unwrap_or_else(|error| panic!("registry completion visit failed: {error}"));
        assert!(matches!(
            outcome,
            ThreadComponentPollOutcome::Completed { .. }
        ));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);

        registry
            .shutdown()
            .unwrap_or_else(|error| panic!("registry component shutdown failed: {error}"));
        assert_eq!(registry.domain_count(), 0);
        assert_eq!(
            registry
                .budget_snapshot()
                .unwrap_or_else(|error| panic!("registry zero snapshot failed: {error}"))
                .active_reservations(),
            0
        );
    }

    #[test]
    fn registry_plan_mismatch_precedes_reservation_and_domain_install() {
        let (prepared, _, _) = prepare(Behavior::Complete);
        let wider_budget = ExecutorBudgetSpec::try_new(3, 1)
            .unwrap_or_else(|error| panic!("wider fixture budget must build: {error}"));
        let mut registry = RuntimeThreadRegistry::try_new(wider_budget)
            .unwrap_or_else(|error| panic!("fixture registry must build: {error}"));

        assert!(matches!(
            prepared.install(&mut registry, epoch(13)),
            Err(crate::thread_registry::ThreadRegistryError::ExecutorPlanMismatch)
        ));
        assert_eq!(registry.domain_count(), 0);
        let snapshot = registry
            .budget_snapshot()
            .unwrap_or_else(|error| panic!("unchanged registry snapshot failed: {error}"));
        assert_eq!(snapshot.active_reservations(), 0);
        assert_eq!(snapshot.managed_workers(), 0);
        assert_eq!(snapshot.native_threads(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn signed_run_and_grace_deadlines_cancel_then_wedge_a_late_card() {
        let gate = Arc::new(ControlledLatch::new());
        let mut harness = start(Behavior::Wait(Arc::clone(&gate)), 12);
        offer(&mut harness, 12, b"signed-timeout");
        assert_eq!(
            harness.runtime.try_dispatch_once(),
            Ok(ThreadComponentDispatchOutcome::Started)
        );
        wait_until_called(&harness.probe);

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            harness
                .runtime
                .poll_pending()
                .unwrap_or_else(|error| panic!("run deadline poll failed: {error}")),
            ThreadComponentPollOutcome::Pending(ThreadInvocationObservation::CancellationRequested)
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            harness
                .runtime
                .poll_pending()
                .unwrap_or_else(|error| panic!("grace deadline poll failed: {error}")),
            ThreadComponentPollOutcome::Pending(ThreadInvocationObservation::Wedged)
        );
        assert_eq!(
            harness.runtime.domain_snapshot().lifecycle(),
            ThreadDomainLifecycle::Degraded
        );

        gate.release();
        let ThreadComponentPollOutcome::LateRejected { reason, uncertain } =
            wait_for_terminal(&mut harness.runtime)
        else {
            panic!("wedged callable return must remain fenced");
        };
        assert_eq!(reason, LateResultReason::Wedged);
        assert_eq!(uncertain.len(), 1);
        assert_eq!(uncertain[0].reason(), TerminalReason::Uncertain);
        assert!(harness.probe.saw_cancellation.load(Ordering::SeqCst));
        harness.finish_shutdown();
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_manual_cancellation_cannot_extend_or_weaken_the_first_grace_fence() {
        let gate = Arc::new(ControlledLatch::new());
        let mut harness = start(Behavior::Wait(Arc::clone(&gate)), 14);
        offer(&mut harness, 14, b"manual-grace");
        assert_eq!(
            harness.runtime.try_dispatch_once(),
            Ok(ThreadComponentDispatchOutcome::Started)
        );
        wait_until_called(&harness.probe);

        tokio::time::advance(Duration::from_millis(100)).await;
        harness
            .runtime
            .request_pending_cancellation()
            .unwrap_or_else(|error| panic!("manual cancellation failed: {error}"));
        tokio::time::advance(Duration::from_millis(500)).await;
        harness
            .runtime
            .request_pending_cancellation()
            .unwrap_or_else(|error| panic!("repeated cancellation failed: {error}"));
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(
            harness
                .runtime
                .poll_pending()
                .unwrap_or_else(|error| panic!("manual grace poll failed: {error}")),
            ThreadComponentPollOutcome::Pending(ThreadInvocationObservation::Wedged)
        );
        harness
            .runtime
            .request_pending_cancellation()
            .unwrap_or_else(|error| panic!("wedged cancellation must be idempotent: {error}"));
        harness
            .runtime
            .mark_pending_uncertain()
            .unwrap_or_else(|error| panic!("wedged uncertainty must be idempotent: {error}"));

        gate.release();
        let ThreadComponentPollOutcome::LateRejected { reason, uncertain } =
            wait_for_terminal(&mut harness.runtime)
        else {
            panic!("manual grace overrun must fence the returned value");
        };
        assert_eq!(reason, LateResultReason::Wedged);
        assert_eq!(uncertain.len(), 1);
        assert_eq!(uncertain[0].reason(), TerminalReason::Uncertain);
        harness.finish_shutdown();
    }

    #[test]
    fn successful_path_uses_original_inflight_token_and_returns_exact_zero() {
        let mut harness = start(Behavior::Complete, 1);
        offer(&mut harness, 1, b"thread-success");
        assert_eq!(
            harness.runtime.try_dispatch_once(),
            Ok(ThreadComponentDispatchOutcome::Started)
        );
        let ThreadComponentPollOutcome::Completed {
            callback,
            terminal,
            expired,
        } = wait_for_terminal(&mut harness.runtime)
        else {
            panic!("successful callback must complete");
        };
        assert_eq!(callback, Ok(()));
        assert_eq!(terminal.reason(), TerminalReason::Completed);
        assert!(expired.is_empty());
        assert_eq!(harness.probe.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            harness
                .probe
                .payloads
                .lock()
                .unwrap_or_else(|_| panic!("probe payload lock must remain usable"))[0],
            b"thread-success"
        );
        assert_eq!(
            harness.runtime.try_dispatch_once(),
            Ok(ThreadComponentDispatchOutcome::Idle(
                ThreadComponentIdleReason::Empty
            ))
        );
        assert_eq!(
            harness
                .runtime
                .mailbox_snapshot()
                .unwrap_or_else(|error| panic!("Mailbox snapshot failed: {error}"))
                .retained_bytes(),
            0
        );
        harness.finish_shutdown();
    }

    #[test]
    fn accepted_result_can_immediately_dispatch_final_card_cleanup() {
        let (drop_sender, drop_receiver) = std::sync::mpsc::channel();
        let (mut runtime, mut budget, clock) =
            start_drop_probe(false, CardDropBehavior::Return, drop_sender, 101);
        offer_runtime(&mut runtime, clock, 101, b"accepted-cleanup");
        assert_eq!(
            runtime.try_dispatch_once(),
            Ok(ThreadComponentDispatchOutcome::Started)
        );
        assert!(matches!(
            wait_for_terminal(&mut runtime),
            ThreadComponentPollOutcome::Completed { .. }
        ));
        // Accepted handoff removes the old invocation and publishes the direct
        // cell atomically; no yield/wait is allowed before cleanup submission.
        let accepted = runtime.domain_snapshot();
        assert_eq!(accepted.active_invocations(), 0);
        assert_eq!(accepted.idle_workers(), 1);

        let outcome = runtime
            .shutdown_for(Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("immediate shutdown failed: {error}"));
        let ThreadComponentShutdownOutcome::Complete(mut report) = outcome else {
            panic!("immediate final cleanup must join in one drain");
        };
        let drop_thread = drop_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("Card destructor must be observed");
        assert!(drop_thread.starts_with("paraegox-thread-"));
        assert!(report.is_zero_cleanup());
        let mut proof = report
            .take_join_proof()
            .unwrap_or_else(|error| panic!("complete cleanup needs proof: {error}"));
        budget
            .release(&mut proof)
            .unwrap_or_else(|error| panic!("proof release failed: {error}"));
        let released = budget
            .snapshot()
            .unwrap_or_else(|error| panic!("released budget snapshot failed: {error}"));
        assert_eq!(released.active_reservations(), 0);
        assert_eq!(released.managed_workers(), 0);
    }

    #[test]
    fn blocking_final_card_drop_keeps_worker_and_budget_charged_until_retry() {
        let gate = Arc::new(ControlledLatch::new());
        let (drop_sender, drop_receiver) = std::sync::mpsc::channel();
        let (mut runtime, mut budget, _) = start_drop_probe(
            false,
            CardDropBehavior::Wait(Arc::clone(&gate)),
            drop_sender,
            102,
        );

        let started = Instant::now();
        let outcome = runtime
            .shutdown_for(Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("bounded cleanup failed: {error}"));
        assert!(started.elapsed() < Duration::from_millis(500));
        let ThreadComponentShutdownOutcome::Incomplete { domain, .. } = outcome else {
            panic!("blocking Card destructor must keep shutdown incomplete");
        };
        let drop_thread = drop_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("blocking Card destructor must start");
        assert!(drop_thread.starts_with("paraegox-thread-"));
        assert!(!domain.complete());
        assert!(domain.wait_expired());
        assert_eq!(domain.snapshot().active_invocations(), 1);
        assert_eq!(domain.snapshot().occupied_workers(), 1);
        assert_eq!(
            budget
                .snapshot()
                .unwrap_or_else(|error| panic!("budget snapshot failed: {error}"))
                .active_reservations(),
            1
        );

        gate.release();
        let outcome = runtime
            .shutdown_for(Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("released cleanup retry failed: {error}"));
        let ThreadComponentShutdownOutcome::Complete(mut report) = outcome else {
            panic!("released Card destructor must join on retry");
        };
        assert!(report.is_zero_cleanup());
        let mut proof = report
            .take_join_proof()
            .unwrap_or_else(|error| panic!("complete cleanup needs proof: {error}"));
        budget
            .release(&mut proof)
            .unwrap_or_else(|error| panic!("proof release failed: {error}"));
        let released = budget
            .snapshot()
            .unwrap_or_else(|error| panic!("released budget snapshot failed: {error}"));
        assert_eq!(released.active_reservations(), 0);
        assert_eq!(released.managed_workers(), 0);
    }

    #[test]
    fn final_card_drop_panic_is_explicit_and_registry_retains_owner_and_budget() {
        let (drop_sender, drop_receiver) = std::sync::mpsc::channel();
        let selected = TrustedThreadCardImplementation::try_resolve::<DropProbeCard, _>(
            execution(),
            move || DropProbeCard {
                callback_panics: false,
                drop_behavior: CardDropBehavior::Panic,
                drop_events: drop_sender,
            },
        )
        .unwrap_or_else(|error| panic!("fixture implementation must resolve: {error}"));
        let clock = RuntimeClock::new(CLOCK_DOMAIN, generation(), 0);
        let prepared = PreparedThreadComponentRuntime::try_new(&slice(), selected, clock)
            .unwrap_or_else(|error| panic!("fixture component must prepare: {error}"));
        let budget_spec = ExecutorBudgetSpec::try_new(2, 1)
            .unwrap_or_else(|error| panic!("fixture budget spec must build: {error}"));
        let mut registry = RuntimeThreadRegistry::try_new(budget_spec)
            .unwrap_or_else(|error| panic!("fixture registry must build: {error}"));
        let handle = prepared
            .install(&mut registry, epoch(103))
            .unwrap_or_else(|error| panic!("component install failed: {error}"));

        assert!(matches!(
            registry.shutdown(),
            Err(crate::thread_registry::ThreadRegistryError::OwnerCleanupFailed)
        ));
        let drop_thread = drop_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("panicking Card destructor must be observed");
        assert!(drop_thread.starts_with("paraegox-thread-"));
        let (lifecycle, domain) = registry
            .with_owner_mut(&handle, |runtime| {
                (runtime.lifecycle(), runtime.domain_snapshot())
            })
            .unwrap_or_else(|error| panic!("retained owner visit failed: {error}"));
        assert_eq!(lifecycle, ThreadComponentLifecycle::Closing);
        assert_eq!(domain.lifecycle(), ThreadDomainLifecycle::Closed);
        assert_eq!(domain.cleanup_panics(), 1);
        assert_eq!(domain.panicked_workers(), 0);
        assert_eq!(registry.domain_count(), 1);
        let budget = registry
            .budget_snapshot()
            .unwrap_or_else(|error| panic!("retained budget snapshot failed: {error}"));
        assert_eq!(budget.active_reservations(), 1);
        assert_eq!(budget.managed_workers(), 1);
        assert!(matches!(
            registry.shutdown(),
            Err(crate::thread_registry::ThreadRegistryError::OwnerCleanupFailed)
        ));
        let retry = registry
            .with_owner_mut(&handle, |runtime| runtime.domain_snapshot())
            .unwrap_or_else(|error| panic!("retry owner visit failed: {error}"));
        assert_eq!(retry.cleanup_panics(), 1);
        assert_eq!(retry.live_workers(), 0);
        assert_eq!(retry.joined_workers(), 1);
        assert_eq!(retry.active_invocations(), 0);
        let retained = registry
            .budget_snapshot()
            .unwrap_or_else(|error| panic!("retry budget snapshot failed: {error}"));
        assert_eq!(retained.active_reservations(), 1);
        assert_eq!(retained.managed_workers(), 1);
    }

    #[test]
    fn callback_panic_and_card_drop_panic_never_double_unwind() {
        let (drop_sender, drop_receiver) = std::sync::mpsc::channel();
        let (mut runtime, budget, clock) =
            start_drop_probe(true, CardDropBehavior::Panic, drop_sender, 104);
        offer_runtime(&mut runtime, clock, 104, b"double-panic-guard");
        assert_eq!(
            runtime.try_dispatch_once(),
            Ok(ThreadComponentDispatchOutcome::Started)
        );
        let ThreadComponentPollOutcome::Panicked { uncertain } = wait_for_terminal(&mut runtime)
        else {
            panic!("callback panic must remain explicitly observable");
        };
        assert_eq!(uncertain.len(), 1);
        assert_eq!(runtime.lifecycle(), ThreadComponentLifecycle::Poisoned);

        assert!(matches!(
            runtime.shutdown_for(Duration::from_secs(1)),
            Err(ThreadComponentRuntimeError::NonZeroShutdown)
        ));
        let drop_thread = drop_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("panicking Card destructor must be observed");
        assert!(drop_thread.starts_with("paraegox-thread-"));
        let domain = runtime.domain_snapshot();
        assert_eq!(domain.lifecycle(), ThreadDomainLifecycle::Closed);
        assert_eq!(domain.cleanup_panics(), 1);
        assert_eq!(domain.panicked_workers(), 0);
        assert!(matches!(
            runtime.domain.take_join_proof(),
            Err(ThreadDomainError::JoinProofUnavailable)
        ));
        assert_eq!(
            budget
                .snapshot()
                .unwrap_or_else(|error| panic!("budget snapshot failed: {error}"))
                .active_reservations(),
            1
        );
    }

    #[test]
    fn direct_component_drop_blocks_only_on_the_worker_owned_card_destructor() {
        let gate = Arc::new(ControlledLatch::new());
        let (drop_sender, drop_receiver) = std::sync::mpsc::channel();
        let (runtime, budget, _) = start_drop_probe(
            false,
            CardDropBehavior::Wait(Arc::clone(&gate)),
            drop_sender,
            105,
        );
        let (done_sender, done_receiver) = std::sync::mpsc::sync_channel(0);
        let owner_drop = thread::spawn(move || {
            drop(runtime);
            let _ = done_sender.send(());
        });

        let drop_thread = drop_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("direct Drop must hand the Card to its worker");
        assert!(drop_thread.starts_with("paraegox-thread-"));
        assert!(matches!(
            done_receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        gate.release();
        done_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("owner Drop must finish after worker cleanup");
        owner_drop
            .join()
            .expect("worker-contained blocking Drop must not panic owner Drop");
        assert_eq!(
            budget
                .snapshot()
                .unwrap_or_else(|error| panic!("budget snapshot failed: {error}"))
                .active_reservations(),
            1
        );
    }

    #[test]
    fn direct_component_drop_contains_panicking_card_destructor_on_worker() {
        let (drop_sender, drop_receiver) = std::sync::mpsc::channel();
        let (runtime, budget, _) =
            start_drop_probe(false, CardDropBehavior::Panic, drop_sender, 106);
        let owner_drop = thread::spawn(move || drop(runtime));
        let drop_thread = drop_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("direct Drop must hand the Card to its worker");
        assert!(drop_thread.starts_with("paraegox-thread-"));
        owner_drop
            .join()
            .expect("worker must contain Card destructor panic");
        assert_eq!(
            budget
                .snapshot()
                .unwrap_or_else(|error| panic!("budget snapshot failed: {error}"))
                .active_reservations(),
            1
        );
    }

    #[test]
    fn saturated_worker_does_not_dequeue_or_invoke_the_card() {
        let (prepared, clock, probe) = prepare(Behavior::Complete);
        let mut budget = ExecutorBudget::try_new(2, 1)
            .unwrap_or_else(|error| panic!("fixture budget must build: {error}"));
        let reservation = budget
            .try_reserve(1, 0)
            .unwrap_or_else(|error| panic!("fixture reservation must fit: {error}"));
        let config = ThreadDomainConfig::try_new(1, Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("fixture config must build: {error}"));
        let mut domain =
            match ThreadDomain::<ThreadWorkerResult>::try_new(epoch(2), config, reservation) {
                Ok(domain) => domain,
                Err(failure) => panic!("fixture domain failed: {}", failure.error()),
            };
        let gate = Arc::new(ControlledLatch::new());
        let worker_gate = Arc::clone(&gate);
        let mut blocker = domain
            .try_submit(|| {
                move |_| {
                    worker_gate.wait();
                    ThreadWorkerResult::NoInvocation {
                        implementation: None,
                        expired: Vec::new(),
                        error: None,
                    }
                }
            })
            .unwrap_or_else(|error| panic!("blocker must admit: {error}"));
        let runtime = ThreadComponentRuntime::from_prepared(prepared, domain);
        let mut harness = Harness {
            runtime,
            budget,
            clock,
            probe,
        };
        offer(&mut harness, 2, b"still-queued");
        assert_eq!(
            harness.runtime.try_dispatch_once(),
            Err(ThreadComponentRuntimeError::ThreadDomain(
                ThreadDomainError::CapacityExhausted
            ))
        );
        let mailbox = harness
            .runtime
            .mailbox_snapshot()
            .unwrap_or_else(|error| panic!("Mailbox snapshot failed: {error}"));
        assert_eq!(mailbox.queued_items(), 1);
        assert_eq!(mailbox.inflight_items(), 0);
        assert_eq!(harness.probe.calls.load(Ordering::SeqCst), 0);

        gate.release();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match harness.runtime.domain.try_take_completion(&mut blocker) {
                Ok(ThreadCompletion::Returned(ThreadWorkerResult::NoInvocation { .. })) => break,
                Ok(ThreadCompletion::Pending(_)) => {}
                Ok(_) | Err(_) => panic!("blocker must complete normally"),
            }
            assert!(Instant::now() < deadline, "blocker did not return");
            thread::yield_now();
        }
        assert_eq!(
            harness.runtime.try_dispatch_once(),
            Ok(ThreadComponentDispatchOutcome::Started)
        );
        assert!(matches!(
            wait_for_terminal(&mut harness.runtime),
            ThreadComponentPollOutcome::Completed { .. }
        ));
        harness.finish_shutdown();
    }

    #[test]
    fn cancellation_then_uncertain_rejects_late_result_and_releases_mailbox_bytes() {
        let gate = Arc::new(ControlledLatch::new());
        let mut harness = start(Behavior::Wait(Arc::clone(&gate)), 3);
        offer(&mut harness, 3, b"late");
        assert_eq!(
            harness.runtime.try_dispatch_once(),
            Ok(ThreadComponentDispatchOutcome::Started)
        );
        wait_until_called(&harness.probe);
        harness
            .runtime
            .request_pending_cancellation()
            .unwrap_or_else(|error| panic!("cancellation request failed: {error}"));
        harness
            .runtime
            .mark_pending_uncertain()
            .unwrap_or_else(|error| panic!("uncertain mark failed: {error}"));
        assert_eq!(
            harness
                .runtime
                .mailbox_snapshot()
                .unwrap_or_else(|error| panic!("Mailbox snapshot failed: {error}"))
                .inflight_items(),
            1
        );
        gate.release();
        let ThreadComponentPollOutcome::LateRejected { reason, uncertain } =
            wait_for_terminal(&mut harness.runtime)
        else {
            panic!("fenced callback must be late-rejected");
        };
        assert_eq!(reason, LateResultReason::Uncertain);
        assert_eq!(uncertain.len(), 1);
        assert_eq!(uncertain[0].reason(), TerminalReason::Uncertain);
        assert!(harness.probe.saw_cancellation.load(Ordering::SeqCst));
        let mailbox = harness
            .runtime
            .mailbox_snapshot()
            .unwrap_or_else(|error| panic!("Mailbox snapshot failed: {error}"));
        assert_eq!(mailbox.inflight_items(), 0);
        assert_eq!(mailbox.retained_bytes(), 0);
        assert_eq!(
            harness.runtime.lifecycle(),
            ThreadComponentLifecycle::Poisoned
        );
        harness.finish_shutdown();
    }

    #[test]
    fn callback_panic_poison_is_fail_closed_and_inflight_becomes_uncertain() {
        let mut harness = start(Behavior::Panic, 4);
        offer(&mut harness, 4, b"panic");
        assert_eq!(
            harness.runtime.try_dispatch_once(),
            Ok(ThreadComponentDispatchOutcome::Started)
        );
        let ThreadComponentPollOutcome::Panicked { uncertain } =
            wait_for_terminal(&mut harness.runtime)
        else {
            panic!("panic must be observed as panic");
        };
        assert_eq!(uncertain.len(), 1);
        assert_eq!(uncertain[0].reason(), TerminalReason::Uncertain);
        let domain = harness.runtime.domain_snapshot();
        assert_eq!(domain.lifecycle(), ThreadDomainLifecycle::Accepting);
        assert_eq!(domain.idle_workers(), 1);
        assert_eq!(domain.active_invocations(), 0);
        assert!(domain.conserves_worker_capacity());
        assert_eq!(
            harness.runtime.try_dispatch_once(),
            Err(ThreadComponentRuntimeError::InvalidLifecycle)
        );
        assert_eq!(
            harness
                .runtime
                .mailbox_snapshot()
                .unwrap_or_else(|error| panic!("Mailbox snapshot failed: {error}"))
                .retained_bytes(),
            0
        );
        harness.finish_shutdown();
    }

    #[test]
    fn incomplete_shutdown_has_no_proof_then_real_return_joins_and_zeroes() {
        let gate = Arc::new(ControlledLatch::new());
        let mut harness = start(Behavior::Wait(Arc::clone(&gate)), 5);
        offer(&mut harness, 5, b"shutdown-race");
        assert_eq!(
            harness.runtime.try_dispatch_once(),
            Ok(ThreadComponentDispatchOutcome::Started)
        );
        wait_until_called(&harness.probe);
        let shutdown_started = Instant::now();
        let incomplete = harness
            .runtime
            .shutdown_for(Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("bounded shutdown failed: {error}"));
        assert!(
            shutdown_started.elapsed() < Duration::from_millis(500),
            "signed drain budget must cap a larger caller budget"
        );
        let ThreadComponentShutdownOutcome::Incomplete { domain, terminals } = incomplete else {
            panic!("blocked callable must prevent complete shutdown");
        };
        assert!(!domain.complete());
        assert!(domain.wait_expired());
        assert!(terminals.is_empty());
        assert_eq!(
            harness
                .budget
                .snapshot()
                .unwrap_or_else(|error| panic!("budget snapshot failed: {error}"))
                .active_reservations(),
            1
        );

        gate.release();
        let complete = harness
            .runtime
            .shutdown_for(Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("second shutdown failed: {error}"));
        let ThreadComponentShutdownOutcome::Complete(mut report) = complete else {
            panic!("released callable must join");
        };
        assert!(report.is_zero_cleanup());
        assert!(
            report
                .terminals()
                .iter()
                .any(|terminal| terminal.reason() == TerminalReason::Uncertain)
        );
        let mut proof = report
            .take_join_proof()
            .unwrap_or_else(|error| panic!("complete shutdown needs proof: {error}"));
        harness
            .budget
            .release(&mut proof)
            .unwrap_or_else(|error| panic!("proof release failed: {error}"));
    }
}
