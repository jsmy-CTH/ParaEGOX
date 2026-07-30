//! RuntimeHost-owned lifecycle for one fixed, prevalidated CoreService dependency.
//!
//! P2b needs production lifecycle ownership evidence without introducing the P2e
//! ServiceSpec schema, dependency-graph planner, controller, journal, or apply
//! endpoint. This owner therefore accepts exactly two already-selected services:
//! one provider and its one consumer. Their order is structural rather than a
//! second desired-state graph.

use core::fmt;
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::time::Duration;
use std::panic::{AssertUnwindSafe, catch_unwind};

use paraegox_kernel::time::{BoundedDuration, ClockReading, MonotonicDeadline};

use crate::runtime_clock::{RuntimeClock, RuntimeClockError};
use crate::task_registry::{CancellationSource, CancellationView};

const PROVIDER_INDEX: usize = 0;
const CONSUMER_INDEX: usize = 1;
const CORE_SERVICE_COUNT: usize = 2;

/// Private identity for the P2b lifecycle owner. This is not a public ServiceSpec
/// or a language-neutral service identity contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct CoreServiceIdentity([u8; 16]);

impl CoreServiceIdentity {
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Structural role in the one admitted provider -> consumer fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreServiceRole {
    Provider,
    Consumer,
}

/// RuntimeHost-observed lifecycle state. Services cannot write this state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreServiceLifecycle {
    Created,
    Preparing,
    Prepared,
    Starting,
    Started,
    CheckingReadiness,
    Ready,
    Draining,
    Stopping,
    Stopped,
    StartupFailed,
    CleanupFailed,
}

/// Bounded service-owned readiness observation; RuntimeHost derives the
/// conjunction and remains the lifecycle truth owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreServiceReadiness {
    Ready,
    NotReady,
}

/// Bounded implementation failure with no payload or dynamic diagnostic text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreServiceFailure {
    Failed,
}

/// A boxed borrowing future avoids a public Rust plugin ABI or async-trait
/// dependency while keeping callbacks owned by the current RuntimeHost task.
pub(crate) type CoreServiceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Private P2b CoreService callback seam from the architecture baseline.
pub(crate) trait CoreService: Send {
    fn prepare<'a>(
        &'a mut self,
        context: &'a ServiceContext,
    ) -> CoreServiceFuture<'a, Result<(), CoreServiceFailure>>;

    fn start(&mut self) -> CoreServiceFuture<'_, Result<(), CoreServiceFailure>>;

    fn readiness(
        &mut self,
    ) -> CoreServiceFuture<'_, Result<CoreServiceReadiness, CoreServiceFailure>>;

    fn drain(
        &mut self,
        deadline: MonotonicDeadline,
    ) -> CoreServiceFuture<'_, Result<(), CoreServiceFailure>>;

    fn stop(&mut self) -> CoreServiceFuture<'_, Result<(), CoreServiceFailure>>;
}

/// Narrow service input: identity, owner-local clock, and cancellation only.
/// It exposes no RuntimeHost, task registry, Tokio handle, dynamic lookup, or
/// mutable lifecycle handle.
#[derive(Clone, Debug)]
pub(crate) struct ServiceContext {
    identity: CoreServiceIdentity,
    clock: RuntimeClock,
    cancellation: CancellationView,
}

impl ServiceContext {
    const fn new(
        identity: CoreServiceIdentity,
        clock: RuntimeClock,
        cancellation: CancellationView,
    ) -> Self {
        Self {
            identity,
            clock,
            cancellation,
        }
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> CoreServiceIdentity {
        self.identity
    }

    pub(crate) fn clock_reading(&self) -> Result<ClockReading, RuntimeClockError> {
        self.clock.reading()
    }

    #[must_use]
    pub(crate) const fn cancellation(&self) -> &CancellationView {
        &self.cancellation
    }
}

/// Finite RuntimeHost-owned budget for every lifecycle stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreServiceLifecycleBudgets {
    prepare: BoundedDuration,
    start: BoundedDuration,
    readiness: BoundedDuration,
    drain: BoundedDuration,
    stop: BoundedDuration,
}

impl CoreServiceLifecycleBudgets {
    pub(crate) fn try_new(
        prepare: BoundedDuration,
        start: BoundedDuration,
        readiness: BoundedDuration,
        drain: BoundedDuration,
        stop: BoundedDuration,
    ) -> Result<Self, CoreServiceLifecycleError> {
        if [prepare, start, readiness, drain, stop]
            .into_iter()
            .any(|budget| budget.value() == 0)
        {
            return Err(CoreServiceLifecycleError::InvalidBudget);
        }
        Ok(Self {
            prepare,
            start,
            readiness,
            drain,
            stop,
        })
    }
}

/// Lifecycle stage attached to bounded failure evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreServiceStage {
    Prepare,
    Start,
    Readiness,
    Drain,
    Stop,
}

/// Payload-free terminal observation for one lifecycle callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreServiceStageFact {
    NotAttempted,
    NotRequired,
    Succeeded,
    NotReady,
    Failed,
    TimedOut,
    Cancelled,
    Panicked,
    ClockFailed,
}

impl CoreServiceStageFact {
    const fn callback_succeeded(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

/// Readiness-specific fact kept separate from lifecycle and cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreServiceReadinessFact {
    NotChecked,
    Ready,
    NotReady,
    Failed,
    TimedOut,
    Cancelled,
    Panicked,
}

/// Bounded, copy-only snapshot for one of the two fixed services.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreServiceSnapshot {
    role: CoreServiceRole,
    identity: CoreServiceIdentity,
    lifecycle: CoreServiceLifecycle,
    prepare: CoreServiceStageFact,
    start: CoreServiceStageFact,
    readiness: CoreServiceReadinessFact,
    drain: CoreServiceStageFact,
    stop: CoreServiceStageFact,
    cleanup_pending: bool,
}

impl CoreServiceSnapshot {
    #[must_use]
    pub(crate) const fn role(self) -> CoreServiceRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn identity(self) -> CoreServiceIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn lifecycle(self) -> CoreServiceLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub(crate) const fn prepare(self) -> CoreServiceStageFact {
        self.prepare
    }

    #[must_use]
    pub(crate) const fn start(self) -> CoreServiceStageFact {
        self.start
    }

    #[must_use]
    pub(crate) const fn readiness(self) -> CoreServiceReadinessFact {
        self.readiness
    }

    #[must_use]
    pub(crate) const fn drain(self) -> CoreServiceStageFact {
        self.drain
    }

    #[must_use]
    pub(crate) const fn stop(self) -> CoreServiceStageFact {
        self.stop
    }

    #[must_use]
    pub(crate) const fn cleanup_pending(self) -> bool {
        self.cleanup_pending
    }
}

/// Explicit provider/consumer readiness conjunction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreServiceReadinessFacts {
    provider: CoreServiceReadinessFact,
    consumer: CoreServiceReadinessFact,
    all_ready: bool,
}

impl CoreServiceReadinessFacts {
    #[must_use]
    pub(crate) const fn provider(self) -> CoreServiceReadinessFact {
        self.provider
    }

    #[must_use]
    pub(crate) const fn consumer(self) -> CoreServiceReadinessFact {
        self.consumer
    }

    #[must_use]
    pub(crate) const fn all_ready(self) -> bool {
        self.all_ready
    }
}

/// Read-only, bounded and payload-free lifecycle observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreServicesSnapshot {
    observed_at: ClockReading,
    services: [CoreServiceSnapshot; CORE_SERVICE_COUNT],
    readiness: CoreServiceReadinessFacts,
}

impl CoreServicesSnapshot {
    #[must_use]
    pub(crate) const fn observed_at(self) -> ClockReading {
        self.observed_at
    }

    #[must_use]
    pub(crate) const fn services(self) -> [CoreServiceSnapshot; CORE_SERVICE_COUNT] {
        self.services
    }

    #[must_use]
    pub(crate) const fn readiness(self) -> CoreServiceReadinessFacts {
        self.readiness
    }
}

/// Bounded startup failure retained after rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreServiceStartupFailure {
    role: CoreServiceRole,
    stage: CoreServiceStage,
    fact: CoreServiceStageFact,
}

impl CoreServiceStartupFailure {
    #[must_use]
    pub(crate) const fn role(self) -> CoreServiceRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn stage(self) -> CoreServiceStage {
        self.stage
    }

    #[must_use]
    pub(crate) const fn fact(self) -> CoreServiceStageFact {
        self.fact
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreServiceStartupOutcome {
    Ready,
    Failed(CoreServiceStartupFailure),
}

impl CoreServiceStartupOutcome {
    #[must_use]
    pub(crate) const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Startup observation delivered from the owned lifecycle task to RuntimeHost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreServiceStartupEvidence {
    outcome: CoreServiceStartupOutcome,
    snapshot: CoreServicesSnapshot,
}

impl CoreServiceStartupEvidence {
    #[must_use]
    pub(crate) const fn outcome(self) -> CoreServiceStartupOutcome {
        self.outcome
    }

    #[must_use]
    pub(crate) const fn snapshot(self) -> CoreServicesSnapshot {
        self.snapshot
    }

    #[must_use]
    pub(crate) const fn is_ready(self) -> bool {
        self.outcome.is_ready() && self.snapshot.readiness.all_ready()
    }
}

/// Per-service cleanup result. A later successful stop never erases an earlier
/// drain failure, timeout, panic, or missing cleanup obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreServiceCleanupFact {
    role: CoreServiceRole,
    drain: CoreServiceStageFact,
    stop: CoreServiceStageFact,
    cleanup_pending: bool,
}

impl CoreServiceCleanupFact {
    #[must_use]
    pub(crate) const fn role(self) -> CoreServiceRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn drain(self) -> CoreServiceStageFact {
        self.drain
    }

    #[must_use]
    pub(crate) const fn stop(self) -> CoreServiceStageFact {
        self.stop
    }

    #[must_use]
    pub(crate) const fn cleanup_pending(self) -> bool {
        self.cleanup_pending
    }

    const fn is_zero(self) -> bool {
        !self.cleanup_pending
            && matches!(
                self.drain,
                CoreServiceStageFact::Succeeded | CoreServiceStageFact::NotRequired
            )
            && matches!(
                self.stop,
                CoreServiceStageFact::Succeeded | CoreServiceStageFact::NotRequired
            )
    }
}

/// Terminal cleanup report, retained by the owner and returned unchanged on a
/// repeated shutdown observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreServiceCleanupReport {
    services: [CoreServiceCleanupFact; CORE_SERVICE_COUNT],
}

impl CoreServiceCleanupReport {
    #[must_use]
    pub(crate) const fn services(self) -> [CoreServiceCleanupFact; CORE_SERVICE_COUNT] {
        self.services
    }

    #[must_use]
    pub(crate) const fn is_zero_cleanup(self) -> bool {
        self.services[PROVIDER_INDEX].is_zero() && self.services[CONSUMER_INDEX].is_zero()
    }
}

/// Structured result returned by the one owned RuntimeHost task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreServiceLifecycleReport {
    startup: CoreServiceStartupOutcome,
    cleanup: CoreServiceCleanupReport,
    terminal_snapshot: CoreServicesSnapshot,
}

impl CoreServiceLifecycleReport {
    #[must_use]
    pub(crate) const fn startup(self) -> CoreServiceStartupOutcome {
        self.startup
    }

    #[must_use]
    pub(crate) const fn cleanup(self) -> CoreServiceCleanupReport {
        self.cleanup
    }

    #[must_use]
    pub(crate) const fn terminal_snapshot(self) -> CoreServicesSnapshot {
        self.terminal_snapshot
    }

    #[must_use]
    pub(crate) const fn is_acceptable(self) -> bool {
        self.startup.is_ready() && self.cleanup.is_zero_cleanup()
    }
}

struct ServiceSlot {
    role: CoreServiceRole,
    identity: CoreServiceIdentity,
    service: Box<dyn CoreService>,
    cancellation: CancellationSource,
    lifecycle: CoreServiceLifecycle,
    prepare: CoreServiceStageFact,
    start: CoreServiceStageFact,
    readiness: CoreServiceStageFact,
    drain: CoreServiceStageFact,
    stop: CoreServiceStageFact,
    cleanup_required: bool,
    drain_required: bool,
}

impl ServiceSlot {
    fn new(
        role: CoreServiceRole,
        identity: CoreServiceIdentity,
        service: Box<dyn CoreService>,
        cancellation: CancellationSource,
    ) -> Self {
        Self {
            role,
            identity,
            service,
            cancellation,
            lifecycle: CoreServiceLifecycle::Created,
            prepare: CoreServiceStageFact::NotAttempted,
            start: CoreServiceStageFact::NotAttempted,
            readiness: CoreServiceStageFact::NotAttempted,
            drain: CoreServiceStageFact::NotAttempted,
            stop: CoreServiceStageFact::NotAttempted,
            cleanup_required: false,
            drain_required: false,
        }
    }

    fn readiness_fact(&self) -> CoreServiceReadinessFact {
        match self.readiness {
            CoreServiceStageFact::Succeeded => CoreServiceReadinessFact::Ready,
            CoreServiceStageFact::NotReady => CoreServiceReadinessFact::NotReady,
            CoreServiceStageFact::Failed | CoreServiceStageFact::ClockFailed => {
                CoreServiceReadinessFact::Failed
            }
            CoreServiceStageFact::TimedOut => CoreServiceReadinessFact::TimedOut,
            CoreServiceStageFact::Cancelled => CoreServiceReadinessFact::Cancelled,
            CoreServiceStageFact::Panicked => CoreServiceReadinessFact::Panicked,
            CoreServiceStageFact::NotAttempted | CoreServiceStageFact::NotRequired => {
                CoreServiceReadinessFact::NotChecked
            }
        }
    }

    fn snapshot(&self) -> CoreServiceSnapshot {
        CoreServiceSnapshot {
            role: self.role,
            identity: self.identity,
            lifecycle: self.lifecycle,
            prepare: self.prepare,
            start: self.start,
            readiness: self.readiness_fact(),
            drain: self.drain,
            stop: self.stop,
            cleanup_pending: self.cleanup_required,
        }
    }

    fn cleanup_fact(&self) -> CoreServiceCleanupFact {
        CoreServiceCleanupFact {
            role: self.role,
            drain: self.drain,
            stop: self.stop,
            cleanup_pending: self.cleanup_required,
        }
    }
}

/// Sole lifecycle owner for one fixed provider -> consumer relation.
pub(crate) struct CoreServiceLifecycleOwner {
    clock: RuntimeClock,
    budgets: CoreServiceLifecycleBudgets,
    root_cancellation: CancellationView,
    services: [ServiceSlot; CORE_SERVICE_COUNT],
    startup_outcome: Option<CoreServiceStartupOutcome>,
    terminal_cleanup: Option<CoreServiceCleanupReport>,
}

impl CoreServiceLifecycleOwner {
    pub(crate) fn try_new(
        provider_identity: CoreServiceIdentity,
        provider: Box<dyn CoreService>,
        consumer_identity: CoreServiceIdentity,
        consumer: Box<dyn CoreService>,
        clock: RuntimeClock,
        budgets: CoreServiceLifecycleBudgets,
        parent_cancellation: &CancellationSource,
    ) -> Result<Self, CoreServiceLifecycleError> {
        if provider_identity == consumer_identity {
            return Err(CoreServiceLifecycleError::DuplicateIdentity);
        }
        Ok(Self {
            clock,
            budgets,
            root_cancellation: parent_cancellation.view(),
            services: [
                ServiceSlot::new(
                    CoreServiceRole::Provider,
                    provider_identity,
                    provider,
                    parent_cancellation.child(),
                ),
                ServiceSlot::new(
                    CoreServiceRole::Consumer,
                    consumer_identity,
                    consumer,
                    parent_cancellation.child(),
                ),
            ],
            startup_outcome: None,
            terminal_cleanup: None,
        })
    }

    /// Starts and gates the provider before touching the consumer. Any failure
    /// immediately rolls back every touched service in reverse order.
    pub(crate) async fn startup(&mut self) -> CoreServiceStartupOutcome {
        if let Some(outcome) = self.startup_outcome {
            return outcome;
        }

        for index in [PROVIDER_INDEX, CONSUMER_INDEX] {
            let prepare = self.prepare_one(index).await;
            if !prepare.callback_succeeded() {
                return self
                    .fail_startup(index, CoreServiceStage::Prepare, prepare)
                    .await;
            }

            let start = self.start_one(index).await;
            if !start.callback_succeeded() {
                return self
                    .fail_startup(index, CoreServiceStage::Start, start)
                    .await;
            }

            let readiness = self.readiness_one(index).await;
            if !readiness.callback_succeeded() {
                return self
                    .fail_startup(index, CoreServiceStage::Readiness, readiness)
                    .await;
            }
        }

        let outcome = CoreServiceStartupOutcome::Ready;
        self.startup_outcome = Some(outcome);
        outcome
    }

    pub(crate) fn startup_evidence(
        &self,
    ) -> Result<CoreServiceStartupEvidence, CoreServiceLifecycleError> {
        let outcome = self
            .startup_outcome
            .ok_or(CoreServiceLifecycleError::LifecycleIncomplete)?;
        Ok(CoreServiceStartupEvidence {
            outcome,
            snapshot: self.snapshot()?,
        })
    }

    /// Cancels service contexts, drains and stops consumer-before-provider, and
    /// retains every nonzero result instead of overwriting it with later success.
    pub(crate) async fn shutdown(&mut self) -> CoreServiceCleanupReport {
        if let Some(report) = self.terminal_cleanup {
            return report;
        }

        for index in [CONSUMER_INDEX, PROVIDER_INDEX] {
            self.services[index].cancellation.cancel();
            if !self.services[index].cleanup_required {
                self.services[index].drain = CoreServiceStageFact::NotRequired;
                self.services[index].stop = CoreServiceStageFact::NotRequired;
                continue;
            }
            if self.services[index].drain_required {
                self.drain_one(index).await;
            } else {
                self.services[index].drain = CoreServiceStageFact::NotRequired;
            }
            self.stop_one(index).await;
        }

        let report = CoreServiceCleanupReport {
            services: [
                self.services[PROVIDER_INDEX].cleanup_fact(),
                self.services[CONSUMER_INDEX].cleanup_fact(),
            ],
        };
        self.terminal_cleanup = Some(report);
        report
    }

    pub(crate) fn snapshot(&self) -> Result<CoreServicesSnapshot, CoreServiceLifecycleError> {
        let provider = self.services[PROVIDER_INDEX].snapshot();
        let consumer = self.services[CONSUMER_INDEX].snapshot();
        let readiness = CoreServiceReadinessFacts {
            provider: provider.readiness,
            consumer: consumer.readiness,
            all_ready: provider.readiness == CoreServiceReadinessFact::Ready
                && consumer.readiness == CoreServiceReadinessFact::Ready
                && provider.lifecycle == CoreServiceLifecycle::Ready
                && consumer.lifecycle == CoreServiceLifecycle::Ready,
        };
        Ok(CoreServicesSnapshot {
            observed_at: self.clock.reading()?,
            services: [provider, consumer],
            readiness,
        })
    }

    pub(crate) fn terminal_report(
        &self,
    ) -> Result<CoreServiceLifecycleReport, CoreServiceLifecycleError> {
        let startup = self
            .startup_outcome
            .ok_or(CoreServiceLifecycleError::LifecycleIncomplete)?;
        let cleanup = self
            .terminal_cleanup
            .ok_or(CoreServiceLifecycleError::LifecycleIncomplete)?;
        Ok(CoreServiceLifecycleReport {
            startup,
            cleanup,
            terminal_snapshot: self.snapshot()?,
        })
    }

    #[must_use]
    pub(crate) const fn root_cancellation(&self) -> &CancellationView {
        &self.root_cancellation
    }

    async fn fail_startup(
        &mut self,
        index: usize,
        stage: CoreServiceStage,
        fact: CoreServiceStageFact,
    ) -> CoreServiceStartupOutcome {
        let outcome = CoreServiceStartupOutcome::Failed(CoreServiceStartupFailure {
            role: self.services[index].role,
            stage,
            fact,
        });
        self.startup_outcome = Some(outcome);
        let _ = self.shutdown().await;
        outcome
    }

    async fn prepare_one(&mut self, index: usize) -> CoreServiceStageFact {
        if self.root_cancellation.is_cancelled() {
            self.services[index].prepare = CoreServiceStageFact::Cancelled;
            self.services[index].lifecycle = CoreServiceLifecycle::StartupFailed;
            return CoreServiceStageFact::Cancelled;
        }

        let context = ServiceContext::new(
            self.services[index].identity,
            self.clock,
            self.services[index].cancellation.view(),
        );
        self.services[index].cleanup_required = true;
        self.services[index].lifecycle = CoreServiceLifecycle::Preparing;
        let service = &mut self.services[index].service;
        let callback = async { service.prepare(&context).await };
        let fact = unit_callback_fact(callback, self.budgets.prepare).await;
        self.services[index].prepare = fact;
        self.services[index].lifecycle = if fact.callback_succeeded() {
            CoreServiceLifecycle::Prepared
        } else {
            self.services[index].cancellation.cancel();
            CoreServiceLifecycle::StartupFailed
        };
        fact
    }

    async fn start_one(&mut self, index: usize) -> CoreServiceStageFact {
        if self.root_cancellation.is_cancelled() {
            self.services[index].start = CoreServiceStageFact::Cancelled;
            self.services[index].lifecycle = CoreServiceLifecycle::StartupFailed;
            return CoreServiceStageFact::Cancelled;
        }

        self.services[index].drain_required = true;
        self.services[index].lifecycle = CoreServiceLifecycle::Starting;
        let service = &mut self.services[index].service;
        let callback = async { service.start().await };
        let fact = unit_callback_fact(callback, self.budgets.start).await;
        self.services[index].start = fact;
        self.services[index].lifecycle = if fact.callback_succeeded() {
            CoreServiceLifecycle::Started
        } else {
            self.services[index].cancellation.cancel();
            CoreServiceLifecycle::StartupFailed
        };
        fact
    }

    async fn readiness_one(&mut self, index: usize) -> CoreServiceStageFact {
        if self.root_cancellation.is_cancelled() {
            self.services[index].readiness = CoreServiceStageFact::Cancelled;
            self.services[index].lifecycle = CoreServiceLifecycle::StartupFailed;
            return CoreServiceStageFact::Cancelled;
        }

        self.services[index].lifecycle = CoreServiceLifecycle::CheckingReadiness;
        let service = &mut self.services[index].service;
        let callback = async { service.readiness().await };
        let fact = readiness_callback_fact(callback, self.budgets.readiness).await;
        self.services[index].readiness = fact;
        self.services[index].lifecycle = if fact.callback_succeeded() {
            CoreServiceLifecycle::Ready
        } else {
            self.services[index].cancellation.cancel();
            CoreServiceLifecycle::StartupFailed
        };
        fact
    }

    async fn drain_one(&mut self, index: usize) {
        self.services[index].lifecycle = CoreServiceLifecycle::Draining;
        let deadline = match self.clock.deadline_after(self.budgets.drain) {
            Ok(deadline) => deadline,
            Err(_) => {
                self.services[index].drain = CoreServiceStageFact::ClockFailed;
                return;
            }
        };
        let service = &mut self.services[index].service;
        let callback = async { service.drain(deadline).await };
        self.services[index].drain = unit_callback_fact(callback, self.budgets.drain).await;
    }

    async fn stop_one(&mut self, index: usize) {
        self.services[index].lifecycle = CoreServiceLifecycle::Stopping;
        let service = &mut self.services[index].service;
        let callback = async { service.stop().await };
        let fact = unit_callback_fact(callback, self.budgets.stop).await;
        self.services[index].stop = fact;
        if fact.callback_succeeded()
            && matches!(
                self.services[index].drain,
                CoreServiceStageFact::Succeeded | CoreServiceStageFact::NotRequired
            )
        {
            self.services[index].cleanup_required = false;
            self.services[index].lifecycle = CoreServiceLifecycle::Stopped;
        } else {
            self.services[index].lifecycle = CoreServiceLifecycle::CleanupFailed;
        }
    }
}

async fn unit_callback_fact<F>(callback: F, budget: BoundedDuration) -> CoreServiceStageFact
where
    F: Future<Output = Result<(), CoreServiceFailure>>,
{
    match tokio::time::timeout(duration(budget), catch_callback(callback)).await {
        Ok(Ok(Ok(()))) => CoreServiceStageFact::Succeeded,
        Ok(Ok(Err(CoreServiceFailure::Failed))) => CoreServiceStageFact::Failed,
        Ok(Err(())) => CoreServiceStageFact::Panicked,
        Err(_) => CoreServiceStageFact::TimedOut,
    }
}

async fn readiness_callback_fact<F>(callback: F, budget: BoundedDuration) -> CoreServiceStageFact
where
    F: Future<Output = Result<CoreServiceReadiness, CoreServiceFailure>>,
{
    match tokio::time::timeout(duration(budget), catch_callback(callback)).await {
        Ok(Ok(Ok(CoreServiceReadiness::Ready))) => CoreServiceStageFact::Succeeded,
        Ok(Ok(Ok(CoreServiceReadiness::NotReady))) => CoreServiceStageFact::NotReady,
        Ok(Ok(Err(CoreServiceFailure::Failed))) => CoreServiceStageFact::Failed,
        Ok(Err(())) => CoreServiceStageFact::Panicked,
        Err(_) => CoreServiceStageFact::TimedOut,
    }
}

const fn duration(value: BoundedDuration) -> Duration {
    Duration::from_nanos(value.value())
}

/// Contains callback construction, polling, and Future destruction panics so a
/// startup failure can still execute bounded reverse rollback.
struct PanicContainedFuture<F: Future> {
    inner: Option<Pin<Box<F>>>,
}

impl<F: Future> PanicContainedFuture<F> {
    fn new(future: F) -> Self {
        Self {
            inner: Some(Box::pin(future)),
        }
    }

    fn close(&mut self) -> Result<(), ()> {
        catch_unwind(AssertUnwindSafe(|| drop(self.inner.take()))).map_err(|_| ())
    }
}

impl<F: Future> Future for PanicContainedFuture<F> {
    type Output = Result<F::Output, ()>;

    fn poll(
        mut self: Pin<&mut Self>,
        context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let Some(inner) = self.inner.as_mut() else {
            return core::task::Poll::Ready(Err(()));
        };
        match catch_unwind(AssertUnwindSafe(|| inner.as_mut().poll(context))) {
            Ok(core::task::Poll::Ready(output)) => core::task::Poll::Ready(Ok(output)),
            Ok(core::task::Poll::Pending) => core::task::Poll::Pending,
            Err(_) => core::task::Poll::Ready(Err(())),
        }
    }
}

impl<F: Future> Drop for PanicContainedFuture<F> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

async fn catch_callback<F>(callback: F) -> Result<F::Output, ()>
where
    F: Future,
{
    let mut callback = PanicContainedFuture::new(callback);
    let outcome = poll_fn(|context| Pin::new(&mut callback).poll(context)).await;
    callback.close()?;
    outcome
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreServiceLifecycleError {
    InvalidBudget,
    DuplicateIdentity,
    LifecycleIncomplete,
    Clock(RuntimeClockError),
}

impl From<RuntimeClockError> for CoreServiceLifecycleError {
    fn from(value: RuntimeClockError) -> Self {
        Self::Clock(value)
    }
}

impl fmt::Display for CoreServiceLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBudget => {
                formatter.write_str("CoreService lifecycle budgets must be finite and nonzero")
            }
            Self::DuplicateIdentity => {
                formatter.write_str("provider and consumer CoreService identities must differ")
            }
            Self::LifecycleIncomplete => {
                formatter.write_str("CoreService lifecycle has no terminal structured result")
            }
            Self::Clock(error) => write!(formatter, "CoreService lifecycle clock failed: {error}"),
        }
    }
}

impl std::error::Error for CoreServiceLifecycleError {}

#[cfg(test)]
mod tests {
    use core::future::pending;
    use std::sync::{Arc, Mutex};

    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};

    use super::{
        CONSUMER_INDEX, CoreService, CoreServiceFailure, CoreServiceFuture, CoreServiceIdentity,
        CoreServiceLifecycle, CoreServiceLifecycleBudgets, CoreServiceLifecycleOwner,
        CoreServiceReadiness, CoreServiceReadinessFact, CoreServiceRole, CoreServiceStage,
        CoreServiceStageFact, ServiceContext,
    };
    use crate::runtime_clock::RuntimeClock;
    use crate::task_registry::{CancellationSource, CancellationView};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestStage {
        Prepare,
        Start,
        Readiness,
        Drain,
        Stop,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestEvent {
        role: CoreServiceRole,
        stage: TestStage,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReadinessBehavior {
        Ready,
        NotReady,
        Pending,
    }

    struct FakeCoreService {
        role: CoreServiceRole,
        identity: CoreServiceIdentity,
        events: Arc<Mutex<Vec<TestEvent>>>,
        readiness: ReadinessBehavior,
        drain_fails: bool,
        stop_fails: bool,
        cancellation: Option<CancellationView>,
    }

    impl FakeCoreService {
        fn record(&self, stage: TestStage) {
            self.events
                .lock()
                .unwrap_or_else(|_| panic!("event log must remain usable"))
                .push(TestEvent {
                    role: self.role,
                    stage,
                });
        }
    }

    impl CoreService for FakeCoreService {
        fn prepare<'a>(
            &'a mut self,
            context: &'a ServiceContext,
        ) -> CoreServiceFuture<'a, Result<(), CoreServiceFailure>> {
            self.record(TestStage::Prepare);
            let context_valid = context.identity() == self.identity
                && context.clock_reading().is_ok()
                && !context.cancellation().is_cancelled();
            self.cancellation = Some(context.cancellation().clone());
            Box::pin(async move {
                if context_valid {
                    Ok(())
                } else {
                    Err(CoreServiceFailure::Failed)
                }
            })
        }

        fn start(&mut self) -> CoreServiceFuture<'_, Result<(), CoreServiceFailure>> {
            self.record(TestStage::Start);
            Box::pin(async { Ok(()) })
        }

        fn readiness(
            &mut self,
        ) -> CoreServiceFuture<'_, Result<CoreServiceReadiness, CoreServiceFailure>> {
            self.record(TestStage::Readiness);
            match self.readiness {
                ReadinessBehavior::Ready => Box::pin(async { Ok(CoreServiceReadiness::Ready) }),
                ReadinessBehavior::NotReady => {
                    Box::pin(async { Ok(CoreServiceReadiness::NotReady) })
                }
                ReadinessBehavior::Pending => Box::pin(async {
                    pending::<()>().await;
                    Ok(CoreServiceReadiness::Ready)
                }),
            }
        }

        fn drain(
            &mut self,
            _deadline: paraegox_kernel::time::MonotonicDeadline,
        ) -> CoreServiceFuture<'_, Result<(), CoreServiceFailure>> {
            self.record(TestStage::Drain);
            let cancelled = self
                .cancellation
                .as_ref()
                .is_some_and(CancellationView::is_cancelled);
            let fails = self.drain_fails;
            Box::pin(async move {
                if cancelled && !fails {
                    Ok(())
                } else {
                    Err(CoreServiceFailure::Failed)
                }
            })
        }

        fn stop(&mut self) -> CoreServiceFuture<'_, Result<(), CoreServiceFailure>> {
            self.record(TestStage::Stop);
            let fails = self.stop_fails;
            Box::pin(async move {
                if fails {
                    Err(CoreServiceFailure::Failed)
                } else {
                    Ok(())
                }
            })
        }
    }

    fn identity(byte: u8) -> CoreServiceIdentity {
        CoreServiceIdentity::from_bytes([byte; 16])
    }

    fn clock() -> RuntimeClock {
        let generation = ClockGeneration::try_new(1)
            .unwrap_or_else(|error| panic!("test clock generation must build: {error}"));
        RuntimeClock::new(ClockDomainRef::from_bytes([0x31; 16]), generation, 0)
    }

    fn budgets(readiness_nanos: u64) -> CoreServiceLifecycleBudgets {
        CoreServiceLifecycleBudgets::try_new(
            BoundedDuration::from_nanos(10),
            BoundedDuration::from_nanos(10),
            BoundedDuration::from_nanos(readiness_nanos),
            BoundedDuration::from_nanos(10),
            BoundedDuration::from_nanos(10),
        )
        .unwrap_or_else(|error| panic!("test lifecycle budgets must build: {error}"))
    }

    fn fake(
        role: CoreServiceRole,
        identity: CoreServiceIdentity,
        events: &Arc<Mutex<Vec<TestEvent>>>,
        readiness: ReadinessBehavior,
        drain_fails: bool,
        stop_fails: bool,
    ) -> Box<dyn CoreService> {
        Box::new(FakeCoreService {
            role,
            identity,
            events: Arc::clone(events),
            readiness,
            drain_fails,
            stop_fails,
            cancellation: None,
        })
    }

    fn owner(
        root: &CancellationSource,
        events: &Arc<Mutex<Vec<TestEvent>>>,
        provider_readiness: ReadinessBehavior,
        consumer_readiness: ReadinessBehavior,
        consumer_drain_fails: bool,
        consumer_stop_fails: bool,
        lifecycle_budgets: CoreServiceLifecycleBudgets,
    ) -> CoreServiceLifecycleOwner {
        CoreServiceLifecycleOwner::try_new(
            identity(1),
            fake(
                CoreServiceRole::Provider,
                identity(1),
                events,
                provider_readiness,
                false,
                false,
            ),
            identity(2),
            fake(
                CoreServiceRole::Consumer,
                identity(2),
                events,
                consumer_readiness,
                consumer_drain_fails,
                consumer_stop_fails,
            ),
            clock(),
            lifecycle_budgets,
            root,
        )
        .unwrap_or_else(|error| panic!("fixed lifecycle owner must build: {error}"))
    }

    fn recorded(events: &Arc<Mutex<Vec<TestEvent>>>) -> Vec<TestEvent> {
        events
            .lock()
            .unwrap_or_else(|_| panic!("event log must remain usable"))
            .clone()
    }

    fn event(role: CoreServiceRole, stage: TestStage) -> TestEvent {
        TestEvent { role, stage }
    }

    #[tokio::test(start_paused = true)]
    async fn provider_ready_precedes_consumer_and_shutdown_is_strictly_reverse() {
        let root = CancellationSource::root();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut owner = owner(
            &root,
            &events,
            ReadinessBehavior::Ready,
            ReadinessBehavior::Ready,
            false,
            false,
            budgets(10),
        );

        assert!(owner.startup().await.is_ready());
        let snapshot = owner
            .snapshot()
            .unwrap_or_else(|error| panic!("ready snapshot must build: {error}"));
        assert_eq!(snapshot.observed_at().domain(), clock().domain());
        assert!(snapshot.readiness().all_ready());
        assert_eq!(
            snapshot.readiness().provider(),
            CoreServiceReadinessFact::Ready
        );
        assert_eq!(
            snapshot.readiness().consumer(),
            CoreServiceReadinessFact::Ready
        );
        assert_eq!(snapshot.services()[0].role(), CoreServiceRole::Provider);
        assert_eq!(snapshot.services()[0].identity(), identity(1));
        assert_eq!(
            snapshot.services()[0].lifecycle(),
            CoreServiceLifecycle::Ready
        );
        assert_eq!(snapshot.services()[1].role(), CoreServiceRole::Consumer);
        assert_eq!(snapshot.services()[1].identity(), identity(2));
        assert_eq!(
            snapshot.services()[1].lifecycle(),
            CoreServiceLifecycle::Ready
        );

        root.cancel();
        assert!(owner.root_cancellation().is_cancelled());
        let cleanup = owner.shutdown().await;
        assert!(cleanup.is_zero_cleanup());
        assert_eq!(cleanup, owner.shutdown().await);
        let terminal = owner
            .terminal_report()
            .unwrap_or_else(|error| panic!("terminal report must build: {error}"));
        assert!(terminal.is_acceptable());
        assert!(!terminal.terminal_snapshot().readiness().all_ready());
        assert_eq!(
            terminal.terminal_snapshot().services()[0].lifecycle(),
            CoreServiceLifecycle::Stopped
        );
        assert_eq!(
            terminal.terminal_snapshot().services()[1].lifecycle(),
            CoreServiceLifecycle::Stopped
        );

        assert_eq!(
            recorded(&events),
            vec![
                event(CoreServiceRole::Provider, TestStage::Prepare),
                event(CoreServiceRole::Provider, TestStage::Start),
                event(CoreServiceRole::Provider, TestStage::Readiness),
                event(CoreServiceRole::Consumer, TestStage::Prepare),
                event(CoreServiceRole::Consumer, TestStage::Start),
                event(CoreServiceRole::Consumer, TestStage::Readiness),
                event(CoreServiceRole::Consumer, TestStage::Drain),
                event(CoreServiceRole::Consumer, TestStage::Stop),
                event(CoreServiceRole::Provider, TestStage::Drain),
                event(CoreServiceRole::Provider, TestStage::Stop),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn consumer_not_ready_rolls_back_both_services_in_reverse_order() {
        let root = CancellationSource::root();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut owner = owner(
            &root,
            &events,
            ReadinessBehavior::Ready,
            ReadinessBehavior::NotReady,
            false,
            false,
            budgets(10),
        );

        let outcome = owner.startup().await;
        let super::CoreServiceStartupOutcome::Failed(failure) = outcome else {
            panic!("consumer not-ready must fail startup");
        };
        assert_eq!(failure.role(), CoreServiceRole::Consumer);
        assert_eq!(failure.stage(), CoreServiceStage::Readiness);
        assert_eq!(failure.fact(), CoreServiceStageFact::NotReady);
        let cleanup = owner.shutdown().await;
        assert!(cleanup.is_zero_cleanup());
        assert_eq!(
            recorded(&events),
            vec![
                event(CoreServiceRole::Provider, TestStage::Prepare),
                event(CoreServiceRole::Provider, TestStage::Start),
                event(CoreServiceRole::Provider, TestStage::Readiness),
                event(CoreServiceRole::Consumer, TestStage::Prepare),
                event(CoreServiceRole::Consumer, TestStage::Start),
                event(CoreServiceRole::Consumer, TestStage::Readiness),
                event(CoreServiceRole::Consumer, TestStage::Drain),
                event(CoreServiceRole::Consumer, TestStage::Stop),
                event(CoreServiceRole::Provider, TestStage::Drain),
                event(CoreServiceRole::Provider, TestStage::Stop),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_timeout_is_bounded_and_rolls_back_without_leaking_obligations() {
        let root = CancellationSource::root();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut owner = owner(
            &root,
            &events,
            ReadinessBehavior::Ready,
            ReadinessBehavior::Pending,
            false,
            false,
            budgets(1),
        );

        let outcome = owner.startup().await;
        let super::CoreServiceStartupOutcome::Failed(failure) = outcome else {
            panic!("pending readiness must time out");
        };
        assert_eq!(failure.role(), CoreServiceRole::Consumer);
        assert_eq!(failure.stage(), CoreServiceStage::Readiness);
        assert_eq!(failure.fact(), CoreServiceStageFact::TimedOut);
        let report = owner
            .terminal_report()
            .unwrap_or_else(|error| panic!("rollback must persist a terminal report: {error}"));
        assert!(report.cleanup().is_zero_cleanup());
        assert!(!report.is_acceptable());
        assert!(
            report
                .cleanup()
                .services()
                .into_iter()
                .all(|fact| !fact.cleanup_pending())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn drain_failure_is_not_erased_by_successful_stop_or_repeated_shutdown() {
        let root = CancellationSource::root();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut owner = owner(
            &root,
            &events,
            ReadinessBehavior::Ready,
            ReadinessBehavior::Ready,
            true,
            false,
            budgets(10),
        );

        assert!(owner.startup().await.is_ready());
        root.cancel();
        let first = owner.shutdown().await;
        let repeated = owner.shutdown().await;
        assert_eq!(first, repeated);
        assert!(!first.is_zero_cleanup());
        let consumer = first.services()[CONSUMER_INDEX];
        assert_eq!(consumer.role(), CoreServiceRole::Consumer);
        assert_eq!(consumer.drain(), CoreServiceStageFact::Failed);
        assert_eq!(consumer.stop(), CoreServiceStageFact::Succeeded);
        assert!(consumer.cleanup_pending());
        let snapshot = owner
            .snapshot()
            .unwrap_or_else(|error| panic!("nonzero snapshot must remain readable: {error}"));
        assert_eq!(
            snapshot.services()[CONSUMER_INDEX].lifecycle(),
            CoreServiceLifecycle::CleanupFailed
        );
        assert_eq!(
            snapshot.services()[CONSUMER_INDEX].prepare(),
            CoreServiceStageFact::Succeeded
        );
        assert_eq!(
            snapshot.services()[CONSUMER_INDEX].start(),
            CoreServiceStageFact::Succeeded
        );
        assert_eq!(
            snapshot.services()[CONSUMER_INDEX].readiness(),
            CoreServiceReadinessFact::Ready
        );
        assert_eq!(
            snapshot.services()[CONSUMER_INDEX].drain(),
            CoreServiceStageFact::Failed
        );
        assert_eq!(
            snapshot.services()[CONSUMER_INDEX].stop(),
            CoreServiceStageFact::Succeeded
        );
        assert!(snapshot.services()[CONSUMER_INDEX].cleanup_pending());
    }

    #[test]
    fn identities_and_budgets_fail_closed_before_service_callbacks() {
        let root = CancellationSource::root();
        let events = Arc::new(Mutex::new(Vec::new()));
        let duplicate = CoreServiceLifecycleOwner::try_new(
            identity(1),
            fake(
                CoreServiceRole::Provider,
                identity(1),
                &events,
                ReadinessBehavior::Ready,
                false,
                false,
            ),
            identity(1),
            fake(
                CoreServiceRole::Consumer,
                identity(1),
                &events,
                ReadinessBehavior::Ready,
                false,
                false,
            ),
            clock(),
            budgets(10),
            &root,
        );
        assert!(matches!(
            duplicate,
            Err(super::CoreServiceLifecycleError::DuplicateIdentity)
        ));
        assert!(
            CoreServiceLifecycleBudgets::try_new(
                BoundedDuration::from_nanos(0),
                BoundedDuration::from_nanos(1),
                BoundedDuration::from_nanos(1),
                BoundedDuration::from_nanos(1),
                BoundedDuration::from_nanos(1),
            )
            .is_err()
        );
        assert!(recorded(&events).is_empty());
    }
}
