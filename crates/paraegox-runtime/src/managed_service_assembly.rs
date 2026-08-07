//! RuntimeHost-owned lifecycle assembly for one managed CoreService.
//!
//! This is the first consumer of the versioned managed-service contract. It
//! owns callback ordering, bounded waits, cancellation, cleanup, observed
//! lifecycle state, and runtime-generation fencing. It deliberately does not
//! resolve a Service dependency graph, launch a ProcessDomain, own desired
//! state, or expose a second RuntimeHost entrypoint.

use core::fmt;
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::time::Duration;
use std::panic::{AssertUnwindSafe, catch_unwind};

use paraegox_kernel::time::{ClockReading, MonotonicDeadline};
use paraegox_runtime_contracts::managed_service::{
    ManagedServiceGeneration, ManagedServiceId, ManagedServiceLifecycleStage, ManagedServiceSpecV1,
};

use crate::runtime_clock::{RuntimeClock, RuntimeClockError};
use crate::task_registry::{CancellationSource, CancellationView};

/// Callback result reported by one managed-service implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedServiceFailure {
    Failed,
}

/// Bounded implementation-owned readiness observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedServiceReadiness {
    Ready,
    NotReady,
}

/// Exact callback attempt issued by the RuntimeHost owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedServiceAttempt {
    service_id: ManagedServiceId,
    generation: ManagedServiceGeneration,
    stage: ManagedServiceLifecycleStage,
}

impl ManagedServiceAttempt {
    const fn new(
        service_id: ManagedServiceId,
        generation: ManagedServiceGeneration,
        stage: ManagedServiceLifecycleStage,
    ) -> Self {
        Self {
            service_id,
            generation,
            stage,
        }
    }
}

/// Correlated callback completion. The assembly rejects a completion from a
/// different service, generation, or stage before it can advance lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedServiceCompletion<T> {
    attempt: ManagedServiceAttempt,
    outcome: Result<T, ManagedServiceFailure>,
}

impl<T> ManagedServiceCompletion<T> {
    #[must_use]
    pub(crate) const fn succeeded(attempt: ManagedServiceAttempt, value: T) -> Self {
        Self {
            attempt,
            outcome: Ok(value),
        }
    }

    #[must_use]
    pub(crate) const fn failed(attempt: ManagedServiceAttempt) -> Self {
        Self {
            attempt,
            outcome: Err(ManagedServiceFailure::Failed),
        }
    }
}

/// Narrow callback context. It exposes neither RuntimeHost nor raw Fabric.
#[derive(Clone, Debug)]
pub(crate) struct ManagedServiceContext {
    service_id: ManagedServiceId,
    generation: ManagedServiceGeneration,
    clock: RuntimeClock,
    cancellation: CancellationView,
}

impl ManagedServiceContext {
    const fn new(
        service_id: ManagedServiceId,
        generation: ManagedServiceGeneration,
        clock: RuntimeClock,
        cancellation: CancellationView,
    ) -> Self {
        Self {
            service_id,
            generation,
            clock,
            cancellation,
        }
    }

    #[must_use]
    pub(crate) const fn service_id(&self) -> ManagedServiceId {
        self.service_id
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> ManagedServiceGeneration {
        self.generation
    }

    pub(crate) fn clock_reading(&self) -> Result<ClockReading, RuntimeClockError> {
        self.clock.reading()
    }

    #[must_use]
    pub(crate) const fn cancellation(&self) -> &CancellationView {
        &self.cancellation
    }
}

/// Boxed callback future keeps the implementation seam private and avoids a
/// Rust plugin ABI or another async runtime.
pub(crate) type ManagedServiceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Private implementation seam consumed by the single-service assembly.
pub(crate) trait ManagedServiceImplementation: Send {
    fn prepare<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>>;

    fn start<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>>;

    fn readiness<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<ManagedServiceReadiness>>;

    fn drain<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
        deadline: MonotonicDeadline,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>>;

    fn stop<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>>;
}

/// RuntimeHost-observed lifecycle. An implementation cannot write this state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedServiceLifecycle {
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

/// Structured observation for one bounded callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedServiceStageFact {
    NotAttempted,
    NotRequired,
    Succeeded,
    NotReady,
    Failed,
    TimedOut,
    Cancelled,
    Panicked,
    Fenced,
    ClockFailed,
}

impl ManagedServiceStageFact {
    const fn callback_succeeded(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

/// Stable startup outcome for the exact service generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedServiceStartupOutcome {
    Ready,
    Failed {
        stage: ManagedServiceLifecycleStage,
        fact: ManagedServiceStageFact,
    },
}

/// Copy-only snapshot of the Runtime-owned lifecycle facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedServiceSnapshot {
    observed_at: ClockReading,
    service_id: ManagedServiceId,
    generation: ManagedServiceGeneration,
    lifecycle: ManagedServiceLifecycle,
    prepare: ManagedServiceStageFact,
    start: ManagedServiceStageFact,
    readiness: ManagedServiceStageFact,
    drain: ManagedServiceStageFact,
    stop: ManagedServiceStageFact,
    cleanup_pending: bool,
}

impl ManagedServiceSnapshot {
    #[must_use]
    pub(crate) const fn observed_at(self) -> ClockReading {
        self.observed_at
    }

    #[must_use]
    pub(crate) const fn service_id(self) -> ManagedServiceId {
        self.service_id
    }

    #[must_use]
    pub(crate) const fn generation(self) -> ManagedServiceGeneration {
        self.generation
    }

    #[must_use]
    pub(crate) const fn lifecycle(self) -> ManagedServiceLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub(crate) const fn prepare(self) -> ManagedServiceStageFact {
        self.prepare
    }

    #[must_use]
    pub(crate) const fn start(self) -> ManagedServiceStageFact {
        self.start
    }

    #[must_use]
    pub(crate) const fn readiness(self) -> ManagedServiceStageFact {
        self.readiness
    }

    #[must_use]
    pub(crate) const fn drain(self) -> ManagedServiceStageFact {
        self.drain
    }

    #[must_use]
    pub(crate) const fn stop(self) -> ManagedServiceStageFact {
        self.stop
    }

    #[must_use]
    pub(crate) const fn cleanup_pending(self) -> bool {
        self.cleanup_pending
    }
}

/// Terminal cleanup evidence for the exact service generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedServiceCleanupReport {
    drain: ManagedServiceStageFact,
    stop: ManagedServiceStageFact,
    cleanup_pending: bool,
}

impl ManagedServiceCleanupReport {
    #[must_use]
    pub(crate) const fn drain(self) -> ManagedServiceStageFact {
        self.drain
    }

    #[must_use]
    pub(crate) const fn stop(self) -> ManagedServiceStageFact {
        self.stop
    }

    #[must_use]
    pub(crate) const fn exact_zero(self) -> bool {
        !self.cleanup_pending
    }
}

/// Sole lifecycle owner for one exact managed service and generation.
pub(crate) struct ManagedServiceAssembly {
    spec: ManagedServiceSpecV1,
    generation: ManagedServiceGeneration,
    clock: RuntimeClock,
    service: Box<dyn ManagedServiceImplementation>,
    cancellation: CancellationSource,
    parent_cancellation: CancellationView,
    lifecycle: ManagedServiceLifecycle,
    prepare: ManagedServiceStageFact,
    start: ManagedServiceStageFact,
    readiness: ManagedServiceStageFact,
    drain: ManagedServiceStageFact,
    stop: ManagedServiceStageFact,
    cleanup_required: bool,
    drain_required: bool,
    startup_outcome: Option<ManagedServiceStartupOutcome>,
    cleanup_report: Option<ManagedServiceCleanupReport>,
}

impl ManagedServiceAssembly {
    #[must_use]
    pub(crate) fn new(
        spec: ManagedServiceSpecV1,
        generation: ManagedServiceGeneration,
        service: Box<dyn ManagedServiceImplementation>,
        clock: RuntimeClock,
        parent_cancellation: &CancellationSource,
    ) -> Self {
        Self {
            spec,
            generation,
            clock,
            service,
            cancellation: parent_cancellation.child(),
            parent_cancellation: parent_cancellation.view(),
            lifecycle: ManagedServiceLifecycle::Created,
            prepare: ManagedServiceStageFact::NotAttempted,
            start: ManagedServiceStageFact::NotAttempted,
            readiness: ManagedServiceStageFact::NotAttempted,
            drain: ManagedServiceStageFact::NotAttempted,
            stop: ManagedServiceStageFact::NotAttempted,
            cleanup_required: false,
            drain_required: false,
            startup_outcome: None,
            cleanup_report: None,
        }
    }

    /// Executes prepare -> start -> readiness exactly once. Any non-success
    /// immediately performs bounded cleanup without advancing to the next stage.
    pub(crate) async fn startup(&mut self) -> ManagedServiceStartupOutcome {
        if let Some(outcome) = self.startup_outcome {
            return outcome;
        }

        let prepare = self.prepare().await;
        if !prepare.callback_succeeded() {
            return self
                .fail_startup(ManagedServiceLifecycleStage::Prepare, prepare)
                .await;
        }

        let start = self.start().await;
        if !start.callback_succeeded() {
            return self
                .fail_startup(ManagedServiceLifecycleStage::Start, start)
                .await;
        }

        let readiness = self.readiness().await;
        if !readiness.callback_succeeded() {
            return self
                .fail_startup(ManagedServiceLifecycleStage::Readiness, readiness)
                .await;
        }

        let outcome = ManagedServiceStartupOutcome::Ready;
        self.startup_outcome = Some(outcome);
        outcome
    }

    /// Cancels the callback context, then drains and stops exactly once.
    pub(crate) async fn shutdown(&mut self) -> ManagedServiceCleanupReport {
        if let Some(report) = self.cleanup_report {
            return report;
        }

        self.cancellation.cancel();
        if !self.cleanup_required {
            self.drain = ManagedServiceStageFact::NotRequired;
            self.stop = ManagedServiceStageFact::NotRequired;
        } else {
            if self.drain_required {
                self.drain().await;
            } else {
                self.drain = ManagedServiceStageFact::NotRequired;
            }
            self.stop().await;
        }

        let report = ManagedServiceCleanupReport {
            drain: self.drain,
            stop: self.stop,
            cleanup_pending: self.cleanup_required,
        };
        self.cleanup_report = Some(report);
        report
    }

    pub(crate) fn snapshot(&self) -> Result<ManagedServiceSnapshot, ManagedServiceAssemblyError> {
        Ok(ManagedServiceSnapshot {
            observed_at: self.clock.reading()?,
            service_id: self.spec.service_id(),
            generation: self.generation,
            lifecycle: self.lifecycle,
            prepare: self.prepare,
            start: self.start,
            readiness: self.readiness,
            drain: self.drain,
            stop: self.stop,
            cleanup_pending: self.cleanup_required,
        })
    }

    fn context(&self) -> ManagedServiceContext {
        ManagedServiceContext::new(
            self.spec.service_id(),
            self.generation,
            self.clock,
            self.cancellation.view(),
        )
    }

    fn attempt(&self, stage: ManagedServiceLifecycleStage) -> ManagedServiceAttempt {
        ManagedServiceAttempt::new(self.spec.service_id(), self.generation, stage)
    }

    fn cancelled(&self) -> bool {
        self.parent_cancellation.is_cancelled() || self.cancellation.view().is_cancelled()
    }

    async fn fail_startup(
        &mut self,
        stage: ManagedServiceLifecycleStage,
        fact: ManagedServiceStageFact,
    ) -> ManagedServiceStartupOutcome {
        let outcome = ManagedServiceStartupOutcome::Failed { stage, fact };
        self.startup_outcome = Some(outcome);
        let _ = self.shutdown().await;
        outcome
    }

    async fn prepare(&mut self) -> ManagedServiceStageFact {
        if self.cancelled() {
            self.prepare = ManagedServiceStageFact::Cancelled;
            self.lifecycle = ManagedServiceLifecycle::StartupFailed;
            return self.prepare;
        }

        self.cleanup_required = true;
        self.lifecycle = ManagedServiceLifecycle::Preparing;
        let context = self.context();
        let attempt = self.attempt(ManagedServiceLifecycleStage::Prepare);
        let service = &mut self.service;
        let callback = async { service.prepare(&context, attempt).await };
        let fact = unit_callback_fact(
            callback,
            self.spec
                .lifecycle_budgets()
                .for_stage(ManagedServiceLifecycleStage::Prepare),
            attempt,
        )
        .await;
        self.prepare = fact;
        self.lifecycle = if fact.callback_succeeded() {
            ManagedServiceLifecycle::Prepared
        } else {
            self.cancellation.cancel();
            ManagedServiceLifecycle::StartupFailed
        };
        fact
    }

    async fn start(&mut self) -> ManagedServiceStageFact {
        if self.cancelled() {
            self.start = ManagedServiceStageFact::Cancelled;
            self.lifecycle = ManagedServiceLifecycle::StartupFailed;
            return self.start;
        }

        self.drain_required = true;
        self.lifecycle = ManagedServiceLifecycle::Starting;
        let context = self.context();
        let attempt = self.attempt(ManagedServiceLifecycleStage::Start);
        let service = &mut self.service;
        let callback = async { service.start(&context, attempt).await };
        let fact = unit_callback_fact(
            callback,
            self.spec
                .lifecycle_budgets()
                .for_stage(ManagedServiceLifecycleStage::Start),
            attempt,
        )
        .await;
        self.start = fact;
        self.lifecycle = if fact.callback_succeeded() {
            ManagedServiceLifecycle::Started
        } else {
            self.cancellation.cancel();
            ManagedServiceLifecycle::StartupFailed
        };
        fact
    }

    async fn readiness(&mut self) -> ManagedServiceStageFact {
        if self.cancelled() {
            self.readiness = ManagedServiceStageFact::Cancelled;
            self.lifecycle = ManagedServiceLifecycle::StartupFailed;
            return self.readiness;
        }

        self.lifecycle = ManagedServiceLifecycle::CheckingReadiness;
        let context = self.context();
        let attempt = self.attempt(ManagedServiceLifecycleStage::Readiness);
        let service = &mut self.service;
        let callback = async { service.readiness(&context, attempt).await };
        let fact = readiness_callback_fact(
            callback,
            self.spec
                .lifecycle_budgets()
                .for_stage(ManagedServiceLifecycleStage::Readiness),
            attempt,
        )
        .await;
        self.readiness = fact;
        self.lifecycle = if fact.callback_succeeded() {
            ManagedServiceLifecycle::Ready
        } else {
            self.cancellation.cancel();
            ManagedServiceLifecycle::StartupFailed
        };
        fact
    }

    async fn drain(&mut self) {
        self.lifecycle = ManagedServiceLifecycle::Draining;
        let budget = self
            .spec
            .lifecycle_budgets()
            .for_stage(ManagedServiceLifecycleStage::Drain);
        let deadline = match self.clock.deadline_after(budget) {
            Ok(deadline) => deadline,
            Err(_) => {
                self.drain = ManagedServiceStageFact::ClockFailed;
                return;
            }
        };
        let context = self.context();
        let attempt = self.attempt(ManagedServiceLifecycleStage::Drain);
        let service = &mut self.service;
        let callback = async { service.drain(&context, attempt, deadline).await };
        self.drain = unit_callback_fact(callback, budget, attempt).await;
    }

    async fn stop(&mut self) {
        self.lifecycle = ManagedServiceLifecycle::Stopping;
        let context = self.context();
        let attempt = self.attempt(ManagedServiceLifecycleStage::Stop);
        let service = &mut self.service;
        let callback = async { service.stop(&context, attempt).await };
        let fact = unit_callback_fact(
            callback,
            self.spec
                .lifecycle_budgets()
                .for_stage(ManagedServiceLifecycleStage::Stop),
            attempt,
        )
        .await;
        self.stop = fact;
        if fact.callback_succeeded()
            && matches!(
                self.drain,
                ManagedServiceStageFact::Succeeded | ManagedServiceStageFact::NotRequired
            )
        {
            self.cleanup_required = false;
            self.lifecycle = ManagedServiceLifecycle::Stopped;
        } else {
            self.lifecycle = ManagedServiceLifecycle::CleanupFailed;
        }
    }
}

async fn unit_callback_fact<F>(
    callback: F,
    budget: paraegox_kernel::time::BoundedDuration,
    expected: ManagedServiceAttempt,
) -> ManagedServiceStageFact
where
    F: Future<Output = ManagedServiceCompletion<()>>,
{
    match tokio::time::timeout(duration(budget), catch_callback(callback)).await {
        Ok(Ok(completion)) if completion.attempt != expected => ManagedServiceStageFact::Fenced,
        Ok(Ok(ManagedServiceCompletion {
            outcome: Ok(()), ..
        })) => ManagedServiceStageFact::Succeeded,
        Ok(Ok(ManagedServiceCompletion {
            outcome: Err(ManagedServiceFailure::Failed),
            ..
        })) => ManagedServiceStageFact::Failed,
        Ok(Err(())) => ManagedServiceStageFact::Panicked,
        Err(_) => ManagedServiceStageFact::TimedOut,
    }
}

async fn readiness_callback_fact<F>(
    callback: F,
    budget: paraegox_kernel::time::BoundedDuration,
    expected: ManagedServiceAttempt,
) -> ManagedServiceStageFact
where
    F: Future<Output = ManagedServiceCompletion<ManagedServiceReadiness>>,
{
    match tokio::time::timeout(duration(budget), catch_callback(callback)).await {
        Ok(Ok(completion)) if completion.attempt != expected => ManagedServiceStageFact::Fenced,
        Ok(Ok(ManagedServiceCompletion {
            outcome: Ok(ManagedServiceReadiness::Ready),
            ..
        })) => ManagedServiceStageFact::Succeeded,
        Ok(Ok(ManagedServiceCompletion {
            outcome: Ok(ManagedServiceReadiness::NotReady),
            ..
        })) => ManagedServiceStageFact::NotReady,
        Ok(Ok(ManagedServiceCompletion {
            outcome: Err(ManagedServiceFailure::Failed),
            ..
        })) => ManagedServiceStageFact::Failed,
        Ok(Err(())) => ManagedServiceStageFact::Panicked,
        Err(_) => ManagedServiceStageFact::TimedOut,
    }
}

const fn duration(value: paraegox_kernel::time::BoundedDuration) -> Duration {
    Duration::from_nanos(value.value())
}

/// Contains callback polling and destruction panics so cleanup can still run.
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

/// Fail-closed assembly failures outside implementation callback results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedServiceAssemblyError {
    Clock(RuntimeClockError),
}

impl From<RuntimeClockError> for ManagedServiceAssemblyError {
    fn from(value: RuntimeClockError) -> Self {
        Self::Clock(value)
    }
}

impl fmt::Display for ManagedServiceAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(error) => {
                write!(formatter, "managed-service assembly clock failed: {error}")
            }
        }
    }
}

impl std::error::Error for ManagedServiceAssemblyError {}

#[cfg(test)]
mod tests {
    use core::future::pending;
    use std::sync::{Arc, Mutex};

    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::managed_service::{
        ManagedServiceGeneration, ManagedServiceId, ManagedServiceLifecycleBudgetsV1,
        ManagedServiceLifecycleStage, ManagedServiceSpecV1,
    };

    use super::{
        ManagedServiceAssembly, ManagedServiceAttempt, ManagedServiceCompletion,
        ManagedServiceContext, ManagedServiceFuture, ManagedServiceImplementation,
        ManagedServiceLifecycle, ManagedServiceReadiness, ManagedServiceStageFact,
        ManagedServiceStartupOutcome,
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
    enum TestBehavior {
        Ready,
        NotReady,
        StalePrepareGeneration,
        PendingStart,
    }

    struct FakeManagedService {
        expected_id: ManagedServiceId,
        expected_generation: ManagedServiceGeneration,
        behavior: TestBehavior,
        events: Arc<Mutex<Vec<TestStage>>>,
        cancellation: Option<CancellationView>,
    }

    impl FakeManagedService {
        fn record(&self, stage: TestStage) {
            self.events
                .lock()
                .unwrap_or_else(|_| panic!("event log must remain usable"))
                .push(stage);
        }

        fn context_is_exact(&self, context: &ManagedServiceContext) -> bool {
            context.service_id() == self.expected_id
                && context.generation() == self.expected_generation
                && context.clock_reading().is_ok()
                && !context.cancellation().is_cancelled()
        }
    }

    impl ManagedServiceImplementation for FakeManagedService {
        fn prepare<'a>(
            &'a mut self,
            context: &'a ManagedServiceContext,
            attempt: ManagedServiceAttempt,
        ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
            self.record(TestStage::Prepare);
            let context_valid = self.context_is_exact(context);
            self.cancellation = Some(context.cancellation().clone());
            let completion = if !context_valid {
                ManagedServiceCompletion::failed(attempt)
            } else if self.behavior == TestBehavior::StalePrepareGeneration {
                let stale_generation = ManagedServiceGeneration::try_new(
                    self.expected_generation.value().saturating_sub(1),
                )
                .unwrap_or_else(|error| panic!("stale fixture generation must exist: {error}"));
                ManagedServiceCompletion::succeeded(
                    ManagedServiceAttempt {
                        generation: stale_generation,
                        ..attempt
                    },
                    (),
                )
            } else {
                ManagedServiceCompletion::succeeded(attempt, ())
            };
            Box::pin(async move { completion })
        }

        fn start<'a>(
            &'a mut self,
            _context: &'a ManagedServiceContext,
            attempt: ManagedServiceAttempt,
        ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
            self.record(TestStage::Start);
            if self.behavior == TestBehavior::PendingStart {
                return Box::pin(pending());
            }
            Box::pin(async move { ManagedServiceCompletion::succeeded(attempt, ()) })
        }

        fn readiness<'a>(
            &'a mut self,
            _context: &'a ManagedServiceContext,
            attempt: ManagedServiceAttempt,
        ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<ManagedServiceReadiness>> {
            self.record(TestStage::Readiness);
            let readiness = if self.behavior == TestBehavior::NotReady {
                ManagedServiceReadiness::NotReady
            } else {
                ManagedServiceReadiness::Ready
            };
            Box::pin(async move { ManagedServiceCompletion::succeeded(attempt, readiness) })
        }

        fn drain<'a>(
            &'a mut self,
            _context: &'a ManagedServiceContext,
            attempt: ManagedServiceAttempt,
            _deadline: paraegox_kernel::time::MonotonicDeadline,
        ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
            self.record(TestStage::Drain);
            Box::pin(async move { ManagedServiceCompletion::succeeded(attempt, ()) })
        }

        fn stop<'a>(
            &'a mut self,
            context: &'a ManagedServiceContext,
            attempt: ManagedServiceAttempt,
        ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
            self.record(TestStage::Stop);
            let cancellation_visible = context.cancellation().is_cancelled();
            Box::pin(async move {
                if cancellation_visible {
                    ManagedServiceCompletion::succeeded(attempt, ())
                } else {
                    ManagedServiceCompletion::failed(attempt)
                }
            })
        }
    }

    fn generation(value: u64) -> ManagedServiceGeneration {
        ManagedServiceGeneration::try_new(value)
            .unwrap_or_else(|error| panic!("fixture generation must be valid: {error}"))
    }

    fn clock() -> RuntimeClock {
        let generation = ClockGeneration::try_new(1)
            .unwrap_or_else(|error| panic!("fixture clock generation must be valid: {error}"));
        RuntimeClock::new(ClockDomainRef::from_bytes([0x71; 16]), generation, 0)
    }

    fn spec(service_id: ManagedServiceId, stage_budget: u64) -> ManagedServiceSpecV1 {
        let duration = BoundedDuration::from_nanos(stage_budget);
        let budgets = ManagedServiceLifecycleBudgetsV1::try_new(
            duration, duration, duration, duration, duration,
        )
        .unwrap_or_else(|error| panic!("fixture lifecycle budgets must be valid: {error}"));
        ManagedServiceSpecV1::new(service_id, budgets)
    }

    fn assembly(
        behavior: TestBehavior,
        stage_budget: u64,
    ) -> (
        ManagedServiceAssembly,
        Arc<Mutex<Vec<TestStage>>>,
        CancellationSource,
    ) {
        let service_id = ManagedServiceId::from_bytes([0x61; 16]);
        let service_generation = generation(7);
        let events = Arc::new(Mutex::new(Vec::new()));
        let parent_cancellation = CancellationSource::root();
        let service = FakeManagedService {
            expected_id: service_id,
            expected_generation: service_generation,
            behavior,
            events: Arc::clone(&events),
            cancellation: None,
        };
        let assembly = ManagedServiceAssembly::new(
            spec(service_id, stage_budget),
            service_generation,
            Box::new(service),
            clock(),
            &parent_cancellation,
        );
        (assembly, events, parent_cancellation)
    }

    fn event_snapshot(events: &Arc<Mutex<Vec<TestStage>>>) -> Vec<TestStage> {
        events
            .lock()
            .unwrap_or_else(|_| panic!("event log must remain usable"))
            .clone()
    }

    #[tokio::test(start_paused = true)]
    async fn contract_is_consumed_by_one_real_runtime_owned_lifecycle() {
        let (mut assembly, events, _parent) = assembly(TestBehavior::Ready, 1_000);

        assert_eq!(
            assembly.startup().await,
            ManagedServiceStartupOutcome::Ready
        );
        let ready = assembly
            .snapshot()
            .unwrap_or_else(|error| panic!("ready snapshot must be available: {error}"));
        assert_eq!(ready.service_id().as_bytes(), &[0x61; 16]);
        assert_eq!(ready.generation(), generation(7));
        assert_eq!(ready.lifecycle(), ManagedServiceLifecycle::Ready);
        assert_eq!(ready.prepare(), ManagedServiceStageFact::Succeeded);
        assert_eq!(ready.start(), ManagedServiceStageFact::Succeeded);
        assert_eq!(ready.readiness(), ManagedServiceStageFact::Succeeded);
        assert!(!ready.observed_at().now().value().eq(&u64::MAX));

        let cleanup = assembly.shutdown().await;
        assert!(cleanup.exact_zero());
        assert_eq!(cleanup.drain(), ManagedServiceStageFact::Succeeded);
        assert_eq!(cleanup.stop(), ManagedServiceStageFact::Succeeded);
        let stopped = assembly
            .snapshot()
            .unwrap_or_else(|error| panic!("terminal snapshot must be available: {error}"));
        assert_eq!(stopped.lifecycle(), ManagedServiceLifecycle::Stopped);
        assert!(!stopped.cleanup_pending());
        assert_eq!(stopped.drain(), ManagedServiceStageFact::Succeeded);
        assert_eq!(stopped.stop(), ManagedServiceStageFact::Succeeded);
        assert_eq!(
            event_snapshot(&events),
            vec![
                TestStage::Prepare,
                TestStage::Start,
                TestStage::Readiness,
                TestStage::Drain,
                TestStage::Stop,
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stale_generation_completion_is_fenced_before_start_or_ready() {
        let (mut assembly, events, _parent) = assembly(TestBehavior::StalePrepareGeneration, 1_000);

        assert_eq!(
            assembly.startup().await,
            ManagedServiceStartupOutcome::Failed {
                stage: ManagedServiceLifecycleStage::Prepare,
                fact: ManagedServiceStageFact::Fenced,
            }
        );
        let snapshot = assembly
            .snapshot()
            .unwrap_or_else(|error| panic!("failure snapshot must be available: {error}"));
        assert_eq!(snapshot.prepare(), ManagedServiceStageFact::Fenced);
        assert_eq!(snapshot.start(), ManagedServiceStageFact::NotAttempted);
        assert_eq!(snapshot.readiness(), ManagedServiceStageFact::NotAttempted);
        assert_eq!(snapshot.lifecycle(), ManagedServiceLifecycle::Stopped);
        assert_eq!(
            event_snapshot(&events),
            vec![TestStage::Prepare, TestStage::Stop]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn not_ready_rolls_back_started_service_with_bounded_cleanup() {
        let (mut assembly, events, _parent) = assembly(TestBehavior::NotReady, 1_000);

        assert_eq!(
            assembly.startup().await,
            ManagedServiceStartupOutcome::Failed {
                stage: ManagedServiceLifecycleStage::Readiness,
                fact: ManagedServiceStageFact::NotReady,
            }
        );
        assert_eq!(
            event_snapshot(&events),
            vec![
                TestStage::Prepare,
                TestStage::Start,
                TestStage::Readiness,
                TestStage::Drain,
                TestStage::Stop,
            ]
        );
        assert!(assembly.shutdown().await.exact_zero());
    }

    #[tokio::test(start_paused = true)]
    async fn lifecycle_budget_times_out_pending_start_and_still_cleans_up() {
        let (mut assembly, events, _parent) = assembly(TestBehavior::PendingStart, 10);

        assert_eq!(
            assembly.startup().await,
            ManagedServiceStartupOutcome::Failed {
                stage: ManagedServiceLifecycleStage::Start,
                fact: ManagedServiceStageFact::TimedOut,
            }
        );
        assert_eq!(
            event_snapshot(&events),
            vec![
                TestStage::Prepare,
                TestStage::Start,
                TestStage::Drain,
                TestStage::Stop,
            ]
        );
        assert!(assembly.shutdown().await.exact_zero());
    }
}
