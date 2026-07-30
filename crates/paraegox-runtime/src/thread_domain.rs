//! RuntimeHost-owned bounded synchronous execution without a hidden backlog.
//!
//! Each worker owns one bounded command slot. A caller must first reserve that
//! exact worker before its callable is constructed, and the reservation stays
//! charged until the owner accepts or fences the result. Cancellation is only
//! an observable request: a running OS thread is never reported as terminated.

use core::fmt;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::time::Duration;
use std::collections::BTreeMap;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crate::card_instance::{DomainEpoch, InvocationId};
use crate::executor_budget::ExecutorReservation;

/// A defensive ceiling for one in-process synchronous execution class.
const MAX_THREAD_DOMAIN_WORKERS: usize = 64;

/// The admitted fixed worker count for one ThreadDomain generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadDomainConfig {
    workers: NonZeroUsize,
    start_budget: Duration,
}

impl ThreadDomainConfig {
    pub(crate) fn try_new(
        workers: usize,
        start_budget: Duration,
    ) -> Result<Self, ThreadDomainBuildError> {
        let Some(workers) = NonZeroUsize::new(workers) else {
            return Err(ThreadDomainBuildError::InvalidWorkerCount);
        };
        if workers.get() > MAX_THREAD_DOMAIN_WORKERS {
            return Err(ThreadDomainBuildError::InvalidWorkerCount);
        }
        if start_budget.is_zero() {
            return Err(ThreadDomainBuildError::InvalidStartBudget);
        }
        Ok(Self {
            workers,
            start_budget,
        })
    }

    #[must_use]
    pub(crate) const fn workers(self) -> usize {
        self.workers.get()
    }

    #[must_use]
    pub(crate) const fn start_budget(self) -> Duration {
        self.start_budget
    }
}

/// A callable-facing cancellation observation with no thread or executor
/// mutation authority.
#[derive(Clone, Debug)]
pub(crate) struct ThreadCancellation {
    control: Arc<InvocationControl>,
}

impl ThreadCancellation {
    #[must_use]
    pub(crate) fn is_cancellation_requested(&self) -> bool {
        self.control.cancelled.load(Ordering::Acquire)
    }
}

/// Opaque identity for one concrete owner allocation. The marker prevents a
/// repeated numeric epoch in a successor fixture from accepting stale output.
#[derive(Clone, Debug)]
struct ThreadDomainOwnerIdentity {
    domain_epoch: DomainEpoch,
    marker: Arc<()>,
}

impl ThreadDomainOwnerIdentity {
    fn new(domain_epoch: DomainEpoch) -> Self {
        Self {
            domain_epoch,
            marker: Arc::new(()),
        }
    }
}

impl PartialEq for ThreadDomainOwnerIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.domain_epoch == other.domain_epoch && Arc::ptr_eq(&self.marker, &other.marker)
    }
}

impl Eq for ThreadDomainOwnerIdentity {}

/// Copy-free completion credential carried by a ThreadDomain invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ThreadInvocationFence {
    owner: ThreadDomainOwnerIdentity,
    domain_epoch: DomainEpoch,
    invocation: InvocationId,
}

impl ThreadInvocationFence {
    #[must_use]
    pub(crate) const fn domain_epoch(&self) -> DomainEpoch {
        self.domain_epoch
    }

    #[must_use]
    pub(crate) const fn invocation(&self) -> InvocationId {
        self.invocation
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FenceReasonCode {
    Open = 0,
    CancellationRequested = 1,
    Uncertain = 2,
    Wedged = 3,
    Shutdown = 4,
    HandleDropped = 5,
}

impl FenceReasonCode {
    fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::CancellationRequested,
            2 => Self::Uncertain,
            3 => Self::Wedged,
            4 => Self::Shutdown,
            5 => Self::HandleDropped,
            _ => Self::Open,
        }
    }

    const fn observable(self) -> Option<LateResultReason> {
        match self {
            Self::Open => None,
            Self::CancellationRequested => Some(LateResultReason::CancellationRequested),
            Self::Uncertain => Some(LateResultReason::Uncertain),
            Self::Wedged => Some(LateResultReason::Wedged),
            Self::Shutdown | Self::HandleDropped => Some(LateResultReason::Shutdown),
        }
    }

    const fn precedence(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::CancellationRequested => 1,
            Self::Uncertain => 2,
            // The first terminal fence wins. In particular, an already-wedged
            // invocation remains wedged during shutdown, while an invocation
            // first fenced by shutdown cannot later be relabelled wedged.
            Self::Wedged | Self::Shutdown | Self::HandleDropped => 3,
        }
    }
}

#[derive(Debug)]
struct InvocationControl {
    cancelled: AtomicBool,
    fence_reason: AtomicU8,
}

impl InvocationControl {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            fence_reason: AtomicU8::new(FenceReasonCode::Open as u8),
        }
    }

    fn fence(&self, reason: FenceReasonCode) {
        self.cancelled.store(true, Ordering::Release);
        let mut current = self.fence_reason.load(Ordering::Acquire);
        loop {
            let current_reason = FenceReasonCode::from_raw(current);
            if reason.precedence() <= current_reason.precedence() {
                return;
            }
            match self.fence_reason.compare_exchange_weak(
                current,
                reason as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    fn reason(&self) -> FenceReasonCode {
        FenceReasonCode::from_raw(self.fence_reason.load(Ordering::Acquire))
    }
}

/// Honest owner observation while a synchronous callable is still charged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadInvocationObservation {
    Running,
    CancellationRequested,
    Uncertain,
    Wedged,
    ResultPending,
}

/// Why a returned value was not allowed to cross the owner fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LateResultReason {
    CancellationRequested,
    Uncertain,
    Wedged,
    Shutdown,
}

/// Poll result for one explicitly owned result slot.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ThreadCompletion<T> {
    Pending(ThreadInvocationObservation),
    Returned(T),
    Panicked,
    LateRejected(LateResultReason),
}

enum WorkerOutcome<T> {
    Returned(T),
    Panicked,
}

/// An explicit result slot. It is bounded one-for-one with a charged worker;
/// dropping it requests cancellation but never claims the thread was stopped.
#[must_use = "a ThreadDomain invocation must be observed, fenced, or shut down"]
pub(crate) struct ThreadInvocation<T: Send + 'static> {
    fence: ThreadInvocationFence,
    control: Arc<InvocationControl>,
    shared: Arc<SharedState<T>>,
    consumed: bool,
    result_pending_observed: bool,
}

impl<T: Send + 'static> ThreadInvocation<T> {
    #[must_use]
    pub(crate) const fn fence(&self) -> &ThreadInvocationFence {
        &self.fence
    }
}

impl<T: Send + 'static> Drop for ThreadInvocation<T> {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        self.shared
            .fence_abandoned_invocation(self.fence.invocation, &self.control);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvocationPhase {
    Running,
    CancellationRequested,
    Uncertain,
    Wedged,
    ResultPending,
}

impl InvocationPhase {
    const fn observation(self) -> ThreadInvocationObservation {
        match self {
            Self::Running => ThreadInvocationObservation::Running,
            Self::CancellationRequested => ThreadInvocationObservation::CancellationRequested,
            Self::Uncertain => ThreadInvocationObservation::Uncertain,
            Self::Wedged => ThreadInvocationObservation::Wedged,
            Self::ResultPending => ThreadInvocationObservation::ResultPending,
        }
    }

    const fn cancellation_rank(self) -> Option<u8> {
        match self {
            Self::Running => Some(0),
            Self::CancellationRequested => Some(1),
            Self::Uncertain => Some(2),
            Self::Wedged => Some(3),
            Self::ResultPending => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvocationDisposition {
    Pending,
    Accepted,
    Fenced,
}

struct InvocationRecord<T> {
    worker: usize,
    phase: InvocationPhase,
    accepts_result: bool,
    control: Arc<InvocationControl>,
    outcome: Option<WorkerOutcome<T>>,
    disposition: InvocationDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerPhase {
    Starting,
    Idle,
    Running(InvocationId),
    ResultPending(InvocationId),
    Wedged(InvocationId),
    Stopping,
    Exited,
}

/// RuntimeHost-visible lifecycle of this concrete executor generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadDomainLifecycle {
    Accepting,
    Degraded,
    Closing,
    Closed,
    Poisoned,
}

struct DomainState<T> {
    lifecycle: ThreadDomainLifecycle,
    workers: Vec<WorkerPhase>,
    active: BTreeMap<InvocationId, InvocationRecord<T>>,
    joined_workers: usize,
    panicked_workers: usize,
    cleanup_panics: usize,
}

struct SharedState<T> {
    state: Mutex<DomainState<T>>,
    changed: Condvar,
}

impl<T> SharedState<T> {
    fn lock(&self) -> MutexGuard<'_, DomainState<T>> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.lifecycle = ThreadDomainLifecycle::Poisoned;
                state
            }
        }
    }

    fn wait<'a>(&self, state: MutexGuard<'a, DomainState<T>>) -> MutexGuard<'a, DomainState<T>> {
        match self.changed.wait(state) {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.lifecycle = ThreadDomainLifecycle::Poisoned;
                state
            }
        }
    }

    fn fence_abandoned_invocation(&self, invocation: InvocationId, control: &InvocationControl) {
        let mut state = self.lock();
        let Some(record) = state.active.get_mut(&invocation) else {
            return;
        };
        record.accepts_result = false;
        control.fence(FenceReasonCode::HandleDropped);
        record.control.fence(FenceReasonCode::HandleDropped);
        match record.phase {
            InvocationPhase::Wedged => {}
            InvocationPhase::Running => {
                record.phase = InvocationPhase::CancellationRequested;
            }
            InvocationPhase::CancellationRequested
            | InvocationPhase::Uncertain
            | InvocationPhase::ResultPending => {}
        }
        record.disposition = InvocationDisposition::Fenced;
        self.changed.notify_all();
    }
}

type ThreadCallable<T> = Box<dyn FnOnce(ThreadCancellation) -> T + Send + 'static>;

struct ThreadWork<T> {
    fence: ThreadInvocationFence,
    control: Arc<InvocationControl>,
    callable: ThreadCallable<T>,
}

enum WorkerCommand<T> {
    Run(ThreadWork<T>),
    Shutdown,
}

struct WorkerSlot<T> {
    sender: SyncSender<WorkerCommand<T>>,
    join: Option<JoinHandle<()>>,
}

/// Fixed-width counts derived from the actual worker and invocation census.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadDomainSnapshot {
    domain_epoch: DomainEpoch,
    lifecycle: ThreadDomainLifecycle,
    planned_workers: usize,
    live_workers: usize,
    idle_workers: usize,
    occupied_workers: usize,
    stopping_workers: usize,
    exited_workers: usize,
    active_invocations: usize,
    wedged_workers: usize,
    joined_workers: usize,
    panicked_workers: usize,
    cleanup_panics: usize,
}

impl ThreadDomainSnapshot {
    #[must_use]
    pub(crate) const fn domain_epoch(self) -> DomainEpoch {
        self.domain_epoch
    }

    #[must_use]
    pub(crate) const fn lifecycle(self) -> ThreadDomainLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub(crate) const fn planned_workers(self) -> usize {
        self.planned_workers
    }

    #[must_use]
    pub(crate) const fn live_workers(self) -> usize {
        self.live_workers
    }

    #[must_use]
    pub(crate) const fn idle_workers(self) -> usize {
        self.idle_workers
    }

    #[must_use]
    pub(crate) const fn occupied_workers(self) -> usize {
        self.occupied_workers
    }

    #[must_use]
    pub(crate) const fn stopping_workers(self) -> usize {
        self.stopping_workers
    }

    #[must_use]
    pub(crate) const fn exited_workers(self) -> usize {
        self.exited_workers
    }

    #[must_use]
    pub(crate) const fn active_invocations(self) -> usize {
        self.active_invocations
    }

    #[must_use]
    pub(crate) const fn wedged_workers(self) -> usize {
        self.wedged_workers
    }

    #[must_use]
    pub(crate) const fn joined_workers(self) -> usize {
        self.joined_workers
    }

    #[must_use]
    pub(crate) const fn panicked_workers(self) -> usize {
        self.panicked_workers
    }

    /// Number of fenced user values whose destructor panicked while the
    /// responsible worker was still charged. The panic is contained, but it
    /// remains explicit evidence for the owner rather than being rewritten to
    /// a clean shutdown.
    #[must_use]
    pub(crate) const fn cleanup_panics(self) -> usize {
        self.cleanup_panics
    }

    #[must_use]
    pub(crate) const fn conserves_worker_capacity(self) -> bool {
        self.idle_workers + self.occupied_workers + self.stopping_workers + self.exited_workers
            == self.planned_workers
            && self.live_workers + self.exited_workers == self.planned_workers
            && self.active_invocations == self.occupied_workers
    }
}

/// Bounded result from a real-time shutdown wait. `complete=false` means the
/// owner still holds non-joined threads; it is never rewritten to success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadDomainShutdownReport {
    complete: bool,
    wait_expired: bool,
    snapshot: ThreadDomainSnapshot,
}

impl ThreadDomainShutdownReport {
    #[must_use]
    pub(crate) const fn complete(self) -> bool {
        self.complete
    }

    #[must_use]
    pub(crate) const fn wait_expired(self) -> bool {
        self.wait_expired
    }

    #[must_use]
    pub(crate) const fn snapshot(self) -> ThreadDomainSnapshot {
        self.snapshot
    }
}

/// Why a fully joined worker census is being returned to the global budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadDomainJoinKind {
    ConstructionRollback,
    CompleteShutdown,
}

/// Linear proof that every OS worker actually started by this owner was joined.
///
/// Only this module constructs the proof because it owns the `JoinHandle`s.
/// The global ExecutorBudget consumes it before returning plan capacity.
#[must_use = "a joined ThreadDomain proof must settle its ExecutorBudget reservation"]
pub(crate) struct ThreadDomainJoinProof {
    kind: ThreadDomainJoinKind,
    reservation: Option<ExecutorReservation>,
    started_workers: usize,
    joined_workers: usize,
    native_threads_released: bool,
}

impl ThreadDomainJoinProof {
    fn new(
        kind: ThreadDomainJoinKind,
        reservation: ExecutorReservation,
        started_workers: usize,
        joined_workers: usize,
        native_threads_released: bool,
    ) -> Self {
        Self {
            kind,
            reservation: Some(reservation),
            started_workers,
            joined_workers,
            native_threads_released,
        }
    }

    pub(crate) const fn kind(&self) -> ThreadDomainJoinKind {
        self.kind
    }

    pub(crate) const fn reservation(&self) -> Option<&ExecutorReservation> {
        self.reservation.as_ref()
    }

    pub(crate) const fn started_workers(&self) -> usize {
        self.started_workers
    }

    pub(crate) const fn joined_workers(&self) -> usize {
        self.joined_workers
    }

    pub(crate) const fn native_threads_released(&self) -> bool {
        self.native_threads_released
    }

    pub(crate) fn mark_released(&mut self) {
        self.reservation = None;
    }
}

/// Construction failure paired with proof that every partially-created worker
/// was joined before the global reservation can be rolled back.
pub(crate) struct ThreadDomainBuildFailure {
    error: ThreadDomainBuildError,
    join_proof: ThreadDomainJoinProof,
}

impl ThreadDomainBuildFailure {
    #[must_use]
    pub(crate) const fn error(&self) -> &ThreadDomainBuildError {
        &self.error
    }

    pub(crate) fn into_join_proof(self) -> ThreadDomainJoinProof {
        self.join_proof
    }

    pub(crate) fn into_parts(self) -> (ThreadDomainBuildError, ThreadDomainJoinProof) {
        (self.error, self.join_proof)
    }
}

/// One RuntimeHost-owned fixed synchronous executor class.
pub(crate) struct ThreadDomain<T: Send + 'static> {
    config: ThreadDomainConfig,
    owner: ThreadDomainOwnerIdentity,
    next_invocation: u64,
    shared: Arc<SharedState<T>>,
    workers: Vec<WorkerSlot<T>>,
    reservation: Option<ExecutorReservation>,
}

impl<T: Send + 'static> ThreadDomain<T> {
    pub(crate) fn try_new(
        domain_epoch: DomainEpoch,
        config: ThreadDomainConfig,
        reservation: ExecutorReservation,
    ) -> Result<Self, ThreadDomainBuildFailure> {
        let configured_workers = match u32::try_from(config.workers()) {
            Ok(workers) => workers,
            Err(_) => {
                return Err(construction_failure(
                    ThreadDomainBuildError::ReservationWorkerMismatch,
                    reservation,
                    0,
                    0,
                ));
            }
        };
        if reservation.managed_workers() != configured_workers {
            return Err(construction_failure(
                ThreadDomainBuildError::ReservationWorkerMismatch,
                reservation,
                0,
                0,
            ));
        }
        if reservation.native_threads() != 0 {
            return Err(construction_failure(
                ThreadDomainBuildError::UnsupportedNativeReservation,
                reservation,
                0,
                0,
            ));
        }
        let shared = Arc::new(SharedState {
            state: Mutex::new(DomainState {
                lifecycle: ThreadDomainLifecycle::Accepting,
                workers: vec![WorkerPhase::Starting; config.workers()],
                active: BTreeMap::new(),
                joined_workers: 0,
                panicked_workers: 0,
                cleanup_panics: 0,
            }),
            changed: Condvar::new(),
        });
        let owner = ThreadDomainOwnerIdentity::new(domain_epoch);
        let mut workers = Vec::with_capacity(config.workers());
        let Some(start_deadline) = Instant::now().checked_add(config.start_budget()) else {
            return Err(construction_failure(
                ThreadDomainBuildError::StartDeadlineOverflow,
                reservation,
                0,
                0,
            ));
        };

        for worker in 0..config.workers() {
            let (sender, receiver) = sync_channel(1);
            let (started_sender, started_receiver) = sync_channel(0);
            let worker_shared = Arc::clone(&shared);
            let name = format!("paraegox-thread-{}-{worker}", domain_epoch.value());
            let spawned = thread::Builder::new().name(name).spawn(move || {
                let _ = started_sender.send(());
                worker_main(worker, receiver, worker_shared);
            });
            let join = match spawned {
                Ok(join) => join,
                Err(error) => {
                    let joined = stop_partially_built_workers(&shared, &mut workers);
                    return Err(construction_failure(
                        ThreadDomainBuildError::Spawn(error),
                        reservation,
                        workers.len(),
                        joined,
                    ));
                }
            };
            workers.push(WorkerSlot {
                sender,
                join: Some(join),
            });
            let remaining = match remaining_start_budget(start_deadline, Instant::now()) {
                Ok(remaining) => remaining,
                Err(error) => {
                    drop(started_receiver);
                    let started = workers.len();
                    let joined = stop_partially_built_workers(&shared, &mut workers);
                    return Err(construction_failure(error, reservation, started, joined));
                }
            };
            match started_receiver.recv_timeout(remaining) {
                Ok(()) => {
                    let mut state = shared.lock();
                    state.workers[worker] = WorkerPhase::Idle;
                }
                Err(error) => {
                    drop(started_receiver);
                    let started = workers.len();
                    let joined = stop_partially_built_workers(&shared, &mut workers);
                    let error = match error {
                        RecvTimeoutError::Timeout => ThreadDomainBuildError::StartTimedOut,
                        RecvTimeoutError::Disconnected => {
                            ThreadDomainBuildError::StartHandshakeDisconnected
                        }
                    };
                    return Err(construction_failure(error, reservation, started, joined));
                }
            }
        }

        Ok(Self {
            config,
            owner,
            next_invocation: 0,
            shared,
            workers,
            reservation: Some(reservation),
        })
    }

    /// Reserves an exact idle worker before invoking `build`. Rejection never
    /// constructs a callable and therefore creates no executor-side backlog.
    pub(crate) fn try_submit<Build, Callable>(
        &mut self,
        build: Build,
    ) -> Result<ThreadInvocation<T>, ThreadDomainError>
    where
        Build: FnOnce() -> Callable,
        Callable: FnOnce(ThreadCancellation) -> T + Send + 'static,
    {
        let (worker, fence, control) = self.reserve_invocation()?;
        let callable = match catch_unwind(AssertUnwindSafe(build)) {
            Ok(callable) => callable,
            Err(_) => {
                self.rollback_reservation(worker, fence.invocation, false);
                return Err(ThreadDomainError::CallableBuildPanicked);
            }
        };
        let work = ThreadWork {
            fence: fence.clone(),
            control: Arc::clone(&control),
            callable: Box::new(callable),
        };
        match self.workers[worker]
            .sender
            .try_send(WorkerCommand::Run(work))
        {
            Ok(()) => Ok(ThreadInvocation {
                fence,
                control,
                shared: Arc::clone(&self.shared),
                consumed: false,
                result_pending_observed: false,
            }),
            Err(TrySendError::Full(_)) => {
                self.rollback_reservation(worker, fence.invocation, true);
                Err(ThreadDomainError::WorkerDispatchFailed)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.rollback_reservation(worker, fence.invocation, true);
                Err(ThreadDomainError::WorkerUnavailable)
            }
        }
    }

    pub(crate) fn request_cancellation(
        &mut self,
        invocation: &ThreadInvocation<T>,
    ) -> Result<(), ThreadDomainError> {
        self.mark_invocation(
            invocation,
            InvocationPhase::CancellationRequested,
            FenceReasonCode::CancellationRequested,
        )
    }

    pub(crate) fn mark_uncertain(
        &mut self,
        invocation: &ThreadInvocation<T>,
    ) -> Result<(), ThreadDomainError> {
        self.mark_invocation(
            invocation,
            InvocationPhase::Uncertain,
            FenceReasonCode::Uncertain,
        )
    }

    pub(crate) fn mark_wedged(
        &mut self,
        invocation: &ThreadInvocation<T>,
    ) -> Result<(), ThreadDomainError> {
        self.mark_invocation(invocation, InvocationPhase::Wedged, FenceReasonCode::Wedged)
    }

    /// Polls the explicit result slot and applies the exact owner, epoch, and
    /// invocation fence before exposing a returned value.
    pub(crate) fn try_take_completion(
        &mut self,
        invocation: &mut ThreadInvocation<T>,
    ) -> Result<ThreadCompletion<T>, ThreadDomainError> {
        self.validate_fence(&invocation.fence)?;
        if invocation.consumed {
            return Err(ThreadDomainError::CompletionAlreadyConsumed);
        }

        let invocation_id = invocation.fence.invocation;
        let mut state = self.shared.lock();
        let Some(record) = state.active.get_mut(&invocation_id) else {
            if let Some(reason) = invocation.control.reason().observable() {
                invocation.consumed = true;
                return Ok(ThreadCompletion::LateRejected(reason));
            }
            return Err(ThreadDomainError::WorkerUnavailable);
        };

        // A fence never transfers the payload back to the owner merely to
        // destroy it. The same charged worker will take it from this shared
        // slot, contain its destructor, and only then publish reusable/terminal
        // capacity by removing the active record.
        if record.disposition == InvocationDisposition::Fenced
            || !record.accepts_result
            || invocation.control.reason().observable().is_some()
        {
            record.accepts_result = false;
            record.disposition = InvocationDisposition::Fenced;
            let observation = record.phase.observation();
            self.shared.changed.notify_all();
            return Ok(ThreadCompletion::Pending(observation));
        }

        if record.outcome.is_none() {
            return Ok(ThreadCompletion::Pending(record.phase.observation()));
        }

        // Preserve the explicit ResultPending observation as a separate state
        // transition. A later poll performs the linear ownership transfer.
        if !invocation.result_pending_observed {
            invocation.result_pending_observed = true;
            return Ok(ThreadCompletion::Pending(
                ThreadInvocationObservation::ResultPending,
            ));
        }

        let outcome = record
            .outcome
            .take()
            .unwrap_or_else(|| panic!("result-pending outcome must exist exactly once"));
        let worker = record.worker;
        record.accepts_result = false;
        record.disposition = InvocationDisposition::Accepted;
        // The callable has returned and ownership of T moves atomically to the
        // caller here, so no worker-side user cleanup remains. Publish this
        // direct command cell as reusable now. The old worker observes the
        // removed record as an accepted handoff and must never overwrite a
        // successor reservation that may already occupy the same cell.
        state.active.remove(&invocation_id);
        state.workers[worker] = WorkerPhase::Idle;
        invocation.consumed = true;
        self.shared.changed.notify_all();
        drop(state);
        match outcome {
            WorkerOutcome::Returned(value) => Ok(ThreadCompletion::Returned(value)),
            WorkerOutcome::Panicked => Ok(ThreadCompletion::Panicked),
        }
    }

    #[must_use]
    pub(crate) fn snapshot(&self) -> ThreadDomainSnapshot {
        snapshot_from_state(self.owner.domain_epoch, self.config, &self.shared.lock())
    }

    /// Stops admission, fences every result, requests cooperative cancellation,
    /// and waits only up to `budget`. Unfinished `JoinHandle`s remain owned by
    /// this object and are reported rather than detached or called terminated.
    pub(crate) fn shutdown_for(&mut self, budget: Duration) -> ThreadDomainShutdownReport {
        self.begin_shutdown();
        let start = Instant::now();
        let deadline = start.checked_add(budget);
        let mut wait_expired = false;
        {
            let mut state = self.shared.lock();
            while state
                .workers
                .iter()
                .any(|phase| *phase != WorkerPhase::Exited)
            {
                let Some(deadline) = deadline else {
                    wait_expired = true;
                    break;
                };
                let now = Instant::now();
                let Some(remaining) = deadline.checked_duration_since(now) else {
                    wait_expired = true;
                    break;
                };
                let waited = self.shared.changed.wait_timeout(state, remaining);
                let (next_state, timeout) = match waited {
                    Ok(waited) => waited,
                    Err(poisoned) => poisoned.into_inner(),
                };
                state = next_state;
                if timeout.timed_out()
                    && state
                        .workers
                        .iter()
                        .any(|phase| *phase != WorkerPhase::Exited)
                {
                    wait_expired = true;
                    break;
                }
            }
        }
        let all_exited = self
            .shared
            .lock()
            .workers
            .iter()
            .all(|phase| *phase == WorkerPhase::Exited);
        if all_exited {
            // The worker terminal fact is published immediately before the
            // thread returns. Joining here closes that tiny publication/return
            // race and turns a real terminal census into a structural proof.
            self.join_all_workers_blocking();
        } else {
            self.reap_finished_workers();
        }
        let complete = self.workers.iter().all(|worker| worker.join.is_none());
        if complete {
            self.shared.lock().lifecycle = ThreadDomainLifecycle::Closed;
        }
        ThreadDomainShutdownReport {
            complete,
            wait_expired: wait_expired || !complete,
            snapshot: self.snapshot(),
        }
    }

    /// Transfers the global budget lease only after every fixed worker has a
    /// real joined terminal and the domain owns no active invocation.
    pub(crate) fn take_join_proof(&mut self) -> Result<ThreadDomainJoinProof, ThreadDomainError> {
        let snapshot = self.snapshot();
        if snapshot.lifecycle() != ThreadDomainLifecycle::Closed
            || snapshot.live_workers() != 0
            || snapshot.active_invocations() != 0
            || snapshot.joined_workers() != snapshot.planned_workers()
            || snapshot.panicked_workers() != 0
            || snapshot.cleanup_panics() != 0
            || self.workers.iter().any(|worker| worker.join.is_some())
        {
            return Err(ThreadDomainError::JoinProofUnavailable);
        }
        let reservation = self
            .reservation
            .take()
            .ok_or(ThreadDomainError::JoinProofAlreadyTaken)?;
        Ok(ThreadDomainJoinProof::new(
            ThreadDomainJoinKind::CompleteShutdown,
            reservation,
            snapshot.planned_workers(),
            snapshot.joined_workers(),
            true,
        ))
    }

    fn reserve_invocation(
        &mut self,
    ) -> Result<(usize, ThreadInvocationFence, Arc<InvocationControl>), ThreadDomainError> {
        let mut state = self.shared.lock();
        match state.lifecycle {
            ThreadDomainLifecycle::Accepting => {}
            ThreadDomainLifecycle::Degraded => return Err(ThreadDomainError::DomainDegraded),
            ThreadDomainLifecycle::Closing | ThreadDomainLifecycle::Closed => {
                return Err(ThreadDomainError::DomainClosing);
            }
            ThreadDomainLifecycle::Poisoned => return Err(ThreadDomainError::DomainPoisoned),
        }
        let Some(worker) = state
            .workers
            .iter()
            .position(|phase| *phase == WorkerPhase::Idle)
        else {
            return Err(ThreadDomainError::CapacityExhausted);
        };
        let Some(next_invocation) = self.next_invocation.checked_add(1) else {
            return Err(ThreadDomainError::InvocationIdentifierExhausted);
        };
        let invocation = InvocationId::try_new(next_invocation)
            .map_err(|_| ThreadDomainError::InvocationIdentifierExhausted)?;
        let control = Arc::new(InvocationControl::new());
        let replaced = state.active.insert(
            invocation,
            InvocationRecord {
                worker,
                phase: InvocationPhase::Running,
                accepts_result: true,
                control: Arc::clone(&control),
                outcome: None,
                disposition: InvocationDisposition::Pending,
            },
        );
        if replaced.is_some() {
            state.lifecycle = ThreadDomainLifecycle::Poisoned;
            return Err(ThreadDomainError::DomainPoisoned);
        }
        state.workers[worker] = WorkerPhase::Running(invocation);
        self.next_invocation = next_invocation;
        Ok((
            worker,
            ThreadInvocationFence {
                owner: self.owner.clone(),
                domain_epoch: self.owner.domain_epoch,
                invocation,
            },
            control,
        ))
    }

    fn rollback_reservation(&mut self, worker: usize, invocation: InvocationId, poison: bool) {
        let mut state = self.shared.lock();
        state.active.remove(&invocation);
        state.workers[worker] = WorkerPhase::Idle;
        if poison {
            state.lifecycle = ThreadDomainLifecycle::Poisoned;
        }
        self.shared.changed.notify_all();
    }

    fn validate_fence(&self, fence: &ThreadInvocationFence) -> Result<(), ThreadDomainError> {
        if fence.domain_epoch != self.owner.domain_epoch || fence.owner != self.owner {
            return Err(ThreadDomainError::StaleCompletionFence);
        }
        Ok(())
    }

    fn mark_invocation(
        &mut self,
        invocation: &ThreadInvocation<T>,
        phase: InvocationPhase,
        reason: FenceReasonCode,
    ) -> Result<(), ThreadDomainError> {
        self.validate_fence(&invocation.fence)?;
        if invocation.consumed {
            return Err(ThreadDomainError::CompletionAlreadyConsumed);
        }
        let mut state = self.shared.lock();
        let Some(record) = state.active.get_mut(&invocation.fence.invocation) else {
            return Err(ThreadDomainError::InvocationNotActive);
        };
        if let (Some(current), Some(requested)) =
            (record.phase.cancellation_rank(), phase.cancellation_rank())
            && requested < current
        {
            return Ok(());
        }
        record.control.fence(reason);
        record.accepts_result = false;
        record.disposition = InvocationDisposition::Fenced;
        let worker = record.worker;
        let effective_reason = record.control.reason();
        if record.phase != InvocationPhase::Wedged {
            record.phase = match effective_reason {
                FenceReasonCode::CancellationRequested => InvocationPhase::CancellationRequested,
                FenceReasonCode::Uncertain => InvocationPhase::Uncertain,
                FenceReasonCode::Wedged => InvocationPhase::Wedged,
                FenceReasonCode::Shutdown | FenceReasonCode::HandleDropped => {
                    InvocationPhase::CancellationRequested
                }
                FenceReasonCode::Open => phase,
            };
        }
        if effective_reason == FenceReasonCode::Wedged {
            state.workers[worker] = WorkerPhase::Wedged(invocation.fence.invocation);
            if state.lifecycle == ThreadDomainLifecycle::Accepting {
                state.lifecycle = ThreadDomainLifecycle::Degraded;
            }
        }
        self.shared.changed.notify_all();
        Ok(())
    }

    fn begin_shutdown(&mut self) {
        let mut wake_workers = Vec::with_capacity(self.workers.len());
        {
            let mut state = self.shared.lock();
            if matches!(
                state.lifecycle,
                ThreadDomainLifecycle::Closing | ThreadDomainLifecycle::Closed
            ) {
                return;
            }
            state.lifecycle = ThreadDomainLifecycle::Closing;
            for record in state.active.values_mut() {
                if record.disposition == InvocationDisposition::Accepted {
                    continue;
                }
                record.accepts_result = false;
                if record.phase == InvocationPhase::Wedged {
                    record.control.fence(FenceReasonCode::Wedged);
                } else {
                    record.control.fence(FenceReasonCode::Shutdown);
                }
                record.disposition = InvocationDisposition::Fenced;
                if record.phase == InvocationPhase::Running
                    || record.phase == InvocationPhase::ResultPending
                {
                    record.phase = InvocationPhase::CancellationRequested;
                }
            }
            for (worker, phase) in state.workers.iter_mut().enumerate() {
                if *phase == WorkerPhase::Idle {
                    *phase = WorkerPhase::Stopping;
                    wake_workers.push(worker);
                }
            }
            self.shared.changed.notify_all();
        }
        for worker in wake_workers {
            if self.workers[worker]
                .sender
                .try_send(WorkerCommand::Shutdown)
                .is_err()
            {
                self.mark_shutdown_dispatch_failure(worker);
            }
        }
    }

    fn mark_shutdown_dispatch_failure(&mut self, worker: usize) {
        let mut state = self.shared.lock();
        if self.workers[worker]
            .join
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            state.workers[worker] = WorkerPhase::Exited;
        }
        self.shared.changed.notify_all();
    }

    fn reap_finished_workers(&mut self) {
        let mut joined = 0;
        let mut panicked = 0;
        for worker in &mut self.workers {
            let is_finished = worker.join.as_ref().is_some_and(JoinHandle::is_finished);
            if !is_finished {
                continue;
            }
            let Some(join) = worker.join.take() else {
                continue;
            };
            joined += 1;
            if join.join().is_err() {
                panicked += 1;
            }
        }
        if joined != 0 || panicked != 0 {
            let mut state = self.shared.lock();
            state.joined_workers += joined;
            state.panicked_workers += panicked;
        }
    }

    fn join_all_workers_blocking(&mut self) {
        let mut joined = 0;
        let mut panicked = 0;
        for worker in &mut self.workers {
            let Some(join) = worker.join.take() else {
                continue;
            };
            joined += 1;
            if join.join().is_err() {
                panicked += 1;
            }
        }
        if joined != 0 || panicked != 0 {
            let mut state = self.shared.lock();
            state.joined_workers += joined;
            state.panicked_workers += panicked;
            for phase in &mut state.workers {
                *phase = WorkerPhase::Exited;
            }
            if state.active.is_empty() {
                state.lifecycle = ThreadDomainLifecycle::Closed;
            } else {
                state.lifecycle = ThreadDomainLifecycle::Poisoned;
            }
            self.shared.changed.notify_all();
        }
    }
}

fn remaining_start_budget(
    deadline: Instant,
    now: Instant,
) -> Result<Duration, ThreadDomainBuildError> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ThreadDomainBuildError::StartTimedOut)
}

impl<T: Send + 'static> Drop for ThreadDomain<T> {
    fn drop(&mut self) {
        self.begin_shutdown();
        // Rust cannot terminate a running thread. Blocking here is deliberate:
        // detaching a live JoinHandle would lose the sole RuntimeHost owner and
        // falsely return global capacity. A truly wedged callable therefore
        // requires the later ProcessDomain/out-of-process recovery boundary.
        self.join_all_workers_blocking();
    }
}

fn worker_main<T: Send + 'static>(
    worker: usize,
    receiver: Receiver<WorkerCommand<T>>,
    shared: Arc<SharedState<T>>,
) {
    loop {
        match receiver.recv() {
            Ok(WorkerCommand::Run(work)) => {
                let should_exit = run_work(worker, work, &shared);
                if should_exit {
                    return;
                }
            }
            Ok(WorkerCommand::Shutdown) => {
                mark_worker_exited(worker, &shared, false);
                return;
            }
            Err(_) => {
                mark_worker_exited(worker, &shared, true);
                return;
            }
        }
    }
}

fn run_work<T: Send + 'static>(
    worker: usize,
    work: ThreadWork<T>,
    shared: &SharedState<T>,
) -> bool {
    let ThreadWork {
        fence,
        control,
        callable,
    } = work;
    let cancellation = ThreadCancellation {
        control: Arc::clone(&control),
    };
    let mut outcome = Some(
        match catch_unwind(AssertUnwindSafe(|| callable(cancellation))) {
            Ok(value) => WorkerOutcome::Returned(value),
            Err(_) => WorkerOutcome::Panicked,
        },
    );
    let callable_panicked = matches!(outcome, Some(WorkerOutcome::Panicked));
    let mut cleanup = None;
    let mut accepted_handoff = false;
    let mut state = shared.lock();
    let closing = state.lifecycle == ThreadDomainLifecycle::Closing;
    if callable_panicked && !closing {
        state.lifecycle = ThreadDomainLifecycle::Poisoned;
    }
    let accepts_result = state.active.get(&fence.invocation).is_some_and(|record| {
        record.worker == worker
            && record.accepts_result
            && record.disposition == InvocationDisposition::Pending
            && record.control.reason() == FenceReasonCode::Open
    });

    if accepts_result && !closing {
        let record = state
            .active
            .get_mut(&fence.invocation)
            .unwrap_or_else(|| panic!("reserved invocation must remain active"));
        record.outcome = outcome.take();
        record.phase = InvocationPhase::ResultPending;
        state.workers[worker] = WorkerPhase::ResultPending(fence.invocation);
        shared.changed.notify_all();

        // The OS worker remains charged while the result is pending. The
        // owner either accepts the exact slot or closes its fence; only this
        // worker may then destroy a rejected payload and publish capacity.
        loop {
            let disposition = state
                .active
                .get(&fence.invocation)
                .map(|record| record.disposition);
            match disposition {
                Some(InvocationDisposition::Pending) => {
                    state = shared.wait(state);
                }
                Some(InvocationDisposition::Accepted) => {
                    let record = state
                        .active
                        .get_mut(&fence.invocation)
                        .unwrap_or_else(|| panic!("accepted invocation must remain active"));
                    // Normally the owner already took the value. Preserve
                    // fail-closed cleanup if an internal invariant ever leaves
                    // a payload behind.
                    cleanup = record.outcome.take();
                    break;
                }
                Some(InvocationDisposition::Fenced) => {
                    let record = state
                        .active
                        .get_mut(&fence.invocation)
                        .unwrap_or_else(|| panic!("fenced invocation must remain active"));
                    cleanup = record.outcome.take();
                    break;
                }
                None => {
                    // `try_take_completion` atomically transferred T, removed
                    // this record, and published the direct command cell as
                    // Idle. A successor Run or Shutdown may already be queued;
                    // the old invocation must not overwrite either state.
                    accepted_handoff = true;
                    break;
                }
            }
        }
    } else {
        if let Some(record) = state.active.get_mut(&fence.invocation) {
            record.accepts_result = false;
            record.disposition = InvocationDisposition::Fenced;
        }
        cleanup = outcome.take();
    }
    drop(state);

    if accepted_handoff {
        debug_assert!(cleanup.is_none());
        return false;
    }

    // Destruction of a rejected user value is part of the same worker's
    // charged cleanup. Keep the active record until the destructor really
    // returns; a blocking or panicking destructor can therefore never create
    // false reusable capacity or a false terminal drain.
    let outcome_drop_panicked = catch_unwind(AssertUnwindSafe(|| drop(cleanup))).is_err();
    let mut state = shared.lock();
    let closing = state.lifecycle == ThreadDomainLifecycle::Closing;
    if outcome_drop_panicked {
        state.cleanup_panics = state.cleanup_panics.saturating_add(1);
        if !closing {
            state.lifecycle = ThreadDomainLifecycle::Poisoned;
        }
    }
    let matches_worker = state
        .active
        .get(&fence.invocation)
        .is_some_and(|record| record.worker == worker);
    let phase_matches = matches!(
        state.workers[worker],
        WorkerPhase::Running(invocation)
            | WorkerPhase::ResultPending(invocation)
            | WorkerPhase::Wedged(invocation)
            if invocation == fence.invocation
    );
    let settled = matches_worker && phase_matches;
    if settled {
        let removed = state.active.remove(&fence.invocation);
        debug_assert!(
            removed
                .as_ref()
                .is_some_and(|record| record.outcome.is_none())
        );
        state.workers[worker] = if closing {
            WorkerPhase::Exited
        } else {
            WorkerPhase::Idle
        };
    } else {
        state.lifecycle = ThreadDomainLifecycle::Poisoned;
    }
    refresh_closed_lifecycle(&mut state);
    shared.changed.notify_all();
    closing && settled
}

fn mark_worker_exited<T>(worker: usize, shared: &SharedState<T>, unexpected: bool) {
    let mut state = shared.lock();
    state.workers[worker] = WorkerPhase::Exited;
    if unexpected
        && !matches!(
            state.lifecycle,
            ThreadDomainLifecycle::Closing | ThreadDomainLifecycle::Closed
        )
    {
        state.lifecycle = ThreadDomainLifecycle::Poisoned;
    }
    refresh_closed_lifecycle(&mut state);
    shared.changed.notify_all();
}

fn refresh_closed_lifecycle<T>(state: &mut DomainState<T>) {
    if state.lifecycle == ThreadDomainLifecycle::Closing
        && state
            .workers
            .iter()
            .all(|phase| *phase == WorkerPhase::Exited)
    {
        state.lifecycle = ThreadDomainLifecycle::Closed;
    }
}

fn snapshot_from_state<T>(
    domain_epoch: DomainEpoch,
    config: ThreadDomainConfig,
    state: &DomainState<T>,
) -> ThreadDomainSnapshot {
    let idle_workers = state
        .workers
        .iter()
        .filter(|phase| **phase == WorkerPhase::Idle)
        .count();
    let occupied_workers = state
        .workers
        .iter()
        .filter(|phase| {
            matches!(
                phase,
                WorkerPhase::Running(_) | WorkerPhase::ResultPending(_) | WorkerPhase::Wedged(_)
            )
        })
        .count();
    let stopping_workers = state
        .workers
        .iter()
        .filter(|phase| matches!(phase, WorkerPhase::Starting | WorkerPhase::Stopping))
        .count();
    let exited_workers = state
        .workers
        .iter()
        .filter(|phase| **phase == WorkerPhase::Exited)
        .count();
    ThreadDomainSnapshot {
        domain_epoch,
        lifecycle: state.lifecycle,
        planned_workers: config.workers(),
        live_workers: config.workers() - exited_workers,
        idle_workers,
        occupied_workers,
        stopping_workers,
        exited_workers,
        active_invocations: state.active.len(),
        wedged_workers: state
            .active
            .values()
            .filter(|record| record.phase == InvocationPhase::Wedged)
            .count(),
        joined_workers: state.joined_workers,
        panicked_workers: state.panicked_workers,
        cleanup_panics: state.cleanup_panics,
    }
}

fn stop_partially_built_workers<T: Send + 'static>(
    shared: &SharedState<T>,
    workers: &mut [WorkerSlot<T>],
) -> usize {
    {
        let mut state = shared.lock();
        state.lifecycle = ThreadDomainLifecycle::Closing;
        for phase in state.workers.iter_mut().skip(workers.len()) {
            *phase = WorkerPhase::Exited;
        }
    }
    for worker in workers.iter() {
        let _ = worker.sender.try_send(WorkerCommand::Shutdown);
    }
    let mut joined = 0;
    for worker in workers.iter_mut() {
        if let Some(join) = worker.join.take() {
            let _ = join.join();
            joined += 1;
        }
    }
    joined
}

fn construction_failure(
    error: ThreadDomainBuildError,
    reservation: ExecutorReservation,
    started_workers: usize,
    joined_workers: usize,
) -> ThreadDomainBuildFailure {
    ThreadDomainBuildFailure {
        error,
        join_proof: ThreadDomainJoinProof::new(
            ThreadDomainJoinKind::ConstructionRollback,
            reservation,
            started_workers,
            joined_workers,
            true,
        ),
    }
}

/// Construction failures before a ThreadDomain can own its complete census.
#[derive(Debug)]
pub(crate) enum ThreadDomainBuildError {
    InvalidWorkerCount,
    InvalidStartBudget,
    ReservationWorkerMismatch,
    UnsupportedNativeReservation,
    Spawn(io::Error),
    StartDeadlineOverflow,
    StartTimedOut,
    StartHandshakeDisconnected,
}

impl fmt::Display for ThreadDomainBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWorkerCount => formatter.write_str("invalid ThreadDomain worker count"),
            Self::InvalidStartBudget => {
                formatter.write_str("ThreadDomain start budget must be positive")
            }
            Self::ReservationWorkerMismatch => {
                formatter.write_str("ThreadDomain worker count differs from its global reservation")
            }
            Self::UnsupportedNativeReservation => formatter
                .write_str("ThreadDomain has no admitted owner for reserved native threads"),
            Self::Spawn(error) => write!(formatter, "failed to spawn ThreadDomain worker: {error}"),
            Self::StartDeadlineOverflow => {
                formatter.write_str("ThreadDomain start deadline cannot be represented")
            }
            Self::StartTimedOut => formatter.write_str("ThreadDomain worker start timed out"),
            Self::StartHandshakeDisconnected => {
                formatter.write_str("ThreadDomain worker start handshake disconnected")
            }
        }
    }
}

impl std::error::Error for ThreadDomainBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidWorkerCount
            | Self::InvalidStartBudget
            | Self::ReservationWorkerMismatch
            | Self::UnsupportedNativeReservation
            | Self::StartDeadlineOverflow
            | Self::StartTimedOut
            | Self::StartHandshakeDisconnected => None,
            Self::Spawn(error) => Some(error),
        }
    }
}

/// Fail-closed admission, ownership, and completion errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadDomainError {
    CapacityExhausted,
    DomainDegraded,
    DomainClosing,
    DomainPoisoned,
    InvocationIdentifierExhausted,
    CallableBuildPanicked,
    WorkerDispatchFailed,
    WorkerUnavailable,
    StaleCompletionFence,
    InvocationNotActive,
    CompletionAlreadyConsumed,
    JoinProofUnavailable,
    JoinProofAlreadyTaken,
}

impl fmt::Display for ThreadDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::CapacityExhausted => "ThreadDomain capacity exhausted before callable build",
            Self::DomainDegraded => "ThreadDomain is degraded by a wedged worker",
            Self::DomainClosing => "ThreadDomain is closing",
            Self::DomainPoisoned => "ThreadDomain internal state is poisoned",
            Self::InvocationIdentifierExhausted => "ThreadDomain invocation identity exhausted",
            Self::CallableBuildPanicked => "ThreadDomain callable construction panicked",
            Self::WorkerDispatchFailed => "reserved ThreadDomain worker rejected direct dispatch",
            Self::WorkerUnavailable => "ThreadDomain worker became unavailable",
            Self::StaleCompletionFence => "completion belongs to another ThreadDomain owner epoch",
            Self::InvocationNotActive => "ThreadDomain invocation is not active",
            Self::CompletionAlreadyConsumed => "ThreadDomain completion was already consumed",
            Self::JoinProofUnavailable => "ThreadDomain still owns live or unjoined work",
            Self::JoinProofAlreadyTaken => "ThreadDomain join proof was already transferred",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ThreadDomainError {}

#[cfg(test)]
mod tests {
    use core::ops::{Deref, DerefMut};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::time::Duration;
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;
    use std::time::Instant;

    use super::{
        LateResultReason, ThreadCompletion, ThreadDomain, ThreadDomainBuildError,
        ThreadDomainConfig, ThreadDomainError, ThreadDomainLifecycle, ThreadInvocation,
        ThreadInvocationObservation, remaining_start_budget,
    };
    use crate::card_instance::DomainEpoch;
    use crate::executor_budget::ExecutorBudget;

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
            let mut open = match self.open.lock() {
                Ok(open) => open,
                Err(poisoned) => poisoned.into_inner(),
            };
            while !*open {
                open = match self.changed.wait(open) {
                    Ok(open) => open,
                    Err(poisoned) => poisoned.into_inner(),
                };
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

    struct BlockingDrop {
        entered: std::sync::mpsc::SyncSender<()>,
        release: Arc<ControlledLatch>,
    }

    impl Drop for BlockingDrop {
        fn drop(&mut self) {
            let _ = self.entered.send(());
            self.release.wait();
        }
    }

    struct PanickingDrop;

    impl Drop for PanickingDrop {
        fn drop(&mut self) {
            panic!("fixture result destructor panic");
        }
    }

    fn epoch(value: u64) -> DomainEpoch {
        let Ok(epoch) = DomainEpoch::try_new(value) else {
            panic!("fixture epoch must be nonzero");
        };
        epoch
    }

    fn config(workers: usize) -> ThreadDomainConfig {
        let Ok(config) = ThreadDomainConfig::try_new(workers, Duration::from_secs(1)) else {
            panic!("fixture worker count must be valid");
        };
        config
    }

    struct TestDomain<T: Send + 'static> {
        budget: ExecutorBudget,
        domain: ThreadDomain<T>,
    }

    impl<T: Send + 'static> Deref for TestDomain<T> {
        type Target = ThreadDomain<T>;

        fn deref(&self) -> &Self::Target {
            &self.domain
        }
    }

    impl<T: Send + 'static> DerefMut for TestDomain<T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.domain
        }
    }

    impl<T: Send + 'static> TestDomain<T> {
        fn settle_budget(&mut self) {
            let mut proof = self
                .domain
                .take_join_proof()
                .unwrap_or_else(|error| panic!("complete domain needs join proof: {error}"));
            self.budget
                .release(&mut proof)
                .unwrap_or_else(|error| panic!("join proof must release budget: {error}"));
            assert_eq!(
                self.budget
                    .snapshot()
                    .unwrap_or_else(|error| panic!("budget snapshot failed: {error}"))
                    .active_reservations(),
                0
            );
        }
    }

    fn domain<T: Send + 'static>(workers: usize, epoch_value: u64) -> TestDomain<T> {
        let maximum = u32::try_from(workers + 1).expect("test worker budget must fit");
        let worker_count = u32::try_from(workers).expect("test worker count must fit");
        let mut budget = ExecutorBudget::try_new(maximum, 1)
            .unwrap_or_else(|error| panic!("fixture budget must be valid: {error}"));
        let reservation = budget
            .try_reserve(worker_count, 0)
            .unwrap_or_else(|error| panic!("fixture reservation must fit: {error}"));
        let domain = match ThreadDomain::try_new(epoch(epoch_value), config(workers), reservation) {
            Ok(domain) => domain,
            Err(failure) => {
                let error = failure.error().to_string();
                let mut proof = failure.into_join_proof();
                budget
                    .release(&mut proof)
                    .unwrap_or_else(|release| panic!("build rollback failed: {release}"));
                panic!("fixture domain must start: {error}");
            }
        };
        TestDomain { budget, domain }
    }

    fn wait_for_observation<T: Send + 'static>(
        domain: &mut ThreadDomain<T>,
        invocation: &mut ThreadInvocation<T>,
        expected: ThreadInvocationObservation,
    ) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let Ok(observation) = domain.try_take_completion(invocation) else {
                panic!("invocation observation must remain valid");
            };
            match observation {
                ThreadCompletion::Pending(actual) if actual == expected => {
                    return;
                }
                ThreadCompletion::Pending(_) => {}
                ThreadCompletion::Returned(_)
                | ThreadCompletion::Panicked
                | ThreadCompletion::LateRejected(_) => {
                    panic!("invocation reached an unexpected terminal state");
                }
            }
            assert!(Instant::now() < deadline, "worker observation timed out");
            thread::yield_now();
        }
    }

    fn wait_for_late<T: Send + 'static>(
        domain: &mut ThreadDomain<T>,
        invocation: &mut ThreadInvocation<T>,
        expected: LateResultReason,
    ) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let Ok(completion) = domain.try_take_completion(invocation) else {
                panic!("late completion must remain observable");
            };
            match completion {
                ThreadCompletion::LateRejected(reason) => {
                    assert_eq!(reason, expected);
                    return;
                }
                ThreadCompletion::Pending(_) => {}
                ThreadCompletion::Returned(_) | ThreadCompletion::Panicked => {
                    panic!("fenced invocation must not expose a success result");
                }
            }
            assert!(
                Instant::now() < deadline,
                "late result observation timed out"
            );
            thread::yield_now();
        }
    }

    fn wait_for_idle<T: Send + 'static>(domain: &ThreadDomain<T>) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let snapshot = domain.snapshot();
            assert!(snapshot.conserves_worker_capacity());
            if snapshot.active_invocations() == 0 && snapshot.occupied_workers() == 0 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "worker did not publish idle state"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn one_start_deadline_is_shared_by_every_worker_handshake() {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(20);
        assert_eq!(
            remaining_start_budget(deadline, start + Duration::from_millis(7))
                .expect("shared deadline must retain its remainder"),
            Duration::from_millis(13)
        );
        assert!(matches!(
            remaining_start_budget(deadline, deadline),
            Err(ThreadDomainBuildError::StartTimedOut)
        ));
        assert!(matches!(
            remaining_start_budget(deadline, deadline + Duration::from_nanos(1)),
            Err(ThreadDomainBuildError::StartTimedOut)
        ));
    }

    #[test]
    fn saturation_rejects_before_callable_construction_and_has_no_queue() {
        let mut domain = domain::<u8>(2, 1);
        let gate = Arc::new(ControlledLatch::new());
        let first_gate = Arc::clone(&gate);
        let Ok(mut first) = domain.try_submit(|| {
            move |_| {
                first_gate.wait();
                1
            }
        }) else {
            panic!("first worker must admit");
        };
        let second_gate = Arc::clone(&gate);
        let Ok(mut second) = domain.try_submit(|| {
            move |_| {
                second_gate.wait();
                2
            }
        }) else {
            panic!("second worker must admit");
        };
        let built = Arc::new(AtomicUsize::new(0));
        let rejected_built = Arc::clone(&built);
        assert!(matches!(
            domain.try_submit(move || {
                rejected_built.fetch_add(1, Ordering::SeqCst);
                |_| 3
            }),
            Err(ThreadDomainError::CapacityExhausted)
        ));
        assert_eq!(built.load(Ordering::SeqCst), 0);
        let snapshot = domain.snapshot();
        assert_eq!(snapshot.occupied_workers(), 2);
        assert_eq!(snapshot.active_invocations(), 2);
        assert!(snapshot.conserves_worker_capacity());

        gate.release();
        wait_for_observation(
            &mut domain,
            &mut first,
            ThreadInvocationObservation::ResultPending,
        );
        assert_eq!(
            domain.try_take_completion(&mut first),
            Ok(ThreadCompletion::Returned(1))
        );
        wait_for_observation(
            &mut domain,
            &mut second,
            ThreadInvocationObservation::ResultPending,
        );
        assert_eq!(
            domain.try_take_completion(&mut second),
            Ok(ThreadCompletion::Returned(2))
        );
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        domain.settle_budget();
    }

    #[test]
    fn controlled_never_return_is_wedged_without_replacement_or_false_shutdown() {
        let mut domain = domain::<u8>(1, 2);
        let gate = Arc::new(ControlledLatch::new());
        let worker_gate = Arc::clone(&gate);
        let Ok(mut invocation) = domain.try_submit(|| {
            move |cancellation| {
                worker_gate.wait();
                assert!(cancellation.is_cancellation_requested());
                7
            }
        }) else {
            panic!("worker must admit");
        };
        assert_eq!(domain.mark_wedged(&invocation), Ok(()));
        let snapshot = domain.snapshot();
        assert_eq!(snapshot.lifecycle(), ThreadDomainLifecycle::Degraded);
        assert_eq!(snapshot.live_workers(), 1);
        assert_eq!(snapshot.wedged_workers(), 1);
        assert_eq!(snapshot.occupied_workers(), 1);
        assert!(snapshot.conserves_worker_capacity());
        assert!(matches!(
            domain.try_submit(|| |_| 8),
            Err(ThreadDomainError::DomainDegraded)
        ));

        let incomplete = domain.shutdown_for(Duration::from_millis(10));
        assert!(!incomplete.complete());
        assert!(incomplete.wait_expired());
        assert_eq!(incomplete.snapshot().wedged_workers(), 1);
        assert_eq!(incomplete.snapshot().live_workers(), 1);

        gate.release();
        wait_for_late(&mut domain, &mut invocation, LateResultReason::Wedged);
        let complete = domain.shutdown_for(Duration::from_secs(1));
        assert!(complete.complete());
        assert_eq!(complete.snapshot().joined_workers(), 1);
        assert!(complete.snapshot().conserves_worker_capacity());
        domain.settle_budget();
    }

    #[test]
    fn cancellation_and_uncertain_fence_late_result_until_real_return() {
        let mut domain = domain::<u8>(1, 3);
        let gate = Arc::new(ControlledLatch::new());
        let worker_gate = Arc::clone(&gate);
        let Ok(mut invocation) = domain.try_submit(|| {
            move |cancellation| {
                worker_gate.wait();
                assert!(cancellation.is_cancellation_requested());
                11
            }
        }) else {
            panic!("worker must admit");
        };
        assert_eq!(domain.request_cancellation(&invocation), Ok(()));
        assert_eq!(domain.mark_uncertain(&invocation), Ok(()));
        assert_eq!(domain.snapshot().occupied_workers(), 1);
        assert!(matches!(
            domain.try_submit(|| |_| 12),
            Err(ThreadDomainError::CapacityExhausted)
        ));

        gate.release();
        wait_for_late(&mut domain, &mut invocation, LateResultReason::Uncertain);
        let snapshot = domain.snapshot();
        assert_eq!(snapshot.idle_workers(), 1);
        assert_eq!(snapshot.active_invocations(), 0);
        assert!(snapshot.conserves_worker_capacity());
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        domain.settle_budget();
    }

    #[test]
    fn cancellation_phase_and_late_reason_only_advance() {
        let mut domain = domain::<u8>(1, 31);
        let gate = Arc::new(ControlledLatch::new());
        let worker_gate = Arc::clone(&gate);
        let Ok(mut invocation) = domain.try_submit(|| {
            move |_| {
                worker_gate.wait();
                41
            }
        }) else {
            panic!("worker must admit");
        };

        assert_eq!(domain.request_cancellation(&invocation), Ok(()));
        assert_eq!(domain.mark_uncertain(&invocation), Ok(()));
        assert_eq!(domain.request_cancellation(&invocation), Ok(()));
        assert!(matches!(
            domain.try_take_completion(&mut invocation),
            Ok(ThreadCompletion::Pending(
                ThreadInvocationObservation::Uncertain
            ))
        ));

        assert_eq!(domain.mark_wedged(&invocation), Ok(()));
        assert_eq!(domain.mark_uncertain(&invocation), Ok(()));
        assert_eq!(domain.request_cancellation(&invocation), Ok(()));
        assert_eq!(
            domain.try_take_completion(&mut invocation),
            Ok(ThreadCompletion::Pending(
                ThreadInvocationObservation::Wedged
            ))
        );
        assert_eq!(domain.snapshot().wedged_workers(), 1);

        gate.release();
        wait_for_late(&mut domain, &mut invocation, LateResultReason::Wedged);
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        domain.settle_budget();
    }

    #[test]
    fn callable_panic_during_shutdown_exits_in_the_first_drain() {
        let mut domain = domain::<u8>(1, 32);
        let Ok(mut invocation) = domain.try_submit(|| {
            move |cancellation| -> u8 {
                while !cancellation.is_cancellation_requested() {
                    thread::yield_now();
                }
                panic!("fixture panic after shutdown fence");
            }
        }) else {
            panic!("worker must admit");
        };

        let report = domain.shutdown_for(Duration::from_secs(1));
        assert!(report.complete());
        assert!(!report.wait_expired());
        assert!(matches!(
            domain.try_take_completion(&mut invocation),
            Ok(ThreadCompletion::LateRejected(LateResultReason::Shutdown))
        ));
        domain.settle_budget();
    }

    #[test]
    fn blocking_result_drop_remains_charged_and_cannot_overrun_drain_join() {
        let mut domain = domain::<BlockingDrop>(1, 33);
        let release = Arc::new(ControlledLatch::new());
        let worker_release = Arc::clone(&release);
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let watchdog_release = Arc::clone(&release);
        let watchdog = thread::spawn(move || {
            entered_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("result destructor must start");
            let _ = release_receiver.recv_timeout(Duration::from_millis(200));
            watchdog_release.release();
        });
        let Ok(mut invocation) = domain.try_submit(|| {
            move |cancellation| {
                while !cancellation.is_cancellation_requested() {
                    thread::yield_now();
                }
                BlockingDrop {
                    entered: entered_sender,
                    release: worker_release,
                }
            }
        }) else {
            panic!("worker must admit");
        };

        let report = domain.shutdown_for(Duration::from_millis(10));
        assert!(!report.complete());
        assert!(report.wait_expired());
        assert_eq!(report.snapshot().live_workers(), 1);
        release_sender
            .send(())
            .expect("watchdog release channel must remain open");
        watchdog
            .join()
            .expect("result-drop watchdog must not panic");
        wait_for_late(&mut domain, &mut invocation, LateResultReason::Shutdown);
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        domain.settle_budget();
    }

    #[test]
    fn running_fence_keeps_worker_charged_until_rejected_value_is_destroyed() {
        let mut domain = domain::<BlockingDrop>(1, 331);
        let callable_gate = Arc::new(ControlledLatch::new());
        let worker_gate = Arc::clone(&callable_gate);
        let drop_release = Arc::new(ControlledLatch::new());
        let worker_drop_release = Arc::clone(&drop_release);
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(0);
        let (observed_sender, observed_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let watchdog_release = Arc::clone(&drop_release);
        let watchdog = thread::spawn(move || {
            entered_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("fenced result destructor must run on its worker");
            observed_sender
                .send(())
                .expect("test must observe entered destructor");
            let _ = release_receiver.recv_timeout(Duration::from_millis(500));
            watchdog_release.release();
        });
        let Ok(mut invocation) = domain.try_submit(|| {
            move |_| {
                worker_gate.wait();
                BlockingDrop {
                    entered: entered_sender,
                    release: worker_drop_release,
                }
            }
        }) else {
            panic!("worker must admit");
        };

        assert_eq!(domain.request_cancellation(&invocation), Ok(()));
        assert_eq!(domain.mark_uncertain(&invocation), Ok(()));
        callable_gate.release();
        observed_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("test must observe blocked destructor");
        let snapshot = domain.snapshot();
        assert_eq!(snapshot.active_invocations(), 1);
        assert_eq!(snapshot.occupied_workers(), 1);
        assert_eq!(snapshot.idle_workers(), 0);
        assert!(matches!(
            domain.try_submit(|| -> fn(super::ThreadCancellation) -> BlockingDrop {
                panic!("rejected callable must not be built")
            }),
            Err(ThreadDomainError::CapacityExhausted)
        ));
        assert!(matches!(
            domain.try_take_completion(&mut invocation),
            Ok(ThreadCompletion::Pending(
                ThreadInvocationObservation::Uncertain
            ))
        ));

        release_sender
            .send(())
            .expect("watchdog release channel must remain open");
        watchdog.join().expect("drop watchdog must not panic");
        wait_for_late(&mut domain, &mut invocation, LateResultReason::Uncertain);
        wait_for_idle(&domain);
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        domain.settle_budget();
    }

    #[test]
    fn result_pending_fence_returns_payload_to_the_charged_worker_for_cleanup() {
        let mut domain = domain::<BlockingDrop>(1, 332);
        let drop_release = Arc::new(ControlledLatch::new());
        let worker_drop_release = Arc::clone(&drop_release);
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(0);
        let (observed_sender, observed_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let watchdog_release = Arc::clone(&drop_release);
        let watchdog = thread::spawn(move || {
            entered_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("pending result destructor must run on its worker");
            observed_sender
                .send(())
                .expect("test must observe entered destructor");
            let _ = release_receiver.recv_timeout(Duration::from_millis(500));
            watchdog_release.release();
        });
        let Ok(mut invocation) = domain.try_submit(|| {
            move |_| BlockingDrop {
                entered: entered_sender,
                release: worker_drop_release,
            }
        }) else {
            panic!("worker must admit");
        };

        wait_for_observation(
            &mut domain,
            &mut invocation,
            ThreadInvocationObservation::ResultPending,
        );
        assert_eq!(domain.mark_uncertain(&invocation), Ok(()));
        observed_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("test must observe blocked destructor");
        let snapshot = domain.snapshot();
        assert_eq!(snapshot.active_invocations(), 1);
        assert_eq!(snapshot.occupied_workers(), 1);
        assert_eq!(snapshot.idle_workers(), 0);
        assert!(matches!(
            domain.try_submit(|| -> fn(super::ThreadCancellation) -> BlockingDrop {
                panic!("pending cleanup must retain capacity")
            }),
            Err(ThreadDomainError::CapacityExhausted)
        ));

        release_sender
            .send(())
            .expect("watchdog release channel must remain open");
        watchdog.join().expect("drop watchdog must not panic");
        wait_for_late(&mut domain, &mut invocation, LateResultReason::Uncertain);
        wait_for_idle(&domain);
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        domain.settle_budget();
    }

    #[test]
    fn dropping_result_pending_handle_cleans_payload_before_capacity_reuse() {
        let mut domain = domain::<BlockingDrop>(1, 333);
        let drop_release = Arc::new(ControlledLatch::new());
        let worker_drop_release = Arc::clone(&drop_release);
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(0);
        let (observed_sender, observed_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let watchdog_release = Arc::clone(&drop_release);
        let watchdog = thread::spawn(move || {
            entered_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("abandoned result destructor must run on its worker");
            observed_sender
                .send(())
                .expect("test must observe entered destructor");
            let _ = release_receiver.recv_timeout(Duration::from_millis(500));
            watchdog_release.release();
        });
        let Ok(mut invocation) = domain.try_submit(|| {
            move |_| BlockingDrop {
                entered: entered_sender,
                release: worker_drop_release,
            }
        }) else {
            panic!("worker must admit");
        };

        wait_for_observation(
            &mut domain,
            &mut invocation,
            ThreadInvocationObservation::ResultPending,
        );
        drop(invocation);
        observed_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("test must observe blocked destructor");
        let snapshot = domain.snapshot();
        assert_eq!(snapshot.active_invocations(), 1);
        assert_eq!(snapshot.occupied_workers(), 1);
        assert_eq!(snapshot.idle_workers(), 0);
        assert!(matches!(
            domain.try_submit(|| -> fn(super::ThreadCancellation) -> BlockingDrop {
                panic!("abandoned cleanup must retain capacity")
            }),
            Err(ThreadDomainError::CapacityExhausted)
        ));

        release_sender
            .send(())
            .expect("watchdog release channel must remain open");
        watchdog.join().expect("drop watchdog must not panic");
        wait_for_idle(&domain);
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        domain.settle_budget();
    }

    #[test]
    fn panicking_result_drop_cannot_orphan_worker_or_invocation_state() {
        let mut domain = domain::<PanickingDrop>(1, 34);
        let Ok(mut invocation) = domain.try_submit(|| {
            move |cancellation| {
                while !cancellation.is_cancellation_requested() {
                    thread::yield_now();
                }
                PanickingDrop
            }
        }) else {
            panic!("worker must admit");
        };

        let report = domain.shutdown_for(Duration::from_secs(1));
        assert!(report.complete());
        assert_eq!(report.snapshot().active_invocations(), 0);
        assert_eq!(report.snapshot().joined_workers(), 1);
        assert_eq!(report.snapshot().cleanup_panics(), 1);
        assert!(matches!(
            domain.try_take_completion(&mut invocation),
            Ok(ThreadCompletion::LateRejected(LateResultReason::Shutdown))
        ));
        assert!(matches!(
            domain.take_join_proof(),
            Err(ThreadDomainError::JoinProofUnavailable)
        ));
        assert_eq!(
            domain
                .budget
                .snapshot()
                .unwrap_or_else(|error| panic!("budget snapshot failed: {error}"))
                .active_reservations(),
            1
        );
    }

    #[test]
    fn result_pending_cleanup_panic_is_contained_and_remains_explicit() {
        let mut domain = domain::<PanickingDrop>(1, 341);
        let Ok(mut invocation) = domain.try_submit(|| |_| PanickingDrop) else {
            panic!("worker must admit");
        };
        wait_for_observation(
            &mut domain,
            &mut invocation,
            ThreadInvocationObservation::ResultPending,
        );
        assert_eq!(domain.mark_uncertain(&invocation), Ok(()));
        wait_for_late(&mut domain, &mut invocation, LateResultReason::Uncertain);
        wait_for_idle(&domain);
        let snapshot = domain.snapshot();
        assert_eq!(snapshot.cleanup_panics(), 1);
        assert_eq!(snapshot.panicked_workers(), 0);
        assert_eq!(snapshot.lifecycle(), ThreadDomainLifecycle::Poisoned);
        assert!(snapshot.conserves_worker_capacity());
        assert!(matches!(
            domain.try_submit(|| |_| PanickingDrop),
            Err(ThreadDomainError::DomainPoisoned)
        ));
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        assert!(matches!(
            domain.take_join_proof(),
            Err(ThreadDomainError::JoinProofUnavailable)
        ));
        assert_eq!(
            domain
                .budget
                .snapshot()
                .unwrap_or_else(|error| panic!("budget snapshot failed: {error}"))
                .active_reservations(),
            1
        );
    }

    #[test]
    fn shutdown_terminal_fence_cannot_be_relabelled_by_later_wedge() {
        let mut domain = domain::<u8>(1, 35);
        let gate = Arc::new(ControlledLatch::new());
        let worker_gate = Arc::clone(&gate);
        let Ok(mut invocation) = domain.try_submit(|| {
            move |_| {
                worker_gate.wait();
                43
            }
        }) else {
            panic!("worker must admit");
        };

        let first = domain.shutdown_for(Duration::from_millis(10));
        assert!(!first.complete());
        assert_eq!(domain.mark_wedged(&invocation), Ok(()));
        gate.release();
        wait_for_late(&mut domain, &mut invocation, LateResultReason::Shutdown);
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        domain.settle_budget();
    }

    #[test]
    fn successor_rejects_old_owner_result_even_when_numeric_epoch_repeats() {
        let mut original = domain::<u8>(1, 4);
        let Ok(mut invocation) = original.try_submit(|| |_| 13) else {
            panic!("original invocation must admit");
        };
        wait_for_observation(
            &mut original,
            &mut invocation,
            ThreadInvocationObservation::ResultPending,
        );
        let mut successor = domain::<u8>(1, 4);
        assert_eq!(
            successor.try_take_completion(&mut invocation),
            Err(ThreadDomainError::StaleCompletionFence)
        );
        assert_eq!(invocation.fence().domain_epoch(), epoch(4));
        assert_eq!(invocation.fence().invocation().value(), 1);
        assert_eq!(
            original.try_take_completion(&mut invocation),
            Ok(ThreadCompletion::Returned(13))
        );
        assert!(original.shutdown_for(Duration::from_secs(1)).complete());
        assert!(successor.shutdown_for(Duration::from_secs(1)).complete());
        original.settle_budget();
        successor.settle_budget();
    }

    #[test]
    fn shutdown_race_fences_pending_and_running_results_then_joins_exactly() {
        let mut domain = domain::<u8>(2, 5);
        let Ok(mut already_returned) = domain.try_submit(|| |_| 17) else {
            panic!("first invocation must admit");
        };
        wait_for_observation(
            &mut domain,
            &mut already_returned,
            ThreadInvocationObservation::ResultPending,
        );
        let gate = Arc::new(ControlledLatch::new());
        let worker_gate = Arc::clone(&gate);
        let Ok(mut running) = domain.try_submit(|| {
            move |_| {
                worker_gate.wait();
                19
            }
        }) else {
            panic!("second invocation must admit");
        };

        let incomplete = domain.shutdown_for(Duration::from_millis(10));
        assert!(!incomplete.complete());
        assert_eq!(
            domain.try_take_completion(&mut already_returned),
            Ok(ThreadCompletion::LateRejected(LateResultReason::Shutdown))
        );
        assert!(matches!(
            domain.try_submit(|| |_| 23),
            Err(ThreadDomainError::DomainClosing)
        ));
        gate.release();
        wait_for_late(&mut domain, &mut running, LateResultReason::Shutdown);
        let complete = domain.shutdown_for(Duration::from_secs(1));
        assert!(complete.complete());
        assert_eq!(complete.snapshot().joined_workers(), 2);
        assert_eq!(complete.snapshot().active_invocations(), 0);
        assert!(complete.snapshot().conserves_worker_capacity());
        domain.settle_budget();
    }

    #[test]
    fn result_pending_and_panic_both_conserve_the_same_permit() {
        let mut domain = domain::<u8>(1, 6);
        let Ok(mut returned) = domain.try_submit(|| |_| 29) else {
            panic!("returning invocation must admit");
        };
        wait_for_observation(
            &mut domain,
            &mut returned,
            ThreadInvocationObservation::ResultPending,
        );
        assert!(matches!(
            domain.try_submit(|| |_| 31),
            Err(ThreadDomainError::CapacityExhausted)
        ));
        assert_eq!(
            domain.try_take_completion(&mut returned),
            Ok(ThreadCompletion::Returned(29))
        );
        wait_for_idle(&domain);

        let Ok(mut panicked) = domain.try_submit(|| |_| -> u8 { panic!("fixture panic") }) else {
            panic!("panic invocation must admit");
        };
        wait_for_observation(
            &mut domain,
            &mut panicked,
            ThreadInvocationObservation::ResultPending,
        );
        assert_eq!(
            domain.try_take_completion(&mut panicked),
            Ok(ThreadCompletion::Panicked)
        );
        wait_for_idle(&domain);
        let snapshot = domain.snapshot();
        assert_eq!(snapshot.idle_workers(), 1);
        assert_eq!(snapshot.active_invocations(), 0);
        assert_eq!(snapshot.panicked_workers(), 0);
        assert_eq!(snapshot.lifecycle(), ThreadDomainLifecycle::Poisoned);
        assert!(matches!(
            domain.try_submit(|| |_| 37),
            Err(ThreadDomainError::DomainPoisoned)
        ));
        assert!(snapshot.conserves_worker_capacity());
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        domain.settle_budget();
    }
}
