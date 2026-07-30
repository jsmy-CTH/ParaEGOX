//! RuntimeHost-owned registry for heterogeneous bounded ThreadDomains.
//!
//! The registry is the single owner of the process-wide executor ledger and
//! of every domain's concrete `JoinHandle`s. Typed handles carry no thread or
//! lifecycle authority; they only allow the owning RuntimeHost scope to visit
//! the exact domain while it remains installed here.

use core::any::Any;
use core::fmt;
use core::marker::PhantomData;
use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::Arc;

use paraegox_runtime_contracts::thread_execution::{
    ExecutorBudgetSpec, ThreadDomainRef, ThreadDomainSpec,
};

use crate::card_instance::DomainEpoch;
use crate::executor_budget::{
    ExecutorBudget, ExecutorBudgetError, ExecutorBudgetSnapshot, ExecutorReservation,
    ThreadInventoryMismatch, ThreadInventoryObservation,
};
use crate::thread_domain::{
    ThreadDomain, ThreadDomainBuildError, ThreadDomainBuildFailure, ThreadDomainConfig,
    ThreadDomainError, ThreadDomainJoinProof, ThreadDomainSnapshot,
};

const MAX_OWNED_THREAD_DOMAINS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadOwnerShutdownError {
    Incomplete,
    Failed,
}

/// Type-erased lifecycle contract for an owner that directly retains one
/// ThreadDomain's JoinHandles and can return its linear global-budget proof.
pub(crate) trait RuntimeThreadOwner: Send {
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn domain_snapshot(&self) -> ThreadDomainSnapshot;

    /// Every call must synchronously stop new admission and request
    /// cancellation before waiting for `budget` or returning any error. A zero
    /// budget is therefore the registry's non-waiting phase-one transition.
    /// `Incomplete` and `Failed` retain all owner and proof authority in self.
    fn shutdown_and_prove(
        &mut self,
        budget: Duration,
    ) -> Result<ThreadDomainJoinProof, ThreadOwnerShutdownError>;
}

impl<T: Send + 'static> RuntimeThreadOwner for ThreadDomain<T> {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn domain_snapshot(&self) -> ThreadDomainSnapshot {
        self.snapshot()
    }

    fn shutdown_and_prove(
        &mut self,
        budget: Duration,
    ) -> Result<ThreadDomainJoinProof, ThreadOwnerShutdownError> {
        let report = self.shutdown_for(budget);
        let snapshot = report.snapshot();
        if snapshot.cleanup_panics() != 0 || snapshot.panicked_workers() != 0 {
            return Err(ThreadOwnerShutdownError::Failed);
        }
        if !report.complete() {
            return Err(ThreadOwnerShutdownError::Incomplete);
        }
        self.take_join_proof()
            .map_err(|_| ThreadOwnerShutdownError::Failed)
    }
}

struct OwnedThreadDomain {
    drain_budget: Duration,
    owner: Box<dyn RuntimeThreadOwner>,
    join_proof: Option<ThreadDomainJoinProof>,
}

/// Non-authoritative typed selector for a domain retained by one registry.
pub(crate) struct ThreadOwnerHandle<Owner: RuntimeThreadOwner + 'static> {
    registry: Arc<()>,
    domain: ThreadDomainRef,
    value: PhantomData<fn() -> Owner>,
}

impl<Owner: RuntimeThreadOwner + 'static> ThreadOwnerHandle<Owner> {
    #[must_use]
    pub(crate) const fn domain(&self) -> ThreadDomainRef {
        self.domain
    }
}

pub(crate) type ThreadDomainHandle<T> = ThreadOwnerHandle<ThreadDomain<T>>;

/// One process-local ThreadDomain census and its global planned budget.
pub(crate) struct RuntimeThreadRegistry {
    identity: Arc<()>,
    plan: ExecutorBudgetSpec,
    budget: ExecutorBudget,
    domains: BTreeMap<ThreadDomainRef, OwnedThreadDomain>,
}

impl RuntimeThreadRegistry {
    pub(crate) fn try_new(spec: ExecutorBudgetSpec) -> Result<Self, ThreadRegistryError> {
        let budget = ExecutorBudget::try_new(spec.max_total_threads(), spec.framework_threads())?;
        Ok(Self {
            identity: Arc::new(()),
            plan: spec,
            budget,
            domains: BTreeMap::new(),
        })
    }

    #[must_use]
    pub(crate) const fn plan(&self) -> ExecutorBudgetSpec {
        self.plan
    }

    /// Atomically reserves the exact global worker budget before construction.
    ///
    /// S5 deliberately supports the trusted synchronous I/O profile with zero
    /// native-library threads. A later target-specific native-pool adapter must
    /// supply shutdown and census proof before nonzero native reservations can
    /// become operational; the desired-state contract can already express it.
    pub(crate) fn try_create<T: Send + 'static>(
        &mut self,
        domain_epoch: DomainEpoch,
        spec: ThreadDomainSpec,
        native_threads: u32,
    ) -> Result<ThreadDomainHandle<T>, ThreadRegistryError> {
        let workers = usize::try_from(spec.worker_count())
            .map_err(|_| ThreadRegistryError::InvalidDomainConfiguration)?;
        let config =
            ThreadDomainConfig::try_new(workers, Duration::from_nanos(spec.start_budget().value()))
                .map_err(ThreadRegistryError::DomainBuild)?;
        self.try_create_owner(spec, native_threads, move |reservation| {
            ThreadDomain::<T>::try_new(domain_epoch, config, reservation)
        })
    }

    /// Reserves one canonical domain allocation and installs the concrete
    /// lifecycle owner only after its fixed workers have started. This is the
    /// sole reservation path used by both raw domains and the L2 component.
    pub(crate) fn try_create_owner<Owner, Build>(
        &mut self,
        spec: ThreadDomainSpec,
        native_threads: u32,
        build: Build,
    ) -> Result<ThreadOwnerHandle<Owner>, ThreadRegistryError>
    where
        Owner: RuntimeThreadOwner + 'static,
        Build: FnOnce(ExecutorReservation) -> Result<Owner, ThreadDomainBuildFailure>,
    {
        if self.domains.contains_key(&spec.domain()) {
            return Err(ThreadRegistryError::DomainAlreadyOwned);
        }
        if self.domains.len() >= MAX_OWNED_THREAD_DOMAINS {
            return Err(ThreadRegistryError::DomainCapacityExhausted);
        }
        if native_threads != 0 {
            return Err(ThreadRegistryError::NativeOwnerUnavailable);
        }
        let drain_budget = Duration::from_nanos(spec.drain_budget().value());
        if drain_budget.is_zero() {
            return Err(ThreadRegistryError::InvalidDomainConfiguration);
        }
        let reservation = self
            .budget
            .try_reserve(spec.worker_count(), native_threads)?;
        let owner = match build(reservation) {
            Ok(owner) => owner,
            Err(failure) => {
                let (error, mut proof) = failure.into_parts();
                self.budget.release(&mut proof)?;
                return Err(ThreadRegistryError::DomainBuild(error));
            }
        };
        let replaced = self.domains.insert(
            spec.domain(),
            OwnedThreadDomain {
                drain_budget,
                owner: Box::new(owner),
                join_proof: None,
            },
        );
        if replaced.is_some() {
            return Err(ThreadRegistryError::StateInconsistent);
        }
        Ok(ThreadOwnerHandle {
            registry: Arc::clone(&self.identity),
            domain: spec.domain(),
            value: PhantomData,
        })
    }

    /// Visits the concrete domain without transferring its lifecycle owner.
    pub(crate) fn with_domain_mut<T: Send + 'static, R>(
        &mut self,
        handle: &ThreadDomainHandle<T>,
        visit: impl FnOnce(&mut ThreadDomain<T>) -> R,
    ) -> Result<R, ThreadRegistryError> {
        self.with_owner_mut(handle, visit)
    }

    /// Visits any concrete owner without moving its ThreadDomain or budget
    /// lease out of the RuntimeHost registry.
    pub(crate) fn with_owner_mut<Owner, R>(
        &mut self,
        handle: &ThreadOwnerHandle<Owner>,
        visit: impl FnOnce(&mut Owner) -> R,
    ) -> Result<R, ThreadRegistryError>
    where
        Owner: RuntimeThreadOwner + 'static,
    {
        if !Arc::ptr_eq(&self.identity, &handle.registry) {
            return Err(ThreadRegistryError::HandleOwnerMismatch);
        }
        let owned = self
            .domains
            .get_mut(&handle.domain)
            .ok_or(ThreadRegistryError::DomainNotOwned)?;
        let owner = owned
            .owner
            .as_any_mut()
            .downcast_mut::<Owner>()
            .ok_or(ThreadRegistryError::HandleTypeMismatch)?;
        Ok(visit(owner))
    }

    #[must_use]
    pub(crate) fn domain_count(&self) -> usize {
        self.domains.len()
    }

    pub(crate) fn budget_snapshot(&self) -> Result<ExecutorBudgetSnapshot, ThreadRegistryError> {
        self.budget.snapshot().map_err(ThreadRegistryError::Budget)
    }

    /// Compares the registry's actual live-worker census with injected facts
    /// from a target-specific framework/native thread observer.
    pub(crate) fn evaluate_observation(
        &self,
        observed_framework_threads: u32,
        observed_native_threads: u32,
        observed_unknown_threads: u32,
    ) -> Result<(), ThreadRegistryError> {
        let live_workers = self.domains.values().try_fold(0_u32, |total, domain| {
            let live = u32::try_from(domain.owner.domain_snapshot().live_workers())
                .map_err(|_| ThreadRegistryError::ObservedCounterOverflow)?;
            total
                .checked_add(live)
                .ok_or(ThreadRegistryError::ObservedCounterOverflow)
        })?;
        self.budget
            .evaluate_observation(ThreadInventoryObservation::new(
                observed_framework_threads,
                live_workers,
                observed_native_threads,
                observed_unknown_threads,
            ))
            .map_err(ThreadRegistryError::Observation)
    }

    /// Initiates shutdown for every owner before spending any signed drain
    /// budget, then best-effort joins and settles every proof. An incomplete or
    /// failed owner never leaves a later owner accepting work, and every
    /// unsettled proof remains attached to its owner for an honest retry.
    pub(crate) fn shutdown(&mut self) -> Result<(), ThreadRegistryError> {
        let domains: Vec<_> = self.domains.keys().copied().collect();
        let mut hard_error = None;

        // Phase 1 is deliberately non-waiting. A zero-budget call still
        // performs the concrete owner's stop-admission and cancellation
        // transition. Already-quiescent owners may return their proof here;
        // retain it linearly until the ledger accepts it below.
        for domain_ref in &domains {
            let outcome = {
                let owned = self
                    .domains
                    .get_mut(domain_ref)
                    .ok_or(ThreadRegistryError::StateInconsistent)?;
                if owned.join_proof.is_some() {
                    None
                } else {
                    Some(owner_shutdown_for(owned, Duration::ZERO))
                }
            };
            if let Some(Ok(proof)) = outcome {
                let owned = self
                    .domains
                    .get_mut(domain_ref)
                    .ok_or(ThreadRegistryError::StateInconsistent)?;
                owned.join_proof = Some(proof);
            }
        }

        // Phase 2 waits each still-live owner only for its own signed budget.
        // Errors are accumulated so one bad owner cannot strand later domains
        // in Accepting state.
        let mut incomplete = false;
        let mut cleanup_failed = false;
        for domain_ref in &domains {
            let outcome = {
                let owned = self
                    .domains
                    .get_mut(domain_ref)
                    .ok_or(ThreadRegistryError::StateInconsistent)?;
                if owned.join_proof.is_some() {
                    None
                } else {
                    Some(owner_shutdown_for(owned, owned.drain_budget))
                }
            };
            match outcome {
                Some(Ok(proof)) => {
                    let owned = self
                        .domains
                        .get_mut(domain_ref)
                        .ok_or(ThreadRegistryError::StateInconsistent)?;
                    owned.join_proof = Some(proof);
                }
                Some(Err(ThreadOwnerShutdownError::Incomplete)) => incomplete = true,
                Some(Err(ThreadOwnerShutdownError::Failed)) => cleanup_failed = true,
                None => {}
            }
        }

        // Proof settlement is also best-effort. A rejected proof stays stored
        // beside the closed owner; dropping it would erase the only linear
        // evidence capable of reconciling the global executor ledger.
        for domain_ref in domains {
            let release = {
                let Some(owned) = self.domains.get_mut(&domain_ref) else {
                    if hard_error.is_none() {
                        hard_error = Some(ThreadRegistryError::StateInconsistent);
                    }
                    continue;
                };
                owned
                    .join_proof
                    .as_mut()
                    .map(|proof| self.budget.release(proof))
            };
            match release {
                Some(Ok(())) => {
                    if self.domains.remove(&domain_ref).is_none() && hard_error.is_none() {
                        hard_error = Some(ThreadRegistryError::StateInconsistent);
                    }
                }
                Some(Err(error)) if hard_error.is_none() => {
                    hard_error = Some(ThreadRegistryError::Budget(error));
                }
                Some(Err(_)) | None => {}
            }
        }

        if let Some(error) = hard_error {
            return Err(error);
        }
        if cleanup_failed {
            return Err(ThreadRegistryError::OwnerCleanupFailed);
        }
        if incomplete || !self.domains.is_empty() {
            return Err(ThreadRegistryError::DrainIncomplete);
        }
        let snapshot = self.budget.snapshot()?;
        if snapshot.active_reservations() != 0
            || snapshot.managed_workers() != 0
            || snapshot.native_threads() != 0
        {
            return Err(ThreadRegistryError::StateInconsistent);
        }
        Ok(())
    }
}

fn owner_shutdown_for(
    owned: &mut OwnedThreadDomain,
    budget: Duration,
) -> Result<ThreadDomainJoinProof, ThreadOwnerShutdownError> {
    owned.owner.shutdown_and_prove(budget)
}

#[derive(Debug)]
pub(crate) enum ThreadRegistryError {
    Budget(ExecutorBudgetError),
    Observation(ThreadInventoryMismatch),
    DomainBuild(ThreadDomainBuildError),
    Domain(ThreadDomainError),
    InvalidDomainConfiguration,
    ExecutorPlanMismatch,
    NativeOwnerUnavailable,
    DomainCapacityExhausted,
    DomainAlreadyOwned,
    DomainNotOwned,
    HandleOwnerMismatch,
    HandleTypeMismatch,
    ObservedCounterOverflow,
    DrainIncomplete,
    OwnerCleanupFailed,
    StateInconsistent,
}

impl From<ExecutorBudgetError> for ThreadRegistryError {
    fn from(value: ExecutorBudgetError) -> Self {
        Self::Budget(value)
    }
}

impl From<ThreadDomainError> for ThreadRegistryError {
    fn from(value: ThreadDomainError) -> Self {
        Self::Domain(value)
    }
}

impl fmt::Display for ThreadRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Budget(error) => write!(formatter, "ThreadDomain budget rejected: {error}"),
            Self::Observation(error) => write!(formatter, "thread census rejected: {error}"),
            Self::DomainBuild(error) => write!(formatter, "ThreadDomain build rejected: {error}"),
            Self::Domain(error) => write!(formatter, "ThreadDomain owner rejected: {error}"),
            Self::InvalidDomainConfiguration => {
                formatter.write_str("ThreadDomain plan cannot be represented by this target")
            }
            Self::ExecutorPlanMismatch => formatter
                .write_str("component executor budget differs from the RuntimeHost registry plan"),
            Self::NativeOwnerUnavailable => formatter
                .write_str("no admitted native-pool census and shutdown owner is installed"),
            Self::DomainCapacityExhausted => {
                formatter.write_str("RuntimeHost ThreadDomain registry is full")
            }
            Self::DomainAlreadyOwned => {
                formatter.write_str("ThreadDomain reference is already owned")
            }
            Self::DomainNotOwned => formatter.write_str("ThreadDomain reference is not owned"),
            Self::HandleOwnerMismatch => {
                formatter.write_str("ThreadDomain handle belongs to another RuntimeHost registry")
            }
            Self::HandleTypeMismatch => {
                formatter.write_str("ThreadDomain handle result type does not match its owner")
            }
            Self::ObservedCounterOverflow => {
                formatter.write_str("observed ThreadDomain worker census overflowed")
            }
            Self::DrainIncomplete => {
                formatter.write_str("ThreadDomain retained live or unjoined OS workers")
            }
            Self::OwnerCleanupFailed => {
                formatter.write_str("ThreadDomain owner failed exact-zero cleanup")
            }
            Self::StateInconsistent => {
                formatter.write_str("RuntimeHost ThreadDomain registry is inconsistent")
            }
        }
    }
}

impl std::error::Error for ThreadRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Budget(error) => Some(error),
            Self::Observation(error) => Some(error),
            Self::DomainBuild(error) => Some(error),
            Self::Domain(error) => Some(error),
            Self::InvalidDomainConfiguration
            | Self::ExecutorPlanMismatch
            | Self::NativeOwnerUnavailable
            | Self::DomainCapacityExhausted
            | Self::DomainAlreadyOwned
            | Self::DomainNotOwned
            | Self::HandleOwnerMismatch
            | Self::HandleTypeMismatch
            | Self::ObservedCounterOverflow
            | Self::DrainIncomplete
            | Self::OwnerCleanupFailed
            | Self::StateInconsistent => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;
    use std::time::Instant;

    use paraegox_kernel::time::BoundedDuration;
    use paraegox_runtime_contracts::thread_execution::{
        ExecutorBudgetSpec, ThreadDomainRef, ThreadDomainSpec,
    };

    use super::{RuntimeThreadRegistry, ThreadRegistryError};
    use crate::card_instance::DomainEpoch;
    use crate::executor_budget::{ExecutorBudgetError, ThreadInventoryMismatch};
    use crate::thread_domain::{
        LateResultReason, ThreadCompletion, ThreadDomainError, ThreadDomainLifecycle,
        ThreadInvocationObservation,
    };

    struct PanickingDrop;

    impl Drop for PanickingDrop {
        fn drop(&mut self) {
            panic!("test result cleanup panic");
        }
    }

    struct Gate {
        open: Mutex<bool>,
        changed: Condvar,
    }

    impl Gate {
        fn new() -> Self {
            Self {
                open: Mutex::new(false),
                changed: Condvar::new(),
            }
        }

        fn wait(&self) {
            let mut open = self.open.lock().unwrap_or_else(|error| error.into_inner());
            while !*open {
                open = self
                    .changed
                    .wait(open)
                    .unwrap_or_else(|error| error.into_inner());
            }
        }

        fn release(&self) {
            let mut open = self.open.lock().unwrap_or_else(|error| error.into_inner());
            *open = true;
            self.changed.notify_all();
        }
    }

    fn duration(nanos: u64) -> BoundedDuration {
        BoundedDuration::from_nanos(nanos)
    }

    fn domain_spec(byte: u8, workers: u32, drain_nanos: u64) -> ThreadDomainSpec {
        ThreadDomainSpec::try_new(
            ThreadDomainRef::from_bytes([byte; 16]),
            workers,
            duration(1_000_000_000),
            duration(1_000_000_000),
            duration(drain_nanos),
        )
        .expect("test ThreadDomain spec")
    }

    fn epoch(value: u64) -> DomainEpoch {
        DomainEpoch::try_new(value).expect("test domain epoch")
    }

    #[test]
    fn heterogeneous_domains_share_one_budget_and_root_owned_join_census() {
        let budget = ExecutorBudgetSpec::try_new(4, 1).expect("test budget");
        let mut registry = RuntimeThreadRegistry::try_new(budget).expect("registry");
        let first = registry
            .try_create::<u8>(epoch(1), domain_spec(0xa1, 1, 1_000_000_000), 0)
            .expect("first domain");
        let second = registry
            .try_create::<String>(epoch(2), domain_spec(0xa2, 2, 1_000_000_000), 0)
            .expect("second domain");
        assert_eq!(first.domain(), ThreadDomainRef::from_bytes([0xa1; 16]));
        assert_eq!(second.domain(), ThreadDomainRef::from_bytes([0xa2; 16]));
        assert_eq!(registry.domain_count(), 2);
        assert_eq!(
            registry
                .budget_snapshot()
                .expect("budget snapshot")
                .reserved_threads(),
            4
        );
        assert!(registry.evaluate_observation(1, 0, 0).is_ok());
        registry.shutdown().expect("all workers join");
        assert_eq!(registry.domain_count(), 0);
        assert_eq!(
            registry
                .budget_snapshot()
                .expect("terminal budget")
                .active_reservations(),
            0
        );
    }

    #[test]
    fn global_budget_rejects_a_second_domain_without_starting_workers() {
        let budget = ExecutorBudgetSpec::try_new(3, 1).expect("test budget");
        let mut registry = RuntimeThreadRegistry::try_new(budget).expect("registry");
        let _first = registry
            .try_create::<()>(epoch(3), domain_spec(0xb1, 2, 1_000_000_000), 0)
            .expect("first domain");
        assert!(matches!(
            registry.try_create::<()>(epoch(4), domain_spec(0xb2, 1, 1_000_000_000), 0),
            Err(ThreadRegistryError::Budget(
                ExecutorBudgetError::CapacityExhausted
            ))
        ));
        assert_eq!(registry.domain_count(), 1);
        registry.shutdown().expect("first domain joins");
    }

    #[test]
    fn handles_are_registry_and_result_type_scoped() {
        let budget = ExecutorBudgetSpec::try_new(2, 1).expect("test budget");
        let mut first = RuntimeThreadRegistry::try_new(budget).expect("first registry");
        let mut second = RuntimeThreadRegistry::try_new(budget).expect("second registry");
        let handle = first
            .try_create::<u8>(epoch(5), domain_spec(0xc1, 1, 1_000_000_000), 0)
            .expect("domain");
        assert!(matches!(
            second.with_domain_mut(&handle, |_| ()),
            Err(ThreadRegistryError::HandleOwnerMismatch)
        ));
        first.shutdown().expect("first joins");
        second.shutdown().expect("empty registry closes");
    }

    #[test]
    fn native_and_unknown_thread_facts_fail_closed_without_an_owner_adapter() {
        let budget = ExecutorBudgetSpec::try_new(3, 1).expect("test budget");
        let mut registry = RuntimeThreadRegistry::try_new(budget).expect("registry");
        assert!(matches!(
            registry.try_create::<()>(epoch(6), domain_spec(0xd1, 1, 1_000_000_000), 1),
            Err(ThreadRegistryError::NativeOwnerUnavailable)
        ));
        assert_eq!(
            registry
                .budget_snapshot()
                .expect("unchanged budget")
                .active_reservations(),
            0
        );
        let _handle = registry
            .try_create::<()>(epoch(7), domain_spec(0xd2, 1, 1_000_000_000), 0)
            .expect("zero-native domain");
        assert!(matches!(
            registry.evaluate_observation(1, 0, 1),
            Err(ThreadRegistryError::Observation(
                ThreadInventoryMismatch::UnknownThreadsObserved
            ))
        ));
        assert!(matches!(
            registry.evaluate_observation(1, 1, 0),
            Err(ThreadRegistryError::Observation(
                ThreadInventoryMismatch::NativeReservationExceeded
            ))
        ));
        registry.shutdown().expect("domain joins");
    }

    #[test]
    fn incomplete_root_shutdown_retains_wedged_owner_until_real_return() {
        let budget = ExecutorBudgetSpec::try_new(2, 1).expect("test budget");
        let mut registry = RuntimeThreadRegistry::try_new(budget).expect("registry");
        let handle = registry
            .try_create::<u8>(epoch(8), domain_spec(0xe1, 1, 2_000_000), 0)
            .expect("domain");
        let gate = Arc::new(Gate::new());
        let worker_gate = Arc::clone(&gate);
        let mut invocation = registry
            .with_domain_mut(&handle, |domain| {
                domain.try_submit(|| {
                    move |_| {
                        worker_gate.wait();
                        41
                    }
                })
            })
            .expect("visit domain")
            .expect("submit work");
        registry
            .with_domain_mut(&handle, |domain| domain.mark_wedged(&invocation))
            .expect("visit domain")
            .expect("mark wedged");
        assert!(matches!(
            registry.shutdown(),
            Err(ThreadRegistryError::DrainIncomplete)
        ));
        assert_eq!(registry.domain_count(), 1);
        assert_eq!(
            registry
                .budget_snapshot()
                .expect("retained budget")
                .active_reservations(),
            1
        );

        gate.release();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let completion = registry
                .with_domain_mut(&handle, |domain| {
                    domain.try_take_completion(&mut invocation)
                })
                .expect("visit domain")
                .expect("observe completion");
            match completion {
                ThreadCompletion::LateRejected(LateResultReason::Wedged) => break,
                ThreadCompletion::LateRejected(_) => {
                    panic!("unexpected late-result reason")
                }
                ThreadCompletion::Pending(_) => {}
                ThreadCompletion::Returned(_) | ThreadCompletion::Panicked => {
                    panic!("wedged output crossed the owner fence")
                }
            }
            assert!(Instant::now() < deadline, "late result timed out");
            thread::yield_now();
        }
        registry.shutdown().expect("real return allows join");
        assert_eq!(registry.domain_count(), 0);
    }

    #[test]
    fn rejected_result_cleanup_panic_retains_owner_and_budget_proof() {
        let budget = ExecutorBudgetSpec::try_new(2, 1).expect("test budget");
        let mut registry = RuntimeThreadRegistry::try_new(budget).expect("registry");
        let handle = registry
            .try_create::<PanickingDrop>(epoch(13), domain_spec(0xf5, 1, 1_000_000_000), 0)
            .expect("domain");
        let mut invocation = registry
            .with_domain_mut(&handle, |domain| domain.try_submit(|| |_| PanickingDrop))
            .expect("visit domain")
            .expect("submit work");

        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let completion = registry
                .with_domain_mut(&handle, |domain| {
                    domain.try_take_completion(&mut invocation)
                })
                .expect("visit domain")
                .expect("observe completion");
            if matches!(
                completion,
                ThreadCompletion::Pending(ThreadInvocationObservation::ResultPending)
            ) {
                break;
            }
            assert!(
                matches!(completion, ThreadCompletion::Pending(_)),
                "panicking result must remain worker-owned"
            );
            assert!(Instant::now() < deadline, "result-pending timed out");
            thread::yield_now();
        }

        assert!(matches!(
            registry.shutdown(),
            Err(ThreadRegistryError::OwnerCleanupFailed)
        ));
        assert_eq!(registry.domain_count(), 1);
        let snapshot = registry
            .with_domain_mut(&handle, |domain| domain.snapshot())
            .expect("failed-cleanup owner remains installed");
        assert_eq!(snapshot.lifecycle(), ThreadDomainLifecycle::Closed);
        assert_eq!(snapshot.live_workers(), 0);
        assert_eq!(snapshot.joined_workers(), 1);
        assert_eq!(snapshot.active_invocations(), 0);
        assert_eq!(snapshot.cleanup_panics(), 1);
        let retained = registry.budget_snapshot().expect("retained budget");
        assert_eq!(retained.active_reservations(), 1);
        assert_eq!(retained.managed_workers(), 1);

        assert!(matches!(
            registry.shutdown(),
            Err(ThreadRegistryError::OwnerCleanupFailed)
        ));
        assert_eq!(registry.domain_count(), 1);
        assert_eq!(
            registry
                .with_domain_mut(&handle, |domain| domain.snapshot().cleanup_panics())
                .expect("failed-cleanup owner remains installed"),
            1
        );
        let retry_retained = registry
            .budget_snapshot()
            .expect("retry retains the same budget proof");
        assert_eq!(retry_retained.active_reservations(), 1);
        assert_eq!(retry_retained.managed_workers(), 1);
    }

    #[test]
    fn first_incomplete_domain_still_closes_every_later_domain_before_retry() {
        let budget = ExecutorBudgetSpec::try_new(3, 1).expect("test budget");
        let mut registry = RuntimeThreadRegistry::try_new(budget).expect("registry");
        let first = registry
            .try_create::<bool>(epoch(9), domain_spec(0xf1, 1, 2_000_000), 0)
            .expect("first domain");
        let second = registry
            .try_create::<bool>(epoch(10), domain_spec(0xf2, 1, 2_000_000), 0)
            .expect("second domain");
        let first_gate = Arc::new(Gate::new());
        let second_gate = Arc::new(Gate::new());
        let worker_first_gate = Arc::clone(&first_gate);
        let worker_second_gate = Arc::clone(&second_gate);
        let mut first_invocation = registry
            .with_domain_mut(&first, |domain| {
                domain.try_submit(|| {
                    move |cancellation| {
                        worker_first_gate.wait();
                        cancellation.is_cancellation_requested()
                    }
                })
            })
            .expect("visit first domain")
            .expect("submit first work");
        let mut second_invocation = registry
            .with_domain_mut(&second, |domain| {
                domain.try_submit(|| {
                    move |cancellation| {
                        worker_second_gate.wait();
                        cancellation.is_cancellation_requested()
                    }
                })
            })
            .expect("visit second domain")
            .expect("submit second work");

        assert!(matches!(
            registry.shutdown(),
            Err(ThreadRegistryError::DrainIncomplete)
        ));
        assert_eq!(registry.domain_count(), 2);
        for handle in [&first, &second] {
            let snapshot = registry
                .with_domain_mut(handle, |domain| domain.snapshot())
                .expect("closing domain remains owned");
            assert_eq!(snapshot.lifecycle(), ThreadDomainLifecycle::Closing);
            assert!(matches!(
                registry
                    .with_domain_mut(handle, |domain| domain.try_submit(|| |_| false))
                    .expect("visit closing domain"),
                Err(ThreadDomainError::DomainClosing)
            ));
        }
        let retained = registry.budget_snapshot().expect("retained budget");
        assert_eq!(retained.active_reservations(), 2);
        assert_eq!(retained.managed_workers(), 2);

        first_gate.release();
        second_gate.release();
        for (handle, invocation) in [
            (&first, &mut first_invocation),
            (&second, &mut second_invocation),
        ] {
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                let completion = registry
                    .with_domain_mut(handle, |domain| domain.try_take_completion(invocation))
                    .expect("visit returning domain")
                    .expect("observe fenced completion");
                match completion {
                    ThreadCompletion::LateRejected(LateResultReason::Shutdown) => break,
                    ThreadCompletion::Pending(_) => {}
                    ThreadCompletion::LateRejected(_)
                    | ThreadCompletion::Returned(_)
                    | ThreadCompletion::Panicked => {
                        panic!("shutdown-fenced output crossed or changed its fence")
                    }
                }
                assert!(Instant::now() < deadline, "shutdown result timed out");
                thread::yield_now();
            }
        }

        registry
            .shutdown()
            .expect("real returns allow exact-zero retry");
        assert_eq!(registry.domain_count(), 0);
        let zero = registry.budget_snapshot().expect("terminal budget");
        assert_eq!(zero.active_reservations(), 0);
        assert_eq!(zero.managed_workers(), 0);
        assert_eq!(zero.native_threads(), 0);
    }

    #[test]
    fn incomplete_owner_does_not_block_later_proof_settlement() {
        let budget = ExecutorBudgetSpec::try_new(3, 1).expect("test budget");
        let mut registry = RuntimeThreadRegistry::try_new(budget).expect("registry");
        let first = registry
            .try_create::<u8>(epoch(11), domain_spec(0xf3, 1, 2_000_000), 0)
            .expect("first domain");
        let second = registry
            .try_create::<()>(epoch(12), domain_spec(0xf4, 1, 1_000_000_000), 0)
            .expect("second domain");
        let gate = Arc::new(Gate::new());
        let worker_gate = Arc::clone(&gate);
        let mut invocation = registry
            .with_domain_mut(&first, |domain| {
                domain.try_submit(|| {
                    move |_| {
                        worker_gate.wait();
                        73
                    }
                })
            })
            .expect("visit first domain")
            .expect("submit first work");

        assert!(matches!(
            registry.shutdown(),
            Err(ThreadRegistryError::DrainIncomplete)
        ));
        assert_eq!(registry.domain_count(), 1);
        assert!(matches!(
            registry.with_domain_mut(&second, |_| ()),
            Err(ThreadRegistryError::DomainNotOwned)
        ));
        let retained = registry
            .budget_snapshot()
            .expect("partially settled budget");
        assert_eq!(retained.active_reservations(), 1);
        assert_eq!(retained.managed_workers(), 1);
        assert_eq!(
            registry
                .with_domain_mut(&first, |domain| domain.snapshot().lifecycle())
                .expect("first owner remains installed"),
            ThreadDomainLifecycle::Closing
        );

        gate.release();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let completion = registry
                .with_domain_mut(&first, |domain| domain.try_take_completion(&mut invocation))
                .expect("visit first domain")
                .expect("observe first completion");
            match completion {
                ThreadCompletion::LateRejected(LateResultReason::Shutdown) => break,
                ThreadCompletion::Pending(_) => {}
                ThreadCompletion::LateRejected(_)
                | ThreadCompletion::Returned(_)
                | ThreadCompletion::Panicked => {
                    panic!("shutdown-fenced first result crossed or changed its fence")
                }
            }
            assert!(Instant::now() < deadline, "first result timed out");
            thread::yield_now();
        }
        registry.shutdown().expect("first owner now joins");
        assert_eq!(registry.domain_count(), 0);
        let zero = registry.budget_snapshot().expect("terminal budget");
        assert_eq!(zero.active_reservations(), 0);
        assert_eq!(zero.managed_workers(), 0);
    }
}
