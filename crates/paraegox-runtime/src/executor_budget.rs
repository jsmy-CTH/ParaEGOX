//! RuntimeHost-owned accounting for the S5 bounded thread inventory.
//!
//! This ledger owns plan reservations, not operating-system threads. A
//! reservation must remain active until the corresponding worker owner has
//! observed every callable return and joined every worker. In particular,
//! caller timeout, cancellation intent, and a wedged fact never release it.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::thread_domain::{ThreadDomainJoinKind, ThreadDomainJoinProof};

#[derive(Debug)]
struct ExecutorBudgetMarker;

/// One linear reservation from the RuntimeHost-wide executor budget.
#[must_use = "an executor reservation must remain owned until its workers are really joined"]
#[derive(Debug)]
pub(crate) struct ExecutorReservation {
    marker: Arc<ExecutorBudgetMarker>,
    reservation_id: u64,
    managed_workers: u32,
    native_threads: u32,
    active: bool,
}

impl ExecutorReservation {
    #[must_use]
    pub(crate) const fn managed_workers(&self) -> u32 {
        self.managed_workers
    }

    #[must_use]
    pub(crate) const fn native_threads(&self) -> u32 {
        self.native_threads
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReservationRecord {
    managed_workers: u32,
    native_threads: u32,
}

/// Bounded planned inventory at one observation point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecutorBudgetSnapshot {
    maximum_threads: u32,
    framework_threads: u32,
    managed_workers: u32,
    native_threads: u32,
    active_reservations: u32,
}

impl ExecutorBudgetSnapshot {
    #[must_use]
    pub(crate) const fn maximum_threads(self) -> u32 {
        self.maximum_threads
    }

    #[must_use]
    pub(crate) const fn framework_threads(self) -> u32 {
        self.framework_threads
    }

    #[must_use]
    pub(crate) const fn managed_workers(self) -> u32 {
        self.managed_workers
    }

    #[must_use]
    pub(crate) const fn native_threads(self) -> u32 {
        self.native_threads
    }

    #[must_use]
    pub(crate) const fn active_reservations(self) -> u32 {
        self.active_reservations
    }

    #[must_use]
    pub(crate) const fn reserved_threads(self) -> u32 {
        self.framework_threads + self.managed_workers + self.native_threads
    }

    #[must_use]
    pub(crate) const fn available_threads(self) -> u32 {
        self.maximum_threads - self.reserved_threads()
    }
}

/// Injected observation owned by a target-specific census adapter.
///
/// S5 has no portable arbitrary-thread census. The local Harness supplies this
/// value from the Runtime-owned worker registry and trusted native-pool facts;
/// `unknown_threads` keeps that limitation fail-closed instead of silently
/// spending unused plan headroom.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadInventoryObservation {
    framework_threads: u32,
    managed_workers: u32,
    native_threads: u32,
    unknown_threads: u32,
}

impl ThreadInventoryObservation {
    #[must_use]
    pub(crate) const fn new(
        framework_threads: u32,
        managed_workers: u32,
        native_threads: u32,
        unknown_threads: u32,
    ) -> Self {
        Self {
            framework_threads,
            managed_workers,
            native_threads,
            unknown_threads,
        }
    }
}

/// Single RuntimeHost owner for all planned in-process thread reservations.
pub(crate) struct ExecutorBudget {
    marker: Arc<ExecutorBudgetMarker>,
    maximum_threads: u32,
    framework_threads: u32,
    managed_workers: u32,
    native_threads: u32,
    next_reservation_id: u64,
    active: BTreeMap<u64, ReservationRecord>,
}

impl ExecutorBudget {
    pub(crate) fn try_new(
        maximum_threads: u32,
        framework_threads: u32,
    ) -> Result<Self, ExecutorBudgetError> {
        if maximum_threads == 0 || framework_threads == 0 || framework_threads > maximum_threads {
            return Err(ExecutorBudgetError::InvalidPlan);
        }
        Ok(Self {
            marker: Arc::new(ExecutorBudgetMarker),
            maximum_threads,
            framework_threads,
            managed_workers: 0,
            native_threads: 0,
            next_reservation_id: 0,
            active: BTreeMap::new(),
        })
    }

    /// Reserves all managed and trusted-native capacity before worker creation.
    pub(crate) fn try_reserve(
        &mut self,
        managed_workers: u32,
        native_threads: u32,
    ) -> Result<ExecutorReservation, ExecutorBudgetError> {
        self.validate_state()?;
        if managed_workers == 0 {
            return Err(ExecutorBudgetError::InvalidReservation);
        }
        let new_managed = self
            .managed_workers
            .checked_add(managed_workers)
            .ok_or(ExecutorBudgetError::CounterOverflow)?;
        let new_native = self
            .native_threads
            .checked_add(native_threads)
            .ok_or(ExecutorBudgetError::CounterOverflow)?;
        let total = self
            .framework_threads
            .checked_add(new_managed)
            .and_then(|value| value.checked_add(new_native))
            .ok_or(ExecutorBudgetError::CounterOverflow)?;
        if total > self.maximum_threads {
            return Err(ExecutorBudgetError::CapacityExhausted);
        }
        let reservation_id = self
            .next_reservation_id
            .checked_add(1)
            .ok_or(ExecutorBudgetError::IdentifierExhausted)?;
        let record = ReservationRecord {
            managed_workers,
            native_threads,
        };
        if self.active.insert(reservation_id, record).is_some() {
            return Err(ExecutorBudgetError::StateInconsistent);
        }
        self.managed_workers = new_managed;
        self.native_threads = new_native;
        self.next_reservation_id = reservation_id;
        Ok(ExecutorReservation {
            marker: Arc::clone(&self.marker),
            reservation_id,
            managed_workers,
            native_threads,
            active: true,
        })
    }

    /// Returns plan capacity only after the ThreadDomain owner proves every
    /// started worker was joined and every native reservation was settled.
    pub(crate) fn release(
        &mut self,
        proof: &mut ThreadDomainJoinProof,
    ) -> Result<(), ExecutorBudgetError> {
        self.validate_state()?;
        let reservation = proof
            .reservation()
            .ok_or(ExecutorBudgetError::AlreadyReleased)?;
        if !reservation.active {
            return Err(ExecutorBudgetError::AlreadyReleased);
        }
        if !Arc::ptr_eq(&reservation.marker, &self.marker) {
            return Err(ExecutorBudgetError::OwnerMismatch);
        }
        let Some(record) = self.active.get(&reservation.reservation_id).copied() else {
            return Err(ExecutorBudgetError::ReservationMismatch);
        };
        if record.managed_workers != reservation.managed_workers
            || record.native_threads != reservation.native_threads
        {
            return Err(ExecutorBudgetError::ReservationMismatch);
        }
        let managed_workers = usize::try_from(reservation.managed_workers)
            .map_err(|_| ExecutorBudgetError::ReservationMismatch)?;
        if proof.started_workers() != proof.joined_workers()
            || proof.started_workers() > managed_workers
            || (proof.kind() == ThreadDomainJoinKind::CompleteShutdown
                && proof.started_workers() != managed_workers)
            || (reservation.native_threads != 0 && !proof.native_threads_released())
        {
            return Err(ExecutorBudgetError::JoinProofMismatch);
        }
        let new_managed = self
            .managed_workers
            .checked_sub(record.managed_workers)
            .ok_or(ExecutorBudgetError::StateInconsistent)?;
        let new_native = self
            .native_threads
            .checked_sub(record.native_threads)
            .ok_or(ExecutorBudgetError::StateInconsistent)?;
        self.active.remove(&reservation.reservation_id);
        self.managed_workers = new_managed;
        self.native_threads = new_native;
        proof.mark_released();
        self.validate_state()
    }

    pub(crate) fn snapshot(&self) -> Result<ExecutorBudgetSnapshot, ExecutorBudgetError> {
        self.validate_state()?;
        let active_reservations =
            u32::try_from(self.active.len()).map_err(|_| ExecutorBudgetError::StateInconsistent)?;
        Ok(ExecutorBudgetSnapshot {
            maximum_threads: self.maximum_threads,
            framework_threads: self.framework_threads,
            managed_workers: self.managed_workers,
            native_threads: self.native_threads,
            active_reservations,
        })
    }

    /// Compares planned ownership with an injected observed inventory.
    pub(crate) fn evaluate_observation(
        &self,
        observation: ThreadInventoryObservation,
    ) -> Result<(), ThreadInventoryMismatch> {
        let planned = self
            .snapshot()
            .map_err(|_| ThreadInventoryMismatch::BudgetStateInvalid)?;
        let observed_total = observation
            .framework_threads
            .checked_add(observation.managed_workers)
            .and_then(|value| value.checked_add(observation.native_threads))
            .and_then(|value| value.checked_add(observation.unknown_threads))
            .ok_or(ThreadInventoryMismatch::ObservedCounterOverflow)?;
        if observed_total > planned.maximum_threads() {
            return Err(ThreadInventoryMismatch::ObservedTotalExceeded);
        }
        if observation.framework_threads != planned.framework_threads() {
            return Err(ThreadInventoryMismatch::FrameworkMismatch);
        }
        if observation.managed_workers != planned.managed_workers() {
            return Err(ThreadInventoryMismatch::ManagedWorkerMismatch);
        }
        if observation.native_threads > planned.native_threads() {
            return Err(ThreadInventoryMismatch::NativeReservationExceeded);
        }
        if observation.unknown_threads != 0 {
            return Err(ThreadInventoryMismatch::UnknownThreadsObserved);
        }
        Ok(())
    }

    fn validate_state(&self) -> Result<(), ExecutorBudgetError> {
        if self.maximum_threads == 0
            || self.framework_threads == 0
            || self.framework_threads > self.maximum_threads
        {
            return Err(ExecutorBudgetError::StateInconsistent);
        }
        let recomputed_managed = self.active.values().try_fold(0_u32, |total, record| {
            total.checked_add(record.managed_workers)
        });
        let recomputed_native = self.active.values().try_fold(0_u32, |total, record| {
            total.checked_add(record.native_threads)
        });
        if recomputed_managed != Some(self.managed_workers)
            || recomputed_native != Some(self.native_threads)
        {
            return Err(ExecutorBudgetError::StateInconsistent);
        }
        let total = self
            .framework_threads
            .checked_add(self.managed_workers)
            .and_then(|value| value.checked_add(self.native_threads))
            .ok_or(ExecutorBudgetError::StateInconsistent)?;
        if total > self.maximum_threads {
            return Err(ExecutorBudgetError::StateInconsistent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutorBudgetError {
    InvalidPlan,
    InvalidReservation,
    CapacityExhausted,
    CounterOverflow,
    IdentifierExhausted,
    AlreadyReleased,
    OwnerMismatch,
    ReservationMismatch,
    JoinProofMismatch,
    StateInconsistent,
}

impl fmt::Display for ExecutorBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPlan => "executor budget plan is invalid",
            Self::InvalidReservation => "executor reservation is invalid",
            Self::CapacityExhausted => "RuntimeHost executor budget is exhausted",
            Self::CounterOverflow => "executor reservation counter overflowed",
            Self::IdentifierExhausted => "executor reservation identity exhausted",
            Self::AlreadyReleased => "executor reservation was already released",
            Self::OwnerMismatch => "executor reservation belongs to another RuntimeHost budget",
            Self::ReservationMismatch => "executor reservation does not match active state",
            Self::JoinProofMismatch => "ThreadDomain join proof does not settle the reservation",
            Self::StateInconsistent => "executor budget state is inconsistent",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ExecutorBudgetError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadInventoryMismatch {
    BudgetStateInvalid,
    ObservedCounterOverflow,
    ObservedTotalExceeded,
    FrameworkMismatch,
    ManagedWorkerMismatch,
    NativeReservationExceeded,
    UnknownThreadsObserved,
}

impl fmt::Display for ThreadInventoryMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BudgetStateInvalid => "planned executor budget state is invalid",
            Self::ObservedCounterOverflow => "observed thread inventory overflowed",
            Self::ObservedTotalExceeded => "observed thread total exceeds the RuntimeHost budget",
            Self::FrameworkMismatch => "observed framework threads differ from the plan",
            Self::ManagedWorkerMismatch => {
                "observed managed workers differ from the owner registry"
            }
            Self::NativeReservationExceeded => "observed native threads exceed their reservation",
            Self::UnknownThreadsObserved => "unowned threads were observed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ThreadInventoryMismatch {}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::time::Duration;

    use super::{
        ExecutorBudget, ExecutorBudgetError, ThreadInventoryMismatch, ThreadInventoryObservation,
    };
    use crate::card_instance::DomainEpoch;
    use crate::thread_domain::{ThreadDomain, ThreadDomainConfig, ThreadDomainJoinProof};

    fn joined_domain_proof(
        reservation: super::ExecutorReservation,
        workers: usize,
        epoch: u64,
    ) -> ThreadDomainJoinProof {
        let domain_epoch = DomainEpoch::try_new(epoch).expect("test epoch");
        let config =
            ThreadDomainConfig::try_new(workers, Duration::from_secs(1)).expect("test config");
        let mut domain = ThreadDomain::<()>::try_new(domain_epoch, config, reservation)
            .unwrap_or_else(|failure| panic!("test domain build failed: {}", failure.error()));
        assert!(domain.shutdown_for(Duration::from_secs(1)).complete());
        domain.take_join_proof().expect("joined proof")
    }

    #[test]
    fn global_budget_cannot_be_oversold_across_domain_reservations() {
        let Ok(mut budget) = ExecutorBudget::try_new(5, 1) else {
            panic!("test budget must be valid");
        };
        let Ok(first) = budget.try_reserve(2, 0) else {
            panic!("first domain must fit");
        };
        assert_eq!(
            budget.try_reserve(3, 0).err(),
            Some(ExecutorBudgetError::CapacityExhausted)
        );
        let snapshot = budget.snapshot().expect("valid snapshot");
        assert_eq!(snapshot.reserved_threads(), 3);
        assert_eq!(snapshot.available_threads(), 2);
        assert_eq!(snapshot.active_reservations(), 1);

        let mut proof = joined_domain_proof(first, 2, 1);
        budget
            .release(&mut proof)
            .expect("real join releases lease");
        let second = budget.try_reserve(2, 0).expect("released plan must fit");
        let mut second_proof = joined_domain_proof(second, 2, 2);
        budget
            .release(&mut second_proof)
            .expect("replacement domain must settle");
    }

    #[test]
    fn failed_capacity_never_constructs_the_worker_owner() {
        let Ok(mut budget) = ExecutorBudget::try_new(2, 1) else {
            panic!("test budget must be valid");
        };
        let constructed = Cell::new(0_u32);
        let result = budget.try_reserve(2, 0).inspect(|_reservation| {
            constructed.set(constructed.get() + 1);
        });
        assert!(matches!(
            result,
            Err(ExecutorBudgetError::CapacityExhausted)
        ));
        assert_eq!(constructed.get(), 0);
        assert_eq!(
            budget.snapshot().expect("snapshot").active_reservations(),
            0
        );
    }

    #[test]
    fn failed_domain_construction_returns_join_proof_for_budget_rollback() {
        let Ok(mut budget) = ExecutorBudget::try_new(6, 1) else {
            panic!("test budget must be valid");
        };
        let reservation = budget.try_reserve(2, 0).expect("reservation");
        let epoch = DomainEpoch::try_new(7).expect("epoch");
        let config = ThreadDomainConfig::try_new(1, Duration::from_secs(1)).expect("config");
        let failure = ThreadDomain::<()>::try_new(epoch, config, reservation)
            .err()
            .expect("worker mismatch must reject");
        let mut proof = failure.into_join_proof();
        budget.release(&mut proof).expect("rollback proof");
        let snapshot = budget.snapshot().expect("snapshot");
        assert_eq!(snapshot.managed_workers(), 0);
        assert_eq!(snapshot.native_threads(), 0);
        assert_eq!(snapshot.active_reservations(), 0);
    }

    #[test]
    fn foreign_and_double_release_fail_closed() {
        let Ok(mut first_budget) = ExecutorBudget::try_new(3, 1) else {
            panic!("test budget must be valid");
        };
        let Ok(mut second_budget) = ExecutorBudget::try_new(3, 1) else {
            panic!("test budget must be valid");
        };
        let reservation = first_budget.try_reserve(1, 0).expect("reservation");
        let mut proof = joined_domain_proof(reservation, 1, 8);
        assert_eq!(
            second_budget.release(&mut proof),
            Err(ExecutorBudgetError::OwnerMismatch)
        );
        first_budget.release(&mut proof).expect("matching release");
        assert_eq!(
            first_budget.release(&mut proof),
            Err(ExecutorBudgetError::AlreadyReleased)
        );
    }

    #[test]
    fn observed_inventory_is_exact_for_owned_workers_and_fail_closed_for_unknowns() {
        let Ok(mut budget) = ExecutorBudget::try_new(8, 1) else {
            panic!("test budget must be valid");
        };
        let _reservation = budget.try_reserve(2, 3).expect("reservation");
        assert_eq!(
            budget.evaluate_observation(ThreadInventoryObservation::new(1, 2, 2, 0)),
            Ok(())
        );
        assert_eq!(
            budget.evaluate_observation(ThreadInventoryObservation::new(1, 1, 2, 0)),
            Err(ThreadInventoryMismatch::ManagedWorkerMismatch)
        );
        assert_eq!(
            budget.evaluate_observation(ThreadInventoryObservation::new(1, 2, 4, 0)),
            Err(ThreadInventoryMismatch::NativeReservationExceeded)
        );
        assert_eq!(
            budget.evaluate_observation(ThreadInventoryObservation::new(1, 2, 2, 1)),
            Err(ThreadInventoryMismatch::UnknownThreadsObserved)
        );
    }

    #[test]
    fn zero_overflow_and_total_observation_fail_closed() {
        assert!(matches!(
            ExecutorBudget::try_new(0, 0),
            Err(ExecutorBudgetError::InvalidPlan)
        ));
        let Ok(mut budget) = ExecutorBudget::try_new(u32::MAX, 1) else {
            panic!("maximum fixed-width budget must be valid");
        };
        let _reservation = budget
            .try_reserve(u32::MAX - 1, 0)
            .expect("exact maximum must fit");
        assert_eq!(
            budget.evaluate_observation(ThreadInventoryObservation::new(u32::MAX, u32::MAX, 0, 0,)),
            Err(ThreadInventoryMismatch::ObservedCounterOverflow)
        );
    }
}
