//! Narrow contract for one Runtime-managed CoreService lifecycle.
//!
//! This successor deliberately does not reuse [`crate::assignment::InstanceRef`]:
//! a managed service has its own identity owner and runtime generation. The
//! contract only carries the lifecycle inputs consumed by the RuntimeHost-owned
//! assembly mechanism. It is not yet a `ServiceSpec`, dependency graph, wire
//! encoding, endpoint binding, or ProcessDomain launch contract.

use core::{fmt, num::NonZeroU64};

use paraegox_kernel::time::BoundedDuration;

/// Version of the first single managed-service lifecycle contract.
pub const MANAGED_SERVICE_CONTRACT_VERSION: u16 = 1;

/// Stable identity of one managed CoreService, independent of Card instances.
///
/// ```compile_fail
/// use paraegox_runtime_contracts::assignment::InstanceRef;
/// use paraegox_runtime_contracts::managed_service::ManagedServiceId;
///
/// fn select_service(_service: ManagedServiceId) {}
///
/// let card_instance = InstanceRef::from_bytes([7; 16]);
/// select_service(card_instance);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedServiceId([u8; 16]);

impl ManagedServiceId {
    /// Creates an opaque managed-service identity from its canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Nonzero RuntimeHost-owned incarnation of one managed service.
///
/// A generation is an observed runtime fence. It is not desired state and is
/// intentionally absent from [`ManagedServiceSpecV1`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManagedServiceGeneration(NonZeroU64);

impl ManagedServiceGeneration {
    /// Creates a generation, rejecting the reserved zero value.
    pub const fn try_new(value: u64) -> Result<Self, ManagedServiceContractError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(ManagedServiceContractError::InvalidGeneration),
        }
    }

    /// Returns the nonzero generation value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0.get()
    }

    /// Advances to the next generation without wrapping an exhausted fence.
    pub const fn try_successor(self) -> Result<Self, ManagedServiceContractError> {
        match self.value().checked_add(1) {
            Some(value) => Self::try_new(value),
            None => Err(ManagedServiceContractError::GenerationExhausted),
        }
    }
}

/// Lifecycle stages whose callbacks must each have a finite nonzero budget.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManagedServiceLifecycleStage {
    /// Validate resolved inputs and acquire reversible local resources.
    Prepare = 1,
    /// Start the implementation without claiming readiness.
    Start = 2,
    /// Produce the implementation-owned readiness observation.
    Readiness = 3,
    /// Stop accepting new work and drain admitted work.
    Drain = 4,
    /// Release all remaining implementation resources.
    Stop = 5,
}

/// Runtime-owned finite budgets for the five lifecycle callbacks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManagedServiceLifecycleBudgetsV1 {
    prepare: BoundedDuration,
    start: BoundedDuration,
    readiness: BoundedDuration,
    drain: BoundedDuration,
    stop: BoundedDuration,
}

impl ManagedServiceLifecycleBudgetsV1 {
    /// Builds lifecycle budgets, rejecting an unbounded-by-convention zero.
    pub const fn try_new(
        prepare: BoundedDuration,
        start: BoundedDuration,
        readiness: BoundedDuration,
        drain: BoundedDuration,
        stop: BoundedDuration,
    ) -> Result<Self, ManagedServiceContractError> {
        if prepare.value() == 0 {
            return Err(ManagedServiceContractError::ZeroLifecycleBudget(
                ManagedServiceLifecycleStage::Prepare,
            ));
        }
        if start.value() == 0 {
            return Err(ManagedServiceContractError::ZeroLifecycleBudget(
                ManagedServiceLifecycleStage::Start,
            ));
        }
        if readiness.value() == 0 {
            return Err(ManagedServiceContractError::ZeroLifecycleBudget(
                ManagedServiceLifecycleStage::Readiness,
            ));
        }
        if drain.value() == 0 {
            return Err(ManagedServiceContractError::ZeroLifecycleBudget(
                ManagedServiceLifecycleStage::Drain,
            ));
        }
        if stop.value() == 0 {
            return Err(ManagedServiceContractError::ZeroLifecycleBudget(
                ManagedServiceLifecycleStage::Stop,
            ));
        }
        Ok(Self {
            prepare,
            start,
            readiness,
            drain,
            stop,
        })
    }

    /// Returns the budget for a lifecycle stage.
    #[must_use]
    pub const fn for_stage(self, stage: ManagedServiceLifecycleStage) -> BoundedDuration {
        match stage {
            ManagedServiceLifecycleStage::Prepare => self.prepare,
            ManagedServiceLifecycleStage::Start => self.start,
            ManagedServiceLifecycleStage::Readiness => self.readiness,
            ManagedServiceLifecycleStage::Drain => self.drain,
            ManagedServiceLifecycleStage::Stop => self.stop,
        }
    }
}

/// Exact first-version input consumed by the managed-service assembly owner.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManagedServiceSpecV1 {
    service_id: ManagedServiceId,
    lifecycle_budgets: ManagedServiceLifecycleBudgetsV1,
}

impl ManagedServiceSpecV1 {
    /// Creates the exact single-service lifecycle input.
    #[must_use]
    pub const fn new(
        service_id: ManagedServiceId,
        lifecycle_budgets: ManagedServiceLifecycleBudgetsV1,
    ) -> Self {
        Self {
            service_id,
            lifecycle_budgets,
        }
    }

    /// Returns the fixed contract version represented by this type.
    #[must_use]
    pub const fn contract_version(self) -> u16 {
        MANAGED_SERVICE_CONTRACT_VERSION
    }

    /// Returns the independently owned service identity.
    #[must_use]
    pub const fn service_id(self) -> ManagedServiceId {
        self.service_id
    }

    /// Returns the finite Runtime-owned lifecycle budgets.
    #[must_use]
    pub const fn lifecycle_budgets(self) -> ManagedServiceLifecycleBudgetsV1 {
        self.lifecycle_budgets
    }
}

/// Stable construction failures for the managed-service contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedServiceContractError {
    /// Runtime generation zero is reserved.
    InvalidGeneration,
    /// A runtime generation cannot wrap and revive an old fence.
    GenerationExhausted,
    /// Every lifecycle callback needs a finite nonzero owner budget.
    ZeroLifecycleBudget(ManagedServiceLifecycleStage),
}

impl fmt::Display for ManagedServiceContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGeneration => {
                formatter.write_str("managed-service generation must be nonzero")
            }
            Self::GenerationExhausted => {
                formatter.write_str("managed-service generation is exhausted")
            }
            Self::ZeroLifecycleBudget(stage) => {
                write!(
                    formatter,
                    "managed-service {stage:?} budget must be nonzero"
                )
            }
        }
    }
}

impl std::error::Error for ManagedServiceContractError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::time::BoundedDuration;

    use super::{
        MANAGED_SERVICE_CONTRACT_VERSION, ManagedServiceContractError, ManagedServiceGeneration,
        ManagedServiceId, ManagedServiceLifecycleBudgetsV1, ManagedServiceLifecycleStage,
        ManagedServiceSpecV1,
    };

    fn duration(value: u64) -> BoundedDuration {
        BoundedDuration::from_nanos(value)
    }

    fn budgets() -> ManagedServiceLifecycleBudgetsV1 {
        ManagedServiceLifecycleBudgetsV1::try_new(
            duration(1),
            duration(2),
            duration(3),
            duration(4),
            duration(5),
        )
        .unwrap_or_else(|error| panic!("fixture budgets must be valid: {error}"))
    }

    #[test]
    fn spec_retains_independent_service_identity_and_exact_version() {
        let service_id = ManagedServiceId::from_bytes([0x51; 16]);
        let spec = ManagedServiceSpecV1::new(service_id, budgets());

        assert_eq!(spec.contract_version(), MANAGED_SERVICE_CONTRACT_VERSION);
        assert_eq!(spec.service_id(), service_id);
        assert_eq!(spec.service_id().as_bytes(), &[0x51; 16]);
        assert_eq!(
            spec.lifecycle_budgets()
                .for_stage(ManagedServiceLifecycleStage::Readiness)
                .value(),
            3
        );
    }

    #[test]
    fn generation_is_nonzero_monotonic_and_never_wraps() {
        assert_eq!(
            ManagedServiceGeneration::try_new(0),
            Err(ManagedServiceContractError::InvalidGeneration)
        );
        let generation = ManagedServiceGeneration::try_new(7)
            .unwrap_or_else(|error| panic!("fixture generation must be valid: {error}"));
        assert_eq!(generation.value(), 7);
        assert_eq!(
            generation
                .try_successor()
                .unwrap_or_else(|error| panic!("successor must fit: {error}"))
                .value(),
            8
        );
        let exhausted = ManagedServiceGeneration::try_new(u64::MAX)
            .unwrap_or_else(|error| panic!("maximum nonzero generation must construct: {error}"));
        assert_eq!(
            exhausted.try_successor(),
            Err(ManagedServiceContractError::GenerationExhausted)
        );
    }

    #[test]
    fn every_zero_lifecycle_budget_is_rejected_at_its_stage() {
        let nonzero = duration(1);
        for (zero_index, expected_stage) in [
            ManagedServiceLifecycleStage::Prepare,
            ManagedServiceLifecycleStage::Start,
            ManagedServiceLifecycleStage::Readiness,
            ManagedServiceLifecycleStage::Drain,
            ManagedServiceLifecycleStage::Stop,
        ]
        .into_iter()
        .enumerate()
        {
            let mut values = [nonzero; 5];
            values[zero_index] = duration(0);
            assert_eq!(
                ManagedServiceLifecycleBudgetsV1::try_new(
                    values[0], values[1], values[2], values[3], values[4],
                ),
                Err(ManagedServiceContractError::ZeroLifecycleBudget(
                    expected_stage
                ))
            );
        }
    }
}
