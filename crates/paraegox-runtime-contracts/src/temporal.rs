//! Authenticated temporal constraints installed by a target Runtime ingress.

use core::fmt;
use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};

/// The only temporal-constraint version admitted by the B2 apply envelope.
pub const APPLY_TEMPORAL_CONSTRAINT_VERSION: u16 = 1;

/// Identifies one authenticated temporal constraint independently of an operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TemporalConstraintId([u8; 16]);

impl TemporalConstraintId {
    /// Creates an opaque temporal-constraint identity from canonical bytes.
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

/// A target-clock constraint whose remaining budget never exceeds its origin.
///
/// The value carries no producer monotonic timestamp. The target ingress compares
/// the clock domain and generation, rejects an expired zero remaining budget, and
/// installs the remaining duration against its own local monotonic reading.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ApplyTemporalConstraint {
    version: u16,
    constraint_id: TemporalConstraintId,
    target_clock_domain: ClockDomainRef,
    target_clock_generation: ClockGeneration,
    original_budget: BoundedDuration,
    remaining_budget: BoundedDuration,
}

impl ApplyTemporalConstraint {
    /// Creates a v1 constraint, preserving zero remaining budget for expiry admission.
    pub const fn try_new(
        constraint_id: TemporalConstraintId,
        target_clock_domain: ClockDomainRef,
        target_clock_generation: ClockGeneration,
        original_budget: BoundedDuration,
        remaining_budget: BoundedDuration,
    ) -> Result<Self, TemporalContractError> {
        Self::try_from_parts(
            APPLY_TEMPORAL_CONSTRAINT_VERSION,
            constraint_id,
            target_clock_domain,
            target_clock_generation,
            original_budget,
            remaining_budget,
        )
    }

    /// Reconstructs a versioned constraint after canonical wire decoding.
    pub const fn try_from_parts(
        version: u16,
        constraint_id: TemporalConstraintId,
        target_clock_domain: ClockDomainRef,
        target_clock_generation: ClockGeneration,
        original_budget: BoundedDuration,
        remaining_budget: BoundedDuration,
    ) -> Result<Self, TemporalContractError> {
        if version != APPLY_TEMPORAL_CONSTRAINT_VERSION {
            return Err(TemporalContractError::UnsupportedVersion);
        }
        if original_budget.value() == 0 {
            return Err(TemporalContractError::ZeroOriginalBudget);
        }
        if remaining_budget.value() > original_budget.value() {
            return Err(TemporalContractError::RemainingBudgetExceedsOriginal);
        }
        Ok(Self {
            version,
            constraint_id,
            target_clock_domain,
            target_clock_generation,
            original_budget,
            remaining_budget,
        })
    }

    /// Returns a forwarded copy with a budget no greater than the current remainder.
    pub const fn try_reduce_remaining(
        self,
        remaining_budget: BoundedDuration,
    ) -> Result<Self, TemporalContractError> {
        if remaining_budget.value() > self.remaining_budget.value() {
            return Err(TemporalContractError::RemainingBudgetExtended);
        }
        Self::try_from_parts(
            self.version,
            self.constraint_id,
            self.target_clock_domain,
            self.target_clock_generation,
            self.original_budget,
            remaining_budget,
        )
    }

    /// Returns the temporal contract version.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }

    /// Returns the temporal constraint identity.
    #[must_use]
    pub const fn constraint_id(self) -> TemporalConstraintId {
        self.constraint_id
    }

    /// Returns the target-local monotonic clock domain.
    #[must_use]
    pub const fn target_clock_domain(self) -> ClockDomainRef {
        self.target_clock_domain
    }

    /// Returns the target-local clock generation.
    #[must_use]
    pub const fn target_clock_generation(self) -> ClockGeneration {
        self.target_clock_generation
    }

    /// Returns the authenticated original budget.
    #[must_use]
    pub const fn original_budget(self) -> BoundedDuration {
        self.original_budget
    }

    /// Returns the authenticated remaining budget to install at target ingress.
    #[must_use]
    pub const fn remaining_budget(self) -> BoundedDuration {
        self.remaining_budget
    }
}

/// Stable construction failures for apply temporal constraints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalContractError {
    /// The temporal constraint version is not admitted by this implementation.
    UnsupportedVersion,
    /// The origin must issue a positive budget.
    ZeroOriginalBudget,
    /// A standalone constraint cannot carry more budget than its authenticated origin.
    RemainingBudgetExceedsOriginal,
    /// A forwarding step cannot increase the previously authenticated remainder.
    RemainingBudgetExtended,
}

impl fmt::Display for TemporalContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => formatter.write_str("unsupported temporal version"),
            Self::ZeroOriginalBudget => {
                formatter.write_str("temporal original budget must be positive")
            }
            Self::RemainingBudgetExceedsOriginal => {
                formatter.write_str("temporal remaining budget exceeds original budget")
            }
            Self::RemainingBudgetExtended => {
                formatter.write_str("forwarded temporal budget was extended")
            }
        }
    }
}

impl std::error::Error for TemporalContractError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};

    use super::{
        APPLY_TEMPORAL_CONSTRAINT_VERSION, ApplyTemporalConstraint, TemporalConstraintId,
        TemporalContractError,
    };

    fn generation(value: u64) -> ClockGeneration {
        let Ok(generation) = ClockGeneration::try_new(value) else {
            panic!("test generation must be valid");
        };
        generation
    }

    fn constraint(remaining: u64) -> Result<ApplyTemporalConstraint, TemporalContractError> {
        ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([1; 16]),
            ClockDomainRef::from_bytes([2; 16]),
            generation(3),
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(remaining),
        )
    }

    #[test]
    fn zero_remaining_is_representable_for_expiry_admission() {
        let Ok(value) = constraint(0) else {
            panic!("expired constraint must remain decodable");
        };

        assert_eq!(value.version(), APPLY_TEMPORAL_CONSTRAINT_VERSION);
        assert_eq!(value.constraint_id().as_bytes(), &[1; 16]);
        assert_eq!(value.target_clock_domain().as_bytes(), &[2; 16]);
        assert_eq!(value.target_clock_generation().value(), 3);
        assert_eq!(value.original_budget().value(), 100);
        assert_eq!(value.remaining_budget().value(), 0);
    }

    #[test]
    fn original_budget_must_be_positive() {
        assert_eq!(
            ApplyTemporalConstraint::try_new(
                TemporalConstraintId::from_bytes([1; 16]),
                ClockDomainRef::from_bytes([2; 16]),
                generation(3),
                BoundedDuration::from_nanos(0),
                BoundedDuration::from_nanos(0),
            ),
            Err(TemporalContractError::ZeroOriginalBudget)
        );
    }

    #[test]
    fn remaining_budget_cannot_exceed_origin_or_previous_hop() {
        assert_eq!(
            constraint(101),
            Err(TemporalContractError::RemainingBudgetExceedsOriginal)
        );

        let Ok(value) = constraint(60) else {
            panic!("test constraint must be valid");
        };
        assert_eq!(
            value.try_reduce_remaining(BoundedDuration::from_nanos(61)),
            Err(TemporalContractError::RemainingBudgetExtended)
        );
        let Ok(reduced) = value.try_reduce_remaining(BoundedDuration::from_nanos(40)) else {
            panic!("budget reduction must succeed");
        };
        assert_eq!(reduced.remaining_budget().value(), 40);
        assert_eq!(reduced.original_budget().value(), 100);
    }

    #[test]
    fn unsupported_version_is_rejected() {
        assert_eq!(
            ApplyTemporalConstraint::try_from_parts(
                2,
                TemporalConstraintId::from_bytes([1; 16]),
                ClockDomainRef::from_bytes([2; 16]),
                generation(3),
                BoundedDuration::from_nanos(100),
                BoundedDuration::from_nanos(50),
            ),
            Err(TemporalContractError::UnsupportedVersion)
        );
    }
}
