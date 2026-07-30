//! Pure values for owner-local monotonic deadlines.
//!
//! This module does not read a clock or wait for time to pass. A clock owner
//! supplies [`ClockReading`] values, and deadlines remain comparable only while
//! their clock domain and generation match.

use core::{fmt, num::NonZeroU64};

/// Identifies one monotonic clock domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClockDomainRef([u8; 16]);

impl ClockDomainRef {
    /// Creates an opaque clock-domain reference from its canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical clock-domain bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Identifies one nonzero generation of a monotonic clock domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClockGeneration(NonZeroU64);

impl ClockGeneration {
    /// Creates a clock generation, rejecting the reserved zero value.
    pub const fn try_new(value: u64) -> Result<Self, TimeError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(TimeError::InvalidClockGeneration),
        }
    }

    /// Returns the nonzero generation value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

/// A bounded duration represented as a nonnegative number of nanoseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedDuration(u64);

impl BoundedDuration {
    /// Creates a duration from nanoseconds. Zero is a valid duration.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Returns the duration in nanoseconds.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// An instant in an owner-local monotonic clock's nanosecond tick domain.
///
/// The numeric value alone carries no cross-domain or cross-generation
/// ordering. Use [`MonotonicDeadline`] with a matching [`ClockReading`] for
/// deadline decisions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MonotonicInstant(u64);

impl MonotonicInstant {
    /// Creates an instant from its owner-local tick value.
    #[must_use]
    pub const fn from_ticks(ticks: u64) -> Self {
        Self(ticks)
    }

    /// Returns the owner-local tick value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// A monotonic-clock reading bound to its domain and generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ClockReading {
    domain: ClockDomainRef,
    generation: ClockGeneration,
    now: MonotonicInstant,
}

impl ClockReading {
    /// Creates a reading supplied by the owner of a monotonic clock.
    #[must_use]
    pub const fn new(
        domain: ClockDomainRef,
        generation: ClockGeneration,
        now: MonotonicInstant,
    ) -> Self {
        Self {
            domain,
            generation,
            now,
        }
    }

    /// Returns the clock domain.
    #[must_use]
    pub const fn domain(self) -> ClockDomainRef {
        self.domain
    }

    /// Returns the clock generation.
    #[must_use]
    pub const fn generation(self) -> ClockGeneration {
        self.generation
    }

    /// Returns the sampled monotonic instant.
    #[must_use]
    pub const fn now(self) -> MonotonicInstant {
        self.now
    }

    /// Installs a bounded duration as a deadline in this local reading's domain.
    ///
    /// Arithmetic overflow is rejected instead of wrapping into a revived or
    /// prematurely expired deadline.
    pub fn try_deadline_after(
        self,
        duration: BoundedDuration,
    ) -> Result<MonotonicDeadline, TimeError> {
        let Some(deadline) = self.now.value().checked_add(duration.value()) else {
            return Err(TimeError::DeadlineOverflow);
        };

        Ok(MonotonicDeadline {
            domain: self.domain,
            generation: self.generation,
            deadline: MonotonicInstant::from_ticks(deadline),
        })
    }
}

/// An owner-local monotonic deadline bound to one clock generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MonotonicDeadline {
    domain: ClockDomainRef,
    generation: ClockGeneration,
    deadline: MonotonicInstant,
}

impl MonotonicDeadline {
    /// Returns the clock domain in which the deadline was installed.
    #[must_use]
    pub const fn domain(self) -> ClockDomainRef {
        self.domain
    }

    /// Returns the clock generation in which the deadline was installed.
    #[must_use]
    pub const fn generation(self) -> ClockGeneration {
        self.generation
    }

    /// Returns the owner-local deadline instant.
    #[must_use]
    pub const fn deadline(self) -> MonotonicInstant {
        self.deadline
    }

    /// Returns the remaining duration at a compatible local clock reading.
    ///
    /// A reading at or after the deadline returns zero. Domain or generation
    /// mismatches are rejected before any numeric comparison is performed.
    pub fn remaining_at(self, reading: ClockReading) -> Result<BoundedDuration, TimeError> {
        self.ensure_compatible(reading)?;
        Ok(BoundedDuration::from_nanos(
            self.deadline.value().saturating_sub(reading.now.value()),
        ))
    }

    /// Reports whether a compatible local clock reading reached the deadline.
    ///
    /// Domain or generation mismatches are rejected before any numeric
    /// comparison is performed.
    pub fn is_expired_at(self, reading: ClockReading) -> Result<bool, TimeError> {
        self.ensure_compatible(reading)?;
        Ok(reading.now.value() >= self.deadline.value())
    }

    fn ensure_compatible(self, reading: ClockReading) -> Result<(), TimeError> {
        if reading.domain != self.domain {
            return Err(TimeError::ClockDomainMismatch);
        }
        if reading.generation != self.generation {
            return Err(TimeError::ClockGenerationMismatch);
        }
        Ok(())
    }
}

/// Stable failures raised while constructing or evaluating monotonic deadlines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeError {
    /// Clock generation zero is reserved and cannot identify a live baseline.
    InvalidClockGeneration,
    /// Adding a duration to the sampled instant exceeded the representable range.
    DeadlineOverflow,
    /// The reading and deadline belong to different clock domains.
    ClockDomainMismatch,
    /// The reading and deadline belong to different generations.
    ClockGenerationMismatch,
}

impl fmt::Display for TimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClockGeneration => formatter.write_str("clock generation must be nonzero"),
            Self::DeadlineOverflow => formatter.write_str("monotonic deadline overflow"),
            Self::ClockDomainMismatch => formatter.write_str("clock domain mismatch"),
            Self::ClockGenerationMismatch => formatter.write_str("clock generation mismatch"),
        }
    }
}

impl std::error::Error for TimeError {}

#[cfg(test)]
mod tests {
    use super::{
        BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant, TimeError,
    };

    fn generation(value: u64) -> ClockGeneration {
        let Ok(generation) = ClockGeneration::try_new(value) else {
            panic!("test generation must be nonzero");
        };
        generation
    }

    fn reading(domain: u8, generation_value: u64, now: u64) -> ClockReading {
        ClockReading::new(
            ClockDomainRef::from_bytes([domain; 16]),
            generation(generation_value),
            MonotonicInstant::from_ticks(now),
        )
    }

    #[test]
    fn clock_generation_rejects_zero() {
        assert_eq!(
            ClockGeneration::try_new(0),
            Err(TimeError::InvalidClockGeneration)
        );
        assert_eq!(generation(7).value(), 7);
    }

    #[test]
    fn zero_duration_is_immediately_expired() {
        let now = reading(1, 1, 50);
        let Ok(deadline) = now.try_deadline_after(BoundedDuration::from_nanos(0)) else {
            panic!("zero duration must be representable");
        };

        assert_eq!(deadline.deadline().value(), 50);
        assert_eq!(
            deadline.remaining_at(now),
            Ok(BoundedDuration::from_nanos(0))
        );
        assert_eq!(deadline.is_expired_at(now), Ok(true));
    }

    #[test]
    fn deadline_installation_rejects_overflow() {
        let now = reading(1, 1, u64::MAX);

        assert_eq!(
            now.try_deadline_after(BoundedDuration::from_nanos(1)),
            Err(TimeError::DeadlineOverflow)
        );
    }

    #[test]
    fn deadline_rejects_domain_mismatch() {
        let Ok(deadline) = reading(1, 1, 10).try_deadline_after(BoundedDuration::from_nanos(5))
        else {
            panic!("test deadline must be representable");
        };
        let foreign_reading = reading(2, 1, 10);

        assert_eq!(
            deadline.remaining_at(foreign_reading),
            Err(TimeError::ClockDomainMismatch)
        );
        assert_eq!(
            deadline.is_expired_at(foreign_reading),
            Err(TimeError::ClockDomainMismatch)
        );
    }

    #[test]
    fn deadline_rejects_generation_mismatch() {
        let Ok(deadline) = reading(1, 1, 10).try_deadline_after(BoundedDuration::from_nanos(5))
        else {
            panic!("test deadline must be representable");
        };
        let restarted_reading = reading(1, 2, 10);

        assert_eq!(
            deadline.remaining_at(restarted_reading),
            Err(TimeError::ClockGenerationMismatch)
        );
        assert_eq!(
            deadline.is_expired_at(restarted_reading),
            Err(TimeError::ClockGenerationMismatch)
        );
    }

    #[test]
    fn remaining_counts_down_and_clamps_at_zero() {
        let Ok(deadline) = reading(1, 1, 100).try_deadline_after(BoundedDuration::from_nanos(50))
        else {
            panic!("test deadline must be representable");
        };

        assert_eq!(
            deadline.remaining_at(reading(1, 1, 120)),
            Ok(BoundedDuration::from_nanos(30))
        );
        assert_eq!(deadline.is_expired_at(reading(1, 1, 120)), Ok(false));
        assert_eq!(
            deadline.remaining_at(reading(1, 1, 150)),
            Ok(BoundedDuration::from_nanos(0))
        );
        assert_eq!(deadline.is_expired_at(reading(1, 1, 150)), Ok(true));
        assert_eq!(
            deadline.remaining_at(reading(1, 1, 151)),
            Ok(BoundedDuration::from_nanos(0))
        );
        assert_eq!(deadline.is_expired_at(reading(1, 1, 151)), Ok(true));
    }
}
