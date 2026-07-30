//! RuntimeHost-owned bridge from Tokio time to owner-local Kernel readings.

use core::fmt;

use paraegox_kernel::time::{
    BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicDeadline,
    MonotonicInstant, TimeError,
};
use tokio::time::Instant;

/// One reactor-local monotonic clock mapping.
///
/// The Tokio origin never crosses a contract boundary. Only the resulting
/// owner-local [`ClockReading`] is passed to Mailbox and admission mechanisms.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RuntimeClock {
    domain: ClockDomainRef,
    generation: ClockGeneration,
    origin: Instant,
    origin_ticks: u64,
}

impl RuntimeClock {
    /// Captures the current reactor instant as the origin of one clock generation.
    #[must_use]
    pub(crate) fn new(
        domain: ClockDomainRef,
        generation: ClockGeneration,
        origin_ticks: u64,
    ) -> Self {
        Self {
            domain,
            generation,
            origin: Instant::now(),
            origin_ticks,
        }
    }

    #[must_use]
    pub(crate) const fn domain(self) -> ClockDomainRef {
        self.domain
    }

    #[must_use]
    pub(crate) const fn generation(self) -> ClockGeneration {
        self.generation
    }

    /// Samples the reactor clock with checked nanosecond conversion.
    pub(crate) fn reading(self) -> Result<ClockReading, RuntimeClockError> {
        let elapsed = Instant::now().saturating_duration_since(self.origin);
        let elapsed_nanos =
            u64::try_from(elapsed.as_nanos()).map_err(|_| RuntimeClockError::ElapsedOutOfRange)?;
        let ticks = self
            .origin_ticks
            .checked_add(elapsed_nanos)
            .ok_or(RuntimeClockError::TickOverflow)?;
        Ok(ClockReading::new(
            self.domain,
            self.generation,
            MonotonicInstant::from_ticks(ticks),
        ))
    }

    /// Installs a target-local deadline from the same sampled owner clock.
    pub(crate) fn deadline_after(
        self,
        duration: BoundedDuration,
    ) -> Result<MonotonicDeadline, RuntimeClockError> {
        self.reading()?
            .try_deadline_after(duration)
            .map_err(RuntimeClockError::Time)
    }
}

/// Fail-closed failures while mapping the private reactor clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeClockError {
    ElapsedOutOfRange,
    TickOverflow,
    Time(TimeError),
}

impl fmt::Display for RuntimeClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ElapsedOutOfRange => {
                formatter.write_str("reactor elapsed time exceeds u64 nanos")
            }
            Self::TickOverflow => formatter.write_str("runtime clock tick overflow"),
            Self::Time(error) => write!(formatter, "runtime clock deadline failed: {error}"),
        }
    }
}

impl std::error::Error for RuntimeClockError {}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};

    use super::RuntimeClock;

    fn generation(value: u64) -> ClockGeneration {
        let Ok(generation) = ClockGeneration::try_new(value) else {
            panic!("fixture generation must be nonzero");
        };
        generation
    }

    #[tokio::test(start_paused = true)]
    async fn paused_reactor_time_maps_to_one_owner_local_generation() {
        let clock = RuntimeClock::new(ClockDomainRef::from_bytes([0x41; 16]), generation(7), 11);
        let Ok(first) = clock.reading() else {
            panic!("initial reading must fit");
        };

        tokio::time::advance(Duration::from_nanos(23)).await;

        let Ok(second) = clock.reading() else {
            panic!("advanced reading must fit");
        };
        assert_eq!(first.domain(), clock.domain());
        assert_eq!(first.generation(), clock.generation());
        assert_eq!(first.now().value(), 11);
        assert_eq!(second.now().value(), 34);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_uses_the_same_domain_generation_and_ticks() {
        let clock = RuntimeClock::new(ClockDomainRef::from_bytes([0x42; 16]), generation(8), 100);
        let Ok(deadline) = clock.deadline_after(BoundedDuration::from_nanos(50)) else {
            panic!("bounded deadline must build");
        };

        assert_eq!(deadline.domain(), clock.domain());
        assert_eq!(deadline.generation(), clock.generation());
        assert_eq!(deadline.deadline().value(), 150);
    }
}
