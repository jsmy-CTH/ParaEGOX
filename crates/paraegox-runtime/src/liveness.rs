//! Strict owner-local liveness observations for one ProcessDomain generation.
//!
//! Liveness is deliberately separate from health and deployment readiness. A
//! valid startup acknowledgement only moves this diagnostic state into live
//! heartbeat monitoring; it cannot make an instance or RuntimeHost Ready.

use core::fmt;

use paraegox_kernel::time::{
    BoundedDuration, ClockReading, MonotonicDeadline, MonotonicInstant, TimeError,
};
use paraegox_runtime_contracts::process_execution::ProcessLifecycleBudgets;

use crate::runtime_ownership::ProcessGenerationIdentity;

/// Process-generation liveness as observed by its RuntimeHost owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LivenessPhase {
    Bootstrapping,
    Live,
    Unresponsive,
    Exited,
    Quarantined,
}

/// One liveness deadline that became false for the current generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LivenessFailure {
    StartupTimedOut,
    HeartbeatMissed { last_heartbeat_sequence: u64 },
    ControlResponseMissed { probe: u64 },
}

/// Result of a current-generation worker frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LivenessFrameDisposition {
    Advanced,
    Duplicate,
}

/// Absolute heartbeat deadline plus its remaining owner-local wait budget.
///
/// The absolute value stays bound to the same clock domain and generation as
/// the heartbeat observation from which it was derived. Re-reading this value
/// after a duplicate frame cannot extend either field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeartbeatDeadline {
    deadline: MonotonicDeadline,
    remaining: BoundedDuration,
}

impl HeartbeatDeadline {
    #[must_use]
    pub(crate) const fn deadline(self) -> MonotonicDeadline {
        self.deadline
    }

    #[must_use]
    pub(crate) const fn remaining(self) -> BoundedDuration {
        self.remaining
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutstandingProbe {
    id: u64,
    sent_at: ClockReading,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompletedProbe {
    id: u64,
    worker_sequence: u64,
}

/// Bounded liveness state for one exact ProcessDomain generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessLivenessState {
    identity: ProcessGenerationIdentity,
    budgets: ProcessLifecycleBudgets,
    phase: LivenessPhase,
    started_at: ClockReading,
    last_observed_at: ClockReading,
    last_worker_sequence: u64,
    last_heartbeat_sequence: u64,
    last_heartbeat_at: Option<ClockReading>,
    outstanding_probe: Option<OutstandingProbe>,
    last_control_response: Option<CompletedProbe>,
    last_probe_id: u64,
}

impl ProcessLivenessState {
    pub(crate) fn try_new(
        identity: ProcessGenerationIdentity,
        budgets: ProcessLifecycleBudgets,
        observed_at: ClockReading,
    ) -> Result<Self, LivenessError> {
        // The signed constructor already validates finite budgets. Compute the
        // first deadline now so a clock near u64::MAX cannot create a state
        // whose startup timeout is impossible to evaluate.
        deadline(observed_at, budgets.start())?;
        Ok(Self {
            identity,
            budgets,
            phase: LivenessPhase::Bootstrapping,
            started_at: observed_at,
            last_observed_at: observed_at,
            last_worker_sequence: 0,
            last_heartbeat_sequence: 0,
            last_heartbeat_at: None,
            outstanding_probe: None,
            last_control_response: None,
            last_probe_id: 0,
        })
    }

    #[must_use]
    pub(crate) const fn identity(self) -> ProcessGenerationIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn phase(self) -> LivenessPhase {
        self.phase
    }

    #[must_use]
    pub(crate) const fn last_heartbeat_sequence(self) -> u64 {
        self.last_heartbeat_sequence
    }

    #[must_use]
    pub(crate) const fn outstanding_probe(self) -> Option<u64> {
        match self.outstanding_probe {
            Some(probe) => Some(probe.id),
            None => None,
        }
    }

    /// Returns the current absolute heartbeat deadline and the remaining wait
    /// at a compatible owner-local clock reading. This is a read-only query:
    /// only a strictly newer valid heartbeat can move the absolute deadline.
    pub(crate) fn heartbeat_deadline(
        &self,
        identity: ProcessGenerationIdentity,
        observed_at: ClockReading,
    ) -> Result<HeartbeatDeadline, LivenessError> {
        self.validate_identity_and_time(identity, observed_at)?;
        if self.phase != LivenessPhase::Live {
            return Err(LivenessError::TerminalState);
        }
        let heartbeat_at = self
            .last_heartbeat_at
            .ok_or(LivenessError::StateInconsistent)?;
        let deadline = heartbeat_at
            .try_deadline_after(self.budgets.heartbeat_timeout())
            .map_err(map_time_error)?;
        let remaining = deadline.remaining_at(observed_at).map_err(map_time_error)?;
        Ok(HeartbeatDeadline {
            deadline,
            remaining,
        })
    }

    /// Accepts a successful `Constructed` frame as startup liveness evidence,
    /// not deployment readiness. The worker-frame sequence and the independent
    /// heartbeat-body sequence deliberately remain separate.
    pub(crate) fn observe_startup_ack(
        &mut self,
        identity: ProcessGenerationIdentity,
        worker_frame_sequence: u64,
        observed_at: ClockReading,
    ) -> Result<LivenessFrameDisposition, LivenessError> {
        self.validate_identity_and_time(identity, observed_at)?;
        if self.phase != LivenessPhase::Bootstrapping {
            return self.duplicate_or_terminal(worker_frame_sequence);
        }
        match compare_sequence(worker_frame_sequence, self.last_worker_sequence)? {
            LivenessFrameDisposition::Duplicate => Ok(LivenessFrameDisposition::Duplicate),
            LivenessFrameDisposition::Advanced => {
                ensure_before(
                    observed_at,
                    deadline(self.started_at, self.budgets.start())?,
                )?;
                deadline(observed_at, self.budgets.heartbeat_timeout())?;
                self.phase = LivenessPhase::Live;
                self.last_worker_sequence = worker_frame_sequence;
                self.last_heartbeat_at = Some(observed_at);
                self.last_observed_at = observed_at;
                Ok(LivenessFrameDisposition::Advanced)
            }
        }
    }

    /// Advances heartbeat freshness only for an exact, strictly newer frame.
    pub(crate) fn observe_heartbeat(
        &mut self,
        identity: ProcessGenerationIdentity,
        worker_frame_sequence: u64,
        heartbeat_sequence: u64,
        observed_at: ClockReading,
    ) -> Result<LivenessFrameDisposition, LivenessError> {
        self.validate_identity_and_time(identity, observed_at)?;
        if self.phase != LivenessPhase::Live {
            return self.duplicate_or_terminal(worker_frame_sequence);
        }
        let heartbeat_at = self
            .last_heartbeat_at
            .ok_or(LivenessError::StateInconsistent)?;
        ensure_before(
            observed_at,
            deadline(heartbeat_at, self.budgets.heartbeat_timeout())?,
        )?;
        match compare_sequence(worker_frame_sequence, self.last_worker_sequence)? {
            LivenessFrameDisposition::Duplicate => {
                if heartbeat_sequence == self.last_heartbeat_sequence && heartbeat_sequence != 0 {
                    Ok(LivenessFrameDisposition::Duplicate)
                } else {
                    Err(LivenessError::StaleHeartbeatSequence)
                }
            }
            LivenessFrameDisposition::Advanced => {
                if heartbeat_sequence == 0 || heartbeat_sequence <= self.last_heartbeat_sequence {
                    return Err(LivenessError::StaleHeartbeatSequence);
                }
                deadline(observed_at, self.budgets.heartbeat_timeout())?;
                self.last_worker_sequence = worker_frame_sequence;
                self.last_heartbeat_sequence = heartbeat_sequence;
                self.last_heartbeat_at = Some(observed_at);
                self.last_observed_at = observed_at;
                Ok(LivenessFrameDisposition::Advanced)
            }
        }
    }

    /// Records one bounded control probe. Only one may be outstanding.
    pub(crate) fn begin_control_probe(
        &mut self,
        identity: ProcessGenerationIdentity,
        probe: u64,
        observed_at: ClockReading,
    ) -> Result<(), LivenessError> {
        self.validate_identity_and_time(identity, observed_at)?;
        if self.phase != LivenessPhase::Live {
            return Err(LivenessError::TerminalState);
        }
        if self.outstanding_probe.is_some() {
            return Err(LivenessError::ProbeAlreadyOutstanding);
        }
        if probe == 0 || probe <= self.last_probe_id {
            return Err(LivenessError::StaleProbe);
        }
        let heartbeat_at = self
            .last_heartbeat_at
            .ok_or(LivenessError::StateInconsistent)?;
        ensure_before(
            observed_at,
            deadline(heartbeat_at, self.budgets.heartbeat_timeout())?,
        )?;
        deadline(observed_at, self.budgets.control_response())?;
        self.outstanding_probe = Some(OutstandingProbe {
            id: probe,
            sent_at: observed_at,
        });
        self.last_probe_id = probe;
        self.last_observed_at = observed_at;
        Ok(())
    }

    /// Completes the exact outstanding probe without treating unrelated frames
    /// or old probe replies as proof of control responsiveness.
    pub(crate) fn observe_control_response(
        &mut self,
        identity: ProcessGenerationIdentity,
        worker_sequence: u64,
        probe: u64,
        observed_at: ClockReading,
    ) -> Result<LivenessFrameDisposition, LivenessError> {
        self.validate_identity_and_time(identity, observed_at)?;
        if self.last_control_response
            == Some(CompletedProbe {
                id: probe,
                worker_sequence,
            })
        {
            return Ok(LivenessFrameDisposition::Duplicate);
        }
        if self.phase != LivenessPhase::Live {
            return Err(LivenessError::TerminalState);
        }
        let Some(outstanding) = self.outstanding_probe else {
            return Err(LivenessError::NoProbeOutstanding);
        };
        if outstanding.id != probe {
            return Err(LivenessError::ProbeMismatch);
        }
        ensure_before(
            observed_at,
            deadline(outstanding.sent_at, self.budgets.control_response())?,
        )?;
        if worker_sequence == 0 || worker_sequence <= self.last_worker_sequence {
            return Err(LivenessError::StaleWorkerSequence);
        }
        self.last_worker_sequence = worker_sequence;
        self.outstanding_probe = None;
        self.last_control_response = Some(CompletedProbe {
            id: probe,
            worker_sequence,
        });
        self.last_observed_at = observed_at;
        Ok(LivenessFrameDisposition::Advanced)
    }

    /// Evaluates the earliest current liveness deadline exactly once.
    pub(crate) fn evaluate(
        &mut self,
        observed_at: ClockReading,
    ) -> Result<Option<LivenessFailure>, LivenessError> {
        validate_clock(self.last_observed_at, observed_at)?;
        if matches!(
            self.phase,
            LivenessPhase::Unresponsive | LivenessPhase::Exited | LivenessPhase::Quarantined
        ) {
            self.last_observed_at = observed_at;
            return Ok(None);
        }

        let failure = match self.phase {
            LivenessPhase::Bootstrapping => {
                if reached(
                    observed_at,
                    deadline(self.started_at, self.budgets.start())?,
                ) {
                    Some(LivenessFailure::StartupTimedOut)
                } else {
                    None
                }
            }
            LivenessPhase::Live => {
                let heartbeat_at = self
                    .last_heartbeat_at
                    .ok_or(LivenessError::StateInconsistent)?;
                let heartbeat_deadline = deadline(heartbeat_at, self.budgets.heartbeat_timeout())?;
                let probe_deadline = self
                    .outstanding_probe
                    .map(|probe| {
                        deadline(probe.sent_at, self.budgets.control_response())
                            .map(|value| (value, probe.id))
                    })
                    .transpose()?;
                match probe_deadline {
                    Some((probe_at, probe))
                        if reached(observed_at, probe_at)
                            && probe_at.value() <= heartbeat_deadline.value() =>
                    {
                        Some(LivenessFailure::ControlResponseMissed { probe })
                    }
                    _ if reached(observed_at, heartbeat_deadline) => {
                        Some(LivenessFailure::HeartbeatMissed {
                            last_heartbeat_sequence: self.last_heartbeat_sequence,
                        })
                    }
                    _ => None,
                }
            }
            LivenessPhase::Unresponsive | LivenessPhase::Exited | LivenessPhase::Quarantined => {
                None
            }
        };
        if failure.is_some() {
            self.phase = LivenessPhase::Unresponsive;
        }
        self.last_observed_at = observed_at;
        Ok(failure)
    }

    pub(crate) fn mark_exited(
        &mut self,
        identity: ProcessGenerationIdentity,
        observed_at: ClockReading,
    ) -> Result<(), LivenessError> {
        self.validate_identity_and_time(identity, observed_at)?;
        self.phase = LivenessPhase::Exited;
        self.outstanding_probe = None;
        self.last_observed_at = observed_at;
        Ok(())
    }

    pub(crate) fn mark_quarantined(
        &mut self,
        identity: ProcessGenerationIdentity,
        observed_at: ClockReading,
    ) -> Result<(), LivenessError> {
        self.validate_identity_and_time(identity, observed_at)?;
        self.phase = LivenessPhase::Quarantined;
        self.outstanding_probe = None;
        self.last_observed_at = observed_at;
        Ok(())
    }

    fn validate_identity_and_time(
        &self,
        identity: ProcessGenerationIdentity,
        observed_at: ClockReading,
    ) -> Result<(), LivenessError> {
        if identity != self.identity {
            return Err(LivenessError::GenerationMismatch);
        }
        validate_clock(self.last_observed_at, observed_at)
    }

    fn duplicate_or_terminal(
        &self,
        worker_sequence: u64,
    ) -> Result<LivenessFrameDisposition, LivenessError> {
        if worker_sequence == self.last_worker_sequence && worker_sequence != 0 {
            Ok(LivenessFrameDisposition::Duplicate)
        } else {
            Err(LivenessError::TerminalState)
        }
    }
}

fn compare_sequence(
    incoming: u64,
    current: u64,
) -> Result<LivenessFrameDisposition, LivenessError> {
    if incoming == 0 || incoming < current {
        return Err(LivenessError::StaleWorkerSequence);
    }
    if incoming == current {
        return Ok(LivenessFrameDisposition::Duplicate);
    }
    Ok(LivenessFrameDisposition::Advanced)
}

fn validate_clock(previous: ClockReading, current: ClockReading) -> Result<(), LivenessError> {
    if previous.domain() != current.domain() || previous.generation() != current.generation() {
        return Err(LivenessError::ClockMismatch);
    }
    if current.now().value() < previous.now().value() {
        return Err(LivenessError::ClockRegressed);
    }
    Ok(())
}

const fn map_time_error(error: TimeError) -> LivenessError {
    match error {
        TimeError::DeadlineOverflow => LivenessError::DeadlineOverflow,
        TimeError::ClockDomainMismatch | TimeError::ClockGenerationMismatch => {
            LivenessError::ClockMismatch
        }
        TimeError::InvalidClockGeneration => LivenessError::StateInconsistent,
    }
}

fn deadline(
    reading: ClockReading,
    budget: BoundedDuration,
) -> Result<MonotonicInstant, LivenessError> {
    reading
        .now()
        .value()
        .checked_add(budget.value())
        .map(MonotonicInstant::from_ticks)
        .ok_or(LivenessError::DeadlineOverflow)
}

fn ensure_before(reading: ClockReading, deadline: MonotonicInstant) -> Result<(), LivenessError> {
    if reached(reading, deadline) {
        Err(LivenessError::DeadlineElapsed)
    } else {
        Ok(())
    }
}

const fn reached(reading: ClockReading, at: MonotonicInstant) -> bool {
    reading.now().value() >= at.value()
}

/// Stable fail-closed errors for process liveness observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LivenessError {
    GenerationMismatch,
    ClockMismatch,
    ClockRegressed,
    DeadlineOverflow,
    DeadlineElapsed,
    StaleWorkerSequence,
    StaleHeartbeatSequence,
    StaleProbe,
    ProbeAlreadyOutstanding,
    NoProbeOutstanding,
    ProbeMismatch,
    TerminalState,
    StateInconsistent,
}

impl fmt::Display for LivenessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::GenerationMismatch => "liveness fact belongs to another process generation",
            Self::ClockMismatch => "liveness observation uses another clock domain or generation",
            Self::ClockRegressed => "liveness observation clock regressed",
            Self::DeadlineOverflow => "liveness deadline overflowed",
            Self::DeadlineElapsed => "liveness evidence arrived at or after its deadline",
            Self::StaleWorkerSequence => "worker liveness sequence is zero or stale",
            Self::StaleHeartbeatSequence => {
                "heartbeat body sequence is zero, stale, or conflicts with its worker frame"
            }
            Self::StaleProbe => "control probe identity is zero or stale",
            Self::ProbeAlreadyOutstanding => "a control probe is already outstanding",
            Self::NoProbeOutstanding => "no control probe is outstanding",
            Self::ProbeMismatch => "control response does not match the outstanding probe",
            Self::TerminalState => "liveness state no longer accepts worker progress",
            Self::StateInconsistent => "liveness state is internally inconsistent",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LivenessError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::{
        BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant,
    };
    use paraegox_runtime_contracts::process_execution::{
        ProcessDomainRef, ProcessLifecycleBudgets, ProcessLivenessBudgets, ProcessShutdownBudgets,
    };
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};

    use super::{
        LivenessError, LivenessFailure, LivenessFrameDisposition, LivenessPhase,
        ProcessLivenessState,
    };
    use crate::card_instance::{DomainEpoch, RuntimeHostEpoch};
    use crate::runtime_ownership::ProcessGenerationIdentity;

    fn host_epoch(value: u64) -> RuntimeHostEpoch {
        RuntimeHostEpoch::try_new(value).unwrap_or_else(|error| panic!("host epoch: {error}"))
    }

    fn domain_epoch(value: u64) -> DomainEpoch {
        DomainEpoch::try_new(value).unwrap_or_else(|error| panic!("domain epoch: {error}"))
    }

    fn identity(domain: u8) -> ProcessGenerationIdentity {
        ProcessGenerationIdentity::new(
            RuntimeHostId::from_bytes([1; 16]),
            host_epoch(2),
            SourcePlanRevision::new(3),
            TargetSliceDigest::new(Digest32::from_bytes([4; 32])),
            ProcessDomainRef::from_bytes([domain; 16]),
            domain_epoch(5),
        )
    }

    fn generation(value: u64) -> ClockGeneration {
        ClockGeneration::try_new(value).unwrap_or_else(|error| panic!("clock: {error}"))
    }

    fn reading(domain: u8, generation_value: u64, ticks: u64) -> ClockReading {
        ClockReading::new(
            ClockDomainRef::from_bytes([domain; 16]),
            generation(generation_value),
            MonotonicInstant::from_ticks(ticks),
        )
    }

    fn budgets() -> ProcessLifecycleBudgets {
        let liveness = ProcessLivenessBudgets::try_new(
            BoundedDuration::from_nanos(10),
            BoundedDuration::from_nanos(2),
            BoundedDuration::from_nanos(6),
            BoundedDuration::from_nanos(3),
        )
        .unwrap_or_else(|error| panic!("liveness budgets: {error}"));
        let shutdown = ProcessShutdownBudgets::try_new(
            BoundedDuration::from_nanos(8),
            BoundedDuration::from_nanos(4),
            BoundedDuration::from_nanos(4),
            BoundedDuration::from_nanos(4),
            BoundedDuration::from_nanos(5),
        )
        .unwrap_or_else(|error| panic!("shutdown budgets: {error}"));
        ProcessLifecycleBudgets::new(liveness, shutdown)
    }

    #[test]
    fn constructed_ack_and_first_heartbeat_use_independent_sequences() {
        let identity = identity(7);
        let mut state = ProcessLivenessState::try_new(identity, budgets(), reading(8, 1, 0))
            .unwrap_or_else(|error| panic!("state: {error}"));
        assert_eq!(state.phase(), LivenessPhase::Bootstrapping);
        assert_eq!(
            state.observe_startup_ack(identity, 2, reading(8, 1, 4)),
            Ok(LivenessFrameDisposition::Advanced)
        );
        assert_eq!(state.phase(), LivenessPhase::Live);
        assert_eq!(state.last_heartbeat_sequence(), 0);
        assert_eq!(
            state.observe_heartbeat(identity, 3, 1, reading(8, 1, 5)),
            Ok(LivenessFrameDisposition::Advanced)
        );
        assert_eq!(state.last_heartbeat_sequence(), 1);
    }

    #[test]
    fn duplicate_heartbeat_does_not_extend_freshness() {
        let identity = identity(7);
        let mut state = ProcessLivenessState::try_new(identity, budgets(), reading(8, 1, 0))
            .unwrap_or_else(|error| panic!("state: {error}"));
        state
            .observe_startup_ack(identity, 2, reading(8, 1, 1))
            .unwrap_or_else(|error| panic!("startup: {error}"));
        state
            .observe_heartbeat(identity, 3, 1, reading(8, 1, 2))
            .unwrap_or_else(|error| panic!("heartbeat: {error}"));
        let initial_deadline = state
            .heartbeat_deadline(identity, reading(8, 1, 2))
            .unwrap_or_else(|error| panic!("deadline: {error}"));
        assert_eq!(
            initial_deadline.deadline().domain(),
            reading(8, 1, 2).domain()
        );
        assert_eq!(
            initial_deadline.deadline().generation(),
            reading(8, 1, 2).generation()
        );
        assert_eq!(initial_deadline.deadline().deadline().value(), 8);
        assert_eq!(initial_deadline.remaining().value(), 6);
        assert_eq!(
            state.observe_heartbeat(identity, 3, 1, reading(8, 1, 7)),
            Ok(LivenessFrameDisposition::Duplicate)
        );
        let after_duplicate = state
            .heartbeat_deadline(identity, reading(8, 1, 7))
            .unwrap_or_else(|error| panic!("deadline after duplicate: {error}"));
        assert_eq!(
            after_duplicate.deadline().deadline(),
            initial_deadline.deadline().deadline()
        );
        assert_eq!(after_duplicate.remaining().value(), 1);
        assert_eq!(
            state.heartbeat_deadline(identity, reading(9, 1, 7)),
            Err(LivenessError::ClockMismatch)
        );
        let expired = state
            .heartbeat_deadline(identity, reading(8, 1, 8))
            .unwrap_or_else(|error| panic!("expired deadline: {error}"));
        assert_eq!(expired.remaining().value(), 0);
        assert_eq!(
            state.observe_heartbeat(identity, 3, 1, reading(8, 1, 8)),
            Err(LivenessError::DeadlineElapsed)
        );
        assert_eq!(
            state.evaluate(reading(8, 1, 8)),
            Ok(Some(LivenessFailure::HeartbeatMissed {
                last_heartbeat_sequence: 1
            }))
        );
        assert_eq!(state.phase(), LivenessPhase::Unresponsive);
        assert_eq!(state.evaluate(reading(8, 1, 20)), Ok(None));
    }

    #[test]
    fn stale_heartbeat_body_sequence_never_refreshes_freshness() {
        let identity = identity(7);
        let mut state = ProcessLivenessState::try_new(identity, budgets(), reading(8, 1, 0))
            .unwrap_or_else(|error| panic!("state: {error}"));
        state
            .observe_startup_ack(identity, 2, reading(8, 1, 1))
            .unwrap_or_else(|error| panic!("startup: {error}"));
        state
            .observe_heartbeat(identity, 3, 1, reading(8, 1, 2))
            .unwrap_or_else(|error| panic!("heartbeat: {error}"));

        assert_eq!(
            state.observe_heartbeat(identity, 4, 1, reading(8, 1, 5)),
            Err(LivenessError::StaleHeartbeatSequence)
        );
        assert_eq!(
            state.evaluate(reading(8, 1, 8)),
            Ok(Some(LivenessFailure::HeartbeatMissed {
                last_heartbeat_sequence: 1
            }))
        );
    }

    #[test]
    fn stale_generation_and_clock_mismatch_never_refresh_state() {
        let current = identity(7);
        let mut state = ProcessLivenessState::try_new(current, budgets(), reading(8, 1, 0))
            .unwrap_or_else(|error| panic!("state: {error}"));
        assert_eq!(
            state.observe_startup_ack(identity(9), 2, reading(8, 1, 1)),
            Err(LivenessError::GenerationMismatch)
        );
        assert_eq!(
            state.observe_startup_ack(current, 2, reading(9, 1, 1)),
            Err(LivenessError::ClockMismatch)
        );
        assert_eq!(
            state.evaluate(reading(8, 1, 10)),
            Ok(Some(LivenessFailure::StartupTimedOut))
        );
    }

    #[test]
    fn control_probe_deadline_wins_when_it_is_earlier() {
        let identity = identity(7);
        let mut state = ProcessLivenessState::try_new(identity, budgets(), reading(8, 1, 0))
            .unwrap_or_else(|error| panic!("state: {error}"));
        state
            .observe_startup_ack(identity, 2, reading(8, 1, 1))
            .unwrap_or_else(|error| panic!("startup: {error}"));
        state
            .begin_control_probe(identity, 9, reading(8, 1, 2))
            .unwrap_or_else(|error| panic!("probe: {error}"));
        assert_eq!(state.outstanding_probe(), Some(9));
        assert_eq!(
            state.evaluate(reading(8, 1, 5)),
            Ok(Some(LivenessFailure::ControlResponseMissed { probe: 9 }))
        );
    }

    #[test]
    fn only_the_exact_probe_response_advances_control_freshness() {
        let identity = identity(7);
        let mut state = ProcessLivenessState::try_new(identity, budgets(), reading(8, 1, 0))
            .unwrap_or_else(|error| panic!("state: {error}"));
        state
            .observe_startup_ack(identity, 2, reading(8, 1, 1))
            .unwrap_or_else(|error| panic!("startup: {error}"));
        state
            .begin_control_probe(identity, 2, reading(8, 1, 2))
            .unwrap_or_else(|error| panic!("probe: {error}"));
        assert_eq!(
            state.observe_control_response(identity, 2, 3, reading(8, 1, 3)),
            Err(LivenessError::ProbeMismatch)
        );
        assert_eq!(
            state.observe_control_response(identity, 2, 3, reading(8, 1, 3)),
            Err(LivenessError::ProbeMismatch)
        );
        assert_eq!(state.outstanding_probe(), Some(2));
        assert_eq!(
            state.observe_control_response(identity, 3, 2, reading(8, 1, 3)),
            Ok(LivenessFrameDisposition::Advanced)
        );
        assert_eq!(state.outstanding_probe(), None);
        assert_eq!(
            state.observe_control_response(identity, 3, 2, reading(8, 1, 4)),
            Ok(LivenessFrameDisposition::Duplicate)
        );
        assert_eq!(
            state.evaluate(reading(8, 1, 7)),
            Ok(Some(LivenessFailure::HeartbeatMissed {
                last_heartbeat_sequence: 0
            }))
        );
    }

    #[test]
    fn late_frames_cannot_resurrect_expired_liveness() {
        let identity = identity(7);
        let mut startup = ProcessLivenessState::try_new(identity, budgets(), reading(8, 1, 0))
            .unwrap_or_else(|error| panic!("state: {error}"));
        assert_eq!(
            startup.observe_startup_ack(identity, 2, reading(8, 1, 10)),
            Err(LivenessError::DeadlineElapsed)
        );
        assert_eq!(
            startup.evaluate(reading(8, 1, 10)),
            Ok(Some(LivenessFailure::StartupTimedOut))
        );

        let mut heartbeat = ProcessLivenessState::try_new(identity, budgets(), reading(8, 1, 0))
            .unwrap_or_else(|error| panic!("state: {error}"));
        heartbeat
            .observe_startup_ack(identity, 2, reading(8, 1, 1))
            .unwrap_or_else(|error| panic!("startup: {error}"));
        assert_eq!(
            heartbeat.observe_heartbeat(identity, 3, 1, reading(8, 1, 7)),
            Err(LivenessError::DeadlineElapsed)
        );
        assert_eq!(
            heartbeat.evaluate(reading(8, 1, 7)),
            Ok(Some(LivenessFailure::HeartbeatMissed {
                last_heartbeat_sequence: 0
            }))
        );

        let mut control = ProcessLivenessState::try_new(identity, budgets(), reading(8, 1, 0))
            .unwrap_or_else(|error| panic!("state: {error}"));
        control
            .observe_startup_ack(identity, 2, reading(8, 1, 1))
            .unwrap_or_else(|error| panic!("startup: {error}"));
        control
            .begin_control_probe(identity, 1, reading(8, 1, 2))
            .unwrap_or_else(|error| panic!("probe: {error}"));
        assert_eq!(
            control.observe_control_response(identity, 3, 1, reading(8, 1, 5)),
            Err(LivenessError::DeadlineElapsed)
        );
        assert_eq!(
            control.evaluate(reading(8, 1, 5)),
            Ok(Some(LivenessFailure::ControlResponseMissed { probe: 1 }))
        );
    }

    #[test]
    fn clock_regression_and_deadline_overflow_fail_closed() {
        let identity = identity(7);
        let mut state = ProcessLivenessState::try_new(identity, budgets(), reading(8, 1, 10))
            .unwrap_or_else(|error| panic!("state: {error}"));
        assert_eq!(
            state.evaluate(reading(8, 1, 9)),
            Err(LivenessError::ClockRegressed)
        );
        assert_eq!(
            ProcessLivenessState::try_new(identity, budgets(), reading(8, 1, u64::MAX - 5)),
            Err(LivenessError::DeadlineOverflow)
        );
    }
}
