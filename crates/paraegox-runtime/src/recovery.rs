//! Deterministic ProcessDomain recovery decisions over typed Runtime facts.
//!
//! The engine is a pure reducer. It owns no PID, process handle, timer, task,
//! payload, receipt, or retry loop. A RuntimeHost-owned ProcessDomain applies
//! each returned action and feeds the exact action completion or cleanup fact
//! back into a new transition. The action vocabulary intentionally contains no
//! replay operation.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder};
use paraegox_kernel::time::{ClockReading, MonotonicInstant};
use paraegox_runtime_contracts::assignment::InstanceRef;
use paraegox_runtime_contracts::process_execution::{
    InvocationReplayPolicy, ProcessLifecycleBudgets, ProcessRestartPolicy, SideEffectClass,
};

use crate::card_instance::{DomainEpoch, InstanceGeneration, InvocationId};
use crate::runtime_ownership::{
    ProcessCleanupCensus, ProcessCleanupProof, ProcessGenerationIdentity, ProcessLossLineage,
    ProcessLossObservation,
};

const RECOVERY_FACT_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.failure-fact.sha256.internal.v1";
const RECOVERY_JITTER_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.restart-jitter.sha256.internal.v1";

/// Protocol faults are bounded facts rather than untrusted diagnostic strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessProtocolFailure {
    InvalidFrame,
    UnsupportedVersion,
    GenerationMismatch,
    SequenceViolation,
    CreditViolation,
    PayloadTooLarge,
}

/// Concrete signed process-resource ceiling exceeded by the owned tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessResourceFailure {
    Memory,
    OpenFds,
    ProcessTree,
    Cpu,
}

/// Internal owner invariant that failed independently of worker-controlled
/// protocol bytes. These facts are never restart-safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessOwnerInvariantFailure {
    GenerationMismatch,
    ClockMismatch,
    ClockRegressed,
    DeadlineOverflow,
    StateInconsistent,
}

/// Exact invocation whose progress or outcome became suspect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessInvocationFailure {
    instance: InstanceRef,
    generation: InstanceGeneration,
    invocation: InvocationId,
    side_effect: SideEffectClass,
}

impl ProcessInvocationFailure {
    #[must_use]
    pub(crate) const fn new(
        instance: InstanceRef,
        generation: InstanceGeneration,
        invocation: InvocationId,
        side_effect: SideEffectClass,
    ) -> Self {
        Self {
            instance,
            generation,
            invocation,
            side_effect,
        }
    }

    #[must_use]
    pub(crate) const fn side_effect(self) -> SideEffectClass {
        self.side_effect
    }
}

/// Typed Runtime observation consumed by recovery policy.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum RuntimeFailureFactKind {
    ProcessExited(ProcessLossObservation),
    HeartbeatMissed { last_sequence: u64 },
    ControlProbeMissed { probe: u64 },
    WedgeDetected(ProcessInvocationFailure),
    InvocationUncertain(ProcessInvocationFailure),
    ProtocolViolation(ProcessProtocolFailure),
    ResourceLimitExceeded(ProcessResourceFailure),
    OwnerInvariantViolation(ProcessOwnerInvariantFailure),
    LaunchFailed,
    ShutdownFailed,
    CleanupCompleted(ProcessCleanupProof),
    CleanupIncomplete(ProcessCleanupCensus),
}

/// One ordered fact from the sole owner of a ProcessDomain generation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RuntimeFailureFact {
    identity: ProcessGenerationIdentity,
    sequence: u64,
    observed_at: ClockReading,
    kind: RuntimeFailureFactKind,
}

impl RuntimeFailureFact {
    pub(crate) fn try_new(
        identity: ProcessGenerationIdentity,
        sequence: u64,
        observed_at: ClockReading,
        kind: RuntimeFailureFactKind,
    ) -> Result<Self, RecoveryError> {
        if sequence == 0 {
            return Err(RecoveryError::InvalidFactSequence);
        }
        match &kind {
            RuntimeFailureFactKind::ProcessExited(observation)
                if observation.identity() != identity =>
            {
                return Err(RecoveryError::GenerationMismatch);
            }
            RuntimeFailureFactKind::CleanupCompleted(proof) if proof.identity() != identity => {
                return Err(RecoveryError::GenerationMismatch);
            }
            _ => {}
        }
        Ok(Self {
            identity,
            sequence,
            observed_at,
            kind,
        })
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> ProcessGenerationIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn observed_at(&self) -> ClockReading {
        self.observed_at
    }
}

/// Why a domain can no longer restart automatically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuarantineReason {
    RestartAttemptsExhausted,
    ExternalEffectUncertain,
    CleanupNotProven,
    RecoveryActionFailed,
    OwnerInvariantViolation,
    EpochExhausted,
}

/// Pure recovery lifecycle for the old process generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryPhase {
    Healthy,
    Fencing,
    CooperativeStopping,
    WaitingCooperative { deadline: MonotonicInstant },
    Terminating,
    WaitingTerminate { deadline: MonotonicInstant },
    Killing,
    WaitingKill { deadline: MonotonicInstant },
    AwaitingProcessLoss { deadline: MonotonicInstant },
    Cleaning,
    AwaitingCleanup { deadline: MonotonicInstant },
    Backoff { restart_at: MonotonicInstant },
    StartingFresh { next_epoch: DomainEpoch },
    Recovered { next_epoch: DomainEpoch },
    Stopped,
    Quarantined { reason: QuarantineReason },
}

/// RuntimeHost-owned lifecycle operation requested by the pure reducer.
///
/// No variant accepts an invocation payload or requests replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryAction {
    FenceAndStopAdmission,
    RequestCooperativeStop,
    SendTerminate,
    SendKill,
    CollectCleanup,
    StartFreshDomain { next_epoch: DomainEpoch },
    EnterQuarantine { reason: QuarantineReason },
}

/// Idempotency identity assigned before a side-effecting recovery action.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RecoveryActionId(u64);

impl RecoveryActionId {
    #[must_use]
    pub(crate) const fn value(self) -> u64 {
        self.0
    }
}

/// One action paired with its stable idempotency identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryActionEnvelope {
    id: RecoveryActionId,
    action: RecoveryAction,
}

impl RecoveryActionEnvelope {
    #[must_use]
    pub(crate) const fn id(self) -> RecoveryActionId {
        self.id
    }

    #[must_use]
    pub(crate) const fn action(self) -> RecoveryAction {
        self.action
    }
}

/// Result returned by the concrete RuntimeHost action owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryActionOutcome {
    Succeeded,
    ProcessAlreadyExited,
    Failed,
}

/// Pure decision for one owner turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryDecision {
    NoAction,
    Execute(RecoveryActionEnvelope),
    AwaitingAction(RecoveryActionId),
    WaitUntil(MonotonicInstant),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompletedAction {
    id: RecoveryActionId,
    outcome: RecoveryActionOutcome,
}

/// Reducer state retained by the concrete ProcessDomain owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryState {
    identity: ProcessGenerationIdentity,
    lifecycle: ProcessLifecycleBudgets,
    restart: ProcessRestartPolicy,
    replay: InvocationReplayPolicy,
    phase: RecoveryPhase,
    restart_after_cleanup: bool,
    process_exited: bool,
    external_effect_uncertain: bool,
    quarantine_reason: Option<QuarantineReason>,
    quarantine_entered: bool,
    loss_lineage: Option<ProcessLossLineage>,
    unsettled_handoffs: u32,
    cleanup_proven: bool,
    attempt_sequence: u64,
    attempts: Vec<MonotonicInstant>,
    next_action_id: u64,
    pending_action: Option<RecoveryActionEnvelope>,
    last_completed_action: Option<CompletedAction>,
    last_fact_sequence: u64,
    last_fact_fingerprint: Option<Digest32>,
    last_observed_at: ClockReading,
}

impl RecoveryState {
    pub(crate) fn try_new(
        identity: ProcessGenerationIdentity,
        lifecycle: ProcessLifecycleBudgets,
        restart: ProcessRestartPolicy,
        replay: InvocationReplayPolicy,
        observed_at: ClockReading,
    ) -> Result<Self, RecoveryError> {
        let attempts_capacity =
            usize::try_from(restart.max_attempts()).map_err(|_| RecoveryError::CounterOverflow)?;
        Ok(Self {
            identity,
            lifecycle,
            restart,
            replay,
            phase: RecoveryPhase::Healthy,
            restart_after_cleanup: false,
            process_exited: false,
            external_effect_uncertain: false,
            quarantine_reason: None,
            quarantine_entered: false,
            loss_lineage: None,
            unsettled_handoffs: 0,
            cleanup_proven: false,
            attempt_sequence: 0,
            attempts: Vec::with_capacity(attempts_capacity),
            next_action_id: 0,
            pending_action: None,
            last_completed_action: None,
            last_fact_sequence: 0,
            last_fact_fingerprint: None,
            last_observed_at: observed_at,
        })
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> ProcessGenerationIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> RecoveryPhase {
        self.phase
    }

    #[must_use]
    pub(crate) fn restart_attempts_in_window(&self) -> usize {
        self.attempts.len()
    }

    #[must_use]
    pub(crate) const fn external_effect_uncertain(&self) -> bool {
        self.external_effect_uncertain
    }

    /// Sticky policy reason that forbids this generation from restarting.
    /// Resource-loss and cleanup phases may continue after this is set.
    #[must_use]
    pub(crate) const fn quarantine_reason(&self) -> Option<QuarantineReason> {
        self.quarantine_reason
    }

    #[must_use]
    pub(crate) const fn replay_policy(&self) -> InvocationReplayPolicy {
        self.replay
    }

    #[must_use]
    pub(crate) const fn unsettled_handoffs(&self) -> u32 {
        self.unsettled_handoffs
    }

    /// Returns the exact action envelope that still belongs to this reducer
    /// state. Later failure facts may add evidence without replacing an action
    /// already assigned to the sole RuntimeHost owner.
    #[must_use]
    pub(crate) const fn pending_action(&self) -> Option<RecoveryActionEnvelope> {
        self.pending_action
    }
}

/// Stateless deterministic recovery reducer.
pub(crate) struct RecoveryEngine;

impl RecoveryEngine {
    /// Consumes one ordered Runtime fact and returns a new immutable transition.
    pub(crate) fn observe_fact(
        state: &RecoveryState,
        fact: RuntimeFailureFact,
    ) -> Result<RecoveryTransition, RecoveryError> {
        if fact.identity() != state.identity {
            return Err(RecoveryError::GenerationMismatch);
        }
        validate_clock(state.last_observed_at, fact.observed_at())?;
        let fingerprint = fingerprint_fact(&fact)?;
        if fact.sequence() < state.last_fact_sequence {
            return Err(RecoveryError::StaleFact);
        }
        if fact.sequence() == state.last_fact_sequence {
            return if state.last_fact_fingerprint == Some(fingerprint) {
                Ok(RecoveryTransition::unchanged(state.clone()))
            } else {
                Err(RecoveryError::ConflictingFact)
            };
        }

        let mut next = state.clone();
        next.last_fact_sequence = fact.sequence();
        next.last_fact_fingerprint = Some(fingerprint);
        next.last_observed_at = fact.observed_at();
        let fact_observed_at = fact.observed_at();

        if matches!(next.phase, RecoveryPhase::Quarantined { .. })
            && (next.cleanup_proven
                || !matches!(
                    &fact.kind,
                    RuntimeFailureFactKind::ProcessExited(_)
                        | RuntimeFailureFactKind::CleanupCompleted(_)
                        | RuntimeFailureFactKind::CleanupIncomplete(_)
                ))
        {
            return Ok(RecoveryTransition::unchanged(next));
        }

        match fact.kind {
            RuntimeFailureFactKind::ProcessExited(observation) => {
                if next.loss_lineage.is_some() {
                    return Err(RecoveryError::ProcessLossAlreadyObserved);
                }
                if !observation.all_crossed_handoffs_settled() {
                    return Err(RecoveryError::UnsettledProcessHandoffs);
                }
                let expected = observation.expected();
                let lineage = observation.lineage();
                next.unsettled_handoffs = lineage.unsettled_handoffs();
                next.external_effect_uncertain |= observation.external_effect_uncertain();
                next.loss_lineage = Some(lineage);
                next.process_exited = true;
                if expected && next.phase == RecoveryPhase::Healthy {
                    next.restart_after_cleanup = false;
                    issue(
                        &mut next,
                        RecoveryPhase::Fencing,
                        RecoveryAction::FenceAndStopAdmission,
                    )
                } else if next.phase == RecoveryPhase::Healthy {
                    next.restart_after_cleanup = true;
                    issue(
                        &mut next,
                        RecoveryPhase::Fencing,
                        RecoveryAction::FenceAndStopAdmission,
                    )
                } else if next.pending_action.is_none()
                    && !matches!(
                        next.phase,
                        RecoveryPhase::Cleaning
                            | RecoveryPhase::AwaitingCleanup { .. }
                            | RecoveryPhase::Backoff { .. }
                            | RecoveryPhase::StartingFresh { .. }
                            | RecoveryPhase::Recovered { .. }
                            | RecoveryPhase::Stopped
                    )
                {
                    begin_cleanup(next)
                } else {
                    Ok(RecoveryTransition::unchanged(next))
                }
            }
            RuntimeFailureFactKind::HeartbeatMissed { .. }
            | RuntimeFailureFactKind::ControlProbeMissed { .. }
            | RuntimeFailureFactKind::ProtocolViolation(_)
            | RuntimeFailureFactKind::ResourceLimitExceeded(_)
            | RuntimeFailureFactKind::LaunchFailed => begin_failure(next),
            RuntimeFailureFactKind::ShutdownFailed => begin_failure(next),
            RuntimeFailureFactKind::OwnerInvariantViolation(_) => {
                begin_owner_invariant_failure(next)
            }
            RuntimeFailureFactKind::WedgeDetected(invocation)
            | RuntimeFailureFactKind::InvocationUncertain(invocation) => {
                if invocation.side_effect() != SideEffectClass::EffectFree {
                    next.external_effect_uncertain = true;
                    if matches!(
                        next.phase,
                        RecoveryPhase::Backoff { .. }
                            | RecoveryPhase::Recovered { .. }
                            | RecoveryPhase::Stopped
                    ) {
                        return quarantine(next, QuarantineReason::ExternalEffectUncertain);
                    }
                }
                begin_failure(next)
            }
            RuntimeFailureFactKind::CleanupCompleted(proof) => {
                if proof.identity() != next.identity {
                    return Err(RecoveryError::GenerationMismatch);
                }
                let Some(lineage) = next.loss_lineage else {
                    return Err(RecoveryError::ProcessLossNotObserved);
                };
                if next.unsettled_handoffs != 0 {
                    return Err(RecoveryError::UnsettledProcessHandoffs);
                }
                if proof.lineage() != lineage {
                    return Err(RecoveryError::CleanupLineageMismatch);
                }
                next.external_effect_uncertain |= proof.external_effect_uncertain();
                let deadline = match next.phase {
                    RecoveryPhase::AwaitingCleanup { deadline } => Some(deadline),
                    RecoveryPhase::Quarantined { .. } if next.quarantine_reason.is_some() => None,
                    _ => return Err(RecoveryError::UnexpectedCleanupFact),
                };
                next.cleanup_proven = true;
                if deadline.is_some_and(|deadline| reached(fact_observed_at, deadline)) {
                    return quarantine(next, QuarantineReason::CleanupNotProven);
                }
                if next.pending_action.is_some() {
                    Ok(RecoveryTransition::unchanged(next))
                } else {
                    schedule_after_cleanup(next, fact_observed_at)
                }
            }
            RuntimeFailureFactKind::CleanupIncomplete(_) => match next.phase {
                RecoveryPhase::AwaitingCleanup { .. } => {
                    quarantine(next, QuarantineReason::CleanupNotProven)
                }
                RecoveryPhase::Quarantined { .. } if next.quarantine_reason.is_some() => {
                    Ok(RecoveryTransition::unchanged(next))
                }
                _ => Err(RecoveryError::UnexpectedCleanupFact),
            },
        }
    }

    /// Applies the result of the exact pending RuntimeHost-owned action.
    pub(crate) fn complete_action(
        state: &RecoveryState,
        id: RecoveryActionId,
        outcome: RecoveryActionOutcome,
        observed_at: ClockReading,
    ) -> Result<RecoveryTransition, RecoveryError> {
        validate_clock(state.last_observed_at, observed_at)?;
        if let Some(completed) = state.last_completed_action {
            if completed.id == id && completed.outcome == outcome {
                return Ok(RecoveryTransition::unchanged(state.clone()));
            }
            if completed.id == id {
                return Err(RecoveryError::ConflictingActionCompletion);
            }
        }
        let Some(pending) = state.pending_action else {
            return Err(RecoveryError::NoActionPending);
        };
        if pending.id != id {
            return Err(RecoveryError::ActionMismatch);
        }
        if outcome == RecoveryActionOutcome::ProcessAlreadyExited
            && !matches!(
                pending.action,
                RecoveryAction::RequestCooperativeStop
                    | RecoveryAction::SendTerminate
                    | RecoveryAction::SendKill
            )
        {
            return Err(RecoveryError::InvalidActionOutcome);
        }

        let mut next = state.clone();
        next.pending_action = None;
        next.last_completed_action = Some(CompletedAction { id, outcome });
        next.last_observed_at = observed_at;
        if outcome == RecoveryActionOutcome::Failed {
            match pending.action {
                RecoveryAction::RequestCooperativeStop => {
                    remember_action_failure(&mut next);
                    return if next.process_exited {
                        begin_cleanup(next)
                    } else {
                        issue(
                            &mut next,
                            RecoveryPhase::Terminating,
                            RecoveryAction::SendTerminate,
                        )
                    };
                }
                RecoveryAction::SendTerminate => {
                    remember_action_failure(&mut next);
                    return if next.process_exited {
                        begin_cleanup(next)
                    } else {
                        issue(&mut next, RecoveryPhase::Killing, RecoveryAction::SendKill)
                    };
                }
                RecoveryAction::SendKill => {
                    remember_action_failure(&mut next);
                    return if next.process_exited {
                        begin_cleanup(next)
                    } else {
                        let reason = next
                            .quarantine_reason
                            .ok_or(RecoveryError::StateInconsistent)?;
                        quarantine(next, reason)
                    };
                }
                RecoveryAction::EnterQuarantine { reason } => {
                    remember_quarantine_reason(&mut next, reason);
                    if next.external_effect_uncertain {
                        remember_quarantine_reason(
                            &mut next,
                            QuarantineReason::ExternalEffectUncertain,
                        );
                    }
                    let reason = next
                        .quarantine_reason
                        .ok_or(RecoveryError::StateInconsistent)?;
                    next.phase = RecoveryPhase::Quarantined { reason };
                    return Ok(RecoveryTransition::unchanged(next));
                }
                RecoveryAction::FenceAndStopAdmission
                | RecoveryAction::CollectCleanup
                | RecoveryAction::StartFreshDomain { .. } => {
                    remember_action_failure(&mut next);
                    let reason = next
                        .quarantine_reason
                        .ok_or(RecoveryError::StateInconsistent)?;
                    return quarantine(next, reason);
                }
            }
        }
        match pending.action {
            RecoveryAction::FenceAndStopAdmission => {
                if next.process_exited {
                    begin_cleanup(next)
                } else {
                    issue(
                        &mut next,
                        RecoveryPhase::CooperativeStopping,
                        RecoveryAction::RequestCooperativeStop,
                    )
                }
            }
            RecoveryAction::RequestCooperativeStop => {
                if next.process_exited {
                    begin_cleanup(next)
                } else if outcome == RecoveryActionOutcome::ProcessAlreadyExited {
                    await_process_loss(next, observed_at)
                } else {
                    let deadline = add_budget(observed_at, next.lifecycle.cooperative_stop())?;
                    next.phase = RecoveryPhase::WaitingCooperative { deadline };
                    Ok(RecoveryTransition::waiting(next, deadline))
                }
            }
            RecoveryAction::SendTerminate => {
                if next.process_exited {
                    begin_cleanup(next)
                } else if outcome == RecoveryActionOutcome::ProcessAlreadyExited {
                    await_process_loss(next, observed_at)
                } else {
                    let deadline = add_budget(observed_at, next.lifecycle.terminate_grace())?;
                    next.phase = RecoveryPhase::WaitingTerminate { deadline };
                    Ok(RecoveryTransition::waiting(next, deadline))
                }
            }
            RecoveryAction::SendKill => {
                if next.process_exited {
                    begin_cleanup(next)
                } else if outcome == RecoveryActionOutcome::ProcessAlreadyExited {
                    await_process_loss(next, observed_at)
                } else {
                    let deadline = add_budget(observed_at, next.lifecycle.kill_grace())?;
                    next.phase = RecoveryPhase::WaitingKill { deadline };
                    Ok(RecoveryTransition::waiting(next, deadline))
                }
            }
            RecoveryAction::CollectCleanup => {
                ensure_loss_settled(&next)?;
                let deadline = add_budget(observed_at, next.lifecycle.cleanup())?;
                next.phase = RecoveryPhase::AwaitingCleanup { deadline };
                Ok(RecoveryTransition::waiting(next, deadline))
            }
            RecoveryAction::StartFreshDomain { next_epoch } => {
                ensure_loss_settled(&next)?;
                if !next.cleanup_proven {
                    return Err(RecoveryError::CleanupNotProven);
                }
                if next.external_effect_uncertain {
                    quarantine(next, QuarantineReason::ExternalEffectUncertain)
                } else if let Some(reason) = next.quarantine_reason {
                    quarantine(next, reason)
                } else {
                    next.phase = RecoveryPhase::Recovered { next_epoch };
                    Ok(RecoveryTransition::unchanged(next))
                }
            }
            RecoveryAction::EnterQuarantine { reason } => {
                remember_quarantine_reason(&mut next, reason);
                if next.external_effect_uncertain {
                    remember_quarantine_reason(
                        &mut next,
                        QuarantineReason::ExternalEffectUncertain,
                    );
                }
                next.quarantine_entered = true;
                if next.process_exited && !next.cleanup_proven {
                    begin_cleanup(next)
                } else {
                    let reason = next
                        .quarantine_reason
                        .ok_or(RecoveryError::StateInconsistent)?;
                    next.phase = RecoveryPhase::Quarantined { reason };
                    Ok(RecoveryTransition::unchanged(next))
                }
            }
        }
    }

    /// Carries the bounded restart ledger into the exact generation whose
    /// spawn action completed. No desired state or live resource is copied;
    /// only policy accounting and idempotency identities survive the fence.
    pub(crate) fn roll_generation(
        state: &RecoveryState,
        identity: ProcessGenerationIdentity,
        observed_at: ClockReading,
    ) -> Result<RecoveryState, RecoveryError> {
        validate_clock(state.last_observed_at, observed_at)?;
        let RecoveryPhase::Recovered { next_epoch } = state.phase else {
            return Err(RecoveryError::GenerationRollNotReady);
        };
        if state.pending_action.is_some() {
            return Err(RecoveryError::StateInconsistent);
        }
        if state.external_effect_uncertain
            || state.quarantine_reason.is_some()
            || state.quarantine_entered
        {
            return Err(RecoveryError::StateInconsistent);
        }
        if identity.runtime_host() != state.identity.runtime_host()
            || identity.runtime_host_epoch() != state.identity.runtime_host_epoch()
            || identity.source_revision() != state.identity.source_revision()
            || identity.target_slice_digest() != state.identity.target_slice_digest()
            || identity.domain() != state.identity.domain()
            || identity.domain_epoch() != next_epoch
        {
            return Err(RecoveryError::GenerationContinuityMismatch);
        }

        let mut next = state.clone();
        next.identity = identity;
        next.phase = RecoveryPhase::Healthy;
        next.restart_after_cleanup = false;
        next.process_exited = false;
        next.external_effect_uncertain = false;
        next.quarantine_reason = None;
        next.quarantine_entered = false;
        next.loss_lineage = None;
        next.unsettled_handoffs = 0;
        next.cleanup_proven = false;
        next.last_fact_sequence = 0;
        next.last_fact_fingerprint = None;
        next.last_observed_at = observed_at;
        Ok(next)
    }

    /// Advances one owner-local deadline. Calling before the deadline is pure
    /// and returns the same wait decision without consuming an attempt.
    pub(crate) fn poll(
        state: &RecoveryState,
        observed_at: ClockReading,
    ) -> Result<RecoveryTransition, RecoveryError> {
        validate_clock(state.last_observed_at, observed_at)?;
        if let Some(pending) = state.pending_action {
            return Ok(RecoveryTransition {
                state: state.clone(),
                decision: RecoveryDecision::AwaitingAction(pending.id),
            });
        }
        let mut next = state.clone();
        next.last_observed_at = observed_at;
        match next.phase {
            RecoveryPhase::WaitingCooperative { deadline } => {
                if !reached(observed_at, deadline) {
                    return Ok(RecoveryTransition::waiting(next, deadline));
                }
                issue(
                    &mut next,
                    RecoveryPhase::Terminating,
                    RecoveryAction::SendTerminate,
                )
            }
            RecoveryPhase::WaitingTerminate { deadline } => {
                if !reached(observed_at, deadline) {
                    return Ok(RecoveryTransition::waiting(next, deadline));
                }
                issue(&mut next, RecoveryPhase::Killing, RecoveryAction::SendKill)
            }
            RecoveryPhase::WaitingKill { deadline }
            | RecoveryPhase::AwaitingProcessLoss { deadline }
            | RecoveryPhase::AwaitingCleanup { deadline } => {
                if !reached(observed_at, deadline) {
                    return Ok(RecoveryTransition::waiting(next, deadline));
                }
                quarantine(next, QuarantineReason::CleanupNotProven)
            }
            RecoveryPhase::Backoff { restart_at } => {
                if !reached(observed_at, restart_at) {
                    return Ok(RecoveryTransition::waiting(next, restart_at));
                }
                ensure_loss_settled(&next)?;
                if !next.cleanup_proven {
                    return Err(RecoveryError::CleanupNotProven);
                }
                prune_attempts(&mut next, observed_at)?;
                if attempts_exhausted(&next)? {
                    return quarantine(next, QuarantineReason::RestartAttemptsExhausted);
                }
                let next_epoch = match next.identity.domain_epoch().try_next() {
                    Ok(value) => value,
                    Err(_) => return quarantine(next, QuarantineReason::EpochExhausted),
                };
                next.attempt_sequence = next
                    .attempt_sequence
                    .checked_add(1)
                    .ok_or(RecoveryError::CounterOverflow)?;
                // The attempt is consumed before the action that can spawn.
                next.attempts.push(observed_at.now());
                issue(
                    &mut next,
                    RecoveryPhase::StartingFresh { next_epoch },
                    RecoveryAction::StartFreshDomain { next_epoch },
                )
            }
            RecoveryPhase::Quarantined { .. } if next.process_exited && !next.cleanup_proven => {
                begin_cleanup(next)
            }
            RecoveryPhase::Healthy
            | RecoveryPhase::Recovered { .. }
            | RecoveryPhase::Stopped
            | RecoveryPhase::Quarantined { .. } => Ok(RecoveryTransition::unchanged(next)),
            RecoveryPhase::Fencing
            | RecoveryPhase::CooperativeStopping
            | RecoveryPhase::Terminating
            | RecoveryPhase::Killing
            | RecoveryPhase::Cleaning
            | RecoveryPhase::StartingFresh { .. } => Err(RecoveryError::StateInconsistent),
        }
    }
}

/// Result of one pure reducer call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryTransition {
    state: RecoveryState,
    decision: RecoveryDecision,
}

impl RecoveryTransition {
    fn unchanged(state: RecoveryState) -> Self {
        let decision = state
            .pending_action
            .map_or(RecoveryDecision::NoAction, |pending| {
                RecoveryDecision::AwaitingAction(pending.id)
            });
        Self { state, decision }
    }

    fn waiting(state: RecoveryState, deadline: MonotonicInstant) -> Self {
        Self {
            state,
            decision: RecoveryDecision::WaitUntil(deadline),
        }
    }

    #[must_use]
    pub(crate) const fn state(&self) -> &RecoveryState {
        &self.state
    }

    #[must_use]
    pub(crate) const fn decision(&self) -> RecoveryDecision {
        self.decision
    }

    #[must_use]
    pub(crate) fn into_state(self) -> RecoveryState {
        self.state
    }
}

fn begin_failure(mut state: RecoveryState) -> Result<RecoveryTransition, RecoveryError> {
    state.restart_after_cleanup = true;
    if state.phase == RecoveryPhase::Healthy {
        issue(
            &mut state,
            RecoveryPhase::Fencing,
            RecoveryAction::FenceAndStopAdmission,
        )
    } else {
        Ok(RecoveryTransition::unchanged(state))
    }
}

fn begin_owner_invariant_failure(
    mut state: RecoveryState,
) -> Result<RecoveryTransition, RecoveryError> {
    remember_quarantine_reason(&mut state, QuarantineReason::OwnerInvariantViolation);
    if matches!(
        state.phase,
        RecoveryPhase::Backoff { .. }
            | RecoveryPhase::StartingFresh { .. }
            | RecoveryPhase::Recovered { .. }
            | RecoveryPhase::Stopped
    ) {
        return quarantine(state, QuarantineReason::OwnerInvariantViolation);
    }
    begin_failure(state)
}

fn ensure_loss_settled(state: &RecoveryState) -> Result<ProcessLossLineage, RecoveryError> {
    let Some(lineage) = state.loss_lineage else {
        return Err(RecoveryError::ProcessLossNotObserved);
    };
    if state.unsettled_handoffs != 0 || lineage.unsettled_handoffs() != 0 {
        return Err(RecoveryError::UnsettledProcessHandoffs);
    }
    Ok(lineage)
}

fn begin_cleanup(mut state: RecoveryState) -> Result<RecoveryTransition, RecoveryError> {
    ensure_loss_settled(&state)?;
    if !state.process_exited {
        return Err(RecoveryError::ProcessLossNotObserved);
    }
    issue(
        &mut state,
        RecoveryPhase::Cleaning,
        RecoveryAction::CollectCleanup,
    )
}

fn await_process_loss(
    mut state: RecoveryState,
    observed_at: ClockReading,
) -> Result<RecoveryTransition, RecoveryError> {
    let deadline = add_budget(observed_at, state.lifecycle.cleanup())?;
    state.phase = RecoveryPhase::AwaitingProcessLoss { deadline };
    Ok(RecoveryTransition::waiting(state, deadline))
}

fn schedule_after_cleanup(
    mut state: RecoveryState,
    observed_at: ClockReading,
) -> Result<RecoveryTransition, RecoveryError> {
    ensure_loss_settled(&state)?;
    if !state.cleanup_proven {
        return Err(RecoveryError::CleanupNotProven);
    }
    if state.external_effect_uncertain {
        return quarantine(state, QuarantineReason::ExternalEffectUncertain);
    }
    if let Some(reason) = state.quarantine_reason {
        return quarantine(state, reason);
    }
    if !state.restart_after_cleanup {
        state.phase = RecoveryPhase::Stopped;
        return Ok(RecoveryTransition::unchanged(state));
    }
    prune_attempts(&mut state, observed_at)?;
    if attempts_exhausted(&state)? {
        return quarantine(state, QuarantineReason::RestartAttemptsExhausted);
    }
    let delay = restart_delay(&state)?;
    let restart_at = observed_at
        .now()
        .value()
        .checked_add(delay)
        .map(MonotonicInstant::from_ticks)
        .ok_or(RecoveryError::DeadlineOverflow)?;
    state.phase = RecoveryPhase::Backoff { restart_at };
    Ok(RecoveryTransition::waiting(state, restart_at))
}

fn quarantine(
    mut state: RecoveryState,
    reason: QuarantineReason,
) -> Result<RecoveryTransition, RecoveryError> {
    remember_quarantine_reason(&mut state, reason);
    let reason = state
        .quarantine_reason
        .ok_or(RecoveryError::StateInconsistent)?;
    if state.pending_action.is_some() {
        return Ok(RecoveryTransition::unchanged(state));
    }
    if state.quarantine_entered {
        state.phase = RecoveryPhase::Quarantined { reason };
        return Ok(RecoveryTransition::unchanged(state));
    }
    issue(
        &mut state,
        RecoveryPhase::Quarantined { reason },
        RecoveryAction::EnterQuarantine { reason },
    )
}

fn remember_quarantine_reason(state: &mut RecoveryState, reason: QuarantineReason) {
    if state.quarantine_reason.is_none()
        || reason == QuarantineReason::ExternalEffectUncertain
        || (reason == QuarantineReason::OwnerInvariantViolation
            && state.quarantine_reason != Some(QuarantineReason::ExternalEffectUncertain))
    {
        state.quarantine_reason = Some(reason);
    }
}

fn remember_action_failure(state: &mut RecoveryState) {
    remember_quarantine_reason(state, QuarantineReason::RecoveryActionFailed);
    if state.external_effect_uncertain {
        remember_quarantine_reason(state, QuarantineReason::ExternalEffectUncertain);
    }
}

fn issue(
    state: &mut RecoveryState,
    phase: RecoveryPhase,
    action: RecoveryAction,
) -> Result<RecoveryTransition, RecoveryError> {
    if state.pending_action.is_some() {
        return Err(RecoveryError::ActionAlreadyPending);
    }
    let value = state
        .next_action_id
        .checked_add(1)
        .ok_or(RecoveryError::CounterOverflow)?;
    let envelope = RecoveryActionEnvelope {
        id: RecoveryActionId(value),
        action,
    };
    state.next_action_id = value;
    state.phase = phase;
    state.pending_action = Some(envelope);
    Ok(RecoveryTransition {
        state: state.clone(),
        decision: RecoveryDecision::Execute(envelope),
    })
}

fn attempts_exhausted(state: &RecoveryState) -> Result<bool, RecoveryError> {
    let maximum = usize::try_from(state.restart.max_attempts())
        .map_err(|_| RecoveryError::CounterOverflow)?;
    Ok(state.attempts.len() >= maximum)
}

fn prune_attempts(
    state: &mut RecoveryState,
    observed_at: ClockReading,
) -> Result<(), RecoveryError> {
    validate_clock(state.last_observed_at, observed_at)?;
    let window = state.restart.restart_window().value();
    let now = observed_at.now().value();
    for attempt in &state.attempts {
        attempt
            .value()
            .checked_add(window)
            .ok_or(RecoveryError::DeadlineOverflow)?;
    }
    state
        .attempts
        .retain(|attempt| attempt.value().saturating_add(window) > now);
    Ok(())
}

fn restart_delay(state: &RecoveryState) -> Result<u64, RecoveryError> {
    let initial = state.restart.initial_backoff().value();
    let maximum = state.restart.max_backoff().value();
    let mut base = initial;
    for _ in 0..state.attempts.len() {
        base = base.checked_mul(2).unwrap_or(maximum).min(maximum);
    }
    let jitter_cap = u128::from(base)
        .checked_mul(u128::from(state.restart.jitter_basis_points()))
        .ok_or(RecoveryError::CounterOverflow)?
        / 10_000;
    let available = maximum.saturating_sub(base);
    let jitter_cap = u64::try_from(jitter_cap)
        .map_err(|_| RecoveryError::CounterOverflow)?
        .min(available);
    let jitter = if jitter_cap == 0 {
        0
    } else {
        deterministic_jitter(state, jitter_cap)?
    };
    base.checked_add(jitter)
        .ok_or(RecoveryError::CounterOverflow)
}

fn deterministic_jitter(state: &RecoveryState, cap: u64) -> Result<u64, RecoveryError> {
    let mut builder = Digest32Builder::try_new(RECOVERY_JITTER_DIGEST_DOMAIN)
        .map_err(|_| RecoveryError::DigestFailed)?;
    field_bytes(&mut builder, state.identity.runtime_host().as_bytes())?;
    field_u64(&mut builder, state.identity.runtime_host_epoch().value())?;
    field_u64(&mut builder, state.identity.source_revision().value())?;
    field_bytes(
        &mut builder,
        state.identity.target_slice_digest().value().as_bytes(),
    )?;
    field_bytes(&mut builder, state.identity.domain().as_bytes())?;
    field_u64(&mut builder, state.identity.domain_epoch().value())?;
    let next_attempt = state
        .attempt_sequence
        .checked_add(1)
        .ok_or(RecoveryError::CounterOverflow)?;
    field_u64(&mut builder, next_attempt)?;
    let digest = builder.finish().into_bytes();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    let range = cap.checked_add(1).ok_or(RecoveryError::CounterOverflow)?;
    Ok(u64::from_be_bytes(prefix) % range)
}

fn fingerprint_fact(fact: &RuntimeFailureFact) -> Result<Digest32, RecoveryError> {
    let mut builder = Digest32Builder::try_new(RECOVERY_FACT_DIGEST_DOMAIN)
        .map_err(|_| RecoveryError::DigestFailed)?;
    let identity = fact.identity;
    field_bytes(&mut builder, identity.runtime_host().as_bytes())?;
    field_u64(&mut builder, identity.runtime_host_epoch().value())?;
    field_u64(&mut builder, identity.source_revision().value())?;
    field_bytes(
        &mut builder,
        identity.target_slice_digest().value().as_bytes(),
    )?;
    field_bytes(&mut builder, identity.domain().as_bytes())?;
    field_u64(&mut builder, identity.domain_epoch().value())?;
    field_u64(&mut builder, fact.sequence)?;
    field_bytes(&mut builder, fact.observed_at.domain().as_bytes())?;
    field_u64(&mut builder, fact.observed_at.generation().value())?;
    field_u64(&mut builder, fact.observed_at.now().value())?;
    append_fact_kind(&mut builder, &fact.kind)?;
    Ok(builder.finish())
}

fn append_fact_kind(
    builder: &mut Digest32Builder,
    kind: &RuntimeFailureFactKind,
) -> Result<(), RecoveryError> {
    match kind {
        RuntimeFailureFactKind::ProcessExited(observation) => {
            field_tag(builder, 1)?;
            field_bool(builder, observation.expected())?;
            append_loss_observation(builder, observation)
        }
        RuntimeFailureFactKind::HeartbeatMissed { last_sequence } => {
            field_tag(builder, 2)?;
            field_u64(builder, *last_sequence)
        }
        RuntimeFailureFactKind::ControlProbeMissed { probe } => {
            field_tag(builder, 3)?;
            field_u64(builder, *probe)
        }
        RuntimeFailureFactKind::WedgeDetected(invocation) => {
            field_tag(builder, 4)?;
            append_invocation(builder, *invocation)
        }
        RuntimeFailureFactKind::InvocationUncertain(invocation) => {
            field_tag(builder, 5)?;
            append_invocation(builder, *invocation)
        }
        RuntimeFailureFactKind::ProtocolViolation(failure) => {
            field_tag(builder, 6)?;
            field_tag(builder, protocol_failure_tag(*failure))
        }
        RuntimeFailureFactKind::ResourceLimitExceeded(failure) => {
            field_tag(builder, 10)?;
            field_tag(builder, resource_failure_tag(*failure))
        }
        RuntimeFailureFactKind::OwnerInvariantViolation(failure) => {
            field_tag(builder, 11)?;
            field_tag(builder, owner_invariant_failure_tag(*failure))
        }
        RuntimeFailureFactKind::LaunchFailed => field_tag(builder, 7),
        RuntimeFailureFactKind::ShutdownFailed => field_tag(builder, 12),
        RuntimeFailureFactKind::CleanupCompleted(proof) => {
            field_tag(builder, 8)?;
            append_loss_lineage(builder, proof.lineage())?;
            append_census(builder, proof.census())
        }
        RuntimeFailureFactKind::CleanupIncomplete(census) => {
            field_tag(builder, 9)?;
            append_census(builder, *census)
        }
    }
}

fn append_loss_observation(
    builder: &mut Digest32Builder,
    observation: &ProcessLossObservation,
) -> Result<(), RecoveryError> {
    let identity = observation.identity();
    field_bytes(builder, identity.runtime_host().as_bytes())?;
    field_u64(builder, identity.runtime_host_epoch().value())?;
    field_u64(builder, identity.source_revision().value())?;
    field_bytes(builder, identity.target_slice_digest().value().as_bytes())?;
    field_bytes(builder, identity.domain().as_bytes())?;
    field_u64(builder, identity.domain_epoch().value())?;
    append_loss_lineage(builder, observation.lineage())?;
    for invocation in observation.uncertain_invocations() {
        field_bytes(builder, invocation.instance().as_bytes())?;
        field_u64(builder, invocation.generation().value())?;
        field_u64(builder, invocation.invocation().value())?;
        field_tag(builder, side_effect_tag(invocation.side_effect()))?;
    }
    Ok(())
}

fn append_loss_lineage(
    builder: &mut Digest32Builder,
    lineage: ProcessLossLineage,
) -> Result<(), RecoveryError> {
    let (tree, outstanding, credits, retained, crossed, classified, external_uncertain) =
        lineage.fingerprint_fields();
    field_u32(builder, tree)?;
    field_u32(builder, outstanding)?;
    field_u32(builder, credits)?;
    field_u64(builder, retained)?;
    field_u32(builder, crossed)?;
    field_u32(builder, classified)?;
    field_bool(builder, external_uncertain)
}

fn append_invocation(
    builder: &mut Digest32Builder,
    invocation: ProcessInvocationFailure,
) -> Result<(), RecoveryError> {
    field_bytes(builder, invocation.instance.as_bytes())?;
    field_u64(builder, invocation.generation.value())?;
    field_u64(builder, invocation.invocation.value())?;
    field_tag(builder, side_effect_tag(invocation.side_effect))
}

fn append_census(
    builder: &mut Digest32Builder,
    census: ProcessCleanupCensus,
) -> Result<(), RecoveryError> {
    let (leader, tree, handles, credits, bytes, workspace, resources) = census.fingerprint_fields();
    field_bool(builder, leader)?;
    field_u32(builder, tree)?;
    field_u32(builder, handles)?;
    field_u32(builder, credits)?;
    field_u64(builder, bytes)?;
    field_u32(builder, workspace)?;
    field_u32(builder, resources)
}

fn field_bytes(builder: &mut Digest32Builder, value: &[u8]) -> Result<(), RecoveryError> {
    builder
        .field_bytes(value)
        .map(|_| ())
        .map_err(|_| RecoveryError::DigestFailed)
}

fn field_tag(builder: &mut Digest32Builder, value: u8) -> Result<(), RecoveryError> {
    field_bytes(builder, &[value])
}

fn field_bool(builder: &mut Digest32Builder, value: bool) -> Result<(), RecoveryError> {
    field_bytes(builder, &[u8::from(value)])
}

fn field_u32(builder: &mut Digest32Builder, value: u32) -> Result<(), RecoveryError> {
    field_bytes(builder, &value.to_be_bytes())
}

fn field_u64(builder: &mut Digest32Builder, value: u64) -> Result<(), RecoveryError> {
    builder
        .field_u64(value)
        .map(|_| ())
        .map_err(|_| RecoveryError::DigestFailed)
}

const fn side_effect_tag(value: SideEffectClass) -> u8 {
    match value {
        SideEffectClass::EffectFree => 1,
        SideEffectClass::External => 2,
        SideEffectClass::Unknown => 3,
    }
}

const fn protocol_failure_tag(value: ProcessProtocolFailure) -> u8 {
    match value {
        ProcessProtocolFailure::InvalidFrame => 1,
        ProcessProtocolFailure::UnsupportedVersion => 2,
        ProcessProtocolFailure::GenerationMismatch => 3,
        ProcessProtocolFailure::SequenceViolation => 4,
        ProcessProtocolFailure::CreditViolation => 5,
        ProcessProtocolFailure::PayloadTooLarge => 6,
    }
}

const fn resource_failure_tag(value: ProcessResourceFailure) -> u8 {
    match value {
        ProcessResourceFailure::Memory => 1,
        ProcessResourceFailure::OpenFds => 2,
        ProcessResourceFailure::ProcessTree => 3,
        ProcessResourceFailure::Cpu => 4,
    }
}

const fn owner_invariant_failure_tag(value: ProcessOwnerInvariantFailure) -> u8 {
    match value {
        ProcessOwnerInvariantFailure::GenerationMismatch => 1,
        ProcessOwnerInvariantFailure::ClockMismatch => 2,
        ProcessOwnerInvariantFailure::ClockRegressed => 3,
        ProcessOwnerInvariantFailure::DeadlineOverflow => 4,
        ProcessOwnerInvariantFailure::StateInconsistent => 5,
    }
}

fn validate_clock(previous: ClockReading, current: ClockReading) -> Result<(), RecoveryError> {
    if previous.domain() != current.domain() || previous.generation() != current.generation() {
        return Err(RecoveryError::ClockMismatch);
    }
    if current.now().value() < previous.now().value() {
        return Err(RecoveryError::ClockRegressed);
    }
    Ok(())
}

fn add_budget(
    reading: ClockReading,
    budget: paraegox_kernel::time::BoundedDuration,
) -> Result<MonotonicInstant, RecoveryError> {
    reading
        .now()
        .value()
        .checked_add(budget.value())
        .map(MonotonicInstant::from_ticks)
        .ok_or(RecoveryError::DeadlineOverflow)
}

const fn reached(reading: ClockReading, at: MonotonicInstant) -> bool {
    reading.now().value() >= at.value()
}

/// Fail-closed errors from the pure recovery reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryError {
    GenerationMismatch,
    ClockMismatch,
    ClockRegressed,
    DeadlineOverflow,
    CounterOverflow,
    InvalidFactSequence,
    StaleFact,
    ConflictingFact,
    ProcessLossAlreadyObserved,
    ProcessLossNotObserved,
    UnsettledProcessHandoffs,
    CleanupLineageMismatch,
    CleanupNotProven,
    UnexpectedCleanupFact,
    ActionAlreadyPending,
    NoActionPending,
    ActionMismatch,
    ConflictingActionCompletion,
    InvalidActionOutcome,
    GenerationRollNotReady,
    GenerationContinuityMismatch,
    DigestFailed,
    StateInconsistent,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::GenerationMismatch => "recovery input belongs to another process generation",
            Self::ClockMismatch => "recovery input uses another clock domain or generation",
            Self::ClockRegressed => "recovery observation clock regressed",
            Self::DeadlineOverflow => "recovery deadline overflowed",
            Self::CounterOverflow => "recovery counter overflowed",
            Self::InvalidFactSequence => "recovery fact sequence must be nonzero",
            Self::StaleFact => "recovery fact sequence is stale",
            Self::ConflictingFact => "same recovery fact sequence has different content",
            Self::ProcessLossAlreadyObserved => {
                "process loss was already observed for this generation"
            }
            Self::ProcessLossNotObserved => {
                "process cleanup cannot begin before fenced loss is observed"
            }
            Self::UnsettledProcessHandoffs => {
                "process loss still contains unclassified or unsettled handoffs"
            }
            Self::CleanupLineageMismatch => {
                "cleanup proof does not belong to the observed process loss"
            }
            Self::CleanupNotProven => {
                "fresh process generation cannot start before exact cleanup proof"
            }
            Self::UnexpectedCleanupFact => "cleanup fact arrived outside cleanup ownership",
            Self::ActionAlreadyPending => "a recovery action is already pending",
            Self::NoActionPending => "no recovery action is pending",
            Self::ActionMismatch => "action completion does not match the pending action",
            Self::ConflictingActionCompletion => {
                "same recovery action has conflicting completion facts"
            }
            Self::InvalidActionOutcome => {
                "recovery action outcome is invalid for the pending action"
            }
            Self::GenerationRollNotReady => "recovery has not completed a fresh-generation spawn",
            Self::GenerationContinuityMismatch => {
                "fresh process generation breaks runtime, plan, domain, or epoch continuity"
            }
            Self::DigestFailed => "recovery internal digest construction failed",
            Self::StateInconsistent => "recovery state is internally inconsistent",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RecoveryError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::{
        BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant,
    };
    use paraegox_runtime_contracts::assignment::InstanceRef;
    use paraegox_runtime_contracts::process_execution::{
        InvocationReplayPolicy, ProcessDomainRef, ProcessLifecycleBudgets, ProcessLivenessBudgets,
        ProcessRestartPolicy, ProcessShutdownBudgets, SideEffectClass,
    };
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};

    use super::{
        ProcessInvocationFailure, ProcessOwnerInvariantFailure, ProcessProtocolFailure,
        ProcessResourceFailure, QuarantineReason, RecoveryAction, RecoveryActionOutcome,
        RecoveryDecision, RecoveryEngine, RecoveryError, RecoveryPhase, RecoveryState,
        RuntimeFailureFact, RuntimeFailureFactKind,
    };
    use crate::card_instance::{DomainEpoch, InstanceGeneration, InvocationId, RuntimeHostEpoch};
    use crate::runtime_ownership::{
        ProcessAdmissionGate, ProcessCleanupAuthority, ProcessCleanupCensus, ProcessCleanupProof,
        ProcessDomainOwnership, ProcessGenerationIdentity, ProcessInstanceOwnership,
        ProcessInvocationOwnership, ProcessInvocationOwnershipStage, ProcessLossObservation,
        ProcessOwnershipLifecycle, ProcessOwnershipLimits, RuntimeOwnershipError,
    };

    fn host_epoch(value: u64) -> RuntimeHostEpoch {
        RuntimeHostEpoch::try_new(value).unwrap_or_else(|error| panic!("host epoch: {error}"))
    }

    fn domain_epoch(value: u64) -> DomainEpoch {
        DomainEpoch::try_new(value).unwrap_or_else(|error| panic!("domain epoch: {error}"))
    }

    fn generation(value: u64) -> InstanceGeneration {
        InstanceGeneration::try_new(value).unwrap_or_else(|error| panic!("generation: {error}"))
    }

    fn invocation(value: u64) -> InvocationId {
        InvocationId::try_new(value).unwrap_or_else(|error| panic!("invocation: {error}"))
    }

    fn clock_generation(value: u64) -> ClockGeneration {
        ClockGeneration::try_new(value).unwrap_or_else(|error| panic!("clock: {error}"))
    }

    fn at(ticks: u64) -> ClockReading {
        ClockReading::new(
            ClockDomainRef::from_bytes([8; 16]),
            clock_generation(1),
            MonotonicInstant::from_ticks(ticks),
        )
    }

    fn identity(domain: u8) -> ProcessGenerationIdentity {
        identity_with_epoch(domain, 5)
    }

    fn identity_with_epoch(domain: u8, epoch: u64) -> ProcessGenerationIdentity {
        ProcessGenerationIdentity::new(
            RuntimeHostId::from_bytes([1; 16]),
            host_epoch(2),
            SourcePlanRevision::new(3),
            TargetSliceDigest::new(Digest32::from_bytes([4; 32])),
            ProcessDomainRef::from_bytes([domain; 16]),
            domain_epoch(epoch),
        )
    }

    fn lifecycle() -> ProcessLifecycleBudgets {
        let liveness = ProcessLivenessBudgets::try_new(
            BoundedDuration::from_nanos(10),
            BoundedDuration::from_nanos(2),
            BoundedDuration::from_nanos(6),
            BoundedDuration::from_nanos(3),
        )
        .unwrap_or_else(|error| panic!("liveness: {error}"));
        let shutdown = ProcessShutdownBudgets::try_new(
            BoundedDuration::from_nanos(8),
            BoundedDuration::from_nanos(4),
            BoundedDuration::from_nanos(5),
            BoundedDuration::from_nanos(6),
            BoundedDuration::from_nanos(7),
        )
        .unwrap_or_else(|error| panic!("shutdown: {error}"));
        ProcessLifecycleBudgets::new(liveness, shutdown)
    }

    fn restart(max_attempts: u32) -> ProcessRestartPolicy {
        ProcessRestartPolicy::try_new(
            max_attempts,
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(10),
            BoundedDuration::from_nanos(40),
            2_500,
        )
        .unwrap_or_else(|error| panic!("restart: {error}"))
    }

    fn state(max_attempts: u32) -> RecoveryState {
        RecoveryState::try_new(
            identity(7),
            lifecycle(),
            restart(max_attempts),
            InvocationReplayPolicy::NoReplay,
            at(0),
        )
        .unwrap_or_else(|error| panic!("state: {error}"))
    }

    fn fact(sequence: u64, ticks: u64, kind: RuntimeFailureFactKind) -> RuntimeFailureFact {
        fact_for(identity(7), sequence, ticks, kind)
    }

    fn fact_for(
        identity: ProcessGenerationIdentity,
        sequence: u64,
        ticks: u64,
        kind: RuntimeFailureFactKind,
    ) -> RuntimeFailureFact {
        RuntimeFailureFact::try_new(identity, sequence, at(ticks), kind)
            .unwrap_or_else(|error| panic!("fact: {error}"))
    }

    fn execute(transition: &super::RecoveryTransition) -> super::RecoveryActionEnvelope {
        let RecoveryDecision::Execute(action) = transition.decision() else {
            panic!("expected executable action")
        };
        action
    }

    fn complete_success(
        transition: super::RecoveryTransition,
        ticks: u64,
    ) -> super::RecoveryTransition {
        complete_with_outcome(transition, RecoveryActionOutcome::Succeeded, ticks)
    }

    fn complete_with_outcome(
        transition: super::RecoveryTransition,
        outcome: RecoveryActionOutcome,
        ticks: u64,
    ) -> super::RecoveryTransition {
        let action = execute(&transition);
        RecoveryEngine::complete_action(transition.state(), action.id(), outcome, at(ticks))
            .unwrap_or_else(|error| panic!("action completion: {error}"))
    }

    fn loss_bundle(
        generation_identity: ProcessGenerationIdentity,
        expected: bool,
        invocations: Vec<ProcessInvocationOwnership>,
    ) -> (ProcessLossObservation, ProcessCleanupAuthority) {
        let instance = ProcessInstanceOwnership::try_new(
            InstanceRef::from_bytes([9; 16]),
            generation(1),
            invocations,
        )
        .unwrap_or_else(|error| panic!("instance ownership: {error}"));
        let ownership = ProcessDomainOwnership::try_new(
            generation_identity,
            ProcessOwnershipLifecycle::Closing,
            0,
            ProcessOwnershipLimits::new(8, 8, 1_024, 2),
            vec![instance],
        )
        .unwrap_or_else(|error| panic!("domain ownership: {error}"));
        ProcessAdmissionGate::new(generation_identity)
            .fence()
            .observe_process_loss(expected, ownership)
            .unwrap_or_else(|error| panic!("process loss: {error}"))
            .into_parts()
    }

    trait CleanupAuthorityTestExt {
        fn try_prove(
            self,
            census: ProcessCleanupCensus,
        ) -> Result<ProcessCleanupProof, RuntimeOwnershipError>;
    }

    impl CleanupAuthorityTestExt for ProcessCleanupAuthority {
        fn try_prove(
            self,
            census: ProcessCleanupCensus,
        ) -> Result<ProcessCleanupProof, RuntimeOwnershipError> {
            let identity = self.identity();
            let settled = self
                .uncertain_invocations()
                .iter()
                .map(|invocation| {
                    ProcessInvocationOwnership::new(
                        invocation.invocation(),
                        ProcessInvocationOwnershipStage::Uncertain,
                        invocation.side_effect(),
                        false,
                        0,
                    )
                })
                .collect();
            let instance = ProcessInstanceOwnership::try_new(
                InstanceRef::from_bytes([9; 16]),
                generation(1),
                settled,
            )?;
            let ownership = ProcessDomainOwnership::try_new(
                identity,
                ProcessOwnershipLifecycle::Closing,
                0,
                ProcessOwnershipLimits::new(8, 8, 1_024, 2),
                vec![instance],
            )?;
            self.reconcile(ownership)?.try_prove(census)
        }
    }

    struct CleanupFixture {
        state: RecoveryState,
        authority: ProcessCleanupAuthority,
    }

    fn reach_cleanup(mut current: RecoveryState) -> CleanupFixture {
        let identity = current.identity();
        let start = current.last_observed_at.now().value();
        let (loss, authority) = loss_bundle(identity, false, Vec::new());
        let transition = RecoveryEngine::observe_fact(
            &current,
            fact_for(
                identity,
                1,
                start + 1,
                RuntimeFailureFactKind::ProcessExited(loss),
            ),
        )
        .unwrap_or_else(|error| panic!("exit: {error}"));
        assert_eq!(
            execute(&transition).action(),
            RecoveryAction::FenceAndStopAdmission
        );
        let transition = complete_success(transition, start + 2);
        assert_eq!(
            execute(&transition).action(),
            RecoveryAction::CollectCleanup
        );
        let transition = complete_success(transition, start + 3);
        current = transition.into_state();
        assert!(matches!(
            current.phase(),
            RecoveryPhase::AwaitingCleanup { .. }
        ));
        CleanupFixture {
            state: current,
            authority,
        }
    }

    fn complete_one_restart(current: RecoveryState) -> RecoveryState {
        let CleanupFixture {
            state: current,
            authority,
        } = reach_cleanup(current);
        let identity = current.identity();
        let cleanup_ticks = current.last_observed_at.now().value() + 1;
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        let transition = RecoveryEngine::observe_fact(
            &current,
            fact_for(
                identity,
                2,
                cleanup_ticks,
                RuntimeFailureFactKind::CleanupCompleted(proof),
            ),
        )
        .unwrap_or_else(|error| panic!("cleanup: {error}"));
        let RecoveryDecision::WaitUntil(restart_at) = transition.decision() else {
            panic!("cleanup must schedule a restart")
        };
        let transition = RecoveryEngine::poll(transition.state(), at(restart_at.value()))
            .unwrap_or_else(|error| panic!("restart poll: {error}"));
        complete_success(transition, restart_at.value() + 1).into_state()
    }

    #[test]
    fn action_vocabulary_has_no_replay_and_attempt_is_consumed_before_spawn() {
        let CleanupFixture {
            state: current,
            authority,
        } = reach_cleanup(state(2));
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        let transition = RecoveryEngine::observe_fact(
            &current,
            fact(2, 4, RuntimeFailureFactKind::CleanupCompleted(proof)),
        )
        .unwrap_or_else(|error| panic!("cleanup: {error}"));
        let RecoveryDecision::WaitUntil(restart_at) = transition.decision() else {
            panic!("cleanup must schedule a backoff")
        };
        assert_eq!(transition.state().restart_attempts_in_window(), 0);

        let transition = RecoveryEngine::poll(transition.state(), at(restart_at.value()))
            .unwrap_or_else(|error| panic!("restart poll: {error}"));
        let action = execute(&transition);
        assert_eq!(
            action.action(),
            RecoveryAction::StartFreshDomain {
                next_epoch: domain_epoch(6)
            }
        );
        assert_eq!(transition.state().restart_attempts_in_window(), 1);
        assert_eq!(
            transition.state().replay_policy(),
            InvocationReplayPolicy::NoReplay
        );
    }

    #[test]
    fn already_exited_cannot_complete_admission_fence_or_cleanup() {
        let (loss, _authority) = loss_bundle(identity(7), false, Vec::new());
        let fencing = RecoveryEngine::observe_fact(
            &state(2),
            fact(1, 1, RuntimeFailureFactKind::ProcessExited(loss)),
        )
        .unwrap_or_else(|error| panic!("loss: {error}"));
        let fence = execute(&fencing);
        assert_eq!(fence.action(), RecoveryAction::FenceAndStopAdmission);
        assert_eq!(
            RecoveryEngine::complete_action(
                fencing.state(),
                fence.id(),
                RecoveryActionOutcome::ProcessAlreadyExited,
                at(2),
            ),
            Err(RecoveryError::InvalidActionOutcome)
        );

        let cleaning = complete_success(fencing, 2);
        let collect = execute(&cleaning);
        assert_eq!(collect.action(), RecoveryAction::CollectCleanup);
        assert_eq!(
            RecoveryEngine::complete_action(
                cleaning.state(),
                collect.id(),
                RecoveryActionOutcome::ProcessAlreadyExited,
                at(3),
            ),
            Err(RecoveryError::InvalidActionOutcome)
        );
    }

    #[test]
    fn action_failure_quarantine_still_consumes_loss_and_cleanup_proof() {
        for quarantine_outcome in [
            RecoveryActionOutcome::Succeeded,
            RecoveryActionOutcome::Failed,
        ] {
            let heartbeat = RecoveryEngine::observe_fact(
                &state(2),
                fact(
                    1,
                    1,
                    RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 7 },
                ),
            )
            .unwrap_or_else(|error| panic!("heartbeat failure: {error}"));
            let fence = execute(&heartbeat);
            let entering = RecoveryEngine::complete_action(
                heartbeat.state(),
                fence.id(),
                RecoveryActionOutcome::Failed,
                at(2),
            )
            .unwrap_or_else(|error| panic!("failed fence: {error}"));
            let enter = execute(&entering);
            assert_eq!(
                enter.action(),
                RecoveryAction::EnterQuarantine {
                    reason: QuarantineReason::RecoveryActionFailed
                }
            );
            assert_eq!(
                entering.state().quarantine_reason(),
                Some(QuarantineReason::RecoveryActionFailed)
            );

            let quarantined = RecoveryEngine::complete_action(
                entering.state(),
                enter.id(),
                quarantine_outcome,
                at(3),
            )
            .unwrap_or_else(|error| panic!("quarantine completion: {error}"));
            assert_eq!(
                quarantined.state().phase(),
                RecoveryPhase::Quarantined {
                    reason: QuarantineReason::RecoveryActionFailed
                }
            );
            assert_eq!(quarantined.state().pending_action(), None);

            let (loss, authority) = loss_bundle(identity(7), false, Vec::new());
            let cleaning = RecoveryEngine::observe_fact(
                quarantined.state(),
                fact(2, 4, RuntimeFailureFactKind::ProcessExited(loss)),
            )
            .unwrap_or_else(|error| panic!("loss after quarantine: {error}"));
            let collect = execute(&cleaning);
            assert_eq!(collect.action(), RecoveryAction::CollectCleanup);
            let awaiting = complete_success(cleaning, 5);
            assert!(matches!(
                awaiting.state().phase(),
                RecoveryPhase::AwaitingCleanup { .. }
            ));

            let proof = authority
                .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
                .unwrap_or_else(|error| panic!("cleanup proof: {error}"));
            let settled = RecoveryEngine::observe_fact(
                awaiting.state(),
                fact(3, 6, RuntimeFailureFactKind::CleanupCompleted(proof)),
            )
            .unwrap_or_else(|error| panic!("cleanup after quarantine: {error}"));
            let final_state = if quarantine_outcome == RecoveryActionOutcome::Failed {
                let retry_enter = execute(&settled);
                assert_eq!(
                    retry_enter.action(),
                    RecoveryAction::EnterQuarantine {
                        reason: QuarantineReason::RecoveryActionFailed
                    }
                );
                RecoveryEngine::complete_action(
                    settled.state(),
                    retry_enter.id(),
                    RecoveryActionOutcome::Succeeded,
                    at(7),
                )
                .unwrap_or_else(|error| panic!("retry quarantine: {error}"))
                .into_state()
            } else {
                assert_eq!(settled.decision(), RecoveryDecision::NoAction);
                settled.into_state()
            };
            assert_eq!(
                final_state.phase(),
                RecoveryPhase::Quarantined {
                    reason: QuarantineReason::RecoveryActionFailed
                }
            );
            assert_eq!(final_state.pending_action(), None);
            assert_eq!(final_state.restart_attempts_in_window(), 0);
            assert_eq!(
                final_state.replay_policy(),
                InvocationReplayPolicy::NoReplay
            );
            let stable = RecoveryEngine::poll(&final_state, at(8))
                .unwrap_or_else(|error| panic!("stable quarantine: {error}"));
            assert_eq!(stable.decision(), RecoveryDecision::NoAction);
        }
    }

    #[test]
    fn stop_and_terminate_failures_continue_to_kill_before_quarantine() {
        let heartbeat = RecoveryEngine::observe_fact(
            &state(2),
            fact(
                1,
                1,
                RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 7 },
            ),
        )
        .unwrap_or_else(|error| panic!("heartbeat failure: {error}"));
        let stopping = complete_success(heartbeat, 2);
        let stop = execute(&stopping);
        assert_eq!(stop.action(), RecoveryAction::RequestCooperativeStop);

        let terminating = RecoveryEngine::complete_action(
            stopping.state(),
            stop.id(),
            RecoveryActionOutcome::Failed,
            at(3),
        )
        .unwrap_or_else(|error| panic!("failed cooperative stop: {error}"));
        let terminate = execute(&terminating);
        assert_eq!(terminate.action(), RecoveryAction::SendTerminate);
        assert_eq!(
            terminating.state().quarantine_reason(),
            Some(QuarantineReason::RecoveryActionFailed)
        );

        let killing = RecoveryEngine::complete_action(
            terminating.state(),
            terminate.id(),
            RecoveryActionOutcome::Failed,
            at(4),
        )
        .unwrap_or_else(|error| panic!("failed terminate: {error}"));
        let kill = execute(&killing);
        assert_eq!(kill.action(), RecoveryAction::SendKill);
        assert_eq!(
            killing.state().quarantine_reason(),
            Some(QuarantineReason::RecoveryActionFailed)
        );

        let entering = RecoveryEngine::complete_action(
            killing.state(),
            kill.id(),
            RecoveryActionOutcome::Failed,
            at(5),
        )
        .unwrap_or_else(|error| panic!("failed kill: {error}"));
        let enter = execute(&entering);
        assert_eq!(
            enter.action(),
            RecoveryAction::EnterQuarantine {
                reason: QuarantineReason::RecoveryActionFailed
            }
        );
        let quarantined = complete_success(entering, 6);
        assert_eq!(
            quarantined.state().phase(),
            RecoveryPhase::Quarantined {
                reason: QuarantineReason::RecoveryActionFailed
            }
        );

        let (loss, authority) = loss_bundle(identity(7), false, Vec::new());
        let cleaning = RecoveryEngine::observe_fact(
            quarantined.state(),
            fact(2, 7, RuntimeFailureFactKind::ProcessExited(loss)),
        )
        .unwrap_or_else(|error| panic!("external process loss: {error}"));
        assert_eq!(execute(&cleaning).action(), RecoveryAction::CollectCleanup);
        let awaiting = complete_success(cleaning, 8);
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("cleanup proof: {error}"));
        let settled = RecoveryEngine::observe_fact(
            awaiting.state(),
            fact(3, 9, RuntimeFailureFactKind::CleanupCompleted(proof)),
        )
        .unwrap_or_else(|error| panic!("cleanup completion: {error}"));
        assert_eq!(settled.decision(), RecoveryDecision::NoAction);
        assert_eq!(
            settled.state().phase(),
            RecoveryPhase::Quarantined {
                reason: QuarantineReason::RecoveryActionFailed
            }
        );
        assert_eq!(settled.state().restart_attempts_in_window(), 0);
    }

    #[test]
    fn failed_stop_with_observed_loss_skips_redundant_signals_and_cleans() {
        let heartbeat = RecoveryEngine::observe_fact(
            &state(2),
            fact(
                1,
                1,
                RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 7 },
            ),
        )
        .unwrap_or_else(|error| panic!("heartbeat failure: {error}"));
        let stopping = complete_success(heartbeat, 2);
        let stop = execute(&stopping);
        let (loss, _authority) = loss_bundle(identity(7), false, Vec::new());
        let exited = RecoveryEngine::observe_fact(
            stopping.state(),
            fact(2, 3, RuntimeFailureFactKind::ProcessExited(loss)),
        )
        .unwrap_or_else(|error| panic!("process loss: {error}"));
        assert_eq!(
            exited.decision(),
            RecoveryDecision::AwaitingAction(stop.id())
        );

        let cleaning = RecoveryEngine::complete_action(
            exited.state(),
            stop.id(),
            RecoveryActionOutcome::Failed,
            at(4),
        )
        .unwrap_or_else(|error| panic!("failed stop after loss: {error}"));
        assert_eq!(execute(&cleaning).action(), RecoveryAction::CollectCleanup);
        assert_eq!(
            cleaning.state().quarantine_reason(),
            Some(QuarantineReason::RecoveryActionFailed)
        );
    }

    #[test]
    fn cleanup_action_failure_accepts_a_later_authoritative_proof() {
        let (loss, authority) = loss_bundle(identity(7), false, Vec::new());
        let fencing = RecoveryEngine::observe_fact(
            &state(2),
            fact(1, 1, RuntimeFailureFactKind::ProcessExited(loss)),
        )
        .unwrap_or_else(|error| panic!("process loss: {error}"));
        let cleaning = complete_success(fencing, 2);
        let first_collect = execute(&cleaning);
        assert_eq!(first_collect.action(), RecoveryAction::CollectCleanup);

        let entering = RecoveryEngine::complete_action(
            cleaning.state(),
            first_collect.id(),
            RecoveryActionOutcome::Failed,
            at(3),
        )
        .unwrap_or_else(|error| panic!("first cleanup failure: {error}"));
        let enter = execute(&entering);
        assert!(matches!(
            enter.action(),
            RecoveryAction::EnterQuarantine { .. }
        ));
        let retrying = complete_success(entering, 4);
        let retry_collect = execute(&retrying);
        assert_eq!(retry_collect.action(), RecoveryAction::CollectCleanup);

        let quarantined = RecoveryEngine::complete_action(
            retrying.state(),
            retry_collect.id(),
            RecoveryActionOutcome::Failed,
            at(5),
        )
        .unwrap_or_else(|error| panic!("retry cleanup failure: {error}"));
        assert_eq!(quarantined.decision(), RecoveryDecision::NoAction);
        assert_eq!(
            quarantined.state().phase(),
            RecoveryPhase::Quarantined {
                reason: QuarantineReason::RecoveryActionFailed
            }
        );

        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("late proof: {error}"));
        let settled = RecoveryEngine::observe_fact(
            quarantined.state(),
            fact(2, 6, RuntimeFailureFactKind::CleanupCompleted(proof)),
        )
        .unwrap_or_else(|error| panic!("late proof observation: {error}"));
        assert_eq!(settled.decision(), RecoveryDecision::NoAction);
        assert_eq!(
            settled.state().phase(),
            RecoveryPhase::Quarantined {
                reason: QuarantineReason::RecoveryActionFailed
            }
        );
        assert!(settled.state().cleanup_proven);
        assert_eq!(settled.state().restart_attempts_in_window(), 0);
    }

    #[test]
    fn already_exited_signal_waits_for_typed_loss_before_cleanup() {
        let failure = RecoveryEngine::observe_fact(
            &state(2),
            fact(
                1,
                1,
                RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 7 },
            ),
        )
        .unwrap_or_else(|error| panic!("failure: {error}"));
        let stopping = complete_success(failure, 2);
        assert_eq!(
            execute(&stopping).action(),
            RecoveryAction::RequestCooperativeStop
        );
        let awaiting =
            complete_with_outcome(stopping, RecoveryActionOutcome::ProcessAlreadyExited, 3);
        assert!(matches!(
            awaiting.state().phase(),
            RecoveryPhase::AwaitingProcessLoss { .. }
        ));
        assert_eq!(awaiting.state().unsettled_handoffs(), 0);

        let (_withheld_loss, authority) = loss_bundle(identity(7), false, Vec::new());
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        assert_eq!(
            RecoveryEngine::observe_fact(
                awaiting.state(),
                fact(2, 4, RuntimeFailureFactKind::CleanupCompleted(proof)),
            ),
            Err(RecoveryError::ProcessLossNotObserved)
        );
    }

    #[test]
    fn later_faults_and_process_loss_preserve_the_exact_pending_fence() {
        let initial = state(2);
        let heartbeat = RecoveryEngine::observe_fact(
            &initial,
            fact(
                1,
                1,
                RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 7 },
            ),
        )
        .unwrap_or_else(|error| panic!("heartbeat failure: {error}"));
        let fence = execute(&heartbeat);
        assert_eq!(fence.action(), RecoveryAction::FenceAndStopAdmission);
        assert_eq!(heartbeat.state().pending_action(), Some(fence));

        let protocol = RecoveryEngine::observe_fact(
            heartbeat.state(),
            fact(
                2,
                2,
                RuntimeFailureFactKind::ProtocolViolation(ProcessProtocolFailure::InvalidFrame),
            ),
        )
        .unwrap_or_else(|error| panic!("protocol failure: {error}"));
        assert_eq!(
            protocol.decision(),
            RecoveryDecision::AwaitingAction(fence.id())
        );
        assert_eq!(protocol.state().pending_action(), Some(fence));

        let (loss, authority) = loss_bundle(identity(7), false, Vec::new());
        let exited = RecoveryEngine::observe_fact(
            protocol.state(),
            fact(3, 3, RuntimeFailureFactKind::ProcessExited(loss)),
        )
        .unwrap_or_else(|error| panic!("process loss: {error}"));
        assert_eq!(
            exited.decision(),
            RecoveryDecision::AwaitingAction(fence.id())
        );
        assert_eq!(exited.state().pending_action(), Some(fence));

        let cleaning = RecoveryEngine::complete_action(
            exited.state(),
            fence.id(),
            RecoveryActionOutcome::Succeeded,
            at(4),
        )
        .unwrap_or_else(|error| panic!("fence completion: {error}"));
        let collect = execute(&cleaning);
        assert_eq!(collect.action(), RecoveryAction::CollectCleanup);
        assert_eq!(cleaning.state().pending_action(), Some(collect));

        let awaiting = complete_success(cleaning, 5);
        assert!(matches!(
            awaiting.state().phase(),
            RecoveryPhase::AwaitingCleanup { .. }
        ));
        assert_eq!(awaiting.state().pending_action(), None);
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("cleanup proof: {error}"));
        let restart = RecoveryEngine::observe_fact(
            awaiting.state(),
            fact(4, 6, RuntimeFailureFactKind::CleanupCompleted(proof)),
        )
        .unwrap_or_else(|error| panic!("cleanup completion: {error}"));
        assert!(matches!(restart.decision(), RecoveryDecision::WaitUntil(_)));
    }

    #[test]
    fn each_resource_limit_fact_fences_and_has_a_distinct_fingerprint() {
        let failures = [
            ProcessResourceFailure::Memory,
            ProcessResourceFailure::OpenFds,
            ProcessResourceFailure::ProcessTree,
            ProcessResourceFailure::Cpu,
        ];
        for (index, failure) in failures.into_iter().enumerate() {
            let transition = RecoveryEngine::observe_fact(
                &state(2),
                fact(1, 1, RuntimeFailureFactKind::ResourceLimitExceeded(failure)),
            )
            .unwrap_or_else(|error| panic!("resource failure: {error}"));
            let fence = execute(&transition);
            assert_eq!(fence.action(), RecoveryAction::FenceAndStopAdmission);
            let duplicate = RecoveryEngine::observe_fact(
                transition.state(),
                fact(1, 1, RuntimeFailureFactKind::ResourceLimitExceeded(failure)),
            )
            .unwrap_or_else(|error| panic!("duplicate resource failure: {error}"));
            assert_eq!(
                duplicate.decision(),
                RecoveryDecision::AwaitingAction(fence.id())
            );

            let different = failures[(index + 1) % failures.len()];
            assert_eq!(
                RecoveryEngine::observe_fact(
                    transition.state(),
                    fact(
                        1,
                        1,
                        RuntimeFailureFactKind::ResourceLimitExceeded(different),
                    ),
                ),
                Err(RecoveryError::ConflictingFact)
            );
        }
    }

    #[test]
    fn owner_invariant_facts_have_distinct_fingerprints() {
        let failures = [
            ProcessOwnerInvariantFailure::GenerationMismatch,
            ProcessOwnerInvariantFailure::ClockMismatch,
            ProcessOwnerInvariantFailure::ClockRegressed,
            ProcessOwnerInvariantFailure::DeadlineOverflow,
            ProcessOwnerInvariantFailure::StateInconsistent,
        ];
        for (index, failure) in failures.into_iter().enumerate() {
            let transition = RecoveryEngine::observe_fact(
                &state(2),
                fact(
                    1,
                    1,
                    RuntimeFailureFactKind::OwnerInvariantViolation(failure),
                ),
            )
            .unwrap_or_else(|error| panic!("owner invariant: {error}"));
            assert_eq!(
                execute(&transition).action(),
                RecoveryAction::FenceAndStopAdmission
            );
            assert_eq!(
                transition.state().quarantine_reason(),
                Some(QuarantineReason::OwnerInvariantViolation)
            );
            let different = failures[(index + 1) % failures.len()];
            assert_eq!(
                RecoveryEngine::observe_fact(
                    transition.state(),
                    fact(
                        1,
                        1,
                        RuntimeFailureFactKind::OwnerInvariantViolation(different),
                    ),
                ),
                Err(RecoveryError::ConflictingFact)
            );
        }
    }

    #[test]
    fn owner_invariant_quarantine_still_requires_loss_and_cleanup_proof() {
        let fencing = RecoveryEngine::observe_fact(
            &state(2),
            fact(
                1,
                1,
                RuntimeFailureFactKind::OwnerInvariantViolation(
                    ProcessOwnerInvariantFailure::ClockRegressed,
                ),
            ),
        )
        .unwrap_or_else(|error| panic!("owner invariant: {error}"));
        assert_eq!(
            execute(&fencing).action(),
            RecoveryAction::FenceAndStopAdmission
        );
        let stopping = complete_success(fencing, 2);
        let stop = execute(&stopping);
        assert_eq!(stop.action(), RecoveryAction::RequestCooperativeStop);
        assert_eq!(
            stopping.state().quarantine_reason(),
            Some(QuarantineReason::OwnerInvariantViolation)
        );

        let (loss, authority) = loss_bundle(identity(7), false, Vec::new());
        let exited = RecoveryEngine::observe_fact(
            stopping.state(),
            fact(2, 3, RuntimeFailureFactKind::ProcessExited(loss)),
        )
        .unwrap_or_else(|error| panic!("loss after owner invariant: {error}"));
        assert_eq!(
            exited.decision(),
            RecoveryDecision::AwaitingAction(stop.id())
        );
        let cleaning = RecoveryEngine::complete_action(
            exited.state(),
            stop.id(),
            RecoveryActionOutcome::ProcessAlreadyExited,
            at(4),
        )
        .unwrap_or_else(|error| panic!("stop after owner loss: {error}"));
        assert_eq!(execute(&cleaning).action(), RecoveryAction::CollectCleanup);
        let awaiting = complete_success(cleaning, 5);
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("cleanup proof: {error}"));
        let entering = RecoveryEngine::observe_fact(
            awaiting.state(),
            fact(3, 6, RuntimeFailureFactKind::CleanupCompleted(proof)),
        )
        .unwrap_or_else(|error| panic!("cleanup after owner invariant: {error}"));
        assert_eq!(
            execute(&entering).action(),
            RecoveryAction::EnterQuarantine {
                reason: QuarantineReason::OwnerInvariantViolation
            }
        );
        let settled = complete_success(entering, 7);
        assert_eq!(
            settled.state().phase(),
            RecoveryPhase::Quarantined {
                reason: QuarantineReason::OwnerInvariantViolation
            }
        );
        assert!(settled.state().cleanup_proven);
        assert_eq!(settled.state().restart_attempts_in_window(), 0);
        assert_eq!(
            settled.state().replay_policy(),
            InvocationReplayPolicy::NoReplay
        );
    }

    #[test]
    fn process_loss_preserves_an_already_pending_stop_action() {
        let heartbeat = RecoveryEngine::observe_fact(
            &state(2),
            fact(
                1,
                1,
                RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 7 },
            ),
        )
        .unwrap_or_else(|error| panic!("heartbeat failure: {error}"));
        let stopping = complete_success(heartbeat, 2);
        let stop = execute(&stopping);
        assert_eq!(stop.action(), RecoveryAction::RequestCooperativeStop);
        assert_eq!(stopping.state().pending_action(), Some(stop));

        let protocol = RecoveryEngine::observe_fact(
            stopping.state(),
            fact(
                2,
                3,
                RuntimeFailureFactKind::ProtocolViolation(ProcessProtocolFailure::InvalidFrame),
            ),
        )
        .unwrap_or_else(|error| panic!("protocol failure: {error}"));
        assert_eq!(protocol.state().pending_action(), Some(stop));

        let (loss, _authority) = loss_bundle(identity(7), false, Vec::new());
        let exited = RecoveryEngine::observe_fact(
            protocol.state(),
            fact(3, 4, RuntimeFailureFactKind::ProcessExited(loss)),
        )
        .unwrap_or_else(|error| panic!("process loss: {error}"));
        assert_eq!(
            exited.decision(),
            RecoveryDecision::AwaitingAction(stop.id())
        );
        assert_eq!(exited.state().pending_action(), Some(stop));

        let cleaning = RecoveryEngine::complete_action(
            exited.state(),
            stop.id(),
            RecoveryActionOutcome::ProcessAlreadyExited,
            at(5),
        )
        .unwrap_or_else(|error| panic!("stop completion: {error}"));
        assert_eq!(execute(&cleaning).action(), RecoveryAction::CollectCleanup);
    }

    #[test]
    fn planned_exit_still_executes_fence_before_cleanup_and_stop() {
        let (loss, authority) = loss_bundle(identity(7), true, Vec::new());
        let fencing = RecoveryEngine::observe_fact(
            &state(2),
            fact(1, 1, RuntimeFailureFactKind::ProcessExited(loss)),
        )
        .unwrap_or_else(|error| panic!("planned loss: {error}"));
        assert_eq!(
            execute(&fencing).action(),
            RecoveryAction::FenceAndStopAdmission
        );
        let cleaning = complete_success(fencing, 2);
        assert_eq!(execute(&cleaning).action(), RecoveryAction::CollectCleanup);
        let awaiting = complete_success(cleaning, 3);
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        let stopped = RecoveryEngine::observe_fact(
            awaiting.state(),
            fact(2, 4, RuntimeFailureFactKind::CleanupCompleted(proof)),
        )
        .unwrap_or_else(|error| panic!("cleanup: {error}"));
        assert_eq!(stopped.state().phase(), RecoveryPhase::Stopped);
        assert_eq!(stopped.decision(), RecoveryDecision::NoAction);
    }

    #[test]
    fn planned_exit_with_crossed_external_effect_is_quarantined() {
        let crossed_handoff = ProcessInvocationOwnership::new(
            invocation(1),
            ProcessInvocationOwnershipStage::HandoffStarted,
            SideEffectClass::External,
            true,
            17,
        );
        let (loss, authority) = loss_bundle(identity(7), true, vec![crossed_handoff]);
        let fencing = RecoveryEngine::observe_fact(
            &state(2),
            fact(1, 1, RuntimeFailureFactKind::ProcessExited(loss)),
        )
        .unwrap_or_else(|error| panic!("planned loss: {error}"));
        let cleaning = complete_success(fencing, 2);
        let awaiting = complete_success(cleaning, 3);
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        let quarantining = RecoveryEngine::observe_fact(
            awaiting.state(),
            fact(2, 4, RuntimeFailureFactKind::CleanupCompleted(proof)),
        )
        .unwrap_or_else(|error| panic!("cleanup: {error}"));
        assert_eq!(
            execute(&quarantining).action(),
            RecoveryAction::EnterQuarantine {
                reason: QuarantineReason::ExternalEffectUncertain,
            }
        );
    }

    #[test]
    fn cleanup_proof_must_match_the_observed_loss_lineage() {
        let (observed_loss, _matching_authority) = loss_bundle(identity(7), false, Vec::new());
        let unrelated_handoff = ProcessInvocationOwnership::new(
            invocation(1),
            ProcessInvocationOwnershipStage::HandoffStarted,
            SideEffectClass::EffectFree,
            true,
            17,
        );
        let (_unrelated_loss, unrelated_authority) =
            loss_bundle(identity(7), false, vec![unrelated_handoff]);
        let fencing = RecoveryEngine::observe_fact(
            &state(2),
            fact(1, 1, RuntimeFailureFactKind::ProcessExited(observed_loss)),
        )
        .unwrap_or_else(|error| panic!("loss: {error}"));
        let cleaning = complete_success(fencing, 2);
        let awaiting = complete_success(cleaning, 3);
        let unrelated_proof = unrelated_authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));

        assert_eq!(
            RecoveryEngine::observe_fact(
                awaiting.state(),
                fact(
                    2,
                    4,
                    RuntimeFailureFactKind::CleanupCompleted(unrelated_proof),
                ),
            ),
            Err(RecoveryError::CleanupLineageMismatch)
        );
    }

    #[test]
    fn cleanup_fact_deduplication_includes_the_loss_lineage() {
        let CleanupFixture {
            state: current,
            authority,
        } = reach_cleanup(state(2));
        let matching_proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("matching proof: {error}"));
        let accepted = RecoveryEngine::observe_fact(
            &current,
            fact(
                2,
                4,
                RuntimeFailureFactKind::CleanupCompleted(matching_proof),
            ),
        )
        .unwrap_or_else(|error| panic!("matching cleanup: {error}"));

        let unrelated_handoff = ProcessInvocationOwnership::new(
            invocation(1),
            ProcessInvocationOwnershipStage::HandoffStarted,
            SideEffectClass::EffectFree,
            true,
            17,
        );
        let (_unrelated_loss, unrelated_authority) =
            loss_bundle(identity(7), false, vec![unrelated_handoff]);
        let unrelated_proof = unrelated_authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("unrelated proof: {error}"));

        assert_eq!(
            RecoveryEngine::observe_fact(
                accepted.state(),
                fact(
                    2,
                    4,
                    RuntimeFailureFactKind::CleanupCompleted(unrelated_proof),
                ),
            ),
            Err(RecoveryError::ConflictingFact)
        );
    }

    #[test]
    fn external_or_unknown_effect_uncertain_is_sticky_quarantine() {
        for side_effect in [SideEffectClass::External, SideEffectClass::Unknown] {
            let crossed_handoff = ProcessInvocationOwnership::new(
                invocation(1),
                ProcessInvocationOwnershipStage::HandoffStarted,
                side_effect,
                true,
                17,
            );
            let (loss, authority) = loss_bundle(identity(7), false, vec![crossed_handoff]);
            let transition = RecoveryEngine::observe_fact(
                &state(2),
                fact(1, 1, RuntimeFailureFactKind::ProcessExited(loss)),
            )
            .unwrap_or_else(|error| panic!("loss: {error}"));
            let transition = complete_success(transition, 2);
            assert_eq!(
                execute(&transition).action(),
                RecoveryAction::CollectCleanup
            );
            let transition = complete_success(transition, 3);
            let current = transition.into_state();
            let proof = authority
                .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
                .unwrap_or_else(|error| panic!("proof: {error}"));
            let transition = RecoveryEngine::observe_fact(
                &current,
                fact(2, 4, RuntimeFailureFactKind::CleanupCompleted(proof)),
            )
            .unwrap_or_else(|error| panic!("cleanup: {error}"));
            assert_eq!(
                execute(&transition).action(),
                RecoveryAction::EnterQuarantine {
                    reason: QuarantineReason::ExternalEffectUncertain
                }
            );
            assert!(transition.state().external_effect_uncertain());
            let transition = complete_success(transition, 5);
            assert_eq!(
                RecoveryEngine::observe_fact(
                    transition.state(),
                    fact(
                        3,
                        7,
                        RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 9 },
                    ),
                )
                .unwrap_or_else(|error| panic!("sticky fact: {error}"))
                .state()
                .phase(),
                RecoveryPhase::Quarantined {
                    reason: QuarantineReason::ExternalEffectUncertain
                }
            );
        }
    }

    #[test]
    fn exact_cleanup_proof_is_required_before_backoff() {
        let CleanupFixture { state: current, .. } = reach_cleanup(state(2));
        let transition = RecoveryEngine::observe_fact(
            &current,
            fact(
                2,
                4,
                RuntimeFailureFactKind::CleanupIncomplete(ProcessCleanupCensus::new(
                    true, 1, 0, 0, 0, 0, 0,
                )),
            ),
        )
        .unwrap_or_else(|error| panic!("cleanup incomplete: {error}"));
        assert_eq!(
            execute(&transition).action(),
            RecoveryAction::EnterQuarantine {
                reason: QuarantineReason::CleanupNotProven
            }
        );
    }

    #[test]
    fn cleanup_proof_at_deadline_is_too_late() {
        let CleanupFixture {
            state: current,
            authority,
        } = reach_cleanup(state(2));
        let RecoveryPhase::AwaitingCleanup { deadline } = current.phase() else {
            panic!("must await cleanup")
        };
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        let transition = RecoveryEngine::observe_fact(
            &current,
            fact(
                2,
                deadline.value(),
                RuntimeFailureFactKind::CleanupCompleted(proof),
            ),
        )
        .unwrap_or_else(|error| panic!("late cleanup: {error}"));
        assert_eq!(
            execute(&transition).action(),
            RecoveryAction::EnterQuarantine {
                reason: QuarantineReason::CleanupNotProven
            }
        );
    }

    #[test]
    fn external_uncertainty_cancels_backoff_and_pending_spawn() {
        let CleanupFixture {
            state: current,
            authority,
        } = reach_cleanup(state(2));
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        let backoff = RecoveryEngine::observe_fact(
            &current,
            fact(2, 4, RuntimeFailureFactKind::CleanupCompleted(proof)),
        )
        .unwrap_or_else(|error| panic!("cleanup: {error}"));
        let external_invocation = ProcessInvocationFailure::new(
            InstanceRef::from_bytes([9; 16]),
            generation(1),
            invocation(1),
            SideEffectClass::External,
        );
        let transition = RecoveryEngine::observe_fact(
            backoff.state(),
            fact(
                3,
                5,
                RuntimeFailureFactKind::InvocationUncertain(external_invocation),
            ),
        )
        .unwrap_or_else(|error| panic!("late uncertainty: {error}"));
        assert_eq!(
            execute(&transition).action(),
            RecoveryAction::EnterQuarantine {
                reason: QuarantineReason::ExternalEffectUncertain
            }
        );

        let RecoveryDecision::WaitUntil(restart_at) = backoff.decision() else {
            panic!("must await restart")
        };
        let spawning = RecoveryEngine::poll(backoff.state(), at(restart_at.value()))
            .unwrap_or_else(|error| panic!("spawn poll: {error}"));
        let unknown_invocation = ProcessInvocationFailure::new(
            InstanceRef::from_bytes([9; 16]),
            generation(1),
            invocation(2),
            SideEffectClass::Unknown,
        );
        let uncertain = RecoveryEngine::observe_fact(
            spawning.state(),
            fact(
                3,
                restart_at.value(),
                RuntimeFailureFactKind::InvocationUncertain(unknown_invocation),
            ),
        )
        .unwrap_or_else(|error| panic!("spawn uncertainty: {error}"));
        let spawn = execute(&spawning);
        assert_eq!(
            uncertain.decision(),
            RecoveryDecision::AwaitingAction(spawn.id())
        );
        let transition = RecoveryEngine::complete_action(
            uncertain.state(),
            spawn.id(),
            RecoveryActionOutcome::Succeeded,
            at(restart_at.value() + 1),
        )
        .unwrap_or_else(|error| panic!("spawn completion: {error}"));
        assert_eq!(
            execute(&transition).action(),
            RecoveryAction::EnterQuarantine {
                reason: QuarantineReason::ExternalEffectUncertain
            }
        );
    }

    #[test]
    fn duplicate_fact_and_action_completion_are_idempotent_but_conflicts_fail() {
        let first_fact = fact(
            1,
            1,
            RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 7 },
        );
        let transition = RecoveryEngine::observe_fact(&state(2), first_fact)
            .unwrap_or_else(|error| panic!("first fact: {error}"));
        let action = execute(&transition);
        let duplicate = RecoveryEngine::observe_fact(
            transition.state(),
            fact(
                1,
                1,
                RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 7 },
            ),
        )
        .unwrap_or_else(|error| panic!("duplicate fact: {error}"));
        assert_eq!(
            duplicate.decision(),
            RecoveryDecision::AwaitingAction(action.id())
        );
        assert_eq!(
            RecoveryEngine::observe_fact(
                transition.state(),
                fact(
                    1,
                    1,
                    RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 8 },
                ),
            ),
            Err(RecoveryError::ConflictingFact)
        );

        let completed = RecoveryEngine::complete_action(
            transition.state(),
            action.id(),
            RecoveryActionOutcome::Succeeded,
            at(2),
        )
        .unwrap_or_else(|error| panic!("completion: {error}"));
        let duplicate = RecoveryEngine::complete_action(
            completed.state(),
            action.id(),
            RecoveryActionOutcome::Succeeded,
            at(2),
        )
        .unwrap_or_else(|error| panic!("duplicate completion: {error}"));
        let next_action = execute(&completed);
        assert_eq!(
            duplicate.decision(),
            RecoveryDecision::AwaitingAction(next_action.id())
        );
        assert_eq!(
            RecoveryEngine::complete_action(
                completed.state(),
                action.id(),
                RecoveryActionOutcome::Failed,
                at(2),
            ),
            Err(RecoveryError::ConflictingActionCompletion)
        );
    }

    #[test]
    fn restart_window_and_attempt_ledger_cross_generation_fences() {
        let recovered = complete_one_restart(state(2));
        assert_eq!(recovered.restart_attempts_in_window(), 1);
        assert_eq!(
            recovered.phase(),
            RecoveryPhase::Recovered {
                next_epoch: domain_epoch(6)
            }
        );
        let roll_at = recovered.last_observed_at.now().value() + 1;
        assert_eq!(
            RecoveryEngine::roll_generation(&recovered, identity_with_epoch(8, 6), at(roll_at)),
            Err(RecoveryError::GenerationContinuityMismatch)
        );
        let fresh =
            RecoveryEngine::roll_generation(&recovered, identity_with_epoch(7, 6), at(roll_at))
                .unwrap_or_else(|error| panic!("first roll: {error}"));
        assert_eq!(fresh.phase(), RecoveryPhase::Healthy);
        assert_eq!(fresh.restart_attempts_in_window(), 1);

        let recovered = complete_one_restart(fresh);
        assert_eq!(recovered.restart_attempts_in_window(), 2);
        let roll_at = recovered.last_observed_at.now().value() + 1;
        let fresh =
            RecoveryEngine::roll_generation(&recovered, identity_with_epoch(7, 7), at(roll_at))
                .unwrap_or_else(|error| panic!("second roll: {error}"));
        let CleanupFixture {
            state: current,
            authority,
        } = reach_cleanup(fresh);
        let identity = current.identity();
        let cleanup_ticks = current.last_observed_at.now().value() + 1;
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        let transition = RecoveryEngine::observe_fact(
            &current,
            fact_for(
                identity,
                2,
                cleanup_ticks,
                RuntimeFailureFactKind::CleanupCompleted(proof),
            ),
        )
        .unwrap_or_else(|error| panic!("third cleanup: {error}"));
        assert_eq!(transition.state().restart_attempts_in_window(), 2);
        assert_eq!(
            execute(&transition).action(),
            RecoveryAction::EnterQuarantine {
                reason: QuarantineReason::RestartAttemptsExhausted
            }
        );
    }

    #[test]
    fn expired_attempt_leaves_the_restart_window() {
        let recovered = complete_one_restart(state(1));
        let roll_at = recovered.last_observed_at.now().value() + 1;
        let fresh =
            RecoveryEngine::roll_generation(&recovered, identity_with_epoch(7, 6), at(roll_at))
                .unwrap_or_else(|error| panic!("roll: {error}"));
        let fresh = RecoveryEngine::poll(&fresh, at(200))
            .unwrap_or_else(|error| panic!("advance clock: {error}"))
            .into_state();
        let CleanupFixture {
            state: current,
            authority,
        } = reach_cleanup(fresh);
        let identity = current.identity();
        let cleanup_ticks = current.last_observed_at.now().value() + 1;
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        let transition = RecoveryEngine::observe_fact(
            &current,
            fact_for(
                identity,
                2,
                cleanup_ticks,
                RuntimeFailureFactKind::CleanupCompleted(proof),
            ),
        )
        .unwrap_or_else(|error| panic!("cleanup after window: {error}"));
        assert!(matches!(
            transition.decision(),
            RecoveryDecision::WaitUntil(_)
        ));
        assert_eq!(transition.state().restart_attempts_in_window(), 0);
    }

    #[test]
    fn escalation_deadlines_are_ordered_and_cleanup_timeout_quarantines() {
        let transition = RecoveryEngine::observe_fact(
            &state(2),
            fact(
                1,
                1,
                RuntimeFailureFactKind::HeartbeatMissed { last_sequence: 1 },
            ),
        )
        .unwrap_or_else(|error| panic!("failure: {error}"));
        let transition = complete_success(transition, 2);
        assert_eq!(
            execute(&transition).action(),
            RecoveryAction::RequestCooperativeStop
        );
        let transition = complete_success(transition, 3);
        let RecoveryPhase::WaitingCooperative { deadline } = transition.state().phase() else {
            panic!("must await cooperative deadline")
        };
        let transition = RecoveryEngine::poll(transition.state(), at(deadline.value()))
            .unwrap_or_else(|error| panic!("cooperative poll: {error}"));
        assert_eq!(execute(&transition).action(), RecoveryAction::SendTerminate);
        let transition = complete_success(transition, deadline.value() + 1);
        let RecoveryPhase::WaitingTerminate { deadline } = transition.state().phase() else {
            panic!("must await terminate deadline")
        };
        let transition = RecoveryEngine::poll(transition.state(), at(deadline.value()))
            .unwrap_or_else(|error| panic!("terminate poll: {error}"));
        assert_eq!(execute(&transition).action(), RecoveryAction::SendKill);
        let transition = complete_success(transition, deadline.value() + 1);
        let RecoveryPhase::WaitingKill { deadline } = transition.state().phase() else {
            panic!("must await kill deadline")
        };
        let transition = RecoveryEngine::poll(transition.state(), at(deadline.value()))
            .unwrap_or_else(|error| panic!("kill poll: {error}"));
        assert_eq!(
            execute(&transition).action(),
            RecoveryAction::EnterQuarantine {
                reason: QuarantineReason::CleanupNotProven
            }
        );
    }

    #[test]
    fn zero_restart_budget_quarantines_and_clock_mismatch_is_rejected() {
        let CleanupFixture {
            state: current,
            authority,
        } = reach_cleanup(state(0));
        let proof = authority
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        let transition = RecoveryEngine::observe_fact(
            &current,
            fact(2, 4, RuntimeFailureFactKind::CleanupCompleted(proof)),
        )
        .unwrap_or_else(|error| panic!("cleanup: {error}"));
        assert_eq!(
            execute(&transition).action(),
            RecoveryAction::EnterQuarantine {
                reason: QuarantineReason::RestartAttemptsExhausted
            }
        );

        let wrong_clock = ClockReading::new(
            ClockDomainRef::from_bytes([99; 16]),
            clock_generation(1),
            MonotonicInstant::from_ticks(5),
        );
        assert_eq!(
            RecoveryEngine::poll(transition.state(), wrong_clock),
            Err(RecoveryError::ClockMismatch)
        );
    }

    #[test]
    fn deterministic_hash_jitter_is_stable_for_same_state() {
        let make_transition = || {
            let CleanupFixture {
                state: current,
                authority,
            } = reach_cleanup(state(2));
            let proof = authority
                .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
                .unwrap_or_else(|error| panic!("proof: {error}"));
            RecoveryEngine::observe_fact(
                &current,
                fact(2, 4, RuntimeFailureFactKind::CleanupCompleted(proof)),
            )
            .unwrap_or_else(|error| panic!("cleanup: {error}"))
        };
        let first = make_transition();
        let second = make_transition();
        assert_eq!(first.decision(), second.decision());
        let RecoveryDecision::WaitUntil(at) = first.decision() else {
            panic!("expected backoff")
        };
        assert!((14..=16).contains(&at.value()));
    }
}
