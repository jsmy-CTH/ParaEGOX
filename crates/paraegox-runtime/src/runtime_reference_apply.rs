//! Durable Runtime apply owner for the strict reference control profile.
//!
//! This first tranche owns admission commits, exact terminal replay and the
//! already-exact-zero no-effect path.  Materialized Loop start/retire paths are
//! added behind the same store/owner boundary; this module never fabricates
//! ingress authentication, policy evidence, resource ownership or tombstones.

use ed25519_dalek::{Signer, SigningKey};
use paraegox_kernel::{
    digest::{Digest32, Digest32Builder},
    identity::PrincipalRef,
    time::ClockGeneration,
};
use paraegox_runtime_contracts::{
    provenance::{PlanProvenance, TargetSliceDigest},
    reference_control::{
        ReferenceApplyRequestV1, ReferenceApplyTerminalFactsV1, ReferenceApplyTerminalHeadV1,
        ReferenceApplyTerminalLifecycleEffectV1, ReferenceApplyTerminalOutcomeV1,
        ReferenceApplyTerminalReceiptAuthClaimV1, ReferenceApplyTerminalReceiptDraftV1,
        ReferenceApplyTerminalReceiptV1, ReferenceAssemblyModeV1, ReferenceChannelBindingV1,
        ReferenceTargetExecutionPlanV4, ValidatedReferenceLifecycleBudgetsV1,
    },
    wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef},
};

use super::{
    RuntimeAdmissionDisposition, RuntimeControlState, RuntimeControlStateError,
    RuntimeReferenceApplyPreflight,
};
use crate::{
    runtime_journal::{
        DesiredHeadKind, JournalActionKind, JournalActionRef, LiveMaterialization,
        OpaqueCanonicalValue, OwnedResourceRecord, PreparedOperation, PreparedPhase, RecoveryPhase,
        ResourceKind, ResourcePhase, RuntimeDeadlineObservation, RuntimeJournalSnapshot,
        RuntimeOneSourceCallbackSuccessInput, RuntimeOneSourceOwnershipInput,
        RuntimeOneSourceResourceRefs, RuntimeOneSourceTombstonesInput,
        RuntimeRecoveryCallbackOutcome, RuntimeRecoveryPlanInput, RuntimeStartActionInput,
        RuntimeTenureAdmissionInput, RuntimeTerminalInput, RuntimeTerminalPreview,
        StartupRecoveryEligibility, TerminalHeadDisposition, TerminalOutcome,
        decode_and_validate_terminal_receipt,
    },
    runtime_store::RuntimeStore,
};

const RECOVERY_DEADLINE_EVIDENCE_DOMAIN: &[u8] =
    b"paraegox.runtime.restart-reassembly.deadline.sha256.v1";
const RECOVERY_OWNER_FAILURE_DOMAIN: &[u8] =
    b"paraegox.runtime.restart-reassembly.owner-failure.sha256.v1";
// This owner-local cap is fingerprinted by the pinned Runtime executable. It
// bounds restart work independently of a potentially much larger signed Slice
// lifecycle budget.
const RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS: u64 = 60_000_000_000;

/// Narrow durable-store port used by apply.  The production implementation is
/// the crash-consistent `RuntimeStore`; focused tests can inject deterministic
/// failures without weakening the production store.
pub(crate) trait RuntimeReferenceApplyStore {
    fn current_snapshot(&self) -> Result<RuntimeJournalSnapshot, RuntimeReferenceApplyStoreError>;

    fn commit_snapshot(
        &mut self,
        next: RuntimeJournalSnapshot,
    ) -> Result<(), RuntimeReferenceApplyStoreError>;
}

impl RuntimeReferenceApplyStore for RuntimeStore {
    fn current_snapshot(&self) -> Result<RuntimeJournalSnapshot, RuntimeReferenceApplyStoreError> {
        self.snapshot()
            .cloned()
            .map_err(|_| RuntimeReferenceApplyStoreError::Unavailable)
    }

    fn commit_snapshot(
        &mut self,
        next: RuntimeJournalSnapshot,
    ) -> Result<(), RuntimeReferenceApplyStoreError> {
        self.commit(next)
            .map_err(|_| RuntimeReferenceApplyStoreError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeReferenceApplyStoreError {
    Unavailable,
}

/// Owner monotonic-clock port.  Implementations return a real observation in
/// the already-installed Runtime clock generation.
pub(crate) trait RuntimeReferenceApplyClock {
    fn observe(
        &mut self,
        expected_clock_generation: u64,
    ) -> Result<RuntimeDeadlineObservation, RuntimeReferenceApplyClockError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeReferenceApplyClockError {
    Unavailable,
}

/// Fresh owner identities and fixed logical resources prepared in memory
/// before the start-intent commit.  Preparing this value must not invoke the
/// lifecycle callback or allocate an externally visible resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeOneSourceOwnerPlan {
    pub(crate) action_id: [u8; 16],
    pub(crate) domain_generation: u64,
    pub(crate) instance_generation: u64,
    pub(crate) resource_generation: u64,
    pub(crate) resources: RuntimeOneSourceResourceRefs,
    pub(crate) signed_budgets: ValidatedReferenceLifecycleBudgetsV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeEmptyRetireOwnerPlan {
    pub(crate) action_id: [u8; 16],
    pub(crate) signed_budgets: ValidatedReferenceLifecycleBudgetsV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeReferenceMaterializationOwnerError {
    Unavailable,
    MissingInMemoryToken,
    ConflictingEvidence,
    CallbackFailed,
    CleanupFailed,
}

/// Real materialization-owner port.  Implementations retain an in-memory token
/// keyed by the exact action and make every method idempotent for that token.
/// A fresh process without the token must return `MissingInMemoryToken`; the
/// core then fails closed instead of laundering journal phase into ownership.
pub(crate) trait RuntimeReferenceMaterializationOwner {
    fn prepare_one_source(
        &mut self,
        request: &ReferenceApplyRequestV1,
        durable_action: Option<JournalActionRef>,
    ) -> Result<RuntimeOneSourceOwnerPlan, RuntimeReferenceMaterializationOwnerError>;

    fn materialize_one_source(
        &mut self,
        action: JournalActionRef,
        resources: RuntimeOneSourceResourceRefs,
    ) -> Result<RuntimeOneSourceOwnershipInput, RuntimeReferenceMaterializationOwnerError>;

    fn start_one_source_once(
        &mut self,
        action: JournalActionRef,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError>;

    fn prepare_empty_retire(
        &mut self,
        active_slice_digest: TargetSliceDigest,
        resource_generation: u64,
        durable_action: Option<JournalActionRef>,
    ) -> Result<RuntimeEmptyRetireOwnerPlan, RuntimeReferenceMaterializationOwnerError>;

    fn stop_one_source_once(
        &mut self,
        action: JournalActionRef,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError>;

    fn cleanup_one_source_once(
        &mut self,
        action: JournalActionRef,
    ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError>;

    fn prove_restart_exact_zero(
        &mut self,
        _execution: &ReferenceTargetExecutionPlanV4,
        _provenance: PlanProvenance,
        _target_slice_digest: TargetSliceDigest,
        _resources: &[OwnedResourceRecord],
    ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn prove_restart_action_exact_zero(
        &mut self,
        _execution: &ReferenceTargetExecutionPlanV4,
        _provenance: PlanProvenance,
        _target_slice_digest: TargetSliceDigest,
        _action: JournalActionRef,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn prove_interrupted_normal_action_exact_zero(
        &mut self,
        _execution: &ReferenceTargetExecutionPlanV4,
        _provenance: PlanProvenance,
        _target_slice_digest: TargetSliceDigest,
        _action: JournalActionRef,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn prepare_recovery_one_source(
        &mut self,
        _execution: &ReferenceTargetExecutionPlanV4,
        _provenance: PlanProvenance,
        _target_slice_digest: TargetSliceDigest,
        _durable_action: Option<JournalActionRef>,
    ) -> Result<RuntimeOneSourceOwnerPlan, RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn cleanup_recovery_one_source_once(
        &mut self,
        _action: JournalActionRef,
    ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }
}

/// Default owner used by the no-effect core constructor.  Materialized paths
/// fail closed until startup supplies a real owner implementation.
pub(crate) struct RuntimeNoMaterializationOwner;

impl RuntimeReferenceMaterializationOwner for RuntimeNoMaterializationOwner {
    fn prepare_one_source(
        &mut self,
        _request: &ReferenceApplyRequestV1,
        _durable_action: Option<JournalActionRef>,
    ) -> Result<RuntimeOneSourceOwnerPlan, RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn materialize_one_source(
        &mut self,
        _action: JournalActionRef,
        _resources: RuntimeOneSourceResourceRefs,
    ) -> Result<RuntimeOneSourceOwnershipInput, RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn start_one_source_once(
        &mut self,
        _action: JournalActionRef,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn prepare_empty_retire(
        &mut self,
        _active_slice_digest: TargetSliceDigest,
        _resource_generation: u64,
        _durable_action: Option<JournalActionRef>,
    ) -> Result<RuntimeEmptyRetireOwnerPlan, RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn stop_one_source_once(
        &mut self,
        _action: JournalActionRef,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn cleanup_one_source_once(
        &mut self,
        _action: JournalActionRef,
    ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn prove_restart_exact_zero(
        &mut self,
        _execution: &ReferenceTargetExecutionPlanV4,
        _provenance: PlanProvenance,
        _target_slice_digest: TargetSliceDigest,
        _resources: &[OwnedResourceRecord],
    ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn prepare_recovery_one_source(
        &mut self,
        _execution: &ReferenceTargetExecutionPlanV4,
        _provenance: PlanProvenance,
        _target_slice_digest: TargetSliceDigest,
        _durable_action: Option<JournalActionRef>,
    ) -> Result<RuntimeOneSourceOwnerPlan, RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn cleanup_recovery_one_source_once(
        &mut self,
        _action: JournalActionRef,
    ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError> {
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }
}

pub(crate) struct RuntimeRestartReassemblyParts<S, O> {
    pub(crate) store: S,
    pub(crate) state: RuntimeControlState,
    pub(crate) owner: O,
}

/// Runs the fixed-profile restart state machine before a listener capability
/// can exist. Every state update is committed through the same Runtime store;
/// any post-intent reopen is terminalized or quarantined and never calls
/// `on_start` again.
pub(crate) fn run_runtime_restart_reassembly<S, C, O>(
    store: S,
    state: RuntimeControlState,
    clock: C,
    owner: O,
    signer: &RuntimeReferenceApplySigner,
    execution: Option<&ReferenceTargetExecutionPlanV4>,
) -> Result<RuntimeRestartReassemblyParts<S, O>, RuntimeRestartReassemblyError>
where
    S: RuntimeReferenceApplyStore,
    C: RuntimeReferenceApplyClock,
    O: RuntimeReferenceMaterializationOwner,
{
    let mut core = RuntimeRestartReassemblyCore {
        store,
        state,
        clock,
        owner,
    };
    core.run(signer, execution)?;
    Ok(RuntimeRestartReassemblyParts {
        store: core.store,
        state: core.state,
        owner: core.owner,
    })
}

struct RuntimeRestartReassemblyCore<S, C, O> {
    store: S,
    state: RuntimeControlState,
    clock: C,
    owner: O,
}

impl<S, C, O> RuntimeRestartReassemblyCore<S, C, O>
where
    S: RuntimeReferenceApplyStore,
    C: RuntimeReferenceApplyClock,
    O: RuntimeReferenceMaterializationOwner,
{
    fn run(
        &mut self,
        signer: &RuntimeReferenceApplySigner,
        execution: Option<&ReferenceTargetExecutionPlanV4>,
    ) -> Result<(), RuntimeRestartReassemblyError> {
        let snapshot = self.state.snapshot().state();
        let prepared_reconcile = snapshot.prepared.as_ref().filter(|prepared| {
            matches!(
                prepared.phase,
                PreparedPhase::StartupExpiredNoEffects
                    | PreparedPhase::StartupReconcileRequired
                    | PreparedPhase::SupersededBeforeEffects
                    | PreparedPhase::SupersededReconcileRequired
            )
        });
        let has_prepared_reconcile = prepared_reconcile.is_some();
        let active = snapshot.active_desired.as_ref();
        let has_nonterminal_resources = snapshot
            .owned_resources
            .iter()
            .any(|resource| !resource.phase.is_terminal());
        if active.is_none()
            && !has_prepared_reconcile
            && snapshot.recovery_action.is_none()
            && !has_nonterminal_resources
        {
            return Ok(());
        }
        if active.is_some_and(|active| active.kind == DesiredHeadKind::EmptyDeactivate)
            && !has_prepared_reconcile
            && snapshot.recovery_action.is_none()
            && !has_nonterminal_resources
        {
            return Ok(());
        }
        if prepared_reconcile
            .is_some_and(|prepared| prepared.phase == PreparedPhase::StartupExpiredNoEffects)
        {
            self.terminalize_aborted_no_effects(signer)?;
            return self.run(signer, execution);
        }

        let Some(execution) = execution else {
            return self.quarantine(b"restart-owner-binding-unavailable");
        };
        let Some(cleanup_provenance) = prepared_reconcile
            .and_then(|prepared| {
                prepared
                    .retiring
                    .as_ref()
                    .map(|retiring| retiring.old_slice_provenance)
                    .or((prepared.incoming_kind == DesiredHeadKind::OneSourceLoop)
                        .then_some(prepared.slice_provenance))
            })
            .or_else(|| {
                active
                    .filter(|active| active.kind == DesiredHeadKind::OneSourceLoop)
                    .map(|active| active.slice_provenance)
            })
        else {
            return self.quarantine(b"restart-cleanup-provenance-unavailable");
        };
        let cleanup_plan_provenance = cleanup_provenance.plan_provenance();
        let cleanup_slice_digest = cleanup_provenance.target_slice_digest;
        if execution.mode() != ReferenceAssemblyModeV1::OneSourceLoop
            || execution.target().as_bytes() != &cleanup_provenance.target
        {
            return self.quarantine(b"active-execution-mismatch");
        }

        let mut startup_tombstones = None;
        if has_nonterminal_resources {
            let tombstones = match self.owner.prove_restart_exact_zero(
                execution,
                cleanup_plan_provenance,
                cleanup_slice_digest,
                &self.state.snapshot().state().owned_resources,
            ) {
                Ok(value) => value,
                Err(_) => return self.quarantine(b"old-generation-not-proven-zero"),
            };
            let next = self.state.try_begin_startup_resource_cleanup()?;
            self.commit(next)?;
            if has_prepared_reconcile {
                startup_tombstones = Some(tombstones);
            } else {
                let next = self
                    .state
                    .try_complete_startup_resource_cleanup(tombstones)?;
                self.commit(next)?;
            }
        }

        if has_prepared_reconcile {
            if startup_tombstones.is_none() {
                let action = self
                    .state
                    .snapshot()
                    .state()
                    .prepared
                    .as_ref()
                    .and_then(|prepared| prepared.action)
                    .ok_or(RuntimeRestartReassemblyError::InvalidState)?;
                if self
                    .owner
                    .prove_interrupted_normal_action_exact_zero(
                        execution,
                        cleanup_plan_provenance,
                        cleanup_slice_digest,
                        action,
                    )
                    .is_err()
                {
                    return self.quarantine(b"normal-action-not-proven-zero");
                }
            }
            return self.terminalize_interrupted_normal(signer, startup_tombstones);
        }

        let active = self
            .state
            .snapshot()
            .state()
            .active_desired
            .as_ref()
            .filter(|active| active.kind == DesiredHeadKind::OneSourceLoop)
            .ok_or(RuntimeRestartReassemblyError::InvalidState)?;
        let provenance = active.slice_provenance.plan_provenance();
        let active_slice_digest = active.slice_provenance.target_slice_digest;
        if execution.manifest_digest() != active.manifest_digest {
            return self.quarantine(b"active-manifest-mismatch");
        }

        if let Some(recovery) = self.state.snapshot().state().recovery_action {
            match recovery.phase {
                RecoveryPhase::StartupInvalidatedNoEffects => {
                    let observation = self.observe()?;
                    let next = self
                        .state
                        .try_abort_startup_invalidated_recovery(observation)?;
                    self.commit(next)?;
                }
                RecoveryPhase::StartupReconcileRequired => {
                    if self
                        .owner
                        .prove_restart_action_exact_zero(
                            execution,
                            provenance,
                            active_slice_digest,
                            recovery.action,
                        )
                        .is_err()
                    {
                        return self.quarantine(b"post-intent-action-not-proven-zero");
                    }
                    let observation = self.observe()?;
                    let next = self
                        .state
                        .try_recovery_failed_not_ready(None, observation)?;
                    self.commit(next)?;
                    return Ok(());
                }
                RecoveryPhase::RecoveryPlannedNoEffects | RecoveryPhase::StartCallIntent => {
                    return self.quarantine(b"startup-recovery-phase-not-invalidated");
                }
            }
        }

        let (eligibility, failure_evidence_digest) =
            match self.state.snapshot().state().live_materialization {
                LiveMaterialization::StartupInvalidated {
                    recovery_eligibility,
                    failure_evidence_digest,
                    ..
                } => (recovery_eligibility, failure_evidence_digest),
                LiveMaterialization::RecoveryFailedNotReady { .. }
                | LiveMaterialization::ExactZero { .. } => return Ok(()),
                _ => return self.quarantine(b"startup-live-state-not-recoverable"),
            };
        match eligibility {
            StartupRecoveryEligibility::NoActiveHead
            | StartupRecoveryEligibility::CanonicalEmptyExactZero
            | StartupRecoveryEligibility::RecoveryFailureLatched => return Ok(()),
            StartupRecoveryEligibility::ReconcileRequired => {
                let prior_failure =
                    failure_evidence_digest.ok_or(RuntimeRestartReassemblyError::InvalidState)?;
                return self
                    .quarantine_preserving_failure(b"startup-reconcile-required", prior_failure);
            }
            StartupRecoveryEligibility::EligibleOneSourceLoop => {}
        }

        let plan = match self.owner.prepare_recovery_one_source(
            execution,
            provenance,
            active_slice_digest,
            None,
        ) {
            Ok(value) => value,
            Err(_) => return self.quarantine(b"recovery-plan-owner-rejected"),
        };
        let planned_at = self.observe()?;
        let effective_start_budget_nanos =
            effective_recovery_start_budget(plan.signed_budgets.start().value());
        if effective_start_budget_nanos == 0 {
            return self.quarantine(b"recovery-budget-invalid");
        }
        let deadline_nanos = planned_at
            .observed_at_nanos
            .checked_add(effective_start_budget_nanos)
            .ok_or(RuntimeRestartReassemblyError::InvalidDeadline)?;
        let deadline_evidence_digest =
            recovery_deadline_evidence(self.state.snapshot(), plan, planned_at, deadline_nanos)?;
        let next = self.state.try_recovery_plan(RuntimeRecoveryPlanInput {
            action_id: plan.action_id,
            domain_generation: plan.domain_generation,
            instance_generation: plan.instance_generation,
            resource_generation: plan.resource_generation,
            signed_start_budget_nanos: plan.signed_budgets.start().value(),
            deadline_nanos,
            deadline_evidence_digest,
        })?;
        self.commit(next)?;

        let pre_intent = self.observe()?;
        if pre_intent.observed_at_nanos >= deadline_nanos {
            let next = self.state.try_recovery_failed_not_ready(None, pre_intent)?;
            self.commit(next)?;
            return Ok(());
        }
        let next = self.state.try_recovery_intent(pre_intent)?;
        self.commit(next)?;

        let post_intent = self.observe()?;
        if post_intent.observed_at_nanos >= deadline_nanos {
            let next = self
                .state
                .try_recovery_failed_not_ready(None, post_intent)?;
            self.commit(next)?;
            return Ok(());
        }
        let action = self
            .state
            .snapshot()
            .state()
            .recovery_action
            .ok_or(RuntimeRestartReassemblyError::InvalidState)?
            .action;
        let durable_plan = match self.owner.prepare_recovery_one_source(
            execution,
            provenance,
            active_slice_digest,
            Some(action),
        ) {
            Ok(value) if value == plan => value,
            _ => return self.quarantine(b"durable-recovery-plan-diverged"),
        };
        let next = self
            .state
            .try_reserve_recovery_resources(durable_plan.resources)?;
        self.commit(next)?;
        let ownership = match self
            .owner
            .materialize_one_source(action, durable_plan.resources)
        {
            Ok(value) => value,
            Err(_) => return self.quarantine(b"recovery-materialization-uncertain"),
        };
        let next = self.state.try_own_recovery_resources(ownership)?;
        self.commit(next)?;

        let callback = self.owner.start_one_source_once(action);
        let callback_observation = self.observe()?;
        let callback_outcome = match callback {
            Ok(()) => RuntimeRecoveryCallbackOutcome::Success,
            Err(error) => RuntimeRecoveryCallbackOutcome::Error {
                reason_digest: recovery_owner_failure_digest(error)?,
            },
        };
        let callback_succeeded = callback_outcome == RuntimeRecoveryCallbackOutcome::Success;
        let next = self
            .state
            .try_latch_recovery_callback(callback_outcome, callback_observation)?;
        self.commit(next)?;

        if callback_succeeded && callback_observation.observed_at_nanos < deadline_nanos {
            let selection = self.observe()?;
            if selection.observed_at_nanos < deadline_nanos {
                let next = self.state.try_recovery_live_ready(selection)?;
                self.commit(next)?;
                return Ok(());
            }
            let next = self.state.try_latch_recovery_deadline(selection)?;
            self.commit(next)?;
        }

        let next = self.state.try_begin_recovery_cleanup()?;
        self.commit(next)?;
        let tombstones = match self.owner.cleanup_recovery_one_source_once(action) {
            Ok(value) => value,
            Err(_) => return self.quarantine(b"recovery-cleanup-not-proven-zero"),
        };
        let selection = self.observe()?;
        let next = self
            .state
            .try_recovery_failed_not_ready(Some(tombstones), selection)?;
        self.commit(next)?;
        Ok(())
    }

    fn observe(&mut self) -> Result<RuntimeDeadlineObservation, RuntimeRestartReassemblyError> {
        let generation = self
            .state
            .snapshot()
            .state()
            .host
            .clock_generation_high_water;
        self.clock
            .observe(generation)
            .map_err(RuntimeRestartReassemblyError::Clock)
    }

    fn terminalize_interrupted_normal(
        &mut self,
        signer: &RuntimeReferenceApplySigner,
        tombstones: Option<RuntimeOneSourceTombstonesInput>,
    ) -> Result<(), RuntimeRestartReassemblyError> {
        let prepared = self
            .state
            .snapshot()
            .state()
            .prepared
            .as_ref()
            .ok_or(RuntimeRestartReassemblyError::InvalidState)?;
        let request = ReferenceApplyRequestV1::decode(&prepared.request.canonical_bytes)
            .map_err(|_| RuntimeRestartReassemblyError::InvalidState)?;
        let historical_channel = prepared
            .response_channel
            .to_contract()
            .map_err(|_| RuntimeRestartReassemblyError::InvalidState)?;
        let incoming_kind = prepared.incoming_kind;
        let observation = self.observe()?;
        let preview = match incoming_kind {
            DesiredHeadKind::OneSourceLoop => self
                .state
                .snapshot()
                .try_preview_startup_interrupted_start_terminal(tombstones.as_ref(), observation)
                .map_err(RuntimeControlStateError::from)?,
            DesiredHeadKind::EmptyDeactivate => self
                .state
                .snapshot()
                .try_preview_empty_exact_zero_terminal(tombstones.as_ref(), observation)
                .map_err(RuntimeControlStateError::from)?,
        };
        let receipt = signer
            .sign_terminal(&request, preview, historical_channel)
            .map_err(RuntimeRestartReassemblyError::Apply)?;
        let terminal = RuntimeTerminalInput {
            canonical_response: OpaqueCanonicalValue::try_terminal_response(
                receipt.canonical_wire(),
                receipt.receipt_digest(),
            )
            .map_err(RuntimeControlStateError::from)?,
            selection: observation,
        };
        let next = match incoming_kind {
            DesiredHeadKind::OneSourceLoop => self
                .state
                .try_startup_interrupted_start_terminal(tombstones, terminal)?,
            DesiredHeadKind::EmptyDeactivate => self
                .state
                .try_startup_interrupted_empty_terminal(tombstones, terminal)?,
        };
        self.commit(next)
    }

    fn terminalize_aborted_no_effects(
        &mut self,
        signer: &RuntimeReferenceApplySigner,
    ) -> Result<(), RuntimeRestartReassemblyError> {
        let prepared = self
            .state
            .snapshot()
            .state()
            .prepared
            .as_ref()
            .ok_or(RuntimeRestartReassemblyError::InvalidState)?;
        let request = ReferenceApplyRequestV1::decode(&prepared.request.canonical_bytes)
            .map_err(|_| RuntimeRestartReassemblyError::InvalidState)?;
        let historical_channel = prepared
            .response_channel
            .to_contract()
            .map_err(|_| RuntimeRestartReassemblyError::InvalidState)?;
        let observation = self.observe()?;
        let preview = self
            .state
            .snapshot()
            .try_preview_startup_aborted_no_effects_terminal(observation)
            .map_err(RuntimeControlStateError::from)?;
        let receipt = signer
            .sign_terminal(&request, preview, historical_channel)
            .map_err(RuntimeRestartReassemblyError::Apply)?;
        let terminal = RuntimeTerminalInput {
            canonical_response: OpaqueCanonicalValue::try_terminal_response(
                receipt.canonical_wire(),
                receipt.receipt_digest(),
            )
            .map_err(RuntimeControlStateError::from)?,
            selection: observation,
        };
        let next = self
            .state
            .try_startup_aborted_no_effects_terminal(terminal)?;
        self.commit(next)
    }

    fn commit(&mut self, next: RuntimeControlState) -> Result<(), RuntimeRestartReassemblyError> {
        self.store
            .commit_snapshot(next.snapshot().clone())
            .map_err(RuntimeRestartReassemblyError::Store)?;
        self.state = next;
        Ok(())
    }

    fn quarantine(&mut self, reason: &[u8]) -> Result<(), RuntimeRestartReassemblyError> {
        let reason_digest = recovery_quarantine_digest(self.state.snapshot(), reason)?;
        let next = self.state.try_operational_quarantine(reason_digest)?;
        self.commit(next)
    }

    fn quarantine_preserving_failure(
        &mut self,
        reason: &[u8],
        prior_failure: Digest32,
    ) -> Result<(), RuntimeRestartReassemblyError> {
        let reason_digest =
            recovery_quarantine_digest_with_failure(self.state.snapshot(), reason, prior_failure)?;
        let next = self.state.try_operational_quarantine(reason_digest)?;
        self.commit(next)
    }
}

const fn effective_recovery_start_budget(signed_start_budget_nanos: u64) -> u64 {
    if signed_start_budget_nanos < RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS {
        signed_start_budget_nanos
    } else {
        RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS
    }
}

fn recovery_deadline_evidence(
    snapshot: &RuntimeJournalSnapshot,
    plan: RuntimeOneSourceOwnerPlan,
    observation: RuntimeDeadlineObservation,
    deadline_nanos: u64,
) -> Result<Digest32, RuntimeRestartReassemblyError> {
    let mut digest = Digest32Builder::try_new(RECOVERY_DEADLINE_EVIDENCE_DOMAIN)
        .map_err(|_| RuntimeRestartReassemblyError::Digest)?;
    digest
        .field_u64(snapshot.sequence())
        .and_then(|builder| builder.field_bytes(&plan.action_id))
        .and_then(|builder| builder.field_u64(plan.resource_generation))
        .and_then(|builder| builder.field_u64(observation.clock_generation))
        .and_then(|builder| builder.field_u64(observation.observed_at_nanos))
        .and_then(|builder| builder.field_u64(plan.signed_budgets.start().value()))
        .and_then(|builder| builder.field_u64(RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS))
        .and_then(|builder| builder.field_u64(deadline_nanos))
        .map_err(|_| RuntimeRestartReassemblyError::Digest)?;
    Ok(digest.finish())
}

fn recovery_owner_failure_digest(
    error: RuntimeReferenceMaterializationOwnerError,
) -> Result<Digest32, RuntimeRestartReassemblyError> {
    let mut digest = Digest32Builder::try_new(RECOVERY_OWNER_FAILURE_DOMAIN)
        .map_err(|_| RuntimeRestartReassemblyError::Digest)?;
    digest
        .field_u16(error as u16)
        .map_err(|_| RuntimeRestartReassemblyError::Digest)?;
    Ok(digest.finish())
}

fn recovery_quarantine_digest(
    snapshot: &RuntimeJournalSnapshot,
    reason: &[u8],
) -> Result<Digest32, RuntimeRestartReassemblyError> {
    let mut digest = Digest32Builder::try_new(RECOVERY_OWNER_FAILURE_DOMAIN)
        .map_err(|_| RuntimeRestartReassemblyError::Digest)?;
    digest
        .field_u64(snapshot.sequence())
        .and_then(|builder| builder.field_bytes(reason))
        .map_err(|_| RuntimeRestartReassemblyError::Digest)?;
    Ok(digest.finish())
}

fn recovery_quarantine_digest_with_failure(
    snapshot: &RuntimeJournalSnapshot,
    reason: &[u8],
    prior_failure: Digest32,
) -> Result<Digest32, RuntimeRestartReassemblyError> {
    recovery_quarantine_digest_with_failure_fields(snapshot.sequence(), reason, prior_failure)
}

fn recovery_quarantine_digest_with_failure_fields(
    snapshot_sequence: u64,
    reason: &[u8],
    prior_failure: Digest32,
) -> Result<Digest32, RuntimeRestartReassemblyError> {
    let mut digest = Digest32Builder::try_new(RECOVERY_OWNER_FAILURE_DOMAIN)
        .map_err(|_| RuntimeRestartReassemblyError::Digest)?;
    digest
        .field_u64(snapshot_sequence)
        .and_then(|builder| builder.field_bytes(reason))
        .and_then(|builder| builder.field_digest(&prior_failure))
        .map_err(|_| RuntimeRestartReassemblyError::Digest)?;
    Ok(digest.finish())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeRestartReassemblyError {
    Store(RuntimeReferenceApplyStoreError),
    Clock(RuntimeReferenceApplyClockError),
    State(RuntimeControlStateError),
    Apply(RuntimeReferenceApplyError),
    InvalidState,
    InvalidDeadline,
    Digest,
}

impl From<RuntimeControlStateError> for RuntimeRestartReassemblyError {
    fn from(error: RuntimeControlStateError) -> Self {
        Self::State(error)
    }
}

/// Provisioned Runtime response signer.  Apply receives this capability from
/// startup provisioning; request/preflight input never carries a response key.
pub(crate) struct RuntimeReferenceApplySigner {
    signing_key: SigningKey,
    key_ref: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

impl RuntimeReferenceApplySigner {
    pub(crate) fn try_new(
        signing_key: SigningKey,
        key_ref: ApplyAuthKeyRef,
        algorithm: ApplyAuthAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, RuntimeReferenceApplyError> {
        if key_ref.as_bytes().iter().all(|byte| *byte == 0)
            || signing_key.verifying_key().is_weak()
            || algorithm.value() != 1
            || algorithm_version != 1
        {
            return Err(RuntimeReferenceApplyError::ResponseSignerRejected);
        }
        Ok(Self {
            signing_key,
            key_ref,
            algorithm,
            algorithm_version,
        })
    }

    pub(crate) fn sign_terminal(
        &self,
        request: &ReferenceApplyRequestV1,
        preview: RuntimeTerminalPreview,
        channel: ReferenceChannelBindingV1,
    ) -> Result<ReferenceApplyTerminalReceiptV1, RuntimeReferenceApplyError> {
        let facts = ReferenceApplyTerminalFactsV1::try_new(
            request,
            reference_outcome(preview.outcome),
            reference_lifecycle(preview.lifecycle_effect),
            reference_head(preview.head_disposition),
            preview.resource_census_digest,
            preview.raw_outcome_digest,
            preview.completion_runtime_host_epoch,
            preview.completion_snapshot_sequence,
            ClockGeneration::try_new(preview.selection_clock_generation)
                .map_err(|_| RuntimeReferenceApplyError::TerminalReceiptRejected)?,
            preview.selection_observed_at_nanos,
        )
        .map_err(|_| RuntimeReferenceApplyError::TerminalReceiptRejected)?;
        let auth_claim = ReferenceApplyTerminalReceiptAuthClaimV1::try_new(
            channel,
            self.key_ref,
            self.algorithm,
            self.algorithm_version,
        )
        .map_err(|_| RuntimeReferenceApplyError::TerminalReceiptRejected)?;
        let draft =
            ReferenceApplyTerminalReceiptDraftV1::try_new(request, facts, channel, auth_claim)
                .map_err(|_| RuntimeReferenceApplyError::TerminalReceiptRejected)?;
        let transcript = draft
            .signing_transcript()
            .map_err(|_| RuntimeReferenceApplyError::TerminalReceiptRejected)?;
        let signature = self.signing_key.sign(transcript.as_bytes());
        let receipt = draft
            .finalize(&signature.to_bytes())
            .map_err(|_| RuntimeReferenceApplyError::TerminalReceiptRejected)?;

        // Do not persist a builder-side object.  Strictly decode the exact wire
        // and verify the exact reconstructed transcript first.
        let strict = ReferenceApplyTerminalReceiptV1::decode(receipt.canonical_wire())
            .map_err(|_| RuntimeReferenceApplyError::TerminalReceiptRejected)?;
        let strict_transcript = strict
            .signing_transcript()
            .map_err(|_| RuntimeReferenceApplyError::TerminalReceiptRejected)?;
        self.signing_key
            .verifying_key()
            .verify_strict(strict_transcript.as_bytes(), &signature)
            .map_err(|_| RuntimeReferenceApplyError::ResponseSignerRejected)?;
        Ok(strict)
    }
}

/// Typed historical terminal response.  Replay returns these stored bytes and
/// the authentication binding recorded with them; it never re-signs against
/// the caller's current channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeStoredReferenceApplyReceipt {
    receipt: ReferenceApplyTerminalReceiptV1,
    original_runtime_peer: PrincipalRef,
    original_channel_binding_digest: Digest32,
}

impl RuntimeStoredReferenceApplyReceipt {
    #[must_use]
    pub(crate) const fn receipt(&self) -> &ReferenceApplyTerminalReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub(crate) fn canonical_wire(&self) -> &[u8] {
        self.receipt.canonical_wire()
    }

    #[must_use]
    pub(crate) const fn original_runtime_peer(&self) -> PrincipalRef {
        self.original_runtime_peer
    }

    #[must_use]
    pub(crate) const fn original_channel_binding_digest(&self) -> Digest32 {
        self.original_channel_binding_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeReferenceApplyOutcome {
    Terminal(Box<RuntimeStoredReferenceApplyReceipt>),
    /// A crash/retry found only the tenure commit.  No new admission deadline
    /// is installed and no action is attempted without the original capability.
    TenureOnlyDurable,
}

/// Non-durable proof that this service process successfully published one full
/// admission under the exact current writer tenure.
///
/// It is intentionally absent at construction and omitted from recovery parts.
/// Terminal replay and an already-durable full admission therefore cannot
/// manufacture permission for a later request after restart.
struct RuntimeResidentFullAdmissionTenure {
    tenure: RuntimeTenureAdmissionInput,
}

/// Single-writer apply core.  `state` is advanced only after the store confirms
/// the complete successor publication (including directory fsync in
/// `RuntimeStore::commit`).
pub(crate) struct RuntimeReferenceApplyCore<S, C, O = RuntimeNoMaterializationOwner> {
    store: S,
    state: RuntimeControlState,
    clock: C,
    owner: O,
    signer: RuntimeReferenceApplySigner,
    channel: ReferenceChannelBindingV1,
    resident_full_admitted_tenure: Option<RuntimeResidentFullAdmissionTenure>,
}

impl<S, C> RuntimeReferenceApplyCore<S, C, RuntimeNoMaterializationOwner>
where
    S: RuntimeReferenceApplyStore,
    C: RuntimeReferenceApplyClock,
{
    pub(crate) fn try_new(
        store: S,
        clock: C,
        signer: RuntimeReferenceApplySigner,
        channel: ReferenceChannelBindingV1,
    ) -> Result<Self, RuntimeReferenceApplyError> {
        Self::try_new_with_owner(store, clock, RuntimeNoMaterializationOwner, signer, channel)
    }
}

impl<S, C, O> RuntimeReferenceApplyCore<S, C, O>
where
    S: RuntimeReferenceApplyStore,
    C: RuntimeReferenceApplyClock,
    O: RuntimeReferenceMaterializationOwner,
{
    pub(crate) fn try_new_with_owner(
        store: S,
        clock: C,
        owner: O,
        signer: RuntimeReferenceApplySigner,
        channel: ReferenceChannelBindingV1,
    ) -> Result<Self, RuntimeReferenceApplyError> {
        let snapshot = store
            .current_snapshot()
            .map_err(RuntimeReferenceApplyError::Store)?;
        let state = RuntimeControlState::try_from_started_snapshot(&snapshot)?;
        Ok(Self {
            store,
            state,
            clock,
            owner,
            signer,
            channel,
            resident_full_admitted_tenure: None,
        })
    }

    #[must_use]
    pub(crate) const fn snapshot(&self) -> &RuntimeJournalSnapshot {
        self.state.snapshot()
    }

    /// Consumes the legacy apply owner only at the DeveloperLocal managed
    /// cutover boundary.  Read-only PXBR/PXQR traffic cannot alter these
    /// conditions; any legacy apply, recovery, live resource, or resident
    /// tenure makes the one-way transfer fail closed.
    pub(crate) fn into_developer_managed_cutover_store(
        self,
    ) -> Result<S, RuntimeReferenceApplyError> {
        let state = self.state.snapshot().state();
        if state.prepared.is_some()
            || state.active_desired.is_some()
            || state.recovery_action.is_some()
            || !state.owned_resources.is_empty()
            || self.resident_full_admitted_tenure.is_some()
            || !matches!(
                state.live_materialization,
                LiveMaterialization::StartupInvalidated {
                    active_slice_digest: None,
                    recovery_eligibility: StartupRecoveryEligibility::NoActiveHead,
                    failure_evidence_digest: None,
                    ..
                }
            )
        {
            return Err(RuntimeReferenceApplyError::StoreStateDiverged);
        }
        Ok(self.store)
    }

    #[cfg(test)]
    pub(crate) fn into_test_recovery_parts(
        self,
    ) -> (
        S,
        C,
        O,
        RuntimeReferenceApplySigner,
        ReferenceChannelBindingV1,
    ) {
        (
            self.store,
            self.clock,
            self.owner,
            self.signer,
            self.channel,
        )
    }

    #[cfg(test)]
    pub(crate) const fn has_test_resident_full_admitted_tenure(&self) -> bool {
        self.resident_full_admitted_tenure.is_some()
    }

    /// Looks up one exact historical terminal result without requiring a
    /// current-clock admission capability.  This is intentionally narrower
    /// than `try_apply`: it only proves that the durable store still matches
    /// the in-memory projection and then performs the request-digest-bound
    /// replay correlation.  It never renews a deadline, signs a new receipt,
    /// or mutates owner state.
    pub(crate) fn try_exact_terminal_replay(
        &self,
        request: &ReferenceApplyRequestV1,
    ) -> Result<Option<RuntimeStoredReferenceApplyReceipt>, RuntimeReferenceApplyError> {
        self.ensure_store_matches_state()?;
        self.try_terminal_replay(request)
    }

    /// Applies only strict PXAR plus ingress-produced preflight evidence.  The
    /// first executable tranche completes authoritative empty on an already
    /// exact-zero predecessor; materialized paths fail closed after admission.
    pub(crate) fn try_apply(
        &mut self,
        request: &ReferenceApplyRequestV1,
        preflight: RuntimeReferenceApplyPreflight,
    ) -> Result<RuntimeReferenceApplyOutcome, RuntimeReferenceApplyError> {
        if preflight.response_channel != self.channel {
            return Err(RuntimeControlStateError::PreflightRejected.into());
        }
        if let Some(replay) = self.try_exact_terminal_replay(request)? {
            return Ok(RuntimeReferenceApplyOutcome::Terminal(Box::new(replay)));
        }

        let tenure = self.state.try_reference_tenure_only(request, preflight)?;
        let (tenured, tenure_disposition, prepared) = tenure.into_parts();
        if tenure_disposition == RuntimeAdmissionDisposition::Committed {
            self.resident_full_admitted_tenure = None;
            self.commit_state(tenured)?;
        }
        let prepared = match prepared {
            Some(prepared) => prepared,
            None => {
                let Some(resident_tenure) = self
                    .resident_full_admitted_tenure
                    .take()
                    .map(|resident| resident.tenure)
                else {
                    return Ok(RuntimeReferenceApplyOutcome::TenureOnlyDurable);
                };
                let Some(prepared) = self.state.try_reference_resident_tenure_continuation(
                    request,
                    preflight,
                    resident_tenure,
                )?
                else {
                    return Ok(RuntimeReferenceApplyOutcome::TenureOnlyDurable);
                };
                prepared
            }
        };

        let admitted_tenure = prepared.tenure();
        let full = self.state.try_reference_full_admission(prepared)?;
        let (admitted, full_disposition, _) = full.into_parts();
        if full_disposition == RuntimeAdmissionDisposition::Committed {
            self.commit_state(admitted)?;
            self.resident_full_admitted_tenure = Some(RuntimeResidentFullAdmissionTenure {
                tenure: admitted_tenure,
            });
        }

        match request.target_execution().mode() {
            ReferenceAssemblyModeV1::OneSourceLoop => self.execute_one_source(request),
            ReferenceAssemblyModeV1::EmptyDeactivate => self.execute_empty(request),
        }
    }

    fn execute_one_source(
        &mut self,
        request: &ReferenceApplyRequestV1,
    ) -> Result<RuntimeReferenceApplyOutcome, RuntimeReferenceApplyError> {
        let prepared = self.prepared()?.clone();
        if prepared.incoming_kind != DesiredHeadKind::OneSourceLoop {
            return Err(RuntimeReferenceApplyError::TerminalReceiptRejected);
        }
        if prepared.phase == PreparedPhase::PreparedNoEffects {
            let pre_intent = self.observe(prepared.installed_clock_generation)?;
            if pre_intent.observed_at_nanos >= prepared.installed_deadline_nanos {
                return self.finish_no_effect_deadline(request, pre_intent);
            }
            let plan = self
                .owner
                .prepare_one_source(request, None)
                .map_err(RuntimeReferenceApplyError::Owner)?;
            validate_one_source_plan(request, plan, None)?;
            let intent = self.state.try_one_source_intent(RuntimeStartActionInput {
                action_id: plan.action_id,
                domain_generation: plan.domain_generation,
                instance_generation: plan.instance_generation,
                resource_generation: plan.resource_generation,
                pre_intent,
            })?;
            self.commit_state(intent)?;
        }

        let action = self.start_action()?;
        let plan = self
            .owner
            .prepare_one_source(request, Some(action))
            .map_err(RuntimeReferenceApplyError::Owner)?;
        validate_one_source_plan(request, plan, Some(action))?;

        let resource_phase = self.start_resource_phase(action, plan.resources)?;
        if resource_phase == StartResourcePhase::Absent {
            // Re-sample after the intent is durable and immediately before the
            // first resource effect. Equality belongs to the timed-out side.
            let post_intent = self.observe(self.prepared()?.installed_clock_generation)?;
            if post_intent.observed_at_nanos >= self.prepared()?.installed_deadline_nanos {
                return self.finish_one_source_post_intent_timeout(request, post_intent);
            }
        }
        match resource_phase {
            StartResourcePhase::Absent => {
                let reserved = self
                    .state
                    .try_reserve_one_source_resources(plan.resources)?;
                self.commit_state(reserved)?;
            }
            StartResourcePhase::Reserved | StartResourcePhase::Owned => {}
        }
        if self.start_resource_phase(action, plan.resources)? == StartResourcePhase::Reserved {
            let ownership = self
                .owner
                .materialize_one_source(action, plan.resources)
                .map_err(RuntimeReferenceApplyError::Owner)?;
            let owned = self.state.try_own_one_source_resources(ownership)?;
            self.commit_state(owned)?;
        }
        if self.start_resource_phase(action, plan.resources)? != StartResourcePhase::Owned {
            return Err(RuntimeReferenceApplyError::OwnerRecoveryRequired);
        }

        self.owner
            .start_one_source_once(action)
            .map_err(RuntimeReferenceApplyError::Owner)?;
        let callback_success = RuntimeOneSourceCallbackSuccessInput {
            action_id: action.action_id,
        };
        let selection = self.observe(self.prepared()?.installed_clock_generation)?;
        let preview = self
            .state
            .snapshot()
            .try_preview_one_source_success_terminal(&callback_success, selection)
            .map_err(RuntimeControlStateError::from)?;
        self.finish_one_source_terminal(request, callback_success, selection, preview)
    }

    fn execute_empty(
        &mut self,
        request: &ReferenceApplyRequestV1,
    ) -> Result<RuntimeReferenceApplyOutcome, RuntimeReferenceApplyError> {
        let prepared = self.prepared()?.clone();
        if prepared.incoming_kind != DesiredHeadKind::EmptyDeactivate {
            return Err(RuntimeReferenceApplyError::TerminalReceiptRejected);
        }
        if prepared.phase == PreparedPhase::PreparedNoEffects {
            let pre_intent = self.observe(prepared.installed_clock_generation)?;
            if pre_intent.observed_at_nanos >= prepared.installed_deadline_nanos {
                return self.finish_no_effect_deadline(request, pre_intent);
            }
            if let Ok(preview) = self
                .state
                .snapshot()
                .try_preview_empty_exact_zero_fast_path(pre_intent)
            {
                return self.finish_empty_fast_terminal(request, pre_intent, preview);
            }

            let (active_slice_digest, resource_generation) =
                self.active_one_source_retire_facts()?;
            let retire_plan = self
                .owner
                .prepare_empty_retire(active_slice_digest, resource_generation, None)
                .map_err(RuntimeReferenceApplyError::Owner)?;
            let retiring = self.state.try_empty_head_retire(
                request,
                retire_plan.action_id,
                retire_plan.signed_budgets,
                pre_intent,
            )?;
            self.commit_state(retiring)?;
        }

        let prepared = self.prepared()?.clone();
        if prepared.phase != PreparedPhase::HeadCommittedRetiringOld {
            return Err(RuntimeReferenceApplyError::OwnerRecoveryRequired);
        }
        let action = prepared
            .action
            .filter(|action| action.kind == JournalActionKind::DrainToEmpty)
            .ok_or(RuntimeReferenceApplyError::OwnerRecoveryRequired)?;
        let retiring = prepared
            .retiring
            .as_ref()
            .ok_or(RuntimeReferenceApplyError::OwnerRecoveryRequired)?;
        let active_slice_digest = TargetSliceDigest::new(retiring.old_slice.digest);
        let retire_plan = self
            .owner
            .prepare_empty_retire(
                active_slice_digest,
                retiring.old_resource_generation,
                Some(action),
            )
            .map_err(RuntimeReferenceApplyError::Owner)?;
        if retire_plan.action_id != action.action_id
            || retire_plan.signed_budgets.start().value() != retiring.signed_start_budget_nanos
            || retire_plan.signed_budgets.drain().value() != retiring.signed_drain_budget_nanos
            || retire_plan.signed_budgets.cleanup().value() != retiring.signed_cleanup_budget_nanos
        {
            return Err(RuntimeReferenceApplyError::OwnerRecoveryRequired);
        }
        if prepared.raw_outcome.is_none() {
            // The empty head is already durable and cannot roll back. Sample
            // once more before stop; if this crosses the deadline we still
            // converge through cleanup, but the terminal outcome is timed out.
            let pre_stop = self.observe(prepared.installed_clock_generation)?;
            self.owner
                .stop_one_source_once(action)
                .map_err(RuntimeReferenceApplyError::Owner)?;
            let callback_observation =
                if pre_stop.observed_at_nanos >= prepared.installed_deadline_nanos {
                    pre_stop
                } else {
                    self.observe(prepared.installed_clock_generation)?
                };
            let latched = self.state.try_latch_empty_success(callback_observation)?;
            self.commit_state(latched)?;
        }

        let tombstones = self
            .owner
            .cleanup_one_source_once(action)
            .map_err(RuntimeReferenceApplyError::Owner)?;
        let selection = self.observe(self.prepared()?.installed_clock_generation)?;
        let preview = self
            .state
            .snapshot()
            .try_preview_empty_exact_zero_terminal(Some(&tombstones), selection)
            .map_err(RuntimeControlStateError::from)?;
        let receipt = self.signer.sign_terminal(request, preview, self.channel)?;
        let terminal = RuntimeTerminalInput {
            canonical_response: OpaqueCanonicalValue::try_terminal_response(
                receipt.canonical_wire(),
                receipt.receipt_digest(),
            )
            .map_err(RuntimeControlStateError::from)?,
            selection,
        };
        let terminal_state = self
            .state
            .try_empty_exact_zero_terminal(tombstones, terminal)?;
        self.commit_state(terminal_state)?;
        self.completed_outcome(request)
    }

    fn prepared(&self) -> Result<&PreparedOperation, RuntimeReferenceApplyError> {
        self.state
            .snapshot()
            .state()
            .prepared
            .as_ref()
            .ok_or(RuntimeReferenceApplyError::OwnerRecoveryRequired)
    }

    fn observe(
        &mut self,
        clock_generation: u64,
    ) -> Result<RuntimeDeadlineObservation, RuntimeReferenceApplyError> {
        self.clock
            .observe(clock_generation)
            .map_err(RuntimeReferenceApplyError::Clock)
    }

    fn start_action(&self) -> Result<JournalActionRef, RuntimeReferenceApplyError> {
        let prepared = self.prepared()?;
        if prepared.phase != PreparedPhase::FirstActionIntent || prepared.raw_outcome.is_some() {
            return Err(RuntimeReferenceApplyError::OwnerRecoveryRequired);
        }
        prepared
            .action
            .filter(|action| action.kind == JournalActionKind::StartOneSourceLoop)
            .ok_or(RuntimeReferenceApplyError::OwnerRecoveryRequired)
    }

    fn start_resource_phase(
        &self,
        action: JournalActionRef,
        resources: RuntimeOneSourceResourceRefs,
    ) -> Result<StartResourcePhase, RuntimeReferenceApplyError> {
        let records = self
            .state
            .snapshot()
            .state()
            .owned_resources
            .iter()
            .filter(|resource| resource.action_id == Some(action.action_id))
            .collect::<Vec<_>>();
        if records.is_empty() {
            return Ok(StartResourcePhase::Absent);
        }
        if records.len() != 2
            || records.iter().any(|resource| {
                resource.generation != action.resource_generation
                    || resource.runtime_host_epoch != action.runtime_host_epoch
            })
        {
            return Err(RuntimeReferenceApplyError::OwnerRecoveryRequired);
        }
        let loop_domain = records.iter().find(|resource| {
            resource.kind == ResourceKind::LoopDomain
                && resource.logical_ref == resources.loop_domain
        });
        let card_instance = records.iter().find(|resource| {
            resource.kind == ResourceKind::CardInstance
                && resource.logical_ref == resources.card_instance
        });
        if loop_domain.is_none() || card_instance.is_none() {
            return Err(RuntimeReferenceApplyError::OwnerRecoveryRequired);
        }
        if records
            .iter()
            .all(|resource| resource.phase == ResourcePhase::Reserved)
        {
            Ok(StartResourcePhase::Reserved)
        } else if records
            .iter()
            .all(|resource| resource.phase == ResourcePhase::Owned)
        {
            Ok(StartResourcePhase::Owned)
        } else {
            Err(RuntimeReferenceApplyError::OwnerRecoveryRequired)
        }
    }

    fn active_one_source_retire_facts(
        &self,
    ) -> Result<(TargetSliceDigest, u64), RuntimeReferenceApplyError> {
        let state = self.state.snapshot().state();
        let active = state
            .active_desired
            .as_ref()
            .filter(|active| active.kind == DesiredHeadKind::OneSourceLoop)
            .ok_or(RuntimeReferenceApplyError::OwnerRecoveryRequired)?;
        let LiveMaterialization::LiveReady {
            active_slice_digest,
            resource_generation,
            ..
        } = state.live_materialization
        else {
            return Err(RuntimeReferenceApplyError::OwnerRecoveryRequired);
        };
        if TargetSliceDigest::new(active.slice.digest) != active_slice_digest {
            return Err(RuntimeReferenceApplyError::OwnerRecoveryRequired);
        }
        Ok((active_slice_digest, resource_generation))
    }

    fn finish_no_effect_deadline(
        &mut self,
        request: &ReferenceApplyRequestV1,
        selection: RuntimeDeadlineObservation,
    ) -> Result<RuntimeReferenceApplyOutcome, RuntimeReferenceApplyError> {
        let preview = self
            .state
            .snapshot()
            .try_preview_no_effect_deadline_terminal(selection)
            .map_err(RuntimeControlStateError::from)?;
        let terminal = self.terminal_input(request, preview, selection)?;
        let terminal_state = self
            .state
            .try_no_effect_deadline_terminal(request, terminal)?;
        self.commit_state(terminal_state)?;
        self.completed_outcome(request)
    }

    fn finish_empty_fast_terminal(
        &mut self,
        request: &ReferenceApplyRequestV1,
        selection: RuntimeDeadlineObservation,
        preview: RuntimeTerminalPreview,
    ) -> Result<RuntimeReferenceApplyOutcome, RuntimeReferenceApplyError> {
        let terminal = self.terminal_input(request, preview, selection)?;
        let terminal_state = self
            .state
            .try_empty_exact_zero_fast_path(request, terminal)?;
        self.commit_state(terminal_state)?;
        self.completed_outcome(request)
    }

    fn finish_one_source_post_intent_timeout(
        &mut self,
        request: &ReferenceApplyRequestV1,
        selection: RuntimeDeadlineObservation,
    ) -> Result<RuntimeReferenceApplyOutcome, RuntimeReferenceApplyError> {
        let preview = self
            .state
            .snapshot()
            .try_preview_one_source_post_intent_timeout_terminal(selection)
            .map_err(RuntimeControlStateError::from)?;
        let terminal = self.terminal_input(request, preview, selection)?;
        let terminal_state = self
            .state
            .try_one_source_post_intent_timeout_terminal(request, terminal)?;
        self.commit_state(terminal_state)?;
        self.completed_outcome(request)
    }

    fn finish_one_source_terminal(
        &mut self,
        request: &ReferenceApplyRequestV1,
        callback_success: RuntimeOneSourceCallbackSuccessInput,
        selection: RuntimeDeadlineObservation,
        preview: RuntimeTerminalPreview,
    ) -> Result<RuntimeReferenceApplyOutcome, RuntimeReferenceApplyError> {
        let terminal = self.terminal_input(request, preview, selection)?;
        let terminal_state =
            self.state
                .try_one_source_success_terminal(request, callback_success, terminal)?;
        self.commit_state(terminal_state)?;
        self.completed_outcome(request)
    }

    fn terminal_input(
        &self,
        request: &ReferenceApplyRequestV1,
        preview: RuntimeTerminalPreview,
        selection: RuntimeDeadlineObservation,
    ) -> Result<RuntimeTerminalInput, RuntimeReferenceApplyError> {
        let receipt = self.signer.sign_terminal(request, preview, self.channel)?;
        Ok(RuntimeTerminalInput {
            canonical_response: OpaqueCanonicalValue::try_terminal_response(
                receipt.canonical_wire(),
                receipt.receipt_digest(),
            )
            .map_err(RuntimeControlStateError::from)?,
            selection,
        })
    }

    fn completed_outcome(
        &self,
        request: &ReferenceApplyRequestV1,
    ) -> Result<RuntimeReferenceApplyOutcome, RuntimeReferenceApplyError> {
        let stored = self
            .try_terminal_replay(request)?
            .ok_or(RuntimeReferenceApplyError::TerminalReceiptRejected)?;
        Ok(RuntimeReferenceApplyOutcome::Terminal(Box::new(stored)))
    }

    fn try_terminal_replay(
        &self,
        request: &ReferenceApplyRequestV1,
    ) -> Result<Option<RuntimeStoredReferenceApplyReceipt>, RuntimeReferenceApplyError> {
        let scope = request.provenance().source_scope();
        let operation = request.control_commitment().control().operation_id();
        let Some(terminal) = self
            .state
            .snapshot()
            .state()
            .terminal_operations
            .iter()
            .find(|terminal| {
                terminal.source_scope == *scope.as_bytes()
                    && terminal.operation_id == *operation.as_bytes()
            })
        else {
            return Ok(None);
        };
        if terminal.request_digest != request.envelope_request_digest() {
            return Err(RuntimeReferenceApplyError::OperationConflict);
        }
        let receipt = decode_and_validate_terminal_receipt(
            *self.state.snapshot().store_instance_id(),
            terminal,
        )
        .map_err(RuntimeControlStateError::from)?;
        if receipt.target() != request.target()
            || receipt.request_nonce() != request.authentication().claim().nonce()
        {
            return Err(RuntimeReferenceApplyError::TerminalReceiptRejected);
        }
        Ok(Some(RuntimeStoredReferenceApplyReceipt {
            original_runtime_peer: receipt.authentication_runtime_peer(),
            original_channel_binding_digest: receipt.authentication_channel_binding_digest(),
            receipt,
        }))
    }

    fn ensure_store_matches_state(&self) -> Result<(), RuntimeReferenceApplyError> {
        let current = self
            .store
            .current_snapshot()
            .map_err(RuntimeReferenceApplyError::Store)?;
        if current != *self.state.snapshot() {
            return Err(RuntimeReferenceApplyError::StoreStateDiverged);
        }
        Ok(())
    }

    fn commit_state(
        &mut self,
        next: RuntimeControlState,
    ) -> Result<(), RuntimeReferenceApplyError> {
        self.store
            .commit_snapshot(next.snapshot().clone())
            .map_err(RuntimeReferenceApplyError::Store)?;
        self.state = next;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartResourcePhase {
    Absent,
    Reserved,
    Owned,
}

fn validate_one_source_plan(
    request: &ReferenceApplyRequestV1,
    plan: RuntimeOneSourceOwnerPlan,
    durable_action: Option<JournalActionRef>,
) -> Result<(), RuntimeReferenceApplyError> {
    let loop_facts = request
        .target_execution()
        .loop_facts()
        .ok_or(RuntimeReferenceApplyError::OwnerRecoveryRequired)?;
    if plan.action_id.iter().all(|byte| *byte == 0)
        || plan.domain_generation == 0
        || plan.instance_generation == 0
        || plan.resource_generation == 0
        || plan.resources.loop_domain != *loop_facts.domain().as_bytes()
        || plan.resources.card_instance != *loop_facts.instance().as_bytes()
        || plan.signed_budgets != loop_facts.budgets()
    {
        return Err(RuntimeReferenceApplyError::OwnerRecoveryRequired);
    }
    if let Some(action) = durable_action
        && (action.kind != JournalActionKind::StartOneSourceLoop
            || plan.action_id != action.action_id
            || plan.domain_generation != action.domain_generation
            || plan.instance_generation != action.instance_generation
            || plan.resource_generation != action.resource_generation)
    {
        return Err(RuntimeReferenceApplyError::OwnerRecoveryRequired);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeReferenceApplyError {
    Store(RuntimeReferenceApplyStoreError),
    Clock(RuntimeReferenceApplyClockError),
    State(RuntimeControlStateError),
    StoreStateDiverged,
    OperationConflict,
    Owner(RuntimeReferenceMaterializationOwnerError),
    OwnerRecoveryRequired,
    ResponseSignerRejected,
    TerminalReceiptRejected,
}

impl From<RuntimeControlStateError> for RuntimeReferenceApplyError {
    fn from(error: RuntimeControlStateError) -> Self {
        Self::State(error)
    }
}

const fn reference_outcome(value: TerminalOutcome) -> ReferenceApplyTerminalOutcomeV1 {
    match value {
        TerminalOutcome::OneSourceLoopActive => {
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
        }
        TerminalOutcome::EmptyDeactivateExactZero => {
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero
        }
        TerminalOutcome::StartTimedOutBeforeIntentNoEffects => {
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects
        }
        TerminalOutcome::StopTimedOutBeforeHeadCommitNoEffects => {
            ReferenceApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects
        }
        TerminalOutcome::StartFailedBeforeHeadCommitExactZero => {
            ReferenceApplyTerminalOutcomeV1::StartFailedBeforeHeadCommitExactZero
        }
        TerminalOutcome::StartTimedOutBeforeHeadCommitExactZero => {
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero
        }
        TerminalOutcome::StopFailedButExactZero => {
            ReferenceApplyTerminalOutcomeV1::StopFailedButExactZero
        }
        TerminalOutcome::TimedOutButExactZero => {
            ReferenceApplyTerminalOutcomeV1::TimedOutButExactZero
        }
        TerminalOutcome::AbortedBeforeIntentNoEffects => {
            ReferenceApplyTerminalOutcomeV1::AbortedBeforeIntentNoEffects
        }
        TerminalOutcome::AbortedBeforeHeadCommitExactZero => {
            ReferenceApplyTerminalOutcomeV1::AbortedBeforeHeadCommitExactZero
        }
        TerminalOutcome::SupersededAfterIntentExactZero => {
            ReferenceApplyTerminalOutcomeV1::SupersededAfterIntentExactZero
        }
        TerminalOutcome::InterruptedButNowExactZero => {
            ReferenceApplyTerminalOutcomeV1::InterruptedButNowExactZero
        }
    }
}

const fn reference_lifecycle(
    value: crate::runtime_journal::TerminalLifecycleEffect,
) -> ReferenceApplyTerminalLifecycleEffectV1 {
    match value {
        crate::runtime_journal::TerminalLifecycleEffect::ProvenNotStarted => {
            ReferenceApplyTerminalLifecycleEffectV1::ProvenNotStarted
        }
        crate::runtime_journal::TerminalLifecycleEffect::MayHaveStarted => {
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted
        }
    }
}

const fn reference_head(value: TerminalHeadDisposition) -> ReferenceApplyTerminalHeadV1 {
    match value {
        TerminalHeadDisposition::Preserved(None) => ReferenceApplyTerminalHeadV1::PreservedNone,
        TerminalHeadDisposition::Preserved(Some(digest)) => {
            ReferenceApplyTerminalHeadV1::PreservedExisting(digest)
        }
        TerminalHeadDisposition::CommittedIncoming => {
            ReferenceApplyTerminalHeadV1::CommittedIncoming
        }
    }
}

#[cfg(test)]
mod restart_reassembly_regression_tests {
    use super::{
        RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS, effective_recovery_start_budget,
        recovery_quarantine_digest_with_failure_fields,
    };
    use paraegox_kernel::digest::Digest32;

    #[test]
    fn effective_recovery_budget_uses_the_smaller_signed_value_or_local_cap() {
        assert_eq!(effective_recovery_start_budget(1), 1);
        assert_eq!(
            effective_recovery_start_budget(RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS - 1),
            RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS - 1,
        );
        assert_eq!(
            effective_recovery_start_budget(RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS),
            RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS,
        );
        assert_eq!(
            effective_recovery_start_budget(RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS + 1),
            RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS,
        );
        assert_eq!(
            effective_recovery_start_budget(u64::MAX),
            RUNTIME_RECOVERY_MAX_START_BUDGET_NANOS,
        );
    }

    #[test]
    fn repeated_quarantine_reason_is_chained_to_the_prior_failure_evidence() {
        let first = recovery_quarantine_digest_with_failure_fields(
            17,
            b"startup-reconcile-required",
            Digest32::from_bytes([0x41; 32]),
        )
        .expect("first chained quarantine digest must build");
        let replay = recovery_quarantine_digest_with_failure_fields(
            17,
            b"startup-reconcile-required",
            Digest32::from_bytes([0x41; 32]),
        )
        .expect("same chained quarantine digest must build deterministically");
        let different_prior = recovery_quarantine_digest_with_failure_fields(
            17,
            b"startup-reconcile-required",
            Digest32::from_bytes([0x42; 32]),
        )
        .expect("second chained quarantine digest must build");

        assert_eq!(first, replay);
        assert_ne!(first, different_prior);
        assert_ne!(first, Digest32::from_bytes([0; 32]));
    }
}
