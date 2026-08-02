//! Runtime-owned production transition facade over the validated owner journal.
//!
//! This module does not define a wire codec, manifest schema, query protocol,
//! or lifecycle backend.  It holds only a validated journal snapshot and
//! exposes post-start facts that an authenticated control adapter may consume.

use paraegox_kernel::{digest::Digest32, identity::RuntimeHostId};
use paraegox_runtime_contracts::{
    apply::ExpectedActive,
    installation::verify_immutable_manifest_ingress,
    reference_control::{
        ReferenceApplyRequestV1, ReferenceAssemblyModeV1, ValidatedReferenceLifecycleBudgetsV1,
    },
};

use crate::runtime_journal::{
    DesiredHeadKind, ExpectedActiveCas, LiveMaterialization, OpaqueCanonicalValue,
    RuntimeApplyAdmissionInput, RuntimeDeadlineObservation, RuntimeEmptyRetireInput,
    RuntimeJournalError, RuntimeJournalSnapshot, RuntimeJournalState, RuntimeJournalTransaction,
    RuntimeOneSourceCallbackSuccessInput, RuntimeOneSourceOwnershipInput,
    RuntimeOneSourceResourceRefs, RuntimeOneSourceTombstonesInput, RuntimeRetiringLifecycleBudgets,
    RuntimeStartActionInput, RuntimeTemporalAdmissionInput, RuntimeTenureAdmissionInput,
    RuntimeTerminalInput, StartupRecoveryEligibility, StorePinnedBuildIdentity,
};

// Kept as children of the control-state owner after the authenticated endpoint
// wiring so the production adapter consumes the durable core without widening
// either mechanism into the crate-root API.
#[allow(dead_code)] // GOV-WAIVER-0012
#[path = "runtime_reference_apply.rs"]
pub(crate) mod runtime_reference_apply;
#[cfg(unix)]
#[path = "runtime_reference_owner.rs"]
pub(crate) mod runtime_reference_owner;

/// Validated Runtime control state after the process-start invalidation commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeControlState {
    snapshot: RuntimeJournalSnapshot,
}

/// Evidence retained by the Runtime ingress after exact target/channel/policy
/// checks and both request and tenure signature verifications succeed.
///
/// The canonical request remains the source of every contract field and byte
/// sequence.  This evidence supplies only owner-local bindings that the PXAR
/// contract cannot derive: configured fingerprints, replay identities and the
/// monotonic instant used to install its remaining budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeReferenceApplyPreflight {
    pub(crate) local_target: RuntimeHostId,
    pub(crate) owner_target_fingerprint: Digest32,
    pub(crate) admission_policy_fingerprint: Digest32,
    pub(crate) channel_policy_fingerprint: Digest32,
    pub(crate) controller_key_fingerprint: Digest32,
    pub(crate) tenure_nonce_identity: Digest32,
    pub(crate) request_nonce_identity: Digest32,
    pub(crate) temporal_lineage_digest: Digest32,
    pub(crate) admitted_at_nanos: u64,
}

/// Whether a facade call produced a new journal snapshot or recognized the
/// exact already-durable stage after a retry/crash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeAdmissionDisposition {
    Committed,
    AlreadyDurable,
}

/// Ephemeral capability binding full admission to the exact current tenure
/// snapshot.
///
/// It may be minted by the preceding tenure-only transition, an exact durable
/// full-admission replay, or an owner-private resident-tenure continuation in
/// the same service process. Its fields are deliberately private and it is
/// deliberately not `Clone`: the full-admission call consumes it, and a fresh
/// process cannot restore the resident continuation from durable state. A
/// fresh external retry that observes only the durable tenure stage therefore
/// cannot recompute `admitted_at_nanos` and silently renew the signed remaining
/// budget. No temporal fact is persisted in the tenure-only transaction.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RuntimePreparedReferenceAdmission {
    admission: RuntimeApplyAdmissionInput,
    tenure_snapshot: RuntimeJournalSnapshot,
}

impl RuntimePreparedReferenceAdmission {
    #[must_use]
    pub(crate) const fn bound_sequence(&self) -> u64 {
        self.tenure_snapshot.sequence()
    }

    #[must_use]
    pub(crate) const fn tenure(&self) -> RuntimeTenureAdmissionInput {
        self.admission.tenure
    }
}

/// State plus explicit idempotency disposition returned to the endpoint.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RuntimeControlTransition {
    state: RuntimeControlState,
    disposition: RuntimeAdmissionDisposition,
    prepared_admission: Option<RuntimePreparedReferenceAdmission>,
}

impl RuntimeControlTransition {
    #[must_use]
    pub(crate) const fn state(&self) -> &RuntimeControlState {
        &self.state
    }

    #[must_use]
    pub(crate) const fn disposition(&self) -> RuntimeAdmissionDisposition {
        self.disposition
    }

    #[must_use]
    pub(crate) const fn prepared_admission(&self) -> Option<&RuntimePreparedReferenceAdmission> {
        self.prepared_admission.as_ref()
    }

    #[must_use]
    pub(crate) fn into_parts(
        self,
    ) -> (
        RuntimeControlState,
        RuntimeAdmissionDisposition,
        Option<RuntimePreparedReferenceAdmission>,
    ) {
        (self.state, self.disposition, self.prepared_admission)
    }
}

impl RuntimeControlState {
    /// Advances an already validated snapshot through the mandatory startup
    /// invalidation transaction before exposing any control-plane fact.
    pub(crate) fn try_start(
        previous: &RuntimeJournalSnapshot,
    ) -> Result<Self, RuntimeControlStateError> {
        Ok(Self {
            snapshot: previous.try_startup_invalidation_successor()?,
        })
    }

    /// Reconstructs the in-memory facade from the exact snapshot already
    /// committed in the Runtime store.  Sequence one is rejected: endpoint
    /// apply can resume only after the mandatory startup invalidation commit.
    pub(crate) fn try_from_started_snapshot(
        snapshot: &RuntimeJournalSnapshot,
    ) -> Result<Self, RuntimeControlStateError> {
        let state = Self {
            snapshot: snapshot.clone(),
        };
        state.bootstrap_facts()?;
        Ok(state)
    }

    /// Returns the exact validated snapshot to the Runtime store publisher.
    #[must_use]
    pub(crate) const fn snapshot(&self) -> &RuntimeJournalSnapshot {
        &self.snapshot
    }

    /// Projects read-only bootstrap facts only after startup invalidation has
    /// advanced the durable RuntimeHost and clock generations.
    pub(crate) fn bootstrap_facts(
        &self,
    ) -> Result<RuntimeJournalBootstrapFacts, RuntimeControlStateError> {
        let state = self.snapshot.state();
        if state.last_transaction == RuntimeJournalTransaction::Initialized
            || state.host.runtime_host_epoch_high_water == 0
            || state.host.clock_generation_high_water == 0
        {
            return Err(RuntimeControlStateError::StartupNotCommitted);
        }
        let (readiness, reason, reason_evidence_digest) =
            bootstrap_readiness(state.live_materialization);
        Ok(RuntimeJournalBootstrapFacts {
            store_instance_id: *self.snapshot.store_instance_id(),
            owner_target_fingerprint: *self.snapshot.owner_target_fingerprint(),
            snapshot_sequence: self.snapshot.sequence(),
            runtime_host_epoch: state.host.runtime_host_epoch_high_water,
            clock_domain: state.host.clock_domain,
            clock_generation: state.host.clock_generation_high_water,
            compiled_build_instance_id: state.host.compiled_build_instance_id,
            compiled_compatibility_digest: state.host.compiled_compatibility_digest,
            store_pinned_build_identity: state.host.store_pinned_build_identity,
            manifest_digest: state.host.singleton_manifest.digest,
            admission_policy_fingerprint: state.host.admission_policy_fingerprint,
            readiness,
            reason,
            reason_evidence_digest,
        })
    }

    /// Produces and commits the tenure-only successor from one already strict,
    /// authenticated PXAR request and its owner-local preflight evidence.
    pub(crate) fn try_reference_tenure_only(
        &self,
        request: &ReferenceApplyRequestV1,
        preflight: RuntimeReferenceApplyPreflight,
    ) -> Result<RuntimeControlTransition, RuntimeControlStateError> {
        let input = self.try_reference_admission_input(request, preflight)?;
        match tenure_admission_status(self.snapshot.state(), input.tenure) {
            AdmissionMutationStatus::Exact => {
                let prepared_admission = match full_admission_status(self.snapshot.state(), &input)
                {
                    AdmissionMutationStatus::Exact => Some(RuntimePreparedReferenceAdmission {
                        admission: input,
                        tenure_snapshot: self.snapshot.clone(),
                    }),
                    AdmissionMutationStatus::New => None,
                    AdmissionMutationStatus::Conflict => {
                        return Err(RuntimeControlStateError::PreflightRejected);
                    }
                };
                Ok(RuntimeControlTransition {
                    state: self.clone(),
                    disposition: RuntimeAdmissionDisposition::AlreadyDurable,
                    prepared_admission,
                })
            }
            AdmissionMutationStatus::Conflict => Err(RuntimeControlStateError::PreflightRejected),
            AdmissionMutationStatus::New => {
                let snapshot = self.snapshot.try_tenure_only_successor(input.tenure)?;
                let prepared_admission = RuntimePreparedReferenceAdmission {
                    admission: input,
                    tenure_snapshot: snapshot.clone(),
                };
                Ok(RuntimeControlTransition {
                    state: Self { snapshot },
                    disposition: RuntimeAdmissionDisposition::Committed,
                    prepared_admission: Some(prepared_admission),
                })
            }
        }
    }

    /// Mints a sequence-bound full-admission capability for a new request only
    /// when the apply core proves that this exact tenure already completed one
    /// full admission in the current service process.
    ///
    /// The resident tenure is deliberately owner-private and non-durable.  A
    /// process reconstructed from a tenure-only or fully admitted snapshot
    /// cannot call this path successfully without first completing a new full
    /// admission commit itself.
    pub(crate) fn try_reference_resident_tenure_continuation(
        &self,
        request: &ReferenceApplyRequestV1,
        preflight: RuntimeReferenceApplyPreflight,
        resident_tenure: RuntimeTenureAdmissionInput,
    ) -> Result<Option<RuntimePreparedReferenceAdmission>, RuntimeControlStateError> {
        let input = self.try_reference_admission_input(request, preflight)?;
        if input.tenure != resident_tenure {
            return Ok(None);
        }
        if tenure_admission_status(self.snapshot.state(), input.tenure)
            != AdmissionMutationStatus::Exact
            || full_admission_status(self.snapshot.state(), &input) != AdmissionMutationStatus::New
        {
            return Err(RuntimeControlStateError::PreflightRejected);
        }
        Ok(Some(RuntimePreparedReferenceAdmission {
            admission: input,
            tenure_snapshot: self.snapshot.clone(),
        }))
    }

    /// Commits the separate full-admission successor using a non-renewable,
    /// sequence-bound capability minted by an exact tenure transition or an
    /// authorized resident-tenure continuation.
    pub(crate) fn try_reference_full_admission(
        &self,
        prepared: RuntimePreparedReferenceAdmission,
    ) -> Result<RuntimeControlTransition, RuntimeControlStateError> {
        if self.snapshot != prepared.tenure_snapshot {
            return Err(RuntimeControlStateError::PreflightRejected);
        }
        let input = prepared.admission;
        if tenure_admission_status(self.snapshot.state(), input.tenure)
            != AdmissionMutationStatus::Exact
        {
            return Err(RuntimeControlStateError::PreflightRejected);
        }
        match full_admission_status(self.snapshot.state(), &input) {
            AdmissionMutationStatus::Exact => Ok(RuntimeControlTransition {
                state: self.clone(),
                disposition: RuntimeAdmissionDisposition::AlreadyDurable,
                prepared_admission: None,
            }),
            AdmissionMutationStatus::Conflict => Err(RuntimeControlStateError::PreflightRejected),
            AdmissionMutationStatus::New => Ok(RuntimeControlTransition {
                state: Self {
                    snapshot: self.snapshot.try_full_admission_successor(input)?,
                },
                disposition: RuntimeAdmissionDisposition::Committed,
                prepared_admission: None,
            }),
        }
    }

    /// Commits the one-source pre-intent action marker without performing an
    /// OS or lifecycle effect.
    pub(crate) fn try_one_source_intent(
        &self,
        input: RuntimeStartActionInput,
    ) -> Result<Self, RuntimeControlStateError> {
        Ok(Self {
            snapshot: self.snapshot.try_one_source_intent_successor(input)?,
        })
    }

    /// Commits the fixed action-bound resource reservations.
    pub(crate) fn try_reserve_one_source_resources(
        &self,
        resources: RuntimeOneSourceResourceRefs,
    ) -> Result<Self, RuntimeControlStateError> {
        Ok(Self {
            snapshot: self
                .snapshot
                .try_reserve_one_source_resources_successor(resources)?,
        })
    }

    /// Commits exact resource-owner evidence returned after real allocation.
    pub(crate) fn try_own_one_source_resources(
        &self,
        input: RuntimeOneSourceOwnershipInput,
    ) -> Result<Self, RuntimeControlStateError> {
        Ok(Self {
            snapshot: self
                .snapshot
                .try_own_one_source_resources_successor(input)?,
        })
    }

    /// Atomically publishes the strict PXAR Slice as the one-source desired/live
    /// head and records its canonical terminal response.
    pub(crate) fn try_one_source_success_terminal(
        &self,
        request: &ReferenceApplyRequestV1,
        callback_success: RuntimeOneSourceCallbackSuccessInput,
        terminal: RuntimeTerminalInput,
    ) -> Result<Self, RuntimeControlStateError> {
        let incoming_slice = self.reference_slice(request)?;
        Ok(Self {
            snapshot: self.snapshot.try_one_source_success_terminal_successor(
                incoming_slice,
                callback_success,
                terminal,
            )?,
        })
    }

    /// Commits the post-intent timeout selected before the first resource or
    /// callback effect, preserving the exact predecessor head and census.
    pub(crate) fn try_one_source_post_intent_timeout_terminal(
        &self,
        request: &ReferenceApplyRequestV1,
        terminal: RuntimeTerminalInput,
    ) -> Result<Self, RuntimeControlStateError> {
        let _ = self.reference_slice(request)?;
        Ok(Self {
            snapshot: self
                .snapshot
                .try_one_source_post_intent_timeout_terminal_successor(terminal)?,
        })
    }

    /// Commits the strict empty Slice as desired head before stop/cleanup.
    pub(crate) fn try_empty_head_retire(
        &self,
        request: &ReferenceApplyRequestV1,
        action_id: [u8; 16],
        old_budgets: ValidatedReferenceLifecycleBudgetsV1,
        pre_intent: RuntimeDeadlineObservation,
    ) -> Result<Self, RuntimeControlStateError> {
        let incoming_slice = self.reference_slice(request)?;
        Ok(Self {
            snapshot: self
                .snapshot
                .try_empty_head_retire_successor(RuntimeEmptyRetireInput {
                    action_id,
                    incoming_slice,
                    budgets: RuntimeRetiringLifecycleBudgets {
                        start_nanos: old_budgets.start().value(),
                        drain_nanos: old_budgets.drain().value(),
                        cleanup_nanos: old_budgets.cleanup().value(),
                    },
                    pre_intent,
                })?,
        })
    }

    /// Durably records the real stop callback success before cleanup.
    pub(crate) fn try_latch_empty_success(
        &self,
        observation: RuntimeDeadlineObservation,
    ) -> Result<Self, RuntimeControlStateError> {
        Ok(Self {
            snapshot: self
                .snapshot
                .try_latch_empty_success_successor(observation)?,
        })
    }

    /// Commits real fixed-profile tombstones and the exact-zero terminal.
    pub(crate) fn try_empty_exact_zero_terminal(
        &self,
        tombstones: RuntimeOneSourceTombstonesInput,
        terminal: RuntimeTerminalInput,
    ) -> Result<Self, RuntimeControlStateError> {
        Ok(Self {
            snapshot: self
                .snapshot
                .try_empty_exact_zero_terminal_successor(tombstones, terminal)?,
        })
    }

    /// Commits a pre-effect deadline terminal while preserving the exact
    /// current desired/live state.
    pub(crate) fn try_no_effect_deadline_terminal(
        &self,
        request: &ReferenceApplyRequestV1,
        terminal: RuntimeTerminalInput,
    ) -> Result<Self, RuntimeControlStateError> {
        // Recheck the exact prepared PXAR/Slice correlation even though this
        // terminal deliberately does not commit the incoming head.
        let _ = self.reference_slice(request)?;
        Ok(Self {
            snapshot: self
                .snapshot
                .try_no_effect_deadline_terminal_successor(terminal)?,
        })
    }

    /// Commits the strict empty Slice and exact-zero terminal without an action
    /// when the durable predecessor is already exact zero.
    pub(crate) fn try_empty_exact_zero_fast_path(
        &self,
        request: &ReferenceApplyRequestV1,
        terminal: RuntimeTerminalInput,
    ) -> Result<Self, RuntimeControlStateError> {
        let incoming_slice = self.reference_slice(request)?;
        Ok(Self {
            snapshot: self
                .snapshot
                .try_empty_exact_zero_fast_path_successor(incoming_slice, terminal)?,
        })
    }

    fn try_reference_admission_input(
        &self,
        request: &ReferenceApplyRequestV1,
        preflight: RuntimeReferenceApplyPreflight,
    ) -> Result<RuntimeApplyAdmissionInput, RuntimeControlStateError> {
        let state = self.snapshot.state();
        let provenance = request.provenance();
        let control = request.control_commitment().control();
        let writer = control.writer_context();
        let proof = writer.proof();
        let claim = proof.claim();
        let temporal = request.temporal();
        let authentication = request.authentication().claim();
        let execution = request.target_execution();

        let manifest = verify_immutable_manifest_ingress(
            &state.host.singleton_manifest.canonical_bytes,
            state.host.singleton_manifest.digest,
        )
        .map_err(|_| RuntimeControlStateError::PreflightRejected)?;
        request
            .validate_manifest(&manifest)
            .map_err(|_| RuntimeControlStateError::PreflightRejected)?;

        if request.target() != preflight.local_target
            || execution.target() != preflight.local_target
            || preflight.owner_target_fingerprint != *self.snapshot.owner_target_fingerprint()
            || preflight.admission_policy_fingerprint != state.host.admission_policy_fingerprint
            || preflight.channel_policy_fingerprint != state.host.channel_policy_fingerprint
            || preflight.controller_key_fingerprint != state.host.controller_key_fingerprint
            || request.expected_runtime_store_instance_id() != *self.snapshot.store_instance_id()
            || execution.manifest_digest() != state.host.singleton_manifest.digest
            || claim.source_scope() != provenance.source_scope()
            || claim.writer() != writer.writer()
            || claim.epoch() != writer.epoch()
            || temporal.target_clock_domain().as_bytes() != &state.host.clock_domain
            || temporal.target_clock_generation().value() != state.host.clock_generation_high_water
        {
            return Err(RuntimeControlStateError::PreflightRejected);
        }
        let remaining_budget_nanos = temporal.remaining_budget().value();
        if remaining_budget_nanos == 0 {
            return Err(RuntimeControlStateError::PreflightRejected);
        }
        let installed_deadline_nanos = preflight
            .admitted_at_nanos
            .checked_add(remaining_budget_nanos)
            .ok_or(RuntimeControlStateError::PreflightRejected)?;
        let proof_envelope_digest = proof
            .envelope_digest()
            .map_err(|_| RuntimeControlStateError::PreflightRejected)?;
        let incoming_kind = match execution.mode() {
            ReferenceAssemblyModeV1::OneSourceLoop => DesiredHeadKind::OneSourceLoop,
            ReferenceAssemblyModeV1::EmptyDeactivate => DesiredHeadKind::EmptyDeactivate,
        };
        let expected_active = match control.expected_active() {
            ExpectedActive::None => ExpectedActiveCas::None,
            ExpectedActive::Exact(digest) => ExpectedActiveCas::Exact(digest),
        };

        Ok(RuntimeApplyAdmissionInput {
            tenure: RuntimeTenureAdmissionInput {
                expected_store_instance_id: request.expected_runtime_store_instance_id(),
                owner_target_fingerprint: preflight.owner_target_fingerprint,
                source_scope: *claim.source_scope().as_bytes(),
                writer: *writer.writer().as_bytes(),
                epoch: writer.epoch().value(),
                supersedes_through_epoch: claim.supersedes_through_epoch().value(),
                proof_envelope_digest,
                tenure_nonce_identity: preflight.tenure_nonce_identity,
                principal: *authentication.principal().as_bytes(),
            },
            request: OpaqueCanonicalValue::try_request_or_slice(
                request.canonical_wire(),
                request.envelope_request_digest(),
            )?,
            request_nonce_identity: preflight.request_nonce_identity,
            operation_id: *control.operation_id().as_bytes(),
            source_revision: provenance.source_revision().value(),
            source_plan_digest: provenance.source_plan_digest(),
            incoming_slice_digest: request.target_slice_digest(),
            incoming_kind,
            manifest_digest: execution.manifest_digest(),
            expected_active,
            temporal: RuntimeTemporalAdmissionInput {
                constraint_id: *temporal.constraint_id().as_bytes(),
                original_budget_nanos: temporal.original_budget().value(),
                remaining_budget_nanos,
                installed_clock_generation: temporal.target_clock_generation().value(),
                installed_deadline_nanos,
                lineage_digest: preflight.temporal_lineage_digest,
            },
        })
    }

    fn reference_slice(
        &self,
        request: &ReferenceApplyRequestV1,
    ) -> Result<OpaqueCanonicalValue, RuntimeControlStateError> {
        let prepared = self
            .snapshot
            .state()
            .prepared
            .as_ref()
            .ok_or(RuntimeControlStateError::PreflightRejected)?;
        if prepared.request.canonical_bytes.as_ref() != request.canonical_wire()
            || prepared.request.digest != request.envelope_request_digest()
            || prepared.incoming_slice_digest != request.target_slice_digest()
        {
            return Err(RuntimeControlStateError::PreflightRejected);
        }
        Ok(OpaqueCanonicalValue::try_request_or_slice(
            request.canonical_slice_wire(),
            *request.target_slice_digest().value(),
        )?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionMutationStatus {
    New,
    Exact,
    Conflict,
}

fn tenure_admission_status(
    state: &RuntimeJournalState,
    input: RuntimeTenureAdmissionInput,
) -> AdmissionMutationStatus {
    let nonce = state
        .host
        .tenure_nonces
        .iter()
        .find(|record| record.identity == input.tenure_nonce_identity);
    if state.writer_fence == Some(input.fence())
        && nonce.is_some_and(|record| record.value_digest == input.proof_envelope_digest)
    {
        return AdmissionMutationStatus::Exact;
    }
    if nonce.is_some()
        || state.writer_fence.is_some_and(|fence| {
            fence.source_scope == input.source_scope && fence.epoch >= input.epoch
        })
    {
        AdmissionMutationStatus::Conflict
    } else {
        AdmissionMutationStatus::New
    }
}

fn full_admission_status(
    state: &RuntimeJournalState,
    input: &RuntimeApplyAdmissionInput,
) -> AdmissionMutationStatus {
    let request_nonce = state
        .host
        .request_nonces
        .iter()
        .find(|record| record.identity == input.request_nonce_identity);
    let temporal = state
        .host
        .temporal_lineages
        .iter()
        .find(|record| record.constraint_id == input.temporal.constraint_id);
    let exact_request_nonce =
        request_nonce.is_some_and(|record| record.value_digest == input.request.digest);
    let exact_temporal = temporal.is_some_and(|record| {
        record.source_scope == input.tenure.source_scope
            && record.target_fingerprint == input.tenure.owner_target_fingerprint
            && record.original_budget_nanos == input.temporal.original_budget_nanos
            && record.remaining_budget_nanos == input.temporal.remaining_budget_nanos
            && record.clock_generation == input.temporal.installed_clock_generation
            && record.deadline_nanos == input.temporal.installed_deadline_nanos
            && record.lineage_digest == input.temporal.lineage_digest
    });
    let exact_prepared = state.prepared.as_ref().is_some_and(|prepared| {
        prepared.source_scope == input.tenure.source_scope
            && prepared.operation_id == input.operation_id
            && prepared.source_revision == input.source_revision
            && prepared.request == input.request
            && prepared.request_nonce_identity == input.request_nonce_identity
            && prepared.source_plan_digest == input.source_plan_digest
            && prepared.incoming_slice_digest == input.incoming_slice_digest
            && prepared.incoming_kind == input.incoming_kind
            && prepared.manifest_digest == input.manifest_digest
            && prepared.expected_active == input.expected_active
            && prepared.temporal_constraint_id == input.temporal.constraint_id
            && prepared.temporal_lineage_digest == input.temporal.lineage_digest
            && prepared.installed_clock_generation == input.temporal.installed_clock_generation
            && prepared.installed_deadline_nanos == input.temporal.installed_deadline_nanos
    });
    let exact_terminal = state.terminal_operations.iter().any(|terminal| {
        terminal.source_scope == input.tenure.source_scope
            && terminal.operation_id == input.operation_id
            && terminal.request_digest == input.request.digest
            && terminal.request_nonce_identity == input.request_nonce_identity
            && terminal.source_revision == input.source_revision
            && terminal.source_plan_digest == input.source_plan_digest
            && terminal.target_slice_digest == input.incoming_slice_digest
            && terminal.temporal_constraint_id == input.temporal.constraint_id
            && terminal.temporal_lineage_digest == input.temporal.lineage_digest
            && terminal.incoming_kind == input.incoming_kind
            && terminal.installed_clock_generation == input.temporal.installed_clock_generation
            && terminal.installed_deadline_nanos == input.temporal.installed_deadline_nanos
    });
    let exact_revision = state.source_revision_high_water.is_some_and(|high_water| {
        high_water.source_scope == input.tenure.source_scope
            && high_water.revision >= input.source_revision
    });
    if exact_request_nonce && exact_temporal && exact_revision && (exact_prepared || exact_terminal)
    {
        return AdmissionMutationStatus::Exact;
    }

    let operation_conflict = state.prepared.as_ref().is_some_and(|prepared| {
        prepared.source_scope == input.tenure.source_scope
            && prepared.operation_id == input.operation_id
    }) || state.terminal_operations.iter().any(|terminal| {
        terminal.source_scope == input.tenure.source_scope
            && terminal.operation_id == input.operation_id
    });
    if request_nonce.is_some()
        || temporal.is_some()
        || operation_conflict
        || state.source_revision_high_water.is_some_and(|high_water| {
            high_water.source_scope == input.tenure.source_scope
                && high_water.revision >= input.source_revision
        })
    {
        AdmissionMutationStatus::Conflict
    } else {
        AdmissionMutationStatus::New
    }
}

/// Journal-derived bootstrap readiness after the startup service gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeJournalBootstrapState {
    ReadyForApply,
    NotReadyRecovering,
    ValidatedOperationalQuarantine,
    RecoveryFailedNotReady,
    NotReadyBusy,
}

/// Stable journal-owned reason accompanying a non-ready bootstrap state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeJournalBootstrapReason {
    Recovering,
    RecoveryFailed,
    OwnershipUncertain,
    RuntimeBusy,
}

/// Exact read-only facts available from the validated Runtime journal.
///
/// The authenticated bootstrap contract adapter must additionally supply the
/// exact `RuntimeHostId` and manifest-derived profile fingerprint from the
/// strict startup installation token; neither is reconstructed here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeJournalBootstrapFacts {
    store_instance_id: [u8; 32],
    owner_target_fingerprint: Digest32,
    snapshot_sequence: u64,
    runtime_host_epoch: u64,
    clock_domain: [u8; 16],
    clock_generation: u64,
    compiled_build_instance_id: [u8; 32],
    compiled_compatibility_digest: Digest32,
    store_pinned_build_identity: StorePinnedBuildIdentity,
    manifest_digest: Digest32,
    admission_policy_fingerprint: Digest32,
    readiness: RuntimeJournalBootstrapState,
    reason: Option<RuntimeJournalBootstrapReason>,
    reason_evidence_digest: Option<Digest32>,
}

impl RuntimeJournalBootstrapFacts {
    #[must_use]
    pub(crate) const fn store_instance_id(self) -> [u8; 32] {
        self.store_instance_id
    }

    #[must_use]
    pub(crate) const fn owner_target_fingerprint(self) -> Digest32 {
        self.owner_target_fingerprint
    }

    #[must_use]
    pub(crate) const fn snapshot_sequence(self) -> u64 {
        self.snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn runtime_host_epoch(self) -> u64 {
        self.runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn clock_domain(self) -> [u8; 16] {
        self.clock_domain
    }

    #[must_use]
    pub(crate) const fn clock_generation(self) -> u64 {
        self.clock_generation
    }

    #[must_use]
    pub(crate) const fn compiled_build_instance_id(self) -> [u8; 32] {
        self.compiled_build_instance_id
    }

    #[must_use]
    pub(crate) const fn compiled_compatibility_digest(self) -> Digest32 {
        self.compiled_compatibility_digest
    }

    #[must_use]
    pub(crate) const fn store_pinned_build_identity(self) -> StorePinnedBuildIdentity {
        self.store_pinned_build_identity
    }

    #[must_use]
    pub(crate) const fn manifest_digest(self) -> Digest32 {
        self.manifest_digest
    }

    #[must_use]
    pub(crate) const fn admission_policy_fingerprint(self) -> Digest32 {
        self.admission_policy_fingerprint
    }

    #[must_use]
    pub(crate) const fn readiness(self) -> RuntimeJournalBootstrapState {
        self.readiness
    }

    #[must_use]
    pub(crate) const fn reason(self) -> Option<RuntimeJournalBootstrapReason> {
        self.reason
    }

    #[must_use]
    pub(crate) const fn reason_evidence_digest(self) -> Option<Digest32> {
        self.reason_evidence_digest
    }
}

fn bootstrap_readiness(
    live: LiveMaterialization,
) -> (
    RuntimeJournalBootstrapState,
    Option<RuntimeJournalBootstrapReason>,
    Option<Digest32>,
) {
    match live {
        LiveMaterialization::None
        | LiveMaterialization::LiveReady { .. }
        | LiveMaterialization::ExactZero { .. }
        | LiveMaterialization::StartupInvalidated {
            recovery_eligibility:
                StartupRecoveryEligibility::NoActiveHead
                | StartupRecoveryEligibility::CanonicalEmptyExactZero,
            ..
        } => (RuntimeJournalBootstrapState::ReadyForApply, None, None),
        LiveMaterialization::Recovering { .. }
        | LiveMaterialization::StartupInvalidated {
            recovery_eligibility: StartupRecoveryEligibility::EligibleOneSourceLoop,
            ..
        } => (
            RuntimeJournalBootstrapState::NotReadyRecovering,
            Some(RuntimeJournalBootstrapReason::Recovering),
            None,
        ),
        LiveMaterialization::RecoveryFailedNotReady {
            failure_latch_digest,
            ..
        }
        | LiveMaterialization::StartupInvalidated {
            recovery_eligibility: StartupRecoveryEligibility::RecoveryFailureLatched,
            failure_evidence_digest: Some(failure_latch_digest),
            ..
        } => (
            RuntimeJournalBootstrapState::RecoveryFailedNotReady,
            Some(RuntimeJournalBootstrapReason::RecoveryFailed),
            Some(failure_latch_digest),
        ),
        LiveMaterialization::Draining { .. } => (
            RuntimeJournalBootstrapState::NotReadyBusy,
            Some(RuntimeJournalBootstrapReason::RuntimeBusy),
            None,
        ),
        LiveMaterialization::Quarantined { reason_digest, .. }
        | LiveMaterialization::StartupInvalidated {
            recovery_eligibility: StartupRecoveryEligibility::ReconcileRequired,
            failure_evidence_digest: Some(reason_digest),
            ..
        } => (
            RuntimeJournalBootstrapState::ValidatedOperationalQuarantine,
            Some(RuntimeJournalBootstrapReason::OwnershipUncertain),
            Some(reason_digest),
        ),
        LiveMaterialization::StartupInvalidated {
            recovery_eligibility:
                StartupRecoveryEligibility::RecoveryFailureLatched
                | StartupRecoveryEligibility::ReconcileRequired,
            failure_evidence_digest: None,
            ..
        } => (
            RuntimeJournalBootstrapState::ValidatedOperationalQuarantine,
            Some(RuntimeJournalBootstrapReason::OwnershipUncertain),
            None,
        ),
    }
}

/// Fail-closed production transition error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeControlStateError {
    StartupNotCommitted,
    PreflightRejected,
    Journal(RuntimeJournalError),
}

impl From<RuntimeJournalError> for RuntimeControlStateError {
    fn from(error: RuntimeJournalError) -> Self {
        Self::Journal(error)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    use ed25519_dalek::SigningKey;

    use super::runtime_reference_apply::{
        RuntimeEmptyRetireOwnerPlan, RuntimeOneSourceOwnerPlan, RuntimeReferenceApplyClock,
        RuntimeReferenceApplyClockError, RuntimeReferenceApplyCore, RuntimeReferenceApplyError,
        RuntimeReferenceApplyOutcome, RuntimeReferenceApplySigner, RuntimeReferenceApplyStore,
        RuntimeReferenceApplyStoreError, RuntimeReferenceMaterializationOwner,
        RuntimeReferenceMaterializationOwnerError,
    };
    #[cfg(unix)]
    use super::runtime_reference_owner::RuntimeFixedReferenceMaterializationOwner;
    use super::*;
    #[cfg(unix)]
    use crate::runtime_clock::RuntimeClock;
    use crate::runtime_journal::{
        JournalActionRef, MAX_RUNTIME_TENURE_NONCES, OpaqueCanonicalValue, ReplayLedgerRecord,
        RuntimeJournalSequenceOne, RuntimeJournalSnapshot, RuntimeOneSourceOwnershipInput,
        RuntimeOneSourceResourceRefs, RuntimeOneSourceTombstonesInput,
        RuntimeResourceOwnershipInput, RuntimeResourceTombstoneInput, StorePinnedBuildIdentity,
        decode_and_validate_terminal_receipt,
    };
    use paraegox_kernel::{
        identity::PrincipalRef,
        time::{BoundedDuration, ClockDomainRef, ClockGeneration},
    };
    use paraegox_runtime_contracts::{
        apply::{
            ApplyOperationId, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
            RuntimeApplyControl, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
            TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
        },
        assignment::InstanceRef,
        execution::{CardDefinitionRef, CardImplementationRef, DomainRef},
        installation::{
            InstalledRuntimeArtifactObservationV1, RuntimeCompiledInstallationFactsV1,
            VerifiedRuntimeInstallationV1, VerifiedRuntimeManifestIngressV1,
            generate_build_descriptor, generate_manifest,
        },
        provenance::{
            PlanProvenance, SourcePlanDigest, SourcePlanRef, SourcePlanRevision, SourceScopeRef,
            TargetSliceDigest,
        },
        reference_control::{
            ReferenceApplyRequestDraftV1, ReferenceApplyTerminalOutcomeV1,
            ReferenceChannelBindingV1, ReferenceTargetExecutionPlanV4,
        },
        temporal::{ApplyTemporalConstraint, TemporalConstraintId},
        wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim},
    };

    const TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x11; 16]);
    const SCOPE: SourceScopeRef = SourceScopeRef::from_bytes([0x22; 16]);
    const STORE: [u8; 32] = [0x33; 32];
    const CLOCK_DOMAIN: [u8; 16] = [0x64; 16];

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn sequence_one() -> RuntimeJournalSnapshot {
        RuntimeJournalSnapshot::try_initialize(
            [0x11; 32],
            digest(0x22),
            RuntimeJournalSequenceOne {
                clock_domain: [0x33; 16],
                build_descriptor: OpaqueCanonicalValue::try_pinned_artifact(
                    b"descriptor-v1",
                    digest(0x44),
                )
                .expect("descriptor pin"),
                singleton_manifest: OpaqueCanonicalValue::try_pinned_artifact(
                    b"manifest-v1",
                    digest(0x55),
                )
                .expect("manifest pin"),
                store_pinned_build_identity: StorePinnedBuildIdentity::try_new(
                    [0x57; 32],
                    digest(0x44),
                    digest(0x56),
                    digest(0x58),
                )
                .expect("build identity"),
                compiled_build_instance_id: [0x57; 32],
                compiled_compatibility_digest: digest(0x58),
                admission_policy_fingerprint: digest(0x66),
                channel_policy_fingerprint: digest(0x67),
                controller_key_fingerprint: digest(0x68),
            },
        )
        .expect("sequence one")
    }

    fn compiled_facts() -> RuntimeCompiledInstallationFactsV1 {
        RuntimeCompiledInstallationFactsV1::try_new(
            [0x41; 32],
            CardDefinitionRef::from_bytes([0x42; 16]),
            CardImplementationRef::from_bytes([0x43; 16]),
            [0x44; 16],
            digest(0x45),
            digest(0x46),
        )
        .expect("compiled facts")
    }

    fn installation() -> (
        VerifiedRuntimeInstallationV1,
        RuntimeCompiledInstallationFactsV1,
    ) {
        let compiled = compiled_facts();
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            digest(0x47),
            "aarch64-unknown-linux-gnu",
        )
        .expect("artifact observation");
        let descriptor =
            generate_build_descriptor(&artifact, compiled).expect("descriptor generation");
        let installation = generate_manifest(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            TARGET,
            &artifact,
            compiled,
        )
        .expect("manifest generation");
        (installation, compiled)
    }

    fn installed_sequence_one(
        installation: &VerifiedRuntimeInstallationV1,
        compiled: RuntimeCompiledInstallationFactsV1,
        manifest_wire: &[u8],
        manifest_digest: Digest32,
    ) -> RuntimeJournalSnapshot {
        RuntimeJournalSnapshot::try_initialize(
            STORE,
            digest(0x22),
            RuntimeJournalSequenceOne {
                clock_domain: CLOCK_DOMAIN,
                build_descriptor: OpaqueCanonicalValue::try_pinned_artifact(
                    installation.descriptor_canonical_wire(),
                    installation.descriptor_digest(),
                )
                .expect("descriptor pin"),
                singleton_manifest: OpaqueCanonicalValue::try_pinned_artifact(
                    manifest_wire,
                    manifest_digest,
                )
                .expect("manifest pin"),
                store_pinned_build_identity: StorePinnedBuildIdentity::try_new(
                    installation.build_instance_id(),
                    installation.build_descriptor_digest(),
                    installation.runtime_artifact_sha256(),
                    installation.compiled_reference_compatibility_digest(),
                )
                .expect("build identity"),
                compiled_build_instance_id: compiled.compiled_build_instance_id(),
                compiled_compatibility_digest: compiled
                    .compiled_reference_compatibility_digest()
                    .expect("compiled compatibility"),
                admission_policy_fingerprint: digest(0x66),
                channel_policy_fingerprint: digest(0x67),
                controller_key_fingerprint: digest(0x68),
            },
        )
        .expect("installed sequence one")
    }

    fn writer_control(epoch: u64, supersedes: u64, operation: u8) -> RuntimeApplyControl {
        writer_control_with_expected(epoch, supersedes, operation, ExpectedActive::None)
    }

    fn writer_control_with_expected(
        epoch: u64,
        supersedes: u64,
        operation: u8,
        expected_active: ExpectedActive,
    ) -> RuntimeApplyControl {
        let authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([0x51; 16]),
            TenureKeyRef::from_bytes([0x52; 16]),
            TenureProofAlgorithm::try_new(1).expect("tenure algorithm"),
            1,
        )
        .expect("tenure authority");
        let writer = PlanWriterRef::from_bytes([0x53; 16]);
        let claim = WriterTenureClaim::try_new(
            SCOPE,
            writer,
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(supersedes),
        )
        .expect("tenure claim");
        let proof =
            WriterTenureProof::try_new(authority, claim, &[epoch as u8], &[0x59, epoch as u8])
                .expect("tenure proof");
        let context = PlanWriterContext::try_new(writer, PlanWriterEpoch::new(epoch), proof)
            .expect("writer context");
        RuntimeApplyControl::new(
            context,
            expected_active,
            ApplyOperationId::from_bytes([operation; 16]),
        )
    }

    fn apply_request(
        manifest: &VerifiedRuntimeManifestIngressV1,
        revision: u64,
        epoch: u64,
        supersedes: u64,
        operation: u8,
        temporal_id: u8,
        auth_nonce: &[u8],
    ) -> ReferenceApplyRequestV1 {
        let execution = ReferenceTargetExecutionPlanV4::try_one_source_loop(
            manifest,
            InstanceRef::from_bytes([0x81; 16]),
            DomainRef::from_bytes([0x82; 16]),
            ValidatedReferenceLifecycleBudgetsV1::try_new(
                BoundedDuration::from_nanos(100),
                BoundedDuration::from_nanos(200),
                BoundedDuration::from_nanos(300),
            )
            .expect("lifecycle budgets"),
        )
        .expect("one-source execution");
        let provenance = PlanProvenance::new(
            SCOPE,
            SourcePlanRef::from_bytes([0x61; 16]),
            SourcePlanRevision::new(revision),
            SourcePlanDigest::new(digest(0x62)),
        );
        let temporal = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([temporal_id; 16]),
            ClockDomainRef::from_bytes(CLOCK_DOMAIN),
            ClockGeneration::try_new(1).expect("clock generation"),
            BoundedDuration::from_nanos(10_000),
            BoundedDuration::from_nanos(9_000),
        )
        .expect("temporal constraint");
        let auth = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([0x71; 16]),
            ApplyAuthKeyRef::from_bytes([0x72; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("auth algorithm"),
            1,
            auth_nonce,
        )
        .expect("auth claim");
        ReferenceApplyRequestDraftV1::try_new(
            execution,
            provenance,
            writer_control(epoch, supersedes, operation),
            temporal,
            STORE,
            auth,
        )
        .expect("PXAR draft")
        .finalize(&[0x73, operation])
        .expect("signed PXAR")
    }

    fn empty_apply_request(
        manifest: &VerifiedRuntimeManifestIngressV1,
        revision: u64,
        epoch: u64,
        supersedes: u64,
        operation: u8,
        temporal_id: u8,
        auth_nonce: &[u8],
    ) -> ReferenceApplyRequestV1 {
        empty_apply_request_with_expected(
            manifest,
            revision,
            epoch,
            supersedes,
            operation,
            temporal_id,
            auth_nonce,
            ExpectedActive::None,
        )
    }

    #[allow(clippy::too_many_arguments)] // GOV-WAIVER-0012
    fn empty_apply_request_with_expected(
        manifest: &VerifiedRuntimeManifestIngressV1,
        revision: u64,
        epoch: u64,
        supersedes: u64,
        operation: u8,
        temporal_id: u8,
        auth_nonce: &[u8],
        expected_active: ExpectedActive,
    ) -> ReferenceApplyRequestV1 {
        let execution = ReferenceTargetExecutionPlanV4::try_empty_deactivate(manifest)
            .expect("empty execution");
        let provenance = PlanProvenance::new(
            SCOPE,
            SourcePlanRef::from_bytes([0x61; 16]),
            SourcePlanRevision::new(revision),
            SourcePlanDigest::new(digest(0x62)),
        );
        let temporal = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([temporal_id; 16]),
            ClockDomainRef::from_bytes(CLOCK_DOMAIN),
            ClockGeneration::try_new(1).expect("clock generation"),
            BoundedDuration::from_nanos(10_000),
            BoundedDuration::from_nanos(9_000),
        )
        .expect("temporal constraint");
        let auth = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([0x71; 16]),
            ApplyAuthKeyRef::from_bytes([0x72; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("auth algorithm"),
            1,
            auth_nonce,
        )
        .expect("auth claim");
        ReferenceApplyRequestDraftV1::try_new(
            execution,
            provenance,
            writer_control_with_expected(epoch, supersedes, operation, expected_active),
            temporal,
            STORE,
            auth,
        )
        .expect("empty PXAR draft")
        .finalize(&[0x73, operation])
        .expect("signed empty PXAR")
    }

    fn preflight(
        tenure_nonce: u8,
        request_nonce: u8,
        temporal_lineage: u8,
        admitted_at_nanos: u64,
    ) -> RuntimeReferenceApplyPreflight {
        RuntimeReferenceApplyPreflight {
            local_target: TARGET,
            owner_target_fingerprint: digest(0x22),
            admission_policy_fingerprint: digest(0x66),
            channel_policy_fingerprint: digest(0x67),
            controller_key_fingerprint: digest(0x68),
            tenure_nonce_identity: digest(tenure_nonce),
            request_nonce_identity: digest(request_nonce),
            temporal_lineage_digest: digest(temporal_lineage),
            admitted_at_nanos,
        }
    }

    fn indexed_digest(index: u64) -> Digest32 {
        let mut bytes = [0xa5; 32];
        bytes[24..].copy_from_slice(&index.to_be_bytes());
        Digest32::from_bytes(bytes)
    }

    #[test]
    fn startup_commit_precedes_read_only_bootstrap_facts() {
        let sequence_one = sequence_one();
        let started = RuntimeControlState::try_start(&sequence_one).expect("startup successor");
        let facts = started.bootstrap_facts().expect("bootstrap facts");

        assert_eq!(started.snapshot().sequence(), 2);
        assert_eq!(facts.store_instance_id(), [0x11; 32]);
        assert_eq!(facts.owner_target_fingerprint(), digest(0x22));
        assert_eq!(facts.snapshot_sequence(), 2);
        assert_eq!(facts.runtime_host_epoch(), 1);
        assert_eq!(facts.clock_domain(), [0x33; 16]);
        assert_eq!(facts.clock_generation(), 1);
        assert_eq!(facts.compiled_build_instance_id(), [0x57; 32]);
        assert_eq!(facts.compiled_compatibility_digest(), digest(0x58));
        assert_eq!(facts.manifest_digest(), digest(0x55));
        assert_eq!(facts.admission_policy_fingerprint(), digest(0x66));
        assert_eq!(
            facts.readiness(),
            RuntimeJournalBootstrapState::ReadyForApply
        );
        assert_eq!(facts.reason(), None);
        assert_eq!(facts.reason_evidence_digest(), None);
    }

    #[test]
    fn sequence_one_cannot_be_wrapped_as_post_start_control_state() {
        let state = RuntimeControlState {
            snapshot: sequence_one(),
        };
        assert_eq!(
            state.bootstrap_facts(),
            Err(RuntimeControlStateError::StartupNotCommitted)
        );
    }

    #[test]
    fn committed_tenure_token_is_sequence_bound_and_commits_full_once() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let sequence_one = installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        );
        let started = RuntimeControlState::try_start(&sequence_one).expect("startup");
        let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"apply-nonce");
        let preflight = preflight(0x74, 0x75, 0x76, 1_000);

        let transition = started
            .try_reference_tenure_only(&request, preflight)
            .expect("tenure commit");
        assert_eq!(
            transition.disposition(),
            RuntimeAdmissionDisposition::Committed
        );
        assert_eq!(transition.state().snapshot().sequence(), 3);
        assert_eq!(
            transition
                .prepared_admission()
                .expect("same-ingress capability")
                .bound_sequence(),
            3
        );
        let (tenured, _, prepared) = transition.into_parts();
        let prepared = prepared.expect("same-ingress capability");

        let full = tenured
            .try_reference_full_admission(prepared)
            .expect("full admission");
        assert_eq!(full.disposition(), RuntimeAdmissionDisposition::Committed);
        assert_eq!(full.state().snapshot().sequence(), 4);
        assert_eq!(full.prepared_admission(), None);
        assert_eq!(full.state().snapshot().state().host.tenure_nonces.len(), 1);
        assert_eq!(full.state().snapshot().state().host.request_nonces.len(), 1);
        assert_eq!(
            full.state().snapshot().state().host.temporal_lineages.len(),
            1
        );
        assert_eq!(
            full.state()
                .snapshot()
                .state()
                .prepared
                .as_ref()
                .expect("prepared operation")
                .installed_deadline_nanos,
            10_000
        );
    }

    #[test]
    fn fresh_retry_after_tenure_only_cannot_renew_deadline_or_mint_token() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"apply-nonce");
        let original = preflight(0x74, 0x75, 0x76, 1_000);
        let (tenured, _, original_token) = started
            .try_reference_tenure_only(&request, original)
            .expect("tenure commit")
            .into_parts();
        assert!(original_token.is_some());

        let renewed = RuntimeReferenceApplyPreflight {
            admitted_at_nanos: 100_000,
            ..original
        };
        let retry = tenured
            .try_reference_tenure_only(&request, renewed)
            .expect("exact tenure retry");
        assert_eq!(
            retry.disposition(),
            RuntimeAdmissionDisposition::AlreadyDurable
        );
        assert_eq!(retry.state().snapshot().sequence(), 3);
        assert_eq!(retry.prepared_admission(), None);
        assert!(
            retry
                .state()
                .snapshot()
                .state()
                .host
                .request_nonces
                .is_empty()
        );
        assert!(
            retry
                .state()
                .snapshot()
                .state()
                .host
                .temporal_lineages
                .is_empty()
        );
        assert!(retry.state().snapshot().state().prepared.is_none());
    }

    #[test]
    fn fully_durable_exact_replay_is_idempotent_but_changed_deadline_is_rejected() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"apply-nonce");
        let original = preflight(0x74, 0x75, 0x76, 1_000);
        let (tenured, _, prepared) = started
            .try_reference_tenure_only(&request, original)
            .expect("tenure commit")
            .into_parts();
        let (fully_admitted, _, _) = tenured
            .try_reference_full_admission(prepared.expect("capability"))
            .expect("full admission")
            .into_parts();

        let exact = fully_admitted
            .try_reference_tenure_only(&request, original)
            .expect("exact full replay");
        assert_eq!(
            exact.disposition(),
            RuntimeAdmissionDisposition::AlreadyDurable
        );
        assert_eq!(exact.state().snapshot().sequence(), 4);
        let (same_state, _, replay_token) = exact.into_parts();
        let replay = same_state
            .try_reference_full_admission(replay_token.expect("exact replay capability"))
            .expect("idempotent full replay");
        assert_eq!(
            replay.disposition(),
            RuntimeAdmissionDisposition::AlreadyDurable
        );
        assert_eq!(replay.state().snapshot().sequence(), 4);
        assert_eq!(
            replay.state().snapshot().state().host.tenure_nonces.len(),
            1
        );
        assert_eq!(
            replay.state().snapshot().state().host.request_nonces.len(),
            1
        );

        let renewed = RuntimeReferenceApplyPreflight {
            admitted_at_nanos: 100_000,
            ..original
        };
        assert_eq!(
            replay.state().try_reference_tenure_only(&request, renewed),
            Err(RuntimeControlStateError::PreflightRejected)
        );
    }

    #[test]
    fn prepared_admission_token_rejects_a_different_journal_sequence() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"apply-nonce");
        let (_, _, prepared) = started
            .try_reference_tenure_only(&request, preflight(0x74, 0x75, 0x76, 1_000))
            .expect("tenure commit")
            .into_parts();

        assert_eq!(
            started.try_reference_full_admission(prepared.expect("capability")),
            Err(RuntimeControlStateError::PreflightRejected)
        );
        assert_eq!(started.snapshot().sequence(), 2);
        assert!(started.snapshot().state().host.request_nonces.is_empty());
    }

    #[test]
    fn same_request_nonce_with_different_pxar_is_rejected_without_mutation() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"apply-nonce");
        let evidence = preflight(0x74, 0x75, 0x76, 1_000);
        let (tenured, _, prepared) = started
            .try_reference_tenure_only(&request, evidence)
            .expect("tenure commit")
            .into_parts();
        let (fully_admitted, _, _) = tenured
            .try_reference_full_admission(prepared.expect("capability"))
            .expect("full admission")
            .into_parts();
        let different = apply_request(&ingress, 8, 1, 0, 0x55, 0x65, b"different-nonce");

        assert_eq!(
            fully_admitted.try_reference_tenure_only(&different, evidence),
            Err(RuntimeControlStateError::PreflightRejected)
        );
        assert_eq!(fully_admitted.snapshot().sequence(), 4);
        assert_eq!(
            fully_admitted.snapshot().state().host.request_nonces.len(),
            1
        );
    }

    #[test]
    fn wrong_manifest_bytes_fail_even_when_the_caller_supplies_the_real_digest() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let wrong_bytes = b"not-the-installer-manifest";
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            wrong_bytes,
            installation.manifest_digest(),
        ))
        .expect("startup keeps manifest opaque");
        let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"apply-nonce");

        assert_eq!(
            started.try_reference_tenure_only(&request, preflight(0x74, 0x75, 0x76, 1_000)),
            Err(RuntimeControlStateError::PreflightRejected)
        );
        assert_eq!(started.snapshot().sequence(), 2);
        assert!(started.snapshot().state().host.tenure_nonces.is_empty());
    }

    #[test]
    fn full_tenure_capacity_allows_exact_retry_but_rejects_a_new_identity() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"apply-nonce");
        let original = preflight(0x74, 0x75, 0x76, 1_000);
        let (tenured, _, _) = started
            .try_reference_tenure_only(&request, original)
            .expect("tenure commit")
            .into_parts();

        let mut state = tenured.snapshot().state().clone();
        let admitted = state.host.tenure_nonces[0];
        state.host.tenure_nonces = (1..MAX_RUNTIME_TENURE_NONCES)
            .map(|index| ReplayLedgerRecord {
                identity: indexed_digest(index as u64),
                value_digest: digest(0xd1),
            })
            .chain(core::iter::once(admitted))
            .collect();
        state.host.tenure_nonces.sort_unstable();
        let at_capacity = RuntimeControlState {
            snapshot: RuntimeJournalSnapshot::try_new(
                *tenured.snapshot().store_instance_id(),
                *tenured.snapshot().owner_target_fingerprint(),
                tenured.snapshot().sequence(),
                state,
            )
            .expect("valid capacity snapshot"),
        };

        let exact = at_capacity
            .try_reference_tenure_only(&request, original)
            .expect("exact identity does not consume capacity");
        assert_eq!(
            exact.disposition(),
            RuntimeAdmissionDisposition::AlreadyDurable
        );
        assert_eq!(
            exact.state().snapshot().state().host.tenure_nonces.len(),
            MAX_RUNTIME_TENURE_NONCES
        );

        let new_request = apply_request(&ingress, 8, 2, 1, 0x55, 0x65, b"new-apply-nonce");
        let error = at_capacity
            .try_reference_tenure_only(&new_request, preflight(0x77, 0x78, 0x79, 2_000))
            .expect_err("new identity must consume capacity");
        assert_eq!(
            error,
            RuntimeControlStateError::Journal(RuntimeJournalError::InvalidStateInvariant)
        );
        assert_eq!(at_capacity.snapshot().sequence(), 3);
        assert_eq!(
            at_capacity.snapshot().state().host.tenure_nonces.len(),
            MAX_RUNTIME_TENURE_NONCES
        );
    }

    #[derive(Clone)]
    struct FakeApplyStore {
        snapshot: RuntimeJournalSnapshot,
        commits: Rc<Cell<u64>>,
    }

    impl RuntimeReferenceApplyStore for FakeApplyStore {
        fn current_snapshot(
            &self,
        ) -> Result<RuntimeJournalSnapshot, RuntimeReferenceApplyStoreError> {
            Ok(self.snapshot.clone())
        }

        fn commit_snapshot(
            &mut self,
            next: RuntimeJournalSnapshot,
        ) -> Result<(), RuntimeReferenceApplyStoreError> {
            next.validate_successor_of(&self.snapshot)
                .map_err(|_| RuntimeReferenceApplyStoreError::Unavailable)?;
            self.snapshot = next;
            self.commits.set(self.commits.get() + 1);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FailpointApplyStore {
        snapshot: Rc<RefCell<RuntimeJournalSnapshot>>,
        attempts: Rc<Cell<u64>>,
        published: Rc<Cell<u64>>,
        fail_before_publish: Rc<Cell<Option<u64>>>,
        fail_after_publish: Rc<Cell<Option<u64>>>,
    }

    impl FailpointApplyStore {
        fn new(snapshot: RuntimeJournalSnapshot, fail_on_attempt: u64) -> Self {
            Self {
                snapshot: Rc::new(RefCell::new(snapshot)),
                attempts: Rc::new(Cell::new(0)),
                published: Rc::new(Cell::new(0)),
                fail_before_publish: Rc::new(Cell::new(Some(fail_on_attempt))),
                fail_after_publish: Rc::new(Cell::new(None)),
            }
        }

        fn new_after_publish(snapshot: RuntimeJournalSnapshot, fail_on_attempt: u64) -> Self {
            Self {
                snapshot: Rc::new(RefCell::new(snapshot)),
                attempts: Rc::new(Cell::new(0)),
                published: Rc::new(Cell::new(0)),
                fail_before_publish: Rc::new(Cell::new(None)),
                fail_after_publish: Rc::new(Cell::new(Some(fail_on_attempt))),
            }
        }
    }

    impl RuntimeReferenceApplyStore for FailpointApplyStore {
        fn current_snapshot(
            &self,
        ) -> Result<RuntimeJournalSnapshot, RuntimeReferenceApplyStoreError> {
            Ok(self.snapshot.borrow().clone())
        }

        fn commit_snapshot(
            &mut self,
            next: RuntimeJournalSnapshot,
        ) -> Result<(), RuntimeReferenceApplyStoreError> {
            let attempt = self.attempts.get() + 1;
            self.attempts.set(attempt);
            if self.fail_before_publish.get() == Some(attempt) {
                return Err(RuntimeReferenceApplyStoreError::Unavailable);
            }
            next.validate_successor_of(&self.snapshot.borrow())
                .map_err(|_| RuntimeReferenceApplyStoreError::Unavailable)?;
            *self.snapshot.borrow_mut() = next;
            self.published.set(self.published.get() + 1);
            if self.fail_after_publish.get() == Some(attempt) {
                return Err(RuntimeReferenceApplyStoreError::Unavailable);
            }
            Ok(())
        }
    }

    struct FakeApplyClock {
        observed_at_nanos: u64,
    }

    impl RuntimeReferenceApplyClock for FakeApplyClock {
        fn observe(
            &mut self,
            expected_clock_generation: u64,
        ) -> Result<RuntimeDeadlineObservation, RuntimeReferenceApplyClockError> {
            Ok(RuntimeDeadlineObservation {
                clock_generation: expected_clock_generation,
                observed_at_nanos: self.observed_at_nanos,
            })
        }
    }

    struct ScriptedApplyClock {
        observations: Vec<u64>,
        next: usize,
    }

    impl ScriptedApplyClock {
        fn new(observations: &[u64]) -> Self {
            Self {
                observations: observations.to_vec(),
                next: 0,
            }
        }
    }

    impl RuntimeReferenceApplyClock for ScriptedApplyClock {
        fn observe(
            &mut self,
            expected_clock_generation: u64,
        ) -> Result<RuntimeDeadlineObservation, RuntimeReferenceApplyClockError> {
            let observed_at_nanos = *self
                .observations
                .get(self.next)
                .ok_or(RuntimeReferenceApplyClockError::Unavailable)?;
            self.next += 1;
            Ok(RuntimeDeadlineObservation {
                clock_generation: expected_clock_generation,
                observed_at_nanos,
            })
        }
    }

    #[derive(Clone)]
    struct FakeOwnerCounters {
        materialize: Rc<Cell<u64>>,
        start: Rc<Cell<u64>>,
        stop: Rc<Cell<u64>>,
        cleanup: Rc<Cell<u64>>,
    }

    impl FakeOwnerCounters {
        fn new() -> Self {
            Self {
                materialize: Rc::new(Cell::new(0)),
                start: Rc::new(Cell::new(0)),
                stop: Rc::new(Cell::new(0)),
                cleanup: Rc::new(Cell::new(0)),
            }
        }
    }

    struct FakeOwnerToken {
        _allocation: Box<[u8; 32]>,
        plan: RuntimeOneSourceOwnerPlan,
        materialized: bool,
        started: bool,
        active_slice_digest: Option<TargetSliceDigest>,
        stop_action_id: Option<[u8; 16]>,
        stopped: bool,
        cleaned: bool,
    }

    struct FakeMaterializationOwner {
        token: Option<FakeOwnerToken>,
        counters: FakeOwnerCounters,
    }

    impl FakeMaterializationOwner {
        fn new(counters: FakeOwnerCounters) -> Self {
            Self {
                token: None,
                counters,
            }
        }

        fn token_for_action(
            &mut self,
            action: JournalActionRef,
        ) -> Result<&mut FakeOwnerToken, RuntimeReferenceMaterializationOwnerError> {
            self.token
                .as_mut()
                .filter(|token| {
                    token.plan.action_id == action.action_id
                        && token.plan.domain_generation == action.domain_generation
                        && token.plan.instance_generation == action.instance_generation
                        && token.plan.resource_generation == action.resource_generation
                })
                .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)
        }
    }

    impl RuntimeReferenceMaterializationOwner for FakeMaterializationOwner {
        fn prepare_one_source(
            &mut self,
            request: &ReferenceApplyRequestV1,
            durable_action: Option<JournalActionRef>,
        ) -> Result<RuntimeOneSourceOwnerPlan, RuntimeReferenceMaterializationOwnerError> {
            let loop_facts = request
                .target_execution()
                .loop_facts()
                .ok_or(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
            let expected = RuntimeOneSourceOwnerPlan {
                action_id: [0xa1; 16],
                domain_generation: 7,
                instance_generation: 7,
                resource_generation: 7,
                resources: RuntimeOneSourceResourceRefs {
                    loop_domain: *loop_facts.domain().as_bytes(),
                    card_instance: *loop_facts.instance().as_bytes(),
                },
                signed_budgets: loop_facts.budgets(),
            };
            if self.token.is_none() {
                if durable_action.is_some() {
                    return Err(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken);
                }
                self.token = Some(FakeOwnerToken {
                    _allocation: Box::new([0xcd; 32]),
                    plan: expected,
                    materialized: false,
                    started: false,
                    active_slice_digest: None,
                    stop_action_id: None,
                    stopped: false,
                    cleaned: false,
                });
            }
            let token = self
                .token
                .as_ref()
                .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
            if token.plan != expected
                || durable_action.is_some_and(|action| {
                    action.action_id != token.plan.action_id
                        || action.domain_generation != token.plan.domain_generation
                        || action.instance_generation != token.plan.instance_generation
                        || action.resource_generation != token.plan.resource_generation
                })
            {
                return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
            }
            Ok(token.plan)
        }

        fn materialize_one_source(
            &mut self,
            action: JournalActionRef,
            resources: RuntimeOneSourceResourceRefs,
        ) -> Result<RuntimeOneSourceOwnershipInput, RuntimeReferenceMaterializationOwnerError>
        {
            let first_materialization = {
                let token = self.token_for_action(action)?;
                if token.plan.resources != resources {
                    return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
                }
                let first = !token.materialized;
                token.materialized = true;
                first
            };
            if first_materialization {
                self.counters
                    .materialize
                    .set(self.counters.materialize.get() + 1);
            }
            Ok(RuntimeOneSourceOwnershipInput {
                loop_domain: RuntimeResourceOwnershipInput {
                    logical_ref: resources.loop_domain,
                    os_identity: OpaqueCanonicalValue::try_resource_evidence(
                        b"fake-loop-os-token",
                        digest(0xa2),
                    )
                    .expect("loop OS evidence"),
                    workspace_identity: OpaqueCanonicalValue::try_resource_evidence(
                        b"fake-loop-workspace-token",
                        digest(0xa3),
                    )
                    .expect("loop workspace evidence"),
                    containment_identity: OpaqueCanonicalValue::try_resource_evidence(
                        b"fake-loop-containment-token",
                        digest(0xa4),
                    )
                    .expect("loop containment evidence"),
                },
                card_instance: RuntimeResourceOwnershipInput {
                    logical_ref: resources.card_instance,
                    os_identity: OpaqueCanonicalValue::try_resource_evidence(
                        b"fake-card-os-token",
                        digest(0xa5),
                    )
                    .expect("card OS evidence"),
                    workspace_identity: OpaqueCanonicalValue::try_resource_evidence(
                        b"fake-card-workspace-token",
                        digest(0xa6),
                    )
                    .expect("card workspace evidence"),
                    containment_identity: OpaqueCanonicalValue::try_resource_evidence(
                        b"fake-card-containment-token",
                        digest(0xa7),
                    )
                    .expect("card containment evidence"),
                },
            })
        }

        fn start_one_source_once(
            &mut self,
            action: JournalActionRef,
        ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
            let first_start = {
                let token = self.token_for_action(action)?;
                if !token.materialized || token.cleaned {
                    return Err(RuntimeReferenceMaterializationOwnerError::CallbackFailed);
                }
                let first = !token.started;
                token.started = true;
                first
            };
            if first_start {
                self.counters.start.set(self.counters.start.get() + 1);
            }
            Ok(())
        }

        fn prepare_empty_retire(
            &mut self,
            active_slice_digest: TargetSliceDigest,
            resource_generation: u64,
            durable_action: Option<JournalActionRef>,
        ) -> Result<RuntimeEmptyRetireOwnerPlan, RuntimeReferenceMaterializationOwnerError>
        {
            let token = self
                .token
                .as_mut()
                .filter(|token| {
                    token.started && token.plan.resource_generation == resource_generation
                })
                .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
            if token
                .active_slice_digest
                .is_some_and(|digest| digest != active_slice_digest)
            {
                return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
            }
            token.active_slice_digest = Some(active_slice_digest);
            let action_id = *token.stop_action_id.get_or_insert([0xb1; 16]);
            if durable_action.is_some_and(|action| action.action_id != action_id) {
                return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
            }
            Ok(RuntimeEmptyRetireOwnerPlan {
                action_id,
                signed_budgets: token.plan.signed_budgets,
            })
        }

        fn stop_one_source_once(
            &mut self,
            action: JournalActionRef,
        ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
            let token = self
                .token
                .as_mut()
                .filter(|token| token.stop_action_id == Some(action.action_id) && token.started)
                .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
            if !token.stopped {
                token.stopped = true;
                self.counters.stop.set(self.counters.stop.get() + 1);
            }
            Ok(())
        }

        fn cleanup_one_source_once(
            &mut self,
            action: JournalActionRef,
        ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError>
        {
            let token = self
                .token
                .as_mut()
                .filter(|token| token.stop_action_id == Some(action.action_id) && token.stopped)
                .ok_or(RuntimeReferenceMaterializationOwnerError::CleanupFailed)?;
            if !token.cleaned {
                token.cleaned = true;
                self.counters.cleanup.set(self.counters.cleanup.get() + 1);
            }
            Ok(RuntimeOneSourceTombstonesInput {
                loop_domain: RuntimeResourceTombstoneInput {
                    logical_ref: token.plan.resources.loop_domain,
                    evidence: OpaqueCanonicalValue::try_resource_evidence(
                        b"fake-loop-tombstone",
                        digest(0xb2),
                    )
                    .expect("loop tombstone"),
                },
                card_instance: RuntimeResourceTombstoneInput {
                    logical_ref: token.plan.resources.card_instance,
                    evidence: OpaqueCanonicalValue::try_resource_evidence(
                        b"fake-card-tombstone",
                        digest(0xb3),
                    )
                    .expect("card tombstone"),
                },
            })
        }
    }

    fn reference_apply_channel() -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            TARGET,
            PrincipalRef::from_bytes([0x91; 16]),
            digest(0x92),
            digest(0x93),
        )
        .expect("reference apply channel")
    }

    fn reference_apply_signer() -> RuntimeReferenceApplySigner {
        RuntimeReferenceApplySigner::try_new(
            SigningKey::from_bytes(&[0x94; 32]),
            ApplyAuthKeyRef::from_bytes([0x95; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("response algorithm"),
            1,
        )
        .expect("response signer")
    }

    #[test]
    fn no_active_empty_apply_commits_three_durable_boundaries_and_replays_exact_pxrt() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let commits = Rc::new(Cell::new(0));
        let store = FakeApplyStore {
            snapshot: started.snapshot().clone(),
            commits: Rc::clone(&commits),
        };
        let channel = reference_apply_channel();
        let mut core = RuntimeReferenceApplyCore::try_new(
            store,
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            reference_apply_signer(),
            channel,
        )
        .expect("apply core");
        let request = empty_apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"empty-apply-nonce");
        let evidence = preflight(0x74, 0x75, 0x76, 1_000);

        let first = core.try_apply(&request, evidence).unwrap_or_else(|error| {
            panic!(
                "no-effect empty apply failed after {} commits: {error:?}",
                commits.get()
            )
        });
        let RuntimeReferenceApplyOutcome::Terminal(first) = first else {
            panic!("empty apply must complete")
        };
        let first_wire = first.canonical_wire().to_vec();
        assert_eq!(
            first.receipt().facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero
        );
        assert_eq!(first.receipt().facts().completion_snapshot_sequence(), 5);
        assert_eq!(first.original_runtime_peer(), channel.runtime_peer());
        assert_eq!(
            first.original_channel_binding_digest(),
            channel.binding_digest()
        );
        assert_eq!(commits.get(), 3, "tenure, full admission, terminal");

        let replay = core.try_apply(&request, evidence).expect("exact replay");
        let RuntimeReferenceApplyOutcome::Terminal(replay) = replay else {
            panic!("replay must return the stored terminal")
        };
        assert_eq!(replay.canonical_wire(), first_wire);
        assert_eq!(commits.get(), 3, "replay must not mutate the journal");

        let terminal = core.snapshot().state().terminal_operations[0].clone();
        let decoded = decode_and_validate_terminal_receipt(STORE, &terminal)
            .expect("stored PXRT cross-check");
        assert_eq!(decoded.canonical_wire(), first_wire);

        let mut wrong_facts = terminal.clone();
        wrong_facts.resource_census_digest = digest(0xfe);
        assert!(decode_and_validate_terminal_receipt(STORE, &wrong_facts).is_err());

        let mut second_codec = terminal;
        second_codec.canonical_response =
            OpaqueCanonicalValue::try_terminal_response(b"not-pxrt", second_codec.result_digest)
                .expect("opaque bound alone deliberately does not decode");
        assert!(decode_and_validate_terminal_receipt(STORE, &second_codec).is_err());
    }

    #[test]
    fn same_operation_with_different_request_is_conflict_without_mutation() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let commits = Rc::new(Cell::new(0));
        let mut core = RuntimeReferenceApplyCore::try_new(
            FakeApplyStore {
                snapshot: started.snapshot().clone(),
                commits: Rc::clone(&commits),
            },
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("apply core");
        let original = empty_apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"empty-apply-nonce");
        let evidence = preflight(0x74, 0x75, 0x76, 1_000);
        core.try_apply(&original, evidence).expect("initial apply");
        let conflicting =
            empty_apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"different-request-nonce");

        assert_eq!(
            core.try_apply(&conflicting, evidence),
            Err(RuntimeReferenceApplyError::OperationConflict)
        );
        assert_eq!(commits.get(), 3);
        assert_eq!(core.snapshot().sequence(), 5);
    }

    #[test]
    fn real_in_memory_owner_runs_loop_active_then_head_first_empty_exact_zero() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let commits = Rc::new(Cell::new(0));
        let counters = FakeOwnerCounters::new();
        let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
            FakeApplyStore {
                snapshot: started.snapshot().clone(),
                commits: Rc::clone(&commits),
            },
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            FakeMaterializationOwner::new(counters.clone()),
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("materialized apply core");
        let loop_request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"materialize-loop-nonce");

        let active = core
            .try_apply(&loop_request, preflight(0x74, 0x75, 0x76, 1_000))
            .expect("one-source active");
        let RuntimeReferenceApplyOutcome::Terminal(active) = active else {
            panic!("one-source must terminate active")
        };
        assert_eq!(
            active.receipt().facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
        );
        assert_eq!(active.receipt().facts().completion_snapshot_sequence(), 8);
        assert_eq!(commits.get(), 6);
        assert_eq!(counters.materialize.get(), 1);
        assert_eq!(counters.start.get(), 1);
        assert_eq!(counters.stop.get(), 0);
        assert_eq!(counters.cleanup.get(), 0);

        assert!(matches!(
            core.try_apply(&loop_request, preflight(0x74, 0x75, 0x76, 1_000),),
            Ok(RuntimeReferenceApplyOutcome::Terminal(_))
        ));
        assert_eq!(commits.get(), 6, "terminal replay must not commit");

        let empty_request = empty_apply_request_with_expected(
            &ingress,
            8,
            1,
            0,
            0x55,
            0x64,
            b"materialize-empty-nonce",
            ExpectedActive::Exact(loop_request.target_slice_digest()),
        );
        let empty = core
            .try_apply(&empty_request, preflight(0x74, 0x85, 0x86, 1_000))
            .unwrap_or_else(|error| {
                panic!(
                    "head-first empty failed after {} commits (stop {}, cleanup {}): {error:?}",
                    commits.get(),
                    counters.stop.get(),
                    counters.cleanup.get()
                )
            });
        let RuntimeReferenceApplyOutcome::Terminal(empty) = empty else {
            panic!("empty must terminate exact zero")
        };
        assert_eq!(
            empty.receipt().facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero
        );
        assert_eq!(empty.receipt().facts().completion_snapshot_sequence(), 12);
        assert_eq!(commits.get(), 10);
        assert_eq!(counters.materialize.get(), 1);
        assert_eq!(counters.start.get(), 1);
        assert_eq!(counters.stop.get(), 1);
        assert_eq!(counters.cleanup.get(), 1);
        assert!(core.snapshot().state().prepared.is_none());
        assert!(matches!(
            core.snapshot().state().live_materialization,
            LiveMaterialization::ExactZero { .. }
        ));
        assert!(
            core.snapshot()
                .state()
                .owned_resources
                .iter()
                .all(|resource| resource.phase == crate::runtime_journal::ResourcePhase::Terminal)
        );
    }

    #[test]
    fn restarted_core_terminal_replay_does_not_restore_same_tenure_continuation() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let commits = Rc::new(Cell::new(0));
        let counters = FakeOwnerCounters::new();
        let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
            FakeApplyStore {
                snapshot: started.snapshot().clone(),
                commits: Rc::clone(&commits),
            },
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            FakeMaterializationOwner::new(counters.clone()),
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("materialized apply core");
        let loop_request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"resident-restart-loop");
        let loop_evidence = preflight(0x74, 0x75, 0x76, 1_000);
        assert!(matches!(
            core.try_apply(&loop_request, loop_evidence),
            Ok(RuntimeReferenceApplyOutcome::Terminal(_))
        ));
        assert_eq!(commits.get(), 6);

        let (store, clock, owner, signer, channel) = core.into_test_recovery_parts();
        let mut restarted =
            RuntimeReferenceApplyCore::try_new_with_owner(store, clock, owner, signer, channel)
                .expect("restarted core");
        assert!(matches!(
            restarted.try_apply(&loop_request, loop_evidence),
            Ok(RuntimeReferenceApplyOutcome::Terminal(_))
        ));
        assert_eq!(commits.get(), 6, "terminal replay must not commit");

        let empty_request = empty_apply_request_with_expected(
            &ingress,
            8,
            1,
            0,
            0x55,
            0x64,
            b"resident-restart-empty",
            ExpectedActive::Exact(loop_request.target_slice_digest()),
        );
        let before = restarted.snapshot().clone();
        assert_eq!(
            restarted.try_apply(&empty_request, preflight(0x74, 0x85, 0x86, 1_000)),
            Ok(RuntimeReferenceApplyOutcome::TenureOnlyDurable)
        );
        assert_eq!(restarted.snapshot(), &before);
        assert_eq!(commits.get(), 6);
        assert_eq!(counters.stop.get(), 0);
        assert_eq!(counters.cleanup.get(), 0);
    }

    #[test]
    fn same_tenure_full_commit_failure_consumes_resident_continuation() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        // The active Loop consumes six publications. The same-tenure Empty
        // skips tenure and fails before publishing its full admission.
        let store = FailpointApplyStore::new(started.snapshot().clone(), 7);
        let published = Rc::clone(&store.published);
        let counters = FakeOwnerCounters::new();
        let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
            store,
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            FakeMaterializationOwner::new(counters.clone()),
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("failpoint core");
        let loop_request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"resident-fail-loop");
        core.try_apply(&loop_request, preflight(0x74, 0x75, 0x76, 1_000))
            .expect("active predecessor");

        let empty_request = empty_apply_request_with_expected(
            &ingress,
            8,
            1,
            0,
            0x55,
            0x64,
            b"resident-fail-empty",
            ExpectedActive::Exact(loop_request.target_slice_digest()),
        );
        let evidence = preflight(0x74, 0x85, 0x86, 1_000);
        assert!(matches!(
            core.try_apply(&empty_request, evidence),
            Err(RuntimeReferenceApplyError::Store(
                RuntimeReferenceApplyStoreError::Unavailable
            ))
        ));
        let before_retry = core.snapshot().clone();
        assert_eq!(published.get(), 6);
        assert_eq!(counters.stop.get(), 0);

        assert_eq!(
            core.try_apply(&empty_request, evidence),
            Ok(RuntimeReferenceApplyOutcome::TenureOnlyDurable)
        );
        assert_eq!(core.snapshot(), &before_retry);
        assert_eq!(published.get(), 6);
        assert_eq!(counters.stop.get(), 0);
        assert_eq!(counters.cleanup.get(), 0);
    }

    #[test]
    fn uncertain_same_tenure_full_commit_consumes_resident_continuation() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        // The active Loop consumes six publications. The same-tenure full
        // admission is published seventh, but the store reports uncertainty.
        let store = FailpointApplyStore::new_after_publish(started.snapshot().clone(), 7);
        let durable = store.clone();
        let published = Rc::clone(&store.published);
        let counters = FakeOwnerCounters::new();
        let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
            store,
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            FakeMaterializationOwner::new(counters.clone()),
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("failpoint core");
        let loop_request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"resident-uncertain-loop");
        core.try_apply(&loop_request, preflight(0x74, 0x75, 0x76, 1_000))
            .expect("active predecessor");
        assert!(core.has_test_resident_full_admitted_tenure());

        let empty_request = empty_apply_request_with_expected(
            &ingress,
            8,
            1,
            0,
            0x55,
            0x64,
            b"resident-uncertain-empty",
            ExpectedActive::Exact(loop_request.target_slice_digest()),
        );
        assert!(matches!(
            core.try_apply(&empty_request, preflight(0x74, 0x85, 0x86, 1_000)),
            Err(RuntimeReferenceApplyError::Store(
                RuntimeReferenceApplyStoreError::Unavailable
            ))
        ));
        assert!(!core.has_test_resident_full_admitted_tenure());
        assert_eq!(published.get(), 7);
        assert_eq!(durable.snapshot.borrow().sequence(), 9);
        assert_eq!(core.snapshot().sequence(), 8);
        assert_eq!(counters.stop.get(), 0);
        assert_eq!(counters.cleanup.get(), 0);
    }

    #[test]
    fn higher_tenure_full_commit_failure_cannot_reuse_old_resident_continuation() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        // The active Loop consumes six publications. Higher tenure publishes
        // its fence seventh, then fails before publishing full admission.
        let store = FailpointApplyStore::new(started.snapshot().clone(), 8);
        let published = Rc::clone(&store.published);
        let counters = FakeOwnerCounters::new();
        let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
            store,
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            FakeMaterializationOwner::new(counters.clone()),
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("failpoint core");
        let loop_request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"higher-fail-loop");
        core.try_apply(&loop_request, preflight(0x74, 0x75, 0x76, 1_000))
            .expect("active predecessor");

        let empty_request = empty_apply_request_with_expected(
            &ingress,
            8,
            2,
            1,
            0x55,
            0x64,
            b"higher-fail-empty",
            ExpectedActive::Exact(loop_request.target_slice_digest()),
        );
        let evidence = preflight(0x84, 0x85, 0x86, 1_000);
        assert!(matches!(
            core.try_apply(&empty_request, evidence),
            Err(RuntimeReferenceApplyError::Store(
                RuntimeReferenceApplyStoreError::Unavailable
            ))
        ));
        let before_retry = core.snapshot().clone();
        assert_eq!(published.get(), 7);
        assert_eq!(counters.stop.get(), 0);

        assert_eq!(
            core.try_apply(&empty_request, evidence),
            Ok(RuntimeReferenceApplyOutcome::TenureOnlyDurable)
        );
        assert_eq!(core.snapshot(), &before_retry);
        assert_eq!(published.get(), 7);
        assert_eq!(counters.stop.get(), 0);
        assert_eq!(counters.cleanup.get(), 0);
    }

    #[test]
    fn uncertain_higher_tenure_fence_commit_clears_old_resident_continuation() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        // The active Loop consumes six publications. The higher-tenure fence is
        // published seventh, but the store reports an uncertain failure.
        let store = FailpointApplyStore::new_after_publish(started.snapshot().clone(), 7);
        let durable = store.clone();
        let published = Rc::clone(&store.published);
        let counters = FakeOwnerCounters::new();
        let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
            store,
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            FakeMaterializationOwner::new(counters.clone()),
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("failpoint core");
        let loop_request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"fence-uncertain-loop");
        core.try_apply(&loop_request, preflight(0x74, 0x75, 0x76, 1_000))
            .expect("active predecessor");
        assert!(core.has_test_resident_full_admitted_tenure());

        let empty_request = empty_apply_request_with_expected(
            &ingress,
            8,
            2,
            1,
            0x55,
            0x64,
            b"fence-uncertain-empty",
            ExpectedActive::Exact(loop_request.target_slice_digest()),
        );
        assert!(matches!(
            core.try_apply(&empty_request, preflight(0x84, 0x85, 0x86, 1_000)),
            Err(RuntimeReferenceApplyError::Store(
                RuntimeReferenceApplyStoreError::Unavailable
            ))
        ));
        assert!(!core.has_test_resident_full_admitted_tenure());
        assert_eq!(published.get(), 7);
        assert_eq!(durable.snapshot.borrow().sequence(), 9);
        assert_eq!(core.snapshot().sequence(), 8);
        assert_eq!(counters.stop.get(), 0);
        assert_eq!(counters.cleanup.get(), 0);
    }

    #[test]
    fn deadline_crossing_after_start_intent_creates_no_resource_or_callback() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let commits = Rc::new(Cell::new(0));
        let counters = FakeOwnerCounters::new();
        let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
            FakeApplyStore {
                snapshot: started.snapshot().clone(),
                commits: Rc::clone(&commits),
            },
            ScriptedApplyClock::new(&[9_999, 10_000]),
            FakeMaterializationOwner::new(counters.clone()),
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("scripted apply core");
        let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"post-intent-timeout");

        let outcome = core
            .try_apply(&request, preflight(0x74, 0x75, 0x76, 1_000))
            .expect("post-intent timeout terminal");
        let RuntimeReferenceApplyOutcome::Terminal(stored) = outcome else {
            panic!("post-intent timeout must be terminal")
        };
        assert_eq!(
            stored.receipt().facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeHeadCommitExactZero
        );
        assert_eq!(commits.get(), 4, "tenure, admission, intent, terminal");
        assert_eq!(counters.materialize.get(), 0);
        assert_eq!(counters.start.get(), 0);
        assert!(core.snapshot().state().owned_resources.is_empty());
        assert!(core.snapshot().state().active_desired.is_none());
        assert!(core.snapshot().state().prepared.is_none());
    }

    #[test]
    fn deadline_crossing_after_empty_head_still_stops_and_cleans_exact_zero() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let commits = Rc::new(Cell::new(0));
        let counters = FakeOwnerCounters::new();
        let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
            FakeApplyStore {
                snapshot: started.snapshot().clone(),
                commits: Rc::clone(&commits),
            },
            ScriptedApplyClock::new(&[2_000, 2_000, 2_000, 9_999, 10_000, 10_000]),
            FakeMaterializationOwner::new(counters.clone()),
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("scripted apply core");
        let loop_request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"pre-empty-active");
        core.try_apply(&loop_request, preflight(0x74, 0x75, 0x76, 1_000))
            .expect("active predecessor");
        let empty_request = empty_apply_request_with_expected(
            &ingress,
            8,
            2,
            1,
            0x55,
            0x64,
            b"post-head-timeout",
            ExpectedActive::Exact(loop_request.target_slice_digest()),
        );

        let outcome = core
            .try_apply(&empty_request, preflight(0x84, 0x85, 0x86, 1_000))
            .expect("post-head timeout exact zero");
        let RuntimeReferenceApplyOutcome::Terminal(stored) = outcome else {
            panic!("post-head timeout must be terminal")
        };
        assert_eq!(
            stored.receipt().facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::TimedOutButExactZero
        );
        assert_eq!(counters.stop.get(), 1);
        assert_eq!(counters.cleanup.get(), 1);
        assert_eq!(commits.get(), 11);
        assert!(matches!(
            core.snapshot().state().live_materialization,
            LiveMaterialization::ExactZero { .. }
        ));
    }

    #[test]
    fn start_failpoints_resume_without_duplicate_materialize_or_callback() {
        for fail_on_attempt in [4, 5, 6] {
            let (installation, compiled) = installation();
            let ingress = installation
                .immutable_manifest_ingress()
                .expect("manifest ingress");
            let started = RuntimeControlState::try_start(&installed_sequence_one(
                &installation,
                compiled,
                installation.manifest_canonical_wire(),
                installation.manifest_digest(),
            ))
            .expect("startup");
            let store = FailpointApplyStore::new(started.snapshot().clone(), fail_on_attempt);
            let published = Rc::clone(&store.published);
            let counters = FakeOwnerCounters::new();
            let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
                store,
                FakeApplyClock {
                    observed_at_nanos: 2_000,
                },
                FakeMaterializationOwner::new(counters.clone()),
                reference_apply_signer(),
                reference_apply_channel(),
            )
            .expect("failpoint core");
            let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"start-failpoint");
            let evidence = preflight(0x74, 0x75, 0x76, 1_000);

            assert!(matches!(
                core.try_apply(&request, evidence),
                Err(RuntimeReferenceApplyError::Store(
                    RuntimeReferenceApplyStoreError::Unavailable
                ))
            ));
            let retry = core.try_apply(&request, evidence).unwrap_or_else(|error| {
                panic!("failpoint {fail_on_attempt} did not resume: {error:?}")
            });
            let RuntimeReferenceApplyOutcome::Terminal(retry) = retry else {
                panic!("resumed start must terminate")
            };
            assert_eq!(
                retry.receipt().facts().outcome(),
                ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
            );
            assert_eq!(published.get(), 6);
            assert_eq!(counters.materialize.get(), 1);
            assert_eq!(counters.start.get(), 1);
        }
    }

    #[test]
    fn empty_failpoints_resume_head_first_without_duplicate_stop_or_cleanup() {
        for fail_on_attempt in [10, 11] {
            let (installation, compiled) = installation();
            let ingress = installation
                .immutable_manifest_ingress()
                .expect("manifest ingress");
            let started = RuntimeControlState::try_start(&installed_sequence_one(
                &installation,
                compiled,
                installation.manifest_canonical_wire(),
                installation.manifest_digest(),
            ))
            .expect("startup");
            let store = FailpointApplyStore::new(started.snapshot().clone(), fail_on_attempt);
            let published = Rc::clone(&store.published);
            let counters = FakeOwnerCounters::new();
            let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
                store,
                FakeApplyClock {
                    observed_at_nanos: 2_000,
                },
                FakeMaterializationOwner::new(counters.clone()),
                reference_apply_signer(),
                reference_apply_channel(),
            )
            .expect("failpoint core");
            let loop_request =
                apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"empty-failpoint-active");
            core.try_apply(&loop_request, preflight(0x74, 0x75, 0x76, 1_000))
                .expect("active predecessor");
            let empty_request = empty_apply_request_with_expected(
                &ingress,
                8,
                2,
                1,
                0x55,
                0x64,
                b"empty-failpoint",
                ExpectedActive::Exact(loop_request.target_slice_digest()),
            );
            let evidence = preflight(0x84, 0x85, 0x86, 1_000);

            assert!(matches!(
                core.try_apply(&empty_request, evidence),
                Err(RuntimeReferenceApplyError::Store(
                    RuntimeReferenceApplyStoreError::Unavailable
                ))
            ));
            let retry = core
                .try_apply(&empty_request, evidence)
                .unwrap_or_else(|error| {
                    panic!("empty failpoint {fail_on_attempt} did not resume: {error:?}")
                });
            let RuntimeReferenceApplyOutcome::Terminal(retry) = retry else {
                panic!("resumed empty must terminate")
            };
            assert_eq!(
                retry.receipt().facts().outcome(),
                ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero
            );
            assert_eq!(published.get(), 11);
            assert_eq!(counters.stop.get(), 1);
            assert_eq!(counters.cleanup.get(), 1);
        }
    }

    #[test]
    fn crash_after_each_durable_start_boundary_recovers_with_same_owner_token() {
        // Successful start publishes: tenure, full admission, intent,
        // reservation, ownership, terminal.
        for fail_after_publish in [3, 4, 5, 6] {
            let (installation, compiled) = installation();
            let ingress = installation
                .immutable_manifest_ingress()
                .expect("manifest ingress");
            let started = RuntimeControlState::try_start(&installed_sequence_one(
                &installation,
                compiled,
                installation.manifest_canonical_wire(),
                installation.manifest_digest(),
            ))
            .expect("startup");
            let store = FailpointApplyStore::new_after_publish(
                started.snapshot().clone(),
                fail_after_publish,
            );
            let published = Rc::clone(&store.published);
            let counters = FakeOwnerCounters::new();
            let mut interrupted = RuntimeReferenceApplyCore::try_new_with_owner(
                store,
                FakeApplyClock {
                    observed_at_nanos: 2_000,
                },
                FakeMaterializationOwner::new(counters.clone()),
                reference_apply_signer(),
                reference_apply_channel(),
            )
            .expect("interrupted core");
            let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"durable-start-boundary");
            let evidence = preflight(0x74, 0x75, 0x76, 1_000);
            assert!(matches!(
                interrupted.try_apply(&request, evidence),
                Err(RuntimeReferenceApplyError::Store(_))
            ));
            let (store, clock, owner, signer, channel) = interrupted.into_test_recovery_parts();
            let mut recovered =
                RuntimeReferenceApplyCore::try_new_with_owner(store, clock, owner, signer, channel)
                    .unwrap_or_else(|error| {
                        panic!("boundary {fail_after_publish} reopen failed: {error:?}")
                    });
            let outcome = recovered
                .try_apply(&request, evidence)
                .unwrap_or_else(|error| {
                    panic!("boundary {fail_after_publish} recovery failed: {error:?}")
                });
            let RuntimeReferenceApplyOutcome::Terminal(stored) = outcome else {
                panic!("recovered start must terminate")
            };
            assert_eq!(
                stored.receipt().facts().outcome(),
                ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
            );
            assert_eq!(published.get(), 6);
            assert_eq!(counters.materialize.get(), 1);
            assert_eq!(counters.start.get(), 1);
        }
    }

    #[test]
    fn crash_after_head_latch_or_terminal_recovers_head_first_exact_zero() {
        // The active predecessor consumes six publications. Empty then
        // publishes tenure, admission, head, stop-success latch, terminal.
        for fail_after_publish in [9, 10, 11] {
            let (installation, compiled) = installation();
            let ingress = installation
                .immutable_manifest_ingress()
                .expect("manifest ingress");
            let started = RuntimeControlState::try_start(&installed_sequence_one(
                &installation,
                compiled,
                installation.manifest_canonical_wire(),
                installation.manifest_digest(),
            ))
            .expect("startup");
            let store = FailpointApplyStore::new_after_publish(
                started.snapshot().clone(),
                fail_after_publish,
            );
            let published = Rc::clone(&store.published);
            let counters = FakeOwnerCounters::new();
            let mut interrupted = RuntimeReferenceApplyCore::try_new_with_owner(
                store,
                FakeApplyClock {
                    observed_at_nanos: 2_000,
                },
                FakeMaterializationOwner::new(counters.clone()),
                reference_apply_signer(),
                reference_apply_channel(),
            )
            .expect("interrupted core");
            let loop_request =
                apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"durable-empty-active");
            interrupted
                .try_apply(&loop_request, preflight(0x74, 0x75, 0x76, 1_000))
                .expect("active predecessor");
            let empty_request = empty_apply_request_with_expected(
                &ingress,
                8,
                2,
                1,
                0x55,
                0x64,
                b"durable-empty-boundary",
                ExpectedActive::Exact(loop_request.target_slice_digest()),
            );
            let evidence = preflight(0x84, 0x85, 0x86, 1_000);
            assert!(matches!(
                interrupted.try_apply(&empty_request, evidence),
                Err(RuntimeReferenceApplyError::Store(_))
            ));
            let (store, clock, owner, signer, channel) = interrupted.into_test_recovery_parts();
            let mut recovered =
                RuntimeReferenceApplyCore::try_new_with_owner(store, clock, owner, signer, channel)
                    .unwrap_or_else(|error| {
                        panic!("empty boundary {fail_after_publish} reopen failed: {error:?}")
                    });
            let outcome = recovered
                .try_apply(&empty_request, evidence)
                .unwrap_or_else(|error| {
                    panic!("empty boundary {fail_after_publish} recovery failed: {error:?}")
                });
            let RuntimeReferenceApplyOutcome::Terminal(stored) = outcome else {
                panic!("recovered empty must terminate")
            };
            assert_eq!(
                stored.receipt().facts().outcome(),
                ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero
            );
            assert_eq!(published.get(), 11);
            assert_eq!(counters.stop.get(), 1);
            assert_eq!(counters.cleanup.get(), 1);
        }
    }

    #[test]
    fn fresh_owner_without_post_intent_token_fails_closed_without_mutation() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        // Attempt four is the reservation publication, leaving tenure, full
        // admission, and the start intent durable.
        let store = FailpointApplyStore::new(started.snapshot().clone(), 4);
        let request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"missing-owner-token");
        let evidence = preflight(0x74, 0x75, 0x76, 1_000);
        let mut first = RuntimeReferenceApplyCore::try_new_with_owner(
            store.clone(),
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            FakeMaterializationOwner::new(FakeOwnerCounters::new()),
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("first owner");
        assert!(matches!(
            first.try_apply(&request, evidence),
            Err(RuntimeReferenceApplyError::Store(_))
        ));
        let durable_before = store.snapshot.borrow().clone();
        let mut restarted = RuntimeReferenceApplyCore::try_new_with_owner(
            store.clone(),
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            FakeMaterializationOwner::new(FakeOwnerCounters::new()),
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("fresh owner core");

        assert_eq!(
            restarted.try_apply(&request, evidence),
            Err(RuntimeReferenceApplyError::Owner(
                RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken
            ))
        );
        assert_eq!(*store.snapshot.borrow(), durable_before);
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn production_fixed_owner_runs_compiled_loop_then_exact_zero_cleanup() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let owner_clock = RuntimeClock::new(
            ClockDomainRef::from_bytes(CLOCK_DOMAIN),
            ClockGeneration::try_new(1).expect("clock generation"),
            1,
        );
        let owner = RuntimeFixedReferenceMaterializationOwner::try_new(
            compiled,
            owner_clock,
            started.snapshot(),
        )
        .expect("compiled fixed owner");
        let commits = Rc::new(Cell::new(0));
        let mut core = RuntimeReferenceApplyCore::try_new_with_owner(
            FakeApplyStore {
                snapshot: started.snapshot().clone(),
                commits: Rc::clone(&commits),
            },
            FakeApplyClock {
                observed_at_nanos: 2_000,
            },
            owner,
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("production-owner core");
        let loop_request = apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"production-owner-loop");

        let active = core
            .try_apply(&loop_request, preflight(0x74, 0x75, 0x76, 1_000))
            .expect("compiled loop active");
        let RuntimeReferenceApplyOutcome::Terminal(active) = active else {
            panic!("compiled loop must return terminal receipt")
        };
        assert_eq!(
            active.receipt().facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive
        );

        let empty_request = empty_apply_request_with_expected(
            &ingress,
            8,
            1,
            0,
            0x55,
            0x64,
            b"production-owner-empty",
            ExpectedActive::Exact(loop_request.target_slice_digest()),
        );
        let empty = core
            .try_apply(&empty_request, preflight(0x74, 0x85, 0x86, 1_000))
            .expect("compiled loop cleanup");
        let RuntimeReferenceApplyOutcome::Terminal(empty) = empty else {
            panic!("compiled cleanup must return terminal receipt")
        };
        assert_eq!(
            empty.receipt().facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero
        );
        assert_eq!(commits.get(), 10);
        assert!(matches!(
            core.snapshot().state().live_materialization,
            LiveMaterialization::ExactZero { .. }
        ));
    }

    #[test]
    fn empty_apply_at_deadline_commits_no_effect_terminal_instead_of_stranding_prepared() {
        let (installation, compiled) = installation();
        let ingress = installation
            .immutable_manifest_ingress()
            .expect("manifest ingress");
        let started = RuntimeControlState::try_start(&installed_sequence_one(
            &installation,
            compiled,
            installation.manifest_canonical_wire(),
            installation.manifest_digest(),
        ))
        .expect("startup");
        let commits = Rc::new(Cell::new(0));
        let mut core = RuntimeReferenceApplyCore::try_new(
            FakeApplyStore {
                snapshot: started.snapshot().clone(),
                commits: Rc::clone(&commits),
            },
            FakeApplyClock {
                // admitted_at 1_000 + remaining 9_000; equality is timed out.
                observed_at_nanos: 10_000,
            },
            reference_apply_signer(),
            reference_apply_channel(),
        )
        .expect("apply core");
        let request = empty_apply_request(&ingress, 7, 1, 0, 0x54, 0x63, b"deadline-empty-nonce");

        let outcome = core
            .try_apply(&request, preflight(0x74, 0x75, 0x76, 1_000))
            .expect("deadline terminal");
        let RuntimeReferenceApplyOutcome::Terminal(stored) = outcome else {
            panic!("deadline must be terminal")
        };
        assert_eq!(
            stored.receipt().facts().outcome(),
            ReferenceApplyTerminalOutcomeV1::StopTimedOutBeforeHeadCommitNoEffects
        );
        assert!(core.snapshot().state().prepared.is_none());
        assert!(core.snapshot().state().active_desired.is_none());
        assert_eq!(commits.get(), 3);
    }

    #[test]
    fn response_signer_rejects_zero_key_reference() {
        assert!(matches!(
            RuntimeReferenceApplySigner::try_new(
                SigningKey::from_bytes(&[0x94; 32]),
                ApplyAuthKeyRef::from_bytes([0; 16]),
                ApplyAuthAlgorithm::try_new(1).expect("response algorithm"),
                1,
            ),
            Err(RuntimeReferenceApplyError::ResponseSignerRejected)
        ));
    }
}
