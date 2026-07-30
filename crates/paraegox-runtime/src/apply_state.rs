//! Pure writer-fence and apply-control state transitions.

use core::fmt;
use paraegox_kernel::digest::{Digest32, DigestBuildError};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_runtime_contracts::apply::{
    ApplyContractError, ApplyOperationId, ExpectedActive, PlanWriterEpoch, PlanWriterRef,
    RuntimeApplyControlCommitment,
};
use paraegox_runtime_contracts::provenance::{RuntimeSliceCommitment, SourceScopeRef};

/// Durable highest accepted writer tenure for one source scope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WriterFence {
    writer: PlanWriterRef,
    epoch: PlanWriterEpoch,
    proof_envelope_digest: Digest32,
    principal: PrincipalRef,
}

impl WriterFence {
    /// Returns the accepted writer identity.
    #[must_use]
    pub const fn writer(&self) -> PlanWriterRef {
        self.writer
    }

    /// Returns the highest accepted writer epoch.
    #[must_use]
    pub const fn epoch(&self) -> PlanWriterEpoch {
        self.epoch
    }

    /// Returns the exact authority-proof envelope fingerprint admitted for this epoch.
    #[must_use]
    pub const fn proof_envelope_digest(&self) -> &Digest32 {
        &self.proof_envelope_digest
    }

    /// Returns the principal authenticated with this writer tenure.
    #[must_use]
    pub const fn principal(&self) -> PrincipalRef {
        self.principal
    }
}

/// B1 control state recorded before RuntimeAssemblyEngine exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyControlState {
    source_scope: SourceScopeRef,
    target: RuntimeHostId,
    writer_fence: Option<WriterFence>,
    prepared: Option<PreparedControl>,
    active: Option<ActiveControl>,
}

impl ApplyControlState {
    /// Creates empty control state for one source scope and RuntimeHost target.
    #[must_use]
    pub const fn new(source_scope: SourceScopeRef, target: RuntimeHostId) -> Self {
        Self {
            source_scope,
            target,
            writer_fence: None,
            prepared: None,
            active: None,
        }
    }

    /// Returns the only source scope admitted by this B1 reference profile.
    #[must_use]
    pub const fn source_scope(&self) -> SourceScopeRef {
        self.source_scope
    }

    /// Returns the local RuntimeHost target.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    /// Returns the highest durably accepted writer tenure.
    #[must_use]
    pub const fn writer_fence(&self) -> Option<&WriterFence> {
        self.writer_fence.as_ref()
    }

    /// Returns the control operation currently prepared but not active.
    #[must_use]
    pub const fn prepared(&self) -> Option<&PreparedControl> {
        self.prepared.as_ref()
    }

    /// Returns the currently active slice commitment.
    #[must_use]
    pub const fn active(&self) -> Option<&ActiveControl> {
        self.active.as_ref()
    }
}

/// Verified tenure facts produced by a future owning admission implementation.
///
/// The owning verifier must establish proof validity and authentication. When no
/// durable fence exists, it must additionally establish authoritative freshness;
/// recovery must not turn lost fence state into a fresh bootstrap. For an existing
/// fence, this reducer owns stale/newer ordering so exact historical replays remain
/// queryable after writer turnover.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VerifiedWriterTenure {
    source_scope: SourceScopeRef,
    writer: PlanWriterRef,
    epoch: PlanWriterEpoch,
    supersedes_through_epoch: PlanWriterEpoch,
    proof_envelope_digest: Digest32,
    principal: PrincipalRef,
}

impl VerifiedWriterTenure {
    #[cfg(test)]
    fn from_payload_for_test(
        payload: &RuntimeApplyControlCommitment,
        principal: PrincipalRef,
    ) -> Result<Self, ApplyRejection> {
        payload.validate().map_err(ApplyRejection::Contract)?;
        let context = payload.control().writer_context();
        let claim = context.proof().claim();
        let proof_envelope_digest = context.proof().envelope_digest()?;
        Ok(Self {
            source_scope: claim.source_scope(),
            writer: context.writer(),
            epoch: context.epoch(),
            supersedes_through_epoch: claim.supersedes_through_epoch(),
            proof_envelope_digest,
            principal,
        })
    }
}

/// Apply payload after authentication and tenure-proof admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedApply {
    payload: RuntimeApplyControlCommitment,
    tenure: VerifiedWriterTenure,
}

impl AdmittedApply {
    #[cfg(test)]
    fn from_payload_for_test(
        payload: RuntimeApplyControlCommitment,
        principal: PrincipalRef,
    ) -> Result<Self, ApplyRejection> {
        let tenure = VerifiedWriterTenure::from_payload_for_test(&payload, principal)?;
        Ok(Self { payload, tenure })
    }

    /// Returns canonical slice and controls admitted by the owning verifier.
    #[must_use]
    pub const fn payload(&self) -> &RuntimeApplyControlCommitment {
        &self.payload
    }

    /// Returns verified writer-tenure facts.
    #[must_use]
    pub const fn tenure(&self) -> &VerifiedWriterTenure {
        &self.tenure
    }
}

/// Whether writer admission changed durable fence state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceDisposition {
    /// The exact writer, proof, and principal were already fenced at this epoch.
    Kept,
    /// A first or strictly newer writer tenure must be persisted.
    Advanced,
}

/// Pure result of writer-fence evaluation; persist it before prepare evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FenceTransition {
    next_state: ApplyControlState,
    disposition: FenceDisposition,
    superseded_operation: Option<OperationRecord>,
}

impl FenceTransition {
    /// Returns state that must be durable before any prepare side effect.
    #[must_use]
    pub const fn next_state(&self) -> &ApplyControlState {
        &self.next_state
    }

    /// Returns whether the fence advanced.
    #[must_use]
    pub const fn disposition(&self) -> FenceDisposition {
        self.disposition
    }

    /// Returns the prepared operation that must be marked superseded atomically.
    ///
    /// A future journal must conditionally update the matching scope, target,
    /// operation id, and request digest from `Prepared` to `Superseded`. If that
    /// exact prior row is absent, the transaction must not persist `next_state`.
    #[must_use]
    pub const fn superseded_operation(&self) -> Option<OperationRecord> {
        self.superseded_operation
    }

    /// Consumes every value that a future journal must persist atomically.
    #[must_use]
    pub fn into_parts(self) -> (ApplyControlState, Option<OperationRecord>) {
        (self.next_state, self.superseded_operation)
    }
}

/// Evaluates a verified writer tenure independently of plan CAS.
pub fn evaluate_writer_fence(
    state: &ApplyControlState,
    verified: &VerifiedWriterTenure,
) -> Result<FenceTransition, ApplyRejection> {
    if verified.source_scope != state.source_scope {
        return Err(ApplyRejection::SourceScopeMismatch);
    }
    ensure_control_state_consistent(state)?;

    let next_fence = WriterFence {
        writer: verified.writer,
        epoch: verified.epoch,
        proof_envelope_digest: verified.proof_envelope_digest,
        principal: verified.principal,
    };

    match state.writer_fence {
        None => {
            let mut next_state = state.clone();
            next_state.writer_fence = Some(next_fence);
            Ok(FenceTransition {
                next_state,
                disposition: FenceDisposition::Advanced,
                superseded_operation: None,
            })
        }
        Some(current) if verified.epoch < current.epoch => Err(ApplyRejection::StaleWriterEpoch),
        Some(current) if verified.epoch == current.epoch => {
            if current != next_fence {
                return Err(ApplyRejection::WriterFenceConflict);
            }
            Ok(FenceTransition {
                next_state: state.clone(),
                disposition: FenceDisposition::Kept,
                superseded_operation: None,
            })
        }
        Some(current) => {
            if verified.supersedes_through_epoch < current.epoch {
                return Err(ApplyRejection::TenureDoesNotSupersedeFence);
            }
            let mut next_state = state.clone();
            next_state.writer_fence = Some(next_fence);
            let superseded_operation = next_state.prepared.take().map(|prepared| OperationRecord {
                source_scope: state.source_scope,
                target: state.target,
                operation_id: prepared.operation_id,
                request_digest: prepared.request_digest,
                phase: OperationPhase::Superseded,
            });
            Ok(FenceTransition {
                next_state,
                disposition: FenceDisposition::Advanced,
                superseded_operation,
            })
        }
    }
}

/// Stage durably associated with a prepared control operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrepareStage {
    /// Control admission is durable; Runtime resources are not claimed ready.
    ControlAccepted,
}

/// Control metadata that is prepared but cannot become active without readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedControl {
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    incoming: RuntimeSliceCommitment,
    expected_active: ExpectedActive,
    writer_fence: WriterFence,
    stage: PrepareStage,
}

impl PreparedControl {
    /// Returns the apply operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> ApplyOperationId {
        self.operation_id
    }

    /// Returns the exact canonical request commitment.
    #[must_use]
    pub const fn request_digest(&self) -> &Digest32 {
        &self.request_digest
    }

    /// Returns the incoming target-slice commitment.
    #[must_use]
    pub const fn incoming(&self) -> RuntimeSliceCommitment {
        self.incoming
    }

    /// Returns the exact active-slice compare-and-swap input.
    #[must_use]
    pub const fn expected_active(&self) -> ExpectedActive {
        self.expected_active
    }

    /// Returns the durable writer fence that authorized this preparation.
    #[must_use]
    pub const fn writer_fence(&self) -> WriterFence {
        self.writer_fence
    }

    /// Returns the durable prepare stage.
    #[must_use]
    pub const fn stage(&self) -> PrepareStage {
        self.stage
    }
}

/// Control identity for the successfully activated target slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveControl {
    slice: RuntimeSliceCommitment,
}

impl ActiveControl {
    /// Returns the active target-slice commitment.
    #[must_use]
    pub const fn slice(&self) -> RuntimeSliceCommitment {
        self.slice
    }
}

/// Durable phase of one operation record owned by the eventual Runtime journal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationPhase {
    /// Control metadata was accepted and prepared.
    Prepared,
    /// The incoming slice commitment became active.
    Active,
    /// A newer writer tenure invalidated the prepared operation.
    Superseded,
}

/// Lookup/mutation value supplied separately from bounded apply control state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperationRecord {
    source_scope: SourceScopeRef,
    target: RuntimeHostId,
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    phase: OperationPhase,
}

impl OperationRecord {
    /// Returns the desired-state scope that owns this operation identity.
    #[must_use]
    pub const fn source_scope(&self) -> SourceScopeRef {
        self.source_scope
    }

    /// Returns the RuntimeHost target that owns this operation identity.
    #[must_use]
    pub const fn target(&self) -> RuntimeHostId {
        self.target
    }

    /// Returns the operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> ApplyOperationId {
        self.operation_id
    }

    /// Returns the canonical request commitment.
    #[must_use]
    pub const fn request_digest(&self) -> &Digest32 {
        &self.request_digest
    }

    /// Returns the last durable operation phase.
    #[must_use]
    pub const fn phase(&self) -> OperationPhase {
        self.phase
    }
}

/// Whether prepare created state or replayed the same operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrepareDisposition {
    /// A new prepared record must be persisted atomically with its operation row.
    Prepared,
    /// The exact operation already exists with the returned durable phase.
    Replayed(OperationPhase),
}

/// Pure prepare result; active state is always preserved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareTransition {
    next_state: ApplyControlState,
    operation: OperationRecord,
    disposition: PrepareDisposition,
}

impl PrepareTransition {
    /// Returns state to persist after successful prepare evaluation.
    #[must_use]
    pub const fn next_state(&self) -> &ApplyControlState {
        &self.next_state
    }

    /// Returns the operation journal mutation or existing record.
    #[must_use]
    pub const fn operation(&self) -> OperationRecord {
        self.operation
    }

    /// Returns whether this evaluation prepared or replayed.
    #[must_use]
    pub const fn disposition(&self) -> PrepareDisposition {
        self.disposition
    }

    /// Consumes every value that a future journal must persist atomically.
    #[must_use]
    pub fn into_parts(self) -> (ApplyControlState, OperationRecord) {
        (self.next_state, self.operation)
    }
}

/// Evaluates operation idempotency, CAS, and revision ordering.
pub fn evaluate_prepare(
    state: &ApplyControlState,
    admitted: &AdmittedApply,
    prior_operation: Option<&OperationRecord>,
) -> Result<PrepareTransition, ApplyRejection> {
    admitted.payload.validate()?;
    let payload = admitted.payload();
    let slice = payload.slice();
    let control = payload.control();

    if slice.header().target() != state.target {
        return Err(ApplyRejection::TargetMismatch);
    }
    if slice.header().provenance().source_scope() != state.source_scope {
        return Err(ApplyRejection::SourceScopeMismatch);
    }
    ensure_control_state_consistent(state)?;

    if let Some(existing) = prior_operation {
        ensure_operation_belongs_to_state(state, existing)?;
        if existing.operation_id != control.operation_id() {
            return Err(ApplyRejection::OperationLookupMismatch);
        }
        if existing.request_digest != *payload.commitment_digest() {
            return Err(ApplyRejection::OperationConflict);
        }
        ensure_replayed_operation_consistent(state, existing)?;
        return Ok(PrepareTransition {
            next_state: state.clone(),
            operation: *existing,
            disposition: PrepareDisposition::Replayed(existing.phase),
        });
    }

    let writer_fence = matching_writer_fence(state, admitted.tenure())?;
    ensure_expected_active(state, control.expected_active())?;
    ensure_revision_advances(state, slice)?;
    if state.prepared.is_some() {
        return Err(ApplyRejection::PrepareInProgress);
    }

    let prepared = PreparedControl {
        operation_id: control.operation_id(),
        request_digest: *payload.commitment_digest(),
        incoming: slice,
        expected_active: control.expected_active(),
        writer_fence,
        stage: PrepareStage::ControlAccepted,
    };
    let operation = OperationRecord {
        source_scope: state.source_scope,
        target: state.target,
        operation_id: prepared.operation_id,
        request_digest: prepared.request_digest,
        phase: OperationPhase::Prepared,
    };
    let mut next_state = state.clone();
    next_state.prepared = Some(prepared);

    Ok(PrepareTransition {
        next_state,
        operation,
        disposition: PrepareDisposition::Prepared,
    })
}

fn matching_writer_fence(
    state: &ApplyControlState,
    verified: &VerifiedWriterTenure,
) -> Result<WriterFence, ApplyRejection> {
    let expected = WriterFence {
        writer: verified.writer,
        epoch: verified.epoch,
        proof_envelope_digest: verified.proof_envelope_digest,
        principal: verified.principal,
    };
    if state.writer_fence != Some(expected) {
        return Err(ApplyRejection::WriterFenceNotDurable);
    }
    Ok(expected)
}

fn ensure_control_state_consistent(state: &ApplyControlState) -> Result<(), ApplyRejection> {
    if state.active.is_some() && state.writer_fence.is_none() {
        return Err(ApplyRejection::OperationStateMismatch);
    }

    if let Some(active) = state.active.as_ref() {
        validate_stored_slice(active.slice)?;
        if active.slice.header().target() != state.target
            || active.slice.header().provenance().source_scope() != state.source_scope
        {
            return Err(ApplyRejection::OperationStateMismatch);
        }
    }

    if let Some(prepared) = state.prepared.as_ref() {
        validate_stored_slice(prepared.incoming)?;
        if prepared.incoming.header().target() != state.target
            || prepared.incoming.header().provenance().source_scope() != state.source_scope
            || state.writer_fence != Some(prepared.writer_fence)
            || !expected_active_matches(state, prepared.expected_active)
        {
            return Err(ApplyRejection::OperationStateMismatch);
        }
        if let Some(active) = state.active.as_ref()
            && prepared.incoming.header().provenance().source_revision()
                <= active.slice.header().provenance().source_revision()
        {
            return Err(ApplyRejection::OperationStateMismatch);
        }
    }
    Ok(())
}

fn validate_stored_slice(slice: RuntimeSliceCommitment) -> Result<(), ApplyRejection> {
    slice
        .validate()
        .map_err(|error| ApplyRejection::Contract(ApplyContractError::Provenance(error)))
}

fn ensure_operation_belongs_to_state(
    state: &ApplyControlState,
    operation: &OperationRecord,
) -> Result<(), ApplyRejection> {
    if operation.source_scope != state.source_scope {
        return Err(ApplyRejection::SourceScopeMismatch);
    }
    if operation.target != state.target {
        return Err(ApplyRejection::TargetMismatch);
    }
    Ok(())
}

fn ensure_replayed_operation_consistent(
    state: &ApplyControlState,
    operation: &OperationRecord,
) -> Result<(), ApplyRejection> {
    match operation.phase {
        OperationPhase::Prepared => {
            let Some(prepared) = state.prepared.as_ref() else {
                return Err(ApplyRejection::OperationStateMismatch);
            };
            if prepared.operation_id != operation.operation_id
                || prepared.request_digest != operation.request_digest
                || state.writer_fence != Some(prepared.writer_fence)
            {
                return Err(ApplyRejection::OperationStateMismatch);
            }
        }
        OperationPhase::Active | OperationPhase::Superseded => {
            if state.prepared.as_ref().is_some_and(|prepared| {
                prepared.operation_id == operation.operation_id
                    || prepared.request_digest == operation.request_digest
            }) {
                return Err(ApplyRejection::OperationStateMismatch);
            }
        }
    }
    Ok(())
}

fn ensure_expected_active(
    state: &ApplyControlState,
    expected: ExpectedActive,
) -> Result<(), ApplyRejection> {
    if !expected_active_matches(state, expected) {
        return Err(ApplyRejection::ExpectedActiveMismatch);
    }
    Ok(())
}

fn expected_active_matches(state: &ApplyControlState, expected: ExpectedActive) -> bool {
    match (expected, state.active.as_ref()) {
        (ExpectedActive::None, None) => true,
        (ExpectedActive::Exact(expected_digest), Some(active)) => {
            active.slice.target_slice_digest() == expected_digest
        }
        _ => false,
    }
}

fn ensure_revision_advances(
    state: &ApplyControlState,
    incoming: RuntimeSliceCommitment,
) -> Result<(), ApplyRejection> {
    if let Some(active) = state.active.as_ref()
        && incoming.header().provenance().source_revision()
            <= active.slice.header().provenance().source_revision()
    {
        return Err(ApplyRejection::NonMonotonicRevision);
    }
    Ok(())
}

/// Readiness evidence later produced only by RuntimeAssemblyEngine.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PreparationReadyFact {
    operation_id: ApplyOperationId,
    request_digest: Digest32,
}

impl PreparationReadyFact {
    #[cfg(test)]
    fn for_test(operation_id: ApplyOperationId, request_digest: Digest32) -> Self {
        Self {
            operation_id,
            request_digest,
        }
    }
}

/// Pure activation result; journal persistence must atomically apply every field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivateTransition {
    next_state: ApplyControlState,
    operation: OperationRecord,
    disposition: ActivateDisposition,
}

/// Whether activation changed state or replayed an already active operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivateDisposition {
    /// The prepared operation became active.
    Activated,
    /// The operation was already active and no state changed.
    Replayed,
}

impl ActivateTransition {
    /// Returns state with incoming active and prepared cleared.
    #[must_use]
    pub const fn next_state(&self) -> &ApplyControlState {
        &self.next_state
    }

    /// Returns the terminal operation mutation committed with activation.
    #[must_use]
    pub const fn operation(&self) -> OperationRecord {
        self.operation
    }

    /// Returns whether activation happened or was an idempotent replay.
    #[must_use]
    pub const fn disposition(&self) -> ActivateDisposition {
        self.disposition
    }

    /// Consumes every value that a future journal must persist atomically.
    #[must_use]
    pub fn into_parts(self) -> (ApplyControlState, OperationRecord) {
        (self.next_state, self.operation)
    }
}

/// Activates only the exact prepared operation with explicit readiness evidence.
///
/// Readiness is required only for the first `Prepared` to `Active` transition.
/// A durable `Active` operation record is the authority for side-effect-free replay.
pub fn evaluate_activate(
    state: &ApplyControlState,
    operation: &OperationRecord,
    ready: &PreparationReadyFact,
) -> Result<ActivateTransition, ApplyRejection> {
    ensure_operation_belongs_to_state(state, operation)?;
    ensure_control_state_consistent(state)?;
    ensure_replayed_operation_consistent(state, operation)?;
    match operation.phase {
        OperationPhase::Superseded => return Err(ApplyRejection::OperationSuperseded),
        OperationPhase::Active => {
            return Ok(ActivateTransition {
                next_state: state.clone(),
                operation: *operation,
                disposition: ActivateDisposition::Replayed,
            });
        }
        OperationPhase::Prepared => {}
    }

    let Some(prepared) = state.prepared.as_ref() else {
        return Err(ApplyRejection::OperationStateMismatch);
    };
    if prepared.operation_id != operation.operation_id
        || prepared.request_digest != operation.request_digest
    {
        return Err(ApplyRejection::OperationStateMismatch);
    }
    if ready.operation_id != operation.operation_id
        || ready.request_digest != operation.request_digest
    {
        return Err(ApplyRejection::ReadinessMismatch);
    }
    let active_operation = OperationRecord {
        source_scope: state.source_scope,
        target: state.target,
        operation_id: operation.operation_id,
        request_digest: operation.request_digest,
        phase: OperationPhase::Active,
    };
    let mut next_state = state.clone();
    next_state.active = Some(ActiveControl {
        slice: prepared.incoming,
    });
    next_state.prepared = None;

    Ok(ActivateTransition {
        next_state,
        operation: active_operation,
        disposition: ActivateDisposition::Activated,
    })
}

/// Stable, fail-closed reasons returned before any Runtime execution side effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyRejection {
    /// Canonical slice or control validation failed.
    Contract(ApplyContractError),
    /// Canonical proof-envelope fingerprint construction failed.
    Digest(DigestBuildError),
    /// The request is for another RuntimeHost.
    TargetMismatch,
    /// The request is for another source desired-state scope.
    SourceScopeMismatch,
    /// A late writer epoch cannot pass the durable fence.
    StaleWriterEpoch,
    /// The same epoch carried a different writer, proof, or principal.
    WriterFenceConflict,
    /// A newer proof did not explicitly supersede the current fence.
    TenureDoesNotSupersedeFence,
    /// Prepare was attempted before its exact writer fence became durable.
    WriterFenceNotDurable,
    /// Operation lookup returned a record for a different identity.
    OperationLookupMismatch,
    /// One operation identity was reused with different canonical controls.
    OperationConflict,
    /// Operation journal phase and apply-control state cannot describe one snapshot.
    OperationStateMismatch,
    /// A newer writer tenure superseded this prepared operation.
    OperationSuperseded,
    /// Expected-active compare-and-swap failed.
    ExpectedActiveMismatch,
    /// A new operation attempted source revision rollback or reuse.
    NonMonotonicRevision,
    /// Another operation is already prepared.
    PrepareInProgress,
    /// Readiness evidence did not identify the exact prepared operation.
    ReadinessMismatch,
}

impl From<ApplyContractError> for ApplyRejection {
    fn from(value: ApplyContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<DigestBuildError> for ApplyRejection {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ApplyRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "apply contract rejected: {error}"),
            Self::Digest(error) => write!(formatter, "proof envelope rejected: {error}"),
            Self::TargetMismatch => formatter.write_str("runtime target mismatch"),
            Self::SourceScopeMismatch => formatter.write_str("source scope mismatch"),
            Self::StaleWriterEpoch => formatter.write_str("stale writer epoch"),
            Self::WriterFenceConflict => formatter.write_str("writer fence conflict"),
            Self::TenureDoesNotSupersedeFence => {
                formatter.write_str("writer proof does not supersede current fence")
            }
            Self::WriterFenceNotDurable => {
                formatter.write_str("writer fence is not durably admitted")
            }
            Self::OperationLookupMismatch => formatter.write_str("operation lookup mismatch"),
            Self::OperationConflict => formatter.write_str("operation identity conflict"),
            Self::OperationStateMismatch => {
                formatter.write_str("operation journal and control state do not match")
            }
            Self::OperationSuperseded => {
                formatter.write_str("operation was superseded by a newer writer tenure")
            }
            Self::ExpectedActiveMismatch => {
                formatter.write_str("expected active target slice mismatch")
            }
            Self::NonMonotonicRevision => formatter.write_str("source revision did not advance"),
            Self::PrepareInProgress => formatter.write_str("another apply operation is prepared"),
            Self::ReadinessMismatch => {
                formatter.write_str("readiness evidence does not match activation")
            }
        }
    }
}

impl std::error::Error for ApplyRejection {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_runtime_contracts::apply::{
        ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
        RuntimeApplyControl, RuntimeApplyControlCommitment, TenureAuthorityRef, TenureKeyRef,
        TenureProofAlgorithm, TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
    };
    use paraegox_runtime_contracts::provenance::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest,
    };

    use super::{
        ActivateDisposition, AdmittedApply, ApplyControlState, ApplyRejection, FenceDisposition,
        OperationPhase, OperationRecord, PreparationReadyFact, PrepareDisposition,
        evaluate_activate, evaluate_prepare, evaluate_writer_fence,
    };

    const SCOPE_BYTES: [u8; 16] = [1; 16];
    const TARGET_BYTES: [u8; 16] = [2; 16];
    const WRITER_BYTES: [u8; 16] = [4; 16];

    #[derive(Clone, Copy)]
    struct Fixture {
        scope_byte: u8,
        target_byte: u8,
        writer_byte: u8,
        principal_byte: u8,
        revision: u64,
        epoch: u64,
        supersedes: u64,
        expected_active: ExpectedActive,
        operation_byte: u8,
        plan_byte: u8,
        plan_digest_byte: u8,
        assignment_byte: u8,
    }

    fn fixture(
        revision: u64,
        epoch: u64,
        expected_active: ExpectedActive,
        operation_byte: u8,
    ) -> Fixture {
        Fixture {
            scope_byte: SCOPE_BYTES[0],
            target_byte: TARGET_BYTES[0],
            writer_byte: WRITER_BYTES[0],
            principal_byte: WRITER_BYTES[0],
            revision,
            epoch,
            supersedes: epoch - 1,
            expected_active,
            operation_byte,
            plan_byte: 7,
            plan_digest_byte: 8,
            assignment_byte: 9,
        }
    }

    impl Fixture {
        fn slice(self) -> RuntimeSliceCommitment {
            let provenance = PlanProvenance::new(
                SourceScopeRef::from_bytes([self.scope_byte; 16]),
                SourcePlanRef::from_bytes([self.plan_byte; 16]),
                SourcePlanRevision::new(self.revision),
                SourcePlanDigest::new(Digest32::from_bytes([self.plan_digest_byte; 32])),
            );
            let header = RuntimeSliceHeader::new(
                RuntimeHostId::from_bytes([self.target_byte; 16]),
                provenance,
                TargetAssignmentDigest::new(Digest32::from_bytes([self.assignment_byte; 32])),
            );
            let Ok(slice) = RuntimeSliceCommitment::try_new(header) else {
                panic!("test slice commitment must be valid");
            };
            slice
        }

        fn admitted(self) -> AdmittedApply {
            let scope = SourceScopeRef::from_bytes([self.scope_byte; 16]);
            let writer = PlanWriterRef::from_bytes([self.writer_byte; 16]);
            let Ok(algorithm) = TenureProofAlgorithm::try_new(1) else {
                panic!("test algorithm must be valid");
            };
            let Ok(authority) = TenureProofAuthority::try_new(
                TenureAuthorityRef::from_bytes([5; 16]),
                TenureKeyRef::from_bytes([6; 16]),
                algorithm,
                1,
            ) else {
                panic!("test authority must be valid");
            };
            let Ok(claim) = WriterTenureClaim::try_new(
                scope,
                writer,
                PlanWriterEpoch::new(self.epoch),
                PlanWriterEpoch::new(self.supersedes),
            ) else {
                panic!("test tenure claim must be valid");
            };
            let Ok(proof) = WriterTenureProof::try_new(authority, claim, b"nonce", b"signature")
            else {
                panic!("test tenure proof must be valid");
            };
            let Ok(writer_context) =
                PlanWriterContext::try_new(writer, PlanWriterEpoch::new(self.epoch), proof)
            else {
                panic!("test writer context must be valid");
            };
            let control = RuntimeApplyControl::new(
                writer_context,
                self.expected_active,
                ApplyOperationId::from_bytes([self.operation_byte; 16]),
            );
            let Ok(payload) = RuntimeApplyControlCommitment::try_new(self.slice(), control) else {
                panic!("test control commitment must be valid");
            };
            let Ok(admitted) = AdmittedApply::from_payload_for_test(
                payload,
                PrincipalRef::from_bytes([self.principal_byte; 16]),
            ) else {
                panic!("test admission facts must be valid");
            };
            admitted
        }
    }

    fn state() -> ApplyControlState {
        ApplyControlState::new(
            SourceScopeRef::from_bytes(SCOPE_BYTES),
            RuntimeHostId::from_bytes(TARGET_BYTES),
        )
    }

    fn fence(state: &ApplyControlState, apply: &AdmittedApply) -> ApplyControlState {
        let Ok(transition) = evaluate_writer_fence(state, apply.tenure()) else {
            panic!("test writer tenure must be admitted");
        };
        let (next_state, superseded) = transition.into_parts();
        assert!(superseded.is_none());
        next_state
    }

    fn prepare(
        state: &ApplyControlState,
        apply: &AdmittedApply,
    ) -> (ApplyControlState, super::OperationRecord) {
        let Ok(transition) = evaluate_prepare(state, apply, None) else {
            panic!("test apply must prepare");
        };
        transition.into_parts()
    }

    fn activate(state: &ApplyControlState, operation: super::OperationRecord) -> ApplyControlState {
        let ready =
            PreparationReadyFact::for_test(operation.operation_id(), *operation.request_digest());
        let Ok(transition) = evaluate_activate(state, &operation, &ready) else {
            panic!("test apply must activate");
        };
        transition.into_parts().0
    }

    #[test]
    fn higher_tenure_advances_fence_before_cas_rejection() {
        let first = fixture(1, 1, ExpectedActive::None, 10).admitted();
        let state = fence(&state(), &first);
        let (state, operation) = prepare(&state, &first);
        let state = activate(&state, operation);
        let old_active = state.active().copied();

        let second = fixture(2, 2, ExpectedActive::None, 11).admitted();
        let Ok(fence_transition) = evaluate_writer_fence(&state, second.tenure()) else {
            panic!("new tenure must advance the fence");
        };
        assert_eq!(fence_transition.disposition(), FenceDisposition::Advanced);
        let (fenced_state, superseded) = fence_transition.into_parts();
        assert!(superseded.is_none());
        assert_eq!(
            fenced_state
                .writer_fence()
                .map(|value| value.epoch().value()),
            Some(2)
        );

        assert_eq!(
            evaluate_prepare(&fenced_state, &second, None).err(),
            Some(ApplyRejection::ExpectedActiveMismatch)
        );
        assert_eq!(fenced_state.active().copied(), old_active);
        assert!(fenced_state.prepared().is_none());
    }

    #[test]
    fn prepare_never_changes_active_and_activate_requires_readiness() {
        let first = fixture(1, 1, ExpectedActive::None, 10).admitted();
        let state = fence(&state(), &first);
        let Ok(prepare_transition) = evaluate_prepare(&state, &first, None) else {
            panic!("valid apply must prepare");
        };
        assert_eq!(
            prepare_transition.disposition(),
            PrepareDisposition::Prepared
        );
        assert!(prepare_transition.next_state().active().is_none());

        let prepared_state = prepare_transition.next_state();
        let operation = prepare_transition.operation();
        let wrong_ready = PreparationReadyFact::for_test(
            ApplyOperationId::from_bytes([99; 16]),
            *operation.request_digest(),
        );
        assert_eq!(
            evaluate_activate(prepared_state, &operation, &wrong_ready).err(),
            Some(ApplyRejection::ReadinessMismatch)
        );

        let ready =
            PreparationReadyFact::for_test(operation.operation_id(), *operation.request_digest());
        let Ok(activated) = evaluate_activate(prepared_state, &operation, &ready) else {
            panic!("matching readiness must activate");
        };
        assert!(activated.next_state().prepared().is_none());
        assert!(activated.next_state().active().is_some());
        assert_eq!(activated.operation().phase(), OperationPhase::Active);
        assert_eq!(activated.disposition(), ActivateDisposition::Activated);
    }

    #[test]
    fn same_operation_replays_and_changed_digest_conflicts() {
        let apply = fixture(1, 1, ExpectedActive::None, 10).admitted();
        let state = fence(&state(), &apply);
        let Ok(first) = evaluate_prepare(&state, &apply, None) else {
            panic!("valid apply must prepare");
        };
        let record = first.operation();
        let Ok(replay) = evaluate_prepare(first.next_state(), &apply, Some(&record)) else {
            panic!("exact operation replay must be idempotent");
        };
        assert_eq!(
            replay.disposition(),
            PrepareDisposition::Replayed(OperationPhase::Prepared)
        );

        let changed_apply = fixture(1, 1, ExpectedActive::None, 11).admitted();
        assert_eq!(
            evaluate_prepare(first.next_state(), &changed_apply, Some(&record)).err(),
            Some(ApplyRejection::OperationLookupMismatch)
        );

        let conflicting_record = super::OperationRecord {
            source_scope: first.next_state().source_scope,
            target: first.next_state().target,
            operation_id: changed_apply.payload().control().operation_id(),
            request_digest: *record.request_digest(),
            phase: OperationPhase::Prepared,
        };
        assert_eq!(
            evaluate_prepare(
                first.next_state(),
                &changed_apply,
                Some(&conflicting_record)
            )
            .err(),
            Some(ApplyRejection::OperationConflict)
        );
    }

    #[test]
    fn dropped_prepare_or_activate_transition_preserves_old_state() {
        let apply = fixture(1, 1, ExpectedActive::None, 10).admitted();
        let fenced_state = fence(&state(), &apply);
        let baseline = fenced_state.clone();
        let Ok(prepare_transition) = evaluate_prepare(&fenced_state, &apply, None) else {
            panic!("valid apply must prepare");
        };
        assert_eq!(fenced_state, baseline);

        let prepared_state = prepare_transition.next_state().clone();
        let operation = prepare_transition.operation();
        let ready =
            PreparationReadyFact::for_test(operation.operation_id(), *operation.request_digest());
        let Ok(_activation) = evaluate_activate(&prepared_state, &operation, &ready) else {
            panic!("matching readiness must produce activation transition");
        };
        assert!(prepared_state.active().is_none());
        assert!(prepared_state.prepared().is_some());
    }

    #[test]
    fn exact_active_cas_distinguishes_same_revision_slices() {
        let mut active_fixture = fixture(1, 1, ExpectedActive::None, 10);
        active_fixture.plan_byte = 20;
        active_fixture.plan_digest_byte = 21;
        active_fixture.assignment_byte = 22;
        let active_apply = active_fixture.admitted();
        let state = fence(&state(), &active_apply);
        let (state, operation) = prepare(&state, &active_apply);
        let state = activate(&state, operation);
        let Some(active) = state.active() else {
            panic!("test active slice must exist");
        };
        let actual_digest = active.slice().target_slice_digest();

        let mut other_fixture = fixture(1, 1, ExpectedActive::None, 99);
        other_fixture.plan_byte = 30;
        other_fixture.plan_digest_byte = 31;
        other_fixture.assignment_byte = 32;
        let other_digest = other_fixture.slice().target_slice_digest();
        assert_ne!(actual_digest, other_digest);

        let mut next_fixture = fixture(2, 1, ExpectedActive::Exact(other_digest), 11);
        next_fixture.plan_byte = 40;
        let wrong_expectation = next_fixture.admitted();
        assert_eq!(
            evaluate_prepare(&state, &wrong_expectation, None).err(),
            Some(ApplyRejection::ExpectedActiveMismatch)
        );

        next_fixture.expected_active = ExpectedActive::Exact(actual_digest);
        let exact_expectation = next_fixture.admitted();
        assert!(evaluate_prepare(&state, &exact_expectation, None).is_ok());

        let same_revision = fixture(1, 1, ExpectedActive::Exact(actual_digest), 12).admitted();
        assert_eq!(
            evaluate_prepare(&state, &same_revision, None).err(),
            Some(ApplyRejection::NonMonotonicRevision)
        );
    }

    #[test]
    fn writer_fence_rejects_stale_conflicting_and_insufficient_tenures() {
        let current = fixture(1, 2, ExpectedActive::None, 10).admitted();
        let state = fence(&state(), &current);

        let stale = fixture(1, 1, ExpectedActive::None, 11).admitted();
        assert_eq!(
            evaluate_writer_fence(&state, stale.tenure()).err(),
            Some(ApplyRejection::StaleWriterEpoch)
        );

        let mut conflicting_fixture = fixture(1, 2, ExpectedActive::None, 12);
        conflicting_fixture.principal_byte = 44;
        let conflicting = conflicting_fixture.admitted();
        assert_eq!(
            evaluate_writer_fence(&state, conflicting.tenure()).err(),
            Some(ApplyRejection::WriterFenceConflict)
        );

        let mut insufficient_fixture = fixture(1, 3, ExpectedActive::None, 13);
        insufficient_fixture.supersedes = 1;
        let insufficient = insufficient_fixture.admitted();
        assert_eq!(
            evaluate_writer_fence(&state, insufficient.tenure()).err(),
            Some(ApplyRejection::TenureDoesNotSupersedeFence)
        );

        assert_eq!(
            evaluate_prepare(&state, &stale, None).err(),
            Some(ApplyRejection::WriterFenceNotDurable)
        );
    }

    #[test]
    fn routing_and_single_prepare_fail_closed() {
        let mut wrong_target_fixture = fixture(1, 1, ExpectedActive::None, 10);
        wrong_target_fixture.target_byte = 99;
        let wrong_target = wrong_target_fixture.admitted();
        assert_eq!(
            evaluate_prepare(&state(), &wrong_target, None).err(),
            Some(ApplyRejection::TargetMismatch)
        );

        let mut wrong_scope_fixture = fixture(1, 1, ExpectedActive::None, 11);
        wrong_scope_fixture.scope_byte = 99;
        let wrong_scope = wrong_scope_fixture.admitted();
        assert_eq!(
            evaluate_writer_fence(&state(), wrong_scope.tenure()).err(),
            Some(ApplyRejection::SourceScopeMismatch)
        );

        let first = fixture(1, 1, ExpectedActive::None, 12).admitted();
        let fenced = fence(&state(), &first);
        let (prepared_state, _) = prepare(&fenced, &first);
        let second = fixture(2, 1, ExpectedActive::None, 13).admitted();
        assert_eq!(
            evaluate_prepare(&prepared_state, &second, None).err(),
            Some(ApplyRejection::PrepareInProgress)
        );
    }

    #[test]
    fn newer_tenure_atomically_supersedes_prepared_operation() {
        let first = fixture(1, 1, ExpectedActive::None, 10).admitted();
        let fenced = fence(&state(), &first);
        let (prepared_state, prepared_operation) = prepare(&fenced, &first);
        let baseline = prepared_state.clone();

        let mut next_fixture = fixture(1, 2, ExpectedActive::None, 11);
        next_fixture.writer_byte = 44;
        next_fixture.principal_byte = 44;
        let next = next_fixture.admitted();
        let Ok(transition) = evaluate_writer_fence(&prepared_state, next.tenure()) else {
            panic!("new writer tenure must advance");
        };
        assert_eq!(transition.disposition(), FenceDisposition::Advanced);
        let Some(superseded) = transition.superseded_operation() else {
            panic!("prepared operation must be superseded");
        };
        assert_eq!(superseded.operation_id(), prepared_operation.operation_id());
        assert_eq!(superseded.phase(), OperationPhase::Superseded);
        assert!(transition.next_state().prepared().is_none());
        assert_eq!(
            transition
                .next_state()
                .writer_fence()
                .map(|fence| fence.epoch().value()),
            Some(2)
        );
        assert_eq!(prepared_state, baseline);

        let ready = PreparationReadyFact::for_test(
            prepared_operation.operation_id(),
            *prepared_operation.request_digest(),
        );
        assert_eq!(
            evaluate_activate(transition.next_state(), &superseded, &ready).err(),
            Some(ApplyRejection::OperationSuperseded)
        );

        let mut wrong_scope = superseded;
        wrong_scope.source_scope = SourceScopeRef::from_bytes([99; 16]);
        assert_eq!(
            evaluate_activate(transition.next_state(), &wrong_scope, &ready).err(),
            Some(ApplyRejection::SourceScopeMismatch)
        );
        assert_eq!(
            evaluate_prepare(transition.next_state(), &first, Some(&wrong_scope)).err(),
            Some(ApplyRejection::SourceScopeMismatch)
        );
        let mut wrong_target = superseded;
        wrong_target.target = RuntimeHostId::from_bytes([99; 16]);
        assert_eq!(
            evaluate_activate(transition.next_state(), &wrong_target, &ready).err(),
            Some(ApplyRejection::TargetMismatch)
        );
        assert_eq!(
            evaluate_prepare(transition.next_state(), &first, Some(&wrong_target)).err(),
            Some(ApplyRejection::TargetMismatch)
        );
        assert!(evaluate_prepare(transition.next_state(), &next, None).is_ok());
    }

    #[test]
    fn completed_replay_survives_writer_turnover() {
        let first_fixture = fixture(1, 1, ExpectedActive::None, 10);
        let first = first_fixture.admitted();
        let state = fence(&state(), &first);
        let (state, prepared_operation) = prepare(&state, &first);
        let ready = PreparationReadyFact::for_test(
            prepared_operation.operation_id(),
            *prepared_operation.request_digest(),
        );
        let Ok(activation) = evaluate_activate(&state, &prepared_operation, &ready) else {
            panic!("first operation must activate");
        };
        let (active_state, active_operation) = activation.into_parts();
        let active_digest = active_state
            .active()
            .map(|active| active.slice().target_slice_digest())
            .expect("test active slice must exist");

        let next = fixture(2, 2, ExpectedActive::Exact(active_digest), 11).admitted();
        let Ok(turnover) = evaluate_writer_fence(&active_state, next.tenure()) else {
            panic!("new writer tenure must advance");
        };
        let (state, superseded) = turnover.into_parts();
        assert!(superseded.is_none());
        let baseline = state.clone();

        let Ok(replay) = evaluate_prepare(&state, &first, Some(&active_operation)) else {
            panic!("completed operation must replay after writer turnover");
        };
        assert_eq!(
            replay.disposition(),
            PrepareDisposition::Replayed(OperationPhase::Active)
        );
        assert_eq!(replay.next_state(), &baseline);

        let mut wrong_scope_record = active_operation;
        wrong_scope_record.source_scope = SourceScopeRef::from_bytes([99; 16]);
        assert_eq!(
            evaluate_prepare(&state, &first, Some(&wrong_scope_record)).err(),
            Some(ApplyRejection::SourceScopeMismatch)
        );
        let mut wrong_target_record = active_operation;
        wrong_target_record.target = RuntimeHostId::from_bytes([99; 16]);
        assert_eq!(
            evaluate_prepare(&state, &first, Some(&wrong_target_record)).err(),
            Some(ApplyRejection::TargetMismatch)
        );

        let mut changed_fixture = first_fixture;
        changed_fixture.assignment_byte = 55;
        let changed = changed_fixture.admitted();
        assert_eq!(
            evaluate_prepare(&state, &changed, Some(&active_operation)).err(),
            Some(ApplyRejection::OperationConflict)
        );

        let unseen = fixture(1, 1, ExpectedActive::None, 99).admitted();
        assert_eq!(
            evaluate_prepare(&state, &unseen, None).err(),
            Some(ApplyRejection::WriterFenceNotDurable)
        );
    }

    #[test]
    fn operation_state_corruption_fails_closed() {
        let apply = fixture(1, 1, ExpectedActive::None, 10).admitted();
        let fenced = fence(&state(), &apply);
        let Ok(preparation) = evaluate_prepare(&fenced, &apply, None) else {
            panic!("test operation must prepare");
        };
        let record = preparation.operation();
        let ready = PreparationReadyFact::for_test(record.operation_id(), *record.request_digest());

        assert_eq!(
            evaluate_prepare(&fenced, &apply, Some(&record)).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );

        for phase in [OperationPhase::Active, OperationPhase::Superseded] {
            let mut torn_terminal = record;
            torn_terminal.phase = phase;
            assert_eq!(
                evaluate_prepare(preparation.next_state(), &apply, Some(&torn_terminal)).err(),
                Some(ApplyRejection::OperationStateMismatch)
            );
            assert_eq!(
                evaluate_activate(preparation.next_state(), &torn_terminal, &ready).err(),
                Some(ApplyRejection::OperationStateMismatch)
            );
        }

        let unrelated_apply = fixture(2, 1, ExpectedActive::None, 77).admitted();
        let mut unrelated_terminal = record;
        unrelated_terminal.operation_id = unrelated_apply.payload().control().operation_id();
        unrelated_terminal.request_digest = *unrelated_apply.payload().commitment_digest();
        unrelated_terminal.phase = OperationPhase::Active;
        let Ok(unrelated_prepare_replay) = evaluate_prepare(
            preparation.next_state(),
            &unrelated_apply,
            Some(&unrelated_terminal),
        ) else {
            panic!("unrelated historical operation must replay");
        };
        assert_eq!(
            unrelated_prepare_replay.disposition(),
            PrepareDisposition::Replayed(OperationPhase::Active)
        );
        let unrelated_ready = PreparationReadyFact::for_test(
            unrelated_terminal.operation_id(),
            *unrelated_terminal.request_digest(),
        );
        let Ok(unrelated_activation_replay) = evaluate_activate(
            preparation.next_state(),
            &unrelated_terminal,
            &unrelated_ready,
        ) else {
            panic!("unrelated historical activation must replay");
        };
        assert_eq!(
            unrelated_activation_replay.disposition(),
            ActivateDisposition::Replayed
        );
        assert_eq!(
            unrelated_activation_replay.next_state(),
            preparation.next_state()
        );

        let mut corrupted_digest = preparation.next_state().clone();
        let Some(prepared) = corrupted_digest.prepared.as_mut() else {
            panic!("prepared state must exist");
        };
        prepared.request_digest = Digest32::from_bytes([99; 32]);
        assert_eq!(
            evaluate_prepare(&corrupted_digest, &apply, Some(&record)).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );

        let mut corrupted_fence = preparation.next_state().clone();
        let Some(writer_fence) = corrupted_fence.writer_fence.as_mut() else {
            panic!("writer fence must exist");
        };
        writer_fence.epoch = PlanWriterEpoch::new(2);
        assert_eq!(
            evaluate_prepare(&corrupted_fence, &apply, Some(&record)).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );

        let mut corrupted_prepared_target = preparation.next_state().clone();
        let Some(prepared) = corrupted_prepared_target.prepared.as_mut() else {
            panic!("prepared state must exist");
        };
        let mut wrong_target_fixture = fixture(1, 1, ExpectedActive::None, 10);
        wrong_target_fixture.target_byte = 99;
        prepared.incoming = wrong_target_fixture.slice();
        assert_eq!(
            evaluate_writer_fence(&corrupted_prepared_target, apply.tenure()).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );
        assert_eq!(
            evaluate_prepare(&corrupted_prepared_target, &apply, Some(&record)).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );
        assert_eq!(
            evaluate_activate(&corrupted_prepared_target, &record, &ready).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );

        let Ok(activation) = evaluate_activate(preparation.next_state(), &record, &ready) else {
            panic!("test operation must activate");
        };
        let (active_state, active_record) = activation.into_parts();

        let mut missing_active_fence = active_state.clone();
        missing_active_fence.writer_fence = None;
        assert_eq!(
            evaluate_writer_fence(&missing_active_fence, apply.tenure()).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );
        assert_eq!(
            evaluate_prepare(&missing_active_fence, &apply, Some(&active_record)).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );
        assert_eq!(
            evaluate_activate(&missing_active_fence, &active_record, &ready).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );

        let mut corrupted_active_scope = active_state;
        let Some(active) = corrupted_active_scope.active.as_mut() else {
            panic!("active state must exist");
        };
        let mut wrong_scope_fixture = fixture(1, 1, ExpectedActive::None, 10);
        wrong_scope_fixture.scope_byte = 99;
        active.slice = wrong_scope_fixture.slice();
        assert_eq!(
            evaluate_writer_fence(&corrupted_active_scope, apply.tenure()).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );
        assert_eq!(
            evaluate_prepare(&corrupted_active_scope, &apply, Some(&active_record)).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );
        assert_eq!(
            evaluate_activate(&corrupted_active_scope, &active_record, &ready).err(),
            Some(ApplyRejection::OperationStateMismatch)
        );

        let wrong_lookup = OperationRecord {
            source_scope: preparation.next_state().source_scope,
            target: preparation.next_state().target,
            operation_id: ApplyOperationId::from_bytes([88; 16]),
            request_digest: *record.request_digest(),
            phase: OperationPhase::Prepared,
        };
        assert_eq!(
            evaluate_prepare(preparation.next_state(), &apply, Some(&wrong_lookup)).err(),
            Some(ApplyRejection::OperationLookupMismatch)
        );
    }

    #[test]
    fn activation_replay_is_side_effect_free() {
        let apply = fixture(1, 1, ExpectedActive::None, 10).admitted();
        let state = fence(&state(), &apply);
        let (state, prepared_operation) = prepare(&state, &apply);
        let ready = PreparationReadyFact::for_test(
            prepared_operation.operation_id(),
            *prepared_operation.request_digest(),
        );
        let Ok(first) = evaluate_activate(&state, &prepared_operation, &ready) else {
            panic!("test operation must activate");
        };
        let (active_state, active_operation) = first.into_parts();

        let Ok(replay) = evaluate_activate(&active_state, &active_operation, &ready) else {
            panic!("active operation must replay");
        };
        assert_eq!(replay.disposition(), ActivateDisposition::Replayed);
        assert_eq!(replay.operation(), active_operation);
        assert_eq!(replay.next_state(), &active_state);

        let mut wrong_scope = active_operation;
        wrong_scope.source_scope = SourceScopeRef::from_bytes([99; 16]);
        assert_eq!(
            evaluate_activate(&active_state, &wrong_scope, &ready).err(),
            Some(ApplyRejection::SourceScopeMismatch)
        );
        let mut wrong_target = active_operation;
        wrong_target.target = RuntimeHostId::from_bytes([99; 16]);
        assert_eq!(
            evaluate_activate(&active_state, &wrong_target, &ready).err(),
            Some(ApplyRejection::TargetMismatch)
        );
    }
}
