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
    proof_digest: Digest32,
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

    /// Returns the exact authority-proof digest admitted for this epoch.
    #[must_use]
    pub const fn proof_digest(&self) -> &Digest32 {
        &self.proof_digest
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VerifiedWriterTenure {
    source_scope: SourceScopeRef,
    writer: PlanWriterRef,
    epoch: PlanWriterEpoch,
    supersedes_through_epoch: PlanWriterEpoch,
    proof_digest: Digest32,
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
        let proof_digest = context.proof().digest()?;
        Ok(Self {
            source_scope: claim.source_scope(),
            writer: context.writer(),
            epoch: context.epoch(),
            supersedes_through_epoch: claim.supersedes_through_epoch(),
            proof_digest,
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

    /// Consumes the transition after the caller has chosen to persist it.
    #[must_use]
    pub fn into_state(self) -> ApplyControlState {
        self.next_state
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

    let next_fence = WriterFence {
        writer: verified.writer,
        epoch: verified.epoch,
        proof_digest: verified.proof_digest,
        principal: verified.principal,
    };

    match state.writer_fence {
        None => {
            let mut next_state = state.clone();
            next_state.writer_fence = Some(next_fence);
            Ok(FenceTransition {
                next_state,
                disposition: FenceDisposition::Advanced,
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
            })
        }
        Some(current) => {
            if verified.supersedes_through_epoch < current.epoch {
                return Err(ApplyRejection::TenureDoesNotSupersedeFence);
            }
            let mut next_state = state.clone();
            next_state.writer_fence = Some(next_fence);
            Ok(FenceTransition {
                next_state,
                disposition: FenceDisposition::Advanced,
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

    /// Returns the active-revision compare-and-swap input.
    #[must_use]
    pub const fn expected_active(&self) -> ExpectedActive {
        self.expected_active
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
}

/// Lookup/mutation value supplied separately from bounded apply control state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperationRecord {
    operation_id: ApplyOperationId,
    request_digest: Digest32,
    phase: OperationPhase,
}

impl OperationRecord {
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
    /// The exact operation and request digest already exist.
    Idempotent,
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

    /// Consumes the transition after its state and operation record are durable.
    #[must_use]
    pub fn into_state(self) -> ApplyControlState {
        self.next_state
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
    ensure_fence_matches(state, admitted.tenure())?;

    if let Some(existing) = prior_operation {
        if existing.operation_id != control.operation_id() {
            return Err(ApplyRejection::OperationLookupMismatch);
        }
        if existing.request_digest != *payload.commitment_digest() {
            return Err(ApplyRejection::OperationConflict);
        }
        return Ok(PrepareTransition {
            next_state: state.clone(),
            operation: *existing,
            disposition: PrepareDisposition::Idempotent,
        });
    }

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
        stage: PrepareStage::ControlAccepted,
    };
    let operation = OperationRecord {
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

fn ensure_fence_matches(
    state: &ApplyControlState,
    verified: &VerifiedWriterTenure,
) -> Result<(), ApplyRejection> {
    let expected = WriterFence {
        writer: verified.writer,
        epoch: verified.epoch,
        proof_digest: verified.proof_digest,
        principal: verified.principal,
    };
    if state.writer_fence != Some(expected) {
        return Err(ApplyRejection::WriterFenceNotDurable);
    }
    Ok(())
}

fn ensure_expected_active(
    state: &ApplyControlState,
    expected: ExpectedActive,
) -> Result<(), ApplyRejection> {
    let matches = match (expected, state.active.as_ref()) {
        (ExpectedActive::None, None) => true,
        (ExpectedActive::Revision(expected_revision), Some(active)) => {
            active.slice.header().provenance().source_revision() == expected_revision
        }
        _ => false,
    };
    if !matches {
        return Err(ApplyRejection::ExpectedActiveMismatch);
    }
    Ok(())
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

    /// Consumes the transition after one atomic journal commit.
    #[must_use]
    pub fn into_state(self) -> ApplyControlState {
        self.next_state
    }
}

/// Activates only the exact prepared operation with explicit readiness evidence.
pub fn evaluate_activate(
    state: &ApplyControlState,
    operation_id: ApplyOperationId,
    request_digest: &Digest32,
    ready: &PreparationReadyFact,
) -> Result<ActivateTransition, ApplyRejection> {
    let Some(prepared) = state.prepared.as_ref() else {
        return Err(ApplyRejection::NoPreparedOperation);
    };
    if prepared.operation_id != operation_id || prepared.request_digest != *request_digest {
        return Err(ApplyRejection::PreparedOperationMismatch);
    }
    if ready.operation_id != operation_id || ready.request_digest != *request_digest {
        return Err(ApplyRejection::ReadinessMismatch);
    }
    let operation = OperationRecord {
        operation_id,
        request_digest: *request_digest,
        phase: OperationPhase::Active,
    };
    let mut next_state = state.clone();
    next_state.active = Some(ActiveControl {
        slice: prepared.incoming,
    });
    next_state.prepared = None;

    Ok(ActivateTransition {
        next_state,
        operation,
    })
}

/// Stable, fail-closed reasons returned before any Runtime execution side effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyRejection {
    /// Canonical slice or control validation failed.
    Contract(ApplyContractError),
    /// Canonical proof digest construction failed.
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
    /// Expected-active compare-and-swap failed.
    ExpectedActiveMismatch,
    /// A new operation attempted source revision rollback or reuse.
    NonMonotonicRevision,
    /// Another operation is already prepared.
    PrepareInProgress,
    /// No prepared operation exists to activate.
    NoPreparedOperation,
    /// Activation did not identify the exact prepared operation.
    PreparedOperationMismatch,
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
            Self::Digest(error) => write!(formatter, "proof digest rejected: {error}"),
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
            Self::ExpectedActiveMismatch => {
                formatter.write_str("expected active revision mismatch")
            }
            Self::NonMonotonicRevision => formatter.write_str("source revision did not advance"),
            Self::PrepareInProgress => formatter.write_str("another apply operation is prepared"),
            Self::NoPreparedOperation => formatter.write_str("no prepared operation exists"),
            Self::PreparedOperationMismatch => {
                formatter.write_str("prepared operation does not match activation")
            }
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
        AdmittedApply, ApplyControlState, ApplyRejection, FenceDisposition, OperationPhase,
        PreparationReadyFact, PrepareDisposition, evaluate_activate, evaluate_prepare,
        evaluate_writer_fence,
    };

    const SCOPE_BYTES: [u8; 16] = [1; 16];
    const TARGET_BYTES: [u8; 16] = [2; 16];
    const WRITER_BYTES: [u8; 16] = [4; 16];

    fn state() -> ApplyControlState {
        ApplyControlState::new(
            SourceScopeRef::from_bytes(SCOPE_BYTES),
            RuntimeHostId::from_bytes(TARGET_BYTES),
        )
    }

    fn admitted(
        revision: u64,
        epoch: u64,
        expected_active: ExpectedActive,
        operation_byte: u8,
    ) -> AdmittedApply {
        let scope = SourceScopeRef::from_bytes(SCOPE_BYTES);
        let writer = PlanWriterRef::from_bytes(WRITER_BYTES);
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
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(epoch - 1),
        ) else {
            panic!("test tenure claim must be valid");
        };
        let Ok(proof) = WriterTenureProof::try_new(authority, claim, b"nonce", b"signature") else {
            panic!("test tenure proof must be valid");
        };
        let Ok(writer_context) =
            PlanWriterContext::try_new(writer, PlanWriterEpoch::new(epoch), proof)
        else {
            panic!("test writer context must be valid");
        };
        let provenance = PlanProvenance::new(
            scope,
            SourcePlanRef::from_bytes([7; 16]),
            SourcePlanRevision::new(revision),
            SourcePlanDigest::new(Digest32::from_bytes([8; 32])),
        );
        let header = RuntimeSliceHeader::new(
            RuntimeHostId::from_bytes(TARGET_BYTES),
            provenance,
            TargetAssignmentDigest::new(Digest32::from_bytes([9; 32])),
        );
        let Ok(slice) = RuntimeSliceCommitment::try_new(header) else {
            panic!("test slice commitment must be valid");
        };
        let control = RuntimeApplyControl::new(
            writer_context,
            expected_active,
            ApplyOperationId::from_bytes([operation_byte; 16]),
        );
        let Ok(payload) = RuntimeApplyControlCommitment::try_new(slice, control) else {
            panic!("test control commitment must be valid");
        };
        let Ok(value) =
            AdmittedApply::from_payload_for_test(payload, PrincipalRef::from_bytes(WRITER_BYTES))
        else {
            panic!("test admission facts must be valid");
        };
        value
    }

    fn fence(state: &ApplyControlState, apply: &AdmittedApply) -> ApplyControlState {
        let Ok(transition) = evaluate_writer_fence(state, apply.tenure()) else {
            panic!("test writer tenure must be admitted");
        };
        transition.into_state()
    }

    fn prepare(
        state: &ApplyControlState,
        apply: &AdmittedApply,
    ) -> (ApplyControlState, super::OperationRecord) {
        let Ok(transition) = evaluate_prepare(state, apply, None) else {
            panic!("test apply must prepare");
        };
        let operation = transition.operation();
        (transition.into_state(), operation)
    }

    fn activate(state: &ApplyControlState, operation: super::OperationRecord) -> ApplyControlState {
        let ready =
            PreparationReadyFact::for_test(operation.operation_id(), *operation.request_digest());
        let Ok(transition) = evaluate_activate(
            state,
            operation.operation_id(),
            operation.request_digest(),
            &ready,
        ) else {
            panic!("test apply must activate");
        };
        transition.into_state()
    }

    #[test]
    fn higher_tenure_advances_fence_before_cas_rejection() {
        let first = admitted(1, 1, ExpectedActive::None, 10);
        let state = fence(&state(), &first);
        let (state, operation) = prepare(&state, &first);
        let state = activate(&state, operation);
        let old_active = state.active().copied();

        let second = admitted(2, 2, ExpectedActive::None, 11);
        let Ok(fence_transition) = evaluate_writer_fence(&state, second.tenure()) else {
            panic!("new tenure must advance the fence");
        };
        assert_eq!(fence_transition.disposition(), FenceDisposition::Advanced);
        let fenced_state = fence_transition.into_state();
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
        let first = admitted(1, 1, ExpectedActive::None, 10);
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
            evaluate_activate(
                prepared_state,
                operation.operation_id(),
                operation.request_digest(),
                &wrong_ready,
            )
            .err(),
            Some(ApplyRejection::ReadinessMismatch)
        );

        let ready =
            PreparationReadyFact::for_test(operation.operation_id(), *operation.request_digest());
        let Ok(activated) = evaluate_activate(
            prepared_state,
            operation.operation_id(),
            operation.request_digest(),
            &ready,
        ) else {
            panic!("matching readiness must activate");
        };
        assert!(activated.next_state().prepared().is_none());
        assert!(activated.next_state().active().is_some());
        assert_eq!(activated.operation().phase(), OperationPhase::Active);
    }

    #[test]
    fn same_operation_is_idempotent_and_changed_digest_conflicts() {
        let apply = admitted(1, 1, ExpectedActive::None, 10);
        let state = fence(&state(), &apply);
        let Ok(first) = evaluate_prepare(&state, &apply, None) else {
            panic!("valid apply must prepare");
        };
        let record = first.operation();
        let Ok(replay) = evaluate_prepare(first.next_state(), &apply, Some(&record)) else {
            panic!("exact operation replay must be idempotent");
        };
        assert_eq!(replay.disposition(), PrepareDisposition::Idempotent);

        let changed_apply = admitted(1, 1, ExpectedActive::None, 11);
        assert_eq!(
            evaluate_prepare(first.next_state(), &changed_apply, Some(&record)).err(),
            Some(ApplyRejection::OperationLookupMismatch)
        );

        let conflicting_record = super::OperationRecord {
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
        let apply = admitted(1, 1, ExpectedActive::None, 10);
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
        let Ok(_activation) = evaluate_activate(
            &prepared_state,
            operation.operation_id(),
            operation.request_digest(),
            &ready,
        ) else {
            panic!("matching readiness must produce activation transition");
        };
        assert!(prepared_state.active().is_none());
        assert!(prepared_state.prepared().is_some());
    }
}
