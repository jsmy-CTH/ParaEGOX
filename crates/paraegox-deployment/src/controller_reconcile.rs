//! Bounded Controller reconciliation for one exact Runtime query.
//!
//! One invocation either consumes durable response evidence without network,
//! explicitly closes a request-only restart boundary, or prepares and sends at
//! most one fresh PXQR.  It never sends or replays PXAR and commits the rollout
//! decision only after the PXQS has its own durable snapshot.

use core::fmt;
use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::path::Path;

use ed25519_dalek::SigningKey;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use paraegox_kernel::digest::Digest32;
use paraegox_runtime_contracts::provenance::{
    SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetSliceDigest,
};
use paraegox_runtime_contracts::reference_control::{
    ReferenceApplyRequestV1, ReferenceApplyTerminalOutcomeV1, ReferenceAssemblyModeV1,
    ReferenceQueryDesiredHeadV1, ReferenceQueryDurablePhaseV1, ReferenceQueryFactsV1,
    ReferenceQueryLiveStateV1, ReferenceQueryOperationLookupV1, ReferenceQueryOwnerStateV1,
    ReferenceQueryRequestV1, ReferenceQueryResponseV1,
};

use crate::controller_journal::{
    ControllerJournalError, ControllerJournalSnapshot, ControllerJournalState,
    ControllerObservedTarget, ControllerOwnerIdentityFingerprint, ControllerReceiptRef,
};
use crate::controller_query::{
    ControllerQueryError, ControllerQueryProvisioningV1, ControllerReferenceQueryError,
    FreshControllerQueryRequestV1, close_recovered_reference_query_v1, prepare_reference_query_v1,
    query_reference_once_v1_with, recover_reference_query_v1,
};
use crate::controller_store::{ControllerStore, ControllerStoreError};
use crate::planner::TargetIntent;
use crate::runtime_control_client::{
    PreparedRuntimeQueryRequest, RuntimeQueryExchangeError, UnixRuntimeQueryClient,
    ValidatedRuntimeQueryResponse,
};

const QUERY_ENTROPY_BYTES: usize = 48;

/// Stable, non-sensitive one-shot result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerReconcileOutcomeV1 {
    Prepared,
    Active(ControllerReceiptRef),
    Retired(ControllerReceiptRef),
    Uncertain,
}

impl ControllerReconcileOutcomeV1 {
    #[must_use]
    pub(crate) const fn receipt(self) -> Option<ControllerReceiptRef> {
        match self {
            Self::Active(receipt) | Self::Retired(receipt) => Some(receipt),
            Self::Prepared | Self::Uncertain => None,
        }
    }

    const fn journal_parts(self) -> (ControllerObservedTarget, Option<ControllerReceiptRef>) {
        match self {
            Self::Prepared => (ControllerObservedTarget::Prepared, None),
            Self::Active(receipt) => (ControllerObservedTarget::Active, Some(receipt)),
            Self::Retired(receipt) => (ControllerObservedTarget::Retired, Some(receipt)),
            Self::Uncertain => (ControllerObservedTarget::Uncertain, None),
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Active(_) | Self::Retired(_))
    }
}

/// Executes one bounded production query/reconcile attempt.
pub(crate) async fn reconcile_reference_once_v1(
    store: &mut ControllerStore,
    client: &UnixRuntimeQueryClient,
    expected_owner: ControllerOwnerIdentityFingerprint,
    controller_signer: &SigningKey,
    provisioning: ControllerQueryProvisioningV1,
) -> Result<ControllerReconcileOutcomeV1, ControllerReconcileError> {
    reconcile_reference_once_v1_with(
        store,
        expected_owner,
        controller_signer,
        provisioning,
        fresh_reference_query_request_v1,
        |durable| async move { client.exchange(durable).await },
        ControllerStore::commit,
        decide_from_durable_observation,
    )
    .await
}

#[allow(clippy::too_many_arguments)] // GOV-WAIVER-0011
async fn reconcile_reference_once_v1_with<
    FreshSource,
    Exchange,
    ExchangeFuture,
    DecisionCommit,
    Decide,
>(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    controller_signer: &SigningKey,
    provisioning: ControllerQueryProvisioningV1,
    fresh_source: FreshSource,
    exchange: Exchange,
    decision_commit: DecisionCommit,
    decide: Decide,
) -> Result<ControllerReconcileOutcomeV1, ControllerReconcileError>
where
    FreshSource: FnOnce() -> Result<FreshControllerQueryRequestV1, ControllerReconcileError>,
    Exchange: FnOnce(PreparedRuntimeQueryRequest) -> ExchangeFuture,
    ExchangeFuture:
        Future<Output = Result<ValidatedRuntimeQueryResponse, RuntimeQueryExchangeError>>,
    DecisionCommit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
    Decide: Fn(
        &ControllerJournalState,
        &ReferenceQueryRequestV1,
        &ReferenceQueryResponseV1,
    ) -> Result<ControllerReconcileOutcomeV1, ControllerReconcileError>,
{
    // This read also validates owner/provisioning and revalidates the durable
    // PXQR signature.  A decided attempt intentionally returns no recovery
    // token, so it is handled from the immutable journal view below.
    let recovered = recover_reference_query_v1(
        store,
        expected_owner,
        &controller_signer.verifying_key(),
        provisioning,
    )?;
    let before = store.snapshot()?.clone();

    if before.state().current_query_decision_is_terminal() {
        let replay = decision_from_current_observation(before.state(), &decide)?;
        validate_existing_decision(before.state(), replay)?;
        if !replay.is_terminal() {
            return Err(ControllerReconcileError::DecisionPersistenceMismatch);
        }
        return Ok(replay);
    } else if before.state().current_query_has_decision() {
        // A previous non-terminal decision is complete historical evidence.
        // A later direct PXRT may have arrived after that decision, so its
        // classification must not be retroactively rewritten. The new
        // invocation allocates a fresh query identity below.
    } else if let Some(recovered) = recovered {
        if let Some(response) = recovered.response() {
            let outcome = decide(before.state(), recovered.request(), response)?;
            return commit_decision_with(store, outcome, decision_commit, &decide);
        }
        if recovered.closure().is_none() {
            close_recovered_reference_query_v1(
                store,
                expected_owner,
                &recovered,
                &controller_signer.verifying_key(),
                provisioning,
            )?;
            return Ok(ControllerReconcileOutcomeV1::Uncertain);
        }
        // A previous no-response attempt is durably closed.  The new attempt
        // below is fresh; the old canonical PXQR is never sent again.
    }

    let fresh = fresh_source()?;
    let prepared = prepare_reference_query_v1(
        store,
        expected_owner,
        controller_signer,
        provisioning,
        fresh,
    )?;
    let durable_request = prepared.request().clone();
    let queried = match query_reference_once_v1_with(
        store,
        prepared,
        exchange,
        ControllerStore::commit,
    )
    .await
    {
        Ok(queried) => queried,
        Err(error) if error.has_durable_no_response_closure() => {
            return Ok(ControllerReconcileOutcomeV1::Uncertain);
        }
        Err(error) => return Err(ControllerReconcileError::Query(error)),
    };
    let outcome = decide(
        store.snapshot()?.state(),
        &durable_request,
        queried.response(),
    )?;
    commit_decision_with(store, outcome, decision_commit, &decide)
}

fn fresh_reference_query_request_v1()
-> Result<FreshControllerQueryRequestV1, ControllerReconcileError> {
    let owned = open(
        Path::new("/dev/urandom"),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ControllerReconcileError::EntropyUnavailable)?;
    let mut source = File::from(owned);
    let mut entropy = [0_u8; QUERY_ENTROPY_BYTES];
    source
        .read_exact(&mut entropy)
        .map_err(|_| ControllerReconcileError::EntropyUnavailable)?;
    fresh_reference_query_request_from_entropy(&entropy)
}

fn fresh_reference_query_request_from_entropy(
    entropy: &[u8; QUERY_ENTROPY_BYTES],
) -> Result<FreshControllerQueryRequestV1, ControllerReconcileError> {
    let mut query_id = [0_u8; 16];
    query_id.copy_from_slice(&entropy[..16]);
    let mut client_nonce = [0_u8; 32];
    client_nonce.copy_from_slice(&entropy[16..]);
    Ok(FreshControllerQueryRequestV1::try_new(
        query_id,
        client_nonce,
        true,
    )?)
}

fn decision_from_current_observation<Decide>(
    state: &ControllerJournalState,
    decide: &Decide,
) -> Result<ControllerReconcileOutcomeV1, ControllerReconcileError>
where
    Decide: Fn(
        &ControllerJournalState,
        &ReferenceQueryRequestV1,
        &ReferenceQueryResponseV1,
    ) -> Result<ControllerReconcileOutcomeV1, ControllerReconcileError>,
{
    let request = state
        .current_prepared_query()
        .ok_or(ControllerReconcileError::MissingDurableObservation)?
        .request();
    let response = state
        .current_query_observation()
        .ok_or(ControllerReconcileError::MissingDurableObservation)?
        .response();
    decide(state, request, response)
}

fn validate_existing_decision(
    state: &ControllerJournalState,
    outcome: ControllerReconcileOutcomeV1,
) -> Result<(), ControllerReconcileError> {
    let (observed, receipt) = outcome.journal_parts();
    let replay = state.record_rollout_decision(observed, receipt)?;
    if &replay != state {
        return Err(ControllerReconcileError::DecisionPersistenceMismatch);
    }
    Ok(())
}

fn commit_decision_with<DecisionCommit, Decide>(
    store: &mut ControllerStore,
    outcome: ControllerReconcileOutcomeV1,
    decision_commit: DecisionCommit,
    decide: &Decide,
) -> Result<ControllerReconcileOutcomeV1, ControllerReconcileError>
where
    DecisionCommit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
    Decide: Fn(
        &ControllerJournalState,
        &ReferenceQueryRequestV1,
        &ReferenceQueryResponseV1,
    ) -> Result<ControllerReconcileOutcomeV1, ControllerReconcileError>,
{
    let before = store.snapshot()?.clone();
    let (observed, receipt) = outcome.journal_parts();
    let decided_state = before.state().record_rollout_decision(observed, receipt)?;
    if &decided_state == before.state() {
        return Ok(outcome);
    }
    let next = before.try_successor(decided_state)?;
    decision_commit(store, next)?;

    let committed = store.snapshot()?;
    if !committed.state().current_query_has_decision() {
        return Err(ControllerReconcileError::DecisionPersistenceMismatch);
    }
    let durable = decision_from_current_observation(committed.state(), decide)?;
    validate_existing_decision(committed.state(), durable)?;
    if durable != outcome {
        return Err(ControllerReconcileError::DecisionPersistenceMismatch);
    }
    Ok(durable)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpectedReconcileStateV1 {
    target: paraegox_kernel::identity::RuntimeHostId,
    runtime_store_instance_id: [u8; 32],
    minimum_runtime_host_epoch: u64,
    request_digest: Digest32,
    source_revision: SourcePlanRevision,
    target_slice_digest: TargetSliceDigest,
    manifest_digest: Digest32,
    shape: TargetIntent,
}

fn decide_from_durable_observation(
    state: &ControllerJournalState,
    query: &ReferenceQueryRequestV1,
    response: &ReferenceQueryResponseV1,
) -> Result<ControllerReconcileOutcomeV1, ControllerReconcileError> {
    if response.query_id() != query.query_id()
        || response.query_request_digest() != query.request_digest()
        || response.client_nonce() != query.authentication().claim().nonce()
    {
        return Ok(ControllerReconcileOutcomeV1::Uncertain);
    }
    reject_conflicting_raw_terminal_reference(state, response.facts())?;
    let Some(expected) = expected_reconcile_state(state, query) else {
        return Ok(ControllerReconcileOutcomeV1::Uncertain);
    };
    constrain_by_direct_terminal(state, classify_query_facts(expected, response.facts()))
}

fn reject_conflicting_raw_terminal_reference(
    state: &ControllerJournalState,
    facts: ReferenceQueryFactsV1,
) -> Result<(), ControllerReconcileError> {
    let Some(direct) = state.current_direct_terminal_receipt() else {
        return Ok(());
    };
    let ReferenceQueryOperationLookupV1::Known {
        durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
        terminal_result: Some(queried),
        ..
    } = facts.operation().lookup()
    else {
        return Ok(());
    };
    if queried.as_bytes() != direct.facts().terminal_result_ref().as_bytes() {
        return Err(ControllerReconcileError::ConflictingTerminalEvidence);
    }
    Ok(())
}

fn constrain_by_direct_terminal(
    state: &ControllerJournalState,
    outcome: ControllerReconcileOutcomeV1,
) -> Result<ControllerReconcileOutcomeV1, ControllerReconcileError> {
    let Some(direct) = state.current_direct_terminal_receipt() else {
        return Ok(outcome);
    };
    let direct_facts = direct.facts();
    match outcome {
        ControllerReconcileOutcomeV1::Active(receipt)
        | ControllerReconcileOutcomeV1::Retired(receipt)
            if receipt.as_bytes() != direct_facts.terminal_result_ref().as_bytes() =>
        {
            Err(ControllerReconcileError::ConflictingTerminalEvidence)
        }
        ControllerReconcileOutcomeV1::Active(receipt)
            if direct_facts.outcome() == ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive =>
        {
            Ok(ControllerReconcileOutcomeV1::Active(receipt))
        }
        ControllerReconcileOutcomeV1::Retired(receipt)
            if direct_facts.outcome()
                == ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero =>
        {
            Ok(ControllerReconcileOutcomeV1::Retired(receipt))
        }
        ControllerReconcileOutcomeV1::Prepared => Ok(ControllerReconcileOutcomeV1::Prepared),
        ControllerReconcileOutcomeV1::Active(_)
        | ControllerReconcileOutcomeV1::Retired(_)
        | ControllerReconcileOutcomeV1::Uncertain => Ok(ControllerReconcileOutcomeV1::Uncertain),
    }
}

fn expected_reconcile_state(
    state: &ControllerJournalState,
    query: &ReferenceQueryRequestV1,
) -> Option<ExpectedReconcileStateV1> {
    let plan = state.committed_plan()?;
    let intent = state.current_signed_apply_intent()?;
    let binding = state.target_binding()?;
    let apply = ReferenceApplyRequestV1::decode(intent.signed_request()).ok()?;
    let provenance = apply.provenance();
    let execution = apply.target_execution();
    let expected_mode = match plan.content().shape() {
        TargetIntent::OneSourceLoop => ReferenceAssemblyModeV1::OneSourceLoop,
        TargetIntent::EmptyTarget => ReferenceAssemblyModeV1::EmptyDeactivate,
        TargetIntent::Omitted => return None,
    };
    let exact_shape = match (
        plan.content().shape(),
        plan.content().stable_allocation_subject(),
        plan.content().reference_lifecycle(),
        execution.loop_facts(),
    ) {
        (
            TargetIntent::OneSourceLoop,
            Some((_, expected_instance, expected_domain)),
            Some(expected_budgets),
            Some(loop_facts),
        ) => {
            loop_facts.instance() == expected_instance
                && loop_facts.domain() == expected_domain
                && loop_facts.budgets() == expected_budgets
        }
        (TargetIntent::EmptyTarget, None, None, None) => true,
        _ => false,
    };
    let apply_claim = apply.authentication().claim();
    let query_claim = query.authentication().claim();
    if !exact_shape
        || apply.canonical_wire() != intent.signed_request()
        || apply.target() != plan.target()
        || apply.target() != intent.target()
        || apply.target() != binding.target()
        || apply.target_slice_digest() != intent.target_slice_digest()
        || apply.envelope_request_digest() != intent.request_digest().value()
        || apply.expected_runtime_store_instance_id() != intent.runtime_store_instance_id()
        || apply.expected_runtime_store_instance_id() != binding.runtime_store_instance_id()
        || provenance.source_scope() != SourceScopeRef::from_bytes(*plan.scope().as_bytes())
        || provenance.source_plan() != SourcePlanRef::from_bytes(*plan.plan().as_bytes())
        || provenance.source_revision().value() != plan.revision().value()
        || provenance.source_plan_digest() != plan.deployment_plan_digest()
        || provenance.source_plan_digest() != intent.source_plan_digest()
        || apply.control_commitment().control().operation_id() != intent.apply_operation()
        || execution.mode() != expected_mode
        || execution.target() != plan.target()
        || execution.manifest_digest() != plan.content().manifest_digest().value()
        || execution.manifest_digest() != state.installed_manifest().manifest_digest()
        || execution
            .validate_manifest(state.installed_manifest().verified_manifest())
            .is_err()
        || apply_claim.principal() != query_claim.principal()
        || query.target() != apply.target()
        || query.source_scope() != provenance.source_scope()
        || query.expected_runtime_store_instance_id() != apply.expected_runtime_store_instance_id()
        || query.requested_operation_id() != intent.apply_operation()
        || query.expected_request_digest() != Some(intent.request_digest().value())
    {
        return None;
    }
    Some(ExpectedReconcileStateV1 {
        target: plan.target(),
        runtime_store_instance_id: binding.runtime_store_instance_id(),
        minimum_runtime_host_epoch: binding.last_runtime_host_epoch(),
        request_digest: intent.request_digest().value(),
        source_revision: SourcePlanRevision::new(plan.revision().value()),
        target_slice_digest: intent.target_slice_digest(),
        manifest_digest: plan.content().manifest_digest().value(),
        shape: plan.content().shape(),
    })
}

fn classify_query_facts(
    expected: ExpectedReconcileStateV1,
    facts: ReferenceQueryFactsV1,
) -> ControllerReconcileOutcomeV1 {
    let serving = facts.serving();
    let operation = facts.operation();
    if serving.target() != expected.target
        || serving.runtime_store_instance_id() != expected.runtime_store_instance_id
        || serving.runtime_host_epoch() < expected.minimum_runtime_host_epoch
        || operation.owner_state() != ReferenceQueryOwnerStateV1::Operational
        || !desired_matches(expected, facts)
    {
        return ControllerReconcileOutcomeV1::Uncertain;
    }

    let ReferenceQueryOperationLookupV1::Known {
        request_digest,
        durable_phase,
        terminal_result,
    } = operation.lookup()
    else {
        return ControllerReconcileOutcomeV1::Uncertain;
    };
    if request_digest != expected.request_digest {
        return ControllerReconcileOutcomeV1::Uncertain;
    }
    match durable_phase {
        ReferenceQueryDurablePhaseV1::PreparedNoEffects
        | ReferenceQueryDurablePhaseV1::FirstActionIntent
        | ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld => {
            ControllerReconcileOutcomeV1::Prepared
        }
        ReferenceQueryDurablePhaseV1::Terminal => {
            let Some(result) = terminal_result else {
                return ControllerReconcileOutcomeV1::Uncertain;
            };
            let receipt = ControllerReceiptRef::from_bytes(*result.as_bytes());
            match (expected.shape, facts.live().state()) {
                (TargetIntent::OneSourceLoop, ReferenceQueryLiveStateV1::LiveReady) => {
                    ControllerReconcileOutcomeV1::Active(receipt)
                }
                (TargetIntent::EmptyTarget, ReferenceQueryLiveStateV1::ExactZero) => {
                    ControllerReconcileOutcomeV1::Retired(receipt)
                }
                _ => ControllerReconcileOutcomeV1::Uncertain,
            }
        }
    }
}

fn desired_matches(expected: ExpectedReconcileStateV1, facts: ReferenceQueryFactsV1) -> bool {
    let desired = facts.desired();
    if desired.source_revision_high_water() != expected.source_revision {
        return false;
    }
    match (expected.shape, desired.head()) {
        (
            TargetIntent::OneSourceLoop,
            ReferenceQueryDesiredHeadV1::OneSourceLoop {
                source_revision,
                target_slice_digest,
                manifest_digest,
            },
        )
        | (
            TargetIntent::EmptyTarget,
            ReferenceQueryDesiredHeadV1::EmptyDeactivate {
                source_revision,
                target_slice_digest,
                manifest_digest,
            },
        ) => {
            source_revision == expected.source_revision
                && target_slice_digest == expected.target_slice_digest
                && manifest_digest == expected.manifest_digest
        }
        _ => false,
    }
}

#[derive(Debug)]
pub(crate) enum ControllerReconcileError {
    EntropyUnavailable,
    MissingDurableObservation,
    DecisionPersistenceMismatch,
    ConflictingTerminalEvidence,
    QueryPreparation(ControllerQueryError),
    Query(ControllerReferenceQueryError),
    Journal(ControllerJournalError),
    Store(ControllerStoreError),
}

impl From<ControllerQueryError> for ControllerReconcileError {
    fn from(value: ControllerQueryError) -> Self {
        Self::QueryPreparation(value)
    }
}

impl From<ControllerJournalError> for ControllerReconcileError {
    fn from(value: ControllerJournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<ControllerStoreError> for ControllerReconcileError {
    fn from(value: ControllerStoreError) -> Self {
        Self::Store(value)
    }
}

impl fmt::Display for ControllerReconcileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller reconcile failed closed: {self:?}")
    }
}

impl std::error::Error for ControllerReconcileError {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};
    use paraegox_runtime_contracts::reference_control::{
        ReferenceApplyRequestV1, ReferenceApplyTerminalFactsV1, ReferenceApplyTerminalHeadV1,
        ReferenceApplyTerminalLifecycleEffectV1, ReferenceApplyTerminalOutcomeV1,
        ReferenceBootstrapResponseV1, ReferenceBootstrapServingIdentityV1,
        ReferenceOperationalReasonV1, ReferenceQueryDesiredHeadV1, ReferenceQueryDesiredStateV1,
        ReferenceQueryDurablePhaseV1, ReferenceQueryFactsV1, ReferenceQueryLiveFactsV1,
        ReferenceQueryLiveStateV1, ReferenceQueryOperationLookupV1, ReferenceQueryOperationStateV1,
        ReferenceQueryOwnerStateV1, ReferenceQueryResponseAuthClaimV1,
        ReferenceQueryResponseDraftV1,
    };

    use crate::controller_journal::{
        ControllerJournalError, ControllerJournalSnapshot, ControllerQueryClosureKind,
        ControllerReceiptRef,
        tests::{binding, direct_active_snapshot, direct_active_snapshot_with_operation},
    };
    use crate::controller_query::{
        ControllerQueryError, ControllerQueryProvisioningV1, FreshControllerQueryRequestV1,
        prepare_reference_query_v1, query_reference_once_v1_with,
        tests::{invalid_query_ready_snapshot, query_ready_empty_snapshot, query_ready_snapshot},
    };
    use crate::controller_store::{
        ControllerCommitFailpoint, ControllerFilesystemPolicy, ControllerStore,
        create_and_lock_controller_initializer_lock, ensure_fresh_controller_directory,
        open_controller_directory, publish_initial_controller_snapshot,
    };
    use crate::planner::TargetIntent;
    use crate::runtime_control_client::{
        PreparedRuntimeQueryRequest, RuntimeQueryClientFailure, RuntimeQueryExchangeError,
        ValidatedRuntimeQueryResponse,
    };

    use super::{
        ControllerReconcileError, ControllerReconcileOutcomeV1, ExpectedReconcileStateV1,
        classify_query_facts, expected_reconcile_state, fresh_reference_query_request_from_entropy,
        reconcile_reference_once_v1_with,
    };

    const CONTROLLER_SEED: [u8; 32] = [0xc1; 32];
    const RUNTIME_SEED: [u8; 32] = [0xc2; 32];
    const CONTROLLER_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0xc3; 16]);
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|error| panic!("reconcile fixture root failed: {error}"));
            let path = root.join(format!(
                "paraegox-controller-reconcile-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("reconcile fixture create failed: {error}"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("reconcile fixture chmod failed: {error}"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn install_snapshot(snapshot: &ControllerJournalSnapshot, directory: &TestDirectory) {
        let handle = open_controller_directory(
            directory.path(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("open reconcile fixture failed: {error}"));
        ensure_fresh_controller_directory(&handle)
            .unwrap_or_else(|error| panic!("fresh reconcile fixture failed: {error}"));
        let lock = create_and_lock_controller_initializer_lock(&handle)
            .unwrap_or_else(|error| panic!("reconcile fixture lock failed: {error}"));
        publish_initial_controller_snapshot(
            &handle,
            &snapshot
                .encode()
                .unwrap_or_else(|error| panic!("reconcile fixture encode failed: {error}")),
            [0xd1; 16],
            ControllerCommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("reconcile fixture publish failed: {error:?}"));
        drop(lock);
    }

    fn open_snapshot(
        snapshot: &ControllerJournalSnapshot,
        directory: &TestDirectory,
    ) -> ControllerStore {
        ControllerStore::open_with_policy(
            directory.path(),
            *snapshot.store_instance_id(),
            snapshot.owner_identity_fingerprint(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("reconcile fixture store open failed: {error}"))
    }

    fn provisioning() -> ControllerQueryProvisioningV1 {
        ControllerQueryProvisioningV1::try_new(CONTROLLER_PRINCIPAL)
            .unwrap_or_else(|error| panic!("reconcile provisioning failed: {error}"))
    }

    fn fresh(marker: u8) -> FreshControllerQueryRequestV1 {
        FreshControllerQueryRequestV1::try_new([marker; 16], [marker.wrapping_add(1); 32], true)
            .unwrap_or_else(|error| panic!("reconcile fresh identity failed: {error}"))
    }

    fn validated_unknown(prepared: PreparedRuntimeQueryRequest) -> ValidatedRuntimeQueryResponse {
        let request = prepared.request();
        let baseline = prepared.serving_baseline();
        let sequence = baseline.snapshot_sequence() + 1;
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            baseline.target(),
            baseline.runtime_store_instance_id(),
            sequence,
            baseline.runtime_host_epoch(),
            baseline.clock_domain(),
            baseline.clock_generation(),
        )
        .unwrap_or_else(|error| panic!("reconcile serving facts failed: {error}"));
        let operation = ReferenceQueryOperationStateV1::try_new(
            ReferenceQueryOwnerStateV1::Operational,
            None,
            ReferenceQueryOperationLookupV1::Unknown,
        )
        .unwrap_or_else(|error| panic!("reconcile operation facts failed: {error}"));
        let desired = ReferenceQueryDesiredStateV1::try_new(
            ReferenceQueryDesiredHeadV1::None,
            SourcePlanRevision::new(0),
        )
        .unwrap_or_else(|error| panic!("reconcile desired facts failed: {error}"));
        let live = ReferenceQueryLiveFactsV1::try_new(
            ReferenceQueryLiveStateV1::ExactZero,
            0,
            sequence,
            Digest32::from_bytes([0xd2; 32]),
        )
        .unwrap_or_else(|error| panic!("reconcile live facts failed: {error}"));
        let facts = ReferenceQueryFactsV1::try_new(serving, operation, desired, live)
            .unwrap_or_else(|error| panic!("reconcile query facts failed: {error}"));
        let channel = prepared.request_time_channel();
        let claim = ReferenceQueryResponseAuthClaimV1::try_new(
            channel,
            prepared.response_key(),
            prepared.response_algorithm(),
            prepared.response_algorithm_version(),
        )
        .unwrap_or_else(|error| panic!("reconcile response claim failed: {error}"));
        let draft = ReferenceQueryResponseDraftV1::try_new(request, facts, channel, claim)
            .unwrap_or_else(|error| panic!("reconcile response draft failed: {error}"));
        let signature = SigningKey::from_bytes(&RUNTIME_SEED).sign(
            draft
                .signing_transcript()
                .unwrap_or_else(|error| panic!("reconcile response transcript failed: {error}"))
                .as_bytes(),
        );
        let response = draft
            .finalize(&signature.to_bytes())
            .unwrap_or_else(|error| panic!("reconcile response failed: {error}"));
        ValidatedRuntimeQueryResponse::try_from_contract_fixture(
            response, request, channel, channel, baseline,
        )
        .unwrap_or_else(|error| panic!("reconcile validated response failed: {error}"))
    }

    fn validated_terminal(
        prepared: PreparedRuntimeQueryRequest,
        expected: ExpectedReconcileStateV1,
        result: paraegox_runtime_contracts::reference_control::ReferenceApplyTerminalResultRefV1,
    ) -> ValidatedRuntimeQueryResponse {
        let sequence = prepared.serving_baseline().snapshot_sequence() + 1;
        validated_terminal_at_sequence(prepared, expected, result, sequence)
    }

    fn validated_terminal_at_sequence(
        prepared: PreparedRuntimeQueryRequest,
        expected: ExpectedReconcileStateV1,
        result: paraegox_runtime_contracts::reference_control::ReferenceApplyTerminalResultRefV1,
        sequence: u64,
    ) -> ValidatedRuntimeQueryResponse {
        validated_known_at_sequence(
            prepared,
            expected,
            ReferenceQueryDurablePhaseV1::Terminal,
            Some(result),
            sequence,
        )
    }

    fn validated_prepared(
        prepared: PreparedRuntimeQueryRequest,
        expected: ExpectedReconcileStateV1,
    ) -> ValidatedRuntimeQueryResponse {
        let sequence = prepared.serving_baseline().snapshot_sequence() + 1;
        validated_known_at_sequence(
            prepared,
            expected,
            ReferenceQueryDurablePhaseV1::PreparedNoEffects,
            None,
            sequence,
        )
    }

    fn validated_known_at_sequence(
        prepared: PreparedRuntimeQueryRequest,
        expected: ExpectedReconcileStateV1,
        durable_phase: ReferenceQueryDurablePhaseV1,
        terminal_result: Option<
            paraegox_runtime_contracts::reference_control::ReferenceApplyTerminalResultRefV1,
        >,
        sequence: u64,
    ) -> ValidatedRuntimeQueryResponse {
        let request = prepared.request();
        let baseline = prepared.serving_baseline();
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            baseline.target(),
            baseline.runtime_store_instance_id(),
            sequence,
            baseline.runtime_host_epoch(),
            baseline.clock_domain(),
            baseline.clock_generation(),
        )
        .unwrap_or_else(|error| panic!("terminal reconcile serving facts failed: {error}"));
        let operation = ReferenceQueryOperationStateV1::try_new(
            ReferenceQueryOwnerStateV1::Operational,
            None,
            ReferenceQueryOperationLookupV1::Known {
                request_digest: expected.request_digest,
                durable_phase,
                terminal_result,
            },
        )
        .unwrap_or_else(|error| panic!("terminal reconcile operation facts failed: {error}"));
        let desired = ReferenceQueryDesiredStateV1::try_new(
            exact_desired(expected),
            expected.source_revision,
        )
        .unwrap_or_else(|error| panic!("terminal reconcile desired facts failed: {error}"));
        let (live_state, resource_generation) = match expected.shape {
            TargetIntent::OneSourceLoop => (ReferenceQueryLiveStateV1::LiveReady, 1),
            TargetIntent::EmptyTarget => (ReferenceQueryLiveStateV1::ExactZero, 0),
            TargetIntent::Omitted => panic!("omitted plan cannot return terminal query facts"),
        };
        let live = ReferenceQueryLiveFactsV1::try_new(
            live_state,
            resource_generation,
            sequence,
            Digest32::from_bytes([0xd3; 32]),
        )
        .unwrap_or_else(|error| panic!("terminal reconcile live facts failed: {error}"));
        let facts = ReferenceQueryFactsV1::try_new(serving, operation, desired, live)
            .unwrap_or_else(|error| panic!("terminal reconcile query facts failed: {error}"));
        let channel = prepared.request_time_channel();
        let claim = ReferenceQueryResponseAuthClaimV1::try_new(
            channel,
            prepared.response_key(),
            prepared.response_algorithm(),
            prepared.response_algorithm_version(),
        )
        .unwrap_or_else(|error| panic!("terminal reconcile response claim failed: {error}"));
        let draft = ReferenceQueryResponseDraftV1::try_new(request, facts, channel, claim)
            .unwrap_or_else(|error| panic!("terminal reconcile response draft failed: {error}"));
        let signature = SigningKey::from_bytes(&RUNTIME_SEED).sign(
            draft
                .signing_transcript()
                .unwrap_or_else(|error| {
                    panic!("terminal reconcile response transcript failed: {error}")
                })
                .as_bytes(),
        );
        let response = draft
            .finalize(&signature.to_bytes())
            .unwrap_or_else(|error| panic!("terminal reconcile response failed: {error}"));
        ValidatedRuntimeQueryResponse::try_from_contract_fixture(
            response, request, channel, channel, baseline,
        )
        .unwrap_or_else(|error| panic!("terminal reconcile validated response failed: {error}"))
    }

    fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("reconcile test runtime failed: {error}"))
            .block_on(future)
    }

    fn expected(shape: TargetIntent) -> ExpectedReconcileStateV1 {
        ExpectedReconcileStateV1 {
            target: RuntimeHostId::from_bytes([0x31; 16]),
            runtime_store_instance_id: [0x32; 32],
            minimum_runtime_host_epoch: 3,
            request_digest: Digest32::from_bytes([0x33; 32]),
            source_revision: SourcePlanRevision::new(1),
            target_slice_digest: TargetSliceDigest::new(Digest32::from_bytes([0x34; 32])),
            manifest_digest: Digest32::from_bytes([0x35; 32]),
            shape,
        }
    }

    fn exact_desired(expected: ExpectedReconcileStateV1) -> ReferenceQueryDesiredHeadV1 {
        match expected.shape {
            TargetIntent::OneSourceLoop => ReferenceQueryDesiredHeadV1::OneSourceLoop {
                source_revision: expected.source_revision,
                target_slice_digest: expected.target_slice_digest,
                manifest_digest: expected.manifest_digest,
            },
            TargetIntent::EmptyTarget => ReferenceQueryDesiredHeadV1::EmptyDeactivate {
                source_revision: expected.source_revision,
                target_slice_digest: expected.target_slice_digest,
                manifest_digest: expected.manifest_digest,
            },
            TargetIntent::Omitted => panic!("omitted is not a reconcilable desired state"),
        }
    }

    #[allow(clippy::too_many_arguments)] // GOV-WAIVER-0011
    fn facts(
        _expected: ExpectedReconcileStateV1,
        serving_target: RuntimeHostId,
        serving_store: [u8; 32],
        serving_epoch: u64,
        owner: ReferenceQueryOwnerStateV1,
        reason: Option<ReferenceOperationalReasonV1>,
        lookup: ReferenceQueryOperationLookupV1,
        desired_head: ReferenceQueryDesiredHeadV1,
        desired_high_water: SourcePlanRevision,
        live_state: ReferenceQueryLiveStateV1,
    ) -> ReferenceQueryFactsV1 {
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            serving_target,
            serving_store,
            7,
            serving_epoch,
            ClockDomainRef::from_bytes([0x36; 16]),
            ClockGeneration::try_new(1)
                .unwrap_or_else(|error| panic!("fixture clock generation failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("fixture serving failed: {error}"));
        let operation = ReferenceQueryOperationStateV1::try_new(owner, reason, lookup)
            .unwrap_or_else(|error| panic!("fixture operation failed: {error}"));
        let desired = ReferenceQueryDesiredStateV1::try_new(desired_head, desired_high_water)
            .unwrap_or_else(|error| panic!("fixture desired failed: {error}"));
        let resource_generation = match live_state {
            ReferenceQueryLiveStateV1::LiveReady | ReferenceQueryLiveStateV1::Draining => 1,
            ReferenceQueryLiveStateV1::Recovering | ReferenceQueryLiveStateV1::Uncertain => 1,
            _ => 0,
        };
        let live = ReferenceQueryLiveFactsV1::try_new(
            live_state,
            resource_generation,
            9,
            Digest32::from_bytes([0x37; 32]),
        )
        .unwrap_or_else(|error| panic!("fixture live failed: {error}"));
        ReferenceQueryFactsV1::try_new(serving, operation, desired, live)
            .unwrap_or_else(|error| panic!("fixture query facts failed: {error}"))
    }

    fn exact_facts(
        expected: ExpectedReconcileStateV1,
        lookup: ReferenceQueryOperationLookupV1,
        live: ReferenceQueryLiveStateV1,
    ) -> ReferenceQueryFactsV1 {
        facts(
            expected,
            expected.target,
            expected.runtime_store_instance_id,
            expected.minimum_runtime_host_epoch,
            ReferenceQueryOwnerStateV1::Operational,
            None,
            lookup,
            exact_desired(expected),
            expected.source_revision,
            live,
        )
    }

    fn terminal_result()
    -> paraegox_runtime_contracts::reference_control::ReferenceApplyTerminalResultRefV1 {
        let (_, receipt, _) = direct_active_snapshot();
        receipt.facts().terminal_result_ref()
    }

    fn terminal_result_for_snapshot(
        snapshot: &ControllerJournalSnapshot,
    ) -> paraegox_runtime_contracts::reference_control::ReferenceApplyTerminalResultRefV1 {
        let state = snapshot.state();
        let intent = state
            .current_signed_apply_intent()
            .expect("terminal result fixture signed intent");
        let request = ReferenceApplyRequestV1::decode(intent.signed_request())
            .expect("terminal result fixture canonical PXAR");
        let binding = state
            .target_binding()
            .expect("terminal result fixture target binding");
        let bootstrap = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())
            .expect("terminal result fixture bootstrap");
        let (outcome, lifecycle) = match state
            .committed_plan()
            .expect("terminal result fixture committed plan")
            .content()
            .shape()
        {
            TargetIntent::OneSourceLoop => (
                ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
                ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ),
            TargetIntent::EmptyTarget => (
                ReferenceApplyTerminalOutcomeV1::EmptyDeactivateExactZero,
                ReferenceApplyTerminalLifecycleEffectV1::ProvenNotStarted,
            ),
            TargetIntent::Omitted => panic!("omitted plan cannot derive terminal result"),
        };
        ReferenceApplyTerminalFactsV1::try_new(
            &request,
            outcome,
            lifecycle,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
            Digest32::from_bytes([0xd4; 32]),
            Digest32::from_bytes([0xd5; 32]),
            bootstrap.facts().runtime_host_epoch(),
            10,
            bootstrap.facts().clock_generation(),
            11_000,
        )
        .expect("terminal result fixture facts")
        .terminal_result_ref()
    }

    #[test]
    fn exact_mapping_produces_prepared_active_retired_and_uncertain() {
        let result = terminal_result();
        let loop_expected = expected(TargetIntent::OneSourceLoop);
        for phase in [
            ReferenceQueryDurablePhaseV1::PreparedNoEffects,
            ReferenceQueryDurablePhaseV1::FirstActionIntent,
            ReferenceQueryDurablePhaseV1::HeadCommittedRetiringOld,
        ] {
            assert_eq!(
                classify_query_facts(
                    loop_expected,
                    exact_facts(
                        loop_expected,
                        ReferenceQueryOperationLookupV1::Known {
                            request_digest: loop_expected.request_digest,
                            durable_phase: phase,
                            terminal_result: None,
                        },
                        ReferenceQueryLiveStateV1::LiveReady,
                    ),
                ),
                ControllerReconcileOutcomeV1::Prepared
            );
        }
        let active = ControllerReceiptRef::from_bytes(*result.as_bytes());
        assert_eq!(
            classify_query_facts(
                loop_expected,
                exact_facts(
                    loop_expected,
                    ReferenceQueryOperationLookupV1::Known {
                        request_digest: loop_expected.request_digest,
                        durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                        terminal_result: Some(result),
                    },
                    ReferenceQueryLiveStateV1::LiveReady,
                ),
            ),
            ControllerReconcileOutcomeV1::Active(active)
        );

        let empty_expected = expected(TargetIntent::EmptyTarget);
        assert_eq!(
            classify_query_facts(
                empty_expected,
                exact_facts(
                    empty_expected,
                    ReferenceQueryOperationLookupV1::Known {
                        request_digest: empty_expected.request_digest,
                        durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                        terminal_result: Some(result),
                    },
                    ReferenceQueryLiveStateV1::ExactZero,
                ),
            ),
            ControllerReconcileOutcomeV1::Retired(active)
        );
        assert_eq!(
            classify_query_facts(
                loop_expected,
                exact_facts(
                    loop_expected,
                    ReferenceQueryOperationLookupV1::Unknown,
                    ReferenceQueryLiveStateV1::LiveReady,
                ),
            ),
            ControllerReconcileOutcomeV1::Uncertain
        );
    }

    #[test]
    fn every_owner_lookup_request_desired_live_and_serving_mismatch_is_uncertain() {
        let expected = expected(TargetIntent::OneSourceLoop);
        let result = terminal_result();
        let terminal = ReferenceQueryOperationLookupV1::Known {
            request_digest: expected.request_digest,
            durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
            terminal_result: Some(result),
        };
        let exact = || exact_facts(expected, terminal, ReferenceQueryLiveStateV1::LiveReady);
        assert_eq!(
            classify_query_facts(
                expected,
                facts(
                    expected,
                    expected.target,
                    expected.runtime_store_instance_id,
                    expected.minimum_runtime_host_epoch,
                    ReferenceQueryOwnerStateV1::ApplyDisabled,
                    Some(ReferenceOperationalReasonV1::RuntimeBusy),
                    terminal,
                    exact_desired(expected),
                    expected.source_revision,
                    ReferenceQueryLiveStateV1::LiveReady,
                ),
            ),
            ControllerReconcileOutcomeV1::Uncertain
        );
        for lookup in [
            ReferenceQueryOperationLookupV1::Conflict {
                existing_request_digest: Digest32::from_bytes([0x41; 32]),
            },
            ReferenceQueryOperationLookupV1::Unknown,
            ReferenceQueryOperationLookupV1::Known {
                request_digest: Digest32::from_bytes([0x42; 32]),
                durable_phase: ReferenceQueryDurablePhaseV1::Terminal,
                terminal_result: Some(result),
            },
        ] {
            assert_eq!(
                classify_query_facts(
                    expected,
                    exact_facts(expected, lookup, ReferenceQueryLiveStateV1::LiveReady),
                ),
                ControllerReconcileOutcomeV1::Uncertain
            );
        }
        assert_eq!(
            classify_query_facts(
                expected,
                facts(
                    expected,
                    expected.target,
                    expected.runtime_store_instance_id,
                    expected.minimum_runtime_host_epoch,
                    ReferenceQueryOwnerStateV1::OwnershipUncertain,
                    Some(ReferenceOperationalReasonV1::OwnershipUncertain),
                    ReferenceQueryOperationLookupV1::Indeterminate {
                        reason: ReferenceOperationalReasonV1::OwnershipUncertain,
                    },
                    exact_desired(expected),
                    expected.source_revision,
                    ReferenceQueryLiveStateV1::Uncertain,
                ),
            ),
            ControllerReconcileOutcomeV1::Uncertain
        );

        for mismatched in [
            facts(
                expected,
                RuntimeHostId::from_bytes([0x43; 16]),
                expected.runtime_store_instance_id,
                expected.minimum_runtime_host_epoch,
                ReferenceQueryOwnerStateV1::Operational,
                None,
                terminal,
                exact_desired(expected),
                expected.source_revision,
                ReferenceQueryLiveStateV1::LiveReady,
            ),
            facts(
                expected,
                expected.target,
                [0x44; 32],
                expected.minimum_runtime_host_epoch,
                ReferenceQueryOwnerStateV1::Operational,
                None,
                terminal,
                exact_desired(expected),
                expected.source_revision,
                ReferenceQueryLiveStateV1::LiveReady,
            ),
            facts(
                expected,
                expected.target,
                expected.runtime_store_instance_id,
                expected.minimum_runtime_host_epoch - 1,
                ReferenceQueryOwnerStateV1::Operational,
                None,
                terminal,
                exact_desired(expected),
                expected.source_revision,
                ReferenceQueryLiveStateV1::LiveReady,
            ),
            facts(
                expected,
                expected.target,
                expected.runtime_store_instance_id,
                expected.minimum_runtime_host_epoch,
                ReferenceQueryOwnerStateV1::Operational,
                None,
                terminal,
                ReferenceQueryDesiredHeadV1::OneSourceLoop {
                    source_revision: SourcePlanRevision::new(2),
                    target_slice_digest: expected.target_slice_digest,
                    manifest_digest: expected.manifest_digest,
                },
                SourcePlanRevision::new(2),
                ReferenceQueryLiveStateV1::LiveReady,
            ),
            facts(
                expected,
                expected.target,
                expected.runtime_store_instance_id,
                expected.minimum_runtime_host_epoch,
                ReferenceQueryOwnerStateV1::Operational,
                None,
                terminal,
                ReferenceQueryDesiredHeadV1::OneSourceLoop {
                    source_revision: expected.source_revision,
                    target_slice_digest: TargetSliceDigest::new(Digest32::from_bytes([0x45; 32])),
                    manifest_digest: expected.manifest_digest,
                },
                expected.source_revision,
                ReferenceQueryLiveStateV1::LiveReady,
            ),
            facts(
                expected,
                expected.target,
                expected.runtime_store_instance_id,
                expected.minimum_runtime_host_epoch,
                ReferenceQueryOwnerStateV1::Operational,
                None,
                terminal,
                ReferenceQueryDesiredHeadV1::OneSourceLoop {
                    source_revision: expected.source_revision,
                    target_slice_digest: expected.target_slice_digest,
                    manifest_digest: Digest32::from_bytes([0x46; 32]),
                },
                expected.source_revision,
                ReferenceQueryLiveStateV1::LiveReady,
            ),
            facts(
                expected,
                expected.target,
                expected.runtime_store_instance_id,
                expected.minimum_runtime_host_epoch,
                ReferenceQueryOwnerStateV1::Operational,
                None,
                terminal,
                exact_desired(expected),
                SourcePlanRevision::new(2),
                ReferenceQueryLiveStateV1::LiveReady,
            ),
            facts(
                expected,
                expected.target,
                expected.runtime_store_instance_id,
                expected.minimum_runtime_host_epoch,
                ReferenceQueryOwnerStateV1::Operational,
                None,
                terminal,
                exact_desired(expected),
                expected.source_revision,
                ReferenceQueryLiveStateV1::NotReady,
            ),
        ] {
            assert_eq!(
                classify_query_facts(expected, mismatched),
                ControllerReconcileOutcomeV1::Uncertain
            );
        }
        assert_eq!(
            classify_query_facts(expected, exact()),
            ControllerReconcileOutcomeV1::Active(ControllerReceiptRef::from_bytes(
                *result.as_bytes()
            ))
        );
    }

    #[test]
    fn entropy_is_exactly_query_id_plus_nonce_and_never_caller_supplied() {
        let mut entropy = [0x51; super::QUERY_ENTROPY_BYTES];
        entropy[..16].copy_from_slice(&[0x52; 16]);
        entropy[16..].copy_from_slice(&[0x53; 32]);
        let fresh = fresh_reference_query_request_from_entropy(&entropy)
            .unwrap_or_else(|error| panic!("valid query entropy failed: {error}"));
        assert_eq!(
            fresh,
            FreshControllerQueryRequestV1::try_new([0x52; 16], [0x53; 32], true)
                .expect("expected entropy split")
        );
        assert!(
            fresh_reference_query_request_from_entropy(&[0; super::QUERY_ENTROPY_BYTES]).is_err()
        );
    }

    #[test]
    fn fresh_attempt_sends_exactly_one_pxqr_and_commits_response_then_decision() {
        run_async(async {
            let ready = query_ready_snapshot();
            let directory = TestDirectory::new();
            install_snapshot(&ready, &directory);
            let mut store = open_snapshot(&ready, &directory);
            let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
            let sends = Cell::new(0_u32);
            let before = store
                .snapshot()
                .expect("fresh starting snapshot")
                .snapshot_sequence();
            let outcome = reconcile_reference_once_v1_with(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || Ok(fresh(0x61)),
                |prepared| {
                    sends.set(sends.get() + 1);
                    async move { Ok(validated_unknown(prepared)) }
                },
                ControllerStore::commit,
                |_, _, _| Ok(ControllerReconcileOutcomeV1::Prepared),
            )
            .await
            .unwrap_or_else(|error| panic!("fresh reconcile failed: {error}"));
            assert_eq!(outcome, ControllerReconcileOutcomeV1::Prepared);
            assert_eq!(sends.get(), 1, "one invocation may send only one PXQR");
            let committed = store.snapshot().expect("fresh decided snapshot");
            assert_eq!(committed.snapshot_sequence(), before + 3);
            assert!(committed.state().current_query_has_decision());
        });
    }

    #[test]
    fn response_only_restart_commits_decision_with_zero_network_and_zero_fresh_entropy() {
        run_async(async {
            let ready = query_ready_snapshot();
            let directory = TestDirectory::new();
            install_snapshot(&ready, &directory);
            let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
            let mut store = open_snapshot(&ready, &directory);
            let resident = prepare_reference_query_v1(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                fresh(0x62),
            )
            .expect("response-only request prepare");
            query_reference_once_v1_with(
                &mut store,
                resident,
                |prepared| async move { Ok(validated_unknown(prepared)) },
                ControllerStore::commit,
            )
            .await
            .expect("response-only PXQS commit");
            let response_sequence = store
                .snapshot()
                .expect("response snapshot")
                .snapshot_sequence();
            drop(store);

            let mut reopened = open_snapshot(&ready, &directory);
            let fresh_calls = Cell::new(0_u32);
            let sends = Cell::new(0_u32);
            let outcome = reconcile_reference_once_v1_with(
                &mut reopened,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || {
                    fresh_calls.set(fresh_calls.get() + 1);
                    Ok(fresh(0x63))
                },
                |_| {
                    sends.set(sends.get() + 1);
                    async {
                        Err(RuntimeQueryExchangeError::NotSent(
                            RuntimeQueryClientFailure::RequestBoundExceeded,
                        ))
                    }
                },
                ControllerStore::commit,
                |_, _, _| Ok(ControllerReconcileOutcomeV1::Prepared),
            )
            .await
            .expect("response-only reconcile");
            assert_eq!(outcome, ControllerReconcileOutcomeV1::Prepared);
            assert_eq!(fresh_calls.get(), 0);
            assert_eq!(sends.get(), 0);
            assert_eq!(
                reopened
                    .snapshot()
                    .expect("decision snapshot")
                    .snapshot_sequence(),
                response_sequence + 1
            );
        });
    }

    #[test]
    fn request_only_restart_closes_resident_authority_and_returns_uncertain_without_network() {
        run_async(async {
            let ready = query_ready_snapshot();
            let directory = TestDirectory::new();
            install_snapshot(&ready, &directory);
            let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
            let mut store = open_snapshot(&ready, &directory);
            let resident = prepare_reference_query_v1(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                fresh(0x64),
            )
            .expect("request-only prepare");
            let request_sequence = resident.controller_snapshot_sequence();
            drop(resident);
            drop(store);

            let mut reopened = open_snapshot(&ready, &directory);
            let fresh_calls = Cell::new(0_u32);
            let sends = Cell::new(0_u32);
            let outcome = reconcile_reference_once_v1_with(
                &mut reopened,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || {
                    fresh_calls.set(fresh_calls.get() + 1);
                    Ok(fresh(0x65))
                },
                |_| {
                    sends.set(sends.get() + 1);
                    async {
                        Err(RuntimeQueryExchangeError::NotSent(
                            RuntimeQueryClientFailure::RequestBoundExceeded,
                        ))
                    }
                },
                ControllerStore::commit,
                |_, _, _| Ok(ControllerReconcileOutcomeV1::Uncertain),
            )
            .await
            .expect("request-only restart reconcile");
            assert_eq!(outcome, ControllerReconcileOutcomeV1::Uncertain);
            assert_eq!(fresh_calls.get(), 0);
            assert_eq!(sends.get(), 0);
            let closed = reopened.snapshot().expect("closed request snapshot");
            assert_eq!(closed.snapshot_sequence(), request_sequence + 1);
            assert_eq!(
                closed.state().current_query_closure(),
                Some(ControllerQueryClosureKind::ResidentAuthorityLostAfterRestart)
            );
        });
    }

    #[test]
    fn decision_commit_ambiguity_replays_terminal_outcome_without_network() {
        run_async(async {
            let ready = query_ready_snapshot();
            let directory = TestDirectory::new();
            install_snapshot(&ready, &directory);
            let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
            let result = direct_active_snapshot_with_operation(0x67)
                .1
                .facts()
                .terminal_result_ref();
            let terminal = ControllerReconcileOutcomeV1::Active(ControllerReceiptRef::from_bytes(
                *result.as_bytes(),
            ));
            let mut store = open_snapshot(&ready, &directory);
            let first = reconcile_reference_once_v1_with(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || Ok(fresh(0x66)),
                |prepared| {
                    let expected = expected_reconcile_state(ready.state(), prepared.request())
                        .expect("canonical reconcile fixture must bind exact PXAR");
                    async move { Ok(validated_terminal(prepared, expected, result)) }
                },
                |store, next| {
                    store.commit_with_test_failpoint(
                        next,
                        ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn,
                    )
                },
                |_, _, _| Ok(terminal),
            )
            .await;
            assert!(matches!(first, Err(ControllerReconcileError::Store(_))));
            assert!(store.snapshot().is_err(), "ambiguous handle must stop");
            drop(store);

            let mut reopened = open_snapshot(&ready, &directory);
            let fresh_calls = Cell::new(0_u32);
            let sends = Cell::new(0_u32);
            let replay = reconcile_reference_once_v1_with(
                &mut reopened,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || {
                    fresh_calls.set(fresh_calls.get() + 1);
                    Ok(fresh(0x67))
                },
                |_| {
                    sends.set(sends.get() + 1);
                    async {
                        Err(RuntimeQueryExchangeError::NotSent(
                            RuntimeQueryClientFailure::RequestBoundExceeded,
                        ))
                    }
                },
                ControllerStore::commit,
                |_, _, _| Ok(terminal),
            )
            .await
            .expect("terminal decision replay");
            assert_eq!(replay, terminal);
            assert_eq!(fresh_calls.get(), 0);
            assert_eq!(sends.get(), 0);
        });
    }

    #[test]
    fn lost_direct_receipt_terminal_query_commits_and_replays_active_and_retired_stably() {
        for ready in [query_ready_snapshot(), query_ready_empty_snapshot()] {
            run_async(async {
                let directory = TestDirectory::new();
                install_snapshot(&ready, &directory);
                let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
                let result = terminal_result_for_snapshot(&ready);
                let receipt = ControllerReceiptRef::from_bytes(*result.as_bytes());
                let expected_outcome = match ready
                    .state()
                    .committed_plan()
                    .expect("lost-PXRT fixture committed plan")
                    .content()
                    .shape()
                {
                    TargetIntent::OneSourceLoop => ControllerReconcileOutcomeV1::Active(receipt),
                    TargetIntent::EmptyTarget => ControllerReconcileOutcomeV1::Retired(receipt),
                    TargetIntent::Omitted => panic!("lost-PXRT fixture must be actionable"),
                };
                let mut store = open_snapshot(&ready, &directory);
                let first_sends = Cell::new(0_u32);
                let first = reconcile_reference_once_v1_with(
                    &mut store,
                    ready.owner_identity_fingerprint(),
                    &signer,
                    provisioning(),
                    || Ok(fresh(0x69)),
                    |prepared| {
                        first_sends.set(first_sends.get() + 1);
                        let expected = expected_reconcile_state(ready.state(), prepared.request())
                            .expect("lost-PXRT query must bind the canonical PXAR");
                        async move { Ok(validated_terminal(prepared, expected, result)) }
                    },
                    ControllerStore::commit,
                    super::decide_from_durable_observation,
                )
                .await
                .expect("lost-PXRT terminal query reconcile");
                assert_eq!(first, expected_outcome);
                assert_eq!(first_sends.get(), 1);
                let durable_bytes = store
                    .snapshot()
                    .expect("lost-PXRT decided snapshot")
                    .encode()
                    .expect("lost-PXRT decided snapshot bytes");

                let fresh_calls = Cell::new(0_u32);
                let replay_sends = Cell::new(0_u32);
                let replay = reconcile_reference_once_v1_with(
                    &mut store,
                    ready.owner_identity_fingerprint(),
                    &signer,
                    provisioning(),
                    || {
                        fresh_calls.set(fresh_calls.get() + 1);
                        Ok(fresh(0x6a))
                    },
                    |_| {
                        replay_sends.set(replay_sends.get() + 1);
                        async {
                            Err(RuntimeQueryExchangeError::NotSent(
                                RuntimeQueryClientFailure::RequestBoundExceeded,
                            ))
                        }
                    },
                    ControllerStore::commit,
                    super::decide_from_durable_observation,
                )
                .await
                .expect("lost-PXRT terminal replay");
                assert_eq!(replay, expected_outcome);
                assert_eq!(fresh_calls.get(), 0);
                assert_eq!(replay_sends.get(), 0);
                assert_eq!(
                    store
                        .snapshot()
                        .expect("lost-PXRT replay snapshot")
                        .encode()
                        .expect("lost-PXRT replay snapshot bytes"),
                    durable_bytes
                );
            });
        }
    }

    #[test]
    fn historical_terminal_query_after_epoch_advance_runs_one_fresh_query() {
        run_async(async {
            let ready = query_ready_snapshot();
            let directory = TestDirectory::new();
            install_snapshot(&ready, &directory);
            let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
            let result = terminal_result_for_snapshot(&ready);
            let mut store = open_snapshot(&ready, &directory);
            let first = reconcile_reference_once_v1_with(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || Ok(fresh(0x6b)),
                |prepared| {
                    let expected = expected_reconcile_state(ready.state(), prepared.request())
                        .expect("epoch fixture initial query binding");
                    async move { Ok(validated_terminal(prepared, expected, result)) }
                },
                ControllerStore::commit,
                super::decide_from_durable_observation,
            )
            .await
            .expect("epoch fixture initial terminal query");
            assert!(matches!(first, ControllerReconcileOutcomeV1::Active(_)));

            let before_refresh = store.snapshot().expect("pre-refresh snapshot").clone();
            let refreshed_state = before_refresh
                .state()
                .record_target_binding(binding(4, b"bootstrap-four"))
                .expect("epoch fixture binding refresh");
            store
                .commit(
                    before_refresh
                        .try_successor(refreshed_state)
                        .expect("epoch fixture binding successor"),
                )
                .expect("epoch fixture binding commit");
            assert!(
                !store
                    .snapshot()
                    .expect("refreshed snapshot")
                    .state()
                    .current_query_decision_is_terminal(),
                "the epoch-three terminal query is historical at epoch four"
            );

            let fresh_calls = Cell::new(0_u32);
            let sends = Cell::new(0_u32);
            let refreshed = store.snapshot().expect("fresh epoch base snapshot").clone();
            let second = reconcile_reference_once_v1_with(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || {
                    fresh_calls.set(fresh_calls.get() + 1);
                    Ok(fresh(0x6c))
                },
                |prepared| {
                    sends.set(sends.get() + 1);
                    let expected = expected_reconcile_state(refreshed.state(), prepared.request())
                        .expect("epoch fixture fresh query binding");
                    async move { Ok(validated_terminal(prepared, expected, result)) }
                },
                ControllerStore::commit,
                super::decide_from_durable_observation,
            )
            .await
            .expect("epoch fixture current terminal query");
            assert_eq!(second, first);
            assert_eq!(fresh_calls.get(), 1);
            assert_eq!(sends.get(), 1);
            assert!(
                store
                    .snapshot()
                    .expect("current epoch terminal snapshot")
                    .state()
                    .current_query_decision_is_terminal()
            );
        });
    }

    #[test]
    fn direct_receipt_after_prepared_decision_still_runs_one_fresh_query() {
        run_async(async {
            let ready = query_ready_snapshot();
            let (_, direct_receipt, _) = direct_active_snapshot_with_operation(0x67);
            let result = direct_receipt.facts().terminal_result_ref();
            let directory = TestDirectory::new();
            install_snapshot(&ready, &directory);
            let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
            let mut store = open_snapshot(&ready, &directory);
            let first = reconcile_reference_once_v1_with(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || Ok(fresh(0x6d)),
                |prepared| {
                    let expected = expected_reconcile_state(ready.state(), prepared.request())
                        .expect("direct-after-Prepared query binding");
                    async move { Ok(validated_prepared(prepared, expected)) }
                },
                ControllerStore::commit,
                super::decide_from_durable_observation,
            )
            .await
            .expect("direct-after-Prepared initial reconcile");
            assert_eq!(first, ControllerReconcileOutcomeV1::Prepared);

            let before_direct = store.snapshot().expect("pre-direct snapshot").clone();
            let direct_state = before_direct
                .state()
                .record_direct_terminal_receipt(&direct_receipt)
                .expect("matching direct receipt after Prepared");
            store
                .commit(
                    before_direct
                        .try_successor(direct_state)
                        .expect("direct-after-Prepared successor"),
                )
                .expect("direct-after-Prepared commit");

            let fresh_calls = Cell::new(0_u32);
            let sends = Cell::new(0_u32);
            let current = store.snapshot().expect("direct current snapshot").clone();
            let second = reconcile_reference_once_v1_with(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || {
                    fresh_calls.set(fresh_calls.get() + 1);
                    Ok(fresh(0x6e))
                },
                |prepared| {
                    sends.set(sends.get() + 1);
                    let expected = expected_reconcile_state(current.state(), prepared.request())
                        .expect("direct-after-Prepared fresh query binding");
                    async move {
                        Ok(validated_terminal_at_sequence(
                            prepared, expected, result, 11,
                        ))
                    }
                },
                ControllerStore::commit,
                super::decide_from_durable_observation,
            )
            .await
            .expect("direct-after-Prepared fresh reconcile");
            assert_eq!(
                second,
                ControllerReconcileOutcomeV1::Active(ControllerReceiptRef::from_bytes(
                    *result.as_bytes()
                ))
            );
            assert_eq!(fresh_calls.get(), 1);
            assert_eq!(sends.get(), 1);
        });
    }

    #[test]
    fn conflicting_terminal_query_after_direct_is_durable_and_restart_stable_hard_error() {
        run_async(async {
            let ready = query_ready_snapshot();
            let (_, direct_receipt, _) = direct_active_snapshot_with_operation(0x67);
            let conflicting_result = direct_active_snapshot_with_operation(0x99)
                .1
                .facts()
                .terminal_result_ref();
            let directory = TestDirectory::new();
            install_snapshot(&ready, &directory);
            let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
            let mut store = open_snapshot(&ready, &directory);
            let prepared = reconcile_reference_once_v1_with(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || Ok(fresh(0x6f)),
                |request| {
                    let expected = expected_reconcile_state(ready.state(), request.request())
                        .expect("conflict fixture Prepared binding");
                    async move { Ok(validated_prepared(request, expected)) }
                },
                ControllerStore::commit,
                super::decide_from_durable_observation,
            )
            .await
            .expect("conflict fixture Prepared decision");
            assert_eq!(prepared, ControllerReconcileOutcomeV1::Prepared);

            let before_direct = store
                .snapshot()
                .expect("conflict pre-direct snapshot")
                .clone();
            let direct_state = before_direct
                .state()
                .record_direct_terminal_receipt(&direct_receipt)
                .expect("conflict fixture matching direct receipt");
            store
                .commit(
                    before_direct
                        .try_successor(direct_state)
                        .expect("conflict fixture direct successor"),
                )
                .expect("conflict fixture direct commit");
            let current = store.snapshot().expect("conflict direct snapshot").clone();
            let sends = Cell::new(0_u32);
            let first = reconcile_reference_once_v1_with(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || Ok(fresh(0x70)),
                |request| {
                    sends.set(sends.get() + 1);
                    let expected = expected_reconcile_state(current.state(), request.request())
                        .expect("conflict fixture terminal binding");
                    async move {
                        Ok(validated_terminal_at_sequence(
                            request,
                            expected,
                            conflicting_result,
                            11,
                        ))
                    }
                },
                ControllerStore::commit,
                super::decide_from_durable_observation,
            )
            .await;
            assert!(matches!(
                first,
                Err(ControllerReconcileError::ConflictingTerminalEvidence)
            ));
            assert_eq!(sends.get(), 1);
            assert!(
                store
                    .snapshot()
                    .expect("conflicting response snapshot")
                    .state()
                    .current_query_observation()
                    .is_some()
            );
            assert!(
                !store
                    .snapshot()
                    .expect("conflicting undecided snapshot")
                    .state()
                    .current_query_has_decision()
            );
            drop(store);

            let mut reopened = open_snapshot(&ready, &directory);
            let fresh_calls = Cell::new(0_u32);
            let replay_sends = Cell::new(0_u32);
            let replay = reconcile_reference_once_v1_with(
                &mut reopened,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                || {
                    fresh_calls.set(fresh_calls.get() + 1);
                    Ok(fresh(0x71))
                },
                |_| {
                    replay_sends.set(replay_sends.get() + 1);
                    async {
                        Err(RuntimeQueryExchangeError::NotSent(
                            RuntimeQueryClientFailure::RequestBoundExceeded,
                        ))
                    }
                },
                ControllerStore::commit,
                super::decide_from_durable_observation,
            )
            .await;
            assert!(matches!(
                replay,
                Err(ControllerReconcileError::ConflictingTerminalEvidence)
            ));
            assert_eq!(fresh_calls.get(), 0);
            assert_eq!(replay_sends.get(), 0);
        });
    }

    #[test]
    fn only_confirmed_no_response_closures_are_surfaceable_as_uncertain() {
        use crate::controller_query::ControllerReferenceQueryError;

        assert!(
            ControllerReferenceQueryError::ValidatedResponseMismatch
                .has_durable_no_response_closure()
        );
        assert!(
            !ControllerReferenceQueryError::DurableResponseCompletionMismatch
                .has_durable_no_response_closure()
        );
    }

    #[test]
    fn invalid_controller_plan_to_pxar_binding_cannot_become_a_decision() {
        let ready = invalid_query_ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
        let mut store = open_snapshot(&ready, &directory);
        let before = store.snapshot().expect("invalid-plan snapshot").clone();
        assert!(matches!(
            prepare_reference_query_v1(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                fresh(0x68),
            ),
            Err(ControllerQueryError::Journal(
                ControllerJournalError::InvalidQueryRequest
            ))
        ));
        assert_eq!(
            store.snapshot().expect("rejected invalid-plan snapshot"),
            &before,
            "opaque non-PXAR bytes must fail before any durable query mutation"
        );
    }
}
