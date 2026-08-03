//! Controller owner facade for constructing and durably preparing PXAR v5.
//!
//! A newly signed request is committed to the Controller journal before this
//! module returns any value that a transport may send.  If an intent already
//! exists, only its exact canonical bytes are reconstructed; fresh identities
//! are never substituted for an indeterminate prior attempt.

use core::fmt;
use std::future::Future;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
use paraegox_kernel::time::BoundedDuration;
use paraegox_runtime_contracts::apply::{
    ApplyContractError, ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterRef,
    RuntimeApplyControl, TenureAuthorityRef, TenureKeyRef,
};
use paraegox_runtime_contracts::provenance::{
    PlanProvenance, SourcePlanRef, SourcePlanRevision, SourceScopeRef,
};
use paraegox_runtime_contracts::reference_control::{
    MAX_REFERENCE_LIFECYCLE_NANOS, ReferenceAdmissionPolicyFingerprintV1,
    ReferenceAdmissionPolicyInputV1, ReferenceApplyRequestDraftV1, ReferenceApplyRequestV1,
    ReferenceApplyTerminalReceiptV1, ReferenceAssemblyModeV1, ReferenceBootstrapResponseV1,
    ReferenceBootstrapStateV1, ReferenceControlError, ReferenceTargetExecutionPlanV4,
    ed25519_control_key_fingerprint, reference_admission_policy_fingerprint_v1,
};
use paraegox_runtime_contracts::temporal::{
    ApplyTemporalConstraint, TemporalConstraintId, TemporalContractError,
};
use paraegox_runtime_contracts::wire::{
    ApplyAuthAlgorithm, ApplyAuthError, ApplyAuthKeyRef, ApplyRequestAuthClaim,
};

use crate::controller_journal::{
    ControllerApplyRequestDigest, ControllerJournalError, ControllerJournalSnapshot,
    ControllerJournalState, ControllerOwnerIdentityFingerprint, ControllerSignedApplyIntent,
    ControllerSignedApplyIntentInput,
};
use crate::controller_store::{ControllerStore, ControllerStoreError};
use crate::plan::DeploymentWriterRef;
use crate::planner::{PlanContent, TargetIntent};
use crate::runtime_control_client::{
    RuntimeApplyExchangeError, UnixRuntimeApplyClient, ValidatedRuntimeApplyTerminalReceipt,
};

const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
const ED25519_SIGNATURE_BYTES: usize = 64;

/// Fresh identities consumed only when no current apply intent is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreshControllerApplyRequestV1 {
    apply_operation: [u8; 16],
    temporal_constraint: [u8; 16],
    authentication_nonce: [u8; 32],
}

impl FreshControllerApplyRequestV1 {
    pub(crate) fn try_new(
        apply_operation: [u8; 16],
        temporal_constraint: [u8; 16],
        authentication_nonce: [u8; 32],
    ) -> Result<Self, ControllerApplyError> {
        if bytes_are_zero(&apply_operation)
            || bytes_are_zero(&temporal_constraint)
            || bytes_are_zero(&authentication_nonce)
            || apply_operation == temporal_constraint
        {
            return Err(ControllerApplyError::InvalidFreshIdentity);
        }
        Ok(Self {
            apply_operation,
            temporal_constraint,
            authentication_nonce,
        })
    }
}

/// Sealed actual Controller/Authority facts used by one apply producer.
///
/// No constructor accepts a policy digest. The token derives from journal
/// target/scope/auth truth, the actual Controller key, one committed Authority
/// proof, and protected Authority provisioning facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerApplyProvisioningV1 {
    target: RuntimeHostId,
    source_scope: SourceScopeRef,
    controller_principal: PrincipalRef,
    writer: DeploymentWriterRef,
    admission_policy: ReferenceAdmissionPolicyFingerprintV1,
}

impl ControllerApplyProvisioningV1 {
    #[allow(clippy::too_many_arguments)] // GOV-WAIVER-0011
    pub(crate) fn try_from_controller_state(
        state: &ControllerJournalState,
        controller_signer: &SigningKey,
        controller_principal: PrincipalRef,
        writer: DeploymentWriterRef,
        authority_principal: PrincipalRef,
        authority_uid: u32,
        authority_gid: u32,
        tenure_authority_ref: TenureAuthorityRef,
        tenure_key_ref: TenureKeyRef,
        tenure_public_key: [u8; 32],
    ) -> Result<Self, ControllerApplyError> {
        validate_controller_signer(state, controller_signer)?;
        let target = state.installed_manifest().target();
        let source_scope = SourceScopeRef::from_bytes(*state.scope().as_bytes());
        let plan_writer = PlanWriterRef::from_bytes(*writer.as_bytes());
        let proof = state
            .latest_committed_tenure_proof(plan_writer)
            .ok_or(ControllerApplyError::MissingCommittedTenureProof)?;
        let authority = proof.authority();
        if authority.authority() != tenure_authority_ref
            || authority.key() != tenure_key_ref
            || authority.algorithm().value() != ED25519_ALGORITHM
            || authority.algorithm_version() != ED25519_ALGORITHM_VERSION
            || proof.claim().source_scope() != source_scope
        {
            return Err(ControllerApplyError::InvalidTenureProvisioning);
        }
        validate_tenure_signature(proof, &tenure_public_key)?;

        let request_auth = state.request_auth();
        let admission_policy =
            reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
                target,
                source_scope,
                writer: plan_writer,
                controller_principal,
                controller_key_ref: request_auth.key(),
                controller_public_key: controller_signer.verifying_key().as_bytes(),
                authority_principal,
                authority_uid,
                authority_gid,
                tenure_authority_ref,
                tenure_key_ref,
                tenure_public_key: &tenure_public_key,
            })?;
        Ok(Self {
            target,
            source_scope,
            controller_principal,
            writer,
            admission_policy,
        })
    }
}

/// Request-time Runtime response expectation copied from the durable intent.
///
/// The current target binding may advance after a Runtime restart.  This
/// sealed value deliberately retains the original channel and signer selector
/// required to verify a historical PXRT replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedRuntimeApplyResponseExpectationV1 {
    channel: paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1,
    key: ApplyAuthKeyRef,
    algorithm: ApplyAuthAlgorithm,
    algorithm_version: u16,
}

impl PreparedRuntimeApplyResponseExpectationV1 {
    #[must_use]
    pub(crate) const fn channel(
        self,
    ) -> paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1 {
        self.channel
    }

    #[must_use]
    pub(crate) const fn key(self) -> ApplyAuthKeyRef {
        self.key
    }

    #[must_use]
    pub(crate) const fn algorithm(self) -> ApplyAuthAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub(crate) const fn algorithm_version(self) -> u16 {
        self.algorithm_version
    }
}

/// Narrow proof that an exact signed PXAR request is already durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedControllerApplyAttemptV1 {
    controller_store_instance_id: [u8; 32],
    controller_snapshot_sequence: u64,
    request: ReferenceApplyRequestV1,
    channel_auth_fingerprint: paraegox_kernel::digest::Digest32,
    runtime_response_expectation: PreparedRuntimeApplyResponseExpectationV1,
    replayed_from_journal: bool,
}

impl PreparedControllerApplyAttemptV1 {
    #[must_use]
    pub(crate) const fn controller_store_instance_id(&self) -> &[u8; 32] {
        &self.controller_store_instance_id
    }

    #[must_use]
    pub(crate) const fn controller_snapshot_sequence(&self) -> u64 {
        self.controller_snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ReferenceApplyRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) fn canonical_request_bytes(&self) -> &[u8] {
        self.request.canonical_wire()
    }

    #[must_use]
    pub(crate) const fn channel_auth_fingerprint(&self) -> paraegox_kernel::digest::Digest32 {
        self.channel_auth_fingerprint
    }

    #[must_use]
    pub(crate) const fn runtime_response_expectation(
        &self,
    ) -> PreparedRuntimeApplyResponseExpectationV1 {
        self.runtime_response_expectation
    }

    #[must_use]
    pub(crate) const fn replayed_from_journal(&self) -> bool {
        self.replayed_from_journal
    }
}

/// Durable terminal outcome of one Controller-owned apply orchestration.
///
/// `terminal_receipt == None` is possible only when older opaque reconcile
/// evidence had already made the operation terminal. It never represents a
/// newly completed direct apply exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerAppliedReferenceV1 {
    controller_store_instance_id: [u8; 32],
    controller_snapshot_sequence: u64,
    terminal_receipt: Option<ReferenceApplyTerminalReceiptV1>,
    replayed_from_journal: bool,
}

impl ControllerAppliedReferenceV1 {
    #[must_use]
    pub(crate) const fn controller_store_instance_id(&self) -> &[u8; 32] {
        &self.controller_store_instance_id
    }

    #[must_use]
    pub(crate) const fn controller_snapshot_sequence(&self) -> u64 {
        self.controller_snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn terminal_receipt(&self) -> Option<&ReferenceApplyTerminalReceiptV1> {
        self.terminal_receipt.as_ref()
    }

    #[must_use]
    pub(crate) const fn replayed_from_journal(&self) -> bool {
        self.replayed_from_journal
    }
}

/// Constructs, signs, and crash-safely commits one PXAR v5 before send.
pub(crate) fn prepare_reference_apply_v1(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    controller_signer: &SigningKey,
    provisioning: &ControllerApplyProvisioningV1,
    fresh: FreshControllerApplyRequestV1,
) -> Result<PreparedControllerApplyAttemptV1, ControllerApplyError> {
    prepare_reference_apply_v1_with_commit(
        store,
        expected_owner,
        controller_signer,
        provisioning,
        fresh,
        ControllerStore::commit,
    )
}

/// Reconstructs an exact durable PXAR without allocating any fresh identity.
/// Callers generate operation/temporal/nonce entropy only when this returns
/// `None` while holding the same single-writer Controller store lock.
pub(crate) fn replay_prepared_reference_apply_v1(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    controller_signer: &SigningKey,
    provisioning: &ControllerApplyProvisioningV1,
) -> Result<Option<PreparedControllerApplyAttemptV1>, ControllerApplyError> {
    let snapshot = store.snapshot()?.clone();
    validate_apply_context(&snapshot, expected_owner, provisioning)?;
    let Some(intent) = snapshot.state().current_signed_apply_intent() else {
        validate_controller_signer(snapshot.state(), controller_signer)?;
        return Ok(None);
    };
    validate_controller_signer_pin(intent.request_auth(), controller_signer)?;
    let request = validate_durable_request(
        snapshot.state(),
        intent,
        provisioning.controller_principal,
        provisioning.writer,
    )?;
    validate_request_signature(&request, &controller_signer.verifying_key())?;
    Ok(Some(prepared_from_snapshot(&snapshot, request, true)?))
}

/// Performs at most one direct Runtime exchange for an already-durable PXAR
/// and commits only the client's sealed, fully validated PXRT.
pub(crate) async fn apply_reference_once_v1(
    store: &mut ControllerStore,
    client: &UnixRuntimeApplyClient,
    prepared: &PreparedControllerApplyAttemptV1,
) -> Result<ControllerAppliedReferenceV1, ControllerReferenceApplyError> {
    apply_reference_once_v1_with(
        store,
        prepared,
        |durable| async move { client.exchange(&durable).await },
        ControllerStore::commit,
    )
    .await
}

async fn apply_reference_once_v1_with<Exchange, ExchangeFuture, Commit>(
    store: &mut ControllerStore,
    prepared: &PreparedControllerApplyAttemptV1,
    exchange: Exchange,
    commit: Commit,
) -> Result<ControllerAppliedReferenceV1, ControllerReferenceApplyError>
where
    Exchange: FnOnce(PreparedControllerApplyAttemptV1) -> ExchangeFuture,
    ExchangeFuture:
        Future<Output = Result<ValidatedRuntimeApplyTerminalReceipt, RuntimeApplyExchangeError>>,
    Commit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
{
    let before = store.snapshot()?.clone();
    let durable = reconstruct_durable_apply_attempt(&before, prepared)?;
    if before.state().current_apply_is_terminal() {
        return Ok(terminal_completion_from_snapshot(&before, true)?);
    }

    match exchange(durable.clone()).await {
        Ok(validated) => commit_validated_runtime_receipt_with(store, &durable, &validated, commit),
        Err(error) => Err(ControllerReferenceApplyError::Exchange(error)),
    }
}

fn commit_validated_runtime_receipt_with<Commit>(
    store: &mut ControllerStore,
    prepared: &PreparedControllerApplyAttemptV1,
    validated: &ValidatedRuntimeApplyTerminalReceipt,
    commit: Commit,
) -> Result<ControllerAppliedReferenceV1, ControllerReferenceApplyError>
where
    Commit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
{
    let before = store.snapshot()?.clone();
    let durable = reconstruct_durable_apply_attempt(&before, prepared)?;
    if before.state().current_apply_is_terminal() {
        return Ok(terminal_completion_from_snapshot(&before, true)?);
    }
    validate_validated_runtime_receipt(&durable, validated)?;
    let receipt = validated.receipt();
    let committed_state = before
        .state()
        .record_direct_terminal_receipt(receipt)
        .map_err(ControllerApplyError::from)?;
    let next = before
        .try_successor(committed_state)
        .map_err(ControllerApplyError::from)?;
    if let Err(store_error) = commit(store, next) {
        return Err(ControllerReferenceApplyError::VerifiedReceiptPersistence {
            receipt_digest: receipt.receipt_digest(),
            store: store_error,
        });
    }
    let committed = store.snapshot()?.clone();
    let completion = terminal_completion_from_snapshot(&committed, false)?;
    if completion.terminal_receipt() != Some(receipt) {
        return Err(ControllerReferenceApplyError::ValidatedReceiptMismatch);
    }
    Ok(completion)
}

fn validate_validated_runtime_receipt(
    prepared: &PreparedControllerApplyAttemptV1,
    validated: &ValidatedRuntimeApplyTerminalReceipt,
) -> Result<(), ControllerReferenceApplyError> {
    let expectation = prepared.runtime_response_expectation();
    let request_time_channel = validated.request_time_channel();
    let current_channel = validated.current_channel();
    if request_time_channel != expectation.channel()
        || current_channel.target() != prepared.request().target()
        || current_channel.runtime_peer() != expectation.channel().runtime_peer()
        || validated.facts() != validated.receipt().facts()
    {
        return Err(ControllerReferenceApplyError::ValidatedReceiptMismatch);
    }
    Ok(())
}

fn prepare_reference_apply_v1_with_commit<Commit>(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    controller_signer: &SigningKey,
    provisioning: &ControllerApplyProvisioningV1,
    fresh: FreshControllerApplyRequestV1,
    commit: Commit,
) -> Result<PreparedControllerApplyAttemptV1, ControllerApplyError>
where
    Commit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
{
    if let Some(replayed) =
        replay_prepared_reference_apply_v1(store, expected_owner, controller_signer, provisioning)?
    {
        return Ok(replayed);
    }
    let before = store.snapshot()?.clone();
    let request = build_fresh_request(before.state(), controller_signer, provisioning, fresh)?;
    let next_state =
        before
            .state()
            .record_signed_apply_intent(ControllerSignedApplyIntentInput {
                target: request.target(),
                source_plan_digest: request.provenance().source_plan_digest(),
                target_slice_digest: request.target_slice_digest(),
                apply_operation: request.control_commitment().control().operation_id(),
                request_digest: ControllerApplyRequestDigest::from_stored(
                    request.envelope_request_digest(),
                ),
                signed_request: request.canonical_wire(),
            })?;
    let next = before.try_successor(next_state)?;
    commit(store, next)?;

    let durable = store.snapshot()?.clone();
    let intent = durable
        .state()
        .current_signed_apply_intent()
        .ok_or(ControllerApplyError::MissingDurableIntent)?;
    let request = validate_durable_request(
        durable.state(),
        intent,
        provisioning.controller_principal,
        provisioning.writer,
    )?;
    validate_request_signature(&request, &controller_signer.verifying_key())?;
    prepared_from_snapshot(&durable, request, false)
}

fn build_fresh_request(
    state: &ControllerJournalState,
    controller_signer: &SigningKey,
    provisioning: &ControllerApplyProvisioningV1,
    fresh: FreshControllerApplyRequestV1,
) -> Result<ReferenceApplyRequestV1, ControllerApplyError> {
    let plan = state
        .committed_plan()
        .ok_or(ControllerApplyError::MissingCommittedPlan)?;
    let binding = state
        .target_binding()
        .ok_or(ControllerApplyError::MissingTargetBinding)?;
    let bootstrap = validate_bootstrap_binding(state, provisioning.admission_policy)?;
    let execution = execution_for_content(state, plan.content())?;
    let provenance = PlanProvenance::new(
        SourceScopeRef::from_bytes(*plan.scope().as_bytes()),
        SourcePlanRef::from_bytes(*plan.plan().as_bytes()),
        SourcePlanRevision::new(plan.revision().value()),
        plan.deployment_plan_digest(),
    );

    let plan_writer = PlanWriterRef::from_bytes(*provisioning.writer.as_bytes());
    let proof = state
        .latest_committed_tenure_proof(plan_writer)
        .ok_or(ControllerApplyError::MissingCommittedTenureProof)?
        .clone();
    let writer_context = PlanWriterContext::try_new(plan_writer, proof.claim().epoch(), proof)?;
    let expected_active = state
        .last_terminal_target_slice_digest()?
        .map_or(ExpectedActive::None, ExpectedActive::Exact);
    let control = RuntimeApplyControl::new(
        writer_context,
        expected_active,
        ApplyOperationId::from_bytes(fresh.apply_operation),
    );
    let budget = BoundedDuration::from_nanos(MAX_REFERENCE_LIFECYCLE_NANOS);
    let temporal = ApplyTemporalConstraint::try_new(
        TemporalConstraintId::from_bytes(fresh.temporal_constraint),
        bootstrap.facts().clock_domain(),
        bootstrap.facts().clock_generation(),
        budget,
        budget,
    )?;
    let request_auth = state.request_auth();
    let auth_claim = ApplyRequestAuthClaim::try_new(
        provisioning.controller_principal,
        request_auth.key(),
        request_auth.algorithm(),
        request_auth.algorithm_version(),
        &fresh.authentication_nonce,
    )?;
    let draft = ReferenceApplyRequestDraftV1::try_new(
        execution,
        provenance,
        control,
        temporal,
        binding.runtime_store_instance_id(),
        auth_claim,
    )?;
    let transcript = draft.signing_transcript()?;
    let signature = controller_signer.sign(transcript.as_bytes());
    let request = draft.finalize(&signature.to_bytes())?;
    let decoded = ReferenceApplyRequestV1::decode(request.canonical_wire())?;
    if decoded != request {
        return Err(ControllerApplyError::StoredRequestMismatch);
    }
    Ok(request)
}

fn execution_for_content(
    state: &ControllerJournalState,
    content: &PlanContent,
) -> Result<ReferenceTargetExecutionPlanV4, ControllerApplyError> {
    match (
        content.shape(),
        content.stable_allocation_subject(),
        content.reference_lifecycle(),
    ) {
        (TargetIntent::OneSourceLoop, Some((_, instance, domain)), Some(budgets)) => {
            Ok(ReferenceTargetExecutionPlanV4::try_one_source_loop(
                state.installed_manifest().verified_manifest(),
                instance,
                domain,
                budgets,
            )?)
        }
        (TargetIntent::EmptyTarget, None, None) => {
            Ok(ReferenceTargetExecutionPlanV4::try_empty_deactivate(
                state.installed_manifest().verified_manifest(),
            )?)
        }
        _ => Err(ControllerApplyError::InvalidCommittedPlanShape),
    }
}

fn validate_bootstrap_binding(
    state: &ControllerJournalState,
    admission_policy: ReferenceAdmissionPolicyFingerprintV1,
) -> Result<ReferenceBootstrapResponseV1, ControllerApplyError> {
    let binding = state
        .target_binding()
        .ok_or(ControllerApplyError::MissingTargetBinding)?;
    let response = ReferenceBootstrapResponseV1::decode(binding.bootstrap_response())?;
    let facts = response.facts();
    if response.canonical_wire() != binding.bootstrap_response()
        || response.response_digest() != binding.bootstrap_response_digest().value()
        || facts.target() != binding.target()
        || facts.runtime_store_instance_id() != binding.runtime_store_instance_id()
        || facts.runtime_host_epoch() != binding.last_runtime_host_epoch()
        || facts.manifest_digest() != binding.manifest_digest().value()
        || facts.manifest_digest() != state.installed_manifest().manifest_digest()
        || facts.profile_fingerprint()
            != state
                .installed_manifest()
                .projection()
                .profile_fingerprint()
        || facts.admission_policy_fingerprint() != admission_policy.digest()
        || facts.state() != ReferenceBootstrapStateV1::ReadyForApply
    {
        return Err(ControllerApplyError::BootstrapBindingMismatch);
    }
    Ok(response)
}

fn validate_durable_request(
    state: &ControllerJournalState,
    intent: &ControllerSignedApplyIntent,
    controller_principal: PrincipalRef,
    writer: DeploymentWriterRef,
) -> Result<ReferenceApplyRequestV1, ControllerApplyError> {
    let plan = state
        .committed_plan()
        .ok_or(ControllerApplyError::MissingCommittedPlan)?;
    let binding = state
        .target_binding()
        .ok_or(ControllerApplyError::MissingTargetBinding)?;
    let request = ReferenceApplyRequestV1::decode(intent.signed_request())?;
    let provenance = request.provenance();
    let control = request.control_commitment().control();
    let auth = request.authentication();
    let claim = auth.claim();
    let request_auth = intent.request_auth();
    let expected_active = state
        .last_terminal_target_slice_digest()?
        .map_or(ExpectedActive::None, ExpectedActive::Exact);
    let plan_writer = PlanWriterRef::from_bytes(*writer.as_bytes());
    let expected_execution = execution_for_content(state, plan.content())?;

    if request.canonical_wire() != intent.signed_request()
        || request.target() != intent.target()
        || request.target() != plan.target()
        || request.target() != binding.target()
        || request.target_slice_digest() != intent.target_slice_digest()
        || request.envelope_request_digest() != intent.request_digest().value()
        || request.expected_runtime_store_instance_id() != intent.runtime_store_instance_id()
        || intent.runtime_store_instance_id() != binding.runtime_store_instance_id()
        || intent.binding_channel_auth_fingerprint() != binding.channel_auth_fingerprint()
        || intent.binding_manifest_digest() != binding.manifest_digest()
        || provenance.source_scope() != SourceScopeRef::from_bytes(*plan.scope().as_bytes())
        || provenance.source_plan() != SourcePlanRef::from_bytes(*plan.plan().as_bytes())
        || provenance.source_revision().value() != plan.revision().value()
        || provenance.source_plan_digest() != intent.source_plan_digest()
        || provenance.source_plan_digest() != plan.deployment_plan_digest()
        || control.operation_id() != intent.apply_operation()
        || control.expected_active() != expected_active
        || control.writer_context().writer() != plan_writer
        || !state.contains_committed_tenure_proof(control.writer_context().proof())
        || claim.principal() != controller_principal
        || claim.key() != request_auth.key()
        || claim.algorithm() != request_auth.algorithm()
        || claim.algorithm_version() != request_auth.algorithm_version()
        || claim.algorithm().value() != ED25519_ALGORITHM
        || claim.algorithm_version() != ED25519_ALGORITHM_VERSION
        || auth.signature().len() != ED25519_SIGNATURE_BYTES
        || request.target_execution().canonical_wire() != expected_execution.canonical_wire()
    {
        return Err(ControllerApplyError::StoredRequestMismatch);
    }
    request
        .target_execution()
        .validate_manifest(state.installed_manifest().verified_manifest())?;
    match (request.target_execution().mode(), plan.content().shape()) {
        (ReferenceAssemblyModeV1::OneSourceLoop, TargetIntent::OneSourceLoop)
        | (ReferenceAssemblyModeV1::EmptyDeactivate, TargetIntent::EmptyTarget) => {}
        _ => return Err(ControllerApplyError::StoredRequestMismatch),
    }
    Ok(request)
}

fn validate_controller_signer(
    state: &ControllerJournalState,
    signer: &SigningKey,
) -> Result<(), ControllerApplyError> {
    validate_controller_signer_pin(state.request_auth(), signer)
}

fn validate_controller_signer_pin(
    request_auth: crate::controller_journal::ControllerRequestAuthPin,
    signer: &SigningKey,
) -> Result<(), ControllerApplyError> {
    if request_auth.algorithm().value() != ED25519_ALGORITHM
        || request_auth.algorithm_version() != ED25519_ALGORITHM_VERSION
    {
        return Err(ControllerApplyError::UnsupportedRequestAuthProfile);
    }
    let fingerprint = ed25519_control_key_fingerprint(signer.verifying_key().as_bytes())?;
    if fingerprint != request_auth.verification_key_fingerprint().value() {
        return Err(ControllerApplyError::ControllerSigningKeyMismatch);
    }
    Ok(())
}

fn validate_apply_context(
    snapshot: &ControllerJournalSnapshot,
    expected_owner: ControllerOwnerIdentityFingerprint,
    provisioning: &ControllerApplyProvisioningV1,
) -> Result<(), ControllerApplyError> {
    if snapshot.owner_identity_fingerprint() != expected_owner {
        return Err(ControllerApplyError::OwnerIdentityMismatch);
    }
    let state = snapshot.state();
    if bytes_are_zero(provisioning.controller_principal.as_bytes())
        || bytes_are_zero(provisioning.writer.as_bytes())
        || state.installed_manifest().target() != provisioning.target
        || SourceScopeRef::from_bytes(*state.scope().as_bytes()) != provisioning.source_scope
    {
        return Err(ControllerApplyError::InvalidControllerIdentity);
    }
    validate_bootstrap_binding(state, provisioning.admission_policy)?;
    Ok(())
}

fn validate_request_signature(
    request: &ReferenceApplyRequestV1,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), ControllerApplyError> {
    let signature = Signature::from_slice(request.authentication().signature())
        .map_err(|_| ControllerApplyError::StoredRequestMismatch)?;
    let transcript = request.signing_transcript()?;
    verifying_key
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| ControllerApplyError::StoredRequestMismatch)
}

fn validate_tenure_signature(
    proof: &paraegox_runtime_contracts::apply::WriterTenureProof,
    public_key: &[u8; 32],
) -> Result<(), ControllerApplyError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| ControllerApplyError::InvalidTenureProvisioning)?;
    let signature = Signature::from_slice(proof.signature())
        .map_err(|_| ControllerApplyError::InvalidTenureProvisioning)?;
    let transcript = proof
        .signing_transcript()
        .map_err(|_| ControllerApplyError::InvalidTenureProvisioning)?;
    verifying_key
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| ControllerApplyError::InvalidTenureProvisioning)
}

fn prepared_from_snapshot(
    snapshot: &ControllerJournalSnapshot,
    request: ReferenceApplyRequestV1,
    replayed_from_journal: bool,
) -> Result<PreparedControllerApplyAttemptV1, ControllerApplyError> {
    let intent = snapshot
        .state()
        .current_signed_apply_intent()
        .ok_or(ControllerApplyError::MissingDurableIntent)?;
    if request.canonical_wire() != intent.signed_request() {
        return Err(ControllerApplyError::StoredRequestMismatch);
    }
    let runtime_auth = intent.runtime_response_auth();
    Ok(PreparedControllerApplyAttemptV1 {
        controller_store_instance_id: *snapshot.store_instance_id(),
        controller_snapshot_sequence: snapshot.snapshot_sequence(),
        request,
        channel_auth_fingerprint: intent.binding_channel_auth_fingerprint().value(),
        runtime_response_expectation: PreparedRuntimeApplyResponseExpectationV1 {
            channel: runtime_auth.channel(intent.target())?,
            key: runtime_auth.key(),
            algorithm: runtime_auth.algorithm(),
            algorithm_version: runtime_auth.algorithm_version(),
        },
        replayed_from_journal,
    })
}

fn reconstruct_durable_apply_attempt(
    snapshot: &ControllerJournalSnapshot,
    prepared: &PreparedControllerApplyAttemptV1,
) -> Result<PreparedControllerApplyAttemptV1, ControllerApplyError> {
    if prepared.controller_store_instance_id != *snapshot.store_instance_id()
        || prepared.controller_snapshot_sequence > snapshot.snapshot_sequence()
    {
        return Err(ControllerApplyError::PreparedAttemptMismatch);
    }
    let intent = snapshot
        .state()
        .current_signed_apply_intent()
        .ok_or(ControllerApplyError::MissingDurableIntent)?;
    let request = ReferenceApplyRequestV1::decode(intent.signed_request())?;
    let durable = prepared_from_snapshot(snapshot, request, true)?;
    if durable.request.canonical_wire() != prepared.request.canonical_wire()
        || durable.channel_auth_fingerprint != prepared.channel_auth_fingerprint
        || durable.runtime_response_expectation != prepared.runtime_response_expectation
    {
        return Err(ControllerApplyError::PreparedAttemptMismatch);
    }
    Ok(durable)
}

fn terminal_completion_from_snapshot(
    snapshot: &ControllerJournalSnapshot,
    replayed_from_journal: bool,
) -> Result<ControllerAppliedReferenceV1, ControllerApplyError> {
    if !snapshot.state().current_apply_is_terminal() {
        return Err(ControllerApplyError::StoredRequestMismatch);
    }
    Ok(ControllerAppliedReferenceV1 {
        controller_store_instance_id: *snapshot.store_instance_id(),
        controller_snapshot_sequence: snapshot.snapshot_sequence(),
        terminal_receipt: snapshot.state().current_direct_terminal_receipt().cloned(),
        replayed_from_journal,
    })
}

const fn bytes_are_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

/// Fail-closed preparation failures.  A store error returns no send token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerApplyError {
    Journal(ControllerJournalError),
    Store(ControllerStoreError),
    ControlContract(ReferenceControlError),
    ApplyContract(ApplyContractError),
    TemporalContract(TemporalContractError),
    Authentication(ApplyAuthError),
    OwnerIdentityMismatch,
    InvalidControllerIdentity,
    InvalidFreshIdentity,
    MissingCommittedPlan,
    MissingTargetBinding,
    MissingCommittedTenureProof,
    InvalidTenureProvisioning,
    MissingDurableIntent,
    InvalidCommittedPlanShape,
    BootstrapBindingMismatch,
    UnsupportedRequestAuthProfile,
    ControllerSigningKeyMismatch,
    StoredRequestMismatch,
    PreparedAttemptMismatch,
}

/// Fail-closed outcome of one direct PXAR/PXRT orchestration attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerReferenceApplyError {
    Controller(ControllerApplyError),
    Store(ControllerStoreError),
    Exchange(RuntimeApplyExchangeError),
    ValidatedReceiptMismatch,
    VerifiedReceiptPersistence {
        receipt_digest: paraegox_kernel::digest::Digest32,
        store: ControllerStoreError,
    },
}

impl fmt::Display for ControllerReferenceApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller reference apply failed: {self:?}")
    }
}

impl std::error::Error for ControllerReferenceApplyError {}

impl From<ControllerApplyError> for ControllerReferenceApplyError {
    fn from(value: ControllerApplyError) -> Self {
        Self::Controller(value)
    }
}

impl From<ControllerStoreError> for ControllerReferenceApplyError {
    fn from(value: ControllerStoreError) -> Self {
        Self::Store(value)
    }
}

impl From<ControllerJournalError> for ControllerApplyError {
    fn from(value: ControllerJournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<ControllerStoreError> for ControllerApplyError {
    fn from(value: ControllerStoreError) -> Self {
        Self::Store(value)
    }
}

impl From<ReferenceControlError> for ControllerApplyError {
    fn from(value: ReferenceControlError) -> Self {
        Self::ControlContract(value)
    }
}

impl From<ApplyContractError> for ControllerApplyError {
    fn from(value: ApplyContractError) -> Self {
        Self::ApplyContract(value)
    }
}

impl From<TemporalContractError> for ControllerApplyError {
    fn from(value: TemporalContractError) -> Self {
        Self::TemporalContract(value)
    }
}

impl From<ApplyAuthError> for ControllerApplyError {
    fn from(value: ApplyAuthError) -> Self {
        Self::Authentication(value)
    }
}

impl fmt::Display for ControllerApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller apply preparation failed: {self:?}")
    }
}

impl std::error::Error for ControllerApplyError {}

#[cfg(test)]
pub(crate) fn prepare_reference_apply_v1_with_test_commit<Commit>(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    controller_signer: &SigningKey,
    provisioning: &ControllerApplyProvisioningV1,
    fresh: FreshControllerApplyRequestV1,
    commit: Commit,
) -> Result<PreparedControllerApplyAttemptV1, ControllerApplyError>
where
    Commit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
{
    prepare_reference_apply_v1_with_commit(
        store,
        expected_owner,
        controller_signer,
        provisioning,
        fresh,
        commit,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future::Future;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::apply::{
        PlanWriterEpoch, PlanWriterRef, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
        TenureProofAuthority, WriterTenureClaim, WriterTenureProof, WriterTenureSigningTranscript,
    };
    use paraegox_runtime_contracts::execution::{CardDefinitionRef, CardImplementationRef};
    use paraegox_runtime_contracts::installation::{
        InstalledRuntimeArtifactObservationV1, RuntimeCompiledInstallationFactsV1,
        generate_build_descriptor, generate_manifest,
    };
    use paraegox_runtime_contracts::provenance::SourceScopeRef;
    use paraegox_runtime_contracts::reference_control::{
        MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES, ReferenceAdmissionPolicyInputV1,
        ReferenceApplyTerminalFactsV1, ReferenceApplyTerminalHeadV1,
        ReferenceApplyTerminalLifecycleEffectV1, ReferenceApplyTerminalOutcomeV1,
        ReferenceApplyTerminalReceiptAuthClaimV1, ReferenceApplyTerminalReceiptDraftV1,
        ReferenceApplyTerminalReceiptV1, ReferenceBootstrapCompatibilityV1,
        ReferenceBootstrapFactsV1, ReferenceBootstrapRequestDraftV1, ReferenceBootstrapRequestIdV1,
        ReferenceBootstrapResponseAuthClaimV1, ReferenceBootstrapResponseDraftV1,
        ReferenceBootstrapServingIdentityV1, ReferenceBootstrapStateV1, ReferenceChannelBindingV1,
        ed25519_control_key_fingerprint, reference_admission_policy_fingerprint_v1,
    };
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim,
    };
    use tokio::runtime::Builder as RuntimeBuilder;

    use crate::controller_journal::{
        ControllerAuthKeyFingerprint, ControllerBootstrapResponseDigest,
        ControllerChannelAuthFingerprint, ControllerJournalError, ControllerJournalSnapshot,
        ControllerJournalState, ControllerOperationId, ControllerOwnerIdentityFingerprint,
        ControllerRequestAuthPin, ControllerRuntimeResponseAuthPin, ControllerTargetBinding,
        ControllerTargetBindingInput, ControllerTenureAuthorityDomainFingerprint,
        controller_test_manifest,
    };
    use crate::controller_store::{
        ControllerCommitFailpoint, ControllerFilesystemPolicy, ControllerStore,
        create_and_lock_controller_initializer_lock, ensure_fresh_controller_directory,
        open_controller_directory, publish_initial_controller_snapshot,
    };
    use crate::plan::{DeploymentId, DeploymentScopeId, DeploymentWriterRef};
    use crate::planner::{StableAllocationSnapshot, journal_test_candidate};
    use crate::runtime_control_client::{
        RuntimeApplyClientFailure, RuntimeApplyExchangeError, ValidatedRuntimeApplyTerminalReceipt,
    };
    use crate::tenure_protocol::{
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        AcquireTenureResponseV1, ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };

    use super::{
        ControllerApplyProvisioningV1, ControllerReferenceApplyError,
        FreshControllerApplyRequestV1, apply_reference_once_v1_with, prepare_reference_apply_v1,
        prepare_reference_apply_v1_with_test_commit, replay_prepared_reference_apply_v1,
    };

    const TARGET: RuntimeHostId = RuntimeHostId::from_bytes([0x31; 16]);
    const SCOPE: DeploymentScopeId = DeploymentScopeId::from_bytes([0x32; 16]);
    const PLAN: DeploymentId = DeploymentId::from_bytes([0x33; 16]);
    const WRITER: DeploymentWriterRef = DeploymentWriterRef::from_bytes([0x34; 16]);
    const SUCCESSOR_WRITER: DeploymentWriterRef = DeploymentWriterRef::from_bytes([0x55; 16]);
    const CONTROLLER_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x35; 16]);
    const RUNTIME_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x36; 16]);
    const AUTHORITY_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0x50; 16]);
    const AUTHORITY_UID: u32 = 3_001;
    const AUTHORITY_GID: u32 = 3_002;
    const TENURE_AUTHORITY_REF: TenureAuthorityRef = TenureAuthorityRef::from_bytes([0x49; 16]);
    const TENURE_KEY_REF: TenureKeyRef = TenureKeyRef::from_bytes([0x4a; 16]);
    const CONTROLLER_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x37; 16]);
    const RUNTIME_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x38; 16]);
    const STORE_ID: [u8; 32] = [0x39; 32];
    const RUNTIME_STORE_ID: [u8; 32] = [0x3a; 32];
    const CONTROLLER_SEED: [u8; 32] = [0x3b; 32];
    const AUTHORITY_SEED: [u8; 32] = [0x3c; 32];
    const RUNTIME_SEED: [u8; 32] = [0x3d; 32];
    const CLOCK_DOMAIN: ClockDomainRef = ClockDomainRef::from_bytes([0x3e; 16]);
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn run_async<F: Future>(future: F) -> F::Output {
        RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().canonicalize().expect("temp root");
            let path = root.join(format!(
                "paraegox-controller-apply-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create fixture directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("chmod fixture directory");
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

    fn owner() -> ControllerOwnerIdentityFingerprint {
        ControllerOwnerIdentityFingerprint::from_stored(Digest32::from_bytes([0x40; 32]))
    }

    fn fresh(marker: u8) -> FreshControllerApplyRequestV1 {
        FreshControllerApplyRequestV1::try_new(
            [marker; 16],
            [marker.wrapping_add(1); 16],
            [marker.wrapping_add(2); 32],
        )
        .expect("fresh apply identities")
    }

    fn installation() -> (
        paraegox_runtime_contracts::installation::VerifiedRuntimeInstallationV1,
        RuntimeCompiledInstallationFactsV1,
    ) {
        let artifact = InstalledRuntimeArtifactObservationV1::try_new(
            1_048_576,
            Digest32::from_bytes([0x22; 32]),
            "aarch64-unknown-linux-gnu",
        )
        .expect("artifact facts");
        let compiled = RuntimeCompiledInstallationFactsV1::try_new(
            [0x11; 32],
            CardDefinitionRef::from_bytes([0xa1; 16]),
            CardImplementationRef::from_bytes([0xa2; 16]),
            [0xa3; 16],
            Digest32::from_bytes([0xa4; 32]),
            Digest32::from_bytes([0xa5; 32]),
        )
        .expect("compiled facts");
        let descriptor = generate_build_descriptor(&artifact, compiled).expect("descriptor");
        let installation = generate_manifest(
            descriptor.canonical_wire(),
            descriptor.descriptor_digest(),
            TARGET,
            &artifact,
            compiled,
        )
        .expect("installation");
        (installation, compiled)
    }

    fn bootstrap_channel() -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            Digest32::from_bytes([0x44; 32]),
            Digest32::from_bytes([0x45; 32]),
        )
        .expect("Runtime channel")
    }

    fn restarted_channel() -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            TARGET,
            RUNTIME_PRINCIPAL,
            Digest32::from_bytes([0x54; 32]),
            Digest32::from_bytes([0x55; 32]),
        )
        .expect("restarted Runtime channel")
    }

    fn bootstrap_response()
    -> paraegox_runtime_contracts::reference_control::ReferenceBootstrapResponseV1 {
        bootstrap_response_for(2, bootstrap_channel())
    }

    fn bootstrap_response_for(
        runtime_host_epoch: u64,
        channel: ReferenceChannelBindingV1,
    ) -> paraegox_runtime_contracts::reference_control::ReferenceBootstrapResponseV1 {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let runtime = SigningKey::from_bytes(&RUNTIME_SEED);
        let request_claim = ApplyRequestAuthClaim::try_new(
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
            &[0x41; 32],
        )
        .expect("bootstrap request claim");
        let request_draft = ReferenceBootstrapRequestDraftV1::try_new(
            ReferenceBootstrapRequestIdV1::from_bytes([0x42; 16]),
            TARGET,
            SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            request_claim,
            u32::try_from(MAX_REFERENCE_BOOTSTRAP_RESPONSE_BYTES).expect("response bound"),
        )
        .expect("bootstrap request draft");
        let request_signature = controller.sign(
            request_draft
                .signing_transcript()
                .expect("request transcript")
                .as_bytes(),
        );
        let request = request_draft
            .finalize(&request_signature.to_bytes())
            .expect("bootstrap request");

        let (installation, compiled) = installation();
        let authority = SigningKey::from_bytes(&AUTHORITY_SEED);
        let policy = reference_admission_policy_fingerprint_v1(ReferenceAdmissionPolicyInputV1 {
            target: TARGET,
            source_scope: SourceScopeRef::from_bytes(*SCOPE.as_bytes()),
            writer: paraegox_runtime_contracts::apply::PlanWriterRef::from_bytes(
                *WRITER.as_bytes(),
            ),
            controller_principal: CONTROLLER_PRINCIPAL,
            controller_key_ref: CONTROLLER_KEY_REF,
            controller_public_key: controller.verifying_key().as_bytes(),
            authority_principal: AUTHORITY_PRINCIPAL,
            authority_uid: AUTHORITY_UID,
            authority_gid: AUTHORITY_GID,
            tenure_authority_ref: TENURE_AUTHORITY_REF,
            tenure_key_ref: TENURE_KEY_REF,
            tenure_public_key: authority.verifying_key().as_bytes(),
        })
        .expect("admission policy");
        let compatibility = ReferenceBootstrapCompatibilityV1::try_from_verified_installation(
            &installation,
            compiled,
            policy.digest(),
        )
        .expect("bootstrap compatibility");
        let serving = ReferenceBootstrapServingIdentityV1::try_new(
            TARGET,
            RUNTIME_STORE_ID,
            11,
            runtime_host_epoch,
            CLOCK_DOMAIN,
            ClockGeneration::try_new(3).expect("clock generation"),
        )
        .expect("serving identity");
        let facts = ReferenceBootstrapFactsV1::try_new(
            serving,
            &compatibility,
            ReferenceBootstrapStateV1::ReadyForApply,
            None,
        )
        .expect("bootstrap facts");
        let response_claim = ReferenceBootstrapResponseAuthClaimV1::try_new(
            channel,
            RUNTIME_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
        )
        .expect("response claim");
        let response_draft =
            ReferenceBootstrapResponseDraftV1::try_new(&request, facts, channel, response_claim)
                .expect("response draft");
        let response_signature = runtime.sign(
            response_draft
                .signing_transcript()
                .expect("response transcript")
                .as_bytes(),
        );
        response_draft
            .finalize(&response_signature.to_bytes())
            .expect("bootstrap response")
    }

    fn tenure_request() -> crate::tenure_protocol::AcquireTenureRequestV1 {
        tenure_request_for(WRITER, [0x46; 16], &[0x48; 32])
    }

    fn tenure_request_for(
        writer: DeploymentWriterRef,
        operation: [u8; 16],
        nonce: &[u8],
    ) -> crate::tenure_protocol::AcquireTenureRequestV1 {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let fingerprint =
            ControllerPublicKeyFingerprint::for_ed25519_key(controller.verifying_key().as_bytes())
                .expect("Controller acquire key fingerprint");
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                SCOPE,
                writer,
                AcquireTenureOperationId::from_bytes(operation),
            ),
            CONTROLLER_PRINCIPAL,
            ControllerAcquireKeyRef::from_bytes([0x47; 16]),
            fingerprint,
            nonce,
            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES).expect("response bound"),
        )
        .expect("tenure request draft");
        let signature = controller.sign(
            draft
                .signing_transcript()
                .expect("tenure request transcript")
                .as_bytes(),
        );
        draft
            .finalize_ed25519(&signature.to_bytes())
            .expect("tenure request")
    }

    fn tenure_response(
        request: &crate::tenure_protocol::AcquireTenureRequestV1,
    ) -> AcquireTenureResponseV1 {
        tenure_response_for(request, 1, 0)
    }

    fn tenure_response_for(
        request: &crate::tenure_protocol::AcquireTenureRequestV1,
        epoch: u64,
        supersedes_through: u64,
    ) -> AcquireTenureResponseV1 {
        let authority = TenureProofAuthority::try_new(
            TENURE_AUTHORITY_REF,
            TENURE_KEY_REF,
            TenureProofAlgorithm::try_new(1).expect("proof algorithm"),
            1,
        )
        .expect("proof authority");
        let claim = WriterTenureClaim::try_new(
            request.proof_source_scope(),
            request.proof_writer(),
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(supersedes_through),
        )
        .expect("writer claim");
        let transcript =
            WriterTenureSigningTranscript::try_new(authority, claim, request.client_nonce())
                .expect("proof transcript");
        let signature = SigningKey::from_bytes(&AUTHORITY_SEED).sign(transcript.as_bytes());
        let proof = WriterTenureProof::try_new(
            authority,
            claim,
            request.client_nonce(),
            &signature.to_bytes(),
        )
        .expect("writer proof");
        AcquireTenureResponseV1::try_new(request, proof).expect("tenure response")
    }

    fn ready_snapshot() -> ControllerJournalSnapshot {
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let fingerprint = ed25519_control_key_fingerprint(controller.verifying_key().as_bytes())
            .expect("Controller key fingerprint");
        let request_auth = ControllerRequestAuthPin::try_new(
            CONTROLLER_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
            1,
            ControllerAuthKeyFingerprint::from_stored(fingerprint),
            1,
        )
        .expect("request auth pin");
        let allocation =
            StableAllocationSnapshot::try_new(TARGET, 0, 0, Vec::new()).expect("allocation");
        let state = ControllerJournalState::try_initialize(
            SCOPE,
            PLAN,
            allocation,
            controller_test_manifest(TARGET),
            request_auth,
        )
        .expect("initial state");
        let initial = ControllerJournalSnapshot::try_initialize(STORE_ID, owner(), state)
            .expect("initial snapshot");
        let candidate = journal_test_candidate(
            TARGET,
            initial.state().installed_manifest().projection(),
            initial.state().allocation(),
            Some([0x4b; 16]),
            0x4c,
        )
        .expect("plan candidate");
        let operation = ControllerOperationId::from_bytes([0x4d; 16]);
        let prepared_plan = initial
            .try_successor(
                initial
                    .state()
                    .prepare_plan_candidate(operation, &candidate)
                    .expect("prepare plan"),
            )
            .expect("prepared-plan successor");
        let committed_plan = prepared_plan
            .try_successor(
                prepared_plan
                    .state()
                    .commit_plan_candidate(operation, &candidate)
                    .expect("commit plan"),
            )
            .expect("committed-plan successor");

        let request = tenure_request();
        let prepared_tenure = committed_plan
            .try_successor(
                committed_plan
                    .state()
                    .prepare_tenure_acquisition(
                        &request,
                        ControllerTenureAuthorityDomainFingerprint::from_stored(
                            Digest32::from_bytes([0xa5; 32]),
                        ),
                    )
                    .expect("prepare tenure"),
            )
            .expect("prepared-tenure successor");
        let response = tenure_response(&request);
        let committed_tenure = prepared_tenure
            .try_successor(
                prepared_tenure
                    .state()
                    .commit_tenure_response(&request, &response)
                    .expect("commit tenure"),
            )
            .expect("committed-tenure successor");

        let response = bootstrap_response();
        let binding = ControllerTargetBinding::try_new(ControllerTargetBindingInput {
            target: TARGET,
            runtime_store_instance_id: RUNTIME_STORE_ID,
            channel_auth_fingerprint: ControllerChannelAuthFingerprint::from_stored(
                Digest32::from_bytes([0x4e; 32]),
            ),
            manifest_digest: crate::planner::PlanManifestDigest::try_new(
                committed_tenure
                    .state()
                    .installed_manifest()
                    .manifest_digest(),
            )
            .expect("manifest digest"),
            first_runtime_host_epoch: 2,
            last_runtime_host_epoch: 2,
            bootstrap_response: response.canonical_wire(),
            bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(
                response.response_digest(),
            ),
            runtime_response_auth: ControllerRuntimeResponseAuthPin::try_from_bootstrap_response(
                &response,
                bootstrap_channel(),
            )
            .expect("Runtime response auth pin"),
        })
        .expect("target binding");
        committed_tenure
            .try_successor(
                committed_tenure
                    .state()
                    .record_target_binding(binding)
                    .expect("record binding"),
            )
            .expect("bound successor")
    }

    fn install_snapshot(snapshot: &ControllerJournalSnapshot, directory: &TestDirectory) {
        let handle = open_controller_directory(
            directory.path(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("open fixture directory");
        ensure_fresh_controller_directory(&handle).expect("fresh fixture directory");
        let _lock = create_and_lock_controller_initializer_lock(&handle).expect("initializer lock");
        publish_initial_controller_snapshot(
            &handle,
            &snapshot.encode().expect("snapshot bytes"),
            [0x4f; 16],
            ControllerCommitFailpoint::None,
        )
        .expect("publish snapshot");
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
        .expect("open fixture store")
    }

    fn provisioning(
        state: &ControllerJournalState,
        controller: &SigningKey,
    ) -> ControllerApplyProvisioningV1 {
        ControllerApplyProvisioningV1::try_from_controller_state(
            state,
            controller,
            CONTROLLER_PRINCIPAL,
            WRITER,
            AUTHORITY_PRINCIPAL,
            AUTHORITY_UID,
            AUTHORITY_GID,
            TENURE_AUTHORITY_REF,
            TENURE_KEY_REF,
            SigningKey::from_bytes(&AUTHORITY_SEED)
                .verifying_key()
                .to_bytes(),
        )
        .expect("sealed apply provisioning")
    }

    fn terminal_receipt(
        request: &paraegox_runtime_contracts::reference_control::ReferenceApplyRequestV1,
        outcome: ReferenceApplyTerminalOutcomeV1,
        lifecycle: ReferenceApplyTerminalLifecycleEffectV1,
        head: ReferenceApplyTerminalHeadV1,
    ) -> ReferenceApplyTerminalReceiptV1 {
        terminal_receipt_on_channel(request, outcome, lifecycle, head, bootstrap_channel())
    }

    fn terminal_receipt_on_channel(
        request: &paraegox_runtime_contracts::reference_control::ReferenceApplyRequestV1,
        outcome: ReferenceApplyTerminalOutcomeV1,
        lifecycle: ReferenceApplyTerminalLifecycleEffectV1,
        head: ReferenceApplyTerminalHeadV1,
        channel: ReferenceChannelBindingV1,
    ) -> ReferenceApplyTerminalReceiptV1 {
        let facts = ReferenceApplyTerminalFactsV1::try_new(
            request,
            outcome,
            lifecycle,
            head,
            Digest32::from_bytes([0xa1; 32]),
            Digest32::from_bytes([0xa2; 32]),
            2,
            20,
            ClockGeneration::try_new(3).expect("selection clock"),
            21_000,
        )
        .expect("terminal facts");
        let claim = ReferenceApplyTerminalReceiptAuthClaimV1::try_new(
            channel,
            RUNTIME_KEY_REF,
            ApplyAuthAlgorithm::try_new(1).expect("terminal algorithm"),
            1,
        )
        .expect("terminal auth claim");
        let draft = ReferenceApplyTerminalReceiptDraftV1::try_new(request, facts, channel, claim)
            .expect("terminal receipt draft");
        let runtime = SigningKey::from_bytes(&RUNTIME_SEED);
        let signature = runtime.sign(
            draft
                .signing_transcript()
                .expect("terminal transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("terminal receipt")
    }

    fn validated_terminal_receipt(
        receipt: ReferenceApplyTerminalReceiptV1,
        current_channel: ReferenceChannelBindingV1,
    ) -> ValidatedRuntimeApplyTerminalReceipt {
        ValidatedRuntimeApplyTerminalReceipt::try_from_contract_fixture(
            receipt,
            bootstrap_channel(),
            current_channel,
        )
        .expect("validated Runtime receipt fixture")
    }

    fn commit_terminal_receipt(
        store: &mut ControllerStore,
        receipt: &ReferenceApplyTerminalReceiptV1,
    ) {
        let before = store.snapshot().expect("store snapshot").clone();
        let state = before
            .state()
            .record_direct_terminal_receipt(receipt)
            .expect("record direct terminal receipt");
        store
            .commit(before.try_successor(state).expect("terminal successor"))
            .expect("commit direct terminal receipt");
    }

    fn commit_empty_plan(store: &mut ControllerStore, operation_marker: u8) {
        let before = store.snapshot().expect("store snapshot").clone();
        let candidate = journal_test_candidate(
            TARGET,
            before.state().installed_manifest().projection(),
            before.state().allocation(),
            None,
            operation_marker,
        )
        .expect("empty plan candidate");
        let operation = ControllerOperationId::from_bytes([operation_marker; 16]);
        let prepared_state = before
            .state()
            .prepare_plan_candidate(operation, &candidate)
            .expect("prepare empty plan");
        store
            .commit(
                before
                    .try_successor(prepared_state)
                    .expect("empty prepared successor"),
            )
            .expect("commit empty preparation");
        let prepared = store.snapshot().expect("prepared snapshot").clone();
        let committed_state = prepared
            .state()
            .commit_plan_candidate(operation, &candidate)
            .expect("commit empty plan state");
        store
            .commit(
                prepared
                    .try_successor(committed_state)
                    .expect("empty committed successor"),
            )
            .expect("commit empty plan");
    }

    #[test]
    fn exact_request_is_committed_before_exposure_and_replays_after_reopen() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        assert_eq!(
            replay_prepared_reference_apply_v1(&mut store, owner(), &controller, &provisioning,)
                .expect("fresh replay check"),
            None
        );
        let first = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0x51),
        )
        .expect("prepare first apply");
        assert!(!first.replayed_from_journal());
        assert_eq!(
            first.controller_snapshot_sequence(),
            ready.snapshot_sequence() + 1
        );
        let exact = first.canonical_request_bytes().to_vec();

        let replay = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0x61),
        )
        .expect("in-memory replay");
        assert!(replay.replayed_from_journal());
        assert_eq!(replay.canonical_request_bytes(), exact);
        assert_eq!(
            replay.controller_snapshot_sequence(),
            first.controller_snapshot_sequence()
        );
        let rotated_signer = SigningKey::from_bytes(&[0xee; 32]);
        let rotated_fingerprint =
            ed25519_control_key_fingerprint(rotated_signer.verifying_key().as_bytes())
                .expect("rotated Controller fingerprint");
        let rotated_auth = ControllerRequestAuthPin::try_new(
            ApplyAuthKeyRef::from_bytes([0xef; 16]),
            ApplyAuthAlgorithm::try_new(1).expect("rotated algorithm"),
            1,
            ControllerAuthKeyFingerprint::from_stored(rotated_fingerprint),
            2,
        )
        .expect("rotated auth pin");
        let before_rotation = store.snapshot().expect("before auth rotation").clone();
        let rotated_state = before_rotation
            .state()
            .rotate_request_auth(rotated_auth)
            .expect("rotate future request auth");
        store
            .commit(
                before_rotation
                    .try_successor(rotated_state)
                    .expect("auth rotation successor"),
            )
            .expect("commit auth rotation");
        let pinned_replay =
            replay_prepared_reference_apply_v1(&mut store, owner(), &controller, &provisioning)
                .expect("replay with request-time signer")
                .expect("durable request after rotation");
        assert_eq!(pinned_replay.canonical_request_bytes(), exact);
        assert_eq!(
            replay_prepared_reference_apply_v1(&mut store, owner(), &rotated_signer, &provisioning,),
            Err(super::ControllerApplyError::ControllerSigningKeyMismatch)
        );
        drop(store);

        let mut reopened = open_snapshot(&ready, &directory);
        let recovered =
            replay_prepared_reference_apply_v1(&mut reopened, owner(), &controller, &provisioning)
                .expect("reopened replay check")
                .expect("durable request must exist");
        assert!(recovered.replayed_from_journal());
        assert_eq!(recovered.canonical_request_bytes(), exact);

        assert_eq!(
            replay_prepared_reference_apply_v1(
                &mut reopened,
                owner(),
                &rotated_signer,
                &provisioning,
            ),
            Err(super::ControllerApplyError::ControllerSigningKeyMismatch)
        );
    }

    #[test]
    fn durable_replay_rejects_authority_admission_drift_without_journal_mutation() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let original_provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &original_provisioning,
            fresh(0x69),
        )
        .expect("prepare durable apply");
        let before = store.snapshot().expect("durable intent snapshot").clone();
        let before_bytes = before.encode().expect("durable intent bytes");
        let active_snapshot_path = directory
            .path()
            .join(crate::controller_store::CONTROLLER_ACTIVE_FILE_NAME);
        let before_disk = fs::read(&active_snapshot_path).expect("durable journal bytes");

        for (authority_principal, authority_uid) in [
            (PrincipalRef::from_bytes([0x51; 16]), AUTHORITY_UID),
            (AUTHORITY_PRINCIPAL, AUTHORITY_UID + 1),
        ] {
            let drifted = ControllerApplyProvisioningV1::try_from_controller_state(
                store.snapshot().expect("unchanged snapshot").state(),
                &controller,
                CONTROLLER_PRINCIPAL,
                WRITER,
                authority_principal,
                authority_uid,
                AUTHORITY_GID,
                TENURE_AUTHORITY_REF,
                TENURE_KEY_REF,
                SigningKey::from_bytes(&AUTHORITY_SEED)
                    .verifying_key()
                    .to_bytes(),
            )
            .expect("drifted facts still form a sealed provisioning candidate");
            assert_eq!(
                replay_prepared_reference_apply_v1(&mut store, owner(), &controller, &drifted,),
                Err(super::ControllerApplyError::BootstrapBindingMismatch)
            );
            let after = store.snapshot().expect("rejected replay snapshot");
            assert_eq!(after, &before);
            assert_eq!(after.encode().expect("rejected replay bytes"), before_bytes);
            assert_eq!(
                fs::read(&active_snapshot_path).expect("rejected journal bytes"),
                before_disk
            );
        }
    }

    #[test]
    fn later_global_writer_tenure_fences_old_writer_apply_replay() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let old_provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        let prepared = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &old_provisioning,
            fresh(0x6a),
        )
        .expect("writer A apply must become durable");
        let old_request = prepared.canonical_request_bytes().to_vec();

        let successor_request = tenure_request_for(SUCCESSOR_WRITER, [0x56; 16], &[0x57; 32]);
        let before_successor = store.snapshot().expect("before successor tenure").clone();
        let successor_prepared_state = before_successor
            .state()
            .prepare_tenure_acquisition(
                &successor_request,
                ControllerTenureAuthorityDomainFingerprint::from_stored(Digest32::from_bytes(
                    [0xa5; 32],
                )),
            )
            .expect("writer B tenure must prepare");
        store
            .commit(
                before_successor
                    .try_successor(successor_prepared_state)
                    .expect("writer B Prepared successor"),
            )
            .expect("commit writer B Prepared");
        let successor_response = tenure_response_for(&successor_request, 2, 1);
        let before_commit = store.snapshot().expect("before writer B commit").clone();
        let successor_committed_state = before_commit
            .state()
            .commit_tenure_response(&successor_request, &successor_response)
            .expect("writer B tenure must commit");
        store
            .commit(
                before_commit
                    .try_successor(successor_committed_state)
                    .expect("writer B Committed successor"),
            )
            .expect("commit writer B tenure");

        assert_eq!(
            store
                .snapshot()
                .expect("writer B snapshot")
                .state()
                .latest_committed_tenure_proof(PlanWriterRef::from_bytes(*WRITER.as_bytes())),
            None
        );
        assert_eq!(
            replay_prepared_reference_apply_v1(&mut store, owner(), &controller, &old_provisioning,),
            Err(super::ControllerApplyError::StoredRequestMismatch)
        );
        assert_eq!(
            store
                .snapshot()
                .expect("fenced replay must not mutate")
                .state()
                .current_signed_apply_intent()
                .expect("old durable intent remains for later reconciliation")
                .signed_request(),
            old_request
        );
        assert!(matches!(
            ControllerApplyProvisioningV1::try_from_controller_state(
                store.snapshot().expect("fenced state").state(),
                &controller,
                CONTROLLER_PRINCIPAL,
                WRITER,
                AUTHORITY_PRINCIPAL,
                AUTHORITY_UID,
                AUTHORITY_GID,
                TENURE_AUTHORITY_REF,
                TENURE_KEY_REF,
                SigningKey::from_bytes(&AUTHORITY_SEED)
                    .verifying_key()
                    .to_bytes(),
            ),
            Err(super::ControllerApplyError::MissingCommittedTenureProof)
        ));
    }

    #[test]
    fn uncertain_publish_returns_no_send_token_and_disk_truth_reopens() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        let result = prepare_reference_apply_v1_with_test_commit(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0x81),
            |store, next| {
                store.commit_with_test_failpoint(
                    next,
                    ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn,
                )
            },
        );
        assert!(
            result.is_err(),
            "ambiguous publish must expose no send token"
        );
        assert!(store.snapshot().is_err(), "ambiguous store must stop");
        drop(store);

        let mut reopened = open_snapshot(&ready, &directory);
        let recovered = prepare_reference_apply_v1(
            &mut reopened,
            owner(),
            &controller,
            &provisioning,
            fresh(0x91),
        )
        .expect("reopened exact request");
        assert!(recovered.replayed_from_journal());
    }

    #[test]
    fn direct_active_receipt_survives_reopen_and_drives_empty_exact_cas() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        let loop_attempt = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0xb1),
        )
        .expect("prepare Loop apply");
        let loop_digest = loop_attempt.request().target_slice_digest();
        let terminal = terminal_receipt(
            loop_attempt.request(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
        );
        commit_terminal_receipt(&mut store, &terminal);
        drop(store);

        let mut reopened = open_snapshot(&ready, &directory);
        commit_empty_plan(&mut reopened, 0xb5);
        assert_eq!(
            reopened
                .snapshot()
                .expect("empty committed snapshot")
                .state()
                .last_terminal_target_slice_digest(),
            Ok(Some(loop_digest))
        );
        let empty = prepare_reference_apply_v1(
            &mut reopened,
            owner(),
            &controller,
            &provisioning,
            fresh(0xb8),
        )
        .expect("prepare Empty apply");
        assert_eq!(
            empty.request().target_execution().mode(),
            paraegox_runtime_contracts::reference_control::ReferenceAssemblyModeV1::EmptyDeactivate
        );
        assert_eq!(
            empty
                .request()
                .control_commitment()
                .control()
                .expected_active(),
            paraegox_runtime_contracts::apply::ExpectedActive::Exact(loop_digest)
        );
    }

    #[test]
    fn no_effect_failure_receipt_never_promotes_failed_incoming_slice_to_cas() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        let loop_attempt = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0xc1),
        )
        .expect("prepare Loop apply");
        let failed_slice = loop_attempt.request().target_slice_digest();
        let terminal = terminal_receipt(
            loop_attempt.request(),
            ReferenceApplyTerminalOutcomeV1::StartTimedOutBeforeIntentNoEffects,
            ReferenceApplyTerminalLifecycleEffectV1::ProvenNotStarted,
            ReferenceApplyTerminalHeadV1::PreservedNone,
        );
        commit_terminal_receipt(&mut store, &terminal);
        let terminal_state = store.snapshot().expect("failed terminal snapshot");
        assert_eq!(
            terminal_state
                .state()
                .current_active_target_slice_digest_for_plan_advance(),
            Ok(None)
        );
        let candidate = journal_test_candidate(
            TARGET,
            terminal_state.state().installed_manifest().projection(),
            terminal_state.state().allocation(),
            None,
            0xc5,
        )
        .expect("failed apply empty candidate");
        let operation = ControllerOperationId::from_bytes([0xc5; 16]);
        let prepared = terminal_state
            .state()
            .prepare_plan_candidate(operation, &candidate)
            .expect("failed apply plan preparation remains durable");
        assert_eq!(
            prepared.commit_plan_candidate(operation, &candidate),
            Err(ControllerJournalError::NonTerminalRolloutBlocksPlanCommit),
            "a failure PXRT cannot promote slice {failed_slice:?} or advance the plan"
        );
    }

    #[test]
    fn old_terminal_receipt_remains_valid_after_new_runtime_bootstrap_and_reopen() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        let attempt = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0xd1),
        )
        .expect("prepare apply on original Runtime channel");
        let desired_head = attempt.request().target_slice_digest();
        let old_receipt = terminal_receipt(
            attempt.request(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
        );

        let restarted_channel = restarted_channel();
        let restarted_response = bootstrap_response_for(3, restarted_channel);
        let before_refresh = store.snapshot().expect("pre-refresh snapshot").clone();
        let old_binding = before_refresh
            .state()
            .target_binding()
            .expect("original binding");
        let refreshed_binding = ControllerTargetBinding::try_new(ControllerTargetBindingInput {
            target: TARGET,
            runtime_store_instance_id: RUNTIME_STORE_ID,
            channel_auth_fingerprint: old_binding.channel_auth_fingerprint(),
            manifest_digest: old_binding.manifest_digest(),
            first_runtime_host_epoch: old_binding.first_runtime_host_epoch(),
            last_runtime_host_epoch: 3,
            bootstrap_response: restarted_response.canonical_wire(),
            bootstrap_response_digest: ControllerBootstrapResponseDigest::from_stored(
                restarted_response.response_digest(),
            ),
            runtime_response_auth: ControllerRuntimeResponseAuthPin::try_from_bootstrap_response(
                &restarted_response,
                restarted_channel,
            )
            .expect("restarted Runtime auth pin"),
        })
        .expect("restarted Runtime binding");
        let refreshed_state = before_refresh
            .state()
            .record_target_binding(refreshed_binding)
            .expect("refresh Runtime binding while request is outstanding");
        store
            .commit(
                before_refresh
                    .try_successor(refreshed_state)
                    .expect("refresh successor"),
            )
            .expect("commit refreshed bootstrap");

        let refreshed = store.snapshot().expect("refreshed snapshot");
        assert_eq!(
            refreshed
                .state()
                .target_binding()
                .expect("current binding")
                .runtime_response_auth()
                .channel(TARGET)
                .expect("current channel"),
            restarted_channel
        );
        assert_eq!(
            refreshed
                .state()
                .current_signed_apply_intent()
                .expect("durable original intent")
                .runtime_response_auth()
                .channel(TARGET)
                .expect("original request channel"),
            bootstrap_channel()
        );
        let replay_after_refresh = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0xd4),
        )
        .expect("replay prepared attempt after Runtime refresh");
        assert!(replay_after_refresh.replayed_from_journal());
        assert_eq!(
            replay_after_refresh
                .runtime_response_expectation()
                .channel(),
            bootstrap_channel()
        );
        assert_eq!(
            replay_after_refresh.runtime_response_expectation().key(),
            RUNTIME_KEY_REF
        );
        assert_eq!(
            replay_after_refresh
                .runtime_response_expectation()
                .algorithm()
                .value(),
            1
        );
        assert_eq!(
            replay_after_refresh
                .runtime_response_expectation()
                .algorithm_version(),
            1
        );
        assert_eq!(
            replay_after_refresh.channel_auth_fingerprint(),
            attempt.channel_auth_fingerprint()
        );

        // Historical Runtime replay returns the original PXRT, signed for the
        // original request channel. It must not be checked against the newer
        // mutable bootstrap binding.
        commit_terminal_receipt(&mut store, &old_receipt);
        drop(store);
        let reopened = open_snapshot(&ready, &directory);
        let reopened_state = reopened.snapshot().expect("reopened terminal snapshot");
        assert_eq!(
            reopened_state.state().current_direct_terminal_receipt(),
            Some(&old_receipt),
            "the exact historical-channel PXRT remains valid audit evidence"
        );
        assert_eq!(
            reopened_state
                .state()
                .current_active_target_slice_digest_for_plan_advance(),
            Ok(None),
            "the newer Runtime epoch requires a fresh terminal query before plan advance"
        );
        assert_eq!(
            old_receipt.facts().desired_head_digest(),
            Some(desired_head)
        );
    }

    #[test]
    fn terminal_receipt_on_a_different_channel_is_rejected_without_state_change() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        let attempt = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0xe1),
        )
        .expect("prepare original apply");
        let wrong_channel_receipt = terminal_receipt_on_channel(
            attempt.request(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
            restarted_channel(),
        );
        let before = store.snapshot().expect("before rejection").clone();
        assert_eq!(
            before
                .state()
                .record_direct_terminal_receipt(&wrong_channel_receipt),
            Err(ControllerJournalError::InvalidDirectTerminalReceipt)
        );
        assert_eq!(store.snapshot().expect("unchanged store"), &before);

        let correct = terminal_receipt(
            attempt.request(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
        );
        commit_terminal_receipt(&mut store, &correct);
        drop(store);
        let mut reopened = open_snapshot(&ready, &directory);
        commit_empty_plan(&mut reopened, 0xe5);
        assert_eq!(
            reopened
                .snapshot()
                .expect("reopened correct receipt")
                .state()
                .last_terminal_target_slice_digest(),
            Ok(Some(attempt.request().target_slice_digest()))
        );
    }

    #[test]
    fn orchestration_commits_only_validated_receipt_and_never_resends_terminal_operation() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        let prepared = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0xf1),
        )
        .expect("prepare durable apply");
        let receipt = terminal_receipt(
            prepared.request(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
        );
        let validated = validated_terminal_receipt(receipt.clone(), bootstrap_channel());
        let expected_request = prepared.canonical_request_bytes().to_vec();
        let committed = run_async(apply_reference_once_v1_with(
            &mut store,
            &prepared,
            move |durable| async move {
                assert_eq!(durable.canonical_request_bytes(), expected_request);
                Ok(validated)
            },
            ControllerStore::commit,
        ))
        .expect("commit validated receipt");
        assert!(!committed.replayed_from_journal());
        assert_eq!(committed.terminal_receipt(), Some(&receipt));
        assert_eq!(
            committed.controller_store_instance_id(),
            prepared.controller_store_instance_id()
        );

        drop(store);
        let mut reopened = open_snapshot(&ready, &directory);
        let sends = AtomicU64::new(0);
        let replayed = run_async(apply_reference_once_v1_with(
            &mut reopened,
            &prepared,
            |_| {
                sends.fetch_add(1, Ordering::Relaxed);
                async {
                    Err(RuntimeApplyExchangeError::NotSent(
                        RuntimeApplyClientFailure::RequestTargetMismatch,
                    ))
                }
            },
            ControllerStore::commit,
        ))
        .expect("terminal journal replay");
        assert_eq!(sends.load(Ordering::Relaxed), 0);
        assert!(replayed.replayed_from_journal());
        assert_eq!(replayed.terminal_receipt(), Some(&receipt));
        assert_eq!(
            replayed.controller_snapshot_sequence(),
            reopened
                .snapshot()
                .expect("reopened terminal snapshot")
                .snapshot_sequence()
        );
    }

    #[test]
    fn orchestration_not_sent_and_uncertain_never_fabricate_or_commit_a_receipt() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        let prepared = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0x91),
        )
        .expect("prepare durable apply");
        let before = store.snapshot().expect("durable intent snapshot").clone();

        let not_sent =
            RuntimeApplyExchangeError::NotSent(RuntimeApplyClientFailure::RequestTargetMismatch);
        assert_eq!(
            run_async(apply_reference_once_v1_with(
                &mut store,
                &prepared,
                |_| async { Err(not_sent) },
                ControllerStore::commit,
            )),
            Err(ControllerReferenceApplyError::Exchange(not_sent))
        );
        assert_eq!(store.snapshot().expect("NotSent store unchanged"), &before);
        assert!(!before.state().current_apply_is_terminal());

        let uncertain =
            RuntimeApplyExchangeError::Uncertain(RuntimeApplyClientFailure::TruncatedResponse);
        assert_eq!(
            run_async(apply_reference_once_v1_with(
                &mut store,
                &prepared,
                |_| async { Err(uncertain) },
                ControllerStore::commit,
            )),
            Err(ControllerReferenceApplyError::Exchange(uncertain))
        );
        assert_eq!(
            store.snapshot().expect("Uncertain store unchanged"),
            &before
        );
        assert!(
            store
                .snapshot()
                .expect("intent remains replayable")
                .state()
                .current_direct_terminal_receipt()
                .is_none()
        );
    }

    #[test]
    fn orchestration_rejects_wrong_request_sealed_fixture_without_journal_mutation() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        let prepared = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0x81),
        )
        .expect("prepare durable apply");
        let unrelated_request = super::build_fresh_request(
            store.snapshot().expect("durable intent").state(),
            &controller,
            &provisioning,
            fresh(0x85),
        )
        .expect("unrelated valid PXAR fixture");
        assert_ne!(
            unrelated_request.envelope_request_digest(),
            prepared.request().envelope_request_digest()
        );
        let unrelated_receipt = terminal_receipt(
            &unrelated_request,
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
        );
        let wrong_sealed = validated_terminal_receipt(unrelated_receipt, bootstrap_channel());
        let before = store.snapshot().expect("before wrong receipt").clone();
        assert_eq!(
            run_async(apply_reference_once_v1_with(
                &mut store,
                &prepared,
                move |_| async move { Ok(wrong_sealed) },
                ControllerStore::commit,
            )),
            Err(ControllerReferenceApplyError::Controller(
                super::ControllerApplyError::Journal(
                    ControllerJournalError::InvalidDirectTerminalReceipt,
                ),
            ))
        );
        assert_eq!(
            store.snapshot().expect("wrong receipt no mutation"),
            &before
        );
        assert!(!before.state().current_apply_is_terminal());
    }

    #[test]
    fn verified_receipt_publish_uncertainty_reopens_terminal_and_suppresses_resend() {
        let ready = ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let mut store = open_snapshot(&ready, &directory);
        let controller = SigningKey::from_bytes(&CONTROLLER_SEED);
        let provisioning = provisioning(
            store.snapshot().expect("store snapshot").state(),
            &controller,
        );
        let prepared = prepare_reference_apply_v1(
            &mut store,
            owner(),
            &controller,
            &provisioning,
            fresh(0xa1),
        )
        .expect("prepare durable apply");
        let receipt = terminal_receipt(
            prepared.request(),
            ReferenceApplyTerminalOutcomeV1::OneSourceLoopActive,
            ReferenceApplyTerminalLifecycleEffectV1::MayHaveStarted,
            ReferenceApplyTerminalHeadV1::CommittedIncoming,
        );
        let receipt_digest = receipt.receipt_digest();
        let validated = validated_terminal_receipt(receipt.clone(), bootstrap_channel());
        let result = run_async(apply_reference_once_v1_with(
            &mut store,
            &prepared,
            move |_| async move { Ok(validated) },
            |store, next| {
                store.commit_with_test_failpoint(
                    next,
                    ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn,
                )
            },
        ));
        assert!(matches!(
            result,
            Err(
                ControllerReferenceApplyError::VerifiedReceiptPersistence {
                    receipt_digest: observed,
                    ..
                }
            ) if observed == receipt_digest
        ));
        assert!(store.snapshot().is_err(), "ambiguous store must stop");
        drop(store);

        let mut reopened = open_snapshot(&ready, &directory);
        let sends = AtomicU64::new(0);
        let replayed = run_async(apply_reference_once_v1_with(
            &mut reopened,
            &prepared,
            |_| {
                sends.fetch_add(1, Ordering::Relaxed);
                async {
                    Err(RuntimeApplyExchangeError::NotSent(
                        RuntimeApplyClientFailure::RequestTargetMismatch,
                    ))
                }
            },
            ControllerStore::commit,
        ))
        .expect("disk-durable receipt must replay");
        assert_eq!(sends.load(Ordering::Relaxed), 0);
        assert!(replayed.replayed_from_journal());
        assert_eq!(replayed.terminal_receipt(), Some(&receipt));
    }
}
