//! Controller owner facade for exact authenticated Runtime query evidence.
//!
//! A canonical PXQR is signed and committed before this module returns a value
//! that transport may send. The client performs at most one exchange. A
//! verified PXQS is then committed in its own Controller snapshot; this module
//! intentionally owns no rollout/reconcile decision and exposes no CLI path.

use core::fmt;
use std::future::Future;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use paraegox_kernel::identity::PrincipalRef;
use paraegox_runtime_contracts::provenance::SourceScopeRef;
use paraegox_runtime_contracts::reference_control::{
    MAX_REFERENCE_QUERY_RESPONSE_BYTES, ReferenceControlError, ReferenceQueryIdV1,
    ReferenceQueryRequestDraftV1, ReferenceQueryRequestV1, ReferenceQueryResponseV1,
    ReferenceQuerySelectorV1, ed25519_control_key_fingerprint,
};
use paraegox_runtime_contracts::wire::{ApplyAuthError, ApplyRequestAuthClaim};

use crate::controller_journal::{
    ControllerJournalError, ControllerJournalSnapshot, ControllerOwnerIdentityFingerprint,
    ControllerPreparedQuery, ControllerQueryClosureKind,
};
use crate::controller_store::{ControllerStore, ControllerStoreError};
use crate::runtime_control_client::{
    PreparedRuntimeQueryRequest, RuntimeControlClientConfigurationError, RuntimeQueryExchangeError,
    UnixRuntimeQueryClient, ValidatedRuntimeQueryResponse,
};

const ED25519_SIGNATURE_BYTES: usize = 64;

/// Fresh identities consumed only when no unresolved durable PXQR exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreshControllerQueryRequestV1 {
    query_id: [u8; 16],
    client_nonce: [u8; 32],
    bind_expected_request_digest: bool,
}

impl FreshControllerQueryRequestV1 {
    pub(crate) fn try_new(
        query_id: [u8; 16],
        client_nonce: [u8; 32],
        bind_expected_request_digest: bool,
    ) -> Result<Self, ControllerQueryError> {
        if bytes_are_zero(&query_id) || bytes_are_zero(&client_nonce) {
            return Err(ControllerQueryError::InvalidFreshIdentity);
        }
        Ok(Self {
            query_id,
            client_nonce,
            bind_expected_request_digest,
        })
    }
}

/// Protected Controller principal selected for the PXQR request-auth claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerQueryProvisioningV1 {
    controller_principal: PrincipalRef,
}

impl ControllerQueryProvisioningV1 {
    pub(crate) fn try_new(
        controller_principal: PrincipalRef,
    ) -> Result<Self, ControllerQueryError> {
        if bytes_are_zero(controller_principal.as_bytes()) {
            return Err(ControllerQueryError::InvalidProvisioning);
        }
        Ok(Self {
            controller_principal,
        })
    }
}

/// Resident, one-use authority to send one exact canonical PXQR.
///
/// This value is deliberately neither `Clone` nor reconstructible from the
/// journal. It exists only in the process that observed the request-only
/// snapshot commit succeed, and [`query_reference_once_v1`] consumes it.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PreparedControllerQueryAttemptV1 {
    controller_store_instance_id: [u8; 32],
    controller_snapshot_sequence: u64,
    runtime_request: PreparedRuntimeQueryRequest,
}

impl PreparedControllerQueryAttemptV1 {
    #[must_use]
    pub(crate) const fn controller_store_instance_id(&self) -> &[u8; 32] {
        &self.controller_store_instance_id
    }

    #[must_use]
    pub(crate) const fn controller_snapshot_sequence(&self) -> u64 {
        self.controller_snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ReferenceQueryRequestV1 {
        self.runtime_request.request()
    }

    #[must_use]
    pub(crate) fn canonical_request_bytes(&self) -> &[u8] {
        self.request().canonical_wire()
    }
}

/// Read-only recovery view. It proves what exact query evidence survived but
/// intentionally contains no Runtime transport request and grants no send
/// authority after restart or an uncertain request-only commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveredControllerQueryV1 {
    controller_store_instance_id: [u8; 32],
    controller_snapshot_sequence: u64,
    request: ReferenceQueryRequestV1,
    response: Option<ReferenceQueryResponseV1>,
    closure: Option<ControllerQueryClosureKind>,
}

impl RecoveredControllerQueryV1 {
    #[must_use]
    pub(crate) const fn controller_store_instance_id(&self) -> &[u8; 32] {
        &self.controller_store_instance_id
    }

    #[must_use]
    pub(crate) const fn controller_snapshot_sequence(&self) -> u64 {
        self.controller_snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &ReferenceQueryRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) const fn response(&self) -> Option<&ReferenceQueryResponseV1> {
        self.response.as_ref()
    }

    #[must_use]
    pub(crate) const fn closure(&self) -> Option<ControllerQueryClosureKind> {
        self.closure
    }
}

/// Exact PXQS after its response-only Controller snapshot is durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerQueriedRuntimeV1 {
    controller_store_instance_id: [u8; 32],
    controller_snapshot_sequence: u64,
    response: ReferenceQueryResponseV1,
    replayed_from_journal: bool,
}

impl ControllerQueriedRuntimeV1 {
    #[must_use]
    pub(crate) const fn controller_store_instance_id(&self) -> &[u8; 32] {
        &self.controller_store_instance_id
    }

    #[must_use]
    pub(crate) const fn controller_snapshot_sequence(&self) -> u64 {
        self.controller_snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn response(&self) -> &ReferenceQueryResponseV1 {
        &self.response
    }

    #[must_use]
    pub(crate) const fn replayed_from_journal(&self) -> bool {
        self.replayed_from_journal
    }
}

/// Signs and crash-safely commits one exact PXQR before returning the only
/// resident send authority. An unresolved prior request is uncertain and
/// cannot be transparently replayed with caller-supplied fresh entropy.
pub(crate) fn prepare_reference_query_v1(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    controller_signer: &SigningKey,
    provisioning: ControllerQueryProvisioningV1,
    fresh: FreshControllerQueryRequestV1,
) -> Result<PreparedControllerQueryAttemptV1, ControllerQueryError> {
    prepare_reference_query_v1_with_commit(
        store,
        expected_owner,
        controller_signer,
        provisioning,
        fresh,
        ControllerStore::commit,
    )
}

/// Recovers exact durable query evidence across restart without manufacturing
/// a Runtime send authority or allocating a replacement query id/nonce.
pub(crate) fn recover_reference_query_v1(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    request_time_verifying_key: &VerifyingKey,
    provisioning: ControllerQueryProvisioningV1,
) -> Result<Option<RecoveredControllerQueryV1>, ControllerQueryError> {
    let snapshot = store.snapshot()?.clone();
    validate_owner_context(&snapshot, expected_owner, provisioning)?;
    recovered_query_from_snapshot(&snapshot, request_time_verifying_key, provisioning)
}

/// Commits only the loss of resident send authority for one exact read-only
/// recovery view. This explicit restart boundary never allocates a fresh
/// identity and never returns a Runtime transport token.
pub(crate) fn close_recovered_reference_query_v1(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    recovered: &RecoveredControllerQueryV1,
    request_time_verifying_key: &VerifyingKey,
    provisioning: ControllerQueryProvisioningV1,
) -> Result<RecoveredControllerQueryV1, ControllerQueryError> {
    close_recovered_reference_query_v1_with_commit(
        store,
        expected_owner,
        recovered,
        request_time_verifying_key,
        provisioning,
        ControllerStore::commit,
    )
}

fn close_recovered_reference_query_v1_with_commit<Commit>(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    recovered: &RecoveredControllerQueryV1,
    request_time_verifying_key: &VerifyingKey,
    provisioning: ControllerQueryProvisioningV1,
    commit: Commit,
) -> Result<RecoveredControllerQueryV1, ControllerQueryError>
where
    Commit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
{
    let before = store.snapshot()?.clone();
    validate_owner_context(&before, expected_owner, provisioning)?;
    if recovered.controller_store_instance_id != *before.store_instance_id() {
        return Err(ControllerQueryError::RecoveredQueryEvidenceChanged);
    }
    let current = recovered_query_from_snapshot(&before, request_time_verifying_key, provisioning)?
        .ok_or(ControllerQueryError::RecoveredQueryEvidenceChanged)?;
    if current.request != recovered.request {
        return Err(ControllerQueryError::RecoveredQueryEvidenceChanged);
    }

    if current == *recovered {
        if current.response.is_none()
            && current.closure
                == Some(ControllerQueryClosureKind::ResidentAuthorityLostAfterRestart)
        {
            return Ok(current);
        }
        if current.response.is_some()
            || current.closure.is_some()
            || !before.state().current_query_is_open()
            || before.state().current_query_decision_is_terminal()
        {
            return Err(ControllerQueryError::RecoveredQueryEvidenceChanged);
        }
        let closed_state = before
            .state()
            .record_query_closure(ControllerQueryClosureKind::ResidentAuthorityLostAfterRestart)?;
        let next = before.try_successor(closed_state)?;
        commit(store, next)?;
        let committed = store.snapshot()?.clone();
        let closed =
            recovered_query_from_snapshot(&committed, request_time_verifying_key, provisioning)?
                .ok_or(ControllerQueryError::RecoveredQueryEvidenceChanged)?;
        if closed.controller_snapshot_sequence
            != recovered
                .controller_snapshot_sequence
                .checked_add(1)
                .ok_or(ControllerQueryError::RecoveredQueryEvidenceChanged)?
            || closed.request != recovered.request
            || closed.response.is_some()
            || closed.closure != Some(ControllerQueryClosureKind::ResidentAuthorityLostAfterRestart)
        {
            return Err(ControllerQueryError::ClosurePersistenceMismatch {
                expected: ControllerQueryClosureKind::ResidentAuthorityLostAfterRestart,
            });
        }
        return Ok(closed);
    }

    let expected_closed_sequence = recovered
        .controller_snapshot_sequence
        .checked_add(1)
        .ok_or(ControllerQueryError::RecoveredQueryEvidenceChanged)?;
    if recovered.response.is_none()
        && recovered.closure.is_none()
        && current.controller_snapshot_sequence == expected_closed_sequence
        && current.response.is_none()
        && current.closure == Some(ControllerQueryClosureKind::ResidentAuthorityLostAfterRestart)
    {
        return Ok(current);
    }
    Err(ControllerQueryError::RecoveredQueryEvidenceChanged)
}

fn recovered_query_from_snapshot(
    snapshot: &ControllerJournalSnapshot,
    request_time_verifying_key: &VerifyingKey,
    provisioning: ControllerQueryProvisioningV1,
) -> Result<Option<RecoveredControllerQueryV1>, ControllerQueryError> {
    let state = snapshot.state();
    if state.current_query_has_decision() {
        return Ok(None);
    }
    let Some(prepared) = state.current_prepared_query() else {
        return Ok(None);
    };
    let request = validate_durable_query(prepared, provisioning.controller_principal)?;
    validate_controller_verifying_key_pin(prepared.request_auth(), request_time_verifying_key)?;
    validate_request_signature(&request, request_time_verifying_key)?;
    Ok(Some(RecoveredControllerQueryV1 {
        controller_store_instance_id: *snapshot.store_instance_id(),
        controller_snapshot_sequence: snapshot.snapshot_sequence(),
        request,
        response: state
            .current_query_observation()
            .map(|observation| observation.response().clone()),
        closure: state.current_query_closure(),
    }))
}

/// Performs at most one Runtime exchange and commits only the client's sealed,
/// signature-first validated PXQS. It never commits a rollout decision.
pub(crate) async fn query_reference_once_v1(
    store: &mut ControllerStore,
    client: &UnixRuntimeQueryClient,
    prepared: PreparedControllerQueryAttemptV1,
) -> Result<ControllerQueriedRuntimeV1, ControllerReferenceQueryError> {
    query_reference_once_v1_with(
        store,
        prepared,
        |durable| async move { client.exchange(durable).await },
        ControllerStore::commit,
    )
    .await
}

pub(crate) async fn query_reference_once_v1_with<Exchange, ExchangeFuture, Commit>(
    store: &mut ControllerStore,
    prepared: PreparedControllerQueryAttemptV1,
    exchange: Exchange,
    commit: Commit,
) -> Result<ControllerQueriedRuntimeV1, ControllerReferenceQueryError>
where
    Exchange: FnOnce(PreparedRuntimeQueryRequest) -> ExchangeFuture,
    ExchangeFuture:
        Future<Output = Result<ValidatedRuntimeQueryResponse, RuntimeQueryExchangeError>>,
    Commit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
{
    let before = store.snapshot()?.clone();
    validate_resident_query_attempt(&before, &prepared)?;
    match exchange(prepared.runtime_request).await {
        Ok(validated) => commit_validated_query_response_with(store, &validated, commit),
        Err(error) => {
            let closure = closure_for_exchange_error(error);
            let closed_state = before.state().record_query_closure(closure)?;
            let next = before.try_successor(closed_state)?;
            if let Err(store_error) = commit(store, next) {
                return Err(ControllerReferenceQueryError::ExchangeClosurePersistence {
                    closure,
                    exchange: error,
                    store: store_error,
                });
            }
            let committed = store.snapshot()?;
            if committed.state().current_query_closure() != Some(closure)
                || committed.state().current_query_observation().is_some()
                || committed.state().current_query_has_decision()
            {
                return Err(ControllerReferenceQueryError::ClosurePersistenceMismatch {
                    expected: closure,
                });
            }
            Err(ControllerReferenceQueryError::Exchange(error))
        }
    }
}

const fn closure_for_exchange_error(
    error: RuntimeQueryExchangeError,
) -> ControllerQueryClosureKind {
    match error {
        RuntimeQueryExchangeError::NotSent(_) => ControllerQueryClosureKind::NotSent,
        RuntimeQueryExchangeError::Uncertain(_) => ControllerQueryClosureKind::DeliveryUncertain,
        RuntimeQueryExchangeError::Rejected(_) => ControllerQueryClosureKind::ResponseRejected,
    }
}

fn commit_validated_query_response_with<Commit>(
    store: &mut ControllerStore,
    validated: &ValidatedRuntimeQueryResponse,
    commit: Commit,
) -> Result<ControllerQueriedRuntimeV1, ControllerReferenceQueryError>
where
    Commit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
{
    let before = store.snapshot()?.clone();
    if before.state().current_query_observation().is_some() {
        return Ok(query_completion_from_snapshot(&before, true)?);
    }
    let durable = before
        .state()
        .current_prepared_query()
        .ok_or(ControllerQueryError::MissingDurableQuery)?;
    if validated.request_time_channel() != durable.request_time_channel()
        || validated.current_channel() != durable.request_time_channel()
        || validated.response().query_id() != durable.request().query_id()
        || validated.facts() != validated.response().facts()
    {
        let closure = ControllerQueryClosureKind::ResponseRejected;
        let closed_state = before.state().record_query_closure(closure)?;
        let next = before.try_successor(closed_state)?;
        if let Err(store_error) = commit(store, next) {
            return Err(
                ControllerReferenceQueryError::ResponseRejectionClosurePersistence {
                    store: store_error,
                },
            );
        }
        if store.snapshot()?.state().current_query_closure() != Some(closure) {
            return Err(ControllerReferenceQueryError::ClosurePersistenceMismatch {
                expected: closure,
            });
        }
        return Err(ControllerReferenceQueryError::ValidatedResponseMismatch);
    }
    let response = validated.response();
    let committed_state = before
        .state()
        .record_query_response(response, validated.current_channel())?;
    let next = before.try_successor(committed_state)?;
    if let Err(store_error) = commit(store, next) {
        return Err(ControllerReferenceQueryError::VerifiedResponsePersistence {
            response_digest: response.response_digest(),
            store: store_error,
        });
    }
    let committed = store.snapshot()?.clone();
    let completion = query_completion_from_snapshot(&committed, false)?;
    if completion.response() != response {
        return Err(ControllerReferenceQueryError::DurableResponseCompletionMismatch);
    }
    Ok(completion)
}

fn prepare_reference_query_v1_with_commit<Commit>(
    store: &mut ControllerStore,
    expected_owner: ControllerOwnerIdentityFingerprint,
    controller_signer: &SigningKey,
    provisioning: ControllerQueryProvisioningV1,
    fresh: FreshControllerQueryRequestV1,
    commit: Commit,
) -> Result<PreparedControllerQueryAttemptV1, ControllerQueryError>
where
    Commit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
{
    let before = store.snapshot()?.clone();
    validate_owner_context(&before, expected_owner, provisioning)?;
    if let Some(prepared) = before.state().current_prepared_query() {
        validate_durable_query(prepared, provisioning.controller_principal)?;
        if before.state().current_query_observation().is_some()
            && !before.state().current_query_has_decision()
        {
            return Err(ControllerQueryError::DurableQueryAwaitingDecision);
        }
        if before.state().current_query_is_open() {
            return Err(ControllerQueryError::UnresolvedQueryUncertain);
        }
    }
    validate_controller_signer(before.state(), controller_signer)?;
    let request = build_fresh_request(before.state(), controller_signer, provisioning, fresh)?;
    let next_state = before.state().prepare_query_request(&request)?;
    let next = before.try_successor(next_state)?;
    commit(store, next)?;

    let durable = store.snapshot()?.clone();
    let prepared = durable
        .state()
        .current_prepared_query()
        .ok_or(ControllerQueryError::MissingDurableQuery)?;
    let request = validate_durable_query(prepared, provisioning.controller_principal)?;
    validate_request_signature(&request, &controller_signer.verifying_key())?;
    resident_attempt_from_snapshot(&durable, request)
}

fn build_fresh_request(
    state: &crate::controller_journal::ControllerJournalState,
    controller_signer: &SigningKey,
    provisioning: ControllerQueryProvisioningV1,
    fresh: FreshControllerQueryRequestV1,
) -> Result<ReferenceQueryRequestV1, ControllerQueryError> {
    validate_controller_signer(state, controller_signer)?;
    let binding = state
        .target_binding()
        .ok_or(ControllerQueryError::MissingTargetBinding)?;
    let intent = state
        .current_signed_apply_intent()
        .ok_or(ControllerQueryError::MissingApplyIntent)?;
    let request_auth = state.request_auth();
    let selector = ReferenceQuerySelectorV1::try_new(
        ReferenceQueryIdV1::from_bytes(fresh.query_id),
        intent.target(),
        SourceScopeRef::from_bytes(*state.scope().as_bytes()),
        binding.runtime_store_instance_id(),
        intent.apply_operation(),
        fresh
            .bind_expected_request_digest
            .then_some(intent.request_digest().value()),
    )?;
    let claim = ApplyRequestAuthClaim::try_new(
        provisioning.controller_principal,
        request_auth.key(),
        request_auth.algorithm(),
        request_auth.algorithm_version(),
        &fresh.client_nonce,
    )?;
    let draft = ReferenceQueryRequestDraftV1::try_new(
        selector,
        claim,
        MAX_REFERENCE_QUERY_RESPONSE_BYTES as u32,
    )?;
    let transcript = draft.signing_transcript()?;
    let signature = controller_signer.sign(transcript.as_bytes());
    let request = draft.finalize(&signature.to_bytes())?;
    if ReferenceQueryRequestV1::decode(request.canonical_wire())? != request {
        return Err(ControllerQueryError::StoredRequestMismatch);
    }
    Ok(request)
}

fn validate_owner_context(
    snapshot: &ControllerJournalSnapshot,
    expected_owner: ControllerOwnerIdentityFingerprint,
    provisioning: ControllerQueryProvisioningV1,
) -> Result<(), ControllerQueryError> {
    if snapshot.owner_identity_fingerprint() != expected_owner {
        return Err(ControllerQueryError::OwnerIdentityMismatch);
    }
    if bytes_are_zero(provisioning.controller_principal.as_bytes()) {
        return Err(ControllerQueryError::InvalidProvisioning);
    }
    Ok(())
}

fn validate_controller_signer(
    state: &crate::controller_journal::ControllerJournalState,
    signer: &SigningKey,
) -> Result<(), ControllerQueryError> {
    validate_controller_signer_pin(state.request_auth(), signer)
}

fn validate_controller_signer_pin(
    request_auth: crate::controller_journal::ControllerRequestAuthPin,
    signer: &SigningKey,
) -> Result<(), ControllerQueryError> {
    let verifying_key = signer.verifying_key();
    validate_controller_verifying_key_pin(request_auth, &verifying_key)
}

fn validate_controller_verifying_key_pin(
    request_auth: crate::controller_journal::ControllerRequestAuthPin,
    verifying_key: &VerifyingKey,
) -> Result<(), ControllerQueryError> {
    if verifying_key.is_weak()
        || ed25519_control_key_fingerprint(verifying_key.as_bytes())?
            != request_auth.verification_key_fingerprint().value()
    {
        return Err(ControllerQueryError::ControllerSigningKeyMismatch);
    }
    Ok(())
}

fn validate_durable_query(
    prepared: &ControllerPreparedQuery,
    controller_principal: PrincipalRef,
) -> Result<ReferenceQueryRequestV1, ControllerQueryError> {
    let request = ReferenceQueryRequestV1::decode(prepared.request().canonical_wire())?;
    let claim = request.authentication().claim();
    let request_auth = prepared.request_auth();
    if request != *prepared.request()
        || request.canonical_wire().is_empty()
        || claim.principal() != controller_principal
        || claim.key() != request_auth.key()
        || claim.algorithm() != request_auth.algorithm()
        || claim.algorithm_version() != request_auth.algorithm_version()
        || request.authentication().signature().len() != ED25519_SIGNATURE_BYTES
        || request.target() != prepared.request_time_channel().target()
        || request.expected_runtime_store_instance_id()
            != prepared.serving_baseline().runtime_store_instance_id()
    {
        return Err(ControllerQueryError::StoredRequestMismatch);
    }
    Ok(request)
}

fn validate_request_signature(
    request: &ReferenceQueryRequestV1,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), ControllerQueryError> {
    let signature = Signature::from_slice(request.authentication().signature())
        .map_err(|_| ControllerQueryError::StoredRequestMismatch)?;
    let transcript = request.signing_transcript()?;
    verifying_key
        .verify_strict(transcript.as_bytes(), &signature)
        .map_err(|_| ControllerQueryError::StoredRequestMismatch)
}

fn resident_attempt_from_snapshot(
    snapshot: &ControllerJournalSnapshot,
    request: ReferenceQueryRequestV1,
) -> Result<PreparedControllerQueryAttemptV1, ControllerQueryError> {
    let prepared = snapshot
        .state()
        .current_prepared_query()
        .ok_or(ControllerQueryError::MissingDurableQuery)?;
    if request.canonical_wire() != prepared.request().canonical_wire() {
        return Err(ControllerQueryError::StoredRequestMismatch);
    }
    let runtime_auth = prepared.runtime_response_auth();
    let runtime_request = PreparedRuntimeQueryRequest::try_new(
        request,
        prepared.request_time_channel(),
        runtime_auth.key(),
        runtime_auth.algorithm(),
        runtime_auth.algorithm_version(),
        prepared.serving_baseline(),
    )?;
    Ok(PreparedControllerQueryAttemptV1 {
        controller_store_instance_id: *snapshot.store_instance_id(),
        controller_snapshot_sequence: snapshot.snapshot_sequence(),
        runtime_request,
    })
}

fn validate_resident_query_attempt(
    snapshot: &ControllerJournalSnapshot,
    prepared: &PreparedControllerQueryAttemptV1,
) -> Result<(), ControllerQueryError> {
    if prepared.controller_store_instance_id != *snapshot.store_instance_id()
        || prepared.controller_snapshot_sequence > snapshot.snapshot_sequence()
    {
        return Err(ControllerQueryError::PreparedAttemptMismatch);
    }
    let durable = snapshot
        .state()
        .current_prepared_query()
        .ok_or(ControllerQueryError::MissingDurableQuery)?;
    let runtime_auth = durable.runtime_response_auth();
    if prepared.runtime_request.request() != durable.request()
        || prepared.runtime_request.request_time_channel() != durable.request_time_channel()
        || prepared.runtime_request.response_key() != runtime_auth.key()
        || prepared.runtime_request.response_algorithm() != runtime_auth.algorithm()
        || prepared.runtime_request.response_algorithm_version() != runtime_auth.algorithm_version()
        || prepared.runtime_request.serving_baseline() != durable.serving_baseline()
    {
        return Err(ControllerQueryError::PreparedAttemptMismatch);
    }
    if !snapshot.state().current_query_is_open()
        || snapshot.state().current_query_decision_is_terminal()
    {
        return Err(ControllerQueryError::PreparedAttemptNoLongerOpen);
    }
    Ok(())
}

fn query_completion_from_snapshot(
    snapshot: &ControllerJournalSnapshot,
    replayed_from_journal: bool,
) -> Result<ControllerQueriedRuntimeV1, ControllerQueryError> {
    let observation = snapshot
        .state()
        .current_query_observation()
        .ok_or(ControllerQueryError::MissingDurableResponse)?;
    Ok(ControllerQueriedRuntimeV1 {
        controller_store_instance_id: *snapshot.store_instance_id(),
        controller_snapshot_sequence: snapshot.snapshot_sequence(),
        response: observation.response().clone(),
        replayed_from_journal,
    })
}

#[derive(Debug)]
pub(crate) enum ControllerQueryError {
    InvalidFreshIdentity,
    InvalidProvisioning,
    OwnerIdentityMismatch,
    ControllerSigningKeyMismatch,
    MissingTargetBinding,
    MissingApplyIntent,
    MissingDurableQuery,
    MissingDurableResponse,
    UnresolvedQueryUncertain,
    DurableQueryAwaitingDecision,
    RecoveredQueryEvidenceChanged,
    StoredRequestMismatch,
    PreparedAttemptMismatch,
    PreparedAttemptNoLongerOpen,
    ClosurePersistenceMismatch {
        expected: ControllerQueryClosureKind,
    },
    Journal(ControllerJournalError),
    Store(ControllerStoreError),
    ControlContract(ReferenceControlError),
    WireContract(ApplyAuthError),
    ClientConfiguration(RuntimeControlClientConfigurationError),
}

impl From<ControllerJournalError> for ControllerQueryError {
    fn from(value: ControllerJournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<ControllerStoreError> for ControllerQueryError {
    fn from(value: ControllerStoreError) -> Self {
        Self::Store(value)
    }
}

impl From<ReferenceControlError> for ControllerQueryError {
    fn from(value: ReferenceControlError) -> Self {
        Self::ControlContract(value)
    }
}

impl From<ApplyAuthError> for ControllerQueryError {
    fn from(value: ApplyAuthError) -> Self {
        Self::WireContract(value)
    }
}

impl From<RuntimeControlClientConfigurationError> for ControllerQueryError {
    fn from(value: RuntimeControlClientConfigurationError) -> Self {
        Self::ClientConfiguration(value)
    }
}

impl fmt::Display for ControllerQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller query rejected: {self:?}")
    }
}

impl std::error::Error for ControllerQueryError {}

#[derive(Debug)]
pub(crate) enum ControllerReferenceQueryError {
    Query(ControllerQueryError),
    Store(ControllerStoreError),
    Exchange(RuntimeQueryExchangeError),
    ExchangeClosurePersistence {
        closure: ControllerQueryClosureKind,
        exchange: RuntimeQueryExchangeError,
        store: ControllerStoreError,
    },
    ClosurePersistenceMismatch {
        expected: ControllerQueryClosureKind,
    },
    ResponseRejectionClosurePersistence {
        store: ControllerStoreError,
    },
    ValidatedResponseMismatch,
    DurableResponseCompletionMismatch,
    VerifiedResponsePersistence {
        response_digest: paraegox_kernel::digest::Digest32,
        store: ControllerStoreError,
    },
}

impl From<ControllerQueryError> for ControllerReferenceQueryError {
    fn from(value: ControllerQueryError) -> Self {
        Self::Query(value)
    }
}

impl From<ControllerStoreError> for ControllerReferenceQueryError {
    fn from(value: ControllerStoreError) -> Self {
        Self::Store(value)
    }
}

impl From<ControllerJournalError> for ControllerReferenceQueryError {
    fn from(value: ControllerJournalError) -> Self {
        Self::Query(ControllerQueryError::Journal(value))
    }
}

impl fmt::Display for ControllerReferenceQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller query orchestration failed: {self:?}")
    }
}

impl std::error::Error for ControllerReferenceQueryError {}

impl ControllerReferenceQueryError {
    /// Reports only failures whose exact no-response closure is already
    /// durable.  A one-shot reconciler may safely surface these as
    /// `Uncertain`; every persistence or post-commit ambiguity remains a hard
    /// fail-closed error.
    #[must_use]
    pub(crate) const fn has_durable_no_response_closure(&self) -> bool {
        matches!(self, Self::Exchange(_) | Self::ValidatedResponseMismatch)
    }
}

const fn bytes_are_zero(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::PrincipalRef;
    use paraegox_runtime_contracts::provenance::SourcePlanRevision;
    use paraegox_runtime_contracts::reference_control::{
        ReferenceQueryDesiredHeadV1, ReferenceQueryDesiredStateV1, ReferenceQueryFactsV1,
        ReferenceQueryIdV1, ReferenceQueryLiveFactsV1, ReferenceQueryLiveStateV1,
        ReferenceQueryOperationLookupV1, ReferenceQueryOperationStateV1,
        ReferenceQueryOwnerStateV1, ReferenceQueryResponseAuthClaimV1,
        ReferenceQueryResponseDraftV1, ReferenceQueryResponseV1, ed25519_control_key_fingerprint,
    };
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

    use crate::controller_journal::{
        ControllerAuthKeyFingerprint, ControllerJournalError, ControllerJournalSnapshot,
        ControllerQueryClosureKind, ControllerRequestAuthPin,
        tests::{canonical_empty_signed_snapshot, canonical_signed_snapshot, signed_snapshot},
    };
    use crate::controller_store::{
        ControllerCommitFailpoint, ControllerFilesystemPolicy, ControllerStore,
        create_and_lock_controller_initializer_lock, ensure_fresh_controller_directory,
        open_controller_directory, publish_initial_controller_snapshot,
    };
    use crate::runtime_control_client::{
        RuntimeQueryClientFailure, RuntimeQueryExchangeError, RuntimeQueryIoPhase,
        ValidatedRuntimeQueryResponse,
    };

    use super::{
        ControllerQueryError, ControllerQueryProvisioningV1, ControllerReferenceQueryError,
        FreshControllerQueryRequestV1, close_recovered_reference_query_v1,
        close_recovered_reference_query_v1_with_commit, prepare_reference_query_v1,
        prepare_reference_query_v1_with_commit, query_reference_once_v1_with,
        recover_reference_query_v1,
    };

    const CONTROLLER_SEED: [u8; 32] = [0xc1; 32];
    const RUNTIME_SEED: [u8; 32] = [0xc2; 32];
    const CONTROLLER_PRINCIPAL: PrincipalRef = PrincipalRef::from_bytes([0xc3; 16]);
    const CONTROLLER_KEY: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0xc4; 16]);
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|error| panic!("query fixture root failed: {error}"));
            let path = root.join(format!(
                "paraegox-controller-query-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("query fixture create failed: {error}"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("query fixture chmod failed: {error}"));
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

    pub(crate) fn query_ready_snapshot() -> ControllerJournalSnapshot {
        query_ready_from(canonical_signed_snapshot(0x67))
    }

    pub(crate) fn query_ready_empty_snapshot() -> ControllerJournalSnapshot {
        query_ready_from(canonical_empty_signed_snapshot(0x77))
    }

    pub(crate) fn invalid_query_ready_snapshot() -> ControllerJournalSnapshot {
        query_ready_from(signed_snapshot())
    }

    fn query_ready_from(signed: ControllerJournalSnapshot) -> ControllerJournalSnapshot {
        let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
        let fingerprint = ed25519_control_key_fingerprint(signer.verifying_key().as_bytes())
            .unwrap_or_else(|error| panic!("Controller fingerprint failed: {error}"));
        let auth = ControllerRequestAuthPin::try_new(
            CONTROLLER_KEY,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("Controller algorithm failed: {error}")),
            1,
            ControllerAuthKeyFingerprint::from_stored(fingerprint),
            2,
        )
        .unwrap_or_else(|error| panic!("Controller auth pin failed: {error}"));
        let state = signed
            .state()
            .rotate_request_auth(auth)
            .unwrap_or_else(|error| panic!("Controller auth rotation failed: {error}"));
        signed
            .try_successor(state)
            .unwrap_or_else(|error| panic!("query-ready successor failed: {error}"))
    }

    fn install_snapshot(snapshot: &ControllerJournalSnapshot, directory: &TestDirectory) {
        let handle = open_controller_directory(
            directory.path(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("open query fixture failed: {error}"));
        ensure_fresh_controller_directory(&handle)
            .unwrap_or_else(|error| panic!("fresh query fixture failed: {error}"));
        let lock = create_and_lock_controller_initializer_lock(&handle)
            .unwrap_or_else(|error| panic!("query initializer lock failed: {error}"));
        publish_initial_controller_snapshot(
            &handle,
            &snapshot
                .encode()
                .unwrap_or_else(|error| panic!("query fixture encode failed: {error}")),
            [0xc5; 16],
            ControllerCommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("query fixture publish failed: {error:?}"));
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
        .unwrap_or_else(|error| panic!("query fixture store open failed: {error}"))
    }

    fn fresh(marker: u8) -> FreshControllerQueryRequestV1 {
        FreshControllerQueryRequestV1::try_new([marker; 16], [marker.wrapping_add(1); 32], true)
            .unwrap_or_else(|error| panic!("fresh query identity failed: {error}"))
    }

    fn provisioning() -> ControllerQueryProvisioningV1 {
        ControllerQueryProvisioningV1::try_new(CONTROLLER_PRINCIPAL)
            .unwrap_or_else(|error| panic!("query provisioning failed: {error}"))
    }

    fn response_for_current_query(store: &ControllerStore) -> ReferenceQueryResponseV1 {
        let prepared = store
            .snapshot()
            .unwrap_or_else(|error| panic!("query snapshot failed: {error}"))
            .state()
            .current_prepared_query()
            .unwrap_or_else(|| panic!("durable query missing"));
        let request = prepared.request();
        let baseline = prepared.serving_baseline();
        let sequence = baseline.snapshot_sequence() + 1;
        let operation = ReferenceQueryOperationStateV1::try_new(
            ReferenceQueryOwnerStateV1::Operational,
            None,
            ReferenceQueryOperationLookupV1::Unknown,
        )
        .unwrap_or_else(|error| panic!("query operation facts failed: {error}"));
        let desired = ReferenceQueryDesiredStateV1::try_new(
            ReferenceQueryDesiredHeadV1::None,
            SourcePlanRevision::new(0),
        )
        .unwrap_or_else(|error| panic!("query desired facts failed: {error}"));
        let live = ReferenceQueryLiveFactsV1::try_new(
            ReferenceQueryLiveStateV1::ExactZero,
            0,
            sequence,
            Digest32::from_bytes([0xc6; 32]),
        )
        .unwrap_or_else(|error| panic!("query live facts failed: {error}"));
        let serving = paraegox_runtime_contracts::reference_control::ReferenceBootstrapServingIdentityV1::try_new(
            baseline.target(),
            baseline.runtime_store_instance_id(),
            sequence,
            baseline.runtime_host_epoch(),
            baseline.clock_domain(),
            baseline.clock_generation(),
        )
        .unwrap_or_else(|error| panic!("query serving facts failed: {error}"));
        let facts = ReferenceQueryFactsV1::try_new(serving, operation, desired, live)
            .unwrap_or_else(|error| panic!("query facts failed: {error}"));
        let auth = prepared.runtime_response_auth();
        let channel = prepared.request_time_channel();
        let claim = ReferenceQueryResponseAuthClaimV1::try_new(
            channel,
            auth.key(),
            auth.algorithm(),
            auth.algorithm_version(),
        )
        .unwrap_or_else(|error| panic!("query response claim failed: {error}"));
        let draft = ReferenceQueryResponseDraftV1::try_new(request, facts, channel, claim)
            .unwrap_or_else(|error| panic!("query response draft failed: {error}"));
        let signature = SigningKey::from_bytes(&RUNTIME_SEED).sign(
            draft
                .signing_transcript()
                .unwrap_or_else(|error| panic!("query response transcript failed: {error}"))
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .unwrap_or_else(|error| panic!("query response failed: {error}"))
    }

    fn validated_response(
        store: &ControllerStore,
        response: ReferenceQueryResponseV1,
    ) -> ValidatedRuntimeQueryResponse {
        let prepared = store
            .snapshot()
            .unwrap_or_else(|error| panic!("query snapshot failed: {error}"))
            .state()
            .current_prepared_query()
            .unwrap_or_else(|| panic!("durable query missing"));
        ValidatedRuntimeQueryResponse::try_from_contract_fixture(
            response,
            prepared.request(),
            prepared.request_time_channel(),
            prepared.request_time_channel(),
            prepared.serving_baseline(),
        )
        .unwrap_or_else(|error| panic!("validated query fixture failed: {error}"))
    }

    fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("query test runtime failed: {error}"))
            .block_on(future)
    }

    #[test]
    fn crash_after_request_commit_recovers_evidence_but_never_send_authority() {
        let ready = query_ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
        let request_time_verifying_key = signer.verifying_key();
        let mut store = open_snapshot(&ready, &directory);
        let resident = prepare_reference_query_v1(
            &mut store,
            ready.owner_identity_fingerprint(),
            &signer,
            provisioning(),
            fresh(0xd1),
        )
        .unwrap_or_else(|error| panic!("fresh query prepare failed: {error}"));
        let exact = resident.canonical_request_bytes().to_vec();
        let request_sequence = resident.controller_snapshot_sequence();
        assert_eq!(
            store
                .snapshot()
                .unwrap_or_else(|error| panic!("durable request snapshot failed: {error}"))
                .state()
                .current_prepared_query()
                .unwrap_or_else(|| panic!("durable query missing"))
                .request()
                .canonical_wire(),
            exact
        );
        let rotated_signer = SigningKey::from_bytes(&[0xe1; 32]);
        let rotated_fingerprint =
            ed25519_control_key_fingerprint(rotated_signer.verifying_key().as_bytes())
                .unwrap_or_else(|error| panic!("rotated Controller fingerprint failed: {error}"));
        let rotated_auth = ControllerRequestAuthPin::try_new(
            ApplyAuthKeyRef::from_bytes([0xe2; 16]),
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("rotated algorithm failed: {error}")),
            1,
            ControllerAuthKeyFingerprint::from_stored(rotated_fingerprint),
            3,
        )
        .unwrap_or_else(|error| panic!("rotated auth pin failed: {error}"));
        let before_rotation = store
            .snapshot()
            .unwrap_or_else(|error| panic!("before rotation snapshot failed: {error}"))
            .clone();
        let rotated_state = before_rotation
            .state()
            .rotate_request_auth(rotated_auth)
            .unwrap_or_else(|error| panic!("request auth rotation failed: {error}"));
        store
            .commit(
                before_rotation
                    .try_successor(rotated_state)
                    .unwrap_or_else(|error| panic!("request auth successor failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("request auth commit failed: {error}"));
        let recovery_sequence = store
            .snapshot()
            .unwrap_or_else(|error| panic!("rotated snapshot failed: {error}"))
            .snapshot_sequence();
        drop(resident);
        drop(store);
        drop(signer);

        let mut reopened = open_snapshot(&ready, &directory);
        let recovered = recover_reference_query_v1(
            &mut reopened,
            ready.owner_identity_fingerprint(),
            &request_time_verifying_key,
            provisioning(),
        )
        .unwrap_or_else(|error| panic!("query recovery failed: {error}"))
        .unwrap_or_else(|| panic!("request-only recovery missing"));
        assert_eq!(recovered.controller_snapshot_sequence(), recovery_sequence);
        assert!(recovered.controller_snapshot_sequence() > request_sequence);
        assert_eq!(recovered.request().canonical_wire(), exact);
        assert_eq!(recovered.response(), None);
        assert_eq!(recovered.closure(), None);
        let fresh_after_recovery = fresh(0xd3);
        assert!(matches!(
            prepare_reference_query_v1(
                &mut reopened,
                ready.owner_identity_fingerprint(),
                &rotated_signer,
                provisioning(),
                fresh_after_recovery,
            ),
            Err(ControllerQueryError::UnresolvedQueryUncertain)
        ));
        assert_eq!(
            reopened
                .snapshot()
                .unwrap_or_else(|error| panic!("read-only prepare rejection failed: {error}"))
                .snapshot_sequence(),
            recovery_sequence,
            "prepare must not infer that a restart occurred"
        );
        let closed = close_recovered_reference_query_v1(
            &mut reopened,
            ready.owner_identity_fingerprint(),
            &recovered,
            &request_time_verifying_key,
            provisioning(),
        )
        .unwrap_or_else(|error| panic!("recovered query closure failed: {error}"));
        assert_eq!(closed.controller_snapshot_sequence(), recovery_sequence + 1);
        assert_eq!(closed.request().canonical_wire(), exact);
        assert_eq!(
            closed.closure(),
            Some(ControllerQueryClosureKind::ResidentAuthorityLostAfterRestart)
        );
        assert_eq!(
            close_recovered_reference_query_v1(
                &mut reopened,
                ready.owner_identity_fingerprint(),
                &recovered,
                &request_time_verifying_key,
                provisioning(),
            )
            .unwrap_or_else(|error| panic!("exact closure replay failed: {error}")),
            closed,
            "the original open recovery view may idempotently observe its exact closure"
        );
        let next = prepare_reference_query_v1(
            &mut reopened,
            ready.owner_identity_fingerprint(),
            &rotated_signer,
            provisioning(),
            fresh_after_recovery,
        )
        .unwrap_or_else(|error| panic!("fresh prepare after recovery closure failed: {error}"));
        assert_ne!(next.canonical_request_bytes(), exact);
    }

    #[test]
    fn ambiguous_request_publish_returns_no_token_and_restart_stays_no_send() {
        let ready = query_ready_snapshot();
        let directory = TestDirectory::new();
        install_snapshot(&ready, &directory);
        let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
        let mut store = open_snapshot(&ready, &directory);
        let result = prepare_reference_query_v1_with_commit(
            &mut store,
            ready.owner_identity_fingerprint(),
            &signer,
            provisioning(),
            fresh(0xd5),
            |store, next| {
                store.commit_with_test_failpoint(
                    next,
                    ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn,
                )
            },
        );
        assert!(
            result.is_err(),
            "ambiguous commit must expose no send token"
        );
        assert!(store.snapshot().is_err(), "ambiguous store must stop");
        drop(store);

        let mut reopened = open_snapshot(&ready, &directory);
        let recovered = recover_reference_query_v1(
            &mut reopened,
            ready.owner_identity_fingerprint(),
            &signer.verifying_key(),
            provisioning(),
        )
        .unwrap_or_else(|error| panic!("ambiguous recovery failed: {error}"))
        .unwrap_or_else(|| panic!("ambiguous request evidence missing"));
        let closed = close_recovered_reference_query_v1(
            &mut reopened,
            ready.owner_identity_fingerprint(),
            &recovered,
            &signer.verifying_key(),
            provisioning(),
        )
        .unwrap_or_else(|error| panic!("ambiguous request closure failed: {error}"));
        assert_eq!(
            closed.closure(),
            Some(ControllerQueryClosureKind::ResidentAuthorityLostAfterRestart)
        );
        prepare_reference_query_v1(
            &mut reopened,
            ready.owner_identity_fingerprint(),
            &signer,
            provisioning(),
            fresh(0xd7),
        )
        .unwrap_or_else(|error| panic!("fresh prepare after ambiguous closure failed: {error}"));
    }

    #[test]
    fn recovered_close_is_exact_idempotent_and_commit_uncertainty_never_mints_a_token() {
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
            fresh(0xe1),
        )
        .unwrap_or_else(|error| panic!("recovery fixture prepare failed: {error}"));
        drop(resident);
        let recovered = recover_reference_query_v1(
            &mut store,
            ready.owner_identity_fingerprint(),
            &signer.verifying_key(),
            provisioning(),
        )
        .unwrap_or_else(|error| panic!("recovery fixture read failed: {error}"))
        .unwrap_or_else(|| panic!("recovery fixture evidence missing"));
        let result = close_recovered_reference_query_v1_with_commit(
            &mut store,
            ready.owner_identity_fingerprint(),
            &recovered,
            &signer.verifying_key(),
            provisioning(),
            |store, next| {
                store.commit_with_test_failpoint(
                    next,
                    ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn,
                )
            },
        );
        assert!(matches!(result, Err(ControllerQueryError::Store(_))));
        assert!(
            store.snapshot().is_err(),
            "uncertain commit must stop the handle"
        );
        drop(store);

        let mut reopened = open_snapshot(&ready, &directory);
        let closed = recover_reference_query_v1(
            &mut reopened,
            ready.owner_identity_fingerprint(),
            &signer.verifying_key(),
            provisioning(),
        )
        .unwrap_or_else(|error| panic!("uncertain closure recovery failed: {error}"))
        .unwrap_or_else(|| panic!("uncertain closure evidence missing"));
        assert_eq!(
            closed.closure(),
            Some(ControllerQueryClosureKind::ResidentAuthorityLostAfterRestart)
        );
        assert_eq!(
            close_recovered_reference_query_v1(
                &mut reopened,
                ready.owner_identity_fingerprint(),
                &recovered,
                &signer.verifying_key(),
                provisioning(),
            )
            .unwrap_or_else(|error| panic!("uncertain closure replay failed: {error}")),
            closed
        );
    }

    #[test]
    fn recovered_close_rejects_stale_view_and_wrong_request_time_key_without_mutation() {
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
            fresh(0xe3),
        )
        .unwrap_or_else(|error| panic!("stale recovery fixture prepare failed: {error}"));
        drop(resident);
        let recovered = recover_reference_query_v1(
            &mut store,
            ready.owner_identity_fingerprint(),
            &signer.verifying_key(),
            provisioning(),
        )
        .unwrap_or_else(|error| panic!("stale recovery fixture read failed: {error}"))
        .unwrap_or_else(|| panic!("stale recovery fixture evidence missing"));
        let original_sequence = recovered.controller_snapshot_sequence();
        let mut stale = recovered.clone();
        stale.controller_snapshot_sequence = stale
            .controller_snapshot_sequence
            .checked_add(1)
            .unwrap_or_else(|| panic!("fixture sequence exhausted"));
        assert!(matches!(
            close_recovered_reference_query_v1(
                &mut store,
                ready.owner_identity_fingerprint(),
                &stale,
                &signer.verifying_key(),
                provisioning(),
            ),
            Err(ControllerQueryError::RecoveredQueryEvidenceChanged)
        ));
        let wrong_key = SigningKey::from_bytes(&[0xe4; 32]).verifying_key();
        assert!(matches!(
            close_recovered_reference_query_v1(
                &mut store,
                ready.owner_identity_fingerprint(),
                &recovered,
                &wrong_key,
                provisioning(),
            ),
            Err(ControllerQueryError::ControllerSigningKeyMismatch)
        ));
        let unchanged = store
            .snapshot()
            .unwrap_or_else(|error| panic!("unchanged recovery snapshot failed: {error}"));
        assert_eq!(unchanged.snapshot_sequence(), original_sequence);
        assert!(unchanged.state().current_query_is_open());
    }

    #[test]
    fn resident_token_survives_prepare_rejection_but_is_stale_after_explicit_close() {
        run_async(async {
            let ready = query_ready_snapshot();
            let live_directory = TestDirectory::new();
            install_snapshot(&ready, &live_directory);
            let signer = SigningKey::from_bytes(&CONTROLLER_SEED);
            let mut live_store = open_snapshot(&ready, &live_directory);
            let live_resident = prepare_reference_query_v1(
                &mut live_store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                fresh(0xe5),
            )
            .unwrap_or_else(|error| panic!("live token prepare failed: {error}"));
            assert!(matches!(
                prepare_reference_query_v1(
                    &mut live_store,
                    ready.owner_identity_fingerprint(),
                    &signer,
                    provisioning(),
                    fresh(0xe7),
                ),
                Err(ControllerQueryError::UnresolvedQueryUncertain)
            ));
            let response = response_for_current_query(&live_store);
            let validated = validated_response(&live_store, response);
            let sends = Cell::new(0_u32);
            query_reference_once_v1_with(
                &mut live_store,
                live_resident,
                |_| {
                    sends.set(sends.get() + 1);
                    async move { Ok(validated) }
                },
                ControllerStore::commit,
            )
            .await
            .unwrap_or_else(|error| panic!("live token exchange failed: {error}"));
            assert_eq!(sends.get(), 1);

            let stale_directory = TestDirectory::new();
            install_snapshot(&ready, &stale_directory);
            let mut stale_store = open_snapshot(&ready, &stale_directory);
            let stale_resident = prepare_reference_query_v1(
                &mut stale_store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                fresh(0xe9),
            )
            .unwrap_or_else(|error| panic!("stale token prepare failed: {error}"));
            let recovered = recover_reference_query_v1(
                &mut stale_store,
                ready.owner_identity_fingerprint(),
                &signer.verifying_key(),
                provisioning(),
            )
            .unwrap_or_else(|error| panic!("stale token recovery failed: {error}"))
            .unwrap_or_else(|| panic!("stale token evidence missing"));
            close_recovered_reference_query_v1(
                &mut stale_store,
                ready.owner_identity_fingerprint(),
                &recovered,
                &signer.verifying_key(),
                provisioning(),
            )
            .unwrap_or_else(|error| panic!("stale token closure failed: {error}"));
            let stale_sends = Cell::new(0_u32);
            let result = query_reference_once_v1_with(
                &mut stale_store,
                stale_resident,
                |_| {
                    stale_sends.set(stale_sends.get() + 1);
                    async {
                        Err(RuntimeQueryExchangeError::NotSent(
                            RuntimeQueryClientFailure::RequestBoundExceeded,
                        ))
                    }
                },
                ControllerStore::commit,
            )
            .await;
            assert!(matches!(
                result,
                Err(ControllerReferenceQueryError::Query(
                    ControllerQueryError::PreparedAttemptNoLongerOpen
                ))
            ));
            assert_eq!(stale_sends.get(), 0, "stale token must not reach transport");
        });
    }

    #[test]
    fn timeout_commits_delivery_uncertain_and_next_prepare_is_fresh_without_resend() {
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
                fresh(0xd9),
            )
            .unwrap_or_else(|error| panic!("timeout query prepare failed: {error}"));
            let sends = Cell::new(0_u32);
            let result = query_reference_once_v1_with(
                &mut store,
                resident,
                |_| {
                    sends.set(sends.get() + 1);
                    async {
                        Err(RuntimeQueryExchangeError::Uncertain(
                            RuntimeQueryClientFailure::DeadlineExceeded(
                                RuntimeQueryIoPhase::ReadResponseLength,
                            ),
                        ))
                    }
                },
                ControllerStore::commit,
            )
            .await;
            assert!(matches!(
                result,
                Err(ControllerReferenceQueryError::Exchange(
                    RuntimeQueryExchangeError::Uncertain(
                        RuntimeQueryClientFailure::DeadlineExceeded(
                            RuntimeQueryIoPhase::ReadResponseLength
                        )
                    )
                ))
            ));
            assert_eq!(sends.get(), 1);
            assert_eq!(
                store
                    .snapshot()
                    .unwrap_or_else(|error| panic!("closed snapshot failed: {error}"))
                    .state()
                    .current_query_closure(),
                Some(ControllerQueryClosureKind::DeliveryUncertain)
            );
            assert!(matches!(
                prepare_reference_query_v1(
                    &mut store,
                    ready.owner_identity_fingerprint(),
                    &signer,
                    provisioning(),
                    fresh(0xd9),
                ),
                Err(ControllerQueryError::Journal(
                    ControllerJournalError::QueryAlreadyClosed
                ))
            ));
            let next = prepare_reference_query_v1(
                &mut store,
                ready.owner_identity_fingerprint(),
                &signer,
                provisioning(),
                fresh(0xdb),
            )
            .unwrap_or_else(|error| panic!("fresh query after closure failed: {error}"));
            assert_ne!(
                next.request().query_id(),
                ReferenceQueryIdV1::from_bytes([0xd9; 16])
            );
            assert_eq!(sends.get(), 1, "retry path must not invoke transport");
        });
    }

    #[test]
    fn exchange_failure_classes_commit_distinct_exact_closures() {
        run_async(async {
            for (marker, exchange, expected_closure) in [
                (
                    0xf1,
                    RuntimeQueryExchangeError::NotSent(
                        RuntimeQueryClientFailure::RequestBoundExceeded,
                    ),
                    ControllerQueryClosureKind::NotSent,
                ),
                (
                    0xf3,
                    RuntimeQueryExchangeError::Rejected(
                        RuntimeQueryClientFailure::InvalidResponseSignature,
                    ),
                    ControllerQueryClosureKind::ResponseRejected,
                ),
            ] {
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
                    fresh(marker),
                )
                .unwrap_or_else(|error| panic!("classified query prepare failed: {error}"));
                let request_sequence = resident.controller_snapshot_sequence();
                let result = query_reference_once_v1_with(
                    &mut store,
                    resident,
                    move |_| async move { Err(exchange) },
                    ControllerStore::commit,
                )
                .await;
                assert!(matches!(
                    result,
                    Err(ControllerReferenceQueryError::Exchange(observed)) if observed == exchange
                ));
                let closed = store
                    .snapshot()
                    .unwrap_or_else(|error| panic!("classified closure snapshot failed: {error}"));
                assert_eq!(closed.snapshot_sequence(), request_sequence + 1);
                assert_eq!(
                    closed.state().current_query_closure(),
                    Some(expected_closure)
                );
                assert!(closed.state().current_query_observation().is_none());
                assert!(!closed.state().current_query_has_decision());
                let recovered = recover_reference_query_v1(
                    &mut store,
                    ready.owner_identity_fingerprint(),
                    &signer.verifying_key(),
                    provisioning(),
                )
                .unwrap_or_else(|error| panic!("classified closure recovery failed: {error}"))
                .unwrap_or_else(|| panic!("classified closure evidence missing"));
                assert_eq!(recovered.closure(), Some(expected_closure));
            }
        });
    }

    #[test]
    fn validated_response_commits_in_its_own_snapshot_before_any_decision() {
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
                fresh(0xdd),
            )
            .unwrap_or_else(|error| panic!("successful query prepare failed: {error}"));
            let request_sequence = resident.controller_snapshot_sequence();
            let response = response_for_current_query(&store);
            let validated = validated_response(&store, response.clone());
            let completion = query_reference_once_v1_with(
                &mut store,
                resident,
                move |_| async move { Ok(validated) },
                ControllerStore::commit,
            )
            .await
            .unwrap_or_else(|error| panic!("query response commit failed: {error}"));

            assert_eq!(
                completion.controller_snapshot_sequence(),
                request_sequence + 1
            );
            assert_eq!(completion.response(), &response);
            assert!(!completion.replayed_from_journal());
            let committed = store
                .snapshot()
                .unwrap_or_else(|error| panic!("response snapshot failed: {error}"));
            assert_eq!(committed.snapshot_sequence(), request_sequence + 1);
            assert_eq!(
                committed
                    .state()
                    .current_query_observation()
                    .unwrap_or_else(|| panic!("durable response missing"))
                    .response(),
                &response
            );
            assert!(!committed.state().current_query_has_decision());
            assert_eq!(committed.state().current_query_closure(), None);
            drop(store);

            let mut reopened = open_snapshot(&ready, &directory);
            let recovered = recover_reference_query_v1(
                &mut reopened,
                ready.owner_identity_fingerprint(),
                &signer.verifying_key(),
                provisioning(),
            )
            .unwrap_or_else(|error| panic!("response recovery failed: {error}"))
            .unwrap_or_else(|| panic!("response recovery missing"));
            assert_eq!(recovered.response(), Some(&response));
            assert_eq!(recovered.closure(), None);
            assert!(matches!(
                prepare_reference_query_v1(
                    &mut reopened,
                    ready.owner_identity_fingerprint(),
                    &signer,
                    provisioning(),
                    fresh(0xdf),
                ),
                Err(ControllerQueryError::DurableQueryAwaitingDecision)
            ));
        });
    }
}
