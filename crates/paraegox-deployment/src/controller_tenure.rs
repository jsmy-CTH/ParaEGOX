//! Crash-safe Controller orchestration for one canonical tenure acquisition.
//!
//! This owner-private layer only sequences the existing journal, store, and
//! Unix client owners. It allocates no identity, nonce, key, epoch, or proof,
//! and it never retries an exchange.

use core::fmt;
use std::future::Future;

use paraegox_runtime_contracts::apply::WriterTenureProof;

use crate::controller_journal::{
    ControllerJournalError, ControllerJournalSnapshot, ControllerTenureAuthorityDomainFingerprint,
    ControllerTenurePhase,
};
use crate::controller_store::{ControllerStore, ControllerStoreError};
use crate::tenure_client::{
    AcquireTenureExchangeError, PreparedAcquireTenureRequest, UnixTenureAuthorityClient,
};
use crate::tenure_protocol::{AcquireTenureResponseDigest, AcquireTenureResponseV1};

/// Successfully committed proof returned from the byte-exact journal value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerAcquiredTenure {
    proof: WriterTenureProof,
    replayed_from_journal: bool,
}

impl ControllerAcquiredTenure {
    #[must_use]
    pub(crate) const fn proof(&self) -> &WriterTenureProof {
        &self.proof
    }

    #[must_use]
    pub(crate) const fn replayed_from_journal(&self) -> bool {
        self.replayed_from_journal
    }
}

/// Fail-closed outcome of one Controller-owned acquisition attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerTenureError {
    Journal(ControllerJournalError),
    Store(ControllerStoreError),
    Exchange(AcquireTenureExchangeError),
    UncertainPersistence {
        exchange: AcquireTenureExchangeError,
        store: ControllerStoreError,
    },
    VerifiedResponsePersistence {
        response_digest: AcquireTenureResponseDigest,
        store: ControllerStoreError,
    },
}

impl fmt::Display for ControllerTenureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller tenure acquisition failed: {self:?}")
    }
}

impl std::error::Error for ControllerTenureError {}

impl From<ControllerJournalError> for ControllerTenureError {
    fn from(value: ControllerJournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<ControllerStoreError> for ControllerTenureError {
    fn from(value: ControllerStoreError) -> Self {
        Self::Store(value)
    }
}

/// Persists Prepared, reconstructs the identical request from the journal,
/// then performs exactly one Unix exchange.
pub(crate) async fn acquire_tenure_once(
    store: &mut ControllerStore,
    client: &UnixTenureAuthorityClient,
    prepared: &PreparedAcquireTenureRequest,
) -> Result<ControllerAcquiredTenure, ControllerTenureError> {
    let authority_domain_fingerprint = ControllerTenureAuthorityDomainFingerprint::from_stored(
        client.authority_domain_fingerprint(),
    );
    acquire_tenure_once_with(
        store,
        prepared,
        authority_domain_fingerprint,
        |durable| async move { client.exchange(&durable).await },
    )
    .await
}

async fn acquire_tenure_once_with<Exchange, ExchangeFuture>(
    store: &mut ControllerStore,
    prepared: &PreparedAcquireTenureRequest,
    authority_domain_fingerprint: ControllerTenureAuthorityDomainFingerprint,
    exchange: Exchange,
) -> Result<ControllerAcquiredTenure, ControllerTenureError>
where
    Exchange: FnOnce(PreparedAcquireTenureRequest) -> ExchangeFuture,
    ExchangeFuture: Future<Output = Result<AcquireTenureResponseV1, AcquireTenureExchangeError>>,
{
    let request = prepared.request();
    let before = store.snapshot()?.clone();
    let prepared_state = before
        .state()
        .prepare_tenure_acquisition(request, authority_domain_fingerprint)?;
    if prepared_state != *before.state() {
        store.commit(before.try_successor(prepared_state)?)?;
    }

    let operation_id = request.operation_id();
    let durable_transaction = store
        .snapshot()?
        .state()
        .tenure_transaction(operation_id)
        .ok_or(ControllerJournalError::MissingTenureTransaction)?;
    if durable_transaction.request().canonical_bytes() != request.canonical_bytes() {
        return Err(ControllerJournalError::TenureTransactionConflict.into());
    }
    if durable_transaction.authority_domain_fingerprint() != authority_domain_fingerprint {
        return Err(ControllerJournalError::TenureAuthorityDomainMismatch.into());
    }
    if let Some(proof) = durable_transaction.committed_proof() {
        return Ok(ControllerAcquiredTenure {
            proof: proof.clone(),
            replayed_from_journal: true,
        });
    }

    let durable = PreparedAcquireTenureRequest::try_from_canonical_request_bytes(
        durable_transaction.request().canonical_bytes(),
    )
    .map_err(ControllerJournalError::from)?;
    match exchange(durable).await {
        Ok(response) => commit_response(store, request, &response),
        Err(error @ AcquireTenureExchangeError::NotSent(_)) => {
            Err(ControllerTenureError::Exchange(error))
        }
        Err(error @ AcquireTenureExchangeError::Uncertain(_)) => {
            persist_uncertain(store, request, error)
        }
    }
}

fn persist_uncertain(
    store: &mut ControllerStore,
    request: &crate::tenure_protocol::AcquireTenureRequestV1,
    exchange: AcquireTenureExchangeError,
) -> Result<ControllerAcquiredTenure, ControllerTenureError> {
    let before = store.snapshot()?.clone();
    let uncertain_state = before.state().mark_tenure_uncertain(request)?;
    if uncertain_state != *before.state() {
        let next = before.try_successor(uncertain_state)?;
        if let Err(store_error) = store.commit(next) {
            return Err(ControllerTenureError::UncertainPersistence {
                exchange,
                store: store_error,
            });
        }
    }
    Err(ControllerTenureError::Exchange(exchange))
}

fn commit_response(
    store: &mut ControllerStore,
    request: &crate::tenure_protocol::AcquireTenureRequestV1,
    response: &AcquireTenureResponseV1,
) -> Result<ControllerAcquiredTenure, ControllerTenureError> {
    commit_response_with(store, request, response, ControllerStore::commit)
}

fn commit_response_with<Commit>(
    store: &mut ControllerStore,
    request: &crate::tenure_protocol::AcquireTenureRequestV1,
    response: &AcquireTenureResponseV1,
    commit: Commit,
) -> Result<ControllerAcquiredTenure, ControllerTenureError>
where
    Commit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
{
    let before = store.snapshot()?.clone();
    let committed_state = before.state().commit_tenure_response(request, response)?;
    if committed_state != *before.state() {
        let next = before.try_successor(committed_state)?;
        if let Err(store_error) = commit(store, next) {
            return Err(ControllerTenureError::VerifiedResponsePersistence {
                response_digest: response.response_digest(),
                store: store_error,
            });
        }
    }
    let transaction = store
        .snapshot()?
        .state()
        .tenure_transaction(request.operation_id())
        .ok_or(ControllerJournalError::MissingTenureTransaction)?;
    if transaction.phase() != ControllerTenurePhase::Committed {
        return Err(ControllerJournalError::InvalidTenureTransition.into());
    }
    let proof = transaction
        .committed_proof()
        .ok_or(ControllerJournalError::InvalidTenureTransaction)?
        .clone();
    Ok(ControllerAcquiredTenure {
        proof,
        replayed_from_journal: false,
    })
}

#[cfg(test)]
pub(crate) fn commit_verified_response_with_test_commit<Commit>(
    store: &mut ControllerStore,
    request: &crate::tenure_protocol::AcquireTenureRequestV1,
    response: &AcquireTenureResponseV1,
    commit: Commit,
) -> Result<ControllerAcquiredTenure, ControllerTenureError>
where
    Commit:
        FnOnce(&mut ControllerStore, ControllerJournalSnapshot) -> Result<(), ControllerStoreError>,
{
    commit_response_with(store, request, response, commit)
}

#[cfg(test)]
pub(crate) async fn acquire_tenure_once_with_test_exchange<Exchange, ExchangeFuture>(
    store: &mut ControllerStore,
    prepared: &PreparedAcquireTenureRequest,
    exchange: Exchange,
) -> Result<ControllerAcquiredTenure, ControllerTenureError>
where
    Exchange: FnOnce(PreparedAcquireTenureRequest) -> ExchangeFuture,
    ExchangeFuture: Future<Output = Result<AcquireTenureResponseV1, AcquireTenureExchangeError>>,
{
    acquire_tenure_once_with(
        store,
        prepared,
        ControllerTenureAuthorityDomainFingerprint::from_stored(
            paraegox_kernel::digest::Digest32::from_bytes([0xa5; 32]),
        ),
        exchange,
    )
    .await
}

/// Test-only selector for proving that a changed protected Authority domain is
/// rejected before the exchange closure receives a send token.
#[cfg(test)]
pub(crate) async fn acquire_tenure_once_with_test_domain<Exchange, ExchangeFuture>(
    store: &mut ControllerStore,
    prepared: &PreparedAcquireTenureRequest,
    authority_domain_fingerprint: ControllerTenureAuthorityDomainFingerprint,
    exchange: Exchange,
) -> Result<ControllerAcquiredTenure, ControllerTenureError>
where
    Exchange: FnOnce(PreparedAcquireTenureRequest) -> ExchangeFuture,
    ExchangeFuture: Future<Output = Result<AcquireTenureResponseV1, AcquireTenureExchangeError>>,
{
    acquire_tenure_once_with(store, prepared, authority_domain_fingerprint, exchange).await
}

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
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};
    use tokio::runtime::Builder as RuntimeBuilder;

    use crate::controller_journal::{
        ControllerAuthKeyFingerprint, ControllerJournalSnapshot, ControllerJournalState,
        ControllerOwnerIdentityFingerprint, ControllerRequestAuthPin,
        ControllerTenureAuthorityDomainFingerprint, controller_test_manifest,
    };
    use crate::controller_store::{
        ControllerCommitFailpoint, ControllerFilesystemPolicy, ControllerStore,
        create_and_lock_controller_initializer_lock, ensure_fresh_controller_directory,
        open_controller_directory, publish_initial_controller_snapshot,
    };
    use crate::plan::{DeploymentId, DeploymentScopeId, DeploymentWriterRef};
    use crate::planner::StableAllocationSnapshot;
    use crate::tenure_client::{
        AcquireTenureExchangeError, AcquireTenureRequestToSign, PreparedAcquireTenureRequest,
        TenureClientFailure,
    };
    use crate::tenure_protocol::{
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };

    use super::{ControllerTenureError, acquire_tenure_once_with_test_domain};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
    const STORE_ID: [u8; 32] = [0x41; 32];
    const SCOPE: DeploymentScopeId = DeploymentScopeId::from_bytes([0x42; 16]);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|error| panic!("fixture root canonicalize failed: {error}"));
            let path = root.join(format!(
                "paraegox-controller-tenure-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("fixture directory create failed: {error}"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("fixture directory chmod failed: {error}"));
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
        ControllerOwnerIdentityFingerprint::from_stored(Digest32::from_bytes([0x43; 32]))
    }

    fn initial_snapshot() -> ControllerJournalSnapshot {
        let target = RuntimeHostId::from_bytes([0x44; 16]);
        let state = ControllerJournalState::try_initialize(
            SCOPE,
            DeploymentId::from_bytes([0x45; 16]),
            StableAllocationSnapshot::try_new(target, 0, 0, Vec::new())
                .expect("fixture allocation"),
            controller_test_manifest(target),
            ControllerRequestAuthPin::try_new(
                ApplyAuthKeyRef::from_bytes([0x46; 16]),
                ApplyAuthAlgorithm::try_new(1).expect("fixture algorithm"),
                1,
                ControllerAuthKeyFingerprint::from_stored(Digest32::from_bytes([0x47; 32])),
                1,
            )
            .expect("fixture auth pin"),
        )
        .expect("fixture state");
        ControllerJournalSnapshot::try_initialize(STORE_ID, owner(), state)
            .expect("fixture snapshot")
    }

    fn open_fixture(
        snapshot: &ControllerJournalSnapshot,
        directory: &TestDirectory,
    ) -> ControllerStore {
        let handle = open_controller_directory(
            directory.path(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("open fixture directory");
        ensure_fresh_controller_directory(&handle).expect("fresh fixture directory");
        let initializer_lock =
            create_and_lock_controller_initializer_lock(&handle).expect("initializer lock");
        publish_initial_controller_snapshot(
            &handle,
            &snapshot.encode().expect("snapshot bytes"),
            [0x48; 16],
            ControllerCommitFailpoint::None,
        )
        .expect("publish snapshot");
        drop(initializer_lock);
        ControllerStore::open_with_policy(
            directory.path(),
            STORE_ID,
            owner(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("open fixture store")
    }

    fn prepared_request() -> PreparedAcquireTenureRequest {
        let signer = SigningKey::from_bytes(&[0x49; 32]);
        let public_key_fingerprint =
            ControllerPublicKeyFingerprint::for_ed25519_key(signer.verifying_key().as_bytes())
                .expect("Controller public-key fingerprint");
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                SCOPE,
                DeploymentWriterRef::from_bytes([0x4a; 16]),
                AcquireTenureOperationId::from_bytes([0x4b; 16]),
            ),
            PrincipalRef::from_bytes([0x4c; 16]),
            ControllerAcquireKeyRef::from_bytes([0x4d; 16]),
            public_key_fingerprint,
            &[0x4e; 32],
            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .expect("response bound must fit"),
        )
        .expect("tenure request draft");
        let to_sign = AcquireTenureRequestToSign::try_new(draft).expect("request to sign");
        let signature = signer.sign(to_sign.signing_bytes());
        to_sign
            .finalize_ed25519(&signature.to_bytes())
            .expect("prepared tenure request")
    }

    fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
        RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    #[test]
    fn changed_authority_domain_is_rejected_before_a_second_send() {
        let directory = TestDirectory::new();
        let snapshot = initial_snapshot();
        let mut store = open_fixture(&snapshot, &directory);
        let prepared = prepared_request();
        let sends = Cell::new(0_u32);
        let first_domain = ControllerTenureAuthorityDomainFingerprint::from_stored(
            Digest32::from_bytes([0x51; 32]),
        );
        let first = run_async(acquire_tenure_once_with_test_domain(
            &mut store,
            &prepared,
            first_domain,
            |_| {
                sends.set(sends.get() + 1);
                async {
                    Err(AcquireTenureExchangeError::NotSent(
                        TenureClientFailure::SocketMetadataUnavailable,
                    ))
                }
            },
        ));
        assert!(matches!(
            first,
            Err(ControllerTenureError::Exchange(
                AcquireTenureExchangeError::NotSent(TenureClientFailure::SocketMetadataUnavailable)
            ))
        ));
        assert_eq!(sends.get(), 1);
        let prepared_snapshot = store.snapshot().expect("Prepared snapshot").clone();

        let changed_domain = ControllerTenureAuthorityDomainFingerprint::from_stored(
            Digest32::from_bytes([0x52; 32]),
        );
        let replay = run_async(acquire_tenure_once_with_test_domain(
            &mut store,
            &prepared,
            changed_domain,
            |_| {
                sends.set(sends.get() + 1);
                async {
                    Err(AcquireTenureExchangeError::NotSent(
                        TenureClientFailure::SocketMetadataUnavailable,
                    ))
                }
            },
        ));
        assert_eq!(
            replay,
            Err(ControllerTenureError::Journal(
                crate::controller_journal::ControllerJournalError::TenureAuthorityDomainMismatch,
            ))
        );
        assert_eq!(sends.get(), 1, "domain mismatch must receive no send token");
        assert_eq!(
            store.snapshot().expect("store remains operational"),
            &prepared_snapshot,
            "domain mismatch must not mutate the durable transaction"
        );
    }
}
