#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalFailureV1,
    AgentConversationTerminalResultV1, AgentConversationTurnId,
};
use paraegox_agent_service::{
    AgentConversationModelCancellation, AgentConversationModelFuture,
    AgentConversationModelOutcomeV1, AgentConversationModelProvider,
    AgentConversationModelServiceProviderV1, AgentService, AgentServiceAcceptOutcomeV1,
    AgentServiceConfigV1, AgentServiceError, AgentServiceSubmitOutcomeV1, AgentSessionJournalError,
    AgentSessionOpenOutcomeV1, DeterministicEchoModelProvider,
};
use paraegox_kernel::digest::Digest32;
use paraegox_model::{
    ModelBackendFuture, ModelBackendIdentityV1, ModelBackendV1, ModelCancellationViewV1,
    ModelInvocationOutcomeV1, ModelInvocationRequestV1, ModelServiceConfigV1, ModelServiceV1,
};
use std::task::{Context, Poll, Waker};

static NEXT_STORE: AtomicU64 = AtomicU64::new(1);

struct TestStore {
    root: PathBuf,
}

impl TestStore {
    fn new(label: &str) -> Self {
        let nonce = NEXT_STORE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "paraegox-agent-journal-{}-{nonce}-{label}",
            std::process::id()
        ));
        Self { root }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn records(&self) -> PathBuf {
        self.root.join("records")
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove isolated test journal");
        }
    }
}

fn config() -> AgentServiceConfigV1 {
    AgentServiceConfigV1::try_new(8, 8, 8, 32).expect("config")
}

fn deck(byte: u8) -> AgentConversationDeckRunId {
    AgentConversationDeckRunId::try_from_bytes([byte; 16]).expect("DeckRun id")
}

fn session(byte: u8) -> AgentConversationSessionId {
    AgentConversationSessionId::try_from_bytes([byte; 16]).expect("Session id")
}

fn request(
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
) -> AgentConversationRequestV1 {
    AgentConversationRequestV1::try_new(
        deck_run_id,
        session_id,
        AgentConversationTurnId::try_from_bytes([3; 16]).expect("Turn id"),
        AgentConversationRequestId::try_from_bytes([4; 16]).expect("Request id"),
        5_000_000_000,
        "durable hello",
    )
    .expect("request")
}

fn record_path(store: &TestStore, sequence: u64) -> PathBuf {
    store.records().join(format!("{sequence:020}.pxaj"))
}

fn committed_record_count(store: &TestStore) -> usize {
    fs::read_dir(store.records())
        .expect("read records")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".pxaj"))
        })
        .count()
}

fn submit_ready<P: AgentConversationModelProvider>(
    service: &mut AgentService,
    provider: &mut P,
    request: AgentConversationRequestV1,
) -> Result<AgentServiceSubmitOutcomeV1, AgentServiceError> {
    let deck_run_id = request.deck_run_id();
    let session_id = request.session_id();
    let request_id = request.request_id();
    match service.accept_request(request)? {
        AgentServiceAcceptOutcomeV1::Accepted => {
            let invocation = service.begin_execution(deck_run_id, session_id, request_id)?;
            let mut future =
                provider.complete(invocation.request().clone(), invocation.cancellation());
            let mut context = Context::from_waker(Waker::noop());
            let Poll::Ready(outcome) = future.as_mut().poll(&mut context) else {
                panic!("durable fixture provider must complete immediately");
            };
            service.complete_execution(invocation, outcome)
        }
        AgentServiceAcceptOutcomeV1::PendingReplay => {
            Err(AgentServiceError::DurableRecoveryRequired)
        }
        AgentServiceAcceptOutcomeV1::TerminalReplay(terminal) => {
            Ok(AgentServiceSubmitOutcomeV1::TerminalReplay(terminal))
        }
        AgentServiceAcceptOutcomeV1::Rejected(terminal) => {
            Ok(AgentServiceSubmitOutcomeV1::Rejected(terminal))
        }
    }
}

#[derive(Debug)]
struct CommitObservingProvider {
    records_directory: PathBuf,
    observed_acceptance: bool,
    calls: usize,
}

impl AgentConversationModelProvider for CommitObservingProvider {
    fn complete(
        &mut self,
        request: AgentConversationRequestV1,
        _cancellation: AgentConversationModelCancellation,
    ) -> AgentConversationModelFuture {
        self.calls += 1;
        self.observed_acceptance = fs::read_dir(&self.records_directory)
            .expect("provider observes journal")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(".pxaj"))
            })
            .count()
            == 3;
        Box::pin(async move {
            AgentConversationModelOutcomeV1::Success(
                format!("durable: {}", request.input()).into_boxed_str(),
            )
        })
    }
}

struct CancellationObservingBackend;

impl ModelBackendV1 for CancellationObservingBackend {
    fn identity(&self) -> ModelBackendIdentityV1 {
        ModelBackendIdentityV1::try_new([31; 16], Digest32::from_bytes([32; 32]))
            .expect("test backend identity")
    }

    fn invoke(
        &self,
        _request: ModelInvocationRequestV1,
        cancellation: ModelCancellationViewV1,
    ) -> ModelBackendFuture {
        Box::pin(async move {
            if cancellation.is_cancellation_requested() {
                ModelInvocationOutcomeV1::OutcomeUncertain
            } else {
                ModelInvocationOutcomeV1::Failed
            }
        })
    }
}

#[test]
fn accepted_is_durable_before_provider_and_reopen_replays_exact_terminal() {
    let store = TestStore::new("replay");
    let deck_run_id = deck(1);
    let session_id = session(2);
    let request = request(deck_run_id, session_id);
    let terminal_wire;
    {
        let mut provider = CommitObservingProvider {
            records_directory: store.records(),
            observed_acceptance: false,
            calls: 0,
        };
        let mut service =
            AgentService::open_durable(config(), store.root()).expect("open durable service");
        assert_eq!(
            service.open_session(deck_run_id, session_id),
            Ok(AgentSessionOpenOutcomeV1::Opened)
        );
        let committed =
            submit_ready(&mut service, &mut provider, request.clone()).expect("submit request");
        terminal_wire = committed.terminal().canonical_wire();
        assert!(provider.observed_acceptance);
        assert_eq!(provider.calls, 1);
        assert_eq!(committed_record_count(&store), 4);
    }

    let mut reopened =
        AgentService::open_durable(config(), store.root()).expect("reopen durable service");
    let snapshot = reopened
        .export_session_snapshot(deck_run_id, session_id)
        .expect("recovered snapshot");
    assert_eq!(snapshot.requests().len(), 1);
    assert_eq!(
        snapshot.requests()[0]
            .terminal()
            .expect("recovered terminal")
            .canonical_wire(),
        terminal_wire
    );
    let replay = reopened.accept_request(request).expect("exact replay");
    let AgentServiceAcceptOutcomeV1::TerminalReplay(replay) = replay else {
        panic!("expected terminal replay");
    };
    assert_eq!(replay.canonical_wire(), terminal_wire);
    assert_eq!(committed_record_count(&store), 4);
}

#[test]
fn durable_cancel_record_precedes_model_cancellation_view_signal() {
    let store = TestStore::new("model-cancel-signal");
    let deck_run_id = deck(1);
    let session_id = session(2);
    let request = request(deck_run_id, session_id);
    let mut service = AgentService::open_durable(config(), store.root()).expect("open service");
    service
        .open_session(deck_run_id, session_id)
        .expect("open Session");
    assert_eq!(
        service
            .accept_request(request.clone())
            .expect("accept request"),
        AgentServiceAcceptOutcomeV1::Accepted
    );
    let invocation = service
        .begin_execution(deck_run_id, session_id, request.request_id())
        .expect("commit model handoff");
    assert_eq!(committed_record_count(&store), 3);
    assert!(!invocation.cancellation().is_cancellation_requested());

    let model_service = ModelServiceV1::new(
        ModelServiceConfigV1::try_new(1).expect("test model capacity"),
        CancellationObservingBackend,
    );
    let mut provider = AgentConversationModelServiceProviderV1::new(model_service);
    let mut operation = provider.complete(invocation.request().clone(), invocation.cancellation());
    assert_eq!(
        service
            .cancel_request(deck_run_id, session_id, request.request_id())
            .expect("commit cancellation intent"),
        paraegox_agent_contracts::control::AgentConversationCancelStateV1::IntentRecorded
    );
    assert_eq!(committed_record_count(&store), 4);

    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(outcome) = operation.as_mut().poll(&mut context) else {
        panic!("cancellation-observing backend must complete immediately");
    };
    assert_eq!(outcome, AgentConversationModelOutcomeV1::OutcomeUncertain);
    let terminal = service
        .complete_execution(invocation, outcome)
        .expect("commit uncertain terminal");
    assert_eq!(
        terminal.terminal().result(),
        &AgentConversationTerminalResultV1::Failure(
            AgentConversationTerminalFailureV1::ModelOutcomeUncertain
        )
    );
    assert_eq!(committed_record_count(&store), 5);
}

#[test]
fn cancel_before_provider_is_durable_and_never_invokes_provider_after_reopen() {
    let store = TestStore::new("cancel");
    let deck_run_id = deck(1);
    let session_id = session(2);
    let request = request(deck_run_id, session_id);
    let terminal_wire;
    {
        let mut service =
            AgentService::open_durable(config(), store.root()).expect("open durable service");
        service
            .open_session(deck_run_id, session_id)
            .expect("open Session");
        assert_eq!(
            service
                .accept_request(request.clone())
                .expect("durable acceptance"),
            AgentServiceAcceptOutcomeV1::Accepted
        );
        let cancelled = service
            .cancel_request(deck_run_id, session_id, request.request_id())
            .expect("durable cancellation");
        let paraegox_agent_contracts::control::AgentConversationCancelStateV1::Terminal(terminal) =
            cancelled
        else {
            panic!("expected cancellation terminal");
        };
        assert_eq!(
            terminal.result(),
            &AgentConversationTerminalResultV1::Failure(
                AgentConversationTerminalFailureV1::CancelledBeforeModel
            )
        );
        terminal_wire = terminal.canonical_wire();
        assert_eq!(committed_record_count(&store), 4);
    }

    let reopened =
        AgentService::open_durable(config(), store.root()).expect("reopen cancelled request");
    let snapshot = reopened
        .export_session_snapshot(deck_run_id, session_id)
        .expect("snapshot");
    assert!(snapshot.requests()[0].cancel_requested());
    assert_eq!(
        snapshot.requests()[0]
            .terminal()
            .expect("terminal")
            .canonical_wire(),
        terminal_wire
    );
    assert_eq!(committed_record_count(&store), 4);
}

#[test]
fn sealed_deck_run_reopens_sealed_and_retains_terminal_queries() {
    let store = TestStore::new("sealed");
    let deck_run_id = deck(1);
    let session_id = session(2);
    let request = request(deck_run_id, session_id);
    let terminal_wire;
    {
        let mut service =
            AgentService::open_durable(config(), store.root()).expect("open durable service");
        let mut provider = DeterministicEchoModelProvider::new();
        service
            .open_session(deck_run_id, session_id)
            .expect("open Session");
        terminal_wire = submit_ready(&mut service, &mut provider, request.clone())
            .expect("terminal")
            .terminal()
            .canonical_wire();
        service.seal_deck_run(deck_run_id).expect("seal DeckRun");
        let empty_seal = service
            .seal_deck_run(deck(8))
            .expect("seal DeckRun with no Session");
        assert_eq!(empty_seal.retained_sessions(), 0);
    }

    let mut reopened =
        AgentService::open_durable(config(), store.root()).expect("reopen sealed service");
    let snapshot = reopened
        .export_session_snapshot(deck_run_id, session_id)
        .expect("sealed snapshot");
    assert!(snapshot.is_sealed());
    assert_eq!(snapshot.event_high_watermark(), 4);
    assert_eq!(
        reopened
            .terminal(deck_run_id, session_id, request.request_id())
            .expect("terminal query")
            .expect("retained terminal")
            .canonical_wire(),
        terminal_wire
    );
    assert_eq!(
        reopened.accept_request(request),
        Err(AgentServiceError::SessionSealed)
    );
    assert_eq!(
        reopened.open_session(deck_run_id, session(9)),
        Err(AgentServiceError::DeckRunSealed)
    );
    assert_eq!(
        reopened.open_session(deck(8), session(9)),
        Err(AgentServiceError::DeckRunSealed)
    );
}

#[test]
fn writer_lock_is_exclusive_and_store_paths_are_private() {
    let store = TestStore::new("lock");
    let service = AgentService::open_durable(config(), store.root()).expect("first writer");
    let contention = AgentService::open_durable(config(), store.root())
        .expect_err("second writer must be rejected");
    assert_eq!(
        contention,
        AgentServiceError::Journal(AgentSessionJournalError::LockContended)
    );
    for path in [
        store.root().to_path_buf(),
        store.records(),
        store.root().join(".writer.lock"),
    ] {
        let mode = fs::symlink_metadata(path)
            .expect("store metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
    drop(service);
    AgentService::open_durable(config(), store.root()).expect("lock releases when writer drops");
}

#[test]
fn only_canonical_uncommitted_temp_is_cleaned_and_other_files_are_preserved() {
    let store = TestStore::new("temp-scope");
    {
        let mut service =
            AgentService::open_durable(config(), store.root()).expect("open durable service");
        service
            .open_session(deck(1), session(2))
            .expect("one committed record");
    }
    let canonical_temp = store.records().join(".00000000000000000002.pxaj.tmp");
    let unrelated = store.records().join("notes.tmp");
    fs::write(&canonical_temp, b"uncommitted").expect("canonical temp");
    fs::set_permissions(&canonical_temp, fs::Permissions::from_mode(0o600))
        .expect("private canonical temp");
    fs::write(&unrelated, b"must remain").expect("unrelated file");

    let error = AgentService::open_durable(config(), store.root())
        .expect_err("unexpected entry fails closed before cleanup");
    assert_eq!(
        error,
        AgentServiceError::Journal(AgentSessionJournalError::UnexpectedStoreEntry)
    );
    assert!(canonical_temp.exists());
    assert!(unrelated.exists());

    fs::remove_file(&unrelated).expect("remove test obstruction");
    AgentService::open_durable(config(), store.root()).expect("canonical temp is recoverable");
    assert!(!canonical_temp.exists());

    let future_temp = store.records().join(".00000000000000000009.pxaj.tmp");
    fs::write(&future_temp, b"not the next sequence").expect("future temp");
    fs::set_permissions(&future_temp, fs::Permissions::from_mode(0o600))
        .expect("private future temp");
    let error = AgentService::open_durable(config(), store.root())
        .expect_err("non-next canonical temp is not owned cleanup state");
    assert_eq!(
        error,
        AgentServiceError::Journal(AgentSessionJournalError::UnexpectedStoreEntry)
    );
    assert!(future_temp.exists());
}

fn one_record_store(label: &str) -> TestStore {
    let store = TestStore::new(label);
    {
        let mut service =
            AgentService::open_durable(config(), store.root()).expect("open durable service");
        service
            .open_session(deck(1), session(2))
            .expect("one record");
    }
    store
}

fn reopen_error(store: &TestStore) -> AgentSessionJournalError {
    match AgentService::open_durable(config(), store.root()) {
        Err(AgentServiceError::Journal(error)) => error,
        other => panic!("expected journal rejection, got {other:?}"),
    }
}

#[test]
fn root_records_lock_and_committed_record_require_exact_private_modes() {
    let root = one_record_store("root-mode");
    fs::set_permissions(root.root(), fs::Permissions::from_mode(0o1700)).expect("mutate root mode");
    assert_eq!(
        reopen_error(&root),
        AgentSessionJournalError::InsecurePermissions
    );
    fs::set_permissions(root.root(), fs::Permissions::from_mode(0o700)).expect("restore root mode");

    let records = one_record_store("records-mode");
    fs::set_permissions(records.records(), fs::Permissions::from_mode(0o750))
        .expect("mutate records mode");
    assert_eq!(
        reopen_error(&records),
        AgentSessionJournalError::InsecurePermissions
    );
    fs::set_permissions(records.records(), fs::Permissions::from_mode(0o700))
        .expect("restore records mode");

    let lock = one_record_store("lock-mode");
    let lock_path = lock.root().join(".writer.lock");
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o640)).expect("mutate lock mode");
    assert_eq!(
        reopen_error(&lock),
        AgentSessionJournalError::InsecurePermissions
    );
    fs::set_permissions(lock_path, fs::Permissions::from_mode(0o600)).expect("restore lock mode");

    let record = one_record_store("record-mode");
    let committed = record_path(&record, 1);
    fs::set_permissions(&committed, fs::Permissions::from_mode(0o640)).expect("mutate record mode");
    assert_eq!(
        reopen_error(&record),
        AgentSessionJournalError::InsecurePermissions
    );
    fs::set_permissions(committed, fs::Permissions::from_mode(0o600)).expect("restore record mode");
}

#[test]
fn torn_corrupt_and_unknown_version_records_fail_closed() {
    let torn = one_record_store("torn");
    OpenOptions::new()
        .write(true)
        .open(record_path(&torn, 1))
        .expect("open record")
        .set_len(10)
        .expect("truncate record");
    assert_eq!(
        reopen_error(&torn),
        AgentSessionJournalError::TruncatedRecord
    );

    let corrupt = one_record_store("checksum");
    let corrupt_path = record_path(&corrupt, 1);
    let mut corrupt_bytes = fs::read(&corrupt_path).expect("read record");
    let last = corrupt_bytes.last_mut().expect("record payload");
    *last ^= 1;
    fs::write(&corrupt_path, corrupt_bytes).expect("corrupt record");
    assert_eq!(
        reopen_error(&corrupt),
        AgentSessionJournalError::ChecksumMismatch
    );

    let version = one_record_store("version");
    let version_path = record_path(&version, 1);
    let mut version_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(version_path)
        .expect("open record");
    version_file.seek(SeekFrom::Start(4)).expect("seek version");
    version_file
        .write_all(&2_u16.to_be_bytes())
        .expect("unknown version");
    version_file.sync_all().expect("sync mutation");
    assert_eq!(
        reopen_error(&version),
        AgentSessionJournalError::UnsupportedVersion
    );
}

#[test]
fn sequence_gap_and_duplicate_record_sequence_fail_closed() {
    let gap = one_record_store("gap");
    fs::copy(record_path(&gap, 1), record_path(&gap, 3)).expect("create sequence gap");
    assert_eq!(reopen_error(&gap), AgentSessionJournalError::SequenceGap);

    let duplicate = one_record_store("duplicate");
    fs::copy(record_path(&duplicate, 1), record_path(&duplicate, 2))
        .expect("duplicate record sequence");
    assert_eq!(
        reopen_error(&duplicate),
        AgentSessionJournalError::DuplicateSequence
    );
}

#[test]
fn record_payload_reader_does_not_accept_trailing_mutation() {
    let store = one_record_store("trailing");
    let path = record_path(&store, 1);
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(path)
        .expect("open record");
    let mut prefix = [0; 4];
    file.read_exact(&mut prefix).expect("read magic");
    assert_eq!(&prefix, b"PXAJ");
    file.write_all(&[0]).expect("append trailing byte");
    file.sync_all().expect("sync mutation");
    assert_eq!(
        reopen_error(&store),
        AgentSessionJournalError::InvalidFrameLength
    );
}
