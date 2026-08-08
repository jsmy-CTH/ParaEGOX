#![cfg(unix)]

use std::fs::{self, DirBuilder};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::ops::{Deref, DerefMut};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, getegid, geteuid};
use paraegox_kernel::{
    digest::{Digest32, Digest32Builder},
    identity::{PrincipalRef, RuntimeHostId},
    time::{ClockDomainRef, ClockGeneration},
};
use paraegox_node::observation::{
    RUNTIME_OBSERVATION_ACK_BYTES, RUNTIME_OBSERVATION_TOKEN_BYTES, RuntimeObservationAckOutcomeV1,
    RuntimeObservationAckV1, RuntimeObservationAuthorityV1, RuntimeObservationBootstrapInputV1,
    RuntimeObservationBootstrapV1, RuntimeObservationEndpointRefV1, RuntimeObservationError,
    RuntimeObservationRequestInputV1, RuntimeObservationRequestV1,
    derive_runtime_observation_query_nonce_v1,
};
use paraegox_node::process::{
    DeveloperLocalNodeManagementEndpointErrorV1, DeveloperLocalNodeManagementEndpointV1,
    DeveloperLocalReferenceBootstrapInputV1, DeveloperLocalReferenceBootstrapV1,
    MAX_DEVELOPER_LOCAL_NODE_MANAGEMENT_EXCHANGE_TIMEOUT, NodeDaemonProcessError,
    serve_developer_local_runtime_observation_node_daemon_v1,
};
use paraegox_node::protocol::{
    MAX_NODE_MANAGEMENT_RESPONSE_BYTES, NODE_MANAGEMENT_REQUEST_BYTES, NodeManagementClientErrorV1,
    NodeManagementClientV1, NodeManagementEndpointErrorV1, NodeManagementRequestV1,
    NodeManagementResponseOutcomeV1, NodeManagementResponseV1, NodeManagementTargetV1,
    NodeStatusCursorV1,
};
use paraegox_node::store::DurableNodeDaemonV1;
use paraegox_node::{
    EnrollmentIssuerRefV1, NodeArchitectureV1, NodeFeatureReportInputV1, NodeFeatureReportV1,
    NodeId, NodeIdentityV1, NodeIncarnation, NodeManagementEndpointRefV1, NodeOperatingSystemV1,
    NodeRegistrationTenureV1, NodeStatusV1, RuntimeApplyEndpointDescriptorV1,
    RuntimeApplyEndpointRefV1, RuntimeHostLivenessV1,
};
use paraegox_runtime_contracts::{
    apply::ApplyOperationId,
    provenance::{SourcePlanRevision, SourceScopeRef},
    reference_control::{
        MAX_REFERENCE_QUERY_RESPONSE_BYTES, ReferenceBootstrapServingIdentityV1,
        ReferenceChannelBindingV1, ReferenceQueryDesiredHeadV1, ReferenceQueryDesiredStateV1,
        ReferenceQueryFactsV1, ReferenceQueryIdV1, ReferenceQueryLiveFactsV1,
        ReferenceQueryLiveStateV1, ReferenceQueryOperationLookupV1, ReferenceQueryOperationStateV1,
        ReferenceQueryOwnerStateV1, ReferenceQueryRequestDraftV1,
        ReferenceQueryResponseAuthClaimV1, ReferenceQueryResponseDraftV1, ReferenceQuerySelectorV1,
    },
    wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim},
};

const LOCAL_HEADER_BYTES: usize = 48;
const LOCAL_FRAME_BYTES: usize = LOCAL_HEADER_BYTES + NODE_MANAGEMENT_REQUEST_BYTES;
const TOKEN: [u8; 32] = [0x71; 32];
const OBSERVATION_TOKEN: [u8; RUNTIME_OBSERVATION_TOKEN_BYTES] = [0x72; 32];
const RUNTIME_SIGNING_SEED: [u8; 32] = [0x73; 32];
const PROCESS_WAIT: Duration = Duration::from_secs(8);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new() -> Self {
        let sequence = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
        let parent = std::env::temp_dir().canonicalize().expect("canonical temp");
        let path = parent.join(format!("pxn-{}-{sequence}", std::process::id()));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private test root");
        Self { path }
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Fixture {
    _root: TestRoot,
    bootstrap_path: PathBuf,
    state_root: PathBuf,
    socket_path: PathBuf,
    observation_bootstrap_path: PathBuf,
    observation_socket_path: PathBuf,
    target: NodeManagementTargetV1,
    status: NodeStatusV1,
    observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    observation_authority: RuntimeObservationAuthorityV1,
}

struct TestChild(Child);

impl Deref for TestChild {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TestChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for TestChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

impl Fixture {
    fn new() -> Self {
        let root = TestRoot::new();
        let state_root = root.path.join("state");
        let socket_path = root.path.join("n.sock");
        let bootstrap_path = root.path.join("n.pxnb");
        let observation_bootstrap_path = root.path.join("n.pxob");
        let observation_socket_path = root.path.join("o.sock");
        let node_id = NodeId::try_from_bytes([0x11; 16]).expect("node id");
        let identity = NodeIdentityV1::try_new(
            node_id,
            PrincipalRef::from_bytes([0x12; 16]),
            EnrollmentIssuerRefV1::try_from_bytes([0x13; 16]).expect("issuer"),
        )
        .expect("identity");
        let node_incarnation = NodeIncarnation::try_from_bytes([0x14; 16]).expect("incarnation");
        let tenure = NodeRegistrationTenureV1::try_new(node_id, 7, node_incarnation)
            .expect("exact external tenure");
        let management_endpoint_ref =
            NodeManagementEndpointRefV1::try_from_bytes([0x15; 16]).expect("management ref");
        let feature = NodeFeatureReportV1::try_new(NodeFeatureReportInputV1 {
            node_id,
            node_incarnation,
            report_sequence: 1,
            operating_system: if cfg!(target_os = "macos") {
                NodeOperatingSystemV1::MacOs
            } else {
                NodeOperatingSystemV1::Linux
            },
            architecture: if cfg!(target_arch = "aarch64") {
                NodeArchitectureV1::Aarch64
            } else {
                NodeArchitectureV1::X86_64
            },
            platform_profile_digest: Digest32::from_bytes([0x16; 32]),
            runtime_contract_version: 1,
            fabric_contract_version: 1,
        })
        .expect("feature");
        let status = {
            let mut durable = DurableNodeDaemonV1::open(
                &state_root,
                identity,
                tenure,
                management_endpoint_ref,
                feature,
            )
            .expect("durable owner");
            durable
                .publish_status(5_000_000_000)
                .expect("external owner publication")
        };
        let bootstrap =
            DeveloperLocalReferenceBootstrapV1::try_new(DeveloperLocalReferenceBootstrapInputV1 {
                expected_uid: geteuid().as_raw(),
                expected_gid: getegid().as_raw(),
                generation_token: TOKEN,
                identity,
                tenure,
                management_endpoint_ref,
                initial_feature_report: feature,
                state_root: state_root.clone(),
                socket_path: socket_path.clone(),
            })
            .expect("typed bootstrap");
        let wire = bootstrap.canonical_wire().expect("canonical PXNB");
        let decoded = DeveloperLocalReferenceBootstrapV1::decode_canonical_wire(&wire)
            .expect("strict PXNB roundtrip");
        assert_eq!(decoded.identity(), identity);
        assert_eq!(decoded.tenure(), tenure);
        assert_eq!(decoded.state_root(), state_root);
        assert_eq!(decoded.socket_path(), socket_path);
        bootstrap
            .write_owner_private_file(&bootstrap_path)
            .expect("atomic owner-private bootstrap");
        assert_eq!(
            bootstrap
                .write_owner_private_file(&bootstrap_path)
                .expect_err("bootstrap cannot be replaced"),
            NodeDaemonProcessError::BootstrapAlreadyExists
        );
        let metadata = fs::symlink_metadata(&bootstrap_path).expect("bootstrap metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        let target = NodeManagementTargetV1::try_new(
            node_id,
            management_endpoint_ref,
            node_incarnation,
            tenure.registration_epoch(),
        )
        .expect("target");
        let runtime_host_id = RuntimeHostId::from_bytes([0x31; 16]);
        let runtime_principal = PrincipalRef::from_bytes([0x32; 16]);
        let runtime_signing_key = SigningKey::from_bytes(&RUNTIME_SIGNING_SEED);
        let channel = ReferenceChannelBindingV1::try_new(
            runtime_host_id,
            runtime_principal,
            Digest32::from_bytes([0x35; 32]),
            Digest32::from_bytes([0x36; 32]),
        )
        .expect("Runtime channel");
        let serving_baseline = ReferenceBootstrapServingIdentityV1::try_new(
            runtime_host_id,
            [0x37; 32],
            10,
            5,
            ClockDomainRef::from_bytes([0x38; 16]),
            ClockGeneration::try_new(2).expect("clock generation"),
        )
        .expect("serving baseline");
        let endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
            RuntimeApplyEndpointRefV1::try_from_bytes([0x39; 16]).expect("Runtime endpoint"),
            runtime_host_id,
            7,
            "paraegox/v1/nodes/11/runtime/31/apply",
            [0x34; 16],
            runtime_signing_key.verifying_key().to_bytes(),
        )
        .expect("exact Runtime apply endpoint");
        let observation_authority = RuntimeObservationAuthorityV1::try_new(
            runtime_principal,
            channel,
            serving_baseline,
            endpoint,
        )
        .expect("Runtime observation authority");
        let observation_endpoint_ref = RuntimeObservationEndpointRefV1::try_from_bytes([0x3a; 16])
            .expect("observation endpoint");
        let observation_bootstrap =
            RuntimeObservationBootstrapV1::try_new(RuntimeObservationBootstrapInputV1 {
                expected_uid: geteuid().as_raw(),
                expected_gid: getegid().as_raw(),
                generation_token: OBSERVATION_TOKEN,
                node_target: target,
                observation_endpoint_ref,
                socket_path: observation_socket_path.clone(),
                authorities: vec![observation_authority.clone()],
            })
            .expect("observation bootstrap");
        let observation_wire = observation_bootstrap
            .canonical_wire()
            .expect("canonical PXOB");
        let decoded_observation =
            RuntimeObservationBootstrapV1::decode_canonical_wire(observation_wire.as_ref())
                .expect("strict PXOB roundtrip");
        assert_eq!(decoded_observation.node_target(), target);
        assert_eq!(
            decoded_observation.authorities(),
            std::slice::from_ref(&observation_authority)
        );
        observation_bootstrap
            .write_owner_private_file(&observation_bootstrap_path)
            .expect("atomic owner-private PXOB");
        let interrupted_link = interrupted_bootstrap_link(&observation_bootstrap_path);
        fs::hard_link(&observation_bootstrap_path, &interrupted_link)
            .expect("simulate post-link pre-unlink crash");
        assert_eq!(
            fs::symlink_metadata(&observation_bootstrap_path)
                .expect("interrupted PXOB metadata")
                .nlink(),
            2
        );
        assert_eq!(
            observation_bootstrap
                .write_owner_private_file(&observation_bootstrap_path)
                .expect_err("PXOB cannot be replaced"),
            RuntimeObservationError::BootstrapAlreadyExists
        );
        assert!(!interrupted_link.exists());
        assert_eq!(
            fs::symlink_metadata(&observation_bootstrap_path)
                .expect("recovered PXOB metadata")
                .nlink(),
            1
        );
        Self {
            _root: root,
            bootstrap_path,
            state_root,
            socket_path,
            observation_bootstrap_path,
            observation_socket_path,
            target,
            status,
            observation_endpoint_ref,
            observation_authority,
        }
    }

    fn spawn(&self) -> TestChild {
        TestChild(
            Command::new(env!("CARGO_BIN_EXE_paraegox-noded"))
                .arg("developer-local-reference-v1")
                .arg("--bootstrap-file")
                .arg(&self.bootstrap_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn paraegox-noded"),
        )
    }

    fn spawn_with_observation(&self) -> TestChild {
        TestChild(
            Command::new(env!("CARGO_BIN_EXE_paraegox-noded"))
                .arg("developer-local-runtime-observation-v1")
                .arg("--bootstrap-file")
                .arg(&self.bootstrap_path)
                .arg("--observation-bootstrap-file")
                .arg(&self.observation_bootstrap_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn paraegox-noded observation mode"),
        )
    }
}

#[test]
fn process_is_crash_restartable_read_only_token_bound_and_single_writer() {
    let fixture = Fixture::new();
    let state_path = fixture.state_root.join("node-daemon.pxnd");
    let state_before = fs::read(&state_path).expect("state before queries");

    let mut first = fixture.spawn();
    wait_for_socket(&fixture.socket_path, &mut first);

    reject_without_response(
        &fixture.socket_path,
        &[0x72; 32],
        &NodeManagementRequestV1::try_latest([0x81; 16], fixture.target)
            .expect("wrong-token request"),
        false,
    );
    reject_without_response(
        &fixture.socket_path,
        &TOKEN,
        &NodeManagementRequestV1::try_latest([0x82; 16], fixture.target).expect("trailing request"),
        true,
    );

    let latest_request =
        NodeManagementRequestV1::try_latest([0x83; 16], fixture.target).expect("latest request");
    let latest = exchange(&fixture.socket_path, &TOKEN, &latest_request);
    assert_eq!(latest.outcome(), NodeManagementResponseOutcomeV1::Status);
    assert_eq!(latest.status_value(), Some(&fixture.status));
    assert_eq!(
        fs::read(&state_path).expect("state after read-only queries"),
        state_before
    );

    let second = Command::new(env!("CARGO_BIN_EXE_paraegox-noded"))
        .arg("developer-local-reference-v1")
        .arg("--bootstrap-file")
        .arg(&fixture.bootstrap_path)
        .output()
        .expect("second writer exits");
    assert!(!second.status.success());

    first.kill().expect("crash first process");
    let crashed = wait_for_exit(&mut first);
    assert!(!crashed.success());
    assert!(
        fixture.socket_path.exists(),
        "SIGKILL leaves a stale socket"
    );

    let mut restarted = fixture.spawn();
    wait_for_socket(&fixture.socket_path, &mut restarted);
    let cursor = NodeStatusCursorV1::try_from(&fixture.status).expect("status cursor");
    let watch_request = NodeManagementRequestV1::try_watch([0x84; 16], fixture.target, cursor)
        .expect("watch request");
    let watch = exchange(&fixture.socket_path, &TOKEN, &watch_request);
    assert_eq!(
        watch.outcome(),
        NodeManagementResponseOutcomeV1::NotModified
    );
    assert_eq!(
        fs::read(&state_path).expect("state after crash recovery read"),
        state_before
    );

    kill(
        Pid::from_raw(i32::try_from(restarted.id()).expect("child pid fits i32")),
        Signal::SIGTERM,
    )
    .expect("request joined shutdown");
    assert!(wait_for_exit(&mut restarted).success());
    assert!(
        !fixture.socket_path.exists(),
        "joined shutdown removes socket"
    );
    assert!(
        fixture.bootstrap_path.exists(),
        "external bootstrap remains owner-owned"
    );
}

#[test]
fn sigterm_closes_listeners_and_rejects_a_queued_observation_before_join() {
    let fixture = Fixture::new();
    let state_path = fixture.state_root.join("node-daemon.pxnd");
    let state_before = fs::read(&state_path).expect("state before queued observation");
    let mut child = fixture.spawn_with_observation();
    wait_for_socket(&fixture.socket_path, &mut child);
    wait_for_socket(&fixture.observation_socket_path, &mut child);

    let observation = runtime_observation(&fixture, 2, 11, 0x43);
    let observation_frame = local_observation_frame(&OBSERVATION_TOKEN, &observation);
    let mut accepted = UnixStream::connect(&fixture.observation_socket_path)
        .expect("connect queued observation client");
    accepted
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| accepted.set_write_timeout(Some(IO_TIMEOUT)))
        .expect("bounded queued observation client");
    accepted
        .write_all(&observation_frame)
        .expect("write observation without finishing it");
    reject_observation_without_response(
        &fixture.observation_socket_path,
        &[0x7f; RUNTIME_OBSERVATION_TOKEN_BYTES],
        &observation,
    );

    kill(
        Pid::from_raw(i32::try_from(child.id()).expect("child pid fits i32")),
        Signal::SIGTERM,
    )
    .expect("request joined shutdown");
    let refuses_connection = |path: &Path| match UnixStream::connect(path) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            true
        }
        Ok(stream) => {
            drop(stream);
            false
        }
        Err(error) => panic!("unexpected post-SIGTERM connect error: {error}"),
    };
    let refusal_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        assert!(
            child.try_wait().expect("poll draining process").is_none(),
            "accepted connection must keep the process in its drain window"
        );
        let management_closed = refuses_connection(&fixture.socket_path);
        let observation_closed = refuses_connection(&fixture.observation_socket_path);
        if management_closed && observation_closed {
            break;
        }
        assert!(
            Instant::now() < refusal_deadline,
            "a listener remained connectable during shutdown drain"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        child
            .try_wait()
            .expect("poll closed listener process")
            .is_none(),
        "listener must close before the accepted connection is released"
    );

    drop(accepted);
    assert!(wait_for_exit(&mut child).success());
    assert!(!fixture.socket_path.exists());
    assert!(!fixture.observation_socket_path.exists());
    assert_eq!(
        fs::read(&state_path).expect("state after queued observation shutdown"),
        state_before,
        "an observation waiting for EOF when shutdown begins must not commit PXND"
    );
    let bootstrap =
        DeveloperLocalReferenceBootstrapV1::read_owner_private_file(&fixture.bootstrap_path)
            .expect("reopen PXNB after joined shutdown");
    let durable = DurableNodeDaemonV1::open(
        bootstrap.state_root(),
        bootstrap.identity(),
        bootstrap.tenure(),
        bootstrap.management_endpoint_ref(),
        bootstrap.initial_feature_report(),
    )
    .expect("joined shutdown releases the PXND writer");
    assert_eq!(durable.current_status(), Some(&fixture.status));
}

#[test]
fn typed_management_endpoint_securely_reopens_pxnb_and_drives_the_real_process() {
    let fixture = Fixture::new();
    let state_path = fixture.state_root.join("node-daemon.pxnd");
    let state_before = fs::read(&state_path).expect("state before typed queries");
    let reopened =
        DeveloperLocalReferenceBootstrapV1::read_owner_private_file(&fixture.bootstrap_path)
            .expect("strict owner-private PXNB reopen");
    assert_eq!(reopened.identity().node_id(), fixture.target.node_id());
    assert_eq!(reopened.socket_path(), fixture.socket_path);
    assert_eq!(
        DeveloperLocalNodeManagementEndpointV1::try_from_bootstrap(&reopened, Duration::ZERO,)
            .expect_err("zero exchange timeout must fail"),
        DeveloperLocalNodeManagementEndpointErrorV1::InvalidConfiguration
    );
    let overlong_timeout = MAX_DEVELOPER_LOCAL_NODE_MANAGEMENT_EXCHANGE_TIMEOUT
        .checked_add(Duration::from_nanos(1))
        .expect("overlong timeout fits");
    assert_eq!(
        DeveloperLocalNodeManagementEndpointV1::try_from_bootstrap(&reopened, overlong_timeout,)
            .expect_err("overlong exchange timeout must fail"),
        DeveloperLocalNodeManagementEndpointErrorV1::InvalidConfiguration
    );
    let endpoint =
        DeveloperLocalNodeManagementEndpointV1::try_from_bootstrap(&reopened, IO_TIMEOUT)
            .expect("typed management endpoint");
    let debug = format!("{endpoint:?}");
    assert!(debug.contains("<owner-private>"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&fixture.socket_path.display().to_string()));
    assert_eq!(
        endpoint
            .exchange_canonical(&[0_u8; NODE_MANAGEMENT_REQUEST_BYTES])
            .expect_err("malformed request must fail before connect"),
        DeveloperLocalNodeManagementEndpointErrorV1::InvalidRequest
    );
    drop(reopened);

    let mut child = fixture.spawn();
    wait_for_socket(&fixture.socket_path, &mut child);
    assert_eq!(
        DeveloperLocalReferenceBootstrapV1::read_owner_private_file(&fixture.bootstrap_path)
            .expect_err("live process must retain the writer lease"),
        NodeDaemonProcessError::BootstrapContended
    );

    let mut client = NodeManagementClientV1::new(endpoint, fixture.target.node_id());
    let latest = client
        .latest([0x91; 16], fixture.target)
        .expect("typed Latest over real PXNL process");
    assert_eq!(latest.outcome(), NodeManagementResponseOutcomeV1::Status);
    assert_eq!(latest.status_value(), Some(&fixture.status));
    assert_eq!(client.current_status(), Some(&fixture.status));

    fs::set_permissions(&fixture.socket_path, fs::Permissions::from_mode(0o660))
        .expect("make socket metadata insecure");
    assert_eq!(
        client
            .latest([0x92; 16], fixture.target)
            .expect_err("insecure socket metadata must fail before connect"),
        NodeManagementClientErrorV1::Endpoint(NodeManagementEndpointErrorV1::Unavailable)
    );
    fs::set_permissions(&fixture.socket_path, fs::Permissions::from_mode(0o600))
        .expect("restore private socket mode");

    let cursor = NodeStatusCursorV1::try_from(&fixture.status).expect("status cursor");
    let watch = client
        .watch([0x93; 16], fixture.target, cursor)
        .expect("typed Watch over real PXNL process");
    assert_eq!(
        watch.outcome(),
        NodeManagementResponseOutcomeV1::NotModified
    );
    assert_eq!(
        fs::read(&state_path).expect("state after typed read-only queries"),
        state_before
    );

    kill(
        Pid::from_raw(i32::try_from(child.id()).expect("child pid fits i32")),
        Signal::SIGTERM,
    )
    .expect("request joined shutdown");
    assert!(wait_for_exit(&mut child).success());
    assert!(!fixture.socket_path.exists());
    assert_eq!(
        client
            .latest([0x94; 16], fixture.target)
            .expect_err("joined endpoint must be disconnected"),
        NodeManagementClientErrorV1::Endpoint(NodeManagementEndpointErrorV1::Unavailable)
    );
}

#[test]
fn typed_management_endpoint_rejects_a_bounded_non_pxns_response() {
    let fixture = Fixture::new();
    let reopened =
        DeveloperLocalReferenceBootstrapV1::read_owner_private_file(&fixture.bootstrap_path)
            .expect("strict owner-private PXNB reopen");
    let endpoint =
        DeveloperLocalNodeManagementEndpointV1::try_from_bootstrap(&reopened, IO_TIMEOUT)
            .expect("typed management endpoint");
    drop(reopened);
    let listener = UnixListener::bind(&fixture.socket_path).expect("bind fake same-user endpoint");
    fs::set_permissions(&fixture.socket_path, fs::Permissions::from_mode(0o600))
        .expect("private fake endpoint mode");
    let fake = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept one PXNL exchange");
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
            .expect("bounded fake endpoint");
        let mut frame = [0_u8; LOCAL_FRAME_BYTES];
        stream
            .read_exact(&mut frame)
            .expect("read exact PXNL frame");
        assert_eq!(&frame[..4], b"PXNL");
        assert_eq!(
            u16::from_be_bytes(frame[4..6].try_into().expect("PXNL version")),
            1
        );
        assert_eq!(
            usize::from(u16::from_be_bytes(
                frame[6..8].try_into().expect("PXNL header length")
            )),
            LOCAL_HEADER_BYTES
        );
        assert_eq!(
            usize::try_from(u32::from_be_bytes(
                frame[8..12].try_into().expect("PXNL total length")
            ))
            .expect("PXNL total fits usize"),
            LOCAL_FRAME_BYTES
        );
        assert_eq!(
            usize::try_from(u32::from_be_bytes(
                frame[12..16].try_into().expect("PXNL payload length")
            ))
            .expect("PXNL payload fits usize"),
            NODE_MANAGEMENT_REQUEST_BYTES
        );
        assert_eq!(&frame[16..LOCAL_HEADER_BYTES], &TOKEN);
        NodeManagementRequestV1::decode(&frame[LOCAL_HEADER_BYTES..])
            .expect("exact canonical PXNQ payload");
        let mut trailing = [0_u8; 1];
        assert_eq!(stream.read(&mut trailing).expect("PXNL EOF"), 0);
        let mut malformed = [0_u8; 12];
        malformed[..4].copy_from_slice(b"NOPE");
        malformed[8..12].copy_from_slice(&12_u32.to_be_bytes());
        stream
            .write_all(&malformed)
            .expect("write bounded malformed response");
        stream
            .shutdown(Shutdown::Write)
            .expect("finish malformed response");
    });
    let request =
        NodeManagementRequestV1::try_latest([0x95; 16], fixture.target).expect("latest request");
    assert_eq!(
        endpoint
            .exchange_canonical(request.canonical_wire())
            .expect_err("length-bounded non-PXNS response must fail"),
        DeveloperLocalNodeManagementEndpointErrorV1::InvalidResponse
    );
    fake.join().expect("fake endpoint joins");
}

#[test]
fn observation_capability_token_must_be_distinct_from_management_token() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.observation_bootstrap_path).expect("remove original PXOB");
    RuntimeObservationBootstrapV1::try_new(RuntimeObservationBootstrapInputV1 {
        expected_uid: geteuid().as_raw(),
        expected_gid: getegid().as_raw(),
        generation_token: TOKEN,
        node_target: fixture.target,
        observation_endpoint_ref: fixture.observation_endpoint_ref,
        socket_path: fixture.observation_socket_path.clone(),
        authorities: vec![fixture.observation_authority.clone()],
    })
    .expect("individually valid but correlated PXOB")
    .write_owner_private_file(&fixture.observation_bootstrap_path)
    .expect("write correlated PXOB");

    assert_eq!(
        serve_developer_local_runtime_observation_node_daemon_v1(
            &fixture.bootstrap_path,
            &fixture.observation_bootstrap_path,
        )
        .expect_err("shared capability token must fail before endpoint bind"),
        NodeDaemonProcessError::InvalidBootstrap
    );
    assert!(!fixture.socket_path.exists());
    assert!(!fixture.observation_socket_path.exists());
}

#[test]
fn authenticated_runtime_observation_commits_before_ack_reads_through_pxns_and_replays_after_restart()
 {
    let fixture = Fixture::new();
    let state_path = fixture.state_root.join("node-daemon.pxnd");
    let state_before_rejections =
        fs::read(&state_path).expect("state before rejected observations");
    let mut first = fixture.spawn_with_observation();
    wait_for_socket(&fixture.socket_path, &mut first);
    wait_for_socket(&fixture.observation_socket_path, &mut first);

    let first_observation = runtime_observation(&fixture, 2, 11, 0x41);
    reject_observation_without_response(
        &fixture.observation_socket_path,
        &[0x7f; RUNTIME_OBSERVATION_TOKEN_BYTES],
        &first_observation,
    );
    let mut wrong_challenge_variant = default_observation_variant(&fixture);
    wrong_challenge_variant.nonce_token = [0x7e; RUNTIME_OBSERVATION_TOKEN_BYTES];
    let wrong_challenge =
        runtime_observation_with_variant(&fixture, 2, 11, 0x3e, wrong_challenge_variant);
    reject_observation_without_response(
        &fixture.observation_socket_path,
        &OBSERVATION_TOKEN,
        &wrong_challenge,
    );
    let mut wrong_signature_variant = default_observation_variant(&fixture);
    wrong_signature_variant.runtime_signing_seed = [0x7d; 32];
    let wrong_signature =
        runtime_observation_with_variant(&fixture, 2, 11, 0x3f, wrong_signature_variant);
    reject_observation_without_response(
        &fixture.observation_socket_path,
        &OBSERVATION_TOKEN,
        &wrong_signature,
    );
    let mut wrong_authority_variant = default_observation_variant(&fixture);
    wrong_authority_variant.authority_digest = Digest32::from_bytes([0x7c; 32]);
    let wrong_authority =
        runtime_observation_with_variant(&fixture, 2, 11, 0x40, wrong_authority_variant);
    reject_observation_without_response(
        &fixture.observation_socket_path,
        &OBSERVATION_TOKEN,
        &wrong_authority,
    );
    let mut wrong_endpoint_variant = default_observation_variant(&fixture);
    wrong_endpoint_variant.observation_endpoint_ref =
        RuntimeObservationEndpointRefV1::try_from_bytes([0x7b; 16])
            .expect("different observation endpoint");
    let wrong_endpoint =
        runtime_observation_with_variant(&fixture, 2, 11, 0x3c, wrong_endpoint_variant);
    reject_observation_without_response(
        &fixture.observation_socket_path,
        &OBSERVATION_TOKEN,
        &wrong_endpoint,
    );
    let (now, _) = challenge_window();
    let mut expired_variant = default_observation_variant(&fixture);
    expired_variant.challenge_window = (
        now.checked_sub(30_000_000_000)
            .expect("expired challenge issue time"),
        now.checked_sub(1).expect("expired challenge deadline"),
    );
    let expired = runtime_observation_with_variant(&fixture, 2, 11, 0x3d, expired_variant);
    reject_observation_without_response(
        &fixture.observation_socket_path,
        &OBSERVATION_TOKEN,
        &expired,
    );
    assert_eq!(
        fs::read(&state_path).expect("state after rejected observations"),
        state_before_rejections,
        "authentication failures must not mutate PXND"
    );

    let first_ack = observation_exchange(
        &fixture.observation_socket_path,
        &OBSERVATION_TOKEN,
        &first_observation,
    );
    assert_eq!(
        first_ack.outcome(),
        RuntimeObservationAckOutcomeV1::Published
    );
    assert_eq!(first_ack.status_sequence(), 2);

    let latest_request =
        NodeManagementRequestV1::try_latest([0x91; 16], fixture.target).expect("latest request");
    let latest = exchange(&fixture.socket_path, &TOKEN, &latest_request);
    let published = latest.status_value().expect("published NodeStatus");
    assert_eq!(published.status_sequence(), 2);
    assert_eq!(
        published.valid_until_unix_nanos(),
        Some(first_observation.challenge_expires_at_unix_nanos())
    );
    assert_eq!(published.runtime_hosts().len(), 1);
    let runtime = &published.runtime_hosts()[0];
    assert_eq!(
        runtime.runtime_host_id(),
        RuntimeHostId::from_bytes([0x31; 16])
    );
    assert_eq!(runtime.runtime_host_epoch(), 5);
    assert_eq!(runtime.observation_sequence(), 11);
    assert_eq!(runtime.liveness(), RuntimeHostLivenessV1::Live);
    assert_eq!(
        runtime.apply_endpoint(),
        fixture.observation_authority.apply_endpoint()
    );
    assert_eq!(first_ack.status_digest(), published.status_digest());
    assert_eq!(first_ack.runtime_status_digest(), runtime.status_digest());
    let state_after_first = fs::read(&state_path).expect("committed observation state");

    first.kill().expect("crash observation process");
    assert!(!wait_for_exit(&mut first).success());
    let mut restarted = fixture.spawn_with_observation();
    wait_for_socket(&fixture.socket_path, &mut restarted);
    wait_for_socket(&fixture.observation_socket_path, &mut restarted);

    let replay = observation_exchange(
        &fixture.observation_socket_path,
        &OBSERVATION_TOKEN,
        &first_observation,
    );
    assert_eq!(
        replay.outcome(),
        RuntimeObservationAckOutcomeV1::ExactReplay
    );
    assert_eq!(replay.status_digest(), published.status_digest());
    assert_eq!(
        fs::read(&state_path).expect("state after exact replay"),
        state_after_first,
        "an exact retry acknowledges the existing durable PXNS without rewriting it"
    );
    let equivalent_but_distinct = runtime_observation(&fixture, 2, 11, 0x55);
    reject_observation_without_response(
        &fixture.observation_socket_path,
        &OBSERVATION_TOKEN,
        &equivalent_but_distinct,
    );
    assert_eq!(
        fs::read(&state_path).expect("state after non-exact replay"),
        state_after_first,
        "an uncommitted request with an equivalent projection is not an exact replay"
    );

    let successor = runtime_observation(&fixture, 3, 12, 0x42);
    let successor_ack = observation_exchange(
        &fixture.observation_socket_path,
        &OBSERVATION_TOKEN,
        &successor,
    );
    assert_eq!(
        successor_ack.outcome(),
        RuntimeObservationAckOutcomeV1::Published
    );
    let latest_request =
        NodeManagementRequestV1::try_latest([0x92; 16], fixture.target).expect("latest request");
    let latest = exchange(&fixture.socket_path, &TOKEN, &latest_request);
    let successor_status = latest.status_value().expect("successor NodeStatus");
    assert_eq!(successor_status.status_sequence(), 3);
    assert_eq!(
        successor_status.runtime_hosts()[0].observation_sequence(),
        12
    );

    kill(
        Pid::from_raw(i32::try_from(restarted.id()).expect("child pid fits i32")),
        Signal::SIGTERM,
    )
    .expect("request joined shutdown");
    assert!(wait_for_exit(&mut restarted).success());
    assert!(!fixture.socket_path.exists());
    assert!(!fixture.observation_socket_path.exists());
}

fn runtime_observation(
    fixture: &Fixture,
    intended_status_sequence: u64,
    runtime_snapshot_sequence: u64,
    marker: u8,
) -> RuntimeObservationRequestV1 {
    runtime_observation_with_variant(
        fixture,
        intended_status_sequence,
        runtime_snapshot_sequence,
        marker,
        default_observation_variant(fixture),
    )
}

struct RuntimeObservationVariant {
    nonce_token: [u8; RUNTIME_OBSERVATION_TOKEN_BYTES],
    runtime_signing_seed: [u8; 32],
    authority_digest: Digest32,
    observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    challenge_window: (u64, u64),
}

fn default_observation_variant(fixture: &Fixture) -> RuntimeObservationVariant {
    RuntimeObservationVariant {
        nonce_token: OBSERVATION_TOKEN,
        runtime_signing_seed: RUNTIME_SIGNING_SEED,
        authority_digest: fixture.observation_authority.authority_digest(),
        observation_endpoint_ref: fixture.observation_endpoint_ref,
        challenge_window: challenge_window(),
    }
}

fn runtime_observation_with_variant(
    fixture: &Fixture,
    intended_status_sequence: u64,
    runtime_snapshot_sequence: u64,
    marker: u8,
    variant: RuntimeObservationVariant,
) -> RuntimeObservationRequestV1 {
    let (challenge_issued_at_unix_nanos, challenge_expires_at_unix_nanos) =
        variant.challenge_window;
    let nonce = derive_runtime_observation_query_nonce_v1(
        &variant.nonce_token,
        fixture.target,
        variant.observation_endpoint_ref,
        &fixture.observation_authority,
        intended_status_sequence,
        challenge_issued_at_unix_nanos,
        challenge_expires_at_unix_nanos,
    )
    .expect("Node observation query nonce");
    let selector = ReferenceQuerySelectorV1::try_new(
        ReferenceQueryIdV1::from_bytes([marker; 16]),
        fixture.observation_authority.runtime_host_id(),
        SourceScopeRef::from_bytes([0x43; 16]),
        fixture
            .observation_authority
            .serving_baseline()
            .runtime_store_instance_id(),
        ApplyOperationId::from_bytes([0x44; 16]),
        None,
    )
    .expect("query selector");
    let request_claim = ApplyRequestAuthClaim::try_new(
        PrincipalRef::from_bytes([0x45; 16]),
        ApplyAuthKeyRef::from_bytes([0x46; 16]),
        ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
        1,
        nonce.as_bytes(),
    )
    .expect("request auth claim");
    let request_draft = ReferenceQueryRequestDraftV1::try_new(
        selector,
        request_claim,
        MAX_REFERENCE_QUERY_RESPONSE_BYTES as u32,
    )
    .expect("query request draft");
    let controller = SigningKey::from_bytes(&[0x47; 32]);
    let request_signature = controller.sign(
        request_draft
            .signing_transcript()
            .expect("query request transcript")
            .as_bytes(),
    );
    let query_request = request_draft
        .finalize(&request_signature.to_bytes())
        .expect("signed PXQR");

    let baseline = fixture.observation_authority.serving_baseline();
    let serving = ReferenceBootstrapServingIdentityV1::try_new(
        baseline.target(),
        baseline.runtime_store_instance_id(),
        runtime_snapshot_sequence,
        baseline.runtime_host_epoch(),
        baseline.clock_domain(),
        baseline.clock_generation(),
    )
    .expect("query serving facts");
    let operation = ReferenceQueryOperationStateV1::try_new(
        ReferenceQueryOwnerStateV1::Operational,
        None,
        ReferenceQueryOperationLookupV1::Unknown,
    )
    .expect("operation facts");
    let desired = ReferenceQueryDesiredStateV1::try_new(
        ReferenceQueryDesiredHeadV1::None,
        SourcePlanRevision::new(0),
    )
    .expect("desired facts");
    let live = ReferenceQueryLiveFactsV1::try_new(
        ReferenceQueryLiveStateV1::ExactZero,
        0,
        runtime_snapshot_sequence,
        Digest32::from_bytes([0x48; 32]),
    )
    .expect("exact-zero Runtime facts");
    let facts = ReferenceQueryFactsV1::try_new(serving, operation, desired, live)
        .expect("complete Runtime query facts");
    let response_claim = ReferenceQueryResponseAuthClaimV1::try_new(
        fixture.observation_authority.channel(),
        ApplyAuthKeyRef::from_bytes(
            fixture
                .observation_authority
                .apply_endpoint()
                .runtime_response_key_ref(),
        ),
        ApplyAuthAlgorithm::try_new(1).expect("algorithm"),
        1,
    )
    .expect("response auth claim");
    let response_draft = ReferenceQueryResponseDraftV1::try_new(
        &query_request,
        facts,
        fixture.observation_authority.channel(),
        response_claim,
    )
    .expect("response draft");
    let runtime_signer = SigningKey::from_bytes(&variant.runtime_signing_seed);
    let response_signature = runtime_signer.sign(
        response_draft
            .signing_transcript()
            .expect("response transcript")
            .as_bytes(),
    );
    let query_response = response_draft
        .finalize(&response_signature.to_bytes())
        .expect("signed PXQS");
    RuntimeObservationRequestV1::try_new(RuntimeObservationRequestInputV1 {
        intended_status_sequence,
        freshness_budget_nanos: 30_000_000_000,
        runtime_host_id: fixture.observation_authority.runtime_host_id(),
        authority_digest: variant.authority_digest,
        challenge_issued_at_unix_nanos,
        challenge_expires_at_unix_nanos,
        query_request,
        query_response,
    })
    .expect("strict PXNO")
}

fn challenge_window() -> (u64, u64) {
    let issued_at = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos(),
    )
    .expect("Unix nanoseconds fit u64");
    let expires_at = issued_at
        .checked_add(30_000_000_000)
        .expect("challenge deadline fits u64");
    (issued_at, expires_at)
}

fn interrupted_bootstrap_link(final_path: &Path) -> PathBuf {
    let mut builder = Digest32Builder::try_new(
        b"paraegox.node.developer-local-reference.bootstrap-temp.sha256.v1",
    )
    .expect("bootstrap temp digest domain");
    builder
        .field_bytes(final_path.as_os_str().as_bytes())
        .expect("bootstrap final path");
    let digest = builder.finish().into_bytes();
    let discriminator = u64::from_be_bytes(digest[..8].try_into().expect("digest prefix"));
    final_path.parent().expect("bootstrap parent").join(format!(
        ".paraegox-noded-{discriminator:016x}-deadbeef.pxnb.next"
    ))
}

fn observation_exchange(
    socket_path: &Path,
    token: &[u8; RUNTIME_OBSERVATION_TOKEN_BYTES],
    request: &RuntimeObservationRequestV1,
) -> RuntimeObservationAckV1 {
    let mut stream = UnixStream::connect(socket_path).expect("connect observation endpoint");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .expect("bounded observation socket timeouts");
    let frame = local_observation_frame(token, request);
    stream.write_all(&frame).expect("write PXOL/PXNO");
    stream.shutdown(Shutdown::Write).expect("finish PXNO");
    let mut response = [0_u8; RUNTIME_OBSERVATION_ACK_BYTES];
    stream.read_exact(&mut response).expect("read PXNA");
    let mut trailing = [0_u8; 1];
    assert_eq!(stream.read(&mut trailing).expect("PXNA EOF"), 0);
    let ack = RuntimeObservationAckV1::decode(&response).expect("strict PXNA");
    ack.validate_for(request).expect("PXNA correlation");
    ack
}

fn reject_observation_without_response(
    socket_path: &Path,
    token: &[u8; RUNTIME_OBSERVATION_TOKEN_BYTES],
    request: &RuntimeObservationRequestV1,
) {
    let frame = local_observation_frame(token, request);
    let mut stream = UnixStream::connect(socket_path).expect("connect observation endpoint");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .expect("bounded observation socket timeouts");
    stream.write_all(&frame).expect("write rejected PXOL/PXNO");
    stream
        .shutdown(Shutdown::Write)
        .expect("finish rejected PXNO");
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) => {}
        Ok(_) => panic!("rejected observation received response bytes"),
        Err(error) => panic!("rejected observation did not close: {error}"),
    }
}

fn local_observation_frame(
    token: &[u8; RUNTIME_OBSERVATION_TOKEN_BYTES],
    request: &RuntimeObservationRequestV1,
) -> Vec<u8> {
    let mut frame = vec![0_u8; 48 + request.canonical_wire().len()];
    frame[..4].copy_from_slice(b"PXOL");
    frame[4..6].copy_from_slice(&1_u16.to_be_bytes());
    frame[6..8].copy_from_slice(&48_u16.to_be_bytes());
    let frame_length = u32::try_from(frame.len()).expect("observation frame bound");
    let request_length =
        u32::try_from(request.canonical_wire().len()).expect("observation request bound");
    frame[8..12].copy_from_slice(&frame_length.to_be_bytes());
    frame[12..16].copy_from_slice(&request_length.to_be_bytes());
    frame[16..48].copy_from_slice(token);
    frame[48..].copy_from_slice(request.canonical_wire());
    frame
}

fn exchange(
    socket_path: &Path,
    token: &[u8; 32],
    request: &NodeManagementRequestV1,
) -> NodeManagementResponseV1 {
    let mut stream = UnixStream::connect(socket_path).expect("connect local endpoint");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .expect("bounded socket timeouts");
    let frame = local_frame(token, request);
    stream.write_all(&frame).expect("write local frame");
    stream
        .shutdown(Shutdown::Write)
        .expect("finish local request");
    let mut prefix = [0_u8; 12];
    stream.read_exact(&mut prefix).expect("PXNS prefix");
    let total = usize::try_from(u32::from_be_bytes(
        prefix[8..12].try_into().expect("fixed total field"),
    ))
    .expect("response length fits usize");
    assert!((12..=MAX_NODE_MANAGEMENT_RESPONSE_BYTES).contains(&total));
    let mut response = vec![0_u8; total];
    response[..12].copy_from_slice(&prefix);
    stream
        .read_exact(&mut response[12..])
        .expect("bounded PXNS response");
    let mut trailing = [0_u8; 1];
    assert_eq!(stream.read(&mut trailing).expect("response EOF"), 0);
    let decoded = NodeManagementResponseV1::decode(&response).expect("strict PXNS");
    decoded.validate_for(request).expect("request correlation");
    decoded
}

fn reject_without_response(
    socket_path: &Path,
    token: &[u8; 32],
    request: &NodeManagementRequestV1,
    add_trailing_byte: bool,
) {
    let mut stream = UnixStream::connect(socket_path).expect("connect rejected client");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .expect("bounded rejected client");
    let mut frame = local_frame(token, request);
    if add_trailing_byte {
        frame.push(0xff);
    }
    stream.write_all(&frame).expect("write rejected frame");
    stream
        .shutdown(Shutdown::Write)
        .expect("finish rejected request");
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) => {}
        Ok(_) => panic!("rejected request received response bytes"),
        Err(error) => panic!("rejected request did not close: {error}"),
    }
}

fn local_frame(token: &[u8; 32], request: &NodeManagementRequestV1) -> Vec<u8> {
    let mut frame = vec![0_u8; LOCAL_FRAME_BYTES];
    frame[..4].copy_from_slice(b"PXNL");
    frame[4..6].copy_from_slice(&1_u16.to_be_bytes());
    frame[6..8].copy_from_slice(&(LOCAL_HEADER_BYTES as u16).to_be_bytes());
    frame[8..12].copy_from_slice(&(LOCAL_FRAME_BYTES as u32).to_be_bytes());
    frame[12..16].copy_from_slice(&(NODE_MANAGEMENT_REQUEST_BYTES as u32).to_be_bytes());
    frame[16..48].copy_from_slice(token);
    frame[LOCAL_HEADER_BYTES..].copy_from_slice(request.canonical_wire());
    frame
}

fn wait_for_socket(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + PROCESS_WAIT;
    loop {
        if let Ok(metadata) = fs::symlink_metadata(path)
            && metadata.file_type().is_socket()
            && UnixStream::connect(path).is_ok()
        {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll process") {
            panic!("paraegox-noded exited before ready: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "paraegox-noded readiness timeout"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_exit(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + PROCESS_WAIT;
    loop {
        if let Some(status) = child.try_wait().expect("poll process exit") {
            return status;
        }
        assert!(Instant::now() < deadline, "paraegox-noded exit timeout");
        thread::sleep(Duration::from_millis(20));
    }
}
