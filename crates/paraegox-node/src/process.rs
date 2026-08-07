#![cfg(unix)]

//! DeveloperLocal/reference process substrate for one exact NodeDaemon tenure.
//!
//! This is deliberately not a production enrollment or authenticated Zenoh
//! adapter.  An external owner writes one strict, owner-private PXNB bootstrap
//! file containing an already-authorized identity and registration tenure.
//! This process neither allocates nor advances either registration epoch or
//! `NodeIncarnation`; it only reopens the matching durable owner and serves the
//! last immutable PXNS publication over a same-user, token-bound Unix socket.
//! The additive runtime-observation mode verifies Runtime-owned PXQR/PXQS on a
//! separate local capability socket before one atomic status publication. It
//! binds and persists the authenticated absolute expiry in PXNS/PXND, refuses
//! to re-serve the PXNS after that deadline, aggregates multiple Runtime facts
//! under their earliest retained deadline, and can recover a lost exact PXNA
//! without renewing the status. It has no Runtime apply request type,
//! forwarding path, or readiness inference.

use core::{fmt, time::Duration};
use std::ffi::OsString;
use std::fs::{self, File, TryLockError};
use std::future::pending;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::observation::{
    MAX_RUNTIME_OBSERVATION_BOOTSTRAP_BYTES, MAX_RUNTIME_OBSERVATION_REQUEST_BYTES,
    RUNTIME_OBSERVATION_REQUEST_HEADER_BYTES, RUNTIME_OBSERVATION_TOKEN_BYTES,
    RuntimeObservationAckOutcomeV1, RuntimeObservationAckV1, RuntimeObservationBootstrapV1,
    RuntimeObservationError, RuntimeObservationRequestV1,
};
use crate::protocol::{
    MAX_NODE_MANAGEMENT_RESPONSE_BYTES, NODE_MANAGEMENT_REQUEST_BYTES,
    NodeManagementEndpointErrorV1, NodeManagementEndpointV1, NodeManagementRequestV1,
    NodeManagementResponseV1,
};
use crate::store::{
    DurableNodeDaemonV1, DurableRuntimeObservationCommitOutcome, NodeDaemonStoreError,
};
use crate::{
    EnrollmentIssuerRefV1, NodeArchitectureV1, NodeFeatureReportInputV1, NodeFeatureReportV1,
    NodeId, NodeIdentityV1, NodeIncarnation, NodeManagementEndpointRefV1, NodeOperatingSystemV1,
    NodeRegistrationTenureV1,
};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use nix::unistd::{getegid, geteuid};
use paraegox_kernel::{
    digest::{Digest32, Digest32Builder},
    identity::PrincipalRef,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use zeroize::{Zeroize, Zeroizing};

const BOOTSTRAP_MAGIC: &[u8; 4] = b"PXNB";
const LOCAL_REQUEST_MAGIC: &[u8; 4] = b"PXNL";
const LOCAL_OBSERVATION_MAGIC: &[u8; 4] = b"PXOL";
const PROCESS_VERSION: u16 = 1;
const BOOTSTRAP_HEADER_BYTES: usize = 224;
const BOOTSTRAP_DIGEST_OFFSET: usize = 192;
const LOCAL_REQUEST_HEADER_BYTES: usize = 48;
const LOCAL_REQUEST_BYTES: usize = LOCAL_REQUEST_HEADER_BYTES + NODE_MANAGEMENT_REQUEST_BYTES;
const MAX_LOCAL_OBSERVATION_BYTES: usize =
    LOCAL_REQUEST_HEADER_BYTES + MAX_RUNTIME_OBSERVATION_REQUEST_BYTES;
const MAX_STATE_ROOT_BYTES: usize = 1_024;
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;
const MAX_BOOTSTRAP_BYTES: usize =
    BOOTSTRAP_HEADER_BYTES + MAX_STATE_ROOT_BYTES + MAX_UNIX_SOCKET_PATH_BYTES;
/// Fixed secret-token size for the non-production local PXNB/PXNL boundary.
pub const DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES: usize = 32;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_MODE_MASK: u32 = 0o7777;
const MAX_IN_FLIGHT: usize = 16;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest accepted absolute budget for one DeveloperLocal management
/// connect/write/read exchange.
pub const MAX_DEVELOPER_LOCAL_NODE_MANAGEMENT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const BOOTSTRAP_DIGEST_DOMAIN: &[u8] =
    b"paraegox.node.developer-local-reference.bootstrap.sha256.v1";

/// Display-safe failures for the non-production local process boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeDaemonProcessError {
    Usage,
    InvalidPath,
    InsecurePermissions,
    BootstrapUnavailable,
    BootstrapContended,
    BootstrapAlreadyExists,
    BootstrapCommitUncertain,
    InvalidBootstrap,
    BootstrapDigestMismatch,
    Observation(RuntimeObservationError),
    State(NodeDaemonStoreError),
    EndpointAlreadyActive,
    EndpointIdentityChanged,
    EndpointUnavailable,
    SignalUnavailable,
    Io(io::ErrorKind),
}

impl fmt::Display for NodeDaemonProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Usage => {
                "usage: paraegox-noded developer-local-reference-v1 --bootstrap-file <path> | developer-local-runtime-observation-v1 --bootstrap-file <path> --observation-bootstrap-file <path>"
            }
            Self::InvalidPath => "DeveloperLocal NodeDaemon path is invalid",
            Self::InsecurePermissions => {
                "DeveloperLocal NodeDaemon owner-private permissions are invalid"
            }
            Self::BootstrapUnavailable => {
                "DeveloperLocal NodeDaemon bootstrap is unavailable"
            }
            Self::BootstrapContended => {
                "another process owns this DeveloperLocal NodeDaemon bootstrap"
            }
            Self::BootstrapAlreadyExists => {
                "DeveloperLocal NodeDaemon bootstrap already exists"
            }
            Self::BootstrapCommitUncertain => {
                "DeveloperLocal NodeDaemon bootstrap publication is uncertain"
            }
            Self::InvalidBootstrap | Self::BootstrapDigestMismatch => {
                "DeveloperLocal NodeDaemon bootstrap validation failed"
            }
            Self::Observation(_) => {
                "DeveloperLocal NodeDaemon Runtime observation was rejected"
            }
            Self::State(_) => "DeveloperLocal NodeDaemon durable state could not be opened",
            Self::EndpointAlreadyActive => {
                "DeveloperLocal NodeDaemon endpoint is already active"
            }
            Self::EndpointIdentityChanged => {
                "DeveloperLocal NodeDaemon endpoint identity changed"
            }
            Self::EndpointUnavailable => "DeveloperLocal NodeDaemon endpoint failed",
            Self::SignalUnavailable => "DeveloperLocal NodeDaemon signal owner is unavailable",
            Self::Io(_) => "DeveloperLocal NodeDaemon I/O failed",
        })
    }
}

impl std::error::Error for NodeDaemonProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::State(error) => Some(error),
            Self::Observation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<NodeDaemonStoreError> for NodeDaemonProcessError {
    fn from(error: NodeDaemonStoreError) -> Self {
        Self::State(error)
    }
}

impl From<RuntimeObservationError> for NodeDaemonProcessError {
    fn from(error: RuntimeObservationError) -> Self {
        Self::Observation(error)
    }
}

pub struct DeveloperLocalReferenceBootstrapV1 {
    expected_uid: u32,
    expected_gid: u32,
    generation_token: Zeroizing<[u8; DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES]>,
    identity: NodeIdentityV1,
    tenure: NodeRegistrationTenureV1,
    management_endpoint_ref: NodeManagementEndpointRefV1,
    initial_feature_report: NodeFeatureReportV1,
    state_root: PathBuf,
    socket_path: PathBuf,
}

/// Exact externally-owned inputs for one non-production local process.
///
/// `generation_token` is a Secret even though this transport-neutral input
/// uses a fixed byte array. Callers must clear their input after construction.
pub struct DeveloperLocalReferenceBootstrapInputV1 {
    pub expected_uid: u32,
    pub expected_gid: u32,
    pub generation_token: [u8; DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES],
    pub identity: NodeIdentityV1,
    pub tenure: NodeRegistrationTenureV1,
    pub management_endpoint_ref: NodeManagementEndpointRefV1,
    pub initial_feature_report: NodeFeatureReportV1,
    pub state_root: PathBuf,
    pub socket_path: PathBuf,
}

impl fmt::Debug for DeveloperLocalReferenceBootstrapV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperLocalReferenceBootstrapV1")
            .field("expected_uid", &self.expected_uid)
            .field("expected_gid", &self.expected_gid)
            .field("generation_token", &"<redacted>")
            .field("identity", &self.identity)
            .field("tenure", &self.tenure)
            .field("management_endpoint_ref", &self.management_endpoint_ref)
            .field("initial_feature_report", &self.initial_feature_report)
            .field("state_root", &self.state_root)
            .field("socket_path", &self.socket_path)
            .finish()
    }
}

impl DeveloperLocalReferenceBootstrapV1 {
    /// Builds one exact non-production bootstrap supplied by an external
    /// registration owner.
    ///
    /// This constructor never generates a token, identity, registration
    /// epoch, or `NodeIncarnation`. The caller remains responsible for
    /// obtaining those values from its owning authority. The token is copied
    /// into zeroizing storage; the caller must clear any other copy it keeps.
    pub fn try_new(
        mut input: DeveloperLocalReferenceBootstrapInputV1,
    ) -> Result<Self, NodeDaemonProcessError> {
        let generation_token = Zeroizing::new(input.generation_token);
        input.generation_token.zeroize();
        if input.expected_uid != geteuid().as_raw()
            || input.expected_gid != getegid().as_raw()
            || generation_token.iter().all(|byte| *byte == 0)
            || input.identity.node_id() != input.tenure.node_id()
            || input.initial_feature_report.node_id() != input.identity.node_id()
            || input.initial_feature_report.node_incarnation() != input.tenure.node_incarnation()
        {
            return Err(NodeDaemonProcessError::InvalidBootstrap);
        }
        let value = Self {
            expected_uid: input.expected_uid,
            expected_gid: input.expected_gid,
            generation_token,
            identity: input.identity,
            tenure: input.tenure,
            management_endpoint_ref: input.management_endpoint_ref,
            initial_feature_report: input.initial_feature_report,
            state_root: input.state_root,
            socket_path: input.socket_path,
        };
        validate_bootstrap_runtime_paths(&value)?;
        Ok(value)
    }

    /// Strictly decodes the one canonical PXNB-v1 byte representation.
    ///
    /// The input contains the local generation token and must be treated as a
    /// Secret by the caller. Decoding does not acquire registration authority
    /// and does not open or mutate NodeDaemon state.
    pub fn decode_canonical_wire(wire: &[u8]) -> Result<Self, NodeDaemonProcessError> {
        decode_bootstrap(wire)
    }

    /// Encodes the one canonical PXNB-v1 representation in zeroizing memory.
    ///
    /// These bytes contain the local generation token. They must only be
    /// handed to an owner-private file or another equivalently protected
    /// local channel.
    pub fn canonical_wire(&self) -> Result<Zeroizing<Vec<u8>>, NodeDaemonProcessError> {
        encode_bootstrap(self)
    }

    /// Atomically publishes a new owner-private PXNB file without replacing
    /// an existing bootstrap.
    ///
    /// Publication uses a same-directory, owner-private temporary inode and
    /// an atomic no-replace hard link, then synchronizes the directory. The
    /// caller must choose a new path for token/tenure rotation; this method
    /// never overwrites a live generation.
    pub fn write_owner_private_file(&self, path: &Path) -> Result<(), NodeDaemonProcessError> {
        write_bootstrap_file(self, path)
    }

    /// Strictly reopens one owner-private PXNB snapshot for an external local
    /// composition owner.
    ///
    /// The read uses the same private-directory, no-follow, exact-inode and
    /// canonical-wire validation as the process owner. An exclusive advisory
    /// lock is held across that validation and released before this function
    /// returns, so the returned value is a validated snapshot rather than a
    /// NodeDaemon writer lease. A later socket exchange independently re-pins
    /// the live socket inode and same-user peer before sending the secret-
    /// authenticated request.
    pub fn read_owner_private_file(path: &Path) -> Result<Self, NodeDaemonProcessError> {
        let BootstrapLease { _file: file, value } = load_bootstrap(path)?;
        drop(file);
        Ok(value)
    }

    #[must_use]
    pub const fn expected_uid(&self) -> u32 {
        self.expected_uid
    }

    #[must_use]
    pub const fn expected_gid(&self) -> u32 {
        self.expected_gid
    }

    #[must_use]
    pub const fn identity(&self) -> NodeIdentityV1 {
        self.identity
    }

    #[must_use]
    pub const fn tenure(&self) -> NodeRegistrationTenureV1 {
        self.tenure
    }

    #[must_use]
    pub const fn management_endpoint_ref(&self) -> NodeManagementEndpointRefV1 {
        self.management_endpoint_ref
    }

    #[must_use]
    pub const fn initial_feature_report(&self) -> NodeFeatureReportV1 {
        self.initial_feature_report
    }

    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// Display-safe failure for one bounded DeveloperLocal PXNL exchange.
///
/// Variants intentionally contain no socket path, token, request bytes, or
/// response bytes. The transport performs one attempt and never retries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeveloperLocalNodeManagementEndpointErrorV1 {
    InvalidConfiguration,
    InvalidRequest,
    SocketMetadata,
    SocketIdentityChanged,
    PeerCredentialsUnavailable,
    PeerCredentialsMismatch,
    Disconnected,
    Connect,
    Write,
    Read,
    DeadlineExceeded,
    TruncatedResponse,
    ResponseTooLarge,
    TrailingResponseBytes,
    InvalidResponse,
    ExecutorUnavailable,
}

impl fmt::Display for DeveloperLocalNodeManagementEndpointErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => {
                "DeveloperLocal Node management endpoint configuration is invalid"
            }
            Self::InvalidRequest => "DeveloperLocal Node management request is invalid",
            Self::SocketMetadata => "DeveloperLocal Node management socket metadata is invalid",
            Self::SocketIdentityChanged => "DeveloperLocal Node management socket identity changed",
            Self::PeerCredentialsUnavailable => {
                "DeveloperLocal Node management peer credentials are unavailable"
            }
            Self::PeerCredentialsMismatch => {
                "DeveloperLocal Node management peer credentials do not match"
            }
            Self::Disconnected => "DeveloperLocal Node management endpoint is disconnected",
            Self::Connect => "DeveloperLocal Node management connection failed",
            Self::Write => "DeveloperLocal Node management request write failed",
            Self::Read => "DeveloperLocal Node management response read failed",
            Self::DeadlineExceeded => "DeveloperLocal Node management deadline was exceeded",
            Self::TruncatedResponse => "DeveloperLocal Node management response was truncated",
            Self::ResponseTooLarge => "DeveloperLocal Node management response length is invalid",
            Self::TrailingResponseBytes => {
                "DeveloperLocal Node management response has trailing bytes"
            }
            Self::InvalidResponse => "DeveloperLocal Node management response is invalid",
            Self::ExecutorUnavailable => {
                "DeveloperLocal Node management exchange executor is unavailable"
            }
        })
    }
}

impl std::error::Error for DeveloperLocalNodeManagementEndpointErrorV1 {}

impl From<DeveloperLocalNodeManagementEndpointErrorV1> for NodeManagementEndpointErrorV1 {
    fn from(error: DeveloperLocalNodeManagementEndpointErrorV1) -> Self {
        match error {
            DeveloperLocalNodeManagementEndpointErrorV1::InvalidRequest => Self::MalformedRequest,
            DeveloperLocalNodeManagementEndpointErrorV1::InvalidConfiguration
            | DeveloperLocalNodeManagementEndpointErrorV1::SocketMetadata
            | DeveloperLocalNodeManagementEndpointErrorV1::SocketIdentityChanged
            | DeveloperLocalNodeManagementEndpointErrorV1::PeerCredentialsUnavailable
            | DeveloperLocalNodeManagementEndpointErrorV1::PeerCredentialsMismatch
            | DeveloperLocalNodeManagementEndpointErrorV1::Disconnected
            | DeveloperLocalNodeManagementEndpointErrorV1::Connect
            | DeveloperLocalNodeManagementEndpointErrorV1::ExecutorUnavailable => Self::Unavailable,
            DeveloperLocalNodeManagementEndpointErrorV1::Write
            | DeveloperLocalNodeManagementEndpointErrorV1::Read
            | DeveloperLocalNodeManagementEndpointErrorV1::DeadlineExceeded
            | DeveloperLocalNodeManagementEndpointErrorV1::TruncatedResponse
            | DeveloperLocalNodeManagementEndpointErrorV1::ResponseTooLarge
            | DeveloperLocalNodeManagementEndpointErrorV1::TrailingResponseBytes
            | DeveloperLocalNodeManagementEndpointErrorV1::InvalidResponse => {
                Self::ResponseUnavailable
            }
        }
    }
}

/// Same-user, token-authenticated one-shot transport for DeveloperLocal
/// [`crate::protocol::NodeManagementClientV1`].
///
/// Construction borrows a validated PXNB value and copies its capability
/// token directly into zeroizing storage. Each exchange pins the private
/// socket metadata and inode before connecting, revalidates that identity
/// after connect, verifies the server uid/gid, sends one exact PXNL/PXNQ
/// frame, and accepts only one bounded PXNS followed by EOF. Connect, write,
/// and read share one absolute deadline and are never retried.
pub struct DeveloperLocalNodeManagementEndpointV1 {
    socket_path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    generation_token: Zeroizing<[u8; DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES]>,
    exchange_timeout: Duration,
}

impl fmt::Debug for DeveloperLocalNodeManagementEndpointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperLocalNodeManagementEndpointV1")
            .field("socket_path", &"<owner-private>")
            .field("expected_uid", &self.expected_uid)
            .field("expected_gid", &self.expected_gid)
            .field("generation_token", &"<redacted>")
            .field("exchange_timeout", &self.exchange_timeout)
            .finish()
    }
}

impl DeveloperLocalNodeManagementEndpointV1 {
    /// Creates one endpoint without exposing the PXNB generation token.
    pub fn try_from_bootstrap(
        bootstrap: &DeveloperLocalReferenceBootstrapV1,
        exchange_timeout: Duration,
    ) -> Result<Self, DeveloperLocalNodeManagementEndpointErrorV1> {
        if bootstrap.expected_uid != geteuid().as_raw()
            || bootstrap.expected_gid != getegid().as_raw()
            || exchange_timeout.is_zero()
            || exchange_timeout > MAX_DEVELOPER_LOCAL_NODE_MANAGEMENT_EXCHANGE_TIMEOUT
        {
            return Err(DeveloperLocalNodeManagementEndpointErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            socket_path: bootstrap.socket_path.clone(),
            expected_uid: bootstrap.expected_uid,
            expected_gid: bootstrap.expected_gid,
            generation_token: duplicate_token(&bootstrap.generation_token),
            exchange_timeout,
        })
    }

    /// Performs one bounded transport exchange and preserves detailed,
    /// display-safe transport failure classification.
    pub fn exchange_canonical(
        &self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, DeveloperLocalNodeManagementEndpointErrorV1> {
        let request = NodeManagementRequestV1::decode(canonical_request)
            .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::InvalidRequest)?;
        let deadline = Instant::now()
            .checked_add(self.exchange_timeout)
            .ok_or(DeveloperLocalNodeManagementEndpointErrorV1::InvalidConfiguration)?;
        let socket_identity = validate_management_socket_metadata(
            &self.socket_path,
            self.expected_uid,
            self.expected_gid,
        )?;
        let socket_path = self.socket_path.clone();
        let expected_uid = self.expected_uid;
        let expected_gid = self.expected_gid;
        let generation_token = duplicate_token(&self.generation_token);
        let request_wire: Box<[u8]> = request.canonical_wire().into();
        let worker = std::thread::Builder::new()
            .name("paraegox-node-management-exchange".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .map_err(|_| {
                        DeveloperLocalNodeManagementEndpointErrorV1::ExecutorUnavailable
                    })?;
                runtime.block_on(exchange_developer_local_node_management(
                    socket_path,
                    expected_uid,
                    expected_gid,
                    generation_token,
                    request_wire,
                    socket_identity,
                    deadline,
                ))
            })
            .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::ExecutorUnavailable)?;
        let response_wire = worker
            .join()
            .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::ExecutorUnavailable)??;
        let response = NodeManagementResponseV1::decode(&response_wire)
            .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::InvalidResponse)?;
        response
            .validate_for(&request)
            .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::InvalidResponse)?;
        Ok(response_wire)
    }
}

impl NodeManagementEndpointV1 for DeveloperLocalNodeManagementEndpointV1 {
    fn exchange(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, NodeManagementEndpointErrorV1> {
        self.exchange_canonical(canonical_request)
            .map_err(NodeManagementEndpointErrorV1::from)
    }
}

struct BootstrapLease {
    _file: File,
    value: DeveloperLocalReferenceBootstrapV1,
}

struct ObservationBootstrapLease {
    _file: File,
    value: RuntimeObservationBootstrapV1,
}

struct SocketGuard {
    path: PathBuf,
    identity: FileIdentity,
}

struct BootstrapTemporaryGuard {
    path: PathBuf,
    identity: FileIdentity,
    armed: bool,
}

struct TrackedBlockingTasks {
    accepting: AtomicBool,
    tasks: Mutex<Vec<tokio::task::JoinHandle<Result<(), NodeDaemonProcessError>>>>,
}

struct ShutdownSignals {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

impl ShutdownSignals {
    fn install() -> Result<Self, NodeDaemonProcessError> {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| NodeDaemonProcessError::SignalUnavailable)?;
        let interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|_| NodeDaemonProcessError::SignalUnavailable)?;
        Ok(Self {
            terminate,
            interrupt,
        })
    }
}

impl TrackedBlockingTasks {
    fn new() -> Self {
        Self {
            accepting: AtomicBool::new(true),
            tasks: Mutex::new(Vec::with_capacity(MAX_IN_FLIGHT)),
        }
    }

    async fn run<T, F>(&self, operation: F) -> Result<T, NodeDaemonProcessError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, NodeDaemonProcessError> + Send + 'static,
    {
        let finished_tasks = {
            let mut tasks = self
                .tasks
                .lock()
                .map_err(|_| NodeDaemonProcessError::State(NodeDaemonStoreError::Poisoned))?;
            let mut finished = Vec::new();
            let mut index = 0;
            while index < tasks.len() {
                if tasks[index].is_finished() {
                    finished.push(tasks.swap_remove(index));
                } else {
                    index += 1;
                }
            }
            finished
        };
        for task in finished_tasks {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    return Err(NodeDaemonProcessError::State(
                        NodeDaemonStoreError::Poisoned,
                    ));
                }
            }
        }
        let receiver = {
            let mut tasks = self
                .tasks
                .lock()
                .map_err(|_| NodeDaemonProcessError::State(NodeDaemonStoreError::Poisoned))?;
            if !self.accepting.load(Ordering::Acquire) {
                return Err(NodeDaemonProcessError::EndpointUnavailable);
            }
            let (sender, receiver) = oneshot::channel();
            tasks.push(tokio::task::spawn_blocking(move || {
                let outcome = operation();
                let tracked_outcome = match &outcome {
                    Err(error) if fatal_process_error(*error) => Err(*error),
                    _ => Ok(()),
                };
                let _ = sender.send(outcome);
                tracked_outcome
            }));
            receiver
        };
        match receiver.await {
            Ok(outcome) => outcome,
            Err(_) => Err(NodeDaemonProcessError::State(
                NodeDaemonStoreError::Poisoned,
            )),
        }
    }

    fn close(&self) -> Result<(), NodeDaemonProcessError> {
        let (tasks, poisoned) = match self.tasks.lock() {
            Ok(tasks) => (tasks, false),
            Err(error) => (error.into_inner(), true),
        };
        self.accepting.store(false, Ordering::Release);
        drop(tasks);
        if poisoned {
            Err(NodeDaemonProcessError::State(
                NodeDaemonStoreError::Poisoned,
            ))
        } else {
            Ok(())
        }
    }

    fn ensure_open(&self) -> Result<(), NodeDaemonProcessError> {
        if self.accepting.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(NodeDaemonProcessError::EndpointUnavailable)
        }
    }

    async fn join_closed(&self) -> Result<(), NodeDaemonProcessError> {
        let (tasks, poisoned) = {
            let (mut tasks, poisoned) = match self.tasks.lock() {
                Ok(tasks) => (tasks, false),
                Err(error) => (error.into_inner(), true),
            };
            self.accepting.store(false, Ordering::Release);
            (core::mem::take(&mut *tasks), poisoned)
        };
        let mut join_error = poisoned.then_some(NodeDaemonProcessError::State(
            NodeDaemonStoreError::Poisoned,
        ));
        for task in tasks {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if join_error.is_none() => join_error = Some(error),
                Err(_) if join_error.is_none() => {
                    join_error = Some(NodeDaemonProcessError::State(
                        NodeDaemonStoreError::Poisoned,
                    ));
                }
                _ => {}
            }
        }
        join_error.map_or(Ok(()), Err)
    }
}

impl Drop for BootstrapTemporaryGuard {
    fn drop(&mut self) {
        if self.armed {
            remove_same_regular_file(&self.path, self.identity);
        }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && FileIdentity::from_metadata(&metadata) == self.identity
        {
            let _ = fs::remove_file(&self.path);
            let _ = sync_parent(&self.path);
        }
    }
}

/// Runs the non-production local process for one owner-private PXNB file.
///
/// The call blocks until SIGINT/SIGTERM, closes its listener before the
/// bounded connection drain, and joins every started durable-owner operation
/// before releasing the PXND writer. It opens the existing durable tenure
/// without publishing a new `NodeStatus`; Latest/Watch can therefore return
/// only the last snapshot previously committed by the real Node observation
/// owner (or NotFound). Signal ownership is installed before the socket is
/// bound. Socket visibility alone is not process readiness; the local
/// composition owner must still complete one typed Latest exchange.
pub fn serve_developer_local_reference_node_daemon_v1(
    bootstrap_path: &Path,
) -> Result<(), NodeDaemonProcessError> {
    let lease = load_bootstrap(bootstrap_path)?;
    let owner = DurableNodeDaemonV1::open(
        &lease.value.state_root,
        lease.value.identity,
        lease.value.tenure,
        lease.value.management_endpoint_ref,
        lease.value.initial_feature_report,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| NodeDaemonProcessError::EndpointUnavailable)?;
    let signals = runtime.block_on(async { ShutdownSignals::install() })?;
    let (standard_listener, socket_guard) = bind_endpoint(&lease.value)?;
    let result = runtime.block_on(serve_endpoint(
        standard_listener,
        None,
        owner,
        &lease.value,
        signals,
    ));
    runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    result?;
    drop(socket_guard);
    drop(lease);
    Ok(())
}

/// Runs the same durable NodeDaemon owner with separate read-only PXNQ/PXNS
/// and authenticated PXNO mutation sockets. Signal ownership is installed
/// before either socket is bound; a typed Latest exchange remains the local
/// composition readiness boundary.
pub fn serve_developer_local_runtime_observation_node_daemon_v1(
    bootstrap_path: &Path,
    observation_bootstrap_path: &Path,
) -> Result<(), NodeDaemonProcessError> {
    if bootstrap_path == observation_bootstrap_path {
        return Err(NodeDaemonProcessError::InvalidPath);
    }
    let lease = load_bootstrap(bootstrap_path)?;
    let observation_lease = load_observation_bootstrap(observation_bootstrap_path)?;
    validate_observation_correlation(&lease.value, &observation_lease.value)?;
    let owner = DurableNodeDaemonV1::open(
        &lease.value.state_root,
        lease.value.identity,
        lease.value.tenure,
        lease.value.management_endpoint_ref,
        lease.value.initial_feature_report,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| NodeDaemonProcessError::EndpointUnavailable)?;
    let signals = runtime.block_on(async { ShutdownSignals::install() })?;
    let (standard_listener, socket_guard) = bind_endpoint(&lease.value)?;
    let (observation_listener, observation_socket_guard) = bind_socket_endpoint(
        observation_lease.value.socket_path(),
        observation_lease.value.expected_uid(),
        observation_lease.value.expected_gid(),
    )?;
    let ObservationBootstrapLease {
        _file: observation_file,
        value: observation_value,
    } = observation_lease;
    let observation_value = Arc::new(observation_value);
    let result = runtime.block_on(serve_endpoint(
        standard_listener,
        Some((observation_listener, Arc::clone(&observation_value))),
        owner,
        &lease.value,
        signals,
    ));
    runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    result?;
    drop(observation_value);
    drop(observation_file);
    drop(observation_socket_guard);
    drop(socket_guard);
    drop(lease);
    Ok(())
}

fn load_bootstrap(path: &Path) -> Result<BootstrapLease, NodeDaemonProcessError> {
    validate_lexical_absolute_path(path, MAX_STATE_ROOT_BYTES)?;
    let expected_uid = geteuid().as_raw();
    let expected_gid = getegid().as_raw();
    let parent = path.parent().ok_or(NodeDaemonProcessError::InvalidPath)?;
    validate_private_directory(parent, expected_uid, expected_gid)?;

    let mut named_before =
        fs::symlink_metadata(path).map_err(|_| NodeDaemonProcessError::BootstrapUnavailable)?;
    if named_before.nlink() == 2 {
        recover_interrupted_bootstrap_publication(path, expected_uid, expected_gid)?;
        named_before =
            fs::symlink_metadata(path).map_err(|_| NodeDaemonProcessError::BootstrapUnavailable)?;
    }
    validate_private_regular_file(&named_before, expected_uid, expected_gid)?;
    let named_identity = FileIdentity::from_metadata(&named_before);
    let owned = open(
        path,
        OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| NodeDaemonProcessError::BootstrapUnavailable)?;
    let mut file = File::from(owned);
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(NodeDaemonProcessError::BootstrapContended);
        }
        Err(TryLockError::Error(error)) => {
            return Err(NodeDaemonProcessError::Io(error.kind()));
        }
    }
    let opened = file
        .metadata()
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    validate_private_regular_file(&opened, expected_uid, expected_gid)?;
    let length =
        usize::try_from(opened.len()).map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    if FileIdentity::from_metadata(&opened) != named_identity
        || !(BOOTSTRAP_HEADER_BYTES..=MAX_BOOTSTRAP_BYTES).contains(&length)
    {
        return Err(NodeDaemonProcessError::EndpointIdentityChanged);
    }
    let mut wire = Zeroizing::new(vec![0_u8; length]);
    file.read_exact(wire.as_mut_slice())
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?
        != 0
    {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let named_after =
        fs::symlink_metadata(path).map_err(|_| NodeDaemonProcessError::EndpointIdentityChanged)?;
    if FileIdentity::from_metadata(&named_after) != named_identity {
        return Err(NodeDaemonProcessError::EndpointIdentityChanged);
    }
    let value = decode_bootstrap(&wire)?;
    if value.expected_uid != expected_uid || value.expected_gid != expected_gid {
        return Err(NodeDaemonProcessError::InsecurePermissions);
    }
    validate_runtime_paths(&value, path)?;
    Ok(BootstrapLease { _file: file, value })
}

fn load_observation_bootstrap(
    file_path: &Path,
) -> Result<ObservationBootstrapLease, NodeDaemonProcessError> {
    validate_lexical_absolute_path(file_path, MAX_STATE_ROOT_BYTES)?;
    let expected_uid = geteuid().as_raw();
    let expected_gid = getegid().as_raw();
    let parent = file_path
        .parent()
        .ok_or(NodeDaemonProcessError::InvalidPath)?;
    validate_private_directory(parent, expected_uid, expected_gid)?;
    let mut named_before = fs::symlink_metadata(file_path)
        .map_err(|_| NodeDaemonProcessError::BootstrapUnavailable)?;
    if named_before.nlink() == 2 {
        recover_interrupted_bootstrap_publication(file_path, expected_uid, expected_gid)?;
        named_before = fs::symlink_metadata(file_path)
            .map_err(|_| NodeDaemonProcessError::BootstrapUnavailable)?;
    }
    validate_private_regular_file(&named_before, expected_uid, expected_gid)?;
    let named_identity = FileIdentity::from_metadata(&named_before);
    let owned = open(
        file_path,
        OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| NodeDaemonProcessError::BootstrapUnavailable)?;
    let mut file = File::from(owned);
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(NodeDaemonProcessError::BootstrapContended);
        }
        Err(TryLockError::Error(error)) => {
            return Err(NodeDaemonProcessError::Io(error.kind()));
        }
    }
    let opened = file
        .metadata()
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    validate_private_regular_file(&opened, expected_uid, expected_gid)?;
    let length =
        usize::try_from(opened.len()).map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    if FileIdentity::from_metadata(&opened) != named_identity
        || !(160..=MAX_RUNTIME_OBSERVATION_BOOTSTRAP_BYTES).contains(&length)
    {
        return Err(NodeDaemonProcessError::EndpointIdentityChanged);
    }
    let mut wire = Zeroizing::new(vec![0_u8; length]);
    file.read_exact(wire.as_mut_slice())
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?
        != 0
    {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let named_after = fs::symlink_metadata(file_path)
        .map_err(|_| NodeDaemonProcessError::EndpointIdentityChanged)?;
    if FileIdentity::from_metadata(&named_after) != named_identity {
        return Err(NodeDaemonProcessError::EndpointIdentityChanged);
    }
    let value = RuntimeObservationBootstrapV1::decode_canonical_wire(&wire)?;
    if value.expected_uid() != expected_uid || value.expected_gid() != expected_gid {
        return Err(NodeDaemonProcessError::InsecurePermissions);
    }
    let socket_parent = value
        .socket_path()
        .parent()
        .ok_or(NodeDaemonProcessError::InvalidPath)?;
    validate_private_directory(socket_parent, expected_uid, expected_gid)?;
    if value.socket_path() == file_path {
        return Err(NodeDaemonProcessError::InvalidPath);
    }
    Ok(ObservationBootstrapLease { _file: file, value })
}

fn validate_observation_correlation(
    node: &DeveloperLocalReferenceBootstrapV1,
    observation: &RuntimeObservationBootstrapV1,
) -> Result<(), NodeDaemonProcessError> {
    let target = observation.node_target();
    if target.node_id() != node.identity.node_id()
        || target.node_incarnation() != node.tenure.node_incarnation()
        || target.registration_epoch() != node.tenure.registration_epoch()
        || target.management_endpoint_ref() != node.management_endpoint_ref
        || constant_time_eq(
            node.generation_token.as_ref(),
            observation.generation_token().as_ref(),
        )
        || observation.socket_path() == node.socket_path
        || observation.socket_path() == node.state_root
        || observation.socket_path().starts_with(&node.state_root)
    {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    Ok(())
}

fn decode_bootstrap(
    wire: &[u8],
) -> Result<DeveloperLocalReferenceBootstrapV1, NodeDaemonProcessError> {
    if wire.len() < BOOTSTRAP_HEADER_BYTES
        || wire.len() > MAX_BOOTSTRAP_BYTES
        || &wire[..4] != BOOTSTRAP_MAGIC
        || read_u16(wire, 4) != PROCESS_VERSION
        || usize::from(read_u16(wire, 6)) != BOOTSTRAP_HEADER_BYTES
        || usize::try_from(read_u32(wire, 8)).ok() != Some(wire.len())
        || wire[158..160].iter().any(|byte| *byte != 0)
    {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let state_root_length = usize::from(read_u16(wire, 12));
    let socket_path_length = usize::from(read_u16(wire, 14));
    if state_root_length == 0
        || state_root_length > MAX_STATE_ROOT_BYTES
        || socket_path_length == 0
        || socket_path_length > MAX_UNIX_SOCKET_PATH_BYTES
        || BOOTSTRAP_HEADER_BYTES
            .checked_add(state_root_length)
            .and_then(|length| length.checked_add(socket_path_length))
            != Some(wire.len())
    {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let expected_uid = read_u32(wire, 16);
    let expected_gid = read_u32(wire, 20);
    let generation_token = Zeroizing::new(copy_array::<DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES>(
        wire, 24,
    ));
    if generation_token.iter().all(|byte| *byte == 0) {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let node_id = NodeId::try_from_bytes(copy_array::<16>(wire, 56))
        .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    let identity = NodeIdentityV1::try_new(
        node_id,
        PrincipalRef::from_bytes(copy_array::<16>(wire, 72)),
        EnrollmentIssuerRefV1::try_from_bytes(copy_array::<16>(wire, 88))
            .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?,
    )
    .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    let node_incarnation = NodeIncarnation::try_from_bytes(copy_array::<16>(wire, 112))
        .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    let tenure = NodeRegistrationTenureV1::try_new(node_id, read_u64(wire, 104), node_incarnation)
        .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    let management_endpoint_ref =
        NodeManagementEndpointRefV1::try_from_bytes(copy_array::<16>(wire, 128))
            .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    let operating_system = match wire[152] {
        1 => NodeOperatingSystemV1::Linux,
        2 => NodeOperatingSystemV1::MacOs,
        3 => NodeOperatingSystemV1::Windows,
        _ => return Err(NodeDaemonProcessError::InvalidBootstrap),
    };
    let architecture = match wire[153] {
        1 => NodeArchitectureV1::X86_64,
        2 => NodeArchitectureV1::Aarch64,
        _ => return Err(NodeDaemonProcessError::InvalidBootstrap),
    };
    let initial_feature_report = NodeFeatureReportV1::try_new(NodeFeatureReportInputV1 {
        node_id,
        node_incarnation,
        report_sequence: read_u64(wire, 144),
        operating_system,
        architecture,
        platform_profile_digest: Digest32::from_bytes(copy_array::<32>(wire, 160)),
        runtime_contract_version: read_u16(wire, 154),
        fabric_contract_version: read_u16(wire, 156),
    })
    .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    let state_root_start = BOOTSTRAP_HEADER_BYTES;
    let socket_path_start = state_root_start + state_root_length;
    let state_root = PathBuf::from(OsString::from_vec(
        wire[state_root_start..socket_path_start].to_vec(),
    ));
    let socket_path = PathBuf::from(OsString::from_vec(wire[socket_path_start..].to_vec()));
    let value = DeveloperLocalReferenceBootstrapV1 {
        expected_uid,
        expected_gid,
        generation_token,
        identity,
        tenure,
        management_endpoint_ref,
        initial_feature_report,
        state_root,
        socket_path,
    };
    validate_bootstrap_runtime_paths(&value)?;
    let expected_digest = bootstrap_digest(&value)?;
    if !constant_time_eq(
        expected_digest.as_bytes(),
        &wire[BOOTSTRAP_DIGEST_OFFSET..BOOTSTRAP_HEADER_BYTES],
    ) {
        return Err(NodeDaemonProcessError::BootstrapDigestMismatch);
    }
    let canonical = encode_bootstrap(&value)?;
    if !constant_time_eq(canonical.as_ref(), wire) {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    Ok(value)
}

fn encode_bootstrap(
    value: &DeveloperLocalReferenceBootstrapV1,
) -> Result<Zeroizing<Vec<u8>>, NodeDaemonProcessError> {
    validate_bootstrap_runtime_paths(value)?;
    let state_root = value.state_root.as_os_str().as_bytes();
    let socket_path = value.socket_path.as_os_str().as_bytes();
    let total_length = BOOTSTRAP_HEADER_BYTES
        .checked_add(state_root.len())
        .and_then(|length| length.checked_add(socket_path.len()))
        .ok_or(NodeDaemonProcessError::InvalidBootstrap)?;
    if total_length > MAX_BOOTSTRAP_BYTES {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let mut wire = Zeroizing::new(vec![0_u8; total_length]);
    wire[..4].copy_from_slice(BOOTSTRAP_MAGIC);
    write_u16(&mut wire, 4, PROCESS_VERSION);
    write_u16(
        &mut wire,
        6,
        u16::try_from(BOOTSTRAP_HEADER_BYTES)
            .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?,
    );
    write_u32(
        &mut wire,
        8,
        u32::try_from(total_length).map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?,
    );
    write_u16(
        &mut wire,
        12,
        u16::try_from(state_root.len()).map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?,
    );
    write_u16(
        &mut wire,
        14,
        u16::try_from(socket_path.len()).map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?,
    );
    write_u32(&mut wire, 16, value.expected_uid);
    write_u32(&mut wire, 20, value.expected_gid);
    wire[24..56].copy_from_slice(value.generation_token.as_ref());
    wire[56..72].copy_from_slice(value.identity.node_id().as_bytes());
    wire[72..88].copy_from_slice(value.identity.principal().as_bytes());
    wire[88..104].copy_from_slice(value.identity.enrollment_issuer().as_bytes());
    write_u64(&mut wire, 104, value.tenure.registration_epoch());
    wire[112..128].copy_from_slice(value.tenure.node_incarnation().as_bytes());
    wire[128..144].copy_from_slice(value.management_endpoint_ref.as_bytes());
    write_u64(
        &mut wire,
        144,
        value.initial_feature_report.report_sequence(),
    );
    wire[152] = value.initial_feature_report.operating_system() as u8;
    wire[153] = value.initial_feature_report.architecture() as u8;
    write_u16(
        &mut wire,
        154,
        value.initial_feature_report.runtime_contract_version(),
    );
    write_u16(
        &mut wire,
        156,
        value.initial_feature_report.fabric_contract_version(),
    );
    wire[160..192].copy_from_slice(
        value
            .initial_feature_report
            .platform_profile_digest()
            .as_bytes(),
    );
    let digest = bootstrap_digest(value)?;
    wire[BOOTSTRAP_DIGEST_OFFSET..BOOTSTRAP_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    let state_root_end = BOOTSTRAP_HEADER_BYTES + state_root.len();
    wire[BOOTSTRAP_HEADER_BYTES..state_root_end].copy_from_slice(state_root);
    wire[state_root_end..].copy_from_slice(socket_path);
    Ok(wire)
}

fn write_bootstrap_file(
    value: &DeveloperLocalReferenceBootstrapV1,
    path: &Path,
) -> Result<(), NodeDaemonProcessError> {
    validate_lexical_absolute_path(path, MAX_STATE_ROOT_BYTES)?;
    if path == value.state_root || path == value.socket_path {
        return Err(NodeDaemonProcessError::InvalidPath);
    }
    let parent = path.parent().ok_or(NodeDaemonProcessError::InvalidPath)?;
    validate_private_directory(parent, value.expected_uid, value.expected_gid)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(metadata) => {
            if metadata.nlink() == 2 {
                recover_interrupted_bootstrap_publication(
                    path,
                    value.expected_uid,
                    value.expected_gid,
                )?;
            }
            return Err(NodeDaemonProcessError::BootstrapAlreadyExists);
        }
        Err(error) => return Err(NodeDaemonProcessError::Io(error.kind())),
    }
    let temporary_path = bootstrap_temporary_path(path)?;
    let wire = value.canonical_wire()?;
    let owned = open(
        &temporary_path,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|error| {
        if error == nix::errno::Errno::EEXIST {
            NodeDaemonProcessError::BootstrapAlreadyExists
        } else {
            NodeDaemonProcessError::Io(io::Error::from(error).kind())
        }
    })?;
    let mut temporary = File::from(owned);
    let created_metadata = temporary
        .metadata()
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    let identity = FileIdentity::from_metadata(&created_metadata);
    let mut guard = BootstrapTemporaryGuard {
        path: temporary_path.clone(),
        identity,
        armed: true,
    };
    temporary
        .set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .and_then(|()| temporary.write_all(wire.as_ref()))
        .and_then(|()| temporary.sync_all())
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    let temporary_metadata = temporary
        .metadata()
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    validate_private_regular_file(&temporary_metadata, value.expected_uid, value.expected_gid)?;
    if FileIdentity::from_metadata(&temporary_metadata) != identity {
        return Err(NodeDaemonProcessError::EndpointIdentityChanged);
    }
    fs::hard_link(&temporary_path, path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            NodeDaemonProcessError::BootstrapAlreadyExists
        } else {
            NodeDaemonProcessError::Io(error.kind())
        }
    })?;
    let linked =
        fs::symlink_metadata(path).map_err(|_| NodeDaemonProcessError::BootstrapCommitUncertain)?;
    if FileIdentity::from_metadata(&linked) != identity || linked.nlink() != 2 {
        return Err(NodeDaemonProcessError::BootstrapCommitUncertain);
    }
    fs::remove_file(&temporary_path)
        .map_err(|_| NodeDaemonProcessError::BootstrapCommitUncertain)?;
    guard.armed = false;
    sync_parent(path).map_err(|_| NodeDaemonProcessError::BootstrapCommitUncertain)?;
    let published =
        fs::symlink_metadata(path).map_err(|_| NodeDaemonProcessError::BootstrapCommitUncertain)?;
    validate_private_regular_file(&published, value.expected_uid, value.expected_gid)
        .map_err(|_| NodeDaemonProcessError::BootstrapCommitUncertain)?;
    if FileIdentity::from_metadata(&published) != identity {
        return Err(NodeDaemonProcessError::BootstrapCommitUncertain);
    }
    Ok(())
}

pub(crate) fn write_owner_private_canonical_file_v1(
    file_path: &Path,
    wire: &[u8],
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), NodeDaemonProcessError> {
    validate_lexical_absolute_path(file_path, MAX_STATE_ROOT_BYTES)?;
    let parent = file_path
        .parent()
        .ok_or(NodeDaemonProcessError::InvalidPath)?;
    validate_private_directory(parent, expected_uid, expected_gid)?;
    match fs::symlink_metadata(file_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(metadata) => {
            if metadata.nlink() == 2 {
                recover_interrupted_bootstrap_publication(file_path, expected_uid, expected_gid)?;
            }
            return Err(NodeDaemonProcessError::BootstrapAlreadyExists);
        }
        Err(error) => return Err(NodeDaemonProcessError::Io(error.kind())),
    }
    let temporary_path = bootstrap_temporary_path(file_path)?;
    let owned = open(
        &temporary_path,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|error| {
        if error == nix::errno::Errno::EEXIST {
            NodeDaemonProcessError::BootstrapAlreadyExists
        } else {
            NodeDaemonProcessError::Io(io::Error::from(error).kind())
        }
    })?;
    let mut temporary = File::from(owned);
    let created_metadata = temporary
        .metadata()
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    let identity = FileIdentity::from_metadata(&created_metadata);
    let mut guard = BootstrapTemporaryGuard {
        path: temporary_path.clone(),
        identity,
        armed: true,
    };
    temporary
        .set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .and_then(|()| temporary.write_all(wire))
        .and_then(|()| temporary.sync_all())
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    let temporary_metadata = temporary
        .metadata()
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    validate_private_regular_file(&temporary_metadata, expected_uid, expected_gid)?;
    if FileIdentity::from_metadata(&temporary_metadata) != identity {
        return Err(NodeDaemonProcessError::EndpointIdentityChanged);
    }
    fs::hard_link(&temporary_path, file_path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            NodeDaemonProcessError::BootstrapAlreadyExists
        } else {
            NodeDaemonProcessError::Io(error.kind())
        }
    })?;
    let linked = fs::symlink_metadata(file_path)
        .map_err(|_| NodeDaemonProcessError::BootstrapCommitUncertain)?;
    if FileIdentity::from_metadata(&linked) != identity || linked.nlink() != 2 {
        return Err(NodeDaemonProcessError::BootstrapCommitUncertain);
    }
    fs::remove_file(&temporary_path)
        .map_err(|_| NodeDaemonProcessError::BootstrapCommitUncertain)?;
    guard.armed = false;
    sync_parent(file_path).map_err(|_| NodeDaemonProcessError::BootstrapCommitUncertain)?;
    let published = fs::symlink_metadata(file_path)
        .map_err(|_| NodeDaemonProcessError::BootstrapCommitUncertain)?;
    validate_private_regular_file(&published, expected_uid, expected_gid)
        .map_err(|_| NodeDaemonProcessError::BootstrapCommitUncertain)?;
    if FileIdentity::from_metadata(&published) != identity {
        return Err(NodeDaemonProcessError::BootstrapCommitUncertain);
    }
    Ok(())
}

fn bootstrap_temporary_path(path: &Path) -> Result<PathBuf, NodeDaemonProcessError> {
    let parent = path.parent().ok_or(NodeDaemonProcessError::InvalidPath)?;
    let discriminator = bootstrap_temporary_discriminator(path)?;
    Ok(parent.join(format!(
        ".paraegox-noded-{discriminator:016x}-{:08x}.pxnb.next",
        std::process::id()
    )))
}

fn bootstrap_temporary_discriminator(path: &Path) -> Result<u64, NodeDaemonProcessError> {
    let mut builder = Digest32Builder::try_new(
        b"paraegox.node.developer-local-reference.bootstrap-temp.sha256.v1",
    )
    .map_err(|_| NodeDaemonProcessError::InvalidPath)?;
    builder
        .field_bytes(path.as_os_str().as_bytes())
        .map_err(|_| NodeDaemonProcessError::InvalidPath)?;
    let digest = builder.finish().into_bytes();
    Ok(u64::from_be_bytes(copy_array::<8>(&digest, 0)))
}

fn recover_interrupted_bootstrap_publication(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), NodeDaemonProcessError> {
    let parent = path.parent().ok_or(NodeDaemonProcessError::InvalidPath)?;
    validate_private_directory(parent, expected_uid, expected_gid)?;
    let final_metadata =
        fs::symlink_metadata(path).map_err(|_| NodeDaemonProcessError::EndpointIdentityChanged)?;
    let identity = FileIdentity::from_metadata(&final_metadata);
    if final_metadata.nlink() == 1 {
        return validate_recovered_bootstrap_publication(
            path,
            identity,
            expected_uid,
            expected_gid,
        );
    }
    validate_private_regular_file_with_links(&final_metadata, expected_uid, expected_gid, 2)?;
    let discriminator = bootstrap_temporary_discriminator(path)?;
    let prefix = format!(".paraegox-noded-{discriminator:016x}-");
    let suffix = b".pxnb.next";
    let mut matching_path = None;
    for entry in fs::read_dir(parent).map_err(|error| NodeDaemonProcessError::Io(error.kind()))? {
        let entry = entry.map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
        let name = entry.file_name();
        let name = name.as_os_str().as_bytes();
        if name.len() != prefix.len() + 8 + suffix.len()
            || !name.starts_with(prefix.as_bytes())
            || !name.ends_with(suffix)
            || !name[prefix.len()..prefix.len() + 8]
                .iter()
                .all(u8::is_ascii_hexdigit)
        {
            continue;
        }
        let candidate = entry.path();
        if candidate == path {
            continue;
        }
        let metadata = match fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(NodeDaemonProcessError::EndpointIdentityChanged),
        };
        if FileIdentity::from_metadata(&metadata) != identity {
            continue;
        }
        validate_private_regular_file_with_links(&metadata, expected_uid, expected_gid, 2)?;
        if matching_path.replace(candidate).is_some() {
            return Err(NodeDaemonProcessError::InsecurePermissions);
        }
    }
    let Some(temporary_path) = matching_path else {
        return validate_recovered_bootstrap_publication(
            path,
            identity,
            expected_uid,
            expected_gid,
        );
    };
    let final_before =
        fs::symlink_metadata(path).map_err(|_| NodeDaemonProcessError::EndpointIdentityChanged)?;
    let temporary_before = match fs::symlink_metadata(&temporary_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return validate_recovered_bootstrap_publication(
                path,
                identity,
                expected_uid,
                expected_gid,
            );
        }
        Err(_) => return Err(NodeDaemonProcessError::EndpointIdentityChanged),
    };
    if FileIdentity::from_metadata(&final_before) != identity
        || FileIdentity::from_metadata(&temporary_before) != identity
        || final_before.nlink() != 2
        || temporary_before.nlink() != 2
    {
        return Err(NodeDaemonProcessError::EndpointIdentityChanged);
    }
    if let Err(error) = fs::remove_file(&temporary_path) {
        if error.kind() == io::ErrorKind::NotFound {
            return validate_recovered_bootstrap_publication(
                path,
                identity,
                expected_uid,
                expected_gid,
            );
        }
        return Err(NodeDaemonProcessError::Io(error.kind()));
    }
    sync_parent(path)?;
    validate_recovered_bootstrap_publication(path, identity, expected_uid, expected_gid)
}

fn validate_recovered_bootstrap_publication(
    path: &Path,
    identity: FileIdentity,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), NodeDaemonProcessError> {
    let recovered =
        fs::symlink_metadata(path).map_err(|_| NodeDaemonProcessError::EndpointIdentityChanged)?;
    if FileIdentity::from_metadata(&recovered) != identity {
        return Err(NodeDaemonProcessError::EndpointIdentityChanged);
    }
    validate_private_regular_file(&recovered, expected_uid, expected_gid)
}

fn bootstrap_digest(
    value: &DeveloperLocalReferenceBootstrapV1,
) -> Result<Digest32, NodeDaemonProcessError> {
    let state_root = value.state_root.as_os_str().as_bytes();
    let socket_path = value.socket_path.as_os_str().as_bytes();
    let max_in_flight =
        u16::try_from(MAX_IN_FLIGHT).map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    let io_timeout_nanos = u64::try_from(IO_TIMEOUT.as_nanos())
        .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    let mut builder = Digest32Builder::try_new(BOOTSTRAP_DIGEST_DOMAIN)
        .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    builder
        .field_u16(PROCESS_VERSION)
        .and_then(|builder| builder.field_bytes(&value.expected_uid.to_be_bytes()))
        .and_then(|builder| builder.field_bytes(&value.expected_gid.to_be_bytes()))
        .and_then(|builder| builder.field_bytes(value.generation_token.as_ref()))
        .and_then(|builder| builder.field_bytes(value.identity.node_id().as_bytes()))
        .and_then(|builder| builder.field_bytes(value.identity.principal().as_bytes()))
        .and_then(|builder| builder.field_bytes(value.identity.enrollment_issuer().as_bytes()))
        .and_then(|builder| builder.field_u64(value.tenure.registration_epoch()))
        .and_then(|builder| builder.field_bytes(value.tenure.node_incarnation().as_bytes()))
        .and_then(|builder| builder.field_bytes(value.management_endpoint_ref.as_bytes()))
        .and_then(|builder| builder.field_u64(value.initial_feature_report.report_sequence()))
        .and_then(|builder| {
            builder.field_u16(u16::from(
                value.initial_feature_report.operating_system() as u8
            ))
        })
        .and_then(|builder| {
            builder.field_u16(u16::from(value.initial_feature_report.architecture() as u8))
        })
        .and_then(|builder| {
            builder.field_u16(value.initial_feature_report.runtime_contract_version())
        })
        .and_then(|builder| {
            builder.field_u16(value.initial_feature_report.fabric_contract_version())
        })
        .and_then(|builder| {
            builder.field_digest(&value.initial_feature_report.platform_profile_digest())
        })
        .and_then(|builder| builder.field_u16(max_in_flight))
        .and_then(|builder| builder.field_u64(io_timeout_nanos))
        .and_then(|builder| builder.field_bytes(state_root))
        .and_then(|builder| builder.field_bytes(socket_path))
        .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    Ok(builder.finish())
}

fn validate_runtime_paths(
    value: &DeveloperLocalReferenceBootstrapV1,
    bootstrap_path: &Path,
) -> Result<(), NodeDaemonProcessError> {
    validate_bootstrap_runtime_paths(value)?;
    if value.state_root == bootstrap_path || value.socket_path == bootstrap_path {
        return Err(NodeDaemonProcessError::InvalidPath);
    }
    Ok(())
}

fn validate_bootstrap_runtime_paths(
    value: &DeveloperLocalReferenceBootstrapV1,
) -> Result<(), NodeDaemonProcessError> {
    validate_lexical_absolute_path(&value.state_root, MAX_STATE_ROOT_BYTES)?;
    validate_lexical_absolute_path(&value.socket_path, MAX_UNIX_SOCKET_PATH_BYTES)?;
    if value.state_root == value.socket_path || value.socket_path.starts_with(&value.state_root) {
        return Err(NodeDaemonProcessError::InvalidPath);
    }
    let state_parent = value
        .state_root
        .parent()
        .ok_or(NodeDaemonProcessError::InvalidPath)?;
    validate_existing_path_chain(state_parent)?;
    let socket_parent = value
        .socket_path
        .parent()
        .ok_or(NodeDaemonProcessError::InvalidPath)?;
    validate_private_directory(socket_parent, value.expected_uid, value.expected_gid)?;
    Ok(())
}

fn bind_endpoint(
    bootstrap: &DeveloperLocalReferenceBootstrapV1,
) -> Result<(StdUnixListener, SocketGuard), NodeDaemonProcessError> {
    bind_socket_endpoint(
        &bootstrap.socket_path,
        bootstrap.expected_uid,
        bootstrap.expected_gid,
    )
}

fn bind_socket_endpoint(
    socket_path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(StdUnixListener, SocketGuard), NodeDaemonProcessError> {
    remove_stale_socket(socket_path, expected_uid, expected_gid)?;
    let listener = StdUnixListener::bind(socket_path)
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .and_then(|()| listener.set_nonblocking(true))
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    let metadata = fs::symlink_metadata(socket_path)
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    validate_private_socket(&metadata, expected_uid, expected_gid)?;
    sync_parent(socket_path)?;
    let identity = FileIdentity::from_metadata(&metadata);
    Ok((
        listener,
        SocketGuard {
            path: socket_path.to_path_buf(),
            identity,
        },
    ))
}

fn remove_stale_socket(
    socket_path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), NodeDaemonProcessError> {
    let before = match fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(NodeDaemonProcessError::Io(error.kind())),
    };
    validate_private_socket(&before, expected_uid, expected_gid)?;
    match StdUnixStream::connect(socket_path) {
        Ok(_) => return Err(NodeDaemonProcessError::EndpointAlreadyActive),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) => {}
        Err(error) => return Err(NodeDaemonProcessError::Io(error.kind())),
    }
    let after = fs::symlink_metadata(socket_path)
        .map_err(|_| NodeDaemonProcessError::EndpointIdentityChanged)?;
    if FileIdentity::from_metadata(&before) != FileIdentity::from_metadata(&after) {
        return Err(NodeDaemonProcessError::EndpointIdentityChanged);
    }
    fs::remove_file(socket_path).map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    sync_parent(socket_path)
}

async fn serve_endpoint(
    standard_listener: StdUnixListener,
    observation_listener: Option<(StdUnixListener, Arc<RuntimeObservationBootstrapV1>)>,
    owner: DurableNodeDaemonV1,
    bootstrap: &DeveloperLocalReferenceBootstrapV1,
    mut signals: ShutdownSignals,
) -> Result<(), NodeDaemonProcessError> {
    let listener = UnixListener::from_std(standard_listener)
        .map_err(|_| NodeDaemonProcessError::EndpointUnavailable)?;
    let observation_listener = observation_listener
        .map(|(listener, bootstrap)| {
            UnixListener::from_std(listener)
                .map(|listener| (listener, bootstrap))
                .map_err(|_| NodeDaemonProcessError::EndpointUnavailable)
        })
        .transpose()?;
    let owner = Arc::new(Mutex::new(owner));
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let blocking_tasks = Arc::new(TrackedBlockingTasks::new());
    let mut tasks = JoinSet::new();
    let serving_result = loop {
        tokio::select! {
            _ = signals.terminate.recv() => break Ok(()),
            _ = signals.interrupt.recv() => break Ok(()),
            completed = tasks.join_next(), if !tasks.is_empty() => {
                match completed {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(_)) => {
                        break Err(NodeDaemonProcessError::EndpointUnavailable);
                    }
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(NodeDaemonProcessError::Io(error.kind())),
                };
                if !peer_matches(
                    &stream,
                    bootstrap.expected_uid,
                    bootstrap.expected_gid,
                ) {
                    drop(stream);
                    continue;
                }
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let owner = Arc::clone(&owner);
                let blocking_tasks = Arc::clone(&blocking_tasks);
                let token = duplicate_token(&bootstrap.generation_token);
                tasks.spawn(async move {
                    let _permit = permit;
                    match serve_connection(stream, owner, blocking_tasks, token).await {
                        Err(error) if fatal_process_error(error) => Err(error),
                        _ => Ok(()),
                    }
                });
            }
            accepted = async {
                if let Some((listener, _)) = &observation_listener {
                    listener.accept().await.map(Some)
                } else {
                    pending().await
                }
            } => {
                let accepted = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(NodeDaemonProcessError::Io(error.kind())),
                };
                let Some((stream, _)) = accepted else {
                    continue;
                };
                let Some((_, observation_bootstrap)) = &observation_listener else {
                    continue;
                };
                if !peer_matches(
                    &stream,
                    observation_bootstrap.expected_uid(),
                    observation_bootstrap.expected_gid(),
                ) {
                    drop(stream);
                    continue;
                }
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let owner = Arc::clone(&owner);
                let blocking_tasks = Arc::clone(&blocking_tasks);
                let observation_bootstrap = Arc::clone(observation_bootstrap);
                tasks.spawn(async move {
                    let _permit = permit;
                    match serve_observation_connection(
                        stream,
                        owner,
                        blocking_tasks,
                        observation_bootstrap,
                    )
                    .await
                    {
                        Err(error) if fatal_process_error(error) => Err(error),
                        _ => Ok(()),
                    }
                });
            }
        }
    };
    drop(listener);
    drop(observation_listener);
    let close_result = blocking_tasks.close();
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    let mut drain_error = None;
    while !tasks.is_empty() {
        match timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(error)))) => {
                if drain_error.is_none() {
                    drain_error = Some(error);
                }
            }
            Ok(Some(Err(_))) => {
                if drain_error.is_none() {
                    drain_error = Some(NodeDaemonProcessError::EndpointUnavailable);
                }
            }
            Ok(None) => break,
            Err(_) => {
                tasks.abort_all();
                while let Some(completed) = tasks.join_next().await {
                    match completed {
                        Ok(Err(error)) if drain_error.is_none() => {
                            drain_error = Some(error);
                        }
                        Err(error) if !error.is_cancelled() && drain_error.is_none() => {
                            drain_error = Some(NodeDaemonProcessError::EndpointUnavailable);
                        }
                        _ => {}
                    }
                }
                break;
            }
        }
    }
    let blocking_join_result = blocking_tasks.join_closed().await;
    blocking_join_result?;
    close_result?;
    if let Some(error) = drain_error {
        return Err(error);
    }
    serving_result
}

const fn fatal_process_error(error: NodeDaemonProcessError) -> bool {
    matches!(
        error,
        NodeDaemonProcessError::State(
            NodeDaemonStoreError::CommitUncertain(_) | NodeDaemonStoreError::Poisoned
        )
    )
}

async fn serve_observation_connection(
    mut stream: UnixStream,
    owner: Arc<Mutex<DurableNodeDaemonV1>>,
    blocking_tasks: Arc<TrackedBlockingTasks>,
    bootstrap: Arc<RuntimeObservationBootstrapV1>,
) -> Result<(), NodeDaemonProcessError> {
    let (token, request) = timeout(IO_TIMEOUT, read_local_observation_request(&mut stream))
        .await
        .map_err(|_| NodeDaemonProcessError::EndpointUnavailable)??;
    if !constant_time_eq(token.as_ref(), bootstrap.generation_token().as_ref()) {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let intended_status_sequence = request.intended_status_sequence();
    let runtime_host_id = request.runtime_host_id();
    let request_digest = request.request_digest();
    let replay_owner = Arc::clone(&owner);
    let replay_gate = Arc::clone(&blocking_tasks);
    let replay = blocking_tasks
        .run(move || {
            let owner = replay_owner
                .lock()
                .map_err(|_| NodeDaemonProcessError::State(NodeDaemonStoreError::Poisoned))?;
            replay_gate.ensure_open()?;
            owner
                .recover_exact_runtime_observation_ack(
                    intended_status_sequence,
                    runtime_host_id,
                    request_digest,
                )
                .map_err(NodeDaemonProcessError::from)
        })
        .await?;
    let commit = if let Some(replay) = replay {
        replay
    } else {
        let authority = bootstrap.authority(runtime_host_id)?;
        let runtime_status = authority.verify_and_project(
            bootstrap.node_target(),
            bootstrap.observation_endpoint_ref(),
            bootstrap.generation_token(),
            &request,
        )?;
        let valid_until_unix_nanos = request.challenge_expires_at_unix_nanos();
        let commit_owner = Arc::clone(&owner);
        let commit_gate = Arc::clone(&blocking_tasks);
        blocking_tasks
            .run(move || {
                let mut owner = commit_owner
                    .lock()
                    .map_err(|_| NodeDaemonProcessError::State(NodeDaemonStoreError::Poisoned))?;
                commit_gate.ensure_open()?;
                owner
                    .commit_authenticated_runtime_observation(
                        intended_status_sequence,
                        runtime_status,
                        valid_until_unix_nanos,
                        request_digest,
                    )
                    .map_err(NodeDaemonProcessError::from)
            })
            .await?
    };
    let runtime_status_digest = commit
        .status
        .runtime_hosts()
        .iter()
        .find(|runtime| runtime.runtime_host_id() == runtime_host_id)
        .map(|runtime| runtime.status_digest())
        .ok_or(RuntimeObservationError::AckMismatch)?;
    let outcome = match commit.outcome {
        DurableRuntimeObservationCommitOutcome::Published => {
            RuntimeObservationAckOutcomeV1::Published
        }
        DurableRuntimeObservationCommitOutcome::ExactReplay => {
            RuntimeObservationAckOutcomeV1::ExactReplay
        }
    };
    let ack =
        RuntimeObservationAckV1::try_new(outcome, &request, &commit.status, runtime_status_digest)?;
    timeout(
        IO_TIMEOUT,
        write_response(&mut stream, ack.canonical_wire()),
    )
    .await
    .map_err(|_| NodeDaemonProcessError::EndpointUnavailable)??;
    Ok(())
}

fn peer_matches(stream: &UnixStream, expected_uid: u32, expected_gid: u32) -> bool {
    stream.peer_cred().is_ok_and(|credentials| {
        credentials.uid() == expected_uid && credentials.gid() == expected_gid
    })
}

async fn exchange_developer_local_node_management(
    socket_path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    generation_token: Zeroizing<[u8; DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES]>,
    request_wire: Box<[u8]>,
    socket_identity: FileIdentity,
    deadline: Instant,
) -> Result<Box<[u8]>, DeveloperLocalNodeManagementEndpointErrorV1> {
    let mut stream = match timeout_at(deadline, UnixStream::connect(&socket_path)).await {
        Err(_) => {
            return Err(DeveloperLocalNodeManagementEndpointErrorV1::DeadlineExceeded);
        }
        Ok(Err(error))
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Err(DeveloperLocalNodeManagementEndpointErrorV1::Disconnected);
        }
        Ok(Err(_)) => return Err(DeveloperLocalNodeManagementEndpointErrorV1::Connect),
        Ok(Ok(stream)) => stream,
    };
    if validate_management_socket_metadata(&socket_path, expected_uid, expected_gid)?
        != socket_identity
    {
        return Err(DeveloperLocalNodeManagementEndpointErrorV1::SocketIdentityChanged);
    }
    let peer = stream
        .peer_cred()
        .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::PeerCredentialsUnavailable)?;
    if peer.uid() != expected_uid || peer.gid() != expected_gid {
        return Err(DeveloperLocalNodeManagementEndpointErrorV1::PeerCredentialsMismatch);
    }

    let mut frame = Zeroizing::new([0_u8; LOCAL_REQUEST_BYTES]);
    frame[..4].copy_from_slice(LOCAL_REQUEST_MAGIC);
    write_u16(frame.as_mut(), 4, PROCESS_VERSION);
    write_u16(
        frame.as_mut(),
        6,
        u16::try_from(LOCAL_REQUEST_HEADER_BYTES)
            .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::InvalidConfiguration)?,
    );
    write_u32(
        frame.as_mut(),
        8,
        u32::try_from(LOCAL_REQUEST_BYTES)
            .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::InvalidConfiguration)?,
    );
    write_u32(
        frame.as_mut(),
        12,
        u32::try_from(NODE_MANAGEMENT_REQUEST_BYTES)
            .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::InvalidConfiguration)?,
    );
    frame[16..LOCAL_REQUEST_HEADER_BYTES].copy_from_slice(generation_token.as_ref());
    frame[LOCAL_REQUEST_HEADER_BYTES..].copy_from_slice(&request_wire);
    timeout_at(deadline, stream.write_all(frame.as_ref()))
        .await
        .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::DeadlineExceeded)?
        .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::Write)?;
    timeout_at(deadline, stream.shutdown())
        .await
        .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::DeadlineExceeded)?
        .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::Write)?;
    drop(frame);

    let mut prefix = [0_u8; 12];
    read_developer_local_node_management_exact(deadline, &mut stream, &mut prefix).await?;
    let response_length = usize::try_from(read_u32(&prefix, 8))
        .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::ResponseTooLarge)?;
    if !(12..=MAX_NODE_MANAGEMENT_RESPONSE_BYTES).contains(&response_length) {
        return Err(DeveloperLocalNodeManagementEndpointErrorV1::ResponseTooLarge);
    }
    let mut response = vec![0_u8; response_length];
    response[..12].copy_from_slice(&prefix);
    read_developer_local_node_management_exact(deadline, &mut stream, &mut response[12..]).await?;
    let mut trailing = [0_u8; 1];
    let trailing_length = timeout_at(deadline, stream.read(&mut trailing))
        .await
        .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::DeadlineExceeded)?
        .map_err(|_| DeveloperLocalNodeManagementEndpointErrorV1::Read)?;
    if trailing_length != 0 {
        return Err(DeveloperLocalNodeManagementEndpointErrorV1::TrailingResponseBytes);
    }
    Ok(response.into_boxed_slice())
}

async fn read_developer_local_node_management_exact(
    deadline: Instant,
    stream: &mut UnixStream,
    buffer: &mut [u8],
) -> Result<(), DeveloperLocalNodeManagementEndpointErrorV1> {
    match timeout_at(deadline, stream.read_exact(buffer)).await {
        Err(_) => Err(DeveloperLocalNodeManagementEndpointErrorV1::DeadlineExceeded),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(DeveloperLocalNodeManagementEndpointErrorV1::TruncatedResponse)
        }
        Ok(Err(_)) => Err(DeveloperLocalNodeManagementEndpointErrorV1::Read),
        Ok(Ok(_)) => Ok(()),
    }
}

async fn serve_connection(
    mut stream: UnixStream,
    owner: Arc<Mutex<DurableNodeDaemonV1>>,
    blocking_tasks: Arc<TrackedBlockingTasks>,
    expected_token: Zeroizing<[u8; DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES]>,
) -> Result<(), NodeDaemonProcessError> {
    let request = timeout(IO_TIMEOUT, read_local_request(&mut stream))
        .await
        .map_err(|_| NodeDaemonProcessError::EndpointUnavailable)??;
    if !constant_time_eq(
        &request[..DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES],
        expected_token.as_ref(),
    ) {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let exchange_gate = Arc::clone(&blocking_tasks);
    let response = blocking_tasks
        .run(move || {
            let mut owner = owner
                .lock()
                .map_err(|_| NodeDaemonProcessError::State(NodeDaemonStoreError::Poisoned))?;
            exchange_gate.ensure_open()?;
            owner
                .exchange(&request[DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES..])
                .map_err(|_| NodeDaemonProcessError::EndpointUnavailable)
        })
        .await?;
    if response.len() > MAX_NODE_MANAGEMENT_RESPONSE_BYTES {
        return Err(NodeDaemonProcessError::EndpointUnavailable);
    }
    timeout(IO_TIMEOUT, write_response(&mut stream, &response))
        .await
        .map_err(|_| NodeDaemonProcessError::EndpointUnavailable)??;
    Ok(())
}

async fn read_local_request(
    stream: &mut UnixStream,
) -> Result<Zeroizing<Vec<u8>>, NodeDaemonProcessError> {
    let mut wire = Zeroizing::new(vec![0_u8; LOCAL_REQUEST_BYTES]);
    stream
        .read_exact(wire.as_mut_slice())
        .await
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    if &wire[..4] != LOCAL_REQUEST_MAGIC
        || read_u16(&wire, 4) != PROCESS_VERSION
        || usize::from(read_u16(&wire, 6)) != LOCAL_REQUEST_HEADER_BYTES
        || usize::try_from(read_u32(&wire, 8)).ok() != Some(LOCAL_REQUEST_BYTES)
        || usize::try_from(read_u32(&wire, 12)).ok() != Some(NODE_MANAGEMENT_REQUEST_BYTES)
    {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .await
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?
        != 0
    {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let mut authenticated = Zeroizing::new(vec![
        0_u8;
        DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES
            + NODE_MANAGEMENT_REQUEST_BYTES
    ]);
    authenticated[..DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES]
        .copy_from_slice(&wire[16..LOCAL_REQUEST_HEADER_BYTES]);
    authenticated[DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES..]
        .copy_from_slice(&wire[LOCAL_REQUEST_HEADER_BYTES..]);
    Ok(authenticated)
}

async fn read_local_observation_request(
    stream: &mut UnixStream,
) -> Result<
    (
        Zeroizing<[u8; RUNTIME_OBSERVATION_TOKEN_BYTES]>,
        RuntimeObservationRequestV1,
    ),
    NodeDaemonProcessError,
> {
    let mut header = Zeroizing::new([0_u8; LOCAL_REQUEST_HEADER_BYTES]);
    stream
        .read_exact(header.as_mut())
        .await
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    let total = usize::try_from(read_u32(header.as_ref(), 8))
        .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    let payload_length = usize::try_from(read_u32(header.as_ref(), 12))
        .map_err(|_| NodeDaemonProcessError::InvalidBootstrap)?;
    if &header[..4] != LOCAL_OBSERVATION_MAGIC
        || read_u16(header.as_ref(), 4) != PROCESS_VERSION
        || usize::from(read_u16(header.as_ref(), 6)) != LOCAL_REQUEST_HEADER_BYTES
        || total != LOCAL_REQUEST_HEADER_BYTES.saturating_add(payload_length)
        || !(RUNTIME_OBSERVATION_REQUEST_HEADER_BYTES..=MAX_RUNTIME_OBSERVATION_REQUEST_BYTES)
            .contains(&payload_length)
        || total > MAX_LOCAL_OBSERVATION_BYTES
    {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let mut payload = Zeroizing::new(vec![0_u8; payload_length]);
    stream
        .read_exact(payload.as_mut_slice())
        .await
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .await
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?
        != 0
    {
        return Err(NodeDaemonProcessError::InvalidBootstrap);
    }
    let mut token = Zeroizing::new([0_u8; RUNTIME_OBSERVATION_TOKEN_BYTES]);
    token.copy_from_slice(&header[16..LOCAL_REQUEST_HEADER_BYTES]);
    let request = RuntimeObservationRequestV1::decode(payload.as_ref())?;
    Ok((token, request))
}

async fn write_response(
    stream: &mut UnixStream,
    response: &[u8],
) -> Result<(), NodeDaemonProcessError> {
    stream
        .write_all(response)
        .await
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    stream
        .shutdown()
        .await
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))
}

fn validate_lexical_absolute_path(
    path: &Path,
    max_bytes: usize,
) -> Result<(), NodeDaemonProcessError> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.as_os_str().as_bytes().is_empty()
        || path.as_os_str().as_bytes().len() > max_bytes
    {
        return Err(NodeDaemonProcessError::InvalidPath);
    }
    for component in path.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(NodeDaemonProcessError::InvalidPath);
        }
    }
    Ok(())
}

fn validate_existing_path_chain(path: &Path) -> Result<(), NodeDaemonProcessError> {
    validate_lexical_absolute_path(path, usize::MAX)?;
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
        if metadata.file_type().is_symlink() {
            return Err(NodeDaemonProcessError::InvalidPath);
        }
    }
    Ok(())
}

fn validate_private_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), NodeDaemonProcessError> {
    validate_existing_path_chain(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| NodeDaemonProcessError::Io(error.kind()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & PRIVATE_MODE_MASK != PRIVATE_DIRECTORY_MODE
    {
        return Err(NodeDaemonProcessError::InsecurePermissions);
    }
    Ok(())
}

fn validate_private_regular_file(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), NodeDaemonProcessError> {
    validate_private_regular_file_with_links(metadata, expected_uid, expected_gid, 1)
}

fn validate_private_regular_file_with_links(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
    expected_links: u64,
) -> Result<(), NodeDaemonProcessError> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != expected_links
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & PRIVATE_MODE_MASK != PRIVATE_FILE_MODE
    {
        return Err(NodeDaemonProcessError::InsecurePermissions);
    }
    Ok(())
}

fn validate_private_socket(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), NodeDaemonProcessError> {
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & PRIVATE_MODE_MASK != PRIVATE_FILE_MODE
    {
        return Err(NodeDaemonProcessError::InsecurePermissions);
    }
    Ok(())
}

fn validate_management_socket_metadata(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<FileIdentity, DeveloperLocalNodeManagementEndpointErrorV1> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => DeveloperLocalNodeManagementEndpointErrorV1::Disconnected,
        _ => DeveloperLocalNodeManagementEndpointErrorV1::SocketMetadata,
    })?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & PRIVATE_MODE_MASK != PRIVATE_FILE_MODE
    {
        return Err(DeveloperLocalNodeManagementEndpointErrorV1::SocketMetadata);
    }
    Ok(FileIdentity::from_metadata(&metadata))
}

fn sync_parent(path: &Path) -> Result<(), NodeDaemonProcessError> {
    let parent = path.parent().ok_or(NodeDaemonProcessError::InvalidPath)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| NodeDaemonProcessError::Io(error.kind()))
}

fn remove_same_regular_file(path: &Path, identity: FileIdentity) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.is_file() && FileIdentity::from_metadata(&metadata) == identity {
        let _ = fs::remove_file(path);
    }
}

fn duplicate_token(
    token: &Zeroizing<[u8; DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES]>,
) -> Zeroizing<[u8; DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES]> {
    let mut duplicate = Zeroizing::new([0_u8; DEVELOPER_LOCAL_REFERENCE_TOKEN_BYTES]);
    duplicate.copy_from_slice(token.as_ref());
    duplicate
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn copy_array<const BYTES: usize>(wire: &[u8], offset: usize) -> [u8; BYTES] {
    let mut value = [0_u8; BYTES];
    value.copy_from_slice(&wire[offset..offset + BYTES]);
    value
}

fn read_u16(wire: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(copy_array(wire, offset))
}

fn read_u32(wire: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(copy_array(wire, offset))
}

fn read_u64(wire: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(copy_array(wire, offset))
}

fn write_u16(wire: &mut [u8], offset: usize, value: u16) {
    wire[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn write_u32(wire: &mut [u8], offset: usize, value: u32) {
    wire[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_u64(wire: &mut [u8], offset: usize, value: u64) {
    wire[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
