#![cfg(unix)]

//! Non-production, same-user Unix IPC for a Runtime-issued Agent capability.
//!
//! The endpoint owns no Agent or Fabric semantics. It forwards one bounded,
//! authenticated PXAI request at a time to an opaque
//! [`RuntimeAgentConversationHandle`].  PXAB bootstrap bytes live in an
//! owner-private file so a TUI process never receives a raw Zenoh session,
//! route, provider credential, or capability token on its command line.

use core::{fmt, time::Duration};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use nix::unistd::{getegid, geteuid};
use paraegox_agent_contracts::control::{
    AgentConversationCancelStateV1, AgentConversationControlBodyV1, AgentConversationControlV1,
    AgentConversationGetStateV1, AgentConversationOpenOutcomeV1, AgentConversationWatchBatchV1,
    MAX_AGENT_CONVERSATION_CONTROL_FRAME_BYTES,
};
use paraegox_agent_contracts::{
    AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
    AgentConversationSessionId, AgentConversationTerminalV1,
    MAX_AGENT_CONVERSATION_DEADLINE_BUDGET_NANOS,
};
use paraegox_kernel::digest::{Digest32, Digest32Builder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use zeroize::{Zeroize, Zeroizing};

use crate::managed_agent_runtime::{RuntimeAgentConversationError, RuntimeAgentConversationHandle};

const PXAB_MAGIC: &[u8; 4] = b"PXAB";
const PXAI_REQUEST_MAGIC: &[u8; 4] = b"PXAI";
const PXAI_RESPONSE_MAGIC: &[u8; 4] = b"PXAO";
const IPC_VERSION: u16 = 1;
const PXAB_HEADER_BYTES: usize = 144;
const PXAI_HEADER_BYTES: usize = 112;
const MAX_BOOTSTRAP_PATH_BYTES: usize = 512;
const MAX_BOOTSTRAP_FRAME_BYTES: usize = PXAB_HEADER_BYTES + MAX_BOOTSTRAP_PATH_BYTES;
const MAX_IPC_BODY_BYTES: usize = MAX_AGENT_CONVERSATION_CONTROL_FRAME_BYTES;
const MAX_IPC_FRAME_BYTES: usize = PXAI_HEADER_BYTES + MAX_IPC_BODY_BYTES;
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;
const MAX_IN_FLIGHT: usize = 16;
const MAX_CLIENT_COMMAND_CAPACITY: u16 = 32;
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const SOCKET_MODE: u32 = 0o600;
const BOOTSTRAP_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const SHARED_SOCKET_DIRECTORY_MODE: u32 = 0o2750;
const PXAB_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.agent.developer-local.bootstrap.sha256.v1";
const PXAI_FRAME_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.agent.developer-local.ipc-frame.sha256.v1";
const PXAI_CORRELATION_DOMAIN: &[u8] =
    b"paraegox.runtime.agent.developer-local.correlation.sha256.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum OperationKind {
    Open = 1,
    Submit = 2,
    Get = 3,
    Watch = 4,
    Cancel = 5,
}

impl OperationKind {
    fn decode(value: u8) -> Result<Self, RuntimeAgentDeveloperLocalIpcError> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::Submit),
            3 => Ok(Self::Get),
            4 => Ok(Self::Watch),
            5 => Ok(Self::Cancel),
            _ => Err(RuntimeAgentDeveloperLocalIpcError::UnknownOperation),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ResponseStatus {
    Ok = 0,
    Malformed = 1,
    AuthenticationFailed = 2,
    OwnerUnavailable = 3,
    GenerationRetired = 4,
    OperationRejected = 5,
    OperationTimedOut = 6,
    Overloaded = 7,
}

impl ResponseStatus {
    fn decode(value: u8) -> Result<Self, RuntimeAgentDeveloperLocalIpcError> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Malformed),
            2 => Ok(Self::AuthenticationFailed),
            3 => Ok(Self::OwnerUnavailable),
            4 => Ok(Self::GenerationRetired),
            5 => Ok(Self::OperationRejected),
            6 => Ok(Self::OperationTimedOut),
            7 => Ok(Self::Overloaded),
            _ => Err(RuntimeAgentDeveloperLocalIpcError::UnknownResponseStatus),
        }
    }
}

/// Explicit bounds and identity for one non-production same-user endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAgentDeveloperLocalIpcConfigV1 {
    socket_path: PathBuf,
    bootstrap_path: PathBuf,
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    request_deadline_budget: Duration,
    operation_timeout: Duration,
    shutdown_timeout: Duration,
    command_capacity: u16,
    max_in_flight: usize,
    expected_uid: u32,
    expected_gid: u32,
}

/// Validated socket/bootstrap paths and the exact same-user peer identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAgentDeveloperLocalIpcPathsV1 {
    socket_path: PathBuf,
    bootstrap_path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
}

impl RuntimeAgentDeveloperLocalIpcPathsV1 {
    pub fn try_new(
        socket_path: PathBuf,
        bootstrap_path: PathBuf,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, RuntimeAgentDeveloperLocalIpcError> {
        validate_endpoint_paths(&socket_path, &bootstrap_path, expected_uid, expected_gid)?;
        if geteuid().as_raw() != expected_uid || getegid().as_raw() != expected_gid {
            return Err(RuntimeAgentDeveloperLocalIpcError::InvalidConfiguration);
        }
        Ok(Self {
            socket_path,
            bootstrap_path,
            expected_uid,
            expected_gid,
        })
    }
}

/// Exact conversation scope and bounded request/operation budgets in PXAB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAgentDeveloperLocalConversationV1 {
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    request_deadline_budget: Duration,
    operation_timeout: Duration,
}

impl RuntimeAgentDeveloperLocalConversationV1 {
    pub fn try_new(
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_deadline_budget: Duration,
        operation_timeout: Duration,
    ) -> Result<Self, RuntimeAgentDeveloperLocalIpcError> {
        if request_deadline_budget.is_zero()
            || request_deadline_budget.as_nanos()
                > u128::from(MAX_AGENT_CONVERSATION_DEADLINE_BUDGET_NANOS)
            || operation_timeout.is_zero()
            || operation_timeout > MAX_OPERATION_TIMEOUT
        {
            return Err(RuntimeAgentDeveloperLocalIpcError::InvalidConfiguration);
        }
        Ok(Self {
            deck_run_id,
            session_id,
            request_deadline_budget,
            operation_timeout,
        })
    }
}

/// Bounded endpoint lifecycle and client-adapter queue facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAgentDeveloperLocalIpcLimitsV1 {
    shutdown_timeout: Duration,
    command_capacity: u16,
    max_in_flight: usize,
}

impl RuntimeAgentDeveloperLocalIpcLimitsV1 {
    pub fn try_new(
        shutdown_timeout: Duration,
        command_capacity: u16,
        max_in_flight: usize,
    ) -> Result<Self, RuntimeAgentDeveloperLocalIpcError> {
        if shutdown_timeout.is_zero()
            || shutdown_timeout > MAX_SHUTDOWN_TIMEOUT
            || !(1..=MAX_CLIENT_COMMAND_CAPACITY).contains(&command_capacity)
            || !(1..=MAX_IN_FLIGHT).contains(&max_in_flight)
        {
            return Err(RuntimeAgentDeveloperLocalIpcError::InvalidConfiguration);
        }
        Ok(Self {
            shutdown_timeout,
            command_capacity,
            max_in_flight,
        })
    }
}

impl RuntimeAgentDeveloperLocalIpcConfigV1 {
    pub fn try_new(
        paths: RuntimeAgentDeveloperLocalIpcPathsV1,
        conversation: RuntimeAgentDeveloperLocalConversationV1,
        limits: RuntimeAgentDeveloperLocalIpcLimitsV1,
    ) -> Result<Self, RuntimeAgentDeveloperLocalIpcError> {
        validate_endpoint_paths(
            &paths.socket_path,
            &paths.bootstrap_path,
            paths.expected_uid,
            paths.expected_gid,
        )?;
        Ok(Self {
            socket_path: paths.socket_path,
            bootstrap_path: paths.bootstrap_path,
            deck_run_id: conversation.deck_run_id,
            session_id: conversation.session_id,
            request_deadline_budget: conversation.request_deadline_budget,
            operation_timeout: conversation.operation_timeout,
            shutdown_timeout: limits.shutdown_timeout,
            command_capacity: limits.command_capacity,
            max_in_flight: limits.max_in_flight,
            expected_uid: paths.expected_uid,
            expected_gid: paths.expected_gid,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn bootstrap_path(&self) -> &Path {
        &self.bootstrap_path
    }
}

/// Strict PXAB value loaded from an owner-private bootstrap file.
pub struct RuntimeAgentDeveloperLocalBootstrapV1 {
    socket_path: PathBuf,
    generation_token: Zeroizing<[u8; 32]>,
    deck_run_id: AgentConversationDeckRunId,
    session_id: AgentConversationSessionId,
    request_deadline_budget_nanos: u64,
    operation_timeout_nanos: u64,
    command_capacity: u16,
    server_uid: u32,
    server_gid: u32,
}

impl Drop for RuntimeAgentDeveloperLocalBootstrapV1 {
    fn drop(&mut self) {
        self.generation_token.zeroize();
    }
}

impl fmt::Debug for RuntimeAgentDeveloperLocalBootstrapV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeAgentDeveloperLocalBootstrapV1")
            .field("socket_path", &self.socket_path)
            .field("deck_run_id", &self.deck_run_id)
            .field("session_id", &self.session_id)
            .field(
                "request_deadline_budget_nanos",
                &self.request_deadline_budget_nanos,
            )
            .field("operation_timeout_nanos", &self.operation_timeout_nanos)
            .field("command_capacity", &self.command_capacity)
            .field("server_uid", &self.server_uid)
            .field("server_gid", &self.server_gid)
            .finish_non_exhaustive()
    }
}

impl RuntimeAgentDeveloperLocalBootstrapV1 {
    pub fn read_private_file(path: &Path) -> Result<Self, RuntimeAgentDeveloperLocalIpcError> {
        read_bootstrap_file(path)
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub const fn deck_run_id(&self) -> AgentConversationDeckRunId {
        self.deck_run_id
    }

    pub const fn session_id(&self) -> AgentConversationSessionId {
        self.session_id
    }

    pub const fn request_deadline_budget_nanos(&self) -> u64 {
        self.request_deadline_budget_nanos
    }

    pub const fn operation_timeout(&self) -> Duration {
        Duration::from_nanos(self.operation_timeout_nanos)
    }

    pub const fn command_capacity(&self) -> u16 {
        self.command_capacity
    }
}

fn encode_bootstrap(
    value: &RuntimeAgentDeveloperLocalBootstrapV1,
) -> Result<Zeroizing<Vec<u8>>, RuntimeAgentDeveloperLocalIpcError> {
    let path = value.socket_path.as_os_str().as_bytes();
    let frame_len = PXAB_HEADER_BYTES
        .checked_add(path.len())
        .ok_or(RuntimeAgentDeveloperLocalIpcError::FrameTooLarge)?;
    if path.is_empty()
        || path.len() > MAX_BOOTSTRAP_PATH_BYTES
        || frame_len > MAX_BOOTSTRAP_FRAME_BYTES
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::FrameTooLarge);
    }
    let path_len =
        u16::try_from(path.len()).map_err(|_| RuntimeAgentDeveloperLocalIpcError::FrameTooLarge)?;
    let frame_len_u32 =
        u32::try_from(frame_len).map_err(|_| RuntimeAgentDeveloperLocalIpcError::FrameTooLarge)?;
    let digest = bootstrap_digest(value, path)?;
    let mut wire = Zeroizing::new(vec![0_u8; frame_len]);
    wire[0..4].copy_from_slice(PXAB_MAGIC);
    write_u16(&mut wire, 4, IPC_VERSION);
    write_u16(
        &mut wire,
        6,
        u16::try_from(PXAB_HEADER_BYTES).expect("fixed PXAB header fits u16"),
    );
    write_u32(&mut wire, 8, frame_len_u32);
    write_u16(&mut wire, 12, path_len);
    write_u16(&mut wire, 14, 1);
    write_u32(&mut wire, 16, value.server_uid);
    write_u32(&mut wire, 20, value.server_gid);
    wire[24..56].copy_from_slice(value.generation_token.as_ref());
    wire[56..72].copy_from_slice(value.deck_run_id.as_bytes());
    wire[72..88].copy_from_slice(value.session_id.as_bytes());
    write_u64(&mut wire, 88, value.request_deadline_budget_nanos);
    write_u64(&mut wire, 96, value.operation_timeout_nanos);
    write_u16(&mut wire, 104, value.command_capacity);
    write_u16(&mut wire, 106, 0);
    write_u32(
        &mut wire,
        108,
        u32::try_from(MAX_IPC_BODY_BYTES).expect("fixed IPC body bound fits u32"),
    );
    wire[112..144].copy_from_slice(digest.as_bytes());
    wire[PXAB_HEADER_BYTES..].copy_from_slice(path);
    Ok(wire)
}

fn decode_bootstrap(
    wire: &[u8],
) -> Result<RuntimeAgentDeveloperLocalBootstrapV1, RuntimeAgentDeveloperLocalIpcError> {
    if wire.len() < PXAB_HEADER_BYTES || wire.len() > MAX_BOOTSTRAP_FRAME_BYTES {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap);
    }
    if &wire[0..4] != PXAB_MAGIC
        || read_u16(wire, 4) != IPC_VERSION
        || usize::from(read_u16(wire, 6)) != PXAB_HEADER_BYTES
        || usize::try_from(read_u32(wire, 8)).ok() != Some(wire.len())
        || read_u16(wire, 14) != 1
        || read_u16(wire, 106) != 0
        || usize::try_from(read_u32(wire, 108)).ok() != Some(MAX_IPC_BODY_BYTES)
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap);
    }
    let path_len = usize::from(read_u16(wire, 12));
    if path_len == 0
        || path_len > MAX_BOOTSTRAP_PATH_BYTES
        || PXAB_HEADER_BYTES.checked_add(path_len) != Some(wire.len())
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap);
    }
    let server_uid = read_u32(wire, 16);
    let server_gid = read_u32(wire, 20);
    if server_uid != geteuid().as_raw() || server_gid != getegid().as_raw() {
        return Err(RuntimeAgentDeveloperLocalIpcError::PeerCredentialsMismatch);
    }
    let token = Zeroizing::new(copy_array::<32>(wire, 24));
    if token.iter().all(|byte| *byte == 0) {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap);
    }
    let deck_run_id = AgentConversationDeckRunId::try_from_bytes(copy_array(wire, 56))
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap)?;
    let session_id = AgentConversationSessionId::try_from_bytes(copy_array(wire, 72))
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap)?;
    let request_deadline_budget_nanos = read_u64(wire, 88);
    let operation_timeout_nanos = read_u64(wire, 96);
    let command_capacity = read_u16(wire, 104);
    if request_deadline_budget_nanos == 0
        || request_deadline_budget_nanos > MAX_AGENT_CONVERSATION_DEADLINE_BUDGET_NANOS
        || operation_timeout_nanos == 0
        || operation_timeout_nanos
            > u64::try_from(MAX_OPERATION_TIMEOUT.as_nanos()).expect("timeout fits u64")
        || !(1..=MAX_CLIENT_COMMAND_CAPACITY).contains(&command_capacity)
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap);
    }
    let socket_path = PathBuf::from(OsString::from_vec(wire[PXAB_HEADER_BYTES..].to_vec()));
    validate_lexical_absolute_path(&socket_path, MAX_UNIX_SOCKET_PATH_BYTES)?;
    let candidate = RuntimeAgentDeveloperLocalBootstrapV1 {
        socket_path,
        generation_token: token,
        deck_run_id,
        session_id,
        request_deadline_budget_nanos,
        operation_timeout_nanos,
        command_capacity,
        server_uid,
        server_gid,
    };
    let expected = bootstrap_digest(&candidate, &wire[PXAB_HEADER_BYTES..])?;
    if !constant_time_eq(expected.as_bytes(), &wire[112..144]) {
        return Err(RuntimeAgentDeveloperLocalIpcError::DigestMismatch);
    }
    Ok(candidate)
}

fn bootstrap_digest(
    value: &RuntimeAgentDeveloperLocalBootstrapV1,
    path: &[u8],
) -> Result<Digest32, RuntimeAgentDeveloperLocalIpcError> {
    let mut builder = Digest32Builder::try_new(PXAB_DIGEST_DOMAIN)
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::DigestBuild)?;
    builder
        .field_u16(1)
        .and_then(|builder| builder.field_bytes(&value.server_uid.to_be_bytes()))
        .and_then(|builder| builder.field_bytes(&value.server_gid.to_be_bytes()))
        .and_then(|builder| builder.field_bytes(value.generation_token.as_ref()))
        .and_then(|builder| builder.field_bytes(value.deck_run_id.as_bytes()))
        .and_then(|builder| builder.field_bytes(value.session_id.as_bytes()))
        .and_then(|builder| builder.field_u64(value.request_deadline_budget_nanos))
        .and_then(|builder| builder.field_u64(value.operation_timeout_nanos))
        .and_then(|builder| builder.field_u16(value.command_capacity))
        .and_then(|builder| {
            builder.field_bytes(
                &u32::try_from(MAX_IPC_BODY_BYTES)
                    .expect("fixed IPC body bound fits u32")
                    .to_be_bytes(),
            )
        })
        .and_then(|builder| builder.field_bytes(path))
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::DigestBuild)?;
    Ok(builder.finish())
}

struct IpcFrame {
    kind: OperationKind,
    status: ResponseStatus,
    correlation: [u8; 16],
    generation_token: Zeroizing<[u8; 32]>,
    operation_timeout_nanos: u64,
    body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for IpcFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IpcFrame")
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("correlation", &self.correlation)
            .field("operation_timeout_nanos", &self.operation_timeout_nanos)
            .field("body_length", &self.body.len())
            .finish_non_exhaustive()
    }
}

fn encode_ipc_frame(
    magic: &[u8; 4],
    frame: &IpcFrame,
) -> Result<Zeroizing<Vec<u8>>, RuntimeAgentDeveloperLocalIpcError> {
    if frame.correlation.iter().all(|byte| *byte == 0)
        || frame.generation_token.iter().all(|byte| *byte == 0)
        || frame.operation_timeout_nanos == 0
        || frame.operation_timeout_nanos
            > u64::try_from(MAX_OPERATION_TIMEOUT.as_nanos()).expect("timeout fits u64")
        || frame.body.len() > MAX_IPC_BODY_BYTES
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidFrame);
    }
    let frame_len = PXAI_HEADER_BYTES
        .checked_add(frame.body.len())
        .ok_or(RuntimeAgentDeveloperLocalIpcError::FrameTooLarge)?;
    let mut wire = Zeroizing::new(vec![0_u8; frame_len]);
    wire[0..4].copy_from_slice(magic);
    write_u16(&mut wire, 4, IPC_VERSION);
    write_u16(
        &mut wire,
        6,
        u16::try_from(PXAI_HEADER_BYTES).expect("fixed PXAI header fits u16"),
    );
    write_u32(
        &mut wire,
        8,
        u32::try_from(frame_len).map_err(|_| RuntimeAgentDeveloperLocalIpcError::FrameTooLarge)?,
    );
    wire[12] = frame.kind as u8;
    wire[13] = frame.status as u8;
    write_u16(&mut wire, 14, 0);
    wire[16..32].copy_from_slice(&frame.correlation);
    wire[32..64].copy_from_slice(frame.generation_token.as_ref());
    write_u64(&mut wire, 64, frame.operation_timeout_nanos);
    write_u32(
        &mut wire,
        72,
        u32::try_from(frame.body.len())
            .map_err(|_| RuntimeAgentDeveloperLocalIpcError::FrameTooLarge)?,
    );
    write_u32(&mut wire, 76, 0);
    let digest = ipc_frame_digest(frame)?;
    wire[80..112].copy_from_slice(digest.as_bytes());
    wire[PXAI_HEADER_BYTES..].copy_from_slice(&frame.body);
    Ok(wire)
}

fn decode_ipc_frame(
    magic: &[u8; 4],
    wire: &[u8],
) -> Result<IpcFrame, RuntimeAgentDeveloperLocalIpcError> {
    if wire.len() < PXAI_HEADER_BYTES || wire.len() > MAX_IPC_FRAME_BYTES {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidFrame);
    }
    if &wire[0..4] != magic
        || read_u16(wire, 4) != IPC_VERSION
        || usize::from(read_u16(wire, 6)) != PXAI_HEADER_BYTES
        || usize::try_from(read_u32(wire, 8)).ok() != Some(wire.len())
        || read_u16(wire, 14) != 0
        || read_u32(wire, 76) != 0
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidFrame);
    }
    let body_len = usize::try_from(read_u32(wire, 72))
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::InvalidFrame)?;
    if body_len > MAX_IPC_BODY_BYTES || PXAI_HEADER_BYTES.checked_add(body_len) != Some(wire.len())
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidFrame);
    }
    let kind = OperationKind::decode(wire[12])?;
    let status = ResponseStatus::decode(wire[13])?;
    let correlation = copy_array::<16>(wire, 16);
    let generation_token = Zeroizing::new(copy_array::<32>(wire, 32));
    let operation_timeout_nanos = read_u64(wire, 64);
    if correlation.iter().all(|byte| *byte == 0)
        || generation_token.iter().all(|byte| *byte == 0)
        || operation_timeout_nanos == 0
        || operation_timeout_nanos
            > u64::try_from(MAX_OPERATION_TIMEOUT.as_nanos()).expect("timeout fits u64")
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidFrame);
    }
    let frame = IpcFrame {
        kind,
        status,
        correlation,
        generation_token,
        operation_timeout_nanos,
        body: Zeroizing::new(wire[PXAI_HEADER_BYTES..].to_vec()),
    };
    let expected = ipc_frame_digest(&frame)?;
    if !constant_time_eq(expected.as_bytes(), &wire[80..112]) {
        return Err(RuntimeAgentDeveloperLocalIpcError::DigestMismatch);
    }
    Ok(frame)
}

fn ipc_frame_digest(frame: &IpcFrame) -> Result<Digest32, RuntimeAgentDeveloperLocalIpcError> {
    let mut builder = Digest32Builder::try_new(PXAI_FRAME_DIGEST_DOMAIN)
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::DigestBuild)?;
    builder
        .field_u16(u16::from(frame.kind as u8))
        .and_then(|builder| builder.field_u16(u16::from(frame.status as u8)))
        .and_then(|builder| builder.field_bytes(&frame.correlation))
        .and_then(|builder| builder.field_bytes(frame.generation_token.as_ref()))
        .and_then(|builder| builder.field_u64(frame.operation_timeout_nanos))
        .and_then(|builder| builder.field_bytes(&frame.body))
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::DigestBuild)?;
    Ok(builder.finish())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
        }
    }
}

fn validate_endpoint_paths(
    socket_path: &Path,
    bootstrap_path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    validate_lexical_absolute_path(socket_path, MAX_UNIX_SOCKET_PATH_BYTES)?;
    validate_lexical_absolute_path(bootstrap_path, MAX_BOOTSTRAP_PATH_BYTES)?;
    let socket_parent = socket_path
        .parent()
        .ok_or(RuntimeAgentDeveloperLocalIpcError::InvalidPath)?;
    let bootstrap_parent = bootstrap_path
        .parent()
        .ok_or(RuntimeAgentDeveloperLocalIpcError::InvalidPath)?;
    if socket_parent != bootstrap_parent || socket_path == bootstrap_path {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidPath);
    }
    validate_private_parent(socket_parent, expected_uid, expected_gid)?;
    Ok(())
}

fn validate_lexical_absolute_path(
    path: &Path,
    max_bytes: usize,
) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.as_os_str().as_bytes().is_empty()
        || path.as_os_str().as_bytes().len() > max_bytes
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidPath);
    }
    for component in path.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(RuntimeAgentDeveloperLocalIpcError::InvalidPath);
        }
    }
    Ok(())
}

fn validate_existing_path_chain(path: &Path) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    validate_lexical_absolute_path(path, usize::MAX)?;
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeAgentDeveloperLocalIpcError::SymlinkRejected);
        }
    }
    Ok(())
}

fn validate_private_parent(
    parent: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    validate_existing_path_chain(parent)?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || !matches!(mode, PRIVATE_DIRECTORY_MODE | SHARED_SOCKET_DIRECTORY_MODE)
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InsecurePermissions);
    }
    Ok(())
}

fn validate_private_regular_file(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != BOOTSTRAP_MODE
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InsecurePermissions);
    }
    Ok(())
}

fn validate_private_socket(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o7777 != SOCKET_MODE
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InsecurePermissions);
    }
    Ok(())
}

fn generate_secret<const BYTES: usize>()
-> Result<Zeroizing<[u8; BYTES]>, RuntimeAgentDeveloperLocalIpcError> {
    let owned = open(
        Path::new("/dev/urandom"),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| RuntimeAgentDeveloperLocalIpcError::EntropyUnavailable)?;
    let mut source = File::from(owned);
    let metadata = source
        .metadata()
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    if !metadata.file_type().is_char_device() {
        return Err(RuntimeAgentDeveloperLocalIpcError::EntropyUnavailable);
    }
    let mut secret = Zeroizing::new([0_u8; BYTES]);
    source
        .read_exact(secret.as_mut())
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    if secret.iter().all(|byte| *byte == 0) {
        return Err(RuntimeAgentDeveloperLocalIpcError::EntropyUnavailable);
    }
    Ok(secret)
}

fn create_bootstrap_file(
    path: &Path,
    wire: &[u8],
    expected_uid: u32,
    expected_gid: u32,
) -> Result<FileIdentity, RuntimeAgentDeveloperLocalIpcError> {
    let owned = open(
        path,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|_| RuntimeAgentDeveloperLocalIpcError::BootstrapCreateFailed)?;
    let mut file = File::from(owned);
    file.set_permissions(fs::Permissions::from_mode(BOOTSTRAP_MODE))
        .and_then(|()| file.write_all(wire))
        .and_then(|()| file.sync_all())
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    validate_private_regular_file(&metadata, expected_uid, expected_gid)?;
    let named = fs::symlink_metadata(path)
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    validate_private_regular_file(&named, expected_uid, expected_gid)?;
    let identity = FileIdentity::from_metadata(&metadata);
    if identity != FileIdentity::from_metadata(&named) {
        return Err(RuntimeAgentDeveloperLocalIpcError::EndpointIdentityChanged);
    }
    sync_parent(path)?;
    Ok(identity)
}

fn read_bootstrap_file(
    path: &Path,
) -> Result<RuntimeAgentDeveloperLocalBootstrapV1, RuntimeAgentDeveloperLocalIpcError> {
    validate_lexical_absolute_path(path, MAX_BOOTSTRAP_PATH_BYTES)?;
    let uid = geteuid().as_raw();
    let gid = getegid().as_raw();
    let parent = path
        .parent()
        .ok_or(RuntimeAgentDeveloperLocalIpcError::InvalidPath)?;
    validate_private_parent(parent, uid, gid)?;
    let named_before = fs::symlink_metadata(path)
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    validate_private_regular_file(&named_before, uid, gid)?;
    let expected = FileIdentity::from_metadata(&named_before);
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| RuntimeAgentDeveloperLocalIpcError::BootstrapOpenFailed)?;
    let mut file = File::from(owned);
    let opened = file
        .metadata()
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    validate_private_regular_file(&opened, uid, gid)?;
    if expected != FileIdentity::from_metadata(&opened)
        || usize::try_from(opened.len())
            .ok()
            .is_none_or(|length| !(PXAB_HEADER_BYTES..=MAX_BOOTSTRAP_FRAME_BYTES).contains(&length))
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::EndpointIdentityChanged);
    }
    let length = usize::try_from(opened.len())
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::FrameTooLarge)?;
    let mut wire = Zeroizing::new(vec![0_u8; length]);
    file.read_exact(&mut wire)
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    let named_after = fs::symlink_metadata(path)
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    if expected != FileIdentity::from_metadata(&named_after) {
        return Err(RuntimeAgentDeveloperLocalIpcError::EndpointIdentityChanged);
    }
    let bootstrap = decode_bootstrap(&wire)?;
    if bootstrap.socket_path.parent() != Some(parent) {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap);
    }
    validate_socket_path(&bootstrap)?;
    Ok(bootstrap)
}

fn validate_socket_path(
    bootstrap: &RuntimeAgentDeveloperLocalBootstrapV1,
) -> Result<FileIdentity, RuntimeAgentDeveloperLocalIpcError> {
    let parent = bootstrap
        .socket_path
        .parent()
        .ok_or(RuntimeAgentDeveloperLocalIpcError::InvalidPath)?;
    validate_private_parent(parent, bootstrap.server_uid, bootstrap.server_gid)?;
    let metadata = fs::symlink_metadata(&bootstrap.socket_path)
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    validate_private_socket(&metadata, bootstrap.server_uid, bootstrap.server_gid)?;
    Ok(FileIdentity::from_metadata(&metadata))
}

fn bind_listener(
    config: &RuntimeAgentDeveloperLocalIpcConfigV1,
) -> Result<(StdUnixListener, FileIdentity), RuntimeAgentDeveloperLocalIpcError> {
    validate_endpoint_paths(
        &config.socket_path,
        &config.bootstrap_path,
        config.expected_uid,
        config.expected_gid,
    )?;
    recover_stale_endpoint_files(
        &config.socket_path,
        &config.bootstrap_path,
        config.expected_uid,
        config.expected_gid,
    )?;
    let listener = StdUnixListener::bind(&config.socket_path)
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(SOCKET_MODE))
        .and_then(|()| listener.set_nonblocking(true))
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    let metadata = fs::symlink_metadata(&config.socket_path)
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    validate_private_socket(&metadata, config.expected_uid, config.expected_gid)?;
    sync_parent(&config.socket_path)?;
    Ok((listener, FileIdentity::from_metadata(&metadata)))
}

fn recover_stale_endpoint_files(
    socket_path: &Path,
    bootstrap_path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    let socket_metadata = match fs::symlink_metadata(socket_path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(RuntimeAgentDeveloperLocalIpcError::Io(error.kind())),
    };
    let bootstrap_metadata = match fs::symlink_metadata(bootstrap_path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(RuntimeAgentDeveloperLocalIpcError::Io(error.kind())),
    };

    let Some(socket_metadata) = socket_metadata else {
        return if bootstrap_metadata.is_none() {
            Ok(())
        } else {
            // This implementation never publishes PXAB before PXAI. A lone
            // bootstrap therefore has no positive stale-owner proof and stays
            // fail-closed instead of being treated as disposable state.
            Err(RuntimeAgentDeveloperLocalIpcError::EndpointAlreadyExists)
        };
    };
    validate_private_socket(&socket_metadata, expected_uid, expected_gid)?;
    let socket_identity = FileIdentity::from_metadata(&socket_metadata);

    let bootstrap_identity = match bootstrap_metadata {
        Some(metadata) => {
            validate_private_regular_file(&metadata, expected_uid, expected_gid)?;
            let identity = FileIdentity::from_metadata(&metadata);
            let bootstrap = read_bootstrap_file(bootstrap_path)?;
            if bootstrap.socket_path.as_path() != socket_path
                || bootstrap.server_uid != expected_uid
                || bootstrap.server_gid != expected_gid
            {
                return Err(RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap);
            }
            Some(identity)
        }
        None => None,
    };

    match StdUnixStream::connect(socket_path) {
        Ok(stream) => {
            drop(stream);
            return Err(RuntimeAgentDeveloperLocalIpcError::EndpointAlreadyExists);
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        Err(error) => return Err(RuntimeAgentDeveloperLocalIpcError::Io(error.kind())),
    }

    if let Some(identity) = bootstrap_identity {
        remove_exact_endpoint_file(bootstrap_path, identity, false, expected_uid, expected_gid)?;
    }
    remove_exact_endpoint_file(
        socket_path,
        socket_identity,
        true,
        expected_uid,
        expected_gid,
    )?;
    sync_parent(socket_path)
}

fn remove_exact_endpoint_file(
    path: &Path,
    identity: FileIdentity,
    socket: bool,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::EndpointIdentityChanged)?;
    if socket {
        validate_private_socket(&metadata, expected_uid, expected_gid)?;
    } else {
        validate_private_regular_file(&metadata, expected_uid, expected_gid)?;
    }
    if FileIdentity::from_metadata(&metadata) != identity {
        return Err(RuntimeAgentDeveloperLocalIpcError::EndpointIdentityChanged);
    }
    fs::remove_file(path).map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))
}

fn sync_parent(path: &Path) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    let parent = path
        .parent()
        .ok_or(RuntimeAgentDeveloperLocalIpcError::InvalidPath)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))
}

struct EndpointFilesGuard {
    socket_path: PathBuf,
    socket_identity: FileIdentity,
    bootstrap_path: PathBuf,
    bootstrap_identity: Option<FileIdentity>,
}

impl EndpointFilesGuard {
    fn cleanup(&mut self) {
        if let Some(identity) = self.bootstrap_identity.take() {
            remove_same_file(&self.bootstrap_path, identity, false);
        }
        remove_same_file(&self.socket_path, self.socket_identity, true);
        let _ = sync_parent(&self.socket_path);
    }
}

impl Drop for EndpointFilesGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn remove_same_file(path: &Path, identity: FileIdentity, socket: bool) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    let expected_type = if socket {
        metadata.file_type().is_socket()
    } else {
        metadata.is_file()
    };
    if expected_type && FileIdentity::from_metadata(&metadata) == identity {
        let _ = fs::remove_file(path);
    }
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

fn duplicate_token(token: &Zeroizing<[u8; 32]>) -> Zeroizing<[u8; 32]> {
    let mut duplicate = Zeroizing::new([0_u8; 32]);
    duplicate.copy_from_slice(token.as_ref());
    duplicate
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

/// Display-safe local IPC failures; secret bytes and raw payloads are absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAgentDeveloperLocalIpcError {
    InvalidConfiguration,
    InvalidPath,
    SymlinkRejected,
    InsecurePermissions,
    EndpointAlreadyExists,
    EndpointIdentityChanged,
    EntropyUnavailable,
    BootstrapCreateFailed,
    BootstrapOpenFailed,
    InvalidBootstrap,
    InvalidFrame,
    FrameTooLarge,
    DigestBuild,
    DigestMismatch,
    UnknownOperation,
    UnknownResponseStatus,
    PeerCredentialsMismatch,
    AuthenticationFailed,
    CorrelationMismatch,
    ResponseKindMismatch,
    OwnerUnavailable,
    GenerationRetired,
    OperationRejected,
    OperationTimedOut,
    Overloaded,
    Closed,
    SequenceExhausted,
    ThreadStartFailed,
    ThreadPanicked,
    EndpointFailed,
    ShutdownAlreadyRequested,
    Io(io::ErrorKind),
    Protocol,
}

impl fmt::Display for RuntimeAgentDeveloperLocalIpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "DeveloperLocal Agent IPC configuration is invalid",
            Self::InvalidPath => "DeveloperLocal Agent IPC path is invalid",
            Self::SymlinkRejected => "DeveloperLocal Agent IPC path contains a symlink",
            Self::InsecurePermissions => "DeveloperLocal Agent IPC permissions are insecure",
            Self::EndpointAlreadyExists => "DeveloperLocal Agent IPC endpoint already exists",
            Self::EndpointIdentityChanged => "DeveloperLocal Agent IPC endpoint identity changed",
            Self::EntropyUnavailable => "DeveloperLocal Agent IPC entropy is unavailable",
            Self::BootstrapCreateFailed => "DeveloperLocal Agent IPC bootstrap creation failed",
            Self::BootstrapOpenFailed => "DeveloperLocal Agent IPC bootstrap open failed",
            Self::InvalidBootstrap => "DeveloperLocal Agent IPC bootstrap is invalid",
            Self::InvalidFrame => "DeveloperLocal Agent IPC frame is invalid",
            Self::FrameTooLarge => "DeveloperLocal Agent IPC frame exceeds its bound",
            Self::DigestBuild | Self::DigestMismatch => {
                "DeveloperLocal Agent IPC integrity validation failed"
            }
            Self::UnknownOperation => "DeveloperLocal Agent IPC operation is unknown",
            Self::UnknownResponseStatus => "DeveloperLocal Agent IPC response status is unknown",
            Self::PeerCredentialsMismatch => "DeveloperLocal Agent IPC peer identity mismatched",
            Self::AuthenticationFailed => "DeveloperLocal Agent IPC authentication failed",
            Self::CorrelationMismatch => "DeveloperLocal Agent IPC response correlation mismatched",
            Self::ResponseKindMismatch => "DeveloperLocal Agent IPC response kind mismatched",
            Self::OwnerUnavailable => "Runtime-managed Agent owner is unavailable",
            Self::GenerationRetired => "Runtime-managed Agent generation is retired",
            Self::OperationRejected => "Runtime-managed Agent operation was rejected",
            Self::OperationTimedOut => "Runtime-managed Agent operation timed out",
            Self::Overloaded => "DeveloperLocal Agent IPC endpoint is overloaded",
            Self::Closed => "DeveloperLocal Agent IPC client is closed",
            Self::SequenceExhausted => "DeveloperLocal Agent IPC correlation space is exhausted",
            Self::ThreadStartFailed => "DeveloperLocal Agent IPC owner thread failed to start",
            Self::ThreadPanicked => "DeveloperLocal Agent IPC owner thread panicked",
            Self::EndpointFailed => "DeveloperLocal Agent IPC endpoint failed",
            Self::ShutdownAlreadyRequested => {
                "DeveloperLocal Agent IPC shutdown was already requested"
            }
            Self::Io(_) => "DeveloperLocal Agent IPC I/O failed",
            Self::Protocol => "Agent conversation protocol validation failed",
        })
    }
}

impl std::error::Error for RuntimeAgentDeveloperLocalIpcError {}

/// Joined lifecycle owner for one PXAI socket and its PXAB bootstrap file.
pub struct RuntimeAgentDeveloperLocalIpcLifecycleV1 {
    socket_path: PathBuf,
    bootstrap_path: PathBuf,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), RuntimeAgentDeveloperLocalIpcError>>>,
}

impl fmt::Debug for RuntimeAgentDeveloperLocalIpcLifecycleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeAgentDeveloperLocalIpcLifecycleV1")
            .field("socket_path", &self.socket_path)
            .field("bootstrap_path", &self.bootstrap_path)
            .field("running", &self.thread.is_some())
            .finish()
    }
}

impl RuntimeAgentDeveloperLocalIpcLifecycleV1 {
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn bootstrap_path(&self) -> &Path {
        &self.bootstrap_path
    }

    pub fn shutdown_and_join(mut self) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
        let sender = self.shutdown.take();
        let thread = self.thread.take();
        if sender.is_none() && thread.is_none() {
            return Err(RuntimeAgentDeveloperLocalIpcError::ShutdownAlreadyRequested);
        }
        if let Some(sender) = sender {
            let _ = sender.send(());
        }
        match thread {
            None => Ok(()),
            Some(thread) => match thread.join() {
                Ok(result) => result,
                Err(_) => Err(RuntimeAgentDeveloperLocalIpcError::ThreadPanicked),
            },
        }
    }
}

impl Drop for RuntimeAgentDeveloperLocalIpcLifecycleV1 {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

/// Starts a same-user PXAI endpoint backed only by an opaque Runtime handle.
pub fn start_runtime_agent_developer_local_ipc_v1(
    handle: RuntimeAgentConversationHandle,
    config: RuntimeAgentDeveloperLocalIpcConfigV1,
) -> Result<RuntimeAgentDeveloperLocalIpcLifecycleV1, RuntimeAgentDeveloperLocalIpcError> {
    validate_endpoint_paths(
        &config.socket_path,
        &config.bootstrap_path,
        config.expected_uid,
        config.expected_gid,
    )?;
    let (standard_listener, socket_identity) = bind_listener(&config)?;
    let mut guard = EndpointFilesGuard {
        socket_path: config.socket_path.clone(),
        socket_identity,
        bootstrap_path: config.bootstrap_path.clone(),
        bootstrap_identity: None,
    };
    let generation_token = generate_secret::<32>()?;
    let bootstrap = Arc::new(RuntimeAgentDeveloperLocalBootstrapV1 {
        socket_path: config.socket_path.clone(),
        generation_token,
        deck_run_id: config.deck_run_id,
        session_id: config.session_id,
        request_deadline_budget_nanos: u64::try_from(config.request_deadline_budget.as_nanos())
            .map_err(|_| RuntimeAgentDeveloperLocalIpcError::InvalidConfiguration)?,
        operation_timeout_nanos: u64::try_from(config.operation_timeout.as_nanos())
            .map_err(|_| RuntimeAgentDeveloperLocalIpcError::InvalidConfiguration)?,
        command_capacity: config.command_capacity,
        server_uid: config.expected_uid,
        server_gid: config.expected_gid,
    });
    let bootstrap_wire = encode_bootstrap(&bootstrap)?;
    guard.bootstrap_identity = Some(create_bootstrap_file(
        &config.bootstrap_path,
        &bootstrap_wire,
        config.expected_uid,
        config.expected_gid,
    )?);

    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let max_in_flight = config.max_in_flight;
    let shutdown_timeout = config.shutdown_timeout;
    let thread = thread::Builder::new()
        .name("paraegox-agent-developer-local-ipc-v1".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| RuntimeAgentDeveloperLocalIpcError::EndpointFailed);
            let result = match runtime {
                Ok(runtime) => runtime.block_on(async move {
                    let listener = UnixListener::from_std(standard_listener)
                        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::EndpointFailed)?;
                    let _ = ready_sender.send(Ok(()));
                    serve_endpoint(
                        listener,
                        handle,
                        bootstrap,
                        max_in_flight,
                        shutdown_timeout,
                        shutdown_receiver,
                    )
                    .await
                }),
                Err(error) => {
                    let _ = ready_sender.send(Err(error));
                    Err(error)
                }
            };
            drop(guard);
            result
        })
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::ThreadStartFailed)?;
    match ready_receiver.recv_timeout(MAX_IO_TIMEOUT) {
        Ok(Ok(())) => Ok(RuntimeAgentDeveloperLocalIpcLifecycleV1 {
            socket_path: config.socket_path,
            bootstrap_path: config.bootstrap_path,
            shutdown: Some(shutdown_sender),
            thread: Some(thread),
        }),
        Ok(Err(error)) => {
            let _ = shutdown_sender.send(());
            let _ = thread.join();
            Err(error)
        }
        Err(_) => {
            let _ = shutdown_sender.send(());
            let _ = thread.join();
            Err(RuntimeAgentDeveloperLocalIpcError::EndpointFailed)
        }
    }
}

async fn serve_endpoint(
    listener: UnixListener,
    handle: RuntimeAgentConversationHandle,
    bootstrap: Arc<RuntimeAgentDeveloperLocalBootstrapV1>,
    max_in_flight: usize,
    shutdown_timeout: Duration,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    let permits = Arc::new(Semaphore::new(max_in_flight));
    let mut tasks = JoinSet::new();
    let mut first_task_failure = None;
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) {
                    first_task_failure = Some(RuntimeAgentDeveloperLocalIpcError::EndpointFailed);
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                if !peer_matches(&stream, bootstrap.server_uid, bootstrap.server_gid) {
                    drop(stream);
                    continue;
                }
                let connection_handle = handle.clone();
                let connection_bootstrap = Arc::clone(&bootstrap);
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = serve_connection(stream, connection_handle, connection_bootstrap).await;
                });
            }
        }
    }

    let deadline = Instant::now() + shutdown_timeout;
    while !tasks.is_empty() {
        match timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok(()))) => {}
            Ok(Some(Err(_))) => {
                first_task_failure = Some(RuntimeAgentDeveloperLocalIpcError::EndpointFailed);
            }
            Ok(None) => break,
            Err(_) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }
        }
    }
    first_task_failure.map_or(Ok(()), Err)
}

fn peer_matches(stream: &UnixStream, expected_uid: u32, expected_gid: u32) -> bool {
    stream.peer_cred().is_ok_and(|credentials| {
        credentials.uid() == expected_uid && credentials.gid() == expected_gid
    })
}

async fn serve_connection(
    mut stream: UnixStream,
    handle: RuntimeAgentConversationHandle,
    bootstrap: Arc<RuntimeAgentDeveloperLocalBootstrapV1>,
) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    let request = timeout(
        MAX_IO_TIMEOUT,
        read_ipc_frame(&mut stream, PXAI_REQUEST_MAGIC),
    )
    .await
    .map_err(|_| RuntimeAgentDeveloperLocalIpcError::OperationTimedOut)??;
    if request.status != ResponseStatus::Ok
        || !constant_time_eq(
            request.generation_token.as_ref(),
            bootstrap.generation_token.as_ref(),
        )
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::AuthenticationFailed);
    }
    let operation_timeout = Duration::from_nanos(request.operation_timeout_nanos);
    if operation_timeout > bootstrap.operation_timeout() {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidFrame);
    }
    let (status, body) = match timeout(
        operation_timeout,
        dispatch_request(&handle, &request, &bootstrap),
    )
    .await
    {
        Ok(Ok(body)) => (ResponseStatus::Ok, body),
        Ok(Err(status)) => (status, Zeroizing::new(Vec::new())),
        Err(_) => (
            ResponseStatus::OperationTimedOut,
            Zeroizing::new(Vec::new()),
        ),
    };
    let response = IpcFrame {
        kind: request.kind,
        status,
        correlation: request.correlation,
        generation_token: duplicate_token(&bootstrap.generation_token),
        operation_timeout_nanos: request.operation_timeout_nanos,
        body,
    };
    let response_wire = encode_ipc_frame(PXAI_RESPONSE_MAGIC, &response)?;
    timeout(MAX_IO_TIMEOUT, write_ipc_frame(&mut stream, &response_wire))
        .await
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::OperationTimedOut)??;
    Ok(())
}

async fn dispatch_request(
    handle: &RuntimeAgentConversationHandle,
    request: &IpcFrame,
    bootstrap: &RuntimeAgentDeveloperLocalBootstrapV1,
) -> Result<Zeroizing<Vec<u8>>, ResponseStatus> {
    let timeout = Duration::from_nanos(request.operation_timeout_nanos);
    match decode_scoped_request(request, bootstrap)? {
        ScopedRequest::Submit(semantic) => {
            let terminal = handle
                .submit(semantic, timeout)
                .await
                .map_err(runtime_error_status)?;
            Ok(Zeroizing::new(terminal.canonical_wire().into_vec()))
        }
        ScopedRequest::Open(control) => {
            let outcome = handle
                .open_session(control.deck_run_id(), control.session_id(), timeout)
                .await
                .map_err(runtime_error_status)?;
            let response = AgentConversationControlV1::open_result(
                control.deck_run_id(),
                control.session_id(),
                outcome,
            );
            encode_control_response(response)
        }
        ScopedRequest::Get(control) => {
            let request_id = control.request_id().ok_or(ResponseStatus::Malformed)?;
            let state = handle
                .get(
                    control.deck_run_id(),
                    control.session_id(),
                    request_id,
                    timeout,
                )
                .await
                .map_err(runtime_error_status)?;
            let response = AgentConversationControlV1::get_result(
                control.deck_run_id(),
                control.session_id(),
                request_id,
                state,
            )
            .map_err(|_| ResponseStatus::OperationRejected)?;
            encode_control_response(response)
        }
        ScopedRequest::Watch(control) => {
            let AgentConversationControlBodyV1::WatchRequest { cursor, limit } = control.body()
            else {
                return Err(ResponseStatus::Malformed);
            };
            let batch = handle
                .watch(
                    control.deck_run_id(),
                    control.session_id(),
                    *cursor,
                    *limit,
                    timeout,
                )
                .await
                .map_err(runtime_error_status)?;
            let response = match batch {
                None => AgentConversationControlV1::watch_result_not_found(
                    control.deck_run_id(),
                    control.session_id(),
                ),
                Some(batch) => AgentConversationControlV1::watch_result(
                    control.deck_run_id(),
                    control.session_id(),
                    batch,
                )
                .map_err(|_| ResponseStatus::OperationRejected)?,
            };
            encode_control_response(response)
        }
        ScopedRequest::Cancel(control) => {
            let request_id = control.request_id().ok_or(ResponseStatus::Malformed)?;
            let state = handle
                .cancel(
                    control.deck_run_id(),
                    control.session_id(),
                    request_id,
                    timeout,
                )
                .await
                .map_err(runtime_error_status)?;
            let response = AgentConversationControlV1::cancel_result(
                control.deck_run_id(),
                control.session_id(),
                request_id,
                state,
            )
            .map_err(|_| ResponseStatus::OperationRejected)?;
            encode_control_response(response)
        }
    }
}

enum ScopedRequest {
    Open(AgentConversationControlV1),
    Submit(AgentConversationRequestV1),
    Get(AgentConversationControlV1),
    Watch(AgentConversationControlV1),
    Cancel(AgentConversationControlV1),
}

fn decode_scoped_request(
    request: &IpcFrame,
    bootstrap: &RuntimeAgentDeveloperLocalBootstrapV1,
) -> Result<ScopedRequest, ResponseStatus> {
    match request.kind {
        OperationKind::Submit => {
            let semantic = AgentConversationRequestV1::decode(&request.body)
                .map_err(|_| ResponseStatus::Malformed)?;
            if !constant_time_eq(semantic.request_id().as_bytes(), &request.correlation)
                || semantic.deck_run_id() != bootstrap.deck_run_id
                || semantic.session_id() != bootstrap.session_id
            {
                return Err(ResponseStatus::Malformed);
            }
            Ok(ScopedRequest::Submit(semantic))
        }
        OperationKind::Open => decode_scoped_control(
            request,
            bootstrap,
            ControlRequestKind::Open,
            ScopedRequest::Open,
        ),
        OperationKind::Get => decode_scoped_control(
            request,
            bootstrap,
            ControlRequestKind::Get,
            ScopedRequest::Get,
        ),
        OperationKind::Watch => decode_scoped_control(
            request,
            bootstrap,
            ControlRequestKind::Watch,
            ScopedRequest::Watch,
        ),
        OperationKind::Cancel => decode_scoped_control(
            request,
            bootstrap,
            ControlRequestKind::Cancel,
            ScopedRequest::Cancel,
        ),
    }
}

fn decode_scoped_control(
    request: &IpcFrame,
    bootstrap: &RuntimeAgentDeveloperLocalBootstrapV1,
    expected: ControlRequestKind,
    wrap: fn(AgentConversationControlV1) -> ScopedRequest,
) -> Result<ScopedRequest, ResponseStatus> {
    let control = decode_control_request(request, expected)?;
    if control.deck_run_id() != bootstrap.deck_run_id
        || control.session_id() != bootstrap.session_id
    {
        return Err(ResponseStatus::Malformed);
    }
    Ok(wrap(control))
}

#[derive(Clone, Copy)]
enum ControlRequestKind {
    Open,
    Get,
    Watch,
    Cancel,
}

fn decode_control_request(
    request: &IpcFrame,
    expected: ControlRequestKind,
) -> Result<AgentConversationControlV1, ResponseStatus> {
    let control =
        AgentConversationControlV1::decode(&request.body).map_err(|_| ResponseStatus::Malformed)?;
    let matches = matches!(
        (expected, control.body()),
        (
            ControlRequestKind::Open,
            AgentConversationControlBodyV1::OpenRequest
        ) | (
            ControlRequestKind::Get,
            AgentConversationControlBodyV1::GetRequest
        ) | (
            ControlRequestKind::Watch,
            AgentConversationControlBodyV1::WatchRequest { .. }
        ) | (
            ControlRequestKind::Cancel,
            AgentConversationControlBodyV1::CancelRequest
        )
    );
    if !matches {
        return Err(ResponseStatus::Malformed);
    }
    Ok(control)
}

fn encode_control_response(
    response: AgentConversationControlV1,
) -> Result<Zeroizing<Vec<u8>>, ResponseStatus> {
    response
        .canonical_wire()
        .map(|wire| Zeroizing::new(wire.into_vec()))
        .map_err(|_| ResponseStatus::OperationRejected)
}

fn runtime_error_status(error: RuntimeAgentConversationError) -> ResponseStatus {
    match error {
        RuntimeAgentConversationError::Closed | RuntimeAgentConversationError::OwnerUnavailable => {
            ResponseStatus::OwnerUnavailable
        }
        RuntimeAgentConversationError::OwnerRetired => ResponseStatus::GenerationRetired,
        RuntimeAgentConversationError::OperationRejected => ResponseStatus::OperationRejected,
    }
}

async fn read_ipc_frame(
    stream: &mut UnixStream,
    magic: &[u8; 4],
) -> Result<IpcFrame, RuntimeAgentDeveloperLocalIpcError> {
    let mut header = Zeroizing::new([0_u8; PXAI_HEADER_BYTES]);
    stream
        .read_exact(header.as_mut())
        .await
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    if &header[0..4] != magic || usize::from(read_u16(header.as_ref(), 6)) != PXAI_HEADER_BYTES {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidFrame);
    }
    let frame_len = usize::try_from(read_u32(header.as_ref(), 8))
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::InvalidFrame)?;
    if !(PXAI_HEADER_BYTES..=MAX_IPC_FRAME_BYTES).contains(&frame_len) {
        return Err(RuntimeAgentDeveloperLocalIpcError::FrameTooLarge);
    }
    let mut wire = Zeroizing::new(vec![0_u8; frame_len]);
    wire[..PXAI_HEADER_BYTES].copy_from_slice(header.as_ref());
    stream
        .read_exact(&mut wire[PXAI_HEADER_BYTES..])
        .await
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .await
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?
        != 0
    {
        return Err(RuntimeAgentDeveloperLocalIpcError::InvalidFrame);
    }
    decode_ipc_frame(magic, &wire)
}

async fn write_ipc_frame(
    stream: &mut UnixStream,
    wire: &[u8],
) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
    stream
        .write_all(wire)
        .await
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
    stream
        .shutdown()
        .await
        .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))
}

struct ClientInner {
    bootstrap: RuntimeAgentDeveloperLocalBootstrapV1,
    client_instance_nonce: Zeroizing<[u8; 32]>,
    next_correlation_sequence: AtomicU64,
    closed: AtomicBool,
}

/// Cloneable, no-retry typed client for a single PXAB generation.
#[derive(Clone)]
pub struct RuntimeAgentDeveloperLocalIpcClientV1 {
    inner: Arc<ClientInner>,
}

impl fmt::Debug for RuntimeAgentDeveloperLocalIpcClientV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeAgentDeveloperLocalIpcClientV1")
            .field("socket_path", &self.inner.bootstrap.socket_path)
            .field("deck_run_id", &self.inner.bootstrap.deck_run_id)
            .field("session_id", &self.inner.bootstrap.session_id)
            .field("closed", &self.inner.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl RuntimeAgentDeveloperLocalIpcClientV1 {
    /// Loads one owner-private PXAB file and creates a fresh process-local
    /// request-identity nonce. No connection or operation is retried.
    pub fn from_private_bootstrap_file(
        path: &Path,
    ) -> Result<Self, RuntimeAgentDeveloperLocalIpcError> {
        let bootstrap = read_bootstrap_file(path)?;
        let client_instance_nonce = generate_secret::<32>()?;
        Ok(Self {
            inner: Arc::new(ClientInner {
                bootstrap,
                client_instance_nonce,
                next_correlation_sequence: AtomicU64::new(1),
                closed: AtomicBool::new(false),
            }),
        })
    }

    pub const fn initial_request_sequence(&self) -> u64 {
        1
    }

    pub fn client_instance_nonce(&self) -> [u8; 32] {
        *self.inner.client_instance_nonce
    }

    pub fn deck_run_id(&self) -> AgentConversationDeckRunId {
        self.inner.bootstrap.deck_run_id
    }

    pub fn session_id(&self) -> AgentConversationSessionId {
        self.inner.bootstrap.session_id
    }

    pub fn request_deadline_budget_nanos(&self) -> u64 {
        self.inner.bootstrap.request_deadline_budget_nanos
    }

    pub fn operation_timeout(&self) -> Duration {
        self.inner.bootstrap.operation_timeout()
    }

    pub fn command_capacity(&self) -> u16 {
        self.inner.bootstrap.command_capacity
    }

    pub async fn open_session(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        operation_timeout: Duration,
    ) -> Result<AgentConversationOpenOutcomeV1, RuntimeAgentDeveloperLocalIpcError> {
        self.validate_scope(deck_run_id, session_id)?;
        let control = AgentConversationControlV1::open_request(deck_run_id, session_id);
        let response = self
            .send_control(OperationKind::Open, control, operation_timeout)
            .await?;
        match response.body() {
            AgentConversationControlBodyV1::OpenResult(outcome) => Ok(*outcome),
            _ => Err(RuntimeAgentDeveloperLocalIpcError::ResponseKindMismatch),
        }
    }

    pub async fn submit(
        &self,
        request: AgentConversationRequestV1,
        operation_timeout: Duration,
    ) -> Result<AgentConversationTerminalV1, RuntimeAgentDeveloperLocalIpcError> {
        self.validate_scope(request.deck_run_id(), request.session_id())?;
        let correlation = *request.request_id().as_bytes();
        let response = self
            .exchange(
                OperationKind::Submit,
                correlation,
                Zeroizing::new(request.canonical_wire().into_vec()),
                operation_timeout,
            )
            .await?;
        let terminal = AgentConversationTerminalV1::decode(&response.body)
            .map_err(|_| RuntimeAgentDeveloperLocalIpcError::Protocol)?;
        if !terminal.correlates(&request) {
            return Err(RuntimeAgentDeveloperLocalIpcError::CorrelationMismatch);
        }
        Ok(terminal)
    }

    pub async fn get(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        operation_timeout: Duration,
    ) -> Result<AgentConversationGetStateV1, RuntimeAgentDeveloperLocalIpcError> {
        self.validate_scope(deck_run_id, session_id)?;
        let control = AgentConversationControlV1::get_request(deck_run_id, session_id, request_id);
        let response = self
            .send_control(OperationKind::Get, control, operation_timeout)
            .await?;
        match response.body() {
            AgentConversationControlBodyV1::GetResult(state) => Ok(state.clone()),
            _ => Err(RuntimeAgentDeveloperLocalIpcError::ResponseKindMismatch),
        }
    }

    pub async fn watch(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        cursor: u64,
        limit: u32,
        operation_timeout: Duration,
    ) -> Result<Option<AgentConversationWatchBatchV1>, RuntimeAgentDeveloperLocalIpcError> {
        self.validate_scope(deck_run_id, session_id)?;
        let control =
            AgentConversationControlV1::watch_request(deck_run_id, session_id, cursor, limit)
                .map_err(|_| RuntimeAgentDeveloperLocalIpcError::Protocol)?;
        let response = self
            .send_control(OperationKind::Watch, control, operation_timeout)
            .await?;
        match response.body() {
            AgentConversationControlBodyV1::WatchResultNotFound => Ok(None),
            AgentConversationControlBodyV1::WatchResult(batch) => {
                batch
                    .validate_for_request(cursor, limit)
                    .map_err(|_| RuntimeAgentDeveloperLocalIpcError::Protocol)?;
                Ok(Some(batch.clone()))
            }
            _ => Err(RuntimeAgentDeveloperLocalIpcError::ResponseKindMismatch),
        }
    }

    pub async fn cancel(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
        request_id: AgentConversationRequestId,
        operation_timeout: Duration,
    ) -> Result<AgentConversationCancelStateV1, RuntimeAgentDeveloperLocalIpcError> {
        self.validate_scope(deck_run_id, session_id)?;
        let control =
            AgentConversationControlV1::cancel_request(deck_run_id, session_id, request_id);
        let response = self
            .send_control(OperationKind::Cancel, control, operation_timeout)
            .await?;
        match response.body() {
            AgentConversationControlBodyV1::CancelResult(state) => Ok(state.clone()),
            _ => Err(RuntimeAgentDeveloperLocalIpcError::ResponseKindMismatch),
        }
    }

    /// Closes only this client value and its clones. Runtime remains the sole
    /// binding and Agent lifecycle owner.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
    }

    fn validate_scope(
        &self,
        deck_run_id: AgentConversationDeckRunId,
        session_id: AgentConversationSessionId,
    ) -> Result<(), RuntimeAgentDeveloperLocalIpcError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RuntimeAgentDeveloperLocalIpcError::Closed);
        }
        if deck_run_id != self.inner.bootstrap.deck_run_id
            || session_id != self.inner.bootstrap.session_id
        {
            return Err(RuntimeAgentDeveloperLocalIpcError::OperationRejected);
        }
        Ok(())
    }

    async fn send_control(
        &self,
        kind: OperationKind,
        control: AgentConversationControlV1,
        operation_timeout: Duration,
    ) -> Result<AgentConversationControlV1, RuntimeAgentDeveloperLocalIpcError> {
        let body = Zeroizing::new(
            control
                .canonical_wire()
                .map_err(|_| RuntimeAgentDeveloperLocalIpcError::Protocol)?
                .into_vec(),
        );
        let correlation = self.next_control_correlation(kind, &body)?;
        let response = self
            .exchange(kind, correlation, body, operation_timeout)
            .await?;
        let semantic = AgentConversationControlV1::decode(&response.body)
            .map_err(|_| RuntimeAgentDeveloperLocalIpcError::Protocol)?;
        if semantic.deck_run_id() != control.deck_run_id()
            || semantic.session_id() != control.session_id()
            || semantic.request_id() != control.request_id()
        {
            return Err(RuntimeAgentDeveloperLocalIpcError::CorrelationMismatch);
        }
        Ok(semantic)
    }

    fn next_control_correlation(
        &self,
        kind: OperationKind,
        body: &[u8],
    ) -> Result<[u8; 16], RuntimeAgentDeveloperLocalIpcError> {
        let sequence = self
            .inner
            .next_correlation_sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| RuntimeAgentDeveloperLocalIpcError::SequenceExhausted)?;
        let mut builder = Digest32Builder::try_new(PXAI_CORRELATION_DOMAIN)
            .map_err(|_| RuntimeAgentDeveloperLocalIpcError::DigestBuild)?;
        builder
            .field_bytes(self.inner.client_instance_nonce.as_ref())
            .and_then(|builder| builder.field_u64(sequence))
            .and_then(|builder| builder.field_u16(u16::from(kind as u8)))
            .and_then(|builder| builder.field_bytes(body))
            .map_err(|_| RuntimeAgentDeveloperLocalIpcError::DigestBuild)?;
        let digest = builder.finish();
        let mut correlation = [0_u8; 16];
        correlation.copy_from_slice(&digest.as_bytes()[..16]);
        if correlation.iter().all(|byte| *byte == 0) {
            return Err(RuntimeAgentDeveloperLocalIpcError::DigestBuild);
        }
        Ok(correlation)
    }

    async fn exchange(
        &self,
        kind: OperationKind,
        correlation: [u8; 16],
        body: Zeroizing<Vec<u8>>,
        operation_timeout: Duration,
    ) -> Result<IpcFrame, RuntimeAgentDeveloperLocalIpcError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RuntimeAgentDeveloperLocalIpcError::Closed);
        }
        if operation_timeout.is_zero()
            || operation_timeout > self.inner.bootstrap.operation_timeout()
        {
            return Err(RuntimeAgentDeveloperLocalIpcError::InvalidConfiguration);
        }
        let operation_timeout_nanos = u64::try_from(operation_timeout.as_nanos())
            .map_err(|_| RuntimeAgentDeveloperLocalIpcError::InvalidConfiguration)?;
        let request = IpcFrame {
            kind,
            status: ResponseStatus::Ok,
            correlation,
            generation_token: duplicate_token(&self.inner.bootstrap.generation_token),
            operation_timeout_nanos,
            body,
        };
        let wire = encode_ipc_frame(PXAI_REQUEST_MAGIC, &request)?;
        let socket_identity = validate_socket_path(&self.inner.bootstrap)?;
        let result = timeout(operation_timeout, async {
            let mut stream = UnixStream::connect(&self.inner.bootstrap.socket_path)
                .await
                .map_err(|error| RuntimeAgentDeveloperLocalIpcError::Io(error.kind()))?;
            if !peer_matches(
                &stream,
                self.inner.bootstrap.server_uid,
                self.inner.bootstrap.server_gid,
            ) {
                return Err(RuntimeAgentDeveloperLocalIpcError::PeerCredentialsMismatch);
            }
            if validate_socket_path(&self.inner.bootstrap)? != socket_identity {
                return Err(RuntimeAgentDeveloperLocalIpcError::EndpointIdentityChanged);
            }
            write_ipc_frame(&mut stream, &wire).await?;
            read_ipc_frame(&mut stream, PXAI_RESPONSE_MAGIC).await
        })
        .await
        .map_err(|_| RuntimeAgentDeveloperLocalIpcError::OperationTimedOut)??;
        if result.kind != kind
            || result.correlation != correlation
            || result.operation_timeout_nanos != operation_timeout_nanos
        {
            return Err(RuntimeAgentDeveloperLocalIpcError::CorrelationMismatch);
        }
        if !constant_time_eq(
            result.generation_token.as_ref(),
            self.inner.bootstrap.generation_token.as_ref(),
        ) {
            return Err(RuntimeAgentDeveloperLocalIpcError::AuthenticationFailed);
        }
        match result.status {
            ResponseStatus::Ok => Ok(result),
            ResponseStatus::Malformed => Err(RuntimeAgentDeveloperLocalIpcError::Protocol),
            ResponseStatus::AuthenticationFailed => {
                Err(RuntimeAgentDeveloperLocalIpcError::AuthenticationFailed)
            }
            ResponseStatus::OwnerUnavailable => {
                Err(RuntimeAgentDeveloperLocalIpcError::OwnerUnavailable)
            }
            ResponseStatus::GenerationRetired => {
                Err(RuntimeAgentDeveloperLocalIpcError::GenerationRetired)
            }
            ResponseStatus::OperationRejected => {
                Err(RuntimeAgentDeveloperLocalIpcError::OperationRejected)
            }
            ResponseStatus::OperationTimedOut => {
                Err(RuntimeAgentDeveloperLocalIpcError::OperationTimedOut)
            }
            ResponseStatus::Overloaded => Err(RuntimeAgentDeveloperLocalIpcError::Overloaded),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    use paraegox_agent_contracts::AgentConversationTurnId;

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "paraegox-agent-ipc-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .expect("set private mode");
            let path = path.canonicalize().expect("canonical test directory");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if let Ok(entries) = fs::read_dir(&self.path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let _ = fs::remove_file(&path).or_else(|_| fs::remove_dir_all(&path));
                }
            }
            let _ = fs::remove_dir(&self.path);
        }
    }

    fn scope() -> (AgentConversationDeckRunId, AgentConversationSessionId) {
        (
            AgentConversationDeckRunId::try_from_bytes([0x11; 16]).expect("DeckRun"),
            AgentConversationSessionId::try_from_bytes([0x22; 16]).expect("Session"),
        )
    }

    fn bootstrap(path: PathBuf, token: u8) -> RuntimeAgentDeveloperLocalBootstrapV1 {
        let (deck_run_id, session_id) = scope();
        RuntimeAgentDeveloperLocalBootstrapV1 {
            socket_path: path,
            generation_token: Zeroizing::new([token; 32]),
            deck_run_id,
            session_id,
            request_deadline_budget_nanos: 2_000_000_000,
            operation_timeout_nanos: 3_000_000_000,
            command_capacity: 4,
            server_uid: geteuid().as_raw(),
            server_gid: getegid().as_raw(),
        }
    }

    fn config(directory: &TestDirectory) -> RuntimeAgentDeveloperLocalIpcConfigV1 {
        let (deck_run_id, session_id) = scope();
        let paths = RuntimeAgentDeveloperLocalIpcPathsV1::try_new(
            directory.join("agent.sock"),
            directory.join("agent.pxab"),
            geteuid().as_raw(),
            getegid().as_raw(),
        )
        .expect("paths");
        let conversation = RuntimeAgentDeveloperLocalConversationV1::try_new(
            deck_run_id,
            session_id,
            Duration::from_secs(2),
            Duration::from_secs(3),
        )
        .expect("conversation");
        let limits = RuntimeAgentDeveloperLocalIpcLimitsV1::try_new(Duration::from_secs(2), 4, 4)
            .expect("limits");
        RuntimeAgentDeveloperLocalIpcConfigV1::try_new(paths, conversation, limits).expect("config")
    }

    #[test]
    fn pxab_round_trip_is_canonical_bounded_and_secret_redacted() {
        let directory = TestDirectory::new();
        let value = bootstrap(directory.join("agent.sock"), 0x5a);
        let wire = encode_bootstrap(&value).expect("encode bootstrap");
        assert!(wire.len() <= MAX_BOOTSTRAP_FRAME_BYTES);
        let decoded = decode_bootstrap(&wire).expect("decode bootstrap");
        assert_eq!(decoded.socket_path(), value.socket_path());
        assert_eq!(decoded.deck_run_id(), value.deck_run_id());
        assert_eq!(decoded.session_id(), value.session_id());
        assert!(constant_time_eq(
            decoded.generation_token.as_ref(),
            value.generation_token.as_ref()
        ));
        let debug = format!("{decoded:?}");
        assert!(!debug.contains(&"5a".repeat(32)));

        let mut corrupted = Zeroizing::new(wire.to_vec());
        corrupted[106] = 1;
        assert_eq!(
            decode_bootstrap(&corrupted).expect_err("reserved byte must reject"),
            RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap
        );
        let mut trailing = Zeroizing::new(wire.to_vec());
        trailing.push(0);
        assert_eq!(
            decode_bootstrap(&trailing).expect_err("trailing byte must reject"),
            RuntimeAgentDeveloperLocalIpcError::InvalidBootstrap
        );
    }

    #[test]
    fn pxai_frame_rejects_digest_length_token_and_correlation_changes() {
        let frame = IpcFrame {
            kind: OperationKind::Open,
            status: ResponseStatus::Ok,
            correlation: [0x31; 16],
            generation_token: Zeroizing::new([0x32; 32]),
            operation_timeout_nanos: 1_000_000_000,
            body: Zeroizing::new(vec![0x33; 128]),
        };
        let wire = encode_ipc_frame(PXAI_REQUEST_MAGIC, &frame).expect("encode frame");
        let decoded = decode_ipc_frame(PXAI_REQUEST_MAGIC, &wire).expect("decode frame");
        assert_eq!(decoded.kind, OperationKind::Open);
        assert_eq!(decoded.correlation, [0x31; 16]);

        for offset in [16, 32, 64, 111, PXAI_HEADER_BYTES] {
            let mut corrupted = Zeroizing::new(wire.to_vec());
            corrupted[offset] ^= 1;
            assert!(decode_ipc_frame(PXAI_REQUEST_MAGIC, &corrupted).is_err());
        }
        let mut false_length = Zeroizing::new(wire.to_vec());
        write_u32(&mut false_length, 8, u32::try_from(wire.len() + 1).unwrap());
        assert_eq!(
            decode_ipc_frame(PXAI_REQUEST_MAGIC, &false_length)
                .expect_err("false length must reject"),
            RuntimeAgentDeveloperLocalIpcError::InvalidFrame
        );
    }

    #[test]
    fn bootstrap_file_and_socket_are_owner_private_and_removed_by_guard() {
        let directory = TestDirectory::new();
        let config = config(&directory);
        let (listener, socket_identity) = bind_listener(&config).expect("bind listener");
        let value = bootstrap(config.socket_path.clone(), 0x61);
        let wire = encode_bootstrap(&value).expect("bootstrap wire");
        let bootstrap_identity = create_bootstrap_file(
            &config.bootstrap_path,
            &wire,
            config.expected_uid,
            config.expected_gid,
        )
        .expect("bootstrap file");
        let loaded =
            RuntimeAgentDeveloperLocalBootstrapV1::read_private_file(&config.bootstrap_path)
                .expect("secure bootstrap load");
        assert_eq!(loaded.socket_path(), config.socket_path());
        assert_eq!(
            fs::symlink_metadata(config.socket_path())
                .expect("socket metadata")
                .permissions()
                .mode()
                & 0o7777,
            SOCKET_MODE
        );
        assert_eq!(
            fs::symlink_metadata(config.bootstrap_path())
                .expect("bootstrap metadata")
                .permissions()
                .mode()
                & 0o7777,
            BOOTSTRAP_MODE
        );
        drop(listener);
        drop(EndpointFilesGuard {
            socket_path: config.socket_path.clone(),
            socket_identity,
            bootstrap_path: config.bootstrap_path.clone(),
            bootstrap_identity: Some(bootstrap_identity),
        });
        assert!(!config.socket_path().exists());
        assert!(!config.bootstrap_path().exists());
    }

    #[test]
    fn crash_left_endpoint_pair_is_recovered_before_a_fresh_generation_binds() {
        let directory = TestDirectory::new();
        let first = config(&directory);
        let (listener, _) = bind_listener(&first).expect("bind first-generation listener");
        let value = bootstrap(first.socket_path.clone(), 0x62);
        let wire = encode_bootstrap(&value).expect("first-generation bootstrap wire");
        create_bootstrap_file(
            &first.bootstrap_path,
            &wire,
            first.expected_uid,
            first.expected_gid,
        )
        .expect("first-generation bootstrap file");

        // A terminated process closes the listener descriptor without running
        // EndpointFilesGuard::drop, leaving the two durable names behind.
        drop(listener);

        let restarted = config(&directory);
        let (listener, socket_identity) =
            bind_listener(&restarted).expect("recover stale pair and bind fresh listener");
        assert!(restarted.socket_path().exists());
        assert!(!restarted.bootstrap_path().exists());

        drop(listener);
        drop(EndpointFilesGuard {
            socket_path: restarted.socket_path.clone(),
            socket_identity,
            bootstrap_path: restarted.bootstrap_path.clone(),
            bootstrap_identity: None,
        });
    }

    #[test]
    fn live_endpoint_pair_remains_single_owner_and_fails_closed() {
        let directory = TestDirectory::new();
        let first = config(&directory);
        let (listener, socket_identity) =
            bind_listener(&first).expect("bind active first-generation listener");
        let value = bootstrap(first.socket_path.clone(), 0x63);
        let wire = encode_bootstrap(&value).expect("active bootstrap wire");
        let bootstrap_identity = create_bootstrap_file(
            &first.bootstrap_path,
            &wire,
            first.expected_uid,
            first.expected_gid,
        )
        .expect("active bootstrap file");

        let contender = config(&directory);
        assert_eq!(
            bind_listener(&contender).expect_err("active listener must not be replaced"),
            RuntimeAgentDeveloperLocalIpcError::EndpointAlreadyExists
        );
        assert!(first.socket_path().exists());
        assert!(first.bootstrap_path().exists());

        drop(listener);
        drop(EndpointFilesGuard {
            socket_path: first.socket_path.clone(),
            socket_identity,
            bootstrap_path: first.bootstrap_path.clone(),
            bootstrap_identity: Some(bootstrap_identity),
        });
    }

    #[test]
    fn bootstrap_load_rejects_symlink_and_insecure_mode_without_token_output() {
        let directory = TestDirectory::new();
        let target = directory.join("target");
        fs::write(&target, b"not a bootstrap").expect("write target");
        fs::set_permissions(&target, fs::Permissions::from_mode(BOOTSTRAP_MODE))
            .expect("target mode");
        let linked = directory.join("linked.pxab");
        symlink(&target, &linked).expect("symlink");
        assert_eq!(
            RuntimeAgentDeveloperLocalBootstrapV1::read_private_file(&linked)
                .expect_err("symlink must reject"),
            RuntimeAgentDeveloperLocalIpcError::InsecurePermissions
        );

        let insecure = directory.join("insecure.pxab");
        fs::write(&insecure, vec![0_u8; PXAB_HEADER_BYTES]).expect("write insecure");
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o640)).expect("insecure mode");
        let error = RuntimeAgentDeveloperLocalBootstrapV1::read_private_file(&insecure)
            .expect_err("insecure mode must reject");
        assert_eq!(
            error,
            RuntimeAgentDeveloperLocalIpcError::InsecurePermissions
        );
        assert!(!error.to_string().contains("token"));
    }

    #[test]
    fn prior_generation_token_never_authenticates_a_new_generation() {
        let directory = TestDirectory::new();
        let prior = bootstrap(directory.join("agent.sock"), 0x71);
        let next = bootstrap(directory.join("agent.sock"), 0x72);
        assert!(!constant_time_eq(
            prior.generation_token.as_ref(),
            next.generation_token.as_ref()
        ));
    }

    #[test]
    fn forged_valid_cross_scope_frames_reject_before_handle_dispatch() {
        let directory = TestDirectory::new();
        let expected = bootstrap(directory.join("agent.sock"), 0x75);
        let wrong_deck = AgentConversationDeckRunId::try_from_bytes([0x76; 16])
            .expect("wrong DeckRun remains syntactically valid");
        let wrong_session = AgentConversationSessionId::try_from_bytes([0x77; 16])
            .expect("wrong Session remains syntactically valid");
        let request_id =
            AgentConversationRequestId::try_from_bytes([0x78; 16]).expect("Request identity");
        let semantic = AgentConversationRequestV1::try_new(
            wrong_deck,
            expected.session_id,
            AgentConversationTurnId::try_from_bytes([0x79; 16]).expect("Turn identity"),
            request_id,
            1_000_000_000,
            "forged cross-scope turn",
        )
        .expect("cross-scope PXAC remains canonically valid");
        let submit = IpcFrame {
            kind: OperationKind::Submit,
            status: ResponseStatus::Ok,
            correlation: *request_id.as_bytes(),
            generation_token: duplicate_token(&expected.generation_token),
            operation_timeout_nanos: 1_000_000_000,
            body: Zeroizing::new(semantic.canonical_wire().into_vec()),
        };
        assert!(matches!(
            decode_scoped_request(&submit, &expected),
            Err(ResponseStatus::Malformed)
        ));

        let control = AgentConversationControlV1::open_request(expected.deck_run_id, wrong_session);
        let control_wire = control.canonical_wire().expect("valid control wire");
        let control_frame = IpcFrame {
            kind: OperationKind::Open,
            status: ResponseStatus::Ok,
            correlation: [0x7a; 16],
            generation_token: duplicate_token(&expected.generation_token),
            operation_timeout_nanos: 1_000_000_000,
            body: Zeroizing::new(control_wire.into_vec()),
        };
        assert!(matches!(
            decode_scoped_request(&control_frame, &expected),
            Err(ResponseStatus::Malformed)
        ));
    }
}
