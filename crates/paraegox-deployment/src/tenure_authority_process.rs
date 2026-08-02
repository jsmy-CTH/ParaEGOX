//! Narrow executable facade for the S7-D local tenure-authority process.
//!
//! The acquire DTOs remain crate-private. This module exposes only the process
//! entrypoint and an opaque failure type for the thin binary owner.

use core::fmt;

/// Opaque startup or service failure returned by the tenure-authority process.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TenureAuthorityProcessError {
    kind: ProcessErrorKind,
    diagnostic: ProcessDiagnostic,
}

impl TenureAuthorityProcessError {
    const fn new(kind: ProcessErrorKind) -> Self {
        Self {
            kind,
            diagnostic: ProcessDiagnostic::for_kind(kind),
        }
    }

    const fn diagnosed(kind: ProcessErrorKind, diagnostic: ProcessDiagnostic) -> Self {
        Self { kind, diagnostic }
    }
}

impl fmt::Debug for TenureAuthorityProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenureAuthorityProcessError")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for TenureAuthorityProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            #[cfg(not(unix))]
            ProcessErrorKind::UnsupportedPlatform => {
                "the S7-D tenure-authority process requires a Unix platform"
            }
            ProcessErrorKind::Arguments => "invalid tenure-authority command line",
            ProcessErrorKind::Configuration => {
                "tenure-authority security configuration was rejected"
            }
            ProcessErrorKind::KeyMaterial => "tenure-authority key material was rejected",
            ProcessErrorKind::Provisioning => "tenure-authority provisioning was rejected",
            ProcessErrorKind::Initialization => "tenure-authority initialization failed",
            ProcessErrorKind::Receipt => "tenure-authority initialization receipt is unavailable",
            ProcessErrorKind::Store => "tenure-authority store failed closed",
            ProcessErrorKind::Runtime => "tenure-authority async runtime failed",
            ProcessErrorKind::Socket => "tenure-authority local socket failed closed",
            ProcessErrorKind::Output => "tenure-authority receipt output failed",
        };
        write!(
            formatter,
            "{message}; code={} stage={} path_role={} fact={}",
            self.diagnostic.code,
            self.diagnostic.stage,
            self.diagnostic.path_role,
            self.diagnostic.fact,
        )
    }
}

impl std::error::Error for TenureAuthorityProcessError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessErrorKind {
    #[cfg(not(unix))]
    UnsupportedPlatform,
    Arguments,
    Configuration,
    KeyMaterial,
    Provisioning,
    Initialization,
    Receipt,
    Store,
    Runtime,
    Socket,
    Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessDiagnostic {
    code: &'static str,
    stage: &'static str,
    path_role: &'static str,
    fact: &'static str,
}

impl ProcessDiagnostic {
    const fn new(
        code: &'static str,
        stage: &'static str,
        path_role: &'static str,
        fact: &'static str,
    ) -> Self {
        Self {
            code,
            stage,
            path_role,
            fact,
        }
    }

    const fn for_kind(kind: ProcessErrorKind) -> Self {
        match kind {
            #[cfg(not(unix))]
            ProcessErrorKind::UnsupportedPlatform => Self::new(
                "PXTA-PLATFORM-UNSUPPORTED",
                "start_process",
                "process",
                "unsupported",
            ),
            ProcessErrorKind::Arguments => Self::new(
                "PXTA-ARGUMENTS-INVALID",
                "parse_arguments",
                "command_line",
                "invalid",
            ),
            ProcessErrorKind::Configuration => Self::new(
                "PXTA-CONFIGURATION-REJECTED",
                "validate_configuration",
                "configuration",
                "invalid",
            ),
            ProcessErrorKind::KeyMaterial => Self::new(
                "PXTA-KEY-MATERIAL-REJECTED",
                "validate_key_material",
                "key",
                "invalid",
            ),
            ProcessErrorKind::Provisioning => Self::new(
                "PXTA-PROVISIONING-REJECTED",
                "build_provisioning",
                "provisioning",
                "invalid",
            ),
            ProcessErrorKind::Initialization => Self::new(
                "PXTA-INITIALIZATION-FAILED",
                "initialize_store",
                "state_dir",
                "failed",
            ),
            ProcessErrorKind::Receipt => Self::new(
                "PXTA-RECEIPT-UNAVAILABLE",
                "reconstruct_receipt",
                "active_snapshot",
                "unavailable",
            ),
            ProcessErrorKind::Store => Self::new(
                "PXTA-STORE-FAILED-CLOSED",
                "operate_store",
                "active_snapshot",
                "failed_closed",
            ),
            ProcessErrorKind::Runtime => {
                Self::new("PXTA-RUNTIME-FAILED", "run_service", "process", "failed")
            }
            ProcessErrorKind::Socket => Self::new(
                "PXTA-SOCKET-FAILED-CLOSED",
                "operate_socket",
                "socket",
                "failed_closed",
            ),
            ProcessErrorKind::Output => Self::new(
                "PXTA-OUTPUT-FAILED",
                "write_receipt",
                "stdout",
                "io_failure",
            ),
        }
    }
}

/// Parses the exact CLI and runs one tenure-authority administrative or serve operation.
pub fn run_tenure_authority_process() -> Result<(), TenureAuthorityProcessError> {
    platform::run()
}

#[cfg(not(unix))]
mod platform {
    use super::{ProcessErrorKind, TenureAuthorityProcessError};

    pub(super) fn run() -> Result<(), TenureAuthorityProcessError> {
        Err(TenureAuthorityProcessError::new(
            ProcessErrorKind::UnsupportedPlatform,
        ))
    }
}

#[cfg(unix)]
mod platform {
    use core::future::{Future, poll_fn};
    use core::task::Poll;
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, Metadata};
    use std::io::{self, Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
    use std::path::{Component, Path, PathBuf};
    use std::time::Duration;

    use ed25519_dalek::VerifyingKey;
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    use nix::unistd::{UnlinkatFlags, getegid, geteuid, unlinkat};
    use paraegox_kernel::{
        digest::{Digest32, Digest32Builder},
        identity::PrincipalRef,
    };
    use paraegox_runtime_contracts::apply::{
        TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
    use tokio::signal::unix::{Signal, SignalKind, signal};
    use tokio::time::timeout;
    use zeroize::Zeroizing;

    use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
    use crate::tenure_authority::{
        ControllerAcquireAuthorization, DeploymentTenureAuthority, TenureAcquireError,
        TenureAuthorityFailureDiagnostic, TenureAuthorityFingerprints,
        TenureAuthorityInitializationReceipt, TenureAuthorityProvisioning,
        ed25519_authority_key_fingerprint, initialize_tenure_authority_store,
        reconstruct_sequence_one_initialization_receipt,
    };
    use crate::tenure_protocol::{
        ACQUIRE_TENURE_FRAME_HEADER_BYTES, ACQUIRE_TENURE_PROTOCOL_VERSION,
        AcquireTenureFrameHeaderV1, AcquireTenureFrameKind, AcquireTenureRequestV1,
        ControllerAcquireKeyRef, ControllerPublicKeyFingerprint, MAX_ACQUIRE_TENURE_FRAME_BYTES,
        MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES, MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
        encode_acquire_tenure_response_frame,
    };

    use super::{ProcessDiagnostic, ProcessErrorKind, TenureAuthorityProcessError};

    const POLICY_FINGERPRINT_DOMAIN: &[u8] =
        b"paraegox.deployment.tenure-authority.process-policy.sha256.v1";
    const SERVICE_PRINCIPAL_FINGERPRINT_DOMAIN: &[u8] =
        b"paraegox.deployment.tenure-authority.service-principal.sha256.v1";
    const OWNER_IDENTITY_FINGERPRINT_DOMAIN: &[u8] =
        b"paraegox.deployment.tenure-authority.owner-identity.sha256.v1";
    const ED25519_ALGORITHM: u16 = 1;
    const ED25519_ALGORITHM_VERSION: u16 = 1;
    const STATE_DIRECTORY_MODE: u32 = 0o700;
    const SOCKET_DIRECTORY_MODE: u32 = 0o2750;
    const SOCKET_MODE: u32 = 0o660;
    const IO_TIMEOUT: Duration = Duration::from_secs(5);

    pub(super) fn run() -> Result<(), TenureAuthorityProcessError> {
        let command = parse_arguments(std::env::args_os().skip(1))?;
        execute(command)
    }

    fn execute(command: ProcessCommand) -> Result<(), TenureAuthorityProcessError> {
        match command {
            ProcessCommand::Initialize(common) => {
                let loaded = load_provisioning(&common)?;
                let receipt =
                    initialize_tenure_authority_store(&common.state_directory, loaded.provisioning)
                        .map_err(|error| {
                            authority_process_error(
                                ProcessErrorKind::Initialization,
                                error.diagnostic(),
                            )
                        })?;
                write_receipt(&receipt)
            }
            ProcessCommand::InitializationReceipt(common) => {
                let loaded = load_provisioning(&common)?;
                let receipt = reconstruct_sequence_one_initialization_receipt(
                    &common.state_directory,
                    loaded.provisioning,
                )
                .map_err(|error| {
                    authority_process_error(ProcessErrorKind::Receipt, error.diagnostic())
                })?;
                write_receipt(&receipt)
            }
            ProcessCommand::Serve {
                common,
                expected_store_instance_id,
                private_seed_path,
            } => serve(common, expected_store_instance_id, &private_seed_path),
        }
    }

    fn serve(
        common: CommonArguments,
        expected_store_instance_id: [u8; 32],
        private_seed_path: &Path,
    ) -> Result<(), TenureAuthorityProcessError> {
        validate_private_seed_separation(&common, private_seed_path)?;
        let loaded = load_provisioning(&common)?;
        let private_seed = read_private_seed(
            private_seed_path,
            common.expected_authority_uid,
            common.expected_authority_gid,
        )?;
        validate_private_seed_material(
            &private_seed,
            &loaded.authority_public_key,
            &loaded.controller_public_key,
        )?;
        let mut authority = DeploymentTenureAuthority::open(
            &common.state_directory,
            expected_store_instance_id,
            loaded.provisioning,
            private_seed,
        )
        .map_err(|error| authority_process_error(ProcessErrorKind::Store, error.diagnostic()))?;

        // `DeploymentTenureAuthority::open` owns the exclusive store lock. No
        // stale socket inspection or deletion is reachable before this point.
        let runtime = build_runtime()?;
        let (listener, socket_guard) = {
            let _runtime_context = runtime.enter();
            prepare_listener(&common, &authority)?
        };
        let service_result = runtime.block_on(serve_loop(
            listener,
            &mut authority,
            PeerIdentity {
                uid: common.expected_peer_uid,
                gid: common.expected_peer_gid,
            },
        ));
        drop(runtime);
        let cleanup_result = socket_guard.cleanup();
        match (service_result, cleanup_result) {
            (_, Err(error)) => Err(error),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    fn build_runtime() -> Result<Runtime, TenureAuthorityProcessError> {
        RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| process_error(ProcessErrorKind::Runtime))
    }

    async fn serve_loop(
        listener: UnixListener,
        authority: &mut DeploymentTenureAuthority,
        expected_peer: PeerIdentity,
    ) -> Result<(), TenureAuthorityProcessError> {
        let mut terminate = signal(SignalKind::terminate())
            .map_err(|_| process_error(ProcessErrorKind::Runtime))?;
        let mut interrupt = signal(SignalKind::interrupt())
            .map_err(|_| process_error(ProcessErrorKind::Runtime))?;
        loop {
            match next_server_event(&listener, &mut terminate, &mut interrupt).await {
                ServerEvent::Shutdown => return Ok(()),
                ServerEvent::Accept(Err(_)) => {
                    return Err(process_error(ProcessErrorKind::Socket));
                }
                ServerEvent::Accept(Ok((mut stream, _address))) => {
                    if !peer_is_authorized(&stream, expected_peer) {
                        continue;
                    }
                    let request = match read_request(&mut stream).await {
                        Ok(request) => request,
                        Err(()) => continue,
                    };
                    let committed = match authority.acquire_authorized_request(&request) {
                        Ok(committed) => committed,
                        Err(error) if fatal_authority_error(error) => {
                            let diagnostic = error.store_diagnostic().unwrap_or_else(|| {
                                TenureAuthorityFailureDiagnostic::new(
                                    "PXTA-STORE-OWNER-FAILED",
                                    "acquire_tenure",
                                    "active_snapshot",
                                    "failed_closed",
                                )
                            });
                            return Err(authority_process_error(
                                ProcessErrorKind::Store,
                                diagnostic,
                            ));
                        }
                        Err(_) => continue,
                    };
                    let response_frame = encode_acquire_tenure_response_frame(committed.response());
                    // The Authority transaction is already durable here. A
                    // failed write is deliberately non-fatal: the client must
                    // retry the same operation id and digest to replay bytes.
                    let _ = timeout(IO_TIMEOUT, stream.write_all(&response_frame)).await;
                }
            }
        }
    }

    async fn next_server_event(
        listener: &UnixListener,
        terminate: &mut Signal,
        interrupt: &mut Signal,
    ) -> ServerEvent {
        await_server_event(listener.accept(), terminate.recv(), interrupt.recv()).await
    }

    async fn await_server_event<Accept, Terminate, Interrupt, Accepted>(
        accept: Accept,
        terminate: Terminate,
        interrupt: Interrupt,
    ) -> ServerEvent<Accepted>
    where
        Accept: Future<Output = io::Result<Accepted>>,
        Terminate: Future<Output = Option<()>>,
        Interrupt: Future<Output = Option<()>>,
    {
        let mut accept = Box::pin(accept);
        let mut terminate = Box::pin(terminate);
        let mut interrupt = Box::pin(interrupt);
        poll_fn(move |context| {
            if let Poll::Ready(_signal) = terminate.as_mut().poll(context) {
                return Poll::Ready(ServerEvent::Shutdown);
            }
            if let Poll::Ready(_signal) = interrupt.as_mut().poll(context) {
                return Poll::Ready(ServerEvent::Shutdown);
            }
            if let Poll::Ready(result) = accept.as_mut().poll(context) {
                return Poll::Ready(ServerEvent::Accept(result));
            }
            Poll::Pending
        })
        .await
    }

    enum ServerEvent<Accepted = (UnixStream, tokio::net::unix::SocketAddr)> {
        Accept(io::Result<Accepted>),
        Shutdown,
    }

    #[derive(Clone, Copy)]
    struct PeerIdentity {
        uid: u32,
        gid: u32,
    }

    fn peer_is_authorized(stream: &UnixStream, expected: PeerIdentity) -> bool {
        stream.peer_cred().is_ok_and(|credentials| {
            credentials.uid() == expected.uid && credentials.gid() == expected.gid
        })
    }

    async fn read_request(stream: &mut UnixStream) -> Result<AcquireTenureRequestV1, ()> {
        read_request_with_timeout(stream, IO_TIMEOUT).await
    }

    async fn read_request_with_timeout(
        stream: &mut UnixStream,
        deadline: Duration,
    ) -> Result<AcquireTenureRequestV1, ()> {
        timeout(deadline, read_request_before_deadline(stream))
            .await
            .map_err(|_| ())?
    }

    async fn read_request_before_deadline(
        stream: &mut UnixStream,
    ) -> Result<AcquireTenureRequestV1, ()> {
        let mut header_bytes = [0; ACQUIRE_TENURE_FRAME_HEADER_BYTES];
        stream.read_exact(&mut header_bytes).await.map_err(|_| ())?;
        let header = AcquireTenureFrameHeaderV1::decode_prefix(&header_bytes).map_err(|_| ())?;
        if header.kind() != AcquireTenureFrameKind::Request {
            return Err(());
        }
        let payload_length = usize::try_from(header.payload_bytes()).map_err(|_| ())?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_length).map_err(|_| ())?;
        payload.resize(payload_length, 0);
        stream.read_exact(&mut payload).await.map_err(|_| ())?;
        AcquireTenureRequestV1::decode(&payload).map_err(|_| ())
    }

    fn fatal_authority_error(error: TenureAcquireError) -> bool {
        matches!(
            error,
            TenureAcquireError::InvalidStoredResponse
                | TenureAcquireError::SigningFailed
                | TenureAcquireError::ResponseEncodingFailed
                | TenureAcquireError::StoreStopped
                | TenureAcquireError::RejectedBeforePublish(_)
                | TenureAcquireError::UncertainAfterPublish(_)
                | TenureAcquireError::StoreUnavailableOrInvalid(_)
        )
    }

    fn write_receipt(
        receipt: &TenureAuthorityInitializationReceipt,
    ) -> Result<(), TenureAuthorityProcessError> {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        write_labeled_hex(
            &mut output,
            b"store_instance_id",
            receipt.store_instance_id(),
        )?;
        writeln!(output, "snapshot_sequence={}", receipt.snapshot_sequence())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        writeln!(output, "epoch_high_water={}", receipt.epoch_high_water())
            .map_err(|_| process_error(ProcessErrorKind::Output))?;
        write_labeled_hex(
            &mut output,
            b"snapshot_checksum",
            receipt.snapshot_checksum().as_bytes(),
        )?;
        write_labeled_hex(
            &mut output,
            b"receipt_digest",
            receipt.receipt_digest().as_bytes(),
        )?;
        write_labeled_hex(&mut output, b"receipt_bytes", receipt.canonical_bytes())?;
        output
            .flush()
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    fn write_labeled_hex(
        output: &mut impl Write,
        label: &[u8],
        bytes: &[u8],
    ) -> Result<(), TenureAuthorityProcessError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = Vec::with_capacity(label.len() + 1 + (bytes.len() * 2) + 1);
        encoded.extend_from_slice(label);
        encoded.push(b'=');
        for byte in bytes {
            encoded.push(HEX[usize::from(byte >> 4)]);
            encoded.push(HEX[usize::from(byte & 0x0f)]);
        }
        encoded.push(b'\n');
        output
            .write_all(&encoded)
            .map_err(|_| process_error(ProcessErrorKind::Output))
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ProcessCommand {
        Initialize(CommonArguments),
        InitializationReceipt(CommonArguments),
        Serve {
            common: CommonArguments,
            expected_store_instance_id: [u8; 32],
            private_seed_path: PathBuf,
        },
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CommonArguments {
        state_directory: PathBuf,
        socket_path: PathBuf,
        authority_public_key_path: PathBuf,
        controller_public_key_path: PathBuf,
        source_scope: [u8; 16],
        writer: [u8; 16],
        authority: [u8; 16],
        tenure_key: [u8; 16],
        controller_principal: [u8; 16],
        controller_key: [u8; 16],
        service_principal: [u8; 16],
        owner_id: [u8; 16],
        expected_authority_uid: u32,
        expected_authority_gid: u32,
        expected_peer_uid: u32,
        expected_peer_gid: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CommandKind {
        Initialize,
        InitializationReceipt,
        Serve,
    }

    #[derive(Default)]
    struct RawOptions {
        state_directory: Option<OsString>,
        socket_path: Option<OsString>,
        authority_public_key_path: Option<OsString>,
        controller_public_key_path: Option<OsString>,
        private_seed_path: Option<OsString>,
        source_scope: Option<OsString>,
        writer: Option<OsString>,
        authority: Option<OsString>,
        tenure_key: Option<OsString>,
        controller_principal: Option<OsString>,
        controller_key: Option<OsString>,
        service_principal: Option<OsString>,
        owner_id: Option<OsString>,
        expected_authority_uid: Option<OsString>,
        expected_authority_gid: Option<OsString>,
        expected_peer_uid: Option<OsString>,
        expected_peer_gid: Option<OsString>,
        expected_store_instance_id: Option<OsString>,
    }

    fn parse_arguments(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<ProcessCommand, TenureAuthorityProcessError> {
        let mut arguments = arguments.into_iter();
        let kind = match arguments.next().and_then(|value| value.into_string().ok()) {
            Some(value) if value == "initialize" => CommandKind::Initialize,
            Some(value) if value == "initialization-receipt" => CommandKind::InitializationReceipt,
            Some(value) if value == "serve" => CommandKind::Serve,
            _ => return Err(process_error(ProcessErrorKind::Arguments)),
        };
        let mut raw = RawOptions::default();
        while let Some(flag) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| process_error(ProcessErrorKind::Arguments))?;
            raw.set(&flag, value)?;
        }
        raw.finish(kind)
    }

    impl RawOptions {
        fn set(
            &mut self,
            flag: &OsStr,
            value: OsString,
        ) -> Result<(), TenureAuthorityProcessError> {
            let Some(flag) = flag.to_str() else {
                return Err(process_error(ProcessErrorKind::Arguments));
            };
            let slot = match flag {
                "--state-dir" => &mut self.state_directory,
                "--socket-path" => &mut self.socket_path,
                "--authority-public-key" => &mut self.authority_public_key_path,
                "--controller-public-key" => &mut self.controller_public_key_path,
                "--private-seed" => &mut self.private_seed_path,
                "--source-scope" => &mut self.source_scope,
                "--writer-ref" => &mut self.writer,
                "--authority-ref" => &mut self.authority,
                "--tenure-key-ref" => &mut self.tenure_key,
                "--controller-principal-ref" => &mut self.controller_principal,
                "--controller-key-ref" => &mut self.controller_key,
                "--service-principal-ref" => &mut self.service_principal,
                "--owner-id" => &mut self.owner_id,
                "--expected-authority-uid" => &mut self.expected_authority_uid,
                "--expected-authority-gid" => &mut self.expected_authority_gid,
                "--expected-peer-uid" => &mut self.expected_peer_uid,
                "--expected-peer-gid" => &mut self.expected_peer_gid,
                "--expected-store-id" => &mut self.expected_store_instance_id,
                _ => return Err(process_error(ProcessErrorKind::Arguments)),
            };
            set_once(slot, value)
        }

        fn finish(self, kind: CommandKind) -> Result<ProcessCommand, TenureAuthorityProcessError> {
            let common = CommonArguments {
                state_directory: parse_absolute_path(required(self.state_directory)?)?,
                socket_path: parse_socket_path(required(self.socket_path)?)?,
                authority_public_key_path: parse_absolute_path(required(
                    self.authority_public_key_path,
                )?)?,
                controller_public_key_path: parse_absolute_path(required(
                    self.controller_public_key_path,
                )?)?,
                source_scope: parse_nonzero_hex(required(self.source_scope)?)?,
                writer: parse_nonzero_hex(required(self.writer)?)?,
                authority: parse_nonzero_hex(required(self.authority)?)?,
                tenure_key: parse_nonzero_hex(required(self.tenure_key)?)?,
                controller_principal: parse_nonzero_hex(required(self.controller_principal)?)?,
                controller_key: parse_nonzero_hex(required(self.controller_key)?)?,
                service_principal: parse_nonzero_hex(required(self.service_principal)?)?,
                owner_id: parse_nonzero_hex(required(self.owner_id)?)?,
                expected_authority_uid: parse_u32(required(self.expected_authority_uid)?)?,
                expected_authority_gid: parse_u32(required(self.expected_authority_gid)?)?,
                expected_peer_uid: parse_u32(required(self.expected_peer_uid)?)?,
                expected_peer_gid: parse_u32(required(self.expected_peer_gid)?)?,
            };
            match kind {
                CommandKind::Initialize => {
                    if self.expected_store_instance_id.is_some() || self.private_seed_path.is_some()
                    {
                        return Err(process_error(ProcessErrorKind::Arguments));
                    }
                    Ok(ProcessCommand::Initialize(common))
                }
                CommandKind::InitializationReceipt => {
                    if self.private_seed_path.is_some() || self.expected_store_instance_id.is_some()
                    {
                        return Err(process_error(ProcessErrorKind::Arguments));
                    }
                    Ok(ProcessCommand::InitializationReceipt(common))
                }
                CommandKind::Serve => Ok(ProcessCommand::Serve {
                    common,
                    expected_store_instance_id: parse_nonzero_hex(required(
                        self.expected_store_instance_id,
                    )?)?,
                    private_seed_path: parse_absolute_path(required(self.private_seed_path)?)?,
                }),
            }
        }
    }

    fn required<T>(value: Option<T>) -> Result<T, TenureAuthorityProcessError> {
        value.ok_or_else(|| process_error(ProcessErrorKind::Arguments))
    }

    fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), TenureAuthorityProcessError> {
        if slot.is_some() {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        *slot = Some(value);
        Ok(())
    }

    fn parse_absolute_path(value: OsString) -> Result<PathBuf, TenureAuthorityProcessError> {
        let path = PathBuf::from(value);
        validate_lexical_absolute_path(&path)?;
        Ok(path)
    }

    fn parse_socket_path(value: OsString) -> Result<PathBuf, TenureAuthorityProcessError> {
        let path = parse_absolute_path(value)?;
        if path.parent().is_none() || path.file_name().is_none() {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        Ok(path)
    }

    fn validate_lexical_absolute_path(path: &Path) -> Result<(), TenureAuthorityProcessError> {
        let bytes = path.as_os_str().as_bytes();
        if !path.is_absolute()
            || bytes.len() <= 1
            || bytes.first() != Some(&b'/')
            || bytes.last() == Some(&b'/')
            || bytes.contains(&0)
            || bytes.windows(2).any(|window| window == b"//")
            || bytes[1..]
                .split(|byte| *byte == b'/')
                .any(|component| component == b"." || component == b"..")
        {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        let mut normal_components = 0_usize;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(_) => normal_components += 1,
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(process_error(ProcessErrorKind::Arguments));
                }
            }
        }
        if normal_components == 0 {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        Ok(())
    }

    fn parse_nonzero_hex<const N: usize>(
        value: OsString,
    ) -> Result<[u8; N], TenureAuthorityProcessError> {
        let value = value
            .to_str()
            .ok_or_else(|| process_error(ProcessErrorKind::Arguments))?;
        if value.len() != N * 2 {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        let mut decoded = [0; N];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        if decoded.iter().all(|byte| *byte == 0) {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        Ok(decoded)
    }

    fn hex_nibble(value: u8) -> Result<u8, TenureAuthorityProcessError> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(process_error(ProcessErrorKind::Arguments)),
        }
    }

    fn parse_u32(value: OsString) -> Result<u32, TenureAuthorityProcessError> {
        let value = value
            .to_str()
            .ok_or_else(|| process_error(ProcessErrorKind::Arguments))?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(process_error(ProcessErrorKind::Arguments));
        }
        value
            .parse()
            .map_err(|_| process_error(ProcessErrorKind::Arguments))
    }

    struct LoadedProvisioning {
        provisioning: TenureAuthorityProvisioning,
        authority_public_key: [u8; 32],
        controller_public_key: [u8; 32],
    }

    fn load_provisioning(
        arguments: &CommonArguments,
    ) -> Result<LoadedProvisioning, TenureAuthorityProcessError> {
        validate_service_identity(arguments)?;
        validate_installation_paths(arguments)?;
        let authority_key = read_public_key(
            &arguments.authority_public_key_path,
            arguments.expected_authority_uid,
            arguments.expected_authority_gid,
            &[arguments.expected_authority_uid],
        )?;
        let controller_key = read_public_key(
            &arguments.controller_public_key_path,
            arguments.expected_authority_uid,
            arguments.expected_authority_gid,
            &[
                arguments.expected_authority_uid,
                arguments.expected_peer_uid,
            ],
        )?;
        if authority_key == controller_key {
            return Err(separation_error(
                ProcessErrorKind::Provisioning,
                "validate_public_key_separation",
                "public_keys",
            ));
        }
        let signing_key_fingerprint = ed25519_authority_key_fingerprint(&authority_key)
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let controller_key_fingerprint =
            ControllerPublicKeyFingerprint::for_ed25519_key(&controller_key)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let algorithm = TenureProofAlgorithm::try_new(ED25519_ALGORITHM)
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let proof_authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes(arguments.authority),
            TenureKeyRef::from_bytes(arguments.tenure_key),
            algorithm,
            ED25519_ALGORITHM_VERSION,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let service_principal_fingerprint = service_principal_fingerprint(arguments)?;
        let policy_fingerprint = policy_fingerprint(
            arguments,
            signing_key_fingerprint,
            *controller_key_fingerprint.as_bytes(),
        )?;
        let owner_identity_fingerprint =
            owner_identity_fingerprint(arguments, service_principal_fingerprint)?;
        let controller_authorization = ControllerAcquireAuthorization::try_new(
            PrincipalRef::from_bytes(arguments.controller_principal),
            ControllerAcquireKeyRef::from_bytes(arguments.controller_key),
            controller_key,
            controller_key_fingerprint,
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        let provisioning = TenureAuthorityProvisioning::try_new(
            DeploymentScopeId::from_bytes(arguments.source_scope),
            DeploymentWriterRef::from_bytes(arguments.writer),
            proof_authority,
            authority_key,
            controller_authorization,
            TenureAuthorityFingerprints::new(
                signing_key_fingerprint,
                policy_fingerprint,
                service_principal_fingerprint,
                owner_identity_fingerprint,
            ),
        )
        .map_err(|_| process_error(ProcessErrorKind::Provisioning))?;
        Ok(LoadedProvisioning {
            provisioning,
            authority_public_key: authority_key,
            controller_public_key: controller_key,
        })
    }

    fn validate_service_identity(
        arguments: &CommonArguments,
    ) -> Result<(), TenureAuthorityProcessError> {
        if arguments.expected_authority_uid == 0
            || arguments.expected_authority_gid == 0
            || arguments.expected_peer_uid == 0
            || arguments.expected_peer_gid == 0
            || arguments.expected_authority_uid == arguments.expected_peer_uid
            || arguments.controller_principal == arguments.service_principal
            || geteuid().as_raw() != arguments.expected_authority_uid
            || getegid().as_raw() != arguments.expected_authority_gid
        {
            return Err(separation_error(
                ProcessErrorKind::Configuration,
                "validate_service_identity",
                "service_identity",
            ));
        }
        Ok(())
    }

    fn service_principal_fingerprint(
        arguments: &CommonArguments,
    ) -> Result<Digest32, TenureAuthorityProcessError> {
        let mut builder = digest_builder(SERVICE_PRINCIPAL_FINGERPRINT_DOMAIN)?;
        digest_bytes(&mut builder, &arguments.service_principal)?;
        digest_u64(&mut builder, u64::from(arguments.expected_authority_uid))?;
        digest_u64(&mut builder, u64::from(arguments.expected_authority_gid))?;
        Ok(builder.finish())
    }

    fn policy_fingerprint(
        arguments: &CommonArguments,
        authority_key_fingerprint: Digest32,
        controller_key_fingerprint: [u8; 32],
    ) -> Result<Digest32, TenureAuthorityProcessError> {
        policy_fingerprint_for_profile(
            arguments,
            authority_key_fingerprint,
            controller_key_fingerprint,
            STATE_DIRECTORY_MODE,
            SOCKET_DIRECTORY_MODE,
            SOCKET_MODE,
        )
    }

    fn policy_fingerprint_for_profile(
        arguments: &CommonArguments,
        authority_key_fingerprint: Digest32,
        controller_key_fingerprint: [u8; 32],
        state_directory_mode: u32,
        socket_directory_mode: u32,
        socket_mode: u32,
    ) -> Result<Digest32, TenureAuthorityProcessError> {
        let mut builder = digest_builder(POLICY_FINGERPRINT_DOMAIN)?;
        digest_u64(&mut builder, u64::from(ACQUIRE_TENURE_PROTOCOL_VERSION))?;
        digest_bytes(&mut builder, &arguments.source_scope)?;
        digest_bytes(&mut builder, &arguments.writer)?;
        digest_bytes(&mut builder, &arguments.authority)?;
        digest_bytes(&mut builder, &arguments.tenure_key)?;
        digest_u64(&mut builder, u64::from(ED25519_ALGORITHM))?;
        digest_u64(&mut builder, u64::from(ED25519_ALGORITHM_VERSION))?;
        digest_bytes(&mut builder, authority_key_fingerprint.as_bytes())?;
        digest_bytes(&mut builder, &arguments.controller_principal)?;
        digest_bytes(&mut builder, &arguments.controller_key)?;
        digest_bytes(&mut builder, &controller_key_fingerprint)?;
        digest_u64(&mut builder, u64::from(arguments.expected_peer_uid))?;
        digest_u64(&mut builder, u64::from(arguments.expected_peer_gid))?;
        digest_u64(&mut builder, u64::from(arguments.expected_authority_uid))?;
        digest_u64(&mut builder, u64::from(arguments.expected_authority_gid))?;
        digest_u64(
            &mut builder,
            u64::try_from(MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?,
        )?;
        digest_u64(
            &mut builder,
            u64::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?,
        )?;
        digest_u64(
            &mut builder,
            u64::try_from(MAX_ACQUIRE_TENURE_FRAME_BYTES)
                .map_err(|_| process_error(ProcessErrorKind::Provisioning))?,
        )?;
        digest_u64(&mut builder, u64::from(socket_mode))?;
        digest_u64(&mut builder, u64::from(socket_directory_mode))?;
        digest_u64(&mut builder, u64::from(state_directory_mode))?;
        digest_bytes(&mut builder, arguments.socket_path.as_os_str().as_bytes())?;
        Ok(builder.finish())
    }

    fn owner_identity_fingerprint(
        arguments: &CommonArguments,
        service_principal_fingerprint: Digest32,
    ) -> Result<Digest32, TenureAuthorityProcessError> {
        let mut builder = digest_builder(OWNER_IDENTITY_FINGERPRINT_DOMAIN)?;
        digest_bytes(&mut builder, &arguments.owner_id)?;
        digest_bytes(&mut builder, service_principal_fingerprint.as_bytes())?;
        digest_bytes(&mut builder, &arguments.source_scope)?;
        digest_bytes(&mut builder, &arguments.authority)?;
        digest_bytes(&mut builder, &arguments.tenure_key)?;
        digest_bytes(
            &mut builder,
            arguments.state_directory.as_os_str().as_bytes(),
        )?;
        digest_bytes(&mut builder, arguments.socket_path.as_os_str().as_bytes())?;
        Ok(builder.finish())
    }

    fn digest_builder(domain: &[u8]) -> Result<Digest32Builder, TenureAuthorityProcessError> {
        Digest32Builder::try_new(domain).map_err(|_| process_error(ProcessErrorKind::Provisioning))
    }

    fn digest_bytes(
        builder: &mut Digest32Builder,
        bytes: &[u8],
    ) -> Result<(), TenureAuthorityProcessError> {
        builder
            .field_bytes(bytes)
            .map(|_| ())
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))
    }

    fn digest_u64(
        builder: &mut Digest32Builder,
        value: u64,
    ) -> Result<(), TenureAuthorityProcessError> {
        builder
            .field_u64(value)
            .map(|_| ())
            .map_err(|_| process_error(ProcessErrorKind::Provisioning))
    }

    fn validate_installation_paths(
        arguments: &CommonArguments,
    ) -> Result<(), TenureAuthorityProcessError> {
        let state = open_secure_directory(
            &arguments.state_directory,
            DirectoryRole::State,
            arguments.expected_authority_uid,
            arguments.expected_authority_gid,
        )?;
        let socket_parent = arguments
            .socket_path
            .parent()
            .ok_or_else(|| process_error(ProcessErrorKind::Configuration))?;
        let socket = open_secure_directory(
            socket_parent,
            DirectoryRole::Socket,
            arguments.expected_authority_uid,
            arguments.expected_peer_gid,
        )?;
        if (state.dev, state.ino) == (socket.dev, socket.ino)
            || arguments
                .socket_path
                .starts_with(&arguments.state_directory)
        {
            return Err(path_role_error(
                ProcessErrorKind::Configuration,
                "PXTA-INSTALLATION-PATH-SEPARATION",
                "validate_state_socket_separation",
                "state_dir_socket",
                "not_separated",
            ));
        }
        if arguments
            .authority_public_key_path
            .starts_with(&arguments.state_directory)
            || arguments
                .controller_public_key_path
                .starts_with(&arguments.state_directory)
        {
            return Err(path_role_error(
                ProcessErrorKind::Configuration,
                "PXTA-INSTALLATION-PATH-SEPARATION",
                "validate_key_state_separation",
                "public_keys",
                "inside_state_dir",
            ));
        }
        if arguments.authority_public_key_path == arguments.controller_public_key_path {
            return Err(separation_error(
                ProcessErrorKind::Configuration,
                "validate_public_key_paths",
                "public_keys",
            ));
        }
        let authority_key_metadata = fs::symlink_metadata(&arguments.authority_public_key_path)
            .map_err(|_| {
                path_role_error(
                    ProcessErrorKind::Configuration,
                    "PXTA-KEY-PATH-INSPECTION-FAILED",
                    "inspect_authority_public_key",
                    "authority_public_key",
                    "io_failure",
                )
            })?;
        let controller_key_metadata = fs::symlink_metadata(&arguments.controller_public_key_path)
            .map_err(|_| {
            path_role_error(
                ProcessErrorKind::Configuration,
                "PXTA-KEY-PATH-INSPECTION-FAILED",
                "inspect_controller_public_key",
                "controller_public_key",
                "io_failure",
            )
        })?;
        if authority_key_metadata.dev() == controller_key_metadata.dev()
            && authority_key_metadata.ino() == controller_key_metadata.ino()
        {
            return Err(separation_error(
                ProcessErrorKind::Configuration,
                "validate_public_key_inodes",
                "public_keys",
            ));
        }
        Ok(())
    }

    fn validate_private_seed_separation(
        arguments: &CommonArguments,
        private_seed_path: &Path,
    ) -> Result<(), TenureAuthorityProcessError> {
        if private_seed_path.starts_with(&arguments.state_directory)
            || private_seed_path == arguments.authority_public_key_path
            || private_seed_path == arguments.controller_public_key_path
        {
            return Err(separation_error(
                ProcessErrorKind::Configuration,
                "validate_private_seed_path",
                "private_seed",
            ));
        }
        let seed_metadata = fs::symlink_metadata(private_seed_path).map_err(|_| {
            path_role_error(
                ProcessErrorKind::Configuration,
                "PXTA-KEY-PATH-INSPECTION-FAILED",
                "inspect_private_seed",
                "private_seed",
                "io_failure",
            )
        })?;
        for public_path in [
            &arguments.authority_public_key_path,
            &arguments.controller_public_key_path,
        ] {
            let public_metadata = fs::symlink_metadata(public_path).map_err(|_| {
                path_role_error(
                    ProcessErrorKind::Configuration,
                    "PXTA-KEY-PATH-INSPECTION-FAILED",
                    "inspect_public_key",
                    "public_key",
                    "io_failure",
                )
            })?;
            if seed_metadata.dev() == public_metadata.dev()
                && seed_metadata.ino() == public_metadata.ino()
            {
                return Err(separation_error(
                    ProcessErrorKind::Configuration,
                    "validate_private_seed_inode",
                    "private_seed",
                ));
            }
        }
        Ok(())
    }

    fn validate_private_seed_material(
        private_seed: &[u8; 32],
        authority_public_key: &[u8; 32],
        controller_public_key: &[u8; 32],
    ) -> Result<(), TenureAuthorityProcessError> {
        if private_seed == authority_public_key || private_seed == controller_public_key {
            return Err(separation_error(
                ProcessErrorKind::KeyMaterial,
                "validate_private_seed_material",
                "private_seed",
            ));
        }
        Ok(())
    }

    #[derive(Clone, Copy)]
    enum DirectoryRole {
        State,
        Socket,
    }

    impl DirectoryRole {
        const fn path_role(self) -> &'static str {
            match self {
                Self::State => "state_dir",
                Self::Socket => "socket_dir",
            }
        }
    }

    struct OpenedDirectory {
        path: PathBuf,
        file: File,
        dev: u64,
        ino: u64,
        expected_uid: u32,
        expected_gid: u32,
    }

    fn open_secure_directory(
        path: &Path,
        role: DirectoryRole,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<OpenedDirectory, TenureAuthorityProcessError> {
        validate_existing_path_chain(path).map_err(|_| {
            path_role_error(
                ProcessErrorKind::Configuration,
                "PXTA-DIRECTORY-PATH-UNSAFE",
                "validate_directory_path",
                role.path_role(),
                "unsafe",
            )
        })?;
        validate_trusted_ancestor_chain(path, &[expected_uid], role.path_role())?;
        let before = fs::symlink_metadata(path)
            .map_err(|_| directory_io_error(role, "inspect_directory"))?;
        validate_directory_metadata(&before, role, expected_uid, expected_gid)?;
        let owned = open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| directory_io_error(role, "open_directory"))?;
        let file = File::from(owned);
        let after = file
            .metadata()
            .map_err(|_| directory_io_error(role, "inspect_open_directory"))?;
        validate_directory_metadata(&after, role, expected_uid, expected_gid)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(path_role_error(
                ProcessErrorKind::Configuration,
                "PXTA-DIRECTORY-IDENTITY-CHANGED",
                "open_directory",
                role.path_role(),
                "identity_changed",
            ));
        }
        Ok(OpenedDirectory {
            path: path.to_path_buf(),
            file,
            dev: after.dev(),
            ino: after.ino(),
            expected_uid,
            expected_gid,
        })
    }

    fn validate_directory_metadata(
        metadata: &Metadata,
        role: DirectoryRole,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<(), TenureAuthorityProcessError> {
        if !metadata.file_type().is_dir()
            || metadata.uid() != expected_uid
            || metadata.gid() != expected_gid
            || metadata.nlink() == 0
        {
            return Err(path_role_error(
                ProcessErrorKind::Configuration,
                "PXTA-DIRECTORY-METADATA-REJECTED",
                "validate_directory_metadata",
                role.path_role(),
                "invalid",
            ));
        }
        let mode = metadata.mode() & 0o7777;
        let valid = match role {
            DirectoryRole::State => mode == STATE_DIRECTORY_MODE,
            DirectoryRole::Socket => mode == SOCKET_DIRECTORY_MODE,
        };
        if !valid {
            return Err(path_role_error(
                ProcessErrorKind::Configuration,
                "PXTA-DIRECTORY-METADATA-REJECTED",
                "validate_directory_metadata",
                role.path_role(),
                "invalid",
            ));
        }
        Ok(())
    }

    fn validate_existing_path_chain(path: &Path) -> Result<(), TenureAuthorityProcessError> {
        validate_lexical_absolute_path(path)
            .map_err(|_| process_error(ProcessErrorKind::Configuration))?;
        let mut current = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir => current.push(component.as_os_str()),
                Component::Normal(value) => {
                    current.push(value);
                    let metadata = fs::symlink_metadata(&current)
                        .map_err(|_| process_error(ProcessErrorKind::Configuration))?;
                    if metadata.file_type().is_symlink() {
                        return Err(process_error(ProcessErrorKind::Configuration));
                    }
                }
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(process_error(ProcessErrorKind::Configuration));
                }
            }
        }
        Ok(())
    }

    fn validate_trusted_ancestor_chain(
        path: &Path,
        allowed_non_root_uids: &[u32],
        path_role: &'static str,
    ) -> Result<(), TenureAuthorityProcessError> {
        let parent = path
            .parent()
            .ok_or_else(|| trusted_ancestor_error(path_role, "missing_parent"))?;
        let mut current = PathBuf::new();
        for component in parent.components() {
            match component {
                Component::RootDir => current.push(component.as_os_str()),
                Component::Normal(value) => current.push(value),
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(trusted_ancestor_error(path_role, "unsafe_component"));
                }
            }
            let metadata = fs::symlink_metadata(&current)
                .map_err(|_| trusted_ancestor_error(path_role, "inspection_failed"))?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(trusted_ancestor_error(path_role, "unsafe_type"));
            }
            let owner_uid = metadata.uid();
            let mode = metadata.mode() & 0o7777;
            let root_owned_sticky = owner_uid == 0 && mode & 0o1000 != 0;
            let owner_is_trusted = owner_uid == 0 || allowed_non_root_uids.contains(&owner_uid);
            if !owner_is_trusted || (mode & 0o022 != 0 && !root_owned_sticky) {
                return Err(trusted_ancestor_error(path_role, "replaceable"));
            }
        }
        Ok(())
    }

    fn trusted_ancestor_error(
        path_role: &'static str,
        fact: &'static str,
    ) -> TenureAuthorityProcessError {
        TenureAuthorityProcessError::diagnosed(
            ProcessErrorKind::Configuration,
            ProcessDiagnostic::new(
                "PXTA-PATH-ANCESTOR-UNTRUSTED",
                "validate_path_ancestors",
                path_role,
                fact,
            ),
        )
    }

    #[derive(Clone, Copy)]
    enum KeyFileRole {
        PrivateSeed,
        PublicKey,
    }

    impl KeyFileRole {
        const fn path_role(self) -> &'static str {
            match self {
                Self::PrivateSeed => "private_seed",
                Self::PublicKey => "public_key",
            }
        }
    }

    fn open_secure_key_file(
        path: &Path,
        role: KeyFileRole,
        expected_uid: u32,
        expected_gid: u32,
        trusted_ancestor_uids: &[u32],
    ) -> Result<File, TenureAuthorityProcessError> {
        validate_existing_path_chain(path)
            .map_err(|_| key_path_error(role, "validate_key_path", "unsafe"))?;
        validate_trusted_ancestor_chain(path, trusted_ancestor_uids, "key_parent")?;
        let before = fs::symlink_metadata(path)
            .map_err(|_| key_path_error(role, "inspect_key", "io_failure"))?;
        validate_key_metadata(&before, role, expected_uid, expected_gid)?;
        let owned = open(
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| key_path_error(role, "open_key", "io_failure"))?;
        let file = File::from(owned);
        let after = file
            .metadata()
            .map_err(|_| key_path_error(role, "inspect_open_key", "io_failure"))?;
        validate_key_metadata(&after, role, expected_uid, expected_gid)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(key_path_error(role, "open_key", "identity_changed"));
        }
        Ok(file)
    }

    fn validate_key_metadata(
        metadata: &Metadata,
        role: KeyFileRole,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<(), TenureAuthorityProcessError> {
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.uid() != expected_uid
            || metadata.gid() != expected_gid
            || metadata.len() != 32
        {
            return Err(key_path_error(role, "validate_key_metadata", "invalid"));
        }
        let mode = metadata.mode() & 0o7777;
        let valid = match role {
            KeyFileRole::PrivateSeed => mode == 0o600,
            KeyFileRole::PublicKey => {
                mode & 0o400 == 0o400
                    && mode & 0o022 == 0
                    && mode & 0o111 == 0
                    && mode & 0o7000 == 0
            }
        };
        if !valid {
            return Err(key_path_error(role, "validate_key_metadata", "invalid"));
        }
        Ok(())
    }

    fn read_public_key(
        path: &Path,
        expected_uid: u32,
        expected_gid: u32,
        trusted_ancestor_uids: &[u32],
    ) -> Result<[u8; 32], TenureAuthorityProcessError> {
        let mut file = open_secure_key_file(
            path,
            KeyFileRole::PublicKey,
            expected_uid,
            expected_gid,
            trusted_ancestor_uids,
        )?;
        let mut bytes = [0; 32];
        read_exact_key_bytes(&mut file, &mut bytes)?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| process_error(ProcessErrorKind::KeyMaterial))?;
        if key.is_weak() {
            return Err(process_error(ProcessErrorKind::KeyMaterial));
        }
        Ok(bytes)
    }

    fn read_private_seed(
        path: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Zeroizing<[u8; 32]>, TenureAuthorityProcessError> {
        let mut file = open_secure_key_file(
            path,
            KeyFileRole::PrivateSeed,
            expected_uid,
            expected_gid,
            &[expected_uid],
        )?;
        let mut bytes = Zeroizing::new([0; 32]);
        read_exact_key_bytes(&mut file, &mut bytes)?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(process_error(ProcessErrorKind::KeyMaterial));
        }
        Ok(bytes)
    }

    fn read_exact_key_bytes(
        file: &mut File,
        output: &mut [u8; 32],
    ) -> Result<(), TenureAuthorityProcessError> {
        file.read_exact(output)
            .map_err(|_| process_error(ProcessErrorKind::KeyMaterial))?;
        let mut trailing = [0; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| process_error(ProcessErrorKind::KeyMaterial))?
            != 0
        {
            return Err(process_error(ProcessErrorKind::KeyMaterial));
        }
        Ok(())
    }

    fn prepare_listener(
        arguments: &CommonArguments,
        _locked_authority: &DeploymentTenureAuthority,
    ) -> Result<(UnixListener, SocketGuard), TenureAuthorityProcessError> {
        let parent = arguments
            .socket_path
            .parent()
            .ok_or_else(|| process_error(ProcessErrorKind::Socket))?;
        let directory = open_secure_directory(
            parent,
            DirectoryRole::Socket,
            arguments.expected_authority_uid,
            arguments.expected_peer_gid,
        )?;
        remove_stale_socket_if_present(&directory, &arguments.socket_path)?;
        let standard = StdUnixListener::bind(&arguments.socket_path)
            .map_err(|_| process_error(ProcessErrorKind::Socket))?;
        let metadata = fs::symlink_metadata(&arguments.socket_path)
            .map_err(|_| process_error(ProcessErrorKind::Socket))?;
        let identity = SocketIdentity::from_metadata(&metadata);
        let guard = SocketGuard {
            path: arguments.socket_path.clone(),
            directory,
            identity,
        };
        let setup = (|| {
            fs::set_permissions(
                &arguments.socket_path,
                fs::Permissions::from_mode(SOCKET_MODE),
            )
            .map_err(|_| process_error(ProcessErrorKind::Socket))?;
            let metadata = fs::symlink_metadata(&arguments.socket_path)
                .map_err(|_| process_error(ProcessErrorKind::Socket))?;
            validate_socket_metadata(
                &metadata,
                arguments.expected_authority_uid,
                arguments.expected_peer_gid,
            )?;
            if !identity.matches(&metadata) {
                return Err(process_error(ProcessErrorKind::Socket));
            }
            validate_open_directory_identity(&guard.directory)?;
            guard
                .directory
                .file
                .sync_all()
                .map_err(|_| process_error(ProcessErrorKind::Socket))?;
            standard
                .set_nonblocking(true)
                .map_err(|_| process_error(ProcessErrorKind::Socket))?;
            Ok(())
        })();
        if let Err(error) = setup {
            drop(standard);
            let _ = guard.cleanup();
            return Err(error);
        }
        let listener = UnixListener::from_std(standard).map_err(|_| {
            let _ = guard.cleanup();
            process_error(ProcessErrorKind::Socket)
        })?;
        Ok((listener, guard))
    }

    fn remove_stale_socket_if_present(
        directory: &OpenedDirectory,
        path: &Path,
    ) -> Result<(), TenureAuthorityProcessError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(process_error(ProcessErrorKind::Socket)),
        };
        validate_socket_metadata(&metadata, directory.expected_uid, directory.expected_gid)?;
        match StdUnixStream::connect(path) {
            Ok(stream) => {
                drop(stream);
                return Err(process_error(ProcessErrorKind::Socket));
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
            Err(_) => return Err(process_error(ProcessErrorKind::Socket)),
        }
        remove_exact_socket(directory, path, SocketIdentity::from_metadata(&metadata))
    }

    fn validate_socket_metadata(
        metadata: &Metadata,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<(), TenureAuthorityProcessError> {
        if !metadata.file_type().is_socket()
            || metadata.nlink() != 1
            || metadata.uid() != expected_uid
            || metadata.gid() != expected_gid
            || metadata.mode() & 0o7777 != SOCKET_MODE
        {
            return Err(process_error(ProcessErrorKind::Socket));
        }
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct SocketIdentity {
        dev: u64,
        ino: u64,
    }

    impl SocketIdentity {
        fn from_metadata(metadata: &Metadata) -> Self {
            Self {
                dev: metadata.dev(),
                ino: metadata.ino(),
            }
        }

        fn matches(self, metadata: &Metadata) -> bool {
            self.dev == metadata.dev() && self.ino == metadata.ino()
        }
    }

    struct SocketGuard {
        path: PathBuf,
        directory: OpenedDirectory,
        identity: SocketIdentity,
    }

    impl SocketGuard {
        fn cleanup(&self) -> Result<(), TenureAuthorityProcessError> {
            remove_exact_socket(&self.directory, &self.path, self.identity)
        }
    }

    fn remove_exact_socket(
        directory: &OpenedDirectory,
        path: &Path,
        expected_identity: SocketIdentity,
    ) -> Result<(), TenureAuthorityProcessError> {
        if path.parent() != Some(directory.path.as_path()) {
            return Err(process_error(ProcessErrorKind::Socket));
        }
        validate_open_directory_identity(directory)?;
        let metadata =
            fs::symlink_metadata(path).map_err(|_| process_error(ProcessErrorKind::Socket))?;
        validate_socket_metadata(&metadata, directory.expected_uid, directory.expected_gid)?;
        if !expected_identity.matches(&metadata) {
            return Err(process_error(ProcessErrorKind::Socket));
        }
        let name = path
            .file_name()
            .ok_or_else(|| process_error(ProcessErrorKind::Socket))?;
        unlinkat(&directory.file, name, UnlinkatFlags::NoRemoveDir)
            .map_err(|_| process_error(ProcessErrorKind::Socket))?;
        directory
            .file
            .sync_all()
            .map_err(|_| process_error(ProcessErrorKind::Socket))
    }

    fn validate_open_directory_identity(
        directory: &OpenedDirectory,
    ) -> Result<(), TenureAuthorityProcessError> {
        let metadata = directory
            .file
            .metadata()
            .map_err(|_| process_error(ProcessErrorKind::Socket))?;
        let path_metadata = fs::symlink_metadata(&directory.path)
            .map_err(|_| process_error(ProcessErrorKind::Socket))?;
        if metadata.dev() != directory.dev
            || metadata.ino() != directory.ino
            || path_metadata.dev() != directory.dev
            || path_metadata.ino() != directory.ino
        {
            return Err(process_error(ProcessErrorKind::Socket));
        }
        Ok(())
    }

    fn process_error(kind: ProcessErrorKind) -> TenureAuthorityProcessError {
        TenureAuthorityProcessError::new(kind)
    }

    fn path_role_error(
        kind: ProcessErrorKind,
        code: &'static str,
        stage: &'static str,
        path_role: &'static str,
        fact: &'static str,
    ) -> TenureAuthorityProcessError {
        TenureAuthorityProcessError::diagnosed(
            kind,
            ProcessDiagnostic::new(code, stage, path_role, fact),
        )
    }

    fn directory_io_error(role: DirectoryRole, stage: &'static str) -> TenureAuthorityProcessError {
        path_role_error(
            ProcessErrorKind::Configuration,
            "PXTA-DIRECTORY-IO",
            stage,
            role.path_role(),
            "io_failure",
        )
    }

    fn key_path_error(
        role: KeyFileRole,
        stage: &'static str,
        fact: &'static str,
    ) -> TenureAuthorityProcessError {
        path_role_error(
            ProcessErrorKind::KeyMaterial,
            "PXTA-KEY-FILE-REJECTED",
            stage,
            role.path_role(),
            fact,
        )
    }

    fn separation_error(
        kind: ProcessErrorKind,
        stage: &'static str,
        path_role: &'static str,
    ) -> TenureAuthorityProcessError {
        TenureAuthorityProcessError::diagnosed(
            kind,
            ProcessDiagnostic::new(
                "PXTA-IDENTITY-KEY-SEPARATION",
                stage,
                path_role,
                "not_separated",
            ),
        )
    }

    fn authority_process_error(
        kind: ProcessErrorKind,
        diagnostic: TenureAuthorityFailureDiagnostic,
    ) -> TenureAuthorityProcessError {
        TenureAuthorityProcessError::diagnosed(
            kind,
            ProcessDiagnostic::new(
                diagnostic.code(),
                diagnostic.stage(),
                diagnostic.path_role(),
                diagnostic.fact(),
            ),
        )
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::OsString;
        use std::fs;
        use std::future::{pending, ready};
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        use std::os::unix::net::UnixListener as StdUnixListener;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::Duration;

        use ed25519_dalek::{Signer, SigningKey};
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        use nix::unistd::{getegid, geteuid};
        use paraegox_kernel::{digest::Digest32, identity::PrincipalRef};
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;
        use tokio::time::timeout as tokio_timeout;

        use super::super::{ProcessErrorKind, TenureAuthorityProcessError};
        use super::{
            CommandKind, CommonArguments, DirectoryRole, IO_TIMEOUT, KeyFileRole,
            POLICY_FINGERPRINT_DOMAIN, PeerIdentity, ProcessCommand, RawOptions,
            SOCKET_DIRECTORY_MODE, SOCKET_MODE, STATE_DIRECTORY_MODE, SocketGuard, SocketIdentity,
            await_server_event, build_runtime, fatal_authority_error, load_provisioning,
            open_secure_directory, open_secure_key_file, parse_absolute_path, parse_arguments,
            parse_nonzero_hex, parse_socket_path, parse_u32, peer_is_authorized,
            policy_fingerprint, policy_fingerprint_for_profile, read_private_seed, read_public_key,
            read_request, read_request_with_timeout, remove_exact_socket,
            remove_stale_socket_if_present, validate_directory_metadata,
            validate_installation_paths, validate_private_seed_material,
            validate_private_seed_separation, validate_service_identity, validate_socket_metadata,
            validate_trusted_ancestor_chain,
        };
        use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
        use crate::tenure_authority::TenureAcquireError;
        use crate::tenure_authority::TenureAuthorityFailureDiagnostic;
        use crate::tenure_protocol::{
            ACQUIRE_TENURE_FRAME_HEADER_BYTES, AcquireTenureIntentV1, AcquireTenureOperationId,
            AcquireTenureRequestDraftV1, ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
            MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES, MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
            encode_acquire_tenure_request_frame,
        };

        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

        const AUTHORITY_SEED: [u8; 32] = [0x31; 32];
        const CONTROLLER_SEED: [u8; 32] = [0x42; 32];
        const WEAK_ED25519_PUBLIC_KEY: [u8; 32] = [
            236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ];

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new() -> Self {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                // Unix-domain socket path limits are short on some supported
                // platforms, so keep the unique child name deliberately tiny.
                // The canonical per-user temp root also avoids symlinked path
                // components and preserves the caller's primary group.
                let fixture_root = std::env::temp_dir()
                    .canonicalize()
                    .unwrap_or_else(|error| panic!("fixture root canonicalize failed: {error}"));
                let path = fixture_root.join(format!("pxap-{}-{sequence}", std::process::id()));
                fs::create_dir(&path)
                    .unwrap_or_else(|error| panic!("fixture directory create failed: {error}"));
                set_mode(&path, 0o700);
                Self(path)
            }

            fn directory(&self, name: &str, mode: u32) -> PathBuf {
                let path = self.0.join(name);
                fs::create_dir(&path)
                    .unwrap_or_else(|error| panic!("fixture child directory failed: {error}"));
                set_mode(&path, mode);
                path
            }

            fn file(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
                let path = self.0.join(name);
                fs::write(&path, bytes)
                    .unwrap_or_else(|error| panic!("fixture file write failed: {error}"));
                set_mode(&path, mode);
                path
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        struct SecurityFixture {
            _root: TestDirectory,
            state_directory: PathBuf,
            socket_directory: PathBuf,
            socket_path: PathBuf,
            authority_public_key: PathBuf,
            controller_public_key: PathBuf,
            private_seed: PathBuf,
            authority_uid: u32,
            authority_gid: u32,
        }

        impl SecurityFixture {
            fn new() -> Self {
                let root = TestDirectory::new();
                let state_directory = root.directory("state", STATE_DIRECTORY_MODE);
                let socket_directory = root.directory("run", SOCKET_DIRECTORY_MODE);
                let _keys = root.directory("keys", 0o700);
                let authority_key = SigningKey::from_bytes(&AUTHORITY_SEED);
                let controller_key = SigningKey::from_bytes(&CONTROLLER_SEED);
                let authority_public_key = root.file(
                    "keys/authority.pub",
                    &authority_key.verifying_key().to_bytes(),
                    0o400,
                );
                let controller_public_key = root.file(
                    "keys/controller.pub",
                    &controller_key.verifying_key().to_bytes(),
                    0o440,
                );
                let private_seed = root.file("keys/authority.seed", &AUTHORITY_SEED, 0o600);
                let metadata = fs::metadata(&state_directory)
                    .unwrap_or_else(|error| panic!("state metadata failed: {error}"));
                Self {
                    _root: root,
                    socket_path: socket_directory.join("authority.sock"),
                    state_directory,
                    socket_directory,
                    authority_public_key,
                    controller_public_key,
                    private_seed,
                    authority_uid: metadata.uid(),
                    authority_gid: metadata.gid(),
                }
            }

            fn common(&self) -> CommonArguments {
                CommonArguments {
                    state_directory: self.state_directory.clone(),
                    socket_path: self.socket_path.clone(),
                    authority_public_key_path: self.authority_public_key.clone(),
                    controller_public_key_path: self.controller_public_key.clone(),
                    source_scope: [0x11; 16],
                    writer: [0x22; 16],
                    authority: [0x33; 16],
                    tenure_key: [0x44; 16],
                    controller_principal: [0x55; 16],
                    controller_key: [0x66; 16],
                    service_principal: [0x77; 16],
                    owner_id: [0x88; 16],
                    expected_authority_uid: self.authority_uid,
                    expected_authority_gid: self.authority_gid,
                    expected_peer_uid: different(self.authority_uid),
                    expected_peer_gid: getegid().as_raw(),
                }
            }

            fn cli(&self, command: &str) -> Vec<OsString> {
                let common = self.common();
                vec![
                    command.into(),
                    "--state-dir".into(),
                    common.state_directory.into_os_string(),
                    "--socket-path".into(),
                    common.socket_path.into_os_string(),
                    "--authority-public-key".into(),
                    common.authority_public_key_path.into_os_string(),
                    "--controller-public-key".into(),
                    common.controller_public_key_path.into_os_string(),
                    "--source-scope".into(),
                    hex(0x11, 16).into(),
                    "--writer-ref".into(),
                    hex(0x22, 16).into(),
                    "--authority-ref".into(),
                    hex(0x33, 16).into(),
                    "--tenure-key-ref".into(),
                    hex(0x44, 16).into(),
                    "--controller-principal-ref".into(),
                    hex(0x55, 16).into(),
                    "--controller-key-ref".into(),
                    hex(0x66, 16).into(),
                    "--service-principal-ref".into(),
                    hex(0x77, 16).into(),
                    "--owner-id".into(),
                    hex(0x88, 16).into(),
                    "--expected-authority-uid".into(),
                    common.expected_authority_uid.to_string().into(),
                    "--expected-authority-gid".into(),
                    common.expected_authority_gid.to_string().into(),
                    "--expected-peer-uid".into(),
                    common.expected_peer_uid.to_string().into(),
                    "--expected-peer-gid".into(),
                    common.expected_peer_gid.to_string().into(),
                ]
            }
        }

        fn set_mode(path: &Path, mode: u32) {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .unwrap_or_else(|error| panic!("fixture chmod failed: {error}"));
        }

        fn hex(byte: u8, bytes: usize) -> String {
            format!("{byte:02x}").repeat(bytes)
        }

        fn different(value: u32) -> u32 {
            if value == u32::MAX {
                value - 1
            } else {
                value + 1
            }
        }

        fn replace_flag_value(arguments: &mut [OsString], flag: &str, value: impl Into<OsString>) {
            let Some(index) = arguments.iter().position(|item| item == flag) else {
                panic!("fixture flag missing: {flag}");
            };
            arguments[index + 1] = value.into();
        }

        fn assert_argument_rejected(arguments: Vec<OsString>) {
            let error = parse_arguments(arguments)
                .expect_err("non-canonical or incomplete command must be rejected");
            assert_eq!(error.kind, ProcessErrorKind::Arguments);
        }

        fn assert_cloexec(file: &fs::File) {
            let raw_flags = fcntl(file, FcntlArg::F_GETFD)
                .unwrap_or_else(|error| panic!("F_GETFD failed: {error}"));
            let flags = FdFlag::from_bits_truncate(raw_flags);
            assert!(flags.contains(FdFlag::FD_CLOEXEC));
        }

        fn opened_socket_directory(fixture: &SecurityFixture) -> super::OpenedDirectory {
            open_secure_directory(
                &fixture.socket_directory,
                DirectoryRole::Socket,
                fixture.authority_uid,
                fixture.common().expected_peer_gid,
            )
            .unwrap_or_else(|error| panic!("secure socket directory must open: {error}"))
        }

        fn install_socket(path: &Path) -> StdUnixListener {
            let listener = StdUnixListener::bind(path)
                .unwrap_or_else(|error| panic!("fixture socket bind failed: {error}"));
            set_mode(path, SOCKET_MODE);
            listener
        }

        fn request_frame() -> (crate::tenure_protocol::AcquireTenureRequestV1, Box<[u8]>) {
            let signing_key = SigningKey::from_bytes(&CONTROLLER_SEED);
            let fingerprint = ControllerPublicKeyFingerprint::for_ed25519_key(
                &signing_key.verifying_key().to_bytes(),
            )
            .unwrap_or_else(|error| panic!("controller fingerprint failed: {error}"));
            let response_bound = u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .unwrap_or_else(|error| panic!("response bound conversion failed: {error}"));
            let draft = AcquireTenureRequestDraftV1::try_new(
                AcquireTenureIntentV1::new(
                    DeploymentScopeId::from_bytes([0x11; 16]),
                    DeploymentWriterRef::from_bytes([0x22; 16]),
                    AcquireTenureOperationId::from_bytes([0x33; 16]),
                ),
                PrincipalRef::from_bytes([0x55; 16]),
                ControllerAcquireKeyRef::from_bytes([0x66; 16]),
                fingerprint,
                b"process-test-nonce",
                response_bound,
            )
            .unwrap_or_else(|error| panic!("request draft failed: {error}"));
            let transcript = draft
                .signing_transcript()
                .unwrap_or_else(|error| panic!("request transcript failed: {error}"));
            let signature = signing_key.sign(transcript.as_bytes());
            let request = draft
                .finalize_ed25519(&signature.to_bytes())
                .unwrap_or_else(|error| panic!("request finalize failed: {error}"));
            let frame = encode_acquire_tenure_request_frame(&request);
            (request, frame)
        }

        fn frame_header(kind: u16, payload_bytes: u32) -> [u8; ACQUIRE_TENURE_FRAME_HEADER_BYTES] {
            let mut header = [0; ACQUIRE_TENURE_FRAME_HEADER_BYTES];
            header[..8].copy_from_slice(b"PXATFRM\0");
            header[8..10].copy_from_slice(&1_u16.to_be_bytes());
            header[10..12].copy_from_slice(&kind.to_be_bytes());
            header[12..16].copy_from_slice(&payload_bytes.to_be_bytes());
            header
        }

        #[test]
        fn cli_accepts_only_the_exact_subcommand_specific_flags() {
            let fixture = SecurityFixture::new();

            let initialize = parse_arguments(fixture.cli("initialize"))
                .unwrap_or_else(|error| panic!("initialize CLI must parse: {error}"));
            assert!(matches!(initialize, ProcessCommand::Initialize(_)));

            let receipt = parse_arguments(fixture.cli("initialization-receipt"))
                .unwrap_or_else(|error| panic!("receipt CLI must parse without store id: {error}"));
            assert!(matches!(receipt, ProcessCommand::InitializationReceipt(_)));

            let mut serve = fixture.cli("serve");
            serve.extend([
                OsString::from("--expected-store-id"),
                OsString::from(hex(0x99, 32)),
                OsString::from("--private-seed"),
                fixture.private_seed.clone().into_os_string(),
            ]);
            let serve = parse_arguments(serve)
                .unwrap_or_else(|error| panic!("serve CLI must parse: {error}"));
            assert!(matches!(serve, ProcessCommand::Serve { .. }));

            let mut initialize_with_seed = fixture.cli("initialize");
            initialize_with_seed.extend([
                OsString::from("--private-seed"),
                fixture.private_seed.clone().into_os_string(),
            ]);
            assert_argument_rejected(initialize_with_seed);

            let mut receipt_with_store_id = fixture.cli("initialization-receipt");
            receipt_with_store_id.extend([
                OsString::from("--expected-store-id"),
                OsString::from(hex(0x99, 32)),
            ]);
            assert_argument_rejected(receipt_with_store_id);
            assert_argument_rejected(fixture.cli("serve"));
        }

        #[test]
        fn cli_rejects_unknown_duplicate_missing_and_noncanonical_values() {
            let fixture = SecurityFixture::new();

            assert_argument_rejected(Vec::new());
            assert_argument_rejected(vec![OsString::from("unknown")]);
            assert_argument_rejected(vec![
                OsString::from("initialize"),
                OsString::from("--state-dir"),
            ]);

            let mut unknown = fixture.cli("initialize");
            unknown.extend([OsString::from("--unknown"), OsString::from("value")]);
            assert_argument_rejected(unknown);

            let mut duplicate = fixture.cli("initialize");
            duplicate.extend([OsString::from("--owner-id"), OsString::from(hex(0x88, 16))]);
            assert_argument_rejected(duplicate);

            let mut uppercase_hex = fixture.cli("initialize");
            replace_flag_value(&mut uppercase_hex, "--source-scope", "AA".repeat(16));
            assert_argument_rejected(uppercase_hex);

            let mut zero_hex = fixture.cli("initialize");
            replace_flag_value(&mut zero_hex, "--source-scope", "00".repeat(16));
            assert_argument_rejected(zero_hex);

            let mut short_hex = fixture.cli("initialize");
            replace_flag_value(&mut short_hex, "--source-scope", "11".repeat(15));
            assert_argument_rejected(short_hex);

            for value in ["", "01", "+1", "-1", "4294967296", "1x"] {
                let mut invalid_u32 = fixture.cli("initialize");
                replace_flag_value(&mut invalid_u32, "--expected-peer-uid", value);
                assert_argument_rejected(invalid_u32);
            }
        }

        #[test]
        fn scalar_and_path_parsers_reject_noncanonical_encodings() {
            assert_eq!(parse_u32(OsString::from("0")).ok(), Some(0));
            assert_eq!(parse_u32(OsString::from("4294967295")).ok(), Some(u32::MAX));
            assert_eq!(
                parse_nonzero_hex::<16>(OsString::from("01".repeat(16))).ok(),
                Some([1; 16])
            );
            assert!(parse_nonzero_hex::<16>(OsString::from("01".repeat(15))).is_err());

            for path in [
                "relative/path",
                "/",
                "/tmp/./authority",
                "/tmp/../authority",
                "/tmp//authority",
                "//tmp/authority",
                "/tmp/authority/",
            ] {
                assert!(parse_absolute_path(OsString::from(path)).is_err(), "{path}");
            }
            assert!(parse_absolute_path(OsString::from("/tmp/authority")).is_ok());
            assert!(parse_socket_path(OsString::from("/authority.sock")).is_ok());
        }

        #[test]
        fn secure_key_files_require_exact_shape_and_are_close_on_exec() {
            let fixture = SecurityFixture::new();
            let public = read_public_key(
                &fixture.authority_public_key,
                fixture.authority_uid,
                fixture.authority_gid,
                &[fixture.authority_uid],
            )
            .unwrap_or_else(|error| panic!("valid public key must load: {error}"));
            assert_eq!(
                public,
                SigningKey::from_bytes(&AUTHORITY_SEED)
                    .verifying_key()
                    .to_bytes()
            );
            let private = read_private_seed(
                &fixture.private_seed,
                fixture.authority_uid,
                fixture.authority_gid,
            )
            .unwrap_or_else(|error| panic!("valid private seed must load: {error}"));
            assert_eq!(&*private, &AUTHORITY_SEED);

            let file = open_secure_key_file(
                &fixture.authority_public_key,
                KeyFileRole::PublicKey,
                fixture.authority_uid,
                fixture.authority_gid,
                &[fixture.authority_uid],
            )
            .unwrap_or_else(|error| panic!("valid public key must open: {error}"));
            assert_cloexec(&file);

            assert!(
                read_public_key(
                    &fixture.authority_public_key,
                    different(fixture.authority_uid),
                    fixture.authority_gid,
                    &[fixture.authority_uid],
                )
                .is_err()
            );
            assert!(
                read_public_key(
                    &fixture.authority_public_key,
                    fixture.authority_uid,
                    different(fixture.authority_gid),
                    &[fixture.authority_uid],
                )
                .is_err()
            );
        }

        #[test]
        fn key_symlinks_hardlinks_modes_lengths_and_weak_material_fail_closed() {
            let fixture = SecurityFixture::new();
            let root = fixture
                .state_directory
                .parent()
                .unwrap_or_else(|| panic!("fixture state must have parent"));

            let symlink_path = root.join("keys/symlink.pub");
            symlink(&fixture.authority_public_key, &symlink_path)
                .unwrap_or_else(|error| panic!("fixture symlink failed: {error}"));
            assert!(
                read_public_key(
                    &symlink_path,
                    fixture.authority_uid,
                    fixture.authority_gid,
                    &[fixture.authority_uid],
                )
                .is_err()
            );

            let hardlink_path = root.join("keys/hardlink.pub");
            fs::hard_link(&fixture.authority_public_key, &hardlink_path)
                .unwrap_or_else(|error| panic!("fixture hardlink failed: {error}"));
            assert!(
                read_public_key(
                    &fixture.authority_public_key,
                    fixture.authority_uid,
                    fixture.authority_gid,
                    &[fixture.authority_uid],
                )
                .is_err()
            );

            let invalid_mode = root.join("keys/invalid-mode.seed");
            fs::write(&invalid_mode, AUTHORITY_SEED)
                .unwrap_or_else(|error| panic!("fixture seed write failed: {error}"));
            set_mode(&invalid_mode, 0o640);
            assert!(
                read_private_seed(&invalid_mode, fixture.authority_uid, fixture.authority_gid)
                    .is_err()
            );

            for (name, bytes) in [
                ("short.seed", vec![1; 31]),
                ("long.seed", vec![1; 33]),
                ("zero.seed", vec![0; 32]),
            ] {
                let path = root.join("keys").join(name);
                fs::write(&path, bytes)
                    .unwrap_or_else(|error| panic!("fixture malformed seed failed: {error}"));
                set_mode(&path, 0o600);
                assert!(
                    read_private_seed(&path, fixture.authority_uid, fixture.authority_gid).is_err()
                );
            }

            let weak_path = root.join("keys/weak.pub");
            fs::write(&weak_path, WEAK_ED25519_PUBLIC_KEY)
                .unwrap_or_else(|error| panic!("fixture weak key failed: {error}"));
            set_mode(&weak_path, 0o400);
            assert!(
                read_public_key(
                    &weak_path,
                    fixture.authority_uid,
                    fixture.authority_gid,
                    &[fixture.authority_uid],
                )
                .is_err()
            );
        }

        #[test]
        fn installation_paths_enforce_exact_acl_and_state_socket_separation() {
            let fixture = SecurityFixture::new();
            let common = fixture.common();
            validate_installation_paths(&common)
                .unwrap_or_else(|error| panic!("valid installation paths rejected: {error}"));

            let state_metadata = fs::metadata(&fixture.state_directory)
                .unwrap_or_else(|error| panic!("state metadata failed: {error}"));
            assert!(
                validate_directory_metadata(
                    &state_metadata,
                    DirectoryRole::State,
                    fixture.authority_uid,
                    fixture.authority_gid,
                )
                .is_ok()
            );
            assert!(
                validate_directory_metadata(
                    &state_metadata,
                    DirectoryRole::State,
                    different(fixture.authority_uid),
                    fixture.authority_gid,
                )
                .is_err()
            );

            set_mode(&fixture.state_directory, 0o750);
            assert!(validate_installation_paths(&common).is_err());
            set_mode(&fixture.state_directory, STATE_DIRECTORY_MODE);

            set_mode(&fixture.socket_directory, 0o750);
            assert!(validate_installation_paths(&common).is_err());
            set_mode(&fixture.socket_directory, SOCKET_DIRECTORY_MODE);

            let mut inside_state = common.clone();
            inside_state.socket_path = fixture.state_directory.join("authority.sock");
            assert!(validate_installation_paths(&inside_state).is_err());

            let mut key_inside_state = common.clone();
            key_inside_state.authority_public_key_path =
                fixture.state_directory.join("authority.pub");
            assert!(validate_installation_paths(&key_inside_state).is_err());

            assert!(validate_private_seed_separation(&common, &fixture.private_seed).is_ok());
            assert!(
                validate_private_seed_separation(
                    &common,
                    &fixture.state_directory.join("authority.seed"),
                )
                .is_err()
            );
            assert!(
                validate_private_seed_separation(&common, &fixture.controller_public_key).is_err()
            );

            let mut same_key_path = common.clone();
            same_key_path.controller_public_key_path = fixture.authority_public_key.clone();
            assert!(validate_installation_paths(&same_key_path).is_err());
        }

        #[test]
        fn trusted_ancestor_policy_allows_root_sticky_temp_and_rejects_peer_writable_parent() {
            let root_sticky_child = TestDirectory::new();
            validate_trusted_ancestor_chain(
                &root_sticky_child.0,
                &[geteuid().as_raw()],
                "state_dir",
            )
            .unwrap_or_else(|error| panic!("root-sticky temp ancestor rejected: {error}"));

            let replaceable_root = TestDirectory::new();
            let peer_writable = replaceable_root.directory("peer-writable", 0o770);
            let state = peer_writable.join("state");
            fs::create_dir(&state)
                .unwrap_or_else(|error| panic!("replaceable state create failed: {error}"));
            set_mode(&state, STATE_DIRECTORY_MODE);
            let error = validate_trusted_ancestor_chain(&state, &[geteuid().as_raw()], "state_dir")
                .expect_err("peer-writable ancestor must be rejected");
            assert_eq!(error.diagnostic.code, "PXTA-PATH-ANCESTOR-UNTRUSTED");
            assert_eq!(error.diagnostic.stage, "validate_path_ancestors");
            assert_eq!(error.diagnostic.path_role, "state_dir");
            assert_eq!(error.diagnostic.fact, "replaceable");
        }

        #[test]
        fn service_accounts_principals_and_signing_keys_must_be_distinct() {
            let fixture = SecurityFixture::new();
            let common = fixture.common();
            validate_service_identity(&common)
                .unwrap_or_else(|error| panic!("valid service separation rejected: {error}"));
            load_provisioning(&common)
                .unwrap_or_else(|error| panic!("valid distinct keys rejected: {error}"));
            assert!(
                validate_private_seed_material(
                    &AUTHORITY_SEED,
                    &SigningKey::from_bytes(&AUTHORITY_SEED)
                        .verifying_key()
                        .to_bytes(),
                    &SigningKey::from_bytes(&CONTROLLER_SEED)
                        .verifying_key()
                        .to_bytes(),
                )
                .is_ok()
            );
            assert!(
                validate_private_seed_material(
                    &SigningKey::from_bytes(&CONTROLLER_SEED)
                        .verifying_key()
                        .to_bytes(),
                    &SigningKey::from_bytes(&AUTHORITY_SEED)
                        .verifying_key()
                        .to_bytes(),
                    &SigningKey::from_bytes(&CONTROLLER_SEED)
                        .verifying_key()
                        .to_bytes(),
                )
                .is_err()
            );

            let mut same_uid = common.clone();
            same_uid.expected_peer_uid = same_uid.expected_authority_uid;
            let error = validate_service_identity(&same_uid)
                .expect_err("same service uid must fail separation");
            assert_eq!(error.diagnostic.code, "PXTA-IDENTITY-KEY-SEPARATION");
            assert_eq!(error.diagnostic.stage, "validate_service_identity");
            assert_eq!(error.diagnostic.path_role, "service_identity");

            let mut wrong_authority = common.clone();
            wrong_authority.expected_authority_uid = different(common.expected_authority_uid);
            assert!(validate_service_identity(&wrong_authority).is_err());

            let mut same_principal = common.clone();
            same_principal.service_principal = same_principal.controller_principal;
            assert!(validate_service_identity(&same_principal).is_err());

            let mut root_identity = common.clone();
            root_identity.expected_peer_uid = 0;
            assert!(validate_service_identity(&root_identity).is_err());

            set_mode(&fixture.controller_public_key, 0o600);
            fs::write(
                &fixture.controller_public_key,
                SigningKey::from_bytes(&AUTHORITY_SEED)
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap_or_else(|error| panic!("matching key fixture write failed: {error}"));
            set_mode(&fixture.controller_public_key, 0o440);
            let Err(error) = load_provisioning(&common) else {
                panic!("reused Authority and Controller key must fail closed")
            };
            assert_eq!(error.kind, ProcessErrorKind::Provisioning);
        }

        #[test]
        fn policy_fingerprint_binds_peer_identity_authority_identity_and_acl_modes() {
            let fixture = SecurityFixture::new();
            let common = fixture.common();
            let authority_fingerprint = Digest32::from_bytes([0xa1; 32]);
            let controller_fingerprint = [0xb2; 32];
            let baseline =
                policy_fingerprint(&common, authority_fingerprint, controller_fingerprint)
                    .unwrap_or_else(|error| panic!("policy fingerprint failed: {error}"));
            assert!(!POLICY_FINGERPRINT_DOMAIN.is_empty());

            for mutate in [
                |arguments: &mut CommonArguments| {
                    arguments.expected_peer_uid = different(arguments.expected_peer_uid);
                },
                |arguments: &mut CommonArguments| {
                    arguments.expected_peer_gid = different(arguments.expected_peer_gid);
                },
                |arguments: &mut CommonArguments| {
                    arguments.expected_authority_uid = different(arguments.expected_authority_uid);
                },
                |arguments: &mut CommonArguments| {
                    arguments.expected_authority_gid = different(arguments.expected_authority_gid);
                },
            ] {
                let mut changed = common.clone();
                mutate(&mut changed);
                assert_ne!(
                    policy_fingerprint(&changed, authority_fingerprint, controller_fingerprint,)
                        .unwrap_or_else(|error| panic!("changed policy failed: {error}")),
                    baseline
                );
            }

            for (state_mode, directory_mode, socket_mode) in [
                (
                    STATE_DIRECTORY_MODE ^ 0o020,
                    SOCKET_DIRECTORY_MODE,
                    SOCKET_MODE,
                ),
                (
                    STATE_DIRECTORY_MODE,
                    SOCKET_DIRECTORY_MODE ^ 0o020,
                    SOCKET_MODE,
                ),
                (
                    STATE_DIRECTORY_MODE,
                    SOCKET_DIRECTORY_MODE,
                    SOCKET_MODE ^ 0o020,
                ),
            ] {
                assert_ne!(
                    policy_fingerprint_for_profile(
                        &common,
                        authority_fingerprint,
                        controller_fingerprint,
                        state_mode,
                        directory_mode,
                        socket_mode,
                    )
                    .unwrap_or_else(|error| panic!("profile fingerprint failed: {error}")),
                    baseline
                );
            }
        }

        #[test]
        fn socket_metadata_active_socket_and_non_socket_checks_fail_closed() {
            let fixture = SecurityFixture::new();
            let directory = opened_socket_directory(&fixture);
            assert_cloexec(&directory.file);

            let active = install_socket(&fixture.socket_path);
            let metadata = fs::symlink_metadata(&fixture.socket_path)
                .unwrap_or_else(|error| panic!("socket metadata failed: {error}"));
            validate_socket_metadata(
                &metadata,
                fixture.authority_uid,
                fixture.common().expected_peer_gid,
            )
            .unwrap_or_else(|error| panic!("valid socket metadata rejected: {error}"));
            assert_eq!(metadata.mode() & 0o7777, SOCKET_MODE);
            assert_eq!(metadata.uid(), fixture.authority_uid);
            assert_eq!(metadata.gid(), fixture.common().expected_peer_gid);
            assert!(
                validate_socket_metadata(
                    &metadata,
                    different(fixture.authority_uid),
                    fixture.common().expected_peer_gid,
                )
                .is_err()
            );
            assert!(remove_stale_socket_if_present(&directory, &fixture.socket_path).is_err());
            assert!(fixture.socket_path.exists());
            drop(active);
            fs::remove_file(&fixture.socket_path)
                .unwrap_or_else(|error| panic!("active fixture cleanup failed: {error}"));

            fs::write(&fixture.socket_path, b"not a socket")
                .unwrap_or_else(|error| panic!("non-socket fixture failed: {error}"));
            set_mode(&fixture.socket_path, SOCKET_MODE);
            assert!(remove_stale_socket_if_present(&directory, &fixture.socket_path).is_err());
            assert!(fixture.socket_path.is_file());
        }

        #[test]
        fn stale_socket_cleanup_is_exact_and_replacement_safe() {
            let fixture = SecurityFixture::new();
            let directory = opened_socket_directory(&fixture);
            let stale = install_socket(&fixture.socket_path);
            drop(stale);
            remove_stale_socket_if_present(&directory, &fixture.socket_path)
                .unwrap_or_else(|error| panic!("valid stale socket cleanup failed: {error}"));
            assert!(!fixture.socket_path.exists());

            let exact_listener = install_socket(&fixture.socket_path);
            let exact_metadata = fs::symlink_metadata(&fixture.socket_path)
                .unwrap_or_else(|error| panic!("exact socket metadata failed: {error}"));
            let exact_identity = SocketIdentity::from_metadata(&exact_metadata);
            drop(exact_listener);
            remove_exact_socket(&directory, &fixture.socket_path, exact_identity)
                .unwrap_or_else(|error| panic!("exact cleanup failed: {error}"));
            assert!(!fixture.socket_path.exists());

            let original_listener = install_socket(&fixture.socket_path);
            let original_metadata = fs::symlink_metadata(&fixture.socket_path)
                .unwrap_or_else(|error| panic!("original socket metadata failed: {error}"));
            let original_identity = SocketIdentity::from_metadata(&original_metadata);
            fs::remove_file(&fixture.socket_path)
                .unwrap_or_else(|error| panic!("unlink original socket failed: {error}"));
            let replacement_listener = install_socket(&fixture.socket_path);
            let replacement_metadata = fs::symlink_metadata(&fixture.socket_path)
                .unwrap_or_else(|error| panic!("replacement socket metadata failed: {error}"));
            assert!(!original_identity.matches(&replacement_metadata));
            let guard = SocketGuard {
                path: fixture.socket_path.clone(),
                directory,
                identity: original_identity,
            };
            assert!(guard.cleanup().is_err());
            assert!(fixture.socket_path.exists());
            drop(replacement_listener);
            drop(original_listener);
        }

        #[test]
        fn peer_credentials_are_checked_before_protocol_bytes() {
            let runtime =
                build_runtime().unwrap_or_else(|error| panic!("test runtime must build: {error}"));
            let _runtime_context = runtime.enter();
            let (server, _client) = UnixStream::pair()
                .unwrap_or_else(|error| panic!("Unix stream pair failed: {error}"));
            let expected = PeerIdentity {
                uid: geteuid().as_raw(),
                gid: getegid().as_raw(),
            };
            assert!(peer_is_authorized(&server, expected));
            assert!(!peer_is_authorized(
                &server,
                PeerIdentity {
                    uid: different(expected.uid),
                    gid: expected.gid,
                }
            ));
            assert!(!peer_is_authorized(
                &server,
                PeerIdentity {
                    uid: expected.uid,
                    gid: different(expected.gid),
                }
            ));
        }

        #[test]
        fn shutdown_wins_when_accept_and_signal_are_ready_together() {
            let runtime =
                build_runtime().unwrap_or_else(|error| panic!("test runtime must build: {error}"));
            let event = runtime.block_on(await_server_event(
                ready(Ok::<u8, std::io::Error>(7)),
                ready(Some(())),
                pending::<Option<()>>(),
            ));
            assert!(matches!(event, super::ServerEvent::Shutdown));
        }

        #[test]
        fn request_reader_round_trips_and_rejects_header_bombs_before_payload_read() {
            let runtime =
                build_runtime().unwrap_or_else(|error| panic!("test runtime must build: {error}"));
            runtime.block_on(async {
                let (request, frame) = request_frame();
                let (mut server, mut client) = UnixStream::pair()
                    .unwrap_or_else(|error| panic!("Unix stream pair failed: {error}"));
                client
                    .write_all(&frame)
                    .await
                    .unwrap_or_else(|error| panic!("request frame write failed: {error}"));
                let decoded = read_request(&mut server)
                    .await
                    .unwrap_or_else(|()| panic!("valid request frame rejected"));
                assert_eq!(decoded, request);

                let oversized = u32::try_from(MAX_ACQUIRE_TENURE_REQUEST_PAYLOAD_BYTES + 1)
                    .unwrap_or_else(|error| panic!("oversized length conversion failed: {error}"));
                let (mut server, mut client) = UnixStream::pair()
                    .unwrap_or_else(|error| panic!("Unix stream pair failed: {error}"));
                client
                    .write_all(&frame_header(1, oversized))
                    .await
                    .unwrap_or_else(|error| panic!("oversized header write failed: {error}"));
                let rejected = tokio_timeout(Duration::from_secs(1), read_request(&mut server))
                    .await
                    .unwrap_or_else(|_| {
                        panic!("oversized header must reject without payload wait")
                    });
                assert!(rejected.is_err());

                let (mut server, mut client) = UnixStream::pair()
                    .unwrap_or_else(|error| panic!("Unix stream pair failed: {error}"));
                client
                    .write_all(&frame_header(2, 0))
                    .await
                    .unwrap_or_else(|error| panic!("wrong-kind header write failed: {error}"));
                assert!(read_request(&mut server).await.is_err());
            });
        }

        #[test]
        fn request_reader_has_a_fixed_non_configurable_deadline() {
            assert_eq!(IO_TIMEOUT, Duration::from_secs(5));
            let runtime =
                build_runtime().unwrap_or_else(|error| panic!("test runtime must build: {error}"));
            runtime.block_on(async {
                let (mut server, _client) = UnixStream::pair()
                    .unwrap_or_else(|error| panic!("Unix stream pair failed: {error}"));
                let result = tokio_timeout(
                    Duration::from_secs(1),
                    read_request_with_timeout(&mut server, Duration::from_millis(20)),
                )
                .await
                .unwrap_or_else(|_| panic!("test deadline wrapper did not return"));
                assert!(result.is_err());
            });
        }

        #[test]
        fn only_store_integrity_or_publish_failures_stop_the_service_loop() {
            let diagnostic = TenureAuthorityFailureDiagnostic::new(
                "PXTA-TEST",
                "test",
                "active_snapshot",
                "test",
            );
            for fatal in [
                TenureAcquireError::InvalidStoredResponse,
                TenureAcquireError::SigningFailed,
                TenureAcquireError::ResponseEncodingFailed,
                TenureAcquireError::StoreStopped,
                TenureAcquireError::RejectedBeforePublish(diagnostic),
                TenureAcquireError::UncertainAfterPublish(diagnostic),
                TenureAcquireError::StoreUnavailableOrInvalid(diagnostic),
            ] {
                assert!(fatal_authority_error(fatal), "{fatal:?}");
            }
            for request_rejection in [
                TenureAcquireError::UnauthorizedScope,
                TenureAcquireError::UnauthorizedWriter,
                TenureAcquireError::UnauthorizedControllerPrincipal,
                TenureAcquireError::UnauthorizedControllerKey,
                TenureAcquireError::UnsupportedRequestSignatureProfile,
                TenureAcquireError::InvalidRequestSignature,
                TenureAcquireError::OperationDigestConflict,
                TenureAcquireError::CapacityExceeded,
                TenureAcquireError::ResponseBoundExceeded,
            ] {
                assert!(
                    !fatal_authority_error(request_rejection),
                    "{request_rejection:?}"
                );
            }
        }

        #[test]
        fn raw_options_do_not_offer_environment_or_test_service_controls() {
            let raw = RawOptions::default();
            assert!(raw.state_directory.is_none());
            assert!(raw.socket_path.is_none());
            assert!(raw.private_seed_path.is_none());
            assert!(matches!(CommandKind::Serve, CommandKind::Serve));
            let error = TenureAuthorityProcessError::new(ProcessErrorKind::Arguments);
            assert_eq!(
                format!("{error}\n"),
                "invalid tenure-authority command line; code=PXTA-ARGUMENTS-INVALID \
                 stage=parse_arguments path_role=command_line fact=invalid\n"
            );
            assert_eq!(format!("{error:?}"), "TenureAuthorityProcessError { .. }");
        }

        #[test]
        fn thin_cli_stderr_has_stable_non_sensitive_authority_failure_classification() {
            let diagnostic = TenureAuthorityFailureDiagnostic::new(
                "PXTA-SNAPSHOT-CHECKSUM-MISMATCH",
                "decode_snapshot",
                "active_snapshot",
                "checksum_mismatch",
            );
            let error = super::authority_process_error(ProcessErrorKind::Store, diagnostic);
            assert_eq!(
                format!("{error}\n"),
                "tenure-authority store failed closed; code=PXTA-SNAPSHOT-CHECKSUM-MISMATCH \
                 stage=decode_snapshot path_role=active_snapshot fact=checksum_mismatch\n"
            );
            let debug = format!("{error:?}");
            assert!(!debug.contains("checksum"));
            assert!(!debug.contains("snapshot"));
        }
    }
}
