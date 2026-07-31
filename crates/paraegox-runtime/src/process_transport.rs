//! RuntimeHost-owned PXWP transport over one owned Unix child process.
//!
//! Protocol state is advanced before a host frame can hand off bytes. If an
//! async operation is cancelled or an I/O error occurs, the transport remains
//! poisoned and can only be fenced and cleaned by its ProcessDomain owner.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use paraegox_kernel::digest::Digest32;
use paraegox_runtime_contracts::process_protocol::{
    ConstructOutcome, InvocationTerminalKind, MAX_PROCESS_WORKER_FRAME_BYTES,
    PROCESS_WORKER_HEADER_BYTES, ProcessFrame, ProcessFrameBody, ProcessFrameDirection,
    ProcessFrameKind, ProcessProtocolError, ProcessProtocolPhase, ProcessProtocolSession,
    ProcessSessionIdentity, ProcessWorkerState, StoppedOutcome,
};

use crate::process_platform::{ProcessPlatformError, ResolvedProcessLaunch, UnixChildProcess};

const STREAM_LENGTH_BYTES: usize = 4;

/// A single-owner stream plus its exact fail-closed PXWP dialogue state.
#[derive(Debug)]
pub(crate) struct ProcessTransport {
    process: UnixChildProcess,
    identity: ProcessSessionIdentity,
    session: ProcessProtocolSession,
    host_sequence: u64,
    receive_buffer: Vec<u8>,
    expected_frame_length: Option<usize>,
    max_retained_bytes: Option<u64>,
    delivered_payload_bytes: Arc<AtomicU64>,
    poisoned: bool,
}

impl ProcessTransport {
    pub(crate) fn spawn(
        profile: &ResolvedProcessLaunch,
        identity: ProcessSessionIdentity,
    ) -> Result<Self, ProcessTransportError> {
        Ok(Self {
            process: UnixChildProcess::spawn(profile)?,
            identity,
            session: ProcessProtocolSession::new(identity),
            host_sequence: 0,
            receive_buffer: Vec::with_capacity(PROCESS_WORKER_HEADER_BYTES),
            expected_frame_length: None,
            max_retained_bytes: None,
            delivered_payload_bytes: Arc::new(AtomicU64::new(0)),
            poisoned: false,
        })
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> ProcessProtocolPhase {
        self.session.phase()
    }

    #[must_use]
    pub(crate) fn active_invocations(&self) -> usize {
        self.session.active_invocations()
    }

    #[must_use]
    pub(crate) fn retained_bytes(&self) -> u64 {
        self.session
            .retained_bytes()
            .saturating_add(self.delivered_payload_bytes.load(Ordering::Acquire))
    }

    #[must_use]
    pub(crate) fn delivered_payload_bytes(&self) -> u64 {
        self.delivered_payload_bytes.load(Ordering::Acquire)
    }

    #[must_use]
    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    #[must_use]
    pub(crate) const fn process(&self) -> &UnixChildProcess {
        &self.process
    }

    #[must_use]
    pub(crate) const fn process_mut(&mut self) -> &mut UnixChildProcess {
        &mut self.process
    }

    /// Conservatively commits the next protocol state before awaiting the
    /// first possible write. Cancellation therefore leaves a poisoned owner,
    /// never a reusable transport with unknowable handoff state.
    pub(crate) async fn send_host_frame(
        &mut self,
        state: ProcessWorkerState,
        invocation_id: u64,
        body: ProcessFrameBody,
    ) -> Result<(), ProcessTransportError> {
        self.require_healthy()?;
        if let ProcessFrameBody::Invoke {
            response_reservation_bytes,
            payload,
            ..
        } = &body
        {
            let request_bytes = u64::try_from(payload.len())
                .map_err(|_| ProcessTransportError::RetainedByteOverflow)?;
            let requested = request_bytes
                .checked_add(u64::from(*response_reservation_bytes))
                .ok_or(ProcessTransportError::RetainedByteOverflow)?;
            let effective = self
                .retained_bytes()
                .checked_add(requested)
                .ok_or(ProcessTransportError::RetainedByteOverflow)?;
            if self
                .max_retained_bytes
                .is_none_or(|maximum| effective > maximum)
            {
                return Err(ProcessProtocolError::RetainedBytesExceeded.into());
            }
        }
        let advertised_maximum = match &body {
            ProcessFrameBody::Start {
                max_retained_bytes, ..
            } => Some(*max_retained_bytes),
            _ => None,
        };
        let sequence = self
            .host_sequence
            .checked_add(1)
            .ok_or(ProcessTransportError::SequenceExhausted)?;
        let frame = ProcessFrame::try_new(
            self.identity,
            sequence,
            ProcessFrameDirection::HostToWorker,
            state,
            invocation_id,
            body,
        )?;
        let next = self.session.advance(&frame)?;
        self.session = next;
        self.host_sequence = sequence;
        if let Some(maximum) = advertised_maximum {
            self.max_retained_bytes = Some(maximum);
        }
        self.poisoned = true;
        let frame_length = u32::try_from(frame.canonical_wire().len())
            .map_err(|_| ProcessTransportError::InvalidFrameLength)?;
        self.process.write_all(&frame_length.to_be_bytes()).await?;
        self.process.write_all(frame.canonical_wire()).await?;
        self.poisoned = false;
        Ok(())
    }

    /// Reads one complete bounded worker frame and advances only after strict
    /// canonical decode, direction, identity, sequence, phase, and credit
    /// validation all succeed.
    pub(crate) async fn receive_worker_frame(
        &mut self,
    ) -> Result<ReceivedProcessFrame, ProcessTransportError> {
        self.require_healthy()?;
        let wire = match self.read_frame_wire().await {
            Ok(wire) => wire,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let frame = match ProcessFrame::decode(&wire) {
            Ok(frame) => frame,
            Err(error) => {
                self.poisoned = true;
                return Err(error.into());
            }
        };
        if frame.direction() != ProcessFrameDirection::WorkerToHost {
            self.poisoned = true;
            return Err(ProcessTransportError::WrongEndpointDirection);
        }
        let next = match self.session.advance(&frame) {
            Ok(next) => next,
            Err(error) => {
                self.poisoned = true;
                return Err(error.into());
            }
        };
        self.session = next;
        let charge = match frame.body() {
            ProcessFrameBody::Terminal { payload, .. } if !payload.is_empty() => {
                let bytes = u64::try_from(payload.len())
                    .map_err(|_| ProcessTransportError::RetainedByteOverflow)?;
                self.delivered_payload_bytes
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                        current.checked_add(bytes)
                    })
                    .map_err(|_| ProcessTransportError::RetainedByteOverflow)?;
                Some(RetainedPayloadCharge {
                    ledger: Arc::clone(&self.delivered_payload_bytes),
                    bytes,
                })
            }
            _ => None,
        };
        Ok(ReceivedProcessFrame { frame, charge })
    }

    fn require_healthy(&self) -> Result<(), ProcessTransportError> {
        if self.poisoned {
            Err(ProcessTransportError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Stream reads are cancellation-safe: every byte returned by the OS is
    /// committed to owner state before the next await. A deadline may stop
    /// waiting and later resume the same partial frame without desynchronizing
    /// the stream or preventing a host-side Cancel frame.
    async fn read_frame_wire(&mut self) -> Result<Box<[u8]>, ProcessTransportError> {
        loop {
            if self.expected_frame_length.is_none()
                && self.receive_buffer.len() == STREAM_LENGTH_BYTES
            {
                let total_length = usize::try_from(u32::from_be_bytes(
                    self.receive_buffer[..STREAM_LENGTH_BYTES]
                        .try_into()
                        .map_err(|_| ProcessTransportError::InvalidFramePrefix)?,
                ))
                .map_err(|_| ProcessTransportError::InvalidFramePrefix)?;
                if !(PROCESS_WORKER_HEADER_BYTES..=MAX_PROCESS_WORKER_FRAME_BYTES)
                    .contains(&total_length)
                {
                    return Err(ProcessTransportError::InvalidFrameLength);
                }
                self.receive_buffer.clear();
                self.receive_buffer.reserve(total_length);
                self.expected_frame_length = Some(total_length);
            }

            if let Some(expected) = self.expected_frame_length
                && self.receive_buffer.len() == expected
            {
                self.expected_frame_length = None;
                return Ok(core::mem::take(&mut self.receive_buffer).into_boxed_slice());
            }

            let target = self.expected_frame_length.unwrap_or(STREAM_LENGTH_BYTES);
            let remaining = target
                .checked_sub(self.receive_buffer.len())
                .ok_or(ProcessTransportError::InvalidFrameLength)?;
            let mut chunk = [0_u8; 8 * 1024];
            let requested = remaining.min(chunk.len());
            let read = self.process.read(&mut chunk[..requested]).await?;
            if read == 0 {
                return Err(ProcessPlatformError::UnexpectedEof.into());
            }
            self.receive_buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

/// Non-cloneable worker frame. Terminal bytes remain charged after the PXWP
/// credit is released and until this owner (or a transferred terminal value)
/// is dropped.
#[derive(Debug)]
pub(crate) struct ReceivedProcessFrame {
    frame: ProcessFrame,
    charge: Option<RetainedPayloadCharge>,
}

impl ReceivedProcessFrame {
    #[must_use]
    pub(crate) const fn sequence(&self) -> u64 {
        self.frame.sequence()
    }

    #[must_use]
    pub(crate) const fn invocation_id(&self) -> u64 {
        self.frame.invocation_id()
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> ProcessFrameKind {
        self.frame.kind()
    }

    #[must_use]
    pub(crate) fn ready_runtime_digest(&self) -> Option<Digest32> {
        match self.frame.body() {
            ProcessFrameBody::Ready {
                worker_runtime_digest,
            } => Some(*worker_runtime_digest),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) fn constructed_outcome(&self) -> Option<ConstructOutcome> {
        match self.frame.body() {
            ProcessFrameBody::Constructed { outcome } => Some(*outcome),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) fn invoked_credit(&self) -> Option<u64> {
        match self.frame.body() {
            ProcessFrameBody::Invoked { credit_id } => Some(*credit_id),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) fn heartbeat(&self) -> Option<(u64, u32, u64)> {
        match self.frame.body() {
            ProcessFrameBody::Heartbeat {
                heartbeat_sequence,
                active_invocations,
                retained_bytes,
            } => Some((*heartbeat_sequence, *active_invocations, *retained_bytes)),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) fn stopped_outcome(&self) -> Option<StoppedOutcome> {
        match self.frame.body() {
            ProcessFrameBody::Stopped { outcome } => Some(*outcome),
            _ => None,
        }
    }

    pub(crate) fn into_terminal(mut self) -> Option<ReceivedTerminal> {
        let (invocation_id, credit_id, kind, payload) =
            self.frame.into_terminal_parts()?.into_parts();
        Some(ReceivedTerminal {
            invocation_id,
            credit_id,
            kind,
            payload,
            _charge: self.charge.take(),
        })
    }

    #[cfg(test)]
    fn canonical_wire(&self) -> &[u8] {
        self.frame.canonical_wire()
    }
}

/// Terminal callback bytes with a non-cloneable retained-byte charge.
#[derive(Debug)]
pub(crate) struct ReceivedTerminal {
    invocation_id: u64,
    credit_id: u64,
    kind: InvocationTerminalKind,
    payload: Box<[u8]>,
    _charge: Option<RetainedPayloadCharge>,
}

impl ReceivedTerminal {
    #[must_use]
    pub(crate) const fn invocation_id(&self) -> u64 {
        self.invocation_id
    }

    #[must_use]
    pub(crate) const fn credit_id(&self) -> u64 {
        self.credit_id
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> InvocationTerminalKind {
        self.kind
    }

    #[must_use]
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Debug)]
struct RetainedPayloadCharge {
    ledger: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for RetainedPayloadCharge {
    fn drop(&mut self) {
        let previous = self.ledger.fetch_sub(self.bytes, Ordering::AcqRel);
        debug_assert!(previous >= self.bytes, "terminal payload charge underflow");
    }
}

#[derive(Debug)]
pub(crate) enum ProcessTransportError {
    Poisoned,
    SequenceExhausted,
    InvalidFramePrefix,
    InvalidFrameLength,
    WrongEndpointDirection,
    RetainedByteOverflow,
    Platform(ProcessPlatformError),
    Protocol(ProcessProtocolError),
}

impl From<ProcessPlatformError> for ProcessTransportError {
    fn from(value: ProcessPlatformError) -> Self {
        Self::Platform(value)
    }
}

impl From<ProcessProtocolError> for ProcessTransportError {
    fn from(value: ProcessProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl fmt::Display for ProcessTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => formatter.write_str("process transport is poisoned"),
            Self::SequenceExhausted => formatter.write_str("process host sequence is exhausted"),
            Self::InvalidFramePrefix => formatter.write_str("process frame prefix is invalid"),
            Self::InvalidFrameLength => {
                formatter.write_str("process frame length is out of bounds")
            }
            Self::WrongEndpointDirection => {
                formatter.write_str("worker transport received a host-direction frame")
            }
            Self::RetainedByteOverflow => {
                formatter.write_str("delivered process payload charge overflowed")
            }
            Self::Platform(error) => write!(formatter, "{error}"),
            Self::Protocol(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ProcessTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};

    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_runtime_contracts::assignment::InstanceRef;
    use paraegox_runtime_contracts::process_execution::ProcessDomainRef;
    use paraegox_runtime_contracts::process_protocol::ProcessSessionGenerations;
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};
    use tokio::time::{Duration, timeout};

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestArea(PathBuf);

    impl TestArea {
        fn create() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "paraegox-process-transport-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test area should be unique");
            Self(path)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).expect("test response should be writable");
            path
        }
    }

    impl Drop for TestArea {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("test area should be removable");
        }
    }

    fn identity() -> ProcessSessionIdentity {
        ProcessSessionIdentity::try_new(
            RuntimeHostId::from_bytes([1; 16]),
            ProcessDomainRef::from_bytes([3; 16]),
            InstanceRef::from_bytes([5; 16]),
            ProcessSessionGenerations::try_new(2, 4, 6)
                .expect("session generations should be valid"),
            SourcePlanRevision::new(7),
            TargetSliceDigest::new(Digest32::from_bytes([8; 32])),
        )
        .expect("session identity should be valid")
    }

    fn start_body() -> ProcessFrameBody {
        ProcessFrameBody::Start {
            max_inflight: 1,
            max_retained_bytes: 4096,
            max_payload_bytes: 1024,
            heartbeat_interval_nanos: 1_000_000,
            heartbeat_timeout_nanos: 5_000_000,
        }
    }

    fn shell_profile(
        workspace: &Path,
        script: &str,
        environment: Vec<(OsString, OsString)>,
    ) -> ResolvedProcessLaunch {
        ResolvedProcessLaunch::try_new_for_test(
            PathBuf::from("/bin/sh"),
            vec![OsString::from("-c"), OsString::from(script)],
            environment,
            workspace.to_path_buf(),
        )
        .expect("shell profile should be valid")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn framed_transport_advances_only_a_valid_worker_dialogue() {
        let area = TestArea::create();
        let identity = identity();
        let start = ProcessFrame::try_new(
            identity,
            1,
            ProcessFrameDirection::HostToWorker,
            ProcessWorkerState::Starting,
            0,
            start_body(),
        )
        .expect("start frame should build");
        let ready = ProcessFrame::try_new(
            identity,
            1,
            ProcessFrameDirection::WorkerToHost,
            ProcessWorkerState::Starting,
            0,
            ProcessFrameBody::Ready {
                worker_runtime_digest: Digest32::from_bytes([9; 32]),
            },
        )
        .expect("ready frame should build");
        let mut response_wire = u32::try_from(ready.canonical_wire().len())
            .expect("ready length should fit")
            .to_be_bytes()
            .to_vec();
        response_wire.extend_from_slice(ready.canonical_wire());
        let response = area.file("ready.pxwp", &response_wire);
        let profile = shell_profile(
            &area.0,
            "/bin/dd bs=1 count=\"$READ_BYTES\" of=/dev/null 2>/dev/null; /bin/cat \"$RESPONSE\"",
            vec![
                (
                    OsString::from("READ_BYTES"),
                    OsString::from(
                        (STREAM_LENGTH_BYTES + start.canonical_wire().len()).to_string(),
                    ),
                ),
                (OsString::from("RESPONSE"), response.into_os_string()),
            ],
        );
        let mut transport =
            ProcessTransport::spawn(&profile, identity).expect("worker transport should launch");

        transport
            .send_host_frame(ProcessWorkerState::Starting, 0, start_body())
            .await
            .expect("start should be written");
        let received = transport
            .receive_worker_frame()
            .await
            .expect("ready should be accepted");

        assert_eq!(received.canonical_wire(), ready.canonical_wire());
        assert_eq!(transport.phase(), ProcessProtocolPhase::AwaitConstruct);
        assert!(!transport.is_poisoned());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_advertised_frame_is_rejected_before_allocation() {
        let area = TestArea::create();
        let prefix = u32::try_from(MAX_PROCESS_WORKER_FRAME_BYTES + 1)
            .expect("test length should fit")
            .to_be_bytes();
        let response = area.file("oversized-prefix.pxwp", &prefix);
        let profile = shell_profile(
            &area.0,
            "/bin/cat \"$RESPONSE\"; while :; do :; done",
            vec![(OsString::from("RESPONSE"), response.into_os_string())],
        );
        let mut transport =
            ProcessTransport::spawn(&profile, identity()).expect("transport should launch");
        transport
            .send_host_frame(ProcessWorkerState::Starting, 0, start_body())
            .await
            .expect("small start frame should fit the pipe");

        let error = transport
            .receive_worker_frame()
            .await
            .expect_err("oversized frame must fail closed");

        assert!(matches!(error, ProcessTransportError::InvalidFrameLength));
        assert!(transport.is_poisoned());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delivered_terminal_payload_remains_charged_until_its_owner_drops() {
        let area = TestArea::create();
        let identity = identity();
        let frames = [
            ProcessFrame::try_new(
                identity,
                1,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Starting,
                0,
                ProcessFrameBody::Ready {
                    worker_runtime_digest: Digest32::from_bytes([9; 32]),
                },
            )
            .expect("ready frame should build"),
            ProcessFrame::try_new(
                identity,
                2,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Constructing,
                0,
                ProcessFrameBody::Constructed {
                    outcome: ConstructOutcome::Constructed,
                },
            )
            .expect("constructed frame should build"),
            ProcessFrame::try_new(
                identity,
                3,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Invoked { credit_id: 71 },
            )
            .expect("invoked frame should build"),
            ProcessFrame::try_new(
                identity,
                4,
                ProcessFrameDirection::WorkerToHost,
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Terminal {
                    credit_id: 71,
                    kind: InvocationTerminalKind::Completed,
                    payload: Box::from(&b"done"[..]),
                },
            )
            .expect("terminal frame should build"),
        ];
        let mut response_wire = Vec::new();
        for frame in &frames {
            response_wire.extend_from_slice(
                &u32::try_from(frame.canonical_wire().len())
                    .expect("frame length should fit")
                    .to_be_bytes(),
            );
            response_wire.extend_from_slice(frame.canonical_wire());
        }
        let response = area.file("terminal.pxwp", &response_wire);
        let profile = shell_profile(
            &area.0,
            "/bin/cat \"$RESPONSE\"; /bin/cat >/dev/null",
            vec![(OsString::from("RESPONSE"), response.into_os_string())],
        );
        let mut transport =
            ProcessTransport::spawn(&profile, identity).expect("worker transport should launch");

        transport
            .send_host_frame(ProcessWorkerState::Starting, 0, start_body())
            .await
            .expect("start should be written");
        transport
            .receive_worker_frame()
            .await
            .expect("ready should be accepted");
        transport
            .send_host_frame(
                ProcessWorkerState::Constructing,
                0,
                ProcessFrameBody::Construct {
                    artifact_digest: Digest32::from_bytes([11; 32]),
                    config_digest: Digest32::from_bytes([12; 32]),
                    entrypoint_ref:
                        paraegox_runtime_contracts::process_execution::ProcessEntrypointRef::from_bytes(
                            [13; 16],
                        ),
                },
            )
            .await
            .expect("construct should be written");
        transport
            .receive_worker_frame()
            .await
            .expect("constructed should be accepted");
        transport
            .send_host_frame(
                ProcessWorkerState::Running,
                41,
                ProcessFrameBody::Invoke {
                    credit_id: 71,
                    response_reservation_bytes: 5,
                    remaining_budget_nanos: 1_000_000,
                    payload: Box::from(&b"ask"[..]),
                },
            )
            .await
            .expect("invoke should be written");
        transport
            .receive_worker_frame()
            .await
            .expect("invoked should be accepted");
        let terminal = transport
            .receive_worker_frame()
            .await
            .expect("terminal should be accepted")
            .into_terminal()
            .expect("frame should carry terminal ownership");

        assert_eq!(terminal.invocation_id(), 41);
        assert_eq!(terminal.credit_id(), 71);
        assert_eq!(terminal.kind(), InvocationTerminalKind::Completed);
        assert_eq!(terminal.payload(), b"done");
        assert_eq!(transport.active_invocations(), 0);
        assert_eq!(transport.retained_bytes(), 4);

        drop(terminal);
        assert_eq!(transport.retained_bytes(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_partial_read_resumes_the_same_frame() {
        let area = TestArea::create();
        let identity = identity();
        let ready = ProcessFrame::try_new(
            identity,
            1,
            ProcessFrameDirection::WorkerToHost,
            ProcessWorkerState::Starting,
            0,
            ProcessFrameBody::Ready {
                worker_runtime_digest: Digest32::from_bytes([9; 32]),
            },
        )
        .expect("ready frame should build");
        let mut response_wire = u32::try_from(ready.canonical_wire().len())
            .expect("ready length should fit")
            .to_be_bytes()
            .to_vec();
        response_wire.extend_from_slice(ready.canonical_wire());
        let response = area.file("split-ready.pxwp", &response_wire);
        let profile = shell_profile(
            &area.0,
            "/bin/dd if=\"$RESPONSE\" bs=1 count=2 2>/dev/null; /bin/sleep 0.05; /bin/dd if=\"$RESPONSE\" bs=1 skip=2 2>/dev/null",
            vec![(OsString::from("RESPONSE"), response.into_os_string())],
        );
        let mut transport =
            ProcessTransport::spawn(&profile, identity).expect("transport should launch");
        transport
            .send_host_frame(ProcessWorkerState::Starting, 0, start_body())
            .await
            .expect("small start frame should fit the pipe");

        timeout(Duration::from_millis(10), transport.receive_worker_frame())
            .await
            .expect_err("only a partial prefix should be available");
        assert!(!transport.is_poisoned());

        let resumed = timeout(Duration::from_secs(1), transport.receive_worker_frame())
            .await
            .expect("remaining bytes should arrive")
            .expect("the buffered frame should remain valid");

        assert_eq!(resumed.canonical_wire(), ready.canonical_wire());
        assert_eq!(transport.phase(), ProcessProtocolPhase::AwaitConstruct);
    }
}
