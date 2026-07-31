//! Rust PXWP v1 reference worker used by cross-process system evidence.
//!
//! This executable owns no Runtime or recovery policy. It is a deliberately
//! small subordinate that validates every host frame with the canonical PXWP
//! decoder/session and emits only canonical worker frames.

use std::fmt;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use paraegox_kernel::digest::Digest32;
use paraegox_runtime_contracts::process_protocol::{
    ConstructOutcome, InvocationTerminalKind, MAX_PROCESS_WORKER_FRAME_BYTES,
    PROCESS_WORKER_HEADER_BYTES, ProcessFrame, ProcessFrameBody, ProcessFrameDirection,
    ProcessFrameKind, ProcessProtocolError, ProcessProtocolSession, ProcessSessionIdentity,
    ProcessWorkerState,
};

const WORKER_RUNTIME_DIGEST: Digest32 = Digest32::from_bytes([0x52; 32]);
const FAULT_EXIT_CODE: u8 = 70;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultMode {
    None,
    PartialInvoked,
    PartialTerminal,
}

impl FaultMode {
    fn parse() -> Result<Self, WorkerError> {
        let mut arguments = std::env::args().skip(1);
        let Some(first) = arguments.next() else {
            return Ok(Self::None);
        };
        if first != "--fault" {
            return Err(WorkerError::Arguments);
        }
        let fault = match arguments.next().as_deref() {
            Some("partial-invoked") => Self::PartialInvoked,
            Some("partial-terminal") => Self::PartialTerminal,
            _ => return Err(WorkerError::Arguments),
        };
        if arguments.next().is_some() {
            return Err(WorkerError::Arguments);
        }
        Ok(fault)
    }
}

#[derive(Debug)]
enum WorkerError {
    Arguments,
    EndOfInput,
    Io(io::Error),
    Protocol(ProcessProtocolError),
    UnexpectedHostFrame(ProcessFrameKind),
}

impl From<io::Error> for WorkerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProcessProtocolError> for WorkerError {
    fn from(error: ProcessProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments => formatter.write_str(
                "usage: paraegox-rust-reference-worker [--fault partial-invoked|partial-terminal]",
            ),
            Self::EndOfInput => formatter.write_str("host closed PXWP input before Stop"),
            Self::Io(error) => write!(formatter, "PXWP worker I/O failed: {error}"),
            Self::Protocol(error) => write!(formatter, "PXWP worker rejected a frame: {error}"),
            Self::UnexpectedHostFrame(kind) => {
                write!(
                    formatter,
                    "PXWP worker received unsupported host frame {kind:?}"
                )
            }
        }
    }
}

struct WorkerSession {
    identity: ProcessSessionIdentity,
    protocol: ProcessProtocolSession,
    worker_sequence: u64,
    fault: FaultMode,
}

impl WorkerSession {
    fn start(frame: &ProcessFrame, fault: FaultMode) -> Result<Self, WorkerError> {
        if frame.kind() != ProcessFrameKind::Start {
            return Err(WorkerError::UnexpectedHostFrame(frame.kind()));
        }
        let identity = frame.identity();
        let protocol = ProcessProtocolSession::new(identity).advance(frame)?;
        Ok(Self {
            identity,
            protocol,
            worker_sequence: 0,
            fault,
        })
    }

    fn accept_host(&mut self, frame: &ProcessFrame) -> Result<(), WorkerError> {
        self.protocol = self.protocol.advance(frame)?;
        Ok(())
    }

    fn worker_frame(
        &mut self,
        state: ProcessWorkerState,
        invocation_id: u64,
        body: ProcessFrameBody,
    ) -> Result<ProcessFrame, WorkerError> {
        self.worker_sequence = self
            .worker_sequence
            .checked_add(1)
            .ok_or(ProcessProtocolError::IntegerOverflow)?;
        let frame = ProcessFrame::try_new(
            self.identity,
            self.worker_sequence,
            ProcessFrameDirection::WorkerToHost,
            state,
            invocation_id,
            body,
        )?;
        self.protocol = self.protocol.advance(&frame)?;
        Ok(frame)
    }
}

fn read_frame(input: &mut impl Read) -> Result<ProcessFrame, WorkerError> {
    let mut length_prefix = [0_u8; 4];
    if let Err(error) = input.read_exact(&mut length_prefix) {
        return if error.kind() == io::ErrorKind::UnexpectedEof {
            Err(WorkerError::EndOfInput)
        } else {
            Err(WorkerError::Io(error))
        };
    }
    let total_length = usize::try_from(u32::from_be_bytes(length_prefix))
        .map_err(|_| ProcessProtocolError::IntegerOverflow)?;
    if total_length < PROCESS_WORKER_HEADER_BYTES {
        return Err(WorkerError::Protocol(
            ProcessProtocolError::InvalidFrameLength,
        ));
    }
    if total_length > MAX_PROCESS_WORKER_FRAME_BYTES {
        return Err(WorkerError::Protocol(ProcessProtocolError::FrameTooLarge));
    }
    let mut wire = vec![0_u8; total_length];
    input.read_exact(&mut wire)?;
    Ok(ProcessFrame::decode(&wire)?)
}

fn write_frame(output: &mut impl Write, frame: &ProcessFrame) -> Result<(), WorkerError> {
    let wire = frame.canonical_wire();
    let length = u32::try_from(wire.len()).map_err(|_| ProcessProtocolError::IntegerOverflow)?;
    output.write_all(&length.to_be_bytes())?;
    output.write_all(wire)?;
    output.flush()?;
    Ok(())
}

fn write_partial_frame(output: &mut impl Write, frame: &ProcessFrame) -> Result<(), WorkerError> {
    let wire = frame.canonical_wire();
    let partial_length = wire.len() / 2;
    let length = u32::try_from(wire.len()).map_err(|_| ProcessProtocolError::IntegerOverflow)?;
    output.write_all(&length.to_be_bytes())?;
    output.write_all(&wire[..partial_length])?;
    output.flush()?;
    Ok(())
}

fn serve(fault: FaultMode) -> Result<bool, WorkerError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();

    let start = read_frame(&mut input)?;
    let mut session = WorkerSession::start(&start, fault)?;
    let ready = session.worker_frame(
        ProcessWorkerState::Starting,
        0,
        ProcessFrameBody::Ready {
            worker_runtime_digest: WORKER_RUNTIME_DIGEST,
        },
    )?;
    write_frame(&mut output, &ready)?;

    loop {
        let host = read_frame(&mut input)?;
        let invocation_id = host.invocation_id();
        let response = match host.body() {
            ProcessFrameBody::Construct { .. } => {
                session.accept_host(&host)?;
                session.worker_frame(
                    ProcessWorkerState::Constructing,
                    0,
                    ProcessFrameBody::Constructed {
                        outcome: ConstructOutcome::Constructed,
                    },
                )?
            }
            ProcessFrameBody::Invoke {
                credit_id, payload, ..
            } => {
                let credit_id = *credit_id;
                let payload = payload.clone();
                session.accept_host(&host)?;
                let invoked = session.worker_frame(
                    ProcessWorkerState::Running,
                    invocation_id,
                    ProcessFrameBody::Invoked { credit_id },
                )?;
                if session.fault == FaultMode::PartialInvoked {
                    write_partial_frame(&mut output, &invoked)?;
                    return Ok(true);
                }
                write_frame(&mut output, &invoked)?;
                let terminal = session.worker_frame(
                    ProcessWorkerState::Running,
                    invocation_id,
                    ProcessFrameBody::Terminal {
                        credit_id,
                        kind: InvocationTerminalKind::Completed,
                        payload,
                    },
                )?;
                if session.fault == FaultMode::PartialTerminal {
                    write_partial_frame(&mut output, &terminal)?;
                    return Ok(true);
                }
                write_frame(&mut output, &terminal)?;
                continue;
            }
            ProcessFrameBody::StopAccepting => {
                session.accept_host(&host)?;
                session.worker_frame(ProcessWorkerState::Draining, 0, ProcessFrameBody::Drained)?
            }
            ProcessFrameBody::Stop { .. } => {
                session.accept_host(&host)?;
                let stopped = session.worker_frame(
                    ProcessWorkerState::Stopped,
                    0,
                    ProcessFrameBody::Stopped {
                        outcome:
                            paraegox_runtime_contracts::process_protocol::StoppedOutcome::Clean,
                    },
                )?;
                write_frame(&mut output, &stopped)?;
                return Ok(false);
            }
            ProcessFrameBody::Ping { nonce } => {
                let nonce = *nonce;
                session.accept_host(&host)?;
                session.worker_frame(host.state(), 0, ProcessFrameBody::Pong { nonce })?
            }
            _ => return Err(WorkerError::UnexpectedHostFrame(host.kind())),
        };
        write_frame(&mut output, &response)?;
    }
}

fn main() -> ExitCode {
    let fault = match FaultMode::parse() {
        Ok(fault) => fault,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(64);
        }
    };
    match serve(fault) {
        Ok(true) => ExitCode::from(FAULT_EXIT_CODE),
        Ok(false) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(65)
        }
    }
}
