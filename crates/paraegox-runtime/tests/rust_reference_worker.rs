//! Real-process contract evidence for the Rust PXWP reference worker.

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_runtime_contracts::assignment::InstanceRef;
use paraegox_runtime_contracts::process_execution::{ProcessDomainRef, ProcessEntrypointRef};
use paraegox_runtime_contracts::process_protocol::{
    ConstructOutcome, InvocationTerminalKind, PROCESS_WORKER_HEADER_BYTES, ProcessFrame,
    ProcessFrameBody, ProcessFrameDirection, ProcessFrameKind, ProcessProtocolSession,
    ProcessSessionGenerations, ProcessSessionIdentity, ProcessWorkerState,
};
use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};

const WORKER: &str = env!("CARGO_BIN_EXE_paraegox-rust-reference-worker");

fn identity() -> ProcessSessionIdentity {
    ProcessSessionIdentity::try_new(
        RuntimeHostId::from_bytes([0x11; 16]),
        ProcessDomainRef::from_bytes([0x22; 16]),
        InstanceRef::from_bytes([0x33; 16]),
        ProcessSessionGenerations::try_new(7, 9, 3).expect("fixture generations"),
        SourcePlanRevision::new(5),
        TargetSliceDigest::new(Digest32::from_bytes([0x44; 32])),
    )
    .expect("fixture identity")
}

fn frame(
    sequence: u64,
    direction: ProcessFrameDirection,
    state: ProcessWorkerState,
    invocation_id: u64,
    body: ProcessFrameBody,
) -> ProcessFrame {
    ProcessFrame::try_new(identity(), sequence, direction, state, invocation_id, body)
        .expect("valid fixture frame")
}

fn spawn(arguments: &[&str]) -> (Child, ChildStdin, ChildStdout) {
    let mut child = Command::new(WORKER)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Rust reference worker must spawn");
    let input = child.stdin.take().expect("worker stdin");
    let output = child.stdout.take().expect("worker stdout");
    (child, input, output)
}

fn send(input: &mut ChildStdin, session: &mut ProcessProtocolSession, value: &ProcessFrame) {
    *session = session.advance(value).expect("host frame must advance");
    let length = u32::try_from(value.canonical_wire().len()).expect("frame length fits u32");
    input
        .write_all(&length.to_be_bytes())
        .expect("host frame length write");
    input
        .write_all(value.canonical_wire())
        .expect("host frame write");
    input.flush().expect("host frame flush");
}

fn receive(output: &mut ChildStdout, session: &mut ProcessProtocolSession) -> ProcessFrame {
    let mut length_prefix = [0_u8; 4];
    output
        .read_exact(&mut length_prefix)
        .expect("worker frame length");
    let total_length =
        usize::try_from(u32::from_be_bytes(length_prefix)).expect("frame length fits usize");
    assert!(total_length >= PROCESS_WORKER_HEADER_BYTES);
    let mut wire = vec![0_u8; total_length];
    output.read_exact(&mut wire).expect("complete worker frame");
    let value = ProcessFrame::decode(&wire).expect("canonical worker frame");
    *session = session.advance(&value).expect("worker frame must advance");
    value
}

fn bootstrap(input: &mut ChildStdin, output: &mut ChildStdout) -> ProcessProtocolSession {
    let mut session = ProcessProtocolSession::new(identity());
    send(
        input,
        &mut session,
        &frame(
            1,
            ProcessFrameDirection::HostToWorker,
            ProcessWorkerState::Starting,
            0,
            ProcessFrameBody::Start {
                max_inflight: 2,
                max_retained_bytes: 128,
                max_payload_bytes: 64,
                heartbeat_interval_nanos: 1_000_000,
                heartbeat_timeout_nanos: 3_000_000,
            },
        ),
    );
    let ready = receive(output, &mut session);
    assert_eq!(ready.kind(), ProcessFrameKind::Ready);

    send(
        input,
        &mut session,
        &frame(
            2,
            ProcessFrameDirection::HostToWorker,
            ProcessWorkerState::Constructing,
            0,
            ProcessFrameBody::Construct {
                artifact_digest: Digest32::from_bytes([0x66; 32]),
                config_digest: Digest32::from_bytes([0x77; 32]),
                entrypoint_ref: ProcessEntrypointRef::from_bytes([0x88; 16]),
            },
        ),
    );
    let constructed = receive(output, &mut session);
    assert_eq!(
        constructed.body(),
        &ProcessFrameBody::Constructed {
            outcome: ConstructOutcome::Constructed
        }
    );
    session
}

fn send_invoke(input: &mut ChildStdin, session: &mut ProcessProtocolSession) {
    send(
        input,
        session,
        &frame(
            3,
            ProcessFrameDirection::HostToWorker,
            ProcessWorkerState::Running,
            41,
            ProcessFrameBody::Invoke {
                credit_id: 71,
                response_reservation_bytes: 16,
                remaining_budget_nanos: 10_000_000,
                payload: Box::from(&b"rust-echo"[..]),
            },
        ),
    );
}

fn assert_fault_exit(status: ExitStatus) {
    assert_eq!(status.code(), Some(70), "fault worker status: {status}");
}

fn assert_partial_frame(actual: &[u8], expected: &ProcessFrame) {
    assert!(
        actual.len() > 4,
        "outer length must precede a nonempty prefix"
    );
    let advertised = u32::from_be_bytes(
        actual[..4]
            .try_into()
            .expect("outer length prefix has four bytes"),
    );
    assert_eq!(
        usize::try_from(advertised).expect("advertised length fits usize"),
        expected.canonical_wire().len()
    );
    let partial = &actual[4..];
    assert_eq!(partial, &expected.canonical_wire()[..partial.len()]);
    assert!(!partial.is_empty());
    assert!(partial.len() < expected.canonical_wire().len());
}

#[test]
fn canonical_rust_worker_echoes_and_stops_cleanly() {
    let (mut child, mut input, mut output) = spawn(&[]);
    let mut session = bootstrap(&mut input, &mut output);
    send_invoke(&mut input, &mut session);

    let invoked = receive(&mut output, &mut session);
    assert_eq!(invoked.body(), &ProcessFrameBody::Invoked { credit_id: 71 });
    let terminal = receive(&mut output, &mut session);
    assert_eq!(
        terminal.body(),
        &ProcessFrameBody::Terminal {
            credit_id: 71,
            kind: InvocationTerminalKind::Completed,
            payload: Box::from(&b"rust-echo"[..]),
        }
    );
    assert_eq!(session.active_invocations(), 0);
    assert_eq!(session.retained_bytes(), 0);

    send(
        &mut input,
        &mut session,
        &frame(
            4,
            ProcessFrameDirection::HostToWorker,
            ProcessWorkerState::Draining,
            0,
            ProcessFrameBody::StopAccepting,
        ),
    );
    assert_eq!(
        receive(&mut output, &mut session).kind(),
        ProcessFrameKind::Drained
    );
    send(
        &mut input,
        &mut session,
        &frame(
            5,
            ProcessFrameDirection::HostToWorker,
            ProcessWorkerState::Stopping,
            0,
            ProcessFrameBody::Stop {
                reason: paraegox_runtime_contracts::process_protocol::StopReason::Planned,
            },
        ),
    );
    assert_eq!(
        receive(&mut output, &mut session).kind(),
        ProcessFrameKind::Stopped
    );
    drop(input);
    assert!(child.wait().expect("worker exit").success());
}

#[test]
fn partial_invoked_fault_exits_after_only_a_frame_prefix() {
    let (mut child, mut input, mut output) = spawn(&["--fault", "partial-invoked"]);
    let mut session = bootstrap(&mut input, &mut output);
    send_invoke(&mut input, &mut session);
    drop(input);

    let mut partial = Vec::new();
    output.read_to_end(&mut partial).expect("fault output");
    let expected = frame(
        3,
        ProcessFrameDirection::WorkerToHost,
        ProcessWorkerState::Running,
        41,
        ProcessFrameBody::Invoked { credit_id: 71 },
    );
    assert_partial_frame(&partial, &expected);
    assert_fault_exit(child.wait().expect("worker exit"));
}

#[test]
fn partial_terminal_fault_acks_then_exits_after_only_a_terminal_prefix() {
    let (mut child, mut input, mut output) = spawn(&["--fault", "partial-terminal"]);
    let mut session = bootstrap(&mut input, &mut output);
    send_invoke(&mut input, &mut session);
    assert_eq!(
        receive(&mut output, &mut session).kind(),
        ProcessFrameKind::Invoked
    );
    drop(input);

    let mut partial = Vec::new();
    output.read_to_end(&mut partial).expect("fault output");
    let expected = frame(
        4,
        ProcessFrameDirection::WorkerToHost,
        ProcessWorkerState::Running,
        41,
        ProcessFrameBody::Terminal {
            credit_id: 71,
            kind: InvocationTerminalKind::Completed,
            payload: Box::from(&b"rust-echo"[..]),
        },
    );
    assert_partial_frame(&partial, &expected);
    assert_fault_exit(child.wait().expect("worker exit"));
}
