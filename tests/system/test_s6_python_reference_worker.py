from __future__ import annotations

import errno
import os
import select
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

import pytest

from paraegox_sdk.worker.protocol import (
    CancelBody,
    ConstructBody,
    ConstructedBody,
    ConstructOutcome,
    Direction,
    DrainedBody,
    Frame,
    FrameBody,
    HeartbeatBody,
    InvokeBody,
    InvokedBody,
    PingBody,
    PongBody,
    ProtocolError,
    ReadyBody,
    SessionIdentity,
    StartBody,
    StopAcceptingBody,
    StopBody,
    StoppedBody,
    StopReason,
    TerminalBody,
    TerminalKind,
    WorkerState,
    encode_packet,
    read_frame,
    write_frame,
)
from paraegox_sdk.worker.runner import (
    FAULT_CRASH_EXIT,
    FAULT_PARTIAL_FRAME_EXIT,
    MEMORY_PRESSURE_BYTES,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="ProcessDomain baseline is POSIX"
)  # GOV-WAIVER-0003


def _identity() -> SessionIdentity:
    return SessionIdentity(
        b"\x11" * 16,
        7,
        b"\x22" * 16,
        9,
        b"\x33" * 16,
        3,
        5,
        b"\x44" * 32,
    )


def _host_frame(
    sequence: int,
    state: WorkerState,
    body: FrameBody,
    invocation_id: int = 0,
) -> Frame:
    return Frame(
        _identity(),
        sequence,
        Direction.HOST_TO_WORKER,
        state,
        invocation_id,
        body,
    )


@contextmanager
def _worker(*arguments: str) -> Iterator[subprocess.Popen[bytes]]:
    process = subprocess.Popen(
        [sys.executable, "-m", "paraegox_sdk.worker", *arguments],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        start_new_session=True,
        close_fds=True,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=3)


def _pipes(process: subprocess.Popen[bytes]) -> tuple[BinaryIO, BinaryIO]:
    assert process.stdin is not None
    assert process.stdout is not None
    return process.stdin, process.stdout


def _read_timeout(process: subprocess.Popen[bytes], timeout: float = 2.0) -> Frame:
    _, stdout = _pipes(process)
    readable, _, _ = select.select([stdout], [], [], timeout)
    if not readable:
        stderr = b""
        if process.poll() is not None and process.stderr is not None:
            stderr = process.stderr.read()
        pytest.fail(f"worker produced no frame; status={process.poll()} stderr={stderr!r}")
    frame = read_frame(stdout)
    assert frame is not None
    return frame


def _assert_no_output(process: subprocess.Popen[bytes], timeout: float) -> None:
    _, stdout = _pipes(process)
    readable, _, _ = select.select([stdout], [], [], timeout)
    assert readable == []


def _start_and_construct(
    process: subprocess.Popen[bytes],
    *,
    heartbeat_interval_nanos: int = 1_000_000_000,
) -> None:
    stdin, _ = _pipes(process)
    write_frame(
        stdin,
        _host_frame(
            1,
            WorkerState.STARTING,
            StartBody(2, 128, 64, heartbeat_interval_nanos, heartbeat_interval_nanos * 3),
        ),
    )
    ready = _read_timeout(process)
    assert ready.sequence == 1
    assert isinstance(ready.body, ReadyBody)
    write_frame(
        stdin,
        _host_frame(
            2,
            WorkerState.CONSTRUCTING,
            ConstructBody(b"\x66" * 32, b"\x77" * 32, b"\x88" * 16),
        ),
    )
    constructed = _read_timeout(process)
    assert constructed.sequence == 2
    assert constructed.body == ConstructedBody(ConstructOutcome.CONSTRUCTED)


def _graceful_stop(
    process: subprocess.Popen[bytes],
    *,
    host_sequence: int,
    next_worker_sequence: int,
) -> None:
    stdin, _ = _pipes(process)
    write_frame(
        stdin,
        _host_frame(host_sequence, WorkerState.DRAINING, StopAcceptingBody()),
    )
    deadline = time.monotonic() + 2
    while True:
        drained = _read_timeout(process, deadline - time.monotonic())
        assert drained.sequence == next_worker_sequence
        next_worker_sequence += 1
        if isinstance(drained.body, DrainedBody):
            break
        assert isinstance(drained.body, HeartbeatBody)
        assert drained.body.active_invocations == 0
        assert drained.body.retained_bytes == 0
    write_frame(
        stdin,
        _host_frame(host_sequence + 1, WorkerState.STOPPING, StopBody(StopReason.PLANNED)),
    )
    stopped = _read_timeout(process)
    assert stopped.sequence == next_worker_sequence
    assert isinstance(stopped.body, StoppedBody)
    assert process.wait(timeout=2) == 0


def _wait_pid_file(path: Path, timeout: float = 2.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.read_text(encoding="ascii").strip():
            return int(path.read_text(encoding="ascii").strip())
        time.sleep(0.01)
    pytest.fail("grandchild PID file was not written")


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError as error:
        return error.errno == errno.EPERM
    return True


def _wait_pid_gone(pid: int, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_exists(pid):
            return
        time.sleep(0.01)
    pytest.fail(f"PID {pid} leaked after process-group cleanup")


def test_cli_is_installed_and_exposes_only_reference_worker_controls() -> None:
    installed_cli = Path(sys.executable).with_name("paraegox-worker")
    assert installed_cli.is_file()
    completed = subprocess.run(
        [installed_cli, "--help"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "subordinate PXWP v1" in completed.stdout
    assert "--fault" in completed.stdout
    assert "stale-generation" in completed.stdout
    assert "memory-pressure" in completed.stdout
    assert "restart" not in completed.stdout.lower()
    assert "readiness" not in completed.stdout.lower()


def test_rust_process_domain_owns_real_python_worker_fault_matrix() -> None:
    environment = dict(os.environ)
    environment["PARAEGOX_PYTHON"] = sys.executable
    completed = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "paraegox-runtime",
            "process_domain::tests::python_reference_worker_round_trips_through_rust_process_domain",
            "--",
            "--ignored",
            "--exact",
        ],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_real_child_completes_heartbeat_ping_invoke_ack_terminal_and_shutdown() -> None:
    with _worker() as process:
        _start_and_construct(process, heartbeat_interval_nanos=200_000_000)
        heartbeat = _read_timeout(process)
        assert heartbeat.sequence == 3
        assert heartbeat.body == HeartbeatBody(1, 0, 0)

        stdin, _ = _pipes(process)
        write_frame(stdin, _host_frame(3, WorkerState.RUNNING, PingBody(91)))
        pong = _read_timeout(process)
        assert pong.sequence == 4
        assert pong.body == PongBody(91)

        write_frame(
            stdin,
            _host_frame(
                4,
                WorkerState.RUNNING,
                InvokeBody(71, 16, 10_000, b"input"),
                41,
            ),
        )
        invoked = _read_timeout(process)
        assert invoked.sequence == 5
        assert invoked.body == InvokedBody(71)
        assert invoked.invocation_id == 41
        terminal = _read_timeout(process)
        assert terminal.sequence == 6
        assert terminal.body == TerminalBody(71, TerminalKind.COMPLETED, b"input")
        _graceful_stop(process, host_sequence=5, next_worker_sequence=7)


def test_cancel_releases_credit_and_returns_cancelled_terminal() -> None:
    with _worker("--invoke-delay-ms", "500") as process:
        _start_and_construct(process)
        stdin, _ = _pipes(process)
        pipelined = encode_packet(
            _host_frame(
                3,
                WorkerState.RUNNING,
                InvokeBody(71, 16, 10_000, b"input"),
                41,
            )
        ) + encode_packet(_host_frame(4, WorkerState.RUNNING, CancelBody(71, 100_000), 41))
        assert os.write(stdin.fileno(), pipelined) == len(pipelined)
        invoked = _read_timeout(process)
        assert invoked.sequence == 3
        assert invoked.body == InvokedBody(71)
        terminal = _read_timeout(process)
        assert terminal.sequence == 4
        assert terminal.body == TerminalBody(71, TerminalKind.CANCELLED_BEFORE_RUN, b"")
        _graceful_stop(process, host_sequence=5, next_worker_sequence=5)


def test_crash_fault_exits_during_an_active_invocation() -> None:
    with _worker("--fault", "crash") as process:
        _start_and_construct(process)
        stdin, _ = _pipes(process)
        write_frame(
            stdin,
            _host_frame(3, WorkerState.RUNNING, InvokeBody(71, 16, 10_000, b"x"), 41),
        )
        assert process.wait(timeout=2) == FAULT_CRASH_EXIT


def test_stale_generation_fault_uses_an_old_domain_epoch_on_first_worker_frame() -> None:
    with _worker("--fault", "stale-generation") as process:
        stdin, _ = _pipes(process)
        write_frame(
            stdin,
            _host_frame(
                1,
                WorkerState.STARTING,
                StartBody(2, 128, 64, 1_000_000_000, 3_000_000_000),
            ),
        )
        stale_ready = _read_timeout(process)
        assert isinstance(stale_ready.body, ReadyBody)
        assert stale_ready.identity.process_domain_epoch == _identity().process_domain_epoch - 1
        assert stale_ready.identity != _identity()
        assert process.poll() is None


def test_memory_pressure_fault_is_bounded_and_keeps_heartbeating() -> None:
    assert MEMORY_PRESSURE_BYTES == 96 * 1_024 * 1_024
    with _worker("--fault", "memory-pressure") as process:
        _start_and_construct(process, heartbeat_interval_nanos=50_000_000)
        heartbeat = _read_timeout(process)
        assert heartbeat.sequence == 3
        assert heartbeat.body == HeartbeatBody(1, 0, 0)
        assert process.poll() is None
        _graceful_stop(process, host_sequence=3, next_worker_sequence=4)


def test_block_fault_stops_reading_and_ignores_cancel_until_host_kills_group() -> None:
    with _worker("--fault", "block") as process:
        _start_and_construct(process)
        stdin, _ = _pipes(process)
        write_frame(
            stdin,
            _host_frame(3, WorkerState.RUNNING, InvokeBody(71, 16, 10_000, b"x"), 41),
        )
        write_frame(stdin, _host_frame(4, WorkerState.RUNNING, CancelBody(71, 1), 41))
        invoked = _read_timeout(process)
        assert invoked.sequence == 3
        assert invoked.body == InvokedBody(71)
        _assert_no_output(process, 0.15)
        assert process.poll() is None


def test_ignore_cancel_fault_keeps_credit_and_reports_it_in_heartbeat() -> None:
    with _worker("--fault", "ignore-cancel") as process:
        _start_and_construct(process, heartbeat_interval_nanos=50_000_000)
        stdin, _ = _pipes(process)
        write_frame(
            stdin,
            _host_frame(3, WorkerState.RUNNING, InvokeBody(71, 16, 10_000, b"x"), 41),
        )
        write_frame(stdin, _host_frame(4, WorkerState.RUNNING, CancelBody(71, 1), 41))
        invoked = _read_timeout(process)
        assert invoked.sequence == 3
        assert invoked.body == InvokedBody(71)
        deadline = time.monotonic() + 1
        observed: Frame | None = None
        while time.monotonic() < deadline:
            candidate = _read_timeout(process, deadline - time.monotonic())
            assert not isinstance(candidate.body, TerminalBody)
            if isinstance(candidate.body, HeartbeatBody) and candidate.body.active_invocations == 1:
                observed = candidate
                break
        assert observed is not None
        assert observed.body == HeartbeatBody(1, 1, 17)
        assert process.poll() is None


def test_ignore_term_fault_requires_group_kill() -> None:
    with _worker("--fault", "ignore-term") as process:
        _start_and_construct(process)
        os.killpg(process.pid, signal.SIGTERM)
        time.sleep(0.1)
        assert process.poll() is None
        os.killpg(process.pid, signal.SIGKILL)
        assert process.wait(timeout=2) == -signal.SIGKILL


def test_same_group_grandchild_is_observable_and_group_kill_leaves_no_process(
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "grandchild.pid"
    with _worker(
        "--fault",
        "spawn-grandchild",
        "--grandchild-pid-file",
        str(pid_file),
    ) as process:
        grandchild_pid = _wait_pid_file(pid_file)
        assert os.getpgid(process.pid) == process.pid
        assert os.getpgid(grandchild_pid) == process.pid
        os.killpg(process.pid, signal.SIGKILL)
        assert process.wait(timeout=2) == -signal.SIGKILL
        _wait_pid_gone(grandchild_pid)


def test_partial_frame_fault_emits_declared_length_then_eof() -> None:
    with _worker("--fault", "partial-frame") as process:
        stdin, stdout = _pipes(process)
        write_frame(
            stdin,
            _host_frame(
                1,
                WorkerState.STARTING,
                StartBody(2, 128, 64, 1_000_000_000, 3_000_000_000),
            ),
        )
        with pytest.raises(ProtocolError, match="mid-frame"):
            read_frame(stdout)
        assert process.wait(timeout=2) == FAULT_PARTIAL_FRAME_EXIT


def test_malformed_stream_exits_nonzero_without_emitting_protocol_bytes() -> None:
    with _worker() as process:
        stdin, _ = _pipes(process)
        stdin.write(b"\0\0\0\0")
        stdin.flush()
        assert process.wait(timeout=2) == 2
        assert process.stdout is not None
        assert process.stdout.read() == b""
        assert process.stderr is not None
        assert b"length is zero" in process.stderr.read()
