"""Subordinate Python ProcessDomain reference worker.

RuntimeHost remains the lifecycle, restart, readiness, Mailbox, and process-tree
owner. This worker owns only frames and invocation bytes admitted for its exact
PXWP session. Fault modes are deterministic test hooks, never recovery policy.
"""

from __future__ import annotations

import hashlib
import os
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from .protocol import (
    MAX_FRAME_BYTES,
    CancelBody,
    ConstructBody,
    ConstructedBody,
    ConstructOutcome,
    Direction,
    DrainedBody,
    Frame,
    HeartbeatBody,
    InvokeBody,
    InvokedBody,
    PingBody,
    PongBody,
    ProtocolError,
    ProtocolErrorCode,
    ReadyBody,
    SessionIdentity,
    StartBody,
    StopAcceptingBody,
    StopBody,
    StoppedBody,
    StoppedOutcome,
    TerminalBody,
    TerminalKind,
    WorkerState,
    read_frame,
    write_frame,
)

WORKER_RUNTIME_DIGEST = hashlib.sha256(b"ParaEGOX Python reference worker PXWP v1").digest()
FAULT_CRASH_EXIT = 86
FAULT_PARTIAL_FRAME_EXIT = 87
_MINIMUM_HEARTBEAT_SECONDS = 0.001
_PARTIAL_PREFIX = 4
MEMORY_PRESSURE_BYTES = 96 * 1_024 * 1_024
_MEMORY_PAGE_BYTES = 4_096


class FaultMode(StrEnum):
    NORMAL = "normal"
    CRASH = "crash"
    BLOCK = "block"
    IGNORE_CANCEL = "ignore-cancel"
    IGNORE_TERM = "ignore-term"
    SPAWN_GRANDCHILD = "spawn-grandchild"
    PARTIAL_FRAME = "partial-frame"
    STALE_GENERATION = "stale-generation"
    MEMORY_PRESSURE = "memory-pressure"


class WorkerPhase(StrEnum):
    AWAIT_START = "await-start"
    AWAIT_CONSTRUCT = "await-construct"
    RUNNING = "running"
    DRAINING = "draining"
    AWAIT_STOP = "await-stop"
    STOPPED = "stopped"


@dataclass(slots=True)
class ActiveInvocation:
    credit_id: int
    response_reservation_bytes: int
    retained_bytes: int
    payload: bytes
    due_at: float | None


class ReferenceWorker:
    """One single-session PXWP v1 worker loop."""

    def __init__(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        *,
        fault: FaultMode = FaultMode.NORMAL,
        invoke_delay_seconds: float = 0.0,
        grandchild_pid_file: Path | None = None,
    ) -> None:
        if invoke_delay_seconds < 0:
            raise ValueError("invoke delay must not be negative")
        self._input = input_stream
        self._output = output_stream
        self._fault = fault
        self._invoke_delay = invoke_delay_seconds
        self._grandchild_pid_file = grandchild_pid_file
        self._phase = WorkerPhase.AWAIT_START
        self._identity: SessionIdentity | None = None
        self._host_sequence = 0
        self._worker_sequence = 0
        self._heartbeat_sequence = 0
        self._heartbeat_interval = 0.0
        self._next_heartbeat: float | None = None
        self._max_inflight = 0
        self._max_retained = 0
        self._max_payload = 0
        self._retained = 0
        self._active: dict[int, ActiveInvocation] = {}
        self._grandchild: subprocess.Popen[bytes] | None = None
        self._memory_pressure: bytearray | None = None
        self._partial_sent = False

    def run(self) -> int:
        self._install_fault_mode()
        selector = selectors.DefaultSelector()
        selector.register(self._input, selectors.EVENT_READ)
        try:
            while self._phase is not WorkerPhase.STOPPED:
                self._complete_due_invocations()
                self._maybe_finish_drain()
                self._maybe_heartbeat()
                if self._phase is WorkerPhase.STOPPED:
                    break
                timeout = self._next_timeout()
                events = selector.select(timeout)
                if not events:
                    continue
                frame = read_frame(self._input)
                if frame is None:
                    raise ProtocolError(
                        ProtocolErrorCode.TRUNCATED,
                        "RuntimeHost closed worker input before Stop/Stopped",
                    )
                self._accept(frame)
        finally:
            selector.close()
        return 0

    def _install_fault_mode(self) -> None:
        if self._fault is FaultMode.IGNORE_TERM:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if self._fault is FaultMode.SPAWN_GRANDCHILD:
            if os.name != "posix":
                raise RuntimeError("same-group grandchild fault mode requires POSIX")
            code = (
                "import signal,time;signal.signal(signal.SIGTERM, signal.SIG_IGN);time.sleep(300)"
            )
            self._grandchild = subprocess.Popen(
                [sys.executable, "-c", code],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=False,
            )
            if self._grandchild_pid_file is not None:
                self._grandchild_pid_file.write_text(
                    f"{self._grandchild.pid}\n",
                    encoding="ascii",
                )

    def _accept(self, frame: Frame) -> None:
        if frame.direction is not Direction.HOST_TO_WORKER:
            raise ProtocolError(
                ProtocolErrorCode.DIRECTION_MISMATCH,
                "worker received a worker-to-host frame",
            )
        expected = self._host_sequence + 1
        if frame.sequence != expected:
            raise ProtocolError(
                ProtocolErrorCode.SEQUENCE_VIOLATION,
                "host sequence is not exactly next",
            )
        if self._identity is not None and frame.identity != self._identity:
            raise ProtocolError(
                ProtocolErrorCode.IDENTITY_MISMATCH,
                "frame does not match the established worker identity",
            )
        self._transition(frame)
        self._host_sequence = frame.sequence

    def _transition(self, frame: Frame) -> None:
        body = frame.body
        if isinstance(body, StartBody) and self._phase is WorkerPhase.AWAIT_START:
            self._identity = frame.identity
            self._max_inflight = body.max_inflight
            self._max_retained = body.max_retained_bytes
            self._max_payload = body.max_payload_bytes
            self._heartbeat_interval = max(
                body.heartbeat_interval_nanos / 1_000_000_000,
                _MINIMUM_HEARTBEAT_SECONDS,
            )
            self._phase = WorkerPhase.AWAIT_CONSTRUCT
            self._send(ReadyBody(WORKER_RUNTIME_DIGEST), WorkerState.STARTING)
            return
        if isinstance(body, ConstructBody) and self._phase is WorkerPhase.AWAIT_CONSTRUCT:
            self._phase = WorkerPhase.RUNNING
            self._send(
                ConstructedBody(ConstructOutcome.CONSTRUCTED),
                WorkerState.CONSTRUCTING,
            )
            if self._fault is FaultMode.MEMORY_PRESSURE:
                self._memory_pressure = bytearray(MEMORY_PRESSURE_BYTES)
                self._memory_pressure[::_MEMORY_PAGE_BYTES] = b"\xa5" * len(
                    self._memory_pressure[::_MEMORY_PAGE_BYTES]
                )
            self._next_heartbeat = time.monotonic() + self._heartbeat_interval
            return
        if isinstance(body, InvokeBody) and self._phase is WorkerPhase.RUNNING:
            self._invoke(frame.invocation_id, body)
            return
        if isinstance(body, CancelBody) and self._phase in {
            WorkerPhase.RUNNING,
            WorkerPhase.DRAINING,
        }:
            self._cancel(frame.invocation_id, body)
            return
        if isinstance(body, PingBody) and self._phase in {
            WorkerPhase.RUNNING,
            WorkerPhase.DRAINING,
        }:
            self._send(PongBody(body.nonce), self._live_state())
            return
        if isinstance(body, StopAcceptingBody) and self._phase is WorkerPhase.RUNNING:
            self._phase = WorkerPhase.DRAINING
            self._maybe_finish_drain()
            return
        if isinstance(body, StopBody) and self._phase is WorkerPhase.AWAIT_STOP:
            self._phase = WorkerPhase.STOPPED
            self._next_heartbeat = None
            self._send(StoppedBody(StoppedOutcome.CLEAN), WorkerState.STOPPED)
            return
        raise ProtocolError(
            ProtocolErrorCode.PHASE_VIOLATION,
            f"{type(body).__name__} is invalid during {self._phase.value}",
        )

    def _invoke(self, invocation_id: int, body: InvokeBody) -> None:
        if len(self._active) >= self._max_inflight:
            raise ProtocolError(ProtocolErrorCode.CREDIT_EXHAUSTED, "worker credits are exhausted")
        if invocation_id in self._active or any(
            active.credit_id == body.credit_id for active in self._active.values()
        ):
            raise ProtocolError(ProtocolErrorCode.DUPLICATE_CREDIT, "credit is already active")
        if (
            len(body.payload) > self._max_payload
            or body.response_reservation_bytes > self._max_payload
        ):
            raise ProtocolError(
                ProtocolErrorCode.INVALID_BODY_VALUE,
                "Invoke exceeds the negotiated payload bound",
            )
        retained = len(body.payload) + body.response_reservation_bytes
        if self._retained + retained > self._max_retained:
            raise ProtocolError(
                ProtocolErrorCode.RETAINED_BYTES_EXCEEDED,
                "Invoke exceeds the negotiated retained-byte bound",
            )
        due_at = None
        if self._fault not in {FaultMode.BLOCK, FaultMode.IGNORE_CANCEL}:
            due_at = time.monotonic() + self._invoke_delay
        self._active[invocation_id] = ActiveInvocation(
            body.credit_id,
            body.response_reservation_bytes,
            retained,
            body.payload,
            due_at,
        )
        self._retained += retained
        if self._fault is FaultMode.CRASH:
            os._exit(FAULT_CRASH_EXIT)
        self._send(InvokedBody(body.credit_id), self._live_state(), invocation_id)
        if self._fault is FaultMode.BLOCK:
            while True:
                time.sleep(3_600)
        self._complete_due_invocations()

    def _cancel(self, invocation_id: int, body: CancelBody) -> None:
        active = self._active.get(invocation_id)
        if active is None or active.credit_id != body.credit_id:
            raise ProtocolError(ProtocolErrorCode.UNKNOWN_CREDIT, "Cancel credit is not active")
        if self._fault is FaultMode.IGNORE_CANCEL:
            return
        self._terminal(invocation_id, TerminalKind.CANCELLED_BEFORE_RUN, b"")

    def _complete_due_invocations(self) -> None:
        now = time.monotonic()
        due = [
            invocation_id
            for invocation_id, active in self._active.items()
            if active.due_at is not None and active.due_at <= now
        ]
        for invocation_id in due:
            active = self._active[invocation_id]
            if len(active.payload) <= active.response_reservation_bytes:
                self._terminal(invocation_id, TerminalKind.COMPLETED, active.payload)
            else:
                self._terminal(invocation_id, TerminalKind.FAILED, b"")

    def _terminal(self, invocation_id: int, kind: TerminalKind, payload: bytes) -> None:
        active = self._active.pop(invocation_id)
        self._retained -= active.retained_bytes
        self._send(
            TerminalBody(active.credit_id, kind, payload),
            self._live_state(),
            invocation_id,
        )
        self._maybe_finish_drain()

    def _maybe_heartbeat(self) -> None:
        if self._next_heartbeat is None or self._phase not in {
            WorkerPhase.RUNNING,
            WorkerPhase.DRAINING,
        }:
            return
        now = time.monotonic()
        if now < self._next_heartbeat:
            return
        self._heartbeat_sequence += 1
        self._send(
            HeartbeatBody(self._heartbeat_sequence, len(self._active), self._retained),
            self._live_state(),
        )
        self._next_heartbeat = now + self._heartbeat_interval

    def _maybe_finish_drain(self) -> None:
        if self._phase is WorkerPhase.DRAINING and not self._active and self._retained == 0:
            self._send(DrainedBody(), WorkerState.DRAINING)
            self._phase = WorkerPhase.AWAIT_STOP
            self._next_heartbeat = None

    def _next_timeout(self) -> float | None:
        deadlines = [active.due_at for active in self._active.values() if active.due_at is not None]
        if self._next_heartbeat is not None:
            deadlines.append(self._next_heartbeat)
        if not deadlines:
            return None
        return max(0.0, min(deadlines) - time.monotonic())

    def _live_state(self) -> WorkerState:
        if self._phase is WorkerPhase.DRAINING:
            return WorkerState.DRAINING
        return WorkerState.RUNNING

    def _send(
        self,
        body: ReadyBody
        | ConstructedBody
        | InvokedBody
        | HeartbeatBody
        | TerminalBody
        | DrainedBody
        | StoppedBody
        | PongBody,
        state: WorkerState,
        invocation_id: int = 0,
    ) -> None:
        identity = self._identity
        if identity is None:
            raise ProtocolError(ProtocolErrorCode.INVALID_IDENTITY, "worker identity is unset")
        self._worker_sequence += 1
        if self._fault is FaultMode.STALE_GENERATION and self._worker_sequence == 1:
            stale_epoch = (
                identity.process_domain_epoch - 1
                if identity.process_domain_epoch > 1
                else identity.process_domain_epoch + 1
            )
            identity = replace(identity, process_domain_epoch=stale_epoch)
        frame = Frame(
            identity,
            self._worker_sequence,
            Direction.WORKER_TO_HOST,
            state,
            invocation_id,
            body,
        )
        if self._fault is FaultMode.PARTIAL_FRAME and not self._partial_sent:
            self._partial_sent = True
            encoded = frame.encode()
            self._output.write(len(encoded).to_bytes(_PARTIAL_PREFIX, "big"))
            self._output.write(encoded[: max(1, len(encoded) // 2)])
            self._output.flush()
            os._exit(FAULT_PARTIAL_FRAME_EXIT)
        write_frame(self._output, frame)


__all__ = [
    "FAULT_CRASH_EXIT",
    "FAULT_PARTIAL_FRAME_EXIT",
    "FaultMode",
    "MEMORY_PRESSURE_BYTES",
    "MAX_FRAME_BYTES",
    "ReferenceWorker",
    "WORKER_RUNTIME_DIGEST",
]
