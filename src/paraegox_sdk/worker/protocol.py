"""Strict, dependency-free PXWP v1 codec and length-framed stream helpers.

The Rust runtime-contracts crate remains the protocol authority. This module is
an independent Python implementation of those fixed bytes for the subordinate
reference worker. The four-byte stream prefix is transport framing and is not
part of the canonical PXWP frame or its digest.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import BinaryIO, TypeAlias

MAGIC = b"PXWP"
VERSION = 1
HEADER_BYTES = 148
MAX_FRAME_BYTES = 1_048_576
MAX_PAYLOAD_BYTES = MAX_FRAME_BYTES - HEADER_BYTES - 24
MAX_CREDITS = 4_096
MAX_RETAINED_BYTES = 4 * 1_024 * 1_024 * 1_024

_HEADER = struct.Struct(">4sHHIBBBBQ16sQ16sQ16sQQQ32sI")
_PACKET_LENGTH = struct.Struct(">I")
_DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
_DIGEST_VERSION = 1
_DIGEST_DOMAIN = b"paraegox.runtime.process-worker-frame.sha256.v1"

if _HEADER.size != HEADER_BYTES:  # pragma: no cover - import-time invariant
    raise RuntimeError("PXWP v1 header layout drifted")


class Direction(IntEnum):
    HOST_TO_WORKER = 1
    WORKER_TO_HOST = 2


class WorkerState(IntEnum):
    STARTING = 1
    CONSTRUCTING = 2
    RUNNING = 3
    DRAINING = 4
    STOPPING = 5
    STOPPED = 6


class FrameKind(IntEnum):
    START = 1
    READY = 2
    CONSTRUCT = 3
    CONSTRUCTED = 4
    INVOKE = 5
    HEARTBEAT = 6
    CANCEL = 7
    TERMINAL = 8
    STOP_ACCEPTING = 9
    DRAINED = 10
    STOP = 11
    STOPPED = 12
    PING = 13
    PONG = 14
    INVOKED = 15


class ConstructOutcome(IntEnum):
    CONSTRUCTED = 1
    REJECTED = 2
    FAILED = 3


class TerminalKind(IntEnum):
    COMPLETED = 1
    REJECTED = 2
    FAILED = 3
    CANCELLED_BEFORE_RUN = 4
    UNCERTAIN = 5


class StopReason(IntEnum):
    PLANNED = 1
    APPLY_REPLACEMENT = 2
    PROTOCOL_FAILURE = 3
    HOST_SHUTDOWN = 4


class StoppedOutcome(IntEnum):
    CLEAN = 1
    FORCED = 2
    FAILED = 3


class ProtocolErrorCode(IntEnum):
    FRAME_TOO_LARGE = 1
    TRUNCATED = 2
    INVALID_MAGIC = 3
    UNSUPPORTED_VERSION = 4
    INVALID_HEADER_LENGTH = 5
    INVALID_FRAME_LENGTH = 6
    INVALID_ENUM_VALUE = 7
    RESERVED_BITS_SET = 8
    INVALID_IDENTITY = 9
    INVALID_SEQUENCE = 10
    INVALID_INVOCATION_SCOPE = 11
    INVALID_BODY_LENGTH = 12
    INVALID_BODY_VALUE = 13
    DIRECTION_MISMATCH = 14
    STATE_MISMATCH = 15
    PHASE_VIOLATION = 16
    SEQUENCE_VIOLATION = 17
    IDENTITY_MISMATCH = 18
    CREDIT_EXHAUSTED = 19
    DUPLICATE_CREDIT = 20
    UNKNOWN_CREDIT = 21
    RETAINED_BYTES_EXCEEDED = 22
    RETAINED_SNAPSHOT_MISMATCH = 23
    HEARTBEAT_SEQUENCE_VIOLATION = 24
    PING_VIOLATION = 25
    NON_CANONICAL_FRAME = 26
    DIGEST_FAILURE = 27
    INTEGER_OVERFLOW = 28
    INVOCATION_ACK_VIOLATION = 29


class ProtocolError(ValueError):
    """Stable PXWP construction, decoding, or stream rejection."""

    def __init__(self, code: ProtocolErrorCode, message: str):
        super().__init__(message)
        self.code = code


def _error(code: ProtocolErrorCode, message: str) -> ProtocolError:
    return ProtocolError(code, message)


def _uint(value: int, bits: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << bits:
        raise _error(ProtocolErrorCode.INVALID_BODY_VALUE, f"value is not an unsigned u{bits}")
    return value


def _fixed_bytes(value: bytes, length: int, *, identity: bool = False) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        code = (
            ProtocolErrorCode.INVALID_IDENTITY if identity else ProtocolErrorCode.INVALID_BODY_VALUE
        )
        raise _error(code, f"value must contain exactly {length} bytes")
    if not any(value):
        code = (
            ProtocolErrorCode.INVALID_IDENTITY if identity else ProtocolErrorCode.INVALID_BODY_VALUE
        )
        raise _error(code, "all-zero opaque values are forbidden")
    return value


@dataclass(frozen=True, slots=True)
class SessionIdentity:
    runtime_host_id: bytes
    runtime_host_epoch: int
    process_domain_id: bytes
    process_domain_epoch: int
    instance_id: bytes
    instance_generation: int
    source_plan_revision: int
    target_slice_digest: bytes

    def __post_init__(self) -> None:
        _fixed_bytes(self.runtime_host_id, 16, identity=True)
        _fixed_bytes(self.process_domain_id, 16, identity=True)
        _fixed_bytes(self.instance_id, 16, identity=True)
        _fixed_bytes(self.target_slice_digest, 32, identity=True)
        for value in (
            self.runtime_host_epoch,
            self.process_domain_epoch,
            self.instance_generation,
            self.source_plan_revision,
        ):
            if _uint(value, 64) == 0:
                raise _error(ProtocolErrorCode.INVALID_IDENTITY, "live generations must be nonzero")


@dataclass(frozen=True, slots=True)
class StartBody:
    max_inflight: int
    max_retained_bytes: int
    max_payload_bytes: int
    heartbeat_interval_nanos: int
    heartbeat_timeout_nanos: int


@dataclass(frozen=True, slots=True)
class ReadyBody:
    worker_runtime_digest: bytes


@dataclass(frozen=True, slots=True)
class ConstructBody:
    artifact_digest: bytes
    config_digest: bytes
    entrypoint_ref: bytes


@dataclass(frozen=True, slots=True)
class ConstructedBody:
    outcome: ConstructOutcome


@dataclass(frozen=True, slots=True)
class InvokeBody:
    credit_id: int
    response_reservation_bytes: int
    remaining_budget_nanos: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class InvokedBody:
    """Acknowledges complete receipt of one exact Invoke and credit."""

    credit_id: int


@dataclass(frozen=True, slots=True)
class HeartbeatBody:
    heartbeat_sequence: int
    active_invocations: int
    retained_bytes: int


@dataclass(frozen=True, slots=True)
class CancelBody:
    credit_id: int
    grace_remaining_nanos: int


@dataclass(frozen=True, slots=True)
class TerminalBody:
    credit_id: int
    kind: TerminalKind
    payload: bytes


@dataclass(frozen=True, slots=True)
class StopAcceptingBody:
    pass


@dataclass(frozen=True, slots=True)
class DrainedBody:
    pass


@dataclass(frozen=True, slots=True)
class StopBody:
    reason: StopReason


@dataclass(frozen=True, slots=True)
class StoppedBody:
    outcome: StoppedOutcome


@dataclass(frozen=True, slots=True)
class PingBody:
    nonce: int


@dataclass(frozen=True, slots=True)
class PongBody:
    nonce: int


FrameBody: TypeAlias = (
    StartBody
    | ReadyBody
    | ConstructBody
    | ConstructedBody
    | InvokeBody
    | InvokedBody
    | HeartbeatBody
    | CancelBody
    | TerminalBody
    | StopAcceptingBody
    | DrainedBody
    | StopBody
    | StoppedBody
    | PingBody
    | PongBody
)

_BODY_KINDS: dict[type[object], FrameKind] = {
    StartBody: FrameKind.START,
    ReadyBody: FrameKind.READY,
    ConstructBody: FrameKind.CONSTRUCT,
    ConstructedBody: FrameKind.CONSTRUCTED,
    InvokeBody: FrameKind.INVOKE,
    InvokedBody: FrameKind.INVOKED,
    HeartbeatBody: FrameKind.HEARTBEAT,
    CancelBody: FrameKind.CANCEL,
    TerminalBody: FrameKind.TERMINAL,
    StopAcceptingBody: FrameKind.STOP_ACCEPTING,
    DrainedBody: FrameKind.DRAINED,
    StopBody: FrameKind.STOP,
    StoppedBody: FrameKind.STOPPED,
    PingBody: FrameKind.PING,
    PongBody: FrameKind.PONG,
}

_HOST_KINDS = {
    FrameKind.START,
    FrameKind.CONSTRUCT,
    FrameKind.INVOKE,
    FrameKind.CANCEL,
    FrameKind.STOP_ACCEPTING,
    FrameKind.STOP,
    FrameKind.PING,
}
_INVOCATION_KINDS = {
    FrameKind.INVOKE,
    FrameKind.INVOKED,
    FrameKind.CANCEL,
    FrameKind.TERMINAL,
}
_VALID_STATES = {
    FrameKind.START: {WorkerState.STARTING},
    FrameKind.READY: {WorkerState.STARTING},
    FrameKind.CONSTRUCT: {WorkerState.CONSTRUCTING},
    FrameKind.CONSTRUCTED: {WorkerState.CONSTRUCTING},
    FrameKind.INVOKE: {WorkerState.RUNNING},
    FrameKind.INVOKED: {WorkerState.RUNNING, WorkerState.DRAINING},
    FrameKind.HEARTBEAT: {WorkerState.RUNNING, WorkerState.DRAINING},
    FrameKind.CANCEL: {WorkerState.RUNNING, WorkerState.DRAINING},
    FrameKind.TERMINAL: {WorkerState.RUNNING, WorkerState.DRAINING},
    FrameKind.STOP_ACCEPTING: {WorkerState.DRAINING},
    FrameKind.DRAINED: {WorkerState.DRAINING},
    FrameKind.STOP: {WorkerState.STOPPING},
    FrameKind.STOPPED: {WorkerState.STOPPED},
    FrameKind.PING: {WorkerState.RUNNING, WorkerState.DRAINING},
    FrameKind.PONG: {WorkerState.RUNNING, WorkerState.DRAINING},
}


def body_kind(body: FrameBody) -> FrameKind:
    try:
        return _BODY_KINDS[type(body)]
    except KeyError as error:  # pragma: no cover - closed TypeAlias at runtime
        raise _error(ProtocolErrorCode.INVALID_BODY_VALUE, "unknown PXWP body type") from error


def _enum(enum_type: type[IntEnum], value: int) -> IntEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise _error(ProtocolErrorCode.INVALID_ENUM_VALUE, "unknown enum discriminant") from error


def encode_body(body: FrameBody) -> bytes:
    if isinstance(body, StartBody):
        if not (
            0 < _uint(body.max_inflight, 32) <= MAX_CREDITS
            and 0 < _uint(body.max_retained_bytes, 64) <= MAX_RETAINED_BYTES
            and 0 < _uint(body.max_payload_bytes, 32) <= MAX_PAYLOAD_BYTES
            and 0
            < _uint(body.heartbeat_interval_nanos, 64)
            < _uint(body.heartbeat_timeout_nanos, 64)
        ):
            raise _error(ProtocolErrorCode.INVALID_BODY_VALUE, "invalid Start bounds")
        return struct.pack(
            ">IQIQQ",
            body.max_inflight,
            body.max_retained_bytes,
            body.max_payload_bytes,
            body.heartbeat_interval_nanos,
            body.heartbeat_timeout_nanos,
        )
    if isinstance(body, ReadyBody):
        return _fixed_bytes(body.worker_runtime_digest, 32)
    if isinstance(body, ConstructBody):
        return b"".join(
            (
                _fixed_bytes(body.artifact_digest, 32),
                _fixed_bytes(body.config_digest, 32),
                _fixed_bytes(body.entrypoint_ref, 16),
            )
        )
    if isinstance(body, ConstructedBody):
        return struct.pack(">B", int(_enum(ConstructOutcome, int(body.outcome))))
    if isinstance(body, InvokeBody):
        if (
            _uint(body.credit_id, 64) == 0
            or _uint(body.remaining_budget_nanos, 64) == 0
            or not isinstance(body.payload, bytes)
            or len(body.payload) > MAX_PAYLOAD_BYTES
        ):
            raise _error(ProtocolErrorCode.INVALID_BODY_VALUE, "invalid Invoke body")
        _uint(body.response_reservation_bytes, 32)
        return b"".join(
            (
                struct.pack(
                    ">QIIQ",
                    body.credit_id,
                    len(body.payload),
                    body.response_reservation_bytes,
                    body.remaining_budget_nanos,
                ),
                body.payload,
            )
        )
    if isinstance(body, InvokedBody):
        if _uint(body.credit_id, 64) == 0:
            raise _error(ProtocolErrorCode.INVALID_BODY_VALUE, "Invoked credit is zero")
        return struct.pack(">Q", body.credit_id)
    if isinstance(body, HeartbeatBody):
        if _uint(body.heartbeat_sequence, 64) == 0:
            raise _error(ProtocolErrorCode.INVALID_BODY_VALUE, "heartbeat sequence is zero")
        return struct.pack(
            ">QIQ",
            body.heartbeat_sequence,
            _uint(body.active_invocations, 32),
            _uint(body.retained_bytes, 64),
        )
    if isinstance(body, CancelBody):
        if _uint(body.credit_id, 64) == 0:
            raise _error(ProtocolErrorCode.INVALID_BODY_VALUE, "Cancel credit is zero")
        return struct.pack(">QQ", body.credit_id, _uint(body.grace_remaining_nanos, 64))
    if isinstance(body, TerminalBody):
        if (
            _uint(body.credit_id, 64) == 0
            or not isinstance(body.payload, bytes)
            or len(body.payload) > MAX_PAYLOAD_BYTES
        ):
            raise _error(ProtocolErrorCode.INVALID_BODY_VALUE, "invalid Terminal body")
        kind = int(_enum(TerminalKind, int(body.kind)))
        return struct.pack(">QB3xI", body.credit_id, kind, len(body.payload)) + body.payload
    if isinstance(body, (StopAcceptingBody, DrainedBody)):
        return b""
    if isinstance(body, StopBody):
        return struct.pack(">B", int(_enum(StopReason, int(body.reason))))
    if isinstance(body, StoppedBody):
        return struct.pack(">B", int(_enum(StoppedOutcome, int(body.outcome))))
    if isinstance(body, (PingBody, PongBody)):
        if _uint(body.nonce, 64) == 0:
            raise _error(ProtocolErrorCode.INVALID_BODY_VALUE, "ping nonce is zero")
        return struct.pack(">Q", body.nonce)
    raise _error(ProtocolErrorCode.INVALID_BODY_VALUE, "unknown PXWP body type")


def _exact(body: bytes, expected: int) -> None:
    if len(body) != expected:
        raise _error(ProtocolErrorCode.INVALID_BODY_LENGTH, "PXWP body length is invalid")


def decode_body(kind: FrameKind, body: bytes) -> FrameBody:
    if kind is FrameKind.START:
        _exact(body, 32)
        return StartBody(*struct.unpack(">IQIQQ", body))
    if kind is FrameKind.READY:
        _exact(body, 32)
        return ReadyBody(body)
    if kind is FrameKind.CONSTRUCT:
        _exact(body, 80)
        return ConstructBody(body[:32], body[32:64], body[64:80])
    if kind is FrameKind.CONSTRUCTED:
        _exact(body, 1)
        return ConstructedBody(ConstructOutcome(_enum(ConstructOutcome, body[0])))
    if kind is FrameKind.INVOKE:
        if len(body) < 24:
            raise _error(ProtocolErrorCode.TRUNCATED, "Invoke body is truncated")
        credit, payload_length, response_reservation, budget = struct.unpack_from(">QIIQ", body)
        if len(body) != 24 + payload_length:
            raise _error(ProtocolErrorCode.INVALID_BODY_LENGTH, "Invoke payload length is invalid")
        return InvokeBody(credit, response_reservation, budget, body[24:])
    if kind is FrameKind.INVOKED:
        _exact(body, 8)
        return InvokedBody(struct.unpack(">Q", body)[0])
    if kind is FrameKind.HEARTBEAT:
        _exact(body, 20)
        return HeartbeatBody(*struct.unpack(">QIQ", body))
    if kind is FrameKind.CANCEL:
        _exact(body, 16)
        return CancelBody(*struct.unpack(">QQ", body))
    if kind is FrameKind.TERMINAL:
        if len(body) < 16:
            raise _error(ProtocolErrorCode.TRUNCATED, "Terminal body is truncated")
        if body[9:12] != b"\0\0\0":
            raise _error(ProtocolErrorCode.RESERVED_BITS_SET, "Terminal reserved bytes are nonzero")
        credit = struct.unpack_from(">Q", body)[0]
        terminal_kind = TerminalKind(_enum(TerminalKind, body[8]))
        payload_length = struct.unpack_from(">I", body, 12)[0]
        if len(body) != 16 + payload_length:
            raise _error(
                ProtocolErrorCode.INVALID_BODY_LENGTH, "Terminal payload length is invalid"
            )
        return TerminalBody(credit, terminal_kind, body[16:])
    if kind is FrameKind.STOP_ACCEPTING:
        _exact(body, 0)
        return StopAcceptingBody()
    if kind is FrameKind.DRAINED:
        _exact(body, 0)
        return DrainedBody()
    if kind is FrameKind.STOP:
        _exact(body, 1)
        return StopBody(StopReason(_enum(StopReason, body[0])))
    if kind is FrameKind.STOPPED:
        _exact(body, 1)
        return StoppedBody(StoppedOutcome(_enum(StoppedOutcome, body[0])))
    if kind is FrameKind.PING:
        _exact(body, 8)
        return PingBody(struct.unpack(">Q", body)[0])
    if kind is FrameKind.PONG:
        _exact(body, 8)
        return PongBody(struct.unpack(">Q", body)[0])
    raise _error(ProtocolErrorCode.INVALID_ENUM_VALUE, "unknown PXWP body kind")


@dataclass(frozen=True, slots=True)
class Frame:
    identity: SessionIdentity
    sequence: int
    direction: Direction
    state: WorkerState
    invocation_id: int
    body: FrameBody

    def __post_init__(self) -> None:
        if _uint(self.sequence, 64) == 0:
            raise _error(ProtocolErrorCode.INVALID_SEQUENCE, "PXWP frame sequence is zero")
        _uint(self.invocation_id, 64)
        kind = self.kind
        expected_direction = (
            Direction.HOST_TO_WORKER if kind in _HOST_KINDS else Direction.WORKER_TO_HOST
        )
        if self.direction is not expected_direction:
            raise _error(ProtocolErrorCode.DIRECTION_MISMATCH, "PXWP direction is invalid")
        if self.state not in _VALID_STATES[kind]:
            raise _error(ProtocolErrorCode.STATE_MISMATCH, "PXWP worker state is invalid")
        if (kind in _INVOCATION_KINDS) != (self.invocation_id != 0):
            raise _error(
                ProtocolErrorCode.INVALID_INVOCATION_SCOPE,
                "PXWP invocation scope is inconsistent with frame kind",
            )
        encode_body(self.body)

    @property
    def kind(self) -> FrameKind:
        return body_kind(self.body)

    def encode(self) -> bytes:
        body = encode_body(self.body)
        total_length = HEADER_BYTES + len(body)
        if total_length > MAX_FRAME_BYTES:
            raise _error(ProtocolErrorCode.FRAME_TOO_LARGE, "PXWP frame exceeds the maximum")
        identity = self.identity
        header = _HEADER.pack(
            MAGIC,
            VERSION,
            HEADER_BYTES,
            total_length,
            int(self.kind),
            int(self.direction),
            int(self.state),
            0,
            self.sequence,
            identity.runtime_host_id,
            identity.runtime_host_epoch,
            identity.process_domain_id,
            identity.process_domain_epoch,
            identity.instance_id,
            identity.instance_generation,
            self.invocation_id,
            identity.source_plan_revision,
            identity.target_slice_digest,
            len(body),
        )
        return header + body

    @classmethod
    def decode(cls, encoded: bytes) -> Frame:
        if not isinstance(encoded, bytes):
            raise _error(ProtocolErrorCode.INVALID_FRAME_LENGTH, "PXWP frame must be bytes")
        if len(encoded) > MAX_FRAME_BYTES:
            raise _error(ProtocolErrorCode.FRAME_TOO_LARGE, "PXWP frame exceeds the maximum")
        if len(encoded) < HEADER_BYTES:
            raise _error(ProtocolErrorCode.TRUNCATED, "PXWP frame is truncated")
        values = _HEADER.unpack_from(encoded)
        (
            magic,
            version,
            header_length,
            total_length,
            kind_raw,
            direction_raw,
            state_raw,
            flags,
            sequence,
            runtime_host_id,
            runtime_host_epoch,
            process_domain_id,
            process_domain_epoch,
            instance_id,
            instance_generation,
            invocation_id,
            source_plan_revision,
            target_slice_digest,
            body_length,
        ) = values
        if magic != MAGIC:
            raise _error(ProtocolErrorCode.INVALID_MAGIC, "PXWP magic is invalid")
        if version != VERSION:
            raise _error(ProtocolErrorCode.UNSUPPORTED_VERSION, "PXWP version is unsupported")
        if header_length != HEADER_BYTES:
            raise _error(ProtocolErrorCode.INVALID_HEADER_LENGTH, "PXWP header length is invalid")
        if total_length != len(encoded):
            raise _error(ProtocolErrorCode.INVALID_FRAME_LENGTH, "PXWP total length is invalid")
        kind = FrameKind(_enum(FrameKind, kind_raw))
        direction = Direction(_enum(Direction, direction_raw))
        state = WorkerState(_enum(WorkerState, state_raw))
        if flags != 0:
            raise _error(ProtocolErrorCode.RESERVED_BITS_SET, "PXWP flags are nonzero")
        if HEADER_BYTES + body_length != len(encoded):
            raise _error(ProtocolErrorCode.INVALID_BODY_LENGTH, "PXWP body length is invalid")
        identity = SessionIdentity(
            runtime_host_id,
            runtime_host_epoch,
            process_domain_id,
            process_domain_epoch,
            instance_id,
            instance_generation,
            source_plan_revision,
            target_slice_digest,
        )
        frame = cls(
            identity,
            sequence,
            direction,
            state,
            invocation_id,
            decode_body(kind, encoded[HEADER_BYTES:]),
        )
        if frame.kind is not kind or frame.encode() != encoded:
            raise _error(ProtocolErrorCode.NON_CANONICAL_FRAME, "PXWP frame is not canonical")
        return frame


def frame_digest(encoded: bytes) -> bytes:
    """Return the Rust-compatible canonical digest of one PXWP frame."""

    domain = _DIGEST_DOMAIN
    transcript = bytearray(_DIGEST_MAGIC)
    transcript += struct.pack(">H", _DIGEST_VERSION)
    transcript += struct.pack(">I", len(domain))
    transcript += domain
    transcript += b"\x01"
    transcript += struct.pack(">I", 1)
    transcript += struct.pack(">Q", len(encoded))
    transcript += encoded
    transcript += b"\xff"
    transcript += struct.pack(">I", 1)
    return hashlib.sha256(transcript).digest()


def _read_exact(stream: BinaryIO, length: int, *, clean_eof: bool = False) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.read(length - len(chunks))
        if not chunk:
            if clean_eof and not chunks:
                return None
            raise _error(ProtocolErrorCode.TRUNCATED, "length-framed stream ended mid-frame")
        chunks += chunk
    return bytes(chunks)


def read_frame(stream: BinaryIO) -> Frame | None:
    """Read one outer-u32-length-prefixed PXWP frame; clean EOF returns ``None``."""

    prefix = _read_exact(stream, _PACKET_LENGTH.size, clean_eof=True)
    if prefix is None:
        return None
    length = _PACKET_LENGTH.unpack(prefix)[0]
    if length > MAX_FRAME_BYTES:
        raise _error(ProtocolErrorCode.FRAME_TOO_LARGE, "stream frame exceeds PXWP maximum")
    if length == 0:
        raise _error(ProtocolErrorCode.INVALID_FRAME_LENGTH, "stream frame length is zero")
    encoded = _read_exact(stream, length)
    if encoded is None:  # pragma: no cover - clean EOF is disabled for the body
        raise _error(ProtocolErrorCode.TRUNCATED, "stream frame is truncated")
    return Frame.decode(encoded)


def write_frame(stream: BinaryIO, frame: Frame) -> None:
    """Write and flush one outer-u32-length-prefixed canonical PXWP frame."""

    encoded = frame.encode()
    stream.write(_PACKET_LENGTH.pack(len(encoded)))
    stream.write(encoded)
    stream.flush()


def encode_packet(frame: Frame) -> bytes:
    """Return stream bytes for tests and non-file transports."""

    encoded = frame.encode()
    return _PACKET_LENGTH.pack(len(encoded)) + encoded


__all__ = [
    "CancelBody",
    "ConstructBody",
    "ConstructOutcome",
    "ConstructedBody",
    "Direction",
    "DrainedBody",
    "Frame",
    "FrameBody",
    "FrameKind",
    "HEADER_BYTES",
    "HeartbeatBody",
    "InvokeBody",
    "InvokedBody",
    "MAX_CREDITS",
    "MAX_FRAME_BYTES",
    "MAX_PAYLOAD_BYTES",
    "MAX_RETAINED_BYTES",
    "PingBody",
    "PongBody",
    "ProtocolError",
    "ProtocolErrorCode",
    "ReadyBody",
    "SessionIdentity",
    "StartBody",
    "StopAcceptingBody",
    "StopBody",
    "StopReason",
    "StoppedBody",
    "StoppedOutcome",
    "TerminalBody",
    "TerminalKind",
    "VERSION",
    "WorkerState",
    "encode_packet",
    "frame_digest",
    "read_frame",
    "write_frame",
]
