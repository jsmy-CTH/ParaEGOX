"""Independent Python codec for additive PXAC v1 conversation controls.

Kinds 1/2 remain owned by :mod:`protocol`; this module accepts only the
separate open/get/watch/cancel kinds 3..10 and reconstructs their canonical
digest and fixed header without calling the Rust implementation.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum

from .protocol import (
    AGENT_CONVERSATION_HEADER_BYTES,
    AGENT_CONVERSATION_PROTOCOL_MAGIC,
    AGENT_CONVERSATION_PROTOCOL_VERSION,
    AgentConversationRequestV1,
    AgentConversationTerminalV1,
    decode_request_v1,
    decode_terminal_v1,
)

MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES = 64 * 1024
MAX_AGENT_CONVERSATION_CONTROL_FRAME_BYTES = (
    AGENT_CONVERSATION_HEADER_BYTES + MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES
)
MAX_AGENT_CONVERSATION_WATCH_EVENTS = 32

_HEADER = struct.Struct(">4sHHIBBHI16s16s16s16s32sQI")
_BATCH_HEADER = struct.Struct(">QQB3sI")
_EVENT_HEADER = struct.Struct(">QB3sI")
_CONTROL_DIGEST_DOMAIN = b"paraegox.agent.conversation.control.sha256.v1"
_DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
_DIGEST_VERSION = 1
_FIELD_MARKER = 1
_END_MARKER = 0xFF
_ZERO_ID = bytes(16)


class AgentConversationControlKindV1(IntEnum):
    OPEN_REQUEST = 3
    OPEN_RESULT = 4
    GET_REQUEST = 5
    GET_RESULT = 6
    WATCH_REQUEST = 7
    WATCH_RESULT = 8
    CANCEL_REQUEST = 9
    CANCEL_RESULT = 10


class AgentConversationOpenOutcomeV1(IntEnum):
    OPENED = 1
    EXISTING = 2
    DECK_RUN_SEALED = 3
    CAPACITY_EXHAUSTED = 4


class AgentConversationGetOutcomeV1(IntEnum):
    NOT_FOUND = 1
    PENDING = 2
    PENDING_CANCEL_REQUESTED = 3
    TERMINAL = 4


class AgentConversationWatchOutcomeV1(IntEnum):
    NOT_FOUND = 1
    BATCH = 2


class AgentConversationCancelOutcomeV1(IntEnum):
    NOT_FOUND = 1
    INTENT_RECORDED = 2
    INTENT_ALREADY_RECORDED = 3
    SESSION_SEALED = 4
    TERMINAL = 5


class AgentConversationWatchEventKindV1(IntEnum):
    SESSION_OPENED = 1
    REQUEST_ACCEPTED = 2
    TERMINAL_COMMITTED = 3
    CANCEL_INTENT_RECORDED = 4
    SESSION_SEALED = 5


class AgentConversationControlErrorCode(IntEnum):
    TRUNCATED = 1
    FRAME_TOO_LARGE = 2
    PAYLOAD_TOO_LARGE = 3
    INVALID_MAGIC = 4
    UNSUPPORTED_VERSION = 5
    INVALID_HEADER_LENGTH = 6
    INVALID_FRAME_LENGTH = 7
    UNKNOWN_FRAME_KIND = 8
    RESERVED_BITS_SET = 9
    INVALID_IDENTITY = 10
    INVALID_DIGEST = 11
    DIGEST_MISMATCH = 12
    INVALID_OUTCOME = 13
    INVALID_REQUEST_IDENTITY = 14
    WATCH_LIMIT_OUT_OF_RANGE = 15
    INVALID_WATCH_BATCH = 16
    INVALID_WATCH_EVENT = 17
    INVALID_WATCH_SEQUENCE = 18
    CORRELATION_MISMATCH = 19
    EMBEDDED_VALUE_INVALID = 20


class AgentConversationControlError(ValueError):
    def __init__(self, code: AgentConversationControlErrorCode, message: str):
        super().__init__(message)
        self.code = code


def _error(code: AgentConversationControlErrorCode, message: str) -> AgentConversationControlError:
    return AgentConversationControlError(code, message)


def _identity(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 16 or not any(value):
        raise _error(
            AgentConversationControlErrorCode.INVALID_IDENTITY,
            "control identity must contain 16 nonzero bytes",
        )
    return value


def _required_request_id(value: bytes | None) -> bytes:
    if value is None:
        raise _error(
            AgentConversationControlErrorCode.INVALID_REQUEST_IDENTITY,
            "control request identity is required",
        )
    return _identity(value)


def _canonical_digest(fields: tuple[bytes, ...]) -> bytes:
    digest = hashlib.sha256()
    digest.update(_DIGEST_MAGIC)
    digest.update(_DIGEST_VERSION.to_bytes(2, "big"))
    digest.update(len(_CONTROL_DIGEST_DOMAIN).to_bytes(4, "big"))
    digest.update(_CONTROL_DIGEST_DOMAIN)
    for ordinal, field in enumerate(fields, start=1):
        digest.update(bytes([_FIELD_MARKER]))
        digest.update(ordinal.to_bytes(4, "big"))
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    digest.update(bytes([_END_MARKER]))
    digest.update(len(fields).to_bytes(4, "big"))
    return digest.digest()


def control_digest_v1(
    kind: AgentConversationControlKindV1,
    outcome: int,
    deck_run_id: bytes,
    session_id: bytes,
    request_id: bytes | None,
    payload: bytes,
) -> bytes:
    request_raw = _ZERO_ID if request_id is None else _identity(request_id)
    return _canonical_digest(
        (
            bytes([int(kind)]),
            bytes([outcome]),
            _identity(deck_run_id),
            _identity(session_id),
            request_raw,
            payload,
        )
    )


@dataclass(frozen=True, slots=True)
class AgentConversationWatchEventV1:
    sequence: int
    kind: AgentConversationWatchEventKindV1
    value: AgentConversationRequestV1 | AgentConversationTerminalV1 | bytes | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence <= 0
            or self.sequence > (1 << 64) - 1
        ):
            raise _error(
                AgentConversationControlErrorCode.INVALID_WATCH_SEQUENCE,
                "watch sequence is out of range",
            )
        if (
            self.kind
            in {
                AgentConversationWatchEventKindV1.SESSION_OPENED,
                AgentConversationWatchEventKindV1.SESSION_SEALED,
            }
            and self.value is not None
        ):
            raise _error(
                AgentConversationControlErrorCode.INVALID_WATCH_EVENT,
                "payload-free watch event has a value",
            )
        if self.kind is AgentConversationWatchEventKindV1.REQUEST_ACCEPTED and not isinstance(
            self.value, AgentConversationRequestV1
        ):
            raise _error(
                AgentConversationControlErrorCode.INVALID_WATCH_EVENT,
                "request event value is invalid",
            )
        if self.kind is AgentConversationWatchEventKindV1.TERMINAL_COMMITTED and not isinstance(
            self.value, AgentConversationTerminalV1
        ):
            raise _error(
                AgentConversationControlErrorCode.INVALID_WATCH_EVENT,
                "terminal event value is invalid",
            )
        if self.kind is AgentConversationWatchEventKindV1.CANCEL_INTENT_RECORDED:
            if not isinstance(self.value, bytes):
                raise _error(
                    AgentConversationControlErrorCode.INVALID_WATCH_EVENT,
                    "cancel-intent event value is invalid",
                )
            _identity(self.value)


@dataclass(frozen=True, slots=True)
class AgentConversationWatchBatchV1:
    events: tuple[AgentConversationWatchEventV1, ...]
    next_cursor: int
    high_watermark: int
    has_more: bool
    sealed: bool

    def __post_init__(self) -> None:
        _validate_watch_batch(self)

    def validate_for_request(self, cursor: int, limit: int) -> None:
        """Validate against the originating watch request's cursor and limit."""
        _validate_cursor_limit(cursor, limit)
        if len(self.events) > limit:
            raise _error(
                AgentConversationControlErrorCode.INVALID_WATCH_BATCH,
                "watch response exceeds the requested event limit",
            )
        if self.events:
            if (
                cursor == (1 << 64) - 1
                or self.events[0].sequence != cursor + 1
                or self.events[-1].sequence != self.next_cursor
            ):
                raise _error(
                    AgentConversationControlErrorCode.INVALID_WATCH_SEQUENCE,
                    "watch response does not continue the request cursor",
                )
        elif self.next_cursor != cursor:
            raise _error(
                AgentConversationControlErrorCode.INVALID_WATCH_SEQUENCE,
                "empty watch response changed the request cursor",
            )


@dataclass(frozen=True, slots=True)
class AgentConversationControlV1:
    deck_run_id: bytes
    session_id: bytes
    request_id: bytes | None
    kind: AgentConversationControlKindV1
    outcome: int
    value: AgentConversationTerminalV1 | AgentConversationWatchBatchV1 | tuple[int, int] | None

    def __post_init__(self) -> None:
        _identity(self.deck_run_id)
        _identity(self.session_id)
        if self.request_id is not None:
            _identity(self.request_id)
        _encode_body(self)

    @classmethod
    def open_request(cls, deck_run_id: bytes, session_id: bytes) -> AgentConversationControlV1:
        return cls(
            deck_run_id, session_id, None, AgentConversationControlKindV1.OPEN_REQUEST, 0, None
        )

    @classmethod
    def open_result(
        cls,
        deck_run_id: bytes,
        session_id: bytes,
        outcome: AgentConversationOpenOutcomeV1,
    ) -> AgentConversationControlV1:
        return cls(
            deck_run_id,
            session_id,
            None,
            AgentConversationControlKindV1.OPEN_RESULT,
            int(outcome),
            None,
        )

    @classmethod
    def get_request(
        cls, deck_run_id: bytes, session_id: bytes, request_id: bytes
    ) -> AgentConversationControlV1:
        return cls(
            deck_run_id, session_id, request_id, AgentConversationControlKindV1.GET_REQUEST, 0, None
        )

    @classmethod
    def get_result(
        cls,
        deck_run_id: bytes,
        session_id: bytes,
        request_id: bytes,
        outcome: AgentConversationGetOutcomeV1,
        terminal: AgentConversationTerminalV1 | None = None,
    ) -> AgentConversationControlV1:
        return cls(
            deck_run_id,
            session_id,
            request_id,
            AgentConversationControlKindV1.GET_RESULT,
            int(outcome),
            terminal,
        )

    @classmethod
    def watch_request(
        cls, deck_run_id: bytes, session_id: bytes, cursor: int, limit: int
    ) -> AgentConversationControlV1:
        return cls(
            deck_run_id,
            session_id,
            None,
            AgentConversationControlKindV1.WATCH_REQUEST,
            0,
            (cursor, limit),
        )

    @classmethod
    def watch_not_found(cls, deck_run_id: bytes, session_id: bytes) -> AgentConversationControlV1:
        return cls(
            deck_run_id,
            session_id,
            None,
            AgentConversationControlKindV1.WATCH_RESULT,
            int(AgentConversationWatchOutcomeV1.NOT_FOUND),
            None,
        )

    @classmethod
    def watch_result(
        cls,
        deck_run_id: bytes,
        session_id: bytes,
        batch: AgentConversationWatchBatchV1,
    ) -> AgentConversationControlV1:
        return cls(
            deck_run_id,
            session_id,
            None,
            AgentConversationControlKindV1.WATCH_RESULT,
            int(AgentConversationWatchOutcomeV1.BATCH),
            batch,
        )

    @classmethod
    def cancel_request(
        cls, deck_run_id: bytes, session_id: bytes, request_id: bytes
    ) -> AgentConversationControlV1:
        return cls(
            deck_run_id,
            session_id,
            request_id,
            AgentConversationControlKindV1.CANCEL_REQUEST,
            0,
            None,
        )

    @classmethod
    def cancel_result(
        cls,
        deck_run_id: bytes,
        session_id: bytes,
        request_id: bytes,
        outcome: AgentConversationCancelOutcomeV1,
        terminal: AgentConversationTerminalV1 | None = None,
    ) -> AgentConversationControlV1:
        return cls(
            deck_run_id,
            session_id,
            request_id,
            AgentConversationControlKindV1.CANCEL_RESULT,
            int(outcome),
            terminal,
        )

    def canonical_wire(self) -> bytes:
        payload = _encode_body(self)
        digest = control_digest_v1(
            self.kind,
            self.outcome,
            self.deck_run_id,
            self.session_id,
            self.request_id,
            payload,
        )
        frame_length = AGENT_CONVERSATION_HEADER_BYTES + len(payload)
        return (
            _HEADER.pack(
                AGENT_CONVERSATION_PROTOCOL_MAGIC,
                AGENT_CONVERSATION_PROTOCOL_VERSION,
                AGENT_CONVERSATION_HEADER_BYTES,
                frame_length,
                int(self.kind),
                self.outcome,
                0,
                0,
                self.deck_run_id,
                self.session_id,
                _ZERO_ID,
                _ZERO_ID if self.request_id is None else self.request_id,
                digest,
                0,
                len(payload),
            )
            + payload
        )


def _encode_body(control: AgentConversationControlV1) -> bytes:
    has_request = control.request_id is not None
    if control.kind is AgentConversationControlKindV1.OPEN_REQUEST:
        _require(control.outcome == 0 and not has_request and control.value is None)
        return b""
    if control.kind is AgentConversationControlKindV1.OPEN_RESULT:
        try:
            AgentConversationOpenOutcomeV1(control.outcome)
        except ValueError as error:
            raise _error(
                AgentConversationControlErrorCode.INVALID_OUTCOME, "open outcome is invalid"
            ) from error
        _require(not has_request and control.value is None)
        return b""
    if control.kind is AgentConversationControlKindV1.GET_REQUEST:
        _require(control.outcome == 0 and has_request and control.value is None)
        return b""
    if control.kind is AgentConversationControlKindV1.GET_RESULT:
        _require(has_request)
        try:
            outcome = AgentConversationGetOutcomeV1(control.outcome)
        except ValueError as error:
            raise _error(
                AgentConversationControlErrorCode.INVALID_OUTCOME, "get outcome is invalid"
            ) from error
        if outcome is AgentConversationGetOutcomeV1.TERMINAL:
            terminal = _terminal_value(control)
            _validate_terminal_correlation(control, terminal)
            return terminal.canonical_wire()
        _require(control.value is None)
        return b""
    if control.kind is AgentConversationControlKindV1.WATCH_REQUEST:
        _require(
            control.outcome == 0
            and not has_request
            and isinstance(control.value, tuple)
            and len(control.value) == 2
        )
        cursor, limit = control.value
        _validate_cursor_limit(cursor, limit)
        return struct.pack(">QI", cursor, limit)
    if control.kind is AgentConversationControlKindV1.WATCH_RESULT:
        _require(not has_request)
        if control.outcome == int(AgentConversationWatchOutcomeV1.NOT_FOUND):
            _require(control.value is None)
            return b""
        if control.outcome == int(AgentConversationWatchOutcomeV1.BATCH) and isinstance(
            control.value, AgentConversationWatchBatchV1
        ):
            return _encode_watch_batch(control.deck_run_id, control.session_id, control.value)
        raise _error(AgentConversationControlErrorCode.INVALID_OUTCOME, "watch outcome is invalid")
    if control.kind is AgentConversationControlKindV1.CANCEL_REQUEST:
        _require(control.outcome == 0 and has_request and control.value is None)
        return b""
    if control.kind is AgentConversationControlKindV1.CANCEL_RESULT:
        _require(has_request)
        try:
            outcome = AgentConversationCancelOutcomeV1(control.outcome)
        except ValueError as error:
            raise _error(
                AgentConversationControlErrorCode.INVALID_OUTCOME, "cancel outcome is invalid"
            ) from error
        if outcome is AgentConversationCancelOutcomeV1.TERMINAL:
            terminal = _terminal_value(control)
            _validate_terminal_correlation(control, terminal)
            return terminal.canonical_wire()
        _require(control.value is None)
        return b""
    raise _error(AgentConversationControlErrorCode.UNKNOWN_FRAME_KIND, "control kind is unknown")


def _terminal_value(control: AgentConversationControlV1) -> AgentConversationTerminalV1:
    if not isinstance(control.value, AgentConversationTerminalV1):
        raise _error(
            AgentConversationControlErrorCode.INVALID_OUTCOME, "terminal result has no terminal"
        )
    return control.value


def _require(condition: bool) -> None:
    if not condition:
        raise _error(
            AgentConversationControlErrorCode.INVALID_OUTCOME, "control fields are inconsistent"
        )


def _validate_terminal_correlation(
    control: AgentConversationControlV1, terminal: AgentConversationTerminalV1
) -> None:
    if (
        terminal.deck_run_id != control.deck_run_id
        or terminal.session_id != control.session_id
        or terminal.request_id != control.request_id
    ):
        raise _error(
            AgentConversationControlErrorCode.CORRELATION_MISMATCH,
            "terminal correlation mismatched",
        )


def _validate_cursor_limit(cursor: int, limit: int) -> None:
    if (
        not isinstance(cursor, int)
        or isinstance(cursor, bool)
        or not 0 <= cursor <= (1 << 64) - 1
        or not isinstance(limit, int)
        or isinstance(limit, bool)
        or not 1 <= limit <= MAX_AGENT_CONVERSATION_WATCH_EVENTS
    ):
        raise _error(
            AgentConversationControlErrorCode.WATCH_LIMIT_OUT_OF_RANGE,
            "watch cursor or limit is out of range",
        )


def _validate_watch_batch(batch: AgentConversationWatchBatchV1) -> None:
    if len(batch.events) > MAX_AGENT_CONVERSATION_WATCH_EVENTS:
        raise _error(
            AgentConversationControlErrorCode.WATCH_LIMIT_OUT_OF_RANGE,
            "watch event count exceeds its bound",
        )
    if (
        not 0 <= batch.next_cursor <= (1 << 64) - 1
        or not 0 <= batch.high_watermark <= (1 << 64) - 1
        or batch.next_cursor > batch.high_watermark
        or not isinstance(batch.has_more, bool)
        or batch.has_more != (batch.next_cursor < batch.high_watermark)
        or not isinstance(batch.sealed, bool)
    ):
        raise _error(
            AgentConversationControlErrorCode.INVALID_WATCH_BATCH,
            "watch batch cursor state is invalid",
        )
    for left, right in zip(batch.events, batch.events[1:]):
        if left.sequence + 1 != right.sequence:
            raise _error(
                AgentConversationControlErrorCode.INVALID_WATCH_SEQUENCE,
                "watch events are not contiguous",
            )
    if batch.events and batch.events[-1].sequence != batch.next_cursor:
        raise _error(
            AgentConversationControlErrorCode.INVALID_WATCH_SEQUENCE, "watch next cursor mismatched"
        )


def _encode_watch_batch(
    deck_run_id: bytes,
    session_id: bytes,
    batch: AgentConversationWatchBatchV1,
) -> bytes:
    _validate_watch_batch(batch)
    flags = int(batch.sealed) | (int(batch.has_more) << 1)
    payload = bytearray(
        _BATCH_HEADER.pack(
            batch.next_cursor, batch.high_watermark, flags, bytes(3), len(batch.events)
        )
    )
    for event in batch.events:
        if event.kind in {
            AgentConversationWatchEventKindV1.SESSION_OPENED,
            AgentConversationWatchEventKindV1.SESSION_SEALED,
        }:
            event_payload = b""
        elif event.kind is AgentConversationWatchEventKindV1.REQUEST_ACCEPTED:
            request = event.value
            if not isinstance(request, AgentConversationRequestV1):
                raise _error(
                    AgentConversationControlErrorCode.INVALID_WATCH_EVENT,
                    "request event value is invalid",
                )
            if request.deck_run_id != deck_run_id or request.session_id != session_id:
                raise _error(
                    AgentConversationControlErrorCode.CORRELATION_MISMATCH,
                    "watch request correlation mismatched",
                )
            event_payload = request.canonical_wire()
        elif event.kind is AgentConversationWatchEventKindV1.TERMINAL_COMMITTED:
            terminal = event.value
            if not isinstance(terminal, AgentConversationTerminalV1):
                raise _error(
                    AgentConversationControlErrorCode.INVALID_WATCH_EVENT,
                    "terminal event value is invalid",
                )
            if terminal.deck_run_id != deck_run_id or terminal.session_id != session_id:
                raise _error(
                    AgentConversationControlErrorCode.CORRELATION_MISMATCH,
                    "watch terminal correlation mismatched",
                )
            event_payload = terminal.canonical_wire()
        else:
            if (
                event.kind is not AgentConversationWatchEventKindV1.CANCEL_INTENT_RECORDED
                or not isinstance(event.value, bytes)
            ):
                raise _error(
                    AgentConversationControlErrorCode.INVALID_WATCH_EVENT,
                    "cancel-intent event value is invalid",
                )
            event_payload = _identity(event.value)
        payload.extend(
            _EVENT_HEADER.pack(event.sequence, int(event.kind), bytes(3), len(event_payload))
        )
        payload.extend(event_payload)
        if len(payload) > MAX_AGENT_CONVERSATION_CONTROL_PAYLOAD_BYTES:
            raise _error(
                AgentConversationControlErrorCode.PAYLOAD_TOO_LARGE,
                "watch batch exceeds its byte bound",
            )
    return bytes(payload)


def decode_control_v1(wire: bytes) -> AgentConversationControlV1:
    if not isinstance(wire, bytes) or len(wire) < AGENT_CONVERSATION_HEADER_BYTES:
        raise _error(AgentConversationControlErrorCode.TRUNCATED, "control frame is truncated")
    if len(wire) > MAX_AGENT_CONVERSATION_CONTROL_FRAME_BYTES:
        raise _error(
            AgentConversationControlErrorCode.FRAME_TOO_LARGE, "control frame exceeds its bound"
        )
    (
        magic,
        version,
        header_bytes,
        frame_length,
        kind_raw,
        outcome,
        terminal_error,
        flags,
        deck_run_id,
        session_id,
        turn_id,
        request_raw,
        digest,
        deadline,
        payload_length,
    ) = _HEADER.unpack_from(wire)
    if magic != AGENT_CONVERSATION_PROTOCOL_MAGIC:
        raise _error(AgentConversationControlErrorCode.INVALID_MAGIC, "control magic mismatched")
    if version != AGENT_CONVERSATION_PROTOCOL_VERSION:
        raise _error(
            AgentConversationControlErrorCode.UNSUPPORTED_VERSION, "control version is unsupported"
        )
    if header_bytes != AGENT_CONVERSATION_HEADER_BYTES:
        raise _error(
            AgentConversationControlErrorCode.INVALID_HEADER_LENGTH,
            "control header length is invalid",
        )
    if frame_length != len(wire) or header_bytes + payload_length != len(wire):
        raise _error(
            AgentConversationControlErrorCode.INVALID_FRAME_LENGTH,
            "control frame length is invalid",
        )
    try:
        kind = AgentConversationControlKindV1(kind_raw)
    except ValueError as error:
        raise _error(
            AgentConversationControlErrorCode.UNKNOWN_FRAME_KIND, "control kind is unknown"
        ) from error
    if terminal_error != 0 or flags != 0 or any(turn_id) or deadline != 0:
        raise _error(
            AgentConversationControlErrorCode.RESERVED_BITS_SET,
            "control reserved fields are nonzero",
        )
    _identity(deck_run_id)
    _identity(session_id)
    request_id = None if request_raw == _ZERO_ID else _identity(request_raw)
    if not any(digest):
        raise _error(AgentConversationControlErrorCode.INVALID_DIGEST, "control digest is all-zero")
    payload = wire[header_bytes:]
    expected = control_digest_v1(kind, outcome, deck_run_id, session_id, request_id, payload)
    if digest != expected:
        raise _error(AgentConversationControlErrorCode.DIGEST_MISMATCH, "control digest mismatched")
    return _decode_body(deck_run_id, session_id, request_id, kind, outcome, payload)


def _decode_body(
    deck_run_id: bytes,
    session_id: bytes,
    request_id: bytes | None,
    kind: AgentConversationControlKindV1,
    outcome: int,
    payload: bytes,
) -> AgentConversationControlV1:
    try:
        if kind is AgentConversationControlKindV1.OPEN_REQUEST and outcome == 0 and not payload:
            return AgentConversationControlV1.open_request(deck_run_id, session_id)
        if kind is AgentConversationControlKindV1.OPEN_RESULT and not payload:
            return AgentConversationControlV1.open_result(
                deck_run_id, session_id, AgentConversationOpenOutcomeV1(outcome)
            )
        if kind is AgentConversationControlKindV1.GET_REQUEST and outcome == 0 and not payload:
            return AgentConversationControlV1.get_request(
                deck_run_id, session_id, _required_request_id(request_id)
            )
        if kind is AgentConversationControlKindV1.GET_RESULT:
            request = _required_request_id(request_id)
            get_outcome = AgentConversationGetOutcomeV1(outcome)
            terminal = (
                decode_terminal_v1(payload)
                if get_outcome is AgentConversationGetOutcomeV1.TERMINAL
                else None
            )
            if get_outcome is not AgentConversationGetOutcomeV1.TERMINAL and payload:
                raise _error(
                    AgentConversationControlErrorCode.INVALID_OUTCOME,
                    "payload-free get result has bytes",
                )
            return AgentConversationControlV1.get_result(
                deck_run_id, session_id, request, get_outcome, terminal
            )
        if (
            kind is AgentConversationControlKindV1.WATCH_REQUEST
            and outcome == 0
            and len(payload) == 12
        ):
            cursor, limit = struct.unpack(">QI", payload)
            return AgentConversationControlV1.watch_request(deck_run_id, session_id, cursor, limit)
        if (
            kind is AgentConversationControlKindV1.WATCH_RESULT
            and outcome == int(AgentConversationWatchOutcomeV1.NOT_FOUND)
            and not payload
        ):
            return AgentConversationControlV1.watch_not_found(deck_run_id, session_id)
        if kind is AgentConversationControlKindV1.WATCH_RESULT and outcome == int(
            AgentConversationWatchOutcomeV1.BATCH
        ):
            return AgentConversationControlV1.watch_result(
                deck_run_id, session_id, _decode_watch_batch(deck_run_id, session_id, payload)
            )
        if kind is AgentConversationControlKindV1.CANCEL_REQUEST and outcome == 0 and not payload:
            return AgentConversationControlV1.cancel_request(
                deck_run_id, session_id, _required_request_id(request_id)
            )
        if kind is AgentConversationControlKindV1.CANCEL_RESULT:
            request = _required_request_id(request_id)
            cancel_outcome = AgentConversationCancelOutcomeV1(outcome)
            terminal = (
                decode_terminal_v1(payload)
                if cancel_outcome is AgentConversationCancelOutcomeV1.TERMINAL
                else None
            )
            if cancel_outcome is not AgentConversationCancelOutcomeV1.TERMINAL and payload:
                raise _error(
                    AgentConversationControlErrorCode.INVALID_OUTCOME,
                    "payload-free cancel result has bytes",
                )
            return AgentConversationControlV1.cancel_result(
                deck_run_id, session_id, request, cancel_outcome, terminal
            )
    except AgentConversationControlError:
        raise
    except (TypeError, ValueError) as error:
        raise _error(
            AgentConversationControlErrorCode.EMBEDDED_VALUE_INVALID,
            "embedded control value is invalid",
        ) from error
    raise _error(
        AgentConversationControlErrorCode.INVALID_OUTCOME, "control outcome or payload is invalid"
    )


def _decode_watch_batch(
    deck_run_id: bytes, session_id: bytes, payload: bytes
) -> AgentConversationWatchBatchV1:
    if len(payload) < _BATCH_HEADER.size:
        raise _error(
            AgentConversationControlErrorCode.INVALID_WATCH_BATCH, "watch batch is truncated"
        )
    next_cursor, high_watermark, flags, reserved, count = _BATCH_HEADER.unpack_from(payload)
    if flags & ~0b11 or any(reserved):
        raise _error(
            AgentConversationControlErrorCode.RESERVED_BITS_SET,
            "watch batch reserved bits are nonzero",
        )
    if count > MAX_AGENT_CONVERSATION_WATCH_EVENTS:
        raise _error(
            AgentConversationControlErrorCode.WATCH_LIMIT_OUT_OF_RANGE,
            "watch event count exceeds its bound",
        )
    offset = _BATCH_HEADER.size
    events: list[AgentConversationWatchEventV1] = []
    for _ in range(count):
        if len(payload) - offset < _EVENT_HEADER.size:
            raise _error(
                AgentConversationControlErrorCode.INVALID_WATCH_BATCH, "watch event is truncated"
            )
        sequence, kind_raw, reserved, length = _EVENT_HEADER.unpack_from(payload, offset)
        if any(reserved):
            raise _error(
                AgentConversationControlErrorCode.RESERVED_BITS_SET,
                "watch event reserved bits are nonzero",
            )
        offset += _EVENT_HEADER.size
        end = offset + length
        if end > len(payload):
            raise _error(
                AgentConversationControlErrorCode.INVALID_WATCH_BATCH,
                "watch event length is invalid",
            )
        event_payload = payload[offset:end]
        try:
            kind = AgentConversationWatchEventKindV1(kind_raw)
            if kind in {
                AgentConversationWatchEventKindV1.SESSION_OPENED,
                AgentConversationWatchEventKindV1.SESSION_SEALED,
            }:
                if event_payload:
                    raise ValueError("payload-free event")
                value = None
            elif kind is AgentConversationWatchEventKindV1.REQUEST_ACCEPTED:
                value = decode_request_v1(event_payload)
                if value.deck_run_id != deck_run_id or value.session_id != session_id:
                    raise _error(
                        AgentConversationControlErrorCode.CORRELATION_MISMATCH,
                        "watch request correlation mismatched",
                    )
            elif kind is AgentConversationWatchEventKindV1.TERMINAL_COMMITTED:
                value = decode_terminal_v1(event_payload)
                if value.deck_run_id != deck_run_id or value.session_id != session_id:
                    raise _error(
                        AgentConversationControlErrorCode.CORRELATION_MISMATCH,
                        "watch terminal correlation mismatched",
                    )
            else:
                value = _identity(event_payload)
        except AgentConversationControlError:
            raise
        except (TypeError, ValueError) as error:
            raise _error(
                AgentConversationControlErrorCode.INVALID_WATCH_EVENT, "watch event is invalid"
            ) from error
        events.append(AgentConversationWatchEventV1(sequence, kind, value))
        offset = end
    if offset != len(payload):
        raise _error(
            AgentConversationControlErrorCode.INVALID_WATCH_BATCH, "watch batch has trailing bytes"
        )
    return AgentConversationWatchBatchV1(
        tuple(events),
        next_cursor,
        high_watermark,
        bool(flags & 0b10),
        bool(flags & 0b01),
    )
