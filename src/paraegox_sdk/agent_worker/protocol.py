"""Independent Python AgentConversationProtocol v1 codec.

The Rust contract crate owns the admitted protocol. This module independently
reconstructs its fixed bytes and canonical DeckRun-bound request digest for the
subordinate Python worker. It intentionally defines no Tool, Memory, model
credentials, Runtime handle, Fabric session, or transport retry policy.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum

AGENT_CONVERSATION_PROTOCOL_MAGIC = b"PXAC"
AGENT_CONVERSATION_PROTOCOL_VERSION = 1
AGENT_CONVERSATION_HEADER_BYTES = 128
MAX_AGENT_CONVERSATION_INPUT_BYTES = 16 * 1024
MAX_AGENT_CONVERSATION_OUTPUT_BYTES = 32 * 1024
MAX_AGENT_CONVERSATION_FRAME_BYTES = (
    AGENT_CONVERSATION_HEADER_BYTES + MAX_AGENT_CONVERSATION_OUTPUT_BYTES
)
MAX_AGENT_CONVERSATION_DEADLINE_BUDGET_NANOS = 300_000_000_000
MAX_AGENT_CONVERSATION_REQUESTS = 1_024

_HEADER = struct.Struct(">4sHHIBBHI16s16s16s16s32sQI")
_REQUEST_DIGEST_DOMAIN = b"paraegox.agent.conversation.request.sha256.v1"
_DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
_DIGEST_VERSION = 1
_FIELD_MARKER = 1
_END_MARKER = 0xFF
_REQUEST_KIND = 1
_TERMINAL_KIND = 2
_REQUEST_OUTCOME = 0
_TERMINAL_SUCCESS_OUTCOME = 1
_TERMINAL_FAILURE_OUTCOME = 2
_NO_TERMINAL_ERROR = 0
_RESERVED_FLAGS = 0

if _HEADER.size != AGENT_CONVERSATION_HEADER_BYTES:  # pragma: no cover
    raise RuntimeError("AgentConversationProtocol v1 header layout drifted")


class AgentConversationProtocolErrorCode(IntEnum):
    INVALID_IDENTITY = 1
    INPUT_EMPTY = 2
    INPUT_TOO_LARGE = 3
    OUTPUT_EMPTY = 4
    OUTPUT_TOO_LARGE = 5
    INVALID_UTF8 = 6
    DEADLINE_OUT_OF_RANGE = 7
    FRAME_TOO_LARGE = 8
    TRUNCATED = 9
    INVALID_MAGIC = 10
    UNSUPPORTED_VERSION = 11
    INVALID_HEADER_LENGTH = 12
    INVALID_FRAME_LENGTH = 13
    UNKNOWN_FRAME_KIND = 14
    RESERVED_BITS_SET = 15
    INVALID_REQUEST_FIELDS = 16
    INVALID_TERMINAL_FIELDS = 17
    INVALID_REQUEST_DIGEST = 18
    REQUEST_DIGEST_MISMATCH = 19
    UNKNOWN_TERMINAL_FAILURE = 20


class AgentConversationProtocolError(ValueError):
    """Stable fail-closed codec error with no recovery policy."""

    def __init__(self, code: AgentConversationProtocolErrorCode, message: str):
        super().__init__(message)
        self.code = code


class AgentConversationTerminalFailureV1(IntEnum):
    MODEL_FAILED = 1
    DEADLINE_EXCEEDED = 2
    REQUEST_CONFLICT = 3
    CAPACITY_EXHAUSTED = 4
    MODEL_OUTCOME_UNCERTAIN = 5
    CANCELLED_BEFORE_MODEL = 6


class TerminalOutcome(IntEnum):
    SUCCESS = _TERMINAL_SUCCESS_OUTCOME
    FAILURE = _TERMINAL_FAILURE_OUTCOME


def _error(
    code: AgentConversationProtocolErrorCode, message: str
) -> AgentConversationProtocolError:
    return AgentConversationProtocolError(code, message)


def _identity(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 16 or not any(value):
        raise _error(
            AgentConversationProtocolErrorCode.INVALID_IDENTITY,
            "conversation identity must contain 16 nonzero opaque bytes",
        )
    return value


def _deadline(value: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= MAX_AGENT_CONVERSATION_DEADLINE_BUDGET_NANOS
    ):
        raise _error(
            AgentConversationProtocolErrorCode.DEADLINE_OUT_OF_RANGE,
            "conversation deadline budget is out of range",
        )
    return value


def _utf8(value: str, maximum: int, *, output: bool) -> bytes:
    if not isinstance(value, str):
        raise _error(
            AgentConversationProtocolErrorCode.INVALID_UTF8,
            "conversation text must be a string",
        )
    encoded = value.encode("utf-8")
    if not encoded:
        code = (
            AgentConversationProtocolErrorCode.OUTPUT_EMPTY
            if output
            else AgentConversationProtocolErrorCode.INPUT_EMPTY
        )
        raise _error(code, "conversation text must not be empty")
    if len(encoded) > maximum:
        code = (
            AgentConversationProtocolErrorCode.OUTPUT_TOO_LARGE
            if output
            else AgentConversationProtocolErrorCode.INPUT_TOO_LARGE
        )
        raise _error(code, "conversation text exceeds its bound")
    return encoded


def _decode_utf8(payload: bytes, maximum: int, *, output: bool) -> str:
    if not payload:
        code = (
            AgentConversationProtocolErrorCode.OUTPUT_EMPTY
            if output
            else AgentConversationProtocolErrorCode.INPUT_EMPTY
        )
        raise _error(code, "conversation text must not be empty")
    if len(payload) > maximum:
        code = (
            AgentConversationProtocolErrorCode.OUTPUT_TOO_LARGE
            if output
            else AgentConversationProtocolErrorCode.INPUT_TOO_LARGE
        )
        raise _error(code, "conversation text exceeds its bound")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _error(
            AgentConversationProtocolErrorCode.INVALID_UTF8,
            "conversation text is not valid UTF-8",
        ) from error


def _canonical_digest(domain: bytes, fields: tuple[bytes, ...]) -> bytes:
    digest = hashlib.sha256()
    digest.update(_DIGEST_MAGIC)
    digest.update(_DIGEST_VERSION.to_bytes(2, "big"))
    digest.update(len(domain).to_bytes(4, "big"))
    digest.update(domain)
    for ordinal, field in enumerate(fields, start=1):
        digest.update(bytes([_FIELD_MARKER]))
        digest.update(ordinal.to_bytes(4, "big"))
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    digest.update(bytes([_END_MARKER]))
    digest.update(len(fields).to_bytes(4, "big"))
    return digest.digest()


def request_digest_v1(
    deck_run_id: bytes,
    session_id: bytes,
    turn_id: bytes,
    request_id: bytes,
    deadline_budget_nanos: int,
    input_bytes: bytes,
) -> bytes:
    return _canonical_digest(
        _REQUEST_DIGEST_DOMAIN,
        (
            _identity(deck_run_id),
            _identity(session_id),
            _identity(turn_id),
            _identity(request_id),
            _deadline(deadline_budget_nanos).to_bytes(8, "big"),
            input_bytes,
        ),
    )


@dataclass(frozen=True, slots=True)
class AgentConversationRequestV1:
    deck_run_id: bytes
    session_id: bytes
    turn_id: bytes
    request_id: bytes
    request_digest: bytes
    deadline_budget_nanos: int
    input: str

    @classmethod
    def create(
        cls,
        deck_run_id: bytes,
        session_id: bytes,
        turn_id: bytes,
        request_id: bytes,
        deadline_budget_nanos: int,
        input: str,
    ) -> AgentConversationRequestV1:
        input_bytes = _utf8(input, MAX_AGENT_CONVERSATION_INPUT_BYTES, output=False)
        digest = request_digest_v1(
            deck_run_id,
            session_id,
            turn_id,
            request_id,
            deadline_budget_nanos,
            input_bytes,
        )
        return cls(
            _identity(deck_run_id),
            _identity(session_id),
            _identity(turn_id),
            _identity(request_id),
            digest,
            _deadline(deadline_budget_nanos),
            input,
        )

    def canonical_wire(self) -> bytes:
        input_bytes = _utf8(self.input, MAX_AGENT_CONVERSATION_INPUT_BYTES, output=False)
        expected = request_digest_v1(
            self.deck_run_id,
            self.session_id,
            self.turn_id,
            self.request_id,
            self.deadline_budget_nanos,
            input_bytes,
        )
        if self.request_digest != expected:
            raise _error(
                AgentConversationProtocolErrorCode.REQUEST_DIGEST_MISMATCH,
                "conversation request digest mismatched",
            )
        return _encode_frame(
            _REQUEST_KIND,
            _REQUEST_OUTCOME,
            _NO_TERMINAL_ERROR,
            self.deck_run_id,
            self.session_id,
            self.turn_id,
            self.request_id,
            self.request_digest,
            self.deadline_budget_nanos,
            input_bytes,
        )


@dataclass(frozen=True, slots=True)
class AgentConversationTerminalV1:
    deck_run_id: bytes
    session_id: bytes
    turn_id: bytes
    request_id: bytes
    request_digest: bytes
    deadline_budget_nanos: int
    outcome: TerminalOutcome
    output: str | None = None
    failure: AgentConversationTerminalFailureV1 | None = None

    @classmethod
    def success(
        cls, request: AgentConversationRequestV1, output: str
    ) -> AgentConversationTerminalV1:
        _utf8(output, MAX_AGENT_CONVERSATION_OUTPUT_BYTES, output=True)
        return cls(
            request.deck_run_id,
            request.session_id,
            request.turn_id,
            request.request_id,
            request.request_digest,
            request.deadline_budget_nanos,
            TerminalOutcome.SUCCESS,
            output=output,
        )

    @classmethod
    def failed(
        cls,
        request: AgentConversationRequestV1,
        failure: AgentConversationTerminalFailureV1,
    ) -> AgentConversationTerminalV1:
        return cls(
            request.deck_run_id,
            request.session_id,
            request.turn_id,
            request.request_id,
            request.request_digest,
            request.deadline_budget_nanos,
            TerminalOutcome.FAILURE,
            failure=failure,
        )

    def canonical_wire(self) -> bytes:
        if self.outcome is TerminalOutcome.SUCCESS:
            if self.failure is not None or self.output is None:
                raise _error(
                    AgentConversationProtocolErrorCode.INVALID_TERMINAL_FIELDS,
                    "successful terminal fields are inconsistent",
                )
            payload = _utf8(
                self.output,
                MAX_AGENT_CONVERSATION_OUTPUT_BYTES,
                output=True,
            )
            terminal_error = _NO_TERMINAL_ERROR
        elif self.outcome is TerminalOutcome.FAILURE:
            if self.failure is None or self.output is not None:
                raise _error(
                    AgentConversationProtocolErrorCode.INVALID_TERMINAL_FIELDS,
                    "failed terminal fields are inconsistent",
                )
            payload = b""
            terminal_error = int(self.failure)
        else:  # pragma: no cover - enum construction already fences this
            raise _error(
                AgentConversationProtocolErrorCode.INVALID_TERMINAL_FIELDS,
                "terminal outcome is unknown",
            )
        return _encode_frame(
            _TERMINAL_KIND,
            int(self.outcome),
            terminal_error,
            self.deck_run_id,
            self.session_id,
            self.turn_id,
            self.request_id,
            self.request_digest,
            self.deadline_budget_nanos,
            payload,
        )

    def correlates(self, request: AgentConversationRequestV1) -> bool:
        return (
            self.deck_run_id == request.deck_run_id
            and self.session_id == request.session_id
            and self.turn_id == request.turn_id
            and self.request_id == request.request_id
            and self.request_digest == request.request_digest
            and self.deadline_budget_nanos == request.deadline_budget_nanos
        )


@dataclass(frozen=True, slots=True)
class _ParsedHeader:
    kind: int
    outcome: int
    terminal_error: int
    deck_run_id: bytes
    session_id: bytes
    turn_id: bytes
    request_id: bytes
    request_digest: bytes
    deadline_budget_nanos: int
    payload: bytes


def _parse_header(wire: bytes) -> _ParsedHeader:
    if not isinstance(wire, bytes):
        raise _error(
            AgentConversationProtocolErrorCode.TRUNCATED,
            "conversation frame must be immutable bytes",
        )
    if len(wire) < AGENT_CONVERSATION_HEADER_BYTES:
        raise _error(
            AgentConversationProtocolErrorCode.TRUNCATED,
            "conversation frame is truncated",
        )
    if len(wire) > MAX_AGENT_CONVERSATION_FRAME_BYTES:
        raise _error(
            AgentConversationProtocolErrorCode.FRAME_TOO_LARGE,
            "conversation frame exceeds its bound",
        )
    (
        magic,
        version,
        header_bytes,
        frame_length,
        kind,
        outcome,
        terminal_error,
        flags,
        deck_run_id,
        session_id,
        turn_id,
        request_id,
        request_digest,
        deadline_budget_nanos,
        payload_length,
    ) = _HEADER.unpack_from(wire)
    if magic != AGENT_CONVERSATION_PROTOCOL_MAGIC:
        raise _error(
            AgentConversationProtocolErrorCode.INVALID_MAGIC,
            "conversation frame magic mismatched",
        )
    if version != AGENT_CONVERSATION_PROTOCOL_VERSION:
        raise _error(
            AgentConversationProtocolErrorCode.UNSUPPORTED_VERSION,
            "conversation protocol version is unsupported",
        )
    if header_bytes != AGENT_CONVERSATION_HEADER_BYTES:
        raise _error(
            AgentConversationProtocolErrorCode.INVALID_HEADER_LENGTH,
            "conversation header length is invalid",
        )
    if frame_length != len(wire) or header_bytes + payload_length != len(wire):
        raise _error(
            AgentConversationProtocolErrorCode.INVALID_FRAME_LENGTH,
            "conversation frame length is invalid",
        )
    if kind not in {_REQUEST_KIND, _TERMINAL_KIND}:
        raise _error(
            AgentConversationProtocolErrorCode.UNKNOWN_FRAME_KIND,
            "conversation frame kind is unknown",
        )
    if flags != _RESERVED_FLAGS:
        raise _error(
            AgentConversationProtocolErrorCode.RESERVED_BITS_SET,
            "conversation reserved flags are nonzero",
        )
    _identity(deck_run_id)
    _identity(session_id)
    _identity(turn_id)
    _identity(request_id)
    if not any(request_digest):
        raise _error(
            AgentConversationProtocolErrorCode.INVALID_REQUEST_DIGEST,
            "conversation request digest is all-zero",
        )
    return _ParsedHeader(
        kind,
        outcome,
        terminal_error,
        deck_run_id,
        session_id,
        turn_id,
        request_id,
        request_digest,
        _deadline(deadline_budget_nanos),
        wire[header_bytes:],
    )


def decode_request_v1(wire: bytes) -> AgentConversationRequestV1:
    header = _parse_header(wire)
    if (
        header.kind != _REQUEST_KIND
        or header.outcome != _REQUEST_OUTCOME
        or header.terminal_error != _NO_TERMINAL_ERROR
    ):
        raise _error(
            AgentConversationProtocolErrorCode.INVALID_REQUEST_FIELDS,
            "conversation request fields are invalid",
        )
    input = _decode_utf8(
        header.payload,
        MAX_AGENT_CONVERSATION_INPUT_BYTES,
        output=False,
    )
    expected = request_digest_v1(
        header.deck_run_id,
        header.session_id,
        header.turn_id,
        header.request_id,
        header.deadline_budget_nanos,
        header.payload,
    )
    if expected != header.request_digest:
        raise _error(
            AgentConversationProtocolErrorCode.REQUEST_DIGEST_MISMATCH,
            "conversation request digest mismatched",
        )
    return AgentConversationRequestV1(
        header.deck_run_id,
        header.session_id,
        header.turn_id,
        header.request_id,
        header.request_digest,
        header.deadline_budget_nanos,
        input,
    )


def decode_terminal_v1(wire: bytes) -> AgentConversationTerminalV1:
    header = _parse_header(wire)
    if header.kind != _TERMINAL_KIND:
        raise _error(
            AgentConversationProtocolErrorCode.INVALID_TERMINAL_FIELDS,
            "conversation terminal fields are invalid",
        )
    if header.outcome == _TERMINAL_SUCCESS_OUTCOME and header.terminal_error == _NO_TERMINAL_ERROR:
        output = _decode_utf8(
            header.payload,
            MAX_AGENT_CONVERSATION_OUTPUT_BYTES,
            output=True,
        )
        return AgentConversationTerminalV1(
            header.deck_run_id,
            header.session_id,
            header.turn_id,
            header.request_id,
            header.request_digest,
            header.deadline_budget_nanos,
            TerminalOutcome.SUCCESS,
            output=output,
        )
    if header.outcome == _TERMINAL_FAILURE_OUTCOME and not header.payload:
        try:
            failure = AgentConversationTerminalFailureV1(header.terminal_error)
        except ValueError as error:
            raise _error(
                AgentConversationProtocolErrorCode.UNKNOWN_TERMINAL_FAILURE,
                "conversation terminal failure is unknown",
            ) from error
        return AgentConversationTerminalV1(
            header.deck_run_id,
            header.session_id,
            header.turn_id,
            header.request_id,
            header.request_digest,
            header.deadline_budget_nanos,
            TerminalOutcome.FAILURE,
            failure=failure,
        )
    raise _error(
        AgentConversationProtocolErrorCode.INVALID_TERMINAL_FIELDS,
        "conversation terminal fields are invalid",
    )


def _encode_frame(
    kind: int,
    outcome: int,
    terminal_error: int,
    deck_run_id: bytes,
    session_id: bytes,
    turn_id: bytes,
    request_id: bytes,
    request_digest: bytes,
    deadline_budget_nanos: int,
    payload: bytes,
) -> bytes:
    _identity(deck_run_id)
    _identity(session_id)
    _identity(turn_id)
    _identity(request_id)
    if (
        not isinstance(request_digest, bytes)
        or len(request_digest) != 32
        or not any(request_digest)
    ):
        raise _error(
            AgentConversationProtocolErrorCode.INVALID_REQUEST_DIGEST,
            "conversation request digest must contain 32 nonzero bytes",
        )
    _deadline(deadline_budget_nanos)
    frame_length = AGENT_CONVERSATION_HEADER_BYTES + len(payload)
    return (
        _HEADER.pack(
            AGENT_CONVERSATION_PROTOCOL_MAGIC,
            AGENT_CONVERSATION_PROTOCOL_VERSION,
            AGENT_CONVERSATION_HEADER_BYTES,
            frame_length,
            kind,
            outcome,
            terminal_error,
            _RESERVED_FLAGS,
            deck_run_id,
            session_id,
            turn_id,
            request_id,
            request_digest,
            deadline_budget_nanos,
            len(payload),
        )
        + payload
    )
