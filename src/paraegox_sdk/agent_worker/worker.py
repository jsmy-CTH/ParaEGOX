"""Deterministic subordinate consumer of AgentConversationProtocol v1.

The worker owns only its bounded in-memory request ledger and terminal bytes.
It receives no Runtime object, raw Fabric handle, Tool/Memory surface, model
credential, or retry authority. A real provider is intentionally an integration
dependency injected through the narrow `ConversationModel` seam.
"""

from __future__ import annotations

import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO, Protocol

from .protocol import (
    AGENT_CONVERSATION_HEADER_BYTES,
    MAX_AGENT_CONVERSATION_FRAME_BYTES,
    MAX_AGENT_CONVERSATION_REQUESTS,
    AgentConversationProtocolError,
    AgentConversationProtocolErrorCode,
    AgentConversationTerminalFailureV1,
    AgentConversationTerminalV1,
    decode_request_v1,
)

_STREAM_LENGTH = struct.Struct(">I")


class ConversationModel(Protocol):
    """One text-only model turn; no provider credential is part of this API."""

    def respond(self, input: str, deadline_budget_nanos: int) -> str: ...


class DeterministicEchoConversationModel:
    """Offline fixture used before a real model-provider integration exists."""

    def respond(self, input: str, deadline_budget_nanos: int) -> str:
        del deadline_budget_nanos
        return f"echo: {input}"


@dataclass(frozen=True, slots=True)
class _RequestRecord:
    request_digest: bytes
    terminal_wire: bytes


class AgentConversationWorker:
    """Bounded subordinate request consumer with scoped byte-identical replay."""

    def __init__(
        self,
        model: ConversationModel,
        *,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        capacity: int = MAX_AGENT_CONVERSATION_REQUESTS,
    ) -> None:
        if not 1 <= capacity <= MAX_AGENT_CONVERSATION_REQUESTS:
            raise ValueError("conversation worker capacity is out of range")
        self._model = model
        self._clock_ns = clock_ns
        self._capacity = capacity
        self._records: dict[tuple[bytes, bytes, bytes], _RequestRecord] = {}

    def handle(self, request_wire: bytes) -> bytes:
        request = decode_request_v1(request_wire)
        request_scope = (
            request.deck_run_id,
            request.session_id,
            request.request_id,
        )
        previous = self._records.get(request_scope)
        if previous is not None:
            if previous.request_digest == request.request_digest:
                return previous.terminal_wire
            return AgentConversationTerminalV1.failed(
                request,
                AgentConversationTerminalFailureV1.REQUEST_CONFLICT,
            ).canonical_wire()
        if len(self._records) >= self._capacity:
            return AgentConversationTerminalV1.failed(
                request,
                AgentConversationTerminalFailureV1.CAPACITY_EXHAUSTED,
            ).canonical_wire()

        started_at = self._clock_ns()
        deadline = started_at + request.deadline_budget_nanos
        try:
            output = self._model.respond(request.input, request.deadline_budget_nanos)
            if self._clock_ns() >= deadline:
                terminal = AgentConversationTerminalV1.failed(
                    request,
                    AgentConversationTerminalFailureV1.DEADLINE_EXCEEDED,
                )
            else:
                terminal = AgentConversationTerminalV1.success(request, output)
        except (AgentConversationProtocolError, RuntimeError, ValueError, TypeError):
            terminal = AgentConversationTerminalV1.failed(
                request,
                AgentConversationTerminalFailureV1.MODEL_FAILED,
            )
        terminal_wire = terminal.canonical_wire()
        self._records[request_scope] = _RequestRecord(
            request.request_digest,
            terminal_wire,
        )
        return terminal_wire

    @property
    def retained_requests(self) -> int:
        return len(self._records)

    def run_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> int:
        """Consumes bounded length-prefixed canonical frames until clean EOF."""

        handled = 0
        while True:
            prefix = input_stream.read(_STREAM_LENGTH.size)
            if prefix == b"":
                return handled
            if len(prefix) != _STREAM_LENGTH.size:
                raise AgentConversationProtocolError(
                    AgentConversationProtocolErrorCode.TRUNCATED,
                    "conversation stream length prefix is truncated",
                )
            frame_length = _STREAM_LENGTH.unpack(prefix)[0]
            if not (
                AGENT_CONVERSATION_HEADER_BYTES
                <= frame_length
                <= MAX_AGENT_CONVERSATION_FRAME_BYTES
            ):
                raise AgentConversationProtocolError(
                    AgentConversationProtocolErrorCode.INVALID_FRAME_LENGTH,
                    "conversation stream frame length is invalid",
                )
            request_wire = _read_exact(input_stream, frame_length)
            terminal_wire = self.handle(request_wire)
            output_stream.write(_STREAM_LENGTH.pack(len(terminal_wire)))
            output_stream.write(terminal_wire)
            output_stream.flush()
            handled += 1


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if chunk == b"":
            raise AgentConversationProtocolError(
                AgentConversationProtocolErrorCode.TRUNCATED,
                "conversation stream frame is truncated",
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
