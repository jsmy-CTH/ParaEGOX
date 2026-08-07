from __future__ import annotations

import io
import struct

from paraegox_sdk.agent_worker.protocol import (
    AgentConversationRequestV1,
    AgentConversationTerminalFailureV1,
    TerminalOutcome,
    decode_terminal_v1,
)
from paraegox_sdk.agent_worker.worker import AgentConversationWorker


class CountingModel:
    def __init__(self) -> None:
        self.inputs: list[str] = []

    def respond(self, input: str, deadline_budget_nanos: int) -> str:
        assert deadline_budget_nanos > 0
        self.inputs.append(input)
        return f"model: {input}"


class FailingModel:
    def respond(self, input: str, deadline_budget_nanos: int) -> str:
        del input, deadline_budget_nanos
        raise RuntimeError("deterministic model failure")


def _request(
    input: str = "hello",
    *,
    deck_run_byte: int = 4,
    session_byte: int = 1,
    request_byte: int = 3,
    deadline_budget_nanos: int = 1_000,
) -> AgentConversationRequestV1:
    return AgentConversationRequestV1.create(
        bytes([deck_run_byte]) * 16,
        bytes([session_byte]) * 16,
        bytes([2]) * 16,
        bytes([request_byte]) * 16,
        deadline_budget_nanos,
        input,
    )


def test_worker_executes_once_and_replays_byte_identical_terminal() -> None:
    model = CountingModel()
    clock_values = iter([100, 101])
    worker = AgentConversationWorker(model, clock_ns=lambda: next(clock_values))
    request = _request()

    first = worker.handle(request.canonical_wire())
    replay = worker.handle(request.canonical_wire())

    assert replay == first
    assert model.inputs == ["hello"]
    terminal = decode_terminal_v1(first)
    assert terminal.outcome is TerminalOutcome.SUCCESS
    assert terminal.output == "model: hello"
    assert terminal.correlates(request)
    assert worker.retained_requests == 1


def test_same_request_id_with_different_digest_is_rejected_without_model_call() -> None:
    model = CountingModel()
    worker = AgentConversationWorker(model, clock_ns=lambda: 100)
    first = _request("first")
    conflict = _request("different")

    worker.handle(first.canonical_wire())
    terminal = decode_terminal_v1(worker.handle(conflict.canonical_wire()))

    assert model.inputs == ["first"]
    assert terminal.outcome is TerminalOutcome.FAILURE
    assert terminal.failure is AgentConversationTerminalFailureV1.REQUEST_CONFLICT
    assert terminal.correlates(conflict)
    assert worker.retained_requests == 1


def test_same_request_id_is_independent_across_deck_run_and_session_scopes() -> None:
    model = CountingModel()
    worker = AgentConversationWorker(model, clock_ns=lambda: 100, capacity=3)
    base = _request()
    another_session = _request(session_byte=5)
    another_deck_run = _request(deck_run_byte=6)

    terminals = [
        decode_terminal_v1(worker.handle(request.canonical_wire()))
        for request in (base, another_session, another_deck_run)
    ]

    assert model.inputs == ["hello", "hello", "hello"]
    assert all(terminal.outcome is TerminalOutcome.SUCCESS for terminal in terminals)
    assert all(
        terminal.correlates(request)
        for terminal, request in zip(
            terminals,
            (base, another_session, another_deck_run),
            strict=True,
        )
    )
    assert worker.retained_requests == 3


def test_model_failure_and_deadline_are_terminal_and_idempotent() -> None:
    failed_worker = AgentConversationWorker(FailingModel(), clock_ns=lambda: 100)
    failed_request = _request()
    failed_wire = failed_worker.handle(failed_request.canonical_wire())
    assert failed_worker.handle(failed_request.canonical_wire()) == failed_wire
    failed = decode_terminal_v1(failed_wire)
    assert failed.failure is AgentConversationTerminalFailureV1.MODEL_FAILED

    model = CountingModel()
    clock_values = iter([100, 1_100])
    deadline_worker = AgentConversationWorker(model, clock_ns=lambda: next(clock_values))
    deadline_request = _request(deadline_budget_nanos=1_000)
    deadline = decode_terminal_v1(deadline_worker.handle(deadline_request.canonical_wire()))
    assert deadline.failure is AgentConversationTerminalFailureV1.DEADLINE_EXCEEDED


def test_worker_capacity_fails_closed_without_evicting_prior_request() -> None:
    model = CountingModel()
    worker = AgentConversationWorker(model, clock_ns=lambda: 100, capacity=1)
    first = _request(request_byte=3)
    second = _request(request_byte=4)

    first_wire = worker.handle(first.canonical_wire())
    capacity = decode_terminal_v1(worker.handle(second.canonical_wire()))

    assert capacity.failure is AgentConversationTerminalFailureV1.CAPACITY_EXHAUSTED
    assert worker.handle(first.canonical_wire()) == first_wire
    assert model.inputs == ["hello"]
    assert worker.retained_requests == 1


def test_stream_consumer_crosses_real_framed_worker_boundary() -> None:
    model = CountingModel()
    worker = AgentConversationWorker(model, clock_ns=lambda: 100)
    request = _request()
    wire = request.canonical_wire()
    input_stream = io.BytesIO(struct.pack(">I", len(wire)) + wire)
    output_stream = io.BytesIO()

    assert worker.run_stream(input_stream, output_stream) == 1
    output_stream.seek(0)
    terminal_length = struct.unpack(">I", output_stream.read(4))[0]
    terminal_wire = output_stream.read(terminal_length)
    assert output_stream.read() == b""
    terminal = decode_terminal_v1(terminal_wire)
    assert terminal.output == "model: hello"
    assert terminal.correlates(request)
