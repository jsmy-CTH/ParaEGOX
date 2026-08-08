from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest
from textual.pilot import Pilot
from textual.widgets import Input, RichLog, Static

from paraegox_sdk.agent_worker.control import AgentConversationCancelOutcomeV1
from paraegox_sdk.agent_worker.protocol import (
    MAX_AGENT_CONVERSATION_INPUT_BYTES,
    AgentConversationRequestV1,
    AgentConversationTerminalFailureV1,
    AgentConversationTerminalV1,
)
from paraegox_sdk.console_client import RuntimeAgentConversationCancelResultV1
from paraegox_sdk.console_tui import ParaEGOXConsoleApp, _parse_arguments


def _request(input_text: str, sequence: int) -> AgentConversationRequestV1:
    return AgentConversationRequestV1.create(
        bytes([0x41]) * 16,
        bytes([0x42]) * 16,
        bytes([0x50 + sequence]) * 16,
        bytes([0x60 + sequence]) * 16,
        30_000_000_000,
        input_text,
    )


class FakeConversationClient:
    def __init__(
        self,
        *,
        output: str = "Hello from ParaEGOX",
        terminal_failure: AgentConversationTerminalFailureV1 | None = None,
        open_error: Exception | None = None,
        hold_submit: bool = False,
        cancel_outcome: AgentConversationCancelOutcomeV1 = (
            AgentConversationCancelOutcomeV1.INTENT_RECORDED
        ),
        release_submit_on_cancel: bool = False,
    ) -> None:
        self.output = output
        self.terminal_failure = terminal_failure
        self.open_error = open_error
        self.cancel_outcome = cancel_outcome
        self.release_submit_on_cancel = release_submit_on_cancel
        self.open_calls = 0
        self.submit_calls: list[str] = []
        self.cancel_calls = 0
        self.close_calls = 0
        self.submit_started = asyncio.Event()
        self.submit_release = asyncio.Event()
        if not hold_submit:
            self.submit_release.set()

    async def open(self) -> object:
        self.open_calls += 1
        if self.open_error is not None:
            raise self.open_error
        return object()

    async def submit(self, input_text: str) -> AgentConversationTerminalV1:
        self.submit_calls.append(input_text)
        self.submit_started.set()
        await self.submit_release.wait()
        request = _request(input_text, len(self.submit_calls))
        if self.terminal_failure is not None:
            return AgentConversationTerminalV1.failed(request, self.terminal_failure)
        return AgentConversationTerminalV1.success(request, self.output)

    async def cancel_pending(self) -> RuntimeAgentConversationCancelResultV1:
        self.cancel_calls += 1
        if self.release_submit_on_cancel:
            self.submit_release.set()
        terminal = None
        if self.cancel_outcome is AgentConversationCancelOutcomeV1.TERMINAL:
            input_text = self.submit_calls[-1]
            request = _request(input_text, len(self.submit_calls))
            terminal = (
                AgentConversationTerminalV1.failed(request, self.terminal_failure)
                if self.terminal_failure is not None
                else AgentConversationTerminalV1.success(request, self.output)
            )
        return RuntimeAgentConversationCancelResultV1(self.cancel_outcome, terminal)

    def close(self) -> None:
        self.close_calls += 1


async def _wait_until(
    pilot: Pilot[None],
    predicate: Callable[[], bool],
    *,
    attempts: int = 30,
) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError("Textual state did not reach the expected condition")


async def _enter(app: ParaEGOXConsoleApp, pilot: Pilot[None], value: str) -> None:
    chat_input = app.query_one("#chat-input", Input)
    chat_input.value = value
    chat_input.focus()
    await pilot.press("enter")
    await pilot.pause()


def test_console_connects_and_submits_one_successful_turn() -> None:
    async def scenario() -> None:
        client = FakeConversationClient(output="A typed reply")
        app = ParaEGOXConsoleApp(
            client,
            inspection_bootstrap_file=Path("/private/inspection.pxib"),
        )
        async with app.run_test(size=(100, 30)) as pilot:
            await _wait_until(pilot, lambda: app.connected)
            status = app.query_one("#connection-status", Static)
            inspection = app.query_one("#inspection-status", Static)
            assert str(status.content) == "Connection: connected · Request: idle"
            assert "snapshot not loaded" in str(inspection.content)

            await _enter(app, pilot, "hello")
            await _wait_until(pilot, lambda: "Agent: A typed reply" in app.transcript)

            assert client.open_calls == 1
            assert client.submit_calls == ["hello"]
            assert "You: hello" in app.transcript
            assert not app.conversation_pending
        assert client.close_calls == 1

    asyncio.run(scenario())


def test_console_renders_connection_and_terminal_failures_safely() -> None:
    async def connection_failure_scenario() -> None:
        client = FakeConversationClient(open_error=RuntimeError("owner unavailable"))
        app = ParaEGOXConsoleApp(client)
        async with app.run_test(size=(100, 30)) as pilot:
            await _wait_until(
                pilot,
                lambda: any("connection failed" in line for line in app.transcript),
            )
            assert not app.connected
            assert "owner unavailable" in app.transcript[-1]
            assert app.query_one("#chat-input", Input).disabled
        assert client.close_calls == 1

    async def terminal_failure_scenario() -> None:
        client = FakeConversationClient(
            terminal_failure=AgentConversationTerminalFailureV1.MODEL_OUTCOME_UNCERTAIN
        )
        app = ParaEGOXConsoleApp(client)
        async with app.run_test(size=(100, 30)) as pilot:
            await _wait_until(pilot, lambda: app.connected)
            await _enter(app, pilot, "do not replay this")
            await _wait_until(
                pilot,
                lambda: any("outcome is uncertain" in line for line in app.transcript),
            )
            assert any("did not replay" in line for line in app.transcript)
            assert not app.conversation_pending
        assert client.close_calls == 1

    asyncio.run(connection_failure_scenario())
    asyncio.run(terminal_failure_scenario())


def test_console_enforces_single_pending_request_and_supports_cancel() -> None:
    async def scenario() -> None:
        client = FakeConversationClient(
            terminal_failure=AgentConversationTerminalFailureV1.CANCELLED_BEFORE_MODEL,
            hold_submit=True,
        )
        app = ParaEGOXConsoleApp(client)
        async with app.run_test(size=(100, 30)) as pilot:
            await _wait_until(pilot, lambda: app.connected)
            await _enter(app, pilot, "first")
            await _wait_until(pilot, client.submit_started.is_set)
            assert app.conversation_pending

            await _enter(app, pilot, "second")
            assert client.submit_calls == ["first"]
            assert any("one request is already pending" in line for line in app.transcript)

            await _enter(app, pilot, "/cancel")
            await _wait_until(pilot, lambda: client.cancel_calls == 1)
            assert any("cancellation intent was recorded" in line for line in app.transcript)

            client.submit_release.set()
            await _wait_until(pilot, lambda: not app.conversation_pending)
            assert any("cancelled before the model" in line for line in app.transcript)
        assert client.close_calls == 1

    asyncio.run(scenario())


def test_console_consumes_cancel_terminal_once_and_retires_submit() -> None:
    async def scenario() -> None:
        client = FakeConversationClient(
            terminal_failure=AgentConversationTerminalFailureV1.CANCELLED_BEFORE_MODEL,
            hold_submit=True,
            cancel_outcome=AgentConversationCancelOutcomeV1.TERMINAL,
            release_submit_on_cancel=True,
        )
        app = ParaEGOXConsoleApp(client)
        async with app.run_test(size=(100, 30)) as pilot:
            await _wait_until(pilot, lambda: app.connected)
            await _enter(app, pilot, "cancel race")
            await _wait_until(pilot, client.submit_started.is_set)

            await _enter(app, pilot, "/cancel")
            await _wait_until(pilot, lambda: not app.conversation_pending)
            terminal_lines = [
                line for line in app.transcript if "cancelled before the model" in line
            ]
            assert terminal_lines == [
                "Agent request failed: The request was cancelled before the model started."
            ]
        assert client.close_calls == 1

    asyncio.run(scenario())


def test_console_help_clear_and_quit_are_local_commands() -> None:
    async def scenario() -> None:
        client = FakeConversationClient()
        app = ParaEGOXConsoleApp(client)
        async with app.run_test(size=(100, 30)) as pilot:
            await _wait_until(pilot, lambda: app.connected)
            await _enter(app, pilot, "/help")
            assert app.transcript[-1] == "System: commands — /help /clear /cancel /quit"

            await _enter(app, pilot, "/clear")
            assert app.transcript == ()
            assert app.query_one("#chat-log", RichLog).lines == []

            chat_input = app.query_one("#chat-input", Input)
            chat_input.value = "/quit"
            chat_input.focus()
            await pilot.press("enter")
            assert client.close_calls == 1
        assert client.close_calls == 1

    asyncio.run(scenario())


def test_console_rejects_utf8_input_above_protocol_limit() -> None:
    async def scenario() -> None:
        client = FakeConversationClient()
        app = ParaEGOXConsoleApp(client)
        async with app.run_test(size=(100, 30)) as pilot:
            await _wait_until(pilot, lambda: app.connected)
            oversized = "界" * (MAX_AGENT_CONVERSATION_INPUT_BYTES // 3 + 1)
            assert len(oversized.encode("utf-8")) > MAX_AGENT_CONVERSATION_INPUT_BYTES
            await _enter(app, pilot, oversized)
            assert client.submit_calls == []
            assert "exceeds the 16 KiB protocol limit" in app.transcript[-1]
        assert client.close_calls == 1

    asyncio.run(scenario())


def test_console_cli_accepts_only_explicit_absolute_bootstrap_paths(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime.pxab"
    inspection = tmp_path / "inspection.pxib"
    parsed = _parse_arguments(
        [
            "--runtime-bootstrap-file",
            str(runtime),
            "--inspection-bootstrap-file",
            str(inspection),
        ]
    )
    assert parsed.runtime_bootstrap_file == runtime
    assert parsed.inspection_bootstrap_file == inspection

    invalid_arguments = [
        [],
        ["--runtime-bootstrap-file", "relative.pxab"],
        ["--runtime-bootstrap-file", str(runtime), "unexpected"],
        [
            "--runtime-bootstrap-file",
            str(runtime),
            "--runtime-bootstrap-file",
            str(runtime),
        ],
        [
            "--runtime-bootstrap-file",
            str(runtime),
            "--inspection-bootstrap-file",
            str(runtime),
        ],
    ]
    for arguments in invalid_arguments:
        with pytest.raises(SystemExit) as captured:
            _parse_arguments(arguments)
        assert captured.value.code == 2
