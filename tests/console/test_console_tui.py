from __future__ import annotations

import asyncio
import fcntl
import importlib.util
import os
import struct
import subprocess
import sys
import termios
import tty
from collections.abc import Callable
from pathlib import Path

import pytest
from textual.pilot import Pilot
from textual.widgets import Input, RichLog, Static

import paraegox_sdk.console_client as console_client
import paraegox_sdk.console_tui as console_tui
from paraegox_sdk.agent_worker.control import AgentConversationCancelOutcomeV1
from paraegox_sdk.agent_worker.protocol import (
    MAX_AGENT_CONVERSATION_INPUT_BYTES,
    AgentConversationRequestV1,
    AgentConversationTerminalFailureV1,
    AgentConversationTerminalV1,
)
from paraegox_sdk.console_client import RuntimeAgentConversationCancelResultV1
from paraegox_sdk.console_tui import ParaEGOXConsoleApp, _parse_arguments

_SMOKE_SPEC = importlib.util.spec_from_file_location(
    "paraegox_macos_textual_smoke",
    Path(__file__).parents[2] / "scripts" / "smoke_macos_textual_chat.py",
)
if _SMOKE_SPEC is None or _SMOKE_SPEC.loader is None:
    raise RuntimeError("unable to load the macOS Textual smoke harness")
macos_textual_smoke = importlib.util.module_from_spec(_SMOKE_SPEC)
_SMOKE_SPEC.loader.exec_module(macos_textual_smoke)


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


def _inspection_snapshot() -> console_client.LocalInspectionSnapshotV2:
    records = tuple(
        console_client.LocalInspectionRecordV1(
            owner=owner,
            freshness=console_client.InspectionFreshnessV1.MISSING,
            subject_ref=bytes([0x40 + int(owner)]) * 16,
            coordinate=None,
            observed_at_nanos=None,
            valid_until_nanos=None,
            liveness=console_client.InspectionLivenessV1.UNKNOWN,
            readiness=console_client.InspectionReadinessV1.UNKNOWN,
            health=console_client.InspectionHealthV1.UNKNOWN,
            feature_support=console_client.InspectionFeatureSupportV1.UNKNOWN,
            reason=console_client.InspectionReasonV1.SOURCE_MISSING,
            owner_fact_digest=None,
        )
        for owner in console_client.InspectionSourceOwnerV1
    )
    base = console_client.LocalInspectionSnapshotV1(
        projection_id=bytes([0x21]) * 16,
        observation_clock_ref=bytes([0x31]) * 16,
        projection_revision=7,
        projected_at_nanos=150,
        overall=console_client.LocalInspectionOverallV1.UNKNOWN,
        records=(records[0], records[1], records[2], records[3], records[4]),
        projection_digest=bytes([0x51]) * 32,
        canonical_wire=bytes(592),
    )
    node = console_client.NodeInspectionRecordV2(
        freshness=console_client.InspectionFreshnessV1.FRESH,
        node_ref=bytes([0x61]) * 16,
        node_incarnation_ref=bytes([0x62]) * 16,
        registration_epoch=31,
        status_sequence=41,
        observed_at_nanos=100,
        valid_until_nanos=200,
        liveness=console_client.InspectionLivenessV1.LIVE,
        readiness=console_client.InspectionReadinessV1.READY,
        health=console_client.InspectionHealthV1.HEALTHY,
        feature_support=console_client.InspectionFeatureSupportV1.ALL_REQUIRED_SUPPORTED,
        reason=console_client.InspectionReasonV1.NONE,
        node_status_digest=bytes([0x63]) * 32,
    )
    return console_client.LocalInspectionSnapshotV2(
        base_snapshot=base,
        node=node,
        overall=console_client.LocalInspectionOverallV1.UNKNOWN,
        projection_digest=bytes([0x71]) * 32,
        canonical_wire=bytes(832),
    )


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
            inspection_snapshot=_inspection_snapshot(),
        )
        async with app.run_test(size=(100, 30)) as pilot:
            await _wait_until(pilot, lambda: app.connected)
            status = app.query_one("#connection-status", Static)
            inspection = app.query_one("#inspection-status", Static)
            assert str(status.content) == "Connection: connected · Request: idle"
            assert str(inspection.content).splitlines() == [
                (
                    "Node-local startup snapshot UNKNOWN r7 | NodeDaemon ready · "
                    "registration e31 · status s41"
                ),
                "Authority missing | Deployment missing | Runtime missing",
                "Fabric missing | Agent missing | health unreported",
            ]

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


def test_console_ctrl_c_binding_closes_client_and_exits() -> None:
    async def scenario() -> None:
        client = FakeConversationClient()
        app = ParaEGOXConsoleApp(client)
        async with app.run_test(size=(100, 30)) as pilot:
            await _wait_until(pilot, lambda: app.connected)

            await pilot.press("ctrl+c")
            await pilot.pause()

            assert client.close_calls == 1
            assert app.return_code == 0
        assert client.close_calls == 1

    asyncio.run(scenario())


def test_console_real_pty_ctrl_c_drains_teardown_and_exits() -> None:
    child_code = (
        "from paraegox_sdk.console_tui import ParaEGOXConsoleApp\n"
        "class Client:\n"
        "    def __init__(self): self.close_calls = 0\n"
        "    async def open(self): return object()\n"
        "    async def submit(self, input_text): raise AssertionError(input_text)\n"
        "    async def cancel_pending(self): raise AssertionError('unexpected cancel')\n"
        "    def close(self): self.close_calls += 1\n"
        "client = Client()\n"
        "app = ParaEGOXConsoleApp(client)\n"
        "app.run()\n"
        "print(f'PX_REAL_PTY_EXIT:{app.return_code}:{client.close_calls}', flush=True)\n"
    )
    master_fd, slave_fd = os.openpty()
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    environment = os.environ.copy()
    environment["TERM"] = "xterm-256color"
    environment.pop("TEXTUAL_ALLOW_SIGNALS", None)
    process = subprocess.Popen(
        [sys.executable, "-c", child_code],
        cwd=Path(__file__).parents[2],
        env=environment,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        start_new_session=True,
    )
    os.close(slave_fd)
    capture = bytearray()
    try:
        macos_textual_smoke._read_until(
            master_fd,
            process,
            capture,
            b"System: connected",
            5.0,
        )
        assert termios.tcgetattr(master_fd)[tty.LFLAG] & termios.ISIG == 0

        os.write(master_fd, b"\x03")
        macos_textual_smoke._wait_for_exit(master_fd, process, capture, 5.0)

        assert b"PX_REAL_PTY_EXIT:0:1" in capture
        assert macos_textual_smoke._TEXTUAL_TERMINAL_RESTORE in capture
    finally:
        macos_textual_smoke._stop_process(process)
        os.close(master_fd)


def test_console_smoke_exit_wait_keeps_timeout_and_nonzero_fail_closed() -> None:
    class RunningProcess:
        returncode = None

        @staticmethod
        def poll() -> None:
            return None

    capture = bytearray()
    reader_fd, writer_fd = os.pipe()
    try:
        os.write(writer_fd, b"PX_TEXTUAL_TEARDOWN_STARTED")
        with pytest.raises(TimeoutError, match="Textual did not restore"):
            macos_textual_smoke._wait_for_exit(
                reader_fd,
                RunningProcess(),
                capture,
                0.05,
            )
    finally:
        os.close(writer_fd)
        os.close(reader_fd)
    assert b"PX_TEXTUAL_TEARDOWN_STARTED" in capture

    reader_fd, writer_fd = os.pipe()
    try:
        with pytest.raises(TimeoutError, match="Rust parent did not join"):
            macos_textual_smoke._wait_for_exit(
                reader_fd,
                RunningProcess(),
                bytearray(macos_textual_smoke._TEXTUAL_TERMINAL_RESTORE),
                0.05,
            )
    finally:
        os.close(writer_fd)
        os.close(reader_fd)

    class FailedProcess:
        returncode = 7

        @staticmethod
        def poll() -> int:
            return 7

    reader_fd, writer_fd = os.pipe()
    os.close(writer_fd)
    try:
        with pytest.raises(RuntimeError, match="unsuccessfully with code 7"):
            macos_textual_smoke._wait_for_exit(
                reader_fd,
                FailedProcess(),
                bytearray(),
                0.05,
            )
    finally:
        os.close(reader_fd)


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


def test_startup_inspection_loader_reads_once_and_closes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    snapshot = _inspection_snapshot()

    class FakeInspectionClient:
        def __init__(self) -> None:
            self.latest_calls = 0
            self.close_calls = 0

        async def latest(self) -> console_client.LocalInspectionSnapshotV2:
            self.latest_calls += 1
            return snapshot

        def close(self) -> None:
            self.close_calls += 1

    client = FakeInspectionClient()
    monkeypatch.setattr(
        console_tui.DeveloperLocalInspectionClientV2,
        "from_private_bootstrap_file",
        lambda _path: client,
    )
    loaded = console_tui._load_inspection_snapshot_once(tmp_path / "inspection.pxib")
    assert loaded is snapshot
    assert client.latest_calls == 1
    assert client.close_calls == 1


def test_inspection_startup_failure_closes_agent_client_before_ui(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent_client = FakeConversationClient()

    class RuntimeClientFactory:
        @staticmethod
        def from_private_bootstrap_file(_path: Path) -> FakeConversationClient:
            return agent_client

    def fail_inspection(_path: Path) -> console_client.LocalInspectionSnapshotV2:
        raise console_client.DeveloperLocalInspectionClientError(
            console_client.DeveloperLocalInspectionClientErrorCode.SNAPSHOT_UNAVAILABLE,
            "DeveloperLocal Inspection v2 startup snapshot is unavailable",
        )

    monkeypatch.setattr(
        console_tui,
        "RuntimeAgentConversationClientV1",
        RuntimeClientFactory,
    )
    monkeypatch.setattr(console_tui, "_load_inspection_snapshot_once", fail_inspection)
    with pytest.raises(SystemExit) as captured:
        console_tui.main(
            [
                "--runtime-bootstrap-file",
                str(tmp_path / "runtime.pxab"),
                "--inspection-bootstrap-file",
                str(tmp_path / "inspection.pxib"),
            ]
        )
    assert agent_client.close_calls == 1
    assert "startup snapshot is unavailable" in str(captured.value)
    assert str(tmp_path) not in str(captured.value)
