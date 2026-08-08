from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import socket
import stat
import struct
import tempfile
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import paraegox_sdk.console_client as console_client
from paraegox_sdk.agent_worker.control import (
    AgentConversationCancelOutcomeV1,
    AgentConversationControlKindV1,
    AgentConversationControlV1,
    AgentConversationOpenOutcomeV1,
    decode_control_v1,
)
from paraegox_sdk.agent_worker.protocol import (
    AgentConversationTerminalFailureV1,
    AgentConversationTerminalV1,
    TerminalOutcome,
    decode_request_v1,
)
from paraegox_sdk.console_client import (
    RuntimeAgentConversationClientError,
    RuntimeAgentConversationClientErrorCode,
    RuntimeAgentConversationClientV1,
)

PXAB_DIGEST_HEX = "9f1801332f8c4b590534fcff9a8ace9105ede142b0f3e60e66bbc009c24a8bc1"
PXAI_WIRE_HEX = (
    "5058414900010070000000f001000000"
    "31313131313131313131313131313131"
    "3232323232323232323232323232323232323232323232323232323232323232"
    "000000003b9aca000000008000000000"
    "bd80a1f59bb8c6801628e282e701d7e009f5a69faa58ee4b95730c9cdf63c835"
    "3333333333333333333333333333333333333333333333333333333333333333"
    "3333333333333333333333333333333333333333333333333333333333333333"
    "3333333333333333333333333333333333333333333333333333333333333333"
    "3333333333333333333333333333333333333333333333333333333333333333"
)

_PXAB_HEADER = struct.Struct(">4sHHIHHII32s16s16sQQHHI32s")
_PXAI_HEADER_BYTES = 112
_MAX_IPC_BODY_BYTES = 65_664
_GENERATION_TOKEN = bytes([0x5A]) * 32
_DECK_RUN_ID = bytes([0x44]) * 16
_SESSION_ID = bytes([0x11]) * 16
_DEADLINE_NANOS = 5_000_000_000
_OPERATION_TIMEOUT_NANOS = 2_000_000_000
_COMMAND_CAPACITY = 8
_INSPECTION_PROJECTION_ID = bytes([0x21]) * 16
_INSPECTION_CLOCK_REF = bytes([0x31]) * 16
_INSPECTION_TOKEN = bytes([0x5B]) * 32
_INSPECTION_REQUEST_SEED = bytes([0x6C]) * 16
_INSPECTION_TIMEOUT_NANOS = 2_000_000_000
_RUST_INSPECTION_FIXTURES = (
    Path(__file__).parents[2] / "crates/paraegox-inspection/tests/fixtures"
)


def _inspection_fixture(name: str) -> bytes:
    return bytes.fromhex((_RUST_INSPECTION_FIXTURES / name).read_text(encoding="ascii"))


def _rust_canonical_digest(domain: bytes, fields: tuple[bytes, ...]) -> bytes:
    digest = hashlib.sha256()
    digest.update(b"ParaEGOX\0canonical-digest")
    digest.update((1).to_bytes(2, "big"))
    digest.update(len(domain).to_bytes(4, "big"))
    digest.update(domain)
    for ordinal, value in enumerate(fields, start=1):
        digest.update(b"\x01")
        digest.update(ordinal.to_bytes(4, "big"))
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    digest.update(b"\xff")
    digest.update(len(fields).to_bytes(4, "big"))
    return digest.digest()


def _rust_bootstrap_wire(socket_path: Path) -> bytes:
    path = os.fsencode(socket_path)
    uid = os.geteuid()
    gid = os.getegid()
    digest = _rust_canonical_digest(
        b"paraegox.runtime.agent.developer-local.bootstrap.sha256.v1",
        (
            (1).to_bytes(2, "big"),
            uid.to_bytes(4, "big"),
            gid.to_bytes(4, "big"),
            _GENERATION_TOKEN,
            _DECK_RUN_ID,
            _SESSION_ID,
            _DEADLINE_NANOS.to_bytes(8, "big"),
            _OPERATION_TIMEOUT_NANOS.to_bytes(8, "big"),
            _COMMAND_CAPACITY.to_bytes(2, "big"),
            _MAX_IPC_BODY_BYTES.to_bytes(4, "big"),
            path,
        ),
    )
    return (
        _PXAB_HEADER.pack(
            b"PXAB",
            1,
            144,
            144 + len(path),
            len(path),
            1,
            uid,
            gid,
            _GENERATION_TOKEN,
            _DECK_RUN_ID,
            _SESSION_ID,
            _DEADLINE_NANOS,
            _OPERATION_TIMEOUT_NANOS,
            _COMMAND_CAPACITY,
            0,
            _MAX_IPC_BODY_BYTES,
            digest,
        )
        + path
    )


def _inspection_bootstrap_wire(socket_path: Path) -> bytes:
    bootstrap = console_client._InspectionBootstrapV2(
        socket_path=os.fsencode(socket_path),
        projection_id=_INSPECTION_PROJECTION_ID,
        generation_token=bytearray(_INSPECTION_TOKEN),
        server_uid=os.geteuid(),
        server_gid=os.getegid(),
        operation_timeout_nanos=_INSPECTION_TIMEOUT_NANOS,
        request_seed=bytearray(_INSPECTION_REQUEST_SEED),
    )
    return console_client._encode_inspection_bootstrap_v2(bootstrap)


def _write_bootstrap(path: Path, socket_path: Path, *, wire: bytes | None = None) -> None:
    path.write_bytes(_rust_bootstrap_wire(socket_path) if wire is None else wire)
    path.chmod(0o600)


def _write_inspection_bootstrap(path: Path, socket_path: Path) -> None:
    path.write_bytes(_inspection_bootstrap_wire(socket_path))
    path.chmod(0o600)


@contextmanager
def _private_directory() -> Iterator[Path]:
    created = Path(tempfile.mkdtemp(prefix="px-console-"))
    resolved = Path(os.path.realpath(created))
    resolved.chmod(0o700)
    try:
        yield resolved
    finally:
        shutil.rmtree(created)


@contextmanager
def _bound_private_socket(directory: Path) -> Iterator[Path]:
    socket_path = directory / "agent.sock"
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    endpoint.bind(os.fspath(socket_path))
    socket_path.chmod(0o600)
    try:
        yield socket_path
    finally:
        endpoint.close()
        with contextlib_suppress(FileNotFoundError):
            socket_path.unlink()


@contextmanager
def contextlib_suppress(*exceptions: type[BaseException]) -> Iterator[None]:
    try:
        yield
    except exceptions:
        pass


def test_bootstrap_and_ipc_codecs_match_rust_golden_vectors() -> None:
    fixed_bootstrap_digest = console_client._bootstrap_digest(
        server_uid=501,
        server_gid=20,
        generation_token=bytes([0x5A]) * 32,
        deck_run_id=_DECK_RUN_ID,
        session_id=_SESSION_ID,
        request_deadline_budget_nanos=5_000_000_000,
        operation_timeout_nanos=1_000_000_000,
        command_capacity=8,
        socket_path=b"/tmp/paraegox-agent.sock",
    )
    assert fixed_bootstrap_digest.hex() == PXAB_DIGEST_HEX

    frame = console_client._IpcFrame(
        kind=console_client._OperationKind.OPEN,
        status=console_client._ResponseStatus.OK,
        correlation=bytes([0x31]) * 16,
        generation_token=bytes([0x32]) * 32,
        operation_timeout_nanos=1_000_000_000,
        body=bytes([0x33]) * 128,
    )
    wire = console_client._encode_ipc_frame(b"PXAI", frame)
    assert wire.hex() == PXAI_WIRE_HEX
    assert console_client._decode_ipc_frame(b"PXAI", wire) == frame


def test_private_bootstrap_reader_checks_permissions_digest_and_socket() -> None:
    with _private_directory() as directory, _bound_private_socket(directory) as socket_path:
        bootstrap_path = directory / "agent.bootstrap"
        _write_bootstrap(bootstrap_path, socket_path)

        client = RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
        client.close()
        client.close()

        bootstrap_path.chmod(0o644)
        with pytest.raises(RuntimeAgentConversationClientError) as permissions:
            RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
        assert (
            permissions.value.code
            is RuntimeAgentConversationClientErrorCode.INSECURE_PERMISSIONS
        )

        bootstrap_path.chmod(0o600)
        tampered = bytearray(_rust_bootstrap_wire(socket_path))
        tampered[112] ^= 1
        _write_bootstrap(bootstrap_path, socket_path, wire=bytes(tampered))
        with pytest.raises(RuntimeAgentConversationClientError) as digest:
            RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
        assert digest.value.code is RuntimeAgentConversationClientErrorCode.DIGEST_MISMATCH

        _write_bootstrap(bootstrap_path, socket_path)
        socket_path.chmod(0o666)
        with pytest.raises(RuntimeAgentConversationClientError) as insecure_socket:
            RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
        assert insecure_socket.value.code is RuntimeAgentConversationClientErrorCode.INVALID_SOCKET


def test_bootstrap_reader_rejects_insecure_parent() -> None:
    with _private_directory() as directory, _bound_private_socket(directory) as socket_path:
        bootstrap_path = directory / "agent.bootstrap"
        _write_bootstrap(bootstrap_path, socket_path)
        directory.chmod(0o755)
        with pytest.raises(RuntimeAgentConversationClientError) as permissions:
            RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
        assert (
            permissions.value.code
            is RuntimeAgentConversationClientErrorCode.INSECURE_PERMISSIONS
        )
        directory.chmod(0o700)


def test_unknown_response_status_is_rejected_even_with_a_valid_digest() -> None:
    wire = bytearray(bytes.fromhex(PXAI_WIRE_HEX))
    wire[13] = 0xFF
    digest = _rust_canonical_digest(
        b"paraegox.runtime.agent.developer-local.ipc-frame.sha256.v1",
        (
            (1).to_bytes(2, "big"),
            (0xFF).to_bytes(2, "big"),
            bytes([0x31]) * 16,
            bytes([0x32]) * 32,
            (1_000_000_000).to_bytes(8, "big"),
            bytes([0x33]) * 128,
        ),
    )
    wire[80:112] = digest
    with pytest.raises(RuntimeAgentConversationClientError) as unknown:
        console_client._decode_ipc_frame(b"PXAI", bytes(wire))
    assert unknown.value.code is RuntimeAgentConversationClientErrorCode.UNKNOWN_RESPONSE_STATUS


async def _read_request(reader: asyncio.StreamReader) -> console_client._IpcFrame:
    header = await reader.readexactly(_PXAI_HEADER_BYTES)
    frame_length = int.from_bytes(header[8:12], "big")
    body = await reader.readexactly(frame_length - _PXAI_HEADER_BYTES)
    assert await reader.read(1) == b""
    return console_client._decode_ipc_frame(b"PXAI", header + body)


async def _write_response(
    writer: asyncio.StreamWriter,
    request: console_client._IpcFrame,
    body: bytes,
    *,
    correlation: bytes | None = None,
) -> None:
    response = console_client._IpcFrame(
        kind=request.kind,
        status=console_client._ResponseStatus.OK,
        correlation=request.correlation if correlation is None else correlation,
        generation_token=request.generation_token,
        operation_timeout_nanos=request.operation_timeout_nanos,
        body=body,
    )
    writer.write(console_client._encode_ipc_frame(b"PXAO", response))
    await writer.drain()
    if writer.can_write_eof():
        writer.write_eof()


async def _with_fake_server(
    scenario: Callable[
        [Path, Path, list[BaseException]], Awaitable[None]
    ],
) -> None:
    with _private_directory() as directory:
        socket_path = directory / "agent.sock"
        bootstrap_path = directory / "agent.bootstrap"
        errors: list[BaseException] = []
        tasks: set[asyncio.Task[None]] = set()

        def start_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            async def invoke() -> None:
                try:
                    await handler(reader, writer)
                except BaseException as cause:
                    errors.append(cause)
                finally:
                    writer.close()
                    with contextlib_suppress(Exception):
                        await writer.wait_closed()

            task = asyncio.create_task(invoke())
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]
        handler = scenario.handler  # type: ignore[attr-defined]
        server = await asyncio.start_unix_server(start_handler, path=socket_path)
        socket_path.chmod(0o600)
        _write_bootstrap(bootstrap_path, socket_path)
        try:
            await scenario(bootstrap_path, socket_path, errors)
        finally:
            server.close()
            await server.wait_closed()
            if tasks:
                await asyncio.gather(*tuple(tasks), return_exceptions=True)
        assert not errors


async def _with_fake_inspection_server(
    response_wire: bytes,
    scenario: Callable[
        [console_client.DeveloperLocalInspectionClientV2, list[bytes]], Awaitable[None]
    ],
) -> None:
    with _private_directory() as directory:
        socket_path = directory / "inspection.sock"
        bootstrap_path = directory / "inspection.pxib"
        requests: list[bytes] = []
        errors: list[BaseException] = []
        tasks: set[asyncio.Task[None]] = set()

        def start_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            async def invoke() -> None:
                try:
                    authenticated_request = await reader.readexactly(128)
                    assert await reader.read(1) == b""
                    assert authenticated_request[:32] == _INSPECTION_TOKEN
                    request = authenticated_request[32:]
                    requests.append(request)
                    assert request == _inspection_fixture("inspection_latest_request_v2.hex")
                    writer.write(len(response_wire).to_bytes(4, "big") + response_wire)
                    await writer.drain()
                    if writer.can_write_eof():
                        writer.write_eof()
                except BaseException as cause:
                    errors.append(cause)
                finally:
                    writer.close()
                    with contextlib_suppress(Exception):
                        await writer.wait_closed()

            task = asyncio.create_task(invoke())
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        server = await asyncio.start_unix_server(start_handler, path=socket_path)
        socket_path.chmod(0o600)
        _write_inspection_bootstrap(bootstrap_path, socket_path)
        client = console_client.DeveloperLocalInspectionClientV2.from_private_bootstrap_file(
            bootstrap_path
        )
        try:
            await scenario(client, requests)
        finally:
            client.close()
            server.close()
            await server.wait_closed()
            if tasks:
                await asyncio.gather(*tuple(tasks), return_exceptions=True)
        assert not errors


def test_successful_fake_uds_open_and_submit() -> None:
    async def scenario(
        bootstrap_path: Path,
        _socket_path: Path,
        errors: list[BaseException],
    ) -> None:
        client = RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
        assert await client.open() is AgentConversationOpenOutcomeV1.OPENED
        terminal = await client.submit("hello from Textual")
        assert terminal.outcome is TerminalOutcome.SUCCESS
        assert terminal.output == "echo: hello from Textual"
        client.close()
        assert not errors

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await _read_request(reader)
        if request.kind is console_client._OperationKind.OPEN:
            control = decode_control_v1(request.body)
            assert control.kind is AgentConversationControlKindV1.OPEN_REQUEST
            body = AgentConversationControlV1.open_result(
                _DECK_RUN_ID,
                _SESSION_ID,
                AgentConversationOpenOutcomeV1.OPENED,
            ).canonical_wire()
        else:
            assert request.kind is console_client._OperationKind.SUBMIT
            semantic = decode_request_v1(request.body)
            assert semantic.request_id == request.correlation
            body = AgentConversationTerminalV1.success(
                semantic,
                f"echo: {semantic.input}",
            ).canonical_wire()
        await _write_response(writer, request, body)

    scenario.handler = handler  # type: ignore[attr-defined]
    asyncio.run(_with_fake_server(scenario))


def test_exchange_rejects_response_correlation_mismatch() -> None:
    async def scenario(
        bootstrap_path: Path,
        _socket_path: Path,
        _errors: list[BaseException],
    ) -> None:
        client = RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
        with pytest.raises(RuntimeAgentConversationClientError) as mismatch:
            await client.open()
        assert mismatch.value.code is RuntimeAgentConversationClientErrorCode.CORRELATION_MISMATCH
        client.close()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await _read_request(reader)
        body = AgentConversationControlV1.open_result(
            _DECK_RUN_ID,
            _SESSION_ID,
            AgentConversationOpenOutcomeV1.OPENED,
        ).canonical_wire()
        wrong = bytes([request.correlation[0] ^ 1]) + request.correlation[1:]
        await _write_response(writer, request, body, correlation=wrong)

    scenario.handler = handler  # type: ignore[attr-defined]
    asyncio.run(_with_fake_server(scenario))


def test_open_accepts_only_opened_or_existing() -> None:
    async def scenario(
        bootstrap_path: Path,
        _socket_path: Path,
        _errors: list[BaseException],
    ) -> None:
        client = RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
        with pytest.raises(RuntimeAgentConversationClientError) as rejected:
            await client.open()
        assert rejected.value.code is RuntimeAgentConversationClientErrorCode.OPERATION_REJECTED
        client.close()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await _read_request(reader)
        body = AgentConversationControlV1.open_result(
            _DECK_RUN_ID,
            _SESSION_ID,
            AgentConversationOpenOutcomeV1.DECK_RUN_SEALED,
        ).canonical_wire()
        await _write_response(writer, request, body)

    scenario.handler = handler  # type: ignore[attr-defined]
    asyncio.run(_with_fake_server(scenario))


@pytest.mark.parametrize(
    "cancel_outcome",
    [
        AgentConversationCancelOutcomeV1.INTENT_RECORDED,
        AgentConversationCancelOutcomeV1.INTENT_ALREADY_RECORDED,
    ],
)
def test_cancel_pending_uses_the_exact_active_request(
    cancel_outcome: AgentConversationCancelOutcomeV1,
) -> None:
    async def run() -> None:
        submit_seen = asyncio.Event()
        cancel_seen = asyncio.Event()

        async def scenario(
            bootstrap_path: Path,
            _socket_path: Path,
            _errors: list[BaseException],
        ) -> None:
            client = RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
            submit = asyncio.create_task(client.submit("cancel this request"))
            await submit_seen.wait()
            result = await client.cancel_pending()
            assert result.outcome is cancel_outcome
            assert result.terminal is None
            terminal = await submit
            assert terminal.outcome is TerminalOutcome.FAILURE
            assert terminal.failure is AgentConversationTerminalFailureV1.CANCELLED_BEFORE_MODEL
            client.close()

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            request = await _read_request(reader)
            if request.kind is console_client._OperationKind.SUBMIT:
                semantic = decode_request_v1(request.body)
                submit_seen.set()
                await cancel_seen.wait()
                body = AgentConversationTerminalV1.failed(
                    semantic,
                    AgentConversationTerminalFailureV1.CANCELLED_BEFORE_MODEL,
                ).canonical_wire()
            else:
                assert request.kind is console_client._OperationKind.CANCEL
                control = decode_control_v1(request.body)
                assert control.kind is AgentConversationControlKindV1.CANCEL_REQUEST
                assert control.request_id is not None
                body = AgentConversationControlV1.cancel_result(
                    _DECK_RUN_ID,
                    _SESSION_ID,
                    control.request_id,
                    cancel_outcome,
                ).canonical_wire()
                cancel_seen.set()
            await _write_response(writer, request, body)

        scenario.handler = handler  # type: ignore[attr-defined]
        await _with_fake_server(scenario)

    asyncio.run(run())


def test_cancel_terminal_retires_the_original_submit() -> None:
    async def run() -> None:
        submit_seen = asyncio.Event()
        release_submit_handler = asyncio.Event()
        submitted: list[console_client.AgentConversationRequestV1] = []

        async def scenario(
            bootstrap_path: Path,
            _socket_path: Path,
            _errors: list[BaseException],
        ) -> None:
            client = RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
            submit = asyncio.create_task(client.submit("cancel before handoff"))
            await submit_seen.wait()

            result = await client.cancel_pending()
            assert result.outcome is AgentConversationCancelOutcomeV1.TERMINAL
            assert result.terminal is not None
            assert result.terminal.failure is (
                AgentConversationTerminalFailureV1.CANCELLED_BEFORE_MODEL
            )
            assert submit.done()
            with pytest.raises(asyncio.CancelledError):
                await submit
            with pytest.raises(RuntimeAgentConversationClientError) as no_pending:
                await client.cancel_pending()
            assert no_pending.value.code is (
                RuntimeAgentConversationClientErrorCode.NO_PENDING_REQUEST
            )
            release_submit_handler.set()
            client.close()

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            request = await _read_request(reader)
            if request.kind is console_client._OperationKind.SUBMIT:
                submitted.append(decode_request_v1(request.body))
                submit_seen.set()
                await release_submit_handler.wait()
                return

            assert request.kind is console_client._OperationKind.CANCEL
            control = decode_control_v1(request.body)
            assert control.request_id == submitted[0].request_id
            terminal = AgentConversationTerminalV1.failed(
                submitted[0],
                AgentConversationTerminalFailureV1.CANCELLED_BEFORE_MODEL,
            )
            body = AgentConversationControlV1.cancel_result(
                _DECK_RUN_ID,
                _SESSION_ID,
                submitted[0].request_id,
                AgentConversationCancelOutcomeV1.TERMINAL,
                terminal,
            ).canonical_wire()
            await _write_response(writer, request, body)

        scenario.handler = handler  # type: ignore[attr-defined]
        await _with_fake_server(scenario)

    asyncio.run(run())


@pytest.mark.parametrize(
    ("cancel_outcome", "safe_fragment"),
    [
        (AgentConversationCancelOutcomeV1.NOT_FOUND, "was not found"),
        (AgentConversationCancelOutcomeV1.SESSION_SEALED, "Session is sealed"),
    ],
)
def test_cancel_rejections_are_safe_and_retire_the_original_submit(
    cancel_outcome: AgentConversationCancelOutcomeV1,
    safe_fragment: str,
) -> None:
    async def run() -> None:
        submit_seen = asyncio.Event()
        release_submit_handler = asyncio.Event()
        submitted_request_ids: list[bytes] = []

        async def scenario(
            bootstrap_path: Path,
            socket_path: Path,
            _errors: list[BaseException],
        ) -> None:
            client = RuntimeAgentConversationClientV1.from_private_bootstrap_file(bootstrap_path)
            submit = asyncio.create_task(client.submit("reject cancellation"))
            await submit_seen.wait()

            with pytest.raises(RuntimeAgentConversationClientError) as rejected:
                await client.cancel_pending()
            assert rejected.value.code is RuntimeAgentConversationClientErrorCode.OPERATION_REJECTED
            assert safe_fragment in str(rejected.value)
            assert str(bootstrap_path) not in str(rejected.value)
            assert str(socket_path) not in str(rejected.value)
            assert _GENERATION_TOKEN.hex() not in str(rejected.value)
            assert submit.done()
            with pytest.raises(asyncio.CancelledError):
                await submit
            release_submit_handler.set()
            client.close()

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            request = await _read_request(reader)
            if request.kind is console_client._OperationKind.SUBMIT:
                submitted_request_ids.append(decode_request_v1(request.body).request_id)
                submit_seen.set()
                await release_submit_handler.wait()
                return

            control = decode_control_v1(request.body)
            assert request.kind is console_client._OperationKind.CANCEL
            assert control.request_id == submitted_request_ids[0]
            body = AgentConversationControlV1.cancel_result(
                _DECK_RUN_ID,
                _SESSION_ID,
                submitted_request_ids[0],
                cancel_outcome,
            ).canonical_wire()
            await _write_response(writer, request, body)

        scenario.handler = handler  # type: ignore[attr-defined]
        await _with_fake_server(scenario)

    asyncio.run(run())


def test_operation_timeout_does_not_wait_for_hung_writer_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NeverRespondingReader:
        async def readexactly(self, _count: int) -> bytes:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    class HangingCleanupWriter:
        def __init__(self) -> None:
            self.closed = False
            self.wait_closed_called = False

        def get_extra_info(self, name: str) -> object | None:
            return object() if name == "socket" else None

        def write(self, _wire: bytes) -> None:
            return None

        async def drain(self) -> None:
            return None

        def can_write_eof(self) -> bool:
            return True

        def write_eof(self) -> None:
            return None

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            self.wait_closed_called = True
            await asyncio.Event().wait()

    async def run() -> None:
        writer = HangingCleanupWriter()

        async def open_connection(*, path: bytes) -> tuple[NeverRespondingReader, object]:
            assert path == b"/private/runtime-agent.sock"
            return NeverRespondingReader(), writer

        bootstrap = console_client._BootstrapV1(
            socket_path=b"/private/runtime-agent.sock",
            generation_token=bytearray(_GENERATION_TOKEN),
            deck_run_id=_DECK_RUN_ID,
            session_id=_SESSION_ID,
            request_deadline_budget_nanos=_DEADLINE_NANOS,
            operation_timeout_nanos=5_000_000,
            command_capacity=_COMMAND_CAPACITY,
            server_uid=os.geteuid(),
            server_gid=os.getegid(),
        )
        client = RuntimeAgentConversationClientV1(bootstrap, bytes([0x6A]) * 32)
        monkeypatch.setattr(console_client.asyncio, "open_unix_connection", open_connection)
        monkeypatch.setattr(
            console_client,
            "_validate_socket_path",
            lambda _bootstrap: console_client._FileIdentity(1, 2, stat.S_IFSOCK | 0o600),
        )
        monkeypatch.setattr(
            console_client,
            "_peer_credentials",
            lambda _socket: (os.geteuid(), os.getegid()),
        )

        with pytest.raises(RuntimeAgentConversationClientError) as timed_out:
            await asyncio.wait_for(
                client._exchange(
                    console_client._OperationKind.OPEN,
                    bytes([0x31]) * 16,
                    AgentConversationControlV1.open_request(
                        _DECK_RUN_ID, _SESSION_ID
                    ).canonical_wire(),
                ),
                timeout=0.5,
            )
        assert timed_out.value.code is RuntimeAgentConversationClientErrorCode.OPERATION_TIMED_OUT
        assert writer.closed
        assert not writer.wait_closed_called
        client.close()

    asyncio.run(run())


def test_inspection_v2_decodes_all_rust_generated_fixtures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_bootstrap = console_client._InspectionBootstrapV2(
        socket_path=b"/tmp/inspection.sock",
        projection_id=_INSPECTION_PROJECTION_ID,
        generation_token=bytearray(_INSPECTION_TOKEN),
        server_uid=501,
        server_gid=20,
        operation_timeout_nanos=_INSPECTION_TIMEOUT_NANOS,
        request_seed=bytearray(_INSPECTION_REQUEST_SEED),
    )
    bootstrap_wire = _inspection_fixture("developer_local_inspection_bootstrap_v2.hex")
    assert console_client._encode_inspection_bootstrap_v2(expected_bootstrap) == bootstrap_wire
    monkeypatch.setattr(console_client.os, "geteuid", lambda: 501)
    monkeypatch.setattr(console_client.os, "getegid", lambda: 20)
    bootstrap = console_client._decode_inspection_bootstrap_v2(bootstrap_wire)
    assert bootstrap.socket_path == b"/tmp/inspection.sock"
    assert bootstrap.projection_id == _INSPECTION_PROJECTION_ID

    request_id = console_client._inspection_request_id_v2(bootstrap, 1)
    request = console_client._encode_inspection_latest_request_v2(
        request_id,
        _INSPECTION_PROJECTION_ID,
    )
    request_wire = _inspection_fixture("inspection_latest_request_v2.hex")
    assert request.canonical_wire == request_wire
    assert (
        bytes(bootstrap.generation_token) + request.canonical_wire
        == _inspection_fixture("developer_local_inspection_authenticated_request_v2.hex")
    )

    snapshot_wire = _inspection_fixture("local_inspection_snapshot_v2.hex")
    snapshot = console_client._decode_local_inspection_snapshot_v2(snapshot_wire)
    assert snapshot.canonical_wire == snapshot_wire
    assert snapshot.projection_revision == 7
    assert snapshot.overall is console_client.LocalInspectionOverallV1.UNKNOWN
    assert tuple(record.owner for record in snapshot.base_snapshot.records) == tuple(
        console_client.InspectionSourceOwnerV1
    )
    assert all(
        record.freshness is console_client.InspectionFreshnessV1.MISSING
        for record in snapshot.base_snapshot.records
    )
    assert snapshot.node.registration_epoch == 31
    assert snapshot.node.status_sequence == 41
    response_snapshot = console_client._decode_inspection_response_v2(
        _inspection_fixture("inspection_snapshot_response_v2.hex"),
        request,
    )
    assert response_snapshot == snapshot
    assert (
        console_client._decode_inspection_response_v2(
            _inspection_fixture("inspection_not_found_response_v2.hex"),
            request,
        )
        is None
    )
    with pytest.raises(FrozenInstanceError):
        setattr(snapshot, "overall", console_client.LocalInspectionOverallV1.READY)
    console_client.DeveloperLocalInspectionClientV2(bootstrap).close()


def test_inspection_v2_rejects_digest_owner_order_and_aggregate_corruption() -> None:
    request_wire = _inspection_fixture("inspection_latest_request_v2.hex")
    request = console_client._InspectionRequestV2(
        request_id=request_wire[16:32],
        projection_id=request_wire[32:48],
        request_digest=request_wire[64:96],
        canonical_wire=request_wire,
    )
    response = bytearray(_inspection_fixture("inspection_snapshot_response_v2.hex"))
    response[-1] ^= 1
    with pytest.raises(console_client.DeveloperLocalInspectionClientError) as digest:
        console_client._decode_inspection_response_v2(bytes(response), request)
    assert (
        digest.value.code
        is console_client.DeveloperLocalInspectionClientErrorCode.DIGEST_MISMATCH
    )

    correlation = bytearray(_inspection_fixture("inspection_snapshot_response_v2.hex"))
    correlation[24] ^= 1
    correlation[112:144] = _rust_canonical_digest(
        b"paraegox.inspection.protocol-response.v2",
        (bytes(correlation[:112]), bytes(correlation[144:])),
    )
    with pytest.raises(console_client.DeveloperLocalInspectionClientError) as mismatch:
        console_client._decode_inspection_response_v2(bytes(correlation), request)
    assert (
        mismatch.value.code
        is console_client.DeveloperLocalInspectionClientErrorCode.CORRELATION_MISMATCH
    )

    reserved = bytearray(_inspection_fixture("local_inspection_snapshot_v2.hex"))
    reserved[71] = 1
    reserved[80:112] = _rust_canonical_digest(
        b"paraegox.inspection.local-snapshot.v2",
        (bytes(reserved[:80]), bytes(reserved[112:])),
    )
    with pytest.raises(console_client.DeveloperLocalInspectionClientError) as noncanonical:
        console_client._decode_local_inspection_snapshot_v2(bytes(reserved))
    assert (
        noncanonical.value.code
        is console_client.DeveloperLocalInspectionClientErrorCode.PROTOCOL
    )

    aggregate = bytearray(_inspection_fixture("local_inspection_snapshot_v2.hex"))
    aggregate[70] = 1
    aggregate[80:112] = _rust_canonical_digest(
        b"paraegox.inspection.local-snapshot.v2",
        (bytes(aggregate[:80]), bytes(aggregate[112:])),
    )
    with pytest.raises(console_client.DeveloperLocalInspectionClientError) as invalid_aggregate:
        console_client._decode_local_inspection_snapshot_v2(bytes(aggregate))
    assert (
        invalid_aggregate.value.code
        is console_client.DeveloperLocalInspectionClientErrorCode.PROTOCOL
    )

    owner_order = bytearray(_inspection_fixture("local_inspection_snapshot_v2.hex"))
    base_start = 112
    owner_order[base_start + 112] = 2
    owner_order[base_start + 80 : base_start + 112] = _rust_canonical_digest(
        b"paraegox.inspection.local-snapshot.v1",
        (
            bytes(owner_order[base_start : base_start + 80]),
            bytes(owner_order[base_start + 112 : base_start + 592]),
        ),
    )
    owner_order[80:112] = _rust_canonical_digest(
        b"paraegox.inspection.local-snapshot.v2",
        (bytes(owner_order[:80]), bytes(owner_order[112:])),
    )
    with pytest.raises(console_client.DeveloperLocalInspectionClientError) as invalid_order:
        console_client._decode_local_inspection_snapshot_v2(bytes(owner_order))
    assert (
        invalid_order.value.code
        is console_client.DeveloperLocalInspectionClientErrorCode.PROTOCOL
    )

    node_coordinate = bytearray(_inspection_fixture("local_inspection_snapshot_v2.hex"))
    node_start = 112 + 592
    node_coordinate[node_start + 40 : node_start + 48] = bytes(8)
    node_coordinate[80:112] = _rust_canonical_digest(
        b"paraegox.inspection.local-snapshot.v2",
        (bytes(node_coordinate[:80]), bytes(node_coordinate[112:])),
    )
    with pytest.raises(console_client.DeveloperLocalInspectionClientError) as invalid_node:
        console_client._decode_local_inspection_snapshot_v2(bytes(node_coordinate))
    assert (
        invalid_node.value.code
        is console_client.DeveloperLocalInspectionClientErrorCode.PROTOCOL
    )


def test_inspection_v2_real_uds_reads_latest_exactly_once_and_closes() -> None:
    async def scenario(
        client: console_client.DeveloperLocalInspectionClientV2,
        requests: list[bytes],
    ) -> None:
        snapshot = await client.latest()
        assert snapshot.projection_revision == 7
        assert snapshot.node.registration_epoch == 31
        assert len(requests) == 1
        assert requests[0][:4] == b"PXIQ"
        assert requests[0][4:6] == (2).to_bytes(2, "big")
        assert requests[0][12] == 1
        assert not any(requests[0][48:64])

        with pytest.raises(console_client.DeveloperLocalInspectionClientError) as reused:
            await client.latest()
        assert (
            reused.value.code
            is console_client.DeveloperLocalInspectionClientErrorCode.ALREADY_USED
        )
        client.close()
        client.close()
        assert not any(client._bootstrap.generation_token)
        assert not any(client._bootstrap.request_seed)

    asyncio.run(
        _with_fake_inspection_server(
            _inspection_fixture("inspection_snapshot_response_v2.hex"),
            scenario,
        )
    )


def test_inspection_v2_not_found_and_closed_client_fail_closed() -> None:
    async def not_found_scenario(
        client: console_client.DeveloperLocalInspectionClientV2,
        requests: list[bytes],
    ) -> None:
        with pytest.raises(console_client.DeveloperLocalInspectionClientError) as unavailable:
            await client.latest()
        assert (
            unavailable.value.code
            is console_client.DeveloperLocalInspectionClientErrorCode.SNAPSHOT_UNAVAILABLE
        )
        assert len(requests) == 1

    asyncio.run(
        _with_fake_inspection_server(
            _inspection_fixture("inspection_not_found_response_v2.hex"),
            not_found_scenario,
        )
    )

    bootstrap = console_client._InspectionBootstrapV2(
        socket_path=b"/private/inspection.sock",
        projection_id=_INSPECTION_PROJECTION_ID,
        generation_token=bytearray(_INSPECTION_TOKEN),
        server_uid=os.geteuid(),
        server_gid=os.getegid(),
        operation_timeout_nanos=_INSPECTION_TIMEOUT_NANOS,
        request_seed=bytearray(_INSPECTION_REQUEST_SEED),
    )
    closed = console_client.DeveloperLocalInspectionClientV2(bootstrap)
    closed.close()
    closed.close()
    with pytest.raises(console_client.DeveloperLocalInspectionClientError) as error:
        asyncio.run(closed.latest())
    assert error.value.code is console_client.DeveloperLocalInspectionClientErrorCode.CLOSED
