"""Typed DeveloperLocal console client for Runtime-owned Agent conversations.

The Rust Runtime owns the PXAB bootstrap and PXAI/PXAO Unix-socket protocol.
This module is the Python console's strict, no-retry consumer of that boundary.
It deliberately reuses the admitted PXAC request, terminal, and control codecs;
it does not own Runtime, Fabric, AgentService, model, or credential lifecycle.
"""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import hmac
import os
import posixpath
import secrets
import socket
import stat
import struct
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

from .agent_worker.control import (
    AgentConversationCancelOutcomeV1,
    AgentConversationControlKindV1,
    AgentConversationControlV1,
    AgentConversationOpenOutcomeV1,
    decode_control_v1,
)
from .agent_worker.protocol import (
    AgentConversationRequestV1,
    AgentConversationTerminalV1,
    decode_terminal_v1,
)

_PXAB_MAGIC = b"PXAB"
_PXAI_REQUEST_MAGIC = b"PXAI"
_PXAI_RESPONSE_MAGIC = b"PXAO"
_IPC_VERSION = 1
_PXAB_HEADER_BYTES = 144
_PXAI_HEADER_BYTES = 112
_MAX_BOOTSTRAP_PATH_BYTES = 512
_MAX_BOOTSTRAP_FRAME_BYTES = _PXAB_HEADER_BYTES + _MAX_BOOTSTRAP_PATH_BYTES
_MAX_IPC_BODY_BYTES = 128 + 64 * 1024
_MAX_IPC_FRAME_BYTES = _PXAI_HEADER_BYTES + _MAX_IPC_BODY_BYTES
_MAX_UNIX_SOCKET_PATH_BYTES = 103
_MAX_REQUEST_DEADLINE_BUDGET_NANOS = 300_000_000_000
_MAX_OPERATION_TIMEOUT_NANOS = 120_000_000_000
_MAX_COMMAND_CAPACITY = 32
_BOOTSTRAP_MODE = 0o600
_SOCKET_MODE = 0o600
_PRIVATE_DIRECTORY_MODES = frozenset({0o700, 0o2750})

_PXAB_DIGEST_DOMAIN = b"paraegox.runtime.agent.developer-local.bootstrap.sha256.v1"
_PXAI_FRAME_DIGEST_DOMAIN = b"paraegox.runtime.agent.developer-local.ipc-frame.sha256.v1"
_PXAI_CORRELATION_DOMAIN = b"paraegox.runtime.agent.developer-local.correlation.sha256.v1"
_TURN_ID_DOMAIN = b"paraegox.tui.local-chat.turn-id.sha256.v1"
_REQUEST_ID_DOMAIN = b"paraegox.tui.local-chat.request-id.sha256.v1"
_DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
_DIGEST_VERSION = 1

_PXAB_HEADER = struct.Struct(">4sHHIHHII32s16s16sQQHHI32s")
_PXAI_HEADER = struct.Struct(">4sHHIBBH16s32sQII32s")

if _PXAB_HEADER.size != _PXAB_HEADER_BYTES:  # pragma: no cover
    raise RuntimeError("PXAB v1 header layout drifted")
if _PXAI_HEADER.size != _PXAI_HEADER_BYTES:  # pragma: no cover
    raise RuntimeError("PXAI v1 header layout drifted")


class RuntimeAgentConversationClientErrorCode(IntEnum):
    """Stable, display-safe failure categories for the console boundary."""

    INVALID_PATH = 1
    SYMLINK_REJECTED = 2
    INSECURE_PERMISSIONS = 3
    BOOTSTRAP_OPEN_FAILED = 4
    INVALID_BOOTSTRAP = 5
    DIGEST_MISMATCH = 6
    PEER_CREDENTIALS_MISMATCH = 7
    INVALID_SOCKET = 8
    ENDPOINT_IDENTITY_CHANGED = 9
    ENTROPY_UNAVAILABLE = 10
    CLOSED = 11
    REQUEST_PENDING = 12
    NO_PENDING_REQUEST = 13
    SEQUENCE_EXHAUSTED = 14
    INVALID_FRAME = 15
    UNKNOWN_OPERATION = 16
    UNKNOWN_RESPONSE_STATUS = 17
    CORRELATION_MISMATCH = 18
    AUTHENTICATION_FAILED = 19
    OWNER_UNAVAILABLE = 20
    GENERATION_RETIRED = 21
    OPERATION_REJECTED = 22
    OPERATION_TIMED_OUT = 23
    OVERLOADED = 24
    PROTOCOL = 25
    RESPONSE_KIND_MISMATCH = 26
    IO = 27


class RuntimeAgentConversationClientError(RuntimeError):
    """Fail-closed client error that never embeds a capability path or token."""

    def __init__(
        self,
        code: RuntimeAgentConversationClientErrorCode,
        message: str,
    ) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RuntimeAgentConversationCancelResultV1:
    """Usable cancel result after terminal and rejection outcomes are resolved."""

    outcome: AgentConversationCancelOutcomeV1
    terminal: AgentConversationTerminalV1 | None = None

    def __post_init__(self) -> None:
        terminal_expected = self.outcome is AgentConversationCancelOutcomeV1.TERMINAL
        if terminal_expected != (self.terminal is not None) or self.outcome not in {
            AgentConversationCancelOutcomeV1.INTENT_RECORDED,
            AgentConversationCancelOutcomeV1.INTENT_ALREADY_RECORDED,
            AgentConversationCancelOutcomeV1.TERMINAL,
        }:
            raise ValueError("Runtime Agent cancellation result is inconsistent")


def _error(
    code: RuntimeAgentConversationClientErrorCode,
    message: str,
) -> RuntimeAgentConversationClientError:
    return RuntimeAgentConversationClientError(code, message)


class _OperationKind(IntEnum):
    OPEN = 1
    SUBMIT = 2
    GET = 3
    WATCH = 4
    CANCEL = 5


class _ResponseStatus(IntEnum):
    OK = 0
    MALFORMED = 1
    AUTHENTICATION_FAILED = 2
    OWNER_UNAVAILABLE = 3
    GENERATION_RETIRED = 4
    OPERATION_REJECTED = 5
    OPERATION_TIMED_OUT = 6
    OVERLOADED = 7


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> _FileIdentity:
        return cls(metadata.st_dev, metadata.st_ino, metadata.st_mode)


@dataclass(slots=True)
class _BootstrapV1:
    socket_path: bytes
    generation_token: bytearray = field(repr=False)
    deck_run_id: bytes = bytes(16)
    session_id: bytes = bytes(16)
    request_deadline_budget_nanos: int = 0
    operation_timeout_nanos: int = 0
    command_capacity: int = 0
    server_uid: int = 0
    server_gid: int = 0


@dataclass(frozen=True, slots=True)
class _IpcFrame:
    kind: _OperationKind
    status: _ResponseStatus
    correlation: bytes
    generation_token: bytes = field(repr=False)
    operation_timeout_nanos: int = 0
    body: bytes = b""


def _canonical_digest(domain: bytes, fields: tuple[bytes, ...]) -> bytes:
    digest = hashlib.sha256()
    digest.update(_DIGEST_MAGIC)
    digest.update(_DIGEST_VERSION.to_bytes(2, "big"))
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


def _bootstrap_digest(
    *,
    server_uid: int,
    server_gid: int,
    generation_token: bytes,
    deck_run_id: bytes,
    session_id: bytes,
    request_deadline_budget_nanos: int,
    operation_timeout_nanos: int,
    command_capacity: int,
    socket_path: bytes,
) -> bytes:
    return _canonical_digest(
        _PXAB_DIGEST_DOMAIN,
        (
            (1).to_bytes(2, "big"),
            server_uid.to_bytes(4, "big"),
            server_gid.to_bytes(4, "big"),
            generation_token,
            deck_run_id,
            session_id,
            request_deadline_budget_nanos.to_bytes(8, "big"),
            operation_timeout_nanos.to_bytes(8, "big"),
            command_capacity.to_bytes(2, "big"),
            _MAX_IPC_BODY_BYTES.to_bytes(4, "big"),
            socket_path,
        ),
    )


def _ipc_frame_digest(frame: _IpcFrame) -> bytes:
    return _canonical_digest(
        _PXAI_FRAME_DIGEST_DOMAIN,
        (
            int(frame.kind).to_bytes(2, "big"),
            int(frame.status).to_bytes(2, "big"),
            frame.correlation,
            frame.generation_token,
            frame.operation_timeout_nanos.to_bytes(8, "big"),
            frame.body,
        ),
    )


def _identity(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 16 or not any(value):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_BOOTSTRAP,
            "DeveloperLocal Agent identity is invalid",
        )
    return value


def _lexical_absolute_path(
    value: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    maximum: int,
) -> bytes:
    try:
        raw = os.fsencode(os.fspath(value))
    except (TypeError, ValueError, UnicodeError) as cause:
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_PATH,
            "DeveloperLocal Agent endpoint path is invalid",
        ) from cause
    if not raw or raw == b"/" or not raw.startswith(b"/") or len(raw) > maximum or b"\0" in raw:
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_PATH,
            "DeveloperLocal Agent endpoint path is invalid",
        )
    components = raw.split(b"/")[1:]
    if any(component in {b".", b".."} for component in components):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_PATH,
            "DeveloperLocal Agent endpoint path is invalid",
        )
    return raw


def _lstat(path: bytes) -> os.stat_result:
    try:
        return os.lstat(path)
    except OSError as cause:
        raise _error(
            RuntimeAgentConversationClientErrorCode.IO,
            "DeveloperLocal Agent endpoint metadata is unavailable",
        ) from cause


def _validate_existing_path_chain(path: bytes) -> None:
    _lexical_absolute_path(path, sys.maxsize)
    current = b"/"
    if stat.S_ISLNK(_lstat(current).st_mode):  # pragma: no cover - impossible on Unix
        raise _error(
            RuntimeAgentConversationClientErrorCode.SYMLINK_REJECTED,
            "DeveloperLocal Agent endpoint path contains a symbolic link",
        )
    for component in (part for part in path.split(b"/") if part):
        current = posixpath.join(current, component)
        if stat.S_ISLNK(_lstat(current).st_mode):
            raise _error(
                RuntimeAgentConversationClientErrorCode.SYMLINK_REJECTED,
                "DeveloperLocal Agent endpoint path contains a symbolic link",
            )


def _validate_private_parent(parent: bytes, expected_uid: int, expected_gid: int) -> None:
    _validate_existing_path_chain(parent)
    metadata = _lstat(parent)
    mode = metadata.st_mode & 0o7777
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or mode not in _PRIVATE_DIRECTORY_MODES
    ):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INSECURE_PERMISSIONS,
            "DeveloperLocal Agent endpoint directory is not owner-private",
        )


def _validate_private_bootstrap(
    metadata: os.stat_result,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o7777 != _BOOTSTRAP_MODE
    ):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INSECURE_PERMISSIONS,
            "DeveloperLocal Agent bootstrap is not owner-private",
        )


def _validate_socket_path(bootstrap: _BootstrapV1) -> _FileIdentity:
    parent = posixpath.dirname(bootstrap.socket_path)
    _validate_private_parent(parent, bootstrap.server_uid, bootstrap.server_gid)
    metadata = _lstat(bootstrap.socket_path)
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != bootstrap.server_uid
        or metadata.st_gid != bootstrap.server_gid
        or metadata.st_mode & 0o7777 != _SOCKET_MODE
    ):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_SOCKET,
            "DeveloperLocal Agent socket is not owner-private",
        )
    return _FileIdentity.from_stat(metadata)


def _decode_bootstrap(wire: bytes) -> _BootstrapV1:
    if not isinstance(wire, bytes) or not (
        _PXAB_HEADER_BYTES <= len(wire) <= _MAX_BOOTSTRAP_FRAME_BYTES
    ):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_BOOTSTRAP,
            "DeveloperLocal Agent bootstrap is invalid",
        )
    try:
        (
            magic,
            version,
            header_bytes,
            frame_length,
            path_length,
            bootstrap_kind,
            server_uid,
            server_gid,
            generation_token,
            deck_run_id,
            session_id,
            deadline_nanos,
            operation_timeout_nanos,
            command_capacity,
            reserved,
            max_body_bytes,
            actual_digest,
        ) = _PXAB_HEADER.unpack_from(wire)
    except struct.error as cause:  # pragma: no cover - length fence is exact
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_BOOTSTRAP,
            "DeveloperLocal Agent bootstrap is invalid",
        ) from cause
    if (
        magic != _PXAB_MAGIC
        or version != _IPC_VERSION
        or header_bytes != _PXAB_HEADER_BYTES
        or frame_length != len(wire)
        or bootstrap_kind != 1
        or reserved != 0
        or max_body_bytes != _MAX_IPC_BODY_BYTES
        or path_length == 0
        or path_length > _MAX_BOOTSTRAP_PATH_BYTES
        or _PXAB_HEADER_BYTES + path_length != len(wire)
        or not any(generation_token)
        or not 1 <= deadline_nanos <= _MAX_REQUEST_DEADLINE_BUDGET_NANOS
        or not 1 <= operation_timeout_nanos <= _MAX_OPERATION_TIMEOUT_NANOS
        or not 1 <= command_capacity <= _MAX_COMMAND_CAPACITY
    ):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_BOOTSTRAP,
            "DeveloperLocal Agent bootstrap is invalid",
        )
    if server_uid != os.geteuid() or server_gid != os.getegid():
        raise _error(
            RuntimeAgentConversationClientErrorCode.PEER_CREDENTIALS_MISMATCH,
            "DeveloperLocal Agent owner identity mismatched",
        )
    socket_path = _lexical_absolute_path(
        wire[_PXAB_HEADER_BYTES:],
        _MAX_UNIX_SOCKET_PATH_BYTES,
    )
    _identity(deck_run_id)
    _identity(session_id)
    expected_digest = _bootstrap_digest(
        server_uid=server_uid,
        server_gid=server_gid,
        generation_token=generation_token,
        deck_run_id=deck_run_id,
        session_id=session_id,
        request_deadline_budget_nanos=deadline_nanos,
        operation_timeout_nanos=operation_timeout_nanos,
        command_capacity=command_capacity,
        socket_path=socket_path,
    )
    if not hmac.compare_digest(expected_digest, actual_digest):
        raise _error(
            RuntimeAgentConversationClientErrorCode.DIGEST_MISMATCH,
            "DeveloperLocal Agent bootstrap digest mismatched",
        )
    return _BootstrapV1(
        socket_path=socket_path,
        generation_token=bytearray(generation_token),
        deck_run_id=deck_run_id,
        session_id=session_id,
        request_deadline_budget_nanos=deadline_nanos,
        operation_timeout_nanos=operation_timeout_nanos,
        command_capacity=command_capacity,
        server_uid=server_uid,
        server_gid=server_gid,
    )


def _read_private_bootstrap_file(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
) -> _BootstrapV1:
    if os.name != "posix":  # pragma: no cover - protocol is Unix-only
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_PATH,
            "DeveloperLocal Agent IPC requires a Unix host",
        )
    raw_path = _lexical_absolute_path(path, _MAX_BOOTSTRAP_PATH_BYTES)
    parent = posixpath.dirname(raw_path)
    uid = os.geteuid()
    gid = os.getegid()
    _validate_private_parent(parent, uid, gid)
    named_before = _lstat(raw_path)
    _validate_private_bootstrap(named_before, uid, gid)
    expected_identity = _FileIdentity.from_stat(named_before)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:  # pragma: no cover - supported Unix hosts expose it
        raise _error(
            RuntimeAgentConversationClientErrorCode.BOOTSTRAP_OPEN_FAILED,
            "DeveloperLocal Agent bootstrap cannot be opened safely",
        )
    flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(raw_path, flags)
    except OSError as cause:
        raise _error(
            RuntimeAgentConversationClientErrorCode.BOOTSTRAP_OPEN_FAILED,
            "DeveloperLocal Agent bootstrap cannot be opened safely",
        ) from cause
    try:
        opened = os.fstat(descriptor)
        _validate_private_bootstrap(opened, uid, gid)
        length = opened.st_size
        if (
            expected_identity != _FileIdentity.from_stat(opened)
            or not _PXAB_HEADER_BYTES <= length <= _MAX_BOOTSTRAP_FRAME_BYTES
        ):
            raise _error(
                RuntimeAgentConversationClientErrorCode.ENDPOINT_IDENTITY_CHANGED,
                "DeveloperLocal Agent bootstrap identity changed",
            )
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise _error(
                    RuntimeAgentConversationClientErrorCode.IO,
                    "DeveloperLocal Agent bootstrap read was incomplete",
                )
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    named_after = _lstat(raw_path)
    _validate_private_bootstrap(named_after, uid, gid)
    if expected_identity != _FileIdentity.from_stat(named_after):
        raise _error(
            RuntimeAgentConversationClientErrorCode.ENDPOINT_IDENTITY_CHANGED,
            "DeveloperLocal Agent bootstrap identity changed",
        )
    bootstrap = _decode_bootstrap(b"".join(chunks))
    if posixpath.dirname(bootstrap.socket_path) != parent:
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_BOOTSTRAP,
            "DeveloperLocal Agent bootstrap scope is invalid",
        )
    _validate_socket_path(bootstrap)
    return bootstrap


def _encode_ipc_frame(magic: bytes, frame: _IpcFrame) -> bytes:
    if (
        magic not in {_PXAI_REQUEST_MAGIC, _PXAI_RESPONSE_MAGIC}
        or len(frame.correlation) != 16
        or not any(frame.correlation)
        or len(frame.generation_token) != 32
        or not any(frame.generation_token)
        or not 1 <= frame.operation_timeout_nanos <= _MAX_OPERATION_TIMEOUT_NANOS
        or len(frame.body) > _MAX_IPC_BODY_BYTES
    ):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_FRAME,
            "DeveloperLocal Agent IPC frame is invalid",
        )
    frame_length = _PXAI_HEADER_BYTES + len(frame.body)
    digest = _ipc_frame_digest(frame)
    return (
        _PXAI_HEADER.pack(
            magic,
            _IPC_VERSION,
            _PXAI_HEADER_BYTES,
            frame_length,
            int(frame.kind),
            int(frame.status),
            0,
            frame.correlation,
            frame.generation_token,
            frame.operation_timeout_nanos,
            len(frame.body),
            0,
            digest,
        )
        + frame.body
    )


def _decode_ipc_frame(magic: bytes, wire: bytes) -> _IpcFrame:
    if not isinstance(wire, bytes) or not (_PXAI_HEADER_BYTES <= len(wire) <= _MAX_IPC_FRAME_BYTES):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_FRAME,
            "DeveloperLocal Agent IPC frame is invalid",
        )
    try:
        (
            actual_magic,
            version,
            header_bytes,
            frame_length,
            kind_raw,
            status_raw,
            reserved_short,
            correlation,
            generation_token,
            operation_timeout_nanos,
            body_length,
            reserved_long,
            actual_digest,
        ) = _PXAI_HEADER.unpack_from(wire)
    except struct.error as cause:  # pragma: no cover - length fence is exact
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_FRAME,
            "DeveloperLocal Agent IPC frame is invalid",
        ) from cause
    if (
        actual_magic != magic
        or version != _IPC_VERSION
        or header_bytes != _PXAI_HEADER_BYTES
        or frame_length != len(wire)
        or reserved_short != 0
        or reserved_long != 0
        or body_length > _MAX_IPC_BODY_BYTES
        or _PXAI_HEADER_BYTES + body_length != len(wire)
        or not any(correlation)
        or not any(generation_token)
        or not 1 <= operation_timeout_nanos <= _MAX_OPERATION_TIMEOUT_NANOS
    ):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_FRAME,
            "DeveloperLocal Agent IPC frame is invalid",
        )
    try:
        kind = _OperationKind(kind_raw)
    except ValueError as cause:
        raise _error(
            RuntimeAgentConversationClientErrorCode.UNKNOWN_OPERATION,
            "DeveloperLocal Agent IPC operation is unknown",
        ) from cause
    try:
        status = _ResponseStatus(status_raw)
    except ValueError as cause:
        raise _error(
            RuntimeAgentConversationClientErrorCode.UNKNOWN_RESPONSE_STATUS,
            "DeveloperLocal Agent IPC response status is unknown",
        ) from cause
    frame = _IpcFrame(
        kind=kind,
        status=status,
        correlation=correlation,
        generation_token=generation_token,
        operation_timeout_nanos=operation_timeout_nanos,
        body=wire[_PXAI_HEADER_BYTES:],
    )
    if not hmac.compare_digest(_ipc_frame_digest(frame), actual_digest):
        raise _error(
            RuntimeAgentConversationClientErrorCode.DIGEST_MISMATCH,
            "DeveloperLocal Agent IPC frame digest mismatched",
        )
    return frame


def _peer_credentials(stream_socket: object) -> tuple[int, int]:
    descriptor = stream_socket.fileno()  # type: ignore[attr-defined]
    if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
        try:
            raw = stream_socket.getsockopt(  # type: ignore[attr-defined]
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
            _, uid, gid = struct.unpack("3i", raw)
            return uid, gid
        except (OSError, struct.error) as cause:
            raise _error(
                RuntimeAgentConversationClientErrorCode.PEER_CREDENTIALS_MISMATCH,
                "DeveloperLocal Agent peer identity is unavailable",
            ) from cause
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        getpeereid = libc.getpeereid
    except (AttributeError, OSError) as cause:  # pragma: no cover - unsupported Unix
        raise _error(
            RuntimeAgentConversationClientErrorCode.PEER_CREDENTIALS_MISMATCH,
            "DeveloperLocal Agent peer identity is unavailable",
        ) from cause
    getpeereid.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
    ]
    getpeereid.restype = ctypes.c_int
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    if getpeereid(descriptor, ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise _error(
            RuntimeAgentConversationClientErrorCode.PEER_CREDENTIALS_MISMATCH,
            "DeveloperLocal Agent peer identity is unavailable",
        )
    return uid.value, gid.value


async def _read_ipc_frame(reader: asyncio.StreamReader, magic: bytes) -> _IpcFrame:
    header = await reader.readexactly(_PXAI_HEADER_BYTES)
    if header[:4] != magic or int.from_bytes(header[6:8], "big") != _PXAI_HEADER_BYTES:
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_FRAME,
            "DeveloperLocal Agent IPC response is invalid",
        )
    frame_length = int.from_bytes(header[8:12], "big")
    if not _PXAI_HEADER_BYTES <= frame_length <= _MAX_IPC_FRAME_BYTES:
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_FRAME,
            "DeveloperLocal Agent IPC response is invalid",
        )
    body = await reader.readexactly(frame_length - _PXAI_HEADER_BYTES)
    if await reader.read(1):
        raise _error(
            RuntimeAgentConversationClientErrorCode.INVALID_FRAME,
            "DeveloperLocal Agent IPC response has trailing bytes",
        )
    return _decode_ipc_frame(magic, header + body)


def _status_error(status: _ResponseStatus) -> RuntimeAgentConversationClientError:
    values = {
        _ResponseStatus.MALFORMED: (
            RuntimeAgentConversationClientErrorCode.PROTOCOL,
            "Runtime-managed Agent conversation protocol was rejected",
        ),
        _ResponseStatus.AUTHENTICATION_FAILED: (
            RuntimeAgentConversationClientErrorCode.AUTHENTICATION_FAILED,
            "Runtime-managed Agent conversation authentication failed",
        ),
        _ResponseStatus.OWNER_UNAVAILABLE: (
            RuntimeAgentConversationClientErrorCode.OWNER_UNAVAILABLE,
            "Runtime-managed Agent conversation owner is unavailable",
        ),
        _ResponseStatus.GENERATION_RETIRED: (
            RuntimeAgentConversationClientErrorCode.GENERATION_RETIRED,
            "Runtime-managed Agent conversation generation is retired",
        ),
        _ResponseStatus.OPERATION_REJECTED: (
            RuntimeAgentConversationClientErrorCode.OPERATION_REJECTED,
            "Runtime-managed Agent conversation operation was rejected",
        ),
        _ResponseStatus.OPERATION_TIMED_OUT: (
            RuntimeAgentConversationClientErrorCode.OPERATION_TIMED_OUT,
            "Runtime-managed Agent conversation operation timed out",
        ),
        _ResponseStatus.OVERLOADED: (
            RuntimeAgentConversationClientErrorCode.OVERLOADED,
            "Runtime-managed Agent conversation endpoint is overloaded",
        ),
    }
    code, message = values[status]
    return _error(code, message)


class RuntimeAgentConversationClientV1:
    """One generation-scoped, no-retry typed console client for Rust Runtime."""

    def __init__(self, bootstrap: _BootstrapV1, client_instance_nonce: bytes) -> None:
        self._bootstrap = bootstrap
        self._client_instance_nonce = bytearray(client_instance_nonce)
        self._next_request_sequence = 1
        self._next_control_sequence = 1
        self._pending_request: AgentConversationRequestV1 | None = None
        self._pending_submit_task: asyncio.Task[object] | None = None
        self._state_lock = asyncio.Lock()
        self._closed = False

    @classmethod
    def from_private_bootstrap_file(
        cls,
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes] | Path,
    ) -> RuntimeAgentConversationClientV1:
        bootstrap = _read_private_bootstrap_file(path)
        nonce = secrets.token_bytes(32)
        if not any(nonce):  # pragma: no cover - cryptographically negligible
            bootstrap.generation_token[:] = bytes(32)
            raise _error(
                RuntimeAgentConversationClientErrorCode.ENTROPY_UNAVAILABLE,
                "DeveloperLocal Agent client entropy is unavailable",
            )
        return cls(bootstrap, nonce)

    async def open(self) -> AgentConversationOpenOutcomeV1:
        self._ensure_open()
        request = AgentConversationControlV1.open_request(
            self._bootstrap.deck_run_id,
            self._bootstrap.session_id,
        )
        response = await self._send_control(_OperationKind.OPEN, request)
        if response.kind is not AgentConversationControlKindV1.OPEN_RESULT:
            raise _error(
                RuntimeAgentConversationClientErrorCode.RESPONSE_KIND_MISMATCH,
                "Runtime-managed Agent open response kind mismatched",
            )
        outcome = AgentConversationOpenOutcomeV1(response.outcome)
        if outcome not in {
            AgentConversationOpenOutcomeV1.OPENED,
            AgentConversationOpenOutcomeV1.EXISTING,
        }:
            raise _error(
                RuntimeAgentConversationClientErrorCode.OPERATION_REJECTED,
                "Runtime-managed Agent conversation session cannot be opened",
            )
        return outcome

    async def submit(self, text: str) -> AgentConversationTerminalV1:
        submit_task = asyncio.current_task()
        async with self._state_lock:
            self._ensure_open()
            if self._pending_request is not None:
                raise _error(
                    RuntimeAgentConversationClientErrorCode.REQUEST_PENDING,
                    "A Runtime-managed Agent conversation request is already pending",
                )
            sequence = self._take_request_sequence()
            request = AgentConversationRequestV1.create(
                self._bootstrap.deck_run_id,
                self._bootstrap.session_id,
                self._request_identity(_TURN_ID_DOMAIN, sequence),
                self._request_identity(_REQUEST_ID_DOMAIN, sequence),
                self._bootstrap.request_deadline_budget_nanos,
                text,
            )
            self._pending_request = request
            self._pending_submit_task = submit_task
        try:
            response = await self._exchange(
                _OperationKind.SUBMIT,
                request.request_id,
                request.canonical_wire(),
            )
            try:
                terminal = decode_terminal_v1(response.body)
            except ValueError as cause:
                raise _error(
                    RuntimeAgentConversationClientErrorCode.PROTOCOL,
                    "Runtime-managed Agent terminal response is invalid",
                ) from cause
            if not terminal.correlates(request):
                raise _error(
                    RuntimeAgentConversationClientErrorCode.CORRELATION_MISMATCH,
                    "Runtime-managed Agent terminal response correlation mismatched",
                )
            return terminal
        finally:
            async with self._state_lock:
                if self._pending_request is request:
                    self._pending_request = None
                    self._pending_submit_task = None

    async def cancel_pending(self) -> RuntimeAgentConversationCancelResultV1:
        async with self._state_lock:
            self._ensure_open()
            request = self._pending_request
        if request is None:
            raise _error(
                RuntimeAgentConversationClientErrorCode.NO_PENDING_REQUEST,
                "No Runtime-managed Agent conversation request is pending",
            )
        control = AgentConversationControlV1.cancel_request(
            self._bootstrap.deck_run_id,
            self._bootstrap.session_id,
            request.request_id,
        )
        response = await self._send_control(_OperationKind.CANCEL, control)
        if response.kind is not AgentConversationControlKindV1.CANCEL_RESULT:
            raise _error(
                RuntimeAgentConversationClientErrorCode.RESPONSE_KIND_MISMATCH,
                "Runtime-managed Agent cancel response kind mismatched",
            )
        outcome = AgentConversationCancelOutcomeV1(response.outcome)
        if outcome is AgentConversationCancelOutcomeV1.TERMINAL:
            terminal = response.value
            if not isinstance(terminal, AgentConversationTerminalV1) or not terminal.correlates(
                request
            ):
                raise _error(
                    RuntimeAgentConversationClientErrorCode.CORRELATION_MISMATCH,
                    "Runtime-managed Agent cancel response correlation mismatched",
                )
            await self._retire_pending_submit(request)
            return RuntimeAgentConversationCancelResultV1(outcome, terminal)
        if outcome is AgentConversationCancelOutcomeV1.NOT_FOUND:
            await self._retire_pending_submit(request)
            raise _error(
                RuntimeAgentConversationClientErrorCode.OPERATION_REJECTED,
                "Runtime-managed Agent cancel target was not found",
            )
        if outcome is AgentConversationCancelOutcomeV1.SESSION_SEALED:
            await self._retire_pending_submit(request)
            raise _error(
                RuntimeAgentConversationClientErrorCode.OPERATION_REJECTED,
                "Runtime-managed Agent cancel target Session is sealed",
            )
        return RuntimeAgentConversationCancelResultV1(outcome)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._pending_request = None
        self._pending_submit_task = None
        self._bootstrap.generation_token[:] = bytes(32)
        self._client_instance_nonce[:] = bytes(32)

    async def _retire_pending_submit(self, request: AgentConversationRequestV1) -> None:
        submit_task = None
        async with self._state_lock:
            if self._pending_request is request:
                self._pending_request = None
                submit_task = self._pending_submit_task
                self._pending_submit_task = None
        if (
            submit_task is not None
            and submit_task is not asyncio.current_task()
            and not submit_task.done()
        ):
            submit_task.cancel()
            try:
                await submit_task
            except (asyncio.CancelledError, Exception):
                # The cancel result is now the authoritative terminal or
                # rejection. Consume the retired submit task's completion so
                # callers never retain a second live operation or an
                # unobserved task exception for the same semantic request.
                pass

    def _ensure_open(self) -> None:
        if self._closed:
            raise _error(
                RuntimeAgentConversationClientErrorCode.CLOSED,
                "DeveloperLocal Agent IPC is closed",
            )

    def _take_request_sequence(self) -> int:
        sequence = self._next_request_sequence
        if sequence == 0:
            raise _error(
                RuntimeAgentConversationClientErrorCode.SEQUENCE_EXHAUSTED,
                "Runtime-managed Agent request identity space is exhausted",
            )
        self._next_request_sequence = sequence + 1 if sequence < (1 << 64) - 1 else 0
        return sequence

    def _request_identity(self, domain: bytes, sequence: int) -> bytes:
        digest = _canonical_digest(
            domain,
            (
                self._bootstrap.deck_run_id,
                self._bootstrap.session_id,
                bytes(self._client_instance_nonce),
                sequence.to_bytes(8, "big"),
            ),
        )
        identity = digest[:16]
        if not any(identity):  # pragma: no cover - cryptographically negligible
            raise _error(
                RuntimeAgentConversationClientErrorCode.ENTROPY_UNAVAILABLE,
                "Runtime-managed Agent identity derivation failed",
            )
        return identity

    def _control_correlation(self, kind: _OperationKind, body: bytes) -> bytes:
        sequence = self._next_control_sequence
        if sequence == 0:
            raise _error(
                RuntimeAgentConversationClientErrorCode.SEQUENCE_EXHAUSTED,
                "Runtime-managed Agent control correlation space is exhausted",
            )
        self._next_control_sequence = sequence + 1 if sequence < (1 << 64) - 1 else 0
        digest = _canonical_digest(
            _PXAI_CORRELATION_DOMAIN,
            (
                bytes(self._client_instance_nonce),
                sequence.to_bytes(8, "big"),
                int(kind).to_bytes(2, "big"),
                body,
            ),
        )
        correlation = digest[:16]
        if not any(correlation):  # pragma: no cover - cryptographically negligible
            raise _error(
                RuntimeAgentConversationClientErrorCode.ENTROPY_UNAVAILABLE,
                "Runtime-managed Agent control correlation derivation failed",
            )
        return correlation

    async def _send_control(
        self,
        kind: _OperationKind,
        request: AgentConversationControlV1,
    ) -> AgentConversationControlV1:
        body = request.canonical_wire()
        response = await self._exchange(kind, self._control_correlation(kind, body), body)
        try:
            semantic = decode_control_v1(response.body)
        except ValueError as cause:
            raise _error(
                RuntimeAgentConversationClientErrorCode.PROTOCOL,
                "Runtime-managed Agent control response is invalid",
            ) from cause
        if (
            semantic.deck_run_id != request.deck_run_id
            or semantic.session_id != request.session_id
            or semantic.request_id != request.request_id
        ):
            raise _error(
                RuntimeAgentConversationClientErrorCode.CORRELATION_MISMATCH,
                "Runtime-managed Agent control response correlation mismatched",
            )
        return semantic

    async def _exchange(
        self,
        kind: _OperationKind,
        correlation: bytes,
        body: bytes,
    ) -> _IpcFrame:
        self._ensure_open()
        operation_timeout_nanos = self._bootstrap.operation_timeout_nanos
        token = bytes(self._bootstrap.generation_token)
        request = _IpcFrame(
            kind=kind,
            status=_ResponseStatus.OK,
            correlation=correlation,
            generation_token=token,
            operation_timeout_nanos=operation_timeout_nanos,
            body=body,
        )
        wire = _encode_ipc_frame(_PXAI_REQUEST_MAGIC, request)
        socket_identity = _validate_socket_path(self._bootstrap)

        async def exchange_once() -> _IpcFrame:
            writer: asyncio.StreamWriter | None = None
            try:
                reader, writer = await asyncio.open_unix_connection(
                    path=self._bootstrap.socket_path
                )
                stream_socket = writer.get_extra_info("socket")
                if stream_socket is None or _peer_credentials(stream_socket) != (
                    self._bootstrap.server_uid,
                    self._bootstrap.server_gid,
                ):
                    raise _error(
                        RuntimeAgentConversationClientErrorCode.PEER_CREDENTIALS_MISMATCH,
                        "DeveloperLocal Agent peer identity mismatched",
                    )
                if _validate_socket_path(self._bootstrap) != socket_identity:
                    raise _error(
                        RuntimeAgentConversationClientErrorCode.ENDPOINT_IDENTITY_CHANGED,
                        "DeveloperLocal Agent socket identity changed",
                    )
                writer.write(wire)
                await writer.drain()
                if not writer.can_write_eof():
                    raise _error(
                        RuntimeAgentConversationClientErrorCode.IO,
                        "DeveloperLocal Agent IPC cannot complete request framing",
                    )
                writer.write_eof()
                return await _read_ipc_frame(reader, _PXAI_RESPONSE_MAGIC)
            finally:
                if writer is not None:
                    writer.close()

        try:
            response = await asyncio.wait_for(
                exchange_once(),
                timeout=operation_timeout_nanos / 1_000_000_000,
            )
        except TimeoutError as cause:
            raise _error(
                RuntimeAgentConversationClientErrorCode.OPERATION_TIMED_OUT,
                "Runtime-managed Agent conversation operation timed out",
            ) from cause
        except RuntimeAgentConversationClientError:
            raise
        except (OSError, asyncio.IncompleteReadError) as cause:
            raise _error(
                RuntimeAgentConversationClientErrorCode.IO,
                "Runtime-managed Agent conversation exchange failed",
            ) from cause
        if (
            response.kind is not kind
            or response.correlation != correlation
            or response.operation_timeout_nanos != operation_timeout_nanos
        ):
            raise _error(
                RuntimeAgentConversationClientErrorCode.CORRELATION_MISMATCH,
                "Runtime-managed Agent IPC response correlation mismatched",
            )
        if not hmac.compare_digest(response.generation_token, token):
            raise _error(
                RuntimeAgentConversationClientErrorCode.AUTHENTICATION_FAILED,
                "Runtime-managed Agent IPC response authentication failed",
            )
        if response.status is not _ResponseStatus.OK:
            raise _status_error(response.status)
        return response


__all__ = [
    "RuntimeAgentConversationCancelResultV1",
    "RuntimeAgentConversationClientError",
    "RuntimeAgentConversationClientErrorCode",
    "RuntimeAgentConversationClientV1",
]
