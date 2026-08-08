"""Typed DeveloperLocal clients for Agent conversation and Inspection startup reads.

The Rust Runtime owns PXAB/PXAI/PXAO Agent conversation IPC, while Inspection
owns the separate PXIB/PXIQ/PXIP/PXIS read-only boundary. This module is the
Python console's strict, no-retry consumer of both. It does not own Runtime,
Inspection projection, Fabric, AgentService, model, or credential lifecycle.
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
from typing import TypeVar

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
_PXIB_MAGIC = b"PXIB"
_PXIQ_MAGIC = b"PXIQ"
_PXIP_MAGIC = b"PXIP"
_INSPECTION_VERSION = 2
_PXIB_HEADER_BYTES = 128
_PXIQ_BYTES = 96
_PXIP_HEADER_BYTES = 144
_PXIS_V1_BYTES = 592
_PXIS_V2_BYTES = 832
_PXIS_HEADER_BYTES = 112
_PXIS_OWNER_RECORD_BYTES = 96
_PXIS_NODE_RECORD_BYTES = 128
_MAX_INSPECTION_BOOTSTRAP_BYTES = _PXIB_HEADER_BYTES + _MAX_BOOTSTRAP_PATH_BYTES
_MAX_INSPECTION_RESPONSE_BYTES = _PXIP_HEADER_BYTES + _PXIS_V2_BYTES
_INSPECTION_BOOTSTRAP_DIGEST_DOMAIN = (
    b"paraegox.inspection.developer-local.bootstrap.v2"
)
_INSPECTION_REQUEST_ID_DOMAIN = b"paraegox.inspection.developer-local.request-id.v2"
_INSPECTION_REQUEST_DIGEST_DOMAIN = b"paraegox.inspection.protocol-request.v2"
_INSPECTION_RESPONSE_DIGEST_DOMAIN = b"paraegox.inspection.protocol-response.v2"
_INSPECTION_SNAPSHOT_V1_DIGEST_DOMAIN = b"paraegox.inspection.local-snapshot.v1"
_INSPECTION_SNAPSHOT_V2_DIGEST_DOMAIN = b"paraegox.inspection.local-snapshot.v2"
_DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
_DIGEST_VERSION = 1

_PXAB_HEADER = struct.Struct(">4sHHIHHII32s16s16sQQHHI32s")
_PXAI_HEADER = struct.Struct(">4sHHIBBH16s32sQII32s")
_PXIB_HEADER = struct.Struct(">4sHHII16s32sIIQ16s32s")

if _PXAB_HEADER.size != _PXAB_HEADER_BYTES:  # pragma: no cover
    raise RuntimeError("PXAB v1 header layout drifted")
if _PXAI_HEADER.size != _PXAI_HEADER_BYTES:  # pragma: no cover
    raise RuntimeError("PXAI v1 header layout drifted")
if _PXIB_HEADER.size != _PXIB_HEADER_BYTES:
    raise RuntimeError("PXIB v2 header layout drifted")


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


class DeveloperLocalInspectionClientErrorCode(IntEnum):
    """Stable, display-safe failures for the read-only Inspection boundary."""

    INVALID_PATH = 1
    SYMLINK_REJECTED = 2
    INSECURE_PERMISSIONS = 3
    BOOTSTRAP_OPEN_FAILED = 4
    INVALID_BOOTSTRAP = 5
    DIGEST_MISMATCH = 6
    PEER_CREDENTIALS_MISMATCH = 7
    INVALID_SOCKET = 8
    ENDPOINT_IDENTITY_CHANGED = 9
    CLOSED = 10
    ALREADY_USED = 11
    INVALID_FRAME = 12
    CORRELATION_MISMATCH = 13
    SNAPSHOT_UNAVAILABLE = 14
    OPERATION_TIMED_OUT = 15
    PROTOCOL = 16
    IO = 17


class DeveloperLocalInspectionClientError(RuntimeError):
    """Fail-closed Inspection error without capability or endpoint material."""

    def __init__(self, code: DeveloperLocalInspectionClientErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


def _inspection_error(
    code: DeveloperLocalInspectionClientErrorCode,
    message: str,
) -> DeveloperLocalInspectionClientError:
    return DeveloperLocalInspectionClientError(code, message)


class InspectionSourceOwnerV1(IntEnum):
    AUTHORITY = 1
    DEPLOYMENT_CONTROLLER = 2
    RUNTIME_HOST = 3
    FABRIC_SERVICE = 4
    AGENT_SERVICE = 5


class InspectionFreshnessV1(IntEnum):
    FRESH = 1
    STALE = 2
    PARTITIONED = 3
    MISSING = 4


class InspectionLivenessV1(IntEnum):
    UNKNOWN = 0
    BOOTSTRAPPING = 1
    LIVE = 2
    UNRESPONSIVE = 3
    EXITED = 4
    QUARANTINED = 5


class InspectionReadinessV1(IntEnum):
    UNKNOWN = 0
    READY = 1
    NOT_READY = 2
    DEGRADED = 3
    BLOCKED = 4


class InspectionHealthV1(IntEnum):
    UNKNOWN = 0
    HEALTHY = 1
    DEGRADED = 2
    FAULTED = 3


class InspectionFeatureSupportV1(IntEnum):
    UNKNOWN = 0
    ALL_REQUIRED_SUPPORTED = 1
    REQUIRED_UNSUPPORTED = 2


class InspectionReasonV1(IntEnum):
    NONE = 0
    BOOTSTRAPPING = 1
    DEPENDENCY_UNAVAILABLE = 2
    OWNER_REPORTED_DEGRADED = 3
    OWNER_REPORTED_FAILURE = 4
    FEATURE_UNSUPPORTED = 5
    QUARANTINED = 6
    OUTCOME_UNCERTAIN = 7
    SOURCE_UNKNOWN = 8
    SOURCE_MISSING = 9
    SOURCE_STALE = 10
    SOURCE_PARTITIONED = 11


class LocalInspectionOverallV1(IntEnum):
    READY = 1
    DEGRADED = 2
    UNAVAILABLE = 3
    UNKNOWN = 4


@dataclass(frozen=True, slots=True)
class InspectionSourceCoordinateV1:
    owner: InspectionSourceOwnerV1
    value: int
    sequence: int


@dataclass(frozen=True, slots=True)
class LocalInspectionRecordV1:
    owner: InspectionSourceOwnerV1
    freshness: InspectionFreshnessV1
    subject_ref: bytes
    coordinate: InspectionSourceCoordinateV1 | None
    observed_at_nanos: int | None
    valid_until_nanos: int | None
    liveness: InspectionLivenessV1
    readiness: InspectionReadinessV1
    health: InspectionHealthV1
    feature_support: InspectionFeatureSupportV1
    reason: InspectionReasonV1
    owner_fact_digest: bytes | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalInspectionSnapshotV1:
    projection_id: bytes
    observation_clock_ref: bytes
    projection_revision: int
    projected_at_nanos: int
    overall: LocalInspectionOverallV1
    records: tuple[
        LocalInspectionRecordV1,
        LocalInspectionRecordV1,
        LocalInspectionRecordV1,
        LocalInspectionRecordV1,
        LocalInspectionRecordV1,
    ]
    projection_digest: bytes
    canonical_wire: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class NodeInspectionRecordV2:
    freshness: InspectionFreshnessV1
    node_ref: bytes
    node_incarnation_ref: bytes
    registration_epoch: int | None
    status_sequence: int | None
    observed_at_nanos: int | None
    valid_until_nanos: int | None
    liveness: InspectionLivenessV1
    readiness: InspectionReadinessV1
    health: InspectionHealthV1
    feature_support: InspectionFeatureSupportV1
    reason: InspectionReasonV1
    node_status_digest: bytes | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalInspectionSnapshotV2:
    base_snapshot: LocalInspectionSnapshotV1
    node: NodeInspectionRecordV2
    overall: LocalInspectionOverallV1
    projection_digest: bytes
    canonical_wire: bytes = field(repr=False)

    @property
    def projection_id(self) -> bytes:
        return self.base_snapshot.projection_id

    @property
    def observation_clock_ref(self) -> bytes:
        return self.base_snapshot.observation_clock_ref

    @property
    def projection_revision(self) -> int:
        return self.base_snapshot.projection_revision

    @property
    def projected_at_nanos(self) -> int:
        return self.base_snapshot.projected_at_nanos


@dataclass(slots=True)
class _InspectionBootstrapV2:
    socket_path: bytes
    projection_id: bytes
    generation_token: bytearray = field(repr=False)
    server_uid: int = 0
    server_gid: int = 0
    operation_timeout_nanos: int = 0
    request_seed: bytearray = field(default_factory=bytearray, repr=False)


@dataclass(frozen=True, slots=True)
class _InspectionRequestV2:
    request_id: bytes
    projection_id: bytes
    request_digest: bytes
    canonical_wire: bytes = field(repr=False)


class _InspectionResponseOutcomeV2(IntEnum):
    SNAPSHOT = 1
    NOT_MODIFIED = 2
    NOT_FOUND = 3


_InspectionEnumT = TypeVar("_InspectionEnumT", bound=IntEnum)


def _decode_inspection_enum(enum: type[_InspectionEnumT], value: int) -> _InspectionEnumT:
    try:
        return enum(value)
    except ValueError as cause:
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.PROTOCOL,
            "DeveloperLocal Inspection v2 frame contains an unknown state",
        ) from cause


def _inspection_bootstrap_digest(bootstrap: _InspectionBootstrapV2) -> bytes:
    return _canonical_digest(
        _INSPECTION_BOOTSTRAP_DIGEST_DOMAIN,
        (
            _INSPECTION_VERSION.to_bytes(2, "big"),
            bootstrap.projection_id,
            bytes(bootstrap.generation_token),
            bootstrap.server_uid.to_bytes(8, "big"),
            bootstrap.server_gid.to_bytes(8, "big"),
            bootstrap.operation_timeout_nanos.to_bytes(8, "big"),
            bytes(bootstrap.request_seed),
            bootstrap.socket_path,
        ),
    )


def _encode_inspection_bootstrap_v2(bootstrap: _InspectionBootstrapV2) -> bytes:
    path_length = len(bootstrap.socket_path)
    return _PXIB_HEADER.pack(
        _PXIB_MAGIC,
        _INSPECTION_VERSION,
        _PXIB_HEADER_BYTES,
        _PXIB_HEADER_BYTES + path_length,
        path_length,
        bootstrap.projection_id,
        bytes(bootstrap.generation_token),
        bootstrap.server_uid,
        bootstrap.server_gid,
        bootstrap.operation_timeout_nanos,
        bytes(bootstrap.request_seed),
        _inspection_bootstrap_digest(bootstrap),
    ) + bootstrap.socket_path


def _decode_inspection_bootstrap_v2(wire: bytes) -> _InspectionBootstrapV2:
    if not isinstance(wire, bytes) or not (
        _PXIB_HEADER_BYTES <= len(wire) <= _MAX_INSPECTION_BOOTSTRAP_BYTES
    ):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.INVALID_BOOTSTRAP,
            "DeveloperLocal Inspection v2 bootstrap is invalid",
        )
    try:
        (
            magic,
            version,
            header_bytes,
            frame_length,
            path_length,
            projection_id,
            generation_token,
            server_uid,
            server_gid,
            operation_timeout_nanos,
            request_seed,
            declared_digest,
        ) = _PXIB_HEADER.unpack_from(wire)
    except struct.error as cause:
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.INVALID_BOOTSTRAP,
            "DeveloperLocal Inspection v2 bootstrap is invalid",
        ) from cause
    if (
        magic != _PXIB_MAGIC
        or version != _INSPECTION_VERSION
        or header_bytes != _PXIB_HEADER_BYTES
        or frame_length != len(wire)
        or path_length == 0
        or path_length > _MAX_BOOTSTRAP_PATH_BYTES
        or _PXIB_HEADER_BYTES + path_length != len(wire)
        or not any(projection_id)
        or not any(generation_token)
        or not any(request_seed)
        or server_uid == 0
        or server_gid == 0
        or not 1 <= operation_timeout_nanos <= _MAX_OPERATION_TIMEOUT_NANOS
    ):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.INVALID_BOOTSTRAP,
            "DeveloperLocal Inspection v2 bootstrap is invalid",
        )
    if server_uid != os.geteuid() or server_gid != os.getegid():
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.PEER_CREDENTIALS_MISMATCH,
            "DeveloperLocal Inspection v2 owner identity mismatched",
        )
    try:
        socket_path = _lexical_absolute_path(
            wire[_PXIB_HEADER_BYTES:],
            _MAX_BOOTSTRAP_PATH_BYTES,
        )
    except RuntimeAgentConversationClientError as cause:
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.INVALID_PATH,
            "DeveloperLocal Inspection v2 endpoint path is invalid",
        ) from cause
    bootstrap = _InspectionBootstrapV2(
        socket_path=socket_path,
        projection_id=projection_id,
        generation_token=bytearray(generation_token),
        server_uid=server_uid,
        server_gid=server_gid,
        operation_timeout_nanos=operation_timeout_nanos,
        request_seed=bytearray(request_seed),
    )
    if not hmac.compare_digest(_inspection_bootstrap_digest(bootstrap), declared_digest):
        bootstrap.generation_token[:] = bytes(32)
        bootstrap.request_seed[:] = bytes(16)
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.DIGEST_MISMATCH,
            "DeveloperLocal Inspection v2 bootstrap digest mismatched",
        )
    if _encode_inspection_bootstrap_v2(bootstrap) != wire:
        bootstrap.generation_token[:] = bytes(32)
        bootstrap.request_seed[:] = bytes(16)
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.INVALID_BOOTSTRAP,
            "DeveloperLocal Inspection v2 bootstrap is non-canonical",
        )
    return bootstrap


def _map_inspection_path_error(
    cause: RuntimeAgentConversationClientError,
) -> DeveloperLocalInspectionClientError:
    mapping = {
        RuntimeAgentConversationClientErrorCode.INVALID_PATH: (
            DeveloperLocalInspectionClientErrorCode.INVALID_PATH,
            "DeveloperLocal Inspection v2 endpoint path is invalid",
        ),
        RuntimeAgentConversationClientErrorCode.SYMLINK_REJECTED: (
            DeveloperLocalInspectionClientErrorCode.SYMLINK_REJECTED,
            "DeveloperLocal Inspection v2 endpoint path contains a symbolic link",
        ),
        RuntimeAgentConversationClientErrorCode.INSECURE_PERMISSIONS: (
            DeveloperLocalInspectionClientErrorCode.INSECURE_PERMISSIONS,
            "DeveloperLocal Inspection v2 endpoint is not owner-private",
        ),
        RuntimeAgentConversationClientErrorCode.BOOTSTRAP_OPEN_FAILED: (
            DeveloperLocalInspectionClientErrorCode.BOOTSTRAP_OPEN_FAILED,
            "DeveloperLocal Inspection v2 bootstrap cannot be opened safely",
        ),
        RuntimeAgentConversationClientErrorCode.INVALID_SOCKET: (
            DeveloperLocalInspectionClientErrorCode.INVALID_SOCKET,
            "DeveloperLocal Inspection v2 socket is not owner-private",
        ),
        RuntimeAgentConversationClientErrorCode.ENDPOINT_IDENTITY_CHANGED: (
            DeveloperLocalInspectionClientErrorCode.ENDPOINT_IDENTITY_CHANGED,
            "DeveloperLocal Inspection v2 endpoint identity changed",
        ),
    }
    code, message = mapping.get(
        cause.code,
        (
            DeveloperLocalInspectionClientErrorCode.IO,
            "DeveloperLocal Inspection v2 endpoint metadata is unavailable",
        ),
    )
    return _inspection_error(code, message)


def _validate_inspection_socket_path(bootstrap: _InspectionBootstrapV2) -> _FileIdentity:
    try:
        return _validate_socket_path(bootstrap)
    except RuntimeAgentConversationClientError as cause:
        raise _map_inspection_path_error(cause) from cause


def _read_private_inspection_bootstrap_file_v2(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes] | Path,
) -> _InspectionBootstrapV2:
    if os.name != "posix":
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.INVALID_PATH,
            "DeveloperLocal Inspection v2 requires a Unix host",
        )
    try:
        raw_path = _lexical_absolute_path(path, _MAX_BOOTSTRAP_PATH_BYTES)
        parent = posixpath.dirname(raw_path)
        uid = os.geteuid()
        gid = os.getegid()
        _validate_private_parent(parent, uid, gid)
        named_before = _lstat(raw_path)
        _validate_private_bootstrap(named_before, uid, gid)
    except RuntimeAgentConversationClientError as cause:
        raise _map_inspection_path_error(cause) from cause
    expected_identity = _FileIdentity.from_stat(named_before)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.BOOTSTRAP_OPEN_FAILED,
            "DeveloperLocal Inspection v2 bootstrap cannot be opened safely",
        )
    flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(raw_path, flags)
    except OSError as cause:
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.BOOTSTRAP_OPEN_FAILED,
            "DeveloperLocal Inspection v2 bootstrap cannot be opened safely",
        ) from cause
    try:
        opened = os.fstat(descriptor)
        try:
            _validate_private_bootstrap(opened, uid, gid)
        except RuntimeAgentConversationClientError as cause:
            raise _map_inspection_path_error(cause) from cause
        length = opened.st_size
        if (
            expected_identity != _FileIdentity.from_stat(opened)
            or not _PXIB_HEADER_BYTES <= length <= _MAX_INSPECTION_BOOTSTRAP_BYTES
        ):
            raise _inspection_error(
                DeveloperLocalInspectionClientErrorCode.ENDPOINT_IDENTITY_CHANGED,
                "DeveloperLocal Inspection v2 bootstrap identity changed",
            )
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            try:
                chunk = os.read(descriptor, remaining)
            except OSError as cause:
                raise _inspection_error(
                    DeveloperLocalInspectionClientErrorCode.IO,
                    "DeveloperLocal Inspection v2 bootstrap read failed",
                ) from cause
            if not chunk:
                raise _inspection_error(
                    DeveloperLocalInspectionClientErrorCode.IO,
                    "DeveloperLocal Inspection v2 bootstrap read was incomplete",
                )
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    try:
        named_after = _lstat(raw_path)
        _validate_private_bootstrap(named_after, uid, gid)
    except RuntimeAgentConversationClientError as cause:
        raise _map_inspection_path_error(cause) from cause
    if expected_identity != _FileIdentity.from_stat(named_after):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.ENDPOINT_IDENTITY_CHANGED,
            "DeveloperLocal Inspection v2 bootstrap identity changed",
        )
    bootstrap = _decode_inspection_bootstrap_v2(b"".join(chunks))
    if posixpath.dirname(bootstrap.socket_path) != parent:
        bootstrap.generation_token[:] = bytes(32)
        bootstrap.request_seed[:] = bytes(16)
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.INVALID_BOOTSTRAP,
            "DeveloperLocal Inspection v2 bootstrap scope is invalid",
        )
    try:
        _validate_inspection_socket_path(bootstrap)
    except DeveloperLocalInspectionClientError:
        bootstrap.generation_token[:] = bytes(32)
        bootstrap.request_seed[:] = bytes(16)
        raise
    return bootstrap


def _inspection_request_id_v2(bootstrap: _InspectionBootstrapV2, sequence: int) -> bytes:
    if sequence <= 0 or sequence > (1 << 64) - 1:
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.PROTOCOL,
            "DeveloperLocal Inspection v2 request sequence is invalid",
        )
    request_id = _canonical_digest(
        _INSPECTION_REQUEST_ID_DOMAIN,
        (
            bytes(bootstrap.request_seed),
            bootstrap.projection_id,
            sequence.to_bytes(8, "big"),
        ),
    )[:16]
    if not any(request_id):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.PROTOCOL,
            "DeveloperLocal Inspection v2 request identity is invalid",
        )
    return request_id


def _encode_inspection_latest_request_v2(
    request_id: bytes,
    projection_id: bytes,
) -> _InspectionRequestV2:
    if len(request_id) != 16 or not any(request_id) or len(projection_id) != 16 or not any(
        projection_id
    ):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.PROTOCOL,
            "DeveloperLocal Inspection v2 request identity is invalid",
        )
    wire = bytearray(_PXIQ_BYTES)
    wire[:4] = _PXIQ_MAGIC
    wire[4:6] = _INSPECTION_VERSION.to_bytes(2, "big")
    wire[6:8] = _PXIQ_BYTES.to_bytes(2, "big")
    wire[8:12] = _PXIQ_BYTES.to_bytes(4, "big")
    wire[12] = 1
    wire[16:32] = request_id
    wire[32:48] = projection_id
    request_digest = _canonical_digest(
        _INSPECTION_REQUEST_DIGEST_DOMAIN,
        (bytes(wire[:64]),),
    )
    wire[64:96] = request_digest
    return _InspectionRequestV2(
        request_id=request_id,
        projection_id=projection_id,
        request_digest=request_digest,
        canonical_wire=bytes(wire),
    )


def _inspection_protocol_failure(message: str) -> DeveloperLocalInspectionClientError:
    return _inspection_error(DeveloperLocalInspectionClientErrorCode.PROTOCOL, message)


def _require_nonzero(value: bytes, message: str) -> None:
    if not value or not any(value):
        raise _inspection_protocol_failure(message)


def _validate_inspection_owner_state(
    liveness: InspectionLivenessV1,
    readiness: InspectionReadinessV1,
    health: InspectionHealthV1,
    feature_support: InspectionFeatureSupportV1,
    reason: InspectionReasonV1,
) -> None:
    exact_green = (
        liveness is InspectionLivenessV1.LIVE
        and readiness is InspectionReadinessV1.READY
        and health is InspectionHealthV1.HEALTHY
        and feature_support is InspectionFeatureSupportV1.ALL_REQUIRED_SUPPORTED
    )
    projection_owned = reason in {
        InspectionReasonV1.SOURCE_MISSING,
        InspectionReasonV1.SOURCE_STALE,
        InspectionReasonV1.SOURCE_PARTITIONED,
    }
    invalid_ready = readiness is InspectionReadinessV1.READY and (
        liveness not in {InspectionLivenessV1.LIVE, InspectionLivenessV1.UNKNOWN}
        or feature_support is not InspectionFeatureSupportV1.ALL_REQUIRED_SUPPORTED
    )
    invalid_terminated = liveness in {
        InspectionLivenessV1.EXITED,
        InspectionLivenessV1.QUARANTINED,
    } and (
        readiness in {InspectionReadinessV1.READY, InspectionReadinessV1.DEGRADED}
        or health in {InspectionHealthV1.HEALTHY, InspectionHealthV1.DEGRADED}
    )
    if (
        exact_green != (reason is InspectionReasonV1.NONE)
        or projection_owned
        or invalid_ready
        or invalid_terminated
    ):
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 snapshot contains inconsistent owner state"
        )


def _is_masked_unknown(
    liveness: InspectionLivenessV1,
    readiness: InspectionReadinessV1,
    health: InspectionHealthV1,
    feature_support: InspectionFeatureSupportV1,
    reason: InspectionReasonV1,
    expected_reason: InspectionReasonV1,
) -> bool:
    return (
        liveness is InspectionLivenessV1.UNKNOWN
        and readiness is InspectionReadinessV1.UNKNOWN
        and health is InspectionHealthV1.UNKNOWN
        and feature_support is InspectionFeatureSupportV1.UNKNOWN
        and reason is expected_reason
    )


def _decode_inspection_owner_record_v1(
    wire: bytes,
    projected_at_nanos: int,
) -> LocalInspectionRecordV1:
    if len(wire) != _PXIS_OWNER_RECORD_BYTES or any(wire[88:96]):
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 snapshot owner record is non-canonical"
        )
    owner = _decode_inspection_enum(InspectionSourceOwnerV1, wire[0])
    freshness = _decode_inspection_enum(InspectionFreshnessV1, wire[1])
    liveness = _decode_inspection_enum(InspectionLivenessV1, wire[3])
    readiness = _decode_inspection_enum(InspectionReadinessV1, wire[4])
    health = _decode_inspection_enum(InspectionHealthV1, wire[5])
    feature_support = _decode_inspection_enum(InspectionFeatureSupportV1, wire[6])
    reason = _decode_inspection_enum(InspectionReasonV1, wire[7])
    subject_ref = wire[8:24]
    _require_nonzero(
        subject_ref,
        "DeveloperLocal Inspection v2 snapshot owner subject is invalid",
    )
    coordinate_value = int.from_bytes(wire[24:32], "big")
    coordinate_sequence = int.from_bytes(wire[32:40], "big")
    observed_at_nanos = int.from_bytes(wire[40:48], "big")
    valid_until_nanos = int.from_bytes(wire[48:56], "big")
    owner_fact_digest = wire[56:88]
    coordinate: InspectionSourceCoordinateV1 | None
    observed: int | None
    valid_until: int | None
    digest: bytes | None
    if freshness is InspectionFreshnessV1.MISSING:
        if (
            wire[2] != 0
            or coordinate_value != 0
            or coordinate_sequence != 0
            or observed_at_nanos != 0
            or valid_until_nanos != 0
            or any(owner_fact_digest)
            or not _is_masked_unknown(
                liveness,
                readiness,
                health,
                feature_support,
                reason,
                InspectionReasonV1.SOURCE_MISSING,
            )
        ):
            raise _inspection_protocol_failure(
                "DeveloperLocal Inspection v2 missing owner record is non-canonical"
            )
        coordinate = None
        observed = None
        valid_until = None
        digest = None
    else:
        coordinate_owner = _decode_inspection_enum(InspectionSourceOwnerV1, wire[2])
        if (
            coordinate_owner is not owner
            or coordinate_value == 0
            or coordinate_sequence == 0
            or observed_at_nanos == 0
            or observed_at_nanos > valid_until_nanos
            or observed_at_nanos > projected_at_nanos
            or not any(owner_fact_digest)
        ):
            raise _inspection_protocol_failure(
                "DeveloperLocal Inspection v2 owner record correlation is invalid"
            )
        if freshness is InspectionFreshnessV1.FRESH:
            if projected_at_nanos > valid_until_nanos:
                raise _inspection_protocol_failure(
                    "DeveloperLocal Inspection v2 fresh owner record is expired"
                )
            _validate_inspection_owner_state(
                liveness,
                readiness,
                health,
                feature_support,
                reason,
            )
        elif freshness is InspectionFreshnessV1.STALE:
            if projected_at_nanos <= valid_until_nanos or not _is_masked_unknown(
                liveness,
                readiness,
                health,
                feature_support,
                reason,
                InspectionReasonV1.SOURCE_STALE,
            ):
                raise _inspection_protocol_failure(
                    "DeveloperLocal Inspection v2 stale owner record is non-canonical"
                )
        elif freshness is InspectionFreshnessV1.PARTITIONED:
            if not _is_masked_unknown(
                liveness,
                readiness,
                health,
                feature_support,
                reason,
                InspectionReasonV1.SOURCE_PARTITIONED,
            ):
                raise _inspection_protocol_failure(
                    "DeveloperLocal Inspection v2 partitioned owner record is non-canonical"
                )
        else:
            raise _inspection_protocol_failure(
                "DeveloperLocal Inspection v2 owner freshness is invalid"
            )
        coordinate = InspectionSourceCoordinateV1(
            owner=coordinate_owner,
            value=coordinate_value,
            sequence=coordinate_sequence,
        )
        observed = observed_at_nanos
        valid_until = valid_until_nanos
        digest = owner_fact_digest
    return LocalInspectionRecordV1(
        owner=owner,
        freshness=freshness,
        subject_ref=subject_ref,
        coordinate=coordinate,
        observed_at_nanos=observed,
        valid_until_nanos=valid_until,
        liveness=liveness,
        readiness=readiness,
        health=health,
        feature_support=feature_support,
        reason=reason,
        owner_fact_digest=digest,
    )


def _derive_inspection_overall_v1(
    records: tuple[
        LocalInspectionRecordV1,
        LocalInspectionRecordV1,
        LocalInspectionRecordV1,
        LocalInspectionRecordV1,
        LocalInspectionRecordV1,
    ],
) -> LocalInspectionOverallV1:
    if any(
        record.liveness in {InspectionLivenessV1.EXITED, InspectionLivenessV1.QUARANTINED}
        or record.readiness in {InspectionReadinessV1.NOT_READY, InspectionReadinessV1.BLOCKED}
        or record.health is InspectionHealthV1.FAULTED
        or record.feature_support is InspectionFeatureSupportV1.REQUIRED_UNSUPPORTED
        for record in records
    ):
        return LocalInspectionOverallV1.UNAVAILABLE
    if any(
        record.freshness is not InspectionFreshnessV1.FRESH
        or record.liveness is InspectionLivenessV1.UNKNOWN
        or record.readiness is InspectionReadinessV1.UNKNOWN
        or record.health is InspectionHealthV1.UNKNOWN
        or record.feature_support is InspectionFeatureSupportV1.UNKNOWN
        for record in records
    ):
        return LocalInspectionOverallV1.UNKNOWN
    if any(
        record.liveness
        in {InspectionLivenessV1.BOOTSTRAPPING, InspectionLivenessV1.UNRESPONSIVE}
        or record.readiness is InspectionReadinessV1.DEGRADED
        or record.health is InspectionHealthV1.DEGRADED
        for record in records
    ):
        return LocalInspectionOverallV1.DEGRADED
    return LocalInspectionOverallV1.READY


def _decode_local_inspection_snapshot_v1(wire: bytes) -> LocalInspectionSnapshotV1:
    if len(wire) != _PXIS_V1_BYTES:
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 nested PXIS-v1 length is invalid"
        )
    if wire[:4] != b"PXIS" or int.from_bytes(wire[4:6], "big") != 1 or int.from_bytes(
        wire[6:8], "big"
    ) != _PXIS_HEADER_BYTES:
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 nested PXIS-v1 version is invalid"
        )
    if (
        int.from_bytes(wire[8:12], "big") != _PXIS_V1_BYTES
        or int.from_bytes(wire[12:16], "big") != 5 * _PXIS_OWNER_RECORD_BYTES
        or int.from_bytes(wire[64:66], "big") != 5
        or int.from_bytes(wire[66:68], "big") != _PXIS_OWNER_RECORD_BYTES
        or any(wire[69:80])
    ):
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 nested PXIS-v1 header is non-canonical"
        )
    projection_id = wire[16:32]
    observation_clock_ref = wire[32:48]
    _require_nonzero(
        projection_id,
        "DeveloperLocal Inspection v2 snapshot projection identity is invalid",
    )
    _require_nonzero(
        observation_clock_ref,
        "DeveloperLocal Inspection v2 snapshot clock identity is invalid",
    )
    projection_revision = int.from_bytes(wire[48:56], "big")
    projected_at_nanos = int.from_bytes(wire[56:64], "big")
    if projection_revision == 0 or projected_at_nanos == 0:
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 snapshot revision or timestamp is invalid"
        )
    declared_overall = _decode_inspection_enum(LocalInspectionOverallV1, wire[68])
    declared_digest = wire[80:112]
    computed_digest = _canonical_digest(
        _INSPECTION_SNAPSHOT_V1_DIGEST_DOMAIN,
        (wire[:80], wire[_PXIS_HEADER_BYTES:]),
    )
    if not hmac.compare_digest(declared_digest, computed_digest):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.DIGEST_MISMATCH,
            "DeveloperLocal Inspection v2 nested snapshot digest mismatched",
        )
    decoded = tuple(
        _decode_inspection_owner_record_v1(
            wire[
                _PXIS_HEADER_BYTES
                + index * _PXIS_OWNER_RECORD_BYTES : _PXIS_HEADER_BYTES
                + (index + 1) * _PXIS_OWNER_RECORD_BYTES
            ],
            projected_at_nanos,
        )
        for index in range(5)
    )
    records = (decoded[0], decoded[1], decoded[2], decoded[3], decoded[4])
    expected_owners = tuple(InspectionSourceOwnerV1)
    if tuple(record.owner for record in records) != expected_owners:
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 snapshot owner order is non-canonical"
        )
    overall = _derive_inspection_overall_v1(records)
    if declared_overall is not overall:
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 nested snapshot aggregate is invalid"
        )
    return LocalInspectionSnapshotV1(
        projection_id=projection_id,
        observation_clock_ref=observation_clock_ref,
        projection_revision=projection_revision,
        projected_at_nanos=projected_at_nanos,
        overall=overall,
        records=records,
        projection_digest=declared_digest,
        canonical_wire=wire,
    )


def _decode_inspection_node_record_v2(
    wire: bytes,
    projected_at_nanos: int,
) -> NodeInspectionRecordV2:
    if (
        len(wire) != _PXIS_NODE_RECORD_BYTES
        or any(wire[6:8])
        or any(wire[104:])
    ):
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 NodeDaemon record is non-canonical"
        )
    freshness = _decode_inspection_enum(InspectionFreshnessV1, wire[0])
    liveness = _decode_inspection_enum(InspectionLivenessV1, wire[1])
    readiness = _decode_inspection_enum(InspectionReadinessV1, wire[2])
    health = _decode_inspection_enum(InspectionHealthV1, wire[3])
    feature_support = _decode_inspection_enum(InspectionFeatureSupportV1, wire[4])
    reason = _decode_inspection_enum(InspectionReasonV1, wire[5])
    node_ref = wire[8:24]
    node_incarnation_ref = wire[24:40]
    _require_nonzero(
        node_ref,
        "DeveloperLocal Inspection v2 NodeDaemon identity is invalid",
    )
    _require_nonzero(
        node_incarnation_ref,
        "DeveloperLocal Inspection v2 NodeDaemon incarnation is invalid",
    )
    epoch_value = int.from_bytes(wire[40:48], "big")
    sequence_value = int.from_bytes(wire[48:56], "big")
    observed_value = int.from_bytes(wire[56:64], "big")
    valid_until_value = int.from_bytes(wire[64:72], "big")
    digest_value = wire[72:104]
    registration_epoch: int | None
    status_sequence: int | None
    observed_at_nanos: int | None
    valid_until_nanos: int | None
    node_status_digest: bytes | None
    if freshness is InspectionFreshnessV1.MISSING:
        if (
            epoch_value != 0
            or sequence_value != 0
            or observed_value != 0
            or valid_until_value != 0
            or any(digest_value)
            or not _is_masked_unknown(
                liveness,
                readiness,
                health,
                feature_support,
                reason,
                InspectionReasonV1.SOURCE_MISSING,
            )
        ):
            raise _inspection_protocol_failure(
                "DeveloperLocal Inspection v2 missing NodeDaemon record is non-canonical"
            )
        registration_epoch = None
        status_sequence = None
        observed_at_nanos = None
        valid_until_nanos = None
        node_status_digest = None
    else:
        if (
            epoch_value == 0
            or sequence_value == 0
            or observed_value == 0
            or observed_value > valid_until_value
            or observed_value > projected_at_nanos
            or not any(digest_value)
        ):
            raise _inspection_protocol_failure(
                "DeveloperLocal Inspection v2 NodeDaemon correlation is invalid"
            )
        if freshness is InspectionFreshnessV1.FRESH:
            if projected_at_nanos > valid_until_value:
                raise _inspection_protocol_failure(
                    "DeveloperLocal Inspection v2 fresh NodeDaemon record is expired"
                )
            _validate_inspection_owner_state(
                liveness,
                readiness,
                health,
                feature_support,
                reason,
            )
        elif freshness is InspectionFreshnessV1.STALE:
            if projected_at_nanos <= valid_until_value or not _is_masked_unknown(
                liveness,
                readiness,
                health,
                feature_support,
                reason,
                InspectionReasonV1.SOURCE_STALE,
            ):
                raise _inspection_protocol_failure(
                    "DeveloperLocal Inspection v2 stale NodeDaemon record is non-canonical"
                )
        elif freshness is InspectionFreshnessV1.PARTITIONED:
            if not _is_masked_unknown(
                liveness,
                readiness,
                health,
                feature_support,
                reason,
                InspectionReasonV1.SOURCE_PARTITIONED,
            ):
                raise _inspection_protocol_failure(
                    "DeveloperLocal Inspection v2 partitioned NodeDaemon record is non-canonical"
                )
        else:
            raise _inspection_protocol_failure(
                "DeveloperLocal Inspection v2 NodeDaemon freshness is invalid"
            )
        registration_epoch = epoch_value
        status_sequence = sequence_value
        observed_at_nanos = observed_value
        valid_until_nanos = valid_until_value
        node_status_digest = digest_value
    return NodeInspectionRecordV2(
        freshness=freshness,
        node_ref=node_ref,
        node_incarnation_ref=node_incarnation_ref,
        registration_epoch=registration_epoch,
        status_sequence=status_sequence,
        observed_at_nanos=observed_at_nanos,
        valid_until_nanos=valid_until_nanos,
        liveness=liveness,
        readiness=readiness,
        health=health,
        feature_support=feature_support,
        reason=reason,
        node_status_digest=node_status_digest,
    )


def _derive_inspection_overall_v2(
    base: LocalInspectionOverallV1,
    node: NodeInspectionRecordV2,
) -> LocalInspectionOverallV1:
    if (
        base is LocalInspectionOverallV1.UNAVAILABLE
        or node.liveness in {InspectionLivenessV1.EXITED, InspectionLivenessV1.QUARANTINED}
        or node.readiness in {InspectionReadinessV1.NOT_READY, InspectionReadinessV1.BLOCKED}
        or node.health is InspectionHealthV1.FAULTED
        or node.feature_support is InspectionFeatureSupportV1.REQUIRED_UNSUPPORTED
    ):
        return LocalInspectionOverallV1.UNAVAILABLE
    if (
        base is LocalInspectionOverallV1.UNKNOWN
        or node.freshness is not InspectionFreshnessV1.FRESH
        or node.liveness is InspectionLivenessV1.UNKNOWN
        or node.readiness is InspectionReadinessV1.UNKNOWN
        or node.health is InspectionHealthV1.UNKNOWN
        or node.feature_support is InspectionFeatureSupportV1.UNKNOWN
    ):
        return LocalInspectionOverallV1.UNKNOWN
    if (
        base is LocalInspectionOverallV1.DEGRADED
        or node.liveness
        in {InspectionLivenessV1.BOOTSTRAPPING, InspectionLivenessV1.UNRESPONSIVE}
        or node.readiness is InspectionReadinessV1.DEGRADED
        or node.health is InspectionHealthV1.DEGRADED
    ):
        return LocalInspectionOverallV1.DEGRADED
    return LocalInspectionOverallV1.READY


def _decode_local_inspection_snapshot_v2(wire: bytes) -> LocalInspectionSnapshotV2:
    if len(wire) != _PXIS_V2_BYTES:
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 snapshot length is invalid"
        )
    if (
        wire[:4] != b"PXIS"
        or int.from_bytes(wire[4:6], "big") != _INSPECTION_VERSION
        or int.from_bytes(wire[6:8], "big") != _PXIS_HEADER_BYTES
    ):
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 snapshot version is invalid"
        )
    if (
        int.from_bytes(wire[8:12], "big") != _PXIS_V2_BYTES
        or int.from_bytes(wire[12:16], "big")
        != _PXIS_V1_BYTES + _PXIS_NODE_RECORD_BYTES
        or int.from_bytes(wire[64:68], "big") != _PXIS_V1_BYTES
        or int.from_bytes(wire[68:70], "big") != _PXIS_NODE_RECORD_BYTES
        or any(wire[71:80])
    ):
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 snapshot header is non-canonical"
        )
    projection_id = wire[16:32]
    observation_clock_ref = wire[32:48]
    _require_nonzero(
        projection_id,
        "DeveloperLocal Inspection v2 snapshot projection identity is invalid",
    )
    _require_nonzero(
        observation_clock_ref,
        "DeveloperLocal Inspection v2 snapshot clock identity is invalid",
    )
    projection_revision = int.from_bytes(wire[48:56], "big")
    projected_at_nanos = int.from_bytes(wire[56:64], "big")
    if projection_revision == 0 or projected_at_nanos == 0:
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 snapshot revision or timestamp is invalid"
        )
    declared_overall = _decode_inspection_enum(LocalInspectionOverallV1, wire[70])
    declared_digest = wire[80:112]
    computed_digest = _canonical_digest(
        _INSPECTION_SNAPSHOT_V2_DIGEST_DOMAIN,
        (wire[:80], wire[_PXIS_HEADER_BYTES:]),
    )
    if not hmac.compare_digest(declared_digest, computed_digest):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.DIGEST_MISMATCH,
            "DeveloperLocal Inspection v2 snapshot digest mismatched",
        )
    base_end = _PXIS_HEADER_BYTES + _PXIS_V1_BYTES
    base = _decode_local_inspection_snapshot_v1(wire[_PXIS_HEADER_BYTES:base_end])
    if (
        base.projection_id != projection_id
        or base.observation_clock_ref != observation_clock_ref
        or base.projection_revision != projection_revision
        or base.projected_at_nanos != projected_at_nanos
    ):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.CORRELATION_MISMATCH,
            "DeveloperLocal Inspection v2 nested snapshot correlation mismatched",
        )
    node = _decode_inspection_node_record_v2(wire[base_end:], projected_at_nanos)
    overall = _derive_inspection_overall_v2(base.overall, node)
    if declared_overall is not overall:
        raise _inspection_protocol_failure(
            "DeveloperLocal Inspection v2 snapshot aggregate is invalid"
        )
    return LocalInspectionSnapshotV2(
        base_snapshot=base,
        node=node,
        overall=overall,
        projection_digest=declared_digest,
        canonical_wire=wire,
    )


def _decode_inspection_response_v2(
    wire: bytes,
    request: _InspectionRequestV2,
) -> LocalInspectionSnapshotV2 | None:
    if not isinstance(wire, bytes) or not (
        _PXIP_HEADER_BYTES <= len(wire) <= _MAX_INSPECTION_RESPONSE_BYTES
    ):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.INVALID_FRAME,
            "DeveloperLocal Inspection v2 response length is invalid",
        )
    if (
        wire[:4] != _PXIP_MAGIC
        or int.from_bytes(wire[4:6], "big") != _INSPECTION_VERSION
        or int.from_bytes(wire[6:8], "big") != _PXIP_HEADER_BYTES
    ):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.INVALID_FRAME,
            "DeveloperLocal Inspection v2 response version is invalid",
        )
    payload_length = int.from_bytes(wire[12:16], "big")
    if (
        int.from_bytes(wire[8:12], "big") != len(wire)
        or _PXIP_HEADER_BYTES + payload_length != len(wire)
        or any(wire[18:24])
        or any(wire[104:112])
    ):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.INVALID_FRAME,
            "DeveloperLocal Inspection v2 response is non-canonical",
        )
    payload = wire[_PXIP_HEADER_BYTES:]
    computed_digest = _canonical_digest(
        _INSPECTION_RESPONSE_DIGEST_DOMAIN,
        (wire[:112], payload),
    )
    if not hmac.compare_digest(wire[112:144], computed_digest):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.DIGEST_MISMATCH,
            "DeveloperLocal Inspection v2 response digest mismatched",
        )
    outcome = _decode_inspection_enum(_InspectionResponseOutcomeV2, wire[16])
    request_kind = wire[17]
    request_id = wire[24:40]
    projection_id = wire[40:56]
    after_revision = int.from_bytes(wire[56:64], "big")
    current_revision = int.from_bytes(wire[64:72], "big")
    request_digest = wire[72:104]
    if (
        request_kind != 1
        or after_revision != 0
        or request_id != request.request_id
        or projection_id != request.projection_id
        or not hmac.compare_digest(request_digest, request.request_digest)
    ):
        raise _inspection_error(
            DeveloperLocalInspectionClientErrorCode.CORRELATION_MISMATCH,
            "DeveloperLocal Inspection v2 response correlation mismatched",
        )
    if outcome is _InspectionResponseOutcomeV2.SNAPSHOT:
        if payload_length != _PXIS_V2_BYTES or current_revision == 0:
            raise _inspection_error(
                DeveloperLocalInspectionClientErrorCode.INVALID_FRAME,
                "DeveloperLocal Inspection v2 snapshot response shape is invalid",
            )
        snapshot = _decode_local_inspection_snapshot_v2(payload)
        if (
            snapshot.projection_id != projection_id
            or snapshot.projection_revision != current_revision
        ):
            raise _inspection_error(
                DeveloperLocalInspectionClientErrorCode.CORRELATION_MISMATCH,
                "DeveloperLocal Inspection v2 snapshot response correlation mismatched",
            )
        return snapshot
    if outcome is _InspectionResponseOutcomeV2.NOT_FOUND:
        if payload_length != 0 or current_revision != 0:
            raise _inspection_error(
                DeveloperLocalInspectionClientErrorCode.INVALID_FRAME,
                "DeveloperLocal Inspection v2 not-found response shape is invalid",
            )
        return None
    raise _inspection_error(
        DeveloperLocalInspectionClientErrorCode.INVALID_FRAME,
        "DeveloperLocal Inspection v2 Latest response outcome is invalid",
    )


class DeveloperLocalInspectionClientV2:
    """Generation-scoped, single-use PXIQ-v2 Latest client over private UDS."""

    def __init__(self, bootstrap: _InspectionBootstrapV2) -> None:
        self._bootstrap = bootstrap
        self._used = False
        self._closed = False

    @classmethod
    def from_private_bootstrap_file(
        cls,
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes] | Path,
    ) -> DeveloperLocalInspectionClientV2:
        return cls(_read_private_inspection_bootstrap_file_v2(path))

    async def latest(self) -> LocalInspectionSnapshotV2:
        if self._closed:
            raise _inspection_error(
                DeveloperLocalInspectionClientErrorCode.CLOSED,
                "DeveloperLocal Inspection v2 client is closed",
            )
        if self._used:
            raise _inspection_error(
                DeveloperLocalInspectionClientErrorCode.ALREADY_USED,
                "DeveloperLocal Inspection v2 startup read was already attempted",
            )
        self._used = True
        request = _encode_inspection_latest_request_v2(
            _inspection_request_id_v2(self._bootstrap, 1),
            self._bootstrap.projection_id,
        )
        authenticated_request = bytearray(self._bootstrap.generation_token)
        authenticated_request.extend(request.canonical_wire)
        socket_identity = _validate_inspection_socket_path(self._bootstrap)

        async def exchange_once() -> bytes:
            writer: asyncio.StreamWriter | None = None
            try:
                reader, writer = await asyncio.open_unix_connection(
                    path=self._bootstrap.socket_path
                )
                stream_socket = writer.get_extra_info("socket")
                try:
                    peer = _peer_credentials(stream_socket) if stream_socket is not None else None
                except RuntimeAgentConversationClientError as cause:
                    raise _inspection_error(
                        DeveloperLocalInspectionClientErrorCode.PEER_CREDENTIALS_MISMATCH,
                        "DeveloperLocal Inspection v2 peer identity is unavailable",
                    ) from cause
                if peer != (self._bootstrap.server_uid, self._bootstrap.server_gid):
                    raise _inspection_error(
                        DeveloperLocalInspectionClientErrorCode.PEER_CREDENTIALS_MISMATCH,
                        "DeveloperLocal Inspection v2 peer identity mismatched",
                    )
                if _validate_inspection_socket_path(self._bootstrap) != socket_identity:
                    raise _inspection_error(
                        DeveloperLocalInspectionClientErrorCode.ENDPOINT_IDENTITY_CHANGED,
                        "DeveloperLocal Inspection v2 socket identity changed",
                    )
                writer.write(authenticated_request)
                await writer.drain()
                if not writer.can_write_eof():
                    raise _inspection_error(
                        DeveloperLocalInspectionClientErrorCode.IO,
                        "DeveloperLocal Inspection v2 request framing cannot complete",
                    )
                writer.write_eof()
                length = int.from_bytes(await reader.readexactly(4), "big")
                if not 1 <= length <= _MAX_INSPECTION_RESPONSE_BYTES:
                    raise _inspection_error(
                        DeveloperLocalInspectionClientErrorCode.INVALID_FRAME,
                        "DeveloperLocal Inspection v2 response length is invalid",
                    )
                response = await reader.readexactly(length)
                if await reader.read(1):
                    raise _inspection_error(
                        DeveloperLocalInspectionClientErrorCode.INVALID_FRAME,
                        "DeveloperLocal Inspection v2 response has trailing bytes",
                    )
                return response
            finally:
                if writer is not None:
                    writer.close()

        try:
            response_wire = await asyncio.wait_for(
                exchange_once(),
                timeout=self._bootstrap.operation_timeout_nanos / 1_000_000_000,
            )
        except TimeoutError as cause:
            raise _inspection_error(
                DeveloperLocalInspectionClientErrorCode.OPERATION_TIMED_OUT,
                "DeveloperLocal Inspection v2 startup read timed out",
            ) from cause
        except DeveloperLocalInspectionClientError:
            raise
        except (OSError, asyncio.IncompleteReadError) as cause:
            raise _inspection_error(
                DeveloperLocalInspectionClientErrorCode.IO,
                "DeveloperLocal Inspection v2 exchange failed",
            ) from cause
        finally:
            authenticated_request[:] = bytes(len(authenticated_request))
        snapshot = _decode_inspection_response_v2(response_wire, request)
        if snapshot is None:
            raise _inspection_error(
                DeveloperLocalInspectionClientErrorCode.SNAPSHOT_UNAVAILABLE,
                "DeveloperLocal Inspection v2 startup snapshot is unavailable",
            )
        return snapshot

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._bootstrap.generation_token[:] = bytes(32)
        self._bootstrap.request_seed[:] = bytes(16)


__all__ = [
    "DeveloperLocalInspectionClientError",
    "DeveloperLocalInspectionClientErrorCode",
    "DeveloperLocalInspectionClientV2",
    "InspectionFeatureSupportV1",
    "InspectionFreshnessV1",
    "InspectionHealthV1",
    "InspectionLivenessV1",
    "InspectionReadinessV1",
    "InspectionReasonV1",
    "InspectionSourceCoordinateV1",
    "InspectionSourceOwnerV1",
    "LocalInspectionOverallV1",
    "LocalInspectionRecordV1",
    "LocalInspectionSnapshotV1",
    "LocalInspectionSnapshotV2",
    "NodeInspectionRecordV2",
    "RuntimeAgentConversationCancelResultV1",
    "RuntimeAgentConversationClientError",
    "RuntimeAgentConversationClientErrorCode",
    "RuntimeAgentConversationClientV1",
]
