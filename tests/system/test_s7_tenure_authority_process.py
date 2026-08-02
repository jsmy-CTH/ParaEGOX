from __future__ import annotations

import errno
import hashlib
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="the S7-D reference Authority uses Unix credentials and sockets"
)  # GOV-WAIVER-0006

DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
DIGEST_VERSION = 1
DIGEST_FIELD = b"\x01"
DIGEST_END = b"\xff"

REQUEST_MAGIC = b"PXATREQ\0"
RESPONSE_MAGIC = b"PXATRSP\0"
FRAME_MAGIC = b"PXATFRM\0"
PROTOCOL_VERSION = 1
FRAME_VERSION = 1
REQUEST_KIND = 1
RESPONSE_KIND = 2
REQUEST_FIELD_COUNT = 12
RESPONSE_FIELD_COUNT = 15
MIN_RESPONSE_PAYLOAD_BYTES = 301
MAX_RESPONSE_PAYLOAD_BYTES = 938

REQUEST_TRANSCRIPT_MAGIC = b"ParaEGOX\0acquire-tenure-request-auth"
REQUEST_TRANSCRIPT_DOMAIN = b"paraegox.deployment.acquire-tenure.request-auth.ed25519.v1"
REQUEST_TRANSCRIPT_VERSION = 1
INTENT_DIGEST_DOMAIN = b"paraegox.deployment.acquire-tenure.intent.sha256.v1"
REQUEST_DIGEST_DOMAIN = b"paraegox.deployment.acquire-tenure.request.sha256.v1"
RESPONSE_DIGEST_DOMAIN = b"paraegox.deployment.acquire-tenure.response.sha256.v1"
CONTROLLER_KEY_DOMAIN = b"paraegox.deployment.acquire-tenure.controller-key.sha256.v1"
TENURE_PROOF_DOMAIN = b"paraegox.runtime.writer-tenure-proof.sha256.v1"
TENURE_TRANSCRIPT_MAGIC = b"ParaEGOX\0canonical-signing-transcript"
TENURE_TRANSCRIPT_DOMAIN = b"paraegox.runtime.writer-tenure.signing.v1"
TENURE_TRANSCRIPT_VERSION = 1
RECEIPT_DIGEST_DOMAIN = (
    b"paraegox.deployment.tenure-authority.initialization-receipt.sha256.v1"
)


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _digest(domain: bytes, fields: Sequence[bytes]) -> bytes:
    digest = hashlib.sha256()
    digest.update(DIGEST_MAGIC)
    digest.update(_u16(DIGEST_VERSION))
    digest.update(_u32(len(domain)))
    digest.update(domain)
    for ordinal, field in enumerate(fields, start=1):
        digest.update(DIGEST_FIELD)
        digest.update(_u32(ordinal))
        digest.update(_u64(len(field)))
        digest.update(field)
    digest.update(DIGEST_END)
    digest.update(_u32(len(fields)))
    return digest.digest()


def _tlv(tag: int, value: bytes) -> bytes:
    return _u16(tag) + _u32(len(value)) + value


def _value(magic: bytes, field_count: int, fields: Sequence[bytes]) -> bytes:
    assert len(fields) == field_count
    return magic + _u16(PROTOCOL_VERSION) + _u16(field_count) + b"".join(
        _tlv(tag, value) for tag, value in enumerate(fields, start=1)
    )


def _transcript(magic: bytes, version: int, domain: bytes, fields: Sequence[bytes]) -> bytes:
    return (
        magic
        + _u16(version)
        + _u16(len(domain))
        + domain
        + _u16(len(fields))
        + b"".join(_tlv(tag, value) for tag, value in enumerate(fields, start=1))
    )


def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


@dataclass(frozen=True)
class AcquireRequest:
    operation: bytes
    scope: bytes
    writer: bytes
    nonce: bytes
    payload: bytes
    request_digest: bytes
    frame: bytes


def _build_request(
    *,
    operation: bytes,
    scope: bytes,
    writer: bytes,
    principal: bytes,
    controller_key_ref: bytes,
    controller_public_key: bytes,
    nonce: bytes,
    signer: Ed25519PrivateKey,
    carried_key_fingerprint: bytes | None = None,
    max_response_payload_bytes: int = MAX_RESPONSE_PAYLOAD_BYTES,
) -> AcquireRequest:
    fingerprint = carried_key_fingerprint or _digest(
        CONTROLLER_KEY_DOMAIN,
        [_u16(1), _u16(1), controller_public_key],
    )
    intent_digest = _digest(INTENT_DIGEST_DOMAIN, [scope, writer, operation])
    unsigned_fields = [
        scope,
        writer,
        operation,
        principal,
        controller_key_ref,
        fingerprint,
        _u16(1),
        _u16(1),
        nonce,
        _u32(max_response_payload_bytes),
        intent_digest,
    ]
    signature = signer.sign(
        _transcript(
            REQUEST_TRANSCRIPT_MAGIC,
            REQUEST_TRANSCRIPT_VERSION,
            REQUEST_TRANSCRIPT_DOMAIN,
            unsigned_fields,
        )
    )
    payload = _value(REQUEST_MAGIC, REQUEST_FIELD_COUNT, [*unsigned_fields, signature])
    request_digest = _digest(REQUEST_DIGEST_DOMAIN, [payload])
    frame = FRAME_MAGIC + _u16(FRAME_VERSION) + _u16(REQUEST_KIND) + _u32(len(payload)) + payload
    return AcquireRequest(operation, scope, writer, nonce, payload, request_digest, frame)


def _parse_value(payload: bytes, magic: bytes, field_count: int) -> list[bytes]:
    assert payload[:8] == magic
    assert int.from_bytes(payload[8:10], "big") == PROTOCOL_VERSION
    assert int.from_bytes(payload[10:12], "big") == field_count
    cursor = 12
    fields: list[bytes] = []
    for expected_tag in range(1, field_count + 1):
        assert cursor + 6 <= len(payload)
        tag = int.from_bytes(payload[cursor : cursor + 2], "big")
        length = int.from_bytes(payload[cursor + 2 : cursor + 6], "big")
        assert tag == expected_tag
        cursor += 6
        assert cursor + length <= len(payload)
        fields.append(payload[cursor : cursor + length])
        cursor += length
    assert cursor == len(payload)
    return fields


def _read_exact(stream: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.recv(length - len(chunks))
        if not chunk:
            raise EOFError(f"socket closed after {len(chunks)} of {length} bytes")
        chunks.extend(chunk)
    return bytes(chunks)


def _exchange(socket_path: Path, request: AcquireRequest) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(3)
        stream.connect(os.fspath(socket_path))
        stream.sendall(request.frame)
        header = _read_exact(stream, 16)
        assert header[:8] == FRAME_MAGIC
        assert int.from_bytes(header[8:10], "big") == FRAME_VERSION
        assert int.from_bytes(header[10:12], "big") == RESPONSE_KIND
        payload_length = int.from_bytes(header[12:16], "big")
        assert 0 < payload_length <= MAX_RESPONSE_PAYLOAD_BYTES
        payload = _read_exact(stream, payload_length)
        return header + payload


def _exchange_rejected(socket_path: Path, request: AcquireRequest) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(3)
        stream.connect(os.fspath(socket_path))
        try:
            stream.sendall(request.frame)
            stream.shutdown(socket.SHUT_WR)
            response = stream.recv(1)
        except OSError as error:
            assert error.errno in {errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN}
            response = b""
        assert response == b""


def _send_without_reading_response(socket_path: Path, request: AcquireRequest) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(3)
        stream.connect(os.fspath(socket_path))
        stream.sendall(request.frame)
        stream.shutdown(socket.SHUT_RDWR)


@dataclass(frozen=True)
class AcquireResponse:
    frame: bytes
    epoch: int
    supersedes: int
    proof_digest: bytes
    response_digest: bytes


def _verify_response(
    encoded_frame: bytes,
    request: AcquireRequest,
    *,
    authority_public_key: bytes,
    authority_ref: bytes,
    tenure_key_ref: bytes,
) -> AcquireResponse:
    assert encoded_frame[:8] == FRAME_MAGIC
    payload_length = int.from_bytes(encoded_frame[12:16], "big")
    assert len(encoded_frame) == 16 + payload_length
    payload = encoded_frame[16:]
    fields = _parse_value(payload, RESPONSE_MAGIC, RESPONSE_FIELD_COUNT)
    assert fields[0] == request.operation
    assert fields[1] == request.request_digest
    assert fields[2] == request.nonce
    assert fields[3] == authority_ref
    assert fields[4] == tenure_key_ref
    assert fields[5] == _u16(1)
    assert fields[6] == _u16(1)
    assert fields[7] == request.scope
    assert fields[8] == request.writer
    epoch = int.from_bytes(fields[9], "big")
    supersedes = int.from_bytes(fields[10], "big")
    assert epoch > 0
    assert supersedes == epoch - 1
    assert fields[11] == request.nonce
    assert len(fields[12]) == 64

    proof_fields = fields[3:13]
    expected_proof_digest = _digest(TENURE_PROOF_DOMAIN, proof_fields)
    assert fields[13] == expected_proof_digest
    tenure_transcript = _transcript(
        TENURE_TRANSCRIPT_MAGIC,
        TENURE_TRANSCRIPT_VERSION,
        TENURE_TRANSCRIPT_DOMAIN,
        fields[3:12],
    )
    Ed25519PublicKey.from_public_bytes(authority_public_key).verify(fields[12], tenure_transcript)

    unsigned_response = _value(RESPONSE_MAGIC, RESPONSE_FIELD_COUNT - 1, fields[:14])
    expected_response_digest = _digest(RESPONSE_DIGEST_DOMAIN, [unsigned_response])
    assert fields[14] == expected_response_digest
    return AcquireResponse(
        encoded_frame,
        epoch,
        supersedes,
        expected_proof_digest,
        expected_response_digest,
    )


@dataclass
class InstalledAuthority:
    state_dir: Path
    socket_dir: Path
    socket_path: Path
    private_seed_path: Path
    authority_private: Ed25519PrivateKey
    controller_private: Ed25519PrivateKey
    authority_public: bytes
    controller_public: bytes
    scope: bytes
    writer: bytes
    authority_ref: bytes
    tenure_key_ref: bytes
    controller_principal: bytes
    controller_key_ref: bytes
    common_arguments: list[str]
    command_prefix: tuple[str, ...]
    restrictive_umask: bool
    store_id: bytes | None = None

    def serve_arguments(self) -> list[str]:
        assert self.store_id is not None
        return [
            "serve",
            *self.common_arguments,
            "--expected-store-id",
            self.store_id.hex(),
            "--private-seed",
            os.fspath(self.private_seed_path),
        ]


def _run_checked(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed


def _set_owner_mode(path: Path, uid: int, gid: int, mode: int) -> None:
    if uid == os.getuid() and gid == os.getgid():
        os.chown(path, uid, gid)
        path.chmod(mode)
        return
    _run_checked(["sudo", "-n", "chown", f"{uid}:{gid}", os.fspath(path)])
    _run_checked(["sudo", "-n", "chmod", f"{mode:o}", os.fspath(path)])


def _mode_bits(path: Path) -> int:
    try:
        return path.stat().st_mode & 0o7777
    except PermissionError:
        assert sys.platform == "linux"
        completed = _run_checked(["sudo", "-n", "stat", "-c", "%a", os.fspath(path)])
        return int(completed.stdout.strip(), 8)


def _file_identity(path: Path) -> tuple[int, int, int]:
    try:
        metadata = path.stat()
        return metadata.st_dev, metadata.st_ino, metadata.st_size
    except PermissionError:
        assert sys.platform == "linux"
        completed = _run_checked(
            ["sudo", "-n", "stat", "-c", "%d %i %s", os.fspath(path)]
        )
        device, inode, size = (int(value) for value in completed.stdout.split())
        return device, inode, size


def _write_key(path: Path, value: bytes, mode: int, *, uid: int, gid: int) -> None:
    path.write_bytes(value)
    _set_owner_mode(path, uid, gid, mode)


def _authority_command(
    binary: Path,
    arguments: Sequence[str],
    *,
    command_prefix: Sequence[str],
    restrictive_umask: bool,
) -> list[str]:
    command = [os.fspath(binary), *arguments]
    if restrictive_umask:
        command = [
            "/bin/sh",
            "-c",
            'umask 0777; exec "$@"',
            "paraegox-authority-umask",
            *command,
        ]
    return [*command_prefix, *command]


def _linux_distinct_authority_identity() -> tuple[int, int, tuple[str, ...]]:
    assert sys.platform == "linux"
    _run_checked(["sudo", "-n", "true"])
    import pwd

    for name in ("nobody", "daemon"):
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            continue
        if account.pw_uid not in {0, os.getuid()} and account.pw_gid != 0:
            prefix = (
                "sudo",
                "-n",
                "-u",
                f"#{account.pw_uid}",
                "-g",
                f"#{account.pw_gid}",
                "--",
            )
            completed = _run_checked([*prefix, "id", "-u"])
            assert int(completed.stdout.strip()) == account.pw_uid
            return account.pw_uid, account.pw_gid, prefix
    pytest.fail("no distinct non-root Authority service account is available")


def _install(
    tmp_path: Path,
    *,
    authority_uid: int | None = None,
    authority_gid: int | None = None,
    expected_peer_uid: int | None = None,
    expected_peer_gid: int | None = None,
    command_prefix: Sequence[str] = (),
    restrictive_umask: bool = False,
) -> InstalledAuthority:
    root = tmp_path.resolve()
    authority_uid = os.getuid() if authority_uid is None else authority_uid
    authority_gid = os.getgid() if authority_gid is None else authority_gid
    peer_uid = os.getuid() if expected_peer_uid is None else expected_peer_uid
    peer_gid = os.getgid() if expected_peer_gid is None else expected_peer_gid
    state_dir = root / "state"
    socket_dir = root / "socket"
    key_dir = root / "keys"
    state_dir.mkdir(mode=0o700)
    socket_dir.mkdir(mode=0o750)
    key_dir.mkdir(mode=0o700)
    for directory, uid, gid, mode in (
        (state_dir, authority_uid, authority_gid, 0o700),
        (socket_dir, authority_uid, peer_gid, 0o2750),
    ):
        _set_owner_mode(directory, uid, gid, mode)

    authority_private = Ed25519PrivateKey.from_private_bytes(b"\x71" * 32)
    controller_private = Ed25519PrivateKey.from_private_bytes(b"\x72" * 32)
    authority_public = _raw_public_key(authority_private)
    controller_public = _raw_public_key(controller_private)
    private_seed_path = key_dir / "authority.seed"
    authority_public_path = key_dir / "authority.pub"
    controller_public_path = key_dir / "controller.pub"
    _write_key(
        private_seed_path,
        b"\x71" * 32,
        0o600,
        uid=authority_uid,
        gid=authority_gid,
    )
    _write_key(
        authority_public_path,
        authority_public,
        0o644,
        uid=authority_uid,
        gid=authority_gid,
    )
    _write_key(
        controller_public_path,
        controller_public,
        0o644,
        uid=authority_uid,
        gid=authority_gid,
    )
    _set_owner_mode(key_dir, authority_uid, authority_gid, 0o700)

    scope = b"\x11" * 16
    writer = b"\x12" * 16
    authority_ref = b"\x13" * 16
    tenure_key_ref = b"\x14" * 16
    controller_principal = b"\x15" * 16
    controller_key_ref = b"\x16" * 16
    socket_path = socket_dir / "authority.sock"
    common_arguments = [
        "--state-dir",
        os.fspath(state_dir),
        "--socket-path",
        os.fspath(socket_path),
        "--authority-public-key",
        os.fspath(authority_public_path),
        "--controller-public-key",
        os.fspath(controller_public_path),
        "--source-scope",
        scope.hex(),
        "--writer-ref",
        writer.hex(),
        "--authority-ref",
        authority_ref.hex(),
        "--tenure-key-ref",
        tenure_key_ref.hex(),
        "--controller-principal-ref",
        controller_principal.hex(),
        "--controller-key-ref",
        controller_key_ref.hex(),
        "--service-principal-ref",
        (b"\x17" * 16).hex(),
        "--owner-id",
        (b"\x18" * 16).hex(),
        "--expected-authority-uid",
        str(authority_uid),
        "--expected-authority-gid",
        str(authority_gid),
        "--expected-peer-uid",
        str(peer_uid),
        "--expected-peer-gid",
        str(peer_gid),
    ]
    _set_owner_mode(root, authority_uid, peer_gid, 0o710)
    return InstalledAuthority(
        state_dir=state_dir,
        socket_dir=socket_dir,
        socket_path=socket_path,
        private_seed_path=private_seed_path,
        authority_private=authority_private,
        controller_private=controller_private,
        authority_public=authority_public,
        controller_public=controller_public,
        scope=scope,
        writer=writer,
        authority_ref=authority_ref,
        tenure_key_ref=tenure_key_ref,
        controller_principal=controller_principal,
        controller_key_ref=controller_key_ref,
        common_arguments=common_arguments,
        command_prefix=tuple(command_prefix),
        restrictive_umask=restrictive_umask,
    )


def _run_admin(
    binary: Path,
    arguments: Sequence[str],
    *,
    command_prefix: Sequence[str] = (),
    restrictive_umask: bool = False,
) -> dict[str, str]:
    completed = subprocess.run(
        _authority_command(
            binary,
            arguments,
            command_prefix=command_prefix,
            restrictive_umask=restrictive_umask,
        ),
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        assert separator == "=" and key not in result and value
        result[key] = value
    assert set(result) == {
        "store_instance_id",
        "snapshot_sequence",
        "epoch_high_water",
        "snapshot_checksum",
        "receipt_digest",
        "receipt_bytes",
    }
    assert result["snapshot_sequence"] == "1"
    assert result["epoch_high_water"] == "0"
    receipt_bytes = bytes.fromhex(result["receipt_bytes"])
    assert bytes.fromhex(result["receipt_digest"]) == _digest(
        RECEIPT_DIGEST_DOMAIN, [receipt_bytes]
    )
    return result


def _initialize(binary: Path, fixture: InstalledAuthority) -> dict[str, str]:
    receipt = _run_admin(
        binary,
        ["initialize", *fixture.common_arguments],
        command_prefix=fixture.command_prefix,
        restrictive_umask=fixture.restrictive_umask,
    )
    fixture.store_id = bytes.fromhex(receipt["store_instance_id"])
    assert len(fixture.store_id) == 32 and any(fixture.store_id)
    recovered = _run_admin(
        binary,
        [
            "initialization-receipt",
            *fixture.common_arguments,
        ],
        command_prefix=fixture.command_prefix,
        restrictive_umask=fixture.restrictive_umask,
    )
    assert recovered == receipt
    return receipt


def _wait_for_socket(process: subprocess.Popen[bytes], path: Path) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                f"Authority exited before readiness: {process.returncode}; "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.2)
                probe.connect(os.fspath(path))
            return
        except (TimeoutError, FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.02)
    pytest.fail("Authority socket did not become ready")


@contextmanager
def _server(binary: Path, fixture: InstalledAuthority) -> Iterator[subprocess.Popen[bytes]]:
    process = subprocess.Popen(
        _authority_command(
            binary,
            fixture.serve_arguments(),
            command_prefix=fixture.command_prefix,
            restrictive_umask=fixture.restrictive_umask,
        ),
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
    try:
        _wait_for_socket(process, fixture.socket_path)
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def _kill_server(process: subprocess.Popen[bytes]) -> None:
    os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


def _wait_for_snapshot_replacement(
    process: subprocess.Popen[bytes],
    path: Path,
    previous_identity: tuple[int, int, int],
) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                f"Authority exited before lost-reply commit: {process.returncode}; "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
        if _file_identity(path) != previous_identity:
            return
        time.sleep(0.02)
    pytest.fail("Authority did not durably replace the snapshot after the dropped reply")


@pytest.fixture(scope="module")
def authority_binary() -> Path:
    completed = subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "paraegox-deployment",
            "--bin",
            "paraegox-tenure-authority",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    binary = REPO_ROOT / "target" / "debug" / "paraegox-tenure-authority"
    assert binary.is_file()
    return binary


@pytest.fixture
def authority_tmp_path() -> Iterator[Path]:
    # Darwin limits AF_UNIX paths to 104 bytes, while pytest's default path can
    # exceed that before the socket filename is appended.
    with tempfile.TemporaryDirectory(prefix="pxa-", dir="/tmp") as path:
        root = Path(path)
        try:
            yield root
        finally:
            if root.exists() and root.stat().st_uid != os.getuid():
                _run_checked(
                    [
                        "sudo",
                        "-n",
                        "chown",
                        "-R",
                        f"{os.getuid()}:{os.getgid()}",
                        os.fspath(root),
                    ]
                )


def test_cli_stderr_has_stable_non_sensitive_diagnostic_fields(
    authority_binary: Path,
) -> None:
    completed = subprocess.run(
        [os.fspath(authority_binary), "unknown-command"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == (
        "invalid tenure-authority command line; code=PXTA-ARGUMENTS-INVALID "
        "stage=parse_arguments path_role=command_line fact=invalid\n"
    )


def test_independent_request_encoder_matches_frozen_rust_golden() -> None:
    controller = Ed25519PrivateKey.from_private_bytes(b"\x21" * 32)
    controller_public = _raw_public_key(controller)
    request = _build_request(
        operation=b"\x33" * 16,
        scope=b"\x11" * 16,
        writer=b"\x22" * 16,
        principal=b"\x44" * 16,
        controller_key_ref=b"\x55" * 16,
        controller_public_key=controller_public,
        nonce=b"s7-d-client-nonce",
        signer=controller,
    )
    assert len(request.payload) == 317
    assert _digest(CONTROLLER_KEY_DOMAIN, [_u16(1), _u16(1), controller_public]).hex() == (
        "a13c6e77913b3b115dfdfc72550e88af12fe6079e7c8f897f15daaaadfb72efa"
    )
    intent_digest = _digest(
        INTENT_DIGEST_DOMAIN,
        [request.scope, request.writer, request.operation],
    )
    assert intent_digest.hex() == (
        "54c50dbc7d32b6d666dd1eb3b4667d5408c666bda0a9a9d5944f69147cf107b9"
    )
    assert request.request_digest.hex() == (
        "baf7fb6da57650a7b6d342bb11fa72f70312e7e525b7f462c0071a261520ba18"
    )


@pytest.mark.skipif(  # GOV-WAIVER-0007
    sys.platform != "linux",
    reason="distinct service-account execution evidence runs on the Linux reference target",
)
def test_real_authority_process_commits_replays_locks_and_recovers(
    authority_binary: Path,
    authority_tmp_path: Path,
) -> None:
    authority_uid, authority_gid, command_prefix = _linux_distinct_authority_identity()
    fixture = _install(
        authority_tmp_path,
        authority_uid=authority_uid,
        authority_gid=authority_gid,
        expected_peer_uid=os.getuid(),
        expected_peer_gid=os.getgid(),
        command_prefix=command_prefix,
        restrictive_umask=True,
    )
    with pytest.raises(PermissionError):
        fixture.private_seed_path.read_bytes()
    _initialize(authority_binary, fixture)
    with pytest.raises(PermissionError):
        (fixture.state_dir / "authority.snapshot").read_bytes()
    assert _mode_bits(fixture.state_dir / "authority.lock") == 0o600
    assert _mode_bits(fixture.state_dir / "authority.snapshot") == 0o600
    sequence_one_identity = _file_identity(fixture.state_dir / "authority.snapshot")
    rogue = Ed25519PrivateKey.from_private_bytes(b"\x73" * 32)

    invalid_requests = [
        _build_request(
            operation=bytes([operation]) * 16,
            scope=scope,
            writer=writer,
            principal=principal,
            controller_key_ref=key_ref,
            controller_public_key=fixture.controller_public,
            nonce=bytes([operation]),
            signer=signer,
            carried_key_fingerprint=fingerprint,
        )
        for operation, scope, writer, principal, key_ref, signer, fingerprint in [
            (
                0x21,
                fixture.scope,
                fixture.writer,
                fixture.controller_principal,
                fixture.controller_key_ref,
                rogue,
                None,
            ),
            (
                0x22,
                b"\x31" * 16,
                fixture.writer,
                fixture.controller_principal,
                fixture.controller_key_ref,
                fixture.controller_private,
                None,
            ),
            (
                0x23,
                fixture.scope,
                b"\x32" * 16,
                fixture.controller_principal,
                fixture.controller_key_ref,
                fixture.controller_private,
                None,
            ),
            (
                0x24,
                fixture.scope,
                fixture.writer,
                b"\x33" * 16,
                fixture.controller_key_ref,
                fixture.controller_private,
                None,
            ),
            (
                0x25,
                fixture.scope,
                fixture.writer,
                fixture.controller_principal,
                b"\x34" * 16,
                fixture.controller_private,
                None,
            ),
            (
                0x26,
                fixture.scope,
                fixture.writer,
                fixture.controller_principal,
                fixture.controller_key_ref,
                fixture.controller_private,
                b"\x35" * 32,
            ),
        ]
    ]
    invalid_requests.append(
        _build_request(
            operation=b"\x27" * 16,
            scope=fixture.scope,
            writer=fixture.writer,
            principal=fixture.controller_principal,
            controller_key_ref=fixture.controller_key_ref,
            controller_public_key=fixture.controller_public,
            nonce=b"small-response-bound",
            signer=fixture.controller_private,
            max_response_payload_bytes=MIN_RESPONSE_PAYLOAD_BYTES,
        )
    )

    first_request = _build_request(
        operation=b"\x41" * 16,
        scope=fixture.scope,
        writer=fixture.writer,
        principal=fixture.controller_principal,
        controller_key_ref=fixture.controller_key_ref,
        controller_public_key=fixture.controller_public,
        nonce=b"first-nonce",
        signer=fixture.controller_private,
    )
    with _server(authority_binary, fixture) as first_server:
        for invalid in invalid_requests:
            _exchange_rejected(fixture.socket_path, invalid)
        assert _file_identity(fixture.state_dir / "authority.snapshot") == sequence_one_identity

        _send_without_reading_response(fixture.socket_path, first_request)
        _wait_for_snapshot_replacement(
            first_server,
            fixture.state_dir / "authority.snapshot",
            sequence_one_identity,
        )
        assert _mode_bits(fixture.state_dir / "authority.snapshot") == 0o600

        conflict = _build_request(
            operation=first_request.operation,
            scope=fixture.scope,
            writer=fixture.writer,
            principal=fixture.controller_principal,
            controller_key_ref=fixture.controller_key_ref,
            controller_public_key=fixture.controller_public,
            nonce=b"conflicting-nonce",
            signer=fixture.controller_private,
        )
        _exchange_rejected(fixture.socket_path, conflict)

        contender = subprocess.run(
            _authority_command(
                authority_binary,
                fixture.serve_arguments(),
                command_prefix=fixture.command_prefix,
                restrictive_umask=fixture.restrictive_umask,
            ),
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            timeout=5,
        )
        assert contender.returncode != 0
        contender_stderr = contender.stderr.decode("utf-8", errors="strict")
        assert "code=PXTA-STORE-LOCK-CONTENDED" in contender_stderr
        assert "stage=acquire_lock" in contender_stderr
        assert "path_role=lock" in contender_stderr

        _kill_server(first_server)
        assert fixture.socket_path.exists()

    with _server(authority_binary, fixture):
        first_frame = _exchange(fixture.socket_path, first_request)
        first = _verify_response(
            first_frame,
            first_request,
            authority_public_key=fixture.authority_public,
            authority_ref=fixture.authority_ref,
            tenure_key_ref=fixture.tenure_key_ref,
        )
        assert first.epoch == 1
        assert _exchange(fixture.socket_path, first_request) == first_frame
        second_request = _build_request(
            operation=b"\x42" * 16,
            scope=fixture.scope,
            writer=fixture.writer,
            principal=fixture.controller_principal,
            controller_key_ref=fixture.controller_key_ref,
            controller_public_key=fixture.controller_public,
            nonce=b"second-nonce",
            signer=fixture.controller_private,
        )
        second = _verify_response(
            _exchange(fixture.socket_path, second_request),
            second_request,
            authority_public_key=fixture.authority_public,
            authority_ref=fixture.authority_ref,
            tenure_key_ref=fixture.tenure_key_ref,
        )
        assert second.epoch == 2
        assert second.supersedes == 1

    assert not fixture.socket_path.exists()


def test_same_uid_authority_and_controller_configuration_is_rejected(
    authority_binary: Path,
    authority_tmp_path: Path,
) -> None:
    fixture = _install(
        authority_tmp_path,
        expected_peer_uid=os.getuid(),
        expected_peer_gid=os.getgid(),
    )
    completed = subprocess.run(
        _authority_command(
            authority_binary,
            ["initialize", *fixture.common_arguments],
            command_prefix=fixture.command_prefix,
            restrictive_umask=fixture.restrictive_umask,
        ),
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode != 0
    assert "security configuration was rejected" in completed.stderr
    assert "code=PXTA-IDENTITY-KEY-SEPARATION" in completed.stderr
    assert "stage=validate_service_identity" in completed.stderr
    assert "path_role=service_identity" in completed.stderr
    assert list(fixture.state_dir.iterdir()) == []


def test_wrong_peer_credential_cannot_advance_sequence_one_store(
    authority_binary: Path,
    authority_tmp_path: Path,
) -> None:
    fixture = _install(
        authority_tmp_path,
        expected_peer_uid=(os.getuid() + 1) % (2**32),
        expected_peer_gid=os.getgid(),
        restrictive_umask=True,
    )
    original = _initialize(authority_binary, fixture)
    assert _mode_bits(fixture.state_dir / "authority.lock") == 0o600
    assert _mode_bits(fixture.state_dir / "authority.snapshot") == 0o600
    request = _build_request(
        operation=b"\x51" * 16,
        scope=fixture.scope,
        writer=fixture.writer,
        principal=fixture.controller_principal,
        controller_key_ref=fixture.controller_key_ref,
        controller_public_key=fixture.controller_public,
        nonce=b"wrong-peer",
        signer=fixture.controller_private,
    )
    with _server(authority_binary, fixture):
        _exchange_rejected(fixture.socket_path, request)

    assert fixture.store_id is not None
    recovered = _run_admin(
        authority_binary,
        [
            "initialization-receipt",
            *fixture.common_arguments,
        ],
        command_prefix=fixture.command_prefix,
        restrictive_umask=fixture.restrictive_umask,
    )
    assert recovered == original
