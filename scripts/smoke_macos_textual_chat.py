#!/usr/bin/env python3
"""Exercise the relocatable macOS bundle through a real Textual PTY."""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import termios
import time
from pathlib import Path

_STARTUP_TIMEOUT_SECONDS = 45.0
_REPLY_TIMEOUT_SECONDS = 45.0
_EXIT_TIMEOUT_SECONDS = 20.0
_MAX_CAPTURE_BYTES = 2 * 1024 * 1024
_MESSAGE = "artifact-smoke-echo"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Smoke the bundled paraegox parent, Textual child, and Rust Agent IPC."
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    return parser.parse_args()


def _require_bundle(bundle_dir: Path) -> tuple[Path, Path]:
    resolved = bundle_dir.resolve(strict=True)
    binary = resolved / "paraegox"
    launcher = resolved / "paraegox-console"
    for path in (binary, launcher):
        metadata = path.lstat()
        if not path.is_file() or path.is_symlink() or metadata.st_mode & 0o111 == 0:
            raise RuntimeError(f"bundle executable is not a regular executable: {path.name}")
    if not (resolved / "python" / "paraegox_sdk").is_dir():
        raise RuntimeError("bundle is missing python/paraegox_sdk")
    return binary, launcher


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _write_config(directory: Path) -> Path:
    state_root = directory / "state"
    config_path = directory / "paraegox-smoke.toml"
    config = (
        "schema_version = 1\n"
        f"state_root = {json.dumps(os.fspath(state_root))}\n"
        f'fabric_listen = "tcp/127.0.0.1:{_reserve_loopback_port()}"\n'
        "\n[model]\n"
        'provider = "deterministic-echo-v1"\n'
    )
    config_path.write_text(config, encoding="utf-8")
    config_path.chmod(0o600)
    return config_path


def _bounded_append(capture: bytearray, chunk: bytes) -> None:
    capture.extend(chunk)
    if len(capture) > _MAX_CAPTURE_BYTES:
        del capture[: len(capture) - _MAX_CAPTURE_BYTES]


def _read_until(
    master_fd: int,
    process: subprocess.Popen[bytes],
    capture: bytearray,
    marker: bytes,
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while marker not in capture:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for terminal marker {marker!r}")
        ready, _, _ = select.select([master_fd], [], [], 0.25)
        if ready:
            try:
                chunk = os.read(master_fd, 65_536)
            except OSError as error:
                if error.errno == errno.EIO:
                    chunk = b""
                else:
                    raise
            if not chunk:
                if process.poll() is not None:
                    raise RuntimeError(
                        f"paraegox exited with {process.returncode} before {marker!r}"
                    )
                continue
            _bounded_append(capture, chunk)
        elif process.poll() is not None:
            raise RuntimeError(f"paraegox exited with {process.returncode} before {marker!r}")


def _wait_for_exit(process: subprocess.Popen[bytes], timeout_seconds: float) -> None:
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        raise TimeoutError("paraegox did not join after /quit") from error
    if return_code != 0:
        raise RuntimeError(f"paraegox exited unsuccessfully with code {return_code}")


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def _safe_terminal_tail(capture: bytearray) -> str:
    text = bytes(capture[-8_192:]).decode("utf-8", errors="replace")
    return "".join(character for character in text if character in "\n\r\t" or character >= " ")


def main() -> int:
    bundle_dir = _arguments().bundle_dir
    binary, _ = _require_bundle(bundle_dir)
    python = shutil.which("python3")
    if python is None:
        raise RuntimeError("Python 3.11 or newer is required to run the Textual console")

    temp_parent = Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="paraegox-macos-textual-smoke-", dir=temp_parent
    ) as temporary:
        temporary_path = Path(temporary).resolve(strict=True)
        config_path = _write_config(temporary_path)
        master_fd, slave_fd = os.openpty()
        fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 120, 0, 0))
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.pop("VIRTUAL_ENV", None)
        environment.pop("OPENAI_API_KEY", None)
        environment.pop("DEEPSEEK_API_KEY", None)
        environment["PATH"] = os.pathsep.join(
            [os.fspath(Path(python).parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        )
        environment["TERM"] = "xterm-256color"
        environment["COLUMNS"] = "120"
        environment["LINES"] = "32"

        process = subprocess.Popen(
            [os.fspath(binary), "chat", "--config", os.fspath(config_path)],
            cwd=bundle_dir,
            env=environment,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            start_new_session=True,
        )
        os.close(slave_fd)
        capture = bytearray()
        try:
            _read_until(
                master_fd,
                process,
                capture,
                b"System: connected",
                _STARTUP_TIMEOUT_SECONDS,
            )
            os.write(master_fd, f"{_MESSAGE}\r".encode())
            _read_until(
                master_fd,
                process,
                capture,
                f"echo: {_MESSAGE}".encode(),
                _REPLY_TIMEOUT_SECONDS,
            )
            os.write(master_fd, b"/quit\r")
            _wait_for_exit(process, _EXIT_TIMEOUT_SECONDS)
        except Exception:
            print(_safe_terminal_tail(capture))
            raise
        finally:
            _stop_process(process)
            os.close(master_fd)

    print("macOS bundle smoke passed: parent -> Textual -> Runtime Agent IPC -> Echo")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
