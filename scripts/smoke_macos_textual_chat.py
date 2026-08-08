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
# The joined Rust owner chain has an admitted worst-case serial shutdown
# budget of roughly 68 seconds. This remains a hard failure bound while
# leaving enough scheduling margin for a conforming macOS runner.
_EXIT_TIMEOUT_SECONDS = 90.0
_MAX_CAPTURE_BYTES = 2 * 1024 * 1024
_MESSAGE = "artifact-smoke-echo"
_TEXTUAL_TERMINAL_RESTORE = b"\x1b[?1049l"


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


def _wait_for_exit(
    master_fd: int,
    process: subprocess.Popen[bytes],
    capture: bytearray,
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    pty_open = True
    return_code: int | None = None
    while return_code is None:
        return_code = process.poll()
        if return_code is not None:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if _TEXTUAL_TERMINAL_RESTORE in capture:
                raise TimeoutError(
                    "paraegox Rust parent did not join after Textual restored the terminal"
                )
            raise TimeoutError(
                "Textual did not restore the terminal after its Ctrl+C quit binding"
            )
        if not pty_open:
            try:
                return_code = process.wait(timeout=min(0.25, remaining))
            except subprocess.TimeoutExpired:
                continue
            break
        ready, _, _ = select.select([master_fd], [], [], min(0.25, remaining))
        if not ready:
            continue
        try:
            chunk = os.read(master_fd, 65_536)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            pty_open = False
            continue
        if chunk:
            _bounded_append(capture, chunk)
        else:
            pty_open = False

    # Textual restores the terminal while shutting down. Consume bytes that
    # were already committed before the joined parent exited so failure logs
    # retain the complete teardown tail without allowing output backpressure
    # to keep the Textual child alive.
    while pty_open:
        ready, _, _ = select.select([master_fd], [], [], 0)
        if not ready:
            break
        try:
            chunk = os.read(master_fd, 65_536)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            break
        if not chunk:
            break
        _bounded_append(capture, chunk)

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
            for inspection_marker in (
                b"Node-local startup snapshot",
                b"NodeDaemon",
                b"Authority",
                b"Fabric",
                b"health unreported",
            ):
                _read_until(
                    master_fd,
                    process,
                    capture,
                    inspection_marker,
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
            # Textual owns Ctrl+C as a priority binding while it is in raw
            # terminal mode. Exercise that public application-level exit path
            # directly instead of racing a second Input submission with the
            # response redraw that supplied the Echo marker above.
            os.write(master_fd, b"\x03")
            _wait_for_exit(master_fd, process, capture, _EXIT_TIMEOUT_SECONDS)
            if _TEXTUAL_TERMINAL_RESTORE not in capture:
                raise RuntimeError(
                    "Textual exited without an observed terminal restore sequence"
                )
        except Exception:
            print(_safe_terminal_tail(capture))
            raise
        finally:
            _stop_process(process)
            os.close(master_fd)

    print(
        "macOS bundle smoke passed: parent -> Inspection -> Textual -> "
        "Runtime Agent IPC -> Echo"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
