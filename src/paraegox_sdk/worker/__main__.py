"""Command-line entry point for the subordinate reference worker."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .protocol import ProtocolError
from .runner import FaultMode, ReferenceWorker


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="paraegox-worker",
        description="Run one subordinate PXWP v1 Python reference worker on stdin/stdout.",
    )
    parser.add_argument(
        "--fault",
        choices=[mode.value for mode in FaultMode],
        default=FaultMode.NORMAL.value,
        help="TEST-ONLY deterministic process fault injection",
    )
    parser.add_argument(
        "--invoke-delay-ms",
        type=int,
        default=0,
        help="defer normal terminal frames so cancellation can race deterministically",
    )
    parser.add_argument(
        "--grandchild-pid-file",
        type=Path,
        help="TEST-ONLY path used to report the same-group grandchild PID",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 0 <= args.invoke_delay_ms <= 86_400_000:
        _parser().error("--invoke-delay-ms must be between 0 and 86400000")
    try:
        worker = ReferenceWorker(
            sys.stdin.buffer.raw,
            sys.stdout.buffer,
            fault=FaultMode(args.fault),
            invoke_delay_seconds=args.invoke_delay_ms / 1_000,
            grandchild_pid_file=args.grandchild_pid_file,
        )
        return worker.run()
    except (OSError, ProtocolError, RuntimeError, ValueError) as error:
        print(f"paraegox-worker: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
