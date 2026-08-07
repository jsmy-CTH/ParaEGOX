"""CLI for the deterministic AgentConversationProtocol reference worker."""

from __future__ import annotations

import sys

from .protocol import AgentConversationProtocolError
from .worker import AgentConversationWorker, DeterministicEchoConversationModel


def main() -> int:
    worker = AgentConversationWorker(DeterministicEchoConversationModel())
    try:
        worker.run_stream(sys.stdin.buffer, sys.stdout.buffer)
    except (AgentConversationProtocolError, OSError):
        print("agent-conversation-worker: rejected input", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
