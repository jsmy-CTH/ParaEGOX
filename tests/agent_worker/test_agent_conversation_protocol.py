from __future__ import annotations

from collections.abc import Callable

import pytest

from paraegox_sdk.agent_worker.protocol import (
    AGENT_CONVERSATION_PROTOCOL_VERSION,
    MAX_AGENT_CONVERSATION_INPUT_BYTES,
    AgentConversationProtocolError,
    AgentConversationProtocolErrorCode,
    AgentConversationRequestV1,
    AgentConversationTerminalFailureV1,
    AgentConversationTerminalV1,
    TerminalOutcome,
    decode_request_v1,
    decode_terminal_v1,
)

REQUEST_DIGEST_HEX = "19d46e69b3fea496d44ee43f631d0791797cc3689ddeaac3708862bee308df9a"
REQUEST_WIRE_HEX = (
    "50584143000100800000008f0100000000000000"
    "44444444444444444444444444444444"
    "11111111111111111111111111111111"
    "22222222222222222222222222222222"
    "33333333333333333333333333333333"
    "19d46e69b3fea496d44ee43f631d0791797cc3689ddeaac3708862bee308df9a"
    "000000012a05f2000000000f"
    "68656c6c6f2c205061726145474f58"
)
TERMINAL_WIRE_HEX = (
    "5058414300010080000000950201000000000000"
    "44444444444444444444444444444444"
    "11111111111111111111111111111111"
    "22222222222222222222222222222222"
    "33333333333333333333333333333333"
    "19d46e69b3fea496d44ee43f631d0791797cc3689ddeaac3708862bee308df9a"
    "000000012a05f20000000015"
    "6563686f3a2068656c6c6f2c205061726145474f58"
)
UNCERTAIN_TERMINAL_WIRE_HEX = (
    "5058414300010080000000800202000500000000"
    "44444444444444444444444444444444"
    "11111111111111111111111111111111"
    "22222222222222222222222222222222"
    "33333333333333333333333333333333"
    "19d46e69b3fea496d44ee43f631d0791797cc3689ddeaac3708862bee308df9a"
    "000000012a05f20000000000"
)


def _request(input: str = "hello, ParaEGOX") -> AgentConversationRequestV1:
    return AgentConversationRequestV1.create(
        bytes([0x44]) * 16,
        bytes([0x11]) * 16,
        bytes([0x22]) * 16,
        bytes([0x33]) * 16,
        5_000_000_000,
        input,
    )


def test_python_independent_codec_matches_rust_golden_vectors() -> None:
    request = _request()
    assert request.request_digest.hex() == REQUEST_DIGEST_HEX
    assert request.canonical_wire().hex() == REQUEST_WIRE_HEX
    assert decode_request_v1(bytes.fromhex(REQUEST_WIRE_HEX)) == request

    terminal = AgentConversationTerminalV1.success(request, "echo: hello, ParaEGOX")
    assert terminal.canonical_wire().hex() == TERMINAL_WIRE_HEX
    assert decode_terminal_v1(bytes.fromhex(TERMINAL_WIRE_HEX)) == terminal
    assert terminal.correlates(request)

    uncertain = AgentConversationTerminalV1.failed(
        request,
        AgentConversationTerminalFailureV1.MODEL_OUTCOME_UNCERTAIN,
    )
    assert uncertain.canonical_wire().hex() == UNCERTAIN_TERMINAL_WIRE_HEX
    assert decode_terminal_v1(bytes.fromhex(UNCERTAIN_TERMINAL_WIRE_HEX)) == uncertain


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda wire: wire.__setitem__(
                slice(4, 6),
                (AGENT_CONVERSATION_PROTOCOL_VERSION + 1).to_bytes(2, "big"),
            ),
            AgentConversationProtocolErrorCode.UNSUPPORTED_VERSION,
        ),
        (
            lambda wire: wire.__setitem__(19, 1),
            AgentConversationProtocolErrorCode.RESERVED_BITS_SET,
        ),
        (
            lambda wire: wire.__setitem__(12, 99),
            AgentConversationProtocolErrorCode.UNKNOWN_FRAME_KIND,
        ),
        (
            lambda wire: wire.__setitem__(84, wire[84] ^ 1),
            AgentConversationProtocolErrorCode.REQUEST_DIGEST_MISMATCH,
        ),
        (
            lambda wire: wire.__setitem__(128, 0xFF),
            AgentConversationProtocolErrorCode.INVALID_UTF8,
        ),
    ],
)
def test_request_decoder_fails_closed(
    mutate: Callable[[bytearray], None],
    expected: AgentConversationProtocolErrorCode,
) -> None:
    wire = bytearray(_request().canonical_wire())
    mutate(wire)
    with pytest.raises(AgentConversationProtocolError) as captured:
        decode_request_v1(bytes(wire))
    assert captured.value.code is expected


def test_request_constructor_enforces_text_and_deadline_bounds() -> None:
    with pytest.raises(AgentConversationProtocolError) as empty:
        _request("")
    assert empty.value.code is AgentConversationProtocolErrorCode.INPUT_EMPTY

    with pytest.raises(AgentConversationProtocolError) as oversized:
        _request("x" * (MAX_AGENT_CONVERSATION_INPUT_BYTES + 1))
    assert oversized.value.code is AgentConversationProtocolErrorCode.INPUT_TOO_LARGE

    with pytest.raises(AgentConversationProtocolError) as deadline:
        AgentConversationRequestV1.create(
            bytes([4]) * 16,
            bytes([1]) * 16,
            bytes([2]) * 16,
            bytes([3]) * 16,
            0,
            "hello",
        )
    assert deadline.value.code is AgentConversationProtocolErrorCode.DEADLINE_OUT_OF_RANGE


def test_terminal_failure_is_payload_free_and_strictly_typed() -> None:
    request = _request()
    terminal = AgentConversationTerminalV1.failed(
        request,
        AgentConversationTerminalFailureV1.MODEL_FAILED,
    )
    decoded = decode_terminal_v1(terminal.canonical_wire())
    assert decoded.outcome is TerminalOutcome.FAILURE
    assert decoded.failure is AgentConversationTerminalFailureV1.MODEL_FAILED
    assert decoded.output is None
