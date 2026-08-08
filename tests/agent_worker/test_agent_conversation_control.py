from __future__ import annotations

import pytest

from paraegox_sdk.agent_worker.control import (
    MAX_AGENT_CONVERSATION_WATCH_EVENTS,
    AgentConversationCancelOutcomeV1,
    AgentConversationControlError,
    AgentConversationControlErrorCode,
    AgentConversationControlV1,
    AgentConversationGetOutcomeV1,
    AgentConversationOpenOutcomeV1,
    AgentConversationWatchBatchV1,
    AgentConversationWatchEventKindV1,
    AgentConversationWatchEventV1,
    control_digest_v1,
    decode_control_v1,
)
from paraegox_sdk.agent_worker.protocol import (
    AgentConversationProtocolError,
    AgentConversationProtocolErrorCode,
    AgentConversationRequestV1,
    AgentConversationTerminalV1,
    decode_request_v1,
    decode_terminal_v1,
)

OPEN_REQUEST_WIRE_HEX = (
    "5058414300010080000000800300000000000000"
    "44444444444444444444444444444444"
    "11111111111111111111111111111111"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "43aec8b758e56091d025f7e70080fcc4d6b479bdd883084350e0d344e5775ec6"
    "000000000000000000000000"
)
GET_PENDING_CANCEL_WIRE_HEX = (
    "5058414300010080000000800603000000000000"
    "44444444444444444444444444444444"
    "11111111111111111111111111111111"
    "00000000000000000000000000000000"
    "33333333333333333333333333333333"
    "8e34a6ad16173b0b86506a17ab1b7d8e2d061d8308a4af366cd2b03764254de4"
    "000000000000000000000000"
)
WATCH_REQUEST_WIRE_HEX = (
    "50584143000100800000008c0700000000000000"
    "44444444444444444444444444444444"
    "11111111111111111111111111111111"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "a26fb51e56197a4417ecac0926a06ec657f8058b5daed56b15aec3aa5e8a91f4"
    "00000000000000000000000c"
    "000000000000000700000008"
)
CANCEL_INTENT_WIRE_HEX = (
    "5058414300010080000000800a02000000000000"
    "44444444444444444444444444444444"
    "11111111111111111111111111111111"
    "00000000000000000000000000000000"
    "33333333333333333333333333333333"
    "663d9bcd48eecfe54117cfe7d083a5bc696ca4647c3dd85317395d1f44a76ca5"
    "000000000000000000000000"
)


def _deck() -> bytes:
    return bytes([0x44]) * 16


def _session() -> bytes:
    return bytes([0x11]) * 16


def _request_id() -> bytes:
    return bytes([0x33]) * 16


def _request() -> AgentConversationRequestV1:
    return AgentConversationRequestV1.create(
        _deck(),
        _session(),
        bytes([0x22]) * 16,
        _request_id(),
        5_000_000_000,
        "hello, ParaEGOX",
    )


def test_python_control_codec_matches_rust_golden_vectors() -> None:
    values = [
        (
            AgentConversationControlV1.open_request(_deck(), _session()),
            OPEN_REQUEST_WIRE_HEX,
        ),
        (
            AgentConversationControlV1.get_result(
                _deck(),
                _session(),
                _request_id(),
                AgentConversationGetOutcomeV1.PENDING_CANCEL_REQUESTED,
            ),
            GET_PENDING_CANCEL_WIRE_HEX,
        ),
        (
            AgentConversationControlV1.watch_request(_deck(), _session(), 7, 8),
            WATCH_REQUEST_WIRE_HEX,
        ),
        (
            AgentConversationControlV1.cancel_result(
                _deck(),
                _session(),
                _request_id(),
                AgentConversationCancelOutcomeV1.INTENT_RECORDED,
            ),
            CANCEL_INTENT_WIRE_HEX,
        ),
    ]
    for value, expected in values:
        assert value.canonical_wire().hex() == expected
        assert decode_control_v1(bytes.fromhex(expected)) == value
        with pytest.raises(AgentConversationProtocolError) as request_error:
            decode_request_v1(value.canonical_wire())
        assert request_error.value.code is AgentConversationProtocolErrorCode.UNKNOWN_FRAME_KIND
        with pytest.raises(AgentConversationProtocolError) as terminal_error:
            decode_terminal_v1(value.canonical_wire())
        assert terminal_error.value.code is AgentConversationProtocolErrorCode.UNKNOWN_FRAME_KIND


def test_all_control_values_and_watch_events_round_trip() -> None:
    request = _request()
    terminal = AgentConversationTerminalV1.success(request, "echo: hello")
    batch = AgentConversationWatchBatchV1(
        (
            AgentConversationWatchEventV1(1, AgentConversationWatchEventKindV1.SESSION_OPENED),
            AgentConversationWatchEventV1(
                2,
                AgentConversationWatchEventKindV1.REQUEST_ACCEPTED,
                request,
            ),
            AgentConversationWatchEventV1(
                3,
                AgentConversationWatchEventKindV1.CANCEL_INTENT_RECORDED,
                _request_id(),
            ),
            AgentConversationWatchEventV1(
                4,
                AgentConversationWatchEventKindV1.TERMINAL_COMMITTED,
                terminal,
            ),
        ),
        4,
        4,
        False,
        False,
    )
    values = [
        AgentConversationControlV1.open_result(
            _deck(), _session(), AgentConversationOpenOutcomeV1.OPENED
        ),
        AgentConversationControlV1.get_request(_deck(), _session(), _request_id()),
        AgentConversationControlV1.get_result(
            _deck(),
            _session(),
            _request_id(),
            AgentConversationGetOutcomeV1.TERMINAL,
            terminal,
        ),
        AgentConversationControlV1.watch_result(_deck(), _session(), batch),
        AgentConversationControlV1.cancel_request(_deck(), _session(), _request_id()),
        AgentConversationControlV1.cancel_result(
            _deck(),
            _session(),
            _request_id(),
            AgentConversationCancelOutcomeV1.TERMINAL,
            terminal,
        ),
    ]
    for value in values:
        assert decode_control_v1(value.canonical_wire()) == value


@pytest.mark.parametrize(
    ("offset", "replacement", "expected"),
    [
        (12, 1, AgentConversationControlErrorCode.UNKNOWN_FRAME_KIND),
        (52, 1, AgentConversationControlErrorCode.RESERVED_BITS_SET),
        (84, 1, AgentConversationControlErrorCode.DIGEST_MISMATCH),
    ],
)
def test_control_decoder_fails_closed(
    offset: int,
    replacement: int,
    expected: AgentConversationControlErrorCode,
) -> None:
    wire = bytearray(
        AgentConversationControlV1.get_request(_deck(), _session(), _request_id()).canonical_wire()
    )
    wire[offset] = replacement
    with pytest.raises(AgentConversationControlError) as captured:
        decode_control_v1(bytes(wire))
    assert captured.value.code is expected


@pytest.mark.parametrize(
    "value",
    [
        AgentConversationControlV1.open_request(_deck(), _session()),
        AgentConversationControlV1.open_result(
            _deck(), _session(), AgentConversationOpenOutcomeV1.OPENED
        ),
        AgentConversationControlV1.watch_request(_deck(), _session(), 7, 8),
        AgentConversationControlV1.watch_not_found(_deck(), _session()),
        AgentConversationControlV1.watch_result(
            _deck(),
            _session(),
            AgentConversationWatchBatchV1((), 0, 0, False, False),
        ),
    ],
)
def test_unscoped_control_decoder_rejects_nonzero_request_identity(
    value: AgentConversationControlV1,
) -> None:
    wire = bytearray(value.canonical_wire())
    wire[68:84] = _request_id()
    wire[84:116] = control_digest_v1(
        value.kind,
        value.outcome,
        value.deck_run_id,
        value.session_id,
        _request_id(),
        bytes(wire[128:]),
    )

    with pytest.raises(AgentConversationControlError) as captured:
        decode_control_v1(bytes(wire))
    assert captured.value.code is AgentConversationControlErrorCode.INVALID_OUTCOME


def test_watch_and_terminal_correlation_are_bounded_and_fail_closed() -> None:
    with pytest.raises(AgentConversationControlError) as limit:
        AgentConversationControlV1.watch_request(
            _deck(), _session(), 0, MAX_AGENT_CONVERSATION_WATCH_EVENTS + 1
        )
    assert limit.value.code is AgentConversationControlErrorCode.WATCH_LIMIT_OUT_OF_RANGE

    terminal = AgentConversationTerminalV1.success(_request(), "echo")
    with pytest.raises(AgentConversationControlError) as correlation:
        AgentConversationControlV1.get_result(
            bytes([9]) * 16,
            _session(),
            _request_id(),
            AgentConversationGetOutcomeV1.TERMINAL,
            terminal,
        )
    assert correlation.value.code is AgentConversationControlErrorCode.CORRELATION_MISMATCH

    with pytest.raises(AgentConversationControlError) as sequence:
        AgentConversationWatchBatchV1(
            (
                AgentConversationWatchEventV1(1, AgentConversationWatchEventKindV1.SESSION_OPENED),
                AgentConversationWatchEventV1(3, AgentConversationWatchEventKindV1.SESSION_SEALED),
            ),
            3,
            3,
            False,
            True,
        )
    assert sequence.value.code is AgentConversationControlErrorCode.INVALID_WATCH_SEQUENCE

    standalone = AgentConversationWatchBatchV1(
        (AgentConversationWatchEventV1(3, AgentConversationWatchEventKindV1.SESSION_SEALED),),
        3,
        3,
        False,
        True,
    )
    with pytest.raises(AgentConversationControlError) as request_relative:
        standalone.validate_for_request(1, 1)
    assert request_relative.value.code is AgentConversationControlErrorCode.INVALID_WATCH_SEQUENCE
