from __future__ import annotations

import io
import json
import struct
from pathlib import Path

import pytest

from paraegox_sdk.worker.protocol import (
    Direction,
    Frame,
    FrameKind,
    ProtocolError,
    ProtocolErrorCode,
    SessionIdentity,
    StartBody,
    WorkerState,
    encode_packet,
    frame_digest,
    read_frame,
    write_frame,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests/fixtures/wire/s6_process_worker_protocol_v1.json"


def _fixture() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _identity() -> SessionIdentity:
    return SessionIdentity(
        bytes.fromhex("11" * 16),
        7,
        bytes.fromhex("22" * 16),
        9,
        bytes.fromhex("33" * 16),
        3,
        5,
        bytes.fromhex("44" * 32),
    )


def _start() -> Frame:
    return Frame(
        _identity(),
        1,
        Direction.HOST_TO_WORKER,
        WorkerState.STARTING,
        0,
        StartBody(2, 64, 32, 1_000, 3_000),
    )


def test_python_worker_codec_consumes_every_rust_python_golden_frame() -> None:
    fixture = _fixture()
    expected = fixture["expected"]
    assert isinstance(expected, list)
    assert len(expected) == 15
    for record in expected:
        assert isinstance(record, dict)
        wire = bytes.fromhex(record["wire_hex"])
        frame = Frame.decode(wire)
        assert frame.kind.name.lower() == record["name"]
        assert frame.encode() == wire
        assert frame_digest(wire).hex() == record["frame_digest_hex"]


def test_start_constructor_matches_independent_golden_bytes() -> None:
    fixture = _fixture()
    expected = fixture["expected"]
    assert isinstance(expected, list)
    start = expected[0]
    assert isinstance(start, dict)
    frame = _start()
    assert frame.kind is FrameKind.START
    assert frame.encode().hex() == start["wire_hex"]
    assert frame_digest(frame.encode()).hex() == start["frame_digest_hex"]


def test_outer_length_framing_round_trips_and_clean_eof_is_distinct() -> None:
    stream = io.BytesIO()
    write_frame(stream, _start())
    assert stream.getvalue() == encode_packet(_start())
    stream.seek(0)
    assert read_frame(stream) == _start()
    assert read_frame(stream) is None


@pytest.mark.parametrize(
    ("wire", "code"),
    [
        (b"\0", ProtocolErrorCode.TRUNCATED),
        (struct.pack(">I", 0), ProtocolErrorCode.INVALID_FRAME_LENGTH),
        (struct.pack(">I", 1_048_577), ProtocolErrorCode.FRAME_TOO_LARGE),
        (struct.pack(">I", 100) + b"x" * 50, ProtocolErrorCode.TRUNCATED),
    ],
)
def test_stream_prefix_and_partial_body_fail_closed(
    wire: bytes,
    code: ProtocolErrorCode,
) -> None:
    with pytest.raises(ProtocolError) as rejected:
        read_frame(io.BytesIO(wire))
    assert rejected.value.code is code


def test_frame_rejects_direction_state_scope_and_reserved_tampering() -> None:
    baseline = _start()
    with pytest.raises(ProtocolError) as wrong_direction:
        Frame(
            baseline.identity,
            1,
            Direction.WORKER_TO_HOST,
            WorkerState.STARTING,
            0,
            baseline.body,
        )
    assert wrong_direction.value.code is ProtocolErrorCode.DIRECTION_MISMATCH

    with pytest.raises(ProtocolError) as wrong_state:
        Frame(
            baseline.identity,
            1,
            Direction.HOST_TO_WORKER,
            WorkerState.RUNNING,
            0,
            baseline.body,
        )
    assert wrong_state.value.code is ProtocolErrorCode.STATE_MISMATCH

    with pytest.raises(ProtocolError) as wrong_scope:
        Frame(
            baseline.identity,
            1,
            Direction.HOST_TO_WORKER,
            WorkerState.STARTING,
            41,
            baseline.body,
        )
    assert wrong_scope.value.code is ProtocolErrorCode.INVALID_INVOCATION_SCOPE

    reserved = bytearray(baseline.encode())
    reserved[15] = 1
    with pytest.raises(ProtocolError) as nonzero_reserved:
        Frame.decode(bytes(reserved))
    assert nonzero_reserved.value.code is ProtocolErrorCode.RESERVED_BITS_SET


def test_identity_and_error_code_values_are_strict_and_stable() -> None:
    with pytest.raises(ProtocolError) as zero_identity:
        SessionIdentity(b"\0" * 16, 1, b"\x01" * 16, 1, b"\x02" * 16, 1, 1, b"\x03" * 32)
    assert zero_identity.value.code is ProtocolErrorCode.INVALID_IDENTITY
    assert [code.value for code in ProtocolErrorCode] == list(range(1, 30))
