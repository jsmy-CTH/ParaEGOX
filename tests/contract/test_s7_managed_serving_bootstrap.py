"""Independent PXFB/PXFR v1 canonical-wire and digest oracle."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

FIXTURE = Path(__file__).parents[1] / "fixtures/wire/s7_managed_serving_bootstrap_v1.json"
DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
CHANNEL_DOMAIN = b"paraegox.runtime.local-control-channel-binding.sha256.v1"
REQUEST_DOMAIN = b"paraegox.runtime.managed-serving-bootstrap.request.sha256.v1"
RESPONSE_DOMAIN = b"paraegox.runtime.managed-serving-bootstrap.response.sha256.v1"


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _digest(domain: bytes, fields: list[bytes]) -> bytes:
    encoded = bytearray(DIGEST_MAGIC)
    encoded += _u16(1) + _u32(len(domain)) + domain
    for ordinal, field in enumerate(fields, start=1):
        encoded += b"\x01" + _u32(ordinal) + _u64(len(field)) + field
    encoded += b"\xff" + _u32(len(fields))
    return hashlib.sha256(encoded).digest()


def _projection() -> bytes:
    return bytes.fromhex(json.loads(FIXTURE.read_text())["inputs"]["projection_hex"])


def _channel(projection: bytes) -> tuple[bytes, bytes]:
    target = projection[38:54]
    runtime_peer = bytes([0x31]) * 16
    endpoint = bytes([0x32]) * 32
    credentials = bytes([0x33]) * 32
    wire = target + runtime_peer + endpoint + credentials
    binding = _digest(
        CHANNEL_DOMAIN,
        [_u16(1), target, runtime_peer, endpoint, credentials],
    )
    return wire, binding


def _request() -> bytes:
    projection = _projection()
    target = projection[38:54]
    channel, _ = _channel(projection)
    return b"".join(
        [
            b"PXFB",
            _u16(1),
            bytes([0x37]) * 16,
            target,
            bytes([0x38]) * 16,
            bytes([0x39]) * 32,
            _u32(len(projection)),
            channel,
            bytes([0x34]) * 16,
            bytes([0x35]) * 16,
            _u16(1),
            _u16(1),
            _u16(32),
            bytes([0x36]) * 32,
            _u16(64),
            projection,
            bytes([0x3A]) * 64,
        ]
    )


def _response(request: bytes) -> bytes:
    projection = _projection()
    target = projection[38:54]
    channel, binding = _channel(projection)
    request_digest = _digest(REQUEST_DOMAIN, [request])
    return b"".join(
        [
            b"PXFR",
            _u16(1),
            bytes([0x37]) * 16,
            request_digest,
            _u16(32),
            target,
            bytes([0x39]) * 32,
            _u32(len(projection)),
            _u64(7),
            _u64(11),
            bytes([0x3B]) * 16,
            _u64(13),
            _u64(17),
            _u16(1),
            channel,
            bytes([0x31]) * 16,
            binding,
            bytes([0x3C]) * 16,
            _u16(1),
            _u16(1),
            _u16(64),
            projection,
            bytes([0x36]) * 32,
            bytes([0x3D]) * 64,
        ]
    )


def test_independent_request_wire_and_digest_match_fixture() -> None:
    expected = json.loads(FIXTURE.read_text())["expected"]
    request = _request()
    assert request[:6] == b"PXFB\x00\x01"
    assert len(request) == expected["request_length"]
    assert _digest(REQUEST_DOMAIN, [request]).hex() == expected["request_digest_hex"]


def test_independent_recovered_ready_response_wire_and_digest_match_fixture() -> None:
    expected = json.loads(FIXTURE.read_text())["expected"]
    response = _response(_request())
    assert response[:6] == b"PXFR\x00\x01"
    assert response[156:158] == _u16(1)
    assert len(response) == expected["response_length"]
    assert _digest(RESPONSE_DOMAIN, [response]).hex() == expected["response_digest_hex"]


def test_response_is_bound_to_complete_signed_request() -> None:
    request = bytearray(_request())
    original = _response(bytes(request))
    request[-1] ^= 1
    changed = _response(bytes(request))
    assert changed != original
    assert changed[22:54] != original[22:54]


def test_protocol_has_no_not_ready_wire_value() -> None:
    response = bytearray(_response(_request()))
    assert response[156:158] == _u16(1)
    response[156:158] = _u16(2)
    assert _digest(RESPONSE_DOMAIN, [bytes(response)]).hex() != json.loads(FIXTURE.read_text())[
        "expected"
    ]["response_digest_hex"]
