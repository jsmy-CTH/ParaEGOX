from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wire" / "s6_process_worker_protocol_v1.json"

DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
DIGEST_VERSION = 1
DIGEST_DOMAIN = b"paraegox.runtime.process-worker-frame.sha256.v1"

PXWP_MAGIC = b"PXWP"
PXWP_VERSION = 1
PXWP_HEADER_BYTES = 148
PXWP_MAX_FRAME_BYTES = 1_048_576
PXWP_MAX_PAYLOAD_BYTES = PXWP_MAX_FRAME_BYTES - PXWP_HEADER_BYTES - 24
PXWP_MAX_CREDITS = 4_096
PXWP_MAX_RETAINED_BYTES = 4 * 1_024 * 1_024 * 1_024

KINDS = {
    "start": 1,
    "ready": 2,
    "construct": 3,
    "constructed": 4,
    "invoke": 5,
    "heartbeat": 6,
    "cancel": 7,
    "terminal": 8,
    "stop_accepting": 9,
    "drained": 10,
    "stop": 11,
    "stopped": 12,
    "ping": 13,
    "pong": 14,
    "invoked": 15,
}
DIRECTIONS = {"host_to_worker": 1, "worker_to_host": 2}
STATES = {
    "starting": 1,
    "constructing": 2,
    "running": 3,
    "draining": 4,
    "stopping": 5,
    "stopped": 6,
}

ERROR_CODES = {
    "frame_too_large": 1,
    "truncated": 2,
    "invalid_magic": 3,
    "unsupported_version": 4,
    "invalid_header_length": 5,
    "invalid_frame_length": 6,
    "invalid_enum_value": 7,
    "reserved_bits_set": 8,
    "invalid_identity": 9,
    "invalid_sequence": 10,
    "invalid_invocation_scope": 11,
    "invalid_body_length": 12,
    "invalid_body_value": 13,
    "direction_mismatch": 14,
    "state_mismatch": 15,
    "phase_violation": 16,
    "sequence_violation": 17,
    "identity_mismatch": 18,
    "credit_exhausted": 19,
    "duplicate_credit": 20,
    "unknown_credit": 21,
    "retained_bytes_exceeded": 22,
    "retained_snapshot_mismatch": 23,
    "heartbeat_sequence_violation": 24,
    "ping_violation": 25,
    "non_canonical_frame": 26,
    "digest_failure": 27,
    "integer_overflow": 28,
    "invocation_ack_violation": 29,
}

IDENTITY = {
    "runtime_host_id": bytes.fromhex("11" * 16),
    "runtime_host_epoch": 7,
    "process_domain_id": bytes.fromhex("22" * 16),
    "process_domain_epoch": 9,
    "instance_id": bytes.fromhex("33" * 16),
    "instance_generation": 3,
    "source_plan_revision": 5,
    "target_slice_digest": bytes.fromhex("44" * 32),
}


class ProtocolError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canonical_digest(domain: bytes, fields: list[bytes]) -> bytes:
    encoded = bytearray(DIGEST_MAGIC)
    encoded += struct.pack(">H", DIGEST_VERSION)
    encoded += struct.pack(">I", len(domain))
    encoded += domain
    for ordinal, value in enumerate(fields, start=1):
        encoded += b"\x01"
        encoded += struct.pack(">I", ordinal)
        encoded += struct.pack(">Q", len(value))
        encoded += value
    encoded += b"\xff"
    encoded += struct.pack(">I", len(fields))
    return hashlib.sha256(encoded).digest()


def _frame_digest(frame: bytes) -> bytes:
    return _canonical_digest(DIGEST_DOMAIN, [frame])


def _frame(
    name: str,
    direction: str,
    state: str,
    sequence: int,
    invocation_id: int,
    body: bytes,
    identity: dict[str, Any] = IDENTITY,
) -> bytes:
    total = PXWP_HEADER_BYTES + len(body)
    return b"".join(
        [
            PXWP_MAGIC,
            struct.pack(">H", PXWP_VERSION),
            struct.pack(">H", PXWP_HEADER_BYTES),
            struct.pack(">I", total),
            struct.pack(">BBBB", KINDS[name], DIRECTIONS[direction], STATES[state], 0),
            struct.pack(">Q", sequence),
            identity["runtime_host_id"],
            struct.pack(">Q", identity["runtime_host_epoch"]),
            identity["process_domain_id"],
            struct.pack(">Q", identity["process_domain_epoch"]),
            identity["instance_id"],
            struct.pack(">Q", identity["instance_generation"]),
            struct.pack(">Q", invocation_id),
            struct.pack(">Q", identity["source_plan_revision"]),
            identity["target_slice_digest"],
            struct.pack(">I", len(body)),
            body,
        ]
    )


def _bodies() -> dict[str, bytes]:
    invoke_payload = b"input"
    terminal_payload = b"output"
    return {
        "start": struct.pack(">IQIQQ", 2, 64, 32, 1_000, 3_000),
        "ready": bytes.fromhex("55" * 32),
        "construct": bytes.fromhex("66" * 32 + "77" * 32 + "88" * 16),
        "constructed": b"\x01",
        "invoke": b"".join(
            [
                struct.pack(">Q", 71),
                struct.pack(">I", len(invoke_payload)),
                struct.pack(">I", 8),
                struct.pack(">Q", 10_000),
                invoke_payload,
            ]
        ),
        "invoked": struct.pack(">Q", 71),
        "heartbeat": struct.pack(">QIQ", 1, 1, 13),
        "cancel": struct.pack(">QQ", 71, 500),
        "ping": struct.pack(">Q", 91),
        "pong": struct.pack(">Q", 91),
        "terminal": b"".join(
            [
                struct.pack(">Q", 71),
                b"\x01\x00\x00\x00",
                struct.pack(">I", len(terminal_payload)),
                terminal_payload,
            ]
        ),
        "stop_accepting": b"",
        "drained": b"",
        "stop": b"\x01",
        "stopped": b"\x01",
    }


def _dialogue_frames() -> list[tuple[str, bytes]]:
    body = _bodies()
    specs = [
        ("start", "host_to_worker", "starting", 1, 0),
        ("ready", "worker_to_host", "starting", 1, 0),
        ("construct", "host_to_worker", "constructing", 2, 0),
        ("constructed", "worker_to_host", "constructing", 2, 0),
        ("invoke", "host_to_worker", "running", 3, 41),
        ("invoked", "worker_to_host", "running", 3, 41),
        ("heartbeat", "worker_to_host", "running", 4, 0),
        ("cancel", "host_to_worker", "running", 4, 41),
        ("ping", "host_to_worker", "running", 5, 0),
        ("pong", "worker_to_host", "running", 5, 0),
        ("terminal", "worker_to_host", "running", 6, 41),
        ("stop_accepting", "host_to_worker", "draining", 6, 0),
        ("drained", "worker_to_host", "draining", 7, 0),
        ("stop", "host_to_worker", "stopping", 7, 0),
        ("stopped", "worker_to_host", "stopped", 8, 0),
    ]
    return [
        (name, _frame(name, direction, state, sequence, invocation, body[name]))
        for name, direction, state, sequence, invocation in specs
    ]


_DIRECTION_BY_KIND = {
    **{
        name: DIRECTIONS["host_to_worker"]
        for name in ("start", "construct", "invoke", "cancel", "stop_accepting", "stop", "ping")
    },
    **{
        name: DIRECTIONS["worker_to_host"]
        for name in (
            "ready",
            "constructed",
            "invoked",
            "heartbeat",
            "terminal",
            "drained",
            "stopped",
            "pong",
        )
    },
}
_STATE_BY_KIND = {
    "start": {STATES["starting"]},
    "ready": {STATES["starting"]},
    "construct": {STATES["constructing"]},
    "constructed": {STATES["constructing"]},
    "invoke": {STATES["running"]},
    "invoked": {STATES["running"], STATES["draining"]},
    "heartbeat": {STATES["running"], STATES["draining"]},
    "cancel": {STATES["running"], STATES["draining"]},
    "terminal": {STATES["running"], STATES["draining"]},
    "stop_accepting": {STATES["draining"]},
    "drained": {STATES["draining"]},
    "stop": {STATES["stopping"]},
    "stopped": {STATES["stopped"]},
    "ping": {STATES["running"], STATES["draining"]},
    "pong": {STATES["running"], STATES["draining"]},
}


def _parse(frame: bytes) -> dict[str, Any]:
    if len(frame) > PXWP_MAX_FRAME_BYTES:
        raise ProtocolError("frame_too_large")
    if len(frame) < PXWP_HEADER_BYTES:
        raise ProtocolError("truncated")
    if frame[:4] != PXWP_MAGIC:
        raise ProtocolError("invalid_magic")
    if struct.unpack_from(">H", frame, 4)[0] != PXWP_VERSION:
        raise ProtocolError("unsupported_version")
    if struct.unpack_from(">H", frame, 6)[0] != PXWP_HEADER_BYTES:
        raise ProtocolError("invalid_header_length")
    if struct.unpack_from(">I", frame, 8)[0] != len(frame):
        raise ProtocolError("invalid_frame_length")
    try:
        name = next(name for name, value in KINDS.items() if value == frame[12])
    except StopIteration as error:
        raise ProtocolError("invalid_enum_value") from error
    if frame[13] not in DIRECTIONS.values() or frame[14] not in STATES.values():
        raise ProtocolError("invalid_enum_value")
    if frame[15] != 0:
        raise ProtocolError("reserved_bits_set")
    sequence = struct.unpack_from(">Q", frame, 16)[0]
    if sequence == 0:
        raise ProtocolError("invalid_sequence")
    identity = {
        "runtime_host_id": frame[24:40],
        "runtime_host_epoch": struct.unpack_from(">Q", frame, 40)[0],
        "process_domain_id": frame[48:64],
        "process_domain_epoch": struct.unpack_from(">Q", frame, 64)[0],
        "instance_id": frame[72:88],
        "instance_generation": struct.unpack_from(">Q", frame, 88)[0],
        "source_plan_revision": struct.unpack_from(">Q", frame, 104)[0],
        "target_slice_digest": frame[112:144],
    }
    if (
        not any(identity["runtime_host_id"])
        or not any(identity["process_domain_id"])
        or not any(identity["instance_id"])
        or not any(identity["target_slice_digest"])
        or any(
            identity[key] == 0
            for key in (
                "runtime_host_epoch",
                "process_domain_epoch",
                "instance_generation",
                "source_plan_revision",
            )
        )
    ):
        raise ProtocolError("invalid_identity")
    invocation_id = struct.unpack_from(">Q", frame, 96)[0]
    scoped = name in {"invoke", "invoked", "cancel", "terminal"}
    if scoped != (invocation_id != 0):
        raise ProtocolError("invalid_invocation_scope")
    body_length = struct.unpack_from(">I", frame, 144)[0]
    if PXWP_HEADER_BYTES + body_length != len(frame):
        raise ProtocolError("invalid_body_length")
    if frame[13] != _DIRECTION_BY_KIND[name]:
        raise ProtocolError("direction_mismatch")
    if frame[14] not in _STATE_BY_KIND[name]:
        raise ProtocolError("state_mismatch")
    body = frame[PXWP_HEADER_BYTES:]
    fields = _parse_body(name, body)
    return {
        "name": name,
        "direction": frame[13],
        "state": frame[14],
        "sequence": sequence,
        "identity": identity,
        "invocation_id": invocation_id,
        "body": fields,
    }


def _parse_body(name: str, body: bytes) -> dict[str, Any]:
    exact = {
        "start": 32,
        "ready": 32,
        "construct": 80,
        "constructed": 1,
        "invoked": 8,
        "heartbeat": 20,
        "cancel": 16,
        "stop_accepting": 0,
        "drained": 0,
        "stop": 1,
        "stopped": 1,
        "ping": 8,
        "pong": 8,
    }
    if name in exact and len(body) != exact[name]:
        raise ProtocolError("invalid_body_length")
    if name == "start":
        inflight, retained, payload, interval, timeout = struct.unpack(">IQIQQ", body)
        if not (
            0 < inflight <= PXWP_MAX_CREDITS
            and 0 < retained <= PXWP_MAX_RETAINED_BYTES
            and 0 < payload <= PXWP_MAX_PAYLOAD_BYTES
            and 0 < interval < timeout
        ):
            raise ProtocolError("invalid_body_value")
        return {"max_inflight": inflight, "max_retained": retained, "max_payload": payload}
    if name == "invoke":
        if len(body) < 24:
            raise ProtocolError("truncated")
        credit, request_len, response_reserved, budget = struct.unpack_from(">QIIQ", body)
        if len(body) != 24 + request_len:
            raise ProtocolError("invalid_body_length")
        if credit == 0 or budget == 0 or request_len > PXWP_MAX_PAYLOAD_BYTES:
            raise ProtocolError("invalid_body_value")
        return {
            "credit": credit,
            "request_len": request_len,
            "response_reserved": response_reserved,
            "payload": body[24:],
        }
    if name == "invoked":
        credit = struct.unpack(">Q", body)[0]
        if credit == 0:
            raise ProtocolError("invalid_body_value")
        return {"credit": credit}
    if name == "heartbeat":
        heartbeat, active, retained = struct.unpack(">QIQ", body)
        if heartbeat == 0:
            raise ProtocolError("invalid_body_value")
        return {"heartbeat": heartbeat, "active": active, "retained": retained}
    if name == "cancel":
        credit, grace = struct.unpack(">QQ", body)
        if credit == 0:
            raise ProtocolError("invalid_body_value")
        return {"credit": credit, "grace": grace}
    if name == "terminal":
        if len(body) < 16:
            raise ProtocolError("truncated")
        credit = struct.unpack_from(">Q", body)[0]
        terminal_kind = body[8]
        if body[9:12] != b"\0\0\0":
            raise ProtocolError("reserved_bits_set")
        length = struct.unpack_from(">I", body, 12)[0]
        if len(body) != 16 + length:
            raise ProtocolError("invalid_body_length")
        if credit == 0 or terminal_kind not in range(1, 6):
            raise ProtocolError("invalid_body_value")
        return {"credit": credit, "payload": body[16:]}
    if name in {"ping", "pong"}:
        nonce = struct.unpack(">Q", body)[0]
        if nonce == 0:
            raise ProtocolError("invalid_body_value")
        return {"nonce": nonce}
    if name == "constructed" and body[0] not in range(1, 4):
        raise ProtocolError("invalid_enum_value")
    if name == "stop" and body[0] not in range(1, 5):
        raise ProtocolError("invalid_enum_value")
    if name == "stopped" and body[0] not in range(1, 4):
        raise ProtocolError("invalid_enum_value")
    return {"raw": body}


@dataclass
class Dialogue:
    identity: dict[str, Any] = field(default_factory=lambda: dict(IDENTITY))
    phase: str = "await_start"
    host_sequence: int = 0
    worker_sequence: int = 0
    limits: dict[str, int] | None = None
    active: dict[int, tuple[int, int, int]] = field(default_factory=dict)
    acknowledged: set[int] = field(default_factory=set)
    retained: int = 0
    heartbeat: int = 0
    pending_ping: int | None = None

    def accept(self, raw: bytes) -> None:
        frame = _parse(raw)
        if frame["identity"] != self.identity:
            raise ProtocolError("identity_mismatch")
        sequence_field = "host_sequence" if frame["direction"] == 1 else "worker_sequence"
        if frame["sequence"] != getattr(self, sequence_field) + 1:
            raise ProtocolError("sequence_violation")
        self._transition(frame)
        setattr(self, sequence_field, frame["sequence"])

    def _transition(self, frame: dict[str, Any]) -> None:
        name = frame["name"]
        body = frame["body"]
        simple = {
            ("await_start", "start"): "await_ready",
            ("await_ready", "ready"): "await_construct",
            ("await_construct", "construct"): "await_constructed",
            ("await_constructed", "constructed"): "running",
            ("running", "stop_accepting"): "draining",
            ("draining", "drained"): "await_stop",
            ("await_stop", "stop"): "stopping",
            ("stopping", "stopped"): "stopped",
        }
        if (self.phase, name) in simple:
            if name == "start":
                self.limits = body
            if name == "drained" and (self.active or self.retained):
                raise ProtocolError("retained_snapshot_mismatch")
            self.phase = simple[(self.phase, name)]
            return
        if self.phase not in {"running", "draining"}:
            raise ProtocolError("phase_violation")
        if name == "invoke" and self.phase == "running":
            assert self.limits is not None
            if len(self.active) >= self.limits["max_inflight"]:
                raise ProtocolError("credit_exhausted")
            if (
                body["request_len"] > self.limits["max_payload"]
                or body["response_reserved"] > self.limits["max_payload"]
            ):
                raise ProtocolError("invalid_body_value")
            if frame["invocation_id"] in self.active or any(
                lease[0] == body["credit"] for lease in self.active.values()
            ):
                raise ProtocolError("duplicate_credit")
            retained = body["request_len"] + body["response_reserved"]
            if self.retained + retained > self.limits["max_retained"]:
                raise ProtocolError("retained_bytes_exceeded")
            self.active[frame["invocation_id"]] = (
                body["credit"],
                body["response_reserved"],
                retained,
            )
            self.retained += retained
            return
        if name == "invoked":
            lease = self.active.get(frame["invocation_id"])
            if lease is None or lease[0] != body["credit"]:
                raise ProtocolError("unknown_credit")
            if frame["invocation_id"] in self.acknowledged:
                raise ProtocolError("invocation_ack_violation")
            self.acknowledged.add(frame["invocation_id"])
            return
        if name == "terminal":
            lease = self.active.get(frame["invocation_id"])
            if lease is None or lease[0] != body["credit"]:
                raise ProtocolError("unknown_credit")
            if frame["invocation_id"] not in self.acknowledged:
                raise ProtocolError("invocation_ack_violation")
            if len(body["payload"]) > lease[1]:
                raise ProtocolError("retained_bytes_exceeded")
            del self.active[frame["invocation_id"]]
            self.acknowledged.remove(frame["invocation_id"])
            self.retained -= lease[2]
            return
        if name == "cancel":
            lease = self.active.get(frame["invocation_id"])
            if lease is None or lease[0] != body["credit"]:
                raise ProtocolError("unknown_credit")
            return
        if name == "heartbeat":
            if body["heartbeat"] != self.heartbeat + 1:
                raise ProtocolError("heartbeat_sequence_violation")
            acknowledged_retained = sum(
                self.active[invocation_id][2] for invocation_id in self.acknowledged
            )
            if (
                body["active"] != len(self.acknowledged)
                or body["retained"] != acknowledged_retained
            ):
                raise ProtocolError("retained_snapshot_mismatch")
            self.heartbeat = body["heartbeat"]
            return
        if name == "ping":
            if self.pending_ping is not None:
                raise ProtocolError("ping_violation")
            self.pending_ping = body["nonce"]
            return
        if name == "pong":
            if self.pending_ping != body["nonce"]:
                raise ProtocolError("ping_violation")
            self.pending_ping = None
            return
        raise ProtocolError("phase_violation")


def _fixture_document() -> dict[str, Any]:
    expected = []
    for name, frame in _dialogue_frames():
        expected.append(
            {
                "name": name,
                "wire_hex": frame.hex(),
                "frame_digest_hex": _frame_digest(frame).hex(),
            }
        )
    return {
        "fixture_version": 1,
        "source": "independent Python struct/hashlib PXWP v1 contract fixture",
        "semantic": {
            "runtime_host_id_hex": IDENTITY["runtime_host_id"].hex(),
            "runtime_host_epoch": 7,
            "process_domain_id_hex": IDENTITY["process_domain_id"].hex(),
            "process_domain_epoch": 9,
            "instance_id_hex": IDENTITY["instance_id"].hex(),
            "instance_generation": 3,
            "source_plan_revision": 5,
            "target_slice_digest_hex": IDENTITY["target_slice_digest"].hex(),
            "invocation_id": 41,
            "credit_id": 71,
        },
        "protocol": {
            "magic_hex": PXWP_MAGIC.hex(),
            "version": PXWP_VERSION,
            "fixed_header_bytes": PXWP_HEADER_BYTES,
            "header": (
                "magic:4,version:u16,header_len:u16,total_len:u32,kind:u8,direction:u8,"
                "state:u8,flags:u8,sequence:u64,host:16,host_epoch:u64,domain:16,"
                "domain_epoch:u64,instance:16,instance_generation:u64,invocation:u64,"
                "source_revision:u64,target_slice_digest:32,body_len:u32; integers big-endian"
            ),
            "max_frame_bytes": PXWP_MAX_FRAME_BYTES,
            "max_payload_bytes": PXWP_MAX_PAYLOAD_BYTES,
            "max_credits": PXWP_MAX_CREDITS,
            "max_retained_bytes": PXWP_MAX_RETAINED_BYTES,
            "frame_digest_domain_hex": DIGEST_DOMAIN.hex(),
            "directions": DIRECTIONS,
            "states": STATES,
            "kinds": KINDS,
        },
        "error_codes": ERROR_CODES,
        "expected": expected,
    }


def _load_fixture() -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate fixture key: {key}")
            result[key] = value
        return result

    return json.loads(FIXTURE_PATH.read_text(), object_pairs_hook=no_duplicates)


def test_independent_python_rebuild_matches_checked_in_fixture() -> None:
    assert _load_fixture() == _fixture_document()


def test_python_parser_consumes_every_bidirectional_golden_frame() -> None:
    fixture = _load_fixture()
    for expected in fixture["expected"]:
        frame = bytes.fromhex(expected["wire_hex"])
        parsed = _parse(frame)
        assert parsed["name"] == expected["name"]
        assert _frame_digest(frame).hex() == expected["frame_digest_hex"]
        assert parsed["identity"] == IDENTITY


def test_complete_construct_invoke_heartbeat_terminal_and_shutdown_dialogue() -> None:
    dialogue = Dialogue()
    for _, frame in _dialogue_frames():
        dialogue.accept(frame)
    assert dialogue.phase == "stopped"
    assert dialogue.active == {}
    assert dialogue.acknowledged == set()
    assert dialogue.retained == 0
    assert dialogue.pending_ping is None


@pytest.mark.parametrize(
    ("offset", "value", "expected"),
    [
        (0, 0, "invalid_magic"),
        (5, 0, "unsupported_version"),
        (7, 0, "invalid_header_length"),
        (12, 255, "invalid_enum_value"),
        (13, 255, "invalid_enum_value"),
        (14, 255, "invalid_enum_value"),
        (15, 1, "reserved_bits_set"),
    ],
)
def test_header_tampering_is_rejected(offset: int, value: int, expected: str) -> None:
    frame = bytearray(_dialogue_frames()[0][1])
    frame[offset] = value
    with pytest.raises(ProtocolError, match=expected):
        _parse(bytes(frame))


def test_lengths_and_partial_frames_fail_closed() -> None:
    frame = _dialogue_frames()[0][1]
    with pytest.raises(ProtocolError, match="truncated"):
        _parse(frame[: PXWP_HEADER_BYTES - 1])
    wrong_total = bytearray(frame)
    struct.pack_into(">I", wrong_total, 8, len(frame) + 1)
    with pytest.raises(ProtocolError, match="invalid_frame_length"):
        _parse(bytes(wrong_total))
    wrong_body = bytearray(frame)
    struct.pack_into(">I", wrong_body, 144, 31)
    with pytest.raises(ProtocolError, match="invalid_body_length"):
        _parse(bytes(wrong_body))
    with pytest.raises(ProtocolError, match="frame_too_large"):
        _parse(b"x" * (PXWP_MAX_FRAME_BYTES + 1))


def test_direction_state_invocation_and_terminal_reserved_bytes_are_strict() -> None:
    start = bytearray(_dialogue_frames()[0][1])
    start[13] = DIRECTIONS["worker_to_host"]
    with pytest.raises(ProtocolError, match="direction_mismatch"):
        _parse(bytes(start))
    start = bytearray(_dialogue_frames()[0][1])
    start[14] = STATES["running"]
    with pytest.raises(ProtocolError, match="state_mismatch"):
        _parse(bytes(start))
    start = bytearray(_dialogue_frames()[0][1])
    struct.pack_into(">Q", start, 96, 41)
    with pytest.raises(ProtocolError, match="invalid_invocation_scope"):
        _parse(bytes(start))
    terminal = bytearray(dict(_dialogue_frames())["terminal"])
    terminal[PXWP_HEADER_BYTES + 9] = 1
    with pytest.raises(ProtocolError, match="reserved_bits_set"):
        _parse(bytes(terminal))


def test_replay_stale_identity_and_heartbeat_snapshot_do_not_advance_dialogue() -> None:
    frames = dict(_dialogue_frames())
    dialogue = Dialogue()
    for name in ("start", "ready", "construct", "constructed", "invoke"):
        dialogue.accept(frames[name])
    with pytest.raises(ProtocolError, match="sequence_violation"):
        dialogue.accept(frames["invoke"])
    assert len(dialogue.active) == 1 and dialogue.retained == 13

    stale = dict(IDENTITY)
    stale["process_domain_epoch"] = 10
    stale_heartbeat = _frame(
        "heartbeat",
        "worker_to_host",
        "running",
        3,
        0,
        _bodies()["heartbeat"],
        stale,
    )
    with pytest.raises(ProtocolError, match="identity_mismatch"):
        dialogue.accept(stale_heartbeat)

    lying = _frame(
        "heartbeat",
        "worker_to_host",
        "running",
        3,
        0,
        struct.pack(">QIQ", 1, 1, 13),
    )
    with pytest.raises(ProtocolError, match="retained_snapshot_mismatch"):
        dialogue.accept(lying)
    assert dialogue.worker_sequence == 2


def test_heartbeat_snapshot_moves_from_pending_handoff_to_acknowledged_lease() -> None:
    frames = dict(_dialogue_frames())
    dialogue = Dialogue()
    for name in ("start", "ready", "construct", "constructed", "invoke"):
        dialogue.accept(frames[name])
    assert dialogue.retained == 13
    assert dialogue.acknowledged == set()

    dialogue.accept(
        _frame(
            "heartbeat",
            "worker_to_host",
            "running",
            3,
            0,
            struct.pack(">QIQ", 1, 0, 0),
        )
    )
    dialogue.accept(_frame("invoked", "worker_to_host", "running", 4, 41, _bodies()["invoked"]))
    dialogue.accept(
        _frame(
            "heartbeat",
            "worker_to_host",
            "running",
            5,
            0,
            struct.pack(">QIQ", 2, 1, 13),
        )
    )
    assert dialogue.retained == 13
    assert dialogue.acknowledged == {41}


def test_heartbeat_snapshot_excludes_only_unacknowledged_invokes() -> None:
    frames = dict(_dialogue_frames())
    dialogue = Dialogue()
    for name in ("start", "ready", "construct", "constructed", "invoke"):
        dialogue.accept(frames[name])
    dialogue.accept(
        _frame(
            "invoke",
            "host_to_worker",
            "running",
            4,
            42,
            struct.pack(">QIIQ", 72, 2, 7, 10_000) + b"xy",
        )
    )
    dialogue.accept(frames["invoked"])
    dialogue.accept(
        _frame(
            "heartbeat",
            "worker_to_host",
            "running",
            4,
            0,
            struct.pack(">QIQ", 1, 1, 13),
        )
    )
    assert len(dialogue.active) == 2
    assert dialogue.retained == 22
    assert dialogue.acknowledged == {41}


def test_cancel_before_ack_is_allowed_but_terminal_cannot_replace_invoked() -> None:
    frames = dict(_dialogue_frames())
    dialogue = Dialogue()
    for name in ("start", "ready", "construct", "constructed", "invoke"):
        dialogue.accept(frames[name])
    dialogue.accept(frames["cancel"])

    terminal_before_ack = _frame(
        "terminal",
        "worker_to_host",
        "running",
        3,
        41,
        _bodies()["terminal"],
    )
    with pytest.raises(ProtocolError, match="invocation_ack_violation"):
        dialogue.accept(terminal_before_ack)
    dialogue.accept(frames["invoked"])
    duplicate_ack = _frame(
        "invoked",
        "worker_to_host",
        "running",
        4,
        41,
        _bodies()["invoked"],
    )
    with pytest.raises(ProtocolError, match="invocation_ack_violation"):
        dialogue.accept(duplicate_ack)


def test_credit_and_retained_limits_are_independent_and_fail_closed() -> None:
    frames = dict(_dialogue_frames())
    dialogue = Dialogue()
    for name in ("start", "ready", "construct", "constructed"):
        dialogue.accept(frames[name])
    dialogue.accept(frames["invoke"])
    too_large = _frame(
        "invoke",
        "host_to_worker",
        "running",
        4,
        42,
        struct.pack(">QIIQ", 72, 20, 32, 1) + b"12345678901234567890",
    )
    with pytest.raises(ProtocolError, match="retained_bytes_exceeded"):
        dialogue.accept(too_large)
    assert dialogue.host_sequence == 3 and len(dialogue.active) == 1
    assert dialogue.retained == 13

    duplicate_credit = _frame(
        "invoke",
        "host_to_worker",
        "running",
        4,
        42,
        struct.pack(">QIIQ", 71, 1, 1, 1) + b"x",
    )
    with pytest.raises(ProtocolError, match="duplicate_credit"):
        dialogue.accept(duplicate_credit)
    assert dialogue.host_sequence == 3 and len(dialogue.active) == 1


def test_error_codes_are_stable_dense_and_match_fixture() -> None:
    assert list(ERROR_CODES.values()) == list(range(1, 30))
    assert _load_fixture()["error_codes"] == ERROR_CODES
