from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import struct
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests/fixtures/wire/s7_managed_agent_stack_successor_v1.json"
FABRIC_FIXTURE_PATH = REPO_ROOT / "tests/fixtures/wire/s7_managed_fabric_successor_v1.json"
FABRIC_ORACLE_PATH = REPO_ROOT / "tests/contract/test_s7_managed_fabric_successor.py"

DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
DIGEST_VERSION = 1
STACK_PROJECTION_MAGIC = b"PXSP"
STACK_PROJECTION_VERSION = 1
BASE_PROJECTION_BYTES = 186
STACK_PROJECTION_BYTES = 228
PXTE_MAGIC = b"PXTE"
PXTE_VERSION = 6
PROFILE_VERSION = 1
MODE_FABRIC_AND_AGENT = 1
MODE_EMPTY = 2
PXTE_FIXED_BYTES = 242
AGENT_PLAN_FIXED_BYTES = 199
MAX_FABRIC_PXTE_BYTES = 512
MAX_KEY_EXPRESSION_BYTES = 256
MAX_PXTE_BYTES = PXTE_FIXED_BYTES + MAX_FABRIC_PXTE_BYTES + AGENT_PLAN_FIXED_BYTES + 512
PXAR_MAGIC = b"PXAR"
PXAR_VERSION = 7
PXAR_HEADER_BYTES = 18
MAX_ENVELOPE_BYTES = 4_096
PXTA_ZERO = bytes.fromhex("50585441000100000000")
MAX_PXAR_BYTES = PXAR_HEADER_BYTES + MAX_ENVELOPE_BYTES + len(PXTA_ZERO) + MAX_PXTE_BYTES
MANAGED_SERVICE_VERSION = 1
PROVIDER_SELECTION_VERSION = 1
PROVIDER_PROVISIONED = 1
PROVIDER_DETERMINISTIC_FIXTURE = 2
MAX_LIFECYCLE_NANOS = 86_400_000_000_000
MAX_INGRESS_ITEMS = 4_096
MAX_INGRESS_BYTES = 64 * 1024 * 1024
MIN_FRAME_BYTES = 104 + 128
MAX_FRAME_BYTES = 1_048_680
MIN_RESPONSE_BODY_BYTES = 128
MAX_RESPONSE_BODY_BYTES = 1_048_576
MAX_SESSIONS = 256
MAX_TURNS_PER_SESSION = 1_024
MAX_REQUESTS_PER_SESSION = 1_024
MAX_EVENT_BATCH = 1_024
STACK_COMPATIBILITY_DOMAIN = (
    b"paraegox.runtime.compiled-managed-agent-stack-compatibility.sha256.v1"
)
PXTA_DIGEST_DOMAIN = b"paraegox.runtime.target-assignments.sha256.v1"
PXTE_DIGEST_DOMAIN = b"paraegox.runtime.target-execution.sha256.v6"
ASSIGNMENT_DIGEST_DOMAIN = b"paraegox.runtime.target-plan-assignments.sha256.v7"
TERMINAL_MAGIC = b"PXST"
TERMINAL_VERSION = 1
TERMINAL_SIGNING_VERSION = 1
TERMINAL_SIGNING_MAGIC = b"ParaEGOX\0managed-agent-stack-terminal-signing"
TERMINAL_RESULT_REF_DOMAIN = b"paraegox.runtime.managed-agent-stack-terminal-result.sha256.v1"
TERMINAL_DIGEST_DOMAIN = b"paraegox.runtime.managed-agent-stack-terminal-receipt.sha256.v1"
MAX_TERMINAL_BYTES = 2_048
MAX_TERMINAL_SIGNATURE_BYTES = 512
TERMINAL_FIELDS_BYTES = 516
KEY_EXPRESSION_RE = re.compile(r"[A-Za-z0-9/._-]+")

SEMANTIC: dict[str, Any] = {
    "agent": {
        "service_id_hex": "65" * 16,
        "prepare_budget_nanos": 1_000_000,
        "start_budget_nanos": 2_000_000,
        "readiness_budget_nanos": 3_000_000,
        "drain_budget_nanos": 4_000_000,
        "stop_budget_nanos": 5_000_000,
        "max_sessions": 16,
        "max_turns_per_session": 64,
        "max_requests_per_session": 64,
        "max_event_batch": 64,
        "submit_binding_id_hex": "61" * 16,
        "control_binding_id_hex": "62" * 16,
        "submit_key_expression": "paraegox/agent/v1/submit",
        "control_key_expression": "paraegox/agent/v1/control",
        "max_items": 8,
        "max_bytes": 256 * 1024,
        "max_frame_bytes": 64 * 1024,
        "max_response_body_bytes": 64 * 1024,
        "handler_timeout_nanos": 5_000_000_000,
        "provider_profile": PROVIDER_PROVISIONED,
        "provider_ref_hex": "63" * 16,
        "config_digest_hex": "64" * 32,
        "secret_ref_hex": "66" * 16,
    },
    "fabric": deepcopy(
        {
            "projection": {
                "manifest_digest_hex": (
                    "fad22cd7f146653019a6b9570d06c222a34689d5b669481cdb7b314ec05edf53"
                ),
                "target_hex": "05" * 16,
                "build_instance_id_hex": "11" * 32,
                "build_descriptor_digest_hex": (
                    "29e532abc1ac2f6ea13b45ce7029020e2863e1d302c5cdab0dab0e272652a2c1"
                ),
                "runtime_artifact_sha256_hex": "22" * 32,
            },
            "service": {
                "service_id_hex": "51" * 16,
                "prepare_budget_nanos": 1_000_000_000,
                "start_budget_nanos": 2_000_000_000,
                "readiness_budget_nanos": 3_000_000_000,
                "drain_budget_nanos": 4_000_000_000,
                "stop_budget_nanos": 5_000_000_000,
                "listen_endpoint": "tcp/127.0.0.1:7447",
            },
        }
    ),
}


class ContractReject(ValueError):
    pass


def _load_fabric_oracle() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_paraegox_s7_managed_fabric_oracle", FABRIC_ORACLE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FABRIC = _load_fabric_oracle()


def _u8(value: int) -> bytes:
    return struct.pack(">B", value)


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _hex(value: object) -> bytes:
    assert isinstance(value, str)
    return bytes.fromhex(value)


def _digest(domain: bytes, fields: list[bytes]) -> bytes:
    encoded = bytearray(DIGEST_MAGIC)
    encoded += _u16(DIGEST_VERSION)
    encoded += _u32(len(domain))
    encoded += domain
    for ordinal, field in enumerate(fields, start=1):
        encoded += b"\x01" + _u32(ordinal) + _u64(len(field)) + field
    encoded += b"\xff" + _u32(len(fields))
    return hashlib.sha256(encoded).digest()


def _compatibility_digest() -> bytes:
    return _digest(
        STACK_COMPATIBILITY_DOMAIN,
        [
            STACK_PROJECTION_MAGIC,
            _u16(STACK_PROJECTION_VERSION),
            _u16(STACK_PROJECTION_BYTES),
            PXAR_MAGIC,
            _u16(PXAR_VERSION),
            _u16(PXAR_HEADER_BYTES),
            _u32(MAX_PXAR_BYTES),
            PXTE_MAGIC,
            _u16(PXTE_VERSION),
            _u32(MAX_PXTE_BYTES),
            _u16(PROFILE_VERSION),
            _u16(PROVIDER_SELECTION_VERSION),
            _u16(MANAGED_SERVICE_VERSION),
            _u16(2),
            _u16(2),
            PXTA_ZERO,
            _u16(MAX_KEY_EXPRESSION_BYTES),
            _u32(MAX_INGRESS_ITEMS),
            _u64(MAX_INGRESS_BYTES),
            _u32(MIN_FRAME_BYTES),
            _u32(MAX_FRAME_BYTES),
            _u32(MIN_RESPONSE_BODY_BYTES),
            _u32(MAX_RESPONSE_BODY_BYTES),
            _u64(MAX_LIFECYCLE_NANOS),
            _u16(MAX_SESSIONS),
            _u16(MAX_TURNS_PER_SESSION),
            _u16(MAX_REQUESTS_PER_SESSION),
            _u16(MAX_EVENT_BATCH),
            PXTE_DIGEST_DOMAIN,
            ASSIGNMENT_DIGEST_DOMAIN,
            _u16(MODE_FABRIC_AND_AGENT),
            _u16(MODE_EMPTY),
            _u16(PROVIDER_PROVISIONED),
            _u16(PROVIDER_DETERMINISTIC_FIXTURE),
            TERMINAL_MAGIC,
            _u16(TERMINAL_VERSION),
            _u16(TERMINAL_SIGNING_VERSION),
            _u16(MAX_TERMINAL_BYTES),
            _u16(MAX_TERMINAL_SIGNATURE_BYTES),
            TERMINAL_RESULT_REF_DOMAIN,
            TERMINAL_SIGNING_MAGIC,
            TERMINAL_DIGEST_DOMAIN,
        ],
    )


def _encode_projection(base_projection: bytes) -> bytes:
    FABRIC._decode_projection(base_projection)
    wire = (
        STACK_PROJECTION_MAGIC
        + _u16(STACK_PROJECTION_VERSION)
        + base_projection
        + _compatibility_digest()
        + _u16(PXAR_VERSION)
        + _u16(PROFILE_VERSION)
    )
    assert len(wire) == STACK_PROJECTION_BYTES
    _decode_projection(wire)
    return wire


def _decode_projection(wire: bytes) -> dict[str, Any]:
    if len(wire) != STACK_PROJECTION_BYTES:
        raise ContractReject("PXSP length")
    if wire[:4] != STACK_PROJECTION_MAGIC or struct.unpack_from(">H", wire, 4)[0] != 1:
        raise ContractReject("PXSP wire")
    try:
        base = FABRIC._decode_projection(wire[6 : 6 + BASE_PROJECTION_BYTES])
    except FABRIC.ContractReject as error:
        raise ContractReject("embedded PXMP") from error
    tail = 6 + BASE_PROJECTION_BYTES
    if wire[tail : tail + 32] != _compatibility_digest():
        raise ContractReject("PXSP compatibility")
    if struct.unpack_from(">HH", wire, tail + 32) != (PXAR_VERSION, PROFILE_VERSION):
        raise ContractReject("PXSP selection")
    canonical = _encode_projection_unchecked(base["wire"])
    if canonical != wire:
        raise ContractReject("PXSP noncanonical")
    return {"base": base, "wire": wire}


def _encode_projection_unchecked(base_projection: bytes) -> bytes:
    return (
        STACK_PROJECTION_MAGIC
        + _u16(STACK_PROJECTION_VERSION)
        + base_projection
        + _compatibility_digest()
        + _u16(PXAR_VERSION)
        + _u16(PROFILE_VERSION)
    )


def _validate_key_expression(value: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ContractReject("Agent key expression") from error
    if (
        not encoded
        or len(encoded) > MAX_KEY_EXPRESSION_BYTES
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or KEY_EXPRESSION_RE.fullmatch(value) is None
    ):
        raise ContractReject("Agent key expression")
    return encoded


def _validate_agent(agent: dict[str, Any]) -> None:
    if len(_hex(agent["service_id_hex"])) != 16 or _hex(agent["service_id_hex"]) == bytes(16):
        raise ContractReject("Agent service")
    budgets = [
        agent["prepare_budget_nanos"],
        agent["start_budget_nanos"],
        agent["readiness_budget_nanos"],
        agent["drain_budget_nanos"],
        agent["stop_budget_nanos"],
    ]
    if any(not 0 < value <= MAX_LIFECYCLE_NANOS for value in budgets):
        raise ContractReject("Agent lifecycle")
    semantic = [
        (agent["max_sessions"], MAX_SESSIONS),
        (agent["max_turns_per_session"], MAX_TURNS_PER_SESSION),
        (agent["max_requests_per_session"], MAX_REQUESTS_PER_SESSION),
        (agent["max_event_batch"], MAX_EVENT_BATCH),
    ]
    if any(not 0 < value <= maximum for value, maximum in semantic):
        raise ContractReject("Agent semantic limits")
    submit_id = _hex(agent["submit_binding_id_hex"])
    control_id = _hex(agent["control_binding_id_hex"])
    if (
        len(submit_id) != 16
        or len(control_id) != 16
        or submit_id == bytes(16)
        or control_id == bytes(16)
        or submit_id == control_id
    ):
        raise ContractReject("Agent bindings")
    submit = _validate_key_expression(agent["submit_key_expression"])
    control = _validate_key_expression(agent["control_key_expression"])
    if submit == control:
        raise ContractReject("Agent bindings")
    if (
        not 0 < agent["max_items"] <= MAX_INGRESS_ITEMS
        or not 0 < agent["max_bytes"] <= MAX_INGRESS_BYTES
        or not MIN_FRAME_BYTES <= agent["max_frame_bytes"] <= MAX_FRAME_BYTES
        or agent["max_frame_bytes"] > agent["max_bytes"]
        or not MIN_RESPONSE_BODY_BYTES
        <= agent["max_response_body_bytes"]
        <= MAX_RESPONSE_BODY_BYTES
        or not 0 < agent["handler_timeout_nanos"] <= MAX_LIFECYCLE_NANOS
    ):
        raise ContractReject("Agent ingress")
    provider_ref = _hex(agent["provider_ref_hex"])
    config_digest = _hex(agent["config_digest_hex"])
    secret_ref = _hex(agent["secret_ref_hex"])
    if (
        len(provider_ref) != 16
        or provider_ref == bytes(16)
        or len(config_digest) != 32
        or config_digest == bytes(32)
        or len(secret_ref) != 16
    ):
        raise ContractReject("Agent provider")
    profile = agent["provider_profile"]
    if profile == PROVIDER_PROVISIONED:
        if secret_ref == bytes(16):
            raise ContractReject("Agent provider")
    elif profile == PROVIDER_DETERMINISTIC_FIXTURE:
        if secret_ref != bytes(16):
            raise ContractReject("Agent provider")
    else:
        raise ContractReject("Agent provider")


def _encode_agent_plan(agent: dict[str, Any]) -> bytes:
    _validate_agent(agent)
    submit = _validate_key_expression(agent["submit_key_expression"])
    control = _validate_key_expression(agent["control_key_expression"])
    budgets = [
        agent["prepare_budget_nanos"],
        agent["start_budget_nanos"],
        agent["readiness_budget_nanos"],
        agent["drain_budget_nanos"],
        agent["stop_budget_nanos"],
    ]
    wire = bytearray(_u16(MANAGED_SERVICE_VERSION) + _hex(agent["service_id_hex"]))
    wire += b"".join(_u64(value) for value in budgets)
    wire += b"".join(
        _u16(agent[key])
        for key in (
            "max_sessions",
            "max_turns_per_session",
            "max_requests_per_session",
            "max_event_batch",
        )
    )
    wire += _hex(agent["submit_binding_id_hex"]) + _hex(agent["control_binding_id_hex"])
    wire += _u16(len(submit)) + _u16(len(control))
    wire += _u32(agent["max_items"]) + _u64(agent["max_bytes"])
    wire += _u32(agent["max_frame_bytes"]) + _u32(agent["max_response_body_bytes"])
    wire += _u64(agent["handler_timeout_nanos"])
    wire += _u16(PROVIDER_SELECTION_VERSION) + _u8(agent["provider_profile"]) + b"\x00"
    wire += _hex(agent["provider_ref_hex"]) + _hex(agent["config_digest_hex"])
    secret = _hex(agent["secret_ref_hex"])
    wire += _u8(secret != bytes(16)) + secret + submit + control
    encoded = bytes(wire)
    assert len(encoded) == AGENT_PLAN_FIXED_BYTES + len(submit) + len(control)
    return encoded


class _Cursor:
    def __init__(self, wire: bytes) -> None:
        self.wire = wire
        self.offset = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.wire):
            raise ContractReject("truncated")
        value = self.wire[self.offset : end]
        self.offset = end
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def finish(self) -> None:
        if self.offset != len(self.wire):
            raise ContractReject("trailing bytes")


def _decode_agent_plan(wire: bytes) -> dict[str, Any]:
    if len(wire) < AGENT_PLAN_FIXED_BYTES:
        raise ContractReject("Agent truncated")
    cursor = _Cursor(wire)
    if cursor.u16() != MANAGED_SERVICE_VERSION:
        raise ContractReject("Agent service version")
    agent: dict[str, Any] = {"service_id_hex": cursor.take(16).hex()}
    for key in (
        "prepare_budget_nanos",
        "start_budget_nanos",
        "readiness_budget_nanos",
        "drain_budget_nanos",
        "stop_budget_nanos",
    ):
        agent[key] = cursor.u64()
    for key in (
        "max_sessions",
        "max_turns_per_session",
        "max_requests_per_session",
        "max_event_batch",
    ):
        agent[key] = cursor.u16()
    agent["submit_binding_id_hex"] = cursor.take(16).hex()
    agent["control_binding_id_hex"] = cursor.take(16).hex()
    submit_length = cursor.u16()
    control_length = cursor.u16()
    agent["max_items"] = cursor.u32()
    agent["max_bytes"] = cursor.u64()
    agent["max_frame_bytes"] = cursor.u32()
    agent["max_response_body_bytes"] = cursor.u32()
    agent["handler_timeout_nanos"] = cursor.u64()
    if cursor.u16() != PROVIDER_SELECTION_VERSION:
        raise ContractReject("Agent provider version")
    agent["provider_profile"] = cursor.u8()
    if cursor.u8() != 0:
        raise ContractReject("Agent provider reserved")
    agent["provider_ref_hex"] = cursor.take(16).hex()
    agent["config_digest_hex"] = cursor.take(32).hex()
    secret_present = cursor.u8()
    secret = cursor.take(16)
    try:
        agent["submit_key_expression"] = cursor.take(submit_length).decode("utf-8")
        agent["control_key_expression"] = cursor.take(control_length).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractReject("Agent key expression") from error
    cursor.finish()
    if secret_present not in {0, 1} or secret_present != int(secret != bytes(16)):
        raise ContractReject("Agent provider presence")
    agent["secret_ref_hex"] = secret.hex()
    _validate_agent(agent)
    if _encode_agent_plan(agent) != wire:
        raise ContractReject("Agent noncanonical")
    return agent


def _encode_pxte(
    projection: bytes,
    mode: int,
    fabric_pxte: bytes,
    agent: dict[str, Any] | None,
) -> bytes:
    _decode_projection(projection)
    try:
        fabric = FABRIC._decode_pxte(fabric_pxte)
    except FABRIC.ContractReject as error:
        raise ContractReject("embedded Fabric PXTE") from error
    if mode == MODE_FABRIC_AND_AGENT:
        if fabric["mode"] != FABRIC.MODE_ONE_SERVICE or agent is None:
            raise ContractReject("stack shape")
        if fabric["service"]["service_id"] == _hex(agent["service_id_hex"]):
            raise ContractReject("duplicate service")
    elif mode == MODE_EMPTY:
        if fabric["mode"] != FABRIC.MODE_EMPTY or agent is not None:
            raise ContractReject("stack shape")
    else:
        raise ContractReject("stack mode")
    wire = bytearray(PXTE_MAGIC + _u16(PXTE_VERSION) + projection)
    wire += _u16(PROFILE_VERSION) + _u8(mode) + _u8(agent is not None)
    wire += _u32(len(fabric_pxte)) + fabric_pxte
    if agent is not None:
        wire += _encode_agent_plan(agent)
    encoded = bytes(wire)
    _decode_pxte(encoded)
    return encoded


def _decode_pxte(wire: bytes) -> dict[str, Any]:
    if len(wire) > MAX_PXTE_BYTES:
        raise ContractReject("PXTE too large")
    if len(wire) < PXTE_FIXED_BYTES:
        raise ContractReject("PXTE truncated")
    if wire[:4] != PXTE_MAGIC or struct.unpack_from(">H", wire, 4)[0] != PXTE_VERSION:
        raise ContractReject("PXTE wire")
    projection = _decode_projection(wire[6 : 6 + STACK_PROJECTION_BYTES])
    tail = 6 + STACK_PROJECTION_BYTES
    profile, mode, present, fabric_length = struct.unpack_from(">HBBI", wire, tail)
    if profile != PROFILE_VERSION or mode not in {MODE_FABRIC_AND_AGENT, MODE_EMPTY}:
        raise ContractReject("PXTE selection")
    if not 0 < fabric_length <= MAX_FABRIC_PXTE_BYTES:
        raise ContractReject("PXTE Fabric length")
    fabric_end = PXTE_FIXED_BYTES + fabric_length
    if len(wire) < fabric_end:
        raise ContractReject("PXTE truncated")
    fabric_wire = wire[PXTE_FIXED_BYTES:fabric_end]
    try:
        fabric = FABRIC._decode_pxte(fabric_wire)
    except FABRIC.ContractReject as error:
        raise ContractReject("embedded Fabric PXTE") from error
    if fabric["projection"]["wire"] != projection["base"]["wire"]:
        raise ContractReject("projection mismatch")
    agent_wire = wire[fabric_end:]
    if mode == MODE_FABRIC_AND_AGENT and present == 1:
        agent = _decode_agent_plan(agent_wire)
        if fabric["mode"] != FABRIC.MODE_ONE_SERVICE:
            raise ContractReject("stack shape")
        if fabric["service"]["service_id"] == _hex(agent["service_id_hex"]):
            raise ContractReject("duplicate service")
    elif mode == MODE_EMPTY and present == 0 and not agent_wire:
        agent = None
        if fabric["mode"] != FABRIC.MODE_EMPTY:
            raise ContractReject("stack shape")
    else:
        raise ContractReject("stack shape")
    canonical = _encode_pxte_unchecked(projection["wire"], mode, fabric_wire, agent)
    if canonical != wire:
        raise ContractReject("PXTE noncanonical")
    return {
        "projection": projection,
        "mode": mode,
        "fabric": fabric,
        "fabric_wire": fabric_wire,
        "agent": agent,
        "wire": wire,
    }


def _encode_pxte_unchecked(
    projection: bytes,
    mode: int,
    fabric_wire: bytes,
    agent: dict[str, Any] | None,
) -> bytes:
    wire = bytearray(PXTE_MAGIC + _u16(PXTE_VERSION) + projection)
    wire += _u16(PROFILE_VERSION) + _u8(mode) + _u8(agent is not None)
    wire += _u32(len(fabric_wire)) + fabric_wire
    if agent is not None:
        wire += _encode_agent_plan(agent)
    return bytes(wire)


def _pxta_digest() -> bytes:
    return _digest(PXTA_DIGEST_DOMAIN, [PXTA_ZERO])


def _pxte_digest(wire: bytes) -> bytes:
    _decode_pxte(wire)
    return _digest(PXTE_DIGEST_DOMAIN, [wire])


def _assignment_digest(wire: bytes) -> bytes:
    return _digest(ASSIGNMENT_DIGEST_DOMAIN, [_pxta_digest(), _pxte_digest(wire)])


def _encode_pxar(envelope_wire: bytes, pxte_wire: bytes) -> bytes:
    try:
        FABRIC.LEGACY._decode_envelope(envelope_wire)
    except FABRIC.LEGACY.ContractReject as error:
        raise ContractReject("envelope") from error
    _decode_pxte(pxte_wire)
    wire = (
        PXAR_MAGIC
        + _u16(PXAR_VERSION)
        + _u32(len(envelope_wire))
        + _u32(len(PXTA_ZERO))
        + _u32(len(pxte_wire))
        + envelope_wire
        + PXTA_ZERO
        + pxte_wire
    )
    _decode_pxar(wire)
    return wire


def _decode_pxar(wire: bytes) -> dict[str, Any]:
    if len(wire) > MAX_PXAR_BYTES:
        raise ContractReject("PXAR too large")
    if len(wire) < PXAR_HEADER_BYTES:
        raise ContractReject("PXAR truncated")
    if wire[:4] != PXAR_MAGIC or struct.unpack_from(">H", wire, 4)[0] != PXAR_VERSION:
        raise ContractReject("PXAR wire")
    envelope_length, bindings_length, execution_length = struct.unpack_from(">III", wire, 6)
    if (
        envelope_length > MAX_ENVELOPE_BYTES
        or bindings_length != len(PXTA_ZERO)
        or execution_length > MAX_PXTE_BYTES
    ):
        raise ContractReject("PXAR length")
    expected = PXAR_HEADER_BYTES + envelope_length + bindings_length + execution_length
    if len(wire) != expected:
        raise ContractReject("PXAR total length")
    envelope_end = PXAR_HEADER_BYTES + envelope_length
    binding_end = envelope_end + bindings_length
    envelope_wire = wire[PXAR_HEADER_BYTES:envelope_end]
    binding_wire = wire[envelope_end:binding_end]
    execution_wire = wire[binding_end:]
    try:
        envelope = FABRIC.LEGACY._decode_envelope(envelope_wire)
    except FABRIC.LEGACY.ContractReject as error:
        raise ContractReject("envelope") from error
    if binding_wire != PXTA_ZERO:
        raise ContractReject("PXTA binding")
    execution = _decode_pxte(execution_wire)
    if envelope[2] != execution["projection"]["base"]["target"]:
        raise ContractReject("target correlation")
    assignment_digest = _assignment_digest(execution_wire)
    if envelope[7] != assignment_digest:
        raise ContractReject("assignment correlation")
    return {
        "envelope": envelope,
        "envelope_wire": envelope_wire,
        "execution": execution,
        "assignment_digest": assignment_digest,
        "target_slice_digest": envelope[8],
        "request_digest": _digest(FABRIC.LEGACY.REQUEST_DIGEST_DOMAIN, [envelope_wire]),
        "wire": wire,
    }


def _terminal_result_ref(request: dict[str, Any]) -> bytes:
    envelope = request["envelope"]
    return _digest(
        TERMINAL_RESULT_REF_DOMAIN,
        [
            TERMINAL_MAGIC,
            _u16(TERMINAL_VERSION),
            envelope[2],
            envelope[32],
            envelope[3],
            envelope[24],
            request["request_digest"],
        ],
    )[:16]


def _validate_state(state: dict[str, Any], evidence: dict[str, Any]) -> None:
    outcome = state["outcome"]
    lifecycle = state["lifecycle_effect"]
    head = state["head"]
    fabric_generation = state["fabric_generation"]
    agent_generation = state["agent_generation"]
    if agent_generation is not None and fabric_generation is None:
        raise ContractReject("terminal generation")
    committed = head == 3
    valid_state = {
        1: lifecycle == 2
        and committed
        and fabric_generation is not None
        and agent_generation is not None,
        2: committed and fabric_generation is None and agent_generation is None,
        3: lifecycle == 1 and not committed,
        4: lifecycle == 2,
        5: lifecycle == 2 and committed and fabric_generation is not None,
    }
    if not valid_state.get(outcome, False):
        raise ContractReject("terminal state")
    if fabric_generation is not None and fabric_generation <= 0:
        raise ContractReject("Fabric generation")
    if agent_generation is not None and agent_generation <= 0:
        raise ContractReject("Agent generation")
    census = evidence["physical_binding_census"]
    flags = [
        evidence["census_complete"],
        evidence["fabric_ready"],
        evidence["agent_ready"],
        evidence["dependency_satisfied"],
        evidence["exact_zero"],
        evidence["quarantined"],
    ]
    if census > 2 or (flags[2] and (not flags[1] or not flags[3])):
        raise ContractReject("terminal evidence")
    if flags[4] and (census != 0 or flags[1] or flags[2] or flags[3] or flags[5]):
        raise ContractReject("terminal exact zero")
    if (
        evidence["resource_census_digest"] == bytes(32)
        or evidence["raw_outcome_digest"] == bytes(32)
        or evidence["completion_runtime_host_epoch"] == 0
        or evidence["completion_snapshot_sequence"] == 0
        or evidence["selection_clock_generation"] == 0
        or evidence["selection_observed_at_nanos"] == 0
    ):
        raise ContractReject("terminal evidence")
    generations_ready = fabric_generation is not None and agent_generation is not None
    valid_evidence = {
        1: generations_ready
        and flags[0]
        and census == 2
        and all(flags[1:4])
        and not flags[4]
        and not flags[5],
        2: flags[0] and flags[4] and not flags[5],
        3: flags[0]
        and not flags[5]
        and (
            (flags[4] and fabric_generation is None and agent_generation is None)
            or (not flags[4] and generations_ready and census == 2 and all(flags[1:4]))
        ),
        4: not flags[4] and not flags[5],
        5: flags[5] and not flags[4] and not flags[2] and not flags[3],
    }
    if not valid_evidence.get(outcome, False):
        raise ContractReject("terminal state/evidence")


def _desired_head(request: dict[str, Any], state: dict[str, Any]) -> bytes | None:
    head = state["head"]
    if head == 1:
        return None
    if head == 2:
        value = state.get("preserved_head_digest")
        if not isinstance(value, bytes) or value == bytes(32):
            raise ContractReject("terminal head")
        return value
    if head == 3:
        return request["target_slice_digest"]
    raise ContractReject("terminal head")


def _validate_terminal_for_request(
    request: dict[str, Any], state: dict[str, Any], evidence: dict[str, Any]
) -> bytes | None:
    _validate_state(state, evidence)
    if state["outcome"] == 1 and request["execution"]["mode"] != MODE_FABRIC_AND_AGENT:
        raise ContractReject("terminal request mode")
    if state["outcome"] == 2 and request["execution"]["mode"] != MODE_EMPTY:
        raise ContractReject("terminal request mode")
    if evidence["selection_clock_generation"] < struct.unpack(">Q", request["envelope"][29])[0]:
        raise ContractReject("terminal clock correlation")
    return _desired_head(request, state)


def _evidence_flags(evidence: dict[str, Any]) -> int:
    return sum(
        int(evidence[key]) << bit
        for bit, key in enumerate(
            (
                "census_complete",
                "fabric_ready",
                "agent_ready",
                "dependency_satisfied",
                "exact_zero",
                "quarantined",
            )
        )
    )


def _terminal_fields(
    magic: bytes,
    version: int,
    request: dict[str, Any],
    state: dict[str, Any],
    evidence: dict[str, Any],
    channel: dict[str, bytes],
    auth: dict[str, Any],
) -> bytes:
    desired = _validate_terminal_for_request(request, state, evidence)
    envelope = request["envelope"]
    wire = bytearray(magic + _u16(version))
    wire += envelope[2] + envelope[32] + envelope[3] + envelope[24]
    wire += request["request_digest"] + request["target_slice_digest"]
    wire += request["assignment_digest"] + _terminal_result_ref(request)
    wire += _u8(request["execution"]["mode"])
    wire += _u8(state["outcome"]) + _u8(state["lifecycle_effect"]) + _u8(state["head"])
    wire += _u8(desired is not None) + (bytes(32) if desired is None else desired)
    for generation in (state["fabric_generation"], state["agent_generation"]):
        wire += _u8(generation is not None) + _u64(0 if generation is None else generation)
    wire += _u16(evidence["physical_binding_census"]) + _u8(_evidence_flags(evidence))
    wire += evidence["resource_census_digest"] + evidence["raw_outcome_digest"]
    wire += _u64(evidence["completion_runtime_host_epoch"])
    wire += _u64(evidence["completion_snapshot_sequence"])
    wire += _u64(evidence["selection_clock_generation"])
    wire += _u64(evidence["selection_observed_at_nanos"])
    wire += channel["target"] + channel["runtime_peer"]
    wire += channel["local_endpoint_identity_digest"] + channel["peer_credentials_digest"]
    wire += auth["runtime_peer"] + auth["channel_binding_digest"] + auth["key"]
    wire += _u16(auth["algorithm"]) + _u16(auth["algorithm_version"])
    return bytes(wire)


def _encode_terminal_receipt(
    request_wire: bytes,
    state: dict[str, Any],
    evidence: dict[str, Any],
    channel: dict[str, bytes],
) -> dict[str, bytes]:
    request = _decode_pxar(request_wire)
    auth = {
        "runtime_peer": channel["runtime_peer"],
        "channel_binding_digest": channel["binding_digest"],
        "key": bytes.fromhex("76" * 16),
        "algorithm": 1,
        "algorithm_version": 1,
    }
    if channel["target"] != request["envelope"][2]:
        raise ContractReject("terminal channel target")
    transcript = _terminal_fields(
        TERMINAL_SIGNING_MAGIC,
        TERMINAL_SIGNING_VERSION,
        request,
        state,
        evidence,
        channel,
        auth,
    )
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("77" * 32))
    signature = private_key.sign(transcript)
    body = _terminal_fields(
        TERMINAL_MAGIC, TERMINAL_VERSION, request, state, evidence, channel, auth
    )
    assert len(body) == TERMINAL_FIELDS_BYTES
    wire = body + _u16(len(signature)) + signature
    receipt = _decode_terminal_receipt(wire)
    _validate_terminal_against_request(receipt, request_wire, channel)
    public_key = private_key.public_key().public_bytes_raw()
    _verify_terminal_signature(receipt, public_key)
    return {
        "wire": wire,
        "receipt_digest": _digest(TERMINAL_DIGEST_DOMAIN, [wire]),
        "signing_transcript": transcript,
        "signature": signature,
        "public_key": public_key,
    }


def _decode_generation(cursor: _Cursor) -> int | None:
    present = cursor.u8()
    value = cursor.u64()
    if (present, value) == (0, 0):
        return None
    if present == 1 and value > 0:
        return value
    raise ContractReject("terminal generation")


def _decode_terminal_receipt(wire: bytes) -> dict[str, Any]:
    if len(wire) > MAX_TERMINAL_BYTES:
        raise ContractReject("PXST too large")
    if len(wire) < TERMINAL_FIELDS_BYTES + 3:
        raise ContractReject("PXST truncated")
    cursor = _Cursor(wire)
    if cursor.take(4) != TERMINAL_MAGIC or cursor.u16() != TERMINAL_VERSION:
        raise ContractReject("PXST wire")
    facts: dict[str, Any] = {
        "target": cursor.take(16),
        "runtime_store_instance_id": cursor.take(32),
        "source_scope": cursor.take(16),
        "operation_id": cursor.take(16),
        "request_digest": cursor.take(32),
        "target_slice_digest": cursor.take(32),
        "assignment_digest": cursor.take(32),
        "terminal_result_ref": cursor.take(16),
        "request_mode": cursor.u8(),
    }
    state: dict[str, Any] = {
        "outcome": cursor.u8(),
        "lifecycle_effect": cursor.u8(),
        "head": cursor.u8(),
    }
    desired_present = cursor.u8()
    desired = cursor.take(32)
    if desired_present == 0 and desired == bytes(32):
        facts["desired_head_digest"] = None
    elif desired_present == 1:
        facts["desired_head_digest"] = desired
    else:
        raise ContractReject("terminal desired head")
    if state["head"] == 2:
        state["preserved_head_digest"] = desired
    state["fabric_generation"] = _decode_generation(cursor)
    state["agent_generation"] = _decode_generation(cursor)
    flags_census = cursor.u16()
    flags = cursor.u8()
    if flags & 0b1100_0000:
        raise ContractReject("terminal flags")
    evidence: dict[str, Any] = {
        "physical_binding_census": flags_census,
        "census_complete": bool(flags & 1),
        "fabric_ready": bool(flags & 2),
        "agent_ready": bool(flags & 4),
        "dependency_satisfied": bool(flags & 8),
        "exact_zero": bool(flags & 16),
        "quarantined": bool(flags & 32),
        "resource_census_digest": cursor.take(32),
        "raw_outcome_digest": cursor.take(32),
        "completion_runtime_host_epoch": cursor.u64(),
        "completion_snapshot_sequence": cursor.u64(),
        "selection_clock_generation": cursor.u64(),
        "selection_observed_at_nanos": cursor.u64(),
    }
    channel = {
        "target": cursor.take(16),
        "runtime_peer": cursor.take(16),
        "local_endpoint_identity_digest": cursor.take(32),
        "peer_credentials_digest": cursor.take(32),
    }
    try:
        channel = FABRIC.LEGACY._channel_binding(**channel)
    except FABRIC.LEGACY.ContractReject as error:
        raise ContractReject("terminal channel") from error
    auth = {
        "runtime_peer": cursor.take(16),
        "channel_binding_digest": cursor.take(32),
        "key": cursor.take(16),
        "algorithm": cursor.u16(),
        "algorithm_version": cursor.u16(),
    }
    if (
        auth["runtime_peer"] == bytes(16)
        or auth["channel_binding_digest"] == bytes(32)
        or auth["key"] == bytes(16)
        or auth["algorithm"] == 0
        or auth["algorithm_version"] == 0
    ):
        raise ContractReject("terminal auth")
    signature_length = cursor.u16()
    if not 0 < signature_length <= MAX_TERMINAL_SIGNATURE_BYTES:
        raise ContractReject("terminal signature length")
    signature = cursor.take(signature_length)
    cursor.finish()
    _validate_state(state, evidence)
    if facts["request_mode"] not in {MODE_FABRIC_AND_AGENT, MODE_EMPTY}:
        raise ContractReject("terminal mode")
    if state["outcome"] == 1 and facts["request_mode"] != MODE_FABRIC_AND_AGENT:
        raise ContractReject("terminal mode")
    if state["outcome"] == 2 and facts["request_mode"] != MODE_EMPTY:
        raise ContractReject("terminal mode")
    if any(
        value == bytes(len(value))
        for value in (
            facts["target"],
            facts["runtime_store_instance_id"],
            facts["source_scope"],
            facts["operation_id"],
            facts["request_digest"],
            facts["target_slice_digest"],
            facts["assignment_digest"],
            facts["terminal_result_ref"],
        )
    ):
        raise ContractReject("terminal facts")
    canonical_body = _terminal_fields_from_decoded(
        TERMINAL_MAGIC, TERMINAL_VERSION, facts, state, evidence, channel, auth
    )
    if canonical_body + _u16(len(signature)) + signature != wire:
        raise ContractReject("PXST noncanonical")
    return {
        "facts": facts,
        "state": state,
        "evidence": evidence,
        "channel": channel,
        "auth": auth,
        "signature": signature,
        "wire": wire,
    }


def _terminal_fields_from_decoded(
    magic: bytes,
    version: int,
    facts: dict[str, Any],
    state: dict[str, Any],
    evidence: dict[str, Any],
    channel: dict[str, bytes],
    auth: dict[str, Any],
) -> bytes:
    desired = facts["desired_head_digest"]
    wire = bytearray(magic + _u16(version))
    for key in (
        "target",
        "runtime_store_instance_id",
        "source_scope",
        "operation_id",
        "request_digest",
        "target_slice_digest",
        "assignment_digest",
        "terminal_result_ref",
    ):
        wire += facts[key]
    wire += _u8(facts["request_mode"])
    wire += _u8(state["outcome"]) + _u8(state["lifecycle_effect"]) + _u8(state["head"])
    wire += _u8(desired is not None) + (bytes(32) if desired is None else desired)
    for generation in (state["fabric_generation"], state["agent_generation"]):
        wire += _u8(generation is not None) + _u64(0 if generation is None else generation)
    wire += _u16(evidence["physical_binding_census"]) + _u8(_evidence_flags(evidence))
    wire += evidence["resource_census_digest"] + evidence["raw_outcome_digest"]
    for key in (
        "completion_runtime_host_epoch",
        "completion_snapshot_sequence",
        "selection_clock_generation",
        "selection_observed_at_nanos",
    ):
        wire += _u64(evidence[key])
    wire += channel["target"] + channel["runtime_peer"]
    wire += channel["local_endpoint_identity_digest"] + channel["peer_credentials_digest"]
    wire += auth["runtime_peer"] + auth["channel_binding_digest"] + auth["key"]
    wire += _u16(auth["algorithm"]) + _u16(auth["algorithm_version"])
    return bytes(wire)


def _validate_terminal_against_request(
    receipt: dict[str, Any], request_wire: bytes, channel: dict[str, bytes]
) -> None:
    request = _decode_pxar(request_wire)
    facts = receipt["facts"]
    state = receipt["state"]
    evidence = receipt["evidence"]
    desired = _validate_terminal_for_request(request, state, evidence)
    envelope = request["envelope"]
    expected = {
        "target": envelope[2],
        "runtime_store_instance_id": envelope[32],
        "source_scope": envelope[3],
        "operation_id": envelope[24],
        "request_digest": request["request_digest"],
        "target_slice_digest": request["target_slice_digest"],
        "assignment_digest": request["assignment_digest"],
        "terminal_result_ref": _terminal_result_ref(request),
        "request_mode": request["execution"]["mode"],
        "desired_head_digest": desired,
    }
    if any(facts[key] != value for key, value in expected.items()):
        raise ContractReject("terminal request correlation")
    auth = receipt["auth"]
    if (
        receipt["channel"] != channel
        or channel["target"] != envelope[2]
        or auth["runtime_peer"] != channel["runtime_peer"]
        or auth["channel_binding_digest"] != channel["binding_digest"]
    ):
        raise ContractReject("terminal channel correlation")


def _verify_terminal_signature(receipt: dict[str, Any], public_key: bytes) -> None:
    transcript = _terminal_fields_from_decoded(
        TERMINAL_SIGNING_MAGIC,
        TERMINAL_SIGNING_VERSION,
        receipt["facts"],
        receipt["state"],
        receipt["evidence"],
        receipt["channel"],
        receipt["auth"],
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(receipt["signature"], transcript)
    except (InvalidSignature, ValueError) as error:
        raise ContractReject("terminal signature") from error


def _build_vectors() -> dict[str, Any]:
    base_projection = FABRIC._encode_projection(SEMANTIC["fabric"]["projection"])
    projection = _encode_projection(base_projection)
    fabric_active = FABRIC._encode_pxte(
        base_projection,
        FABRIC.MODE_ONE_SERVICE,
        SEMANTIC["fabric"]["service"],
    )
    active_pxte = _encode_pxte(
        projection,
        MODE_FABRIC_AND_AGENT,
        fabric_active,
        SEMANTIC["agent"],
    )
    active_envelope = FABRIC.LEGACY._build_envelope(
        _assignment_digest(active_pxte),
        source_revision=5,
        operation_byte="6d",
        temporal_byte="6e",
        auth_nonce=b"test-only-managed-agent-stack-active",
    )
    active_outer = _encode_pxar(active_envelope["wire"], active_pxte)
    fabric_empty = FABRIC._encode_pxte(base_projection, FABRIC.MODE_EMPTY, None)
    empty_pxte = _encode_pxte(projection, MODE_EMPTY, fabric_empty, None)
    empty_envelope = FABRIC.LEGACY._build_envelope(
        _assignment_digest(empty_pxte),
        source_revision=6,
        operation_byte="6f",
        temporal_byte="70",
        auth_nonce=b"test-only-managed-agent-stack-empty",
        expected_active_digest=active_envelope["target_slice_digest"],
    )
    empty_outer = _encode_pxar(empty_envelope["wire"], empty_pxte)
    channel = FABRIC.LEGACY._channel_binding(
        target=bytes.fromhex("05" * 16),
        runtime_peer=bytes.fromhex("71" * 16),
        local_endpoint_identity_digest=bytes.fromhex("72" * 32),
        peer_credentials_digest=bytes.fromhex("73" * 32),
    )
    active_terminal = _encode_terminal_receipt(
        active_outer,
        {
            "outcome": 1,
            "lifecycle_effect": 2,
            "head": 3,
            "fabric_generation": 7,
            "agent_generation": 8,
        },
        {
            "physical_binding_census": 2,
            "census_complete": True,
            "fabric_ready": True,
            "agent_ready": True,
            "dependency_satisfied": True,
            "exact_zero": False,
            "quarantined": False,
            "resource_census_digest": bytes.fromhex("74" * 32),
            "raw_outcome_digest": bytes.fromhex("75" * 32),
            "completion_runtime_host_epoch": 9,
            "completion_snapshot_sequence": 11,
            "selection_clock_generation": 3,
            "selection_observed_at_nanos": 13,
        },
        channel,
    )
    empty_terminal = _encode_terminal_receipt(
        empty_outer,
        {
            "outcome": 2,
            "lifecycle_effect": 2,
            "head": 3,
            "fabric_generation": None,
            "agent_generation": None,
        },
        {
            "physical_binding_census": 0,
            "census_complete": True,
            "fabric_ready": False,
            "agent_ready": False,
            "dependency_satisfied": False,
            "exact_zero": True,
            "quarantined": False,
            "resource_census_digest": bytes.fromhex("78" * 32),
            "raw_outcome_digest": bytes.fromhex("79" * 32),
            "completion_runtime_host_epoch": 9,
            "completion_snapshot_sequence": 12,
            "selection_clock_generation": 3,
            "selection_observed_at_nanos": 14,
        },
        channel,
    )
    return {
        "base_projection": base_projection,
        "projection": projection,
        "channel": channel,
        "active": {
            "fabric_pxte": fabric_active,
            "pxte": active_pxte,
            "envelope": active_envelope,
            "outer": active_outer,
            "terminal": active_terminal,
        },
        "empty": {
            "fabric_pxte": fabric_empty,
            "pxte": empty_pxte,
            "envelope": empty_envelope,
            "outer": empty_outer,
            "terminal": empty_terminal,
        },
    }


def _expected_terminal(value: dict[str, bytes]) -> dict[str, Any]:
    return {
        "wire_hex": value["wire"].hex(),
        "wire_length": len(value["wire"]),
        "receipt_digest_hex": value["receipt_digest"].hex(),
        "signature_hex": value["signature"].hex(),
        "public_key_hex": value["public_key"].hex(),
        "signing_transcript_length": len(value["signing_transcript"]),
        "signing_transcript_sha256_hex": hashlib.sha256(value["signing_transcript"]).hexdigest(),
    }


def _expected_vector(value: dict[str, Any]) -> dict[str, Any]:
    pxte = value["pxte"]
    envelope = value["envelope"]
    return {
        "embedded_pxte_v5_hex": value["fabric_pxte"].hex(),
        "pxte_v6_hex": pxte.hex(),
        "pxte_v6_length": len(pxte),
        "pxte_v6_digest_hex": _pxte_digest(pxte).hex(),
        "assignment_v7_digest_hex": _assignment_digest(pxte).hex(),
        "target_slice_digest_hex": envelope["target_slice_digest"].hex(),
        "control_digest_hex": envelope["control_digest"].hex(),
        "request_digest_hex": envelope["request_digest"].hex(),
        "envelope_v2_hex": envelope["wire"].hex(),
        "envelope_v2_length": len(envelope["wire"]),
        "apply_signing_transcript_sha256_hex": hashlib.sha256(
            envelope["signing_transcript"]
        ).hexdigest(),
        "outer_v7_hex": value["outer"].hex(),
        "outer_v7_length": len(value["outer"]),
        "durable_slice_hex": (PXTA_ZERO + pxte).hex(),
        "terminal": _expected_terminal(value["terminal"]),
    }


def _generated_fixture() -> dict[str, Any]:
    vectors = _build_vectors()
    return {
        "format": "paraegox-s7-managed-agent-stack-successor-v1",
        "versions": {
            "pxsp": STACK_PROJECTION_VERSION,
            "profile": PROFILE_VERSION,
            "pxte": PXTE_VERSION,
            "pxar": PXAR_VERSION,
            "envelope": 2,
            "pxst": TERMINAL_VERSION,
        },
        "semantic": SEMANTIC,
        "expected": {
            "compatibility_digest_hex": _compatibility_digest().hex(),
            "base_projection_pxmp_hex": vectors["base_projection"].hex(),
            "projection_pxsp_hex": vectors["projection"].hex(),
            "projection_pxsp_length": len(vectors["projection"]),
            "pxta_zero_hex": PXTA_ZERO.hex(),
            "pxta_digest_hex": _pxta_digest().hex(),
            "channel_binding_digest_hex": vectors["channel"]["binding_digest"].hex(),
            "fabric_and_agent": _expected_vector(vectors["active"]),
            "empty_deactivate": _expected_vector(vectors["empty"]),
        },
        "cross_rejection": [
            "PXSP-v1-is-not-PXMP-v1",
            "PXTE-v6-is-not-PXTE-v5",
            "PXAR-v7-is-not-PXAR-v6",
            "PXST-v1-is-not-PXFT-v1",
        ],
        "managed_fabric_fixture_sha256": hashlib.sha256(
            FABRIC_FIXTURE_PATH.read_bytes()
        ).hexdigest(),
    }


def test_independent_python_oracle_matches_checked_in_golden() -> None:
    assert json.loads(FIXTURE_PATH.read_text()) == _generated_fixture()


def test_pxsp_pxte6_pxar7_roundtrip_and_digest_correlation() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())
    expected = fixture["expected"]
    projection = bytes.fromhex(expected["projection_pxsp_hex"])
    assert _decode_projection(projection)["wire"] == projection
    for name in ("fabric_and_agent", "empty_deactivate"):
        vector = expected[name]
        pxte = bytes.fromhex(vector["pxte_v6_hex"])
        outer = bytes.fromhex(vector["outer_v7_hex"])
        decoded = _decode_pxar(outer)
        assert decoded["execution"]["wire"] == pxte
        assert _pxte_digest(pxte).hex() == vector["pxte_v6_digest_hex"]
        assert _assignment_digest(pxte).hex() == vector["assignment_v7_digest_hex"]
        assert decoded["target_slice_digest"].hex() == vector["target_slice_digest_hex"]
        assert decoded["request_digest"].hex() == vector["request_digest_hex"]
        assert PXTA_ZERO + pxte == bytes.fromhex(vector["durable_slice_hex"])


def test_python_stack_retains_exact_rust_validated_pxmp_and_pxte5_predecessors() -> None:
    fabric_fixture = json.loads(FABRIC_FIXTURE_PATH.read_text())
    fixture = json.loads(FIXTURE_PATH.read_text())
    expected = fixture["expected"]
    assert expected["base_projection_pxmp_hex"] == fabric_fixture["expected"]["projection_hex"]
    assert (
        expected["fabric_and_agent"]["embedded_pxte_v5_hex"]
        == fabric_fixture["expected"]["one_managed_fabric_service"]["pxte_v5_hex"]
    )
    assert (
        expected["empty_deactivate"]["embedded_pxte_v5_hex"]
        == fabric_fixture["expected"]["empty_deactivate"]["pxte_v5_hex"]
    )


def test_predecessor_and_successor_wires_are_cross_rejected_in_both_directions() -> None:
    fabric_fixture = json.loads(FABRIC_FIXTURE_PATH.read_text())["expected"]
    fixture = json.loads(FIXTURE_PATH.read_text())["expected"]
    old_pxmp = bytes.fromhex(fabric_fixture["projection_hex"])
    new_pxsp = bytes.fromhex(fixture["projection_pxsp_hex"])
    old_pxte = bytes.fromhex(fabric_fixture["one_managed_fabric_service"]["pxte_v5_hex"])
    new_pxte = bytes.fromhex(fixture["fabric_and_agent"]["pxte_v6_hex"])
    old_pxar = bytes.fromhex(fabric_fixture["one_managed_fabric_service"]["outer_v6_hex"])
    new_pxar = bytes.fromhex(fixture["fabric_and_agent"]["outer_v7_hex"])
    old_pxft = bytes.fromhex(fabric_fixture["terminal"]["active_ready"]["wire_hex"])
    new_pxst = bytes.fromhex(fixture["fabric_and_agent"]["terminal"]["wire_hex"])
    with pytest.raises(ContractReject):
        _decode_projection(old_pxmp)
    with pytest.raises(FABRIC.ContractReject):
        FABRIC._decode_projection(new_pxsp)
    with pytest.raises(ContractReject):
        _decode_pxte(old_pxte)
    with pytest.raises(FABRIC.ContractReject):
        FABRIC._decode_pxte(new_pxte)
    with pytest.raises(ContractReject):
        _decode_pxar(old_pxar)
    with pytest.raises(FABRIC.ContractReject):
        FABRIC._decode_pxar(new_pxar)
    with pytest.raises(ContractReject):
        _decode_terminal_receipt(old_pxft)
    with pytest.raises(FABRIC.ContractReject):
        FABRIC._decode_terminal_receipt(new_pxst)


def test_agent_two_lane_provider_and_ingress_fields_fail_closed() -> None:
    for mutation in (
        {"control_binding_id_hex": SEMANTIC["agent"]["submit_binding_id_hex"]},
        {"control_key_expression": SEMANTIC["agent"]["submit_key_expression"]},
        {"submit_key_expression": "paraegox/*/submit"},
        {"max_frame_bytes": SEMANTIC["agent"]["max_bytes"] + 1},
        {"provider_ref_hex": "00" * 16},
        {"secret_ref_hex": "00" * 16},
    ):
        invalid = {**SEMANTIC["agent"], **mutation}
        with pytest.raises(ContractReject):
            _encode_agent_plan(invalid)
    fixture = json.loads(FIXTURE_PATH.read_text())["expected"]
    pxte = bytearray.fromhex(fixture["fabric_and_agent"]["pxte_v6_hex"])
    fabric_length = struct.unpack_from(">I", pxte, 238)[0]
    reserved = PXTE_FIXED_BYTES + fabric_length + 133
    pxte[reserved] = 1
    with pytest.raises(ContractReject):
        _decode_pxte(bytes(pxte))


def test_pxst_roundtrip_signature_and_exact_request_channel_correlation() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())["expected"]
    channel = FABRIC.LEGACY._channel_binding(
        target=bytes.fromhex("05" * 16),
        runtime_peer=bytes.fromhex("71" * 16),
        local_endpoint_identity_digest=bytes.fromhex("72" * 32),
        peer_credentials_digest=bytes.fromhex("73" * 32),
    )
    for name in ("fabric_and_agent", "empty_deactivate"):
        vector = fixture[name]
        terminal = vector["terminal"]
        wire = bytes.fromhex(terminal["wire_hex"])
        receipt = _decode_terminal_receipt(wire)
        _validate_terminal_against_request(receipt, bytes.fromhex(vector["outer_v7_hex"]), channel)
        _verify_terminal_signature(receipt, bytes.fromhex(terminal["public_key_hex"]))
        assert _digest(TERMINAL_DIGEST_DOMAIN, [wire]).hex() == terminal["receipt_digest_hex"]
        assert len(wire) == terminal["wire_length"]


def test_pxst_tampering_wrong_request_and_wrong_channel_fail_closed() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())["expected"]
    active = fixture["fabric_and_agent"]
    wire = bytes.fromhex(active["terminal"]["wire_hex"])
    receipt = _decode_terminal_receipt(wire)
    channel = FABRIC.LEGACY._channel_binding(
        target=bytes.fromhex("05" * 16),
        runtime_peer=bytes.fromhex("71" * 16),
        local_endpoint_identity_digest=bytes.fromhex("72" * 32),
        peer_credentials_digest=bytes.fromhex("73" * 32),
    )
    with pytest.raises(ContractReject):
        _validate_terminal_against_request(
            receipt,
            bytes.fromhex(fixture["empty_deactivate"]["outer_v7_hex"]),
            channel,
        )
    wrong_channel = dict(channel)
    wrong_channel["runtime_peer"] = bytes.fromhex("99" * 16)
    with pytest.raises(ContractReject):
        _validate_terminal_against_request(
            receipt, bytes.fromhex(active["outer_v7_hex"]), wrong_channel
        )
    bad_signature = bytearray(wire)
    bad_signature[-1] ^= 1
    decoded = _decode_terminal_receipt(bytes(bad_signature))
    with pytest.raises(ContractReject):
        _verify_terminal_signature(decoded, bytes.fromhex(active["terminal"]["public_key_hex"]))
    bad_flags = bytearray(wire)
    bad_flags[253 + 2] |= 0b1000_0000
    with pytest.raises(ContractReject):
        _decode_terminal_receipt(bytes(bad_flags))


def test_managed_fabric_fixture_is_unchanged() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())
    assert (
        hashlib.sha256(FABRIC_FIXTURE_PATH.read_bytes()).hexdigest()
        == fixture["managed_fabric_fixture_sha256"]
    )
