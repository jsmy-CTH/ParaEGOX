from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import struct
from collections.abc import Callable
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
FIXTURE_PATH = REPO_ROOT / "tests/fixtures/wire/s7_managed_fabric_successor_v1.json"
LEGACY_FIXTURE_PATH = REPO_ROOT / "tests/fixtures/wire/s7_reference_successor_v1.json"
LEGACY_ORACLE_PATH = REPO_ROOT / "tests/contract/test_s7_reference_successor.py"

DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
DIGEST_VERSION = 1
PROJECTION_MAGIC = b"PXMP"
PROJECTION_VERSION = 1
PROJECTION_BYTES = 186
PXTE_MAGIC = b"PXTE"
PXTE_VERSION = 5
PROFILE_VERSION = 2
MODE_ONE_SERVICE = 1
MODE_EMPTY = 2
PXTE_FIXED_BYTES = 196
SERVICE_FIXED_BYTES = 60
MAX_ENDPOINT_BYTES = 256
MAX_LIFECYCLE_NANOS = 86_400_000_000_000
PXTE_MAX_BYTES = PXTE_FIXED_BYTES + SERVICE_FIXED_BYTES + MAX_ENDPOINT_BYTES
PXAR_MAGIC = b"PXAR"
PXAR_VERSION = 6
PXAR_HEADER_BYTES = 18
MAX_ENVELOPE_BYTES = 4_096
PXTA_ZERO = bytes.fromhex("50585441000100000000")
PXTA_DIGEST_DOMAIN = b"paraegox.runtime.target-assignments.sha256.v1"
COMPATIBILITY_DOMAIN = b"paraegox.runtime.compiled-managed-fabric-compatibility.sha256.v1"
PXTE_DIGEST_DOMAIN = b"paraegox.runtime.target-execution.sha256.v5"
COMPOSITE_DIGEST_DOMAIN = b"paraegox.runtime.target-plan-assignments.sha256.v6"
TERMINAL_MAGIC = b"PXFT"
TERMINAL_VERSION = 1
TERMINAL_FIELD_COUNT = 30
MAX_TERMINAL_BYTES = 2_048
MAX_TERMINAL_SIGNATURE_BYTES = 512
TERMINAL_SIGNING_DOMAIN = (
    b"paraegox.runtime.managed-fabric-apply-terminal-receipt.response-auth.signing.v1"
)
TERMINAL_DIGEST_DOMAIN = b"paraegox.runtime.managed-fabric-apply-terminal-receipt.sha256.v1"
TERMINAL_RESULT_REF_DOMAIN = b"paraegox.runtime.managed-fabric-apply-terminal-result.sha256.v1"
ENDPOINT_PREFIX = "tcp/127.0.0.1:"
ENDPOINT_RE = re.compile(r"tcp/127\.0\.0\.1:([1-9][0-9]{0,4})")

ERROR = {
    "frame_too_large": 1,
    "truncated": 2,
    "invalid_magic": 3,
    "unsupported_version": 4,
    "invalid_field_length": 9,
    "invalid_field_value": 10,
    "digest_mismatch": 12,
    "cross_reference_mismatch": 13,
    "unsupported_shape": 14,
    "binding_not_allowed": 15,
    "target_mismatch": 17,
    "trailing_bytes": 21,
    "invalid_presence": 23,
    "compatibility_mismatch": 25,
}

SEMANTIC: dict[str, Any] = {
    "projection": {
        "manifest_digest_hex": "fad22cd7f146653019a6b9570d06c222a34689d5b669481cdb7b314ec05edf53",
        "target_hex": "05" * 16,
        "build_instance_id_hex": "11" * 32,
        "build_descriptor_digest_hex": "29e532abc1ac2f6ea13b45ce7029020e"
        "2863e1d302c5cdab0dab0e272652a2c1",
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


class ContractReject(ValueError):
    def __init__(self, code: int, detail: int | None = None) -> None:
        super().__init__(f"contract rejection code={code} detail={detail}")
        self.code = code
        self.detail = detail


def _load_legacy_oracle() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_paraegox_s7_reference_oracle", LEGACY_ORACLE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LEGACY = _load_legacy_oracle()


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
        COMPATIBILITY_DOMAIN,
        [
            PXAR_MAGIC,
            _u16(PXAR_VERSION),
            _u16(PXAR_HEADER_BYTES),
            _u32(PXAR_HEADER_BYTES + MAX_ENVELOPE_BYTES + len(PXTA_ZERO) + PXTE_MAX_BYTES),
            PXTE_MAGIC,
            _u16(PXTE_VERSION),
            _u32(PXTE_MAX_BYTES),
            _u16(PROJECTION_BYTES),
            PXTA_ZERO,
            _u16(2),
            _u32(MAX_ENVELOPE_BYTES),
            _u16(PROFILE_VERSION),
            _u16(1),
            _u64(MAX_LIFECYCLE_NANOS),
            _u16(MAX_ENDPOINT_BYTES),
            ENDPOINT_PREFIX.encode("ascii"),
            PXTE_DIGEST_DOMAIN,
            COMPOSITE_DIGEST_DOMAIN,
            PROJECTION_MAGIC,
            _u16(PROJECTION_VERSION),
            TERMINAL_MAGIC,
            _u16(TERMINAL_VERSION),
            _u16(TERMINAL_FIELD_COUNT),
            _u32(MAX_TERMINAL_BYTES),
            _u16(1),
            _u16(MAX_TERMINAL_SIGNATURE_BYTES),
            TERMINAL_SIGNING_DOMAIN,
            TERMINAL_DIGEST_DOMAIN,
            TERMINAL_RESULT_REF_DOMAIN,
        ],
    )


def _encode_projection(value: dict[str, str]) -> bytes:
    wire = (
        PROJECTION_MAGIC
        + _u16(PROJECTION_VERSION)
        + _hex(value["manifest_digest_hex"])
        + _hex(value["target_hex"])
        + _hex(value["build_instance_id_hex"])
        + _hex(value["build_descriptor_digest_hex"])
        + _hex(value["runtime_artifact_sha256_hex"])
        + _compatibility_digest()
        + _u16(PXAR_VERSION)
        + _u16(PROFILE_VERSION)
    )
    assert len(wire) == PROJECTION_BYTES
    _decode_projection(wire)
    return wire


def _decode_projection(wire: bytes) -> dict[str, bytes]:
    if len(wire) > PROJECTION_BYTES:
        raise ContractReject(ERROR["frame_too_large"])
    if len(wire) < PROJECTION_BYTES:
        raise ContractReject(ERROR["truncated"])
    if wire[:4] != PROJECTION_MAGIC:
        raise ContractReject(ERROR["invalid_magic"])
    if struct.unpack_from(">H", wire, 4)[0] != PROJECTION_VERSION:
        raise ContractReject(ERROR["unsupported_version"])
    if struct.unpack_from(">H", wire, 182)[0] != PXAR_VERSION:
        raise ContractReject(ERROR["unsupported_version"], 7)
    if struct.unpack_from(">H", wire, 184)[0] != PROFILE_VERSION:
        raise ContractReject(ERROR["unsupported_version"], 8)
    if (
        wire[6:38] == bytes(32)
        or wire[54:86] == bytes(32)
        or wire[86:118] == bytes(32)
        or wire[118:150] == bytes(32)
        or wire[150:182] != _compatibility_digest()
    ):
        raise ContractReject(ERROR["compatibility_mismatch"])
    canonical = wire[:150] + _compatibility_digest() + _u16(PXAR_VERSION) + _u16(PROFILE_VERSION)
    if canonical != wire:
        raise ContractReject(ERROR["compatibility_mismatch"])
    return {
        "manifest_digest": wire[6:38],
        "target": wire[38:54],
        "build_instance_id": wire[54:86],
        "build_descriptor_digest": wire[86:118],
        "runtime_artifact_sha256": wire[118:150],
        "compatibility_digest": wire[150:182],
        "wire": wire,
    }


def _validate_endpoint(value: str) -> None:
    matched = ENDPOINT_RE.fullmatch(value)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ContractReject(ERROR["invalid_field_value"], 12) from error
    if matched is None or len(encoded) > MAX_ENDPOINT_BYTES:
        raise ContractReject(ERROR["invalid_field_value"], 12)
    port_text = matched.group(1)
    port = int(port_text)
    if not 1 <= port <= 65_535 or f"{ENDPOINT_PREFIX}{port}" != value:
        raise ContractReject(ERROR["invalid_field_value"], 12)


def _encode_pxte(projection: bytes, mode: int, service: dict[str, Any] | None) -> bytes:
    _decode_projection(projection)
    wire = bytearray(PXTE_MAGIC + _u16(PXTE_VERSION) + projection + _u16(PROFILE_VERSION))
    wire += _u8(mode) + _u8(service is not None)
    if service is not None:
        endpoint = service["listen_endpoint"].encode("ascii")
        _validate_endpoint(service["listen_endpoint"])
        budgets = [
            service["prepare_budget_nanos"],
            service["start_budget_nanos"],
            service["readiness_budget_nanos"],
            service["drain_budget_nanos"],
            service["stop_budget_nanos"],
        ]
        wire += _u16(1) + _hex(service["service_id_hex"])
        wire += b"".join(_u64(value) for value in budgets)
        wire += _u16(len(endpoint)) + endpoint
    encoded = bytes(wire)
    _decode_pxte(encoded)
    return encoded


def _decode_pxte(wire: bytes) -> dict[str, Any]:
    if len(wire) > PXTE_MAX_BYTES:
        raise ContractReject(ERROR["frame_too_large"])
    if len(wire) < PXTE_FIXED_BYTES:
        raise ContractReject(ERROR["truncated"])
    if wire[:4] != PXTE_MAGIC:
        raise ContractReject(ERROR["invalid_magic"])
    if struct.unpack_from(">H", wire, 4)[0] != PXTE_VERSION:
        raise ContractReject(ERROR["unsupported_version"])
    projection = _decode_projection(wire[6 : 6 + PROJECTION_BYTES])
    profile, mode, present = struct.unpack_from(">HBB", wire, 6 + PROJECTION_BYTES)
    if profile != PROFILE_VERSION:
        raise ContractReject(ERROR["unsupported_version"], 2)
    if mode not in {MODE_ONE_SERVICE, MODE_EMPTY}:
        raise ContractReject(ERROR["unsupported_shape"], 3)
    payload = wire[PXTE_FIXED_BYTES:]
    if mode == MODE_EMPTY:
        if present != 0:
            raise ContractReject(ERROR["invalid_presence"], 4)
        if payload:
            raise ContractReject(ERROR["trailing_bytes"])
        service = None
    else:
        if present != 1:
            raise ContractReject(ERROR["invalid_presence"], 4)
        if len(payload) < SERVICE_FIXED_BYTES:
            raise ContractReject(ERROR["truncated"])
        if struct.unpack_from(">H", payload, 0)[0] != 1:
            raise ContractReject(ERROR["unsupported_version"], 5)
        if payload[2:18] == bytes(16):
            raise ContractReject(ERROR["invalid_field_value"], 6)
        budgets = struct.unpack_from(">QQQQQ", payload, 18)
        for offset, value in enumerate(budgets, start=7):
            if not 0 < value <= MAX_LIFECYCLE_NANOS:
                raise ContractReject(ERROR["invalid_field_value"], offset)
        endpoint_length = struct.unpack_from(">H", payload, 58)[0]
        if not 0 < endpoint_length <= MAX_ENDPOINT_BYTES:
            raise ContractReject(ERROR["invalid_field_length"], 12)
        expected = SERVICE_FIXED_BYTES + endpoint_length
        if len(payload) < expected:
            raise ContractReject(ERROR["truncated"])
        if len(payload) > expected:
            raise ContractReject(ERROR["trailing_bytes"])
        try:
            endpoint = payload[60:].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ContractReject(ERROR["invalid_field_value"], 12) from error
        _validate_endpoint(endpoint)
        service = {
            "service_id": payload[2:18],
            "budgets": budgets,
            "listen_endpoint": endpoint,
        }
    return {"projection": projection, "mode": mode, "service": service, "wire": wire}


def _pxta_digest() -> bytes:
    return _digest(PXTA_DIGEST_DOMAIN, [PXTA_ZERO])


def _pxte_digest(wire: bytes) -> bytes:
    _decode_pxte(wire)
    return _digest(PXTE_DIGEST_DOMAIN, [wire])


def _composite_digest(wire: bytes) -> bytes:
    return _digest(COMPOSITE_DIGEST_DOMAIN, [_pxta_digest(), _pxte_digest(wire)])


def _encode_pxar(envelope: bytes, pxte: bytes) -> bytes:
    LEGACY._decode_envelope(envelope)
    _decode_pxte(pxte)
    wire = (
        PXAR_MAGIC
        + _u16(PXAR_VERSION)
        + _u32(len(envelope))
        + _u32(len(PXTA_ZERO))
        + _u32(len(pxte))
        + envelope
        + PXTA_ZERO
        + pxte
    )
    _decode_pxar(wire)
    return wire


def _decode_pxar(wire: bytes) -> dict[str, Any]:
    maximum = PXAR_HEADER_BYTES + MAX_ENVELOPE_BYTES + len(PXTA_ZERO) + PXTE_MAX_BYTES
    if len(wire) > maximum:
        raise ContractReject(ERROR["frame_too_large"])
    if len(wire) < PXAR_HEADER_BYTES:
        raise ContractReject(ERROR["truncated"])
    if wire[:4] != PXAR_MAGIC:
        raise ContractReject(ERROR["invalid_magic"])
    version, envelope_length, binding_length, execution_length = struct.unpack_from(
        ">HIII", wire, 4
    )
    if version != PXAR_VERSION:
        raise ContractReject(ERROR["unsupported_version"])
    if envelope_length > MAX_ENVELOPE_BYTES:
        raise ContractReject(ERROR["frame_too_large"], 1)
    if binding_length != len(PXTA_ZERO):
        raise ContractReject(ERROR["binding_not_allowed"], 2)
    if execution_length > PXTE_MAX_BYTES:
        raise ContractReject(ERROR["frame_too_large"], 3)
    expected = PXAR_HEADER_BYTES + envelope_length + binding_length + execution_length
    if len(wire) < expected:
        raise ContractReject(ERROR["truncated"])
    if len(wire) > expected:
        raise ContractReject(ERROR["trailing_bytes"])
    envelope_end = PXAR_HEADER_BYTES + envelope_length
    binding_end = envelope_end + binding_length
    envelope_wire = wire[PXAR_HEADER_BYTES:envelope_end]
    binding_wire = wire[envelope_end:binding_end]
    execution_wire = wire[binding_end:]
    try:
        envelope = LEGACY._decode_envelope(envelope_wire)
    except LEGACY.ContractReject as error:
        raise ContractReject(error.code, error.detail_code) from error
    if binding_wire != PXTA_ZERO:
        raise ContractReject(ERROR["binding_not_allowed"], 2)
    execution = _decode_pxte(execution_wire)
    if envelope[2] != execution["projection"]["target"]:
        raise ContractReject(ERROR["target_mismatch"], 2)
    composite = _composite_digest(execution_wire)
    if envelope[7] != composite:
        raise ContractReject(ERROR["digest_mismatch"], 7)
    return {
        "envelope": envelope,
        "execution": execution,
        "composite_digest": composite,
        "wire": wire,
    }


def _terminal_result_ref(request: dict[str, Any]) -> bytes:
    envelope = request["envelope"]
    digest = _digest(
        TERMINAL_RESULT_REF_DOMAIN,
        [
            TERMINAL_MAGIC,
            _u16(TERMINAL_VERSION),
            envelope[2],
            envelope[32],
            envelope[3],
            envelope[24],
            _digest(LEGACY.REQUEST_DIGEST_DOMAIN, [request["envelope_wire"]]),
        ],
    )
    assert digest[:16] != bytes(16)
    return digest[:16]


def _terminal_head(facts: dict[str, Any]) -> tuple[int, bytes]:
    disposition = facts["head_disposition"]
    digest = facts.get("desired_head_digest", bytes(32))
    if disposition == 1 and digest == bytes(32):
        return disposition, digest
    if disposition in {2, 3} and digest != bytes(32):
        return disposition, digest
    raise ContractReject(ERROR["invalid_field_value"], 14)


def _validate_terminal_facts(request: dict[str, Any], facts: dict[str, Any]) -> None:
    outcome = facts["outcome"]
    lifecycle = facts["lifecycle_effect"]
    disposition, desired_head = _terminal_head(facts)
    generation = facts["generation"]
    has_generation = generation is not None and generation > 0
    general = {
        1: has_generation and lifecycle == 2 and disposition == 3,
        2: generation is None and lifecycle in {1, 2} and disposition == 3,
        3: generation is None and lifecycle == 1 and disposition != 3,
        4: has_generation and lifecycle == 2,
        5: has_generation and lifecycle == 2 and disposition == 3,
    }
    if not general.get(outcome, False):
        raise ContractReject(ERROR["invalid_field_value"], 12)
    mode = request["execution"]["mode"]
    if outcome in {1, 5} and mode != MODE_ONE_SERVICE:
        raise ContractReject(ERROR["cross_reference_mismatch"], 12)
    if outcome == 2 and mode != MODE_EMPTY:
        raise ContractReject(ERROR["cross_reference_mismatch"], 12)
    incoming = request["envelope"][8]
    expected_tag = struct.unpack(">H", request["envelope"][22])[0]
    expected_digest = request["envelope"][23]
    preserves_expected = (disposition == 1 and expected_tag == 0) or (
        disposition == 2 and expected_tag == 1 and desired_head == expected_digest
    )
    committed = disposition == 3 and desired_head == incoming
    if outcome in {1, 2, 5} and not committed:
        raise ContractReject(ERROR["cross_reference_mismatch"], 12)
    if outcome == 4 and not (committed or preserves_expected):
        raise ContractReject(ERROR["cross_reference_mismatch"], 12)
    if (
        facts["resource_census_digest"] == bytes(32)
        or facts["raw_outcome_digest"] == bytes(32)
        or facts["completion_runtime_host_epoch"] == 0
        or facts["completion_snapshot_sequence"] == 0
        or facts["selection_clock_generation"] < struct.unpack(">Q", request["envelope"][29])[0]
        or facts["selection_observed_at_nanos"] == 0
    ):
        raise ContractReject(ERROR["invalid_field_value"], 18)


def _terminal_fields(
    request: dict[str, Any],
    facts: dict[str, Any],
    channel: dict[str, bytes],
    signature: bytes | None,
) -> list[tuple[int, bytes]]:
    _validate_terminal_facts(request, facts)
    envelope = request["envelope"]
    generation = facts["generation"]
    fields = [
        (1, envelope[2]),
        (2, envelope[32]),
        (3, envelope[3]),
        (4, envelope[4]),
        (5, envelope[5]),
        (6, envelope[6]),
        (7, envelope[24]),
        (8, _digest(LEGACY.REQUEST_DIGEST_DOMAIN, [request["envelope_wire"]])),
        (9, envelope[37]),
        (10, envelope[8]),
        (11, envelope[7]),
        (12, _u16(facts["outcome"])),
        (13, _u16(facts["lifecycle_effect"])),
        (14, _u16(facts["head_disposition"])),
        (15, facts["desired_head_digest"]),
        (16, _u8(generation is not None)),
        (17, _u64(0 if generation is None else generation)),
        (18, facts["resource_census_digest"]),
        (19, facts["raw_outcome_digest"]),
        (20, _u64(facts["completion_runtime_host_epoch"])),
        (21, _u64(facts["completion_snapshot_sequence"])),
        (22, _u64(facts["selection_clock_generation"])),
        (23, _u64(facts["selection_observed_at_nanos"])),
        (24, _terminal_result_ref(request)),
        (25, channel["runtime_peer"]),
        (26, channel["binding_digest"]),
        (27, bytes.fromhex("e2" * 16)),
        (28, _u16(1)),
        (29, _u16(1)),
    ]
    if signature is not None:
        fields.append((30, signature))
    return fields


def _encode_terminal_receipt(
    request_wire: bytes, facts: dict[str, Any], channel: dict[str, bytes]
) -> dict[str, bytes]:
    request = _decode_pxar(request_wire)
    request["envelope_wire"] = request_wire[
        PXAR_HEADER_BYTES : PXAR_HEADER_BYTES + struct.unpack_from(">I", request_wire, 6)[0]
    ]
    unsigned = _terminal_fields(request, facts, channel, None)
    transcript = LEGACY._signing_transcript(1, TERMINAL_SIGNING_DOMAIN, unsigned)
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("44" * 32))
    signature = private_key.sign(transcript)
    fields = _terminal_fields(request, facts, channel, signature)
    wire = (
        TERMINAL_MAGIC
        + _u16(TERMINAL_VERSION)
        + _u16(len(fields))
        + b"".join(LEGACY._tlv(tag, value) for tag, value in fields)
    )
    decoded = _decode_terminal_receipt(wire)
    _validate_terminal_against_request(decoded, request_wire, channel)
    public_key = private_key.public_key().public_bytes_raw()
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, transcript)
    return {
        "wire": wire,
        "receipt_digest": _digest(TERMINAL_DIGEST_DOMAIN, [wire]),
        "signing_transcript": transcript,
        "signature": signature,
        "public_key": public_key,
    }


def _valid_terminal_length(tag: int, length: int) -> bool:
    if tag in {1, 3, 4, 7, 24, 25, 27}:
        return length == 16
    if tag in {2, 6, 8, 10, 11, 15, 18, 19, 26}:
        return length == 32
    if tag in {5, 17, 20, 21, 22, 23}:
        return length == 8
    if tag == 9:
        return 1 <= length <= 64
    if tag in {12, 13, 14, 28, 29}:
        return length == 2
    if tag == 16:
        return length == 1
    if tag == 30:
        return 1 <= length <= MAX_TERMINAL_SIGNATURE_BYTES
    return False


def _parse_terminal_fields(wire: bytes) -> dict[int, bytes]:
    if len(wire) > MAX_TERMINAL_BYTES:
        raise ContractReject(ERROR["frame_too_large"])
    if len(wire) < 8:
        raise ContractReject(ERROR["truncated"])
    if wire[:4] != TERMINAL_MAGIC:
        raise ContractReject(ERROR["invalid_magic"])
    version, count = struct.unpack_from(">HH", wire, 4)
    if version != TERMINAL_VERSION:
        raise ContractReject(ERROR["unsupported_version"])
    if count < TERMINAL_FIELD_COUNT:
        raise ContractReject(8, count + 1)
    if count > TERMINAL_FIELD_COUNT:
        raise ContractReject(5, TERMINAL_FIELD_COUNT + 1)
    cursor = 8
    values: dict[int, bytes] = {}
    for expected_tag in range(1, count + 1):
        if cursor + 6 > len(wire):
            raise ContractReject(ERROR["truncated"])
        tag, length = struct.unpack_from(">HI", wire, cursor)
        cursor += 6
        if tag == 0 or tag > TERMINAL_FIELD_COUNT:
            raise ContractReject(5, tag)
        if tag < expected_tag:
            raise ContractReject(6, tag)
        if tag > expected_tag:
            raise ContractReject(7, tag)
        if not _valid_terminal_length(tag, length):
            raise ContractReject(ERROR["invalid_field_length"], tag)
        end = cursor + length
        if end > len(wire):
            raise ContractReject(ERROR["truncated"], tag)
        values[tag] = wire[cursor:end]
        cursor = end
    if cursor != len(wire):
        raise ContractReject(ERROR["trailing_bytes"])
    return values


def _decode_terminal_receipt(wire: bytes) -> dict[str, Any]:
    values = _parse_terminal_fields(wire)
    if values[2] == bytes(32):
        raise ContractReject(ERROR["invalid_field_value"], 2)
    for tag in (6, 8, 10, 11, 18, 19, 26):
        if values[tag] == bytes(32):
            raise ContractReject(ERROR["invalid_field_value"], tag)
    outcome, lifecycle, disposition = struct.unpack(">HHH", values[12] + values[13] + values[14])
    generation_presence = values[16][0]
    generation_value = struct.unpack(">Q", values[17])[0]
    if (generation_presence, generation_value) == (0, 0):
        generation = None
    elif generation_presence == 1 and generation_value > 0:
        generation = generation_value
    else:
        raise ContractReject(23, 16)
    facts = {
        "outcome": outcome,
        "lifecycle_effect": lifecycle,
        "head_disposition": disposition,
        "desired_head_digest": values[15],
        "generation": generation,
        "resource_census_digest": values[18],
        "raw_outcome_digest": values[19],
        "completion_runtime_host_epoch": struct.unpack(">Q", values[20])[0],
        "completion_snapshot_sequence": struct.unpack(">Q", values[21])[0],
        "selection_clock_generation": struct.unpack(">Q", values[22])[0],
        "selection_observed_at_nanos": struct.unpack(">Q", values[23])[0],
    }
    general_request = {
        "execution": {"mode": MODE_ONE_SERVICE if outcome != 2 else MODE_EMPTY},
        "envelope": {
            8: values[10],
            22: _u16(0 if disposition == 1 else 1),
            23: values[15],
            29: values[22],
        },
    }
    if outcome in {1, 2, 5}:
        general_request["envelope"][8] = values[15]
    _validate_terminal_facts(general_request, facts)
    if any(struct.unpack(">Q", values[tag])[0] == 0 for tag in (20, 21, 22, 23)):
        raise ContractReject(ERROR["invalid_field_value"], 20)
    expected_ref = _digest(
        TERMINAL_RESULT_REF_DOMAIN,
        [
            TERMINAL_MAGIC,
            _u16(TERMINAL_VERSION),
            values[1],
            values[2],
            values[3],
            values[7],
            values[8],
        ],
    )[:16]
    if values[24] != expected_ref:
        raise ContractReject(ERROR["digest_mismatch"], 24)
    if struct.unpack(">H", values[28])[0] == 0:
        raise ContractReject(ERROR["invalid_field_value"], 28)
    if struct.unpack(">H", values[29])[0] == 0:
        raise ContractReject(ERROR["invalid_field_value"], 29)
    canonical = (
        TERMINAL_MAGIC
        + _u16(TERMINAL_VERSION)
        + _u16(TERMINAL_FIELD_COUNT)
        + b"".join(LEGACY._tlv(tag, values[tag]) for tag in range(1, TERMINAL_FIELD_COUNT + 1))
    )
    if canonical != wire:
        raise ContractReject(11)
    return {"values": values, "facts": facts, "wire": wire}


def _validate_terminal_against_request(
    receipt: dict[str, Any], request_wire: bytes, channel: dict[str, bytes]
) -> None:
    request = _decode_pxar(request_wire)
    envelope_length = struct.unpack_from(">I", request_wire, 6)[0]
    request["envelope_wire"] = request_wire[PXAR_HEADER_BYTES : PXAR_HEADER_BYTES + envelope_length]
    values = receipt["values"]
    envelope = request["envelope"]
    expected = {
        1: envelope[2],
        2: envelope[32],
        3: envelope[3],
        4: envelope[4],
        5: envelope[5],
        6: envelope[6],
        7: envelope[24],
        8: _digest(LEGACY.REQUEST_DIGEST_DOMAIN, [request["envelope_wire"]]),
        9: envelope[37],
        10: envelope[8],
        11: envelope[7],
        25: channel["runtime_peer"],
        26: channel["binding_digest"],
    }
    for tag, value in expected.items():
        if values[tag] != value:
            raise ContractReject(
                ERROR["target_mismatch"]
                if tag in {1, 25, 26}
                else ERROR["cross_reference_mismatch"],
                tag,
            )
    _validate_terminal_facts(request, receipt["facts"])


def _verify_terminal_signature(receipt: dict[str, Any], public_key: bytes) -> None:
    values = receipt["values"]
    transcript = LEGACY._signing_transcript(
        1, TERMINAL_SIGNING_DOMAIN, [(tag, values[tag]) for tag in range(1, 30)]
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(values[30], transcript)
    except (InvalidSignature, ValueError) as error:
        raise ContractReject(22, 30) from error


def _build_vectors() -> dict[str, Any]:
    projection = _encode_projection(SEMANTIC["projection"])
    one_pxte = _encode_pxte(projection, MODE_ONE_SERVICE, SEMANTIC["service"])
    one_envelope = LEGACY._build_envelope(
        _composite_digest(one_pxte),
        source_revision=3,
        operation_byte="0d",
        temporal_byte="0e",
        auth_nonce=b"test-only-managed-fabric-one",
    )
    one_outer = _encode_pxar(one_envelope["wire"], one_pxte)
    empty_pxte = _encode_pxte(projection, MODE_EMPTY, None)
    empty_envelope = LEGACY._build_envelope(
        _composite_digest(empty_pxte),
        source_revision=4,
        operation_byte="0f",
        temporal_byte="10",
        auth_nonce=b"test-only-managed-fabric-empty",
        expected_active_digest=one_envelope["target_slice_digest"],
    )
    empty_outer = _encode_pxar(empty_envelope["wire"], empty_pxte)
    channel = LEGACY._channel_binding(
        target=bytes.fromhex("05" * 16),
        runtime_peer=bytes.fromhex("e1" * 16),
        local_endpoint_identity_digest=bytes.fromhex("e3" * 32),
        peer_credentials_digest=bytes.fromhex("e4" * 32),
    )
    active_terminal = _encode_terminal_receipt(
        one_outer,
        {
            "outcome": 1,
            "lifecycle_effect": 2,
            "head_disposition": 3,
            "desired_head_digest": one_envelope["target_slice_digest"],
            "generation": 7,
            "resource_census_digest": bytes.fromhex("c1" * 32),
            "raw_outcome_digest": bytes.fromhex("c2" * 32),
            "completion_runtime_host_epoch": 5,
            "completion_snapshot_sequence": 6,
            "selection_clock_generation": 3,
            "selection_observed_at_nanos": 200,
        },
        channel,
    )
    empty_terminal = _encode_terminal_receipt(
        empty_outer,
        {
            "outcome": 2,
            "lifecycle_effect": 2,
            "head_disposition": 3,
            "desired_head_digest": empty_envelope["target_slice_digest"],
            "generation": None,
            "resource_census_digest": bytes.fromhex("c3" * 32),
            "raw_outcome_digest": bytes.fromhex("c4" * 32),
            "completion_runtime_host_epoch": 5,
            "completion_snapshot_sequence": 7,
            "selection_clock_generation": 3,
            "selection_observed_at_nanos": 201,
        },
        channel,
    )
    return {
        "projection": projection,
        "one": {
            "pxte": one_pxte,
            "pxte_digest": _pxte_digest(one_pxte),
            "composite_digest": _composite_digest(one_pxte),
            "envelope": one_envelope,
            "outer": one_outer,
        },
        "empty": {
            "pxte": empty_pxte,
            "pxte_digest": _pxte_digest(empty_pxte),
            "composite_digest": _composite_digest(empty_pxte),
            "envelope": empty_envelope,
            "outer": empty_outer,
        },
        "channel": channel,
        "active_terminal": active_terminal,
        "empty_terminal": empty_terminal,
    }


def _expected_vector(vector: dict[str, Any]) -> dict[str, Any]:
    envelope = vector["envelope"]
    return {
        "pxte_v5_hex": vector["pxte"].hex(),
        "pxte_v5_length": len(vector["pxte"]),
        "pxte_v5_digest_hex": vector["pxte_digest"].hex(),
        "composite_v6_digest_hex": vector["composite_digest"].hex(),
        "target_slice_digest_hex": envelope["target_slice_digest"].hex(),
        "control_digest_hex": envelope["control_digest"].hex(),
        "signing_transcript_sha256_hex": hashlib.sha256(envelope["signing_transcript"]).hexdigest(),
        "signing_transcript_length": len(envelope["signing_transcript"]),
        "request_digest_hex": envelope["request_digest"].hex(),
        "envelope_v2_length": len(envelope["wire"]),
        "outer_v6_hex": vector["outer"].hex(),
        "outer_v6_length": len(vector["outer"]),
    }


def _expected_terminal(vector: dict[str, bytes]) -> dict[str, Any]:
    return {
        "wire_hex": vector["wire"].hex(),
        "wire_length": len(vector["wire"]),
        "receipt_digest_hex": vector["receipt_digest"].hex(),
        "signature_hex": vector["signature"].hex(),
        "public_key_hex": vector["public_key"].hex(),
        "signing_transcript_sha256_hex": hashlib.sha256(vector["signing_transcript"]).hexdigest(),
        "signing_transcript_length": len(vector["signing_transcript"]),
    }


def _generated_fixture() -> dict[str, Any]:
    vectors = _build_vectors()
    return {
        "format": "paraegox-s7-managed-fabric-successor-v1",
        "versions": {
            "projection": PROJECTION_VERSION,
            "profile": PROFILE_VERSION,
            "pxte": PXTE_VERSION,
            "pxar": PXAR_VERSION,
            "envelope": 2,
            "pxft": TERMINAL_VERSION,
        },
        "semantic": SEMANTIC,
        "expected": {
            "compatibility_digest_hex": _compatibility_digest().hex(),
            "projection_hex": vectors["projection"].hex(),
            "projection_length": len(vectors["projection"]),
            "pxta_zero_hex": PXTA_ZERO.hex(),
            "pxta_digest_hex": _pxta_digest().hex(),
            "one_managed_fabric_service": _expected_vector(vectors["one"]),
            "empty_deactivate": _expected_vector(vectors["empty"]),
            "terminal": {
                "channel_binding_digest_hex": vectors["channel"]["binding_digest"].hex(),
                "active_ready": _expected_terminal(vectors["active_terminal"]),
                "empty_exact_zero": _expected_terminal(vectors["empty_terminal"]),
            },
        },
        "invalid_precedence": [
            {"name": "outer_frame_too_large", "code": 1, "detail": None},
            {"name": "outer_truncated", "code": 2, "detail": None},
            {"name": "outer_magic_before_version", "code": 3, "detail": None},
            {"name": "outer_version_before_lengths", "code": 4, "detail": None},
            {"name": "outer_binding_length_before_body", "code": 15, "detail": 2},
            {"name": "outer_execution_bound_before_total", "code": 1, "detail": 3},
            {"name": "outer_declared_truncated", "code": 2, "detail": None},
            {"name": "outer_trailing", "code": 21, "detail": None},
            {"name": "nested_envelope_before_pxta", "code": 3, "detail": None},
            {"name": "pxta_before_pxte", "code": 15, "detail": 2},
            {"name": "pxte_magic_before_profile", "code": 3, "detail": None},
            {"name": "pxte_version_before_projection", "code": 4, "detail": None},
            {"name": "pxte_presence_before_payload", "code": 23, "detail": 4},
            {"name": "pxte_service_id_before_budget", "code": 10, "detail": 6},
            {"name": "pxte_budget_before_endpoint", "code": 10, "detail": 7},
            {"name": "pxte_endpoint_before_commitment", "code": 10, "detail": 12},
            {"name": "target_before_assignment_digest", "code": 17, "detail": 2},
            {"name": "assignment_digest_after_valid_pxte", "code": 12, "detail": 7},
        ],
        "legacy_reference_fixture_sha256": hashlib.sha256(
            LEGACY_FIXTURE_PATH.read_bytes()
        ).hexdigest(),
    }


def _outer_offsets(wire: bytes) -> tuple[int, int, int]:
    envelope_length, binding_length, _ = struct.unpack_from(">III", wire, 6)
    envelope_start = PXAR_HEADER_BYTES
    binding_start = envelope_start + envelope_length
    pxte_start = binding_start + binding_length
    return envelope_start, binding_start, pxte_start


def _invalid_wire(name: str, base: bytes) -> bytes:
    wire = bytearray(base)
    envelope_start, binding_start, pxte_start = _outer_offsets(base)
    profile_offset = pxte_start + 6 + PROJECTION_BYTES
    service_offset = pxte_start + PXTE_FIXED_BYTES
    if name == "outer_frame_too_large":
        return base + bytes(
            PXAR_HEADER_BYTES + MAX_ENVELOPE_BYTES + len(PXTA_ZERO) + PXTE_MAX_BYTES + 1 - len(base)
        )
    if name == "outer_truncated":
        return base[:17]
    if name == "outer_magic_before_version":
        wire[0] ^= 1
        wire[4:6] = _u16(99)
    elif name == "outer_version_before_lengths":
        wire[4:6] = _u16(99)
        wire[10:14] = _u32(9)
    elif name == "outer_binding_length_before_body":
        wire[10:14] = _u32(9)
        wire[envelope_start] ^= 1
    elif name == "outer_execution_bound_before_total":
        wire[14:18] = _u32(PXTE_MAX_BYTES + 1)
    elif name == "outer_declared_truncated":
        wire[6:10] = _u32(struct.unpack_from(">I", wire, 6)[0] + 1)
    elif name == "outer_trailing":
        return base + b"\x00"
    elif name == "nested_envelope_before_pxta":
        wire[envelope_start] ^= 1
        wire[binding_start] ^= 1
    elif name == "pxta_before_pxte":
        wire[binding_start] ^= 1
        wire[pxte_start] ^= 1
    elif name == "pxte_magic_before_profile":
        wire[pxte_start] ^= 1
        wire[profile_offset : profile_offset + 2] = _u16(99)
    elif name == "pxte_version_before_projection":
        wire[pxte_start + 4 : pxte_start + 6] = _u16(99)
        wire[pxte_start + 6] ^= 1
    elif name == "pxte_presence_before_payload":
        wire[profile_offset + 3] = 0
    elif name == "pxte_service_id_before_budget":
        wire[service_offset + 2 : service_offset + 18] = bytes(16)
        wire[service_offset + 18 : service_offset + 26] = bytes(8)
    elif name == "pxte_budget_before_endpoint":
        wire[service_offset + 18 : service_offset + 26] = bytes(8)
        wire[-1] = ord("x")
    elif name == "pxte_endpoint_before_commitment":
        endpoint_start = service_offset + SERVICE_FIXED_BYTES
        wire[endpoint_start + len(ENDPOINT_PREFIX)] = ord("0")
    elif name == "target_before_assignment_digest":
        wire[pxte_start + 6 + 38] ^= 1
    elif name == "assignment_digest_after_valid_pxte":
        endpoint_start = service_offset + SERVICE_FIXED_BYTES
        wire[endpoint_start + len(ENDPOINT_PREFIX) + 3] = ord("8")
    else:
        raise AssertionError(f"unknown invalid mutation: {name}")
    return bytes(wire)


def _assert_reject(
    decoder: Callable[[bytes], Any], wire: bytes, code: int, detail: int | None
) -> None:
    with pytest.raises(ContractReject) as rejected:
        decoder(wire)
    assert (rejected.value.code, rejected.value.detail) == (code, detail)


def test_independent_oracle_matches_checked_in_golden() -> None:
    assert json.loads(FIXTURE_PATH.read_text()) == _generated_fixture()


def test_projection_pxte_and_pxar_roundtrip_exact_canonical_bytes() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())
    expected = fixture["expected"]
    projection = bytes.fromhex(expected["projection_hex"])
    assert _decode_projection(projection)["wire"] == projection
    for name in ("one_managed_fabric_service", "empty_deactivate"):
        vector = expected[name]
        pxte = bytes.fromhex(vector["pxte_v5_hex"])
        outer = bytes.fromhex(vector["outer_v6_hex"])
        assert _decode_pxte(pxte)["wire"] == pxte
        assert _decode_pxar(outer)["wire"] == outer


def test_pxft_terminal_golden_roundtrip_signature_and_request_channel_correlation() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())
    expected = fixture["expected"]
    channel = LEGACY._channel_binding(
        target=bytes.fromhex("05" * 16),
        runtime_peer=bytes.fromhex("e1" * 16),
        local_endpoint_identity_digest=bytes.fromhex("e3" * 32),
        peer_credentials_digest=bytes.fromhex("e4" * 32),
    )
    pairs = (
        ("active_ready", "one_managed_fabric_service"),
        ("empty_exact_zero", "empty_deactivate"),
    )
    for terminal_name, request_name in pairs:
        vector = expected["terminal"][terminal_name]
        wire = bytes.fromhex(vector["wire_hex"])
        receipt = _decode_terminal_receipt(wire)
        request = bytes.fromhex(expected[request_name]["outer_v6_hex"])
        _validate_terminal_against_request(receipt, request, channel)
        _verify_terminal_signature(receipt, bytes.fromhex(vector["public_key_hex"]))
        assert _digest(TERMINAL_DIGEST_DOMAIN, [wire]).hex() == vector["receipt_digest_hex"]
        assert len(wire) == vector["wire_length"]


def test_pxft_terminal_strict_perturbations_and_wrong_correlation_fail_closed() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())
    expected = fixture["expected"]
    vector = expected["terminal"]["active_ready"]
    wire = bytes.fromhex(vector["wire_hex"])
    channel = LEGACY._channel_binding(
        target=bytes.fromhex("05" * 16),
        runtime_peer=bytes.fromhex("e1" * 16),
        local_endpoint_identity_digest=bytes.fromhex("e3" * 32),
        peer_credentials_digest=bytes.fromhex("e4" * 32),
    )

    bad = bytearray(wire)
    bad[0] ^= 1
    bad[4:6] = _u16(99)
    _assert_reject(_decode_terminal_receipt, bytes(bad), 3, None)
    bad = bytearray(wire)
    bad[4:6] = _u16(99)
    _assert_reject(_decode_terminal_receipt, bytes(bad), 4, None)
    bad = bytearray(wire)
    bad[6:8] = _u16(29)
    _assert_reject(_decode_terminal_receipt, bytes(bad), 8, 30)
    _assert_reject(_decode_terminal_receipt, wire + b"\x00", 21, None)

    receipt = _decode_terminal_receipt(wire)
    wrong_request = bytes.fromhex(expected["empty_deactivate"]["outer_v6_hex"])
    with pytest.raises(ContractReject):
        _validate_terminal_against_request(receipt, wrong_request, channel)
    wrong_channel = dict(channel)
    wrong_channel["binding_digest"] = bytes.fromhex("99" * 32)
    with pytest.raises(ContractReject) as rejected:
        _validate_terminal_against_request(
            receipt,
            bytes.fromhex(expected["one_managed_fabric_service"]["outer_v6_hex"]),
            wrong_channel,
        )
    assert (rejected.value.code, rejected.value.detail) == (17, 26)

    wrong_signature = bytearray(wire)
    wrong_signature[-1] ^= 1
    decoded = _decode_terminal_receipt(bytes(wrong_signature))
    with pytest.raises(ContractReject) as rejected:
        _verify_terminal_signature(decoded, bytes.fromhex(vector["public_key_hex"]))
    assert (rejected.value.code, rejected.value.detail) == (22, 30)

    _assert_reject(_decode_terminal_receipt, b"PXRT\x00\x01\x00\x17", 3, None)


def test_empty_exact_zero_effect_free_paths_and_invalid_shapes() -> None:
    incoming = bytes.fromhex("41" * 32)
    facts = {
        "outcome": 2,
        "lifecycle_effect": 1,
        "head_disposition": 3,
        "desired_head_digest": incoming,
        "generation": None,
        "resource_census_digest": bytes.fromhex("42" * 32),
        "raw_outcome_digest": bytes.fromhex("43" * 32),
        "completion_runtime_host_epoch": 1,
        "completion_snapshot_sequence": 1,
        "selection_clock_generation": 3,
        "selection_observed_at_nanos": 1,
    }
    for expected_presence, expected_digest in (
        (0, bytes(32)),
        (1, incoming),
    ):
        request = {
            "execution": {"mode": MODE_EMPTY},
            "envelope": {
                8: incoming,
                22: _u16(expected_presence),
                23: expected_digest,
                29: _u64(3),
            },
        }
        _validate_terminal_facts(request, facts)

    no_effect_existing = {
        **facts,
        "outcome": 3,
        "head_disposition": 2,
        "desired_head_digest": bytes.fromhex("45" * 32),
    }
    _validate_terminal_facts(
        {
            "execution": {"mode": MODE_ONE_SERVICE},
            "envelope": {
                8: incoming,
                22: _u16(0),
                23: bytes(32),
                29: _u64(3),
            },
        },
        no_effect_existing,
    )
    no_effect_none = {
        **facts,
        "outcome": 3,
        "head_disposition": 1,
        "desired_head_digest": bytes(32),
    }
    _validate_terminal_facts(
        {
            "execution": {"mode": MODE_EMPTY},
            "envelope": {
                8: incoming,
                22: _u16(1),
                23: bytes.fromhex("46" * 32),
                29: _u64(3),
            },
        },
        no_effect_none,
    )

    for invalid in (
        {**facts, "generation": 1},
        {**facts, "outcome": 1},
        {
            **facts,
            "outcome": 3,
            "lifecycle_effect": 2,
            "head_disposition": 1,
            "desired_head_digest": bytes(32),
        },
        {
            **facts,
            "outcome": 3,
            "lifecycle_effect": 1,
            "head_disposition": 3,
        },
    ):
        with pytest.raises(ContractReject):
            _validate_terminal_facts(
                {
                    "execution": {"mode": MODE_EMPTY},
                    "envelope": {
                        8: incoming,
                        22: _u16(0),
                        23: bytes(32),
                        29: _u64(3),
                    },
                },
                invalid,
            )


def test_invalid_precedence_is_frozen() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())
    base = bytes.fromhex(fixture["expected"]["one_managed_fabric_service"]["outer_v6_hex"])
    for vector in fixture["invalid_precedence"]:
        _assert_reject(
            _decode_pxar,
            _invalid_wire(vector["name"], base),
            vector["code"],
            vector["detail"],
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "tcp/127.0.0.1:0",
        "tcp/127.0.0.1:07447",
        "tcp/127.0.0.1:65536",
        "tcp/0.0.0.0:7447",
        "tcp/localhost:7447",
        "tcp/[::1]:7447",
        "tcp/127.0.0.1:7447/key/route",
    ],
)
def test_endpoint_profile_rejects_implicit_or_route_bearing_values(endpoint: str) -> None:
    with pytest.raises(ContractReject) as rejected:
        _validate_endpoint(endpoint)
    assert (rejected.value.code, rejected.value.detail) == (ERROR["invalid_field_value"], 12)


def test_legacy_v4_v5_fixture_is_byte_identical() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())
    assert (
        hashlib.sha256(LEGACY_FIXTURE_PATH.read_bytes()).hexdigest()
        == fixture["legacy_reference_fixture_sha256"]
    )
    legacy = json.loads(LEGACY_FIXTURE_PATH.read_text())
    for name in ("one_source_loop", "empty_deactivate"):
        vector = legacy["expected"][name]
        assert bytes.fromhex(vector["pxte_v4_body_hex"])[4:6] == _u16(4)
        assert bytes.fromhex(vector["outer_v5_hex"])[4:6] == _u16(5)
