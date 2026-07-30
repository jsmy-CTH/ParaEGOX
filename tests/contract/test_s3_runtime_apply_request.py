from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wire" / "s3_runtime_apply_request_v1.json"

DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
DIGEST_VERSION = 1
DIGEST_FIELD_MARKER = b"\x01"
DIGEST_END_MARKER = b"\xff"
SIGNING_MAGIC = b"ParaEGOX\0canonical-signing-transcript"

ASSIGNMENT_MAGIC = b"PXTA"
ASSIGNMENT_VERSION = 1
ASSIGNMENT_HEADER_BYTES = 10
ASSIGNMENT_RECORD_BYTES = 256
RECORD_SOURCE_ENDPOINT_OFFSET = 16
RECORD_TARGET_ENDPOINT_OFFSET = 103
RECORD_MAILBOX_OFFSET = 190
RECORD_MAX_PAYLOAD_OFFSET = 206
MAX_ASSIGNMENTS = 256
MAX_ASSIGNMENT_BYTES = ASSIGNMENT_HEADER_BYTES + MAX_ASSIGNMENTS * ASSIGNMENT_RECORD_BYTES
ASSIGNMENT_DIGEST_DOMAIN = b"paraegox.runtime.target-assignments.sha256.v1"

OUTER_MAGIC = b"PXAR"
OUTER_VERSION = 1
OUTER_HEADER_BYTES = 14
MAX_OUTER_BYTES = OUTER_HEADER_BYTES + 4096 + MAX_ASSIGNMENT_BYTES

S2_MAGIC = b"ParaEGOX\0runtime-apply-envelope"
S2_VERSION = 1
S2_FIELD_COUNT = 37
MAX_S2_BYTES = 4096
TENURE_SIGNING_DOMAIN = b"paraegox.runtime.writer-tenure.signing.v1"
AUTH_SIGNING_DOMAIN = b"paraegox.runtime.apply-envelope-auth.signing.v1"
TARGET_SLICE_DIGEST_DOMAIN = b"paraegox.runtime.target-slice.sha256.v1"
TENURE_PROOF_DIGEST_DOMAIN = b"paraegox.runtime.writer-tenure-proof.sha256.v1"
APPLY_CONTROL_DIGEST_DOMAIN = b"paraegox.runtime.apply-control.sha256.v1"
REQUEST_DIGEST_DOMAIN = b"paraegox.runtime.apply-envelope.request.sha256.v1"

ASSIGNMENT_ERROR_CODES = {
    "frame_too_large": 1,
    "truncated": 2,
    "invalid_magic": 3,
    "unsupported_version": 4,
    "assignment_count_exceeded": 5,
    "invalid_frame_length": 6,
    "invalid_enum_value": 7,
    "invalid_assignment": 8,
    "duplicate_binding_id": 9,
    "duplicate_source_endpoint": 10,
    "duplicate_target_endpoint": 11,
    "non_canonical_frame": 12,
    "duplicate_mailbox_ref": 13,
}

OUTER_ERROR_CODES = {
    "frame_too_large": 1,
    "truncated": 2,
    "invalid_magic": 3,
    "unsupported_version": 4,
    "invalid_frame_length": 5,
    "envelope_rejected": 6,
    "assignments_rejected": 7,
    "commitment_mismatch": 8,
}

S2_ERROR_CODES = {
    "frame_too_large": 1,
    "truncated": 2,
    "invalid_magic": 3,
    "unsupported_version": 4,
    "unknown_field": 5,
    "missing_field": 6,
    "duplicate_field": 7,
    "out_of_order_field": 8,
    "invalid_field_length": 9,
    "invalid_field_value": 10,
    "derived_digest_mismatch": 11,
    "non_canonical_frame": 12,
    "trailing_bytes": 13,
}

TEST_ONLY_KEYS = {
    "tenure_authority_seed_hex": "11" * 32,
    "request_writer_seed_hex": "22" * 32,
}


def _assignment(
    binding: str,
    source_instance: str,
    source_port: str,
    target_instance: str,
    target_port: str,
    mailbox: str,
) -> dict[str, Any]:
    return {
        "binding_id_hex": binding * 16,
        "source_instance_hex": source_instance * 16,
        "source_port_hex": source_port * 16,
        "source_direction": 1,
        "source_schema_id_hex": "21" * 16,
        "source_schema_version": 1,
        "source_schema_digest_hex": "22" * 32,
        "source_interaction": 1,
        "source_cardinality": 1,
        "target_instance_hex": target_instance * 16,
        "target_port_hex": target_port * 16,
        "target_direction": 2,
        "target_schema_id_hex": "21" * 16,
        "target_schema_version": 1,
        "target_schema_digest_hex": "22" * 32,
        "target_interaction": 1,
        "target_cardinality": 1,
        "mailbox_ref_hex": mailbox * 16,
        "delivery_max_payload_bytes": 128,
        "delivery_max_message_age_nanos": 1_000,
        "delivery_overflow_policy": 3,
        "mailbox_capacity_items": 2,
        "mailbox_capacity_bytes": 256,
        "mailbox_max_queue_age_nanos": 500,
        "mailbox_max_inflight": 1,
        "mailbox_max_retained_bytes": 256,
        "mailbox_overflow_policy": 3,
    }


# Input is intentionally reverse BindingId order; canonical PXTA sorts it.
SEMANTIC = {
    "assignments": [
        _assignment("32", "42", "52", "62", "72", "82"),
        _assignment("31", "41", "51", "61", "71", "81"),
    ],
    "slice_contract_version": 1,
    "target_hex": "05" * 16,
    "source_scope_hex": "01" * 16,
    "source_plan_hex": "02" * 16,
    "source_revision": 3,
    "source_plan_digest_hex": "04" * 32,
    "writer_hex": "09" * 16,
    "writer_epoch": 1,
    "tenure_authority_hex": "07" * 16,
    "tenure_key_hex": "08" * 16,
    "tenure_algorithm": 1,
    "tenure_algorithm_version": 1,
    "supersedes_through_epoch": 0,
    "tenure_nonce_hex": b"test-only-tenure-nonce".hex(),
    "expected_active_tag": 0,
    "expected_active_digest_hex": "00" * 32,
    "operation_id_hex": "0d" * 16,
    "temporal_version": 1,
    "temporal_constraint_id_hex": "0a" * 16,
    "clock_domain_hex": "0b" * 16,
    "clock_generation": 3,
    "original_budget_nanos": 100,
    "remaining_budget_nanos": 60,
    "auth_principal_hex": "09" * 16,
    "auth_key_hex": "0c" * 16,
    "auth_algorithm": 1,
    "auth_algorithm_version": 1,
    "auth_nonce_hex": b"test-only-request-nonce".hex(),
}

PROTOCOL = {
    "assignment_magic_hex": ASSIGNMENT_MAGIC.hex(),
    "assignment_version": ASSIGNMENT_VERSION,
    "assignment_header": "magic:4,version:u16-be,count:u32-be",
    "assignment_record_bytes": ASSIGNMENT_RECORD_BYTES,
    "max_assignments": MAX_ASSIGNMENTS,
    "max_assignment_bytes": MAX_ASSIGNMENT_BYTES,
    "assignment_digest_domain_hex": ASSIGNMENT_DIGEST_DOMAIN.hex(),
    "outer_magic_hex": OUTER_MAGIC.hex(),
    "outer_version": OUTER_VERSION,
    "outer_header": "magic:4,version:u16-be,envelope_len:u32-be,assignments_len:u32-be",
    "max_outer_bytes": MAX_OUTER_BYTES,
    "s2_magic_hex": S2_MAGIC.hex(),
    "s2_version": S2_VERSION,
    "s2_field_count": S2_FIELD_COUNT,
    "max_s2_bytes": MAX_S2_BYTES,
    "digest_magic_hex": DIGEST_MAGIC.hex(),
    "digest_version": DIGEST_VERSION,
    "target_slice_digest_domain_hex": TARGET_SLICE_DIGEST_DOMAIN.hex(),
    "tenure_proof_digest_domain_hex": TENURE_PROOF_DIGEST_DOMAIN.hex(),
    "apply_control_digest_domain_hex": APPLY_CONTROL_DIGEST_DOMAIN.hex(),
    "request_digest_domain_hex": REQUEST_DIGEST_DOMAIN.hex(),
    "tenure_signing_domain_hex": TENURE_SIGNING_DOMAIN.hex(),
    "request_signing_domain_hex": AUTH_SIGNING_DOMAIN.hex(),
}


class AssignmentReject(Exception):
    def __init__(self, code: int, record_index: int | None = None) -> None:
        super().__init__(f"assignment rejection code={code} record={record_index}")
        self.code = code
        self.record_index = record_index


class S2Reject(Exception):
    def __init__(self, code: int, field_tag: int | None = None) -> None:
        super().__init__(f"S2 rejection code={code} field={field_tag}")
        self.code = code
        self.field_tag = field_tag


class OuterReject(Exception):
    def __init__(self, code: int, detail_code: int | None = None) -> None:
        super().__init__(f"outer rejection code={code} detail={detail_code}")
        self.code = code
        self.detail_code = detail_code


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _hex(value: object) -> bytes:
    assert isinstance(value, str)
    return bytes.fromhex(value)


def _canonical_digest(domain: bytes, fields: list[bytes]) -> bytes:
    encoded = bytearray(DIGEST_MAGIC)
    encoded += _u16(DIGEST_VERSION)
    encoded += _u32(len(domain))
    encoded += domain
    for ordinal, field in enumerate(fields, start=1):
        encoded += DIGEST_FIELD_MARKER
        encoded += _u32(ordinal)
        encoded += _u64(len(field))
        encoded += field
    encoded += DIGEST_END_MARKER
    encoded += _u32(len(fields))
    return hashlib.sha256(encoded).digest()


def _tlv(tag: int, value: bytes) -> bytes:
    return _u16(tag) + _u32(len(value)) + value


def _signing_transcript(domain: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    encoded = bytearray(SIGNING_MAGIC)
    encoded += _u16(1)
    encoded += _u16(len(domain))
    encoded += domain
    encoded += _u16(len(fields))
    for tag, value in fields:
        encoded += _tlv(tag, value)
    return bytes(encoded)


def _encode_record(value: dict[str, Any]) -> bytes:
    encoded = bytearray()
    encoded += _hex(value["binding_id_hex"])
    encoded += _hex(value["source_instance_hex"])
    encoded += _hex(value["source_port_hex"])
    encoded += struct.pack(">B", value["source_direction"])
    encoded += _hex(value["source_schema_id_hex"])
    encoded += _u32(value["source_schema_version"])
    encoded += _hex(value["source_schema_digest_hex"])
    encoded += struct.pack(">BB", value["source_interaction"], value["source_cardinality"])
    encoded += _hex(value["target_instance_hex"])
    encoded += _hex(value["target_port_hex"])
    encoded += struct.pack(">B", value["target_direction"])
    encoded += _hex(value["target_schema_id_hex"])
    encoded += _u32(value["target_schema_version"])
    encoded += _hex(value["target_schema_digest_hex"])
    encoded += struct.pack(">BB", value["target_interaction"], value["target_cardinality"])
    encoded += _hex(value["mailbox_ref_hex"])
    encoded += _u64(value["delivery_max_payload_bytes"])
    encoded += _u64(value["delivery_max_message_age_nanos"])
    encoded += struct.pack(">B", value["delivery_overflow_policy"])
    encoded += _u32(value["mailbox_capacity_items"])
    encoded += _u64(value["mailbox_capacity_bytes"])
    encoded += _u64(value["mailbox_max_queue_age_nanos"])
    encoded += _u32(value["mailbox_max_inflight"])
    encoded += _u64(value["mailbox_max_retained_bytes"])
    encoded += struct.pack(">B", value["mailbox_overflow_policy"])
    assert len(encoded) == ASSIGNMENT_RECORD_BYTES
    return bytes(encoded)


def _canonical_assignment_body(values: list[dict[str, Any]]) -> bytes:
    records = sorted((_encode_record(value) for value in values), key=lambda record: record[:16])
    return ASSIGNMENT_MAGIC + _u16(ASSIGNMENT_VERSION) + _u32(len(records)) + b"".join(records)


def _decode_record(record: bytes, record_index: int) -> dict[str, Any]:
    assert len(record) == ASSIGNMENT_RECORD_BYTES
    cursor = 0

    def take(length: int) -> bytes:
        nonlocal cursor
        value = record[cursor : cursor + length]
        cursor += length
        return value

    def byte() -> int:
        return take(1)[0]

    def uint32() -> int:
        return struct.unpack(">I", take(4))[0]

    def uint64() -> int:
        return struct.unpack(">Q", take(8))[0]

    value = {
        "binding_id": take(16),
        "source_instance": take(16),
        "source_port": take(16),
        "source_direction": byte(),
        "source_schema_id": take(16),
        "source_schema_version": uint32(),
        "source_schema_digest": take(32),
        "source_interaction": byte(),
        "source_cardinality": byte(),
        "target_instance": take(16),
        "target_port": take(16),
        "target_direction": byte(),
        "target_schema_id": take(16),
        "target_schema_version": uint32(),
        "target_schema_digest": take(32),
        "target_interaction": byte(),
        "target_cardinality": byte(),
        "mailbox_ref": take(16),
        "delivery_max_payload_bytes": uint64(),
        "delivery_max_message_age_nanos": uint64(),
        "delivery_overflow_policy": byte(),
        "mailbox_capacity_items": uint32(),
        "mailbox_capacity_bytes": uint64(),
        "mailbox_max_queue_age_nanos": uint64(),
        "mailbox_max_inflight": uint32(),
        "mailbox_max_retained_bytes": uint64(),
        "mailbox_overflow_policy": byte(),
        "canonical_record": record,
    }
    assert cursor == ASSIGNMENT_RECORD_BYTES

    enum_values = (
        value["source_direction"] in {1, 2}
        and value["target_direction"] in {1, 2}
        and value["source_interaction"] in {1, 2}
        and value["target_interaction"] in {1, 2}
        and value["source_cardinality"] == 1
        and value["target_cardinality"] == 1
        and value["delivery_overflow_policy"] in {1, 2, 3, 4, 5}
        and value["mailbox_overflow_policy"] in {1, 2, 3, 4, 5}
    )
    if not enum_values:
        raise AssignmentReject(ASSIGNMENT_ERROR_CODES["invalid_enum_value"], record_index)

    source_schema = (
        value["source_schema_id"],
        value["source_schema_version"],
        value["source_schema_digest"],
    )
    target_schema = (
        value["target_schema_id"],
        value["target_schema_version"],
        value["target_schema_digest"],
    )
    positive_bounds = all(
        value[name] > 0
        for name in (
            "source_schema_version",
            "target_schema_version",
            "delivery_max_payload_bytes",
            "delivery_max_message_age_nanos",
            "mailbox_capacity_items",
            "mailbox_capacity_bytes",
            "mailbox_max_queue_age_nanos",
            "mailbox_max_inflight",
            "mailbox_max_retained_bytes",
        )
    )
    semantics_valid = (
        positive_bounds
        and value["source_direction"] == 1
        and value["target_direction"] == 2
        and source_schema == target_schema
        and value["source_interaction"] == value["target_interaction"]
        and value["delivery_overflow_policy"] == value["mailbox_overflow_policy"]
        and value["mailbox_max_queue_age_nanos"]
        <= value["delivery_max_message_age_nanos"]
        and value["mailbox_capacity_bytes"] >= value["delivery_max_payload_bytes"]
        and value["mailbox_max_retained_bytes"] >= value["mailbox_capacity_bytes"]
        and not (
            value["source_interaction"] == 2
            and value["delivery_overflow_policy"] not in {1, 5}
        )
    )
    if not semantics_valid:
        raise AssignmentReject(ASSIGNMENT_ERROR_CODES["invalid_assignment"], record_index)
    return value


def _parse_assignments(frame: bytes) -> list[dict[str, Any]]:
    if len(frame) > MAX_ASSIGNMENT_BYTES:
        raise AssignmentReject(ASSIGNMENT_ERROR_CODES["frame_too_large"])
    if len(frame) < ASSIGNMENT_HEADER_BYTES:
        raise AssignmentReject(ASSIGNMENT_ERROR_CODES["truncated"])
    if frame[:4] != ASSIGNMENT_MAGIC:
        raise AssignmentReject(ASSIGNMENT_ERROR_CODES["invalid_magic"])
    version, count = struct.unpack_from(">HI", frame, 4)
    if version != ASSIGNMENT_VERSION:
        raise AssignmentReject(ASSIGNMENT_ERROR_CODES["unsupported_version"])
    if count > MAX_ASSIGNMENTS:
        raise AssignmentReject(ASSIGNMENT_ERROR_CODES["assignment_count_exceeded"])
    expected_length = ASSIGNMENT_HEADER_BYTES + count * ASSIGNMENT_RECORD_BYTES
    if len(frame) < expected_length:
        raise AssignmentReject(ASSIGNMENT_ERROR_CODES["truncated"])
    if len(frame) != expected_length:
        raise AssignmentReject(ASSIGNMENT_ERROR_CODES["invalid_frame_length"])

    records = [
        _decode_record(
            frame[
                ASSIGNMENT_HEADER_BYTES
                + index * ASSIGNMENT_RECORD_BYTES : ASSIGNMENT_HEADER_BYTES
                + (index + 1) * ASSIGNMENT_RECORD_BYTES
            ],
            index,
        )
        for index in range(count)
    ]
    sorted_records = sorted(records, key=lambda record: record["binding_id"])
    for index, current in enumerate(sorted_records):
        for previous in sorted_records[:index]:
            if previous["binding_id"] == current["binding_id"]:
                raise AssignmentReject(ASSIGNMENT_ERROR_CODES["duplicate_binding_id"])
            if (
                previous["source_instance"],
                previous["source_port"],
            ) == (current["source_instance"], current["source_port"]):
                raise AssignmentReject(ASSIGNMENT_ERROR_CODES["duplicate_source_endpoint"])
            if (
                previous["target_instance"],
                previous["target_port"],
            ) == (current["target_instance"], current["target_port"]):
                raise AssignmentReject(ASSIGNMENT_ERROR_CODES["duplicate_target_endpoint"])
            if previous["mailbox_ref"] == current["mailbox_ref"]:
                raise AssignmentReject(ASSIGNMENT_ERROR_CODES["duplicate_mailbox_ref"])

    canonical = (
        ASSIGNMENT_MAGIC
        + _u16(ASSIGNMENT_VERSION)
        + _u32(len(sorted_records))
        + b"".join(record["canonical_record"] for record in sorted_records)
    )
    if canonical != frame:
        raise AssignmentReject(ASSIGNMENT_ERROR_CODES["non_canonical_frame"])
    return sorted_records


def _valid_s2_field_length(tag: int, length: int) -> bool:
    if tag in {1, 13, 14, 22, 26, 34, 35}:
        return length == 2
    if tag in {5, 10, 17, 18, 29, 30, 31}:
        return length == 8
    if tag in {2, 3, 4, 9, 11, 12, 15, 16, 24, 27, 28, 32, 33}:
        return length == 16
    if tag in {6, 7, 8, 21, 23, 25}:
        return length == 32
    if tag in {19, 36}:
        return 1 <= length <= 64
    if tag in {20, 37}:
        return 1 <= length <= 512
    return False


def _encode_s2(fields: list[tuple[int, bytes]]) -> bytes:
    return S2_MAGIC + _u16(S2_VERSION) + _u16(len(fields)) + b"".join(
        _tlv(tag, value) for tag, value in fields
    )


def _parse_s2(frame: bytes) -> list[tuple[int, bytes]]:
    if len(frame) > MAX_S2_BYTES:
        raise S2Reject(S2_ERROR_CODES["frame_too_large"])
    header_length = len(S2_MAGIC) + 4
    if len(frame) < header_length:
        raise S2Reject(S2_ERROR_CODES["truncated"])
    if frame[: len(S2_MAGIC)] != S2_MAGIC:
        raise S2Reject(S2_ERROR_CODES["invalid_magic"])
    version, count = struct.unpack_from(">HH", frame, len(S2_MAGIC))
    if version != S2_VERSION:
        raise S2Reject(S2_ERROR_CODES["unsupported_version"])
    cursor = header_length
    fields = []
    for index in range(count):
        expected_tag = index + 1
        if cursor + 6 > len(frame):
            raise S2Reject(S2_ERROR_CODES["truncated"])
        tag, length = struct.unpack_from(">HI", frame, cursor)
        cursor += 6
        if tag == 0 or tag > S2_FIELD_COUNT:
            raise S2Reject(S2_ERROR_CODES["unknown_field"], tag)
        if tag < expected_tag:
            raise S2Reject(S2_ERROR_CODES["duplicate_field"], tag)
        if tag > expected_tag:
            raise S2Reject(S2_ERROR_CODES["out_of_order_field"], tag)
        if not _valid_s2_field_length(tag, length):
            raise S2Reject(S2_ERROR_CODES["invalid_field_length"], tag)
        end = cursor + length
        if end > len(frame):
            raise S2Reject(S2_ERROR_CODES["truncated"], tag)
        fields.append((tag, frame[cursor:end]))
        cursor = end
    if count < S2_FIELD_COUNT:
        raise S2Reject(S2_ERROR_CODES["missing_field"], count + 1)
    if cursor != len(frame):
        raise S2Reject(S2_ERROR_CODES["trailing_bytes"])
    if _encode_s2(fields) != frame:
        raise S2Reject(S2_ERROR_CODES["non_canonical_frame"])
    return fields


def _validate_s2(
    frame: bytes,
    tenure_public_key: bytes,
    request_public_key: bytes,
) -> dict[int, bytes]:
    fields = _parse_s2(frame)
    values = dict(fields)
    target_slice_digest = _canonical_digest(
        TARGET_SLICE_DIGEST_DOMAIN, [values[tag] for tag in range(1, 8)]
    )
    if values[8] != target_slice_digest:
        raise S2Reject(S2_ERROR_CODES["derived_digest_mismatch"], 8)
    tenure_digest = _canonical_digest(
        TENURE_PROOF_DIGEST_DOMAIN, [values[tag] for tag in range(11, 21)]
    )
    if values[21] != tenure_digest:
        raise S2Reject(S2_ERROR_CODES["derived_digest_mismatch"], 21)
    control_digest = _canonical_digest(
        APPLY_CONTROL_DIGEST_DOMAIN,
        [
            values[8],
            *[values[tag] for tag in range(1, 8)],
            values[9],
            values[10],
            values[21],
            values[22],
            values[23],
            values[24],
        ],
    )
    if values[25] != control_digest:
        raise S2Reject(S2_ERROR_CODES["derived_digest_mismatch"], 25)

    tenure_transcript = _signing_transcript(
        TENURE_SIGNING_DOMAIN,
        [(tag, values[wire_tag]) for tag, wire_tag in enumerate(range(11, 20), start=1)],
    )
    request_transcript = _signing_transcript(
        AUTH_SIGNING_DOMAIN, [(tag, values[tag]) for tag in range(1, 37)]
    )
    try:
        Ed25519PublicKey.from_public_bytes(tenure_public_key).verify(
            values[20], tenure_transcript
        )
        Ed25519PublicKey.from_public_bytes(request_public_key).verify(
            values[37], request_transcript
        )
    except (InvalidSignature, ValueError) as error:
        raise S2Reject(S2_ERROR_CODES["invalid_field_value"]) from error
    return values


def _build_s2(assignment_digest: bytes) -> dict[str, bytes]:
    target = _hex(SEMANTIC["target_hex"])
    scope = _hex(SEMANTIC["source_scope_hex"])
    plan = _hex(SEMANTIC["source_plan_hex"])
    source_revision = _u64(SEMANTIC["source_revision"])
    source_plan_digest = _hex(SEMANTIC["source_plan_digest_hex"])
    writer = _hex(SEMANTIC["writer_hex"])
    writer_epoch = _u64(SEMANTIC["writer_epoch"])
    authority = _hex(SEMANTIC["tenure_authority_hex"])
    tenure_key = _hex(SEMANTIC["tenure_key_hex"])
    tenure_nonce = _hex(SEMANTIC["tenure_nonce_hex"])
    slice_version = _u16(SEMANTIC["slice_contract_version"])
    tenure_algorithm = _u16(SEMANTIC["tenure_algorithm"])
    tenure_algorithm_version = _u16(SEMANTIC["tenure_algorithm_version"])
    supersedes = _u64(SEMANTIC["supersedes_through_epoch"])

    target_slice_digest = _canonical_digest(
        TARGET_SLICE_DIGEST_DOMAIN,
        [
            slice_version,
            target,
            scope,
            plan,
            source_revision,
            source_plan_digest,
            assignment_digest,
        ],
    )
    tenure_fields = [
        (1, authority),
        (2, tenure_key),
        (3, tenure_algorithm),
        (4, tenure_algorithm_version),
        (5, scope),
        (6, writer),
        (7, writer_epoch),
        (8, supersedes),
        (9, tenure_nonce),
    ]
    tenure_transcript = _signing_transcript(TENURE_SIGNING_DOMAIN, tenure_fields)
    tenure_private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(TEST_ONLY_KEYS["tenure_authority_seed_hex"])
    )
    tenure_signature = tenure_private_key.sign(tenure_transcript)
    tenure_public_key = tenure_private_key.public_key().public_bytes_raw()
    tenure_digest = _canonical_digest(
        TENURE_PROOF_DIGEST_DOMAIN,
        [
            authority,
            tenure_key,
            tenure_algorithm,
            tenure_algorithm_version,
            scope,
            writer,
            writer_epoch,
            supersedes,
            tenure_nonce,
            tenure_signature,
        ],
    )
    expected_tag = _u16(SEMANTIC["expected_active_tag"])
    expected_digest = _hex(SEMANTIC["expected_active_digest_hex"])
    operation_id = _hex(SEMANTIC["operation_id_hex"])
    control_digest = _canonical_digest(
        APPLY_CONTROL_DIGEST_DOMAIN,
        [
            target_slice_digest,
            slice_version,
            target,
            scope,
            plan,
            source_revision,
            source_plan_digest,
            assignment_digest,
            writer,
            writer_epoch,
            tenure_digest,
            expected_tag,
            expected_digest,
            operation_id,
        ],
    )
    unsigned_fields = [
        (1, slice_version),
        (2, target),
        (3, scope),
        (4, plan),
        (5, source_revision),
        (6, source_plan_digest),
        (7, assignment_digest),
        (8, target_slice_digest),
        (9, writer),
        (10, writer_epoch),
        (11, authority),
        (12, tenure_key),
        (13, tenure_algorithm),
        (14, tenure_algorithm_version),
        (15, scope),
        (16, writer),
        (17, writer_epoch),
        (18, supersedes),
        (19, tenure_nonce),
        (20, tenure_signature),
        (21, tenure_digest),
        (22, expected_tag),
        (23, expected_digest),
        (24, operation_id),
        (25, control_digest),
        (26, _u16(SEMANTIC["temporal_version"])),
        (27, _hex(SEMANTIC["temporal_constraint_id_hex"])),
        (28, _hex(SEMANTIC["clock_domain_hex"])),
        (29, _u64(SEMANTIC["clock_generation"])),
        (30, _u64(SEMANTIC["original_budget_nanos"])),
        (31, _u64(SEMANTIC["remaining_budget_nanos"])),
        (32, _hex(SEMANTIC["auth_principal_hex"])),
        (33, _hex(SEMANTIC["auth_key_hex"])),
        (34, _u16(SEMANTIC["auth_algorithm"])),
        (35, _u16(SEMANTIC["auth_algorithm_version"])),
        (36, _hex(SEMANTIC["auth_nonce_hex"])),
    ]
    request_transcript = _signing_transcript(AUTH_SIGNING_DOMAIN, unsigned_fields)
    request_private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(TEST_ONLY_KEYS["request_writer_seed_hex"])
    )
    request_signature = request_private_key.sign(request_transcript)
    request_public_key = request_private_key.public_key().public_bytes_raw()
    envelope = _encode_s2([*unsigned_fields, (37, request_signature)])
    return {
        "target_slice_digest": target_slice_digest,
        "tenure_public_key": tenure_public_key,
        "tenure_signature": tenure_signature,
        "tenure_proof_digest": tenure_digest,
        "control_digest": control_digest,
        "request_public_key": request_public_key,
        "request_signature": request_signature,
        "request_digest": _canonical_digest(REQUEST_DIGEST_DOMAIN, [envelope]),
        "envelope": envelope,
    }


def _build_vector(assignments: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    semantic_assignments = SEMANTIC["assignments"] if assignments is None else assignments
    assignment_body = _canonical_assignment_body(semantic_assignments)
    assignment_digest = _canonical_digest(ASSIGNMENT_DIGEST_DOMAIN, [assignment_body])
    s2 = _build_s2(assignment_digest)
    envelope = s2["envelope"]
    outer = (
        OUTER_MAGIC
        + _u16(OUTER_VERSION)
        + _u32(len(envelope))
        + _u32(len(assignment_body))
        + envelope
        + assignment_body
    )
    return {
        **s2,
        "assignment_body": assignment_body,
        "assignment_digest": assignment_digest,
        "outer": outer,
    }


def _parse_outer(
    frame: bytes,
    tenure_public_key: bytes,
    request_public_key: bytes,
) -> dict[str, Any]:
    if len(frame) > MAX_OUTER_BYTES:
        raise OuterReject(OUTER_ERROR_CODES["frame_too_large"])
    if len(frame) < OUTER_HEADER_BYTES:
        raise OuterReject(OUTER_ERROR_CODES["truncated"])
    if frame[:4] != OUTER_MAGIC:
        raise OuterReject(OUTER_ERROR_CODES["invalid_magic"])
    version, envelope_length, assignment_length = struct.unpack_from(">HII", frame, 4)
    if version != OUTER_VERSION:
        raise OuterReject(OUTER_ERROR_CODES["unsupported_version"])
    expected_length = OUTER_HEADER_BYTES + envelope_length + assignment_length
    if len(frame) < expected_length:
        raise OuterReject(OUTER_ERROR_CODES["truncated"])
    if len(frame) != expected_length:
        raise OuterReject(OUTER_ERROR_CODES["invalid_frame_length"])
    envelope_end = OUTER_HEADER_BYTES + envelope_length
    envelope = frame[OUTER_HEADER_BYTES:envelope_end]
    assignment_body = frame[envelope_end:]
    try:
        s2_values = _validate_s2(envelope, tenure_public_key, request_public_key)
    except S2Reject as error:
        raise OuterReject(OUTER_ERROR_CODES["envelope_rejected"], error.code) from error
    try:
        assignments = _parse_assignments(assignment_body)
    except AssignmentReject as error:
        raise OuterReject(OUTER_ERROR_CODES["assignments_rejected"], error.code) from error
    assignment_digest = _canonical_digest(ASSIGNMENT_DIGEST_DOMAIN, [assignment_body])
    if assignment_digest != s2_values[7]:
        raise OuterReject(OUTER_ERROR_CODES["commitment_mismatch"])
    return {
        "envelope": envelope,
        "assignments": assignments,
        "assignment_body": assignment_body,
        "assignment_digest": assignment_digest,
        "s2_values": s2_values,
    }


def _fixture_document() -> dict[str, Any]:
    vector = _build_vector()
    return {
        "fixture_version": 1,
        "source": "independent Python struct/hashlib/cryptography S3 contract fixture",
        "test_only_notice": "TEST-ONLY deterministic keys; never production",
        "test_only_keys": TEST_ONLY_KEYS,
        "semantic": SEMANTIC,
        "protocol": PROTOCOL,
        "assignment_error_codes": ASSIGNMENT_ERROR_CODES,
        "outer_error_codes": OUTER_ERROR_CODES,
        "expected": {
            "canonical_binding_order_hex": ["31" * 16, "32" * 16],
            "assignment_body_hex": vector["assignment_body"].hex(),
            "assignment_body_length": len(vector["assignment_body"]),
            "assignment_digest_hex": vector["assignment_digest"].hex(),
            "target_slice_digest_hex": vector["target_slice_digest"].hex(),
            "tenure_public_key_hex": vector["tenure_public_key"].hex(),
            "tenure_signature_hex": vector["tenure_signature"].hex(),
            "tenure_proof_digest_hex": vector["tenure_proof_digest"].hex(),
            "control_digest_hex": vector["control_digest"].hex(),
            "request_public_key_hex": vector["request_public_key"].hex(),
            "request_signature_hex": vector["request_signature"].hex(),
            "request_digest_hex": vector["request_digest"].hex(),
            "s2_envelope_hex": vector["envelope"].hex(),
            "s2_envelope_length": len(vector["envelope"]),
            "outer_wire_hex": vector["outer"].hex(),
            "outer_wire_length": len(vector["outer"]),
        },
    }


def _load_fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _copy_first_record_field_to_second(frame: bytes, offset: int, length: int) -> bytes:
    mutated = bytearray(frame)
    first = ASSIGNMENT_HEADER_BYTES + offset
    second = ASSIGNMENT_HEADER_BYTES + ASSIGNMENT_RECORD_BYTES + offset
    mutated[second : second + length] = mutated[first : first + length]
    return bytes(mutated)


def _zero_first_record_field(frame: bytes, offset: int, length: int) -> bytes:
    mutated = bytearray(frame)
    start = ASSIGNMENT_HEADER_BYTES + offset
    mutated[start : start + length] = bytes(length)
    return bytes(mutated)


def test_independent_rebuild_matches_complete_request_fixture() -> None:
    fixture = _load_fixture()
    assert fixture == _fixture_document()


def test_reverse_input_sorts_to_two_exact_fixed_records() -> None:
    vector = _build_vector()
    body = vector["assignment_body"]
    assert len(body) == ASSIGNMENT_HEADER_BYTES + 2 * ASSIGNMENT_RECORD_BYTES
    records = _parse_assignments(body)
    assert [record["binding_id"].hex() for record in records] == ["31" * 16, "32" * 16]
    assert _build_vector(list(reversed(SEMANTIC["assignments"]))) ["assignment_body"] == body


def test_complete_outer_parser_revalidates_digest_and_real_signatures() -> None:
    vector = _build_vector()
    parsed = _parse_outer(
        vector["outer"], vector["tenure_public_key"], vector["request_public_key"]
    )
    assert parsed["assignment_digest"] == vector["assignment_digest"]
    assert parsed["s2_values"][7] == vector["assignment_digest"]
    assert parsed["s2_values"][8] == vector["target_slice_digest"]
    assert len(parsed["assignments"]) == 2


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (lambda frame: b"BAD!" + frame[4:], ASSIGNMENT_ERROR_CODES["invalid_magic"]),
        (
            lambda frame: frame[:4] + _u16(2) + frame[6:],
            ASSIGNMENT_ERROR_CODES["unsupported_version"],
        ),
        (
            lambda frame: frame[:6] + _u32(MAX_ASSIGNMENTS + 1) + frame[10:],
            ASSIGNMENT_ERROR_CODES["assignment_count_exceeded"],
        ),
        (lambda frame: frame[:-1], ASSIGNMENT_ERROR_CODES["truncated"]),
        (lambda frame: frame + b"\0", ASSIGNMENT_ERROR_CODES["invalid_frame_length"]),
        (
            lambda frame: frame[: ASSIGNMENT_HEADER_BYTES + 48]
            + b"\x63"
            + frame[ASSIGNMENT_HEADER_BYTES + 49 :],
            ASSIGNMENT_ERROR_CODES["invalid_enum_value"],
        ),
        (
            lambda frame: _zero_first_record_field(frame, RECORD_MAX_PAYLOAD_OFFSET, 8),
            ASSIGNMENT_ERROR_CODES["invalid_assignment"],
        ),
    ],
)
def test_assignment_parser_has_stable_structural_errors(mutator: Any, expected_code: int) -> None:
    body = _build_vector()["assignment_body"]
    with pytest.raises(AssignmentReject) as raised:
        _parse_assignments(mutator(body))
    assert raised.value.code == expected_code


def test_assignment_parser_rejects_unsorted_and_duplicate_static_ownership() -> None:
    body = _build_vector()["assignment_body"]
    first = body[ASSIGNMENT_HEADER_BYTES : ASSIGNMENT_HEADER_BYTES + ASSIGNMENT_RECORD_BYTES]
    second = body[ASSIGNMENT_HEADER_BYTES + ASSIGNMENT_RECORD_BYTES :]
    reversed_body = body[:ASSIGNMENT_HEADER_BYTES] + second + first
    with pytest.raises(AssignmentReject) as unsorted:
        _parse_assignments(reversed_body)
    assert unsorted.value.code == ASSIGNMENT_ERROR_CODES["non_canonical_frame"]

    duplicate_cases = [
        (0, 16, ASSIGNMENT_ERROR_CODES["duplicate_binding_id"]),
        (
            RECORD_SOURCE_ENDPOINT_OFFSET,
            32,
            ASSIGNMENT_ERROR_CODES["duplicate_source_endpoint"],
        ),
        (
            RECORD_TARGET_ENDPOINT_OFFSET,
            32,
            ASSIGNMENT_ERROR_CODES["duplicate_target_endpoint"],
        ),
        (RECORD_MAILBOX_OFFSET, 16, ASSIGNMENT_ERROR_CODES["duplicate_mailbox_ref"]),
    ]
    for offset, length, expected_code in duplicate_cases:
        with pytest.raises(AssignmentReject) as duplicate:
            _parse_assignments(_copy_first_record_field_to_second(body, offset, length))
        assert duplicate.value.code == expected_code


def test_outer_parser_has_stable_structural_and_nested_errors() -> None:
    vector = _build_vector()
    outer = vector["outer"]

    cases = [
        (outer[:-1], OUTER_ERROR_CODES["truncated"], None),
        (b"BAD!" + outer[4:], OUTER_ERROR_CODES["invalid_magic"], None),
        (
            outer[:4] + _u16(2) + outer[6:],
            OUTER_ERROR_CODES["unsupported_version"],
            None,
        ),
        (outer + b"\0", OUTER_ERROR_CODES["invalid_frame_length"], None),
    ]
    envelope_length = len(vector["envelope"])
    bad_envelope = bytearray(outer)
    bad_envelope[OUTER_HEADER_BYTES] ^= 1
    cases.append(
        (
            bytes(bad_envelope),
            OUTER_ERROR_CODES["envelope_rejected"],
            S2_ERROR_CODES["invalid_magic"],
        )
    )
    bad_assignments = bytearray(outer)
    assignment_start = OUTER_HEADER_BYTES + envelope_length
    bad_assignments[assignment_start] ^= 1
    cases.append(
        (
            bytes(bad_assignments),
            OUTER_ERROR_CODES["assignments_rejected"],
            ASSIGNMENT_ERROR_CODES["invalid_magic"],
        )
    )
    for frame, code, detail in cases:
        with pytest.raises(OuterReject) as raised:
            _parse_outer(frame, vector["tenure_public_key"], vector["request_public_key"])
        assert (raised.value.code, raised.value.detail_code) == (code, detail)


def test_outer_rejects_canonical_assignment_body_that_breaks_authenticated_commitment() -> None:
    vector = _build_vector()
    outer = bytearray(vector["outer"])
    assignment_start = OUTER_HEADER_BYTES + len(vector["envelope"])
    first_binding = assignment_start + ASSIGNMENT_HEADER_BYTES
    outer[first_binding] = 0x30
    with pytest.raises(OuterReject) as raised:
        _parse_outer(bytes(outer), vector["tenure_public_key"], vector["request_public_key"])
    assert raised.value.code == OUTER_ERROR_CODES["commitment_mismatch"]


def test_real_signature_failures_survive_valid_downstream_rebuilds() -> None:
    vector = _build_vector()
    assignment_body = vector["assignment_body"]
    values = dict(_parse_s2(vector["envelope"]))

    bad_request_signature = bytearray(values[37])
    bad_request_signature[0] ^= 1
    values[37] = bytes(bad_request_signature)
    bad_request_envelope = _encode_s2([(tag, values[tag]) for tag in range(1, 38)])
    bad_request_outer = (
        OUTER_MAGIC
        + _u16(OUTER_VERSION)
        + _u32(len(bad_request_envelope))
        + _u32(len(assignment_body))
        + bad_request_envelope
        + assignment_body
    )
    with pytest.raises(OuterReject) as bad_request:
        _parse_outer(
            bad_request_outer, vector["tenure_public_key"], vector["request_public_key"]
        )
    assert (bad_request.value.code, bad_request.value.detail_code) == (
        OUTER_ERROR_CODES["envelope_rejected"],
        S2_ERROR_CODES["invalid_field_value"],
    )

    values = dict(_parse_s2(vector["envelope"]))
    bad_tenure_signature = bytearray(values[20])
    bad_tenure_signature[0] ^= 1
    values[20] = bytes(bad_tenure_signature)
    values[21] = _canonical_digest(
        TENURE_PROOF_DIGEST_DOMAIN, [values[tag] for tag in range(11, 21)]
    )
    values[25] = _canonical_digest(
        APPLY_CONTROL_DIGEST_DOMAIN,
        [
            values[8],
            *[values[tag] for tag in range(1, 8)],
            values[9],
            values[10],
            values[21],
            values[22],
            values[23],
            values[24],
        ],
    )
    request_private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(TEST_ONLY_KEYS["request_writer_seed_hex"])
    )
    values[37] = request_private_key.sign(
        _signing_transcript(
            AUTH_SIGNING_DOMAIN, [(tag, values[tag]) for tag in range(1, 37)]
        )
    )
    bad_tenure_envelope = _encode_s2([(tag, values[tag]) for tag in range(1, 38)])
    bad_tenure_outer = (
        OUTER_MAGIC
        + _u16(OUTER_VERSION)
        + _u32(len(bad_tenure_envelope))
        + _u32(len(assignment_body))
        + bad_tenure_envelope
        + assignment_body
    )
    with pytest.raises(OuterReject) as bad_tenure:
        _parse_outer(
            bad_tenure_outer, vector["tenure_public_key"], vector["request_public_key"]
        )
    assert (bad_tenure.value.code, bad_tenure.value.detail_code) == (
        OUTER_ERROR_CODES["envelope_rejected"],
        S2_ERROR_CODES["invalid_field_value"],
    )


def test_preparse_size_bounds_fail_before_component_work() -> None:
    maximum_assignments = [
        _assignment(
            f"{index:02x}",
            "40",
            f"{index:02x}",
            "60",
            f"{index:02x}",
            f"{index:02x}",
        )
        for index in range(MAX_ASSIGNMENTS)
    ]
    maximum_body = _canonical_assignment_body(maximum_assignments)
    assert len(maximum_body) == MAX_ASSIGNMENT_BYTES
    assert len(_parse_assignments(maximum_body)) == MAX_ASSIGNMENTS

    with pytest.raises(AssignmentReject) as assignment:
        _parse_assignments(bytes(MAX_ASSIGNMENT_BYTES + 1))
    assert assignment.value.code == ASSIGNMENT_ERROR_CODES["frame_too_large"]
    with pytest.raises(OuterReject) as exact_outer_bound:
        _parse_outer(bytes(MAX_OUTER_BYTES), bytes(32), bytes(32))
    assert exact_outer_bound.value.code == OUTER_ERROR_CODES["invalid_magic"]
    with pytest.raises(OuterReject) as outer:
        _parse_outer(bytes(MAX_OUTER_BYTES + 1), bytes(32), bytes(32))
    assert outer.value.code == OUTER_ERROR_CODES["frame_too_large"]
