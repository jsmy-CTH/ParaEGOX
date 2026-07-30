from __future__ import annotations

import copy
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
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wire" / "s4_runtime_apply_request_v2.json"

DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
DIGEST_VERSION = 1
DIGEST_FIELD_MARKER = b"\x01"
DIGEST_END_MARKER = b"\xff"
SIGNING_MAGIC = b"ParaEGOX\0canonical-signing-transcript"

PXTA_MAGIC = b"PXTA"
PXTA_VERSION = 1
PXTA_HEADER_BYTES = 10
PXTA_RECORD_BYTES = 256
PXTA_MAX_RECORDS = 256
PXTA_MAX_BYTES = PXTA_HEADER_BYTES + PXTA_MAX_RECORDS * PXTA_RECORD_BYTES
PXTA_DIGEST_DOMAIN = b"paraegox.runtime.target-assignments.sha256.v1"

PXTE_MAGIC = b"PXTE"
PXTE_VERSION = 1
PXTE_HEADER_BYTES = 14
PXTE_DOMAIN_RECORD_BYTES = 64
PXTE_MAILBOX_RECORD_BYTES = 236
PXTE_MAX_DOMAINS = 64
PXTE_MAX_MAILBOXES = PXTA_MAX_RECORDS
PXTE_MAX_BYTES = (
    PXTE_HEADER_BYTES
    + PXTE_MAX_DOMAINS * PXTE_DOMAIN_RECORD_BYTES
    + PXTE_MAX_MAILBOXES * PXTE_MAILBOX_RECORD_BYTES
)
PXTE_DIGEST_DOMAIN = b"paraegox.runtime.target-execution.sha256.v1"
COMPOSITE_DIGEST_DOMAIN = b"paraegox.runtime.target-plan-assignments.sha256.v2"
MAX_DOMAIN_OUTSTANDING = 65_535
MAX_SERVICE_COST_TOKENS = 1_000_000
MAX_MINIMUM_SERVICE_WEIGHT = 1_000_000
MAX_ARRIVALS_PER_WINDOW = 1_000_000
MAX_EXECUTION_DURATION_NANOS = 86_400_000_000_000

PXAR_MAGIC = b"PXAR"
PXAR_V1_VERSION = 1
PXAR_V1_HEADER_BYTES = 14
PXAR_V2_VERSION = 2
PXAR_V2_HEADER_BYTES = 18
PXAR_V2_MAX_BYTES = PXAR_V2_HEADER_BYTES + 4096 + PXTA_MAX_BYTES + PXTE_MAX_BYTES

S2_MAGIC = b"ParaEGOX\0runtime-apply-envelope"
S2_VERSION = 1
S2_FIELD_COUNT = 37
S2_MAX_BYTES = 4096
TENURE_SIGNING_DOMAIN = b"paraegox.runtime.writer-tenure.signing.v1"
AUTH_SIGNING_DOMAIN = b"paraegox.runtime.apply-envelope-auth.signing.v1"
TARGET_SLICE_DIGEST_DOMAIN = b"paraegox.runtime.target-slice.sha256.v1"
TENURE_PROOF_DIGEST_DOMAIN = b"paraegox.runtime.writer-tenure-proof.sha256.v1"
APPLY_CONTROL_DIGEST_DOMAIN = b"paraegox.runtime.apply-control.sha256.v1"
REQUEST_DIGEST_DOMAIN = b"paraegox.runtime.apply-envelope.request.sha256.v1"

PXTE_DOMAIN_MAX_OUTSTANDING_OFFSET = 16
PXTE_MAILBOX_ENUM_OFFSET = 192
PXTE_MAILBOX_SERVICE_COST_OFFSET = 197

PXTA_ERROR_CODES = {
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

PXTE_ERROR_CODES = {
    "frame_too_large": 1,
    "truncated": 2,
    "invalid_magic": 3,
    "unsupported_version": 4,
    "domain_count_exceeded": 5,
    "execution_count_exceeded": 6,
    "invalid_frame_length": 7,
    "invalid_enum_value": 8,
    "invalid_domain": 9,
    "invalid_mailbox_execution": 10,
    "duplicate_domain_ref": 11,
    "duplicate_execution_binding": 12,
    "duplicate_execution_mailbox": 13,
    "orphan_domain_ref": 14,
    "unused_domain_ref": 15,
    "unsupported_loop_execution": 16,
    "control_reservation_required": 17,
    "control_utilization_exceeded": 18,
    "domain_utilization_exceeded": 19,
    "missing_records": 20,
    "non_canonical_frame": 21,
    "unsafe_loop_overrun_action": 22,
    "shared_capacity_required": 23,
}

TARGET_PLAN_ERROR_CODES = {
    "orphan_binding": 1,
    "binding_mailbox_mismatch": 2,
    "binding_target_mismatch": 3,
    "block_until_deadline_forbidden": 4,
    "subject_execution_mismatch": 5,
    "invalid_target_plan": 6,
    "control_start_slo_exceeded": 7,
}

PXAR_V2_ERROR_CODES = {
    "frame_too_large": 1,
    "truncated": 2,
    "invalid_magic": 3,
    "unsupported_version": 4,
    "invalid_frame_length": 5,
    "envelope_rejected": 6,
    "bindings_rejected": 7,
    "execution_rejected": 8,
    "target_plan_rejected": 9,
    "commitment_mismatch": 10,
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


def _binding(
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
        "delivery_max_message_age_nanos": 5_000_000_000,
        "delivery_overflow_policy": 3,
        "mailbox_capacity_items": 2,
        "mailbox_capacity_bytes": 256,
        "mailbox_max_queue_age_nanos": 5_000_000_000,
        "mailbox_max_inflight": 1,
        "mailbox_max_retained_bytes": 256,
        "mailbox_overflow_policy": 3,
    }


SEMANTIC: dict[str, Any] = {
    # Reverse input proves that PXTA canonicalizes by BindingId.
    "bindings": [
        _binding("32", "42", "52", "62", "72", "82"),
        _binding("31", "41", "51", "61", "71", "81"),
    ],
    "domains": [
        {
            "domain_ref_hex": "91" * 16,
            "max_outstanding": 2,
            "control_reserved": 1,
            "capacity_window_nanos": 4_000_000_000,
            "control_reserved_run_budget_nanos": 4_000_000_000,
            "start_budget_nanos": 1_000_000_000,
            "drain_budget_nanos": 1_000_000_000,
            "cleanup_budget_nanos": 1_000_000_000,
        }
    ],
    # Binding32 is intentionally not executable in PXTE; binding supersets are valid.
    "mailbox_executions": [
        {
            "binding_id_hex": "31" * 16,
            "mailbox_ref_hex": "81" * 16,
            "target_instance_hex": "61" * 16,
            "domain_ref_hex": "91" * 16,
            "card_definition_ref_hex": "a1" * 16,
            "card_implementation_ref_hex": "a2" * 16,
            "definition_digest_hex": "a3" * 32,
            "artifact_digest_hex": "a4" * 32,
            "config_digest_hex": "a5" * 32,
            "call_model": 1,
            "workload_kind": 1,
            "blocking_risk": 1,
            "run_bound_provenance": 2,
            "dispatch_class": 1,
            "service_cost_tokens": 2,
            "minimum_service_weight": 4,
            "max_burst": 2,
            "max_arrivals_per_window": 2,
            "max_nonpreemptive_run_nanos": 1_000_000_000,
            "run_budget_nanos": 1_000_000_000,
            "cleanup_budget_nanos": 1_000_000_000,
            "overrun_action": 2,
        }
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
    "pxta_magic_hex": PXTA_MAGIC.hex(),
    "pxta_version": PXTA_VERSION,
    "pxta_header": "magic:4,version:u16-be,binding_count:u32-be",
    "pxta_record_bytes": PXTA_RECORD_BYTES,
    "max_pxta_records": PXTA_MAX_RECORDS,
    "max_pxta_bytes": PXTA_MAX_BYTES,
    "pxta_digest_domain_hex": PXTA_DIGEST_DOMAIN.hex(),
    "pxte_magic_hex": PXTE_MAGIC.hex(),
    "pxte_version": PXTE_VERSION,
    "pxte_header": "magic:4,version:u16-be,domain_count:u32-be,mailbox_count:u32-be",
    "pxte_domain_record_bytes": PXTE_DOMAIN_RECORD_BYTES,
    "pxte_mailbox_record_bytes": PXTE_MAILBOX_RECORD_BYTES,
    "max_pxte_domains": PXTE_MAX_DOMAINS,
    "max_pxte_mailboxes": PXTE_MAX_MAILBOXES,
    "max_pxte_bytes": PXTE_MAX_BYTES,
    "pxte_digest_domain_hex": PXTE_DIGEST_DOMAIN.hex(),
    "composite_digest_domain_hex": COMPOSITE_DIGEST_DOMAIN.hex(),
    "pxar_magic_hex": PXAR_MAGIC.hex(),
    "pxar_v2_version": PXAR_V2_VERSION,
    "pxar_v2_header": (
        "magic:4,version:u16-be,envelope_len:u32-be,pxta_len:u32-be,pxte_len:u32-be"
    ),
    "max_pxar_v2_bytes": PXAR_V2_MAX_BYTES,
    "s2_magic_hex": S2_MAGIC.hex(),
    "s2_version": S2_VERSION,
    "s2_field_count": S2_FIELD_COUNT,
    "max_s2_bytes": S2_MAX_BYTES,
    "digest_magic_hex": DIGEST_MAGIC.hex(),
    "digest_version": DIGEST_VERSION,
    "target_slice_digest_domain_hex": TARGET_SLICE_DIGEST_DOMAIN.hex(),
    "tenure_proof_digest_domain_hex": TENURE_PROOF_DIGEST_DOMAIN.hex(),
    "apply_control_digest_domain_hex": APPLY_CONTROL_DIGEST_DOMAIN.hex(),
    "request_digest_domain_hex": REQUEST_DIGEST_DOMAIN.hex(),
    "tenure_signing_domain_hex": TENURE_SIGNING_DOMAIN.hex(),
    "request_signing_domain_hex": AUTH_SIGNING_DOMAIN.hex(),
}


class PxtaReject(Exception):
    def __init__(self, code: int, record_index: int | None = None) -> None:
        super().__init__(f"PXTA rejection code={code} record={record_index}")
        self.code = code
        self.record_index = record_index


class PxteReject(Exception):
    def __init__(
        self,
        code: int,
        section: int | None = None,
        record_index: int | None = None,
    ) -> None:
        super().__init__(f"PXTE rejection code={code} section={section} record={record_index}")
        self.code = code
        self.section = section
        self.record_index = record_index


class S2Reject(Exception):
    def __init__(self, code: int, field_tag: int | None = None) -> None:
        super().__init__(f"S2 rejection code={code} field={field_tag}")
        self.code = code
        self.field_tag = field_tag


class PxarV2Reject(Exception):
    def __init__(self, code: int, detail_code: int | None = None) -> None:
        super().__init__(f"PXAR v2 rejection code={code} detail={detail_code}")
        self.code = code
        self.detail_code = detail_code


class TargetPlanReject(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(f"target plan rejection code={code}")
        self.code = code


class SignatureReject(Exception):
    pass


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


def _encode_binding_record(value: dict[str, Any]) -> bytes:
    encoded = bytearray()
    encoded += _hex(value["binding_id_hex"])
    encoded += _hex(value["source_instance_hex"])
    encoded += _hex(value["source_port_hex"])
    encoded += _u8(value["source_direction"])
    encoded += _hex(value["source_schema_id_hex"])
    encoded += _u32(value["source_schema_version"])
    encoded += _hex(value["source_schema_digest_hex"])
    encoded += _u8(value["source_interaction"])
    encoded += _u8(value["source_cardinality"])
    encoded += _hex(value["target_instance_hex"])
    encoded += _hex(value["target_port_hex"])
    encoded += _u8(value["target_direction"])
    encoded += _hex(value["target_schema_id_hex"])
    encoded += _u32(value["target_schema_version"])
    encoded += _hex(value["target_schema_digest_hex"])
    encoded += _u8(value["target_interaction"])
    encoded += _u8(value["target_cardinality"])
    encoded += _hex(value["mailbox_ref_hex"])
    encoded += _u64(value["delivery_max_payload_bytes"])
    encoded += _u64(value["delivery_max_message_age_nanos"])
    encoded += _u8(value["delivery_overflow_policy"])
    encoded += _u32(value["mailbox_capacity_items"])
    encoded += _u64(value["mailbox_capacity_bytes"])
    encoded += _u64(value["mailbox_max_queue_age_nanos"])
    encoded += _u32(value["mailbox_max_inflight"])
    encoded += _u64(value["mailbox_max_retained_bytes"])
    encoded += _u8(value["mailbox_overflow_policy"])
    assert len(encoded) == PXTA_RECORD_BYTES
    return bytes(encoded)


def _canonical_pxta(values: list[dict[str, Any]]) -> bytes:
    records = sorted(
        (_encode_binding_record(value) for value in values), key=lambda item: item[:16]
    )
    return PXTA_MAGIC + _u16(PXTA_VERSION) + _u32(len(records)) + b"".join(records)


class _Cursor:
    def __init__(self, record: bytes) -> None:
        self.record = record
        self.offset = 0

    def take(self, length: int) -> bytes:
        value = self.record[self.offset : self.offset + length]
        self.offset += length
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]


def _decode_binding_record(record: bytes, record_index: int) -> dict[str, Any]:
    cursor = _Cursor(record)
    value = {
        "binding_id": cursor.take(16),
        "source_instance": cursor.take(16),
        "source_port": cursor.take(16),
        "source_direction": cursor.u8(),
        "source_schema_id": cursor.take(16),
        "source_schema_version": cursor.u32(),
        "source_schema_digest": cursor.take(32),
        "source_interaction": cursor.u8(),
        "source_cardinality": cursor.u8(),
        "target_instance": cursor.take(16),
        "target_port": cursor.take(16),
        "target_direction": cursor.u8(),
        "target_schema_id": cursor.take(16),
        "target_schema_version": cursor.u32(),
        "target_schema_digest": cursor.take(32),
        "target_interaction": cursor.u8(),
        "target_cardinality": cursor.u8(),
        "mailbox_ref": cursor.take(16),
        "delivery_max_payload_bytes": cursor.u64(),
        "delivery_max_message_age_nanos": cursor.u64(),
        "delivery_overflow_policy": cursor.u8(),
        "mailbox_capacity_items": cursor.u32(),
        "mailbox_capacity_bytes": cursor.u64(),
        "mailbox_max_queue_age_nanos": cursor.u64(),
        "mailbox_max_inflight": cursor.u32(),
        "mailbox_max_retained_bytes": cursor.u64(),
        "mailbox_overflow_policy": cursor.u8(),
        "canonical_record": record,
    }
    assert cursor.offset == PXTA_RECORD_BYTES
    valid_enums = (
        value["source_direction"] in {1, 2}
        and value["target_direction"] in {1, 2}
        and value["source_interaction"] in {1, 2}
        and value["target_interaction"] in {1, 2}
        and value["source_cardinality"] == 1
        and value["target_cardinality"] == 1
        and value["delivery_overflow_policy"] in {1, 2, 3, 4, 5}
        and value["mailbox_overflow_policy"] in {1, 2, 3, 4, 5}
    )
    if not valid_enums:
        raise PxtaReject(PXTA_ERROR_CODES["invalid_enum_value"], record_index)
    positive_names = (
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
    same_schema = (
        value["source_schema_id"],
        value["source_schema_version"],
        value["source_schema_digest"],
    ) == (
        value["target_schema_id"],
        value["target_schema_version"],
        value["target_schema_digest"],
    )
    valid = (
        all(value[name] > 0 for name in positive_names)
        and value["source_direction"] == 1
        and value["target_direction"] == 2
        and same_schema
        and value["source_interaction"] == value["target_interaction"]
        and value["delivery_overflow_policy"] == value["mailbox_overflow_policy"]
        and value["mailbox_max_queue_age_nanos"] <= value["delivery_max_message_age_nanos"]
        and value["mailbox_capacity_bytes"] >= value["delivery_max_payload_bytes"]
        and value["mailbox_max_retained_bytes"] >= value["mailbox_capacity_bytes"]
        and not (
            value["source_interaction"] == 2 and value["delivery_overflow_policy"] not in {1, 5}
        )
    )
    if not valid:
        raise PxtaReject(PXTA_ERROR_CODES["invalid_assignment"], record_index)
    return value


def _parse_pxta(frame: bytes) -> list[dict[str, Any]]:
    if len(frame) > PXTA_MAX_BYTES:
        raise PxtaReject(PXTA_ERROR_CODES["frame_too_large"])
    if len(frame) < PXTA_HEADER_BYTES:
        raise PxtaReject(PXTA_ERROR_CODES["truncated"])
    if frame[:4] != PXTA_MAGIC:
        raise PxtaReject(PXTA_ERROR_CODES["invalid_magic"])
    version, count = struct.unpack_from(">HI", frame, 4)
    if version != PXTA_VERSION:
        raise PxtaReject(PXTA_ERROR_CODES["unsupported_version"])
    if count > PXTA_MAX_RECORDS:
        raise PxtaReject(PXTA_ERROR_CODES["assignment_count_exceeded"])
    expected_length = PXTA_HEADER_BYTES + count * PXTA_RECORD_BYTES
    if len(frame) < expected_length:
        raise PxtaReject(PXTA_ERROR_CODES["truncated"])
    if len(frame) != expected_length:
        raise PxtaReject(PXTA_ERROR_CODES["invalid_frame_length"])
    records = []
    for index in range(count):
        start = PXTA_HEADER_BYTES + index * PXTA_RECORD_BYTES
        records.append(_decode_binding_record(frame[start : start + PXTA_RECORD_BYTES], index))
    ordered = sorted(records, key=lambda item: item["binding_id"])
    for index, current in enumerate(ordered):
        for previous in ordered[:index]:
            if previous["binding_id"] == current["binding_id"]:
                raise PxtaReject(PXTA_ERROR_CODES["duplicate_binding_id"])
            if (previous["source_instance"], previous["source_port"]) == (
                current["source_instance"],
                current["source_port"],
            ):
                raise PxtaReject(PXTA_ERROR_CODES["duplicate_source_endpoint"])
            if (previous["target_instance"], previous["target_port"]) == (
                current["target_instance"],
                current["target_port"],
            ):
                raise PxtaReject(PXTA_ERROR_CODES["duplicate_target_endpoint"])
            if previous["mailbox_ref"] == current["mailbox_ref"]:
                raise PxtaReject(PXTA_ERROR_CODES["duplicate_mailbox_ref"])
    canonical = (
        PXTA_MAGIC
        + _u16(PXTA_VERSION)
        + _u32(len(ordered))
        + b"".join(item["canonical_record"] for item in ordered)
    )
    if canonical != frame:
        raise PxtaReject(PXTA_ERROR_CODES["non_canonical_frame"])
    return ordered


def _valid_duration(value: int) -> bool:
    return 0 < value <= MAX_EXECUTION_DURATION_NANOS


def _encode_domain_record(value: dict[str, Any]) -> bytes:
    encoded = bytearray(_hex(value["domain_ref_hex"]))
    encoded += _u32(value["max_outstanding"])
    encoded += _u32(value["control_reserved"])
    encoded += _u64(value["capacity_window_nanos"])
    encoded += _u64(value["control_reserved_run_budget_nanos"])
    encoded += _u64(value["start_budget_nanos"])
    encoded += _u64(value["drain_budget_nanos"])
    encoded += _u64(value["cleanup_budget_nanos"])
    assert len(encoded) == PXTE_DOMAIN_RECORD_BYTES
    return bytes(encoded)


def _encode_mailbox_execution_record(value: dict[str, Any]) -> bytes:
    encoded = bytearray(_hex(value["binding_id_hex"]))
    encoded += _hex(value["mailbox_ref_hex"])
    encoded += _hex(value["target_instance_hex"])
    encoded += _hex(value["domain_ref_hex"])
    encoded += _hex(value["card_definition_ref_hex"])
    encoded += _hex(value["card_implementation_ref_hex"])
    encoded += _hex(value["definition_digest_hex"])
    encoded += _hex(value["artifact_digest_hex"])
    encoded += _hex(value["config_digest_hex"])
    encoded += _u8(value["call_model"])
    encoded += _u8(value["workload_kind"])
    encoded += _u8(value["blocking_risk"])
    encoded += _u8(value["run_bound_provenance"])
    encoded += _u8(value["dispatch_class"])
    encoded += _u32(value["service_cost_tokens"])
    encoded += _u32(value["minimum_service_weight"])
    encoded += _u16(value["max_burst"])
    encoded += _u32(value["max_arrivals_per_window"])
    encoded += _u64(value["max_nonpreemptive_run_nanos"])
    encoded += _u64(value["run_budget_nanos"])
    encoded += _u64(value["cleanup_budget_nanos"])
    encoded += _u8(value["overrun_action"])
    assert len(encoded) == PXTE_MAILBOX_RECORD_BYTES
    return bytes(encoded)


def _canonical_pxte(domains: list[dict[str, Any]], mailboxes: list[dict[str, Any]]) -> bytes:
    domain_records = sorted(
        (_encode_domain_record(value) for value in domains), key=lambda item: item[:16]
    )
    mailbox_records = sorted(
        (_encode_mailbox_execution_record(value) for value in mailboxes),
        key=lambda item: (item[:16], item[16:32], item[32:48], item[48:64]),
    )
    return (
        PXTE_MAGIC
        + _u16(PXTE_VERSION)
        + _u32(len(domain_records))
        + _u32(len(mailbox_records))
        + b"".join(domain_records)
        + b"".join(mailbox_records)
    )


def _decode_domain_record(record: bytes, record_index: int) -> dict[str, Any]:
    cursor = _Cursor(record)
    value = {
        "domain_ref": cursor.take(16),
        "max_outstanding": cursor.u32(),
        "control_reserved": cursor.u32(),
        "capacity_window_nanos": cursor.u64(),
        "control_reserved_run_budget_nanos": cursor.u64(),
        "start_budget_nanos": cursor.u64(),
        "drain_budget_nanos": cursor.u64(),
        "cleanup_budget_nanos": cursor.u64(),
        "canonical_record": record,
    }
    assert cursor.offset == PXTE_DOMAIN_RECORD_BYTES
    control_valid = (
        value["control_reserved"] == 0 and value["control_reserved_run_budget_nanos"] == 0
    ) or (
        value["control_reserved"] > 0
        and _valid_duration(value["control_reserved_run_budget_nanos"])
        and value["control_reserved_run_budget_nanos"] <= value["capacity_window_nanos"]
    )
    valid = (
        0 < value["max_outstanding"] <= MAX_DOMAIN_OUTSTANDING
        and value["control_reserved"] <= value["max_outstanding"]
        and _valid_duration(value["capacity_window_nanos"])
        and _valid_duration(value["start_budget_nanos"])
        and _valid_duration(value["drain_budget_nanos"])
        and _valid_duration(value["cleanup_budget_nanos"])
        and control_valid
    )
    if not valid:
        raise PxteReject(PXTE_ERROR_CODES["invalid_domain"], 1, record_index)
    return value


def _decode_mailbox_execution_record(record: bytes, record_index: int) -> dict[str, Any]:
    cursor = _Cursor(record)
    value = {
        "binding_id": cursor.take(16),
        "mailbox_ref": cursor.take(16),
        "target_instance": cursor.take(16),
        "domain_ref": cursor.take(16),
        "card_definition_ref": cursor.take(16),
        "card_implementation_ref": cursor.take(16),
        "definition_digest": cursor.take(32),
        "artifact_digest": cursor.take(32),
        "config_digest": cursor.take(32),
        "call_model": cursor.u8(),
        "workload_kind": cursor.u8(),
        "blocking_risk": cursor.u8(),
        "run_bound_provenance": cursor.u8(),
        "dispatch_class": cursor.u8(),
        "service_cost_tokens": cursor.u32(),
        "minimum_service_weight": cursor.u32(),
        "max_burst": cursor.u16(),
        "max_arrivals_per_window": cursor.u32(),
        "max_nonpreemptive_run_nanos": cursor.u64(),
        "run_budget_nanos": cursor.u64(),
        "cleanup_budget_nanos": cursor.u64(),
        "overrun_action": cursor.u8(),
        "canonical_record": record,
    }
    assert cursor.offset == PXTE_MAILBOX_RECORD_BYTES
    valid_enums = (
        value["call_model"] in {1, 2, 3}
        and value["workload_kind"] in {1, 2, 3, 4, 5, 6}
        and value["blocking_risk"] in {1, 2, 3}
        and value["run_bound_provenance"] in {1, 2, 3, 4}
        and value["dispatch_class"] in {1, 2, 3, 4}
        and value["overrun_action"] in {1, 2, 3, 4}
    )
    if not valid_enums:
        raise PxteReject(PXTE_ERROR_CODES["invalid_enum_value"], 2, record_index)
    valid = (
        0 < value["service_cost_tokens"] <= MAX_SERVICE_COST_TOKENS
        and 0 < value["minimum_service_weight"] <= MAX_MINIMUM_SERVICE_WEIGHT
        and value["max_burst"] > 0
        and 0 < value["max_arrivals_per_window"] <= MAX_ARRIVALS_PER_WINDOW
        and _valid_duration(value["max_nonpreemptive_run_nanos"])
        and _valid_duration(value["run_budget_nanos"])
        and _valid_duration(value["cleanup_budget_nanos"])
        and value["max_nonpreemptive_run_nanos"] <= value["run_budget_nanos"]
    )
    if not valid:
        raise PxteReject(PXTE_ERROR_CODES["invalid_mailbox_execution"], 2, record_index)
    return value


def _same_subject_contract(left: dict[str, Any], right: dict[str, Any]) -> bool:
    names = (
        "target_instance",
        "domain_ref",
        "card_definition_ref",
        "card_implementation_ref",
        "definition_digest",
        "artifact_digest",
        "config_digest",
        "call_model",
        "workload_kind",
        "blocking_risk",
        "run_bound_provenance",
    )
    return all(left[name] == right[name] for name in names)


def _validate_execution_records(
    domains: list[dict[str, Any]], mailboxes: list[dict[str, Any]]
) -> None:
    for index, domain in enumerate(domains):
        if any(previous["domain_ref"] == domain["domain_ref"] for previous in domains[:index]):
            raise PxteReject(PXTE_ERROR_CODES["duplicate_domain_ref"])
    for index, execution in enumerate(mailboxes):
        for previous in mailboxes[:index]:
            if previous["binding_id"] == execution["binding_id"]:
                raise PxteReject(PXTE_ERROR_CODES["duplicate_execution_binding"])
            if previous["mailbox_ref"] == execution["mailbox_ref"]:
                raise PxteReject(PXTE_ERROR_CODES["duplicate_execution_mailbox"])
        if not any(domain["domain_ref"] == execution["domain_ref"] for domain in domains):
            raise PxteReject(PXTE_ERROR_CODES["orphan_domain_ref"])
        loop_eligible = (
            execution["call_model"] == 1
            and execution["workload_kind"] in {1, 2}
            and execution["blocking_risk"] == 1
            and execution["run_bound_provenance"] in {2, 3}
        )
        if not loop_eligible:
            raise PxteReject(PXTE_ERROR_CODES["unsupported_loop_execution"])
        if execution["overrun_action"] not in {2, 3}:
            raise PxteReject(PXTE_ERROR_CODES["unsafe_loop_overrun_action"])
    for domain in domains:
        assigned = [item for item in mailboxes if item["domain_ref"] == domain["domain_ref"]]
        if not assigned:
            raise PxteReject(PXTE_ERROR_CODES["unused_domain_ref"])
        total = 0
        control = 0
        for execution in assigned:
            if (
                execution["run_budget_nanos"] > domain["capacity_window_nanos"]
                or execution["cleanup_budget_nanos"] > domain["cleanup_budget_nanos"]
            ):
                raise PxteReject(PXTE_ERROR_CODES["invalid_mailbox_execution"])
            demand = execution["max_arrivals_per_window"] * (
                execution["run_budget_nanos"] + execution["cleanup_budget_nanos"]
            )
            total += demand
            if execution["dispatch_class"] == 1:
                if domain["control_reserved"] == 0:
                    raise PxteReject(PXTE_ERROR_CODES["control_reservation_required"])
                control += demand
        if total > domain["capacity_window_nanos"]:
            raise PxteReject(PXTE_ERROR_CODES["domain_utilization_exceeded"])
        if control > domain["control_reserved_run_budget_nanos"]:
            raise PxteReject(PXTE_ERROR_CODES["control_utilization_exceeded"])
        if domain["control_reserved"] == domain["max_outstanding"] and any(
            execution["dispatch_class"] != 1 for execution in assigned
        ):
            raise PxteReject(PXTE_ERROR_CODES["shared_capacity_required"])


def _parse_pxte(frame: bytes) -> dict[str, list[dict[str, Any]]]:
    if len(frame) > PXTE_MAX_BYTES:
        raise PxteReject(PXTE_ERROR_CODES["frame_too_large"])
    if len(frame) < PXTE_HEADER_BYTES:
        raise PxteReject(PXTE_ERROR_CODES["truncated"])
    if frame[:4] != PXTE_MAGIC:
        raise PxteReject(PXTE_ERROR_CODES["invalid_magic"])
    version, domain_count, mailbox_count = struct.unpack_from(">HII", frame, 4)
    if version != PXTE_VERSION:
        raise PxteReject(PXTE_ERROR_CODES["unsupported_version"])
    if domain_count > PXTE_MAX_DOMAINS:
        raise PxteReject(PXTE_ERROR_CODES["domain_count_exceeded"])
    if mailbox_count > PXTE_MAX_MAILBOXES:
        raise PxteReject(PXTE_ERROR_CODES["execution_count_exceeded"])
    expected_length = (
        PXTE_HEADER_BYTES
        + domain_count * PXTE_DOMAIN_RECORD_BYTES
        + mailbox_count * PXTE_MAILBOX_RECORD_BYTES
    )
    if len(frame) < expected_length:
        raise PxteReject(PXTE_ERROR_CODES["truncated"])
    if len(frame) != expected_length:
        raise PxteReject(PXTE_ERROR_CODES["invalid_frame_length"])
    domains = []
    for index in range(domain_count):
        start = PXTE_HEADER_BYTES + index * PXTE_DOMAIN_RECORD_BYTES
        domains.append(
            _decode_domain_record(frame[start : start + PXTE_DOMAIN_RECORD_BYTES], index)
        )
    mailbox_start = PXTE_HEADER_BYTES + domain_count * PXTE_DOMAIN_RECORD_BYTES
    mailboxes = []
    for index in range(mailbox_count):
        start = mailbox_start + index * PXTE_MAILBOX_RECORD_BYTES
        mailboxes.append(
            _decode_mailbox_execution_record(
                frame[start : start + PXTE_MAILBOX_RECORD_BYTES], index
            )
        )
    if not domains or not mailboxes:
        raise PxteReject(PXTE_ERROR_CODES["missing_records"])
    ordered_domains = sorted(domains, key=lambda item: item["domain_ref"])
    ordered_mailboxes = sorted(
        mailboxes,
        key=lambda item: (
            item["binding_id"],
            item["mailbox_ref"],
            item["target_instance"],
            item["domain_ref"],
        ),
    )
    _validate_execution_records(ordered_domains, ordered_mailboxes)
    canonical = (
        PXTE_MAGIC
        + _u16(PXTE_VERSION)
        + _u32(len(ordered_domains))
        + _u32(len(ordered_mailboxes))
        + b"".join(item["canonical_record"] for item in ordered_domains)
        + b"".join(item["canonical_record"] for item in ordered_mailboxes)
    )
    if canonical != frame:
        raise PxteReject(PXTE_ERROR_CODES["non_canonical_frame"])
    return {"domains": ordered_domains, "mailboxes": ordered_mailboxes}


def _validate_target_plan(
    bindings: list[dict[str, Any]], execution: dict[str, list[dict[str, Any]]]
) -> None:
    if any(
        binding["delivery_overflow_policy"] == 5 or binding["mailbox_overflow_policy"] == 5
        for binding in bindings
    ):
        raise TargetPlanReject(TARGET_PLAN_ERROR_CODES["block_until_deadline_forbidden"])
    for mailbox in execution["mailboxes"]:
        binding = next(
            (item for item in bindings if item["binding_id"] == mailbox["binding_id"]), None
        )
        if binding is None:
            raise TargetPlanReject(TARGET_PLAN_ERROR_CODES["orphan_binding"])
        if binding["mailbox_ref"] != mailbox["mailbox_ref"]:
            raise TargetPlanReject(TARGET_PLAN_ERROR_CODES["binding_mailbox_mismatch"])
        if binding["target_instance"] != mailbox["target_instance"]:
            raise TargetPlanReject(TARGET_PLAN_ERROR_CODES["binding_target_mismatch"])
    for index, current in enumerate(execution["mailboxes"]):
        for previous in execution["mailboxes"][:index]:
            if previous["target_instance"] == current[
                "target_instance"
            ] and not _same_subject_contract(previous, current):
                raise TargetPlanReject(TARGET_PLAN_ERROR_CODES["subject_execution_mismatch"])

    binding_by_id = {binding["binding_id"]: binding for binding in bindings}
    domain_by_ref = {domain["domain_ref"]: domain for domain in execution["domains"]}
    for control in (
        mailbox for mailbox in execution["mailboxes"] if mailbox["dispatch_class"] == 1
    ):
        domain = domain_by_ref[control["domain_ref"]]
        control_binding = binding_by_id[control["binding_id"]]
        slo = control_binding["mailbox_max_queue_age_nanos"]
        window = domain["capacity_window_nanos"]
        # The extra window is a conservative phase allowance because the
        # signed arrival envelope does not define a sliding-window phase.
        arrival_horizon = (slo + window - 1) // window + 1
        assigned = [
            mailbox
            for mailbox in execution["mailboxes"]
            if mailbox["domain_ref"] == control["domain_ref"]
        ]
        occupancy = {
            mailbox["binding_id"]: max(
                mailbox["run_budget_nanos"] + mailbox["cleanup_budget_nanos"],
                mailbox["max_nonpreemptive_run_nanos"],
            )
            for mailbox in assigned
        }
        wait_bound = max(occupancy.values())
        wait_bound += (
            control_binding["mailbox_capacity_items"] - 1
        ) * occupancy[control["binding_id"]]
        for peer in assigned:
            if peer["binding_id"] == control["binding_id"]:
                continue
            peer_binding = binding_by_id[peer["binding_id"]]
            peer_work = peer_binding["mailbox_capacity_items"] + (
                arrival_horizon * peer["max_arrivals_per_window"]
            )
            wait_bound += peer_work * occupancy[peer["binding_id"]]
        # Owner-local deadline expiry is inclusive at equality.
        if wait_bound >= slo:
            raise TargetPlanReject(TARGET_PLAN_ERROR_CODES["control_start_slo_exceeded"])


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
    return (
        S2_MAGIC
        + _u16(S2_VERSION)
        + _u16(len(fields))
        + b"".join(_tlv(tag, value) for tag, value in fields)
    )


def _parse_s2(frame: bytes) -> list[tuple[int, bytes]]:
    if len(frame) > S2_MAX_BYTES:
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
    fields: list[tuple[int, bytes]] = []
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


def _decode_s2(frame: bytes) -> dict[int, bytes]:
    values = dict(_parse_s2(frame))
    if struct.unpack(">H", values[1])[0] != 1:
        raise S2Reject(S2_ERROR_CODES["unsupported_version"], 1)
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
    semantic_valid = (
        values[3] == values[15]
        and values[9] == values[16]
        and values[10] == values[17]
        and struct.unpack(">Q", values[29])[0] > 0
        and struct.unpack(">Q", values[31])[0] <= struct.unpack(">Q", values[30])[0]
        and ((values[22] == _u16(0) and values[23] == bytes(32)) or values[22] == _u16(1))
    )
    if not semantic_valid:
        raise S2Reject(S2_ERROR_CODES["invalid_field_value"])
    return values


def _verify_s2_signatures(
    values: dict[int, bytes], tenure_public_key: bytes, request_public_key: bytes
) -> None:
    tenure_transcript = _signing_transcript(
        TENURE_SIGNING_DOMAIN,
        [(tag, values[wire_tag]) for tag, wire_tag in enumerate(range(11, 20), start=1)],
    )
    request_transcript = _signing_transcript(
        AUTH_SIGNING_DOMAIN, [(tag, values[tag]) for tag in range(1, 37)]
    )
    try:
        Ed25519PublicKey.from_public_bytes(tenure_public_key).verify(values[20], tenure_transcript)
        Ed25519PublicKey.from_public_bytes(request_public_key).verify(
            values[37], request_transcript
        )
    except (InvalidSignature, ValueError) as error:
        raise SignatureReject("signed S2 envelope authentication failed") from error


def _build_s2(composite_digest: bytes) -> dict[str, bytes]:
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
            composite_digest,
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
    tenure_private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(TEST_ONLY_KEYS["tenure_authority_seed_hex"])
    )
    tenure_signature = tenure_private_key.sign(
        _signing_transcript(TENURE_SIGNING_DOMAIN, tenure_fields)
    )
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
            composite_digest,
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
        (7, composite_digest),
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
    request_private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(TEST_ONLY_KEYS["request_writer_seed_hex"])
    )
    request_signature = request_private_key.sign(
        _signing_transcript(AUTH_SIGNING_DOMAIN, unsigned_fields)
    )
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


def _build_vector(
    bindings: list[dict[str, Any]] | None = None,
    domains: list[dict[str, Any]] | None = None,
    mailboxes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    binding_values = SEMANTIC["bindings"] if bindings is None else bindings
    domain_values = SEMANTIC["domains"] if domains is None else domains
    mailbox_values = SEMANTIC["mailbox_executions"] if mailboxes is None else mailboxes
    pxta = _canonical_pxta(binding_values)
    pxte = _canonical_pxte(domain_values, mailbox_values)
    pxta_digest = _canonical_digest(PXTA_DIGEST_DOMAIN, [pxta])
    pxte_digest = _canonical_digest(PXTE_DIGEST_DOMAIN, [pxte])
    composite_digest = _canonical_digest(COMPOSITE_DIGEST_DOMAIN, [pxta_digest, pxte_digest])
    s2 = _build_s2(composite_digest)
    envelope = s2["envelope"]
    outer = (
        PXAR_MAGIC
        + _u16(PXAR_V2_VERSION)
        + _u32(len(envelope))
        + _u32(len(pxta))
        + _u32(len(pxte))
        + envelope
        + pxta
        + pxte
    )
    return {
        **s2,
        "pxta": pxta,
        "pxte": pxte,
        "pxta_digest": pxta_digest,
        "pxte_digest": pxte_digest,
        "composite_digest": composite_digest,
        "outer": outer,
    }


def _parse_outer_v2(frame: bytes) -> dict[str, Any]:
    if len(frame) > PXAR_V2_MAX_BYTES:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["frame_too_large"])
    if len(frame) < PXAR_V2_HEADER_BYTES:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["truncated"])
    if frame[:4] != PXAR_MAGIC:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["invalid_magic"])
    version, envelope_length, pxta_length, pxte_length = struct.unpack_from(">HIII", frame, 4)
    if version != PXAR_V2_VERSION:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["unsupported_version"])
    expected_length = PXAR_V2_HEADER_BYTES + envelope_length + pxta_length + pxte_length
    if len(frame) < expected_length:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["truncated"])
    if len(frame) != expected_length:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["invalid_frame_length"])
    envelope_start = PXAR_V2_HEADER_BYTES
    envelope_end = envelope_start + envelope_length
    pxta_end = envelope_end + pxta_length
    envelope = frame[envelope_start:envelope_end]
    pxta = frame[envelope_end:pxta_end]
    pxte = frame[pxta_end:]
    try:
        s2_values = _decode_s2(envelope)
    except S2Reject as error:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["envelope_rejected"], error.code) from error
    try:
        bindings = _parse_pxta(pxta)
    except PxtaReject as error:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["bindings_rejected"], error.code) from error
    try:
        execution = _parse_pxte(pxte)
    except PxteReject as error:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["execution_rejected"], error.code) from error
    try:
        _validate_target_plan(bindings, execution)
    except TargetPlanReject as error:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["target_plan_rejected"], error.code) from error
    pxta_digest = _canonical_digest(PXTA_DIGEST_DOMAIN, [pxta])
    pxte_digest = _canonical_digest(PXTE_DIGEST_DOMAIN, [pxte])
    composite_digest = _canonical_digest(COMPOSITE_DIGEST_DOMAIN, [pxta_digest, pxte_digest])
    if s2_values[7] != composite_digest:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["commitment_mismatch"])
    return {
        "s2_values": s2_values,
        "bindings": bindings,
        "execution": execution,
        "pxta_digest": pxta_digest,
        "pxte_digest": pxte_digest,
        "composite_digest": composite_digest,
    }


def _admit_outer_v2(
    frame: bytes, tenure_public_key: bytes, request_public_key: bytes
) -> dict[str, Any]:
    parsed = _parse_outer_v2(frame)
    _verify_s2_signatures(parsed["s2_values"], tenure_public_key, request_public_key)
    return parsed


def _parse_outer_v1_version(frame: bytes) -> None:
    if len(frame) < PXAR_V1_HEADER_BYTES:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["truncated"])
    if frame[:4] != PXAR_MAGIC:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["invalid_magic"])
    if struct.unpack_from(">H", frame, 4)[0] != PXAR_V1_VERSION:
        raise PxarV2Reject(PXAR_V2_ERROR_CODES["unsupported_version"])


def _fixture_document() -> dict[str, Any]:
    vector = _build_vector()
    parsed_pxta = _parse_pxta(vector["pxta"])
    parsed_pxte = _parse_pxte(vector["pxte"])
    return {
        "fixture_version": 2,
        "source": "independent Python struct/hashlib/cryptography S4 contract fixture",
        "test_only_notice": "TEST-ONLY deterministic keys; never production",
        "test_only_keys": TEST_ONLY_KEYS,
        "semantic": SEMANTIC,
        "protocol": PROTOCOL,
        "pxta_error_codes": PXTA_ERROR_CODES,
        "pxte_error_codes": PXTE_ERROR_CODES,
        "target_plan_error_codes": TARGET_PLAN_ERROR_CODES,
        "pxar_v2_error_codes": PXAR_V2_ERROR_CODES,
        "expected": {
            "canonical_binding_order_hex": [item["binding_id"].hex() for item in parsed_pxta],
            "canonical_domain_order_hex": [
                item["domain_ref"].hex() for item in parsed_pxte["domains"]
            ],
            "canonical_execution_binding_order_hex": [
                item["binding_id"].hex() for item in parsed_pxte["mailboxes"]
            ],
            "pxta_body_hex": vector["pxta"].hex(),
            "pxta_body_length": len(vector["pxta"]),
            "pxta_digest_hex": vector["pxta_digest"].hex(),
            "pxte_body_hex": vector["pxte"].hex(),
            "pxte_body_length": len(vector["pxte"]),
            "pxte_digest_hex": vector["pxte_digest"].hex(),
            "composite_digest_hex": vector["composite_digest"].hex(),
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
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for name, member in pairs:
            if name in value:
                raise ValueError(f"duplicate fixture key: {name}")
            value[name] = member
        return value

    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def _mutate_pxte_field(frame: bytes, absolute_offset: int, replacement: bytes) -> bytes:
    mutated = bytearray(frame)
    mutated[absolute_offset : absolute_offset + len(replacement)] = replacement
    return bytes(mutated)


def test_independent_rebuild_matches_v2_fixture() -> None:
    assert _load_fixture() == _fixture_document()


def test_pxte_has_exact_fixed_layout_and_binding_superset_is_legal() -> None:
    vector = _build_vector()
    assert (
        len(vector["pxte"])
        == PXTE_HEADER_BYTES + PXTE_DOMAIN_RECORD_BYTES + PXTE_MAILBOX_RECORD_BYTES
    )
    parsed = _admit_outer_v2(
        vector["outer"], vector["tenure_public_key"], vector["request_public_key"]
    )
    assert [item["binding_id"].hex() for item in parsed["bindings"]] == ["31" * 16, "32" * 16]
    assert [item["binding_id"].hex() for item in parsed["execution"]["mailboxes"]] == ["31" * 16]
    assert parsed["s2_values"][7] == vector["composite_digest"]


def test_v1_and_v2_outer_decoders_mutually_reject_without_fallback() -> None:
    vector = _build_vector()
    v1_outer = (
        PXAR_MAGIC
        + _u16(PXAR_V1_VERSION)
        + _u32(len(vector["envelope"]))
        + _u32(len(vector["pxta"]))
        + vector["envelope"]
        + vector["pxta"]
    )
    with pytest.raises(PxarV2Reject) as v2_rejects_v1:
        _parse_outer_v2(v1_outer)
    assert v2_rejects_v1.value.code == PXAR_V2_ERROR_CODES["unsupported_version"]
    with pytest.raises(PxarV2Reject) as v1_rejects_v2:
        _parse_outer_v1_version(vector["outer"])
    assert v1_rejects_v2.value.code == PXAR_V2_ERROR_CODES["unsupported_version"]


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (lambda frame: b"BAD!" + frame[4:], PXTE_ERROR_CODES["invalid_magic"]),
        (
            lambda frame: frame[:4] + _u16(2) + frame[6:],
            PXTE_ERROR_CODES["unsupported_version"],
        ),
        (
            lambda frame: frame[:6] + _u32(PXTE_MAX_DOMAINS + 1) + frame[10:],
            PXTE_ERROR_CODES["domain_count_exceeded"],
        ),
        (
            lambda frame: frame[:10] + _u32(PXTE_MAX_MAILBOXES + 1) + frame[14:],
            PXTE_ERROR_CODES["execution_count_exceeded"],
        ),
        (lambda frame: frame[:-1], PXTE_ERROR_CODES["truncated"]),
        (lambda frame: frame + b"\0", PXTE_ERROR_CODES["invalid_frame_length"]),
        (
            lambda frame: _mutate_pxte_field(
                frame,
                PXTE_HEADER_BYTES + PXTE_DOMAIN_MAX_OUTSTANDING_OFFSET,
                _u32(0),
            ),
            PXTE_ERROR_CODES["invalid_domain"],
        ),
        (
            lambda frame: _mutate_pxte_field(
                frame,
                PXTE_HEADER_BYTES + PXTE_DOMAIN_RECORD_BYTES + PXTE_MAILBOX_ENUM_OFFSET,
                b"\x63",
            ),
            PXTE_ERROR_CODES["invalid_enum_value"],
        ),
        (
            lambda frame: _mutate_pxte_field(
                frame,
                PXTE_HEADER_BYTES + PXTE_DOMAIN_RECORD_BYTES + PXTE_MAILBOX_SERVICE_COST_OFFSET,
                _u32(0),
            ),
            PXTE_ERROR_CODES["invalid_mailbox_execution"],
        ),
    ],
)
def test_pxte_decoder_has_stable_structural_errors(mutator: Any, expected_code: int) -> None:
    with pytest.raises(PxteReject) as raised:
        _parse_pxte(mutator(_build_vector()["pxte"]))
    assert raised.value.code == expected_code


def test_pxte_duplicate_and_orphan_rejections_are_stable() -> None:
    domain = copy.deepcopy(SEMANTIC["domains"][0])
    execution = copy.deepcopy(SEMANTIC["mailbox_executions"][0])
    duplicate_domain_body = _canonical_pxte([domain, copy.deepcopy(domain)], [execution])
    with pytest.raises(PxteReject) as duplicate_domain:
        _parse_pxte(duplicate_domain_body)
    assert duplicate_domain.value.code == PXTE_ERROR_CODES["duplicate_domain_ref"]

    second = copy.deepcopy(execution)
    second["mailbox_ref_hex"] = "82" * 16
    second["target_instance_hex"] = "62" * 16
    with pytest.raises(PxteReject) as duplicate_binding:
        _parse_pxte(_canonical_pxte([domain], [execution, second]))
    assert duplicate_binding.value.code == PXTE_ERROR_CODES["duplicate_execution_binding"]

    second["binding_id_hex"] = "32" * 16
    second["mailbox_ref_hex"] = execution["mailbox_ref_hex"]
    with pytest.raises(PxteReject) as duplicate_mailbox:
        _parse_pxte(_canonical_pxte([domain], [execution, second]))
    assert duplicate_mailbox.value.code == PXTE_ERROR_CODES["duplicate_execution_mailbox"]

    orphan = copy.deepcopy(execution)
    orphan["domain_ref_hex"] = "92" * 16
    with pytest.raises(PxteReject) as orphan_domain:
        _parse_pxte(_canonical_pxte([domain], [orphan]))
    assert orphan_domain.value.code == PXTE_ERROR_CODES["orphan_domain_ref"]


def test_loop_eligibility_and_utilization_fail_closed() -> None:
    domain = copy.deepcopy(SEMANTIC["domains"][0])
    execution = copy.deepcopy(SEMANTIC["mailbox_executions"][0])

    unsupported = copy.deepcopy(execution)
    unsupported["workload_kind"] = 3
    with pytest.raises(PxteReject) as unsupported_error:
        _parse_pxte(_canonical_pxte([domain], [unsupported]))
    assert unsupported_error.value.code == PXTE_ERROR_CODES["unsupported_loop_execution"]

    unsafe_overrun = copy.deepcopy(execution)
    unsafe_overrun["overrun_action"] = 1
    with pytest.raises(PxteReject) as unsafe_overrun_error:
        _parse_pxte(_canonical_pxte([domain], [unsafe_overrun]))
    assert unsafe_overrun_error.value.code == PXTE_ERROR_CODES["unsafe_loop_overrun_action"]

    no_reserve = copy.deepcopy(domain)
    no_reserve["control_reserved"] = 0
    no_reserve["control_reserved_run_budget_nanos"] = 0
    with pytest.raises(PxteReject) as reserve_error:
        _parse_pxte(_canonical_pxte([no_reserve], [execution]))
    assert reserve_error.value.code == PXTE_ERROR_CODES["control_reservation_required"]

    all_reserved = copy.deepcopy(domain)
    all_reserved["max_outstanding"] = 1
    non_control = copy.deepcopy(execution)
    non_control["dispatch_class"] = 2
    with pytest.raises(PxteReject) as shared_capacity_error:
        _parse_pxte(_canonical_pxte([all_reserved], [non_control]))
    assert shared_capacity_error.value.code == PXTE_ERROR_CODES["shared_capacity_required"]
    overloaded_non_control = copy.deepcopy(non_control)
    overloaded_non_control["max_arrivals_per_window"] = 5
    with pytest.raises(PxteReject) as precedence_error:
        _parse_pxte(_canonical_pxte([all_reserved], [overloaded_non_control]))
    assert precedence_error.value.code == PXTE_ERROR_CODES["domain_utilization_exceeded"]
    assert _parse_pxte(_canonical_pxte([all_reserved], [execution]))["mailboxes"][0][
        "dispatch_class"
    ] == 1
    assert _parse_pxte(_canonical_pxte([domain], [non_control]))["mailboxes"][0][
        "dispatch_class"
    ] == 2

    control_overload = copy.deepcopy(domain)
    # Run demand is exactly 2B, but run plus cleanup demand is 4B.
    control_overload["control_reserved_run_budget_nanos"] = 2_000_000_000
    with pytest.raises(PxteReject) as control_error:
        _parse_pxte(_canonical_pxte([control_overload], [execution]))
    assert control_error.value.code == PXTE_ERROR_CODES["control_utilization_exceeded"]

    domain_overload = copy.deepcopy(domain)
    domain_overload["capacity_window_nanos"] = 2_000_000_000
    domain_overload["control_reserved_run_budget_nanos"] = 2_000_000_000
    non_control = copy.deepcopy(execution)
    non_control["dispatch_class"] = 2
    non_control["max_nonpreemptive_run_nanos"] = 7
    with pytest.raises(PxteReject) as domain_error:
        _parse_pxte(_canonical_pxte([domain_overload], [non_control]))
    assert domain_error.value.code == PXTE_ERROR_CODES["domain_utilization_exceeded"]


def test_target_plan_allows_binding_superset_but_rejects_orphan_and_mismatch() -> None:
    vector = _build_vector()
    bindings = _parse_pxta(vector["pxta"])
    _validate_target_plan(bindings, _parse_pxte(vector["pxte"]))

    cases = [
        ("binding_id_hex", "30" * 16, TARGET_PLAN_ERROR_CODES["orphan_binding"]),
        (
            "mailbox_ref_hex",
            "82" * 16,
            TARGET_PLAN_ERROR_CODES["binding_mailbox_mismatch"],
        ),
        (
            "target_instance_hex",
            "62" * 16,
            TARGET_PLAN_ERROR_CODES["binding_target_mismatch"],
        ),
    ]
    for name, value, expected in cases:
        execution = copy.deepcopy(SEMANTIC["mailbox_executions"])
        execution[0][name] = value
        with pytest.raises(TargetPlanReject) as raised:
            _validate_target_plan(
                bindings, _parse_pxte(_canonical_pxte(SEMANTIC["domains"], execution))
            )
        assert raised.value.code == expected

    blocking_bindings = copy.deepcopy(SEMANTIC["bindings"])
    for binding in blocking_bindings:
        binding["delivery_overflow_policy"] = 5
        binding["mailbox_overflow_policy"] = 5
    with pytest.raises(TargetPlanReject) as block_until_deadline:
        _validate_target_plan(
            _parse_pxta(_canonical_pxta(blocking_bindings)), _parse_pxte(vector["pxte"])
        )
    assert (
        block_until_deadline.value.code == TARGET_PLAN_ERROR_CODES["block_until_deadline_forbidden"]
    )


def test_control_start_slo_is_strict_and_accounts_for_serial_cross_class_work() -> None:
    at_deadline = copy.deepcopy(SEMANTIC["bindings"])
    at_deadline[1]["mailbox_max_queue_age_nanos"] = 4_000_000_000
    with pytest.raises(PxarV2Reject) as equality:
        _parse_outer_v2(_build_vector(bindings=at_deadline)["outer"])
    assert (equality.value.code, equality.value.detail_code) == (
        PXAR_V2_ERROR_CODES["target_plan_rejected"],
        TARGET_PLAN_ERROR_CODES["control_start_slo_exceeded"],
    )

    just_after = copy.deepcopy(at_deadline)
    just_after[1]["mailbox_max_queue_age_nanos"] = 4_000_000_001
    _parse_outer_v2(_build_vector(bindings=just_after)["outer"])

    domains = copy.deepcopy(SEMANTIC["domains"])
    domains[0]["capacity_window_nanos"] = 20_000_000_000
    controls = copy.deepcopy(SEMANTIC["mailbox_executions"])
    stream = copy.deepcopy(controls[0])
    stream["binding_id_hex"] = "32" * 16
    stream["mailbox_ref_hex"] = "82" * 16
    stream["target_instance_hex"] = "62" * 16
    stream["dispatch_class"] = 3
    stream["max_arrivals_per_window"] = 1
    stream["max_nonpreemptive_run_nanos"] = 1_000_000
    stream["run_budget_nanos"] = 10_000_000_000
    stream["cleanup_budget_nanos"] = 1
    bindings = copy.deepcopy(SEMANTIC["bindings"])
    bindings[1]["delivery_max_message_age_nanos"] = 5_000_000
    bindings[1]["mailbox_max_queue_age_nanos"] = 5_000_000
    counterexample = _build_vector(
        bindings=bindings,
        domains=domains,
        mailboxes=[controls[0], stream],
    )
    with pytest.raises(PxarV2Reject) as cross_class:
        _parse_outer_v2(counterexample["outer"])
    assert (cross_class.value.code, cross_class.value.detail_code) == (
        PXAR_V2_ERROR_CODES["target_plan_rejected"],
        TARGET_PLAN_ERROR_CODES["control_start_slo_exceeded"],
    )


def test_outer_detects_nested_tamper_and_valid_body_commitment_tamper() -> None:
    vector = _build_vector()
    outer = vector["outer"]
    envelope_start = PXAR_V2_HEADER_BYTES
    pxta_start = envelope_start + len(vector["envelope"])
    pxte_start = PXAR_V2_HEADER_BYTES + len(vector["envelope"]) + len(vector["pxta"])

    bad_envelope = bytearray(outer)
    bad_envelope[envelope_start] ^= 1
    with pytest.raises(PxarV2Reject) as envelope_nested:
        _parse_outer_v2(bytes(bad_envelope))
    assert (envelope_nested.value.code, envelope_nested.value.detail_code) == (
        PXAR_V2_ERROR_CODES["envelope_rejected"],
        S2_ERROR_CODES["invalid_magic"],
    )

    bad_bindings = bytearray(outer)
    bad_bindings[pxta_start] ^= 1
    with pytest.raises(PxarV2Reject) as bindings_nested:
        _parse_outer_v2(bytes(bad_bindings))
    assert (bindings_nested.value.code, bindings_nested.value.detail_code) == (
        PXAR_V2_ERROR_CODES["bindings_rejected"],
        PXTA_ERROR_CODES["invalid_magic"],
    )

    bad_magic = bytearray(outer)
    bad_magic[pxte_start] ^= 1
    with pytest.raises(PxarV2Reject) as nested:
        _parse_outer_v2(bytes(bad_magic))
    assert (nested.value.code, nested.value.detail_code) == (
        PXAR_V2_ERROR_CODES["execution_rejected"],
        PXTE_ERROR_CODES["invalid_magic"],
    )

    all_reserved = copy.deepcopy(SEMANTIC["domains"])
    all_reserved[0]["max_outstanding"] = 1
    non_control = copy.deepcopy(SEMANTIC["mailbox_executions"])
    non_control[0]["dispatch_class"] = 2
    undispatchable = _build_vector(domains=all_reserved, mailboxes=non_control)
    with pytest.raises(PxarV2Reject) as shared_capacity:
        _parse_outer_v2(undispatchable["outer"])
    assert (shared_capacity.value.code, shared_capacity.value.detail_code) == (
        PXAR_V2_ERROR_CODES["execution_rejected"],
        PXTE_ERROR_CODES["shared_capacity_required"],
    )

    changed_execution = copy.deepcopy(SEMANTIC["mailbox_executions"])
    changed_execution[0]["service_cost_tokens"] = 3
    canonical_tamper = _canonical_pxte(SEMANTIC["domains"], changed_execution)
    tampered_outer = outer[:pxte_start] + canonical_tamper
    with pytest.raises(PxarV2Reject) as commitment:
        _parse_outer_v2(tampered_outer)
    assert commitment.value.code == PXAR_V2_ERROR_CODES["commitment_mismatch"]

    bad_signature = bytearray(outer)
    envelope_signature_offset = outer.find(vector["request_signature"])
    assert envelope_signature_offset >= PXAR_V2_HEADER_BYTES
    bad_signature[envelope_signature_offset] ^= 1
    assert _parse_outer_v2(bytes(bad_signature))["composite_digest"] == vector["composite_digest"]
    with pytest.raises(SignatureReject):
        _admit_outer_v2(
            bytes(bad_signature), vector["tenure_public_key"], vector["request_public_key"]
        )


def test_outer_length_boundaries_match_nested_rust_framing() -> None:
    vector = _build_vector()
    outer = vector["outer"]
    envelope_length = len(vector["envelope"])
    pxta_length = len(vector["pxta"])
    pxte_length = len(vector["pxte"])

    envelope_absorbs_pxta_byte = (
        outer[:6]
        + _u32(envelope_length + 1)
        + _u32(pxta_length - 1)
        + _u32(pxte_length)
        + outer[PXAR_V2_HEADER_BYTES:]
    )
    with pytest.raises(PxarV2Reject) as envelope_boundary:
        _parse_outer_v2(envelope_absorbs_pxta_byte)
    assert (envelope_boundary.value.code, envelope_boundary.value.detail_code) == (
        PXAR_V2_ERROR_CODES["envelope_rejected"],
        S2_ERROR_CODES["trailing_bytes"],
    )

    pxta_absorbs_pxte_byte = (
        outer[:6]
        + _u32(envelope_length)
        + _u32(pxta_length + 1)
        + _u32(pxte_length - 1)
        + outer[PXAR_V2_HEADER_BYTES:]
    )
    with pytest.raises(PxarV2Reject) as binding_boundary:
        _parse_outer_v2(pxta_absorbs_pxte_byte)
    assert (binding_boundary.value.code, binding_boundary.value.detail_code) == (
        PXAR_V2_ERROR_CODES["bindings_rejected"],
        PXTA_ERROR_CODES["invalid_frame_length"],
    )


def test_outer_has_stable_structural_and_target_plan_errors() -> None:
    vector = _build_vector()
    cases = [
        (vector["outer"][:-1], PXAR_V2_ERROR_CODES["truncated"]),
        (b"BAD!" + vector["outer"][4:], PXAR_V2_ERROR_CODES["invalid_magic"]),
        (
            vector["outer"][:4] + _u16(3) + vector["outer"][6:],
            PXAR_V2_ERROR_CODES["unsupported_version"],
        ),
        (vector["outer"] + b"\0", PXAR_V2_ERROR_CODES["invalid_frame_length"]),
    ]
    for frame, expected in cases:
        with pytest.raises(PxarV2Reject) as raised:
            _parse_outer_v2(frame)
        assert raised.value.code == expected

    orphan_execution = copy.deepcopy(SEMANTIC["mailbox_executions"])
    orphan_execution[0]["binding_id_hex"] = "30" * 16
    mailbox_mismatch = copy.deepcopy(SEMANTIC["mailbox_executions"])
    mailbox_mismatch[0]["mailbox_ref_hex"] = "82" * 16
    target_mismatch = copy.deepcopy(SEMANTIC["mailbox_executions"])
    target_mismatch[0]["target_instance_hex"] = "62" * 16
    blocking_bindings = copy.deepcopy(SEMANTIC["bindings"])
    for binding in blocking_bindings:
        binding["delivery_overflow_policy"] = 5
        binding["mailbox_overflow_policy"] = 5

    shared_target_bindings = copy.deepcopy(SEMANTIC["bindings"])
    shared_target_bindings[0]["target_instance_hex"] = "61" * 16
    second_subject = copy.deepcopy(SEMANTIC["mailbox_executions"][0])
    second_subject["binding_id_hex"] = "32" * 16
    second_subject["mailbox_ref_hex"] = "82" * 16
    second_subject["card_implementation_ref_hex"] = "a6" * 16
    second_subject["dispatch_class"] = 2
    subject_mismatch_executions = [
        copy.deepcopy(SEMANTIC["mailbox_executions"][0]),
        second_subject,
    ]
    for execution in subject_mismatch_executions:
        execution["max_arrivals_per_window"] = 1

    target_plan_cases = [
        (
            _build_vector(mailboxes=orphan_execution),
            TARGET_PLAN_ERROR_CODES["orphan_binding"],
        ),
        (
            _build_vector(mailboxes=mailbox_mismatch),
            TARGET_PLAN_ERROR_CODES["binding_mailbox_mismatch"],
        ),
        (
            _build_vector(mailboxes=target_mismatch),
            TARGET_PLAN_ERROR_CODES["binding_target_mismatch"],
        ),
        (
            _build_vector(bindings=blocking_bindings),
            TARGET_PLAN_ERROR_CODES["block_until_deadline_forbidden"],
        ),
        (
            _build_vector(
                bindings=shared_target_bindings,
                mailboxes=subject_mismatch_executions,
            ),
            TARGET_PLAN_ERROR_CODES["subject_execution_mismatch"],
        ),
    ]
    for target_plan_vector, expected_detail in target_plan_cases:
        with pytest.raises(PxarV2Reject) as rejected:
            _parse_outer_v2(target_plan_vector["outer"])
        assert (rejected.value.code, rejected.value.detail_code) == (
            PXAR_V2_ERROR_CODES["target_plan_rejected"],
            expected_detail,
        )


def test_stable_error_code_tables_and_preparse_bounds() -> None:
    assert list(PXTE_ERROR_CODES.values()) == list(range(1, 24))
    assert list(TARGET_PLAN_ERROR_CODES.values()) == list(range(1, 8))
    assert list(PXAR_V2_ERROR_CODES.values()) == list(range(1, 11))
    with pytest.raises(PxteReject) as pxte:
        _parse_pxte(bytes(PXTE_MAX_BYTES + 1))
    assert pxte.value.code == PXTE_ERROR_CODES["frame_too_large"]
    with pytest.raises(PxarV2Reject) as pxar:
        _parse_outer_v2(bytes(PXAR_V2_MAX_BYTES + 1))
    assert pxar.value.code == PXAR_V2_ERROR_CODES["frame_too_large"]
