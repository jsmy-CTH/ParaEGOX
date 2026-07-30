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
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wire" / "s5_runtime_apply_request_v3.json"
S4_FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wire" / "s4_runtime_apply_request_v2.json"

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
PXTE_V1_VERSION = 1
PXTE_V1_HEADER_BYTES = 14
PXTE_V1_DOMAIN_BYTES = 64
PXTE_V1_MAILBOX_BYTES = 236
PXTE_V1_MAX_DOMAINS = 64
PXTE_V1_MAX_BYTES = (
    PXTE_V1_HEADER_BYTES
    + PXTE_V1_MAX_DOMAINS * PXTE_V1_DOMAIN_BYTES
    + PXTA_MAX_RECORDS * PXTE_V1_MAILBOX_BYTES
)

PXTE_V2_VERSION = 2
PXTE_V2_HEADER_BYTES = 26
PXTE_THREAD_DOMAIN_BYTES = 44
PXTE_THREAD_MAILBOX_BYTES = 239
PXTE_THREAD_MAX_DOMAINS = 64
MAX_EXECUTOR_THREADS = 65_535
PXTE_V2_MAX_BYTES = (
    PXTE_V2_HEADER_BYTES
    + PXTE_V1_MAX_BYTES
    + PXTE_THREAD_MAX_DOMAINS * PXTE_THREAD_DOMAIN_BYTES
    + PXTA_MAX_RECORDS * PXTE_THREAD_MAILBOX_BYTES
)

PXTE_V1_DIGEST_DOMAIN = b"paraegox.runtime.target-execution.sha256.v1"
PXTE_V2_DIGEST_DOMAIN = b"paraegox.runtime.target-execution.sha256.v2"
COMPOSITE_V3_DIGEST_DOMAIN = b"paraegox.runtime.target-plan-assignments.sha256.v3"

MAX_SERVICE_COST_TOKENS = 1_000_000
MAX_MINIMUM_SERVICE_WEIGHT = 1_000_000
MAX_ARRIVALS_PER_WINDOW = 1_000_000
MAX_EXECUTION_DURATION_NANOS = 86_400_000_000_000

PXAR_MAGIC = b"PXAR"
PXAR_V1_VERSION = 1
PXAR_V2_VERSION = 2
PXAR_V3_VERSION = 3
PXAR_V3_HEADER_BYTES = 18
PXAR_V3_MAX_BYTES = PXAR_V3_HEADER_BYTES + 4096 + PXTA_MAX_BYTES + PXTE_V2_MAX_BYTES

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

PXTE_V1_ERROR_CODES = {
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

PXTE_V2_ERROR_CODES = {
    "frame_too_large": 1,
    "truncated": 2,
    "invalid_magic": 3,
    "unsupported_version": 4,
    "loop_body_too_large": 5,
    "domain_count_exceeded": 6,
    "execution_count_exceeded": 7,
    "invalid_frame_length": 8,
    "loop_execution_rejected": 9,
    "invalid_enum_value": 10,
    "invalid_executor_budget": 11,
    "invalid_thread_domain": 12,
    "invalid_thread_execution": 13,
    "duplicate_domain_ref": 14,
    "duplicate_execution_binding": 15,
    "duplicate_execution_mailbox": 16,
    "orphan_domain_ref": 17,
    "unused_domain_ref": 18,
    "unsupported_thread_execution": 19,
    "control_dispatch_forbidden": 20,
    "thread_utilization_exceeded": 21,
    "executor_budget_exceeded": 22,
    "cross_loop_thread_conflict": 23,
    "thread_subject_mismatch": 24,
    "missing_records": 25,
    "non_canonical_frame": 26,
}

TARGET_PLAN_V3_ERROR_CODES = {
    "orphan_binding": 1,
    "binding_mailbox_mismatch": 2,
    "binding_target_mismatch": 3,
    "block_until_deadline_forbidden": 4,
    "invalid_target_plan": 5,
}

PXAR_V3_ERROR_CODES = {
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
    "bindings": [
        _binding("32", "42", "52", "62", "72", "82"),
        _binding("31", "41", "51", "61", "71", "81"),
    ],
    "loop_domains": [
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
    "loop_mailboxes": [
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
    "executor_budget": {"max_total_threads": 3, "framework_threads": 2},
    "thread_domains": [
        {
            "domain_ref_hex": "92" * 16,
            "worker_count": 1,
            "capacity_window_nanos": 2_000_000_000,
            "start_budget_nanos": 1_000_000_000,
            "drain_budget_nanos": 1_000_000_000,
        }
    ],
    "thread_mailboxes": [
        {
            "binding_id_hex": "32" * 16,
            "mailbox_ref_hex": "82" * 16,
            "target_instance_hex": "62" * 16,
            "domain_ref_hex": "92" * 16,
            "card_definition_ref_hex": "b1" * 16,
            "card_implementation_ref_hex": "b2" * 16,
            "definition_digest_hex": "b3" * 32,
            "artifact_digest_hex": "b4" * 32,
            "config_digest_hex": "b5" * 32,
            "call_model": 2,
            "workload_kind": 4,
            "blocking_risk": 2,
            "run_bound_provenance": 3,
            "dispatch_class": 3,
            "service_cost_tokens": 3,
            "minimum_service_weight": 5,
            "max_burst": 2,
            "max_arrivals_per_window": 1,
            "max_nonpreemptive_run_nanos": 500_000_000,
            "run_budget_nanos": 1_000_000_000,
            "cancellation_grace_nanos": 500_000_000,
            "native_thread_reservation": 0,
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


class ContractReject(Exception):
    def __init__(
        self,
        code: int,
        detail_code: int | None = None,
        section: int | None = None,
        record_index: int | None = None,
    ) -> None:
        super().__init__(
            f"contract rejection code={code} detail={detail_code} "
            f"section={section} record={record_index}"
        )
        self.code = code
        self.detail_code = detail_code
        self.section = section
        self.record_index = record_index


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


class _Cursor:
    def __init__(self, record: bytes) -> None:
        self.record = record
        self.offset = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        value = self.record[self.offset : end]
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


def _encode_binding_record(value: dict[str, Any]) -> bytes:
    encoded = bytearray(_hex(value["binding_id_hex"]))
    for endpoint in ("source", "target"):
        encoded += _hex(value[f"{endpoint}_instance_hex"])
        encoded += _hex(value[f"{endpoint}_port_hex"])
        encoded += _u8(value[f"{endpoint}_direction"])
        encoded += _hex(value[f"{endpoint}_schema_id_hex"])
        encoded += _u32(value[f"{endpoint}_schema_version"])
        encoded += _hex(value[f"{endpoint}_schema_digest_hex"])
        encoded += _u8(value[f"{endpoint}_interaction"])
        encoded += _u8(value[f"{endpoint}_cardinality"])
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


def _decode_binding_record(record: bytes, index: int) -> dict[str, Any]:
    cursor = _Cursor(record)
    value: dict[str, Any] = {"binding_id": cursor.take(16)}
    for endpoint in ("source", "target"):
        value[f"{endpoint}_instance"] = cursor.take(16)
        value[f"{endpoint}_port"] = cursor.take(16)
        value[f"{endpoint}_direction"] = cursor.u8()
        value[f"{endpoint}_schema_id"] = cursor.take(16)
        value[f"{endpoint}_schema_version"] = cursor.u32()
        value[f"{endpoint}_schema_digest"] = cursor.take(32)
        value[f"{endpoint}_interaction"] = cursor.u8()
        value[f"{endpoint}_cardinality"] = cursor.u8()
    value.update(
        {
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
    )
    assert cursor.offset == PXTA_RECORD_BYTES
    enums_valid = (
        value["source_direction"] in {1, 2}
        and value["target_direction"] in {1, 2}
        and value["source_interaction"] in {1, 2}
        and value["target_interaction"] in {1, 2}
        and value["source_cardinality"] == 1
        and value["target_cardinality"] == 1
        and value["delivery_overflow_policy"] in {1, 2, 3, 4, 5}
        and value["mailbox_overflow_policy"] in {1, 2, 3, 4, 5}
    )
    if not enums_valid:
        raise ContractReject(PXTA_ERROR_CODES["invalid_enum_value"], record_index=index)
    same_schema = (
        value["source_schema_id"],
        value["source_schema_version"],
        value["source_schema_digest"],
    ) == (
        value["target_schema_id"],
        value["target_schema_version"],
        value["target_schema_digest"],
    )
    positive = all(
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
    valid = (
        positive
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
        raise ContractReject(PXTA_ERROR_CODES["invalid_assignment"], record_index=index)
    return value


def _parse_pxta(frame: bytes) -> list[dict[str, Any]]:
    if len(frame) > PXTA_MAX_BYTES:
        raise ContractReject(PXTA_ERROR_CODES["frame_too_large"])
    if len(frame) < PXTA_HEADER_BYTES:
        raise ContractReject(PXTA_ERROR_CODES["truncated"])
    if frame[:4] != PXTA_MAGIC:
        raise ContractReject(PXTA_ERROR_CODES["invalid_magic"])
    version, count = struct.unpack_from(">HI", frame, 4)
    if version != PXTA_VERSION:
        raise ContractReject(PXTA_ERROR_CODES["unsupported_version"])
    if count > PXTA_MAX_RECORDS:
        raise ContractReject(PXTA_ERROR_CODES["assignment_count_exceeded"])
    expected = PXTA_HEADER_BYTES + count * PXTA_RECORD_BYTES
    if len(frame) < expected:
        raise ContractReject(PXTA_ERROR_CODES["truncated"])
    if len(frame) != expected:
        raise ContractReject(PXTA_ERROR_CODES["invalid_frame_length"])
    records = [
        _decode_binding_record(
            frame[
                PXTA_HEADER_BYTES + index * PXTA_RECORD_BYTES : PXTA_HEADER_BYTES
                + (index + 1) * PXTA_RECORD_BYTES
            ],
            index,
        )
        for index in range(count)
    ]
    ordered = sorted(records, key=lambda item: item["binding_id"])
    for index, current in enumerate(ordered):
        for previous in ordered[:index]:
            if previous["binding_id"] == current["binding_id"]:
                raise ContractReject(PXTA_ERROR_CODES["duplicate_binding_id"])
            if (previous["source_instance"], previous["source_port"]) == (
                current["source_instance"],
                current["source_port"],
            ):
                raise ContractReject(PXTA_ERROR_CODES["duplicate_source_endpoint"])
            if (previous["target_instance"], previous["target_port"]) == (
                current["target_instance"],
                current["target_port"],
            ):
                raise ContractReject(PXTA_ERROR_CODES["duplicate_target_endpoint"])
            if previous["mailbox_ref"] == current["mailbox_ref"]:
                raise ContractReject(PXTA_ERROR_CODES["duplicate_mailbox_ref"])
    canonical = (
        PXTA_MAGIC
        + _u16(PXTA_VERSION)
        + _u32(len(ordered))
        + b"".join(item["canonical_record"] for item in ordered)
    )
    if canonical != frame:
        raise ContractReject(PXTA_ERROR_CODES["non_canonical_frame"])
    return ordered


def _valid_duration(value: int) -> bool:
    return 0 < value <= MAX_EXECUTION_DURATION_NANOS


def _encode_loop_domain(value: dict[str, Any]) -> bytes:
    encoded = bytearray(_hex(value["domain_ref_hex"]))
    encoded += _u32(value["max_outstanding"])
    encoded += _u32(value["control_reserved"])
    encoded += _u64(value["capacity_window_nanos"])
    encoded += _u64(value["control_reserved_run_budget_nanos"])
    encoded += _u64(value["start_budget_nanos"])
    encoded += _u64(value["drain_budget_nanos"])
    encoded += _u64(value["cleanup_budget_nanos"])
    assert len(encoded) == PXTE_V1_DOMAIN_BYTES
    return bytes(encoded)


def _encode_loop_mailbox(value: dict[str, Any]) -> bytes:
    encoded = bytearray()
    for name in (
        "binding_id_hex",
        "mailbox_ref_hex",
        "target_instance_hex",
        "domain_ref_hex",
        "card_definition_ref_hex",
        "card_implementation_ref_hex",
        "definition_digest_hex",
        "artifact_digest_hex",
        "config_digest_hex",
    ):
        encoded += _hex(value[name])
    for name in (
        "call_model",
        "workload_kind",
        "blocking_risk",
        "run_bound_provenance",
        "dispatch_class",
    ):
        encoded += _u8(value[name])
    encoded += _u32(value["service_cost_tokens"])
    encoded += _u32(value["minimum_service_weight"])
    encoded += _u16(value["max_burst"])
    encoded += _u32(value["max_arrivals_per_window"])
    encoded += _u64(value["max_nonpreemptive_run_nanos"])
    encoded += _u64(value["run_budget_nanos"])
    encoded += _u64(value["cleanup_budget_nanos"])
    encoded += _u8(value["overrun_action"])
    assert len(encoded) == PXTE_V1_MAILBOX_BYTES
    return bytes(encoded)


def _canonical_pxte_v1(domains: list[dict[str, Any]], mailboxes: list[dict[str, Any]]) -> bytes:
    domain_records = sorted(
        (_encode_loop_domain(value) for value in domains), key=lambda item: item[:16]
    )
    mailbox_records = sorted(
        (_encode_loop_mailbox(value) for value in mailboxes),
        key=lambda item: (item[:16], item[16:32], item[32:48], item[48:64]),
    )
    return (
        PXTE_MAGIC
        + _u16(PXTE_V1_VERSION)
        + _u32(len(domain_records))
        + _u32(len(mailbox_records))
        + b"".join(domain_records)
        + b"".join(mailbox_records)
    )


def _decode_loop_domain(record: bytes, index: int) -> dict[str, Any]:
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
    control_valid = (
        value["control_reserved"] == 0 and value["control_reserved_run_budget_nanos"] == 0
    ) or (
        value["control_reserved"] > 0
        and _valid_duration(value["control_reserved_run_budget_nanos"])
        and value["control_reserved_run_budget_nanos"] <= value["capacity_window_nanos"]
    )
    valid = (
        0 < value["max_outstanding"] <= MAX_EXECUTOR_THREADS
        and value["control_reserved"] <= value["max_outstanding"]
        and _valid_duration(value["capacity_window_nanos"])
        and _valid_duration(value["start_budget_nanos"])
        and _valid_duration(value["drain_budget_nanos"])
        and _valid_duration(value["cleanup_budget_nanos"])
        and control_valid
    )
    if not valid:
        raise ContractReject(PXTE_V1_ERROR_CODES["invalid_domain"], section=1, record_index=index)
    return value


def _decode_subject_and_ids(cursor: _Cursor) -> dict[str, bytes]:
    return {
        "binding_id": cursor.take(16),
        "mailbox_ref": cursor.take(16),
        "target_instance": cursor.take(16),
        "domain_ref": cursor.take(16),
        "card_definition_ref": cursor.take(16),
        "card_implementation_ref": cursor.take(16),
        "definition_digest": cursor.take(32),
        "artifact_digest": cursor.take(32),
        "config_digest": cursor.take(32),
    }


def _decode_loop_mailbox(record: bytes, index: int) -> dict[str, Any]:
    cursor = _Cursor(record)
    value: dict[str, Any] = _decode_subject_and_ids(cursor)
    value.update(
        {
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
    )
    enums_valid = (
        value["call_model"] in {1, 2, 3}
        and value["workload_kind"] in {1, 2, 3, 4, 5, 6}
        and value["blocking_risk"] in {1, 2, 3}
        and value["run_bound_provenance"] in {1, 2, 3, 4}
        and value["dispatch_class"] in {1, 2, 3, 4}
        and value["overrun_action"] in {1, 2, 3, 4}
    )
    if not enums_valid:
        raise ContractReject(
            PXTE_V1_ERROR_CODES["invalid_enum_value"], section=2, record_index=index
        )
    scalars_valid = (
        0 < value["service_cost_tokens"] <= MAX_SERVICE_COST_TOKENS
        and 0 < value["minimum_service_weight"] <= MAX_MINIMUM_SERVICE_WEIGHT
        and value["max_burst"] > 0
        and 0 < value["max_arrivals_per_window"] <= MAX_ARRIVALS_PER_WINDOW
        and _valid_duration(value["max_nonpreemptive_run_nanos"])
        and _valid_duration(value["run_budget_nanos"])
        and _valid_duration(value["cleanup_budget_nanos"])
        and value["max_nonpreemptive_run_nanos"] <= value["run_budget_nanos"]
    )
    if not scalars_valid:
        raise ContractReject(
            PXTE_V1_ERROR_CODES["invalid_mailbox_execution"],
            section=2,
            record_index=index,
        )
    return value


def _same_loop_subject(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(
        left[name] == right[name]
        for name in (
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
            "max_nonpreemptive_run_nanos",
        )
    )


def _validate_loop_records(domains: list[dict[str, Any]], mailboxes: list[dict[str, Any]]) -> None:
    for index, domain in enumerate(domains):
        if any(item["domain_ref"] == domain["domain_ref"] for item in domains[:index]):
            raise ContractReject(PXTE_V1_ERROR_CODES["duplicate_domain_ref"])
    for index, mailbox in enumerate(mailboxes):
        for previous in mailboxes[:index]:
            if previous["binding_id"] == mailbox["binding_id"]:
                raise ContractReject(PXTE_V1_ERROR_CODES["duplicate_execution_binding"])
            if previous["mailbox_ref"] == mailbox["mailbox_ref"]:
                raise ContractReject(PXTE_V1_ERROR_CODES["duplicate_execution_mailbox"])
        if not any(item["domain_ref"] == mailbox["domain_ref"] for item in domains):
            raise ContractReject(PXTE_V1_ERROR_CODES["orphan_domain_ref"])
        eligible = (
            mailbox["call_model"] == 1
            and mailbox["workload_kind"] in {1, 2}
            and mailbox["blocking_risk"] == 1
            and mailbox["run_bound_provenance"] in {2, 3}
        )
        if not eligible:
            raise ContractReject(PXTE_V1_ERROR_CODES["unsupported_loop_execution"])
        if mailbox["overrun_action"] not in {2, 3}:
            raise ContractReject(PXTE_V1_ERROR_CODES["unsafe_loop_overrun_action"])
    for domain in domains:
        assigned = [item for item in mailboxes if item["domain_ref"] == domain["domain_ref"]]
        if not assigned:
            raise ContractReject(PXTE_V1_ERROR_CODES["unused_domain_ref"])
        total = 0
        control = 0
        for mailbox in assigned:
            if (
                mailbox["run_budget_nanos"] > domain["capacity_window_nanos"]
                or mailbox["cleanup_budget_nanos"] > domain["cleanup_budget_nanos"]
            ):
                raise ContractReject(PXTE_V1_ERROR_CODES["invalid_mailbox_execution"])
            demand = mailbox["max_arrivals_per_window"] * (
                mailbox["run_budget_nanos"] + mailbox["cleanup_budget_nanos"]
            )
            total += demand
            if mailbox["dispatch_class"] == 1:
                if domain["control_reserved"] == 0:
                    raise ContractReject(PXTE_V1_ERROR_CODES["control_reservation_required"])
                control += demand
        if total > domain["capacity_window_nanos"]:
            raise ContractReject(PXTE_V1_ERROR_CODES["domain_utilization_exceeded"])
        if control > domain["control_reserved_run_budget_nanos"]:
            raise ContractReject(PXTE_V1_ERROR_CODES["control_utilization_exceeded"])
        if domain["control_reserved"] == domain["max_outstanding"] and any(
            item["dispatch_class"] != 1 for item in assigned
        ):
            raise ContractReject(PXTE_V1_ERROR_CODES["shared_capacity_required"])


def _parse_pxte_v1(frame: bytes) -> dict[str, Any]:
    if len(frame) > PXTE_V1_MAX_BYTES:
        raise ContractReject(PXTE_V1_ERROR_CODES["frame_too_large"])
    if len(frame) < PXTE_V1_HEADER_BYTES:
        raise ContractReject(PXTE_V1_ERROR_CODES["truncated"])
    if frame[:4] != PXTE_MAGIC:
        raise ContractReject(PXTE_V1_ERROR_CODES["invalid_magic"])
    version, domain_count, mailbox_count = struct.unpack_from(">HII", frame, 4)
    if version != PXTE_V1_VERSION:
        raise ContractReject(PXTE_V1_ERROR_CODES["unsupported_version"])
    if domain_count > PXTE_V1_MAX_DOMAINS:
        raise ContractReject(PXTE_V1_ERROR_CODES["domain_count_exceeded"])
    if mailbox_count > PXTA_MAX_RECORDS:
        raise ContractReject(PXTE_V1_ERROR_CODES["execution_count_exceeded"])
    expected = (
        PXTE_V1_HEADER_BYTES
        + domain_count * PXTE_V1_DOMAIN_BYTES
        + mailbox_count * PXTE_V1_MAILBOX_BYTES
    )
    if len(frame) < expected:
        raise ContractReject(PXTE_V1_ERROR_CODES["truncated"])
    if len(frame) != expected:
        raise ContractReject(PXTE_V1_ERROR_CODES["invalid_frame_length"])
    domains = []
    for index in range(domain_count):
        start = PXTE_V1_HEADER_BYTES + index * PXTE_V1_DOMAIN_BYTES
        domains.append(_decode_loop_domain(frame[start : start + PXTE_V1_DOMAIN_BYTES], index))
    mailbox_start = PXTE_V1_HEADER_BYTES + domain_count * PXTE_V1_DOMAIN_BYTES
    mailboxes = []
    for index in range(mailbox_count):
        start = mailbox_start + index * PXTE_V1_MAILBOX_BYTES
        mailboxes.append(_decode_loop_mailbox(frame[start : start + PXTE_V1_MAILBOX_BYTES], index))
    if not domains or not mailboxes:
        raise ContractReject(PXTE_V1_ERROR_CODES["missing_records"])
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
    _validate_loop_records(ordered_domains, ordered_mailboxes)
    canonical = (
        PXTE_MAGIC
        + _u16(PXTE_V1_VERSION)
        + _u32(len(ordered_domains))
        + _u32(len(ordered_mailboxes))
        + b"".join(item["canonical_record"] for item in ordered_domains)
        + b"".join(item["canonical_record"] for item in ordered_mailboxes)
    )
    if canonical != frame:
        raise ContractReject(PXTE_V1_ERROR_CODES["non_canonical_frame"])
    return {"domains": ordered_domains, "mailboxes": ordered_mailboxes, "wire": frame}


def _encode_thread_domain(value: dict[str, Any]) -> bytes:
    encoded = bytearray(_hex(value["domain_ref_hex"]))
    encoded += _u32(value["worker_count"])
    encoded += _u64(value["capacity_window_nanos"])
    encoded += _u64(value["start_budget_nanos"])
    encoded += _u64(value["drain_budget_nanos"])
    assert len(encoded) == PXTE_THREAD_DOMAIN_BYTES
    return bytes(encoded)


def _encode_thread_mailbox(value: dict[str, Any]) -> bytes:
    encoded = bytearray()
    for name in (
        "binding_id_hex",
        "mailbox_ref_hex",
        "target_instance_hex",
        "domain_ref_hex",
        "card_definition_ref_hex",
        "card_implementation_ref_hex",
        "definition_digest_hex",
        "artifact_digest_hex",
        "config_digest_hex",
    ):
        encoded += _hex(value[name])
    for name in (
        "call_model",
        "workload_kind",
        "blocking_risk",
        "run_bound_provenance",
        "dispatch_class",
    ):
        encoded += _u8(value[name])
    encoded += _u32(value["service_cost_tokens"])
    encoded += _u32(value["minimum_service_weight"])
    encoded += _u16(value["max_burst"])
    encoded += _u32(value["max_arrivals_per_window"])
    encoded += _u64(value["max_nonpreemptive_run_nanos"])
    encoded += _u64(value["run_budget_nanos"])
    encoded += _u64(value["cancellation_grace_nanos"])
    encoded += _u32(value["native_thread_reservation"])
    assert len(encoded) == PXTE_THREAD_MAILBOX_BYTES
    return bytes(encoded)


def _canonical_pxte_v2(
    loop_wire: bytes,
    budget: dict[str, Any],
    domains: list[dict[str, Any]],
    mailboxes: list[dict[str, Any]],
) -> bytes:
    domain_records = sorted(
        (_encode_thread_domain(value) for value in domains), key=lambda item: item[:16]
    )
    mailbox_records = sorted(
        (_encode_thread_mailbox(value) for value in mailboxes),
        key=lambda item: (item[:16], item[16:32], item[32:48], item[48:64]),
    )
    return (
        PXTE_MAGIC
        + _u16(PXTE_V2_VERSION)
        + _u32(len(loop_wire))
        + _u32(len(domain_records))
        + _u32(len(mailbox_records))
        + _u32(budget["max_total_threads"])
        + _u32(budget["framework_threads"])
        + loop_wire
        + b"".join(domain_records)
        + b"".join(mailbox_records)
    )


def _decode_thread_domain(record: bytes, index: int) -> dict[str, Any]:
    cursor = _Cursor(record)
    value = {
        "domain_ref": cursor.take(16),
        "worker_count": cursor.u32(),
        "capacity_window_nanos": cursor.u64(),
        "start_budget_nanos": cursor.u64(),
        "drain_budget_nanos": cursor.u64(),
        "canonical_record": record,
    }
    valid = (
        0 < value["worker_count"] <= MAX_EXECUTOR_THREADS
        and _valid_duration(value["capacity_window_nanos"])
        and _valid_duration(value["start_budget_nanos"])
        and _valid_duration(value["drain_budget_nanos"])
    )
    if not valid:
        raise ContractReject(
            PXTE_V2_ERROR_CODES["invalid_thread_domain"], section=2, record_index=index
        )
    return value


def _decode_thread_mailbox(record: bytes, index: int) -> dict[str, Any]:
    cursor = _Cursor(record)
    value: dict[str, Any] = _decode_subject_and_ids(cursor)
    value.update(
        {
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
            "cancellation_grace_nanos": cursor.u64(),
            "native_thread_reservation": cursor.u32(),
            "canonical_record": record,
        }
    )
    enums_valid = (
        value["call_model"] in {1, 2, 3}
        and value["workload_kind"] in {1, 2, 3, 4, 5, 6}
        and value["blocking_risk"] in {1, 2, 3}
        and value["run_bound_provenance"] in {1, 2, 3, 4}
        and value["dispatch_class"] in {1, 2, 3, 4}
    )
    if not enums_valid:
        raise ContractReject(
            PXTE_V2_ERROR_CODES["invalid_enum_value"], section=3, record_index=index
        )
    scalars_valid = (
        0 < value["service_cost_tokens"] <= MAX_SERVICE_COST_TOKENS
        and 0 < value["minimum_service_weight"] <= MAX_MINIMUM_SERVICE_WEIGHT
        and value["max_burst"] > 0
        and 0 < value["max_arrivals_per_window"] <= MAX_ARRIVALS_PER_WINDOW
        and _valid_duration(value["max_nonpreemptive_run_nanos"])
        and _valid_duration(value["run_budget_nanos"])
        and _valid_duration(value["cancellation_grace_nanos"])
        and value["max_nonpreemptive_run_nanos"] <= value["run_budget_nanos"]
        and value["native_thread_reservation"] <= MAX_EXECUTOR_THREADS
    )
    if not scalars_valid:
        raise ContractReject(
            PXTE_V2_ERROR_CODES["invalid_thread_execution"],
            section=3,
            record_index=index,
        )
    eligible = (
        value["call_model"] == 2
        and value["workload_kind"] in {1, 4}
        and value["blocking_risk"] == 2
        and value["run_bound_provenance"] in {2, 3}
    )
    if not eligible:
        raise ContractReject(
            PXTE_V2_ERROR_CODES["unsupported_thread_execution"],
            section=3,
            record_index=index,
        )
    if value["dispatch_class"] == 1:
        raise ContractReject(
            PXTE_V2_ERROR_CODES["control_dispatch_forbidden"],
            section=3,
            record_index=index,
        )
    return value


def _same_thread_subject(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(
        left[name] == right[name]
        for name in (
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
            "max_nonpreemptive_run_nanos",
            "run_budget_nanos",
            "cancellation_grace_nanos",
            "native_thread_reservation",
        )
    )


def _validate_thread_records(
    loop: dict[str, Any] | None,
    maximum_threads: int,
    framework_threads: int,
    domains: list[dict[str, Any]],
    mailboxes: list[dict[str, Any]],
) -> None:
    for index, domain in enumerate(domains):
        if any(item["domain_ref"] == domain["domain_ref"] for item in domains[:index]):
            raise ContractReject(PXTE_V2_ERROR_CODES["duplicate_domain_ref"])
    for index, mailbox in enumerate(mailboxes):
        for previous in mailboxes[:index]:
            if previous["binding_id"] == mailbox["binding_id"]:
                raise ContractReject(PXTE_V2_ERROR_CODES["duplicate_execution_binding"])
            if previous["mailbox_ref"] == mailbox["mailbox_ref"]:
                raise ContractReject(PXTE_V2_ERROR_CODES["duplicate_execution_mailbox"])
            if previous["target_instance"] == mailbox[
                "target_instance"
            ] and not _same_thread_subject(previous, mailbox):
                raise ContractReject(PXTE_V2_ERROR_CODES["thread_subject_mismatch"])
        if not any(item["domain_ref"] == mailbox["domain_ref"] for item in domains):
            raise ContractReject(PXTE_V2_ERROR_CODES["orphan_domain_ref"])
    for domain in domains:
        assigned = [item for item in mailboxes if item["domain_ref"] == domain["domain_ref"]]
        if not assigned:
            raise ContractReject(PXTE_V2_ERROR_CODES["unused_domain_ref"])
        demand = sum(
            item["max_arrivals_per_window"]
            * (item["run_budget_nanos"] + item["cancellation_grace_nanos"])
            for item in assigned
        )
        capacity = domain["worker_count"] * domain["capacity_window_nanos"]
        if demand > capacity:
            raise ContractReject(PXTE_V2_ERROR_CODES["thread_utilization_exceeded"])
    if loop is not None:
        if any(
            loop_domain["domain_ref"] == thread_domain["domain_ref"]
            for loop_domain in loop["domains"]
            for thread_domain in domains
        ):
            raise ContractReject(PXTE_V2_ERROR_CODES["cross_loop_thread_conflict"])
        for loop_mailbox in loop["mailboxes"]:
            for thread_mailbox in mailboxes:
                overlaps = (
                    loop_mailbox["binding_id"] == thread_mailbox["binding_id"]
                    or loop_mailbox["mailbox_ref"] == thread_mailbox["mailbox_ref"]
                    or loop_mailbox["target_instance"] == thread_mailbox["target_instance"]
                )
                if overlaps:
                    raise ContractReject(PXTE_V2_ERROR_CODES["cross_loop_thread_conflict"])
    total_threads = framework_threads + sum(item["worker_count"] for item in domains)
    seen_instances: set[bytes] = set()
    for mailbox in mailboxes:
        if mailbox["target_instance"] not in seen_instances:
            seen_instances.add(mailbox["target_instance"])
            total_threads += mailbox["native_thread_reservation"]
    if total_threads > maximum_threads:
        raise ContractReject(PXTE_V2_ERROR_CODES["executor_budget_exceeded"])


def _parse_pxte_v2(frame: bytes) -> dict[str, Any]:
    if len(frame) > PXTE_V2_MAX_BYTES:
        raise ContractReject(PXTE_V2_ERROR_CODES["frame_too_large"])
    if len(frame) < PXTE_V2_HEADER_BYTES:
        raise ContractReject(PXTE_V2_ERROR_CODES["truncated"])
    if frame[:4] != PXTE_MAGIC:
        raise ContractReject(PXTE_V2_ERROR_CODES["invalid_magic"])
    (
        version,
        loop_length,
        domain_count,
        mailbox_count,
        maximum_threads,
        framework_threads,
    ) = struct.unpack_from(">HIIIII", frame, 4)
    if version != PXTE_V2_VERSION:
        raise ContractReject(PXTE_V2_ERROR_CODES["unsupported_version"])
    if loop_length > PXTE_V1_MAX_BYTES:
        raise ContractReject(PXTE_V2_ERROR_CODES["loop_body_too_large"])
    if domain_count > PXTE_THREAD_MAX_DOMAINS:
        raise ContractReject(PXTE_V2_ERROR_CODES["domain_count_exceeded"])
    if mailbox_count > PXTA_MAX_RECORDS:
        raise ContractReject(PXTE_V2_ERROR_CODES["execution_count_exceeded"])
    expected = (
        PXTE_V2_HEADER_BYTES
        + loop_length
        + domain_count * PXTE_THREAD_DOMAIN_BYTES
        + mailbox_count * PXTE_THREAD_MAILBOX_BYTES
    )
    if len(frame) < expected:
        raise ContractReject(PXTE_V2_ERROR_CODES["truncated"])
    if len(frame) != expected:
        raise ContractReject(PXTE_V2_ERROR_CODES["invalid_frame_length"])
    budget_valid = (
        0 < maximum_threads <= MAX_EXECUTOR_THREADS and 0 < framework_threads <= maximum_threads
    )
    if not budget_valid:
        raise ContractReject(PXTE_V2_ERROR_CODES["invalid_executor_budget"])
    loop_start = PXTE_V2_HEADER_BYTES
    loop_end = loop_start + loop_length
    loop = None
    if loop_length:
        try:
            loop = _parse_pxte_v1(frame[loop_start:loop_end])
        except ContractReject as error:
            raise ContractReject(
                PXTE_V2_ERROR_CODES["loop_execution_rejected"],
                detail_code=error.code,
                section=1,
                record_index=0,
            ) from error
    domain_end = loop_end + domain_count * PXTE_THREAD_DOMAIN_BYTES
    domains = []
    for index in range(domain_count):
        start = loop_end + index * PXTE_THREAD_DOMAIN_BYTES
        domains.append(
            _decode_thread_domain(frame[start : start + PXTE_THREAD_DOMAIN_BYTES], index)
        )
    mailboxes = []
    for index in range(mailbox_count):
        start = domain_end + index * PXTE_THREAD_MAILBOX_BYTES
        mailboxes.append(
            _decode_thread_mailbox(frame[start : start + PXTE_THREAD_MAILBOX_BYTES], index)
        )
    if not domains or not mailboxes:
        raise ContractReject(PXTE_V2_ERROR_CODES["missing_records"])
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
    _validate_thread_records(
        loop,
        maximum_threads,
        framework_threads,
        ordered_domains,
        ordered_mailboxes,
    )
    canonical = (
        PXTE_MAGIC
        + _u16(PXTE_V2_VERSION)
        + _u32(loop_length)
        + _u32(len(ordered_domains))
        + _u32(len(ordered_mailboxes))
        + _u32(maximum_threads)
        + _u32(framework_threads)
        + (b"" if loop is None else loop["wire"])
        + b"".join(item["canonical_record"] for item in ordered_domains)
        + b"".join(item["canonical_record"] for item in ordered_mailboxes)
    )
    if canonical != frame:
        raise ContractReject(PXTE_V2_ERROR_CODES["non_canonical_frame"])
    return {
        "loop": loop,
        "maximum_threads": maximum_threads,
        "framework_threads": framework_threads,
        "domains": ordered_domains,
        "mailboxes": ordered_mailboxes,
        "wire": frame,
    }


def _matching_binding(bindings: list[dict[str, Any]], mailbox: dict[str, Any]) -> dict[str, Any]:
    binding = next((item for item in bindings if item["binding_id"] == mailbox["binding_id"]), None)
    if binding is None:
        raise ContractReject(TARGET_PLAN_V3_ERROR_CODES["orphan_binding"])
    if binding["mailbox_ref"] != mailbox["mailbox_ref"]:
        raise ContractReject(TARGET_PLAN_V3_ERROR_CODES["binding_mailbox_mismatch"])
    if binding["target_instance"] != mailbox["target_instance"]:
        raise ContractReject(TARGET_PLAN_V3_ERROR_CODES["binding_target_mismatch"])
    return binding


def _validate_loop_target_plan(bindings: list[dict[str, Any]], loop: dict[str, Any]) -> None:
    for mailbox in loop["mailboxes"]:
        try:
            _matching_binding(bindings, mailbox)
        except ContractReject as error:
            raise ContractReject(TARGET_PLAN_V3_ERROR_CODES["invalid_target_plan"]) from error
    for index, mailbox in enumerate(loop["mailboxes"]):
        for previous in loop["mailboxes"][:index]:
            if previous["target_instance"] == mailbox["target_instance"] and not _same_loop_subject(
                previous, mailbox
            ):
                raise ContractReject(TARGET_PLAN_V3_ERROR_CODES["invalid_target_plan"])
    binding_by_id = {item["binding_id"]: item for item in bindings}
    domain_by_ref = {item["domain_ref"]: item for item in loop["domains"]}
    for control in (item for item in loop["mailboxes"] if item["dispatch_class"] == 1):
        binding = binding_by_id[control["binding_id"]]
        domain = domain_by_ref[control["domain_ref"]]
        slo = binding["mailbox_max_queue_age_nanos"]
        window = domain["capacity_window_nanos"]
        arrival_horizon = (slo + window - 1) // window + 1
        assigned = [
            item for item in loop["mailboxes"] if item["domain_ref"] == control["domain_ref"]
        ]
        occupancy = {
            item["binding_id"]: max(
                item["run_budget_nanos"] + item["cleanup_budget_nanos"],
                item["max_nonpreemptive_run_nanos"],
            )
            for item in assigned
        }
        wait_bound = max(occupancy.values())
        wait_bound += (binding["mailbox_capacity_items"] - 1) * occupancy[control["binding_id"]]
        for peer in assigned:
            if peer["binding_id"] == control["binding_id"]:
                continue
            peer_binding = binding_by_id[peer["binding_id"]]
            peer_work = peer_binding["mailbox_capacity_items"] + (
                arrival_horizon * peer["max_arrivals_per_window"]
            )
            wait_bound += peer_work * occupancy[peer["binding_id"]]
        if wait_bound >= slo:
            raise ContractReject(TARGET_PLAN_V3_ERROR_CODES["invalid_target_plan"])


def _validate_target_plan_v3(bindings: list[dict[str, Any]], execution: dict[str, Any]) -> None:
    if any(
        item["delivery_overflow_policy"] == 5 or item["mailbox_overflow_policy"] == 5
        for item in bindings
    ):
        raise ContractReject(TARGET_PLAN_V3_ERROR_CODES["block_until_deadline_forbidden"])
    if execution["loop"] is not None:
        _validate_loop_target_plan(bindings, execution["loop"])
    for mailbox in execution["mailboxes"]:
        _matching_binding(bindings, mailbox)


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
        raise ContractReject(S2_ERROR_CODES["frame_too_large"])
    header_length = len(S2_MAGIC) + 4
    if len(frame) < header_length:
        raise ContractReject(S2_ERROR_CODES["truncated"])
    if frame[: len(S2_MAGIC)] != S2_MAGIC:
        raise ContractReject(S2_ERROR_CODES["invalid_magic"])
    version, count = struct.unpack_from(">HH", frame, len(S2_MAGIC))
    if version != S2_VERSION:
        raise ContractReject(S2_ERROR_CODES["unsupported_version"])
    cursor = header_length
    fields: list[tuple[int, bytes]] = []
    for index in range(count):
        expected_tag = index + 1
        if cursor + 6 > len(frame):
            raise ContractReject(S2_ERROR_CODES["truncated"])
        tag, length = struct.unpack_from(">HI", frame, cursor)
        cursor += 6
        if tag == 0 or tag > S2_FIELD_COUNT:
            raise ContractReject(S2_ERROR_CODES["unknown_field"], detail_code=tag)
        if tag < expected_tag:
            raise ContractReject(S2_ERROR_CODES["duplicate_field"], detail_code=tag)
        if tag > expected_tag:
            raise ContractReject(S2_ERROR_CODES["out_of_order_field"], detail_code=tag)
        if not _valid_s2_field_length(tag, length):
            raise ContractReject(S2_ERROR_CODES["invalid_field_length"], detail_code=tag)
        end = cursor + length
        if end > len(frame):
            raise ContractReject(S2_ERROR_CODES["truncated"], detail_code=tag)
        fields.append((tag, frame[cursor:end]))
        cursor = end
    if count < S2_FIELD_COUNT:
        raise ContractReject(S2_ERROR_CODES["missing_field"], detail_code=count + 1)
    if cursor != len(frame):
        raise ContractReject(S2_ERROR_CODES["trailing_bytes"])
    if _encode_s2(fields) != frame:
        raise ContractReject(S2_ERROR_CODES["non_canonical_frame"])
    return fields


def _decode_s2(frame: bytes) -> dict[int, bytes]:
    values = dict(_parse_s2(frame))
    if values[1] != _u16(1):
        raise ContractReject(S2_ERROR_CODES["unsupported_version"], detail_code=1)
    target_slice_digest = _canonical_digest(
        TARGET_SLICE_DIGEST_DOMAIN, [values[tag] for tag in range(1, 8)]
    )
    if values[8] != target_slice_digest:
        raise ContractReject(S2_ERROR_CODES["derived_digest_mismatch"], detail_code=8)
    tenure_digest = _canonical_digest(
        TENURE_PROOF_DIGEST_DOMAIN, [values[tag] for tag in range(11, 21)]
    )
    if values[21] != tenure_digest:
        raise ContractReject(S2_ERROR_CODES["derived_digest_mismatch"], detail_code=21)
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
        raise ContractReject(S2_ERROR_CODES["derived_digest_mismatch"], detail_code=25)
    semantic_valid = (
        values[3] == values[15]
        and values[9] == values[16]
        and values[10] == values[17]
        and struct.unpack(">Q", values[29])[0] > 0
        and struct.unpack(">Q", values[31])[0] <= struct.unpack(">Q", values[30])[0]
        and ((values[22] == _u16(0) and values[23] == bytes(32)) or values[22] == _u16(1))
    )
    if not semantic_valid:
        raise ContractReject(S2_ERROR_CODES["invalid_field_value"])
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
    *,
    bindings: list[dict[str, Any]] | None = None,
    include_loop: bool = True,
    loop_domains: list[dict[str, Any]] | None = None,
    loop_mailboxes: list[dict[str, Any]] | None = None,
    budget: dict[str, Any] | None = None,
    thread_domains: list[dict[str, Any]] | None = None,
    thread_mailboxes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    binding_values = SEMANTIC["bindings"] if bindings is None else bindings
    loop_domain_values = SEMANTIC["loop_domains"] if loop_domains is None else loop_domains
    loop_mailbox_values = SEMANTIC["loop_mailboxes"] if loop_mailboxes is None else loop_mailboxes
    budget_value = SEMANTIC["executor_budget"] if budget is None else budget
    thread_domain_values = SEMANTIC["thread_domains"] if thread_domains is None else thread_domains
    thread_mailbox_values = (
        SEMANTIC["thread_mailboxes"] if thread_mailboxes is None else thread_mailboxes
    )
    pxta = _canonical_pxta(binding_values)
    loop_wire = _canonical_pxte_v1(loop_domain_values, loop_mailbox_values) if include_loop else b""
    pxte_v2 = _canonical_pxte_v2(
        loop_wire, budget_value, thread_domain_values, thread_mailbox_values
    )
    pxta_digest = _canonical_digest(PXTA_DIGEST_DOMAIN, [pxta])
    loop_digest = _canonical_digest(PXTE_V1_DIGEST_DOMAIN, [loop_wire]) if loop_wire else b""
    pxte_v2_digest = _canonical_digest(PXTE_V2_DIGEST_DOMAIN, [pxte_v2])
    composite_digest = _canonical_digest(COMPOSITE_V3_DIGEST_DOMAIN, [pxta_digest, pxte_v2_digest])
    s2 = _build_s2(composite_digest)
    envelope = s2["envelope"]
    outer = (
        PXAR_MAGIC
        + _u16(PXAR_V3_VERSION)
        + _u32(len(envelope))
        + _u32(len(pxta))
        + _u32(len(pxte_v2))
        + envelope
        + pxta
        + pxte_v2
    )
    return {
        **s2,
        "pxta": pxta,
        "loop_pxte_v1": loop_wire,
        "pxte_v2": pxte_v2,
        "pxta_digest": pxta_digest,
        "loop_pxte_v1_digest": loop_digest,
        "pxte_v2_digest": pxte_v2_digest,
        "composite_digest": composite_digest,
        "outer": outer,
    }


def _parse_outer_v3(frame: bytes) -> dict[str, Any]:
    if len(frame) > PXAR_V3_MAX_BYTES:
        raise ContractReject(PXAR_V3_ERROR_CODES["frame_too_large"])
    if len(frame) < PXAR_V3_HEADER_BYTES:
        raise ContractReject(PXAR_V3_ERROR_CODES["truncated"])
    if frame[:4] != PXAR_MAGIC:
        raise ContractReject(PXAR_V3_ERROR_CODES["invalid_magic"])
    version, envelope_length, pxta_length, pxte_length = struct.unpack_from(">HIII", frame, 4)
    if version != PXAR_V3_VERSION:
        raise ContractReject(PXAR_V3_ERROR_CODES["unsupported_version"])
    expected = PXAR_V3_HEADER_BYTES + envelope_length + pxta_length + pxte_length
    if len(frame) < expected:
        raise ContractReject(PXAR_V3_ERROR_CODES["truncated"])
    if len(frame) != expected:
        raise ContractReject(PXAR_V3_ERROR_CODES["invalid_frame_length"])
    envelope_start = PXAR_V3_HEADER_BYTES
    envelope_end = envelope_start + envelope_length
    pxta_end = envelope_end + pxta_length
    envelope = frame[envelope_start:envelope_end]
    pxta = frame[envelope_end:pxta_end]
    pxte_v2 = frame[pxta_end:]
    try:
        s2_values = _decode_s2(envelope)
    except ContractReject as error:
        raise ContractReject(
            PXAR_V3_ERROR_CODES["envelope_rejected"], detail_code=error.code
        ) from error
    try:
        bindings = _parse_pxta(pxta)
    except ContractReject as error:
        raise ContractReject(
            PXAR_V3_ERROR_CODES["bindings_rejected"], detail_code=error.code
        ) from error
    try:
        execution = _parse_pxte_v2(pxte_v2)
    except ContractReject as error:
        raise ContractReject(
            PXAR_V3_ERROR_CODES["execution_rejected"], detail_code=error.code
        ) from error
    try:
        _validate_target_plan_v3(bindings, execution)
    except ContractReject as error:
        raise ContractReject(
            PXAR_V3_ERROR_CODES["target_plan_rejected"], detail_code=error.code
        ) from error
    pxta_digest = _canonical_digest(PXTA_DIGEST_DOMAIN, [pxta])
    pxte_v2_digest = _canonical_digest(PXTE_V2_DIGEST_DOMAIN, [pxte_v2])
    composite_digest = _canonical_digest(COMPOSITE_V3_DIGEST_DOMAIN, [pxta_digest, pxte_v2_digest])
    if s2_values[7] != composite_digest:
        raise ContractReject(PXAR_V3_ERROR_CODES["commitment_mismatch"])
    return {
        "s2_values": s2_values,
        "bindings": bindings,
        "execution": execution,
        "pxta_digest": pxta_digest,
        "pxte_v2_digest": pxte_v2_digest,
        "composite_digest": composite_digest,
    }


def _admit_outer_v3(
    frame: bytes, tenure_public_key: bytes, request_public_key: bytes
) -> dict[str, Any]:
    parsed = _parse_outer_v3(frame)
    _verify_s2_signatures(parsed["s2_values"], tenure_public_key, request_public_key)
    return parsed


def _reject_non_version(frame: bytes, expected_version: int, header_bytes: int) -> None:
    if len(frame) < header_bytes:
        raise ContractReject(PXAR_V3_ERROR_CODES["truncated"])
    if frame[:4] != PXAR_MAGIC:
        raise ContractReject(PXAR_V3_ERROR_CODES["invalid_magic"])
    if struct.unpack_from(">H", frame, 4)[0] != expected_version:
        raise ContractReject(PXAR_V3_ERROR_CODES["unsupported_version"])


PROTOCOL = {
    "pxta_magic_hex": PXTA_MAGIC.hex(),
    "pxta_version": PXTA_VERSION,
    "pxta_header": "magic:4,version:u16-be,binding_count:u32-be",
    "pxta_record_bytes": PXTA_RECORD_BYTES,
    "pxta_digest_domain_hex": PXTA_DIGEST_DOMAIN.hex(),
    "embedded_pxte_v1_version": PXTE_V1_VERSION,
    "embedded_pxte_v1_header": "magic:4,version:u16-be,domain_count:u32-be,mailbox_count:u32-be",
    "embedded_pxte_v1_domain_record_bytes": PXTE_V1_DOMAIN_BYTES,
    "embedded_pxte_v1_mailbox_record_bytes": PXTE_V1_MAILBOX_BYTES,
    "embedded_pxte_v1_digest_domain_hex": PXTE_V1_DIGEST_DOMAIN.hex(),
    "pxte_v2_magic_hex": PXTE_MAGIC.hex(),
    "pxte_v2_version": PXTE_V2_VERSION,
    "pxte_v2_header": (
        "magic:4,version:u16-be,loop_body_len:u32-be,thread_domain_count:u32-be,"
        "thread_execution_count:u32-be,max_total_threads:u32-be,framework_threads:u32-be"
    ),
    "pxte_v2_thread_domain_record_bytes": PXTE_THREAD_DOMAIN_BYTES,
    "pxte_v2_thread_mailbox_record_bytes": PXTE_THREAD_MAILBOX_BYTES,
    "pxte_v2_digest_domain_hex": PXTE_V2_DIGEST_DOMAIN.hex(),
    "composite_v3_digest_domain_hex": COMPOSITE_V3_DIGEST_DOMAIN.hex(),
    "pxar_v3_version": PXAR_V3_VERSION,
    "pxar_v3_header": (
        "magic:4,version:u16-be,envelope_len:u32-be,pxta_len:u32-be,pxte_v2_len:u32-be"
    ),
    "max_pxar_v3_bytes": PXAR_V3_MAX_BYTES,
    "s2_magic_hex": S2_MAGIC.hex(),
    "s2_version": S2_VERSION,
    "s2_field_count": S2_FIELD_COUNT,
    "target_slice_digest_domain_hex": TARGET_SLICE_DIGEST_DOMAIN.hex(),
    "tenure_proof_digest_domain_hex": TENURE_PROOF_DIGEST_DOMAIN.hex(),
    "apply_control_digest_domain_hex": APPLY_CONTROL_DIGEST_DOMAIN.hex(),
    "request_digest_domain_hex": REQUEST_DIGEST_DOMAIN.hex(),
    "tenure_signing_domain_hex": TENURE_SIGNING_DOMAIN.hex(),
    "request_signing_domain_hex": AUTH_SIGNING_DOMAIN.hex(),
}


def _fixture_document() -> dict[str, Any]:
    vector = _build_vector()
    parsed_pxta = _parse_pxta(vector["pxta"])
    parsed_v1 = _parse_pxte_v1(vector["loop_pxte_v1"])
    parsed_v2 = _parse_pxte_v2(vector["pxte_v2"])
    return {
        "fixture_version": 1,
        "source": "independent Python struct/hashlib/cryptography S5 contract fixture",
        "test_only_notice": "TEST-ONLY deterministic keys; never production",
        "test_only_keys": TEST_ONLY_KEYS,
        "semantic": SEMANTIC,
        "protocol": PROTOCOL,
        "pxta_error_codes": PXTA_ERROR_CODES,
        "embedded_pxte_v1_error_codes": PXTE_V1_ERROR_CODES,
        "pxte_v2_error_codes": PXTE_V2_ERROR_CODES,
        "target_plan_v3_error_codes": TARGET_PLAN_V3_ERROR_CODES,
        "pxar_v3_error_codes": PXAR_V3_ERROR_CODES,
        "expected": {
            "canonical_binding_order_hex": [item["binding_id"].hex() for item in parsed_pxta],
            "canonical_loop_domain_order_hex": [
                item["domain_ref"].hex() for item in parsed_v1["domains"]
            ],
            "canonical_loop_execution_binding_order_hex": [
                item["binding_id"].hex() for item in parsed_v1["mailboxes"]
            ],
            "canonical_thread_domain_order_hex": [
                item["domain_ref"].hex() for item in parsed_v2["domains"]
            ],
            "canonical_thread_execution_binding_order_hex": [
                item["binding_id"].hex() for item in parsed_v2["mailboxes"]
            ],
            "pxta_body_hex": vector["pxta"].hex(),
            "pxta_body_length": len(vector["pxta"]),
            "pxta_digest_hex": vector["pxta_digest"].hex(),
            "embedded_pxte_v1_body_hex": vector["loop_pxte_v1"].hex(),
            "embedded_pxte_v1_body_length": len(vector["loop_pxte_v1"]),
            "embedded_pxte_v1_digest_hex": vector["loop_pxte_v1_digest"].hex(),
            "pxte_v2_body_hex": vector["pxte_v2"].hex(),
            "pxte_v2_body_length": len(vector["pxte_v2"]),
            "pxte_v2_digest_hex": vector["pxte_v2_digest"].hex(),
            "composite_v3_digest_hex": vector["composite_digest"].hex(),
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


def _replace_pxte_v2(outer: bytes, replacement: bytes) -> bytes:
    envelope_length, pxta_length, old_length = struct.unpack_from(">III", outer, 6)
    assert len(replacement) == old_length
    start = PXAR_V3_HEADER_BYTES + envelope_length + pxta_length
    return outer[:start] + replacement


def test_independent_rebuild_matches_s5_fixture() -> None:
    assert _load_fixture() == _fixture_document()


def test_embedded_pxte_v1_is_byte_exact_s4_not_a_replanned_loop_body() -> None:
    s4 = json.loads(S4_FIXTURE_PATH.read_text(encoding="utf-8"))
    vector = _build_vector()
    assert vector["loop_pxte_v1"].hex() == s4["expected"]["pxte_body_hex"]
    assert vector["loop_pxte_v1_digest"].hex() == s4["expected"]["pxte_digest_hex"]


def test_complete_v3_vector_round_trips_and_both_signatures_verify() -> None:
    vector = _build_vector()
    assert len(vector["pxta"]) == 522
    assert len(vector["loop_pxte_v1"]) == 314
    assert len(vector["pxte_v2"]) == 623
    parsed = _admit_outer_v3(
        vector["outer"], vector["tenure_public_key"], vector["request_public_key"]
    )
    assert [item["binding_id"].hex() for item in parsed["bindings"]] == [
        "31" * 16,
        "32" * 16,
    ]
    assert parsed["execution"]["loop"] is not None
    assert parsed["execution"]["maximum_threads"] == 3
    assert parsed["execution"]["framework_threads"] == 2
    assert parsed["s2_values"][7] == vector["composite_digest"]


def test_pxte_v2_optional_loop_body_is_absent_without_placeholder_records() -> None:
    vector = _build_vector(include_loop=False)
    assert len(vector["pxte_v2"]) == 309
    parsed = _admit_outer_v3(
        vector["outer"], vector["tenure_public_key"], vector["request_public_key"]
    )
    assert parsed["execution"]["loop"] is None
    assert struct.unpack_from(">I", vector["pxte_v2"], 6)[0] == 0


def test_pxte_and_pxar_versions_never_fallback() -> None:
    vector = _build_vector()
    with pytest.raises(ContractReject) as v1_pxte_rejects_v2:
        _parse_pxte_v1(vector["pxte_v2"])
    assert v1_pxte_rejects_v2.value.code == PXTE_V1_ERROR_CODES["unsupported_version"]
    with pytest.raises(ContractReject) as v2_pxte_rejects_v1:
        _parse_pxte_v2(vector["loop_pxte_v1"])
    assert v2_pxte_rejects_v1.value.code == PXTE_V2_ERROR_CODES["unsupported_version"]
    for old_version, old_header in ((PXAR_V1_VERSION, 14), (PXAR_V2_VERSION, 18)):
        with pytest.raises(ContractReject) as old_rejects_v3:
            _reject_non_version(vector["outer"], old_version, old_header)
        assert old_rejects_v3.value.code == PXAR_V3_ERROR_CODES["unsupported_version"]
        older = vector["outer"][:4] + _u16(old_version) + vector["outer"][6:]
        with pytest.raises(ContractReject) as v3_rejects_old:
            _parse_outer_v3(older)
        assert v3_rejects_old.value.code == PXAR_V3_ERROR_CODES["unsupported_version"]


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (lambda frame: b"BAD!" + frame[4:], PXTE_V2_ERROR_CODES["invalid_magic"]),
        (
            lambda frame: frame[:4] + _u16(3) + frame[6:],
            PXTE_V2_ERROR_CODES["unsupported_version"],
        ),
        (
            lambda frame: frame[:6] + _u32(PXTE_V1_MAX_BYTES + 1) + frame[10:],
            PXTE_V2_ERROR_CODES["loop_body_too_large"],
        ),
        (
            lambda frame: frame[:10] + _u32(PXTE_THREAD_MAX_DOMAINS + 1) + frame[14:],
            PXTE_V2_ERROR_CODES["domain_count_exceeded"],
        ),
        (
            lambda frame: frame[:14] + _u32(PXTA_MAX_RECORDS + 1) + frame[18:],
            PXTE_V2_ERROR_CODES["execution_count_exceeded"],
        ),
        (lambda frame: frame[:-1], PXTE_V2_ERROR_CODES["truncated"]),
        (lambda frame: frame + b"\0", PXTE_V2_ERROR_CODES["invalid_frame_length"]),
        (
            lambda frame: frame[:18] + _u32(0) + frame[22:],
            PXTE_V2_ERROR_CODES["invalid_executor_budget"],
        ),
    ],
)
def test_pxte_v2_structural_rejections_are_stable(mutator: Any, expected_code: int) -> None:
    with pytest.raises(ContractReject) as raised:
        _parse_pxte_v2(mutator(_build_vector()["pxte_v2"]))
    assert raised.value.code == expected_code


def test_nested_loop_rejection_preserves_the_v1_detail_code() -> None:
    vector = _build_vector()
    frame = bytearray(vector["pxte_v2"])
    frame[PXTE_V2_HEADER_BYTES + 4 : PXTE_V2_HEADER_BYTES + 6] = _u16(2)
    with pytest.raises(ContractReject) as raised:
        _parse_pxte_v2(bytes(frame))
    assert raised.value.code == PXTE_V2_ERROR_CODES["loop_execution_rejected"]
    assert raised.value.detail_code == PXTE_V1_ERROR_CODES["unsupported_version"]
    assert (raised.value.section, raised.value.record_index) == (1, 0)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("call_model", 1),
        ("workload_kind", 3),
        ("workload_kind", 5),
        ("workload_kind", 6),
        ("blocking_risk", 3),
        ("run_bound_provenance", 1),
        ("run_bound_provenance", 4),
    ],
)
def test_thread_profile_requires_sync_bounded_measured_or_certified(field: str, value: int) -> None:
    mailboxes = copy.deepcopy(SEMANTIC["thread_mailboxes"])
    mailboxes[0][field] = value
    frame = _build_vector(thread_mailboxes=mailboxes)["pxte_v2"]
    with pytest.raises(ContractReject) as raised:
        _parse_pxte_v2(frame)
    assert raised.value.code == PXTE_V2_ERROR_CODES["unsupported_thread_execution"]


def test_thread_control_and_unknown_enum_are_distinct_rejections() -> None:
    control = copy.deepcopy(SEMANTIC["thread_mailboxes"])
    control[0]["dispatch_class"] = 1
    with pytest.raises(ContractReject) as control_error:
        _parse_pxte_v2(_build_vector(thread_mailboxes=control)["pxte_v2"])
    assert control_error.value.code == PXTE_V2_ERROR_CODES["control_dispatch_forbidden"]

    vector = _build_vector()
    loop_length = len(vector["loop_pxte_v1"])
    enum_offset = (
        PXTE_V2_HEADER_BYTES + loop_length + PXTE_THREAD_DOMAIN_BYTES + 4 * 16 + 2 * 16 + 3 * 32
    )
    unknown = bytearray(vector["pxte_v2"])
    unknown[enum_offset] = 0xFF
    with pytest.raises(ContractReject) as enum_error:
        _parse_pxte_v2(bytes(unknown))
    assert enum_error.value.code == PXTE_V2_ERROR_CODES["invalid_enum_value"]
    assert (enum_error.value.section, enum_error.value.record_index) == (3, 0)


def test_executor_budget_is_exact_and_native_reservation_is_per_distinct_instance() -> None:
    assert _parse_pxte_v2(_build_vector()["pxte_v2"])["maximum_threads"] == 3
    too_small = {"max_total_threads": 2, "framework_threads": 2}
    with pytest.raises(ContractReject) as exceeded:
        _parse_pxte_v2(_build_vector(budget=too_small)["pxte_v2"])
    assert exceeded.value.code == PXTE_V2_ERROR_CODES["executor_budget_exceeded"]

    mailboxes = copy.deepcopy(SEMANTIC["thread_mailboxes"])
    mailboxes[0]["native_thread_reservation"] = 2
    second = copy.deepcopy(mailboxes[0])
    second["binding_id_hex"] = "33" * 16
    second["mailbox_ref_hex"] = "83" * 16
    mailboxes.append(second)
    domains = copy.deepcopy(SEMANTIC["thread_domains"])
    domains[0]["capacity_window_nanos"] = 4_000_000_000
    abstract_budget = {"max_total_threads": 5, "framework_threads": 2}
    frame = _canonical_pxte_v2(
        b"",
        abstract_budget,
        domains,
        mailboxes,
    )
    assert len(_parse_pxte_v2(frame)["mailboxes"]) == 2
    mailboxes[1]["target_instance_hex"] = "63" * 16
    with pytest.raises(ContractReject) as distinct_exceeded:
        _parse_pxte_v2(_canonical_pxte_v2(b"", abstract_budget, domains, mailboxes))
    assert distinct_exceeded.value.code == PXTE_V2_ERROR_CODES["executor_budget_exceeded"]


def test_thread_utilization_uses_workers_times_window_and_charges_cancellation() -> None:
    domains = copy.deepcopy(SEMANTIC["thread_domains"])
    domains[0]["capacity_window_nanos"] = 1_499_999_999
    with pytest.raises(ContractReject) as exceeded:
        _parse_pxte_v2(_build_vector(thread_domains=domains)["pxte_v2"])
    assert exceeded.value.code == PXTE_V2_ERROR_CODES["thread_utilization_exceeded"]
    domains[0]["capacity_window_nanos"] = 1_500_000_000
    assert _parse_pxte_v2(_build_vector(thread_domains=domains)["pxte_v2"])["domains"]


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("domain", "domain_ref_hex", "91" * 16),
        ("mailbox", "binding_id_hex", "31" * 16),
        ("mailbox", "mailbox_ref_hex", "81" * 16),
        ("mailbox", "target_instance_hex", "61" * 16),
    ],
)
def test_loop_and_thread_identities_cannot_overlap(section: str, field: str, value: str) -> None:
    domains = copy.deepcopy(SEMANTIC["thread_domains"])
    mailboxes = copy.deepcopy(SEMANTIC["thread_mailboxes"])
    (domains if section == "domain" else mailboxes)[0][field] = value
    if section == "domain":
        mailboxes[0]["domain_ref_hex"] = value
    frame = _build_vector(thread_domains=domains, thread_mailboxes=mailboxes)["pxte_v2"]
    with pytest.raises(ContractReject) as raised:
        _parse_pxte_v2(frame)
    assert raised.value.code == PXTE_V2_ERROR_CODES["cross_loop_thread_conflict"]


@pytest.mark.parametrize(
    ("field", "value", "expected_detail"),
    [
        ("binding_id_hex", "30" * 16, TARGET_PLAN_V3_ERROR_CODES["orphan_binding"]),
        (
            "mailbox_ref_hex",
            "83" * 16,
            TARGET_PLAN_V3_ERROR_CODES["binding_mailbox_mismatch"],
        ),
        (
            "target_instance_hex",
            "63" * 16,
            TARGET_PLAN_V3_ERROR_CODES["binding_target_mismatch"],
        ),
    ],
)
def test_thread_execution_references_exact_pxta_records(
    field: str, value: str, expected_detail: int
) -> None:
    mailboxes = copy.deepcopy(SEMANTIC["thread_mailboxes"])
    mailboxes[0][field] = value
    with pytest.raises(ContractReject) as raised:
        _parse_outer_v3(_build_vector(thread_mailboxes=mailboxes)["outer"])
    assert (raised.value.code, raised.value.detail_code) == (
        PXAR_V3_ERROR_CODES["target_plan_rejected"],
        expected_detail,
    )


def test_embedded_loop_same_target_requires_exact_nonpreemptive_bound() -> None:
    bindings = copy.deepcopy(SEMANTIC["bindings"])
    bindings.append(_binding("33", "43", "53", "61", "73", "83"))

    loop_mailboxes = copy.deepcopy(SEMANTIC["loop_mailboxes"])
    loop_mailboxes[0]["dispatch_class"] = 2
    loop_mailboxes[0]["max_arrivals_per_window"] = 1
    second = copy.deepcopy(loop_mailboxes[0])
    second["binding_id_hex"] = "33" * 16
    second["mailbox_ref_hex"] = "83" * 16
    second["max_nonpreemptive_run_nanos"] = 500_000_000
    loop_mailboxes.append(second)

    with pytest.raises(ContractReject) as raised:
        _parse_outer_v3(
            _build_vector(bindings=bindings, loop_mailboxes=loop_mailboxes)["outer"]
        )
    assert (raised.value.code, raised.value.detail_code) == (
        PXAR_V3_ERROR_CODES["target_plan_rejected"],
        TARGET_PLAN_V3_ERROR_CODES["invalid_target_plan"],
    )


def test_block_until_deadline_is_forbidden_for_all_executor_assignments() -> None:
    bindings = copy.deepcopy(SEMANTIC["bindings"])
    bindings[0]["delivery_overflow_policy"] = 5
    bindings[0]["mailbox_overflow_policy"] = 5
    with pytest.raises(ContractReject) as raised:
        _parse_outer_v3(_build_vector(bindings=bindings)["outer"])
    assert (raised.value.code, raised.value.detail_code) == (
        PXAR_V3_ERROR_CODES["target_plan_rejected"],
        TARGET_PLAN_V3_ERROR_CODES["block_until_deadline_forbidden"],
    )


def test_outer_recomputes_both_digests_and_rejects_nested_or_signature_tamper() -> None:
    vector = _build_vector()
    envelope_length, pxta_length, _ = struct.unpack_from(">III", vector["outer"], 6)
    pxte_start = PXAR_V3_HEADER_BYTES + envelope_length + pxta_length
    bad_magic = bytearray(vector["outer"])
    bad_magic[pxte_start] ^= 1
    with pytest.raises(ContractReject) as nested:
        _parse_outer_v3(bytes(bad_magic))
    assert (nested.value.code, nested.value.detail_code) == (
        PXAR_V3_ERROR_CODES["execution_rejected"],
        PXTE_V2_ERROR_CODES["invalid_magic"],
    )

    changed = copy.deepcopy(SEMANTIC["thread_mailboxes"])
    changed[0]["service_cost_tokens"] = 4
    replacement = _build_vector(thread_mailboxes=changed)["pxte_v2"]
    with pytest.raises(ContractReject) as commitment:
        _parse_outer_v3(_replace_pxte_v2(vector["outer"], replacement))
    assert commitment.value.code == PXAR_V3_ERROR_CODES["commitment_mismatch"]

    bad_signature = bytearray(vector["outer"])
    signature_offset = vector["outer"].find(vector["request_signature"])
    assert signature_offset >= PXAR_V3_HEADER_BYTES
    bad_signature[signature_offset] ^= 1
    _parse_outer_v3(bytes(bad_signature))
    with pytest.raises(SignatureReject):
        _admit_outer_v3(
            bytes(bad_signature), vector["tenure_public_key"], vector["request_public_key"]
        )
    with pytest.raises(SignatureReject):
        _admit_outer_v3(vector["outer"], bytes(32), vector["request_public_key"])


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (lambda frame: frame[:-1], PXAR_V3_ERROR_CODES["truncated"]),
        (lambda frame: frame + b"\0", PXAR_V3_ERROR_CODES["invalid_frame_length"]),
        (lambda frame: b"BAD!" + frame[4:], PXAR_V3_ERROR_CODES["invalid_magic"]),
        (
            lambda frame: frame[:4] + _u16(4) + frame[6:],
            PXAR_V3_ERROR_CODES["unsupported_version"],
        ),
    ],
)
def test_outer_v3_length_and_version_errors_are_stable(mutator: Any, expected_code: int) -> None:
    with pytest.raises(ContractReject) as raised:
        _parse_outer_v3(mutator(_build_vector()["outer"]))
    assert raised.value.code == expected_code


def test_unsorted_thread_records_are_rejected_not_normalized() -> None:
    domains = copy.deepcopy(SEMANTIC["thread_domains"])
    second_domain = copy.deepcopy(domains[0])
    second_domain["domain_ref_hex"] = "93" * 16
    domains.append(second_domain)
    mailboxes = copy.deepcopy(SEMANTIC["thread_mailboxes"])
    second_mailbox = copy.deepcopy(mailboxes[0])
    second_mailbox.update(
        {
            "binding_id_hex": "33" * 16,
            "mailbox_ref_hex": "83" * 16,
            "target_instance_hex": "63" * 16,
            "domain_ref_hex": "93" * 16,
            "card_definition_ref_hex": "c1" * 16,
            "card_implementation_ref_hex": "c2" * 16,
            "definition_digest_hex": "c3" * 32,
            "artifact_digest_hex": "c4" * 32,
            "config_digest_hex": "c5" * 32,
            "native_thread_reservation": 0,
        }
    )
    mailboxes.append(second_mailbox)
    budget = {"max_total_threads": 8, "framework_threads": 2}
    wire = bytearray(_canonical_pxte_v2(b"", budget, domains, mailboxes))
    domain_start = PXTE_V2_HEADER_BYTES
    domain_middle = domain_start + PXTE_THREAD_DOMAIN_BYTES
    domain_end = domain_middle + PXTE_THREAD_DOMAIN_BYTES
    first = bytes(wire[domain_start:domain_middle])
    second = bytes(wire[domain_middle:domain_end])
    wire[domain_start:domain_middle] = second
    wire[domain_middle:domain_end] = first
    with pytest.raises(ContractReject) as raised:
        _parse_pxte_v2(bytes(wire))
    assert raised.value.code == PXTE_V2_ERROR_CODES["non_canonical_frame"]


def test_stable_error_tables_and_preparse_bounds() -> None:
    assert list(PXTE_V2_ERROR_CODES.values()) == list(range(1, 27))
    assert list(TARGET_PLAN_V3_ERROR_CODES.values()) == list(range(1, 6))
    assert list(PXAR_V3_ERROR_CODES.values()) == list(range(1, 11))
    with pytest.raises(ContractReject) as pxte:
        _parse_pxte_v2(bytes(PXTE_V2_MAX_BYTES + 1))
    assert pxte.value.code == PXTE_V2_ERROR_CODES["frame_too_large"]
    with pytest.raises(ContractReject) as pxar:
        _parse_outer_v3(bytes(PXAR_V3_MAX_BYTES + 1))
    assert pxar.value.code == PXAR_V3_ERROR_CODES["frame_too_large"]
