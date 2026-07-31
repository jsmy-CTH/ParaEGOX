from __future__ import annotations

import copy
import json
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import test_s5_runtime_thread_execution_request as s5

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wire" / "s6_runtime_apply_request_v4.json"
S5_FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wire" / "s5_runtime_apply_request_v3.json"

PXTE_MAGIC = b"PXTE"
PXTE_V3_VERSION = 3
PXTE_V3_HEADER_BYTES = 18
PROCESS_DOMAIN_BYTES = 336
PROCESS_MAILBOX_BYTES = 289
MAX_PROCESS_DOMAINS = 64
MAX_PROCESS_MAILBOXES = 256
MAX_RESTART_ATTEMPTS = 1_024
MAX_PROCESS_WORKER_FRAME_BYTES = 1_048_576
PROCESS_WORKER_HEADER_BYTES = 148
MAX_IPC_PAYLOAD_BYTES = MAX_PROCESS_WORKER_FRAME_BYTES - PROCESS_WORKER_HEADER_BYTES - 24
MAX_PROCESS_WORKER_CREDITS = 4_096
MAX_PROCESS_WORKER_RETAINED_BYTES = 4 * 1_024 * 1_024 * 1_024
PXTE_V3_MAX_BYTES = (
    PXTE_V3_HEADER_BYTES
    + s5.PXTE_V2_MAX_BYTES
    + MAX_PROCESS_DOMAINS * PROCESS_DOMAIN_BYTES
    + MAX_PROCESS_MAILBOXES * PROCESS_MAILBOX_BYTES
)
PXTE_V3_DIGEST_DOMAIN = b"paraegox.runtime.target-execution.sha256.v3"
COMPOSITE_V4_DIGEST_DOMAIN = b"paraegox.runtime.target-plan-assignments.sha256.v4"

PXAR_MAGIC = b"PXAR"
PXAR_V4_VERSION = 4
PXAR_V4_HEADER_BYTES = 18
PXAR_V4_MAX_BYTES = PXAR_V4_HEADER_BYTES + 4_096 + s5.PXTA_MAX_BYTES + PXTE_V3_MAX_BYTES

PXTE_V3_ERROR_CODES = {
    "frame_too_large": 1,
    "truncated": 2,
    "invalid_magic": 3,
    "unsupported_version": 4,
    "thread_body_too_large": 5,
    "domain_count_exceeded": 6,
    "execution_count_exceeded": 7,
    "invalid_frame_length": 8,
    "thread_execution_rejected": 9,
    "invalid_enum_value": 10,
    "invalid_launch_spec": 11,
    "invalid_process_domain": 12,
    "invalid_process_execution": 13,
    "duplicate_domain_ref": 14,
    "duplicate_execution_binding": 15,
    "duplicate_execution_mailbox": 16,
    "orphan_domain_ref": 17,
    "unused_domain_ref": 18,
    "unsupported_process_execution": 19,
    "invalid_ipc_budget": 20,
    "invalid_liveness_budget": 21,
    "invalid_resource_budget": 22,
    "invalid_restart_policy": 23,
    "process_utilization_exceeded": 24,
    "cross_execution_conflict": 25,
    "process_subject_mismatch": 26,
    "missing_records": 27,
    "non_canonical_frame": 28,
}

TARGET_PLAN_V4_ERROR_CODES = {
    "orphan_binding": 1,
    "binding_mailbox_mismatch": 2,
    "binding_target_mismatch": 3,
    "block_until_deadline_forbidden": 4,
    "binding_payload_exceeds_ipc_frame": 5,
    "binding_inflight_exceeds_credit": 6,
    "invalid_target_plan": 7,
}

PXAR_V4_ERROR_CODES = {
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

ContractReject = s5.ContractReject


def _u8(value: int) -> bytes:
    return struct.pack(">B", value)


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _hex(value: str) -> bytes:
    return bytes.fromhex(value)


PROCESS_DOMAIN: dict[str, Any] = {
    "domain_ref_hex": "d1" * 16,
    "launch_profile_ref_hex": "d2" * 16,
    "launch_profile_digest_hex": "d3" * 32,
    "protocol_version": 1,
    "runtime_kind": 2,
    "runtime_min_major": 3,
    "runtime_min_minor": 11,
    "runtime_max_major": 3,
    "runtime_max_minor": 13,
    "target_profile_ref_hex": "d4" * 16,
    "target_profile_digest_hex": "d5" * 32,
    "sandbox_profile_ref_hex": "d6" * 16,
    "sandbox_profile_digest_hex": "d7" * 32,
    "max_outstanding": 8,
    "max_concurrent": 2,
    "capacity_window_nanos": 2_000_000_000,
    "ipc_credit_items": 8,
    "ipc_credit_bytes": 4_096,
    "max_retained_bytes": 8_192,
    "start_budget_nanos": 1_000_000_000,
    "heartbeat_interval_nanos": 100_000_000,
    "heartbeat_timeout_nanos": 500_000_000,
    "control_response_budget_nanos": 1_000_000_000,
    "drain_budget_nanos": 2_000_000_000,
    "cooperative_stop_budget_nanos": 1_000_000_000,
    "terminate_grace_nanos": 1_000_000_000,
    "kill_grace_nanos": 1_000_000_000,
    "cleanup_budget_nanos": 1_000_000_000,
    "max_memory_bytes": 65_536,
    "max_open_fds": 32,
    "max_process_tree_members": 4,
    "max_cpu_time_nanos": 2_000_000_000,
    "max_restart_attempts": 3,
    "restart_window_nanos": 60_000_000_000,
    "initial_backoff_nanos": 100_000_000,
    "max_backoff_nanos": 5_000_000_000,
    "jitter_basis_points": 50,
    "workspace_policy": 1,
    "access_policy": 1,
    "failure_containment_policy": 1,
}

PROCESS_MAILBOX: dict[str, Any] = {
    "binding_id_hex": "33" * 16,
    "mailbox_ref_hex": "83" * 16,
    "target_instance_hex": "63" * 16,
    "domain_ref_hex": "d1" * 16,
    "card_definition_ref_hex": "c1" * 16,
    "card_implementation_ref_hex": "c2" * 16,
    "definition_digest_hex": "c3" * 32,
    "artifact_digest_hex": "c4" * 32,
    "config_digest_hex": "c5" * 32,
    "entrypoint_ref_hex": "c6" * 16,
    "entrypoint_digest_hex": "c7" * 32,
    "call_model": 2,
    "workload_kind": 5,
    "blocking_risk": 3,
    "run_bound_provenance": 4,
    "side_effect_class": 2,
    "replay_policy": 1,
    "dispatch_class": 4,
    "service_cost_tokens": 7,
    "minimum_service_weight": 9,
    "max_burst": 2,
    "max_arrivals_per_window": 1,
    "invoke_ack_budget_nanos": 100_000_000,
    "run_budget_nanos": 1_000_000_000,
    "cancellation_grace_nanos": 500_000_000,
    "max_terminal_payload_bytes": 128,
}


def _bindings() -> list[dict[str, Any]]:
    values = copy.deepcopy(s5.SEMANTIC["bindings"])
    values.append(s5._binding("33", "43", "53", "63", "73", "83"))
    return values


def _s5_pxte_v2() -> bytes:
    document = json.loads(S5_FIXTURE_PATH.read_text(encoding="utf-8"))
    return bytes.fromhex(document["expected"]["pxte_v2_body_hex"])


def _encode_process_domain(value: dict[str, Any]) -> bytes:
    encoded = bytearray(_hex(value["domain_ref_hex"]))
    encoded += _hex(value["launch_profile_ref_hex"])
    encoded += _hex(value["launch_profile_digest_hex"])
    encoded += _u16(value["protocol_version"])
    encoded += _u8(value["runtime_kind"])
    encoded += _u16(value["runtime_min_major"])
    encoded += _u16(value["runtime_min_minor"])
    encoded += _u16(value["runtime_max_major"])
    encoded += _u16(value["runtime_max_minor"])
    encoded += _hex(value["target_profile_ref_hex"])
    encoded += _hex(value["target_profile_digest_hex"])
    encoded += _hex(value["sandbox_profile_ref_hex"])
    encoded += _hex(value["sandbox_profile_digest_hex"])
    encoded += _u32(value["max_outstanding"])
    encoded += _u32(value["max_concurrent"])
    encoded += _u64(value["capacity_window_nanos"])
    encoded += _u32(value["ipc_credit_items"])
    encoded += _u64(value["ipc_credit_bytes"])
    encoded += _u64(value["max_retained_bytes"])
    for field in (
        "start_budget_nanos",
        "heartbeat_interval_nanos",
        "heartbeat_timeout_nanos",
        "control_response_budget_nanos",
        "drain_budget_nanos",
        "cooperative_stop_budget_nanos",
        "terminate_grace_nanos",
        "kill_grace_nanos",
        "cleanup_budget_nanos",
    ):
        encoded += _u64(value[field])
    encoded += _u64(value["max_memory_bytes"])
    encoded += _u32(value["max_open_fds"])
    encoded += _u32(value["max_process_tree_members"])
    encoded += _u64(value["max_cpu_time_nanos"])
    encoded += _u32(value["max_restart_attempts"])
    encoded += _u64(value["restart_window_nanos"])
    encoded += _u64(value["initial_backoff_nanos"])
    encoded += _u64(value["max_backoff_nanos"])
    encoded += _u16(value["jitter_basis_points"])
    encoded += _u8(value["workspace_policy"])
    encoded += _u8(value["access_policy"])
    encoded += _u8(value["failure_containment_policy"])
    assert len(encoded) == PROCESS_DOMAIN_BYTES
    return bytes(encoded)


def _encode_process_mailbox(value: dict[str, Any]) -> bytes:
    encoded = bytearray()
    for field in (
        "binding_id_hex",
        "mailbox_ref_hex",
        "target_instance_hex",
        "domain_ref_hex",
        "card_definition_ref_hex",
        "card_implementation_ref_hex",
    ):
        encoded += _hex(value[field])
    for field in ("definition_digest_hex", "artifact_digest_hex", "config_digest_hex"):
        encoded += _hex(value[field])
    encoded += _hex(value["entrypoint_ref_hex"])
    encoded += _hex(value["entrypoint_digest_hex"])
    for field in (
        "call_model",
        "workload_kind",
        "blocking_risk",
        "run_bound_provenance",
        "side_effect_class",
        "replay_policy",
        "dispatch_class",
    ):
        encoded += _u8(value[field])
    encoded += _u32(value["service_cost_tokens"])
    encoded += _u32(value["minimum_service_weight"])
    encoded += _u16(value["max_burst"])
    encoded += _u32(value["max_arrivals_per_window"])
    encoded += _u64(value["invoke_ack_budget_nanos"])
    encoded += _u64(value["run_budget_nanos"])
    encoded += _u64(value["cancellation_grace_nanos"])
    encoded += _u32(value["max_terminal_payload_bytes"])
    assert len(encoded) == PROCESS_MAILBOX_BYTES
    return bytes(encoded)


def _canonical_pxte_v3(
    thread_wire: bytes,
    domains: list[dict[str, Any]],
    mailboxes: list[dict[str, Any]],
) -> bytes:
    domain_records = sorted(
        (_encode_process_domain(value) for value in domains), key=lambda x: x[:16]
    )
    mailbox_records = sorted(
        (_encode_process_mailbox(value) for value in mailboxes),
        key=lambda x: (x[:16], x[16:32], x[32:48], x[48:64]),
    )
    return (
        PXTE_MAGIC
        + _u16(PXTE_V3_VERSION)
        + _u32(len(thread_wire))
        + _u32(len(domain_records))
        + _u32(len(mailbox_records))
        + thread_wire
        + b"".join(domain_records)
        + b"".join(mailbox_records)
    )


def _record_error(code: int, section: int, index: int) -> ContractReject:
    return ContractReject(code, section=section, record_index=index)


def _valid_duration(value: int) -> bool:
    return 0 < value <= s5.MAX_EXECUTION_DURATION_NANOS


def _decode_process_domain(record: bytes, index: int) -> dict[str, Any]:
    cursor = s5._Cursor(record)
    value = {
        "domain_ref": cursor.take(16),
        "launch_profile_ref": cursor.take(16),
        "launch_profile_digest": cursor.take(32),
        "protocol_version": cursor.u16(),
        "runtime_kind": cursor.u8(),
        "runtime_min_major": cursor.u16(),
        "runtime_min_minor": cursor.u16(),
        "runtime_max_major": cursor.u16(),
        "runtime_max_minor": cursor.u16(),
        "target_profile_ref": cursor.take(16),
        "target_profile_digest": cursor.take(32),
        "sandbox_profile_ref": cursor.take(16),
        "sandbox_profile_digest": cursor.take(32),
        "max_outstanding": cursor.u32(),
        "max_concurrent": cursor.u32(),
        "capacity_window_nanos": cursor.u64(),
        "ipc_credit_items": cursor.u32(),
        "ipc_credit_bytes": cursor.u64(),
        "max_retained_bytes": cursor.u64(),
    }
    for field in (
        "start_budget_nanos",
        "heartbeat_interval_nanos",
        "heartbeat_timeout_nanos",
        "control_response_budget_nanos",
        "drain_budget_nanos",
        "cooperative_stop_budget_nanos",
        "terminate_grace_nanos",
        "kill_grace_nanos",
        "cleanup_budget_nanos",
    ):
        value[field] = cursor.u64()
    value.update(
        {
            "max_memory_bytes": cursor.u64(),
            "max_open_fds": cursor.u32(),
            "max_process_tree_members": cursor.u32(),
            "max_cpu_time_nanos": cursor.u64(),
            "max_restart_attempts": cursor.u32(),
            "restart_window_nanos": cursor.u64(),
            "initial_backoff_nanos": cursor.u64(),
            "max_backoff_nanos": cursor.u64(),
            "jitter_basis_points": cursor.u16(),
            "workspace_policy": cursor.u8(),
            "access_policy": cursor.u8(),
            "failure_containment_policy": cursor.u8(),
            "canonical_record": record,
        }
    )
    if value["runtime_kind"] not in {1, 2} or any(
        value[field] != 1
        for field in ("workspace_policy", "access_policy", "failure_containment_policy")
    ):
        raise _record_error(PXTE_V3_ERROR_CODES["invalid_enum_value"], 2, index)
    ordered_runtime = (
        value["runtime_min_major"],
        value["runtime_min_minor"],
    ) <= (value["runtime_max_major"], value["runtime_max_minor"])
    if (
        value["protocol_version"] == 0
        or value["runtime_min_major"] == 0
        or value["runtime_max_major"] == 0
        or not ordered_runtime
    ):
        raise _record_error(PXTE_V3_ERROR_CODES["invalid_launch_spec"], 2, index)
    if not (
        0 < value["max_concurrent"] <= value["max_outstanding"] <= MAX_PROCESS_WORKER_CREDITS
        and value["max_concurrent"] <= value["ipc_credit_items"] <= value["max_outstanding"]
        and 0
        < value["ipc_credit_bytes"]
        <= value["max_retained_bytes"]
        <= MAX_PROCESS_WORKER_RETAINED_BYTES
        and _valid_duration(value["capacity_window_nanos"])
    ):
        raise _record_error(PXTE_V3_ERROR_CODES["invalid_ipc_budget"], 2, index)
    lifecycle = [
        value[field]
        for field in (
            "start_budget_nanos",
            "heartbeat_interval_nanos",
            "heartbeat_timeout_nanos",
            "control_response_budget_nanos",
            "drain_budget_nanos",
            "cooperative_stop_budget_nanos",
            "terminate_grace_nanos",
            "kill_grace_nanos",
            "cleanup_budget_nanos",
        )
    ]
    if (
        not all(_valid_duration(item) for item in lifecycle)
        or value["heartbeat_timeout_nanos"] <= value["heartbeat_interval_nanos"]
    ):
        raise _record_error(PXTE_V3_ERROR_CODES["invalid_liveness_budget"], 2, index)
    if not (
        value["max_memory_bytes"] >= value["max_retained_bytes"] > 0
        and value["max_open_fds"] > 0
        and value["max_process_tree_members"] > 0
        and _valid_duration(value["max_cpu_time_nanos"])
    ):
        raise _record_error(PXTE_V3_ERROR_CODES["invalid_resource_budget"], 2, index)
    if not (
        value["max_restart_attempts"] <= MAX_RESTART_ATTEMPTS
        and _valid_duration(value["restart_window_nanos"])
        and _valid_duration(value["initial_backoff_nanos"])
        and _valid_duration(value["max_backoff_nanos"])
        and value["initial_backoff_nanos"]
        <= value["max_backoff_nanos"]
        <= value["restart_window_nanos"]
        and value["jitter_basis_points"] <= 10_000
    ):
        raise _record_error(PXTE_V3_ERROR_CODES["invalid_restart_policy"], 2, index)
    return value


def _decode_process_mailbox(record: bytes, index: int) -> dict[str, Any]:
    cursor = s5._Cursor(record)
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
        "entrypoint_ref": cursor.take(16),
        "entrypoint_digest": cursor.take(32),
        "call_model": cursor.u8(),
        "workload_kind": cursor.u8(),
        "blocking_risk": cursor.u8(),
        "run_bound_provenance": cursor.u8(),
        "side_effect_class": cursor.u8(),
        "replay_policy": cursor.u8(),
        "dispatch_class": cursor.u8(),
        "service_cost_tokens": cursor.u32(),
        "minimum_service_weight": cursor.u32(),
        "max_burst": cursor.u16(),
        "max_arrivals_per_window": cursor.u32(),
        "invoke_ack_budget_nanos": cursor.u64(),
        "run_budget_nanos": cursor.u64(),
        "cancellation_grace_nanos": cursor.u64(),
        "max_terminal_payload_bytes": cursor.u32(),
        "canonical_record": record,
    }
    enum_values = {
        "call_model": {1, 2, 3},
        "workload_kind": {1, 2, 3, 4, 5, 6},
        "blocking_risk": {1, 2, 3},
        "run_bound_provenance": {1, 2, 3, 4},
        "side_effect_class": {1, 2, 3},
        "replay_policy": {1},
        "dispatch_class": {1, 2, 3, 4},
    }
    if any(value[field] not in admitted for field, admitted in enum_values.items()):
        raise _record_error(PXTE_V3_ERROR_CODES["invalid_enum_value"], 3, index)
    if value["dispatch_class"] == 1:
        raise _record_error(PXTE_V3_ERROR_CODES["unsupported_process_execution"], 3, index)
    if not (
        0 < value["service_cost_tokens"] <= s5.MAX_SERVICE_COST_TOKENS
        and 0 < value["minimum_service_weight"] <= s5.MAX_MINIMUM_SERVICE_WEIGHT
        and value["max_burst"] > 0
        and 0 < value["max_arrivals_per_window"] <= s5.MAX_ARRIVALS_PER_WINDOW
        and _valid_duration(value["invoke_ack_budget_nanos"])
        and _valid_duration(value["run_budget_nanos"])
        and _valid_duration(value["cancellation_grace_nanos"])
        and value["max_terminal_payload_bytes"] <= MAX_IPC_PAYLOAD_BYTES
    ):
        raise _record_error(PXTE_V3_ERROR_CODES["invalid_process_execution"], 3, index)
    return value


def _same_process_subject(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(
        left[field] == right[field]
        for field in (
            "target_instance",
            "domain_ref",
            "card_definition_ref",
            "card_implementation_ref",
            "definition_digest",
            "artifact_digest",
            "config_digest",
            "entrypoint_ref",
            "entrypoint_digest",
            "call_model",
            "workload_kind",
            "blocking_risk",
            "run_bound_provenance",
            "side_effect_class",
            "replay_policy",
            "invoke_ack_budget_nanos",
            "run_budget_nanos",
            "cancellation_grace_nanos",
            "max_terminal_payload_bytes",
        )
    )


def _validate_process_records(
    prior: dict[str, Any] | None,
    domains: list[dict[str, Any]],
    mailboxes: list[dict[str, Any]],
) -> None:
    for index, domain in enumerate(domains):
        if any(item["domain_ref"] == domain["domain_ref"] for item in domains[:index]):
            raise ContractReject(PXTE_V3_ERROR_CODES["duplicate_domain_ref"])
    for index, mailbox in enumerate(mailboxes):
        for previous in mailboxes[:index]:
            if previous["binding_id"] == mailbox["binding_id"]:
                raise ContractReject(PXTE_V3_ERROR_CODES["duplicate_execution_binding"])
            if previous["mailbox_ref"] == mailbox["mailbox_ref"]:
                raise ContractReject(PXTE_V3_ERROR_CODES["duplicate_execution_mailbox"])
            if previous["domain_ref"] == mailbox["domain_ref"] and not _same_process_subject(
                previous, mailbox
            ):
                raise ContractReject(PXTE_V3_ERROR_CODES["process_subject_mismatch"])
            if previous["target_instance"] == mailbox[
                "target_instance"
            ] and not _same_process_subject(previous, mailbox):
                raise ContractReject(PXTE_V3_ERROR_CODES["process_subject_mismatch"])
        if not any(domain["domain_ref"] == mailbox["domain_ref"] for domain in domains):
            raise ContractReject(PXTE_V3_ERROR_CODES["orphan_domain_ref"])
    for domain in domains:
        assigned = [item for item in mailboxes if item["domain_ref"] == domain["domain_ref"]]
        if not assigned:
            raise ContractReject(PXTE_V3_ERROR_CODES["unused_domain_ref"])
        demand = 0
        for mailbox in assigned:
            occupancy = mailbox["run_budget_nanos"] + mailbox["cancellation_grace_nanos"]
            if occupancy > domain["capacity_window_nanos"]:
                raise ContractReject(PXTE_V3_ERROR_CODES["invalid_liveness_budget"])
            demand += mailbox["max_arrivals_per_window"] * occupancy
        capacity = domain["max_concurrent"] * domain["capacity_window_nanos"]
        if demand > capacity:
            raise ContractReject(PXTE_V3_ERROR_CODES["process_utilization_exceeded"])
    if prior is None:
        return
    prior_domains = list(prior["domains"])
    if prior["loop"] is not None:
        prior_domains += prior["loop"]["domains"]
    if any(
        process["domain_ref"] == previous["domain_ref"]
        for process in domains
        for previous in prior_domains
    ):
        raise ContractReject(PXTE_V3_ERROR_CODES["cross_execution_conflict"])
    prior_mailboxes = list(prior["mailboxes"])
    if prior["loop"] is not None:
        prior_mailboxes += prior["loop"]["mailboxes"]
    for process in mailboxes:
        for previous in prior_mailboxes:
            if any(
                process[field] == previous[field]
                for field in ("binding_id", "mailbox_ref", "target_instance")
            ):
                raise ContractReject(PXTE_V3_ERROR_CODES["cross_execution_conflict"])


def _parse_pxte_v3(frame: bytes) -> dict[str, Any]:
    if len(frame) > PXTE_V3_MAX_BYTES:
        raise ContractReject(PXTE_V3_ERROR_CODES["frame_too_large"])
    if len(frame) < PXTE_V3_HEADER_BYTES:
        raise ContractReject(PXTE_V3_ERROR_CODES["truncated"])
    if frame[:4] != PXTE_MAGIC:
        raise ContractReject(PXTE_V3_ERROR_CODES["invalid_magic"])
    version, prior_length, domain_count, mailbox_count = struct.unpack_from(">HIII", frame, 4)
    if version != PXTE_V3_VERSION:
        raise ContractReject(PXTE_V3_ERROR_CODES["unsupported_version"])
    if prior_length > s5.PXTE_V2_MAX_BYTES:
        raise ContractReject(PXTE_V3_ERROR_CODES["thread_body_too_large"])
    if domain_count > MAX_PROCESS_DOMAINS:
        raise ContractReject(PXTE_V3_ERROR_CODES["domain_count_exceeded"])
    if mailbox_count > MAX_PROCESS_MAILBOXES:
        raise ContractReject(PXTE_V3_ERROR_CODES["execution_count_exceeded"])
    expected = (
        PXTE_V3_HEADER_BYTES
        + prior_length
        + domain_count * PROCESS_DOMAIN_BYTES
        + mailbox_count * PROCESS_MAILBOX_BYTES
    )
    if len(frame) < expected:
        raise ContractReject(PXTE_V3_ERROR_CODES["truncated"])
    if len(frame) != expected:
        raise ContractReject(PXTE_V3_ERROR_CODES["invalid_frame_length"])
    prior_end = PXTE_V3_HEADER_BYTES + prior_length
    prior = None
    if prior_length:
        try:
            prior = s5._parse_pxte_v2(frame[PXTE_V3_HEADER_BYTES:prior_end])
        except ContractReject as error:
            raise ContractReject(
                PXTE_V3_ERROR_CODES["thread_execution_rejected"],
                detail_code=error.code,
                section=1,
                record_index=0,
            ) from error
    domain_end = prior_end + domain_count * PROCESS_DOMAIN_BYTES
    domains = [
        _decode_process_domain(
            frame[
                prior_end + index * PROCESS_DOMAIN_BYTES : prior_end
                + (index + 1) * PROCESS_DOMAIN_BYTES
            ],
            index,
        )
        for index in range(domain_count)
    ]
    mailboxes = [
        _decode_process_mailbox(
            frame[
                domain_end + index * PROCESS_MAILBOX_BYTES : domain_end
                + (index + 1) * PROCESS_MAILBOX_BYTES
            ],
            index,
        )
        for index in range(mailbox_count)
    ]
    if not domains or not mailboxes:
        raise ContractReject(PXTE_V3_ERROR_CODES["missing_records"])
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
    _validate_process_records(prior, ordered_domains, ordered_mailboxes)
    canonical = (
        PXTE_MAGIC
        + _u16(PXTE_V3_VERSION)
        + _u32(prior_length)
        + _u32(len(ordered_domains))
        + _u32(len(ordered_mailboxes))
        + (b"" if prior is None else prior["wire"])
        + b"".join(item["canonical_record"] for item in ordered_domains)
        + b"".join(item["canonical_record"] for item in ordered_mailboxes)
    )
    if canonical != frame:
        raise ContractReject(PXTE_V3_ERROR_CODES["non_canonical_frame"])
    return {
        "prior": prior,
        "domains": ordered_domains,
        "mailboxes": ordered_mailboxes,
        "wire": frame,
    }


def _validate_target_plan_v4(bindings: list[dict[str, Any]], execution: dict[str, Any]) -> None:
    if any(
        item["delivery_overflow_policy"] == 5 or item["mailbox_overflow_policy"] == 5
        for item in bindings
    ):
        raise ContractReject(TARGET_PLAN_V4_ERROR_CODES["block_until_deadline_forbidden"])
    if execution["prior"] is not None:
        try:
            s5._validate_target_plan_v3(bindings, execution["prior"])
        except ContractReject as error:
            raise ContractReject(TARGET_PLAN_V4_ERROR_CODES["invalid_target_plan"]) from error
    domains = {item["domain_ref"]: item for item in execution["domains"]}
    for mailbox in execution["mailboxes"]:
        binding = next(
            (item for item in bindings if item["binding_id"] == mailbox["binding_id"]), None
        )
        if binding is None:
            raise ContractReject(TARGET_PLAN_V4_ERROR_CODES["orphan_binding"])
        if binding["mailbox_ref"] != mailbox["mailbox_ref"]:
            raise ContractReject(TARGET_PLAN_V4_ERROR_CODES["binding_mailbox_mismatch"])
        if binding["target_instance"] != mailbox["target_instance"]:
            raise ContractReject(TARGET_PLAN_V4_ERROR_CODES["binding_target_mismatch"])
        domain = domains[mailbox["domain_ref"]]
        payload = binding["delivery_max_payload_bytes"]
        if (
            payload > MAX_IPC_PAYLOAD_BYTES
            or payload > domain["ipc_credit_bytes"]
            or payload > domain["max_retained_bytes"]
            or mailbox["max_terminal_payload_bytes"] > domain["ipc_credit_bytes"]
        ):
            raise ContractReject(TARGET_PLAN_V4_ERROR_CODES["binding_payload_exceeds_ipc_frame"])
        if (
            binding["mailbox_max_inflight"] > domain["max_outstanding"]
            or binding["mailbox_max_inflight"] > domain["ipc_credit_items"]
        ):
            raise ContractReject(TARGET_PLAN_V4_ERROR_CODES["binding_inflight_exceeds_credit"])


def _build_vector(
    *,
    bindings: list[dict[str, Any]] | None = None,
    thread_wire: bytes | None = None,
    domains: list[dict[str, Any]] | None = None,
    mailboxes: list[dict[str, Any]] | None = None,
) -> dict[str, bytes]:
    binding_values = _bindings() if bindings is None else bindings
    embedded = _s5_pxte_v2() if thread_wire is None else thread_wire
    domain_values = [copy.deepcopy(PROCESS_DOMAIN)] if domains is None else domains
    mailbox_values = [copy.deepcopy(PROCESS_MAILBOX)] if mailboxes is None else mailboxes
    pxta = s5._canonical_pxta(binding_values)
    pxte_v3 = _canonical_pxte_v3(embedded, domain_values, mailbox_values)
    pxta_digest = s5._canonical_digest(s5.PXTA_DIGEST_DOMAIN, [pxta])
    pxte_v3_digest = s5._canonical_digest(PXTE_V3_DIGEST_DOMAIN, [pxte_v3])
    composite_digest = s5._canonical_digest(
        COMPOSITE_V4_DIGEST_DOMAIN, [pxta_digest, pxte_v3_digest]
    )
    s2 = s5._build_s2(composite_digest)
    envelope = s2["envelope"]
    outer = (
        PXAR_MAGIC
        + _u16(PXAR_V4_VERSION)
        + _u32(len(envelope))
        + _u32(len(pxta))
        + _u32(len(pxte_v3))
        + envelope
        + pxta
        + pxte_v3
    )
    return {
        **s2,
        "pxta": pxta,
        "pxte_v2": embedded,
        "pxte_v3": pxte_v3,
        "pxta_digest": pxta_digest,
        "pxte_v3_digest": pxte_v3_digest,
        "composite_digest": composite_digest,
        "outer": outer,
    }


def _parse_outer_v4(frame: bytes) -> dict[str, Any]:
    if len(frame) > PXAR_V4_MAX_BYTES:
        raise ContractReject(PXAR_V4_ERROR_CODES["frame_too_large"])
    if len(frame) < PXAR_V4_HEADER_BYTES:
        raise ContractReject(PXAR_V4_ERROR_CODES["truncated"])
    if frame[:4] != PXAR_MAGIC:
        raise ContractReject(PXAR_V4_ERROR_CODES["invalid_magic"])
    version, envelope_length, pxta_length, pxte_length = struct.unpack_from(">HIII", frame, 4)
    if version != PXAR_V4_VERSION:
        raise ContractReject(PXAR_V4_ERROR_CODES["unsupported_version"])
    expected = PXAR_V4_HEADER_BYTES + envelope_length + pxta_length + pxte_length
    if len(frame) < expected:
        raise ContractReject(PXAR_V4_ERROR_CODES["truncated"])
    if len(frame) != expected:
        raise ContractReject(PXAR_V4_ERROR_CODES["invalid_frame_length"])
    envelope_start = PXAR_V4_HEADER_BYTES
    envelope_end = envelope_start + envelope_length
    pxta_end = envelope_end + pxta_length
    envelope = frame[envelope_start:envelope_end]
    pxta = frame[envelope_end:pxta_end]
    pxte = frame[pxta_end:]
    try:
        s2_values = s5._decode_s2(envelope)
    except ContractReject as error:
        raise ContractReject(
            PXAR_V4_ERROR_CODES["envelope_rejected"], detail_code=error.code
        ) from error
    try:
        bindings = s5._parse_pxta(pxta)
    except ContractReject as error:
        raise ContractReject(
            PXAR_V4_ERROR_CODES["bindings_rejected"], detail_code=error.code
        ) from error
    try:
        execution = _parse_pxte_v3(pxte)
    except ContractReject as error:
        raise ContractReject(
            PXAR_V4_ERROR_CODES["execution_rejected"], detail_code=error.code
        ) from error
    try:
        _validate_target_plan_v4(bindings, execution)
    except ContractReject as error:
        raise ContractReject(
            PXAR_V4_ERROR_CODES["target_plan_rejected"], detail_code=error.code
        ) from error
    pxta_digest = s5._canonical_digest(s5.PXTA_DIGEST_DOMAIN, [pxta])
    pxte_digest = s5._canonical_digest(PXTE_V3_DIGEST_DOMAIN, [pxte])
    composite = s5._canonical_digest(COMPOSITE_V4_DIGEST_DOMAIN, [pxta_digest, pxte_digest])
    if s2_values[7] != composite:
        raise ContractReject(PXAR_V4_ERROR_CODES["commitment_mismatch"])
    return {
        "s2_values": s2_values,
        "bindings": bindings,
        "execution": execution,
        "pxta_digest": pxta_digest,
        "pxte_v3_digest": pxte_digest,
        "composite_digest": composite,
    }


def _admit_outer_v4(frame: bytes, tenure_key: bytes, request_key: bytes) -> dict[str, Any]:
    parsed = _parse_outer_v4(frame)
    s5._verify_s2_signatures(parsed["s2_values"], tenure_key, request_key)
    return parsed


def _replace_pxte(outer: bytes, replacement: bytes) -> bytes:
    envelope_length, pxta_length, _ = struct.unpack_from(">III", outer, 6)
    start = PXAR_V4_HEADER_BYTES + envelope_length + pxta_length
    return outer[:14] + _u32(len(replacement)) + outer[18:start] + replacement


def _fixture_document() -> dict[str, Any]:
    vector = _build_vector()
    parsed = _parse_outer_v4(vector["outer"])
    return {
        "fixture_version": 1,
        "source": "independent Python struct/hashlib/cryptography S6 process desired-state fixture",
        "test_only_notice": "TEST-ONLY deterministic keys; never production",
        "test_only_keys": s5.TEST_ONLY_KEYS,
        "semantic": {
            "bindings": _bindings(),
            "process_domains": [PROCESS_DOMAIN],
            "process_mailboxes": [PROCESS_MAILBOX],
        },
        "protocol": {
            "pxte_v3_version": PXTE_V3_VERSION,
            "pxte_v3_header": (
                "magic:4,version:u16-be,pxte_v2_len:u32-be,"
                "process_domain_count:u32-be,process_execution_count:u32-be"
            ),
            "process_domain_record_bytes": PROCESS_DOMAIN_BYTES,
            "process_mailbox_record_bytes": PROCESS_MAILBOX_BYTES,
            "pxte_v3_digest_domain_hex": PXTE_V3_DIGEST_DOMAIN.hex(),
            "composite_v4_digest_domain_hex": COMPOSITE_V4_DIGEST_DOMAIN.hex(),
            "pxar_v4_version": PXAR_V4_VERSION,
            "max_pxte_v3_bytes": PXTE_V3_MAX_BYTES,
            "max_pxar_v4_bytes": PXAR_V4_MAX_BYTES,
            "max_process_worker_frame_bytes": MAX_PROCESS_WORKER_FRAME_BYTES,
            "max_process_worker_payload_bytes": MAX_IPC_PAYLOAD_BYTES,
            "max_process_worker_credits": MAX_PROCESS_WORKER_CREDITS,
            "max_process_worker_retained_bytes": MAX_PROCESS_WORKER_RETAINED_BYTES,
            "embedded_pxte_v2_source": "tests/fixtures/wire/s5_runtime_apply_request_v3.json",
        },
        "pxte_v3_error_codes": PXTE_V3_ERROR_CODES,
        "target_plan_v4_error_codes": TARGET_PLAN_V4_ERROR_CODES,
        "pxar_v4_error_codes": PXAR_V4_ERROR_CODES,
        "expected": {
            "canonical_binding_order_hex": [
                item["binding_id"].hex() for item in parsed["bindings"]
            ],
            "canonical_process_domain_order_hex": [
                item["domain_ref"].hex() for item in parsed["execution"]["domains"]
            ],
            "canonical_process_execution_binding_order_hex": [
                item["binding_id"].hex() for item in parsed["execution"]["mailboxes"]
            ],
            "pxta_body_hex": vector["pxta"].hex(),
            "pxta_body_length": len(vector["pxta"]),
            "pxta_digest_hex": vector["pxta_digest"].hex(),
            "embedded_pxte_v2_body_hex": vector["pxte_v2"].hex(),
            "embedded_pxte_v2_body_length": len(vector["pxte_v2"]),
            "pxte_v3_body_hex": vector["pxte_v3"].hex(),
            "pxte_v3_body_length": len(vector["pxte_v3"]),
            "pxte_v3_digest_hex": vector["pxte_v3_digest"].hex(),
            "composite_v4_digest_hex": vector["composite_digest"].hex(),
            "target_slice_digest_hex": vector["target_slice_digest"].hex(),
            "tenure_public_key_hex": vector["tenure_public_key"].hex(),
            "tenure_signature_hex": vector["tenure_signature"].hex(),
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


def test_independent_rebuild_matches_s6_fixture() -> None:
    assert _fixture_document() == _load_fixture()


def test_complete_v4_vector_round_trips_and_signatures_verify() -> None:
    fixture = _load_fixture()
    expected = fixture["expected"]
    outer = bytes.fromhex(expected["outer_wire_hex"])
    parsed = _admit_outer_v4(
        outer,
        bytes.fromhex(expected["tenure_public_key_hex"]),
        bytes.fromhex(expected["request_public_key_hex"]),
    )
    assert parsed["composite_digest"].hex() == expected["composite_v4_digest_hex"]
    assert parsed["pxte_v3_digest"].hex() == expected["pxte_v3_digest_hex"]


def test_embedded_pxte_v2_is_byte_exact_s5_fixture() -> None:
    fixture = _load_fixture()["expected"]
    s5_fixture = json.loads(S5_FIXTURE_PATH.read_text(encoding="utf-8"))["expected"]
    assert fixture["embedded_pxte_v2_body_hex"] == s5_fixture["pxte_v2_body_hex"]
    parsed = _parse_pxte_v3(bytes.fromhex(fixture["pxte_v3_body_hex"]))
    assert parsed["prior"]["wire"].hex() == s5_fixture["pxte_v2_body_hex"]


def test_process_only_pxte_v3_has_zero_prior_length_without_placeholder() -> None:
    vector = _build_vector(bindings=[_bindings()[2]], thread_wire=b"")
    parsed = _parse_outer_v4(vector["outer"])
    assert parsed["execution"]["prior"] is None
    assert struct.unpack_from(">I", vector["pxte_v3"], 6)[0] == 0


def test_pxte_and_pxar_versions_never_fallback() -> None:
    vector = _build_vector()
    prior = bytearray(vector["pxte_v3"])
    prior[4:6] = _u16(2)
    with pytest.raises(ContractReject) as rejected:
        _parse_pxte_v3(bytes(prior))
    assert rejected.value.code == PXTE_V3_ERROR_CODES["unsupported_version"]
    outer = bytearray(vector["outer"])
    outer[4:6] = _u16(3)
    with pytest.raises(ContractReject) as rejected:
        _parse_outer_v4(bytes(outer))
    assert rejected.value.code == PXAR_V4_ERROR_CODES["unsupported_version"]


@pytest.mark.parametrize(
    ("mutator", "expected"),
    [
        (lambda wire: b"BAD!" + wire[4:], "invalid_magic"),
        (lambda wire: wire[:10], "truncated"),
        (lambda wire: wire + b"x", "invalid_frame_length"),
        (lambda wire: wire[:10] + _u32(65) + wire[14:], "domain_count_exceeded"),
        (lambda wire: wire[:14] + _u32(257) + wire[18:], "execution_count_exceeded"),
    ],
)
def test_pxte_v3_structural_rejections_are_stable(
    mutator: Callable[[bytes], bytes], expected: str
) -> None:
    with pytest.raises(ContractReject) as rejected:
        _parse_pxte_v3(mutator(_build_vector()["pxte_v3"]))
    assert rejected.value.code == PXTE_V3_ERROR_CODES[expected]


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"runtime_kind": 0}, "invalid_enum_value"),
        ({"max_outstanding": 0}, "invalid_ipc_budget"),
        ({"heartbeat_timeout_nanos": 100_000_000}, "invalid_liveness_budget"),
        ({"max_memory_bytes": 0}, "invalid_resource_budget"),
        ({"max_restart_attempts": 1_025}, "invalid_restart_policy"),
    ],
)
def test_process_domain_record_bounds_are_fail_closed(
    change: dict[str, int], expected: str
) -> None:
    domain = {**copy.deepcopy(PROCESS_DOMAIN), **change}
    with pytest.raises(ContractReject) as rejected:
        _parse_pxte_v3(_canonical_pxte_v3(b"", [domain], [PROCESS_MAILBOX]))
    assert rejected.value.code == PXTE_V3_ERROR_CODES[expected]


def test_no_replay_is_the_only_admitted_replay_policy() -> None:
    vector = _build_vector(thread_wire=b"")
    wire = bytearray(vector["pxte_v3"])
    replay = PXTE_V3_HEADER_BYTES + PROCESS_DOMAIN_BYTES + 64 + 128 + 48 + 5
    wire[replay] = 2
    with pytest.raises(ContractReject) as rejected:
        _parse_pxte_v3(bytes(wire))
    assert rejected.value.code == PXTE_V3_ERROR_CODES["invalid_enum_value"]
    assert rejected.value.section == 3
    assert rejected.value.record_index == 0


@pytest.mark.parametrize(
    "change",
    [
        {"max_outstanding": MAX_PROCESS_WORKER_CREDITS + 1},
        {
            "ipc_credit_bytes": MAX_PROCESS_WORKER_RETAINED_BYTES + 1,
            "max_retained_bytes": MAX_PROCESS_WORKER_RETAINED_BYTES + 1,
        },
        {"max_retained_bytes": MAX_PROCESS_WORKER_RETAINED_BYTES + 1},
    ],
)
def test_signed_capacity_cannot_exceed_pxwp_start_limits(change: dict[str, int]) -> None:
    domain = {**copy.deepcopy(PROCESS_DOMAIN), **change}
    with pytest.raises(ContractReject) as rejected:
        _parse_pxte_v3(_canonical_pxte_v3(b"", [domain], [PROCESS_MAILBOX]))
    assert rejected.value.code == PXTE_V3_ERROR_CODES["invalid_ipc_budget"]


def test_duplicate_orphan_unused_and_utilization_rules() -> None:
    domain = copy.deepcopy(PROCESS_DOMAIN)
    mailbox = copy.deepcopy(PROCESS_MAILBOX)
    for domains, mailboxes, expected in (
        ([domain, copy.deepcopy(domain)], [mailbox], "duplicate_domain_ref"),
        ([domain], [{**mailbox, "domain_ref_hex": "ee" * 16}], "orphan_domain_ref"),
        (
            [domain, {**copy.deepcopy(domain), "domain_ref_hex": "ee" * 16}],
            [mailbox],
            "unused_domain_ref",
        ),
            (
                [{**domain, "capacity_window_nanos": 1_000_000_000, "max_concurrent": 1}],
                [
                    {
                        **mailbox,
                        "run_budget_nanos": 400_000_000,
                        "cancellation_grace_nanos": 100_000_000,
                        "max_arrivals_per_window": 3,
                    }
                ],
                "process_utilization_exceeded",
            ),
    ):
        with pytest.raises(ContractReject) as rejected:
            _parse_pxte_v3(_canonical_pxte_v3(b"", domains, mailboxes))
        assert rejected.value.code == PXTE_V3_ERROR_CODES[expected]


@pytest.mark.parametrize(
    ("prior_section", "field"),
    [
        ("domains", "domain_ref_hex"),
        ("mailboxes", "binding_id_hex"),
        ("mailboxes", "mailbox_ref_hex"),
        ("mailboxes", "target_instance_hex"),
    ],
)
def test_loop_thread_process_identities_cannot_overlap(prior_section: str, field: str) -> None:
    prior = s5._parse_pxte_v2(_s5_pxte_v2())
    prior_record = prior[prior_section][0]
    if prior_section == "domains":
        domain = {**copy.deepcopy(PROCESS_DOMAIN), field: prior_record["domain_ref"].hex()}
        mailbox = {
            **copy.deepcopy(PROCESS_MAILBOX),
            "domain_ref_hex": prior_record["domain_ref"].hex(),
        }
    else:
        domain = copy.deepcopy(PROCESS_DOMAIN)
        mailbox = {
            **copy.deepcopy(PROCESS_MAILBOX),
            field: prior_record[field.removesuffix("_hex")].hex(),
        }
    with pytest.raises(ContractReject) as rejected:
        _parse_pxte_v3(_canonical_pxte_v3(_s5_pxte_v2(), [domain], [mailbox]))
    assert rejected.value.code == PXTE_V3_ERROR_CODES["cross_execution_conflict"]


def test_same_instance_requires_one_process_subject_contract() -> None:
    second = copy.deepcopy(PROCESS_MAILBOX)
    second["binding_id_hex"] = "34" * 16
    second["mailbox_ref_hex"] = "84" * 16
    second["entrypoint_ref_hex"] = "ef" * 16
    with pytest.raises(ContractReject) as rejected:
        _parse_pxte_v3(_canonical_pxte_v3(b"", [PROCESS_DOMAIN], [PROCESS_MAILBOX, second]))
    assert rejected.value.code == PXTE_V3_ERROR_CODES["process_subject_mismatch"]


def test_one_process_domain_cannot_span_target_instances() -> None:
    second = copy.deepcopy(PROCESS_MAILBOX)
    second["binding_id_hex"] = "34" * 16
    second["mailbox_ref_hex"] = "84" * 16
    second["target_instance_hex"] = "64" * 16
    with pytest.raises(ContractReject) as rejected:
        _parse_pxte_v3(_canonical_pxte_v3(b"", [PROCESS_DOMAIN], [PROCESS_MAILBOX, second]))
    assert rejected.value.code == PXTE_V3_ERROR_CODES["process_subject_mismatch"]


@pytest.mark.parametrize(
    ("binding_change", "expected"),
    [
        ({"binding_id_hex": "ef" * 16}, "orphan_binding"),
        ({"mailbox_ref_hex": "ef" * 16}, "binding_mailbox_mismatch"),
        ({"target_instance_hex": "ef" * 16}, "binding_target_mismatch"),
        (
            {"delivery_max_payload_bytes": MAX_IPC_PAYLOAD_BYTES + 1},
            "binding_payload_exceeds_ipc_frame",
        ),
        ({"mailbox_max_inflight": 9}, "binding_inflight_exceeds_credit"),
        ({"delivery_overflow_policy": 5}, "block_until_deadline_forbidden"),
    ],
)
def test_process_execution_references_exact_pxta_and_credit(
    binding_change: dict[str, Any], expected: str
) -> None:
    bindings = _bindings()
    bindings[2].update(binding_change)
    if "delivery_max_payload_bytes" in binding_change:
        bindings[2]["mailbox_capacity_bytes"] = binding_change["delivery_max_payload_bytes"]
        bindings[2]["mailbox_max_retained_bytes"] = binding_change["delivery_max_payload_bytes"]
    if binding_change.get("delivery_overflow_policy") == 5:
        bindings[2]["mailbox_overflow_policy"] = 5
    vector = _build_vector(bindings=bindings, thread_wire=b"")
    with pytest.raises(ContractReject) as rejected:
        _parse_outer_v4(vector["outer"])
    assert rejected.value.code == PXAR_V4_ERROR_CODES["target_plan_rejected"]
    assert rejected.value.detail_code == TARGET_PLAN_V4_ERROR_CODES[expected]


def test_outer_recomputes_digests_before_accepting_commitment() -> None:
    vector = _build_vector()
    wire = bytearray(vector["pxte_v3"])
    wire[-1] ^= 1
    tampered = _replace_pxte(vector["outer"], bytes(wire))
    with pytest.raises(ContractReject) as rejected:
        _parse_outer_v4(tampered)
    assert rejected.value.code in {
        PXAR_V4_ERROR_CODES["execution_rejected"],
        PXAR_V4_ERROR_CODES["commitment_mismatch"],
    }


def test_unsorted_process_records_are_rejected_not_normalized() -> None:
    first_domain = copy.deepcopy(PROCESS_DOMAIN)
    first_mailbox = copy.deepcopy(PROCESS_MAILBOX)
    second_domain = {**copy.deepcopy(PROCESS_DOMAIN), "domain_ref_hex": "d0" * 16}
    second_mailbox = {
        **copy.deepcopy(PROCESS_MAILBOX),
        "binding_id_hex": "30" * 16,
        "mailbox_ref_hex": "80" * 16,
        "target_instance_hex": "60" * 16,
        "domain_ref_hex": "d0" * 16,
    }
    canonical = _canonical_pxte_v3(
        b"", [first_domain, second_domain], [first_mailbox, second_mailbox]
    )
    wire = bytearray(canonical)
    start = PXTE_V3_HEADER_BYTES
    first = bytes(wire[start : start + PROCESS_DOMAIN_BYTES])
    second = bytes(wire[start + PROCESS_DOMAIN_BYTES : start + 2 * PROCESS_DOMAIN_BYTES])
    wire[start : start + PROCESS_DOMAIN_BYTES] = second
    wire[start + PROCESS_DOMAIN_BYTES : start + 2 * PROCESS_DOMAIN_BYTES] = first
    with pytest.raises(ContractReject) as rejected:
        _parse_pxte_v3(bytes(wire))
    assert rejected.value.code == PXTE_V3_ERROR_CODES["non_canonical_frame"]


def test_stable_error_tables_and_exact_preparse_bounds() -> None:
    fixture = _load_fixture()
    assert fixture["pxte_v3_error_codes"] == PXTE_V3_ERROR_CODES
    assert fixture["target_plan_v4_error_codes"] == TARGET_PLAN_V4_ERROR_CODES
    assert fixture["pxar_v4_error_codes"] == PXAR_V4_ERROR_CODES
    assert PXTE_V3_MAX_BYTES == 224_058
    assert PXAR_V4_MAX_BYTES == 293_718
    assert PROCESS_DOMAIN_BYTES == 336
    assert PROCESS_MAILBOX_BYTES == 289
    assert MAX_IPC_PAYLOAD_BYTES == 1_048_404
    assert MAX_PROCESS_WORKER_CREDITS == 4_096
    assert MAX_PROCESS_WORKER_RETAINED_BYTES == 4_294_967_296


if __name__ == "__main__":
    print(json.dumps(_fixture_document(), indent=2))
