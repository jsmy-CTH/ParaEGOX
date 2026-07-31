from __future__ import annotations

import copy
import hashlib
import json
import random
import re
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
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wire" / "s7_reference_successor_v1.json"
S6_FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wire" / "s6_runtime_apply_request_v4.json"

DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
DIGEST_VERSION = 1
DIGEST_FIELD_MARKER = b"\x01"
DIGEST_END_MARKER = b"\xff"
SIGNING_MAGIC = b"ParaEGOX\0canonical-signing-transcript"

DESCRIPTOR_MAGIC = b"PXBD"
DESCRIPTOR_VERSION = 1
MAX_TARGET_TRIPLE_BYTES = 255
MAX_RUNTIME_ARTIFACT_BYTES = 4_294_967_296
MAX_DESCRIPTOR_BYTES = 367
DESCRIPTOR_DIGEST_DOMAIN = b"paraegox.runtime.build-descriptor.sha256.v1"

COMPILED_COMPATIBILITY_DOMAIN = b"paraegox.runtime.compiled-reference-compatibility.sha256.v1"
MANIFEST_MAGIC = b"PXCM"
MANIFEST_VERSION = 1
MANIFEST_BYTES = 266
MANIFEST_DIGEST_DOMAIN = b"paraegox.runtime.artifact-compatibility-manifest.sha256.v1"
PROJECTION_MAGIC = b"PXMP"
PROJECTION_VERSION = 1
PROJECTION_BYTES = 298
FIXTURE_ENTRY_BYTES = 112
BUILD_IDENTITY_BYTES = 128
TARGET_ROW_BYTES = 260

EMPTY_CONFIG_DIGEST_DOMAIN = b"paraegox.runtime.reference-empty-config.sha256.v1"
PROFILE_VERSION = 1
PROFILE_ONE_SOURCE_LOOP = 1
PROFILE_EMPTY_DEACTIVATE = 2
PROFILE_LIFECYCLE_CONCURRENCY = 1
PROFILE_MAILBOX_SLOTS = 0
PROFILE_DISPATCH_SLOTS = 0
PROFILE_BACKGROUND_TASK_SLOTS = 0
MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS = 86_400_000_000_000

PXTA_ZERO = bytes.fromhex("50585441000100000000")
PXTA_DIGEST_DOMAIN = b"paraegox.runtime.target-assignments.sha256.v1"
PXTE_MAGIC = b"PXTE"
PXTE_VERSION = 4
REFERENCE_DOMAIN_BYTES = 40
REFERENCE_SUBJECT_BYTES = 176
PXTE_EMPTY_BYTES = 309
PXTE_ONE_SOURCE_LOOP_BYTES = 525
PXTE_MAX_BYTES = PXTE_ONE_SOURCE_LOOP_BYTES
PXTE_DIGEST_DOMAIN = b"paraegox.runtime.target-execution.sha256.v4"
COMPOSITE_DIGEST_DOMAIN = b"paraegox.runtime.target-plan-assignments.sha256.v5"

PXAR_MAGIC = b"PXAR"
PXAR_VERSION = 5
PXAR_HEADER_BYTES = 18

ENVELOPE_MAGIC = b"ParaEGOX\0runtime-apply-envelope"
ENVELOPE_VERSION = 2
ENVELOPE_FIELD_COUNT = 38
MAX_ENVELOPE_BYTES = 4_096
TENURE_SIGNING_DOMAIN = b"paraegox.runtime.writer-tenure.signing.v1"
AUTH_SIGNING_DOMAIN = b"paraegox.runtime.apply-envelope-auth.signing.v2"
TARGET_SLICE_DIGEST_DOMAIN = b"paraegox.runtime.target-slice.sha256.v1"
TENURE_PROOF_DIGEST_DOMAIN = b"paraegox.runtime.writer-tenure-proof.sha256.v1"
APPLY_CONTROL_DIGEST_DOMAIN = b"paraegox.runtime.apply-control.sha256.v1"
REQUEST_DIGEST_DOMAIN = b"paraegox.runtime.apply-envelope.request.sha256.v2"

CONTROL_PROTOCOL_VERSION = 1
BOOTSTRAP_REQUEST_MAGIC = b"PXBR"
BOOTSTRAP_RESPONSE_MAGIC = b"PXBS"
QUERY_REQUEST_MAGIC = b"PXQR"
QUERY_RESPONSE_MAGIC = b"PXQS"
MAX_BOOTSTRAP_REQUEST_BYTES = 1_024
MAX_BOOTSTRAP_RESPONSE_BYTES = 2_048
MAX_QUERY_REQUEST_BYTES = 1_024
MAX_QUERY_RESPONSE_BYTES = 2_048
MAX_TENURE_NONCE_BYTES = 64
MAX_TENURE_SIGNATURE_BYTES = 512
MAX_APPLY_AUTH_NONCE_BYTES = 64
MAX_APPLY_AUTH_SIGNATURE_BYTES = 512
MAX_CONTROL_NONCE_BYTES = 64
MAX_CONTROL_SIGNATURE_BYTES = 512
MAX_QUERY_RECORD_COUNT = 1

BOOTSTRAP_REQUEST_SIGNING_DOMAIN = b"paraegox.runtime.bootstrap.request-auth.signing.v1"
BOOTSTRAP_REQUEST_DIGEST_DOMAIN = b"paraegox.runtime.bootstrap.request.sha256.v1"
BOOTSTRAP_RESPONSE_SIGNING_DOMAIN = b"paraegox.runtime.bootstrap.response-auth.signing.v1"
BOOTSTRAP_RESPONSE_DIGEST_DOMAIN = b"paraegox.runtime.bootstrap.response.sha256.v1"
QUERY_REQUEST_SIGNING_DOMAIN = b"paraegox.runtime.query.request-auth.signing.v1"
QUERY_REQUEST_DIGEST_DOMAIN = b"paraegox.runtime.query.request.sha256.v1"
QUERY_RESPONSE_SIGNING_DOMAIN = b"paraegox.runtime.query.response-auth.signing.v1"
QUERY_RESPONSE_DIGEST_DOMAIN = b"paraegox.runtime.query.response.sha256.v1"
PROFILE_FINGERPRINT_DOMAIN = b"paraegox.runtime.reference-profile-fingerprint.sha256.v1"
CHANNEL_BINDING_DOMAIN = b"paraegox.runtime.local-control-channel-binding.sha256.v1"
CHANNEL_BINDING_VERSION = 1

TARGET_TRIPLE_RE = re.compile(rb"[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?")


class ContractReject(ValueError):
    def __init__(self, code: int, detail_code: int | None = None) -> None:
        super().__init__(f"contract rejection code={code} detail={detail_code}")
        self.code = code
        self.detail_code = detail_code


class SignatureReject(ValueError):
    pass


S7_CODEC_ERROR_CODES = {
    "frame_too_large": 1,
    "truncated": 2,
    "invalid_magic": 3,
    "unsupported_version": 4,
    "unknown_field": 5,
    "duplicate_field": 6,
    "out_of_order_field": 7,
    "missing_field": 8,
    "invalid_field_length": 9,
    "invalid_field_value": 10,
    "non_canonical_frame": 11,
    "digest_mismatch": 12,
    "cross_reference_mismatch": 13,
    "unsupported_shape": 14,
    "binding_not_allowed": 15,
    "runtime_store_mismatch": 16,
    "target_mismatch": 17,
    "fixture_mismatch": 18,
    "response_bound_exceeded": 19,
    "unknown_reason": 20,
    "trailing_bytes": 21,
    "invalid_signature_field": 22,
    "invalid_presence": 23,
    "artifact_mismatch": 24,
    "compatibility_mismatch": 25,
}

DESCRIPTOR_ERROR_CODES = {
    "frame_too_large": S7_CODEC_ERROR_CODES["frame_too_large"],
    "truncated": S7_CODEC_ERROR_CODES["truncated"],
    "invalid_magic": S7_CODEC_ERROR_CODES["invalid_magic"],
    "unsupported_version": S7_CODEC_ERROR_CODES["unsupported_version"],
    "invalid_frame_length": S7_CODEC_ERROR_CODES["invalid_field_length"],
    "invalid_build_instance_id": S7_CODEC_ERROR_CODES["invalid_field_value"],
    "invalid_artifact_length": S7_CODEC_ERROR_CODES["invalid_field_value"],
    "invalid_target_triple": S7_CODEC_ERROR_CODES["invalid_field_value"],
    "non_canonical_frame": S7_CODEC_ERROR_CODES["non_canonical_frame"],
}

MANIFEST_ERROR_CODES = {
    "invalid_frame_length": S7_CODEC_ERROR_CODES["invalid_field_length"],
    "invalid_magic": S7_CODEC_ERROR_CODES["invalid_magic"],
    "unsupported_version": S7_CODEC_ERROR_CODES["unsupported_version"],
    "invalid_identity": S7_CODEC_ERROR_CODES["invalid_field_value"],
    "invalid_protocol_selection": S7_CODEC_ERROR_CODES["unsupported_version"],
    "invalid_fixture": S7_CODEC_ERROR_CODES["fixture_mismatch"],
    "digest_mismatch": S7_CODEC_ERROR_CODES["digest_mismatch"],
    "non_canonical_frame": S7_CODEC_ERROR_CODES["non_canonical_frame"],
}

PXTE_ERROR_CODES = {
    "frame_too_large": S7_CODEC_ERROR_CODES["frame_too_large"],
    "truncated": S7_CODEC_ERROR_CODES["truncated"],
    "invalid_magic": S7_CODEC_ERROR_CODES["invalid_magic"],
    "unsupported_version": S7_CODEC_ERROR_CODES["unsupported_version"],
    "invalid_frame_length": S7_CODEC_ERROR_CODES["invalid_field_length"],
    "manifest_rejected": S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
    "invalid_profile": S7_CODEC_ERROR_CODES["unsupported_shape"],
    "invalid_presence": S7_CODEC_ERROR_CODES["invalid_presence"],
    "invalid_domain": S7_CODEC_ERROR_CODES["invalid_field_value"],
    "invalid_subject": S7_CODEC_ERROR_CODES["invalid_field_value"],
    "shape_mismatch": S7_CODEC_ERROR_CODES["unsupported_shape"],
    "orphan_domain_ref": S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
    "fixture_mismatch": S7_CODEC_ERROR_CODES["fixture_mismatch"],
    "config_mismatch": S7_CODEC_ERROR_CODES["fixture_mismatch"],
    "non_canonical_frame": S7_CODEC_ERROR_CODES["non_canonical_frame"],
}

ENVELOPE_ERROR_CODES = {
    "frame_too_large": S7_CODEC_ERROR_CODES["frame_too_large"],
    "truncated": S7_CODEC_ERROR_CODES["truncated"],
    "invalid_magic": S7_CODEC_ERROR_CODES["invalid_magic"],
    "unsupported_version": S7_CODEC_ERROR_CODES["unsupported_version"],
    "unknown_field": S7_CODEC_ERROR_CODES["unknown_field"],
    "missing_field": S7_CODEC_ERROR_CODES["missing_field"],
    "duplicate_field": S7_CODEC_ERROR_CODES["duplicate_field"],
    "out_of_order_field": S7_CODEC_ERROR_CODES["out_of_order_field"],
    "invalid_field_length": S7_CODEC_ERROR_CODES["invalid_field_length"],
    "invalid_field_value": S7_CODEC_ERROR_CODES["invalid_field_value"],
    "derived_digest_mismatch": S7_CODEC_ERROR_CODES["digest_mismatch"],
    "non_canonical_frame": S7_CODEC_ERROR_CODES["non_canonical_frame"],
    "trailing_bytes": S7_CODEC_ERROR_CODES["trailing_bytes"],
    "runtime_store_mismatch": S7_CODEC_ERROR_CODES["runtime_store_mismatch"],
}

PXAR_ERROR_CODES = {
    "frame_too_large": S7_CODEC_ERROR_CODES["frame_too_large"],
    "truncated": S7_CODEC_ERROR_CODES["truncated"],
    "invalid_magic": S7_CODEC_ERROR_CODES["invalid_magic"],
    "unsupported_version": S7_CODEC_ERROR_CODES["unsupported_version"],
    "invalid_frame_length": S7_CODEC_ERROR_CODES["invalid_field_length"],
    "envelope_rejected": S7_CODEC_ERROR_CODES["invalid_field_value"],
    "bindings_rejected": S7_CODEC_ERROR_CODES["binding_not_allowed"],
    "execution_rejected": S7_CODEC_ERROR_CODES["unsupported_shape"],
    "commitment_mismatch": S7_CODEC_ERROR_CODES["digest_mismatch"],
}

TEST_ONLY_KEYS = {
    "tenure_authority_seed_hex": "11" * 32,
    "request_writer_seed_hex": "22" * 32,
    "controller_read_seed_hex": "33" * 32,
    "runtime_read_seed_hex": "44" * 32,
}

BOOTSTRAP_STATES = {
    "ready_for_apply": 1,
    "not_ready_recovering": 2,
    "validated_operational_quarantine": 3,
    "recovery_failed_not_ready": 4,
    "not_ready_busy": 5,
}
OPERATIONAL_REASONS = {
    "none": 0,
    "recovering": 1,
    "active_compatibility_mismatch": 2,
    "recovery_failed": 3,
    "ownership_uncertain": 4,
    "history_unavailable": 5,
    "resource_census_uncertain": 6,
    "runtime_busy": 7,
    "ownership_transfer_required": 8,
}
OWNER_STATES = {
    "operational": 1,
    "apply_disabled": 2,
    "ownership_uncertain": 3,
}
LOOKUP_KINDS = {
    "known": 1,
    "conflict": 2,
    "unknown": 3,
    "indeterminate": 4,
}
DURABLE_PHASES = {
    "none": 0,
    "prepared_no_effects": 1,
    "first_action_intent": 2,
    "head_committed_retiring_old": 3,
    "terminal": 4,
}
DESIRED_HEAD_KINDS = {
    "none": 1,
    "one_source_loop": 2,
    "empty_deactivate": 3,
}
LIVE_STATES = {
    "not_ready": 1,
    "recovering": 2,
    "live_ready": 3,
    "draining": 4,
    "recovery_failed_not_ready": 5,
    "exact_zero": 6,
    "validated_operational_quarantine": 7,
    "uncertain": 8,
}

FIXTURE_ENTRY: dict[str, str] = {
    "definition_ref_hex": "a1" * 16,
    "implementation_ref_hex": "a2" * 16,
    "export_ref_hex": "a3" * 16,
    "definition_digest_hex": "a4" * 32,
    "fixture_artifact_digest_hex": "a5" * 32,
}

DESCRIPTOR: dict[str, Any] = {
    "build_instance_id_hex": "11" * 32,
    "runtime_artifact_length": 1_048_576,
    "runtime_artifact_sha256_hex": "22" * 32,
    "target_triple": "aarch64-unknown-linux-gnu",
}

TARGET_HEX = "05" * 16
EXPECTED_STORE_HEX = "44" * 32
EXPECTED_ADMISSION_POLICY_DIGEST = bytes.fromhex("c1" * 32)
DOMAIN: dict[str, Any] = {
    "domain_ref_hex": "b1" * 16,
    "start_budget_nanos": 1_000_000_000,
    "drain_budget_nanos": 2_000_000_000,
    "cleanup_budget_nanos": 3_000_000_000,
}
SUBJECT: dict[str, str] = {
    "instance_ref_hex": "b2" * 16,
    "domain_ref_hex": DOMAIN["domain_ref_hex"],
    **FIXTURE_ENTRY,
}

ENVELOPE_SEMANTIC: dict[str, Any] = {
    "slice_contract_version": 1,
    "target_hex": TARGET_HEX,
    "source_scope_hex": "01" * 16,
    "source_plan_hex": "02" * 16,
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
    "temporal_version": 1,
    "clock_domain_hex": "0a" * 16,
    "clock_generation": 3,
    "original_budget_nanos": 100,
    "remaining_budget_nanos": 60,
    "auth_principal_hex": "09" * 16,
    "auth_key_hex": "0c" * 16,
    "auth_algorithm": 1,
    "auth_algorithm_version": 1,
    "expected_runtime_store_instance_id_hex": EXPECTED_STORE_HEX,
}


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
        encoded += DIGEST_FIELD_MARKER
        encoded += _u32(ordinal)
        encoded += _u64(len(field))
        encoded += field
    encoded += DIGEST_END_MARKER
    encoded += _u32(len(fields))
    return hashlib.sha256(encoded).digest()


def _tlv(tag: int, value: bytes) -> bytes:
    return _u16(tag) + _u32(len(value)) + value


def _signing_transcript(version: int, domain: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    encoded = bytearray(SIGNING_MAGIC)
    encoded += _u16(version)
    encoded += _u16(len(domain))
    encoded += domain
    encoded += _u16(len(fields))
    for tag, value in fields:
        encoded += _tlv(tag, value)
    return bytes(encoded)


def _fixture_entry_wire(value: dict[str, str]) -> bytes:
    encoded = b"".join(
        _hex(value[field])
        for field in (
            "definition_ref_hex",
            "implementation_ref_hex",
            "export_ref_hex",
            "definition_digest_hex",
            "fixture_artifact_digest_hex",
        )
    )
    assert len(encoded) == FIXTURE_ENTRY_BYTES
    return encoded


def _decode_fixture_entry(wire: bytes) -> dict[str, bytes]:
    if len(wire) != FIXTURE_ENTRY_BYTES:
        raise ContractReject(MANIFEST_ERROR_CODES["invalid_fixture"])
    return {
        "definition_ref": wire[0:16],
        "implementation_ref": wire[16:32],
        "export_ref": wire[32:48],
        "definition_digest": wire[48:80],
        "fixture_artifact_digest": wire[80:112],
    }


def _compiled_compatibility_digest(fixture: dict[str, str]) -> bytes:
    return _digest(
        COMPILED_COMPATIBILITY_DOMAIN,
        [
            PXAR_MAGIC,
            _u16(PXAR_VERSION),
            _u16(PXAR_HEADER_BYTES),
            _u32(PXAR_HEADER_BYTES + MAX_ENVELOPE_BYTES + len(PXTA_ZERO) + PXTE_MAX_BYTES),
            PXTE_MAGIC,
            _u16(PXTE_VERSION),
            _u32(PXTE_MAX_BYTES),
            _u16(PROJECTION_BYTES),
            _u16(REFERENCE_DOMAIN_BYTES),
            _u16(REFERENCE_SUBJECT_BYTES),
            PXTA_ZERO,
            ENVELOPE_MAGIC,
            _u16(ENVELOPE_VERSION),
            _u16(ENVELOPE_FIELD_COUNT),
            _u16(32),
            _u32(MAX_ENVELOPE_BYTES),
            _u16(MAX_APPLY_AUTH_NONCE_BYTES),
            _u16(MAX_APPLY_AUTH_SIGNATURE_BYTES),
            _u16(PROFILE_VERSION),
            _u16(PROFILE_LIFECYCLE_CONCURRENCY),
            _u16(PROFILE_MAILBOX_SLOTS),
            _u16(PROFILE_DISPATCH_SLOTS),
            _u16(PROFILE_BACKGROUND_TASK_SLOTS),
            _u64(MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS),
            PXTE_DIGEST_DOMAIN,
            COMPOSITE_DIGEST_DOMAIN,
            AUTH_SIGNING_DOMAIN,
            REQUEST_DIGEST_DOMAIN,
            EMPTY_CONFIG_DIGEST_DOMAIN,
            PROJECTION_MAGIC,
            _u16(PROJECTION_VERSION),
            _u16(PROJECTION_BYTES),
            MANIFEST_MAGIC,
            _u16(MANIFEST_VERSION),
            _u16(MANIFEST_BYTES),
            MANIFEST_DIGEST_DOMAIN,
            _u16(BUILD_IDENTITY_BYTES),
            _u16(FIXTURE_ENTRY_BYTES),
            _hex(fixture["definition_ref_hex"]),
            _hex(fixture["implementation_ref_hex"]),
            _hex(fixture["export_ref_hex"]),
            _hex(fixture["definition_digest_hex"]),
            _hex(fixture["fixture_artifact_digest_hex"]),
        ],
    )


def _empty_config_digest() -> bytes:
    return _digest(EMPTY_CONFIG_DIGEST_DOMAIN, [])


def _encode_descriptor(value: dict[str, Any], compiled_compatibility_digest: bytes) -> bytes:
    target = value["target_triple"].encode("ascii")
    wire = (
        DESCRIPTOR_MAGIC
        + _u16(DESCRIPTOR_VERSION)
        + _hex(value["build_instance_id_hex"])
        + _u64(value["runtime_artifact_length"])
        + _hex(value["runtime_artifact_sha256_hex"])
        + _u16(len(target))
        + target
        + compiled_compatibility_digest
    )
    _decode_descriptor(wire)
    return wire


def _decode_descriptor(wire: bytes) -> dict[str, Any]:
    if len(wire) > MAX_DESCRIPTOR_BYTES:
        raise ContractReject(DESCRIPTOR_ERROR_CODES["frame_too_large"])
    if len(wire) < 113:
        raise ContractReject(DESCRIPTOR_ERROR_CODES["truncated"])
    if wire[:4] != DESCRIPTOR_MAGIC:
        raise ContractReject(DESCRIPTOR_ERROR_CODES["invalid_magic"])
    version = struct.unpack_from(">H", wire, 4)[0]
    if version != DESCRIPTOR_VERSION:
        raise ContractReject(DESCRIPTOR_ERROR_CODES["unsupported_version"])
    build_id = wire[6:38]
    artifact_length = struct.unpack_from(">Q", wire, 38)[0]
    artifact_sha256 = wire[46:78]
    target_length = struct.unpack_from(">H", wire, 78)[0]
    if not 0 < target_length <= MAX_TARGET_TRIPLE_BYTES:
        raise ContractReject(DESCRIPTOR_ERROR_CODES["invalid_frame_length"], detail_code=4)
    expected = 112 + target_length
    if len(wire) != expected:
        code = (
            S7_CODEC_ERROR_CODES["truncated"]
            if len(wire) < expected
            else S7_CODEC_ERROR_CODES["trailing_bytes"]
        )
        raise ContractReject(code)
    if build_id == bytes(32):
        raise ContractReject(DESCRIPTOR_ERROR_CODES["invalid_build_instance_id"], detail_code=1)
    if not 0 < artifact_length <= MAX_RUNTIME_ARTIFACT_BYTES:
        raise ContractReject(DESCRIPTOR_ERROR_CODES["invalid_artifact_length"], detail_code=2)
    if artifact_sha256 == bytes(32):
        raise ContractReject(DESCRIPTOR_ERROR_CODES["invalid_artifact_length"], detail_code=3)
    target = wire[80 : 80 + target_length]
    if TARGET_TRIPLE_RE.fullmatch(target) is None:
        raise ContractReject(DESCRIPTOR_ERROR_CODES["invalid_target_triple"], detail_code=4)
    if wire[-32:] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["compatibility_mismatch"], detail_code=5)
    canonical = (
        DESCRIPTOR_MAGIC
        + _u16(version)
        + build_id
        + _u64(artifact_length)
        + artifact_sha256
        + _u16(target_length)
        + target
        + wire[-32:]
    )
    if canonical != wire:
        raise ContractReject(DESCRIPTOR_ERROR_CODES["non_canonical_frame"])
    return {
        "build_instance_id": build_id,
        "runtime_artifact_length": artifact_length,
        "runtime_artifact_sha256": artifact_sha256,
        "target_triple": target,
        "compiled_compatibility_digest": wire[-32:],
        "wire": wire,
    }


def _descriptor_digest(wire: bytes) -> bytes:
    _decode_descriptor(wire)
    return _digest(DESCRIPTOR_DIGEST_DOMAIN, [wire])


def _build_identity_wire(descriptor: dict[str, Any], descriptor_digest: bytes) -> bytes:
    wire = (
        descriptor["build_instance_id"]
        + descriptor_digest
        + descriptor["runtime_artifact_sha256"]
        + descriptor["compiled_compatibility_digest"]
    )
    assert len(wire) == BUILD_IDENTITY_BYTES
    return wire


def _decode_identity(wire: bytes) -> dict[str, bytes]:
    if len(wire) < BUILD_IDENTITY_BYTES:
        raise ContractReject(S7_CODEC_ERROR_CODES["truncated"])
    if len(wire) > BUILD_IDENTITY_BYTES:
        raise ContractReject(S7_CODEC_ERROR_CODES["trailing_bytes"])
    for index, offset in enumerate(range(0, 128, 32), start=1):
        if wire[offset : offset + 32] == bytes(32):
            raise ContractReject(MANIFEST_ERROR_CODES["invalid_identity"], detail_code=index)
    return {
        "build_instance_id": wire[:32],
        "build_descriptor_digest": wire[32:64],
        "runtime_artifact_sha256": wire[64:96],
        "compiled_compatibility_digest": wire[96:128],
        "wire": wire,
    }


def _target_row_wire(target: bytes, identity: bytes, fixture: dict[str, str]) -> bytes:
    assert len(target) == 16
    _decode_identity(identity)
    row = (
        target
        + identity
        + _u16(PXAR_VERSION)
        + _u16(PROFILE_VERSION)
        + _fixture_entry_wire(fixture)
    )
    assert len(row) == TARGET_ROW_BYTES
    return row


def _decode_target_row(wire: bytes) -> dict[str, Any]:
    if len(wire) != TARGET_ROW_BYTES:
        raise ContractReject(MANIFEST_ERROR_CODES["invalid_frame_length"])
    target = wire[:16]
    identity = _decode_identity(wire[16:144])
    pxar_version, profile_version = struct.unpack_from(">HH", wire, 144)
    if pxar_version != PXAR_VERSION:
        raise ContractReject(MANIFEST_ERROR_CODES["invalid_protocol_selection"], detail_code=1)
    if profile_version != PROFILE_VERSION:
        raise ContractReject(MANIFEST_ERROR_CODES["invalid_protocol_selection"], detail_code=2)
    fixture = _decode_fixture_entry(wire[148:])
    fixture_value = {
        "definition_ref_hex": fixture["definition_ref"].hex(),
        "implementation_ref_hex": fixture["implementation_ref"].hex(),
        "export_ref_hex": fixture["export_ref"].hex(),
        "definition_digest_hex": fixture["definition_digest"].hex(),
        "fixture_artifact_digest_hex": fixture["fixture_artifact_digest"].hex(),
    }
    if identity["compiled_compatibility_digest"] != (_compiled_compatibility_digest(fixture_value)):
        raise ContractReject(S7_CODEC_ERROR_CODES["compatibility_mismatch"])
    return {
        "target": target,
        "identity": identity,
        "pxar_version": pxar_version,
        "profile_version": profile_version,
        "fixture": fixture,
        "wire": wire,
    }


def _encode_manifest(row: bytes) -> bytes:
    _decode_target_row(row)
    wire = MANIFEST_MAGIC + _u16(MANIFEST_VERSION) + row
    assert len(wire) == MANIFEST_BYTES
    return wire


def _decode_manifest(wire: bytes) -> dict[str, Any]:
    if len(wire) < MANIFEST_BYTES:
        raise ContractReject(S7_CODEC_ERROR_CODES["truncated"])
    if len(wire) > MANIFEST_BYTES:
        raise ContractReject(S7_CODEC_ERROR_CODES["trailing_bytes"])
    if wire[:4] != MANIFEST_MAGIC:
        raise ContractReject(MANIFEST_ERROR_CODES["invalid_magic"])
    if struct.unpack_from(">H", wire, 4)[0] != MANIFEST_VERSION:
        raise ContractReject(MANIFEST_ERROR_CODES["unsupported_version"])
    row = _decode_target_row(wire[6:])
    canonical = _encode_manifest(row["wire"])
    if canonical != wire:
        raise ContractReject(MANIFEST_ERROR_CODES["non_canonical_frame"])
    return {"row": row, "wire": wire}


def _manifest_digest(wire: bytes) -> bytes:
    _decode_manifest(wire)
    return _digest(MANIFEST_DIGEST_DOMAIN, [wire])


def _encode_projection(manifest_wire: bytes) -> bytes:
    manifest = _decode_manifest(manifest_wire)
    wire = (
        PROJECTION_MAGIC
        + _u16(PROJECTION_VERSION)
        + _manifest_digest(manifest_wire)
        + manifest["row"]["wire"]
    )
    assert len(wire) == PROJECTION_BYTES
    return wire


def _decode_projection(wire: bytes) -> dict[str, Any]:
    if len(wire) < PROJECTION_BYTES:
        raise ContractReject(S7_CODEC_ERROR_CODES["truncated"])
    if len(wire) > PROJECTION_BYTES:
        raise ContractReject(S7_CODEC_ERROR_CODES["trailing_bytes"])
    if wire[:4] != PROJECTION_MAGIC:
        raise ContractReject(MANIFEST_ERROR_CODES["invalid_magic"])
    if struct.unpack_from(">H", wire, 4)[0] != PROJECTION_VERSION:
        raise ContractReject(MANIFEST_ERROR_CODES["unsupported_version"])
    digest = wire[6:38]
    row = _decode_target_row(wire[38:])
    rebuilt_manifest = _encode_manifest(row["wire"])
    if digest != _manifest_digest(rebuilt_manifest):
        raise ContractReject(MANIFEST_ERROR_CODES["digest_mismatch"])
    canonical = PROJECTION_MAGIC + _u16(PROJECTION_VERSION) + digest + row["wire"]
    if canonical != wire:
        raise ContractReject(MANIFEST_ERROR_CODES["non_canonical_frame"])
    return {
        "manifest_digest": digest,
        "row": row,
        "manifest_wire": rebuilt_manifest,
        "wire": wire,
    }


def _validate_release_chain(
    descriptor_wire: bytes,
    identity_wire: bytes,
    manifest_wire: bytes,
    projection_wire: bytes,
) -> None:
    descriptor = _decode_descriptor(descriptor_wire)
    _decode_identity(identity_wire)
    manifest = _decode_manifest(manifest_wire)
    projection = _decode_projection(projection_wire)
    expected_identity = _build_identity_wire(descriptor, _descriptor_digest(descriptor_wire))
    if identity_wire != expected_identity:
        raise ContractReject(S7_CODEC_ERROR_CODES["cross_reference_mismatch"])
    if manifest["row"]["identity"]["wire"] != identity_wire:
        raise ContractReject(S7_CODEC_ERROR_CODES["cross_reference_mismatch"])
    if projection["manifest_wire"] != manifest_wire:
        raise ContractReject(MANIFEST_ERROR_CODES["digest_mismatch"])


def _encode_reference_domain(value: dict[str, Any]) -> bytes:
    wire = (
        _hex(value["domain_ref_hex"])
        + _u64(value["start_budget_nanos"])
        + _u64(value["drain_budget_nanos"])
        + _u64(value["cleanup_budget_nanos"])
    )
    if len(wire) != REFERENCE_DOMAIN_BYTES:
        raise ContractReject(PXTE_ERROR_CODES["invalid_domain"])
    _decode_reference_domain(wire)
    return wire


def _decode_reference_domain(wire: bytes) -> dict[str, Any]:
    if len(wire) != REFERENCE_DOMAIN_BYTES:
        raise ContractReject(PXTE_ERROR_CODES["invalid_domain"], detail_code=4)
    budgets = struct.unpack_from(">QQQ", wire, 16)
    if any(not 0 < budget <= MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS for budget in budgets):
        raise ContractReject(PXTE_ERROR_CODES["invalid_domain"], detail_code=4)
    return {
        "domain_ref": wire[:16],
        "start_budget_nanos": budgets[0],
        "drain_budget_nanos": budgets[1],
        "cleanup_budget_nanos": budgets[2],
        "wire": wire,
    }


def _encode_reference_subject(value: dict[str, str]) -> bytes:
    wire = b"".join(
        _hex(value[field])
        for field in (
            "instance_ref_hex",
            "domain_ref_hex",
            "definition_ref_hex",
            "implementation_ref_hex",
            "export_ref_hex",
            "definition_digest_hex",
            "fixture_artifact_digest_hex",
            "config_digest_hex",
        )
    )
    if len(wire) != REFERENCE_SUBJECT_BYTES:
        raise ContractReject(PXTE_ERROR_CODES["invalid_subject"])
    return wire


def _decode_reference_subject(wire: bytes) -> dict[str, bytes]:
    if len(wire) != REFERENCE_SUBJECT_BYTES:
        raise ContractReject(PXTE_ERROR_CODES["invalid_subject"], detail_code=5)
    return {
        "instance_ref": wire[0:16],
        "domain_ref": wire[16:32],
        "definition_ref": wire[32:48],
        "implementation_ref": wire[48:64],
        "export_ref": wire[64:80],
        "definition_digest": wire[80:112],
        "fixture_artifact_digest": wire[112:144],
        "config_digest": wire[144:176],
        "wire": wire,
    }


def _encode_pxte(
    projection: bytes,
    mode: int,
    domain: dict[str, Any] | None,
    subject: dict[str, str] | None,
) -> bytes:
    _decode_projection(projection)
    wire = bytearray(PXTE_MAGIC)
    wire += _u16(PXTE_VERSION)
    wire += projection
    wire += _u16(PROFILE_VERSION)
    wire += _u8(mode)
    if domain is None:
        wire += _u8(0)
    else:
        wire += _u8(1)
        wire += _encode_reference_domain(domain)
    if subject is None:
        wire += _u8(0)
    else:
        wire += _u8(1)
        wire += _encode_reference_subject(subject)
    encoded = bytes(wire)
    _decode_pxte(encoded)
    return encoded


def _decode_pxte(wire: bytes) -> dict[str, Any]:
    if len(wire) > PXTE_MAX_BYTES:
        raise ContractReject(PXTE_ERROR_CODES["frame_too_large"])
    if len(wire) < PXTE_EMPTY_BYTES:
        raise ContractReject(PXTE_ERROR_CODES["truncated"])
    if wire[:4] != PXTE_MAGIC:
        raise ContractReject(PXTE_ERROR_CODES["invalid_magic"])
    if struct.unpack_from(">H", wire, 4)[0] != PXTE_VERSION:
        raise ContractReject(PXTE_ERROR_CODES["unsupported_version"])
    projection_wire = wire[6 : 6 + PROJECTION_BYTES]
    cursor = 6 + PROJECTION_BYTES
    profile_version, mode = struct.unpack_from(">HB", wire, cursor)
    cursor += 3
    domain_presence = wire[cursor]
    cursor += 1
    if domain_presence not in {0, 1}:
        raise ContractReject(PXTE_ERROR_CODES["invalid_presence"], detail_code=4)
    domain_wire = None
    if domain_presence:
        end = cursor + REFERENCE_DOMAIN_BYTES
        if end > len(wire):
            raise ContractReject(PXTE_ERROR_CODES["truncated"])
        domain_wire = wire[cursor:end]
        cursor = end
    if cursor >= len(wire):
        raise ContractReject(PXTE_ERROR_CODES["truncated"])
    subject_presence = wire[cursor]
    cursor += 1
    if subject_presence not in {0, 1}:
        raise ContractReject(PXTE_ERROR_CODES["invalid_presence"], detail_code=5)
    subject_wire = None
    if subject_presence:
        end = cursor + REFERENCE_SUBJECT_BYTES
        if end > len(wire):
            raise ContractReject(PXTE_ERROR_CODES["truncated"])
        subject_wire = wire[cursor:end]
        cursor = end
    if cursor != len(wire):
        raise ContractReject(S7_CODEC_ERROR_CODES["trailing_bytes"])

    projection = _decode_projection(projection_wire)
    if profile_version != PROFILE_VERSION:
        raise ContractReject(PXTE_ERROR_CODES["unsupported_version"], detail_code=2)
    if mode not in {
        PROFILE_ONE_SOURCE_LOOP,
        PROFILE_EMPTY_DEACTIVATE,
    }:
        raise ContractReject(PXTE_ERROR_CODES["invalid_profile"], detail_code=3)
    domain = None if domain_wire is None else _decode_reference_domain(domain_wire)
    subject = None if subject_wire is None else _decode_reference_subject(subject_wire)

    if mode == PROFILE_ONE_SOURCE_LOOP:
        if domain is None:
            raise ContractReject(PXTE_ERROR_CODES["shape_mismatch"], detail_code=4)
        if subject is None:
            raise ContractReject(PXTE_ERROR_CODES["shape_mismatch"], detail_code=5)
        if subject["domain_ref"] != domain["domain_ref"]:
            raise ContractReject(PXTE_ERROR_CODES["orphan_domain_ref"], detail_code=5)
        fixture = projection["row"]["fixture"]
        if any(
            subject[field] != fixture[field]
            for field in (
                "definition_ref",
                "implementation_ref",
                "export_ref",
                "definition_digest",
                "fixture_artifact_digest",
            )
        ):
            raise ContractReject(PXTE_ERROR_CODES["fixture_mismatch"], detail_code=5)
        if subject["config_digest"] != _empty_config_digest():
            raise ContractReject(PXTE_ERROR_CODES["config_mismatch"], detail_code=5)
    elif domain is not None:
        raise ContractReject(PXTE_ERROR_CODES["shape_mismatch"], detail_code=4)
    elif subject is not None:
        raise ContractReject(PXTE_ERROR_CODES["shape_mismatch"], detail_code=5)

    canonical = bytearray(PXTE_MAGIC)
    canonical += _u16(PXTE_VERSION)
    canonical += projection["wire"]
    canonical += _u16(PROFILE_VERSION)
    canonical += _u8(mode)
    canonical += _u8(domain is not None)
    if domain is not None:
        canonical += domain["wire"]
    canonical += _u8(subject is not None)
    if subject is not None:
        canonical += subject["wire"]
    if bytes(canonical) != wire:
        raise ContractReject(PXTE_ERROR_CODES["non_canonical_frame"])
    return {
        "projection": projection,
        "mode": mode,
        "domain": domain,
        "subject": subject,
        "wire": wire,
    }


def _pxte_digest(wire: bytes) -> bytes:
    _decode_pxte(wire)
    return _digest(PXTE_DIGEST_DOMAIN, [wire])


def _pxta_digest() -> bytes:
    return _digest(PXTA_DIGEST_DOMAIN, [PXTA_ZERO])


def _composite_digest(pxte: bytes) -> bytes:
    return _digest(COMPOSITE_DIGEST_DOMAIN, [_pxta_digest(), _pxte_digest(pxte)])


def _valid_envelope_field_length(tag: int, length: int) -> bool:
    if tag in {1, 13, 14, 22, 26, 35, 36}:
        return length == 2
    if tag in {5, 10, 17, 18, 29, 30, 31}:
        return length == 8
    if tag in {
        2,
        3,
        4,
        9,
        11,
        12,
        15,
        16,
        24,
        27,
        28,
        33,
        34,
    }:
        return length == 16
    if tag in {6, 7, 8, 21, 23, 25, 32}:
        return length == 32
    if tag in {19, 37}:
        maximum = MAX_APPLY_AUTH_NONCE_BYTES if tag == 37 else MAX_TENURE_NONCE_BYTES
        return 1 <= length <= maximum
    if tag in {20, 38}:
        maximum = (
            MAX_APPLY_AUTH_SIGNATURE_BYTES if tag == 38 else MAX_TENURE_SIGNATURE_BYTES
        )
        return 1 <= length <= maximum
    return False


def _encode_envelope_fields(fields: list[tuple[int, bytes]]) -> bytes:
    return (
        ENVELOPE_MAGIC
        + _u16(ENVELOPE_VERSION)
        + _u16(len(fields))
        + b"".join(_tlv(tag, value) for tag, value in fields)
    )


def _parse_envelope_fields(wire: bytes) -> list[tuple[int, bytes]]:
    if len(wire) > MAX_ENVELOPE_BYTES:
        raise ContractReject(ENVELOPE_ERROR_CODES["frame_too_large"])
    header_bytes = len(ENVELOPE_MAGIC) + 4
    if len(wire) < header_bytes:
        raise ContractReject(ENVELOPE_ERROR_CODES["truncated"])
    if wire[: len(ENVELOPE_MAGIC)] != ENVELOPE_MAGIC:
        raise ContractReject(ENVELOPE_ERROR_CODES["invalid_magic"])
    version, count = struct.unpack_from(">HH", wire, len(ENVELOPE_MAGIC))
    if version != ENVELOPE_VERSION:
        raise ContractReject(ENVELOPE_ERROR_CODES["unsupported_version"])
    if count < ENVELOPE_FIELD_COUNT:
        raise ContractReject(ENVELOPE_ERROR_CODES["missing_field"], detail_code=count + 1)
    if count > ENVELOPE_FIELD_COUNT:
        raise ContractReject(
            ENVELOPE_ERROR_CODES["unknown_field"],
            detail_code=ENVELOPE_FIELD_COUNT + 1,
        )
    cursor = header_bytes
    fields: list[tuple[int, bytes]] = []
    for index in range(count):
        expected_tag = index + 1
        if cursor + 6 > len(wire):
            raise ContractReject(ENVELOPE_ERROR_CODES["truncated"])
        tag, length = struct.unpack_from(">HI", wire, cursor)
        cursor += 6
        if tag == 0 or tag > ENVELOPE_FIELD_COUNT:
            raise ContractReject(ENVELOPE_ERROR_CODES["unknown_field"], detail_code=tag)
        if tag < expected_tag:
            raise ContractReject(ENVELOPE_ERROR_CODES["duplicate_field"], detail_code=tag)
        if tag > expected_tag:
            raise ContractReject(ENVELOPE_ERROR_CODES["out_of_order_field"], detail_code=tag)
        if not _valid_envelope_field_length(tag, length):
            raise ContractReject(ENVELOPE_ERROR_CODES["invalid_field_length"], detail_code=tag)
        end = cursor + length
        if end > len(wire):
            raise ContractReject(ENVELOPE_ERROR_CODES["truncated"], detail_code=tag)
        fields.append((tag, wire[cursor:end]))
        cursor = end
    if cursor != len(wire):
        raise ContractReject(ENVELOPE_ERROR_CODES["trailing_bytes"])
    if _encode_envelope_fields(fields) != wire:
        raise ContractReject(ENVELOPE_ERROR_CODES["non_canonical_frame"])
    return fields


def _decode_envelope(wire: bytes) -> dict[int, bytes]:
    values = dict(_parse_envelope_fields(wire))
    if values[1] != _u16(1):
        raise ContractReject(ENVELOPE_ERROR_CODES["unsupported_version"], detail_code=1)
    target_slice_digest = _digest(TARGET_SLICE_DIGEST_DOMAIN, [values[tag] for tag in range(1, 8)])
    if values[8] != target_slice_digest:
        raise ContractReject(ENVELOPE_ERROR_CODES["derived_digest_mismatch"], detail_code=8)
    if values[9] != values[16] or values[10] != values[17]:
        raise ContractReject(S7_CODEC_ERROR_CODES["cross_reference_mismatch"], detail_code=9)
    if struct.unpack(">H", values[13])[0] == 0:
        raise ContractReject(ENVELOPE_ERROR_CODES["invalid_field_value"], detail_code=13)
    if struct.unpack(">H", values[14])[0] == 0:
        raise ContractReject(ENVELOPE_ERROR_CODES["invalid_field_value"], detail_code=14)
    if values[3] != values[15]:
        raise ContractReject(S7_CODEC_ERROR_CODES["cross_reference_mismatch"], detail_code=15)
    proof_epoch = struct.unpack(">Q", values[17])[0]
    supersedes_through_epoch = struct.unpack(">Q", values[18])[0]
    if proof_epoch == 0 or supersedes_through_epoch >= proof_epoch:
        raise ContractReject(ENVELOPE_ERROR_CODES["invalid_field_value"], detail_code=17)
    tenure_digest = _digest(TENURE_PROOF_DIGEST_DOMAIN, [values[tag] for tag in range(11, 21)])
    if values[21] != tenure_digest:
        raise ContractReject(ENVELOPE_ERROR_CODES["derived_digest_mismatch"], detail_code=21)
    expected_active_valid = (values[22] == _u16(0) and values[23] == bytes(32)) or values[
        22
    ] == _u16(1)
    if not expected_active_valid:
        raise ContractReject(ENVELOPE_ERROR_CODES["invalid_field_value"], detail_code=22)
    control_digest = _digest(
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
        raise ContractReject(ENVELOPE_ERROR_CODES["derived_digest_mismatch"], detail_code=25)
    original_budget = struct.unpack(">Q", values[30])[0]
    remaining_budget = struct.unpack(">Q", values[31])[0]
    if values[26] != _u16(1) or original_budget == 0 or remaining_budget > original_budget:
        raise ContractReject(ENVELOPE_ERROR_CODES["invalid_field_value"], detail_code=26)
    if struct.unpack(">Q", values[29])[0] == 0:
        raise ContractReject(ENVELOPE_ERROR_CODES["invalid_field_value"], detail_code=29)
    if values[32] == bytes(32):
        raise ContractReject(ENVELOPE_ERROR_CODES["invalid_field_value"], detail_code=32)
    if struct.unpack(">H", values[35])[0] == 0:
        raise ContractReject(ENVELOPE_ERROR_CODES["invalid_field_value"], detail_code=35)
    if struct.unpack(">H", values[36])[0] == 0:
        raise ContractReject(ENVELOPE_ERROR_CODES["invalid_field_value"], detail_code=36)
    return values


def _rebuild_envelope_after_field_changes(envelope: bytes, changes: dict[int, bytes]) -> bytes:
    fields = [(tag, changes.get(tag, value)) for tag, value in _parse_envelope_fields(envelope)]
    values = dict(fields)
    values[8] = _digest(TARGET_SLICE_DIGEST_DOMAIN, [values[tag] for tag in range(1, 8)])
    values[21] = _digest(TENURE_PROOF_DIGEST_DOMAIN, [values[tag] for tag in range(11, 21)])
    values[25] = _digest(
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
    unsigned = [(tag, values[tag]) for tag in range(1, 38)]
    key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(TEST_ONLY_KEYS["request_writer_seed_hex"])
    )
    values[38] = key.sign(_signing_transcript(2, AUTH_SIGNING_DOMAIN, unsigned))
    return _encode_envelope_fields(
        [(tag, values[tag]) for tag in range(1, ENVELOPE_FIELD_COUNT + 1)]
    )


def _verify_envelope_signatures(
    values: dict[int, bytes], tenure_public_key: bytes, request_public_key: bytes
) -> None:
    tenure_transcript = _signing_transcript(
        1,
        TENURE_SIGNING_DOMAIN,
        [(tag, values[wire_tag]) for tag, wire_tag in enumerate(range(11, 20), start=1)],
    )
    request_transcript = _signing_transcript(
        2, AUTH_SIGNING_DOMAIN, [(tag, values[tag]) for tag in range(1, 38)]
    )
    try:
        Ed25519PublicKey.from_public_bytes(tenure_public_key).verify(values[20], tenure_transcript)
        Ed25519PublicKey.from_public_bytes(request_public_key).verify(
            values[38], request_transcript
        )
    except (InvalidSignature, ValueError) as error:
        raise SignatureReject("signed v2 envelope authentication failed") from error


def _admit_expected_store(values: dict[int, bytes], local_store: bytes) -> None:
    if values[32] != local_store:
        raise ContractReject(ENVELOPE_ERROR_CODES["runtime_store_mismatch"])


def _build_envelope(
    composite_digest: bytes,
    *,
    source_revision: int,
    operation_byte: str,
    temporal_byte: str,
    auth_nonce: bytes,
    expected_active_digest: bytes = bytes(32),
) -> dict[str, bytes]:
    semantic = ENVELOPE_SEMANTIC
    target = _hex(semantic["target_hex"])
    scope = _hex(semantic["source_scope_hex"])
    plan = _hex(semantic["source_plan_hex"])
    revision = _u64(source_revision)
    plan_digest = _hex(semantic["source_plan_digest_hex"])
    writer = _hex(semantic["writer_hex"])
    writer_epoch = _u64(semantic["writer_epoch"])
    authority = _hex(semantic["tenure_authority_hex"])
    tenure_key = _hex(semantic["tenure_key_hex"])
    tenure_algorithm = _u16(semantic["tenure_algorithm"])
    tenure_algorithm_version = _u16(semantic["tenure_algorithm_version"])
    supersedes = _u64(semantic["supersedes_through_epoch"])
    tenure_nonce = _hex(semantic["tenure_nonce_hex"])
    slice_version = _u16(semantic["slice_contract_version"])
    target_slice_digest = _digest(
        TARGET_SLICE_DIGEST_DOMAIN,
        [
            slice_version,
            target,
            scope,
            plan,
            revision,
            plan_digest,
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
        _signing_transcript(1, TENURE_SIGNING_DOMAIN, tenure_fields)
    )
    tenure_public_key = tenure_private_key.public_key().public_bytes_raw()
    tenure_digest = _digest(
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
    expected_tag = _u16(0 if expected_active_digest == bytes(32) else 1)
    operation_id = bytes.fromhex(operation_byte * 16)
    control_digest = _digest(
        APPLY_CONTROL_DIGEST_DOMAIN,
        [
            target_slice_digest,
            slice_version,
            target,
            scope,
            plan,
            revision,
            plan_digest,
            composite_digest,
            writer,
            writer_epoch,
            tenure_digest,
            expected_tag,
            expected_active_digest,
            operation_id,
        ],
    )
    unsigned_fields = [
        (1, slice_version),
        (2, target),
        (3, scope),
        (4, plan),
        (5, revision),
        (6, plan_digest),
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
        (23, expected_active_digest),
        (24, operation_id),
        (25, control_digest),
        (26, _u16(semantic["temporal_version"])),
        (27, bytes.fromhex(temporal_byte * 16)),
        (28, _hex(semantic["clock_domain_hex"])),
        (29, _u64(semantic["clock_generation"])),
        (30, _u64(semantic["original_budget_nanos"])),
        (31, _u64(semantic["remaining_budget_nanos"])),
        (32, _hex(semantic["expected_runtime_store_instance_id_hex"])),
        (33, _hex(semantic["auth_principal_hex"])),
        (34, _hex(semantic["auth_key_hex"])),
        (35, _u16(semantic["auth_algorithm"])),
        (36, _u16(semantic["auth_algorithm_version"])),
        (37, auth_nonce),
    ]
    request_private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(TEST_ONLY_KEYS["request_writer_seed_hex"])
    )
    signing_transcript = _signing_transcript(2, AUTH_SIGNING_DOMAIN, unsigned_fields)
    request_signature = request_private_key.sign(signing_transcript)
    request_public_key = request_private_key.public_key().public_bytes_raw()
    wire = _encode_envelope_fields([*unsigned_fields, (38, request_signature)])
    return {
        "target_slice_digest": target_slice_digest,
        "tenure_public_key": tenure_public_key,
        "tenure_signature": tenure_signature,
        "tenure_proof_digest": tenure_digest,
        "control_digest": control_digest,
        "request_public_key": request_public_key,
        "request_signature": request_signature,
        "signing_transcript": signing_transcript,
        "request_digest": _digest(REQUEST_DIGEST_DOMAIN, [wire]),
        "wire": wire,
    }


def _encode_pxar(envelope: bytes, pxte: bytes) -> bytes:
    _decode_envelope(envelope)
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
    max_bytes = PXAR_HEADER_BYTES + MAX_ENVELOPE_BYTES + len(PXTA_ZERO) + PXTE_MAX_BYTES
    if len(wire) > max_bytes:
        raise ContractReject(PXAR_ERROR_CODES["frame_too_large"])
    if len(wire) < PXAR_HEADER_BYTES:
        raise ContractReject(PXAR_ERROR_CODES["truncated"])
    if wire[:4] != PXAR_MAGIC:
        raise ContractReject(PXAR_ERROR_CODES["invalid_magic"])
    version, envelope_length, binding_length, execution_length = struct.unpack_from(
        ">HIII", wire, 4
    )
    if version != PXAR_VERSION:
        raise ContractReject(PXAR_ERROR_CODES["unsupported_version"])
    if envelope_length > MAX_ENVELOPE_BYTES:
        raise ContractReject(S7_CODEC_ERROR_CODES["frame_too_large"], detail_code=1)
    if binding_length != len(PXTA_ZERO):
        raise ContractReject(S7_CODEC_ERROR_CODES["binding_not_allowed"], detail_code=2)
    if execution_length > PXTE_MAX_BYTES:
        raise ContractReject(S7_CODEC_ERROR_CODES["frame_too_large"], detail_code=3)
    expected = PXAR_HEADER_BYTES + envelope_length + binding_length + execution_length
    if len(wire) < expected:
        raise ContractReject(PXAR_ERROR_CODES["truncated"])
    if len(wire) != expected:
        raise ContractReject(S7_CODEC_ERROR_CODES["trailing_bytes"])
    envelope_start = PXAR_HEADER_BYTES
    envelope_end = envelope_start + envelope_length
    binding_end = envelope_end + binding_length
    envelope_wire = wire[envelope_start:envelope_end]
    pxta_wire = wire[envelope_end:binding_end]
    pxte_wire = wire[binding_end:]
    envelope = _decode_envelope(envelope_wire)
    if pxta_wire != PXTA_ZERO:
        raise ContractReject(PXAR_ERROR_CODES["bindings_rejected"], detail_code=2)
    execution = _decode_pxte(pxte_wire)
    if execution["projection"]["row"]["target"] != envelope[2]:
        raise ContractReject(S7_CODEC_ERROR_CODES["target_mismatch"], detail_code=2)
    composite = _composite_digest(pxte_wire)
    if envelope[7] != composite:
        raise ContractReject(PXAR_ERROR_CODES["commitment_mismatch"], detail_code=7)
    return {
        "envelope": envelope,
        "execution": execution,
        "pxta_digest": _pxta_digest(),
        "pxte_digest": _pxte_digest(pxte_wire),
        "composite_digest": composite,
        "wire": wire,
    }


def _admit_pxar(
    wire: bytes,
    tenure_public_key: bytes,
    request_public_key: bytes,
    local_store: bytes,
) -> dict[str, Any]:
    parsed = _decode_pxar(wire)
    _verify_envelope_signatures(parsed["envelope"], tenure_public_key, request_public_key)
    _admit_expected_store(parsed["envelope"], local_store)
    return parsed


def _build_artifact_vector() -> dict[str, bytes]:
    compiled_digest = _compiled_compatibility_digest(FIXTURE_ENTRY)
    descriptor_wire = _encode_descriptor(DESCRIPTOR, compiled_digest)
    descriptor = _decode_descriptor(descriptor_wire)
    descriptor_digest = _descriptor_digest(descriptor_wire)
    identity_wire = _build_identity_wire(descriptor, descriptor_digest)
    row = _target_row_wire(_hex(TARGET_HEX), identity_wire, FIXTURE_ENTRY)
    manifest_wire = _encode_manifest(row)
    projection_wire = _encode_projection(manifest_wire)
    _validate_release_chain(descriptor_wire, identity_wire, manifest_wire, projection_wire)
    return {
        "compiled_compatibility_digest": compiled_digest,
        "empty_config_digest": _empty_config_digest(),
        "descriptor": descriptor_wire,
        "descriptor_digest": descriptor_digest,
        "identity": identity_wire,
        "manifest": manifest_wire,
        "manifest_digest": _manifest_digest(manifest_wire),
        "projection": projection_wire,
    }


def _build_vectors() -> dict[str, Any]:
    artifact = _build_artifact_vector()
    subject = {
        **copy.deepcopy(SUBJECT),
        "config_digest_hex": artifact["empty_config_digest"].hex(),
    }
    one_pxte = _encode_pxte(
        artifact["projection"],
        PROFILE_ONE_SOURCE_LOOP,
        copy.deepcopy(DOMAIN),
        subject,
    )
    one_envelope = _build_envelope(
        _composite_digest(one_pxte),
        source_revision=3,
        operation_byte="0d",
        temporal_byte="0e",
        auth_nonce=b"test-only-request-nonce-one",
    )
    one_outer = _encode_pxar(one_envelope["wire"], one_pxte)
    empty_pxte = _encode_pxte(artifact["projection"], PROFILE_EMPTY_DEACTIVATE, None, None)
    empty_envelope = _build_envelope(
        _composite_digest(empty_pxte),
        source_revision=4,
        operation_byte="0f",
        temporal_byte="10",
        auth_nonce=b"test-only-request-nonce-empty",
        expected_active_digest=one_envelope["target_slice_digest"],
    )
    empty_outer = _encode_pxar(empty_envelope["wire"], empty_pxte)
    return {
        "artifact": artifact,
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
    }


def _expected_shape(vector: dict[str, Any]) -> dict[str, Any]:
    envelope = vector["envelope"]
    return {
        "pxte_v4_body_hex": vector["pxte"].hex(),
        "pxte_v4_body_length": len(vector["pxte"]),
        "pxte_v4_digest_hex": vector["pxte_digest"].hex(),
        "composite_v5_digest_hex": vector["composite_digest"].hex(),
        "target_slice_digest_hex": envelope["target_slice_digest"].hex(),
        "tenure_public_key_hex": envelope["tenure_public_key"].hex(),
        "tenure_signature_hex": envelope["tenure_signature"].hex(),
        "request_public_key_hex": envelope["request_public_key"].hex(),
        "request_signature_hex": envelope["request_signature"].hex(),
        "signing_transcript_hex": envelope["signing_transcript"].hex(),
        "request_digest_hex": envelope["request_digest"].hex(),
        "envelope_v2_hex": envelope["wire"].hex(),
        "envelope_v2_length": len(envelope["wire"]),
        "outer_v5_hex": vector["outer"].hex(),
        "outer_v5_length": len(vector["outer"]),
    }


def _invalid_precedence_fixture(
    vectors: dict[str, Any], controls: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    def expected(
        decoder: str, wire: bytes, code: int, detail: int | None
    ) -> dict[str, Any]:
        return {
            "decoder": decoder,
            "wire_hex": wire.hex(),
            "expected_code": code,
            "expected_detail": detail,
        }

    descriptor_structure = bytearray(vectors["artifact"]["descriptor"])
    descriptor_structure[6:38] = bytes(32)
    descriptor_structure[78:80] = _u16(0)
    descriptor_semantics = bytearray(vectors["artifact"]["descriptor"])
    descriptor_semantics[6:38] = bytes(32)
    descriptor_semantics[38:46] = _u64(0)

    manifest_trailing = bytearray(vectors["artifact"]["manifest"])
    manifest_trailing[22:54] = bytes(32)
    manifest_trailing += b"\x00"
    manifest_versions = bytearray(vectors["artifact"]["manifest"])
    manifest_versions[150:152] = _u16(PXAR_VERSION - 1)
    manifest_versions[152:154] = _u16(PROFILE_VERSION + 1)

    projection_trailing = bytearray(vectors["artifact"]["projection"])
    projection_trailing[54:86] = bytes(32)
    projection_trailing += b"\x00"
    projection_versions = bytearray(vectors["artifact"]["projection"])
    projection_versions[182:184] = _u16(PXAR_VERSION - 1)
    projection_versions[184:186] = _u16(PROFILE_VERSION + 1)

    pxte_trailing = bytearray(vectors["empty"]["pxte"])
    profile_offset = 6 + PROJECTION_BYTES
    pxte_trailing[profile_offset : profile_offset + 2] = _u16(2)
    pxte_trailing += b"\x00"
    pxte_semantics = bytearray(vectors["empty"]["pxte"])
    pxte_semantics[profile_offset : profile_offset + 2] = _u16(2)
    pxte_semantics[profile_offset + 2] = 99

    envelope = vectors["one"]["envelope"]["wire"]
    envelope_writer_claim = _rebuild_envelope_after_field_changes(envelope, {17: _u64(0)})
    envelope_scope = _rebuild_envelope_after_field_changes(
        envelope, {15: bytes.fromhex("fe" * 16)}
    )
    envelope_auth = _rebuild_envelope_after_field_changes(
        envelope, {35: _u16(0), 36: _u16(0)}
    )

    replacement_row = bytearray(vectors["artifact"]["projection"][38:])
    replacement_row[:16] = bytes.fromhex("ef" * 16)
    replacement_manifest = _encode_manifest(bytes(replacement_row))
    replacement_projection = _encode_projection(replacement_manifest)
    replacement_subject = {
        **copy.deepcopy(SUBJECT),
        "config_digest_hex": vectors["artifact"]["empty_config_digest"].hex(),
    }
    replacement_execution = _encode_pxte(
        replacement_projection,
        PROFILE_ONE_SOURCE_LOOP,
        copy.deepcopy(DOMAIN),
        replacement_subject,
    )
    pxar_target_and_digest = (
        PXAR_MAGIC
        + _u16(PXAR_VERSION)
        + _u32(len(envelope))
        + _u32(len(PXTA_ZERO))
        + _u32(len(replacement_execution))
        + envelope
        + PXTA_ZERO
        + replacement_execution
    )

    bootstrap_request = _resigned_control_changes(
        controls["bootstrap_request"],
        magic=BOOTSTRAP_REQUEST_MAGIC,
        maximum_bytes=MAX_BOOTSTRAP_REQUEST_BYTES,
        schema=BOOTSTRAP_REQUEST_SCHEMA,
        signing_domain=BOOTSTRAP_REQUEST_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
        changes={6: _u16(0), 9: _u32(0)},
    )
    bootstrap_response_state = _resigned_control_changes(
        controls["bootstrap_response"],
        magic=BOOTSTRAP_RESPONSE_MAGIC,
        maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
        schema=BOOTSTRAP_RESPONSE_SCHEMA,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={16: _u16(99), 17: _u16(99)},
    )
    invalid_identity_after_build_id = (
        vectors["artifact"]["identity"][:32] + bytes(BUILD_IDENTITY_BYTES - 32)
    )
    bootstrap_response_identity = _resigned_control_changes(
        controls["bootstrap_response"],
        magic=BOOTSTRAP_RESPONSE_MAGIC,
        maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
        schema=BOOTSTRAP_RESPONSE_SCHEMA,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={11: bytes(32), 12: invalid_identity_after_build_id},
    )
    bootstrap_response_compatibility = _resigned_control_changes(
        controls["bootstrap_response"],
        magic=BOOTSTRAP_RESPONSE_MAGIC,
        maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
        schema=BOOTSTRAP_RESPONSE_SCHEMA,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={10: bytes.fromhex("f0" * 32), 11: bytes(32)},
    )
    query_request = _resigned_control_changes(
        controls["query_request"],
        magic=QUERY_REQUEST_MAGIC,
        maximum_bytes=MAX_QUERY_REQUEST_BYTES,
        schema=QUERY_REQUEST_SCHEMA,
        signing_domain=QUERY_REQUEST_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
        changes={4: bytes(32), 10: _u16(2)},
    )
    query_response_kind = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={12: _u16(99), 15: _u16(99)},
    )
    query_response_owner_reason = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={
            11: _u16(OPERATIONAL_REASONS["runtime_busy"]),
            16: _u8(0),
            17: bytes(16),
        },
    )
    query_response_live = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={
            23: _u16(LIVE_STATES["validated_operational_quarantine"]),
            24: _u64(1),
            26: bytes(32),
        },
    )

    identity = vectors["artifact"]["identity"]
    identity_semantics = bytearray(identity)
    identity_semantics[32:64] = bytes(32)
    identity_semantics[96:128] = bytes(32)
    return {
        "descriptor_structure_before_semantics": expected(
            "descriptor",
            bytes(descriptor_structure),
            S7_CODEC_ERROR_CODES["invalid_field_length"],
            4,
        ),
        "descriptor_semantic_1_before_2": expected(
            "descriptor",
            bytes(descriptor_semantics),
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            1,
        ),
        "identity_truncated": expected(
            "identity",
            identity[:-1],
            S7_CODEC_ERROR_CODES["truncated"],
            None,
        ),
        "identity_trailing": expected(
            "identity",
            identity + b"\x00",
            S7_CODEC_ERROR_CODES["trailing_bytes"],
            None,
        ),
        "identity_semantic_2_before_4": expected(
            "identity",
            bytes(identity_semantics),
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            2,
        ),
        "manifest_outer_structure_before_row_semantics": expected(
            "manifest",
            bytes(manifest_trailing),
            S7_CODEC_ERROR_CODES["trailing_bytes"],
            None,
        ),
        "manifest_selected_version_1_before_2": expected(
            "manifest",
            bytes(manifest_versions),
            S7_CODEC_ERROR_CODES["unsupported_version"],
            1,
        ),
        "projection_outer_structure_before_row_semantics": expected(
            "projection",
            bytes(projection_trailing),
            S7_CODEC_ERROR_CODES["trailing_bytes"],
            None,
        ),
        "projection_selected_version_1_before_2": expected(
            "projection",
            bytes(projection_versions),
            S7_CODEC_ERROR_CODES["unsupported_version"],
            1,
        ),
        "pxte_outer_trailing_before_nested_semantics": expected(
            "pxte",
            bytes(pxte_trailing),
            S7_CODEC_ERROR_CODES["trailing_bytes"],
            None,
        ),
        "pxte_semantic_2_before_3": expected(
            "pxte",
            bytes(pxte_semantics),
            S7_CODEC_ERROR_CODES["unsupported_version"],
            2,
        ),
        "envelope_9_before_17": expected(
            "envelope",
            envelope_writer_claim,
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            9,
        ),
        "envelope_scope_detail_15": expected(
            "envelope",
            envelope_scope,
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            15,
        ),
        "envelope_35_before_36": expected(
            "envelope",
            envelope_auth,
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            35,
        ),
        "pxar_target_2_before_digest_7": expected(
            "pxar",
            pxar_target_and_digest,
            S7_CODEC_ERROR_CODES["target_mismatch"],
            2,
        ),
        "bootstrap_request_6_before_9": expected(
            "bootstrap_request",
            bootstrap_request,
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            6,
        ),
        "bootstrap_response_16_before_17": expected(
            "bootstrap_response",
            bootstrap_response_state,
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            16,
        ),
        "bootstrap_response_11_before_12": expected(
            "bootstrap_response",
            bootstrap_response_identity,
            S7_CODEC_ERROR_CODES["compatibility_mismatch"],
            11,
        ),
        "bootstrap_response_10_before_11": expected(
            "bootstrap_response",
            bootstrap_response_compatibility,
            S7_CODEC_ERROR_CODES["compatibility_mismatch"],
            10,
        ),
        "query_request_4_before_10": expected(
            "query_request",
            query_request,
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            4,
        ),
        "query_response_12_before_15": expected(
            "query_response",
            query_response_kind,
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            12,
        ),
        "query_response_11_before_16": expected(
            "query_response",
            query_response_owner_reason,
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            11,
        ),
        "query_response_23_before_24_26": expected(
            "query_response",
            query_response_live,
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            23,
        ),
    }


def _fixture_document() -> dict[str, Any]:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)
    artifact = vectors["artifact"]
    return {
        "fixture_version": 1,
        "source": (
            "independent Python struct/hashlib/cryptography S7-B internal "
            "reference-successor fixture"
        ),
        "capability_status": (
            "internal enabler only; no release/installer/planner/runtime endpoint "
            "producer-consumer path"
        ),
        "test_only_notice": "TEST-ONLY deterministic keys and identities; never production",
        "test_only_keys": TEST_ONLY_KEYS,
        "semantic": {
            "descriptor": DESCRIPTOR,
            "target_hex": TARGET_HEX,
            "expected_runtime_store_instance_id_hex": EXPECTED_STORE_HEX,
            "admission_policy_fingerprint_hex": (EXPECTED_ADMISSION_POLICY_DIGEST.hex()),
            "fixture_entry": FIXTURE_ENTRY,
            "reference_domain": DOMAIN,
            "reference_subject": SUBJECT,
            "channel_binding": {
                "binding_version": CHANNEL_BINDING_VERSION,
                "runtime_peer_hex": "e1" * 16,
                "local_endpoint_identity_digest_hex": "e3" * 32,
                "peer_credentials_digest_hex": "e4" * 32,
            },
        },
        "protocol": {
            "descriptor_version": DESCRIPTOR_VERSION,
            "max_target_triple_bytes": MAX_TARGET_TRIPLE_BYTES,
            "max_runtime_artifact_bytes": MAX_RUNTIME_ARTIFACT_BYTES,
            "max_descriptor_bytes": MAX_DESCRIPTOR_BYTES,
            "fixture_entry_bytes": FIXTURE_ENTRY_BYTES,
            "build_identity_bytes": BUILD_IDENTITY_BYTES,
            "manifest_version": MANIFEST_VERSION,
            "manifest_bytes": MANIFEST_BYTES,
            "projection_version": PROJECTION_VERSION,
            "projection_bytes": PROJECTION_BYTES,
            "profile_version": PROFILE_VERSION,
            "profile_modes": {
                "one_source_loop": PROFILE_ONE_SOURCE_LOOP,
                "empty_deactivate": PROFILE_EMPTY_DEACTIVATE,
            },
            "profile_fixed_semantics": {
                "lifecycle_concurrency": PROFILE_LIFECYCLE_CONCURRENCY,
                "mailbox_slots": PROFILE_MAILBOX_SLOTS,
                "dispatch_slots": PROFILE_DISPATCH_SLOTS,
                "background_task_slots": PROFILE_BACKGROUND_TASK_SLOTS,
            },
            "max_reference_lifecycle_budget_nanos": (MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS),
            "reference_domain_bytes": REFERENCE_DOMAIN_BYTES,
            "reference_subject_bytes": REFERENCE_SUBJECT_BYTES,
            "pxte_v4_version": PXTE_VERSION,
            "pxte_v4_empty_bytes": PXTE_EMPTY_BYTES,
            "pxte_v4_one_source_loop_bytes": PXTE_ONE_SOURCE_LOOP_BYTES,
            "pxar_v5_version": PXAR_VERSION,
            "max_envelope_v2_bytes": MAX_ENVELOPE_BYTES,
            "max_pxar_v5_bytes": (
                PXAR_HEADER_BYTES + MAX_ENVELOPE_BYTES + len(PXTA_ZERO) + PXTE_MAX_BYTES
            ),
            "envelope_v2_version": ENVELOPE_VERSION,
            "envelope_v2_field_count": ENVELOPE_FIELD_COUNT,
            "descriptor_digest_domain_hex": DESCRIPTOR_DIGEST_DOMAIN.hex(),
            "compiled_compatibility_domain_hex": (COMPILED_COMPATIBILITY_DOMAIN.hex()),
            "manifest_digest_domain_hex": MANIFEST_DIGEST_DOMAIN.hex(),
            "empty_config_digest_domain_hex": EMPTY_CONFIG_DIGEST_DOMAIN.hex(),
            "pxte_v4_digest_domain_hex": PXTE_DIGEST_DOMAIN.hex(),
            "composite_v5_digest_domain_hex": COMPOSITE_DIGEST_DOMAIN.hex(),
            "auth_signing_domain_v2_hex": AUTH_SIGNING_DOMAIN.hex(),
            "request_digest_domain_v2_hex": REQUEST_DIGEST_DOMAIN.hex(),
            "bootstrap_request_signing_domain_hex": (BOOTSTRAP_REQUEST_SIGNING_DOMAIN.hex()),
            "bootstrap_request_digest_domain_hex": (BOOTSTRAP_REQUEST_DIGEST_DOMAIN.hex()),
            "bootstrap_response_signing_domain_hex": (BOOTSTRAP_RESPONSE_SIGNING_DOMAIN.hex()),
            "bootstrap_response_digest_domain_hex": (BOOTSTRAP_RESPONSE_DIGEST_DOMAIN.hex()),
            "query_request_signing_domain_hex": (QUERY_REQUEST_SIGNING_DOMAIN.hex()),
            "query_request_digest_domain_hex": QUERY_REQUEST_DIGEST_DOMAIN.hex(),
            "query_response_signing_domain_hex": (QUERY_RESPONSE_SIGNING_DOMAIN.hex()),
            "query_response_digest_domain_hex": (QUERY_RESPONSE_DIGEST_DOMAIN.hex()),
            "profile_fingerprint_domain_hex": PROFILE_FINGERPRINT_DOMAIN.hex(),
            "channel_binding_domain_hex": CHANNEL_BINDING_DOMAIN.hex(),
            "max_bootstrap_request_bytes": MAX_BOOTSTRAP_REQUEST_BYTES,
            "max_bootstrap_response_bytes": MAX_BOOTSTRAP_RESPONSE_BYTES,
            "max_query_request_bytes": MAX_QUERY_REQUEST_BYTES,
            "max_query_response_bytes": MAX_QUERY_RESPONSE_BYTES,
            "max_query_record_count": MAX_QUERY_RECORD_COUNT,
            "zero_pxta_hex": PXTA_ZERO.hex(),
        },
        "codec_error_codes": S7_CODEC_ERROR_CODES,
        "bootstrap_states": BOOTSTRAP_STATES,
        "operational_reasons": OPERATIONAL_REASONS,
        "owner_states": OWNER_STATES,
        "lookup_kinds": LOOKUP_KINDS,
        "durable_phases": DURABLE_PHASES,
        "desired_head_kinds": DESIRED_HEAD_KINDS,
        "live_states": LIVE_STATES,
        "invalid_precedence": _invalid_precedence_fixture(vectors, controls),
        "legacy_fixture_sha256": {
            "s2_apply_envelope_v1.json": (
                "df1f878215bdea41778742028bc9a2fe5453e5c420550694011b33082c908a25"
            ),
            "s3_runtime_apply_request_v1.json": (
                "e98a2c4020381d9741d40c8249c42245e6eaa3263647be4b91e2d562288f0159"
            ),
            "s4_runtime_apply_request_v2.json": (
                "675555df6a95b9994353c564b7d030a7f418c632a83c3d5c9383bff2ca311d86"
            ),
            "s5_runtime_apply_request_v3.json": (
                "e76c41202d5e65bafcca845fe9189b425e0c5888acb59c28ebccd0927ed0216e"
            ),
            "s6_runtime_apply_request_v4.json": (
                "fdc22400348f4cc608a499611294b3e11fe1957b777cc0dc202f303ed867713f"
            ),
        },
        "expected": {
            "compiled_compatibility_digest_hex": (artifact["compiled_compatibility_digest"].hex()),
            "empty_config_digest_hex": artifact["empty_config_digest"].hex(),
            "descriptor_hex": artifact["descriptor"].hex(),
            "descriptor_length": len(artifact["descriptor"]),
            "descriptor_digest_hex": artifact["descriptor_digest"].hex(),
            "build_identity_hex": artifact["identity"].hex(),
            "manifest_hex": artifact["manifest"].hex(),
            "manifest_digest_hex": artifact["manifest_digest"].hex(),
            "projection_hex": artifact["projection"].hex(),
            "one_source_loop": _expected_shape(vectors["one"]),
            "empty_deactivate": _expected_shape(vectors["empty"]),
            "channel_binding_digest_hex": controls["channel_binding_digest"].hex(),
            "profile_fingerprint_hex": controls["profile_fingerprint"].hex(),
            "bootstrap_request": _control_expected(controls["bootstrap_request"]),
            "bootstrap_response": _control_expected(controls["bootstrap_response"]),
            "query_request": _control_expected(controls["query_request"]),
            "query_response": _control_expected(controls["query_response"]),
        },
    }


def _load_fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _resign_envelope_with_store(envelope: bytes, store: bytes) -> bytes:
    fields = _parse_envelope_fields(envelope)
    unsigned = [(tag, store if tag == 32 else value) for tag, value in fields if tag != 38]
    key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(TEST_ONLY_KEYS["request_writer_seed_hex"])
    )
    signature = key.sign(_signing_transcript(2, AUTH_SIGNING_DOMAIN, unsigned))
    return _encode_envelope_fields([*unsigned, (38, signature)])


def test_independent_rebuild_matches_s7_fixture() -> None:
    assert _fixture_document() == _load_fixture()


def test_shared_multi_invalid_precedence_vectors_freeze_exact_rejections() -> None:
    decoders = {
        "descriptor": _decode_descriptor,
        "identity": _decode_identity,
        "manifest": _decode_manifest,
        "projection": _decode_projection,
        "pxte": _decode_pxte,
        "envelope": _decode_envelope,
        "pxar": _decode_pxar,
        "bootstrap_request": _decode_bootstrap_request,
        "bootstrap_response": _decode_bootstrap_response,
        "query_request": _decode_query_request,
        "query_response": _decode_query_response,
    }
    for vector in _load_fixture()["invalid_precedence"].values():
        _assert_contract_rejection(
            decoders[vector["decoder"]],
            bytes.fromhex(vector["wire_hex"]),
            vector["expected_code"],
            vector["expected_detail"],
        )


def test_artifact_chain_round_trips_and_keeps_runtime_and_fixture_digests_distinct() -> None:
    fixture = _load_fixture()["expected"]
    descriptor = bytes.fromhex(fixture["descriptor_hex"])
    identity = bytes.fromhex(fixture["build_identity_hex"])
    manifest = bytes.fromhex(fixture["manifest_hex"])
    projection = bytes.fromhex(fixture["projection_hex"])
    _validate_release_chain(descriptor, identity, manifest, projection)
    parsed_identity = _decode_identity(identity)
    parsed_projection = _decode_projection(projection)
    assert (
        parsed_identity["runtime_artifact_sha256"]
        != parsed_projection["row"]["fixture"]["fixture_artifact_digest"]
    )
    assert _descriptor_digest(descriptor).hex() == fixture["descriptor_digest_hex"]
    assert _manifest_digest(manifest).hex() == fixture["manifest_digest_hex"]


@pytest.mark.parametrize(
    ("mutator", "expected_code", "expected_detail"),
    [
        (
            lambda wire: wire[:4] + _u16(2) + wire[6:],
            S7_CODEC_ERROR_CODES["unsupported_version"],
            None,
        ),
        (
            lambda wire: wire + b"\x00",
            S7_CODEC_ERROR_CODES["trailing_bytes"],
            None,
        ),
        (
            lambda wire: wire[:6] + bytes(32) + wire[38:],
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            1,
        ),
        (
            lambda wire: wire[:78] + _u16(0) + wire[80:],
            S7_CODEC_ERROR_CODES["invalid_field_length"],
            4,
        ),
    ],
)
def test_descriptor_strict_rejections(
    mutator: Any, expected_code: int, expected_detail: int | None
) -> None:
    descriptor = _build_artifact_vector()["descriptor"]
    with pytest.raises(ContractReject) as rejected:
        _decode_descriptor(mutator(descriptor))
    assert rejected.value.code == expected_code
    assert rejected.value.detail_code == expected_detail


@pytest.mark.parametrize(
    ("changes", "expected_detail"),
    [
        ({"runtime_artifact_length": 0}, 2),
        ({"runtime_artifact_sha256_hex": "00" * 32}, 3),
        ({"target_triple": "AARCH64-unknown-linux-gnu"}, 4),
    ],
)
def test_descriptor_semantic_fields_fail_closed(
    changes: dict[str, Any], expected_detail: int
) -> None:
    value = {**DESCRIPTOR, **changes}
    compiled = _compiled_compatibility_digest(FIXTURE_ENTRY)
    with pytest.raises(ContractReject) as rejected:
        _encode_descriptor(value, compiled)
    assert rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_value"]
    assert rejected.value.detail_code == expected_detail


def test_descriptor_zero_compiled_compatibility_has_stable_reason() -> None:
    with pytest.raises(ContractReject) as rejected:
        _encode_descriptor(DESCRIPTOR, bytes(32))
    assert rejected.value.code == S7_CODEC_ERROR_CODES["compatibility_mismatch"]
    assert rejected.value.detail_code == 5


@pytest.mark.parametrize("offset", [0, 32, 64, 96])
def test_build_identity_zero_components_are_invalid_values(offset: int) -> None:
    identity = bytearray(_build_artifact_vector()["identity"])
    identity[offset : offset + 32] = bytes(32)
    with pytest.raises(ContractReject) as rejected:
        _decode_identity(bytes(identity))
    assert rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_value"]
    assert rejected.value.detail_code == offset // 32 + 1


@pytest.mark.parametrize(
    ("offset", "expected_detail"),
    [(150, 1), (152, 2)],
)
def test_manifest_selected_versions_report_local_row_tags(
    offset: int, expected_detail: int
) -> None:
    manifest = bytearray(_build_artifact_vector()["manifest"])
    manifest[offset : offset + 2] = _u16(99)
    with pytest.raises(ContractReject) as rejected:
        _decode_manifest(bytes(manifest))
    assert rejected.value.code == S7_CODEC_ERROR_CODES["unsupported_version"]
    assert rejected.value.detail_code == expected_detail


def test_manifest_rejects_second_row_projection_tamper_and_identity_cross_ref() -> None:
    artifact = _build_artifact_vector()
    with pytest.raises(ContractReject) as second_row:
        _decode_manifest(artifact["manifest"] + artifact["manifest"][6:])
    assert second_row.value.code == S7_CODEC_ERROR_CODES["trailing_bytes"]

    projection = bytearray(artifact["projection"])
    projection[6] ^= 1
    with pytest.raises(ContractReject) as tampered:
        _decode_projection(bytes(projection))
    assert tampered.value.code == S7_CODEC_ERROR_CODES["digest_mismatch"]

    identity = bytearray(artifact["identity"])
    identity[32] ^= 1
    with pytest.raises(ContractReject) as mismatch:
        _validate_release_chain(
            artifact["descriptor"],
            bytes(identity),
            artifact["manifest"],
            artifact["projection"],
        )
    assert mismatch.value.code == S7_CODEC_ERROR_CODES["cross_reference_mismatch"]


def test_release_chain_rejects_self_consistent_but_uncompiled_fixture_table() -> None:
    bad_compatibility = bytes.fromhex("55" * 32)
    descriptor_wire = _encode_descriptor(DESCRIPTOR, bad_compatibility)
    descriptor = _decode_descriptor(descriptor_wire)
    identity = _build_identity_wire(descriptor, _descriptor_digest(descriptor_wire))
    row = (
        _hex(TARGET_HEX)
        + identity
        + _u16(PXAR_VERSION)
        + _u16(PROFILE_VERSION)
        + _fixture_entry_wire(FIXTURE_ENTRY)
    )
    manifest = MANIFEST_MAGIC + _u16(MANIFEST_VERSION) + row
    manifest_digest = _digest(MANIFEST_DIGEST_DOMAIN, [manifest])
    projection = PROJECTION_MAGIC + _u16(PROJECTION_VERSION) + manifest_digest + row
    with pytest.raises(ContractReject) as mismatch:
        _validate_release_chain(descriptor_wire, identity, manifest, projection)
    assert mismatch.value.code == S7_CODEC_ERROR_CODES["compatibility_mismatch"]


@pytest.mark.parametrize("shape", ["one_source_loop", "empty_deactivate"])
def test_both_exact_shapes_round_trip_with_signatures_and_store_binding(
    shape: str,
) -> None:
    expected = _load_fixture()["expected"][shape]
    outer = bytes.fromhex(expected["outer_v5_hex"])
    parsed = _admit_pxar(
        outer,
        bytes.fromhex(expected["tenure_public_key_hex"]),
        bytes.fromhex(expected["request_public_key_hex"]),
        bytes.fromhex(EXPECTED_STORE_HEX),
    )
    assert parsed["pxte_digest"].hex() == expected["pxte_v4_digest_hex"]
    assert parsed["composite_digest"].hex() == expected["composite_v5_digest_hex"]
    assert len(parsed["execution"]["wire"]) == expected["pxte_v4_body_length"]


def test_reference_profile_rejects_partial_or_mismatched_shapes() -> None:
    vectors = _build_vectors()
    one = vectors["one"]["pxte"]
    domain_only = one[:348] + b"\x00"
    with pytest.raises(ContractReject) as partial:
        _decode_pxte(domain_only)
    assert partial.value.code == S7_CODEC_ERROR_CODES["unsupported_shape"]
    assert partial.value.detail_code == 5

    wrong_domain = bytearray(one)
    wrong_domain[365] ^= 1
    with pytest.raises(ContractReject) as orphan:
        _decode_pxte(bytes(wrong_domain))
    assert orphan.value.code == S7_CODEC_ERROR_CODES["cross_reference_mismatch"]
    assert orphan.value.detail_code == 5

    wrong_fixture = bytearray(one)
    wrong_fixture[381] ^= 1
    with pytest.raises(ContractReject) as fixture:
        _decode_pxte(bytes(wrong_fixture))
    assert fixture.value.code == S7_CODEC_ERROR_CODES["fixture_mismatch"]
    assert fixture.value.detail_code == 5

    wrong_config = bytearray(one)
    wrong_config[-1] ^= 1
    with pytest.raises(ContractReject) as config:
        _decode_pxte(bytes(wrong_config))
    assert config.value.code == S7_CODEC_ERROR_CODES["fixture_mismatch"]
    assert config.value.detail_code == 5

    empty = vectors["empty"]["pxte"]
    empty_with_domain = empty[:307] + b"\x01" + _encode_reference_domain(DOMAIN) + b"\x00"
    with pytest.raises(ContractReject) as nonempty:
        _decode_pxte(empty_with_domain)
    assert nonempty.value.code == S7_CODEC_ERROR_CODES["unsupported_shape"]
    assert nonempty.value.detail_code == 4


def test_profile_presence_domain_budget_and_each_fixture_field_are_strict() -> None:
    one = _build_vectors()["one"]["pxte"]
    invalid_profile_version = bytearray(one)
    invalid_profile_version[304:306] = _u16(PROFILE_VERSION + 1)
    with pytest.raises(ContractReject) as profile_version:
        _decode_pxte(bytes(invalid_profile_version))
    assert profile_version.value.code == S7_CODEC_ERROR_CODES["unsupported_version"]
    assert profile_version.value.detail_code == 2

    invalid_mode = bytearray(one)
    invalid_mode[306] = 3
    with pytest.raises(ContractReject) as mode:
        _decode_pxte(bytes(invalid_mode))
    assert mode.value.code == S7_CODEC_ERROR_CODES["unsupported_shape"]
    assert mode.value.detail_code == 3

    invalid_presence = bytearray(one)
    invalid_presence[307] = 2
    with pytest.raises(ContractReject) as presence:
        _decode_pxte(bytes(invalid_presence))
    assert presence.value.code == S7_CODEC_ERROR_CODES["invalid_presence"]
    assert presence.value.detail_code == 4

    invalid_subject_presence = bytearray(one)
    invalid_subject_presence[348] = 2
    with pytest.raises(ContractReject) as subject_presence:
        _decode_pxte(bytes(invalid_subject_presence))
    assert subject_presence.value.code == S7_CODEC_ERROR_CODES["invalid_presence"]
    assert subject_presence.value.detail_code == 5

    missing_domain = one[:307] + _u8(0) + one[348:]
    with pytest.raises(ContractReject) as domain_shape:
        _decode_pxte(missing_domain)
    assert domain_shape.value.code == S7_CODEC_ERROR_CODES["unsupported_shape"]
    assert domain_shape.value.detail_code == 4

    zero_budget = bytearray(one)
    zero_budget[324:332] = bytes(8)
    with pytest.raises(ContractReject) as budget:
        _decode_pxte(bytes(zero_budget))
    assert budget.value.code == S7_CODEC_ERROR_CODES["invalid_field_value"]
    assert budget.value.detail_code == 4

    for offset in (381, 397, 413, 429, 461):
        fixture_mismatch = bytearray(one)
        fixture_mismatch[offset] ^= 1
        with pytest.raises(ContractReject) as fixture:
            _decode_pxte(bytes(fixture_mismatch))
        assert fixture.value.code == S7_CODEC_ERROR_CODES["fixture_mismatch"]
        assert fixture.value.detail_code == 5


def test_projection_errors_propagate_through_pxte_and_empty_trailing_is_exact() -> None:
    one = bytearray(_build_vectors()["one"]["pxte"])
    one[12] ^= 1
    with pytest.raises(ContractReject) as digest:
        _decode_pxte(bytes(one))
    assert digest.value.code == S7_CODEC_ERROR_CODES["digest_mismatch"]

    incompatible = bytearray(_build_vectors()["one"]["pxte"])
    incompatible[156] ^= 1
    with pytest.raises(ContractReject) as compatibility:
        _decode_pxte(bytes(incompatible))
    assert compatibility.value.code == S7_CODEC_ERROR_CODES["compatibility_mismatch"]

    empty = _build_vectors()["empty"]["pxte"]
    with pytest.raises(ContractReject) as trailing:
        _decode_pxte(empty + b"\x00")
    assert trailing.value.code == S7_CODEC_ERROR_CODES["trailing_bytes"]


def test_v5_rejects_any_binding_and_legacy_capacity_bearing_execution() -> None:
    vectors = _build_vectors()
    one = vectors["one"]
    envelope = one["envelope"]["wire"]
    old_fixture = json.loads(S6_FIXTURE_PATH.read_text(encoding="utf-8"))
    old_pxta = bytes.fromhex(old_fixture["expected"]["pxta_body_hex"])
    bound_outer = (
        PXAR_MAGIC
        + _u16(PXAR_VERSION)
        + _u32(len(envelope))
        + _u32(len(old_pxta))
        + _u32(len(one["pxte"]))
        + envelope
        + old_pxta
        + one["pxte"]
    )
    with pytest.raises(ContractReject) as binding:
        _decode_pxar(bound_outer)
    assert binding.value.code == S7_CODEC_ERROR_CODES["binding_not_allowed"]
    assert binding.value.detail_code == 2

    old_pxte = bytes.fromhex(old_fixture["expected"]["pxte_v3_body_hex"])
    with pytest.raises(ContractReject) as legacy:
        _decode_pxte(old_pxte)
    assert legacy.value.code == S7_CODEC_ERROR_CODES["frame_too_large"]


def test_outer_v5_propagates_nested_version_digest_and_presence_reasons() -> None:
    outer = _build_vectors()["one"]["outer"]
    envelope_length, binding_length, execution_length = struct.unpack_from(">III", outer, 6)
    execution_start = PXAR_HEADER_BYTES + envelope_length + binding_length

    envelope_version = bytearray(outer)
    offset = PXAR_HEADER_BYTES + len(ENVELOPE_MAGIC)
    envelope_version[offset : offset + 2] = _u16(1)
    with pytest.raises(ContractReject) as envelope:
        _decode_pxar(bytes(envelope_version))
    assert envelope.value.code == S7_CODEC_ERROR_CODES["unsupported_version"]
    assert envelope.value.detail_code is None

    execution_version = bytearray(outer)
    execution_version[execution_start + 4 : execution_start + 6] = _u16(3)
    with pytest.raises(ContractReject) as version:
        _decode_pxar(bytes(execution_version))
    assert version.value.code == S7_CODEC_ERROR_CODES["unsupported_version"]

    projection_digest = bytearray(outer)
    projection_digest[execution_start + 12] ^= 1
    with pytest.raises(ContractReject) as digest:
        _decode_pxar(bytes(projection_digest))
    assert digest.value.code == S7_CODEC_ERROR_CODES["digest_mismatch"]

    presence = bytearray(outer)
    presence[execution_start + 307] = 2
    with pytest.raises(ContractReject) as invalid_presence:
        _decode_pxar(bytes(presence))
    assert invalid_presence.value.code == S7_CODEC_ERROR_CODES["invalid_presence"]
    assert invalid_presence.value.detail_code == 4

    declared_short = bytearray(outer)
    declared_short[14:18] = _u32(execution_length - 1)
    with pytest.raises(ContractReject) as trailing:
        _decode_pxar(bytes(declared_short))
    assert trailing.value.code == S7_CODEC_ERROR_CODES["trailing_bytes"]


def test_expected_store_is_signed_digested_and_checked_before_admission() -> None:
    vector = _build_vectors()["one"]
    envelope = vector["envelope"]["wire"]
    values = _decode_envelope(envelope)
    request_public_key = vector["envelope"]["request_public_key"]

    bit_flipped_fields = [
        (tag, bytes([value[0] ^ 1]) + value[1:] if tag == 32 else value)
        for tag, value in _parse_envelope_fields(envelope)
    ]
    bit_flipped = _encode_envelope_fields(bit_flipped_fields)
    with pytest.raises(SignatureReject):
        _verify_envelope_signatures(
            _decode_envelope(bit_flipped),
            vector["envelope"]["tenure_public_key"],
            request_public_key,
        )
    assert _digest(REQUEST_DIGEST_DOMAIN, [bit_flipped]) != vector["envelope"]["request_digest"]

    wrong_store = bytes.fromhex("45" * 32)
    valid_wrong_store = _resign_envelope_with_store(envelope, wrong_store)
    wrong_values = _decode_envelope(valid_wrong_store)
    _verify_envelope_signatures(
        wrong_values, vector["envelope"]["tenure_public_key"], request_public_key
    )
    with pytest.raises(ContractReject) as mismatch:
        _admit_expected_store(wrong_values, bytes.fromhex(EXPECTED_STORE_HEX))
    assert mismatch.value.code == S7_CODEC_ERROR_CODES["runtime_store_mismatch"]

    _admit_expected_store(values, bytes.fromhex(EXPECTED_STORE_HEX))


def test_expected_store_missing_zero_and_wrong_width_fail_closed() -> None:
    vector = _build_vectors()["one"]
    fields = _parse_envelope_fields(vector["envelope"]["wire"])

    missing = _encode_envelope_fields(fields[:31])
    with pytest.raises(ContractReject) as missing_rejected:
        _decode_envelope(missing)
    assert missing_rejected.value.code == S7_CODEC_ERROR_CODES["missing_field"]
    assert missing_rejected.value.detail_code == 32

    zero = _resign_envelope_with_store(vector["envelope"]["wire"], bytes(32))
    with pytest.raises(ContractReject) as zero_rejected:
        _decode_envelope(zero)
    assert zero_rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_value"]
    assert zero_rejected.value.detail_code == 32

    wrong_width_fields = [(tag, value[:-1] if tag == 32 else value) for tag, value in fields]
    wrong_width = _encode_envelope_fields(wrong_width_fields)
    with pytest.raises(ContractReject) as width_rejected:
        _decode_envelope(wrong_width)
    assert width_rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_length"]
    assert width_rejected.value.detail_code == 32


def test_every_envelope_field_is_authenticated_or_digest_cross_checked() -> None:
    vector = _build_vectors()["one"]["envelope"]
    original_fields = _parse_envelope_fields(vector["wire"])
    for index in range(len(original_fields)):
        fields = copy.deepcopy(original_fields)
        tag, value = fields[index]
        fields[index] = (tag, bytes([value[0] ^ 1]) + value[1:])
        mutated = _encode_envelope_fields(fields)
        try:
            values = _decode_envelope(mutated)
        except ContractReject:
            continue
        with pytest.raises(SignatureReject):
            _verify_envelope_signatures(
                values, vector["tenure_public_key"], vector["request_public_key"]
            )


def test_envelope_tlv_duplicate_order_unknown_and_trailing_rejections_are_stable() -> None:
    fields = _parse_envelope_fields(_build_vectors()["one"]["envelope"]["wire"])
    duplicate = copy.deepcopy(fields)
    duplicate[31] = (31, duplicate[31][1])
    with pytest.raises(ContractReject) as duplicate_rejected:
        _decode_envelope(_encode_envelope_fields(duplicate))
    assert duplicate_rejected.value.code == S7_CODEC_ERROR_CODES["duplicate_field"]
    assert duplicate_rejected.value.detail_code == 31

    out_of_order = copy.deepcopy(fields)
    out_of_order[31] = (33, out_of_order[31][1])
    with pytest.raises(ContractReject) as order_rejected:
        _decode_envelope(_encode_envelope_fields(out_of_order))
    assert order_rejected.value.code == S7_CODEC_ERROR_CODES["out_of_order_field"]
    assert order_rejected.value.detail_code == 33

    unknown = _encode_envelope_fields([*fields, (39, b"\x01")])
    with pytest.raises(ContractReject) as unknown_rejected:
        _decode_envelope(unknown)
    assert unknown_rejected.value.code == S7_CODEC_ERROR_CODES["unknown_field"]
    assert unknown_rejected.value.detail_code == 39

    trailing = _build_vectors()["one"]["envelope"]["wire"] + b"\x00"
    with pytest.raises(ContractReject) as trailing_rejected:
        _decode_envelope(trailing)
    assert trailing_rejected.value.code == S7_CODEC_ERROR_CODES["trailing_bytes"]


def test_envelope_tag_zero_and_declared_width_eof_precedence_is_stable() -> None:
    prefix = ENVELOPE_MAGIC + _u16(ENVELOPE_VERSION) + _u16(ENVELOPE_FIELD_COUNT)
    cases = [
        (
            prefix + _u16(0) + _u32(2) + _u16(1),
            S7_CODEC_ERROR_CODES["unknown_field"],
            0,
        ),
        (
            prefix + _u16(1) + _u32(3),
            S7_CODEC_ERROR_CODES["invalid_field_length"],
            1,
        ),
        (
            prefix + _u16(1) + _u32(2),
            S7_CODEC_ERROR_CODES["truncated"],
            1,
        ),
    ]
    for wire, expected_code, expected_detail in cases:
        with pytest.raises(ContractReject) as rejected:
            _decode_envelope(wire)
        assert rejected.value.code == expected_code
        assert rejected.value.detail_code == expected_detail


@pytest.mark.parametrize(
    ("declared_count", "expected_code", "expected_detail"),
    [
        (
            ENVELOPE_FIELD_COUNT - 1,
            S7_CODEC_ERROR_CODES["missing_field"],
            ENVELOPE_FIELD_COUNT,
        ),
        (
            ENVELOPE_FIELD_COUNT + 1,
            S7_CODEC_ERROR_CODES["unknown_field"],
            ENVELOPE_FIELD_COUNT + 1,
        ),
    ],
)
def test_envelope_declared_count_precedence_is_stable(
    declared_count: int, expected_code: int, expected_detail: int
) -> None:
    header_only = ENVELOPE_MAGIC + _u16(ENVELOPE_VERSION) + _u16(declared_count)
    with pytest.raises(ContractReject) as rejected:
        _decode_envelope(header_only)
    assert rejected.value.code == expected_code
    assert rejected.value.detail_code == expected_detail


@pytest.mark.parametrize(
    ("changes", "expected_code", "expected_detail"),
    [
        ({13: _u16(0)}, S7_CODEC_ERROR_CODES["invalid_field_value"], 13),
        ({14: _u16(0)}, S7_CODEC_ERROR_CODES["invalid_field_value"], 14),
        (
            {17: _u64(0)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            9,
        ),
        ({18: _u64(1)}, S7_CODEC_ERROR_CODES["invalid_field_value"], 17),
        (
            {10: _u64(0)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            9,
        ),
        (
            {15: bytes.fromhex("fe" * 16)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            15,
        ),
        ({26: _u16(2)}, S7_CODEC_ERROR_CODES["invalid_field_value"], 26),
        ({29: _u64(0)}, S7_CODEC_ERROR_CODES["invalid_field_value"], 29),
        ({30: _u64(0)}, S7_CODEC_ERROR_CODES["invalid_field_value"], 26),
        ({31: _u64(101)}, S7_CODEC_ERROR_CODES["invalid_field_value"], 26),
        ({32: bytes(32)}, S7_CODEC_ERROR_CODES["invalid_field_value"], 32),
        ({35: _u16(0)}, S7_CODEC_ERROR_CODES["invalid_field_value"], 35),
        ({36: _u16(0)}, S7_CODEC_ERROR_CODES["invalid_field_value"], 36),
    ],
)
def test_envelope_semantic_fields_fail_closed_after_valid_rehash_and_resign(
    changes: dict[int, bytes], expected_code: int, expected_detail: int | None
) -> None:
    envelope = _build_vectors()["one"]["envelope"]["wire"]
    mutated = _rebuild_envelope_after_field_changes(envelope, changes)
    with pytest.raises(ContractReject) as rejected:
        _decode_envelope(mutated)
    assert rejected.value.code == expected_code
    assert rejected.value.detail_code == expected_detail


@pytest.mark.parametrize(
    ("offset", "declared_length", "expected_code", "expected_detail"),
    [
        (6, MAX_ENVELOPE_BYTES + 1, S7_CODEC_ERROR_CODES["frame_too_large"], 1),
        (10, len(PXTA_ZERO) + 1, S7_CODEC_ERROR_CODES["binding_not_allowed"], 2),
        (14, PXTE_MAX_BYTES + 1, S7_CODEC_ERROR_CODES["frame_too_large"], 3),
    ],
)
def test_pxar_component_length_bombs_fail_before_total_length_arithmetic(
    offset: int,
    declared_length: int,
    expected_code: int,
    expected_detail: int | None,
) -> None:
    outer = bytearray(_build_vectors()["one"]["outer"])
    outer[offset : offset + 4] = _u32(declared_length)
    with pytest.raises(ContractReject) as rejected:
        _decode_pxar(bytes(outer))
    assert rejected.value.code == expected_code
    assert rejected.value.detail_code == expected_detail


def test_pxar_rejects_projection_target_that_differs_from_signed_slice_target() -> None:
    artifact = _build_artifact_vector()
    row = _target_row_wire(bytes.fromhex("06" * 16), artifact["identity"], FIXTURE_ENTRY)
    manifest = _encode_manifest(row)
    projection = _encode_projection(manifest)
    subject = {
        **SUBJECT,
        "config_digest_hex": artifact["empty_config_digest"].hex(),
    }
    pxte = _encode_pxte(
        projection,
        PROFILE_ONE_SOURCE_LOOP,
        copy.deepcopy(DOMAIN),
        subject,
    )
    envelope = _build_envelope(
        _composite_digest(pxte),
        source_revision=3,
        operation_byte="0d",
        temporal_byte="0e",
        auth_nonce=b"test-only-request-nonce-one",
    )["wire"]
    outer = (
        PXAR_MAGIC
        + _u16(PXAR_VERSION)
        + _u32(len(envelope))
        + _u32(len(PXTA_ZERO))
        + _u32(len(pxte))
        + envelope
        + PXTA_ZERO
        + pxte
    )
    with pytest.raises(ContractReject) as mismatch:
        _decode_pxar(outer)
    assert mismatch.value.code == S7_CODEC_ERROR_CODES["target_mismatch"]
    assert mismatch.value.detail_code == 2


def test_pxar_composite_mismatch_reports_signed_assignment_tag() -> None:
    vector = _build_vectors()["one"]
    envelope = _rebuild_envelope_after_field_changes(
        vector["envelope"]["wire"], {7: bytes.fromhex("ed" * 32)}
    )
    outer = (
        PXAR_MAGIC
        + _u16(PXAR_VERSION)
        + _u32(len(envelope))
        + _u32(len(PXTA_ZERO))
        + _u32(len(vector["pxte"]))
        + envelope
        + PXTA_ZERO
        + vector["pxte"]
    )
    with pytest.raises(ContractReject) as rejected:
        _decode_pxar(outer)
    assert rejected.value.code == S7_CODEC_ERROR_CODES["digest_mismatch"]
    assert rejected.value.detail_code == 7


def test_mapping_input_order_cannot_change_fixed_canonical_bytes() -> None:
    compiled = _compiled_compatibility_digest(FIXTURE_ENTRY)
    reversed_descriptor = dict(reversed(list(DESCRIPTOR.items())))
    assert (
        _encode_descriptor(reversed_descriptor, compiled)
        == (_build_artifact_vector()["descriptor"])
    )
    reversed_domain = dict(reversed(list(DOMAIN.items())))
    assert _encode_reference_domain(reversed_domain) == _encode_reference_domain(DOMAIN)


def test_legacy_wire_fixtures_remain_byte_exact() -> None:
    expected = _load_fixture()["legacy_fixture_sha256"]
    wire_dir = REPO_ROOT / "tests" / "fixtures" / "wire"
    for name, digest in expected.items():
        assert hashlib.sha256((wire_dir / name).read_bytes()).hexdigest() == digest


def test_frozen_bounds_domains_and_error_taxonomy_are_exact() -> None:
    fixture = _load_fixture()
    assert fixture["codec_error_codes"] == S7_CODEC_ERROR_CODES
    assert MAX_DESCRIPTOR_BYTES == 367
    assert MANIFEST_BYTES == 266
    assert PROJECTION_BYTES == 298
    assert PXTE_EMPTY_BYTES == 309
    assert PXTE_ONE_SOURCE_LOOP_BYTES == 525
    assert PXAR_HEADER_BYTES + MAX_ENVELOPE_BYTES + len(PXTA_ZERO) + PXTE_MAX_BYTES == 4_649
    assert fixture["protocol"]["auth_signing_domain_v2_hex"] == (AUTH_SIGNING_DOMAIN.hex())
    assert fixture["protocol"]["request_digest_domain_v2_hex"] == (REQUEST_DIGEST_DOMAIN.hex())


FieldWidth = int | tuple[int, int] | str

BOOTSTRAP_REQUEST_SCHEMA: dict[int, FieldWidth] = {
    1: 16,
    2: 16,
    3: 16,
    4: 16,
    5: 16,
    6: 2,
    7: 2,
    8: (1, MAX_CONTROL_NONCE_BYTES),
    9: 4,
    10: "signature",
}
BOOTSTRAP_RESPONSE_SCHEMA: dict[int, FieldWidth] = {
    1: 16,
    2: 32,
    3: (1, MAX_CONTROL_NONCE_BYTES),
    4: 16,
    5: 32,
    6: 8,
    7: 8,
    8: 16,
    9: 8,
    10: 32,
    11: 32,
    12: BUILD_IDENTITY_BYTES,
    13: 32,
    14: 32,
    15: 32,
    16: 2,
    17: 2,
    18: 16,
    19: 32,
    20: 16,
    21: 2,
    22: 2,
    23: "signature",
}
QUERY_REQUEST_SCHEMA: dict[int, FieldWidth] = {
    1: 16,
    2: 16,
    3: 16,
    4: 32,
    5: 16,
    6: 1,
    7: 32,
    8: (1, MAX_CONTROL_NONCE_BYTES),
    9: 4,
    10: 2,
    11: 16,
    12: 16,
    13: 2,
    14: 2,
    15: "signature",
}
QUERY_RESPONSE_SCHEMA: dict[int, FieldWidth] = {
    1: 16,
    2: 32,
    3: (1, MAX_CONTROL_NONCE_BYTES),
    4: 16,
    5: 32,
    6: 8,
    7: 8,
    8: 16,
    9: 8,
    10: 2,
    11: 2,
    12: 2,
    13: 1,
    14: 32,
    15: 2,
    16: 1,
    17: 16,
    18: 2,
    19: 8,
    20: 32,
    21: 32,
    22: 8,
    23: 2,
    24: 8,
    25: 8,
    26: 32,
    27: 16,
    28: 32,
    29: 16,
    30: 2,
    31: 2,
    32: "signature",
}


def _valid_control_width(width: FieldWidth, length: int) -> tuple[bool, int]:
    if width == "signature":
        valid = 1 <= length <= MAX_CONTROL_SIGNATURE_BYTES
        return valid, S7_CODEC_ERROR_CODES["invalid_field_length"]
    if isinstance(width, int):
        return length == width, S7_CODEC_ERROR_CODES["invalid_field_length"]
    return (
        width[0] <= length <= width[1],
        S7_CODEC_ERROR_CODES["invalid_field_length"],
    )


def _encode_control_frame(magic: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    return (
        magic
        + _u16(CONTROL_PROTOCOL_VERSION)
        + _u16(len(fields))
        + b"".join(_tlv(tag, value) for tag, value in fields)
    )


def _parse_control_frame(
    wire: bytes,
    *,
    magic: bytes,
    maximum_bytes: int,
    schema: dict[int, FieldWidth],
) -> dict[int, bytes]:
    if len(wire) > maximum_bytes:
        raise ContractReject(S7_CODEC_ERROR_CODES["frame_too_large"])
    if len(wire) < 8:
        raise ContractReject(S7_CODEC_ERROR_CODES["truncated"])
    if wire[:4] != magic:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_magic"])
    version, count = struct.unpack_from(">HH", wire, 4)
    if version != CONTROL_PROTOCOL_VERSION:
        raise ContractReject(S7_CODEC_ERROR_CODES["unsupported_version"])
    if count < len(schema):
        raise ContractReject(S7_CODEC_ERROR_CODES["missing_field"], detail_code=count + 1)
    if count > len(schema):
        raise ContractReject(S7_CODEC_ERROR_CODES["unknown_field"], detail_code=len(schema) + 1)
    cursor = 8
    fields: list[tuple[int, bytes]] = []
    for index in range(count):
        if cursor + 6 > len(wire):
            raise ContractReject(S7_CODEC_ERROR_CODES["truncated"])
        tag, length = struct.unpack_from(">HI", wire, cursor)
        cursor += 6
        expected_tag = index + 1
        if tag == 0 or tag > len(schema):
            raise ContractReject(S7_CODEC_ERROR_CODES["unknown_field"], detail_code=tag)
        if tag < expected_tag:
            raise ContractReject(S7_CODEC_ERROR_CODES["duplicate_field"], detail_code=tag)
        if tag > expected_tag:
            raise ContractReject(S7_CODEC_ERROR_CODES["out_of_order_field"], detail_code=tag)
        valid, error_code = _valid_control_width(schema[tag], length)
        if not valid:
            raise ContractReject(error_code, detail_code=tag)
        end = cursor + length
        if end > len(wire):
            raise ContractReject(S7_CODEC_ERROR_CODES["truncated"], detail_code=tag)
        fields.append((tag, wire[cursor:end]))
        cursor = end
    if cursor != len(wire):
        raise ContractReject(S7_CODEC_ERROR_CODES["trailing_bytes"])
    if _encode_control_frame(magic, fields) != wire:
        raise ContractReject(S7_CODEC_ERROR_CODES["non_canonical_frame"])
    return dict(fields)


def _signed_control_frame(
    *,
    magic: bytes,
    unsigned: list[tuple[int, bytes]],
    signing_domain: bytes,
    seed_hex: str,
) -> dict[str, bytes]:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    signing_transcript = _signing_transcript(1, signing_domain, unsigned)
    signature = key.sign(signing_transcript)
    wire = _encode_control_frame(magic, [*unsigned, (len(unsigned) + 1, signature)])
    return {
        "wire": wire,
        "signature": signature,
        "signing_transcript": signing_transcript,
        "public_key": key.public_key().public_bytes_raw(),
    }


def _verify_control_signature(
    values: dict[int, bytes],
    *,
    signing_domain: bytes,
    public_key: bytes,
) -> None:
    signature_tag = len(values)
    unsigned = [(tag, values[tag]) for tag in range(1, signature_tag)]
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            values[signature_tag],
            _signing_transcript(1, signing_domain, unsigned),
        )
    except (InvalidSignature, ValueError) as error:
        raise SignatureReject("control-frame authentication failed") from error


def _profile_fingerprint(fixture: dict[str, str]) -> bytes:
    return _digest(
        PROFILE_FINGERPRINT_DOMAIN,
        [
            _u16(PROFILE_VERSION),
            _u16(2),
            _u8(PROFILE_ONE_SOURCE_LOOP),
            _u8(PROFILE_EMPTY_DEACTIVATE),
            _u16(PROFILE_LIFECYCLE_CONCURRENCY),
            _u16(PROFILE_MAILBOX_SLOTS),
            _u16(PROFILE_DISPATCH_SLOTS),
            _u16(PROFILE_BACKGROUND_TASK_SLOTS),
            _u64(MAX_REFERENCE_LIFECYCLE_BUDGET_NANOS),
            _empty_config_digest(),
            _hex(fixture["definition_ref_hex"]),
            _hex(fixture["implementation_ref_hex"]),
            _hex(fixture["export_ref_hex"]),
            _hex(fixture["definition_digest_hex"]),
            _hex(fixture["fixture_artifact_digest_hex"]),
        ],
    )


def _channel_binding_digest(
    *,
    target: bytes,
    runtime_peer: bytes,
    local_endpoint_identity_digest: bytes,
    peer_credentials_digest: bytes,
) -> bytes:
    if any(
        len(value) != expected
        for value, expected in (
            (target, 16),
            (runtime_peer, 16),
            (local_endpoint_identity_digest, 32),
            (peer_credentials_digest, 32),
        )
    ):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_length"])
    return _digest(
        CHANNEL_BINDING_DOMAIN,
        [
            _u16(CHANNEL_BINDING_VERSION),
            target,
            runtime_peer,
            local_endpoint_identity_digest,
            peer_credentials_digest,
        ],
    )


def _channel_binding(
    *,
    target: bytes,
    runtime_peer: bytes,
    local_endpoint_identity_digest: bytes,
    peer_credentials_digest: bytes,
) -> dict[str, bytes]:
    if local_endpoint_identity_digest == bytes(32) or peer_credentials_digest == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["compatibility_mismatch"])
    return {
        "target": target,
        "runtime_peer": runtime_peer,
        "local_endpoint_identity_digest": local_endpoint_identity_digest,
        "peer_credentials_digest": peer_credentials_digest,
        "binding_digest": _channel_binding_digest(
            target=target,
            runtime_peer=runtime_peer,
            local_endpoint_identity_digest=local_endpoint_identity_digest,
            peer_credentials_digest=peer_credentials_digest,
        ),
    }


def _build_bootstrap_request() -> dict[str, bytes]:
    unsigned = [
        (1, bytes.fromhex("d1" * 16)),
        (2, _hex(TARGET_HEX)),
        (3, _hex(ENVELOPE_SEMANTIC["source_scope_hex"])),
        (4, _hex(ENVELOPE_SEMANTIC["auth_principal_hex"])),
        (5, _hex(ENVELOPE_SEMANTIC["auth_key_hex"])),
        (6, _u16(1)),
        (7, _u16(1)),
        (8, b"test-only-bootstrap-nonce"),
        (9, _u32(MAX_BOOTSTRAP_RESPONSE_BYTES)),
    ]
    signed = _signed_control_frame(
        magic=BOOTSTRAP_REQUEST_MAGIC,
        unsigned=unsigned,
        signing_domain=BOOTSTRAP_REQUEST_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
    )
    values = _decode_bootstrap_request(signed["wire"])
    _verify_control_signature(
        values,
        signing_domain=BOOTSTRAP_REQUEST_SIGNING_DOMAIN,
        public_key=signed["public_key"],
    )
    return {
        **signed,
        "digest": _digest(BOOTSTRAP_REQUEST_DIGEST_DOMAIN, [signed["wire"]]),
    }


def _decode_bootstrap_request(wire: bytes) -> dict[int, bytes]:
    values = _parse_control_frame(
        wire,
        magic=BOOTSTRAP_REQUEST_MAGIC,
        maximum_bytes=MAX_BOOTSTRAP_REQUEST_BYTES,
        schema=BOOTSTRAP_REQUEST_SCHEMA,
    )
    algorithm = struct.unpack(">H", values[6])[0]
    algorithm_version = struct.unpack(">H", values[7])[0]
    max_response = struct.unpack(">I", values[9])[0]
    if algorithm == 0:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=6)
    if algorithm_version == 0:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=7)
    if not 0 < max_response <= MAX_BOOTSTRAP_RESPONSE_BYTES:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=9)
    return values


def _decode_bootstrap_response(wire: bytes) -> dict[int, bytes]:
    values = _parse_control_frame(
        wire,
        magic=BOOTSTRAP_RESPONSE_MAGIC,
        maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
        schema=BOOTSTRAP_RESPONSE_SCHEMA,
    )
    if values[2] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=2)
    identity_error = None
    try:
        _decode_identity(values[12])
    except ContractReject as error:
        identity_error = error
    if values[5] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=5)
    for tag in (6, 7, 9):
        if struct.unpack(">Q", values[tag])[0] == 0:
            raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=tag)
    if values[10] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=10)
    if values[10] != values[12][:32]:
        raise ContractReject(S7_CODEC_ERROR_CODES["compatibility_mismatch"], detail_code=10)
    if values[11] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["compatibility_mismatch"], detail_code=11)
    if values[11] != values[12][96:128]:
        raise ContractReject(S7_CODEC_ERROR_CODES["compatibility_mismatch"], detail_code=11)
    if identity_error is not None:
        raise ContractReject(
            S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=12
        ) from identity_error
    for tag in (13, 14, 15):
        if values[tag] == bytes(32):
            raise ContractReject(
                S7_CODEC_ERROR_CODES["compatibility_mismatch"],
                detail_code=tag,
            )
    state = struct.unpack(">H", values[16])[0]
    if state not in BOOTSTRAP_STATES.values():
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=16)
    reason = struct.unpack(">H", values[17])[0]
    if reason not in OPERATIONAL_REASONS.values():
        raise ContractReject(S7_CODEC_ERROR_CODES["unknown_reason"], detail_code=17)
    state_reason_valid = (
        (state == BOOTSTRAP_STATES["ready_for_apply"] and reason == OPERATIONAL_REASONS["none"])
        or (
            state == BOOTSTRAP_STATES["not_ready_recovering"]
            and reason == OPERATIONAL_REASONS["recovering"]
        )
        or (
            state == BOOTSTRAP_STATES["recovery_failed_not_ready"]
            and reason == OPERATIONAL_REASONS["recovery_failed"]
        )
        or (
            state == BOOTSTRAP_STATES["validated_operational_quarantine"]
            and reason
            in {
                OPERATIONAL_REASONS["active_compatibility_mismatch"],
                OPERATIONAL_REASONS["ownership_uncertain"],
                OPERATIONAL_REASONS["history_unavailable"],
                OPERATIONAL_REASONS["resource_census_uncertain"],
                OPERATIONAL_REASONS["ownership_transfer_required"],
            }
        )
        or (
            state == BOOTSTRAP_STATES["not_ready_busy"]
            and reason == OPERATIONAL_REASONS["runtime_busy"]
        )
    )
    if not state_reason_valid:
        raise ContractReject(S7_CODEC_ERROR_CODES["unknown_reason"], detail_code=17)
    if values[19] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=19)
    auth_algorithm = struct.unpack(">H", values[21])[0]
    if auth_algorithm == 0:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=21)
    auth_algorithm_version = struct.unpack(">H", values[22])[0]
    if auth_algorithm_version == 0:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=22)
    return values


def _build_bootstrap_response(
    request: dict[str, bytes],
    artifact: dict[str, bytes],
    channel_binding_digest: bytes,
) -> dict[str, bytes]:
    request_values = _decode_bootstrap_request(request["wire"])
    unsigned = [
        (1, request_values[1]),
        (2, request["digest"]),
        (3, request_values[8]),
        (4, request_values[2]),
        (5, _hex(EXPECTED_STORE_HEX)),
        (6, _u64(7)),
        (7, _u64(3)),
        (8, _hex(ENVELOPE_SEMANTIC["clock_domain_hex"])),
        (9, _u64(3)),
        (10, _hex(DESCRIPTOR["build_instance_id_hex"])),
        (11, artifact["compiled_compatibility_digest"]),
        (12, artifact["identity"]),
        (13, artifact["manifest_digest"]),
        (14, _profile_fingerprint(FIXTURE_ENTRY)),
        (15, EXPECTED_ADMISSION_POLICY_DIGEST),
        (16, _u16(BOOTSTRAP_STATES["ready_for_apply"])),
        (17, _u16(OPERATIONAL_REASONS["none"])),
        (18, bytes.fromhex("e1" * 16)),
        (19, channel_binding_digest),
        (20, bytes.fromhex("e2" * 16)),
        (21, _u16(1)),
        (22, _u16(1)),
    ]
    signed = _signed_control_frame(
        magic=BOOTSTRAP_RESPONSE_MAGIC,
        unsigned=unsigned,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
    )
    if len(signed["wire"]) > struct.unpack(">I", request_values[9])[0]:
        raise ContractReject(S7_CODEC_ERROR_CODES["response_bound_exceeded"])
    values = _decode_bootstrap_response(signed["wire"])
    _verify_control_signature(
        values,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        public_key=signed["public_key"],
    )
    return {
        **signed,
        "digest": _digest(BOOTSTRAP_RESPONSE_DIGEST_DOMAIN, [signed["wire"]]),
    }


def _verify_bootstrap_exchange(
    request: dict[str, bytes],
    response: dict[str, bytes],
    *,
    request_public_key: bytes,
    response_public_key: bytes,
    channel: dict[str, bytes],
    expected_artifact: dict[str, bytes],
    expected_admission_policy_digest: bytes,
) -> None:
    request_values = _decode_bootstrap_request(request["wire"])
    response_values = _decode_bootstrap_response(response["wire"])
    _verify_control_signature(
        request_values,
        signing_domain=BOOTSTRAP_REQUEST_SIGNING_DOMAIN,
        public_key=request_public_key,
    )
    _verify_control_signature(
        response_values,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        public_key=response_public_key,
    )
    expected_echoes = {
        1: request_values[1],
        2: _digest(BOOTSTRAP_REQUEST_DIGEST_DOMAIN, [request["wire"]]),
        3: request_values[8],
    }
    for tag, expected in expected_echoes.items():
        if response_values[tag] != expected:
            raise ContractReject(
                S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
                detail_code=tag,
            )
    if response_values[4] != request_values[2] or channel["target"] != request_values[2]:
        raise ContractReject(S7_CODEC_ERROR_CODES["target_mismatch"], detail_code=4)
    manifest = _decode_manifest(expected_artifact["manifest"])
    row = manifest["row"]
    if row["target"] != request_values[2]:
        raise ContractReject(S7_CODEC_ERROR_CODES["target_mismatch"], detail_code=4)
    expected_compatibility = {
        10: row["identity"]["build_instance_id"],
        11: row["identity"]["compiled_compatibility_digest"],
        12: expected_artifact["identity"],
        13: _manifest_digest(expected_artifact["manifest"]),
        14: _profile_fingerprint(
            {f"{name}_hex": value.hex() for name, value in row["fixture"].items()}
        ),
        15: expected_admission_policy_digest,
    }
    if row["identity"]["wire"] != expected_artifact["identity"]:
        raise ContractReject(S7_CODEC_ERROR_CODES["compatibility_mismatch"], detail_code=12)
    for tag, expected in expected_compatibility.items():
        if response_values[tag] != expected:
            raise ContractReject(
                S7_CODEC_ERROR_CODES["compatibility_mismatch"],
                detail_code=tag,
            )
    if response_values[18] != channel["runtime_peer"]:
        raise ContractReject(S7_CODEC_ERROR_CODES["target_mismatch"], detail_code=18)
    if response_values[19] != channel["binding_digest"]:
        raise ContractReject(S7_CODEC_ERROR_CODES["target_mismatch"], detail_code=19)
    if len(response["wire"]) > struct.unpack(">I", request_values[9])[0]:
        raise ContractReject(S7_CODEC_ERROR_CODES["response_bound_exceeded"])


def _decode_query_request(wire: bytes) -> dict[int, bytes]:
    values = _parse_control_frame(
        wire,
        magic=QUERY_REQUEST_MAGIC,
        maximum_bytes=MAX_QUERY_REQUEST_BYTES,
        schema=QUERY_REQUEST_SCHEMA,
    )
    presence = values[6][0]
    max_response = struct.unpack(">I", values[9])[0]
    max_records = struct.unpack(">H", values[10])[0]
    algorithm = struct.unpack(">H", values[13])[0]
    algorithm_version = struct.unpack(">H", values[14])[0]
    if values[4] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=4)
    valid_presence = presence in {0, 1} and (
        (presence == 0 and values[7] == bytes(32)) or (presence == 1 and values[7] != bytes(32))
    )
    if not valid_presence:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_presence"], detail_code=6)
    if not 0 < max_response <= MAX_QUERY_RESPONSE_BYTES:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=9)
    if max_records != MAX_QUERY_RECORD_COUNT:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=10)
    if algorithm == 0:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=13)
    if algorithm_version == 0:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=14)
    return values


def _build_query_request(apply_request_digest: bytes) -> dict[str, bytes]:
    unsigned = [
        (1, bytes.fromhex("d2" * 16)),
        (2, _hex(TARGET_HEX)),
        (3, _hex(ENVELOPE_SEMANTIC["source_scope_hex"])),
        (4, _hex(EXPECTED_STORE_HEX)),
        (5, bytes.fromhex("0d" * 16)),
        (6, _u8(1)),
        (7, apply_request_digest),
        (8, b"test-only-query-nonce"),
        (9, _u32(MAX_QUERY_RESPONSE_BYTES)),
        (10, _u16(MAX_QUERY_RECORD_COUNT)),
        (11, _hex(ENVELOPE_SEMANTIC["auth_principal_hex"])),
        (12, _hex(ENVELOPE_SEMANTIC["auth_key_hex"])),
        (13, _u16(1)),
        (14, _u16(1)),
    ]
    signed = _signed_control_frame(
        magic=QUERY_REQUEST_MAGIC,
        unsigned=unsigned,
        signing_domain=QUERY_REQUEST_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
    )
    values = _decode_query_request(signed["wire"])
    _verify_control_signature(
        values,
        signing_domain=QUERY_REQUEST_SIGNING_DOMAIN,
        public_key=signed["public_key"],
    )
    return {
        **signed,
        "digest": _digest(QUERY_REQUEST_DIGEST_DOMAIN, [signed["wire"]]),
    }


def _decode_query_response(wire: bytes) -> dict[int, bytes]:
    values = _parse_control_frame(
        wire,
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
    )
    owner_state = struct.unpack(">H", values[10])[0]
    reason = struct.unpack(">H", values[11])[0]
    lookup = struct.unpack(">H", values[12])[0]
    lookup_presence = values[13][0]
    phase = struct.unpack(">H", values[15])[0]
    terminal_presence = values[16][0]
    desired_head = struct.unpack(">H", values[18])[0]
    live_state = struct.unpack(">H", values[23])[0]
    auth_algorithm = struct.unpack(">H", values[30])[0]
    auth_algorithm_version = struct.unpack(">H", values[31])[0]
    if values[2] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=2)
    if values[5] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=5)
    for tag in (6, 7, 9):
        if struct.unpack(">Q", values[tag])[0] == 0:
            raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=tag)
    if owner_state not in OWNER_STATES.values():
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=10)
    if reason not in OPERATIONAL_REASONS.values():
        raise ContractReject(S7_CODEC_ERROR_CODES["unknown_reason"], detail_code=11)
    reason_valid = (
        (owner_state == OWNER_STATES["operational"] and reason == OPERATIONAL_REASONS["none"])
        or (
            owner_state == OWNER_STATES["apply_disabled"]
            and reason
            in {
                OPERATIONAL_REASONS["recovering"],
                OPERATIONAL_REASONS["active_compatibility_mismatch"],
                OPERATIONAL_REASONS["recovery_failed"],
                OPERATIONAL_REASONS["runtime_busy"],
            }
        )
        or (
            owner_state == OWNER_STATES["ownership_uncertain"]
            and reason
            in {
                OPERATIONAL_REASONS["ownership_uncertain"],
                OPERATIONAL_REASONS["history_unavailable"],
                OPERATIONAL_REASONS["resource_census_uncertain"],
                OPERATIONAL_REASONS["ownership_transfer_required"],
            }
        )
    )
    if not reason_valid:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=11)
    if lookup not in LOOKUP_KINDS.values():
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=12)
    if lookup == LOOKUP_KINDS["indeterminate"] and reason == OPERATIONAL_REASONS["none"]:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=11)
    lookup_valid = lookup_presence in {0, 1} and (
        (lookup_presence == 0 and values[14] == bytes(32))
        or (lookup_presence == 1 and values[14] != bytes(32))
    )
    if not lookup_valid:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_presence"], detail_code=13)
    digest_presence_matches_lookup = (
        lookup in {LOOKUP_KINDS["known"], LOOKUP_KINDS["conflict"]} and lookup_presence == 1
    ) or (
        lookup in {LOOKUP_KINDS["unknown"], LOOKUP_KINDS["indeterminate"]} and lookup_presence == 0
    )
    if not digest_presence_matches_lookup:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=13)
    if phase not in DURABLE_PHASES.values():
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=15)
    if (lookup == LOOKUP_KINDS["known"] and phase == DURABLE_PHASES["none"]) or (
        lookup != LOOKUP_KINDS["known"] and phase != DURABLE_PHASES["none"]
    ):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=15)
    terminal_valid = terminal_presence in {0, 1} and (
        (terminal_presence == 0 and values[17] == bytes(16))
        or (terminal_presence == 1 and values[17] != bytes(16))
    )
    if not terminal_valid:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_presence"], detail_code=16)
    terminal_expected = lookup == LOOKUP_KINDS["known"] and phase == DURABLE_PHASES["terminal"]
    if terminal_presence != int(terminal_expected):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=16)
    desired_revision = struct.unpack(">Q", values[19])[0]
    revision_high_water = struct.unpack(">Q", values[22])[0]
    resource_generation = struct.unpack(">Q", values[24])[0]
    if desired_head not in DESIRED_HEAD_KINDS.values():
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=18)
    expected_empty_head = desired_head == DESIRED_HEAD_KINDS["none"]
    if (desired_revision == 0) != expected_empty_head:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=19)
    if (values[20] == bytes(32)) != expected_empty_head:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=20)
    if (values[21] == bytes(32)) != expected_empty_head:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=21)
    if revision_high_water < desired_revision:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=22)
    if live_state not in LIVE_STATES.values():
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=23)
    desired_live_valid = (
        (
            live_state
            in {
                LIVE_STATES["live_ready"],
                LIVE_STATES["recovering"],
                LIVE_STATES["recovery_failed_not_ready"],
            }
            and desired_head == DESIRED_HEAD_KINDS["one_source_loop"]
        )
        or (
            live_state == LIVE_STATES["draining"]
            and desired_head == DESIRED_HEAD_KINDS["empty_deactivate"]
        )
        or (
            live_state == LIVE_STATES["exact_zero"]
            and desired_head
            in {
                DESIRED_HEAD_KINDS["none"],
                DESIRED_HEAD_KINDS["empty_deactivate"],
            }
        )
        or live_state
        in {
            LIVE_STATES["not_ready"],
            LIVE_STATES["validated_operational_quarantine"],
            LIVE_STATES["uncertain"],
        }
    )
    if not desired_live_valid:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=23)
    operation_live_valid = (
        (
            owner_state == OWNER_STATES["operational"]
            and live_state
            in {
                LIVE_STATES["not_ready"],
                LIVE_STATES["live_ready"],
                LIVE_STATES["exact_zero"],
            }
        )
        or (
            owner_state == OWNER_STATES["apply_disabled"]
            and (
                (
                    reason == OPERATIONAL_REASONS["recovering"]
                    and live_state == LIVE_STATES["recovering"]
                )
                or (
                    reason == OPERATIONAL_REASONS["active_compatibility_mismatch"]
                    and live_state == LIVE_STATES["validated_operational_quarantine"]
                )
                or (
                    reason == OPERATIONAL_REASONS["recovery_failed"]
                    and live_state == LIVE_STATES["recovery_failed_not_ready"]
                )
                or (
                    reason == OPERATIONAL_REASONS["runtime_busy"]
                    and live_state
                    in {
                        LIVE_STATES["not_ready"],
                        LIVE_STATES["live_ready"],
                        LIVE_STATES["draining"],
                        LIVE_STATES["recovery_failed_not_ready"],
                        LIVE_STATES["exact_zero"],
                    }
                )
            )
        )
        or (
            owner_state == OWNER_STATES["ownership_uncertain"]
            and live_state
            in {
                LIVE_STATES["validated_operational_quarantine"],
                LIVE_STATES["uncertain"],
            }
        )
    )
    if not operation_live_valid:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=23)
    resource_generation_valid = (
        (
            live_state in {LIVE_STATES["live_ready"], LIVE_STATES["draining"]}
            and resource_generation > 0
        )
        or (
            live_state
            in {
                LIVE_STATES["not_ready"],
                LIVE_STATES["recovery_failed_not_ready"],
                LIVE_STATES["exact_zero"],
                LIVE_STATES["validated_operational_quarantine"],
            }
            and resource_generation == 0
        )
        or live_state in {LIVE_STATES["recovering"], LIVE_STATES["uncertain"]}
    )
    if not resource_generation_valid:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=24)
    if values[26] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=26)
    if values[28] == bytes(32):
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=28)
    if auth_algorithm == 0:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=30)
    if auth_algorithm_version == 0:
        raise ContractReject(S7_CODEC_ERROR_CODES["invalid_field_value"], detail_code=31)
    return values


def _build_query_response(
    request: dict[str, bytes],
    *,
    target_slice_digest: bytes,
    manifest_digest: bytes,
    channel_binding_digest: bytes,
) -> dict[str, bytes]:
    request_values = _decode_query_request(request["wire"])
    unsigned = [
        (1, request_values[1]),
        (2, request["digest"]),
        (3, request_values[8]),
        (4, request_values[2]),
        (5, request_values[4]),
        (6, _u64(9)),
        (7, _u64(3)),
        (8, _hex(ENVELOPE_SEMANTIC["clock_domain_hex"])),
        (9, _u64(3)),
        (10, _u16(OWNER_STATES["operational"])),
        (11, _u16(OPERATIONAL_REASONS["none"])),
        (12, _u16(LOOKUP_KINDS["known"])),
        (13, _u8(1)),
        (14, request_values[7]),
        (15, _u16(DURABLE_PHASES["terminal"])),
        (16, _u8(1)),
        (17, bytes.fromhex("d3" * 16)),
        (18, _u16(DESIRED_HEAD_KINDS["one_source_loop"])),
        (19, _u64(3)),
        (20, target_slice_digest),
        (21, manifest_digest),
        (22, _u64(4)),
        (23, _u16(LIVE_STATES["live_ready"])),
        (24, _u64(1)),
        (25, _u64(100)),
        (26, bytes.fromhex("d4" * 32)),
        (27, bytes.fromhex("e1" * 16)),
        (28, channel_binding_digest),
        (29, bytes.fromhex("e2" * 16)),
        (30, _u16(1)),
        (31, _u16(1)),
    ]
    signed = _signed_control_frame(
        magic=QUERY_RESPONSE_MAGIC,
        unsigned=unsigned,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
    )
    if len(signed["wire"]) > struct.unpack(">I", request_values[9])[0]:
        raise ContractReject(S7_CODEC_ERROR_CODES["response_bound_exceeded"])
    values = _decode_query_response(signed["wire"])
    _verify_control_signature(
        values,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        public_key=signed["public_key"],
    )
    return {
        **signed,
        "digest": _digest(QUERY_RESPONSE_DIGEST_DOMAIN, [signed["wire"]]),
    }


def _verify_query_exchange(
    request: dict[str, bytes],
    response: dict[str, bytes],
    *,
    request_public_key: bytes,
    response_public_key: bytes,
    channel: dict[str, bytes],
    serving_baseline: dict[str, Any],
) -> None:
    request_values = _decode_query_request(request["wire"])
    response_values = _decode_query_response(response["wire"])
    _verify_control_signature(
        request_values,
        signing_domain=QUERY_REQUEST_SIGNING_DOMAIN,
        public_key=request_public_key,
    )
    _verify_control_signature(
        response_values,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        public_key=response_public_key,
    )
    expected_echoes = {
        1: request_values[1],
        2: _digest(QUERY_REQUEST_DIGEST_DOMAIN, [request["wire"]]),
        3: request_values[8],
    }
    for tag, expected in expected_echoes.items():
        if response_values[tag] != expected:
            raise ContractReject(
                S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
                detail_code=tag,
            )
    if (
        response_values[4] != request_values[2]
        or channel["target"] != request_values[2]
        or response_values[4] != serving_baseline["target"]
    ):
        raise ContractReject(S7_CODEC_ERROR_CODES["target_mismatch"], detail_code=4)
    if response_values[5] != request_values[4] or response_values[5] != serving_baseline["store"]:
        raise ContractReject(S7_CODEC_ERROR_CODES["target_mismatch"], detail_code=5)
    snapshot_sequence = struct.unpack(">Q", response_values[6])[0]
    host_epoch = struct.unpack(">Q", response_values[7])[0]
    clock_generation = struct.unpack(">Q", response_values[9])[0]
    if snapshot_sequence < serving_baseline["snapshot_sequence"]:
        raise ContractReject(S7_CODEC_ERROR_CODES["cross_reference_mismatch"], detail_code=6)
    if host_epoch < serving_baseline["host_epoch"]:
        raise ContractReject(S7_CODEC_ERROR_CODES["cross_reference_mismatch"], detail_code=7)
    if response_values[8] != serving_baseline["clock_domain"]:
        raise ContractReject(S7_CODEC_ERROR_CODES["target_mismatch"], detail_code=8)
    if host_epoch == serving_baseline["host_epoch"]:
        if clock_generation != serving_baseline["clock_generation"]:
            raise ContractReject(
                S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
                detail_code=9,
            )
    else:
        if snapshot_sequence <= serving_baseline["snapshot_sequence"]:
            raise ContractReject(
                S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
                detail_code=6,
            )
        if clock_generation <= serving_baseline["clock_generation"]:
            raise ContractReject(
                S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
                detail_code=9,
            )
    expected_presence = request_values[6][0]
    lookup_kind = struct.unpack(">H", response_values[12])[0]
    if expected_presence == 0 and lookup_kind == LOOKUP_KINDS["conflict"]:
        raise ContractReject(
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            detail_code=12,
        )
    if expected_presence == 1 and (
        (lookup_kind == LOOKUP_KINDS["known"] and response_values[14] != request_values[7])
        or (lookup_kind == LOOKUP_KINDS["conflict"] and response_values[14] == request_values[7])
    ):
        raise ContractReject(
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            detail_code=14,
        )
    if response_values[27] != channel["runtime_peer"]:
        raise ContractReject(S7_CODEC_ERROR_CODES["target_mismatch"], detail_code=27)
    if response_values[28] != channel["binding_digest"]:
        raise ContractReject(S7_CODEC_ERROR_CODES["target_mismatch"], detail_code=28)
    if len(response["wire"]) > struct.unpack(">I", request_values[9])[0]:
        raise ContractReject(S7_CODEC_ERROR_CODES["response_bound_exceeded"])


def _build_control_vectors(vectors: dict[str, Any]) -> dict[str, Any]:
    channel = _channel_binding(
        target=_hex(TARGET_HEX),
        runtime_peer=bytes.fromhex("e1" * 16),
        local_endpoint_identity_digest=bytes.fromhex("e3" * 32),
        peer_credentials_digest=bytes.fromhex("e4" * 32),
    )
    channel_binding = channel["binding_digest"]
    bootstrap_request = _build_bootstrap_request()
    bootstrap_response = _build_bootstrap_response(
        bootstrap_request, vectors["artifact"], channel_binding
    )
    bootstrap_response_values = _decode_bootstrap_response(bootstrap_response["wire"])
    query_serving_baseline = {
        "target": bootstrap_response_values[4],
        "store": bootstrap_response_values[5],
        "snapshot_sequence": struct.unpack(">Q", bootstrap_response_values[6])[0],
        "host_epoch": struct.unpack(">Q", bootstrap_response_values[7])[0],
        "clock_domain": bootstrap_response_values[8],
        "clock_generation": struct.unpack(">Q", bootstrap_response_values[9])[0],
    }
    _verify_bootstrap_exchange(
        bootstrap_request,
        bootstrap_response,
        request_public_key=bootstrap_request["public_key"],
        response_public_key=bootstrap_response["public_key"],
        channel=channel,
        expected_artifact=vectors["artifact"],
        expected_admission_policy_digest=EXPECTED_ADMISSION_POLICY_DIGEST,
    )
    query_request = _build_query_request(vectors["one"]["envelope"]["request_digest"])
    query_response = _build_query_response(
        query_request,
        target_slice_digest=vectors["one"]["envelope"]["target_slice_digest"],
        manifest_digest=vectors["artifact"]["manifest_digest"],
        channel_binding_digest=channel_binding,
    )
    _verify_query_exchange(
        query_request,
        query_response,
        request_public_key=query_request["public_key"],
        response_public_key=query_response["public_key"],
        channel=channel,
        serving_baseline=query_serving_baseline,
    )
    return {
        "channel": channel,
        "query_serving_baseline": query_serving_baseline,
        "channel_binding_digest": channel_binding,
        "profile_fingerprint": _profile_fingerprint(FIXTURE_ENTRY),
        "bootstrap_request": bootstrap_request,
        "bootstrap_response": bootstrap_response,
        "query_request": query_request,
        "query_response": query_response,
    }


def _control_expected(vector: dict[str, bytes]) -> dict[str, Any]:
    return {
        "wire_hex": vector["wire"].hex(),
        "wire_length": len(vector["wire"]),
        "signature_hex": vector["signature"].hex(),
        "signing_transcript_hex": vector["signing_transcript"].hex(),
        "public_key_hex": vector["public_key"].hex(),
        "digest_hex": vector["digest"].hex(),
    }


def _resign_control_fields(
    *,
    magic: bytes,
    fields: list[tuple[int, bytes]],
    signing_domain: bytes,
    seed_hex: str,
) -> bytes:
    unsigned = fields[:-1]
    return _signed_control_frame(
        magic=magic,
        unsigned=unsigned,
        signing_domain=signing_domain,
        seed_hex=seed_hex,
    )["wire"]


def _resigned_control_changes(
    vector: dict[str, bytes],
    *,
    magic: bytes,
    maximum_bytes: int,
    schema: dict[int, FieldWidth],
    signing_domain: bytes,
    seed_hex: str,
    changes: dict[int, bytes],
) -> bytes:
    fields = list(
        _parse_control_frame(
            vector["wire"],
            magic=magic,
            maximum_bytes=maximum_bytes,
            schema=schema,
        ).items()
    )
    return _resign_control_fields(
        magic=magic,
        fields=[(tag, changes.get(tag, value)) for tag, value in fields],
        signing_domain=signing_domain,
        seed_hex=seed_hex,
    )


def _assert_contract_rejection(
    decoder: Any,
    wire: bytes,
    expected_code: int,
    expected_detail: int | None,
) -> None:
    with pytest.raises(ContractReject) as rejected:
        decoder(wire)
    assert rejected.value.code == expected_code
    assert rejected.value.detail_code == expected_detail


def _golden_tlv_header_offsets(wire: bytes, header_length: int) -> list[int]:
    count = struct.unpack_from(">H", wire, header_length - 2)[0]
    cursor = header_length
    offsets: list[int] = []
    for _ in range(count):
        offsets.append(cursor)
        length = struct.unpack_from(">I", wire, cursor + 2)[0]
        cursor += 6 + length
    assert cursor == len(wire)
    return offsets


def _random_bytes(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(length))


def _mutate_property_wire(
    golden: bytes,
    *,
    rng: random.Random,
    case: int,
    maximum_bytes: int,
    family: str,
    tlv_header_length: int | None,
) -> bytes:
    mode = case % 10
    if mode == 0:
        mutated = bytearray(golden)
        offset = rng.randrange(len(mutated))
        mutated[offset] ^= 1 << rng.randrange(8)
        return bytes(mutated)
    if mode == 1:
        return golden[: rng.randrange(len(golden))]
    if mode == 2:
        return golden + _random_bytes(rng, rng.randrange(1, 17))
    if mode == 3:
        return golden + bytes(maximum_bytes + 1 - len(golden))
    if mode == 4:
        mutated = bytearray(golden)
        offset = rng.randrange(min(8, len(mutated)))
        mutated[offset] ^= rng.randrange(1, 256)
        return bytes(mutated)
    if mode == 5:
        mutated = bytearray(golden)
        offset = rng.randrange(len(mutated) - 1)
        mutated[offset : offset + 2] = _u16(rng.randrange(65_536))
        return bytes(mutated)
    if mode == 6:
        mutated = bytearray(golden)
        offset = rng.randrange(len(mutated) - 3)
        mutated[offset : offset + 4] = _u32(rng.randrange(4_294_967_296))
        return bytes(mutated)
    if tlv_header_length is not None and mode in {7, 8}:
        offsets = _golden_tlv_header_offsets(golden, tlv_header_length)
        offset = offsets[rng.randrange(len(offsets))]
        mutated = bytearray(golden)
        if mode == 7:
            mutated[offset : offset + 2] = _u16(rng.randrange(65_536))
        else:
            mutated[offset + 2 : offset + 6] = _u32(
                rng.choice(
                    [
                        0,
                        1,
                        len(golden),
                        maximum_bytes,
                        4_294_967_295,
                    ]
                )
            )
        return bytes(mutated)
    mutated = bytearray(golden)
    if family == "descriptor":
        mutated[78:80] = _u16(rng.randrange(65_536))
    elif family == "identity":
        block = rng.randrange(4)
        mutated[block * 32 : (block + 1) * 32] = bytes(32)
    elif family in {"manifest", "projection"}:
        mutated[4:6] = _u16(rng.randrange(2, 65_536))
    elif family == "pxte":
        mutated[rng.choice([304, 305, 306, 307])] ^= 0xFF
    elif family == "pxar":
        offset = rng.choice([6, 10, 14])
        mutated[offset : offset + 4] = _u32(rng.randrange(4_294_967_296))
    else:
        mutated[rng.randrange(len(mutated))] ^= 0xA5
    return bytes(mutated)


def test_fixed_seed_randomized_malformed_corpus_is_bounded_and_fail_closed() -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)
    families: list[
        tuple[
            str,
            bytes,
            Any,
            int,
            int | None,
            Any,
        ]
    ] = [
        (
            "descriptor",
            vectors["artifact"]["descriptor"],
            _decode_descriptor,
            MAX_DESCRIPTOR_BYTES,
            None,
            lambda parsed: parsed["wire"],
        ),
        (
            "identity",
            vectors["artifact"]["identity"],
            _decode_identity,
            BUILD_IDENTITY_BYTES,
            None,
            lambda parsed: parsed["wire"],
        ),
        (
            "manifest",
            vectors["artifact"]["manifest"],
            _decode_manifest,
            MANIFEST_BYTES,
            None,
            lambda parsed: parsed["wire"],
        ),
        (
            "projection",
            vectors["artifact"]["projection"],
            _decode_projection,
            PROJECTION_BYTES,
            None,
            lambda parsed: parsed["wire"],
        ),
        (
            "pxte",
            vectors["one"]["pxte"],
            _decode_pxte,
            PXTE_MAX_BYTES,
            None,
            lambda parsed: parsed["wire"],
        ),
        (
            "pxar",
            vectors["one"]["outer"],
            _decode_pxar,
            PXAR_HEADER_BYTES + MAX_ENVELOPE_BYTES + len(PXTA_ZERO) + PXTE_MAX_BYTES,
            None,
            lambda parsed: parsed["wire"],
        ),
        (
            "envelope",
            vectors["one"]["envelope"]["wire"],
            _decode_envelope,
            MAX_ENVELOPE_BYTES,
            len(ENVELOPE_MAGIC) + 4,
            lambda parsed: _encode_envelope_fields(list(parsed.items())),
        ),
    ]
    control_configs = [
        (
            "bootstrap_request",
            BOOTSTRAP_REQUEST_MAGIC,
            MAX_BOOTSTRAP_REQUEST_BYTES,
            BOOTSTRAP_REQUEST_SCHEMA,
            _decode_bootstrap_request,
        ),
        (
            "bootstrap_response",
            BOOTSTRAP_RESPONSE_MAGIC,
            MAX_BOOTSTRAP_RESPONSE_BYTES,
            BOOTSTRAP_RESPONSE_SCHEMA,
            _decode_bootstrap_response,
        ),
        (
            "query_request",
            QUERY_REQUEST_MAGIC,
            MAX_QUERY_REQUEST_BYTES,
            QUERY_REQUEST_SCHEMA,
            _decode_query_request,
        ),
        (
            "query_response",
            QUERY_RESPONSE_MAGIC,
            MAX_QUERY_RESPONSE_BYTES,
            QUERY_RESPONSE_SCHEMA,
            _decode_query_response,
        ),
    ]
    for name, magic, maximum, _schema, decoder in control_configs:
        families.append(
            (
                name,
                controls[name]["wire"],
                decoder,
                maximum,
                8,
                lambda parsed, control_magic=magic: _encode_control_frame(
                    control_magic, list(parsed.items())
                ),
            )
        )

    for family_index, (
        family,
        golden,
        decoder,
        maximum,
        tlv_header_length,
        canonical_wire,
    ) in enumerate(families):
        rng = random.Random(0x5_7B_2026 + family_index)
        for case in range(224):
            mutated = _mutate_property_wire(
                golden,
                rng=rng,
                case=case,
                maximum_bytes=maximum,
                family=family,
                tlv_header_length=tlv_header_length,
            )
            try:
                parsed = decoder(mutated)
            except ContractReject:
                continue
            assert len(mutated) <= maximum
            assert canonical_wire(parsed) == mutated


def test_bootstrap_and_query_vectors_round_trip_and_match_fixture() -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)
    expected = _load_fixture()["expected"]
    for name in (
        "bootstrap_request",
        "bootstrap_response",
        "query_request",
        "query_response",
    ):
        assert _control_expected(controls[name]) == expected[name]
    assert controls["channel_binding_digest"].hex() == expected["channel_binding_digest_hex"]
    assert controls["profile_fingerprint"].hex() == expected["profile_fingerprint_hex"]


@pytest.mark.parametrize(
    ("request_name", "changes", "expected_code", "expected_detail"),
    [
        (
            "bootstrap_request",
            {6: _u16(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            6,
        ),
        (
            "bootstrap_request",
            {7: _u16(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            7,
        ),
        (
            "bootstrap_request",
            {8: b""},
            S7_CODEC_ERROR_CODES["invalid_field_length"],
            8,
        ),
        (
            "bootstrap_request",
            {9: _u32(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            9,
        ),
        (
            "query_request",
            {4: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            4,
        ),
        (
            "query_request",
            {6: _u8(0)},
            S7_CODEC_ERROR_CODES["invalid_presence"],
            6,
        ),
        (
            "query_request",
            {8: b""},
            S7_CODEC_ERROR_CODES["invalid_field_length"],
            8,
        ),
        (
            "query_request",
            {9: _u32(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            9,
        ),
        (
            "query_request",
            {10: _u16(2)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            10,
        ),
        (
            "query_request",
            {13: _u16(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            13,
        ),
        (
            "query_request",
            {14: _u16(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            14,
        ),
    ],
)
def test_control_request_direct_field_detail_parity(
    request_name: str,
    changes: dict[int, bytes],
    expected_code: int,
    expected_detail: int,
) -> None:
    controls = _build_control_vectors(_build_vectors())
    config = {
        "bootstrap_request": (
            BOOTSTRAP_REQUEST_MAGIC,
            MAX_BOOTSTRAP_REQUEST_BYTES,
            BOOTSTRAP_REQUEST_SCHEMA,
            BOOTSTRAP_REQUEST_SIGNING_DOMAIN,
            _decode_bootstrap_request,
        ),
        "query_request": (
            QUERY_REQUEST_MAGIC,
            MAX_QUERY_REQUEST_BYTES,
            QUERY_REQUEST_SCHEMA,
            QUERY_REQUEST_SIGNING_DOMAIN,
            _decode_query_request,
        ),
    }
    magic, maximum_bytes, schema, signing_domain, decoder = config[request_name]
    wire = _resigned_control_changes(
        controls[request_name],
        magic=magic,
        maximum_bytes=maximum_bytes,
        schema=schema,
        signing_domain=signing_domain,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
        changes=changes,
    )
    _assert_contract_rejection(decoder, wire, expected_code, expected_detail)


@pytest.mark.parametrize(
    ("response_name", "changes", "expected_code", "expected_detail"),
    [
        (
            "bootstrap_response",
            {2: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            2,
        ),
        (
            "bootstrap_response",
            {5: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            5,
        ),
        (
            "bootstrap_response",
            {6: _u64(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            6,
        ),
        (
            "bootstrap_response",
            {7: _u64(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            7,
        ),
        (
            "bootstrap_response",
            {9: _u64(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            9,
        ),
        (
            "bootstrap_response",
            {10: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            10,
        ),
        (
            "bootstrap_response",
            {10: bytes.fromhex("f0" * 32)},
            S7_CODEC_ERROR_CODES["compatibility_mismatch"],
            10,
        ),
        (
            "bootstrap_response",
            {11: bytes.fromhex("f1" * 32)},
            S7_CODEC_ERROR_CODES["compatibility_mismatch"],
            11,
        ),
        (
            "bootstrap_response",
            {12: bytes(BUILD_IDENTITY_BYTES)},
            S7_CODEC_ERROR_CODES["compatibility_mismatch"],
            10,
        ),
        (
            "bootstrap_response",
            {13: bytes(32)},
            S7_CODEC_ERROR_CODES["compatibility_mismatch"],
            13,
        ),
        (
            "bootstrap_response",
            {14: bytes(32)},
            S7_CODEC_ERROR_CODES["compatibility_mismatch"],
            14,
        ),
        (
            "bootstrap_response",
            {15: bytes(32)},
            S7_CODEC_ERROR_CODES["compatibility_mismatch"],
            15,
        ),
        (
            "bootstrap_response",
            {16: _u16(99)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            16,
        ),
        (
            "bootstrap_response",
            {17: _u16(99)},
            S7_CODEC_ERROR_CODES["unknown_reason"],
            17,
        ),
        (
            "bootstrap_response",
            {19: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            19,
        ),
        (
            "bootstrap_response",
            {21: _u16(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            21,
        ),
        (
            "bootstrap_response",
            {22: _u16(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            22,
        ),
        (
            "query_response",
            {2: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            2,
        ),
        (
            "query_response",
            {5: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            5,
        ),
        (
            "query_response",
            {6: _u64(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            6,
        ),
        (
            "query_response",
            {7: _u64(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            7,
        ),
        (
            "query_response",
            {9: _u64(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            9,
        ),
        (
            "query_response",
            {10: _u16(99)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            10,
        ),
        (
            "query_response",
            {11: _u16(99)},
            S7_CODEC_ERROR_CODES["unknown_reason"],
            11,
        ),
        (
            "query_response",
            {12: _u16(99)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            12,
        ),
        (
            "query_response",
            {13: _u8(0)},
            S7_CODEC_ERROR_CODES["invalid_presence"],
            13,
        ),
        (
            "query_response",
            {15: _u16(99)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            15,
        ),
        (
            "query_response",
            {16: _u8(0)},
            S7_CODEC_ERROR_CODES["invalid_presence"],
            16,
        ),
        (
            "query_response",
            {18: _u16(99)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            18,
        ),
        (
            "query_response",
            {19: _u64(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            19,
        ),
        (
            "query_response",
            {20: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            20,
        ),
        (
            "query_response",
            {21: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            21,
        ),
        (
            "query_response",
            {22: _u64(2)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            22,
        ),
        (
            "query_response",
            {23: _u16(99)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            23,
        ),
        (
            "query_response",
            {24: _u64(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            24,
        ),
        (
            "query_response",
            {26: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            26,
        ),
        (
            "query_response",
            {28: bytes(32)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            28,
        ),
        (
            "query_response",
            {30: _u16(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            30,
        ),
        (
            "query_response",
            {31: _u16(0)},
            S7_CODEC_ERROR_CODES["invalid_field_value"],
            31,
        ),
    ],
)
def test_control_response_direct_field_detail_parity(
    response_name: str,
    changes: dict[int, bytes],
    expected_code: int,
    expected_detail: int,
) -> None:
    controls = _build_control_vectors(_build_vectors())
    config = {
        "bootstrap_response": (
            BOOTSTRAP_RESPONSE_MAGIC,
            MAX_BOOTSTRAP_RESPONSE_BYTES,
            BOOTSTRAP_RESPONSE_SCHEMA,
            BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
            _decode_bootstrap_response,
        ),
        "query_response": (
            QUERY_RESPONSE_MAGIC,
            MAX_QUERY_RESPONSE_BYTES,
            QUERY_RESPONSE_SCHEMA,
            QUERY_RESPONSE_SIGNING_DOMAIN,
            _decode_query_response,
        ),
    }
    magic, maximum_bytes, schema, signing_domain, decoder = config[response_name]
    wire = _resigned_control_changes(
        controls[response_name],
        magic=magic,
        maximum_bytes=maximum_bytes,
        schema=schema,
        signing_domain=signing_domain,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes=changes,
    )
    _assert_contract_rejection(decoder, wire, expected_code, expected_detail)


def test_bootstrap_response_invalid_later_identity_component_reports_field_12() -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)
    invalid_identity = bytearray(vectors["artifact"]["identity"])
    invalid_identity[32:64] = bytes(32)
    wire = _resigned_control_changes(
        controls["bootstrap_response"],
        magic=BOOTSTRAP_RESPONSE_MAGIC,
        maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
        schema=BOOTSTRAP_RESPONSE_SCHEMA,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={12: bytes(invalid_identity)},
    )
    _assert_contract_rejection(
        _decode_bootstrap_response,
        wire,
        S7_CODEC_ERROR_CODES["invalid_field_value"],
        12,
    )


def test_every_bootstrap_and_query_field_is_covered_by_auth_transcript() -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)
    cases = [
        (
            controls["bootstrap_request"],
            BOOTSTRAP_REQUEST_MAGIC,
            BOOTSTRAP_REQUEST_SIGNING_DOMAIN,
            BOOTSTRAP_REQUEST_DIGEST_DOMAIN,
            TEST_ONLY_KEYS["controller_read_seed_hex"],
            _decode_bootstrap_request,
        ),
        (
            controls["bootstrap_response"],
            BOOTSTRAP_RESPONSE_MAGIC,
            BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
            BOOTSTRAP_RESPONSE_DIGEST_DOMAIN,
            TEST_ONLY_KEYS["runtime_read_seed_hex"],
            _decode_bootstrap_response,
        ),
        (
            controls["query_request"],
            QUERY_REQUEST_MAGIC,
            QUERY_REQUEST_SIGNING_DOMAIN,
            QUERY_REQUEST_DIGEST_DOMAIN,
            TEST_ONLY_KEYS["controller_read_seed_hex"],
            _decode_query_request,
        ),
        (
            controls["query_response"],
            QUERY_RESPONSE_MAGIC,
            QUERY_RESPONSE_SIGNING_DOMAIN,
            QUERY_RESPONSE_DIGEST_DOMAIN,
            TEST_ONLY_KEYS["runtime_read_seed_hex"],
            _decode_query_response,
        ),
    ]
    for vector, magic, signing_domain, digest_domain, _seed, decoder in cases:
        original = vector["wire"]
        public_key = vector["public_key"]
        fields = list(
            _parse_control_frame(
                original,
                magic=magic,
                maximum_bytes=2_048,
                schema={
                    BOOTSTRAP_REQUEST_MAGIC: BOOTSTRAP_REQUEST_SCHEMA,
                    BOOTSTRAP_RESPONSE_MAGIC: BOOTSTRAP_RESPONSE_SCHEMA,
                    QUERY_REQUEST_MAGIC: QUERY_REQUEST_SCHEMA,
                    QUERY_RESPONSE_MAGIC: QUERY_RESPONSE_SCHEMA,
                }[magic],
            ).items()
        )
        for field_index in range(len(fields) - 1):
            mutated_fields = copy.deepcopy(fields)
            tag, value = mutated_fields[field_index]
            mutated_fields[field_index] = (
                tag,
                bytes([value[0] ^ 1]) + value[1:],
            )
            mutated = _encode_control_frame(magic, mutated_fields)
            assert _digest(digest_domain, [mutated]) != vector["digest"]
            try:
                values = decoder(mutated)
            except ContractReject:
                continue
            with pytest.raises(SignatureReject):
                _verify_control_signature(
                    values,
                    signing_domain=signing_domain,
                    public_key=public_key,
                )


def test_control_frames_reject_presence_reason_and_response_bound_violations() -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)

    query_fields = list(
        _parse_control_frame(
            controls["query_request"]["wire"],
            magic=QUERY_REQUEST_MAGIC,
            maximum_bytes=MAX_QUERY_REQUEST_BYTES,
            schema=QUERY_REQUEST_SCHEMA,
        ).items()
    )
    query_fields[5] = (6, b"\x00")
    invalid_presence = _resign_control_fields(
        magic=QUERY_REQUEST_MAGIC,
        fields=query_fields,
        signing_domain=QUERY_REQUEST_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
    )
    with pytest.raises(ContractReject) as presence:
        _decode_query_request(invalid_presence)
    assert presence.value.code == S7_CODEC_ERROR_CODES["invalid_presence"]
    assert presence.value.detail_code == 6

    response_fields = list(
        _parse_control_frame(
            controls["query_response"]["wire"],
            magic=QUERY_RESPONSE_MAGIC,
            maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
            schema=QUERY_RESPONSE_SCHEMA,
        ).items()
    )
    response_fields[10] = (11, _u16(9))
    unknown_reason = _resign_control_fields(
        magic=QUERY_RESPONSE_MAGIC,
        fields=response_fields,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
    )
    with pytest.raises(ContractReject) as reason:
        _decode_query_response(unknown_reason)
    assert reason.value.code == S7_CODEC_ERROR_CODES["unknown_reason"]
    assert reason.value.detail_code == 11

    bootstrap_fields = list(
        _parse_control_frame(
            controls["bootstrap_request"]["wire"],
            magic=BOOTSTRAP_REQUEST_MAGIC,
            maximum_bytes=MAX_BOOTSTRAP_REQUEST_BYTES,
            schema=BOOTSTRAP_REQUEST_SCHEMA,
        ).items()
    )
    bootstrap_fields[8] = (9, _u32(1))
    tiny_bound_wire = _resign_control_fields(
        magic=BOOTSTRAP_REQUEST_MAGIC,
        fields=bootstrap_fields,
        signing_domain=BOOTSTRAP_REQUEST_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
    )
    tiny_bound_request = {
        "wire": tiny_bound_wire,
        "digest": _digest(BOOTSTRAP_REQUEST_DIGEST_DOMAIN, [tiny_bound_wire]),
    }
    channel_binding = controls["channel_binding_digest"]
    with pytest.raises(ContractReject) as bound:
        _build_bootstrap_response(tiny_bound_request, vectors["artifact"], channel_binding)
    assert bound.value.code == S7_CODEC_ERROR_CODES["response_bound_exceeded"]
    assert bound.value.detail_code is None


@pytest.mark.parametrize("protocol", ["bootstrap", "query"])
def test_exchange_consumers_enforce_signed_response_bounds(protocol: str) -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)
    if protocol == "bootstrap":
        request_name = "bootstrap_request"
        response_name = "bootstrap_response"
        request_magic = BOOTSTRAP_REQUEST_MAGIC
        request_schema = BOOTSTRAP_REQUEST_SCHEMA
        request_maximum = MAX_BOOTSTRAP_REQUEST_BYTES
        request_signing_domain = BOOTSTRAP_REQUEST_SIGNING_DOMAIN
        request_digest_domain = BOOTSTRAP_REQUEST_DIGEST_DOMAIN
        response_magic = BOOTSTRAP_RESPONSE_MAGIC
        response_schema = BOOTSTRAP_RESPONSE_SCHEMA
        response_maximum = MAX_BOOTSTRAP_RESPONSE_BYTES
        response_signing_domain = BOOTSTRAP_RESPONSE_SIGNING_DOMAIN
        response_digest_domain = BOOTSTRAP_RESPONSE_DIGEST_DOMAIN
    else:
        request_name = "query_request"
        response_name = "query_response"
        request_magic = QUERY_REQUEST_MAGIC
        request_schema = QUERY_REQUEST_SCHEMA
        request_maximum = MAX_QUERY_REQUEST_BYTES
        request_signing_domain = QUERY_REQUEST_SIGNING_DOMAIN
        request_digest_domain = QUERY_REQUEST_DIGEST_DOMAIN
        response_magic = QUERY_RESPONSE_MAGIC
        response_schema = QUERY_RESPONSE_SCHEMA
        response_maximum = MAX_QUERY_RESPONSE_BYTES
        response_signing_domain = QUERY_RESPONSE_SIGNING_DOMAIN
        response_digest_domain = QUERY_RESPONSE_DIGEST_DOMAIN

    signed_bound = len(controls[response_name]["wire"]) - 1
    request_wire = _resigned_control_changes(
        controls[request_name],
        magic=request_magic,
        maximum_bytes=request_maximum,
        schema=request_schema,
        signing_domain=request_signing_domain,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
        changes={9: _u32(signed_bound)},
    )
    request = {
        "wire": request_wire,
        "digest": _digest(request_digest_domain, [request_wire]),
    }
    response_wire = _resigned_control_changes(
        controls[response_name],
        magic=response_magic,
        maximum_bytes=response_maximum,
        schema=response_schema,
        signing_domain=response_signing_domain,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={2: request["digest"]},
    )
    response = {
        "wire": response_wire,
        "digest": _digest(response_digest_domain, [response_wire]),
    }
    with pytest.raises(ContractReject) as rejected:
        if protocol == "bootstrap":
            _verify_bootstrap_exchange(
                request,
                response,
                request_public_key=controls[request_name]["public_key"],
                response_public_key=controls[response_name]["public_key"],
                channel=controls["channel"],
                expected_artifact=vectors["artifact"],
                expected_admission_policy_digest=EXPECTED_ADMISSION_POLICY_DIGEST,
            )
        else:
            _verify_query_exchange(
                request,
                response,
                request_public_key=controls[request_name]["public_key"],
                response_public_key=controls[response_name]["public_key"],
                channel=controls["channel"],
                serving_baseline=controls["query_serving_baseline"],
            )
    assert rejected.value.code == S7_CODEC_ERROR_CODES["response_bound_exceeded"]
    assert rejected.value.detail_code is None


def test_exchange_consumers_freeze_multi_invalid_precedence() -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)

    bootstrap_request_wire = _resigned_control_changes(
        controls["bootstrap_request"],
        magic=BOOTSTRAP_REQUEST_MAGIC,
        maximum_bytes=MAX_BOOTSTRAP_REQUEST_BYTES,
        schema=BOOTSTRAP_REQUEST_SCHEMA,
        signing_domain=BOOTSTRAP_REQUEST_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
        changes={9: _u32(len(controls["bootstrap_response"]["wire"]) - 1)},
    )
    bootstrap_request = {
        "wire": bootstrap_request_wire,
        "digest": _digest(BOOTSTRAP_REQUEST_DIGEST_DOMAIN, [bootstrap_request_wire]),
    }
    bootstrap_identity = bytearray(vectors["artifact"]["identity"])
    bootstrap_identity[:32] = bytes.fromhex("f1" * 32)
    bootstrap_response_wire = _resigned_control_changes(
        controls["bootstrap_response"],
        magic=BOOTSTRAP_RESPONSE_MAGIC,
        maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
        schema=BOOTSTRAP_RESPONSE_SCHEMA,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={
            2: bootstrap_request["digest"],
            10: bytes.fromhex("f1" * 32),
            12: bytes(bootstrap_identity),
            18: bytes.fromhex("f2" * 16),
            19: bytes.fromhex("f3" * 32),
        },
    )
    with pytest.raises(ContractReject) as bootstrap_rejected:
        _verify_bootstrap_exchange(
            bootstrap_request,
            {
                "wire": bootstrap_response_wire,
                "digest": _digest(
                    BOOTSTRAP_RESPONSE_DIGEST_DOMAIN, [bootstrap_response_wire]
                ),
            },
            request_public_key=controls["bootstrap_request"]["public_key"],
            response_public_key=controls["bootstrap_response"]["public_key"],
            channel=controls["channel"],
            expected_artifact=vectors["artifact"],
            expected_admission_policy_digest=EXPECTED_ADMISSION_POLICY_DIGEST,
        )
    assert (
        bootstrap_rejected.value.code
        == S7_CODEC_ERROR_CODES["compatibility_mismatch"]
    )
    assert bootstrap_rejected.value.detail_code == 10

    query_request_wire = _resigned_control_changes(
        controls["query_request"],
        magic=QUERY_REQUEST_MAGIC,
        maximum_bytes=MAX_QUERY_REQUEST_BYTES,
        schema=QUERY_REQUEST_SCHEMA,
        signing_domain=QUERY_REQUEST_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
        changes={
            7: bytes.fromhex("f4" * 32),
            9: _u32(len(controls["query_response"]["wire"]) - 1),
        },
    )
    query_request = {
        "wire": query_request_wire,
        "digest": _digest(QUERY_REQUEST_DIGEST_DOMAIN, [query_request_wire]),
    }
    query_response_wire = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={
            2: query_request["digest"],
            27: bytes.fromhex("f5" * 16),
        },
    )
    stale_baseline = {
        **controls["query_serving_baseline"],
        "snapshot_sequence": (1 << 64) - 1,
    }
    with pytest.raises(ContractReject) as query_rejected:
        _verify_query_exchange(
            query_request,
            {
                "wire": query_response_wire,
                "digest": _digest(QUERY_RESPONSE_DIGEST_DOMAIN, [query_response_wire]),
            },
            request_public_key=controls["query_request"]["public_key"],
            response_public_key=controls["query_response"]["public_key"],
            channel=controls["channel"],
            serving_baseline=stale_baseline,
        )
    assert query_rejected.value.code == S7_CODEC_ERROR_CODES["cross_reference_mismatch"]
    assert query_rejected.value.detail_code == 6


@pytest.mark.parametrize("tag", [13, 14, 15, 19])
def test_bootstrap_response_rejects_zero_trust_and_channel_digests(tag: int) -> None:
    controls = _build_control_vectors(_build_vectors())
    fields = list(
        _parse_control_frame(
            controls["bootstrap_response"]["wire"],
            magic=BOOTSTRAP_RESPONSE_MAGIC,
            maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
            schema=BOOTSTRAP_RESPONSE_SCHEMA,
        ).items()
    )
    fields = [(field_tag, bytes(32) if field_tag == tag else value) for field_tag, value in fields]
    wire = _resign_control_fields(
        magic=BOOTSTRAP_RESPONSE_MAGIC,
        fields=fields,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
    )
    with pytest.raises(ContractReject) as rejected:
        _decode_bootstrap_response(wire)
    expected = (
        S7_CODEC_ERROR_CODES["invalid_field_value"]
        if tag == 19
        else S7_CODEC_ERROR_CODES["compatibility_mismatch"]
    )
    assert rejected.value.code == expected
    assert rejected.value.detail_code == tag


def test_bootstrap_state_reason_matrix_is_exact() -> None:
    controls = _build_control_vectors(_build_vectors())
    original = list(
        _parse_control_frame(
            controls["bootstrap_response"]["wire"],
            magic=BOOTSTRAP_RESPONSE_MAGIC,
            maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
            schema=BOOTSTRAP_RESPONSE_SCHEMA,
        ).items()
    )
    valid_pairs = {
        (
            BOOTSTRAP_STATES["ready_for_apply"],
            OPERATIONAL_REASONS["none"],
        ),
        (
            BOOTSTRAP_STATES["not_ready_recovering"],
            OPERATIONAL_REASONS["recovering"],
        ),
        (
            BOOTSTRAP_STATES["recovery_failed_not_ready"],
            OPERATIONAL_REASONS["recovery_failed"],
        ),
        (
            BOOTSTRAP_STATES["not_ready_busy"],
            OPERATIONAL_REASONS["runtime_busy"],
        ),
        *{
            (
                BOOTSTRAP_STATES["validated_operational_quarantine"],
                OPERATIONAL_REASONS[name],
            )
            for name in (
                "active_compatibility_mismatch",
                "ownership_uncertain",
                "history_unavailable",
                "resource_census_uncertain",
                "ownership_transfer_required",
            )
        },
    }
    for state in BOOTSTRAP_STATES.values():
        for reason in OPERATIONAL_REASONS.values():
            fields = [
                (
                    tag,
                    _u16(state) if tag == 16 else _u16(reason) if tag == 17 else value,
                )
                for tag, value in original
            ]
            wire = _resign_control_fields(
                magic=BOOTSTRAP_RESPONSE_MAGIC,
                fields=fields,
                signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
                seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
            )
            if (state, reason) in valid_pairs:
                _decode_bootstrap_response(wire)
            else:
                with pytest.raises(ContractReject) as rejected:
                    _decode_bootstrap_response(wire)
                assert rejected.value.code == S7_CODEC_ERROR_CODES["unknown_reason"]
                assert rejected.value.detail_code == 17


@pytest.mark.parametrize("tag", [20, 21, 26, 28])
def test_query_response_rejects_zero_desired_census_and_channel_digests(
    tag: int,
) -> None:
    controls = _build_control_vectors(_build_vectors())
    fields = list(
        _parse_control_frame(
            controls["query_response"]["wire"],
            magic=QUERY_RESPONSE_MAGIC,
            maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
            schema=QUERY_RESPONSE_SCHEMA,
        ).items()
    )
    fields = [(field_tag, bytes(32) if field_tag == tag else value) for field_tag, value in fields]
    wire = _resign_control_fields(
        magic=QUERY_RESPONSE_MAGIC,
        fields=fields,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
    )
    with pytest.raises(ContractReject) as rejected:
        _decode_query_response(wire)
    assert rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_value"]
    assert rejected.value.detail_code == tag


@pytest.mark.parametrize(
    (
        "response_name",
        "magic",
        "signing_domain",
        "maximum_bytes",
        "schema",
        "decoder",
    ),
    [
        (
            "bootstrap_response",
            BOOTSTRAP_RESPONSE_MAGIC,
            BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
            MAX_BOOTSTRAP_RESPONSE_BYTES,
            BOOTSTRAP_RESPONSE_SCHEMA,
            _decode_bootstrap_response,
        ),
        (
            "query_response",
            QUERY_RESPONSE_MAGIC,
            QUERY_RESPONSE_SIGNING_DOMAIN,
            MAX_QUERY_RESPONSE_BYTES,
            QUERY_RESPONSE_SCHEMA,
            _decode_query_response,
        ),
    ],
)
def test_control_responses_reject_zero_request_digest_even_when_resigned(
    response_name: str,
    magic: bytes,
    signing_domain: bytes,
    maximum_bytes: int,
    schema: dict[int, FieldWidth],
    decoder: Any,
) -> None:
    controls = _build_control_vectors(_build_vectors())
    fields = list(
        _parse_control_frame(
            controls[response_name]["wire"],
            magic=magic,
            maximum_bytes=maximum_bytes,
            schema=schema,
        ).items()
    )
    fields = [(tag, bytes(32) if tag == 2 else value) for tag, value in fields]
    wire = _resign_control_fields(
        magic=magic,
        fields=fields,
        signing_domain=signing_domain,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
    )
    with pytest.raises(ContractReject) as rejected:
        decoder(wire)
    assert rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_value"]
    assert rejected.value.detail_code == 2


@pytest.mark.parametrize(
    "changes",
    [
        {24: _u64(0)},
        {
            18: _u16(DESIRED_HEAD_KINDS["empty_deactivate"]),
            10: _u16(OWNER_STATES["apply_disabled"]),
            11: _u16(OPERATIONAL_REASONS["runtime_busy"]),
            23: _u16(LIVE_STATES["draining"]),
            24: _u64(0),
        },
        {23: _u16(LIVE_STATES["not_ready"]), 24: _u64(1)},
        {
            10: _u16(OWNER_STATES["apply_disabled"]),
            11: _u16(OPERATIONAL_REASONS["recovery_failed"]),
            23: _u16(LIVE_STATES["recovery_failed_not_ready"]),
            24: _u64(1),
        },
        {
            18: _u16(DESIRED_HEAD_KINDS["empty_deactivate"]),
            23: _u16(LIVE_STATES["exact_zero"]),
            24: _u64(1),
        },
        {
            10: _u16(OWNER_STATES["apply_disabled"]),
            11: _u16(OPERATIONAL_REASONS["active_compatibility_mismatch"]),
            23: _u16(LIVE_STATES["validated_operational_quarantine"]),
            24: _u64(1),
        },
    ],
)
def test_query_live_state_resource_generation_matrix_is_exact(
    changes: dict[int, bytes],
) -> None:
    controls = _build_control_vectors(_build_vectors())
    fields = list(
        _parse_control_frame(
            controls["query_response"]["wire"],
            magic=QUERY_RESPONSE_MAGIC,
            maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
            schema=QUERY_RESPONSE_SCHEMA,
        ).items()
    )
    fields = [(tag, changes.get(tag, value)) for tag, value in fields]
    wire = _resign_control_fields(
        magic=QUERY_RESPONSE_MAGIC,
        fields=fields,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
    )
    with pytest.raises(ContractReject) as rejected:
        _decode_query_response(wire)
    assert rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_value"]
    assert rejected.value.detail_code == 24


@pytest.mark.parametrize(
    "changes",
    [
        {23: _u16(LIVE_STATES["draining"])},
        {
            18: _u16(DESIRED_HEAD_KINDS["empty_deactivate"]),
            23: _u16(LIVE_STATES["live_ready"]),
        },
        {
            18: _u16(DESIRED_HEAD_KINDS["empty_deactivate"]),
            23: _u16(LIVE_STATES["recovering"]),
        },
        {
            18: _u16(DESIRED_HEAD_KINDS["empty_deactivate"]),
            23: _u16(LIVE_STATES["recovery_failed_not_ready"]),
            24: _u64(0),
        },
        {
            18: _u16(DESIRED_HEAD_KINDS["none"]),
            19: _u64(0),
            20: bytes(32),
            21: bytes(32),
        },
        {
            23: _u16(LIVE_STATES["exact_zero"]),
            24: _u64(0),
        },
    ],
)
def test_query_desired_head_and_live_state_matrix_is_exact(
    changes: dict[int, bytes],
) -> None:
    controls = _build_control_vectors(_build_vectors())
    fields = list(
        _parse_control_frame(
            controls["query_response"]["wire"],
            magic=QUERY_RESPONSE_MAGIC,
            maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
            schema=QUERY_RESPONSE_SCHEMA,
        ).items()
    )
    fields = [(tag, changes.get(tag, value)) for tag, value in fields]
    wire = _resign_control_fields(
        magic=QUERY_RESPONSE_MAGIC,
        fields=fields,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
    )
    with pytest.raises(ContractReject) as rejected:
        _decode_query_response(wire)
    assert rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_value"]
    assert rejected.value.detail_code == 23


def test_channel_binding_and_exchange_echoes_are_not_replaceable() -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)
    alternate_channel = _channel_binding(
        target=_hex(TARGET_HEX),
        runtime_peer=bytes.fromhex("e1" * 16),
        local_endpoint_identity_digest=bytes.fromhex("e3" * 32),
        peer_credentials_digest=bytes.fromhex("e5" * 32),
    )
    assert alternate_channel["binding_digest"] != controls["channel_binding_digest"]

    bootstrap_fields = list(
        _parse_control_frame(
            controls["bootstrap_response"]["wire"],
            magic=BOOTSTRAP_RESPONSE_MAGIC,
            maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
            schema=BOOTSTRAP_RESPONSE_SCHEMA,
        ).items()
    )
    nonce_fields = [
        (tag, b"different-bootstrap-nonce" if tag == 3 else value)
        for tag, value in bootstrap_fields
    ]
    mismatched_wire = _resign_control_fields(
        magic=BOOTSTRAP_RESPONSE_MAGIC,
        fields=nonce_fields,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
    )
    mismatched_response = {
        "wire": mismatched_wire,
        "digest": _digest(BOOTSTRAP_RESPONSE_DIGEST_DOMAIN, [mismatched_wire]),
    }
    with pytest.raises(ContractReject) as mismatch:
        _verify_bootstrap_exchange(
            controls["bootstrap_request"],
            mismatched_response,
            request_public_key=controls["bootstrap_request"]["public_key"],
            response_public_key=controls["bootstrap_response"]["public_key"],
            channel=controls["channel"],
            expected_artifact=vectors["artifact"],
            expected_admission_policy_digest=(EXPECTED_ADMISSION_POLICY_DIGEST),
        )
    assert mismatch.value.code == S7_CODEC_ERROR_CODES["cross_reference_mismatch"]
    assert mismatch.value.detail_code == 3

    cases = [
        (
            "bootstrap_request",
            "bootstrap_response",
            BOOTSTRAP_RESPONSE_MAGIC,
            BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
            BOOTSTRAP_RESPONSE_DIGEST_DOMAIN,
            BOOTSTRAP_RESPONSE_SCHEMA,
            MAX_BOOTSTRAP_RESPONSE_BYTES,
            18,
            19,
            _verify_bootstrap_exchange,
        ),
        (
            "query_request",
            "query_response",
            QUERY_RESPONSE_MAGIC,
            QUERY_RESPONSE_SIGNING_DOMAIN,
            QUERY_RESPONSE_DIGEST_DOMAIN,
            QUERY_RESPONSE_SCHEMA,
            MAX_QUERY_RESPONSE_BYTES,
            27,
            28,
            _verify_query_exchange,
        ),
    ]
    for (
        request_name,
        response_name,
        magic,
        signing_domain,
        digest_domain,
        schema,
        maximum_bytes,
        peer_tag,
        binding_tag,
        verifier,
    ) in cases:
        original_fields = list(
            _parse_control_frame(
                controls[response_name]["wire"],
                magic=magic,
                maximum_bytes=maximum_bytes,
                schema=schema,
            ).items()
        )
        for changed_tag, replacement in (
            (peer_tag, bytes.fromhex("ef" * 16)),
            (binding_tag, alternate_channel["binding_digest"]),
        ):
            changed_fields = [
                (
                    tag,
                    replacement if tag == changed_tag else value,
                )
                for tag, value in original_fields
            ]
            changed_wire = _resign_control_fields(
                magic=magic,
                fields=changed_fields,
                signing_domain=signing_domain,
                seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
            )
            changed_response = {
                "wire": changed_wire,
                "digest": _digest(digest_domain, [changed_wire]),
            }
            with pytest.raises(ContractReject) as channel_rejected:
                if response_name == "bootstrap_response":
                    verifier(
                        controls[request_name],
                        changed_response,
                        request_public_key=controls[request_name]["public_key"],
                        response_public_key=controls[response_name]["public_key"],
                        channel=controls["channel"],
                        expected_artifact=vectors["artifact"],
                        expected_admission_policy_digest=(EXPECTED_ADMISSION_POLICY_DIGEST),
                    )
                else:
                    verifier(
                        controls[request_name],
                        changed_response,
                        request_public_key=controls[request_name]["public_key"],
                        response_public_key=controls[response_name]["public_key"],
                        channel=controls["channel"],
                        serving_baseline=controls["query_serving_baseline"],
                    )
            assert channel_rejected.value.code == S7_CODEC_ERROR_CODES["target_mismatch"]
            assert channel_rejected.value.detail_code == changed_tag


@pytest.mark.parametrize(
    ("pin", "expected_detail"),
    [(10, 10), (11, 11), (12, 12), (13, 13), (14, 14), (15, 15), ("all", 10)],
)
def test_bootstrap_consumer_rejects_resigned_nonzero_compatibility_substitution(
    pin: int | str, expected_detail: int
) -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)
    response_values = _decode_bootstrap_response(controls["bootstrap_response"]["wire"])
    identity = bytearray(response_values[12])
    replacements = {
        10: bytes.fromhex("f0" * 32),
        11: bytes.fromhex("f1" * 32),
        13: bytes.fromhex("f4" * 32),
        14: bytes.fromhex("f5" * 32),
        15: bytes.fromhex("f6" * 32),
    }
    if pin == 10:
        identity[:32] = replacements[10]
        changes = {10: replacements[10], 12: bytes(identity)}
    elif pin == 11:
        identity[96:128] = replacements[11]
        changes = {11: replacements[11], 12: bytes(identity)}
    elif pin == 12:
        identity[32:64] = bytes.fromhex("f2" * 32)
        changes = {12: bytes(identity)}
    elif pin == "all":
        identity = bytearray(
            replacements[10]
            + bytes.fromhex("f2" * 32)
            + bytes.fromhex("f3" * 32)
            + replacements[11]
        )
        changes = {
            10: replacements[10],
            11: replacements[11],
            12: bytes(identity),
            13: replacements[13],
            14: replacements[14],
            15: replacements[15],
        }
    else:
        changes = {pin: replacements[pin]}
    wire = _resigned_control_changes(
        controls["bootstrap_response"],
        magic=BOOTSTRAP_RESPONSE_MAGIC,
        maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
        schema=BOOTSTRAP_RESPONSE_SCHEMA,
        signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes=changes,
    )
    _decode_bootstrap_response(wire)
    response = {
        "wire": wire,
        "digest": _digest(BOOTSTRAP_RESPONSE_DIGEST_DOMAIN, [wire]),
    }
    with pytest.raises(ContractReject) as rejected:
        _verify_bootstrap_exchange(
            controls["bootstrap_request"],
            response,
            request_public_key=controls["bootstrap_request"]["public_key"],
            response_public_key=controls["bootstrap_response"]["public_key"],
            channel=controls["channel"],
            expected_artifact=vectors["artifact"],
            expected_admission_policy_digest=(EXPECTED_ADMISSION_POLICY_DIGEST),
        )
    assert rejected.value.code == S7_CODEC_ERROR_CODES["compatibility_mismatch"]
    assert rejected.value.detail_code == expected_detail


@pytest.mark.parametrize(
    ("changes", "expected_code", "expected_detail"),
    [
        (
            {6: _u64(6)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            6,
        ),
        (
            {7: _u64(2)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            7,
        ),
        (
            {9: _u64(4)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            9,
        ),
        (
            {6: _u64(10), 7: _u64(4), 9: _u64(3)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            9,
        ),
        (
            {6: _u64(7), 7: _u64(4), 9: _u64(4)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            6,
        ),
        (
            {8: bytes.fromhex("f8" * 16)},
            S7_CODEC_ERROR_CODES["target_mismatch"],
            8,
        ),
    ],
)
def test_query_consumer_freshness_rejects_regression_and_domain_substitution(
    changes: dict[int, bytes],
    expected_code: int,
    expected_detail: int,
) -> None:
    controls = _build_control_vectors(_build_vectors())
    wire = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes=changes,
    )
    response = {
        "wire": wire,
        "digest": _digest(QUERY_RESPONSE_DIGEST_DOMAIN, [wire]),
    }
    with pytest.raises(ContractReject) as rejected:
        _verify_query_exchange(
            controls["query_request"],
            response,
            request_public_key=controls["query_request"]["public_key"],
            response_public_key=controls["query_response"]["public_key"],
            channel=controls["channel"],
            serving_baseline=controls["query_serving_baseline"],
        )
    assert rejected.value.code == expected_code
    assert rejected.value.detail_code == expected_detail


def test_query_consumer_accepts_equal_snapshot_replay_and_valid_new_epoch() -> None:
    controls = _build_control_vectors(_build_vectors())
    values = _decode_query_response(controls["query_response"]["wire"])
    current_baseline = {
        "target": values[4],
        "store": values[5],
        "snapshot_sequence": struct.unpack(">Q", values[6])[0],
        "host_epoch": struct.unpack(">Q", values[7])[0],
        "clock_domain": values[8],
        "clock_generation": struct.unpack(">Q", values[9])[0],
    }
    _verify_query_exchange(
        controls["query_request"],
        controls["query_response"],
        request_public_key=controls["query_request"]["public_key"],
        response_public_key=controls["query_response"]["public_key"],
        channel=controls["channel"],
        serving_baseline=current_baseline,
    )

    forward_wire = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={6: _u64(10), 7: _u64(4), 9: _u64(4)},
    )
    _verify_query_exchange(
        controls["query_request"],
        {
            "wire": forward_wire,
            "digest": _digest(QUERY_RESPONSE_DIGEST_DOMAIN, [forward_wire]),
        },
        request_public_key=controls["query_request"]["public_key"],
        response_public_key=controls["query_response"]["public_key"],
        channel=controls["channel"],
        serving_baseline=current_baseline,
    )


@pytest.mark.parametrize(
    ("response_name", "changes", "expected_code", "expected_detail"),
    [
        (
            "bootstrap_response",
            {1: bytes.fromhex("f1" * 16)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            1,
        ),
        (
            "bootstrap_response",
            {2: bytes.fromhex("f2" * 32)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            2,
        ),
        (
            "bootstrap_response",
            {3: b"substituted-bootstrap-nonce"},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            3,
        ),
        (
            "bootstrap_response",
            {4: bytes.fromhex("f4" * 16)},
            S7_CODEC_ERROR_CODES["target_mismatch"],
            4,
        ),
        (
            "query_response",
            {1: bytes.fromhex("f1" * 16)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            1,
        ),
        (
            "query_response",
            {2: bytes.fromhex("f2" * 32)},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            2,
        ),
        (
            "query_response",
            {3: b"substituted-query-nonce"},
            S7_CODEC_ERROR_CODES["cross_reference_mismatch"],
            3,
        ),
        (
            "query_response",
            {4: bytes.fromhex("f4" * 16)},
            S7_CODEC_ERROR_CODES["target_mismatch"],
            4,
        ),
        (
            "query_response",
            {5: bytes.fromhex("f5" * 32)},
            S7_CODEC_ERROR_CODES["target_mismatch"],
            5,
        ),
    ],
)
def test_exchange_echo_and_serving_identity_detail_parity(
    response_name: str,
    changes: dict[int, bytes],
    expected_code: int,
    expected_detail: int,
) -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)
    if response_name == "bootstrap_response":
        wire = _resigned_control_changes(
            controls[response_name],
            magic=BOOTSTRAP_RESPONSE_MAGIC,
            maximum_bytes=MAX_BOOTSTRAP_RESPONSE_BYTES,
            schema=BOOTSTRAP_RESPONSE_SCHEMA,
            signing_domain=BOOTSTRAP_RESPONSE_SIGNING_DOMAIN,
            seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
            changes=changes,
        )
        with pytest.raises(ContractReject) as rejected:
            _verify_bootstrap_exchange(
                controls["bootstrap_request"],
                {
                    "wire": wire,
                    "digest": _digest(BOOTSTRAP_RESPONSE_DIGEST_DOMAIN, [wire]),
                },
                request_public_key=controls["bootstrap_request"]["public_key"],
                response_public_key=controls["bootstrap_response"]["public_key"],
                channel=controls["channel"],
                expected_artifact=vectors["artifact"],
                expected_admission_policy_digest=(EXPECTED_ADMISSION_POLICY_DIGEST),
            )
    else:
        wire = _resigned_control_changes(
            controls[response_name],
            magic=QUERY_RESPONSE_MAGIC,
            maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
            schema=QUERY_RESPONSE_SCHEMA,
            signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
            seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
            changes=changes,
        )
        with pytest.raises(ContractReject) as rejected:
            _verify_query_exchange(
                controls["query_request"],
                {
                    "wire": wire,
                    "digest": _digest(QUERY_RESPONSE_DIGEST_DOMAIN, [wire]),
                },
                request_public_key=controls["query_request"]["public_key"],
                response_public_key=controls["query_response"]["public_key"],
                channel=controls["channel"],
                serving_baseline=controls["query_serving_baseline"],
            )
    assert rejected.value.code == expected_code
    assert rejected.value.detail_code == expected_detail


def test_query_expectation_mismatch_branches_have_exact_details() -> None:
    controls = _build_control_vectors(_build_vectors())
    request_values = _decode_query_request(controls["query_request"]["wire"])

    known_mismatch_wire = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={14: bytes.fromhex("fb" * 32)},
    )
    with pytest.raises(ContractReject) as known_mismatch:
        _verify_query_exchange(
            controls["query_request"],
            {
                "wire": known_mismatch_wire,
                "digest": _digest(QUERY_RESPONSE_DIGEST_DOMAIN, [known_mismatch_wire]),
            },
            request_public_key=controls["query_request"]["public_key"],
            response_public_key=controls["query_response"]["public_key"],
            channel=controls["channel"],
            serving_baseline=controls["query_serving_baseline"],
        )
    assert known_mismatch.value.code == S7_CODEC_ERROR_CODES["cross_reference_mismatch"]
    assert known_mismatch.value.detail_code == 14

    conflict_wire = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={
            12: _u16(LOOKUP_KINDS["conflict"]),
            14: request_values[7],
            15: _u16(DURABLE_PHASES["none"]),
            16: _u8(0),
            17: bytes(16),
        },
    )
    with pytest.raises(ContractReject) as conflict_mismatch:
        _verify_query_exchange(
            controls["query_request"],
            {
                "wire": conflict_wire,
                "digest": _digest(QUERY_RESPONSE_DIGEST_DOMAIN, [conflict_wire]),
            },
            request_public_key=controls["query_request"]["public_key"],
            response_public_key=controls["query_response"]["public_key"],
            channel=controls["channel"],
            serving_baseline=controls["query_serving_baseline"],
        )
    assert conflict_mismatch.value.code == S7_CODEC_ERROR_CODES["cross_reference_mismatch"]
    assert conflict_mismatch.value.detail_code == 14

    no_expectation_wire = _resigned_control_changes(
        controls["query_request"],
        magic=QUERY_REQUEST_MAGIC,
        maximum_bytes=MAX_QUERY_REQUEST_BYTES,
        schema=QUERY_REQUEST_SCHEMA,
        signing_domain=QUERY_REQUEST_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
        changes={6: _u8(0), 7: bytes(32)},
    )
    no_expectation_request = {
        "wire": no_expectation_wire,
        "digest": _digest(QUERY_REQUEST_DIGEST_DOMAIN, [no_expectation_wire]),
        "public_key": controls["query_request"]["public_key"],
    }
    no_expectation_response_wire = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={
            2: no_expectation_request["digest"],
            12: _u16(LOOKUP_KINDS["conflict"]),
            14: bytes.fromhex("fc" * 32),
            15: _u16(DURABLE_PHASES["none"]),
            16: _u8(0),
            17: bytes(16),
        },
    )
    with pytest.raises(ContractReject) as no_expectation:
        _verify_query_exchange(
            no_expectation_request,
            {
                "wire": no_expectation_response_wire,
                "digest": _digest(
                    QUERY_RESPONSE_DIGEST_DOMAIN,
                    [no_expectation_response_wire],
                ),
            },
            request_public_key=controls["query_request"]["public_key"],
            response_public_key=controls["query_response"]["public_key"],
            channel=controls["channel"],
            serving_baseline=controls["query_serving_baseline"],
        )
    assert no_expectation.value.code == S7_CODEC_ERROR_CODES["cross_reference_mismatch"]
    assert no_expectation.value.detail_code == 12


def test_control_protocol_versions_trailing_bytes_and_record_count_are_strict() -> None:
    vectors = _build_vectors()
    controls = _build_control_vectors(vectors)
    request = controls["bootstrap_request"]["wire"]
    with pytest.raises(ContractReject) as version:
        _decode_bootstrap_request(request[:4] + _u16(2) + request[6:])
    assert version.value.code == S7_CODEC_ERROR_CODES["unsupported_version"]
    with pytest.raises(ContractReject) as trailing:
        _decode_bootstrap_request(request + b"\x00")
    assert trailing.value.code == S7_CODEC_ERROR_CODES["trailing_bytes"]

    query_fields = list(
        _parse_control_frame(
            controls["query_request"]["wire"],
            magic=QUERY_REQUEST_MAGIC,
            maximum_bytes=MAX_QUERY_REQUEST_BYTES,
            schema=QUERY_REQUEST_SCHEMA,
        ).items()
    )
    query_fields[9] = (10, _u16(2))
    invalid_count = _resign_control_fields(
        magic=QUERY_REQUEST_MAGIC,
        fields=query_fields,
        signing_domain=QUERY_REQUEST_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["controller_read_seed_hex"],
    )
    with pytest.raises(ContractReject) as count:
        _decode_query_request(invalid_count)
    assert count.value.code == S7_CODEC_ERROR_CODES["invalid_field_value"]
    assert count.value.detail_code == 10


@pytest.mark.parametrize(
    ("magic", "maximum_bytes", "schema"),
    [
        (
            BOOTSTRAP_REQUEST_MAGIC,
            MAX_BOOTSTRAP_REQUEST_BYTES,
            BOOTSTRAP_REQUEST_SCHEMA,
        ),
        (
            QUERY_REQUEST_MAGIC,
            MAX_QUERY_REQUEST_BYTES,
            QUERY_REQUEST_SCHEMA,
        ),
    ],
)
def test_control_tag_zero_and_declared_width_eof_precedence_is_stable(
    magic: bytes,
    maximum_bytes: int,
    schema: dict[int, FieldWidth],
) -> None:
    prefix = magic + _u16(CONTROL_PROTOCOL_VERSION) + _u16(len(schema))
    cases = [
        (
            prefix + _u16(0) + _u32(16) + bytes(16),
            S7_CODEC_ERROR_CODES["unknown_field"],
            0,
        ),
        (
            prefix + _u16(1) + _u32(17),
            S7_CODEC_ERROR_CODES["invalid_field_length"],
            1,
        ),
        (
            prefix + _u16(1) + _u32(16),
            S7_CODEC_ERROR_CODES["truncated"],
            1,
        ),
    ]
    for wire, expected_code, expected_detail in cases:
        with pytest.raises(ContractReject) as rejected:
            _parse_control_frame(
                wire,
                magic=magic,
                maximum_bytes=maximum_bytes,
                schema=schema,
            )
        assert rejected.value.code == expected_code
        assert rejected.value.detail_code == expected_detail


def test_signature_widths_are_field_length_errors_before_signature_semantics() -> None:
    vectors = _build_vectors()
    envelope_fields = _parse_envelope_fields(vectors["one"]["envelope"]["wire"])
    empty_envelope_signature = _encode_envelope_fields(
        [(tag, b"" if tag == ENVELOPE_FIELD_COUNT else value) for tag, value in envelope_fields]
    )
    with pytest.raises(ContractReject) as envelope_rejected:
        _decode_envelope(empty_envelope_signature)
    assert envelope_rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_length"]
    assert envelope_rejected.value.detail_code == ENVELOPE_FIELD_COUNT

    controls = _build_control_vectors(vectors)
    request_fields = list(
        _parse_control_frame(
            controls["bootstrap_request"]["wire"],
            magic=BOOTSTRAP_REQUEST_MAGIC,
            maximum_bytes=MAX_BOOTSTRAP_REQUEST_BYTES,
            schema=BOOTSTRAP_REQUEST_SCHEMA,
        ).items()
    )
    empty_control_signature = _encode_control_frame(
        BOOTSTRAP_REQUEST_MAGIC,
        [
            (tag, b"" if tag == len(BOOTSTRAP_REQUEST_SCHEMA) else value)
            for tag, value in request_fields
        ],
    )
    with pytest.raises(ContractReject) as control_rejected:
        _decode_bootstrap_request(empty_control_signature)
    assert control_rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_length"]
    assert control_rejected.value.detail_code == len(BOOTSTRAP_REQUEST_SCHEMA)


def test_query_owner_reason_lookup_matrix_is_exact() -> None:
    controls = _build_control_vectors(_build_vectors())
    lookup_payloads = {
        LOOKUP_KINDS["known"]: {
            12: _u16(LOOKUP_KINDS["known"]),
            13: _u8(1),
            14: bytes.fromhex("a8" * 32),
            15: _u16(DURABLE_PHASES["terminal"]),
            16: _u8(1),
            17: bytes.fromhex("a9" * 16),
        },
        LOOKUP_KINDS["conflict"]: {
            12: _u16(LOOKUP_KINDS["conflict"]),
            13: _u8(1),
            14: bytes.fromhex("aa" * 32),
            15: _u16(DURABLE_PHASES["none"]),
            16: _u8(0),
            17: bytes(16),
        },
        LOOKUP_KINDS["unknown"]: {
            12: _u16(LOOKUP_KINDS["unknown"]),
            13: _u8(0),
            14: bytes(32),
            15: _u16(DURABLE_PHASES["none"]),
            16: _u8(0),
            17: bytes(16),
        },
        LOOKUP_KINDS["indeterminate"]: {
            12: _u16(LOOKUP_KINDS["indeterminate"]),
            13: _u8(0),
            14: bytes(32),
            15: _u16(DURABLE_PHASES["none"]),
            16: _u8(0),
            17: bytes(16),
        },
    }
    apply_disabled_reasons = {
        OPERATIONAL_REASONS["recovering"],
        OPERATIONAL_REASONS["active_compatibility_mismatch"],
        OPERATIONAL_REASONS["recovery_failed"],
        OPERATIONAL_REASONS["runtime_busy"],
    }
    ownership_uncertain_reasons = {
        OPERATIONAL_REASONS["ownership_uncertain"],
        OPERATIONAL_REASONS["history_unavailable"],
        OPERATIONAL_REASONS["resource_census_uncertain"],
        OPERATIONAL_REASONS["ownership_transfer_required"],
    }
    for owner_state in OWNER_STATES.values():
        for reason in OPERATIONAL_REASONS.values():
            for lookup, payload in lookup_payloads.items():
                changes = {
                    **payload,
                    10: _u16(owner_state),
                    11: _u16(reason),
                }
                if owner_state == OWNER_STATES["ownership_uncertain"]:
                    changes[23] = _u16(LIVE_STATES["uncertain"])
                elif (
                    owner_state == OWNER_STATES["apply_disabled"]
                    and reason == OPERATIONAL_REASONS["recovering"]
                ):
                    changes[23] = _u16(LIVE_STATES["recovering"])
                elif (
                    owner_state == OWNER_STATES["apply_disabled"]
                    and reason == OPERATIONAL_REASONS["active_compatibility_mismatch"]
                ):
                    changes[23] = _u16(LIVE_STATES["validated_operational_quarantine"])
                    changes[24] = _u64(0)
                elif (
                    owner_state == OWNER_STATES["apply_disabled"]
                    and reason == OPERATIONAL_REASONS["recovery_failed"]
                ):
                    changes[23] = _u16(LIVE_STATES["recovery_failed_not_ready"])
                    changes[24] = _u64(0)
                wire = _resigned_control_changes(
                    controls["query_response"],
                    magic=QUERY_RESPONSE_MAGIC,
                    maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
                    schema=QUERY_RESPONSE_SCHEMA,
                    signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
                    seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
                    changes=changes,
                )
                owner_reason_valid = (
                    (
                        owner_state == OWNER_STATES["operational"]
                        and reason == OPERATIONAL_REASONS["none"]
                    )
                    or (
                        owner_state == OWNER_STATES["apply_disabled"]
                        and reason in apply_disabled_reasons
                    )
                    or (
                        owner_state == OWNER_STATES["ownership_uncertain"]
                        and reason in ownership_uncertain_reasons
                    )
                )
                valid = owner_reason_valid and not (
                    lookup == LOOKUP_KINDS["indeterminate"]
                    and reason == OPERATIONAL_REASONS["none"]
                )
                if valid:
                    _decode_query_response(wire)
                else:
                    _assert_contract_rejection(
                        _decode_query_response,
                        wire,
                        S7_CODEC_ERROR_CODES["invalid_field_value"],
                        11,
                    )


@pytest.mark.parametrize(
    ("changes", "expected_detail"),
    [
        (
            {12: _u16(LOOKUP_KINDS["known"]), 13: _u8(0), 14: bytes(32)},
            13,
        ),
        (
            {
                12: _u16(LOOKUP_KINDS["conflict"]),
                13: _u8(0),
                14: bytes(32),
            },
            13,
        ),
        ({12: _u16(LOOKUP_KINDS["unknown"])}, 13),
        (
            {
                10: _u16(OWNER_STATES["apply_disabled"]),
                11: _u16(OPERATIONAL_REASONS["runtime_busy"]),
                12: _u16(LOOKUP_KINDS["indeterminate"]),
            },
            13,
        ),
        (
            {
                15: _u16(DURABLE_PHASES["terminal"]),
                16: _u8(0),
                17: bytes(16),
            },
            16,
        ),
        (
            {
                15: _u16(DURABLE_PHASES["none"]),
                16: _u8(0),
                17: bytes(16),
            },
            15,
        ),
    ],
)
def test_query_lookup_kind_presence_phase_and_reason_are_cross_bound(
    changes: dict[int, bytes],
    expected_detail: int,
) -> None:
    controls = _build_control_vectors(_build_vectors())
    fields = list(
        _parse_control_frame(
            controls["query_response"]["wire"],
            magic=QUERY_RESPONSE_MAGIC,
            maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
            schema=QUERY_RESPONSE_SCHEMA,
        ).items()
    )
    fields = [(tag, changes.get(tag, value)) for tag, value in fields]
    wire = _resign_control_fields(
        magic=QUERY_RESPONSE_MAGIC,
        fields=fields,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
    )
    with pytest.raises(ContractReject) as rejected:
        _decode_query_response(wire)
    assert rejected.value.code == S7_CODEC_ERROR_CODES["invalid_field_value"]
    assert rejected.value.detail_code == expected_detail


def test_apply_disabled_busy_preserves_known_nonterminal_operation_lookup() -> None:
    controls = _build_control_vectors(_build_vectors())
    wire = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={
            10: _u16(OWNER_STATES["apply_disabled"]),
            11: _u16(OPERATIONAL_REASONS["runtime_busy"]),
            15: _u16(DURABLE_PHASES["prepared_no_effects"]),
            16: _u8(0),
            17: bytes(16),
        },
    )
    decoded = _decode_query_response(wire)
    assert decoded[10] == _u16(OWNER_STATES["apply_disabled"])
    assert decoded[12] == _u16(LOOKUP_KINDS["known"])
    assert decoded[15] == _u16(DURABLE_PHASES["prepared_no_effects"])


def test_recovering_owner_preserves_known_historical_terminal_lookup() -> None:
    controls = _build_control_vectors(_build_vectors())
    wire = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={
            10: _u16(OWNER_STATES["apply_disabled"]),
            11: _u16(OPERATIONAL_REASONS["recovering"]),
            23: _u16(LIVE_STATES["recovering"]),
        },
    )
    decoded = _decode_query_response(wire)
    assert decoded[12] == _u16(LOOKUP_KINDS["known"])
    assert decoded[15] == _u16(DURABLE_PHASES["terminal"])
    assert decoded[23] == _u16(LIVE_STATES["recovering"])


def test_operational_owner_cannot_claim_validated_quarantine_live_state() -> None:
    controls = _build_control_vectors(_build_vectors())
    wire = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={
            23: _u16(LIVE_STATES["validated_operational_quarantine"]),
            24: _u64(0),
        },
    )
    _assert_contract_rejection(
        _decode_query_response,
        wire,
        S7_CODEC_ERROR_CODES["invalid_field_value"],
        23,
    )


@pytest.mark.parametrize(
    ("reason", "live_state", "resource_generation"),
    [
        (
            OPERATIONAL_REASONS["active_compatibility_mismatch"],
            LIVE_STATES["live_ready"],
            1,
        ),
        (
            OPERATIONAL_REASONS["recovery_failed"],
            LIVE_STATES["recovering"],
            0,
        ),
    ],
)
def test_apply_disabled_reason_is_bound_to_its_live_state(
    reason: int, live_state: int, resource_generation: int
) -> None:
    controls = _build_control_vectors(_build_vectors())
    wire = _resigned_control_changes(
        controls["query_response"],
        magic=QUERY_RESPONSE_MAGIC,
        maximum_bytes=MAX_QUERY_RESPONSE_BYTES,
        schema=QUERY_RESPONSE_SCHEMA,
        signing_domain=QUERY_RESPONSE_SIGNING_DOMAIN,
        seed_hex=TEST_ONLY_KEYS["runtime_read_seed_hex"],
        changes={
            10: _u16(OWNER_STATES["apply_disabled"]),
            11: _u16(reason),
            23: _u16(live_state),
            24: _u64(resource_generation),
        },
    )
    _assert_contract_rejection(
        _decode_query_response,
        wire,
        S7_CODEC_ERROR_CODES["invalid_field_value"],
        23,
    )


if __name__ == "__main__":
    print(json.dumps(_fixture_document(), indent=2))
