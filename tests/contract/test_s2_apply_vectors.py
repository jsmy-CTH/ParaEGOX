from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "wire" / "s2_apply_envelope_v1.json"

DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
DIGEST_VERSION = 1
DIGEST_FIELD_MARKER = b"\x01"
DIGEST_END_MARKER = b"\xff"

SIGNING_MAGIC = b"ParaEGOX\0canonical-signing-transcript"
TENURE_SIGNING_DOMAIN = b"paraegox.runtime.writer-tenure.signing.v1"
AUTH_SIGNING_DOMAIN = b"paraegox.runtime.apply-envelope-auth.signing.v1"
TARGET_SLICE_DIGEST_DOMAIN = b"paraegox.runtime.target-slice.sha256.v1"
TENURE_PROOF_DIGEST_DOMAIN = b"paraegox.runtime.writer-tenure-proof.sha256.v1"
APPLY_CONTROL_DIGEST_DOMAIN = b"paraegox.runtime.apply-control.sha256.v1"
REQUEST_DIGEST_DOMAIN = b"paraegox.runtime.apply-envelope.request.sha256.v1"

FRAME_MAGIC = b"ParaEGOX\0runtime-apply-envelope"
FRAME_VERSION = 1
FRAME_FIELD_COUNT = 37
MAX_FRAME_BYTES = 4096

# These deterministic keys are TEST-ONLY protocol fixtures, never production credentials.
TEST_ONLY_KEYS = {
    "tenure_authority_seed_hex": "11" * 32,
    "request_writer_seed_hex": "22" * 32,
}

# Literal inputs mirror the deployment producer's signed fixture. Derived digests and signatures
# are intentionally absent and must be independently reconstructed below.
SEMANTIC = {
    "slice_contract_version": 1,
    "target_hex": "05" * 16,
    "source_scope_hex": "01" * 16,
    "source_plan_hex": "02" * 16,
    "source_revision": 3,
    "source_plan_digest_hex": "04" * 32,
    "assignment_digest_hex": "06" * 32,
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

ERROR_CODES = {
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

PROTOCOL = {
    "frame_magic_hex": FRAME_MAGIC.hex(),
    "frame_version": FRAME_VERSION,
    "frame_field_count": FRAME_FIELD_COUNT,
    "max_frame_bytes": MAX_FRAME_BYTES,
    "tlv_header": "tag:u16-be,length:u32-be",
    "digest_magic_hex": DIGEST_MAGIC.hex(),
    "digest_version": DIGEST_VERSION,
    "digest_field_framing": "marker:u8=1,ordinal:u32-be,length:u64-be",
    "digest_terminator": "marker:u8=255,field_count:u32-be",
    "target_slice_digest_domain_hex": TARGET_SLICE_DIGEST_DOMAIN.hex(),
    "tenure_proof_digest_domain_hex": TENURE_PROOF_DIGEST_DOMAIN.hex(),
    "apply_control_digest_domain_hex": APPLY_CONTROL_DIGEST_DOMAIN.hex(),
    "signing_magic_hex": SIGNING_MAGIC.hex(),
    "tenure_signing_version": 1,
    "tenure_signing_domain_hex": TENURE_SIGNING_DOMAIN.hex(),
    "tenure_signing_field_count": 9,
    "request_signing_version": 1,
    "request_signing_domain_hex": AUTH_SIGNING_DOMAIN.hex(),
    "request_signing_field_count": 36,
    "request_digest_domain_hex": REQUEST_DIGEST_DOMAIN.hex(),
}

FIELD_NAMES = {
    1: "slice_contract_version",
    2: "target",
    3: "source_scope",
    4: "source_plan",
    5: "source_revision",
    6: "source_plan_digest",
    7: "assignment_digest",
    8: "target_slice_digest",
    9: "writer",
    10: "writer_epoch",
    11: "tenure_authority",
    12: "tenure_key",
    13: "tenure_algorithm",
    14: "tenure_algorithm_version",
    15: "tenure_claim_scope",
    16: "tenure_claim_writer",
    17: "tenure_claim_epoch",
    18: "supersedes_through_epoch",
    19: "tenure_nonce",
    20: "tenure_signature",
    21: "tenure_proof_envelope_digest",
    22: "expected_active_tag",
    23: "expected_active_digest",
    24: "operation_id",
    25: "apply_control_commitment_digest",
    26: "temporal_version",
    27: "temporal_constraint_id",
    28: "clock_domain",
    29: "clock_generation",
    30: "original_budget_nanos",
    31: "remaining_budget_nanos",
    32: "auth_principal",
    33: "auth_key",
    34: "auth_algorithm",
    35: "auth_algorithm_version",
    36: "auth_nonce",
    37: "auth_signature",
}


class WireReject(Exception):
    def __init__(self, code: int, field_tag: int | None = None) -> None:
        super().__init__(f"wire rejection code={code} field={field_tag}")
        self.code = code
        self.field_tag = field_tag


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _semantic_bytes(name: str) -> bytes:
    value = SEMANTIC[name]
    assert isinstance(value, str)
    return bytes.fromhex(value)


def _tlv(tag: int, value: bytes) -> bytes:
    return _u16(tag) + _u32(len(value)) + value


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


def _signing_transcript(domain: bytes, fields: list[tuple[int, str, bytes]]) -> bytes:
    encoded = bytearray(SIGNING_MAGIC)
    encoded += _u16(1)
    encoded += _u16(len(domain))
    encoded += domain
    encoded += _u16(len(fields))
    for tag, _name, value in fields:
        encoded += _tlv(tag, value)
    return bytes(encoded)


def _build_vector() -> dict[str, object]:
    target = _semantic_bytes("target_hex")
    scope = _semantic_bytes("source_scope_hex")
    plan = _semantic_bytes("source_plan_hex")
    source_plan_digest = _semantic_bytes("source_plan_digest_hex")
    assignment_digest = _semantic_bytes("assignment_digest_hex")
    writer = _semantic_bytes("writer_hex")
    authority = _semantic_bytes("tenure_authority_hex")
    tenure_key_ref = _semantic_bytes("tenure_key_hex")
    tenure_nonce = _semantic_bytes("tenure_nonce_hex")

    slice_version = _u16(int(SEMANTIC["slice_contract_version"]))
    source_revision = _u64(int(SEMANTIC["source_revision"]))
    writer_epoch = _u64(int(SEMANTIC["writer_epoch"]))
    tenure_algorithm = _u16(int(SEMANTIC["tenure_algorithm"]))
    tenure_algorithm_version = _u16(int(SEMANTIC["tenure_algorithm_version"]))
    supersedes_epoch = _u64(int(SEMANTIC["supersedes_through_epoch"]))

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
        (1, "tenure_authority", authority),
        (2, "tenure_key", tenure_key_ref),
        (3, "tenure_algorithm", tenure_algorithm),
        (4, "tenure_algorithm_version", tenure_algorithm_version),
        (5, "source_scope", scope),
        (6, "writer", writer),
        (7, "writer_epoch", writer_epoch),
        (8, "supersedes_through_epoch", supersedes_epoch),
        (9, "tenure_nonce", tenure_nonce),
    ]
    tenure_transcript = _signing_transcript(TENURE_SIGNING_DOMAIN, tenure_fields)
    tenure_private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(TEST_ONLY_KEYS["tenure_authority_seed_hex"])
    )
    tenure_public_key = tenure_private_key.public_key().public_bytes_raw()
    tenure_signature = tenure_private_key.sign(tenure_transcript)
    tenure_proof_digest = _canonical_digest(
        TENURE_PROOF_DIGEST_DOMAIN,
        [
            authority,
            tenure_key_ref,
            tenure_algorithm,
            tenure_algorithm_version,
            scope,
            writer,
            writer_epoch,
            supersedes_epoch,
            tenure_nonce,
            tenure_signature,
        ],
    )

    expected_active_tag = _u16(int(SEMANTIC["expected_active_tag"]))
    expected_active_digest = _semantic_bytes("expected_active_digest_hex")
    operation_id = _semantic_bytes("operation_id_hex")
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
            tenure_proof_digest,
            expected_active_tag,
            expected_active_digest,
            operation_id,
        ],
    )

    unsigned_fields = [
        (1, FIELD_NAMES[1], slice_version),
        (2, FIELD_NAMES[2], target),
        (3, FIELD_NAMES[3], scope),
        (4, FIELD_NAMES[4], plan),
        (5, FIELD_NAMES[5], source_revision),
        (6, FIELD_NAMES[6], source_plan_digest),
        (7, FIELD_NAMES[7], assignment_digest),
        (8, FIELD_NAMES[8], target_slice_digest),
        (9, FIELD_NAMES[9], writer),
        (10, FIELD_NAMES[10], writer_epoch),
        (11, FIELD_NAMES[11], authority),
        (12, FIELD_NAMES[12], tenure_key_ref),
        (13, FIELD_NAMES[13], tenure_algorithm),
        (14, FIELD_NAMES[14], tenure_algorithm_version),
        (15, FIELD_NAMES[15], scope),
        (16, FIELD_NAMES[16], writer),
        (17, FIELD_NAMES[17], writer_epoch),
        (18, FIELD_NAMES[18], supersedes_epoch),
        (19, FIELD_NAMES[19], tenure_nonce),
        (20, FIELD_NAMES[20], tenure_signature),
        (21, FIELD_NAMES[21], tenure_proof_digest),
        (22, FIELD_NAMES[22], expected_active_tag),
        (23, FIELD_NAMES[23], expected_active_digest),
        (24, FIELD_NAMES[24], operation_id),
        (25, FIELD_NAMES[25], control_digest),
        (26, FIELD_NAMES[26], _u16(int(SEMANTIC["temporal_version"]))),
        (27, FIELD_NAMES[27], _semantic_bytes("temporal_constraint_id_hex")),
        (28, FIELD_NAMES[28], _semantic_bytes("clock_domain_hex")),
        (29, FIELD_NAMES[29], _u64(int(SEMANTIC["clock_generation"]))),
        (30, FIELD_NAMES[30], _u64(int(SEMANTIC["original_budget_nanos"]))),
        (31, FIELD_NAMES[31], _u64(int(SEMANTIC["remaining_budget_nanos"]))),
        (32, FIELD_NAMES[32], _semantic_bytes("auth_principal_hex")),
        (33, FIELD_NAMES[33], _semantic_bytes("auth_key_hex")),
        (34, FIELD_NAMES[34], _u16(int(SEMANTIC["auth_algorithm"]))),
        (35, FIELD_NAMES[35], _u16(int(SEMANTIC["auth_algorithm_version"]))),
        (36, FIELD_NAMES[36], _semantic_bytes("auth_nonce_hex")),
    ]
    request_transcript = _signing_transcript(AUTH_SIGNING_DOMAIN, unsigned_fields)
    request_private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(TEST_ONLY_KEYS["request_writer_seed_hex"])
    )
    request_public_key = request_private_key.public_key().public_bytes_raw()
    request_signature = request_private_key.sign(request_transcript)
    fields = [*unsigned_fields, (37, FIELD_NAMES[37], request_signature)]

    wire = bytearray(FRAME_MAGIC)
    wire += _u16(FRAME_VERSION)
    wire += _u16(FRAME_FIELD_COUNT)
    for tag, _name, value in fields:
        wire += _tlv(tag, value)
    canonical_wire = bytes(wire)
    request_digest = _canonical_digest(REQUEST_DIGEST_DOMAIN, [canonical_wire])

    return {
        "fields": fields,
        "target_slice_digest": target_slice_digest,
        "tenure_public_key": tenure_public_key,
        "tenure_transcript": tenure_transcript,
        "tenure_signature": tenure_signature,
        "tenure_proof_digest": tenure_proof_digest,
        "control_digest": control_digest,
        "request_public_key": request_public_key,
        "request_transcript": request_transcript,
        "request_signature": request_signature,
        "canonical_wire": canonical_wire,
        "request_digest": request_digest,
    }


def _valid_field_length(tag: int, length: int) -> bool:
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


def _read_u16(value: bytes) -> int:
    return struct.unpack(">H", value)[0]


def _read_u64(value: bytes) -> int:
    return struct.unpack(">Q", value)[0]


def _parse_wire(frame: bytes) -> list[tuple[int, bytes]]:
    if len(frame) > MAX_FRAME_BYTES:
        raise WireReject(ERROR_CODES["frame_too_large"])
    header_length = len(FRAME_MAGIC) + 4
    if len(frame) < header_length:
        raise WireReject(ERROR_CODES["truncated"])
    if frame[: len(FRAME_MAGIC)] != FRAME_MAGIC:
        raise WireReject(ERROR_CODES["invalid_magic"])

    cursor = len(FRAME_MAGIC)
    version, declared_count = struct.unpack_from(">HH", frame, cursor)
    cursor += 4
    if version != FRAME_VERSION:
        raise WireReject(ERROR_CODES["unsupported_version"])

    fields = []
    for index in range(declared_count):
        expected_tag = index + 1
        if cursor + 6 > len(frame):
            raise WireReject(ERROR_CODES["truncated"])
        tag, value_length = struct.unpack_from(">HI", frame, cursor)
        cursor += 6
        if tag == 0 or tag > FRAME_FIELD_COUNT:
            raise WireReject(ERROR_CODES["unknown_field"], tag)
        if tag < expected_tag:
            raise WireReject(ERROR_CODES["duplicate_field"], tag)
        if tag > expected_tag:
            raise WireReject(ERROR_CODES["out_of_order_field"], tag)
        if not _valid_field_length(tag, value_length):
            raise WireReject(ERROR_CODES["invalid_field_length"], tag)
        value_end = cursor + value_length
        if value_end > len(frame):
            raise WireReject(ERROR_CODES["truncated"], tag)
        fields.append((tag, frame[cursor:value_end]))
        cursor = value_end

    if declared_count < FRAME_FIELD_COUNT:
        raise WireReject(ERROR_CODES["missing_field"], declared_count + 1)
    if cursor != len(frame):
        raise WireReject(ERROR_CODES["trailing_bytes"])
    return fields


def _encode_frame(
    fields: list[tuple[int, bytes]],
    *,
    version: int = FRAME_VERSION,
    declared_count: int | None = None,
) -> bytes:
    encoded = bytearray(FRAME_MAGIC)
    encoded += _u16(version)
    encoded += _u16(len(fields) if declared_count is None else declared_count)
    for tag, value in fields:
        encoded += _tlv(tag, value)
    return bytes(encoded)


def _replace_field_value(frame: bytes, tag: int, value: bytes) -> bytes:
    fields = _parse_wire(frame)
    original_tag, original_value = fields[tag - 1]
    assert original_tag == tag
    assert len(original_value) == len(value)
    fields[tag - 1] = (tag, value)
    return _encode_frame(fields)


def _refresh_tenure_digest(frame: bytes) -> bytes:
    fields = _parse_wire(frame)
    values = dict(fields)
    digest = _canonical_digest(
        TENURE_PROOF_DIGEST_DOMAIN,
        [values[tag] for tag in range(11, 21)],
    )
    return _replace_field_value(frame, 21, digest)


def _validate_wire(
    frame: bytes,
    tenure_public_key: bytes,
    request_public_key: bytes,
) -> dict[str, object]:
    fields = _parse_wire(frame)
    values = dict(fields)

    if _read_u16(values[1]) != 1:
        raise WireReject(ERROR_CODES["unsupported_version"], 1)
    target_slice_digest = _canonical_digest(
        TARGET_SLICE_DIGEST_DOMAIN,
        [values[tag] for tag in range(1, 8)],
    )
    if values[8] != target_slice_digest:
        raise WireReject(ERROR_CODES["derived_digest_mismatch"], 8)

    if _read_u16(values[13]) == 0:
        raise WireReject(ERROR_CODES["invalid_field_value"], 13)
    if _read_u16(values[14]) == 0:
        raise WireReject(ERROR_CODES["invalid_field_value"], 14)
    writer_epoch = _read_u64(values[17])
    if writer_epoch == 0:
        raise WireReject(ERROR_CODES["invalid_field_value"], 17)
    if _read_u64(values[18]) >= writer_epoch:
        raise WireReject(ERROR_CODES["invalid_field_value"], 18)

    tenure_proof_digest = _canonical_digest(
        TENURE_PROOF_DIGEST_DOMAIN,
        [values[tag] for tag in range(11, 21)],
    )
    if values[21] != tenure_proof_digest:
        raise WireReject(ERROR_CODES["derived_digest_mismatch"], 21)
    if values[9] != values[16]:
        raise WireReject(ERROR_CODES["invalid_field_value"], 9)
    if values[10] != values[17]:
        raise WireReject(ERROR_CODES["invalid_field_value"], 10)
    if values[3] != values[15]:
        raise WireReject(ERROR_CODES["invalid_field_value"], 15)

    expected_active_tag = _read_u16(values[22])
    if not ((expected_active_tag == 0 and values[23] == bytes(32)) or expected_active_tag == 1):
        raise WireReject(ERROR_CODES["invalid_field_value"], 22)
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
        raise WireReject(ERROR_CODES["derived_digest_mismatch"], 25)

    if _read_u64(values[29]) == 0:
        raise WireReject(ERROR_CODES["invalid_field_value"], 29)
    if _read_u16(values[26]) != 1:
        raise WireReject(ERROR_CODES["unsupported_version"], 26)
    original_budget = _read_u64(values[30])
    if original_budget == 0:
        raise WireReject(ERROR_CODES["invalid_field_value"], 30)
    if _read_u64(values[31]) > original_budget:
        raise WireReject(ERROR_CODES["invalid_field_value"], 31)

    if _read_u16(values[34]) == 0:
        raise WireReject(ERROR_CODES["invalid_field_value"], 34)
    if _read_u16(values[35]) == 0:
        raise WireReject(ERROR_CODES["invalid_field_value"], 35)

    if _encode_frame(fields) != frame:
        raise WireReject(ERROR_CODES["non_canonical_frame"])

    tenure_fields = [
        (transcript_tag, FIELD_NAMES[wire_tag], values[wire_tag])
        for transcript_tag, wire_tag in enumerate(range(11, 20), start=1)
    ]
    tenure_transcript = _signing_transcript(TENURE_SIGNING_DOMAIN, tenure_fields)
    Ed25519PublicKey.from_public_bytes(tenure_public_key).verify(values[20], tenure_transcript)

    request_fields = [(tag, FIELD_NAMES[tag], values[tag]) for tag in range(1, FRAME_FIELD_COUNT)]
    request_transcript = _signing_transcript(AUTH_SIGNING_DOMAIN, request_fields)
    Ed25519PublicKey.from_public_bytes(request_public_key).verify(values[37], request_transcript)

    return {
        "fields": fields,
        "target_slice_digest": target_slice_digest,
        "tenure_proof_digest": tenure_proof_digest,
        "control_digest": control_digest,
        "tenure_transcript": tenure_transcript,
        "request_transcript": request_transcript,
        "request_digest": _canonical_digest(REQUEST_DIGEST_DOMAIN, [frame]),
    }


def _load_fixture() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _fixture_wire_and_public_keys() -> tuple[bytes, bytes, bytes]:
    fixture = _load_fixture()
    expected = fixture["expected"]
    assert isinstance(expected, dict)
    canonical_wire_hex = expected["canonical_wire_hex"]
    tenure_public_key_hex = expected["tenure_public_key_hex"]
    request_public_key_hex = expected["request_public_key_hex"]
    assert isinstance(canonical_wire_hex, str)
    assert isinstance(tenure_public_key_hex, str)
    assert isinstance(request_public_key_hex, str)
    return (
        bytes.fromhex(canonical_wire_hex),
        bytes.fromhex(tenure_public_key_hex),
        bytes.fromhex(request_public_key_hex),
    )


def _wire_field_records(fields: list[tuple[int, str, bytes]]) -> list[dict[str, object]]:
    return [
        {"tag": tag, "name": name, "length": len(value), "value_hex": value.hex()}
        for tag, name, value in fields
    ]


def test_independent_rebuild_matches_signed_deployment_fixture() -> None:
    fixture = _load_fixture()
    assert fixture["fixture_version"] == 1
    assert fixture["source"] == (
        "crates/paraegox-deployment/src/envelope.rs TEST-ONLY signed fixture literals"
    )
    assert fixture["test_only_notice"] == "TEST-ONLY deterministic keys; never production"
    assert fixture["test_only_keys"] == TEST_ONLY_KEYS
    assert fixture["semantic"] == SEMANTIC
    assert fixture["protocol"] == PROTOCOL
    assert fixture["error_codes"] == ERROR_CODES

    vector = _build_vector()
    expected = fixture["expected"]
    assert isinstance(expected, dict)
    for name in (
        "target_slice_digest",
        "tenure_public_key",
        "tenure_transcript",
        "tenure_signature",
        "tenure_proof_digest",
        "control_digest",
        "request_public_key",
        "request_transcript",
        "request_signature",
        "canonical_wire",
        "request_digest",
    ):
        value = vector[name]
        assert isinstance(value, bytes)
        assert value.hex() == expected[f"{name}_hex"]

    fields = vector["fields"]
    assert isinstance(fields, list)
    assert _wire_field_records(fields) == fixture["wire_fields"]
    assert len(vector["tenure_transcript"]) == expected["tenure_transcript_length"]
    assert len(vector["request_transcript"]) == expected["request_transcript_length"]
    assert len(vector["canonical_wire"]) == expected["canonical_wire_length"]


def test_real_ed25519_signatures_verify_and_bind_transcripts() -> None:
    wire, tenure_public_key_bytes, request_public_key_bytes = _fixture_wire_and_public_keys()
    validated = _validate_wire(wire, tenure_public_key_bytes, request_public_key_bytes)
    parsed = dict(_parse_wire(wire))
    tenure_transcript = validated["tenure_transcript"]
    request_transcript = validated["request_transcript"]
    assert isinstance(tenure_transcript, bytes)
    assert isinstance(request_transcript, bytes)
    tenure_public_key = Ed25519PublicKey.from_public_bytes(tenure_public_key_bytes)
    request_public_key = Ed25519PublicKey.from_public_bytes(request_public_key_bytes)
    tenure_public_key.verify(parsed[20], tenure_transcript)
    request_public_key.verify(parsed[37], request_transcript)

    changed_tenure = bytearray(tenure_transcript)
    changed_tenure[-1] ^= 1
    with pytest.raises(InvalidSignature):
        tenure_public_key.verify(parsed[20], changed_tenure)

    changed_request = bytearray(request_transcript)
    changed_request[-1] ^= 1
    with pytest.raises(InvalidSignature):
        request_public_key.verify(parsed[37], changed_request)


def test_independent_parser_consumes_fixture_and_validates_semantics() -> None:
    fixture = _load_fixture()
    expected = fixture["expected"]
    assert isinstance(expected, dict)
    wire, tenure_public_key, request_public_key = _fixture_wire_and_public_keys()
    parsed = _parse_wire(wire)
    assert [
        {
            "tag": tag,
            "name": FIELD_NAMES[tag],
            "length": len(value),
            "value_hex": value.hex(),
        }
        for tag, value in parsed
    ] == fixture["wire_fields"]

    validated = _validate_wire(wire, tenure_public_key, request_public_key)
    for name in (
        "target_slice_digest",
        "tenure_proof_digest",
        "control_digest",
        "tenure_transcript",
        "request_transcript",
        "request_digest",
    ):
        value = validated[name]
        assert isinstance(value, bytes)
        assert value.hex() == expected[f"{name}_hex"]

    cursor = len(FRAME_MAGIC) + 4
    for tag, value in parsed:
        assert wire[cursor : cursor + 2] == _u16(tag)
        assert wire[cursor + 2 : cursor + 6] == _u32(len(value))
        assert wire[cursor + 6 : cursor + 6 + len(value)] == value
        cursor += 6 + len(value)
    assert cursor == len(wire)


def _assert_wire_reject(
    frame: bytes,
    expected_code: int,
    expected_field: int | None,
) -> None:
    _, tenure_public_key, request_public_key = _fixture_wire_and_public_keys()
    with pytest.raises(WireReject) as rejection:
        _validate_wire(frame, tenure_public_key, request_public_key)
    assert (rejection.value.code, rejection.value.field_tag) == (
        expected_code,
        expected_field,
    )


def test_fixed_wire_semantic_error_conformance() -> None:
    wire, _, _ = _fixture_wire_and_public_keys()

    tag_35_zero = _replace_field_value(wire, 35, _u16(0))
    _assert_wire_reject(tag_35_zero, ERROR_CODES["invalid_field_value"], 35)

    tag_34_zero = _replace_field_value(wire, 34, _u16(0))
    _assert_wire_reject(tag_34_zero, ERROR_CODES["invalid_field_value"], 34)

    tag_8_derived = _replace_field_value(wire, 8, bytes([0xFF]) * 32)
    _assert_wire_reject(tag_8_derived, ERROR_CODES["derived_digest_mismatch"], 8)

    tag_21_derived = _replace_field_value(wire, 21, bytes([0xFF]) * 32)
    _assert_wire_reject(tag_21_derived, ERROR_CODES["derived_digest_mismatch"], 21)

    tag_25_derived = _replace_field_value(wire, 25, bytes([0xFF]) * 32)
    _assert_wire_reject(tag_25_derived, ERROR_CODES["derived_digest_mismatch"], 25)

    tag_30_zero = _replace_field_value(wire, 30, _u64(0))
    _assert_wire_reject(tag_30_zero, ERROR_CODES["invalid_field_value"], 30)

    tag_31_extended = _replace_field_value(wire, 31, _u64(101))
    _assert_wire_reject(tag_31_extended, ERROR_CODES["invalid_field_value"], 31)

    tag_26_version = _replace_field_value(wire, 26, _u16(2))
    _assert_wire_reject(tag_26_version, ERROR_CODES["unsupported_version"], 26)

    tag_22_expected_active = _replace_field_value(wire, 22, _u16(2))
    _assert_wire_reject(
        tag_22_expected_active,
        ERROR_CODES["invalid_field_value"],
        22,
    )


def test_fixed_wire_rejects_duplicate_writer_scope_and_epoch_claims() -> None:
    wire, _, _ = _fixture_wire_and_public_keys()

    writer_mismatch = _replace_field_value(wire, 16, bytes([0x19]) * 16)
    writer_mismatch = _refresh_tenure_digest(writer_mismatch)
    _assert_wire_reject(writer_mismatch, ERROR_CODES["invalid_field_value"], 9)

    scope_mismatch = _replace_field_value(wire, 15, bytes([0x31]) * 16)
    scope_mismatch = _refresh_tenure_digest(scope_mismatch)
    _assert_wire_reject(scope_mismatch, ERROR_CODES["invalid_field_value"], 15)

    epoch_mismatch = _replace_field_value(wire, 17, _u64(2))
    epoch_mismatch = _refresh_tenure_digest(epoch_mismatch)
    _assert_wire_reject(epoch_mismatch, ERROR_CODES["invalid_field_value"], 10)


def test_fixed_wire_structural_error_conformance() -> None:
    wire, _, _ = _fixture_wire_and_public_keys()
    fields = _parse_wire(wire)

    duplicate_fields = fields.copy()
    duplicate_fields[1] = (1, duplicate_fields[1][1])
    _assert_wire_reject(
        _encode_frame(duplicate_fields),
        ERROR_CODES["duplicate_field"],
        1,
    )

    missing_fields = fields[:-1]
    _assert_wire_reject(
        _encode_frame(missing_fields),
        ERROR_CODES["missing_field"],
        37,
    )

    out_of_order_fields = fields.copy()
    out_of_order_fields[0], out_of_order_fields[1] = (
        out_of_order_fields[1],
        out_of_order_fields[0],
    )
    _assert_wire_reject(
        _encode_frame(out_of_order_fields),
        ERROR_CODES["out_of_order_field"],
        2,
    )

    _assert_wire_reject(wire[:-1], ERROR_CODES["truncated"], 37)
    _assert_wire_reject(wire + b"\0", ERROR_CODES["trailing_bytes"], None)


def test_independent_parser_maps_unknown_version_and_oversize_codes() -> None:
    wire, _, _ = _fixture_wire_and_public_keys()
    fields = _parse_wire(wire)

    _assert_wire_reject(
        _encode_frame(fields, version=2),
        ERROR_CODES["unsupported_version"],
        None,
    )

    _assert_wire_reject(
        _encode_frame([*fields, (38, b"\0")]),
        ERROR_CODES["unknown_field"],
        38,
    )

    oversized = wire + bytes(MAX_FRAME_BYTES + 1 - len(wire))
    _assert_wire_reject(oversized, ERROR_CODES["frame_too_large"], None)
