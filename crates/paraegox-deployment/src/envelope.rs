//! Pure deployment-side producer for signed B2 apply envelopes.

use core::fmt;

use paraegox_runtime_contracts::apply::{ApplyOperationId, ExpectedActive};
use paraegox_runtime_contracts::temporal::ApplyTemporalConstraint;
use paraegox_runtime_contracts::wire::{
    ApplyRequestAuthClaim, EnvelopeContractError, RuntimeApplyEnvelopeDraft,
};

use crate::plan::{CommittedTargetProjection, DeploymentWriterTenure};
use crate::projection::{
    ProjectionError, build_runtime_apply_control_commitment, project_runtime_slice_commitment,
};

/// Builds the signature-independent form of one canonical B2 apply envelope.
///
/// The returned draft exposes the complete request-authentication transcript.
/// Its caller owns signing that transcript outside this pure producer and then
/// finalizing the draft with the resulting signature bytes. This function does
/// not hold a signing key, choose a signer, perform I/O, or access a clock.
pub fn build_runtime_apply_envelope_draft(
    projection: &CommittedTargetProjection,
    tenure: DeploymentWriterTenure,
    expected_active: ExpectedActive,
    operation_id: ApplyOperationId,
    temporal: ApplyTemporalConstraint,
    auth_claim: ApplyRequestAuthClaim,
) -> Result<RuntimeApplyEnvelopeDraft, EnvelopeBuildError> {
    let slice = project_runtime_slice_commitment(projection)?;
    let control_commitment =
        build_runtime_apply_control_commitment(slice, tenure, expected_active, operation_id)?;
    RuntimeApplyEnvelopeDraft::try_new(control_commitment, temporal, auth_claim)
        .map_err(EnvelopeBuildError::Envelope)
}

/// Fail-closed errors raised before a B2 apply envelope can be signed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeBuildError {
    /// Deployment projection or writer-tenure mapping failed.
    Projection(ProjectionError),
    /// Runtime-owned B2 draft validation failed.
    Envelope(EnvelopeContractError),
}

impl From<ProjectionError> for EnvelopeBuildError {
    fn from(value: ProjectionError) -> Self {
        Self::Projection(value)
    }
}

impl fmt::Display for EnvelopeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Projection(error) => write!(formatter, "apply projection failed: {error}"),
            Self::Envelope(error) => write!(formatter, "apply envelope draft failed: {error}"),
        }
    }
}

impl std::error::Error for EnvelopeBuildError {}

#[cfg(test)]
mod tests {
    use core::ops::Range;

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};
    use paraegox_runtime_contracts::apply::{
        ApplyContractError, ApplyOperationId, ExpectedActive, PlanWriterEpoch, PlanWriterRef,
        TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
        WriterTenureClaim, WriterTenureProof, WriterTenureSigningTranscript,
    };
    use paraegox_runtime_contracts::provenance::{
        SourcePlanDigest, SourceScopeRef, TargetAssignmentDigest,
    };
    use paraegox_runtime_contracts::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
    use paraegox_runtime_contracts::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim, RuntimeApplyEnvelope,
        RuntimeApplyEnvelopeDraft, WireErrorCode,
    };

    use crate::plan::{
        CommittedPlanIdentity, CommittedTargetProjection, DeploymentId, DeploymentRevision,
        DeploymentScopeId, DeploymentWriterEpoch, DeploymentWriterRef, DeploymentWriterTenure,
    };
    use crate::projection::ProjectionError;

    use super::{EnvelopeBuildError, build_runtime_apply_envelope_draft};

    // TEST-ONLY fixed seed. Production code never holds a tenure-authority signing key.
    const TEST_ONLY_TENURE_AUTHORITY_SEED: [u8; 32] = [0x11; 32];
    // TEST-ONLY fixed seed. Production code delegates request signing to its caller.
    const TEST_ONLY_WRITER_SEED: [u8; 32] = [0x22; 32];
    const S2_APPLY_VECTOR_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s2_apply_envelope_v1.json");
    const APPLY_ENVELOPE_MAGIC: &[u8] = b"ParaEGOX\0runtime-apply-envelope";

    struct TlvLocation {
        tag_offset: usize,
        value: Range<usize>,
        whole: Range<usize>,
    }

    fn fixture_hex(name: &str) -> Vec<u8> {
        let marker = format!("\"{name}\": \"");
        let Some(value_start) = S2_APPLY_VECTOR_JSON
            .find(&marker)
            .map(|offset| offset + marker.len())
        else {
            panic!("S2 fixture must contain {name}");
        };
        let Some(value_length) = S2_APPLY_VECTOR_JSON[value_start..].find('"') else {
            panic!("S2 fixture value {name} must be terminated");
        };
        let value = &S2_APPLY_VECTOR_JSON[value_start..value_start + value_length];
        assert!(
            value.len().is_multiple_of(2),
            "S2 fixture hex must have byte pairs"
        );
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|digits| (hex_digit(digits[0]) << 4) | hex_digit(digits[1]))
            .collect()
    }

    const fn hex_digit(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => panic!("S2 fixture contains non-hex data"),
        }
    }

    fn tlv_location(frame: &[u8], wanted_tag: u16) -> TlvLocation {
        assert!(frame.starts_with(APPLY_ENVELOPE_MAGIC));
        let count_offset = APPLY_ENVELOPE_MAGIC.len() + 2;
        let declared_count = u16::from_be_bytes([frame[count_offset], frame[count_offset + 1]]);
        let mut cursor = count_offset + 2;
        for _ in 0..declared_count {
            let whole_start = cursor;
            let tag = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]);
            let value_length = u32::from_be_bytes([
                frame[cursor + 2],
                frame[cursor + 3],
                frame[cursor + 4],
                frame[cursor + 5],
            ]) as usize;
            cursor += 6;
            let value = cursor..cursor + value_length;
            cursor = value.end;
            if tag == wanted_tag {
                return TlvLocation {
                    tag_offset: whole_start,
                    value,
                    whole: whole_start..cursor,
                };
            }
        }
        panic!("canonical S2 fixture must contain tag {wanted_tag}");
    }

    fn replace_fixture_value(frame: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
        let location = tlv_location(frame, tag);
        assert_eq!(location.value.len(), value.len());
        let mut changed = frame.to_vec();
        changed[location.value].copy_from_slice(value);
        changed
    }

    fn assert_fixture_rejection(
        frame: &[u8],
        expected_code: WireErrorCode,
        expected_field: Option<u16>,
    ) {
        let Err(error) = RuntimeApplyEnvelope::decode(frame) else {
            panic!("mutated S2 fixture must be rejected");
        };
        assert_eq!(error.code(), expected_code);
        assert_eq!(error.field_tag(), expected_field);
    }

    fn projection() -> CommittedTargetProjection {
        let plan = CommittedPlanIdentity::new(
            DeploymentScopeId::from_bytes([1; 16]),
            DeploymentId::from_bytes([2; 16]),
            DeploymentRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([4; 32])),
        );
        CommittedTargetProjection::new(
            plan,
            RuntimeHostId::from_bytes([5; 16]),
            TargetAssignmentDigest::new(Digest32::from_bytes([6; 32])),
        )
    }

    fn tenure(scope_byte: u8, epoch: u64) -> DeploymentWriterTenure {
        let writer = PlanWriterRef::from_bytes([9; 16]);
        let Ok(algorithm) = TenureProofAlgorithm::try_new(1) else {
            panic!("test tenure algorithm must be valid");
        };
        let Ok(authority) = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([7; 16]),
            TenureKeyRef::from_bytes([8; 16]),
            algorithm,
            1,
        ) else {
            panic!("test tenure authority must be valid");
        };
        let Ok(claim) = WriterTenureClaim::try_new(
            SourceScopeRef::from_bytes([scope_byte; 16]),
            writer,
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(epoch - 1),
        ) else {
            panic!("test tenure claim must be valid");
        };
        let nonce = b"test-only-tenure-nonce";
        let Ok(transcript) = WriterTenureSigningTranscript::try_new(authority, claim, nonce) else {
            panic!("test tenure transcript must be valid");
        };
        let authority_signing_key = SigningKey::from_bytes(&TEST_ONLY_TENURE_AUTHORITY_SEED);
        let signature = authority_signing_key.sign(transcript.as_bytes());
        assert!(
            authority_signing_key
                .verifying_key()
                .verify_strict(transcript.as_bytes(), &signature)
                .is_ok()
        );
        let Ok(proof) = WriterTenureProof::try_new(authority, claim, nonce, &signature.to_bytes())
        else {
            panic!("signed test tenure proof must be valid");
        };

        DeploymentWriterTenure::new(
            DeploymentWriterRef::from_bytes([9; 16]),
            DeploymentWriterEpoch::new(epoch),
            proof,
        )
    }

    fn temporal(remaining_nanos: u64) -> ApplyTemporalConstraint {
        let Ok(generation) = ClockGeneration::try_new(3) else {
            panic!("test clock generation must be valid");
        };
        let Ok(temporal) = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([10; 16]),
            ClockDomainRef::from_bytes([11; 16]),
            generation,
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(remaining_nanos),
        ) else {
            panic!("test temporal constraint must be valid");
        };
        temporal
    }

    fn auth_claim(nonce: &[u8]) -> ApplyRequestAuthClaim {
        let Ok(algorithm) = ApplyAuthAlgorithm::try_new(1) else {
            panic!("test request-auth algorithm must be valid");
        };
        let Ok(claim) = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([9; 16]),
            ApplyAuthKeyRef::from_bytes([12; 16]),
            algorithm,
            1,
            nonce,
        ) else {
            panic!("test request-auth claim must be valid");
        };
        claim
    }

    fn draft(epoch: u64, remaining_nanos: u64, auth_nonce: &[u8]) -> RuntimeApplyEnvelopeDraft {
        let Ok(draft) = build_runtime_apply_envelope_draft(
            &projection(),
            tenure(1, epoch),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([13; 16]),
            temporal(remaining_nanos),
            auth_claim(auth_nonce),
        ) else {
            panic!("test envelope draft must be valid");
        };
        draft
    }

    fn sign_and_finalize(draft: RuntimeApplyEnvelopeDraft) -> RuntimeApplyEnvelope {
        let Ok(transcript) = draft.signing_transcript() else {
            panic!("test request transcript must be valid");
        };
        let writer_signing_key = SigningKey::from_bytes(&TEST_ONLY_WRITER_SEED);
        let signature = writer_signing_key.sign(transcript.as_bytes());
        assert!(
            writer_signing_key
                .verifying_key()
                .verify_strict(transcript.as_bytes(), &signature)
                .is_ok()
        );
        let Ok(envelope) = draft.finalize(&signature.to_bytes()) else {
            panic!("signed test envelope must finalize");
        };
        envelope
    }

    #[test]
    fn signed_producer_is_stable_and_round_trips() {
        let fixture_wire = fixture_hex("canonical_wire_hex");
        let fixture_request_digest = fixture_hex("request_digest_hex");
        let fixture_request_transcript = fixture_hex("request_transcript_hex");
        let fixture_request_signature = fixture_hex("request_signature_hex");
        let fixture_tenure_transcript = fixture_hex("tenure_transcript_hex");
        let fixture_tenure_signature = fixture_hex("tenure_signature_hex");
        let first_draft = draft(1, 60, b"test-only-request-nonce");
        let second_draft = draft(1, 60, b"test-only-request-nonce");
        let Ok(first_transcript) = first_draft.signing_transcript() else {
            panic!("test request transcript must be valid");
        };
        let Ok(second_transcript) = second_draft.signing_transcript() else {
            panic!("test request transcript must be valid");
        };
        assert_eq!(first_transcript, second_transcript);
        assert_eq!(
            first_transcript.as_bytes(),
            fixture_request_transcript.as_slice()
        );

        let proof = first_draft
            .control_commitment()
            .control()
            .writer_context()
            .proof();
        let Ok(tenure_transcript) = proof.signing_transcript() else {
            panic!("test tenure transcript must be valid");
        };
        assert_eq!(
            tenure_transcript.as_bytes(),
            fixture_tenure_transcript.as_slice()
        );
        assert_eq!(proof.signature(), fixture_tenure_signature);

        let first = sign_and_finalize(first_draft);
        let second = sign_and_finalize(second_draft);
        assert_eq!(first.canonical_wire(), second.canonical_wire());
        assert_eq!(first.request_digest(), second.request_digest());
        assert_eq!(first.canonical_wire(), fixture_wire);
        assert_eq!(
            first.request_digest().as_bytes(),
            fixture_request_digest.as_slice()
        );
        assert_eq!(
            first.authentication().signature(),
            fixture_request_signature
        );

        let Ok(decoded) = RuntimeApplyEnvelope::decode(&fixture_wire) else {
            panic!("independent canonical fixture must decode");
        };
        assert_eq!(decoded, first);
        let Ok(decoded_transcript) = decoded.signing_transcript() else {
            panic!("decoded fixture transcript must rebuild");
        };
        assert_eq!(decoded_transcript.as_bytes(), fixture_request_transcript);
    }

    #[test]
    fn fixed_wire_rejections_have_stable_codes_and_fields() {
        let wire = fixture_hex("canonical_wire_hex");

        for (tag, value, expected_code) in [
            (35, vec![0; 2], WireErrorCode::InvalidFieldValue),
            (8, vec![0xff; 32], WireErrorCode::DerivedDigestMismatch),
            (21, vec![0xff; 32], WireErrorCode::DerivedDigestMismatch),
            (25, vec![0xff; 32], WireErrorCode::DerivedDigestMismatch),
            (30, vec![0; 8], WireErrorCode::InvalidFieldValue),
            (
                31,
                101_u64.to_be_bytes().to_vec(),
                WireErrorCode::InvalidFieldValue,
            ),
            (
                22,
                2_u16.to_be_bytes().to_vec(),
                WireErrorCode::InvalidFieldValue,
            ),
        ] {
            let changed = replace_fixture_value(&wire, tag, &value);
            assert_fixture_rejection(&changed, expected_code, Some(tag));
        }

        let mut duplicate = wire.clone();
        let tag_two = tlv_location(&duplicate, 2);
        duplicate[tag_two.tag_offset..tag_two.tag_offset + 2].copy_from_slice(&1_u16.to_be_bytes());
        assert_fixture_rejection(&duplicate, WireErrorCode::DuplicateField, Some(1));

        let tag_37 = tlv_location(&wire, 37);
        assert_eq!(tag_37.whole.end, wire.len());
        let mut missing = wire[..tag_37.whole.start].to_vec();
        let count_offset = APPLY_ENVELOPE_MAGIC.len() + 2;
        missing[count_offset..count_offset + 2].copy_from_slice(&36_u16.to_be_bytes());
        assert_fixture_rejection(&missing, WireErrorCode::MissingField, Some(37));

        let mut out_of_order = wire.clone();
        let tag_one = tlv_location(&out_of_order, 1);
        out_of_order[tag_one.tag_offset..tag_one.tag_offset + 2]
            .copy_from_slice(&2_u16.to_be_bytes());
        assert_fixture_rejection(&out_of_order, WireErrorCode::OutOfOrderField, Some(2));

        assert_fixture_rejection(&wire[..wire.len() - 1], WireErrorCode::Truncated, Some(37));

        let mut trailing = wire;
        trailing.push(0);
        assert_fixture_rejection(&trailing, WireErrorCode::TrailingBytes, None);
    }

    #[test]
    fn writer_tenure_change_does_not_change_slice() {
        let first = draft(1, 60, b"test-only-request-nonce");
        let second = draft(2, 60, b"test-only-request-nonce");

        assert_eq!(
            first.control_commitment().slice(),
            second.control_commitment().slice()
        );
        assert_eq!(
            first.control_commitment().slice().target_slice_digest(),
            second.control_commitment().slice().target_slice_digest()
        );
        assert_ne!(
            first.control_commitment().commitment_digest(),
            second.control_commitment().commitment_digest()
        );
    }

    #[test]
    fn temporal_and_auth_changes_change_request_digest_and_signature() {
        let baseline = sign_and_finalize(draft(1, 60, b"test-only-request-nonce"));
        let temporal_changed = sign_and_finalize(draft(1, 59, b"test-only-request-nonce"));
        let auth_changed = sign_and_finalize(draft(1, 60, b"test-only-request-noncf"));

        for changed in [&temporal_changed, &auth_changed] {
            assert_eq!(
                baseline.control_commitment().slice(),
                changed.control_commitment().slice()
            );
            assert_ne!(baseline.request_digest(), changed.request_digest());
            assert_ne!(
                baseline.authentication().signature(),
                changed.authentication().signature()
            );
        }
    }

    #[test]
    fn mismatched_tenure_scope_fails_before_signing() {
        let result = build_runtime_apply_envelope_draft(
            &projection(),
            tenure(99, 1),
            ExpectedActive::None,
            ApplyOperationId::from_bytes([13; 16]),
            temporal(60),
            auth_claim(b"test-only-request-nonce"),
        );

        assert_eq!(
            result.err(),
            Some(EnvelopeBuildError::Projection(ProjectionError::Apply(
                ApplyContractError::WriterScopeMismatch
            )))
        );
    }
}
