//! Writer tenure, apply controls, and canonical control commitments.

use core::fmt;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};

use crate::provenance::{
    ProvenanceContractError, RuntimeSliceCommitment, SourceScopeRef, TargetSliceDigest,
};

const WRITER_TENURE_PROOF_ENVELOPE_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.writer-tenure-proof.sha256.v1";
const APPLY_CONTROL_COMMITMENT_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.apply-control.sha256.v1";
const MAX_TENURE_NONCE_BYTES: usize = 64;
const MAX_TENURE_SIGNATURE_BYTES: usize = 512;

macro_rules! opaque_ref {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates an opaque reference from canonical bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Returns the canonical reference bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_ref!(
    PlanWriterRef,
    "Runtime-owned opaque reference to one source-plan writer."
);
opaque_ref!(
    ApplyOperationId,
    "Identity of one apply operation within source scope and target."
);
opaque_ref!(
    TenureAuthorityRef,
    "Identity of the authority that signs writer-tenure proofs."
);
opaque_ref!(
    TenureKeyRef,
    "Identity of the verification key selected by a tenure proof."
);

/// Runtime-owned monotonically ordered writer tenure.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanWriterEpoch(u64);

impl PlanWriterEpoch {
    /// Creates a writer epoch value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the ordered epoch value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Stable registry value for a tenure-proof signature algorithm.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TenureProofAlgorithm(u16);

impl TenureProofAlgorithm {
    /// Creates a non-zero algorithm registry value.
    pub const fn try_new(value: u16) -> Result<Self, TenureProofError> {
        if value == 0 {
            return Err(TenureProofError::InvalidAlgorithm);
        }
        Ok(Self(value))
    }

    /// Returns the algorithm registry value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Authority and algorithm selector carried by a tenure proof.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TenureProofAuthority {
    authority: TenureAuthorityRef,
    key: TenureKeyRef,
    algorithm: TenureProofAlgorithm,
    algorithm_version: u16,
}

impl TenureProofAuthority {
    /// Creates an authority selector with a non-zero algorithm version.
    pub const fn try_new(
        authority: TenureAuthorityRef,
        key: TenureKeyRef,
        algorithm: TenureProofAlgorithm,
        algorithm_version: u16,
    ) -> Result<Self, TenureProofError> {
        if algorithm_version == 0 {
            return Err(TenureProofError::InvalidAlgorithmVersion);
        }
        Ok(Self {
            authority,
            key,
            algorithm,
            algorithm_version,
        })
    }

    /// Returns the issuing authority.
    #[must_use]
    pub const fn authority(self) -> TenureAuthorityRef {
        self.authority
    }

    /// Returns the verification key reference.
    #[must_use]
    pub const fn key(self) -> TenureKeyRef {
        self.key
    }

    /// Returns the signature algorithm selector.
    #[must_use]
    pub const fn algorithm(self) -> TenureProofAlgorithm {
        self.algorithm
    }

    /// Returns the selected algorithm version.
    #[must_use]
    pub const fn algorithm_version(self) -> u16 {
        self.algorithm_version
    }
}

/// Claims bound by an authority-issued writer-tenure proof.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WriterTenureClaim {
    source_scope: SourceScopeRef,
    writer: PlanWriterRef,
    epoch: PlanWriterEpoch,
    supersedes_through_epoch: PlanWriterEpoch,
}

impl WriterTenureClaim {
    /// Creates a claim whose new epoch strictly supersedes the recorded bound.
    pub const fn try_new(
        source_scope: SourceScopeRef,
        writer: PlanWriterRef,
        epoch: PlanWriterEpoch,
        supersedes_through_epoch: PlanWriterEpoch,
    ) -> Result<Self, TenureProofError> {
        if epoch.value() == 0 {
            return Err(TenureProofError::InvalidEpoch);
        }
        if supersedes_through_epoch.value() >= epoch.value() {
            return Err(TenureProofError::InvalidSupersedesEpoch);
        }
        Ok(Self {
            source_scope,
            writer,
            epoch,
            supersedes_through_epoch,
        })
    }

    /// Returns the scope whose writer is fenced.
    #[must_use]
    pub const fn source_scope(self) -> SourceScopeRef {
        self.source_scope
    }

    /// Returns the admitted writer identity.
    #[must_use]
    pub const fn writer(self) -> PlanWriterRef {
        self.writer
    }

    /// Returns the new writer epoch.
    #[must_use]
    pub const fn epoch(self) -> PlanWriterEpoch {
        self.epoch
    }

    /// Returns the highest epoch explicitly superseded by the proof.
    #[must_use]
    pub const fn supersedes_through_epoch(self) -> PlanWriterEpoch {
        self.supersedes_through_epoch
    }
}

/// Bounded authority proof carried with writer context.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WriterTenureProof {
    authority: TenureProofAuthority,
    claim: WriterTenureClaim,
    nonce: Box<[u8]>,
    signature: Box<[u8]>,
}

impl WriterTenureProof {
    /// Creates a bounded proof envelope without interpreting its signature bytes.
    pub fn try_new(
        authority: TenureProofAuthority,
        claim: WriterTenureClaim,
        nonce: &[u8],
        signature: &[u8],
    ) -> Result<Self, TenureProofError> {
        if nonce.is_empty() {
            return Err(TenureProofError::EmptyNonce);
        }
        if nonce.len() > MAX_TENURE_NONCE_BYTES {
            return Err(TenureProofError::NonceTooLong);
        }
        if signature.is_empty() {
            return Err(TenureProofError::EmptySignature);
        }
        if signature.len() > MAX_TENURE_SIGNATURE_BYTES {
            return Err(TenureProofError::SignatureTooLong);
        }
        Ok(Self {
            authority,
            claim,
            nonce: nonce.into(),
            signature: signature.into(),
        })
    }

    /// Returns authority and algorithm selection.
    #[must_use]
    pub const fn authority(&self) -> TenureProofAuthority {
        self.authority
    }

    /// Returns claims covered by the proof.
    #[must_use]
    pub const fn claim(&self) -> WriterTenureClaim {
        self.claim
    }

    /// Returns the bounded anti-replay nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Returns the opaque signature bytes interpreted by the authority verifier.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Computes the canonical fingerprint of the complete proof envelope.
    ///
    /// The signature bytes are part of this fingerprint. It is therefore not a
    /// signing transcript; the future verifier owns that separate contract.
    pub fn envelope_digest(&self) -> Result<Digest32, DigestBuildError> {
        let authority = self.authority();
        let claim = self.claim();
        let mut builder = Digest32Builder::try_new(WRITER_TENURE_PROOF_ENVELOPE_DIGEST_DOMAIN)?;
        builder.field_bytes(authority.authority().as_bytes())?;
        builder.field_bytes(authority.key().as_bytes())?;
        builder.field_u16(authority.algorithm().value())?;
        builder.field_u16(authority.algorithm_version())?;
        builder.field_bytes(claim.source_scope().as_bytes())?;
        builder.field_bytes(claim.writer().as_bytes())?;
        builder.field_u64(claim.epoch().value())?;
        builder.field_u64(claim.supersedes_through_epoch().value())?;
        builder.field_bytes(self.nonce())?;
        builder.field_bytes(self.signature())?;
        Ok(builder.finish())
    }
}

/// Fail-closed construction errors for tenure-proof envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenureProofError {
    /// Algorithm registry value zero is reserved.
    InvalidAlgorithm,
    /// Algorithm version zero is reserved.
    InvalidAlgorithmVersion,
    /// Writer tenure zero is not a valid acquired tenure.
    InvalidEpoch,
    /// A proof cannot claim to supersede its own or a later epoch.
    InvalidSupersedesEpoch,
    /// A proof needs a nonce.
    EmptyNonce,
    /// The nonce exceeds the admitted control-envelope bound.
    NonceTooLong,
    /// A proof needs an authority signature.
    EmptySignature,
    /// The signature exceeds the admitted control-envelope bound.
    SignatureTooLong,
}

impl fmt::Display for TenureProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAlgorithm => formatter.write_str("invalid tenure-proof algorithm"),
            Self::InvalidAlgorithmVersion => {
                formatter.write_str("invalid tenure-proof algorithm version")
            }
            Self::InvalidEpoch => formatter.write_str("invalid writer epoch"),
            Self::InvalidSupersedesEpoch => formatter.write_str("invalid supersedes-through epoch"),
            Self::EmptyNonce => formatter.write_str("tenure proof nonce must not be empty"),
            Self::NonceTooLong => formatter.write_str("tenure proof nonce is too long"),
            Self::EmptySignature => formatter.write_str("tenure proof signature must not be empty"),
            Self::SignatureTooLong => formatter.write_str("tenure proof signature is too long"),
        }
    }
}

impl std::error::Error for TenureProofError {}

/// Complete writer context consumed by Runtime apply admission.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PlanWriterContext {
    writer: PlanWriterRef,
    epoch: PlanWriterEpoch,
    proof: WriterTenureProof,
}

impl PlanWriterContext {
    /// Creates a context only when its duplicated routing fields match the proof.
    pub fn try_new(
        writer: PlanWriterRef,
        epoch: PlanWriterEpoch,
        proof: WriterTenureProof,
    ) -> Result<Self, ApplyContractError> {
        if proof.claim().writer() != writer {
            return Err(ApplyContractError::WriterRefMismatch);
        }
        if proof.claim().epoch() != epoch {
            return Err(ApplyContractError::WriterEpochMismatch);
        }
        Ok(Self {
            writer,
            epoch,
            proof,
        })
    }

    /// Returns the Runtime-owned writer reference.
    #[must_use]
    pub const fn writer(&self) -> PlanWriterRef {
        self.writer
    }

    /// Returns the Runtime-owned writer epoch.
    #[must_use]
    pub const fn epoch(&self) -> PlanWriterEpoch {
        self.epoch
    }

    /// Returns the authority-issued proof envelope.
    #[must_use]
    pub const fn proof(&self) -> &WriterTenureProof {
        &self.proof
    }
}

/// Compare-and-swap expectation for the exact active target slice.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExpectedActive {
    /// The target must not have an active slice for the source scope.
    None,
    /// The target must have exactly this target-slice commitment active.
    Exact(TargetSliceDigest),
}

/// Runtime-owned controls that are deliberately excluded from slice identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeApplyControl {
    writer_context: PlanWriterContext,
    expected_active: ExpectedActive,
    operation_id: ApplyOperationId,
}

impl RuntimeApplyControl {
    /// Creates apply controls after the deployment producer maps writer ownership.
    #[must_use]
    pub const fn new(
        writer_context: PlanWriterContext,
        expected_active: ExpectedActive,
        operation_id: ApplyOperationId,
    ) -> Self {
        Self {
            writer_context,
            expected_active,
            operation_id,
        }
    }

    /// Returns writer tenure and its proof.
    #[must_use]
    pub const fn writer_context(&self) -> &PlanWriterContext {
        &self.writer_context
    }

    /// Returns the exact active-slice CAS input.
    #[must_use]
    pub const fn expected_active(&self) -> ExpectedActive {
        self.expected_active
    }

    /// Returns the idempotency identity for this apply attempt.
    #[must_use]
    pub const fn operation_id(&self) -> ApplyOperationId {
        self.operation_id
    }
}

/// Canonical B1 commitment over target slice identity and non-temporal controls.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeApplyControlCommitment {
    slice: RuntimeSliceCommitment,
    control: RuntimeApplyControl,
    commitment_digest: Digest32,
}

impl RuntimeApplyControlCommitment {
    /// Builds a canonical commitment over the slice commitment and B1 controls.
    pub fn try_new(
        slice: RuntimeSliceCommitment,
        control: RuntimeApplyControl,
    ) -> Result<Self, ApplyContractError> {
        slice.validate()?;
        ensure_writer_scope_matches(&slice, &control)?;
        let commitment_digest = control_commitment_digest(&slice, &control)?;
        Ok(Self {
            slice,
            control,
            commitment_digest,
        })
    }

    /// Returns the tenure-neutral target-slice commitment.
    #[must_use]
    pub const fn slice(&self) -> RuntimeSliceCommitment {
        self.slice
    }

    /// Returns writer, CAS, and operation controls.
    #[must_use]
    pub const fn control(&self) -> &RuntimeApplyControl {
        &self.control
    }

    /// Returns the canonical commitment consumed by B1 idempotency rules.
    #[must_use]
    pub const fn commitment_digest(&self) -> &Digest32 {
        &self.commitment_digest
    }

    /// Recomputes every B1 commitment before control-state admission.
    pub fn validate(&self) -> Result<(), ApplyContractError> {
        self.slice.validate()?;
        ensure_writer_scope_matches(&self.slice, &self.control)?;
        if control_commitment_digest(&self.slice, &self.control)? != self.commitment_digest {
            return Err(ApplyContractError::ControlCommitmentDigestMismatch);
        }
        Ok(())
    }
}

fn ensure_writer_scope_matches(
    slice: &RuntimeSliceCommitment,
    control: &RuntimeApplyControl,
) -> Result<(), ApplyContractError> {
    let slice_scope = slice.header().provenance().source_scope();
    let proof_scope = control.writer_context().proof().claim().source_scope();
    if proof_scope != slice_scope {
        return Err(ApplyContractError::WriterScopeMismatch);
    }
    Ok(())
}

fn control_commitment_digest(
    slice: &RuntimeSliceCommitment,
    control: &RuntimeApplyControl,
) -> Result<Digest32, ApplyContractError> {
    let header = slice.header();
    let provenance = header.provenance();
    let writer = control.writer_context();
    let proof_envelope_digest = writer.proof().envelope_digest()?;
    let (expected_tag, expected_slice_digest) = match control.expected_active() {
        ExpectedActive::None => (0_u16, Digest32::from_bytes([0; 32])),
        ExpectedActive::Exact(digest) => (1_u16, *digest.value()),
    };

    let mut builder = Digest32Builder::try_new(APPLY_CONTROL_COMMITMENT_DIGEST_DOMAIN)?;
    builder.field_digest(slice.target_slice_digest().value())?;
    builder.field_u16(header.contract_version())?;
    builder.field_bytes(header.target().as_bytes())?;
    builder.field_bytes(provenance.source_scope().as_bytes())?;
    builder.field_bytes(provenance.source_plan().as_bytes())?;
    builder.field_u64(provenance.source_revision().value())?;
    builder.field_digest(provenance.source_plan_digest().value())?;
    builder.field_digest(header.assignment_digest().value())?;
    builder.field_bytes(writer.writer().as_bytes())?;
    builder.field_u64(writer.epoch().value())?;
    builder.field_digest(&proof_envelope_digest)?;
    builder.field_u16(expected_tag)?;
    builder.field_digest(&expected_slice_digest)?;
    builder.field_bytes(control.operation_id().as_bytes())?;
    Ok(builder.finish())
}

/// Fail-closed errors while constructing or validating apply commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyContractError {
    /// Canonical digest construction failed.
    Digest(DigestBuildError),
    /// Slice provenance or commitment validation failed.
    Provenance(ProvenanceContractError),
    /// Writer routing identity does not match its authority proof.
    WriterRefMismatch,
    /// Writer routing epoch does not match its authority proof.
    WriterEpochMismatch,
    /// Writer proof scope does not match the slice provenance scope.
    WriterScopeMismatch,
    /// Stored control commitment does not match slice and control fields.
    ControlCommitmentDigestMismatch,
}

impl From<DigestBuildError> for ApplyContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ProvenanceContractError> for ApplyContractError {
    fn from(value: ProvenanceContractError) -> Self {
        Self::Provenance(value)
    }
}

impl fmt::Display for ApplyContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest(error) => write!(formatter, "canonical digest failed: {error}"),
            Self::Provenance(error) => write!(formatter, "slice commitment failed: {error}"),
            Self::WriterRefMismatch => {
                formatter.write_str("writer reference does not match tenure proof")
            }
            Self::WriterEpochMismatch => {
                formatter.write_str("writer epoch does not match tenure proof")
            }
            Self::WriterScopeMismatch => {
                formatter.write_str("writer proof scope does not match slice provenance")
            }
            Self::ControlCommitmentDigestMismatch => {
                formatter.write_str("apply control commitment does not match its fields")
            }
        }
    }
}

impl std::error::Error for ApplyContractError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;

    use crate::provenance::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest,
        TargetSliceDigest,
    };

    use super::{
        ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
        RuntimeApplyControl, RuntimeApplyControlCommitment, TenureAuthorityRef, TenureKeyRef,
        TenureProofAlgorithm, TenureProofAuthority, TenureProofError, WriterTenureClaim,
        WriterTenureProof,
    };

    #[derive(Clone, Copy)]
    struct ProofFixture {
        authority_byte: u8,
        key_byte: u8,
        algorithm: u16,
        algorithm_version: u16,
        scope_byte: u8,
        writer_byte: u8,
        epoch: u64,
        supersedes: u64,
        nonce: &'static [u8],
        signature: &'static [u8],
    }

    const fn proof_fixture() -> ProofFixture {
        ProofFixture {
            authority_byte: 7,
            key_byte: 8,
            algorithm: 1,
            algorithm_version: 1,
            scope_byte: 1,
            writer_byte: 9,
            epoch: 2,
            supersedes: 1,
            nonce: b"nonce",
            signature: b"signature",
        }
    }

    fn build_proof(fixture: ProofFixture) -> WriterTenureProof {
        let Ok(algorithm) = TenureProofAlgorithm::try_new(fixture.algorithm) else {
            panic!("test algorithm must be valid");
        };
        let Ok(authority) = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([fixture.authority_byte; 16]),
            TenureKeyRef::from_bytes([fixture.key_byte; 16]),
            algorithm,
            fixture.algorithm_version,
        ) else {
            panic!("test authority must be valid");
        };
        let Ok(claim) = WriterTenureClaim::try_new(
            SourceScopeRef::from_bytes([fixture.scope_byte; 16]),
            PlanWriterRef::from_bytes([fixture.writer_byte; 16]),
            PlanWriterEpoch::new(fixture.epoch),
            PlanWriterEpoch::new(fixture.supersedes),
        ) else {
            panic!("test claim must be valid");
        };
        let Ok(proof) =
            WriterTenureProof::try_new(authority, claim, fixture.nonce, fixture.signature)
        else {
            panic!("test proof must be valid");
        };
        proof
    }

    fn proof(scope: SourceScopeRef, writer: PlanWriterRef, epoch: u64) -> WriterTenureProof {
        let mut fixture = proof_fixture();
        fixture.scope_byte = scope.as_bytes()[0];
        fixture.writer_byte = writer.as_bytes()[0];
        fixture.epoch = epoch;
        fixture.supersedes = epoch - 1;
        build_proof(fixture)
    }

    fn slice(scope: SourceScopeRef) -> RuntimeSliceCommitment {
        slice_with_assignment(scope, 6)
    }

    fn slice_with_assignment(scope: SourceScopeRef, assignment_byte: u8) -> RuntimeSliceCommitment {
        let provenance = PlanProvenance::new(
            scope,
            SourcePlanRef::from_bytes([2; 16]),
            SourcePlanRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([4; 32])),
        );
        let header = RuntimeSliceHeader::new(
            RuntimeHostId::from_bytes([5; 16]),
            provenance,
            TargetAssignmentDigest::new(Digest32::from_bytes([assignment_byte; 32])),
        );
        let Ok(value) = RuntimeSliceCommitment::try_new(header) else {
            panic!("test slice must be valid");
        };
        value
    }

    fn payload_with_expected(
        epoch: u64,
        expected_active: ExpectedActive,
        operation: u8,
    ) -> RuntimeApplyControlCommitment {
        let scope = SourceScopeRef::from_bytes([1; 16]);
        let writer = PlanWriterRef::from_bytes([9; 16]);
        commitment_from_parts(
            slice(scope),
            proof(scope, writer, epoch),
            expected_active,
            operation,
        )
    }

    fn commitment_from_parts(
        slice: RuntimeSliceCommitment,
        proof: WriterTenureProof,
        expected_active: ExpectedActive,
        operation: u8,
    ) -> RuntimeApplyControlCommitment {
        let claim = proof.claim();
        let Ok(context) = PlanWriterContext::try_new(claim.writer(), claim.epoch(), proof) else {
            panic!("test writer context must be valid");
        };
        let control = RuntimeApplyControl::new(
            context,
            expected_active,
            ApplyOperationId::from_bytes([operation; 16]),
        );
        let Ok(value) = RuntimeApplyControlCommitment::try_new(slice, control) else {
            panic!("test control commitment must be valid");
        };
        value
    }

    fn payload(epoch: u64, operation: u8) -> RuntimeApplyControlCommitment {
        payload_with_expected(epoch, ExpectedActive::None, operation)
    }

    #[test]
    fn proof_envelope_has_a_stable_golden_vector() {
        let Ok(digest) = build_proof(proof_fixture()).envelope_digest() else {
            panic!("test proof fingerprint must build");
        };
        let expected = [
            0x87, 0x59, 0xf9, 0x22, 0x1d, 0x37, 0xf3, 0x10, 0x8d, 0x6d, 0xf0, 0x43, 0x11, 0xc5,
            0xbe, 0x90, 0x47, 0xa6, 0xee, 0x99, 0x41, 0x42, 0xc8, 0x4c, 0xe7, 0xcd, 0x27, 0x4a,
            0xca, 0x19, 0xf5, 0x3f,
        ];

        assert_eq!(digest.as_bytes(), &expected);
    }

    #[test]
    fn every_proof_envelope_field_is_committed() {
        let Ok(baseline) = build_proof(proof_fixture()).envelope_digest() else {
            panic!("baseline proof fingerprint must build");
        };
        let mut variations = [proof_fixture(); 10];
        variations[0].authority_byte = 0x17;
        variations[1].key_byte = 0x18;
        variations[2].algorithm = 2;
        variations[3].algorithm_version = 2;
        variations[4].scope_byte = 0x11;
        variations[5].writer_byte = 0x19;
        variations[6].epoch = 3;
        variations[7].supersedes = 0;
        variations[8].nonce = b"noncf";
        variations[9].signature = b"signaturf";

        for changed in variations {
            let Ok(changed_digest) = build_proof(changed).envelope_digest() else {
                panic!("changed proof fingerprint must build");
            };
            assert_ne!(baseline, changed_digest);
        }
    }

    #[test]
    fn apply_control_has_stable_none_and_exact_vectors() {
        let none = payload_with_expected(2, ExpectedActive::None, 0x0b);
        let exact = payload_with_expected(
            2,
            ExpectedActive::Exact(TargetSliceDigest::new(Digest32::from_bytes([0x0a; 32]))),
            0x0b,
        );
        let expected_none = [
            0xc7, 0xf3, 0x4b, 0xed, 0xb0, 0x18, 0xae, 0xd6, 0x87, 0xf6, 0x13, 0xbf, 0xbc, 0x8e,
            0x36, 0xbb, 0x13, 0xc6, 0xcc, 0x62, 0x18, 0x4d, 0x25, 0x66, 0xc7, 0x3d, 0x79, 0xe5,
            0x41, 0x66, 0x51, 0x15,
        ];
        let expected_exact = [
            0x1b, 0x91, 0x7b, 0xa6, 0x83, 0x27, 0x58, 0xd2, 0x72, 0x99, 0xd3, 0xaa, 0x32, 0x4f,
            0x82, 0xb2, 0xca, 0xf3, 0x2c, 0x28, 0x41, 0x78, 0x10, 0x8e, 0x28, 0xd6, 0xaf, 0x97,
            0xc5, 0x9b, 0x77, 0xd8,
        ];

        assert_eq!(none.commitment_digest().as_bytes(), &expected_none);
        assert_eq!(exact.commitment_digest().as_bytes(), &expected_exact);
        assert_ne!(none.commitment_digest(), exact.commitment_digest());
    }

    #[test]
    fn apply_control_commits_exact_cas_proof_and_operation() {
        let baseline = payload_with_expected(2, ExpectedActive::None, 0x0b);
        let exact_zero = payload_with_expected(
            2,
            ExpectedActive::Exact(TargetSliceDigest::new(Digest32::from_bytes([0; 32]))),
            0x0b,
        );
        let exact_value = payload_with_expected(
            2,
            ExpectedActive::Exact(TargetSliceDigest::new(Digest32::from_bytes([0x0a; 32]))),
            0x0b,
        );
        let changed_operation = payload_with_expected(2, ExpectedActive::None, 0x1b);

        let mut changed_proof_fixture = proof_fixture();
        changed_proof_fixture.signature = b"signaturf";
        let changed_proof = commitment_from_parts(
            slice(SourceScopeRef::from_bytes([1; 16])),
            build_proof(changed_proof_fixture),
            ExpectedActive::None,
            0x0b,
        );

        assert_ne!(baseline.commitment_digest(), exact_zero.commitment_digest());
        assert_ne!(
            exact_zero.commitment_digest(),
            exact_value.commitment_digest()
        );
        assert_ne!(
            baseline.commitment_digest(),
            changed_operation.commitment_digest()
        );
        assert_ne!(
            baseline.commitment_digest(),
            changed_proof.commitment_digest()
        );

        let changed_slice = commitment_from_parts(
            slice_with_assignment(SourceScopeRef::from_bytes([1; 16]), 0x16),
            build_proof(proof_fixture()),
            ExpectedActive::None,
            0x0b,
        );
        assert_ne!(
            baseline.commitment_digest(),
            changed_slice.commitment_digest()
        );
    }

    #[test]
    fn apply_commitment_rejects_cross_scope_proof() {
        let slice_scope = SourceScopeRef::from_bytes([1; 16]);
        let proof_scope = SourceScopeRef::from_bytes([2; 16]);
        let writer = PlanWriterRef::from_bytes([9; 16]);
        let proof = proof(proof_scope, writer, 2);
        let claim = proof.claim();
        let Ok(context) = PlanWriterContext::try_new(claim.writer(), claim.epoch(), proof) else {
            panic!("test writer context must be valid");
        };
        let control = RuntimeApplyControl::new(
            context,
            ExpectedActive::None,
            ApplyOperationId::from_bytes([0x0b; 16]),
        );

        assert_eq!(
            RuntimeApplyControlCommitment::try_new(slice(slice_scope), control).err(),
            Some(super::ApplyContractError::WriterScopeMismatch)
        );
    }

    #[test]
    fn proof_bytes_are_bounded() {
        let scope = SourceScopeRef::from_bytes([1; 16]);
        let writer = PlanWriterRef::from_bytes([2; 16]);
        let Ok(algorithm) = TenureProofAlgorithm::try_new(1) else {
            panic!("test algorithm must be valid");
        };
        let Ok(authority) = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([3; 16]),
            TenureKeyRef::from_bytes([4; 16]),
            algorithm,
            1,
        ) else {
            panic!("test authority must be valid");
        };
        let Ok(claim) = WriterTenureClaim::try_new(
            scope,
            writer,
            PlanWriterEpoch::new(2),
            PlanWriterEpoch::new(1),
        ) else {
            panic!("test claim must be valid");
        };

        assert_eq!(
            WriterTenureProof::try_new(authority, claim, b"", b"signature").err(),
            Some(TenureProofError::EmptyNonce)
        );
        assert_eq!(
            WriterTenureProof::try_new(authority, claim, b"nonce", b"").err(),
            Some(TenureProofError::EmptySignature)
        );
    }

    #[test]
    fn controls_change_control_digest_but_not_slice_commitment() {
        let first = payload(1, 11);
        let changed_writer = payload(2, 11);
        let changed_operation = payload(1, 12);

        assert_eq!(first.slice(), changed_writer.slice());
        assert_eq!(first.slice(), changed_operation.slice());
        assert_ne!(
            first.commitment_digest(),
            changed_writer.commitment_digest()
        );
        assert_ne!(
            first.commitment_digest(),
            changed_operation.commitment_digest()
        );
        assert_eq!(first.validate(), Ok(()));
    }
}
