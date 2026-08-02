use core::fmt;

use ed25519_dalek::{Signer, SigningKey};
use paraegox_kernel::digest::{Digest32, DigestBuildError};
use paraegox_runtime_contracts::apply::{
    PlanWriterEpoch, PlanWriterRef, TenureProofAuthority, TenureProofError, WriterTenureClaim,
    WriterTenureProof, WriterTenureSigningTranscript,
};
use paraegox_runtime_contracts::provenance::SourceScopeRef;
use zeroize::Zeroizing;

use crate::plan::{DeploymentScopeId, DeploymentWriterRef};

use super::model::{
    AuthorityProvisioning, ED25519_ALGORITHM, ED25519_ALGORITHM_VERSION, ED25519_SIGNATURE_BYTES,
    ModelError, signing_key_fingerprint_for,
};

pub(super) struct Ed25519TenureSigner {
    proof_authority: TenureProofAuthority,
    signing_key_fingerprint: Digest32,
    signing_key: SigningKey,
}

impl fmt::Debug for Ed25519TenureSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ed25519TenureSigner")
            .field("proof_authority", &self.proof_authority)
            .field("signing_key_fingerprint", &self.signing_key_fingerprint)
            .finish_non_exhaustive()
    }
}

impl Ed25519TenureSigner {
    pub(super) fn try_from_seed(
        proof_authority: TenureProofAuthority,
        seed: Zeroizing<[u8; 32]>,
        expected_signing_key_fingerprint: Digest32,
    ) -> Result<Self, SignerError> {
        if seed.iter().all(|byte| *byte == 0) {
            return Err(SignerError::AllZeroSeed);
        }
        if proof_authority.algorithm().value() != ED25519_ALGORITHM
            || proof_authority.algorithm_version() != ED25519_ALGORITHM_VERSION
        {
            return Err(SignerError::UnsupportedSignatureProfile);
        }
        let signing_key = SigningKey::from_bytes(&seed);
        let signing_key_fingerprint =
            signing_key_fingerprint_for(&signing_key.verifying_key().to_bytes())?;
        if signing_key_fingerprint != expected_signing_key_fingerprint {
            return Err(SignerError::SigningKeyFingerprintMismatch);
        }
        Ok(Self {
            proof_authority,
            signing_key_fingerprint,
            signing_key,
        })
    }

    pub(super) fn validate_provisioning(
        &self,
        provisioning: &AuthorityProvisioning,
    ) -> Result<(), SignerError> {
        if self.proof_authority != provisioning.proof_authority {
            return Err(SignerError::ProofAuthorityMismatch);
        }
        if self.signing_key_fingerprint != provisioning.fingerprints.signing_key {
            return Err(SignerError::SigningKeyFingerprintMismatch);
        }
        if self.signing_key.verifying_key().to_bytes() != provisioning.verification_key {
            return Err(SignerError::VerificationKeyMismatch);
        }
        Ok(())
    }

    pub(super) fn sign(
        &self,
        source_scope: DeploymentScopeId,
        writer: DeploymentWriterRef,
        epoch: u64,
        supersedes_through_epoch: u64,
        nonce: &[u8],
    ) -> Result<SignedTenureProof, SignerError> {
        let claim = WriterTenureClaim::try_new(
            SourceScopeRef::from_bytes(*source_scope.as_bytes()),
            PlanWriterRef::from_bytes(*writer.as_bytes()),
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(supersedes_through_epoch),
        )?;
        let transcript =
            WriterTenureSigningTranscript::try_new(self.proof_authority, claim, nonce)?;
        let signature = self.signing_key.sign(transcript.as_bytes()).to_bytes();
        let proof =
            WriterTenureProof::try_new(self.proof_authority, claim, nonce, signature.as_slice())?;
        let envelope_digest = proof.envelope_digest()?;
        Ok(SignedTenureProof {
            proof,
            signature,
            envelope_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SignedTenureProof {
    pub(super) proof: WriterTenureProof,
    pub(super) signature: [u8; ED25519_SIGNATURE_BYTES],
    pub(super) envelope_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SignerError {
    AllZeroSeed,
    UnsupportedSignatureProfile,
    SigningKeyFingerprintMismatch,
    ProofAuthorityMismatch,
    VerificationKeyMismatch,
    Model(ModelError),
    Proof(TenureProofError),
    Digest(DigestBuildError),
}

impl From<ModelError> for SignerError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<TenureProofError> for SignerError {
    fn from(error: TenureProofError) -> Self {
        Self::Proof(error)
    }
}

impl From<DigestBuildError> for SignerError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

impl fmt::Display for SignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "tenure proof signing failed: {self:?}")
    }
}

impl std::error::Error for SignerError {}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Verifier;
    use paraegox_kernel::digest::Digest32;
    use paraegox_runtime_contracts::apply::{
        TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
    };
    use zeroize::Zeroizing;

    use crate::plan::{DeploymentScopeId, DeploymentWriterRef};

    use super::{Ed25519TenureSigner, SignerError};
    use crate::tenure_authority::model::signing_key_fingerprint_for;

    fn signer(seed: [u8; 32]) -> Ed25519TenureSigner {
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let fingerprint = signing_key_fingerprint_for(&key.verifying_key().to_bytes())
            .unwrap_or_else(|error| panic!("fixture fingerprint failed: {error}"));
        let authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([1; 16]),
            TenureKeyRef::from_bytes([2; 16]),
            TenureProofAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("fixture algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("fixture authority failed: {error}"));
        Ed25519TenureSigner::try_from_seed(authority, Zeroizing::new(seed), fingerprint)
            .unwrap_or_else(|error| panic!("fixture signer failed: {error}"))
    }

    #[test]
    fn real_ed25519_signs_runtime_owned_transcript_and_envelope_digest() {
        let signer = signer([3; 32]);
        let signed = signer
            .sign(
                DeploymentScopeId::from_bytes([4; 16]),
                DeploymentWriterRef::from_bytes([5; 16]),
                1,
                0,
                &[6; 32],
            )
            .unwrap_or_else(|error| panic!("sign failed: {error}"));
        let transcript = signed
            .proof
            .signing_transcript()
            .unwrap_or_else(|error| panic!("transcript failed: {error}"));
        signer
            .signing_key
            .verifying_key()
            .verify(
                transcript.as_bytes(),
                &ed25519_dalek::Signature::from_bytes(&signed.signature),
            )
            .unwrap_or_else(|error| panic!("signature verification failed: {error}"));
        assert_eq!(
            signed
                .proof
                .envelope_digest()
                .unwrap_or_else(|error| panic!("proof digest failed: {error}")),
            signed.envelope_digest
        );

        let second = signer
            .sign(
                DeploymentScopeId::from_bytes([4; 16]),
                DeploymentWriterRef::from_bytes([5; 16]),
                1,
                0,
                &[6; 32],
            )
            .unwrap_or_else(|error| panic!("second sign failed: {error}"));
        assert_eq!(signed.signature, second.signature);
        assert_eq!(signed.envelope_digest, second.envelope_digest);
    }

    #[test]
    fn zero_seed_and_fingerprint_mismatch_fail_closed() {
        let authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([1; 16]),
            TenureKeyRef::from_bytes([2; 16]),
            TenureProofAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("fixture algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("fixture authority failed: {error}"));
        assert_eq!(
            Ed25519TenureSigner::try_from_seed(
                authority,
                Zeroizing::new([0; 32]),
                Digest32::from_bytes([7; 32]),
            )
            .err(),
            Some(SignerError::AllZeroSeed)
        );
        assert_eq!(
            Ed25519TenureSigner::try_from_seed(
                authority,
                Zeroizing::new([8; 32]),
                Digest32::from_bytes([9; 32]),
            )
            .err(),
            Some(SignerError::SigningKeyFingerprintMismatch)
        );
    }

    #[test]
    fn debug_output_never_contains_private_seed_material() {
        let signer = signer([0xab; 32]);
        let debug = format!("{signer:?}");
        assert!(!debug.contains("abababab"));
        assert!(!debug.contains("seed"));
        assert!(!debug.contains("signing_key:"));
    }
}
