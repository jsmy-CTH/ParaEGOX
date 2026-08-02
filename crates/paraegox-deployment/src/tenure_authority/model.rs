use core::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::PrincipalRef;
use paraegox_runtime_contracts::apply::{
    PlanWriterEpoch, PlanWriterRef, TenureProofAuthority, TenureProofError, WriterTenureClaim,
    WriterTenureProof,
};
use paraegox_runtime_contracts::provenance::SourceScopeRef;

use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
use crate::tenure_protocol::{
    AcquireTenureRequestV1, AcquireTenureResponseV1, ControllerAcquireKeyRef,
};

pub(super) const AUTHORITY_SNAPSHOT_MAX_BYTES: usize = 1024 * 1024;
pub(super) const MAX_RETAINED_ACQUIRE_RECORDS: usize = 64;
pub(super) const MAX_ACQUIRE_REQUEST_BYTES: usize = 64 * 1024;
pub(super) const MAX_ACQUIRE_RESPONSE_BYTES: usize = 64 * 1024;
pub(super) const ED25519_ALGORITHM: u16 = 1;
pub(super) const ED25519_ALGORITHM_VERSION: u16 = 1;
pub(super) const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub(super) const ED25519_SIGNATURE_BYTES: usize = 64;

const AUTHORITY_KEY_FINGERPRINT_DOMAIN: &[u8] =
    b"paraegox.deployment.tenure-authority.key-fingerprint.sha256.v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct StoreInstanceId([u8; 32]);

impl StoreInstanceId {
    pub(super) fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, ModelError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(ModelError::ZeroStoreInstanceId);
        }
        Ok(Self(bytes))
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct AcquireOperationId([u8; 16]);

impl AcquireOperationId {
    pub(super) fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, ModelError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(ModelError::ZeroOperationId);
        }
        Ok(Self(bytes))
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthorityProvisioning {
    pub(super) source_scope: DeploymentScopeId,
    pub(super) authorized_writer: DeploymentWriterRef,
    pub(super) proof_authority: TenureProofAuthority,
    pub(super) verification_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    pub(super) authorization: AcquireAuthorization,
    pub(super) fingerprints: AuthorityFingerprints,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AcquireAuthorization {
    pub(super) controller_principal: PrincipalRef,
    pub(super) controller_key: ControllerAcquireKeyRef,
    pub(super) controller_verification_key: [u8; 32],
    pub(super) controller_public_key_fingerprint: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthorityFingerprints {
    pub(super) signing_key: Digest32,
    pub(super) policy: Digest32,
    pub(super) service_principal: Digest32,
    pub(super) owner_identity: Digest32,
}

impl AuthorityProvisioning {
    pub(super) fn try_new(
        source_scope: DeploymentScopeId,
        authorized_writer: DeploymentWriterRef,
        proof_authority: TenureProofAuthority,
        verification_key: [u8; ED25519_PUBLIC_KEY_BYTES],
        authorization: AcquireAuthorization,
        fingerprints: AuthorityFingerprints,
    ) -> Result<Self, ModelError> {
        ensure_nonzero(source_scope.as_bytes(), ModelError::ZeroSourceScope)?;
        ensure_nonzero(
            authorized_writer.as_bytes(),
            ModelError::ZeroWriterReference,
        )?;
        ensure_nonzero(
            proof_authority.authority().as_bytes(),
            ModelError::ZeroTenureAuthorityReference,
        )?;
        ensure_nonzero(
            proof_authority.key().as_bytes(),
            ModelError::ZeroTenureKeyReference,
        )?;
        ensure_nonzero(
            authorization.controller_principal.as_bytes(),
            ModelError::ZeroControllerPrincipal,
        )?;
        ensure_nonzero(
            authorization.controller_key.as_bytes(),
            ModelError::ZeroControllerKeyReference,
        )?;
        let controller_verification_key =
            VerifyingKey::from_bytes(&authorization.controller_verification_key)
                .map_err(|_| ModelError::InvalidControllerVerificationKey)?;
        if controller_verification_key.is_weak() {
            return Err(ModelError::WeakControllerVerificationKey);
        }
        let controller_fingerprint =
            crate::tenure_protocol::ControllerPublicKeyFingerprint::for_ed25519_key(
                &authorization.controller_verification_key,
            )
            .map_err(|_| ModelError::InvalidControllerKeyFingerprint)?;
        if controller_fingerprint.as_bytes() != &authorization.controller_public_key_fingerprint {
            return Err(ModelError::ControllerKeyFingerprintMismatch);
        }
        ensure_nonzero(
            &authorization.controller_public_key_fingerprint,
            ModelError::ZeroControllerKeyFingerprint,
        )?;
        ensure_nonzero_digest(
            &fingerprints.signing_key,
            ModelError::ZeroSigningKeyFingerprint,
        )?;
        ensure_nonzero_digest(&fingerprints.policy, ModelError::ZeroPolicyFingerprint)?;
        ensure_nonzero_digest(
            &fingerprints.service_principal,
            ModelError::ZeroServicePrincipalFingerprint,
        )?;
        ensure_nonzero_digest(
            &fingerprints.owner_identity,
            ModelError::ZeroOwnerIdentityFingerprint,
        )?;

        let parsed_key = VerifyingKey::from_bytes(&verification_key)
            .map_err(|_| ModelError::InvalidVerificationKey)?;
        if parsed_key.is_weak() {
            return Err(ModelError::WeakVerificationKey);
        }
        let actual_fingerprint = signing_key_fingerprint_for(&verification_key)?;
        if actual_fingerprint != fingerprints.signing_key {
            return Err(ModelError::SigningKeyFingerprintMismatch);
        }

        if proof_authority.algorithm().value() != ED25519_ALGORITHM
            || proof_authority.algorithm_version() != ED25519_ALGORITHM_VERSION
        {
            return Err(ModelError::UnsupportedSignatureProfile);
        }
        Ok(Self {
            source_scope,
            authorized_writer,
            proof_authority,
            verification_key,
            authorization,
            fingerprints,
        })
    }

    pub(super) fn validate(&self) -> Result<(), ModelError> {
        Self::try_new(
            self.source_scope,
            self.authorized_writer,
            self.proof_authority,
            self.verification_key,
            self.authorization,
            self.fingerprints,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AcquireIntent {
    pub(super) operation_id: AcquireOperationId,
    pub(super) request_digest: Digest32,
    pub(super) exact_request_bytes: Box<[u8]>,
    pub(super) writer: DeploymentWriterRef,
    pub(super) nonce: Box<[u8]>,
    pub(super) response_bound: u32,
}

impl AcquireIntent {
    pub(super) fn try_new(
        operation_id: AcquireOperationId,
        request_digest: Digest32,
        exact_request_bytes: &[u8],
        writer: DeploymentWriterRef,
        nonce: &[u8],
        response_bound: u32,
    ) -> Result<Self, ModelError> {
        ensure_nonzero_digest(&request_digest, ModelError::ZeroRequestDigest)?;
        if exact_request_bytes.is_empty() {
            return Err(ModelError::EmptyRequest);
        }
        if exact_request_bytes.len() > MAX_ACQUIRE_REQUEST_BYTES {
            return Err(ModelError::RequestTooLarge);
        }
        ensure_nonzero(writer.as_bytes(), ModelError::ZeroWriterReference)?;
        if nonce.is_empty() {
            return Err(ModelError::EmptyNonce);
        }
        if nonce.len() > paraegox_runtime_contracts::apply::MAX_TENURE_NONCE_BYTES {
            return Err(ModelError::NonceTooLarge);
        }
        let response_bound =
            usize::try_from(response_bound).map_err(|_| ModelError::ResponseBoundTooLarge)?;
        if response_bound == 0 {
            return Err(ModelError::ZeroResponseBound);
        }
        if response_bound > MAX_ACQUIRE_RESPONSE_BYTES {
            return Err(ModelError::ResponseBoundTooLarge);
        }
        Ok(Self {
            operation_id,
            request_digest,
            exact_request_bytes: exact_request_bytes.into(),
            writer,
            nonce: nonce.into(),
            response_bound: u32::try_from(response_bound)
                .map_err(|_| ModelError::ResponseBoundTooLarge)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EncodedAcquireResponse {
    pub(super) exact_bytes: Box<[u8]>,
    pub(super) response_digest: Digest32,
    pub(super) proof_envelope_digest: Digest32,
}

impl EncodedAcquireResponse {
    pub(super) fn try_new(
        exact_bytes: &[u8],
        response_digest: Digest32,
        proof_envelope_digest: Digest32,
    ) -> Result<Self, ModelError> {
        if exact_bytes.is_empty() {
            return Err(ModelError::EmptyResponse);
        }
        if exact_bytes.len() > MAX_ACQUIRE_RESPONSE_BYTES {
            return Err(ModelError::ResponseTooLarge);
        }
        ensure_nonzero_digest(&response_digest, ModelError::ZeroResponseDigest)?;
        ensure_nonzero_digest(&proof_envelope_digest, ModelError::ZeroProofEnvelopeDigest)?;
        Ok(Self {
            exact_bytes: exact_bytes.into(),
            response_digest,
            proof_envelope_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum IssuanceStatus {
    Issued = 1,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct AcquireRecord {
    pub(super) operation_id: AcquireOperationId,
    pub(super) request_digest: Digest32,
    pub(super) exact_request_bytes: Box<[u8]>,
    pub(super) writer: DeploymentWriterRef,
    pub(super) epoch: u64,
    pub(super) supersedes_through_epoch: u64,
    pub(super) nonce: Box<[u8]>,
    pub(super) response_bound: u32,
    pub(super) signature: [u8; ED25519_SIGNATURE_BYTES],
    pub(super) proof_envelope_digest: Digest32,
    pub(super) exact_response_bytes: Box<[u8]>,
    pub(super) response_digest: Digest32,
    pub(super) status: IssuanceStatus,
}

impl fmt::Debug for AcquireRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcquireRecord")
            .field("operation_id", &self.operation_id)
            .field("request_digest", &self.request_digest)
            .field("writer", &self.writer)
            .field("epoch", &self.epoch)
            .field("supersedes_through_epoch", &self.supersedes_through_epoch)
            .field("response_bound", &self.response_bound)
            .field("proof_envelope_digest", &self.proof_envelope_digest)
            .field("response_digest", &self.response_digest)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct AuthoritySnapshot {
    pub(super) store_instance_id: StoreInstanceId,
    pub(super) owner_identity_fingerprint: Digest32,
    pub(super) snapshot_sequence: u64,
    pub(super) provisioning: AuthorityProvisioning,
    pub(super) epoch_high_water: u64,
    pub(super) acquire_records: Vec<AcquireRecord>,
}

impl fmt::Debug for AuthoritySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthoritySnapshot")
            .field("store_instance_id", &self.store_instance_id)
            .field(
                "owner_identity_fingerprint",
                &self.owner_identity_fingerprint,
            )
            .field("snapshot_sequence", &self.snapshot_sequence)
            .field("provisioning", &self.provisioning)
            .field("epoch_high_water", &self.epoch_high_water)
            .field("acquire_record_count", &self.acquire_records.len())
            .finish_non_exhaustive()
    }
}

impl AuthoritySnapshot {
    pub(super) fn initial(
        store_instance_id: StoreInstanceId,
        provisioning: AuthorityProvisioning,
    ) -> Result<Self, ModelError> {
        let snapshot = Self {
            store_instance_id,
            owner_identity_fingerprint: provisioning.fingerprints.owner_identity,
            snapshot_sequence: 1,
            provisioning,
            epoch_high_water: 0,
            acquire_records: Vec::new(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(super) fn validate(&self) -> Result<(), ModelError> {
        self.provisioning.validate()?;
        if self.snapshot_sequence == 0 {
            return Err(ModelError::ZeroSnapshotSequence);
        }
        if self.owner_identity_fingerprint != self.provisioning.fingerprints.owner_identity {
            return Err(ModelError::OwnerIdentityFingerprintMismatch);
        }
        if self.acquire_records.len() > MAX_RETAINED_ACQUIRE_RECORDS {
            return Err(ModelError::AcquireCapacityExceeded);
        }
        let record_count = u64::try_from(self.acquire_records.len())
            .map_err(|_| ModelError::AcquireCapacityExceeded)?;
        if self.epoch_high_water != record_count {
            return Err(ModelError::EpochHistoryMismatch);
        }
        let expected_sequence = self
            .epoch_high_water
            .checked_add(1)
            .ok_or(ModelError::SnapshotSequenceOverflow)?;
        if self.snapshot_sequence != expected_sequence {
            return Err(ModelError::SnapshotSequenceHistoryMismatch);
        }

        let mut previous_operation = None;
        let mut observed_epochs = [false; MAX_RETAINED_ACQUIRE_RECORDS];
        for record in &self.acquire_records {
            if previous_operation.is_some_and(|previous| previous >= record.operation_id) {
                return Err(ModelError::NonCanonicalOperationOrdering);
            }
            previous_operation = Some(record.operation_id);
            self.validate_record_structure(record)?;

            let epoch_index = usize::try_from(record.epoch.saturating_sub(1))
                .map_err(|_| ModelError::EpochHistoryMismatch)?;
            let Some(observed) = observed_epochs.get_mut(epoch_index) else {
                return Err(ModelError::EpochHistoryMismatch);
            };
            if *observed {
                return Err(ModelError::DuplicateEpoch);
            }
            *observed = true;
        }
        if observed_epochs[..self.acquire_records.len()]
            .iter()
            .any(|observed| !observed)
        {
            return Err(ModelError::EpochHistoryMismatch);
        }
        self.validate_record_protocols()?;
        Ok(())
    }

    fn validate_record_structure(&self, record: &AcquireRecord) -> Result<(), ModelError> {
        AcquireOperationId::try_from_bytes(*record.operation_id.as_bytes())?;
        ensure_nonzero_digest(&record.request_digest, ModelError::ZeroRequestDigest)?;
        if record.exact_request_bytes.is_empty() {
            return Err(ModelError::EmptyRequest);
        }
        if record.exact_request_bytes.len() > MAX_ACQUIRE_REQUEST_BYTES {
            return Err(ModelError::RequestTooLarge);
        }
        ensure_nonzero(record.writer.as_bytes(), ModelError::ZeroWriterReference)?;
        if record.writer != self.provisioning.authorized_writer {
            return Err(ModelError::UnauthorizedWriter);
        }
        if record.epoch == 0 || record.epoch > self.epoch_high_water {
            return Err(ModelError::InvalidEpoch);
        }
        if record.supersedes_through_epoch != record.epoch - 1 {
            return Err(ModelError::InvalidSupersedesEpoch);
        }
        if record.nonce.is_empty() {
            return Err(ModelError::EmptyNonce);
        }
        if record.nonce.len() > paraegox_runtime_contracts::apply::MAX_TENURE_NONCE_BYTES {
            return Err(ModelError::NonceTooLarge);
        }
        let response_bound = usize::try_from(record.response_bound)
            .map_err(|_| ModelError::ResponseBoundTooLarge)?;
        if response_bound == 0 || response_bound > MAX_ACQUIRE_RESPONSE_BYTES {
            return Err(ModelError::ResponseBoundTooLarge);
        }
        if record.exact_response_bytes.is_empty() {
            return Err(ModelError::EmptyResponse);
        }
        if record.exact_response_bytes.len() > response_bound
            || record.exact_response_bytes.len() > MAX_ACQUIRE_RESPONSE_BYTES
        {
            return Err(ModelError::ResponseTooLarge);
        }
        ensure_nonzero_digest(&record.response_digest, ModelError::ZeroResponseDigest)?;
        ensure_nonzero_digest(
            &record.proof_envelope_digest,
            ModelError::ZeroProofEnvelopeDigest,
        )?;
        if record.status != IssuanceStatus::Issued {
            return Err(ModelError::InvalidIssuanceStatus);
        }
        Ok(())
    }

    fn validate_record_protocols(&self) -> Result<(), ModelError> {
        const MAX_VALIDATION_WORKERS: usize = 8;

        let worker_count = std::thread::available_parallelism()
            .map_or(1, core::num::NonZeroUsize::get)
            .min(MAX_VALIDATION_WORKERS)
            .min(self.acquire_records.len());
        if worker_count <= 1 {
            return self
                .acquire_records
                .iter()
                .try_for_each(|record| self.validate_record_protocol(record));
        }

        let chunk_size = self.acquire_records.len().div_ceil(worker_count);
        std::thread::scope(|scope| {
            let mut workers = Vec::with_capacity(worker_count);
            for records in self.acquire_records.chunks(chunk_size) {
                workers.push(scope.spawn(move || {
                    records
                        .iter()
                        .try_for_each(|record| self.validate_record_protocol(record))
                }));
            }
            for worker in workers {
                worker
                    .join()
                    .map_err(|_| ModelError::ValidationWorkerPanicked)??;
            }
            Ok(())
        })
    }

    fn validate_record_protocol(&self, record: &AcquireRecord) -> Result<(), ModelError> {
        let request = AcquireTenureRequestV1::decode(&record.exact_request_bytes)
            .map_err(|_| ModelError::InvalidStoredRequest)?;
        let authorization = self.provisioning.authorization;
        if request.operation_id().as_bytes() != record.operation_id.as_bytes()
            || request.request_digest().as_bytes() != record.request_digest.as_bytes()
            || request.scope() != self.provisioning.source_scope
            || request.writer() != record.writer
            || request.client_nonce() != record.nonce.as_ref()
            || request.max_response_payload_bytes() != record.response_bound
            || request.controller_principal() != authorization.controller_principal
            || request.controller_key() != authorization.controller_key
            || request.controller_public_key_fingerprint().as_bytes()
                != &authorization.controller_public_key_fingerprint
        {
            return Err(ModelError::StoredRequestBindingMismatch);
        }
        let request_signature: [u8; ED25519_SIGNATURE_BYTES] = request
            .auth_signature()
            .try_into()
            .map_err(|_| ModelError::InvalidStoredRequestSignature)?;
        let request_transcript = request
            .signing_transcript()
            .map_err(|_| ModelError::InvalidStoredRequestSignature)?;
        let controller_key = VerifyingKey::from_bytes(&authorization.controller_verification_key)
            .map_err(|_| ModelError::InvalidControllerVerificationKey)?;
        controller_key
            .verify_strict(
                request_transcript.as_bytes(),
                &Signature::from_bytes(&request_signature),
            )
            .map_err(|_| ModelError::InvalidStoredRequestSignature)?;

        let claim = WriterTenureClaim::try_new(
            SourceScopeRef::from_bytes(*self.provisioning.source_scope.as_bytes()),
            PlanWriterRef::from_bytes(*record.writer.as_bytes()),
            PlanWriterEpoch::new(record.epoch),
            PlanWriterEpoch::new(record.supersedes_through_epoch),
        )?;
        let proof = WriterTenureProof::try_new(
            self.provisioning.proof_authority,
            claim,
            &record.nonce,
            &record.signature,
        )?;
        if proof.envelope_digest()? != record.proof_envelope_digest {
            return Err(ModelError::ProofEnvelopeDigestMismatch);
        }
        let transcript = proof.signing_transcript()?;
        let verification_key = VerifyingKey::from_bytes(&self.provisioning.verification_key)
            .map_err(|_| ModelError::InvalidVerificationKey)?;
        let signature = Signature::from_bytes(&record.signature);
        verification_key
            .verify_strict(transcript.as_bytes(), &signature)
            .map_err(|_| ModelError::InvalidProofSignature)?;
        let response =
            AcquireTenureResponseV1::decode_for_request(&record.exact_response_bytes, &request)
                .map_err(|_| ModelError::InvalidStoredResponse)?;
        if response.response_digest().as_bytes() != record.response_digest.as_bytes()
            || response.proof_digest() != &record.proof_envelope_digest
            || response.proof() != &proof
        {
            return Err(ModelError::StoredResponseBindingMismatch);
        }
        Ok(())
    }

    pub(super) fn preflight(&self, intent: &AcquireIntent) -> Result<Preflight, ModelError> {
        if let Ok(index) = self
            .acquire_records
            .binary_search_by_key(&intent.operation_id, |record| record.operation_id)
        {
            let record = &self.acquire_records[index];
            if record.request_digest != intent.request_digest {
                return Err(ModelError::OperationDigestConflict);
            }
            return Ok(Preflight::Replay {
                exact_response_bytes: record.exact_response_bytes.clone(),
                response_digest: record.response_digest,
                proof_envelope_digest: record.proof_envelope_digest,
            });
        }
        if self.acquire_records.len() == MAX_RETAINED_ACQUIRE_RECORDS {
            return Err(ModelError::AcquireCapacityExceeded);
        }
        let next_epoch = self
            .epoch_high_water
            .checked_add(1)
            .ok_or(ModelError::EpochOverflow)?;
        let next_snapshot_sequence = self
            .snapshot_sequence
            .checked_add(1)
            .ok_or(ModelError::SnapshotSequenceOverflow)?;
        Ok(Preflight::Issue {
            next_epoch,
            next_snapshot_sequence,
        })
    }

    pub(super) fn with_issued_record(
        &self,
        intent: &AcquireIntent,
        next_epoch: u64,
        next_snapshot_sequence: u64,
        signature: [u8; ED25519_SIGNATURE_BYTES],
        proof_envelope_digest: Digest32,
        response: EncodedAcquireResponse,
    ) -> Result<Self, ModelError> {
        let Preflight::Issue {
            next_epoch: expected_epoch,
            next_snapshot_sequence: expected_sequence,
        } = self.preflight(intent)?
        else {
            return Err(ModelError::OperationAlreadyIssued);
        };
        if next_epoch != expected_epoch {
            return Err(ModelError::EpochTransitionMismatch);
        }
        if next_snapshot_sequence != expected_sequence {
            return Err(ModelError::SnapshotSequenceTransitionMismatch);
        }
        if response.proof_envelope_digest != proof_envelope_digest {
            return Err(ModelError::ResponseProofBindingMismatch);
        }
        if response.exact_bytes.len()
            > usize::try_from(intent.response_bound)
                .map_err(|_| ModelError::ResponseBoundTooLarge)?
        {
            return Err(ModelError::ResponseTooLarge);
        }

        let record = AcquireRecord {
            operation_id: intent.operation_id,
            request_digest: intent.request_digest,
            exact_request_bytes: intent.exact_request_bytes.clone(),
            writer: intent.writer,
            epoch: next_epoch,
            supersedes_through_epoch: self.epoch_high_water,
            nonce: intent.nonce.clone(),
            response_bound: intent.response_bound,
            signature,
            proof_envelope_digest,
            exact_response_bytes: response.exact_bytes,
            response_digest: response.response_digest,
            status: IssuanceStatus::Issued,
        };
        let mut next = self.clone();
        let insertion = next
            .acquire_records
            .binary_search_by_key(&intent.operation_id, |candidate| candidate.operation_id)
            .unwrap_or_else(|index| index);
        next.acquire_records.insert(insertion, record);
        next.epoch_high_water = next_epoch;
        next.snapshot_sequence = next_snapshot_sequence;
        next.validate()?;
        Ok(next)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Preflight {
    Replay {
        exact_response_bytes: Box<[u8]>,
        response_digest: Digest32,
        proof_envelope_digest: Digest32,
    },
    Issue {
        next_epoch: u64,
        next_snapshot_sequence: u64,
    },
}

pub(super) fn signing_key_fingerprint_for(
    verification_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
) -> Result<Digest32, ModelError> {
    let mut builder = Digest32Builder::try_new(AUTHORITY_KEY_FINGERPRINT_DOMAIN)?;
    builder.field_bytes(verification_key)?;
    Ok(builder.finish())
}

fn ensure_nonzero(bytes: &[u8], error: ModelError) -> Result<(), ModelError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(error);
    }
    Ok(())
}

fn ensure_nonzero_digest(digest: &Digest32, error: ModelError) -> Result<(), ModelError> {
    ensure_nonzero(digest.as_bytes(), error)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ModelError {
    ZeroStoreInstanceId,
    ZeroOperationId,
    ZeroSourceScope,
    ZeroTenureAuthorityReference,
    ZeroTenureKeyReference,
    ZeroWriterReference,
    UnauthorizedWriter,
    ZeroControllerPrincipal,
    ZeroControllerKeyReference,
    ZeroControllerKeyFingerprint,
    InvalidControllerVerificationKey,
    WeakControllerVerificationKey,
    InvalidControllerKeyFingerprint,
    ControllerKeyFingerprintMismatch,
    ZeroSigningKeyFingerprint,
    ZeroPolicyFingerprint,
    ZeroServicePrincipalFingerprint,
    ZeroOwnerIdentityFingerprint,
    ZeroRequestDigest,
    ZeroResponseDigest,
    ZeroProofEnvelopeDigest,
    InvalidVerificationKey,
    WeakVerificationKey,
    SigningKeyFingerprintMismatch,
    UnsupportedSignatureProfile,
    EmptyRequest,
    RequestTooLarge,
    EmptyNonce,
    NonceTooLarge,
    ZeroResponseBound,
    ResponseBoundTooLarge,
    EmptyResponse,
    ResponseTooLarge,
    ZeroSnapshotSequence,
    SnapshotSequenceOverflow,
    SnapshotSequenceHistoryMismatch,
    OwnerIdentityFingerprintMismatch,
    AcquireCapacityExceeded,
    EpochHistoryMismatch,
    NonCanonicalOperationOrdering,
    DuplicateEpoch,
    InvalidEpoch,
    InvalidSupersedesEpoch,
    InvalidIssuanceStatus,
    InvalidStoredRequest,
    StoredRequestBindingMismatch,
    InvalidStoredRequestSignature,
    InvalidStoredResponse,
    StoredResponseBindingMismatch,
    ProofEnvelopeDigestMismatch,
    InvalidProofSignature,
    ValidationWorkerPanicked,
    OperationDigestConflict,
    EpochOverflow,
    OperationAlreadyIssued,
    EpochTransitionMismatch,
    SnapshotSequenceTransitionMismatch,
    ResponseProofBindingMismatch,
    Digest(DigestBuildError),
    Proof(TenureProofError),
}

impl From<DigestBuildError> for ModelError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

impl From<TenureProofError> for ModelError {
    fn from(error: TenureProofError) -> Self {
        Self::Proof(error)
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid tenure-authority state: {self:?}")
    }
}

impl std::error::Error for ModelError {}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_runtime_contracts::apply::{
        PlanWriterEpoch, PlanWriterRef, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
        TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
    };
    use paraegox_runtime_contracts::provenance::SourceScopeRef;

    use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
    use crate::tenure_protocol::{
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        AcquireTenureRequestV1, AcquireTenureResponseV1, ControllerAcquireKeyRef,
        ControllerPublicKeyFingerprint, MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };

    use super::{
        AcquireAuthorization, AcquireIntent, AcquireOperationId, AcquireRecord,
        AuthorityFingerprints, AuthorityProvisioning, AuthoritySnapshot, EncodedAcquireResponse,
        IssuanceStatus, ModelError, Preflight, StoreInstanceId, signing_key_fingerprint_for,
    };

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn provisioning(key: &SigningKey) -> AuthorityProvisioning {
        let verifying_key = key.verifying_key().to_bytes();
        let proof_authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([2; 16]),
            TenureKeyRef::from_bytes([3; 16]),
            TenureProofAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("fixture algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("fixture proof authority failed: {error}"));
        let controller_key = SigningKey::from_bytes(&[0xa0; 32]);
        let controller_verification_key = controller_key.verifying_key().to_bytes();
        let controller_public_key_fingerprint =
            crate::tenure_protocol::ControllerPublicKeyFingerprint::for_ed25519_key(
                &controller_verification_key,
            )
            .unwrap_or_else(|error| panic!("fixture controller fingerprint failed: {error}"));
        AuthorityProvisioning::try_new(
            DeploymentScopeId::from_bytes([1; 16]),
            DeploymentWriterRef::from_bytes([7; 16]),
            proof_authority,
            verifying_key,
            AcquireAuthorization {
                controller_principal: paraegox_kernel::identity::PrincipalRef::from_bytes(
                    [0xa1; 16],
                ),
                controller_key: crate::tenure_protocol::ControllerAcquireKeyRef::from_bytes(
                    [0xa2; 16],
                ),
                controller_verification_key,
                controller_public_key_fingerprint: *controller_public_key_fingerprint.as_bytes(),
            },
            AuthorityFingerprints {
                signing_key: signing_key_fingerprint_for(&verifying_key)
                    .unwrap_or_else(|error| panic!("fixture fingerprint failed: {error}")),
                policy: digest(4),
                service_principal: digest(5),
                owner_identity: digest(6),
            },
        )
        .unwrap_or_else(|error| panic!("fixture provisioning failed: {error}"))
    }

    fn intent(operation: u8, request: u8) -> AcquireIntent {
        let controller_key = SigningKey::from_bytes(&[0xa0; 32]);
        let controller_fingerprint = ControllerPublicKeyFingerprint::for_ed25519_key(
            &controller_key.verifying_key().to_bytes(),
        )
        .unwrap_or_else(|error| panic!("fixture controller fingerprint failed: {error}"));
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                DeploymentScopeId::from_bytes([1; 16]),
                DeploymentWriterRef::from_bytes([7; 16]),
                AcquireTenureOperationId::from_bytes([operation; 16]),
            ),
            paraegox_kernel::identity::PrincipalRef::from_bytes([0xa1; 16]),
            ControllerAcquireKeyRef::from_bytes([0xa2; 16]),
            controller_fingerprint,
            &[request; 32],
            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .unwrap_or_else(|_| panic!("fixture response bound must fit u32")),
        )
        .unwrap_or_else(|error| panic!("fixture request draft failed: {error}"));
        let transcript = draft
            .signing_transcript()
            .unwrap_or_else(|error| panic!("fixture request transcript failed: {error}"));
        let request = draft
            .finalize_ed25519(
                controller_key
                    .sign(transcript.as_bytes())
                    .to_bytes()
                    .as_slice(),
            )
            .unwrap_or_else(|error| panic!("fixture request failed: {error}"));
        AcquireIntent::try_new(
            AcquireOperationId::try_from_bytes([operation; 16])
                .unwrap_or_else(|error| panic!("fixture operation failed: {error}")),
            Digest32::from_bytes(*request.request_digest().as_bytes()),
            request.canonical_bytes(),
            DeploymentWriterRef::from_bytes([7; 16]),
            request.client_nonce(),
            request.max_response_payload_bytes(),
        )
        .unwrap_or_else(|error| panic!("fixture intent failed: {error}"))
    }

    fn issue(
        snapshot: &AuthoritySnapshot,
        key: &SigningKey,
        intent: &AcquireIntent,
    ) -> AuthoritySnapshot {
        let Preflight::Issue {
            next_epoch,
            next_snapshot_sequence,
        } = snapshot
            .preflight(intent)
            .unwrap_or_else(|error| panic!("fixture preflight failed: {error}"))
        else {
            panic!("fresh fixture operation unexpectedly replayed");
        };
        let claim = WriterTenureClaim::try_new(
            SourceScopeRef::from_bytes(*snapshot.provisioning.source_scope.as_bytes()),
            PlanWriterRef::from_bytes(*intent.writer.as_bytes()),
            PlanWriterEpoch::new(next_epoch),
            PlanWriterEpoch::new(snapshot.epoch_high_water),
        )
        .unwrap_or_else(|error| panic!("fixture claim failed: {error}"));
        let transcript = paraegox_runtime_contracts::apply::WriterTenureSigningTranscript::try_new(
            snapshot.provisioning.proof_authority,
            claim,
            &intent.nonce,
        )
        .unwrap_or_else(|error| panic!("fixture transcript failed: {error}"));
        let signature = key.sign(transcript.as_bytes()).to_bytes();
        let proof = WriterTenureProof::try_new(
            snapshot.provisioning.proof_authority,
            claim,
            &intent.nonce,
            &signature,
        )
        .unwrap_or_else(|error| panic!("fixture proof failed: {error}"));
        let proof_digest = proof
            .envelope_digest()
            .unwrap_or_else(|error| panic!("fixture proof digest failed: {error}"));
        let request = AcquireTenureRequestV1::decode(&intent.exact_request_bytes)
            .unwrap_or_else(|error| panic!("fixture stored request failed: {error}"));
        let response = AcquireTenureResponseV1::try_new(&request, proof)
            .unwrap_or_else(|error| panic!("fixture response failed: {error}"));
        snapshot
            .with_issued_record(
                intent,
                next_epoch,
                next_snapshot_sequence,
                signature,
                proof_digest,
                EncodedAcquireResponse::try_new(
                    response.canonical_bytes(),
                    Digest32::from_bytes(*response.response_digest().as_bytes()),
                    proof_digest,
                )
                .unwrap_or_else(|error| panic!("fixture response failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("fixture transition failed: {error}"))
    }

    fn record_for(
        snapshot: &AuthoritySnapshot,
        key: &SigningKey,
        intent: &AcquireIntent,
        epoch: u64,
    ) -> AcquireRecord {
        let supersedes_through_epoch = epoch - 1;
        let claim = WriterTenureClaim::try_new(
            SourceScopeRef::from_bytes(*snapshot.provisioning.source_scope.as_bytes()),
            PlanWriterRef::from_bytes(*intent.writer.as_bytes()),
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(supersedes_through_epoch),
        )
        .unwrap_or_else(|error| panic!("fixture claim failed: {error}"));
        let transcript = paraegox_runtime_contracts::apply::WriterTenureSigningTranscript::try_new(
            snapshot.provisioning.proof_authority,
            claim,
            &intent.nonce,
        )
        .unwrap_or_else(|error| panic!("fixture transcript failed: {error}"));
        let signature = key.sign(transcript.as_bytes()).to_bytes();
        let proof = WriterTenureProof::try_new(
            snapshot.provisioning.proof_authority,
            claim,
            &intent.nonce,
            &signature,
        )
        .unwrap_or_else(|error| panic!("fixture proof failed: {error}"));
        let proof_envelope_digest = proof
            .envelope_digest()
            .unwrap_or_else(|error| panic!("fixture proof digest failed: {error}"));
        let request = AcquireTenureRequestV1::decode(&intent.exact_request_bytes)
            .unwrap_or_else(|error| panic!("fixture stored request failed: {error}"));
        let response = AcquireTenureResponseV1::try_new(&request, proof)
            .unwrap_or_else(|error| panic!("fixture response failed: {error}"));
        AcquireRecord {
            operation_id: intent.operation_id,
            request_digest: intent.request_digest,
            exact_request_bytes: intent.exact_request_bytes.clone(),
            writer: intent.writer,
            epoch,
            supersedes_through_epoch,
            nonce: intent.nonce.clone(),
            response_bound: intent.response_bound,
            signature,
            proof_envelope_digest,
            exact_response_bytes: response.canonical_bytes().into(),
            response_digest: Digest32::from_bytes(*response.response_digest().as_bytes()),
            status: IssuanceStatus::Issued,
        }
    }

    #[test]
    fn sequence_one_explicitly_contains_zero_epoch_high_water() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let snapshot = AuthoritySnapshot::initial(
            StoreInstanceId::try_from_bytes([10; 32])
                .unwrap_or_else(|error| panic!("fixture store failed: {error}")),
            provisioning(&key),
        )
        .unwrap_or_else(|error| panic!("initial snapshot failed: {error}"));

        assert_eq!(snapshot.snapshot_sequence, 1);
        assert_eq!(snapshot.epoch_high_water, 0);
        assert!(snapshot.acquire_records.is_empty());

        let mut invalid = snapshot;
        invalid.epoch_high_water = 1;
        assert_eq!(invalid.validate(), Err(ModelError::EpochHistoryMismatch));
    }

    #[test]
    fn same_operation_digest_replays_and_different_digest_conflicts() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let initial = AuthoritySnapshot::initial(
            StoreInstanceId::try_from_bytes([12; 32])
                .unwrap_or_else(|error| panic!("fixture store failed: {error}")),
            provisioning(&key),
        )
        .unwrap_or_else(|error| panic!("initial snapshot failed: {error}"));
        let original = intent(1, 13);
        let issued = issue(&initial, &key, &original);

        let replay = issued
            .preflight(&original)
            .unwrap_or_else(|error| panic!("replay failed: {error}"));
        assert!(matches!(replay, Preflight::Replay { .. }));

        let conflicting = intent(1, 14);
        assert_eq!(
            issued.preflight(&conflicting),
            Err(ModelError::OperationDigestConflict)
        );
        assert_eq!(issued.epoch_high_water, 1);
        assert_eq!(issued.snapshot_sequence, 2);
    }

    #[test]
    fn records_are_canonical_by_operation_id_but_epochs_remain_contiguous() {
        let key = SigningKey::from_bytes(&[15; 32]);
        let initial = AuthoritySnapshot::initial(
            StoreInstanceId::try_from_bytes([16; 32])
                .unwrap_or_else(|error| panic!("fixture store failed: {error}")),
            provisioning(&key),
        )
        .unwrap_or_else(|error| panic!("initial snapshot failed: {error}"));
        let later_key_first = issue(&initial, &key, &intent(2, 17));
        let complete = issue(&later_key_first, &key, &intent(1, 18));

        assert_eq!(
            complete.acquire_records[0].operation_id.as_bytes(),
            &[1; 16]
        );
        assert_eq!(complete.acquire_records[0].epoch, 2);
        assert_eq!(
            complete.acquire_records[1].operation_id.as_bytes(),
            &[2; 16]
        );
        assert_eq!(complete.acquire_records[1].epoch, 1);
        assert!(complete.validate().is_ok());
    }

    #[test]
    fn proof_signature_and_envelope_digest_are_cross_checked() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let initial = AuthoritySnapshot::initial(
            StoreInstanceId::try_from_bytes([20; 32])
                .unwrap_or_else(|error| panic!("fixture store failed: {error}")),
            provisioning(&key),
        )
        .unwrap_or_else(|error| panic!("initial snapshot failed: {error}"));
        let mut issued = issue(&initial, &key, &intent(1, 21));
        issued.acquire_records[0].signature[0] ^= 1;
        assert!(matches!(
            issued.validate(),
            Err(ModelError::ProofEnvelopeDigestMismatch | ModelError::InvalidProofSignature)
        ));
    }

    #[test]
    fn retained_record_bound_accepts_exact_and_rejects_plus_one() {
        let key = SigningKey::from_bytes(&[22; 32]);
        let mut snapshot = AuthoritySnapshot::initial(
            StoreInstanceId::try_from_bytes([23; 32])
                .unwrap_or_else(|error| panic!("fixture store failed: {error}")),
            provisioning(&key),
        )
        .unwrap_or_else(|error| panic!("initial snapshot failed: {error}"));
        const RECORD_COUNT: usize = 64;
        const FIXTURE_WORKERS: usize = 8;
        let mut records = std::thread::scope(|scope| {
            let snapshot = &snapshot;
            let mut workers = Vec::with_capacity(FIXTURE_WORKERS);
            for worker_index in 0..FIXTURE_WORKERS {
                workers.push(scope.spawn(move || {
                    let key = SigningKey::from_bytes(&[22; 32]);
                    ((worker_index + 1)..=RECORD_COUNT)
                        .step_by(FIXTURE_WORKERS)
                        .map(|epoch| {
                            let epoch = u8::try_from(epoch)
                                .unwrap_or_else(|_| panic!("fixture epoch must fit u8"));
                            let acquire = intent(epoch, epoch);
                            record_for(snapshot, &key, &acquire, u64::from(epoch))
                        })
                        .collect::<Vec<_>>()
                }));
            }
            let mut records = Vec::with_capacity(RECORD_COUNT);
            for worker in workers {
                records.extend(
                    worker
                        .join()
                        .unwrap_or_else(|_| panic!("fixture record worker panicked")),
                );
            }
            records
        });
        records.sort_by_key(|record| record.operation_id);
        snapshot.acquire_records = records;
        snapshot.epoch_high_water = 64;
        snapshot.snapshot_sequence = 65;
        snapshot
            .validate()
            .unwrap_or_else(|error| panic!("exact capacity snapshot failed: {error}"));

        assert_eq!(
            snapshot.preflight(&intent(65, 65)),
            Err(ModelError::AcquireCapacityExceeded)
        );
        assert_eq!(snapshot.epoch_high_water, 64);
        assert_eq!(snapshot.snapshot_sequence, 65);
    }

    #[test]
    fn monotonic_counter_overflows_are_rejected_without_changing_state() {
        let key = SigningKey::from_bytes(&[24; 32]);
        let initial = AuthoritySnapshot::initial(
            StoreInstanceId::try_from_bytes([25; 32])
                .unwrap_or_else(|error| panic!("fixture store failed: {error}")),
            provisioning(&key),
        )
        .unwrap_or_else(|error| panic!("initial snapshot failed: {error}"));
        let acquire = intent(1, 26);

        let mut epoch_exhausted = initial.clone();
        epoch_exhausted.epoch_high_water = u64::MAX;
        assert_eq!(
            epoch_exhausted.preflight(&acquire),
            Err(ModelError::EpochOverflow)
        );
        assert_eq!(epoch_exhausted.epoch_high_water, u64::MAX);
        assert_eq!(epoch_exhausted.snapshot_sequence, 1);

        let mut sequence_exhausted = initial;
        sequence_exhausted.snapshot_sequence = u64::MAX;
        assert_eq!(
            sequence_exhausted.preflight(&acquire),
            Err(ModelError::SnapshotSequenceOverflow)
        );
        assert_eq!(sequence_exhausted.epoch_high_water, 0);
        assert_eq!(sequence_exhausted.snapshot_sequence, u64::MAX);
    }
}
