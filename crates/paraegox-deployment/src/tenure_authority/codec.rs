use core::fmt;

use paraegox_kernel::{
    digest::{Digest32, Digest32Builder, DigestBuildError},
    identity::PrincipalRef,
};
use paraegox_runtime_contracts::apply::{
    TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
};

use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
use crate::tenure_protocol::ControllerAcquireKeyRef;

use super::model::{
    AUTHORITY_SNAPSHOT_MAX_BYTES, AcquireAuthorization, AcquireOperationId, AcquireRecord,
    AuthorityFingerprints, AuthorityProvisioning, AuthoritySnapshot, ED25519_PUBLIC_KEY_BYTES,
    ED25519_SIGNATURE_BYTES, IssuanceStatus, MAX_ACQUIRE_REQUEST_BYTES, MAX_ACQUIRE_RESPONSE_BYTES,
    MAX_RETAINED_ACQUIRE_RECORDS, ModelError, StoreInstanceId,
};

pub(super) const JOURNAL_MAGIC: [u8; 4] = *b"PXJR";
pub(super) const JOURNAL_ENVELOPE_VERSION: u16 = 1;
pub(super) const AUTHORITY_OWNER_KIND: u8 = 2;
pub(super) const AUTHORITY_PAYLOAD_VERSION: u16 = 1;
pub(super) const CHECKSUM_ALGORITHM_SHA256: u8 = 1;
pub(super) const CHECKSUM_ALGORITHM_VERSION: u8 = 1;
pub(super) const ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES: usize = 91;
pub(super) const ENVELOPE_HEADER_BYTES: usize = 123;

const AUTHORITY_ENVELOPE_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.deployment.tenure-authority.journal-envelope.sha256.v1";

pub(super) fn encode_snapshot(snapshot: &AuthoritySnapshot) -> Result<Vec<u8>, CodecError> {
    snapshot.validate()?;
    let payload = encode_payload(snapshot)?;
    let payload_length = u64::try_from(payload.len()).map_err(|_| CodecError::LengthOverflow)?;

    let mut header = Vec::with_capacity(ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES);
    header.extend_from_slice(&JOURNAL_MAGIC);
    header.extend_from_slice(&JOURNAL_ENVELOPE_VERSION.to_be_bytes());
    header.push(AUTHORITY_OWNER_KIND);
    header.extend_from_slice(&AUTHORITY_PAYLOAD_VERSION.to_be_bytes());
    header.push(CHECKSUM_ALGORITHM_SHA256);
    header.push(CHECKSUM_ALGORITHM_VERSION);
    header.extend_from_slice(snapshot.store_instance_id.as_bytes());
    header.extend_from_slice(snapshot.owner_identity_fingerprint.as_bytes());
    header.extend_from_slice(&snapshot.snapshot_sequence.to_be_bytes());
    header.extend_from_slice(&payload_length.to_be_bytes());
    if header.len() != ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES {
        return Err(CodecError::InternalHeaderLayout);
    }

    let checksum = envelope_checksum(&header, &payload)?;
    let total_length = ENVELOPE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(CodecError::LengthOverflow)?;
    if total_length > AUTHORITY_SNAPSHOT_MAX_BYTES {
        return Err(CodecError::EnvelopeTooLarge);
    }
    let mut encoded = Vec::with_capacity(total_length);
    encoded.extend_from_slice(&header);
    encoded.extend_from_slice(checksum.as_bytes());
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

pub(super) fn decode_snapshot(encoded: &[u8]) -> Result<AuthoritySnapshot, CodecError> {
    if encoded.len() > AUTHORITY_SNAPSHOT_MAX_BYTES {
        return Err(CodecError::EnvelopeTooLarge);
    }
    if encoded.len() < ENVELOPE_HEADER_BYTES {
        return Err(CodecError::TruncatedEnvelopeHeader);
    }

    let mut header = Cursor::new(&encoded[..ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES]);
    if header.array::<4>()? != JOURNAL_MAGIC {
        return Err(CodecError::InvalidMagic);
    }
    if header.u16()? != JOURNAL_ENVELOPE_VERSION {
        return Err(CodecError::UnknownEnvelopeVersion);
    }
    if header.u8()? != AUTHORITY_OWNER_KIND {
        return Err(CodecError::OwnerKindMismatch);
    }
    if header.u16()? != AUTHORITY_PAYLOAD_VERSION {
        return Err(CodecError::UnknownPayloadVersion);
    }
    if header.u8()? != CHECKSUM_ALGORITHM_SHA256 {
        return Err(CodecError::UnknownChecksumAlgorithm);
    }
    if header.u8()? != CHECKSUM_ALGORITHM_VERSION {
        return Err(CodecError::UnknownChecksumVersion);
    }
    let store_instance_id = StoreInstanceId::try_from_bytes(header.array::<32>()?)?;
    let owner_identity_fingerprint = Digest32::from_bytes(header.array::<32>()?);
    let snapshot_sequence = header.u64()?;
    let declared_payload_length = header.u64()?;
    if !header.is_finished() {
        return Err(CodecError::InternalHeaderLayout);
    }

    let payload_length = usize::try_from(declared_payload_length)
        .map_err(|_| CodecError::DeclaredPayloadTooLarge)?;
    let expected_length = ENVELOPE_HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(CodecError::DeclaredPayloadTooLarge)?;
    if expected_length > AUTHORITY_SNAPSHOT_MAX_BYTES {
        return Err(CodecError::DeclaredPayloadTooLarge);
    }
    if encoded.len() < expected_length {
        return Err(CodecError::TruncatedPayload);
    }
    if encoded.len() > expected_length {
        return Err(CodecError::TrailingBytes);
    }

    let expected_checksum = Digest32::from_bytes(
        encoded[ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES..ENVELOPE_HEADER_BYTES]
            .try_into()
            .map_err(|_| CodecError::TruncatedEnvelopeHeader)?,
    );
    let payload = &encoded[ENVELOPE_HEADER_BYTES..];
    let actual_checksum =
        envelope_checksum(&encoded[..ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES], payload)?;
    if actual_checksum != expected_checksum {
        return Err(CodecError::ChecksumMismatch);
    }

    let snapshot = decode_payload(
        payload,
        store_instance_id,
        owner_identity_fingerprint,
        snapshot_sequence,
    )?;
    snapshot.validate()?;
    if encode_snapshot(&snapshot)?.as_slice() != encoded {
        return Err(CodecError::NonCanonicalEncoding);
    }
    Ok(snapshot)
}

fn encode_payload(snapshot: &AuthoritySnapshot) -> Result<Vec<u8>, CodecError> {
    let provisioning = snapshot.provisioning;
    let proof_authority = provisioning.proof_authority;
    let record_count = u16::try_from(snapshot.acquire_records.len())
        .map_err(|_| CodecError::RecordCountTooLarge)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(provisioning.source_scope.as_bytes());
    encoded.extend_from_slice(provisioning.authorized_writer.as_bytes());
    encoded.extend_from_slice(proof_authority.authority().as_bytes());
    encoded.extend_from_slice(proof_authority.key().as_bytes());
    encoded.extend_from_slice(&proof_authority.algorithm().value().to_be_bytes());
    encoded.extend_from_slice(&proof_authority.algorithm_version().to_be_bytes());
    encoded.extend_from_slice(&provisioning.verification_key);
    encoded.extend_from_slice(provisioning.authorization.controller_principal.as_bytes());
    encoded.extend_from_slice(provisioning.authorization.controller_key.as_bytes());
    encoded.extend_from_slice(&provisioning.authorization.controller_verification_key);
    encoded.extend_from_slice(&provisioning.authorization.controller_public_key_fingerprint);
    encoded.extend_from_slice(provisioning.fingerprints.signing_key.as_bytes());
    encoded.extend_from_slice(provisioning.fingerprints.policy.as_bytes());
    encoded.extend_from_slice(provisioning.fingerprints.service_principal.as_bytes());
    encoded.extend_from_slice(&snapshot.epoch_high_water.to_be_bytes());
    encoded.extend_from_slice(&record_count.to_be_bytes());

    for record in &snapshot.acquire_records {
        encoded.extend_from_slice(record.operation_id.as_bytes());
        encoded.extend_from_slice(record.request_digest.as_bytes());
        append_u32_bytes(&mut encoded, &record.exact_request_bytes)?;
        encoded.extend_from_slice(record.writer.as_bytes());
        encoded.extend_from_slice(&record.epoch.to_be_bytes());
        encoded.extend_from_slice(&record.supersedes_through_epoch.to_be_bytes());
        append_u16_bytes(&mut encoded, &record.nonce)?;
        encoded.extend_from_slice(&record.response_bound.to_be_bytes());
        append_u16_bytes(&mut encoded, &record.signature)?;
        encoded.extend_from_slice(record.proof_envelope_digest.as_bytes());
        append_u32_bytes(&mut encoded, &record.exact_response_bytes)?;
        encoded.extend_from_slice(record.response_digest.as_bytes());
        encoded.push(record.status as u8);
    }
    Ok(encoded)
}

fn decode_payload(
    payload: &[u8],
    store_instance_id: StoreInstanceId,
    owner_identity_fingerprint: Digest32,
    snapshot_sequence: u64,
) -> Result<AuthoritySnapshot, CodecError> {
    let mut fields = Cursor::new(payload);
    let source_scope = DeploymentScopeId::from_bytes(fields.array::<16>()?);
    let authorized_writer = DeploymentWriterRef::from_bytes(fields.array::<16>()?);
    let authority = TenureAuthorityRef::from_bytes(fields.array::<16>()?);
    let key = TenureKeyRef::from_bytes(fields.array::<16>()?);
    let algorithm = TenureProofAlgorithm::try_new(fields.u16()?)?;
    let algorithm_version = fields.u16()?;
    let proof_authority =
        TenureProofAuthority::try_new(authority, key, algorithm, algorithm_version)?;
    let verification_key = fields.array::<ED25519_PUBLIC_KEY_BYTES>()?;
    let authorization = AcquireAuthorization {
        controller_principal: PrincipalRef::from_bytes(fields.array::<16>()?),
        controller_key: ControllerAcquireKeyRef::from_bytes(fields.array::<16>()?),
        controller_verification_key: fields.array::<32>()?,
        controller_public_key_fingerprint: fields.array::<32>()?,
    };
    let signing_key_fingerprint = Digest32::from_bytes(fields.array::<32>()?);
    let policy_fingerprint = Digest32::from_bytes(fields.array::<32>()?);
    let service_principal_fingerprint = Digest32::from_bytes(fields.array::<32>()?);
    let epoch_high_water = fields.u64()?;
    let record_count = usize::from(fields.u16()?);
    if record_count > MAX_RETAINED_ACQUIRE_RECORDS {
        return Err(CodecError::RecordCountTooLarge);
    }
    let provisioning = AuthorityProvisioning::try_new(
        source_scope,
        authorized_writer,
        proof_authority,
        verification_key,
        authorization,
        AuthorityFingerprints {
            signing_key: signing_key_fingerprint,
            policy: policy_fingerprint,
            service_principal: service_principal_fingerprint,
            owner_identity: owner_identity_fingerprint,
        },
    )?;

    let mut acquire_records = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        let operation_id = AcquireOperationId::try_from_bytes(fields.array::<16>()?)?;
        let request_digest = Digest32::from_bytes(fields.array::<32>()?);
        let exact_request_bytes = fields.u32_bytes(MAX_ACQUIRE_REQUEST_BYTES)?;
        let writer = DeploymentWriterRef::from_bytes(fields.array::<16>()?);
        let epoch = fields.u64()?;
        let supersedes_through_epoch = fields.u64()?;
        let nonce = fields.u16_bytes(paraegox_runtime_contracts::apply::MAX_TENURE_NONCE_BYTES)?;
        let response_bound = fields.u32()?;
        let signature_bytes = fields.u16_bytes(ED25519_SIGNATURE_BYTES)?;
        let signature: [u8; ED25519_SIGNATURE_BYTES] = signature_bytes
            .as_ref()
            .try_into()
            .map_err(|_| CodecError::InvalidSignatureLength)?;
        let proof_envelope_digest = Digest32::from_bytes(fields.array::<32>()?);
        let exact_response_bytes = fields.u32_bytes(MAX_ACQUIRE_RESPONSE_BYTES)?;
        let response_digest = Digest32::from_bytes(fields.array::<32>()?);
        let status = match fields.u8()? {
            1 => IssuanceStatus::Issued,
            _ => return Err(CodecError::UnknownIssuanceStatus),
        };
        acquire_records.push(AcquireRecord {
            operation_id,
            request_digest,
            exact_request_bytes,
            writer,
            epoch,
            supersedes_through_epoch,
            nonce,
            response_bound,
            signature,
            proof_envelope_digest,
            exact_response_bytes,
            response_digest,
            status,
        });
    }
    if !fields.is_finished() {
        return Err(CodecError::TrailingPayloadBytes);
    }
    Ok(AuthoritySnapshot {
        store_instance_id,
        owner_identity_fingerprint,
        snapshot_sequence,
        provisioning,
        epoch_high_water,
        acquire_records,
    })
}

fn append_u16_bytes(encoded: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CodecError> {
    let length = u16::try_from(bytes.len()).map_err(|_| CodecError::LengthOverflow)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(bytes);
    Ok(())
}

fn append_u32_bytes(encoded: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CodecError> {
    let length = u32::try_from(bytes.len()).map_err(|_| CodecError::LengthOverflow)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn envelope_checksum(header: &[u8], payload: &[u8]) -> Result<Digest32, CodecError> {
    let mut builder = Digest32Builder::try_new(AUTHORITY_ENVELOPE_CHECKSUM_DOMAIN)?;
    builder.field_bytes(header)?;
    builder.field_bytes(payload)?;
    Ok(builder.finish())
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let Some((value, rest)) = self.remaining.split_at_checked(N) else {
            return Err(CodecError::TruncatedPayloadField);
        };
        self.remaining = rest;
        value
            .try_into()
            .map_err(|_| CodecError::TruncatedPayloadField)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn u16_bytes(&mut self, maximum: usize) -> Result<Box<[u8]>, CodecError> {
        let length = usize::from(self.u16()?);
        self.bytes(length, maximum)
    }

    fn u32_bytes(&mut self, maximum: usize) -> Result<Box<[u8]>, CodecError> {
        let length = usize::try_from(self.u32()?).map_err(|_| CodecError::LengthOverflow)?;
        self.bytes(length, maximum)
    }

    fn bytes(&mut self, length: usize, maximum: usize) -> Result<Box<[u8]>, CodecError> {
        if length > maximum {
            return Err(CodecError::FieldTooLarge);
        }
        let Some((value, rest)) = self.remaining.split_at_checked(length) else {
            return Err(CodecError::TruncatedPayloadField);
        };
        self.remaining = rest;
        Ok(value.into())
    }

    const fn is_finished(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CodecError {
    EnvelopeTooLarge,
    TruncatedEnvelopeHeader,
    InvalidMagic,
    UnknownEnvelopeVersion,
    OwnerKindMismatch,
    UnknownPayloadVersion,
    UnknownChecksumAlgorithm,
    UnknownChecksumVersion,
    DeclaredPayloadTooLarge,
    TruncatedPayload,
    TrailingBytes,
    ChecksumMismatch,
    TruncatedPayloadField,
    TrailingPayloadBytes,
    FieldTooLarge,
    RecordCountTooLarge,
    InvalidSignatureLength,
    UnknownIssuanceStatus,
    NonCanonicalEncoding,
    LengthOverflow,
    InternalHeaderLayout,
    Digest(DigestBuildError),
    Model(ModelError),
    Proof(paraegox_runtime_contracts::apply::TenureProofError),
}

impl From<DigestBuildError> for CodecError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

impl From<ModelError> for CodecError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<paraegox_runtime_contracts::apply::TenureProofError> for CodecError {
    fn from(error: paraegox_runtime_contracts::apply::TenureProofError) -> Self {
        Self::Proof(error)
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid tenure-authority journal encoding: {self:?}"
        )
    }
}

impl std::error::Error for CodecError {}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::{digest::Digest32, identity::PrincipalRef};
    use paraegox_runtime_contracts::apply::{
        PlanWriterEpoch, PlanWriterRef, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
        TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
    };
    use paraegox_runtime_contracts::provenance::SourceScopeRef;

    use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
    use crate::tenure_protocol::{
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        AcquireTenureResponseV1, ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };

    use super::{
        AUTHORITY_OWNER_KIND, CHECKSUM_ALGORITHM_SHA256, CHECKSUM_ALGORITHM_VERSION, CodecError,
        ENVELOPE_HEADER_BYTES, ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES, JOURNAL_ENVELOPE_VERSION,
        JOURNAL_MAGIC, decode_snapshot, encode_snapshot, envelope_checksum,
    };
    use crate::tenure_authority::model::{
        AUTHORITY_SNAPSHOT_MAX_BYTES, AcquireAuthorization, AcquireIntent, AcquireOperationId,
        AuthorityFingerprints, AuthorityProvisioning, AuthoritySnapshot, EncodedAcquireResponse,
        Preflight, StoreInstanceId, signing_key_fingerprint_for,
    };

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn initial_snapshot() -> AuthoritySnapshot {
        let signing_key = SigningKey::from_bytes(&[0x11; 32]);
        let verification_key = signing_key.verifying_key().to_bytes();
        let authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([0x22; 16]),
            TenureKeyRef::from_bytes([0x33; 16]),
            TenureProofAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("fixture algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("fixture authority failed: {error}"));
        let controller_signing_key = SigningKey::from_bytes(&[0x49; 32]);
        let controller_verification_key = controller_signing_key.verifying_key().to_bytes();
        let controller_public_key_fingerprint =
            crate::tenure_protocol::ControllerPublicKeyFingerprint::for_ed25519_key(
                &controller_verification_key,
            )
            .unwrap_or_else(|error| panic!("fixture controller fingerprint failed: {error}"));
        let provisioning = AuthorityProvisioning::try_new(
            DeploymentScopeId::from_bytes([0x44; 16]),
            crate::plan::DeploymentWriterRef::from_bytes([0x45; 16]),
            authority,
            verification_key,
            AcquireAuthorization {
                controller_principal: paraegox_kernel::identity::PrincipalRef::from_bytes(
                    [0x46; 16],
                ),
                controller_key: crate::tenure_protocol::ControllerAcquireKeyRef::from_bytes(
                    [0x47; 16],
                ),
                controller_verification_key,
                controller_public_key_fingerprint: *controller_public_key_fingerprint.as_bytes(),
            },
            AuthorityFingerprints {
                signing_key: signing_key_fingerprint_for(&verification_key)
                    .unwrap_or_else(|error| panic!("fixture fingerprint failed: {error}")),
                policy: digest(0x55),
                service_principal: digest(0x66),
                owner_identity: digest(0x77),
            },
        )
        .unwrap_or_else(|error| panic!("fixture provisioning failed: {error}"));
        AuthoritySnapshot::initial(
            StoreInstanceId::try_from_bytes([0x88; 32])
                .unwrap_or_else(|error| panic!("fixture store id failed: {error}")),
            provisioning,
        )
        .unwrap_or_else(|error| panic!("fixture snapshot failed: {error}"))
    }

    fn snapshot_with_record() -> AuthoritySnapshot {
        let initial = initial_snapshot();
        let authority_signing_key = SigningKey::from_bytes(&[0x11; 32]);
        let controller_signing_key = SigningKey::from_bytes(&[0x49; 32]);
        let controller_fingerprint = ControllerPublicKeyFingerprint::for_ed25519_key(
            &controller_signing_key.verifying_key().to_bytes(),
        )
        .unwrap_or_else(|error| panic!("fixture controller fingerprint failed: {error}"));
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                initial.provisioning.source_scope,
                initial.provisioning.authorized_writer,
                AcquireTenureOperationId::from_bytes([0x91; 16]),
            ),
            PrincipalRef::from_bytes([0x46; 16]),
            ControllerAcquireKeyRef::from_bytes([0x47; 16]),
            controller_fingerprint,
            &[0x92; 32],
            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .unwrap_or_else(|_| panic!("fixture response bound must fit u32")),
        )
        .unwrap_or_else(|error| panic!("fixture request draft failed: {error}"));
        let request_transcript = draft
            .signing_transcript()
            .unwrap_or_else(|error| panic!("fixture request transcript failed: {error}"));
        let request = draft
            .finalize_ed25519(
                controller_signing_key
                    .sign(request_transcript.as_bytes())
                    .to_bytes()
                    .as_slice(),
            )
            .unwrap_or_else(|error| panic!("fixture request failed: {error}"));
        let intent = AcquireIntent::try_new(
            AcquireOperationId::try_from_bytes([0x91; 16])
                .unwrap_or_else(|error| panic!("fixture operation failed: {error}")),
            Digest32::from_bytes(*request.request_digest().as_bytes()),
            request.canonical_bytes(),
            DeploymentWriterRef::from_bytes([0x45; 16]),
            request.client_nonce(),
            request.max_response_payload_bytes(),
        )
        .unwrap_or_else(|error| panic!("fixture intent failed: {error}"));
        let Preflight::Issue {
            next_epoch,
            next_snapshot_sequence,
        } = initial
            .preflight(&intent)
            .unwrap_or_else(|error| panic!("fixture preflight failed: {error}"))
        else {
            panic!("fresh fixture operation unexpectedly replayed");
        };
        let claim = WriterTenureClaim::try_new(
            SourceScopeRef::from_bytes(*initial.provisioning.source_scope.as_bytes()),
            PlanWriterRef::from_bytes(*initial.provisioning.authorized_writer.as_bytes()),
            PlanWriterEpoch::new(next_epoch),
            PlanWriterEpoch::new(initial.epoch_high_water),
        )
        .unwrap_or_else(|error| panic!("fixture claim failed: {error}"));
        let transcript = paraegox_runtime_contracts::apply::WriterTenureSigningTranscript::try_new(
            initial.provisioning.proof_authority,
            claim,
            &intent.nonce,
        )
        .unwrap_or_else(|error| panic!("fixture proof transcript failed: {error}"));
        let signature = authority_signing_key.sign(transcript.as_bytes()).to_bytes();
        let proof = WriterTenureProof::try_new(
            initial.provisioning.proof_authority,
            claim,
            &intent.nonce,
            &signature,
        )
        .unwrap_or_else(|error| panic!("fixture proof failed: {error}"));
        let proof_digest = proof
            .envelope_digest()
            .unwrap_or_else(|error| panic!("fixture proof digest failed: {error}"));
        let response = AcquireTenureResponseV1::try_new(&request, proof)
            .unwrap_or_else(|error| panic!("fixture response failed: {error}"));
        initial
            .with_issued_record(
                &intent,
                next_epoch,
                next_snapshot_sequence,
                signature,
                proof_digest,
                EncodedAcquireResponse::try_new(
                    response.canonical_bytes(),
                    Digest32::from_bytes(*response.response_digest().as_bytes()),
                    proof_digest,
                )
                .unwrap_or_else(|error| panic!("fixture encoded response failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("fixture issue failed: {error}"))
    }

    fn reseal_envelope(encoded: &mut [u8]) {
        let checksum = envelope_checksum(
            &encoded[..ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES],
            &encoded[ENVELOPE_HEADER_BYTES..],
        )
        .unwrap_or_else(|error| panic!("fixture checksum failed: {error}"));
        encoded[ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES..ENVELOPE_HEADER_BYTES]
            .copy_from_slice(checksum.as_bytes());
    }

    fn assert_exhaustive_fault_rejection(snapshot: &AuthoritySnapshot) {
        let mut encoded = encode_snapshot(snapshot)
            .unwrap_or_else(|error| panic!("snapshot encode failed: {error}"));
        for cut in 0..encoded.len() {
            assert!(
                decode_snapshot(&encoded[..cut]).is_err(),
                "truncation at byte {cut} was accepted"
            );
        }
        for byte_index in 0..encoded.len() {
            for bit in 0..u8::BITS {
                encoded[byte_index] ^= 1 << bit;
                assert!(
                    decode_snapshot(&encoded).is_err(),
                    "single-bit corruption at byte {byte_index}, bit {bit} was accepted"
                );
                encoded[byte_index] ^= 1 << bit;
            }
        }
    }

    #[test]
    fn initial_snapshot_has_shared_envelope_layout_and_round_trips() {
        let snapshot = initial_snapshot();
        let encoded = encode_snapshot(&snapshot)
            .unwrap_or_else(|error| panic!("snapshot encode failed: {error}"));

        assert_eq!(encoded.len(), 425);
        assert_eq!(
            &encoded[91..123],
            &[
                0x6b, 0x3d, 0xc4, 0x22, 0x19, 0x55, 0x5a, 0x95, 0x4e, 0x4a, 0x16, 0x72, 0x6d, 0x2f,
                0x2a, 0x59, 0xc6, 0xba, 0x60, 0x71, 0x3a, 0xfd, 0xfc, 0x16, 0x63, 0x21, 0xd0, 0x1c,
                0x53, 0x4b, 0xb6, 0x43,
            ]
        );
        assert_eq!(&encoded[..4], &JOURNAL_MAGIC);
        assert_eq!(
            u16::from_be_bytes([encoded[4], encoded[5]]),
            JOURNAL_ENVELOPE_VERSION
        );
        assert_eq!(encoded[6], AUTHORITY_OWNER_KIND);
        assert_eq!(encoded[9], CHECKSUM_ALGORITHM_SHA256);
        assert_eq!(encoded[10], CHECKSUM_ALGORITHM_VERSION);
        assert_eq!(&encoded[11..43], &[0x88; 32]);
        assert_eq!(&encoded[43..75], &[0x77; 32]);
        assert_eq!(
            u64::from_be_bytes(encoded[75..83].try_into().unwrap_or([0; 8])),
            1
        );
        assert_eq!(
            u64::from_be_bytes(encoded[83..91].try_into().unwrap_or([0; 8])) as usize,
            encoded.len() - ENVELOPE_HEADER_BYTES
        );
        assert_eq!(
            decode_snapshot(&encoded)
                .unwrap_or_else(|error| panic!("snapshot decode failed: {error}")),
            snapshot
        );
    }

    #[test]
    fn sequence_one_and_record_snapshots_reject_every_truncation_and_single_bit_corruption() {
        assert_exhaustive_fault_rejection(&initial_snapshot());
        assert_exhaustive_fault_rejection(&snapshot_with_record());
    }

    #[test]
    fn envelope_rejects_length_count_and_field_bombs_and_trailing_bytes() {
        let encoded = encode_snapshot(&initial_snapshot())
            .unwrap_or_else(|error| panic!("snapshot encode failed: {error}"));

        let mut bomb = encoded.clone();
        bomb[83..91].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            decode_snapshot(&bomb),
            Err(CodecError::DeclaredPayloadTooLarge)
        );

        let mut record_count_bomb = encoded.clone();
        let count_offset = record_count_bomb.len() - 2;
        record_count_bomb[count_offset..].copy_from_slice(&u16::MAX.to_be_bytes());
        reseal_envelope(&mut record_count_bomb);
        assert_eq!(
            decode_snapshot(&record_count_bomb),
            Err(CodecError::RecordCountTooLarge)
        );

        let mut field_bomb = encode_snapshot(&snapshot_with_record())
            .unwrap_or_else(|error| panic!("record snapshot encode failed: {error}"));
        let fixed_payload_bytes = encoded.len() - ENVELOPE_HEADER_BYTES;
        let request_length_offset = ENVELOPE_HEADER_BYTES + fixed_payload_bytes + 16 + 32;
        field_bomb[request_length_offset..request_length_offset + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        reseal_envelope(&mut field_bomb);
        assert_eq!(decode_snapshot(&field_bomb), Err(CodecError::FieldTooLarge));

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(decode_snapshot(&trailing), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn unknown_header_registry_values_and_owner_swap_are_rejected_before_payload_decode() {
        let encoded = encode_snapshot(&initial_snapshot())
            .unwrap_or_else(|error| panic!("snapshot encode failed: {error}"));
        let cases = [
            (4, 0xff, CodecError::UnknownEnvelopeVersion),
            (6, 1, CodecError::OwnerKindMismatch),
            (7, 0xff, CodecError::UnknownPayloadVersion),
            (9, 0xff, CodecError::UnknownChecksumAlgorithm),
            (10, 0xff, CodecError::UnknownChecksumVersion),
        ];
        for (offset, replacement, expected) in cases {
            let mut changed = encoded.clone();
            changed[offset] = replacement;
            assert_eq!(decode_snapshot(&changed), Err(expected));
        }
    }

    #[test]
    fn envelope_byte_bound_accepts_exact_and_rejects_plus_one_before_parsing() {
        let exact = vec![0; AUTHORITY_SNAPSHOT_MAX_BYTES];
        assert_ne!(decode_snapshot(&exact), Err(CodecError::EnvelopeTooLarge));

        let plus_one = vec![0; AUTHORITY_SNAPSHOT_MAX_BYTES + 1];
        assert_eq!(
            decode_snapshot(&plus_one),
            Err(CodecError::EnvelopeTooLarge)
        );
    }
}
