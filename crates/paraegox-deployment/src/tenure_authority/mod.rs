mod codec;
mod initializer;
mod model;
mod signer;
mod store;

use core::fmt;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use paraegox_kernel::{digest::Digest32, identity::PrincipalRef};
use paraegox_runtime_contracts::apply::TenureProofAuthority;
use zeroize::Zeroizing;

use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
use crate::tenure_protocol::{
    AcquireTenureProtocolErrorCode, AcquireTenureRequestV1, AcquireTenureResponseV1,
    ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
};

use self::codec::CodecError;
use self::initializer::{InitializationError, InitializationReceipt};
use self::model::{
    AcquireAuthorization, AcquireIntent, AcquireOperationId, AuthorityFingerprints,
    AuthorityProvisioning, EncodedAcquireResponse, ModelError, Preflight, StoreInstanceId,
};
use self::signer::{Ed25519TenureSigner, SignerError};
use self::store::{
    AuthorityStore, CommitFailpoint, FileStage, FilesystemPolicy, PublishFailure, PublishFault,
    StoreError, StoreOpenError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TenureAuthorityFingerprints {
    signing_key: Digest32,
    policy: Digest32,
    service_principal: Digest32,
    owner_identity: Digest32,
}

impl TenureAuthorityFingerprints {
    #[must_use]
    pub(crate) const fn new(
        signing_key: Digest32,
        policy: Digest32,
        service_principal: Digest32,
        owner_identity: Digest32,
    ) -> Self {
        Self {
            signing_key,
            policy,
            service_principal,
            owner_identity,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerAcquireAuthorization {
    principal: PrincipalRef,
    key: ControllerAcquireKeyRef,
    verification_key: [u8; 32],
    public_key_fingerprint: [u8; 32],
}

impl ControllerAcquireAuthorization {
    pub(crate) fn try_new(
        principal: PrincipalRef,
        key: ControllerAcquireKeyRef,
        verification_key: [u8; 32],
        public_key_fingerprint: ControllerPublicKeyFingerprint,
    ) -> Result<Self, TenureAuthorityProvisioningError> {
        let authorization = AcquireAuthorization {
            controller_principal: principal,
            controller_key: key,
            controller_verification_key: verification_key,
            controller_public_key_fingerprint: *public_key_fingerprint.as_bytes(),
        };
        // Full validation runs in TenureAuthorityProvisioning::try_new, where
        // all fixed policy inputs are validated as one immutable tuple.
        Ok(Self {
            principal: authorization.controller_principal,
            key: authorization.controller_key,
            verification_key: authorization.controller_verification_key,
            public_key_fingerprint: authorization.controller_public_key_fingerprint,
        })
    }

    const fn into_model(self) -> AcquireAuthorization {
        AcquireAuthorization {
            controller_principal: self.principal,
            controller_key: self.key,
            controller_verification_key: self.verification_key,
            controller_public_key_fingerprint: self.public_key_fingerprint,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TenureAuthorityProvisioning(AuthorityProvisioning);

impl TenureAuthorityProvisioning {
    pub(crate) fn try_new(
        source_scope: DeploymentScopeId,
        authorized_writer: DeploymentWriterRef,
        proof_authority: TenureProofAuthority,
        authority_verification_key: [u8; 32],
        controller_authorization: ControllerAcquireAuthorization,
        fingerprints: TenureAuthorityFingerprints,
    ) -> Result<Self, TenureAuthorityProvisioningError> {
        AuthorityProvisioning::try_new(
            source_scope,
            authorized_writer,
            proof_authority,
            authority_verification_key,
            controller_authorization.into_model(),
            AuthorityFingerprints {
                signing_key: fingerprints.signing_key,
                policy: fingerprints.policy,
                service_principal: fingerprints.service_principal,
                owner_identity: fingerprints.owner_identity,
            },
        )
        .map(Self)
        .map_err(map_provisioning_error)
    }

    #[must_use]
    pub(crate) const fn source_scope(self) -> DeploymentScopeId {
        self.0.source_scope
    }

    #[must_use]
    pub(crate) const fn authorized_writer(self) -> DeploymentWriterRef {
        self.0.authorized_writer
    }
}

pub(crate) fn ed25519_authority_key_fingerprint(
    verification_key: &[u8; 32],
) -> Result<Digest32, TenureAuthorityProvisioningError> {
    model::signing_key_fingerprint_for(verification_key).map_err(map_provisioning_error)
}

pub(crate) fn initialize_tenure_authority_store(
    directory: &Path,
    provisioning: TenureAuthorityProvisioning,
) -> Result<TenureAuthorityInitializationReceipt, TenureAuthorityInitializationError> {
    initializer::initialize(directory, provisioning.0)
        .map(TenureAuthorityInitializationReceipt)
        .map_err(map_initialization_error)
}

pub(crate) fn reconstruct_sequence_one_initialization_receipt(
    directory: &Path,
    provisioning: TenureAuthorityProvisioning,
) -> Result<TenureAuthorityInitializationReceipt, TenureAuthorityReceiptRecoveryError> {
    reconstruct_sequence_one_initialization_receipt_with_policy(
        directory,
        provisioning,
        FilesystemPolicy::ProductionReference,
    )
}

fn reconstruct_sequence_one_initialization_receipt_with_policy(
    directory: &Path,
    provisioning: TenureAuthorityProvisioning,
    filesystem_policy: FilesystemPolicy,
) -> Result<TenureAuthorityInitializationReceipt, TenureAuthorityReceiptRecoveryError> {
    let store = AuthorityStore::open_for_sequence_one_receipt_with_policy(
        directory,
        provisioning.0,
        filesystem_policy,
    )
    .map_err(map_receipt_store_error)?;
    let snapshot = store.snapshot().map_err(map_receipt_store_state_error)?;
    if snapshot.snapshot_sequence != 1
        || snapshot.epoch_high_water != 0
        || !snapshot.acquire_records.is_empty()
    {
        return Err(TenureAuthorityReceiptRecoveryError::NotSequenceOne);
    }
    let encoded = codec::encode_snapshot(snapshot)
        .map_err(|_| TenureAuthorityReceiptRecoveryError::InvalidSnapshot)?;
    InitializationReceipt::from_snapshot(snapshot, &encoded)
        .map(TenureAuthorityInitializationReceipt)
        .map_err(|_| TenureAuthorityReceiptRecoveryError::InvalidSnapshot)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TenureAuthorityInitializationReceipt(InitializationReceipt);

impl TenureAuthorityInitializationReceipt {
    #[must_use]
    pub(crate) const fn store_instance_id(&self) -> &[u8; 32] {
        self.0.store_instance_id_bytes()
    }

    #[must_use]
    pub(crate) const fn snapshot_sequence(&self) -> u64 {
        self.0.snapshot_sequence()
    }

    #[must_use]
    pub(crate) const fn epoch_high_water(&self) -> u64 {
        self.0.epoch_high_water()
    }

    #[must_use]
    pub(crate) const fn snapshot_checksum(&self) -> Digest32 {
        self.0.snapshot_checksum()
    }

    #[must_use]
    pub(crate) const fn receipt_digest(&self) -> Digest32 {
        self.0.receipt_digest()
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        self.0.canonical_bytes()
    }
}

pub(crate) struct DeploymentTenureAuthority {
    store: AuthorityStore,
    signer: Ed25519TenureSigner,
}

impl fmt::Debug for DeploymentTenureAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentTenureAuthority")
            .field("store", &self.store)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl DeploymentTenureAuthority {
    pub(crate) fn open(
        directory: &Path,
        expected_store_instance_id: [u8; 32],
        provisioning: TenureAuthorityProvisioning,
        private_seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, TenureAuthorityOpenError> {
        Self::open_with_policy(
            directory,
            expected_store_instance_id,
            provisioning,
            private_seed,
            FilesystemPolicy::ProductionReference,
        )
    }

    fn open_with_policy(
        directory: &Path,
        expected_store_instance_id: [u8; 32],
        provisioning: TenureAuthorityProvisioning,
        private_seed: Zeroizing<[u8; 32]>,
        filesystem_policy: FilesystemPolicy,
    ) -> Result<Self, TenureAuthorityOpenError> {
        let expected_store_instance_id =
            StoreInstanceId::try_from_bytes(expected_store_instance_id)
                .map_err(|_| TenureAuthorityOpenError::InvalidExpectedStoreIdentity)?;
        let signer = Ed25519TenureSigner::try_from_seed(
            provisioning.0.proof_authority,
            private_seed,
            provisioning.0.fingerprints.signing_key,
        )
        .map_err(map_open_signer_error)?;
        signer
            .validate_provisioning(&provisioning.0)
            .map_err(map_open_signer_error)?;
        let store = AuthorityStore::open_with_policy(
            directory,
            expected_store_instance_id,
            provisioning.0,
            filesystem_policy,
        )
        .map_err(map_open_store_error)?;
        Ok(Self { store, signer })
    }

    pub(crate) fn acquire_authorized_request(
        &mut self,
        request: &AcquireTenureRequestV1,
    ) -> Result<CommittedAcquireTenure, TenureAcquireError> {
        self.acquire_with_failpoint(request, CommitFailpoint::None)
    }

    fn acquire_with_failpoint(
        &mut self,
        request: &AcquireTenureRequestV1,
        failpoint: CommitFailpoint,
    ) -> Result<CommittedAcquireTenure, TenureAcquireError> {
        let snapshot = self
            .store
            .revalidate_current()
            .map_err(map_acquire_store_error)?
            .clone();
        validate_request_policy(&snapshot.provisioning, request)?;
        let intent = AcquireIntent::try_new(
            AcquireOperationId::try_from_bytes(*request.operation_id().as_bytes())
                .map_err(map_acquire_model_error)?,
            Digest32::from_bytes(*request.request_digest().as_bytes()),
            request.canonical_bytes(),
            request.writer(),
            request.client_nonce(),
            request.max_response_payload_bytes(),
        )
        .map_err(map_acquire_model_error)?;

        let Preflight::Issue {
            next_epoch,
            next_snapshot_sequence,
        } = snapshot
            .preflight(&intent)
            .map_err(map_acquire_model_error)?
        else {
            let Preflight::Replay {
                exact_response_bytes,
                response_digest,
                proof_envelope_digest,
            } = snapshot
                .preflight(&intent)
                .map_err(map_acquire_model_error)?
            else {
                return Err(TenureAcquireError::InvalidStoredResponse);
            };
            let response =
                AcquireTenureResponseV1::decode_for_request(&exact_response_bytes, request)
                    .map_err(|_| TenureAcquireError::InvalidStoredResponse)?;
            if response.response_digest().as_bytes() != response_digest.as_bytes()
                || response.proof_digest() != &proof_envelope_digest
            {
                return Err(TenureAcquireError::InvalidStoredResponse);
            }
            return Ok(CommittedAcquireTenure {
                response,
                disposition: AcquireDisposition::Replayed,
            });
        };

        // Capacity and both monotonic overflows have been rejected by
        // preflight before this cryptographic operation is reached.
        let signed = self
            .signer
            .sign(
                snapshot.provisioning.source_scope,
                intent.writer,
                next_epoch,
                snapshot.epoch_high_water,
                &intent.nonce,
            )
            .map_err(|_| TenureAcquireError::SigningFailed)?;
        let signature = signed.signature;
        let proof_envelope_digest = signed.envelope_digest;
        let response =
            AcquireTenureResponseV1::try_new(request, signed.proof).map_err(|error| {
                if error.code() == AcquireTenureProtocolErrorCode::ResponseBoundExceeded {
                    TenureAcquireError::ResponseBoundExceeded
                } else {
                    TenureAcquireError::ResponseEncodingFailed
                }
            })?;
        if response.proof_digest() != &proof_envelope_digest {
            return Err(TenureAcquireError::ResponseEncodingFailed);
        }
        let encoded_response = EncodedAcquireResponse::try_new(
            response.canonical_bytes(),
            Digest32::from_bytes(*response.response_digest().as_bytes()),
            proof_envelope_digest,
        )
        .map_err(map_acquire_model_error)?;
        let next = snapshot
            .with_issued_record(
                &intent,
                next_epoch,
                next_snapshot_sequence,
                signature,
                proof_envelope_digest,
                encoded_response,
            )
            .map_err(map_acquire_model_error)?;
        self.store
            .commit(next, failpoint)
            .map_err(map_acquire_store_error)?;
        Ok(CommittedAcquireTenure {
            response,
            disposition: AcquireDisposition::Issued,
        })
    }

    pub(crate) fn snapshot_sequence(&self) -> Result<u64, TenureAcquireError> {
        self.store
            .snapshot()
            .map(|snapshot| snapshot.snapshot_sequence)
            .map_err(map_acquire_store_error)
    }

    pub(crate) fn epoch_high_water(&self) -> Result<u64, TenureAcquireError> {
        self.store
            .snapshot()
            .map(|snapshot| snapshot.epoch_high_water)
            .map_err(map_acquire_store_error)
    }
}

fn validate_request_policy(
    provisioning: &AuthorityProvisioning,
    request: &AcquireTenureRequestV1,
) -> Result<(), TenureAcquireError> {
    let authorization = provisioning.authorization;
    if request.auth_algorithm() != 1 || request.auth_algorithm_version() != 1 {
        return Err(TenureAcquireError::UnsupportedRequestSignatureProfile);
    }
    let verifying_key = VerifyingKey::from_bytes(&authorization.controller_verification_key)
        .map_err(|_| TenureAcquireError::InvalidProvisionedControllerKey)?;
    let signature_bytes: [u8; 64] = request
        .auth_signature()
        .try_into()
        .map_err(|_| TenureAcquireError::InvalidRequestSignature)?;
    let transcript = request
        .signing_transcript()
        .map_err(|_| TenureAcquireError::InvalidRequestSignature)?;
    verifying_key
        .verify_strict(
            transcript.as_bytes(),
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| TenureAcquireError::InvalidRequestSignature)?;

    if request.scope() != provisioning.source_scope {
        return Err(TenureAcquireError::UnauthorizedScope);
    }
    if request.writer() != provisioning.authorized_writer {
        return Err(TenureAcquireError::UnauthorizedWriter);
    }
    if request.controller_principal() != authorization.controller_principal {
        return Err(TenureAcquireError::UnauthorizedControllerPrincipal);
    }
    if request.controller_key() != authorization.controller_key
        || request.controller_public_key_fingerprint().as_bytes()
            != &authorization.controller_public_key_fingerprint
    {
        return Err(TenureAcquireError::UnauthorizedControllerKey);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommittedAcquireTenure {
    response: AcquireTenureResponseV1,
    disposition: AcquireDisposition,
}

impl CommittedAcquireTenure {
    #[must_use]
    pub(crate) const fn response(&self) -> &AcquireTenureResponseV1 {
        &self.response
    }

    #[must_use]
    pub(crate) const fn disposition(&self) -> AcquireDisposition {
        self.disposition
    }

    #[must_use]
    pub(crate) fn into_response(self) -> AcquireTenureResponseV1 {
        self.response
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcquireDisposition {
    Issued,
    Replayed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TenureAuthorityProvisioningError {
    InvalidIdentity,
    InvalidAuthorityKey,
    InvalidControllerPolicy,
    UnsupportedSignatureProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TenureAuthorityInitializationError {
    EntropyUnavailableOrInvalid,
    InvalidProvisioning,
    ReadBackFailed,
    Store(TenureAuthorityFailureDiagnostic),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TenureAuthorityReceiptRecoveryError {
    Store(TenureAuthorityFailureDiagnostic),
    NotSequenceOne,
    InvalidSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TenureAuthorityOpenError {
    InvalidExpectedStoreIdentity,
    SigningKeyMismatch,
    Store(TenureAuthorityFailureDiagnostic),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TenureAcquireError {
    UnauthorizedScope,
    UnauthorizedWriter,
    UnauthorizedControllerPrincipal,
    UnauthorizedControllerKey,
    UnsupportedRequestSignatureProfile,
    InvalidProvisionedControllerKey,
    InvalidRequestSignature,
    OperationDigestConflict,
    CapacityExceeded,
    EpochOverflow,
    SnapshotSequenceOverflow,
    InvalidStoredResponse,
    SigningFailed,
    ResponseBoundExceeded,
    ResponseEncodingFailed,
    StoreStopped,
    RejectedBeforePublish(TenureAuthorityFailureDiagnostic),
    UncertainAfterPublish(TenureAuthorityFailureDiagnostic),
    StoreUnavailableOrInvalid(TenureAuthorityFailureDiagnostic),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TenureAuthorityFailureDiagnostic {
    code: &'static str,
    stage: &'static str,
    path_role: &'static str,
    fact: &'static str,
}

impl TenureAuthorityFailureDiagnostic {
    pub(crate) const fn new(
        code: &'static str,
        stage: &'static str,
        path_role: &'static str,
        fact: &'static str,
    ) -> Self {
        Self {
            code,
            stage,
            path_role,
            fact,
        }
    }

    pub(crate) const fn code(self) -> &'static str {
        self.code
    }

    pub(crate) const fn stage(self) -> &'static str {
        self.stage
    }

    pub(crate) const fn path_role(self) -> &'static str {
        self.path_role
    }

    pub(crate) const fn fact(self) -> &'static str {
        self.fact
    }
}

fn map_provisioning_error(error: ModelError) -> TenureAuthorityProvisioningError {
    match error {
        ModelError::InvalidVerificationKey
        | ModelError::WeakVerificationKey
        | ModelError::SigningKeyFingerprintMismatch => {
            TenureAuthorityProvisioningError::InvalidAuthorityKey
        }
        ModelError::InvalidControllerVerificationKey
        | ModelError::WeakControllerVerificationKey
        | ModelError::InvalidControllerKeyFingerprint
        | ModelError::ControllerKeyFingerprintMismatch
        | ModelError::ZeroControllerPrincipal
        | ModelError::ZeroControllerKeyReference
        | ModelError::ZeroControllerKeyFingerprint => {
            TenureAuthorityProvisioningError::InvalidControllerPolicy
        }
        ModelError::UnsupportedSignatureProfile => {
            TenureAuthorityProvisioningError::UnsupportedSignatureProfile
        }
        _ => TenureAuthorityProvisioningError::InvalidIdentity,
    }
}

fn map_initialization_error(error: InitializationError) -> TenureAuthorityInitializationError {
    match error {
        InitializationError::Entropy(_)
        | InitializationError::InvalidStoreIdentityWidth
        | InitializationError::InvalidTempTokenWidth
        | InitializationError::AllZeroTempToken => {
            TenureAuthorityInitializationError::EntropyUnavailableOrInvalid
        }
        InitializationError::Model(_) => TenureAuthorityInitializationError::InvalidProvisioning,
        InitializationError::Publish(error) => {
            TenureAuthorityInitializationError::Store(publish_diagnostic(error))
        }
        InitializationError::ReadBackMismatch => TenureAuthorityInitializationError::ReadBackFailed,
        InitializationError::Store(error) => {
            TenureAuthorityInitializationError::Store(store_open_diagnostic(error))
        }
        InitializationError::InvalidEncodedSnapshot | InitializationError::Codec(_) => {
            TenureAuthorityInitializationError::Store(TenureAuthorityFailureDiagnostic::new(
                "PXTA-SNAPSHOT-ENCODE-INVALID",
                "encode_snapshot",
                "active_snapshot",
                "invalid",
            ))
        }
        InitializationError::Digest(_) => {
            TenureAuthorityInitializationError::Store(TenureAuthorityFailureDiagnostic::new(
                "PXTA-SNAPSHOT-DIGEST-FAILED",
                "encode_snapshot",
                "active_snapshot",
                "digest_failed",
            ))
        }
    }
}

fn map_receipt_store_error(error: StoreOpenError) -> TenureAuthorityReceiptRecoveryError {
    TenureAuthorityReceiptRecoveryError::Store(store_open_diagnostic(error))
}

fn map_receipt_store_state_error(error: StoreError) -> TenureAuthorityReceiptRecoveryError {
    let diagnostic = match error {
        StoreError::Stopped => TenureAuthorityFailureDiagnostic::new(
            "PXTA-STORE-STOPPED",
            "read_snapshot",
            "active_snapshot",
            "stopped",
        ),
        _ => TenureAuthorityFailureDiagnostic::new(
            "PXTA-STORE-STATE-INVALID",
            "read_snapshot",
            "active_snapshot",
            "invalid",
        ),
    };
    TenureAuthorityReceiptRecoveryError::Store(diagnostic)
}

fn map_open_signer_error(_error: SignerError) -> TenureAuthorityOpenError {
    TenureAuthorityOpenError::SigningKeyMismatch
}

fn map_open_store_error(error: StoreOpenError) -> TenureAuthorityOpenError {
    TenureAuthorityOpenError::Store(store_open_diagnostic(error))
}

fn map_acquire_model_error(error: ModelError) -> TenureAcquireError {
    match error {
        ModelError::OperationDigestConflict => TenureAcquireError::OperationDigestConflict,
        ModelError::AcquireCapacityExceeded => TenureAcquireError::CapacityExceeded,
        ModelError::EpochOverflow => TenureAcquireError::EpochOverflow,
        ModelError::SnapshotSequenceOverflow => TenureAcquireError::SnapshotSequenceOverflow,
        _ => TenureAcquireError::StoreUnavailableOrInvalid(TenureAuthorityFailureDiagnostic::new(
            "PXTA-STORE-MODEL-INVALID",
            "validate_snapshot",
            "active_snapshot",
            "invalid",
        )),
    }
}

fn map_acquire_store_error(error: StoreError) -> TenureAcquireError {
    match error {
        StoreError::Stopped => TenureAcquireError::StoreStopped,
        StoreError::Publish(error @ PublishFailure::RejectedBeforePublish(_)) => {
            TenureAcquireError::RejectedBeforePublish(publish_diagnostic(error))
        }
        StoreError::Publish(error @ PublishFailure::UncertainAfterPublish(_)) => {
            TenureAcquireError::UncertainAfterPublish(publish_diagnostic(error))
        }
        StoreError::SequenceOverflow => TenureAcquireError::SnapshotSequenceOverflow,
        StoreError::Open(error) => {
            TenureAcquireError::StoreUnavailableOrInvalid(store_open_diagnostic(error))
        }
        StoreError::ActiveSnapshotChanged => {
            TenureAcquireError::StoreUnavailableOrInvalid(TenureAuthorityFailureDiagnostic::new(
                "PXTA-SNAPSHOT-CHANGED",
                "revalidate_snapshot",
                "active_snapshot",
                "identity_changed",
            ))
        }
        _ => TenureAcquireError::StoreUnavailableOrInvalid(TenureAuthorityFailureDiagnostic::new(
            "PXTA-STORE-STATE-INVALID",
            "validate_transition",
            "active_snapshot",
            "invalid",
        )),
    }
}

fn store_open_diagnostic(error: StoreOpenError) -> TenureAuthorityFailureDiagnostic {
    match error {
        StoreOpenError::LockContended => TenureAuthorityFailureDiagnostic::new(
            "PXTA-STORE-LOCK-CONTENDED",
            "acquire_lock",
            "lock",
            "contended",
        ),
        StoreOpenError::StoreInstanceMismatch => TenureAuthorityFailureDiagnostic::new(
            "PXTA-STORE-IDENTITY-MISMATCH",
            "validate_store_identity",
            "active_snapshot",
            "store_identity_mismatch",
        ),
        StoreOpenError::ProvisioningMismatch => TenureAuthorityFailureDiagnostic::new(
            "PXTA-STORE-PROVISIONING-MISMATCH",
            "validate_owner_provisioning",
            "active_snapshot",
            "owner_or_provisioning_mismatch",
        ),
        StoreOpenError::UnsupportedFilesystem => TenureAuthorityFailureDiagnostic::new(
            "PXTA-FILESYSTEM-ATOMICITY-UNSUPPORTED",
            "inspect_filesystem",
            "state_dir",
            "unsupported",
        ),
        StoreOpenError::Io(failure)
            if failure.stage == FileStage::OpenActive
                && failure.kind == std::io::ErrorKind::NotFound =>
        {
            TenureAuthorityFailureDiagnostic::new(
                "PXTA-SNAPSHOT-MISSING",
                "open_active",
                "active_snapshot",
                "missing",
            )
        }
        StoreOpenError::Io(failure)
            if failure.stage == FileStage::OpenLock
                && failure.kind == std::io::ErrorKind::NotFound =>
        {
            TenureAuthorityFailureDiagnostic::new(
                "PXTA-STORE-LOCK-MISSING",
                "open_lock",
                "lock",
                "missing",
            )
        }
        StoreOpenError::Codec(CodecError::ChecksumMismatch) => {
            TenureAuthorityFailureDiagnostic::new(
                "PXTA-SNAPSHOT-CHECKSUM-MISMATCH",
                "decode_snapshot",
                "active_snapshot",
                "checksum_mismatch",
            )
        }
        StoreOpenError::Codec(_) => TenureAuthorityFailureDiagnostic::new(
            "PXTA-SNAPSHOT-CORRUPT",
            "decode_snapshot",
            "active_snapshot",
            "invalid",
        ),
        StoreOpenError::ActiveEmpty
        | StoreOpenError::ActiveTooLarge
        | StoreOpenError::ActiveAllocationFailed
        | StoreOpenError::ActiveChangedDuringRead => TenureAuthorityFailureDiagnostic::new(
            "PXTA-SNAPSHOT-INVALID",
            "read_active",
            "active_snapshot",
            "invalid",
        ),
        StoreOpenError::Io(failure) => TenureAuthorityFailureDiagnostic::new(
            "PXTA-STORE-IO",
            file_stage_name(failure.stage),
            file_stage_path_role(failure.stage),
            "io_failure",
        ),
        StoreOpenError::DirectoryNotFresh => TenureAuthorityFailureDiagnostic::new(
            "PXTA-STORE-NOT-FRESH",
            "scan_directory",
            "state_dir",
            "not_fresh",
        ),
        StoreOpenError::PathMustBeAbsolute
        | StoreOpenError::UnsafeDirectoryPath
        | StoreOpenError::SymlinkInDirectoryPath
        | StoreOpenError::UnsafeDirectoryType
        | StoreOpenError::UnsafeDirectoryMode
        | StoreOpenError::DirectoryIdentityChanged => TenureAuthorityFailureDiagnostic::new(
            "PXTA-STATE-DIRECTORY-UNSAFE",
            "validate_directory",
            "state_dir",
            "unsafe",
        ),
        StoreOpenError::UnsafeFileType
        | StoreOpenError::UnsafeFileMode
        | StoreOpenError::FileOwnerMismatch => TenureAuthorityFailureDiagnostic::new(
            "PXTA-STORE-FILE-UNSAFE",
            "validate_file",
            "store_file",
            "unsafe",
        ),
        StoreOpenError::UnknownDirectoryEntry | StoreOpenError::TooManyOrphanTemps => {
            TenureAuthorityFailureDiagnostic::new(
                "PXTA-STORE-DIRECTORY-CONTAMINATED",
                "scan_directory",
                "state_dir",
                "unexpected_entry",
            )
        }
    }
}

fn publish_diagnostic(error: PublishFailure) -> TenureAuthorityFailureDiagnostic {
    let (code, fault, io_fact, injected_fact) = match error {
        PublishFailure::RejectedBeforePublish(fault) => (
            "PXTA-PUBLISH-REJECTED",
            fault,
            "io_failure_not_published",
            "not_published",
        ),
        PublishFailure::UncertainAfterPublish(fault) => (
            "PXTA-PUBLISH-UNCERTAIN",
            fault,
            "io_failure_publication_uncertain",
            "publication_uncertain",
        ),
    };
    let fact = if fault.kind.is_some() {
        io_fact
    } else {
        injected_fact
    };
    publish_fault_diagnostic(code, fault, fact)
}

fn publish_fault_diagnostic(
    code: &'static str,
    fault: PublishFault,
    fact: &'static str,
) -> TenureAuthorityFailureDiagnostic {
    TenureAuthorityFailureDiagnostic::new(
        code,
        file_stage_name(fault.stage),
        file_stage_path_role(fault.stage),
        fact,
    )
}

const fn file_stage_name(stage: FileStage) -> &'static str {
    match stage {
        FileStage::InspectDirectory => "inspect_directory",
        FileStage::OpenDirectory => "open_directory",
        FileStage::InspectFilesystem => "inspect_filesystem",
        FileStage::ScanDirectory => "scan_directory",
        FileStage::CreateLock => "create_lock",
        FileStage::OpenLock => "open_lock",
        FileStage::AcquireLock => "acquire_lock",
        FileStage::OpenActive => "open_active",
        FileStage::ReadActive => "read_active",
        FileStage::InspectOrphanTemp => "inspect_orphan_temp",
        FileStage::RemoveOrphanTemp => "remove_orphan_temp",
        FileStage::SyncOrphanCleanup => "sync_orphan_cleanup",
        FileStage::GenerateTempName => "generate_temp_name",
        FileStage::ValidateEncodedSnapshot => "validate_encoded_snapshot",
        FileStage::RequireMissingActive => "require_missing_active",
        FileStage::CreateTemp => "create_temp",
        FileStage::InspectTemp => "inspect_temp",
        FileStage::WriteTemp => "write_temp",
        FileStage::SyncTemp => "sync_temp",
        FileStage::Rename => "rename_snapshot",
        FileStage::SyncDirectory => "sync_directory",
        FileStage::ReturnDurableCommit => "return_durable_commit",
    }
}

const fn file_stage_path_role(stage: FileStage) -> &'static str {
    match stage {
        FileStage::InspectDirectory
        | FileStage::OpenDirectory
        | FileStage::InspectFilesystem
        | FileStage::ScanDirectory
        | FileStage::SyncOrphanCleanup
        | FileStage::SyncDirectory
        | FileStage::ReturnDurableCommit => "state_dir",
        FileStage::CreateLock | FileStage::OpenLock | FileStage::AcquireLock => "lock",
        FileStage::OpenActive | FileStage::ReadActive | FileStage::RequireMissingActive => {
            "active_snapshot"
        }
        FileStage::InspectOrphanTemp
        | FileStage::RemoveOrphanTemp
        | FileStage::GenerateTempName
        | FileStage::ValidateEncodedSnapshot
        | FileStage::CreateTemp
        | FileStage::InspectTemp
        | FileStage::WriteTemp
        | FileStage::SyncTemp
        | FileStage::Rename => "temp_snapshot",
    }
}

impl TenureAuthorityInitializationError {
    pub(crate) const fn diagnostic(self) -> TenureAuthorityFailureDiagnostic {
        match self {
            Self::EntropyUnavailableOrInvalid => TenureAuthorityFailureDiagnostic::new(
                "PXTA-INITIALIZATION-ENTROPY",
                "generate_identity",
                "state_dir",
                "entropy_invalid",
            ),
            Self::InvalidProvisioning => TenureAuthorityFailureDiagnostic::new(
                "PXTA-PROVISIONING-INVALID",
                "validate_provisioning",
                "provisioning",
                "invalid",
            ),
            Self::ReadBackFailed => TenureAuthorityFailureDiagnostic::new(
                "PXTA-SNAPSHOT-READBACK-MISMATCH",
                "read_back",
                "active_snapshot",
                "mismatch",
            ),
            Self::Store(diagnostic) => diagnostic,
        }
    }
}

impl TenureAuthorityReceiptRecoveryError {
    pub(crate) const fn diagnostic(self) -> TenureAuthorityFailureDiagnostic {
        match self {
            Self::Store(diagnostic) => diagnostic,
            Self::NotSequenceOne => TenureAuthorityFailureDiagnostic::new(
                "PXTA-RECEIPT-NOT-SEQUENCE-ONE",
                "validate_receipt_state",
                "active_snapshot",
                "not_sequence_one",
            ),
            Self::InvalidSnapshot => TenureAuthorityFailureDiagnostic::new(
                "PXTA-RECEIPT-SNAPSHOT-INVALID",
                "reconstruct_receipt",
                "active_snapshot",
                "invalid",
            ),
        }
    }
}

impl TenureAuthorityOpenError {
    pub(crate) const fn diagnostic(self) -> TenureAuthorityFailureDiagnostic {
        match self {
            Self::InvalidExpectedStoreIdentity => TenureAuthorityFailureDiagnostic::new(
                "PXTA-EXPECTED-STORE-IDENTITY-INVALID",
                "validate_expected_store_identity",
                "active_snapshot",
                "invalid",
            ),
            Self::SigningKeyMismatch => TenureAuthorityFailureDiagnostic::new(
                "PXTA-AUTHORITY-KEY-MISMATCH",
                "validate_signing_key",
                "private_seed",
                "key_mismatch",
            ),
            Self::Store(diagnostic) => diagnostic,
        }
    }
}

impl TenureAcquireError {
    pub(crate) const fn store_diagnostic(self) -> Option<TenureAuthorityFailureDiagnostic> {
        match self {
            Self::RejectedBeforePublish(diagnostic)
            | Self::UncertainAfterPublish(diagnostic)
            | Self::StoreUnavailableOrInvalid(diagnostic) => Some(diagnostic),
            _ => None,
        }
    }
}

impl fmt::Display for TenureAuthorityProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid tenure-authority provisioning: {self:?}")
    }
}

impl std::error::Error for TenureAuthorityProvisioningError {}

impl fmt::Display for TenureAuthorityInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "tenure-authority initialization failed: {self:?}"
        )
    }
}

impl std::error::Error for TenureAuthorityInitializationError {}

impl fmt::Display for TenureAuthorityReceiptRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "initialization receipt recovery failed: {self:?}"
        )
    }
}

impl std::error::Error for TenureAuthorityReceiptRecoveryError {}

impl fmt::Display for TenureAuthorityOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "tenure-authority open failed: {self:?}")
    }
}

impl std::error::Error for TenureAuthorityOpenError {}

impl fmt::Display for TenureAcquireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "tenure acquisition rejected: {self:?}")
    }
}

impl std::error::Error for TenureAcquireError {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::{digest::Digest32, identity::PrincipalRef};
    use paraegox_runtime_contracts::apply::{
        TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
    };
    use zeroize::Zeroizing;

    use crate::plan::{DeploymentScopeId, DeploymentWriterRef};
    use crate::tenure_protocol::{
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        AcquireTenureRequestV1, ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES, MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };

    use super::{
        AcquireDisposition, ControllerAcquireAuthorization, DeploymentTenureAuthority,
        TenureAcquireError, TenureAuthorityFingerprints, TenureAuthorityProvisioning,
        ed25519_authority_key_fingerprint,
    };
    use crate::tenure_authority::codec::{
        CodecError, ENVELOPE_HEADER_BYTES, ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES, decode_snapshot,
        envelope_checksum,
    };
    use crate::tenure_authority::initializer::initialize_fixture;
    use crate::tenure_authority::model::ModelError;
    use crate::tenure_authority::store::{
        ACTIVE_FILE_NAME, CommitFailpoint, FileStage, FilesystemPolicy, IoFailure, PublishFailure,
        PublishFault, StoreOpenError,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let fixture_root = std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|error| panic!("fixture root canonicalize failed: {error}"));
            let path = fixture_root.join(format!(
                "paraegox-authority-core-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("fixture directory create failed: {error}"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("fixture directory chmod failed: {error}"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn install_orphan_temp(directory: &Path, index: u64, bytes: &[u8]) -> PathBuf {
        let path = directory.join(format!(".authority.snapshot.tmp-{index:032x}"));
        fs::write(&path, bytes).unwrap_or_else(|error| panic!("orphan temp write failed: {error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("orphan temp chmod failed: {error}"));
        path
    }

    struct Fixture {
        directory: TestDirectory,
        provisioning: TenureAuthorityProvisioning,
        authority_seed: [u8; 32],
        controller_key: SigningKey,
        controller_principal: PrincipalRef,
        controller_key_ref: ControllerAcquireKeyRef,
        controller_fingerprint: ControllerPublicKeyFingerprint,
    }

    #[derive(Clone, Copy)]
    struct RequestIdentity {
        scope: DeploymentScopeId,
        writer: DeploymentWriterRef,
        principal: PrincipalRef,
        key_ref: ControllerAcquireKeyRef,
        fingerprint: ControllerPublicKeyFingerprint,
    }

    impl Fixture {
        fn new() -> Self {
            let fixture = Self::for_directory(TestDirectory::new());
            initialize_fixture(
                fixture.directory.path(),
                fixture.provisioning.0,
                vec![12; 32],
                vec![13; 16],
                CommitFailpoint::None,
            )
            .unwrap_or_else(|error| panic!("fixture initialize failed: {error}"));
            fixture
        }

        fn existing(path: PathBuf) -> Self {
            Self::for_directory(TestDirectory(path))
        }

        fn for_directory(directory: TestDirectory) -> Self {
            let authority_seed = [1; 32];
            let authority_key = SigningKey::from_bytes(&authority_seed);
            let authority_verification_key = authority_key.verifying_key().to_bytes();
            let controller_key = SigningKey::from_bytes(&[2; 32]);
            let controller_verification_key = controller_key.verifying_key().to_bytes();
            let controller_principal = PrincipalRef::from_bytes([3; 16]);
            let controller_key_ref = ControllerAcquireKeyRef::from_bytes([4; 16]);
            let controller_fingerprint =
                ControllerPublicKeyFingerprint::for_ed25519_key(&controller_verification_key)
                    .unwrap_or_else(|error| panic!("controller fingerprint failed: {error}"));
            let controller_authorization = ControllerAcquireAuthorization::try_new(
                controller_principal,
                controller_key_ref,
                controller_verification_key,
                controller_fingerprint,
            )
            .unwrap_or_else(|error| panic!("controller authorization failed: {error}"));
            let proof_authority = TenureProofAuthority::try_new(
                TenureAuthorityRef::from_bytes([5; 16]),
                TenureKeyRef::from_bytes([6; 16]),
                TenureProofAlgorithm::try_new(1)
                    .unwrap_or_else(|error| panic!("algorithm failed: {error}")),
                1,
            )
            .unwrap_or_else(|error| panic!("proof authority failed: {error}"));
            let fingerprints = TenureAuthorityFingerprints::new(
                ed25519_authority_key_fingerprint(&authority_verification_key)
                    .unwrap_or_else(|error| panic!("authority fingerprint failed: {error}")),
                Digest32::from_bytes([7; 32]),
                Digest32::from_bytes([8; 32]),
                Digest32::from_bytes([9; 32]),
            );
            let provisioning = TenureAuthorityProvisioning::try_new(
                DeploymentScopeId::from_bytes([10; 16]),
                DeploymentWriterRef::from_bytes([11; 16]),
                proof_authority,
                authority_verification_key,
                controller_authorization,
                fingerprints,
            )
            .unwrap_or_else(|error| panic!("provisioning failed: {error}"));
            Self {
                directory,
                provisioning,
                authority_seed,
                controller_key,
                controller_principal,
                controller_key_ref,
                controller_fingerprint,
            }
        }

        fn open(&self) -> DeploymentTenureAuthority {
            DeploymentTenureAuthority::open_with_policy(
                self.directory.path(),
                [12; 32],
                self.provisioning,
                Zeroizing::new(self.authority_seed),
                FilesystemPolicy::ExplicitFixture,
            )
            .unwrap_or_else(|error| panic!("authority open failed: {error}"))
        }

        fn request(&self, operation: u8, nonce: u8) -> AcquireTenureRequestV1 {
            self.request_with(
                operation,
                nonce,
                self.request_identity(),
                &self.controller_key,
            )
        }

        fn request_identity(&self) -> RequestIdentity {
            RequestIdentity {
                scope: self.provisioning.source_scope(),
                writer: self.provisioning.authorized_writer(),
                principal: self.controller_principal,
                key_ref: self.controller_key_ref,
                fingerprint: self.controller_fingerprint,
            }
        }

        fn request_with(
            &self,
            operation: u8,
            nonce: u8,
            identity: RequestIdentity,
            signing_key: &SigningKey,
        ) -> AcquireTenureRequestV1 {
            self.request_with_bound(
                operation,
                nonce,
                identity,
                signing_key,
                u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                    .unwrap_or_else(|_| panic!("response bound must fit u32")),
            )
        }

        fn request_with_bound(
            &self,
            operation: u8,
            nonce: u8,
            identity: RequestIdentity,
            signing_key: &SigningKey,
            response_bound: u32,
        ) -> AcquireTenureRequestV1 {
            let intent = AcquireTenureIntentV1::new(
                identity.scope,
                identity.writer,
                AcquireTenureOperationId::from_bytes([operation; 16]),
            );
            let draft = AcquireTenureRequestDraftV1::try_new(
                intent,
                identity.principal,
                identity.key_ref,
                identity.fingerprint,
                &[nonce; 32],
                response_bound,
            )
            .unwrap_or_else(|error| panic!("request draft failed: {error}"));
            let transcript = draft
                .signing_transcript()
                .unwrap_or_else(|error| panic!("request transcript failed: {error}"));
            draft
                .finalize_ed25519(
                    signing_key
                        .sign(transcript.as_bytes())
                        .to_bytes()
                        .as_slice(),
                )
                .unwrap_or_else(|error| panic!("request finalize failed: {error}"))
        }
    }

    #[test]
    fn authority_store_diagnostics_have_stable_non_sensitive_classifications() {
        let cases = [
            (
                StoreOpenError::LockContended,
                "PXTA-STORE-LOCK-CONTENDED",
                "acquire_lock",
                "lock",
                "contended",
            ),
            (
                StoreOpenError::Io(IoFailure {
                    stage: FileStage::OpenActive,
                    kind: std::io::ErrorKind::NotFound,
                }),
                "PXTA-SNAPSHOT-MISSING",
                "open_active",
                "active_snapshot",
                "missing",
            ),
            (
                StoreOpenError::Codec(CodecError::ChecksumMismatch),
                "PXTA-SNAPSHOT-CHECKSUM-MISMATCH",
                "decode_snapshot",
                "active_snapshot",
                "checksum_mismatch",
            ),
            (
                StoreOpenError::Codec(CodecError::InvalidMagic),
                "PXTA-SNAPSHOT-CORRUPT",
                "decode_snapshot",
                "active_snapshot",
                "invalid",
            ),
            (
                StoreOpenError::ActiveEmpty,
                "PXTA-SNAPSHOT-INVALID",
                "read_active",
                "active_snapshot",
                "invalid",
            ),
            (
                StoreOpenError::StoreInstanceMismatch,
                "PXTA-STORE-IDENTITY-MISMATCH",
                "validate_store_identity",
                "active_snapshot",
                "store_identity_mismatch",
            ),
            (
                StoreOpenError::ProvisioningMismatch,
                "PXTA-STORE-PROVISIONING-MISMATCH",
                "validate_owner_provisioning",
                "active_snapshot",
                "owner_or_provisioning_mismatch",
            ),
            (
                StoreOpenError::UnsupportedFilesystem,
                "PXTA-FILESYSTEM-ATOMICITY-UNSUPPORTED",
                "inspect_filesystem",
                "state_dir",
                "unsupported",
            ),
        ];
        for (error, code, stage, path_role, fact) in cases {
            let diagnostic = super::store_open_diagnostic(error);
            assert_eq!(diagnostic.code(), code);
            assert_eq!(diagnostic.stage(), stage);
            assert_eq!(diagnostic.path_role(), path_role);
            assert_eq!(diagnostic.fact(), fact);
        }

        let diagnostic =
            super::publish_diagnostic(PublishFailure::UncertainAfterPublish(PublishFault {
                stage: FileStage::SyncDirectory,
                kind: Some(std::io::ErrorKind::Other),
            }));
        assert_eq!(diagnostic.code(), "PXTA-PUBLISH-UNCERTAIN");
        assert_eq!(diagnostic.stage(), "sync_directory");
        assert_eq!(diagnostic.path_role(), "state_dir");
        assert_eq!(diagnostic.fact(), "io_failure_publication_uncertain");
    }

    #[test]
    fn issuance_commits_before_return_and_cross_restart_replay_is_byte_identical() {
        let fixture = Fixture::new();
        let request = fixture.request(1, 20);
        let first_bytes = {
            let mut authority = fixture.open();
            let committed = authority
                .acquire_authorized_request(&request)
                .unwrap_or_else(|error| panic!("issuance failed: {error}"));
            assert_eq!(committed.disposition(), AcquireDisposition::Issued);
            assert_eq!(authority.snapshot_sequence(), Ok(2));
            assert_eq!(authority.epoch_high_water(), Ok(1));
            assert_eq!(committed.response().proof().claim().epoch().value(), 1);
            committed.response().canonical_bytes().to_vec()
        };

        let mut restarted = fixture.open();
        let replay = restarted
            .acquire_authorized_request(&request)
            .unwrap_or_else(|error| panic!("replay failed: {error}"));
        assert_eq!(replay.disposition(), AcquireDisposition::Replayed);
        assert_eq!(replay.response().canonical_bytes(), first_bytes);
        assert_eq!(restarted.snapshot_sequence(), Ok(2));
        assert_eq!(restarted.epoch_high_water(), Ok(1));
    }

    #[test]
    fn same_operation_with_different_request_digest_conflicts_without_mutation() {
        let fixture = Fixture::new();
        let mut authority = fixture.open();
        authority
            .acquire_authorized_request(&fixture.request(1, 21))
            .unwrap_or_else(|error| panic!("issuance failed: {error}"));
        assert_eq!(
            authority.acquire_authorized_request(&fixture.request(1, 22)),
            Err(TenureAcquireError::OperationDigestConflict)
        );
        assert_eq!(authority.snapshot_sequence(), Ok(2));
        assert_eq!(authority.epoch_high_water(), Ok(1));
    }

    #[test]
    fn authenticated_too_small_response_bound_is_nonfatal_and_does_not_advance_epoch() {
        let fixture = Fixture::new();
        let request = fixture.request_with_bound(
            1,
            23,
            fixture.request_identity(),
            &fixture.controller_key,
            u32::try_from(MIN_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .unwrap_or_else(|_| panic!("minimum response bound must fit u32")),
        );
        let mut authority = fixture.open();
        assert_eq!(
            authority.acquire_authorized_request(&request),
            Err(TenureAcquireError::ResponseBoundExceeded)
        );
        assert_eq!(authority.snapshot_sequence(), Ok(1));
        assert_eq!(authority.epoch_high_water(), Ok(0));

        let committed = authority
            .acquire_authorized_request(&fixture.request(2, 24))
            .unwrap_or_else(|error| panic!("valid request after rejection failed: {error}"));
        assert_eq!(committed.disposition(), AcquireDisposition::Issued);
        assert_eq!(authority.snapshot_sequence(), Ok(2));
        assert_eq!(authority.epoch_high_water(), Ok(1));
    }

    #[test]
    fn valid_outer_checksum_cannot_hide_a_tampered_stored_request() {
        let fixture = Fixture::new();
        let request = fixture.request(1, 24);
        {
            let mut authority = fixture.open();
            authority
                .acquire_authorized_request(&request)
                .unwrap_or_else(|error| panic!("issuance failed: {error}"));
        }

        let active_path = fixture.directory.path().join(ACTIVE_FILE_NAME);
        let mut encoded = fs::read(&active_path)
            .unwrap_or_else(|error| panic!("active snapshot read failed: {error}"));
        let exact_request = request.canonical_bytes();
        let request_offset = encoded
            .windows(exact_request.len())
            .position(|window| window == exact_request)
            .unwrap_or_else(|| panic!("exact request was not retained in the snapshot"));
        encoded[request_offset + exact_request.len() - 1] ^= 1;
        let checksum = envelope_checksum(
            &encoded[..ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES],
            &encoded[ENVELOPE_HEADER_BYTES..],
        )
        .unwrap_or_else(|error| panic!("fixture checksum failed: {error}"));
        encoded[ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES..ENVELOPE_HEADER_BYTES]
            .copy_from_slice(checksum.as_bytes());

        assert_eq!(
            decode_snapshot(&encoded),
            Err(CodecError::Model(ModelError::StoredRequestBindingMismatch))
        );
        fs::write(&active_path, encoded)
            .unwrap_or_else(|error| panic!("tampered snapshot write failed: {error}"));
        let reopened = DeploymentTenureAuthority::open_with_policy(
            fixture.directory.path(),
            [12; 32],
            fixture.provisioning,
            Zeroizing::new(fixture.authority_seed),
            FilesystemPolicy::ExplicitFixture,
        );
        assert!(matches!(
            reopened,
            Err(super::TenureAuthorityOpenError::Store(_))
        ));
    }

    #[test]
    fn wrong_scope_writer_principal_key_or_signature_never_advances_epoch() {
        let fixture = Fixture::new();
        let rogue_key = SigningKey::from_bytes(&[30; 32]);
        let rogue_fingerprint =
            ControllerPublicKeyFingerprint::for_ed25519_key(&rogue_key.verifying_key().to_bytes())
                .unwrap_or_else(|error| panic!("rogue fingerprint failed: {error}"));
        let cases = [
            (
                fixture.request_with(
                    1,
                    31,
                    RequestIdentity {
                        scope: DeploymentScopeId::from_bytes([31; 16]),
                        ..fixture.request_identity()
                    },
                    &fixture.controller_key,
                ),
                TenureAcquireError::UnauthorizedScope,
            ),
            (
                fixture.request_with(
                    2,
                    32,
                    RequestIdentity {
                        writer: DeploymentWriterRef::from_bytes([32; 16]),
                        ..fixture.request_identity()
                    },
                    &fixture.controller_key,
                ),
                TenureAcquireError::UnauthorizedWriter,
            ),
            (
                fixture.request_with(
                    3,
                    33,
                    RequestIdentity {
                        principal: PrincipalRef::from_bytes([33; 16]),
                        ..fixture.request_identity()
                    },
                    &fixture.controller_key,
                ),
                TenureAcquireError::UnauthorizedControllerPrincipal,
            ),
            (
                fixture.request_with(
                    4,
                    34,
                    RequestIdentity {
                        key_ref: ControllerAcquireKeyRef::from_bytes([34; 16]),
                        fingerprint: rogue_fingerprint,
                        ..fixture.request_identity()
                    },
                    &fixture.controller_key,
                ),
                TenureAcquireError::UnauthorizedControllerKey,
            ),
            (
                fixture.request_with(5, 35, fixture.request_identity(), &rogue_key),
                TenureAcquireError::InvalidRequestSignature,
            ),
            (
                fixture.request_with(
                    6,
                    36,
                    RequestIdentity {
                        scope: DeploymentScopeId::from_bytes([36; 16]),
                        ..fixture.request_identity()
                    },
                    &rogue_key,
                ),
                TenureAcquireError::InvalidRequestSignature,
            ),
        ];
        let mut authority = fixture.open();
        for (request, expected) in cases {
            assert_eq!(
                authority.acquire_authorized_request(&request),
                Err(expected)
            );
            assert_eq!(authority.snapshot_sequence(), Ok(1));
            assert_eq!(authority.epoch_high_water(), Ok(0));
        }
    }

    #[test]
    fn publish_uncertainty_stops_owner_and_restart_replays_published_result() {
        let fixture = Fixture::new();
        let request = fixture.request(1, 40);
        {
            let mut authority = fixture.open();
            assert!(matches!(
                authority.acquire_with_failpoint(&request, CommitFailpoint::AfterRename),
                Err(TenureAcquireError::UncertainAfterPublish(_))
            ));
            assert_eq!(
                authority.acquire_authorized_request(&request),
                Err(TenureAcquireError::StoreStopped)
            );
            assert_eq!(
                authority.snapshot_sequence(),
                Err(TenureAcquireError::StoreStopped)
            );
            assert_eq!(
                authority.epoch_high_water(),
                Err(TenureAcquireError::StoreStopped)
            );
        }
        let mut restarted = fixture.open();
        let replay = restarted
            .acquire_authorized_request(&request)
            .unwrap_or_else(|error| panic!("restart replay failed: {error}"));
        assert_eq!(replay.disposition(), AcquireDisposition::Replayed);
        assert_eq!(replay.response().proof().claim().epoch().value(), 1);
        assert_eq!(restarted.epoch_high_water(), Ok(1));
    }

    #[test]
    fn sequence_one_receipt_can_be_reconstructed_without_the_lost_random_store_id() {
        let fixture = Fixture::for_directory(TestDirectory::new());
        let original = initialize_fixture(
            fixture.directory.path(),
            fixture.provisioning.0,
            vec![12; 32],
            vec![13; 16],
            CommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("fixture initialize failed: {error}"));
        let recovered = super::reconstruct_sequence_one_initialization_receipt_with_policy(
            fixture.directory.path(),
            fixture.provisioning,
            FilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("receipt reconstruction failed: {error}"));
        assert_eq!(
            recovered.store_instance_id(),
            original.store_instance_id_bytes()
        );
        assert_eq!(recovered.canonical_bytes(), original.canonical_bytes());
        assert_eq!(recovered.receipt_digest(), original.receipt_digest());
    }

    #[test]
    fn restart_after_configured_path_replacement_fails_closed_without_resetting_identity() {
        let fixture = Fixture::new();
        let configured_path = fixture.directory.path().to_path_buf();
        let retained_path = configured_path.with_extension("retained-store");
        fs::rename(&configured_path, &retained_path)
            .unwrap_or_else(|error| panic!("configured store rename failed: {error}"));
        fs::create_dir(&configured_path)
            .unwrap_or_else(|error| panic!("replacement store create failed: {error}"));
        fs::set_permissions(&configured_path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("replacement store chmod failed: {error}"));

        let reopened = DeploymentTenureAuthority::open_with_policy(
            &configured_path,
            [12; 32],
            fixture.provisioning,
            Zeroizing::new(fixture.authority_seed),
            FilesystemPolicy::ExplicitFixture,
        );
        let Err(super::TenureAuthorityOpenError::Store(diagnostic)) = reopened else {
            panic!("replacement path unexpectedly reopened Authority store");
        };
        assert_eq!(diagnostic.code(), "PXTA-STORE-LOCK-MISSING");
        assert!(!configured_path.join(ACTIVE_FILE_NAME).exists());
        assert!(retained_path.join(ACTIVE_FILE_NAME).is_file());

        fs::remove_dir(&configured_path)
            .unwrap_or_else(|error| panic!("replacement store cleanup failed: {error}"));
        fs::rename(&retained_path, &configured_path)
            .unwrap_or_else(|error| panic!("configured store restore failed: {error}"));
    }

    #[test]
    fn invalid_active_snapshot_never_promotes_a_valid_orphan_temp() {
        let fixture = Fixture::new();
        let active_path = fixture.directory.path().join(ACTIVE_FILE_NAME);
        let valid_snapshot = fs::read(&active_path)
            .unwrap_or_else(|error| panic!("active snapshot read failed: {error}"));
        let orphan = install_orphan_temp(fixture.directory.path(), 1, &valid_snapshot);

        let mut invalid_snapshot = valid_snapshot;
        invalid_snapshot[0] ^= 1;
        fs::write(&active_path, &invalid_snapshot)
            .unwrap_or_else(|error| panic!("invalid active snapshot write failed: {error}"));

        let reopened = DeploymentTenureAuthority::open_with_policy(
            fixture.directory.path(),
            [12; 32],
            fixture.provisioning,
            Zeroizing::new(fixture.authority_seed),
            FilesystemPolicy::ExplicitFixture,
        );
        let Err(super::TenureAuthorityOpenError::Store(diagnostic)) = reopened else {
            panic!("invalid active snapshot unexpectedly recovered from orphan temp");
        };
        assert_eq!(diagnostic.code(), "PXTA-SNAPSHOT-CORRUPT");
        assert_eq!(
            fs::read(&active_path)
                .unwrap_or_else(|error| panic!("invalid active snapshot reread failed: {error}")),
            invalid_snapshot
        );
        assert!(
            orphan.is_file(),
            "invalid active evidence must not be cleaned"
        );
    }

    #[test]
    fn valid_active_snapshot_remains_authoritative_over_a_higher_sequence_temp() {
        let fixture = Fixture::new();
        let active_path = fixture.directory.path().join(ACTIVE_FILE_NAME);
        let sequence_one = fs::read(&active_path)
            .unwrap_or_else(|error| panic!("sequence-one snapshot read failed: {error}"));
        {
            let mut authority = fixture.open();
            authority
                .acquire_authorized_request(&fixture.request(1, 49))
                .unwrap_or_else(|error| panic!("higher snapshot construction failed: {error}"));
        }
        let sequence_two = fs::read(&active_path)
            .unwrap_or_else(|error| panic!("sequence-two snapshot read failed: {error}"));
        fs::write(&active_path, &sequence_one)
            .unwrap_or_else(|error| panic!("sequence-one restore failed: {error}"));
        let orphan = install_orphan_temp(fixture.directory.path(), 2, &sequence_two);

        let authority = fixture.open();
        assert_eq!(authority.snapshot_sequence(), Ok(1));
        assert_eq!(authority.epoch_high_water(), Ok(0));
        assert_eq!(
            fs::read(&active_path)
                .unwrap_or_else(|error| panic!("authoritative snapshot reread failed: {error}")),
            sequence_one
        );
        assert!(
            !orphan.exists(),
            "higher-sequence temp must only be cleaned"
        );
    }

    #[test]
    fn orphan_temp_scan_accepts_exact_limit_and_quarantines_plus_one_without_partial_cleanup() {
        let exact = Fixture::new();
        let exact_snapshot = fs::read(exact.directory.path().join(ACTIVE_FILE_NAME))
            .unwrap_or_else(|error| panic!("exact-limit snapshot read failed: {error}"));
        let exact_orphans = (0..32)
            .map(|index| install_orphan_temp(exact.directory.path(), index, &exact_snapshot))
            .collect::<Vec<_>>();
        let exact_authority = exact.open();
        assert_eq!(exact_authority.snapshot_sequence(), Ok(1));
        assert!(exact_orphans.iter().all(|path| !path.exists()));
        drop(exact_authority);

        let overflow = Fixture::new();
        let active_path = overflow.directory.path().join(ACTIVE_FILE_NAME);
        let overflow_snapshot = fs::read(&active_path)
            .unwrap_or_else(|error| panic!("overflow snapshot read failed: {error}"));
        let overflow_orphans = (0..33)
            .map(|index| install_orphan_temp(overflow.directory.path(), index, &overflow_snapshot))
            .collect::<Vec<_>>();
        let reopened = DeploymentTenureAuthority::open_with_policy(
            overflow.directory.path(),
            [12; 32],
            overflow.provisioning,
            Zeroizing::new(overflow.authority_seed),
            FilesystemPolicy::ExplicitFixture,
        );
        let Err(super::TenureAuthorityOpenError::Store(diagnostic)) = reopened else {
            panic!("orphan-temp limit + 1 unexpectedly opened");
        };
        assert_eq!(diagnostic.code(), "PXTA-STORE-DIRECTORY-CONTAMINATED");
        assert_eq!(
            fs::read(&active_path)
                .unwrap_or_else(|error| panic!("overflow active snapshot reread failed: {error}")),
            overflow_snapshot
        );
        assert!(
            overflow_orphans.iter().all(|path| path.is_file()),
            "overflow quarantine must not partially clean evidence"
        );
    }

    #[test]
    fn subprocess_crashes_leave_only_strict_old_or_new_authority_state() {
        let cases = [
            ("temp-create", false),
            ("header-partial-write", false),
            ("checksum-partial-write", false),
            ("payload-partial-write", false),
            ("before-file-fsync", false),
            ("file-fsync", false),
            ("rename", true),
            ("directory-fsync", true),
            ("durable-commit-before-reply", true),
        ];
        for (point, published) in cases {
            let fixture = Fixture::new();
            let status = Command::new(
                std::env::current_exe()
                    .unwrap_or_else(|error| panic!("test executable lookup failed: {error}")),
            )
            .args([
                "--exact",
                "tenure_authority::tests::subprocess_publish_crash_child",
                "--nocapture",
            ])
            .env(
                "PARAEGOX_TEST_AUTHORITY_CRASH_STORE",
                fixture.directory.path(),
            )
            .env("PARAEGOX_TEST_AUTHORITY_CRASH_POINT", point)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|error| panic!("crash child spawn failed: {error}"));
            assert!(
                !status.success(),
                "crash child unexpectedly returned at {point}"
            );

            let request = fixture.request(1, 50);
            let mut recovered = fixture.open();
            assert_eq!(recovered.epoch_high_water(), Ok(u64::from(published)));
            let result = recovered
                .acquire_authorized_request(&request)
                .unwrap_or_else(|error| panic!("post-crash acquire failed at {point}: {error}"));
            assert_eq!(
                result.disposition(),
                if published {
                    AcquireDisposition::Replayed
                } else {
                    AcquireDisposition::Issued
                }
            );
            assert_eq!(recovered.epoch_high_water(), Ok(1));
        }
    }

    #[test]
    fn subprocess_publish_crash_child() {
        let Ok(store) = std::env::var("PARAEGOX_TEST_AUTHORITY_CRASH_STORE") else {
            return;
        };
        let point = std::env::var("PARAEGOX_TEST_AUTHORITY_CRASH_POINT")
            .unwrap_or_else(|error| panic!("crash point missing: {error}"));
        let failpoint = match point.as_str() {
            "temp-create" => CommitFailpoint::AbortAfterTempCreate,
            "header-partial-write" => CommitFailpoint::AbortAfterHeaderPartialWrite,
            "checksum-partial-write" => CommitFailpoint::AbortAfterChecksumPartialWrite,
            "payload-partial-write" => CommitFailpoint::AbortAfterPayloadPartialWrite,
            "before-file-fsync" => CommitFailpoint::AbortBeforeFileSync,
            "file-fsync" => CommitFailpoint::AbortAfterFileSync,
            "rename" => CommitFailpoint::AbortAfterRename,
            "directory-fsync" => CommitFailpoint::AbortAfterDirectorySync,
            "durable-commit-before-reply" => CommitFailpoint::AbortAfterDurableCommitBeforeReturn,
            _ => panic!("unknown crash point"),
        };
        let fixture = Fixture::existing(PathBuf::from(store));
        let request = fixture.request(1, 50);
        let mut authority = fixture.open();
        let result = authority.acquire_with_failpoint(&request, failpoint);
        panic!("crash failpoint unexpectedly returned: {result:?}");
    }

    #[test]
    fn normal_drop_unlocks_even_while_a_fork_like_descriptor_reference_survives() {
        let fixture = Fixture::new();
        let authority = fixture.open();
        let inherited_lock_reference = authority
            .store
            .clone_lock_descriptor_for_test()
            .unwrap_or_else(|error| panic!("lock descriptor clone failed: {error}"));

        drop(authority);
        let replacement = fixture.open();

        drop(replacement);
        drop(inherited_lock_reference);
    }

    #[test]
    fn lock_descriptor_is_closed_across_exec_even_when_spawned_child_survives_owner() {
        let fixture = Fixture::new();
        let marker_root = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|error| panic!("fixture root canonicalize failed: {error}"));
        let marker = marker_root.join(format!(
            "paraegox-authority-lock-child-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let status = Command::new(
            std::env::current_exe()
                .unwrap_or_else(|error| panic!("test executable lookup failed: {error}")),
        )
        .args([
            "--exact",
            "tenure_authority::tests::subprocess_lock_owner_child",
            "--nocapture",
        ])
        .env(
            "PARAEGOX_TEST_AUTHORITY_LOCK_STORE",
            fixture.directory.path(),
        )
        .env("PARAEGOX_TEST_AUTHORITY_LOCK_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|error| panic!("lock owner child spawn failed: {error}"));
        assert!(!status.success());
        let sleeper_pid = fs::read_to_string(&marker)
            .unwrap_or_else(|error| panic!("sleeper marker read failed: {error}"));

        let replacement = DeploymentTenureAuthority::open_with_policy(
            fixture.directory.path(),
            [12; 32],
            fixture.provisioning,
            Zeroizing::new(fixture.authority_seed),
            FilesystemPolicy::ExplicitFixture,
        );
        let _ = Command::new("/bin/kill").arg(sleeper_pid.trim()).status();
        let _ = fs::remove_file(&marker);
        replacement.unwrap_or_else(|error| {
            panic!("replacement could not acquire CLOEXEC-protected lock: {error}")
        });
    }

    #[test]
    fn subprocess_lock_owner_child() {
        let Ok(store) = std::env::var("PARAEGOX_TEST_AUTHORITY_LOCK_STORE") else {
            return;
        };
        let marker = std::env::var("PARAEGOX_TEST_AUTHORITY_LOCK_MARKER")
            .unwrap_or_else(|error| panic!("lock marker missing: {error}"));
        let fixture = Fixture::existing(PathBuf::from(store));
        let _authority = fixture.open();
        let sleeper = Command::new("/bin/sleep")
            .arg("10")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("sleeper spawn failed: {error}"));
        fs::write(marker, sleeper.id().to_string())
            .unwrap_or_else(|error| panic!("sleeper marker write failed: {error}"));
        std::process::abort();
    }
}
