//! One-shot initializer for the Controller-owned POSIX journal store.
//!
//! Normal Controller startup must open an already initialized store. This
//! module is an internal install/admin mechanism, not a reset endpoint or a
//! public persistent-format API.

use core::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};

use crate::controller_journal::{
    ControllerJournalError, ControllerJournalSnapshot, ControllerJournalState,
    ControllerOwnerIdentityFingerprint, ControllerRequestAuthPin,
};
use crate::controller_store::{
    CONTROLLER_TEMP_TOKEN_BYTES, ControllerCommitFailpoint, ControllerFilesystemPolicy,
    ControllerInitializerLockFailure, ControllerPublishFailure, ControllerStore,
    ControllerStoreError, ControllerStoreOpenError, create_and_lock_controller_initializer_lock,
    ensure_fresh_controller_directory, open_controller_directory,
    publish_initial_controller_snapshot, read_active_controller_snapshot,
};
use crate::manifest_ingress::ControllerInstalledManifestPin;
use crate::plan::{DeploymentId, DeploymentScopeId};
use crate::planner::StableAllocationSnapshot;

const STORE_INSTANCE_ID_BYTES: usize = 32;
const INITIALIZATION_RECEIPT_MAGIC: &[u8] = b"PXCINIT\0";
const INITIALIZATION_RECEIPT_VERSION: u16 = 1;
const INITIALIZED_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.deployment.controller.initialized-snapshot.sha256.v1";
const INITIALIZATION_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.deployment.controller.initialization-receipt.sha256.v1";

/// Complete immutable inputs pinned by the Controller sequence-one snapshot.
pub(crate) struct ControllerInitializationInput {
    scope: DeploymentScopeId,
    plan_lineage: DeploymentId,
    allocation: StableAllocationSnapshot,
    installed_manifest: ControllerInstalledManifestPin,
    request_auth: ControllerRequestAuthPin,
    owner_identity_fingerprint: ControllerOwnerIdentityFingerprint,
}

impl ControllerInitializationInput {
    pub(crate) fn try_new(
        scope: DeploymentScopeId,
        plan_lineage: DeploymentId,
        allocation: StableAllocationSnapshot,
        installed_manifest: ControllerInstalledManifestPin,
        request_auth: ControllerRequestAuthPin,
        owner_identity_fingerprint: ControllerOwnerIdentityFingerprint,
    ) -> Result<Self, ControllerInitializationError> {
        // Constructing the exact state now validates every caller-controlled
        // field before entropy is requested or the directory is mutated.
        ControllerJournalState::try_initialize(
            scope,
            plan_lineage,
            allocation.clone(),
            installed_manifest.clone(),
            request_auth,
        )?;
        if owner_identity_fingerprint
            .value()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(ControllerJournalError::ZeroOwnerIdentityFingerprint.into());
        }
        Ok(Self {
            scope,
            plan_lineage,
            allocation,
            installed_manifest,
            request_auth,
            owner_identity_fingerprint,
        })
    }

    fn into_state(self) -> Result<ControllerJournalState, ControllerJournalError> {
        ControllerJournalState::try_initialize(
            self.scope,
            self.plan_lineage,
            self.allocation,
            self.installed_manifest,
            self.request_auth,
        )
    }
}

pub(crate) fn initialize_controller_store(
    directory: &Path,
    input: ControllerInitializationInput,
) -> Result<ControllerInitializationReceipt, ControllerInitializationError> {
    let mut entropy = SystemControllerInitializationEntropy;
    initialize_controller_store_with(
        directory,
        input,
        &mut entropy,
        ControllerFilesystemPolicy::ProductionReference,
        ControllerCommitFailpoint::None,
    )
}

pub(crate) fn reconstruct_sequence_one_controller_receipt(
    directory: &Path,
    expected_input: ControllerInitializationInput,
) -> Result<ControllerInitializationReceipt, ControllerReceiptRecoveryError> {
    let expected_owner_identity = expected_input.owner_identity_fingerprint;
    let expected_state = expected_input.into_state()?;
    let store = ControllerStore::open_for_sequence_one_receipt(directory, expected_owner_identity)?;
    receipt_from_sequence_one_store(store, &expected_state)
}

fn initialize_controller_store_with(
    directory: &Path,
    input: ControllerInitializationInput,
    entropy: &mut impl ControllerInitializationEntropy,
    filesystem_policy: ControllerFilesystemPolicy,
    failpoint: ControllerCommitFailpoint,
) -> Result<ControllerInitializationReceipt, ControllerInitializationError> {
    initialize_controller_store_with_readback_failpoint(
        directory,
        input,
        entropy,
        filesystem_policy,
        failpoint,
        ControllerInitializationReadBackFailpoint::None,
    )
}

fn initialize_controller_store_with_readback_failpoint(
    directory: &Path,
    input: ControllerInitializationInput,
    entropy: &mut impl ControllerInitializationEntropy,
    filesystem_policy: ControllerFilesystemPolicy,
    failpoint: ControllerCommitFailpoint,
    readback_failpoint: ControllerInitializationReadBackFailpoint,
) -> Result<ControllerInitializationReceipt, ControllerInitializationError> {
    let owner_identity_fingerprint = input.owner_identity_fingerprint;
    let state = input.into_state()?;
    let directory = open_controller_directory(directory, filesystem_policy)?;
    match ensure_fresh_controller_directory(&directory) {
        Ok(()) => {}
        Err(error @ ControllerStoreOpenError::InitializerMarkerAlreadyPresent) => {
            return Err(ControllerInitializationError::MarkerConsumed(
                ControllerInitializationAfterMarkerFailure::Lock(error),
            ));
        }
        Err(error) => return Err(ControllerInitializationError::Store(error)),
    }

    // Both random values are obtained and validated before lock/temp/snapshot
    // mutation. Production callers cannot inject a store identity.
    let store_bytes = entropy.store_instance_id()?;
    if store_bytes.len() != STORE_INSTANCE_ID_BYTES {
        return Err(ControllerInitializationError::InvalidStoreIdentityWidth);
    }
    let store_instance_id: [u8; STORE_INSTANCE_ID_BYTES] = store_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ControllerInitializationError::InvalidStoreIdentityWidth)?;
    if store_instance_id == [0; STORE_INSTANCE_ID_BYTES] {
        return Err(ControllerInitializationError::AllZeroStoreIdentity);
    }

    let temp_bytes = entropy.temp_token()?;
    if temp_bytes.len() != CONTROLLER_TEMP_TOKEN_BYTES {
        return Err(ControllerInitializationError::InvalidTempTokenWidth);
    }
    let temp_token: [u8; CONTROLLER_TEMP_TOKEN_BYTES] = temp_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ControllerInitializationError::InvalidTempTokenWidth)?;
    if temp_token == [0; CONTROLLER_TEMP_TOKEN_BYTES] {
        return Err(ControllerInitializationError::AllZeroTempToken);
    }

    let snapshot = ControllerJournalSnapshot::try_initialize(
        store_instance_id,
        owner_identity_fingerprint,
        state,
    )?;
    let encoded = snapshot.encode()?;
    let receipt = ControllerInitializationReceipt::from_snapshot(&snapshot, &encoded)?;

    let _lock = match create_and_lock_controller_initializer_lock(&directory) {
        Ok(lock) => lock,
        Err(ControllerInitializerLockFailure::RejectedBeforeMarker(error)) => {
            return Err(ControllerInitializationError::Store(error));
        }
        Err(ControllerInitializerLockFailure::MarkerConsumed(error)) => {
            return Err(ControllerInitializationError::MarkerConsumed(
                ControllerInitializationAfterMarkerFailure::Lock(error),
            ));
        }
    };
    publish_initial_controller_snapshot(&directory, &encoded, temp_token, failpoint).map_err(
        |error| {
            ControllerInitializationError::MarkerConsumed(
                ControllerInitializationAfterMarkerFailure::Publish(error),
            )
        },
    )?;
    let read_back = match readback_failpoint {
        ControllerInitializationReadBackFailpoint::None
        | ControllerInitializationReadBackFailpoint::Mismatch => {
            read_active_controller_snapshot(&directory)
        }
        ControllerInitializationReadBackFailpoint::Error(error) => Err(error),
    }
    .map_err(|error| {
        ControllerInitializationError::PublishedButUnverified(
            ControllerPublishedVerificationFailure::ReadBack(error),
        )
    })?;
    if readback_failpoint == ControllerInitializationReadBackFailpoint::Mismatch
        || read_back != snapshot
    {
        return Err(ControllerInitializationError::PublishedButUnverified(
            ControllerPublishedVerificationFailure::Mismatch,
        ));
    }
    Ok(receipt)
}

fn receipt_from_sequence_one_store(
    store: ControllerStore,
    expected_state: &ControllerJournalState,
) -> Result<ControllerInitializationReceipt, ControllerReceiptRecoveryError> {
    let snapshot = store.snapshot()?;
    if snapshot.snapshot_sequence() != 1 {
        return Err(ControllerReceiptRecoveryError::NotSequenceOne);
    }
    if snapshot.state() != expected_state {
        return Err(ControllerReceiptRecoveryError::InitializationBindingMismatch);
    }
    let encoded = snapshot.encode()?;
    ControllerInitializationReceipt::from_snapshot(snapshot, &encoded)
        .map_err(ControllerReceiptRecoveryError::Initialization)
}

#[cfg(test)]
fn reconstruct_sequence_one_controller_receipt_with_policy(
    directory: &Path,
    expected_input: ControllerInitializationInput,
    filesystem_policy: ControllerFilesystemPolicy,
) -> Result<ControllerInitializationReceipt, ControllerReceiptRecoveryError> {
    let expected_owner_identity = expected_input.owner_identity_fingerprint;
    let expected_state = expected_input.into_state()?;
    let store = ControllerStore::open_for_sequence_one_receipt_with_policy(
        directory,
        expected_owner_identity,
        filesystem_policy,
    )?;
    receipt_from_sequence_one_store(store, &expected_state)
}

trait ControllerInitializationEntropy {
    fn store_instance_id(&mut self) -> Result<Vec<u8>, ControllerInitializationEntropyError>;

    fn temp_token(&mut self) -> Result<Vec<u8>, ControllerInitializationEntropyError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControllerInitializationReadBackFailpoint {
    None,
    Error(ControllerStoreOpenError),
    Mismatch,
}

struct SystemControllerInitializationEntropy;

impl ControllerInitializationEntropy for SystemControllerInitializationEntropy {
    fn store_instance_id(&mut self) -> Result<Vec<u8>, ControllerInitializationEntropyError> {
        read_csprng_exact(STORE_INSTANCE_ID_BYTES)
    }

    fn temp_token(&mut self) -> Result<Vec<u8>, ControllerInitializationEntropyError> {
        read_csprng_exact(CONTROLLER_TEMP_TOKEN_BYTES)
    }
}

fn read_csprng_exact(length: usize) -> Result<Vec<u8>, ControllerInitializationEntropyError> {
    let owned = open(
        Path::new("/dev/urandom"),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        ControllerInitializationEntropyError::Io(io::Error::from_raw_os_error(error as i32).kind())
    })?;
    let mut source = File::from(owned);
    let mut bytes = vec![0; length];
    source
        .read_exact(&mut bytes)
        .map_err(|error| ControllerInitializationEntropyError::Io(error.kind()))?;
    Ok(bytes)
}

/// Auditable receipt for the exact Controller sequence-one snapshot.
///
/// The receipt binds the complete canonical snapshot by digest rather than
/// duplicating its owner-specific payload fields into a second format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerInitializationReceipt {
    store_instance_id: [u8; 32],
    owner_identity_fingerprint: ControllerOwnerIdentityFingerprint,
    snapshot_sequence: u64,
    initialized_snapshot_digest: Digest32,
    canonical_bytes: Box<[u8]>,
    receipt_digest: Digest32,
}

impl ControllerInitializationReceipt {
    fn from_snapshot(
        snapshot: &ControllerJournalSnapshot,
        encoded_snapshot: &[u8],
    ) -> Result<Self, ControllerInitializationError> {
        if snapshot.snapshot_sequence() != 1 || encoded_snapshot.is_empty() {
            return Err(ControllerInitializationError::InvalidEncodedSnapshot);
        }
        let decoded = ControllerJournalSnapshot::decode(encoded_snapshot)?;
        let canonical = snapshot.encode()?;
        if &decoded != snapshot || canonical.as_ref() != encoded_snapshot {
            return Err(ControllerInitializationError::InvalidEncodedSnapshot);
        }
        let mut snapshot_digest = Digest32Builder::try_new(INITIALIZED_SNAPSHOT_DIGEST_DOMAIN)?;
        snapshot_digest.field_bytes(encoded_snapshot)?;
        let initialized_snapshot_digest = snapshot_digest.finish();

        let mut canonical = Vec::new();
        canonical.extend_from_slice(INITIALIZATION_RECEIPT_MAGIC);
        canonical.extend_from_slice(&INITIALIZATION_RECEIPT_VERSION.to_be_bytes());
        canonical.extend_from_slice(snapshot.store_instance_id());
        canonical.extend_from_slice(snapshot.owner_identity_fingerprint().value().as_bytes());
        canonical.extend_from_slice(&snapshot.snapshot_sequence().to_be_bytes());
        canonical.extend_from_slice(initialized_snapshot_digest.as_bytes());

        let mut receipt_digest = Digest32Builder::try_new(INITIALIZATION_RECEIPT_DIGEST_DOMAIN)?;
        receipt_digest.field_bytes(&canonical)?;
        let receipt_digest = receipt_digest.finish();
        Ok(Self {
            store_instance_id: *snapshot.store_instance_id(),
            owner_identity_fingerprint: snapshot.owner_identity_fingerprint(),
            snapshot_sequence: snapshot.snapshot_sequence(),
            initialized_snapshot_digest,
            canonical_bytes: canonical.into_boxed_slice(),
            receipt_digest,
        })
    }

    #[must_use]
    pub(crate) const fn store_instance_id(&self) -> &[u8; 32] {
        &self.store_instance_id
    }

    #[must_use]
    pub(crate) const fn owner_identity_fingerprint(&self) -> ControllerOwnerIdentityFingerprint {
        self.owner_identity_fingerprint
    }

    #[must_use]
    pub(crate) const fn snapshot_sequence(&self) -> u64 {
        self.snapshot_sequence
    }

    #[must_use]
    pub(crate) const fn initialized_snapshot_digest(&self) -> Digest32 {
        self.initialized_snapshot_digest
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub(crate) const fn receipt_digest(&self) -> Digest32 {
        self.receipt_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerInitializationEntropyError {
    Io(io::ErrorKind),
    Unavailable,
}

impl fmt::Display for ControllerInitializationEntropyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Controller initialization CSPRNG failed: {self:?}"
        )
    }
}

impl std::error::Error for ControllerInitializationEntropyError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerInitializationError {
    Entropy(ControllerInitializationEntropyError),
    InvalidStoreIdentityWidth,
    AllZeroStoreIdentity,
    InvalidTempTokenWidth,
    AllZeroTempToken,
    InvalidEncodedSnapshot,
    Journal(ControllerJournalError),
    /// No initializer marker was created by this attempt.
    Store(ControllerStoreOpenError),
    /// The one-shot marker exists or may exist; callers must recover, not retry.
    MarkerConsumed(ControllerInitializationAfterMarkerFailure),
    /// A durable publish completed, but its readback could not be confirmed.
    PublishedButUnverified(ControllerPublishedVerificationFailure),
    Digest(DigestBuildError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerInitializationAfterMarkerFailure {
    Lock(ControllerStoreOpenError),
    Publish(ControllerPublishFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerPublishedVerificationFailure {
    ReadBack(ControllerStoreOpenError),
    Mismatch,
}

impl ControllerInitializationError {
    #[must_use]
    pub(crate) const fn requires_recovery(self) -> bool {
        matches!(
            self,
            Self::MarkerConsumed(_) | Self::PublishedButUnverified(_)
        )
    }
}

impl From<ControllerInitializationEntropyError> for ControllerInitializationError {
    fn from(error: ControllerInitializationEntropyError) -> Self {
        Self::Entropy(error)
    }
}

impl From<ControllerJournalError> for ControllerInitializationError {
    fn from(error: ControllerJournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<ControllerStoreOpenError> for ControllerInitializationError {
    fn from(error: ControllerStoreOpenError) -> Self {
        Self::Store(error)
    }
}

impl From<DigestBuildError> for ControllerInitializationError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

impl fmt::Display for ControllerInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller initialization failed: {self:?}")
    }
}

impl std::error::Error for ControllerInitializationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerReceiptRecoveryError {
    NotSequenceOne,
    InitializationBindingMismatch,
    Store(ControllerStoreOpenError),
    StoreState(ControllerStoreError),
    Journal(ControllerJournalError),
    Initialization(ControllerInitializationError),
}

impl From<ControllerStoreOpenError> for ControllerReceiptRecoveryError {
    fn from(error: ControllerStoreOpenError) -> Self {
        Self::Store(error)
    }
}

impl From<ControllerStoreError> for ControllerReceiptRecoveryError {
    fn from(error: ControllerStoreError) -> Self {
        Self::StoreState(error)
    }
}

impl From<ControllerJournalError> for ControllerReceiptRecoveryError {
    fn from(error: ControllerJournalError) -> Self {
        Self::Journal(error)
    }
}

impl fmt::Display for ControllerReceiptRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller receipt recovery failed: {self:?}")
    }
}

impl std::error::Error for ControllerReceiptRecoveryError {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

    use crate::controller_journal::{
        ControllerAuthKeyFingerprint, ControllerOperationId, ControllerOwnerIdentityFingerprint,
        ControllerRequestAuthPin, controller_test_manifest, controller_test_manifest_with_build,
    };
    use crate::controller_store::{
        CONTROLLER_ACTIVE_FILE_NAME, CONTROLLER_LOCK_FILE_NAME, ControllerCommitFailpoint,
        ControllerFileStage, ControllerFilesystemPolicy, ControllerIoFailure,
        ControllerPublishFailure, ControllerStore, ControllerStoreOpenError,
    };
    use crate::plan::{DeploymentId, DeploymentScopeId};
    use crate::planner::{StableAllocationSnapshot, journal_test_candidate};

    use super::{
        ControllerInitializationAfterMarkerFailure, ControllerInitializationEntropy,
        ControllerInitializationEntropyError, ControllerInitializationError,
        ControllerInitializationInput, ControllerInitializationReadBackFailpoint,
        ControllerPublishedVerificationFailure, ControllerReceiptRecoveryError,
        initialize_controller_store_with, initialize_controller_store_with_readback_failpoint,
        reconstruct_sequence_one_controller_receipt_with_policy,
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
                "paraegox-controller-init-{}-{sequence}",
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

    #[derive(Clone)]
    struct FixtureEntropy {
        store: Result<Vec<u8>, ControllerInitializationEntropyError>,
        temp: Result<Vec<u8>, ControllerInitializationEntropyError>,
    }

    impl ControllerInitializationEntropy for FixtureEntropy {
        fn store_instance_id(&mut self) -> Result<Vec<u8>, ControllerInitializationEntropyError> {
            self.store.clone()
        }

        fn temp_token(&mut self) -> Result<Vec<u8>, ControllerInitializationEntropyError> {
            self.temp.clone()
        }
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn owner() -> ControllerOwnerIdentityFingerprint {
        ControllerOwnerIdentityFingerprint::from_stored(digest(0x42))
    }

    fn auth(key: u8, generation: u64) -> ControllerRequestAuthPin {
        ControllerRequestAuthPin::try_new(
            ApplyAuthKeyRef::from_bytes([key; 16]),
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("fixture algorithm failed: {error}")),
            1,
            ControllerAuthKeyFingerprint::from_stored(digest(key.wrapping_add(1))),
            generation,
        )
        .unwrap_or_else(|error| panic!("fixture auth failed: {error}"))
    }

    fn input() -> ControllerInitializationInput {
        input_with_owner(owner())
    }

    fn input_with_owner(
        owner_identity_fingerprint: ControllerOwnerIdentityFingerprint,
    ) -> ControllerInitializationInput {
        input_with_owner_and_build(owner_identity_fingerprint, 0x11)
    }

    fn input_with_owner_and_build(
        owner_identity_fingerprint: ControllerOwnerIdentityFingerprint,
        build_marker: u8,
    ) -> ControllerInitializationInput {
        let target = RuntimeHostId::from_bytes([0x23; 16]);
        ControllerInitializationInput::try_new(
            DeploymentScopeId::from_bytes([0x21; 16]),
            DeploymentId::from_bytes([0x22; 16]),
            StableAllocationSnapshot::try_new(target, 0, 0, Vec::new())
                .unwrap_or_else(|error| panic!("fixture allocation failed: {error}")),
            controller_test_manifest_with_build(target, build_marker),
            auth(0x24, 1),
            owner_identity_fingerprint,
        )
        .unwrap_or_else(|error| panic!("fixture input failed: {error}"))
    }

    fn successful_entropy() -> FixtureEntropy {
        FixtureEntropy {
            store: Ok(vec![0x31; 32]),
            temp: Ok(vec![0x32; 16]),
        }
    }

    fn initialize_fixture(
        directory: &TestDirectory,
        entropy: &mut FixtureEntropy,
        failpoint: ControllerCommitFailpoint,
    ) -> Result<super::ControllerInitializationReceipt, ControllerInitializationError> {
        initialize_controller_store_with(
            directory.path(),
            input(),
            entropy,
            ControllerFilesystemPolicy::ExplicitFixture,
            failpoint,
        )
    }

    fn initialize_fixture_with_readback_failpoint(
        directory: &TestDirectory,
        entropy: &mut FixtureEntropy,
        readback_failpoint: ControllerInitializationReadBackFailpoint,
    ) -> Result<super::ControllerInitializationReceipt, ControllerInitializationError> {
        initialize_controller_store_with_readback_failpoint(
            directory.path(),
            input(),
            entropy,
            ControllerFilesystemPolicy::ExplicitFixture,
            ControllerCommitFailpoint::None,
            readback_failpoint,
        )
    }

    #[test]
    fn initialization_persists_sequence_one_and_reconstructs_identical_receipt() {
        let directory = TestDirectory::new();
        let receipt = initialize_fixture(
            &directory,
            &mut successful_entropy(),
            ControllerCommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("initialization failed: {error}"));
        assert_eq!(receipt.store_instance_id(), &[0x31; 32]);
        assert_eq!(receipt.owner_identity_fingerprint(), owner());
        assert_eq!(receipt.snapshot_sequence(), 1);
        assert_ne!(receipt.initialized_snapshot_digest().as_bytes(), &[0; 32]);
        assert_ne!(receipt.receipt_digest().as_bytes(), &[0; 32]);
        assert!(!receipt.canonical_bytes().is_empty());
        assert!(directory.path().join(CONTROLLER_LOCK_FILE_NAME).is_file());
        assert!(directory.path().join(CONTROLLER_ACTIVE_FILE_NAME).is_file());

        let reconstructed = reconstruct_sequence_one_controller_receipt_with_policy(
            directory.path(),
            input(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("receipt reconstruction failed: {error}"));
        assert_eq!(reconstructed, receipt);

        let store = ControllerStore::open_with_policy(
            directory.path(),
            *receipt.store_instance_id(),
            owner(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("initialized store reopen failed: {error}"));
        assert_eq!(
            store
                .snapshot()
                .unwrap_or_else(|error| panic!("initialized snapshot unavailable: {error}"))
                .state()
                .installed_manifest(),
            &controller_test_manifest(RuntimeHostId::from_bytes([0x23; 16]))
        );
    }

    #[test]
    fn entropy_failure_short_fill_and_zero_values_leave_directory_unmodified() {
        let cases = [
            FixtureEntropy {
                store: Err(ControllerInitializationEntropyError::Unavailable),
                temp: Ok(vec![1; 16]),
            },
            FixtureEntropy {
                store: Ok(vec![1; 31]),
                temp: Ok(vec![1; 16]),
            },
            FixtureEntropy {
                store: Ok(vec![0; 32]),
                temp: Ok(vec![1; 16]),
            },
            FixtureEntropy {
                store: Ok(vec![1; 32]),
                temp: Err(ControllerInitializationEntropyError::Unavailable),
            },
            FixtureEntropy {
                store: Ok(vec![1; 32]),
                temp: Ok(vec![1; 15]),
            },
            FixtureEntropy {
                store: Ok(vec![1; 32]),
                temp: Ok(vec![0; 16]),
            },
        ];
        for mut entropy in cases {
            let directory = TestDirectory::new();
            assert!(
                initialize_fixture(&directory, &mut entropy, ControllerCommitFailpoint::None)
                    .is_err()
            );
            assert_eq!(
                fs::read_dir(directory.path())
                    .unwrap_or_else(|error| panic!("fixture directory scan failed: {error}"))
                    .count(),
                0
            );
        }
    }

    #[test]
    fn zero_owner_identity_is_rejected_while_building_the_typed_input() {
        assert!(matches!(
            ControllerInitializationInput::try_new(
                DeploymentScopeId::from_bytes([0x21; 16]),
                DeploymentId::from_bytes([0x22; 16]),
                StableAllocationSnapshot::try_new(
                    RuntimeHostId::from_bytes([0x23; 16]),
                    0,
                    0,
                    Vec::new(),
                )
                .unwrap_or_else(|error| panic!("fixture allocation failed: {error}")),
                controller_test_manifest(RuntimeHostId::from_bytes([0x23; 16])),
                auth(0x24, 1),
                ControllerOwnerIdentityFingerprint::from_stored(digest(0)),
            ),
            Err(ControllerInitializationError::Journal(
                crate::controller_journal::ControllerJournalError::ZeroOwnerIdentityFingerprint
            ))
        ));
    }

    #[test]
    fn initializer_is_one_shot_and_never_resets_existing_state() {
        let directory = TestDirectory::new();
        initialize_fixture(
            &directory,
            &mut successful_entropy(),
            ControllerCommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("first initialization failed: {error}"));
        let before = fs::read(directory.path().join(CONTROLLER_ACTIVE_FILE_NAME))
            .unwrap_or_else(|error| panic!("fixture active read failed: {error}"));
        let error = initialize_fixture(
            &directory,
            &mut FixtureEntropy {
                store: Ok(vec![0x55; 32]),
                temp: Ok(vec![0x56; 16]),
            },
            ControllerCommitFailpoint::None,
        )
        .expect_err("second initialization must require recovery");
        assert_eq!(
            error,
            ControllerInitializationError::MarkerConsumed(
                ControllerInitializationAfterMarkerFailure::Lock(
                    ControllerStoreOpenError::InitializerMarkerAlreadyPresent
                )
            )
        );
        assert!(error.requires_recovery());
        assert_eq!(
            fs::read(directory.path().join(CONTROLLER_ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("fixture active read failed: {error}")),
            before
        );
    }

    #[test]
    fn rejected_publish_does_not_create_an_active_snapshot_or_allow_reset() {
        let directory = TestDirectory::new();
        let error = initialize_fixture(
            &directory,
            &mut successful_entropy(),
            ControllerCommitFailpoint::BeforeFileSync,
        )
        .expect_err("pre-publish failure must consume the initializer marker");
        assert!(matches!(
            error,
            ControllerInitializationError::MarkerConsumed(
                ControllerInitializationAfterMarkerFailure::Publish(
                    ControllerPublishFailure::RejectedBeforePublish(_)
                )
            )
        ));
        assert!(error.requires_recovery());
        assert!(!directory.path().join(CONTROLLER_ACTIVE_FILE_NAME).exists());
        assert!(directory.path().join(CONTROLLER_LOCK_FILE_NAME).exists());
        assert!(
            initialize_fixture(
                &directory,
                &mut successful_entropy(),
                ControllerCommitFailpoint::None,
            )
            .is_err()
        );
    }

    #[test]
    fn uncertain_publish_is_nested_under_consumed_marker_and_reconstructs() {
        let directory = TestDirectory::new();
        let error = initialize_fixture(
            &directory,
            &mut successful_entropy(),
            ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn,
        )
        .expect_err("post-publish failpoint must remain uncertain");
        assert!(matches!(
            error,
            ControllerInitializationError::MarkerConsumed(
                ControllerInitializationAfterMarkerFailure::Publish(
                    ControllerPublishFailure::UncertainAfterPublish(_)
                )
            )
        ));
        assert!(error.requires_recovery());
        let reconstructed = reconstruct_sequence_one_controller_receipt_with_policy(
            directory.path(),
            input(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|recovery_error| {
            panic!("uncertain publish receipt recovery failed: {recovery_error}")
        });
        assert_eq!(reconstructed.store_instance_id(), &[0x31; 32]);
        assert_eq!(reconstructed.snapshot_sequence(), 1);
    }

    #[test]
    fn durable_publish_readback_failures_are_explicit_and_reconstruct_exact_receipt() {
        let reference_directory = TestDirectory::new();
        let expected = initialize_fixture(
            &reference_directory,
            &mut successful_entropy(),
            ControllerCommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("reference initialization failed: {error}"));

        for (failpoint, expected_failure) in [
            (
                ControllerInitializationReadBackFailpoint::Error(ControllerStoreOpenError::Io(
                    ControllerIoFailure {
                        stage: ControllerFileStage::OpenActive,
                        kind: std::io::ErrorKind::NotFound,
                    },
                )),
                ControllerPublishedVerificationFailure::ReadBack(ControllerStoreOpenError::Io(
                    ControllerIoFailure {
                        stage: ControllerFileStage::OpenActive,
                        kind: std::io::ErrorKind::NotFound,
                    },
                )),
            ),
            (
                ControllerInitializationReadBackFailpoint::Error(ControllerStoreOpenError::Codec(
                    crate::controller_journal::ControllerJournalError::InvalidMagic,
                )),
                ControllerPublishedVerificationFailure::ReadBack(ControllerStoreOpenError::Codec(
                    crate::controller_journal::ControllerJournalError::InvalidMagic,
                )),
            ),
            (
                ControllerInitializationReadBackFailpoint::Mismatch,
                ControllerPublishedVerificationFailure::Mismatch,
            ),
        ] {
            let directory = TestDirectory::new();
            let error = initialize_fixture_with_readback_failpoint(
                &directory,
                &mut successful_entropy(),
                failpoint,
            )
            .expect_err("injected readback failure must not report initialization success");
            assert_eq!(
                error,
                ControllerInitializationError::PublishedButUnverified(expected_failure)
            );
            assert!(error.requires_recovery());
            let reconstructed = reconstruct_sequence_one_controller_receipt_with_policy(
                directory.path(),
                input(),
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .unwrap_or_else(|recovery_error| {
                panic!("published receipt reconstruction failed: {recovery_error}")
            });
            assert_eq!(reconstructed, expected);
        }
    }

    #[test]
    fn receipt_reconstruction_rejects_wrong_binding_and_non_sequence_one() {
        let directory = TestDirectory::new();
        let receipt = initialize_fixture(
            &directory,
            &mut successful_entropy(),
            ControllerCommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("initialization failed: {error}"));

        assert!(matches!(
            reconstruct_sequence_one_controller_receipt_with_policy(
                directory.path(),
                input_with_owner(ControllerOwnerIdentityFingerprint::from_stored(digest(
                    0x99
                ))),
                ControllerFilesystemPolicy::ExplicitFixture,
            ),
            Err(ControllerReceiptRecoveryError::Store(_))
        ));
        assert_eq!(
            reconstruct_sequence_one_controller_receipt_with_policy(
                directory.path(),
                input_with_owner_and_build(owner(), 0x12),
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("same owner with a different installed manifest pin must fail"),
            ControllerReceiptRecoveryError::InitializationBindingMismatch
        );

        let wrong_lineage = ControllerInitializationInput::try_new(
            DeploymentScopeId::from_bytes([0x21; 16]),
            DeploymentId::from_bytes([0x91; 16]),
            StableAllocationSnapshot::try_new(
                RuntimeHostId::from_bytes([0x23; 16]),
                0,
                0,
                Vec::new(),
            )
            .unwrap_or_else(|error| panic!("fixture allocation failed: {error}")),
            controller_test_manifest(RuntimeHostId::from_bytes([0x23; 16])),
            auth(0x24, 1),
            owner(),
        )
        .unwrap_or_else(|error| panic!("wrong-lineage input failed: {error}"));
        assert_eq!(
            reconstruct_sequence_one_controller_receipt_with_policy(
                directory.path(),
                wrong_lineage,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("same owner with wrong initialization state must fail"),
            ControllerReceiptRecoveryError::InitializationBindingMismatch
        );

        let mut store = ControllerStore::open_with_policy(
            directory.path(),
            *receipt.store_instance_id(),
            owner(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("fixture store open failed: {error}"));
        let allocation = StableAllocationSnapshot::try_new(
            RuntimeHostId::from_bytes([0x23; 16]),
            0,
            0,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("fixture allocation failed: {error}"));
        let candidate = journal_test_candidate(
            RuntimeHostId::from_bytes([0x23; 16]),
            store
                .snapshot()
                .unwrap_or_else(|error| panic!("fixture snapshot unavailable: {error}"))
                .state()
                .installed_manifest()
                .projection(),
            &allocation,
            Some([0x25; 16]),
            0x26,
        )
        .unwrap_or_else(|error| panic!("fixture candidate failed: {error}"));
        let next_state = store
            .snapshot()
            .unwrap_or_else(|error| panic!("fixture snapshot unavailable: {error}"))
            .state()
            .prepare_plan_candidate(ControllerOperationId::from_bytes([0x27; 16]), &candidate)
            .unwrap_or_else(|error| panic!("fixture prepare failed: {error}"));
        let next = store
            .snapshot()
            .unwrap_or_else(|error| panic!("fixture snapshot unavailable: {error}"))
            .try_successor(next_state)
            .unwrap_or_else(|error| panic!("fixture successor failed: {error}"));
        store
            .commit(next)
            .unwrap_or_else(|error| panic!("fixture commit failed: {error}"));
        drop(store);

        assert_eq!(
            reconstruct_sequence_one_controller_receipt_with_policy(
                directory.path(),
                input(),
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("non-sequence-one receipt must fail"),
            ControllerReceiptRecoveryError::NotSequenceOne
        );
    }
}
