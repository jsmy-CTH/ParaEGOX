use core::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};

use super::codec::{
    CodecError, ENVELOPE_HEADER_BYTES, ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES, encode_snapshot,
};
use super::model::{AuthorityProvisioning, AuthoritySnapshot, ModelError, StoreInstanceId};
use super::store::{
    CommitFailpoint, FilesystemPolicy, PublishFailure, StoreOpenError,
    create_and_lock_initializer_lock, ensure_fresh_directory, open_directory,
    publish_initial_snapshot, read_active_snapshot,
};

const STORE_INSTANCE_ID_BYTES: usize = 32;
const TEMP_TOKEN_BYTES: usize = 16;
const INITIALIZATION_RECEIPT_MAGIC: &[u8] = b"PXTAINIT\0";
const INITIALIZATION_RECEIPT_VERSION: u16 = 1;
const INITIALIZATION_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.deployment.tenure-authority.initialization-receipt.sha256.v1";

pub(super) fn initialize(
    directory: &Path,
    provisioning: AuthorityProvisioning,
) -> Result<InitializationReceipt, InitializationError> {
    let mut entropy = SystemInitializationEntropy;
    initialize_with(
        directory,
        provisioning,
        &mut entropy,
        FilesystemPolicy::ProductionReference,
        CommitFailpoint::None,
    )
}

/// Initializes the explicitly selected same-user developer store with the
/// same CSPRNG, lock, codec, checksum, atomic publish, and read-back path as
/// production. Only the target-filesystem evidence gate differs.
pub(super) fn initialize_developer_local(
    directory: &Path,
    provisioning: AuthorityProvisioning,
) -> Result<InitializationReceipt, InitializationError> {
    let mut entropy = SystemInitializationEntropy;
    initialize_with(
        directory,
        provisioning,
        &mut entropy,
        FilesystemPolicy::DeveloperLocal,
        CommitFailpoint::None,
    )
}

fn initialize_with(
    directory: &Path,
    provisioning: AuthorityProvisioning,
    entropy: &mut impl InitializationEntropy,
    filesystem_policy: FilesystemPolicy,
    failpoint: CommitFailpoint,
) -> Result<InitializationReceipt, InitializationError> {
    provisioning.validate()?;
    let directory = open_directory(directory, filesystem_policy)?;
    ensure_fresh_directory(&directory)?;

    // Both random values are validated before lock/temp/snapshot mutation. The
    // store identity is generated here and is never accepted from a caller.
    let store_bytes = entropy.store_instance_id()?;
    if store_bytes.len() != STORE_INSTANCE_ID_BYTES {
        return Err(InitializationError::InvalidStoreIdentityWidth);
    }
    let store_instance_id = StoreInstanceId::try_from_bytes(
        store_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InitializationError::InvalidStoreIdentityWidth)?,
    )?;
    let temp_bytes = entropy.temp_token()?;
    if temp_bytes.len() != TEMP_TOKEN_BYTES {
        return Err(InitializationError::InvalidTempTokenWidth);
    }
    let temp_token: [u8; TEMP_TOKEN_BYTES] = temp_bytes
        .as_slice()
        .try_into()
        .map_err(|_| InitializationError::InvalidTempTokenWidth)?;
    if temp_token.iter().all(|byte| *byte == 0) {
        return Err(InitializationError::AllZeroTempToken);
    }

    let snapshot = AuthoritySnapshot::initial(store_instance_id, provisioning)?;
    let encoded = encode_snapshot(&snapshot)?;
    let receipt = InitializationReceipt::from_snapshot(&snapshot, &encoded)?;

    let _lock = create_and_lock_initializer_lock(&directory)?;
    publish_initial_snapshot(&directory, &encoded, temp_token, failpoint)?;
    let read_back = read_active_snapshot(&directory)?;
    if read_back != snapshot {
        return Err(InitializationError::ReadBackMismatch);
    }
    Ok(receipt)
}

#[cfg(test)]
pub(super) fn initialize_fixture(
    directory: &Path,
    provisioning: AuthorityProvisioning,
    store_instance_id: Vec<u8>,
    temp_token: Vec<u8>,
    failpoint: CommitFailpoint,
) -> Result<InitializationReceipt, InitializationError> {
    struct ExplicitFixtureEntropy {
        store_instance_id: Vec<u8>,
        temp_token: Vec<u8>,
    }

    impl InitializationEntropy for ExplicitFixtureEntropy {
        fn store_instance_id(&mut self) -> Result<Vec<u8>, InitializationEntropyError> {
            Ok(self.store_instance_id.clone())
        }

        fn temp_token(&mut self) -> Result<Vec<u8>, InitializationEntropyError> {
            Ok(self.temp_token.clone())
        }
    }

    initialize_with(
        directory,
        provisioning,
        &mut ExplicitFixtureEntropy {
            store_instance_id,
            temp_token,
        },
        FilesystemPolicy::ExplicitFixture,
        failpoint,
    )
}

trait InitializationEntropy {
    fn store_instance_id(&mut self) -> Result<Vec<u8>, InitializationEntropyError>;

    fn temp_token(&mut self) -> Result<Vec<u8>, InitializationEntropyError>;
}

struct SystemInitializationEntropy;

impl InitializationEntropy for SystemInitializationEntropy {
    fn store_instance_id(&mut self) -> Result<Vec<u8>, InitializationEntropyError> {
        read_csprng_exact(STORE_INSTANCE_ID_BYTES)
    }

    fn temp_token(&mut self) -> Result<Vec<u8>, InitializationEntropyError> {
        read_csprng_exact(TEMP_TOKEN_BYTES)
    }
}

fn read_csprng_exact(length: usize) -> Result<Vec<u8>, InitializationEntropyError> {
    let owned = open(
        Path::new("/dev/urandom"),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        InitializationEntropyError::Io(io::Error::from_raw_os_error(error as i32).kind())
    })?;
    let mut source = File::from(owned);
    let mut bytes = vec![0; length];
    source
        .read_exact(&mut bytes)
        .map_err(|error| InitializationEntropyError::Io(error.kind()))?;
    Ok(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InitializationReceipt {
    store_instance_id: StoreInstanceId,
    owner_identity_fingerprint: Digest32,
    source_scope: crate::plan::DeploymentScopeId,
    authority: paraegox_runtime_contracts::apply::TenureAuthorityRef,
    key: paraegox_runtime_contracts::apply::TenureKeyRef,
    signing_key_fingerprint: Digest32,
    policy_fingerprint: Digest32,
    service_principal_fingerprint: Digest32,
    snapshot_sequence: u64,
    epoch_high_water: u64,
    snapshot_checksum: Digest32,
    canonical_bytes: Box<[u8]>,
    receipt_digest: Digest32,
}

impl InitializationReceipt {
    pub(super) fn from_snapshot(
        snapshot: &AuthoritySnapshot,
        encoded_snapshot: &[u8],
    ) -> Result<Self, InitializationError> {
        if encoded_snapshot.len() < ENVELOPE_HEADER_BYTES {
            return Err(InitializationError::InvalidEncodedSnapshot);
        }
        let snapshot_checksum = Digest32::from_bytes(
            encoded_snapshot[ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES..ENVELOPE_HEADER_BYTES]
                .try_into()
                .map_err(|_| InitializationError::InvalidEncodedSnapshot)?,
        );
        let provisioning = snapshot.provisioning;
        let mut canonical = Vec::new();
        canonical.extend_from_slice(INITIALIZATION_RECEIPT_MAGIC);
        canonical.extend_from_slice(&INITIALIZATION_RECEIPT_VERSION.to_be_bytes());
        canonical.extend_from_slice(snapshot.store_instance_id.as_bytes());
        canonical.extend_from_slice(snapshot.owner_identity_fingerprint.as_bytes());
        canonical.extend_from_slice(provisioning.source_scope.as_bytes());
        canonical.extend_from_slice(provisioning.authorized_writer.as_bytes());
        canonical.extend_from_slice(provisioning.proof_authority.authority().as_bytes());
        canonical.extend_from_slice(provisioning.proof_authority.key().as_bytes());
        canonical.extend_from_slice(provisioning.authorization.controller_principal.as_bytes());
        canonical.extend_from_slice(provisioning.authorization.controller_key.as_bytes());
        canonical.extend_from_slice(&provisioning.authorization.controller_verification_key);
        canonical.extend_from_slice(&provisioning.authorization.controller_public_key_fingerprint);
        canonical.extend_from_slice(provisioning.fingerprints.signing_key.as_bytes());
        canonical.extend_from_slice(provisioning.fingerprints.policy.as_bytes());
        canonical.extend_from_slice(provisioning.fingerprints.service_principal.as_bytes());
        canonical.extend_from_slice(&snapshot.snapshot_sequence.to_be_bytes());
        canonical.extend_from_slice(&snapshot.epoch_high_water.to_be_bytes());
        canonical.extend_from_slice(snapshot_checksum.as_bytes());
        let mut digest = Digest32Builder::try_new(INITIALIZATION_RECEIPT_DIGEST_DOMAIN)?;
        digest.field_bytes(&canonical)?;
        let receipt_digest = digest.finish();
        Ok(Self {
            store_instance_id: snapshot.store_instance_id,
            owner_identity_fingerprint: snapshot.owner_identity_fingerprint,
            source_scope: provisioning.source_scope,
            authority: provisioning.proof_authority.authority(),
            key: provisioning.proof_authority.key(),
            signing_key_fingerprint: provisioning.fingerprints.signing_key,
            policy_fingerprint: provisioning.fingerprints.policy,
            service_principal_fingerprint: provisioning.fingerprints.service_principal,
            snapshot_sequence: snapshot.snapshot_sequence,
            epoch_high_water: snapshot.epoch_high_water,
            snapshot_checksum,
            canonical_bytes: canonical.into_boxed_slice(),
            receipt_digest,
        })
    }

    pub(super) const fn store_instance_id(&self) -> StoreInstanceId {
        self.store_instance_id
    }

    pub(super) const fn store_instance_id_bytes(&self) -> &[u8; 32] {
        self.store_instance_id.as_bytes()
    }

    pub(super) const fn snapshot_sequence(&self) -> u64 {
        self.snapshot_sequence
    }

    pub(super) const fn epoch_high_water(&self) -> u64 {
        self.epoch_high_water
    }

    pub(super) const fn snapshot_checksum(&self) -> Digest32 {
        self.snapshot_checksum
    }

    pub(super) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(super) const fn receipt_digest(&self) -> Digest32 {
        self.receipt_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InitializationEntropyError {
    Io(io::ErrorKind),
    Unavailable,
}

impl fmt::Display for InitializationEntropyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "initialization CSPRNG failed: {self:?}")
    }
}

impl std::error::Error for InitializationEntropyError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InitializationError {
    Entropy(InitializationEntropyError),
    InvalidStoreIdentityWidth,
    InvalidTempTokenWidth,
    AllZeroTempToken,
    InvalidEncodedSnapshot,
    ReadBackMismatch,
    Model(ModelError),
    Codec(CodecError),
    Store(StoreOpenError),
    Publish(PublishFailure),
    Digest(DigestBuildError),
}

impl From<InitializationEntropyError> for InitializationError {
    fn from(error: InitializationEntropyError) -> Self {
        Self::Entropy(error)
    }
}

impl From<ModelError> for InitializationError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<CodecError> for InitializationError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<StoreOpenError> for InitializationError {
    fn from(error: StoreOpenError) -> Self {
        Self::Store(error)
    }
}

impl From<PublishFailure> for InitializationError {
    fn from(error: PublishFailure) -> Self {
        Self::Publish(error)
    }
}

impl From<DigestBuildError> for InitializationError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

impl fmt::Display for InitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "tenure-authority initialization failed: {self:?}"
        )
    }
}

impl std::error::Error for InitializationError {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use paraegox_kernel::digest::Digest32;
    use paraegox_runtime_contracts::apply::{
        TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm, TenureProofAuthority,
    };

    use crate::plan::DeploymentScopeId;

    use super::{
        InitializationEntropy, InitializationEntropyError, InitializationError, initialize_with,
    };
    use crate::tenure_authority::model::{
        AcquireAuthorization, AuthorityFingerprints, AuthorityProvisioning,
        signing_key_fingerprint_for,
    };
    use crate::tenure_authority::store::{
        ACTIVE_FILE_NAME, CommitFailpoint, FilesystemPolicy, LOCK_FILE_NAME, PublishFailure,
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
                "paraegox-authority-init-{}-{sequence}",
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

    struct FixtureEntropy {
        store: Result<Vec<u8>, InitializationEntropyError>,
        temp: Result<Vec<u8>, InitializationEntropyError>,
    }

    impl InitializationEntropy for FixtureEntropy {
        fn store_instance_id(&mut self) -> Result<Vec<u8>, InitializationEntropyError> {
            self.store.clone()
        }

        fn temp_token(&mut self) -> Result<Vec<u8>, InitializationEntropyError> {
            self.temp.clone()
        }
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn provisioning() -> AuthorityProvisioning {
        let key = SigningKey::from_bytes(&[1; 32]);
        let verification_key = key.verifying_key().to_bytes();
        let proof_authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([2; 16]),
            TenureKeyRef::from_bytes([3; 16]),
            TenureProofAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("fixture algorithm failed: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("fixture authority failed: {error}"));
        let controller_key = SigningKey::from_bytes(&[0x34; 32]);
        let controller_verification_key = controller_key.verifying_key().to_bytes();
        let controller_public_key_fingerprint =
            crate::tenure_protocol::ControllerPublicKeyFingerprint::for_ed25519_key(
                &controller_verification_key,
            )
            .unwrap_or_else(|error| panic!("fixture controller fingerprint failed: {error}"));
        AuthorityProvisioning::try_new(
            DeploymentScopeId::from_bytes([4; 16]),
            crate::plan::DeploymentWriterRef::from_bytes([8; 16]),
            proof_authority,
            verification_key,
            AcquireAuthorization {
                controller_principal: paraegox_kernel::identity::PrincipalRef::from_bytes(
                    [0x31; 16],
                ),
                controller_key: crate::tenure_protocol::ControllerAcquireKeyRef::from_bytes(
                    [0x32; 16],
                ),
                controller_verification_key,
                controller_public_key_fingerprint: *controller_public_key_fingerprint.as_bytes(),
            },
            AuthorityFingerprints {
                signing_key: signing_key_fingerprint_for(&verification_key)
                    .unwrap_or_else(|error| panic!("fixture fingerprint failed: {error}")),
                policy: digest(5),
                service_principal: digest(6),
                owner_identity: digest(7),
            },
        )
        .unwrap_or_else(|error| panic!("fixture provisioning failed: {error}"))
    }

    fn successful_entropy() -> FixtureEntropy {
        FixtureEntropy {
            store: Ok(vec![8; 32]),
            temp: Ok(vec![9; 16]),
        }
    }

    #[test]
    fn successful_initialization_persists_explicit_sequence_one_and_auditable_receipt() {
        let directory = TestDirectory::new();
        let receipt = initialize_with(
            directory.path(),
            provisioning(),
            &mut successful_entropy(),
            FilesystemPolicy::ExplicitFixture,
            CommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("initialization failed: {error}"));

        assert_eq!(receipt.store_instance_id().as_bytes(), &[8; 32]);
        assert_eq!(receipt.snapshot_sequence(), 1);
        assert_eq!(receipt.epoch_high_water(), 0);
        assert!(!receipt.canonical_bytes().is_empty());
        assert_ne!(receipt.snapshot_checksum().as_bytes(), &[0; 32]);
        assert_ne!(receipt.receipt_digest().as_bytes(), &[0; 32]);
        assert!(directory.path().join(LOCK_FILE_NAME).is_file());
        assert!(directory.path().join(ACTIVE_FILE_NAME).is_file());
    }

    #[test]
    fn rng_error_short_fill_and_all_zero_store_id_leave_directory_unmodified() {
        let cases = [
            FixtureEntropy {
                store: Err(InitializationEntropyError::Unavailable),
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
                temp: Ok(vec![1; 15]),
            },
        ];
        for mut entropy in cases {
            let directory = TestDirectory::new();
            assert!(
                initialize_with(
                    directory.path(),
                    provisioning(),
                    &mut entropy,
                    FilesystemPolicy::ExplicitFixture,
                    CommitFailpoint::None,
                )
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
    fn existing_active_or_failed_initialization_cannot_be_reset_by_rerunning_initializer() {
        let directory = TestDirectory::new();
        let first = initialize_with(
            directory.path(),
            provisioning(),
            &mut successful_entropy(),
            FilesystemPolicy::ExplicitFixture,
            CommitFailpoint::None,
        );
        assert!(first.is_ok());
        assert!(
            initialize_with(
                directory.path(),
                provisioning(),
                &mut successful_entropy(),
                FilesystemPolicy::ExplicitFixture,
                CommitFailpoint::None,
            )
            .is_err()
        );

        let failed = TestDirectory::new();
        let result = initialize_with(
            failed.path(),
            provisioning(),
            &mut successful_entropy(),
            FilesystemPolicy::ExplicitFixture,
            CommitFailpoint::AfterPartialWrite,
        );
        assert!(matches!(
            result,
            Err(InitializationError::Publish(
                PublishFailure::RejectedBeforePublish(_)
            ))
        ));
        assert!(failed.path().join(LOCK_FILE_NAME).exists());
        assert!(
            initialize_with(
                failed.path(),
                provisioning(),
                &mut successful_entropy(),
                FilesystemPolicy::ExplicitFixture,
                CommitFailpoint::None,
            )
            .is_err()
        );
    }

    #[test]
    fn publish_uncertainty_reports_new_active_without_returning_success_receipt() {
        let directory = TestDirectory::new();
        let result = initialize_with(
            directory.path(),
            provisioning(),
            &mut successful_entropy(),
            FilesystemPolicy::ExplicitFixture,
            CommitFailpoint::AfterRename,
        );
        assert!(matches!(
            result,
            Err(InitializationError::Publish(
                PublishFailure::UncertainAfterPublish(_)
            ))
        ));
        assert!(directory.path().join(ACTIVE_FILE_NAME).is_file());
    }

    #[test]
    fn subprocess_initializer_crashes_preserve_fresh_store_publication_boundary() {
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
            let directory = TestDirectory::new();
            let status = Command::new(
                std::env::current_exe()
                    .unwrap_or_else(|error| panic!("test executable lookup failed: {error}")),
            )
            .args([
                "--exact",
                "tenure_authority::initializer::tests::subprocess_initializer_crash_child",
                "--nocapture",
            ])
            .env(
                "PARAEGOX_TEST_AUTHORITY_INITIALIZER_CRASH_STORE",
                directory.path(),
            )
            .env("PARAEGOX_TEST_AUTHORITY_INITIALIZER_CRASH_POINT", point)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|error| panic!("initializer crash child spawn failed: {error}"));
            assert!(
                !status.success(),
                "initializer crash child unexpectedly returned at {point}"
            );

            let active_path = directory.path().join(ACTIVE_FILE_NAME);
            assert_eq!(active_path.exists(), published, "crash point {point}");
            let before_retry = published.then(|| {
                fs::read(&active_path)
                    .unwrap_or_else(|error| panic!("published snapshot read failed: {error}"))
            });
            let recovered = crate::tenure_authority::reconstruct_sequence_one_initialization_receipt_with_policy(
                directory.path(),
                crate::tenure_authority::TenureAuthorityProvisioning(provisioning()),
                FilesystemPolicy::ExplicitFixture,
            );
            if published {
                let receipt = recovered.unwrap_or_else(|error| {
                    panic!("sequence-one receipt recovery failed at {point}: {error}")
                });
                assert_eq!(receipt.store_instance_id(), &[8; 32]);
                assert_eq!(receipt.snapshot_sequence(), 1);
                assert_eq!(receipt.epoch_high_water(), 0);
                assert!(!receipt.canonical_bytes().is_empty());
            } else {
                assert!(
                    recovered.is_err(),
                    "pre-rename crash reconstructed a nonexistent receipt at {point}"
                );
            }

            let retry = initialize_with(
                directory.path(),
                provisioning(),
                &mut successful_entropy(),
                FilesystemPolicy::ExplicitFixture,
                CommitFailpoint::None,
            );
            assert!(retry.is_err(), "initializer reset crash residue at {point}");
            if let Some(expected) = before_retry {
                assert_eq!(
                    fs::read(&active_path).unwrap_or_else(|error| {
                        panic!("published snapshot reread failed at {point}: {error}")
                    }),
                    expected,
                    "initializer retry rewrote published sequence-one state at {point}"
                );
            } else {
                assert!(
                    !active_path.exists(),
                    "initializer retry published after pre-rename crash at {point}"
                );
            }
        }
    }

    #[test]
    fn subprocess_initializer_crash_child() {
        let Ok(store) = std::env::var("PARAEGOX_TEST_AUTHORITY_INITIALIZER_CRASH_STORE") else {
            return;
        };
        let point = std::env::var("PARAEGOX_TEST_AUTHORITY_INITIALIZER_CRASH_POINT")
            .unwrap_or_else(|error| panic!("initializer crash point missing: {error}"));
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
            _ => panic!("unknown initializer crash point"),
        };
        let result = initialize_with(
            Path::new(&store),
            provisioning(),
            &mut successful_entropy(),
            FilesystemPolicy::ExplicitFixture,
            failpoint,
        );
        panic!("initializer crash failpoint unexpectedly returned: {result:?}");
    }
}
