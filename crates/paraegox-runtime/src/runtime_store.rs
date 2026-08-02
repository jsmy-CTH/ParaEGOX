#![cfg(unix)]

//! Owner-private POSIX snapshot store for the Runtime journal.
//!
//! This module owns only the RuntimeHost filesystem transaction boundary. Its
//! linear initializer guard can publish one already validated typed sequence-one
//! snapshot, but it does not decode installer artifacts or abstract storage for
//! another journal owner. A missing or invalid active snapshot is never
//! reconstructed from a temporary file.

use core::fmt;
use std::fs::{self, File, Metadata, TryLockError};
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use nix::dir::Dir;
use nix::fcntl::{OFlag, open, openat, renameat};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use nix::fcntl::{RenameFlags, renameat2};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{UnlinkatFlags, getegid, geteuid, unlinkat};
use paraegox_kernel::digest::{Digest32, Digest32Builder};

use crate::runtime_journal::{
    MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES, RUNTIME_JOURNAL_PAYLOAD_VERSION, RuntimeJournalError,
    RuntimeJournalPayloadV3Migration, RuntimeJournalSnapshot,
};

const LOCK_FILE_NAME: &str = "runtime.lock";
const ACTIVE_FILE_NAME: &str = "runtime.snapshot";
const TEMP_FILE_PREFIX: &str = ".runtime.snapshot.tmp-";
const MIGRATION_SOURCE_FILE_PREFIX: &str = "runtime.snapshot.source-v3-";
const MIGRATION_SOURCE_FILE_SUFFIX: &str = ".evidence";
const MIGRATION_RECEIPT_FILE_PREFIX: &str = "runtime.snapshot.migration-v1-";
const MIGRATION_RECEIPT_FILE_SUFFIX: &str = ".receipt";
const MIGRATION_EVIDENCE_TEMP_PREFIX: &str = ".runtime.snapshot.migration.tmp-";
const RUNTIME_MIGRATION_RECEIPT_MAGIC: &[u8; 4] = b"PXMR";
const RUNTIME_MIGRATION_RECEIPT_VERSION: u16 = 1;
const RUNTIME_MIGRATION_SOURCE_PAYLOAD_VERSION: u16 = 3;
const RUNTIME_MIGRATION_EVIDENCE_DOMAIN: &[u8] =
    b"paraegox.runtime.owner-journal.migration-evidence.sha256.v1";
const RUNTIME_MIGRATION_RECEIPT_DOMAIN: &[u8] =
    b"paraegox.runtime.owner-journal.migration-receipt.sha256.v1";
const MIGRATION_RECEIPT_WITHOUT_CHECKSUM_BYTES: usize = 226;
const MIGRATION_RECEIPT_BYTES: usize = MIGRATION_RECEIPT_WITHOUT_CHECKSUM_BYTES + 32;
pub(crate) const TEMP_TOKEN_BYTES: usize = 16;
const TEMP_HEX_BYTES: usize = TEMP_TOKEN_BYTES * 2;
const MAX_ORPHAN_TEMP_FILES: usize = 32;
const MAX_MIGRATION_EVIDENCE_ORPHAN_TEMPS: usize = 16;
const MAX_MIGRATION_EVIDENCE_DIRECTORY_ENTRIES: usize = 64;
const STATE_DIRECTORY_MODE_BITS: u32 = 0o700;
const STATE_DIRECTORY_MODE_MASK: u32 = 0o7777;
const PRIVATE_FILE_MODE_BITS: u32 = 0o600;
const PRIVATE_FILE_MODE_MASK: u32 = 0o7777;
const PRIVATE_FILE_MODE: Mode = Mode::S_IRUSR.union(Mode::S_IWUSR);
const READ_ONLY_EVIDENCE_MODE_BITS: u32 = 0o400;
const READ_ONLY_EVIDENCE_MODE: Mode = Mode::S_IRUSR;
#[cfg(any(target_os = "linux", test))]
const MAX_LINUX_FDINFO_BYTES: usize = 64 * 1024;
#[cfg(any(target_os = "linux", test))]
const MAX_LINUX_FDINFO_RECORDS: usize = 256;
#[cfg(any(target_os = "linux", test))]
const MAX_LINUX_FDINFO_LINE_BYTES: usize = 4 * 1024;
#[cfg(any(target_os = "linux", test))]
const MAX_LINUX_MOUNTINFO_BYTES: usize = 4 * 1024 * 1024;
#[cfg(any(target_os = "linux", test))]
const MAX_LINUX_MOUNTINFO_RECORDS: usize = 4_096;
#[cfg(any(target_os = "linux", test))]
const MAX_LINUX_MOUNTINFO_LINE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeFilesystemPolicy {
    ProductionReference,
    #[cfg(test)]
    ExplicitFixture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

pub(crate) struct RuntimeDirectory {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    owner_uid: u32,
    owner_gid: u32,
}

/// Read-only proof that the configured Runtime directory is safe, supported,
/// and fresh at the start of one initialization attempt. Entropy can be
/// obtained after this preflight without having created the durable marker.
pub(crate) struct RuntimeInitializerPreflight {
    directory: RuntimeDirectory,
}

impl fmt::Debug for RuntimeInitializerPreflight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeInitializerPreflight")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RuntimeDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDirectory")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("owner_uid", &self.owner_uid)
            .field("owner_gid", &self.owner_gid)
            .finish_non_exhaustive()
    }
}

struct OpenedRegularFile {
    file: File,
    identity: FileIdentity,
}

struct ActiveSnapshot {
    snapshot: RuntimeJournalSnapshot,
    identity: FileIdentity,
}

struct ActiveSnapshotBytes {
    encoded: Vec<u8>,
    identity: FileIdentity,
}

/// Exact, fixed-width audit receipt for one explicit Runtime payload-v3 to
/// payload-v4 store migration. The separately retained source file remains the
/// rollback/audit evidence; this receipt binds that file to the exact target
/// bytes without becoming a second journal authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeStoreMigrationReceipt {
    migration_id: [u8; 32],
    source_payload_version: u16,
    source_checksum: Digest32,
    source_store_instance_id: [u8; 32],
    source_target_fingerprint: Digest32,
    source_sequence: u64,
    source_snapshot_length: u64,
    source_snapshot_digest: Digest32,
    target_payload_version: u16,
    target_snapshot_length: u64,
    target_snapshot_digest: Digest32,
    canonical_wire: [u8; MIGRATION_RECEIPT_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeStoreMigrationDisposition {
    Migrated,
    AlreadyMigrated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeStoreMigrationOutcome {
    pub(crate) disposition: RuntimeStoreMigrationDisposition,
    pub(crate) receipt: RuntimeStoreMigrationReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeMigrationTokens {
    source_evidence: [u8; TEMP_TOKEN_BYTES],
    receipt_evidence: [u8; TEMP_TOKEN_BYTES],
    active_snapshot: [u8; TEMP_TOKEN_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeMigrationFailpoints {
    source_evidence: RuntimeCommitFailpoint,
    receipt_evidence: RuntimeCommitFailpoint,
    active_snapshot: RuntimeCommitFailpoint,
}

impl RuntimeMigrationFailpoints {
    const NONE: Self = Self {
        source_evidence: RuntimeCommitFailpoint::None,
        receipt_evidence: RuntimeCommitFailpoint::None,
        active_snapshot: RuntimeCommitFailpoint::None,
    };
}

#[derive(Clone, Copy)]
struct RuntimeMigrationRequest<'a> {
    directory: &'a Path,
    evidence_directory: &'a Path,
    expected_store_instance_id: [u8; 32],
    expected_target_fingerprint: Digest32,
    migration_id: [u8; 32],
}

struct RuntimeMigrationGuard {
    directory: RuntimeDirectory,
    lock_file: File,
    lock_identity: FileIdentity,
}

impl Drop for RuntimeMigrationGuard {
    fn drop(&mut self) {
        let _ = self.lock_file.unlock();
    }
}

impl RuntimeStoreMigrationReceipt {
    fn try_new(
        migration_id: [u8; 32],
        source: &RuntimeJournalPayloadV3Migration,
        source_wire: &[u8],
        target: &RuntimeJournalSnapshot,
    ) -> Result<Self, RuntimeStoreMigrationError> {
        if migration_id.iter().all(|byte| *byte == 0) {
            return Err(RuntimeStoreMigrationError::InvalidMigrationId);
        }
        if source.source_payload_version() != RUNTIME_MIGRATION_SOURCE_PAYLOAD_VERSION
            || source.source_store_instance_id() != target.store_instance_id()
            || source.source_target_fingerprint() != *target.owner_target_fingerprint()
            || source.source_sequence() != target.sequence()
            || source.snapshot() != target
            || source_wire.is_empty()
            || source_wire.len() > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES
            || target.canonical_wire().is_empty()
            || target.canonical_wire().len() > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES
        {
            return Err(RuntimeStoreMigrationError::InvalidReceipt);
        }
        let source_snapshot_length = u64::try_from(source_wire.len())
            .map_err(|_| RuntimeStoreMigrationError::InvalidReceipt)?;
        let target_snapshot_length = u64::try_from(target.canonical_wire().len())
            .map_err(|_| RuntimeStoreMigrationError::InvalidReceipt)?;
        let source_snapshot_digest = exact_migration_evidence_digest(source_wire)?;
        let target_snapshot_digest = exact_migration_evidence_digest(target.canonical_wire())?;

        let mut prefix = Vec::with_capacity(MIGRATION_RECEIPT_WITHOUT_CHECKSUM_BYTES);
        prefix.extend_from_slice(RUNTIME_MIGRATION_RECEIPT_MAGIC);
        prefix.extend_from_slice(&RUNTIME_MIGRATION_RECEIPT_VERSION.to_be_bytes());
        prefix.extend_from_slice(&migration_id);
        prefix.extend_from_slice(&source.source_payload_version().to_be_bytes());
        prefix.extend_from_slice(source.source_checksum().as_bytes());
        prefix.extend_from_slice(source.source_store_instance_id());
        prefix.extend_from_slice(source.source_target_fingerprint().as_bytes());
        prefix.extend_from_slice(&source.source_sequence().to_be_bytes());
        prefix.extend_from_slice(&source_snapshot_length.to_be_bytes());
        prefix.extend_from_slice(source_snapshot_digest.as_bytes());
        prefix.extend_from_slice(&RUNTIME_JOURNAL_PAYLOAD_VERSION.to_be_bytes());
        prefix.extend_from_slice(&target_snapshot_length.to_be_bytes());
        prefix.extend_from_slice(target_snapshot_digest.as_bytes());
        if prefix.len() != MIGRATION_RECEIPT_WITHOUT_CHECKSUM_BYTES {
            return Err(RuntimeStoreMigrationError::InvalidReceipt);
        }
        let receipt_checksum = exact_migration_receipt_checksum(&prefix)?;
        prefix.extend_from_slice(receipt_checksum.as_bytes());
        let canonical_wire: [u8; MIGRATION_RECEIPT_BYTES] = prefix
            .try_into()
            .map_err(|_| RuntimeStoreMigrationError::InvalidReceipt)?;
        Ok(Self {
            migration_id,
            source_payload_version: source.source_payload_version(),
            source_checksum: source.source_checksum(),
            source_store_instance_id: *source.source_store_instance_id(),
            source_target_fingerprint: source.source_target_fingerprint(),
            source_sequence: source.source_sequence(),
            source_snapshot_length,
            source_snapshot_digest,
            target_payload_version: RUNTIME_JOURNAL_PAYLOAD_VERSION,
            target_snapshot_length,
            target_snapshot_digest,
            canonical_wire,
        })
    }

    fn decode(frame: &[u8]) -> Result<Self, RuntimeStoreMigrationError> {
        if frame.len() != MIGRATION_RECEIPT_BYTES {
            return Err(RuntimeStoreMigrationError::InvalidReceipt);
        }
        let mut cursor = RuntimeMigrationReceiptCursor::new(frame);
        if cursor.array::<4>()? != *RUNTIME_MIGRATION_RECEIPT_MAGIC
            || cursor.u16()? != RUNTIME_MIGRATION_RECEIPT_VERSION
        {
            return Err(RuntimeStoreMigrationError::InvalidReceipt);
        }
        let migration_id = cursor.array::<32>()?;
        let source_payload_version = cursor.u16()?;
        let source_checksum = Digest32::from_bytes(cursor.array::<32>()?);
        let source_store_instance_id = cursor.array::<32>()?;
        let source_target_fingerprint = Digest32::from_bytes(cursor.array::<32>()?);
        let source_sequence = cursor.u64()?;
        let source_snapshot_length = cursor.u64()?;
        let source_snapshot_digest = Digest32::from_bytes(cursor.array::<32>()?);
        let target_payload_version = cursor.u16()?;
        let target_snapshot_length = cursor.u64()?;
        let target_snapshot_digest = Digest32::from_bytes(cursor.array::<32>()?);
        let receipt_checksum = Digest32::from_bytes(cursor.array::<32>()?);
        cursor.finish()?;
        if migration_id.iter().all(|byte| *byte == 0)
            || source_payload_version != RUNTIME_MIGRATION_SOURCE_PAYLOAD_VERSION
            || target_payload_version != RUNTIME_JOURNAL_PAYLOAD_VERSION
            || source_store_instance_id.iter().all(|byte| *byte == 0)
            || source_sequence == 0
            || source_snapshot_length == 0
            || source_snapshot_length > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES as u64
            || target_snapshot_length == 0
            || target_snapshot_length > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES as u64
            || exact_migration_receipt_checksum(&frame[..MIGRATION_RECEIPT_WITHOUT_CHECKSUM_BYTES])?
                != receipt_checksum
        {
            return Err(RuntimeStoreMigrationError::InvalidReceipt);
        }
        Ok(Self {
            migration_id,
            source_payload_version,
            source_checksum,
            source_store_instance_id,
            source_target_fingerprint,
            source_sequence,
            source_snapshot_length,
            source_snapshot_digest,
            target_payload_version,
            target_snapshot_length,
            target_snapshot_digest,
            canonical_wire: frame
                .try_into()
                .map_err(|_| RuntimeStoreMigrationError::InvalidReceipt)?,
        })
    }

    pub(crate) const fn migration_id(&self) -> &[u8; 32] {
        &self.migration_id
    }

    pub(crate) const fn source_payload_version(&self) -> u16 {
        self.source_payload_version
    }

    pub(crate) const fn source_checksum(&self) -> Digest32 {
        self.source_checksum
    }

    pub(crate) const fn source_store_instance_id(&self) -> &[u8; 32] {
        &self.source_store_instance_id
    }

    pub(crate) const fn source_target_fingerprint(&self) -> Digest32 {
        self.source_target_fingerprint
    }

    pub(crate) const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    pub(crate) const fn canonical_wire(&self) -> &[u8; MIGRATION_RECEIPT_BYTES] {
        &self.canonical_wire
    }
}

struct RuntimeMigrationReceiptCursor<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> RuntimeMigrationReceiptCursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RuntimeStoreMigrationError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(RuntimeStoreMigrationError::InvalidReceipt)?;
        let bytes = self
            .frame
            .get(self.position..end)
            .ok_or(RuntimeStoreMigrationError::InvalidReceipt)?;
        self.position = end;
        bytes
            .try_into()
            .map_err(|_| RuntimeStoreMigrationError::InvalidReceipt)
    }

    fn u16(&mut self) -> Result<u16, RuntimeStoreMigrationError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, RuntimeStoreMigrationError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), RuntimeStoreMigrationError> {
        if self.position == self.frame.len() {
            Ok(())
        } else {
            Err(RuntimeStoreMigrationError::InvalidReceipt)
        }
    }
}

fn exact_migration_evidence_digest(bytes: &[u8]) -> Result<Digest32, RuntimeStoreMigrationError> {
    let mut builder = Digest32Builder::try_new(RUNTIME_MIGRATION_EVIDENCE_DOMAIN)
        .map_err(|_| RuntimeStoreMigrationError::InvalidReceipt)?;
    builder
        .field_bytes(bytes)
        .map_err(|_| RuntimeStoreMigrationError::InvalidReceipt)?;
    Ok(builder.finish())
}

fn exact_migration_receipt_checksum(bytes: &[u8]) -> Result<Digest32, RuntimeStoreMigrationError> {
    let mut builder = Digest32Builder::try_new(RUNTIME_MIGRATION_RECEIPT_DOMAIN)
        .map_err(|_| RuntimeStoreMigrationError::InvalidReceipt)?;
    builder
        .field_bytes(bytes)
        .map_err(|_| RuntimeStoreMigrationError::InvalidReceipt)?;
    Ok(builder.finish())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeStoreState {
    Operational,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimePublishMode {
    RequireMissing,
    ReplaceExisting(FileIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeInitializerState {
    Fresh,
    Published,
    Stopped,
}

/// Linear, owner-private capability for exactly one Runtime sequence-one
/// publication. Holding this value proves the durable marker is installed and
/// its exclusive writer lock remains owned by this initializer.
pub(crate) struct RuntimeInitializerGuard {
    directory: RuntimeDirectory,
    lock_file: File,
    lock_identity: FileIdentity,
    state: RuntimeInitializerState,
}

impl fmt::Debug for RuntimeInitializerGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeInitializerGuard")
            .field("directory", &self.directory)
            .field("lock_identity", &self.lock_identity)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Drop for RuntimeInitializerGuard {
    fn drop(&mut self) {
        // Match RuntimeStore's restart guarantee: a fork-like descriptor clone
        // must not keep the initializer lock alive after normal owner drop.
        let _ = self.lock_file.unlock();
    }
}

/// The single-writer, owner-private Runtime snapshot store.
pub(crate) struct RuntimeStore {
    directory: RuntimeDirectory,
    lock_file: File,
    lock_identity: FileIdentity,
    active: ActiveSnapshot,
    state: RuntimeStoreState,
}

impl fmt::Debug for RuntimeStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeStore")
            .field("directory", &self.directory)
            .field("lock_identity", &self.lock_identity)
            .field("snapshot_sequence", &self.active.snapshot.sequence())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Drop for RuntimeStore {
    fn drop(&mut self) {
        // A forked child temporarily shares this open-file description until
        // exec closes its CLOEXEC descriptor. Unlock explicitly so normal
        // owner shutdown cannot leave restart availability dependent on that
        // transient child reference reaching exec first.
        let _ = self.lock_file.unlock();
    }
}

impl RuntimeStore {
    /// Explicitly migrates one stopped Runtime store from payload v3 to v4.
    ///
    /// The caller selects a separate operator-owned evidence directory and a
    /// stable migration id. Normal store open never invokes this path. A retry
    /// after an uncertain publish accepts a v4 active snapshot only when the
    /// exact read-only v3 evidence and receipt prove that this migration id
    /// produced those exact target bytes.
    pub(crate) fn migrate_payload_v3_offline(
        directory: &Path,
        evidence_directory: &Path,
        expected_store_instance_id: [u8; 32],
        expected_target_fingerprint: Digest32,
        migration_id: [u8; 32],
    ) -> Result<RuntimeStoreMigrationOutcome, RuntimeStoreMigrationError> {
        Self::migrate_payload_v3_offline_with_policy(
            RuntimeMigrationRequest {
                directory,
                evidence_directory,
                expected_store_instance_id,
                expected_target_fingerprint,
                migration_id,
            },
            RuntimeFilesystemPolicy::ProductionReference,
            None,
            RuntimeMigrationFailpoints::NONE,
        )
    }

    fn migrate_payload_v3_offline_with_policy(
        request: RuntimeMigrationRequest<'_>,
        filesystem_policy: RuntimeFilesystemPolicy,
        tokens: Option<RuntimeMigrationTokens>,
        failpoints: RuntimeMigrationFailpoints,
    ) -> Result<RuntimeStoreMigrationOutcome, RuntimeStoreMigrationError> {
        validate_migration_inputs(
            request.expected_store_instance_id,
            request.expected_target_fingerprint,
            request.migration_id,
        )?;
        let guard = acquire_runtime_migration_guard(request.directory, filesystem_policy)?;
        let evidence_directory =
            open_runtime_directory(request.evidence_directory, filesystem_policy)
                .map_err(RuntimeStoreMigrationError::EvidenceDirectory)?;
        if guard.directory.identity == evidence_directory.identity {
            return Err(RuntimeStoreMigrationError::EvidenceDirectoryMatchesStore);
        }
        let active = read_active_snapshot_bytes(&guard.directory)
            .map_err(RuntimeStoreMigrationError::Store)?;

        match RuntimeJournalSnapshot::decode(&active.encoded) {
            Ok(target) => resume_completed_runtime_migration(
                &guard,
                &evidence_directory,
                request.expected_store_instance_id,
                request.expected_target_fingerprint,
                request.migration_id,
                active,
                target,
            ),
            Err(RuntimeJournalError::UnsupportedPayloadVersion) => {
                let source =
                    RuntimeJournalSnapshot::migrate_payload_v3_with_metadata(&active.encoded)
                        .map_err(RuntimeStoreMigrationError::Journal)?;
                let tokens = match tokens {
                    Some(tokens) => tokens,
                    None => runtime_migration_tokens()?,
                };
                publish_runtime_migration(
                    request,
                    &guard,
                    &evidence_directory,
                    active,
                    source,
                    tokens,
                    failpoints,
                )
            }
            Err(error) => Err(RuntimeStoreMigrationError::Journal(error)),
        }
    }

    pub(crate) fn open(
        directory: &Path,
        expected_store_instance_id: [u8; 32],
        expected_target_fingerprint: Digest32,
    ) -> Result<Self, RuntimeStoreOpenError> {
        Self::open_with_policy(
            directory,
            expected_store_instance_id,
            expected_target_fingerprint,
            RuntimeFilesystemPolicy::ProductionReference,
        )
    }

    fn open_with_policy(
        directory: &Path,
        expected_store_instance_id: [u8; 32],
        expected_target_fingerprint: Digest32,
        filesystem_policy: RuntimeFilesystemPolicy,
    ) -> Result<Self, RuntimeStoreOpenError> {
        if expected_store_instance_id.iter().all(|byte| *byte == 0) {
            return Err(RuntimeStoreOpenError::InvalidExpectedStoreInstanceId);
        }
        if expected_target_fingerprint
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(RuntimeStoreOpenError::InvalidExpectedTargetFingerprint);
        }
        let directory = open_runtime_directory(directory, filesystem_policy)?;
        let OpenedRegularFile {
            file: lock_file,
            identity: lock_identity,
        } = open_existing_regular(
            &directory,
            LOCK_FILE_NAME,
            OFlag::O_RDWR,
            RuntimeFileStage::OpenLock,
        )?;
        lock_file.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => RuntimeStoreOpenError::LockContended,
            TryLockError::Error(error) => RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
                RuntimeFileStage::AcquireLock,
                &error,
            )),
        })?;
        validate_named_file_identity(
            &directory,
            LOCK_FILE_NAME,
            lock_identity,
            RuntimeFileStage::ValidateLockIdentity,
        )?;

        // Active is authoritative. It is decoded and identity-checked before
        // orphan temporary files are even classified, so restart never elects
        // a temporary file over a missing or invalid active snapshot.
        let active = read_active_snapshot(&directory)?;
        if active.snapshot.store_instance_id() != &expected_store_instance_id {
            return Err(RuntimeStoreOpenError::StoreInstanceMismatch);
        }
        if active.snapshot.owner_target_fingerprint() != &expected_target_fingerprint {
            return Err(RuntimeStoreOpenError::TargetFingerprintMismatch);
        }
        clean_valid_orphan_temps(&directory)?;

        Ok(Self {
            directory,
            lock_file,
            lock_identity,
            active,
            state: RuntimeStoreState::Operational,
        })
    }

    pub(crate) fn snapshot(&self) -> Result<&RuntimeJournalSnapshot, RuntimeStoreError> {
        self.ensure_operational()?;
        Ok(&self.active.snapshot)
    }

    pub(crate) fn revalidate_current(
        &mut self,
    ) -> Result<&RuntimeJournalSnapshot, RuntimeStoreError> {
        self.ensure_operational()?;
        if validate_runtime_directory_handle(&self.directory).is_err()
            || validate_held_lock(&self.directory, &self.lock_file, self.lock_identity).is_err()
        {
            self.state = RuntimeStoreState::Stopped;
            return Err(RuntimeStoreError::LockOrDirectoryIdentityChanged);
        }
        let disk = read_active_snapshot(&self.directory).map_err(|error| {
            self.state = RuntimeStoreState::Stopped;
            RuntimeStoreError::Open(error)
        })?;
        if disk.identity != self.active.identity || disk.snapshot != self.active.snapshot {
            self.state = RuntimeStoreState::Stopped;
            return Err(RuntimeStoreError::ActiveSnapshotChanged);
        }
        Ok(&self.active.snapshot)
    }

    pub(crate) fn commit(&mut self, next: RuntimeJournalSnapshot) -> Result<(), RuntimeStoreError> {
        self.commit_with_entropy(next, RuntimeCommitFailpoint::None, system_random_token)
    }

    fn commit_with(
        &mut self,
        next: RuntimeJournalSnapshot,
        token: [u8; TEMP_TOKEN_BYTES],
        failpoint: RuntimeCommitFailpoint,
    ) -> Result<(), RuntimeStoreError> {
        self.commit_with_entropy(next, failpoint, || Ok(token))
    }

    fn commit_with_entropy(
        &mut self,
        next: RuntimeJournalSnapshot,
        failpoint: RuntimeCommitFailpoint,
        entropy: impl FnOnce() -> Result<[u8; TEMP_TOKEN_BYTES], io::Error>,
    ) -> Result<(), RuntimeStoreError> {
        self.prepare_commit(&next)?;
        let token = entropy().map_err(|error| {
            self.state = RuntimeStoreState::Stopped;
            RuntimeStoreError::Publish(RuntimePublishFailure::RejectedBeforePublish(
                RuntimePublishFault::io(RuntimeFileStage::GenerateTempName, &error),
            ))
        })?;
        self.publish_prevalidated(next, token, failpoint)
    }

    fn prepare_commit(&mut self, next: &RuntimeJournalSnapshot) -> Result<(), RuntimeStoreError> {
        self.ensure_operational()?;
        next.validate_successor_of(&self.active.snapshot)
            .map_err(|error| {
                self.state = RuntimeStoreState::Stopped;
                RuntimeStoreError::Journal(error)
            })?;
        self.revalidate_current()?;
        Ok(())
    }

    fn publish_prevalidated(
        &mut self,
        next: RuntimeJournalSnapshot,
        token: [u8; TEMP_TOKEN_BYTES],
        failpoint: RuntimeCommitFailpoint,
    ) -> Result<(), RuntimeStoreError> {
        if let Err(error) = publish_atomic(
            &self.directory,
            next.canonical_wire(),
            RuntimePublishMode::ReplaceExisting(self.active.identity),
            token,
            failpoint,
        ) {
            self.state = RuntimeStoreState::Stopped;
            return Err(RuntimeStoreError::Publish(error));
        }

        // The rename and directory fsync have completed, so any inability to
        // prove the exact published bytes is post-publish uncertainty.
        let read_back = read_active_snapshot(&self.directory).map_err(|error| {
            self.state = RuntimeStoreState::Stopped;
            RuntimeStoreError::Publish(RuntimePublishFailure::UncertainAfterPublish(
                publish_fault_from_open(RuntimeFileStage::ReadBackPublished, error),
            ))
        })?;
        if read_back.snapshot != next {
            self.state = RuntimeStoreState::Stopped;
            return Err(RuntimeStoreError::Publish(
                RuntimePublishFailure::UncertainAfterPublish(RuntimePublishFault::injected(
                    RuntimeFileStage::ReadBackPublished,
                )),
            ));
        }
        self.active = read_back;
        Ok(())
    }

    fn ensure_operational(&self) -> Result<(), RuntimeStoreError> {
        if self.state == RuntimeStoreState::Stopped {
            return Err(RuntimeStoreError::Stopped);
        }
        Ok(())
    }
}

fn validate_migration_inputs(
    expected_store_instance_id: [u8; 32],
    expected_target_fingerprint: Digest32,
    migration_id: [u8; 32],
) -> Result<(), RuntimeStoreMigrationError> {
    if expected_store_instance_id.iter().all(|byte| *byte == 0) {
        return Err(RuntimeStoreMigrationError::InvalidExpectedStoreInstanceId);
    }
    if expected_target_fingerprint
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(RuntimeStoreMigrationError::InvalidExpectedTargetFingerprint);
    }
    if migration_id.iter().all(|byte| *byte == 0) {
        return Err(RuntimeStoreMigrationError::InvalidMigrationId);
    }
    Ok(())
}

fn acquire_runtime_migration_guard(
    directory: &Path,
    filesystem_policy: RuntimeFilesystemPolicy,
) -> Result<RuntimeMigrationGuard, RuntimeStoreMigrationError> {
    let directory = open_runtime_directory(directory, filesystem_policy)
        .map_err(RuntimeStoreMigrationError::Store)?;
    let OpenedRegularFile {
        file: lock_file,
        identity: lock_identity,
    } = open_existing_regular(
        &directory,
        LOCK_FILE_NAME,
        OFlag::O_RDWR,
        RuntimeFileStage::OpenLock,
    )
    .map_err(RuntimeStoreMigrationError::Store)?;
    lock_file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => RuntimeStoreMigrationError::LockContended,
        TryLockError::Error(error) => RuntimeStoreMigrationError::Store(RuntimeStoreOpenError::Io(
            RuntimeIoFailure::new(RuntimeFileStage::AcquireLock, &error),
        )),
    })?;
    validate_named_file_identity(
        &directory,
        LOCK_FILE_NAME,
        lock_identity,
        RuntimeFileStage::ValidateLockIdentity,
    )
    .map_err(RuntimeStoreMigrationError::Store)?;
    Ok(RuntimeMigrationGuard {
        directory,
        lock_file,
        lock_identity,
    })
}

fn runtime_migration_tokens() -> Result<RuntimeMigrationTokens, RuntimeStoreMigrationError> {
    Ok(RuntimeMigrationTokens {
        source_evidence: system_random_token().map_err(|error| {
            RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
                RuntimeFileStage::GenerateMigrationEvidenceTempName,
                &error,
            ))
        })?,
        receipt_evidence: system_random_token().map_err(|error| {
            RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
                RuntimeFileStage::GenerateMigrationEvidenceTempName,
                &error,
            ))
        })?,
        active_snapshot: system_random_token().map_err(|error| {
            RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
                RuntimeFileStage::GenerateTempName,
                &error,
            ))
        })?,
    })
}

fn resume_completed_runtime_migration(
    guard: &RuntimeMigrationGuard,
    evidence_directory: &RuntimeDirectory,
    expected_store_instance_id: [u8; 32],
    expected_target_fingerprint: Digest32,
    migration_id: [u8; 32],
    active: ActiveSnapshotBytes,
    target: RuntimeJournalSnapshot,
) -> Result<RuntimeStoreMigrationOutcome, RuntimeStoreMigrationError> {
    validate_migration_target_identity(
        &target,
        expected_store_instance_id,
        expected_target_fingerprint,
    )?;
    if target.canonical_wire() != active.encoded {
        return Err(RuntimeStoreMigrationError::TargetMismatch);
    }
    clean_runtime_migration_evidence_temps(evidence_directory, migration_id)
        .map_err(|_| published_but_unverified(RuntimeFileStage::InspectMigrationEvidence))?;
    let (source_wire, stored_receipt) =
        read_runtime_migration_evidence(evidence_directory, migration_id)
            .map_err(|_| published_but_unverified(RuntimeFileStage::ReadBackMigrationEvidence))?;
    let source = RuntimeJournalSnapshot::migrate_payload_v3_with_metadata(&source_wire)
        .map_err(|_| published_but_unverified(RuntimeFileStage::ReadBackMigrationEvidence))?;
    validate_migration_source_identity(
        &source,
        expected_store_instance_id,
        expected_target_fingerprint,
    )
    .map_err(|_| published_but_unverified(RuntimeFileStage::ReadBackMigrationEvidence))?;
    if source.snapshot() != &target || source.snapshot().canonical_wire() != active.encoded {
        return Err(published_but_unverified(
            RuntimeFileStage::ReadBackPublished,
        ));
    }
    let expected_receipt =
        RuntimeStoreMigrationReceipt::try_new(migration_id, &source, &source_wire, &target)
            .map_err(|_| published_but_unverified(RuntimeFileStage::ReadBackMigrationEvidence))?;
    if stored_receipt != expected_receipt {
        return Err(published_but_unverified(
            RuntimeFileStage::ReadBackMigrationEvidence,
        ));
    }
    validate_migration_handles(guard, evidence_directory)
        .map_err(|_| published_but_unverified(RuntimeFileStage::VerifyPublishedMigration))?;
    clean_valid_orphan_temps(&guard.directory)
        .map_err(|_| published_but_unverified(RuntimeFileStage::VerifyPublishedMigration))?;
    let revalidated = read_active_snapshot(&guard.directory)
        .map_err(|_| published_but_unverified(RuntimeFileStage::ReadBackPublished))?;
    if revalidated.identity != active.identity || revalidated.snapshot != target {
        return Err(published_but_unverified(
            RuntimeFileStage::ReadBackPublished,
        ));
    }
    Ok(RuntimeStoreMigrationOutcome {
        disposition: RuntimeStoreMigrationDisposition::AlreadyMigrated,
        receipt: stored_receipt,
    })
}

fn publish_runtime_migration(
    request: RuntimeMigrationRequest<'_>,
    guard: &RuntimeMigrationGuard,
    evidence_directory: &RuntimeDirectory,
    active: ActiveSnapshotBytes,
    source: RuntimeJournalPayloadV3Migration,
    tokens: RuntimeMigrationTokens,
    failpoints: RuntimeMigrationFailpoints,
) -> Result<RuntimeStoreMigrationOutcome, RuntimeStoreMigrationError> {
    validate_migration_source_identity(
        &source,
        request.expected_store_instance_id,
        request.expected_target_fingerprint,
    )?;
    let target_wire = source.snapshot().canonical_wire().to_vec();
    let target = RuntimeJournalSnapshot::decode(&target_wire)
        .map_err(RuntimeStoreMigrationError::Journal)?;
    validate_migration_target_identity(
        &target,
        request.expected_store_instance_id,
        request.expected_target_fingerprint,
    )?;
    let receipt = RuntimeStoreMigrationReceipt::try_new(
        request.migration_id,
        &source,
        &active.encoded,
        &target,
    )?;

    clean_valid_orphan_temps(&guard.directory).map_err(RuntimeStoreMigrationError::Store)?;
    clean_runtime_migration_evidence_temps(evidence_directory, request.migration_id)?;
    ensure_read_only_migration_evidence(
        evidence_directory,
        request.migration_id,
        &migration_source_file_name(request.migration_id),
        &active.encoded,
        MigrationEvidenceKind::Source,
        tokens.source_evidence,
        failpoints.source_evidence,
    )?;
    ensure_read_only_migration_evidence(
        evidence_directory,
        request.migration_id,
        &migration_receipt_file_name(request.migration_id),
        receipt.canonical_wire(),
        MigrationEvidenceKind::Receipt,
        tokens.receipt_evidence,
        failpoints.receipt_evidence,
    )?;
    let (stored_source, stored_receipt) =
        read_runtime_migration_evidence(evidence_directory, request.migration_id).map_err(
            |_| uncertain_migration_evidence_publish(RuntimeFileStage::ReadBackMigrationEvidence),
        )?;
    if stored_source != active.encoded || stored_receipt != receipt {
        return Err(uncertain_migration_evidence_publish(
            RuntimeFileStage::ReadBackMigrationEvidence,
        ));
    }

    validate_migration_handles(guard, evidence_directory)?;
    let current =
        read_active_snapshot_bytes(&guard.directory).map_err(RuntimeStoreMigrationError::Store)?;
    if current.identity != active.identity || current.encoded != active.encoded {
        return Err(RuntimeStoreMigrationError::TargetMismatch);
    }
    publish_atomic(
        &guard.directory,
        &target_wire,
        RuntimePublishMode::ReplaceExisting(active.identity),
        tokens.active_snapshot,
        failpoints.active_snapshot,
    )
    .map_err(RuntimeStoreMigrationError::Publish)?;

    #[cfg(test)]
    if failpoints.active_snapshot == RuntimeCommitFailpoint::MigrationActiveReadBackFailure {
        return Err(published_but_unverified(
            RuntimeFileStage::ReadBackPublished,
        ));
    }
    let published = read_active_snapshot(&guard.directory)
        .map_err(|_| published_but_unverified(RuntimeFileStage::ReadBackPublished))?;
    if published.snapshot != target || published.snapshot.canonical_wire() != target_wire {
        return Err(published_but_unverified(
            RuntimeFileStage::ReadBackPublished,
        ));
    }
    validate_migration_handles(guard, evidence_directory)
        .map_err(|_| published_but_unverified(RuntimeFileStage::VerifyPublishedMigration))?;
    #[cfg(test)]
    if failpoints.active_snapshot == RuntimeCommitFailpoint::MigrationPostPublishEvidenceFailure {
        return Err(published_but_unverified(
            RuntimeFileStage::ReadBackMigrationEvidence,
        ));
    }
    let (stored_source, stored_receipt) =
        read_runtime_migration_evidence(evidence_directory, request.migration_id)
            .map_err(|_| published_but_unverified(RuntimeFileStage::ReadBackMigrationEvidence))?;
    if stored_source != active.encoded || stored_receipt != receipt {
        return Err(published_but_unverified(
            RuntimeFileStage::ReadBackMigrationEvidence,
        ));
    }
    Ok(RuntimeStoreMigrationOutcome {
        disposition: RuntimeStoreMigrationDisposition::Migrated,
        receipt,
    })
}

fn validate_migration_source_identity(
    source: &RuntimeJournalPayloadV3Migration,
    expected_store_instance_id: [u8; 32],
    expected_target_fingerprint: Digest32,
) -> Result<(), RuntimeStoreMigrationError> {
    if source.source_store_instance_id() != &expected_store_instance_id {
        return Err(RuntimeStoreMigrationError::StoreInstanceMismatch);
    }
    if source.source_target_fingerprint() != expected_target_fingerprint {
        return Err(RuntimeStoreMigrationError::TargetFingerprintMismatch);
    }
    Ok(())
}

fn validate_migration_target_identity(
    target: &RuntimeJournalSnapshot,
    expected_store_instance_id: [u8; 32],
    expected_target_fingerprint: Digest32,
) -> Result<(), RuntimeStoreMigrationError> {
    if target.store_instance_id() != &expected_store_instance_id {
        return Err(RuntimeStoreMigrationError::StoreInstanceMismatch);
    }
    if target.owner_target_fingerprint() != &expected_target_fingerprint {
        return Err(RuntimeStoreMigrationError::TargetFingerprintMismatch);
    }
    Ok(())
}

fn validate_migration_handles(
    guard: &RuntimeMigrationGuard,
    evidence_directory: &RuntimeDirectory,
) -> Result<(), RuntimeStoreMigrationError> {
    validate_runtime_directory_handle(&guard.directory)
        .map_err(RuntimeStoreMigrationError::Store)?;
    validate_held_lock(&guard.directory, &guard.lock_file, guard.lock_identity)
        .map_err(RuntimeStoreMigrationError::Store)?;
    validate_runtime_directory_handle(evidence_directory)
        .map_err(RuntimeStoreMigrationError::EvidenceDirectory)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MigrationEvidenceKind {
    Source,
    Receipt,
}

fn migration_source_file_name(migration_id: [u8; 32]) -> String {
    let mut name = String::with_capacity(
        MIGRATION_SOURCE_FILE_PREFIX.len() + 64 + MIGRATION_SOURCE_FILE_SUFFIX.len(),
    );
    name.push_str(MIGRATION_SOURCE_FILE_PREFIX);
    append_lower_hex(&mut name, &migration_id);
    name.push_str(MIGRATION_SOURCE_FILE_SUFFIX);
    name
}

fn migration_receipt_file_name(migration_id: [u8; 32]) -> String {
    let mut name = String::with_capacity(
        MIGRATION_RECEIPT_FILE_PREFIX.len() + 64 + MIGRATION_RECEIPT_FILE_SUFFIX.len(),
    );
    name.push_str(MIGRATION_RECEIPT_FILE_PREFIX);
    append_lower_hex(&mut name, &migration_id);
    name.push_str(MIGRATION_RECEIPT_FILE_SUFFIX);
    name
}

fn migration_evidence_temp_name(
    migration_id: [u8; 32],
    kind: MigrationEvidenceKind,
    token: [u8; TEMP_TOKEN_BYTES],
) -> String {
    let label = match kind {
        MigrationEvidenceKind::Source => "source-",
        MigrationEvidenceKind::Receipt => "receipt-",
    };
    let mut name = String::with_capacity(
        MIGRATION_EVIDENCE_TEMP_PREFIX.len() + 64 + 1 + label.len() + TEMP_HEX_BYTES,
    );
    name.push_str(MIGRATION_EVIDENCE_TEMP_PREFIX);
    append_lower_hex(&mut name, &migration_id);
    name.push('-');
    name.push_str(label);
    append_lower_hex(&mut name, &token);
    name
}

fn append_lower_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

fn migration_evidence_temp_prefix(migration_id: [u8; 32]) -> String {
    let mut prefix = String::with_capacity(MIGRATION_EVIDENCE_TEMP_PREFIX.len() + 64 + 1);
    prefix.push_str(MIGRATION_EVIDENCE_TEMP_PREFIX);
    append_lower_hex(&mut prefix, &migration_id);
    prefix.push('-');
    prefix
}

fn valid_migration_evidence_temp_name(name: &str, migration_id: [u8; 32]) -> bool {
    let prefix = migration_evidence_temp_prefix(migration_id);
    let Some(suffix) = name.strip_prefix(&prefix) else {
        return false;
    };
    let Some(token) = suffix
        .strip_prefix("source-")
        .or_else(|| suffix.strip_prefix("receipt-"))
    else {
        return false;
    };
    token.len() == TEMP_HEX_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn clean_runtime_migration_evidence_temps(
    directory: &RuntimeDirectory,
    migration_id: [u8; 32],
) -> Result<(), RuntimeStoreMigrationError> {
    let expected_prefix = migration_evidence_temp_prefix(migration_id);
    let mut entries = duplicate_directory_stream(directory)
        .map_err(RuntimeStoreMigrationError::EvidenceDirectory)?;
    let mut orphan_names = Vec::new();
    let mut total_entries = 0_usize;
    for entry in entries.iter() {
        let entry = entry.map_err(|error| {
            RuntimeStoreMigrationError::EvidenceIo(nix_failure(
                RuntimeFileStage::InspectMigrationEvidence,
                error,
            ))
        })?;
        let name_bytes = entry.file_name().to_bytes();
        if is_dot_entry(name_bytes) {
            continue;
        }
        total_entries = total_entries
            .checked_add(1)
            .ok_or(RuntimeStoreMigrationError::TooManyEvidenceDirectoryEntries)?;
        if total_entries > MAX_MIGRATION_EVIDENCE_DIRECTORY_ENTRIES {
            return Err(RuntimeStoreMigrationError::TooManyEvidenceDirectoryEntries);
        }
        if !name_bytes.starts_with(expected_prefix.as_bytes()) {
            continue;
        }
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| RuntimeStoreMigrationError::UnknownEvidenceEntry)?;
        if !valid_migration_evidence_temp_name(name, migration_id) {
            return Err(RuntimeStoreMigrationError::UnknownEvidenceEntry);
        }
        orphan_names.push(name.to_owned());
        if orphan_names.len() > MAX_MIGRATION_EVIDENCE_ORPHAN_TEMPS {
            return Err(RuntimeStoreMigrationError::TooManyEvidenceTemps);
        }
    }

    if orphan_names.is_empty() {
        return Ok(());
    }
    let mut validated_orphans = Vec::with_capacity(orphan_names.len());
    for name in orphan_names {
        let (file, identity) = open_migration_evidence_temp(directory, &name)?;
        validate_named_migration_evidence_temp_identity(directory, &name, identity)?;
        validated_orphans.push((name, file));
    }
    // Deliberately start unlink only after every candidate has passed both
    // descriptor metadata and second named-identity validation. A malformed or
    // replaced later candidate therefore cannot leave a half-cleaned audit dir.
    for (name, file) in validated_orphans {
        unlinkat(&directory.file, name.as_str(), UnlinkatFlags::NoRemoveDir).map_err(|error| {
            RuntimeStoreMigrationError::EvidenceIo(nix_failure(
                RuntimeFileStage::InspectMigrationEvidence,
                error,
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
                RuntimeFileStage::InspectMigrationEvidence,
                &error,
            ))
        })?;
        if metadata.nlink() != 0 {
            return Err(RuntimeStoreMigrationError::EvidenceChangedDuringRead);
        }
    }
    directory.file.sync_all().map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
            RuntimeFileStage::SyncMigrationEvidenceDirectory,
            &error,
        ))
    })
}

fn open_migration_evidence_temp(
    directory: &RuntimeDirectory,
    name: &str,
) -> Result<(File, FileIdentity), RuntimeStoreMigrationError> {
    let owned = openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(nix_failure(
            RuntimeFileStage::InspectMigrationEvidence,
            error,
        ))
    })?;
    let file = File::from(owned);
    let metadata = file.metadata().map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
            RuntimeFileStage::InspectMigrationEvidence,
            &error,
        ))
    })?;
    validate_migration_evidence_temp_metadata(&metadata, directory.owner_uid, directory.owner_gid)?;
    Ok((file, FileIdentity::from_metadata(&metadata)))
}

fn validate_migration_evidence_temp_metadata(
    metadata: &Metadata,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), RuntimeStoreMigrationError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(RuntimeStoreMigrationError::UnsafeEvidenceFile);
    }
    if metadata.uid() != owner_uid || metadata.gid() != owner_gid {
        return Err(RuntimeStoreMigrationError::EvidenceOwnerMismatch);
    }
    let mode = metadata.mode() & PRIVATE_FILE_MODE_MASK;
    if mode != PRIVATE_FILE_MODE_BITS && mode != READ_ONLY_EVIDENCE_MODE_BITS {
        return Err(RuntimeStoreMigrationError::UnsafeEvidenceMode);
    }
    Ok(())
}

fn validate_named_migration_evidence_temp_identity(
    directory: &RuntimeDirectory,
    name: &str,
    expected: FileIdentity,
) -> Result<(), RuntimeStoreMigrationError> {
    let (file, identity) = open_migration_evidence_temp(directory, name)?;
    drop(file);
    if identity != expected {
        return Err(RuntimeStoreMigrationError::EvidenceChangedDuringRead);
    }
    Ok(())
}

fn read_runtime_migration_evidence(
    directory: &RuntimeDirectory,
    migration_id: [u8; 32],
) -> Result<(Vec<u8>, RuntimeStoreMigrationReceipt), RuntimeStoreMigrationError> {
    let source = read_read_only_migration_evidence(
        directory,
        &migration_source_file_name(migration_id),
        MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES,
    )?;
    let receipt_wire = read_read_only_migration_evidence(
        directory,
        &migration_receipt_file_name(migration_id),
        MIGRATION_RECEIPT_BYTES,
    )?;
    let receipt = RuntimeStoreMigrationReceipt::decode(&receipt_wire)?;
    if receipt.migration_id != migration_id
        || receipt.source_snapshot_length != source.len() as u64
        || receipt.source_snapshot_digest != exact_migration_evidence_digest(&source)?
    {
        return Err(RuntimeStoreMigrationError::EvidenceMismatch);
    }
    Ok((source, receipt))
}

fn ensure_read_only_migration_evidence(
    directory: &RuntimeDirectory,
    migration_id: [u8; 32],
    name: &str,
    bytes: &[u8],
    kind: MigrationEvidenceKind,
    token: [u8; TEMP_TOKEN_BYTES],
    failpoint: RuntimeCommitFailpoint,
) -> Result<(), RuntimeStoreMigrationError> {
    match read_read_only_migration_evidence(directory, name, bytes.len()) {
        Ok(existing) => {
            if existing == bytes {
                return Ok(());
            }
            return Err(RuntimeStoreMigrationError::EvidenceMismatch);
        }
        Err(RuntimeStoreMigrationError::EvidenceMissing) => {}
        Err(error) => return Err(error),
    }
    if failpoint == RuntimeCommitFailpoint::BeforeTempCreate {
        return Err(rejected_migration_evidence_publish(
            RuntimeFileStage::CreateMigrationEvidenceTemp,
        ));
    }
    let temp_name = migration_evidence_temp_name(migration_id, kind, token);
    let owned = openat(
        &directory.file,
        temp_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(nix_failure(
            RuntimeFileStage::CreateMigrationEvidenceTemp,
            error,
        ))
    })?;
    let mut temp = File::from(owned);
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::AbortAfterTempCreate {
        std::process::abort();
    }
    if failpoint == RuntimeCommitFailpoint::AfterTempCreate {
        return Err(rejected_migration_evidence_publish(
            RuntimeFileStage::CreateMigrationEvidenceTemp,
        ));
    }
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::AbortAfterPartialWrite {
        let partial_length = bytes.len().saturating_sub(1).max(1);
        temp.write_all(&bytes[..partial_length]).map_err(|error| {
            RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
                RuntimeFileStage::WriteMigrationEvidenceTemp,
                &error,
            ))
        })?;
        std::process::abort();
    }
    if failpoint == RuntimeCommitFailpoint::AfterPartialWrite {
        let partial_length = bytes.len().saturating_sub(1).max(1);
        temp.write_all(&bytes[..partial_length]).map_err(|error| {
            RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
                RuntimeFileStage::WriteMigrationEvidenceTemp,
                &error,
            ))
        })?;
        return Err(rejected_migration_evidence_publish(
            RuntimeFileStage::WriteMigrationEvidenceTemp,
        ));
    }
    temp.write_all(bytes).map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
            RuntimeFileStage::WriteMigrationEvidenceTemp,
            &error,
        ))
    })?;
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::AbortBeforeFileSync {
        std::process::abort();
    }
    if failpoint == RuntimeCommitFailpoint::BeforeFileSync {
        return Err(rejected_migration_evidence_publish(
            RuntimeFileStage::SyncMigrationEvidenceTemp,
        ));
    }
    fchmod(&temp, READ_ONLY_EVIDENCE_MODE).map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(nix_failure(
            RuntimeFileStage::InspectMigrationEvidence,
            error,
        ))
    })?;
    let metadata = temp.metadata().map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
            RuntimeFileStage::InspectMigrationEvidence,
            &error,
        ))
    })?;
    validate_read_only_evidence_metadata(&metadata, directory.owner_uid, directory.owner_gid)?;
    temp.sync_all().map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
            RuntimeFileStage::SyncMigrationEvidenceTemp,
            &error,
        ))
    })?;
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::AbortAfterFileSync {
        std::process::abort();
    }
    if matches!(
        failpoint,
        RuntimeCommitFailpoint::AfterFileSync | RuntimeCommitFailpoint::BeforeRename
    ) {
        return Err(rejected_migration_evidence_publish(
            RuntimeFileStage::RenameMigrationEvidence,
        ));
    }
    validate_runtime_directory_handle(directory)
        .map_err(RuntimeStoreMigrationError::EvidenceDirectory)?;
    ensure_migration_evidence_missing(directory, name)?;
    publish_migration_evidence_temp(directory, &temp_name, name)?;
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::AbortAfterRename {
        std::process::abort();
    }
    if matches!(
        failpoint,
        RuntimeCommitFailpoint::AfterRename | RuntimeCommitFailpoint::BeforeDirectorySync
    ) {
        return Err(uncertain_migration_evidence_publish(
            RuntimeFileStage::SyncMigrationEvidenceDirectory,
        ));
    }
    directory.file.sync_all().map_err(|error| {
        RuntimeStoreMigrationError::EvidencePublish(RuntimePublishFailure::UncertainAfterPublish(
            RuntimePublishFault::io(RuntimeFileStage::SyncMigrationEvidenceDirectory, &error),
        ))
    })?;
    #[cfg(test)]
    if matches!(
        failpoint,
        RuntimeCommitFailpoint::AbortAfterDirectorySync
            | RuntimeCommitFailpoint::AbortAfterDurableCommitBeforeReturn
    ) {
        std::process::abort();
    }
    if failpoint == RuntimeCommitFailpoint::AfterDirectorySyncBeforeReturn {
        return Err(uncertain_migration_evidence_publish(
            RuntimeFileStage::ReturnMigrationEvidence,
        ));
    }
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::MigrationEvidenceReadBackFailure {
        return Err(uncertain_migration_evidence_publish(
            RuntimeFileStage::ReadBackMigrationEvidence,
        ));
    }
    let read_back =
        read_read_only_migration_evidence(directory, name, bytes.len()).map_err(|_| {
            uncertain_migration_evidence_publish(RuntimeFileStage::ReadBackMigrationEvidence)
        })?;
    if read_back != bytes {
        return Err(uncertain_migration_evidence_publish(
            RuntimeFileStage::ReadBackMigrationEvidence,
        ));
    }
    Ok(())
}

fn publish_migration_evidence_temp(
    directory: &RuntimeDirectory,
    temp_name: &str,
    final_name: &str,
) -> Result<(), RuntimeStoreMigrationError> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        renameat2(
            &directory.file,
            temp_name,
            &directory.file,
            final_name,
            RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(|error| {
            RuntimeStoreMigrationError::EvidenceIo(nix_failure(
                RuntimeFileStage::RenameMigrationEvidence,
                error,
            ))
        })
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        renameat(&directory.file, temp_name, &directory.file, final_name).map_err(|error| {
            RuntimeStoreMigrationError::EvidenceIo(nix_failure(
                RuntimeFileStage::RenameMigrationEvidence,
                error,
            ))
        })
    }
}

fn ensure_migration_evidence_missing(
    directory: &RuntimeDirectory,
    name: &str,
) -> Result<(), RuntimeStoreMigrationError> {
    match openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => {
            drop(file);
            Err(RuntimeStoreMigrationError::EvidenceMismatch)
        }
        Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(error) => Err(RuntimeStoreMigrationError::EvidenceIo(nix_failure(
            RuntimeFileStage::OpenMigrationEvidence,
            error,
        ))),
    }
}

fn read_read_only_migration_evidence(
    directory: &RuntimeDirectory,
    name: &str,
    maximum_length: usize,
) -> Result<Vec<u8>, RuntimeStoreMigrationError> {
    let owned = match openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(nix::errno::Errno::ENOENT) => {
            return Err(RuntimeStoreMigrationError::EvidenceMissing);
        }
        Err(error) => {
            return Err(RuntimeStoreMigrationError::EvidenceIo(nix_failure(
                RuntimeFileStage::OpenMigrationEvidence,
                error,
            )));
        }
    };
    let mut file = File::from(owned);
    let before = file.metadata().map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
            RuntimeFileStage::InspectMigrationEvidence,
            &error,
        ))
    })?;
    validate_read_only_evidence_metadata(&before, directory.owner_uid, directory.owner_gid)?;
    let identity = FileIdentity::from_metadata(&before);
    let length =
        usize::try_from(before.len()).map_err(|_| RuntimeStoreMigrationError::EvidenceTooLarge)?;
    if length == 0 || length > maximum_length {
        return Err(RuntimeStoreMigrationError::EvidenceTooLarge);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| RuntimeStoreMigrationError::EvidenceAllocationFailed)?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes).map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
            RuntimeFileStage::ReadMigrationEvidence,
            &error,
        ))
    })?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing).map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
            RuntimeFileStage::ReadMigrationEvidence,
            &error,
        ))
    })? != 0
    {
        return Err(RuntimeStoreMigrationError::EvidenceChangedDuringRead);
    }
    let after = file.metadata().map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
            RuntimeFileStage::ReadMigrationEvidence,
            &error,
        ))
    })?;
    validate_read_only_evidence_metadata(&after, directory.owner_uid, directory.owner_gid)?;
    if FileIdentity::from_metadata(&after) != identity || after.len() != before.len() {
        return Err(RuntimeStoreMigrationError::EvidenceChangedDuringRead);
    }
    validate_named_read_only_evidence_identity(directory, name, identity)?;
    Ok(bytes)
}

fn validate_read_only_evidence_metadata(
    metadata: &Metadata,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), RuntimeStoreMigrationError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(RuntimeStoreMigrationError::UnsafeEvidenceFile);
    }
    if metadata.uid() != owner_uid || metadata.gid() != owner_gid {
        return Err(RuntimeStoreMigrationError::EvidenceOwnerMismatch);
    }
    if metadata.mode() & PRIVATE_FILE_MODE_MASK != READ_ONLY_EVIDENCE_MODE_BITS {
        return Err(RuntimeStoreMigrationError::UnsafeEvidenceMode);
    }
    Ok(())
}

fn validate_named_read_only_evidence_identity(
    directory: &RuntimeDirectory,
    name: &str,
    expected: FileIdentity,
) -> Result<(), RuntimeStoreMigrationError> {
    let owned = openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(nix_failure(
            RuntimeFileStage::OpenMigrationEvidence,
            error,
        ))
    })?;
    let file = File::from(owned);
    let metadata = file.metadata().map_err(|error| {
        RuntimeStoreMigrationError::EvidenceIo(RuntimeIoFailure::new(
            RuntimeFileStage::InspectMigrationEvidence,
            &error,
        ))
    })?;
    validate_read_only_evidence_metadata(&metadata, directory.owner_uid, directory.owner_gid)?;
    if FileIdentity::from_metadata(&metadata) != expected {
        return Err(RuntimeStoreMigrationError::EvidenceChangedDuringRead);
    }
    Ok(())
}

fn open_runtime_directory(
    path: &Path,
    filesystem_policy: RuntimeFilesystemPolicy,
) -> Result<RuntimeDirectory, RuntimeStoreOpenError> {
    validate_lexical_absolute_path(path)?;
    let owner_uid = geteuid().as_raw();
    let owner_gid = getegid().as_raw();
    validate_runtime_service_identity(owner_uid, owner_gid, filesystem_policy)?;
    validate_trusted_ancestor_chain(path, owner_uid)?;
    let before = fs::symlink_metadata(path).map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
            RuntimeFileStage::InspectDirectory,
            &error,
        ))
    })?;
    validate_directory_metadata(&before, owner_uid, owner_gid)?;
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        RuntimeStoreOpenError::Io(nix_failure(RuntimeFileStage::OpenDirectory, error))
    })?;
    let file = File::from(owned);
    let after = file.metadata().map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
            RuntimeFileStage::OpenDirectory,
            &error,
        ))
    })?;
    validate_directory_metadata(&after, owner_uid, owner_gid)?;
    let identity = FileIdentity::from_metadata(&after);
    if identity != FileIdentity::from_metadata(&before) {
        return Err(RuntimeStoreOpenError::DirectoryIdentityChanged);
    }
    verify_filesystem(&file, filesystem_policy)?;
    Ok(RuntimeDirectory {
        path: path.to_path_buf(),
        file,
        identity,
        owner_uid,
        owner_gid,
    })
}

fn validate_runtime_service_identity(
    owner_uid: u32,
    owner_gid: u32,
    filesystem_policy: RuntimeFilesystemPolicy,
) -> Result<(), RuntimeStoreOpenError> {
    #[cfg(test)]
    if filesystem_policy == RuntimeFilesystemPolicy::ExplicitFixture {
        return Ok(());
    }
    let _ = filesystem_policy;
    if owner_uid == 0 || owner_gid == 0 {
        return Err(RuntimeStoreOpenError::UnsafeServiceIdentity);
    }
    Ok(())
}

/// Proves that no prior Runtime initialization marker or other state exists.
fn ensure_fresh_runtime_directory(
    directory: &RuntimeDirectory,
) -> Result<(), RuntimeStoreOpenError> {
    match openat(
        &directory.file,
        LOCK_FILE_NAME,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(existing) => {
            drop(existing);
            return Err(RuntimeStoreOpenError::InitializerMarkerAlreadyPresent);
        }
        Err(nix::errno::Errno::ENOENT) => {}
        Err(nix::errno::Errno::ELOOP) => {
            return Err(RuntimeStoreOpenError::InitializerMarkerAlreadyPresent);
        }
        Err(error) => {
            return Err(RuntimeStoreOpenError::Io(nix_failure(
                RuntimeFileStage::InspectInitializerMarker,
                error,
            )));
        }
    }
    let mut entries = duplicate_directory_stream(directory)?;
    for entry in entries.iter() {
        let entry = entry.map_err(|error| {
            RuntimeStoreOpenError::Io(nix_failure(RuntimeFileStage::ScanDirectory, error))
        })?;
        if !is_dot_entry(entry.file_name().to_bytes()) {
            return Err(RuntimeStoreOpenError::DirectoryNotFresh);
        }
    }
    Ok(())
}

fn create_and_lock_runtime_initializer_lock(
    directory: &RuntimeDirectory,
) -> Result<(File, FileIdentity), RuntimeInitializerLockFailure> {
    let owned = openat(
        &directory.file,
        LOCK_FILE_NAME,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(|error| {
        let failure = RuntimeStoreOpenError::Io(nix_failure(RuntimeFileStage::CreateLock, error));
        if error == nix::errno::Errno::EEXIST {
            RuntimeInitializerLockFailure::MarkerConsumed(failure)
        } else {
            RuntimeInitializerLockFailure::RejectedBeforeMarker(failure)
        }
    })?;
    let lock_file = File::from(owned);
    // Acquire ownership immediately after O_EXCL creates the marker. Normal
    // Runtime startup can no longer win the lock during marker durability work.
    lock_file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => {
            RuntimeInitializerLockFailure::MarkerConsumed(RuntimeStoreOpenError::LockContended)
        }
        TryLockError::Error(error) => {
            runtime_marker_consumed_io(RuntimeFileStage::AcquireLock, &error)
        }
    })?;
    fchmod(&lock_file, PRIVATE_FILE_MODE)
        .map_err(|error| runtime_marker_consumed_nix(RuntimeFileStage::CreateLock, error))?;
    let lock_metadata = lock_file
        .metadata()
        .map_err(|error| runtime_marker_consumed_io(RuntimeFileStage::CreateLock, &error))?;
    validate_regular_file(&lock_metadata, directory.owner_uid, directory.owner_gid)
        .map_err(RuntimeInitializerLockFailure::MarkerConsumed)?;
    let lock_identity = FileIdentity::from_metadata(&lock_metadata);
    lock_file.sync_all().map_err(|error| {
        runtime_marker_consumed_io(RuntimeFileStage::SyncInitializerMarker, &error)
    })?;
    directory.file.sync_all().map_err(|error| {
        runtime_marker_consumed_io(RuntimeFileStage::SyncInitializerMarkerDirectory, &error)
    })?;
    validate_runtime_initializer_lock_is_only_entry(directory, &lock_file)
        .map_err(RuntimeInitializerLockFailure::MarkerConsumed)?;
    Ok((lock_file, lock_identity))
}

fn runtime_marker_consumed_io(
    stage: RuntimeFileStage,
    error: &io::Error,
) -> RuntimeInitializerLockFailure {
    RuntimeInitializerLockFailure::MarkerConsumed(RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
        stage, error,
    )))
}

fn runtime_marker_consumed_nix(
    stage: RuntimeFileStage,
    error: nix::errno::Errno,
) -> RuntimeInitializerLockFailure {
    RuntimeInitializerLockFailure::MarkerConsumed(RuntimeStoreOpenError::Io(nix_failure(
        stage, error,
    )))
}

fn validate_runtime_initializer_lock_is_only_entry(
    directory: &RuntimeDirectory,
    initializer_lock: &File,
) -> Result<(), RuntimeStoreOpenError> {
    let expected = initializer_lock.metadata().map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
            RuntimeFileStage::ValidateInitializerMarker,
            &error,
        ))
    })?;
    validate_regular_file(&expected, directory.owner_uid, directory.owner_gid)?;
    let installed = open_existing_regular(
        directory,
        LOCK_FILE_NAME,
        OFlag::O_RDONLY,
        RuntimeFileStage::ValidateInitializerMarker,
    )?;
    if FileIdentity::from_metadata(&expected) != installed.identity {
        return Err(RuntimeStoreOpenError::InitializerMarkerIdentityChanged);
    }

    let mut entries = duplicate_directory_stream(directory)?;
    let mut marker_entries = 0_usize;
    for entry in entries.iter() {
        let entry = entry.map_err(|error| {
            RuntimeStoreOpenError::Io(nix_failure(
                RuntimeFileStage::ValidateInitializerMarker,
                error,
            ))
        })?;
        let name = entry.file_name().to_bytes();
        if is_dot_entry(name) {
            continue;
        }
        if name != LOCK_FILE_NAME.as_bytes() {
            return Err(RuntimeStoreOpenError::DirectoryNotFresh);
        }
        marker_entries += 1;
    }
    if marker_entries != 1 {
        return Err(RuntimeStoreOpenError::InitializerMarkerIdentityChanged);
    }
    Ok(())
}

impl RuntimeInitializerGuard {
    pub(crate) fn begin(directory: &Path) -> Result<Self, RuntimeInitializerBeginError> {
        RuntimeInitializerPreflight::open(directory)?.acquire()
    }

    #[cfg(test)]
    pub(crate) fn begin_fixture(directory: &Path) -> Result<Self, RuntimeInitializerBeginError> {
        RuntimeInitializerPreflight::open_fixture(directory)?.acquire()
    }

    fn begin_with_policy(
        path: &Path,
        filesystem_policy: RuntimeFilesystemPolicy,
    ) -> Result<Self, RuntimeInitializerBeginError> {
        RuntimeInitializerPreflight::open_with_policy(path, filesystem_policy)?.acquire()
    }

    pub(crate) fn publish_sequence_one(
        &mut self,
        snapshot: RuntimeJournalSnapshot,
        temp_token: [u8; TEMP_TOKEN_BYTES],
    ) -> Result<(), RuntimeInitializerPublishError> {
        self.publish_sequence_one_with(snapshot, temp_token, RuntimeCommitFailpoint::None)
    }

    fn publish_sequence_one_with(
        &mut self,
        snapshot: RuntimeJournalSnapshot,
        temp_token: [u8; TEMP_TOKEN_BYTES],
        failpoint: RuntimeCommitFailpoint,
    ) -> Result<(), RuntimeInitializerPublishError> {
        if self.state != RuntimeInitializerState::Fresh {
            return Err(RuntimeInitializerPublishError::Stopped);
        }
        if snapshot.sequence() != 1 {
            return Err(RuntimeInitializerPublishError::NotSequenceOne);
        }
        if validate_runtime_directory_handle(&self.directory).is_err()
            || validate_held_lock(&self.directory, &self.lock_file, self.lock_identity).is_err()
            || validate_runtime_initializer_lock_is_only_entry(&self.directory, &self.lock_file)
                .is_err()
        {
            self.state = RuntimeInitializerState::Stopped;
            return Err(RuntimeInitializerPublishError::LockOrDirectoryIdentityChanged);
        }
        if let Err(error) = publish_atomic(
            &self.directory,
            snapshot.canonical_wire(),
            RuntimePublishMode::RequireMissing,
            temp_token,
            failpoint,
        ) {
            self.state = RuntimeInitializerState::Stopped;
            return Err(RuntimeInitializerPublishError::Publish(error));
        }
        let read_back = read_active_snapshot(&self.directory).map_err(|error| {
            self.state = RuntimeInitializerState::Stopped;
            RuntimeInitializerPublishError::PublishedButUnverified(error)
        })?;
        if read_back.snapshot != snapshot {
            self.state = RuntimeInitializerState::Stopped;
            return Err(RuntimeInitializerPublishError::PublishedSnapshotMismatch);
        }
        self.state = RuntimeInitializerState::Published;
        Ok(())
    }
}

impl RuntimeInitializerPreflight {
    pub(crate) fn open(path: &Path) -> Result<Self, RuntimeInitializerBeginError> {
        Self::open_with_policy(path, RuntimeFilesystemPolicy::ProductionReference)
    }

    #[cfg(test)]
    pub(crate) fn open_fixture(path: &Path) -> Result<Self, RuntimeInitializerBeginError> {
        Self::open_with_policy(path, RuntimeFilesystemPolicy::ExplicitFixture)
    }

    fn open_with_policy(
        path: &Path,
        filesystem_policy: RuntimeFilesystemPolicy,
    ) -> Result<Self, RuntimeInitializerBeginError> {
        let directory = open_runtime_directory(path, filesystem_policy)
            .map_err(RuntimeInitializerBeginError::Store)?;
        match ensure_fresh_runtime_directory(&directory) {
            Ok(()) => {}
            Err(error @ RuntimeStoreOpenError::InitializerMarkerAlreadyPresent) => {
                return Err(RuntimeInitializerBeginError::MarkerConsumed(error));
            }
            Err(error) => return Err(RuntimeInitializerBeginError::Store(error)),
        }
        Ok(Self { directory })
    }

    pub(crate) fn acquire(self) -> Result<RuntimeInitializerGuard, RuntimeInitializerBeginError> {
        let Self { directory } = self;
        let (lock_file, lock_identity) = match create_and_lock_runtime_initializer_lock(&directory)
        {
            Ok(lock) => lock,
            Err(RuntimeInitializerLockFailure::RejectedBeforeMarker(error)) => {
                return Err(RuntimeInitializerBeginError::Store(error));
            }
            Err(RuntimeInitializerLockFailure::MarkerConsumed(error)) => {
                return Err(RuntimeInitializerBeginError::MarkerConsumed(error));
            }
        };
        Ok(RuntimeInitializerGuard {
            directory,
            lock_file,
            lock_identity,
            state: RuntimeInitializerState::Fresh,
        })
    }
}

fn validate_runtime_directory_handle(
    directory: &RuntimeDirectory,
) -> Result<(), RuntimeStoreOpenError> {
    let metadata = directory.file.metadata().map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
            RuntimeFileStage::ValidateDirectoryIdentity,
            &error,
        ))
    })?;
    validate_directory_metadata(&metadata, directory.owner_uid, directory.owner_gid)?;
    if FileIdentity::from_metadata(&metadata) != directory.identity {
        return Err(RuntimeStoreOpenError::DirectoryIdentityChanged);
    }
    Ok(())
}

fn validate_directory_metadata(
    metadata: &Metadata,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), RuntimeStoreOpenError> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() || metadata.nlink() == 0
    {
        return Err(RuntimeStoreOpenError::UnsafeDirectoryType);
    }
    if metadata.uid() != owner_uid || metadata.gid() != owner_gid {
        return Err(RuntimeStoreOpenError::DirectoryOwnerMismatch);
    }
    if metadata.mode() & STATE_DIRECTORY_MODE_MASK != STATE_DIRECTORY_MODE_BITS {
        return Err(RuntimeStoreOpenError::UnsafeDirectoryMode);
    }
    Ok(())
}

fn validate_lexical_absolute_path(path: &Path) -> Result<(), RuntimeStoreOpenError> {
    if !path.is_absolute() {
        return Err(RuntimeStoreOpenError::PathMustBeAbsolute);
    }
    for component in path.components() {
        if matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::Prefix(_)
        ) {
            return Err(RuntimeStoreOpenError::UnsafeDirectoryPath);
        }
    }
    Ok(())
}

fn validate_trusted_ancestor_chain(
    path: &Path,
    owner_uid: u32,
) -> Result<(), RuntimeStoreOpenError> {
    let parent = path
        .parent()
        .ok_or(RuntimeStoreOpenError::UnsafeDirectoryPath)?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => current.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(RuntimeStoreOpenError::UnsafeDirectoryPath);
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
                RuntimeFileStage::InspectAncestor,
                &error,
            ))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || metadata.nlink() == 0
        {
            return Err(RuntimeStoreOpenError::UnsafeAncestorType);
        }
        let mode = metadata.mode() & STATE_DIRECTORY_MODE_MASK;
        let root_owned_sticky = metadata.uid() == 0 && mode & 0o1000 != 0;
        let owner_is_trusted = metadata.uid() == 0 || metadata.uid() == owner_uid;
        if !owner_is_trusted || (mode & 0o022 != 0 && !root_owned_sticky) {
            return Err(RuntimeStoreOpenError::UntrustedAncestor);
        }
    }
    Ok(())
}

fn open_existing_regular(
    directory: &RuntimeDirectory,
    name: &str,
    access: OFlag,
    stage: RuntimeFileStage,
) -> Result<OpenedRegularFile, RuntimeStoreOpenError> {
    let owned = openat(
        &directory.file,
        name,
        access | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| RuntimeStoreOpenError::Io(nix_failure(stage, error)))?;
    let file = File::from(owned);
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeStoreOpenError::Io(RuntimeIoFailure::new(stage, &error)))?;
    validate_regular_file(&metadata, directory.owner_uid, directory.owner_gid)?;
    Ok(OpenedRegularFile {
        file,
        identity: FileIdentity::from_metadata(&metadata),
    })
}

fn validate_regular_file(
    metadata: &Metadata,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), RuntimeStoreOpenError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(RuntimeStoreOpenError::UnsafeFileType);
    }
    if metadata.uid() != owner_uid || metadata.gid() != owner_gid {
        return Err(RuntimeStoreOpenError::FileOwnerMismatch);
    }
    if metadata.mode() & PRIVATE_FILE_MODE_MASK != PRIVATE_FILE_MODE_BITS {
        return Err(RuntimeStoreOpenError::UnsafeFileMode);
    }
    Ok(())
}

fn validate_named_file_identity(
    directory: &RuntimeDirectory,
    name: &str,
    expected: FileIdentity,
    stage: RuntimeFileStage,
) -> Result<(), RuntimeStoreOpenError> {
    let current = open_existing_regular(directory, name, OFlag::O_RDONLY, stage)?;
    if current.identity != expected {
        return Err(RuntimeStoreOpenError::NamedFileIdentityChanged);
    }
    Ok(())
}

fn validate_held_lock(
    directory: &RuntimeDirectory,
    lock_file: &File,
    expected: FileIdentity,
) -> Result<(), RuntimeStoreOpenError> {
    let metadata = lock_file.metadata().map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
            RuntimeFileStage::ValidateLockIdentity,
            &error,
        ))
    })?;
    validate_regular_file(&metadata, directory.owner_uid, directory.owner_gid)?;
    if FileIdentity::from_metadata(&metadata) != expected {
        return Err(RuntimeStoreOpenError::NamedFileIdentityChanged);
    }
    validate_named_file_identity(
        directory,
        LOCK_FILE_NAME,
        expected,
        RuntimeFileStage::ValidateLockIdentity,
    )
}

fn read_active_snapshot(
    directory: &RuntimeDirectory,
) -> Result<ActiveSnapshot, RuntimeStoreOpenError> {
    let ActiveSnapshotBytes { encoded, identity } = read_active_snapshot_bytes(directory)?;
    let snapshot =
        RuntimeJournalSnapshot::decode(&encoded).map_err(RuntimeStoreOpenError::Journal)?;
    if snapshot.canonical_wire() != encoded {
        return Err(RuntimeStoreOpenError::Journal(
            RuntimeJournalError::NonCanonicalEncoding,
        ));
    }
    Ok(ActiveSnapshot { snapshot, identity })
}

fn read_active_snapshot_bytes(
    directory: &RuntimeDirectory,
) -> Result<ActiveSnapshotBytes, RuntimeStoreOpenError> {
    let OpenedRegularFile { mut file, identity } = open_existing_regular(
        directory,
        ACTIVE_FILE_NAME,
        OFlag::O_RDONLY,
        RuntimeFileStage::OpenActive,
    )?;
    let before = file.metadata().map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(RuntimeFileStage::ReadActive, &error))
    })?;
    let length =
        usize::try_from(before.len()).map_err(|_| RuntimeStoreOpenError::ActiveTooLarge)?;
    if length == 0 {
        return Err(RuntimeStoreOpenError::ActiveEmpty);
    }
    if length > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES {
        return Err(RuntimeStoreOpenError::ActiveTooLarge);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| RuntimeStoreOpenError::ActiveAllocationFailed)?;
    encoded.resize(length, 0);
    file.read_exact(&mut encoded).map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(RuntimeFileStage::ReadActive, &error))
    })?;
    let mut trailing = [0; 1];
    if file.read(&mut trailing).map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(RuntimeFileStage::ReadActive, &error))
    })? != 0
    {
        return Err(RuntimeStoreOpenError::ActiveChangedDuringRead);
    }
    let after = file.metadata().map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(RuntimeFileStage::ReadActive, &error))
    })?;
    validate_regular_file(&after, directory.owner_uid, directory.owner_gid)?;
    if FileIdentity::from_metadata(&after) != identity || after.len() != before.len() {
        return Err(RuntimeStoreOpenError::ActiveChangedDuringRead);
    }
    validate_named_file_identity(
        directory,
        ACTIVE_FILE_NAME,
        identity,
        RuntimeFileStage::ValidateActiveIdentity,
    )?;
    Ok(ActiveSnapshotBytes { encoded, identity })
}

fn clean_valid_orphan_temps(directory: &RuntimeDirectory) -> Result<(), RuntimeStoreOpenError> {
    let mut entries = duplicate_directory_stream(directory)?;
    let mut orphan_names = Vec::new();
    for entry in entries.iter() {
        let entry = entry.map_err(|error| {
            RuntimeStoreOpenError::Io(nix_failure(RuntimeFileStage::ScanDirectory, error))
        })?;
        let name_bytes = entry.file_name().to_bytes();
        if is_dot_entry(name_bytes) {
            continue;
        }
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| RuntimeStoreOpenError::UnknownDirectoryEntry)?;
        if name == LOCK_FILE_NAME || name == ACTIVE_FILE_NAME {
            continue;
        }
        if !valid_temp_name(name) {
            return Err(RuntimeStoreOpenError::UnknownDirectoryEntry);
        }
        orphan_names.push(name.to_owned());
        if orphan_names.len() > MAX_ORPHAN_TEMP_FILES {
            return Err(RuntimeStoreOpenError::TooManyOrphanTemps);
        }
    }

    for name in orphan_names {
        let orphan = open_existing_regular(
            directory,
            &name,
            OFlag::O_RDONLY,
            RuntimeFileStage::InspectOrphanTemp,
        )?;
        validate_named_file_identity(
            directory,
            &name,
            orphan.identity,
            RuntimeFileStage::InspectOrphanTemp,
        )?;
        unlinkat(&directory.file, name.as_str(), UnlinkatFlags::NoRemoveDir).map_err(|error| {
            RuntimeStoreOpenError::Io(nix_failure(RuntimeFileStage::RemoveOrphanTemp, error))
        })?;
        let metadata = orphan.file.metadata().map_err(|error| {
            RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
                RuntimeFileStage::RemoveOrphanTemp,
                &error,
            ))
        })?;
        if metadata.nlink() != 0 {
            return Err(RuntimeStoreOpenError::NamedFileIdentityChanged);
        }
    }
    directory.file.sync_all().map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
            RuntimeFileStage::SyncOrphanCleanup,
            &error,
        ))
    })
}

fn duplicate_directory_stream(directory: &RuntimeDirectory) -> Result<Dir, RuntimeStoreOpenError> {
    let duplicate = directory.file.try_clone().map_err(|error| {
        RuntimeStoreOpenError::Io(RuntimeIoFailure::new(
            RuntimeFileStage::ScanDirectory,
            &error,
        ))
    })?;
    let descriptor: OwnedFd = duplicate.into();
    Dir::from_fd(descriptor).map_err(|error| {
        RuntimeStoreOpenError::Io(nix_failure(RuntimeFileStage::ScanDirectory, error))
    })
}

fn is_dot_entry(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

fn publish_atomic(
    directory: &RuntimeDirectory,
    encoded: &[u8],
    mode: RuntimePublishMode,
    token: [u8; TEMP_TOKEN_BYTES],
    failpoint: RuntimeCommitFailpoint,
) -> Result<(), RuntimePublishFailure> {
    if encoded.is_empty() || encoded.len() > MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES {
        return Err(rejected_injected(RuntimeFileStage::ValidateEncodedSnapshot));
    }
    if failpoint == RuntimeCommitFailpoint::BeforeTempCreate {
        return Err(rejected_injected(RuntimeFileStage::CreateTemp));
    }
    validate_runtime_publish_precondition(directory, mode)?;

    let temp_name = temp_name(token);
    let owned = openat(
        &directory.file,
        temp_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(|error| {
        RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::nix(
            RuntimeFileStage::CreateTemp,
            error,
        ))
    })?;
    let mut temp = File::from(owned);
    fchmod(&temp, PRIVATE_FILE_MODE).map_err(|error| {
        RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::nix(
            RuntimeFileStage::InspectTemp,
            error,
        ))
    })?;
    let temp_metadata = temp.metadata().map_err(|error| {
        RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::io(
            RuntimeFileStage::InspectTemp,
            &error,
        ))
    })?;
    validate_regular_file(&temp_metadata, directory.owner_uid, directory.owner_gid)
        .map_err(|error| rejected_open_error(RuntimeFileStage::InspectTemp, error))?;
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::AbortAfterTempCreate {
        std::process::abort();
    }
    if failpoint == RuntimeCommitFailpoint::AfterTempCreate {
        return Err(rejected_injected(RuntimeFileStage::CreateTemp));
    }
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::AbortAfterPartialWrite {
        let partial_length = encoded.len().saturating_sub(1).max(1);
        temp.write_all(&encoded[..partial_length])
            .map_err(|error| {
                RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::io(
                    RuntimeFileStage::WriteTemp,
                    &error,
                ))
            })?;
        std::process::abort();
    }
    if failpoint == RuntimeCommitFailpoint::AfterPartialWrite {
        let partial_length = encoded.len().saturating_sub(1).max(1);
        temp.write_all(&encoded[..partial_length])
            .map_err(|error| {
                RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::io(
                    RuntimeFileStage::WriteTemp,
                    &error,
                ))
            })?;
        return Err(rejected_injected(RuntimeFileStage::WriteTemp));
    }
    temp.write_all(encoded).map_err(|error| {
        RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::io(
            RuntimeFileStage::WriteTemp,
            &error,
        ))
    })?;
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::AbortBeforeFileSync {
        std::process::abort();
    }
    if failpoint == RuntimeCommitFailpoint::BeforeFileSync {
        return Err(rejected_injected(RuntimeFileStage::SyncTemp));
    }
    temp.sync_all().map_err(|error| {
        RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::io(
            RuntimeFileStage::SyncTemp,
            &error,
        ))
    })?;
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::AbortAfterFileSync {
        std::process::abort();
    }
    if matches!(
        failpoint,
        RuntimeCommitFailpoint::AfterFileSync | RuntimeCommitFailpoint::BeforeRename
    ) {
        return Err(rejected_injected(RuntimeFileStage::Rename));
    }
    validate_runtime_publish_precondition(directory, mode)?;
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::InstallCompetingActiveBeforeRename {
        if mode != RuntimePublishMode::RequireMissing {
            return Err(rejected_injected(RuntimeFileStage::RequireMissingActive));
        }
        install_competing_active_for_test(directory)?;
    }
    publish_temp_name(directory, temp_name.as_str(), mode)?;
    #[cfg(test)]
    if failpoint == RuntimeCommitFailpoint::AbortAfterRename {
        std::process::abort();
    }
    if matches!(
        failpoint,
        RuntimeCommitFailpoint::AfterRename | RuntimeCommitFailpoint::BeforeDirectorySync
    ) {
        return Err(uncertain_injected(RuntimeFileStage::SyncDirectory));
    }
    directory.file.sync_all().map_err(|error| {
        RuntimePublishFailure::UncertainAfterPublish(RuntimePublishFault::io(
            RuntimeFileStage::SyncDirectory,
            &error,
        ))
    })?;
    #[cfg(test)]
    if matches!(
        failpoint,
        RuntimeCommitFailpoint::AbortAfterDirectorySync
            | RuntimeCommitFailpoint::AbortAfterDurableCommitBeforeReturn
    ) {
        std::process::abort();
    }
    if failpoint == RuntimeCommitFailpoint::AfterDirectorySyncBeforeReturn {
        return Err(uncertain_injected(RuntimeFileStage::ReturnDurableCommit));
    }
    Ok(())
}

fn publish_temp_name(
    directory: &RuntimeDirectory,
    temp_name: &str,
    mode: RuntimePublishMode,
) -> Result<(), RuntimePublishFailure> {
    match mode {
        RuntimePublishMode::RequireMissing => {
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            {
                // The precondition check is diagnostic only. RENAME_NOREPLACE
                // is the operation that makes a concurrent active install
                // impossible at the actual publication boundary.
                renameat2(
                    &directory.file,
                    temp_name,
                    &directory.file,
                    ACTIVE_FILE_NAME,
                    RenameFlags::RENAME_NOREPLACE,
                )
                .map_err(|error| {
                    RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::nix(
                        RuntimeFileStage::RequireMissingActive,
                        error,
                    ))
                })
            }
            #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
            {
                // Non-Linux production filesystems are rejected before this
                // point. This fallback exists only so explicit test fixtures
                // can exercise the rest of the transaction on development
                // hosts while PC1/PC2 remain unadmitted.
                renameat(
                    &directory.file,
                    temp_name,
                    &directory.file,
                    ACTIVE_FILE_NAME,
                )
                .map_err(|error| {
                    RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::nix(
                        RuntimeFileStage::Rename,
                        error,
                    ))
                })
            }
        }
        RuntimePublishMode::ReplaceExisting(_) => renameat(
            &directory.file,
            temp_name,
            &directory.file,
            ACTIVE_FILE_NAME,
        )
        .map_err(|error| {
            RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::nix(
                RuntimeFileStage::Rename,
                error,
            ))
        }),
    }
}

#[cfg(test)]
fn install_competing_active_for_test(
    directory: &RuntimeDirectory,
) -> Result<(), RuntimePublishFailure> {
    let owned = openat(
        &directory.file,
        ACTIVE_FILE_NAME,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(|error| {
        RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::nix(
            RuntimeFileStage::RequireMissingActive,
            error,
        ))
    })?;
    let mut active = File::from(owned);
    active.write_all(b"competing-active").map_err(|error| {
        RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::io(
            RuntimeFileStage::RequireMissingActive,
            &error,
        ))
    })?;
    active.sync_all().map_err(|error| {
        RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::io(
            RuntimeFileStage::RequireMissingActive,
            &error,
        ))
    })?;
    directory.file.sync_all().map_err(|error| {
        RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::io(
            RuntimeFileStage::RequireMissingActive,
            &error,
        ))
    })
}

fn validate_runtime_publish_precondition(
    directory: &RuntimeDirectory,
    mode: RuntimePublishMode,
) -> Result<(), RuntimePublishFailure> {
    match mode {
        RuntimePublishMode::RequireMissing => ensure_runtime_active_missing(directory),
        RuntimePublishMode::ReplaceExisting(expected_active_identity) => {
            validate_named_file_identity(
                directory,
                ACTIVE_FILE_NAME,
                expected_active_identity,
                RuntimeFileStage::ValidateActiveIdentity,
            )
            .map_err(|error| rejected_open_error(RuntimeFileStage::ValidateActiveIdentity, error))
        }
    }
}

fn ensure_runtime_active_missing(
    directory: &RuntimeDirectory,
) -> Result<(), RuntimePublishFailure> {
    match openat(
        &directory.file,
        ACTIVE_FILE_NAME,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(active) => {
            drop(active);
            Err(rejected_injected(RuntimeFileStage::RequireMissingActive))
        }
        Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(error) => Err(RuntimePublishFailure::RejectedBeforePublish(
            RuntimePublishFault::nix(RuntimeFileStage::RequireMissingActive, error),
        )),
    }
}

fn system_random_token() -> Result<[u8; TEMP_TOKEN_BYTES], io::Error> {
    let owned = open(
        Path::new("/dev/urandom"),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(errno_to_io)?;
    let mut random = File::from(owned);
    let mut token = [0; TEMP_TOKEN_BYTES];
    random.read_exact(&mut token)?;
    if token.iter().all(|byte| *byte == 0) {
        return Err(io::Error::other(
            "CSPRNG returned an all-zero Runtime temporary token",
        ));
    }
    Ok(token)
}

fn temp_name(token: [u8; TEMP_TOKEN_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(TEMP_FILE_PREFIX.len() + TEMP_HEX_BYTES);
    name.push_str(TEMP_FILE_PREFIX);
    for byte in token {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

fn valid_temp_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(TEMP_FILE_PREFIX) else {
        return false;
    };
    suffix.len() == TEMP_HEX_BYTES
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_filesystem(
    directory: &File,
    _policy: RuntimeFilesystemPolicy,
) -> Result<(), RuntimeStoreOpenError> {
    #[cfg(test)]
    if _policy == RuntimeFilesystemPolicy::ExplicitFixture {
        return Ok(());
    }
    let stat = nix::sys::statfs::fstatfs(directory).map_err(|error| {
        RuntimeStoreOpenError::Io(nix_failure(RuntimeFileStage::InspectFilesystem, error))
    })?;
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        if stat.filesystem_type() != nix::sys::statfs::EXT4_SUPER_MAGIC {
            return Err(RuntimeStoreOpenError::UnsupportedFilesystem);
        }
        verify_linux_ext4_mount(directory).map_err(|_| RuntimeStoreOpenError::UnsupportedFilesystem)
    }
    #[cfg(all(target_os = "linux", not(target_env = "gnu")))]
    {
        // nix exposes the reviewed renameat2 no-replace wrapper only for the
        // GNU Linux target. Other libc profiles stay fail-closed until PC0
        // admits an equally exact backend.
        let _ = stat;
        Err(RuntimeStoreOpenError::UnsupportedFilesystem)
    }
    #[cfg(target_os = "macos")]
    {
        // APFS mode bits do not prove the absence of extended ACL entries,
        // and this workspace forbids an unreviewed unsafe acl_get_fd_np
        // wrapper. PC1 must admit an FD-anchored ACL and crash-durability
        // backend before the macOS production profile can be enabled.
        let _ = stat;
        Err(RuntimeStoreOpenError::UnsupportedFilesystem)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stat;
        Err(RuntimeStoreOpenError::UnsupportedFilesystem)
    }
}

#[cfg(target_os = "linux")]
fn verify_linux_ext4_mount(directory: &File) -> Result<(), LinuxMountEvidenceError> {
    let fdinfo_path = PathBuf::from(format!("/proc/self/fdinfo/{}", directory.as_raw_fd()));
    let fdinfo = read_bounded_linux_proc_file(&fdinfo_path, MAX_LINUX_FDINFO_BYTES)?;
    let mount_id = parse_linux_fdinfo_mount_id(&fdinfo)?;
    let mountinfo =
        read_bounded_linux_proc_file(Path::new("/proc/self/mountinfo"), MAX_LINUX_MOUNTINFO_BYTES)?;
    parse_linux_mountinfo_exact_ext4(&mountinfo, mount_id)
}

#[cfg(target_os = "linux")]
fn read_bounded_linux_proc_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, LinuxMountEvidenceError> {
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| LinuxMountEvidenceError::Io(errno_to_io(error).kind()))?;
    let mut source = File::from(owned);
    let capacity = maximum
        .checked_add(1)
        .ok_or(LinuxMountEvidenceError::EvidenceTooLarge)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| LinuxMountEvidenceError::AllocationFailed)?;
    let mut chunk = [0_u8; 4_096];
    loop {
        let remaining = capacity.saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(LinuxMountEvidenceError::EvidenceTooLarge);
        }
        let read_bound = remaining.min(chunk.len());
        let read = source
            .read(&mut chunk[..read_bound])
            .map_err(|error| LinuxMountEvidenceError::Io(error.kind()))?;
        if read == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > maximum {
            return Err(LinuxMountEvidenceError::EvidenceTooLarge);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxMountEvidenceError {
    Io(io::ErrorKind),
    AllocationFailed,
    EvidenceTooLarge,
    TooManyRecords,
    LineTooLong,
    MalformedFdInfo,
    MissingMountId,
    DuplicateMountId,
    MalformedMountInfo,
    MissingMountRecord,
    DuplicateMountRecord,
    UnexpectedFilesystemType,
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_fdinfo_mount_id(bytes: &[u8]) -> Result<u64, LinuxMountEvidenceError> {
    if bytes.is_empty() || bytes.len() > MAX_LINUX_FDINFO_BYTES || !bytes.ends_with(b"\n") {
        return Err(if bytes.len() > MAX_LINUX_FDINFO_BYTES {
            LinuxMountEvidenceError::EvidenceTooLarge
        } else {
            LinuxMountEvidenceError::MalformedFdInfo
        });
    }
    let mut record_count = 0_usize;
    let mut mount_id = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        record_count = record_count
            .checked_add(1)
            .ok_or(LinuxMountEvidenceError::TooManyRecords)?;
        if record_count > MAX_LINUX_FDINFO_RECORDS {
            return Err(LinuxMountEvidenceError::TooManyRecords);
        }
        if line.is_empty() {
            return Err(LinuxMountEvidenceError::MalformedFdInfo);
        }
        if line.len() > MAX_LINUX_FDINFO_LINE_BYTES {
            return Err(LinuxMountEvidenceError::LineTooLong);
        }
        let Some(value) = line.strip_prefix(b"mnt_id:") else {
            continue;
        };
        let parsed = parse_positive_decimal(trim_horizontal_ascii(value))
            .ok_or(LinuxMountEvidenceError::MalformedFdInfo)?;
        if mount_id.replace(parsed).is_some() {
            return Err(LinuxMountEvidenceError::DuplicateMountId);
        }
    }
    mount_id.ok_or(LinuxMountEvidenceError::MissingMountId)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_mountinfo_exact_ext4(
    bytes: &[u8],
    expected_mount_id: u64,
) -> Result<(), LinuxMountEvidenceError> {
    if bytes.len() > MAX_LINUX_MOUNTINFO_BYTES {
        return Err(LinuxMountEvidenceError::EvidenceTooLarge);
    }
    if expected_mount_id == 0 || bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err(LinuxMountEvidenceError::MalformedMountInfo);
    }
    let mut record_count = 0_usize;
    let mut matched_ext4 = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        record_count = record_count
            .checked_add(1)
            .ok_or(LinuxMountEvidenceError::TooManyRecords)?;
        if record_count > MAX_LINUX_MOUNTINFO_RECORDS {
            return Err(LinuxMountEvidenceError::TooManyRecords);
        }
        if line.is_empty() {
            return Err(LinuxMountEvidenceError::MalformedMountInfo);
        }
        if line.len() > MAX_LINUX_MOUNTINFO_LINE_BYTES {
            return Err(LinuxMountEvidenceError::LineTooLong);
        }
        let mut fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty());
        let mount_id = parse_positive_decimal(
            fields
                .next()
                .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?,
        )
        .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?;
        parse_positive_decimal(
            fields
                .next()
                .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?,
        )
        .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?;
        parse_linux_device_number(
            fields
                .next()
                .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?,
        )?;
        for _ in 0..3 {
            if fields.next().is_none_or(|required| required.is_empty()) {
                return Err(LinuxMountEvidenceError::MalformedMountInfo);
            }
        }
        let filesystem_type = loop {
            let field = fields
                .next()
                .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?;
            if field == b"-" {
                break fields
                    .next()
                    .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?;
            }
        };
        let mount_source = fields
            .next()
            .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?;
        let super_options = fields
            .next()
            .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?;
        if filesystem_type.is_empty()
            || mount_source.is_empty()
            || super_options.is_empty()
            || fields.next().is_some()
        {
            return Err(LinuxMountEvidenceError::MalformedMountInfo);
        }
        if mount_id == expected_mount_id
            && matched_ext4.replace(filesystem_type == b"ext4").is_some()
        {
            return Err(LinuxMountEvidenceError::DuplicateMountRecord);
        }
    }
    match matched_ext4 {
        Some(true) => Ok(()),
        Some(false) => Err(LinuxMountEvidenceError::UnexpectedFilesystemType),
        None => Err(LinuxMountEvidenceError::MissingMountRecord),
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_device_number(bytes: &[u8]) -> Result<(), LinuxMountEvidenceError> {
    let mut parts = bytes.split(|byte| *byte == b':');
    let major = parts
        .next()
        .and_then(parse_decimal)
        .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?;
    let minor = parts
        .next()
        .and_then(parse_decimal)
        .ok_or(LinuxMountEvidenceError::MalformedMountInfo)?;
    if parts.next().is_some() {
        return Err(LinuxMountEvidenceError::MalformedMountInfo);
    }
    let _ = (major, minor);
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn parse_positive_decimal(bytes: &[u8]) -> Option<u64> {
    let value = parse_decimal(bytes)?;
    (value != 0).then_some(value)
}

#[cfg(any(target_os = "linux", test))]
fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
    })
}

#[cfg(any(target_os = "linux", test))]
fn trim_horizontal_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        bytes = &bytes[1..];
    }
    while bytes
        .last()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn rejected_open_error(
    stage: RuntimeFileStage,
    error: RuntimeStoreOpenError,
) -> RuntimePublishFailure {
    match error {
        RuntimeStoreOpenError::Io(failure) => {
            RuntimePublishFailure::RejectedBeforePublish(failure.into())
        }
        _ => RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::injected(stage)),
    }
}

fn publish_fault_from_open(
    stage: RuntimeFileStage,
    error: RuntimeStoreOpenError,
) -> RuntimePublishFault {
    match error {
        RuntimeStoreOpenError::Io(failure) => failure.into(),
        _ => RuntimePublishFault::injected(stage),
    }
}

fn rejected_injected(stage: RuntimeFileStage) -> RuntimePublishFailure {
    RuntimePublishFailure::RejectedBeforePublish(RuntimePublishFault::injected(stage))
}

fn uncertain_injected(stage: RuntimeFileStage) -> RuntimePublishFailure {
    RuntimePublishFailure::UncertainAfterPublish(RuntimePublishFault::injected(stage))
}

fn rejected_migration_evidence_publish(stage: RuntimeFileStage) -> RuntimeStoreMigrationError {
    RuntimeStoreMigrationError::EvidencePublish(rejected_injected(stage))
}

fn uncertain_migration_evidence_publish(stage: RuntimeFileStage) -> RuntimeStoreMigrationError {
    RuntimeStoreMigrationError::EvidencePublish(uncertain_injected(stage))
}

fn published_but_unverified(stage: RuntimeFileStage) -> RuntimeStoreMigrationError {
    RuntimeStoreMigrationError::PublishedButUnverified(stage)
}

fn nix_failure(stage: RuntimeFileStage, error: nix::errno::Errno) -> RuntimeIoFailure {
    RuntimeIoFailure::new(stage, &errno_to_io(error))
}

fn errno_to_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeCommitFailpoint {
    None,
    BeforeTempCreate,
    AfterTempCreate,
    AfterPartialWrite,
    BeforeFileSync,
    AfterFileSync,
    BeforeRename,
    #[cfg(test)]
    InstallCompetingActiveBeforeRename,
    AfterRename,
    BeforeDirectorySync,
    AfterDirectorySyncBeforeReturn,
    #[cfg(test)]
    AbortAfterTempCreate,
    #[cfg(test)]
    AbortAfterPartialWrite,
    #[cfg(test)]
    AbortBeforeFileSync,
    #[cfg(test)]
    AbortAfterFileSync,
    #[cfg(test)]
    AbortAfterRename,
    #[cfg(test)]
    AbortAfterDirectorySync,
    #[cfg(test)]
    AbortAfterDurableCommitBeforeReturn,
    #[cfg(test)]
    MigrationEvidenceReadBackFailure,
    #[cfg(test)]
    MigrationActiveReadBackFailure,
    #[cfg(test)]
    MigrationPostPublishEvidenceFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeFileStage {
    InspectAncestor,
    InspectDirectory,
    OpenDirectory,
    ValidateDirectoryIdentity,
    InspectFilesystem,
    ScanDirectory,
    OpenLock,
    CreateLock,
    AcquireLock,
    ValidateLockIdentity,
    InspectInitializerMarker,
    ValidateInitializerMarker,
    SyncInitializerMarker,
    SyncInitializerMarkerDirectory,
    OpenActive,
    ReadActive,
    ValidateActiveIdentity,
    InspectOrphanTemp,
    RemoveOrphanTemp,
    SyncOrphanCleanup,
    GenerateMigrationEvidenceTempName,
    OpenMigrationEvidence,
    CreateMigrationEvidenceTemp,
    InspectMigrationEvidence,
    ReadMigrationEvidence,
    WriteMigrationEvidenceTemp,
    SyncMigrationEvidenceTemp,
    RenameMigrationEvidence,
    SyncMigrationEvidenceDirectory,
    ReturnMigrationEvidence,
    ReadBackMigrationEvidence,
    VerifyPublishedMigration,
    GenerateTempName,
    ValidateEncodedSnapshot,
    RequireMissingActive,
    CreateTemp,
    InspectTemp,
    WriteTemp,
    SyncTemp,
    Rename,
    SyncDirectory,
    ReadBackPublished,
    ReturnDurableCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeIoFailure {
    pub(crate) stage: RuntimeFileStage,
    pub(crate) kind: io::ErrorKind,
}

impl RuntimeIoFailure {
    fn new(stage: RuntimeFileStage, error: &io::Error) -> Self {
        Self {
            stage,
            kind: error.kind(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimePublishFault {
    pub(crate) stage: RuntimeFileStage,
    pub(crate) kind: Option<io::ErrorKind>,
}

impl RuntimePublishFault {
    fn injected(stage: RuntimeFileStage) -> Self {
        Self { stage, kind: None }
    }

    fn io(stage: RuntimeFileStage, error: &io::Error) -> Self {
        Self {
            stage,
            kind: Some(error.kind()),
        }
    }

    fn nix(stage: RuntimeFileStage, error: nix::errno::Errno) -> Self {
        Self::io(stage, &errno_to_io(error))
    }
}

impl From<RuntimeIoFailure> for RuntimePublishFault {
    fn from(value: RuntimeIoFailure) -> Self {
        Self {
            stage: value.stage,
            kind: Some(value.kind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimePublishFailure {
    RejectedBeforePublish(RuntimePublishFault),
    UncertainAfterPublish(RuntimePublishFault),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeInitializerLockFailure {
    RejectedBeforeMarker(RuntimeStoreOpenError),
    MarkerConsumed(RuntimeStoreOpenError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeInitializerBeginError {
    Store(RuntimeStoreOpenError),
    MarkerConsumed(RuntimeStoreOpenError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeInitializerPublishError {
    Stopped,
    NotSequenceOne,
    LockOrDirectoryIdentityChanged,
    Publish(RuntimePublishFailure),
    PublishedButUnverified(RuntimeStoreOpenError),
    PublishedSnapshotMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeStoreOpenError {
    InvalidExpectedStoreInstanceId,
    InvalidExpectedTargetFingerprint,
    UnsafeServiceIdentity,
    PathMustBeAbsolute,
    UnsafeDirectoryPath,
    UnsafeAncestorType,
    UntrustedAncestor,
    UnsafeDirectoryType,
    UnsafeDirectoryMode,
    DirectoryOwnerMismatch,
    DirectoryIdentityChanged,
    UnsupportedFilesystem,
    UnsafeFileType,
    UnsafeFileMode,
    FileOwnerMismatch,
    NamedFileIdentityChanged,
    DirectoryNotFresh,
    InitializerMarkerAlreadyPresent,
    InitializerMarkerIdentityChanged,
    UnknownDirectoryEntry,
    TooManyOrphanTemps,
    LockContended,
    ActiveEmpty,
    ActiveTooLarge,
    ActiveAllocationFailed,
    ActiveChangedDuringRead,
    StoreInstanceMismatch,
    TargetFingerprintMismatch,
    Io(RuntimeIoFailure),
    Journal(RuntimeJournalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeStoreError {
    Stopped,
    LockOrDirectoryIdentityChanged,
    ActiveSnapshotChanged,
    Open(RuntimeStoreOpenError),
    Journal(RuntimeJournalError),
    Publish(RuntimePublishFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeStoreMigrationError {
    InvalidExpectedStoreInstanceId,
    InvalidExpectedTargetFingerprint,
    InvalidMigrationId,
    EvidenceDirectoryMatchesStore,
    LockContended,
    StoreInstanceMismatch,
    TargetFingerprintMismatch,
    Store(RuntimeStoreOpenError),
    EvidenceDirectory(RuntimeStoreOpenError),
    Journal(RuntimeJournalError),
    EvidenceMissing,
    EvidenceTooLarge,
    EvidenceAllocationFailed,
    EvidenceChangedDuringRead,
    UnknownEvidenceEntry,
    TooManyEvidenceDirectoryEntries,
    TooManyEvidenceTemps,
    UnsafeEvidenceFile,
    UnsafeEvidenceMode,
    EvidenceOwnerMismatch,
    EvidenceMismatch,
    InvalidReceipt,
    TargetMismatch,
    EvidenceIo(RuntimeIoFailure),
    EvidencePublish(RuntimePublishFailure),
    Publish(RuntimePublishFailure),
    PublishedButUnverified(RuntimeFileStage),
}

impl fmt::Display for RuntimeStoreOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime store cannot open: {self:?}")
    }
}

impl std::error::Error for RuntimeStoreOpenError {}

impl fmt::Display for RuntimeInitializerBeginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime initializer cannot begin: {self:?}")
    }
}

impl std::error::Error for RuntimeInitializerBeginError {}

impl fmt::Display for RuntimeInitializerPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime initializer cannot publish: {self:?}")
    }
}

impl std::error::Error for RuntimeInitializerPublishError {}

impl fmt::Display for RuntimeStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime store stopped: {self:?}")
    }
}

impl std::error::Error for RuntimeStoreError {}

impl fmt::Display for RuntimeStoreMigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime store migration failed: {self:?}")
    }
}

impl std::error::Error for RuntimeStoreMigrationError {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use paraegox_kernel::digest::Digest32;

    use super::{
        ACTIVE_FILE_NAME, LOCK_FILE_NAME, LinuxMountEvidenceError, MAX_LINUX_FDINFO_BYTES,
        MAX_LINUX_FDINFO_LINE_BYTES, MAX_LINUX_FDINFO_RECORDS, MAX_LINUX_MOUNTINFO_BYTES,
        MAX_LINUX_MOUNTINFO_LINE_BYTES, MAX_LINUX_MOUNTINFO_RECORDS,
        MAX_MIGRATION_EVIDENCE_DIRECTORY_ENTRIES, MAX_MIGRATION_EVIDENCE_ORPHAN_TEMPS,
        MAX_ORPHAN_TEMP_FILES, MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES, MigrationEvidenceKind,
        PRIVATE_FILE_MODE_BITS, PRIVATE_FILE_MODE_MASK, RuntimeCommitFailpoint, RuntimeFileStage,
        RuntimeFilesystemPolicy, RuntimeInitializerBeginError, RuntimeInitializerGuard,
        RuntimeInitializerPreflight, RuntimeInitializerPublishError, RuntimeMigrationFailpoints,
        RuntimeMigrationRequest, RuntimeMigrationTokens, RuntimePublishFailure, RuntimeStore,
        RuntimeStoreError, RuntimeStoreMigrationDisposition, RuntimeStoreMigrationError,
        RuntimeStoreMigrationReceipt, RuntimeStoreOpenError, TEMP_FILE_PREFIX, TEMP_TOKEN_BYTES,
        migration_evidence_temp_name, migration_receipt_file_name, migration_source_file_name,
        parse_linux_fdinfo_mount_id, parse_linux_mountinfo_exact_ext4, temp_name,
        validate_runtime_service_identity,
    };
    use crate::runtime_journal::{
        HostClockAdmissionState, LiveMaterialization, OpaqueCanonicalValue, ReplayLedgerRecord,
        RuntimeJournalError, RuntimeJournalSnapshot, RuntimeJournalState,
        RuntimeJournalTransaction, StorePinnedBuildIdentity, WriterFenceRecord,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn mountinfo_record(mount_id: usize, filesystem_type: &str) -> Vec<u8> {
        format!("{mount_id} 1 8:1 / / rw,nosuid - {filesystem_type} /dev/root rw\n").into_bytes()
    }

    #[test]
    fn linux_mount_evidence_accepts_only_a_unique_exact_ext4_record() {
        assert_eq!(
            parse_linux_fdinfo_mount_id(b"pos:\t0\nflags:\t0100000\nmnt_id:\t42\n"),
            Ok(42)
        );
        assert_eq!(
            parse_linux_mountinfo_exact_ext4(&mountinfo_record(42, "ext4"), 42),
            Ok(())
        );
        for filesystem_type in ["ext2", "ext3", "overlay", "ext4foo", "EXT4", "ext4."] {
            assert_eq!(
                parse_linux_mountinfo_exact_ext4(&mountinfo_record(42, filesystem_type), 42,),
                Err(LinuxMountEvidenceError::UnexpectedFilesystemType)
            );
        }
    }

    #[test]
    fn linux_mount_evidence_rejects_missing_duplicate_and_malformed_records() {
        assert_eq!(
            parse_linux_fdinfo_mount_id(b"pos:\t0\nflags:\t0100000\n"),
            Err(LinuxMountEvidenceError::MissingMountId)
        );
        assert_eq!(
            parse_linux_fdinfo_mount_id(b"mnt_id:\t42\nmnt_id:\t42\n"),
            Err(LinuxMountEvidenceError::DuplicateMountId)
        );
        assert_eq!(
            parse_linux_fdinfo_mount_id(b"mnt_id:\tnot-a-number\n"),
            Err(LinuxMountEvidenceError::MalformedFdInfo)
        );
        assert_eq!(
            parse_linux_fdinfo_mount_id(b"mnt_id:\t42"),
            Err(LinuxMountEvidenceError::MalformedFdInfo)
        );
        assert_eq!(
            parse_linux_mountinfo_exact_ext4(&mountinfo_record(41, "ext4"), 42),
            Err(LinuxMountEvidenceError::MissingMountRecord)
        );
        let mut duplicate = mountinfo_record(42, "ext4");
        duplicate.extend_from_slice(&mountinfo_record(42, "ext4"));
        assert_eq!(
            parse_linux_mountinfo_exact_ext4(&duplicate, 42),
            Err(LinuxMountEvidenceError::DuplicateMountRecord)
        );
        assert_eq!(
            parse_linux_mountinfo_exact_ext4(b"42 1 8:1 / / rw ext4 /dev/root rw\n", 42),
            Err(LinuxMountEvidenceError::MalformedMountInfo)
        );
        assert_eq!(
            parse_linux_mountinfo_exact_ext4(b"42 1 bad / / rw - ext4 /dev/root rw\n", 42),
            Err(LinuxMountEvidenceError::MalformedMountInfo)
        );
        assert_eq!(
            parse_linux_mountinfo_exact_ext4(b"42 1 8:1 / / rw - ext4 /dev/root rw", 42),
            Err(LinuxMountEvidenceError::MalformedMountInfo)
        );
    }

    #[test]
    fn linux_mount_evidence_parser_work_is_strictly_bounded() {
        assert_eq!(
            parse_linux_fdinfo_mount_id(&vec![b'x'; MAX_LINUX_FDINFO_BYTES + 1]),
            Err(LinuxMountEvidenceError::EvidenceTooLarge)
        );
        let mut long_fdinfo_line = vec![b'x'; MAX_LINUX_FDINFO_LINE_BYTES + 1];
        long_fdinfo_line.push(b'\n');
        assert_eq!(
            parse_linux_fdinfo_mount_id(&long_fdinfo_line),
            Err(LinuxMountEvidenceError::LineTooLong)
        );
        assert_eq!(
            parse_linux_fdinfo_mount_id(&b"field:\tvalue\n".repeat(MAX_LINUX_FDINFO_RECORDS + 1),),
            Err(LinuxMountEvidenceError::TooManyRecords)
        );
        assert_eq!(
            parse_linux_mountinfo_exact_ext4(&vec![b'x'; MAX_LINUX_MOUNTINFO_BYTES + 1], 42,),
            Err(LinuxMountEvidenceError::EvidenceTooLarge)
        );
        let mut long_mountinfo_line = vec![b'x'; MAX_LINUX_MOUNTINFO_LINE_BYTES + 1];
        long_mountinfo_line.push(b'\n');
        assert_eq!(
            parse_linux_mountinfo_exact_ext4(&long_mountinfo_line, 42),
            Err(LinuxMountEvidenceError::LineTooLong)
        );
        let mut too_many_mounts = Vec::new();
        for mount_id in 1..=MAX_LINUX_MOUNTINFO_RECORDS + 1 {
            too_many_mounts.extend_from_slice(&mountinfo_record(mount_id, "ext4"));
        }
        assert_eq!(
            parse_linux_mountinfo_exact_ext4(&too_many_mounts, 1),
            Err(LinuxMountEvidenceError::TooManyRecords)
        );
    }

    #[test]
    fn production_reference_requires_a_non_root_runtime_service_identity() {
        assert_eq!(
            validate_runtime_service_identity(
                0,
                1000,
                RuntimeFilesystemPolicy::ProductionReference
            ),
            Err(RuntimeStoreOpenError::UnsafeServiceIdentity)
        );
        assert_eq!(
            validate_runtime_service_identity(
                1000,
                0,
                RuntimeFilesystemPolicy::ProductionReference
            ),
            Err(RuntimeStoreOpenError::UnsafeServiceIdentity)
        );
        assert_eq!(
            validate_runtime_service_identity(
                1000,
                1000,
                RuntimeFilesystemPolicy::ProductionReference,
            ),
            Ok(())
        );
        assert_eq!(
            validate_runtime_service_identity(0, 0, RuntimeFilesystemPolicy::ExplicitFixture),
            Ok(())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_reference_rejects_dev_shm_tmpfs() {
        let path = Path::new("/dev/shm").join(format!(
            "paraegox-runtime-fs-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("/dev/shm Runtime fixture create failed: {error}"));
        set_mode(&path, 0o700);
        let error =
            super::open_runtime_directory(&path, RuntimeFilesystemPolicy::ProductionReference)
                .err();
        fs::remove_dir(&path)
            .unwrap_or_else(|cleanup| panic!("/dev/shm Runtime fixture cleanup failed: {cleanup}"));
        assert_eq!(error, Some(RuntimeStoreOpenError::UnsupportedFilesystem));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn production_reference_rejects_apfs_until_fd_anchored_acl_evidence_exists() {
        let directory = TestDirectory::new();
        assert_eq!(
            super::open_runtime_directory(
                directory.path(),
                RuntimeFilesystemPolicy::ProductionReference,
            )
            .expect_err("APFS must remain unsupported without FD-anchored ACL evidence"),
            RuntimeStoreOpenError::UnsupportedFilesystem
        );
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let fixture_root = std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|error| panic!("fixture root canonicalize failed: {error}"));
            let path = fixture_root.join(format!(
                "paraegox-runtime-store-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("fixture directory create failed: {error}"));
            set_mode(&path, 0o700);
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

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .unwrap_or_else(|error| panic!("fixture chmod failed: {error}"));
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn pinned(bytes: &[u8], digest_byte: u8) -> OpaqueCanonicalValue {
        OpaqueCanonicalValue::try_pinned_artifact(bytes, digest(digest_byte))
            .unwrap_or_else(|error| panic!("fixture pinned artifact failed: {error}"))
    }

    fn sequence_one_state() -> RuntimeJournalState {
        RuntimeJournalState {
            last_transaction: RuntimeJournalTransaction::Initialized,
            host: HostClockAdmissionState {
                runtime_host_epoch_high_water: 0,
                clock_domain: [0x33; 16],
                clock_generation_high_water: 0,
                build_descriptor: pinned(b"descriptor-v1", 0x44),
                singleton_manifest: pinned(b"manifest-v1", 0x55),
                store_pinned_build_identity: StorePinnedBuildIdentity::try_new(
                    [0x57; 32],
                    digest(0x44),
                    digest(0x56),
                    digest(0x58),
                )
                .unwrap_or_else(|error| panic!("fixture build identity failed: {error}")),
                compiled_build_instance_id: [0x57; 32],
                compiled_compatibility_digest: digest(0x58),
                admission_policy_fingerprint: digest(0x66),
                channel_policy_fingerprint: digest(0x67),
                controller_key_fingerprint: digest(0x68),
                tenure_nonces: Vec::new(),
                request_nonces: Vec::new(),
                temporal_lineages: Vec::new(),
            },
            writer_fence: None,
            source_revision_high_water: None,
            prepared: None,
            active_desired: None,
            live_materialization: LiveMaterialization::None,
            recovery_action: None,
            recovery_terminals: Vec::new(),
            owned_resources: Vec::new(),
            terminal_operations: Vec::new(),
        }
    }

    fn initialized_idle_state() -> RuntimeJournalState {
        let mut state = sequence_one_state();
        state.last_transaction = RuntimeJournalTransaction::StartupInvalidation;
        state.host.runtime_host_epoch_high_water = 3;
        state.host.clock_generation_high_water = 5;
        state
    }

    fn tenure_successor_state(previous: &RuntimeJournalState) -> RuntimeJournalState {
        let mut current = previous.clone();
        current.last_transaction = RuntimeJournalTransaction::TenureOnly;
        current.host.tenure_nonces.push(ReplayLedgerRecord {
            identity: digest(0x20),
            value_digest: digest(0x21),
        });
        current.writer_fence = Some(WriterFenceRecord {
            source_scope: [0x01; 16],
            writer: [0x02; 16],
            epoch: 1,
            proof_envelope_digest: digest(0x21),
            tenure_nonce_identity: digest(0x20),
            principal: [0x03; 16],
        });
        current
    }

    fn sequence_one_snapshot(store: u8, target: u8) -> RuntimeJournalSnapshot {
        RuntimeJournalSnapshot::try_new([store; 32], digest(target), 1, sequence_one_state())
            .unwrap_or_else(|error| panic!("sequence-one fixture failed: {error}"))
    }

    fn idle_snapshot(store: u8, target: u8) -> RuntimeJournalSnapshot {
        RuntimeJournalSnapshot::try_new([store; 32], digest(target), 2, initialized_idle_state())
            .unwrap_or_else(|error| panic!("idle fixture failed: {error}"))
    }

    fn tenure_successor(previous: &RuntimeJournalSnapshot) -> RuntimeJournalSnapshot {
        RuntimeJournalSnapshot::try_new(
            *previous.store_instance_id(),
            *previous.owner_target_fingerprint(),
            previous.sequence() + 1,
            tenure_successor_state(previous.state()),
        )
        .unwrap_or_else(|error| panic!("tenure successor fixture failed: {error}"))
    }

    fn install_private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap_or_else(|error| panic!("fixture file write failed: {error}"));
        set_mode(path, 0o600);
    }

    fn install_store(directory: &Path, snapshot: &RuntimeJournalSnapshot) {
        install_store_bytes(directory, snapshot.canonical_wire());
    }

    fn install_store_bytes(directory: &Path, snapshot: &[u8]) {
        install_private_file(&directory.join(LOCK_FILE_NAME), b"");
        install_private_file(&directory.join(ACTIVE_FILE_NAME), snapshot);
    }

    fn open_fixture(
        directory: &Path,
        snapshot: &RuntimeJournalSnapshot,
    ) -> Result<RuntimeStore, RuntimeStoreOpenError> {
        RuntimeStore::open_with_policy(
            directory,
            *snapshot.store_instance_id(),
            *snapshot.owner_target_fingerprint(),
            RuntimeFilesystemPolicy::ExplicitFixture,
        )
    }

    fn fixture_with_snapshot(snapshot: &RuntimeJournalSnapshot) -> TestDirectory {
        let directory = TestDirectory::new();
        install_store(directory.path(), snapshot);
        directory
    }

    fn migration_tokens(byte: u8) -> RuntimeMigrationTokens {
        RuntimeMigrationTokens {
            source_evidence: [byte; TEMP_TOKEN_BYTES],
            receipt_evidence: [byte.wrapping_add(1); TEMP_TOKEN_BYTES],
            active_snapshot: [byte.wrapping_add(2); TEMP_TOKEN_BYTES],
        }
    }

    fn migrate_fixture(
        directory: &Path,
        evidence_directory: &Path,
        snapshot: &RuntimeJournalSnapshot,
        migration_id: [u8; 32],
        token_byte: u8,
        failpoint: RuntimeCommitFailpoint,
    ) -> Result<super::RuntimeStoreMigrationOutcome, RuntimeStoreMigrationError> {
        migrate_fixture_with_failpoints(
            directory,
            evidence_directory,
            snapshot,
            migration_id,
            token_byte,
            RuntimeMigrationFailpoints {
                active_snapshot: failpoint,
                ..RuntimeMigrationFailpoints::NONE
            },
        )
    }

    fn migrate_fixture_with_failpoints(
        directory: &Path,
        evidence_directory: &Path,
        snapshot: &RuntimeJournalSnapshot,
        migration_id: [u8; 32],
        token_byte: u8,
        failpoints: RuntimeMigrationFailpoints,
    ) -> Result<super::RuntimeStoreMigrationOutcome, RuntimeStoreMigrationError> {
        RuntimeStore::migrate_payload_v3_offline_with_policy(
            RuntimeMigrationRequest {
                directory,
                evidence_directory,
                expected_store_instance_id: *snapshot.store_instance_id(),
                expected_target_fingerprint: *snapshot.owner_target_fingerprint(),
                migration_id,
            },
            RuntimeFilesystemPolicy::ExplicitFixture,
            Some(migration_tokens(token_byte)),
            failpoints,
        )
    }

    fn install_orphan(directory: &Path, token: [u8; 16], bytes: &[u8]) -> PathBuf {
        let path = directory.join(temp_name(token));
        install_private_file(&path, bytes);
        path
    }

    fn orphan_count(directory: &Path) -> usize {
        fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("fixture directory read failed: {error}"))
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(TEMP_FILE_PREFIX))
            })
            .count()
    }

    fn decode_active(directory: &Path) -> RuntimeJournalSnapshot {
        let bytes = fs::read(directory.join(ACTIVE_FILE_NAME))
            .unwrap_or_else(|error| panic!("fixture active read failed: {error}"));
        RuntimeJournalSnapshot::decode(&bytes)
            .unwrap_or_else(|error| panic!("fixture active decode failed: {error}"))
    }

    fn assert_cloexec(file: &fs::File) {
        let raw_flags = fcntl(file, FcntlArg::F_GETFD)
            .unwrap_or_else(|error| panic!("F_GETFD failed: {error}"));
        assert!(FdFlag::from_bits_truncate(raw_flags).contains(FdFlag::FD_CLOEXEC));
    }

    #[test]
    fn explicit_payload_v3_store_migration_retains_read_only_evidence_and_resumes() {
        let expected = sequence_one_snapshot(0xd1, 0xd2);
        let legacy = expected
            .legacy_payload_v3_wire_for_test()
            .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
        let store = TestDirectory::new();
        let evidence = TestDirectory::new();
        install_store_bytes(store.path(), &legacy);
        let migration_id = [0xd3; 32];

        assert_eq!(
            open_fixture(store.path(), &expected).err(),
            Some(RuntimeStoreOpenError::Journal(
                RuntimeJournalError::UnsupportedPayloadVersion,
            )),
            "normal Runtime open must never invoke the offline v3 parser",
        );
        let outcome = migrate_fixture(
            store.path(),
            evidence.path(),
            &expected,
            migration_id,
            0x41,
            RuntimeCommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("explicit migration failed: {error}"));
        assert_eq!(
            outcome.disposition,
            RuntimeStoreMigrationDisposition::Migrated
        );
        assert_eq!(outcome.receipt.migration_id(), &migration_id);
        assert_eq!(outcome.receipt.source_payload_version(), 3);
        assert_eq!(
            outcome.receipt.source_store_instance_id(),
            expected.store_instance_id()
        );
        assert_eq!(
            outcome.receipt.source_target_fingerprint(),
            *expected.owner_target_fingerprint()
        );
        assert_eq!(outcome.receipt.source_sequence(), expected.sequence());
        let source_metadata = fs::metadata(
            evidence
                .path()
                .join(migration_source_file_name(migration_id)),
        )
        .unwrap_or_else(|error| panic!("source evidence metadata failed: {error}"));
        let receipt_path = evidence
            .path()
            .join(migration_receipt_file_name(migration_id));
        let receipt_metadata = fs::metadata(&receipt_path)
            .unwrap_or_else(|error| panic!("receipt metadata failed: {error}"));
        assert_eq!(
            source_metadata.mode() & PRIVATE_FILE_MODE_MASK,
            super::READ_ONLY_EVIDENCE_MODE_BITS
        );
        assert_eq!(
            receipt_metadata.mode() & PRIVATE_FILE_MODE_MASK,
            super::READ_ONLY_EVIDENCE_MODE_BITS
        );
        assert_eq!(
            fs::read(
                evidence
                    .path()
                    .join(migration_source_file_name(migration_id))
            )
            .unwrap_or_else(|error| panic!("source evidence read failed: {error}")),
            legacy
        );
        let receipt_wire =
            fs::read(&receipt_path).unwrap_or_else(|error| panic!("receipt read failed: {error}"));
        assert_eq!(receipt_wire.len(), super::MIGRATION_RECEIPT_BYTES);
        assert_eq!(&receipt_wire[..4], b"PXMR");
        assert_eq!(&receipt_wire[4..6], &1_u16.to_be_bytes());
        assert_eq!(
            RuntimeStoreMigrationReceipt::decode(&receipt_wire),
            Ok(outcome.receipt.clone())
        );
        assert_eq!(decode_active(store.path()), expected);
        drop(
            open_fixture(store.path(), &expected).unwrap_or_else(|error| {
                panic!("target parser could not reopen migrated store: {error}")
            }),
        );

        let resumed = migrate_fixture(
            store.path(),
            evidence.path(),
            &expected,
            migration_id,
            0x51,
            RuntimeCommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("completed migration did not resume: {error}"));
        assert_eq!(
            resumed.disposition,
            RuntimeStoreMigrationDisposition::AlreadyMigrated
        );
        assert_eq!(resumed.receipt, outcome.receipt);
        assert_eq!(decode_active(store.path()), expected);
    }

    #[test]
    fn migration_requires_a_stopped_owner_same_lock_and_separate_evidence_directory() {
        let expected = sequence_one_snapshot(0xd4, 0xd5);
        let legacy = expected
            .legacy_payload_v3_wire_for_test()
            .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
        let store = TestDirectory::new();
        let evidence = TestDirectory::new();
        install_store_bytes(store.path(), &legacy);
        let guard = super::acquire_runtime_migration_guard(
            store.path(),
            RuntimeFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("fixture migration lock failed: {error}"));
        assert_eq!(
            migrate_fixture(
                store.path(),
                evidence.path(),
                &expected,
                [0xd6; 32],
                0x61,
                RuntimeCommitFailpoint::None,
            ),
            Err(RuntimeStoreMigrationError::LockContended)
        );
        assert_eq!(
            fs::read(store.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("active read failed: {error}")),
            legacy
        );
        assert_eq!(
            fs::read_dir(evidence.path())
                .unwrap_or_else(|error| panic!("evidence scan failed: {error}"))
                .count(),
            0
        );
        drop(guard);

        assert_eq!(
            migrate_fixture(
                store.path(),
                store.path(),
                &expected,
                [0xd6; 32],
                0x62,
                RuntimeCommitFailpoint::None,
            ),
            Err(RuntimeStoreMigrationError::EvidenceDirectoryMatchesStore)
        );
        assert_eq!(
            fs::read(store.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("active read failed: {error}")),
            legacy
        );
    }

    #[test]
    fn corrupt_and_unknown_sources_fail_closed_without_evidence_or_active_mutation() {
        let expected = sequence_one_snapshot(0xd7, 0xd8);
        let legacy = expected
            .legacy_payload_v3_wire_for_test()
            .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
        let cases = [
            {
                let mut corrupt = legacy.clone();
                let last = corrupt
                    .last_mut()
                    .unwrap_or_else(|| panic!("legacy fixture must not be empty"));
                *last ^= 1;
                (
                    corrupt,
                    RuntimeJournalError::ChecksumMismatch,
                    "checksum-corrupt",
                )
            },
            {
                let mut unknown = legacy.clone();
                unknown[8..10].copy_from_slice(&99_u16.to_be_bytes());
                (
                    unknown,
                    RuntimeJournalError::UnsupportedPayloadVersion,
                    "unknown-version",
                )
            },
        ];
        for (wire, journal_error, label) in cases {
            let store = TestDirectory::new();
            let evidence = TestDirectory::new();
            install_store_bytes(store.path(), &wire);
            assert_eq!(
                migrate_fixture(
                    store.path(),
                    evidence.path(),
                    &expected,
                    [0xd9; 32],
                    0x71,
                    RuntimeCommitFailpoint::None,
                ),
                Err(RuntimeStoreMigrationError::Journal(journal_error)),
                "{label} must preserve the journal decoder failure"
            );
            assert_eq!(
                fs::read(store.path().join(ACTIVE_FILE_NAME))
                    .unwrap_or_else(|error| panic!("{label} active read failed: {error}")),
                wire,
                "{label} must not mutate active"
            );
            assert_eq!(
                fs::read_dir(evidence.path())
                    .unwrap_or_else(|error| panic!("{label} evidence scan failed: {error}"))
                    .count(),
                0,
                "{label} must not emit evidence"
            );
        }
        // Slice-bearing v3 layouts are rejected as LegacyProvenanceUnavailable
        // by runtime_journal's real active-lineage fixture before this store
        // boundary can publish either evidence or target bytes.
    }

    #[test]
    fn migrated_v4_without_exact_evidence_and_tampered_evidence_fail_closed() {
        let expected = sequence_one_snapshot(0xda, 0xdb);
        let fresh_v4 = fixture_with_snapshot(&expected);
        let missing_evidence = TestDirectory::new();
        assert_eq!(
            migrate_fixture(
                fresh_v4.path(),
                missing_evidence.path(),
                &expected,
                [0xdc; 32],
                0x81,
                RuntimeCommitFailpoint::None,
            ),
            Err(RuntimeStoreMigrationError::PublishedButUnverified(
                RuntimeFileStage::ReadBackMigrationEvidence,
            )),
            "an arbitrary v4 store is not proof that this migration completed"
        );
        assert_eq!(decode_active(fresh_v4.path()), expected);

        let legacy = expected
            .legacy_payload_v3_wire_for_test()
            .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
        let store = TestDirectory::new();
        let evidence = TestDirectory::new();
        install_store_bytes(store.path(), &legacy);
        let migration_id = [0xdd; 32];
        migrate_fixture(
            store.path(),
            evidence.path(),
            &expected,
            migration_id,
            0x82,
            RuntimeCommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("fixture migration failed: {error}"));
        let receipt_path = evidence
            .path()
            .join(migration_receipt_file_name(migration_id));
        set_mode(&receipt_path, 0o600);
        assert_eq!(
            migrate_fixture(
                store.path(),
                evidence.path(),
                &expected,
                migration_id,
                0x83,
                RuntimeCommitFailpoint::None,
            ),
            Err(RuntimeStoreMigrationError::PublishedButUnverified(
                RuntimeFileStage::ReadBackMigrationEvidence,
            ))
        );
        assert_eq!(decode_active(store.path()), expected);

        let mut corrupt_receipt =
            fs::read(&receipt_path).unwrap_or_else(|error| panic!("receipt read failed: {error}"));
        corrupt_receipt[10] ^= 1;
        fs::write(&receipt_path, &corrupt_receipt)
            .unwrap_or_else(|error| panic!("receipt corruption failed: {error}"));
        set_mode(&receipt_path, super::READ_ONLY_EVIDENCE_MODE_BITS);
        assert_eq!(
            migrate_fixture(
                store.path(),
                evidence.path(),
                &expected,
                migration_id,
                0x84,
                RuntimeCommitFailpoint::None,
            ),
            Err(RuntimeStoreMigrationError::PublishedButUnverified(
                RuntimeFileStage::ReadBackMigrationEvidence,
            ))
        );
        assert_eq!(decode_active(store.path()), expected);
    }

    #[test]
    fn migration_publish_failpoints_leave_only_strict_old_or_exact_new_active() {
        for (index, failpoint) in [
            RuntimeCommitFailpoint::BeforeTempCreate,
            RuntimeCommitFailpoint::AfterTempCreate,
            RuntimeCommitFailpoint::AfterPartialWrite,
            RuntimeCommitFailpoint::BeforeFileSync,
            RuntimeCommitFailpoint::AfterFileSync,
            RuntimeCommitFailpoint::BeforeRename,
        ]
        .into_iter()
        .enumerate()
        {
            let expected = sequence_one_snapshot(0xde, 0xdf);
            let legacy = expected
                .legacy_payload_v3_wire_for_test()
                .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
            let store = TestDirectory::new();
            let evidence = TestDirectory::new();
            install_store_bytes(store.path(), &legacy);
            let migration_id = [0xe0; 32];
            assert!(matches!(
                migrate_fixture(
                    store.path(),
                    evidence.path(),
                    &expected,
                    migration_id,
                    u8::try_from(0x90 + index).unwrap_or_else(|_| panic!("token index must fit")),
                    failpoint,
                ),
                Err(RuntimeStoreMigrationError::Publish(
                    RuntimePublishFailure::RejectedBeforePublish(_)
                ))
            ));
            assert_eq!(
                fs::read(store.path().join(ACTIVE_FILE_NAME))
                    .unwrap_or_else(|error| panic!("old active read failed: {error}")),
                legacy
            );
            let completed = migrate_fixture(
                store.path(),
                evidence.path(),
                &expected,
                migration_id,
                u8::try_from(0xa0 + index).unwrap_or_else(|_| panic!("retry token index must fit")),
                RuntimeCommitFailpoint::None,
            )
            .unwrap_or_else(|error| panic!("pre-publish retry failed: {error}"));
            assert_eq!(
                completed.disposition,
                RuntimeStoreMigrationDisposition::Migrated
            );
            assert_eq!(decode_active(store.path()), expected);
            assert_eq!(orphan_count(store.path()), 0);
        }

        for (index, failpoint) in [
            RuntimeCommitFailpoint::AfterRename,
            RuntimeCommitFailpoint::BeforeDirectorySync,
            RuntimeCommitFailpoint::AfterDirectorySyncBeforeReturn,
        ]
        .into_iter()
        .enumerate()
        {
            let expected = sequence_one_snapshot(0xe1, 0xe2);
            let legacy = expected
                .legacy_payload_v3_wire_for_test()
                .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
            let store = TestDirectory::new();
            let evidence = TestDirectory::new();
            install_store_bytes(store.path(), &legacy);
            let migration_id = [0xe3; 32];
            assert!(matches!(
                migrate_fixture(
                    store.path(),
                    evidence.path(),
                    &expected,
                    migration_id,
                    u8::try_from(0xb0 + index).unwrap_or_else(|_| panic!("token index must fit")),
                    failpoint,
                ),
                Err(RuntimeStoreMigrationError::Publish(
                    RuntimePublishFailure::UncertainAfterPublish(_)
                ))
            ));
            assert_eq!(decode_active(store.path()), expected);
            let resumed = migrate_fixture(
                store.path(),
                evidence.path(),
                &expected,
                migration_id,
                u8::try_from(0xc0 + index).unwrap_or_else(|_| panic!("retry token index must fit")),
                RuntimeCommitFailpoint::None,
            )
            .unwrap_or_else(|error| panic!("post-publish resume failed: {error}"));
            assert_eq!(
                resumed.disposition,
                RuntimeStoreMigrationDisposition::AlreadyMigrated
            );
            assert_eq!(decode_active(store.path()), expected);
        }
    }

    #[test]
    fn source_and_receipt_evidence_failpoints_are_bounded_and_crash_retryable() {
        let pre_rename = [
            RuntimeCommitFailpoint::BeforeTempCreate,
            RuntimeCommitFailpoint::AfterTempCreate,
            RuntimeCommitFailpoint::AfterPartialWrite,
            RuntimeCommitFailpoint::BeforeFileSync,
            RuntimeCommitFailpoint::AfterFileSync,
            RuntimeCommitFailpoint::BeforeRename,
        ];
        let post_rename = [
            RuntimeCommitFailpoint::AfterRename,
            RuntimeCommitFailpoint::BeforeDirectorySync,
            RuntimeCommitFailpoint::AfterDirectorySyncBeforeReturn,
        ];
        for kind in [
            MigrationEvidenceKind::Source,
            MigrationEvidenceKind::Receipt,
        ] {
            for (index, failpoint) in pre_rename.into_iter().chain(post_rename).enumerate() {
                let expected = sequence_one_snapshot(0xe8, 0xe9);
                let legacy = expected
                    .legacy_payload_v3_wire_for_test()
                    .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
                let store = TestDirectory::new();
                let evidence = TestDirectory::new();
                install_store_bytes(store.path(), &legacy);
                let migration_id = [0xea; 32];
                let mut failpoints = RuntimeMigrationFailpoints::NONE;
                match kind {
                    MigrationEvidenceKind::Source => {
                        failpoints.source_evidence = failpoint;
                    }
                    MigrationEvidenceKind::Receipt => {
                        failpoints.receipt_evidence = failpoint;
                    }
                }
                let result = migrate_fixture_with_failpoints(
                    store.path(),
                    evidence.path(),
                    &expected,
                    migration_id,
                    u8::try_from(0x20 + index)
                        .unwrap_or_else(|_| panic!("evidence token index must fit")),
                    failpoints,
                );
                if index < pre_rename.len() {
                    assert!(matches!(
                        result,
                        Err(RuntimeStoreMigrationError::EvidencePublish(
                            RuntimePublishFailure::RejectedBeforePublish(_)
                        ))
                    ));
                } else {
                    assert!(matches!(
                        result,
                        Err(RuntimeStoreMigrationError::EvidencePublish(
                            RuntimePublishFailure::UncertainAfterPublish(_)
                        ))
                    ));
                }
                assert_eq!(
                    fs::read(store.path().join(ACTIVE_FILE_NAME))
                        .unwrap_or_else(|error| panic!("evidence failure active read: {error}")),
                    legacy,
                    "evidence publication must complete before active replacement"
                );
                let resumed = migrate_fixture(
                    store.path(),
                    evidence.path(),
                    &expected,
                    migration_id,
                    u8::try_from(0x40 + index)
                        .unwrap_or_else(|_| panic!("evidence retry token index must fit")),
                    RuntimeCommitFailpoint::None,
                )
                .unwrap_or_else(|error| panic!("evidence retry failed: {error}"));
                assert_eq!(
                    resumed.disposition,
                    RuntimeStoreMigrationDisposition::Migrated
                );
                assert_eq!(decode_active(store.path()), expected);
                assert_eq!(
                    fs::read(
                        evidence
                            .path()
                            .join(migration_source_file_name(migration_id))
                    )
                    .unwrap_or_else(|error| panic!("source evidence read failed: {error}")),
                    legacy
                );
                let receipt = fs::read(
                    evidence
                        .path()
                        .join(migration_receipt_file_name(migration_id)),
                )
                .unwrap_or_else(|error| panic!("receipt evidence read failed: {error}"));
                RuntimeStoreMigrationReceipt::decode(&receipt)
                    .unwrap_or_else(|error| panic!("receipt evidence invalid: {error}"));
                assert_eq!(
                    fs::read_dir(evidence.path())
                        .unwrap_or_else(|error| panic!("evidence scan failed: {error}"))
                        .filter_map(Result::ok)
                        .filter(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(super::MIGRATION_EVIDENCE_TEMP_PREFIX)
                        })
                        .count(),
                    0,
                    "retry must remove its bounded orphan evidence temp"
                );
            }
        }
    }

    #[test]
    fn post_rename_verification_failures_are_explicitly_uncertain_or_unverified() {
        for kind in [
            MigrationEvidenceKind::Source,
            MigrationEvidenceKind::Receipt,
        ] {
            let expected = sequence_one_snapshot(0xee, 0xef);
            let legacy = expected
                .legacy_payload_v3_wire_for_test()
                .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
            let store = TestDirectory::new();
            let evidence = TestDirectory::new();
            install_store_bytes(store.path(), &legacy);
            let migration_id = [0xf0; 32];
            let mut failpoints = RuntimeMigrationFailpoints::NONE;
            match kind {
                MigrationEvidenceKind::Source => {
                    failpoints.source_evidence =
                        RuntimeCommitFailpoint::MigrationEvidenceReadBackFailure;
                }
                MigrationEvidenceKind::Receipt => {
                    failpoints.receipt_evidence =
                        RuntimeCommitFailpoint::MigrationEvidenceReadBackFailure;
                }
            }
            assert!(matches!(
                migrate_fixture_with_failpoints(
                    store.path(),
                    evidence.path(),
                    &expected,
                    migration_id,
                    0x63,
                    failpoints,
                ),
                Err(RuntimeStoreMigrationError::EvidencePublish(
                    RuntimePublishFailure::UncertainAfterPublish(fault)
                )) if fault.stage == RuntimeFileStage::ReadBackMigrationEvidence
            ));
            assert_eq!(
                fs::read(store.path().join(ACTIVE_FILE_NAME))
                    .unwrap_or_else(|error| panic!("evidence readback active failed: {error}")),
                legacy
            );
            let completed = migrate_fixture(
                store.path(),
                evidence.path(),
                &expected,
                migration_id,
                0x64,
                RuntimeCommitFailpoint::None,
            )
            .unwrap_or_else(|error| panic!("evidence readback retry failed: {error}"));
            assert_eq!(
                completed.disposition,
                RuntimeStoreMigrationDisposition::Migrated
            );
            assert_eq!(decode_active(store.path()), expected);
        }

        for (failpoint, expected_stage) in [
            (
                RuntimeCommitFailpoint::MigrationActiveReadBackFailure,
                RuntimeFileStage::ReadBackPublished,
            ),
            (
                RuntimeCommitFailpoint::MigrationPostPublishEvidenceFailure,
                RuntimeFileStage::ReadBackMigrationEvidence,
            ),
        ] {
            let expected = sequence_one_snapshot(0xf1, 0xf2);
            let legacy = expected
                .legacy_payload_v3_wire_for_test()
                .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
            let store = TestDirectory::new();
            let evidence = TestDirectory::new();
            install_store_bytes(store.path(), &legacy);
            let migration_id = [0xf3; 32];
            assert_eq!(
                migrate_fixture(
                    store.path(),
                    evidence.path(),
                    &expected,
                    migration_id,
                    0x65,
                    failpoint,
                ),
                Err(RuntimeStoreMigrationError::PublishedButUnverified(
                    expected_stage,
                ))
            );
            assert_eq!(
                decode_active(store.path()),
                expected,
                "post-publish verification failure must leave exact v4 active"
            );
            let resumed = migrate_fixture(
                store.path(),
                evidence.path(),
                &expected,
                migration_id,
                0x66,
                RuntimeCommitFailpoint::None,
            )
            .unwrap_or_else(|error| panic!("post-publish verification retry failed: {error}"));
            assert_eq!(
                resumed.disposition,
                RuntimeStoreMigrationDisposition::AlreadyMigrated
            );
        }
    }

    #[test]
    fn malformed_or_excess_migration_evidence_temps_fail_before_cleanup_or_mutation() {
        let expected = sequence_one_snapshot(0xeb, 0xec);
        let legacy = expected
            .legacy_payload_v3_wire_for_test()
            .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
        let migration_id = [0xed; 32];

        let malformed_store = TestDirectory::new();
        let malformed_evidence = TestDirectory::new();
        install_store_bytes(malformed_store.path(), &legacy);
        let mut malformed = super::migration_evidence_temp_prefix(migration_id);
        malformed.push_str("source-not-hex");
        install_private_file(&malformed_evidence.path().join(&malformed), b"partial");
        assert_eq!(
            migrate_fixture(
                malformed_store.path(),
                malformed_evidence.path(),
                &expected,
                migration_id,
                0x51,
                RuntimeCommitFailpoint::None,
            ),
            Err(RuntimeStoreMigrationError::UnknownEvidenceEntry)
        );
        assert!(malformed_evidence.path().join(malformed).is_file());
        assert_eq!(
            fs::read(malformed_store.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("malformed active read failed: {error}")),
            legacy
        );

        let overflow_store = TestDirectory::new();
        let overflow_evidence = TestDirectory::new();
        install_store_bytes(overflow_store.path(), &legacy);
        let mut orphans = Vec::new();
        for index in 0..=MAX_MIGRATION_EVIDENCE_ORPHAN_TEMPS {
            let mut token = [0_u8; TEMP_TOKEN_BYTES];
            token[14..].copy_from_slice(
                &u16::try_from(index + 1)
                    .unwrap_or_else(|_| panic!("orphan index must fit"))
                    .to_be_bytes(),
            );
            let path = overflow_evidence.path().join(migration_evidence_temp_name(
                migration_id,
                MigrationEvidenceKind::Source,
                token,
            ));
            install_private_file(&path, b"partial");
            orphans.push(path);
        }
        assert_eq!(
            migrate_fixture(
                overflow_store.path(),
                overflow_evidence.path(),
                &expected,
                migration_id,
                0x52,
                RuntimeCommitFailpoint::None,
            ),
            Err(RuntimeStoreMigrationError::TooManyEvidenceTemps)
        );
        assert!(orphans.iter().all(|path| path.is_file()));
        assert_eq!(
            fs::read(overflow_store.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("overflow active read failed: {error}")),
            legacy
        );

        let two_phase_store = TestDirectory::new();
        let two_phase_evidence = TestDirectory::new();
        install_store_bytes(two_phase_store.path(), &legacy);
        let valid = two_phase_evidence.path().join(migration_evidence_temp_name(
            migration_id,
            MigrationEvidenceKind::Source,
            [0x61; TEMP_TOKEN_BYTES],
        ));
        let invalid = two_phase_evidence.path().join(migration_evidence_temp_name(
            migration_id,
            MigrationEvidenceKind::Receipt,
            [0x62; TEMP_TOKEN_BYTES],
        ));
        install_private_file(&valid, b"valid-orphan");
        install_private_file(&invalid, b"unsafe-orphan");
        set_mode(&invalid, 0o644);
        assert_eq!(
            migrate_fixture(
                two_phase_store.path(),
                two_phase_evidence.path(),
                &expected,
                migration_id,
                0x53,
                RuntimeCommitFailpoint::None,
            ),
            Err(RuntimeStoreMigrationError::UnsafeEvidenceMode)
        );
        assert!(
            valid.is_file(),
            "validation failure must not delete an earlier valid orphan"
        );
        assert!(
            invalid.is_file(),
            "validation failure must preserve the invalid candidate"
        );
        assert_eq!(
            fs::read(two_phase_store.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("two-phase active read failed: {error}")),
            legacy
        );

        let total_bound_store = TestDirectory::new();
        let total_bound_evidence = TestDirectory::new();
        install_store_bytes(total_bound_store.path(), &legacy);
        for index in 0..=MAX_MIGRATION_EVIDENCE_DIRECTORY_ENTRIES {
            install_private_file(
                &total_bound_evidence
                    .path()
                    .join(format!("unrelated-audit-{index:03}")),
                b"unrelated",
            );
        }
        assert_eq!(
            migrate_fixture(
                total_bound_store.path(),
                total_bound_evidence.path(),
                &expected,
                migration_id,
                0x54,
                RuntimeCommitFailpoint::None,
            ),
            Err(RuntimeStoreMigrationError::TooManyEvidenceDirectoryEntries)
        );
        assert_eq!(
            fs::read_dir(total_bound_evidence.path())
                .unwrap_or_else(|error| panic!("total-bound evidence scan failed: {error}"))
                .count(),
            MAX_MIGRATION_EVIDENCE_DIRECTORY_ENTRIES + 1
        );
        assert_eq!(
            fs::read(total_bound_store.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("total-bound active read failed: {error}")),
            legacy
        );
    }

    #[test]
    fn migration_subprocess_crashes_resume_from_only_strict_old_or_exact_new_active() {
        let cases = [
            ("temp-create", false),
            ("partial-write", false),
            ("before-file-fsync", false),
            ("file-fsync", false),
            ("rename", true),
            ("directory-fsync", true),
            ("durable-commit-before-return", true),
        ];
        for (point, published) in cases {
            let expected = sequence_one_snapshot(0xe4, 0xe5);
            let legacy = expected
                .legacy_payload_v3_wire_for_test()
                .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
            let store = TestDirectory::new();
            let evidence = TestDirectory::new();
            install_store_bytes(store.path(), &legacy);
            let status = Command::new(
                std::env::current_exe()
                    .unwrap_or_else(|error| panic!("test executable lookup failed: {error}")),
            )
            .args([
                "--exact",
                "runtime_store::tests::subprocess_runtime_migration_crash_child",
                "--nocapture",
            ])
            .env("PARAEGOX_TEST_RUNTIME_MIGRATION_STORE", store.path())
            .env("PARAEGOX_TEST_RUNTIME_MIGRATION_EVIDENCE", evidence.path())
            .env("PARAEGOX_TEST_RUNTIME_MIGRATION_CRASH_POINT", point)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|error| panic!("migration crash child spawn failed: {error}"));
            assert!(!status.success(), "migration child returned at {point}");

            let active = fs::read(store.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("post-crash active read failed: {error}"));
            if published {
                assert_eq!(
                    RuntimeJournalSnapshot::decode(&active),
                    Ok(expected.clone()),
                    "{point} must leave exact v4 active"
                );
            } else {
                assert_eq!(active, legacy, "{point} must leave exact v3 active");
            }
            assert_eq!(
                fs::read(evidence.path().join(migration_source_file_name([0xe6; 32])))
                    .unwrap_or_else(|error| panic!("post-crash source evidence failed: {error}")),
                legacy,
                "{point} must retain exact source evidence before active publication"
            );
            let receipt = fs::read(
                evidence
                    .path()
                    .join(migration_receipt_file_name([0xe6; 32])),
            )
            .unwrap_or_else(|error| panic!("post-crash receipt read failed: {error}"));
            RuntimeStoreMigrationReceipt::decode(&receipt)
                .unwrap_or_else(|error| panic!("post-crash receipt invalid at {point}: {error}"));

            let resumed = migrate_fixture(
                store.path(),
                evidence.path(),
                &expected,
                [0xe6; 32],
                0xe7,
                RuntimeCommitFailpoint::None,
            )
            .unwrap_or_else(|error| panic!("post-crash resume failed at {point}: {error}"));
            assert_eq!(
                resumed.disposition,
                if published {
                    RuntimeStoreMigrationDisposition::AlreadyMigrated
                } else {
                    RuntimeStoreMigrationDisposition::Migrated
                }
            );
            assert_eq!(decode_active(store.path()), expected);
            assert_eq!(orphan_count(store.path()), 0);
        }
    }

    #[test]
    fn source_and_receipt_evidence_subprocess_crashes_leave_retryable_old_active() {
        for (location, point) in [
            ("source", "file-fsync"),
            ("source", "rename"),
            ("source", "directory-fsync"),
            ("receipt", "file-fsync"),
            ("receipt", "rename"),
            ("receipt", "directory-fsync"),
        ] {
            let expected = sequence_one_snapshot(0xe4, 0xe5);
            let legacy = expected
                .legacy_payload_v3_wire_for_test()
                .unwrap_or_else(|error| panic!("legacy fixture failed: {error}"));
            let store = TestDirectory::new();
            let evidence = TestDirectory::new();
            install_store_bytes(store.path(), &legacy);
            let status = Command::new(
                std::env::current_exe()
                    .unwrap_or_else(|error| panic!("test executable lookup failed: {error}")),
            )
            .args([
                "--exact",
                "runtime_store::tests::subprocess_runtime_migration_crash_child",
                "--nocapture",
            ])
            .env("PARAEGOX_TEST_RUNTIME_MIGRATION_STORE", store.path())
            .env("PARAEGOX_TEST_RUNTIME_MIGRATION_EVIDENCE", evidence.path())
            .env("PARAEGOX_TEST_RUNTIME_MIGRATION_CRASH_POINT", point)
            .env("PARAEGOX_TEST_RUNTIME_MIGRATION_CRASH_LOCATION", location)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|error| panic!("evidence crash child spawn failed: {error}"));
            assert!(
                !status.success(),
                "{location} evidence child returned at {point}"
            );
            assert_eq!(
                fs::read(store.path().join(ACTIVE_FILE_NAME))
                    .unwrap_or_else(|error| panic!("post-crash active read failed: {error}")),
                legacy,
                "evidence must be durable before active publication"
            );
            let resumed = migrate_fixture(
                store.path(),
                evidence.path(),
                &expected,
                [0xe6; 32],
                0xe7,
                RuntimeCommitFailpoint::None,
            )
            .unwrap_or_else(|error| {
                panic!("{location} evidence resume failed at {point}: {error}")
            });
            assert_eq!(
                resumed.disposition,
                RuntimeStoreMigrationDisposition::Migrated
            );
            assert_eq!(decode_active(store.path()), expected);
            assert_eq!(
                fs::read_dir(evidence.path())
                    .unwrap_or_else(|error| panic!("evidence scan failed: {error}"))
                    .filter_map(Result::ok)
                    .filter(|entry| entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(super::MIGRATION_EVIDENCE_TEMP_PREFIX))
                    .count(),
                0
            );
        }
    }

    #[test]
    fn subprocess_runtime_migration_crash_child() {
        let Some(store) = std::env::var_os("PARAEGOX_TEST_RUNTIME_MIGRATION_STORE") else {
            return;
        };
        let evidence = std::env::var_os("PARAEGOX_TEST_RUNTIME_MIGRATION_EVIDENCE")
            .unwrap_or_else(|| panic!("migration evidence path missing"));
        let point = std::env::var("PARAEGOX_TEST_RUNTIME_MIGRATION_CRASH_POINT")
            .unwrap_or_else(|error| panic!("migration crash point missing: {error}"));
        let failpoint = match point.as_str() {
            "temp-create" => RuntimeCommitFailpoint::AbortAfterTempCreate,
            "partial-write" => RuntimeCommitFailpoint::AbortAfterPartialWrite,
            "before-file-fsync" => RuntimeCommitFailpoint::AbortBeforeFileSync,
            "file-fsync" => RuntimeCommitFailpoint::AbortAfterFileSync,
            "rename" => RuntimeCommitFailpoint::AbortAfterRename,
            "directory-fsync" => RuntimeCommitFailpoint::AbortAfterDirectorySync,
            "durable-commit-before-return" => {
                RuntimeCommitFailpoint::AbortAfterDurableCommitBeforeReturn
            }
            _ => panic!("unknown Runtime migration crash point"),
        };
        let location = std::env::var("PARAEGOX_TEST_RUNTIME_MIGRATION_CRASH_LOCATION")
            .unwrap_or_else(|_| "active".to_owned());
        let mut failpoints = RuntimeMigrationFailpoints::NONE;
        match location.as_str() {
            "active" => failpoints.active_snapshot = failpoint,
            "source" => failpoints.source_evidence = failpoint,
            "receipt" => failpoints.receipt_evidence = failpoint,
            _ => panic!("unknown Runtime migration crash location"),
        }
        let expected = sequence_one_snapshot(0xe4, 0xe5);
        let result = migrate_fixture_with_failpoints(
            Path::new(&store),
            Path::new(&evidence),
            &expected,
            [0xe6; 32],
            0xd0,
            failpoints,
        );
        panic!("Runtime migration crash failpoint unexpectedly returned: {result:?}");
    }

    #[test]
    fn fresh_initializer_marker_publishes_sequence_one_exactly_once() {
        let directory = TestDirectory::new();
        let mut initializer = RuntimeInitializerGuard::begin_with_policy(
            directory.path(),
            RuntimeFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("initializer begin failed: {error}"));
        assert_cloexec(&initializer.lock_file);

        let snapshot = sequence_one_snapshot(0x11, 0x22);
        initializer
            .publish_sequence_one_with(
                snapshot.clone(),
                [0x31; TEMP_TOKEN_BYTES],
                RuntimeCommitFailpoint::None,
            )
            .unwrap_or_else(|error| panic!("initial publish failed: {error}"));
        assert_eq!(decode_active(directory.path()), snapshot);
        assert!(matches!(
            RuntimeInitializerGuard::begin_with_policy(
                directory.path(),
                RuntimeFilesystemPolicy::ExplicitFixture,
            ),
            Err(RuntimeInitializerBeginError::MarkerConsumed(_))
        ));

        drop(initializer);
        let opened = open_fixture(directory.path(), &snapshot)
            .unwrap_or_else(|error| panic!("initialized store did not reopen: {error}"));
        assert_eq!(opened.snapshot(), Ok(&snapshot));
    }

    #[test]
    fn initializer_rejects_preexisting_state_before_consuming_marker() {
        let directory = TestDirectory::new();
        install_private_file(&directory.path().join("unexpected"), b"not-runtime-state");

        assert_eq!(
            RuntimeInitializerGuard::begin_with_policy(
                directory.path(),
                RuntimeFilesystemPolicy::ExplicitFixture,
            )
            .err(),
            Some(RuntimeInitializerBeginError::Store(
                RuntimeStoreOpenError::DirectoryNotFresh,
            ))
        );
        assert!(!directory.path().join(LOCK_FILE_NAME).exists());
    }

    #[test]
    fn initializer_preflight_is_read_only_and_later_race_consumes_marker() {
        let directory = TestDirectory::new();
        let preflight = RuntimeInitializerPreflight::open_fixture(directory.path())
            .unwrap_or_else(|error| panic!("initializer preflight failed: {error}"));
        assert!(!directory.path().join(LOCK_FILE_NAME).exists());

        install_private_file(&directory.path().join("unexpected"), b"racing-state");
        assert_eq!(
            preflight.acquire().err(),
            Some(RuntimeInitializerBeginError::MarkerConsumed(
                RuntimeStoreOpenError::DirectoryNotFresh,
            ))
        );
        assert!(directory.path().join(LOCK_FILE_NAME).is_file());
    }

    #[test]
    fn failed_initial_publish_cannot_be_reset_or_replace_existing_active() {
        let directory = TestDirectory::new();
        let mut initializer = RuntimeInitializerGuard::begin_with_policy(
            directory.path(),
            RuntimeFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("initializer begin failed: {error}"));
        let snapshot = sequence_one_snapshot(0x11, 0x22);

        assert!(matches!(
            initializer.publish_sequence_one_with(
                snapshot.clone(),
                [0x32; TEMP_TOKEN_BYTES],
                RuntimeCommitFailpoint::AfterPartialWrite,
            ),
            Err(RuntimeInitializerPublishError::Publish(
                RuntimePublishFailure::RejectedBeforePublish(_)
            ))
        ));
        assert_eq!(
            initializer.publish_sequence_one(snapshot.clone(), [0x33; TEMP_TOKEN_BYTES]),
            Err(RuntimeInitializerPublishError::Stopped)
        );
        assert!(!directory.path().join(ACTIVE_FILE_NAME).exists());
        drop(initializer);
        assert!(matches!(
            RuntimeInitializerGuard::begin_with_policy(
                directory.path(),
                RuntimeFilesystemPolicy::ExplicitFixture,
            ),
            Err(RuntimeInitializerBeginError::MarkerConsumed(_))
        ));

        let competing = TestDirectory::new();
        let mut initializer = RuntimeInitializerGuard::begin_with_policy(
            competing.path(),
            RuntimeFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("competing initializer begin failed: {error}"));
        install_private_file(
            &competing.path().join(ACTIVE_FILE_NAME),
            b"preexisting-active",
        );
        assert!(matches!(
            initializer.publish_sequence_one_with(
                snapshot,
                [0x34; TEMP_TOKEN_BYTES],
                RuntimeCommitFailpoint::None,
            ),
            Err(RuntimeInitializerPublishError::LockOrDirectoryIdentityChanged)
        ));
        assert_eq!(
            fs::read(competing.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("competing active read failed: {error}")),
            b"preexisting-active"
        );
    }

    #[test]
    fn initializer_drop_unlocks_while_a_fork_like_descriptor_reference_survives() {
        let directory = TestDirectory::new();
        let snapshot = sequence_one_snapshot(0x15, 0x25);
        let mut initializer = RuntimeInitializerGuard::begin_with_policy(
            directory.path(),
            RuntimeFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("initializer begin failed: {error}"));
        let inherited = initializer
            .lock_file
            .try_clone()
            .unwrap_or_else(|error| panic!("initializer lock clone failed: {error}"));
        initializer
            .publish_sequence_one(snapshot.clone(), [0x35; TEMP_TOKEN_BYTES])
            .unwrap_or_else(|error| panic!("initial publish failed: {error}"));

        drop(initializer);
        let reopened = open_fixture(directory.path(), &snapshot).unwrap_or_else(|error| {
            panic!("initializer drop left restart blocked by cloned descriptor: {error}")
        });
        assert_eq!(reopened.snapshot(), Ok(&snapshot));
        drop(reopened);
        drop(inherited);
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn initializer_no_replace_is_atomic_against_a_last_moment_active_install() {
        let directory = TestDirectory::new();
        let snapshot = sequence_one_snapshot(0x16, 0x26);
        let mut initializer = RuntimeInitializerGuard::begin_with_policy(
            directory.path(),
            RuntimeFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("initializer begin failed: {error}"));

        assert!(matches!(
            initializer.publish_sequence_one_with(
                snapshot.clone(),
                [0x36; TEMP_TOKEN_BYTES],
                RuntimeCommitFailpoint::InstallCompetingActiveBeforeRename,
            ),
            Err(RuntimeInitializerPublishError::Publish(
                RuntimePublishFailure::RejectedBeforePublish(fault)
            )) if fault.stage == RuntimeFileStage::RequireMissingActive
                && fault.kind == Some(std::io::ErrorKind::AlreadyExists)
        ));
        assert_eq!(
            initializer.publish_sequence_one(snapshot.clone(), [0x37; TEMP_TOKEN_BYTES]),
            Err(RuntimeInitializerPublishError::Stopped)
        );
        assert_eq!(
            fs::read(directory.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("competing active read failed: {error}")),
            b"competing-active"
        );
        assert!(directory.path().join(LOCK_FILE_NAME).is_file());
        let candidate = directory.path().join(temp_name([0x36; TEMP_TOKEN_BYTES]));
        assert_eq!(
            fs::read(candidate)
                .unwrap_or_else(|error| panic!("candidate temp read failed: {error}")),
            snapshot.canonical_wire()
        );
        drop(initializer);
        assert!(matches!(
            RuntimeInitializerGuard::begin_with_policy(
                directory.path(),
                RuntimeFilesystemPolicy::ExplicitFixture,
            ),
            Err(RuntimeInitializerBeginError::MarkerConsumed(_))
        ));
    }

    #[test]
    fn invalid_expected_identity_precedes_all_path_and_filesystem_io() {
        let nonexistent_relative = Path::new("relative/does-not-exist");
        assert_eq!(
            RuntimeStore::open_with_policy(
                nonexistent_relative,
                [0; 32],
                digest(0x22),
                RuntimeFilesystemPolicy::ExplicitFixture,
            )
            .err(),
            Some(RuntimeStoreOpenError::InvalidExpectedStoreInstanceId)
        );
        assert_eq!(
            RuntimeStore::open_with_policy(
                nonexistent_relative,
                [0x11; 32],
                Digest32::from_bytes([0; 32]),
                RuntimeFilesystemPolicy::ExplicitFixture,
            )
            .err(),
            Some(RuntimeStoreOpenError::InvalidExpectedTargetFingerprint)
        );
    }

    #[test]
    fn open_binds_exact_store_target_and_bounded_canonical_active() {
        let snapshot = sequence_one_snapshot(0x11, 0x22);
        let directory = fixture_with_snapshot(&snapshot);
        let store = open_fixture(directory.path(), &snapshot)
            .unwrap_or_else(|error| panic!("valid Runtime store rejected: {error}"));
        assert_eq!(
            store
                .snapshot()
                .unwrap_or_else(|error| panic!("valid snapshot unavailable: {error}")),
            &snapshot
        );
        drop(store);

        assert_eq!(
            RuntimeStore::open_with_policy(
                directory.path(),
                [0x12; 32],
                *snapshot.owner_target_fingerprint(),
                RuntimeFilesystemPolicy::ExplicitFixture,
            )
            .err(),
            Some(RuntimeStoreOpenError::StoreInstanceMismatch)
        );
        assert_eq!(
            RuntimeStore::open_with_policy(
                directory.path(),
                *snapshot.store_instance_id(),
                digest(0x23),
                RuntimeFilesystemPolicy::ExplicitFixture,
            )
            .err(),
            Some(RuntimeStoreOpenError::TargetFingerprintMismatch)
        );

        let corrupt = fixture_with_snapshot(&snapshot);
        let mut bytes = snapshot.canonical_wire().to_vec();
        let last = bytes
            .last_mut()
            .unwrap_or_else(|| panic!("snapshot fixture must not be empty"));
        *last ^= 1;
        install_private_file(&corrupt.path().join(ACTIVE_FILE_NAME), &bytes);
        assert_eq!(
            open_fixture(corrupt.path(), &snapshot).err(),
            Some(RuntimeStoreOpenError::Journal(
                RuntimeJournalError::ChecksumMismatch
            ))
        );

        let oversized = fixture_with_snapshot(&snapshot);
        let active = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(oversized.path().join(ACTIVE_FILE_NAME))
            .unwrap_or_else(|error| panic!("oversized fixture open failed: {error}"));
        active
            .set_len(
                u64::try_from(MAX_RUNTIME_JOURNAL_SNAPSHOT_BYTES + 1)
                    .unwrap_or_else(|_| panic!("snapshot maximum must fit u64")),
            )
            .unwrap_or_else(|error| panic!("oversized fixture set_len failed: {error}"));
        drop(active);
        assert_eq!(
            open_fixture(oversized.path(), &snapshot).err(),
            Some(RuntimeStoreOpenError::ActiveTooLarge)
        );
    }

    #[test]
    fn path_directory_and_regular_file_security_fail_closed() {
        let snapshot = sequence_one_snapshot(0x11, 0x22);
        assert_eq!(
            RuntimeStore::open_with_policy(
                Path::new("relative/runtime-state"),
                *snapshot.store_instance_id(),
                *snapshot.owner_target_fingerprint(),
                RuntimeFilesystemPolicy::ExplicitFixture,
            )
            .err(),
            Some(RuntimeStoreOpenError::PathMustBeAbsolute)
        );

        let target = fixture_with_snapshot(&snapshot);
        let link_parent = TestDirectory::new();
        let link = link_parent.path().join("runtime-link");
        symlink(target.path(), &link)
            .unwrap_or_else(|error| panic!("directory symlink fixture failed: {error}"));
        assert!(matches!(
            open_fixture(&link, &snapshot),
            Err(RuntimeStoreOpenError::UnsafeDirectoryType)
                | Err(RuntimeStoreOpenError::UnsafeAncestorType)
        ));

        let unsafe_mode = fixture_with_snapshot(&snapshot);
        set_mode(unsafe_mode.path(), 0o750);
        assert_eq!(
            open_fixture(unsafe_mode.path(), &snapshot).err(),
            Some(RuntimeStoreOpenError::UnsafeDirectoryMode)
        );

        let ancestor_root = TestDirectory::new();
        let peer_writable = ancestor_root.path().join("peer-writable");
        fs::create_dir(&peer_writable)
            .unwrap_or_else(|error| panic!("peer-writable fixture create failed: {error}"));
        set_mode(&peer_writable, 0o770);
        let state = peer_writable.join("state");
        fs::create_dir(&state)
            .unwrap_or_else(|error| panic!("state fixture create failed: {error}"));
        set_mode(&state, 0o700);
        install_store(&state, &snapshot);
        assert_eq!(
            open_fixture(&state, &snapshot).err(),
            Some(RuntimeStoreOpenError::UntrustedAncestor)
        );

        let unsafe_file_mode = fixture_with_snapshot(&snapshot);
        set_mode(&unsafe_file_mode.path().join(ACTIVE_FILE_NAME), 0o640);
        assert_eq!(
            open_fixture(unsafe_file_mode.path(), &snapshot).err(),
            Some(RuntimeStoreOpenError::UnsafeFileMode)
        );

        let hardlinked = fixture_with_snapshot(&snapshot);
        fs::hard_link(
            hardlinked.path().join(ACTIVE_FILE_NAME),
            hardlinked.path().join("active-hardlink"),
        )
        .unwrap_or_else(|error| panic!("hardlink fixture failed: {error}"));
        assert_eq!(
            open_fixture(hardlinked.path(), &snapshot).err(),
            Some(RuntimeStoreOpenError::UnsafeFileType)
        );

        let symlinked_active = fixture_with_snapshot(&snapshot);
        fs::remove_file(symlinked_active.path().join(ACTIVE_FILE_NAME))
            .unwrap_or_else(|error| panic!("active removal failed: {error}"));
        symlink(
            symlinked_active.path().join(LOCK_FILE_NAME),
            symlinked_active.path().join(ACTIVE_FILE_NAME),
        )
        .unwrap_or_else(|error| panic!("active symlink fixture failed: {error}"));
        assert!(matches!(
            open_fixture(symlinked_active.path(), &snapshot),
            Err(RuntimeStoreOpenError::Io(_))
        ));
    }

    #[test]
    fn lock_and_directory_handles_are_cloexec_and_second_writer_is_rejected() {
        let snapshot = sequence_one_snapshot(0x11, 0x22);
        let directory = fixture_with_snapshot(&snapshot);
        let first = open_fixture(directory.path(), &snapshot)
            .unwrap_or_else(|error| panic!("first Runtime store open failed: {error}"));
        assert_cloexec(&first.lock_file);
        assert_cloexec(&first.directory.file);
        assert_eq!(
            open_fixture(directory.path(), &snapshot).err(),
            Some(RuntimeStoreOpenError::LockContended)
        );
    }

    #[test]
    fn normal_drop_unlocks_even_while_a_fork_like_descriptor_reference_survives() {
        let snapshot = sequence_one_snapshot(0x11, 0x22);
        let directory = fixture_with_snapshot(&snapshot);
        let first = open_fixture(directory.path(), &snapshot)
            .unwrap_or_else(|error| panic!("first Runtime store open failed: {error}"));
        let inherited_lock_reference = first
            .lock_file
            .try_clone()
            .unwrap_or_else(|error| panic!("lock descriptor clone failed: {error}"));

        drop(first);
        let replacement = open_fixture(directory.path(), &snapshot)
            .unwrap_or_else(|error| panic!("replacement Runtime store open failed: {error}"));

        drop(replacement);
        drop(inherited_lock_reference);
    }

    #[test]
    fn revalidation_detects_active_content_or_file_identity_change_and_stops() {
        let snapshot = sequence_one_snapshot(0x11, 0x22);
        let directory = fixture_with_snapshot(&snapshot);
        let mut store = open_fixture(directory.path(), &snapshot)
            .unwrap_or_else(|error| panic!("Runtime store open failed: {error}"));
        let replacement_path = directory.path().join("replacement");
        install_private_file(&replacement_path, snapshot.canonical_wire());
        fs::rename(&replacement_path, directory.path().join(ACTIVE_FILE_NAME))
            .unwrap_or_else(|error| panic!("active replacement failed: {error}"));
        assert_eq!(
            store.revalidate_current().err(),
            Some(RuntimeStoreError::ActiveSnapshotChanged)
        );
        assert_eq!(store.snapshot().err(), Some(RuntimeStoreError::Stopped));

        let idle = idle_snapshot(0x31, 0x32);
        let changed = tenure_successor(&idle);
        let changed_directory = fixture_with_snapshot(&idle);
        let mut changed_store = open_fixture(changed_directory.path(), &idle)
            .unwrap_or_else(|error| panic!("changed fixture open failed: {error}"));
        install_private_file(
            &changed_directory.path().join(ACTIVE_FILE_NAME),
            changed.canonical_wire(),
        );
        assert_eq!(
            changed_store.revalidate_current().err(),
            Some(RuntimeStoreError::ActiveSnapshotChanged)
        );
        assert_eq!(
            changed_store.revalidate_current().err(),
            Some(RuntimeStoreError::Stopped)
        );
    }

    #[test]
    fn commit_requires_exact_successor_and_publishes_canonical_bytes() {
        let previous = idle_snapshot(0x41, 0x42);
        let next = tenure_successor(&previous);
        assert_eq!(next.validate_successor_of(&previous), Ok(()));
        let directory = fixture_with_snapshot(&previous);
        let mut store = open_fixture(directory.path(), &previous)
            .unwrap_or_else(|error| panic!("Runtime store open failed: {error}"));
        store
            .commit_with(next.clone(), [0x51; 16], RuntimeCommitFailpoint::None)
            .unwrap_or_else(|error| panic!("valid Runtime commit failed: {error}"));
        assert_eq!(
            store
                .snapshot()
                .unwrap_or_else(|error| panic!("published snapshot unavailable: {error}")),
            &next
        );
        assert_eq!(
            fs::read(directory.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("published bytes read failed: {error}")),
            next.canonical_wire()
        );
        drop(store);
        let reopened = open_fixture(directory.path(), &next)
            .unwrap_or_else(|error| panic!("published Runtime store reopen failed: {error}"));
        assert_eq!(
            reopened
                .snapshot()
                .unwrap_or_else(|error| panic!("reopened snapshot unavailable: {error}")),
            &next
        );

        let invalid_directory = fixture_with_snapshot(&previous);
        let mut invalid_store = open_fixture(invalid_directory.path(), &previous)
            .unwrap_or_else(|error| panic!("invalid fixture open failed: {error}"));
        assert_eq!(
            invalid_store
                .commit_with(previous.clone(), [0x52; 16], RuntimeCommitFailpoint::None,)
                .err(),
            Some(RuntimeStoreError::Journal(
                RuntimeJournalError::NonMonotonicTransition
            ))
        );
        assert_eq!(
            invalid_store.snapshot().err(),
            Some(RuntimeStoreError::Stopped)
        );
        assert_eq!(decode_active(invalid_directory.path()), previous);
    }

    #[test]
    fn commit_checks_state_successor_and_disk_before_requesting_temp_entropy() {
        let previous = idle_snapshot(0x53, 0x54);
        let next = tenure_successor(&previous);

        let invalid_directory = fixture_with_snapshot(&previous);
        let mut invalid_store = open_fixture(invalid_directory.path(), &previous)
            .unwrap_or_else(|error| panic!("invalid fixture open failed: {error}"));
        let invalid_entropy_called = Cell::new(false);
        assert_eq!(
            invalid_store
                .commit_with_entropy(previous.clone(), RuntimeCommitFailpoint::None, || {
                    invalid_entropy_called.set(true);
                    Ok([0x61; 16])
                },)
                .err(),
            Some(RuntimeStoreError::Journal(
                RuntimeJournalError::NonMonotonicTransition
            ))
        );
        assert!(!invalid_entropy_called.get());

        let stopped_entropy_called = Cell::new(false);
        assert_eq!(
            invalid_store
                .commit_with_entropy(next.clone(), RuntimeCommitFailpoint::None, || {
                    stopped_entropy_called.set(true);
                    Ok([0x62; 16])
                })
                .err(),
            Some(RuntimeStoreError::Stopped)
        );
        assert!(!stopped_entropy_called.get());

        let changed_directory = fixture_with_snapshot(&previous);
        let mut changed_store = open_fixture(changed_directory.path(), &previous)
            .unwrap_or_else(|error| panic!("changed fixture open failed: {error}"));
        let replacement_path = changed_directory.path().join("replacement");
        install_private_file(&replacement_path, previous.canonical_wire());
        fs::rename(
            &replacement_path,
            changed_directory.path().join(ACTIVE_FILE_NAME),
        )
        .unwrap_or_else(|error| panic!("changed active install failed: {error}"));
        let changed_entropy_called = Cell::new(false);
        assert_eq!(
            changed_store
                .commit_with_entropy(next.clone(), RuntimeCommitFailpoint::None, || {
                    changed_entropy_called.set(true);
                    Ok([0x63; 16])
                })
                .err(),
            Some(RuntimeStoreError::ActiveSnapshotChanged)
        );
        assert!(!changed_entropy_called.get());

        let entropy_directory = fixture_with_snapshot(&previous);
        let mut entropy_store = open_fixture(entropy_directory.path(), &previous)
            .unwrap_or_else(|error| panic!("entropy fixture open failed: {error}"));
        let entropy_called = Cell::new(false);
        let error = entropy_store
            .commit_with_entropy(next, RuntimeCommitFailpoint::None, || {
                entropy_called.set(true);
                Err(std::io::Error::other("fixture entropy unavailable"))
            })
            .expect_err("entropy failure must reject commit");
        assert!(entropy_called.get());
        assert!(matches!(
            error,
            RuntimeStoreError::Publish(RuntimePublishFailure::RejectedBeforePublish(fault))
                if fault.stage == RuntimeFileStage::GenerateTempName
        ));
        assert_eq!(
            entropy_store.snapshot().err(),
            Some(RuntimeStoreError::Stopped)
        );
        assert_eq!(decode_active(entropy_directory.path()), previous);
    }

    #[test]
    fn pre_rename_failures_keep_old_active_and_restart_discards_only_temps() {
        let failpoints = [
            RuntimeCommitFailpoint::BeforeTempCreate,
            RuntimeCommitFailpoint::AfterTempCreate,
            RuntimeCommitFailpoint::AfterPartialWrite,
            RuntimeCommitFailpoint::BeforeFileSync,
            RuntimeCommitFailpoint::AfterFileSync,
            RuntimeCommitFailpoint::BeforeRename,
        ];
        for (index, failpoint) in failpoints.into_iter().enumerate() {
            let previous = idle_snapshot(0x61, 0x62);
            let next = tenure_successor(&previous);
            let directory = fixture_with_snapshot(&previous);
            let mut store = open_fixture(directory.path(), &previous)
                .unwrap_or_else(|error| panic!("Runtime store open failed: {error}"));
            let token_byte =
                u8::try_from(index + 1).unwrap_or_else(|_| panic!("fixture token index must fit"));
            assert!(matches!(
                store.commit_with(next, [token_byte; 16], failpoint),
                Err(RuntimeStoreError::Publish(
                    RuntimePublishFailure::RejectedBeforePublish(_)
                ))
            ));
            assert_eq!(store.snapshot().err(), Some(RuntimeStoreError::Stopped));
            assert_eq!(decode_active(directory.path()), previous);
            drop(store);

            let reopened = open_fixture(directory.path(), &previous).unwrap_or_else(|error| {
                panic!("old authoritative Runtime store failed to reopen: {error}")
            });
            assert_eq!(
                reopened
                    .snapshot()
                    .unwrap_or_else(|error| panic!("reopened snapshot unavailable: {error}")),
                &previous
            );
            assert_eq!(orphan_count(directory.path()), 0);
        }
    }

    #[test]
    fn post_rename_uncertainty_stops_owner_and_restart_selects_exact_new_active() {
        for (index, failpoint) in [
            RuntimeCommitFailpoint::AfterRename,
            RuntimeCommitFailpoint::BeforeDirectorySync,
            RuntimeCommitFailpoint::AfterDirectorySyncBeforeReturn,
        ]
        .into_iter()
        .enumerate()
        {
            let previous = idle_snapshot(0x71, 0x72);
            let next = tenure_successor(&previous);
            let directory = fixture_with_snapshot(&previous);
            let mut store = open_fixture(directory.path(), &previous)
                .unwrap_or_else(|error| panic!("Runtime store open failed: {error}"));
            let token_byte =
                u8::try_from(index + 20).unwrap_or_else(|_| panic!("fixture token index must fit"));
            assert!(matches!(
                store.commit_with(next.clone(), [token_byte; 16], failpoint),
                Err(RuntimeStoreError::Publish(
                    RuntimePublishFailure::UncertainAfterPublish(_)
                ))
            ));
            assert_eq!(store.snapshot().err(), Some(RuntimeStoreError::Stopped));
            assert_eq!(decode_active(directory.path()), next);
            drop(store);

            let reopened = open_fixture(directory.path(), &next).unwrap_or_else(|error| {
                panic!("new authoritative Runtime store failed to reopen: {error}")
            });
            assert_eq!(
                reopened
                    .snapshot()
                    .unwrap_or_else(|error| panic!("reopened snapshot unavailable: {error}")),
                &next
            );
        }
    }

    #[test]
    fn restart_never_promotes_temp_and_only_cleans_after_valid_active_wins() {
        let previous = idle_snapshot(0x81, 0x82);
        let next = tenure_successor(&previous);

        let invalid_active = fixture_with_snapshot(&previous);
        let orphan = install_orphan(invalid_active.path(), [0x31; 16], next.canonical_wire());
        let mut corrupt = previous.canonical_wire().to_vec();
        corrupt[0] ^= 1;
        install_private_file(&invalid_active.path().join(ACTIVE_FILE_NAME), &corrupt);
        assert!(matches!(
            open_fixture(invalid_active.path(), &previous),
            Err(RuntimeStoreOpenError::Journal(_))
        ));
        assert!(orphan.is_file());

        let valid_active = fixture_with_snapshot(&previous);
        let higher_temp = install_orphan(valid_active.path(), [0x32; 16], next.canonical_wire());
        let store = open_fixture(valid_active.path(), &previous)
            .unwrap_or_else(|error| panic!("valid active with orphan rejected: {error}"));
        assert_eq!(
            store
                .snapshot()
                .unwrap_or_else(|error| panic!("authoritative snapshot unavailable: {error}")),
            &previous
        );
        assert!(!higher_temp.exists());
        assert_eq!(decode_active(valid_active.path()), previous);
    }

    #[test]
    fn orphan_scan_is_all_or_nothing_for_unknown_entries_and_capacity() {
        let snapshot = sequence_one_snapshot(0x91, 0x92);
        let unknown = fixture_with_snapshot(&snapshot);
        let orphan = install_orphan(unknown.path(), [0x41; 16], b"orphan");
        install_private_file(&unknown.path().join("unexpected"), b"unknown");
        assert_eq!(
            open_fixture(unknown.path(), &snapshot).err(),
            Some(RuntimeStoreOpenError::UnknownDirectoryEntry)
        );
        assert!(orphan.is_file());

        let overflow = fixture_with_snapshot(&snapshot);
        let mut orphans = Vec::new();
        for index in 0..=MAX_ORPHAN_TEMP_FILES {
            let mut token = [0_u8; 16];
            token[14..].copy_from_slice(
                &u16::try_from(index + 1)
                    .unwrap_or_else(|_| panic!("fixture orphan index must fit"))
                    .to_be_bytes(),
            );
            orphans.push(install_orphan(overflow.path(), token, b"orphan"));
        }
        assert_eq!(
            open_fixture(overflow.path(), &snapshot).err(),
            Some(RuntimeStoreOpenError::TooManyOrphanTemps)
        );
        assert!(orphans.iter().all(|path| path.is_file()));
    }

    #[test]
    fn initializer_subprocess_crashes_consume_marker_and_never_invent_active_state() {
        let cases = [
            ("temp-create", false, Some(0_usize)),
            ("partial-write", false, None),
            ("before-file-fsync", false, None),
            ("file-fsync", false, None),
            ("rename", true, None),
            ("directory-fsync", true, None),
            ("durable-commit-before-return", true, None),
        ];
        for (point, published, fixed_temp_length) in cases {
            let directory = TestDirectory::new();
            let expected = sequence_one_snapshot(0xb3, 0xb4);
            let status = Command::new(
                std::env::current_exe()
                    .unwrap_or_else(|error| panic!("test executable lookup failed: {error}")),
            )
            .args([
                "--exact",
                "runtime_store::tests::subprocess_initializer_crash_child",
                "--nocapture",
            ])
            .env(
                "PARAEGOX_TEST_RUNTIME_INITIALIZER_CRASH_STORE",
                directory.path(),
            )
            .env("PARAEGOX_TEST_RUNTIME_INITIALIZER_CRASH_POINT", point)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|error| panic!("initializer crash child spawn failed: {error}"));
            assert!(
                !status.success(),
                "initializer crash child returned at {point}"
            );

            let marker = fs::symlink_metadata(directory.path().join(LOCK_FILE_NAME))
                .unwrap_or_else(|error| panic!("initializer marker metadata failed: {error}"));
            assert!(marker.file_type().is_file());
            assert_eq!(
                marker.mode() & PRIVATE_FILE_MODE_MASK,
                PRIVATE_FILE_MODE_BITS
            );
            assert_eq!(marker.nlink(), 1);
            assert!(matches!(
                RuntimeInitializerGuard::begin_with_policy(
                    directory.path(),
                    RuntimeFilesystemPolicy::ExplicitFixture,
                ),
                Err(RuntimeInitializerBeginError::MarkerConsumed(_))
            ));
            if published {
                assert_eq!(decode_active(directory.path()), expected);
                assert!(
                    !directory
                        .path()
                        .join(temp_name([0x72; TEMP_TOKEN_BYTES]))
                        .exists()
                );
                let recovered = open_fixture(directory.path(), &expected).unwrap_or_else(|error| {
                    panic!("published initializer state did not reopen at {point}: {error}")
                });
                assert_eq!(recovered.snapshot(), Ok(&expected));
                assert_eq!(orphan_count(directory.path()), 0);
            } else {
                assert!(!directory.path().join(ACTIVE_FILE_NAME).exists());
                let candidate = directory.path().join(temp_name([0x72; TEMP_TOKEN_BYTES]));
                let candidate_bytes = fs::read(&candidate).unwrap_or_else(|error| {
                    panic!("initializer candidate read failed at {point}: {error}")
                });
                let expected_bytes = match point {
                    "temp-create" => &[][..],
                    "partial-write" => {
                        &expected.canonical_wire()[..expected.canonical_wire().len() - 1]
                    }
                    "before-file-fsync" | "file-fsync" => expected.canonical_wire(),
                    _ => panic!("missing initializer temp bytes for {point}"),
                };
                assert_eq!(candidate_bytes, expected_bytes);
                assert_eq!(
                    candidate_bytes.len(),
                    fixed_temp_length.unwrap_or(expected_bytes.len())
                );
                assert_eq!(orphan_count(directory.path()), 1);
                assert!(matches!(
                    open_fixture(directory.path(), &expected),
                    Err(RuntimeStoreOpenError::Io(failure))
                        if failure.stage == RuntimeFileStage::OpenActive
                            && failure.kind == std::io::ErrorKind::NotFound
                ));
                assert!(candidate.is_file());
                assert_eq!(orphan_count(directory.path()), 1);
            }
        }
    }

    #[test]
    fn subprocess_initializer_crash_child() {
        let Some(store) = std::env::var_os("PARAEGOX_TEST_RUNTIME_INITIALIZER_CRASH_STORE") else {
            return;
        };
        let point = std::env::var("PARAEGOX_TEST_RUNTIME_INITIALIZER_CRASH_POINT")
            .unwrap_or_else(|error| panic!("initializer crash point missing: {error}"));
        let failpoint = match point.as_str() {
            "temp-create" => RuntimeCommitFailpoint::AbortAfterTempCreate,
            "partial-write" => RuntimeCommitFailpoint::AbortAfterPartialWrite,
            "before-file-fsync" => RuntimeCommitFailpoint::AbortBeforeFileSync,
            "file-fsync" => RuntimeCommitFailpoint::AbortAfterFileSync,
            "rename" => RuntimeCommitFailpoint::AbortAfterRename,
            "directory-fsync" => RuntimeCommitFailpoint::AbortAfterDirectorySync,
            "durable-commit-before-return" => {
                RuntimeCommitFailpoint::AbortAfterDurableCommitBeforeReturn
            }
            _ => panic!("unknown Runtime initializer crash point"),
        };
        let mut initializer = RuntimeInitializerGuard::begin_with_policy(
            Path::new(&store),
            RuntimeFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("crash child initializer begin failed: {error}"));
        let result = initializer.publish_sequence_one_with(
            sequence_one_snapshot(0xb3, 0xb4),
            [0x72; TEMP_TOKEN_BYTES],
            failpoint,
        );
        panic!("Runtime initializer crash failpoint unexpectedly returned: {result:?}");
    }

    #[test]
    fn subprocess_crashes_leave_only_the_strict_old_or_new_active_snapshot() {
        let cases = [
            ("temp-create", false),
            ("partial-write", false),
            ("before-file-fsync", false),
            ("file-fsync", false),
            ("rename", true),
            ("directory-fsync", true),
            ("durable-commit-before-return", true),
        ];
        for (point, published) in cases {
            let previous = idle_snapshot(0xb1, 0xb2);
            let next = tenure_successor(&previous);
            let directory = fixture_with_snapshot(&previous);
            let status = Command::new(
                std::env::current_exe()
                    .unwrap_or_else(|error| panic!("test executable lookup failed: {error}")),
            )
            .args([
                "--exact",
                "runtime_store::tests::subprocess_publish_crash_child",
                "--nocapture",
            ])
            .env("PARAEGOX_TEST_RUNTIME_CRASH_STORE", directory.path())
            .env("PARAEGOX_TEST_RUNTIME_CRASH_POINT", point)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|error| panic!("crash child spawn failed: {error}"));
            assert!(!status.success(), "crash child returned at {point}");

            let expected = if published { &next } else { &previous };
            let recovered = open_fixture(directory.path(), expected)
                .unwrap_or_else(|error| panic!("post-crash open failed at {point}: {error}"));
            assert_eq!(
                recovered.snapshot().unwrap_or_else(|error| {
                    panic!("post-crash snapshot unavailable at {point}: {error}")
                }),
                expected
            );
            assert_eq!(decode_active(directory.path()), expected.clone());
            assert_eq!(orphan_count(directory.path()), 0);
        }
    }

    #[test]
    fn subprocess_publish_crash_child() {
        let Some(store) = std::env::var_os("PARAEGOX_TEST_RUNTIME_CRASH_STORE") else {
            return;
        };
        let point = std::env::var("PARAEGOX_TEST_RUNTIME_CRASH_POINT")
            .unwrap_or_else(|error| panic!("crash point missing: {error}"));
        let failpoint = match point.as_str() {
            "temp-create" => RuntimeCommitFailpoint::AbortAfterTempCreate,
            "partial-write" => RuntimeCommitFailpoint::AbortAfterPartialWrite,
            "before-file-fsync" => RuntimeCommitFailpoint::AbortBeforeFileSync,
            "file-fsync" => RuntimeCommitFailpoint::AbortAfterFileSync,
            "rename" => RuntimeCommitFailpoint::AbortAfterRename,
            "directory-fsync" => RuntimeCommitFailpoint::AbortAfterDirectorySync,
            "durable-commit-before-return" => {
                RuntimeCommitFailpoint::AbortAfterDurableCommitBeforeReturn
            }
            _ => panic!("unknown Runtime crash point"),
        };
        let previous = idle_snapshot(0xb1, 0xb2);
        let next = tenure_successor(&previous);
        let mut runtime = open_fixture(Path::new(&store), &previous)
            .unwrap_or_else(|error| panic!("crash child Runtime open failed: {error}"));
        let result = runtime.commit_with(next, [0x71; 16], failpoint);
        panic!("Runtime crash failpoint unexpectedly returned: {result:?}");
    }

    #[test]
    fn lock_descriptor_closes_across_exec_even_when_spawned_child_survives_owner() {
        let snapshot = sequence_one_snapshot(0xc1, 0xc2);
        let directory = fixture_with_snapshot(&snapshot);
        let marker_root = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|error| panic!("marker root canonicalize failed: {error}"));
        let marker = marker_root.join(format!(
            "paraegox-runtime-lock-child-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let status = Command::new(
            std::env::current_exe()
                .unwrap_or_else(|error| panic!("test executable lookup failed: {error}")),
        )
        .args([
            "--exact",
            "runtime_store::tests::subprocess_lock_owner_child",
            "--nocapture",
        ])
        .env("PARAEGOX_TEST_RUNTIME_LOCK_STORE", directory.path())
        .env("PARAEGOX_TEST_RUNTIME_LOCK_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|error| panic!("lock owner child spawn failed: {error}"));
        assert!(!status.success(), "lock owner child unexpectedly returned");
        let sleeper_pid = fs::read_to_string(&marker)
            .unwrap_or_else(|error| panic!("sleeper marker read failed: {error}"));

        let replacement = open_fixture(directory.path(), &snapshot);
        let _ = Command::new("/bin/kill").arg(sleeper_pid.trim()).status();
        let _ = fs::remove_file(&marker);
        replacement.unwrap_or_else(|error| {
            panic!("replacement could not acquire CLOEXEC-protected Runtime lock: {error}")
        });
    }

    #[test]
    fn subprocess_lock_owner_child() {
        let Some(store) = std::env::var_os("PARAEGOX_TEST_RUNTIME_LOCK_STORE") else {
            return;
        };
        let marker = std::env::var_os("PARAEGOX_TEST_RUNTIME_LOCK_MARKER")
            .unwrap_or_else(|| panic!("lock marker missing"));
        let snapshot = sequence_one_snapshot(0xc1, 0xc2);
        let _runtime = open_fixture(Path::new(&store), &snapshot)
            .unwrap_or_else(|error| panic!("lock child Runtime open failed: {error}"));
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

    #[test]
    fn opened_directory_descriptor_cannot_be_redirected_by_path_replacement() {
        let previous = idle_snapshot(0xa1, 0xa2);
        let next = tenure_successor(&previous);
        let configured = fixture_with_snapshot(&previous);
        let mut store = open_fixture(configured.path(), &previous)
            .unwrap_or_else(|error| panic!("Runtime store open failed: {error}"));
        let configured_path = configured.path().to_path_buf();
        let retained_path = configured_path.with_extension("opened-directory");
        fs::rename(&configured_path, &retained_path)
            .unwrap_or_else(|error| panic!("configured directory rename failed: {error}"));
        fs::create_dir(&configured_path)
            .unwrap_or_else(|error| panic!("replacement directory create failed: {error}"));
        set_mode(&configured_path, 0o700);
        install_private_file(&configured_path.join("attacker-marker"), b"replacement");

        store
            .commit_with(next.clone(), [0x51; 16], RuntimeCommitFailpoint::None)
            .unwrap_or_else(|error| panic!("descriptor-relative commit failed: {error}"));
        assert_eq!(decode_active(&retained_path), next);
        assert!(!configured_path.join(ACTIVE_FILE_NAME).exists());
        assert_eq!(
            fs::read(configured_path.join("attacker-marker"))
                .unwrap_or_else(|error| panic!("replacement marker read failed: {error}")),
            b"replacement"
        );

        drop(store);
        fs::remove_dir_all(&configured_path)
            .unwrap_or_else(|error| panic!("replacement cleanup failed: {error}"));
        fs::rename(&retained_path, &configured_path)
            .unwrap_or_else(|error| panic!("configured directory restore failed: {error}"));
    }
}
