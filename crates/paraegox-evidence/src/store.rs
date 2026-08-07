use core::{fmt, num::NonZeroU64};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

use nix::fcntl::{OFlag, open, openat, renameat};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};

use crate::{
    EVIDENCE_RECORD_HEADER_BYTES, EvidenceCommitReceiptV1, EvidenceContractError,
    EvidenceOwnerRefV1, EvidenceRecordIdV1, EvidenceRecordV1, EvidenceRefV1, EvidenceStoreEpochV1,
    MAX_EVIDENCE_RECORD_BYTES,
};

const STORE_LOCK_FILE: &str = ".writer.lock";
const STORE_DATA_FILE: &str = "evidence.pxes";
const STORE_TEMP_FILE: &str = ".evidence.pxes.initializing";
const STORE_MAGIC: &[u8; 4] = b"PXES";
const STORE_VERSION: u16 = 1;
const STORE_HEADER_BYTES: usize = 96;
const STORE_HEADER_DIGEST_DOMAIN: &[u8] = b"paraegox.evidence.store-header.v1";
const FRAME_MAGIC: &[u8; 4] = b"PXEF";
const FRAME_VERSION: u16 = 1;
const FRAME_HEADER_BYTES: usize = 112;
const FRAME_DIGEST_DOMAIN: &[u8] = b"paraegox.evidence.store-frame.v1";
const PRIVATE_DIRECTORY_MODE_BITS: u32 = 0o700;
const PRIVATE_FILE_MODE_BITS: u32 = 0o600;
const PRIVATE_MODE_MASK: u32 = 0o7777;
const PRIVATE_FILE_MODE: Mode = Mode::S_IRUSR.union(Mode::S_IWUSR);
const MIN_STORE_BYTES: u64 =
    (STORE_HEADER_BYTES + FRAME_HEADER_BYTES + EVIDENCE_RECORD_HEADER_BYTES) as u64;

/// Largest page accepted by the local query surface.
pub const MAX_EVIDENCE_QUERY_RECORDS: usize = 256;
/// Hard record-capacity ceiling for one v1 local store.
pub const MAX_EVIDENCE_STORE_RECORDS: u64 = 1_000_000;
/// Hard byte-capacity ceiling for one v1 local store (four GiB).
pub const MAX_EVIDENCE_STORE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Immutable hard capacity pinned into a store header.
///
/// V1 never evicts or compacts authoritative Evidence. Reaching either bound
/// returns `StorageFull`; changing a bound requires a new store epoch and an
/// explicit migration outside this owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceRetentionPolicyV1 {
    max_records: NonZeroU64,
    max_store_bytes: NonZeroU64,
}

impl EvidenceRetentionPolicyV1 {
    /// Constructs bounded capacity for one store epoch.
    pub fn try_new(max_records: u64, max_store_bytes: u64) -> Result<Self, EvidenceStoreError> {
        let max_records = NonZeroU64::new(max_records)
            .filter(|value| value.get() <= MAX_EVIDENCE_STORE_RECORDS)
            .ok_or(EvidenceStoreError::InvalidRetentionPolicy)?;
        let max_store_bytes = NonZeroU64::new(max_store_bytes)
            .filter(|value| {
                value.get() >= MIN_STORE_BYTES && value.get() <= MAX_EVIDENCE_STORE_BYTES
            })
            .ok_or(EvidenceStoreError::InvalidRetentionPolicy)?;
        Ok(Self {
            max_records,
            max_store_bytes,
        })
    }

    #[must_use]
    pub const fn max_records(self) -> u64 {
        self.max_records.get()
    }

    #[must_use]
    pub const fn max_store_bytes(self) -> u64 {
        self.max_store_bytes.get()
    }
}

/// One record together with its local durable reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceStoredRecordV1 {
    evidence_ref: EvidenceRefV1,
    record: EvidenceRecordV1,
}

impl EvidenceStoredRecordV1 {
    #[must_use]
    pub const fn evidence_ref(&self) -> EvidenceRefV1 {
        self.evidence_ref
    }

    #[must_use]
    pub const fn record(&self) -> &EvidenceRecordV1 {
        &self.record
    }
}

/// Result of one append or exact idempotent replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceAppendOutcomeV1 {
    Committed(EvidenceCommitReceiptV1),
    Replayed(EvidenceCommitReceiptV1),
}

impl EvidenceAppendOutcomeV1 {
    #[must_use]
    pub const fn commit_receipt(self) -> EvidenceCommitReceiptV1 {
        match self {
            Self::Committed(receipt) | Self::Replayed(receipt) => receipt,
        }
    }

    #[must_use]
    pub const fn replayed(self) -> bool {
        matches!(self, Self::Replayed(_))
    }
}

/// Opaque continuation bound to one exact store epoch and local sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceListCursorV1 {
    store_epoch: EvidenceStoreEpochV1,
    next_local_sequence: NonZeroU64,
}

impl EvidenceListCursorV1 {
    #[must_use]
    pub const fn store_epoch(self) -> EvidenceStoreEpochV1 {
        self.store_epoch
    }

    #[must_use]
    pub const fn next_local_sequence(self) -> u64 {
        self.next_local_sequence.get()
    }
}

/// One bounded, local-sequence-ordered query page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceListPageV1 {
    records: Box<[EvidenceStoredRecordV1]>,
    next_cursor: Option<EvidenceListCursorV1>,
}

impl EvidenceListPageV1 {
    #[must_use]
    pub fn records(&self) -> &[EvidenceStoredRecordV1] {
        &self.records
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<EvidenceListCursorV1> {
        self.next_cursor
    }
}

/// Fail-closed local store errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStoreError {
    Io(io::ErrorKind),
    InvalidPath,
    InsecureDirectory,
    InsecureFile,
    UnexpectedStoreEntry,
    LockContended,
    InvalidRetentionPolicy,
    TruncatedStoreHeader,
    UnsupportedStoreHeader,
    NonCanonicalStoreHeader,
    StoreHeaderDigestMismatch,
    StoreEpochMismatch,
    RetentionPolicyMismatch,
    StoreBoundsExceeded,
    UnsupportedFrameHeader,
    NonCanonicalFrameHeader,
    FrameDigestMismatch,
    LocalSequenceDiscontinuity,
    RecordIdConflict,
    OwnerSequenceConflict,
    CausalityConflict,
    StorageFull,
    InvalidQueryLimit,
    CursorEpochMismatch,
    CursorOutOfRange,
    ReferenceMismatch,
    Contract(EvidenceContractError),
    Digest(DigestBuildError),
    RecoveryUncertain(io::ErrorKind),
    CommitUncertain(io::ErrorKind),
    Poisoned,
}

impl fmt::Display for EvidenceStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "local Evidence store rejected operation: {self:?}"
        )
    }
}

impl std::error::Error for EvidenceStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Digest(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EvidenceContractError> for EvidenceStoreError {
    fn from(error: EvidenceContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<DigestBuildError> for EvidenceStoreError {
    fn from(error: DigestBuildError) -> Self {
        Self::Digest(error)
    }
}

#[derive(Clone, Copy)]
struct OwnerHead {
    producer_sequence: u64,
    record_id: EvidenceRecordIdV1,
}

struct LoadedStore {
    records: Vec<EvidenceStoredRecordV1>,
    record_index: HashMap<EvidenceRecordIdV1, usize>,
    owner_heads: HashMap<EvidenceOwnerRefV1, OwnerHead>,
    durable_bytes: u64,
}

/// Single-writer, append-only local Unix Evidence store.
///
/// This is a same-user local durability baseline. It is not a replication
/// protocol, an Ops service, a global order, or a ProductionReference
/// filesystem support claim.
pub struct LocalEvidenceStoreV1 {
    _directory: File,
    _writer_lock: File,
    data_file: File,
    store_epoch: EvidenceStoreEpochV1,
    retention_policy: EvidenceRetentionPolicyV1,
    records: Vec<EvidenceStoredRecordV1>,
    record_index: HashMap<EvidenceRecordIdV1, usize>,
    owner_heads: HashMap<EvidenceOwnerRefV1, OwnerHead>,
    durable_bytes: u64,
    poisoned: bool,
    #[cfg(test)]
    append_fault: Option<TestAppendFault>,
}

impl LocalEvidenceStoreV1 {
    /// Opens or creates one exact store epoch under an owner-private directory.
    pub fn open(
        root: &Path,
        expected_store_epoch: EvidenceStoreEpochV1,
        retention_policy: EvidenceRetentionPolicyV1,
    ) -> Result<Self, EvidenceStoreError> {
        let directory = open_or_create_store_directory(root)?;
        let writer_lock = open_or_create_lock(&directory)?;
        try_lock(&writer_lock)?;
        let mut data_file =
            open_or_initialize_data(&directory, expected_store_epoch, retention_policy)?;
        validate_store_entries(root)?;
        validate_path_still_names_directory(root, &directory)?;
        let loaded = load_store(&mut data_file, expected_store_epoch, retention_policy)?;
        data_file
            .seek(SeekFrom::Start(loaded.durable_bytes))
            .map_err(io_error)?;
        Ok(Self {
            _directory: directory,
            _writer_lock: writer_lock,
            data_file,
            store_epoch: expected_store_epoch,
            retention_policy,
            records: loaded.records,
            record_index: loaded.record_index,
            owner_heads: loaded.owner_heads,
            durable_bytes: loaded.durable_bytes,
            poisoned: false,
            #[cfg(test)]
            append_fault: None,
        })
    }

    #[must_use]
    pub const fn store_epoch(&self) -> EvidenceStoreEpochV1 {
        self.store_epoch
    }

    #[must_use]
    pub const fn retention_policy(&self) -> EvidenceRetentionPolicyV1 {
        self.retention_policy
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub const fn durable_bytes(&self) -> u64 {
        self.durable_bytes
    }

    /// Commits exactly one canonical record and synchronizes it before ack.
    pub fn append(
        &mut self,
        record: EvidenceRecordV1,
    ) -> Result<EvidenceAppendOutcomeV1, EvidenceStoreError> {
        self.ensure_usable()?;
        if let Some(index) = self.record_index.get(&record.record_id()).copied() {
            let stored = &self.records[index];
            if stored.record.record_digest() != record.record_digest()
                || stored.record.canonical_wire() != record.canonical_wire()
            {
                return Err(EvidenceStoreError::RecordIdConflict);
            }
            let receipt = EvidenceCommitReceiptV1::new(stored.evidence_ref, true);
            return Ok(EvidenceAppendOutcomeV1::Replayed(receipt));
        }

        validate_owner_progression(&self.owner_heads, &record)?;
        let local_sequence = u64::try_from(self.records.len())
            .map_err(|_| EvidenceStoreError::StorageFull)?
            .checked_add(1)
            .ok_or(EvidenceStoreError::StorageFull)?;
        if local_sequence > self.retention_policy.max_records() {
            return Err(EvidenceStoreError::StorageFull);
        }
        let evidence_ref = EvidenceRefV1::try_new(
            self.store_epoch,
            local_sequence,
            record.record_id(),
            record.record_digest(),
        )?;
        let frame = encode_frame(self.store_epoch, evidence_ref, &record)?;
        let frame_bytes =
            u64::try_from(frame.len()).map_err(|_| EvidenceStoreError::StorageFull)?;
        let next_bytes = self
            .durable_bytes
            .checked_add(frame_bytes)
            .ok_or(EvidenceStoreError::StorageFull)?;
        if next_bytes > self.retention_policy.max_store_bytes() {
            return Err(EvidenceStoreError::StorageFull);
        }

        if let Err(error) = self.write_and_sync_frame(&frame) {
            self.poisoned = true;
            return Err(error);
        }

        let owner_ref = record.owner_ref();
        let record_id = record.record_id();
        let producer_sequence = record.producer_sequence();
        let index = self.records.len();
        self.records.push(EvidenceStoredRecordV1 {
            evidence_ref,
            record,
        });
        self.record_index.insert(record_id, index);
        self.owner_heads.insert(
            owner_ref,
            OwnerHead {
                producer_sequence,
                record_id,
            },
        );
        self.durable_bytes = next_bytes;
        Ok(EvidenceAppendOutcomeV1::Committed(
            EvidenceCommitReceiptV1::new(evidence_ref, false),
        ))
    }

    /// Reads one record by its owner-issued id.
    pub fn read(
        &self,
        record_id: EvidenceRecordIdV1,
    ) -> Result<Option<EvidenceStoredRecordV1>, EvidenceStoreError> {
        self.ensure_usable()?;
        Ok(self
            .record_index
            .get(&record_id)
            .map(|index| self.records[*index].clone()))
    }

    /// Resolves a complete local reference and rejects any mismatched field.
    pub fn read_ref(
        &self,
        evidence_ref: EvidenceRefV1,
    ) -> Result<EvidenceStoredRecordV1, EvidenceStoreError> {
        self.ensure_usable()?;
        if evidence_ref.store_epoch() != self.store_epoch {
            return Err(EvidenceStoreError::ReferenceMismatch);
        }
        let index = usize::try_from(
            evidence_ref
                .local_sequence()
                .checked_sub(1)
                .ok_or(EvidenceStoreError::ReferenceMismatch)?,
        )
        .map_err(|_| EvidenceStoreError::ReferenceMismatch)?;
        let stored = self
            .records
            .get(index)
            .ok_or(EvidenceStoreError::ReferenceMismatch)?;
        if stored.evidence_ref != evidence_ref {
            return Err(EvidenceStoreError::ReferenceMismatch);
        }
        Ok(stored.clone())
    }

    /// Lists a bounded page in durable local sequence order.
    pub fn list(
        &self,
        cursor: Option<EvidenceListCursorV1>,
        limit: usize,
    ) -> Result<EvidenceListPageV1, EvidenceStoreError> {
        self.ensure_usable()?;
        if limit == 0 || limit > MAX_EVIDENCE_QUERY_RECORDS {
            return Err(EvidenceStoreError::InvalidQueryLimit);
        }
        let next_sequence = match cursor {
            Some(cursor) => {
                if cursor.store_epoch != self.store_epoch {
                    return Err(EvidenceStoreError::CursorEpochMismatch);
                }
                cursor.next_local_sequence.get()
            }
            None => 1,
        };
        let start = usize::try_from(
            next_sequence
                .checked_sub(1)
                .ok_or(EvidenceStoreError::CursorOutOfRange)?,
        )
        .map_err(|_| EvidenceStoreError::CursorOutOfRange)?;
        if start > self.records.len() {
            return Err(EvidenceStoreError::CursorOutOfRange);
        }
        let end = start.saturating_add(limit).min(self.records.len());
        let records = self.records[start..end].to_vec().into_boxed_slice();
        let next_cursor = if end < self.records.len() {
            let next_local_sequence = u64::try_from(end)
                .ok()
                .and_then(|value| value.checked_add(1))
                .and_then(NonZeroU64::new)
                .ok_or(EvidenceStoreError::CursorOutOfRange)?;
            Some(EvidenceListCursorV1 {
                store_epoch: self.store_epoch,
                next_local_sequence,
            })
        } else {
            None
        };
        Ok(EvidenceListPageV1 {
            records,
            next_cursor,
        })
    }

    fn ensure_usable(&self) -> Result<(), EvidenceStoreError> {
        if self.poisoned {
            Err(EvidenceStoreError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn write_and_sync_frame(&mut self, frame: &[u8]) -> Result<(), EvidenceStoreError> {
        #[cfg(test)]
        if let Some(fault) = self.append_fault.take() {
            match fault {
                TestAppendFault::AfterPartialWrite => {
                    let partial = frame.len() / 2;
                    self.data_file
                        .write_all(&frame[..partial])
                        .map_err(commit_uncertain)?;
                    self.data_file.sync_all().map_err(commit_uncertain)?;
                    return Err(EvidenceStoreError::CommitUncertain(io::ErrorKind::Other));
                }
                TestAppendFault::AfterSyncBeforeAck => {
                    self.data_file.write_all(frame).map_err(commit_uncertain)?;
                    self.data_file.sync_all().map_err(commit_uncertain)?;
                    return Err(EvidenceStoreError::CommitUncertain(io::ErrorKind::Other));
                }
            }
        }
        self.data_file.write_all(frame).map_err(commit_uncertain)?;
        self.data_file.sync_all().map_err(commit_uncertain)
    }

    #[cfg(test)]
    fn inject_append_fault(&mut self, fault: TestAppendFault) {
        self.append_fault = Some(fault);
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestAppendFault {
    AfterPartialWrite,
    AfterSyncBeforeAck,
}

fn validate_owner_progression(
    owner_heads: &HashMap<EvidenceOwnerRefV1, OwnerHead>,
    record: &EvidenceRecordV1,
) -> Result<(), EvidenceStoreError> {
    match owner_heads.get(&record.owner_ref()).copied() {
        None => {
            if record.producer_sequence() != 1 {
                return Err(EvidenceStoreError::OwnerSequenceConflict);
            }
            if record.previous_evidence_ref().is_some() {
                return Err(EvidenceStoreError::CausalityConflict);
            }
        }
        Some(head) => {
            let expected_sequence = head
                .producer_sequence
                .checked_add(1)
                .ok_or(EvidenceStoreError::OwnerSequenceConflict)?;
            if record.producer_sequence() != expected_sequence {
                return Err(EvidenceStoreError::OwnerSequenceConflict);
            }
            if record.previous_evidence_ref() != Some(head.record_id) {
                return Err(EvidenceStoreError::CausalityConflict);
            }
        }
    }
    Ok(())
}

fn open_or_create_store_directory(root: &Path) -> Result<File, EvidenceStoreError> {
    if !root.is_absolute() || root.parent().is_none() {
        return Err(EvidenceStoreError::InvalidPath);
    }
    let created = match fs::symlink_metadata(root) {
        Ok(metadata) => {
            validate_directory_metadata(&metadata)?;
            false
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder
                .mode(PRIVATE_DIRECTORY_MODE_BITS)
                .create(root)
                .map_err(io_error)?;
            true
        }
        Err(error) => return Err(io_error(error)),
    };
    let before = fs::symlink_metadata(root).map_err(io_error)?;
    validate_directory_metadata(&before)?;
    let owned = open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    let directory = File::from(owned);
    let after = directory.metadata().map_err(io_error)?;
    validate_directory_metadata(&after)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(EvidenceStoreError::InsecureDirectory);
    }
    if created {
        sync_directory(root.parent().ok_or(EvidenceStoreError::InvalidPath)?)?;
    }
    Ok(directory)
}

fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), EvidenceStoreError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & PRIVATE_MODE_MASK != PRIVATE_DIRECTORY_MODE_BITS
    {
        return Err(EvidenceStoreError::InsecureDirectory);
    }
    Ok(())
}

fn validate_path_still_names_directory(
    root: &Path,
    directory: &File,
) -> Result<(), EvidenceStoreError> {
    let path_metadata = fs::symlink_metadata(root).map_err(io_error)?;
    let descriptor_metadata = directory.metadata().map_err(io_error)?;
    validate_directory_metadata(&path_metadata)?;
    if path_metadata.dev() != descriptor_metadata.dev()
        || path_metadata.ino() != descriptor_metadata.ino()
    {
        return Err(EvidenceStoreError::InsecureDirectory);
    }
    Ok(())
}

fn open_or_create_lock(directory: &File) -> Result<File, EvidenceStoreError> {
    match openat(
        directory,
        STORE_LOCK_FILE,
        OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(owned) => {
            let file = File::from(owned);
            validate_private_file(&file)?;
            Ok(file)
        }
        Err(nix::errno::Errno::ENOENT) => {
            let owned = openat(
                directory,
                STORE_LOCK_FILE,
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                PRIVATE_FILE_MODE,
            )
            .map_err(nix_error)?;
            let file = File::from(owned);
            fchmod(&file, PRIVATE_FILE_MODE).map_err(nix_error)?;
            validate_private_file(&file)?;
            file.sync_all().map_err(io_error)?;
            directory.sync_all().map_err(io_error)?;
            Ok(file)
        }
        Err(error) => Err(nix_error(error)),
    }
}

fn try_lock(file: &File) -> Result<(), EvidenceStoreError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => EvidenceStoreError::LockContended,
        TryLockError::Error(error) => io_error(error),
    })
}

fn open_or_initialize_data(
    directory: &File,
    store_epoch: EvidenceStoreEpochV1,
    policy: EvidenceRetentionPolicyV1,
) -> Result<File, EvidenceStoreError> {
    match open_existing_data(directory) {
        Ok(file) => {
            if entry_exists(directory, STORE_TEMP_FILE)? {
                return Err(EvidenceStoreError::UnexpectedStoreEntry);
            }
            Ok(file)
        }
        Err(EvidenceStoreError::Io(io::ErrorKind::NotFound)) => {
            remove_stale_initialization_file(directory)?;
            let header = encode_store_header(store_epoch, policy)?;
            let owned = openat(
                directory,
                STORE_TEMP_FILE,
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                PRIVATE_FILE_MODE,
            )
            .map_err(nix_error)?;
            let mut temporary = File::from(owned);
            fchmod(&temporary, PRIVATE_FILE_MODE).map_err(nix_error)?;
            validate_private_file(&temporary)?;
            temporary.write_all(&header).map_err(io_error)?;
            temporary.sync_all().map_err(io_error)?;
            drop(temporary);
            renameat(directory, STORE_TEMP_FILE, directory, STORE_DATA_FILE).map_err(nix_error)?;
            directory.sync_all().map_err(io_error)?;
            open_existing_data(directory)
        }
        Err(error) => Err(error),
    }
}

fn open_existing_data(directory: &File) -> Result<File, EvidenceStoreError> {
    let owned = openat(
        directory,
        STORE_DATA_FILE,
        OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    let file = File::from(owned);
    validate_private_file(&file)?;
    Ok(file)
}

fn remove_stale_initialization_file(directory: &File) -> Result<(), EvidenceStoreError> {
    match openat(
        directory,
        STORE_TEMP_FILE,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(owned) => {
            let file = File::from(owned);
            validate_private_file(&file)?;
            drop(file);
            unlinkat(directory, STORE_TEMP_FILE, UnlinkatFlags::NoRemoveDir).map_err(nix_error)?;
            directory.sync_all().map_err(io_error)
        }
        Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(error) => Err(nix_error(error)),
    }
}

fn entry_exists(directory: &File, name: &str) -> Result<bool, EvidenceStoreError> {
    match openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(owned) => {
            let file = File::from(owned);
            validate_private_file(&file)?;
            Ok(true)
        }
        Err(nix::errno::Errno::ENOENT) => Ok(false),
        Err(error) => Err(nix_error(error)),
    }
}

fn validate_private_file(file: &File) -> Result<(), EvidenceStoreError> {
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & PRIVATE_MODE_MASK != PRIVATE_FILE_MODE_BITS
    {
        return Err(EvidenceStoreError::InsecureFile);
    }
    Ok(())
}

fn validate_store_entries(root: &Path) -> Result<(), EvidenceStoreError> {
    for entry in fs::read_dir(root).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name();
        if name != OsStr::new(STORE_LOCK_FILE) && name != OsStr::new(STORE_DATA_FILE) {
            return Err(EvidenceStoreError::UnexpectedStoreEntry);
        }
    }
    Ok(())
}

fn encode_store_header(
    store_epoch: EvidenceStoreEpochV1,
    policy: EvidenceRetentionPolicyV1,
) -> Result<[u8; STORE_HEADER_BYTES], EvidenceStoreError> {
    let digest = store_header_digest(store_epoch, policy)?;
    let mut header = [0_u8; STORE_HEADER_BYTES];
    header[..4].copy_from_slice(STORE_MAGIC);
    header[4..6].copy_from_slice(&STORE_VERSION.to_be_bytes());
    header[6..8].copy_from_slice(&(STORE_HEADER_BYTES as u16).to_be_bytes());
    header[8..24].copy_from_slice(store_epoch.as_bytes());
    header[24..32].copy_from_slice(&policy.max_records().to_be_bytes());
    header[32..40].copy_from_slice(&policy.max_store_bytes().to_be_bytes());
    header[64..96].copy_from_slice(digest.as_bytes());
    Ok(header)
}

fn decode_store_header(
    header: &[u8; STORE_HEADER_BYTES],
    expected_epoch: EvidenceStoreEpochV1,
    expected_policy: EvidenceRetentionPolicyV1,
) -> Result<(), EvidenceStoreError> {
    if &header[..4] != STORE_MAGIC
        || read_u16(&header[4..6]) != STORE_VERSION
        || usize::from(read_u16(&header[6..8])) != STORE_HEADER_BYTES
    {
        return Err(EvidenceStoreError::UnsupportedStoreHeader);
    }
    if header[40..64].iter().any(|byte| *byte != 0) {
        return Err(EvidenceStoreError::NonCanonicalStoreHeader);
    }
    let store_epoch = EvidenceStoreEpochV1::try_from_bytes(read_array(&header[8..24]))?;
    let policy =
        EvidenceRetentionPolicyV1::try_new(read_u64(&header[24..32]), read_u64(&header[32..40]))?;
    let declared_digest = Digest32::from_bytes(read_array(&header[64..96]));
    if store_header_digest(store_epoch, policy)? != declared_digest {
        return Err(EvidenceStoreError::StoreHeaderDigestMismatch);
    }
    if store_epoch != expected_epoch {
        return Err(EvidenceStoreError::StoreEpochMismatch);
    }
    if policy != expected_policy {
        return Err(EvidenceStoreError::RetentionPolicyMismatch);
    }
    Ok(())
}

fn store_header_digest(
    store_epoch: EvidenceStoreEpochV1,
    policy: EvidenceRetentionPolicyV1,
) -> Result<Digest32, EvidenceStoreError> {
    let mut builder = Digest32Builder::try_new(STORE_HEADER_DIGEST_DOMAIN)?;
    builder
        .field_bytes(STORE_MAGIC)?
        .field_u16(STORE_VERSION)?
        .field_u16(STORE_HEADER_BYTES as u16)?
        .field_bytes(store_epoch.as_bytes())?
        .field_u64(policy.max_records())?
        .field_u64(policy.max_store_bytes())?;
    Ok(builder.finish())
}

fn load_store(
    file: &mut File,
    store_epoch: EvidenceStoreEpochV1,
    policy: EvidenceRetentionPolicyV1,
) -> Result<LoadedStore, EvidenceStoreError> {
    let original_length = file.metadata().map_err(io_error)?.len();
    if original_length < STORE_HEADER_BYTES as u64 {
        return Err(EvidenceStoreError::TruncatedStoreHeader);
    }
    if original_length > policy.max_store_bytes() {
        return Err(EvidenceStoreError::StoreBoundsExceeded);
    }
    file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let mut store_header = [0_u8; STORE_HEADER_BYTES];
    file.read_exact(&mut store_header).map_err(io_error)?;
    decode_store_header(&store_header, store_epoch, policy)?;

    let mut records = Vec::new();
    let mut record_index = HashMap::new();
    let mut owner_heads = HashMap::new();
    let mut offset = STORE_HEADER_BYTES as u64;
    let mut torn_tail = false;
    while offset < original_length {
        let remaining = original_length - offset;
        if remaining < FRAME_HEADER_BYTES as u64 {
            torn_tail = true;
            break;
        }
        file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
        let mut frame_header = [0_u8; FRAME_HEADER_BYTES];
        file.read_exact(&mut frame_header).map_err(io_error)?;
        let expected_local_sequence = u64::try_from(records.len())
            .map_err(|_| EvidenceStoreError::StoreBoundsExceeded)?
            .checked_add(1)
            .ok_or(EvidenceStoreError::StoreBoundsExceeded)?;
        let parsed = decode_frame_header(&frame_header, expected_local_sequence)?;
        if parsed.frame_length > remaining {
            torn_tail = true;
            break;
        }
        let record_length = usize::try_from(parsed.record_length)
            .map_err(|_| EvidenceStoreError::NonCanonicalFrameHeader)?;
        let mut record_wire = vec![0_u8; record_length];
        file.read_exact(&mut record_wire).map_err(io_error)?;
        if frame_digest(
            store_epoch,
            parsed.local_sequence,
            parsed.record_id,
            parsed.record_digest,
            &record_wire,
        )? != parsed.frame_digest
        {
            return Err(EvidenceStoreError::FrameDigestMismatch);
        }
        let record = EvidenceRecordV1::decode(&record_wire)?;
        if record.record_id() != parsed.record_id || record.record_digest() != parsed.record_digest
        {
            return Err(EvidenceStoreError::NonCanonicalFrameHeader);
        }
        if record_index.contains_key(&record.record_id()) {
            return Err(EvidenceStoreError::RecordIdConflict);
        }
        validate_owner_progression(&owner_heads, &record)?;
        if parsed.local_sequence > policy.max_records() {
            return Err(EvidenceStoreError::StoreBoundsExceeded);
        }
        let evidence_ref = EvidenceRefV1::try_new(
            store_epoch,
            parsed.local_sequence,
            record.record_id(),
            record.record_digest(),
        )?;
        let index = records.len();
        record_index.insert(record.record_id(), index);
        owner_heads.insert(
            record.owner_ref(),
            OwnerHead {
                producer_sequence: record.producer_sequence(),
                record_id: record.record_id(),
            },
        );
        records.push(EvidenceStoredRecordV1 {
            evidence_ref,
            record,
        });
        offset = offset
            .checked_add(parsed.frame_length)
            .ok_or(EvidenceStoreError::StoreBoundsExceeded)?;
    }

    if file.metadata().map_err(io_error)?.len() != original_length {
        return Err(EvidenceStoreError::RecoveryUncertain(io::ErrorKind::Other));
    }
    if torn_tail {
        file.set_len(offset).map_err(recovery_uncertain)?;
        file.sync_all().map_err(recovery_uncertain)?;
    }
    Ok(LoadedStore {
        records,
        record_index,
        owner_heads,
        durable_bytes: offset,
    })
}

struct FrameHeader {
    frame_length: u64,
    local_sequence: u64,
    record_length: u32,
    record_id: EvidenceRecordIdV1,
    record_digest: Digest32,
    frame_digest: Digest32,
}

fn decode_frame_header(
    header: &[u8; FRAME_HEADER_BYTES],
    expected_local_sequence: u64,
) -> Result<FrameHeader, EvidenceStoreError> {
    if &header[..4] != FRAME_MAGIC
        || read_u16(&header[4..6]) != FRAME_VERSION
        || usize::from(read_u16(&header[6..8])) != FRAME_HEADER_BYTES
    {
        return Err(EvidenceStoreError::UnsupportedFrameHeader);
    }
    if header[28..32].iter().any(|byte| *byte != 0) {
        return Err(EvidenceStoreError::NonCanonicalFrameHeader);
    }
    let frame_length = read_u64(&header[8..16]);
    let local_sequence = read_u64(&header[16..24]);
    let record_length = read_u32(&header[24..28]);
    let record_length_usize =
        usize::try_from(record_length).map_err(|_| EvidenceStoreError::NonCanonicalFrameHeader)?;
    if !(EVIDENCE_RECORD_HEADER_BYTES..=MAX_EVIDENCE_RECORD_BYTES).contains(&record_length_usize)
        || frame_length
            != u64::try_from(FRAME_HEADER_BYTES + record_length_usize)
                .map_err(|_| EvidenceStoreError::NonCanonicalFrameHeader)?
    {
        return Err(EvidenceStoreError::NonCanonicalFrameHeader);
    }
    if local_sequence != expected_local_sequence {
        return Err(EvidenceStoreError::LocalSequenceDiscontinuity);
    }
    Ok(FrameHeader {
        frame_length,
        local_sequence,
        record_length,
        record_id: EvidenceRecordIdV1::try_from_bytes(read_array(&header[32..48]))?,
        record_digest: Digest32::from_bytes(read_array(&header[48..80])),
        frame_digest: Digest32::from_bytes(read_array(&header[80..112])),
    })
}

fn encode_frame(
    store_epoch: EvidenceStoreEpochV1,
    evidence_ref: EvidenceRefV1,
    record: &EvidenceRecordV1,
) -> Result<Vec<u8>, EvidenceStoreError> {
    let record_length = record.canonical_wire().len();
    let frame_length = FRAME_HEADER_BYTES
        .checked_add(record_length)
        .ok_or(EvidenceStoreError::StorageFull)?;
    let frame_length_u64 =
        u64::try_from(frame_length).map_err(|_| EvidenceStoreError::StorageFull)?;
    let record_length_u32 =
        u32::try_from(record_length).map_err(|_| EvidenceStoreError::StorageFull)?;
    let digest = frame_digest(
        store_epoch,
        evidence_ref.local_sequence(),
        record.record_id(),
        record.record_digest(),
        record.canonical_wire(),
    )?;
    let mut frame = vec![0_u8; frame_length];
    frame[..4].copy_from_slice(FRAME_MAGIC);
    frame[4..6].copy_from_slice(&FRAME_VERSION.to_be_bytes());
    frame[6..8].copy_from_slice(&(FRAME_HEADER_BYTES as u16).to_be_bytes());
    frame[8..16].copy_from_slice(&frame_length_u64.to_be_bytes());
    frame[16..24].copy_from_slice(&evidence_ref.local_sequence().to_be_bytes());
    frame[24..28].copy_from_slice(&record_length_u32.to_be_bytes());
    frame[32..48].copy_from_slice(record.record_id().as_bytes());
    frame[48..80].copy_from_slice(record.record_digest().as_bytes());
    frame[80..112].copy_from_slice(digest.as_bytes());
    frame[112..].copy_from_slice(record.canonical_wire());
    Ok(frame)
}

fn frame_digest(
    store_epoch: EvidenceStoreEpochV1,
    local_sequence: u64,
    record_id: EvidenceRecordIdV1,
    record_digest: Digest32,
    record_wire: &[u8],
) -> Result<Digest32, EvidenceStoreError> {
    let mut builder = Digest32Builder::try_new(FRAME_DIGEST_DOMAIN)?;
    builder
        .field_bytes(FRAME_MAGIC)?
        .field_u16(FRAME_VERSION)?
        .field_u16(FRAME_HEADER_BYTES as u16)?
        .field_bytes(store_epoch.as_bytes())?
        .field_u64(local_sequence)?
        .field_bytes(record_id.as_bytes())?
        .field_digest(&record_digest)?
        .field_bytes(record_wire)?;
    Ok(builder.finish())
}

fn sync_directory(path: &Path) -> Result<(), EvidenceStoreError> {
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    File::from(owned).sync_all().map_err(io_error)
}

fn io_error(error: io::Error) -> EvidenceStoreError {
    EvidenceStoreError::Io(error.kind())
}

fn nix_error(error: nix::errno::Errno) -> EvidenceStoreError {
    EvidenceStoreError::Io(io::Error::from(error).kind())
}

fn commit_uncertain(error: io::Error) -> EvidenceStoreError {
    EvidenceStoreError::CommitUncertain(error.kind())
}

fn recovery_uncertain(error: io::Error) -> EvidenceStoreError {
    EvidenceStoreError::RecoveryUncertain(error.kind())
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(read_array(bytes))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(read_array(bytes))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(read_array(bytes))
}

fn read_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut array = [0_u8; N];
    array.copy_from_slice(bytes);
    array
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    use super::*;
    use crate::{EvidenceKindV1, EvidencePayloadV1, EvidenceRecordInputV1};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("paraegox-evidence-{}-{unique}", std::process::id()));
            let mut builder = DirBuilder::new();
            builder
                .mode(PRIVATE_DIRECTORY_MODE_BITS)
                .create(&path)
                .unwrap_or_else(|error| panic!("create test parent: {error}"));
            Self(path)
        }

        fn store(&self) -> PathBuf {
            self.0.join("store")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap_or_else(|error| panic!("remove test root: {error}"));
        }
    }

    fn epoch(byte: u8) -> EvidenceStoreEpochV1 {
        EvidenceStoreEpochV1::try_from_bytes([byte; 16])
            .unwrap_or_else(|error| panic!("epoch: {error}"))
    }

    fn policy(max_records: u64, max_bytes: u64) -> EvidenceRetentionPolicyV1 {
        EvidenceRetentionPolicyV1::try_new(max_records, max_bytes)
            .unwrap_or_else(|error| panic!("policy: {error}"))
    }

    fn record(id: u8, owner: u8, producer_sequence: u64, previous: Option<u8>) -> EvidenceRecordV1 {
        EvidenceRecordV1::try_new(EvidenceRecordInputV1 {
            record_id: EvidenceRecordIdV1::try_from_bytes([id; 16])
                .unwrap_or_else(|error| panic!("record id: {error}")),
            owner_ref: EvidenceOwnerRefV1::try_from_bytes([owner; 16])
                .unwrap_or_else(|error| panic!("owner: {error}")),
            producer_sequence,
            causality_ref: None,
            previous_evidence_ref: previous.map(|value| {
                EvidenceRecordIdV1::try_from_bytes([value; 16])
                    .unwrap_or_else(|error| panic!("previous: {error}"))
            }),
            kind: EvidenceKindV1::OwnerReceipt,
            payload: EvidencePayloadV1::try_public_safe_inline(&[id, owner])
                .unwrap_or_else(|error| panic!("payload: {error}")),
        })
        .unwrap_or_else(|error| panic!("record: {error}"))
    }

    fn open_default(root: &TestRoot) -> LocalEvidenceStoreV1 {
        LocalEvidenceStoreV1::open(&root.store(), epoch(7), policy(8, 1024 * 1024))
            .unwrap_or_else(|error| panic!("open store: {error}"))
    }

    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    #[test]
    fn store_header_and_frame_match_exact_pxes_v1_goldens() {
        let policy = policy(8, 1024 * 1024);
        let header =
            encode_store_header(epoch(7), policy).unwrap_or_else(|error| panic!("header: {error}"));
        let record = record(1, 2, 1, None);
        let evidence_ref =
            EvidenceRefV1::try_new(epoch(7), 1, record.record_id(), record.record_digest())
                .unwrap_or_else(|error| panic!("ref: {error}"));
        let frame = encode_frame(epoch(7), evidence_ref, &record)
            .unwrap_or_else(|error| panic!("frame: {error}"));
        assert_eq!(
            lower_hex(&header),
            "505845530001006007070707070707070707070707070707000000000000000800000000001000000000000000000000000000000000000000000000000000008bf54472869b535884b69625d4233042b58fd82d743b025d0e16f4cb3931a586"
        );
        assert_eq!(
            lower_hex(&frame),
            "505845460001007000000000000001120000000000000001000000a2000000000101010101010101010101010101010133c1757645a833e991f7043a852199dc91fb2132c7741d9f5b2a9dcca2523c198e50deb2fe7b8b87b24285c1f5f9bac9fa4455991421dbe55c07dbd6eeec58ab50584556000100a0000000a201010000010101010101010101010101010101010202020202020202020202020202020200000000000000000000000000000000000000000000000000000000000000000000000000000001000000020000000007a40dc764721b83ba2eab2593123d080e04559515398f9f24191f312a59fecb33c1757645a833e991f7043a852199dc91fb2132c7741d9f5b2a9dcca2523c190102"
        );
    }

    #[test]
    fn append_syncs_then_restarts_and_replays_idempotently() {
        let root = TestRoot::new();
        let first_ref = {
            let mut store = open_default(&root);
            let outcome = store
                .append(record(1, 2, 1, None))
                .unwrap_or_else(|error| panic!("append: {error}"));
            assert!(!outcome.replayed());
            outcome.commit_receipt().evidence_ref()
        };
        let mut reopened = open_default(&root);
        assert_eq!(reopened.record_count(), 1);
        let page = reopened
            .list(None, 1)
            .unwrap_or_else(|error| panic!("restart list: {error}"));
        assert_eq!(page.records()[0].evidence_ref(), first_ref);
        assert_eq!(
            reopened
                .read_ref(first_ref)
                .unwrap_or_else(|error| panic!("read ref: {error}"))
                .record()
                .record_id(),
            record(1, 2, 1, None).record_id()
        );
        let replay = reopened
            .append(record(1, 2, 1, None))
            .unwrap_or_else(|error| panic!("replay: {error}"));
        assert!(replay.replayed());
        assert_eq!(replay.commit_receipt().evidence_ref(), first_ref);
    }

    #[test]
    fn same_id_with_different_digest_conflicts_without_poisoning() {
        let root = TestRoot::new();
        let mut store = open_default(&root);
        store
            .append(record(1, 2, 1, None))
            .unwrap_or_else(|error| panic!("append: {error}"));
        let conflicting = EvidenceRecordV1::try_new(EvidenceRecordInputV1 {
            record_id: record(1, 2, 1, None).record_id(),
            owner_ref: record(1, 2, 1, None).owner_ref(),
            producer_sequence: 1,
            causality_ref: None,
            previous_evidence_ref: None,
            kind: EvidenceKindV1::SecurityAudit,
            payload: EvidencePayloadV1::try_public_safe_inline(b"different")
                .unwrap_or_else(|error| panic!("payload: {error}")),
        })
        .unwrap_or_else(|error| panic!("conflict record: {error}"));
        assert_eq!(
            store.append(conflicting),
            Err(EvidenceStoreError::RecordIdConflict)
        );
        assert_eq!(store.record_count(), 1);
    }

    #[test]
    fn owner_sequence_and_previous_ref_form_one_strict_chain() {
        let root = TestRoot::new();
        let mut store = open_default(&root);
        assert_eq!(
            store.append(record(1, 2, 2, None)),
            Err(EvidenceStoreError::OwnerSequenceConflict)
        );
        store
            .append(record(1, 2, 1, None))
            .unwrap_or_else(|error| panic!("first: {error}"));
        assert_eq!(
            store.append(record(2, 2, 2, None)),
            Err(EvidenceStoreError::CausalityConflict)
        );
        store
            .append(record(2, 2, 2, Some(1)))
            .unwrap_or_else(|error| panic!("second: {error}"));
        store
            .append(record(3, 9, 1, None))
            .unwrap_or_else(|error| panic!("independent owner: {error}"));
    }

    #[test]
    fn single_writer_epoch_and_policy_are_pinned() {
        let root = TestRoot::new();
        let store = open_default(&root);
        assert!(matches!(
            LocalEvidenceStoreV1::open(&root.store(), epoch(7), policy(8, 1024 * 1024)),
            Err(EvidenceStoreError::LockContended)
        ));
        drop(store);
        assert!(matches!(
            LocalEvidenceStoreV1::open(&root.store(), epoch(8), policy(8, 1024 * 1024)),
            Err(EvidenceStoreError::StoreEpochMismatch)
        ));
        assert!(matches!(
            LocalEvidenceStoreV1::open(&root.store(), epoch(7), policy(9, 1024 * 1024)),
            Err(EvidenceStoreError::RetentionPolicyMismatch)
        ));
    }

    #[test]
    fn retention_is_bounded_and_full_does_not_evict_or_poison() {
        let root = TestRoot::new();
        let mut store = LocalEvidenceStoreV1::open(&root.store(), epoch(7), policy(1, 1024 * 1024))
            .unwrap_or_else(|error| panic!("open: {error}"));
        store
            .append(record(1, 2, 1, None))
            .unwrap_or_else(|error| panic!("append: {error}"));
        assert_eq!(
            store.append(record(2, 9, 1, None)),
            Err(EvidenceStoreError::StorageFull)
        );
        assert_eq!(store.record_count(), 1);
        assert!(store.read(record(1, 2, 1, None).record_id()).is_ok());
    }

    #[test]
    fn byte_capacity_rejects_before_write_and_keeps_store_usable() {
        let root = TestRoot::new();
        let candidate = record(1, 2, 1, None);
        let evidence_ref = EvidenceRefV1::try_new(
            epoch(7),
            1,
            candidate.record_id(),
            candidate.record_digest(),
        )
        .unwrap_or_else(|error| panic!("ref: {error}"));
        let one_frame = encode_frame(epoch(7), evidence_ref, &candidate)
            .unwrap_or_else(|error| panic!("frame: {error}"));
        let capacity = STORE_HEADER_BYTES as u64
            + u64::try_from(one_frame.len()).unwrap_or_else(|error| panic!("length: {error}"))
            - 1;
        let mut store = LocalEvidenceStoreV1::open(&root.store(), epoch(7), policy(8, capacity))
            .unwrap_or_else(|error| panic!("open: {error}"));
        assert_eq!(
            store.append(candidate.clone()),
            Err(EvidenceStoreError::StorageFull)
        );
        assert_eq!(store.record_count(), 0);
        assert_eq!(store.read(candidate.record_id()), Ok(None));
    }

    #[test]
    fn list_cursor_is_bounded_ordered_and_epoch_scoped() {
        let root = TestRoot::new();
        let mut store = open_default(&root);
        for (id, owner) in [(1, 2), (2, 3), (3, 4)] {
            store
                .append(record(id, owner, 1, None))
                .unwrap_or_else(|error| panic!("append {id}: {error}"));
        }
        let first = store
            .list(None, 2)
            .unwrap_or_else(|error| panic!("first page: {error}"));
        assert_eq!(first.records().len(), 2);
        assert_eq!(first.records()[0].evidence_ref().local_sequence(), 1);
        let cursor = first.next_cursor().unwrap_or_else(|| panic!("cursor"));
        assert_eq!(cursor.next_local_sequence(), 3);
        let second = store
            .list(Some(cursor), 2)
            .unwrap_or_else(|error| panic!("second page: {error}"));
        assert_eq!(second.records().len(), 1);
        assert_eq!(second.next_cursor(), None);
        assert_eq!(
            store.list(None, 0),
            Err(EvidenceStoreError::InvalidQueryLimit)
        );
        let foreign = EvidenceListCursorV1 {
            store_epoch: epoch(8),
            next_local_sequence: NonZeroU64::new(1).unwrap_or_else(|| panic!("nonzero")),
        };
        assert_eq!(
            store.list(Some(foreign), 1),
            Err(EvidenceStoreError::CursorEpochMismatch)
        );
    }

    #[test]
    fn partial_tail_is_truncated_but_complete_corruption_fails_closed() {
        let root = TestRoot::new();
        {
            let mut store = open_default(&root);
            store
                .append(record(1, 2, 1, None))
                .unwrap_or_else(|error| panic!("first: {error}"));
            store
                .append(record(2, 3, 1, None))
                .unwrap_or_else(|error| panic!("second: {error}"));
        }
        let data_path = root.store().join(STORE_DATA_FILE);
        let complete_length = fs::metadata(&data_path)
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .len();
        let file = OpenOptions::new()
            .write(true)
            .mode(PRIVATE_FILE_MODE_BITS)
            .open(&data_path)
            .unwrap_or_else(|error| panic!("open truncate: {error}"));
        file.set_len(complete_length - 5)
            .unwrap_or_else(|error| panic!("truncate: {error}"));
        file.sync_all()
            .unwrap_or_else(|error| panic!("sync truncate: {error}"));
        drop(file);
        let recovered = open_default(&root);
        assert_eq!(recovered.record_count(), 1);
        let recovered_length = recovered.durable_bytes();
        drop(recovered);

        let mut file = OpenOptions::new()
            .append(true)
            .mode(PRIVATE_FILE_MODE_BITS)
            .open(&data_path)
            .unwrap_or_else(|error| panic!("open append: {error}"));
        let valid = encode_frame(
            epoch(7),
            EvidenceRefV1::try_new(
                epoch(7),
                2,
                record(2, 3, 1, None).record_id(),
                record(2, 3, 1, None).record_digest(),
            )
            .unwrap_or_else(|error| panic!("ref: {error}")),
            &record(2, 3, 1, None),
        )
        .unwrap_or_else(|error| panic!("frame: {error}"));
        file.write_all(&valid)
            .unwrap_or_else(|error| panic!("append valid: {error}"));
        file.sync_all()
            .unwrap_or_else(|error| panic!("sync valid: {error}"));
        drop(file);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .mode(PRIVATE_FILE_MODE_BITS)
            .open(&data_path)
            .unwrap_or_else(|error| panic!("open corrupt: {error}"));
        file.seek(SeekFrom::Start(
            recovered_length + FRAME_HEADER_BYTES as u64 + 1,
        ))
        .unwrap_or_else(|error| panic!("seek corrupt: {error}"));
        file.write_all(&[0xff])
            .unwrap_or_else(|error| panic!("corrupt: {error}"));
        file.sync_all()
            .unwrap_or_else(|error| panic!("sync corrupt: {error}"));
        drop(file);
        assert!(matches!(
            LocalEvidenceStoreV1::open(&root.store(), epoch(7), policy(8, 1024 * 1024)),
            Err(EvidenceStoreError::FrameDigestMismatch)
        ));
    }

    #[test]
    fn complete_store_header_corruption_fails_closed() {
        let root = TestRoot::new();
        drop(open_default(&root));
        let data_path = root.store().join(STORE_DATA_FILE);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .mode(PRIVATE_FILE_MODE_BITS)
            .open(&data_path)
            .unwrap_or_else(|error| panic!("open header: {error}"));
        file.seek(SeekFrom::Start(64))
            .unwrap_or_else(|error| panic!("seek digest: {error}"));
        file.write_all(&[0xff])
            .unwrap_or_else(|error| panic!("corrupt digest: {error}"));
        file.sync_all()
            .unwrap_or_else(|error| panic!("sync corruption: {error}"));
        drop(file);
        assert!(matches!(
            LocalEvidenceStoreV1::open(&root.store(), epoch(7), policy(8, 1024 * 1024)),
            Err(EvidenceStoreError::StoreHeaderDigestMismatch)
        ));
    }

    #[test]
    fn uncertain_partial_commit_poison_requires_reopen_and_retry() {
        let root = TestRoot::new();
        let candidate = record(1, 2, 1, None);
        let mut store = open_default(&root);
        store.inject_append_fault(TestAppendFault::AfterPartialWrite);
        assert!(matches!(
            store.append(candidate.clone()),
            Err(EvidenceStoreError::CommitUncertain(_))
        ));
        assert_eq!(
            store.read(candidate.record_id()),
            Err(EvidenceStoreError::Poisoned)
        );
        assert_eq!(
            store.append(candidate.clone()),
            Err(EvidenceStoreError::Poisoned)
        );
        drop(store);
        let mut reopened = open_default(&root);
        assert_eq!(reopened.record_count(), 0);
        assert!(
            !reopened
                .append(candidate)
                .unwrap_or_else(|error| panic!("retry: {error}"))
                .replayed()
        );
    }

    #[test]
    fn uncertain_post_sync_commit_is_discovered_as_replay_after_reopen() {
        let root = TestRoot::new();
        let candidate = record(1, 2, 1, None);
        let mut store = open_default(&root);
        store.inject_append_fault(TestAppendFault::AfterSyncBeforeAck);
        assert!(matches!(
            store.append(candidate.clone()),
            Err(EvidenceStoreError::CommitUncertain(_))
        ));
        drop(store);
        let mut reopened = open_default(&root);
        assert_eq!(reopened.record_count(), 1);
        assert!(
            reopened
                .append(candidate)
                .unwrap_or_else(|error| panic!("replay: {error}"))
                .replayed()
        );
    }
}
