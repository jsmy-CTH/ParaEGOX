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
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{UnlinkatFlags, unlinkat};

use super::codec::{CodecError, decode_snapshot, encode_snapshot};
use super::model::{
    AUTHORITY_SNAPSHOT_MAX_BYTES, AuthorityProvisioning, AuthoritySnapshot, StoreInstanceId,
};

pub(super) const LOCK_FILE_NAME: &str = "authority.lock";
pub(super) const ACTIVE_FILE_NAME: &str = "authority.snapshot";
const TEMP_FILE_PREFIX: &str = ".authority.snapshot.tmp-";
const TEMP_TOKEN_BYTES: usize = 16;
const TEMP_HEX_BYTES: usize = TEMP_TOKEN_BYTES * 2;
const MAX_ORPHAN_TEMP_FILES: usize = 32;
const DIRECTORY_MODE_MASK: u32 = 0o022;
const PRIVATE_FILE_MODE_BITS: u32 = 0o600;
const PRIVATE_FILE_MODE_MASK: u32 = 0o7777;
const PRIVATE_FILE_MODE: Mode = Mode::S_IRUSR.union(Mode::S_IWUSR);
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
pub(super) enum FilesystemPolicy {
    ProductionReference,
    #[cfg(test)]
    ExplicitFixture,
}

pub(super) struct DirectoryHandle {
    path: PathBuf,
    file: File,
    owner_uid: u32,
}

impl fmt::Debug for DirectoryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectoryHandle")
            .field("path", &self.path)
            .field("owner_uid", &self.owner_uid)
            .finish_non_exhaustive()
    }
}

pub(super) struct AuthorityStore {
    directory: DirectoryHandle,
    lock_file: File,
    snapshot: AuthoritySnapshot,
    state: StoreState,
}

impl fmt::Debug for AuthorityStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityStore")
            .field("directory", &self.directory)
            .field("snapshot", &self.snapshot)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Drop for AuthorityStore {
    fn drop(&mut self) {
        // Fork temporarily duplicates the open-file description. Releasing
        // the advisory lock explicitly keeps normal owner shutdown from
        // waiting for an unrelated CLOEXEC child to reach exec.
        let _ = self.lock_file.unlock();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreState {
    Operational,
    Stopped,
}

impl AuthorityStore {
    pub(super) fn open(
        directory: &Path,
        expected_store_instance_id: StoreInstanceId,
        expected_provisioning: AuthorityProvisioning,
    ) -> Result<Self, StoreOpenError> {
        Self::open_with_policy(
            directory,
            expected_store_instance_id,
            expected_provisioning,
            FilesystemPolicy::ProductionReference,
        )
    }

    pub(super) fn open_with_policy(
        directory: &Path,
        expected_store_instance_id: StoreInstanceId,
        expected_provisioning: AuthorityProvisioning,
        filesystem_policy: FilesystemPolicy,
    ) -> Result<Self, StoreOpenError> {
        let store = Self::open_validated(directory, expected_provisioning, filesystem_policy)?;
        if store.snapshot.store_instance_id != expected_store_instance_id {
            return Err(StoreOpenError::StoreInstanceMismatch);
        }
        Ok(store)
    }

    pub(super) fn open_for_sequence_one_receipt(
        directory: &Path,
        expected_provisioning: AuthorityProvisioning,
    ) -> Result<Self, StoreOpenError> {
        Self::open_for_sequence_one_receipt_with_policy(
            directory,
            expected_provisioning,
            FilesystemPolicy::ProductionReference,
        )
    }

    pub(super) fn open_for_sequence_one_receipt_with_policy(
        directory: &Path,
        expected_provisioning: AuthorityProvisioning,
        filesystem_policy: FilesystemPolicy,
    ) -> Result<Self, StoreOpenError> {
        Self::open_validated(directory, expected_provisioning, filesystem_policy)
    }

    fn open_validated(
        directory: &Path,
        expected_provisioning: AuthorityProvisioning,
        filesystem_policy: FilesystemPolicy,
    ) -> Result<Self, StoreOpenError> {
        let directory = open_directory(directory, filesystem_policy)?;
        let lock_file = open_existing_regular(
            &directory,
            LOCK_FILE_NAME,
            OFlag::O_RDWR,
            FileStage::OpenLock,
        )?;
        lock_file.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => StoreOpenError::LockContended,
            TryLockError::Error(error) => {
                StoreOpenError::Io(IoFailure::new(FileStage::AcquireLock, &error))
            }
        })?;

        let snapshot = read_active_snapshot(&directory)?;
        if snapshot.provisioning != expected_provisioning
            || snapshot.owner_identity_fingerprint
                != expected_provisioning.fingerprints.owner_identity
        {
            return Err(StoreOpenError::ProvisioningMismatch);
        }
        clean_valid_orphan_temps(&directory)?;
        Ok(Self {
            directory,
            lock_file,
            snapshot,
            state: StoreState::Operational,
        })
    }

    pub(super) fn snapshot(&self) -> Result<&AuthoritySnapshot, StoreError> {
        self.ensure_operational()?;
        Ok(&self.snapshot)
    }

    #[cfg(test)]
    pub(super) fn clone_lock_descriptor_for_test(&self) -> io::Result<File> {
        self.lock_file.try_clone()
    }

    pub(super) fn revalidate_current(&mut self) -> Result<&AuthoritySnapshot, StoreError> {
        self.ensure_operational()?;
        let disk = read_active_snapshot(&self.directory).map_err(|error| {
            self.state = StoreState::Stopped;
            StoreError::Open(error)
        })?;
        if disk != self.snapshot {
            self.state = StoreState::Stopped;
            return Err(StoreError::ActiveSnapshotChanged);
        }
        Ok(&self.snapshot)
    }

    pub(super) fn commit(
        &mut self,
        next: AuthoritySnapshot,
        failpoint: CommitFailpoint,
    ) -> Result<(), StoreError> {
        self.ensure_operational()?;
        if next.store_instance_id != self.snapshot.store_instance_id
            || next.provisioning != self.snapshot.provisioning
            || next.owner_identity_fingerprint != self.snapshot.owner_identity_fingerprint
        {
            self.state = StoreState::Stopped;
            return Err(StoreError::ImmutableIdentityChanged);
        }
        let expected_sequence =
            self.snapshot
                .snapshot_sequence
                .checked_add(1)
                .ok_or_else(|| {
                    self.state = StoreState::Stopped;
                    StoreError::SequenceOverflow
                })?;
        if next.snapshot_sequence != expected_sequence {
            self.state = StoreState::Stopped;
            return Err(StoreError::SequenceTransitionMismatch);
        }
        next.validate().map_err(|error| {
            self.state = StoreState::Stopped;
            StoreError::Codec(CodecError::Model(error))
        })?;

        self.revalidate_current()?;
        let encoded = encode_snapshot(&next).map_err(|error| {
            self.state = StoreState::Stopped;
            StoreError::Codec(error)
        })?;
        let token = system_random_token().map_err(|error| {
            self.state = StoreState::Stopped;
            StoreError::Publish(PublishFailure::RejectedBeforePublish(PublishFault::io(
                FileStage::GenerateTempName,
                &error,
            )))
        })?;
        match publish_atomic(
            &self.directory,
            &encoded,
            token,
            PublishMode::ReplaceExisting,
            failpoint,
        ) {
            Ok(()) => {
                self.snapshot = next;
                Ok(())
            }
            Err(error) => {
                self.state = StoreState::Stopped;
                Err(StoreError::Publish(error))
            }
        }
    }

    fn ensure_operational(&self) -> Result<(), StoreError> {
        let _ = &self.lock_file;
        if self.state == StoreState::Stopped {
            return Err(StoreError::Stopped);
        }
        Ok(())
    }
}

pub(super) fn open_directory(
    path: &Path,
    filesystem_policy: FilesystemPolicy,
) -> Result<DirectoryHandle, StoreOpenError> {
    validate_absolute_path_chain(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| StoreOpenError::Io(IoFailure::new(FileStage::InspectDirectory, &error)))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(StoreOpenError::UnsafeDirectoryType);
    }
    if metadata.mode() & DIRECTORY_MODE_MASK != 0 {
        return Err(StoreOpenError::UnsafeDirectoryMode);
    }
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| StoreOpenError::Io(nix_failure(FileStage::OpenDirectory, error)))?;
    let file = File::from(owned);
    let opened_metadata = file
        .metadata()
        .map_err(|error| StoreOpenError::Io(IoFailure::new(FileStage::OpenDirectory, &error)))?;
    if !opened_metadata.file_type().is_dir()
        || opened_metadata.dev() != metadata.dev()
        || opened_metadata.ino() != metadata.ino()
    {
        return Err(StoreOpenError::DirectoryIdentityChanged);
    }
    verify_filesystem(&file, filesystem_policy)?;
    Ok(DirectoryHandle {
        path: path.to_path_buf(),
        file,
        owner_uid: opened_metadata.uid(),
    })
}

pub(super) fn ensure_fresh_directory(directory: &DirectoryHandle) -> Result<(), StoreOpenError> {
    let mut entries = duplicate_directory_stream(directory)?;
    for entry in entries.iter() {
        let entry = entry
            .map_err(|error| StoreOpenError::Io(nix_failure(FileStage::ScanDirectory, error)))?;
        if !is_dot_entry(entry.file_name().to_bytes()) {
            return Err(StoreOpenError::DirectoryNotFresh);
        }
    }
    Ok(())
}

pub(super) fn create_and_lock_initializer_lock(
    directory: &DirectoryHandle,
) -> Result<File, StoreOpenError> {
    let owned = openat(
        &directory.file,
        LOCK_FILE_NAME,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(|error| StoreOpenError::Io(nix_failure(FileStage::CreateLock, error)))?;
    let lock_file = File::from(owned);
    fchmod(&lock_file, PRIVATE_FILE_MODE)
        .map_err(|error| StoreOpenError::Io(nix_failure(FileStage::CreateLock, error)))?;
    validate_regular_file(
        &lock_file
            .metadata()
            .map_err(|error| StoreOpenError::Io(IoFailure::new(FileStage::CreateLock, &error)))?,
        directory.owner_uid,
    )?;
    lock_file
        .sync_all()
        .map_err(|error| StoreOpenError::Io(IoFailure::new(FileStage::CreateLock, &error)))?;
    lock_file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => StoreOpenError::LockContended,
        TryLockError::Error(error) => {
            StoreOpenError::Io(IoFailure::new(FileStage::AcquireLock, &error))
        }
    })?;
    Ok(lock_file)
}

pub(super) fn publish_initial_snapshot(
    directory: &DirectoryHandle,
    encoded: &[u8],
    temp_token: [u8; TEMP_TOKEN_BYTES],
    failpoint: CommitFailpoint,
) -> Result<(), PublishFailure> {
    publish_atomic(
        directory,
        encoded,
        temp_token,
        PublishMode::RequireMissing,
        failpoint,
    )
}

pub(super) fn read_active_snapshot(
    directory: &DirectoryHandle,
) -> Result<AuthoritySnapshot, StoreOpenError> {
    let mut active = open_existing_regular(
        directory,
        ACTIVE_FILE_NAME,
        OFlag::O_RDONLY,
        FileStage::OpenActive,
    )?;
    let metadata = active
        .metadata()
        .map_err(|error| StoreOpenError::Io(IoFailure::new(FileStage::ReadActive, &error)))?;
    let length = usize::try_from(metadata.len()).map_err(|_| StoreOpenError::ActiveTooLarge)?;
    if length == 0 {
        return Err(StoreOpenError::ActiveEmpty);
    }
    if length > AUTHORITY_SNAPSHOT_MAX_BYTES {
        return Err(StoreOpenError::ActiveTooLarge);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| StoreOpenError::ActiveAllocationFailed)?;
    encoded.resize(length, 0);
    active
        .read_exact(&mut encoded)
        .map_err(|error| StoreOpenError::Io(IoFailure::new(FileStage::ReadActive, &error)))?;
    let mut trailing = [0; 1];
    if active
        .read(&mut trailing)
        .map_err(|error| StoreOpenError::Io(IoFailure::new(FileStage::ReadActive, &error)))?
        != 0
    {
        return Err(StoreOpenError::ActiveChangedDuringRead);
    }
    decode_snapshot(&encoded).map_err(StoreOpenError::Codec)
}

fn open_existing_regular(
    directory: &DirectoryHandle,
    name: &str,
    access: OFlag,
    stage: FileStage,
) -> Result<File, StoreOpenError> {
    let owned = openat(
        &directory.file,
        name,
        access | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| StoreOpenError::Io(nix_failure(stage, error)))?;
    let file = File::from(owned);
    let metadata = file
        .metadata()
        .map_err(|error| StoreOpenError::Io(IoFailure::new(stage, &error)))?;
    validate_regular_file(&metadata, directory.owner_uid)?;
    Ok(file)
}

fn validate_regular_file(metadata: &Metadata, owner_uid: u32) -> Result<(), StoreOpenError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(StoreOpenError::UnsafeFileType);
    }
    if metadata.uid() != owner_uid {
        return Err(StoreOpenError::FileOwnerMismatch);
    }
    if metadata.mode() & PRIVATE_FILE_MODE_MASK != PRIVATE_FILE_MODE_BITS {
        return Err(StoreOpenError::UnsafeFileMode);
    }
    Ok(())
}

fn clean_valid_orphan_temps(directory: &DirectoryHandle) -> Result<(), StoreOpenError> {
    let mut entries = duplicate_directory_stream(directory)?;
    let mut orphan_names = Vec::new();
    for entry in entries.iter() {
        let entry = entry
            .map_err(|error| StoreOpenError::Io(nix_failure(FileStage::ScanDirectory, error)))?;
        let name_bytes = entry.file_name().to_bytes();
        if is_dot_entry(name_bytes) {
            continue;
        }
        let name =
            std::str::from_utf8(name_bytes).map_err(|_| StoreOpenError::UnknownDirectoryEntry)?;
        if name == LOCK_FILE_NAME || name == ACTIVE_FILE_NAME {
            continue;
        }
        if !valid_temp_name(name) {
            return Err(StoreOpenError::UnknownDirectoryEntry);
        }
        orphan_names.push(name.to_owned());
        if orphan_names.len() > MAX_ORPHAN_TEMP_FILES {
            return Err(StoreOpenError::TooManyOrphanTemps);
        }
    }
    if orphan_names.is_empty() {
        return Ok(());
    }
    for name in orphan_names {
        let orphan = open_existing_regular(
            directory,
            &name,
            OFlag::O_RDONLY,
            FileStage::InspectOrphanTemp,
        )?;
        drop(orphan);
        unlinkat(&directory.file, name.as_str(), UnlinkatFlags::NoRemoveDir)
            .map_err(|error| StoreOpenError::Io(nix_failure(FileStage::RemoveOrphanTemp, error)))?;
    }
    directory.file.sync_all().map_err(|error| {
        StoreOpenError::Io(IoFailure::new(FileStage::SyncOrphanCleanup, &error))
    })?;
    Ok(())
}

fn duplicate_directory_stream(directory: &DirectoryHandle) -> Result<Dir, StoreOpenError> {
    let duplicate = directory
        .file
        .try_clone()
        .map_err(|error| StoreOpenError::Io(IoFailure::new(FileStage::ScanDirectory, &error)))?;
    let descriptor: OwnedFd = duplicate.into();
    Dir::from_fd(descriptor)
        .map_err(|error| StoreOpenError::Io(nix_failure(FileStage::ScanDirectory, error)))
}

fn is_dot_entry(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

fn publish_atomic(
    directory: &DirectoryHandle,
    encoded: &[u8],
    token: [u8; TEMP_TOKEN_BYTES],
    mode: PublishMode,
    failpoint: CommitFailpoint,
) -> Result<(), PublishFailure> {
    if encoded.is_empty() || encoded.len() > AUTHORITY_SNAPSHOT_MAX_BYTES {
        return Err(PublishFailure::RejectedBeforePublish(
            PublishFault::injected(FileStage::ValidateEncodedSnapshot),
        ));
    }
    if failpoint == CommitFailpoint::BeforeTempCreate {
        return Err(rejected_injected(FileStage::CreateTemp));
    }
    match mode {
        PublishMode::RequireMissing => ensure_active_missing(directory)?,
        PublishMode::ReplaceExisting => {
            open_existing_regular(
                directory,
                ACTIVE_FILE_NAME,
                OFlag::O_RDONLY,
                FileStage::OpenActive,
            )
            .map_err(|error| rejected_open_error(FileStage::OpenActive, error))?;
        }
    }

    let temp_name = temp_name(token);
    let owned = openat(
        &directory.file,
        temp_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(|error| {
        PublishFailure::RejectedBeforePublish(PublishFault::nix(FileStage::CreateTemp, error))
    })?;
    let mut temp = File::from(owned);
    fchmod(&temp, PRIVATE_FILE_MODE).map_err(|error| {
        PublishFailure::RejectedBeforePublish(PublishFault::nix(FileStage::InspectTemp, error))
    })?;
    validate_regular_file(
        &temp.metadata().map_err(|error| {
            PublishFailure::RejectedBeforePublish(PublishFault::io(FileStage::InspectTemp, &error))
        })?,
        directory.owner_uid,
    )
    .map_err(|_| {
        PublishFailure::RejectedBeforePublish(PublishFault::injected(FileStage::InspectTemp))
    })?;
    #[cfg(test)]
    if failpoint == CommitFailpoint::AbortAfterTempCreate {
        std::process::abort();
    }
    if failpoint == CommitFailpoint::AfterTempCreate {
        return Err(rejected_injected(FileStage::CreateTemp));
    }
    #[cfg(test)]
    if let Some(boundary) = TestPartialWriteBoundary::for_failpoint(failpoint) {
        abort_after_partial_write(&mut temp, encoded, boundary)?;
    }
    if failpoint == CommitFailpoint::AfterPartialWrite {
        let partial_length = encoded.len().saturating_sub(1).max(1);
        temp.write_all(&encoded[..partial_length])
            .map_err(|error| {
                PublishFailure::RejectedBeforePublish(PublishFault::io(
                    FileStage::WriteTemp,
                    &error,
                ))
            })?;
        return Err(rejected_injected(FileStage::WriteTemp));
    }
    temp.write_all(encoded).map_err(|error| {
        PublishFailure::RejectedBeforePublish(PublishFault::io(FileStage::WriteTemp, &error))
    })?;
    #[cfg(test)]
    if failpoint == CommitFailpoint::AbortBeforeFileSync {
        std::process::abort();
    }
    if failpoint == CommitFailpoint::BeforeFileSync {
        return Err(rejected_injected(FileStage::SyncTemp));
    }
    temp.sync_all().map_err(|error| {
        PublishFailure::RejectedBeforePublish(PublishFault::io(FileStage::SyncTemp, &error))
    })?;
    #[cfg(test)]
    if failpoint == CommitFailpoint::AbortAfterFileSync {
        std::process::abort();
    }
    if matches!(
        failpoint,
        CommitFailpoint::AfterFileSync | CommitFailpoint::BeforeRename
    ) {
        return Err(rejected_injected(FileStage::Rename));
    }
    if mode == PublishMode::RequireMissing {
        ensure_active_missing(directory)?;
    }
    renameat(
        &directory.file,
        temp_name.as_str(),
        &directory.file,
        ACTIVE_FILE_NAME,
    )
    .map_err(|error| {
        PublishFailure::RejectedBeforePublish(PublishFault::nix(FileStage::Rename, error))
    })?;
    #[cfg(test)]
    if failpoint == CommitFailpoint::AbortAfterRename {
        std::process::abort();
    }
    if matches!(
        failpoint,
        CommitFailpoint::AfterRename | CommitFailpoint::BeforeDirectorySync
    ) {
        return Err(uncertain_injected(FileStage::SyncDirectory));
    }
    directory.file.sync_all().map_err(|error| {
        PublishFailure::UncertainAfterPublish(PublishFault::io(FileStage::SyncDirectory, &error))
    })?;
    #[cfg(test)]
    if failpoint == CommitFailpoint::AbortAfterDirectorySync {
        std::process::abort();
    }
    #[cfg(test)]
    if failpoint == CommitFailpoint::AbortAfterDurableCommitBeforeReturn {
        std::process::abort();
    }
    if failpoint == CommitFailpoint::AfterDirectorySyncBeforeReturn {
        return Err(uncertain_injected(FileStage::ReturnDurableCommit));
    }
    Ok(())
}

fn ensure_active_missing(directory: &DirectoryHandle) -> Result<(), PublishFailure> {
    match openat(
        &directory.file,
        ACTIVE_FILE_NAME,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => {
            drop(file);
            Err(PublishFailure::RejectedBeforePublish(
                PublishFault::injected(FileStage::RequireMissingActive),
            ))
        }
        Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(error) => Err(PublishFailure::RejectedBeforePublish(PublishFault::nix(
            FileStage::RequireMissingActive,
            error,
        ))),
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
            "CSPRNG returned an all-zero temporary token",
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

fn validate_absolute_path_chain(path: &Path) -> Result<(), StoreOpenError> {
    if !path.is_absolute() {
        return Err(StoreOpenError::PathMustBeAbsolute);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    StoreOpenError::Io(IoFailure::new(FileStage::InspectDirectory, &error))
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(StoreOpenError::SymlinkInDirectoryPath);
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(StoreOpenError::UnsafeDirectoryPath);
            }
        }
    }
    Ok(())
}

fn verify_filesystem(directory: &File, _policy: FilesystemPolicy) -> Result<(), StoreOpenError> {
    #[cfg(test)]
    if _policy == FilesystemPolicy::ExplicitFixture {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let _ = directory;
        Err(StoreOpenError::UnsupportedFilesystem)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let stat = nix::sys::statfs::fstatfs(directory).map_err(|error| {
            StoreOpenError::Io(nix_failure(FileStage::InspectFilesystem, error))
        })?;
        #[cfg(target_os = "linux")]
        {
            if stat.filesystem_type() != nix::sys::statfs::EXT4_SUPER_MAGIC {
                Err(StoreOpenError::UnsupportedFilesystem)
            } else {
                verify_linux_ext4_mount(directory)
                    .map_err(|_| StoreOpenError::UnsupportedFilesystem)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stat;
            Err(StoreOpenError::UnsupportedFilesystem)
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
        let read = source
            .read(&mut chunk[..remaining.min(chunk.len())])
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

fn rejected_open_error(stage: FileStage, error: StoreOpenError) -> PublishFailure {
    match error {
        StoreOpenError::Io(failure) => PublishFailure::RejectedBeforePublish(failure.into()),
        _ => PublishFailure::RejectedBeforePublish(PublishFault::injected(stage)),
    }
}

fn rejected_injected(stage: FileStage) -> PublishFailure {
    PublishFailure::RejectedBeforePublish(PublishFault::injected(stage))
}

fn uncertain_injected(stage: FileStage) -> PublishFailure {
    PublishFailure::UncertainAfterPublish(PublishFault::injected(stage))
}

fn nix_failure(stage: FileStage, error: nix::errno::Errno) -> IoFailure {
    IoFailure::new(stage, &errno_to_io(error))
}

fn errno_to_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishMode {
    RequireMissing,
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommitFailpoint {
    None,
    BeforeTempCreate,
    AfterTempCreate,
    AfterPartialWrite,
    BeforeFileSync,
    AfterFileSync,
    BeforeRename,
    AfterRename,
    BeforeDirectorySync,
    AfterDirectorySyncBeforeReturn,
    #[cfg(test)]
    AbortAfterTempCreate,
    #[cfg(test)]
    AbortAfterHeaderPartialWrite,
    #[cfg(test)]
    AbortAfterChecksumPartialWrite,
    #[cfg(test)]
    AbortAfterPayloadPartialWrite,
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
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestPartialWriteBoundary {
    Header,
    Checksum,
    Payload,
    LastByte,
}

#[cfg(test)]
impl TestPartialWriteBoundary {
    fn for_failpoint(failpoint: CommitFailpoint) -> Option<Self> {
        match failpoint {
            CommitFailpoint::AbortAfterHeaderPartialWrite => Some(Self::Header),
            CommitFailpoint::AbortAfterChecksumPartialWrite => Some(Self::Checksum),
            CommitFailpoint::AbortAfterPayloadPartialWrite => Some(Self::Payload),
            CommitFailpoint::AbortAfterPartialWrite => Some(Self::LastByte),
            _ => None,
        }
    }
}

#[cfg(test)]
fn abort_after_partial_write(
    temp: &mut File,
    encoded: &[u8],
    boundary: TestPartialWriteBoundary,
) -> Result<(), PublishFailure> {
    let header_without_checksum = super::codec::ENVELOPE_HEADER_WITHOUT_CHECKSUM_BYTES;
    let header = super::codec::ENVELOPE_HEADER_BYTES;
    let partial_length = match boundary {
        TestPartialWriteBoundary::Header => (header_without_checksum / 2).max(1),
        TestPartialWriteBoundary::Checksum => header_without_checksum + 16,
        TestPartialWriteBoundary::Payload => {
            let payload_length = encoded.len().saturating_sub(header);
            header + (payload_length / 2).max(1)
        }
        TestPartialWriteBoundary::LastByte => encoded.len().saturating_sub(1).max(1),
    };
    if partial_length >= encoded.len() {
        return Err(rejected_injected(FileStage::WriteTemp));
    }
    temp.write_all(&encoded[..partial_length])
        .map_err(|error| {
            PublishFailure::RejectedBeforePublish(PublishFault::io(FileStage::WriteTemp, &error))
        })?;
    std::process::abort();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FileStage {
    InspectDirectory,
    OpenDirectory,
    InspectFilesystem,
    ScanDirectory,
    CreateLock,
    OpenLock,
    AcquireLock,
    OpenActive,
    ReadActive,
    InspectOrphanTemp,
    RemoveOrphanTemp,
    SyncOrphanCleanup,
    GenerateTempName,
    ValidateEncodedSnapshot,
    RequireMissingActive,
    CreateTemp,
    InspectTemp,
    WriteTemp,
    SyncTemp,
    Rename,
    SyncDirectory,
    ReturnDurableCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IoFailure {
    pub(super) stage: FileStage,
    pub(super) kind: io::ErrorKind,
}

impl IoFailure {
    fn new(stage: FileStage, error: &io::Error) -> Self {
        Self {
            stage,
            kind: error.kind(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PublishFault {
    pub(super) stage: FileStage,
    pub(super) kind: Option<io::ErrorKind>,
}

impl PublishFault {
    fn injected(stage: FileStage) -> Self {
        Self { stage, kind: None }
    }

    fn io(stage: FileStage, error: &io::Error) -> Self {
        Self {
            stage,
            kind: Some(error.kind()),
        }
    }

    fn nix(stage: FileStage, error: nix::errno::Errno) -> Self {
        Self::io(stage, &errno_to_io(error))
    }
}

impl From<IoFailure> for PublishFault {
    fn from(value: IoFailure) -> Self {
        Self {
            stage: value.stage,
            kind: Some(value.kind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublishFailure {
    RejectedBeforePublish(PublishFault),
    UncertainAfterPublish(PublishFault),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StoreOpenError {
    PathMustBeAbsolute,
    UnsafeDirectoryPath,
    SymlinkInDirectoryPath,
    UnsafeDirectoryType,
    UnsafeDirectoryMode,
    DirectoryIdentityChanged,
    UnsupportedFilesystem,
    DirectoryNotFresh,
    UnsafeFileType,
    UnsafeFileMode,
    FileOwnerMismatch,
    UnknownDirectoryEntry,
    TooManyOrphanTemps,
    LockContended,
    ActiveEmpty,
    ActiveTooLarge,
    ActiveAllocationFailed,
    ActiveChangedDuringRead,
    StoreInstanceMismatch,
    ProvisioningMismatch,
    Io(IoFailure),
    Codec(CodecError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StoreError {
    Stopped,
    ActiveSnapshotChanged,
    ImmutableIdentityChanged,
    SequenceOverflow,
    SequenceTransitionMismatch,
    Open(StoreOpenError),
    Codec(CodecError),
    Publish(PublishFailure),
}

impl fmt::Display for StoreOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "tenure-authority store cannot open: {self:?}")
    }
}

impl std::error::Error for StoreOpenError {}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "tenure-authority store stopped: {self:?}")
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        ACTIVE_FILE_NAME, CommitFailpoint, FilesystemPolicy, LOCK_FILE_NAME,
        LinuxMountEvidenceError, MAX_LINUX_FDINFO_BYTES, MAX_LINUX_FDINFO_LINE_BYTES,
        MAX_LINUX_FDINFO_RECORDS, MAX_LINUX_MOUNTINFO_BYTES, MAX_LINUX_MOUNTINFO_LINE_BYTES,
        MAX_LINUX_MOUNTINFO_RECORDS, PublishFailure, PublishMode, StoreOpenError,
        clean_valid_orphan_temps, ensure_fresh_directory, open_directory,
        parse_linux_fdinfo_mount_id, parse_linux_mountinfo_exact_ext4, publish_atomic,
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
        for filesystem_type in ["ext2", "ext3", "overlay", "ext4foo"] {
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

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let fixture_root = std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|error| panic!("fixture root canonicalize failed: {error}"));
            let path = fixture_root.join(format!(
                "paraegox-authority-store-{}-{sequence}",
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

    fn fixture_directory() -> (TestDirectory, super::DirectoryHandle) {
        let path = TestDirectory::new();
        let handle = open_directory(path.path(), FilesystemPolicy::ExplicitFixture)
            .unwrap_or_else(|error| panic!("fixture directory open failed: {error}"));
        (path, handle)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_apfs_is_rejected_by_the_production_reference_policy() {
        let directory = TestDirectory::new();
        let stat = nix::sys::statfs::statfs(directory.path())
            .unwrap_or_else(|error| panic!("APFS fixture statfs failed: {error}"));
        assert_eq!(
            stat.filesystem_type_name(),
            "apfs",
            "the macOS production-rejection evidence must exercise a real APFS directory"
        );
        assert_eq!(
            open_directory(directory.path(), FilesystemPolicy::ProductionReference).expect_err(
                "macOS APFS must remain fail-closed without descriptor-bound ACL proof"
            ),
            StoreOpenError::UnsupportedFilesystem
        );
    }

    fn install_active(path: &Path, bytes: &[u8]) {
        fs::write(path.join(ACTIVE_FILE_NAME), bytes)
            .unwrap_or_else(|error| panic!("fixture active write failed: {error}"));
        fs::set_permissions(
            path.join(ACTIVE_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap_or_else(|error| panic!("fixture active chmod failed: {error}"));
    }

    #[test]
    fn publish_failpoints_preserve_old_or_publish_complete_new_bytes() {
        let rejected = [
            CommitFailpoint::BeforeTempCreate,
            CommitFailpoint::AfterTempCreate,
            CommitFailpoint::AfterPartialWrite,
            CommitFailpoint::BeforeFileSync,
            CommitFailpoint::AfterFileSync,
            CommitFailpoint::BeforeRename,
        ];
        for (index, failpoint) in rejected.into_iter().enumerate() {
            let (directory, handle) = fixture_directory();
            install_active(directory.path(), b"old");
            let result = publish_atomic(
                &handle,
                b"complete-new",
                [u8::try_from(index + 1).unwrap_or(1); 16],
                PublishMode::ReplaceExisting,
                failpoint,
            );
            assert!(matches!(
                result,
                Err(PublishFailure::RejectedBeforePublish(_))
            ));
            assert_eq!(
                fs::read(directory.path().join(ACTIVE_FILE_NAME))
                    .unwrap_or_else(|error| panic!("fixture active read failed: {error}")),
                b"old"
            );
        }

        for (index, failpoint) in [
            CommitFailpoint::AfterRename,
            CommitFailpoint::BeforeDirectorySync,
            CommitFailpoint::AfterDirectorySyncBeforeReturn,
        ]
        .into_iter()
        .enumerate()
        {
            let (directory, handle) = fixture_directory();
            install_active(directory.path(), b"old");
            let result = publish_atomic(
                &handle,
                b"complete-new",
                [u8::try_from(index + 20).unwrap_or(20); 16],
                PublishMode::ReplaceExisting,
                failpoint,
            );
            assert!(matches!(
                result,
                Err(PublishFailure::UncertainAfterPublish(_))
            ));
            assert_eq!(
                fs::read(directory.path().join(ACTIVE_FILE_NAME))
                    .unwrap_or_else(|error| panic!("fixture active read failed: {error}")),
                b"complete-new"
            );
        }
    }

    #[test]
    fn initial_publish_never_replaces_an_existing_active_file() {
        let (directory, handle) = fixture_directory();
        install_active(directory.path(), b"old");
        let result = publish_atomic(
            &handle,
            b"new",
            [30; 16],
            PublishMode::RequireMissing,
            CommitFailpoint::None,
        );
        assert!(matches!(
            result,
            Err(PublishFailure::RejectedBeforePublish(_))
        ));
        assert_eq!(
            fs::read(directory.path().join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("fixture active read failed: {error}")),
            b"old"
        );
    }

    #[test]
    fn directory_path_replacement_cannot_redirect_descriptor_relative_scan_or_publish() {
        let configured = TestDirectory::new();
        let replacement = TestDirectory::new();
        fs::write(replacement.path().join("attacker-entry"), b"replacement")
            .unwrap_or_else(|error| panic!("replacement marker failed: {error}"));
        let handle = open_directory(configured.path(), FilesystemPolicy::ExplicitFixture)
            .unwrap_or_else(|error| panic!("fixture directory open failed: {error}"));
        let configured_path = configured.path().to_path_buf();
        let retained_path = configured_path.with_extension("opened-directory");
        fs::rename(&configured_path, &retained_path)
            .unwrap_or_else(|error| panic!("configured directory rename failed: {error}"));
        fs::rename(replacement.path(), &configured_path)
            .unwrap_or_else(|error| panic!("replacement installation failed: {error}"));

        ensure_fresh_directory(&handle)
            .unwrap_or_else(|error| panic!("descriptor-relative fresh scan failed: {error}"));
        publish_atomic(
            &handle,
            b"descriptor-owned",
            [0x51; 16],
            PublishMode::RequireMissing,
            CommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("descriptor-relative publish failed: {error:?}"));
        let orphan_name = ".authority.snapshot.tmp-51515151515151515151515151515151";
        let orphan_path = retained_path.join(orphan_name);
        fs::write(&orphan_path, b"orphan")
            .unwrap_or_else(|error| panic!("retained orphan write failed: {error}"));
        fs::set_permissions(&orphan_path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("retained orphan chmod failed: {error}"));
        clean_valid_orphan_temps(&handle)
            .unwrap_or_else(|error| panic!("descriptor-relative cleanup failed: {error}"));

        assert_eq!(
            fs::read(retained_path.join(ACTIVE_FILE_NAME))
                .unwrap_or_else(|error| panic!("retained active read failed: {error}")),
            b"descriptor-owned"
        );
        assert!(!orphan_path.exists());
        assert!(!configured_path.join(ACTIVE_FILE_NAME).exists());
        assert_eq!(
            fs::read(configured_path.join("attacker-entry"))
                .unwrap_or_else(|error| panic!("replacement marker read failed: {error}")),
            b"replacement"
        );

        fs::remove_dir_all(&configured_path)
            .unwrap_or_else(|error| panic!("replacement cleanup failed: {error}"));
        fs::rename(&retained_path, &configured_path)
            .unwrap_or_else(|error| panic!("configured directory restore failed: {error}"));
    }

    #[test]
    fn symlinked_directory_components_and_active_files_are_rejected() {
        let target = TestDirectory::new();
        let parent = TestDirectory::new();
        let link = parent.path().join("linked");
        symlink(target.path(), &link)
            .unwrap_or_else(|error| panic!("fixture symlink failed: {error}"));
        assert_eq!(
            open_directory(&link, FilesystemPolicy::ExplicitFixture).err(),
            Some(StoreOpenError::SymlinkInDirectoryPath)
        );

        fs::write(target.path().join(LOCK_FILE_NAME), b"")
            .unwrap_or_else(|error| panic!("fixture lock failed: {error}"));
        fs::set_permissions(
            target.path().join(LOCK_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap_or_else(|error| panic!("fixture lock chmod failed: {error}"));
        symlink(
            target.path().join(LOCK_FILE_NAME),
            target.path().join(ACTIVE_FILE_NAME),
        )
        .unwrap_or_else(|error| panic!("fixture active symlink failed: {error}"));
        let handle = open_directory(target.path(), FilesystemPolicy::ExplicitFixture)
            .unwrap_or_else(|error| panic!("fixture directory open failed: {error}"));
        assert!(matches!(
            super::read_active_snapshot(&handle),
            Err(StoreOpenError::Io(_))
        ));
    }
}
