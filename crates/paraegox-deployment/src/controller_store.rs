//! Controller-owned POSIX snapshot store.
//!
//! This is deliberately an owner-local implementation. It provides the file
//! and lock mechanics needed by the DeploymentController journal without
//! creating a generic storage service, a second state writer, or a portable
//! filesystem claim. Only the explicitly checked local filesystem profile is
//! accepted.

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
use nix::unistd::{UnlinkatFlags, getegid, geteuid, unlinkat};

use crate::controller_journal::{
    ControllerJournalError, ControllerJournalSnapshot, ControllerOwnerIdentityFingerprint,
    MAX_CONTROLLER_SNAPSHOT_BYTES,
};

pub(crate) const CONTROLLER_LOCK_FILE_NAME: &str = "controller.lock";
pub(crate) const CONTROLLER_ACTIVE_FILE_NAME: &str = "controller.snapshot";
const TEMP_FILE_PREFIX: &str = ".controller.snapshot.tmp-";
pub(crate) const CONTROLLER_TEMP_TOKEN_BYTES: usize = 16;
const TEMP_HEX_BYTES: usize = CONTROLLER_TEMP_TOKEN_BYTES * 2;
const MAX_ORPHAN_TEMP_FILES: usize = 32;
const STATE_DIRECTORY_MODE_BITS: u32 = 0o700;
const STATE_DIRECTORY_MODE_MASK: u32 = 0o7777;
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
pub(crate) enum ControllerFilesystemPolicy {
    ProductionReference,
    #[cfg(test)]
    ExplicitFixture,
}

pub(crate) struct ControllerDirectoryHandle {
    path: PathBuf,
    file: File,
    owner_uid: u32,
    owner_gid: u32,
}

impl fmt::Debug for ControllerDirectoryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerDirectoryHandle")
            .field("path", &self.path)
            .field("owner_uid", &self.owner_uid)
            .field("owner_gid", &self.owner_gid)
            .finish_non_exhaustive()
    }
}

pub(crate) struct ControllerStore {
    directory: ControllerDirectoryHandle,
    lock_file: File,
    snapshot: ControllerJournalSnapshot,
    state: ControllerStoreState,
}

impl fmt::Debug for ControllerStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerStore")
            .field("directory", &self.directory)
            .field("snapshot", &self.snapshot)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Drop for ControllerStore {
    fn drop(&mut self) {
        // Fork temporarily duplicates the open-file description. Releasing
        // the advisory lock explicitly keeps normal owner shutdown from
        // waiting for an unrelated CLOEXEC child to reach exec.
        let _ = self.lock_file.unlock();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControllerStoreState {
    Operational,
    Stopped,
}

impl ControllerStore {
    pub(crate) fn open(
        directory: &Path,
        expected_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
    ) -> Result<Self, ControllerStoreOpenError> {
        Self::open_with_policy(
            directory,
            expected_store_instance_id,
            expected_owner_identity,
            ControllerFilesystemPolicy::ProductionReference,
        )
    }

    pub(crate) fn open_for_sequence_one_receipt(
        directory: &Path,
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
    ) -> Result<Self, ControllerStoreOpenError> {
        Self::open_validated(
            directory,
            None,
            expected_owner_identity,
            ControllerFilesystemPolicy::ProductionReference,
        )
    }

    pub(crate) fn open_with_policy(
        directory: &Path,
        expected_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        filesystem_policy: ControllerFilesystemPolicy,
    ) -> Result<Self, ControllerStoreOpenError> {
        if expected_store_instance_id == [0; 32] {
            return Err(ControllerStoreOpenError::InvalidExpectedStoreIdentity);
        }
        Self::open_validated(
            directory,
            Some(expected_store_instance_id),
            expected_owner_identity,
            filesystem_policy,
        )
    }

    #[cfg(test)]
    pub(crate) fn open_for_sequence_one_receipt_with_policy(
        directory: &Path,
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        filesystem_policy: ControllerFilesystemPolicy,
    ) -> Result<Self, ControllerStoreOpenError> {
        Self::open_validated(directory, None, expected_owner_identity, filesystem_policy)
    }

    fn open_validated(
        directory: &Path,
        expected_store_instance_id: Option<[u8; 32]>,
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        filesystem_policy: ControllerFilesystemPolicy,
    ) -> Result<Self, ControllerStoreOpenError> {
        if expected_owner_identity
            .value()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(ControllerStoreOpenError::InvalidExpectedOwnerIdentity);
        }
        let directory = open_controller_directory(directory, filesystem_policy)?;
        let lock_file = open_existing_regular(
            &directory,
            CONTROLLER_LOCK_FILE_NAME,
            OFlag::O_RDWR,
            ControllerFileStage::OpenLock,
        )?;
        lock_file.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => ControllerStoreOpenError::LockContended,
            TryLockError::Error(error) => ControllerStoreOpenError::Io(ControllerIoFailure::new(
                ControllerFileStage::AcquireLock,
                &error,
            )),
        })?;

        let snapshot = read_active_controller_snapshot(&directory)?;
        if expected_store_instance_id
            .is_some_and(|expected| snapshot.store_instance_id() != &expected)
        {
            return Err(ControllerStoreOpenError::StoreInstanceMismatch);
        }
        if snapshot.owner_identity_fingerprint() != expected_owner_identity {
            return Err(ControllerStoreOpenError::OwnerIdentityMismatch);
        }
        clean_valid_orphan_temps(&directory)?;
        Ok(Self {
            directory,
            lock_file,
            snapshot,
            state: ControllerStoreState::Operational,
        })
    }

    pub(crate) fn snapshot(&self) -> Result<&ControllerJournalSnapshot, ControllerStoreError> {
        self.ensure_operational()?;
        Ok(&self.snapshot)
    }

    pub(crate) fn revalidate_current(
        &mut self,
    ) -> Result<&ControllerJournalSnapshot, ControllerStoreError> {
        self.ensure_operational()?;
        let disk = read_active_controller_snapshot(&self.directory).map_err(|error| {
            self.state = ControllerStoreState::Stopped;
            ControllerStoreError::Open(error)
        })?;
        if disk != self.snapshot {
            self.state = ControllerStoreState::Stopped;
            return Err(ControllerStoreError::ActiveSnapshotChanged);
        }
        Ok(&self.snapshot)
    }

    pub(crate) fn commit(
        &mut self,
        next: ControllerJournalSnapshot,
    ) -> Result<(), ControllerStoreError> {
        self.commit_with_failpoint(next, ControllerCommitFailpoint::None)
    }

    fn commit_with_failpoint(
        &mut self,
        next: ControllerJournalSnapshot,
        failpoint: ControllerCommitFailpoint,
    ) -> Result<(), ControllerStoreError> {
        self.ensure_operational()?;
        next.validate_successor_of(&self.snapshot)
            .map_err(|error| {
                self.state = ControllerStoreState::Stopped;
                ControllerStoreError::InvalidSuccessor(error)
            })?;
        self.revalidate_current()?;
        let encoded = next.encode().map_err(|error| {
            self.state = ControllerStoreState::Stopped;
            ControllerStoreError::Codec(error)
        })?;
        let token = system_random_token().map_err(|error| {
            self.state = ControllerStoreState::Stopped;
            ControllerStoreError::Publish(ControllerPublishFailure::RejectedBeforePublish(
                ControllerPublishFault::io(ControllerFileStage::GenerateTempName, &error),
            ))
        })?;
        match publish_controller_snapshot(
            &self.directory,
            &encoded,
            token,
            ControllerPublishMode::ReplaceExisting,
            failpoint,
        ) {
            Ok(()) => {
                self.snapshot = next;
                Ok(())
            }
            Err(error) => {
                // A caller must reopen and re-read the authoritative active
                // path even for a pre-publish failure. In particular, no
                // process may continue after a rename/fsync ambiguity.
                self.state = ControllerStoreState::Stopped;
                Err(ControllerStoreError::Publish(error))
            }
        }
    }

    fn ensure_operational(&self) -> Result<(), ControllerStoreError> {
        let _ = &self.lock_file;
        if self.state == ControllerStoreState::Stopped {
            return Err(ControllerStoreError::Stopped);
        }
        Ok(())
    }
}

pub(crate) fn open_controller_directory(
    path: &Path,
    filesystem_policy: ControllerFilesystemPolicy,
) -> Result<ControllerDirectoryHandle, ControllerStoreOpenError> {
    validate_absolute_path_chain(path)?;
    let owner_uid = geteuid().as_raw();
    let owner_gid = getegid().as_raw();
    validate_trusted_ancestor_chain(path, owner_uid)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::InspectDirectory,
            &error,
        ))
    })?;
    validate_directory_metadata(&metadata, owner_uid, owner_gid)?;
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        ControllerStoreOpenError::Io(nix_failure(ControllerFileStage::OpenDirectory, error))
    })?;
    let file = File::from(owned);
    let opened_metadata = file.metadata().map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::OpenDirectory,
            &error,
        ))
    })?;
    validate_directory_metadata(&opened_metadata, owner_uid, owner_gid)?;
    if opened_metadata.dev() != metadata.dev() || opened_metadata.ino() != metadata.ino() {
        return Err(ControllerStoreOpenError::DirectoryIdentityChanged);
    }
    verify_filesystem(&file, filesystem_policy)?;
    Ok(ControllerDirectoryHandle {
        path: path.to_path_buf(),
        file,
        owner_uid,
        owner_gid,
    })
}

fn validate_directory_metadata(
    metadata: &Metadata,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), ControllerStoreOpenError> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() || metadata.nlink() == 0
    {
        return Err(ControllerStoreOpenError::UnsafeDirectoryType);
    }
    if metadata.uid() != owner_uid || metadata.gid() != owner_gid {
        return Err(ControllerStoreOpenError::DirectoryOwnerMismatch);
    }
    if metadata.mode() & STATE_DIRECTORY_MODE_MASK != STATE_DIRECTORY_MODE_BITS {
        return Err(ControllerStoreOpenError::UnsafeDirectoryMode);
    }
    Ok(())
}

pub(crate) fn ensure_fresh_controller_directory(
    directory: &ControllerDirectoryHandle,
) -> Result<(), ControllerStoreOpenError> {
    match openat(
        &directory.file,
        CONTROLLER_LOCK_FILE_NAME,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(existing) => {
            drop(existing);
            return Err(ControllerStoreOpenError::InitializerMarkerAlreadyPresent);
        }
        Err(nix::errno::Errno::ENOENT) => {}
        Err(_) => return Err(ControllerStoreOpenError::InitializerMarkerAlreadyPresent),
    }
    let mut entries = duplicate_directory_stream(directory)?;
    for entry in entries.iter() {
        let entry = entry.map_err(|error| {
            ControllerStoreOpenError::Io(nix_failure(ControllerFileStage::ScanDirectory, error))
        })?;
        if !is_dot_entry(entry.file_name().to_bytes()) {
            return Err(ControllerStoreOpenError::DirectoryNotFresh);
        }
    }
    Ok(())
}

pub(crate) fn create_and_lock_controller_initializer_lock(
    directory: &ControllerDirectoryHandle,
) -> Result<File, ControllerInitializerLockFailure> {
    let owned = openat(
        &directory.file,
        CONTROLLER_LOCK_FILE_NAME,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(|error| {
        let failure =
            ControllerStoreOpenError::Io(nix_failure(ControllerFileStage::CreateLock, error));
        if error == nix::errno::Errno::EEXIST {
            ControllerInitializerLockFailure::MarkerConsumed(failure)
        } else {
            ControllerInitializerLockFailure::RejectedBeforeMarker(failure)
        }
    })?;
    let lock_file = File::from(owned);
    fchmod(&lock_file, PRIVATE_FILE_MODE)
        .map_err(|error| marker_consumed_nix(ControllerFileStage::CreateLock, error))?;
    validate_regular_file(
        &lock_file
            .metadata()
            .map_err(|error| marker_consumed_io(ControllerFileStage::CreateLock, &error))?,
        directory.owner_uid,
        directory.owner_gid,
    )
    .map_err(ControllerInitializerLockFailure::MarkerConsumed)?;
    lock_file
        .sync_all()
        .map_err(|error| marker_consumed_io(ControllerFileStage::SyncInitializerMarker, &error))?;
    directory.file.sync_all().map_err(|error| {
        marker_consumed_io(ControllerFileStage::SyncInitializerMarkerDirectory, &error)
    })?;
    lock_file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => ControllerInitializerLockFailure::MarkerConsumed(
            ControllerStoreOpenError::LockContended,
        ),
        TryLockError::Error(error) => marker_consumed_io(ControllerFileStage::AcquireLock, &error),
    })?;
    validate_initializer_lock_is_only_entry(directory, &lock_file)
        .map_err(ControllerInitializerLockFailure::MarkerConsumed)?;
    Ok(lock_file)
}

fn marker_consumed_io(
    stage: ControllerFileStage,
    error: &io::Error,
) -> ControllerInitializerLockFailure {
    ControllerInitializerLockFailure::MarkerConsumed(ControllerStoreOpenError::Io(
        ControllerIoFailure::new(stage, error),
    ))
}

fn marker_consumed_nix(
    stage: ControllerFileStage,
    error: nix::errno::Errno,
) -> ControllerInitializerLockFailure {
    ControllerInitializerLockFailure::MarkerConsumed(ControllerStoreOpenError::Io(nix_failure(
        stage, error,
    )))
}

fn validate_initializer_lock_is_only_entry(
    directory: &ControllerDirectoryHandle,
    initializer_lock: &File,
) -> Result<(), ControllerStoreOpenError> {
    let expected = initializer_lock.metadata().map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::ValidateInitializerMarker,
            &error,
        ))
    })?;
    validate_regular_file(&expected, directory.owner_uid, directory.owner_gid)?;
    let installed = open_existing_regular(
        directory,
        CONTROLLER_LOCK_FILE_NAME,
        OFlag::O_RDONLY,
        ControllerFileStage::ValidateInitializerMarker,
    )?;
    let installed = installed.metadata().map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::ValidateInitializerMarker,
            &error,
        ))
    })?;
    if expected.dev() != installed.dev() || expected.ino() != installed.ino() {
        return Err(ControllerStoreOpenError::InitializerMarkerIdentityChanged);
    }

    let mut entries = duplicate_directory_stream(directory)?;
    let mut initializer_lock_entries = 0_usize;
    for entry in entries.iter() {
        let entry = entry.map_err(|error| {
            ControllerStoreOpenError::Io(nix_failure(
                ControllerFileStage::ValidateInitializerMarker,
                error,
            ))
        })?;
        let name = entry.file_name().to_bytes();
        if is_dot_entry(name) {
            continue;
        }
        if name != CONTROLLER_LOCK_FILE_NAME.as_bytes() {
            return Err(ControllerStoreOpenError::DirectoryNotFresh);
        }
        initializer_lock_entries += 1;
    }
    if initializer_lock_entries != 1 {
        return Err(ControllerStoreOpenError::InitializerMarkerIdentityChanged);
    }
    Ok(())
}

pub(crate) fn publish_initial_controller_snapshot(
    directory: &ControllerDirectoryHandle,
    encoded: &[u8],
    temp_token: [u8; CONTROLLER_TEMP_TOKEN_BYTES],
    failpoint: ControllerCommitFailpoint,
) -> Result<(), ControllerPublishFailure> {
    publish_controller_snapshot(
        directory,
        encoded,
        temp_token,
        ControllerPublishMode::RequireMissing,
        failpoint,
    )
}

pub(crate) fn read_active_controller_snapshot(
    directory: &ControllerDirectoryHandle,
) -> Result<ControllerJournalSnapshot, ControllerStoreOpenError> {
    let mut active = open_existing_regular(
        directory,
        CONTROLLER_ACTIVE_FILE_NAME,
        OFlag::O_RDONLY,
        ControllerFileStage::OpenActive,
    )?;
    let metadata = active.metadata().map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::ReadActive,
            &error,
        ))
    })?;
    let length =
        usize::try_from(metadata.len()).map_err(|_| ControllerStoreOpenError::ActiveTooLarge)?;
    if length == 0 {
        return Err(ControllerStoreOpenError::ActiveEmpty);
    }
    if length > MAX_CONTROLLER_SNAPSHOT_BYTES {
        return Err(ControllerStoreOpenError::ActiveTooLarge);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| ControllerStoreOpenError::ActiveAllocationFailed)?;
    encoded.resize(length, 0);
    active.read_exact(&mut encoded).map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::ReadActive,
            &error,
        ))
    })?;
    let mut trailing = [0; 1];
    if active.read(&mut trailing).map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::ReadActive,
            &error,
        ))
    })? != 0
    {
        return Err(ControllerStoreOpenError::ActiveChangedDuringRead);
    }
    let snapshot =
        ControllerJournalSnapshot::decode(&encoded).map_err(ControllerStoreOpenError::Codec)?;
    let canonical = snapshot.encode().map_err(ControllerStoreOpenError::Codec)?;
    if canonical.as_ref() != encoded.as_slice() {
        return Err(ControllerStoreOpenError::NonCanonicalActiveSnapshot);
    }
    Ok(snapshot)
}

fn open_existing_regular(
    directory: &ControllerDirectoryHandle,
    name: &str,
    access: OFlag,
    stage: ControllerFileStage,
) -> Result<File, ControllerStoreOpenError> {
    let owned = openat(
        &directory.file,
        name,
        access | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| ControllerStoreOpenError::Io(nix_failure(stage, error)))?;
    let file = File::from(owned);
    let metadata = file
        .metadata()
        .map_err(|error| ControllerStoreOpenError::Io(ControllerIoFailure::new(stage, &error)))?;
    validate_regular_file(&metadata, directory.owner_uid, directory.owner_gid)?;
    Ok(file)
}

fn validate_regular_file(
    metadata: &Metadata,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), ControllerStoreOpenError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(ControllerStoreOpenError::UnsafeFileType);
    }
    if metadata.uid() != owner_uid || metadata.gid() != owner_gid {
        return Err(ControllerStoreOpenError::FileOwnerMismatch);
    }
    if metadata.mode() & PRIVATE_FILE_MODE_MASK != PRIVATE_FILE_MODE_BITS {
        return Err(ControllerStoreOpenError::UnsafeFileMode);
    }
    Ok(())
}

fn clean_valid_orphan_temps(
    directory: &ControllerDirectoryHandle,
) -> Result<(), ControllerStoreOpenError> {
    let mut entries = duplicate_directory_stream(directory)?;
    let mut orphan_names = Vec::new();
    for entry in entries.iter() {
        let entry = entry.map_err(|error| {
            ControllerStoreOpenError::Io(nix_failure(ControllerFileStage::ScanDirectory, error))
        })?;
        let name_bytes = entry.file_name().to_bytes();
        if is_dot_entry(name_bytes) {
            continue;
        }
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| ControllerStoreOpenError::UnknownDirectoryEntry)?;
        if name == CONTROLLER_LOCK_FILE_NAME || name == CONTROLLER_ACTIVE_FILE_NAME {
            continue;
        }
        if !valid_temp_name(name) {
            return Err(ControllerStoreOpenError::UnknownDirectoryEntry);
        }
        orphan_names.push(name.to_owned());
        if orphan_names.len() > MAX_ORPHAN_TEMP_FILES {
            return Err(ControllerStoreOpenError::TooManyOrphanTemps);
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
            ControllerFileStage::InspectOrphanTemp,
        )?;
        drop(orphan);
        unlinkat(&directory.file, name.as_str(), UnlinkatFlags::NoRemoveDir).map_err(|error| {
            ControllerStoreOpenError::Io(nix_failure(ControllerFileStage::RemoveOrphanTemp, error))
        })?;
    }
    directory.file.sync_all().map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::SyncOrphanCleanup,
            &error,
        ))
    })?;
    Ok(())
}

fn duplicate_directory_stream(
    directory: &ControllerDirectoryHandle,
) -> Result<Dir, ControllerStoreOpenError> {
    let duplicate = directory.file.try_clone().map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::ScanDirectory,
            &error,
        ))
    })?;
    let descriptor: OwnedFd = duplicate.into();
    Dir::from_fd(descriptor).map_err(|error| {
        ControllerStoreOpenError::Io(nix_failure(ControllerFileStage::ScanDirectory, error))
    })
}

fn is_dot_entry(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

fn publish_controller_snapshot(
    directory: &ControllerDirectoryHandle,
    encoded: &[u8],
    token: [u8; CONTROLLER_TEMP_TOKEN_BYTES],
    mode: ControllerPublishMode,
    failpoint: ControllerCommitFailpoint,
) -> Result<(), ControllerPublishFailure> {
    if encoded.is_empty() || encoded.len() > MAX_CONTROLLER_SNAPSHOT_BYTES {
        return Err(ControllerPublishFailure::RejectedBeforePublish(
            ControllerPublishFault::injected(ControllerFileStage::ValidateEncodedSnapshot),
        ));
    }
    if failpoint == ControllerCommitFailpoint::BeforeTempCreate {
        return Err(rejected_injected(ControllerFileStage::CreateTemp));
    }
    match mode {
        ControllerPublishMode::RequireMissing => ensure_active_missing(directory)?,
        ControllerPublishMode::ReplaceExisting => {
            open_existing_regular(
                directory,
                CONTROLLER_ACTIVE_FILE_NAME,
                OFlag::O_RDONLY,
                ControllerFileStage::OpenActive,
            )
            .map_err(|error| rejected_open_error(ControllerFileStage::OpenActive, error))?;
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
        ControllerPublishFailure::RejectedBeforePublish(ControllerPublishFault::nix(
            ControllerFileStage::CreateTemp,
            error,
        ))
    })?;
    let mut temp = File::from(owned);
    fchmod(&temp, PRIVATE_FILE_MODE).map_err(|error| {
        ControllerPublishFailure::RejectedBeforePublish(ControllerPublishFault::nix(
            ControllerFileStage::InspectTemp,
            error,
        ))
    })?;
    validate_regular_file(
        &temp.metadata().map_err(|error| {
            ControllerPublishFailure::RejectedBeforePublish(ControllerPublishFault::io(
                ControllerFileStage::InspectTemp,
                &error,
            ))
        })?,
        directory.owner_uid,
        directory.owner_gid,
    )
    .map_err(|_| {
        ControllerPublishFailure::RejectedBeforePublish(ControllerPublishFault::injected(
            ControllerFileStage::InspectTemp,
        ))
    })?;
    if failpoint == ControllerCommitFailpoint::AfterTempCreate {
        return Err(rejected_injected(ControllerFileStage::CreateTemp));
    }
    if failpoint == ControllerCommitFailpoint::AfterPartialWrite {
        let partial_length = encoded.len().saturating_sub(1).max(1);
        temp.write_all(&encoded[..partial_length])
            .map_err(|error| {
                ControllerPublishFailure::RejectedBeforePublish(ControllerPublishFault::io(
                    ControllerFileStage::WriteTemp,
                    &error,
                ))
            })?;
        return Err(rejected_injected(ControllerFileStage::WriteTemp));
    }
    temp.write_all(encoded).map_err(|error| {
        ControllerPublishFailure::RejectedBeforePublish(ControllerPublishFault::io(
            ControllerFileStage::WriteTemp,
            &error,
        ))
    })?;
    if failpoint == ControllerCommitFailpoint::BeforeFileSync {
        return Err(rejected_injected(ControllerFileStage::SyncTemp));
    }
    temp.sync_all().map_err(|error| {
        ControllerPublishFailure::RejectedBeforePublish(ControllerPublishFault::io(
            ControllerFileStage::SyncTemp,
            &error,
        ))
    })?;
    if matches!(
        failpoint,
        ControllerCommitFailpoint::AfterFileSync | ControllerCommitFailpoint::BeforeRename
    ) {
        return Err(rejected_injected(ControllerFileStage::Rename));
    }
    if mode == ControllerPublishMode::RequireMissing {
        ensure_active_missing(directory)?;
    }
    renameat(
        &directory.file,
        temp_name.as_str(),
        &directory.file,
        CONTROLLER_ACTIVE_FILE_NAME,
    )
    .map_err(|error| {
        ControllerPublishFailure::RejectedBeforePublish(ControllerPublishFault::nix(
            ControllerFileStage::Rename,
            error,
        ))
    })?;
    if matches!(
        failpoint,
        ControllerCommitFailpoint::AfterRename | ControllerCommitFailpoint::BeforeDirectorySync
    ) {
        return Err(uncertain_injected(ControllerFileStage::SyncDirectory));
    }
    directory.file.sync_all().map_err(|error| {
        ControllerPublishFailure::UncertainAfterPublish(ControllerPublishFault::io(
            ControllerFileStage::SyncDirectory,
            &error,
        ))
    })?;
    if failpoint == ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn {
        return Err(uncertain_injected(ControllerFileStage::ReturnDurableCommit));
    }
    Ok(())
}

fn ensure_active_missing(
    directory: &ControllerDirectoryHandle,
) -> Result<(), ControllerPublishFailure> {
    match openat(
        &directory.file,
        CONTROLLER_ACTIVE_FILE_NAME,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => {
            drop(file);
            Err(ControllerPublishFailure::RejectedBeforePublish(
                ControllerPublishFault::injected(ControllerFileStage::RequireMissingActive),
            ))
        }
        Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(error) => Err(ControllerPublishFailure::RejectedBeforePublish(
            ControllerPublishFault::nix(ControllerFileStage::RequireMissingActive, error),
        )),
    }
}

fn system_random_token() -> Result<[u8; CONTROLLER_TEMP_TOKEN_BYTES], io::Error> {
    let owned = open(
        Path::new("/dev/urandom"),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(errno_to_io)?;
    let mut random = File::from(owned);
    let mut token = [0; CONTROLLER_TEMP_TOKEN_BYTES];
    random.read_exact(&mut token)?;
    if token.iter().all(|byte| *byte == 0) {
        return Err(io::Error::other(
            "CSPRNG returned an all-zero Controller temporary token",
        ));
    }
    Ok(token)
}

fn temp_name(token: [u8; CONTROLLER_TEMP_TOKEN_BYTES]) -> String {
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

fn validate_absolute_path_chain(path: &Path) -> Result<(), ControllerStoreOpenError> {
    if !path.is_absolute() {
        return Err(ControllerStoreOpenError::PathMustBeAbsolute);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    ControllerStoreOpenError::Io(ControllerIoFailure::new(
                        ControllerFileStage::InspectDirectory,
                        &error,
                    ))
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(ControllerStoreOpenError::SymlinkInDirectoryPath);
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ControllerStoreOpenError::UnsafeDirectoryPath);
            }
        }
    }
    Ok(())
}

fn validate_trusted_ancestor_chain(
    path: &Path,
    owner_uid: u32,
) -> Result<(), ControllerStoreOpenError> {
    let parent = path
        .parent()
        .ok_or(ControllerStoreOpenError::UnsafeDirectoryPath)?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => current.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ControllerStoreOpenError::UnsafeDirectoryPath);
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            ControllerStoreOpenError::Io(ControllerIoFailure::new(
                ControllerFileStage::InspectAncestor,
                &error,
            ))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || metadata.nlink() == 0
        {
            return Err(ControllerStoreOpenError::UnsafeAncestorType);
        }
        let mode = metadata.mode() & STATE_DIRECTORY_MODE_MASK;
        let root_owned_sticky = metadata.uid() == 0 && mode & 0o1000 != 0;
        let owner_is_trusted = metadata.uid() == 0 || metadata.uid() == owner_uid;
        if !owner_is_trusted || (mode & 0o022 != 0 && !root_owned_sticky) {
            return Err(ControllerStoreOpenError::UntrustedAncestor);
        }
    }
    Ok(())
}

fn verify_filesystem(
    directory: &File,
    _policy: ControllerFilesystemPolicy,
) -> Result<(), ControllerStoreOpenError> {
    #[cfg(test)]
    if _policy == ControllerFilesystemPolicy::ExplicitFixture {
        return Ok(());
    }
    #[cfg(not(target_os = "macos"))]
    let stat = nix::sys::statfs::fstatfs(directory).map_err(|error| {
        ControllerStoreOpenError::Io(nix_failure(ControllerFileStage::InspectFilesystem, error))
    })?;
    #[cfg(target_os = "linux")]
    {
        if stat.filesystem_type() != nix::sys::statfs::EXT4_SUPER_MAGIC {
            Err(ControllerStoreOpenError::UnsupportedFilesystem)
        } else {
            verify_linux_ext4_mount(directory)
                .map_err(|_| ControllerStoreOpenError::UnsupportedFilesystem)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stat;
        Err(ControllerStoreOpenError::UnsupportedFilesystem)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = directory;
        Err(ControllerStoreOpenError::UnsupportedFilesystem)
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

fn rejected_open_error(
    stage: ControllerFileStage,
    error: ControllerStoreOpenError,
) -> ControllerPublishFailure {
    match error {
        ControllerStoreOpenError::Io(failure) => {
            ControllerPublishFailure::RejectedBeforePublish(failure.into())
        }
        _ => {
            ControllerPublishFailure::RejectedBeforePublish(ControllerPublishFault::injected(stage))
        }
    }
}

fn rejected_injected(stage: ControllerFileStage) -> ControllerPublishFailure {
    ControllerPublishFailure::RejectedBeforePublish(ControllerPublishFault::injected(stage))
}

fn uncertain_injected(stage: ControllerFileStage) -> ControllerPublishFailure {
    ControllerPublishFailure::UncertainAfterPublish(ControllerPublishFault::injected(stage))
}

fn nix_failure(stage: ControllerFileStage, error: nix::errno::Errno) -> ControllerIoFailure {
    ControllerIoFailure::new(stage, &errno_to_io(error))
}

fn errno_to_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControllerPublishMode {
    RequireMissing,
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerCommitFailpoint {
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerFileStage {
    InspectAncestor,
    InspectDirectory,
    OpenDirectory,
    InspectFilesystem,
    ScanDirectory,
    CreateLock,
    SyncInitializerMarker,
    SyncInitializerMarkerDirectory,
    ValidateInitializerMarker,
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
pub(crate) struct ControllerIoFailure {
    pub(crate) stage: ControllerFileStage,
    pub(crate) kind: io::ErrorKind,
}

impl ControllerIoFailure {
    fn new(stage: ControllerFileStage, error: &io::Error) -> Self {
        Self {
            stage,
            kind: error.kind(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerPublishFault {
    pub(crate) stage: ControllerFileStage,
    pub(crate) kind: Option<io::ErrorKind>,
}

impl ControllerPublishFault {
    fn injected(stage: ControllerFileStage) -> Self {
        Self { stage, kind: None }
    }

    fn io(stage: ControllerFileStage, error: &io::Error) -> Self {
        Self {
            stage,
            kind: Some(error.kind()),
        }
    }

    fn nix(stage: ControllerFileStage, error: nix::errno::Errno) -> Self {
        Self::io(stage, &errno_to_io(error))
    }
}

impl From<ControllerIoFailure> for ControllerPublishFault {
    fn from(value: ControllerIoFailure) -> Self {
        Self {
            stage: value.stage,
            kind: Some(value.kind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerPublishFailure {
    RejectedBeforePublish(ControllerPublishFault),
    UncertainAfterPublish(ControllerPublishFault),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerInitializerLockFailure {
    RejectedBeforeMarker(ControllerStoreOpenError),
    MarkerConsumed(ControllerStoreOpenError),
}

impl fmt::Display for ControllerInitializerLockFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller initializer marker failed: {self:?}")
    }
}

impl std::error::Error for ControllerInitializerLockFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerStoreOpenError {
    PathMustBeAbsolute,
    UnsafeDirectoryPath,
    SymlinkInDirectoryPath,
    UnsafeAncestorType,
    UntrustedAncestor,
    UnsafeDirectoryType,
    UnsafeDirectoryMode,
    DirectoryOwnerMismatch,
    DirectoryIdentityChanged,
    UnsupportedFilesystem,
    DirectoryNotFresh,
    UnsafeFileType,
    UnsafeFileMode,
    FileOwnerMismatch,
    UnknownDirectoryEntry,
    TooManyOrphanTemps,
    LockContended,
    InitializerMarkerAlreadyPresent,
    InitializerMarkerIdentityChanged,
    ActiveEmpty,
    ActiveTooLarge,
    ActiveAllocationFailed,
    ActiveChangedDuringRead,
    NonCanonicalActiveSnapshot,
    InvalidExpectedStoreIdentity,
    InvalidExpectedOwnerIdentity,
    StoreInstanceMismatch,
    OwnerIdentityMismatch,
    Io(ControllerIoFailure),
    Codec(ControllerJournalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerStoreError {
    Stopped,
    ActiveSnapshotChanged,
    InvalidSuccessor(ControllerJournalError),
    Open(ControllerStoreOpenError),
    Codec(ControllerJournalError),
    Publish(ControllerPublishFailure),
}

impl fmt::Display for ControllerStoreOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller store cannot open: {self:?}")
    }
}

impl std::error::Error for ControllerStoreOpenError {}

impl fmt::Display for ControllerStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller store stopped: {self:?}")
    }
}

impl std::error::Error for ControllerStoreError {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

    use crate::controller_journal::{
        ControllerAuthKeyFingerprint, ControllerJournalSnapshot, ControllerJournalState,
        ControllerOperationId, ControllerOwnerIdentityFingerprint, ControllerRequestAuthPin,
    };
    use crate::plan::{DeploymentId, DeploymentScopeId};
    use crate::planner::{StableAllocationSnapshot, journal_test_candidate};

    use super::{
        CONTROLLER_ACTIVE_FILE_NAME, CONTROLLER_LOCK_FILE_NAME, ControllerCommitFailpoint,
        ControllerFilesystemPolicy, ControllerInitializerLockFailure, ControllerPublishFailure,
        ControllerStore, ControllerStoreError, ControllerStoreOpenError, LinuxMountEvidenceError,
        MAX_LINUX_FDINFO_BYTES, MAX_LINUX_FDINFO_LINE_BYTES, MAX_LINUX_FDINFO_RECORDS,
        MAX_LINUX_MOUNTINFO_BYTES, MAX_LINUX_MOUNTINFO_LINE_BYTES, MAX_LINUX_MOUNTINFO_RECORDS,
        create_and_lock_controller_initializer_lock, ensure_fresh_controller_directory,
        open_controller_directory, parse_linux_fdinfo_mount_id, parse_linux_mountinfo_exact_ext4,
        publish_initial_controller_snapshot,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
    const STORE_ID: [u8; 32] = [0x41; 32];

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
                "paraegox-controller-store-{}-{sequence}",
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

    #[cfg(target_os = "macos")]
    #[test]
    fn production_reference_rejects_real_apfs_directory() {
        let directory = TestDirectory::new();
        let stat = nix::sys::statfs::statfs(directory.path())
            .unwrap_or_else(|error| panic!("fixture filesystem inspection failed: {error}"));
        assert_eq!(
            stat.filesystem_type_name(),
            "apfs",
            "this regression must exercise a real APFS directory"
        );
        assert_eq!(
            open_controller_directory(
                directory.path(),
                ControllerFilesystemPolicy::ProductionReference,
            )
            .expect_err("macOS production Controller storage must fail closed"),
            ControllerStoreOpenError::UnsupportedFilesystem
        );
        open_controller_directory(
            directory.path(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("explicit fixture policy must remain available: {error}"));
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
        .unwrap_or_else(|error| panic!("fixture auth pin failed: {error}"))
    }

    fn initial_snapshot() -> ControllerJournalSnapshot {
        let target = RuntimeHostId::from_bytes([0x31; 16]);
        let allocation = StableAllocationSnapshot::try_new(target, 0, 0, Vec::new())
            .unwrap_or_else(|error| panic!("fixture allocation failed: {error}"));
        let state = ControllerJournalState::try_initialize(
            DeploymentScopeId::from_bytes([0x32; 16]),
            DeploymentId::from_bytes([0x33; 16]),
            allocation,
            auth(0x34, 1),
        )
        .unwrap_or_else(|error| panic!("fixture state failed: {error}"));
        ControllerJournalSnapshot::try_initialize(STORE_ID, owner(), state)
            .unwrap_or_else(|error| panic!("fixture snapshot failed: {error}"))
    }

    fn install(snapshot: &ControllerJournalSnapshot, directory: &TestDirectory) {
        let handle = open_controller_directory(
            directory.path(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("fixture directory open failed: {error}"));
        ensure_fresh_controller_directory(&handle)
            .unwrap_or_else(|error| panic!("fixture directory not fresh: {error}"));
        let _lock = create_and_lock_controller_initializer_lock(&handle)
            .unwrap_or_else(|error| panic!("fixture lock failed: {error}"));
        let encoded = snapshot
            .encode()
            .unwrap_or_else(|error| panic!("fixture encode failed: {error}"));
        publish_initial_controller_snapshot(
            &handle,
            &encoded,
            [0x51; 16],
            ControllerCommitFailpoint::None,
        )
        .unwrap_or_else(|error| panic!("fixture publish failed: {error:?}"));
    }

    fn open_fixture(directory: &TestDirectory) -> ControllerStore {
        ControllerStore::open_with_policy(
            directory.path(),
            STORE_ID,
            owner(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("fixture store open failed: {error}"))
    }

    fn successor_of(initial: &ControllerJournalSnapshot) -> ControllerJournalSnapshot {
        let allocation = StableAllocationSnapshot::try_new(
            RuntimeHostId::from_bytes([0x31; 16]),
            0,
            0,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("fixture allocation failed: {error}"));
        let candidate = journal_test_candidate(
            RuntimeHostId::from_bytes([0x31; 16]),
            &allocation,
            Some([0x35; 16]),
            0x36,
        )
        .unwrap_or_else(|error| panic!("fixture candidate failed: {error}"));
        let next_state = initial
            .state()
            .prepare_plan_candidate(ControllerOperationId::from_bytes([0x37; 16]), &candidate)
            .unwrap_or_else(|error| panic!("fixture prepare failed: {error}"));
        initial
            .try_successor(next_state)
            .unwrap_or_else(|error| panic!("fixture successor failed: {error}"))
    }

    #[test]
    fn initializer_marker_revalidation_rejects_any_additional_entry() {
        let directory = TestDirectory::new();
        let handle = open_controller_directory(
            directory.path(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("fixture directory open failed: {error}"));
        fs::write(directory.path().join("unexpected"), b"unexpected")
            .unwrap_or_else(|error| panic!("unexpected entry create failed: {error}"));
        fs::set_permissions(
            directory.path().join("unexpected"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap_or_else(|error| panic!("unexpected entry chmod failed: {error}"));
        assert_eq!(
            create_and_lock_controller_initializer_lock(&handle)
                .expect_err("marker revalidation must reject an additional entry"),
            ControllerInitializerLockFailure::MarkerConsumed(
                ControllerStoreOpenError::DirectoryNotFresh
            )
        );
        assert!(directory.path().join(CONTROLLER_LOCK_FILE_NAME).is_file());
    }

    #[test]
    fn store_commits_only_a_validated_successor_and_reopens_exact_bytes() {
        let directory = TestDirectory::new();
        let initial = initial_snapshot();
        install(&initial, &directory);
        let mut store = open_fixture(&directory);
        let next = successor_of(&initial);
        store
            .commit(next.clone())
            .unwrap_or_else(|error| panic!("fixture commit failed: {error}"));
        assert_eq!(store.snapshot(), Ok(&next));
        drop(store);
        assert_eq!(open_fixture(&directory).snapshot(), Ok(&next));
    }

    #[test]
    fn prepublish_rejection_preserves_old_snapshot_and_stops_owner() {
        let directory = TestDirectory::new();
        let initial = initial_snapshot();
        install(&initial, &directory);
        let mut store = open_fixture(&directory);
        let next = successor_of(&initial);
        assert!(matches!(
            store.commit_with_failpoint(next, ControllerCommitFailpoint::BeforeRename),
            Err(ControllerStoreError::Publish(
                ControllerPublishFailure::RejectedBeforePublish(_)
            ))
        ));
        assert!(matches!(
            store.revalidate_current(),
            Err(ControllerStoreError::Stopped)
        ));
        assert_eq!(store.snapshot().err(), Some(ControllerStoreError::Stopped));
        drop(store);
        assert_eq!(open_fixture(&directory).snapshot(), Ok(&initial));
    }

    #[test]
    fn postrename_ambiguity_publishes_complete_successor_but_stops_owner() {
        let directory = TestDirectory::new();
        let initial = initial_snapshot();
        install(&initial, &directory);
        let mut store = open_fixture(&directory);
        let next = successor_of(&initial);
        assert!(matches!(
            store.commit_with_failpoint(
                next.clone(),
                ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn,
            ),
            Err(ControllerStoreError::Publish(
                ControllerPublishFailure::UncertainAfterPublish(_)
            ))
        ));
        assert!(matches!(
            store.revalidate_current(),
            Err(ControllerStoreError::Stopped)
        ));
        assert_eq!(store.snapshot().err(), Some(ControllerStoreError::Stopped));
        drop(store);
        assert_eq!(open_fixture(&directory).snapshot(), Ok(&next));
    }

    #[test]
    fn external_active_change_is_detected_before_commit_and_stops_owner() {
        let directory = TestDirectory::new();
        let initial = initial_snapshot();
        install(&initial, &directory);
        let mut store = open_fixture(&directory);
        let changed = successor_of(&initial);
        fs::write(
            directory.path().join(CONTROLLER_ACTIVE_FILE_NAME),
            changed
                .encode()
                .unwrap_or_else(|error| panic!("fixture encode failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("fixture active replacement failed: {error}"));
        assert!(matches!(
            store.revalidate_current(),
            Err(ControllerStoreError::ActiveSnapshotChanged)
        ));
        assert!(matches!(
            store.revalidate_current(),
            Err(ControllerStoreError::Stopped)
        ));
        assert_eq!(store.snapshot().err(), Some(ControllerStoreError::Stopped));
    }

    #[test]
    fn path_mode_symlink_and_identity_mismatches_fail_closed() {
        let directory = TestDirectory::new();
        assert_eq!(
            ControllerStore::open_with_policy(
                Path::new("relative-controller-store"),
                STORE_ID,
                ControllerOwnerIdentityFingerprint::from_stored(digest(0)),
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("zero expected owner must fail before filesystem access"),
            ControllerStoreOpenError::InvalidExpectedOwnerIdentity
        );
        assert_eq!(
            open_controller_directory(
                Path::new("relative-controller-store"),
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("relative path must fail"),
            ControllerStoreOpenError::PathMustBeAbsolute
        );

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))
            .unwrap_or_else(|error| panic!("fixture chmod failed: {error}"));
        assert_eq!(
            open_controller_directory(
                directory.path(),
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("unsafe mode must fail"),
            ControllerStoreOpenError::UnsafeDirectoryMode
        );
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("fixture chmod failed: {error}"));

        let ancestor_root = TestDirectory::new();
        let peer_writable = ancestor_root.path().join("peer-writable");
        fs::create_dir(&peer_writable)
            .unwrap_or_else(|error| panic!("fixture ancestor create failed: {error}"));
        fs::set_permissions(&peer_writable, fs::Permissions::from_mode(0o770))
            .unwrap_or_else(|error| panic!("fixture ancestor chmod failed: {error}"));
        let nested_directory = peer_writable.join("state");
        fs::create_dir(&nested_directory)
            .unwrap_or_else(|error| panic!("fixture nested directory create failed: {error}"));
        fs::set_permissions(&nested_directory, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("fixture nested directory chmod failed: {error}"));
        assert_eq!(
            open_controller_directory(
                &nested_directory,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("peer-writable ancestor must fail"),
            ControllerStoreOpenError::UntrustedAncestor
        );

        let link = directory.path().with_extension("link");
        symlink(directory.path(), &link)
            .unwrap_or_else(|error| panic!("fixture symlink failed: {error}"));
        assert_eq!(
            open_controller_directory(&link, ControllerFilesystemPolicy::ExplicitFixture)
                .expect_err("symlink path must fail"),
            ControllerStoreOpenError::SymlinkInDirectoryPath
        );
        fs::remove_file(link)
            .unwrap_or_else(|error| panic!("fixture symlink cleanup failed: {error}"));

        let initial = initial_snapshot();
        install(&initial, &directory);
        assert_eq!(
            ControllerStore::open_with_policy(
                directory.path(),
                [0x99; 32],
                owner(),
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("wrong store identity must fail"),
            ControllerStoreOpenError::StoreInstanceMismatch
        );
    }

    #[test]
    fn second_owner_cannot_acquire_the_live_lock() {
        let directory = TestDirectory::new();
        let initial = initial_snapshot();
        install(&initial, &directory);
        let first = open_fixture(&directory);
        assert_eq!(
            ControllerStore::open_with_policy(
                directory.path(),
                STORE_ID,
                owner(),
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("contending owner must fail"),
            ControllerStoreOpenError::LockContended
        );
        drop(first);
        assert!(directory.path().join(CONTROLLER_LOCK_FILE_NAME).is_file());
    }

    #[test]
    fn normal_drop_unlocks_even_while_a_fork_like_descriptor_reference_survives() {
        let directory = TestDirectory::new();
        let initial = initial_snapshot();
        install(&initial, &directory);
        let first = open_fixture(&directory);
        let inherited_lock_reference = first
            .lock_file
            .try_clone()
            .unwrap_or_else(|error| panic!("lock descriptor clone failed: {error}"));

        drop(first);
        let replacement = open_fixture(&directory);

        drop(replacement);
        drop(inherited_lock_reference);
    }
}
