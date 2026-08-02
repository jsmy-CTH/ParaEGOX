#![cfg(unix)]

//! Owner-private Unix file boundary for Runtime release/install artifacts.
//!
//! This is deliberately not a general filesystem or platform abstraction.  It
//! reads the one bounded Runtime build descriptor and publishes only the small
//! descriptor, singleton manifest, and digest artifacts used by the S7 install
//! operation.  Output publication never overwrites a name: an existing file is
//! accepted only as a byte-identical crash retry.

use core::fmt;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{getegid, geteuid};
use paraegox_runtime_contracts::installation::MAX_INSTALLED_RUNTIME_BUILD_DESCRIPTOR_BYTES;

const DIRECTORY_MODE_MASK: u32 = 0o7777;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE_BITS: u32 = 0o600;
const PRIVATE_FILE_MODE: Mode = Mode::S_IRUSR.union(Mode::S_IWUSR);

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegularFileIdentity {
    file: FileIdentity,
    length: u64,
}

impl RegularFileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            file: FileIdentity::from_metadata(metadata),
            length: metadata.len(),
        }
    }
}

struct ParentDirectory {
    file: File,
    identity: FileIdentity,
}

struct OpenedRegularFile {
    file: File,
    identity: RegularFileIdentity,
}

/// Linear preflight for one install artifact output name.
///
/// The retained parent descriptor anchors all later operations.  The value is
/// intentionally neither `Clone` nor reusable: publication consumes it.
pub(crate) struct RuntimeInstallArtifactOutput {
    parent: ParentDirectory,
    name: OsString,
    maximum_bytes: usize,
    owner_uid: u32,
    owner_gid: u32,
    existing_identity: Option<RegularFileIdentity>,
}

impl RuntimeInstallArtifactOutput {
    /// Validates and pins an absolute output path without creating its target.
    ///
    /// The final parent must be a symlink-free directory owned by the current
    /// effective UID/GID with exact mode `0700`.  An existing target is only a
    /// provisional crash-retry candidate; [`Self::publish_or_verify_exact`]
    /// still requires its bytes to be identical to the requested artifact.
    pub(crate) fn preflight(
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Self, RuntimeInstallFileError> {
        validate_maximum(maximum_bytes)?;
        let owner_uid = geteuid().as_raw();
        let owner_gid = getegid().as_raw();
        let (parent, name) = open_absolute_parent(path, RuntimeInstallFileStage::OpenOutputParent)?;
        validate_private_parent(&parent.file, parent.identity, owner_uid, owner_gid)?;
        let existing_identity = inspect_existing_output(
            &parent.file,
            name.as_os_str(),
            maximum_bytes,
            owner_uid,
            owner_gid,
        )?;
        Ok(Self {
            parent,
            name,
            maximum_bytes,
            owner_uid,
            owner_gid,
            existing_identity,
        })
    }

    /// Creates and durably publishes the exact bytes, or verifies one exact
    /// byte-identical existing artifact left by the same install operation.
    ///
    /// The target is never truncated, renamed over, or otherwise overwritten.
    /// Any failure after `O_EXCL` creation leaves the partial target fail-closed
    /// for explicit operator recovery.
    pub(crate) fn publish_or_verify_exact(
        self,
        bytes: &[u8],
    ) -> Result<(), RuntimeInstallFileError> {
        validate_bytes(bytes, self.maximum_bytes)?;
        validate_private_parent(
            &self.parent.file,
            self.parent.identity,
            self.owner_uid,
            self.owner_gid,
        )?;

        if let Some(expected) = self.existing_identity {
            return self.verify_existing_retry(bytes, Some(expected));
        }

        let owned = match openat(
            &self.parent.file,
            self.name.as_os_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            PRIVATE_FILE_MODE,
        ) {
            Ok(owned) => owned,
            Err(nix::errno::Errno::EEXIST) => return self.verify_existing_retry(bytes, None),
            Err(error) => {
                return Err(nix_failure(RuntimeInstallFileStage::CreateOutput, error));
            }
        };
        let mut output = File::from(owned);
        fchmod(&output, PRIVATE_FILE_MODE)
            .map_err(|error| nix_failure(RuntimeInstallFileStage::InspectCreatedOutput, error))?;
        let created_metadata = output
            .metadata()
            .map_err(|error| io_failure(RuntimeInstallFileStage::InspectCreatedOutput, &error))?;
        validate_output_metadata(&created_metadata, self.owner_uid, self.owner_gid)?;
        if created_metadata.len() != 0 {
            return Err(RuntimeInstallFileError::FileIdentityChanged);
        }
        let created_identity = RegularFileIdentity::from_metadata(&created_metadata);

        output
            .write_all(bytes)
            .map_err(|error| io_failure(RuntimeInstallFileStage::WriteOutput, &error))?;
        output
            .sync_all()
            .map_err(|error| io_failure(RuntimeInstallFileStage::SyncOutput, &error))?;
        let written_metadata = output
            .metadata()
            .map_err(|error| io_failure(RuntimeInstallFileStage::InspectCreatedOutput, &error))?;
        validate_output_metadata(&written_metadata, self.owner_uid, self.owner_gid)?;
        if FileIdentity::from_metadata(&written_metadata) != created_identity.file
            || written_metadata.len()
                != u64::try_from(bytes.len())
                    .map_err(|_| RuntimeInstallFileError::ArtifactTooLarge)?
        {
            return Err(RuntimeInstallFileError::ArtifactChangedDuringRead);
        }
        let published_identity = RegularFileIdentity::from_metadata(&written_metadata);
        drop(output);

        self.verify_named_exact(bytes, Some(published_identity))?;
        self.parent
            .file
            .sync_all()
            .map_err(|error| io_failure(RuntimeInstallFileStage::SyncOutputDirectory, &error))?;
        validate_private_parent(
            &self.parent.file,
            self.parent.identity,
            self.owner_uid,
            self.owner_gid,
        )?;
        self.verify_named_exact(bytes, Some(published_identity))?;
        Ok(())
    }

    fn verify_existing_retry(
        &self,
        bytes: &[u8],
        expected_identity: Option<RegularFileIdentity>,
    ) -> Result<(), RuntimeInstallFileError> {
        let opened = self.verify_named_exact(bytes, expected_identity)?;
        opened
            .file
            .sync_all()
            .map_err(|error| io_failure(RuntimeInstallFileStage::SyncOutput, &error))?;
        self.parent
            .file
            .sync_all()
            .map_err(|error| io_failure(RuntimeInstallFileStage::SyncOutputDirectory, &error))?;
        validate_private_parent(
            &self.parent.file,
            self.parent.identity,
            self.owner_uid,
            self.owner_gid,
        )?;
        self.verify_named_exact(bytes, Some(opened.identity))?;
        Ok(())
    }

    fn verify_named_exact(
        &self,
        bytes: &[u8],
        expected_identity: Option<RegularFileIdentity>,
    ) -> Result<OpenedRegularFile, RuntimeInstallFileError> {
        let mut opened = open_existing_output(
            &self.parent.file,
            self.name.as_os_str(),
            self.owner_uid,
            self.owner_gid,
        )?;
        validate_existing_length(opened.identity.length, self.maximum_bytes)?;
        if expected_identity.is_some_and(|expected| expected != opened.identity) {
            return Err(RuntimeInstallFileError::FileIdentityChanged);
        }
        if opened.identity.length
            != u64::try_from(bytes.len()).map_err(|_| RuntimeInstallFileError::ArtifactTooLarge)?
        {
            return Err(RuntimeInstallFileError::ExistingArtifactMismatch);
        }

        let observed = read_bounded(&mut opened.file, self.maximum_bytes)?;
        let after = opened
            .file
            .metadata()
            .map_err(|error| io_failure(RuntimeInstallFileStage::InspectExistingOutput, &error))?;
        validate_output_metadata(&after, self.owner_uid, self.owner_gid)?;
        if RegularFileIdentity::from_metadata(&after) != opened.identity {
            return Err(RuntimeInstallFileError::ArtifactChangedDuringRead);
        }
        if observed.as_slice() != bytes {
            return Err(RuntimeInstallFileError::ExistingArtifactMismatch);
        }
        Ok(opened)
    }
}

/// Reads one canonical Runtime build descriptor from a pinned, safe file.
pub(crate) fn read_runtime_build_descriptor(
    path: &Path,
) -> Result<Box<[u8]>, RuntimeInstallFileError> {
    let owner_uid = geteuid().as_raw();
    let (parent, name) = open_absolute_parent(path, RuntimeInstallFileStage::OpenInputParent)?;
    let mut input = open_named_input(&parent.file, name.as_os_str())?;
    let before = input
        .metadata()
        .map_err(|error| io_failure(RuntimeInstallFileStage::InspectInput, &error))?;
    validate_input_metadata(&before, owner_uid)?;
    validate_existing_length(before.len(), MAX_INSTALLED_RUNTIME_BUILD_DESCRIPTOR_BYTES)?;
    let identity = RegularFileIdentity::from_metadata(&before);
    let bytes = read_bounded(&mut input, MAX_INSTALLED_RUNTIME_BUILD_DESCRIPTOR_BYTES)?;
    let after = input
        .metadata()
        .map_err(|error| io_failure(RuntimeInstallFileStage::InspectInput, &error))?;
    validate_input_metadata(&after, owner_uid)?;
    if RegularFileIdentity::from_metadata(&after) != identity
        || after.len()
            != u64::try_from(bytes.len()).map_err(|_| RuntimeInstallFileError::ArtifactTooLarge)?
    {
        return Err(RuntimeInstallFileError::ArtifactChangedDuringRead);
    }

    let current = open_named_input(&parent.file, name.as_os_str())?;
    let current_metadata = current
        .metadata()
        .map_err(|error| io_failure(RuntimeInstallFileStage::InspectInput, &error))?;
    validate_input_metadata(&current_metadata, owner_uid)?;
    if RegularFileIdentity::from_metadata(&current_metadata) != identity {
        return Err(RuntimeInstallFileError::FileIdentityChanged);
    }
    Ok(bytes.into_boxed_slice())
}

fn validate_maximum(maximum_bytes: usize) -> Result<(), RuntimeInstallFileError> {
    if maximum_bytes == 0 || maximum_bytes > MAX_INSTALLED_RUNTIME_BUILD_DESCRIPTOR_BYTES {
        return Err(RuntimeInstallFileError::InvalidArtifactBound);
    }
    Ok(())
}

fn validate_bytes(bytes: &[u8], maximum_bytes: usize) -> Result<(), RuntimeInstallFileError> {
    validate_maximum(maximum_bytes)?;
    if bytes.is_empty() {
        return Err(RuntimeInstallFileError::InvalidArtifactLength);
    }
    if bytes.len() > maximum_bytes {
        return Err(RuntimeInstallFileError::ArtifactTooLarge);
    }
    Ok(())
}

fn validate_existing_length(
    length: u64,
    maximum_bytes: usize,
) -> Result<(), RuntimeInstallFileError> {
    let maximum =
        u64::try_from(maximum_bytes).map_err(|_| RuntimeInstallFileError::InvalidArtifactBound)?;
    if length == 0 {
        return Err(RuntimeInstallFileError::InvalidArtifactLength);
    }
    if length > maximum {
        return Err(RuntimeInstallFileError::ArtifactTooLarge);
    }
    Ok(())
}

fn read_bounded(file: &mut File, maximum_bytes: usize) -> Result<Vec<u8>, RuntimeInstallFileError> {
    let capacity = maximum_bytes
        .checked_add(1)
        .ok_or(RuntimeInstallFileError::InvalidArtifactBound)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| RuntimeInstallFileError::AllocationFailed)?;
    let limit =
        u64::try_from(capacity).map_err(|_| RuntimeInstallFileError::InvalidArtifactBound)?;
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| io_failure(RuntimeInstallFileStage::ReadArtifact, &error))?;
    if bytes.len() > maximum_bytes {
        return Err(RuntimeInstallFileError::ArtifactTooLarge);
    }
    Ok(bytes)
}

fn open_absolute_parent(
    path: &Path,
    stage: RuntimeInstallFileStage,
) -> Result<(ParentDirectory, OsString), RuntimeInstallFileError> {
    validate_absolute_file_path(path)?;
    let name = path
        .file_name()
        .ok_or(RuntimeInstallFileError::UnsafePath)?
        .to_os_string();
    let parent = path.parent().ok_or(RuntimeInstallFileError::UnsafePath)?;
    let root = open(
        Path::new("/"),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| map_directory_open_error(stage, error))?;
    let mut current = File::from(root);
    for component in parent.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => {
                let owned = openat(
                    &current,
                    value,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|error| map_directory_open_error(stage, error))?;
                let next = File::from(owned);
                let metadata = next.metadata().map_err(|error| io_failure(stage, &error))?;
                validate_directory_type(&metadata)?;
                current = next;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(RuntimeInstallFileError::UnsafePath);
            }
        }
    }
    let metadata = current
        .metadata()
        .map_err(|error| io_failure(stage, &error))?;
    validate_directory_type(&metadata)?;
    Ok((
        ParentDirectory {
            file: current,
            identity: FileIdentity::from_metadata(&metadata),
        },
        name,
    ))
}

fn validate_absolute_file_path(path: &Path) -> Result<(), RuntimeInstallFileError> {
    if !path.is_absolute() {
        return Err(RuntimeInstallFileError::PathMustBeAbsolute);
    }
    if path.file_name().is_none() {
        return Err(RuntimeInstallFileError::UnsafePath);
    }
    for component in path.components() {
        if matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::Prefix(_)
        ) {
            return Err(RuntimeInstallFileError::UnsafePath);
        }
    }
    Ok(())
}

fn validate_directory_type(metadata: &Metadata) -> Result<(), RuntimeInstallFileError> {
    if !metadata.file_type().is_dir() || metadata.nlink() == 0 {
        return Err(RuntimeInstallFileError::UnsafeDirectoryType);
    }
    Ok(())
}

fn validate_private_parent(
    parent: &File,
    expected_identity: FileIdentity,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), RuntimeInstallFileError> {
    let metadata = parent
        .metadata()
        .map_err(|error| io_failure(RuntimeInstallFileStage::InspectOutputParent, &error))?;
    validate_directory_type(&metadata)?;
    if FileIdentity::from_metadata(&metadata) != expected_identity {
        return Err(RuntimeInstallFileError::DirectoryIdentityChanged);
    }
    if metadata.uid() != owner_uid || metadata.gid() != owner_gid {
        return Err(RuntimeInstallFileError::DirectoryOwnerMismatch);
    }
    if metadata.mode() & DIRECTORY_MODE_MASK != PRIVATE_DIRECTORY_MODE {
        return Err(RuntimeInstallFileError::UnsafeDirectoryMode);
    }
    Ok(())
}

fn open_named_input(parent: &File, name: &OsStr) -> Result<File, RuntimeInstallFileError> {
    openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| map_regular_open_error(RuntimeInstallFileStage::OpenInput, error))
}

fn validate_input_metadata(
    metadata: &Metadata,
    owner_uid: u32,
) -> Result<(), RuntimeInstallFileError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(RuntimeInstallFileError::UnsafeFileType);
    }
    if metadata.uid() != 0 && metadata.uid() != owner_uid {
        return Err(RuntimeInstallFileError::FileOwnerMismatch);
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(RuntimeInstallFileError::UnsafeFileMode);
    }
    Ok(())
}

fn inspect_existing_output(
    parent: &File,
    name: &OsStr,
    maximum_bytes: usize,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<Option<RegularFileIdentity>, RuntimeInstallFileError> {
    let first = match open_existing_output(parent, name, owner_uid, owner_gid) {
        Ok(opened) => opened,
        Err(RuntimeInstallFileError::Io {
            stage: RuntimeInstallFileStage::OpenExistingOutput,
            kind: io::ErrorKind::NotFound,
        }) => return Ok(None),
        Err(error) => return Err(error),
    };
    validate_existing_length(first.identity.length, maximum_bytes)?;
    let second = open_existing_output(parent, name, owner_uid, owner_gid)?;
    if second.identity != first.identity {
        return Err(RuntimeInstallFileError::FileIdentityChanged);
    }
    Ok(Some(first.identity))
}

fn open_existing_output(
    parent: &File,
    name: &OsStr,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<OpenedRegularFile, RuntimeInstallFileError> {
    let owned = openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| map_regular_open_error(RuntimeInstallFileStage::OpenExistingOutput, error))?;
    let file = File::from(owned);
    let metadata = file
        .metadata()
        .map_err(|error| io_failure(RuntimeInstallFileStage::InspectExistingOutput, &error))?;
    validate_output_metadata(&metadata, owner_uid, owner_gid)?;
    Ok(OpenedRegularFile {
        file,
        identity: RegularFileIdentity::from_metadata(&metadata),
    })
}

fn validate_output_metadata(
    metadata: &Metadata,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), RuntimeInstallFileError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(RuntimeInstallFileError::UnsafeFileType);
    }
    if metadata.uid() != owner_uid || metadata.gid() != owner_gid {
        return Err(RuntimeInstallFileError::FileOwnerMismatch);
    }
    if metadata.mode() & DIRECTORY_MODE_MASK != PRIVATE_FILE_MODE_BITS {
        return Err(RuntimeInstallFileError::UnsafeFileMode);
    }
    Ok(())
}

fn map_directory_open_error(
    stage: RuntimeInstallFileStage,
    error: nix::errno::Errno,
) -> RuntimeInstallFileError {
    if matches!(error, nix::errno::Errno::ELOOP | nix::errno::Errno::ENOTDIR) {
        RuntimeInstallFileError::UnsafeDirectoryType
    } else {
        nix_failure(stage, error)
    }
}

fn map_regular_open_error(
    stage: RuntimeInstallFileStage,
    error: nix::errno::Errno,
) -> RuntimeInstallFileError {
    if error == nix::errno::Errno::ELOOP {
        RuntimeInstallFileError::UnsafeFileType
    } else {
        nix_failure(stage, error)
    }
}

fn nix_failure(
    stage: RuntimeInstallFileStage,
    error: nix::errno::Errno,
) -> RuntimeInstallFileError {
    RuntimeInstallFileError::Io {
        stage,
        kind: io::Error::from_raw_os_error(error as i32).kind(),
    }
}

fn io_failure(stage: RuntimeInstallFileStage, error: &io::Error) -> RuntimeInstallFileError {
    RuntimeInstallFileError::Io {
        stage,
        kind: error.kind(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeInstallFileStage {
    OpenInputParent,
    OpenInput,
    InspectInput,
    ReadArtifact,
    OpenOutputParent,
    InspectOutputParent,
    OpenExistingOutput,
    InspectExistingOutput,
    CreateOutput,
    InspectCreatedOutput,
    WriteOutput,
    SyncOutput,
    SyncOutputDirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeInstallFileError {
    PathMustBeAbsolute,
    UnsafePath,
    InvalidArtifactBound,
    InvalidArtifactLength,
    ArtifactTooLarge,
    AllocationFailed,
    UnsafeDirectoryType,
    DirectoryOwnerMismatch,
    UnsafeDirectoryMode,
    DirectoryIdentityChanged,
    UnsafeFileType,
    FileOwnerMismatch,
    UnsafeFileMode,
    FileIdentityChanged,
    ArtifactChangedDuringRead,
    ExistingArtifactMismatch,
    Io {
        stage: RuntimeInstallFileStage,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for RuntimeInstallFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime install artifact file failure: {self:?}")
    }
}

impl std::error::Error for RuntimeInstallFileError {}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        MAX_INSTALLED_RUNTIME_BUILD_DESCRIPTOR_BYTES, RuntimeInstallArtifactOutput,
        RuntimeInstallFileError, read_runtime_build_descriptor,
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let root = std::env::current_dir()
                .unwrap_or_else(|error| panic!("current directory unavailable: {error}"))
                .join("target")
                .join("runtime-install-file-tests");
            fs::create_dir_all(&root)
                .unwrap_or_else(|error| panic!("test root creation failed: {error}"));
            let unique = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("case-{}-{unique}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(&path)
                .unwrap_or_else(|error| panic!("test directory creation failed: {error}"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0)
                .unwrap_or_else(|error| panic!("test directory cleanup failed: {error}"));
        }
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options
            .open(path)
            .unwrap_or_else(|error| panic!("test file creation failed: {error}"));
        file.write_all(bytes)
            .unwrap_or_else(|error| panic!("test file write failed: {error}"));
        file.sync_all()
            .unwrap_or_else(|error| panic!("test file sync failed: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("test file mode failed: {error}"));
    }

    #[test]
    fn descriptor_reader_accepts_one_safe_bounded_regular_file() {
        let directory = TestDirectory::new();
        let path = directory.join("runtime.pxbd");
        let expected = b"canonical-descriptor";
        write_private(&path, expected);

        assert_eq!(
            read_runtime_build_descriptor(&path)
                .unwrap_or_else(|error| panic!("descriptor read failed: {error}"))
                .as_ref(),
            expected
        );
    }

    #[test]
    fn descriptor_reader_rejects_relative_symlink_and_group_writable_paths() {
        assert_eq!(
            read_runtime_build_descriptor(Path::new("relative.pxbd")),
            Err(RuntimeInstallFileError::PathMustBeAbsolute)
        );

        let directory = TestDirectory::new();
        let target = directory.join("target.pxbd");
        let link = directory.join("link.pxbd");
        write_private(&target, b"descriptor");
        symlink(&target, &link)
            .unwrap_or_else(|error| panic!("descriptor symlink failed: {error}"));
        assert_eq!(
            read_runtime_build_descriptor(&link),
            Err(RuntimeInstallFileError::UnsafeFileType)
        );

        fs::set_permissions(&target, fs::Permissions::from_mode(0o620))
            .unwrap_or_else(|error| panic!("unsafe descriptor mode failed: {error}"));
        assert_eq!(
            read_runtime_build_descriptor(&target),
            Err(RuntimeInstallFileError::UnsafeFileMode)
        );
    }

    #[test]
    fn descriptor_reader_rejects_oversize_and_linked_identity() {
        let oversize_directory = TestDirectory::new();
        let oversize = oversize_directory.join("oversize.pxbd");
        write_private(
            &oversize,
            &vec![0x55; MAX_INSTALLED_RUNTIME_BUILD_DESCRIPTOR_BYTES + 1],
        );
        assert_eq!(
            read_runtime_build_descriptor(&oversize),
            Err(RuntimeInstallFileError::ArtifactTooLarge)
        );

        let linked_directory = TestDirectory::new();
        let original = linked_directory.join("original.pxbd");
        let alias = linked_directory.join("alias.pxbd");
        write_private(&original, b"descriptor");
        fs::hard_link(&original, &alias)
            .unwrap_or_else(|error| panic!("descriptor hard link failed: {error}"));
        assert_eq!(
            read_runtime_build_descriptor(&original),
            Err(RuntimeInstallFileError::UnsafeFileType)
        );
    }

    #[test]
    fn output_preflight_rejects_unsafe_parent_and_symlinked_parent() {
        assert_eq!(
            RuntimeInstallArtifactOutput::preflight(Path::new("relative-manifest"), 32).err(),
            Some(RuntimeInstallFileError::PathMustBeAbsolute)
        );

        let unsafe_directory = TestDirectory::new();
        fs::set_permissions(unsafe_directory.path(), fs::Permissions::from_mode(0o750))
            .unwrap_or_else(|error| panic!("unsafe directory mode failed: {error}"));
        assert_eq!(
            RuntimeInstallArtifactOutput::preflight(&unsafe_directory.join("manifest"), 32).err(),
            Some(RuntimeInstallFileError::UnsafeDirectoryMode)
        );

        let directory = TestDirectory::new();
        let actual_parent = directory.join("actual");
        let linked_parent = directory.join("linked");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&actual_parent)
            .unwrap_or_else(|error| panic!("actual parent creation failed: {error}"));
        symlink(&actual_parent, &linked_parent)
            .unwrap_or_else(|error| panic!("parent symlink failed: {error}"));
        assert_eq!(
            RuntimeInstallArtifactOutput::preflight(&linked_parent.join("manifest"), 32).err(),
            Some(RuntimeInstallFileError::UnsafeDirectoryType)
        );

        let target = directory.join("target");
        let linked_target = directory.join("linked-target");
        write_private(&target, b"digest");
        symlink(&target, &linked_target)
            .unwrap_or_else(|error| panic!("output symlink failed: {error}"));
        assert_eq!(
            RuntimeInstallArtifactOutput::preflight(&linked_target, 32).err(),
            Some(RuntimeInstallFileError::UnsafeFileType)
        );
    }

    #[test]
    fn output_publishes_new_artifact_once_with_private_mode() {
        let directory = TestDirectory::new();
        let path = directory.join("manifest");
        let expected = b"exact-manifest";
        RuntimeInstallArtifactOutput::preflight(&path, expected.len())
            .unwrap_or_else(|error| panic!("output preflight failed: {error}"))
            .publish_or_verify_exact(expected)
            .unwrap_or_else(|error| panic!("output publish failed: {error}"));

        assert_eq!(
            fs::read(&path).unwrap_or_else(|error| panic!("published read failed: {error}")),
            expected
        );
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|error| panic!("published metadata failed: {error}"))
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn output_accepts_preexisting_and_eexist_byte_identical_retries() {
        let directory = TestDirectory::new();
        let preexisting = directory.join("preexisting");
        let expected = b"exact-digest";
        write_private(&preexisting, expected);
        let before = fs::metadata(&preexisting)
            .unwrap_or_else(|error| panic!("retry metadata failed: {error}"));
        RuntimeInstallArtifactOutput::preflight(&preexisting, expected.len())
            .unwrap_or_else(|error| panic!("retry preflight failed: {error}"))
            .publish_or_verify_exact(expected)
            .unwrap_or_else(|error| panic!("preexisting retry failed: {error}"));
        let after = fs::metadata(&preexisting)
            .unwrap_or_else(|error| panic!("retry metadata reread failed: {error}"));
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));

        let raced = directory.join("raced");
        let output = RuntimeInstallArtifactOutput::preflight(&raced, expected.len())
            .unwrap_or_else(|error| panic!("raced output preflight failed: {error}"));
        write_private(&raced, expected);
        output
            .publish_or_verify_exact(expected)
            .unwrap_or_else(|error| panic!("EEXIST retry failed: {error}"));
    }

    #[test]
    fn output_rejects_changed_existing_bytes_and_identity() {
        let directory = TestDirectory::new();
        let changed = directory.join("changed");
        write_private(&changed, b"wrong-bytes");
        assert_eq!(
            RuntimeInstallArtifactOutput::preflight(&changed, b"exact-bytes".len())
                .unwrap_or_else(|error| panic!("changed output preflight failed: {error}"))
                .publish_or_verify_exact(b"exact-bytes"),
            Err(RuntimeInstallFileError::ExistingArtifactMismatch)
        );
        assert_eq!(
            fs::read(&changed).unwrap_or_else(|error| panic!("changed read failed: {error}")),
            b"wrong-bytes"
        );

        let replaced = directory.join("replaced");
        let retained = directory.join("retained-old-inode");
        write_private(&replaced, b"exact-bytes");
        let output = RuntimeInstallArtifactOutput::preflight(&replaced, b"exact-bytes".len())
            .unwrap_or_else(|error| panic!("identity preflight failed: {error}"));
        fs::hard_link(&replaced, &retained)
            .unwrap_or_else(|error| panic!("retained hard link failed: {error}"));
        fs::remove_file(&replaced)
            .unwrap_or_else(|error| panic!("old output removal failed: {error}"));
        write_private(&replaced, b"exact-bytes");
        assert_eq!(
            output.publish_or_verify_exact(b"exact-bytes"),
            Err(RuntimeInstallFileError::FileIdentityChanged)
        );
    }
}
