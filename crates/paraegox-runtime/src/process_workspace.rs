//! Per-generation ephemeral workspace ownership for ProcessDomain workers.

use core::fmt;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use paraegox_runtime_contracts::assignment::InstanceRef;

use crate::card_instance::InstanceGeneration;
use crate::runtime_ownership::ProcessGenerationIdentity;

/// Exact directory created and later removed by one process generation.
#[derive(Debug)]
pub(crate) struct ProcessWorkspace {
    root: PathBuf,
    path: PathBuf,
    root_identity: DirectoryIdentity,
    workspace_identity: DirectoryIdentity,
    cleaned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn matches(self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && self == Self::from_metadata(metadata)
    }
}

impl ProcessWorkspace {
    /// Creates a new directory without adopting or deleting a pre-existing
    /// path. A stale collision is recovery evidence, not something startup may
    /// silently erase.
    pub(crate) fn create(
        root: &Path,
        identity: ProcessGenerationIdentity,
        instance: InstanceRef,
        instance_generation: InstanceGeneration,
    ) -> Result<Self, ProcessWorkspaceError> {
        if !root.is_absolute() {
            return Err(ProcessWorkspaceError::InvalidRoot);
        }
        let root = fs::canonicalize(root).map_err(ProcessWorkspaceError::Io)?;
        let root_metadata = fs::symlink_metadata(&root).map_err(ProcessWorkspaceError::Io)?;
        if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
            return Err(ProcessWorkspaceError::InvalidRoot);
        }
        let root_identity = DirectoryIdentity::from_metadata(&root_metadata);
        let name = format!(
            "px-{}-h{}-{}-d{}-{}-i{}",
            hex(identity.runtime_host().as_bytes()),
            identity.runtime_host_epoch().value(),
            hex(identity.domain().as_bytes()),
            identity.domain_epoch().value(),
            hex(instance.as_bytes()),
            instance_generation.value(),
        );
        let path = root.join(name);
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => ProcessWorkspaceError::AlreadyExists,
            _ => ProcessWorkspaceError::Io(error),
        })?;
        let path = canonicalize_owned_workspace(&root, &path)?;
        let workspace_metadata = fs::symlink_metadata(&path).map_err(ProcessWorkspaceError::Io)?;
        let workspace_identity = DirectoryIdentity::from_metadata(&workspace_metadata);
        if !root_identity_matches(&root, root_identity)?
            || !workspace_identity.matches(&workspace_metadata)
        {
            return Err(ProcessWorkspaceError::CleanupNotProven);
        }
        Ok(Self {
            root,
            path,
            root_identity,
            workspace_identity,
            cleaned: false,
        })
    }

    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Removes the exact owned tree and verifies the namespace no longer resolves.
    ///
    /// The ProcessDomain must call this only after the complete process tree has
    /// exited, so no worker can mutate the parent namespace between validation
    /// and removal. The stored device/inode identities reject stale-path,
    /// rename, symlink, and substitution observations; they are not a claim that
    /// path-based filesystem operations are race-free against another host actor.
    /// Only explicit success can contribute workspace-zero to a cleanup proof.
    pub(crate) fn cleanup(&mut self) -> Result<(), ProcessWorkspaceError> {
        if self.cleaned {
            return Ok(());
        }
        self.verify_owned_namespace()?;
        fs::remove_dir_all(&self.path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => ProcessWorkspaceError::CleanupNotProven,
            _ => ProcessWorkspaceError::Io(error),
        })?;
        if !root_identity_matches(&self.root, self.root_identity)? {
            return Err(ProcessWorkspaceError::CleanupNotProven);
        }
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.cleaned = true;
                Ok(())
            }
            Ok(_) => Err(ProcessWorkspaceError::CleanupNotProven),
            Err(error) => Err(ProcessWorkspaceError::Io(error)),
        }
    }

    #[must_use]
    pub(crate) const fn is_cleaned(&self) -> bool {
        self.cleaned
    }

    fn verify_owned_namespace(&self) -> Result<(), ProcessWorkspaceError> {
        if self.path.parent() != Some(self.root.as_path())
            || !root_identity_matches(&self.root, self.root_identity)?
        {
            return Err(ProcessWorkspaceError::CleanupNotProven);
        }
        let workspace_metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ProcessWorkspaceError::CleanupNotProven);
            }
            Err(error) => return Err(ProcessWorkspaceError::Io(error)),
        };
        if !self.workspace_identity.matches(&workspace_metadata) {
            return Err(ProcessWorkspaceError::CleanupNotProven);
        }
        let canonical = fs::canonicalize(&self.path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => ProcessWorkspaceError::CleanupNotProven,
            _ => ProcessWorkspaceError::Io(error),
        })?;
        if canonical != self.path || canonical.parent() != Some(self.root.as_path()) {
            return Err(ProcessWorkspaceError::CleanupNotProven);
        }
        let canonical_metadata =
            fs::symlink_metadata(&canonical).map_err(ProcessWorkspaceError::Io)?;
        if !self.workspace_identity.matches(&canonical_metadata)
            || !root_identity_matches(&self.root, self.root_identity)?
        {
            return Err(ProcessWorkspaceError::CleanupNotProven);
        }
        Ok(())
    }
}

impl Drop for ProcessWorkspace {
    fn drop(&mut self) {
        if !self.cleaned {
            // The owning ProcessDomain performs and records explicit cleanup.
            // This is only a last-resort local reclamation attempt and cannot
            // manufacture a cleanup proof.
            let _ = self.cleanup();
        }
    }
}

fn canonicalize_owned_workspace(
    root: &Path,
    path: &Path,
) -> Result<PathBuf, ProcessWorkspaceError> {
    let canonical = fs::canonicalize(path).map_err(ProcessWorkspaceError::Io)?;
    if canonical.parent() != Some(root) {
        return Err(ProcessWorkspaceError::CleanupNotProven);
    }
    Ok(canonical)
}

fn root_identity_matches(
    root: &Path,
    expected: DirectoryIdentity,
) -> Result<bool, ProcessWorkspaceError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => Ok(expected.matches(&metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ProcessWorkspaceError::Io(error)),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Debug)]
pub(crate) enum ProcessWorkspaceError {
    InvalidRoot,
    AlreadyExists,
    CleanupNotProven,
    Io(io::Error),
}

impl fmt::Display for ProcessWorkspaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot => formatter.write_str("process workspace root is invalid"),
            Self::AlreadyExists => {
                formatter.write_str("process workspace generation already exists")
            }
            Self::CleanupNotProven => {
                formatter.write_str("process workspace cleanup is not proven")
            }
            Self::Io(error) => write!(formatter, "process workspace I/O failed: {error}"),
        }
    }
}

impl std::error::Error for ProcessWorkspaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_runtime_contracts::process_execution::ProcessDomainRef;
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};

    use crate::card_instance::{DomainEpoch, RuntimeHostEpoch};

    use super::*;

    static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn create() -> Self {
            let sequence = ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "paraegox-workspace-root-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test root should be unique");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("test root should be removable");
        }
    }

    fn identity() -> ProcessGenerationIdentity {
        ProcessGenerationIdentity::new(
            RuntimeHostId::from_bytes([1; 16]),
            RuntimeHostEpoch::try_new(2).expect("host epoch should be valid"),
            SourcePlanRevision::new(3),
            TargetSliceDigest::new(Digest32::from_bytes([4; 32])),
            ProcessDomainRef::from_bytes([5; 16]),
            DomainEpoch::try_new(6).expect("domain epoch should be valid"),
        )
    }

    fn generation() -> InstanceGeneration {
        InstanceGeneration::try_new(7).expect("instance generation should be valid")
    }

    #[test]
    fn workspace_is_private_unique_and_explicitly_removed() {
        let root = TestRoot::create();
        let instance = InstanceRef::from_bytes([8; 16]);
        let mut workspace = ProcessWorkspace::create(&root.0, identity(), instance, generation())
            .expect("workspace should be created");
        let path = workspace.path().to_path_buf();
        fs::create_dir(path.join("nested")).expect("worker fixture directory should be writable");
        fs::write(path.join("nested/state"), b"private")
            .expect("worker fixture state should be writable");

        assert_eq!(
            workspace.root,
            fs::canonicalize(&root.0).expect("test root should canonicalize")
        );
        assert_eq!(
            workspace.root_identity,
            DirectoryIdentity::from_metadata(
                &fs::symlink_metadata(&workspace.root)
                    .expect("canonical root metadata should remain available")
            )
        );
        assert_eq!(
            workspace.workspace_identity,
            DirectoryIdentity::from_metadata(
                &fs::symlink_metadata(&path).expect("workspace metadata should remain available")
            )
        );

        assert_eq!(
            fs::metadata(&path)
                .expect("workspace should exist")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(matches!(
            ProcessWorkspace::create(&root.0, identity(), instance, generation()),
            Err(ProcessWorkspaceError::AlreadyExists)
        ));

        workspace.cleanup().expect("cleanup should be exact");

        assert!(workspace.is_cleaned());
        assert!(!path.exists());
    }

    #[test]
    fn new_instance_generation_cannot_observe_old_workspace_path() {
        let root = TestRoot::create();
        let instance = InstanceRef::from_bytes([9; 16]);
        let mut first = ProcessWorkspace::create(&root.0, identity(), instance, generation())
            .expect("first workspace should be created");
        let first_path = first.path().to_path_buf();
        fs::write(first_path.join("state"), b"old").expect("old state should be writable");
        first.cleanup().expect("first cleanup should succeed");

        let next_generation = InstanceGeneration::try_new(8).expect("generation should be valid");
        let second = ProcessWorkspace::create(&root.0, identity(), instance, next_generation)
            .expect("replacement workspace should be created");

        assert_ne!(second.path(), first_path);
        assert!(!second.path().join("state").exists());
    }

    #[test]
    fn renamed_workspace_and_directory_substitute_fail_without_deleting_either_tree() {
        let root = TestRoot::create();
        let instance = InstanceRef::from_bytes([10; 16]);
        let mut workspace = ProcessWorkspace::create(&root.0, identity(), instance, generation())
            .expect("workspace should be created");
        let path = workspace.path().to_path_buf();
        let moved = path.with_extension("moved");
        fs::write(path.join("owned"), b"original").expect("owned marker should be writable");
        fs::rename(&path, &moved).expect("owned workspace should be movable for the attack");
        fs::create_dir(&path).expect("substitute directory should be creatable");
        let substitute = path.join("do-not-delete");
        fs::write(&substitute, b"substitute").expect("substitute marker should be writable");

        assert!(matches!(
            workspace.cleanup(),
            Err(ProcessWorkspaceError::CleanupNotProven)
        ));
        assert_eq!(
            fs::read(&substitute).expect("cleanup must preserve the substitute"),
            b"substitute"
        );
        assert_eq!(
            fs::read(moved.join("owned")).expect("cleanup must preserve the renamed owned tree"),
            b"original"
        );

        drop(workspace);
        assert_eq!(
            fs::read(&substitute).expect("fallback Drop must preserve the substitute"),
            b"substitute"
        );
    }

    #[test]
    fn symlink_substitute_fails_without_following_or_removing_the_target() {
        let root = TestRoot::create();
        let instance = InstanceRef::from_bytes([11; 16]);
        let mut workspace = ProcessWorkspace::create(&root.0, identity(), instance, generation())
            .expect("workspace should be created");
        let path = workspace.path().to_path_buf();
        let moved = path.with_extension("moved");
        let target = root.0.join("substitute-target");
        fs::create_dir(&target).expect("substitute target should be creatable");
        let marker = target.join("do-not-delete");
        fs::write(&marker, b"target").expect("target marker should be writable");
        fs::rename(&path, &moved).expect("owned workspace should be movable for the attack");
        symlink(&target, &path).expect("workspace pathname should accept a symlink substitute");

        assert!(matches!(
            workspace.cleanup(),
            Err(ProcessWorkspaceError::CleanupNotProven)
        ));
        assert!(
            fs::symlink_metadata(&path)
                .expect("substitute symlink must remain")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(&marker).expect("cleanup must not follow the substitute symlink"),
            b"target"
        );

        drop(workspace);
        assert!(
            fs::symlink_metadata(&path)
                .expect("fallback Drop must preserve the symlink substitute")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(&marker).expect("fallback Drop must preserve the symlink target"),
            b"target"
        );
    }

    #[test]
    fn replaced_root_fails_without_deleting_the_replacement_workspace() {
        let area = TestRoot::create();
        let root = area.0.join("active-root");
        let moved_root = area.0.join("moved-owned-root");
        fs::create_dir(&root).expect("workspace root should be creatable");
        let instance = InstanceRef::from_bytes([12; 16]);
        let mut workspace = ProcessWorkspace::create(&root, identity(), instance, generation())
            .expect("workspace should be created");
        let workspace_name = workspace
            .path()
            .file_name()
            .expect("workspace should have a generated name")
            .to_owned();
        fs::rename(&root, &moved_root).expect("owned root should be movable for the attack");
        fs::create_dir(&root).expect("replacement root should be creatable");
        let replacement_workspace = root.join(workspace_name);
        fs::create_dir(&replacement_workspace).expect("replacement workspace should be creatable");
        let marker = replacement_workspace.join("do-not-delete");
        fs::write(&marker, b"replacement").expect("replacement marker should be writable");

        assert!(matches!(
            workspace.cleanup(),
            Err(ProcessWorkspaceError::CleanupNotProven)
        ));
        assert_eq!(
            fs::read(&marker).expect("cleanup must preserve the replacement root tree"),
            b"replacement"
        );

        drop(workspace);
        assert_eq!(
            fs::read(&marker).expect("fallback Drop must preserve the replacement root tree"),
            b"replacement"
        );
        let moved_workspace = moved_root.join(
            replacement_workspace
                .file_name()
                .expect("replacement workspace should retain its generated name"),
        );
        let metadata = fs::symlink_metadata(&moved_workspace)
            .expect("the original workspace must remain under the moved root");
        assert!(metadata.file_type().is_dir());
        assert_eq!(
            metadata.dev(),
            fs::symlink_metadata(&moved_root)
                .expect("moved root metadata should remain available")
                .dev()
        );
    }
}
