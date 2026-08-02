#![cfg(unix)]

//! Pinned observation of the currently executing RuntimeHost artifact.
//!
//! The S7 Linux reference opens `/proc/self/exe`, hashes that descriptor as raw
//! SHA-256, and retains the file until the release/install operation finishes.
//! Target and fixture facts come only from constants compiled into this same
//! process image. Other operating systems remain unsupported until their
//! executable-identity backend is admitted.

use core::fmt;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::Metadata;
#[cfg(target_os = "linux")]
use std::io::{self, Read};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use nix::fcntl::{OFlag, open, openat};
#[cfg(target_os = "linux")]
use nix::sys::stat::Mode;
#[cfg(target_os = "linux")]
use nix::sys::statfs::{PROC_SUPER_MAGIC, fstatfs};
#[cfg(target_os = "linux")]
use paraegox_kernel::digest::Digest32;
#[cfg(target_os = "linux")]
use paraegox_runtime_contracts::installation::MAX_INSTALLED_RUNTIME_ARTIFACT_BYTES;
use paraegox_runtime_contracts::installation::{
    InstalledRuntimeArtifactObservationV1, RuntimeCompiledInstallationFactsV1,
    RuntimeInstallationError,
};
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};

#[cfg(not(target_os = "linux"))]
use crate::runtime_build_metadata::RuntimeHostEmbeddedBuildMetadataV1;
#[cfg(target_os = "linux")]
use crate::runtime_build_metadata::{
    RuntimeHostEmbeddedBuildMetadataV1, runtime_compiled_installation_facts,
};

#[cfg(target_os = "linux")]
const HASH_BUFFER_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const INSTALLED_EXECUTABLE_MODE: u32 = 0o555;
#[cfg(target_os = "linux")]
const PERMISSION_MODE_MASK: u32 = 0o7777;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeArtifactObservationPolicy {
    ReleaseBuild,
    InstalledProduction,
}

/// Descriptor-pinned executable observation retained across one operation.
pub(crate) struct PinnedRuntimeArtifactV1 {
    #[cfg(target_os = "linux")]
    _proc_directory: File,
    _file: File,
    observation: InstalledRuntimeArtifactObservationV1,
    compiled: RuntimeCompiledInstallationFactsV1,
}

impl fmt::Debug for PinnedRuntimeArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedRuntimeArtifactV1")
            .field("observation", &self.observation)
            .field("compiled", &self.compiled)
            .finish_non_exhaustive()
    }
}

impl PinnedRuntimeArtifactV1 {
    /// Observes the final executable currently running in the release pipeline.
    pub(crate) fn observe_current_release_build(
        metadata: RuntimeHostEmbeddedBuildMetadataV1,
    ) -> Result<Self, RuntimeArtifactObservationError> {
        Self::observe_current_with_policy(RuntimeArtifactObservationPolicy::ReleaseBuild, metadata)
    }

    /// Observes the installed executable under the fixed production ownership
    /// and mode policy. Runtime installation must use this entrypoint.
    pub(crate) fn observe_current_installed_production(
        metadata: RuntimeHostEmbeddedBuildMetadataV1,
    ) -> Result<Self, RuntimeArtifactObservationError> {
        Self::observe_current_with_policy(
            RuntimeArtifactObservationPolicy::InstalledProduction,
            metadata,
        )
    }

    fn observe_current_with_policy(
        policy: RuntimeArtifactObservationPolicy,
        metadata: RuntimeHostEmbeddedBuildMetadataV1,
    ) -> Result<Self, RuntimeArtifactObservationError> {
        #[cfg(target_os = "linux")]
        {
            let proc_owned = open(
                Path::new("/proc"),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
                Mode::empty(),
            )
            .map_err(nix_io_failure)?;
            let proc_directory = File::from(proc_owned);
            let proc_filesystem = fstatfs(&proc_directory).map_err(nix_io_failure)?;
            if proc_filesystem.filesystem_type() != PROC_SUPER_MAGIC {
                return Err(RuntimeArtifactObservationError::UnsupportedProcFilesystem);
            }

            // `exe` is a procfs magic link and therefore must be followed. The
            // containing proc mount remains descriptor-pinned and verified.
            let owned = openat(
                &proc_directory,
                "self/exe",
                OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(nix_io_failure)?;
            let file = File::from(owned);
            return Self::observe_open_file(proc_directory, file, policy, metadata);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (policy, metadata);
            Err(RuntimeArtifactObservationError::UnsupportedPlatform)
        }
    }

    #[cfg(target_os = "linux")]
    fn observe_open_file(
        proc_directory: File,
        mut file: File,
        policy: RuntimeArtifactObservationPolicy,
        embedded_metadata: RuntimeHostEmbeddedBuildMetadataV1,
    ) -> Result<Self, RuntimeArtifactObservationError> {
        let before = file.metadata().map_err(io_failure)?;
        validate_executable_metadata(&before, policy)?;
        let length = before.len();
        if length == 0 || length > MAX_INSTALLED_RUNTIME_ARTIFACT_BYTES {
            return Err(RuntimeArtifactObservationError::InvalidArtifactLength);
        }

        let mut hasher = Sha256::new();
        let mut observed_length = 0_u64;
        let mut buffer = [0_u8; HASH_BUFFER_BYTES];
        loop {
            let read = file.read(&mut buffer).map_err(io_failure)?;
            if read == 0 {
                break;
            }
            observed_length = observed_length
                .checked_add(
                    u64::try_from(read)
                        .map_err(|_| RuntimeArtifactObservationError::InvalidArtifactLength)?,
                )
                .ok_or(RuntimeArtifactObservationError::InvalidArtifactLength)?;
            if observed_length > length || observed_length > MAX_INSTALLED_RUNTIME_ARTIFACT_BYTES {
                return Err(RuntimeArtifactObservationError::ArtifactChangedDuringRead);
            }
            hasher.update(&buffer[..read]);
        }
        if observed_length != length {
            return Err(RuntimeArtifactObservationError::ArtifactChangedDuringRead);
        }

        let after = file.metadata().map_err(io_failure)?;
        validate_executable_metadata(&after, policy)?;
        if executable_identity(&before) != executable_identity(&after) || after.len() != length {
            return Err(RuntimeArtifactObservationError::ArtifactChangedDuringRead);
        }

        let sha256 = Digest32::from_bytes(hasher.finalize().into());
        let compiled = runtime_compiled_installation_facts(embedded_metadata)?;
        let observation = InstalledRuntimeArtifactObservationV1::try_new(
            length,
            sha256,
            embedded_metadata.target_triple(),
        )?;
        Ok(Self {
            _proc_directory: proc_directory,
            _file: file,
            observation,
            compiled,
        })
    }

    pub(crate) const fn observation(&self) -> &InstalledRuntimeArtifactObservationV1 {
        &self.observation
    }

    pub(crate) const fn compiled_facts(&self) -> RuntimeCompiledInstallationFactsV1 {
        self.compiled
    }
}

#[cfg(target_os = "linux")]
fn validate_executable_metadata(
    metadata: &Metadata,
    policy: RuntimeArtifactObservationPolicy,
) -> Result<(), RuntimeArtifactObservationError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(RuntimeArtifactObservationError::UnsafeExecutableType);
    }
    if policy == RuntimeArtifactObservationPolicy::InstalledProduction {
        if metadata.uid() != 0 || metadata.gid() != 0 {
            return Err(RuntimeArtifactObservationError::UnsafeInstalledOwner);
        }
        if metadata.mode() & PERMISSION_MODE_MASK != INSTALLED_EXECUTABLE_MODE {
            return Err(RuntimeArtifactObservationError::UnsafeInstalledMode);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn executable_identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

#[cfg(target_os = "linux")]
fn io_failure(error: io::Error) -> RuntimeArtifactObservationError {
    RuntimeArtifactObservationError::Io(error.kind())
}

#[cfg(target_os = "linux")]
fn nix_io_failure(error: nix::errno::Errno) -> RuntimeArtifactObservationError {
    RuntimeArtifactObservationError::Io(io::Error::from_raw_os_error(error as i32).kind())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeArtifactObservationError {
    UnsupportedPlatform,
    #[cfg(target_os = "linux")]
    UnsupportedProcFilesystem,
    #[cfg(target_os = "linux")]
    InvalidArtifactLength,
    #[cfg(target_os = "linux")]
    UnsafeExecutableType,
    #[cfg(target_os = "linux")]
    UnsafeInstalledOwner,
    #[cfg(target_os = "linux")]
    UnsafeInstalledMode,
    #[cfg(target_os = "linux")]
    ArtifactChangedDuringRead,
    #[cfg(target_os = "linux")]
    Io(io::ErrorKind),
    Installation(RuntimeInstallationError),
}

impl From<RuntimeInstallationError> for RuntimeArtifactObservationError {
    fn from(error: RuntimeInstallationError) -> Self {
        Self::Installation(error)
    }
}

impl fmt::Display for RuntimeArtifactObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Runtime executable observation failed: {self:?}")
    }
}

impl std::error::Error for RuntimeArtifactObservationError {}

#[cfg(test)]
mod tests {
    use super::{PinnedRuntimeArtifactV1, RuntimeArtifactObservationError};

    #[cfg(target_os = "linux")]
    use std::fs::File;
    #[cfg(target_os = "linux")]
    use std::io::Read;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;

    #[cfg(target_os = "linux")]
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    #[cfg(target_os = "linux")]
    use nix::sys::statfs::{PROC_SUPER_MAGIC, fstatfs};
    #[cfg(target_os = "linux")]
    use paraegox_kernel::digest::Digest32;
    #[cfg(target_os = "linux")]
    use paraegox_runtime_contracts::installation::InstalledRuntimeArtifactObservationV1;
    #[cfg(target_os = "linux")]
    use sha2::{Digest as _, Sha256};

    use crate::runtime_build_metadata::RuntimeHostEmbeddedBuildMetadataV1;

    fn embedded_metadata() -> RuntimeHostEmbeddedBuildMetadataV1 {
        RuntimeHostEmbeddedBuildMetadataV1::from_final_executable(
            [0x31; 32],
            "x86_64-unknown-linux-gnu",
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn release_observation_is_proc_anchored_and_hashes_the_current_image() {
        let pinned = PinnedRuntimeArtifactV1::observe_current_release_build(embedded_metadata())
            .unwrap_or_else(|error| panic!("release artifact observation failed: {error}"));

        assert_eq!(
            fstatfs(&pinned._proc_directory)
                .unwrap_or_else(|error| panic!("pinned proc fstatfs failed: {error}"))
                .filesystem_type(),
            PROC_SUPER_MAGIC
        );
        assert_cloexec(&pinned._proc_directory);
        assert_cloexec(&pinned._file);

        let mut current = File::open("/proc/self/exe")
            .unwrap_or_else(|error| panic!("current executable open failed: {error}"));
        let metadata = current
            .metadata()
            .unwrap_or_else(|error| panic!("current executable metadata failed: {error}"));
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; super::HASH_BUFFER_BYTES];
        loop {
            let read = current
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("current executable read failed: {error}"));
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let expected = InstalledRuntimeArtifactObservationV1::try_new(
            metadata.len(),
            Digest32::from_bytes(hasher.finalize().into()),
            embedded_metadata().target_triple(),
        )
        .unwrap_or_else(|error| panic!("expected artifact observation failed: {error}"));
        assert_eq!(pinned.observation(), &expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_entrypoint_always_applies_root_and_mode_policy() {
        let metadata = File::open("/proc/self/exe")
            .and_then(|file| file.metadata())
            .unwrap_or_else(|error| panic!("current executable metadata failed: {error}"));
        let observed =
            PinnedRuntimeArtifactV1::observe_current_installed_production(embedded_metadata());

        if metadata.uid() != 0 || metadata.gid() != 0 {
            assert!(matches!(
                observed,
                Err(RuntimeArtifactObservationError::UnsafeInstalledOwner)
            ));
        } else if metadata.mode() & super::PERMISSION_MODE_MASK != super::INSTALLED_EXECUTABLE_MODE
        {
            assert!(matches!(
                observed,
                Err(RuntimeArtifactObservationError::UnsafeInstalledMode)
            ));
        } else {
            observed.unwrap_or_else(|error| {
                panic!("valid installed executable observation failed: {error}")
            });
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_cloexec(file: &File) {
        let flags = fcntl(file, FcntlArg::F_GETFD)
            .unwrap_or_else(|error| panic!("F_GETFD failed: {error}"));
        assert!(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_release_and_installed_observation_fail_closed() {
        assert!(matches!(
            PinnedRuntimeArtifactV1::observe_current_release_build(embedded_metadata()),
            Err(RuntimeArtifactObservationError::UnsupportedPlatform)
        ));
        assert!(matches!(
            PinnedRuntimeArtifactV1::observe_current_installed_production(embedded_metadata()),
            Err(RuntimeArtifactObservationError::UnsupportedPlatform)
        ));
    }
}
