//! One-way legacy cutover and owner-local successor snapshot store.
//!
//! The legacy `ControllerStore` is consumed while its writer lock is held. Its
//! v8 active snapshot is atomically replaced by a durable marker whose magic is
//! intentionally not accepted by the v8 opener. The marker carries the exact
//! canonical legacy snapshot, so a crash after marker publication but before
//! successor initialization has one deterministic recovery path.

use core::fmt;
use std::fs::{self, File, Metadata, TryLockError};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::dir::Dir;
use nix::fcntl::{OFlag, open, openat, renameat};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};

use crate::controller_journal::{
    ControllerJournalError, ControllerJournalSnapshot, ControllerOwnerIdentityFingerprint,
    MAX_CONTROLLER_SNAPSHOT_BYTES,
};
use crate::controller_store::{
    CONTROLLER_ACTIVE_FILE_NAME, CONTROLLER_LOCK_FILE_NAME, ControllerFilesystemPolicy,
    ControllerStore, ControllerStoreCutoverIdentity, ControllerStoreError,
    ControllerStoreOpenError, open_controller_directory,
};
use crate::managed_agent_stack_apply::ManagedAgentStackApplyControllerError;
use crate::managed_fabric_apply::{
    ManagedFabricApplyControllerError, ManagedFabricApplyPhaseV1, ManagedFabricControllerStateV1,
};
use crate::managed_fabric_producer::{
    ManagedFabricControllerProvisioningV1, ManagedFabricProducerError,
    VerifiedManagedFabricProducerContextV1,
};

const CUTOVER_MAGIC: &[u8; 4] = b"PXFC";
const CUTOVER_VERSION: u16 = 1;
const CUTOVER_HEADER_BYTES: usize = 146;
const CUTOVER_CHECKSUM_BYTES: usize = 32;
const CUTOVER_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.deployment.managed-fabric-cutover.checksum.sha256.v1";
const CUTOVER_MARKER_DIGEST_DOMAIN: &[u8] =
    b"paraegox.deployment.managed-fabric-cutover.marker.sha256.v1";
const LEGACY_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"paraegox.deployment.managed-fabric-cutover.legacy-snapshot.sha256.v1";
const MAX_CUTOVER_BYTES: usize = MAX_CONTROLLER_SNAPSHOT_BYTES + 256;

const SUCCESSOR_MAGIC: &[u8; 4] = b"PXFS";
const SUCCESSOR_VERSION: u16 = 1;
const SUCCESSOR_HEADER_BYTES: usize = 114;
const SUCCESSOR_CHECKSUM_BYTES: usize = 32;
const SUCCESSOR_CHECKSUM_DOMAIN: &[u8] =
    b"paraegox.deployment.managed-fabric-store.checksum.sha256.v1";
const MAX_SUCCESSOR_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const SUCCESSOR_LOCK_FILE_NAME: &str = "managed-fabric.lock";
const SUCCESSOR_ACTIVE_FILE_NAME: &str = "managed-fabric.snapshot";
const SUCCESSOR_TEMP_PREFIX: &str = ".managed-fabric.snapshot.tmp-";
const LEGACY_TEMP_PREFIX: &str = ".controller.snapshot.tmp-";
const TEMP_TOKEN_BYTES: usize = 16;
const TEMP_HEX_BYTES: usize = TEMP_TOKEN_BYTES * 2;
const PRIVATE_FILE_MODE_BITS: u32 = 0o600;
const PRIVATE_FILE_MODE_MASK: u32 = 0o7777;
const PRIVATE_FILE_MODE: Mode = Mode::S_IRUSR.union(Mode::S_IWUSR);

/// Canonical, self-contained proof that the v8 writer was cut over once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricCutoverMarkerV1 {
    successor_store_instance_id: [u8; 32],
    owner_identity: ControllerOwnerIdentityFingerprint,
    legacy_snapshot: ControllerJournalSnapshot,
    marker_digest: Digest32,
    canonical_wire: Box<[u8]>,
}

impl ManagedFabricCutoverMarkerV1 {
    fn try_new(
        successor_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        legacy_snapshot: ControllerJournalSnapshot,
    ) -> Result<Self, ManagedFabricStoreError> {
        if bytes_are_zero(&successor_store_instance_id)
            || successor_store_instance_id == *legacy_snapshot.store_instance_id()
            || legacy_snapshot.owner_identity_fingerprint() != expected_owner_identity
            || legacy_snapshot.snapshot_sequence() == 0
        {
            return Err(ManagedFabricStoreError::InvalidCutoverIdentity);
        }
        let legacy_wire = legacy_snapshot.encode()?;
        let legacy_length = u32::try_from(legacy_wire.len())
            .map_err(|_| ManagedFabricStoreError::SnapshotTooLarge)?;
        let legacy_digest = digest(LEGACY_SNAPSHOT_DIGEST_DOMAIN, &legacy_wire)?;
        let total = CUTOVER_HEADER_BYTES
            .checked_add(legacy_wire.len())
            .and_then(|value| value.checked_add(CUTOVER_CHECKSUM_BYTES))
            .ok_or(ManagedFabricStoreError::SnapshotTooLarge)?;
        if total > MAX_CUTOVER_BYTES {
            return Err(ManagedFabricStoreError::SnapshotTooLarge);
        }
        let mut wire = Vec::with_capacity(total);
        wire.extend_from_slice(CUTOVER_MAGIC);
        wire.extend_from_slice(&CUTOVER_VERSION.to_be_bytes());
        wire.extend_from_slice(&successor_store_instance_id);
        wire.extend_from_slice(expected_owner_identity.value().as_bytes());
        wire.extend_from_slice(legacy_snapshot.store_instance_id());
        wire.extend_from_slice(&legacy_snapshot.snapshot_sequence().to_be_bytes());
        wire.extend_from_slice(&legacy_length.to_be_bytes());
        wire.extend_from_slice(legacy_digest.as_bytes());
        if wire.len() != CUTOVER_HEADER_BYTES {
            return Err(ManagedFabricStoreError::InvalidCutoverMarker);
        }
        wire.extend_from_slice(&legacy_wire);
        let checksum = digest(CUTOVER_CHECKSUM_DOMAIN, &wire)?;
        wire.extend_from_slice(checksum.as_bytes());
        let marker_digest = digest(CUTOVER_MARKER_DIGEST_DOMAIN, &wire)?;
        Ok(Self {
            successor_store_instance_id,
            owner_identity: expected_owner_identity,
            legacy_snapshot,
            marker_digest,
            canonical_wire: wire.into_boxed_slice(),
        })
    }

    fn decode(frame: &[u8]) -> Result<Self, ManagedFabricStoreError> {
        if frame.len() < CUTOVER_HEADER_BYTES + CUTOVER_CHECKSUM_BYTES {
            return Err(ManagedFabricStoreError::SnapshotTruncated);
        }
        if frame.len() > MAX_CUTOVER_BYTES {
            return Err(ManagedFabricStoreError::SnapshotTooLarge);
        }
        let mut cursor = StoreCursor::new(frame);
        if cursor.array::<4>()? != *CUTOVER_MAGIC || cursor.u16()? != CUTOVER_VERSION {
            return Err(ManagedFabricStoreError::InvalidCutoverMarker);
        }
        let successor_store_instance_id = cursor.array::<32>()?;
        let owner_identity = ControllerOwnerIdentityFingerprint::from_stored(Digest32::from_bytes(
            cursor.array::<32>()?,
        ));
        let legacy_store_instance_id = cursor.array::<32>()?;
        let legacy_sequence = cursor.u64()?;
        let legacy_length = cursor.usize_u32()?;
        let legacy_digest = Digest32::from_bytes(cursor.array::<32>()?);
        let expected_length = CUTOVER_HEADER_BYTES
            .checked_add(legacy_length)
            .and_then(|value| value.checked_add(CUTOVER_CHECKSUM_BYTES))
            .ok_or(ManagedFabricStoreError::SnapshotTooLarge)?;
        if expected_length != frame.len() {
            return Err(ManagedFabricStoreError::InvalidCutoverMarker);
        }
        let legacy_wire = cursor.take(legacy_length)?;
        let checksum = Digest32::from_bytes(cursor.array::<32>()?);
        cursor.finish()?;
        if bytes_are_zero(&successor_store_instance_id)
            || successor_store_instance_id == legacy_store_instance_id
            || legacy_sequence == 0
            || digest(
                CUTOVER_CHECKSUM_DOMAIN,
                &frame[..frame.len() - CUTOVER_CHECKSUM_BYTES],
            )? != checksum
            || digest(LEGACY_SNAPSHOT_DIGEST_DOMAIN, legacy_wire)? != legacy_digest
        {
            return Err(ManagedFabricStoreError::InvalidCutoverMarker);
        }
        let legacy_snapshot = ControllerJournalSnapshot::decode(legacy_wire)?;
        if legacy_snapshot.encode()?.as_ref() != legacy_wire
            || legacy_snapshot.store_instance_id() != &legacy_store_instance_id
            || legacy_snapshot.owner_identity_fingerprint() != owner_identity
            || legacy_snapshot.snapshot_sequence() != legacy_sequence
        {
            return Err(ManagedFabricStoreError::InvalidCutoverMarker);
        }
        let marker = Self::try_new(successor_store_instance_id, owner_identity, legacy_snapshot)?;
        if marker.canonical_wire.as_ref() != frame {
            return Err(ManagedFabricStoreError::InvalidCutoverMarker);
        }
        Ok(marker)
    }

    #[must_use]
    pub(crate) const fn marker_digest(&self) -> Digest32 {
        self.marker_digest
    }

    #[must_use]
    pub(crate) const fn legacy_snapshot(&self) -> &ControllerJournalSnapshot {
        &self.legacy_snapshot
    }

    #[must_use]
    pub(crate) const fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

/// Exclusive successor writer. A stopped store must be reopened from marker.
pub(crate) struct ManagedFabricSuccessorStoreV1 {
    directory_path: PathBuf,
    directory: File,
    lock_file: File,
    store_instance_id: [u8; 32],
    owner_identity: ControllerOwnerIdentityFingerprint,
    marker_digest: Digest32,
    state: ManagedFabricControllerStateV1,
    state_wire: Box<[u8]>,
    lock_identity: FileIdentity,
    operational: bool,
}

/// Borrowed Agent-stack view over the existing managed Fabric successor store.
///
/// PXTE v6/PXAR v7/PXST never own a second lock, snapshot, or store identity.
/// Every transition is committed through the exact same PXFJ state nested in
/// the existing PXFS owner, preserving the predecessor PXAR v6 bytes.
pub(crate) struct ManagedAgentStackDurableStoreV1<'a> {
    successor: &'a mut ManagedFabricSuccessorStoreV1,
}

impl<'a> ManagedAgentStackDurableStoreV1<'a> {
    pub(crate) fn try_new(
        successor: &'a mut ManagedFabricSuccessorStoreV1,
    ) -> Result<Self, ManagedAgentStackApplyControllerError> {
        let state = successor.state();
        if state.phase() != ManagedFabricApplyPhaseV1::ReceiptDurable
            || state.archived_active().is_some()
            || state.receipt().is_none()
        {
            return Err(ManagedAgentStackApplyControllerError::FabricNotActive);
        }
        Ok(Self { successor })
    }

    #[must_use]
    pub(crate) const fn state(&self) -> &ManagedFabricControllerStateV1 {
        self.successor.state()
    }

    pub(crate) fn commit(
        &mut self,
        next: &ManagedFabricControllerStateV1,
    ) -> Result<(), ManagedAgentStackApplyControllerError> {
        if next.agent_stack_state().is_none() {
            return Err(ManagedAgentStackApplyControllerError::InvalidState);
        }
        self.successor
            .commit_state(next)
            .map_err(|_| ManagedAgentStackApplyControllerError::DurabilityRejected)
    }
}

impl fmt::Debug for ManagedFabricSuccessorStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedFabricSuccessorStoreV1")
            .field("directory_path", &self.directory_path)
            .field("store_instance_id", &self.store_instance_id)
            .field("owner_identity", &self.owner_identity)
            .field("marker_digest", &self.marker_digest)
            .field("state", &self.state)
            .field("operational", &self.operational)
            .finish_non_exhaustive()
    }
}

impl Drop for ManagedFabricSuccessorStoreV1 {
    fn drop(&mut self) {
        let _ = self.lock_file.unlock();
    }
}

#[derive(Clone, Copy)]
struct ManagedFabricCutoverRequest<'a> {
    legacy_directory: &'a Path,
    successor_directory: &'a Path,
    successor_store_instance_id: [u8; 32],
    expected_owner_identity: ControllerOwnerIdentityFingerprint,
    controller_signer: &'a ed25519_dalek::SigningKey,
    provisioning: &'a ManagedFabricControllerProvisioningV1,
    filesystem_policy: ControllerFilesystemPolicy,
}

impl ManagedFabricSuccessorStoreV1 {
    /// Replaces the legacy active snapshot while consuming its locked writer.
    pub(crate) fn cutover_from_legacy(
        legacy_store: ControllerStore,
        legacy_directory: &Path,
        successor_directory: &Path,
        successor_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<Self, ManagedFabricStoreError> {
        Self::cutover_from_legacy_with_policy_and_failpoint(
            legacy_store,
            ManagedFabricCutoverRequest {
                legacy_directory,
                successor_directory,
                successor_store_instance_id,
                expected_owner_identity,
                controller_signer,
                provisioning,
                filesystem_policy: ControllerFilesystemPolicy::ProductionReference,
            },
            ManagedFabricCutoverFailpoint::None,
        )
    }

    pub(crate) fn cutover_from_legacy_developer_local(
        legacy_store: ControllerStore,
        legacy_directory: &Path,
        successor_directory: &Path,
        successor_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<Self, ManagedFabricStoreError> {
        Self::cutover_from_legacy_with_policy_and_failpoint(
            legacy_store,
            ManagedFabricCutoverRequest {
                legacy_directory,
                successor_directory,
                successor_store_instance_id,
                expected_owner_identity,
                controller_signer,
                provisioning,
                filesystem_policy: ControllerFilesystemPolicy::DeveloperLocal,
            },
            ManagedFabricCutoverFailpoint::None,
        )
    }

    fn cutover_from_legacy_with_policy_and_failpoint(
        mut legacy_store: ControllerStore,
        request: ManagedFabricCutoverRequest<'_>,
        failpoint: ManagedFabricCutoverFailpoint,
    ) -> Result<Self, ManagedFabricStoreError> {
        let legacy_snapshot = legacy_store.revalidate_current()?.clone();
        let cutover_identity = legacy_store.managed_fabric_cutover_identity()?;
        let _ = VerifiedManagedFabricProducerContextV1::try_from_provisioning(
            legacy_snapshot.state(),
            request.controller_signer,
            request.provisioning,
        )?;
        let marker = ManagedFabricCutoverMarkerV1::try_new(
            request.successor_store_instance_id,
            request.expected_owner_identity,
            legacy_snapshot,
        )?;
        let legacy_directory_handle =
            open_store_directory(request.legacy_directory, request.filesystem_policy)?;
        let legacy_lock = open_named_regular(
            &legacy_directory_handle,
            CONTROLLER_LOCK_FILE_NAME,
            OFlag::O_RDWR,
        )?;
        let legacy_lock_identity = file_identity(&legacy_lock)?;
        validate_cutover_capability(
            &legacy_directory_handle,
            legacy_lock_identity,
            cutover_identity,
        )?;
        let successor_directory_handle =
            open_store_directory(request.successor_directory, request.filesystem_policy)?;
        if file_identity(&successor_directory_handle)? == file_identity(&legacy_directory_handle)? {
            return Err(ManagedFabricStoreError::SuccessorMatchesLegacyDirectory);
        }
        let expected_legacy = marker.legacy_snapshot.encode()?;
        let installed = read_named_snapshot(
            &legacy_directory_handle,
            CONTROLLER_ACTIVE_FILE_NAME,
            MAX_CONTROLLER_SNAPSHOT_BYTES,
        )?;
        if installed.bytes.as_slice() != expected_legacy.as_ref() {
            return Err(ManagedFabricStoreError::LegacySnapshotChanged);
        }
        publish_snapshot(
            &legacy_directory_handle,
            CONTROLLER_ACTIVE_FILE_NAME,
            LEGACY_TEMP_PREFIX,
            marker.canonical_wire(),
            PublishMode::Replace(installed.identity),
            MAX_CUTOVER_BYTES,
            NamedIdentity {
                name: CONTROLLER_LOCK_FILE_NAME,
                identity: legacy_lock_identity,
            },
        )?;
        if failpoint == ManagedFabricCutoverFailpoint::AfterMarkerDurableBeforeSuccessorSnapshot {
            return Err(ManagedFabricStoreError::InterruptedAfterDurableMarker);
        }
        Self::open_or_initialize_successor_in_directory(
            request.successor_directory,
            successor_directory_handle,
            marker,
            request.controller_signer,
            request.provisioning,
        )
    }

    /// Deterministically resumes the only valid path after the v8 marker won.
    pub(crate) fn resume_from_cutover_marker(
        legacy_directory: &Path,
        successor_directory: &Path,
        expected_successor_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<Self, ManagedFabricStoreError> {
        Self::resume_from_cutover_marker_with_policy(
            legacy_directory,
            successor_directory,
            expected_successor_store_instance_id,
            expected_owner_identity,
            controller_signer,
            provisioning,
            ControllerFilesystemPolicy::ProductionReference,
        )
    }

    pub(crate) fn resume_from_cutover_marker_developer_local(
        legacy_directory: &Path,
        successor_directory: &Path,
        expected_successor_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<Self, ManagedFabricStoreError> {
        Self::resume_from_cutover_marker_with_policy(
            legacy_directory,
            successor_directory,
            expected_successor_store_instance_id,
            expected_owner_identity,
            controller_signer,
            provisioning,
            ControllerFilesystemPolicy::DeveloperLocal,
        )
    }

    fn resume_from_cutover_marker_with_policy(
        legacy_directory: &Path,
        successor_directory: &Path,
        expected_successor_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
        filesystem_policy: ControllerFilesystemPolicy,
    ) -> Result<Self, ManagedFabricStoreError> {
        if bytes_are_zero(&expected_successor_store_instance_id) {
            return Err(ManagedFabricStoreError::InvalidCutoverIdentity);
        }
        let legacy_directory_handle = open_store_directory(legacy_directory, filesystem_policy)?;
        let legacy_lock = open_named_regular(
            &legacy_directory_handle,
            CONTROLLER_LOCK_FILE_NAME,
            OFlag::O_RDWR,
        )?;
        try_lock(&legacy_lock)?;
        let marker_wire = read_named_snapshot(
            &legacy_directory_handle,
            CONTROLLER_ACTIVE_FILE_NAME,
            MAX_CUTOVER_BYTES,
        )?;
        let marker = ManagedFabricCutoverMarkerV1::decode(&marker_wire.bytes)?;
        if marker.successor_store_instance_id != expected_successor_store_instance_id
            || marker.owner_identity != expected_owner_identity
        {
            return Err(ManagedFabricStoreError::InvalidCutoverIdentity);
        }
        let _ = VerifiedManagedFabricProducerContextV1::try_from_provisioning(
            marker.legacy_snapshot.state(),
            controller_signer,
            provisioning,
        )?;
        let successor_directory_handle =
            open_store_directory(successor_directory, filesystem_policy)?;
        if file_identity(&successor_directory_handle)? == file_identity(&legacy_directory_handle)? {
            return Err(ManagedFabricStoreError::SuccessorMatchesLegacyDirectory);
        }
        let successor = Self::open_or_initialize_successor_in_directory(
            successor_directory,
            successor_directory_handle,
            marker,
            controller_signer,
            provisioning,
        )?;
        drop(legacy_lock);
        Ok(successor)
    }

    fn open_or_initialize_successor_in_directory(
        successor_directory: &Path,
        directory: File,
        marker: ManagedFabricCutoverMarkerV1,
        controller_signer: &ed25519_dalek::SigningKey,
        provisioning: &ManagedFabricControllerProvisioningV1,
    ) -> Result<Self, ManagedFabricStoreError> {
        let lock_file = open_or_create_successor_lock(&directory)?;
        try_lock(&lock_file)?;
        let lock_identity = file_identity(&lock_file)?;
        clean_successor_temps(&directory)?;
        let initial_state = ManagedFabricControllerStateV1::try_from_cutover(
            marker.marker_digest,
            marker.legacy_snapshot.clone(),
        )?;
        let (state, state_wire) = match read_optional_named_snapshot(
            &directory,
            SUCCESSOR_ACTIVE_FILE_NAME,
            MAX_SUCCESSOR_SNAPSHOT_BYTES,
        )? {
            Some(installed) => decode_successor_snapshot(
                &installed.bytes,
                &marker,
                controller_signer,
                provisioning,
            )?,
            None => {
                ensure_successor_entries(&directory)?;
                let encoded = encode_successor_snapshot(
                    marker.successor_store_instance_id,
                    marker.owner_identity,
                    marker.marker_digest,
                    &initial_state,
                )?;
                publish_snapshot(
                    &directory,
                    SUCCESSOR_ACTIVE_FILE_NAME,
                    SUCCESSOR_TEMP_PREFIX,
                    &encoded,
                    PublishMode::RequireMissing,
                    MAX_SUCCESSOR_SNAPSHOT_BYTES,
                    NamedIdentity {
                        name: SUCCESSOR_LOCK_FILE_NAME,
                        identity: lock_identity,
                    },
                )?;
                (initial_state, encoded)
            }
        };
        Ok(Self {
            directory_path: successor_directory.to_path_buf(),
            directory,
            lock_file,
            store_instance_id: marker.successor_store_instance_id,
            owner_identity: marker.owner_identity,
            marker_digest: marker.marker_digest,
            state,
            state_wire,
            lock_identity,
            operational: true,
        })
    }

    #[must_use]
    pub(crate) const fn state(&self) -> &ManagedFabricControllerStateV1 {
        &self.state
    }

    pub(crate) fn commit_state(
        &mut self,
        next: &ManagedFabricControllerStateV1,
    ) -> Result<(), ManagedFabricStoreError> {
        if !self.operational {
            return Err(ManagedFabricStoreError::Stopped);
        }
        if next.sequence() != self.state.sequence().checked_add(1).unwrap_or(0)
            || next.cutover_marker_digest() != self.marker_digest
            || next.legacy_snapshot() != self.state.legacy_snapshot()
        {
            self.operational = false;
            return Err(ManagedFabricStoreError::InvalidSuccessorState);
        }
        let installed = read_named_snapshot(
            &self.directory,
            SUCCESSOR_ACTIVE_FILE_NAME,
            MAX_SUCCESSOR_SNAPSHOT_BYTES,
        )
        .map_err(|error| self.stop(error))?;
        if installed.bytes.as_slice() != self.state_wire.as_ref() {
            self.operational = false;
            return Err(ManagedFabricStoreError::SuccessorSnapshotChanged);
        }
        let encoded = encode_successor_snapshot(
            self.store_instance_id,
            self.owner_identity,
            self.marker_digest,
            next,
        )
        .map_err(|error| self.stop(error))?;
        publish_snapshot(
            &self.directory,
            SUCCESSOR_ACTIVE_FILE_NAME,
            SUCCESSOR_TEMP_PREFIX,
            &encoded,
            PublishMode::Replace(installed.identity),
            MAX_SUCCESSOR_SNAPSHOT_BYTES,
            NamedIdentity {
                name: SUCCESSOR_LOCK_FILE_NAME,
                identity: self.lock_identity,
            },
        )
        .map_err(|error| self.stop(error))?;
        self.state = next.clone();
        self.state_wire = encoded;
        Ok(())
    }

    fn stop(&mut self, error: ManagedFabricStoreError) -> ManagedFabricStoreError {
        self.operational = false;
        error
    }
}

fn encode_successor_snapshot(
    store_instance_id: [u8; 32],
    owner_identity: ControllerOwnerIdentityFingerprint,
    marker_digest: Digest32,
    state: &ManagedFabricControllerStateV1,
) -> Result<Box<[u8]>, ManagedFabricStoreError> {
    if bytes_are_zero(&store_instance_id)
        || digest_is_zero(marker_digest)
        || state.cutover_marker_digest() != marker_digest
    {
        return Err(ManagedFabricStoreError::InvalidSuccessorState);
    }
    let state_wire = state.encode()?;
    let state_length =
        u32::try_from(state_wire.len()).map_err(|_| ManagedFabricStoreError::SnapshotTooLarge)?;
    let total = SUCCESSOR_HEADER_BYTES
        .checked_add(state_wire.len())
        .and_then(|value| value.checked_add(SUCCESSOR_CHECKSUM_BYTES))
        .ok_or(ManagedFabricStoreError::SnapshotTooLarge)?;
    if total > MAX_SUCCESSOR_SNAPSHOT_BYTES {
        return Err(ManagedFabricStoreError::SnapshotTooLarge);
    }
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(SUCCESSOR_MAGIC);
    encoded.extend_from_slice(&SUCCESSOR_VERSION.to_be_bytes());
    encoded.extend_from_slice(&store_instance_id);
    encoded.extend_from_slice(owner_identity.value().as_bytes());
    encoded.extend_from_slice(marker_digest.as_bytes());
    encoded.extend_from_slice(&state.sequence().to_be_bytes());
    encoded.extend_from_slice(&state_length.to_be_bytes());
    if encoded.len() != SUCCESSOR_HEADER_BYTES {
        return Err(ManagedFabricStoreError::InvalidSuccessorState);
    }
    encoded.extend_from_slice(&state_wire);
    let checksum = digest(SUCCESSOR_CHECKSUM_DOMAIN, &encoded)?;
    encoded.extend_from_slice(checksum.as_bytes());
    Ok(encoded.into_boxed_slice())
}

fn decode_successor_snapshot(
    frame: &[u8],
    marker: &ManagedFabricCutoverMarkerV1,
    controller_signer: &ed25519_dalek::SigningKey,
    provisioning: &ManagedFabricControllerProvisioningV1,
) -> Result<(ManagedFabricControllerStateV1, Box<[u8]>), ManagedFabricStoreError> {
    if frame.len() < SUCCESSOR_HEADER_BYTES + SUCCESSOR_CHECKSUM_BYTES {
        return Err(ManagedFabricStoreError::SnapshotTruncated);
    }
    if frame.len() > MAX_SUCCESSOR_SNAPSHOT_BYTES {
        return Err(ManagedFabricStoreError::SnapshotTooLarge);
    }
    let mut cursor = StoreCursor::new(frame);
    if cursor.array::<4>()? != *SUCCESSOR_MAGIC || cursor.u16()? != SUCCESSOR_VERSION {
        return Err(ManagedFabricStoreError::InvalidSuccessorState);
    }
    let store_instance_id = cursor.array::<32>()?;
    let owner_identity = ControllerOwnerIdentityFingerprint::from_stored(Digest32::from_bytes(
        cursor.array::<32>()?,
    ));
    let marker_digest = Digest32::from_bytes(cursor.array::<32>()?);
    let sequence = cursor.u64()?;
    let state_length = cursor.usize_u32()?;
    let expected_length = SUCCESSOR_HEADER_BYTES
        .checked_add(state_length)
        .and_then(|value| value.checked_add(SUCCESSOR_CHECKSUM_BYTES))
        .ok_or(ManagedFabricStoreError::SnapshotTooLarge)?;
    if expected_length != frame.len() {
        return Err(ManagedFabricStoreError::InvalidSuccessorState);
    }
    let state_wire = cursor.take(state_length)?;
    let checksum = Digest32::from_bytes(cursor.array::<32>()?);
    cursor.finish()?;
    if store_instance_id != marker.successor_store_instance_id
        || owner_identity != marker.owner_identity
        || marker_digest != marker.marker_digest
        || digest(
            SUCCESSOR_CHECKSUM_DOMAIN,
            &frame[..frame.len() - SUCCESSOR_CHECKSUM_BYTES],
        )? != checksum
    {
        return Err(ManagedFabricStoreError::InvalidSuccessorState);
    }
    let state =
        ManagedFabricControllerStateV1::decode(state_wire, controller_signer, provisioning)?;
    if state.sequence() != sequence
        || state.cutover_marker_digest() != marker.marker_digest
        || state.legacy_snapshot() != &marker.legacy_snapshot
    {
        return Err(ManagedFabricStoreError::InvalidSuccessorState);
    }
    Ok((state, frame.into()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedFabricCutoverFailpoint {
    None,
    AfterMarkerDurableBeforeSuccessorSnapshot,
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

struct StoredBytes {
    bytes: Vec<u8>,
    identity: FileIdentity,
}

fn file_identity(file: &File) -> Result<FileIdentity, ManagedFabricStoreError> {
    Ok(FileIdentity::from_metadata(&file.metadata().map_err(
        |error| io_failure(StoreIoStage::InspectFile, &error),
    )?))
}

fn validate_cutover_capability(
    directory: &File,
    lock_identity: FileIdentity,
    expected: ControllerStoreCutoverIdentity,
) -> Result<(), ManagedFabricStoreError> {
    let directory_identity = file_identity(directory)?;
    if directory_identity.device != expected.directory_device
        || directory_identity.inode != expected.directory_inode
        || lock_identity.device != expected.lock_device
        || lock_identity.inode != expected.lock_inode
    {
        return Err(ManagedFabricStoreError::LegacyDirectoryCapabilityMismatch);
    }
    Ok(())
}

fn open_store_directory(
    path: &Path,
    filesystem_policy: ControllerFilesystemPolicy,
) -> Result<File, ManagedFabricStoreError> {
    let _validated = open_controller_directory(path, filesystem_policy)?;
    let before = fs::symlink_metadata(path)
        .map_err(|error| io_failure(StoreIoStage::OpenDirectory, &error))?;
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| nix_failure(StoreIoStage::OpenDirectory, error))?;
    let directory = File::from(owned);
    let after = directory
        .metadata()
        .map_err(|error| io_failure(StoreIoStage::OpenDirectory, &error))?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(ManagedFabricStoreError::DirectoryChanged);
    }
    Ok(directory)
}

fn open_or_create_successor_lock(directory: &File) -> Result<File, ManagedFabricStoreError> {
    match openat(
        directory,
        SUCCESSOR_LOCK_FILE_NAME,
        OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(owned) => {
            let lock = File::from(owned);
            validate_regular_file(&lock)?;
            Ok(lock)
        }
        Err(nix::errno::Errno::ENOENT) => {
            let owned = openat(
                directory,
                SUCCESSOR_LOCK_FILE_NAME,
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                PRIVATE_FILE_MODE,
            )
            .map_err(|error| nix_failure(StoreIoStage::CreateLock, error))?;
            let lock = File::from(owned);
            fchmod(&lock, PRIVATE_FILE_MODE)
                .map_err(|error| nix_failure(StoreIoStage::CreateLock, error))?;
            validate_regular_file(&lock)?;
            lock.sync_all()
                .map_err(|error| io_failure(StoreIoStage::SyncLock, &error))?;
            directory
                .sync_all()
                .map_err(|error| io_failure(StoreIoStage::SyncDirectory, &error))?;
            Ok(lock)
        }
        Err(error) => Err(nix_failure(StoreIoStage::OpenLock, error)),
    }
}

fn try_lock(file: &File) -> Result<(), ManagedFabricStoreError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => ManagedFabricStoreError::LockContended,
        TryLockError::Error(error) => io_failure(StoreIoStage::AcquireLock, &error),
    })
}

fn open_named_regular(
    directory: &File,
    name: &str,
    access: OFlag,
) -> Result<File, ManagedFabricStoreError> {
    let owned = openat(
        directory,
        name,
        access | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| nix_failure(StoreIoStage::OpenSnapshot, error))?;
    let file = File::from(owned);
    validate_regular_file(&file)?;
    Ok(file)
}

fn validate_regular_file(file: &File) -> Result<(), ManagedFabricStoreError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_failure(StoreIoStage::InspectFile, &error))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & PRIVATE_FILE_MODE_MASK != PRIVATE_FILE_MODE_BITS
    {
        return Err(ManagedFabricStoreError::UnsafeFile);
    }
    Ok(())
}

fn read_optional_named_snapshot(
    directory: &File,
    name: &str,
    maximum: usize,
) -> Result<Option<StoredBytes>, ManagedFabricStoreError> {
    match openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(owned) => read_open_snapshot(directory, name, File::from(owned), maximum).map(Some),
        Err(nix::errno::Errno::ENOENT) => Ok(None),
        Err(error) => Err(nix_failure(StoreIoStage::OpenSnapshot, error)),
    }
}

fn read_named_snapshot(
    directory: &File,
    name: &str,
    maximum: usize,
) -> Result<StoredBytes, ManagedFabricStoreError> {
    read_optional_named_snapshot(directory, name, maximum)?
        .ok_or(ManagedFabricStoreError::SnapshotMissing)
}

fn read_open_snapshot(
    directory: &File,
    name: &str,
    mut file: File,
    maximum: usize,
) -> Result<StoredBytes, ManagedFabricStoreError> {
    validate_regular_file(&file)?;
    let before = file
        .metadata()
        .map_err(|error| io_failure(StoreIoStage::ReadSnapshot, &error))?;
    let length =
        usize::try_from(before.len()).map_err(|_| ManagedFabricStoreError::SnapshotTooLarge)?;
    if length == 0 {
        return Err(ManagedFabricStoreError::SnapshotTruncated);
    }
    if length > maximum {
        return Err(ManagedFabricStoreError::SnapshotTooLarge);
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)
        .map_err(|error| io_failure(StoreIoStage::ReadSnapshot, &error))?;
    let mut trailing = [0; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| io_failure(StoreIoStage::ReadSnapshot, &error))?
        != 0
    {
        return Err(ManagedFabricStoreError::SnapshotChangedDuringRead);
    }
    let after = file
        .metadata()
        .map_err(|error| io_failure(StoreIoStage::ReadSnapshot, &error))?;
    let identity = FileIdentity::from_metadata(&before);
    if FileIdentity::from_metadata(&after) != identity || after.len() != before.len() {
        return Err(ManagedFabricStoreError::SnapshotChangedDuringRead);
    }
    let named = open_named_regular(directory, name, OFlag::O_RDONLY)?;
    if FileIdentity::from_metadata(
        &named
            .metadata()
            .map_err(|error| io_failure(StoreIoStage::InspectFile, &error))?,
    ) != identity
    {
        return Err(ManagedFabricStoreError::SnapshotChangedDuringRead);
    }
    Ok(StoredBytes { bytes, identity })
}

#[derive(Clone, Copy)]
enum PublishMode {
    RequireMissing,
    Replace(FileIdentity),
}

#[derive(Clone, Copy)]
struct NamedIdentity<'a> {
    name: &'a str,
    identity: FileIdentity,
}

fn publish_snapshot(
    directory: &File,
    active_name: &str,
    temp_prefix: &str,
    encoded: &[u8],
    mode: PublishMode,
    maximum: usize,
    guard: NamedIdentity<'_>,
) -> Result<(), ManagedFabricStoreError> {
    if encoded.is_empty() || encoded.len() > maximum {
        return Err(ManagedFabricStoreError::SnapshotTooLarge);
    }
    validate_named_identity(directory, guard)?;
    validate_publish_precondition(directory, active_name, mode, maximum)?;
    let temp_name = temp_name(temp_prefix, system_random_token()?);
    let owned = openat(
        directory,
        temp_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(|error| nix_failure(StoreIoStage::CreateTemp, error))?;
    let mut temp = File::from(owned);
    fchmod(&temp, PRIVATE_FILE_MODE)
        .map_err(|error| nix_failure(StoreIoStage::CreateTemp, error))?;
    validate_regular_file(&temp)?;
    temp.write_all(encoded)
        .map_err(|error| io_failure(StoreIoStage::WriteTemp, &error))?;
    temp.sync_all()
        .map_err(|error| io_failure(StoreIoStage::SyncTemp, &error))?;
    validate_named_identity(directory, guard)?;
    validate_publish_precondition(directory, active_name, mode, maximum)?;
    renameat(directory, temp_name.as_str(), directory, active_name)
        .map_err(|error| nix_failure(StoreIoStage::Rename, error))?;
    directory.sync_all().map_err(|error| {
        ManagedFabricStoreError::PublishUncertain(StoreIoFailure::new(
            StoreIoStage::SyncDirectory,
            &error,
        ))
    })?;
    let installed = read_named_snapshot(directory, active_name, maximum)?;
    if installed.bytes.as_slice() != encoded {
        return Err(ManagedFabricStoreError::PublishUncertain(
            StoreIoFailure::injected(StoreIoStage::ReadBack),
        ));
    }
    Ok(())
}

fn validate_publish_precondition(
    directory: &File,
    active_name: &str,
    mode: PublishMode,
    maximum: usize,
) -> Result<(), ManagedFabricStoreError> {
    match (
        mode,
        read_optional_named_snapshot(directory, active_name, maximum)?,
    ) {
        (PublishMode::RequireMissing, None) => Ok(()),
        (PublishMode::RequireMissing, Some(_)) | (PublishMode::Replace(_), None) => {
            Err(ManagedFabricStoreError::PublishPreconditionFailed)
        }
        (PublishMode::Replace(expected), Some(installed)) if installed.identity == expected => {
            Ok(())
        }
        (PublishMode::Replace(_), Some(_)) => {
            Err(ManagedFabricStoreError::PublishPreconditionFailed)
        }
    }
}

fn validate_named_identity(
    directory: &File,
    expected: NamedIdentity<'_>,
) -> Result<(), ManagedFabricStoreError> {
    let named = open_named_regular(directory, expected.name, OFlag::O_RDONLY)?;
    if file_identity(&named)? != expected.identity {
        return Err(ManagedFabricStoreError::LockIdentityChanged);
    }
    Ok(())
}

fn clean_successor_temps(directory: &File) -> Result<(), ManagedFabricStoreError> {
    let mut entries = duplicate_directory_stream(directory)?;
    for entry in entries.iter() {
        let entry = entry.map_err(|error| nix_failure(StoreIoStage::ScanDirectory, error))?;
        let name_bytes = entry.file_name().to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| ManagedFabricStoreError::UnknownDirectoryEntry)?;
        if name == SUCCESSOR_LOCK_FILE_NAME || name == SUCCESSOR_ACTIVE_FILE_NAME {
            continue;
        }
        if valid_temp_name(name, SUCCESSOR_TEMP_PREFIX) {
            let file = open_named_regular(directory, name, OFlag::O_RDONLY)?;
            drop(file);
            unlinkat(directory, name, UnlinkatFlags::NoRemoveDir)
                .map_err(|error| nix_failure(StoreIoStage::RemoveTemp, error))?;
            continue;
        }
        return Err(ManagedFabricStoreError::UnknownDirectoryEntry);
    }
    directory
        .sync_all()
        .map_err(|error| io_failure(StoreIoStage::SyncDirectory, &error))
}

fn ensure_successor_entries(directory: &File) -> Result<(), ManagedFabricStoreError> {
    let mut entries = duplicate_directory_stream(directory)?;
    for entry in entries.iter() {
        let entry = entry.map_err(|error| nix_failure(StoreIoStage::ScanDirectory, error))?;
        let name_bytes = entry.file_name().to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| ManagedFabricStoreError::UnknownDirectoryEntry)?;
        if name != SUCCESSOR_LOCK_FILE_NAME {
            return Err(ManagedFabricStoreError::UnknownDirectoryEntry);
        }
    }
    Ok(())
}

fn duplicate_directory_stream(directory: &File) -> Result<Dir, ManagedFabricStoreError> {
    let duplicate = directory
        .try_clone()
        .map_err(|error| io_failure(StoreIoStage::ScanDirectory, &error))?;
    let descriptor: OwnedFd = duplicate.into();
    Dir::from_fd(descriptor).map_err(|error| nix_failure(StoreIoStage::ScanDirectory, error))
}

fn valid_temp_name(name: &str, prefix: &str) -> bool {
    name.len() == prefix.len() + TEMP_HEX_BYTES
        && name.starts_with(prefix)
        && name.as_bytes()[prefix.len()..]
            .iter()
            .all(u8::is_ascii_hexdigit)
}

fn system_random_token() -> Result<[u8; TEMP_TOKEN_BYTES], ManagedFabricStoreError> {
    let owned = open(
        Path::new("/dev/urandom"),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| nix_failure(StoreIoStage::Random, error))?;
    let mut random = File::from(owned);
    let mut token = [0; TEMP_TOKEN_BYTES];
    random
        .read_exact(&mut token)
        .map_err(|error| io_failure(StoreIoStage::Random, &error))?;
    if bytes_are_zero(&token) {
        return Err(ManagedFabricStoreError::InvalidRandomToken);
    }
    Ok(token)
}

fn temp_name(prefix: &str, token: [u8; TEMP_TOKEN_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(prefix.len() + TEMP_HEX_BYTES);
    name.push_str(prefix);
    for byte in token {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

fn digest(domain: &[u8], bytes: &[u8]) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(domain)?;
    builder.field_bytes(bytes)?;
    Ok(builder.finish())
}

fn digest_is_zero(value: Digest32) -> bool {
    bytes_are_zero(value.as_bytes())
}

const fn bytes_are_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

struct StoreCursor<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> StoreCursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ManagedFabricStoreError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ManagedFabricStoreError::SnapshotTooLarge)?;
        let value = self
            .frame
            .get(self.position..end)
            .ok_or(ManagedFabricStoreError::SnapshotTruncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManagedFabricStoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ManagedFabricStoreError::SnapshotTruncated)
    }

    fn u16(&mut self) -> Result<u16, ManagedFabricStoreError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ManagedFabricStoreError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize_u32(&mut self) -> Result<usize, ManagedFabricStoreError> {
        usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| ManagedFabricStoreError::SnapshotTooLarge)
    }

    fn finish(self) -> Result<(), ManagedFabricStoreError> {
        if self.position == self.frame.len() {
            Ok(())
        } else {
            Err(ManagedFabricStoreError::InvalidSuccessorState)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoreIoStage {
    OpenDirectory,
    ScanDirectory,
    CreateLock,
    OpenLock,
    AcquireLock,
    SyncLock,
    OpenSnapshot,
    InspectFile,
    ReadSnapshot,
    CreateTemp,
    WriteTemp,
    SyncTemp,
    Rename,
    SyncDirectory,
    ReadBack,
    RemoveTemp,
    Random,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StoreIoFailure {
    stage: StoreIoStage,
    kind: Option<io::ErrorKind>,
}

impl StoreIoFailure {
    fn new(stage: StoreIoStage, error: &io::Error) -> Self {
        Self {
            stage,
            kind: Some(error.kind()),
        }
    }

    const fn injected(stage: StoreIoStage) -> Self {
        Self { stage, kind: None }
    }
}

/// Fail-closed cutover/store errors. None authorizes transport replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedFabricStoreError {
    ControllerOpen(ControllerStoreOpenError),
    ControllerStore(ControllerStoreError),
    Journal(ControllerJournalError),
    Producer(ManagedFabricProducerError),
    Apply(ManagedFabricApplyControllerError),
    Digest(DigestBuildError),
    InvalidCutoverIdentity,
    InvalidCutoverMarker,
    InvalidSuccessorState,
    LegacyDirectoryCapabilityMismatch,
    SuccessorMatchesLegacyDirectory,
    LockIdentityChanged,
    LegacySnapshotChanged,
    SuccessorSnapshotChanged,
    SnapshotMissing,
    SnapshotTruncated,
    SnapshotTooLarge,
    SnapshotChangedDuringRead,
    DirectoryChanged,
    UnsafeFile,
    UnknownDirectoryEntry,
    LockContended,
    PublishPreconditionFailed,
    PublishUncertain(StoreIoFailure),
    InterruptedAfterDurableMarker,
    InvalidRandomToken,
    Io(StoreIoFailure),
    Stopped,
}

impl From<ControllerStoreOpenError> for ManagedFabricStoreError {
    fn from(value: ControllerStoreOpenError) -> Self {
        Self::ControllerOpen(value)
    }
}

impl From<ControllerStoreError> for ManagedFabricStoreError {
    fn from(value: ControllerStoreError) -> Self {
        Self::ControllerStore(value)
    }
}

impl From<ControllerJournalError> for ManagedFabricStoreError {
    fn from(value: ControllerJournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<ManagedFabricProducerError> for ManagedFabricStoreError {
    fn from(value: ManagedFabricProducerError) -> Self {
        Self::Producer(value)
    }
}

impl From<ManagedFabricApplyControllerError> for ManagedFabricStoreError {
    fn from(value: ManagedFabricApplyControllerError) -> Self {
        Self::Apply(value)
    }
}

impl From<DigestBuildError> for ManagedFabricStoreError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ManagedFabricStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "managed-fabric store failed: {self:?}")
    }
}

impl std::error::Error for ManagedFabricStoreError {}

fn io_failure(stage: StoreIoStage, error: &io::Error) -> ManagedFabricStoreError {
    ManagedFabricStoreError::Io(StoreIoFailure::new(stage, error))
}

fn nix_failure(stage: StoreIoStage, error: nix::errno::Errno) -> ManagedFabricStoreError {
    io_failure(stage, &io::Error::from_raw_os_error(error as i32))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricListenEndpointV1;

    use crate::controller_store::{
        ControllerCommitFailpoint, ControllerFilesystemPolicy, ControllerStore,
        create_and_lock_controller_initializer_lock, ensure_fresh_controller_directory,
        open_controller_directory, publish_initial_controller_snapshot,
    };
    use crate::managed_fabric_apply::{
        ManagedFabricApplyControllerError, ManagedFabricApplyJournalV1, ManagedFabricApplyPhaseV1,
        tests::{
            active_receipt, controller_signer, current_serving_response, empty_receipt, fresh,
            provisioning, ready_snapshot, service,
        },
    };
    use crate::managed_serving_client::FreshManagedServingBootstrapV1;

    use super::{
        ManagedFabricCutoverFailpoint, ManagedFabricCutoverRequest, ManagedFabricStoreError,
        ManagedFabricSuccessorStoreV1,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
    const SUCCESSOR_STORE_ID: [u8; 32] = [0xd1; 32];

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap_or_else(|error| panic!("fixture root canonicalize failed: {error}"));
            let path = root.join(format!(
                "paraegox-managed-fabric-{label}-{}-{sequence}",
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

    fn install_legacy(directory: &TestDirectory) -> ControllerStore {
        let snapshot = ready_snapshot();
        let encoded = snapshot.encode().expect("ready snapshot encodes");
        let handle = open_controller_directory(
            directory.path(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("fixture directory opens");
        ensure_fresh_controller_directory(&handle).expect("legacy directory is fresh");
        let lock = create_and_lock_controller_initializer_lock(&handle)
            .expect("legacy initializer owns lock");
        publish_initial_controller_snapshot(
            &handle,
            &encoded,
            [0xc1; 16],
            ControllerCommitFailpoint::None,
        )
        .expect("legacy snapshot publishes");
        drop(lock);
        ControllerStore::open_with_policy(
            directory.path(),
            *snapshot.store_instance_id(),
            snapshot.owner_identity_fingerprint(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("legacy store opens")
    }

    fn open_legacy(directory: &TestDirectory) -> ControllerStore {
        let snapshot = ready_snapshot();
        ControllerStore::open_with_policy(
            directory.path(),
            *snapshot.store_instance_id(),
            snapshot.owner_identity_fingerprint(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("legacy store reopens")
    }

    #[test]
    fn cutover_rejects_equal_bytes_from_a_different_store_capability_without_mutation() {
        let legacy_a = TestDirectory::new("legacy-capability-a");
        let legacy_b = TestDirectory::new("legacy-capability-b");
        let successor = TestDirectory::new("successor-capability");
        let store_a = install_legacy(&legacy_a);
        let store_b = install_legacy(&legacy_b);
        drop(store_b);
        let a_before =
            fs::read(legacy_a.path().join("controller.snapshot")).expect("A snapshot readable");
        let b_before =
            fs::read(legacy_b.path().join("controller.snapshot")).expect("B snapshot readable");
        assert_eq!(
            a_before, b_before,
            "negative fixture needs exact equal bytes"
        );
        let owner = store_a
            .snapshot()
            .expect("A operational")
            .owner_identity_fingerprint();
        let signer = controller_signer();
        let provision = provisioning();

        let error = ManagedFabricSuccessorStoreV1::cutover_from_legacy_with_policy_and_failpoint(
            store_a,
            ManagedFabricCutoverRequest {
                legacy_directory: legacy_b.path(),
                successor_directory: successor.path(),
                successor_store_instance_id: SUCCESSOR_STORE_ID,
                expected_owner_identity: owner,
                controller_signer: &signer,
                provisioning: &provision,
                filesystem_policy: ControllerFilesystemPolicy::ExplicitFixture,
            },
            ManagedFabricCutoverFailpoint::None,
        )
        .expect_err("B bytes cannot substitute for A's held directory/lock capability");
        assert_eq!(
            error,
            ManagedFabricStoreError::LegacyDirectoryCapabilityMismatch
        );
        assert_eq!(
            fs::read(legacy_a.path().join("controller.snapshot")).expect("A remains readable"),
            a_before
        );
        assert_eq!(
            fs::read(legacy_b.path().join("controller.snapshot")).expect("B remains readable"),
            b_before
        );
        assert!(
            fs::read_dir(successor.path())
                .expect("successor readable")
                .next()
                .is_none()
        );
        drop(open_legacy(&legacy_a));
        drop(open_legacy(&legacy_b));
    }

    #[test]
    fn cutover_rejects_successor_directory_equal_to_legacy_without_mutation() {
        let legacy = TestDirectory::new("legacy-same-directory");
        let store = install_legacy(&legacy);
        let before =
            fs::read(legacy.path().join("controller.snapshot")).expect("legacy snapshot readable");
        let owner = store
            .snapshot()
            .expect("legacy operational")
            .owner_identity_fingerprint();
        let signer = controller_signer();
        let provision = provisioning();
        let error = ManagedFabricSuccessorStoreV1::cutover_from_legacy_with_policy_and_failpoint(
            store,
            ManagedFabricCutoverRequest {
                legacy_directory: legacy.path(),
                successor_directory: legacy.path(),
                successor_store_instance_id: SUCCESSOR_STORE_ID,
                expected_owner_identity: owner,
                controller_signer: &signer,
                provisioning: &provision,
                filesystem_policy: ControllerFilesystemPolicy::ExplicitFixture,
            },
            ManagedFabricCutoverFailpoint::None,
        )
        .expect_err("successor cannot alias legacy directory");
        assert_eq!(
            error,
            ManagedFabricStoreError::SuccessorMatchesLegacyDirectory
        );
        assert_eq!(
            fs::read(legacy.path().join("controller.snapshot")).expect("legacy remains readable"),
            before
        );
        drop(open_legacy(&legacy));
    }

    #[test]
    fn durable_marker_without_successor_snapshot_has_one_recovery_path() {
        let legacy_directory = TestDirectory::new("legacy-crash");
        let successor_directory = TestDirectory::new("successor-crash");
        let legacy_store = install_legacy(&legacy_directory);
        let owner = legacy_store
            .snapshot()
            .expect("legacy store operational")
            .owner_identity_fingerprint();
        let signer = controller_signer();
        let provision = provisioning();

        let error = ManagedFabricSuccessorStoreV1::cutover_from_legacy_with_policy_and_failpoint(
            legacy_store,
            ManagedFabricCutoverRequest {
                legacy_directory: legacy_directory.path(),
                successor_directory: successor_directory.path(),
                successor_store_instance_id: SUCCESSOR_STORE_ID,
                expected_owner_identity: owner,
                controller_signer: &signer,
                provisioning: &provision,
                filesystem_policy: ControllerFilesystemPolicy::ExplicitFixture,
            },
            ManagedFabricCutoverFailpoint::AfterMarkerDurableBeforeSuccessorSnapshot,
        )
        .expect_err("failpoint stops after the marker is durable");
        assert_eq!(
            error,
            ManagedFabricStoreError::InterruptedAfterDurableMarker
        );
        assert!(
            fs::read_dir(successor_directory.path())
                .expect("successor directory readable")
                .next()
                .is_none(),
            "failpoint must precede every successor-store mutation"
        );
        assert!(
            ControllerStore::open_with_policy(
                legacy_directory.path(),
                *ready_snapshot().store_instance_id(),
                owner,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .is_err(),
            "the v8 opener must fail closed once the marker wins"
        );

        let recovered = ManagedFabricSuccessorStoreV1::resume_from_cutover_marker_with_policy(
            legacy_directory.path(),
            successor_directory.path(),
            SUCCESSOR_STORE_ID,
            owner,
            &signer,
            &provision,
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("marker deterministically initializes successor");
        assert_eq!(recovered.state().sequence(), 1);
        assert_eq!(
            recovered.state().phase(),
            ManagedFabricApplyPhaseV1::CutoverReady
        );
        drop(recovered);

        let reopened = ManagedFabricSuccessorStoreV1::resume_from_cutover_marker_with_policy(
            legacy_directory.path(),
            successor_directory.path(),
            SUCCESSOR_STORE_ID,
            owner,
            &signer,
            &provision,
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("durable successor reopens from the same marker");
        assert_eq!(reopened.state().sequence(), 1);
    }

    #[test]
    fn successor_store_persists_request_uncertain_and_authenticated_terminal() {
        let legacy_directory = TestDirectory::new("legacy-active");
        let successor_directory = TestDirectory::new("successor-active");
        let legacy_store = install_legacy(&legacy_directory);
        let owner = legacy_store
            .snapshot()
            .expect("legacy store operational")
            .owner_identity_fingerprint();
        let signer = controller_signer();
        let provision = provisioning();
        let mut store =
            ManagedFabricSuccessorStoreV1::cutover_from_legacy_with_policy_and_failpoint(
                legacy_store,
                ManagedFabricCutoverRequest {
                    legacy_directory: legacy_directory.path(),
                    successor_directory: successor_directory.path(),
                    successor_store_instance_id: SUCCESSOR_STORE_ID,
                    expected_owner_identity: owner,
                    controller_signer: &signer,
                    provisioning: &provision,
                    filesystem_policy: ControllerFilesystemPolicy::ExplicitFixture,
                },
                ManagedFabricCutoverFailpoint::None,
            )
            .expect("cutover and successor initialization commit");
        let mut journal = ManagedFabricApplyJournalV1::new(store.state().clone());
        let serving_prepared = journal
            .prepare_serving_bootstrap_with(
                &signer,
                &provision,
                FreshManagedServingBootstrapV1::try_new([0xd6; 16], [0xd7; 32])
                    .expect("fresh serving observation"),
                |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                },
            )
            .expect("serving request becomes durable");
        let serving_action = journal
            .claim_serving_bootstrap_with(serving_prepared, |next| {
                store
                    .commit_state(next)
                    .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
            })
            .expect("serving attempt becomes durable before send");
        let serving_response = current_serving_response(serving_action.request());
        journal
            .consume_serving_bootstrap_response_with(
                serving_action,
                serving_response.canonical_wire(),
                &signer,
                &provision,
                |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                },
            )
            .expect("serving response pin becomes durable");
        let prepared = journal
            .prepare_activate_with(
                &signer,
                &provision,
                service(),
                ManagedFabricListenEndpointV1::try_new("tcp/127.0.0.1:7447").expect("endpoint"),
                fresh(0xd2),
                |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                },
            )
            .expect("request becomes durable");
        let action = journal
            .claim_send_with(prepared, &signer, &provision, |next| {
                store
                    .commit_state(next)
                    .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
            })
            .expect("uncertain state becomes durable before send action");
        let receipt = active_receipt(action.request());
        journal
            .consume_pxft_with(
                action,
                receipt.canonical_wire(),
                &signer,
                &provision,
                |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                },
            )
            .expect("authenticated terminal becomes durable");
        assert_eq!(
            store.state().phase(),
            ManagedFabricApplyPhaseV1::ReceiptDurable
        );

        let empty_prepared = journal
            .prepare_empty_deactivate_with(&signer, &provision, fresh(0xd5), |next| {
                store
                    .commit_state(next)
                    .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
            })
            .expect("empty request and active archive become durable");
        let empty_action = journal
            .claim_send_with(empty_prepared, &signer, &provision, |next| {
                store
                    .commit_state(next)
                    .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
            })
            .expect("empty uncertain fence becomes durable");
        let empty_terminal = empty_receipt(empty_action.request());
        journal
            .consume_pxft_with(
                empty_action,
                empty_terminal.canonical_wire(),
                &signer,
                &provision,
                |next| {
                    store
                        .commit_state(next)
                        .map_err(|_| ManagedFabricApplyControllerError::DurabilityRejected)
                },
            )
            .expect("empty exact-zero terminal becomes durable");
        assert!(store.state().archived_active().is_some());
        drop(store);

        let reopened = ManagedFabricSuccessorStoreV1::resume_from_cutover_marker_with_policy(
            legacy_directory.path(),
            successor_directory.path(),
            SUCCESSOR_STORE_ID,
            owner,
            &signer,
            &provision,
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("terminal successor state reopens");
        let replay = ManagedFabricApplyJournalV1::new(reopened.state().clone())
            .terminal(&signer, &provision)
            .expect("terminal revalidates")
            .expect("terminal exists");
        assert!(replay.replayed_from_journal());
    }
}
