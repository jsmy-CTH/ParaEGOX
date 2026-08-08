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
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use nix::fcntl::{RenameFlags, renameat2};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{UnlinkatFlags, getegid, geteuid, unlinkat};
use paraegox_kernel::digest::{Digest32, Digest32Builder};
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_node::observation::{
    RuntimeObservationAckV1, RuntimeObservationAuthorityV1, RuntimeObservationEndpointRefV1,
    RuntimeObservationRequestV1,
};
use paraegox_runtime_contracts::reference_control::ReferenceQueryResponseV1;
use paraegox_runtime_contracts::wire::ApplyAuthAlgorithm;

use crate::controller_journal::{
    CONTROLLER_PAYLOAD_VERSION, CONTROLLER_PREVIOUS_PAYLOAD_VERSION, ControllerJournalError,
    ControllerJournalPayloadV7Migration, ControllerJournalPayloadV8Migration,
    ControllerJournalSnapshot, ControllerOwnerIdentityFingerprint,
    ControllerRemoteConnectorAttemptPhaseV1, ControllerRemoteConnectorCutoverReadyFactsV1,
    ControllerRemoteConnectorRestartRequirementV1, ControllerRemoteConnectorResumeProjectionV1,
    ControllerRemoteConnectorStepV1, MAX_CONTROLLER_SNAPSHOT_BYTES,
};
use crate::distributed_agent_stack_apply::{
    DistributedAgentStackApplyError, DistributedAgentStackApplyJournalV1,
};
use crate::distributed_agent_stack_node_reconcile::{
    DistributedAgentStackNodeDiscoveryStateV1, DistributedAgentStackNodeReconcileError,
    DistributedAgentStackRuntimeQueryMaterialV1, DistributedAgentStackRuntimeQueryPhaseV1,
    DistributedRuntimeObservationCompletionIngressV1,
    TrustedLocalRuntimeObservationExchangeErrorV1,
};
use crate::distributed_agent_stack_producer::VerifiedDistributedAgentStackPredecessorV1;
use crate::runtime_control_client::PreparedRuntimeQueryRequest;

pub(crate) const CONTROLLER_LOCK_FILE_NAME: &str = "controller.lock";
pub(crate) const CONTROLLER_ACTIVE_FILE_NAME: &str = "controller.snapshot";
const TEMP_FILE_PREFIX: &str = ".controller.snapshot.tmp-";
const MIGRATION_SOURCE_FILE_PREFIX: &str = "controller.snapshot.source-v7-";
const MIGRATION_SOURCE_FILE_SUFFIX: &str = ".evidence";
const MIGRATION_RECEIPT_FILE_PREFIX: &str = "controller.snapshot.migration-v1-";
const MIGRATION_RECEIPT_FILE_SUFFIX: &str = ".receipt";
const PAYLOAD_V8_MIGRATION_SOURCE_FILE_PREFIX: &str = "controller.snapshot.source-v8-";
const PAYLOAD_V8_MIGRATION_RECEIPT_FILE_PREFIX: &str = "controller.snapshot.migration-v2-";
const MIGRATION_EVIDENCE_TEMP_PREFIX: &str = ".controller.snapshot.migration.tmp-";
const CONTROLLER_MIGRATION_RECEIPT_MAGIC: &[u8; 4] = b"PXCM";
const CONTROLLER_MIGRATION_RECEIPT_VERSION: u16 = 1;
const CONTROLLER_MIGRATION_SOURCE_PAYLOAD_VERSION: u16 = 7;
const CONTROLLER_MIGRATION_TARGET_PAYLOAD_VERSION: u16 = 8;
const CONTROLLER_PAYLOAD_V8_MIGRATION_RECEIPT_VERSION: u16 = 2;
const CONTROLLER_PAYLOAD_V8_MIGRATION_SOURCE_VERSION: u16 = 8;
const CONTROLLER_PAYLOAD_V8_MIGRATION_TARGET_VERSION: u16 = 9;
const CONTROLLER_MIGRATION_EVIDENCE_DOMAIN: &[u8] =
    b"paraegox.deployment.controller-journal.migration-evidence.sha256.v1";
const CONTROLLER_MIGRATION_RECEIPT_DOMAIN: &[u8] =
    b"paraegox.deployment.controller-journal.migration-receipt.sha256.v1";
const MIGRATION_RECEIPT_WITHOUT_CHECKSUM_BYTES: usize = 226;
const MIGRATION_RECEIPT_BYTES: usize = MIGRATION_RECEIPT_WITHOUT_CHECKSUM_BYTES + 32;
pub(crate) const CONTROLLER_TEMP_TOKEN_BYTES: usize = 16;
const TEMP_HEX_BYTES: usize = CONTROLLER_TEMP_TOKEN_BYTES * 2;
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
const ED25519_ALGORITHM: u16 = 1;
const ED25519_ALGORITHM_VERSION: u16 = 1;
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
    DeveloperLocal,
    #[cfg(test)]
    ExplicitFixture,
}

pub(crate) struct ControllerDirectoryHandle {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    owner_uid: u32,
    owner_gid: u32,
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

/// Exact filesystem capability identity held by one operational Controller writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerStoreCutoverIdentity {
    pub(crate) directory_device: u64,
    pub(crate) directory_inode: u64,
    pub(crate) lock_device: u64,
    pub(crate) lock_inode: u64,
}

impl fmt::Debug for ControllerDirectoryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerDirectoryHandle")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("owner_uid", &self.owner_uid)
            .field("owner_gid", &self.owner_gid)
            .finish_non_exhaustive()
    }
}

/// Fixed-width receipt binding exact v7 source bytes to exact v8 target bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerStoreMigrationReceipt {
    receipt_version: u16,
    migration_id: [u8; 32],
    source_payload_version: u16,
    source_checksum: Digest32,
    source_store_instance_id: [u8; 32],
    source_owner_identity_fingerprint: Digest32,
    source_snapshot_sequence: u64,
    source_snapshot_length: u64,
    source_snapshot_digest: Digest32,
    target_payload_version: u16,
    target_snapshot_length: u64,
    target_snapshot_digest: Digest32,
    canonical_wire: [u8; MIGRATION_RECEIPT_BYTES],
}

struct ControllerMigrationReceiptInput<'a> {
    receipt_version: u16,
    migration_id: [u8; 32],
    source_payload_version: u16,
    source_checksum: Digest32,
    source_store_instance_id: [u8; 32],
    source_owner_identity_fingerprint: Digest32,
    source_snapshot_sequence: u64,
    source_wire: &'a [u8],
    target_payload_version: u16,
    target_wire: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerStoreMigrationDisposition {
    Migrated,
    AlreadyMigrated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerStoreMigrationOutcome {
    pub(crate) disposition: ControllerStoreMigrationDisposition,
    pub(crate) receipt: ControllerStoreMigrationReceipt,
}

impl ControllerStoreMigrationReceipt {
    fn try_new(
        migration_id: [u8; 32],
        source: &ControllerJournalPayloadV7Migration,
        source_wire: &[u8],
        target: &ControllerJournalSnapshot,
        target_wire: &[u8],
    ) -> Result<Self, ControllerStoreMigrationError> {
        if migration_id.iter().all(|byte| *byte == 0)
            || source.source_payload_version() != CONTROLLER_MIGRATION_SOURCE_PAYLOAD_VERSION
            || CONTROLLER_PREVIOUS_PAYLOAD_VERSION != CONTROLLER_MIGRATION_TARGET_PAYLOAD_VERSION
            || source.source_store_instance_id() != target.store_instance_id()
            || source.source_owner_identity_fingerprint() != target.owner_identity_fingerprint()
            || source.source_snapshot_sequence() != target.snapshot_sequence()
            || source.snapshot() != target
            || source_wire.is_empty()
            || source_wire.len() > MAX_CONTROLLER_SNAPSHOT_BYTES
            || target_wire.is_empty()
            || target_wire.len() > MAX_CONTROLLER_SNAPSHOT_BYTES
        {
            return Err(ControllerStoreMigrationError::InvalidReceipt);
        }
        Self::try_new_from_parts(ControllerMigrationReceiptInput {
            receipt_version: CONTROLLER_MIGRATION_RECEIPT_VERSION,
            migration_id,
            source_payload_version: source.source_payload_version(),
            source_checksum: source.source_checksum(),
            source_store_instance_id: *source.source_store_instance_id(),
            source_owner_identity_fingerprint: source.source_owner_identity_fingerprint().value(),
            source_snapshot_sequence: source.source_snapshot_sequence(),
            source_wire,
            target_payload_version: CONTROLLER_MIGRATION_TARGET_PAYLOAD_VERSION,
            target_wire,
        })
    }

    fn try_new_payload_v8(
        migration_id: [u8; 32],
        source: &ControllerJournalPayloadV8Migration,
        source_wire: &[u8],
        target: &ControllerJournalSnapshot,
        target_wire: &[u8],
    ) -> Result<Self, ControllerStoreMigrationError> {
        if migration_id.iter().all(|byte| *byte == 0)
            || source.source_payload_version() != CONTROLLER_PAYLOAD_V8_MIGRATION_SOURCE_VERSION
            || CONTROLLER_PAYLOAD_VERSION != CONTROLLER_PAYLOAD_V8_MIGRATION_TARGET_VERSION
            || source.source_store_instance_id() != target.store_instance_id()
            || source.source_owner_identity_fingerprint() != target.owner_identity_fingerprint()
            || source.source_snapshot_sequence() != target.snapshot_sequence()
            || source.snapshot() != target
            || source_wire.is_empty()
            || source_wire.len() > MAX_CONTROLLER_SNAPSHOT_BYTES
            || target_wire.is_empty()
            || target_wire.len() > MAX_CONTROLLER_SNAPSHOT_BYTES
        {
            return Err(ControllerStoreMigrationError::InvalidReceipt);
        }
        Self::try_new_from_parts(ControllerMigrationReceiptInput {
            receipt_version: CONTROLLER_PAYLOAD_V8_MIGRATION_RECEIPT_VERSION,
            migration_id,
            source_payload_version: source.source_payload_version(),
            source_checksum: source.source_checksum(),
            source_store_instance_id: *source.source_store_instance_id(),
            source_owner_identity_fingerprint: source.source_owner_identity_fingerprint().value(),
            source_snapshot_sequence: source.source_snapshot_sequence(),
            source_wire,
            target_payload_version: CONTROLLER_PAYLOAD_V8_MIGRATION_TARGET_VERSION,
            target_wire,
        })
    }

    fn try_new_from_parts(
        input: ControllerMigrationReceiptInput<'_>,
    ) -> Result<Self, ControllerStoreMigrationError> {
        let source_snapshot_length = u64::try_from(input.source_wire.len())
            .map_err(|_| ControllerStoreMigrationError::InvalidReceipt)?;
        let target_snapshot_length = u64::try_from(input.target_wire.len())
            .map_err(|_| ControllerStoreMigrationError::InvalidReceipt)?;
        let source_snapshot_digest = migration_evidence_digest(input.source_wire)?;
        let target_snapshot_digest = migration_evidence_digest(input.target_wire)?;
        let mut prefix = Vec::with_capacity(MIGRATION_RECEIPT_WITHOUT_CHECKSUM_BYTES);
        prefix.extend_from_slice(CONTROLLER_MIGRATION_RECEIPT_MAGIC);
        prefix.extend_from_slice(&input.receipt_version.to_be_bytes());
        prefix.extend_from_slice(&input.migration_id);
        prefix.extend_from_slice(&input.source_payload_version.to_be_bytes());
        prefix.extend_from_slice(input.source_checksum.as_bytes());
        prefix.extend_from_slice(&input.source_store_instance_id);
        prefix.extend_from_slice(input.source_owner_identity_fingerprint.as_bytes());
        prefix.extend_from_slice(&input.source_snapshot_sequence.to_be_bytes());
        prefix.extend_from_slice(&source_snapshot_length.to_be_bytes());
        prefix.extend_from_slice(source_snapshot_digest.as_bytes());
        prefix.extend_from_slice(&input.target_payload_version.to_be_bytes());
        prefix.extend_from_slice(&target_snapshot_length.to_be_bytes());
        prefix.extend_from_slice(target_snapshot_digest.as_bytes());
        if prefix.len() != MIGRATION_RECEIPT_WITHOUT_CHECKSUM_BYTES {
            return Err(ControllerStoreMigrationError::InvalidReceipt);
        }
        let checksum = migration_receipt_checksum(&prefix)?;
        prefix.extend_from_slice(checksum.as_bytes());
        let canonical_wire = prefix
            .try_into()
            .map_err(|_| ControllerStoreMigrationError::InvalidReceipt)?;
        Ok(Self {
            receipt_version: input.receipt_version,
            migration_id: input.migration_id,
            source_payload_version: input.source_payload_version,
            source_checksum: input.source_checksum,
            source_store_instance_id: input.source_store_instance_id,
            source_owner_identity_fingerprint: input.source_owner_identity_fingerprint,
            source_snapshot_sequence: input.source_snapshot_sequence,
            source_snapshot_length,
            source_snapshot_digest,
            target_payload_version: input.target_payload_version,
            target_snapshot_length,
            target_snapshot_digest,
            canonical_wire,
        })
    }

    fn decode(frame: &[u8]) -> Result<Self, ControllerStoreMigrationError> {
        if frame.len() != MIGRATION_RECEIPT_BYTES {
            return Err(ControllerStoreMigrationError::InvalidReceipt);
        }
        let mut cursor = MigrationReceiptCursor::new(frame);
        if cursor.array::<4>()? != *CONTROLLER_MIGRATION_RECEIPT_MAGIC {
            return Err(ControllerStoreMigrationError::InvalidReceipt);
        }
        let receipt_version = cursor.u16()?;
        let migration_id = cursor.array::<32>()?;
        let source_payload_version = cursor.u16()?;
        let source_checksum = Digest32::from_bytes(cursor.array::<32>()?);
        let source_store_instance_id = cursor.array::<32>()?;
        let source_owner_identity_fingerprint = Digest32::from_bytes(cursor.array::<32>()?);
        let source_snapshot_sequence = cursor.u64()?;
        let source_snapshot_length = cursor.u64()?;
        let source_snapshot_digest = Digest32::from_bytes(cursor.array::<32>()?);
        let target_payload_version = cursor.u16()?;
        let target_snapshot_length = cursor.u64()?;
        let target_snapshot_digest = Digest32::from_bytes(cursor.array::<32>()?);
        let checksum = Digest32::from_bytes(cursor.array::<32>()?);
        cursor.finish()?;
        let supported_versions = matches!(
            (
                receipt_version,
                source_payload_version,
                target_payload_version
            ),
            (
                CONTROLLER_MIGRATION_RECEIPT_VERSION,
                CONTROLLER_MIGRATION_SOURCE_PAYLOAD_VERSION,
                CONTROLLER_MIGRATION_TARGET_PAYLOAD_VERSION
            ) | (
                CONTROLLER_PAYLOAD_V8_MIGRATION_RECEIPT_VERSION,
                CONTROLLER_PAYLOAD_V8_MIGRATION_SOURCE_VERSION,
                CONTROLLER_PAYLOAD_V8_MIGRATION_TARGET_VERSION
            )
        );
        if migration_id.iter().all(|byte| *byte == 0)
            || !supported_versions
            || source_store_instance_id.iter().all(|byte| *byte == 0)
            || source_owner_identity_fingerprint
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || source_snapshot_sequence == 0
            || source_snapshot_length == 0
            || source_snapshot_length > MAX_CONTROLLER_SNAPSHOT_BYTES as u64
            || target_snapshot_length == 0
            || target_snapshot_length > MAX_CONTROLLER_SNAPSHOT_BYTES as u64
            || migration_receipt_checksum(&frame[..MIGRATION_RECEIPT_WITHOUT_CHECKSUM_BYTES])?
                != checksum
        {
            return Err(ControllerStoreMigrationError::InvalidReceipt);
        }
        Ok(Self {
            receipt_version,
            migration_id,
            source_payload_version,
            source_checksum,
            source_store_instance_id,
            source_owner_identity_fingerprint,
            source_snapshot_sequence,
            source_snapshot_length,
            source_snapshot_digest,
            target_payload_version,
            target_snapshot_length,
            target_snapshot_digest,
            canonical_wire: frame
                .try_into()
                .map_err(|_| ControllerStoreMigrationError::InvalidReceipt)?,
        })
    }

    pub(crate) const fn migration_id(&self) -> &[u8; 32] {
        &self.migration_id
    }

    pub(crate) const fn receipt_version(&self) -> u16 {
        self.receipt_version
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

    pub(crate) const fn source_owner_identity_fingerprint(&self) -> Digest32 {
        self.source_owner_identity_fingerprint
    }

    pub(crate) const fn source_snapshot_sequence(&self) -> u64 {
        self.source_snapshot_sequence
    }

    pub(crate) const fn target_payload_version(&self) -> u16 {
        self.target_payload_version
    }

    pub(crate) const fn canonical_wire(&self) -> &[u8; MIGRATION_RECEIPT_BYTES] {
        &self.canonical_wire
    }
}

struct MigrationReceiptCursor<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> MigrationReceiptCursor<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ControllerStoreMigrationError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(ControllerStoreMigrationError::InvalidReceipt)?;
        let bytes = self
            .frame
            .get(self.position..end)
            .ok_or(ControllerStoreMigrationError::InvalidReceipt)?;
        self.position = end;
        bytes
            .try_into()
            .map_err(|_| ControllerStoreMigrationError::InvalidReceipt)
    }

    fn u16(&mut self) -> Result<u16, ControllerStoreMigrationError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ControllerStoreMigrationError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), ControllerStoreMigrationError> {
        if self.position == self.frame.len() {
            Ok(())
        } else {
            Err(ControllerStoreMigrationError::InvalidReceipt)
        }
    }
}

fn migration_evidence_digest(bytes: &[u8]) -> Result<Digest32, ControllerStoreMigrationError> {
    let mut builder = Digest32Builder::try_new(CONTROLLER_MIGRATION_EVIDENCE_DOMAIN)
        .map_err(|_| ControllerStoreMigrationError::InvalidReceipt)?;
    builder
        .field_bytes(bytes)
        .map_err(|_| ControllerStoreMigrationError::InvalidReceipt)?;
    Ok(builder.finish())
}

fn migration_receipt_checksum(bytes: &[u8]) -> Result<Digest32, ControllerStoreMigrationError> {
    let mut builder = Digest32Builder::try_new(CONTROLLER_MIGRATION_RECEIPT_DOMAIN)
        .map_err(|_| ControllerStoreMigrationError::InvalidReceipt)?;
    builder
        .field_bytes(bytes)
        .map_err(|_| ControllerStoreMigrationError::InvalidReceipt)?;
    Ok(builder.finish())
}

pub(crate) struct ControllerStore {
    directory: ControllerDirectoryHandle,
    lock_file: File,
    snapshot: ControllerJournalSnapshot,
    state: ControllerStoreState,
    resident_generation: [u8; CONTROLLER_TEMP_TOKEN_BYTES],
    runtime_observation_grants: Vec<RuntimeObservationResidentGrantV1>,
    active_runtime_observation_claim: Option<RuntimeObservationActiveClaimV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeObservationResidentGrantV1 {
    attempt_count: usize,
    target: RuntimeHostId,
    request_digest: Digest32,
    phase: DistributedAgentStackRuntimeQueryPhaseV1,
    claimed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeObservationActiveClaimV1 {
    snapshot_sequence: u64,
    attempt_count: usize,
    target: RuntimeHostId,
    request_digest: Digest32,
    phase: DistributedAgentStackRuntimeQueryPhaseV1,
}

#[derive(Debug)]
pub(crate) struct ControllerDistributedAgentStackOwnerStateV1 {
    apply_journal: DistributedAgentStackApplyJournalV1,
    node_discovery: DistributedAgentStackNodeDiscoveryStateV1,
}

impl ControllerDistributedAgentStackOwnerStateV1 {
    #[must_use]
    pub(crate) const fn apply_journal(&self) -> &DistributedAgentStackApplyJournalV1 {
        &self.apply_journal
    }

    #[must_use]
    pub(crate) const fn node_discovery(&self) -> &DistributedAgentStackNodeDiscoveryStateV1 {
        &self.node_discovery
    }

    pub(crate) fn parts_mut(
        &mut self,
    ) -> (
        &mut DistributedAgentStackApplyJournalV1,
        &mut DistributedAgentStackNodeDiscoveryStateV1,
    ) {
        (&mut self.apply_journal, &mut self.node_discovery)
    }
}

/// Resident one-shot authority created only by the successful
/// None-to-request-pair commit seam below. Decode/reopen never constructs it.
pub(crate) struct CommittedDistributedRuntimeQueryPairV1 {
    resident_generation: [u8; CONTROLLER_TEMP_TOKEN_BYTES],
    store_instance_id: [u8; 32],
    snapshot_sequence: u64,
    node_state_digest: Digest32,
    attempt_count: usize,
    rows: [DistributedAgentStackRuntimeQueryMaterialV1; 2],
}

impl fmt::Debug for CommittedDistributedRuntimeQueryPairV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedDistributedRuntimeQueryPairV1")
            .field("snapshot_sequence", &self.snapshot_sequence)
            .field("attempt_count", &self.attempt_count)
            .field("targets", &[self.rows[0].target(), self.rows[1].target()])
            .finish_non_exhaustive()
    }
}

/// Sealed authority for one exact already-durable PXNO. Unlike PXQR, this may
/// be reconstructed by the explicit exact-replay seam after restart.
pub(crate) struct CommittedDistributedRuntimeObservationV1 {
    resident_generation: [u8; CONTROLLER_TEMP_TOKEN_BYTES],
    store_instance_id: [u8; 32],
    snapshot_sequence: u64,
    node_state_digest: Digest32,
    attempt_count: usize,
    phase: DistributedAgentStackRuntimeQueryPhaseV1,
    target: RuntimeHostId,
    observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    request: RuntimeObservationRequestV1,
}

impl fmt::Debug for CommittedDistributedRuntimeObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedDistributedRuntimeObservationV1")
            .field("snapshot_sequence", &self.snapshot_sequence)
            .field("target", &self.target)
            .field("request_digest", &self.request.request_digest())
            .finish_non_exhaustive()
    }
}

/// Exact PXNO released for one transport exchange after current-store
/// revalidation. It retains the snapshot witness required by PXNA commit.
pub(crate) struct ClaimedDistributedRuntimeObservationV1 {
    resident_generation: [u8; CONTROLLER_TEMP_TOKEN_BYTES],
    store_instance_id: [u8; 32],
    snapshot_sequence: u64,
    node_state_digest: Digest32,
    attempt_count: usize,
    phase: DistributedAgentStackRuntimeQueryPhaseV1,
    target: RuntimeHostId,
    observation_endpoint_ref: RuntimeObservationEndpointRefV1,
    request: RuntimeObservationRequestV1,
}

impl ClaimedDistributedRuntimeObservationV1 {
    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &RuntimeObservationRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) const fn observation_endpoint_ref(&self) -> RuntimeObservationEndpointRefV1 {
        self.observation_endpoint_ref
    }

    #[cfg(test)]
    pub(crate) fn for_transport_test(
        observation_endpoint_ref: RuntimeObservationEndpointRefV1,
        request: RuntimeObservationRequestV1,
    ) -> Self {
        Self {
            resident_generation: [0x91; CONTROLLER_TEMP_TOKEN_BYTES],
            store_instance_id: [0x92; 32],
            snapshot_sequence: 1,
            node_state_digest: Digest32::from_bytes([0x93; 32]),
            attempt_count: 1,
            phase: DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent,
            target: request.runtime_host_id(),
            observation_endpoint_ref,
            request,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DistributedRuntimeObservationCommitDispositionV1 {
    AckDurable,
    NotSent,
    Uncertain,
    Rejected,
}

impl fmt::Debug for ClaimedDistributedRuntimeObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedDistributedRuntimeObservationV1")
            .field("snapshot_sequence", &self.snapshot_sequence)
            .field("target", &self.target)
            .field("request_digest", &self.request.request_digest())
            .finish_non_exhaustive()
    }
}

/// Move-only authority to perform exactly one transport exchange whose
/// `AttemptInFlight` phase has already been atomically published.
pub(crate) struct ClaimedControllerRemoteConnectorAttemptV1 {
    snapshot_sequence: u64,
    step: ControllerRemoteConnectorStepV1,
    request_wire: Box<[u8]>,
}

impl ClaimedControllerRemoteConnectorAttemptV1 {
    pub(crate) const fn step(&self) -> ControllerRemoteConnectorStepV1 {
        self.step
    }

    pub(crate) fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
}

impl fmt::Debug for ClaimedControllerRemoteConnectorAttemptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedControllerRemoteConnectorAttemptV1")
            .field("snapshot_sequence", &self.snapshot_sequence)
            .field("step", &self.step)
            .field("request_bytes", &self.request_wire.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct ControllerMigrationRequest<'a> {
    directory: &'a Path,
    evidence_directory: &'a Path,
    expected_store_instance_id: [u8; 32],
    expected_owner_identity: ControllerOwnerIdentityFingerprint,
    migration_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControllerMigrationEvidenceFailpoint {
    None,
    AfterRenameBeforeDirectorySync,
}

#[derive(Clone, Copy)]
struct ControllerMigrationFailpoints {
    source_evidence: ControllerMigrationEvidenceFailpoint,
    receipt_evidence: ControllerMigrationEvidenceFailpoint,
    active_snapshot: ControllerCommitFailpoint,
}

impl ControllerMigrationFailpoints {
    const NONE: Self = Self {
        source_evidence: ControllerMigrationEvidenceFailpoint::None,
        receipt_evidence: ControllerMigrationEvidenceFailpoint::None,
        active_snapshot: ControllerCommitFailpoint::None,
    };
}

struct ControllerMigrationGuard {
    directory: ControllerDirectoryHandle,
    lock_file: File,
    lock_identity: FileIdentity,
}

impl Drop for ControllerMigrationGuard {
    fn drop(&mut self) {
        let _ = self.lock_file.unlock();
    }
}

struct ActiveSnapshotBytes {
    encoded: Vec<u8>,
    identity: FileIdentity,
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
    /// Explicitly migrates one stopped Controller store from payload v7 to v8.
    ///
    /// Normal store open never invokes this path. A retry against an already
    /// published v8 snapshot succeeds only when the exact read-only v7 source
    /// evidence and receipt prove the same migration id produced those bytes.
    pub(crate) fn migrate_payload_v7_offline(
        directory: &Path,
        evidence_directory: &Path,
        expected_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        migration_id: [u8; 32],
    ) -> Result<ControllerStoreMigrationOutcome, ControllerStoreMigrationError> {
        Self::migrate_payload_v7_offline_with_policy(
            ControllerMigrationRequest {
                directory,
                evidence_directory,
                expected_store_instance_id,
                expected_owner_identity,
                migration_id,
            },
            ControllerFilesystemPolicy::ProductionReference,
        )
    }

    fn migrate_payload_v7_offline_with_policy(
        request: ControllerMigrationRequest<'_>,
        filesystem_policy: ControllerFilesystemPolicy,
    ) -> Result<ControllerStoreMigrationOutcome, ControllerStoreMigrationError> {
        Self::migrate_payload_v7_offline_with_policy_and_failpoints(
            request,
            filesystem_policy,
            ControllerMigrationFailpoints::NONE,
        )
    }

    fn migrate_payload_v7_offline_with_policy_and_failpoints(
        request: ControllerMigrationRequest<'_>,
        filesystem_policy: ControllerFilesystemPolicy,
        failpoints: ControllerMigrationFailpoints,
    ) -> Result<ControllerStoreMigrationOutcome, ControllerStoreMigrationError> {
        validate_migration_inputs(
            request.expected_store_instance_id,
            request.expected_owner_identity,
            request.migration_id,
        )?;
        let guard = acquire_controller_migration_guard(request.directory, filesystem_policy)?;
        let evidence_directory =
            open_controller_directory(request.evidence_directory, filesystem_policy)
                .map_err(ControllerStoreMigrationError::EvidenceDirectory)?;
        if guard.directory.identity == evidence_directory.identity {
            return Err(ControllerStoreMigrationError::EvidenceDirectoryMatchesStore);
        }
        let active = read_active_controller_snapshot_bytes(&guard.directory)
            .map_err(ControllerStoreMigrationError::Store)?;
        match ControllerJournalSnapshot::migrate_payload_v8(&active.encoded) {
            Ok(target) => resume_completed_controller_migration(
                &guard,
                &evidence_directory,
                request,
                active,
                target,
            ),
            Err(ControllerJournalError::UnknownPayloadVersion) => {
                let source =
                    ControllerJournalSnapshot::migrate_payload_v7_with_metadata(&active.encoded)
                        .map_err(ControllerStoreMigrationError::Journal)?;
                publish_controller_migration(
                    &guard,
                    &evidence_directory,
                    request,
                    active,
                    source,
                    failpoints,
                )
            }
            Err(error) => Err(ControllerStoreMigrationError::Journal(error)),
        }
    }

    /// Explicitly migrates one stopped Controller store from payload v8 to
    /// v9. Normal open is v9-only and never invokes this path implicitly.
    pub(crate) fn migrate_payload_v8_offline(
        directory: &Path,
        evidence_directory: &Path,
        expected_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
        migration_id: [u8; 32],
    ) -> Result<ControllerStoreMigrationOutcome, ControllerStoreMigrationError> {
        Self::migrate_payload_v8_offline_with_policy(
            ControllerMigrationRequest {
                directory,
                evidence_directory,
                expected_store_instance_id,
                expected_owner_identity,
                migration_id,
            },
            ControllerFilesystemPolicy::ProductionReference,
        )
    }

    fn migrate_payload_v8_offline_with_policy(
        request: ControllerMigrationRequest<'_>,
        filesystem_policy: ControllerFilesystemPolicy,
    ) -> Result<ControllerStoreMigrationOutcome, ControllerStoreMigrationError> {
        Self::migrate_payload_v8_offline_with_policy_and_failpoints(
            request,
            filesystem_policy,
            ControllerMigrationFailpoints::NONE,
        )
    }

    fn migrate_payload_v8_offline_with_policy_and_failpoints(
        request: ControllerMigrationRequest<'_>,
        filesystem_policy: ControllerFilesystemPolicy,
        failpoints: ControllerMigrationFailpoints,
    ) -> Result<ControllerStoreMigrationOutcome, ControllerStoreMigrationError> {
        validate_migration_inputs(
            request.expected_store_instance_id,
            request.expected_owner_identity,
            request.migration_id,
        )?;
        let guard = acquire_controller_migration_guard(request.directory, filesystem_policy)?;
        let evidence_directory =
            open_controller_directory(request.evidence_directory, filesystem_policy)
                .map_err(ControllerStoreMigrationError::EvidenceDirectory)?;
        if guard.directory.identity == evidence_directory.identity {
            return Err(ControllerStoreMigrationError::EvidenceDirectoryMatchesStore);
        }
        let active = read_active_controller_snapshot_bytes(&guard.directory)
            .map_err(ControllerStoreMigrationError::Store)?;
        match ControllerJournalSnapshot::decode(&active.encoded) {
            Ok(target) => resume_completed_payload_v8_controller_migration(
                &guard,
                &evidence_directory,
                request,
                active,
                target,
            ),
            Err(ControllerJournalError::UnknownPayloadVersion) => {
                let source =
                    ControllerJournalSnapshot::migrate_payload_v8_with_metadata(&active.encoded)
                        .map_err(ControllerStoreMigrationError::Journal)?;
                publish_payload_v8_controller_migration(
                    &guard,
                    &evidence_directory,
                    request,
                    active,
                    source,
                    failpoints,
                )
            }
            Err(error) => Err(ControllerStoreMigrationError::Journal(error)),
        }
    }

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

    pub(crate) fn open_developer_local(
        directory: &Path,
        expected_store_instance_id: [u8; 32],
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
    ) -> Result<Self, ControllerStoreOpenError> {
        Self::open_with_policy(
            directory,
            expected_store_instance_id,
            expected_owner_identity,
            ControllerFilesystemPolicy::DeveloperLocal,
        )
    }

    /// Reopens a developer-local legacy store when its random store identity
    /// is owned only by the durable snapshot. The owner fingerprint and every
    /// snapshot invariant are still verified before the identity is observed.
    pub(crate) fn open_developer_local_observed_identity(
        directory: &Path,
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
    ) -> Result<Self, ControllerStoreOpenError> {
        Self::open_validated(
            directory,
            None,
            expected_owner_identity,
            ControllerFilesystemPolicy::DeveloperLocal,
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

    pub(crate) fn open_for_sequence_one_receipt_developer_local(
        directory: &Path,
        expected_owner_identity: ControllerOwnerIdentityFingerprint,
    ) -> Result<Self, ControllerStoreOpenError> {
        Self::open_validated(
            directory,
            None,
            expected_owner_identity,
            ControllerFilesystemPolicy::DeveloperLocal,
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
        let resident_generation = system_random_token().map_err(|error| {
            ControllerStoreOpenError::Io(ControllerIoFailure::new(
                ControllerFileStage::GenerateTempName,
                &error,
            ))
        })?;
        Ok(Self {
            directory,
            lock_file,
            snapshot,
            state: ControllerStoreState::Operational,
            resident_generation,
            runtime_observation_grants: Vec::new(),
            active_runtime_observation_claim: None,
        })
    }

    pub(crate) fn snapshot(&self) -> Result<&ControllerJournalSnapshot, ControllerStoreError> {
        self.ensure_operational()?;
        Ok(&self.snapshot)
    }

    /// Atomically persists the owner-private PXCR identity/configuration
    /// before any remote connector request can be prepared.
    pub(crate) fn initialize_remote_connector(
        &mut self,
        configuration_digest: Digest32,
        target: RuntimeHostId,
        successor_store_instance_id: [u8; 32],
        authority_store_instance_id: [u8; 32],
    ) -> Result<(), ControllerStoreError> {
        self.revalidate_current()?;
        let next = self
            .snapshot
            .try_initialize_remote_connector(
                configuration_digest,
                target,
                successor_store_instance_id,
                authority_store_instance_id,
            )
            .map_err(ControllerStoreError::InvalidSuccessor)?;
        self.commit(next)
    }

    /// First half of request-before-send: the exact outer wire is durable but
    /// is not yet transport-authorized.
    pub(crate) fn prepare_remote_connector_request(
        &mut self,
        step: ControllerRemoteConnectorStepV1,
        request_wire: &[u8],
    ) -> Result<(), ControllerStoreError> {
        self.revalidate_current()?;
        let next = self
            .snapshot
            .try_prepare_remote_connector_request(step, request_wire)
            .map_err(ControllerStoreError::InvalidSuccessor)?;
        self.commit(next)
    }

    /// Second half of request-before-send. The returned non-cloneable value is
    /// created only after the `AttemptInFlight` snapshot is published.
    pub(crate) fn claim_remote_connector_attempt(
        &mut self,
        step: ControllerRemoteConnectorStepV1,
    ) -> Result<ClaimedControllerRemoteConnectorAttemptV1, ControllerStoreError> {
        self.revalidate_current()?;
        let request_wire = self
            .snapshot
            .remote_connector_current_attempt()
            .filter(|(current_step, phase, _)| {
                *current_step == step
                    && (*phase == ControllerRemoteConnectorAttemptPhaseV1::RequestDurableNotSent
                        || step == ControllerRemoteConnectorStepV1::NodePublish
                            && matches!(
                                *phase,
                                ControllerRemoteConnectorAttemptPhaseV1::Uncertain
                                    | ControllerRemoteConnectorAttemptPhaseV1::ResidentAuthorityLost
                            ))
            })
            .map(|(_, _, wire)| Box::<[u8]>::from(wire))
            .ok_or(ControllerStoreError::InvalidSuccessor(
                ControllerJournalError::InvalidRemoteConnectorSuccessor,
            ))?;
        let next = self
            .snapshot
            .try_claim_remote_connector_attempt(step)
            .map_err(ControllerStoreError::InvalidSuccessor)?;
        self.commit(next)?;
        let snapshot = self.revalidate_current()?;
        let (current_step, current_phase, current_wire) = snapshot
            .remote_connector_current_attempt()
            .ok_or(ControllerStoreError::Codec(
                ControllerJournalError::InvalidRemoteConnectorState,
            ))?;
        if current_step != step
            || current_phase != ControllerRemoteConnectorAttemptPhaseV1::AttemptInFlight
            || current_wire != request_wire.as_ref()
        {
            self.state = ControllerStoreState::Stopped;
            return Err(ControllerStoreError::ActiveSnapshotChanged);
        }
        Ok(ClaimedControllerRemoteConnectorAttemptV1 {
            snapshot_sequence: snapshot.snapshot_sequence(),
            step,
            request_wire,
        })
    }

    /// Commits the exact response for one consumed claim. A stale or already
    /// consumed claim cannot mutate the active snapshot.
    pub(crate) fn commit_remote_connector_response(
        &mut self,
        claim: ClaimedControllerRemoteConnectorAttemptV1,
        response_wire: &[u8],
    ) -> Result<(), ControllerStoreError> {
        self.revalidate_remote_connector_claim(&claim)?;
        let next = self
            .snapshot
            .try_record_remote_connector_response(claim.step, response_wire)
            .map_err(ControllerStoreError::InvalidSuccessor)?;
        self.commit(next)
    }

    /// Commits one explicit transport closure for a consumed claim.
    pub(crate) fn close_remote_connector_attempt(
        &mut self,
        claim: ClaimedControllerRemoteConnectorAttemptV1,
        closure: ControllerRemoteConnectorAttemptPhaseV1,
    ) -> Result<(), ControllerStoreError> {
        self.revalidate_remote_connector_claim(&claim)?;
        let next = self
            .snapshot
            .try_close_remote_connector_attempt(claim.step, closure)
            .map_err(ControllerStoreError::InvalidSuccessor)?;
        self.commit(next)
    }

    /// Restart closure is deliberately a separate durable operation. It never
    /// produces transport authority or prepares a replacement request.
    pub(crate) fn recover_remote_connector_attempt(
        &mut self,
        step: ControllerRemoteConnectorStepV1,
    ) -> Result<(), ControllerStoreError> {
        self.revalidate_current()?;
        let next = self
            .snapshot
            .try_recover_remote_connector_attempt(step)
            .map_err(ControllerStoreError::InvalidSuccessor)?;
        self.commit(next)
    }

    /// Retires an expired challenge only where the journal proves PXNO was
    /// never sent. A full fresh Node/Runtime discovery round must then be
    /// prepared separately before a new challenge is accepted.
    pub(crate) fn abandon_remote_connector_challenge_round(
        &mut self,
    ) -> Result<(), ControllerStoreError> {
        self.revalidate_current()?;
        let next = self
            .snapshot
            .try_abandon_remote_connector_challenge_round()
            .map_err(ControllerStoreError::InvalidSuccessor)?;
        self.commit(next)
    }

    pub(crate) fn remote_connector_restart_requirement(
        &mut self,
    ) -> Result<ControllerRemoteConnectorRestartRequirementV1, ControllerStoreError> {
        Ok(self
            .revalidate_current()?
            .remote_connector_restart_requirement())
    }

    /// Re-reads the active path while retaining the sole writer lock, then
    /// returns only strictly replayed, transport-authority-free restart facts.
    pub(crate) fn revalidate_remote_connector_resume_projection(
        &mut self,
    ) -> Result<Option<ControllerRemoteConnectorResumeProjectionV1>, ControllerStoreError> {
        self.revalidate_current()?
            .remote_connector_resume_projection()
            .map_err(ControllerStoreError::Codec)
    }

    /// Returns terminal facts only after re-reading the active path while this
    /// store still owns its original lock.
    pub(crate) fn revalidate_remote_connector_cutover_ready(
        &mut self,
    ) -> Result<ControllerRemoteConnectorCutoverReadyFactsV1, ControllerStoreError> {
        self.revalidate_current()?
            .remote_connector_cutover_ready_facts()
            .map_err(ControllerStoreError::Codec)?
            .ok_or(ControllerStoreError::Codec(
                ControllerJournalError::RemoteConnectorCutoverNotReady,
            ))
    }

    fn revalidate_remote_connector_claim(
        &mut self,
        claim: &ClaimedControllerRemoteConnectorAttemptV1,
    ) -> Result<(), ControllerStoreError> {
        let snapshot = self.revalidate_current()?;
        let valid = snapshot.snapshot_sequence() == claim.snapshot_sequence
            && snapshot
                .remote_connector_current_attempt()
                .is_some_and(|(step, phase, wire)| {
                    step == claim.step
                        && phase == ControllerRemoteConnectorAttemptPhaseV1::AttemptInFlight
                        && wire == claim.request_wire.as_ref()
                });
        if !valid {
            self.state = ControllerStoreState::Stopped;
            return Err(ControllerStoreError::ActiveSnapshotChanged);
        }
        Ok(())
    }

    /// Reopens only an owner extension that has not yet introduced PXQR. Once
    /// query history exists, callers must supply exact PXOB authorities and
    /// PXOB endpoint refs through the bound reopen seam below.
    pub(crate) fn reopen_distributed_agent_stack(
        &self,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> Result<
        Option<ControllerDistributedAgentStackOwnerStateV1>,
        ControllerDistributedAgentStackError,
    > {
        let owner =
            self.reopen_distributed_agent_stack_unbound(expected_owner_anchor, predecessors)?;
        if owner
            .as_ref()
            .is_some_and(|owner| owner.node_discovery.runtime_query_attempt_count() != 0)
        {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        Ok(owner)
    }

    pub(crate) fn reopen_distributed_agent_stack_with_runtime_observation(
        &self,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<
        Option<ControllerDistributedAgentStackOwnerStateV1>,
        ControllerDistributedAgentStackError,
    > {
        let owner =
            self.reopen_distributed_agent_stack_unbound(expected_owner_anchor, predecessors)?;
        if let Some(owner) = &owner {
            owner
                .node_discovery
                .validate_runtime_queries(predecessors, authorities, observation_endpoint_refs)
                .map_err(ControllerDistributedAgentStackError::Node)?;
        }
        Ok(owner)
    }

    /// PXJR/PXDE checksum validation performed during store open is followed
    /// here by PXDJ predecessor and Runtime signature reauthentication. This
    /// unbound helper never escapes ControllerStore.
    fn reopen_distributed_agent_stack_unbound(
        &self,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> Result<
        Option<ControllerDistributedAgentStackOwnerStateV1>,
        ControllerDistributedAgentStackError,
    > {
        self.ensure_operational()
            .map_err(ControllerDistributedAgentStackError::Store)?;
        let journal_wire = self.snapshot.distributed_agent_stack_journal_wire();
        let node_wire = self.snapshot.distributed_agent_stack_node_discovery_wire();
        let (Some(journal_wire), Some(node_wire)) = (journal_wire, node_wire) else {
            if journal_wire.is_some() || node_wire.is_some() {
                return Err(ControllerDistributedAgentStackError::IncompleteExtension);
            }
            return Ok(None);
        };
        let apply_journal = DistributedAgentStackApplyJournalV1::try_reopen(
            journal_wire,
            expected_owner_anchor,
            predecessors,
        )
        .map_err(ControllerDistributedAgentStackError::Apply)?;
        let node_discovery = DistributedAgentStackNodeDiscoveryStateV1::decode(node_wire)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        node_discovery
            .validate_runtime_queries_against_predecessors(predecessors)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let apply_state = apply_journal
            .state()
            .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
        if node_discovery.owner_anchor() != expected_owner_anchor
            || node_discovery.owner_anchor() != apply_state.owner_anchor()
            || node_discovery.rollout_id() != apply_state.rollout().rollout_id()
            || node_discovery.runtime_targets()
                != [predecessors[0].target(), predecessors[1].target()]
        {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        Ok(Some(ControllerDistributedAgentStackOwnerStateV1 {
            apply_journal,
            node_discovery,
        }))
    }

    /// Commits exact PXDJ and PXDN bytes inside this store's existing atomic
    /// replace/fsync boundary. No second path, lock, or journal is created.
    pub(crate) fn commit_distributed_agent_stack_wires(
        &mut self,
        journal_wire: &[u8],
        node_discovery_wire: &[u8],
    ) -> Result<(), ControllerDistributedAgentStackError> {
        self.ensure_operational()
            .map_err(ControllerDistributedAgentStackError::Store)?;
        if self.active_runtime_observation_claim.is_some() {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        let next = self
            .snapshot
            .try_distributed_agent_stack_successor(journal_wire, node_discovery_wire)
            .map_err(ControllerDistributedAgentStackError::Journal)?;
        self.commit(next)
            .map_err(ControllerDistributedAgentStackError::Store)
    }

    fn commit_claimed_runtime_observation_successor(
        &mut self,
        journal_wire: &[u8],
        node_discovery_wire: &[u8],
    ) -> Result<(), ControllerDistributedAgentStackError> {
        self.ensure_operational()
            .map_err(ControllerDistributedAgentStackError::Store)?;
        if self.active_runtime_observation_claim.is_none() {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        let next = self
            .snapshot
            .try_distributed_agent_stack_successor(journal_wire, node_discovery_wire)
            .map_err(ControllerDistributedAgentStackError::Journal)?;
        let result = self
            .commit(next)
            .map_err(ControllerDistributedAgentStackError::Store);
        let result = result.and_then(|()| {
            self.revalidate_current()
                .map_err(ControllerDistributedAgentStackError::Store)?;
            if self.snapshot.distributed_agent_stack_journal_wire() != Some(journal_wire)
                || self.snapshot.distributed_agent_stack_node_discovery_wire()
                    != Some(node_discovery_wire)
            {
                return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
            }
            Ok(())
        });
        if result.is_ok() {
            self.active_runtime_observation_claim = None;
        } else {
            self.state = ControllerStoreState::Stopped;
        }
        result
    }

    /// Atomically appends one request-only A/B PXQR attempt, then performs an
    /// exact active-snapshot readback before creating resident send authority.
    /// No reopen path calls this constructor.
    pub(crate) fn commit_distributed_runtime_query_pair(
        &mut self,
        next_node_discovery: &DistributedAgentStackNodeDiscoveryStateV1,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<CommittedDistributedRuntimeQueryPairV1, ControllerDistributedAgentStackError> {
        next_node_discovery
            .validate_runtime_queries(predecessors, authorities, observation_endpoint_refs)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let owner_anchor = next_node_discovery.owner_anchor();
        let before = self
            .reopen_distributed_agent_stack_with_runtime_observation(
                owner_anchor,
                predecessors,
                authorities,
                observation_endpoint_refs,
            )?
            .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
        if next_node_discovery.runtime_query_attempt_count()
            != before
                .node_discovery
                .runtime_query_attempt_count()
                .saturating_add(1)
            || next_node_discovery.runtime_query_phases()
                != Some([
                    DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent,
                    DistributedAgentStackRuntimeQueryPhaseV1::RequestDurableNotSent,
                ])
        {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        let expected_wire = next_node_discovery
            .encode()
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let journal_wire = self.current_distributed_agent_stack_journal_wire()?;
        self.commit_distributed_agent_stack_wires(&journal_wire, &expected_wire)?;
        let readback_result = (|| {
            self.revalidate_current()
                .map_err(ControllerDistributedAgentStackError::Store)?;
            if self.snapshot.distributed_agent_stack_node_discovery_wire()
                != Some(expected_wire.as_ref())
            {
                return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
            }
            let readback = self
                .reopen_distributed_agent_stack_with_runtime_observation(
                    owner_anchor,
                    predecessors,
                    authorities,
                    observation_endpoint_refs,
                )?
                .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
            let targets = readback.node_discovery.runtime_targets();
            let rows = [
                readback
                    .node_discovery
                    .current_runtime_query_material(targets[0], predecessors[0])
                    .map_err(ControllerDistributedAgentStackError::Node)?,
                readback
                    .node_discovery
                    .current_runtime_query_material(targets[1], predecessors[1])
                    .map_err(ControllerDistributedAgentStackError::Node)?,
            ];
            Ok(CommittedDistributedRuntimeQueryPairV1 {
                resident_generation: self.resident_generation,
                store_instance_id: *self.snapshot.store_instance_id(),
                snapshot_sequence: self.snapshot.snapshot_sequence(),
                node_state_digest: readback
                    .node_discovery
                    .durable_digest()
                    .map_err(ControllerDistributedAgentStackError::Node)?,
                attempt_count: readback.node_discovery.runtime_query_attempt_count(),
                rows,
            })
        })();
        if readback_result.is_err() {
            self.state = ControllerStoreState::Stopped;
        }
        readback_result
    }

    /// Consumes the resident post-commit pair token and releases both PXQR
    /// requests together. The token becomes stale after any successor commit.
    pub(crate) fn claim_distributed_runtime_query_pair(
        &mut self,
        prepared: CommittedDistributedRuntimeQueryPairV1,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<[PreparedRuntimeQueryRequest; 2], ControllerDistributedAgentStackError> {
        self.revalidate_current()
            .map_err(ControllerDistributedAgentStackError::Store)?;
        if prepared.resident_generation != self.resident_generation
            || prepared.store_instance_id != *self.snapshot.store_instance_id()
            || prepared.snapshot_sequence != self.snapshot.snapshot_sequence()
        {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        let readback = self
            .reopen_distributed_agent_stack_with_runtime_observation(
                expected_owner_anchor,
                predecessors,
                authorities,
                observation_endpoint_refs,
            )?
            .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
        if prepared.node_state_digest
            != readback
                .node_discovery
                .durable_digest()
                .map_err(ControllerDistributedAgentStackError::Node)?
            || prepared.attempt_count != readback.node_discovery.runtime_query_attempt_count()
        {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        let targets = readback.node_discovery.runtime_targets();
        let current_rows = [
            readback
                .node_discovery
                .current_runtime_query_material(targets[0], predecessors[0])
                .map_err(ControllerDistributedAgentStackError::Node)?,
            readback
                .node_discovery
                .current_runtime_query_material(targets[1], predecessors[1])
                .map_err(ControllerDistributedAgentStackError::Node)?,
        ];
        if prepared.rows != current_rows {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        let algorithm = ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM).map_err(|_| {
            ControllerDistributedAgentStackError::Node(
                DistributedAgentStackNodeReconcileError::InvalidState,
            )
        })?;
        Ok([
            PreparedRuntimeQueryRequest::try_new(
                prepared.rows[0].request().clone(),
                predecessors[0].runtime_channel(),
                predecessors[0].runtime_response_key(),
                algorithm,
                ED25519_ALGORITHM_VERSION,
                prepared.rows[0].serving_baseline(),
            )
            .map_err(|_| {
                ControllerDistributedAgentStackError::Node(
                    DistributedAgentStackNodeReconcileError::InvalidState,
                )
            })?,
            PreparedRuntimeQueryRequest::try_new(
                prepared.rows[1].request().clone(),
                predecessors[1].runtime_channel(),
                predecessors[1].runtime_response_key(),
                algorithm,
                ED25519_ALGORITHM_VERSION,
                prepared.rows[1].serving_baseline(),
            )
            .map_err(|_| {
                ControllerDistributedAgentStackError::Node(
                    DistributedAgentStackNodeReconcileError::InvalidState,
                )
            })?,
        ])
    }

    /// Commits one validated PXQS as its own successor before any PXNO for
    /// either target can be introduced.
    pub(crate) fn commit_distributed_runtime_query_response(
        &mut self,
        target: RuntimeHostId,
        response: ReferenceQueryResponseV1,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<(), ControllerDistributedAgentStackError> {
        let current = self
            .reopen_distributed_agent_stack_with_runtime_observation(
                expected_owner_anchor,
                predecessors,
                authorities,
                observation_endpoint_refs,
            )?
            .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
        let index = if target == predecessors[0].target() {
            0
        } else if target == predecessors[1].target() {
            1
        } else {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        };
        let next = current
            .node_discovery
            .try_record_runtime_query_response(target, response, predecessors[index])
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let next_wire = next
            .encode()
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let journal_wire = self.current_distributed_agent_stack_journal_wire()?;
        self.commit_distributed_agent_stack_wires(&journal_wire, &next_wire)?;
        self.verify_runtime_query_successor_readback(
            &next,
            &next_wire,
            expected_owner_anchor,
            predecessors,
            authorities,
            observation_endpoint_refs,
        )
    }

    /// Durably closes one request-only PXQR row with its classified outcome.
    /// Restart callers must select ResidentAuthorityLost; no method here can
    /// recreate the consumed pair token.
    pub(crate) fn commit_distributed_runtime_query_closure(
        &mut self,
        target: RuntimeHostId,
        closure: DistributedAgentStackRuntimeQueryPhaseV1,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<(), ControllerDistributedAgentStackError> {
        let current = self
            .reopen_distributed_agent_stack_with_runtime_observation(
                expected_owner_anchor,
                predecessors,
                authorities,
                observation_endpoint_refs,
            )?
            .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
        let next = current
            .node_discovery
            .try_close_runtime_query(target, closure)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let next_wire = next
            .encode()
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let journal_wire = self.current_distributed_agent_stack_journal_wire()?;
        self.commit_distributed_agent_stack_wires(&journal_wire, &next_wire)?;
        self.verify_runtime_query_successor_readback(
            &next,
            &next_wire,
            expected_owner_anchor,
            predecessors,
            authorities,
            observation_endpoint_refs,
        )
    }

    fn verify_runtime_query_successor_readback(
        &mut self,
        expected: &DistributedAgentStackNodeDiscoveryStateV1,
        expected_wire: &[u8],
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<(), ControllerDistributedAgentStackError> {
        let result = (|| {
            self.revalidate_current()
                .map_err(ControllerDistributedAgentStackError::Store)?;
            if self.snapshot.distributed_agent_stack_node_discovery_wire() != Some(expected_wire) {
                return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
            }
            let readback = self
                .reopen_distributed_agent_stack_with_runtime_observation(
                    expected_owner_anchor,
                    predecessors,
                    authorities,
                    observation_endpoint_refs,
                )?
                .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
            if &readback.node_discovery != expected {
                return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
            }
            Ok(())
        })();
        if result.is_err() {
            self.state = ControllerStoreState::Stopped;
        }
        result
    }

    /// Commits one exact PXNO before minting any authority to send it.
    pub(crate) fn commit_distributed_runtime_observation(
        &mut self,
        next_node_discovery: &DistributedAgentStackNodeDiscoveryStateV1,
        target: RuntimeHostId,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<CommittedDistributedRuntimeObservationV1, ControllerDistributedAgentStackError>
    {
        next_node_discovery
            .validate_runtime_queries(predecessors, authorities, observation_endpoint_refs)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let owner_anchor = next_node_discovery.owner_anchor();
        let before = self
            .reopen_distributed_agent_stack_with_runtime_observation(
                owner_anchor,
                predecessors,
                authorities,
                observation_endpoint_refs,
            )?
            .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
        if before
            .node_discovery
            .runtime_query_phase(target)
            .map_err(ControllerDistributedAgentStackError::Node)?
            != DistributedAgentStackRuntimeQueryPhaseV1::ResponseDurable
            || next_node_discovery
                .runtime_query_phase(target)
                .map_err(ControllerDistributedAgentStackError::Node)?
                != DistributedAgentStackRuntimeQueryPhaseV1::ObservationDurableNotSent
        {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        let expected_wire = next_node_discovery
            .encode()
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let journal_wire = self.current_distributed_agent_stack_journal_wire()?;
        self.commit_distributed_agent_stack_wires(&journal_wire, &expected_wire)?;
        let readback_result = (|| {
            self.revalidate_current()
                .map_err(ControllerDistributedAgentStackError::Store)?;
            if self.snapshot.distributed_agent_stack_node_discovery_wire()
                != Some(expected_wire.as_ref())
            {
                return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
            }
            let readback = self
                .reopen_distributed_agent_stack_with_runtime_observation(
                    owner_anchor,
                    predecessors,
                    authorities,
                    observation_endpoint_refs,
                )?
                .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
            let request = readback
                .node_discovery
                .current_runtime_observation(target)
                .map_err(ControllerDistributedAgentStackError::Node)?;
            let snapshot_sequence = self.snapshot.snapshot_sequence();
            let node_state_digest = readback
                .node_discovery
                .durable_digest()
                .map_err(ControllerDistributedAgentStackError::Node)?;
            let attempt_count = readback.node_discovery.runtime_query_attempt_count();
            let phase = readback
                .node_discovery
                .runtime_query_phase(target)
                .map_err(ControllerDistributedAgentStackError::Node)?;
            let observation_endpoint_ref = runtime_observation_endpoint_ref_for_target(
                target,
                predecessors,
                observation_endpoint_refs,
            )?;
            self.grant_runtime_observation_once(
                attempt_count,
                target,
                request.request_digest(),
                phase,
            )?;
            Ok(CommittedDistributedRuntimeObservationV1 {
                resident_generation: self.resident_generation,
                store_instance_id: *self.snapshot.store_instance_id(),
                snapshot_sequence,
                node_state_digest,
                attempt_count,
                phase,
                target,
                observation_endpoint_ref,
                request,
            })
        })();
        if readback_result.is_err() {
            self.state = ControllerStoreState::Stopped;
        }
        readback_result
    }

    /// Explicit restart seam for exact PXNO replay. It never returns PXQR
    /// authority and accepts only a durable-not-sent or uncertain PXNO row.
    pub(crate) fn recover_distributed_runtime_observation(
        &mut self,
        expected_owner_anchor: Digest32,
        target: RuntimeHostId,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<CommittedDistributedRuntimeObservationV1, ControllerDistributedAgentStackError>
    {
        self.revalidate_current()
            .map_err(ControllerDistributedAgentStackError::Store)?;
        let readback = self
            .reopen_distributed_agent_stack_with_runtime_observation(
                expected_owner_anchor,
                predecessors,
                authorities,
                observation_endpoint_refs,
            )?
            .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
        let request = readback
            .node_discovery
            .current_runtime_observation(target)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let snapshot_sequence = self.snapshot.snapshot_sequence();
        let node_state_digest = readback
            .node_discovery
            .durable_digest()
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let attempt_count = readback.node_discovery.runtime_query_attempt_count();
        let phase = readback
            .node_discovery
            .runtime_query_phase(target)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let observation_endpoint_ref = runtime_observation_endpoint_ref_for_target(
            target,
            predecessors,
            observation_endpoint_refs,
        )?;
        self.grant_runtime_observation_once(
            attempt_count,
            target,
            request.request_digest(),
            phase,
        )?;
        Ok(CommittedDistributedRuntimeObservationV1 {
            resident_generation: self.resident_generation,
            store_instance_id: *self.snapshot.store_instance_id(),
            snapshot_sequence,
            node_state_digest,
            attempt_count,
            phase,
            target,
            observation_endpoint_ref,
            request,
        })
    }

    /// Revalidates one sealed PXNO against the exact current snapshot before
    /// releasing its canonical request bytes to the transport owner.
    pub(crate) fn claim_distributed_runtime_observation(
        &mut self,
        prepared: CommittedDistributedRuntimeObservationV1,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<ClaimedDistributedRuntimeObservationV1, ControllerDistributedAgentStackError> {
        self.revalidate_current()
            .map_err(ControllerDistributedAgentStackError::Store)?;
        if prepared.resident_generation != self.resident_generation
            || prepared.store_instance_id != *self.snapshot.store_instance_id()
            || prepared.snapshot_sequence != self.snapshot.snapshot_sequence()
        {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        let readback = self
            .reopen_distributed_agent_stack_with_runtime_observation(
                expected_owner_anchor,
                predecessors,
                authorities,
                observation_endpoint_refs,
            )?
            .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
        let request = readback
            .node_discovery
            .current_runtime_observation(prepared.target)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let phase = readback
            .node_discovery
            .runtime_query_phase(prepared.target)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let observation_endpoint_ref = runtime_observation_endpoint_ref_for_target(
            prepared.target,
            predecessors,
            observation_endpoint_refs,
        )?;
        if prepared.node_state_digest
            != readback
                .node_discovery
                .durable_digest()
                .map_err(ControllerDistributedAgentStackError::Node)?
            || prepared.request != request
            || prepared.attempt_count != readback.node_discovery.runtime_query_attempt_count()
            || prepared.phase != phase
            || prepared.observation_endpoint_ref != observation_endpoint_ref
        {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        self.consume_runtime_observation_grant(
            prepared.attempt_count,
            prepared.target,
            prepared.request.request_digest(),
            prepared.phase,
        )?;
        self.active_runtime_observation_claim = Some(RuntimeObservationActiveClaimV1 {
            snapshot_sequence: prepared.snapshot_sequence,
            attempt_count: prepared.attempt_count,
            target: prepared.target,
            request_digest: prepared.request.request_digest(),
            phase: prepared.phase,
        });
        Ok(ClaimedDistributedRuntimeObservationV1 {
            resident_generation: prepared.resident_generation,
            store_instance_id: prepared.store_instance_id,
            snapshot_sequence: prepared.snapshot_sequence,
            node_state_digest: prepared.node_state_digest,
            attempt_count: prepared.attempt_count,
            phase: prepared.phase,
            target: prepared.target,
            observation_endpoint_ref: prepared.observation_endpoint_ref,
            request,
        })
    }

    pub(crate) fn commit_distributed_runtime_observation_ingress(
        &mut self,
        ingress: DistributedRuntimeObservationCompletionIngressV1,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<
        DistributedRuntimeObservationCommitDispositionV1,
        ControllerDistributedAgentStackError,
    > {
        let (claimed, result) = ingress.into_store_parts();
        match result {
            Ok(ack) => {
                self.commit_distributed_runtime_observation_ack(
                    claimed,
                    ack,
                    expected_owner_anchor,
                    predecessors,
                    authorities,
                    observation_endpoint_refs,
                )?;
                Ok(DistributedRuntimeObservationCommitDispositionV1::AckDurable)
            }
            Err(TrustedLocalRuntimeObservationExchangeErrorV1::NotSent(_)) => {
                self.commit_distributed_runtime_observation_closure(
                    claimed,
                    DistributedAgentStackRuntimeQueryPhaseV1::ObservationNotSent,
                    expected_owner_anchor,
                    predecessors,
                    authorities,
                    observation_endpoint_refs,
                )?;
                Ok(DistributedRuntimeObservationCommitDispositionV1::NotSent)
            }
            Err(TrustedLocalRuntimeObservationExchangeErrorV1::Uncertain(_)) => {
                self.commit_distributed_runtime_observation_closure(
                    claimed,
                    DistributedAgentStackRuntimeQueryPhaseV1::ObservationUncertain,
                    expected_owner_anchor,
                    predecessors,
                    authorities,
                    observation_endpoint_refs,
                )?;
                Ok(DistributedRuntimeObservationCommitDispositionV1::Uncertain)
            }
            Err(TrustedLocalRuntimeObservationExchangeErrorV1::Rejected(_)) => {
                self.commit_distributed_runtime_observation_closure(
                    claimed,
                    DistributedAgentStackRuntimeQueryPhaseV1::ObservationRejected,
                    expected_owner_anchor,
                    predecessors,
                    authorities,
                    observation_endpoint_refs,
                )?;
                Ok(DistributedRuntimeObservationCommitDispositionV1::Rejected)
            }
        }
    }

    /// Commits PXNA only while the claimed PXNO still names the exact current
    /// store instance, snapshot sequence, and PXDN digest.
    fn commit_distributed_runtime_observation_ack(
        &mut self,
        claimed: ClaimedDistributedRuntimeObservationV1,
        ack: RuntimeObservationAckV1,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<(), ControllerDistributedAgentStackError> {
        let current = self.validate_claimed_runtime_observation(
            &claimed,
            expected_owner_anchor,
            predecessors,
            authorities,
            observation_endpoint_refs,
        )?;
        let next = current
            .node_discovery
            .try_record_runtime_observation_ack(claimed.target, &claimed.request, ack)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let next_wire = next
            .encode()
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let journal_wire = self.current_distributed_agent_stack_journal_wire()?;
        self.commit_claimed_runtime_observation_successor(&journal_wire, &next_wire)
    }

    /// Durably records the classified PXNO transport outcome while the exact
    /// claimed store witness is still current.
    fn commit_distributed_runtime_observation_closure(
        &mut self,
        claimed: ClaimedDistributedRuntimeObservationV1,
        closure: DistributedAgentStackRuntimeQueryPhaseV1,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<(), ControllerDistributedAgentStackError> {
        let current = self.validate_claimed_runtime_observation(
            &claimed,
            expected_owner_anchor,
            predecessors,
            authorities,
            observation_endpoint_refs,
        )?;
        let next = current
            .node_discovery
            .try_close_runtime_observation(claimed.target, closure)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let next_wire = next
            .encode()
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let journal_wire = self.current_distributed_agent_stack_journal_wire()?;
        self.commit_claimed_runtime_observation_successor(&journal_wire, &next_wire)
    }

    fn validate_claimed_runtime_observation(
        &mut self,
        claimed: &ClaimedDistributedRuntimeObservationV1,
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        authorities: [&RuntimeObservationAuthorityV1; 2],
        observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
    ) -> Result<ControllerDistributedAgentStackOwnerStateV1, ControllerDistributedAgentStackError>
    {
        self.revalidate_current()
            .map_err(ControllerDistributedAgentStackError::Store)?;
        if claimed.resident_generation != self.resident_generation
            || claimed.store_instance_id != *self.snapshot.store_instance_id()
            || claimed.snapshot_sequence != self.snapshot.snapshot_sequence()
            || self.active_runtime_observation_claim
                != Some(RuntimeObservationActiveClaimV1 {
                    snapshot_sequence: claimed.snapshot_sequence,
                    attempt_count: claimed.attempt_count,
                    target: claimed.target,
                    request_digest: claimed.request.request_digest(),
                    phase: claimed.phase,
                })
        {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        let current = self
            .reopen_distributed_agent_stack_with_runtime_observation(
                expected_owner_anchor,
                predecessors,
                authorities,
                observation_endpoint_refs,
            )?
            .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)?;
        let current_phase = current
            .node_discovery
            .runtime_query_phase(claimed.target)
            .map_err(ControllerDistributedAgentStackError::Node)?;
        let current_endpoint_ref = runtime_observation_endpoint_ref_for_target(
            claimed.target,
            predecessors,
            observation_endpoint_refs,
        )?;
        if claimed.node_state_digest
            != current
                .node_discovery
                .durable_digest()
                .map_err(ControllerDistributedAgentStackError::Node)?
            || current
                .node_discovery
                .current_runtime_observation(claimed.target)
                .map_err(ControllerDistributedAgentStackError::Node)?
                != claimed.request
            || claimed.attempt_count != current.node_discovery.runtime_query_attempt_count()
            || claimed.phase != current_phase
            || claimed.observation_endpoint_ref != current_endpoint_ref
        {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        Ok(current)
    }

    fn grant_runtime_observation_once(
        &mut self,
        attempt_count: usize,
        target: RuntimeHostId,
        request_digest: Digest32,
        phase: DistributedAgentStackRuntimeQueryPhaseV1,
    ) -> Result<(), ControllerDistributedAgentStackError> {
        if self.runtime_observation_grants.iter().any(|grant| {
            grant.attempt_count == attempt_count
                && grant.target == target
                && grant.request_digest == request_digest
                && grant.phase == phase
        }) {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        self.runtime_observation_grants
            .try_reserve(1)
            .map_err(|_| ControllerDistributedAgentStackError::CrossBindingMismatch)?;
        self.runtime_observation_grants
            .push(RuntimeObservationResidentGrantV1 {
                attempt_count,
                target,
                request_digest,
                phase,
                claimed: false,
            });
        Ok(())
    }

    fn current_distributed_agent_stack_journal_wire(
        &self,
    ) -> Result<Vec<u8>, ControllerDistributedAgentStackError> {
        self.ensure_operational()
            .map_err(ControllerDistributedAgentStackError::Store)?;
        self.snapshot
            .distributed_agent_stack_journal_wire()
            .map(ToOwned::to_owned)
            .ok_or(ControllerDistributedAgentStackError::IncompleteExtension)
    }

    fn consume_runtime_observation_grant(
        &mut self,
        attempt_count: usize,
        target: RuntimeHostId,
        request_digest: Digest32,
        phase: DistributedAgentStackRuntimeQueryPhaseV1,
    ) -> Result<(), ControllerDistributedAgentStackError> {
        if self.active_runtime_observation_claim.is_some() {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        let grant = self
            .runtime_observation_grants
            .iter_mut()
            .find(|grant| {
                grant.attempt_count == attempt_count
                    && grant.target == target
                    && grant.request_digest == request_digest
                    && grant.phase == phase
            })
            .ok_or(ControllerDistributedAgentStackError::CrossBindingMismatch)?;
        if grant.claimed {
            return Err(ControllerDistributedAgentStackError::CrossBindingMismatch);
        }
        grant.claimed = true;
        Ok(())
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

    /// Revalidates and exposes only the exact directory/lock capability needed
    /// to bind a one-way successor cutover to this consumed writer.
    pub(crate) fn managed_fabric_cutover_identity(
        &mut self,
    ) -> Result<ControllerStoreCutoverIdentity, ControllerStoreError> {
        self.revalidate_current()?;
        let lock_metadata = self.lock_file.metadata().map_err(|error| {
            self.state = ControllerStoreState::Stopped;
            ControllerStoreError::Open(ControllerStoreOpenError::Io(ControllerIoFailure::new(
                ControllerFileStage::ValidateLockIdentity,
                &error,
            )))
        })?;
        let lock_identity = FileIdentity::from_metadata(&lock_metadata);
        validate_named_file_identity(
            &self.directory,
            CONTROLLER_LOCK_FILE_NAME,
            lock_identity,
            ControllerFileStage::ValidateLockIdentity,
        )
        .map_err(|error| {
            self.state = ControllerStoreState::Stopped;
            ControllerStoreError::Open(error)
        })?;
        Ok(ControllerStoreCutoverIdentity {
            directory_device: self.directory.identity.device,
            directory_inode: self.directory.identity.inode,
            lock_device: lock_identity.device,
            lock_inode: lock_identity.inode,
        })
    }

    pub(crate) fn commit(
        &mut self,
        next: ControllerJournalSnapshot,
    ) -> Result<(), ControllerStoreError> {
        self.commit_with_failpoint(next, ControllerCommitFailpoint::None)
    }

    #[cfg(test)]
    pub(crate) fn commit_with_test_failpoint(
        &mut self,
        next: ControllerJournalSnapshot,
        failpoint: ControllerCommitFailpoint,
    ) -> Result<(), ControllerStoreError> {
        self.commit_with_failpoint(next, failpoint)
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
        let active_identity = read_active_controller_snapshot_bytes(&self.directory)
            .map_err(|error| {
                self.state = ControllerStoreState::Stopped;
                ControllerStoreError::Open(error)
            })?
            .identity;
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
            ControllerPublishMode::ReplaceExisting(active_identity),
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

fn runtime_observation_endpoint_ref_for_target(
    target: RuntimeHostId,
    predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
    observation_endpoint_refs: [RuntimeObservationEndpointRefV1; 2],
) -> Result<RuntimeObservationEndpointRefV1, ControllerDistributedAgentStackError> {
    if target == predecessors[0].target() {
        Ok(observation_endpoint_refs[0])
    } else if target == predecessors[1].target() {
        Ok(observation_endpoint_refs[1])
    } else {
        Err(ControllerDistributedAgentStackError::CrossBindingMismatch)
    }
}

fn validate_migration_inputs(
    expected_store_instance_id: [u8; 32],
    expected_owner_identity: ControllerOwnerIdentityFingerprint,
    migration_id: [u8; 32],
) -> Result<(), ControllerStoreMigrationError> {
    if expected_store_instance_id.iter().all(|byte| *byte == 0) {
        return Err(ControllerStoreMigrationError::InvalidExpectedStoreIdentity);
    }
    if expected_owner_identity
        .value()
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(ControllerStoreMigrationError::InvalidExpectedOwnerIdentity);
    }
    if migration_id.iter().all(|byte| *byte == 0) {
        return Err(ControllerStoreMigrationError::InvalidMigrationId);
    }
    Ok(())
}

fn acquire_controller_migration_guard(
    path: &Path,
    filesystem_policy: ControllerFilesystemPolicy,
) -> Result<ControllerMigrationGuard, ControllerStoreMigrationError> {
    let directory = open_controller_directory(path, filesystem_policy)
        .map_err(ControllerStoreMigrationError::Store)?;
    let lock_file = open_existing_regular(
        &directory,
        CONTROLLER_LOCK_FILE_NAME,
        OFlag::O_RDWR,
        ControllerFileStage::OpenLock,
    )
    .map_err(ControllerStoreMigrationError::Store)?;
    let lock_identity = FileIdentity::from_metadata(&lock_file.metadata().map_err(|error| {
        ControllerStoreMigrationError::Store(ControllerStoreOpenError::Io(
            ControllerIoFailure::new(ControllerFileStage::OpenLock, &error),
        ))
    })?);
    lock_file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => ControllerStoreMigrationError::LockContended,
        TryLockError::Error(error) => {
            ControllerStoreMigrationError::Store(ControllerStoreOpenError::Io(
                ControllerIoFailure::new(ControllerFileStage::AcquireLock, &error),
            ))
        }
    })?;
    validate_named_file_identity(
        &directory,
        CONTROLLER_LOCK_FILE_NAME,
        lock_identity,
        ControllerFileStage::ValidateLockIdentity,
    )
    .map_err(ControllerStoreMigrationError::Store)?;
    Ok(ControllerMigrationGuard {
        directory,
        lock_file,
        lock_identity,
    })
}

fn validate_controller_directory_handle(
    directory: &ControllerDirectoryHandle,
) -> Result<(), ControllerStoreOpenError> {
    let metadata = directory.file.metadata().map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::ValidateDirectoryIdentity,
            &error,
        ))
    })?;
    validate_directory_metadata(&metadata, directory.owner_uid, directory.owner_gid)?;
    if FileIdentity::from_metadata(&metadata) != directory.identity {
        return Err(ControllerStoreOpenError::DirectoryIdentityChanged);
    }
    Ok(())
}

fn validate_migration_handles(
    guard: &ControllerMigrationGuard,
    evidence_directory: &ControllerDirectoryHandle,
) -> Result<(), ControllerStoreMigrationError> {
    validate_controller_directory_handle(&guard.directory)
        .map_err(ControllerStoreMigrationError::Store)?;
    let lock_metadata = guard.lock_file.metadata().map_err(|error| {
        ControllerStoreMigrationError::Store(ControllerStoreOpenError::Io(
            ControllerIoFailure::new(ControllerFileStage::ValidateLockIdentity, &error),
        ))
    })?;
    validate_regular_file(
        &lock_metadata,
        guard.directory.owner_uid,
        guard.directory.owner_gid,
    )
    .map_err(ControllerStoreMigrationError::Store)?;
    if FileIdentity::from_metadata(&lock_metadata) != guard.lock_identity {
        return Err(ControllerStoreMigrationError::Store(
            ControllerStoreOpenError::NamedFileIdentityChanged,
        ));
    }
    validate_named_file_identity(
        &guard.directory,
        CONTROLLER_LOCK_FILE_NAME,
        guard.lock_identity,
        ControllerFileStage::ValidateLockIdentity,
    )
    .map_err(ControllerStoreMigrationError::Store)?;
    validate_controller_directory_handle(evidence_directory)
        .map_err(ControllerStoreMigrationError::EvidenceDirectory)
}

fn validate_migration_source_identity(
    source: &ControllerJournalPayloadV7Migration,
    request: ControllerMigrationRequest<'_>,
) -> Result<(), ControllerStoreMigrationError> {
    if source.source_store_instance_id() != &request.expected_store_instance_id {
        return Err(ControllerStoreMigrationError::StoreInstanceMismatch);
    }
    if source.source_owner_identity_fingerprint() != request.expected_owner_identity {
        return Err(ControllerStoreMigrationError::OwnerIdentityMismatch);
    }
    Ok(())
}

fn validate_payload_v8_migration_source_identity(
    source: &ControllerJournalPayloadV8Migration,
    request: ControllerMigrationRequest<'_>,
) -> Result<(), ControllerStoreMigrationError> {
    if source.source_store_instance_id() != &request.expected_store_instance_id {
        return Err(ControllerStoreMigrationError::StoreInstanceMismatch);
    }
    if source.source_owner_identity_fingerprint() != request.expected_owner_identity {
        return Err(ControllerStoreMigrationError::OwnerIdentityMismatch);
    }
    Ok(())
}

fn validate_migration_target_identity(
    target: &ControllerJournalSnapshot,
    request: ControllerMigrationRequest<'_>,
) -> Result<(), ControllerStoreMigrationError> {
    if target.store_instance_id() != &request.expected_store_instance_id {
        return Err(ControllerStoreMigrationError::StoreInstanceMismatch);
    }
    if target.owner_identity_fingerprint() != request.expected_owner_identity {
        return Err(ControllerStoreMigrationError::OwnerIdentityMismatch);
    }
    Ok(())
}

fn resume_completed_controller_migration(
    guard: &ControllerMigrationGuard,
    evidence_directory: &ControllerDirectoryHandle,
    request: ControllerMigrationRequest<'_>,
    active: ActiveSnapshotBytes,
    target: ControllerJournalSnapshot,
) -> Result<ControllerStoreMigrationOutcome, ControllerStoreMigrationError> {
    validate_migration_target_identity(&target, request)?;
    let target_wire = target
        .encode_payload_v8_for_migration()
        .map_err(ControllerStoreMigrationError::Journal)?;
    if target_wire.as_ref() != active.encoded {
        return Err(ControllerStoreMigrationError::TargetMismatch);
    }
    clean_controller_migration_evidence_temps(evidence_directory, request.migration_id)
        .map_err(|_| published_but_unverified(ControllerFileStage::InspectMigrationEvidence))?;
    let (source_wire, stored_receipt) =
        read_controller_migration_evidence(evidence_directory, request.migration_id).map_err(
            |_| published_but_unverified(ControllerFileStage::ReadBackMigrationEvidence),
        )?;
    let source = ControllerJournalSnapshot::migrate_payload_v7_with_metadata(&source_wire)
        .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackMigrationEvidence))?;
    validate_migration_source_identity(&source, request)
        .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackMigrationEvidence))?;
    if source.snapshot() != &target {
        return Err(published_but_unverified(
            ControllerFileStage::ReadBackPublished,
        ));
    }
    let expected_receipt = ControllerStoreMigrationReceipt::try_new(
        request.migration_id,
        &source,
        &source_wire,
        &target,
        &target_wire,
    )
    .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackMigrationEvidence))?;
    if stored_receipt != expected_receipt {
        return Err(published_but_unverified(
            ControllerFileStage::ReadBackMigrationEvidence,
        ));
    }
    validate_migration_handles(guard, evidence_directory)
        .map_err(|_| published_but_unverified(ControllerFileStage::VerifyPublishedMigration))?;
    clean_valid_orphan_temps(&guard.directory)
        .map_err(|_| published_but_unverified(ControllerFileStage::VerifyPublishedMigration))?;
    let revalidated = read_active_controller_snapshot_bytes(&guard.directory)
        .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackPublished))?;
    if revalidated.identity != active.identity || revalidated.encoded != active.encoded {
        return Err(published_but_unverified(
            ControllerFileStage::ReadBackPublished,
        ));
    }
    Ok(ControllerStoreMigrationOutcome {
        disposition: ControllerStoreMigrationDisposition::AlreadyMigrated,
        receipt: stored_receipt,
    })
}

fn publish_controller_migration(
    guard: &ControllerMigrationGuard,
    evidence_directory: &ControllerDirectoryHandle,
    request: ControllerMigrationRequest<'_>,
    active: ActiveSnapshotBytes,
    source: ControllerJournalPayloadV7Migration,
    failpoints: ControllerMigrationFailpoints,
) -> Result<ControllerStoreMigrationOutcome, ControllerStoreMigrationError> {
    validate_migration_source_identity(&source, request)?;
    let target_wire = source
        .snapshot()
        .encode_payload_v8_for_migration()
        .map_err(ControllerStoreMigrationError::Journal)?;
    let target = ControllerJournalSnapshot::migrate_payload_v8(&target_wire)
        .map_err(ControllerStoreMigrationError::Journal)?;
    validate_migration_target_identity(&target, request)?;
    let receipt = ControllerStoreMigrationReceipt::try_new(
        request.migration_id,
        &source,
        &active.encoded,
        &target,
        &target_wire,
    )?;

    clean_valid_orphan_temps(&guard.directory).map_err(ControllerStoreMigrationError::Store)?;
    clean_controller_migration_evidence_temps(evidence_directory, request.migration_id)?;
    ensure_read_only_migration_evidence(
        evidence_directory,
        request.migration_id,
        &migration_source_file_name(request.migration_id),
        &active.encoded,
        MigrationEvidenceKind::Source,
        migration_random_token()?,
        failpoints.source_evidence,
    )?;
    ensure_read_only_migration_evidence(
        evidence_directory,
        request.migration_id,
        &migration_receipt_file_name(request.migration_id),
        receipt.canonical_wire(),
        MigrationEvidenceKind::Receipt,
        migration_random_token()?,
        failpoints.receipt_evidence,
    )?;
    let (stored_source, stored_receipt) =
        read_controller_migration_evidence(evidence_directory, request.migration_id).map_err(
            |_| uncertain_migration_evidence(ControllerFileStage::ReadBackMigrationEvidence),
        )?;
    if stored_source != active.encoded || stored_receipt != receipt {
        return Err(uncertain_migration_evidence(
            ControllerFileStage::ReadBackMigrationEvidence,
        ));
    }

    validate_migration_handles(guard, evidence_directory)?;
    let current = read_active_controller_snapshot_bytes(&guard.directory)
        .map_err(ControllerStoreMigrationError::Store)?;
    if current.identity != active.identity || current.encoded != active.encoded {
        return Err(ControllerStoreMigrationError::TargetMismatch);
    }
    publish_controller_snapshot(
        &guard.directory,
        &target_wire,
        migration_random_token()?,
        ControllerPublishMode::ReplaceExisting(active.identity),
        failpoints.active_snapshot,
    )
    .map_err(ControllerStoreMigrationError::Publish)?;
    let published = read_active_controller_snapshot_bytes(&guard.directory)
        .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackPublished))?;
    if published.encoded != target_wire.as_ref() {
        return Err(published_but_unverified(
            ControllerFileStage::ReadBackPublished,
        ));
    }
    ControllerJournalSnapshot::migrate_payload_v8(&published.encoded)
        .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackPublished))?;
    validate_migration_handles(guard, evidence_directory)
        .map_err(|_| published_but_unverified(ControllerFileStage::VerifyPublishedMigration))?;
    let (post_source, post_receipt) =
        read_controller_migration_evidence(evidence_directory, request.migration_id)
            .map_err(|_| published_but_unverified(ControllerFileStage::VerifyPublishedMigration))?;
    if post_source != active.encoded || post_receipt != receipt {
        return Err(published_but_unverified(
            ControllerFileStage::VerifyPublishedMigration,
        ));
    }
    Ok(ControllerStoreMigrationOutcome {
        disposition: ControllerStoreMigrationDisposition::Migrated,
        receipt,
    })
}

fn resume_completed_payload_v8_controller_migration(
    guard: &ControllerMigrationGuard,
    evidence_directory: &ControllerDirectoryHandle,
    request: ControllerMigrationRequest<'_>,
    active: ActiveSnapshotBytes,
    target: ControllerJournalSnapshot,
) -> Result<ControllerStoreMigrationOutcome, ControllerStoreMigrationError> {
    validate_migration_target_identity(&target, request)?;
    let target_wire = target
        .encode()
        .map_err(ControllerStoreMigrationError::Journal)?;
    if target_wire.as_ref() != active.encoded {
        return Err(ControllerStoreMigrationError::TargetMismatch);
    }
    clean_controller_migration_evidence_temps(evidence_directory, request.migration_id)
        .map_err(|_| published_but_unverified(ControllerFileStage::InspectMigrationEvidence))?;
    let (source_wire, stored_receipt) =
        read_payload_v8_controller_migration_evidence(evidence_directory, request.migration_id)
            .map_err(|_| {
                published_but_unverified(ControllerFileStage::ReadBackMigrationEvidence)
            })?;
    let source = ControllerJournalSnapshot::migrate_payload_v8_with_metadata(&source_wire)
        .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackMigrationEvidence))?;
    validate_payload_v8_migration_source_identity(&source, request)
        .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackMigrationEvidence))?;
    if source.snapshot() != &target {
        return Err(published_but_unverified(
            ControllerFileStage::ReadBackPublished,
        ));
    }
    let expected_receipt = ControllerStoreMigrationReceipt::try_new_payload_v8(
        request.migration_id,
        &source,
        &source_wire,
        &target,
        &target_wire,
    )
    .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackMigrationEvidence))?;
    if stored_receipt != expected_receipt {
        return Err(published_but_unverified(
            ControllerFileStage::ReadBackMigrationEvidence,
        ));
    }
    validate_migration_handles(guard, evidence_directory)
        .map_err(|_| published_but_unverified(ControllerFileStage::VerifyPublishedMigration))?;
    clean_valid_orphan_temps(&guard.directory)
        .map_err(|_| published_but_unverified(ControllerFileStage::VerifyPublishedMigration))?;
    let revalidated = read_active_controller_snapshot_bytes(&guard.directory)
        .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackPublished))?;
    if revalidated.identity != active.identity || revalidated.encoded != active.encoded {
        return Err(published_but_unverified(
            ControllerFileStage::ReadBackPublished,
        ));
    }
    Ok(ControllerStoreMigrationOutcome {
        disposition: ControllerStoreMigrationDisposition::AlreadyMigrated,
        receipt: stored_receipt,
    })
}

fn publish_payload_v8_controller_migration(
    guard: &ControllerMigrationGuard,
    evidence_directory: &ControllerDirectoryHandle,
    request: ControllerMigrationRequest<'_>,
    active: ActiveSnapshotBytes,
    source: ControllerJournalPayloadV8Migration,
    failpoints: ControllerMigrationFailpoints,
) -> Result<ControllerStoreMigrationOutcome, ControllerStoreMigrationError> {
    validate_payload_v8_migration_source_identity(&source, request)?;
    let target_wire = source
        .snapshot()
        .encode()
        .map_err(ControllerStoreMigrationError::Journal)?;
    let target = ControllerJournalSnapshot::decode(&target_wire)
        .map_err(ControllerStoreMigrationError::Journal)?;
    validate_migration_target_identity(&target, request)?;
    let receipt = ControllerStoreMigrationReceipt::try_new_payload_v8(
        request.migration_id,
        &source,
        &active.encoded,
        &target,
        &target_wire,
    )?;

    clean_valid_orphan_temps(&guard.directory).map_err(ControllerStoreMigrationError::Store)?;
    clean_controller_migration_evidence_temps(evidence_directory, request.migration_id)?;
    ensure_read_only_migration_evidence(
        evidence_directory,
        request.migration_id,
        &payload_v8_migration_source_file_name(request.migration_id),
        &active.encoded,
        MigrationEvidenceKind::Source,
        migration_random_token()?,
        failpoints.source_evidence,
    )?;
    ensure_read_only_migration_evidence(
        evidence_directory,
        request.migration_id,
        &payload_v8_migration_receipt_file_name(request.migration_id),
        receipt.canonical_wire(),
        MigrationEvidenceKind::Receipt,
        migration_random_token()?,
        failpoints.receipt_evidence,
    )?;
    let (stored_source, stored_receipt) =
        read_payload_v8_controller_migration_evidence(evidence_directory, request.migration_id)
            .map_err(|_| {
                uncertain_migration_evidence(ControllerFileStage::ReadBackMigrationEvidence)
            })?;
    if stored_source != active.encoded || stored_receipt != receipt {
        return Err(uncertain_migration_evidence(
            ControllerFileStage::ReadBackMigrationEvidence,
        ));
    }

    validate_migration_handles(guard, evidence_directory)?;
    let current = read_active_controller_snapshot_bytes(&guard.directory)
        .map_err(ControllerStoreMigrationError::Store)?;
    if current.identity != active.identity || current.encoded != active.encoded {
        return Err(ControllerStoreMigrationError::TargetMismatch);
    }
    publish_controller_snapshot(
        &guard.directory,
        &target_wire,
        migration_random_token()?,
        ControllerPublishMode::ReplaceExisting(active.identity),
        failpoints.active_snapshot,
    )
    .map_err(ControllerStoreMigrationError::Publish)?;
    let published = read_active_controller_snapshot_bytes(&guard.directory)
        .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackPublished))?;
    if published.encoded != target_wire.as_ref() {
        return Err(published_but_unverified(
            ControllerFileStage::ReadBackPublished,
        ));
    }
    ControllerJournalSnapshot::decode(&published.encoded)
        .map_err(|_| published_but_unverified(ControllerFileStage::ReadBackPublished))?;
    validate_migration_handles(guard, evidence_directory)
        .map_err(|_| published_but_unverified(ControllerFileStage::VerifyPublishedMigration))?;
    let (post_source, post_receipt) =
        read_payload_v8_controller_migration_evidence(evidence_directory, request.migration_id)
            .map_err(|_| published_but_unverified(ControllerFileStage::VerifyPublishedMigration))?;
    if post_source != active.encoded || post_receipt != receipt {
        return Err(published_but_unverified(
            ControllerFileStage::VerifyPublishedMigration,
        ));
    }
    Ok(ControllerStoreMigrationOutcome {
        disposition: ControllerStoreMigrationDisposition::Migrated,
        receipt,
    })
}

fn migration_random_token()
-> Result<[u8; CONTROLLER_TEMP_TOKEN_BYTES], ControllerStoreMigrationError> {
    system_random_token().map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::GenerateMigrationEvidenceTempName,
            &error,
        ))
    })
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

fn payload_v8_migration_source_file_name(migration_id: [u8; 32]) -> String {
    let mut name = String::with_capacity(
        PAYLOAD_V8_MIGRATION_SOURCE_FILE_PREFIX.len() + 64 + MIGRATION_SOURCE_FILE_SUFFIX.len(),
    );
    name.push_str(PAYLOAD_V8_MIGRATION_SOURCE_FILE_PREFIX);
    append_lower_hex(&mut name, &migration_id);
    name.push_str(MIGRATION_SOURCE_FILE_SUFFIX);
    name
}

fn payload_v8_migration_receipt_file_name(migration_id: [u8; 32]) -> String {
    let mut name = String::with_capacity(
        PAYLOAD_V8_MIGRATION_RECEIPT_FILE_PREFIX.len() + 64 + MIGRATION_RECEIPT_FILE_SUFFIX.len(),
    );
    name.push_str(PAYLOAD_V8_MIGRATION_RECEIPT_FILE_PREFIX);
    append_lower_hex(&mut name, &migration_id);
    name.push_str(MIGRATION_RECEIPT_FILE_SUFFIX);
    name
}

fn migration_evidence_temp_prefix(migration_id: [u8; 32]) -> String {
    let mut prefix = String::with_capacity(MIGRATION_EVIDENCE_TEMP_PREFIX.len() + 65);
    prefix.push_str(MIGRATION_EVIDENCE_TEMP_PREFIX);
    append_lower_hex(&mut prefix, &migration_id);
    prefix.push('-');
    prefix
}

fn migration_evidence_temp_name(
    migration_id: [u8; 32],
    kind: MigrationEvidenceKind,
    token: [u8; CONTROLLER_TEMP_TOKEN_BYTES],
) -> String {
    let label = match kind {
        MigrationEvidenceKind::Source => "source-",
        MigrationEvidenceKind::Receipt => "receipt-",
    };
    let mut name = migration_evidence_temp_prefix(migration_id);
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

fn clean_controller_migration_evidence_temps(
    directory: &ControllerDirectoryHandle,
    migration_id: [u8; 32],
) -> Result<(), ControllerStoreMigrationError> {
    let expected_prefix = migration_evidence_temp_prefix(migration_id);
    let mut entries = duplicate_directory_stream(directory)
        .map_err(ControllerStoreMigrationError::EvidenceDirectory)?;
    let mut orphan_names = Vec::new();
    let mut total_entries = 0_usize;
    for entry in entries.iter() {
        let entry = entry.map_err(|error| {
            ControllerStoreMigrationError::EvidenceIo(nix_failure(
                ControllerFileStage::InspectMigrationEvidence,
                error,
            ))
        })?;
        let name_bytes = entry.file_name().to_bytes();
        if is_dot_entry(name_bytes) {
            continue;
        }
        total_entries = total_entries
            .checked_add(1)
            .ok_or(ControllerStoreMigrationError::TooManyEvidenceDirectoryEntries)?;
        if total_entries > MAX_MIGRATION_EVIDENCE_DIRECTORY_ENTRIES {
            return Err(ControllerStoreMigrationError::TooManyEvidenceDirectoryEntries);
        }
        if !name_bytes.starts_with(expected_prefix.as_bytes()) {
            continue;
        }
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| ControllerStoreMigrationError::UnknownEvidenceEntry)?;
        if !valid_migration_evidence_temp_name(name, migration_id) {
            return Err(ControllerStoreMigrationError::UnknownEvidenceEntry);
        }
        orphan_names.push(name.to_owned());
        if orphan_names.len() > MAX_MIGRATION_EVIDENCE_ORPHAN_TEMPS {
            return Err(ControllerStoreMigrationError::TooManyEvidenceTemps);
        }
    }
    let mut validated = Vec::with_capacity(orphan_names.len());
    for name in orphan_names {
        let (file, identity) = open_migration_evidence_temp(directory, &name)?;
        validate_named_migration_evidence_temp_identity(directory, &name, identity)?;
        validated.push((name, file));
    }
    for (name, file) in validated {
        unlinkat(&directory.file, name.as_str(), UnlinkatFlags::NoRemoveDir).map_err(|error| {
            ControllerStoreMigrationError::EvidenceIo(nix_failure(
                ControllerFileStage::InspectMigrationEvidence,
                error,
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
                ControllerFileStage::InspectMigrationEvidence,
                &error,
            ))
        })?;
        if metadata.nlink() != 0 {
            return Err(ControllerStoreMigrationError::EvidenceChangedDuringRead);
        }
    }
    directory.file.sync_all().map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::SyncMigrationEvidenceDirectory,
            &error,
        ))
    })
}

fn open_migration_evidence_temp(
    directory: &ControllerDirectoryHandle,
    name: &str,
) -> Result<(File, FileIdentity), ControllerStoreMigrationError> {
    let owned = openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(nix_failure(
            ControllerFileStage::InspectMigrationEvidence,
            error,
        ))
    })?;
    let file = File::from(owned);
    let metadata = file.metadata().map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::InspectMigrationEvidence,
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
) -> Result<(), ControllerStoreMigrationError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(ControllerStoreMigrationError::UnsafeEvidenceFile);
    }
    if metadata.uid() != owner_uid || metadata.gid() != owner_gid {
        return Err(ControllerStoreMigrationError::EvidenceOwnerMismatch);
    }
    let mode = metadata.mode() & PRIVATE_FILE_MODE_MASK;
    if mode != PRIVATE_FILE_MODE_BITS && mode != READ_ONLY_EVIDENCE_MODE_BITS {
        return Err(ControllerStoreMigrationError::UnsafeEvidenceMode);
    }
    Ok(())
}

fn validate_named_migration_evidence_temp_identity(
    directory: &ControllerDirectoryHandle,
    name: &str,
    expected: FileIdentity,
) -> Result<(), ControllerStoreMigrationError> {
    let (file, identity) = open_migration_evidence_temp(directory, name)?;
    drop(file);
    if identity != expected {
        return Err(ControllerStoreMigrationError::EvidenceChangedDuringRead);
    }
    Ok(())
}

fn ensure_read_only_migration_evidence(
    directory: &ControllerDirectoryHandle,
    migration_id: [u8; 32],
    final_name: &str,
    bytes: &[u8],
    kind: MigrationEvidenceKind,
    token: [u8; CONTROLLER_TEMP_TOKEN_BYTES],
    failpoint: ControllerMigrationEvidenceFailpoint,
) -> Result<(), ControllerStoreMigrationError> {
    match read_read_only_migration_evidence(directory, final_name, bytes.len()) {
        Ok(existing) => {
            if existing != bytes {
                return Err(ControllerStoreMigrationError::EvidenceMismatch);
            }
            validate_controller_directory_handle(directory)
                .map_err(ControllerStoreMigrationError::EvidenceDirectory)?;
            directory.file.sync_all().map_err(|error| {
                ControllerStoreMigrationError::EvidencePublish(
                    ControllerPublishFailure::UncertainAfterPublish(ControllerPublishFault::io(
                        ControllerFileStage::SyncMigrationEvidenceDirectory,
                        &error,
                    )),
                )
            })?;
            let durable = read_read_only_migration_evidence(directory, final_name, bytes.len())
                .map_err(|_| {
                    uncertain_migration_evidence(ControllerFileStage::ReadBackMigrationEvidence)
                })?;
            return if durable == bytes {
                Ok(())
            } else {
                Err(uncertain_migration_evidence(
                    ControllerFileStage::ReadBackMigrationEvidence,
                ))
            };
        }
        Err(ControllerStoreMigrationError::EvidenceMissing) => {}
        Err(error) => return Err(error),
    }
    let temp_name = migration_evidence_temp_name(migration_id, kind, token);
    let owned = openat(
        &directory.file,
        temp_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(nix_failure(
            ControllerFileStage::CreateMigrationEvidenceTemp,
            error,
        ))
    })?;
    let mut temp = File::from(owned);
    temp.write_all(bytes).map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::WriteMigrationEvidenceTemp,
            &error,
        ))
    })?;
    fchmod(&temp, READ_ONLY_EVIDENCE_MODE).map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(nix_failure(
            ControllerFileStage::InspectMigrationEvidence,
            error,
        ))
    })?;
    let metadata = temp.metadata().map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::InspectMigrationEvidence,
            &error,
        ))
    })?;
    validate_read_only_evidence_metadata(&metadata, directory.owner_uid, directory.owner_gid)?;
    temp.sync_all().map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::SyncMigrationEvidenceTemp,
            &error,
        ))
    })?;
    validate_controller_directory_handle(directory)
        .map_err(ControllerStoreMigrationError::EvidenceDirectory)?;
    ensure_migration_evidence_missing(directory, final_name)?;
    publish_migration_evidence_temp(directory, &temp_name, final_name)?;
    if failpoint == ControllerMigrationEvidenceFailpoint::AfterRenameBeforeDirectorySync {
        return Err(uncertain_migration_evidence(
            ControllerFileStage::SyncMigrationEvidenceDirectory,
        ));
    }
    directory.file.sync_all().map_err(|error| {
        ControllerStoreMigrationError::EvidencePublish(
            ControllerPublishFailure::UncertainAfterPublish(ControllerPublishFault::io(
                ControllerFileStage::SyncMigrationEvidenceDirectory,
                &error,
            )),
        )
    })?;
    let read_back =
        read_read_only_migration_evidence(directory, final_name, bytes.len()).map_err(|_| {
            uncertain_migration_evidence(ControllerFileStage::ReadBackMigrationEvidence)
        })?;
    if read_back != bytes {
        return Err(uncertain_migration_evidence(
            ControllerFileStage::ReadBackMigrationEvidence,
        ));
    }
    Ok(())
}

fn publish_migration_evidence_temp(
    directory: &ControllerDirectoryHandle,
    temp_name: &str,
    final_name: &str,
) -> Result<(), ControllerStoreMigrationError> {
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
            ControllerStoreMigrationError::EvidenceIo(nix_failure(
                ControllerFileStage::RenameMigrationEvidence,
                error,
            ))
        })
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        renameat(&directory.file, temp_name, &directory.file, final_name).map_err(|error| {
            ControllerStoreMigrationError::EvidenceIo(nix_failure(
                ControllerFileStage::RenameMigrationEvidence,
                error,
            ))
        })
    }
}

fn ensure_migration_evidence_missing(
    directory: &ControllerDirectoryHandle,
    name: &str,
) -> Result<(), ControllerStoreMigrationError> {
    match openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => {
            drop(file);
            Err(ControllerStoreMigrationError::EvidenceMismatch)
        }
        Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(error) => Err(ControllerStoreMigrationError::EvidenceIo(nix_failure(
            ControllerFileStage::OpenMigrationEvidence,
            error,
        ))),
    }
}

fn read_controller_migration_evidence(
    directory: &ControllerDirectoryHandle,
    migration_id: [u8; 32],
) -> Result<(Vec<u8>, ControllerStoreMigrationReceipt), ControllerStoreMigrationError> {
    let source = read_read_only_migration_evidence(
        directory,
        &migration_source_file_name(migration_id),
        MAX_CONTROLLER_SNAPSHOT_BYTES,
    )?;
    let receipt_wire = read_read_only_migration_evidence(
        directory,
        &migration_receipt_file_name(migration_id),
        MIGRATION_RECEIPT_BYTES,
    )?;
    let receipt = ControllerStoreMigrationReceipt::decode(&receipt_wire)?;
    if receipt.receipt_version != CONTROLLER_MIGRATION_RECEIPT_VERSION
        || receipt.migration_id != migration_id
        || receipt.source_snapshot_length != source.len() as u64
        || receipt.source_snapshot_digest != migration_evidence_digest(&source)?
    {
        return Err(ControllerStoreMigrationError::EvidenceMismatch);
    }
    Ok((source, receipt))
}

fn read_payload_v8_controller_migration_evidence(
    directory: &ControllerDirectoryHandle,
    migration_id: [u8; 32],
) -> Result<(Vec<u8>, ControllerStoreMigrationReceipt), ControllerStoreMigrationError> {
    let source = read_read_only_migration_evidence(
        directory,
        &payload_v8_migration_source_file_name(migration_id),
        MAX_CONTROLLER_SNAPSHOT_BYTES,
    )?;
    let receipt_wire = read_read_only_migration_evidence(
        directory,
        &payload_v8_migration_receipt_file_name(migration_id),
        MIGRATION_RECEIPT_BYTES,
    )?;
    let receipt = ControllerStoreMigrationReceipt::decode(&receipt_wire)?;
    if receipt.receipt_version() != CONTROLLER_PAYLOAD_V8_MIGRATION_RECEIPT_VERSION
        || receipt.migration_id() != &migration_id
        || migration_evidence_digest(&source)? != receipt.source_snapshot_digest
        || u64::try_from(source.len())
            .map_err(|_| ControllerStoreMigrationError::EvidenceTooLarge)?
            != receipt.source_snapshot_length
    {
        return Err(ControllerStoreMigrationError::EvidenceMismatch);
    }
    Ok((source, receipt))
}

fn read_read_only_migration_evidence(
    directory: &ControllerDirectoryHandle,
    name: &str,
    maximum_length: usize,
) -> Result<Vec<u8>, ControllerStoreMigrationError> {
    let owned = match openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(nix::errno::Errno::ENOENT) => {
            return Err(ControllerStoreMigrationError::EvidenceMissing);
        }
        Err(error) => {
            return Err(ControllerStoreMigrationError::EvidenceIo(nix_failure(
                ControllerFileStage::OpenMigrationEvidence,
                error,
            )));
        }
    };
    let mut file = File::from(owned);
    let before = file.metadata().map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::InspectMigrationEvidence,
            &error,
        ))
    })?;
    validate_read_only_evidence_metadata(&before, directory.owner_uid, directory.owner_gid)?;
    let identity = FileIdentity::from_metadata(&before);
    let length = usize::try_from(before.len())
        .map_err(|_| ControllerStoreMigrationError::EvidenceTooLarge)?;
    if length == 0 || length > maximum_length {
        return Err(ControllerStoreMigrationError::EvidenceTooLarge);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ControllerStoreMigrationError::EvidenceAllocationFailed)?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes).map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::ReadMigrationEvidence,
            &error,
        ))
    })?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing).map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::ReadMigrationEvidence,
            &error,
        ))
    })? != 0
    {
        return Err(ControllerStoreMigrationError::EvidenceChangedDuringRead);
    }
    let after = file.metadata().map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::InspectMigrationEvidence,
            &error,
        ))
    })?;
    validate_read_only_evidence_metadata(&after, directory.owner_uid, directory.owner_gid)?;
    if FileIdentity::from_metadata(&after) != identity || after.len() != before.len() {
        return Err(ControllerStoreMigrationError::EvidenceChangedDuringRead);
    }
    validate_named_read_only_evidence_identity(directory, name, identity)?;
    Ok(bytes)
}

fn validate_read_only_evidence_metadata(
    metadata: &Metadata,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), ControllerStoreMigrationError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(ControllerStoreMigrationError::UnsafeEvidenceFile);
    }
    if metadata.uid() != owner_uid || metadata.gid() != owner_gid {
        return Err(ControllerStoreMigrationError::EvidenceOwnerMismatch);
    }
    if metadata.mode() & PRIVATE_FILE_MODE_MASK != READ_ONLY_EVIDENCE_MODE_BITS {
        return Err(ControllerStoreMigrationError::UnsafeEvidenceMode);
    }
    Ok(())
}

fn validate_named_read_only_evidence_identity(
    directory: &ControllerDirectoryHandle,
    name: &str,
    expected: FileIdentity,
) -> Result<(), ControllerStoreMigrationError> {
    let owned = openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(nix_failure(
            ControllerFileStage::OpenMigrationEvidence,
            error,
        ))
    })?;
    let file = File::from(owned);
    let metadata = file.metadata().map_err(|error| {
        ControllerStoreMigrationError::EvidenceIo(ControllerIoFailure::new(
            ControllerFileStage::InspectMigrationEvidence,
            &error,
        ))
    })?;
    validate_read_only_evidence_metadata(&metadata, directory.owner_uid, directory.owner_gid)?;
    if FileIdentity::from_metadata(&metadata) != expected {
        return Err(ControllerStoreMigrationError::EvidenceChangedDuringRead);
    }
    Ok(())
}

fn uncertain_migration_evidence(stage: ControllerFileStage) -> ControllerStoreMigrationError {
    ControllerStoreMigrationError::EvidencePublish(ControllerPublishFailure::UncertainAfterPublish(
        ControllerPublishFault::injected(stage),
    ))
}

const fn published_but_unverified(stage: ControllerFileStage) -> ControllerStoreMigrationError {
    ControllerStoreMigrationError::PublishedButUnverified(stage)
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
        identity: FileIdentity::from_metadata(&opened_metadata),
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
    let active = read_active_controller_snapshot_bytes(directory)?;
    let snapshot = ControllerJournalSnapshot::decode(&active.encoded)
        .map_err(ControllerStoreOpenError::Codec)?;
    let canonical = snapshot.encode().map_err(ControllerStoreOpenError::Codec)?;
    if canonical.as_ref() != active.encoded.as_slice() {
        return Err(ControllerStoreOpenError::NonCanonicalActiveSnapshot);
    }
    Ok(snapshot)
}

fn read_active_controller_snapshot_bytes(
    directory: &ControllerDirectoryHandle,
) -> Result<ActiveSnapshotBytes, ControllerStoreOpenError> {
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
    let identity = FileIdentity::from_metadata(&metadata);
    let after = active.metadata().map_err(|error| {
        ControllerStoreOpenError::Io(ControllerIoFailure::new(
            ControllerFileStage::ReadActive,
            &error,
        ))
    })?;
    validate_regular_file(&after, directory.owner_uid, directory.owner_gid)?;
    if FileIdentity::from_metadata(&after) != identity || after.len() != metadata.len() {
        return Err(ControllerStoreOpenError::ActiveChangedDuringRead);
    }
    validate_named_file_identity(
        directory,
        CONTROLLER_ACTIVE_FILE_NAME,
        identity,
        ControllerFileStage::ValidateActiveIdentity,
    )?;
    Ok(ActiveSnapshotBytes { encoded, identity })
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

fn validate_named_file_identity(
    directory: &ControllerDirectoryHandle,
    name: &str,
    expected: FileIdentity,
    stage: ControllerFileStage,
) -> Result<(), ControllerStoreOpenError> {
    let file = open_existing_regular(directory, name, OFlag::O_RDONLY, stage)?;
    let metadata = file
        .metadata()
        .map_err(|error| ControllerStoreOpenError::Io(ControllerIoFailure::new(stage, &error)))?;
    if FileIdentity::from_metadata(&metadata) != expected {
        return Err(ControllerStoreOpenError::NamedFileIdentityChanged);
    }
    Ok(())
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
        ControllerPublishMode::ReplaceExisting(expected) => {
            validate_named_file_identity(
                directory,
                CONTROLLER_ACTIVE_FILE_NAME,
                expected,
                ControllerFileStage::ValidateActiveIdentity,
            )
            .map_err(|error| {
                rejected_open_error(ControllerFileStage::ValidateActiveIdentity, error)
            })?;
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
    match mode {
        ControllerPublishMode::RequireMissing => ensure_active_missing(directory)?,
        ControllerPublishMode::ReplaceExisting(expected) => {
            validate_named_file_identity(
                directory,
                CONTROLLER_ACTIVE_FILE_NAME,
                expected,
                ControllerFileStage::ValidateActiveIdentity,
            )
            .map_err(|error| {
                rejected_open_error(ControllerFileStage::ValidateActiveIdentity, error)
            })?;
        }
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
    if _policy != ControllerFilesystemPolicy::ProductionReference {
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
    ReplaceExisting(FileIdentity),
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
    ValidateDirectoryIdentity,
    InspectFilesystem,
    ScanDirectory,
    CreateLock,
    SyncInitializerMarker,
    SyncInitializerMarkerDirectory,
    ValidateInitializerMarker,
    OpenLock,
    AcquireLock,
    ValidateLockIdentity,
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
    NamedFileIdentityChanged,
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

#[derive(Debug)]
pub(crate) enum ControllerDistributedAgentStackError {
    Store(ControllerStoreError),
    Journal(ControllerJournalError),
    Apply(DistributedAgentStackApplyError),
    Node(DistributedAgentStackNodeReconcileError),
    IncompleteExtension,
    CrossBindingMismatch,
}

impl fmt::Display for ControllerDistributedAgentStackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Controller distributed Agent stack extension failed: {self:?}"
        )
    }
}

impl std::error::Error for ControllerDistributedAgentStackError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerStoreMigrationError {
    InvalidExpectedStoreIdentity,
    InvalidExpectedOwnerIdentity,
    InvalidMigrationId,
    EvidenceDirectoryMatchesStore,
    LockContended,
    StoreInstanceMismatch,
    OwnerIdentityMismatch,
    Store(ControllerStoreOpenError),
    EvidenceDirectory(ControllerStoreOpenError),
    Journal(ControllerJournalError),
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
    EvidenceIo(ControllerIoFailure),
    EvidencePublish(ControllerPublishFailure),
    Publish(ControllerPublishFailure),
    PublishedButUnverified(ControllerFileStage),
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

impl fmt::Display for ControllerStoreMigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller store migration failed: {self:?}")
    }
}

impl std::error::Error for ControllerStoreMigrationError {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future::Future;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_runtime_contracts::apply::{
        PlanWriterEpoch, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
        TenureProofAuthority, WriterTenureClaim, WriterTenureProof, WriterTenureSigningTranscript,
    };
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};
    use tokio::runtime::Builder as RuntimeBuilder;

    use crate::controller_journal::{
        ControllerAuthKeyFingerprint, ControllerJournalError, ControllerJournalSnapshot,
        ControllerJournalState, ControllerOperationId, ControllerOwnerIdentityFingerprint,
        ControllerRemoteConnectorAttemptPhaseV1, ControllerRemoteConnectorRestartRequirementV1,
        ControllerRemoteConnectorStepV1, ControllerRequestAuthPin, ControllerTenurePhase,
        controller_test_manifest, refresh_controller_test_checksum,
        tests::{
            decode_frozen_base64, frozen_v7_opaque_query_wire, frozen_v7_zero_wire,
            frozen_v8_zero_target_wire, remote_node_describe_wire,
        },
    };
    use crate::controller_tenure::{
        ControllerTenureError, acquire_tenure_once_with_test_exchange,
        commit_verified_response_with_test_commit,
    };
    use crate::plan::{DeploymentId, DeploymentScopeId, DeploymentWriterRef};
    use crate::planner::{StableAllocationSnapshot, journal_test_candidate};
    use crate::tenure_client::{
        AcquireTenureExchangeError, AcquireTenureRequestToSign, PreparedAcquireTenureRequest,
        TenureClientFailure,
    };
    use crate::tenure_protocol::{
        AcquireTenureIntentV1, AcquireTenureOperationId, AcquireTenureRequestDraftV1,
        AcquireTenureResponseV1, ControllerAcquireKeyRef, ControllerPublicKeyFingerprint,
        MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES,
    };

    use super::{
        CONTROLLER_ACTIVE_FILE_NAME, CONTROLLER_LOCK_FILE_NAME, ControllerCommitFailpoint,
        ControllerFilesystemPolicy, ControllerInitializerLockFailure, ControllerPublishFailure,
        ControllerStore, ControllerStoreError, ControllerStoreMigrationDisposition,
        ControllerStoreMigrationError, ControllerStoreOpenError, LinuxMountEvidenceError,
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
            controller_test_manifest(target),
            auth(0x34, 1),
        )
        .unwrap_or_else(|error| panic!("fixture state failed: {error}"));
        ControllerJournalSnapshot::try_initialize(STORE_ID, owner(), state)
            .unwrap_or_else(|error| panic!("fixture snapshot failed: {error}"))
    }

    fn install(snapshot: &ControllerJournalSnapshot, directory: &TestDirectory) {
        let encoded = snapshot
            .encode()
            .unwrap_or_else(|error| panic!("fixture encode failed: {error}"));
        install_wire(&encoded, directory);
    }

    fn install_wire(encoded: &[u8], directory: &TestDirectory) {
        let handle = open_controller_directory(
            directory.path(),
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .unwrap_or_else(|error| panic!("fixture directory open failed: {error}"));
        ensure_fresh_controller_directory(&handle)
            .unwrap_or_else(|error| panic!("fixture directory not fresh: {error}"));
        let _lock = create_and_lock_controller_initializer_lock(&handle)
            .unwrap_or_else(|error| panic!("fixture lock failed: {error}"));
        publish_initial_controller_snapshot(
            &handle,
            encoded,
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

    fn run_async<T>(future: impl Future<Output = T>) -> T {
        RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap_or_else(|error| panic!("test runtime failed: {error}"))
            .block_on(future)
    }

    fn prepared_tenure_request(operation: u8, nonce: &[u8]) -> PreparedAcquireTenureRequest {
        let signing_key = SigningKey::from_bytes(&[0x71; 32]);
        let fingerprint = ControllerPublicKeyFingerprint::for_ed25519_key(
            &signing_key.verifying_key().to_bytes(),
        )
        .expect("Controller tenure fingerprint must validate");
        let draft = AcquireTenureRequestDraftV1::try_new(
            AcquireTenureIntentV1::new(
                DeploymentScopeId::from_bytes([0x32; 16]),
                DeploymentWriterRef::from_bytes([0x72; 16]),
                AcquireTenureOperationId::from_bytes([operation; 16]),
            ),
            PrincipalRef::from_bytes([0x73; 16]),
            ControllerAcquireKeyRef::from_bytes([0x74; 16]),
            fingerprint,
            nonce,
            u32::try_from(MAX_ACQUIRE_TENURE_RESPONSE_PAYLOAD_BYTES)
                .expect("response bound must fit"),
        )
        .expect("tenure request draft must validate");
        let to_sign =
            AcquireTenureRequestToSign::try_new(draft).expect("request must prepare for signing");
        let signature = signing_key.sign(to_sign.signing_bytes());
        to_sign
            .finalize_ed25519(&signature.to_bytes())
            .expect("signed tenure request must validate")
    }

    fn tenure_response(
        prepared: &PreparedAcquireTenureRequest,
        epoch: u64,
    ) -> AcquireTenureResponseV1 {
        let authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([0x75; 16]),
            TenureKeyRef::from_bytes([0x76; 16]),
            TenureProofAlgorithm::try_new(1).expect("proof algorithm must validate"),
            1,
        )
        .expect("proof authority must validate");
        let claim = WriterTenureClaim::try_new(
            prepared.request().proof_source_scope(),
            prepared.request().proof_writer(),
            PlanWriterEpoch::new(epoch),
            PlanWriterEpoch::new(epoch - 1),
        )
        .expect("proof claim must validate");
        let transcript = WriterTenureSigningTranscript::try_new(
            authority,
            claim,
            prepared.request().client_nonce(),
        )
        .expect("proof transcript must validate");
        let signature = SigningKey::from_bytes(&[0x77; 32]).sign(transcript.as_bytes());
        let proof = WriterTenureProof::try_new(
            authority,
            claim,
            prepared.request().client_nonce(),
            &signature.to_bytes(),
        )
        .expect("tenure proof must validate");
        AcquireTenureResponseV1::try_new(prepared.request(), proof)
            .expect("tenure response must validate")
    }

    fn active_snapshot(directory: &TestDirectory) -> ControllerJournalSnapshot {
        let bytes = fs::read(directory.path().join(CONTROLLER_ACTIVE_FILE_NAME))
            .expect("active snapshot must be readable");
        ControllerJournalSnapshot::decode(&bytes).expect("active snapshot must strictly decode")
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
            initial.state().installed_manifest().projection(),
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
        let reopened = open_fixture(&directory);
        assert_eq!(reopened.snapshot(), Ok(&next));
        assert_eq!(
            reopened
                .snapshot()
                .expect("reopened snapshot")
                .state()
                .installed_manifest(),
            initial.state().installed_manifest()
        );
    }

    #[test]
    fn remote_connector_store_commits_before_send_and_restart_only_closes_authority() {
        let directory = TestDirectory::new();
        let initial = initial_snapshot();
        install(&initial, &directory);
        let first = remote_node_describe_wire(0xb1);
        {
            let mut store = open_fixture(&directory);
            assert_eq!(
                store
                    .revalidate_remote_connector_resume_projection()
                    .expect("absent projection must validate"),
                None
            );
            store
                .initialize_remote_connector(
                    digest(0xa1),
                    RuntimeHostId::from_bytes([0x31; 16]),
                    [0xa2; 32],
                    [0xa3; 32],
                )
                .expect("remote connector identity must become durable");
            let initialized = store
                .revalidate_remote_connector_resume_projection()
                .expect("initialized projection must validate")
                .expect("remote extension must exist");
            assert!(initialized.exchanges().is_empty());
            assert_eq!(
                initialized.next_request_step(),
                Some(ControllerRemoteConnectorStepV1::NodeDescribe)
            );
            store
                .prepare_remote_connector_request(
                    ControllerRemoteConnectorStepV1::NodeDescribe,
                    &first,
                )
                .expect("request must commit before send authority exists");
            assert_eq!(
                active_snapshot(&directory).remote_connector_current_attempt(),
                Some((
                    ControllerRemoteConnectorStepV1::NodeDescribe,
                    ControllerRemoteConnectorAttemptPhaseV1::RequestDurableNotSent,
                    first.as_ref(),
                ))
            );
            let prepared = store
                .revalidate_remote_connector_resume_projection()
                .expect("prepared projection must validate")
                .expect("remote extension must exist");
            assert_eq!(prepared.exchanges().len(), 1);
            assert_eq!(
                prepared
                    .current_exchange()
                    .expect("prepared exchange")
                    .request_wire(),
                first.as_ref()
            );
            let claim = store
                .claim_remote_connector_attempt(ControllerRemoteConnectorStepV1::NodeDescribe)
                .expect("atomic claim");
            assert_eq!(claim.step(), ControllerRemoteConnectorStepV1::NodeDescribe);
            assert_eq!(claim.request_wire(), first.as_ref());
            assert_eq!(
                active_snapshot(&directory).remote_connector_current_attempt(),
                Some((
                    ControllerRemoteConnectorStepV1::NodeDescribe,
                    ControllerRemoteConnectorAttemptPhaseV1::AttemptInFlight,
                    first.as_ref(),
                ))
            );
            let in_flight = store
                .revalidate_remote_connector_resume_projection()
                .expect("in-flight projection must validate")
                .expect("remote extension must exist");
            assert_eq!(
                in_flight
                    .current_exchange()
                    .expect("in-flight exchange")
                    .phase(),
                ControllerRemoteConnectorAttemptPhaseV1::AttemptInFlight
            );
        }

        let mut restarted = open_fixture(&directory);
        let reopened = restarted
            .revalidate_remote_connector_resume_projection()
            .expect("reopened projection must validate")
            .expect("remote extension must exist");
        assert_eq!(
            reopened.restart_requirement(),
            ControllerRemoteConnectorRestartRequirementV1::RecoverInFlight(
                ControllerRemoteConnectorStepV1::NodeDescribe
            )
        );
        assert_eq!(
            restarted
                .remote_connector_restart_requirement()
                .expect("restart requirement"),
            ControllerRemoteConnectorRestartRequirementV1::RecoverInFlight(
                ControllerRemoteConnectorStepV1::NodeDescribe
            )
        );
        restarted
            .recover_remote_connector_attempt(ControllerRemoteConnectorStepV1::NodeDescribe)
            .expect("separate restart command closes old resident authority");
        let second = remote_node_describe_wire(0xb2);
        restarted
            .prepare_remote_connector_request(
                ControllerRemoteConnectorStepV1::NodeDescribe,
                &second,
            )
            .expect("fresh read-only request is a separate durable attempt");
        assert!(matches!(
            restarted.revalidate_remote_connector_cutover_ready(),
            Err(ControllerStoreError::Codec(
                ControllerJournalError::RemoteConnectorCutoverNotReady
            ))
        ));
    }

    #[test]
    fn offline_v7_and_v8_migrations_retain_exact_evidence_and_resume_exactly() {
        let directory = TestDirectory::new();
        let evidence = TestDirectory::new();
        let source_wire = frozen_v7_zero_wire();
        let expected_target_wire = frozen_v8_zero_target_wire();
        let expected_target = ControllerJournalSnapshot::migrate_payload_v8(&expected_target_wire)
            .expect("frozen v8 target must parse explicitly");
        install_wire(&source_wire, &directory);
        assert_eq!(
            ControllerStore::open_with_policy(
                directory.path(),
                STORE_ID,
                owner(),
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("normal v9 open must reject v7"),
            ControllerStoreOpenError::Codec(ControllerJournalError::UnknownPayloadVersion)
        );

        let request = super::ControllerMigrationRequest {
            directory: directory.path(),
            evidence_directory: evidence.path(),
            expected_store_instance_id: STORE_ID,
            expected_owner_identity: owner(),
            migration_id: [0x91; 32],
        };
        let migrated = ControllerStore::migrate_payload_v7_offline_with_policy(
            request,
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("v7 migration must succeed");
        assert_eq!(
            migrated.disposition,
            ControllerStoreMigrationDisposition::Migrated
        );
        assert_eq!(migrated.receipt.migration_id(), &[0x91; 32]);
        assert_eq!(
            migrated.receipt.canonical_wire().as_slice(),
            decode_frozen_base64(include_str!("testdata/controller_v7_v8_receipt.b64")).as_ref(),
            "receipt bytes are frozen against the accepted HEAD-v7 source and exact v8 target"
        );
        assert_eq!(
            fs::read(directory.path().join(CONTROLLER_ACTIVE_FILE_NAME)).expect("v8 active bytes"),
            expected_target_wire.as_ref()
        );
        let source_path = evidence
            .path()
            .join(super::migration_source_file_name([0x91; 32]));
        let receipt_path = evidence
            .path()
            .join(super::migration_receipt_file_name([0x91; 32]));
        assert_eq!(
            fs::read(&source_path).expect("source evidence"),
            source_wire.as_ref()
        );
        assert_eq!(
            fs::metadata(&source_path)
                .expect("source evidence metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o400
        );
        assert_eq!(
            fs::metadata(&receipt_path)
                .expect("receipt metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o400
        );

        let resumed = ControllerStore::migrate_payload_v7_offline_with_policy(
            request,
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("exact migration retry must resume");
        assert_eq!(
            resumed.disposition,
            ControllerStoreMigrationDisposition::AlreadyMigrated
        );
        assert_eq!(resumed.receipt, migrated.receipt);

        let v8_request = super::ControllerMigrationRequest {
            migration_id: [0x95; 32],
            ..request
        };
        let v9 = ControllerStore::migrate_payload_v8_offline_with_policy(
            v8_request,
            ControllerFilesystemPolicy::ExplicitFixture,
        )
        .expect("v8 to v9 migration must succeed");
        assert_eq!(
            v9.disposition,
            ControllerStoreMigrationDisposition::Migrated
        );
        assert_eq!(v9.receipt.receipt_version(), 2);
        assert_eq!(v9.receipt.source_payload_version(), 8);
        assert_eq!(v9.receipt.target_payload_version(), 9);
        assert_eq!(active_snapshot(&directory), expected_target);
        assert_eq!(
            ControllerStore::migrate_payload_v8_offline_with_policy(
                v8_request,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("exact v8 migration retry must resume")
            .disposition,
            ControllerStoreMigrationDisposition::AlreadyMigrated
        );
        assert!(
            evidence
                .path()
                .join(super::payload_v8_migration_source_file_name([0x95; 32]))
                .is_file()
        );
        assert!(
            evidence
                .path()
                .join(super::payload_v8_migration_receipt_file_name([0x95; 32]))
                .is_file()
        );

        let held = open_fixture(&directory);
        assert_eq!(
            ControllerStore::migrate_payload_v7_offline_with_policy(
                request,
                ControllerFilesystemPolicy::ExplicitFixture,
            ),
            Err(ControllerStoreMigrationError::LockContended)
        );
        drop(held);
    }

    #[test]
    fn offline_v7_migration_rejects_query_evidence_without_touching_active_or_evidence() {
        let directory = TestDirectory::new();
        let evidence = TestDirectory::new();
        let source_wire = frozen_v7_opaque_query_wire();
        install_wire(&source_wire, &directory);
        let active_path = directory.path().join(CONTROLLER_ACTIVE_FILE_NAME);
        let before = fs::read(&active_path).expect("legacy active bytes");
        let result = ControllerStore::migrate_payload_v7_offline_with_policy(
            super::ControllerMigrationRequest {
                directory: directory.path(),
                evidence_directory: evidence.path(),
                expected_store_instance_id: STORE_ID,
                expected_owner_identity: owner(),
                migration_id: [0x92; 32],
            },
            ControllerFilesystemPolicy::ExplicitFixture,
        );
        assert_eq!(
            result,
            Err(ControllerStoreMigrationError::Journal(
                ControllerJournalError::LegacyOpaqueQueryEvidenceUnavailable
            ))
        );
        assert_eq!(fs::read(active_path).expect("unchanged active"), before);
        assert_eq!(
            fs::read_dir(evidence.path())
                .expect("evidence directory")
                .count(),
            0,
            "rejected legacy query evidence must not produce migration authority"
        );
    }

    #[test]
    fn offline_v7_migration_retries_evidence_and_active_publish_uncertainty() {
        let evidence_uncertain_store = TestDirectory::new();
        let evidence_uncertain_audit = TestDirectory::new();
        let source = initial_snapshot();
        let source_wire = source
            .encode_payload_v7_for_test()
            .expect("legacy source wire");
        install_wire(&source_wire, &evidence_uncertain_store);
        let source_request = super::ControllerMigrationRequest {
            directory: evidence_uncertain_store.path(),
            evidence_directory: evidence_uncertain_audit.path(),
            expected_store_instance_id: STORE_ID,
            expected_owner_identity: owner(),
            migration_id: [0x93; 32],
        };
        let uncertain = ControllerStore::migrate_payload_v7_offline_with_policy_and_failpoints(
            source_request,
            ControllerFilesystemPolicy::ExplicitFixture,
            super::ControllerMigrationFailpoints {
                source_evidence:
                    super::ControllerMigrationEvidenceFailpoint::AfterRenameBeforeDirectorySync,
                receipt_evidence: super::ControllerMigrationEvidenceFailpoint::None,
                active_snapshot: ControllerCommitFailpoint::None,
            },
        );
        assert!(matches!(
            uncertain,
            Err(ControllerStoreMigrationError::EvidencePublish(
                ControllerPublishFailure::UncertainAfterPublish(_)
            ))
        ));
        assert_eq!(
            fs::read(
                evidence_uncertain_store
                    .path()
                    .join(CONTROLLER_ACTIVE_FILE_NAME)
            )
            .expect("old active after evidence uncertainty"),
            source_wire.as_ref()
        );
        assert_eq!(
            ControllerStore::migrate_payload_v7_offline_with_policy(
                source_request,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("existing exact evidence must be fsynced and resumed")
            .disposition,
            ControllerStoreMigrationDisposition::Migrated
        );

        let active_uncertain_store = TestDirectory::new();
        let active_uncertain_audit = TestDirectory::new();
        install_wire(&source_wire, &active_uncertain_store);
        let active_request = super::ControllerMigrationRequest {
            directory: active_uncertain_store.path(),
            evidence_directory: active_uncertain_audit.path(),
            expected_store_instance_id: STORE_ID,
            expected_owner_identity: owner(),
            migration_id: [0x94; 32],
        };
        let uncertain = ControllerStore::migrate_payload_v7_offline_with_policy_and_failpoints(
            active_request,
            ControllerFilesystemPolicy::ExplicitFixture,
            super::ControllerMigrationFailpoints {
                source_evidence: super::ControllerMigrationEvidenceFailpoint::None,
                receipt_evidence: super::ControllerMigrationEvidenceFailpoint::None,
                active_snapshot: ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn,
            },
        );
        assert!(matches!(
            uncertain,
            Err(ControllerStoreMigrationError::Publish(
                ControllerPublishFailure::UncertainAfterPublish(_)
            ))
        ));
        assert_eq!(
            fs::read(
                active_uncertain_store
                    .path()
                    .join(CONTROLLER_ACTIVE_FILE_NAME)
            )
            .expect("v8 active after uncertain publish"),
            source
                .encode_payload_v8_for_migration()
                .expect("exact v8 target")
                .as_ref()
        );
        assert_eq!(
            ControllerStore::migrate_payload_v7_offline_with_policy(
                active_request,
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect("exact evidence must prove uncertain active publish")
            .disposition,
            ControllerStoreMigrationDisposition::AlreadyMigrated
        );
    }

    #[test]
    fn tenure_exchange_observes_durable_prepared_and_success_replays_without_resend() {
        let directory = TestDirectory::new();
        let initial = initial_snapshot();
        install(&initial, &directory);
        let mut store = open_fixture(&directory);
        let prepared = prepared_tenure_request(0x41, b"durable-before-exchange");
        let expected_frame = prepared.frame_bytes().to_vec();
        let response = tenure_response(&prepared, 5);

        let acquired = run_async(acquire_tenure_once_with_test_exchange(
            &mut store,
            &prepared,
            |durable| {
                let disk = active_snapshot(&directory);
                let transaction = disk
                    .state()
                    .tenure_transaction(durable.request().operation_id())
                    .expect("exchange must observe the durable transaction");
                assert_eq!(transaction.phase(), ControllerTenurePhase::Prepared);
                assert_eq!(
                    transaction.request().canonical_bytes(),
                    durable.request().canonical_bytes()
                );
                assert_eq!(durable.frame_bytes(), expected_frame);
                let response = response.clone();
                async move { Ok(response) }
            },
        ))
        .expect("verified response must commit");
        assert!(!acquired.replayed_from_journal());
        assert_eq!(acquired.proof(), response.proof());

        drop(store);
        let mut reopened = open_fixture(&directory);
        let transaction = reopened
            .snapshot()
            .expect("reopened store must remain operational")
            .state()
            .tenure_transaction(prepared.request().operation_id())
            .expect("committed tenure must survive restart");
        assert_eq!(transaction.phase(), ControllerTenurePhase::Committed);
        assert_eq!(transaction.response(), Some(&response));
        let replayed = run_async(acquire_tenure_once_with_test_exchange(
            &mut reopened,
            &prepared,
            |_| async { panic!("committed exact replay must not exchange again") },
        ))
        .expect("committed exact replay must return the journal proof");
        assert!(replayed.replayed_from_journal());
        assert_eq!(replayed.proof(), response.proof());
    }

    #[test]
    fn tenure_not_sent_stays_prepared_and_uncertain_is_durable_with_exact_restart_frame() {
        for (operation, nonce, exchange_error, expected_phase) in [
            (
                0x42,
                b"not-sent-tenure".as_slice(),
                AcquireTenureExchangeError::NotSent(TenureClientFailure::SocketMetadataUnavailable),
                ControllerTenurePhase::Prepared,
            ),
            (
                0x43,
                b"uncertain-tenure".as_slice(),
                AcquireTenureExchangeError::Uncertain(TenureClientFailure::TruncatedResponse),
                ControllerTenurePhase::Uncertain,
            ),
        ] {
            let directory = TestDirectory::new();
            let initial = initial_snapshot();
            install(&initial, &directory);
            let mut store = open_fixture(&directory);
            let prepared = prepared_tenure_request(operation, nonce);
            let expected_frame = prepared.frame_bytes().to_vec();
            let result = run_async(acquire_tenure_once_with_test_exchange(
                &mut store,
                &prepared,
                |_| async move { Err(exchange_error) },
            ));
            assert_eq!(result, Err(ControllerTenureError::Exchange(exchange_error)));

            drop(store);
            let reopened = open_fixture(&directory);
            let transaction = reopened
                .snapshot()
                .expect("reopened store must remain operational")
                .state()
                .tenure_transaction(prepared.request().operation_id())
                .expect("tenure transaction must survive restart");
            assert_eq!(transaction.phase(), expected_phase);
            let recovered = PreparedAcquireTenureRequest::try_from_canonical_request_bytes(
                transaction.request().canonical_bytes(),
            )
            .expect("restart must reconstruct the exact prepared request");
            assert_eq!(recovered.request(), prepared.request());
            assert_eq!(recovered.frame_bytes(), expected_frame);
        }
    }

    #[test]
    fn verified_response_publish_failures_preserve_typed_ambiguity_and_restart_truth() {
        for (operation, nonce, failpoint, expected_phase) in [
            (
                0x44,
                b"verified-before-rename".as_slice(),
                ControllerCommitFailpoint::BeforeRename,
                ControllerTenurePhase::Prepared,
            ),
            (
                0x45,
                b"verified-after-directory-sync".as_slice(),
                ControllerCommitFailpoint::AfterDirectorySyncBeforeReturn,
                ControllerTenurePhase::Committed,
            ),
        ] {
            let directory = TestDirectory::new();
            let initial = initial_snapshot();
            install(&initial, &directory);
            let mut store = open_fixture(&directory);
            let prepared = prepared_tenure_request(operation, nonce);
            let prepared_state = store
                .snapshot()
                .expect("store must be operational")
                .state()
                .prepare_tenure_acquisition(
                    prepared.request(),
                    crate::controller_journal::ControllerTenureAuthorityDomainFingerprint::from_stored(
                        Digest32::from_bytes([0xa5; 32]),
                    ),
                )
                .expect("tenure request must prepare");
            let prepared_snapshot = store
                .snapshot()
                .expect("store must be operational")
                .try_successor(prepared_state)
                .expect("Prepared must be a valid successor");
            store
                .commit(prepared_snapshot)
                .expect("Prepared must be durable before simulated success");
            let response = tenure_response(&prepared, 5);

            let result = commit_verified_response_with_test_commit(
                &mut store,
                prepared.request(),
                &response,
                |store, next| store.commit_with_failpoint(next, failpoint),
            );
            assert!(matches!(
                result,
                Err(ControllerTenureError::VerifiedResponsePersistence {
                    response_digest,
                    store: ControllerStoreError::Publish(_),
                }) if response_digest == response.response_digest()
            ));
            assert_eq!(store.snapshot(), Err(ControllerStoreError::Stopped));

            drop(store);
            let mut reopened = open_fixture(&directory);
            assert_eq!(
                reopened
                    .snapshot()
                    .expect("restart must resolve publish truth")
                    .state()
                    .tenure_transaction(prepared.request().operation_id())
                    .expect("tenure transaction must survive restart")
                    .phase(),
                expected_phase
            );
            let replay = run_async(acquire_tenure_once_with_test_exchange(
                &mut reopened,
                &prepared,
                |durable| {
                    assert_eq!(durable.frame_bytes(), prepared.frame_bytes());
                    let response = response.clone();
                    async move { Ok(response) }
                },
            ))
            .expect("restart must replay Prepared or return Committed exactly");
            assert_eq!(replay.proof(), response.proof());
            assert_eq!(
                replay.replayed_from_journal(),
                expected_phase == ControllerTenurePhase::Committed
            );
        }
    }

    #[test]
    fn restart_file_read_rejects_a_checksum_valid_but_invalid_manifest_pin() {
        let directory = TestDirectory::new();
        let initial = initial_snapshot();
        install(&initial, &directory);

        let mut encoded = initial
            .encode()
            .expect("fixture snapshot must encode")
            .to_vec();
        let manifest = initial
            .state()
            .installed_manifest()
            .canonical_manifest_wire();
        let offset = encoded
            .windows(manifest.len())
            .position(|window| window == manifest)
            .expect("installed manifest must be in the active snapshot");
        encoded[offset + manifest.len() - 1] ^= 1;
        refresh_controller_test_checksum(&mut encoded)
            .expect("forged fixture checksum must rebuild");
        fs::write(directory.path().join(CONTROLLER_ACTIVE_FILE_NAME), encoded)
            .expect("forged active snapshot write");

        assert_eq!(
            ControllerStore::open_with_policy(
                directory.path(),
                STORE_ID,
                owner(),
                ControllerFilesystemPolicy::ExplicitFixture,
            )
            .expect_err("restart must strictly decode the installed manifest pin"),
            ControllerStoreOpenError::Codec(
                crate::controller_journal::ControllerJournalError::InvalidInstalledManifestPin
            )
        );
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
