//! Durable single-writer state for one already-authorized NodeDaemon tenure.
//!
//! This module does not acquire a registration tenure, generate a
//! NodeIncarnation, observe a RuntimeHost, or serve a network transport.  The
//! caller supplies an exact current registration coordinate.  The store only
//! makes the owner reducer's monotonic fences and last immutable publication
//! survive a same-tenure process recovery.

use core::fmt;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::fcntl::{OFlag, open, openat, renameat};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};
use paraegox_kernel::{
    digest::{Digest32, Digest32Builder, DigestBuildError},
    identity::{PrincipalRef, RuntimeHostId},
};

use crate::protocol::{
    NodeManagementEndpointErrorV1, NodeManagementEndpointV1, NodeManagementProtocolError,
    NodeManagementRequestV1, decode_status_payload, encode_status_payload,
};
use crate::{
    EnrollmentIssuerRefV1, MAX_RUNTIME_HOSTS_PER_NODE, NodeArchitectureV1, NodeContractError,
    NodeDaemonV1, NodeFeatureReportInputV1, NodeFeatureReportV1, NodeIdentityV1, NodeIncarnation,
    NodeManagementEndpointRefV1, NodeOperatingSystemV1, NodeRegistrationTenureV1, NodeStatusV1,
    RuntimeApplyEndpointDescriptorV1, RuntimeApplyEndpointRefV1, RuntimeApplyTransportV1,
    RuntimeHostLivenessV1, RuntimeHostObservationV1, RuntimeHostStatusV1,
};

const STORE_LOCK_FILE: &str = ".writer.lock";
const STORE_STATE_FILE: &str = "node-daemon.pxnd";
const STORE_TEMP_FILE: &str = ".node-daemon.pxnd.next";
const STATE_MAGIC: &[u8; 4] = b"PXND";
const LEGACY_STATE_VERSION: u16 = 1;
const STATE_VERSION: u16 = 2;
const STATE_HEADER_BYTES: usize = 256;
const STATE_DIGEST_OFFSET: usize = 224;
const RUNTIME_STATUS_FIXED_BYTES: usize = 108;
const RUNTIME_VALIDITY_RECORD_BYTES: usize = 24;
const MAX_RUNTIME_ROUTE_BYTES: usize = 255;
const MAX_NODE_DAEMON_STATE_BYTES: usize = 8 * 1024;
const STATE_DIGEST_DOMAIN: &[u8] = b"paraegox.node.daemon-state.v1";
const PRIVATE_DIRECTORY_MODE_BITS: u32 = 0o700;
const PRIVATE_FILE_MODE_BITS: u32 = 0o600;
const PRIVATE_MODE_MASK: u32 = 0o7777;
const PRIVATE_FILE_MODE: Mode = Mode::S_IRUSR.union(Mode::S_IWUSR);

/// Fail-closed local durability errors for one NodeDaemon tenure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeDaemonStoreError {
    /// A filesystem operation failed before publication was known to occur.
    Io(io::ErrorKind),
    /// The state root was not an absolute owner-selected directory.
    InvalidPath,
    /// The state directory was not an owner-private, non-symlink directory.
    InsecureDirectory,
    /// A lock, state, or temporary file was not an owner-private regular file.
    InsecureFile,
    /// The state root contained an entry not owned by this store format.
    UnexpectedStoreEntry,
    /// Another writer owns the same current tenure store.
    LockContended,
    /// The persisted state version or framing is unsupported.
    UnsupportedState,
    /// Persisted bytes were not the one canonical encoding of their facts.
    NonCanonicalState,
    /// The persisted state integrity commitment did not match.
    StateDigestMismatch,
    /// Persisted state exceeded the fixed v1 bound.
    StateTooLarge,
    /// The caller attempted to resume a different identity or registration tenure.
    BootstrapMismatch,
    /// A reducer contract rejected the candidate state transition.
    Contract(NodeContractError),
    /// The embedded immutable NodeStatus payload was invalid.
    Protocol(NodeManagementProtocolError),
    /// Atomic replacement may have become durable; the owner must reopen.
    CommitUncertain(io::ErrorKind),
    /// This handle observed an uncertain commit and can no longer mutate.
    Poisoned,
    /// The system wall clock could not provide a bounded Unix-nanosecond value.
    ClockUnavailable,
    /// A fresh Runtime observation reached the durable owner after its deadline.
    ObservationExpired,
    /// A generic publication tried to discard authenticated Runtime-observation provenance.
    ObservationProvenanceConflict,
}

impl fmt::Display for NodeDaemonStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "NodeDaemon store rejected operation: {self:?}")
    }
}

impl std::error::Error for NodeDaemonStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<NodeContractError> for NodeDaemonStoreError {
    fn from(error: NodeContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<NodeManagementProtocolError> for NodeDaemonStoreError {
    fn from(error: NodeManagementProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<DigestBuildError> for NodeDaemonStoreError {
    fn from(error: DigestBuildError) -> Self {
        Self::Contract(NodeContractError::Digest(error))
    }
}

/// Single-writer durable owner for one exact, externally authorized tenure.
///
/// This type is intentionally not `Clone`.  Mutations are applied to a private
/// candidate reducer, atomically persisted and directory-synchronized, and
/// only then made visible through this handle.  Reopening requires the exact
/// stable identity, registration epoch, NodeIncarnation, and management
/// endpoint; this store never allocates or advances any of them.
pub struct DurableNodeDaemonV1 {
    _directory: File,
    _writer_lock: File,
    daemon: NodeDaemonV1,
    last_runtime_observation: Option<DurableRuntimeObservationReplayV1>,
    runtime_observation_valid_until: BTreeMap<RuntimeHostId, u64>,
    poisoned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableRuntimeObservationReplayV1 {
    request_digest: Digest32,
    runtime_host_id: RuntimeHostId,
}

struct RecoveredNodeDaemonState {
    daemon: NodeDaemonV1,
    last_runtime_observation: Option<DurableRuntimeObservationReplayV1>,
    runtime_observation_valid_until: BTreeMap<RuntimeHostId, u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableRuntimeObservationCommitOutcome {
    Published,
    ExactReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DurableRuntimeObservationCommit {
    pub(crate) outcome: DurableRuntimeObservationCommitOutcome,
    pub(crate) status: NodeStatusV1,
}

impl DurableNodeDaemonV1 {
    /// Opens or creates state for one exact current registration tenure.
    ///
    /// `initial_feature_report` is used only when creating a new store.  On
    /// recovery the durable report wins, because a later report may already
    /// have committed before the process stopped.
    pub fn open(
        root: &Path,
        identity: NodeIdentityV1,
        tenure: NodeRegistrationTenureV1,
        management_endpoint_ref: NodeManagementEndpointRefV1,
        initial_feature_report: NodeFeatureReportV1,
    ) -> Result<Self, NodeDaemonStoreError> {
        let directory = open_or_create_store_directory(root)?;
        let writer_lock = open_or_create_lock(&directory)?;
        try_lock(&writer_lock)?;
        remove_stale_temporary(&directory)?;

        let recovered = match read_existing_state(&directory)? {
            Some(bytes) => {
                let persisted = decode_state(&bytes)?;
                if persisted.daemon.identity() != identity
                    || persisted.daemon.tenure() != tenure
                    || persisted.daemon.management_endpoint_ref() != management_endpoint_ref
                {
                    return Err(NodeDaemonStoreError::BootstrapMismatch);
                }
                persisted
            }
            None => {
                let candidate = NodeDaemonV1::try_new(
                    identity,
                    tenure,
                    management_endpoint_ref,
                    initial_feature_report,
                )?;
                publish_state(
                    &directory,
                    &encode_state(&candidate, None, &BTreeMap::new())?,
                )?;
                RecoveredNodeDaemonState {
                    daemon: candidate,
                    last_runtime_observation: None,
                    runtime_observation_valid_until: BTreeMap::new(),
                }
            }
        };
        validate_store_entries(root)?;
        validate_path_still_names_directory(root, &directory)?;
        Ok(Self {
            _directory: directory,
            _writer_lock: writer_lock,
            daemon: recovered.daemon,
            last_runtime_observation: recovered.last_runtime_observation,
            runtime_observation_valid_until: recovered.runtime_observation_valid_until,
            poisoned: false,
        })
    }

    /// Returns the exact stable identity pinned by this durable tenure.
    #[must_use]
    pub const fn identity(&self) -> NodeIdentityV1 {
        self.daemon.identity()
    }

    /// Returns the exact externally authorized registration coordinate.
    #[must_use]
    pub const fn tenure(&self) -> NodeRegistrationTenureV1 {
        self.daemon.tenure()
    }

    /// Returns the owner-private management endpoint reference for this tenure.
    #[must_use]
    pub const fn management_endpoint_ref(&self) -> NodeManagementEndpointRefV1 {
        self.daemon.management_endpoint_ref()
    }

    /// Returns the last durably published immutable status, if one exists.
    #[must_use]
    pub const fn current_status(&self) -> Option<&NodeStatusV1> {
        self.daemon.current_status()
    }

    /// Returns the current immutable status, durably replacing an expired
    /// Runtime-observation-backed publication with a node-only publication.
    ///
    /// The replacement retains every RuntimeHost monotonic fence but hides
    /// the expired discovery records. A subsequent authenticated observation
    /// must make a RuntimeHost visible again. This lets the same Node tenure
    /// restart after its last observation lease expires without serving that
    /// stale lease as fresh discovery data.
    pub fn current_status_or_expire_runtime_observations(
        &mut self,
        node_only_freshness_budget_nanos: u64,
    ) -> Result<Option<NodeStatusV1>, NodeDaemonStoreError> {
        if self.last_runtime_observation.is_none() {
            return Ok(self.daemon.current_status().cloned());
        }
        let now_unix_nanos = current_unix_time_nanos()?;
        self.current_status_or_expire_runtime_observations_at(
            node_only_freshness_budget_nanos,
            now_unix_nanos,
        )
    }

    /// Durably advances one already owner-verified RuntimeHost observation.
    ///
    /// The endpoint remains discovery data.  No request is sent or admitted.
    pub fn observe_runtime_host(
        &mut self,
        status: RuntimeHostStatusV1,
    ) -> Result<RuntimeHostObservationV1, NodeDaemonStoreError> {
        self.transaction(|candidate| candidate.observe_runtime_host(status))
    }

    /// Durably hides one RuntimeHost while retaining its monotonic fence.
    ///
    /// Returns `true` only when the visible inventory changed.
    pub fn forget_runtime_host(
        &mut self,
        runtime_host_id: RuntimeHostId,
    ) -> Result<bool, NodeDaemonStoreError> {
        self.ensure_usable()?;
        if !self.daemon.visible_runtime_hosts.contains(&runtime_host_id) {
            return Ok(false);
        }
        let mut candidate = self.daemon.clone();
        candidate.forget_runtime_host(runtime_host_id);
        self.commit_candidate(candidate)?;
        Ok(true)
    }

    /// Durably advances the owner-verified feature report in this incarnation.
    pub fn replace_feature_report(
        &mut self,
        feature_report: NodeFeatureReportV1,
    ) -> Result<(), NodeDaemonStoreError> {
        self.transaction(|candidate| candidate.replace_feature_report(feature_report))
    }

    /// Builds and durably publishes the next immutable NodeStatus.
    pub fn publish_status(
        &mut self,
        freshness_budget_nanos: u64,
    ) -> Result<NodeStatusV1, NodeDaemonStoreError> {
        self.ensure_usable()?;
        if !self.runtime_observation_valid_until.is_empty() {
            return Err(NodeDaemonStoreError::ObservationProvenanceConflict);
        }
        self.transaction(|candidate| candidate.publish_status(freshness_budget_nanos))
    }

    /// Atomically consumes one already authenticated Runtime observation and
    /// publishes the exact next immutable NodeStatus before returning.
    ///
    /// Authentication is owned by the process observation adapter. This
    /// method only enforces durable sequence/idempotency and the existing
    /// Runtime epoch/snapshot/endpoint fences. A retry of the last committed
    /// exact observation returns its durable NodeStatus without rewriting it,
    /// even after the original challenge expires. New publication computes
    /// the relative PXNS freshness at the instant the durable owner lock is
    /// held, from the authenticated absolute deadline.
    pub(crate) fn commit_authenticated_runtime_observation(
        &mut self,
        intended_status_sequence: u64,
        runtime_status: RuntimeHostStatusV1,
        valid_until_unix_nanos: u64,
        request_digest: Digest32,
    ) -> Result<DurableRuntimeObservationCommit, NodeDaemonStoreError> {
        if let Some(replay) = self.recover_exact_runtime_observation_ack(
            intended_status_sequence,
            runtime_status.runtime_host_id(),
            request_digest,
        )? {
            return Ok(replay);
        }
        let now_unix_nanos = current_unix_time_nanos()?;
        self.commit_fresh_authenticated_runtime_observation_at(
            intended_status_sequence,
            runtime_status,
            valid_until_unix_nanos,
            request_digest,
            now_unix_nanos,
        )
    }

    /// Recovers an ACK for the exact last committed PXNO without revalidating
    /// its now-possibly-expired freshness window. The digest is over the full
    /// canonical PXNO, and the caller has already authenticated the outer
    /// local capability before using this path.
    pub(crate) fn recover_exact_runtime_observation_ack(
        &self,
        intended_status_sequence: u64,
        runtime_host_id: RuntimeHostId,
        request_digest: Digest32,
    ) -> Result<Option<DurableRuntimeObservationCommit>, NodeDaemonStoreError> {
        self.ensure_usable()?;
        if request_digest == Digest32::from_bytes([0; 32]) {
            return Err(NodeDaemonStoreError::Contract(
                NodeContractError::StatusSequenceConflict,
            ));
        }
        let Some(status) = self.daemon.current_status() else {
            return Ok(None);
        };
        let exact_runtime = status
            .runtime_hosts()
            .iter()
            .any(|current| current.runtime_host_id() == runtime_host_id);
        let exact_request = self.last_runtime_observation.is_some_and(|replay| {
            replay.request_digest == request_digest && replay.runtime_host_id == runtime_host_id
        });
        if status.status_sequence() == intended_status_sequence && exact_runtime && exact_request {
            return Ok(Some(DurableRuntimeObservationCommit {
                outcome: DurableRuntimeObservationCommitOutcome::ExactReplay,
                status: status.clone(),
            }));
        }
        Ok(None)
    }

    fn commit_fresh_authenticated_runtime_observation_at(
        &mut self,
        intended_status_sequence: u64,
        runtime_status: RuntimeHostStatusV1,
        valid_until_unix_nanos: u64,
        request_digest: Digest32,
        now_unix_nanos: u64,
    ) -> Result<DurableRuntimeObservationCommit, NodeDaemonStoreError> {
        self.ensure_usable()?;
        if request_digest == Digest32::from_bytes([0; 32]) {
            return Err(NodeDaemonStoreError::Contract(
                NodeContractError::StatusSequenceConflict,
            ));
        }
        let expected = self.daemon.next_status_sequence.get();
        if intended_status_sequence == expected {
            valid_until_unix_nanos
                .checked_sub(now_unix_nanos)
                .filter(|budget| *budget > 0 && *budget <= crate::MAX_NODE_STATUS_FRESHNESS_NANOS)
                .ok_or(NodeDaemonStoreError::ObservationExpired)?;
            let runtime_host_id = runtime_status.runtime_host_id();
            let mut candidate = self.daemon.clone();
            let mut runtime_validity = self.runtime_observation_valid_until.clone();
            runtime_validity.retain(|retained_runtime_host_id, deadline| {
                now_unix_nanos < *deadline
                    && candidate
                        .visible_runtime_hosts
                        .contains(retained_runtime_host_id)
            });
            runtime_validity.insert(runtime_host_id, valid_until_unix_nanos);
            let publication_valid_until = runtime_validity
                .values()
                .copied()
                .min()
                .ok_or(NodeDaemonStoreError::ObservationExpired)?;
            let freshness_budget_nanos = publication_valid_until
                .checked_sub(now_unix_nanos)
                .filter(|budget| *budget > 0 && *budget <= crate::MAX_NODE_STATUS_FRESHNESS_NANOS)
                .ok_or(NodeDaemonStoreError::ObservationExpired)?;
            let visible_runtime_hosts: Vec<RuntimeHostId> =
                candidate.visible_runtime_hosts.iter().copied().collect();
            for visible_runtime_host_id in visible_runtime_hosts {
                if !runtime_validity.contains_key(&visible_runtime_host_id) {
                    candidate.forget_runtime_host(visible_runtime_host_id);
                }
            }
            candidate.observe_runtime_host(runtime_status)?;
            let status = candidate.publish_status_with_valid_until_unix_nanos(
                freshness_budget_nanos,
                publication_valid_until,
            )?;
            let replay = DurableRuntimeObservationReplayV1 {
                request_digest,
                runtime_host_id,
            };
            self.commit_candidate_with_replay(candidate, Some(replay), runtime_validity)?;
            return Ok(DurableRuntimeObservationCommit {
                outcome: DurableRuntimeObservationCommitOutcome::Published,
                status,
            });
        }
        if intended_status_sequence < expected {
            return Err(NodeDaemonStoreError::Contract(
                NodeContractError::StaleStatusSequence,
            ));
        }
        Err(NodeDaemonStoreError::Contract(
            NodeContractError::StatusSequenceConflict,
        ))
    }

    fn current_status_or_expire_runtime_observations_at(
        &mut self,
        node_only_freshness_budget_nanos: u64,
        now_unix_nanos: u64,
    ) -> Result<Option<NodeStatusV1>, NodeDaemonStoreError> {
        self.ensure_usable()?;
        let current = self.daemon.current_status().cloned();
        if self.last_runtime_observation.is_none()
            || !self.observation_backed_status_is_expired_at(now_unix_nanos)
        {
            return Ok(current);
        }

        // PXNS carries one aggregate freshness deadline. Once that deadline
        // expires, retaining any member of the old visible set would
        // accidentally renew it. Hide the complete set, retain the reducer's
        // RuntimeHost fences, and publish the next node-only status atomically.
        let mut candidate = self.daemon.clone();
        let visible_runtime_hosts: Vec<RuntimeHostId> =
            candidate.visible_runtime_hosts.iter().copied().collect();
        for runtime_host_id in visible_runtime_hosts {
            candidate.forget_runtime_host(runtime_host_id);
        }
        let status = candidate.publish_status(node_only_freshness_budget_nanos)?;
        self.commit_candidate_with_replay(candidate, None, BTreeMap::new())?;
        Ok(Some(status))
    }

    fn transaction<T>(
        &mut self,
        mutation: impl FnOnce(&mut NodeDaemonV1) -> Result<T, NodeContractError>,
    ) -> Result<T, NodeDaemonStoreError> {
        self.ensure_usable()?;
        let mut candidate = self.daemon.clone();
        let value = mutation(&mut candidate)?;
        self.commit_candidate(candidate)?;
        Ok(value)
    }

    fn commit_candidate(&mut self, candidate: NodeDaemonV1) -> Result<(), NodeDaemonStoreError> {
        let publication_unchanged = self
            .daemon
            .current_status()
            .zip(candidate.current_status())
            .is_some_and(|(current, next)| current.status_digest() == next.status_digest());
        let last_runtime_observation = if publication_unchanged {
            self.last_runtime_observation
        } else {
            None
        };
        let runtime_observation_valid_until = if publication_unchanged {
            self.runtime_observation_valid_until.clone()
        } else {
            BTreeMap::new()
        };
        self.commit_candidate_with_replay(
            candidate,
            last_runtime_observation,
            runtime_observation_valid_until,
        )
    }

    fn commit_candidate_with_replay(
        &mut self,
        candidate: NodeDaemonV1,
        last_runtime_observation: Option<DurableRuntimeObservationReplayV1>,
        runtime_observation_valid_until: BTreeMap<RuntimeHostId, u64>,
    ) -> Result<(), NodeDaemonStoreError> {
        let encoded = encode_state(
            &candidate,
            last_runtime_observation,
            &runtime_observation_valid_until,
        )?;
        if let Err(error) = publish_state(&self._directory, &encoded) {
            if matches!(error, NodeDaemonStoreError::CommitUncertain(_)) {
                self.poisoned = true;
            }
            return Err(error);
        }
        self.daemon = candidate;
        self.last_runtime_observation = last_runtime_observation;
        self.runtime_observation_valid_until = runtime_observation_valid_until;
        Ok(())
    }

    fn ensure_usable(&self) -> Result<(), NodeDaemonStoreError> {
        if self.poisoned {
            Err(NodeDaemonStoreError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn observation_backed_status_is_expired_at(&self, now_unix_nanos: u64) -> bool {
        self.runtime_observation_valid_until
            .values()
            .copied()
            .min()
            .is_some_and(|deadline| now_unix_nanos >= deadline)
    }
}

impl NodeManagementEndpointV1 for DurableNodeDaemonV1 {
    fn exchange(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<Box<[u8]>, NodeManagementEndpointErrorV1> {
        let request = NodeManagementRequestV1::decode(canonical_request)
            .map_err(|_| NodeManagementEndpointErrorV1::MalformedRequest)?;
        let observation_expired = if self.last_runtime_observation.is_some() {
            let now = current_unix_time_nanos()
                .map_err(|_| NodeManagementEndpointErrorV1::ResponseUnavailable)?;
            self.observation_backed_status_is_expired_at(now)
        } else {
            false
        };
        if observation_expired {
            // PXNS-v1 carries a relative freshness budget. Refusing the
            // immutable observation-backed publication after its persisted,
            // authenticated absolute deadline prevents a new consumer from
            // treating an old Runtime Live fact as freshly observed.
            return Err(NodeManagementEndpointErrorV1::ResponseUnavailable);
        }
        self.daemon
            .answer_read_only_v1(&request)
            .map(|response| response.canonical_wire().into())
            .map_err(|error| match error {
                NodeManagementProtocolError::TargetMismatch => {
                    NodeManagementEndpointErrorV1::Unavailable
                }
                _ => NodeManagementEndpointErrorV1::ResponseUnavailable,
            })
    }
}

fn encode_state(
    daemon: &NodeDaemonV1,
    last_runtime_observation: Option<DurableRuntimeObservationReplayV1>,
    runtime_observation_valid_until: &BTreeMap<RuntimeHostId, u64>,
) -> Result<Vec<u8>, NodeDaemonStoreError> {
    encode_state_version(
        daemon,
        last_runtime_observation,
        runtime_observation_valid_until,
        STATE_VERSION,
    )
}

fn encode_state_version(
    daemon: &NodeDaemonV1,
    last_runtime_observation: Option<DurableRuntimeObservationReplayV1>,
    runtime_observation_valid_until: &BTreeMap<RuntimeHostId, u64>,
    state_version: u16,
) -> Result<Vec<u8>, NodeDaemonStoreError> {
    if !matches!(state_version, LEGACY_STATE_VERSION | STATE_VERSION)
        || (state_version == LEGACY_STATE_VERSION
            && (last_runtime_observation.is_some() || !runtime_observation_valid_until.is_empty()))
    {
        return Err(NodeDaemonStoreError::UnsupportedState);
    }
    let published_valid_until = daemon
        .last_published_status
        .as_ref()
        .and_then(NodeStatusV1::valid_until_unix_nanos);
    let aggregate_valid_until = runtime_observation_valid_until.values().copied().min();
    let status_runtime_hosts = daemon.last_published_status.as_ref().map(|status| {
        status
            .runtime_hosts()
            .iter()
            .map(|runtime| runtime.runtime_host_id())
            .collect::<Vec<_>>()
    });
    let validity_runtime_hosts: Vec<RuntimeHostId> =
        runtime_observation_valid_until.keys().copied().collect();
    if runtime_observation_valid_until.len() > MAX_RUNTIME_HOSTS_PER_NODE
        || runtime_observation_valid_until
            .values()
            .any(|deadline| *deadline == 0)
        || published_valid_until != aggregate_valid_until
        || (state_version == LEGACY_STATE_VERSION && published_valid_until.is_some())
        || match last_runtime_observation {
            Some(replay) => {
                runtime_observation_valid_until.is_empty()
                    || !runtime_observation_valid_until.contains_key(&replay.runtime_host_id)
                    || status_runtime_hosts.as_ref() != Some(&validity_runtime_hosts)
            }
            None => !runtime_observation_valid_until.is_empty() || published_valid_until.is_some(),
        }
    {
        return Err(NodeDaemonStoreError::NonCanonicalState);
    }
    let fence_count = daemon.runtime_hosts.len();
    let visible_count = daemon.visible_runtime_hosts.len();
    if fence_count > MAX_RUNTIME_HOSTS_PER_NODE
        || visible_count > fence_count
        || !daemon
            .visible_runtime_hosts
            .iter()
            .all(|runtime_host_id| daemon.runtime_hosts.contains_key(runtime_host_id))
    {
        return Err(NodeDaemonStoreError::NonCanonicalState);
    }
    validate_sequence_state(daemon)?;

    let mut frame = vec![0_u8; STATE_HEADER_BYTES];
    frame[..4].copy_from_slice(STATE_MAGIC);
    frame[4..6].copy_from_slice(&state_version.to_be_bytes());
    frame[6..8].copy_from_slice(&(STATE_HEADER_BYTES as u16).to_be_bytes());
    frame[12] = u8::try_from(fence_count).map_err(|_| NodeDaemonStoreError::StateTooLarge)?;
    frame[13] = u8::try_from(visible_count).map_err(|_| NodeDaemonStoreError::StateTooLarge)?;
    frame[14] = u8::from(daemon.last_published_status.is_some());
    frame[165] = u8::try_from(runtime_observation_valid_until.len())
        .map_err(|_| NodeDaemonStoreError::StateTooLarge)?;
    frame[16..32].copy_from_slice(daemon.identity.node_id().as_bytes());
    frame[32..48].copy_from_slice(daemon.identity.principal().as_bytes());
    frame[48..64].copy_from_slice(daemon.identity.enrollment_issuer().as_bytes());
    frame[64..72].copy_from_slice(&daemon.tenure.registration_epoch().to_be_bytes());
    frame[72..88].copy_from_slice(daemon.tenure.node_incarnation().as_bytes());
    frame[88..104].copy_from_slice(daemon.management_endpoint_ref.as_bytes());
    frame[104..112].copy_from_slice(&daemon.next_status_sequence.get().to_be_bytes());
    frame[112..120].copy_from_slice(&daemon.feature_report.report_sequence().to_be_bytes());
    frame[120] = daemon.feature_report.operating_system() as u8;
    frame[121] = daemon.feature_report.architecture() as u8;
    frame[122..124].copy_from_slice(
        &daemon
            .feature_report
            .runtime_contract_version()
            .to_be_bytes(),
    );
    frame[124..126].copy_from_slice(
        &daemon
            .feature_report
            .fabric_contract_version()
            .to_be_bytes(),
    );
    frame[128..160].copy_from_slice(daemon.feature_report.platform_profile_digest().as_bytes());

    for runtime in daemon.runtime_hosts.values() {
        encode_runtime_status(&mut frame, runtime)?;
    }
    for (runtime_host_id, valid_until_unix_nanos) in runtime_observation_valid_until {
        frame.extend_from_slice(runtime_host_id.as_bytes());
        frame.extend_from_slice(&valid_until_unix_nanos.to_be_bytes());
    }
    for runtime_host_id in &daemon.visible_runtime_hosts {
        frame.extend_from_slice(runtime_host_id.as_bytes());
    }
    let last_payload = daemon
        .last_published_status
        .as_ref()
        .map(encode_status_payload)
        .transpose()?
        .unwrap_or_default();
    frame[160..164].copy_from_slice(
        &u32::try_from(last_payload.len())
            .map_err(|_| NodeDaemonStoreError::StateTooLarge)?
            .to_be_bytes(),
    );
    if let Some(replay) = last_runtime_observation {
        if crate::bytes_are_zero(replay.request_digest.as_bytes())
            || crate::bytes_are_zero(replay.runtime_host_id.as_bytes())
            || daemon.last_published_status.as_ref().is_none_or(|status| {
                !status
                    .runtime_hosts()
                    .iter()
                    .any(|runtime| runtime.runtime_host_id() == replay.runtime_host_id)
            })
        {
            return Err(NodeDaemonStoreError::NonCanonicalState);
        }
        frame[164] = 1;
        frame[168..200].copy_from_slice(replay.request_digest.as_bytes());
        frame[200..216].copy_from_slice(replay.runtime_host_id.as_bytes());
        frame[216..224].copy_from_slice(
            &aggregate_valid_until
                .ok_or(NodeDaemonStoreError::NonCanonicalState)?
                .to_be_bytes(),
        );
    }
    frame.extend_from_slice(&last_payload);
    if frame.len() > MAX_NODE_DAEMON_STATE_BYTES {
        return Err(NodeDaemonStoreError::StateTooLarge);
    }
    let frame_length =
        u32::try_from(frame.len()).map_err(|_| NodeDaemonStoreError::StateTooLarge)?;
    frame[8..12].copy_from_slice(&frame_length.to_be_bytes());
    let digest = state_digest(&frame)?;
    frame[STATE_DIGEST_OFFSET..STATE_HEADER_BYTES].copy_from_slice(digest.as_bytes());
    Ok(frame)
}

fn decode_state(frame: &[u8]) -> Result<RecoveredNodeDaemonState, NodeDaemonStoreError> {
    if frame.len() < STATE_HEADER_BYTES || frame.len() > MAX_NODE_DAEMON_STATE_BYTES {
        return Err(NodeDaemonStoreError::StateTooLarge);
    }
    let state_version = read_u16(&frame[4..6]);
    if &frame[..4] != STATE_MAGIC
        || !matches!(state_version, LEGACY_STATE_VERSION | STATE_VERSION)
        || usize::from(read_u16(&frame[6..8])) != STATE_HEADER_BYTES
    {
        return Err(NodeDaemonStoreError::UnsupportedState);
    }
    let validity_count = usize::from(frame[165]);
    let invalid_extension = if state_version == LEGACY_STATE_VERSION {
        frame[164..STATE_DIGEST_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
    } else {
        frame[166..168].iter().any(|byte| *byte != 0)
            || frame[164] > 1
            || validity_count > MAX_RUNTIME_HOSTS_PER_NODE
            || (frame[164] == 0
                && (validity_count != 0
                    || frame[168..STATE_DIGEST_OFFSET]
                        .iter()
                        .any(|byte| *byte != 0)))
            || (frame[164] == 1 && (validity_count == 0 || read_u64(&frame[216..224]) == 0))
    };
    if usize::try_from(read_u32(&frame[8..12])).ok() != Some(frame.len())
        || frame[15] != 0
        || frame[126..128].iter().any(|byte| *byte != 0)
        || frame[14] > 1
        || invalid_extension
    {
        return Err(NodeDaemonStoreError::NonCanonicalState);
    }
    let declared_digest = Digest32::from_bytes(read_array::<32>(
        &frame[STATE_DIGEST_OFFSET..STATE_HEADER_BYTES],
    ));
    if state_digest(frame)? != declared_digest {
        return Err(NodeDaemonStoreError::StateDigestMismatch);
    }

    let node_id = crate::NodeId::try_from_bytes(read_array::<16>(&frame[16..32]))?;
    let identity = NodeIdentityV1::try_new(
        node_id,
        PrincipalRef::from_bytes(read_array::<16>(&frame[32..48])),
        EnrollmentIssuerRefV1::try_from_bytes(read_array::<16>(&frame[48..64]))?,
    )?;
    let node_incarnation = NodeIncarnation::try_from_bytes(read_array::<16>(&frame[72..88]))?;
    let tenure =
        NodeRegistrationTenureV1::try_new(node_id, read_u64(&frame[64..72]), node_incarnation)?;
    let management_endpoint_ref =
        NodeManagementEndpointRefV1::try_from_bytes(read_array::<16>(&frame[88..104]))?;
    let feature_report = NodeFeatureReportV1::try_new(NodeFeatureReportInputV1 {
        node_id,
        node_incarnation,
        report_sequence: read_u64(&frame[112..120]),
        operating_system: decode_operating_system(frame[120])?,
        architecture: decode_architecture(frame[121])?,
        platform_profile_digest: Digest32::from_bytes(read_array::<32>(&frame[128..160])),
        runtime_contract_version: read_u16(&frame[122..124]),
        fabric_contract_version: read_u16(&frame[124..126]),
    })?;
    let mut daemon =
        NodeDaemonV1::try_new(identity, tenure, management_endpoint_ref, feature_report)?;

    let fence_count = usize::from(frame[12]);
    let visible_count = usize::from(frame[13]);
    if fence_count > MAX_RUNTIME_HOSTS_PER_NODE || visible_count > fence_count {
        return Err(NodeDaemonStoreError::NonCanonicalState);
    }
    let mut cursor = STATE_HEADER_BYTES;
    let mut previous_runtime_host_id = None;
    for _ in 0..fence_count {
        let (runtime, next) = decode_runtime_status(frame, cursor)?;
        if previous_runtime_host_id.is_some_and(|previous| previous >= runtime.runtime_host_id()) {
            return Err(NodeDaemonStoreError::NonCanonicalState);
        }
        previous_runtime_host_id = Some(runtime.runtime_host_id());
        daemon
            .runtime_hosts
            .insert(runtime.runtime_host_id(), runtime);
        cursor = next;
    }
    let mut runtime_observation_valid_until = BTreeMap::new();
    let mut previous_validity_runtime_host_id = None;
    for _ in 0..validity_count {
        let end = cursor
            .checked_add(RUNTIME_VALIDITY_RECORD_BYTES)
            .ok_or(NodeDaemonStoreError::NonCanonicalState)?;
        let record = frame
            .get(cursor..end)
            .ok_or(NodeDaemonStoreError::NonCanonicalState)?;
        let runtime_host_id = RuntimeHostId::from_bytes(read_array::<16>(&record[..16]));
        let valid_until_unix_nanos = read_u64(&record[16..24]);
        if previous_validity_runtime_host_id.is_some_and(|previous| previous >= runtime_host_id)
            || valid_until_unix_nanos == 0
            || !daemon.runtime_hosts.contains_key(&runtime_host_id)
        {
            return Err(NodeDaemonStoreError::NonCanonicalState);
        }
        runtime_observation_valid_until.insert(runtime_host_id, valid_until_unix_nanos);
        previous_validity_runtime_host_id = Some(runtime_host_id);
        cursor = end;
    }
    let mut previous_visible = None;
    for _ in 0..visible_count {
        let end = cursor
            .checked_add(16)
            .ok_or(NodeDaemonStoreError::NonCanonicalState)?;
        let runtime_host_id = RuntimeHostId::from_bytes(read_array::<16>(
            frame
                .get(cursor..end)
                .ok_or(NodeDaemonStoreError::NonCanonicalState)?,
        ));
        if previous_visible.is_some_and(|previous| previous >= runtime_host_id)
            || !daemon.runtime_hosts.contains_key(&runtime_host_id)
        {
            return Err(NodeDaemonStoreError::NonCanonicalState);
        }
        daemon.visible_runtime_hosts.insert(runtime_host_id);
        previous_visible = Some(runtime_host_id);
        cursor = end;
    }
    let last_payload_length = usize::try_from(read_u32(&frame[160..164]))
        .map_err(|_| NodeDaemonStoreError::NonCanonicalState)?;
    let end = cursor
        .checked_add(last_payload_length)
        .ok_or(NodeDaemonStoreError::NonCanonicalState)?;
    if end != frame.len() || (frame[14] == 0) != (last_payload_length == 0) {
        return Err(NodeDaemonStoreError::NonCanonicalState);
    }
    daemon.last_published_status = if last_payload_length == 0 {
        None
    } else {
        Some(decode_status_payload(
            frame
                .get(cursor..end)
                .ok_or(NodeDaemonStoreError::NonCanonicalState)?,
        )?)
    };
    daemon.next_status_sequence = core::num::NonZeroU64::new(read_u64(&frame[104..112]))
        .ok_or(NodeDaemonStoreError::NonCanonicalState)?;
    validate_recovered_state(&daemon)?;
    let last_runtime_observation = if state_version == LEGACY_STATE_VERSION || frame[164] == 0 {
        None
    } else {
        let request_digest = Digest32::from_bytes(read_array::<32>(&frame[168..200]));
        let runtime_host_id = RuntimeHostId::from_bytes(read_array::<16>(&frame[200..216]));
        let aggregate_valid_until = read_u64(&frame[216..224]);
        if crate::bytes_are_zero(request_digest.as_bytes())
            || crate::bytes_are_zero(runtime_host_id.as_bytes())
            || runtime_observation_valid_until.values().copied().min()
                != Some(aggregate_valid_until)
            || !runtime_observation_valid_until.contains_key(&runtime_host_id)
            || daemon.last_published_status.as_ref().is_none_or(|status| {
                !status
                    .runtime_hosts()
                    .iter()
                    .any(|runtime| runtime.runtime_host_id() == runtime_host_id)
            })
        {
            return Err(NodeDaemonStoreError::NonCanonicalState);
        }
        Some(DurableRuntimeObservationReplayV1 {
            request_digest,
            runtime_host_id,
        })
    };
    if encode_state_version(
        &daemon,
        last_runtime_observation,
        &runtime_observation_valid_until,
        state_version,
    )?
    .as_slice()
        != frame
    {
        return Err(NodeDaemonStoreError::NonCanonicalState);
    }
    Ok(RecoveredNodeDaemonState {
        daemon,
        last_runtime_observation,
        runtime_observation_valid_until,
    })
}

fn validate_sequence_state(daemon: &NodeDaemonV1) -> Result<(), NodeDaemonStoreError> {
    match daemon.last_published_status.as_ref() {
        None if daemon.next_status_sequence.get() == 1 => Ok(()),
        Some(status)
            if status
                .status_sequence()
                .checked_add(1)
                .is_some_and(|next| next == daemon.next_status_sequence.get()) =>
        {
            Ok(())
        }
        _ => Err(NodeDaemonStoreError::NonCanonicalState),
    }
}

fn validate_recovered_state(daemon: &NodeDaemonV1) -> Result<(), NodeDaemonStoreError> {
    validate_sequence_state(daemon)?;
    let Some(status) = daemon.last_published_status.as_ref() else {
        return Ok(());
    };
    if status.node_id() != daemon.identity.node_id()
        || status.node_incarnation() != daemon.tenure.node_incarnation()
        || status.registration_epoch() != daemon.tenure.registration_epoch()
        || status.management_endpoint_ref() != daemon.management_endpoint_ref
        || status.feature_report().report_sequence() > daemon.feature_report.report_sequence()
    {
        return Err(NodeDaemonStoreError::NonCanonicalState);
    }
    for published in status.runtime_hosts() {
        let Some(fence) = daemon.runtime_hosts.get(&published.runtime_host_id()) else {
            return Err(NodeDaemonStoreError::NonCanonicalState);
        };
        if published.runtime_host_epoch() > fence.runtime_host_epoch()
            || (published.runtime_host_epoch() == fence.runtime_host_epoch()
                && published.observation_sequence() > fence.observation_sequence())
        {
            return Err(NodeDaemonStoreError::NonCanonicalState);
        }
        if published.runtime_host_epoch() == fence.runtime_host_epoch()
            && published.observation_sequence() == fence.observation_sequence()
            && published.status_digest() != fence.status_digest()
        {
            return Err(NodeDaemonStoreError::NonCanonicalState);
        }
        crate::validate_runtime_endpoint_successor(published, fence)?;
    }
    Ok(())
}

fn encode_runtime_status(
    frame: &mut Vec<u8>,
    runtime: &RuntimeHostStatusV1,
) -> Result<(), NodeDaemonStoreError> {
    let endpoint = runtime.apply_endpoint();
    let route = endpoint.route().as_bytes();
    if route.len() > MAX_RUNTIME_ROUTE_BYTES {
        return Err(NodeDaemonStoreError::StateTooLarge);
    }
    let mut record = [0_u8; RUNTIME_STATUS_FIXED_BYTES];
    record[..16].copy_from_slice(runtime.runtime_host_id().as_bytes());
    record[16..24].copy_from_slice(&runtime.runtime_host_epoch().to_be_bytes());
    record[24..32].copy_from_slice(&runtime.observation_sequence().to_be_bytes());
    record[32] = runtime.liveness() as u8;
    record[33] = endpoint.transport() as u8;
    record[34..36].copy_from_slice(
        &u16::try_from(route.len())
            .map_err(|_| NodeDaemonStoreError::StateTooLarge)?
            .to_be_bytes(),
    );
    record[36..52].copy_from_slice(endpoint.endpoint_ref().as_bytes());
    record[52..60].copy_from_slice(&endpoint.endpoint_generation().to_be_bytes());
    record[60..76].copy_from_slice(&endpoint.runtime_response_key_ref());
    record[76..108].copy_from_slice(&endpoint.runtime_response_public_key());
    frame.extend_from_slice(&record);
    frame.extend_from_slice(route);
    Ok(())
}

fn decode_runtime_status(
    frame: &[u8],
    offset: usize,
) -> Result<(RuntimeHostStatusV1, usize), NodeDaemonStoreError> {
    let record_end = offset
        .checked_add(RUNTIME_STATUS_FIXED_BYTES)
        .ok_or(NodeDaemonStoreError::NonCanonicalState)?;
    let record = frame
        .get(offset..record_end)
        .ok_or(NodeDaemonStoreError::NonCanonicalState)?;
    let route_length = usize::from(read_u16(&record[34..36]));
    if route_length > MAX_RUNTIME_ROUTE_BYTES
        || record[33] != RuntimeApplyTransportV1::RestrictedZenohQuery as u8
    {
        return Err(NodeDaemonStoreError::NonCanonicalState);
    }
    let route_end = record_end
        .checked_add(route_length)
        .ok_or(NodeDaemonStoreError::NonCanonicalState)?;
    let route = core::str::from_utf8(
        frame
            .get(record_end..route_end)
            .ok_or(NodeDaemonStoreError::NonCanonicalState)?,
    )
    .map_err(|_| NodeDaemonStoreError::NonCanonicalState)?;
    let runtime_host_id = RuntimeHostId::from_bytes(read_array::<16>(&record[..16]));
    let endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
        RuntimeApplyEndpointRefV1::try_from_bytes(read_array::<16>(&record[36..52]))?,
        runtime_host_id,
        read_u64(&record[52..60]),
        route,
        read_array::<16>(&record[60..76]),
        read_array::<32>(&record[76..108]),
    )?;
    let runtime = RuntimeHostStatusV1::try_new(
        read_u64(&record[16..24]),
        read_u64(&record[24..32]),
        decode_runtime_liveness(record[32])?,
        endpoint,
    )?;
    Ok((runtime, route_end))
}

fn state_digest(frame: &[u8]) -> Result<Digest32, NodeDaemonStoreError> {
    let mut canonical = frame.to_vec();
    canonical[STATE_DIGEST_OFFSET..STATE_HEADER_BYTES].fill(0);
    let mut builder = Digest32Builder::try_new(STATE_DIGEST_DOMAIN)?;
    builder.field_bytes(&canonical)?;
    Ok(builder.finish())
}

fn open_or_create_store_directory(root: &Path) -> Result<File, NodeDaemonStoreError> {
    if !root.is_absolute() || root.parent().is_none() {
        return Err(NodeDaemonStoreError::InvalidPath);
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
        return Err(NodeDaemonStoreError::InsecureDirectory);
    }
    if created {
        sync_directory(root.parent().ok_or(NodeDaemonStoreError::InvalidPath)?)?;
    }
    Ok(directory)
}

fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), NodeDaemonStoreError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & PRIVATE_MODE_MASK != PRIVATE_DIRECTORY_MODE_BITS
    {
        return Err(NodeDaemonStoreError::InsecureDirectory);
    }
    Ok(())
}

fn validate_path_still_names_directory(
    root: &Path,
    directory: &File,
) -> Result<(), NodeDaemonStoreError> {
    let path_metadata = fs::symlink_metadata(root).map_err(io_error)?;
    let descriptor_metadata = directory.metadata().map_err(io_error)?;
    validate_directory_metadata(&path_metadata)?;
    if path_metadata.dev() != descriptor_metadata.dev()
        || path_metadata.ino() != descriptor_metadata.ino()
    {
        return Err(NodeDaemonStoreError::InsecureDirectory);
    }
    Ok(())
}

fn open_or_create_lock(directory: &File) -> Result<File, NodeDaemonStoreError> {
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

fn try_lock(file: &File) -> Result<(), NodeDaemonStoreError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => NodeDaemonStoreError::LockContended,
        TryLockError::Error(error) => io_error(error),
    })
}

fn read_existing_state(directory: &File) -> Result<Option<Vec<u8>>, NodeDaemonStoreError> {
    let owned = match openat(
        directory,
        STORE_STATE_FILE,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(owned) => owned,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(nix_error(error)),
    };
    let mut file = File::from(owned);
    validate_private_file(&file)?;
    let length = usize::try_from(file.metadata().map_err(io_error)?.len())
        .map_err(|_| NodeDaemonStoreError::StateTooLarge)?;
    if length > MAX_NODE_DAEMON_STATE_BYTES {
        return Err(NodeDaemonStoreError::StateTooLarge);
    }
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes).map_err(io_error)?;
    Ok(Some(bytes))
}

fn publish_state(directory: &File, state: &[u8]) -> Result<(), NodeDaemonStoreError> {
    remove_stale_temporary(directory)?;
    let owned = openat(
        directory,
        STORE_TEMP_FILE,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    .map_err(io_error_from_nix)?;
    let mut temporary = File::from(owned);
    fchmod(&temporary, PRIVATE_FILE_MODE).map_err(io_error_from_nix)?;
    validate_private_file(&temporary)?;
    temporary.write_all(state).map_err(io_error)?;
    temporary.sync_all().map_err(io_error)?;
    drop(temporary);
    renameat(directory, STORE_TEMP_FILE, directory, STORE_STATE_FILE).map_err(io_error_from_nix)?;
    directory
        .sync_all()
        .map_err(|error| NodeDaemonStoreError::CommitUncertain(error.kind()))
}

fn remove_stale_temporary(directory: &File) -> Result<(), NodeDaemonStoreError> {
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

fn validate_private_file(file: &File) -> Result<(), NodeDaemonStoreError> {
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & PRIVATE_MODE_MASK != PRIVATE_FILE_MODE_BITS
    {
        return Err(NodeDaemonStoreError::InsecureFile);
    }
    Ok(())
}

fn validate_store_entries(root: &Path) -> Result<(), NodeDaemonStoreError> {
    for entry in fs::read_dir(root).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name();
        if name != OsStr::new(STORE_LOCK_FILE) && name != OsStr::new(STORE_STATE_FILE) {
            return Err(NodeDaemonStoreError::UnexpectedStoreEntry);
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), NodeDaemonStoreError> {
    let owned = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    File::from(owned).sync_all().map_err(io_error)
}

fn decode_operating_system(value: u8) -> Result<NodeOperatingSystemV1, NodeDaemonStoreError> {
    match value {
        1 => Ok(NodeOperatingSystemV1::Linux),
        2 => Ok(NodeOperatingSystemV1::MacOs),
        3 => Ok(NodeOperatingSystemV1::Windows),
        _ => Err(NodeDaemonStoreError::NonCanonicalState),
    }
}

fn decode_architecture(value: u8) -> Result<NodeArchitectureV1, NodeDaemonStoreError> {
    match value {
        1 => Ok(NodeArchitectureV1::X86_64),
        2 => Ok(NodeArchitectureV1::Aarch64),
        _ => Err(NodeDaemonStoreError::NonCanonicalState),
    }
}

fn decode_runtime_liveness(value: u8) -> Result<RuntimeHostLivenessV1, NodeDaemonStoreError> {
    match value {
        1 => Ok(RuntimeHostLivenessV1::Bootstrapping),
        2 => Ok(RuntimeHostLivenessV1::Live),
        3 => Ok(RuntimeHostLivenessV1::Unresponsive),
        4 => Ok(RuntimeHostLivenessV1::Exited),
        5 => Ok(RuntimeHostLivenessV1::Quarantined),
        _ => Err(NodeDaemonStoreError::NonCanonicalState),
    }
}

fn read_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut output = [0_u8; N];
    output.copy_from_slice(bytes);
    output
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

fn current_unix_time_nanos() -> Result<u64, NodeDaemonStoreError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NodeDaemonStoreError::ClockUnavailable)?;
    u64::try_from(elapsed.as_nanos()).map_err(|_| NodeDaemonStoreError::ClockUnavailable)
}

fn io_error(error: io::Error) -> NodeDaemonStoreError {
    NodeDaemonStoreError::Io(error.kind())
}

fn io_error_from_nix(error: nix::errno::Errno) -> NodeDaemonStoreError {
    NodeDaemonStoreError::Io(io::Error::from(error).kind())
}

fn nix_error(error: nix::errno::Errno) -> NodeDaemonStoreError {
    io_error_from_nix(error)
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::path::{Path, PathBuf};

    use paraegox_kernel::{digest::Digest32, identity::PrincipalRef};

    use super::{
        DurableNodeDaemonV1, DurableRuntimeObservationCommitOutcome, LEGACY_STATE_VERSION,
        NodeDaemonStoreError, STATE_DIGEST_OFFSET, STATE_HEADER_BYTES, STATE_VERSION,
        STORE_STATE_FILE, read_u16, state_digest,
    };
    use crate::{
        EnrollmentIssuerRefV1, NodeArchitectureV1, NodeFeatureReportInputV1, NodeFeatureReportV1,
        NodeId, NodeIdentityV1, NodeIncarnation, NodeManagementEndpointRefV1,
        NodeOperatingSystemV1, NodeRegistrationTenureV1, RuntimeApplyEndpointDescriptorV1,
        RuntimeApplyEndpointRefV1, RuntimeHostLivenessV1, RuntimeHostStatusV1,
    };
    use paraegox_kernel::identity::RuntimeHostId;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "paraegox-node-store-{}-{sequence}",
                std::process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn digest(value: u8) -> Digest32 {
        Digest32::from_bytes([value; 32])
    }

    fn node_id(value: u8) -> NodeId {
        NodeId::try_from_bytes([value; 16]).expect("node id")
    }

    fn incarnation(value: u8) -> NodeIncarnation {
        NodeIncarnation::try_from_bytes([value; 16]).expect("incarnation")
    }

    fn identity() -> NodeIdentityV1 {
        NodeIdentityV1::try_new(
            node_id(1),
            PrincipalRef::from_bytes([2; 16]),
            EnrollmentIssuerRefV1::try_from_bytes([3; 16]).expect("issuer"),
        )
        .expect("identity")
    }

    fn tenure() -> NodeRegistrationTenureV1 {
        NodeRegistrationTenureV1::try_new(node_id(1), 7, incarnation(8)).expect("tenure")
    }

    fn management() -> NodeManagementEndpointRefV1 {
        NodeManagementEndpointRefV1::try_from_bytes([9; 16]).expect("management")
    }

    fn feature(sequence: u64) -> NodeFeatureReportV1 {
        NodeFeatureReportV1::try_new(NodeFeatureReportInputV1 {
            node_id: node_id(1),
            node_incarnation: incarnation(8),
            report_sequence: sequence,
            operating_system: NodeOperatingSystemV1::MacOs,
            architecture: NodeArchitectureV1::Aarch64,
            platform_profile_digest: digest(10),
            runtime_contract_version: 8,
            fabric_contract_version: 1,
        })
        .expect("feature")
    }

    fn runtime(epoch: u64, sequence: u64, endpoint_generation: u64) -> RuntimeHostStatusV1 {
        runtime_for(11, epoch, sequence, endpoint_generation)
    }

    fn runtime_for(
        runtime_host_value: u8,
        epoch: u64,
        sequence: u64,
        endpoint_generation: u64,
    ) -> RuntimeHostStatusV1 {
        let endpoint = RuntimeApplyEndpointDescriptorV1::try_new(
            RuntimeApplyEndpointRefV1::try_from_bytes(
                [runtime_host_value
                    .checked_add(1)
                    .expect("endpoint ref value"); 16],
            )
            .expect("endpoint ref"),
            RuntimeHostId::from_bytes([runtime_host_value; 16]),
            endpoint_generation,
            &format!("paraegox/v1/nodes/01/runtime/{runtime_host_value:02x}/apply"),
            [runtime_host_value.checked_add(2).expect("key ref value"); 16],
            [runtime_host_value.checked_add(3).expect("key value"); 32],
        )
        .expect("endpoint");
        RuntimeHostStatusV1::try_new(epoch, sequence, RuntimeHostLivenessV1::Live, endpoint)
            .expect("runtime")
    }

    fn open(root: &TestRoot) -> DurableNodeDaemonV1 {
        DurableNodeDaemonV1::open(root.path(), identity(), tenure(), management(), feature(1))
            .expect("open")
    }

    #[test]
    fn restart_preserves_publication_sequence_and_hidden_runtime_fence() {
        let root = TestRoot::new();
        {
            let mut store = open(&root);
            store
                .observe_runtime_host(runtime(2, 4, 2))
                .expect("observe");
            let first = store.publish_status(1_000).expect("publish first");
            assert_eq!(first.status_sequence(), 1);
            assert!(
                store
                    .forget_runtime_host(RuntimeHostId::from_bytes([11; 16]))
                    .expect("forget")
            );
            store.replace_feature_report(feature(2)).expect("feature");
        }

        let mut recovered = open(&root);
        assert_eq!(
            recovered
                .observe_runtime_host(runtime(1, 99, 2))
                .expect_err("old Runtime epoch must remain fenced"),
            NodeDaemonStoreError::Contract(crate::NodeContractError::StaleRuntimeHostEpoch)
        );
        let second = recovered.publish_status(1_000).expect("publish second");
        assert_eq!(second.status_sequence(), 2);
        assert!(second.runtime_hosts().is_empty());
        assert_eq!(second.feature_report().report_sequence(), 2);
    }

    #[test]
    fn one_store_has_exactly_one_writer() {
        let root = TestRoot::new();
        let first = open(&root);
        let error =
            DurableNodeDaemonV1::open(root.path(), identity(), tenure(), management(), feature(1))
                .err()
                .expect("second writer must fail");
        assert_eq!(error, NodeDaemonStoreError::LockContended);
        drop(first);
        open(&root);
    }

    #[test]
    fn recovery_requires_the_exact_registration_tenure() {
        let root = TestRoot::new();
        drop(open(&root));
        let successor = NodeRegistrationTenureV1::try_new(node_id(1), 8, incarnation(15))
            .expect("successor tenure");
        let error = DurableNodeDaemonV1::open(
            root.path(),
            identity(),
            successor,
            management(),
            NodeFeatureReportV1::try_new(NodeFeatureReportInputV1 {
                node_id: node_id(1),
                node_incarnation: incarnation(15),
                report_sequence: 1,
                operating_system: NodeOperatingSystemV1::MacOs,
                architecture: NodeArchitectureV1::Aarch64,
                platform_profile_digest: digest(10),
                runtime_contract_version: 8,
                fabric_contract_version: 1,
            })
            .expect("successor feature"),
        )
        .err()
        .expect("different tenure must fail");
        assert_eq!(error, NodeDaemonStoreError::BootstrapMismatch);
    }

    #[test]
    fn integrity_corruption_fails_closed() {
        let root = TestRoot::new();
        drop(open(&root));
        let state_path = root.path().join(STORE_STATE_FILE);
        let mut bytes = std::fs::read(&state_path).expect("read state");
        bytes[120] ^= 1;
        std::fs::write(&state_path, bytes).expect("write corruption");
        let error =
            DurableNodeDaemonV1::open(root.path(), identity(), tenure(), management(), feature(1))
                .err()
                .expect("corruption must fail");
        assert_eq!(error, NodeDaemonStoreError::StateDigestMismatch);
    }

    #[test]
    fn legacy_v1_state_reopens_and_advances_to_v2_on_the_next_mutation() {
        let root = TestRoot::new();
        drop(open(&root));
        let state_path = root.path().join(STORE_STATE_FILE);
        let mut bytes = std::fs::read(&state_path).expect("read v2 state");
        bytes[4..6].copy_from_slice(&LEGACY_STATE_VERSION.to_be_bytes());
        let digest = state_digest(&bytes).expect("legacy state digest");
        bytes[STATE_DIGEST_OFFSET..STATE_HEADER_BYTES].copy_from_slice(digest.as_bytes());
        std::fs::write(&state_path, bytes).expect("install canonical legacy state");

        let mut recovered = open(&root);
        recovered
            .publish_status(1_000)
            .expect("lossless next mutation");
        drop(recovered);
        let advanced = std::fs::read(&state_path).expect("read advanced state");
        assert_eq!(read_u16(&advanced[4..6]), STATE_VERSION);
    }

    #[test]
    fn authenticated_observation_deadline_survives_restart_but_does_not_block_exact_ack_recovery() {
        let root = TestRoot::new();
        let request_digest = digest(91);
        {
            let mut store = open(&root);
            let commit = store
                .commit_fresh_authenticated_runtime_observation_at(
                    1,
                    runtime(2, 4, 2),
                    200,
                    request_digest,
                    100,
                )
                .expect("publish fresh authenticated observation");
            assert_eq!(
                commit.outcome,
                DurableRuntimeObservationCommitOutcome::Published
            );
            let state_path = root.path().join(STORE_STATE_FILE);
            let committed_state = std::fs::read(&state_path).expect("read committed observation");
            assert_eq!(
                store
                    .publish_status(1_000)
                    .expect_err("generic publication cannot strip observation provenance"),
                NodeDaemonStoreError::ObservationProvenanceConflict
            );
            assert_eq!(
                std::fs::read(&state_path).expect("read state after rejected publication"),
                committed_state
            );
            assert!(!store.observation_backed_status_is_expired_at(199));
            assert!(store.observation_backed_status_is_expired_at(200));
            let target = crate::protocol::NodeManagementTargetV1::try_new(
                identity().node_id(),
                management(),
                tenure().node_incarnation(),
                tenure().registration_epoch(),
            )
            .expect("management target");
            let request = crate::protocol::NodeManagementRequestV1::try_latest([92; 16], target)
                .expect("latest request");
            assert_eq!(
                crate::protocol::NodeManagementEndpointV1::exchange(
                    &mut store,
                    request.canonical_wire(),
                )
                .expect_err("expired observation-backed PXNS is unavailable"),
                crate::protocol::NodeManagementEndpointErrorV1::ResponseUnavailable
            );
        }

        let mut recovered = open(&root);
        assert_eq!(
            recovered
                .runtime_observation_valid_until
                .get(&RuntimeHostId::from_bytes([11; 16]))
                .copied(),
            Some(200)
        );
        let replay = recovered
            .commit_authenticated_runtime_observation(1, runtime(2, 4, 2), 200, request_digest)
            .expect("exact ACK recovery ignores expired challenge clock");
        assert_eq!(
            replay.outcome,
            DurableRuntimeObservationCommitOutcome::ExactReplay
        );
    }

    #[test]
    fn expired_observation_restart_publishes_node_only_status_and_retains_runtime_fence() {
        let root = TestRoot::new();
        let request_digest = digest(98);
        let mut store = open(&root);
        let observed = store
            .commit_fresh_authenticated_runtime_observation_at(
                1,
                runtime(2, 4, 2),
                200,
                request_digest,
                100,
            )
            .expect("publish authenticated observation");

        assert_eq!(
            store
                .current_status_or_expire_runtime_observations_at(1_000, 199)
                .expect("unexpired status")
                .expect("current status"),
            observed.status
        );
        let node_only = store
            .current_status_or_expire_runtime_observations_at(1_000, 200)
            .expect("expire observation")
            .expect("replacement status");
        assert_eq!(node_only.status_sequence(), 2);
        assert!(node_only.runtime_hosts().is_empty());
        assert_eq!(node_only.valid_until_unix_nanos(), None);
        assert_eq!(store.last_runtime_observation, None);
        assert!(store.runtime_observation_valid_until.is_empty());
        drop(store);

        let mut recovered = open(&root);
        assert_eq!(recovered.current_status(), Some(&node_only));
        assert_eq!(
            recovered
                .observe_runtime_host(runtime(1, 99, 2))
                .expect_err("expired visibility must not erase the Runtime epoch fence"),
            NodeDaemonStoreError::Contract(crate::NodeContractError::StaleRuntimeHostEpoch)
        );
    }

    #[test]
    fn aggregate_observation_expiry_hides_every_runtime_and_retains_each_fence() {
        let root = TestRoot::new();
        let mut store = open(&root);
        store
            .commit_fresh_authenticated_runtime_observation_at(
                1,
                runtime_for(21, 2, 4, 2),
                200,
                digest(99),
                100,
            )
            .expect("publish first Runtime observation");
        let aggregate = store
            .commit_fresh_authenticated_runtime_observation_at(
                2,
                runtime_for(31, 3, 5, 3),
                400,
                digest(100),
                150,
            )
            .expect("publish second Runtime observation");
        assert_eq!(aggregate.status.runtime_hosts().len(), 2);
        assert_eq!(aggregate.status.valid_until_unix_nanos(), Some(200));

        let node_only = store
            .current_status_or_expire_runtime_observations_at(1_000, 200)
            .expect("expire aggregate observation")
            .expect("replacement status");
        assert_eq!(node_only.status_sequence(), 3);
        assert!(node_only.runtime_hosts().is_empty());
        assert_eq!(node_only.valid_until_unix_nanos(), None);
        assert_eq!(store.last_runtime_observation, None);
        assert!(store.runtime_observation_valid_until.is_empty());
        assert_eq!(
            store
                .observe_runtime_host(runtime_for(21, 1, 99, 2))
                .expect_err("first Runtime epoch fence must survive"),
            NodeDaemonStoreError::Contract(crate::NodeContractError::StaleRuntimeHostEpoch)
        );
        assert_eq!(
            store
                .observe_runtime_host(runtime_for(31, 2, 99, 3))
                .expect_err("second Runtime epoch fence must survive"),
            NodeDaemonStoreError::Contract(crate::NodeContractError::StaleRuntimeHostEpoch)
        );
    }

    #[test]
    fn one_runtime_can_renew_its_own_deadline_before_expiry() {
        let root = TestRoot::new();
        let mut store = open(&root);
        store
            .commit_fresh_authenticated_runtime_observation_at(
                1,
                runtime_for(21, 2, 4, 2),
                200,
                digest(95),
                100,
            )
            .expect("publish first lease");
        let renewed = store
            .commit_fresh_authenticated_runtime_observation_at(
                2,
                runtime_for(21, 2, 5, 2),
                400,
                digest(96),
                150,
            )
            .expect("renew same Runtime lease");
        assert_eq!(renewed.status.runtime_hosts().len(), 1);
        assert_eq!(renewed.status.valid_until_unix_nanos(), Some(400));
        assert_eq!(renewed.status.freshness_budget_nanos(), 250);
    }

    #[test]
    fn one_runtime_observation_never_renews_an_older_runtime_host() {
        let root = TestRoot::new();
        let mut store = open(&root);
        let first = store
            .commit_fresh_authenticated_runtime_observation_at(
                1,
                runtime_for(21, 2, 4, 2),
                200,
                digest(92),
                100,
            )
            .expect("publish first Runtime");
        assert_eq!(first.status.valid_until_unix_nanos(), Some(200));

        let second = store
            .commit_fresh_authenticated_runtime_observation_at(
                2,
                runtime_for(31, 3, 5, 3),
                400,
                digest(93),
                150,
            )
            .expect("publish second Runtime before first deadline");
        assert_eq!(second.status.runtime_hosts().len(), 2);
        assert_eq!(second.status.valid_until_unix_nanos(), Some(200));
        assert_eq!(second.status.freshness_budget_nanos(), 50);

        let refreshed_earliest = store
            .commit_fresh_authenticated_runtime_observation_at(
                3,
                runtime_for(21, 2, 5, 2),
                500,
                digest(94),
                175,
            )
            .expect("refresh only the earliest Runtime deadline");
        assert_eq!(refreshed_earliest.status.runtime_hosts().len(), 2);
        assert_eq!(
            refreshed_earliest.status.valid_until_unix_nanos(),
            Some(400)
        );
        assert_eq!(refreshed_earliest.status.freshness_budget_nanos(), 225);

        drop(store);
        let mut store = open(&root);
        assert_eq!(
            store
                .runtime_observation_valid_until
                .get(&RuntimeHostId::from_bytes([21; 16]))
                .copied(),
            Some(500)
        );
        assert_eq!(
            store
                .runtime_observation_valid_until
                .get(&RuntimeHostId::from_bytes([31; 16]))
                .copied(),
            Some(400)
        );
        let after_expiry = store
            .commit_fresh_authenticated_runtime_observation_at(
                4,
                runtime_for(21, 2, 6, 2),
                600,
                digest(97),
                450,
            )
            .expect("publish refreshed Runtime after aggregate deadline");
        assert_eq!(after_expiry.status.runtime_hosts().len(), 1);
        assert_eq!(
            after_expiry.status.runtime_hosts()[0].runtime_host_id(),
            RuntimeHostId::from_bytes([21; 16])
        );
        assert_eq!(after_expiry.status.valid_until_unix_nanos(), Some(600));
    }
}
