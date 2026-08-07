#![cfg(unix)]

//! RuntimeHost-owned lifecycle adapter and durable successor owner for PXAR v6.
//!
//! This module deliberately does not reinterpret the payload-v5 Runtime journal
//! or its `OneSourceLoop` desired head.  The one-way cutover and successor
//! journal live beside that frozen journal; the legacy store supplies only
//! independently verified installation facts and must be fresh before cutover.

use core::{fmt, future::Future, pin::Pin, time::Duration};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Weak};

use ed25519_dalek::{Signer, SigningKey};
use paraegox_fabric::{
    ExperimentalRemoteMtlsLinkSnapshotV1, ExperimentalRemoteMtlsObservationErrorV1, FabricService,
    FabricServiceConfig, SessionEndpoint,
};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_kernel::time::{ClockGeneration, ClockReading, MonotonicDeadline};
use paraegox_runtime_contracts::apply::ExpectedActive;
use paraegox_runtime_contracts::managed_fabric_plan::{
    ManagedFabricApplyRequestV1, ManagedFabricApplyTerminalEvidenceV1,
    ManagedFabricApplyTerminalFactsV1, ManagedFabricApplyTerminalHeadV1,
    ManagedFabricApplyTerminalLifecycleEffectV1, ManagedFabricApplyTerminalOutcomeV1,
    ManagedFabricApplyTerminalReceiptAuthClaimV1, ManagedFabricApplyTerminalReceiptDraftV1,
    ManagedFabricApplyTerminalReceiptV1, ManagedFabricApplyTerminalStateV1,
    ManagedFabricListenEndpointV1, ManagedFabricManifestProjectionV1,
    ManagedFabricTargetExecutionV1, ManagedFabricTargetModeV1,
};
use paraegox_runtime_contracts::managed_service::{
    ManagedServiceGeneration, ManagedServiceLifecycleStage,
};
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};
use tokio::sync::RwLock;
use tokio::time::{Instant, timeout_at};

use crate::admission::VerifiedManagedFabricApplyIngressV1;
use crate::managed_fabric_state::{
    ManagedFabricDurableActive, ManagedFabricDurablePending, ManagedFabricDurablePhase,
    ManagedFabricPendingKind, ManagedFabricReplayRecord, ManagedFabricRevisionHighWater,
    ManagedFabricSnapshot, ManagedFabricSnapshotTransition, ManagedFabricStateError,
    ManagedFabricTerminalRecord, ManagedFabricWriterFence,
};
use crate::managed_service_assembly::{
    ManagedServiceAssembly, ManagedServiceAttempt, ManagedServiceCompletion, ManagedServiceContext,
    ManagedServiceFuture, ManagedServiceImplementation, ManagedServiceReadiness,
    ManagedServiceStartupOutcome,
};
use crate::runtime_clock::RuntimeClock;
use crate::runtime_store::{ManagedFabricStore, ManagedFabricStoreError, RuntimeStore};
use crate::task_registry::CancellationSource;

/// Exact Fabric implementation owned by one managed-service assembly.
///
/// The adapter retains no discovery/default path and exposes no raw Zenoh
/// object. `prepare` either translates the predecessor's canonical loopback
/// endpoint or consumes one already validated distributed configuration;
/// `start` opens the sole session, and `stop` consumes and closes it.
pub(crate) struct RuntimeManagedFabricService {
    requested: Option<RuntimeManagedFabricPrepareRequest>,
    prepared: Option<FabricServiceConfig>,
    shared: Arc<RwLock<ManagedFabricSlot>>,
}

enum RuntimeManagedFabricPrepareRequest {
    LoopbackEndpoint(ManagedFabricListenEndpointV1),
    ExactConfig(FabricServiceConfig),
}

impl RuntimeManagedFabricService {
    fn try_from_execution(
        execution: &ManagedFabricTargetExecutionV1,
        generation: ManagedServiceGeneration,
    ) -> Result<(Self, ManagedFabricControlHandle), ManagedFabricRuntimeError> {
        if execution.mode() != ManagedFabricTargetModeV1::OneManagedFabricService {
            return Err(ManagedFabricRuntimeError::ExpectedActiveExecution);
        }
        let endpoint = execution
            .listen_endpoint()
            .ok_or(ManagedFabricRuntimeError::MissingListenEndpoint)?
            .clone();
        if execution.service().is_none() {
            return Err(ManagedFabricRuntimeError::MissingServiceSpec);
        }
        Ok(Self::from_prepare_request(
            RuntimeManagedFabricPrepareRequest::LoopbackEndpoint(endpoint),
            generation,
        ))
    }

    /// Adapts one already validated exact transport configuration to the same
    /// lifecycle owner and generation-fenced slot used by the predecessor.
    /// The distributed mapper remains responsible for producing this config;
    /// this constructor cannot add endpoints, discovery, or another session.
    pub(crate) fn from_exact_config(
        config: FabricServiceConfig,
        generation: ManagedServiceGeneration,
    ) -> (Self, ManagedFabricControlHandle) {
        Self::from_prepare_request(
            RuntimeManagedFabricPrepareRequest::ExactConfig(config),
            generation,
        )
    }

    fn from_prepare_request(
        requested: RuntimeManagedFabricPrepareRequest,
        generation: ManagedServiceGeneration,
    ) -> (Self, ManagedFabricControlHandle) {
        let shared = Arc::new(RwLock::new(ManagedFabricSlot {
            generation,
            state: ManagedFabricSlotState::NotStarted,
            owned_binding_count: 0,
            binding_census_known: true,
        }));
        let handle = ManagedFabricControlHandle {
            generation,
            shared: Arc::downgrade(&shared),
        };
        (
            Self {
                requested: Some(requested),
                prepared: None,
                shared,
            },
            handle,
        )
    }
}

enum ManagedFabricSlotState {
    NotStarted,
    Live(FabricService),
    Stopping,
    Stopped,
}

struct ManagedFabricSlot {
    generation: ManagedServiceGeneration,
    state: ManagedFabricSlotState,
    owned_binding_count: u32,
    binding_census_known: bool,
}

/// Crate-private, generation-fenced access to the one lifecycle-owned Fabric
/// session. The handle cannot construct, replace, or restart a session; it can
/// only run one operation while the exact generation is live. This remains the
/// sole path for a later typed Agent-port installer to share the same session.
#[derive(Clone)]
pub(crate) struct ManagedFabricControlHandle {
    generation: ManagedServiceGeneration,
    shared: Weak<RwLock<ManagedFabricSlot>>,
}

impl ManagedFabricControlHandle {
    #[must_use]
    pub(crate) const fn generation(&self) -> ManagedServiceGeneration {
        self.generation
    }

    pub(crate) async fn binding_census(&self) -> Result<u32, ManagedFabricControlError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(ManagedFabricControlError::OwnerRetired)?;
        let slot = shared.read().await;
        if slot.generation != self.generation {
            return Err(ManagedFabricControlError::GenerationFenced);
        }
        if !slot.binding_census_known {
            return Err(ManagedFabricControlError::BindingCensusUnknown);
        }
        match slot.state {
            ManagedFabricSlotState::Live(_) => Ok(slot.owned_binding_count),
            ManagedFabricSlotState::NotStarted => Err(ManagedFabricControlError::NotReady),
            ManagedFabricSlotState::Stopping | ManagedFabricSlotState::Stopped => {
                Err(ManagedFabricControlError::OwnerRetired)
            }
        }
    }

    pub(crate) async fn with_live_fabric<T>(
        &self,
        operation: impl for<'fabric> FnOnce(
            &'fabric FabricService,
        )
            -> Pin<Box<dyn Future<Output = T> + Send + 'fabric>>,
    ) -> Result<T, ManagedFabricControlError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(ManagedFabricControlError::OwnerRetired)?;
        let slot = shared.read().await;
        if slot.generation != self.generation {
            return Err(ManagedFabricControlError::GenerationFenced);
        }
        match &slot.state {
            ManagedFabricSlotState::Live(service) => Ok(operation(service).await),
            ManagedFabricSlotState::NotStarted => Err(ManagedFabricControlError::NotReady),
            ManagedFabricSlotState::Stopping | ManagedFabricSlotState::Stopped => {
                Err(ManagedFabricControlError::OwnerRetired)
            }
        }
    }

    /// Captures one experimental remote-mTLS link snapshot from the exact live
    /// generation. The caller supplies one absolute reactor deadline shared by
    /// write-fence acquisition and the Session observation; this method never
    /// retries or reopens a session.
    pub(crate) async fn observe_experimental_remote_mtls_links_once(
        &self,
        deadline: Instant,
    ) -> Result<ExperimentalRemoteMtlsLinkSnapshotV1, ManagedFabricExperimentalSnapshotError> {
        let shared =
            self.shared
                .upgrade()
                .ok_or(ManagedFabricExperimentalSnapshotError::Control(
                    ManagedFabricControlError::OwnerRetired,
                ))?;
        if Instant::now() >= deadline {
            return Err(ManagedFabricExperimentalSnapshotError::DeadlineExpired);
        }
        let mut slot = timeout_at(deadline, shared.write())
            .await
            .map_err(|_| ManagedFabricExperimentalSnapshotError::DeadlineExpired)?;
        if slot.generation != self.generation {
            return Err(ManagedFabricExperimentalSnapshotError::Control(
                ManagedFabricControlError::GenerationFenced,
            ));
        }
        let service = match &mut slot.state {
            ManagedFabricSlotState::Live(service) => service,
            ManagedFabricSlotState::NotStarted => {
                return Err(ManagedFabricExperimentalSnapshotError::Control(
                    ManagedFabricControlError::NotReady,
                ));
            }
            ManagedFabricSlotState::Stopping | ManagedFabricSlotState::Stopped => {
                return Err(ManagedFabricExperimentalSnapshotError::Control(
                    ManagedFabricControlError::OwnerRetired,
                ));
            }
        };
        if Instant::now() >= deadline {
            return Err(ManagedFabricExperimentalSnapshotError::DeadlineExpired);
        }
        timeout_at(deadline, service.observe_experimental_remote_mtls_links())
            .await
            .map_err(|_| ManagedFabricExperimentalSnapshotError::DeadlineExpired)?
            .map_err(ManagedFabricExperimentalSnapshotError::Observation)
    }

    /// Performs one binding mutation while holding the exact live generation
    /// fence and within one end-to-end lifecycle budget. Timing out before the
    /// write fence is acquired proves no effect; timing out after the mutation
    /// future is admitted is conservatively outcome-uncertain. A successful
    /// operation advances the owner-observed census.
    pub(crate) async fn mutate_live_fabric<T, E>(
        &self,
        mutation: ManagedFabricBindingMutation,
        budget: Duration,
        deadline_error: E,
        operation: impl for<'fabric> FnOnce(
            &'fabric mut FabricService,
        ) -> Pin<
            Box<dyn Future<Output = ManagedFabricMutationDisposition<T, E>> + Send + 'fabric>,
        >,
    ) -> Result<ManagedFabricMutationDisposition<T, E>, ManagedFabricControlError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(ManagedFabricControlError::OwnerRetired)?;
        let deadline = Instant::now() + budget;
        let mut deadline_error = Some(deadline_error);
        let mut slot = match timeout_at(deadline, shared.write()).await {
            Ok(slot) => slot,
            Err(_) => {
                return Ok(ManagedFabricMutationDisposition::RejectedNoEffect(
                    deadline_error
                        .take()
                        .expect("deadline error is consumed exactly once"),
                ));
            }
        };
        if slot.generation != self.generation {
            return Err(ManagedFabricControlError::GenerationFenced);
        }
        if !slot.binding_census_known {
            return Err(ManagedFabricControlError::BindingCensusUnknown);
        }
        let (retired_count, installed_count) = mutation.counts()?;
        let next_count = slot
            .owned_binding_count
            .checked_sub(retired_count)
            .ok_or(ManagedFabricControlError::BindingCensusUnderflow)?
            .checked_add(installed_count)
            .ok_or(ManagedFabricControlError::BindingCensusOverflow)?;
        let outcome = match &mut slot.state {
            ManagedFabricSlotState::Live(service) => {
                if Instant::now() >= deadline {
                    ManagedFabricMutationDisposition::RejectedNoEffect(
                        deadline_error
                            .take()
                            .expect("deadline error is consumed exactly once"),
                    )
                } else {
                    match timeout_at(deadline, operation(service)).await {
                        Ok(outcome) => outcome,
                        Err(_) => ManagedFabricMutationDisposition::Uncertain(
                            deadline_error
                                .take()
                                .expect("deadline error is consumed exactly once"),
                        ),
                    }
                }
            }
            ManagedFabricSlotState::NotStarted => {
                return Err(ManagedFabricControlError::NotReady);
            }
            ManagedFabricSlotState::Stopping | ManagedFabricSlotState::Stopped => {
                return Err(ManagedFabricControlError::OwnerRetired);
            }
        };
        match &outcome {
            ManagedFabricMutationDisposition::Committed(_) => {
                slot.owned_binding_count = next_count;
            }
            ManagedFabricMutationDisposition::RejectedNoEffect(_)
            | ManagedFabricMutationDisposition::RolledBackExact(_) => {}
            ManagedFabricMutationDisposition::Uncertain(_) => {
                slot.binding_census_known = false;
            }
        }
        Ok(outcome)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedFabricBindingMutation {
    InstallNew {
        physical_bindings: u32,
    },
    ReplaceExisting {
        retired_physical_bindings: u32,
        installed_physical_bindings: u32,
    },
    RetireExisting {
        physical_bindings: u32,
    },
}

impl ManagedFabricBindingMutation {
    fn counts(self) -> Result<(u32, u32), ManagedFabricControlError> {
        match self {
            Self::InstallNew { physical_bindings } if physical_bindings != 0 => {
                Ok((0, physical_bindings))
            }
            Self::ReplaceExisting {
                retired_physical_bindings,
                installed_physical_bindings,
            } if retired_physical_bindings != 0 && installed_physical_bindings != 0 => {
                Ok((retired_physical_bindings, installed_physical_bindings))
            }
            Self::RetireExisting { physical_bindings } if physical_bindings != 0 => {
                Ok((physical_bindings, 0))
            }
            _ => Err(ManagedFabricControlError::InvalidBindingMutation),
        }
    }
}

/// Caller-observed physical mutation boundary. Only `Committed` changes the
/// physical binding census. Proven no-effect and exact rollback preserve it;
/// an uncertain result permanently marks the live generation census unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedFabricMutationDisposition<T, E> {
    Committed(T),
    RejectedNoEffect(E),
    RolledBackExact(E),
    Uncertain(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedFabricControlError {
    NotReady,
    GenerationFenced,
    OwnerRetired,
    BindingCensusUnknown,
    BindingCensusOverflow,
    BindingCensusUnderflow,
    InvalidBindingMutation,
}

/// Exact failures from the bounded, generation-fenced experimental snapshot
/// path. Transport observations stay distinct from binding mutation outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedFabricExperimentalSnapshotError {
    Control(ManagedFabricControlError),
    DeadlineExpired,
    Observation(ExperimentalRemoteMtlsObservationErrorV1),
}

impl fmt::Display for ManagedFabricExperimentalSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(error) => write!(formatter, "managed Fabric control failed: {error:?}"),
            Self::DeadlineExpired => {
                formatter.write_str("managed Fabric experimental snapshot deadline expired")
            }
            Self::Observation(error) => {
                write!(
                    formatter,
                    "managed Fabric experimental snapshot failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for ManagedFabricExperimentalSnapshotError {}

const TRANSITION_PROJECTION_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-fabric-transition-projection.sha256.v1";
const RESOURCE_CENSUS_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-fabric-resource-census.sha256.v1";
const RAW_OUTCOME_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.managed-fabric-raw-outcome.sha256.v1";
const RECOVERY_QUARANTINE_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-fabric-recovery-quarantine.sha256.v1";
const MAX_SUCCESSOR_REPLAY_RECORDS: usize = 256;

pub(crate) struct ManagedFabricOwnerConfig {
    pub(crate) state_directory: PathBuf,
    pub(crate) store_instance_id: [u8; 32],
    pub(crate) owner_target_fingerprint: Digest32,
    pub(crate) projection: ManagedFabricManifestProjectionV1,
    pub(crate) runtime_host_epoch: u64,
    pub(crate) clock: RuntimeClock,
    pub(crate) response_key_ref: ApplyAuthKeyRef,
    pub(crate) response_signer: SigningKey,
}

pub(crate) struct ManagedFabricRuntimeCore {
    store: ManagedFabricStore,
    snapshot: ManagedFabricSnapshot,
    projection: ManagedFabricManifestProjectionV1,
    runtime_host_epoch: u64,
    clock: RuntimeClock,
    response_key_ref: ApplyAuthKeyRef,
    response_signer: SigningKey,
    cancellation: CancellationSource,
    assembly: Option<ManagedServiceAssembly>,
    fabric_control: Option<ManagedFabricControlHandle>,
    cleanup_exact_zero: bool,
    recovery_completed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedFabricApplyOutcome {
    Committed(ManagedFabricApplyTerminalReceiptV1),
    Replayed(ManagedFabricApplyTerminalReceiptV1),
}

/// Runtime-observed successor serving facts exposed only after async recovery
/// reaches a stable ready phase. This is not a wire contract; the endpoint
/// uses it as the narrow source of truth when constructing a signed managed
/// serving response for the request-time channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedFabricRecoveredObservation {
    pub(crate) target: RuntimeHostId,
    pub(crate) store_instance_id: [u8; 32],
    pub(crate) projection: ManagedFabricManifestProjectionV1,
    pub(crate) transition_projection_digest: Digest32,
    pub(crate) runtime_host_epoch: u64,
    pub(crate) clock: ClockReading,
    pub(crate) successor_snapshot_sequence: u64,
}

/// Exact predecessor authority that may be transferred to the PXAR-v7 stack
/// owner without replacing or reopening the live Fabric generation.
#[derive(Clone)]
pub(crate) struct ManagedFabricStackCutoverObservation {
    pub(crate) execution: ManagedFabricTargetExecutionV1,
    pub(crate) target_slice_digest: paraegox_runtime_contracts::provenance::TargetSliceDigest,
    pub(crate) generation: ManagedServiceGeneration,
    pub(crate) control: ManagedFabricControlHandle,
}

#[derive(Clone, Copy)]
struct TerminalSelection {
    outcome: ManagedFabricApplyTerminalOutcomeV1,
    lifecycle_effect: ManagedFabricApplyTerminalLifecycleEffectV1,
    head: ManagedFabricApplyTerminalHeadV1,
    generation: Option<ManagedServiceGeneration>,
    raw_code: u16,
    raw_context: Option<Digest32>,
}

impl ManagedFabricRuntimeCore {
    fn cutover(
        mut legacy_store: RuntimeStore,
        config: ManagedFabricOwnerConfig,
    ) -> Result<Self, ManagedFabricRuntimeError> {
        let projection_digest = transition_projection_digest(&config.projection)?;
        legacy_store.publish_managed_fabric_cutover_marker(projection_digest)?;
        drop(legacy_store);
        Self::open(config)
    }

    pub(crate) fn cutover_developer_local(
        mut legacy_store: RuntimeStore,
        config: ManagedFabricOwnerConfig,
    ) -> Result<Self, ManagedFabricRuntimeError> {
        let projection_digest = transition_projection_digest(&config.projection)?;
        legacy_store.publish_managed_fabric_cutover_marker(projection_digest)?;
        drop(legacy_store);
        let store = ManagedFabricStore::open_developer_local(
            &config.state_directory,
            config.store_instance_id,
            config.owner_target_fingerprint,
            projection_digest,
        )?;
        Self::from_preopened_store(store, config)
    }

    fn open(config: ManagedFabricOwnerConfig) -> Result<Self, ManagedFabricRuntimeError> {
        let projection_digest = transition_projection_digest(&config.projection)?;
        let mut store = ManagedFabricStore::open(
            &config.state_directory,
            config.store_instance_id,
            config.owner_target_fingerprint,
            projection_digest,
        )?;
        let reopening = store.snapshot_bytes()?.is_some();
        let snapshot = match store.snapshot_bytes()? {
            Some(frame) => ManagedFabricSnapshot::decode(
                frame,
                config.store_instance_id,
                config.owner_target_fingerprint,
                projection_digest,
                &config.projection,
            )?,
            None => {
                let initial = ManagedFabricSnapshot::try_initial(
                    config.store_instance_id,
                    config.owner_target_fingerprint,
                    projection_digest,
                    config.runtime_host_epoch,
                    &config.projection,
                )?;
                store.initialize(initial.canonical_wire())?;
                initial
            }
        };
        if config.runtime_host_epoch == 0
            || config.runtime_host_epoch < snapshot.runtime_host_epoch()
            || (reopening && config.runtime_host_epoch == snapshot.runtime_host_epoch())
            || config.clock.generation().value() == 0
        {
            return Err(ManagedFabricRuntimeError::RuntimeEpochRegressed);
        }
        let cleanup_exact_zero = snapshot.phase == ManagedFabricDurablePhase::ExactZero;
        Ok(Self {
            store,
            snapshot,
            projection: config.projection,
            runtime_host_epoch: config.runtime_host_epoch,
            clock: config.clock,
            response_key_ref: config.response_key_ref,
            response_signer: config.response_signer,
            cancellation: CancellationSource::root(),
            assembly: None,
            fabric_control: None,
            cleanup_exact_zero,
            recovery_completed: false,
        })
    }

    pub(crate) fn from_preopened_store(
        mut store: ManagedFabricStore,
        config: ManagedFabricOwnerConfig,
    ) -> Result<Self, ManagedFabricRuntimeError> {
        let projection_digest = transition_projection_digest(&config.projection)?;
        if store.marker().transition_projection_digest() != projection_digest {
            return Err(ManagedFabricRuntimeError::ProjectionMismatch);
        }
        let reopening = store.snapshot_bytes()?.is_some();
        let snapshot = match store.snapshot_bytes()? {
            Some(frame) => ManagedFabricSnapshot::decode(
                frame,
                config.store_instance_id,
                config.owner_target_fingerprint,
                projection_digest,
                &config.projection,
            )?,
            None => {
                let initial = ManagedFabricSnapshot::try_initial(
                    config.store_instance_id,
                    config.owner_target_fingerprint,
                    projection_digest,
                    config.runtime_host_epoch,
                    &config.projection,
                )?;
                store.initialize(initial.canonical_wire())?;
                initial
            }
        };
        if config.runtime_host_epoch == 0
            || config.runtime_host_epoch < snapshot.runtime_host_epoch()
            || (reopening && config.runtime_host_epoch == snapshot.runtime_host_epoch())
            || config.clock.generation().value() == 0
        {
            return Err(ManagedFabricRuntimeError::RuntimeEpochRegressed);
        }
        let cleanup_exact_zero = snapshot.phase == ManagedFabricDurablePhase::ExactZero;
        Ok(Self {
            store,
            snapshot,
            projection: config.projection,
            runtime_host_epoch: config.runtime_host_epoch,
            clock: config.clock,
            response_key_ref: config.response_key_ref,
            response_signer: config.response_signer,
            cancellation: CancellationSource::root(),
            assembly: None,
            fabric_control: None,
            cleanup_exact_zero,
            recovery_completed: false,
        })
    }

    fn lookup_terminal(
        &self,
        request: &ManagedFabricApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<Option<ManagedFabricApplyTerminalReceiptV1>, ManagedFabricRuntimeError> {
        let source_scope = request.provenance().source_scope();
        let operation = request.operation_id();
        let Some(record) =
            self.snapshot.terminals.iter().find(|record| {
                record.source_scope == source_scope && record.operation_id == operation
            })
        else {
            return Ok(None);
        };
        if record.request_digest != request.envelope_request_digest() {
            return Err(ManagedFabricRuntimeError::OperationConflict);
        }
        record
            .receipt
            .validate_against_request(request, channel)
            .map_err(|_| ManagedFabricRuntimeError::TerminalCorrelation)?;
        Ok(Some(record.receipt.clone()))
    }

    /// Returns an already committed terminal after the endpoint has
    /// authenticated the exact request. Temporal generation is deliberately
    /// not rechecked here: a signed terminal remains replayable after a
    /// RuntimeHost restart changes the owner clock generation.
    pub(crate) fn authenticated_terminal_replay(
        &self,
        request: &ManagedFabricApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> Result<Option<ManagedFabricApplyTerminalReceiptV1>, ManagedFabricRuntimeError> {
        self.validate_request(request, channel)?;
        self.lookup_terminal(request, channel)
    }

    pub(crate) fn clock_reading(&self) -> Result<ClockReading, ManagedFabricRuntimeError> {
        self.clock.reading().map_err(Into::into)
    }

    #[must_use]
    pub(crate) const fn stack_clock(&self) -> RuntimeClock {
        self.clock
    }

    #[must_use]
    pub(crate) const fn runtime_host_epoch(&self) -> u64 {
        self.runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn store_instance_id(&self) -> [u8; 32] {
        self.snapshot.store_instance_id()
    }

    #[must_use]
    pub(crate) fn owner_target_fingerprint(&self) -> Digest32 {
        self.snapshot.owner_target_fingerprint()
    }

    pub(crate) fn managed_agent_stack_projection_digest(&self) -> Option<Digest32> {
        self.store.managed_agent_stack_projection_digest()
    }

    pub(crate) fn managed_agent_stack_snapshot_bytes(
        &self,
    ) -> Result<Option<&[u8]>, ManagedFabricRuntimeError> {
        Ok(self.store.managed_agent_stack_snapshot_bytes()?)
    }

    pub(crate) fn initialize_managed_agent_stack(
        &mut self,
        projection_digest: Digest32,
        snapshot: &[u8],
    ) -> Result<(), ManagedFabricRuntimeError> {
        self.store
            .initialize_managed_agent_stack(projection_digest, snapshot)?;
        Ok(())
    }

    pub(crate) fn commit_managed_agent_stack(
        &mut self,
        snapshot: &[u8],
    ) -> Result<(), ManagedFabricRuntimeError> {
        self.store.commit_managed_agent_stack(snapshot)?;
        Ok(())
    }

    pub(crate) fn managed_model_agent_stack_projection_digest(&self) -> Option<Digest32> {
        self.store.managed_model_agent_stack_projection_digest()
    }

    pub(crate) fn managed_model_agent_stack_snapshot_bytes(
        &self,
    ) -> Result<Option<&[u8]>, ManagedFabricRuntimeError> {
        Ok(self.store.managed_model_agent_stack_snapshot_bytes()?)
    }

    pub(crate) fn initialize_managed_model_agent_stack(
        &mut self,
        projection_digest: Digest32,
        snapshot: &[u8],
    ) -> Result<(), ManagedFabricRuntimeError> {
        self.store
            .initialize_managed_model_agent_stack(projection_digest, snapshot)?;
        Ok(())
    }

    pub(crate) fn commit_managed_model_agent_stack(
        &mut self,
        snapshot: &[u8],
    ) -> Result<(), ManagedFabricRuntimeError> {
        self.store.commit_managed_model_agent_stack(snapshot)?;
        Ok(())
    }

    pub(crate) fn distributed_agent_stack_projection_digest(&self) -> Option<Digest32> {
        self.store.distributed_agent_stack_projection_digest()
    }

    pub(crate) fn distributed_agent_stack_snapshot_bytes(
        &self,
    ) -> Result<Option<&[u8]>, ManagedFabricRuntimeError> {
        Ok(self.store.distributed_agent_stack_snapshot_bytes()?)
    }

    pub(crate) fn initialize_distributed_agent_stack(
        &mut self,
        projection_digest: Digest32,
        snapshot: &[u8],
    ) -> Result<(), ManagedFabricRuntimeError> {
        self.store
            .initialize_distributed_agent_stack(projection_digest, snapshot)?;
        Ok(())
    }

    pub(crate) fn commit_distributed_agent_stack(
        &mut self,
        snapshot: &[u8],
    ) -> Result<(), ManagedFabricRuntimeError> {
        self.store.commit_distributed_agent_stack(snapshot)?;
        Ok(())
    }

    /// Returns the exact already-live PXAR-v6 predecessor only when it has no
    /// installed Agent bindings. This is the sole active cutover reuse seam.
    pub(crate) async fn stack_cutover_observation(
        &self,
    ) -> Result<ManagedFabricStackCutoverObservation, ManagedFabricRuntimeError> {
        if !self.recovery_completed || self.snapshot.phase != ManagedFabricDurablePhase::ActiveReady
        {
            return Err(ManagedFabricRuntimeError::RecoveryNotCompleted);
        }
        let active = self
            .snapshot
            .active
            .as_ref()
            .ok_or(ManagedFabricRuntimeError::InvalidDurableState)?;
        let control = self
            .control_handle()
            .map_err(|_| ManagedFabricRuntimeError::InvalidDurableState)?;
        if control.generation() != active.generation
            || control
                .binding_census()
                .await
                .map_err(|_| ManagedFabricRuntimeError::InvalidDurableState)?
                != 0
        {
            return Err(ManagedFabricRuntimeError::InvalidDurableState);
        }
        Ok(ManagedFabricStackCutoverObservation {
            execution: active.request.target_execution().clone(),
            target_slice_digest: active.request.target_slice_digest(),
            generation: active.generation,
            control,
        })
    }

    pub(crate) fn stack_live_control(
        &self,
        expected_generation: ManagedServiceGeneration,
    ) -> Result<ManagedFabricControlHandle, ManagedFabricRuntimeError> {
        let control = self
            .control_handle()
            .map_err(|_| ManagedFabricRuntimeError::InvalidDurableState)?;
        if control.generation() != expected_generation {
            return Err(ManagedFabricRuntimeError::InvalidDurableState);
        }
        Ok(control)
    }

    pub(crate) fn recovered_observation(
        &self,
    ) -> Result<ManagedFabricRecoveredObservation, ManagedFabricRuntimeError> {
        if !self.recovery_completed {
            return Err(ManagedFabricRuntimeError::RecoveryNotCompleted);
        }
        match self.snapshot.phase {
            ManagedFabricDurablePhase::ExactZero
                if self.assembly.is_none()
                    && self.fabric_control.is_none()
                    && self.cleanup_exact_zero => {}
            ManagedFabricDurablePhase::ActiveReady
                if self.assembly.is_some()
                    && self.fabric_control.is_some()
                    && !self.cleanup_exact_zero => {}
            _ => return Err(ManagedFabricRuntimeError::InvalidDurableState),
        }
        Ok(ManagedFabricRecoveredObservation {
            target: self.projection.target(),
            store_instance_id: self.snapshot.store_instance_id(),
            projection: self.projection.clone(),
            transition_projection_digest: transition_projection_digest(&self.projection)?,
            runtime_host_epoch: self.runtime_host_epoch,
            clock: self.clock_reading()?,
            successor_snapshot_sequence: self.snapshot.sequence(),
        })
    }

    pub(crate) async fn apply(
        &mut self,
        request: ManagedFabricApplyRequestV1,
        verified: VerifiedManagedFabricApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<ManagedFabricApplyOutcome, ManagedFabricRuntimeError> {
        if !self.recovery_completed {
            return Err(ManagedFabricRuntimeError::RecoveryNotCompleted);
        }
        self.validate_request(&request, response_channel)?;
        if let Some(receipt) = self.lookup_terminal(&request, response_channel)? {
            return Ok(ManagedFabricApplyOutcome::Replayed(receipt));
        }
        if matches!(
            self.snapshot.phase,
            ManagedFabricDurablePhase::Quarantined
                | ManagedFabricDurablePhase::Uncertain
                | ManagedFabricDurablePhase::StartIntent
                | ManagedFabricDurablePhase::ReplaceIntent
                | ManagedFabricDurablePhase::ReplaceOldStopped
                | ManagedFabricDurablePhase::DeactivateIntent
                | ManagedFabricDurablePhase::RecoveryIntent
        ) {
            return Err(ManagedFabricRuntimeError::RecoveryRequired);
        }
        match self.observe_deadline(verified) {
            Ok(()) => {}
            Err(ManagedFabricRuntimeError::DeadlineExpired) => {
                return self
                    .terminalize_authenticated_no_effect(request, response_channel, 10)
                    .await;
            }
            Err(error) => return Err(error),
        }
        let mut transition = match self.admit_transition(&request, verified) {
            Ok(transition) => transition,
            Err(ManagedFabricRuntimeError::ExpectedActiveMismatch) => {
                return self
                    .terminalize_authenticated_no_effect(request, response_channel, 11)
                    .await;
            }
            Err(ManagedFabricRuntimeError::StaleWriter) => {
                return self
                    .terminalize_authenticated_no_effect(request, response_channel, 12)
                    .await;
            }
            Err(ManagedFabricRuntimeError::StaleRevision) => {
                return self
                    .terminalize_authenticated_no_effect(request, response_channel, 13)
                    .await;
            }
            Err(error) => return Err(error),
        };
        match request.target_execution().mode() {
            ManagedFabricTargetModeV1::OneManagedFabricService => {
                self.apply_active(request, verified, response_channel, &mut transition)
                    .await
            }
            ManagedFabricTargetModeV1::EmptyDeactivate => {
                self.apply_empty(request, verified, response_channel, &mut transition)
                    .await
            }
        }
    }

    /// Reconciles a successor snapshot after RuntimeHost restart without ever
    /// assuming that a prior process effect completed. Every new start gets a
    /// fresh durable generation; exact canonical loopback ports are probed
    /// after the recovery intent and before the sole start effect.
    pub(crate) async fn recover(&mut self) -> Result<(), ManagedFabricRuntimeError> {
        if self.recovery_completed {
            return Ok(());
        }
        if self.assembly.is_some() || self.fabric_control.is_some() {
            return Err(ManagedFabricRuntimeError::RecoveryWhileLive);
        }
        match self.snapshot.phase {
            ManagedFabricDurablePhase::ExactZero => {
                self.cleanup_exact_zero = true;
                if self.snapshot.runtime_host_epoch() != self.runtime_host_epoch {
                    self.commit_transition(self.snapshot.transition())?;
                }
                self.recovery_completed = true;
                return Ok(());
            }
            ManagedFabricDurablePhase::Quarantined => {
                return Err(ManagedFabricRuntimeError::RecoveryQuarantined);
            }
            ManagedFabricDurablePhase::DeactivateIntent => {
                return self.recover_deactivate().await;
            }
            ManagedFabricDurablePhase::Uncertain
                if self.snapshot.pending.as_ref().is_some_and(|pending| {
                    pending.kind == ManagedFabricPendingKind::Deactivate
                }) =>
            {
                return self.recover_deactivate().await;
            }
            ManagedFabricDurablePhase::ActiveReady
            | ManagedFabricDurablePhase::StartIntent
            | ManagedFabricDurablePhase::ReplaceIntent
            | ManagedFabricDurablePhase::ReplaceOldStopped
            | ManagedFabricDurablePhase::RecoveryIntent
            | ManagedFabricDurablePhase::Uncertain => {}
        }

        let (request, response_channel) = match self.snapshot.phase {
            ManagedFabricDurablePhase::ActiveReady => {
                let active = self
                    .snapshot
                    .active
                    .as_ref()
                    .ok_or(ManagedFabricRuntimeError::InvalidDurableState)?;
                (active.request.clone(), active.response_channel)
            }
            _ => {
                let pending = self
                    .snapshot
                    .pending
                    .as_ref()
                    .ok_or(ManagedFabricRuntimeError::InvalidDurableState)?;
                if pending.request.target_execution().mode()
                    != ManagedFabricTargetModeV1::OneManagedFabricService
                {
                    return Err(ManagedFabricRuntimeError::InvalidDurableState);
                }
                (pending.request.clone(), pending.response_channel)
            }
        };
        let generation = next_generation(self.snapshot.generation_high_water())?;
        let (clock_generation, admitted_at_nanos, deadline_nanos) =
            self.recovery_timing(&request)?;
        let mut intent = self.snapshot.transition();
        intent.generation_high_water = generation.value();
        intent.phase = ManagedFabricDurablePhase::RecoveryIntent;
        intent.pending = Some(ManagedFabricDurablePending {
            kind: ManagedFabricPendingKind::RecoverActive,
            generation: Some(generation),
            admitted_clock_generation: clock_generation,
            admitted_at_nanos,
            deadline_nanos,
            response_channel,
            request: request.clone(),
        });
        intent.quarantine_reason = None;
        self.commit_transition(intent)?;

        if let Err(failure) = self.probe_recovery_ports() {
            return self.quarantine_recovery(failure.reason_digest()?, 40).await;
        }
        if self.pending_deadline_expired()? {
            return self
                .quarantine_recovery(recovery_reason_digest(41, 0, 0)?, 41)
                .await;
        }
        if !self.start_live(&request, generation).await? {
            return self
                .quarantine_recovery(recovery_reason_digest(42, request_port(&request)?, 0)?, 42)
                .await;
        }

        let mut ready = self.snapshot.transition();
        ready.phase = ManagedFabricDurablePhase::ActiveReady;
        ready.active = Some(ManagedFabricDurableActive {
            generation,
            response_channel,
            request: request.clone(),
        });
        ready.pending = None;
        ready.quarantine_reason = None;
        if self.lookup_terminal(&request, response_channel)?.is_none() {
            let receipt = self
                .build_terminal(
                    &request,
                    response_channel,
                    TerminalSelection {
                        outcome: ManagedFabricApplyTerminalOutcomeV1::ActiveReady,
                        lifecycle_effect:
                            ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                        head: ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
                        generation: Some(generation),
                        raw_code: 43,
                        raw_context: None,
                    },
                )
                .await?;
            insert_terminal(&mut ready.terminals, &request, receipt)?;
        }
        if let Err(error) = self.commit_transition(ready) {
            let _ = self.stop_live().await;
            return Err(error);
        }
        self.recovery_completed = true;
        Ok(())
    }

    async fn recover_deactivate(&mut self) -> Result<(), ManagedFabricRuntimeError> {
        let pending = self
            .snapshot
            .pending
            .clone()
            .ok_or(ManagedFabricRuntimeError::InvalidDurableState)?;
        if pending.kind != ManagedFabricPendingKind::Deactivate
            || pending.request.target_execution().mode()
                != ManagedFabricTargetModeV1::EmptyDeactivate
        {
            return Err(ManagedFabricRuntimeError::InvalidDurableState);
        }
        // A successor sequence at the new RuntimeHost epoch durably records
        // takeover before the port probe can influence recovery selection.
        self.commit_transition(self.snapshot.transition())?;
        if let Err(failure) = self.probe_recovery_ports() {
            return self.quarantine_recovery(failure.reason_digest()?, 44).await;
        }
        self.cleanup_exact_zero = true;
        let mut exact_zero = self.snapshot.transition();
        exact_zero.phase = ManagedFabricDurablePhase::ExactZero;
        exact_zero.active = None;
        exact_zero.pending = None;
        exact_zero.quarantine_reason = None;
        if self
            .lookup_terminal(&pending.request, pending.response_channel)?
            .is_none()
        {
            let receipt = self
                .build_terminal(
                    &pending.request,
                    pending.response_channel,
                    TerminalSelection {
                        outcome: ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero,
                        lifecycle_effect:
                            ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                        head: ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
                        generation: None,
                        raw_code: 45,
                        raw_context: None,
                    },
                )
                .await?;
            insert_terminal(&mut exact_zero.terminals, &pending.request, receipt)?;
        }
        self.commit_transition(exact_zero)?;
        self.recovery_completed = true;
        Ok(())
    }

    fn recovery_timing(
        &self,
        request: &ManagedFabricApplyRequestV1,
    ) -> Result<(ClockGeneration, u64, u64), ManagedFabricRuntimeError> {
        let service = request
            .target_execution()
            .service()
            .ok_or(ManagedFabricRuntimeError::MissingServiceSpec)?;
        let budgets = service.lifecycle_budgets();
        let total = [
            ManagedServiceLifecycleStage::Prepare,
            ManagedServiceLifecycleStage::Start,
            ManagedServiceLifecycleStage::Readiness,
        ]
        .into_iter()
        .try_fold(0_u64, |total, stage| {
            total.checked_add(budgets.for_stage(stage).value())
        })
        .ok_or(ManagedFabricRuntimeError::DeadlineOverflow)?;
        let reading = self.clock.reading()?;
        let deadline = reading
            .now()
            .value()
            .checked_add(total)
            .ok_or(ManagedFabricRuntimeError::DeadlineOverflow)?;
        Ok((reading.generation(), reading.now().value(), deadline))
    }

    fn probe_recovery_ports(&self) -> Result<(), RecoveryProbeFailure> {
        let mut ports = BTreeSet::new();
        if let Some(active) = &self.snapshot.active {
            let port = request_port(&active.request).map_err(|_| RecoveryProbeFailure {
                port: 0,
                raw_os_error: 0,
            })?;
            ports.insert(port);
        }
        if let Some(pending) = &self.snapshot.pending
            && pending.request.target_execution().mode()
                == ManagedFabricTargetModeV1::OneManagedFabricService
        {
            let port = request_port(&pending.request).map_err(|_| RecoveryProbeFailure {
                port: 0,
                raw_os_error: 0,
            })?;
            ports.insert(port);
        }
        if ports.is_empty() && self.snapshot.active.is_some() {
            return Err(RecoveryProbeFailure {
                port: 0,
                raw_os_error: 0,
            });
        }
        for port in ports {
            match TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)) {
                Ok(listener) => drop(listener),
                Err(error) => {
                    return Err(RecoveryProbeFailure {
                        port,
                        raw_os_error: error.raw_os_error().unwrap_or(0),
                    });
                }
            }
        }
        Ok(())
    }

    async fn quarantine_recovery(
        &mut self,
        reason: Digest32,
        raw_code: u16,
    ) -> Result<(), ManagedFabricRuntimeError> {
        let pending = self
            .snapshot
            .pending
            .clone()
            .ok_or(ManagedFabricRuntimeError::InvalidDurableState)?;
        let mut quarantined = self.snapshot.transition();
        quarantined.phase = ManagedFabricDurablePhase::Quarantined;
        quarantined.quarantine_reason = Some(reason);
        let has_terminal = self
            .lookup_terminal(&pending.request, pending.response_channel)?
            .is_some();
        match pending.request.target_execution().mode() {
            ManagedFabricTargetModeV1::OneManagedFabricService => {
                let generation = pending
                    .generation
                    .ok_or(ManagedFabricRuntimeError::InvalidDurableState)?;
                quarantined.active = Some(ManagedFabricDurableActive {
                    generation,
                    response_channel: pending.response_channel,
                    request: pending.request.clone(),
                });
                quarantined.pending = None;
                if !has_terminal {
                    let receipt = self
                        .build_terminal(
                            &pending.request,
                            pending.response_channel,
                            TerminalSelection {
                                outcome: ManagedFabricApplyTerminalOutcomeV1::Quarantined,
                                lifecycle_effect:
                                    ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                                head: ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
                                generation: Some(generation),
                                raw_code,
                                raw_context: Some(reason),
                            },
                        )
                        .await?;
                    insert_terminal(&mut quarantined.terminals, &pending.request, receipt)?;
                }
            }
            ManagedFabricTargetModeV1::EmptyDeactivate => {
                let generation = quarantined
                    .active
                    .as_ref()
                    .map(|active| active.generation)
                    .ok_or(ManagedFabricRuntimeError::InvalidDurableState)?;
                if !has_terminal {
                    let receipt = self
                        .build_terminal(
                            &pending.request,
                            pending.response_channel,
                            TerminalSelection {
                                outcome: ManagedFabricApplyTerminalOutcomeV1::Uncertain,
                                lifecycle_effect:
                                    ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                                head: preserved_head(quarantined.active.as_ref()),
                                generation: Some(generation),
                                raw_code,
                                raw_context: Some(reason),
                            },
                        )
                        .await?;
                    insert_terminal(&mut quarantined.terminals, &pending.request, receipt)?;
                }
            }
        }
        self.commit_transition(quarantined)?;
        Err(ManagedFabricRuntimeError::RecoveryQuarantined)
    }

    fn validate_request(
        &self,
        request: &ManagedFabricApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<(), ManagedFabricRuntimeError> {
        request
            .validate_expected_store(self.snapshot.store_instance_id())
            .map_err(|_| ManagedFabricRuntimeError::RequestRejected)?;
        request
            .validate_projection(&self.projection)
            .map_err(|_| ManagedFabricRuntimeError::ProjectionMismatch)?;
        if request.target() != self.projection.target()
            || response_channel.target() != request.target()
        {
            return Err(ManagedFabricRuntimeError::RequestRejected);
        }
        Ok(())
    }

    fn observe_deadline(
        &self,
        verified: VerifiedManagedFabricApplyIngressV1,
    ) -> Result<(), ManagedFabricRuntimeError> {
        let reading = self.clock.reading()?;
        if reading.generation() != verified.clock_generation()
            || reading.now().value() >= verified.deadline_nanos()
        {
            return Err(ManagedFabricRuntimeError::DeadlineExpired);
        }
        Ok(())
    }

    fn admit_transition(
        &self,
        request: &ManagedFabricApplyRequestV1,
        verified: VerifiedManagedFabricApplyIngressV1,
    ) -> Result<ManagedFabricSnapshotTransition, ManagedFabricRuntimeError> {
        self.validate_cas(request)?;
        let control = request.control_commitment().control();
        let writer = control.writer_context();
        let claim = writer.proof().claim();
        let proof_digest = verified.authenticated().proof_envelope_digest();
        let writer_fence = match self.snapshot.writer_fence {
            None => ManagedFabricWriterFence {
                source_scope: claim.source_scope(),
                writer: claim.writer(),
                principal: request.authentication().claim().principal(),
                epoch: claim.epoch().value(),
                proof_envelope_digest: proof_digest,
            },
            Some(current)
                if current.source_scope == claim.source_scope()
                    && current.writer == claim.writer()
                    && current.epoch == claim.epoch().value()
                    && current.proof_envelope_digest == proof_digest =>
            {
                current
            }
            Some(current)
                if current.source_scope == claim.source_scope()
                    && claim.epoch().value() > current.epoch
                    && claim.supersedes_through_epoch().value() >= current.epoch =>
            {
                ManagedFabricWriterFence {
                    source_scope: claim.source_scope(),
                    writer: claim.writer(),
                    principal: request.authentication().claim().principal(),
                    epoch: claim.epoch().value(),
                    proof_envelope_digest: proof_digest,
                }
            }
            Some(_) => return Err(ManagedFabricRuntimeError::StaleWriter),
        };
        let provenance = request.provenance();
        let revision_high_water = match self.snapshot.revision_high_water {
            None => ManagedFabricRevisionHighWater {
                source_scope: provenance.source_scope(),
                revision: provenance.source_revision().value(),
                source_plan_digest: provenance.source_plan_digest(),
            },
            Some(current)
                if current.source_scope == provenance.source_scope()
                    && (provenance.source_revision().value() > current.revision
                        || (provenance.source_revision().value() == current.revision
                            && provenance.source_plan_digest() == current.source_plan_digest)) =>
            {
                ManagedFabricRevisionHighWater {
                    source_scope: provenance.source_scope(),
                    revision: provenance.source_revision().value(),
                    source_plan_digest: provenance.source_plan_digest(),
                }
            }
            Some(_) => return Err(ManagedFabricRuntimeError::StaleRevision),
        };
        let mut transition = self.snapshot.transition();
        transition.writer_fence = Some(writer_fence);
        transition.revision_high_water = Some(revision_high_water);
        insert_replay(
            &mut transition.tenure_nonces,
            ManagedFabricReplayRecord {
                identity: verified.authenticated().tenure_nonce_identity(),
                value_digest: proof_digest,
            },
        )?;
        insert_replay(
            &mut transition.request_nonces,
            ManagedFabricReplayRecord {
                identity: verified.authenticated().request_nonce_identity(),
                value_digest: request.envelope_request_digest(),
            },
        )?;
        insert_replay(
            &mut transition.temporal_lineages,
            ManagedFabricReplayRecord {
                identity: verified.authenticated().temporal_lineage_identity(),
                value_digest: request.envelope_request_digest(),
            },
        )?;
        Ok(transition)
    }

    fn validate_cas(
        &self,
        request: &ManagedFabricApplyRequestV1,
    ) -> Result<(), ManagedFabricRuntimeError> {
        let current = self
            .snapshot
            .active
            .as_ref()
            .map(|active| active.request.target_slice_digest());
        match (
            request.control_commitment().control().expected_active(),
            current,
        ) {
            (ExpectedActive::None, None) => Ok(()),
            (ExpectedActive::Exact(expected), Some(actual)) if expected == actual => Ok(()),
            _ => Err(ManagedFabricRuntimeError::ExpectedActiveMismatch),
        }
    }

    async fn apply_active(
        &mut self,
        request: ManagedFabricApplyRequestV1,
        verified: VerifiedManagedFabricApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
        transition: &mut ManagedFabricSnapshotTransition,
    ) -> Result<ManagedFabricApplyOutcome, ManagedFabricRuntimeError> {
        let generation = next_generation(self.snapshot.generation_high_water())?;
        let replacing = self.snapshot.active.is_some();
        transition.generation_high_water = generation.value();
        transition.phase = if replacing {
            ManagedFabricDurablePhase::ReplaceIntent
        } else {
            ManagedFabricDurablePhase::StartIntent
        };
        transition.pending = Some(ManagedFabricDurablePending {
            kind: if replacing {
                ManagedFabricPendingKind::Replace
            } else {
                ManagedFabricPendingKind::Start
            },
            generation: Some(generation),
            admitted_clock_generation: verified.clock_generation(),
            admitted_at_nanos: verified.admitted_at_nanos(),
            deadline_nanos: verified.deadline_nanos(),
            response_channel,
            request: request.clone(),
        });
        transition.quarantine_reason = None;
        self.commit_transition(transition.clone())?;

        if self.pending_deadline_expired()? {
            return self
                .terminalize_no_effect_from_intent(request, response_channel, 20)
                .await;
        }

        if replacing {
            if !self.stop_live().await? {
                return self
                    .terminalize_uncertain(
                        request,
                        response_channel,
                        generation,
                        TerminalSelection {
                            outcome: ManagedFabricApplyTerminalOutcomeV1::Uncertain,
                            lifecycle_effect:
                                ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                            head: preserved_head(self.snapshot.active.as_ref()),
                            generation: Some(generation),
                            raw_code: 2,
                            raw_context: None,
                        },
                    )
                    .await;
            }
            let mut old_stopped = self.snapshot.transition();
            old_stopped.phase = ManagedFabricDurablePhase::ReplaceOldStopped;
            self.commit_transition(old_stopped)?;
        }

        if self.pending_deadline_expired()? {
            if replacing {
                return self
                    .terminalize_uncertain(
                        request,
                        response_channel,
                        generation,
                        TerminalSelection {
                            outcome: ManagedFabricApplyTerminalOutcomeV1::Uncertain,
                            lifecycle_effect:
                                ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                            head: preserved_head(self.snapshot.active.as_ref()),
                            generation: Some(generation),
                            raw_code: 22,
                            raw_context: None,
                        },
                    )
                    .await;
            }
            return self
                .terminalize_no_effect_from_intent(request, response_channel, 22)
                .await;
        }
        match self.start_live(&request, generation).await? {
            true => {
                let active = ManagedFabricDurableActive {
                    generation,
                    response_channel,
                    request: request.clone(),
                };
                let mut final_transition = self.snapshot.transition();
                final_transition.phase = ManagedFabricDurablePhase::ActiveReady;
                final_transition.active = Some(active);
                final_transition.pending = None;
                final_transition.quarantine_reason = None;
                let receipt = self
                    .build_terminal(
                        &request,
                        response_channel,
                        TerminalSelection {
                            outcome: ManagedFabricApplyTerminalOutcomeV1::ActiveReady,
                            lifecycle_effect:
                                ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                            head: ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
                            generation: Some(generation),
                            raw_code: 1,
                            raw_context: None,
                        },
                    )
                    .await?;
                insert_terminal(&mut final_transition.terminals, &request, receipt.clone())?;
                if let Err(error) = self.commit_transition(final_transition) {
                    let _ = self.stop_live().await;
                    return Err(error);
                }
                Ok(ManagedFabricApplyOutcome::Committed(receipt))
            }
            false => {
                self.terminalize_uncertain(
                    request,
                    response_channel,
                    generation,
                    TerminalSelection {
                        outcome: ManagedFabricApplyTerminalOutcomeV1::Uncertain,
                        lifecycle_effect:
                            ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                        head: preserved_head(self.snapshot.active.as_ref()),
                        generation: Some(generation),
                        raw_code: 3,
                        raw_context: None,
                    },
                )
                .await
            }
        }
    }

    async fn apply_empty(
        &mut self,
        request: ManagedFabricApplyRequestV1,
        verified: VerifiedManagedFabricApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
        transition: &mut ManagedFabricSnapshotTransition,
    ) -> Result<ManagedFabricApplyOutcome, ManagedFabricRuntimeError> {
        let had_active = self.snapshot.active.is_some();
        if had_active {
            transition.phase = ManagedFabricDurablePhase::DeactivateIntent;
            transition.pending = Some(ManagedFabricDurablePending {
                kind: ManagedFabricPendingKind::Deactivate,
                generation: None,
                admitted_clock_generation: verified.clock_generation(),
                admitted_at_nanos: verified.admitted_at_nanos(),
                deadline_nanos: verified.deadline_nanos(),
                response_channel,
                request: request.clone(),
            });
            transition.quarantine_reason = None;
            self.commit_transition(transition.clone())?;
            if self.pending_deadline_expired()? {
                return self
                    .terminalize_no_effect_from_intent(request, response_channel, 23)
                    .await;
            }
            if !self.stop_live().await? {
                let generation = self
                    .snapshot
                    .active
                    .as_ref()
                    .map(|active| active.generation)
                    .ok_or(ManagedFabricRuntimeError::InvalidDurableState)?;
                return self
                    .terminalize_uncertain(
                        request,
                        response_channel,
                        generation,
                        TerminalSelection {
                            outcome: ManagedFabricApplyTerminalOutcomeV1::Uncertain,
                            lifecycle_effect:
                                ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted,
                            head: preserved_head(self.snapshot.active.as_ref()),
                            generation: Some(generation),
                            raw_code: 4,
                            raw_context: None,
                        },
                    )
                    .await;
            }
        }
        let mut final_transition = self.snapshot.transition();
        final_transition.phase = ManagedFabricDurablePhase::ExactZero;
        final_transition.active = None;
        final_transition.pending = None;
        final_transition.quarantine_reason = None;
        let receipt = self
            .build_terminal(
                &request,
                response_channel,
                TerminalSelection {
                    outcome: ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero,
                    lifecycle_effect: if had_active {
                        ManagedFabricApplyTerminalLifecycleEffectV1::MayHaveStarted
                    } else {
                        ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted
                    },
                    head: ManagedFabricApplyTerminalHeadV1::CommittedIncoming,
                    generation: None,
                    raw_code: if had_active { 5 } else { 6 },
                    raw_context: None,
                },
            )
            .await?;
        insert_terminal(&mut final_transition.terminals, &request, receipt.clone())?;
        self.commit_transition(final_transition)?;
        Ok(ManagedFabricApplyOutcome::Committed(receipt))
    }

    fn pending_deadline_expired(&self) -> Result<bool, ManagedFabricRuntimeError> {
        let pending = self
            .snapshot
            .pending
            .as_ref()
            .ok_or(ManagedFabricRuntimeError::InvalidDurableState)?;
        let reading = self.clock.reading()?;
        Ok(reading.generation() != pending.admitted_clock_generation
            || reading.now().value() >= pending.deadline_nanos)
    }

    async fn terminalize_no_effect_from_intent(
        &mut self,
        request: ManagedFabricApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        raw_code: u16,
    ) -> Result<ManagedFabricApplyOutcome, ManagedFabricRuntimeError> {
        let mut transition = self.snapshot.transition();
        transition.phase = if transition.active.is_some() {
            ManagedFabricDurablePhase::ActiveReady
        } else {
            ManagedFabricDurablePhase::ExactZero
        };
        transition.pending = None;
        transition.quarantine_reason = None;
        let receipt = self
            .build_terminal(
                &request,
                response_channel,
                TerminalSelection {
                    outcome: ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected,
                    lifecycle_effect: ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted,
                    head: preserved_head(transition.active.as_ref()),
                    generation: None,
                    raw_code,
                    raw_context: None,
                },
            )
            .await?;
        insert_terminal(&mut transition.terminals, &request, receipt.clone())?;
        self.commit_transition(transition)?;
        Ok(ManagedFabricApplyOutcome::Committed(receipt))
    }

    /// Persists an authenticated, correlated rejection without advancing any
    /// writer fence, source revision, or replay high-water.  The terminal is
    /// the sole mutation and reports the Runtime-observed durable head.
    async fn terminalize_authenticated_no_effect(
        &mut self,
        request: ManagedFabricApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        raw_code: u16,
    ) -> Result<ManagedFabricApplyOutcome, ManagedFabricRuntimeError> {
        let mut transition = self.snapshot.transition();
        let receipt = self
            .build_terminal(
                &request,
                response_channel,
                TerminalSelection {
                    outcome: ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected,
                    lifecycle_effect: ManagedFabricApplyTerminalLifecycleEffectV1::ProvenNotStarted,
                    head: preserved_head(transition.active.as_ref()),
                    generation: None,
                    raw_code,
                    raw_context: None,
                },
            )
            .await?;
        insert_terminal(&mut transition.terminals, &request, receipt.clone())?;
        self.commit_transition(transition)?;
        Ok(ManagedFabricApplyOutcome::Committed(receipt))
    }

    async fn terminalize_uncertain(
        &mut self,
        request: ManagedFabricApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        _generation: ManagedServiceGeneration,
        selection: TerminalSelection,
    ) -> Result<ManagedFabricApplyOutcome, ManagedFabricRuntimeError> {
        let mut transition = self.snapshot.transition();
        transition.phase = ManagedFabricDurablePhase::Uncertain;
        let receipt = self
            .build_terminal(&request, response_channel, selection)
            .await?;
        insert_terminal(&mut transition.terminals, &request, receipt.clone())?;
        self.commit_transition(transition)?;
        Ok(ManagedFabricApplyOutcome::Committed(receipt))
    }

    async fn start_live(
        &mut self,
        request: &ManagedFabricApplyRequestV1,
        generation: ManagedServiceGeneration,
    ) -> Result<bool, ManagedFabricRuntimeError> {
        self.start_live_execution(request.target_execution(), generation)
            .await
    }

    pub(crate) async fn start_live_execution(
        &mut self,
        execution: &ManagedFabricTargetExecutionV1,
        generation: ManagedServiceGeneration,
    ) -> Result<bool, ManagedFabricRuntimeError> {
        let spec = execution
            .service()
            .ok_or(ManagedFabricRuntimeError::MissingServiceSpec)?;
        let (implementation, control) =
            RuntimeManagedFabricService::try_from_execution(execution, generation)?;
        let mut assembly = ManagedServiceAssembly::new(
            spec,
            generation,
            Box::new(implementation),
            self.clock,
            &self.cancellation,
        );
        let ready = assembly.startup().await == ManagedServiceStartupOutcome::Ready;
        if ready {
            self.fabric_control = Some(control);
            self.assembly = Some(assembly);
            self.cleanup_exact_zero = false;
        } else {
            let exact_zero = assembly.shutdown().await.exact_zero();
            self.cleanup_exact_zero = exact_zero;
            if !exact_zero {
                self.fabric_control = Some(control);
                self.assembly = Some(assembly);
            }
        }
        Ok(ready)
    }

    fn control_handle(&self) -> Result<ManagedFabricControlHandle, ManagedFabricControlError> {
        self.fabric_control
            .clone()
            .ok_or(ManagedFabricControlError::NotReady)
    }

    async fn stop_live(&mut self) -> Result<bool, ManagedFabricRuntimeError> {
        let control = self.fabric_control.take();
        let Some(mut assembly) = self.assembly.take() else {
            return Ok(self.cleanup_exact_zero);
        };
        let exact_zero = assembly.shutdown().await.exact_zero();
        self.cleanup_exact_zero = exact_zero;
        if !exact_zero {
            self.fabric_control = control;
            self.assembly = Some(assembly);
        }
        Ok(exact_zero)
    }

    pub(crate) async fn stop_live_for_stack(&mut self) -> Result<bool, ManagedFabricRuntimeError> {
        self.stop_live().await
    }

    async fn resource_census_digest(&self) -> Result<Digest32, ManagedFabricRuntimeError> {
        let mut session_live = false;
        let mut generation = 0_u64;
        let mut owned_binding_count = 0_u32;
        let mut binding_census_known = true;
        if let Some(control) = &self.fabric_control
            && let Some(shared) = control.shared.upgrade()
        {
            let slot = shared.read().await;
            if slot.generation == control.generation
                && matches!(slot.state, ManagedFabricSlotState::Live(_))
            {
                session_live = true;
                generation = slot.generation.value();
                owned_binding_count = slot.owned_binding_count;
                binding_census_known = slot.binding_census_known;
            }
        }
        let mut builder = Digest32Builder::try_new(RESOURCE_CENSUS_DIGEST_DOMAIN)?;
        builder.field_u16(if session_live { 1 } else { 0 })?;
        builder.field_u64(generation)?;
        builder.field_bytes(&owned_binding_count.to_be_bytes())?;
        builder.field_u16(if binding_census_known { 1 } else { 0 })?;
        builder.field_u16(if self.cleanup_exact_zero { 1 } else { 0 })?;
        Ok(builder.finish())
    }

    async fn build_terminal(
        &self,
        request: &ManagedFabricApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        selection: TerminalSelection,
    ) -> Result<ManagedFabricApplyTerminalReceiptV1, ManagedFabricRuntimeError> {
        let reading = self.clock.reading()?;
        let completion_sequence = self
            .snapshot
            .sequence()
            .checked_add(1)
            .ok_or(ManagedFabricRuntimeError::SequenceOverflow)?;
        let terminal_state = ManagedFabricApplyTerminalStateV1::try_new(
            selection.outcome,
            selection.lifecycle_effect,
            selection.head,
            selection.generation,
        )?;
        let evidence = ManagedFabricApplyTerminalEvidenceV1::try_new(
            self.resource_census_digest().await?,
            raw_outcome_digest(selection.raw_code, selection.raw_context, request)?,
            self.runtime_host_epoch,
            completion_sequence,
            reading.generation(),
            reading.now().value(),
        )?;
        let facts = ManagedFabricApplyTerminalFactsV1::try_new(request, terminal_state, evidence)?;
        let algorithm = ApplyAuthAlgorithm::try_new(1)
            .map_err(|_| ManagedFabricRuntimeError::SignerConfiguration)?;
        let auth_claim = ManagedFabricApplyTerminalReceiptAuthClaimV1::try_new(
            response_channel,
            self.response_key_ref,
            algorithm,
            1,
        )?;
        let draft = ManagedFabricApplyTerminalReceiptDraftV1::try_new(
            request,
            facts,
            response_channel,
            auth_claim,
        )?;
        let signature = self
            .response_signer
            .sign(draft.signing_transcript()?.as_bytes());
        Ok(draft.finalize(&signature.to_bytes())?)
    }

    fn commit_transition(
        &mut self,
        transition: ManagedFabricSnapshotTransition,
    ) -> Result<(), ManagedFabricRuntimeError> {
        let next = self.snapshot.try_successor_at_epoch(
            self.runtime_host_epoch,
            transition,
            &self.projection,
        )?;
        self.store.commit(next.canonical_wire())?;
        self.snapshot = next;
        Ok(())
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), ManagedFabricRuntimeError> {
        self.recovery_completed = false;
        if self.assembly.is_some() && !self.stop_live().await? {
            return Err(ManagedFabricRuntimeError::ShutdownUncertain);
        }
        Ok(())
    }
}

impl ManagedServiceImplementation for RuntimeManagedFabricService {
    fn prepare<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
        Box::pin(async move {
            if context.cancellation().is_cancelled() {
                return ManagedServiceCompletion::failed(attempt);
            }
            let config = match self.requested.take() {
                Some(RuntimeManagedFabricPrepareRequest::LoopbackEndpoint(endpoint)) => {
                    let endpoint = match SessionEndpoint::try_new(endpoint.as_str().to_owned()) {
                        Ok(mapped) if mapped.as_str() == endpoint.as_str() => mapped,
                        _ => return ManagedServiceCompletion::failed(attempt),
                    };
                    match FabricServiceConfig::try_peer(vec![endpoint], Vec::new()) {
                        Ok(config) => config,
                        Err(_) => return ManagedServiceCompletion::failed(attempt),
                    }
                }
                Some(RuntimeManagedFabricPrepareRequest::ExactConfig(config)) => config,
                None => return ManagedServiceCompletion::failed(attempt),
            };
            self.prepared = Some(config);
            ManagedServiceCompletion::succeeded(attempt, ())
        })
    }

    fn start<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
        Box::pin(async move {
            if context.cancellation().is_cancelled() {
                return ManagedServiceCompletion::failed(attempt);
            }
            let Some(config) = self.prepared.take() else {
                return ManagedServiceCompletion::failed(attempt);
            };
            match FabricService::start(config).await {
                Ok(service) => {
                    let mut slot = self.shared.write().await;
                    if !matches!(slot.state, ManagedFabricSlotState::NotStarted) {
                        drop(slot);
                        let _ = service.shutdown().await;
                        return ManagedServiceCompletion::failed(attempt);
                    }
                    slot.state = ManagedFabricSlotState::Live(service);
                    ManagedServiceCompletion::succeeded(attempt, ())
                }
                Err(_) => ManagedServiceCompletion::failed(attempt),
            }
        })
    }

    fn readiness<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<ManagedServiceReadiness>> {
        Box::pin(async move {
            if context.cancellation().is_cancelled() {
                return ManagedServiceCompletion::failed(attempt);
            }
            // Current evidence is deliberately local: successful
            // `FabricService::start` proves only that the owned session opened.
            // It does not assert any remote peer, route, or Agent port is ready.
            let live = {
                let slot = self.shared.read().await;
                matches!(slot.state, ManagedFabricSlotState::Live(_))
            };
            let readiness = if live {
                ManagedServiceReadiness::Ready
            } else {
                ManagedServiceReadiness::NotReady
            };
            ManagedServiceCompletion::succeeded(attempt, readiness)
        })
    }

    fn drain<'a>(
        &'a mut self,
        _context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
        _deadline: MonotonicDeadline,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
        // This tranche installs no PortBinding during Fabric lifecycle startup,
        // so there is no separately admitted request stream to drain.
        Box::pin(async move { ManagedServiceCompletion::succeeded(attempt, ()) })
    }

    fn stop<'a>(
        &'a mut self,
        _context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
        Box::pin(async move {
            self.requested = None;
            self.prepared = None;
            let service = {
                let mut slot = self.shared.write().await;
                match core::mem::replace(&mut slot.state, ManagedFabricSlotState::Stopping) {
                    ManagedFabricSlotState::Live(service) => Some(service),
                    ManagedFabricSlotState::NotStarted | ManagedFabricSlotState::Stopped => None,
                    ManagedFabricSlotState::Stopping => {
                        return ManagedServiceCompletion::failed(attempt);
                    }
                }
            };
            let outcome = match service {
                Some(service) => service.shutdown().await,
                None => Ok(()),
            };
            let mut slot = self.shared.write().await;
            slot.state = ManagedFabricSlotState::Stopped;
            slot.owned_binding_count = 0;
            slot.binding_census_known = true;
            match outcome {
                Ok(()) => ManagedServiceCompletion::succeeded(attempt, ()),
                Err(_) => ManagedServiceCompletion::failed(attempt),
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryProbeFailure {
    port: u16,
    raw_os_error: i32,
}

impl RecoveryProbeFailure {
    fn reason_digest(self) -> Result<Digest32, DigestBuildError> {
        recovery_reason_digest(40, self.port, self.raw_os_error)
    }
}

fn request_port(request: &ManagedFabricApplyRequestV1) -> Result<u16, ManagedFabricRuntimeError> {
    if request.target_execution().mode() != ManagedFabricTargetModeV1::OneManagedFabricService {
        return Err(ManagedFabricRuntimeError::ExpectedActiveExecution);
    }
    request
        .target_execution()
        .listen_endpoint()
        .map(ManagedFabricListenEndpointV1::port)
        .ok_or(ManagedFabricRuntimeError::MissingListenEndpoint)
}

fn recovery_reason_digest(
    code: u16,
    port: u16,
    raw_os_error: i32,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(RECOVERY_QUARANTINE_DIGEST_DOMAIN)?;
    builder.field_u16(code)?;
    builder.field_u16(port)?;
    builder.field_bytes(&raw_os_error.to_be_bytes())?;
    Ok(builder.finish())
}

fn next_generation(high_water: u64) -> Result<ManagedServiceGeneration, ManagedFabricRuntimeError> {
    high_water
        .checked_add(1)
        .ok_or(ManagedFabricRuntimeError::GenerationExhausted)
        .and_then(|value| {
            ManagedServiceGeneration::try_new(value)
                .map_err(|_| ManagedFabricRuntimeError::GenerationExhausted)
        })
}

fn insert_replay(
    records: &mut Vec<ManagedFabricReplayRecord>,
    incoming: ManagedFabricReplayRecord,
) -> Result<(), ManagedFabricRuntimeError> {
    match records.binary_search_by_key(&incoming.identity, |record| record.identity) {
        Ok(index) if records[index].value_digest == incoming.value_digest => Ok(()),
        Ok(_) => Err(ManagedFabricRuntimeError::ReplayConflict),
        Err(index) if records.len() < MAX_SUCCESSOR_REPLAY_RECORDS => {
            records.insert(index, incoming);
            Ok(())
        }
        Err(_) => Err(ManagedFabricRuntimeError::ReplayCapacityReached),
    }
}

fn insert_terminal(
    records: &mut Vec<ManagedFabricTerminalRecord>,
    request: &ManagedFabricApplyRequestV1,
    receipt: ManagedFabricApplyTerminalReceiptV1,
) -> Result<(), ManagedFabricRuntimeError> {
    let key = (
        *request.provenance().source_scope().as_bytes(),
        *request.operation_id().as_bytes(),
    );
    let position = records.binary_search_by_key(&key, |record| {
        (
            *record.source_scope.as_bytes(),
            *record.operation_id.as_bytes(),
        )
    });
    match position {
        Ok(index) if records[index].request_digest == request.envelope_request_digest() => Ok(()),
        Ok(_) => Err(ManagedFabricRuntimeError::OperationConflict),
        Err(index) if records.len() < MAX_SUCCESSOR_REPLAY_RECORDS => {
            records.insert(
                index,
                ManagedFabricTerminalRecord {
                    source_scope: request.provenance().source_scope(),
                    operation_id: request.operation_id(),
                    request_digest: request.envelope_request_digest(),
                    receipt,
                },
            );
            Ok(())
        }
        Err(_) => Err(ManagedFabricRuntimeError::ReplayCapacityReached),
    }
}

fn preserved_head(active: Option<&ManagedFabricDurableActive>) -> ManagedFabricApplyTerminalHeadV1 {
    active.map_or(ManagedFabricApplyTerminalHeadV1::PreservedNone, |active| {
        ManagedFabricApplyTerminalHeadV1::PreservedExisting(active.request.target_slice_digest())
    })
}

pub(crate) fn transition_projection_digest(
    projection: &ManagedFabricManifestProjectionV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TRANSITION_PROJECTION_DIGEST_DOMAIN)?;
    builder.field_bytes(projection.canonical_wire())?;
    Ok(builder.finish())
}

fn raw_outcome_digest(
    raw_code: u16,
    raw_context: Option<Digest32>,
    request: &ManagedFabricApplyRequestV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(RAW_OUTCOME_DIGEST_DOMAIN)?;
    builder.field_u16(raw_code)?;
    builder.field_u16(if raw_context.is_some() { 1 } else { 0 })?;
    if let Some(raw_context) = raw_context {
        builder.field_digest(&raw_context)?;
    }
    builder.field_digest(&request.envelope_request_digest())?;
    Ok(builder.finish())
}

#[derive(Debug)]
pub(crate) enum ManagedFabricRuntimeError {
    ExpectedActiveExecution,
    MissingListenEndpoint,
    MissingServiceSpec,
    RuntimeEpochRegressed,
    RequestRejected,
    ProjectionMismatch,
    TerminalCorrelation,
    OperationConflict,
    RecoveryRequired,
    RecoveryNotCompleted,
    RecoveryWhileLive,
    RecoveryQuarantined,
    DeadlineExpired,
    DeadlineOverflow,
    StaleWriter,
    StaleRevision,
    ExpectedActiveMismatch,
    ReplayConflict,
    ReplayCapacityReached,
    GenerationExhausted,
    InvalidDurableState,
    SequenceOverflow,
    SignerConfiguration,
    ShutdownUncertain,
    Digest(DigestBuildError),
    Contract(paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricPlanError),
    State(ManagedFabricStateError),
    Store(ManagedFabricStoreError),
    Clock(crate::runtime_clock::RuntimeClockError),
}

impl ManagedFabricRuntimeError {
    pub(crate) const fn is_request_rejection(&self) -> bool {
        matches!(
            self,
            Self::ExpectedActiveExecution
                | Self::MissingListenEndpoint
                | Self::MissingServiceSpec
                | Self::RequestRejected
                | Self::ProjectionMismatch
                | Self::TerminalCorrelation
                | Self::OperationConflict
                | Self::DeadlineExpired
                | Self::StaleWriter
                | Self::StaleRevision
                | Self::ExpectedActiveMismatch
                | Self::ReplayConflict
        )
    }
}

impl fmt::Display for ManagedFabricRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedActiveExecution => {
                formatter.write_str("managed Fabric lifecycle requires an active execution")
            }
            Self::MissingListenEndpoint => {
                formatter.write_str("active managed Fabric execution has no listen endpoint")
            }
            Self::MissingServiceSpec => {
                formatter.write_str("active managed Fabric execution has no service spec")
            }
            Self::RuntimeEpochRegressed => formatter.write_str("RuntimeHost epoch regressed"),
            Self::RequestRejected => formatter.write_str("managed Fabric request rejected"),
            Self::ProjectionMismatch => {
                formatter.write_str("managed Fabric installation projection mismatch")
            }
            Self::TerminalCorrelation => {
                formatter.write_str("managed Fabric terminal correlation mismatch")
            }
            Self::OperationConflict => {
                formatter.write_str("managed Fabric operation identity conflict")
            }
            Self::RecoveryRequired => formatter.write_str("managed Fabric recovery is required"),
            Self::RecoveryNotCompleted => {
                formatter.write_str("managed Fabric startup recovery has not completed")
            }
            Self::RecoveryWhileLive => {
                formatter.write_str("managed Fabric recovery attempted while a generation is live")
            }
            Self::RecoveryQuarantined => {
                formatter.write_str("managed Fabric recovery remains quarantined")
            }
            Self::DeadlineExpired => formatter.write_str("managed Fabric request expired"),
            Self::DeadlineOverflow => formatter.write_str("managed Fabric deadline overflow"),
            Self::StaleWriter => formatter.write_str("managed Fabric writer tenure is stale"),
            Self::StaleRevision => formatter.write_str("managed Fabric plan revision is stale"),
            Self::ExpectedActiveMismatch => {
                formatter.write_str("managed Fabric expected-active CAS mismatch")
            }
            Self::ReplayConflict => formatter.write_str("managed Fabric replay conflict"),
            Self::ReplayCapacityReached => {
                formatter.write_str("managed Fabric replay capacity reached")
            }
            Self::GenerationExhausted => formatter.write_str("managed Fabric generation exhausted"),
            Self::InvalidDurableState => formatter.write_str("invalid managed Fabric state"),
            Self::SequenceOverflow => formatter.write_str("managed Fabric sequence overflow"),
            Self::SignerConfiguration => {
                formatter.write_str("managed Fabric response signer is invalid")
            }
            Self::ShutdownUncertain => formatter.write_str("managed Fabric shutdown is uncertain"),
            Self::Digest(error) => write!(formatter, "managed Fabric digest failed: {error}"),
            Self::Contract(error) => write!(formatter, "managed Fabric contract failed: {error}"),
            Self::State(error) => write!(formatter, "managed Fabric state failed: {error}"),
            Self::Store(error) => write!(formatter, "managed Fabric store failed: {error}"),
            Self::Clock(error) => write!(formatter, "managed Fabric clock failed: {error}"),
        }
    }
}

impl std::error::Error for ManagedFabricRuntimeError {}

impl From<DigestBuildError> for ManagedFabricRuntimeError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricPlanError>
    for ManagedFabricRuntimeError
{
    fn from(
        value: paraegox_runtime_contracts::managed_fabric_plan::ManagedFabricPlanError,
    ) -> Self {
        Self::Contract(value)
    }
}

impl From<ManagedFabricStateError> for ManagedFabricRuntimeError {
    fn from(value: ManagedFabricStateError) -> Self {
        Self::State(value)
    }
}

impl From<ManagedFabricStoreError> for ManagedFabricRuntimeError {
    fn from(value: ManagedFabricStoreError) -> Self {
        Self::Store(value)
    }
}

impl From<crate::runtime_clock::RuntimeClockError> for ManagedFabricRuntimeError {
    fn from(value: crate::runtime_clock::RuntimeClockError) -> Self {
        Self::Clock(value)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
    use std::sync::Arc;
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use paraegox_agent_contracts::control::{
        AgentConversationCancelStateV1, AgentConversationGetStateV1, AgentConversationOpenOutcomeV1,
    };
    use paraegox_agent_contracts::{
        AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
        AgentConversationSessionId, AgentConversationTerminalResultV1, AgentConversationTurnId,
    };
    use paraegox_agent_service::DeterministicEchoModelProvider;
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::PrincipalRef;
    use paraegox_kernel::time::{BoundedDuration, ClockGeneration, ClockReading};
    use paraegox_runtime_contracts::apply::{ExpectedActive, RuntimeApplyControl};
    use paraegox_runtime_contracts::assignment::BindingId;
    use paraegox_runtime_contracts::managed_agent_stack_plan::{
        ManagedAgentIngressLimitsV1, ManagedAgentPortPlanV1, ManagedAgentProviderProfileV1,
        ManagedAgentProviderRefV1, ManagedAgentProviderSelectionV1, ManagedAgentSemanticLimitsV1,
        ManagedAgentServicePlanV1, ManagedAgentStackProjectionV1,
        ManagedAgentStackTargetExecutionV1,
    };
    use paraegox_runtime_contracts::managed_fabric_plan::{
        ManagedFabricApplyRequestDraftV1, ManagedFabricApplyRequestV1,
        ManagedFabricApplyTerminalOutcomeV1, ManagedFabricListenEndpointV1,
        ManagedFabricManifestProjectionV1, ManagedFabricTargetExecutionV1,
    };
    use paraegox_runtime_contracts::managed_service::{
        ManagedServiceGeneration, ManagedServiceId, ManagedServiceLifecycleBudgetsV1,
        ManagedServiceSpecV1,
    };
    use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
    use paraegox_runtime_contracts::wire::ApplyAuthKeyRef;
    use tokio::sync::{Barrier, RwLock};
    use tokio::time::Instant;

    use super::{
        ManagedFabricApplyOutcome, ManagedFabricControlError, ManagedFabricControlHandle,
        ManagedFabricDurablePending, ManagedFabricDurablePhase,
        ManagedFabricExperimentalSnapshotError, ManagedFabricOwnerConfig, ManagedFabricPendingKind,
        ManagedFabricRuntimeCore, ManagedFabricRuntimeError, ManagedFabricSlot,
        ManagedFabricSlotState, next_generation, transition_projection_digest,
    };
    use crate::admission::VerifiedManagedFabricApplyIngressV1;
    use crate::managed_agent_runtime::{ManagedAgentAssembly, RuntimeAgentConversationError};
    use crate::runtime_agent_provider::{
        RuntimeAgentProviderResolveError, RuntimeAgentProviderResolverV1,
        RuntimeResolvedAgentProviderV1,
    };
    use crate::runtime_clock::RuntimeClock;
    use crate::runtime_store::{ManagedFabricStore, tests::managed_fabric_store_fixture};

    const FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s7_managed_fabric_successor_v1.json");
    const STORE_BYTE: u8 = 0x44;
    const TARGET_FINGERPRINT_BYTE: u8 = 0x55;

    struct DeterministicFixtureResolver;

    impl RuntimeAgentProviderResolverV1 for DeterministicFixtureResolver {
        fn resolve(
            &self,
            selection: ManagedAgentProviderSelectionV1,
        ) -> Result<RuntimeResolvedAgentProviderV1, RuntimeAgentProviderResolveError> {
            if selection.profile() != ManagedAgentProviderProfileV1::DeterministicFixture {
                return Err(RuntimeAgentProviderResolveError::ResolutionFailed);
            }
            Ok(RuntimeResolvedAgentProviderV1::new(
                selection,
                DeterministicEchoModelProvider::new(),
            ))
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("fixture contains non-hex byte"),
            }
        }
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn fixture_request(name: &str) -> ManagedFabricApplyRequestV1 {
        let object_key = format!("\"{name}\"");
        let object_start = FIXTURE_JSON
            .find(&object_key)
            .unwrap_or_else(|| panic!("missing fixture object {name}"));
        let field = "\"outer_v6_hex\": \"";
        let field_start = FIXTURE_JSON[object_start..]
            .find(field)
            .map(|offset| object_start + offset + field.len())
            .unwrap_or_else(|| panic!("missing outer request for {name}"));
        let field_end = FIXTURE_JSON[field_start..]
            .find('"')
            .map(|offset| field_start + offset)
            .expect("fixture hex must terminate");
        ManagedFabricApplyRequestV1::decode(&decode_hex(&FIXTURE_JSON[field_start..field_end]))
            .unwrap_or_else(|error| panic!("fixture request must decode: {error}"))
    }

    fn projection() -> ManagedFabricManifestProjectionV1 {
        fixture_request("one_managed_fabric_service")
            .target_execution()
            .projection()
            .clone()
    }

    fn active_request(port: u16, expected_active: ExpectedActive) -> ManagedFabricApplyRequestV1 {
        let basis = fixture_request("one_managed_fabric_service");
        let endpoint = ManagedFabricListenEndpointV1::try_new(&format!("tcp/127.0.0.1:{port}"))
            .expect("ephemeral loopback endpoint must be canonical");
        let execution = ManagedFabricTargetExecutionV1::try_one_managed_fabric_service(
            projection(),
            basis
                .target_execution()
                .service()
                .expect("fixture service must exist"),
            endpoint,
        )
        .expect("active execution must build");
        rebuild_request(&basis, execution, expected_active)
    }

    fn empty_request(expected_active: ExpectedActive) -> ManagedFabricApplyRequestV1 {
        let basis = fixture_request("empty_deactivate");
        let execution = ManagedFabricTargetExecutionV1::try_empty_deactivate(projection())
            .expect("empty execution must build");
        rebuild_request(&basis, execution, expected_active)
    }

    fn rebuild_request(
        basis: &ManagedFabricApplyRequestV1,
        execution: ManagedFabricTargetExecutionV1,
        expected_active: ExpectedActive,
    ) -> ManagedFabricApplyRequestV1 {
        let control = RuntimeApplyControl::new(
            basis
                .control_commitment()
                .control()
                .writer_context()
                .clone(),
            expected_active,
            basis.operation_id(),
        );
        ManagedFabricApplyRequestDraftV1::try_new(
            execution,
            basis.provenance(),
            control,
            basis.temporal(),
            [STORE_BYTE; 32],
            basis.authentication().claim().clone(),
        )
        .expect("request draft must build")
        .finalize(basis.authentication().signature())
        .expect("opaque fixture signature must finalize")
    }

    fn channel(projection: &ManagedFabricManifestProjectionV1) -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            projection.target(),
            PrincipalRef::from_bytes([0xe1; 16]),
            Digest32::from_bytes([0xe3; 32]),
            Digest32::from_bytes([0xe4; 32]),
        )
        .expect("fixture response channel must build")
    }

    fn clock(generation: u64, origin_ticks: u64) -> RuntimeClock {
        let basis = fixture_request("one_managed_fabric_service");
        RuntimeClock::new(
            basis.temporal().target_clock_domain(),
            ClockGeneration::try_new(generation).expect("clock generation must be nonzero"),
            origin_ticks,
        )
    }

    fn verified(reading: ClockReading, seed: u8) -> VerifiedManagedFabricApplyIngressV1 {
        VerifiedManagedFabricApplyIngressV1::for_test(
            reading.now().value(),
            reading
                .now()
                .value()
                .checked_add(60_000_000_000)
                .expect("test deadline must fit"),
            reading.generation(),
            seed,
        )
    }

    fn config(
        directory: &std::path::Path,
        projection: ManagedFabricManifestProjectionV1,
        runtime_host_epoch: u64,
        clock: RuntimeClock,
    ) -> ManagedFabricOwnerConfig {
        ManagedFabricOwnerConfig {
            state_directory: directory.to_path_buf(),
            store_instance_id: [STORE_BYTE; 32],
            owner_target_fingerprint: Digest32::from_bytes([TARGET_FINGERPRINT_BYTE; 32]),
            projection,
            runtime_host_epoch,
            clock,
            response_key_ref: ApplyAuthKeyRef::from_bytes([0xe2; 16]),
            response_signer: SigningKey::from_bytes(&[0x71; 32]),
        }
    }

    fn available_port() -> u16 {
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("ephemeral loopback bind must work")
            .local_addr()
            .expect("ephemeral listener must have an address")
            .port()
    }

    fn fresh_core(
        runtime_host_epoch: u64,
        clock_generation: u64,
    ) -> (
        crate::runtime_store::tests::TestDirectory,
        ManagedFabricRuntimeCore,
    ) {
        let projection = projection();
        let projection_digest =
            transition_projection_digest(&projection).expect("projection digest must build");
        let (directory, store) =
            managed_fabric_store_fixture(STORE_BYTE, TARGET_FINGERPRINT_BYTE, projection_digest);
        let core = ManagedFabricRuntimeCore::from_preopened_store(
            store,
            config(
                directory.path(),
                projection,
                runtime_host_epoch,
                clock(clock_generation, 100),
            ),
        )
        .expect("managed-fabric core must initialize");
        (directory, core)
    }

    #[tokio::test]
    async fn experimental_snapshot_handle_enforces_deadline_and_generation_before_session_access() {
        let owner_generation = ManagedServiceGeneration::try_new(1)
            .unwrap_or_else(|error| panic!("owner generation rejected: {error}"));
        let shared = Arc::new(RwLock::new(ManagedFabricSlot {
            generation: owner_generation,
            state: ManagedFabricSlotState::NotStarted,
            owned_binding_count: 0,
            binding_census_known: true,
        }));
        let matching = ManagedFabricControlHandle {
            generation: owner_generation,
            shared: Arc::downgrade(&shared),
        };
        assert_eq!(
            matching
                .observe_experimental_remote_mtls_links_once(Instant::now())
                .await
                .expect_err("expired absolute deadline must fail before Session access"),
            ManagedFabricExperimentalSnapshotError::DeadlineExpired
        );

        let stale_generation = ManagedServiceGeneration::try_new(2)
            .unwrap_or_else(|error| panic!("stale generation rejected: {error}"));
        let stale = ManagedFabricControlHandle {
            generation: stale_generation,
            shared: Arc::downgrade(&shared),
        };
        assert_eq!(
            stale
                .observe_experimental_remote_mtls_links_once(
                    Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect_err("wrong generation must be fenced before Session access"),
            ManagedFabricExperimentalSnapshotError::Control(
                ManagedFabricControlError::GenerationFenced
            )
        );
        assert_eq!(
            matching
                .observe_experimental_remote_mtls_links_once(
                    Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect_err("not-started generation must not expose a Session"),
            ManagedFabricExperimentalSnapshotError::Control(ManagedFabricControlError::NotReady)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_replay_empty_and_generation_fence_use_one_real_fabric_session() {
        let (_directory, mut core) = fresh_core(1, 3);
        let port = available_port();
        let active = active_request(port, ExpectedActive::None);
        let response_channel = channel(&core.projection);
        let ingress = verified(core.clock.reading().expect("clock must read"), 0xb0);

        assert!(matches!(
            core.apply(active.clone(), ingress, response_channel)
                .await
                .expect_err("apply must remain closed before startup recovery"),
            ManagedFabricRuntimeError::RecoveryNotCompleted
        ));
        core.recover()
            .await
            .expect("fresh exact-zero recovery must pass");
        let committed = core
            .apply(active.clone(), ingress, response_channel)
            .await
            .expect("active apply must complete");
        let ManagedFabricApplyOutcome::Committed(active_receipt) = committed else {
            panic!("first active apply must commit")
        };
        assert_eq!(
            active_receipt.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        );
        assert_eq!(core.snapshot.phase, ManagedFabricDurablePhase::ActiveReady);
        assert_eq!(core.snapshot.generation_high_water(), 1);
        assert!(
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).is_err(),
            "the one managed Fabric session must own the requested TCP port"
        );
        let control = core
            .control_handle()
            .expect("ready generation must expose its fence");

        let sequence = core.snapshot.sequence();
        assert!(matches!(
            core.apply(active.clone(), ingress, response_channel)
                .await
                .expect("exact terminal replay must succeed"),
            ManagedFabricApplyOutcome::Replayed(_)
        ));
        assert_eq!(core.snapshot.sequence(), sequence);

        let empty = empty_request(ExpectedActive::Exact(active.target_slice_digest()));
        let empty_ingress = verified(core.clock.reading().expect("clock must read"), 0xc0);
        let ManagedFabricApplyOutcome::Committed(empty_receipt) = core
            .apply(empty, empty_ingress, response_channel)
            .await
            .expect("empty apply must stop the one live session")
        else {
            panic!("first empty apply must commit")
        };
        assert_eq!(
            empty_receipt.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero
        );
        assert_eq!(core.snapshot.phase, ManagedFabricDurablePhase::ExactZero);
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .expect("exact-zero completion must release the TCP port");
        drop(listener);
        assert_eq!(
            control
                .with_live_fabric(|_| Box::pin(async {}))
                .await
                .expect_err("retired generation must never revive"),
            ManagedFabricControlError::OwnerRetired
        );
        core.shutdown()
            .await
            .expect("exact-zero shutdown must pass");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_cas_rejection_persists_only_truthful_no_effect_terminal() {
        let (_directory, mut core) = fresh_core(1, 3);
        core.recover().await.expect("fresh recovery must pass");
        let port = available_port();
        let request = active_request(
            port,
            ExpectedActive::Exact(
                paraegox_runtime_contracts::provenance::TargetSliceDigest::new(
                    Digest32::from_bytes([0xd9; 32]),
                ),
            ),
        );
        let response_channel = channel(&core.projection);
        let before = core.snapshot.transition();
        let ManagedFabricApplyOutcome::Committed(receipt) = core
            .apply(
                request,
                verified(core.clock.reading().expect("clock must read"), 0xb2),
                response_channel,
            )
            .await
            .expect("authenticated CAS reject must return PXFT")
        else {
            panic!("first CAS rejection must commit its terminal")
        };
        assert_eq!(
            receipt.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::NoEffectRejected
        );
        assert_eq!(core.snapshot.phase, ManagedFabricDurablePhase::ExactZero);
        assert_eq!(core.snapshot.writer_fence, before.writer_fence);
        assert_eq!(
            core.snapshot.revision_high_water,
            before.revision_high_water
        );
        assert_eq!(core.snapshot.tenure_nonces, before.tenure_nonces);
        assert_eq!(core.snapshot.request_nonces, before.request_nonces);
        assert_eq!(core.snapshot.temporal_lineages, before.temporal_lineages);
        assert_eq!(core.snapshot.terminals.len(), 1);
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .expect("CAS no-effect rejection must not start Fabric");
        drop(listener);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_read_requests_share_generation_while_stop_waits_for_both() {
        let (_directory, mut core) = fresh_core(1, 3);
        core.recover().await.expect("fresh recovery must pass");
        let port = available_port();
        let request = active_request(port, ExpectedActive::None);
        let response_channel = channel(&core.projection);
        core.apply(
            request,
            verified(core.clock.reading().expect("clock must read"), 0xb3),
            response_channel,
        )
        .await
        .expect("active apply must start the shared session");
        let control = core
            .control_handle()
            .expect("ready generation must expose its fence");
        let entered = Arc::new(Barrier::new(3));
        let release = Arc::new(Barrier::new(3));
        let mut readers = Vec::new();
        for _ in 0..2 {
            let handle = control.clone();
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            readers.push(tokio::spawn(async move {
                handle
                    .with_live_fabric(move |_| {
                        Box::pin(async move {
                            entered.wait().await;
                            release.wait().await;
                        })
                    })
                    .await
            }));
        }
        entered.wait().await;

        let shutdown = tokio::spawn(async move {
            core.shutdown().await.expect("exclusive stop must finish");
            core
        });
        tokio::task::yield_now().await;
        assert!(
            !shutdown.is_finished(),
            "stop must wait for every in-flight shared read request"
        );
        release.wait().await;
        for reader in readers {
            reader
                .await
                .expect("reader task must join")
                .expect("same-generation read must complete");
        }
        let core = shutdown.await.expect("shutdown task must join");
        assert_eq!(
            control
                .with_live_fabric(|_| Box::pin(async {}))
                .await
                .expect_err("post-stop handle must stay fenced"),
            ManagedFabricControlError::OwnerRetired
        );
        drop(core);
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .expect("exclusive stop must release the one TCP listener");
        drop(listener);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_restart_uses_fresh_durable_generation_before_real_rebind() {
        let (directory, mut first) = fresh_core(1, 3);
        first.recover().await.expect("fresh recovery must pass");
        let port = available_port();
        let request = active_request(port, ExpectedActive::None);
        let response_channel = channel(&first.projection);
        first
            .apply(
                request,
                verified(first.clock.reading().expect("clock must read"), 0xb4),
                response_channel,
            )
            .await
            .expect("initial active apply must pass");
        first
            .shutdown()
            .await
            .expect("first owner must stop exactly");
        drop(first);

        let stale_projection = projection();
        let stale_projection_digest =
            transition_projection_digest(&stale_projection).expect("projection digest must build");
        let stale_store = ManagedFabricStore::open_fixture(
            directory.path(),
            [STORE_BYTE; 32],
            Digest32::from_bytes([TARGET_FINGERPRINT_BYTE; 32]),
            stale_projection_digest,
        )
        .expect("successor store must reopen for stale-epoch proof");
        assert!(matches!(
            ManagedFabricRuntimeCore::from_preopened_store(
                stale_store,
                config(directory.path(), stale_projection, 1, clock(4, 200)),
            ),
            Err(ManagedFabricRuntimeError::RuntimeEpochRegressed)
        ));

        let projection = projection();
        let projection_digest =
            transition_projection_digest(&projection).expect("projection digest must build");
        let store = ManagedFabricStore::open_fixture(
            directory.path(),
            [STORE_BYTE; 32],
            Digest32::from_bytes([TARGET_FINGERPRINT_BYTE; 32]),
            projection_digest,
        )
        .expect("successor store must reopen");
        let mut restarted = ManagedFabricRuntimeCore::from_preopened_store(
            store,
            config(directory.path(), projection, 2, clock(4, 200)),
        )
        .expect("restarted core must decode durable active state");
        restarted
            .recover()
            .await
            .expect("free old port must allow managed recovery");
        assert_eq!(
            restarted.snapshot.phase,
            ManagedFabricDurablePhase::ActiveReady
        );
        assert_eq!(restarted.snapshot.generation_high_water(), 2);
        assert_eq!(
            restarted
                .snapshot
                .active
                .as_ref()
                .expect("recovered service must be active")
                .generation
                .value(),
            2
        );
        assert!(
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).is_err(),
            "recovered generation must own the exact requested port"
        );
        restarted
            .shutdown()
            .await
            .expect("recovered owner must stop exactly");
    }

    async fn quarantined_raw_evidence(port: u16) -> (Digest32, Digest32) {
        let (directory, mut first) = fresh_core(1, 3);
        first.recover().await.expect("fresh recovery must pass");
        let request = active_request(port, ExpectedActive::None);
        let response_channel = channel(&first.projection);
        let ingress = verified(first.clock.reading().expect("clock must read"), 0xb6);
        let mut intent = first
            .admit_transition(&request, ingress)
            .expect("start intent admission must pass");
        let generation = next_generation(first.snapshot.generation_high_water())
            .expect("first generation must exist");
        intent.generation_high_water = generation.value();
        intent.phase = ManagedFabricDurablePhase::StartIntent;
        intent.pending = Some(ManagedFabricDurablePending {
            kind: ManagedFabricPendingKind::Start,
            generation: Some(generation),
            admitted_clock_generation: ingress.clock_generation(),
            admitted_at_nanos: ingress.admitted_at_nanos(),
            deadline_nanos: ingress.deadline_nanos(),
            response_channel,
            request: request.clone(),
        });
        first
            .commit_transition(intent)
            .expect("crash-point intent must be durable");
        drop(first);

        let blocker = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .expect("test must exclusively occupy the recovery port");
        let projection = projection();
        let projection_digest =
            transition_projection_digest(&projection).expect("projection digest must build");
        let store = ManagedFabricStore::open_fixture(
            directory.path(),
            [STORE_BYTE; 32],
            Digest32::from_bytes([TARGET_FINGERPRINT_BYTE; 32]),
            projection_digest,
        )
        .expect("successor store must reopen");
        let mut restarted = ManagedFabricRuntimeCore::from_preopened_store(
            store,
            config(directory.path(), projection, 2, clock(4, 200)),
        )
        .expect("restart must decode the durable start intent");
        assert!(matches!(
            restarted
                .recover()
                .await
                .expect_err("busy exact port must quarantine recovery"),
            ManagedFabricRuntimeError::RecoveryQuarantined
        ));
        assert_eq!(
            restarted.snapshot.phase,
            ManagedFabricDurablePhase::Quarantined
        );
        assert_eq!(restarted.snapshot.generation_high_water(), 2);
        let receipt = restarted
            .lookup_terminal(&request, response_channel)
            .expect("terminal lookup must validate")
            .expect("quarantine must persist a terminal for the pending request");
        assert_eq!(
            receipt.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::Quarantined
        );
        let raw = receipt.facts().raw_outcome_digest();
        let reason = restarted
            .snapshot
            .quarantine_reason
            .expect("quarantine reason must be durable");
        drop(blocker);
        (raw, reason)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn busy_exact_ports_quarantine_without_blind_bind_and_commit_distinct_evidence() {
        let first_port = available_port();
        let mut second_port = available_port();
        while second_port == first_port {
            second_port = available_port();
        }
        let first = quarantined_raw_evidence(first_port).await;
        let second = quarantined_raw_evidence(second_port).await;
        assert_ne!(
            first.1, second.1,
            "port identity must change quarantine reason"
        );
        assert_ne!(
            first.0, second.0,
            "PXFT raw evidence must commit the distinct quarantine reason"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_agent_uses_live_fabric_for_two_turns_then_retires_to_exact_zero() {
        let (directory, mut core) = fresh_core(1, 3);
        core.recover().await.expect("fresh recovery must pass");
        let fabric_port = available_port();
        let active = active_request(fabric_port, ExpectedActive::None);
        let active_digest = active.target_slice_digest();
        let fabric_execution = active.target_execution().clone();
        let response_channel = channel(&core.projection);
        let ingress = verified(core.clock.reading().expect("clock must read"), 0xd0);
        let ManagedFabricApplyOutcome::Committed(active_receipt) = core
            .apply(active, ingress, response_channel)
            .await
            .expect("managed Fabric must become ready")
        else {
            panic!("first active Fabric apply must commit")
        };
        assert_eq!(
            active_receipt.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::ActiveReady
        );

        let lifecycle_budget = BoundedDuration::from_nanos(5_000_000_000);
        let lifecycle_budgets = ManagedServiceLifecycleBudgetsV1::try_new(
            lifecycle_budget,
            lifecycle_budget,
            lifecycle_budget,
            lifecycle_budget,
            lifecycle_budget,
        )
        .expect("Agent lifecycle budgets must be valid");
        let agent_service =
            ManagedServiceSpecV1::new(ManagedServiceId::from_bytes([0xa1; 16]), lifecycle_budgets);
        let semantic_limits = ManagedAgentSemanticLimitsV1::try_new(8, 16, 16, 32)
            .expect("signed Agent semantic limits must be valid");
        let ingress_limits = ManagedAgentIngressLimitsV1::try_new(
            8,
            512 * 1024,
            64 * 1024,
            64 * 1024,
            2_000_000_000,
        )
        .expect("signed Agent ingress limits must be valid");
        let port_plan = ManagedAgentPortPlanV1::try_new(
            BindingId::from_bytes([0xa2; 16]),
            BindingId::from_bytes([0xa3; 16]),
            "paraegox/runtime/managed-agent/test/submit",
            "paraegox/runtime/managed-agent/test/control",
            ingress_limits,
        )
        .expect("signed two-lane Agent port must be valid");
        let provider = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            ManagedAgentProviderRefV1::try_from_bytes([0xa4; 16])
                .expect("fixture provider ref must be valid"),
            Digest32::from_bytes([0xa5; 32]),
        )
        .expect("fixture provider must be explicitly selected");
        let agent_plan =
            ManagedAgentServicePlanV1::try_new(agent_service, semantic_limits, port_plan, provider)
                .expect("signed Agent service plan must be valid");
        let stack_projection = ManagedAgentStackProjectionV1::try_from_managed_fabric_projection(
            fabric_execution.projection().clone(),
        )
        .expect("stack projection must preserve the Fabric projection");
        let stack_execution = ManagedAgentStackTargetExecutionV1::try_fabric_and_agent(
            stack_projection,
            fabric_execution,
            agent_plan,
        )
        .expect("signed Fabric-to-Agent execution must be valid");
        let (mut assembly, handle) = ManagedAgentAssembly::start_from_execution(
            core.control_handle()
                .expect("ready Fabric generation must expose its fence"),
            &stack_execution,
            directory.path().to_path_buf(),
            &DeterministicFixtureResolver,
        )
        .await
        .expect("Agent must install on the existing Fabric generation");

        let deck_run_id = AgentConversationDeckRunId::try_from_bytes([0xb1; 16])
            .expect("DeckRun id must be valid");
        let session_id = AgentConversationSessionId::try_from_bytes([0xb2; 16])
            .expect("Session id must be valid");
        assert_eq!(
            handle
                .open_session(deck_run_id, session_id, Duration::from_secs(2))
                .await
                .expect("explicit Session open must round trip"),
            AgentConversationOpenOutcomeV1::Opened
        );

        let first = AgentConversationRequestV1::try_new(
            deck_run_id,
            session_id,
            AgentConversationTurnId::try_from_bytes([0xb3; 16]).expect("Turn id must be valid"),
            AgentConversationRequestId::try_from_bytes([0xb4; 16])
                .expect("request id must be valid"),
            2_000_000_000,
            "first managed turn",
        )
        .expect("first request must be valid");
        let first_terminal = handle
            .submit(first.clone(), Duration::from_secs(2))
            .await
            .expect("first turn must terminate");
        assert_eq!(
            first_terminal.result(),
            &AgentConversationTerminalResultV1::Success("echo: first managed turn".into())
        );
        assert_eq!(
            handle
                .get(
                    deck_run_id,
                    session_id,
                    first.request_id(),
                    Duration::from_secs(2),
                )
                .await
                .expect("get must observe first terminal"),
            AgentConversationGetStateV1::Terminal(first_terminal)
        );

        let mut closed_lease = handle.clone();
        closed_lease.close().await.expect("lease close must pass");
        assert!(matches!(
            closed_lease
                .open_session(deck_run_id, session_id, Duration::from_secs(2))
                .await,
            Err(RuntimeAgentConversationError::Closed)
        ));

        let second = AgentConversationRequestV1::try_new(
            deck_run_id,
            session_id,
            AgentConversationTurnId::try_from_bytes([0xb5; 16]).expect("Turn id must be valid"),
            AgentConversationRequestId::try_from_bytes([0xb6; 16])
                .expect("request id must be valid"),
            2_000_000_000,
            "second managed turn",
        )
        .expect("second request must be valid");
        let second_terminal = handle
            .submit(second.clone(), Duration::from_secs(2))
            .await
            .expect("second turn must terminate");
        assert_eq!(
            second_terminal.result(),
            &AgentConversationTerminalResultV1::Success("echo: second managed turn".into())
        );
        assert_eq!(
            handle
                .cancel(
                    deck_run_id,
                    session_id,
                    second.request_id(),
                    Duration::from_secs(2),
                )
                .await
                .expect("cancel must observe the terminal truth"),
            AgentConversationCancelStateV1::Terminal(second_terminal)
        );
        let batch = handle
            .watch(deck_run_id, session_id, 0, 16, Duration::from_secs(2))
            .await
            .expect("watch must round trip")
            .expect("opened Session must retain events");
        assert_eq!(batch.events().len(), 5);
        assert_eq!(batch.next_cursor(), batch.high_watermark());
        assert!(!batch.has_more());

        assembly
            .shutdown()
            .await
            .expect("Agent must retire both physical bindings before Fabric");
        assert!(matches!(
            handle
                .open_session(deck_run_id, session_id, Duration::from_secs(2))
                .await,
            Err(RuntimeAgentConversationError::OwnerRetired)
        ));

        let empty = empty_request(ExpectedActive::Exact(active_digest));
        let empty_ingress = verified(core.clock.reading().expect("clock must read"), 0xd1);
        let ManagedFabricApplyOutcome::Committed(empty_receipt) = core
            .apply(empty, empty_ingress, response_channel)
            .await
            .expect("Fabric exact-zero must accept the retired Agent census")
        else {
            panic!("first empty apply must commit")
        };
        assert_eq!(
            empty_receipt.facts().outcome(),
            ManagedFabricApplyTerminalOutcomeV1::EmptyExactZero
        );
        core.shutdown()
            .await
            .expect("exact-zero Runtime shutdown must pass");
    }
}
