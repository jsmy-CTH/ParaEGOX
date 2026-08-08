#![cfg(unix)]

//! RuntimeHost-owned PXAR-v8 distributed Fabric→Agent lifecycle.
//!
//! This owner keeps the PXAR-v6 store and writer lock.  PXDA is only the
//! successor state machine: every session/port effect follows a durable
//! intent. The additive PXDA-v2 path binds one local Evidence store epoch,
//! records generation- and session-correlated PXTP facts through a durable
//! phase-11 handoff and verifies append receipts plus exact readback before it
//! may resolve or start Agent. The normal path then validates the two installed
//! local binding descriptors and census, atomically commits ActiveReady while
//! clearing the verified handoff, and only afterwards publishes the opaque
//! conversation handle. Crash recovery never reuses an old PXTP session to
//! start Agent: it advances through a fresh Fabric generation, PXTP batch, and
//! Evidence commit first.

use core::{fmt, time::Duration};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use paraegox_evidence::{
    EvidenceCommitReceiptV1, EvidenceContractError, EvidenceKindV1, EvidenceOwnerRefV1,
    EvidencePayloadV1, EvidenceRecordIdV1, EvidenceRecordInputV1, EvidenceRecordV1,
    EvidenceRetentionPolicyV1, EvidenceStoreEpochV1, EvidenceStoreError, EvidenceStoredRecordV1,
    LocalEvidenceStoreV1, MAX_EVIDENCE_QUERY_RECORDS,
};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::time::{ClockGeneration, ClockReading};
use paraegox_runtime_contracts::apply::ExpectedActive;
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DistributedAgentStackApplyRequestV1, DistributedAgentStackLocalBindingEvidenceFieldsV1,
    DistributedAgentStackPlanError, DistributedAgentStackProjectionV1,
    DistributedAgentStackTargetModeV1, DistributedAgentStackTerminalAuthClaimV1,
    DistributedAgentStackTerminalEvidenceFieldsV1, DistributedAgentStackTerminalFactsV1,
    DistributedAgentStackTerminalObservationsV1, DistributedAgentStackTerminalOutcomeV1,
    DistributedAgentStackTerminalReceiptDraftV1, DistributedAgentStackTerminalReceiptV1,
    DistributedFabricObservedTransportProofFieldsV1, DistributedFabricObservedTransportProofV1,
    DistributedFabricSessionEpochV1, DistributedFabricTransportEvidenceRefV1,
    distributed_agent_stack_empty_binding_set_digest_v1,
    distributed_agent_stack_installed_binding_set_digest_v1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

use crate::admission::VerifiedDistributedAgentStackApplyIngressV1;
use crate::distributed_agent_stack_state::{
    DistributedAgentStackDurableActive, DistributedAgentStackDurablePending,
    DistributedAgentStackDurablePhase, DistributedAgentStackEvidenceBatchV2,
    DistributedAgentStackEvidenceBindingV2, DistributedAgentStackEvidenceHandoffV2,
    DistributedAgentStackEvidenceOwnerHeadV2, DistributedAgentStackEvidenceStateV2,
    DistributedAgentStackPendingKind, DistributedAgentStackReplayRecord,
    DistributedAgentStackRevisionHighWater, DistributedAgentStackSnapshot,
    DistributedAgentStackSnapshotTransition, DistributedAgentStackSnapshotWireVersion,
    DistributedAgentStackStateError, DistributedAgentStackTerminalRecord,
    DistributedAgentStackWriterFence,
};
use crate::distributed_fabric_runtime::{
    DistributedFabricRuntimeError, DistributedFabricRuntimeGeneration,
    RuntimeFabricCredentialResolverV2,
};
use crate::managed_agent_runtime::{
    ManagedAgentAssembly, ManagedAgentAssemblyError, RuntimeAgentConversationHandle,
};
use crate::managed_agent_stack_runtime::{
    ManagedAgentStackRuntimeCore, ManagedAgentStackRuntimeError, RuntimeAgentHandleBroker,
};
use crate::managed_fabric_runtime::{
    ManagedFabricControlHandle, ManagedFabricExperimentalSnapshotError, ManagedFabricRuntimeCore,
    ManagedFabricRuntimeError,
};
use crate::runtime_agent_provider::RuntimeAgentProviderResolverV1;
use crate::runtime_clock::{RuntimeClock, RuntimeClockError};
use crate::task_registry::CancellationSource;
use tokio::time::Instant;

const PROJECTION_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-agent-stack-transition-projection.sha256.v1";
const RAW_OUTCOME_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-agent-stack-raw-outcome.sha256.v1";
const QUARANTINE_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.distributed-agent-stack-quarantine.sha256.v1";
const MAX_REPLAY_RECORDS: usize = 256;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackEvidenceStoreConfigV1 {
    root: PathBuf,
    store_epoch: EvidenceStoreEpochV1,
    retention_policy: EvidenceRetentionPolicyV1,
    owner_ref: EvidenceOwnerRefV1,
}

impl DistributedAgentStackEvidenceStoreConfigV1 {
    pub(crate) fn try_new(
        root: PathBuf,
        store_epoch: EvidenceStoreEpochV1,
        retention_policy: EvidenceRetentionPolicyV1,
        owner_ref: EvidenceOwnerRefV1,
    ) -> Result<Self, DistributedAgentStackRuntimeError> {
        if !root.is_absolute()
            || root.parent().is_none()
            || root
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(DistributedAgentStackRuntimeError::InvalidEvidenceStoreConfig);
        }
        Ok(Self {
            root,
            store_epoch,
            retention_policy,
            owner_ref,
        })
    }

    #[must_use]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub(crate) const fn store_epoch(&self) -> EvidenceStoreEpochV1 {
        self.store_epoch
    }

    #[must_use]
    pub(crate) const fn retention_policy(&self) -> EvidenceRetentionPolicyV1 {
        self.retention_policy
    }

    #[must_use]
    pub(crate) const fn owner_ref(&self) -> EvidenceOwnerRefV1 {
        self.owner_ref
    }

    const fn binding(&self) -> DistributedAgentStackEvidenceBindingV2 {
        DistributedAgentStackEvidenceBindingV2::new(self.store_epoch, self.owner_ref)
    }
}

impl fmt::Debug for DistributedAgentStackEvidenceStoreConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DistributedAgentStackEvidenceStoreConfigV1")
            .field("configuration", &"<redacted>")
            .finish()
    }
}

pub(crate) struct DistributedAgentStackOwnerConfig {
    pub(crate) state_directory: PathBuf,
    pub(crate) projection: DistributedAgentStackProjectionV1,
    pub(crate) runtime_host_epoch: u64,
    pub(crate) clock: RuntimeClock,
    pub(crate) response_key_ref: ApplyAuthKeyRef,
    pub(crate) response_signer: SigningKey,
    pub(crate) handle_broker: RuntimeAgentHandleBroker,
    pub(crate) fabric_credential_resolver: Option<Arc<dyn RuntimeFabricCredentialResolverV2>>,
    pub(crate) evidence_store_config: Option<DistributedAgentStackEvidenceStoreConfigV1>,
    pub(crate) agent_provider_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
}

pub(crate) struct DistributedAgentStackRuntimeCore {
    snapshot: DistributedAgentStackSnapshot,
    projection: DistributedAgentStackProjectionV1,
    state_directory: PathBuf,
    runtime_host_epoch: u64,
    clock: RuntimeClock,
    response_key_ref: ApplyAuthKeyRef,
    response_signer: SigningKey,
    handle_broker: RuntimeAgentHandleBroker,
    fabric_credential_resolver: Option<Arc<dyn RuntimeFabricCredentialResolverV2>>,
    evidence_store_config: Option<DistributedAgentStackEvidenceStoreConfigV1>,
    evidence_store: Option<LocalEvidenceStoreV1>,
    agent_provider_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
    cancellation: CancellationSource,
    fabric: Option<DistributedFabricRuntimeGeneration>,
    assembly: Option<ManagedAgentAssembly>,
    handle: Option<RuntimeAgentConversationHandle>,
    handle_publication_pending: bool,
    recovery_completed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DistributedAgentStackApplyOutcome {
    Committed(DistributedAgentStackTerminalReceiptV1),
    CommittedHandleUnavailable(DistributedAgentStackTerminalReceiptV1),
    CommittedOwnerRestartRequired,
    Replayed(DistributedAgentStackTerminalReceiptV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalGenerations {
    fabric: Option<ManagedServiceGeneration>,
    agent: Option<ManagedServiceGeneration>,
}

#[derive(Clone, Copy)]
struct TerminalSelection {
    outcome: DistributedAgentStackTerminalOutcomeV1,
    generations: TerminalGenerations,
    local_bindings: DistributedAgentStackLocalBindingEvidenceFieldsV1,
}

#[derive(Debug, Eq, PartialEq)]
struct ValidatedExperimentalSnapshot {
    fabric_generation: ManagedServiceGeneration,
    session_epoch: DistributedFabricSessionEpochV1,
    peer_owner_facts: Box<[ValidatedExperimentalPeerOwnerFacts]>,
}

#[derive(Debug, Eq, PartialEq)]
struct ValidatedExperimentalPeerOwnerFacts {
    identity_binding_digest: Digest32,
    observation_sequence: u64,
}

struct CleanedNonReadyTerminalDecision {
    raw_code: u16,
    proofs: Vec<DistributedFabricObservedTransportProofV1>,
}

impl CleanedNonReadyTerminalDecision {
    fn receipt_selection(
        &self,
        installed_binding_set_digest: Digest32,
        raw_outcome_digest: Digest32,
    ) -> TerminalSelection {
        TerminalSelection {
            outcome: DistributedAgentStackTerminalOutcomeV1::TerminalNonReady,
            generations: TerminalGenerations {
                fabric: None,
                agent: None,
            },
            // PXDS v1 reserves exact-zero evidence for EmptyExactZero. This
            // receipt stays conservative; durable state converges separately.
            local_bindings: DistributedAgentStackLocalBindingEvidenceFieldsV1 {
                physical_binding_census: 0,
                census_complete: false,
                fabric_ready: false,
                agent_ready: false,
                dependency_satisfied: false,
                exact_zero: false,
                quarantined: false,
                installed_binding_set_digest,
                raw_outcome_digest,
            },
        }
    }
}

enum ActivationTerminalMode {
    RecordActiveReady,
    PreserveHistoricalActive(Box<DistributedAgentStackTerminalReceiptV1>),
}

#[derive(Clone, Copy)]
struct ActivationContext<'a> {
    request: &'a DistributedAgentStackApplyRequestV1,
    response_channel: ReferenceChannelBindingV1,
    fabric_generation: ManagedServiceGeneration,
    agent_generation: ManagedServiceGeneration,
    raw_code: u16,
    terminal_mode: &'a ActivationTerminalMode,
}

impl ActivationContext<'_> {
    const fn with_raw_code(self, raw_code: u16) -> Self {
        Self { raw_code, ..self }
    }
}

struct UncertainCleanupInput<'a> {
    request: &'a DistributedAgentStackApplyRequestV1,
    response_channel: ReferenceChannelBindingV1,
    proofs: Vec<DistributedFabricObservedTransportProofV1>,
    raw_code: u16,
    generations: TerminalGenerations,
    terminal_mode: &'a ActivationTerminalMode,
}

/// Conservative compatibility path used only when no Evidence owner was
/// configured for an older deployment. Configured PXDA-v2 activation bypasses
/// this helper and durably commits exact PXTP records first.
fn experimental_snapshot_success_decision(
    snapshot: ValidatedExperimentalSnapshot,
    raw_code: u16,
) -> CleanedNonReadyTerminalDecision {
    let ValidatedExperimentalSnapshot {
        fabric_generation: _validated_fabric_generation,
        session_epoch: _validated_session_epoch,
        peer_owner_facts: validated_peer_owner_facts,
    } = snapshot;
    // An explicitly unconfigured older deployment cannot claim Evidence.
    // Consume its locator-free correlation facts and remain non-ready.
    drop(validated_peer_owner_facts);
    CleanedNonReadyTerminalDecision {
        raw_code,
        proofs: Vec::new(),
    }
}

impl DistributedAgentStackRuntimeCore {
    pub(crate) fn open(
        owner: &ManagedFabricRuntimeCore,
        config: DistributedAgentStackOwnerConfig,
    ) -> Result<Option<Self>, DistributedAgentStackRuntimeError> {
        validate_owner_dependency_pair(&config)?;
        let projection_digest = projection_digest(&config.projection)?;
        let Some(stored_projection_digest) = owner.distributed_agent_stack_projection_digest()
        else {
            if owner.distributed_agent_stack_snapshot_bytes()?.is_some() {
                return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
            }
            return Ok(None);
        };
        if stored_projection_digest != projection_digest {
            return Err(DistributedAgentStackRuntimeError::ProjectionMismatch);
        }
        let frame = owner
            .distributed_agent_stack_snapshot_bytes()?
            .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?;
        let snapshot = DistributedAgentStackSnapshot::decode(
            frame,
            owner.store_instance_id(),
            owner.owner_target_fingerprint(),
            projection_digest,
            &config.projection,
        )?;
        if config.runtime_host_epoch == 0
            || config.runtime_host_epoch <= snapshot.runtime_host_epoch()
            || config.clock.generation().value() == 0
        {
            return Err(DistributedAgentStackRuntimeError::RuntimeEpochRegressed);
        }
        validate_evidence_configuration(&snapshot, config.evidence_store_config.as_ref())?;
        let evidence_store = open_evidence_store(config.evidence_store_config.as_ref())?;
        if let (Some(evidence_config), Some(store)) = (
            config.evidence_store_config.as_ref(),
            evidence_store.as_ref(),
        ) {
            validate_opened_evidence_store(snapshot.evidence_state(), evidence_config, store)?;
        }
        Ok(Some(Self::from_snapshot(
            snapshot,
            config,
            evidence_store,
            false,
        )))
    }

    fn from_snapshot(
        snapshot: DistributedAgentStackSnapshot,
        config: DistributedAgentStackOwnerConfig,
        evidence_store: Option<LocalEvidenceStoreV1>,
        recovery_completed: bool,
    ) -> Self {
        Self {
            snapshot,
            projection: config.projection,
            state_directory: config.state_directory,
            runtime_host_epoch: config.runtime_host_epoch,
            clock: config.clock,
            response_key_ref: config.response_key_ref,
            response_signer: config.response_signer,
            handle_broker: config.handle_broker,
            fabric_credential_resolver: config.fabric_credential_resolver,
            evidence_store_config: config.evidence_store_config,
            evidence_store,
            agent_provider_resolver: config.agent_provider_resolver,
            cancellation: CancellationSource::root(),
            fabric: None,
            assembly: None,
            handle: None,
            handle_publication_pending: false,
            recovery_completed,
        }
    }

    /// Establishes the additive PXDA-v2 Evidence authority before any live
    /// Fabric or Agent effect. The upgrade and exact owner binding are
    /// separate durable successors, so a crash can never make v1 bytes look
    /// as though they already carried Evidence authority.
    fn ensure_evidence_binding(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
    ) -> Result<(), DistributedAgentStackRuntimeError> {
        let Some(configured_binding) = self
            .evidence_store_config
            .as_ref()
            .map(DistributedAgentStackEvidenceStoreConfigV1::binding)
        else {
            if !evidence_state_is_empty(self.snapshot.evidence_state()) {
                return Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch);
            }
            return Ok(());
        };
        let store = self
            .evidence_store
            .as_ref()
            .ok_or(DistributedAgentStackRuntimeError::EvidenceStoreUnavailable)?;
        if store.store_epoch() != configured_binding.store_epoch() {
            return Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch);
        }
        if self.snapshot.wire_version() == DistributedAgentStackSnapshotWireVersion::V1 {
            let upgraded = self
                .snapshot
                .try_upgrade_v1_to_v2_at_epoch(self.runtime_host_epoch, &self.projection)?;
            owner.commit_distributed_agent_stack(upgraded.canonical_wire())?;
            self.snapshot = upgraded;
        }
        match self.snapshot.evidence_state().binding() {
            Some(binding) if binding == configured_binding => Ok(()),
            Some(_) => Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch),
            None => {
                if self.snapshot.evidence_state().owner_head().is_some()
                    || !matches!(
                        self.snapshot.evidence_state().handoff(),
                        DistributedAgentStackEvidenceHandoffV2::None
                    )
                {
                    return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
                }
                let evidence_state = DistributedAgentStackEvidenceStateV2::try_new(
                    Some(configured_binding),
                    None,
                    DistributedAgentStackEvidenceHandoffV2::None,
                )?;
                self.commit_v2_transition(owner, self.snapshot.transition(), evidence_state)
            }
        }
    }

    fn commit_v2_transition(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        transition: DistributedAgentStackSnapshotTransition,
        evidence_state: DistributedAgentStackEvidenceStateV2,
    ) -> Result<(), DistributedAgentStackRuntimeError> {
        let next = self.snapshot.try_v2_successor_at_epoch(
            self.runtime_host_epoch,
            transition,
            evidence_state,
            &self.projection,
        )?;
        owner.commit_distributed_agent_stack(next.canonical_wire())?;
        self.snapshot = next;
        Ok(())
    }

    fn begin_evidence_commit(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        batch: DistributedAgentStackEvidenceBatchV2,
    ) -> Result<(), DistributedAgentStackRuntimeError> {
        let binding = self
            .snapshot
            .evidence_state()
            .binding()
            .ok_or(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch)?;
        let owner_head = self.snapshot.evidence_state().owner_head();
        if batch.base_head() != owner_head
            || !matches!(
                self.snapshot.evidence_state().handoff(),
                DistributedAgentStackEvidenceHandoffV2::None
            )
        {
            return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
        }
        let evidence_state = DistributedAgentStackEvidenceStateV2::try_new(
            Some(binding),
            owner_head,
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch),
        )?;
        let mut transition = self.snapshot.transition();
        transition.phase = DistributedAgentStackDurablePhase::EvidenceCommitIntent;
        transition.physical_binding_census = 0;
        transition.census_complete = true;
        transition.fabric_ready = true;
        transition.agent_ready = false;
        transition.dependency_satisfied = true;
        transition.exact_zero = false;
        transition.quarantined = false;
        transition.installed_binding_set_digest = None;
        transition.raw_outcome_digest = None;
        transition.quarantine_reason = None;
        self.commit_v2_transition(owner, transition, evidence_state)
    }

    fn append_evidence_batch_with_one_reopen(
        &mut self,
        batch: &DistributedAgentStackEvidenceBatchV2,
    ) -> Result<VerifiedEvidenceStoreWrite, DistributedAgentStackRuntimeError> {
        let first = append_and_verify_evidence_batch(
            self.evidence_store
                .as_mut()
                .ok_or(DistributedAgentStackRuntimeError::EvidenceStoreUnavailable)?,
            batch,
        );
        match first {
            Ok(receipts) => Ok(receipts),
            Err(DistributedAgentStackRuntimeError::EvidenceStore(
                EvidenceStoreError::CommitUncertain(_) | EvidenceStoreError::Poisoned,
            )) => {
                let config = self
                    .evidence_store_config
                    .clone()
                    .ok_or(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch)?;
                // The old handle is poisoned and must not be queried again.
                drop(self.evidence_store.take());
                let reopened = LocalEvidenceStoreV1::open(
                    config.root(),
                    config.store_epoch(),
                    config.retention_policy(),
                )?;
                self.evidence_store = Some(reopened);
                // Start at the durable batch head exactly once. Existing IDs
                // replay bit-for-bit; a missing tail is appended once. Any
                // second uncertainty is returned with phase 11 intact.
                append_and_verify_evidence_batch(
                    self.evidence_store
                        .as_mut()
                        .ok_or(DistributedAgentStackRuntimeError::EvidenceStoreUnavailable)?,
                    batch,
                )
            }
            Err(error) => Err(error),
        }
    }

    fn mark_evidence_committed(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        verified: &VerifiedEvidenceStoreWrite,
    ) -> Result<(), DistributedAgentStackRuntimeError> {
        let evidence_state = self
            .snapshot
            .evidence_state()
            .try_mark_committed(&verified.receipts, &verified.readback)?;
        let mut transition = self.snapshot.transition();
        // This existing phase is the strict post-Fabric/pre-Agent shape. No
        // Agent start is performed by this owner tranche.
        transition.phase = DistributedAgentStackDurablePhase::AgentStartIntent;
        self.commit_v2_transition(owner, transition, evidence_state)
    }

    pub(crate) async fn cutover(
        owner: &mut ManagedFabricRuntimeCore,
        predecessor: &mut ManagedAgentStackRuntimeCore,
        config: DistributedAgentStackOwnerConfig,
        request: DistributedAgentStackApplyRequestV1,
        verified: VerifiedDistributedAgentStackApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<(Self, DistributedAgentStackApplyOutcome), DistributedAgentStackRuntimeError> {
        validate_owner_dependency_pair(&config)?;
        validate_request(owner, &config.projection, &request, response_channel)?;
        if owner.distributed_agent_stack_projection_digest().is_some()
            || request.target_execution().mode()
                != DistributedAgentStackTargetModeV1::DistributedFabricAndAgent
        {
            return Err(DistributedAgentStackRuntimeError::RequestRejected);
        }
        observe_deadline(config.clock, verified)?;
        let predecessor_observation = predecessor.distributed_cutover_observation()?;
        if request.target_execution().predecessor() != &predecessor_observation.execution
            || request.control_commitment().control().expected_active()
                != ExpectedActive::Exact(predecessor_observation.target_slice_digest)
        {
            return Err(DistributedAgentStackRuntimeError::PredecessorMismatch);
        }
        let evidence_store = open_evidence_store(config.evidence_store_config.as_ref())?;
        let fabric_generation = next_generation(predecessor_observation.fabric_generation.value())?;
        let agent_generation = next_generation(predecessor_observation.agent_generation.value())?;
        let prepared = prepare_generation(
            config.fabric_credential_resolver.as_deref(),
            &request,
            fabric_generation,
        )?;
        let transition = initial_transition(
            &request,
            verified,
            response_channel,
            fabric_generation,
            agent_generation,
        )?;
        let projection_digest = projection_digest(&config.projection)?;
        let snapshot = DistributedAgentStackSnapshot::try_initial(
            owner.store_instance_id(),
            owner.owner_target_fingerprint(),
            projection_digest,
            config.runtime_host_epoch,
            transition,
            &config.projection,
        )?;
        if let (Some(evidence_config), Some(store)) = (
            config.evidence_store_config.as_ref(),
            evidence_store.as_ref(),
        ) {
            validate_opened_evidence_store(snapshot.evidence_state(), evidence_config, store)?;
        }
        owner.initialize_distributed_agent_stack(projection_digest, snapshot.canonical_wire())?;
        let mut core = Self::from_snapshot(snapshot, config, evidence_store, true);
        if core.ensure_evidence_binding(owner).is_err() {
            // Durable authority has transferred. Return its core even on
            // failure so the endpoint can install it before ordered shutdown;
            // dropping it here could abandon a phase-11 or uncertain owner.
            core.recovery_completed = false;
            return Ok((
                core,
                DistributedAgentStackApplyOutcome::CommittedOwnerRestartRequired,
            ));
        }
        core.fabric = prepared;

        if predecessor.shutdown(owner).await.is_err() {
            let receipt = core.terminalize_quarantined(
                owner,
                &request,
                response_channel,
                Vec::new(),
                20,
                TerminalGenerations {
                    fabric: Some(fabric_generation),
                    agent: Some(agent_generation),
                },
            );
            return match receipt {
                Ok(receipt) => Ok((core, DistributedAgentStackApplyOutcome::Committed(receipt))),
                Err(_) => {
                    core.recovery_completed = false;
                    Ok((
                        core,
                        DistributedAgentStackApplyOutcome::CommittedOwnerRestartRequired,
                    ))
                }
            };
        }
        let terminal_mode = ActivationTerminalMode::RecordActiveReady;
        let receipt = core
            .execute_pending_activation(
                owner,
                ActivationContext {
                    request: &request,
                    response_channel,
                    fabric_generation,
                    agent_generation,
                    raw_code: 30,
                    terminal_mode: &terminal_mode,
                },
            )
            .await;
        match receipt {
            Ok(receipt) => {
                let outcome = core.activation_apply_outcome(receipt);
                Ok((core, outcome))
            }
            Err(_) => {
                core.recovery_completed = false;
                Ok((
                    core,
                    DistributedAgentStackApplyOutcome::CommittedOwnerRestartRequired,
                ))
            }
        }
    }

    pub(crate) fn authenticated_terminal_replay(
        &mut self,
        owner: &ManagedFabricRuntimeCore,
        request: &DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<Option<DistributedAgentStackTerminalReceiptV1>, DistributedAgentStackRuntimeError>
    {
        validate_request(owner, &self.projection, request, response_channel)?;
        let receipt = self.lookup_terminal(request, response_channel)?;
        if self.handle_publication_pending {
            let active = receipt
                .as_ref()
                .filter(|receipt| {
                    receipt.facts().outcome() == DistributedAgentStackTerminalOutcomeV1::ActiveReady
                })
                .ok_or(DistributedAgentStackRuntimeError::HandlePublicationPending)?;
            let handle = self
                .handle
                .as_ref()
                .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?;
            if self
                .handle_broker
                .publish_distributed(handle.clone(), active)
                .is_err()
            {
                return Err(DistributedAgentStackRuntimeError::HandlePublicationPending);
            }
            self.handle_publication_pending = false;
        }
        Ok(receipt)
    }

    #[cfg(test)]
    pub(crate) fn durable_current_is_exact_zero_for_test(&self) -> bool {
        self.snapshot.phase == DistributedAgentStackDurablePhase::ExactZero
            && self.snapshot.active.is_none()
            && self.snapshot.pending.is_none()
            && self.snapshot.physical_binding_census == 0
            && self.snapshot.census_complete
            && !self.snapshot.fabric_ready
            && !self.snapshot.agent_ready
            && !self.snapshot.dependency_satisfied
            && self.snapshot.exact_zero
            && !self.snapshot.quarantined
            && self.snapshot.installed_binding_set_digest
                == distributed_agent_stack_empty_binding_set_digest_v1().ok()
    }

    pub(crate) async fn apply(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        request: DistributedAgentStackApplyRequestV1,
        verified: VerifiedDistributedAgentStackApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<DistributedAgentStackApplyOutcome, DistributedAgentStackRuntimeError> {
        if !self.recovery_completed {
            return Err(DistributedAgentStackRuntimeError::RecoveryNotCompleted);
        }
        validate_request(owner, &self.projection, &request, response_channel)?;
        if let Some(receipt) = self.lookup_terminal(&request, response_channel)? {
            return Ok(DistributedAgentStackApplyOutcome::Replayed(receipt));
        }
        observe_deadline(self.clock, verified)?;
        let mut transition = self.admit_transition(&request, verified)?;
        if request.target_execution().mode() == DistributedAgentStackTargetModeV1::EmptyDeactivate {
            let receipt = self
                .apply_empty(owner, request, verified, response_channel, transition)
                .await?;
            return Ok(DistributedAgentStackApplyOutcome::Committed(receipt));
        }
        if self.snapshot.phase != DistributedAgentStackDurablePhase::ExactZero {
            return Err(DistributedAgentStackRuntimeError::ActiveReplacementRequiresEmpty);
        }
        if request.control_commitment().control().expected_active() != ExpectedActive::None {
            return Err(DistributedAgentStackRuntimeError::ExpectedActiveMismatch);
        }
        let fabric_generation = next_generation(self.snapshot.fabric_generation_high_water)?;
        let agent_generation = next_generation(self.snapshot.agent_generation_high_water)?;
        transition.fabric_generation_high_water = fabric_generation.value();
        transition.agent_generation_high_water = agent_generation.value();
        transition.phase = DistributedAgentStackDurablePhase::PreparedNoEffects;
        transition.pending = Some(DistributedAgentStackDurablePending {
            kind: DistributedAgentStackPendingKind::ActivateDistributedStack,
            fabric_generation: Some(fabric_generation),
            agent_generation: Some(agent_generation),
            admitted_clock_generation: verified.clock_generation(),
            admitted_at_nanos: verified.admitted_at_nanos(),
            deadline_nanos: verified.deadline_nanos(),
            response_channel,
            request: request.clone(),
        });
        transition.exact_zero = false;
        transition.installed_binding_set_digest = None;
        transition.raw_outcome_digest = None;
        self.fabric = prepare_generation(
            self.fabric_credential_resolver.as_deref(),
            &request,
            fabric_generation,
        )?;
        self.commit_transition(owner, transition)?;
        let terminal_mode = ActivationTerminalMode::RecordActiveReady;
        let receipt = self
            .execute_pending_activation(
                owner,
                ActivationContext {
                    request: &request,
                    response_channel,
                    fabric_generation,
                    agent_generation,
                    raw_code: 50,
                    terminal_mode: &terminal_mode,
                },
            )
            .await?;
        Ok(self.activation_apply_outcome(receipt))
    }

    async fn apply_empty(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        request: DistributedAgentStackApplyRequestV1,
        verified: VerifiedDistributedAgentStackApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
        mut transition: DistributedAgentStackSnapshotTransition,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        if self.snapshot.phase == DistributedAgentStackDurablePhase::ExactZero {
            if request.control_commitment().control().expected_active() != ExpectedActive::None {
                return Err(DistributedAgentStackRuntimeError::ExpectedActiveMismatch);
            }
            transition.phase = DistributedAgentStackDurablePhase::ExactZero;
            return self.terminalize_empty_exact_zero(
                owner,
                &request,
                response_channel,
                transition,
                90,
            );
        }
        if self.snapshot.phase != DistributedAgentStackDurablePhase::ActiveReady {
            return Err(DistributedAgentStackRuntimeError::RecoveryNotCompleted);
        }
        let active = self
            .snapshot
            .active
            .as_ref()
            .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?
            .clone();
        if request.control_commitment().control().expected_active()
            != ExpectedActive::Exact(active.request.target_slice_digest())
        {
            return Err(DistributedAgentStackRuntimeError::ExpectedActiveMismatch);
        }
        transition.phase = DistributedAgentStackDurablePhase::AgentRetireIntent;
        transition.pending = Some(DistributedAgentStackDurablePending {
            kind: DistributedAgentStackPendingKind::DeactivateStack,
            fabric_generation: Some(active.fabric_generation),
            agent_generation: Some(active.agent_generation),
            admitted_clock_generation: verified.clock_generation(),
            admitted_at_nanos: verified.admitted_at_nanos(),
            deadline_nanos: verified.deadline_nanos(),
            response_channel,
            request: request.clone(),
        });
        self.commit_transition(owner, transition)?;
        self.revoke_owned_handle()?;
        self.handle = None;
        let agent_stopped = if let Some(assembly) = self.assembly.as_mut() {
            assembly.shutdown().await.is_ok()
        } else {
            false
        };
        if !agent_stopped {
            self.commit_cleanup_quarantine(owner, &request, 91)?;
            return Err(DistributedAgentStackRuntimeError::ShutdownUncertain);
        }
        self.assembly = None;
        let mut fabric_stop_intent = self.snapshot.transition();
        fabric_stop_intent.phase = DistributedAgentStackDurablePhase::FabricStopIntent;
        fabric_stop_intent.physical_binding_census = 0;
        fabric_stop_intent.fabric_ready = true;
        fabric_stop_intent.agent_ready = false;
        fabric_stop_intent.dependency_satisfied = false;
        self.commit_transition(owner, fabric_stop_intent)?;
        let fabric_stopped = if let Some(fabric) = self.fabric.as_mut() {
            fabric.stop(active.fabric_generation).await.is_ok()
        } else {
            false
        };
        if !fabric_stopped {
            self.commit_cleanup_quarantine(owner, &request, 92)?;
            return Err(DistributedAgentStackRuntimeError::ShutdownUncertain);
        }
        self.fabric = None;
        self.terminalize_empty_exact_zero(
            owner,
            &request,
            response_channel,
            self.snapshot.transition(),
            93,
        )
    }

    pub(crate) async fn recover(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
    ) -> Result<(), DistributedAgentStackRuntimeError> {
        if self.recovery_completed {
            return Ok(());
        }
        if self.fabric.is_some() || self.assembly.is_some() || self.handle.is_some() {
            return Err(DistributedAgentStackRuntimeError::RecoveryWhileLive);
        }
        self.ensure_evidence_binding(owner)?;
        if self.recover_evidence_handoff(owner).await? {
            return Ok(());
        }
        match self.snapshot.phase {
            DistributedAgentStackDurablePhase::ExactZero => {
                if self.snapshot.runtime_host_epoch() != self.runtime_host_epoch {
                    self.commit_transition(owner, self.snapshot.transition())?;
                }
                self.recovery_completed = true;
                return Ok(());
            }
            DistributedAgentStackDurablePhase::Quarantined
            | DistributedAgentStackDurablePhase::Uncertain => {
                return Err(DistributedAgentStackRuntimeError::RecoveryQuarantined);
            }
            DistributedAgentStackDurablePhase::EvidenceCommitIntent => {
                return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
            }
            DistributedAgentStackDurablePhase::AgentRetireIntent
            | DistributedAgentStackDurablePhase::FabricStopIntent => {
                self.handle_broker.revoke()?;
                let pending = self
                    .snapshot
                    .pending
                    .as_ref()
                    .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?
                    .clone();
                if pending.kind != DistributedAgentStackPendingKind::DeactivateStack {
                    return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
                }
                self.terminalize_empty_exact_zero(
                    owner,
                    &pending.request,
                    pending.response_channel,
                    self.snapshot.transition(),
                    94,
                )?;
                self.recovery_completed = true;
                return Ok(());
            }
            DistributedAgentStackDurablePhase::PreparedNoEffects
            | DistributedAgentStackDurablePhase::StartIntent
            | DistributedAgentStackDurablePhase::AgentStartIntent
            | DistributedAgentStackDurablePhase::ActiveReady
            | DistributedAgentStackDurablePhase::RecoveryIntent => {}
        }
        let (request, response_channel) = if let Some(active) = &self.snapshot.active {
            self.handle_broker.revoke()?;
            (active.request.clone(), active.response_channel)
        } else {
            let pending = self
                .snapshot
                .pending
                .as_ref()
                .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?;
            (pending.request.clone(), pending.response_channel)
        };
        let terminal_mode = match self.lookup_terminal(&request, response_channel)? {
            Some(historical)
                if historical.facts().outcome()
                    == DistributedAgentStackTerminalOutcomeV1::ActiveReady =>
            {
                self.validate_historical_active_terminal(&request, response_channel, &historical)?;
                ActivationTerminalMode::PreserveHistoricalActive(Box::new(historical))
            }
            Some(_) => return Err(DistributedAgentStackRuntimeError::InvalidDurableState),
            None => ActivationTerminalMode::RecordActiveReady,
        };
        self.restart_activation_with_fresh_evidence(
            owner,
            request,
            response_channel,
            terminal_mode,
            false,
        )
        .await
    }

    /// Resolves one old phase-11 handoff, but never treats its PXTP batch as
    /// authority to start Agent. After exact old-owner cleanup it clears the
    /// verified handoff into a fresh RecoveryIntent, advances both generations,
    /// and requires a new Fabric session plus a new PXTP/Evidence batch.
    async fn recover_evidence_handoff(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
    ) -> Result<bool, DistributedAgentStackRuntimeError> {
        let handoff = self.snapshot.evidence_state().handoff().clone();
        let batch = match handoff {
            DistributedAgentStackEvidenceHandoffV2::None => return Ok(false),
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch) => {
                if self.snapshot.phase != DistributedAgentStackDurablePhase::EvidenceCommitIntent {
                    return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
                }
                let verified = self.append_evidence_batch_with_one_reopen(&batch)?;
                self.mark_evidence_committed(owner, &verified)?;
                batch
            }
            DistributedAgentStackEvidenceHandoffV2::Committed(committed) => {
                if self.snapshot.phase != DistributedAgentStackDurablePhase::AgentStartIntent {
                    return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
                }
                committed.batch().clone()
            }
        };
        let pending = self
            .snapshot
            .pending
            .as_ref()
            .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?
            .clone();
        if pending.request.envelope_request_digest() != batch.request_digest()
            || pending.fabric_generation != Some(batch.fabric_generation())
            || pending.agent_generation.is_none()
        {
            return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
        }
        let terminal_mode =
            match self.lookup_terminal(&pending.request, pending.response_channel)? {
                Some(historical)
                    if historical.facts().outcome()
                        == DistributedAgentStackTerminalOutcomeV1::ActiveReady =>
                {
                    self.validate_historical_active_terminal(
                        &pending.request,
                        pending.response_channel,
                        &historical,
                    )?;
                    ActivationTerminalMode::PreserveHistoricalActive(Box::new(historical))
                }
                Some(_) => return Err(DistributedAgentStackRuntimeError::InvalidDurableState),
                None => ActivationTerminalMode::RecordActiveReady,
            };
        let proofs = exact_proofs_from_evidence_batch(&batch)?;
        self.handle_broker.revoke()?;
        if !self.cleanup_live().await {
            self.complete_uncertain_cleanup(
                owner,
                UncertainCleanupInput {
                    request: &pending.request,
                    response_channel: pending.response_channel,
                    proofs,
                    raw_code: 0x86,
                    generations: TerminalGenerations {
                        fabric: Some(batch.fabric_generation()),
                        agent: pending.agent_generation,
                    },
                    terminal_mode: &terminal_mode,
                },
            )?;
            return Err(DistributedAgentStackRuntimeError::RecoveryQuarantined);
        }
        drop(proofs);
        self.restart_activation_with_fresh_evidence(
            owner,
            pending.request,
            pending.response_channel,
            terminal_mode,
            true,
        )
        .await?;
        self.recovery_completed = true;
        Ok(true)
    }

    async fn restart_activation_with_fresh_evidence(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        request: DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        terminal_mode: ActivationTerminalMode,
        clear_committed_handoff: bool,
    ) -> Result<(), DistributedAgentStackRuntimeError> {
        let reading = self.clock.reading()?;
        let deadline_nanos = recovery_deadline(&request, reading)?;
        let fabric_generation = next_generation(self.snapshot.fabric_generation_high_water)?;
        let agent_generation = next_generation(self.snapshot.agent_generation_high_water)?;
        let prepared = prepare_generation(
            self.fabric_credential_resolver.as_deref(),
            &request,
            fabric_generation,
        )?;
        let mut intent = self.snapshot.transition();
        intent.fabric_generation_high_water = fabric_generation.value();
        intent.agent_generation_high_water = agent_generation.value();
        intent.phase = DistributedAgentStackDurablePhase::RecoveryIntent;
        intent.active = None;
        intent.pending = Some(DistributedAgentStackDurablePending {
            kind: DistributedAgentStackPendingKind::RecoverActive,
            fabric_generation: Some(fabric_generation),
            agent_generation: Some(agent_generation),
            admitted_clock_generation: reading.generation(),
            admitted_at_nanos: reading.now().value(),
            deadline_nanos,
            response_channel,
            request: request.clone(),
        });
        intent.physical_binding_census = 0;
        intent.census_complete = true;
        intent.fabric_ready = false;
        intent.agent_ready = false;
        intent.dependency_satisfied = false;
        intent.exact_zero = false;
        intent.quarantined = false;
        intent.installed_binding_set_digest = None;
        intent.raw_outcome_digest = None;
        intent.quarantine_reason = None;
        if clear_committed_handoff {
            let evidence_state = self.snapshot.evidence_state().try_clear_committed()?;
            self.commit_v2_transition(owner, intent, evidence_state)?;
        } else {
            self.commit_transition(owner, intent)?;
        }
        self.fabric = prepared;
        self.execute_pending_activation(
            owner,
            ActivationContext {
                request: &request,
                response_channel,
                fabric_generation,
                agent_generation,
                raw_code: 70,
                terminal_mode: &terminal_mode,
            },
        )
        .await?;
        if self.snapshot.phase == DistributedAgentStackDurablePhase::ExactZero {
            if self.snapshot.active.is_some()
                || self.snapshot.pending.is_some()
                || self.fabric.is_some()
                || self.assembly.is_some()
                || self.handle.is_some()
                || self.handle_publication_pending
            {
                self.recovery_completed = false;
                return Err(DistributedAgentStackRuntimeError::InvalidLifecycleState);
            }
            self.recovery_completed = true;
            return Ok(());
        }
        if self.snapshot.phase != DistributedAgentStackDurablePhase::ActiveReady
            || self.assembly.is_none()
            || self.handle.is_none()
        {
            self.recovery_completed = false;
            return Err(DistributedAgentStackRuntimeError::RecoveryQuarantined);
        }
        if self.handle_publication_pending {
            return Err(DistributedAgentStackRuntimeError::HandlePublicationPending);
        }
        self.recovery_completed = true;
        Ok(())
    }

    async fn execute_pending_activation(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        context: ActivationContext<'_>,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let request = context.request;
        let response_channel = context.response_channel;
        let fabric_generation = context.fabric_generation;
        let agent_generation = context.agent_generation;
        let raw_code = context.raw_code;
        let terminal_mode = context.terminal_mode;
        if self.fabric.is_none() {
            if !self.cleanup_live().await {
                return self.complete_uncertain_cleanup(
                    owner,
                    UncertainCleanupInput {
                        request,
                        response_channel,
                        proofs: Vec::new(),
                        raw_code,
                        generations: TerminalGenerations {
                            fabric: Some(fabric_generation),
                            agent: Some(agent_generation),
                        },
                        terminal_mode,
                    },
                );
            }
            return self.complete_exact_cleanup(
                owner,
                request,
                response_channel,
                CleanedNonReadyTerminalDecision {
                    raw_code,
                    proofs: Vec::new(),
                },
                terminal_mode,
            );
        }
        let mut start_intent = self.snapshot.transition();
        start_intent.phase = DistributedAgentStackDurablePhase::StartIntent;
        self.commit_transition(owner, start_intent)?;
        let fabric_start = self
            .fabric
            .as_mut()
            .ok_or(DistributedAgentStackRuntimeError::InvalidLifecycleState)?
            .start(fabric_generation, self.clock, &self.cancellation)
            .await;
        let fabric_control = match fabric_start {
            Ok(control) => control,
            Err(_) => {
                let exact = self.cleanup_live().await;
                return if exact {
                    self.complete_exact_cleanup(
                        owner,
                        request,
                        response_channel,
                        CleanedNonReadyTerminalDecision {
                            raw_code: raw_code + 1,
                            proofs: Vec::new(),
                        },
                        terminal_mode,
                    )
                } else {
                    self.complete_uncertain_cleanup(
                        owner,
                        UncertainCleanupInput {
                            request,
                            response_channel,
                            proofs: Vec::new(),
                            raw_code: raw_code + 2,
                            generations: TerminalGenerations {
                                fabric: Some(fabric_generation),
                                agent: None,
                            },
                            terminal_mode,
                        },
                    )
                };
            }
        };
        let snapshot_result = self
            .collect_experimental_snapshot(request, fabric_generation, &fabric_control)
            .await;
        let snapshot_result = match snapshot_result {
            Ok(snapshot) if self.evidence_store_config.is_some() => {
                return self
                    .commit_snapshot_evidence_and_activate(owner, snapshot, fabric_control, context)
                    .await;
            }
            other => other,
        };
        let exact = self.cleanup_live().await;
        if !exact {
            return self.complete_uncertain_cleanup(
                owner,
                UncertainCleanupInput {
                    request,
                    response_channel,
                    proofs: Vec::new(),
                    raw_code: if snapshot_result.is_ok() {
                        raw_code + 10
                    } else {
                        raw_code + 8
                    },
                    generations: TerminalGenerations {
                        fabric: Some(fabric_generation),
                        agent: None,
                    },
                    terminal_mode,
                },
            );
        }
        match snapshot_result {
            Ok(snapshot) => self.complete_exact_cleanup(
                owner,
                request,
                response_channel,
                experimental_snapshot_success_decision(snapshot, raw_code + 9),
                terminal_mode,
            ),
            Err(_) => self.complete_exact_cleanup(
                owner,
                request,
                response_channel,
                CleanedNonReadyTerminalDecision {
                    raw_code: raw_code + 7,
                    proofs: Vec::new(),
                },
                terminal_mode,
            ),
        }
    }

    async fn commit_snapshot_evidence_and_activate(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        snapshot: ValidatedExperimentalSnapshot,
        fabric_control: ManagedFabricControlHandle,
        context: ActivationContext<'_>,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let request = context.request;
        let raw_code = context.raw_code;
        let owner_ref = self
            .evidence_store_config
            .as_ref()
            .ok_or(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch)?
            .owner_ref();
        let fabric_generation = snapshot.fabric_generation;
        let context = ActivationContext {
            fabric_generation,
            ..context
        };
        let batch = match build_evidence_batch(
            request,
            snapshot,
            owner_ref,
            self.snapshot.evidence_state().owner_head(),
        ) {
            Ok(batch) => batch,
            Err(error) => {
                let _exact = self.cleanup_live().await;
                self.recovery_completed = false;
                self.commit_cleanup_quarantine(owner, request, raw_code + 11)?;
                return Err(error);
            }
        };
        if let Err(error) = self.begin_evidence_commit(owner, batch.clone()) {
            self.recovery_completed = false;
            return Err(error);
        }
        let verified = match self.append_evidence_batch_with_one_reopen(&batch) {
            Ok(verified) => verified,
            Err(error) => {
                // The durable phase-11 batch remains the sole replay source.
                // Do not clean up, sign a terminal, or synthesize a new batch.
                self.recovery_completed = false;
                return Err(error);
            }
        };
        if let Err(error) = self.mark_evidence_committed(owner, &verified) {
            self.recovery_completed = false;
            return Err(error);
        }
        let proofs = match exact_proofs_from_evidence_batch(&batch) {
            Ok(proofs) => proofs,
            Err(error) => {
                self.recovery_completed = false;
                return Err(error);
            }
        };
        self.start_agent_after_verified_evidence(owner, fabric_control, proofs, context)
            .await
    }

    async fn start_agent_after_verified_evidence(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        fabric_control: ManagedFabricControlHandle,
        proofs: Vec<DistributedFabricObservedTransportProofV1>,
        context: ActivationContext<'_>,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let request = context.request;
        let response_channel = context.response_channel;
        let fabric_generation = context.fabric_generation;
        let agent_generation = context.agent_generation;
        let raw_code = context.raw_code;
        let terminal_mode = context.terminal_mode;
        let pending = self
            .snapshot
            .pending
            .as_ref()
            .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?;
        let committed_batch = match self.snapshot.evidence_state().handoff() {
            DistributedAgentStackEvidenceHandoffV2::Committed(committed) => committed.batch(),
            DistributedAgentStackEvidenceHandoffV2::None
            | DistributedAgentStackEvidenceHandoffV2::CommitIntent(_) => {
                return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
            }
        };
        if self.snapshot.phase != DistributedAgentStackDurablePhase::AgentStartIntent
            || pending.request.envelope_request_digest() != request.envelope_request_digest()
            || pending.response_channel != response_channel
            || pending.fabric_generation != Some(fabric_generation)
            || pending.agent_generation != Some(agent_generation)
            || committed_batch.request_digest() != request.envelope_request_digest()
            || committed_batch.fabric_generation() != fabric_generation
            || fabric_control.generation() != fabric_generation
            || exact_proofs_from_evidence_batch(committed_batch)? != proofs
        {
            return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
        }
        let empty_census = fabric_control.binding_census().await;
        if !matches!(empty_census, Ok(0)) {
            self.recovery_completed = false;
            return self.commit_agent_activation_quarantine(
                owner,
                proofs,
                context.with_raw_code(raw_code + 12),
            );
        }

        let started = ManagedAgentAssembly::start_from_execution(
            fabric_control.clone(),
            request.target_execution().predecessor(),
            self.state_directory.clone(),
            self.agent_provider_resolver.as_ref(),
        )
        .await;
        let (assembly, handle) = match started {
            Ok(started) => started,
            Err(error) => {
                self.recovery_completed = false;
                return self
                    .complete_agent_activation_failure(
                        owner,
                        proofs,
                        context.with_raw_code(raw_code + 13),
                        None,
                        agent_start_failure_requires_fabric_retention(&error),
                    )
                    .await;
            }
        };

        let installed_binding_set_digest = assembly
            .installed_binding_descriptor_digests()
            .ok()
            .and_then(|(request_descriptor, event_descriptor)| {
                distributed_agent_stack_installed_binding_set_digest_v1(
                    request_descriptor,
                    event_descriptor,
                )
                .ok()
            });
        let installed_binding_set_digest = match (
            installed_binding_set_digest,
            fabric_control.binding_census().await,
        ) {
            (Some(digest), Ok(2)) => digest,
            _ => {
                drop(handle);
                self.recovery_completed = false;
                return self
                    .complete_agent_activation_failure(
                        owner,
                        proofs,
                        context.with_raw_code(raw_code + 14),
                        Some(assembly),
                        false,
                    )
                    .await;
            }
        };

        let ready_result: Result<_, DistributedAgentStackRuntimeError> = (|| {
            let raw_outcome_digest = raw_outcome_digest(raw_code + 9, request)?;
            let observations =
                DistributedAgentStackTerminalObservationsV1::try_new(request, proofs.clone())?;
            let mut ready = self.snapshot.transition();
            ready.phase = DistributedAgentStackDurablePhase::ActiveReady;
            ready.active = Some(DistributedAgentStackDurableActive {
                fabric_generation,
                agent_generation,
                response_channel,
                request: request.clone(),
            });
            ready.pending = None;
            ready.physical_binding_census = 2;
            ready.census_complete = true;
            ready.fabric_ready = true;
            ready.agent_ready = true;
            ready.dependency_satisfied = true;
            ready.exact_zero = false;
            ready.quarantined = false;
            ready.installed_binding_set_digest = Some(installed_binding_set_digest);
            ready.raw_outcome_digest = Some(raw_outcome_digest);
            ready.quarantine_reason = None;
            let receipt = match terminal_mode {
                ActivationTerminalMode::RecordActiveReady => {
                    let receipt = self.build_terminal(
                        request,
                        response_channel,
                        TerminalSelection {
                            outcome: DistributedAgentStackTerminalOutcomeV1::ActiveReady,
                            generations: TerminalGenerations {
                                fabric: Some(fabric_generation),
                                agent: Some(agent_generation),
                            },
                            local_bindings: DistributedAgentStackLocalBindingEvidenceFieldsV1 {
                                physical_binding_census: 2,
                                census_complete: true,
                                fabric_ready: true,
                                agent_ready: true,
                                dependency_satisfied: true,
                                exact_zero: false,
                                quarantined: false,
                                installed_binding_set_digest,
                                raw_outcome_digest,
                            },
                        },
                        observations,
                    )?;
                    insert_terminal(&mut ready.terminals, request, receipt.clone())?;
                    receipt
                }
                ActivationTerminalMode::PreserveHistoricalActive(historical) => {
                    self.validate_historical_active_terminal(
                        request,
                        response_channel,
                        historical.as_ref(),
                    )?;
                    historical.as_ref().clone()
                }
            };
            let cleared_evidence = self.snapshot.evidence_state().try_clear_committed()?;
            Ok((ready, cleared_evidence, receipt))
        })();
        let (ready, cleared_evidence, receipt) = match ready_result {
            Ok(ready) => ready,
            Err(_) => {
                drop(handle);
                self.recovery_completed = false;
                return self
                    .complete_agent_activation_failure(
                        owner,
                        proofs,
                        context.with_raw_code(raw_code + 15),
                        Some(assembly),
                        false,
                    )
                    .await;
            }
        };
        if let Err(error) = self.commit_v2_transition(owner, ready, cleared_evidence) {
            drop(handle);
            self.cleanup_unpublished_agent_after_commit_failure(assembly)
                .await;
            self.recovery_completed = false;
            return Err(error);
        }

        self.assembly = Some(assembly);
        self.handle = Some(handle.clone());
        self.handle_publication_pending = self
            .handle_broker
            .publish_distributed(handle, &receipt)
            .is_err();
        self.recovery_completed = true;
        Ok(receipt)
    }

    fn activation_apply_outcome(
        &self,
        receipt: DistributedAgentStackTerminalReceiptV1,
    ) -> DistributedAgentStackApplyOutcome {
        if self.handle_publication_pending {
            DistributedAgentStackApplyOutcome::CommittedHandleUnavailable(receipt)
        } else {
            DistributedAgentStackApplyOutcome::Committed(receipt)
        }
    }

    async fn complete_agent_activation_failure(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        proofs: Vec<DistributedFabricObservedTransportProofV1>,
        context: ActivationContext<'_>,
        assembly: Option<ManagedAgentAssembly>,
        mut agent_cleanup_uncertain: bool,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let request = context.request;
        let response_channel = context.response_channel;
        let raw_code = context.raw_code;
        let fabric_generation = context.fabric_generation;
        let agent_generation = context.agent_generation;
        let terminal_mode = context.terminal_mode;
        self.handle = None;
        self.handle_publication_pending = false;
        if let Some(mut assembly) = assembly
            && assembly.shutdown().await.is_err()
        {
            self.assembly = Some(assembly);
            agent_cleanup_uncertain = true;
        }
        if agent_cleanup_uncertain {
            return self.commit_agent_activation_quarantine(owner, proofs, context);
        }
        if self.cleanup_live().await {
            self.complete_exact_cleanup(
                owner,
                request,
                response_channel,
                CleanedNonReadyTerminalDecision { raw_code, proofs },
                terminal_mode,
            )
        } else {
            self.complete_uncertain_cleanup(
                owner,
                UncertainCleanupInput {
                    request,
                    response_channel,
                    proofs,
                    raw_code,
                    generations: TerminalGenerations {
                        fabric: Some(fabric_generation),
                        agent: Some(agent_generation),
                    },
                    terminal_mode,
                },
            )
        }
    }

    async fn cleanup_unpublished_agent_after_commit_failure(
        &mut self,
        mut assembly: ManagedAgentAssembly,
    ) {
        self.handle = None;
        self.handle_publication_pending = false;
        if assembly.shutdown().await.is_err() {
            self.assembly = Some(assembly);
            return;
        }
        let _ = self.cleanup_live().await;
    }

    fn commit_agent_activation_quarantine(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        proofs: Vec<DistributedFabricObservedTransportProofV1>,
        context: ActivationContext<'_>,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let request = context.request;
        let response_channel = context.response_channel;
        let raw_code = context.raw_code;
        let fabric_generation = context.fabric_generation;
        let agent_generation = context.agent_generation;
        self.handle = None;
        self.handle_publication_pending = false;
        match context.terminal_mode {
            ActivationTerminalMode::RecordActiveReady => self.terminalize_quarantined(
                owner,
                request,
                response_channel,
                proofs,
                raw_code,
                TerminalGenerations {
                    fabric: Some(fabric_generation),
                    agent: Some(agent_generation),
                },
            ),
            ActivationTerminalMode::PreserveHistoricalActive(historical) => {
                self.validate_historical_active_terminal(
                    request,
                    response_channel,
                    historical.as_ref(),
                )?;
                self.commit_cleanup_quarantine(owner, request, raw_code)?;
                Ok(historical.as_ref().clone())
            }
        }
    }

    async fn collect_experimental_snapshot(
        &self,
        request: &DistributedAgentStackApplyRequestV1,
        fabric_generation: ManagedServiceGeneration,
        control: &ManagedFabricControlHandle,
    ) -> Result<ValidatedExperimentalSnapshot, DistributedAgentStackRuntimeError> {
        let topology = request
            .target_execution()
            .topology()
            .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?;
        let peer_count = topology.peers().len();
        let expected_peer_requirement_digests = topology
            .peers()
            .iter()
            .map(|peer| peer.requirement_digest())
            .collect::<Vec<_>>();
        let expected_binding_digests = {
            let fabric = self
                .fabric
                .as_ref()
                .ok_or(DistributedAgentStackRuntimeError::InvalidLifecycleState)?;
            if fabric.generation() != fabric_generation
                || control.generation() != fabric_generation
                || fabric.execution_digest() != request.target_execution().execution_digest()
            {
                return Err(DistributedAgentStackRuntimeError::ObservationCorrelationMismatch);
            }
            if fabric.peer_requirement_digests() != expected_peer_requirement_digests.as_slice() {
                return Err(DistributedAgentStackRuntimeError::ObservationCorrelationMismatch);
            }
            fabric
                .experimental_identity_binding_digests()
                .ok_or(DistributedAgentStackRuntimeError::ObservationCorrelationMismatch)?
                .to_vec()
        };
        if expected_binding_digests.len() != peer_count {
            return Err(DistributedAgentStackRuntimeError::ObservationCorrelationMismatch);
        }
        let deadline = self.experimental_snapshot_deadline(request, fabric_generation)?;
        let snapshot = control
            .observe_experimental_remote_mtls_links_once(deadline)
            .await?;
        let peer_owner_facts = snapshot
            .remote_peers()
            .iter()
            .map(|peer| ValidatedExperimentalPeerOwnerFacts {
                identity_binding_digest: peer.identity_binding_digest(),
                observation_sequence: peer.observation_sequence(),
            })
            .collect::<Vec<_>>();
        let observed_binding_digests = peer_owner_facts
            .iter()
            .map(|peer| peer.identity_binding_digest)
            .collect::<Vec<_>>();
        validate_experimental_binding_order(&expected_binding_digests, &observed_binding_digests)?;
        let session_epoch = snapshot.session_epoch();
        drop(snapshot);
        Ok(ValidatedExperimentalSnapshot {
            fabric_generation,
            session_epoch,
            // PXTP needs the binding-correlated owner sequence, but not raw
            // Zenoh IDs or locators. The raw snapshot was consumed without
            // cloning those sensitive point-in-time transport details.
            peer_owner_facts: peer_owner_facts.into_boxed_slice(),
        })
    }

    fn experimental_snapshot_deadline(
        &self,
        request: &DistributedAgentStackApplyRequestV1,
        fabric_generation: ManagedServiceGeneration,
    ) -> Result<Instant, DistributedAgentStackRuntimeError> {
        let pending = self
            .snapshot
            .pending
            .as_ref()
            .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?;
        if pending.fabric_generation != Some(fabric_generation)
            || pending.request.envelope_request_digest() != request.envelope_request_digest()
        {
            return Err(DistributedAgentStackRuntimeError::ObservationCorrelationMismatch);
        }
        let reactor_sample = Instant::now();
        let reading = self.clock.reading()?;
        map_runtime_deadline_from_prior_reactor_sample(
            reactor_sample,
            reading,
            pending.admitted_clock_generation,
            pending.deadline_nanos,
        )
    }

    fn complete_exact_cleanup(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        request: &DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        decision: CleanedNonReadyTerminalDecision,
        terminal_mode: &ActivationTerminalMode,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let receipt = match terminal_mode {
            ActivationTerminalMode::RecordActiveReady => {
                self.commit_cleaned_non_ready_terminal(owner, request, response_channel, decision)
            }
            ActivationTerminalMode::PreserveHistoricalActive(historical) => self
                .commit_recovery_exact_zero_preserving_terminal(
                    owner,
                    request,
                    response_channel,
                    historical.as_ref(),
                    decision.raw_code,
                ),
        }?;
        // Only a successfully persisted ExactZero successor reopens this
        // owner for a new operation. Phase-11, uncertain, and quarantined
        // paths never reach this assignment.
        self.recovery_completed = true;
        Ok(receipt)
    }

    fn complete_uncertain_cleanup(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        input: UncertainCleanupInput<'_>,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let UncertainCleanupInput {
            request,
            response_channel,
            proofs,
            raw_code,
            generations,
            terminal_mode,
        } = input;
        match terminal_mode {
            ActivationTerminalMode::RecordActiveReady => self.terminalize_quarantined(
                owner,
                request,
                response_channel,
                proofs,
                raw_code,
                generations,
            ),
            ActivationTerminalMode::PreserveHistoricalActive(historical) => {
                self.validate_historical_active_terminal(
                    request,
                    response_channel,
                    historical.as_ref(),
                )?;
                self.commit_cleanup_quarantine(owner, request, raw_code)?;
                Ok(historical.as_ref().clone())
            }
        }
    }

    fn commit_cleaned_non_ready_terminal(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        request: &DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        decision: CleanedNonReadyTerminalDecision,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let installed_binding_set_digest = distributed_agent_stack_empty_binding_set_digest_v1()?;
        let raw_outcome_digest = raw_outcome_digest(decision.raw_code, request)?;
        let selection =
            decision.receipt_selection(installed_binding_set_digest, raw_outcome_digest);
        let observations =
            DistributedAgentStackTerminalObservationsV1::try_new(request, decision.proofs)?;
        let receipt = self.build_terminal(request, response_channel, selection, observations)?;
        let mut exact_zero = self.snapshot.transition();
        exact_zero.phase = DistributedAgentStackDurablePhase::ExactZero;
        exact_zero.active = None;
        exact_zero.pending = None;
        exact_zero.physical_binding_census = 0;
        exact_zero.census_complete = true;
        exact_zero.fabric_ready = false;
        exact_zero.agent_ready = false;
        exact_zero.dependency_satisfied = false;
        exact_zero.exact_zero = true;
        exact_zero.quarantined = false;
        exact_zero.installed_binding_set_digest = Some(installed_binding_set_digest);
        exact_zero.raw_outcome_digest = Some(raw_outcome_digest);
        exact_zero.quarantine_reason = None;
        insert_terminal(&mut exact_zero.terminals, request, receipt.clone())?;
        self.commit_transition_clearing_committed_evidence(owner, exact_zero)?;
        self.revoke_owned_handle()?;
        Ok(receipt)
    }

    fn commit_recovery_exact_zero_preserving_terminal(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        request: &DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        historical: &DistributedAgentStackTerminalReceiptV1,
        raw_code: u16,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        self.validate_historical_active_terminal(request, response_channel, historical)?;
        let installed_binding_set_digest = distributed_agent_stack_empty_binding_set_digest_v1()?;
        let raw_outcome_digest = raw_outcome_digest(raw_code, request)?;
        let mut exact_zero = self.snapshot.transition();
        exact_zero.phase = DistributedAgentStackDurablePhase::ExactZero;
        exact_zero.active = None;
        exact_zero.pending = None;
        exact_zero.physical_binding_census = 0;
        exact_zero.census_complete = true;
        exact_zero.fabric_ready = false;
        exact_zero.agent_ready = false;
        exact_zero.dependency_satisfied = false;
        exact_zero.exact_zero = true;
        exact_zero.quarantined = false;
        exact_zero.installed_binding_set_digest = Some(installed_binding_set_digest);
        exact_zero.raw_outcome_digest = Some(raw_outcome_digest);
        exact_zero.quarantine_reason = None;
        // Terminals are immutable operation facts. The transition carries the
        // existing vector unchanged while current durable state converges.
        if exact_zero.terminals != self.snapshot.terminals {
            return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
        }
        self.commit_transition_clearing_committed_evidence(owner, exact_zero)?;
        self.revoke_owned_handle()?;
        Ok(historical.clone())
    }

    fn terminalize_empty_exact_zero(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        request: &DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        mut exact_zero: DistributedAgentStackSnapshotTransition,
        raw_code: u16,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let installed_binding_set_digest = distributed_agent_stack_empty_binding_set_digest_v1()?;
        let raw_outcome_digest = raw_outcome_digest(raw_code, request)?;
        let reading = self.clock.reading()?;
        let completion_snapshot_sequence = self
            .snapshot
            .sequence()
            .checked_add(1)
            .ok_or(DistributedAgentStackRuntimeError::SequenceOverflow)?;
        let facts = DistributedAgentStackTerminalFactsV1::try_empty_exact_zero(
            request,
            DistributedAgentStackTerminalEvidenceFieldsV1 {
                runtime_host_epoch: self.runtime_host_epoch,
                completion_snapshot_sequence,
                selection_clock_generation: reading.generation(),
                selection_observed_at_nanos: reading.now().value(),
                fabric_generation: None,
                agent_generation: None,
                local_bindings: DistributedAgentStackLocalBindingEvidenceFieldsV1 {
                    physical_binding_census: 0,
                    census_complete: true,
                    fabric_ready: false,
                    agent_ready: false,
                    dependency_satisfied: false,
                    exact_zero: true,
                    quarantined: false,
                    installed_binding_set_digest,
                    raw_outcome_digest,
                },
            },
        )?;
        let receipt = self.sign_terminal(request, response_channel, facts)?;
        exact_zero.phase = DistributedAgentStackDurablePhase::ExactZero;
        exact_zero.active = None;
        exact_zero.pending = None;
        exact_zero.physical_binding_census = 0;
        exact_zero.census_complete = true;
        exact_zero.fabric_ready = false;
        exact_zero.agent_ready = false;
        exact_zero.dependency_satisfied = false;
        exact_zero.exact_zero = true;
        exact_zero.quarantined = false;
        exact_zero.installed_binding_set_digest = Some(installed_binding_set_digest);
        exact_zero.raw_outcome_digest = Some(raw_outcome_digest);
        exact_zero.quarantine_reason = None;
        insert_terminal(&mut exact_zero.terminals, request, receipt.clone())?;
        self.commit_transition(owner, exact_zero)?;
        self.revoke_owned_handle()?;
        Ok(receipt)
    }

    fn commit_cleanup_quarantine(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        request: &DistributedAgentStackApplyRequestV1,
        raw_code: u16,
    ) -> Result<(), DistributedAgentStackRuntimeError> {
        let raw_outcome_digest = raw_outcome_digest(raw_code, request)?;
        let mut quarantined = self.snapshot.transition();
        quarantined.phase = DistributedAgentStackDurablePhase::Quarantined;
        quarantined.census_complete = false;
        quarantined.fabric_ready = false;
        quarantined.agent_ready = false;
        quarantined.dependency_satisfied = false;
        quarantined.exact_zero = false;
        quarantined.quarantined = true;
        quarantined.installed_binding_set_digest = Some(
            quarantined
                .installed_binding_set_digest
                .unwrap_or(distributed_agent_stack_empty_binding_set_digest_v1()?),
        );
        quarantined.raw_outcome_digest = Some(raw_outcome_digest);
        quarantined.quarantine_reason = Some(quarantine_reason_digest(raw_code, request)?);
        if quarantined.terminals != self.snapshot.terminals {
            return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
        }
        self.commit_transition_clearing_committed_evidence(owner, quarantined)
    }

    fn terminalize_quarantined(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        request: &DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        proofs: Vec<DistributedFabricObservedTransportProofV1>,
        raw_code: u16,
        generations: TerminalGenerations,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let installed_binding_set_digest = distributed_agent_stack_empty_binding_set_digest_v1()?;
        let raw_outcome_digest = raw_outcome_digest(raw_code, request)?;
        let quarantine_reason = quarantine_reason_digest(raw_code, request)?;
        let observations = DistributedAgentStackTerminalObservationsV1::try_new(request, proofs)?;
        let receipt = self.build_terminal(
            request,
            response_channel,
            TerminalSelection {
                outcome: DistributedAgentStackTerminalOutcomeV1::IndeterminateUncertain,
                generations,
                local_bindings: DistributedAgentStackLocalBindingEvidenceFieldsV1 {
                    physical_binding_census: 0,
                    census_complete: false,
                    fabric_ready: false,
                    agent_ready: false,
                    dependency_satisfied: false,
                    exact_zero: false,
                    quarantined: true,
                    installed_binding_set_digest,
                    raw_outcome_digest,
                },
            },
            observations,
        )?;
        let mut quarantined = self.snapshot.transition();
        quarantined.phase = DistributedAgentStackDurablePhase::Quarantined;
        quarantined.active = None;
        quarantined.physical_binding_census = 0;
        quarantined.census_complete = false;
        quarantined.fabric_ready = false;
        quarantined.agent_ready = false;
        quarantined.dependency_satisfied = false;
        quarantined.exact_zero = false;
        quarantined.quarantined = true;
        quarantined.installed_binding_set_digest = Some(installed_binding_set_digest);
        quarantined.raw_outcome_digest = Some(raw_outcome_digest);
        quarantined.quarantine_reason = Some(quarantine_reason);
        insert_terminal(&mut quarantined.terminals, request, receipt.clone())?;
        self.commit_transition_clearing_committed_evidence(owner, quarantined)?;
        self.revoke_owned_handle()?;
        Ok(receipt)
    }

    fn build_terminal(
        &self,
        request: &DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        selection: TerminalSelection,
        observations: DistributedAgentStackTerminalObservationsV1,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let reading = self.clock.reading()?;
        let completion_snapshot_sequence = self
            .snapshot
            .sequence()
            .checked_add(1)
            .ok_or(DistributedAgentStackRuntimeError::SequenceOverflow)?;
        let facts = DistributedAgentStackTerminalFactsV1::try_new(
            request,
            selection.outcome,
            DistributedAgentStackTerminalEvidenceFieldsV1 {
                runtime_host_epoch: self.runtime_host_epoch,
                completion_snapshot_sequence,
                selection_clock_generation: reading.generation(),
                selection_observed_at_nanos: reading.now().value(),
                fabric_generation: selection.generations.fabric,
                agent_generation: selection.generations.agent,
                local_bindings: selection.local_bindings,
            },
            observations,
        )?;
        self.sign_terminal(request, response_channel, facts)
    }

    fn sign_terminal(
        &self,
        request: &DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        facts: DistributedAgentStackTerminalFactsV1,
    ) -> Result<DistributedAgentStackTerminalReceiptV1, DistributedAgentStackRuntimeError> {
        let algorithm = ApplyAuthAlgorithm::try_new(1)
            .map_err(|_| DistributedAgentStackRuntimeError::SignerConfiguration)?;
        let auth_claim = DistributedAgentStackTerminalAuthClaimV1::try_new(
            response_channel,
            self.response_key_ref,
            algorithm,
            1,
        )?;
        let draft = DistributedAgentStackTerminalReceiptDraftV1::try_new(
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

    async fn cleanup_live(&mut self) -> bool {
        let _ = self.revoke_owned_handle();
        let agent_exact = if let Some(assembly) = self.assembly.as_mut() {
            assembly.shutdown().await.is_ok()
        } else {
            true
        };
        if agent_exact {
            self.assembly = None;
        } else {
            // An uncertain Agent-port retirement retains authority over the
            // shared session. Stopping Fabric here could strand or obscure
            // those bindings, so cleanup remains strictly Agent-first.
            return false;
        }
        let fabric_exact = if let Some(fabric) = self.fabric.as_mut() {
            fabric.stop(fabric.generation()).await.is_ok()
        } else {
            true
        };
        if fabric_exact {
            self.fabric = None;
        }
        agent_exact && fabric_exact
    }

    fn revoke_owned_handle(&mut self) -> Result<(), DistributedAgentStackRuntimeError> {
        if self.handle.take().is_some() {
            self.handle_broker.revoke()?;
        }
        self.handle_publication_pending = false;
        Ok(())
    }

    fn lookup_terminal(
        &self,
        request: &DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<Option<DistributedAgentStackTerminalReceiptV1>, DistributedAgentStackRuntimeError>
    {
        let key = (
            *request.provenance().source_scope().as_bytes(),
            *request.operation_id().as_bytes(),
        );
        match self
            .snapshot
            .terminals
            .binary_search_by_key(&key, |record| {
                (
                    *record.source_scope.as_bytes(),
                    *record.operation_id.as_bytes(),
                )
            }) {
            Ok(index) => {
                let record = &self.snapshot.terminals[index];
                if record.request_digest != request.envelope_request_digest()
                    || record
                        .receipt
                        .validate_against_request(request, response_channel)
                        .is_err()
                {
                    return Err(DistributedAgentStackRuntimeError::OperationConflict);
                }
                Ok(Some(record.receipt.clone()))
            }
            Err(_) => Ok(None),
        }
    }

    fn validate_historical_active_terminal(
        &self,
        request: &DistributedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        expected: &DistributedAgentStackTerminalReceiptV1,
    ) -> Result<(), DistributedAgentStackRuntimeError> {
        let stored = self
            .lookup_terminal(request, response_channel)?
            .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?;
        if stored.facts().outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady
            || stored.canonical_wire() != expected.canonical_wire()
        {
            return Err(DistributedAgentStackRuntimeError::InvalidDurableState);
        }
        Ok(())
    }

    fn admit_transition(
        &self,
        request: &DistributedAgentStackApplyRequestV1,
        verified: VerifiedDistributedAgentStackApplyIngressV1,
    ) -> Result<DistributedAgentStackSnapshotTransition, DistributedAgentStackRuntimeError> {
        let proof_digest = verified.authenticated().proof_envelope_digest();
        let claim = request
            .control_commitment()
            .control()
            .writer_context()
            .proof()
            .claim();
        let writer_fence = match self.snapshot.writer_fence {
            None => writer_fence(request, proof_digest),
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
                writer_fence(request, proof_digest)
            }
            Some(_) => return Err(DistributedAgentStackRuntimeError::StaleWriter),
        };
        let provenance = request.provenance();
        let revision_high_water = match self.snapshot.revision_high_water {
            None => revision_high_water(request),
            Some(current)
                if current.source_scope == provenance.source_scope()
                    && (provenance.source_revision().value() > current.revision
                        || provenance.source_revision().value() == current.revision
                            && provenance.source_plan_digest() == current.source_plan_digest) =>
            {
                revision_high_water(request)
            }
            Some(_) => return Err(DistributedAgentStackRuntimeError::StaleRevision),
        };
        let mut transition = self.snapshot.transition();
        transition.writer_fence = Some(writer_fence);
        transition.revision_high_water = Some(revision_high_water);
        insert_replay(
            &mut transition.tenure_nonces,
            DistributedAgentStackReplayRecord {
                identity: verified.authenticated().tenure_nonce_identity(),
                value_digest: proof_digest,
            },
        )?;
        insert_replay(
            &mut transition.request_nonces,
            DistributedAgentStackReplayRecord {
                identity: verified.authenticated().request_nonce_identity(),
                value_digest: request.envelope_request_digest(),
            },
        )?;
        insert_replay(
            &mut transition.temporal_lineages,
            DistributedAgentStackReplayRecord {
                identity: verified.authenticated().temporal_lineage_identity(),
                value_digest: request.envelope_request_digest(),
            },
        )?;
        Ok(transition)
    }

    fn commit_transition(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        transition: DistributedAgentStackSnapshotTransition,
    ) -> Result<(), DistributedAgentStackRuntimeError> {
        let next = self.snapshot.try_successor_at_epoch(
            self.runtime_host_epoch,
            transition,
            &self.projection,
        )?;
        owner.commit_distributed_agent_stack(next.canonical_wire())?;
        self.snapshot = next;
        Ok(())
    }

    fn commit_transition_clearing_committed_evidence(
        &mut self,
        owner: &mut ManagedFabricRuntimeCore,
        transition: DistributedAgentStackSnapshotTransition,
    ) -> Result<(), DistributedAgentStackRuntimeError> {
        if matches!(
            self.snapshot.evidence_state().handoff(),
            DistributedAgentStackEvidenceHandoffV2::Committed(_)
        ) {
            let cleared = self.snapshot.evidence_state().try_clear_committed()?;
            self.commit_v2_transition(owner, transition, cleared)
        } else {
            self.commit_transition(owner, transition)
        }
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), DistributedAgentStackRuntimeError> {
        self.recovery_completed = false;
        self.cancellation.cancel();
        if self.cleanup_live().await {
            Ok(())
        } else {
            Err(DistributedAgentStackRuntimeError::ShutdownUncertain)
        }
    }
}

fn validate_evidence_configuration(
    snapshot: &DistributedAgentStackSnapshot,
    config: Option<&DistributedAgentStackEvidenceStoreConfigV1>,
) -> Result<(), DistributedAgentStackRuntimeError> {
    let state = snapshot.evidence_state();
    match config {
        None if evidence_state_is_empty(state) => Ok(()),
        None => Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch),
        Some(config) => match state.binding() {
            Some(binding) if binding == config.binding() => Ok(()),
            Some(_) => Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch),
            None if evidence_state_is_empty(state) => Ok(()),
            None => Err(DistributedAgentStackRuntimeError::InvalidDurableState),
        },
    }
}

fn validate_owner_dependency_pair(
    config: &DistributedAgentStackOwnerConfig,
) -> Result<(), DistributedAgentStackRuntimeError> {
    if config.fabric_credential_resolver.is_some() != config.evidence_store_config.is_some() {
        return Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch);
    }
    if let Some(evidence) = &config.evidence_store_config
        && !evidence_paths_are_disjoint(&config.state_directory, evidence.root())
    {
        return Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch);
    }
    Ok(())
}

fn evidence_paths_are_disjoint(state_directory: &Path, evidence_root: &Path) -> bool {
    state_directory != evidence_root
        && !state_directory.starts_with(evidence_root)
        && !evidence_root.starts_with(state_directory)
}

fn evidence_state_is_empty(state: &DistributedAgentStackEvidenceStateV2) -> bool {
    state.binding().is_none()
        && state.owner_head().is_none()
        && matches!(
            state.handoff(),
            DistributedAgentStackEvidenceHandoffV2::None
        )
}

fn open_evidence_store(
    config: Option<&DistributedAgentStackEvidenceStoreConfigV1>,
) -> Result<Option<LocalEvidenceStoreV1>, DistributedAgentStackRuntimeError> {
    config
        .map(|config| {
            LocalEvidenceStoreV1::open(
                config.root(),
                config.store_epoch(),
                config.retention_policy(),
            )
        })
        .transpose()
        .map_err(Into::into)
}

fn validate_opened_evidence_store(
    state: &DistributedAgentStackEvidenceStateV2,
    config: &DistributedAgentStackEvidenceStoreConfigV1,
    store: &LocalEvidenceStoreV1,
) -> Result<(), DistributedAgentStackRuntimeError> {
    if store.store_epoch() != config.store_epoch()
        || state
            .binding()
            .is_some_and(|binding| binding != config.binding())
    {
        return Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch);
    }
    let actual_head = evidence_store_owner_head(store, config.owner_ref())?;
    match state.handoff() {
        DistributedAgentStackEvidenceHandoffV2::None => {
            if actual_head != state.owner_head() {
                return Err(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch);
            }
            if let Some(head) = actual_head {
                validate_opened_evidence_record(
                    store,
                    config,
                    head.record_id(),
                    head.producer_sequence(),
                    head.record_digest(),
                )?;
            }
            // Clearing the phase-11 handoff preserves only the exact durable
            // owner head. It is a store-integrity checkpoint, never authority
            // to recreate physical effects: ActiveReady reopen goes through a
            // fresh RecoveryIntent, Fabric session, outer batch, and Evidence
            // commit before `start_agent_after_verified_evidence` is reachable.
            Ok(())
        }
        DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch) => {
            validate_evidence_commit_intent_prefix(store, config, batch, actual_head)
        }
        DistributedAgentStackEvidenceHandoffV2::Committed(committed) => {
            let batch = committed.batch();
            let expected_head = evidence_batch_tail_head(batch)?;
            if actual_head != Some(expected_head) {
                return Err(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch);
            }
            if let Some(base_head) = batch.base_head() {
                validate_opened_evidence_record(
                    store,
                    config,
                    base_head.record_id(),
                    base_head.producer_sequence(),
                    base_head.record_digest(),
                )?;
            }
            for record in batch.records() {
                validate_exact_opened_batch_record(store, config, record)?;
            }
            Ok(())
        }
    }
}

fn evidence_store_owner_head(
    store: &LocalEvidenceStoreV1,
    owner_ref: EvidenceOwnerRefV1,
) -> Result<Option<DistributedAgentStackEvidenceOwnerHeadV2>, DistributedAgentStackRuntimeError> {
    let mut cursor = None;
    let mut owner_head = None;
    loop {
        let page = store.list(cursor, MAX_EVIDENCE_QUERY_RECORDS)?;
        for stored in page.records() {
            let record = stored.record();
            if record.owner_ref() == owner_ref {
                owner_head = Some(DistributedAgentStackEvidenceOwnerHeadV2::try_new(
                    record.producer_sequence(),
                    record.record_id(),
                    record.record_digest(),
                )?);
            }
        }
        match page.next_cursor() {
            Some(next) => cursor = Some(next),
            None => return Ok(owner_head),
        }
    }
}

fn validate_evidence_commit_intent_prefix(
    store: &LocalEvidenceStoreV1,
    config: &DistributedAgentStackEvidenceStoreConfigV1,
    batch: &DistributedAgentStackEvidenceBatchV2,
    actual_head: Option<DistributedAgentStackEvidenceOwnerHeadV2>,
) -> Result<(), DistributedAgentStackRuntimeError> {
    if let Some(base_head) = batch.base_head() {
        validate_opened_evidence_record(
            store,
            config,
            base_head.record_id(),
            base_head.producer_sequence(),
            base_head.record_digest(),
        )?;
    }
    if actual_head == batch.base_head() {
        return Ok(());
    }
    for (index, record) in batch.records().iter().enumerate() {
        let candidate = DistributedAgentStackEvidenceOwnerHeadV2::try_new(
            record.producer_sequence(),
            record.record_id(),
            record.record_digest(),
        )?;
        if actual_head == Some(candidate) {
            for prefix_record in &batch.records()[..=index] {
                validate_exact_opened_batch_record(store, config, prefix_record)?;
            }
            return Ok(());
        }
    }
    Err(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch)
}

fn evidence_batch_tail_head(
    batch: &DistributedAgentStackEvidenceBatchV2,
) -> Result<DistributedAgentStackEvidenceOwnerHeadV2, DistributedAgentStackRuntimeError> {
    let record = batch
        .records()
        .last()
        .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?;
    DistributedAgentStackEvidenceOwnerHeadV2::try_new(
        record.producer_sequence(),
        record.record_id(),
        record.record_digest(),
    )
    .map_err(Into::into)
}

fn validate_exact_opened_batch_record(
    store: &LocalEvidenceStoreV1,
    config: &DistributedAgentStackEvidenceStoreConfigV1,
    record: &EvidenceRecordV1,
) -> Result<(), DistributedAgentStackRuntimeError> {
    validate_opened_evidence_record(
        store,
        config,
        record.record_id(),
        record.producer_sequence(),
        record.record_digest(),
    )?;
    let stored = store
        .read(record.record_id())?
        .ok_or(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch)?;
    if stored.record() != record || stored.record().canonical_wire() != record.canonical_wire() {
        return Err(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch);
    }
    Ok(())
}

fn validate_opened_evidence_record(
    store: &LocalEvidenceStoreV1,
    config: &DistributedAgentStackEvidenceStoreConfigV1,
    record_id: EvidenceRecordIdV1,
    producer_sequence: u64,
    record_digest: Digest32,
) -> Result<(), DistributedAgentStackRuntimeError> {
    let stored = store
        .read(record_id)?
        .ok_or(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch)?;
    let evidence_ref = stored.evidence_ref();
    let record = stored.record();
    if evidence_ref.store_epoch() != config.store_epoch()
        || evidence_ref.record_id() != record_id
        || evidence_ref.record_digest() != record_digest
        || record.record_id() != record_id
        || record.owner_ref() != config.owner_ref()
        || record.producer_sequence() != producer_sequence
        || record.record_digest() != record_digest
    {
        return Err(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch);
    }
    Ok(())
}

fn generated_evidence_record_id() -> Result<EvidenceRecordIdV1, DistributedAgentStackRuntimeError> {
    try_evidence_record_id_with(|destination| getrandom::fill(destination).map_err(|_| ()))
}

fn try_evidence_record_id_with(
    fill: impl FnOnce(&mut [u8; 16]) -> Result<(), ()>,
) -> Result<EvidenceRecordIdV1, DistributedAgentStackRuntimeError> {
    let mut bytes = [0_u8; 16];
    fill(&mut bytes).map_err(|()| DistributedAgentStackRuntimeError::EvidenceEntropyUnavailable)?;
    EvidenceRecordIdV1::try_from_bytes(bytes)
        .map_err(|_| DistributedAgentStackRuntimeError::EvidenceEntropyUnavailable)
}

fn build_evidence_batch(
    request: &DistributedAgentStackApplyRequestV1,
    snapshot: ValidatedExperimentalSnapshot,
    owner_ref: EvidenceOwnerRefV1,
    base_head: Option<DistributedAgentStackEvidenceOwnerHeadV2>,
) -> Result<DistributedAgentStackEvidenceBatchV2, DistributedAgentStackRuntimeError> {
    build_evidence_batch_with(request, snapshot, owner_ref, base_head, |_| {
        generated_evidence_record_id()
    })
}

fn build_evidence_batch_with<NextRecordId>(
    request: &DistributedAgentStackApplyRequestV1,
    snapshot: ValidatedExperimentalSnapshot,
    owner_ref: EvidenceOwnerRefV1,
    base_head: Option<DistributedAgentStackEvidenceOwnerHeadV2>,
    mut next_record_id: NextRecordId,
) -> Result<DistributedAgentStackEvidenceBatchV2, DistributedAgentStackRuntimeError>
where
    NextRecordId: FnMut(usize) -> Result<EvidenceRecordIdV1, DistributedAgentStackRuntimeError>,
{
    let topology = request
        .target_execution()
        .topology()
        .ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?;
    if topology.peers().len() != snapshot.peer_owner_facts.len() {
        return Err(DistributedAgentStackRuntimeError::ObservationCorrelationMismatch);
    }
    let mut producer_sequence = match base_head {
        Some(head) => head
            .producer_sequence()
            .checked_add(1)
            .ok_or(DistributedAgentStackRuntimeError::SequenceOverflow)?,
        None => 1,
    };
    let mut previous = base_head.map(DistributedAgentStackEvidenceOwnerHeadV2::record_id);
    let mut record_ids = Vec::with_capacity(topology.peers().len());
    let mut records = Vec::with_capacity(topology.peers().len());
    for (index, (peer, observed)) in topology
        .peers()
        .iter()
        .zip(snapshot.peer_owner_facts.iter())
        .enumerate()
    {
        if observed
            .identity_binding_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || observed.observation_sequence == 0
        {
            return Err(DistributedAgentStackRuntimeError::ObservationCorrelationMismatch);
        }
        let record_id = next_record_id(index)?;
        if record_ids.contains(&record_id) {
            return Err(DistributedAgentStackRuntimeError::EvidenceRecordIdConflict);
        }
        let authentication = peer.authentication();
        let proof = DistributedFabricObservedTransportProofV1::try_new(
            request.target(),
            peer,
            DistributedFabricObservedTransportProofFieldsV1 {
                local_runtime_host: request.target(),
                peer_runtime_host: peer.peer_runtime_host(),
                session_epoch: snapshot.session_epoch,
                authenticated_peer_identity_ref: authentication.expected_peer_identity_ref(),
                selected_local_credential_ref: authentication.local_credential_ref(),
                transport_evidence_ref: DistributedFabricTransportEvidenceRefV1::try_from_bytes(
                    *record_id.as_bytes(),
                )?,
                observation_sequence: observed.observation_sequence,
            },
        )?;
        let record = EvidenceRecordV1::try_new(EvidenceRecordInputV1 {
            record_id,
            owner_ref,
            producer_sequence,
            causality_ref: None,
            previous_evidence_ref: previous,
            kind: EvidenceKindV1::RuntimeFact,
            payload: EvidencePayloadV1::try_public_safe_inline(proof.canonical_wire())?,
        })?;
        previous = Some(record_id);
        record_ids.push(record_id);
        records.push(record);
        if index + 1 < topology.peers().len() {
            producer_sequence = producer_sequence
                .checked_add(1)
                .ok_or(DistributedAgentStackRuntimeError::SequenceOverflow)?;
        }
    }
    DistributedAgentStackEvidenceBatchV2::try_new(
        request.envelope_request_digest(),
        snapshot.fabric_generation,
        snapshot.session_epoch,
        base_head,
        records,
    )
    .map_err(Into::into)
}

fn exact_proofs_from_evidence_batch(
    batch: &DistributedAgentStackEvidenceBatchV2,
) -> Result<Vec<DistributedFabricObservedTransportProofV1>, DistributedAgentStackRuntimeError> {
    batch
        .records()
        .iter()
        .map(|record| {
            let payload = record
                .payload()
                .inline_bytes()
                .ok_or(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch)?;
            let proof = DistributedFabricObservedTransportProofV1::decode(payload)?;
            if proof.canonical_wire() != payload
                || proof.fields().transport_evidence_ref.as_bytes() != record.record_id().as_bytes()
            {
                return Err(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch);
            }
            Ok(proof)
        })
        .collect()
}

fn append_and_verify_evidence_batch(
    store: &mut LocalEvidenceStoreV1,
    batch: &DistributedAgentStackEvidenceBatchV2,
) -> Result<VerifiedEvidenceStoreWrite, DistributedAgentStackRuntimeError> {
    let mut receipts = Vec::with_capacity(batch.records().len());
    let mut readback = Vec::with_capacity(batch.records().len());
    for record in batch.records() {
        let receipt = store.append(record.clone())?.commit_receipt();
        let evidence_ref = receipt.evidence_ref();
        if evidence_ref.store_epoch() != store.store_epoch()
            || evidence_ref.record_id() != record.record_id()
            || evidence_ref.record_digest() != record.record_digest()
        {
            return Err(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch);
        }
        let stored = store
            .read(record.record_id())?
            .ok_or(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch)?;
        if stored.evidence_ref() != evidence_ref
            || stored.record() != record
            || stored.record().canonical_wire() != record.canonical_wire()
        {
            return Err(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch);
        }
        receipts.push(receipt);
        readback.push(stored);
    }
    Ok(VerifiedEvidenceStoreWrite {
        receipts: receipts.into_boxed_slice(),
        readback: readback.into_boxed_slice(),
    })
}

struct VerifiedEvidenceStoreWrite {
    receipts: Box<[EvidenceCommitReceiptV1]>,
    readback: Box<[EvidenceStoredRecordV1]>,
}

fn prepare_generation(
    resolver: Option<&dyn RuntimeFabricCredentialResolverV2>,
    request: &DistributedAgentStackApplyRequestV1,
    generation: ManagedServiceGeneration,
) -> Result<Option<DistributedFabricRuntimeGeneration>, DistributedAgentStackRuntimeError> {
    resolver
        .map(|resolver| {
            DistributedFabricRuntimeGeneration::try_prepare_experimental_cn_v2(
                request.target_execution(),
                generation,
                resolver,
            )
        })
        .transpose()
        .map_err(Into::into)
}

fn agent_start_failure_requires_fabric_retention(error: &ManagedAgentAssemblyError) -> bool {
    matches!(
        error,
        ManagedAgentAssemblyError::PortMutationUncertain(_)
            | ManagedAgentAssemblyError::ServerJoinDeadlineExceeded
    )
}

fn validate_experimental_binding_order(
    expected: &[Digest32],
    observed: &[Digest32],
) -> Result<(), DistributedAgentStackRuntimeError> {
    if expected.len() != observed.len()
        || expected
            .iter()
            .zip(observed)
            .any(|(expected, observed)| expected != observed)
    {
        return Err(DistributedAgentStackRuntimeError::ObservationCorrelationMismatch);
    }
    Ok(())
}

fn validate_request(
    owner: &ManagedFabricRuntimeCore,
    projection: &DistributedAgentStackProjectionV1,
    request: &DistributedAgentStackApplyRequestV1,
    response_channel: ReferenceChannelBindingV1,
) -> Result<(), DistributedAgentStackRuntimeError> {
    request
        .validate_expected_store(owner.store_instance_id())
        .map_err(|_| DistributedAgentStackRuntimeError::RequestRejected)?;
    request
        .validate_projection(projection)
        .map_err(|_| DistributedAgentStackRuntimeError::RequestRejected)?;
    if request.target() != projection.target() || response_channel.target() != request.target() {
        return Err(DistributedAgentStackRuntimeError::RequestRejected);
    }
    Ok(())
}

fn initial_transition(
    request: &DistributedAgentStackApplyRequestV1,
    verified: VerifiedDistributedAgentStackApplyIngressV1,
    response_channel: ReferenceChannelBindingV1,
    fabric_generation: ManagedServiceGeneration,
    agent_generation: ManagedServiceGeneration,
) -> Result<DistributedAgentStackSnapshotTransition, DistributedAgentStackRuntimeError> {
    let proof_digest = verified.authenticated().proof_envelope_digest();
    let mut tenure_nonces = Vec::new();
    let mut request_nonces = Vec::new();
    let mut temporal_lineages = Vec::new();
    insert_replay(
        &mut tenure_nonces,
        DistributedAgentStackReplayRecord {
            identity: verified.authenticated().tenure_nonce_identity(),
            value_digest: proof_digest,
        },
    )?;
    insert_replay(
        &mut request_nonces,
        DistributedAgentStackReplayRecord {
            identity: verified.authenticated().request_nonce_identity(),
            value_digest: request.envelope_request_digest(),
        },
    )?;
    insert_replay(
        &mut temporal_lineages,
        DistributedAgentStackReplayRecord {
            identity: verified.authenticated().temporal_lineage_identity(),
            value_digest: request.envelope_request_digest(),
        },
    )?;
    Ok(DistributedAgentStackSnapshotTransition {
        fabric_generation_high_water: fabric_generation.value(),
        agent_generation_high_water: agent_generation.value(),
        phase: DistributedAgentStackDurablePhase::PreparedNoEffects,
        writer_fence: Some(writer_fence(request, proof_digest)),
        revision_high_water: Some(revision_high_water(request)),
        active: None,
        pending: Some(DistributedAgentStackDurablePending {
            kind: DistributedAgentStackPendingKind::ActivateDistributedStack,
            fabric_generation: Some(fabric_generation),
            agent_generation: Some(agent_generation),
            admitted_clock_generation: verified.clock_generation(),
            admitted_at_nanos: verified.admitted_at_nanos(),
            deadline_nanos: verified.deadline_nanos(),
            response_channel,
            request: request.clone(),
        }),
        tenure_nonces,
        request_nonces,
        temporal_lineages,
        terminals: Vec::new(),
        physical_binding_census: 0,
        census_complete: true,
        fabric_ready: false,
        agent_ready: false,
        dependency_satisfied: false,
        exact_zero: false,
        quarantined: false,
        installed_binding_set_digest: None,
        raw_outcome_digest: None,
        quarantine_reason: None,
    })
}

fn writer_fence(
    request: &DistributedAgentStackApplyRequestV1,
    proof_envelope_digest: Digest32,
) -> DistributedAgentStackWriterFence {
    let writer = request.control_commitment().control().writer_context();
    let claim = writer.proof().claim();
    DistributedAgentStackWriterFence {
        source_scope: claim.source_scope(),
        writer: claim.writer(),
        principal: request.authentication().claim().principal(),
        epoch: claim.epoch().value(),
        proof_envelope_digest,
    }
}

fn revision_high_water(
    request: &DistributedAgentStackApplyRequestV1,
) -> DistributedAgentStackRevisionHighWater {
    let provenance = request.provenance();
    DistributedAgentStackRevisionHighWater {
        source_scope: provenance.source_scope(),
        revision: provenance.source_revision().value(),
        source_plan_digest: provenance.source_plan_digest(),
    }
}

fn observe_deadline(
    clock: RuntimeClock,
    verified: VerifiedDistributedAgentStackApplyIngressV1,
) -> Result<(), DistributedAgentStackRuntimeError> {
    let reading = clock.reading()?;
    if reading.generation() != verified.clock_generation()
        || reading.now().value() >= verified.deadline_nanos()
    {
        return Err(DistributedAgentStackRuntimeError::DeadlineExpired);
    }
    Ok(())
}

fn recovery_deadline(
    request: &DistributedAgentStackApplyRequestV1,
    reading: ClockReading,
) -> Result<u64, DistributedAgentStackRuntimeError> {
    reading
        .now()
        .value()
        .checked_add(request.temporal().original_budget().value())
        .ok_or(DistributedAgentStackRuntimeError::DeadlineOverflow)
}

fn map_runtime_deadline_from_prior_reactor_sample(
    reactor_sample: Instant,
    reading: ClockReading,
    expected_generation: ClockGeneration,
    deadline_nanos: u64,
) -> Result<Instant, DistributedAgentStackRuntimeError> {
    if reading.generation() != expected_generation || reading.now().value() >= deadline_nanos {
        return Err(DistributedAgentStackRuntimeError::DeadlineExpired);
    }
    reactor_sample
        .checked_add(Duration::from_nanos(deadline_nanos - reading.now().value()))
        .ok_or(DistributedAgentStackRuntimeError::DeadlineOverflow)
}

fn projection_digest(
    projection: &DistributedAgentStackProjectionV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(PROJECTION_DIGEST_DOMAIN)?;
    builder.field_bytes(projection.canonical_wire())?;
    Ok(builder.finish())
}

fn raw_outcome_digest(
    code: u16,
    request: &DistributedAgentStackApplyRequestV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(RAW_OUTCOME_DIGEST_DOMAIN)?;
    builder.field_u16(code)?;
    builder.field_digest(&request.envelope_request_digest())?;
    Ok(builder.finish())
}

fn quarantine_reason_digest(
    code: u16,
    request: &DistributedAgentStackApplyRequestV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(QUARANTINE_DIGEST_DOMAIN)?;
    builder.field_u16(code)?;
    builder.field_digest(&request.envelope_request_digest())?;
    Ok(builder.finish())
}

fn next_generation(
    high_water: u64,
) -> Result<ManagedServiceGeneration, DistributedAgentStackRuntimeError> {
    high_water
        .checked_add(1)
        .ok_or(DistributedAgentStackRuntimeError::GenerationExhausted)
        .and_then(|value| {
            ManagedServiceGeneration::try_new(value)
                .map_err(|_| DistributedAgentStackRuntimeError::GenerationExhausted)
        })
}

fn insert_replay(
    records: &mut Vec<DistributedAgentStackReplayRecord>,
    incoming: DistributedAgentStackReplayRecord,
) -> Result<(), DistributedAgentStackRuntimeError> {
    match records.binary_search_by_key(&incoming.identity, |record| record.identity) {
        Ok(index) if records[index].value_digest == incoming.value_digest => Ok(()),
        Ok(_) => Err(DistributedAgentStackRuntimeError::ReplayConflict),
        Err(index) if records.len() < MAX_REPLAY_RECORDS => {
            records.insert(index, incoming);
            Ok(())
        }
        Err(_) => Err(DistributedAgentStackRuntimeError::ReplayCapacityReached),
    }
}

fn insert_terminal(
    records: &mut Vec<DistributedAgentStackTerminalRecord>,
    request: &DistributedAgentStackApplyRequestV1,
    receipt: DistributedAgentStackTerminalReceiptV1,
) -> Result<(), DistributedAgentStackRuntimeError> {
    let key = (
        *request.provenance().source_scope().as_bytes(),
        *request.operation_id().as_bytes(),
    );
    match records.binary_search_by_key(&key, |record| {
        (
            *record.source_scope.as_bytes(),
            *record.operation_id.as_bytes(),
        )
    }) {
        Ok(index) if records[index].request_digest == request.envelope_request_digest() => Ok(()),
        Ok(_) => Err(DistributedAgentStackRuntimeError::OperationConflict),
        Err(index) if records.len() < MAX_REPLAY_RECORDS => {
            records.insert(
                index,
                DistributedAgentStackTerminalRecord {
                    source_scope: request.provenance().source_scope(),
                    operation_id: request.operation_id(),
                    request_digest: request.envelope_request_digest(),
                    receipt,
                },
            );
            Ok(())
        }
        Err(_) => Err(DistributedAgentStackRuntimeError::ReplayCapacityReached),
    }
}

#[derive(Debug)]
pub(crate) enum DistributedAgentStackRuntimeError {
    RequestRejected,
    ProjectionMismatch,
    PredecessorMismatch,
    ActiveReplacementRequiresEmpty,
    RuntimeEpochRegressed,
    RecoveryNotCompleted,
    RecoveryWhileLive,
    RecoveryQuarantined,
    DeadlineExpired,
    DeadlineOverflow,
    ExpectedActiveMismatch,
    StaleWriter,
    StaleRevision,
    ReplayConflict,
    ReplayCapacityReached,
    OperationConflict,
    GenerationExhausted,
    SequenceOverflow,
    SignerConfiguration,
    InvalidDurableState,
    InvalidLifecycleState,
    ObservationCorrelationMismatch,
    ShutdownUncertain,
    InvalidEvidenceStoreConfig,
    EvidenceConfigurationMismatch,
    EvidenceStoreUnavailable,
    EvidenceEntropyUnavailable,
    EvidenceRecordIdConflict,
    EvidenceReadbackMismatch,
    HandlePublicationPending,
    Digest(DigestBuildError),
    EvidenceContract(EvidenceContractError),
    EvidenceStore(EvidenceStoreError),
    Contract(DistributedAgentStackPlanError),
    State(DistributedAgentStackStateError),
    Fabric(ManagedFabricRuntimeError),
    DistributedFabric(DistributedFabricRuntimeError),
    Agent(ManagedAgentAssemblyError),
    Stack(ManagedAgentStackRuntimeError),
    Clock(RuntimeClockError),
    ExperimentalSnapshot(ManagedFabricExperimentalSnapshotError),
}

impl DistributedAgentStackRuntimeError {
    pub(crate) const fn is_request_rejection(&self) -> bool {
        matches!(
            self,
            Self::RequestRejected
                | Self::ProjectionMismatch
                | Self::PredecessorMismatch
                | Self::ActiveReplacementRequiresEmpty
                | Self::DeadlineExpired
                | Self::ExpectedActiveMismatch
                | Self::StaleWriter
                | Self::StaleRevision
                | Self::ReplayConflict
                | Self::OperationConflict
        )
    }
}

impl fmt::Display for DistributedAgentStackRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("distributed Agent-stack Runtime failed: ")?;
        match self {
            Self::Digest(error) => write!(formatter, "{error}"),
            Self::EvidenceContract(error) => write!(formatter, "{error}"),
            Self::EvidenceStore(error) => write!(formatter, "{error}"),
            Self::Contract(error) => write!(formatter, "{error:?}"),
            Self::State(error) => write!(formatter, "{error}"),
            Self::Fabric(error) => write!(formatter, "{error}"),
            Self::DistributedFabric(error) => write!(formatter, "{error}"),
            Self::Agent(error) => write!(formatter, "{error}"),
            Self::Stack(error) => write!(formatter, "{error}"),
            Self::Clock(error) => write!(formatter, "{error}"),
            Self::ExperimentalSnapshot(error) => write!(formatter, "{error}"),
            other => write!(formatter, "{other:?}"),
        }
    }
}

impl std::error::Error for DistributedAgentStackRuntimeError {}

macro_rules! impl_error_from {
    ($source:ty, $variant:ident) => {
        impl From<$source> for DistributedAgentStackRuntimeError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

impl_error_from!(DigestBuildError, Digest);
impl_error_from!(EvidenceContractError, EvidenceContract);
impl_error_from!(EvidenceStoreError, EvidenceStore);
impl_error_from!(DistributedAgentStackPlanError, Contract);
impl_error_from!(DistributedAgentStackStateError, State);
impl_error_from!(ManagedFabricRuntimeError, Fabric);
impl_error_from!(DistributedFabricRuntimeError, DistributedFabric);
impl_error_from!(ManagedAgentAssemblyError, Agent);
impl_error_from!(ManagedAgentStackRuntimeError, Stack);
impl_error_from!(RuntimeClockError, Clock);
impl_error_from!(ManagedFabricExperimentalSnapshotError, ExperimentalSnapshot);

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_agent_contracts::control::AgentConversationOpenOutcomeV1;
    use paraegox_agent_contracts::{
        AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
        AgentConversationSessionId, AgentConversationTerminalResultV1, AgentConversationTurnId,
    };
    use paraegox_agent_service::DeterministicEchoModelProvider;
    use paraegox_evidence::{
        EvidenceKindV1, EvidenceOwnerRefV1, EvidencePayloadV1, EvidenceRecordIdV1,
        EvidenceRecordInputV1, EvidenceRecordV1, EvidenceRetentionPolicyV1, EvidenceStoreEpochV1,
        EvidenceStoreError, LocalEvidenceStoreV1,
    };
    use paraegox_fabric::{FabricServiceConfig, SessionEndpoint};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::PrincipalRef;
    use paraegox_kernel::time::{ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant};
    use paraegox_runtime_contracts::distributed_agent_stack_plan::{
        DistributedAgentStackApplyRequestV1, DistributedAgentStackProjectionV1,
        DistributedAgentStackTerminalAuthClaimV1, DistributedAgentStackTerminalEvidenceFieldsV1,
        DistributedAgentStackTerminalFactsV1, DistributedAgentStackTerminalObservationsV1,
        DistributedAgentStackTerminalOutcomeV1, DistributedAgentStackTerminalReceiptDraftV1,
        DistributedAgentStackTerminalReceiptV1, DistributedFabricObservedTransportProofV1,
        DistributedFabricSessionEpochV1, distributed_agent_stack_installed_binding_set_digest_v1,
    };
    use paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentProviderSelectionV1;
    use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
    use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};
    use tokio::time::Instant;

    use super::{
        ActivationContext, ActivationTerminalMode, DistributedAgentStackEvidenceStoreConfigV1,
        DistributedAgentStackOwnerConfig, DistributedAgentStackRuntimeCore,
        DistributedAgentStackRuntimeError, TerminalGenerations, UncertainCleanupInput,
        ValidatedExperimentalPeerOwnerFacts, ValidatedExperimentalSnapshot,
        append_and_verify_evidence_batch, build_evidence_batch_with, evidence_paths_are_disjoint,
        experimental_snapshot_success_decision, map_runtime_deadline_from_prior_reactor_sample,
        projection_digest, try_evidence_record_id_with, validate_experimental_binding_order,
        validate_opened_evidence_store,
    };
    use crate::distributed_agent_stack_state::{
        DistributedAgentStackDurableActive, DistributedAgentStackDurablePending,
        DistributedAgentStackDurablePhase, DistributedAgentStackEvidenceBindingV2,
        DistributedAgentStackEvidenceHandoffV2, DistributedAgentStackEvidenceOwnerHeadV2,
        DistributedAgentStackEvidenceStateV2, DistributedAgentStackPendingKind,
        DistributedAgentStackSnapshot, DistributedAgentStackSnapshotTransition,
        DistributedAgentStackTerminalRecord,
    };
    use crate::distributed_fabric_runtime::{
        RuntimeFabricCredentialRequirementV1, RuntimeFabricCredentialResolveErrorV2,
        RuntimeFabricCredentialResolverV2, RuntimeResolvedFabricPeerCredentialV2,
    };
    use crate::managed_agent_stack_runtime::RuntimeAgentHandleBroker;
    use crate::managed_fabric_runtime::{
        ManagedFabricOwnerConfig, ManagedFabricRuntimeCore, RuntimeManagedFabricService,
        transition_projection_digest as managed_fabric_projection_digest,
    };
    use crate::managed_service_assembly::{ManagedServiceAssembly, ManagedServiceStartupOutcome};
    use crate::runtime_agent_provider::{
        RuntimeAgentProviderResolveError, RuntimeAgentProviderResolverV1,
        RuntimeResolvedAgentProviderV1, UnavailableRuntimeAgentProviderResolver,
    };
    use crate::runtime_clock::RuntimeClock;
    use crate::runtime_store::{
        ManagedFabricStore,
        tests::{TestDirectory, managed_fabric_store_fixture},
    };
    use crate::task_registry::CancellationSource;

    const DISTRIBUTED_FIXTURE: &str = include_str!(
        "../../paraegox-runtime-contracts/tests/fixtures/distributed_agent_stack_v1.hex"
    );
    const STORE_BYTE: u8 = 0x44;
    const OWNER_TARGET_BYTE: u8 = 0x32;
    const INITIAL_RUNTIME_EPOCH: u64 = 5;
    const FABRIC_GENERATION: u64 = 3;
    const AGENT_GENERATION: u64 = 4;
    const RESPONSE_SIGNING_SEED: [u8; 32] = [0x51; 32];
    const RESPONSE_KEY_REF: ApplyAuthKeyRef = ApplyAuthKeyRef::from_bytes([0x52; 16]);

    struct PersistedActiveFixture {
        directory: TestDirectory,
        projection: DistributedAgentStackProjectionV1,
        request: DistributedAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
        historical: DistributedAgentStackTerminalReceiptV1,
    }

    struct PersistedPendingFixture {
        directory: TestDirectory,
        projection: DistributedAgentStackProjectionV1,
        request: DistributedAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    }

    struct PersistedEvidenceHandoffFixture {
        directory: TestDirectory,
        _evidence_directory: TestDirectory,
        projection: DistributedAgentStackProjectionV1,
        request: DistributedAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
        evidence_config: DistributedAgentStackEvidenceStoreConfigV1,
        batch: crate::distributed_agent_stack_state::DistributedAgentStackEvidenceBatchV2,
    }

    struct FailClosedEvidenceFixtureResolver;

    impl RuntimeFabricCredentialResolverV2 for FailClosedEvidenceFixtureResolver {
        fn resolve(
            &self,
            _requirement: &RuntimeFabricCredentialRequirementV1,
        ) -> Result<RuntimeResolvedFabricPeerCredentialV2, RuntimeFabricCredentialResolveErrorV2>
        {
            Err(RuntimeFabricCredentialResolveErrorV2::ResolutionFailed)
        }
    }

    struct ExactSelectionEchoFixtureResolver;

    impl RuntimeAgentProviderResolverV1 for ExactSelectionEchoFixtureResolver {
        fn resolve(
            &self,
            selection: ManagedAgentProviderSelectionV1,
        ) -> Result<RuntimeResolvedAgentProviderV1, RuntimeAgentProviderResolveError> {
            // The distributed golden intentionally selects the provisioned
            // profile. This fixture supplies no Secret semantics; it only
            // echoes the exact signed selection while exercising the real
            // durable Agent service and two-lane Fabric port with a bounded
            // deterministic model implementation.
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
                _ => panic!("fixture contains a non-hex byte"),
            }
        }

        assert_eq!(value.len() % 2, 0, "fixture hex length must be even");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn fixture_hex(key: &str) -> Vec<u8> {
        let prefix = format!("{key}=");
        let value = DISTRIBUTED_FIXTURE
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("missing distributed fixture key {key}"));
        decode_hex(value)
    }

    fn fixture_projection() -> DistributedAgentStackProjectionV1 {
        DistributedAgentStackProjectionV1::decode(&fixture_hex("projection"))
            .unwrap_or_else(|error| panic!("distributed projection fixture rejected: {error}"))
    }

    fn fixture_request() -> DistributedAgentStackApplyRequestV1 {
        DistributedAgentStackApplyRequestV1::decode(&fixture_hex("request"))
            .unwrap_or_else(|error| panic!("distributed request fixture rejected: {error}"))
    }

    fn fixture_transport_proof() -> DistributedFabricObservedTransportProofV1 {
        DistributedFabricObservedTransportProofV1::decode(&fixture_hex("transport_proof"))
            .unwrap_or_else(|error| panic!("distributed transport fixture rejected: {error}"))
    }

    fn response_channel(
        projection: &DistributedAgentStackProjectionV1,
    ) -> ReferenceChannelBindingV1 {
        ReferenceChannelBindingV1::try_new(
            projection.target(),
            PrincipalRef::from_bytes([0x53; 16]),
            Digest32::from_bytes([0x54; 32]),
            Digest32::from_bytes([0x55; 32]),
        )
        .unwrap_or_else(|error| panic!("distributed response channel rejected: {error}"))
    }

    fn generation(value: u64) -> ManagedServiceGeneration {
        ManagedServiceGeneration::try_new(value)
            .unwrap_or_else(|error| panic!("managed generation rejected: {error}"))
    }

    fn evidence_owner_ref() -> EvidenceOwnerRefV1 {
        EvidenceOwnerRefV1::try_from_bytes([0x82; 16])
            .unwrap_or_else(|error| panic!("Evidence owner rejected: {error}"))
    }

    fn fixture_evidence_batch(
        request: &DistributedAgentStackApplyRequestV1,
        fabric_generation: ManagedServiceGeneration,
    ) -> crate::distributed_agent_stack_state::DistributedAgentStackEvidenceBatchV2 {
        let topology = request
            .target_execution()
            .topology()
            .unwrap_or_else(|| panic!("distributed fixture lost topology"));
        let snapshot = ValidatedExperimentalSnapshot {
            fabric_generation,
            session_epoch: DistributedFabricSessionEpochV1::try_from_bytes([0x81; 16])
                .unwrap_or_else(|error| panic!("session epoch rejected: {error:?}")),
            peer_owner_facts: topology
                .peers()
                .iter()
                .enumerate()
                .map(|(index, _)| ValidatedExperimentalPeerOwnerFacts {
                    identity_binding_digest: Digest32::from_bytes(
                        [u8::try_from(index + 1)
                            .unwrap_or_else(|_| panic!("fixture peer index overflow"));
                            32],
                    ),
                    observation_sequence: u64::try_from(index)
                        .unwrap_or_else(|_| panic!("fixture peer index overflow"))
                        + 41,
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        };
        build_evidence_batch_with(request, snapshot, evidence_owner_ref(), None, |index| {
            let byte = u8::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(0x90))
                .unwrap_or_else(|| panic!("fixture record index overflow"));
            EvidenceRecordIdV1::try_from_bytes([byte; 16])
                .map_err(DistributedAgentStackRuntimeError::from)
        })
        .unwrap_or_else(|error| panic!("Evidence batch construction failed: {error}"))
    }

    fn fixture_clock(request: &DistributedAgentStackApplyRequestV1) -> RuntimeClock {
        RuntimeClock::new(
            request.temporal().target_clock_domain(),
            request.temporal().target_clock_generation(),
            100,
        )
    }

    fn active_terminal(
        request: &DistributedAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> DistributedAgentStackTerminalReceiptV1 {
        let installed_binding_set_digest = distributed_agent_stack_installed_binding_set_digest_v1(
            Digest32::from_bytes([0x61; 32]),
            Digest32::from_bytes([0x62; 32]),
        )
        .unwrap_or_else(|error| panic!("installed binding-set digest failed: {error}"));
        let observations = DistributedAgentStackTerminalObservationsV1::try_new(
            request,
            vec![fixture_transport_proof()],
        )
        .unwrap_or_else(|error| panic!("active transport observations rejected: {error}"));
        let facts = DistributedAgentStackTerminalFactsV1::try_new(
            request,
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            DistributedAgentStackTerminalEvidenceFieldsV1 {
                runtime_host_epoch: INITIAL_RUNTIME_EPOCH,
                completion_snapshot_sequence: 1,
                selection_clock_generation: request.temporal().target_clock_generation(),
                selection_observed_at_nanos: 101,
                fabric_generation: Some(generation(FABRIC_GENERATION)),
                agent_generation: Some(generation(AGENT_GENERATION)),
                local_bindings:
                    paraegox_runtime_contracts::distributed_agent_stack_plan::DistributedAgentStackLocalBindingEvidenceFieldsV1 {
                        physical_binding_census: 2,
                        census_complete: true,
                        fabric_ready: true,
                        agent_ready: true,
                        dependency_satisfied: true,
                        exact_zero: false,
                        quarantined: false,
                        installed_binding_set_digest,
                        raw_outcome_digest: Digest32::from_bytes([0x63; 32]),
                    },
            },
            observations,
        )
        .unwrap_or_else(|error| panic!("active terminal facts rejected: {error}"));
        let auth = DistributedAgentStackTerminalAuthClaimV1::try_new(
            channel,
            RESPONSE_KEY_REF,
            ApplyAuthAlgorithm::try_new(1)
                .unwrap_or_else(|error| panic!("terminal algorithm rejected: {error}")),
            1,
        )
        .unwrap_or_else(|error| panic!("terminal auth claim rejected: {error}"));
        let draft =
            DistributedAgentStackTerminalReceiptDraftV1::try_new(request, facts, channel, auth)
                .unwrap_or_else(|error| panic!("active terminal draft rejected: {error}"));
        let signature = SigningKey::from_bytes(&RESPONSE_SIGNING_SEED)
            .sign(
                draft
                    .signing_transcript()
                    .unwrap_or_else(|error| panic!("terminal transcript failed: {error}"))
                    .as_bytes(),
            )
            .to_bytes();
        draft
            .finalize(&signature)
            .unwrap_or_else(|error| panic!("active terminal finalization rejected: {error}"))
    }

    fn active_transition(
        request: &DistributedAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
        terminal: DistributedAgentStackTerminalReceiptV1,
    ) -> DistributedAgentStackSnapshotTransition {
        let installed_binding_set_digest = terminal
            .facts()
            .evidence()
            .local_bindings
            .installed_binding_set_digest;
        let raw_outcome_digest = terminal
            .facts()
            .evidence()
            .local_bindings
            .raw_outcome_digest;
        DistributedAgentStackSnapshotTransition {
            fabric_generation_high_water: FABRIC_GENERATION,
            agent_generation_high_water: AGENT_GENERATION,
            phase: DistributedAgentStackDurablePhase::ActiveReady,
            writer_fence: None,
            revision_high_water: None,
            active: Some(DistributedAgentStackDurableActive {
                fabric_generation: generation(FABRIC_GENERATION),
                agent_generation: generation(AGENT_GENERATION),
                response_channel: channel,
                request: request.clone(),
            }),
            pending: None,
            tenure_nonces: Vec::new(),
            request_nonces: Vec::new(),
            temporal_lineages: Vec::new(),
            terminals: vec![DistributedAgentStackTerminalRecord {
                source_scope: request.provenance().source_scope(),
                operation_id: request.operation_id(),
                request_digest: request.envelope_request_digest(),
                receipt: terminal,
            }],
            physical_binding_census: 2,
            census_complete: true,
            fabric_ready: true,
            agent_ready: true,
            dependency_satisfied: true,
            exact_zero: false,
            quarantined: false,
            installed_binding_set_digest: Some(installed_binding_set_digest),
            raw_outcome_digest: Some(raw_outcome_digest),
            quarantine_reason: None,
        }
    }

    fn pending_transition(
        request: &DistributedAgentStackApplyRequestV1,
        channel: ReferenceChannelBindingV1,
    ) -> DistributedAgentStackSnapshotTransition {
        DistributedAgentStackSnapshotTransition {
            fabric_generation_high_water: FABRIC_GENERATION,
            agent_generation_high_water: AGENT_GENERATION,
            phase: DistributedAgentStackDurablePhase::PreparedNoEffects,
            writer_fence: None,
            revision_high_water: None,
            active: None,
            pending: Some(DistributedAgentStackDurablePending {
                kind: DistributedAgentStackPendingKind::ActivateDistributedStack,
                fabric_generation: Some(generation(FABRIC_GENERATION)),
                agent_generation: Some(generation(AGENT_GENERATION)),
                admitted_clock_generation: request.temporal().target_clock_generation(),
                admitted_at_nanos: 100,
                deadline_nanos: 200,
                response_channel: channel,
                request: request.clone(),
            }),
            tenure_nonces: Vec::new(),
            request_nonces: Vec::new(),
            temporal_lineages: Vec::new(),
            terminals: Vec::new(),
            physical_binding_census: 0,
            census_complete: true,
            fabric_ready: false,
            agent_ready: false,
            dependency_satisfied: false,
            exact_zero: false,
            quarantined: false,
            installed_binding_set_digest: None,
            raw_outcome_digest: None,
            quarantine_reason: None,
        }
    }

    fn managed_owner_config(
        directory: &Path,
        projection: &DistributedAgentStackProjectionV1,
        request: &DistributedAgentStackApplyRequestV1,
        runtime_host_epoch: u64,
    ) -> ManagedFabricOwnerConfig {
        ManagedFabricOwnerConfig {
            state_directory: directory.to_path_buf(),
            store_instance_id: [STORE_BYTE; 32],
            owner_target_fingerprint: Digest32::from_bytes([OWNER_TARGET_BYTE; 32]),
            projection: projection
                .managed_agent_stack_projection()
                .managed_fabric_projection()
                .clone(),
            runtime_host_epoch,
            clock: fixture_clock(request),
            response_key_ref: RESPONSE_KEY_REF,
            response_signer: SigningKey::from_bytes(&RESPONSE_SIGNING_SEED),
        }
    }

    fn fresh_managed_owner(
        projection: &DistributedAgentStackProjectionV1,
        request: &DistributedAgentStackApplyRequestV1,
    ) -> (TestDirectory, ManagedFabricRuntimeCore) {
        let managed_projection = projection
            .managed_agent_stack_projection()
            .managed_fabric_projection()
            .clone();
        let managed_projection_digest = managed_fabric_projection_digest(&managed_projection)
            .unwrap_or_else(|error| panic!("managed Fabric projection digest failed: {error}"));
        let (directory, store) =
            managed_fabric_store_fixture(STORE_BYTE, OWNER_TARGET_BYTE, managed_projection_digest);
        let mut owner = ManagedFabricRuntimeCore::from_preopened_store(
            store,
            managed_owner_config(directory.path(), projection, request, INITIAL_RUNTIME_EPOCH),
        )
        .unwrap_or_else(|error| panic!("managed Fabric fixture initialization failed: {error}"));
        // The store's distributed authority transfer requires an already
        // persisted PXAR-v7 predecessor marker. Its nested bytes are opaque to
        // this store-level fixture; the PXDA request and snapshot used below
        // are the real canonical contracts under test.
        owner
            .initialize_managed_agent_stack(
                Digest32::from_bytes([0x71; 32]),
                b"managed-agent-predecessor-fixture",
            )
            .unwrap_or_else(|error| panic!("managed Agent predecessor persist failed: {error}"));
        (directory, owner)
    }

    fn reopen_managed_owner(
        directory: &TestDirectory,
        projection: &DistributedAgentStackProjectionV1,
        request: &DistributedAgentStackApplyRequestV1,
        runtime_host_epoch: u64,
    ) -> ManagedFabricRuntimeCore {
        let managed_projection = projection
            .managed_agent_stack_projection()
            .managed_fabric_projection()
            .clone();
        let managed_projection_digest = managed_fabric_projection_digest(&managed_projection)
            .unwrap_or_else(|error| panic!("managed Fabric projection digest failed: {error}"));
        let store = ManagedFabricStore::open_fixture(
            directory.path(),
            [STORE_BYTE; 32],
            Digest32::from_bytes([OWNER_TARGET_BYTE; 32]),
            managed_projection_digest,
        )
        .unwrap_or_else(|error| panic!("managed Fabric durable reopen failed: {error}"));
        ManagedFabricRuntimeCore::from_preopened_store(
            store,
            managed_owner_config(directory.path(), projection, request, runtime_host_epoch),
        )
        .unwrap_or_else(|error| panic!("managed Fabric core reopen failed: {error}"))
    }

    fn distributed_owner_config(
        directory: &TestDirectory,
        projection: &DistributedAgentStackProjectionV1,
        request: &DistributedAgentStackApplyRequestV1,
        runtime_host_epoch: u64,
    ) -> DistributedAgentStackOwnerConfig {
        DistributedAgentStackOwnerConfig {
            state_directory: directory.path().to_path_buf(),
            projection: projection.clone(),
            runtime_host_epoch,
            clock: fixture_clock(request),
            response_key_ref: RESPONSE_KEY_REF,
            response_signer: SigningKey::from_bytes(&RESPONSE_SIGNING_SEED),
            handle_broker: RuntimeAgentHandleBroker::default(),
            fabric_credential_resolver: None,
            evidence_store_config: None,
            agent_provider_resolver: Arc::new(UnavailableRuntimeAgentProviderResolver),
        }
    }

    fn distributed_owner_config_with_evidence(
        directory: &TestDirectory,
        projection: &DistributedAgentStackProjectionV1,
        request: &DistributedAgentStackApplyRequestV1,
        runtime_host_epoch: u64,
        evidence_config: DistributedAgentStackEvidenceStoreConfigV1,
    ) -> DistributedAgentStackOwnerConfig {
        let mut config =
            distributed_owner_config(directory, projection, request, runtime_host_epoch);
        config.fabric_credential_resolver = Some(Arc::new(FailClosedEvidenceFixtureResolver));
        config.evidence_store_config = Some(evidence_config);
        config
    }

    fn open_distributed_owner(
        owner: &ManagedFabricRuntimeCore,
        directory: &TestDirectory,
        projection: &DistributedAgentStackProjectionV1,
        request: &DistributedAgentStackApplyRequestV1,
        runtime_host_epoch: u64,
    ) -> DistributedAgentStackRuntimeCore {
        DistributedAgentStackRuntimeCore::open(
            owner,
            distributed_owner_config(directory, projection, request, runtime_host_epoch),
        )
        .unwrap_or_else(|error| panic!("distributed owner reopen failed: {error}"))
        .unwrap_or_else(|| panic!("distributed owner marker disappeared"))
    }

    fn open_distributed_owner_with_evidence(
        owner: &ManagedFabricRuntimeCore,
        fixture: &PersistedEvidenceHandoffFixture,
        runtime_host_epoch: u64,
    ) -> DistributedAgentStackRuntimeCore {
        DistributedAgentStackRuntimeCore::open(
            owner,
            distributed_owner_config_with_evidence(
                &fixture.directory,
                &fixture.projection,
                &fixture.request,
                runtime_host_epoch,
                fixture.evidence_config.clone(),
            ),
        )
        .unwrap_or_else(|error| panic!("Evidence distributed owner reopen failed: {error}"))
        .unwrap_or_else(|| panic!("Evidence distributed owner marker disappeared"))
    }

    fn persist_active_fixture(with_recovery_intent: bool) -> PersistedActiveFixture {
        let projection = fixture_projection();
        let request = fixture_request();
        let channel = response_channel(&projection);
        let historical = active_terminal(&request, channel);
        let distributed_projection_digest = projection_digest(&projection)
            .unwrap_or_else(|error| panic!("distributed projection digest failed: {error}"));
        let active = DistributedAgentStackSnapshot::try_initial(
            [STORE_BYTE; 32],
            Digest32::from_bytes([OWNER_TARGET_BYTE; 32]),
            distributed_projection_digest,
            INITIAL_RUNTIME_EPOCH,
            active_transition(&request, channel, historical.clone()),
            &projection,
        )
        .unwrap_or_else(|error| panic!("active distributed snapshot rejected: {error}"));
        let (directory, mut owner) = fresh_managed_owner(&projection, &request);
        owner
            .initialize_distributed_agent_stack(
                distributed_projection_digest,
                active.canonical_wire(),
            )
            .unwrap_or_else(|error| panic!("active distributed snapshot persist failed: {error}"));

        if with_recovery_intent {
            let mut intent = active.transition();
            intent.fabric_generation_high_water = FABRIC_GENERATION + 1;
            intent.agent_generation_high_water = AGENT_GENERATION + 1;
            intent.phase = DistributedAgentStackDurablePhase::RecoveryIntent;
            intent.active = None;
            intent.pending = Some(DistributedAgentStackDurablePending {
                kind: DistributedAgentStackPendingKind::RecoverActive,
                fabric_generation: Some(generation(FABRIC_GENERATION + 1)),
                agent_generation: Some(generation(AGENT_GENERATION + 1)),
                admitted_clock_generation: request.temporal().target_clock_generation(),
                admitted_at_nanos: 110,
                deadline_nanos: 210,
                response_channel: channel,
                request: request.clone(),
            });
            intent.physical_binding_census = 0;
            intent.census_complete = true;
            intent.fabric_ready = false;
            intent.agent_ready = false;
            intent.dependency_satisfied = false;
            intent.exact_zero = false;
            intent.quarantined = false;
            intent.installed_binding_set_digest = None;
            intent.raw_outcome_digest = None;
            intent.quarantine_reason = None;
            let persisted_intent = active
                .try_successor_at_epoch(INITIAL_RUNTIME_EPOCH + 1, intent, &projection)
                .unwrap_or_else(|error| panic!("recovery-intent snapshot rejected: {error}"));
            owner
                .commit_distributed_agent_stack(persisted_intent.canonical_wire())
                .unwrap_or_else(|error| panic!("recovery-intent persist failed: {error}"));
        }
        drop(owner);

        PersistedActiveFixture {
            directory,
            projection,
            request,
            channel,
            historical,
        }
    }

    fn persist_pending_fixture() -> PersistedPendingFixture {
        let projection = fixture_projection();
        let request = fixture_request();
        let channel = response_channel(&projection);
        let distributed_projection_digest = projection_digest(&projection)
            .unwrap_or_else(|error| panic!("distributed projection digest failed: {error}"));
        let pending = DistributedAgentStackSnapshot::try_initial(
            [STORE_BYTE; 32],
            Digest32::from_bytes([OWNER_TARGET_BYTE; 32]),
            distributed_projection_digest,
            INITIAL_RUNTIME_EPOCH,
            pending_transition(&request, channel),
            &projection,
        )
        .unwrap_or_else(|error| panic!("pending distributed snapshot rejected: {error}"));
        let (directory, mut owner) = fresh_managed_owner(&projection, &request);
        owner
            .initialize_distributed_agent_stack(
                distributed_projection_digest,
                pending.canonical_wire(),
            )
            .unwrap_or_else(|error| panic!("pending distributed snapshot persist failed: {error}"));
        drop(owner);

        PersistedPendingFixture {
            directory,
            projection,
            request,
            channel,
        }
    }

    fn persist_evidence_handoff_fixture(
        durable_committed: bool,
    ) -> PersistedEvidenceHandoffFixture {
        persist_evidence_handoff_fixture_with(durable_committed, false, None)
    }

    fn persist_evidence_intent_fixture(
        persisted_prefix_len: usize,
    ) -> PersistedEvidenceHandoffFixture {
        persist_evidence_handoff_fixture_with(false, false, Some(persisted_prefix_len))
    }

    fn persist_evidence_storage_full_fixture() -> PersistedEvidenceHandoffFixture {
        persist_evidence_handoff_fixture_with(false, true, Some(0))
    }

    fn persist_evidence_handoff_fixture_with(
        durable_committed: bool,
        prefill_unrelated_to_capacity: bool,
        persisted_prefix_len: Option<usize>,
    ) -> PersistedEvidenceHandoffFixture {
        assert!(!(durable_committed && prefill_unrelated_to_capacity));
        let projection = fixture_projection();
        let request = fixture_request();
        let channel = response_channel(&projection);
        let batch = fixture_evidence_batch(&request, generation(FABRIC_GENERATION));
        let distributed_projection_digest = projection_digest(&projection)
            .unwrap_or_else(|error| panic!("distributed projection digest failed: {error}"));
        let initial = DistributedAgentStackSnapshot::try_initial(
            [STORE_BYTE; 32],
            Digest32::from_bytes([OWNER_TARGET_BYTE; 32]),
            distributed_projection_digest,
            INITIAL_RUNTIME_EPOCH,
            pending_transition(&request, channel),
            &projection,
        )
        .unwrap_or_else(|error| panic!("initial Evidence snapshot rejected: {error}"));
        let upgraded = initial
            .try_upgrade_v1_to_v2_at_epoch(INITIAL_RUNTIME_EPOCH, &projection)
            .unwrap_or_else(|error| panic!("Evidence v2 upgrade rejected: {error}"));

        let (evidence_directory, evidence_owner) = fresh_managed_owner(&projection, &request);
        drop(evidence_owner);
        let evidence_config = DistributedAgentStackEvidenceStoreConfigV1::try_new(
            evidence_directory.path().join("distributed-evidence"),
            EvidenceStoreEpochV1::try_from_bytes([0x83; 16])
                .unwrap_or_else(|error| panic!("Evidence epoch rejected: {error}")),
            EvidenceRetentionPolicyV1::try_new(
                if prefill_unrelated_to_capacity { 1 } else { 64 },
                1024 * 1024,
            )
            .unwrap_or_else(|error| panic!("Evidence policy rejected: {error}")),
            evidence_owner_ref(),
        )
        .unwrap_or_else(|error| panic!("Evidence config rejected: {error}"));
        let bound_state = DistributedAgentStackEvidenceStateV2::try_new(
            Some(DistributedAgentStackEvidenceBindingV2::new(
                evidence_config.store_epoch(),
                evidence_config.owner_ref(),
            )),
            None,
            DistributedAgentStackEvidenceHandoffV2::None,
        )
        .unwrap_or_else(|error| panic!("Evidence binding state rejected: {error}"));
        let bound = upgraded
            .try_v2_successor_at_epoch(
                INITIAL_RUNTIME_EPOCH,
                upgraded.transition(),
                bound_state.clone(),
                &projection,
            )
            .unwrap_or_else(|error| panic!("Evidence binding successor rejected: {error}"));
        let intent_state = DistributedAgentStackEvidenceStateV2::try_new(
            bound_state.binding(),
            None,
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch.clone()),
        )
        .unwrap_or_else(|error| panic!("Evidence intent state rejected: {error}"));
        let mut intent_transition = bound.transition();
        intent_transition.phase = DistributedAgentStackDurablePhase::EvidenceCommitIntent;
        intent_transition.fabric_ready = true;
        intent_transition.dependency_satisfied = true;
        let intent = bound
            .try_v2_successor_at_epoch(
                INITIAL_RUNTIME_EPOCH,
                intent_transition,
                intent_state,
                &projection,
            )
            .unwrap_or_else(|error| panic!("Evidence intent successor rejected: {error}"));

        let (directory, mut owner) = fresh_managed_owner(&projection, &request);
        owner
            .initialize_distributed_agent_stack(
                distributed_projection_digest,
                intent.canonical_wire(),
            )
            .unwrap_or_else(|error| panic!("Evidence intent persist failed: {error}"));
        let mut evidence_store = LocalEvidenceStoreV1::open(
            evidence_config.root(),
            evidence_config.store_epoch(),
            evidence_config.retention_policy(),
        )
        .unwrap_or_else(|error| panic!("Evidence fixture store open failed: {error}"));
        let verified = if prefill_unrelated_to_capacity {
            let payload = batch.records()[0]
                .payload()
                .inline_bytes()
                .unwrap_or_else(|| panic!("Evidence fixture payload was not inline"));
            let unrelated = EvidenceRecordV1::try_new(EvidenceRecordInputV1 {
                record_id: EvidenceRecordIdV1::try_from_bytes([0xb1; 16])
                    .unwrap_or_else(|error| panic!("unrelated record id rejected: {error}")),
                owner_ref: EvidenceOwnerRefV1::try_from_bytes([0xb2; 16])
                    .unwrap_or_else(|error| panic!("unrelated owner rejected: {error}")),
                producer_sequence: 1,
                causality_ref: None,
                previous_evidence_ref: None,
                kind: EvidenceKindV1::RuntimeFact,
                payload: EvidencePayloadV1::try_public_safe_inline(payload)
                    .unwrap_or_else(|error| panic!("unrelated payload rejected: {error}")),
            })
            .unwrap_or_else(|error| panic!("unrelated Evidence record rejected: {error}"));
            evidence_store
                .append(unrelated)
                .unwrap_or_else(|error| panic!("unrelated Evidence append failed: {error}"));
            None
        } else {
            let prefix_len = persisted_prefix_len.unwrap_or(batch.records().len());
            assert!(prefix_len <= batch.records().len());
            if prefix_len == batch.records().len() {
                Some(
                    append_and_verify_evidence_batch(&mut evidence_store, &batch)
                        .unwrap_or_else(|error| panic!("Evidence fixture append failed: {error}")),
                )
            } else {
                for record in batch.records().iter().take(prefix_len) {
                    evidence_store
                        .append(record.clone())
                        .unwrap_or_else(|error| panic!("Evidence prefix append failed: {error}"));
                }
                None
            }
        };
        if durable_committed {
            let verified = verified
                .as_ref()
                .unwrap_or_else(|| panic!("committed fixture lost store verification"));
            let committed_state = intent
                .evidence_state()
                .try_mark_committed(&verified.receipts, &verified.readback)
                .unwrap_or_else(|error| panic!("verified Evidence commit rejected: {error}"));
            let mut committed_transition = intent.transition();
            committed_transition.phase = DistributedAgentStackDurablePhase::AgentStartIntent;
            let committed = intent
                .try_v2_successor_at_epoch(
                    INITIAL_RUNTIME_EPOCH,
                    committed_transition,
                    committed_state,
                    &projection,
                )
                .unwrap_or_else(|error| panic!("committed Evidence successor rejected: {error}"));
            owner
                .commit_distributed_agent_stack(committed.canonical_wire())
                .unwrap_or_else(|error| panic!("committed Evidence persist failed: {error}"));
        }
        drop(evidence_store);
        drop(owner);
        PersistedEvidenceHandoffFixture {
            directory,
            _evidence_directory: evidence_directory,
            projection,
            request,
            channel,
            evidence_config,
            batch,
        }
    }

    async fn assert_persisted_evidence_handoff_requires_fresh_generation(
        fixture: PersistedEvidenceHandoffFixture,
        expected_phase: DistributedAgentStackDurablePhase,
    ) {
        let mut owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        let mut distributed =
            open_distributed_owner_with_evidence(&owner, &fixture, INITIAL_RUNTIME_EPOCH + 1);
        assert_eq!(distributed.snapshot.phase, expected_phase);
        assert!(distributed.snapshot.terminals.is_empty());
        let result = distributed.recover(&mut owner).await;
        assert!(matches!(
            result,
            Err(DistributedAgentStackRuntimeError::DistributedFabric(_))
        ));
        // Replaying an intent may finish the exact old append, but the old
        // Committed batch remains a recovery checkpoint only. The fail-closed
        // fresh-generation resolver prevents any Agent start or terminal.
        assert_eq!(
            distributed.snapshot.phase,
            DistributedAgentStackDurablePhase::AgentStartIntent
        );
        assert!(matches!(
            distributed.snapshot.evidence_state().handoff(),
            DistributedAgentStackEvidenceHandoffV2::Committed(committed)
                if committed.batch() == &fixture.batch
        ));
        assert!(distributed.snapshot.evidence_state().owner_head().is_some());
        assert!(distributed.snapshot.terminals.is_empty());
        assert!(distributed.fabric.is_none());
        assert!(distributed.assembly.is_none());
        assert!(distributed.handle.is_none());
        assert!(!distributed.recovery_completed);
        assert!(
            distributed
                .authenticated_terminal_replay(&owner, &fixture.request, fixture.channel)
                .unwrap_or_else(|error| panic!("Evidence terminal replay failed: {error}"))
                .is_none()
        );
        drop(distributed);
        drop(owner);

        let mut owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 2,
        );
        let mut reopened =
            open_distributed_owner_with_evidence(&owner, &fixture, INITIAL_RUNTIME_EPOCH + 2);
        assert!(matches!(
            reopened.recover(&mut owner).await,
            Err(DistributedAgentStackRuntimeError::DistributedFabric(_))
        ));
        assert_eq!(
            reopened.snapshot.phase,
            DistributedAgentStackDurablePhase::AgentStartIntent
        );
        assert!(reopened.snapshot.terminals.is_empty());
        assert!(reopened.assembly.is_none());
        assert!(reopened.handle.is_none());
        assert!(!reopened.recovery_completed);
    }

    #[tokio::test]
    async fn phase_eleven_crash_reopens_exact_batch_and_commits_original_pxtp() {
        let zero_prefix = persist_evidence_intent_fixture(0);
        let record_count = zero_prefix.batch.records().len();
        assert_persisted_evidence_handoff_requires_fresh_generation(
            zero_prefix,
            DistributedAgentStackDurablePhase::EvidenceCommitIntent,
        )
        .await;
        if record_count > 1 {
            assert_persisted_evidence_handoff_requires_fresh_generation(
                persist_evidence_intent_fixture(1),
                DistributedAgentStackDurablePhase::EvidenceCommitIntent,
            )
            .await;
        }
        assert_persisted_evidence_handoff_requires_fresh_generation(
            persist_evidence_handoff_fixture(false),
            DistributedAgentStackDurablePhase::EvidenceCommitIntent,
        )
        .await;
    }

    #[tokio::test]
    async fn committed_crash_never_uses_old_batch_to_start_agent() {
        assert_persisted_evidence_handoff_requires_fresh_generation(
            persist_evidence_handoff_fixture(true),
            DistributedAgentStackDurablePhase::AgentStartIntent,
        )
        .await;
    }

    #[tokio::test]
    async fn deterministic_evidence_store_failure_keeps_phase_eleven_without_terminal() {
        let fixture = persist_evidence_storage_full_fixture();
        let mut owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        let mut distributed =
            open_distributed_owner_with_evidence(&owner, &fixture, INITIAL_RUNTIME_EPOCH + 1);
        let result = distributed.recover(&mut owner).await;
        assert!(matches!(
            result,
            Err(DistributedAgentStackRuntimeError::EvidenceStore(
                EvidenceStoreError::StorageFull
            ))
        ));
        assert_eq!(
            distributed.snapshot.phase,
            DistributedAgentStackDurablePhase::EvidenceCommitIntent
        );
        assert!(distributed.snapshot.terminals.is_empty());
        assert!(matches!(
            distributed.snapshot.evidence_state().handoff(),
            DistributedAgentStackEvidenceHandoffV2::CommitIntent(batch)
                if batch == &fixture.batch
        ));
    }

    #[test]
    fn experimental_snapshot_binding_rows_require_exact_count_and_order() {
        let first = Digest32::from_bytes([0x31; 32]);
        let second = Digest32::from_bytes([0x32; 32]);

        validate_experimental_binding_order(&[first, second], &[first, second])
            .unwrap_or_else(|error| panic!("matching snapshot rows were rejected: {error}"));
        assert!(matches!(
            validate_experimental_binding_order(&[first, second], &[first]),
            Err(DistributedAgentStackRuntimeError::ObservationCorrelationMismatch)
        ));
        assert!(matches!(
            validate_experimental_binding_order(&[first, second], &[second, first]),
            Err(DistributedAgentStackRuntimeError::ObservationCorrelationMismatch)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn activation_vertical_after_validated_snapshot_commits_ready_and_serves_echo() {
        let projection = fixture_projection();
        let request = fixture_request();
        let channel = response_channel(&projection);
        let fabric_generation = generation(FABRIC_GENERATION);
        let agent_generation = generation(AGENT_GENERATION);
        let projection_digest = projection_digest(&projection)
            .unwrap_or_else(|error| panic!("distributed projection digest failed: {error}"));

        let (evidence_directory, evidence_owner) = fresh_managed_owner(&projection, &request);
        drop(evidence_owner);
        let evidence_config = DistributedAgentStackEvidenceStoreConfigV1::try_new(
            evidence_directory
                .path()
                .join("activation-vertical-evidence"),
            EvidenceStoreEpochV1::try_from_bytes([0xc1; 16])
                .unwrap_or_else(|error| panic!("Evidence epoch rejected: {error}")),
            EvidenceRetentionPolicyV1::try_new(64, 1024 * 1024)
                .unwrap_or_else(|error| panic!("Evidence policy rejected: {error}")),
            evidence_owner_ref(),
        )
        .unwrap_or_else(|error| panic!("Evidence config rejected: {error}"));
        let initial = DistributedAgentStackSnapshot::try_initial(
            [STORE_BYTE; 32],
            Digest32::from_bytes([OWNER_TARGET_BYTE; 32]),
            projection_digest,
            INITIAL_RUNTIME_EPOCH,
            pending_transition(&request, channel),
            &projection,
        )
        .unwrap_or_else(|error| panic!("initial activation snapshot rejected: {error}"));
        let upgraded = initial
            .try_upgrade_v1_to_v2_at_epoch(INITIAL_RUNTIME_EPOCH, &projection)
            .unwrap_or_else(|error| panic!("Evidence v2 upgrade rejected: {error}"));
        let bound_evidence = DistributedAgentStackEvidenceStateV2::try_new(
            Some(DistributedAgentStackEvidenceBindingV2::new(
                evidence_config.store_epoch(),
                evidence_config.owner_ref(),
            )),
            None,
            DistributedAgentStackEvidenceHandoffV2::None,
        )
        .unwrap_or_else(|error| panic!("Evidence binding rejected: {error}"));
        let bound = upgraded
            .try_v2_successor_at_epoch(
                INITIAL_RUNTIME_EPOCH,
                upgraded.transition(),
                bound_evidence.clone(),
                &projection,
            )
            .unwrap_or_else(|error| panic!("Evidence binding successor rejected: {error}"));
        let mut start_transition = bound.transition();
        start_transition.phase = DistributedAgentStackDurablePhase::StartIntent;
        let start = bound
            .try_v2_successor_at_epoch(
                INITIAL_RUNTIME_EPOCH,
                start_transition,
                bound_evidence,
                &projection,
            )
            .unwrap_or_else(|error| panic!("Fabric start-intent successor rejected: {error}"));

        let (directory, mut owner) = fresh_managed_owner(&projection, &request);
        owner
            .initialize_distributed_agent_stack(projection_digest, start.canonical_wire())
            .unwrap_or_else(|error| panic!("activation snapshot persist failed: {error}"));
        let broker = RuntimeAgentHandleBroker::default();
        let mut config = distributed_owner_config_with_evidence(
            &directory,
            &projection,
            &request,
            INITIAL_RUNTIME_EPOCH + 1,
            evidence_config.clone(),
        );
        config.handle_broker = broker.clone();
        config.agent_provider_resolver = Arc::new(ExactSelectionEchoFixtureResolver);
        let mut distributed = DistributedAgentStackRuntimeCore::open(&owner, config)
            .unwrap_or_else(|error| panic!("activation owner open failed: {error}"))
            .unwrap_or_else(|| panic!("activation owner marker disappeared"));
        distributed.recovery_completed = true;

        let probe = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .unwrap_or_else(|error| panic!("ephemeral Fabric port allocation failed: {error}"));
        let fabric_port = probe
            .local_addr()
            .unwrap_or_else(|error| panic!("ephemeral Fabric port lookup failed: {error}"))
            .port();
        drop(probe);
        let endpoint = SessionEndpoint::try_new(format!("tcp/127.0.0.1:{fabric_port}"))
            .unwrap_or_else(|error| panic!("loopback Fabric endpoint rejected: {error}"));
        let fabric_config = FabricServiceConfig::try_peer(vec![endpoint], Vec::new())
            .unwrap_or_else(|error| panic!("loopback Fabric config rejected: {error}"));
        let (fabric_service, fabric_control) =
            RuntimeManagedFabricService::from_exact_config(fabric_config, fabric_generation);
        let fabric_spec = request
            .target_execution()
            .predecessor()
            .fabric()
            .service()
            .unwrap_or_else(|| panic!("distributed predecessor lost its Fabric service"));
        let fabric_cancellation = CancellationSource::root();
        let mut fabric_assembly = ManagedServiceAssembly::new(
            fabric_spec,
            fabric_generation,
            Box::new(fabric_service),
            fixture_clock(&request),
            &fabric_cancellation,
        );
        assert_eq!(
            fabric_assembly.startup().await,
            ManagedServiceStartupOutcome::Ready
        );
        assert_eq!(
            fabric_control
                .binding_census()
                .await
                .unwrap_or_else(|error| panic!("initial Fabric census failed: {error:?}")),
            0
        );

        let topology = request
            .target_execution()
            .topology()
            .unwrap_or_else(|| panic!("distributed fixture lost topology"));
        let validated_snapshot = ValidatedExperimentalSnapshot {
            fabric_generation,
            session_epoch: DistributedFabricSessionEpochV1::try_from_bytes([0xc2; 16])
                .unwrap_or_else(|error| panic!("session epoch rejected: {error:?}")),
            peer_owner_facts: topology
                .peers()
                .iter()
                .enumerate()
                .map(|(index, _)| ValidatedExperimentalPeerOwnerFacts {
                    identity_binding_digest: Digest32::from_bytes(
                        [u8::try_from(index + 1).unwrap_or_else(|_| panic!("peer index overflow"));
                            32],
                    ),
                    observation_sequence: u64::try_from(index)
                        .unwrap_or_else(|_| panic!("peer index overflow"))
                        + 1,
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        };
        let terminal_mode = ActivationTerminalMode::RecordActiveReady;
        let receipt = distributed
            .commit_snapshot_evidence_and_activate(
                &mut owner,
                validated_snapshot,
                fabric_control.clone(),
                ActivationContext {
                    request: &request,
                    response_channel: channel,
                    fabric_generation,
                    agent_generation,
                    raw_code: 0xd8,
                    terminal_mode: &terminal_mode,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("activation vertical failed: {error}"));

        assert_eq!(
            receipt.facts().outcome(),
            DistributedAgentStackTerminalOutcomeV1::ActiveReady
        );
        assert_eq!(
            distributed.snapshot.phase,
            DistributedAgentStackDurablePhase::ActiveReady
        );
        assert!(matches!(
            distributed.snapshot.evidence_state().handoff(),
            DistributedAgentStackEvidenceHandoffV2::None
        ));
        assert!(distributed.snapshot.evidence_state().owner_head().is_some());
        assert_eq!(distributed.snapshot.physical_binding_census, 2);
        assert_eq!(
            fabric_control
                .binding_census()
                .await
                .unwrap_or_else(|error| panic!("ready Fabric census failed: {error:?}")),
            2
        );
        validate_opened_evidence_store(
            distributed.snapshot.evidence_state(),
            &evidence_config,
            distributed
                .evidence_store
                .as_ref()
                .unwrap_or_else(|| panic!("activation Evidence store disappeared")),
        )
        .unwrap_or_else(|error| panic!("durable Evidence reopen validation failed: {error}"));
        let proofs = receipt
            .facts()
            .observations()
            .unwrap_or_else(|| panic!("ActiveReady terminal lost Evidence proofs"))
            .proofs();
        assert_eq!(proofs.len(), topology.peers().len());
        for proof in proofs {
            let record_id = EvidenceRecordIdV1::try_from_bytes(
                *proof.fields().transport_evidence_ref.as_bytes(),
            )
            .unwrap_or_else(|error| panic!("terminal Evidence ref rejected: {error}"));
            let stored = distributed
                .evidence_store
                .as_mut()
                .unwrap_or_else(|| panic!("activation Evidence store disappeared"))
                .read(record_id)
                .unwrap_or_else(|error| panic!("Evidence record read failed: {error}"))
                .unwrap_or_else(|| panic!("terminal Evidence record disappeared"));
            assert_eq!(
                stored
                    .record()
                    .payload()
                    .inline_bytes()
                    .unwrap_or_else(|| panic!("PXTP Evidence payload was not inline")),
                proof.canonical_wire()
            );
        }

        let claimed = broker
            .try_claim_distributed(receipt.canonical_wire())
            .unwrap_or_else(|error| panic!("distributed broker claim failed: {error}"))
            .unwrap_or_else(|| panic!("committed distributed handle was not published"));
        let deck_run_id = AgentConversationDeckRunId::try_from_bytes([0xd1; 16])
            .unwrap_or_else(|error| panic!("DeckRun id rejected: {error}"));
        let session_id = AgentConversationSessionId::try_from_bytes([0xd2; 16])
            .unwrap_or_else(|error| panic!("Session id rejected: {error}"));
        assert_eq!(
            claimed
                .open_session(deck_run_id, session_id, Duration::from_secs(2))
                .await
                .unwrap_or_else(|error| panic!("distributed Session open failed: {error}")),
            AgentConversationOpenOutcomeV1::Opened
        );
        let request_turn = AgentConversationRequestV1::try_new(
            deck_run_id,
            session_id,
            AgentConversationTurnId::try_from_bytes([0xd3; 16])
                .unwrap_or_else(|error| panic!("Turn id rejected: {error}")),
            AgentConversationRequestId::try_from_bytes([0xd4; 16])
                .unwrap_or_else(|error| panic!("request id rejected: {error}")),
            2_000_000_000,
            "distributed activation vertical",
        )
        .unwrap_or_else(|error| panic!("conversation request rejected: {error}"));
        let terminal = claimed
            .submit(request_turn, Duration::from_secs(2))
            .await
            .unwrap_or_else(|error| panic!("distributed conversation failed: {error}"));
        assert_eq!(
            terminal.result(),
            &AgentConversationTerminalResultV1::Success(
                "echo: distributed activation vertical".into()
            )
        );

        distributed
            .revoke_owned_handle()
            .unwrap_or_else(|error| panic!("distributed handle revoke failed: {error}"));
        let mut agent_assembly = distributed
            .assembly
            .take()
            .unwrap_or_else(|| panic!("ActiveReady Agent assembly disappeared"));
        agent_assembly
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("Agent shutdown failed: {error}"));
        assert_eq!(
            fabric_control
                .binding_census()
                .await
                .unwrap_or_else(|error| panic!("post-Agent Fabric census failed: {error:?}")),
            0
        );
        assert!(
            broker
                .try_claim_distributed(receipt.canonical_wire())
                .unwrap_or_else(|error| panic!("post-revoke broker claim failed: {error}"))
                .is_none()
        );
        assert!(fabric_assembly.shutdown().await.exact_zero());
    }

    #[test]
    fn activation_orders_evidence_agent_ready_commit_and_handle_publication() {
        let source = include_str!("distributed_agent_stack_runtime.rs");
        let helper = source
            .split_once("fn prepare_generation(")
            .and_then(|(_, tail)| tail.split_once("fn validate_experimental_binding_order"))
            .map(|(helper, _)| helper)
            .unwrap_or_else(|| panic!("prepare helper source boundary disappeared"));
        assert!(helper.contains("try_prepare_experimental_cn_v2"));
        assert!(!helper.contains("DistributedFabricRuntimeGeneration::try_prepare("));

        let evidence_commit = source
            .split_once("async fn commit_snapshot_evidence_and_activate(")
            .and_then(|(_, tail)| tail.split_once("async fn start_agent_after_verified_evidence("))
            .map(|(commit, _)| commit)
            .unwrap_or_else(|| panic!("Evidence commit source boundary disappeared"));
        let begin = evidence_commit
            .find("self.begin_evidence_commit(owner, batch.clone())")
            .unwrap_or_else(|| panic!("Evidence CommitIntent disappeared"));
        let append = evidence_commit
            .find("self.append_evidence_batch_with_one_reopen(&batch)")
            .unwrap_or_else(|| panic!("Evidence append/readback disappeared"));
        let committed = evidence_commit
            .find("self.mark_evidence_committed(owner, &verified)")
            .unwrap_or_else(|| panic!("Evidence Committed transition disappeared"));
        let agent_gate = evidence_commit
            .find("self.start_agent_after_verified_evidence(")
            .unwrap_or_else(|| panic!("verified Evidence Agent gate disappeared"));
        assert!(begin < append && append < committed && committed < agent_gate);
        assert!(!evidence_commit.contains("ManagedAgentAssembly::start_from_execution"));
        assert!(!evidence_commit.contains("publish_distributed"));

        let activation = source
            .split_once("async fn start_agent_after_verified_evidence(")
            .and_then(|(_, tail)| tail.split_once("fn activation_apply_outcome("))
            .map(|(activation, _)| activation)
            .unwrap_or_else(|| panic!("Agent activation source boundary disappeared"));
        let verify_committed = activation
            .find("DistributedAgentStackEvidenceHandoffV2::Committed(committed)")
            .unwrap_or_else(|| panic!("Committed Evidence gate disappeared"));
        let start_agent = activation
            .find("ManagedAgentAssembly::start_from_execution(")
            .unwrap_or_else(|| panic!("Agent start disappeared"));
        let verify_bindings = activation
            .rfind("fabric_control.binding_census().await")
            .unwrap_or_else(|| panic!("binding census verification disappeared"));
        let commit_ready = activation
            .find("self.commit_v2_transition(owner, ready, cleared_evidence)")
            .unwrap_or_else(|| panic!("atomic ActiveReady commit disappeared"));
        let publish = activation
            .find(".publish_distributed(handle, &receipt)")
            .unwrap_or_else(|| panic!("distributed handle publication disappeared"));
        assert!(
            verify_committed < start_agent
                && start_agent < verify_bindings
                && verify_bindings < commit_ready
                && commit_ready < publish
        );
    }

    #[test]
    fn cutover_retains_committed_owner_after_post_initialize_failure() {
        let source = include_str!("distributed_agent_stack_runtime.rs");
        let cutover = source
            .split_once("pub(crate) async fn cutover(")
            .and_then(|(_, tail)| tail.split_once("pub(crate) fn authenticated_terminal_replay("))
            .map(|(cutover, _)| cutover)
            .unwrap_or_else(|| panic!("distributed cutover source boundary disappeared"));
        let (_, post_initialize) = cutover
            .split_once("owner.initialize_distributed_agent_stack(")
            .unwrap_or_else(|| panic!("durable owner initialization disappeared"));
        assert!(post_initialize.contains("let mut core = Self::from_snapshot("));
        assert!(
            post_initialize
                .match_indices("DistributedAgentStackApplyOutcome::CommittedOwnerRestartRequired")
                .count()
                >= 3
        );
        assert!(!post_initialize.contains(".await?"));
    }

    #[test]
    fn pending_handle_publication_rejects_non_exact_requests_as_temporarily_unavailable() {
        let source = include_str!("distributed_agent_stack_runtime.rs");
        let replay = source
            .split_once("pub(crate) fn authenticated_terminal_replay(")
            .and_then(|(_, tail)| tail.split_once("pub(crate) async fn apply("))
            .map(|(replay, _)| replay)
            .unwrap_or_else(|| panic!("authenticated replay source boundary disappeared"));
        assert!(replay.contains("if self.handle_publication_pending"));
        assert!(
            replay.contains(".ok_or(DistributedAgentStackRuntimeError::HandlePublicationPending)?")
        );
        assert!(!replay.contains(
            ".ok_or(DistributedAgentStackRuntimeError::InvalidDurableState)?;\n            let handle"
        ));
    }

    #[test]
    fn recovery_prepares_v2_generation_before_durable_intent() {
        let source = include_str!("distributed_agent_stack_runtime.rs");
        let recovery_selection = source
            .split_once("pub(crate) async fn recover(")
            .and_then(|(_, tail)| tail.split_once("let reading = self.clock.reading()?;"))
            .map(|(recovery, _)| recovery)
            .unwrap_or_else(|| panic!("recovery terminal selection boundary disappeared"));
        assert!(
            recovery_selection.contains("match self.lookup_terminal(&request, response_channel)?")
        );
        assert!(
            recovery_selection.contains(
                "ActivationTerminalMode::PreserveHistoricalActive(Box::new(historical))",
            )
        );
        assert!(recovery_selection.contains(
            "Some(_) => return Err(DistributedAgentStackRuntimeError::InvalidDurableState)"
        ));
        assert!(recovery_selection.contains("None => ActivationTerminalMode::RecordActiveReady"));
        let recovery_attempt = source
            .split_once("let deadline_nanos = recovery_deadline")
            .and_then(|(_, tail)| tail.split_once("async fn execute_pending_activation("))
            .map(|(recovery, _)| recovery)
            .unwrap_or_else(|| panic!("recovery source boundary disappeared"));
        let prepare = recovery_attempt
            .find("let prepared = prepare_generation(")
            .unwrap_or_else(|| panic!("recovery V2 prepare disappeared"));
        let commit = recovery_attempt
            .find("self.commit_transition(owner, intent)?;")
            .unwrap_or_else(|| panic!("recovery intent commit disappeared"));
        let install = recovery_attempt
            .find("self.fabric = prepared;")
            .unwrap_or_else(|| panic!("prepared generation install disappeared"));
        assert!(prepare < commit && commit < install);
    }

    #[test]
    fn active_reopen_cannot_use_handoff_none_as_agent_authority() {
        let source = include_str!("distributed_agent_stack_runtime.rs");
        let recover = source
            .split_once("pub(crate) async fn recover(")
            .and_then(|(_, tail)| tail.split_once("async fn recover_evidence_handoff("))
            .map(|(recover, _)| recover)
            .unwrap_or_else(|| panic!("recover source boundary disappeared"));
        assert!(recover.contains("DistributedAgentStackDurablePhase::ActiveReady"));
        assert!(recover.contains("self.restart_activation_with_fresh_evidence("));
        assert!(!recover.contains("start_agent_after_verified_evidence("));

        let restart = source
            .split_once("async fn restart_activation_with_fresh_evidence(")
            .and_then(|(_, tail)| tail.split_once("async fn execute_pending_activation("))
            .map(|(restart, _)| restart)
            .unwrap_or_else(|| panic!("fresh recovery source boundary disappeared"));
        let next_fabric = restart
            .find("next_generation(self.snapshot.fabric_generation_high_water)")
            .unwrap_or_else(|| panic!("fresh Fabric generation disappeared"));
        let recovery_intent = restart
            .find("intent.phase = DistributedAgentStackDurablePhase::RecoveryIntent")
            .unwrap_or_else(|| panic!("fresh RecoveryIntent disappeared"));
        let execute = restart
            .find("self.execute_pending_activation(")
            .unwrap_or_else(|| panic!("fresh activation execution disappeared"));
        assert!(next_fabric < recovery_intent && recovery_intent < execute);
        assert!(!restart.contains("exact_proofs_from_evidence_batch"));
        assert!(!restart.contains("ManagedAgentAssembly::start_from_execution"));
    }

    #[test]
    fn prior_reactor_sample_does_not_extend_runtime_budget() {
        let generation = ClockGeneration::try_new(7)
            .unwrap_or_else(|error| panic!("clock generation failed: {error:?}"));
        let reading = ClockReading::new(
            ClockDomainRef::from_bytes([0x21; 16]),
            generation,
            MonotonicInstant::from_ticks(100),
        );
        let reactor_sample = Instant::now();
        let mapped = map_runtime_deadline_from_prior_reactor_sample(
            reactor_sample,
            reading,
            generation,
            150,
        )
        .unwrap_or_else(|error| panic!("deadline mapping failed: {error}"));
        let later_sample = reactor_sample + core::time::Duration::from_nanos(20);

        assert_eq!(
            mapped,
            reactor_sample + core::time::Duration::from_nanos(50)
        );
        assert!(mapped < later_sample + core::time::Duration::from_nanos(50));
    }

    #[test]
    fn active_recovery_completion_preserves_historical_terminal_source() {
        let source = include_str!("distributed_agent_stack_runtime.rs");
        let helper = source
            .split_once("fn commit_recovery_exact_zero_preserving_terminal(")
            .and_then(|(_, tail)| tail.split_once("fn terminalize_empty_exact_zero("))
            .map(|(helper, _)| helper)
            .unwrap_or_else(|| panic!("historical terminal helper boundary disappeared"));

        assert!(helper.contains("validate_historical_active_terminal"));
        assert!(helper.contains("exact_zero.phase = DistributedAgentStackDurablePhase::ExactZero"));
        assert!(helper.contains("exact_zero.terminals != self.snapshot.terminals"));
        assert!(!helper.contains("insert_terminal("));
        assert!(!helper.contains("build_terminal("));
        assert!(!helper.contains("sign_terminal("));
    }

    #[tokio::test]
    async fn durable_active_recovery_preserves_historical_terminal_across_reopen() {
        let fixture = persist_active_fixture(false);
        let mut owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        let mut distributed = open_distributed_owner(
            &owner,
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        assert_eq!(
            distributed.snapshot.phase,
            DistributedAgentStackDurablePhase::ActiveReady
        );

        distributed
            .recover(&mut owner)
            .await
            .unwrap_or_else(|error| panic!("active durable recovery failed: {error}"));
        assert!(distributed.durable_current_is_exact_zero_for_test());
        assert!(distributed.recovery_completed);
        assert_eq!(distributed.snapshot.terminals.len(), 1);
        let recovered = distributed
            .authenticated_terminal_replay(&owner, &fixture.request, fixture.channel)
            .unwrap_or_else(|error| panic!("recovered terminal lookup failed: {error}"))
            .unwrap_or_else(|| panic!("historical terminal disappeared during recovery"));
        assert_eq!(
            recovered.canonical_wire(),
            fixture.historical.canonical_wire()
        );
        drop(distributed);
        drop(owner);

        let owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 2,
        );
        let mut reopened = open_distributed_owner(
            &owner,
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 2,
        );
        assert!(reopened.durable_current_is_exact_zero_for_test());
        assert_eq!(reopened.snapshot.terminals.len(), 1);
        let durable_replay = reopened
            .authenticated_terminal_replay(&owner, &fixture.request, fixture.channel)
            .unwrap_or_else(|error| panic!("durable terminal replay failed: {error}"))
            .unwrap_or_else(|| panic!("durable historical terminal disappeared"));
        assert_eq!(
            durable_replay.canonical_wire(),
            fixture.historical.canonical_wire()
        );
    }

    #[tokio::test]
    async fn persisted_recovery_intent_second_reopen_preserves_historical_terminal() {
        let fixture = persist_active_fixture(true);
        let mut owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 2,
        );
        let mut distributed = open_distributed_owner(
            &owner,
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 2,
        );
        assert_eq!(
            distributed.snapshot.phase,
            DistributedAgentStackDurablePhase::RecoveryIntent
        );
        assert_eq!(distributed.snapshot.terminals.len(), 1);
        assert_eq!(
            distributed.snapshot.terminals[0].receipt.canonical_wire(),
            fixture.historical.canonical_wire()
        );

        distributed
            .recover(&mut owner)
            .await
            .unwrap_or_else(|error| panic!("second recovery-intent reopen failed: {error}"));
        assert!(distributed.durable_current_is_exact_zero_for_test());
        assert!(distributed.recovery_completed);
        assert_eq!(distributed.snapshot.terminals.len(), 1);
        let recovered = distributed
            .authenticated_terminal_replay(&owner, &fixture.request, fixture.channel)
            .unwrap_or_else(|error| panic!("second-reopen terminal lookup failed: {error}"))
            .unwrap_or_else(|| panic!("second-reopen historical terminal disappeared"));
        assert_eq!(
            recovered.canonical_wire(),
            fixture.historical.canonical_wire()
        );
        drop(distributed);
        drop(owner);

        let owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 3,
        );
        let mut reopened = open_distributed_owner(
            &owner,
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 3,
        );
        let durable_replay = reopened
            .authenticated_terminal_replay(&owner, &fixture.request, fixture.channel)
            .unwrap_or_else(|error| panic!("post-recovery durable replay failed: {error}"))
            .unwrap_or_else(|| panic!("post-recovery historical terminal disappeared"));
        assert_eq!(
            durable_replay.canonical_wire(),
            fixture.historical.canonical_wire()
        );
    }

    #[test]
    fn uncertain_cleanup_quarantine_persists_without_creating_a_terminal() {
        let fixture = persist_active_fixture(false);
        let mut owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        let mut distributed = open_distributed_owner(
            &owner,
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        let mode =
            ActivationTerminalMode::PreserveHistoricalActive(Box::new(fixture.historical.clone()));
        let returned = distributed
            .complete_uncertain_cleanup(
                &mut owner,
                UncertainCleanupInput {
                    request: &fixture.request,
                    response_channel: fixture.channel,
                    proofs: Vec::new(),
                    raw_code: 0x71,
                    generations: TerminalGenerations {
                        fabric: Some(generation(FABRIC_GENERATION)),
                        agent: Some(generation(AGENT_GENERATION)),
                    },
                    terminal_mode: &mode,
                },
            )
            .unwrap_or_else(|error| panic!("uncertain cleanup quarantine failed: {error}"));
        assert_eq!(
            returned.canonical_wire(),
            fixture.historical.canonical_wire()
        );
        assert_eq!(
            distributed.snapshot.phase,
            DistributedAgentStackDurablePhase::Quarantined
        );
        assert_eq!(distributed.snapshot.terminals.len(), 1);
        assert_eq!(
            distributed.snapshot.terminals[0].receipt.canonical_wire(),
            fixture.historical.canonical_wire()
        );
        drop(distributed);
        drop(owner);

        let owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 2,
        );
        let mut reopened = open_distributed_owner(
            &owner,
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 2,
        );
        assert_eq!(
            reopened.snapshot.phase,
            DistributedAgentStackDurablePhase::Quarantined
        );
        assert_eq!(reopened.snapshot.terminals.len(), 1);
        let durable_replay = reopened
            .authenticated_terminal_replay(&owner, &fixture.request, fixture.channel)
            .unwrap_or_else(|error| panic!("quarantined terminal replay failed: {error}"))
            .unwrap_or_else(|| panic!("quarantine dropped the historical terminal"));
        assert_eq!(
            durable_replay.canonical_wire(),
            fixture.historical.canonical_wire()
        );
    }

    #[tokio::test]
    async fn pending_without_terminal_recovers_to_one_conservative_non_ready_terminal() {
        let fixture = persist_pending_fixture();
        let mut owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        let mut distributed = open_distributed_owner(
            &owner,
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        assert!(distributed.snapshot.terminals.is_empty());

        distributed
            .recover(&mut owner)
            .await
            .unwrap_or_else(|error| panic!("pending no-terminal recovery failed: {error}"));
        assert!(distributed.durable_current_is_exact_zero_for_test());
        assert!(distributed.recovery_completed);
        assert_eq!(distributed.snapshot.terminals.len(), 1);
        let recovered = distributed
            .authenticated_terminal_replay(&owner, &fixture.request, fixture.channel)
            .unwrap_or_else(|error| panic!("conservative terminal lookup failed: {error}"))
            .unwrap_or_else(|| panic!("pending recovery did not record a terminal"));
        assert_eq!(
            recovered.facts().outcome(),
            DistributedAgentStackTerminalOutcomeV1::TerminalNonReady
        );
        let local_bindings = recovered.facts().evidence().local_bindings;
        assert_eq!(local_bindings.physical_binding_census, 0);
        assert!(!local_bindings.census_complete);
        assert!(!local_bindings.fabric_ready);
        assert!(!local_bindings.agent_ready);
        assert!(!local_bindings.dependency_satisfied);
        assert!(!local_bindings.exact_zero);
        assert!(!local_bindings.quarantined);
        let recovered_wire = recovered.canonical_wire().to_vec();
        drop(distributed);
        drop(owner);

        let owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 2,
        );
        let mut reopened = open_distributed_owner(
            &owner,
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 2,
        );
        assert!(reopened.durable_current_is_exact_zero_for_test());
        assert_eq!(reopened.snapshot.terminals.len(), 1);
        let durable_replay = reopened
            .authenticated_terminal_replay(&owner, &fixture.request, fixture.channel)
            .unwrap_or_else(|error| panic!("durable conservative replay failed: {error}"))
            .unwrap_or_else(|| panic!("durable conservative terminal disappeared"));
        assert_eq!(durable_replay.canonical_wire(), recovered_wire.as_slice());
    }

    #[test]
    fn validated_snapshot_retains_generation_epoch_and_peer_sequences_then_stays_conservative() {
        let fabric_generation = ManagedServiceGeneration::try_new(17)
            .unwrap_or_else(|error| panic!("fabric generation failed: {error:?}"));
        let session_epoch = DistributedFabricSessionEpochV1::try_from_bytes([0x61; 16])
            .unwrap_or_else(|error| panic!("session epoch failed: {error:?}"));
        let first_binding = Digest32::from_bytes([0x71; 32]);
        let second_binding = Digest32::from_bytes([0x72; 32]);
        let snapshot = ValidatedExperimentalSnapshot {
            fabric_generation,
            session_epoch,
            peer_owner_facts: vec![
                ValidatedExperimentalPeerOwnerFacts {
                    identity_binding_digest: first_binding,
                    observation_sequence: 41,
                },
                ValidatedExperimentalPeerOwnerFacts {
                    identity_binding_digest: second_binding,
                    observation_sequence: 42,
                },
            ]
            .into_boxed_slice(),
        };

        assert_eq!(snapshot.fabric_generation, fabric_generation);
        assert_eq!(snapshot.session_epoch, session_epoch);
        assert_eq!(snapshot.peer_owner_facts.len(), 2);
        assert_eq!(
            snapshot.peer_owner_facts[0],
            ValidatedExperimentalPeerOwnerFacts {
                identity_binding_digest: first_binding,
                observation_sequence: 41,
            }
        );
        assert_eq!(
            snapshot.peer_owner_facts[1],
            ValidatedExperimentalPeerOwnerFacts {
                identity_binding_digest: second_binding,
                observation_sequence: 42,
            }
        );

        let decision = experimental_snapshot_success_decision(snapshot, 0x41);
        let selection = decision.receipt_selection(
            Digest32::from_bytes([0x51; 32]),
            Digest32::from_bytes([0x52; 32]),
        );

        assert_eq!(
            selection.outcome,
            DistributedAgentStackTerminalOutcomeV1::TerminalNonReady
        );
        assert!(selection.generations.fabric.is_none());
        assert!(selection.generations.agent.is_none());
        assert_eq!(selection.local_bindings.physical_binding_census, 0);
        assert!(!selection.local_bindings.census_complete);
        assert!(!selection.local_bindings.fabric_ready);
        assert!(!selection.local_bindings.agent_ready);
        assert!(!selection.local_bindings.dependency_satisfied);
        assert!(!selection.local_bindings.exact_zero);
        assert!(!selection.local_bindings.quarantined);
        assert!(decision.proofs.is_empty());
        assert_eq!(decision.raw_code, 0x41);
    }

    #[test]
    fn evidence_record_id_entropy_failure_and_zero_are_single_attempt_failures() {
        let failed_calls = Cell::new(0_u8);
        let failed = try_evidence_record_id_with(|_| {
            failed_calls.set(failed_calls.get() + 1);
            Err(())
        });
        assert!(matches!(
            failed,
            Err(DistributedAgentStackRuntimeError::EvidenceEntropyUnavailable)
        ));
        assert_eq!(failed_calls.get(), 1);

        let zero_calls = Cell::new(0_u8);
        let zero = try_evidence_record_id_with(|destination| {
            zero_calls.set(zero_calls.get() + 1);
            destination.fill(0);
            Ok(())
        });
        assert!(matches!(
            zero,
            Err(DistributedAgentStackRuntimeError::EvidenceEntropyUnavailable)
        ));
        assert_eq!(zero_calls.get(), 1);
    }

    #[test]
    fn evidence_and_runtime_owner_roots_must_be_disjoint() {
        let runtime = Path::new("/var/lib/paraegox/runtime-a");
        let evidence = Path::new("/var/lib/paraegox/evidence-a");
        assert!(evidence_paths_are_disjoint(runtime, evidence));
        assert!(!evidence_paths_are_disjoint(runtime, runtime));
        assert!(!evidence_paths_are_disjoint(
            runtime,
            Path::new("/var/lib/paraegox/runtime-a/evidence")
        ));
        assert!(!evidence_paths_are_disjoint(
            runtime,
            Path::new("/var/lib/paraegox")
        ));
    }

    #[test]
    fn overlapping_evidence_root_is_rejected_before_store_creation() {
        let fixture = persist_pending_fixture();
        let owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        let overlapping_root = fixture.directory.path().join("nested-evidence-store");
        assert!(!overlapping_root.exists());
        let mut config = distributed_owner_config(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        config.fabric_credential_resolver = Some(Arc::new(FailClosedEvidenceFixtureResolver));
        config.evidence_store_config = Some(
            DistributedAgentStackEvidenceStoreConfigV1::try_new(
                overlapping_root.clone(),
                EvidenceStoreEpochV1::try_from_bytes([0xa1; 16])
                    .unwrap_or_else(|error| panic!("Evidence epoch rejected: {error}")),
                EvidenceRetentionPolicyV1::try_new(64, 1024 * 1024)
                    .unwrap_or_else(|error| panic!("Evidence policy rejected: {error}")),
                EvidenceOwnerRefV1::try_from_bytes([0xa2; 16])
                    .unwrap_or_else(|error| panic!("Evidence owner rejected: {error}")),
            )
            .unwrap_or_else(|error| panic!("Evidence config rejected: {error}")),
        );
        assert!(matches!(
            DistributedAgentStackRuntimeCore::open(&owner, config),
            Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch)
        ));
        assert!(!overlapping_root.exists());
    }

    #[test]
    fn evidence_resolver_and_store_config_must_be_supplied_as_one_dependency() {
        let fixture = persist_pending_fixture();
        let owner = reopen_managed_owner(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );

        let mut resolver_only = distributed_owner_config(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        resolver_only.fabric_credential_resolver =
            Some(Arc::new(FailClosedEvidenceFixtureResolver));
        assert!(matches!(
            DistributedAgentStackRuntimeCore::open(&owner, resolver_only),
            Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch)
        ));

        let (evidence_directory, evidence_owner) =
            fresh_managed_owner(&fixture.projection, &fixture.request);
        drop(evidence_owner);
        let evidence_root = evidence_directory.path().join("dependency-pair-evidence");
        assert!(!evidence_root.exists());
        let mut config_only = distributed_owner_config(
            &fixture.directory,
            &fixture.projection,
            &fixture.request,
            INITIAL_RUNTIME_EPOCH + 1,
        );
        config_only.evidence_store_config = Some(
            DistributedAgentStackEvidenceStoreConfigV1::try_new(
                evidence_root.clone(),
                EvidenceStoreEpochV1::try_from_bytes([0xa3; 16])
                    .unwrap_or_else(|error| panic!("Evidence epoch rejected: {error}")),
                EvidenceRetentionPolicyV1::try_new(64, 1024 * 1024)
                    .unwrap_or_else(|error| panic!("Evidence policy rejected: {error}")),
                EvidenceOwnerRefV1::try_from_bytes([0xa4; 16])
                    .unwrap_or_else(|error| panic!("Evidence owner rejected: {error}")),
            )
            .unwrap_or_else(|error| panic!("Evidence config rejected: {error}")),
        );
        assert!(matches!(
            DistributedAgentStackRuntimeCore::open(&owner, config_only),
            Err(DistributedAgentStackRuntimeError::EvidenceConfigurationMismatch)
        ));
        assert!(!evidence_root.exists());
    }

    #[test]
    fn exact_pxtp_batch_is_written_reopened_and_read_back_byte_for_byte() {
        let projection = fixture_projection();
        let request = fixture_request();
        let owner_ref = evidence_owner_ref();
        let batch = fixture_evidence_batch(&request, generation(17));
        let (directory, managed_owner) = fresh_managed_owner(&projection, &request);
        drop(managed_owner);
        let config = DistributedAgentStackEvidenceStoreConfigV1::try_new(
            directory.path().join("distributed-evidence"),
            EvidenceStoreEpochV1::try_from_bytes([0x83; 16])
                .unwrap_or_else(|error| panic!("Evidence epoch rejected: {error}")),
            EvidenceRetentionPolicyV1::try_new(64, 1024 * 1024)
                .unwrap_or_else(|error| panic!("Evidence policy rejected: {error}")),
            owner_ref,
        )
        .unwrap_or_else(|error| panic!("Evidence config rejected: {error}"));
        let mut store = LocalEvidenceStoreV1::open(
            config.root(),
            config.store_epoch(),
            config.retention_policy(),
        )
        .unwrap_or_else(|error| panic!("Evidence store open failed: {error}"));
        let first = append_and_verify_evidence_batch(&mut store, &batch)
            .unwrap_or_else(|error| panic!("Evidence batch append failed: {error}"));
        assert_eq!(first.receipts.len(), batch.records().len());
        assert!(first.receipts.iter().all(|receipt| !receipt.replayed()));
        drop(store);

        let mut reopened = LocalEvidenceStoreV1::open(
            config.root(),
            config.store_epoch(),
            config.retention_policy(),
        )
        .unwrap_or_else(|error| panic!("Evidence store reopen failed: {error}"));
        for record in batch.records() {
            let stored = reopened
                .read(record.record_id())
                .unwrap_or_else(|error| panic!("Evidence readback failed: {error}"))
                .unwrap_or_else(|| panic!("Evidence record disappeared after reopen"));
            assert_eq!(stored.record(), record);
            assert_eq!(stored.record().canonical_wire(), record.canonical_wire());
        }
        let replay = append_and_verify_evidence_batch(&mut reopened, &batch)
            .unwrap_or_else(|error| panic!("Evidence replay failed: {error}"));
        assert!(replay.receipts.iter().all(|receipt| receipt.replayed()));
        drop(reopened);

        let tail = batch
            .records()
            .last()
            .unwrap_or_else(|| panic!("Evidence batch unexpectedly empty"));
        let head = DistributedAgentStackEvidenceOwnerHeadV2::try_new(
            tail.producer_sequence(),
            tail.record_id(),
            tail.record_digest(),
        )
        .unwrap_or_else(|error| panic!("Evidence owner head rejected: {error}"));
        let durable_state = DistributedAgentStackEvidenceStateV2::try_new(
            Some(config.binding()),
            Some(head),
            DistributedAgentStackEvidenceHandoffV2::None,
        )
        .unwrap_or_else(|error| panic!("Evidence durable state rejected: {error}"));
        let empty_durable_state = DistributedAgentStackEvidenceStateV2::try_new(
            Some(config.binding()),
            None,
            DistributedAgentStackEvidenceHandoffV2::None,
        )
        .unwrap_or_else(|error| panic!("empty Evidence state rejected: {error}"));
        let filled_store = LocalEvidenceStoreV1::open(
            config.root(),
            config.store_epoch(),
            config.retention_policy(),
        )
        .unwrap_or_else(|error| panic!("filled Evidence store reopen failed: {error}"));
        assert!(matches!(
            validate_opened_evidence_store(&empty_durable_state, &config, &filled_store),
            Err(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch)
        ));
        drop(filled_store);
        let alternate_config = DistributedAgentStackEvidenceStoreConfigV1::try_new(
            directory.path().join("alternate-distributed-evidence"),
            config.store_epoch(),
            config.retention_policy(),
            config.owner_ref(),
        )
        .unwrap_or_else(|error| panic!("alternate Evidence config rejected: {error}"));
        let alternate_store = LocalEvidenceStoreV1::open(
            alternate_config.root(),
            alternate_config.store_epoch(),
            alternate_config.retention_policy(),
        )
        .unwrap_or_else(|error| panic!("alternate Evidence store open failed: {error}"));
        assert!(matches!(
            validate_opened_evidence_store(&durable_state, &alternate_config, &alternate_store),
            Err(DistributedAgentStackRuntimeError::EvidenceReadbackMismatch)
        ));
    }
}
