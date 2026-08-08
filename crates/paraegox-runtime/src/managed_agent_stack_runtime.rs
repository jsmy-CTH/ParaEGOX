#![cfg(unix)]

//! RuntimeHost-owned PXAR-v7 Fabric→Agent durable apply owner.
//!
//! PXAS is an independent successor journal. The first intent is embedded in
//! the immutable PXSC cutover record, and every physical effect follows a
//! durable intent. The predecessor PXMS journal remains byte-compatible and is
//! used only as the lifecycle substrate for the already-admitted Fabric.

use core::fmt;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use ed25519_dalek::{Signature, Signer, SigningKey};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::time::ClockReading;
use paraegox_runtime_contracts::apply::ExpectedActive;
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DistributedAgentStackTerminalOutcomeV1, DistributedAgentStackTerminalReceiptV1,
    DistributedAgentStackTerminalReceiptV2,
};
use paraegox_runtime_contracts::managed_agent_stack_plan::{
    ManagedAgentStackApplyRequestV1, ManagedAgentStackPlanError, ManagedAgentStackProjectionV1,
    ManagedAgentStackTargetModeV1, ManagedAgentStackTerminalAuthClaimV1,
    ManagedAgentStackTerminalEvidenceFieldsV1, ManagedAgentStackTerminalEvidenceV1,
    ManagedAgentStackTerminalFactsV1, ManagedAgentStackTerminalHeadV1,
    ManagedAgentStackTerminalLifecycleEffectV1, ManagedAgentStackTerminalOutcomeV1,
    ManagedAgentStackTerminalReceiptDraftV1, ManagedAgentStackTerminalReceiptV1,
    ManagedAgentStackTerminalStateV1,
};
use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
    ManagedModelAgentStackTerminalOutcomeV1, ManagedModelAgentStackTerminalReceiptV1,
};
use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
use paraegox_runtime_contracts::managed_serving_bootstrap::RuntimeVerifiedHistoricalManagedAgentStackReceiptV1;
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

use crate::admission::{
    ED25519_ALGORITHM, ED25519_ALGORITHM_VERSION, VerifiedManagedAgentStackApplyIngressV1,
};
use crate::managed_agent_runtime::{
    ManagedAgentAssembly, ManagedAgentAssemblyConfig, ManagedAgentAssemblyError,
    RuntimeAgentConversationHandle,
};
use crate::managed_agent_stack_state::{
    ManagedAgentStackDurableActive, ManagedAgentStackDurablePending, ManagedAgentStackDurablePhase,
    ManagedAgentStackPendingKind, ManagedAgentStackReplayRecord,
    ManagedAgentStackRevisionHighWater, ManagedAgentStackSnapshot,
    ManagedAgentStackSnapshotTransition, ManagedAgentStackStateError,
    ManagedAgentStackTerminalRecord, ManagedAgentStackWriterFence,
};
use crate::managed_fabric_runtime::{
    ManagedFabricControlHandle, ManagedFabricRuntimeCore, ManagedFabricRuntimeError,
    ManagedFabricStackCutoverObservation,
};
use crate::runtime_agent_provider::{
    RuntimeAgentProviderResolverV1, RuntimeResolvedAgentProviderV1,
};
use crate::runtime_clock::{RuntimeClock, RuntimeClockError};

const STACK_PROJECTION_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-agent-stack-transition-projection.sha256.v1";
const STACK_RESOURCE_CENSUS_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-agent-stack-resource-census.sha256.v1";
const STACK_RAW_OUTCOME_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-agent-stack-raw-outcome.sha256.v1";
const STACK_QUARANTINE_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-agent-stack-quarantine.sha256.v1";
const MAX_STACK_REPLAY_RECORDS: usize = 256;

pub(crate) struct ManagedAgentStackOwnerConfig {
    pub(crate) state_directory: PathBuf,
    pub(crate) projection: ManagedAgentStackProjectionV1,
    pub(crate) runtime_host_epoch: u64,
    pub(crate) clock: RuntimeClock,
    pub(crate) response_key_ref: ApplyAuthKeyRef,
    pub(crate) response_signer: SigningKey,
    pub(crate) handle_broker: RuntimeAgentHandleBroker,
    pub(crate) provider_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
}

/// Process-local issuance point for opaque Agent conversation capabilities.
/// A handle appears only after its protocol-specific ActiveReady receipt is
/// durably published. A trusted restricted endpoint may attach one exact
/// PXDS-v2 alias to the currently published PXDS-v1 receipt; retirement or any
/// successor publication clears that alias.
#[derive(Clone, Default)]
pub(crate) struct RuntimeAgentHandleBroker {
    inner: Arc<RwLock<Option<PublishedRuntimeAgentHandle>>>,
}

struct PublishedRuntimeAgentHandle {
    handle: RuntimeAgentConversationHandle,
    committed_receipt_wire: Box<[u8]>,
    restricted_distributed_alias_wire: Option<Box<[u8]>>,
}

impl RuntimeAgentHandleBroker {
    pub(crate) fn try_acquire(&self) -> Option<RuntimeAgentConversationHandle> {
        self.inner
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|published| published.handle.clone()))
    }

    pub(crate) fn try_claim(
        &self,
        committed_receipt_wire: &[u8],
    ) -> Result<Option<RuntimeAgentConversationHandle>, ManagedAgentStackRuntimeError> {
        let receipt = ManagedAgentStackTerminalReceiptV1::decode(committed_receipt_wire)
            .map_err(|_| ManagedAgentStackRuntimeError::RequestRejected)?;
        if receipt.facts().state().outcome() != ManagedAgentStackTerminalOutcomeV1::ActiveReady {
            return Err(ManagedAgentStackRuntimeError::RequestRejected);
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| ManagedAgentStackRuntimeError::HandleBrokerUnavailable)?;
        Ok(guard.as_ref().and_then(|published| {
            (published.committed_receipt_wire.as_ref() == committed_receipt_wire)
                .then(|| published.handle.clone())
        }))
    }

    pub(crate) fn try_claim_distributed(
        &self,
        committed_receipt_wire: &[u8],
    ) -> Result<Option<RuntimeAgentConversationHandle>, ManagedAgentStackRuntimeError> {
        let receipt = DistributedAgentStackTerminalReceiptV1::decode(committed_receipt_wire)
            .map_err(|_| ManagedAgentStackRuntimeError::RequestRejected)?;
        if receipt.facts().outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady {
            return Err(ManagedAgentStackRuntimeError::RequestRejected);
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| ManagedAgentStackRuntimeError::HandleBrokerUnavailable)?;
        Ok(guard.as_ref().and_then(|published| {
            (published.committed_receipt_wire.as_ref() == committed_receipt_wire)
                .then(|| published.handle.clone())
        }))
    }

    pub(crate) fn try_claim_restricted_distributed(
        &self,
        committed_receipt_wire: &[u8],
    ) -> Result<Option<RuntimeAgentConversationHandle>, ManagedAgentStackRuntimeError> {
        let receipt = DistributedAgentStackTerminalReceiptV2::decode(committed_receipt_wire)
            .map_err(|_| ManagedAgentStackRuntimeError::RequestRejected)?;
        if receipt.facts().outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady {
            return Err(ManagedAgentStackRuntimeError::RequestRejected);
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| ManagedAgentStackRuntimeError::HandleBrokerUnavailable)?;
        Ok(guard.as_ref().and_then(|published| {
            published
                .restricted_distributed_alias_wire
                .as_deref()
                .is_some_and(|alias| alias == committed_receipt_wire)
                .then(|| published.handle.clone())
        }))
    }

    pub(crate) fn try_claim_model_agent(
        &self,
        committed_receipt_wire: &[u8],
    ) -> Result<Option<RuntimeAgentConversationHandle>, ManagedAgentStackRuntimeError> {
        let receipt = ManagedModelAgentStackTerminalReceiptV1::decode(committed_receipt_wire)
            .map_err(|_| ManagedAgentStackRuntimeError::RequestRejected)?;
        if receipt.facts().state().outcome() != ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
        {
            return Err(ManagedAgentStackRuntimeError::RequestRejected);
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| ManagedAgentStackRuntimeError::HandleBrokerUnavailable)?;
        Ok(guard.as_ref().and_then(|published| {
            (published.committed_receipt_wire.as_ref() == committed_receipt_wire)
                .then(|| published.handle.clone())
        }))
    }

    fn publish(
        &self,
        handle: RuntimeAgentConversationHandle,
        receipt: &ManagedAgentStackTerminalReceiptV1,
    ) -> Result<(), ManagedAgentStackRuntimeError> {
        if receipt.facts().state().outcome() != ManagedAgentStackTerminalOutcomeV1::ActiveReady {
            return Err(ManagedAgentStackRuntimeError::InvalidDurableState);
        }
        *self
            .inner
            .write()
            .map_err(|_| ManagedAgentStackRuntimeError::HandleBrokerUnavailable)? =
            Some(PublishedRuntimeAgentHandle {
                handle,
                committed_receipt_wire: receipt.canonical_wire().into(),
                restricted_distributed_alias_wire: None,
            });
        Ok(())
    }

    pub(crate) fn publish_distributed(
        &self,
        handle: RuntimeAgentConversationHandle,
        receipt: &DistributedAgentStackTerminalReceiptV1,
    ) -> Result<(), ManagedAgentStackRuntimeError> {
        if receipt.facts().outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady {
            return Err(ManagedAgentStackRuntimeError::InvalidDurableState);
        }
        *self
            .inner
            .write()
            .map_err(|_| ManagedAgentStackRuntimeError::HandleBrokerUnavailable)? =
            Some(PublishedRuntimeAgentHandle {
                handle,
                committed_receipt_wire: receipt.canonical_wire().into(),
                restricted_distributed_alias_wire: None,
            });
        Ok(())
    }

    pub(crate) fn register_restricted_distributed_alias(
        &self,
        committed_inner_receipt_wire: &[u8],
        committed_outer_receipt_wire: &[u8],
    ) -> Result<(), ManagedAgentStackRuntimeError> {
        let inner = DistributedAgentStackTerminalReceiptV1::decode(committed_inner_receipt_wire)
            .map_err(|_| ManagedAgentStackRuntimeError::RequestRejected)?;
        let outer = DistributedAgentStackTerminalReceiptV2::decode(committed_outer_receipt_wire)
            .map_err(|_| ManagedAgentStackRuntimeError::RequestRejected)?;
        if inner.facts().outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady
            || outer.facts().outcome() != DistributedAgentStackTerminalOutcomeV1::ActiveReady
            || inner.facts() != outer.facts()
        {
            return Err(ManagedAgentStackRuntimeError::RequestRejected);
        }
        // Both strict decoders reconstruct their canonical frame and compare
        // it byte-for-byte with the input. The shared typed facts equality
        // therefore also proves equality of their canonical facts bytes; no
        // PXDS2-to-PXDS1 reconstruction is involved here.
        let mut guard = self
            .inner
            .write()
            .map_err(|_| ManagedAgentStackRuntimeError::HandleBrokerUnavailable)?;
        let published = guard
            .as_mut()
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
        if published.committed_receipt_wire.as_ref() != committed_inner_receipt_wire {
            return Err(ManagedAgentStackRuntimeError::InvalidDurableState);
        }
        match published.restricted_distributed_alias_wire.as_deref() {
            None => {
                published.restricted_distributed_alias_wire =
                    Some(committed_outer_receipt_wire.into());
                Ok(())
            }
            Some(alias) if alias == committed_outer_receipt_wire => Ok(()),
            Some(_) => Err(ManagedAgentStackRuntimeError::InvalidDurableState),
        }
    }

    pub(crate) fn publish_model_agent(
        &self,
        handle: RuntimeAgentConversationHandle,
        receipt: &ManagedModelAgentStackTerminalReceiptV1,
    ) -> Result<(), ManagedAgentStackRuntimeError> {
        if receipt.facts().state().outcome() != ManagedModelAgentStackTerminalOutcomeV1::ActiveReady
        {
            return Err(ManagedAgentStackRuntimeError::InvalidDurableState);
        }
        *self
            .inner
            .write()
            .map_err(|_| ManagedAgentStackRuntimeError::HandleBrokerUnavailable)? =
            Some(PublishedRuntimeAgentHandle {
                handle,
                committed_receipt_wire: receipt.canonical_wire().into(),
                restricted_distributed_alias_wire: None,
            });
        Ok(())
    }

    pub(crate) fn revoke(&self) -> Result<(), ManagedAgentStackRuntimeError> {
        *self
            .inner
            .write()
            .map_err(|_| ManagedAgentStackRuntimeError::HandleBrokerUnavailable)? = None;
        Ok(())
    }
}

pub(crate) struct ManagedAgentStackRuntimeCore {
    snapshot: ManagedAgentStackSnapshot,
    projection: ManagedAgentStackProjectionV1,
    state_directory: PathBuf,
    runtime_host_epoch: u64,
    clock: RuntimeClock,
    response_key_ref: ApplyAuthKeyRef,
    response_signer: SigningKey,
    assembly: Option<ManagedAgentAssembly>,
    handle: Option<RuntimeAgentConversationHandle>,
    handle_broker: RuntimeAgentHandleBroker,
    provider_resolver: Arc<dyn RuntimeAgentProviderResolverV1>,
    recovery_completed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAgentStackDistributedCutoverObservation {
    pub(crate) execution:
        paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentStackTargetExecutionV1,
    pub(crate) target_slice_digest: paraegox_runtime_contracts::provenance::TargetSliceDigest,
    pub(crate) fabric_generation: ManagedServiceGeneration,
    pub(crate) agent_generation: ManagedServiceGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedAgentStackApplyOutcome {
    Committed(ManagedAgentStackTerminalReceiptV1),
    Replayed(ManagedAgentStackTerminalReceiptV1),
    HistoricalReplayed(RuntimeVerifiedHistoricalManagedAgentStackReceiptV1),
}

/// One bootstrap-only snapshot of the exact currently published Agent port.
pub(crate) struct RuntimeAgentConversationPortExportV1 {
    pub(crate) descriptor_wire: Box<[u8]>,
    pub(crate) fabric_generation: ManagedServiceGeneration,
    pub(crate) agent_generation: ManagedServiceGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeAgentConversationPortExportErrorV1 {
    ExpectedActiveReceiptMismatch,
    OwnerUnavailable,
    InternalInvariant,
}

#[derive(Clone, Copy)]
struct TerminalSelection {
    outcome: ManagedAgentStackTerminalOutcomeV1,
    lifecycle_effect: ManagedAgentStackTerminalLifecycleEffectV1,
    head: ManagedAgentStackTerminalHeadV1,
    fabric_generation: Option<ManagedServiceGeneration>,
    agent_generation: Option<ManagedServiceGeneration>,
    physical_binding_census: u16,
    census_complete: bool,
    fabric_ready: bool,
    agent_ready: bool,
    dependency_satisfied: bool,
    exact_zero: bool,
    quarantined: bool,
    raw_code: u16,
    raw_context: Option<Digest32>,
}

impl ManagedAgentStackRuntimeCore {
    pub(crate) fn open(
        fabric: &ManagedFabricRuntimeCore,
        config: ManagedAgentStackOwnerConfig,
    ) -> Result<Option<Self>, ManagedAgentStackRuntimeError> {
        let projection_digest = stack_projection_digest(&config.projection)?;
        let Some(stored_projection_digest) = fabric.managed_agent_stack_projection_digest() else {
            if fabric.managed_agent_stack_snapshot_bytes()?.is_some() {
                return Err(ManagedAgentStackRuntimeError::InvalidDurableState);
            }
            return Ok(None);
        };
        if stored_projection_digest != projection_digest {
            return Err(ManagedAgentStackRuntimeError::ProjectionMismatch);
        }
        let frame = fabric
            .managed_agent_stack_snapshot_bytes()?
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
        let snapshot = ManagedAgentStackSnapshot::decode(
            frame,
            fabric.store_instance_id(),
            fabric.owner_target_fingerprint(),
            projection_digest,
            &config.projection,
        )?;
        if config.runtime_host_epoch == 0
            || config.runtime_host_epoch <= snapshot.runtime_host_epoch()
            || config.clock.generation().value() == 0
        {
            return Err(ManagedAgentStackRuntimeError::RuntimeEpochRegressed);
        }
        Ok(Some(Self {
            snapshot,
            projection: config.projection,
            state_directory: config.state_directory,
            runtime_host_epoch: config.runtime_host_epoch,
            clock: config.clock,
            response_key_ref: config.response_key_ref,
            response_signer: config.response_signer,
            assembly: None,
            handle: None,
            handle_broker: config.handle_broker,
            provider_resolver: config.provider_resolver,
            recovery_completed: false,
        }))
    }

    pub(crate) fn requires_predecessor_recovery(&self) -> bool {
        matches!(
            self.snapshot.phase,
            ManagedAgentStackDurablePhase::AgentStartIntent
                | ManagedAgentStackDurablePhase::ActiveReady
                | ManagedAgentStackDurablePhase::RecoveryIntent
        )
    }

    pub(crate) fn distributed_cutover_observation(
        &self,
    ) -> Result<ManagedAgentStackDistributedCutoverObservation, ManagedAgentStackRuntimeError> {
        if !self.recovery_completed
            || self.snapshot.phase != ManagedAgentStackDurablePhase::ActiveReady
            || self.assembly.is_none()
            || self.handle.is_none()
        {
            return Err(ManagedAgentStackRuntimeError::RecoveryNotCompleted);
        }
        let active = self
            .snapshot
            .active
            .as_ref()
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
        Ok(ManagedAgentStackDistributedCutoverObservation {
            execution: active.request.target_execution().clone(),
            target_slice_digest: active.request.target_slice_digest(),
            fabric_generation: active.fabric_generation,
            agent_generation: active.agent_generation,
        })
    }

    /// Exports a PXAP only from the intersection of durable ActiveReady,
    /// complete two-binding census, the exact currently brokered PXST root,
    /// and this core's live assembly/handle. The terminal receipt generation
    /// is deliberately not compared with the current physical generations:
    /// restart recovery may retain exact PXST bytes while rebuilding both live
    /// generations.
    pub(crate) async fn export_active_conversation_port_v1(
        &self,
        expected_active_pxst_digest: Digest32,
    ) -> Result<RuntimeAgentConversationPortExportV1, RuntimeAgentConversationPortExportErrorV1>
    {
        if !self.recovery_completed
            || self.snapshot.phase != ManagedAgentStackDurablePhase::ActiveReady
        {
            return Err(RuntimeAgentConversationPortExportErrorV1::OwnerUnavailable);
        }
        if self.snapshot.physical_binding_census != 2
            || !self.snapshot.census_complete
            || !self.snapshot.fabric_ready
            || !self.snapshot.agent_ready
            || !self.snapshot.dependency_satisfied
        {
            return Err(RuntimeAgentConversationPortExportErrorV1::InternalInvariant);
        }
        let active = self
            .snapshot
            .active
            .as_ref()
            .ok_or(RuntimeAgentConversationPortExportErrorV1::InternalInvariant)?;
        let receipt = self
            .active_terminal_receipt()
            .map_err(|_| RuntimeAgentConversationPortExportErrorV1::InternalInvariant)?;
        if receipt.facts().state().outcome() != ManagedAgentStackTerminalOutcomeV1::ActiveReady {
            return Err(RuntimeAgentConversationPortExportErrorV1::InternalInvariant);
        }
        if receipt.receipt_digest() != expected_active_pxst_digest {
            return Err(RuntimeAgentConversationPortExportErrorV1::ExpectedActiveReceiptMismatch);
        }
        let broker_handle = self
            .handle_broker
            .try_claim(receipt.canonical_wire())
            .map_err(|_| RuntimeAgentConversationPortExportErrorV1::InternalInvariant)?
            .ok_or(RuntimeAgentConversationPortExportErrorV1::InternalInvariant)?;
        let owner_handle = self
            .handle
            .as_ref()
            .ok_or(RuntimeAgentConversationPortExportErrorV1::InternalInvariant)?;
        let assembly = self
            .assembly
            .as_ref()
            .ok_or(RuntimeAgentConversationPortExportErrorV1::InternalInvariant)?;
        let descriptor_wire = assembly
            .export_live_conversation_port_descriptor_v1(
                owner_handle,
                &broker_handle,
                active.fabric_generation,
            )
            .await
            .map_err(|_| RuntimeAgentConversationPortExportErrorV1::InternalInvariant)?;
        Ok(RuntimeAgentConversationPortExportV1 {
            descriptor_wire,
            fabric_generation: active.fabric_generation,
            agent_generation: active.agent_generation,
        })
    }

    pub(crate) async fn cutover(
        fabric: &mut ManagedFabricRuntimeCore,
        config: ManagedAgentStackOwnerConfig,
        request: ManagedAgentStackApplyRequestV1,
        verified: VerifiedManagedAgentStackApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<(Self, ManagedAgentStackApplyOutcome), ManagedAgentStackRuntimeError> {
        if fabric.managed_agent_stack_projection_digest().is_some()
            || request.target_execution().mode() != ManagedAgentStackTargetModeV1::FabricAndAgent
            || request.target_execution().projection() != &config.projection
            || request.target() != config.projection.target()
            || request.expected_runtime_store_instance_id() != fabric.store_instance_id()
            || response_channel.target() != request.target()
        {
            return Err(ManagedAgentStackRuntimeError::RequestRejected);
        }
        let provider = request
            .target_execution()
            .agent()
            .ok_or(ManagedAgentStackRuntimeError::RequestRejected)?
            .provider();
        let prepared_provider =
            prepare_agent_provider(provider, config.provider_resolver.as_ref())?;
        observe_deadline(config.clock, verified)?;
        let predecessor = fabric.stack_cutover_observation().await?;
        validate_cutover_cas_and_fabric(&request, &predecessor)?;
        let agent_generation = ManagedServiceGeneration::try_new(1)
            .map_err(|_| ManagedAgentStackRuntimeError::GenerationExhausted)?;
        let transition = initial_intent_transition(
            &request,
            verified,
            response_channel,
            predecessor.generation,
            agent_generation,
        )?;
        let projection_digest = stack_projection_digest(&config.projection)?;
        let snapshot = ManagedAgentStackSnapshot::try_initial(
            fabric.store_instance_id(),
            fabric.owner_target_fingerprint(),
            projection_digest,
            config.runtime_host_epoch,
            transition,
            &config.projection,
        )?;
        fabric.initialize_managed_agent_stack(projection_digest, snapshot.canonical_wire())?;
        let mut core = Self {
            snapshot,
            projection: config.projection,
            state_directory: config.state_directory,
            runtime_host_epoch: config.runtime_host_epoch,
            clock: config.clock,
            response_key_ref: config.response_key_ref,
            response_signer: config.response_signer,
            assembly: None,
            handle: None,
            handle_broker: config.handle_broker,
            provider_resolver: config.provider_resolver,
            recovery_completed: true,
        };
        let started = core
            .start_agent(
                predecessor.control,
                request.target_execution(),
                prepared_provider,
            )
            .await;
        if let Err(error) = started {
            let receipt = core
                .quarantine_activation(fabric, &request, response_channel, 30, &error)
                .await?;
            return Ok((core, ManagedAgentStackApplyOutcome::Committed(receipt)));
        }
        let mut ready = core.snapshot.transition();
        ready.phase = ManagedAgentStackDurablePhase::ActiveReady;
        ready.active = Some(ManagedAgentStackDurableActive {
            fabric_generation: predecessor.generation,
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
        ready.quarantine_reason = None;
        let receipt = core.build_terminal(
            &request,
            response_channel,
            TerminalSelection {
                outcome: ManagedAgentStackTerminalOutcomeV1::ActiveReady,
                lifecycle_effect: ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                head: ManagedAgentStackTerminalHeadV1::CommittedIncoming,
                fabric_generation: Some(predecessor.generation),
                agent_generation: Some(agent_generation),
                physical_binding_census: 2,
                census_complete: true,
                fabric_ready: true,
                agent_ready: true,
                dependency_satisfied: true,
                exact_zero: false,
                quarantined: false,
                raw_code: 1,
                raw_context: None,
            },
        )?;
        insert_terminal(&mut ready.terminals, &request, receipt.clone())?;
        if let Err(error) = core.commit_transition(fabric, ready) {
            let _ = core.shutdown_agent().await;
            return Err(error);
        }
        core.publish_handle(&receipt)?;
        Ok((core, ManagedAgentStackApplyOutcome::Committed(receipt)))
    }

    pub(crate) async fn recover(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
    ) -> Result<(), ManagedAgentStackRuntimeError> {
        if self.recovery_completed || self.assembly.is_some() || self.handle.is_some() {
            return if self.recovery_completed {
                Ok(())
            } else {
                Err(ManagedAgentStackRuntimeError::RecoveryWhileLive)
            };
        }
        self.handle_broker.revoke()?;
        match self.snapshot.phase {
            ManagedAgentStackDurablePhase::ExactZero => {
                if self.snapshot.runtime_host_epoch() != self.runtime_host_epoch {
                    self.commit_transition(fabric, self.snapshot.transition())?;
                }
                self.recovery_completed = true;
                return Ok(());
            }
            ManagedAgentStackDurablePhase::AgentRetireIntent
            | ManagedAgentStackDurablePhase::FabricStopIntent => {
                return self.recover_deactivation(fabric).await;
            }
            ManagedAgentStackDurablePhase::Quarantined
            | ManagedAgentStackDurablePhase::Uncertain => {
                return Err(ManagedAgentStackRuntimeError::RecoveryQuarantined);
            }
            ManagedAgentStackDurablePhase::AgentStartIntent
            | ManagedAgentStackDurablePhase::ActiveReady
            | ManagedAgentStackDurablePhase::RecoveryIntent => {}
        }
        let (request, response_channel) = match self.snapshot.phase {
            ManagedAgentStackDurablePhase::ActiveReady => {
                let active = self
                    .snapshot
                    .active
                    .as_ref()
                    .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
                (active.request.clone(), active.response_channel)
            }
            _ => {
                let pending = self
                    .snapshot
                    .pending
                    .as_ref()
                    .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
                (pending.request.clone(), pending.response_channel)
            }
        };
        let provider = request
            .target_execution()
            .agent()
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?
            .provider();
        let prepared_provider = prepare_agent_provider(provider, self.provider_resolver.as_ref())?;
        let predecessor = fabric.stack_cutover_observation().await?;
        if predecessor.execution != *request.target_execution().fabric() {
            return Err(ManagedAgentStackRuntimeError::FabricChangeRequiresEmpty);
        }
        let agent_generation = next_generation(self.snapshot.agent_generation_high_water)?;
        let reading = self.clock.reading()?;
        let deadline_nanos = recovery_deadline(&request, reading)?;
        let mut intent = self.snapshot.transition();
        intent.fabric_generation_high_water = intent
            .fabric_generation_high_water
            .max(predecessor.generation.value());
        intent.agent_generation_high_water = agent_generation.value();
        intent.phase = ManagedAgentStackDurablePhase::RecoveryIntent;
        intent.pending = Some(ManagedAgentStackDurablePending {
            kind: ManagedAgentStackPendingKind::RecoverActive,
            fabric_generation: Some(predecessor.generation),
            agent_generation: Some(agent_generation),
            admitted_clock_generation: reading.generation(),
            admitted_at_nanos: reading.now().value(),
            deadline_nanos,
            response_channel,
            request: request.clone(),
        });
        intent.physical_binding_census = 0;
        intent.census_complete = true;
        intent.fabric_ready = true;
        intent.agent_ready = false;
        intent.dependency_satisfied = true;
        intent.quarantine_reason = None;
        self.commit_transition(fabric, intent)?;
        if let Err(error) = self
            .start_agent(
                predecessor.control,
                request.target_execution(),
                prepared_provider,
            )
            .await
        {
            let _ = self
                .quarantine_activation(fabric, &request, response_channel, 40, &error)
                .await?;
            return Err(ManagedAgentStackRuntimeError::RecoveryQuarantined);
        }
        let mut ready = self.snapshot.transition();
        ready.phase = ManagedAgentStackDurablePhase::ActiveReady;
        ready.active = Some(ManagedAgentStackDurableActive {
            fabric_generation: predecessor.generation,
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
        ready.quarantine_reason = None;
        if self.lookup_terminal(&request, response_channel)?.is_none() {
            let receipt = self.build_terminal(
                &request,
                response_channel,
                TerminalSelection {
                    outcome: ManagedAgentStackTerminalOutcomeV1::ActiveReady,
                    lifecycle_effect: ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                    head: ManagedAgentStackTerminalHeadV1::CommittedIncoming,
                    fabric_generation: Some(predecessor.generation),
                    agent_generation: Some(agent_generation),
                    physical_binding_census: 2,
                    census_complete: true,
                    fabric_ready: true,
                    agent_ready: true,
                    dependency_satisfied: true,
                    exact_zero: false,
                    quarantined: false,
                    raw_code: 41,
                    raw_context: None,
                },
            )?;
            insert_terminal(&mut ready.terminals, &request, receipt)?;
        }
        if let Err(error) = self.commit_transition(fabric, ready) {
            let _ = self.shutdown_agent().await;
            return Err(error);
        }
        let receipt = self.active_terminal_receipt()?;
        self.publish_handle(&receipt)?;
        self.recovery_completed = true;
        Ok(())
    }

    async fn recover_deactivation(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
    ) -> Result<(), ManagedAgentStackRuntimeError> {
        let pending = self
            .snapshot
            .pending
            .clone()
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
        if pending.kind != ManagedAgentStackPendingKind::DeactivateStack
            || pending.request.target_execution().mode()
                != ManagedAgentStackTargetModeV1::EmptyDeactivate
        {
            return Err(ManagedAgentStackRuntimeError::InvalidDurableState);
        }
        let mut exact_zero = self.snapshot.transition();
        exact_zero.phase = ManagedAgentStackDurablePhase::ExactZero;
        exact_zero.active = None;
        exact_zero.pending = None;
        exact_zero.physical_binding_census = 0;
        exact_zero.census_complete = true;
        exact_zero.fabric_ready = false;
        exact_zero.agent_ready = false;
        exact_zero.dependency_satisfied = false;
        exact_zero.quarantine_reason = None;
        if self
            .lookup_terminal(&pending.request, pending.response_channel)?
            .is_none()
        {
            let receipt = self.build_terminal(
                &pending.request,
                pending.response_channel,
                TerminalSelection {
                    outcome: ManagedAgentStackTerminalOutcomeV1::EmptyExactZero,
                    lifecycle_effect: ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                    head: ManagedAgentStackTerminalHeadV1::CommittedIncoming,
                    fabric_generation: None,
                    agent_generation: None,
                    physical_binding_census: 0,
                    census_complete: true,
                    fabric_ready: false,
                    agent_ready: false,
                    dependency_satisfied: false,
                    exact_zero: true,
                    quarantined: false,
                    raw_code: 42,
                    raw_context: None,
                },
            )?;
            insert_terminal(&mut exact_zero.terminals, &pending.request, receipt)?;
        }
        self.commit_transition(fabric, exact_zero)?;
        self.recovery_completed = true;
        Ok(())
    }

    pub(crate) fn authenticated_terminal_replay(
        &self,
        request: &ManagedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<Option<ManagedAgentStackApplyOutcome>, ManagedAgentStackRuntimeError> {
        self.validate_request(request, response_channel)?;
        let Some(record) = self.terminal_record(request)? else {
            return Ok(None);
        };
        let completion_runtime_host_epoch = record
            .receipt
            .facts()
            .evidence()
            .fields()
            .completion_runtime_host_epoch;
        if completion_runtime_host_epoch == self.runtime_host_epoch
            && record
                .receipt
                .validate_against_request(request, response_channel)
                .is_ok()
        {
            return Ok(Some(ManagedAgentStackApplyOutcome::Replayed(
                record.receipt.clone(),
            )));
        }
        let verified = RuntimeVerifiedHistoricalManagedAgentStackReceiptV1::try_verify(
            request,
            self.runtime_host_epoch,
            record.receipt.clone(),
            |key, algorithm, version, transcript, signature| {
                if key != self.response_key_ref
                    || algorithm.value() != ED25519_ALGORITHM
                    || version != ED25519_ALGORITHM_VERSION
                {
                    return false;
                }
                let Ok(signature) = Signature::from_slice(signature) else {
                    return false;
                };
                self.response_signer
                    .verifying_key()
                    .verify_strict(transcript, &signature)
                    .is_ok()
            },
        )
        .map_err(|_| ManagedAgentStackRuntimeError::TerminalCorrelation)?;
        Ok(Some(ManagedAgentStackApplyOutcome::HistoricalReplayed(
            verified,
        )))
    }

    pub(crate) async fn apply(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: ManagedAgentStackApplyRequestV1,
        verified: VerifiedManagedAgentStackApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<ManagedAgentStackApplyOutcome, ManagedAgentStackRuntimeError> {
        if !self.recovery_completed {
            return Err(ManagedAgentStackRuntimeError::RecoveryNotCompleted);
        }
        self.validate_request(&request, response_channel)?;
        if let Some(receipt) = self.lookup_terminal(&request, response_channel)? {
            return Ok(ManagedAgentStackApplyOutcome::Replayed(receipt));
        }
        if !matches!(
            self.snapshot.phase,
            ManagedAgentStackDurablePhase::ActiveReady | ManagedAgentStackDurablePhase::ExactZero
        ) {
            return Err(ManagedAgentStackRuntimeError::RecoveryRequired);
        }
        if observe_deadline(self.clock, verified).is_err() {
            return self
                .terminalize_no_effect(fabric, request, response_channel, 10)
                .map(ManagedAgentStackApplyOutcome::Committed);
        }
        let mut transition = match self.admit_transition(&request, verified) {
            Ok(transition) => transition,
            Err(
                ManagedAgentStackRuntimeError::ExpectedActiveMismatch
                | ManagedAgentStackRuntimeError::StaleWriter
                | ManagedAgentStackRuntimeError::StaleRevision,
            ) => {
                return self
                    .terminalize_no_effect(fabric, request, response_channel, 11)
                    .map(ManagedAgentStackApplyOutcome::Committed);
            }
            Err(error) => return Err(error),
        };
        match request.target_execution().mode() {
            ManagedAgentStackTargetModeV1::FabricAndAgent => self
                .terminalize_no_effect(fabric, request, response_channel, 12)
                .map(ManagedAgentStackApplyOutcome::Committed),
            ManagedAgentStackTargetModeV1::EmptyDeactivate => {
                self.apply_empty(fabric, request, verified, response_channel, &mut transition)
                    .await
            }
        }
    }

    async fn apply_empty(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: ManagedAgentStackApplyRequestV1,
        verified: VerifiedManagedAgentStackApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
        transition: &mut ManagedAgentStackSnapshotTransition,
    ) -> Result<ManagedAgentStackApplyOutcome, ManagedAgentStackRuntimeError> {
        if self.snapshot.active.is_none() {
            return self
                .terminalize_no_effect(fabric, request, response_channel, 20)
                .map(ManagedAgentStackApplyOutcome::Committed);
        }
        transition.phase = ManagedAgentStackDurablePhase::AgentRetireIntent;
        transition.pending = Some(ManagedAgentStackDurablePending {
            kind: ManagedAgentStackPendingKind::DeactivateStack,
            fabric_generation: self
                .snapshot
                .active
                .as_ref()
                .map(|active| active.fabric_generation),
            agent_generation: self
                .snapshot
                .active
                .as_ref()
                .map(|active| active.agent_generation),
            admitted_clock_generation: verified.clock_generation(),
            admitted_at_nanos: verified.admitted_at_nanos(),
            deadline_nanos: verified.deadline_nanos(),
            response_channel,
            request: request.clone(),
        });
        transition.quarantine_reason = None;
        self.commit_transition(fabric, transition.clone())?;
        self.handle_broker.revoke()?;
        self.handle = None;
        if let Err(error) = self.shutdown_agent().await {
            let reason = quarantine_reason_digest(50, &request, Some(&error))?;
            let mut uncertain = self.snapshot.transition();
            uncertain.phase = ManagedAgentStackDurablePhase::Uncertain;
            uncertain.census_complete = false;
            uncertain.agent_ready = false;
            uncertain.dependency_satisfied = false;
            uncertain.quarantine_reason = Some(reason);
            self.commit_transition(fabric, uncertain)?;
            return Err(ManagedAgentStackRuntimeError::Agent(error));
        }
        let mut stop_intent = self.snapshot.transition();
        stop_intent.phase = ManagedAgentStackDurablePhase::FabricStopIntent;
        stop_intent.physical_binding_census = 0;
        stop_intent.census_complete = true;
        stop_intent.agent_ready = false;
        stop_intent.dependency_satisfied = false;
        self.commit_transition(fabric, stop_intent)?;
        if !fabric.stop_live_for_stack().await? {
            let reason = quarantine_reason_digest(51, &request, None)?;
            let mut uncertain = self.snapshot.transition();
            uncertain.phase = ManagedAgentStackDurablePhase::Uncertain;
            uncertain.census_complete = false;
            uncertain.fabric_ready = false;
            uncertain.quarantine_reason = Some(reason);
            self.commit_transition(fabric, uncertain)?;
            return Err(ManagedAgentStackRuntimeError::ShutdownUncertain);
        }
        let mut exact_zero = self.snapshot.transition();
        exact_zero.phase = ManagedAgentStackDurablePhase::ExactZero;
        exact_zero.active = None;
        exact_zero.pending = None;
        exact_zero.physical_binding_census = 0;
        exact_zero.census_complete = true;
        exact_zero.fabric_ready = false;
        exact_zero.agent_ready = false;
        exact_zero.dependency_satisfied = false;
        exact_zero.quarantine_reason = None;
        let receipt = self.build_terminal(
            &request,
            response_channel,
            TerminalSelection {
                outcome: ManagedAgentStackTerminalOutcomeV1::EmptyExactZero,
                lifecycle_effect: ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                head: ManagedAgentStackTerminalHeadV1::CommittedIncoming,
                fabric_generation: None,
                agent_generation: None,
                physical_binding_census: 0,
                census_complete: true,
                fabric_ready: false,
                agent_ready: false,
                dependency_satisfied: false,
                exact_zero: true,
                quarantined: false,
                raw_code: 2,
                raw_context: None,
            },
        )?;
        insert_terminal(&mut exact_zero.terminals, &request, receipt.clone())?;
        self.commit_transition(fabric, exact_zero)?;
        Ok(ManagedAgentStackApplyOutcome::Committed(receipt))
    }

    fn terminalize_no_effect(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: ManagedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        raw_code: u16,
    ) -> Result<ManagedAgentStackTerminalReceiptV1, ManagedAgentStackRuntimeError> {
        let active = self.snapshot.active.as_ref();
        let (
            head,
            fabric_generation,
            agent_generation,
            physical_binding_census,
            fabric_ready,
            agent_ready,
            dependency_satisfied,
            exact_zero,
        ) = active.map_or(
            (
                ManagedAgentStackTerminalHeadV1::PreservedNone,
                None,
                None,
                0,
                false,
                false,
                false,
                true,
            ),
            |active| {
                (
                    ManagedAgentStackTerminalHeadV1::PreservedExisting(
                        active.request.target_slice_digest(),
                    ),
                    Some(active.fabric_generation),
                    Some(active.agent_generation),
                    2,
                    true,
                    true,
                    true,
                    false,
                )
            },
        );
        let receipt = self.build_terminal(
            &request,
            response_channel,
            TerminalSelection {
                outcome: ManagedAgentStackTerminalOutcomeV1::NoEffectRejected,
                lifecycle_effect: ManagedAgentStackTerminalLifecycleEffectV1::ProvenNotStarted,
                head,
                fabric_generation,
                agent_generation,
                physical_binding_census,
                census_complete: true,
                fabric_ready,
                agent_ready,
                dependency_satisfied,
                exact_zero,
                quarantined: false,
                raw_code,
                raw_context: None,
            },
        )?;
        let mut transition = self.snapshot.transition();
        insert_terminal(&mut transition.terminals, &request, receipt.clone())?;
        self.commit_transition(fabric, transition)?;
        Ok(receipt)
    }

    async fn quarantine_activation(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: &ManagedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        raw_code: u16,
        error: &ManagedAgentAssemblyError,
    ) -> Result<ManagedAgentStackTerminalReceiptV1, ManagedAgentStackRuntimeError> {
        self.handle_broker.revoke()?;
        self.handle = None;
        let reason = quarantine_reason_digest(raw_code, request, Some(error))?;
        let pending = self
            .snapshot
            .pending
            .as_ref()
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
        let fabric_generation = pending
            .fabric_generation
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
        let agent_generation = pending
            .agent_generation
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
        let receipt = self.build_terminal(
            request,
            response_channel,
            TerminalSelection {
                outcome: ManagedAgentStackTerminalOutcomeV1::Quarantined,
                lifecycle_effect: ManagedAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                head: ManagedAgentStackTerminalHeadV1::CommittedIncoming,
                fabric_generation: Some(fabric_generation),
                agent_generation: Some(agent_generation),
                physical_binding_census: 0,
                census_complete: false,
                fabric_ready: true,
                agent_ready: false,
                dependency_satisfied: false,
                exact_zero: false,
                quarantined: true,
                raw_code,
                raw_context: Some(reason),
            },
        )?;
        let mut quarantined = self.snapshot.transition();
        quarantined.phase = ManagedAgentStackDurablePhase::Quarantined;
        quarantined.active = Some(ManagedAgentStackDurableActive {
            fabric_generation,
            agent_generation,
            response_channel,
            request: request.clone(),
        });
        quarantined.pending = None;
        quarantined.physical_binding_census = 0;
        quarantined.census_complete = false;
        quarantined.fabric_ready = true;
        quarantined.agent_ready = false;
        quarantined.dependency_satisfied = false;
        quarantined.quarantine_reason = Some(reason);
        insert_terminal(&mut quarantined.terminals, request, receipt.clone())?;
        self.commit_transition(fabric, quarantined)?;
        Ok(receipt)
    }

    async fn start_agent(
        &mut self,
        fabric: ManagedFabricControlHandle,
        execution: &paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentStackTargetExecutionV1,
        provider: RuntimeResolvedAgentProviderV1,
    ) -> Result<(), ManagedAgentAssemblyError> {
        let config = ManagedAgentAssemblyConfig::try_from_execution(
            execution,
            self.state_directory.clone(),
        )?;
        let (assembly, handle) =
            ManagedAgentAssembly::start_resolved_provider(fabric, config, provider).await?;
        self.assembly = Some(assembly);
        self.handle = Some(handle);
        Ok(())
    }

    async fn shutdown_agent(&mut self) -> Result<(), ManagedAgentAssemblyError> {
        let Some(mut assembly) = self.assembly.take() else {
            return Ok(());
        };
        if let Err(error) = assembly.shutdown().await {
            self.assembly = Some(assembly);
            return Err(error);
        }
        Ok(())
    }

    fn publish_handle(
        &self,
        receipt: &ManagedAgentStackTerminalReceiptV1,
    ) -> Result<(), ManagedAgentStackRuntimeError> {
        let handle = self
            .handle
            .as_ref()
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
        self.handle_broker.publish(handle.clone(), receipt)
    }

    fn active_terminal_receipt(
        &self,
    ) -> Result<ManagedAgentStackTerminalReceiptV1, ManagedAgentStackRuntimeError> {
        let active = self
            .snapshot
            .active
            .as_ref()
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)?;
        self.lookup_terminal(&active.request, active.response_channel)?
            .ok_or(ManagedAgentStackRuntimeError::InvalidDurableState)
    }

    fn validate_request(
        &self,
        request: &ManagedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<(), ManagedAgentStackRuntimeError> {
        request
            .validate_expected_store(self.snapshot.store_instance_id())
            .map_err(|_| ManagedAgentStackRuntimeError::RequestRejected)?;
        request
            .validate_projection(&self.projection)
            .map_err(|_| ManagedAgentStackRuntimeError::ProjectionMismatch)?;
        if request.target() != self.projection.target()
            || response_channel.target() != request.target()
        {
            return Err(ManagedAgentStackRuntimeError::RequestRejected);
        }
        Ok(())
    }

    fn lookup_terminal(
        &self,
        request: &ManagedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<Option<ManagedAgentStackTerminalReceiptV1>, ManagedAgentStackRuntimeError> {
        let Some(record) = self.terminal_record(request)? else {
            return Ok(None);
        };
        record
            .receipt
            .validate_against_request(request, response_channel)
            .map_err(|_| ManagedAgentStackRuntimeError::TerminalCorrelation)?;
        Ok(Some(record.receipt.clone()))
    }

    fn terminal_record(
        &self,
        request: &ManagedAgentStackApplyRequestV1,
    ) -> Result<Option<&ManagedAgentStackTerminalRecord>, ManagedAgentStackRuntimeError> {
        let source_scope = request.provenance().source_scope();
        let operation_id = request.operation_id();
        let Some(record) = self.snapshot.terminals.iter().find(|record| {
            record.source_scope == source_scope && record.operation_id == operation_id
        }) else {
            return Ok(None);
        };
        if record.request_digest != request.envelope_request_digest() {
            return Err(ManagedAgentStackRuntimeError::OperationConflict);
        }
        Ok(Some(record))
    }

    fn admit_transition(
        &self,
        request: &ManagedAgentStackApplyRequestV1,
        verified: VerifiedManagedAgentStackApplyIngressV1,
    ) -> Result<ManagedAgentStackSnapshotTransition, ManagedAgentStackRuntimeError> {
        self.validate_cas(request)?;
        let control = request.control_commitment().control();
        let writer = control.writer_context();
        let claim = writer.proof().claim();
        let proof_digest = verified.authenticated().proof_envelope_digest();
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
            Some(_) => return Err(ManagedAgentStackRuntimeError::StaleWriter),
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
            Some(_) => return Err(ManagedAgentStackRuntimeError::StaleRevision),
        };
        let mut transition = self.snapshot.transition();
        transition.writer_fence = Some(writer_fence);
        transition.revision_high_water = Some(revision_high_water);
        insert_replay(
            &mut transition.tenure_nonces,
            ManagedAgentStackReplayRecord {
                identity: verified.authenticated().tenure_nonce_identity(),
                value_digest: proof_digest,
            },
        )?;
        insert_replay(
            &mut transition.request_nonces,
            ManagedAgentStackReplayRecord {
                identity: verified.authenticated().request_nonce_identity(),
                value_digest: request.envelope_request_digest(),
            },
        )?;
        insert_replay(
            &mut transition.temporal_lineages,
            ManagedAgentStackReplayRecord {
                identity: verified.authenticated().temporal_lineage_identity(),
                value_digest: request.envelope_request_digest(),
            },
        )?;
        Ok(transition)
    }

    fn validate_cas(
        &self,
        request: &ManagedAgentStackApplyRequestV1,
    ) -> Result<(), ManagedAgentStackRuntimeError> {
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
            _ => Err(ManagedAgentStackRuntimeError::ExpectedActiveMismatch),
        }
    }

    fn build_terminal(
        &self,
        request: &ManagedAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        selection: TerminalSelection,
    ) -> Result<ManagedAgentStackTerminalReceiptV1, ManagedAgentStackRuntimeError> {
        let reading = self.clock.reading()?;
        let completion_sequence = self
            .snapshot
            .sequence()
            .checked_add(1)
            .ok_or(ManagedAgentStackRuntimeError::SequenceOverflow)?;
        let state = ManagedAgentStackTerminalStateV1::try_new(
            selection.outcome,
            selection.lifecycle_effect,
            selection.head,
            selection.fabric_generation,
            selection.agent_generation,
        )?;
        let evidence = ManagedAgentStackTerminalEvidenceV1::try_new(
            ManagedAgentStackTerminalEvidenceFieldsV1 {
                physical_binding_census: selection.physical_binding_census,
                census_complete: selection.census_complete,
                fabric_ready: selection.fabric_ready,
                agent_ready: selection.agent_ready,
                dependency_satisfied: selection.dependency_satisfied,
                exact_zero: selection.exact_zero,
                quarantined: selection.quarantined,
                resource_census_digest: resource_census_digest(selection)?,
                raw_outcome_digest: raw_outcome_digest(selection, request)?,
                completion_runtime_host_epoch: self.runtime_host_epoch,
                completion_snapshot_sequence: completion_sequence,
                selection_clock_generation: reading.generation(),
                selection_observed_at_nanos: reading.now().value(),
            },
        )?;
        let facts = ManagedAgentStackTerminalFactsV1::try_new(request, state, evidence)?;
        let algorithm = ApplyAuthAlgorithm::try_new(1)
            .map_err(|_| ManagedAgentStackRuntimeError::SignerConfiguration)?;
        let auth_claim = ManagedAgentStackTerminalAuthClaimV1::try_new(
            response_channel,
            self.response_key_ref,
            algorithm,
            1,
        )?;
        let draft = ManagedAgentStackTerminalReceiptDraftV1::try_new(
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
        fabric: &mut ManagedFabricRuntimeCore,
        transition: ManagedAgentStackSnapshotTransition,
    ) -> Result<(), ManagedAgentStackRuntimeError> {
        let next = self.snapshot.try_successor_at_epoch(
            self.runtime_host_epoch,
            transition,
            &self.projection,
        )?;
        fabric.commit_managed_agent_stack(next.canonical_wire())?;
        self.snapshot = next;
        Ok(())
    }

    pub(crate) async fn shutdown(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
    ) -> Result<(), ManagedAgentStackRuntimeError> {
        self.recovery_completed = false;
        self.handle_broker.revoke()?;
        self.handle = None;
        self.shutdown_agent().await?;
        if self.snapshot.phase == ManagedAgentStackDurablePhase::ExactZero {
            return Ok(());
        }
        if !fabric.stop_live_for_stack().await? {
            return Err(ManagedAgentStackRuntimeError::ShutdownUncertain);
        }
        Ok(())
    }
}

fn prepare_agent_provider(
    selection: paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentProviderSelectionV1,
    resolver: &dyn RuntimeAgentProviderResolverV1,
) -> Result<RuntimeResolvedAgentProviderV1, ManagedAgentStackRuntimeError> {
    let provider = resolver
        .resolve(selection)
        .map_err(|_| ManagedAgentStackRuntimeError::ProviderResolverUnavailable)?;
    if provider.selection() != selection {
        return Err(ManagedAgentStackRuntimeError::ProviderResolverUnavailable);
    }
    Ok(provider)
}

fn validate_cutover_cas_and_fabric(
    request: &ManagedAgentStackApplyRequestV1,
    predecessor: &ManagedFabricStackCutoverObservation,
) -> Result<(), ManagedAgentStackRuntimeError> {
    if request.target_execution().fabric() != &predecessor.execution
        || request.control_commitment().control().expected_active()
            != ExpectedActive::Exact(predecessor.target_slice_digest)
    {
        return Err(ManagedAgentStackRuntimeError::FabricChangeRequiresEmpty);
    }
    Ok(())
}

fn initial_intent_transition(
    request: &ManagedAgentStackApplyRequestV1,
    verified: VerifiedManagedAgentStackApplyIngressV1,
    response_channel: ReferenceChannelBindingV1,
    fabric_generation: ManagedServiceGeneration,
    agent_generation: ManagedServiceGeneration,
) -> Result<ManagedAgentStackSnapshotTransition, ManagedAgentStackRuntimeError> {
    let proof_digest = verified.authenticated().proof_envelope_digest();
    let mut tenure_nonces = Vec::new();
    let mut request_nonces = Vec::new();
    let mut temporal_lineages = Vec::new();
    insert_replay(
        &mut tenure_nonces,
        ManagedAgentStackReplayRecord {
            identity: verified.authenticated().tenure_nonce_identity(),
            value_digest: proof_digest,
        },
    )?;
    insert_replay(
        &mut request_nonces,
        ManagedAgentStackReplayRecord {
            identity: verified.authenticated().request_nonce_identity(),
            value_digest: request.envelope_request_digest(),
        },
    )?;
    insert_replay(
        &mut temporal_lineages,
        ManagedAgentStackReplayRecord {
            identity: verified.authenticated().temporal_lineage_identity(),
            value_digest: request.envelope_request_digest(),
        },
    )?;
    Ok(ManagedAgentStackSnapshotTransition {
        fabric_generation_high_water: fabric_generation.value(),
        agent_generation_high_water: agent_generation.value(),
        phase: ManagedAgentStackDurablePhase::AgentStartIntent,
        writer_fence: Some(writer_fence(request, proof_digest)),
        revision_high_water: Some(revision_high_water(request)),
        active: None,
        pending: Some(ManagedAgentStackDurablePending {
            kind: ManagedAgentStackPendingKind::ActivateAgent,
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
        fabric_ready: true,
        agent_ready: false,
        dependency_satisfied: true,
        quarantine_reason: None,
    })
}

fn writer_fence(
    request: &ManagedAgentStackApplyRequestV1,
    proof_envelope_digest: Digest32,
) -> ManagedAgentStackWriterFence {
    let writer = request.control_commitment().control().writer_context();
    let claim = writer.proof().claim();
    ManagedAgentStackWriterFence {
        source_scope: claim.source_scope(),
        writer: claim.writer(),
        principal: request.authentication().claim().principal(),
        epoch: claim.epoch().value(),
        proof_envelope_digest,
    }
}

fn revision_high_water(
    request: &ManagedAgentStackApplyRequestV1,
) -> ManagedAgentStackRevisionHighWater {
    let provenance = request.provenance();
    ManagedAgentStackRevisionHighWater {
        source_scope: provenance.source_scope(),
        revision: provenance.source_revision().value(),
        source_plan_digest: provenance.source_plan_digest(),
    }
}

fn observe_deadline(
    clock: RuntimeClock,
    verified: VerifiedManagedAgentStackApplyIngressV1,
) -> Result<(), ManagedAgentStackRuntimeError> {
    let reading = clock.reading()?;
    if reading.generation() != verified.clock_generation()
        || reading.now().value() >= verified.deadline_nanos()
    {
        return Err(ManagedAgentStackRuntimeError::DeadlineExpired);
    }
    Ok(())
}

fn recovery_deadline(
    request: &ManagedAgentStackApplyRequestV1,
    reading: ClockReading,
) -> Result<u64, ManagedAgentStackRuntimeError> {
    let remaining = request.temporal().original_budget().value();
    reading
        .now()
        .value()
        .checked_add(remaining)
        .ok_or(ManagedAgentStackRuntimeError::DeadlineOverflow)
}

fn stack_projection_digest(
    projection: &ManagedAgentStackProjectionV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(STACK_PROJECTION_DIGEST_DOMAIN)?;
    builder.field_bytes(projection.canonical_wire())?;
    Ok(builder.finish())
}

fn resource_census_digest(selection: TerminalSelection) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(STACK_RESOURCE_CENSUS_DIGEST_DOMAIN)?;
    builder.field_bytes(&selection.physical_binding_census.to_be_bytes())?;
    builder.field_u16(u16::from(selection.census_complete))?;
    builder.field_u16(u16::from(selection.fabric_ready))?;
    builder.field_u16(u16::from(selection.agent_ready))?;
    builder.field_u16(u16::from(selection.dependency_satisfied))?;
    builder.field_u64(
        selection
            .fabric_generation
            .map_or(0, ManagedServiceGeneration::value),
    )?;
    builder.field_u64(
        selection
            .agent_generation
            .map_or(0, ManagedServiceGeneration::value),
    )?;
    Ok(builder.finish())
}

fn raw_outcome_digest(
    selection: TerminalSelection,
    request: &ManagedAgentStackApplyRequestV1,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(STACK_RAW_OUTCOME_DIGEST_DOMAIN)?;
    builder.field_u16(selection.raw_code)?;
    builder.field_u16(u16::from(selection.raw_context.is_some()))?;
    if let Some(context) = selection.raw_context {
        builder.field_digest(&context)?;
    }
    builder.field_digest(&request.envelope_request_digest())?;
    Ok(builder.finish())
}

fn quarantine_reason_digest(
    code: u16,
    request: &ManagedAgentStackApplyRequestV1,
    error: Option<&ManagedAgentAssemblyError>,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(STACK_QUARANTINE_DIGEST_DOMAIN)?;
    builder.field_u16(code)?;
    builder.field_digest(&request.envelope_request_digest())?;
    if let Some(error) = error {
        builder.field_bytes(format!("{error:?}").as_bytes())?;
    }
    Ok(builder.finish())
}

fn next_generation(
    high_water: u64,
) -> Result<ManagedServiceGeneration, ManagedAgentStackRuntimeError> {
    high_water
        .checked_add(1)
        .ok_or(ManagedAgentStackRuntimeError::GenerationExhausted)
        .and_then(|value| {
            ManagedServiceGeneration::try_new(value)
                .map_err(|_| ManagedAgentStackRuntimeError::GenerationExhausted)
        })
}

fn insert_replay(
    records: &mut Vec<ManagedAgentStackReplayRecord>,
    incoming: ManagedAgentStackReplayRecord,
) -> Result<(), ManagedAgentStackRuntimeError> {
    match records.binary_search_by_key(&incoming.identity, |record| record.identity) {
        Ok(index) if records[index].value_digest == incoming.value_digest => Ok(()),
        Ok(_) => Err(ManagedAgentStackRuntimeError::ReplayConflict),
        Err(index) if records.len() < MAX_STACK_REPLAY_RECORDS => {
            records.insert(index, incoming);
            Ok(())
        }
        Err(_) => Err(ManagedAgentStackRuntimeError::ReplayCapacityReached),
    }
}

fn insert_terminal(
    records: &mut Vec<ManagedAgentStackTerminalRecord>,
    request: &ManagedAgentStackApplyRequestV1,
    receipt: ManagedAgentStackTerminalReceiptV1,
) -> Result<(), ManagedAgentStackRuntimeError> {
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
        Ok(_) => Err(ManagedAgentStackRuntimeError::OperationConflict),
        Err(index) if records.len() < MAX_STACK_REPLAY_RECORDS => {
            records.insert(
                index,
                ManagedAgentStackTerminalRecord {
                    source_scope: request.provenance().source_scope(),
                    operation_id: request.operation_id(),
                    request_digest: request.envelope_request_digest(),
                    receipt,
                },
            );
            Ok(())
        }
        Err(_) => Err(ManagedAgentStackRuntimeError::ReplayCapacityReached),
    }
}

#[derive(Debug)]
pub(crate) enum ManagedAgentStackRuntimeError {
    RequestRejected,
    ProjectionMismatch,
    FabricChangeRequiresEmpty,
    ProviderResolverUnavailable,
    RuntimeEpochRegressed,
    RecoveryRequired,
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
    TerminalCorrelation,
    GenerationExhausted,
    SequenceOverflow,
    SignerConfiguration,
    InvalidDurableState,
    HandleBrokerUnavailable,
    ShutdownUncertain,
    Digest(DigestBuildError),
    Contract(ManagedAgentStackPlanError),
    State(ManagedAgentStackStateError),
    Fabric(ManagedFabricRuntimeError),
    Agent(ManagedAgentAssemblyError),
    Clock(RuntimeClockError),
}

impl ManagedAgentStackRuntimeError {
    pub(crate) const fn is_request_rejection(&self) -> bool {
        matches!(
            self,
            Self::RequestRejected
                | Self::ProjectionMismatch
                | Self::FabricChangeRequiresEmpty
                | Self::ProviderResolverUnavailable
                | Self::DeadlineExpired
                | Self::ExpectedActiveMismatch
                | Self::StaleWriter
                | Self::StaleRevision
                | Self::ReplayConflict
                | Self::OperationConflict
                | Self::TerminalCorrelation
        )
    }
}

impl fmt::Display for ManagedAgentStackRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "managed Agent-stack Runtime failed: {self:?}")
    }
}

impl std::error::Error for ManagedAgentStackRuntimeError {}

impl From<DigestBuildError> for ManagedAgentStackRuntimeError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ManagedAgentStackPlanError> for ManagedAgentStackRuntimeError {
    fn from(value: ManagedAgentStackPlanError) -> Self {
        Self::Contract(value)
    }
}

impl From<ManagedAgentStackStateError> for ManagedAgentStackRuntimeError {
    fn from(value: ManagedAgentStackStateError) -> Self {
        Self::State(value)
    }
}

impl From<ManagedFabricRuntimeError> for ManagedAgentStackRuntimeError {
    fn from(value: ManagedFabricRuntimeError) -> Self {
        Self::Fabric(value)
    }
}

impl From<ManagedAgentAssemblyError> for ManagedAgentStackRuntimeError {
    fn from(value: ManagedAgentAssemblyError) -> Self {
        Self::Agent(value)
    }
}

impl From<RuntimeClockError> for ManagedAgentStackRuntimeError {
    fn from(value: RuntimeClockError) -> Self {
        Self::Clock(value)
    }
}

#[cfg(test)]
mod provider_resolver_tests {
    use super::*;

    use paraegox_agent_contracts::AgentConversationRequestV1;
    use paraegox_agent_service::{
        AgentConversationModelCancellation, AgentConversationModelFuture,
        AgentConversationModelOutcomeV1, AgentConversationModelProvider,
    };
    use paraegox_runtime_contracts::managed_agent_stack_plan::{
        ManagedAgentProviderRefV1, ManagedAgentProviderSelectionV1, ManagedAgentSecretRefV1,
    };

    struct ReturnedSelectionResolver(ManagedAgentProviderSelectionV1);

    impl RuntimeAgentProviderResolverV1 for ReturnedSelectionResolver {
        fn resolve(
            &self,
            _selection: ManagedAgentProviderSelectionV1,
        ) -> Result<RuntimeResolvedAgentProviderV1, crate::RuntimeAgentProviderResolveError>
        {
            Ok(RuntimeResolvedAgentProviderV1::new(self.0, TestProvider))
        }
    }

    struct TestProvider;

    impl AgentConversationModelProvider for TestProvider {
        fn complete(
            &mut self,
            _request: AgentConversationRequestV1,
            _cancellation: AgentConversationModelCancellation,
        ) -> AgentConversationModelFuture {
            Box::pin(async { AgentConversationModelOutcomeV1::Failed })
        }
    }

    fn provisioned(byte: u8) -> ManagedAgentProviderSelectionV1 {
        ManagedAgentProviderSelectionV1::try_provisioned(
            ManagedAgentProviderRefV1::try_from_bytes([byte; 16]).expect("test provider reference"),
            Digest32::from_bytes([byte.wrapping_add(1); 32]),
            ManagedAgentSecretRefV1::try_from_bytes([byte.wrapping_add(2); 16])
                .expect("test Secret reference"),
        )
        .expect("test Provisioned selection")
    }

    fn deterministic(byte: u8) -> ManagedAgentProviderSelectionV1 {
        ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            ManagedAgentProviderRefV1::try_from_bytes([byte; 16]).expect("test provider reference"),
            Digest32::from_bytes([byte.wrapping_add(1); 32]),
        )
        .expect("test deterministic selection")
    }

    #[test]
    fn deterministic_fixture_resolves_through_the_same_exact_selection_path() {
        let selection = deterministic(0x11);

        let provider = prepare_agent_provider(selection, &ReturnedSelectionResolver(selection))
            .expect("deterministic fixture must resolve");
        assert_eq!(provider.selection(), selection);
    }

    #[test]
    fn deterministic_fixture_fails_closed_when_the_resolver_is_unavailable() {
        let error = prepare_agent_provider(
            deterministic(0x11),
            &crate::runtime_agent_provider::UnavailableRuntimeAgentProviderResolver,
        )
        .expect_err("unavailable resolver must reject the deterministic fixture");

        assert!(matches!(
            error,
            ManagedAgentStackRuntimeError::ProviderResolverUnavailable
        ));
    }

    #[test]
    fn resolver_must_return_the_exact_requested_selection_for_every_profile() {
        for (requested, different) in [
            (deterministic(0x21), deterministic(0x31)),
            (provisioned(0x41), provisioned(0x51)),
        ] {
            let error = prepare_agent_provider(requested, &ReturnedSelectionResolver(different))
                .expect_err("mismatched resolver output must fail");

            assert!(matches!(
                error,
                ManagedAgentStackRuntimeError::ProviderResolverUnavailable
            ));
        }
    }
}
