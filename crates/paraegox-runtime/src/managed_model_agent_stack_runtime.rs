#![cfg(unix)]

//! RuntimeHost-owned PXAR-v9 Fabric+Model+Agent durable apply owner.
//!
//! This is the fixed A2a sibling of the PXAR-v7 Agent-stack branch. It reuses
//! the already Ready PXAR-v6 Fabric generation, starts exactly one committed
//! Model generation, and only then starts the Agent with a generation-fenced
//! Model dependency. Every physical start/retire effect follows an independent
//! PXMA intent in the same Runtime store.

use core::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::time::ClockReading;
use paraegox_runtime_contracts::apply::ExpectedActive;
use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
    ManagedModelAgentStackApplyRequestV1, ManagedModelAgentStackPlanError,
    ManagedModelAgentStackProjectionV1, ManagedModelAgentStackTargetExecutionV1,
    ManagedModelAgentStackTargetModeV1, ManagedModelAgentStackTerminalAuthClaimV1,
    ManagedModelAgentStackTerminalEvidenceFieldsV1, ManagedModelAgentStackTerminalEvidenceV1,
    ManagedModelAgentStackTerminalFactsV1, ManagedModelAgentStackTerminalHeadV1,
    ManagedModelAgentStackTerminalLifecycleEffectV1, ManagedModelAgentStackTerminalOutcomeV1,
    ManagedModelAgentStackTerminalReceiptDraftV1, ManagedModelAgentStackTerminalReceiptV1,
    ManagedModelAgentStackTerminalStateV1,
};
use paraegox_runtime_contracts::managed_service::{ManagedServiceGeneration, ManagedServiceId};
use paraegox_runtime_contracts::reference_control::ReferenceChannelBindingV1;
use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

use crate::admission::VerifiedManagedModelAgentStackApplyIngressV1;
use crate::managed_agent_runtime::{
    ManagedAgentAssembly, ManagedAgentAssemblyError, RuntimeAgentConversationHandle,
};
use crate::managed_agent_stack_runtime::RuntimeAgentHandleBroker;
use crate::managed_fabric_runtime::{
    ManagedFabricControlHandle, ManagedFabricRuntimeCore, ManagedFabricRuntimeError,
    ManagedFabricStackCutoverObservation,
};
use crate::managed_model_agent_stack_state::{
    ManagedModelAgentStackDurableActive, ManagedModelAgentStackDurablePending,
    ManagedModelAgentStackDurablePhase, ManagedModelAgentStackPendingKind,
    ManagedModelAgentStackReplayRecord, ManagedModelAgentStackRevisionHighWater,
    ManagedModelAgentStackSnapshot, ManagedModelAgentStackSnapshotTransition,
    ManagedModelAgentStackStateError, ManagedModelAgentStackTerminalRecord,
    ManagedModelAgentStackWriterFence,
};
use crate::managed_model_runtime::{
    ManagedModelAssembly, ManagedModelAssemblyError, ManagedModelDependencyHandle,
    RuntimeModelBackendResolverV1,
};
use crate::runtime_clock::{RuntimeClock, RuntimeClockError};
use crate::task_registry::CancellationSource;

const STACK_PROJECTION_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-model-agent-stack-transition-projection.sha256.v1";
const STACK_RESOURCE_CENSUS_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-model-agent-stack-resource-census.sha256.v1";
const STACK_RAW_OUTCOME_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-model-agent-stack-raw-outcome.sha256.v1";
const STACK_QUARANTINE_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.managed-model-agent-stack-quarantine.sha256.v1";
const MAX_STACK_REPLAY_RECORDS: usize = 256;

pub(crate) struct ManagedModelAgentStackOwnerConfig {
    pub(crate) state_directory: PathBuf,
    pub(crate) projection: ManagedModelAgentStackProjectionV1,
    pub(crate) runtime_host_epoch: u64,
    pub(crate) clock: RuntimeClock,
    pub(crate) response_key_ref: ApplyAuthKeyRef,
    pub(crate) response_signer: SigningKey,
    pub(crate) handle_broker: RuntimeAgentHandleBroker,
    pub(crate) model_backend_resolver: Arc<dyn RuntimeModelBackendResolverV1>,
}

pub(crate) struct ManagedModelAgentStackRuntimeCore {
    snapshot: ManagedModelAgentStackSnapshot,
    projection: ManagedModelAgentStackProjectionV1,
    state_directory: PathBuf,
    runtime_host_epoch: u64,
    clock: RuntimeClock,
    response_key_ref: ApplyAuthKeyRef,
    response_signer: SigningKey,
    handle_broker: RuntimeAgentHandleBroker,
    model_backend_resolver: Arc<dyn RuntimeModelBackendResolverV1>,
    cancellation: CancellationSource,
    model: Option<ManagedModelAssembly>,
    agent: Option<ManagedAgentAssembly>,
    handle: Option<RuntimeAgentConversationHandle>,
    recovery_completed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedModelAgentStackApplyOutcome {
    Committed(ManagedModelAgentStackTerminalReceiptV1),
    Replayed(ManagedModelAgentStackTerminalReceiptV1),
}

pub(crate) enum ManagedModelAgentStackCutoverOutcome {
    NoEffect(ManagedModelAgentStackTerminalReceiptV1),
    Installed(
        ManagedModelAgentStackRuntimeCore,
        ManagedModelAgentStackApplyOutcome,
    ),
}

#[derive(Clone, Copy)]
struct TerminalSelection {
    outcome: ManagedModelAgentStackTerminalOutcomeV1,
    lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1,
    head: ManagedModelAgentStackTerminalHeadV1,
    fabric_generation: Option<ManagedServiceGeneration>,
    model_generation: Option<ManagedServiceGeneration>,
    agent_generation: Option<ManagedServiceGeneration>,
    physical_binding_census: u16,
    census_complete: bool,
    fabric_ready: bool,
    model_ready: bool,
    agent_ready: bool,
    fabric_to_agent_dependency_ready: bool,
    model_to_agent_dependency_ready: bool,
    exact_zero: bool,
    quarantined: bool,
    raw_code: u16,
    raw_context: Option<Digest32>,
}

#[derive(Clone, Copy)]
struct QuarantineObservation {
    fabric_generation: Option<ManagedServiceGeneration>,
    model_generation: Option<ManagedServiceGeneration>,
    agent_generation: Option<ManagedServiceGeneration>,
    physical_binding_census: u16,
    census_complete: bool,
    fabric_ready: bool,
    model_ready: bool,
    model_cleanup_exact_zero: Option<bool>,
}

impl ManagedModelAgentStackRuntimeCore {
    pub(crate) fn open(
        fabric: &ManagedFabricRuntimeCore,
        config: ManagedModelAgentStackOwnerConfig,
    ) -> Result<Option<Self>, ManagedModelAgentStackRuntimeError> {
        let projection_digest = stack_projection_digest(&config.projection)?;
        let Some(stored_projection_digest) = fabric.managed_model_agent_stack_projection_digest()
        else {
            if fabric.managed_model_agent_stack_snapshot_bytes()?.is_some() {
                return Err(ManagedModelAgentStackRuntimeError::InvalidDurableState);
            }
            return Ok(None);
        };
        if stored_projection_digest != projection_digest {
            return Err(ManagedModelAgentStackRuntimeError::ProjectionMismatch);
        }
        let frame = fabric
            .managed_model_agent_stack_snapshot_bytes()?
            .ok_or(ManagedModelAgentStackRuntimeError::InvalidDurableState)?;
        let snapshot = ManagedModelAgentStackSnapshot::decode(
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
            return Err(ManagedModelAgentStackRuntimeError::RuntimeEpochRegressed);
        }
        Ok(Some(Self::from_snapshot(snapshot, config, false)))
    }

    fn from_snapshot(
        snapshot: ManagedModelAgentStackSnapshot,
        config: ManagedModelAgentStackOwnerConfig,
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
            model_backend_resolver: config.model_backend_resolver,
            cancellation: CancellationSource::root(),
            model: None,
            agent: None,
            handle: None,
            recovery_completed,
        }
    }

    /// Whether the outer Runtime owner must first recover the retained PXAR-v6
    /// Fabric generation. Retire and exact-zero phases deliberately do not
    /// resurrect a predecessor merely to stop it again.
    pub(crate) fn requires_predecessor_recovery(&self) -> bool {
        matches!(
            self.snapshot.phase,
            ManagedModelAgentStackDurablePhase::ModelStartIntent
                | ManagedModelAgentStackDurablePhase::AgentStartIntent
                | ManagedModelAgentStackDurablePhase::ActiveReady
                | ManagedModelAgentStackDurablePhase::RecoveryIntent
        )
    }

    pub(crate) async fn cutover(
        fabric: &mut ManagedFabricRuntimeCore,
        config: ManagedModelAgentStackOwnerConfig,
        request: ManagedModelAgentStackApplyRequestV1,
        verified: VerifiedManagedModelAgentStackApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<ManagedModelAgentStackCutoverOutcome, ManagedModelAgentStackRuntimeError> {
        validate_cutover_request(fabric, &config, &request, response_channel)?;
        let predecessor = fabric.stack_cutover_observation().await?;
        match observe_deadline(config.clock, verified) {
            Ok(()) => {}
            Err(ManagedModelAgentStackRuntimeError::DeadlineExpired) => {
                return Ok(ManagedModelAgentStackCutoverOutcome::NoEffect(
                    build_pre_cutover_no_effect_terminal(
                        &config,
                        &request,
                        response_channel,
                        predecessor.generation,
                        20,
                    )?,
                ));
            }
            Err(error) => return Err(error),
        }
        if validate_cutover_cas_and_fabric(&request, &predecessor).is_err() {
            return Ok(ManagedModelAgentStackCutoverOutcome::NoEffect(
                build_pre_cutover_no_effect_terminal(
                    &config,
                    &request,
                    response_channel,
                    predecessor.generation,
                    21,
                )?,
            ));
        }

        let model_generation = ManagedServiceGeneration::try_new(1)
            .map_err(|_| ManagedModelAgentStackRuntimeError::GenerationExhausted)?;
        let transition = initial_model_intent_transition(
            &request,
            verified,
            response_channel,
            predecessor.generation,
            model_generation,
        )?;
        let projection_digest = stack_projection_digest(&config.projection)?;
        let snapshot = ManagedModelAgentStackSnapshot::try_initial(
            fabric.store_instance_id(),
            fabric.owner_target_fingerprint(),
            projection_digest,
            config.runtime_host_epoch,
            transition,
            &config.projection,
        )?;
        fabric
            .initialize_managed_model_agent_stack(projection_digest, snapshot.canonical_wire())?;
        let mut core = Self::from_snapshot(snapshot, config, true);

        let model_dependency = match core
            .start_model(request.target_execution(), model_generation)
            .await
        {
            Ok(dependency) => dependency,
            Err(error) => {
                let Some(model_cleanup_exact_zero) = model_start_cleanup_exact_zero(&error) else {
                    return Err(error);
                };
                let receipt = core.terminalize_quarantined(
                    fabric,
                    &request,
                    response_channel,
                    30,
                    QuarantineObservation {
                        fabric_generation: Some(predecessor.generation),
                        model_generation: Some(model_generation),
                        agent_generation: None,
                        physical_binding_census: 0,
                        census_complete: model_cleanup_exact_zero,
                        fabric_ready: true,
                        model_ready: false,
                        model_cleanup_exact_zero: Some(model_cleanup_exact_zero),
                    },
                )?;
                return Ok(ManagedModelAgentStackCutoverOutcome::Installed(
                    core,
                    ManagedModelAgentStackApplyOutcome::Committed(receipt),
                ));
            }
        };

        let agent_generation = next_generation(core.snapshot.agent_generation_high_water)?;
        core.commit_agent_start_intent(
            fabric,
            agent_generation,
            ManagedModelAgentStackPendingKind::ActivateStack,
        )?;
        if core
            .start_agent(
                predecessor.control,
                request.target_execution(),
                model_generation,
                model_dependency,
            )
            .await
            .is_err()
        {
            let _model_exact = core.shutdown_model().await;
            let receipt = core.terminalize_quarantined(
                fabric,
                &request,
                response_channel,
                31,
                QuarantineObservation {
                    fabric_generation: Some(predecessor.generation),
                    model_generation: Some(model_generation),
                    agent_generation: Some(agent_generation),
                    physical_binding_census: 0,
                    census_complete: false,
                    fabric_ready: true,
                    model_ready: false,
                    model_cleanup_exact_zero: Some(_model_exact),
                },
            )?;
            return Ok(ManagedModelAgentStackCutoverOutcome::Installed(
                core,
                ManagedModelAgentStackApplyOutcome::Committed(receipt),
            ));
        }

        let receipt = core.commit_active_ready(
            fabric,
            &request,
            response_channel,
            predecessor.generation,
            model_generation,
            agent_generation,
            1,
        )?;
        core.publish_handle(&receipt)?;
        Ok(ManagedModelAgentStackCutoverOutcome::Installed(
            core,
            ManagedModelAgentStackApplyOutcome::Committed(receipt),
        ))
    }

    pub(crate) async fn recover(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        if self.recovery_completed {
            return Ok(());
        }
        if self.model.is_some() || self.agent.is_some() || self.handle.is_some() {
            return Err(ManagedModelAgentStackRuntimeError::RecoveryWhileLive);
        }
        self.revoke_handle()?;
        match self.snapshot.phase {
            ManagedModelAgentStackDurablePhase::ExactZero => {
                if self.snapshot.runtime_host_epoch() != self.runtime_host_epoch {
                    self.commit_transition(fabric, self.snapshot.transition())?;
                }
                self.recovery_completed = true;
                return Ok(());
            }
            ManagedModelAgentStackDurablePhase::AgentRetireIntent
            | ManagedModelAgentStackDurablePhase::ModelRetireIntent
            | ManagedModelAgentStackDurablePhase::FabricStopIntent => {
                return self.recover_deactivation(fabric);
            }
            ManagedModelAgentStackDurablePhase::Uncertain
            | ManagedModelAgentStackDurablePhase::Quarantined => {
                return Err(ManagedModelAgentStackRuntimeError::RecoveryQuarantined);
            }
            ManagedModelAgentStackDurablePhase::ModelStartIntent
            | ManagedModelAgentStackDurablePhase::AgentStartIntent
            | ManagedModelAgentStackDurablePhase::ActiveReady
            | ManagedModelAgentStackDurablePhase::RecoveryIntent => {}
        }

        let (request, response_channel) = self.recovery_request()?;
        let predecessor = fabric.stack_cutover_observation().await?;
        if request.target_execution().managed_agent_stack().fabric() != &predecessor.execution {
            return Err(ManagedModelAgentStackRuntimeError::FabricChangeRequiresEmpty);
        }
        let model_generation = next_generation(self.snapshot.model_generation_high_water)?;
        let agent_generation = next_generation(self.snapshot.agent_generation_high_water)?;
        let reading = self.clock.reading()?;
        let deadline_nanos = recovery_deadline(&request, reading)?;
        self.commit_recovery_model_intent(
            fabric,
            &request,
            response_channel,
            predecessor.generation,
            model_generation,
            reading,
            deadline_nanos,
        )?;

        let model_dependency = match self
            .start_model(request.target_execution(), model_generation)
            .await
        {
            Ok(dependency) => dependency,
            Err(error) => {
                let Some(model_cleanup_exact_zero) = model_start_cleanup_exact_zero(&error) else {
                    return Err(error);
                };
                self.quarantine_recovery(
                    fabric,
                    &request,
                    response_channel,
                    40,
                    QuarantineObservation {
                        fabric_generation: Some(predecessor.generation),
                        model_generation: Some(model_generation),
                        agent_generation: None,
                        physical_binding_census: 0,
                        census_complete: model_cleanup_exact_zero,
                        fabric_ready: true,
                        model_ready: false,
                        model_cleanup_exact_zero: Some(model_cleanup_exact_zero),
                    },
                )?;
                return Err(ManagedModelAgentStackRuntimeError::RecoveryQuarantined);
            }
        };

        self.commit_agent_start_intent(
            fabric,
            agent_generation,
            ManagedModelAgentStackPendingKind::RecoverActive,
        )?;
        if self
            .start_agent(
                predecessor.control,
                request.target_execution(),
                model_generation,
                model_dependency,
            )
            .await
            .is_err()
        {
            let _model_exact = self.shutdown_model().await;
            self.quarantine_recovery(
                fabric,
                &request,
                response_channel,
                41,
                QuarantineObservation {
                    fabric_generation: Some(predecessor.generation),
                    model_generation: Some(model_generation),
                    agent_generation: Some(agent_generation),
                    physical_binding_census: 0,
                    census_complete: false,
                    fabric_ready: true,
                    model_ready: false,
                    model_cleanup_exact_zero: Some(_model_exact),
                },
            )?;
            return Err(ManagedModelAgentStackRuntimeError::RecoveryQuarantined);
        }

        let existing_terminal = self.lookup_terminal(&request, response_channel)?;
        let receipt = match existing_terminal {
            Some(receipt) => {
                self.commit_active_ready_without_terminal(
                    fabric,
                    &request,
                    response_channel,
                    predecessor.generation,
                    model_generation,
                    agent_generation,
                )?;
                receipt
            }
            None => self.commit_active_ready(
                fabric,
                &request,
                response_channel,
                predecessor.generation,
                model_generation,
                agent_generation,
                42,
            )?,
        };
        self.publish_handle(&receipt)?;
        self.recovery_completed = true;
        Ok(())
    }

    pub(crate) fn authenticated_terminal_replay(
        &self,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<Option<ManagedModelAgentStackTerminalReceiptV1>, ManagedModelAgentStackRuntimeError>
    {
        self.validate_request(request, response_channel)?;
        self.lookup_terminal(request, response_channel)
    }

    pub(crate) async fn apply(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: ManagedModelAgentStackApplyRequestV1,
        verified: VerifiedManagedModelAgentStackApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<ManagedModelAgentStackApplyOutcome, ManagedModelAgentStackRuntimeError> {
        if !self.recovery_completed {
            return Err(ManagedModelAgentStackRuntimeError::RecoveryNotCompleted);
        }
        self.validate_request(&request, response_channel)?;
        if let Some(receipt) = self.lookup_terminal(&request, response_channel)? {
            return Ok(ManagedModelAgentStackApplyOutcome::Replayed(receipt));
        }
        if !matches!(
            self.snapshot.phase,
            ManagedModelAgentStackDurablePhase::ActiveReady
                | ManagedModelAgentStackDurablePhase::ExactZero
        ) {
            return Err(ManagedModelAgentStackRuntimeError::RecoveryRequired);
        }
        if observe_deadline(self.clock, verified).is_err() {
            let no_effect = self.snapshot.transition();
            let receipt =
                self.terminalize_no_effect(fabric, &request, response_channel, 10, no_effect)?;
            return Ok(ManagedModelAgentStackApplyOutcome::Committed(receipt));
        }
        let transition = match self.admit_transition(&request, verified) {
            Ok(transition) => transition,
            Err(
                ManagedModelAgentStackRuntimeError::ExpectedActiveMismatch
                | ManagedModelAgentStackRuntimeError::StaleWriter
                | ManagedModelAgentStackRuntimeError::StaleRevision,
            ) => {
                let no_effect = self.snapshot.transition();
                let receipt =
                    self.terminalize_no_effect(fabric, &request, response_channel, 11, no_effect)?;
                return Ok(ManagedModelAgentStackApplyOutcome::Committed(receipt));
            }
            Err(error) => return Err(error),
        };
        match request.target_execution().mode() {
            ManagedModelAgentStackTargetModeV1::FabricModelAndAgent => {
                let receipt =
                    self.terminalize_no_effect(fabric, &request, response_channel, 12, transition)?;
                Ok(ManagedModelAgentStackApplyOutcome::Committed(receipt))
            }
            ManagedModelAgentStackTargetModeV1::EmptyDeactivate => {
                self.apply_empty(fabric, request, verified, response_channel, transition)
                    .await
            }
        }
    }

    async fn apply_empty(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: ManagedModelAgentStackApplyRequestV1,
        verified: VerifiedManagedModelAgentStackApplyIngressV1,
        response_channel: ReferenceChannelBindingV1,
        mut transition: ManagedModelAgentStackSnapshotTransition,
    ) -> Result<ManagedModelAgentStackApplyOutcome, ManagedModelAgentStackRuntimeError> {
        let Some(active) = self.snapshot.active.clone() else {
            transition.phase = ManagedModelAgentStackDurablePhase::ExactZero;
            let receipt = self.terminalize_empty_exact_zero(
                fabric,
                &request,
                response_channel,
                transition,
                ManagedModelAgentStackTerminalLifecycleEffectV1::ProvenNotStarted,
                20,
            )?;
            return Ok(ManagedModelAgentStackApplyOutcome::Committed(receipt));
        };

        transition.phase = ManagedModelAgentStackDurablePhase::AgentRetireIntent;
        transition.pending = Some(ManagedModelAgentStackDurablePending {
            kind: ManagedModelAgentStackPendingKind::DeactivateStack,
            fabric_generation: Some(active.fabric_generation),
            model_generation: Some(active.model_generation),
            agent_generation: Some(active.agent_generation),
            admitted_clock_generation: verified.clock_generation(),
            admitted_at_nanos: verified.admitted_at_nanos(),
            deadline_nanos: verified.deadline_nanos(),
            response_channel,
            request: request.clone(),
        });
        transition.quarantine_reason = None;
        self.commit_transition(fabric, transition)?;
        self.revoke_handle()?;

        if self.shutdown_agent().await.is_err() {
            let receipt = self.terminalize_quarantined(
                fabric,
                &request,
                response_channel,
                50,
                QuarantineObservation {
                    fabric_generation: Some(active.fabric_generation),
                    model_generation: Some(active.model_generation),
                    agent_generation: Some(active.agent_generation),
                    physical_binding_census: 2,
                    census_complete: false,
                    fabric_ready: true,
                    model_ready: true,
                    model_cleanup_exact_zero: None,
                },
            )?;
            return Ok(ManagedModelAgentStackApplyOutcome::Committed(receipt));
        }

        let mut model_retire = self.snapshot.transition();
        model_retire.phase = ManagedModelAgentStackDurablePhase::ModelRetireIntent;
        model_retire.physical_binding_census = 0;
        model_retire.census_complete = true;
        model_retire.fabric_ready = true;
        model_retire.model_ready = true;
        model_retire.agent_ready = false;
        model_retire.fabric_to_agent_dependency_ready = false;
        model_retire.model_to_agent_dependency_ready = false;
        self.commit_transition(fabric, model_retire)?;

        if !self.shutdown_model().await {
            // The Agent is exactly retired, so Fabric may be stopped. The
            // separate intent is durable first, but no path may claim global
            // exact-zero while Model cleanup remains unproven.
            self.commit_fabric_stop_intent(fabric)?;
            let _fabric_stop = fabric.stop_live_for_stack().await;
            let receipt = self.terminalize_quarantined(
                fabric,
                &request,
                response_channel,
                51,
                QuarantineObservation {
                    fabric_generation: Some(active.fabric_generation),
                    model_generation: Some(active.model_generation),
                    agent_generation: Some(active.agent_generation),
                    physical_binding_census: 0,
                    census_complete: true,
                    fabric_ready: false,
                    model_ready: false,
                    model_cleanup_exact_zero: Some(false),
                },
            )?;
            return Ok(ManagedModelAgentStackApplyOutcome::Committed(receipt));
        }

        self.commit_fabric_stop_intent(fabric)?;
        match fabric.stop_live_for_stack().await {
            Ok(true) => {
                let exact_zero = self.snapshot.transition();
                let receipt = self.terminalize_empty_exact_zero(
                    fabric,
                    &request,
                    response_channel,
                    exact_zero,
                    ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                    2,
                )?;
                Ok(ManagedModelAgentStackApplyOutcome::Committed(receipt))
            }
            Ok(false) => {
                let receipt = self.terminalize_quarantined(
                    fabric,
                    &request,
                    response_channel,
                    52,
                    QuarantineObservation {
                        fabric_generation: Some(active.fabric_generation),
                        model_generation: Some(active.model_generation),
                        agent_generation: Some(active.agent_generation),
                        physical_binding_census: 0,
                        census_complete: true,
                        fabric_ready: false,
                        model_ready: false,
                        model_cleanup_exact_zero: Some(true),
                    },
                )?;
                Ok(ManagedModelAgentStackApplyOutcome::Committed(receipt))
            }
            Err(_) => {
                let receipt = self.terminalize_uncertain(
                    fabric,
                    &request,
                    response_channel,
                    53,
                    Some(active.fabric_generation),
                    Some(active.model_generation),
                    Some(active.agent_generation),
                )?;
                Ok(ManagedModelAgentStackApplyOutcome::Committed(receipt))
            }
        }
    }

    fn recover_deactivation(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        let pending = self
            .snapshot
            .pending
            .clone()
            .ok_or(ManagedModelAgentStackRuntimeError::InvalidDurableState)?;
        if pending.kind != ManagedModelAgentStackPendingKind::DeactivateStack
            || pending.request.target_execution().mode()
                != ManagedModelAgentStackTargetModeV1::EmptyDeactivate
        {
            return Err(ManagedModelAgentStackRuntimeError::InvalidDurableState);
        }
        let transition = self.snapshot.transition();
        if self
            .lookup_terminal(&pending.request, pending.response_channel)?
            .is_none()
        {
            self.terminalize_empty_exact_zero(
                fabric,
                &pending.request,
                pending.response_channel,
                transition,
                ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                54,
            )?;
        } else {
            let mut exact_zero = transition;
            make_exact_zero(&mut exact_zero);
            self.commit_transition(fabric, exact_zero)?;
        }
        self.recovery_completed = true;
        Ok(())
    }

    pub(crate) async fn shutdown(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        self.recovery_completed = false;
        self.revoke_handle()?;
        if self.shutdown_agent().await.is_err() {
            // A partially retired Agent may still hold Model/Fabric work. The
            // dependency order forbids retiring either provider here.
            return Err(ManagedModelAgentStackRuntimeError::ShutdownUncertain);
        }
        if !self.shutdown_model().await {
            let _ = fabric.stop_live_for_stack().await;
            return Err(ManagedModelAgentStackRuntimeError::ModelCleanupUncertain);
        }
        if self.snapshot.phase == ManagedModelAgentStackDurablePhase::ExactZero {
            return Ok(());
        }
        if !fabric.stop_live_for_stack().await? {
            return Err(ManagedModelAgentStackRuntimeError::ShutdownUncertain);
        }
        Ok(())
    }

    fn recovery_request(
        &self,
    ) -> Result<
        (
            ManagedModelAgentStackApplyRequestV1,
            ReferenceChannelBindingV1,
        ),
        ManagedModelAgentStackRuntimeError,
    > {
        match self.snapshot.phase {
            ManagedModelAgentStackDurablePhase::ActiveReady => {
                let active = self
                    .snapshot
                    .active
                    .as_ref()
                    .ok_or(ManagedModelAgentStackRuntimeError::InvalidDurableState)?;
                Ok((active.request.clone(), active.response_channel))
            }
            _ => {
                let pending = self
                    .snapshot
                    .pending
                    .as_ref()
                    .ok_or(ManagedModelAgentStackRuntimeError::InvalidDurableState)?;
                Ok((pending.request.clone(), pending.response_channel))
            }
        }
    }

    async fn start_model(
        &mut self,
        execution: &ManagedModelAgentStackTargetExecutionV1,
        generation: ManagedServiceGeneration,
    ) -> Result<ManagedModelDependencyHandle, ManagedModelAgentStackRuntimeError> {
        let model = *execution
            .model()
            .ok_or(ManagedModelAgentStackRuntimeError::InvalidDurableState)?;
        let agent_service_id = active_agent_service_id(execution)?;
        let (assembly, dependency) = ManagedModelAssembly::start(
            model,
            generation,
            agent_service_id,
            Arc::clone(&self.model_backend_resolver),
            self.clock,
            &self.cancellation,
        )
        .await?;
        self.model = Some(assembly);
        Ok(dependency)
    }

    async fn start_agent(
        &mut self,
        fabric: ManagedFabricControlHandle,
        execution: &ManagedModelAgentStackTargetExecutionV1,
        model_generation: ManagedServiceGeneration,
        model_dependency: ManagedModelDependencyHandle,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        let model_service_id = execution
            .model()
            .ok_or(ManagedModelAgentStackRuntimeError::InvalidDurableState)?
            .service()
            .service_id();
        let (agent, handle) = ManagedAgentAssembly::start_with_model_dependency(
            fabric,
            execution.managed_agent_stack(),
            self.state_directory.clone(),
            model_service_id,
            model_generation,
            model_dependency,
        )
        .await?;
        self.agent = Some(agent);
        self.handle = Some(handle);
        Ok(())
    }

    async fn shutdown_agent(&mut self) -> Result<(), ManagedAgentAssemblyError> {
        let Some(mut agent) = self.agent.take() else {
            self.handle = None;
            return Ok(());
        };
        self.handle = None;
        if let Err(error) = agent.shutdown().await {
            self.agent = Some(agent);
            return Err(error);
        }
        Ok(())
    }

    async fn shutdown_model(&mut self) -> bool {
        let exact_zero = {
            let Some(model) = self.model.as_mut() else {
                return true;
            };
            model.shutdown().await.exact_zero()
        };
        if exact_zero {
            self.model = None;
        }
        exact_zero
    }

    fn commit_recovery_model_intent(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        fabric_generation: ManagedServiceGeneration,
        model_generation: ManagedServiceGeneration,
        reading: ClockReading,
        deadline_nanos: u64,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        let mut intent = self.snapshot.transition();
        intent.fabric_generation_high_water = intent
            .fabric_generation_high_water
            .max(fabric_generation.value());
        intent.model_generation_high_water = model_generation.value();
        intent.phase = ManagedModelAgentStackDurablePhase::ModelStartIntent;
        intent.active = None;
        intent.pending = Some(ManagedModelAgentStackDurablePending {
            kind: ManagedModelAgentStackPendingKind::ActivateStack,
            fabric_generation: Some(fabric_generation),
            model_generation: Some(model_generation),
            agent_generation: None,
            admitted_clock_generation: reading.generation(),
            admitted_at_nanos: reading.now().value(),
            deadline_nanos,
            response_channel,
            request: request.clone(),
        });
        intent.physical_binding_census = 0;
        intent.census_complete = true;
        intent.fabric_ready = true;
        intent.model_ready = false;
        intent.agent_ready = false;
        intent.fabric_to_agent_dependency_ready = true;
        intent.model_to_agent_dependency_ready = false;
        intent.quarantine_reason = None;
        self.commit_transition(fabric, intent)
    }

    fn commit_agent_start_intent(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        agent_generation: ManagedServiceGeneration,
        pending_kind: ManagedModelAgentStackPendingKind,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        let pending = self
            .snapshot
            .pending
            .clone()
            .ok_or(ManagedModelAgentStackRuntimeError::InvalidDurableState)?;
        let mut intent = self.snapshot.transition();
        intent.agent_generation_high_water = agent_generation.value();
        intent.phase = match pending_kind {
            ManagedModelAgentStackPendingKind::RecoverActive => {
                ManagedModelAgentStackDurablePhase::RecoveryIntent
            }
            ManagedModelAgentStackPendingKind::ActivateStack => {
                ManagedModelAgentStackDurablePhase::AgentStartIntent
            }
            ManagedModelAgentStackPendingKind::DeactivateStack => {
                return Err(ManagedModelAgentStackRuntimeError::InvalidDurableState);
            }
        };
        intent.pending = Some(ManagedModelAgentStackDurablePending {
            kind: pending_kind,
            agent_generation: Some(agent_generation),
            ..pending
        });
        intent.physical_binding_census = 0;
        intent.census_complete = true;
        intent.fabric_ready = true;
        intent.model_ready = true;
        intent.agent_ready = false;
        intent.fabric_to_agent_dependency_ready = true;
        intent.model_to_agent_dependency_ready = true;
        intent.quarantine_reason = None;
        self.commit_transition(fabric, intent)
    }

    fn commit_active_ready(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        fabric_generation: ManagedServiceGeneration,
        model_generation: ManagedServiceGeneration,
        agent_generation: ManagedServiceGeneration,
        raw_code: u16,
    ) -> Result<ManagedModelAgentStackTerminalReceiptV1, ManagedModelAgentStackRuntimeError> {
        let receipt = self.build_terminal(
            request,
            response_channel,
            TerminalSelection {
                outcome: ManagedModelAgentStackTerminalOutcomeV1::ActiveReady,
                lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                head: ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                fabric_generation: Some(fabric_generation),
                model_generation: Some(model_generation),
                agent_generation: Some(agent_generation),
                physical_binding_census: 2,
                census_complete: true,
                fabric_ready: true,
                model_ready: true,
                agent_ready: true,
                fabric_to_agent_dependency_ready: true,
                model_to_agent_dependency_ready: true,
                exact_zero: false,
                quarantined: false,
                raw_code,
                raw_context: None,
            },
        )?;
        let mut ready = active_ready_transition(
            self.snapshot.transition(),
            request,
            response_channel,
            fabric_generation,
            model_generation,
            agent_generation,
        );
        insert_terminal(&mut ready.terminals, request, receipt.clone())?;
        if let Err(error) = self.commit_transition(fabric, ready) {
            return Err(error);
        }
        Ok(receipt)
    }

    fn commit_active_ready_without_terminal(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        fabric_generation: ManagedServiceGeneration,
        model_generation: ManagedServiceGeneration,
        agent_generation: ManagedServiceGeneration,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        let ready = active_ready_transition(
            self.snapshot.transition(),
            request,
            response_channel,
            fabric_generation,
            model_generation,
            agent_generation,
        );
        self.commit_transition(fabric, ready)
    }

    fn commit_fabric_stop_intent(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        let mut intent = self.snapshot.transition();
        intent.phase = ManagedModelAgentStackDurablePhase::FabricStopIntent;
        intent.physical_binding_census = 0;
        intent.census_complete = true;
        intent.fabric_ready = true;
        intent.model_ready = false;
        intent.agent_ready = false;
        intent.fabric_to_agent_dependency_ready = false;
        intent.model_to_agent_dependency_ready = false;
        intent.quarantine_reason = None;
        self.commit_transition(fabric, intent)
    }

    fn publish_handle(
        &self,
        receipt: &ManagedModelAgentStackTerminalReceiptV1,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        let handle = self
            .handle
            .as_ref()
            .ok_or(ManagedModelAgentStackRuntimeError::InvalidDurableState)?;
        self.handle_broker
            .publish_model_agent(handle.clone(), receipt)
            .map_err(|_| ManagedModelAgentStackRuntimeError::HandleBrokerUnavailable)
    }

    fn revoke_handle(&mut self) -> Result<(), ManagedModelAgentStackRuntimeError> {
        self.handle_broker
            .revoke()
            .map_err(|_| ManagedModelAgentStackRuntimeError::HandleBrokerUnavailable)?;
        self.handle = None;
        Ok(())
    }

    fn validate_request(
        &self,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        request
            .validate_expected_store(self.snapshot.store_instance_id())
            .map_err(|_| ManagedModelAgentStackRuntimeError::RequestRejected)?;
        request
            .validate_projection(&self.projection)
            .map_err(|_| ManagedModelAgentStackRuntimeError::ProjectionMismatch)?;
        if request.target() != self.projection.target()
            || response_channel.target() != request.target()
        {
            return Err(ManagedModelAgentStackRuntimeError::RequestRejected);
        }
        Ok(())
    }

    fn lookup_terminal(
        &self,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
    ) -> Result<Option<ManagedModelAgentStackTerminalReceiptV1>, ManagedModelAgentStackRuntimeError>
    {
        let source_scope = request.provenance().source_scope();
        let operation_id = request.operation_id();
        let Some(record) = self.snapshot.terminals.iter().find(|record| {
            record.source_scope == source_scope && record.operation_id == operation_id
        }) else {
            return Ok(None);
        };
        if record.request_digest != request.envelope_request_digest() {
            return Err(ManagedModelAgentStackRuntimeError::OperationConflict);
        }
        record
            .receipt
            .validate_against_request(request, response_channel)
            .map_err(|_| ManagedModelAgentStackRuntimeError::TerminalCorrelation)?;
        Ok(Some(record.receipt.clone()))
    }

    fn admit_transition(
        &self,
        request: &ManagedModelAgentStackApplyRequestV1,
        verified: VerifiedManagedModelAgentStackApplyIngressV1,
    ) -> Result<ManagedModelAgentStackSnapshotTransition, ManagedModelAgentStackRuntimeError> {
        self.validate_cas(request)?;
        let writer = request.control_commitment().control().writer_context();
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
            Some(_) => return Err(ManagedModelAgentStackRuntimeError::StaleWriter),
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
            Some(_) => return Err(ManagedModelAgentStackRuntimeError::StaleRevision),
        };
        let mut transition = self.snapshot.transition();
        transition.writer_fence = Some(writer_fence);
        transition.revision_high_water = Some(revision_high_water);
        insert_verified_replays(&mut transition, verified, request.envelope_request_digest())?;
        Ok(transition)
    }

    fn validate_cas(
        &self,
        request: &ManagedModelAgentStackApplyRequestV1,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
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
            _ => Err(ManagedModelAgentStackRuntimeError::ExpectedActiveMismatch),
        }
    }

    fn terminalize_no_effect(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        raw_code: u16,
        mut transition: ManagedModelAgentStackSnapshotTransition,
    ) -> Result<ManagedModelAgentStackTerminalReceiptV1, ManagedModelAgentStackRuntimeError> {
        let selection = self.snapshot.active.as_ref().map_or(
            TerminalSelection {
                outcome: ManagedModelAgentStackTerminalOutcomeV1::NoEffectRejected,
                lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1::ProvenNotStarted,
                head: ManagedModelAgentStackTerminalHeadV1::PreservedNone,
                fabric_generation: None,
                model_generation: None,
                agent_generation: None,
                physical_binding_census: 0,
                census_complete: true,
                fabric_ready: false,
                model_ready: false,
                agent_ready: false,
                fabric_to_agent_dependency_ready: false,
                model_to_agent_dependency_ready: false,
                exact_zero: true,
                quarantined: false,
                raw_code,
                raw_context: None,
            },
            |active| TerminalSelection {
                outcome: ManagedModelAgentStackTerminalOutcomeV1::NoEffectRejected,
                lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1::ProvenNotStarted,
                head: ManagedModelAgentStackTerminalHeadV1::PreservedExisting(
                    active.request.target_slice_digest(),
                ),
                fabric_generation: Some(active.fabric_generation),
                model_generation: Some(active.model_generation),
                agent_generation: Some(active.agent_generation),
                physical_binding_census: 2,
                census_complete: true,
                fabric_ready: true,
                model_ready: true,
                agent_ready: true,
                fabric_to_agent_dependency_ready: true,
                model_to_agent_dependency_ready: true,
                exact_zero: false,
                quarantined: false,
                raw_code,
                raw_context: None,
            },
        );
        let receipt = self.build_terminal(request, response_channel, selection)?;
        insert_terminal(&mut transition.terminals, request, receipt.clone())?;
        self.commit_transition(fabric, transition)?;
        Ok(receipt)
    }

    fn terminalize_empty_exact_zero(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        mut transition: ManagedModelAgentStackSnapshotTransition,
        lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1,
        raw_code: u16,
    ) -> Result<ManagedModelAgentStackTerminalReceiptV1, ManagedModelAgentStackRuntimeError> {
        let receipt = self.build_terminal(
            request,
            response_channel,
            TerminalSelection {
                outcome: ManagedModelAgentStackTerminalOutcomeV1::EmptyExactZero,
                lifecycle_effect,
                head: ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                fabric_generation: None,
                model_generation: None,
                agent_generation: None,
                physical_binding_census: 0,
                census_complete: true,
                fabric_ready: false,
                model_ready: false,
                agent_ready: false,
                fabric_to_agent_dependency_ready: false,
                model_to_agent_dependency_ready: false,
                exact_zero: true,
                quarantined: false,
                raw_code,
                raw_context: None,
            },
        )?;
        make_exact_zero(&mut transition);
        insert_terminal(&mut transition.terminals, request, receipt.clone())?;
        self.commit_transition(fabric, transition)?;
        Ok(receipt)
    }

    fn terminalize_quarantined(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        raw_code: u16,
        observation: QuarantineObservation,
    ) -> Result<ManagedModelAgentStackTerminalReceiptV1, ManagedModelAgentStackRuntimeError> {
        let reason =
            quarantine_reason_digest(raw_code, request, observation.model_cleanup_exact_zero)?;
        let receipt = self.build_terminal(
            request,
            response_channel,
            TerminalSelection {
                outcome: ManagedModelAgentStackTerminalOutcomeV1::Quarantined,
                lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                head: ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                fabric_generation: observation.fabric_generation,
                model_generation: observation.model_generation,
                agent_generation: observation.agent_generation,
                physical_binding_census: observation.physical_binding_census,
                census_complete: observation.census_complete,
                fabric_ready: observation.fabric_ready,
                model_ready: observation.model_ready,
                agent_ready: false,
                fabric_to_agent_dependency_ready: false,
                model_to_agent_dependency_ready: false,
                exact_zero: false,
                quarantined: true,
                raw_code,
                raw_context: Some(reason),
            },
        )?;
        let mut quarantined = self.snapshot.transition();
        apply_quarantine_observation(&mut quarantined, observation, reason);
        insert_terminal(&mut quarantined.terminals, request, receipt.clone())?;
        self.commit_transition(fabric, quarantined)?;
        Ok(receipt)
    }

    fn quarantine_recovery(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        raw_code: u16,
        observation: QuarantineObservation,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        let reason =
            quarantine_reason_digest(raw_code, request, observation.model_cleanup_exact_zero)?;
        let mut quarantined = self.snapshot.transition();
        apply_quarantine_observation(&mut quarantined, observation, reason);
        if self.lookup_terminal(request, response_channel)?.is_none() {
            let receipt = self.build_terminal(
                request,
                response_channel,
                TerminalSelection {
                    outcome: ManagedModelAgentStackTerminalOutcomeV1::Quarantined,
                    lifecycle_effect:
                        ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                    head: ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                    fabric_generation: observation.fabric_generation,
                    model_generation: observation.model_generation,
                    agent_generation: observation.agent_generation,
                    physical_binding_census: observation.physical_binding_census,
                    census_complete: observation.census_complete,
                    fabric_ready: observation.fabric_ready,
                    model_ready: observation.model_ready,
                    agent_ready: false,
                    fabric_to_agent_dependency_ready: false,
                    model_to_agent_dependency_ready: false,
                    exact_zero: false,
                    quarantined: true,
                    raw_code,
                    raw_context: Some(reason),
                },
            )?;
            insert_terminal(&mut quarantined.terminals, request, receipt)?;
        }
        self.commit_transition(fabric, quarantined)
    }

    fn terminalize_uncertain(
        &mut self,
        fabric: &mut ManagedFabricRuntimeCore,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        raw_code: u16,
        fabric_generation: Option<ManagedServiceGeneration>,
        model_generation: Option<ManagedServiceGeneration>,
        agent_generation: Option<ManagedServiceGeneration>,
    ) -> Result<ManagedModelAgentStackTerminalReceiptV1, ManagedModelAgentStackRuntimeError> {
        let receipt = self.build_terminal(
            request,
            response_channel,
            TerminalSelection {
                outcome: ManagedModelAgentStackTerminalOutcomeV1::Uncertain,
                lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
                head: ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
                fabric_generation,
                model_generation,
                agent_generation,
                physical_binding_census: 0,
                census_complete: false,
                fabric_ready: false,
                model_ready: false,
                agent_ready: false,
                fabric_to_agent_dependency_ready: false,
                model_to_agent_dependency_ready: false,
                exact_zero: false,
                quarantined: false,
                raw_code,
                raw_context: None,
            },
        )?;
        let mut uncertain = self.snapshot.transition();
        uncertain.phase = ManagedModelAgentStackDurablePhase::Uncertain;
        uncertain.physical_binding_census = 0;
        uncertain.census_complete = false;
        uncertain.fabric_ready = false;
        uncertain.model_ready = false;
        uncertain.agent_ready = false;
        uncertain.fabric_to_agent_dependency_ready = false;
        uncertain.model_to_agent_dependency_ready = false;
        uncertain.quarantine_reason = None;
        insert_terminal(&mut uncertain.terminals, request, receipt.clone())?;
        self.commit_transition(fabric, uncertain)?;
        Ok(receipt)
    }

    fn build_terminal(
        &self,
        request: &ManagedModelAgentStackApplyRequestV1,
        response_channel: ReferenceChannelBindingV1,
        selection: TerminalSelection,
    ) -> Result<ManagedModelAgentStackTerminalReceiptV1, ManagedModelAgentStackRuntimeError> {
        let reading = self.clock.reading()?;
        let completion_sequence = self
            .snapshot
            .sequence()
            .checked_add(1)
            .ok_or(ManagedModelAgentStackRuntimeError::SequenceOverflow)?;
        let state = ManagedModelAgentStackTerminalStateV1::try_new(
            selection.outcome,
            selection.lifecycle_effect,
            selection.head,
            selection.fabric_generation,
            selection.model_generation,
            selection.agent_generation,
        )?;
        let evidence = ManagedModelAgentStackTerminalEvidenceV1::try_new(
            ManagedModelAgentStackTerminalEvidenceFieldsV1 {
                physical_binding_census: selection.physical_binding_census,
                census_complete: selection.census_complete,
                fabric_ready: selection.fabric_ready,
                model_ready: selection.model_ready,
                agent_ready: selection.agent_ready,
                fabric_to_agent_dependency_ready: selection.fabric_to_agent_dependency_ready,
                model_to_agent_dependency_ready: selection.model_to_agent_dependency_ready,
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
        let facts = ManagedModelAgentStackTerminalFactsV1::try_new(request, state, evidence)?;
        let algorithm = ApplyAuthAlgorithm::try_new(1)
            .map_err(|_| ManagedModelAgentStackRuntimeError::SignerConfiguration)?;
        let auth_claim = ManagedModelAgentStackTerminalAuthClaimV1::try_new(
            response_channel,
            self.response_key_ref,
            algorithm,
            1,
        )?;
        let draft = ManagedModelAgentStackTerminalReceiptDraftV1::try_new(
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
        transition: ManagedModelAgentStackSnapshotTransition,
    ) -> Result<(), ManagedModelAgentStackRuntimeError> {
        let next = self.snapshot.try_successor_at_epoch(
            self.runtime_host_epoch,
            transition,
            &self.projection,
        )?;
        fabric.commit_managed_model_agent_stack(next.canonical_wire())?;
        self.snapshot = next;
        Ok(())
    }
}

fn build_pre_cutover_no_effect_terminal(
    config: &ManagedModelAgentStackOwnerConfig,
    request: &ManagedModelAgentStackApplyRequestV1,
    response_channel: ReferenceChannelBindingV1,
    fabric_generation: ManagedServiceGeneration,
    raw_code: u16,
) -> Result<ManagedModelAgentStackTerminalReceiptV1, ManagedModelAgentStackRuntimeError> {
    let reading = config.clock.reading()?;
    let selection = TerminalSelection {
        outcome: ManagedModelAgentStackTerminalOutcomeV1::NoEffectRejected,
        lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1::ProvenNotStarted,
        head: ManagedModelAgentStackTerminalHeadV1::PreservedNone,
        fabric_generation: Some(fabric_generation),
        model_generation: None,
        agent_generation: None,
        physical_binding_census: 0,
        census_complete: true,
        fabric_ready: true,
        model_ready: false,
        agent_ready: false,
        fabric_to_agent_dependency_ready: false,
        model_to_agent_dependency_ready: false,
        exact_zero: false,
        quarantined: false,
        raw_code,
        raw_context: None,
    };
    let state = ManagedModelAgentStackTerminalStateV1::try_new(
        selection.outcome,
        selection.lifecycle_effect,
        selection.head,
        selection.fabric_generation,
        selection.model_generation,
        selection.agent_generation,
    )?;
    let evidence = ManagedModelAgentStackTerminalEvidenceV1::try_new(
        ManagedModelAgentStackTerminalEvidenceFieldsV1 {
            physical_binding_census: selection.physical_binding_census,
            census_complete: selection.census_complete,
            fabric_ready: selection.fabric_ready,
            model_ready: selection.model_ready,
            agent_ready: selection.agent_ready,
            fabric_to_agent_dependency_ready: selection.fabric_to_agent_dependency_ready,
            model_to_agent_dependency_ready: selection.model_to_agent_dependency_ready,
            exact_zero: selection.exact_zero,
            quarantined: selection.quarantined,
            resource_census_digest: resource_census_digest(selection)?,
            raw_outcome_digest: raw_outcome_digest(selection, request)?,
            completion_runtime_host_epoch: config.runtime_host_epoch,
            // No PXMA authority is installed for a proven-no-effect cutover.
            // Sequence one identifies this standalone selection decision and
            // is never presented as a committed PXMA snapshot.
            completion_snapshot_sequence: 1,
            selection_clock_generation: reading.generation(),
            selection_observed_at_nanos: reading.now().value(),
        },
    )?;
    let facts = ManagedModelAgentStackTerminalFactsV1::try_new(request, state, evidence)?;
    let algorithm = ApplyAuthAlgorithm::try_new(1)
        .map_err(|_| ManagedModelAgentStackRuntimeError::SignerConfiguration)?;
    let auth_claim = ManagedModelAgentStackTerminalAuthClaimV1::try_new(
        response_channel,
        config.response_key_ref,
        algorithm,
        1,
    )?;
    let draft = ManagedModelAgentStackTerminalReceiptDraftV1::try_new(
        request,
        facts,
        response_channel,
        auth_claim,
    )?;
    let signature = config
        .response_signer
        .sign(draft.signing_transcript()?.as_bytes());
    Ok(draft.finalize(&signature.to_bytes())?)
}

fn validate_cutover_request(
    fabric: &ManagedFabricRuntimeCore,
    config: &ManagedModelAgentStackOwnerConfig,
    request: &ManagedModelAgentStackApplyRequestV1,
    response_channel: ReferenceChannelBindingV1,
) -> Result<(), ManagedModelAgentStackRuntimeError> {
    if fabric
        .managed_model_agent_stack_projection_digest()
        .is_some()
        || request.target_execution().mode()
            != ManagedModelAgentStackTargetModeV1::FabricModelAndAgent
        || request.target_execution().projection() != &config.projection
        || request.target() != config.projection.target()
        || request.expected_runtime_store_instance_id() != fabric.store_instance_id()
        || response_channel.target() != request.target()
        || !config.state_directory.is_absolute()
    {
        return Err(ManagedModelAgentStackRuntimeError::RequestRejected);
    }
    active_agent_service_id(request.target_execution())?;
    Ok(())
}

fn validate_cutover_cas_and_fabric(
    request: &ManagedModelAgentStackApplyRequestV1,
    predecessor: &ManagedFabricStackCutoverObservation,
) -> Result<(), ManagedModelAgentStackRuntimeError> {
    if request.target_execution().managed_agent_stack().fabric() != &predecessor.execution
        || request.control_commitment().control().expected_active()
            != ExpectedActive::Exact(predecessor.target_slice_digest)
    {
        return Err(ManagedModelAgentStackRuntimeError::FabricChangeRequiresEmpty);
    }
    Ok(())
}

fn active_agent_service_id(
    execution: &ManagedModelAgentStackTargetExecutionV1,
) -> Result<ManagedServiceId, ManagedModelAgentStackRuntimeError> {
    let agent = execution
        .managed_agent_stack()
        .agent()
        .ok_or(ManagedModelAgentStackRuntimeError::InvalidDurableState)?;
    let model = execution
        .model()
        .ok_or(ManagedModelAgentStackRuntimeError::InvalidDurableState)?;
    if agent.provider() != model.provider() {
        return Err(ManagedModelAgentStackRuntimeError::InvalidDurableState);
    }
    Ok(agent.service().service_id())
}

fn initial_model_intent_transition(
    request: &ManagedModelAgentStackApplyRequestV1,
    verified: VerifiedManagedModelAgentStackApplyIngressV1,
    response_channel: ReferenceChannelBindingV1,
    fabric_generation: ManagedServiceGeneration,
    model_generation: ManagedServiceGeneration,
) -> Result<ManagedModelAgentStackSnapshotTransition, ManagedModelAgentStackRuntimeError> {
    let proof_digest = verified.authenticated().proof_envelope_digest();
    let mut transition = ManagedModelAgentStackSnapshotTransition {
        fabric_generation_high_water: fabric_generation.value(),
        model_generation_high_water: model_generation.value(),
        agent_generation_high_water: 0,
        phase: ManagedModelAgentStackDurablePhase::ModelStartIntent,
        writer_fence: Some(writer_fence(request, proof_digest)),
        revision_high_water: Some(revision_high_water(request)),
        active: None,
        pending: Some(ManagedModelAgentStackDurablePending {
            kind: ManagedModelAgentStackPendingKind::ActivateStack,
            fabric_generation: Some(fabric_generation),
            model_generation: Some(model_generation),
            agent_generation: None,
            admitted_clock_generation: verified.clock_generation(),
            admitted_at_nanos: verified.admitted_at_nanos(),
            deadline_nanos: verified.deadline_nanos(),
            response_channel,
            request: request.clone(),
        }),
        tenure_nonces: Vec::new(),
        request_nonces: Vec::new(),
        temporal_lineages: Vec::new(),
        terminals: Vec::new(),
        physical_binding_census: 0,
        census_complete: true,
        fabric_ready: true,
        model_ready: false,
        agent_ready: false,
        fabric_to_agent_dependency_ready: true,
        model_to_agent_dependency_ready: false,
        quarantine_reason: None,
    };
    insert_verified_replays(&mut transition, verified, request.envelope_request_digest())?;
    Ok(transition)
}

fn active_ready_transition(
    mut transition: ManagedModelAgentStackSnapshotTransition,
    request: &ManagedModelAgentStackApplyRequestV1,
    response_channel: ReferenceChannelBindingV1,
    fabric_generation: ManagedServiceGeneration,
    model_generation: ManagedServiceGeneration,
    agent_generation: ManagedServiceGeneration,
) -> ManagedModelAgentStackSnapshotTransition {
    transition.phase = ManagedModelAgentStackDurablePhase::ActiveReady;
    transition.active = Some(ManagedModelAgentStackDurableActive {
        fabric_generation,
        model_generation,
        agent_generation,
        response_channel,
        request: request.clone(),
    });
    transition.pending = None;
    transition.physical_binding_census = 2;
    transition.census_complete = true;
    transition.fabric_ready = true;
    transition.model_ready = true;
    transition.agent_ready = true;
    transition.fabric_to_agent_dependency_ready = true;
    transition.model_to_agent_dependency_ready = true;
    transition.quarantine_reason = None;
    transition
}

fn make_exact_zero(transition: &mut ManagedModelAgentStackSnapshotTransition) {
    transition.phase = ManagedModelAgentStackDurablePhase::ExactZero;
    transition.active = None;
    transition.pending = None;
    transition.physical_binding_census = 0;
    transition.census_complete = true;
    transition.fabric_ready = false;
    transition.model_ready = false;
    transition.agent_ready = false;
    transition.fabric_to_agent_dependency_ready = false;
    transition.model_to_agent_dependency_ready = false;
    transition.quarantine_reason = None;
}

fn apply_quarantine_observation(
    transition: &mut ManagedModelAgentStackSnapshotTransition,
    observation: QuarantineObservation,
    reason: Digest32,
) {
    transition.phase = ManagedModelAgentStackDurablePhase::Quarantined;
    transition.physical_binding_census = observation.physical_binding_census;
    transition.census_complete = observation.census_complete;
    transition.fabric_ready = observation.fabric_ready;
    transition.model_ready = observation.model_ready;
    transition.agent_ready = false;
    transition.fabric_to_agent_dependency_ready = false;
    transition.model_to_agent_dependency_ready = false;
    transition.quarantine_reason = Some(reason);
}

fn writer_fence(
    request: &ManagedModelAgentStackApplyRequestV1,
    proof_envelope_digest: Digest32,
) -> ManagedModelAgentStackWriterFence {
    let writer = request.control_commitment().control().writer_context();
    let claim = writer.proof().claim();
    ManagedModelAgentStackWriterFence {
        source_scope: claim.source_scope(),
        writer: claim.writer(),
        principal: request.authentication().claim().principal(),
        epoch: claim.epoch().value(),
        proof_envelope_digest,
    }
}

fn revision_high_water(
    request: &ManagedModelAgentStackApplyRequestV1,
) -> ManagedModelAgentStackRevisionHighWater {
    let provenance = request.provenance();
    ManagedModelAgentStackRevisionHighWater {
        source_scope: provenance.source_scope(),
        revision: provenance.source_revision().value(),
        source_plan_digest: provenance.source_plan_digest(),
    }
}

fn insert_verified_replays(
    transition: &mut ManagedModelAgentStackSnapshotTransition,
    verified: VerifiedManagedModelAgentStackApplyIngressV1,
    request_digest: Digest32,
) -> Result<(), ManagedModelAgentStackRuntimeError> {
    insert_replay(
        &mut transition.tenure_nonces,
        ManagedModelAgentStackReplayRecord {
            identity: verified.authenticated().tenure_nonce_identity(),
            value_digest: verified.authenticated().proof_envelope_digest(),
        },
    )?;
    insert_replay(
        &mut transition.request_nonces,
        ManagedModelAgentStackReplayRecord {
            identity: verified.authenticated().request_nonce_identity(),
            value_digest: request_digest,
        },
    )?;
    insert_replay(
        &mut transition.temporal_lineages,
        ManagedModelAgentStackReplayRecord {
            identity: verified.authenticated().temporal_lineage_identity(),
            value_digest: request_digest,
        },
    )
}

fn insert_replay(
    records: &mut Vec<ManagedModelAgentStackReplayRecord>,
    incoming: ManagedModelAgentStackReplayRecord,
) -> Result<(), ManagedModelAgentStackRuntimeError> {
    match records.binary_search_by_key(&incoming.identity, |record| record.identity) {
        Ok(index) if records[index].value_digest == incoming.value_digest => Ok(()),
        Ok(_) => Err(ManagedModelAgentStackRuntimeError::ReplayConflict),
        Err(index) if records.len() < MAX_STACK_REPLAY_RECORDS => {
            records.insert(index, incoming);
            Ok(())
        }
        Err(_) => Err(ManagedModelAgentStackRuntimeError::ReplayCapacityReached),
    }
}

fn insert_terminal(
    records: &mut Vec<ManagedModelAgentStackTerminalRecord>,
    request: &ManagedModelAgentStackApplyRequestV1,
    receipt: ManagedModelAgentStackTerminalReceiptV1,
) -> Result<(), ManagedModelAgentStackRuntimeError> {
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
        Ok(index)
            if records[index].request_digest == request.envelope_request_digest()
                && records[index].receipt == receipt =>
        {
            Ok(())
        }
        Ok(_) => Err(ManagedModelAgentStackRuntimeError::OperationConflict),
        Err(index) if records.len() < MAX_STACK_REPLAY_RECORDS => {
            records.insert(
                index,
                ManagedModelAgentStackTerminalRecord {
                    source_scope: request.provenance().source_scope(),
                    operation_id: request.operation_id(),
                    request_digest: request.envelope_request_digest(),
                    receipt,
                },
            );
            Ok(())
        }
        Err(_) => Err(ManagedModelAgentStackRuntimeError::ReplayCapacityReached),
    }
}

fn observe_deadline(
    clock: RuntimeClock,
    verified: VerifiedManagedModelAgentStackApplyIngressV1,
) -> Result<(), ManagedModelAgentStackRuntimeError> {
    let reading = clock.reading()?;
    if reading.generation() != verified.clock_generation()
        || reading.now().value() >= verified.deadline_nanos()
    {
        return Err(ManagedModelAgentStackRuntimeError::DeadlineExpired);
    }
    Ok(())
}

fn recovery_deadline(
    request: &ManagedModelAgentStackApplyRequestV1,
    reading: ClockReading,
) -> Result<u64, ManagedModelAgentStackRuntimeError> {
    reading
        .now()
        .value()
        .checked_add(request.temporal().original_budget().value())
        .ok_or(ManagedModelAgentStackRuntimeError::DeadlineOverflow)
}

fn next_generation(
    high_water: u64,
) -> Result<ManagedServiceGeneration, ManagedModelAgentStackRuntimeError> {
    high_water
        .checked_add(1)
        .ok_or(ManagedModelAgentStackRuntimeError::GenerationExhausted)
        .and_then(|value| {
            ManagedServiceGeneration::try_new(value)
                .map_err(|_| ManagedModelAgentStackRuntimeError::GenerationExhausted)
        })
}

fn stack_projection_digest(
    projection: &ManagedModelAgentStackProjectionV1,
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
    builder.field_u16(u16::from(selection.model_ready))?;
    builder.field_u16(u16::from(selection.agent_ready))?;
    builder.field_u16(u16::from(selection.fabric_to_agent_dependency_ready))?;
    builder.field_u16(u16::from(selection.model_to_agent_dependency_ready))?;
    builder.field_u64(
        selection
            .fabric_generation
            .map_or(0, ManagedServiceGeneration::value),
    )?;
    builder.field_u64(
        selection
            .model_generation
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
    request: &ManagedModelAgentStackApplyRequestV1,
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
    request: &ManagedModelAgentStackApplyRequestV1,
    model_cleanup_exact_zero: Option<bool>,
) -> Result<Digest32, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(STACK_QUARANTINE_DIGEST_DOMAIN)?;
    builder.field_u16(code)?;
    builder.field_u16(match model_cleanup_exact_zero {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    })?;
    builder.field_digest(&request.envelope_request_digest())?;
    Ok(builder.finish())
}

fn model_start_cleanup_exact_zero(error: &ManagedModelAgentStackRuntimeError) -> Option<bool> {
    match error {
        ManagedModelAgentStackRuntimeError::Model(ManagedModelAssemblyError::StartupFailed {
            cleanup,
            ..
        }) => Some(cleanup.exact_zero()),
        ManagedModelAgentStackRuntimeError::Model(
            ManagedModelAssemblyError::InvalidConsumerAgentIdentity
            | ManagedModelAssemblyError::DependencyIdentityCollision,
        ) => Some(true),
        _ => None,
    }
}

#[derive(Debug)]
pub(crate) enum ManagedModelAgentStackRuntimeError {
    RequestRejected,
    ProjectionMismatch,
    FabricChangeRequiresEmpty,
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
    ModelCleanupUncertain,
    Digest(DigestBuildError),
    Contract(ManagedModelAgentStackPlanError),
    State(ManagedModelAgentStackStateError),
    Fabric(ManagedFabricRuntimeError),
    Agent(ManagedAgentAssemblyError),
    Model(ManagedModelAssemblyError),
    Clock(RuntimeClockError),
}

impl ManagedModelAgentStackRuntimeError {
    pub(crate) const fn is_request_rejection(&self) -> bool {
        matches!(
            self,
            Self::RequestRejected
                | Self::ProjectionMismatch
                | Self::FabricChangeRequiresEmpty
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

impl fmt::Display for ManagedModelAgentStackRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed Model+Agent-stack Runtime failed: {self:?}"
        )
    }
}

impl std::error::Error for ManagedModelAgentStackRuntimeError {}

impl From<DigestBuildError> for ManagedModelAgentStackRuntimeError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl From<ManagedModelAgentStackPlanError> for ManagedModelAgentStackRuntimeError {
    fn from(value: ManagedModelAgentStackPlanError) -> Self {
        Self::Contract(value)
    }
}

impl From<ManagedModelAgentStackStateError> for ManagedModelAgentStackRuntimeError {
    fn from(value: ManagedModelAgentStackStateError) -> Self {
        Self::State(value)
    }
}

impl From<ManagedFabricRuntimeError> for ManagedModelAgentStackRuntimeError {
    fn from(value: ManagedFabricRuntimeError) -> Self {
        Self::Fabric(value)
    }
}

impl From<ManagedAgentAssemblyError> for ManagedModelAgentStackRuntimeError {
    fn from(value: ManagedAgentAssemblyError) -> Self {
        Self::Agent(value)
    }
}

impl From<ManagedModelAssemblyError> for ManagedModelAgentStackRuntimeError {
    fn from(value: ManagedModelAssemblyError) -> Self {
        Self::Model(value)
    }
}

impl From<RuntimeClockError> for ManagedModelAgentStackRuntimeError {
    fn from(value: RuntimeClockError) -> Self {
        Self::Clock(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(value: u64) -> ManagedServiceGeneration {
        ManagedServiceGeneration::try_new(value).expect("test generation must be nonzero")
    }

    fn selection(model_ready: bool) -> TerminalSelection {
        TerminalSelection {
            outcome: ManagedModelAgentStackTerminalOutcomeV1::Quarantined,
            lifecycle_effect: ManagedModelAgentStackTerminalLifecycleEffectV1::MayHaveStarted,
            head: ManagedModelAgentStackTerminalHeadV1::CommittedIncoming,
            fabric_generation: Some(generation(3)),
            model_generation: Some(generation(4)),
            agent_generation: Some(generation(5)),
            physical_binding_census: 0,
            census_complete: true,
            fabric_ready: true,
            model_ready,
            agent_ready: false,
            fabric_to_agent_dependency_ready: false,
            model_to_agent_dependency_ready: false,
            exact_zero: false,
            quarantined: true,
            raw_code: 1,
            raw_context: None,
        }
    }

    #[test]
    fn generation_allocation_is_monotonic_and_fails_at_the_numeric_fence() {
        assert_eq!(
            next_generation(7).expect("next generation must exist"),
            generation(8)
        );
        assert!(matches!(
            next_generation(u64::MAX),
            Err(ManagedModelAgentStackRuntimeError::GenerationExhausted)
        ));
    }

    #[test]
    fn resource_census_commits_model_readiness_independently() {
        let ready = resource_census_digest(selection(true)).expect("digest must build");
        let not_ready = resource_census_digest(selection(false)).expect("digest must build");
        assert_ne!(ready, not_ready);
    }
}
