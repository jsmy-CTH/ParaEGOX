//! Production owner for the fixed v5 reference Loop profile.
//!
//! The reference profile has no mailbox, dispatch, or background-task slots.
//! Its sole same-build source Card is therefore owned directly by one bounded
//! in-process Loop token.  The Card callback seam remains a Future, but this
//! fixed implementation is specified to complete on its first poll; a pending
//! callback is rejected instead of spawning detached work or blocking the
//! current-thread Runtime reactor.

use core::task::{Context, Poll, Waker};
#[cfg(test)]
use std::cell::RefCell;
use std::{collections::BTreeSet, fs::File, io::Read, path::Path};

use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
};
use paraegox_kernel::{
    digest::{Digest32, Digest32Builder},
    identity::RuntimeHostId,
    time::ClockReading,
};
use paraegox_runtime_contracts::{
    assignment::InstanceRef,
    execution::DomainRef,
    installation::RuntimeCompiledInstallationFactsV1,
    provenance::{PlanProvenance, SourcePlanRevision, TargetSliceDigest},
    reference_control::{
        ReferenceApplyRequestV1, ReferenceTargetExecutionPlanV4,
        ValidatedReferenceLifecycleBudgetsV1,
    },
};

use super::runtime_reference_apply::{
    RuntimeEmptyRetireOwnerPlan, RuntimeOneSourceOwnerPlan, RuntimeReferenceMaterializationOwner,
    RuntimeReferenceMaterializationOwnerError,
};
use crate::{
    card_instance::{
        CallbackFailure, CardContext, CardFuture, CardImplementation, CardInstanceIdentity,
        CardInstanceOwner, DomainEpoch, InputView, InstanceGeneration, OutputProposal,
        RuntimeHostEpoch,
    },
    runtime_clock::RuntimeClock,
    runtime_journal::{
        JournalActionKind, JournalActionRef, OpaqueCanonicalValue, OwnedResourceRecord,
        ResourceKind, ResourcePhase, RuntimeJournalSnapshot, RuntimeOneSourceOwnershipInput,
        RuntimeOneSourceResourceRefs, RuntimeOneSourceTombstonesInput,
        RuntimeResourceOwnershipInput, RuntimeResourceTombstoneInput,
    },
    task_registry::CancellationSource,
};

const OWNER_EVIDENCE_MAGIC: &[u8; 4] = b"PXOE";
const OWNER_EVIDENCE_VERSION: u16 = 1;
const OWNER_EVIDENCE_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.fixed-reference-owner-evidence.sha256.v1";
const ACTION_ID_ATTEMPTS: usize = 16;

#[cfg(test)]
thread_local! {
    static TEST_START_CALLBACK_ACTIONS: RefCell<Vec<[u8; 16]>> = const { RefCell::new(Vec::new()) };
    static TEST_STOP_CALLBACK_ACTIONS: RefCell<Vec<[u8; 16]>> = const { RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn reset_fixed_owner_callback_actions_for_test() {
    TEST_START_CALLBACK_ACTIONS.with(|actions| actions.borrow_mut().clear());
    TEST_STOP_CALLBACK_ACTIONS.with(|actions| actions.borrow_mut().clear());
}

#[cfg(test)]
pub(crate) fn fixed_owner_start_callback_actions_for_test() -> Vec<[u8; 16]> {
    TEST_START_CALLBACK_ACTIONS.with(|actions| actions.borrow().clone())
}

#[cfg(test)]
pub(crate) fn fixed_owner_stop_callback_actions_for_test() -> Vec<[u8; 16]> {
    TEST_STOP_CALLBACK_ACTIONS.with(|actions| actions.borrow().clone())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedReferenceBinding {
    target: RuntimeHostId,
    instance: InstanceRef,
    domain: DomainRef,
    source_revision: SourcePlanRevision,
    target_slice_digest: TargetSliceDigest,
    definition_digest: Digest32,
    artifact_digest: Digest32,
    config_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum FixedEvidenceClass {
    LoopProcess = 1,
    LoopNoWorkspace = 2,
    LoopContainment = 3,
    CardProcess = 4,
    CardNoWorkspace = 5,
    CardContainment = 6,
    LoopTombstone = 7,
    CardTombstone = 8,
    RestartLoopTombstone = 9,
    RestartCardTombstone = 10,
    RestartReservedLoopTombstone = 11,
    RestartReservedCardTombstone = 12,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixedLoopLifecycle {
    Allocated,
    Started,
    Stopped,
    Cleaned,
    Poisoned,
}

/// The actual resource owned for the zero-slot reference LoopDomain.
///
/// It retains the signed budgets, cancellation lineage, and sole Card owner.
/// There is deliberately no conversion to the legacy `RuntimePlanSliceV2` or
/// general component registry.
struct FixedReferenceLoopDomain {
    binding: FixedReferenceBinding,
    budgets: ValidatedReferenceLifecycleBudgetsV1,
    cancellation: CancellationSource,
    card: Option<CardInstanceOwner>,
    lifecycle: FixedLoopLifecycle,
}

impl FixedReferenceLoopDomain {
    fn start(
        &mut self,
        clock: RuntimeClock,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        if self.lifecycle == FixedLoopLifecycle::Started {
            return Ok(());
        }
        if self.lifecycle != FixedLoopLifecycle::Allocated {
            return Err(RuntimeReferenceMaterializationOwnerError::CallbackFailed);
        }
        let before = clock
            .reading()
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::CallbackFailed)?;
        let card = self
            .card
            .as_mut()
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
        card.begin_start()
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::CallbackFailed)?;
        let context = card_context(card, self.binding, before, &self.cancellation);
        let outcome = poll_immediate(card.implementation_mut().on_start(&context));
        let within_budget = reading_within_budget(clock, before, self.budgets.start().value());
        if outcome == Ok(Ok(())) && within_budget.is_ok() {
            card.finish_start(true)
                .map_err(|_| RuntimeReferenceMaterializationOwnerError::CallbackFailed)?;
            self.lifecycle = FixedLoopLifecycle::Started;
            Ok(())
        } else {
            let _ = card.finish_start(false);
            self.lifecycle = FixedLoopLifecycle::Poisoned;
            Err(RuntimeReferenceMaterializationOwnerError::CallbackFailed)
        }
    }

    fn stop(
        &mut self,
        clock: RuntimeClock,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        if self.lifecycle == FixedLoopLifecycle::Stopped {
            return Ok(());
        }
        if self.lifecycle != FixedLoopLifecycle::Started {
            return Err(RuntimeReferenceMaterializationOwnerError::CallbackFailed);
        }
        self.cancellation.cancel();
        let before = clock
            .reading()
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::CallbackFailed)?;
        let card = self
            .card
            .as_mut()
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
        card.begin_draining()
            .and_then(|()| card.begin_stop())
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::CallbackFailed)?;
        let context = card_context(card, self.binding, before, &self.cancellation);
        let outcome = poll_immediate(card.implementation_mut().on_stop(&context));
        let within_budget = reading_within_budget(clock, before, self.budgets.drain().value());
        if outcome == Ok(Ok(())) && within_budget.is_ok() {
            card.finish_stop()
                .map_err(|_| RuntimeReferenceMaterializationOwnerError::CallbackFailed)?;
            self.lifecycle = FixedLoopLifecycle::Stopped;
            Ok(())
        } else {
            card.poison();
            self.lifecycle = FixedLoopLifecycle::Poisoned;
            Err(RuntimeReferenceMaterializationOwnerError::CallbackFailed)
        }
    }

    fn cleanup(
        &mut self,
        clock: RuntimeClock,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        if self.lifecycle == FixedLoopLifecycle::Cleaned {
            return Ok(());
        }
        if self.lifecycle != FixedLoopLifecycle::Stopped {
            return Err(RuntimeReferenceMaterializationOwnerError::CleanupFailed);
        }
        let before = clock
            .reading()
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::CleanupFailed)?;
        self.card = None;
        if reading_within_budget(clock, before, self.budgets.cleanup().value()).is_err() {
            self.lifecycle = FixedLoopLifecycle::Poisoned;
            return Err(RuntimeReferenceMaterializationOwnerError::CleanupFailed);
        }
        self.lifecycle = FixedLoopLifecycle::Cleaned;
        Ok(())
    }

    fn cleanup_after_failed_start(
        &mut self,
        clock: RuntimeClock,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        if self.lifecycle == FixedLoopLifecycle::Cleaned {
            return Ok(());
        }
        if !matches!(
            self.lifecycle,
            FixedLoopLifecycle::Allocated
                | FixedLoopLifecycle::Started
                | FixedLoopLifecycle::Poisoned
        ) {
            return Err(RuntimeReferenceMaterializationOwnerError::CleanupFailed);
        }
        self.cancellation.cancel();
        let before = clock
            .reading()
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::CleanupFailed)?;
        self.card = None;
        if reading_within_budget(clock, before, self.budgets.cleanup().value()).is_err() {
            self.lifecycle = FixedLoopLifecycle::Poisoned;
            return Err(RuntimeReferenceMaterializationOwnerError::CleanupFailed);
        }
        self.lifecycle = FixedLoopLifecycle::Cleaned;
        Ok(())
    }
}

struct FixedOwnerToken {
    plan: RuntimeOneSourceOwnerPlan,
    binding: FixedReferenceBinding,
    cancellation: CancellationSource,
    domain: Option<Box<FixedReferenceLoopDomain>>,
    retire_action_id: Option<[u8; 16]>,
    retired_slice_digest: Option<TargetSliceDigest>,
}

impl FixedOwnerToken {
    fn is_cleaned(&self) -> bool {
        self.domain
            .as_deref()
            .is_some_and(|domain| domain.lifecycle == FixedLoopLifecycle::Cleaned)
    }
}

trait FixedReferenceOwnerEntropy: Send {
    fn action_id(&mut self) -> Result<[u8; 16], RuntimeReferenceMaterializationOwnerError>;
}

struct SystemFixedReferenceOwnerEntropy;

impl FixedReferenceOwnerEntropy for SystemFixedReferenceOwnerEntropy {
    fn action_id(&mut self) -> Result<[u8; 16], RuntimeReferenceMaterializationOwnerError> {
        let owned = open(
            Path::new("/dev/urandom"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)?;
        let mut source = File::from(owned);
        let mut action_id = [0_u8; 16];
        source
            .read_exact(&mut action_id)
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)?;
        Ok(action_id)
    }
}

/// Production materialization owner for exactly `OneSourceLoop` and
/// `EmptyDeactivate` under the executable-compiled fixture.
pub(crate) struct RuntimeFixedReferenceMaterializationOwner {
    compiled: RuntimeCompiledInstallationFactsV1,
    clock: RuntimeClock,
    root_cancellation: CancellationSource,
    entropy: Box<dyn FixedReferenceOwnerEntropy>,
    known_action_ids: BTreeSet<[u8; 16]>,
    next_generation: u64,
    runtime_host_epoch: u64,
    token: Option<FixedOwnerToken>,
}

impl RuntimeFixedReferenceMaterializationOwner {
    pub(crate) fn try_new(
        compiled: RuntimeCompiledInstallationFactsV1,
        clock: RuntimeClock,
        snapshot: &RuntimeJournalSnapshot,
    ) -> Result<Self, RuntimeReferenceMaterializationOwnerError> {
        Self::try_new_with_entropy(
            compiled,
            clock,
            snapshot,
            Box::new(SystemFixedReferenceOwnerEntropy),
        )
    }

    fn try_new_with_entropy(
        compiled: RuntimeCompiledInstallationFactsV1,
        clock: RuntimeClock,
        snapshot: &RuntimeJournalSnapshot,
        entropy: Box<dyn FixedReferenceOwnerEntropy>,
    ) -> Result<Self, RuntimeReferenceMaterializationOwnerError> {
        let state = snapshot.state();
        let compiled_compatibility = compiled
            .compiled_reference_compatibility_digest()
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        if state.host.runtime_host_epoch_high_water == 0
            || state.host.compiled_build_instance_id != compiled.compiled_build_instance_id()
            || state.host.compiled_compatibility_digest != compiled_compatibility
            || state.host.clock_domain != *clock.domain().as_bytes()
            || state.host.clock_generation_high_water != clock.generation().value()
        {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }
        let (known_action_ids, generation_high_water) = journal_owner_high_water(snapshot);
        let next_generation = generation_high_water
            .checked_add(1)
            .ok_or(RuntimeReferenceMaterializationOwnerError::Unavailable)?;
        Ok(Self {
            compiled,
            clock,
            root_cancellation: CancellationSource::root(),
            entropy,
            known_action_ids,
            next_generation,
            runtime_host_epoch: state.host.runtime_host_epoch_high_water,
            token: None,
        })
    }

    fn fresh_action_id(&mut self) -> Result<[u8; 16], RuntimeReferenceMaterializationOwnerError> {
        for _ in 0..ACTION_ID_ATTEMPTS {
            let action_id = self.entropy.action_id()?;
            if action_id.iter().any(|byte| *byte != 0) && self.known_action_ids.insert(action_id) {
                return Ok(action_id);
            }
        }
        Err(RuntimeReferenceMaterializationOwnerError::Unavailable)
    }

    fn fresh_generation(&mut self) -> Result<u64, RuntimeReferenceMaterializationOwnerError> {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or(RuntimeReferenceMaterializationOwnerError::Unavailable)?;
        Ok(generation)
    }

    fn start_token_mut(
        &mut self,
        action: JournalActionRef,
    ) -> Result<&mut FixedOwnerToken, RuntimeReferenceMaterializationOwnerError> {
        self.token
            .as_mut()
            .filter(|token| start_action_matches(token.plan, action))
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)
    }

    fn retire_token_mut(
        &mut self,
        action: JournalActionRef,
    ) -> Result<&mut FixedOwnerToken, RuntimeReferenceMaterializationOwnerError> {
        self.token
            .as_mut()
            .filter(|token| {
                action.kind == JournalActionKind::DrainToEmpty
                    && token.retire_action_id == Some(action.action_id)
                    && token.plan.domain_generation == action.domain_generation
                    && token.plan.instance_generation == action.instance_generation
                    && token.plan.resource_generation == action.resource_generation
            })
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)
    }
}

impl Drop for RuntimeFixedReferenceMaterializationOwner {
    fn drop(&mut self) {
        self.root_cancellation.cancel();
    }
}

impl RuntimeReferenceMaterializationOwner for RuntimeFixedReferenceMaterializationOwner {
    fn prepare_one_source(
        &mut self,
        request: &ReferenceApplyRequestV1,
        durable_action: Option<JournalActionRef>,
    ) -> Result<RuntimeOneSourceOwnerPlan, RuntimeReferenceMaterializationOwnerError> {
        let execution = request.target_execution();
        execution
            .validate_compiled_fixture(self.compiled)
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        let loop_facts = execution
            .loop_facts()
            .ok_or(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        let binding = FixedReferenceBinding {
            target: request.target(),
            instance: loop_facts.instance(),
            domain: loop_facts.domain(),
            source_revision: request.provenance().source_revision(),
            target_slice_digest: request.target_slice_digest(),
            definition_digest: execution.fixture_definition_digest(),
            artifact_digest: execution.fixture_artifact_digest(),
            config_digest: loop_facts.config_digest(),
        };

        let replace_cleaned = self.token.as_ref().is_some_and(FixedOwnerToken::is_cleaned);
        if self.token.is_none() || replace_cleaned {
            if durable_action.is_some() {
                return Err(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken);
            }
            let action_id = self.fresh_action_id()?;
            let generation = self.fresh_generation()?;
            let plan = RuntimeOneSourceOwnerPlan {
                action_id,
                domain_generation: generation,
                instance_generation: generation,
                resource_generation: generation,
                resources: RuntimeOneSourceResourceRefs {
                    loop_domain: *loop_facts.domain().as_bytes(),
                    card_instance: *loop_facts.instance().as_bytes(),
                },
                signed_budgets: loop_facts.budgets(),
            };
            self.token = Some(FixedOwnerToken {
                plan,
                binding,
                cancellation: self.root_cancellation.child(),
                domain: None,
                retire_action_id: None,
                retired_slice_digest: None,
            });
        }

        let token = self
            .token
            .as_ref()
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
        if token.binding != binding
            || token.plan.signed_budgets != loop_facts.budgets()
            || durable_action.is_some_and(|action| !start_action_matches(token.plan, action))
        {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }
        Ok(token.plan)
    }

    fn materialize_one_source(
        &mut self,
        action: JournalActionRef,
        resources: RuntimeOneSourceResourceRefs,
    ) -> Result<RuntimeOneSourceOwnershipInput, RuntimeReferenceMaterializationOwnerError> {
        let compiled_build = self.compiled.compiled_build_instance_id();
        let token = self.start_token_mut(action)?;
        if token.plan.resources != resources {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }
        if token.domain.is_none() {
            let identity = CardInstanceIdentity::new(
                token.binding.target,
                RuntimeHostEpoch::try_new(action.runtime_host_epoch)
                    .map_err(|_| RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?,
                token.binding.instance,
                token.binding.source_revision,
                token.binding.target_slice_digest,
                DomainEpoch::try_new(action.domain_generation)
                    .map_err(|_| RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?,
                InstanceGeneration::try_new(action.instance_generation)
                    .map_err(|_| RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?,
            );
            token.domain = Some(Box::new(FixedReferenceLoopDomain {
                binding: token.binding,
                budgets: token.plan.signed_budgets,
                cancellation: token.cancellation.clone(),
                card: Some(CardInstanceOwner::new(
                    identity,
                    Box::new(FixedIdleSourceCard::new()),
                )),
                lifecycle: FixedLoopLifecycle::Allocated,
            }));
        }
        ownership_evidence(token, action, compiled_build)
    }

    fn start_one_source_once(
        &mut self,
        action: JournalActionRef,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        #[cfg(test)]
        TEST_START_CALLBACK_ACTIONS.with(|actions| actions.borrow_mut().push(action.action_id));
        let clock = self.clock;
        self.start_token_mut(action)?
            .domain
            .as_deref_mut()
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?
            .start(clock)
    }

    fn prepare_empty_retire(
        &mut self,
        active_slice_digest: TargetSliceDigest,
        resource_generation: u64,
        durable_action: Option<JournalActionRef>,
    ) -> Result<RuntimeEmptyRetireOwnerPlan, RuntimeReferenceMaterializationOwnerError> {
        let token = self
            .token
            .as_ref()
            .filter(|token| {
                token.plan.resource_generation == resource_generation
                    && token.binding.target_slice_digest == active_slice_digest
                    && token.domain.as_deref().is_some_and(|domain| {
                        domain.lifecycle == FixedLoopLifecycle::Started
                            || domain.lifecycle == FixedLoopLifecycle::Stopped
                            || domain.lifecycle == FixedLoopLifecycle::Cleaned
                    })
            })
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
        if token
            .retired_slice_digest
            .is_some_and(|digest| digest != active_slice_digest)
        {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }

        if token.retire_action_id.is_none() {
            if durable_action.is_some() {
                return Err(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken);
            }
            let action_id = self.fresh_action_id()?;
            let token = self
                .token
                .as_mut()
                .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
            token.retire_action_id = Some(action_id);
            token.retired_slice_digest = Some(active_slice_digest);
        }
        let token = self
            .token
            .as_ref()
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
        let action_id = token
            .retire_action_id
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
        if durable_action.is_some_and(|action| {
            action.kind != JournalActionKind::DrainToEmpty
                || action.action_id != action_id
                || action.domain_generation != token.plan.domain_generation
                || action.instance_generation != token.plan.instance_generation
                || action.resource_generation != token.plan.resource_generation
        }) {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }
        Ok(RuntimeEmptyRetireOwnerPlan {
            action_id,
            signed_budgets: token.plan.signed_budgets,
        })
    }

    fn stop_one_source_once(
        &mut self,
        action: JournalActionRef,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        #[cfg(test)]
        TEST_STOP_CALLBACK_ACTIONS.with(|actions| actions.borrow_mut().push(action.action_id));
        let clock = self.clock;
        self.retire_token_mut(action)?
            .domain
            .as_deref_mut()
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?
            .stop(clock)
    }

    fn cleanup_one_source_once(
        &mut self,
        action: JournalActionRef,
    ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError> {
        let clock = self.clock;
        let compiled_build = self.compiled.compiled_build_instance_id();
        let token = self.retire_token_mut(action)?;
        token
            .domain
            .as_deref_mut()
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?
            .cleanup(clock)?;
        tombstone_evidence(token, action, compiled_build)
    }

    fn prove_restart_exact_zero(
        &mut self,
        execution: &ReferenceTargetExecutionPlanV4,
        provenance: PlanProvenance,
        target_slice_digest: TargetSliceDigest,
        resources: &[OwnedResourceRecord],
    ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError> {
        execution
            .validate_compiled_fixture(self.compiled)
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        let loop_facts = execution
            .loop_facts()
            .ok_or(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        let binding = fixed_binding(execution, provenance, target_slice_digest)?;
        let nonterminal = resources
            .iter()
            .filter(|resource| !resource.phase.is_terminal())
            .collect::<Vec<_>>();
        if nonterminal.len() != 2
            || nonterminal.iter().any(|resource| {
                !matches!(
                    resource.phase,
                    ResourcePhase::Reserved | ResourcePhase::Owned | ResourcePhase::CleanupPending
                ) || resource.runtime_host_epoch >= self.runtime_host_epoch
                    || match resource.phase {
                        ResourcePhase::Reserved => {
                            resource.os_identity.is_some()
                                || resource.workspace_identity.is_some()
                                || resource.containment_identity.is_some()
                        }
                        ResourcePhase::Owned | ResourcePhase::CleanupPending => {
                            resource.os_identity.is_none()
                                || resource.workspace_identity.is_none()
                                || resource.containment_identity.is_none()
                        }
                        ResourcePhase::Terminal | ResourcePhase::ReservedAtCrashExactZero => true,
                    }
            })
        {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }
        let loop_resource = nonterminal
            .iter()
            .find(|resource| {
                resource.kind == ResourceKind::LoopDomain
                    && resource.logical_ref == *loop_facts.domain().as_bytes()
            })
            .ok_or(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        let card_resource = nonterminal
            .iter()
            .find(|resource| {
                resource.kind == ResourceKind::CardInstance
                    && resource.logical_ref == *loop_facts.instance().as_bytes()
            })
            .ok_or(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        if loop_resource.generation != card_resource.generation
            || loop_resource.runtime_host_epoch != card_resource.runtime_host_epoch
        {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }
        Ok(RuntimeOneSourceTombstonesInput {
            loop_domain: RuntimeResourceTombstoneInput {
                logical_ref: loop_resource.logical_ref,
                evidence: restart_tombstone_for_resource(
                    FixedEvidenceClass::RestartLoopTombstone,
                    FixedEvidenceClass::RestartReservedLoopTombstone,
                    binding,
                    loop_resource,
                    self.runtime_host_epoch,
                    self.compiled.compiled_build_instance_id(),
                )?,
            },
            card_instance: RuntimeResourceTombstoneInput {
                logical_ref: card_resource.logical_ref,
                evidence: restart_tombstone_for_resource(
                    FixedEvidenceClass::RestartCardTombstone,
                    FixedEvidenceClass::RestartReservedCardTombstone,
                    binding,
                    card_resource,
                    self.runtime_host_epoch,
                    self.compiled.compiled_build_instance_id(),
                )?,
            },
        })
    }

    fn prepare_recovery_one_source(
        &mut self,
        execution: &ReferenceTargetExecutionPlanV4,
        provenance: PlanProvenance,
        target_slice_digest: TargetSliceDigest,
        durable_action: Option<JournalActionRef>,
    ) -> Result<RuntimeOneSourceOwnerPlan, RuntimeReferenceMaterializationOwnerError> {
        execution
            .validate_compiled_fixture(self.compiled)
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        let loop_facts = execution
            .loop_facts()
            .ok_or(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        let binding = fixed_binding(execution, provenance, target_slice_digest)?;
        if self.token.is_none() {
            if durable_action.is_some() {
                return Err(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken);
            }
            let action_id = self.fresh_action_id()?;
            let generation = self.fresh_generation()?;
            let plan = RuntimeOneSourceOwnerPlan {
                action_id,
                domain_generation: generation,
                instance_generation: generation,
                resource_generation: generation,
                resources: RuntimeOneSourceResourceRefs {
                    loop_domain: *loop_facts.domain().as_bytes(),
                    card_instance: *loop_facts.instance().as_bytes(),
                },
                signed_budgets: loop_facts.budgets(),
            };
            self.token = Some(FixedOwnerToken {
                plan,
                binding,
                cancellation: self.root_cancellation.child(),
                domain: None,
                retire_action_id: None,
                retired_slice_digest: None,
            });
        }
        let token = self
            .token
            .as_ref()
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?;
        if token.binding != binding
            || token.plan.signed_budgets != loop_facts.budgets()
            || durable_action.is_some_and(|action| !start_action_matches(token.plan, action))
        {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }
        Ok(token.plan)
    }

    fn prove_restart_action_exact_zero(
        &mut self,
        execution: &ReferenceTargetExecutionPlanV4,
        provenance: PlanProvenance,
        target_slice_digest: TargetSliceDigest,
        action: JournalActionRef,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        execution
            .validate_compiled_fixture(self.compiled)
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        let _ = fixed_binding(execution, provenance, target_slice_digest)?;
        if action.kind != JournalActionKind::RestartReassembly
            || action.action_id == [0; 16]
            || action.runtime_host_epoch >= self.runtime_host_epoch
            || action.resource_generation == 0
        {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }
        Ok(())
    }

    fn prove_interrupted_normal_action_exact_zero(
        &mut self,
        execution: &ReferenceTargetExecutionPlanV4,
        provenance: PlanProvenance,
        target_slice_digest: TargetSliceDigest,
        action: JournalActionRef,
    ) -> Result<(), RuntimeReferenceMaterializationOwnerError> {
        execution
            .validate_compiled_fixture(self.compiled)
            .map_err(|_| RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        let _ = fixed_binding(execution, provenance, target_slice_digest)?;
        if !matches!(
            action.kind,
            JournalActionKind::StartOneSourceLoop | JournalActionKind::DrainToEmpty
        ) || action.action_id == [0; 16]
            || action.runtime_host_epoch >= self.runtime_host_epoch
            || action.resource_generation == 0
        {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }
        Ok(())
    }

    fn cleanup_recovery_one_source_once(
        &mut self,
        action: JournalActionRef,
    ) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError> {
        if action.kind != JournalActionKind::RestartReassembly {
            return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
        }
        let clock = self.clock;
        let compiled_build = self.compiled.compiled_build_instance_id();
        let token = self.start_token_mut(action)?;
        token
            .domain
            .as_deref_mut()
            .ok_or(RuntimeReferenceMaterializationOwnerError::MissingInMemoryToken)?
            .cleanup_after_failed_start(clock)?;
        tombstone_evidence(token, action, compiled_build)
    }
}

/// The implementation compiled under the fixed reference fixture row.
/// Source-only means every admitted input is structurally impossible in v1.
struct FixedIdleSourceCard {
    started: bool,
    stopped: bool,
}

impl FixedIdleSourceCard {
    const fn new() -> Self {
        Self {
            started: false,
            stopped: false,
        }
    }
}

impl CardImplementation for FixedIdleSourceCard {
    fn on_start<'a>(
        &'a mut self,
        _context: &'a CardContext,
    ) -> CardFuture<'a, Result<(), CallbackFailure>> {
        Box::pin(async move {
            if self.started || self.stopped {
                return Err(CallbackFailure::Rejected);
            }
            self.started = true;
            Ok(())
        })
    }

    fn on_input<'a>(
        &'a mut self,
        _context: &'a CardContext,
        _input: InputView<'a>,
    ) -> CardFuture<'a, Result<Option<OutputProposal>, CallbackFailure>> {
        Box::pin(async move {
            if !self.started || self.stopped {
                return Err(CallbackFailure::Rejected);
            }
            Ok(None)
        })
    }

    fn on_stop<'a>(
        &'a mut self,
        _context: &'a CardContext,
    ) -> CardFuture<'a, Result<(), CallbackFailure>> {
        Box::pin(async move {
            if !self.started || self.stopped {
                return Err(CallbackFailure::Rejected);
            }
            self.stopped = true;
            Ok(())
        })
    }
}

fn card_context(
    card: &CardInstanceOwner,
    binding: FixedReferenceBinding,
    reading: ClockReading,
    cancellation: &CancellationSource,
) -> CardContext {
    CardContext::new(
        card.identity(),
        reading,
        cancellation.view(),
        binding.definition_digest,
        binding.artifact_digest,
        binding.config_digest,
    )
}

fn poll_immediate<T>(mut future: CardFuture<'_, T>) -> Result<T, ()> {
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => Ok(value),
        Poll::Pending => Err(()),
    }
}

fn reading_within_budget(
    clock: RuntimeClock,
    before: ClockReading,
    budget_nanos: u64,
) -> Result<(), ()> {
    let after = clock.reading().map_err(|_| ())?;
    if after.domain() != before.domain()
        || after.generation() != before.generation()
        || after.now().value() < before.now().value()
        || after.now().value() - before.now().value() > budget_nanos
    {
        return Err(());
    }
    Ok(())
}

fn start_action_matches(plan: RuntimeOneSourceOwnerPlan, action: JournalActionRef) -> bool {
    matches!(
        action.kind,
        JournalActionKind::StartOneSourceLoop | JournalActionKind::RestartReassembly
    ) && plan.action_id == action.action_id
        && plan.domain_generation == action.domain_generation
        && plan.instance_generation == action.instance_generation
        && plan.resource_generation == action.resource_generation
}

fn fixed_binding(
    execution: &ReferenceTargetExecutionPlanV4,
    provenance: PlanProvenance,
    target_slice_digest: TargetSliceDigest,
) -> Result<FixedReferenceBinding, RuntimeReferenceMaterializationOwnerError> {
    let loop_facts = execution
        .loop_facts()
        .ok_or(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
    Ok(FixedReferenceBinding {
        target: execution.target(),
        instance: loop_facts.instance(),
        domain: loop_facts.domain(),
        source_revision: provenance.source_revision(),
        target_slice_digest,
        definition_digest: execution.fixture_definition_digest(),
        artifact_digest: execution.fixture_artifact_digest(),
        config_digest: loop_facts.config_digest(),
    })
}

fn ownership_evidence(
    token: &FixedOwnerToken,
    action: JournalActionRef,
    compiled_build: [u8; 32],
) -> Result<RuntimeOneSourceOwnershipInput, RuntimeReferenceMaterializationOwnerError> {
    let resources = token.plan.resources;
    Ok(RuntimeOneSourceOwnershipInput {
        loop_domain: RuntimeResourceOwnershipInput {
            logical_ref: resources.loop_domain,
            os_identity: owner_evidence(
                FixedEvidenceClass::LoopProcess,
                token.binding,
                action,
                resources.loop_domain,
                compiled_build,
            )?,
            workspace_identity: owner_evidence(
                FixedEvidenceClass::LoopNoWorkspace,
                token.binding,
                action,
                resources.loop_domain,
                compiled_build,
            )?,
            containment_identity: owner_evidence(
                FixedEvidenceClass::LoopContainment,
                token.binding,
                action,
                resources.loop_domain,
                compiled_build,
            )?,
        },
        card_instance: RuntimeResourceOwnershipInput {
            logical_ref: resources.card_instance,
            os_identity: owner_evidence(
                FixedEvidenceClass::CardProcess,
                token.binding,
                action,
                resources.card_instance,
                compiled_build,
            )?,
            workspace_identity: owner_evidence(
                FixedEvidenceClass::CardNoWorkspace,
                token.binding,
                action,
                resources.card_instance,
                compiled_build,
            )?,
            containment_identity: owner_evidence(
                FixedEvidenceClass::CardContainment,
                token.binding,
                action,
                resources.card_instance,
                compiled_build,
            )?,
        },
    })
}

fn tombstone_evidence(
    token: &FixedOwnerToken,
    action: JournalActionRef,
    compiled_build: [u8; 32],
) -> Result<RuntimeOneSourceTombstonesInput, RuntimeReferenceMaterializationOwnerError> {
    let resources = token.plan.resources;
    Ok(RuntimeOneSourceTombstonesInput {
        loop_domain: RuntimeResourceTombstoneInput {
            logical_ref: resources.loop_domain,
            evidence: owner_evidence(
                FixedEvidenceClass::LoopTombstone,
                token.binding,
                action,
                resources.loop_domain,
                compiled_build,
            )?,
        },
        card_instance: RuntimeResourceTombstoneInput {
            logical_ref: resources.card_instance,
            evidence: owner_evidence(
                FixedEvidenceClass::CardTombstone,
                token.binding,
                action,
                resources.card_instance,
                compiled_build,
            )?,
        },
    })
}

fn owner_evidence(
    class: FixedEvidenceClass,
    binding: FixedReferenceBinding,
    action: JournalActionRef,
    logical_ref: [u8; 16],
    compiled_build: [u8; 32],
) -> Result<OpaqueCanonicalValue, RuntimeReferenceMaterializationOwnerError> {
    let mut canonical = Vec::with_capacity(151);
    canonical.extend_from_slice(OWNER_EVIDENCE_MAGIC);
    canonical.extend_from_slice(&OWNER_EVIDENCE_VERSION.to_be_bytes());
    canonical.push(class as u8);
    canonical.extend_from_slice(binding.target.as_bytes());
    canonical.extend_from_slice(&action.action_id);
    canonical.extend_from_slice(&logical_ref);
    canonical.extend_from_slice(&action.runtime_host_epoch.to_be_bytes());
    canonical.extend_from_slice(&action.clock_generation.to_be_bytes());
    canonical.extend_from_slice(&action.domain_generation.to_be_bytes());
    canonical.extend_from_slice(&action.instance_generation.to_be_bytes());
    canonical.extend_from_slice(&action.resource_generation.to_be_bytes());
    canonical.extend_from_slice(&u64::from(std::process::id()).to_be_bytes());
    canonical.extend_from_slice(&compiled_build);
    canonical.extend_from_slice(binding.target_slice_digest.value().as_bytes());
    let mut digest = Digest32Builder::try_new(OWNER_EVIDENCE_DIGEST_DOMAIN)
        .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)?;
    digest
        .field_bytes(&canonical)
        .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)?;
    OpaqueCanonicalValue::try_resource_evidence(&canonical, digest.finish())
        .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)
}

fn restart_tombstone_evidence(
    class: FixedEvidenceClass,
    binding: FixedReferenceBinding,
    resource: &OwnedResourceRecord,
    current_runtime_host_epoch: u64,
    compiled_build: [u8; 32],
) -> Result<OpaqueCanonicalValue, RuntimeReferenceMaterializationOwnerError> {
    let mut canonical = Vec::with_capacity(263);
    canonical.extend_from_slice(OWNER_EVIDENCE_MAGIC);
    canonical.extend_from_slice(&OWNER_EVIDENCE_VERSION.to_be_bytes());
    canonical.push(class as u8);
    canonical.extend_from_slice(binding.target.as_bytes());
    canonical.extend_from_slice(&resource.logical_ref);
    canonical.extend_from_slice(&resource.runtime_host_epoch.to_be_bytes());
    canonical.extend_from_slice(&resource.generation.to_be_bytes());
    canonical.extend_from_slice(&current_runtime_host_epoch.to_be_bytes());
    canonical.extend_from_slice(&compiled_build);
    canonical.extend_from_slice(binding.target_slice_digest.value().as_bytes());
    for evidence in [
        resource.os_identity.as_ref(),
        resource.workspace_identity.as_ref(),
        resource.containment_identity.as_ref(),
    ] {
        let evidence =
            evidence.ok_or(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
        canonical.extend_from_slice(evidence.digest.as_bytes());
    }
    let mut digest = Digest32Builder::try_new(OWNER_EVIDENCE_DIGEST_DOMAIN)
        .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)?;
    digest
        .field_bytes(&canonical)
        .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)?;
    OpaqueCanonicalValue::try_resource_evidence(&canonical, digest.finish())
        .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)
}

fn restart_tombstone_for_resource(
    owned_class: FixedEvidenceClass,
    reserved_class: FixedEvidenceClass,
    binding: FixedReferenceBinding,
    resource: &OwnedResourceRecord,
    current_runtime_host_epoch: u64,
    compiled_build: [u8; 32],
) -> Result<OpaqueCanonicalValue, RuntimeReferenceMaterializationOwnerError> {
    match resource.phase {
        ResourcePhase::Reserved => restart_reserved_tombstone_evidence(
            reserved_class,
            binding,
            resource,
            current_runtime_host_epoch,
            compiled_build,
        ),
        ResourcePhase::Owned | ResourcePhase::CleanupPending => restart_tombstone_evidence(
            owned_class,
            binding,
            resource,
            current_runtime_host_epoch,
            compiled_build,
        ),
        ResourcePhase::Terminal | ResourcePhase::ReservedAtCrashExactZero => {
            Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)
        }
    }
}

/// The fixed reference profile allocates only in-process resources.  A
/// durable `Reserved` record therefore means no OS/workspace/containment
/// identity was ever published.  A later RuntimeHost epoch is the process
/// boundary proof that the old reservation cannot still own an in-process
/// token; preserve that distinction instead of fabricating ordinary owned
/// resource identities.
fn restart_reserved_tombstone_evidence(
    class: FixedEvidenceClass,
    binding: FixedReferenceBinding,
    resource: &OwnedResourceRecord,
    current_runtime_host_epoch: u64,
    compiled_build: [u8; 32],
) -> Result<OpaqueCanonicalValue, RuntimeReferenceMaterializationOwnerError> {
    let action_id = resource
        .action_id
        .ok_or(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence)?;
    if resource.phase != ResourcePhase::Reserved
        || resource.runtime_host_epoch >= current_runtime_host_epoch
        || resource.os_identity.is_some()
        || resource.workspace_identity.is_some()
        || resource.containment_identity.is_some()
        || resource.tombstone_evidence.is_some()
    {
        return Err(RuntimeReferenceMaterializationOwnerError::ConflictingEvidence);
    }
    let mut canonical = Vec::with_capacity(183);
    canonical.extend_from_slice(OWNER_EVIDENCE_MAGIC);
    canonical.extend_from_slice(&OWNER_EVIDENCE_VERSION.to_be_bytes());
    canonical.push(class as u8);
    canonical.extend_from_slice(binding.target.as_bytes());
    canonical.extend_from_slice(&action_id);
    canonical.extend_from_slice(&resource.logical_ref);
    canonical.extend_from_slice(&resource.runtime_host_epoch.to_be_bytes());
    canonical.extend_from_slice(&resource.generation.to_be_bytes());
    canonical.extend_from_slice(&current_runtime_host_epoch.to_be_bytes());
    canonical.extend_from_slice(&compiled_build);
    canonical.extend_from_slice(binding.target_slice_digest.value().as_bytes());
    let mut digest = Digest32Builder::try_new(OWNER_EVIDENCE_DIGEST_DOMAIN)
        .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)?;
    digest
        .field_bytes(&canonical)
        .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)?;
    OpaqueCanonicalValue::try_resource_evidence(&canonical, digest.finish())
        .map_err(|_| RuntimeReferenceMaterializationOwnerError::Unavailable)
}

fn journal_owner_high_water(snapshot: &RuntimeJournalSnapshot) -> (BTreeSet<[u8; 16]>, u64) {
    let state = snapshot.state();
    let mut action_ids = BTreeSet::new();
    let mut generation = state
        .owned_resources
        .iter()
        .map(|resource| resource.generation)
        .max()
        .unwrap_or(0);
    let mut observe = |action: JournalActionRef| {
        action_ids.insert(action.action_id);
        generation = generation
            .max(action.domain_generation)
            .max(action.instance_generation)
            .max(action.resource_generation);
    };
    for action in state
        .terminal_operations
        .iter()
        .filter_map(|terminal| terminal.action)
    {
        observe(action);
    }
    for terminal in &state.recovery_terminals {
        observe(terminal.recovery.action);
    }
    if let Some(action) = state.prepared.as_ref().and_then(|prepared| prepared.action) {
        observe(action);
    }
    if let Some(recovery) = state.recovery_action {
        observe(recovery.action);
    }
    (action_ids, generation)
}
