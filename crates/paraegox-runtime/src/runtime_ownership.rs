//! Immutable, bounded observations of RuntimeHost process ownership.
//!
//! This module deliberately owns no process, task, thread, permit, payload, or
//! cleanup action. Concrete Runtime registries remain the lifecycle authority;
//! they may build one of these snapshots during an owner turn so liveness and
//! recovery policy can reason about the exact observed tree without creating a
//! second mutable registry or desired-state graph.

use core::fmt;

use paraegox_kernel::identity::RuntimeHostId;
use paraegox_runtime_contracts::assignment::{InstanceRef, MAX_TARGET_ASSIGNMENTS};
use paraegox_runtime_contracts::process_execution::{
    MAX_PROCESS_DOMAINS, ProcessDomainRef, SideEffectClass,
};
use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};

use crate::card_instance::{DomainEpoch, InstanceGeneration, InvocationId, RuntimeHostEpoch};

/// Hard observed-invocation ceiling independent of caller allocation choices.
///
/// A signed ProcessDomain capacity normally imposes a much smaller bound. This
/// ceiling prevents a malformed observation producer from allocating without
/// limit before that plan-specific check is applied.
const MAX_OBSERVED_INVOCATIONS: usize = MAX_TARGET_ASSIGNMENTS * 64;

/// Exact identity of one live ProcessDomain generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProcessGenerationIdentity {
    runtime_host: RuntimeHostId,
    runtime_host_epoch: RuntimeHostEpoch,
    source_revision: SourcePlanRevision,
    target_slice_digest: TargetSliceDigest,
    domain: ProcessDomainRef,
    domain_epoch: DomainEpoch,
}

impl ProcessGenerationIdentity {
    #[must_use]
    pub(crate) const fn new(
        runtime_host: RuntimeHostId,
        runtime_host_epoch: RuntimeHostEpoch,
        source_revision: SourcePlanRevision,
        target_slice_digest: TargetSliceDigest,
        domain: ProcessDomainRef,
        domain_epoch: DomainEpoch,
    ) -> Self {
        Self {
            runtime_host,
            runtime_host_epoch,
            source_revision,
            target_slice_digest,
            domain,
            domain_epoch,
        }
    }

    #[must_use]
    pub(crate) const fn runtime_host(self) -> RuntimeHostId {
        self.runtime_host
    }

    #[must_use]
    pub(crate) const fn runtime_host_epoch(self) -> RuntimeHostEpoch {
        self.runtime_host_epoch
    }

    #[must_use]
    pub(crate) const fn source_revision(self) -> SourcePlanRevision {
        self.source_revision
    }

    #[must_use]
    pub(crate) const fn target_slice_digest(self) -> TargetSliceDigest {
        self.target_slice_digest
    }

    #[must_use]
    pub(crate) const fn domain(self) -> ProcessDomainRef {
        self.domain
    }

    #[must_use]
    pub(crate) const fn domain_epoch(self) -> DomainEpoch {
        self.domain_epoch
    }
}

/// Observed lifecycle of the concrete process generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessOwnershipLifecycle {
    Starting,
    Live,
    Closing,
    Quarantined,
}

/// The host-side ownership boundary crossed by one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessInvocationOwnershipStage {
    /// Runtime owns the admitted work, but no Invoke bytes may have been sent.
    Admitted,
    /// Runtime recorded the conservative handoff before writing any bytes.
    HandoffStarted,
    /// A current-generation worker acknowledged the complete invocation frame.
    Started,
    /// Cooperative cancellation was requested but no terminal fact exists.
    CancellationRequested,
    /// A current-generation worker returned an authoritative terminal result.
    /// The invocation no longer needs process-loss classification, but the
    /// transferred terminal payload can remain charged until its receiver
    /// releases it.
    TerminalDelivered,
    /// The terminal effect outcome is unknown and the work cannot be replayed.
    Uncertain,
}

impl ProcessInvocationOwnershipStage {
    /// Whether loss of the worker must conservatively classify this invocation
    /// as uncertain. An authoritative terminal result closes that question even
    /// while its transferred payload remains retained by another owner.
    #[must_use]
    pub(crate) const fn crossed_handoff(self) -> bool {
        !matches!(self, Self::Admitted | Self::TerminalDelivered)
    }

    #[must_use]
    pub(crate) const fn requires_loss_classification(self) -> bool {
        self.crossed_handoff()
    }
}

/// One active or resource-retaining invocation observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessInvocationOwnership {
    invocation: InvocationId,
    stage: ProcessInvocationOwnershipStage,
    side_effect: SideEffectClass,
    ipc_credit_held: bool,
    retained_bytes: u64,
}

impl ProcessInvocationOwnership {
    #[must_use]
    pub(crate) const fn new(
        invocation: InvocationId,
        stage: ProcessInvocationOwnershipStage,
        side_effect: SideEffectClass,
        ipc_credit_held: bool,
        retained_bytes: u64,
    ) -> Self {
        Self {
            invocation,
            stage,
            side_effect,
            ipc_credit_held,
            retained_bytes,
        }
    }

    #[must_use]
    pub(crate) const fn invocation(self) -> InvocationId {
        self.invocation
    }

    #[must_use]
    pub(crate) const fn stage(self) -> ProcessInvocationOwnershipStage {
        self.stage
    }

    #[must_use]
    pub(crate) const fn side_effect(self) -> SideEffectClass {
        self.side_effect
    }

    #[must_use]
    pub(crate) const fn ipc_credit_held(self) -> bool {
        self.ipc_credit_held
    }

    #[must_use]
    pub(crate) const fn retained_bytes(self) -> u64 {
        self.retained_bytes
    }
}

/// One planned instance and its exact bounded invocation observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessInstanceOwnership {
    instance: InstanceRef,
    generation: InstanceGeneration,
    invocations: Box<[ProcessInvocationOwnership]>,
}

impl ProcessInstanceOwnership {
    pub(crate) fn try_new(
        instance: InstanceRef,
        generation: InstanceGeneration,
        mut invocations: Vec<ProcessInvocationOwnership>,
    ) -> Result<Self, RuntimeOwnershipError> {
        if invocations.len() > MAX_OBSERVED_INVOCATIONS {
            return Err(RuntimeOwnershipError::InvocationCapacityExceeded);
        }
        invocations.sort_by_key(|value| value.invocation());
        if invocations
            .windows(2)
            .any(|pair| pair[0].invocation() == pair[1].invocation())
        {
            return Err(RuntimeOwnershipError::DuplicateInvocation);
        }
        Ok(Self {
            instance,
            generation,
            invocations: invocations.into_boxed_slice(),
        })
    }

    #[must_use]
    pub(crate) const fn instance(&self) -> InstanceRef {
        self.instance
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> InstanceGeneration {
        self.generation
    }

    #[must_use]
    pub(crate) fn invocations(&self) -> &[ProcessInvocationOwnership] {
        &self.invocations
    }
}

/// Plan ceilings needed to validate one observed domain without retaining the
/// signed plan as a parallel live owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessOwnershipLimits {
    max_outstanding: u32,
    max_ipc_credit_items: u32,
    max_retained_bytes: u64,
    max_process_tree_members: u32,
}

impl ProcessOwnershipLimits {
    #[must_use]
    pub(crate) const fn new(
        max_outstanding: u32,
        max_ipc_credit_items: u32,
        max_retained_bytes: u64,
        max_process_tree_members: u32,
    ) -> Self {
        Self {
            max_outstanding,
            max_ipc_credit_items,
            max_retained_bytes,
            max_process_tree_members,
        }
    }
}

/// Immutable observation of one concrete ProcessDomain generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessDomainOwnership {
    identity: ProcessGenerationIdentity,
    lifecycle: ProcessOwnershipLifecycle,
    process_tree_members: u32,
    instances: Box<[ProcessInstanceOwnership]>,
    outstanding: u32,
    held_ipc_credits: u32,
    retained_bytes: u64,
}

impl ProcessDomainOwnership {
    pub(crate) fn try_new(
        identity: ProcessGenerationIdentity,
        lifecycle: ProcessOwnershipLifecycle,
        process_tree_members: u32,
        limits: ProcessOwnershipLimits,
        mut instances: Vec<ProcessInstanceOwnership>,
    ) -> Result<Self, RuntimeOwnershipError> {
        if instances.is_empty() || instances.len() > MAX_TARGET_ASSIGNMENTS {
            return Err(RuntimeOwnershipError::InstanceCapacityExceeded);
        }
        if process_tree_members > limits.max_process_tree_members {
            return Err(RuntimeOwnershipError::ProcessTreeCapacityExceeded);
        }
        instances.sort_by_key(ProcessInstanceOwnership::instance);
        if instances
            .windows(2)
            .any(|pair| pair[0].instance() == pair[1].instance())
        {
            return Err(RuntimeOwnershipError::DuplicateInstance);
        }

        let mut outstanding = 0_u32;
        let mut held_ipc_credits = 0_u32;
        let mut retained_bytes = 0_u64;
        for invocation in instances
            .iter()
            .flat_map(ProcessInstanceOwnership::invocations)
        {
            outstanding = outstanding
                .checked_add(1)
                .ok_or(RuntimeOwnershipError::CounterOverflow)?;
            if invocation.ipc_credit_held() {
                held_ipc_credits = held_ipc_credits
                    .checked_add(1)
                    .ok_or(RuntimeOwnershipError::CounterOverflow)?;
            }
            retained_bytes = retained_bytes
                .checked_add(invocation.retained_bytes())
                .ok_or(RuntimeOwnershipError::CounterOverflow)?;
        }
        if outstanding > limits.max_outstanding || held_ipc_credits > limits.max_ipc_credit_items {
            return Err(RuntimeOwnershipError::InvocationCapacityExceeded);
        }
        if retained_bytes > limits.max_retained_bytes {
            return Err(RuntimeOwnershipError::RetainedByteCapacityExceeded);
        }

        Ok(Self {
            identity,
            lifecycle,
            process_tree_members,
            instances: instances.into_boxed_slice(),
            outstanding,
            held_ipc_credits,
            retained_bytes,
        })
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> ProcessGenerationIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn lifecycle(&self) -> ProcessOwnershipLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub(crate) const fn process_tree_members(&self) -> u32 {
        self.process_tree_members
    }

    #[must_use]
    pub(crate) fn instances(&self) -> &[ProcessInstanceOwnership] {
        &self.instances
    }

    #[must_use]
    pub(crate) const fn outstanding(&self) -> u32 {
        self.outstanding
    }

    #[must_use]
    pub(crate) const fn held_ipc_credits(&self) -> u32 {
        self.held_ipc_credits
    }

    #[must_use]
    pub(crate) const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }
}

/// Sole admission capability for one live process generation.
///
/// The concrete ProcessDomain keeps this value beside its ingress registry.
/// Fencing consumes it, so normal code cannot retain an accepting capability
/// while also claiming that the generation has been fenced.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "the admission gate must be retained by the sole ProcessDomain owner"]
pub(crate) struct ProcessAdmissionGate {
    identity: ProcessGenerationIdentity,
}

impl ProcessAdmissionGate {
    pub(crate) const fn new(identity: ProcessGenerationIdentity) -> Self {
        Self { identity }
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> ProcessGenerationIdentity {
        self.identity
    }

    /// Irreversibly closes admission and returns the capability required to
    /// observe loss of this exact generation.
    pub(crate) const fn fence(self) -> ProcessAdmissionFence {
        ProcessAdmissionFence {
            identity: self.identity,
        }
    }
}

/// Non-cloneable evidence that admission for one generation was fenced.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "the fence must be consumed into an exact process-loss observation"]
pub(crate) struct ProcessAdmissionFence {
    identity: ProcessGenerationIdentity,
}

impl ProcessAdmissionFence {
    #[must_use]
    pub(crate) const fn identity(&self) -> ProcessGenerationIdentity {
        self.identity
    }

    /// Consumes the fence and an owner-built post-fence snapshot together.
    /// Every invocation whose handoff may have crossed the process boundary is
    /// classified terminally as uncertain in the returned observation.
    pub(crate) fn observe_process_loss(
        self,
        expected: bool,
        ownership: ProcessDomainOwnership,
    ) -> Result<ProcessLossBundle, RuntimeOwnershipError> {
        if ownership.identity() != self.identity {
            return Err(RuntimeOwnershipError::AdmissionFenceIdentityMismatch);
        }
        if !matches!(
            ownership.lifecycle(),
            ProcessOwnershipLifecycle::Closing | ProcessOwnershipLifecycle::Quarantined
        ) {
            return Err(RuntimeOwnershipError::LossSnapshotNotFenced);
        }

        let mut uncertain_invocations = Vec::new();
        for instance in ownership.instances() {
            for invocation in instance
                .invocations()
                .iter()
                .filter(|invocation| invocation.stage().requires_loss_classification())
            {
                uncertain_invocations.push(ProcessInvocationLoss {
                    instance: instance.instance(),
                    generation: instance.generation(),
                    invocation: invocation.invocation(),
                    side_effect: invocation.side_effect(),
                });
            }
        }
        let crossed_handoffs = u32::try_from(uncertain_invocations.len())
            .map_err(|_| RuntimeOwnershipError::CounterOverflow)?;
        let external_effect_uncertain = uncertain_invocations
            .iter()
            .any(|invocation| invocation.side_effect() != SideEffectClass::EffectFree);
        let lineage = ProcessLossLineage {
            identity: self.identity,
            snapshot_process_tree_members: ownership.process_tree_members(),
            snapshot_outstanding: ownership.outstanding(),
            snapshot_held_ipc_credits: ownership.held_ipc_credits(),
            snapshot_retained_bytes: ownership.retained_bytes(),
            crossed_handoffs,
            classified_handoffs: crossed_handoffs,
            external_effect_uncertain,
        };
        let cleanup_invocations = uncertain_invocations.clone().into_boxed_slice();
        Ok(ProcessLossBundle {
            observation: ProcessLossObservation {
                lineage,
                expected,
                uncertain_invocations: uncertain_invocations.into_boxed_slice(),
            },
            cleanup_authority: ProcessCleanupAuthority {
                lineage,
                uncertain_invocations: cleanup_invocations,
            },
        })
    }
}

/// Terminal no-replay classification for one invocation whose handoff crossed
/// into a process generation that was subsequently lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessInvocationLoss {
    instance: InstanceRef,
    generation: InstanceGeneration,
    invocation: InvocationId,
    side_effect: SideEffectClass,
}

impl ProcessInvocationLoss {
    #[must_use]
    pub(crate) const fn instance(self) -> InstanceRef {
        self.instance
    }

    #[must_use]
    pub(crate) const fn generation(self) -> InstanceGeneration {
        self.generation
    }

    #[must_use]
    pub(crate) const fn invocation(self) -> InvocationId {
        self.invocation
    }

    #[must_use]
    pub(crate) const fn side_effect(self) -> SideEffectClass {
        self.side_effect
    }

    #[must_use]
    pub(crate) const fn terminal_stage(self) -> ProcessInvocationOwnershipStage {
        ProcessInvocationOwnershipStage::Uncertain
    }
}

/// Opaque lineage shared only by a loss observation and its cleanup authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessLossLineage {
    identity: ProcessGenerationIdentity,
    snapshot_process_tree_members: u32,
    snapshot_outstanding: u32,
    snapshot_held_ipc_credits: u32,
    snapshot_retained_bytes: u64,
    crossed_handoffs: u32,
    classified_handoffs: u32,
    external_effect_uncertain: bool,
}

impl ProcessLossLineage {
    #[must_use]
    pub(crate) const fn identity(self) -> ProcessGenerationIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn crossed_handoffs(self) -> u32 {
        self.crossed_handoffs
    }

    #[must_use]
    pub(crate) const fn unsettled_handoffs(self) -> u32 {
        self.crossed_handoffs
            .saturating_sub(self.classified_handoffs)
    }

    #[must_use]
    pub(crate) const fn external_effect_uncertain(self) -> bool {
        self.external_effect_uncertain
    }

    #[must_use]
    pub(crate) const fn fingerprint_fields(self) -> (u32, u32, u32, u64, u32, u32, bool) {
        (
            self.snapshot_process_tree_members,
            self.snapshot_outstanding,
            self.snapshot_held_ipc_credits,
            self.snapshot_retained_bytes,
            self.crossed_handoffs,
            self.classified_handoffs,
            self.external_effect_uncertain,
        )
    }
}

/// Non-cloneable, complete loss observation for one fenced generation.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "the loss observation must be consumed by recovery"]
pub(crate) struct ProcessLossObservation {
    lineage: ProcessLossLineage,
    expected: bool,
    uncertain_invocations: Box<[ProcessInvocationLoss]>,
}

impl ProcessLossObservation {
    #[must_use]
    pub(crate) const fn identity(&self) -> ProcessGenerationIdentity {
        self.lineage.identity()
    }

    #[must_use]
    pub(crate) const fn expected(&self) -> bool {
        self.expected
    }

    #[must_use]
    pub(crate) const fn lineage(&self) -> ProcessLossLineage {
        self.lineage
    }

    #[must_use]
    pub(crate) fn uncertain_invocations(&self) -> &[ProcessInvocationLoss] {
        &self.uncertain_invocations
    }

    #[must_use]
    pub(crate) fn external_effect_uncertain(&self) -> bool {
        self.lineage.external_effect_uncertain()
    }

    #[must_use]
    pub(crate) const fn all_crossed_handoffs_settled(&self) -> bool {
        self.lineage.unsettled_handoffs() == 0
    }
}

/// Loss observation plus the unique authority needed to prove its cleanup.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "both loss observation and cleanup authority must be consumed"]
pub(crate) struct ProcessLossBundle {
    observation: ProcessLossObservation,
    cleanup_authority: ProcessCleanupAuthority,
}

impl ProcessLossBundle {
    pub(crate) const fn observation(&self) -> &ProcessLossObservation {
        &self.observation
    }

    pub(crate) fn into_parts(self) -> (ProcessLossObservation, ProcessCleanupAuthority) {
        (self.observation, self.cleanup_authority)
    }
}

/// Bounded observed ownership tree for one RuntimeHost process generation.
///
/// There are intentionally no mutation methods. A concrete registry builds a
/// fresh value after it has observed its real owners; recovery cannot use this
/// value to start, stop, move, or release anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeOwnershipTree {
    runtime_host: RuntimeHostId,
    runtime_host_epoch: RuntimeHostEpoch,
    domains: Box<[ProcessDomainOwnership]>,
}

impl RuntimeOwnershipTree {
    pub(crate) fn try_new(
        runtime_host: RuntimeHostId,
        runtime_host_epoch: RuntimeHostEpoch,
        mut domains: Vec<ProcessDomainOwnership>,
    ) -> Result<Self, RuntimeOwnershipError> {
        if domains.len() > MAX_PROCESS_DOMAINS {
            return Err(RuntimeOwnershipError::DomainCapacityExceeded);
        }
        if domains.iter().any(|domain| {
            domain.identity().runtime_host() != runtime_host
                || domain.identity().runtime_host_epoch() != runtime_host_epoch
        }) {
            return Err(RuntimeOwnershipError::HostIdentityMismatch);
        }
        domains.sort_by_key(|domain| domain.identity().domain());
        if domains
            .windows(2)
            .any(|pair| pair[0].identity().domain() == pair[1].identity().domain())
        {
            return Err(RuntimeOwnershipError::DuplicateDomain);
        }
        let instance_count = domains.iter().try_fold(0_usize, |count, domain| {
            count
                .checked_add(domain.instances().len())
                .ok_or(RuntimeOwnershipError::CounterOverflow)
        })?;
        if instance_count > MAX_TARGET_ASSIGNMENTS {
            return Err(RuntimeOwnershipError::InstanceCapacityExceeded);
        }
        let invocation_count = domains.iter().try_fold(0_usize, |count, domain| {
            count
                .checked_add(
                    usize::try_from(domain.outstanding())
                        .map_err(|_| RuntimeOwnershipError::CounterOverflow)?,
                )
                .ok_or(RuntimeOwnershipError::CounterOverflow)
        })?;
        if invocation_count > MAX_OBSERVED_INVOCATIONS {
            return Err(RuntimeOwnershipError::InvocationCapacityExceeded);
        }
        Ok(Self {
            runtime_host,
            runtime_host_epoch,
            domains: domains.into_boxed_slice(),
        })
    }

    #[must_use]
    pub(crate) const fn runtime_host(&self) -> RuntimeHostId {
        self.runtime_host
    }

    #[must_use]
    pub(crate) const fn runtime_host_epoch(&self) -> RuntimeHostEpoch {
        self.runtime_host_epoch
    }

    #[must_use]
    pub(crate) fn domains(&self) -> &[ProcessDomainOwnership] {
        &self.domains
    }

    #[must_use]
    pub(crate) fn domain(&self, reference: ProcessDomainRef) -> Option<&ProcessDomainOwnership> {
        self.domains
            .binary_search_by_key(&reference, |domain| domain.identity().domain())
            .ok()
            .map(|index| &self.domains[index])
    }
}

/// Exact owner census required before recovery may reuse a process slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessCleanupCensus {
    leader_reaped: bool,
    live_process_tree_members: u32,
    open_ipc_handles: u32,
    outstanding_ipc_credits: u32,
    retained_bytes: u64,
    workspace_entries: u32,
    registered_resources: u32,
}

impl ProcessCleanupCensus {
    #[must_use]
    pub(crate) const fn new(
        leader_reaped: bool,
        live_process_tree_members: u32,
        open_ipc_handles: u32,
        outstanding_ipc_credits: u32,
        retained_bytes: u64,
        workspace_entries: u32,
        registered_resources: u32,
    ) -> Self {
        Self {
            leader_reaped,
            live_process_tree_members,
            open_ipc_handles,
            outstanding_ipc_credits,
            retained_bytes,
            workspace_entries,
            registered_resources,
        }
    }

    #[must_use]
    pub(crate) const fn is_exact_zero(self) -> bool {
        self.leader_reaped
            && self.live_process_tree_members == 0
            && self.open_ipc_handles == 0
            && self.outstanding_ipc_credits == 0
            && self.retained_bytes == 0
            && self.workspace_entries == 0
            && self.registered_resources == 0
    }

    #[must_use]
    pub(crate) const fn fingerprint_fields(self) -> (bool, u32, u32, u32, u64, u32, u32) {
        (
            self.leader_reaped,
            self.live_process_tree_members,
            self.open_ipc_handles,
            self.outstanding_ipc_credits,
            self.retained_bytes,
            self.workspace_entries,
            self.registered_resources,
        )
    }
}

/// Non-cloneable authority to prove cleanup for the exact fenced-loss lineage
/// from which it was minted. A bare numeric census is intentionally
/// insufficient to create reusable-slot evidence.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "cleanup authority must be consumed into proof or quarantine"]
pub(crate) struct ProcessCleanupAuthority {
    lineage: ProcessLossLineage,
    uncertain_invocations: Box<[ProcessInvocationLoss]>,
}

impl ProcessCleanupAuthority {
    #[must_use]
    pub(crate) const fn identity(&self) -> ProcessGenerationIdentity {
        self.lineage.identity()
    }

    #[must_use]
    pub(crate) fn uncertain_invocations(&self) -> &[ProcessInvocationLoss] {
        &self.uncertain_invocations
    }

    /// Validates a candidate post-cleanup snapshot without consuming the unique
    /// cleanup authority. The concrete owner can therefore retain this
    /// capability when resources are not yet settled and retry after observing
    /// real progress.
    pub(crate) fn validate_reconcile(
        &self,
        ownership: &ProcessDomainOwnership,
    ) -> Result<(), RuntimeOwnershipError> {
        if ownership.identity() != self.lineage.identity() {
            return Err(RuntimeOwnershipError::CleanupLineageMismatch);
        }
        if !matches!(
            ownership.lifecycle(),
            ProcessOwnershipLifecycle::Closing | ProcessOwnershipLifecycle::Quarantined
        ) || ownership.process_tree_members() != 0
        {
            return Err(RuntimeOwnershipError::CleanupOwnershipNotSettled);
        }

        let mut settled = Vec::new();
        for instance in ownership.instances() {
            for invocation in instance.invocations() {
                if invocation.stage() != ProcessInvocationOwnershipStage::Uncertain
                    || invocation.ipc_credit_held()
                    || invocation.retained_bytes() != 0
                {
                    return Err(RuntimeOwnershipError::CleanupOwnershipNotSettled);
                }
                settled.push(ProcessInvocationLoss {
                    instance: instance.instance(),
                    generation: instance.generation(),
                    invocation: invocation.invocation(),
                    side_effect: invocation.side_effect(),
                });
            }
        }
        if settled.as_slice() != self.uncertain_invocations.as_ref() {
            return Err(RuntimeOwnershipError::CleanupInvocationMismatch);
        }
        Ok(())
    }

    /// Reconciles the post-cleanup owner registry with the exact invocations
    /// classified by the loss observation. Terminal uncertainty records remain
    /// for audit, but no process, IPC credit, or retained byte may remain live.
    pub(crate) fn reconcile(
        self,
        ownership: ProcessDomainOwnership,
    ) -> Result<ProcessCleanupReadyAuthority, RuntimeOwnershipError> {
        self.validate_reconcile(&ownership)?;
        Ok(ProcessCleanupReadyAuthority {
            lineage: self.lineage,
        })
    }
}

/// Authority whose process tree and invocation resources have been reconciled
/// against the exact fenced-loss lineage.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "reconciled cleanup authority must be consumed into exact-zero proof"]
pub(crate) struct ProcessCleanupReadyAuthority {
    lineage: ProcessLossLineage,
}

impl ProcessCleanupReadyAuthority {
    pub(crate) fn try_prove(
        self,
        census: ProcessCleanupCensus,
    ) -> Result<ProcessCleanupProof, RuntimeOwnershipError> {
        if !census.is_exact_zero() {
            return Err(RuntimeOwnershipError::CleanupNotExactZero);
        }
        Ok(ProcessCleanupProof {
            lineage: self.lineage,
            census,
        })
    }
}

/// Non-cloneable evidence that one concrete process generation reached the
/// complete zero census. It does not itself own or release a process budget.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "cleanup proof must be consumed by the process owner or recovery transition"]
pub(crate) struct ProcessCleanupProof {
    lineage: ProcessLossLineage,
    census: ProcessCleanupCensus,
}

impl ProcessCleanupProof {
    #[must_use]
    pub(crate) const fn identity(&self) -> ProcessGenerationIdentity {
        self.lineage.identity()
    }

    #[must_use]
    pub(crate) const fn lineage(&self) -> ProcessLossLineage {
        self.lineage
    }

    #[must_use]
    pub(crate) const fn census(&self) -> ProcessCleanupCensus {
        self.census
    }

    /// Cleanup can be exact-zero while an external effect remains ambiguous;
    /// such a proof is quarantine-only and must never authorize restart.
    #[must_use]
    pub(crate) const fn external_effect_uncertain(&self) -> bool {
        self.lineage.external_effect_uncertain()
    }
}

/// Fail-closed construction failures for immutable ownership evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeOwnershipError {
    DomainCapacityExceeded,
    InstanceCapacityExceeded,
    InvocationCapacityExceeded,
    ProcessTreeCapacityExceeded,
    RetainedByteCapacityExceeded,
    DuplicateDomain,
    DuplicateInstance,
    DuplicateInvocation,
    HostIdentityMismatch,
    AdmissionFenceIdentityMismatch,
    LossSnapshotNotFenced,
    CleanupLineageMismatch,
    CleanupOwnershipNotSettled,
    CleanupInvocationMismatch,
    CounterOverflow,
    CleanupNotExactZero,
}

impl fmt::Display for RuntimeOwnershipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::DomainCapacityExceeded => "observed process-domain count exceeds its bound",
            Self::InstanceCapacityExceeded => "observed process-instance count exceeds its bound",
            Self::InvocationCapacityExceeded => {
                "observed process invocation or IPC-credit count exceeds its bound"
            }
            Self::ProcessTreeCapacityExceeded => "observed process tree exceeds its planned bound",
            Self::RetainedByteCapacityExceeded => {
                "observed process retained bytes exceed their planned bound"
            }
            Self::DuplicateDomain => "observed ownership contains a duplicate process domain",
            Self::DuplicateInstance => "observed ownership contains a duplicate process instance",
            Self::DuplicateInvocation => "observed ownership contains a duplicate invocation",
            Self::HostIdentityMismatch => "observed process domain belongs to another RuntimeHost",
            Self::AdmissionFenceIdentityMismatch => {
                "admission fence and process ownership belong to different generations"
            }
            Self::LossSnapshotNotFenced => {
                "process loss snapshot was captured before admission was closed"
            }
            Self::CleanupLineageMismatch => {
                "post-cleanup ownership belongs to another fenced loss lineage"
            }
            Self::CleanupOwnershipNotSettled => {
                "post-cleanup ownership still contains live process or invocation resources"
            }
            Self::CleanupInvocationMismatch => {
                "post-cleanup uncertainty records do not match the process loss"
            }
            Self::CounterOverflow => "observed ownership counter overflowed",
            Self::CleanupNotExactZero => "process cleanup census is not exact zero",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RuntimeOwnershipError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_runtime_contracts::assignment::InstanceRef;
    use paraegox_runtime_contracts::process_execution::{ProcessDomainRef, SideEffectClass};
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};

    use super::{
        ProcessAdmissionGate, ProcessCleanupCensus, ProcessCleanupReadyAuthority,
        ProcessDomainOwnership, ProcessGenerationIdentity, ProcessInstanceOwnership,
        ProcessInvocationOwnership, ProcessInvocationOwnershipStage, ProcessOwnershipLifecycle,
        ProcessOwnershipLimits, RuntimeOwnershipError, RuntimeOwnershipTree,
    };
    use crate::card_instance::{DomainEpoch, InstanceGeneration, InvocationId, RuntimeHostEpoch};

    fn host_epoch(value: u64) -> RuntimeHostEpoch {
        RuntimeHostEpoch::try_new(value).unwrap_or_else(|error| panic!("host epoch: {error}"))
    }

    fn domain_epoch(value: u64) -> DomainEpoch {
        DomainEpoch::try_new(value).unwrap_or_else(|error| panic!("domain epoch: {error}"))
    }

    fn generation(value: u64) -> InstanceGeneration {
        InstanceGeneration::try_new(value).unwrap_or_else(|error| panic!("generation: {error}"))
    }

    fn invocation(value: u64) -> InvocationId {
        InvocationId::try_new(value).unwrap_or_else(|error| panic!("invocation: {error}"))
    }

    fn identity(host: u8, domain: u8) -> ProcessGenerationIdentity {
        ProcessGenerationIdentity::new(
            RuntimeHostId::from_bytes([host; 16]),
            host_epoch(1),
            SourcePlanRevision::new(7),
            TargetSliceDigest::new(Digest32::from_bytes([9; 32])),
            ProcessDomainRef::from_bytes([domain; 16]),
            domain_epoch(2),
        )
    }

    fn instance(reference: u8, invocation_values: &[u64]) -> ProcessInstanceOwnership {
        let invocations = invocation_values
            .iter()
            .map(|value| {
                ProcessInvocationOwnership::new(
                    invocation(*value),
                    ProcessInvocationOwnershipStage::HandoffStarted,
                    SideEffectClass::EffectFree,
                    true,
                    10,
                )
            })
            .collect();
        ProcessInstanceOwnership::try_new(
            InstanceRef::from_bytes([reference; 16]),
            generation(3),
            invocations,
        )
        .unwrap_or_else(|error| panic!("instance: {error}"))
    }

    fn domain(host: u8, reference: u8) -> ProcessDomainOwnership {
        ProcessDomainOwnership::try_new(
            identity(host, reference),
            ProcessOwnershipLifecycle::Live,
            1,
            ProcessOwnershipLimits::new(4, 4, 100, 2),
            vec![instance(reference, &[1, 2])],
        )
        .unwrap_or_else(|error| panic!("domain: {error}"))
    }

    fn closing_domain(
        generation_identity: ProcessGenerationIdentity,
        invocations: Vec<ProcessInvocationOwnership>,
    ) -> ProcessDomainOwnership {
        let instance = ProcessInstanceOwnership::try_new(
            InstanceRef::from_bytes([3; 16]),
            generation(3),
            invocations,
        )
        .unwrap_or_else(|error| panic!("instance: {error}"));
        ProcessDomainOwnership::try_new(
            generation_identity,
            ProcessOwnershipLifecycle::Closing,
            0,
            ProcessOwnershipLimits::new(8, 8, 1_024, 2),
            vec![instance],
        )
        .unwrap_or_else(|error| panic!("closing domain: {error}"))
    }

    fn cleanup_ready_authority(
        generation_identity: ProcessGenerationIdentity,
    ) -> ProcessCleanupReadyAuthority {
        let bundle = ProcessAdmissionGate::new(generation_identity)
            .fence()
            .observe_process_loss(false, closing_domain(generation_identity, Vec::new()))
            .unwrap_or_else(|error| panic!("loss: {error}"));
        bundle
            .into_parts()
            .1
            .reconcile(closing_domain(generation_identity, Vec::new()))
            .unwrap_or_else(|error| panic!("reconcile: {error}"))
    }

    #[test]
    fn snapshot_is_sorted_bounded_and_read_only() {
        let host = RuntimeHostId::from_bytes([1; 16]);
        let tree =
            RuntimeOwnershipTree::try_new(host, host_epoch(1), vec![domain(1, 4), domain(1, 3)])
                .unwrap_or_else(|error| panic!("tree: {error}"));

        assert_eq!(tree.domains()[0].identity().domain().as_bytes(), &[3; 16]);
        assert_eq!(tree.domains()[1].outstanding(), 2);
        assert_eq!(tree.domains()[1].held_ipc_credits(), 2);
        assert_eq!(tree.domains()[1].retained_bytes(), 20);
        assert!(tree.domain(ProcessDomainRef::from_bytes([4; 16])).is_some());
    }

    #[test]
    fn duplicate_domain_and_wrong_host_fail_closed() {
        let host = RuntimeHostId::from_bytes([1; 16]);
        assert_eq!(
            RuntimeOwnershipTree::try_new(host, host_epoch(1), vec![domain(1, 3), domain(1, 3)],),
            Err(RuntimeOwnershipError::DuplicateDomain)
        );
        assert_eq!(
            RuntimeOwnershipTree::try_new(host, host_epoch(1), vec![domain(2, 3)]),
            Err(RuntimeOwnershipError::HostIdentityMismatch)
        );
    }

    #[test]
    fn per_domain_credits_bytes_and_process_tree_are_jointly_bounded() {
        let observed = vec![instance(3, &[1, 2])];
        assert_eq!(
            ProcessDomainOwnership::try_new(
                identity(1, 3),
                ProcessOwnershipLifecycle::Live,
                1,
                ProcessOwnershipLimits::new(1, 1, 100, 2),
                observed.clone(),
            ),
            Err(RuntimeOwnershipError::InvocationCapacityExceeded)
        );
        assert_eq!(
            ProcessDomainOwnership::try_new(
                identity(1, 3),
                ProcessOwnershipLifecycle::Live,
                1,
                ProcessOwnershipLimits::new(4, 1, 100, 2),
                observed.clone(),
            ),
            Err(RuntimeOwnershipError::InvocationCapacityExceeded)
        );
        assert_eq!(
            ProcessDomainOwnership::try_new(
                identity(1, 3),
                ProcessOwnershipLifecycle::Live,
                1,
                ProcessOwnershipLimits::new(4, 4, 10, 2),
                observed.clone(),
            ),
            Err(RuntimeOwnershipError::RetainedByteCapacityExceeded)
        );
        assert_eq!(
            ProcessDomainOwnership::try_new(
                identity(1, 3),
                ProcessOwnershipLifecycle::Live,
                3,
                ProcessOwnershipLimits::new(4, 4, 100, 2),
                observed,
            ),
            Err(RuntimeOwnershipError::ProcessTreeCapacityExceeded)
        );
    }

    #[test]
    fn cleanup_proof_requires_every_owner_counter_to_be_zero() {
        let exact = ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0);
        let proof = cleanup_ready_authority(identity(1, 3))
            .try_prove(exact)
            .unwrap_or_else(|error| panic!("proof: {error}"));
        assert!(proof.census().is_exact_zero());
        assert_eq!(proof.identity(), identity(1, 3));

        for nonzero in [
            ProcessCleanupCensus::new(false, 0, 0, 0, 0, 0, 0),
            ProcessCleanupCensus::new(true, 1, 0, 0, 0, 0, 0),
            ProcessCleanupCensus::new(true, 0, 1, 0, 0, 0, 0),
            ProcessCleanupCensus::new(true, 0, 0, 1, 0, 0, 0),
            ProcessCleanupCensus::new(true, 0, 0, 0, 1, 0, 0),
            ProcessCleanupCensus::new(true, 0, 0, 0, 0, 1, 0),
            ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 1),
        ] {
            assert_eq!(
                cleanup_ready_authority(identity(1, 3)).try_prove(nonzero),
                Err(RuntimeOwnershipError::CleanupNotExactZero)
            );
        }
    }

    #[test]
    fn fenced_loss_atomically_classifies_every_crossed_handoff() {
        let generation_identity = identity(1, 3);
        let admitted = ProcessInvocationOwnership::new(
            invocation(1),
            ProcessInvocationOwnershipStage::Admitted,
            SideEffectClass::External,
            false,
            0,
        );
        let handed_off = ProcessInvocationOwnership::new(
            invocation(2),
            ProcessInvocationOwnershipStage::HandoffStarted,
            SideEffectClass::External,
            true,
            17,
        );
        let bundle = ProcessAdmissionGate::new(generation_identity)
            .fence()
            .observe_process_loss(
                false,
                closing_domain(generation_identity, vec![admitted, handed_off]),
            )
            .unwrap_or_else(|error| panic!("loss: {error}"));

        assert_eq!(bundle.observation().uncertain_invocations().len(), 1);
        assert_eq!(
            bundle.observation().uncertain_invocations()[0].invocation(),
            invocation(2)
        );
        assert_eq!(
            bundle.observation().uncertain_invocations()[0].terminal_stage(),
            ProcessInvocationOwnershipStage::Uncertain
        );
        assert!(bundle.observation().external_effect_uncertain());
        assert!(bundle.observation().all_crossed_handoffs_settled());
    }

    #[test]
    fn delivered_terminal_payload_is_retained_without_becoming_uncertain() {
        let generation_identity = identity(1, 3);
        let terminal = ProcessInvocationOwnership::new(
            invocation(2),
            ProcessInvocationOwnershipStage::TerminalDelivered,
            SideEffectClass::External,
            false,
            17,
        );
        assert!(!terminal.stage().crossed_handoff());
        assert!(!terminal.stage().requires_loss_classification());

        let loss_snapshot = closing_domain(generation_identity, vec![terminal]);
        assert_eq!(loss_snapshot.outstanding(), 1);
        assert_eq!(loss_snapshot.held_ipc_credits(), 0);
        assert_eq!(loss_snapshot.retained_bytes(), 17);
        let loss = || {
            ProcessAdmissionGate::new(generation_identity)
                .fence()
                .observe_process_loss(false, closing_domain(generation_identity, vec![terminal]))
                .unwrap_or_else(|error| panic!("loss: {error}"))
        };
        let bundle = loss();
        assert!(bundle.observation().uncertain_invocations().is_empty());
        assert!(!bundle.observation().external_effect_uncertain());

        assert_eq!(
            bundle
                .into_parts()
                .1
                .reconcile(closing_domain(generation_identity, vec![terminal],)),
            Err(RuntimeOwnershipError::CleanupOwnershipNotSettled)
        );
        let authority = loss().into_parts().1;
        let ready = authority
            .reconcile(closing_domain(generation_identity, Vec::new()))
            .unwrap_or_else(|error| panic!("reconcile after payload release: {error}"));
        let proof = ready
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof after payload release: {error}"));
        assert!(!proof.external_effect_uncertain());
    }

    #[test]
    fn cleanup_reconcile_requires_matching_uncertain_records_without_resources() {
        let generation_identity = identity(1, 3);
        let handed_off = || {
            ProcessInvocationOwnership::new(
                invocation(2),
                ProcessInvocationOwnershipStage::HandoffStarted,
                SideEffectClass::External,
                true,
                17,
            )
        };
        let authority = || {
            ProcessAdmissionGate::new(generation_identity)
                .fence()
                .observe_process_loss(
                    false,
                    closing_domain(generation_identity, vec![handed_off()]),
                )
                .unwrap_or_else(|error| panic!("loss: {error}"))
                .into_parts()
                .1
        };

        assert_eq!(
            authority().reconcile(closing_domain(generation_identity, Vec::new())),
            Err(RuntimeOwnershipError::CleanupInvocationMismatch)
        );
        let still_holding_credit = ProcessInvocationOwnership::new(
            invocation(2),
            ProcessInvocationOwnershipStage::Uncertain,
            SideEffectClass::External,
            true,
            17,
        );
        assert_eq!(
            authority().reconcile(closing_domain(
                generation_identity,
                vec![still_holding_credit],
            )),
            Err(RuntimeOwnershipError::CleanupOwnershipNotSettled)
        );
        let settled = ProcessInvocationOwnership::new(
            invocation(2),
            ProcessInvocationOwnershipStage::Uncertain,
            SideEffectClass::External,
            false,
            0,
        );
        let ready = authority()
            .reconcile(closing_domain(generation_identity, vec![settled]))
            .unwrap_or_else(|error| panic!("reconcile: {error}"));
        let proof = ready
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof: {error}"));
        assert!(proof.external_effect_uncertain());
    }

    #[test]
    fn reconcile_prevalidation_preserves_authority_for_retry() {
        let generation_identity = identity(1, 3);
        let handed_off = ProcessInvocationOwnership::new(
            invocation(2),
            ProcessInvocationOwnershipStage::HandoffStarted,
            SideEffectClass::External,
            true,
            17,
        );
        let authority = ProcessAdmissionGate::new(generation_identity)
            .fence()
            .observe_process_loss(false, closing_domain(generation_identity, vec![handed_off]))
            .unwrap_or_else(|error| panic!("loss: {error}"))
            .into_parts()
            .1;

        let still_holding_credit = ProcessInvocationOwnership::new(
            invocation(2),
            ProcessInvocationOwnershipStage::Uncertain,
            SideEffectClass::External,
            true,
            17,
        );
        assert_eq!(
            authority.validate_reconcile(&closing_domain(
                generation_identity,
                vec![still_holding_credit],
            )),
            Err(RuntimeOwnershipError::CleanupOwnershipNotSettled)
        );

        let settled = ProcessInvocationOwnership::new(
            invocation(2),
            ProcessInvocationOwnershipStage::Uncertain,
            SideEffectClass::External,
            false,
            0,
        );
        let settled_ownership = closing_domain(generation_identity, vec![settled]);
        assert_eq!(authority.validate_reconcile(&settled_ownership), Ok(()));
        let ready = authority
            .reconcile(settled_ownership)
            .unwrap_or_else(|error| panic!("reconcile after retry: {error}"));
        let proof = ready
            .try_prove(ProcessCleanupCensus::new(true, 0, 0, 0, 0, 0, 0))
            .unwrap_or_else(|error| panic!("proof after retry: {error}"));
        assert!(proof.external_effect_uncertain());
    }

    #[test]
    fn loss_requires_matching_fence_and_post_fence_snapshot() {
        let first = identity(1, 3);
        let second = identity(1, 4);
        assert_eq!(
            ProcessAdmissionGate::new(first)
                .fence()
                .observe_process_loss(false, closing_domain(second, Vec::new())),
            Err(RuntimeOwnershipError::AdmissionFenceIdentityMismatch)
        );
        assert_eq!(
            ProcessAdmissionGate::new(first)
                .fence()
                .observe_process_loss(false, domain(1, 3)),
            Err(RuntimeOwnershipError::LossSnapshotNotFenced)
        );
    }
}
