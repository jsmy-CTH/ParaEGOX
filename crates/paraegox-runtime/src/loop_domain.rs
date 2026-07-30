//! Single-owner synchronous core for one planned LoopDomain.
//!
//! This module stores the only Mailbox payload queues for the domain and owns
//! their pure dispatcher/permit state. It never creates a task or Future. The
//! RuntimeHost callback layer receives a non-Clone grant only after both a
//! domain permit and the exact Mailbox in-flight token have been acquired.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use paraegox_kernel::time::{ClockDomainRef, ClockGeneration, ClockReading};
use paraegox_runtime_contracts::assignment::{
    BindingAssignment, BindingId, MailboxRef, OverflowPolicy, PortRef,
};
use paraegox_runtime_contracts::execution::{
    BlockingRisk, CallModel, DispatchClass as PlannedDispatchClass, DomainRef, LoopDomainSpec,
    MailboxExecutionSpec, RunBoundProvenance, WorkloadKind,
};

use crate::card_instance::DomainEpoch;
use crate::dispatcher::{
    DispatchClass, DispatchClassPolicy, DispatchDecision, DispatchGrant, DispatchIdleReason,
    DispatchPolicy, DispatchReadiness, DispatchSlotSpec, DispatcherError, DomainPermitLedger,
    DomainPermitLedgerId, DomainPermitSnapshot, DomainPermitToken, MAX_DISPATCH_SLOTS, PermitError,
};
use crate::mailbox::{
    DispatchOutcome as MailboxDispatchOutcome, InflightToken, Mailbox, MailboxError,
    MailboxHeadReadiness, MailboxLifecycle, MailboxSnapshot, OfferReport, TerminalReason,
    TerminalRecord, ValidatedMessage,
};
use crate::port_binding::{BindingEpoch, BindingOfferFailure, PortBinding, PortBindingError};

/// Opaque identity of one concrete domain owner in this process. Its private
/// shared marker keeps a stale capability's allocation
/// alive, so a successor core cannot reuse the same identity without global
/// mutable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoopDomainOwnerIdentity {
    planned_domain: DomainRef,
    domain_epoch: DomainEpoch,
    permit_ledger: DomainPermitLedgerId,
}

impl LoopDomainOwnerIdentity {
    #[must_use]
    pub(crate) const fn planned_domain(&self) -> DomainRef {
        self.planned_domain
    }

    #[must_use]
    pub(crate) const fn domain_epoch(&self) -> DomainEpoch {
        self.domain_epoch
    }
}

struct DomainMailbox {
    mailbox: Mailbox,
    execution: MailboxExecutionSpec,
    assignment: BindingAssignment,
    binding: PortBinding,
    active_epoch: Option<BindingEpoch>,
    draining_epoch: Option<BindingEpoch>,
}

/// Lifecycle summary derived from every owned Mailbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoopDomainLifecycle {
    Accepting,
    Draining,
    Closed,
}

/// Fixed-width, payload-free domain observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LoopDomainSnapshot {
    planned_domain: DomainRef,
    domain_epoch: DomainEpoch,
    clock_domain: ClockDomainRef,
    clock_generation: ClockGeneration,
    lifecycle: LoopDomainLifecycle,
    mailbox_count: u16,
    active_bindings: u16,
    draining_bindings: u16,
    queued_items: u64,
    queued_bytes: u64,
    inflight_items: u64,
    inflight_bytes: u64,
    retained_bytes: u64,
    permits: DomainPermitSnapshot,
}

impl LoopDomainSnapshot {
    #[must_use]
    pub(crate) const fn planned_domain(self) -> DomainRef {
        self.planned_domain
    }

    #[must_use]
    pub(crate) const fn domain_epoch(self) -> DomainEpoch {
        self.domain_epoch
    }

    #[must_use]
    pub(crate) const fn clock_domain(self) -> ClockDomainRef {
        self.clock_domain
    }

    #[must_use]
    pub(crate) const fn clock_generation(self) -> ClockGeneration {
        self.clock_generation
    }

    #[must_use]
    pub(crate) const fn lifecycle(self) -> LoopDomainLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub(crate) const fn mailbox_count(self) -> u16 {
        self.mailbox_count
    }

    #[must_use]
    pub(crate) const fn active_bindings(self) -> u16 {
        self.active_bindings
    }

    #[must_use]
    pub(crate) const fn draining_bindings(self) -> u16 {
        self.draining_bindings
    }

    #[must_use]
    pub(crate) const fn queued_items(self) -> u64 {
        self.queued_items
    }

    #[must_use]
    pub(crate) const fn queued_bytes(self) -> u64 {
        self.queued_bytes
    }

    #[must_use]
    pub(crate) const fn inflight_items(self) -> u64 {
        self.inflight_items
    }

    #[must_use]
    pub(crate) const fn inflight_bytes(self) -> u64 {
        self.inflight_bytes
    }

    #[must_use]
    pub(crate) const fn retained_bytes(self) -> u64 {
        self.retained_bytes
    }

    #[must_use]
    pub(crate) const fn permits(self) -> DomainPermitSnapshot {
        self.permits
    }

    #[must_use]
    pub(crate) const fn is_zero_cleanup(self) -> bool {
        matches!(self.lifecycle, LoopDomainLifecycle::Closed)
            && self.queued_items == 0
            && self.queued_bytes == 0
            && self.inflight_items == 0
            && self.inflight_bytes == 0
            && self.retained_bytes == 0
            && self.active_bindings == 0
            && self.draining_bindings == 0
            && self.permits.in_use() == 0
    }
}

/// The exact payload and permit ownership handed to the callback owner.
#[must_use = "a loop-domain grant must be finished or explicitly abandoned"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LoopDomainGrant {
    owner: LoopDomainOwnerIdentity,
    clock_domain: ClockDomainRef,
    clock_generation: ClockGeneration,
    execution: MailboxExecutionSpec,
    target_port: PortRef,
    inflight: InflightToken,
    permit: DomainPermitToken,
    callback_claimed: bool,
}

impl LoopDomainGrant {
    #[must_use]
    pub(crate) const fn execution_spec(&self) -> MailboxExecutionSpec {
        self.execution
    }

    #[must_use]
    pub(crate) const fn target_port(&self) -> PortRef {
        self.target_port
    }

    #[must_use]
    pub(crate) const fn message(&self) -> &ValidatedMessage {
        self.inflight.message()
    }

    #[must_use]
    pub(crate) const fn owner_identity(&self) -> &LoopDomainOwnerIdentity {
        &self.owner
    }

    /// Claims the sole callback attempt represented by this in-flight grant.
    pub(crate) fn claim_callback(&mut self) -> Result<(), LoopDomainError> {
        if self.callback_claimed {
            return Err(LoopDomainError::CallbackAlreadyClaimed);
        }
        self.callback_claimed = true;
        Ok(())
    }

    /// Rechecks the exact callback-start boundary without changing ownership.
    ///
    /// Dispatch expiry is necessary but not sufficient: an owner may retain a
    /// grant briefly before first polling the callback. The fresh reading must
    /// belong to this exact domain clock generation, and run deadline wins over
    /// freshness at an equal boundary just as it does in `Mailbox`.
    pub(crate) fn pre_run_terminal(
        &self,
        reading: ClockReading,
    ) -> Result<Option<TerminalReason>, LoopDomainError> {
        if reading.domain() != self.clock_domain {
            return Err(LoopDomainError::ClockDomainMismatch);
        }
        if reading.generation() != self.clock_generation {
            return Err(LoopDomainError::ClockGenerationMismatch);
        }
        if self
            .message()
            .run_deadline()
            .is_expired_at(reading)
            .map_err(|_| LoopDomainError::StateInconsistent)?
        {
            return Ok(Some(TerminalReason::RunDeadlineExpired));
        }
        if self
            .message()
            .fresh_until()
            .is_expired_at(reading)
            .map_err(|_| LoopDomainError::StateInconsistent)?
        {
            return Ok(Some(TerminalReason::StaleBeforeRun));
        }
        Ok(None)
    }
}

/// A committed Mailbox terminal whose domain permit still needs release.
#[must_use = "the domain permit remains held until release is called"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LoopDomainRelease {
    owner: LoopDomainOwnerIdentity,
    clock_domain: ClockDomainRef,
    clock_generation: ClockGeneration,
    execution: MailboxExecutionSpec,
    terminal: TerminalRecord,
    permit: DomainPermitToken,
}

/// Exact active ingress capability for one owner-local LoopDomain generation.
///
/// Binding epochs are local to a `PortBinding`, so they can repeat when a
/// planned domain is replaced. Carrying the exact opaque owner identity keeps
/// a stale route from becoming valid again in a successor domain, even if an
/// internal caller accidentally repeats the runtime-visible DomainEpoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoopDomainIngress {
    owner: LoopDomainOwnerIdentity,
    binding_id: BindingId,
    binding_epoch: BindingEpoch,
}

impl LoopDomainIngress {
    #[must_use]
    pub(crate) const fn binding_id(&self) -> BindingId {
        self.binding_id
    }
}

impl LoopDomainRelease {
    #[must_use]
    pub(crate) const fn execution_spec(&self) -> MailboxExecutionSpec {
        self.execution
    }

    #[must_use]
    pub(crate) const fn terminal(&self) -> TerminalRecord {
        self.terminal
    }

    #[must_use]
    pub(crate) const fn permit_is_active(&self) -> bool {
        self.permit.is_active()
    }
}

#[must_use = "a started dispatch report owns a loop-domain grant"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum LoopDomainDispatchOutcome {
    Started(Box<LoopDomainGrant>),
    Idle(DispatchIdleReason),
}

/// One synchronous dispatch decision plus queue terminals emitted before start.
#[must_use = "a dispatch report can own an in-flight payload grant"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LoopDomainDispatchReport {
    outcome: LoopDomainDispatchOutcome,
    terminals: Vec<TerminalRecord>,
}

impl LoopDomainDispatchReport {
    pub(crate) const fn outcome(&self) -> &LoopDomainDispatchOutcome {
        &self.outcome
    }

    #[must_use]
    pub(crate) fn terminals(&self) -> &[TerminalRecord] {
        &self.terminals
    }

    pub(crate) fn into_parts(self) -> (LoopDomainDispatchOutcome, Vec<TerminalRecord>) {
        (self.outcome, self.terminals)
    }
}

/// Returns Message ownership when a domain-level offer fails structurally.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LoopDomainOfferFailure {
    error: LoopDomainError,
    message: Box<ValidatedMessage>,
}

impl LoopDomainOfferFailure {
    fn new(error: LoopDomainError, message: ValidatedMessage) -> Self {
        Self {
            error,
            message: Box::new(message),
        }
    }

    #[must_use]
    pub(crate) const fn error(&self) -> LoopDomainError {
        self.error
    }

    pub(crate) fn into_message(self) -> ValidatedMessage {
        *self.message
    }
}

/// Returns the complete grant when its Mailbox terminal is rejected.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LoopDomainFinishFailure {
    error: LoopDomainError,
    grant: Box<LoopDomainGrant>,
}

impl LoopDomainFinishFailure {
    fn new(error: LoopDomainError, grant: LoopDomainGrant) -> Self {
        Self {
            error,
            grant: Box::new(grant),
        }
    }

    #[must_use]
    pub(crate) const fn error(&self) -> LoopDomainError {
        self.error
    }

    pub(crate) fn into_grant(self) -> LoopDomainGrant {
        *self.grant
    }
}

/// Pure synchronous state for one owner-local LoopDomain generation.
pub(crate) struct LoopDomainCore {
    spec: LoopDomainSpec,
    domain_epoch: DomainEpoch,
    owner: LoopDomainOwnerIdentity,
    clock_domain: ClockDomainRef,
    clock_generation: ClockGeneration,
    mailboxes: BTreeMap<MailboxRef, DomainMailbox>,
    binding_index: BTreeMap<BindingId, MailboxRef>,
    dispatch: DispatchPolicy,
    permits: DomainPermitLedger,
}

impl LoopDomainCore {
    /// Builds a domain from exact, already-authenticated plan records and
    /// separately injected owner-local clock facts.
    pub(crate) fn try_new(
        spec: LoopDomainSpec,
        executions: &[MailboxExecutionSpec],
        bindings: &[BindingAssignment],
        domain_epoch: DomainEpoch,
        clock_domain: ClockDomainRef,
        clock_generation: ClockGeneration,
    ) -> Result<Self, LoopDomainError> {
        if executions.is_empty() {
            return Err(LoopDomainError::MissingExecution);
        }
        if executions.len() > MAX_DISPATCH_SLOTS {
            return Err(LoopDomainError::TooManyExecutions);
        }
        for execution in executions {
            Self::validate_execution(spec, *execution)?;
        }
        if spec.control_reserved() == spec.max_outstanding()
            && executions
                .iter()
                .any(|execution| execution.dispatch_class() != PlannedDispatchClass::Control)
        {
            return Err(LoopDomainError::SharedCapacityRequired);
        }
        let mut execution_bindings = BTreeSet::new();
        let mut execution_mailboxes = BTreeSet::new();
        let mut slot_specs = Vec::with_capacity(executions.len());
        let mut class_quantum = [0_u32; 4];
        let mut class_burst = [0_u32; 4];
        let mut mailboxes = BTreeMap::new();
        let mut binding_index = BTreeMap::new();

        for execution in executions {
            if !execution_bindings.insert(execution.binding_id()) {
                return Err(LoopDomainError::DuplicateExecutionBinding);
            }
            if !execution_mailboxes.insert(execution.mailbox()) {
                return Err(LoopDomainError::DuplicateExecutionMailbox);
            }
            let mut matches = bindings
                .iter()
                .filter(|binding| binding.binding_id() == execution.binding_id());
            let Some(binding) = matches.next().copied() else {
                return Err(LoopDomainError::MissingBinding);
            };
            if matches.next().is_some() {
                return Err(LoopDomainError::DuplicateBinding);
            }
            Self::validate_binding(*execution, binding)?;

            let class = map_dispatch_class(execution.dispatch_class());
            let class_index = dispatch_class_index(class);
            class_quantum[class_index] = class_quantum[class_index]
                .checked_add(execution.minimum_service_weight())
                .ok_or(LoopDomainError::CounterOverflow)?;
            class_burst[class_index] = class_burst[class_index]
                .checked_add(u32::from(execution.max_burst()))
                .ok_or(LoopDomainError::CounterOverflow)?;
            slot_specs.push(DispatchSlotSpec::try_new(
                execution.mailbox(),
                class,
                execution.service_cost_tokens(),
                execution.minimum_service_weight(),
                execution.max_burst(),
            )?);

            let mailbox = Mailbox::try_new(
                binding.mailbox(),
                binding.target_spec().schema(),
                binding.target_spec().interaction(),
                binding.mailbox_spec(),
                clock_domain,
                clock_generation,
            )?;
            let mut installed_binding = PortBinding::new(binding.binding_id());
            let active_epoch = installed_binding.prepare(binding, &mailbox, None)?;
            let route = installed_binding.activate(active_epoch, &mailbox, None)?;
            if route.assignment() != binding || route.epoch() != active_epoch {
                return Err(LoopDomainError::StateInconsistent);
            }
            if binding_index
                .insert(binding.binding_id(), binding.mailbox())
                .is_some()
            {
                return Err(LoopDomainError::DuplicateExecutionBinding);
            }
            if mailboxes
                .insert(
                    execution.mailbox(),
                    DomainMailbox {
                        mailbox,
                        execution: *execution,
                        assignment: binding,
                        binding: installed_binding,
                        active_epoch: Some(active_epoch),
                        draining_epoch: None,
                    },
                )
                .is_some()
            {
                return Err(LoopDomainError::DuplicateExecutionMailbox);
            }
        }

        let class_policies = [
            DispatchClassPolicy::try_new(class_quantum[0].max(1), class_burst[0].max(1))?,
            DispatchClassPolicy::try_new(class_quantum[1].max(1), class_burst[1].max(1))?,
            DispatchClassPolicy::try_new(class_quantum[2].max(1), class_burst[2].max(1))?,
            DispatchClassPolicy::try_new(class_quantum[3].max(1), class_burst[3].max(1))?,
        ];
        let dispatch = DispatchPolicy::try_new(class_policies, slot_specs)?;
        let permit_ledger =
            DomainPermitLedgerId::new(*spec.domain().as_bytes(), domain_epoch.value());
        let owner = LoopDomainOwnerIdentity {
            planned_domain: spec.domain(),
            domain_epoch,
            permit_ledger: permit_ledger.clone(),
        };
        let permits = DomainPermitLedger::try_new(
            permit_ledger,
            spec.max_outstanding(),
            spec.control_reserved(),
        )?;

        Ok(Self {
            spec,
            domain_epoch,
            owner,
            clock_domain,
            clock_generation,
            mailboxes,
            binding_index,
            dispatch,
            permits,
        })
    }

    fn validate_execution(
        spec: LoopDomainSpec,
        execution: MailboxExecutionSpec,
    ) -> Result<(), LoopDomainError> {
        if execution.domain() != spec.domain() {
            return Err(LoopDomainError::ExecutionDomainMismatch);
        }
        if execution.call_model() != CallModel::CooperativeAsync {
            return Err(LoopDomainError::UnsupportedCallModel);
        }
        if !matches!(
            execution.workload_kind(),
            WorkloadKind::Io | WorkloadKind::Routing
        ) {
            return Err(LoopDomainError::UnsupportedWorkloadKind);
        }
        if execution.blocking_risk() != BlockingRisk::None {
            return Err(LoopDomainError::UnsupportedBlockingRisk);
        }
        if !matches!(
            execution.run_bound_provenance(),
            RunBoundProvenance::Measured | RunBoundProvenance::Certified
        ) {
            return Err(LoopDomainError::UnsupportedRunBoundProvenance);
        }
        if !matches!(
            execution.overrun_action(),
            paraegox_runtime_contracts::execution::OverrunAction::CooperativeCancel
                | paraegox_runtime_contracts::execution::OverrunAction::Escalate
        ) {
            return Err(LoopDomainError::UnsupportedOverrunAction);
        }
        Ok(())
    }

    fn validate_binding(
        execution: MailboxExecutionSpec,
        binding: BindingAssignment,
    ) -> Result<(), LoopDomainError> {
        if binding.mailbox() != execution.mailbox() {
            return Err(LoopDomainError::BindingMailboxMismatch);
        }
        if binding.target_instance() != execution.target_instance() {
            return Err(LoopDomainError::BindingTargetMismatch);
        }
        if binding.delivery().overflow_policy() == OverflowPolicy::BlockUntilDeadline
            || binding.mailbox_spec().overflow_policy() == OverflowPolicy::BlockUntilDeadline
        {
            return Err(LoopDomainError::UnsupportedBindingPolicy);
        }
        Ok(())
    }

    #[must_use]
    pub(crate) const fn spec(&self) -> LoopDomainSpec {
        self.spec
    }

    #[must_use]
    pub(crate) const fn domain_epoch(&self) -> DomainEpoch {
        self.domain_epoch
    }

    #[must_use]
    pub(crate) fn owner_identity(&self) -> LoopDomainOwnerIdentity {
        self.owner.clone()
    }

    #[must_use]
    pub(crate) const fn clock_domain(&self) -> ClockDomainRef {
        self.clock_domain
    }

    #[must_use]
    pub(crate) const fn clock_generation(&self) -> ClockGeneration {
        self.clock_generation
    }

    #[must_use]
    pub(crate) fn execution_spec(&self, mailbox: MailboxRef) -> Option<MailboxExecutionSpec> {
        self.mailboxes.get(&mailbox).map(|entry| entry.execution)
    }

    #[must_use]
    pub(crate) fn binding_assignment(&self, mailbox: MailboxRef) -> Option<BindingAssignment> {
        self.mailboxes.get(&mailbox).map(|entry| entry.assignment)
    }

    #[must_use]
    pub(crate) fn active_ingress(&self, binding_id: BindingId) -> Option<LoopDomainIngress> {
        let binding_epoch = self
            .binding_index
            .get(&binding_id)
            .and_then(|mailbox| self.mailboxes.get(mailbox))
            .and_then(|entry| entry.active_epoch)?;
        Some(LoopDomainIngress {
            owner: self.owner.clone(),
            binding_id,
            binding_epoch,
        })
    }

    /// Offers only through the exact installed active PortBinding route.
    pub(crate) fn try_offer(
        &mut self,
        ingress: &LoopDomainIngress,
        message: ValidatedMessage,
        reading: ClockReading,
    ) -> Result<OfferReport, LoopDomainOfferFailure> {
        if ingress.owner != self.owner {
            return Err(LoopDomainOfferFailure::new(
                LoopDomainError::IngressMismatch,
                message,
            ));
        }
        let binding_id = ingress.binding_id;
        let Some(mailbox) = self.binding_index.get(&binding_id).copied() else {
            return Err(LoopDomainOfferFailure::new(
                LoopDomainError::UnknownBinding,
                message,
            ));
        };
        let Some(entry) = self.mailboxes.get_mut(&mailbox) else {
            return Err(LoopDomainOfferFailure::new(
                LoopDomainError::StateInconsistent,
                message,
            ));
        };
        entry
            .binding
            .offer(
                binding_id,
                ingress.binding_epoch,
                message,
                &mut entry.mailbox,
                reading,
            )
            .map_err(|failure: BindingOfferFailure| {
                LoopDomainOfferFailure::new(
                    LoopDomainError::PortBinding(failure.error()),
                    failure.into_message(),
                )
            })
    }

    /// Performs expiry, permit selection, and exact Mailbox dequeue in one
    /// synchronous owner turn. No task or Future is created on any outcome.
    pub(crate) fn try_dispatch(
        &mut self,
        reading: ClockReading,
    ) -> Result<LoopDomainDispatchReport, LoopDomainError> {
        self.ensure_reading(reading)?;
        let mut terminals = Vec::new();
        let initial = self.collect_readiness(reading)?;
        let expired_mailboxes = initial
            .iter()
            .filter_map(|(mailbox, head)| {
                matches!(head, MailboxHeadReadiness::Expired { .. }).then_some(*mailbox)
            })
            .collect::<Vec<_>>();
        for mailbox in expired_mailboxes {
            let entry = self
                .mailboxes
                .get_mut(&mailbox)
                .ok_or(LoopDomainError::StateInconsistent)?;
            terminals.extend(entry.mailbox.expire_queued(reading)?);
        }
        self.retire_closed_bindings()?;
        let readiness = if terminals.is_empty() {
            initial
        } else {
            self.collect_readiness(reading)?
        };
        let inputs = readiness
            .into_iter()
            .map(|(mailbox, head)| DispatchReadiness::new(mailbox, head))
            .collect::<Vec<_>>();
        match self
            .dispatch
            .try_select_and_acquire(&inputs, &mut self.permits)?
        {
            DispatchDecision::Idle(reason) => Ok(LoopDomainDispatchReport {
                outcome: LoopDomainDispatchOutcome::Idle(reason),
                terminals,
            }),
            DispatchDecision::Selected(grant) => self.start_selected(grant, reading, terminals),
        }
    }

    fn start_selected(
        &mut self,
        grant: DispatchGrant,
        reading: ClockReading,
        mut terminals: Vec<TerminalRecord>,
    ) -> Result<LoopDomainDispatchReport, LoopDomainError> {
        let (selection, mut permit) = grant.into_parts();
        let Some(entry) = self.mailboxes.get_mut(&selection.mailbox()) else {
            self.permits.release(&mut permit)?;
            return Err(LoopDomainError::StateInconsistent);
        };
        let report = match entry.mailbox.try_begin_inflight(reading) {
            Ok(report) => report,
            Err(error) => {
                self.permits.release(&mut permit)?;
                return Err(LoopDomainError::Mailbox(error));
            }
        };
        let (outcome, expired) = report.into_parts();
        terminals.extend(expired);
        let MailboxDispatchOutcome::Started(inflight) = outcome else {
            self.permits.release(&mut permit)?;
            return Err(LoopDomainError::DispatchInvariant);
        };
        Ok(LoopDomainDispatchReport {
            outcome: LoopDomainDispatchOutcome::Started(Box::new(LoopDomainGrant {
                owner: self.owner.clone(),
                clock_domain: self.clock_domain,
                clock_generation: self.clock_generation,
                execution: entry.execution,
                target_port: entry.assignment.target_port(),
                inflight,
                permit,
                callback_claimed: false,
            })),
            terminals,
        })
    }

    fn collect_readiness(
        &self,
        reading: ClockReading,
    ) -> Result<Vec<(MailboxRef, MailboxHeadReadiness)>, LoopDomainError> {
        self.mailboxes
            .iter()
            .map(|(mailbox, entry)| {
                entry
                    .mailbox
                    .head_readiness(reading)
                    .map(|head| (*mailbox, head))
                    .map_err(LoopDomainError::Mailbox)
            })
            .collect()
    }

    /// Commits the exact Mailbox terminal while conservatively retaining the
    /// domain permit in the returned release capability.
    pub(crate) fn finish(
        &mut self,
        grant: LoopDomainGrant,
        reason: TerminalReason,
    ) -> Result<LoopDomainRelease, LoopDomainFinishFailure> {
        if !self.matches_grant(&grant) {
            return Err(LoopDomainFinishFailure::new(
                LoopDomainError::GrantMismatch,
                grant,
            ));
        }
        let LoopDomainGrant {
            owner,
            clock_domain,
            clock_generation,
            execution,
            target_port,
            inflight,
            permit,
            callback_claimed,
        } = grant;
        let Some(entry) = self.mailboxes.get_mut(&execution.mailbox()) else {
            return Err(LoopDomainFinishFailure::new(
                LoopDomainError::UnknownMailbox,
                LoopDomainGrant {
                    owner,
                    clock_domain,
                    clock_generation,
                    execution,
                    target_port,
                    inflight,
                    permit,
                    callback_claimed,
                },
            ));
        };
        match entry.mailbox.finish(inflight, reason) {
            Ok(terminal) => Ok(LoopDomainRelease {
                owner,
                clock_domain,
                clock_generation,
                execution,
                terminal,
                permit,
            }),
            Err(failure) => Err(LoopDomainFinishFailure::new(
                LoopDomainError::Mailbox(failure.error()),
                LoopDomainGrant {
                    owner,
                    clock_domain,
                    clock_generation,
                    execution,
                    target_port,
                    inflight: failure.into_token(),
                    permit,
                    callback_claimed,
                },
            )),
        }
    }

    /// Exact uncertain terminal used only after the callback owner has joined
    /// or otherwise returned the grant from its task scope.
    pub(crate) fn abandon_after_caller_release(
        &mut self,
        grant: LoopDomainGrant,
    ) -> Result<LoopDomainRelease, LoopDomainFinishFailure> {
        self.finish(grant, TerminalReason::Uncertain)
    }

    /// Releases a domain permit after its Mailbox terminal has committed.
    pub(crate) fn release(
        &mut self,
        release: &mut LoopDomainRelease,
    ) -> Result<(), LoopDomainError> {
        if release.owner != self.owner
            || release.clock_domain != self.clock_domain
            || release.clock_generation != self.clock_generation
            || self
                .mailboxes
                .get(&release.execution.mailbox())
                .is_none_or(|entry| entry.execution != release.execution)
        {
            return Err(LoopDomainError::GrantMismatch);
        }
        self.permits.release(&mut release.permit)?;
        self.retire_closed_bindings()?;
        Ok(())
    }

    /// Revokes every active PortBinding and begins drain on its exact Mailbox.
    pub(crate) fn stop_accepting(&mut self) -> Result<(), LoopDomainError> {
        for entry in self.mailboxes.values() {
            entry.mailbox.snapshot()?;
            if entry.binding.prepared_epoch().is_some()
                || entry.active_epoch != entry.binding.active().map(|route| route.epoch())
                || entry.draining_epoch != entry.binding.draining().map(|route| route.epoch())
                || entry
                    .binding
                    .active()
                    .is_some_and(|route| route.assignment() != entry.assignment)
                || entry
                    .binding
                    .draining()
                    .is_some_and(|route| route.assignment() != entry.assignment)
            {
                return Err(LoopDomainError::StateInconsistent);
            }
        }
        for entry in self.mailboxes.values_mut() {
            if let Some(active_epoch) = entry.active_epoch {
                entry.binding.revoke(active_epoch, &mut entry.mailbox)?;
                entry.active_epoch = None;
                entry.draining_epoch = Some(active_epoch);
            }
        }
        self.retire_closed_bindings()?;
        Ok(())
    }

    /// Cancels every queued Message after the domain has stopped accepting.
    pub(crate) fn cancel_all_queued(&mut self) -> Result<Vec<TerminalRecord>, LoopDomainError> {
        for entry in self.mailboxes.values() {
            if entry.mailbox.snapshot()?.lifecycle() == MailboxLifecycle::Accepting {
                return Err(LoopDomainError::ShutdownRequiresDraining);
            }
        }
        let mut records = Vec::new();
        for entry in self.mailboxes.values_mut() {
            records.extend(entry.mailbox.cancel_all_queued()?);
        }
        self.retire_closed_bindings()?;
        Ok(records)
    }

    /// Reconciles only accounting whose callback owners and permits have
    /// already been released by the caller. Active permits fail closed.
    pub(crate) fn abandon_all_after_caller_release(
        &mut self,
    ) -> Result<Vec<TerminalRecord>, LoopDomainError> {
        if self.permits.snapshot()?.in_use() != 0 {
            return Err(LoopDomainError::CallerReleaseRequired);
        }
        for entry in self.mailboxes.values() {
            if entry.mailbox.snapshot()?.lifecycle() == MailboxLifecycle::Accepting {
                return Err(LoopDomainError::ShutdownRequiresDraining);
            }
        }
        let mut records = Vec::new();
        for entry in self.mailboxes.values_mut() {
            records.extend(entry.mailbox.abandon_all_inflight_uncertain()?);
        }
        self.retire_closed_bindings()?;
        Ok(records)
    }

    fn retire_closed_bindings(&mut self) -> Result<(), LoopDomainError> {
        for entry in self.mailboxes.values_mut() {
            let Some(draining_epoch) = entry.draining_epoch else {
                continue;
            };
            if entry.mailbox.snapshot()?.lifecycle() == MailboxLifecycle::Closed {
                let route = entry
                    .binding
                    .retire_draining(draining_epoch, &entry.mailbox)?;
                if route.assignment() != entry.assignment || route.epoch() != draining_epoch {
                    return Err(LoopDomainError::StateInconsistent);
                }
                entry.draining_epoch = None;
            }
        }
        Ok(())
    }

    pub(crate) fn mailbox_snapshot(
        &self,
        mailbox: MailboxRef,
    ) -> Result<MailboxSnapshot, LoopDomainError> {
        self.mailboxes
            .get(&mailbox)
            .ok_or(LoopDomainError::UnknownMailbox)?
            .mailbox
            .snapshot()
            .map_err(LoopDomainError::Mailbox)
    }

    pub(crate) fn snapshot(&self) -> Result<LoopDomainSnapshot, LoopDomainError> {
        let mut queued_items = 0_u64;
        let mut queued_bytes = 0_u64;
        let mut inflight_items = 0_u64;
        let mut inflight_bytes = 0_u64;
        let mut retained_bytes = 0_u64;
        let mut accepting = 0_usize;
        let mut closed = 0_usize;
        let mut active_bindings = 0_usize;
        let mut draining_bindings = 0_usize;
        for entry in self.mailboxes.values() {
            let snapshot = entry.mailbox.snapshot()?;
            if entry.binding.prepared_epoch().is_some()
                || entry.active_epoch != entry.binding.active().map(|route| route.epoch())
                || entry.draining_epoch != entry.binding.draining().map(|route| route.epoch())
            {
                return Err(LoopDomainError::StateInconsistent);
            }
            if entry.active_epoch.is_some() {
                active_bindings += 1;
            }
            if entry.draining_epoch.is_some() {
                draining_bindings += 1;
            }
            queued_items = queued_items
                .checked_add(u64::from(snapshot.queued_items()))
                .ok_or(LoopDomainError::CounterOverflow)?;
            queued_bytes = queued_bytes
                .checked_add(snapshot.queued_bytes())
                .ok_or(LoopDomainError::CounterOverflow)?;
            inflight_items = inflight_items
                .checked_add(u64::from(snapshot.inflight_items()))
                .ok_or(LoopDomainError::CounterOverflow)?;
            inflight_bytes = inflight_bytes
                .checked_add(snapshot.inflight_bytes())
                .ok_or(LoopDomainError::CounterOverflow)?;
            retained_bytes = retained_bytes
                .checked_add(snapshot.retained_bytes())
                .ok_or(LoopDomainError::CounterOverflow)?;
            match snapshot.lifecycle() {
                MailboxLifecycle::Accepting => accepting += 1,
                MailboxLifecycle::Draining => {}
                MailboxLifecycle::Closed => closed += 1,
            }
        }
        let lifecycle = if accepting == self.mailboxes.len() {
            LoopDomainLifecycle::Accepting
        } else if closed == self.mailboxes.len() {
            LoopDomainLifecycle::Closed
        } else {
            LoopDomainLifecycle::Draining
        };
        Ok(LoopDomainSnapshot {
            planned_domain: self.spec.domain(),
            domain_epoch: self.domain_epoch,
            clock_domain: self.clock_domain,
            clock_generation: self.clock_generation,
            lifecycle,
            mailbox_count: u16::try_from(self.mailboxes.len())
                .map_err(|_| LoopDomainError::StateInconsistent)?,
            active_bindings: u16::try_from(active_bindings)
                .map_err(|_| LoopDomainError::StateInconsistent)?,
            draining_bindings: u16::try_from(draining_bindings)
                .map_err(|_| LoopDomainError::StateInconsistent)?,
            queued_items,
            queued_bytes,
            inflight_items,
            inflight_bytes,
            retained_bytes,
            permits: self.permits.snapshot()?,
        })
    }

    fn ensure_reading(&self, reading: ClockReading) -> Result<(), LoopDomainError> {
        if reading.domain() != self.clock_domain {
            return Err(LoopDomainError::ClockDomainMismatch);
        }
        if reading.generation() != self.clock_generation {
            return Err(LoopDomainError::ClockGenerationMismatch);
        }
        Ok(())
    }

    fn matches_grant(&self, grant: &LoopDomainGrant) -> bool {
        grant.owner == self.owner
            && grant.clock_domain == self.clock_domain
            && grant.clock_generation == self.clock_generation
            && self
                .mailboxes
                .get(&grant.execution.mailbox())
                .is_some_and(|entry| entry.execution == grant.execution)
    }
}

const fn map_dispatch_class(class: PlannedDispatchClass) -> DispatchClass {
    match class {
        PlannedDispatchClass::Control => DispatchClass::Control,
        PlannedDispatchClass::Interactive => DispatchClass::Interactive,
        PlannedDispatchClass::Stream => DispatchClass::Stream,
        PlannedDispatchClass::Background => DispatchClass::Background,
    }
}

const fn dispatch_class_index(class: DispatchClass) -> usize {
    match class {
        DispatchClass::Control => 0,
        DispatchClass::Interactive => 1,
        DispatchClass::Stream => 2,
        DispatchClass::Background => 3,
    }
}

/// Fail-closed construction, dispatch, and lifecycle errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoopDomainError {
    MissingExecution,
    TooManyExecutions,
    ExecutionDomainMismatch,
    DuplicateExecutionBinding,
    DuplicateExecutionMailbox,
    MissingBinding,
    DuplicateBinding,
    BindingMailboxMismatch,
    BindingTargetMismatch,
    UnsupportedBindingPolicy,
    UnsupportedCallModel,
    UnsupportedWorkloadKind,
    UnsupportedBlockingRisk,
    UnsupportedRunBoundProvenance,
    UnsupportedOverrunAction,
    SharedCapacityRequired,
    UnknownBinding,
    IngressMismatch,
    UnknownMailbox,
    ClockDomainMismatch,
    ClockGenerationMismatch,
    GrantMismatch,
    CallbackAlreadyClaimed,
    ShutdownRequiresDraining,
    CallerReleaseRequired,
    DispatchInvariant,
    CounterOverflow,
    StateInconsistent,
    Mailbox(MailboxError),
    PortBinding(PortBindingError),
    Dispatcher(DispatcherError),
    Permit(PermitError),
}

impl From<MailboxError> for LoopDomainError {
    fn from(error: MailboxError) -> Self {
        Self::Mailbox(error)
    }
}

impl From<DispatcherError> for LoopDomainError {
    fn from(error: DispatcherError) -> Self {
        Self::Dispatcher(error)
    }
}

impl From<PortBindingError> for LoopDomainError {
    fn from(error: PortBindingError) -> Self {
        Self::PortBinding(error)
    }
}

impl From<PermitError> for LoopDomainError {
    fn from(error: PermitError) -> Self {
        Self::Permit(error)
    }
}

impl fmt::Display for LoopDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mailbox(error) => return error.fmt(formatter),
            Self::PortBinding(error) => return error.fmt(formatter),
            Self::Dispatcher(error) => return error.fmt(formatter),
            Self::Permit(error) => return error.fmt(formatter),
            _ => {}
        }
        write!(formatter, "loop-domain error {self:?}")
    }
}

impl std::error::Error for LoopDomainError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::time::{
        BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant,
    };
    use paraegox_runtime_contracts::assignment::{
        BindingAssignment, BindingId, DeliveryProfile, InstanceRef, InteractionKind, MailboxRef,
        MailboxSpec, OverflowPolicy, PortCardinality, PortDirection, PortEndpoint, PortRef,
        PortSpec, SchemaRef,
    };
    use paraegox_runtime_contracts::execution::{
        BlockingRisk, CallModel, CallbackBudgets, CardDefinitionRef, CardImplementationRef,
        CardSubjectSpec, DispatchClass, DomainRef, LoopDomainCapacity, LoopDomainSpec,
        LoopExecutionRequirements, LoopLifecycleBudgets, MAX_MINIMUM_SERVICE_WEIGHT,
        MAX_SERVICE_COST_TOKENS, MailboxDispatchPolicy, MailboxExecutionSpec, OverrunAction,
        RunBoundProvenance, WorkloadKind,
    };

    use crate::card_instance::DomainEpoch;
    use crate::dispatcher::{DispatchIdleReason, PermitError};
    use crate::mailbox::{
        EnqueueOutcome, Mailbox, MessageId, PayloadHandle, TerminalReason, ValidatedMessage,
    };
    use crate::port_binding::{PortBinding, PortBindingError};

    use super::{
        LoopDomainCore, LoopDomainDispatchOutcome, LoopDomainError, LoopDomainGrant,
        LoopDomainIngress, LoopDomainLifecycle,
    };

    const CLOCK_DOMAIN: u8 = 0xC1;
    const CLOCK_GENERATION: u64 = 7;

    fn generation() -> ClockGeneration {
        let Ok(value) = ClockGeneration::try_new(CLOCK_GENERATION) else {
            panic!("test clock generation must be nonzero");
        };
        value
    }

    fn reading(now: u64) -> ClockReading {
        ClockReading::new(
            ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16]),
            generation(),
            MonotonicInstant::from_ticks(now),
        )
    }

    fn schema() -> SchemaRef {
        let Ok(value) = SchemaRef::try_new([0x41; 16], 1, Digest32::from_bytes([0x42; 32])) else {
            panic!("test schema must be valid");
        };
        value
    }

    fn domain(identity: u8, total: u32, reserved: u32) -> LoopDomainSpec {
        let reserved_budget = if reserved == 0 { 0 } else { 1_000 };
        let Ok(capacity) = LoopDomainCapacity::try_new(
            total,
            reserved,
            BoundedDuration::from_nanos(1_000),
            BoundedDuration::from_nanos(reserved_budget),
        ) else {
            panic!("test domain capacity must be valid");
        };
        let Ok(lifecycle) = LoopLifecycleBudgets::try_new(
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(100),
        ) else {
            panic!("test domain lifecycle must be valid");
        };
        LoopDomainSpec::new(DomainRef::from_bytes([identity; 16]), capacity, lifecycle)
    }

    fn binding(identity: u8, overflow: OverflowPolicy) -> BindingAssignment {
        let output = PortSpec::new(
            PortDirection::Out,
            schema(),
            InteractionKind::Signal,
            PortCardinality::One,
        );
        let input = PortSpec::new(
            PortDirection::In,
            schema(),
            InteractionKind::Signal,
            PortCardinality::One,
        );
        let Ok(delivery) =
            DeliveryProfile::try_new(4, BoundedDuration::from_nanos(1_000), overflow)
        else {
            panic!("test delivery profile must be valid");
        };
        let Ok(mailbox_spec) = MailboxSpec::try_new(
            128,
            512,
            BoundedDuration::from_nanos(1_000),
            4,
            512,
            overflow,
        ) else {
            panic!("test mailbox spec must be valid");
        };
        let Ok(value) = BindingAssignment::try_new(
            BindingId::from_bytes([identity; 16]),
            PortEndpoint::new(
                InstanceRef::from_bytes([0x10; 16]),
                PortRef::from_bytes([identity; 16]),
                output,
            ),
            PortEndpoint::new(
                InstanceRef::from_bytes([identity.wrapping_add(0x20); 16]),
                PortRef::from_bytes([identity.wrapping_add(0x40); 16]),
                input,
            ),
            MailboxRef::from_bytes([identity.wrapping_add(0x60); 16]),
            delivery,
            mailbox_spec,
        ) else {
            panic!("test binding must be valid");
        };
        value
    }

    #[derive(Clone, Copy)]
    struct TestExecutionEligibility {
        call_model: CallModel,
        workload: WorkloadKind,
        blocking: BlockingRisk,
        provenance: RunBoundProvenance,
        overrun_action: OverrunAction,
    }

    fn execution(
        binding: BindingAssignment,
        domain: LoopDomainSpec,
        class: DispatchClass,
        cost: u32,
        weight: u32,
        max_burst: u16,
        eligibility: TestExecutionEligibility,
    ) -> MailboxExecutionSpec {
        let subject = CardSubjectSpec::new(
            CardDefinitionRef::from_bytes([0x71; 16]),
            CardImplementationRef::from_bytes([0x72; 16]),
            Digest32::from_bytes([0x73; 32]),
            Digest32::from_bytes([0x74; 32]),
            Digest32::from_bytes([0x75; 32]),
        );
        let Ok(requirements) = LoopExecutionRequirements::try_new(
            eligibility.call_model,
            eligibility.workload,
            eligibility.blocking,
            eligibility.provenance,
            BoundedDuration::from_nanos(1),
        ) else {
            panic!("test execution requirements must be valid");
        };
        let Ok(budgets) = CallbackBudgets::try_new(
            BoundedDuration::from_nanos(10),
            BoundedDuration::from_nanos(10),
            eligibility.overrun_action,
        ) else {
            panic!("test callback budgets must be valid");
        };
        let Ok(dispatch) =
            MailboxDispatchPolicy::try_new(class, cost, weight, max_burst, 1, budgets)
        else {
            panic!("test dispatch policy must be valid");
        };
        let Ok(value) = MailboxExecutionSpec::try_new(
            binding.binding_id(),
            binding.mailbox(),
            binding.target_instance(),
            domain.domain(),
            subject,
            requirements,
            dispatch,
        ) else {
            panic!("test mailbox execution must be valid");
        };
        value
    }

    fn eligible_execution(
        binding: BindingAssignment,
        domain: LoopDomainSpec,
        class: DispatchClass,
        cost: u32,
        weight: u32,
        max_burst: u16,
    ) -> MailboxExecutionSpec {
        execution(
            binding,
            domain,
            class,
            cost,
            weight,
            max_burst,
            TestExecutionEligibility {
                call_model: CallModel::CooperativeAsync,
                workload: WorkloadKind::Io,
                blocking: BlockingRisk::None,
                provenance: RunBoundProvenance::Measured,
                overrun_action: OverrunAction::CooperativeCancel,
            },
        )
    }

    fn core(
        domain: LoopDomainSpec,
        executions: &[MailboxExecutionSpec],
        bindings: &[BindingAssignment],
    ) -> LoopDomainCore {
        core_with_epoch(domain, executions, bindings, 1)
    }

    fn core_with_epoch(
        domain: LoopDomainSpec,
        executions: &[MailboxExecutionSpec],
        bindings: &[BindingAssignment],
        domain_epoch: u64,
    ) -> LoopDomainCore {
        LoopDomainCore::try_new(
            domain,
            executions,
            bindings,
            DomainEpoch::try_new(domain_epoch)
                .unwrap_or_else(|error| panic!("test domain epoch failed: {error}")),
            ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16]),
            generation(),
        )
        .unwrap_or_else(|error| panic!("test loop domain failed: {error}"))
    }

    fn deadline(ticks: u64) -> paraegox_kernel::time::MonotonicDeadline {
        reading(0)
            .try_deadline_after(BoundedDuration::from_nanos(ticks))
            .unwrap_or_else(|error| panic!("test deadline failed: {error}"))
    }

    fn message(
        identity: u8,
        binding: BindingAssignment,
        fresh_until: u64,
        run_deadline: u64,
    ) -> ValidatedMessage {
        let payload = PayloadHandle::try_from_vec(vec![identity])
            .unwrap_or_else(|error| panic!("test payload failed: {error}"));
        ValidatedMessage::new_with_deadlines(
            MessageId::from_bytes([identity; 16]),
            binding.target_spec().schema(),
            binding.target_spec().interaction(),
            None,
            deadline(fresh_until),
            deadline(run_deadline),
            payload,
        )
    }

    fn offer(core: &mut LoopDomainCore, binding: BindingAssignment, message: ValidatedMessage) {
        let Some(ingress) = core.active_ingress(binding.binding_id()) else {
            panic!("test binding must be active");
        };
        let report = core
            .try_offer(&ingress, message, reading(0))
            .unwrap_or_else(|failure| panic!("test offer failed: {}", failure.error()));
        assert!(matches!(report.outcome(), EnqueueOutcome::Admitted));
    }

    fn started(core: &mut LoopDomainCore, now: u64) -> LoopDomainGrant {
        let report = core
            .try_dispatch(reading(now))
            .unwrap_or_else(|error| panic!("test dispatch failed: {error}"));
        let (outcome, terminals) = report.into_parts();
        assert!(terminals.is_empty());
        let LoopDomainDispatchOutcome::Started(grant) = outcome else {
            panic!("test dispatch must start");
        };
        *grant
    }

    fn complete(core: &mut LoopDomainCore, grant: LoopDomainGrant, reason: TerminalReason) {
        let mut release = core
            .finish(grant, reason)
            .unwrap_or_else(|failure| panic!("test finish failed: {}", failure.error()));
        assert!(release.permit_is_active());
        core.release(&mut release)
            .unwrap_or_else(|error| panic!("test release failed: {error}"));
        assert!(!release.permit_is_active());
    }

    #[test]
    fn signed_subset_builds_only_referenced_binding_and_keeps_clock_identity_distinct() {
        let domain = domain(0x31, 1, 0);
        let active = binding(1, OverflowPolicy::RejectNew);
        let inert = binding(2, OverflowPolicy::RejectNew);
        let execution = eligible_execution(
            active,
            domain,
            DispatchClass::Interactive,
            MAX_SERVICE_COST_TOKENS,
            MAX_MINIMUM_SERVICE_WEIGHT,
            u16::MAX,
        );
        let core = core(domain, &[execution], &[active, inert]);
        let snapshot = core
            .snapshot()
            .unwrap_or_else(|error| panic!("test snapshot failed: {error}"));

        assert_eq!(snapshot.planned_domain(), domain.domain());
        assert_eq!(snapshot.domain_epoch().value(), 1);
        assert_eq!(
            snapshot.clock_domain(),
            ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16])
        );
        assert_ne!(
            snapshot.planned_domain().as_bytes(),
            snapshot.clock_domain().as_bytes()
        );
        assert_eq!(snapshot.clock_generation(), generation());
        assert_eq!(snapshot.mailbox_count(), 1);
        assert_eq!(snapshot.active_bindings(), 1);
        assert_eq!(snapshot.draining_bindings(), 0);
        assert_eq!(snapshot.lifecycle(), LoopDomainLifecycle::Accepting);
        assert_eq!(core.execution_spec(active.mailbox()), Some(execution));
        assert_eq!(core.binding_assignment(active.mailbox()), Some(active));
        assert!(core.active_ingress(active.binding_id()).is_some());
        assert!(core.active_ingress(inert.binding_id()).is_none());
    }

    #[test]
    fn runtime_rechecks_every_loop_eligibility_dimension() {
        let domain = domain(0x31, 1, 0);
        let binding = binding(1, OverflowPolicy::RejectNew);
        let cases = [
            (
                CallModel::Synchronous,
                WorkloadKind::Io,
                BlockingRisk::None,
                RunBoundProvenance::Measured,
                LoopDomainError::UnsupportedCallModel,
            ),
            (
                CallModel::CooperativeAsync,
                WorkloadKind::Cpu,
                BlockingRisk::None,
                RunBoundProvenance::Measured,
                LoopDomainError::UnsupportedWorkloadKind,
            ),
            (
                CallModel::CooperativeAsync,
                WorkloadKind::Routing,
                BlockingRisk::Bounded,
                RunBoundProvenance::Measured,
                LoopDomainError::UnsupportedBlockingRisk,
            ),
            (
                CallModel::CooperativeAsync,
                WorkloadKind::Io,
                BlockingRisk::None,
                RunBoundProvenance::Declared,
                LoopDomainError::UnsupportedRunBoundProvenance,
            ),
        ];
        for (call, workload, blocking, provenance, expected) in cases {
            let execution = execution(
                binding,
                domain,
                DispatchClass::Interactive,
                1,
                1,
                1,
                TestExecutionEligibility {
                    call_model: call,
                    workload,
                    blocking,
                    provenance,
                    overrun_action: OverrunAction::CooperativeCancel,
                },
            );
            assert_eq!(
                LoopDomainCore::try_new(
                    domain,
                    &[execution],
                    &[binding],
                    DomainEpoch::try_new(1)
                        .unwrap_or_else(|error| panic!("test domain epoch failed: {error}")),
                    ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16]),
                    generation(),
                )
                .err(),
                Some(expected)
            );
        }

        let execution = execution(
            binding,
            domain,
            DispatchClass::Interactive,
            1,
            1,
            1,
            TestExecutionEligibility {
                call_model: CallModel::CooperativeAsync,
                workload: WorkloadKind::Io,
                blocking: BlockingRisk::None,
                provenance: RunBoundProvenance::Measured,
                overrun_action: OverrunAction::Continue,
            },
        );
        assert_eq!(
            LoopDomainCore::try_new(
                domain,
                &[execution],
                &[binding],
                DomainEpoch::try_new(1)
                    .unwrap_or_else(|error| panic!("test domain epoch failed: {error}")),
                ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16]),
                generation(),
            )
            .err(),
            Some(LoopDomainError::UnsupportedOverrunAction)
        );
    }

    #[test]
    fn ingress_requires_exact_active_binding_and_epoch_without_payload_loss() {
        let domain = domain(0x31, 1, 0);
        let binding = binding(1, OverflowPolicy::RejectNew);
        let execution = eligible_execution(binding, domain, DispatchClass::Interactive, 1, 1, 1);
        let mut core = core(domain, &[execution], &[binding]);
        let empty = core
            .snapshot()
            .unwrap_or_else(|error| panic!("test snapshot failed: {error}"));

        let wrong_id = BindingId::from_bytes([0xEE; 16]);
        let ingress = core
            .active_ingress(binding.binding_id())
            .unwrap_or_else(|| panic!("test binding must be active"));
        let wrong_ingress = LoopDomainIngress {
            binding_id: wrong_id,
            ..ingress.clone()
        };
        let failure = core
            .try_offer(&wrong_ingress, message(1, binding, 100, 100), reading(0))
            .expect_err("wrong binding must fail");
        assert_eq!(failure.error(), LoopDomainError::UnknownBinding);
        assert_eq!(failure.into_message().id(), MessageId::from_bytes([1; 16]));
        assert_eq!(
            core.snapshot()
                .unwrap_or_else(|error| panic!("test snapshot failed: {error}")),
            empty
        );

        let mut separate_mailbox = Mailbox::try_new(
            binding.mailbox(),
            binding.target_spec().schema(),
            binding.target_spec().interaction(),
            binding.mailbox_spec(),
            reading(0).domain(),
            generation(),
        )
        .unwrap_or_else(|error| panic!("test mailbox failed: {error}"));
        let mut separate_binding = PortBinding::new(binding.binding_id());
        let first = separate_binding
            .prepare(binding, &separate_mailbox, None)
            .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
        separate_binding
            .activate(first, &separate_mailbox, None)
            .unwrap_or_else(|error| panic!("test activate failed: {error}"));
        let wrong_epoch = separate_binding
            .revoke(first, &mut separate_mailbox)
            .unwrap_or_else(|error| panic!("test revoke failed: {error}"));
        let wrong_ingress = LoopDomainIngress {
            binding_epoch: wrong_epoch,
            ..ingress
        };
        let failure = core
            .try_offer(&wrong_ingress, message(2, binding, 100, 100), reading(0))
            .expect_err("wrong epoch must fail");
        assert_eq!(
            failure.error(),
            LoopDomainError::PortBinding(PortBindingError::ActiveEpochMismatch)
        );
        assert_eq!(failure.into_message().id(), MessageId::from_bytes([2; 16]));
        assert_eq!(
            core.snapshot()
                .unwrap_or_else(|error| panic!("test snapshot failed: {error}")),
            empty
        );

        offer(&mut core, binding, message(3, binding, 100, 100));
        assert_eq!(
            core.mailbox_snapshot(binding.mailbox())
                .unwrap_or_else(|error| panic!("test mailbox snapshot failed: {error}"))
                .queued_items(),
            1
        );
    }

    #[test]
    fn core_incarnation_rejects_same_epoch_ingress_grant_and_release_without_aba() {
        let planned = domain(0x31, 1, 0);
        let binding = binding(1, OverflowPolicy::RejectNew);
        let execution = eligible_execution(binding, planned, DispatchClass::Interactive, 1, 1, 1);
        let mut old = core_with_epoch(planned, &[execution], &[binding], 1);
        let mut current = core_with_epoch(planned, &[execution], &[binding], 1);
        assert_eq!(old.domain_epoch(), current.domain_epoch());
        assert_ne!(old.owner_identity(), current.owner_identity());

        let stale_ingress = old
            .active_ingress(binding.binding_id())
            .unwrap_or_else(|| panic!("old ingress must be active"));
        let rejected = current
            .try_offer(&stale_ingress, message(2, binding, 100, 100), reading(0))
            .expect_err("successor domain must reject a stale ingress capability");
        assert_eq!(rejected.error(), LoopDomainError::IngressMismatch);
        assert_eq!(rejected.into_message().id(), MessageId::from_bytes([2; 16]));

        offer(&mut old, binding, message(1, binding, 100, 100));
        offer(&mut current, binding, message(1, binding, 100, 100));
        let old_grant = started(&mut old, 0);
        let current_grant = started(&mut current, 0);
        let current_before = current
            .snapshot()
            .unwrap_or_else(|error| panic!("current snapshot failed: {error}"));

        let rejected = current
            .finish(old_grant, TerminalReason::Completed)
            .expect_err("successor domain must reject an old-generation grant");
        assert_eq!(rejected.error(), LoopDomainError::GrantMismatch);
        assert_eq!(
            current
                .snapshot()
                .unwrap_or_else(|error| panic!("current snapshot failed: {error}")),
            current_before
        );
        let old_grant = rejected.into_grant();
        let mut old_release = old
            .finish(old_grant, TerminalReason::Completed)
            .unwrap_or_else(|failure| panic!("old finish failed: {}", failure.error()));

        assert_eq!(
            current.release(&mut old_release),
            Err(LoopDomainError::GrantMismatch)
        );
        assert!(old_release.permit_is_active());
        assert_eq!(
            current
                .snapshot()
                .unwrap_or_else(|error| panic!("current snapshot failed: {error}")),
            current_before
        );
        old.release(&mut old_release)
            .unwrap_or_else(|error| panic!("old release failed: {error}"));
        complete(&mut current, current_grant, TerminalReason::Completed);

        for core in [&mut old, &mut current] {
            core.stop_accepting()
                .unwrap_or_else(|error| panic!("test stop failed: {error}"));
            assert!(
                core.cancel_all_queued()
                    .unwrap_or_else(|error| panic!("test cancel failed: {error}"))
                    .is_empty()
            );
            assert!(
                core.snapshot()
                    .unwrap_or_else(|error| panic!("test zero snapshot failed: {error}"))
                    .is_zero_cleanup()
            );
        }
    }

    #[test]
    fn zero_shared_capacity_is_rejected_before_non_control_ingress_exists() {
        let reserved_domain = domain(0x31, 1, 1);
        let data_binding = binding(1, OverflowPolicy::RejectNew);
        let execution = eligible_execution(
            data_binding,
            reserved_domain,
            DispatchClass::Interactive,
            1,
            1,
            1,
        );
        assert_eq!(
            LoopDomainCore::try_new(
                reserved_domain,
                &[execution],
                &[data_binding],
                DomainEpoch::try_new(1)
                    .unwrap_or_else(|error| panic!("test domain epoch failed: {error}")),
                ClockDomainRef::from_bytes([CLOCK_DOMAIN; 16]),
                generation(),
            )
            .err(),
            Some(LoopDomainError::SharedCapacityRequired)
        );
    }

    #[test]
    fn exact_expiry_never_dequeues_or_creates_a_grant() {
        let expiry_domain = domain(0x32, 1, 0);
        let expiry_binding = binding(2, OverflowPolicy::RejectNew);
        let expiry_execution = eligible_execution(
            expiry_binding,
            expiry_domain,
            DispatchClass::Control,
            1,
            1,
            1,
        );
        let mut expiry_core = core(expiry_domain, &[expiry_execution], &[expiry_binding]);
        offer(
            &mut expiry_core,
            expiry_binding,
            message(2, expiry_binding, 5, 50),
        );
        let report = expiry_core
            .try_dispatch(reading(5))
            .unwrap_or_else(|error| panic!("test expiry dispatch failed: {error}"));
        assert!(matches!(
            report.outcome(),
            LoopDomainDispatchOutcome::Idle(DispatchIdleReason::NoReadyMailbox)
        ));
        assert_eq!(report.terminals().len(), 1);
        assert_eq!(
            report.terminals()[0].reason(),
            TerminalReason::StaleBeforeRun
        );
        let snapshot = expiry_core
            .snapshot()
            .unwrap_or_else(|error| panic!("test snapshot failed: {error}"));
        assert_eq!(snapshot.queued_items(), 0);
        assert_eq!(snapshot.inflight_items(), 0);
        assert_eq!(snapshot.permits().in_use(), 0);
    }

    #[test]
    fn control_uses_reserve_while_data_holds_shared_capacity() {
        let domain = domain(0x31, 2, 1);
        let data = binding(1, OverflowPolicy::RejectNew);
        let control = binding(2, OverflowPolicy::RejectNew);
        let executions = [
            eligible_execution(data, domain, DispatchClass::Interactive, 1, 1, 1),
            eligible_execution(control, domain, DispatchClass::Control, 1, 1, 1),
        ];
        let mut core = core(domain, &executions, &[data, control]);
        offer(&mut core, data, message(1, data, 100, 100));
        let data_grant = started(&mut core, 0);
        assert_eq!(data_grant.execution_spec(), executions[0]);

        offer(&mut core, control, message(2, control, 100, 100));
        let control_grant = started(&mut core, 0);
        assert_eq!(control_grant.execution_spec(), executions[1]);
        let full = core
            .snapshot()
            .unwrap_or_else(|error| panic!("test snapshot failed: {error}"));
        assert_eq!(full.permits().shared_in_use(), 1);
        assert_eq!(full.permits().control_reserved_in_use(), 1);

        complete(&mut core, data_grant, TerminalReason::Completed);
        complete(&mut core, control_grant, TerminalReason::Completed);
        assert_eq!(
            core.snapshot()
                .unwrap_or_else(|error| panic!("test snapshot failed: {error}"))
                .permits()
                .in_use(),
            0
        );
    }

    #[test]
    fn rejected_finish_returns_the_complete_grant_and_keeps_permit_conservative() {
        let domain = domain(0x31, 1, 0);
        let binding = binding(1, OverflowPolicy::RejectNew);
        let execution = eligible_execution(binding, domain, DispatchClass::Interactive, 1, 1, 1);
        let mut core = core(domain, &[execution], &[binding]);
        offer(&mut core, binding, message(1, binding, 100, 100));
        let grant = started(&mut core, 0);

        let failure = core
            .finish(grant, TerminalReason::Evicted)
            .expect_err("queued-only terminal must be rejected");
        assert_eq!(
            failure.error(),
            LoopDomainError::Mailbox(crate::mailbox::MailboxError::InvalidTerminalReason)
        );
        let held = core
            .snapshot()
            .unwrap_or_else(|error| panic!("test snapshot failed: {error}"));
        assert_eq!(held.inflight_items(), 1);
        assert_eq!(held.permits().in_use(), 1);

        complete(&mut core, failure.into_grant(), TerminalReason::Completed);
        let released = core
            .snapshot()
            .unwrap_or_else(|error| panic!("test snapshot failed: {error}"));
        assert_eq!(released.inflight_items(), 0);
        assert_eq!(released.permits().in_use(), 0);
    }

    #[test]
    fn signed_class_weight_is_aggregated_across_same_class_mailboxes() {
        let domain = domain(0x31, 1, 0);
        let first = binding(1, OverflowPolicy::RejectNew);
        let second = binding(2, OverflowPolicy::RejectNew);
        let third = binding(3, OverflowPolicy::RejectNew);
        let executions = [
            eligible_execution(first, domain, DispatchClass::Interactive, 1, 1, 1),
            eligible_execution(second, domain, DispatchClass::Interactive, 1, 1, 1),
            eligible_execution(third, domain, DispatchClass::Stream, 1, 1, 1),
        ];
        let mut core = core(domain, &executions, &[first, second, third]);
        for identity in 0..90_u8 {
            offer(&mut core, first, message(identity, first, 1_000, 1_000));
            offer(&mut core, second, message(identity, second, 1_000, 1_000));
            offer(&mut core, third, message(identity, third, 1_000, 1_000));
        }

        let mut counts = [0_u32; 3];
        for _ in 0..90 {
            let grant = started(&mut core, 0);
            let binding_id = grant.execution_spec().binding_id();
            if binding_id == first.binding_id() {
                counts[0] += 1;
            } else if binding_id == second.binding_id() {
                counts[1] += 1;
            } else if binding_id == third.binding_id() {
                counts[2] += 1;
            } else {
                panic!("dispatcher selected unknown signed metadata");
            }
            complete(&mut core, grant, TerminalReason::Completed);
        }
        assert_eq!(counts, [30, 30, 30]);
        assert_eq!(counts[0] + counts[1], counts[2] * 2);
    }

    #[test]
    fn shutdown_cancels_queue_and_reaches_zero_only_after_exact_abandon_release() {
        let domain = domain(0x31, 1, 0);
        let binding = binding(1, OverflowPolicy::RejectNew);
        let execution = eligible_execution(binding, domain, DispatchClass::Interactive, 1, 1, 1);
        let mut core = core(domain, &[execution], &[binding]);
        offer(&mut core, binding, message(1, binding, 100, 100));
        offer(&mut core, binding, message(2, binding, 100, 100));
        let grant = started(&mut core, 0);
        let ingress = core
            .active_ingress(binding.binding_id())
            .unwrap_or_else(|| panic!("test binding must be active"));

        core.stop_accepting()
            .unwrap_or_else(|error| panic!("test stop failed: {error}"));
        assert!(core.active_ingress(binding.binding_id()).is_none());
        let failure = core
            .try_offer(&ingress, message(3, binding, 100, 100), reading(0))
            .expect_err("revoked route must reject");
        assert_eq!(
            failure.error(),
            LoopDomainError::PortBinding(PortBindingError::NoActiveRoute)
        );
        assert_eq!(failure.into_message().id(), MessageId::from_bytes([3; 16]));

        let cancelled = core
            .cancel_all_queued()
            .unwrap_or_else(|error| panic!("test cancellation failed: {error}"));
        assert_eq!(cancelled.len(), 1);
        assert_eq!(cancelled[0].reason(), TerminalReason::Cancelled);
        assert_eq!(
            core.abandon_all_after_caller_release().err(),
            Some(LoopDomainError::CallerReleaseRequired)
        );

        let mut release = core
            .abandon_after_caller_release(grant)
            .unwrap_or_else(|failure| panic!("test abandon failed: {}", failure.error()));
        assert_eq!(release.terminal().reason(), TerminalReason::Uncertain);
        let before_release = core
            .snapshot()
            .unwrap_or_else(|error| panic!("test snapshot failed: {error}"));
        assert_eq!(before_release.lifecycle(), LoopDomainLifecycle::Closed);
        assert_eq!(before_release.permits().in_use(), 1);
        assert_eq!(before_release.active_bindings(), 0);
        assert_eq!(before_release.draining_bindings(), 1);
        assert!(!before_release.is_zero_cleanup());

        core.release(&mut release)
            .unwrap_or_else(|error| panic!("test release failed: {error}"));
        let zero = core
            .snapshot()
            .unwrap_or_else(|error| panic!("test snapshot failed: {error}"));
        assert!(zero.is_zero_cleanup());
        assert!(
            core.cancel_all_queued()
                .unwrap_or_else(|error| panic!("repeated cancellation failed: {error}"))
                .is_empty()
        );
        assert!(
            core.abandon_all_after_caller_release()
                .unwrap_or_else(|error| panic!("repeated abandon failed: {error}"))
                .is_empty()
        );
        assert_eq!(
            core.release(&mut release),
            Err(LoopDomainError::Permit(PermitError::AlreadyReleased))
        );
        assert!(
            core.snapshot()
                .unwrap_or_else(|error| panic!("test snapshot failed: {error}"))
                .is_zero_cleanup()
        );
    }
}
