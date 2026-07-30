//! Canonical, bounded execution assignments for a target Runtime apply request.
//!
//! PXTE v1 carries desired LoopDomain and Mailbox execution policy beside the
//! existing PXTA v1 binding body. A v2 composite target-assignment digest commits
//! both body digests through the existing opaque assignment-digest field in the
//! signed Runtime Slice header. These values are plans only: this module does not
//! create a RuntimeHost, live DomainEpoch, dispatcher, callback, task, or clock.
//!
//! PXTA remains the complete data-plane binding body. PXTE v1 is the exact subset
//! authorized to enter a LoopDomain in this apply. A PXTA-only record may support
//! a passive source/sink boundary, but it grants no authority to create a Card,
//! register a callback or task, or enqueue that Mailbox in a Loop dispatcher.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::time::BoundedDuration;

use crate::assignment::{
    AssignmentContractError, AssignmentWireError, BindingId, InstanceRef, MAX_TARGET_ASSIGNMENTS,
    MAX_TARGET_ASSIGNMENTS_BYTES, MailboxRef, OverflowPolicy, TargetAssignments,
};
use crate::provenance::{ProvenanceContractError, RuntimeSliceCommitment, TargetAssignmentDigest};
use crate::wire::{
    EnvelopeContractError, MAX_RUNTIME_APPLY_ENVELOPE_BYTES, RuntimeApplyEnvelope, WireError,
};

/// Version of the canonical target execution body.
pub const TARGET_EXECUTION_PLAN_VERSION: u16 = 1;
/// Version of the apply-request outer frame carrying PXTA and PXTE bodies.
pub const RUNTIME_APPLY_REQUEST_V2_VERSION: u16 = 2;
/// Maximum LoopDomain records in one target execution body.
pub const MAX_LOOP_DOMAINS: usize = 64;
/// Maximum Mailbox execution records in one target execution body.
pub const MAX_MAILBOX_EXECUTIONS: usize = MAX_TARGET_ASSIGNMENTS;
/// Maximum admitted Domain outstanding count.
pub const MAX_DOMAIN_OUTSTANDING: u32 = 65_535;
/// Maximum explicit dispatcher service-cost token.
pub const MAX_SERVICE_COST_TOKENS: u32 = 1_000_000;
/// Maximum explicit minimum-service weight.
pub const MAX_MINIMUM_SERVICE_WEIGHT: u32 = 1_000_000;
/// Maximum bounded arrivals declared per capacity window.
pub const MAX_ARRIVALS_PER_WINDOW: u32 = 1_000_000;
/// Maximum duration representable by this first execution contract: one day.
pub const MAX_EXECUTION_DURATION_NANOS: u64 = 86_400_000_000_000;

const TARGET_EXECUTION_MAGIC: &[u8; 4] = b"PXTE";
const RUNTIME_APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const TARGET_EXECUTION_HEADER_BYTES: usize = 14;
const LOOP_DOMAIN_RECORD_BYTES: usize = 64;
const MAILBOX_EXECUTION_RECORD_BYTES: usize = 236;
const APPLY_REQUEST_V2_HEADER_BYTES: usize = 18;
const TARGET_EXECUTION_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.target-execution.sha256.v1";
const TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.target-plan-assignments.sha256.v2";

/// Maximum canonical byte length of one PXTE v1 execution body.
pub const MAX_TARGET_EXECUTION_PLAN_BYTES: usize = TARGET_EXECUTION_HEADER_BYTES
    + MAX_LOOP_DOMAINS * LOOP_DOMAIN_RECORD_BYTES
    + MAX_MAILBOX_EXECUTIONS * MAILBOX_EXECUTION_RECORD_BYTES;
/// Maximum canonical byte length of one PXAR v2 complete apply request.
pub const MAX_RUNTIME_APPLY_REQUEST_V2_BYTES: usize = APPLY_REQUEST_V2_HEADER_BYTES
    + MAX_RUNTIME_APPLY_ENVELOPE_BYTES
    + MAX_TARGET_ASSIGNMENTS_BYTES
    + MAX_TARGET_EXECUTION_PLAN_BYTES;

macro_rules! opaque_ref {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates an opaque reference from canonical bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Returns the canonical opaque bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_ref!(
    DomainRef,
    "Desired identity of one target-local LoopDomain slot."
);
opaque_ref!(
    CardDefinitionRef,
    "Resolved Card definition reference for one planned subject."
);
opaque_ref!(
    CardImplementationRef,
    "Resolved trusted implementation reference for one planned Card subject."
);

/// Digest of one exact canonical PXTE v1 body.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TargetExecutionDigest(Digest32);

impl TargetExecutionDigest {
    /// Wraps a digest already assigned by the canonical execution-body owner.
    #[must_use]
    pub const fn new(value: Digest32) -> Self {
        Self(value)
    }

    /// Returns the underlying SHA-256 value.
    #[must_use]
    pub const fn value(self) -> Digest32 {
        self.0
    }
}

/// Invocation model compiled for a target execution assignment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CallModel {
    /// Short, trusted, cooperatively yielding asynchronous callbacks.
    CooperativeAsync = 1,
    /// Synchronous invocation requiring a stronger execution domain.
    Synchronous = 2,
    /// Invocation behavior has not been proven.
    Unknown = 3,
}

/// Dominant work kind used for LoopDomain admission.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum WorkloadKind {
    /// Cooperatively yielding asynchronous I/O state transitions.
    Io = 1,
    /// Short routing or state-machine work.
    Routing = 2,
    /// CPU work requiring stronger isolation.
    Cpu = 3,
    /// Native-library work whose scheduling behavior is not Loop-owned.
    Native = 4,
    /// Device work requiring a stronger fault boundary.
    Device = 5,
    /// Workload kind is unknown.
    Unknown = 6,
}

/// Blocking risk supplied by the committed execution plan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BlockingRisk {
    /// The invocation is proven not to block the LoopDomain reactor.
    None = 1,
    /// A bounded synchronous wait exists and requires ThreadDomain review.
    Bounded = 2,
    /// Blocking behavior is unknown.
    Unknown = 3,
}

/// Provenance of the effective non-preemptive run bound.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RunBoundProvenance {
    /// Developer-declared only; insufficient for Loop admission.
    Declared = 1,
    /// Measured for the selected target profile.
    Measured = 2,
    /// Certified by an admitted target-profile evidence owner.
    Certified = 3,
    /// No usable bound exists.
    Unknown = 4,
}

/// Effective dispatch class authorized upstream and carried by the signed plan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DispatchClass {
    /// Reserved-capacity low-latency work; not a hard-safety path.
    Control = 1,
    /// Interactive work with bounded fairness.
    Interactive = 2,
    /// Sustained stream processing.
    Stream = 3,
    /// Background work that must retain a minimum service share.
    Background = 4,
}

/// Planned response when a callback exceeds its run budget.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum OverrunAction {
    /// Continue while recording an explicit degraded fact; rejected for LoopDomain admission.
    Continue = 1,
    /// Deliver cooperative cancellation to the invocation scope.
    CooperativeCancel = 2,
    /// Escalate to the Runtime-owned lifecycle policy.
    Escalate = 3,
    /// Preserve an unknown terminal until the real owner reconciles it; rejected for LoopDomain.
    Uncertain = 4,
}

/// Bounded capacity parameters for one desired LoopDomain slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LoopDomainCapacity {
    max_outstanding: u32,
    control_reserved: u32,
    capacity_window: BoundedDuration,
    control_reserved_run_budget: BoundedDuration,
}

impl LoopDomainCapacity {
    /// Validates queue and run-capacity bounds for one desired LoopDomain.
    pub const fn try_new(
        max_outstanding: u32,
        control_reserved: u32,
        capacity_window: BoundedDuration,
        control_reserved_run_budget: BoundedDuration,
    ) -> Result<Self, ExecutionContractError> {
        if max_outstanding == 0 || max_outstanding > MAX_DOMAIN_OUTSTANDING {
            return Err(ExecutionContractError::InvalidMaxOutstanding);
        }
        if control_reserved > max_outstanding {
            return Err(ExecutionContractError::InvalidControlReservation);
        }
        if !valid_duration(capacity_window) {
            return Err(ExecutionContractError::InvalidDomainBudget);
        }
        if (control_reserved == 0 && control_reserved_run_budget.value() != 0)
            || (control_reserved > 0
                && (!valid_duration(control_reserved_run_budget)
                    || control_reserved_run_budget.value() > capacity_window.value()))
        {
            return Err(ExecutionContractError::InvalidControlBudget);
        }
        Ok(Self {
            max_outstanding,
            control_reserved,
            capacity_window,
            control_reserved_run_budget,
        })
    }

    #[must_use]
    pub const fn max_outstanding(self) -> u32 {
        self.max_outstanding
    }

    #[must_use]
    pub const fn control_reserved(self) -> u32 {
        self.control_reserved
    }

    #[must_use]
    pub const fn capacity_window(self) -> BoundedDuration {
        self.capacity_window
    }

    #[must_use]
    pub const fn control_reserved_run_budget(self) -> BoundedDuration {
        self.control_reserved_run_budget
    }
}

/// Bounded start, drain, and cleanup budgets for one desired LoopDomain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LoopLifecycleBudgets {
    start_budget: BoundedDuration,
    drain_budget: BoundedDuration,
    cleanup_budget: BoundedDuration,
}

impl LoopLifecycleBudgets {
    /// Validates desired LoopDomain lifecycle budgets.
    pub const fn try_new(
        start_budget: BoundedDuration,
        drain_budget: BoundedDuration,
        cleanup_budget: BoundedDuration,
    ) -> Result<Self, ExecutionContractError> {
        if !valid_duration(start_budget)
            || !valid_duration(drain_budget)
            || !valid_duration(cleanup_budget)
        {
            return Err(ExecutionContractError::InvalidDomainBudget);
        }
        Ok(Self {
            start_budget,
            drain_budget,
            cleanup_budget,
        })
    }

    #[must_use]
    pub const fn start_budget(self) -> BoundedDuration {
        self.start_budget
    }

    #[must_use]
    pub const fn drain_budget(self) -> BoundedDuration {
        self.drain_budget
    }

    #[must_use]
    pub const fn cleanup_budget(self) -> BoundedDuration {
        self.cleanup_budget
    }
}

/// Bounded desired capacity and lifecycle budgets for one LoopDomain slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LoopDomainSpec {
    domain: DomainRef,
    capacity: LoopDomainCapacity,
    lifecycle: LoopLifecycleBudgets,
}

impl LoopDomainSpec {
    /// Combines already-validated capacity and lifecycle parameters.
    #[must_use]
    pub const fn new(
        domain: DomainRef,
        capacity: LoopDomainCapacity,
        lifecycle: LoopLifecycleBudgets,
    ) -> Self {
        Self {
            domain,
            capacity,
            lifecycle,
        }
    }

    #[must_use]
    pub const fn domain(self) -> DomainRef {
        self.domain
    }

    #[must_use]
    pub const fn capacity(self) -> LoopDomainCapacity {
        self.capacity
    }

    #[must_use]
    pub const fn lifecycle(self) -> LoopLifecycleBudgets {
        self.lifecycle
    }

    #[must_use]
    pub const fn max_outstanding(self) -> u32 {
        self.capacity.max_outstanding()
    }

    #[must_use]
    pub const fn control_reserved(self) -> u32 {
        self.capacity.control_reserved()
    }

    #[must_use]
    pub const fn capacity_window(self) -> BoundedDuration {
        self.capacity.capacity_window()
    }

    #[must_use]
    pub const fn control_reserved_run_budget(self) -> BoundedDuration {
        self.capacity.control_reserved_run_budget()
    }

    #[must_use]
    pub const fn start_budget(self) -> BoundedDuration {
        self.lifecycle.start_budget()
    }

    #[must_use]
    pub const fn drain_budget(self) -> BoundedDuration {
        self.lifecycle.drain_budget()
    }

    #[must_use]
    pub const fn cleanup_budget(self) -> BoundedDuration {
        self.lifecycle.cleanup_budget()
    }
}

/// Definition, implementation, and immutable content identity for one Card subject.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CardSubjectSpec {
    card_definition: CardDefinitionRef,
    card_implementation: CardImplementationRef,
    definition_digest: Digest32,
    artifact_digest: Digest32,
    config_digest: Digest32,
}

impl CardSubjectSpec {
    /// Creates an exact Card subject identity from resolved immutable references.
    #[must_use]
    pub const fn new(
        card_definition: CardDefinitionRef,
        card_implementation: CardImplementationRef,
        definition_digest: Digest32,
        artifact_digest: Digest32,
        config_digest: Digest32,
    ) -> Self {
        Self {
            card_definition,
            card_implementation,
            definition_digest,
            artifact_digest,
            config_digest,
        }
    }

    #[must_use]
    pub const fn card_definition(self) -> CardDefinitionRef {
        self.card_definition
    }

    #[must_use]
    pub const fn card_implementation(self) -> CardImplementationRef {
        self.card_implementation
    }

    #[must_use]
    pub const fn definition_digest(self) -> Digest32 {
        self.definition_digest
    }

    #[must_use]
    pub const fn artifact_digest(self) -> Digest32 {
        self.artifact_digest
    }

    #[must_use]
    pub const fn config_digest(self) -> Digest32 {
        self.config_digest
    }
}

/// Proven invocation properties used to decide LoopDomain eligibility.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LoopExecutionRequirements {
    call_model: CallModel,
    workload_kind: WorkloadKind,
    blocking_risk: BlockingRisk,
    run_bound_provenance: RunBoundProvenance,
    max_nonpreemptive_run: BoundedDuration,
}

impl LoopExecutionRequirements {
    /// Validates the scalar run bound and records upstream execution evidence.
    pub const fn try_new(
        call_model: CallModel,
        workload_kind: WorkloadKind,
        blocking_risk: BlockingRisk,
        run_bound_provenance: RunBoundProvenance,
        max_nonpreemptive_run: BoundedDuration,
    ) -> Result<Self, ExecutionContractError> {
        if !valid_duration(max_nonpreemptive_run) {
            return Err(ExecutionContractError::InvalidExecutionBudget);
        }
        Ok(Self {
            call_model,
            workload_kind,
            blocking_risk,
            run_bound_provenance,
            max_nonpreemptive_run,
        })
    }

    #[must_use]
    pub const fn call_model(self) -> CallModel {
        self.call_model
    }

    #[must_use]
    pub const fn workload_kind(self) -> WorkloadKind {
        self.workload_kind
    }

    #[must_use]
    pub const fn blocking_risk(self) -> BlockingRisk {
        self.blocking_risk
    }

    #[must_use]
    pub const fn run_bound_provenance(self) -> RunBoundProvenance {
        self.run_bound_provenance
    }

    #[must_use]
    pub const fn max_nonpreemptive_run(self) -> BoundedDuration {
        self.max_nonpreemptive_run
    }

    const fn is_loop_eligible(self) -> bool {
        matches!(self.call_model, CallModel::CooperativeAsync)
            && matches!(self.workload_kind, WorkloadKind::Io | WorkloadKind::Routing)
            && matches!(self.blocking_risk, BlockingRisk::None)
            && matches!(
                self.run_bound_provenance,
                RunBoundProvenance::Measured | RunBoundProvenance::Certified
            )
    }
}

/// Invocation run budget, post-overrun cooperative cleanup budget, and the
/// planned overrun response. Final Card shutdown uses the enclosing
/// `LoopLifecycleBudgets::cleanup_budget` instead.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CallbackBudgets {
    run_budget: BoundedDuration,
    cleanup_budget: BoundedDuration,
    overrun_action: OverrunAction,
}

impl CallbackBudgets {
    /// Validates finite callback budgets.
    pub const fn try_new(
        run_budget: BoundedDuration,
        cleanup_budget: BoundedDuration,
        overrun_action: OverrunAction,
    ) -> Result<Self, ExecutionContractError> {
        if !valid_duration(run_budget) || !valid_duration(cleanup_budget) {
            return Err(ExecutionContractError::InvalidExecutionBudget);
        }
        Ok(Self {
            run_budget,
            cleanup_budget,
            overrun_action,
        })
    }

    #[must_use]
    pub const fn run_budget(self) -> BoundedDuration {
        self.run_budget
    }

    #[must_use]
    pub const fn cleanup_budget(self) -> BoundedDuration {
        self.cleanup_budget
    }

    #[must_use]
    pub const fn overrun_action(self) -> OverrunAction {
        self.overrun_action
    }
}

/// Effective weighted dispatch policy and bounded arrival model for one Mailbox.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MailboxDispatchPolicy {
    dispatch_class: DispatchClass,
    service_cost_tokens: u32,
    minimum_service_weight: u32,
    max_burst: u16,
    max_arrivals_per_window: u32,
    callback_budgets: CallbackBudgets,
}

impl MailboxDispatchPolicy {
    /// Validates explicit fairness scalars and retains callback budgets.
    pub const fn try_new(
        dispatch_class: DispatchClass,
        service_cost_tokens: u32,
        minimum_service_weight: u32,
        max_burst: u16,
        max_arrivals_per_window: u32,
        callback_budgets: CallbackBudgets,
    ) -> Result<Self, ExecutionContractError> {
        if service_cost_tokens == 0 || service_cost_tokens > MAX_SERVICE_COST_TOKENS {
            return Err(ExecutionContractError::InvalidServiceCost);
        }
        if minimum_service_weight == 0 || minimum_service_weight > MAX_MINIMUM_SERVICE_WEIGHT {
            return Err(ExecutionContractError::InvalidMinimumServiceWeight);
        }
        if max_burst == 0 {
            return Err(ExecutionContractError::InvalidMaxBurst);
        }
        if max_arrivals_per_window == 0 || max_arrivals_per_window > MAX_ARRIVALS_PER_WINDOW {
            return Err(ExecutionContractError::InvalidArrivalBound);
        }
        Ok(Self {
            dispatch_class,
            service_cost_tokens,
            minimum_service_weight,
            max_burst,
            max_arrivals_per_window,
            callback_budgets,
        })
    }

    #[must_use]
    pub const fn dispatch_class(self) -> DispatchClass {
        self.dispatch_class
    }

    #[must_use]
    pub const fn service_cost_tokens(self) -> u32 {
        self.service_cost_tokens
    }

    #[must_use]
    pub const fn minimum_service_weight(self) -> u32 {
        self.minimum_service_weight
    }

    #[must_use]
    pub const fn max_burst(self) -> u16 {
        self.max_burst
    }

    #[must_use]
    pub const fn max_arrivals_per_window(self) -> u32 {
        self.max_arrivals_per_window
    }

    #[must_use]
    pub const fn callback_budgets(self) -> CallbackBudgets {
        self.callback_budgets
    }
}

/// One Mailbox-to-LoopDomain execution assignment from the committed target plan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MailboxExecutionSpec {
    binding_id: BindingId,
    mailbox: MailboxRef,
    target_instance: InstanceRef,
    domain: DomainRef,
    subject: CardSubjectSpec,
    requirements: LoopExecutionRequirements,
    dispatch: MailboxDispatchPolicy,
}

impl MailboxExecutionSpec {
    /// Validates the bounded scalar portion of one Mailbox execution assignment.
    pub const fn try_new(
        binding_id: BindingId,
        mailbox: MailboxRef,
        target_instance: InstanceRef,
        domain: DomainRef,
        subject: CardSubjectSpec,
        requirements: LoopExecutionRequirements,
        dispatch: MailboxDispatchPolicy,
    ) -> Result<Self, ExecutionContractError> {
        if requirements.max_nonpreemptive_run().value()
            > dispatch.callback_budgets().run_budget().value()
        {
            return Err(ExecutionContractError::RunBoundExceedsRunBudget);
        }
        Ok(Self {
            binding_id,
            mailbox,
            target_instance,
            domain,
            subject,
            requirements,
            dispatch,
        })
    }

    #[must_use]
    pub const fn binding_id(self) -> BindingId {
        self.binding_id
    }

    #[must_use]
    pub const fn mailbox(self) -> MailboxRef {
        self.mailbox
    }

    #[must_use]
    pub const fn target_instance(self) -> InstanceRef {
        self.target_instance
    }

    #[must_use]
    pub const fn domain(self) -> DomainRef {
        self.domain
    }

    #[must_use]
    pub const fn card_definition(self) -> CardDefinitionRef {
        self.subject.card_definition()
    }

    #[must_use]
    pub const fn card_implementation(self) -> CardImplementationRef {
        self.subject.card_implementation()
    }

    #[must_use]
    pub const fn definition_digest(self) -> Digest32 {
        self.subject.definition_digest()
    }

    #[must_use]
    pub const fn artifact_digest(self) -> Digest32 {
        self.subject.artifact_digest()
    }

    #[must_use]
    pub const fn config_digest(self) -> Digest32 {
        self.subject.config_digest()
    }

    #[must_use]
    pub const fn call_model(self) -> CallModel {
        self.requirements.call_model()
    }

    #[must_use]
    pub const fn workload_kind(self) -> WorkloadKind {
        self.requirements.workload_kind()
    }

    #[must_use]
    pub const fn blocking_risk(self) -> BlockingRisk {
        self.requirements.blocking_risk()
    }

    #[must_use]
    pub const fn run_bound_provenance(self) -> RunBoundProvenance {
        self.requirements.run_bound_provenance()
    }

    #[must_use]
    pub const fn dispatch_class(self) -> DispatchClass {
        self.dispatch.dispatch_class()
    }

    #[must_use]
    pub const fn service_cost_tokens(self) -> u32 {
        self.dispatch.service_cost_tokens()
    }

    #[must_use]
    pub const fn minimum_service_weight(self) -> u32 {
        self.dispatch.minimum_service_weight()
    }

    #[must_use]
    pub const fn max_burst(self) -> u16 {
        self.dispatch.max_burst()
    }

    #[must_use]
    pub const fn max_arrivals_per_window(self) -> u32 {
        self.dispatch.max_arrivals_per_window()
    }

    #[must_use]
    pub const fn max_nonpreemptive_run(self) -> BoundedDuration {
        self.requirements.max_nonpreemptive_run()
    }

    #[must_use]
    pub const fn run_budget(self) -> BoundedDuration {
        self.dispatch.callback_budgets().run_budget()
    }

    #[must_use]
    pub const fn cleanup_budget(self) -> BoundedDuration {
        self.dispatch.callback_budgets().cleanup_budget()
    }

    #[must_use]
    pub const fn overrun_action(self) -> OverrunAction {
        self.dispatch.callback_budgets().overrun_action()
    }

    const fn is_loop_eligible(self) -> bool {
        self.requirements.is_loop_eligible()
    }

    const fn has_bounded_loop_overrun_response(self) -> bool {
        matches!(
            self.overrun_action(),
            OverrunAction::CooperativeCancel | OverrunAction::Escalate
        )
    }

    fn same_subject_contract(self, other: Self) -> bool {
        self.target_instance == other.target_instance
            && self.domain == other.domain
            && self.subject == other.subject
            && self.requirements == other.requirements
    }
}

/// Canonically ordered PXTE v1 domain and Mailbox execution records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetExecutionPlan {
    domains: Box<[LoopDomainSpec]>,
    mailboxes: Box<[MailboxExecutionSpec]>,
    canonical_wire: Box<[u8]>,
    execution_digest: TargetExecutionDigest,
}

impl TargetExecutionPlan {
    /// Sorts, validates, bounds, and canonically commits target execution records.
    pub fn try_new(
        mut domains: Vec<LoopDomainSpec>,
        mut mailboxes: Vec<MailboxExecutionSpec>,
    ) -> Result<Self, ExecutionContractError> {
        if domains.is_empty() {
            return Err(ExecutionContractError::MissingLoopDomain);
        }
        if mailboxes.is_empty() {
            return Err(ExecutionContractError::MissingMailboxExecution);
        }
        if domains.len() > MAX_LOOP_DOMAINS {
            return Err(ExecutionContractError::DomainCountExceeded);
        }
        if mailboxes.len() > MAX_MAILBOX_EXECUTIONS {
            return Err(ExecutionContractError::ExecutionCountExceeded);
        }
        domains.sort_by_key(|domain| domain.domain());
        mailboxes.sort_by_key(|execution| {
            (
                execution.binding_id(),
                execution.mailbox(),
                execution.target_instance(),
                execution.domain(),
            )
        });
        validate_execution_records(&domains, &mailboxes)?;
        let canonical_wire = build_target_execution_wire(&domains, &mailboxes);
        let execution_digest = digest_target_execution(&canonical_wire)?;
        Ok(Self {
            domains: domains.into_boxed_slice(),
            mailboxes: mailboxes.into_boxed_slice(),
            canonical_wire: canonical_wire.into_boxed_slice(),
            execution_digest,
        })
    }

    /// Strictly decodes one canonical PXTE v1 body.
    pub fn decode(frame: &[u8]) -> Result<Self, ExecutionWireError> {
        decode_target_execution(frame)
    }

    #[must_use]
    pub fn domains(&self) -> &[LoopDomainSpec] {
        &self.domains
    }

    #[must_use]
    pub fn mailbox_executions(&self) -> &[MailboxExecutionSpec] {
        &self.mailboxes
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    #[must_use]
    pub const fn execution_digest(&self) -> TargetExecutionDigest {
        self.execution_digest
    }

    /// Revalidates records, canonical bytes, and the stored execution digest.
    pub fn validate(&self) -> Result<(), ExecutionContractError> {
        let rebuilt = Self::try_new(self.domains.to_vec(), self.mailboxes.to_vec())?;
        if rebuilt.domains != self.domains || rebuilt.mailboxes != self.mailboxes {
            return Err(ExecutionContractError::CanonicalWireMismatch);
        }
        if rebuilt.canonical_wire != self.canonical_wire {
            return Err(ExecutionContractError::CanonicalWireMismatch);
        }
        if rebuilt.execution_digest != self.execution_digest {
            return Err(ExecutionContractError::ExecutionDigestMismatch);
        }
        Ok(())
    }
}

/// Complete PXTA bindings and their Loop-authorized PXTE subset, committed together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetPlanAssignments {
    bindings: TargetAssignments,
    execution: TargetExecutionPlan,
    assignment_digest: TargetAssignmentDigest,
}

impl TargetPlanAssignments {
    /// Validates every PXTE reference without requiring all PXTA bindings to execute.
    ///
    /// Bindings absent from PXTE remain execution-inert; they cannot be used to
    /// synthesize Card, Domain, callback, dispatcher, or Task authority.
    pub fn try_new(
        bindings: TargetAssignments,
        execution: TargetExecutionPlan,
    ) -> Result<Self, TargetPlanContractError> {
        bindings.validate()?;
        execution.validate()?;
        validate_target_plan_references(&bindings, &execution)?;
        let assignment_digest = digest_target_plan_assignments(&bindings, &execution)?;
        Ok(Self {
            bindings,
            execution,
            assignment_digest,
        })
    }

    #[must_use]
    pub const fn bindings(&self) -> &TargetAssignments {
        &self.bindings
    }

    #[must_use]
    pub const fn execution(&self) -> &TargetExecutionPlan {
        &self.execution
    }

    /// Returns the composite digest authenticated by the existing Slice field.
    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.assignment_digest
    }

    /// Revalidates both bodies, cross-references, and the composite digest.
    pub fn validate(&self) -> Result<(), TargetPlanContractError> {
        self.bindings.validate()?;
        self.execution.validate()?;
        validate_target_plan_references(&self.bindings, &self.execution)?;
        if digest_target_plan_assignments(&self.bindings, &self.execution)?
            != self.assignment_digest
        {
            return Err(TargetPlanContractError::CompositeDigestMismatch);
        }
        Ok(())
    }
}

/// Complete v2 target Slice: one existing signed commitment and both canonical bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePlanSliceV2 {
    commitment: RuntimeSliceCommitment,
    assignments: TargetPlanAssignments,
}

impl RuntimePlanSliceV2 {
    /// Binds the v2 composite target digest to the existing opaque Slice field.
    pub fn try_new(
        commitment: RuntimeSliceCommitment,
        assignments: TargetPlanAssignments,
    ) -> Result<Self, TargetPlanContractError> {
        commitment.validate()?;
        assignments.validate()?;
        if commitment.header().assignment_digest() != assignments.assignment_digest() {
            return Err(TargetPlanContractError::SliceAssignmentDigestMismatch);
        }
        Ok(Self {
            commitment,
            assignments,
        })
    }

    #[must_use]
    pub const fn commitment(&self) -> RuntimeSliceCommitment {
        self.commitment
    }

    #[must_use]
    pub const fn assignments(&self) -> &TargetPlanAssignments {
        &self.assignments
    }

    pub fn validate(&self) -> Result<(), TargetPlanContractError> {
        self.commitment.validate()?;
        self.assignments.validate()?;
        if self.commitment.header().assignment_digest() != self.assignments.assignment_digest() {
            return Err(TargetPlanContractError::SliceAssignmentDigestMismatch);
        }
        Ok(())
    }
}

/// PXAR v2 request carrying an unchanged signed envelope plus PXTA and PXTE bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyRequestV2 {
    envelope: RuntimeApplyEnvelope,
    slice: RuntimePlanSliceV2,
    canonical_wire: Box<[u8]>,
}

impl RuntimeApplyRequestV2 {
    /// Builds a strict v2 outer request without changing the envelope wire format.
    pub fn try_new(
        envelope: RuntimeApplyEnvelope,
        slice: RuntimePlanSliceV2,
    ) -> Result<Self, TargetPlanContractError> {
        envelope.validate()?;
        slice.validate()?;
        if envelope.control_commitment().slice() != slice.commitment() {
            return Err(TargetPlanContractError::EnvelopeSliceMismatch);
        }
        let canonical_wire = build_runtime_apply_request_v2_wire(&envelope, &slice);
        if canonical_wire.len() > MAX_RUNTIME_APPLY_REQUEST_V2_BYTES {
            return Err(TargetPlanContractError::RequestFrameTooLarge);
        }
        Ok(Self {
            envelope,
            slice,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes PXAR v2. It never falls back to the v1 decoder.
    pub fn decode(frame: &[u8]) -> Result<Self, RequestV2WireError> {
        decode_runtime_apply_request_v2(frame)
    }

    #[must_use]
    pub const fn envelope(&self) -> &RuntimeApplyEnvelope {
        &self.envelope
    }

    #[must_use]
    pub const fn slice(&self) -> &RuntimePlanSliceV2 {
        &self.slice
    }

    #[must_use]
    pub const fn request_digest(&self) -> &Digest32 {
        self.envelope.request_digest()
    }

    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    pub fn validate(&self) -> Result<(), TargetPlanContractError> {
        self.envelope.validate()?;
        self.slice.validate()?;
        if self.envelope.control_commitment().slice() != self.slice.commitment() {
            return Err(TargetPlanContractError::EnvelopeSliceMismatch);
        }
        if build_runtime_apply_request_v2_wire(&self.envelope, &self.slice)
            != self.canonical_wire.as_ref()
        {
            return Err(TargetPlanContractError::RequestCanonicalWireMismatch);
        }
        Ok(())
    }
}

const fn valid_duration(value: BoundedDuration) -> bool {
    value.value() > 0 && value.value() <= MAX_EXECUTION_DURATION_NANOS
}

fn validate_execution_records(
    domains: &[LoopDomainSpec],
    mailboxes: &[MailboxExecutionSpec],
) -> Result<(), ExecutionContractError> {
    for (index, domain) in domains.iter().enumerate() {
        if domains
            .iter()
            .take(index)
            .any(|previous| previous.domain() == domain.domain())
        {
            return Err(ExecutionContractError::DuplicateDomainRef);
        }
    }
    for (index, execution) in mailboxes.iter().enumerate() {
        for previous in mailboxes.iter().take(index) {
            if previous.binding_id() == execution.binding_id() {
                return Err(ExecutionContractError::DuplicateExecutionBinding);
            }
            if previous.mailbox() == execution.mailbox() {
                return Err(ExecutionContractError::DuplicateExecutionMailbox);
            }
        }
        if !domains
            .iter()
            .any(|domain| domain.domain() == execution.domain())
        {
            return Err(ExecutionContractError::OrphanDomainRef);
        }
        if !execution.is_loop_eligible() {
            return Err(ExecutionContractError::UnsupportedLoopExecution);
        }
        if !execution.has_bounded_loop_overrun_response() {
            return Err(ExecutionContractError::UnsafeLoopOverrunAction);
        }
    }
    for domain in domains {
        if !mailboxes
            .iter()
            .any(|execution| execution.domain() == domain.domain())
        {
            return Err(ExecutionContractError::UnusedDomainRef);
        }
        validate_domain_utilization(*domain, mailboxes)?;
    }
    Ok(())
}

fn validate_domain_utilization(
    domain: LoopDomainSpec,
    mailboxes: &[MailboxExecutionSpec],
) -> Result<(), ExecutionContractError> {
    let mut total = 0_u128;
    let mut control = 0_u128;
    for execution in mailboxes
        .iter()
        .filter(|execution| execution.domain() == domain.domain())
    {
        if execution.run_budget().value() > domain.capacity_window().value()
            || execution.cleanup_budget().value() > domain.cleanup_budget().value()
        {
            return Err(ExecutionContractError::ExecutionBudgetExceedsDomain);
        }
        let callback_occupancy = u128::from(execution.run_budget().value())
            .checked_add(u128::from(execution.cleanup_budget().value()))
            .ok_or(ExecutionContractError::UtilizationOverflow)?;
        let demand = u128::from(execution.max_arrivals_per_window())
            .checked_mul(callback_occupancy)
            .ok_or(ExecutionContractError::UtilizationOverflow)?;
        total = total
            .checked_add(demand)
            .ok_or(ExecutionContractError::UtilizationOverflow)?;
        if execution.dispatch_class() == DispatchClass::Control {
            if domain.control_reserved() == 0 {
                return Err(ExecutionContractError::ControlReservationRequired);
            }
            control = control
                .checked_add(demand)
                .ok_or(ExecutionContractError::UtilizationOverflow)?;
        }
    }
    if total > u128::from(domain.capacity_window().value()) {
        return Err(ExecutionContractError::DomainUtilizationExceeded);
    }
    if control > u128::from(domain.control_reserved_run_budget().value()) {
        return Err(ExecutionContractError::ControlUtilizationExceeded);
    }
    if domain.control_reserved() == domain.max_outstanding()
        && mailboxes.iter().any(|execution| {
            execution.domain() == domain.domain()
                && execution.dispatch_class() != DispatchClass::Control
        })
    {
        return Err(ExecutionContractError::SharedCapacityRequired);
    }
    Ok(())
}

fn validate_target_plan_references(
    bindings: &TargetAssignments,
    execution: &TargetExecutionPlan,
) -> Result<(), TargetPlanContractError> {
    if bindings.as_slice().iter().any(|binding| {
        binding.delivery().overflow_policy() == OverflowPolicy::BlockUntilDeadline
            || binding.mailbox_spec().overflow_policy() == OverflowPolicy::BlockUntilDeadline
    }) {
        return Err(TargetPlanContractError::BlockUntilDeadlineForbidden);
    }
    for mailbox in execution.mailbox_executions() {
        let Some(binding) = bindings
            .as_slice()
            .iter()
            .find(|binding| binding.binding_id() == mailbox.binding_id())
        else {
            return Err(TargetPlanContractError::OrphanBinding);
        };
        if binding.mailbox() != mailbox.mailbox() {
            return Err(TargetPlanContractError::BindingMailboxMismatch);
        }
        if binding.target_instance() != mailbox.target_instance() {
            return Err(TargetPlanContractError::BindingTargetMismatch);
        }
    }
    for (index, execution_record) in execution.mailbox_executions().iter().enumerate() {
        for previous in execution.mailbox_executions().iter().take(index) {
            if previous.target_instance() == execution_record.target_instance()
                && !previous.same_subject_contract(*execution_record)
            {
                return Err(TargetPlanContractError::SubjectExecutionMismatch);
            }
        }
    }
    validate_control_start_slo(bindings, execution)?;
    Ok(())
}

/// Computes a scheduler-independent signed-plan admission bound for Control
/// enqueue-to-start under the declared arrival envelope.
///
/// The current P2b owner serially awaits the complete callback and its
/// post-overrun cleanup before dispatching again, so every interfering item is
/// charged `run + cleanup`, which also dominates its non-preemptive segment.
/// For each Control mailbox the bound includes one domain-wide carry-in
/// callback, every older item in its own FIFO, and every peer's full queue plus
/// a conservatively phased arrival horizon. Assuming every peer runs first
/// dominates any cost/weight/max-burst arbitration order without freezing a
/// particular dispatcher algorithm into the signed contract. This is not a
/// target-platform wall-clock proof: ingress must honor or observe violations
/// of the signed arrival envelope, and live evidence must retain margin for
/// dispatcher, expiry, and payload-accounting overhead.
fn validate_control_start_slo(
    bindings: &TargetAssignments,
    execution: &TargetExecutionPlan,
) -> Result<(), TargetPlanContractError> {
    for control in execution
        .mailbox_executions()
        .iter()
        .filter(|mailbox| mailbox.dispatch_class() == DispatchClass::Control)
    {
        let Some(domain) = execution
            .domains()
            .iter()
            .find(|domain| domain.domain() == control.domain())
        else {
            return Err(TargetPlanContractError::ControlStartSloExceeded);
        };
        let Some(control_binding) = bindings
            .as_slice()
            .iter()
            .find(|binding| binding.binding_id() == control.binding_id())
        else {
            return Err(TargetPlanContractError::OrphanBinding);
        };

        let slo = u128::from(control_binding.mailbox_spec().max_queue_age().value());
        let window = u128::from(domain.capacity_window().value());
        let arrival_horizon = checked_ceil_div(slo, window)
            .and_then(|windows| windows.checked_add(1))
            .ok_or(TargetPlanContractError::ControlStartSloExceeded)?;

        let mut carry_in = 0_u128;
        for candidate in execution
            .mailbox_executions()
            .iter()
            .filter(|mailbox| mailbox.domain() == domain.domain())
        {
            let occupancy = callback_occupancy(*candidate)
                .ok_or(TargetPlanContractError::ControlStartSloExceeded)?;
            let nonpreemptive = u128::from(candidate.max_nonpreemptive_run().value());
            carry_in = carry_in.max(occupancy.max(nonpreemptive));
        }

        let control_occupancy =
            callback_occupancy(*control).ok_or(TargetPlanContractError::ControlStartSloExceeded)?;
        let own_ahead = u128::from(control_binding.mailbox_spec().capacity_items())
            .checked_sub(1)
            .ok_or(TargetPlanContractError::ControlStartSloExceeded)?;
        let own_delay = own_ahead
            .checked_mul(control_occupancy)
            .ok_or(TargetPlanContractError::ControlStartSloExceeded)?;
        let mut wait_bound = carry_in
            .checked_add(own_delay)
            .ok_or(TargetPlanContractError::ControlStartSloExceeded)?;

        for peer in execution.mailbox_executions().iter().filter(|mailbox| {
            mailbox.domain() == domain.domain() && mailbox.binding_id() != control.binding_id()
        }) {
            let Some(peer_binding) = bindings
                .as_slice()
                .iter()
                .find(|binding| binding.binding_id() == peer.binding_id())
            else {
                return Err(TargetPlanContractError::OrphanBinding);
            };
            let horizon_arrivals = arrival_horizon
                .checked_mul(u128::from(peer.max_arrivals_per_window()))
                .ok_or(TargetPlanContractError::ControlStartSloExceeded)?;
            let peer_work = u128::from(peer_binding.mailbox_spec().capacity_items())
                .checked_add(horizon_arrivals)
                .ok_or(TargetPlanContractError::ControlStartSloExceeded)?;
            let peer_delay = peer_work
                .checked_mul(
                    callback_occupancy(*peer)
                        .ok_or(TargetPlanContractError::ControlStartSloExceeded)?,
                )
                .ok_or(TargetPlanContractError::ControlStartSloExceeded)?;
            wait_bound = wait_bound
                .checked_add(peer_delay)
                .ok_or(TargetPlanContractError::ControlStartSloExceeded)?;
        }

        // Mailbox expiry is inclusive at equality, so only a strict bound is
        // sufficient to prove that the Control callback can begin in time.
        if wait_bound >= slo {
            return Err(TargetPlanContractError::ControlStartSloExceeded);
        }
    }
    Ok(())
}

fn callback_occupancy(execution: MailboxExecutionSpec) -> Option<u128> {
    u128::from(execution.run_budget().value())
        .checked_add(u128::from(execution.cleanup_budget().value()))
}

fn checked_ceil_div(value: u128, divisor: u128) -> Option<u128> {
    value
        .checked_add(divisor.checked_sub(1)?)?
        .checked_div(divisor)
}

fn digest_target_execution(
    canonical_wire: &[u8],
) -> Result<TargetExecutionDigest, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TARGET_EXECUTION_DIGEST_DOMAIN)?;
    builder.field_bytes(canonical_wire)?;
    Ok(TargetExecutionDigest::new(builder.finish()))
}

fn digest_target_plan_assignments(
    bindings: &TargetAssignments,
    execution: &TargetExecutionPlan,
) -> Result<TargetAssignmentDigest, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TARGET_PLAN_ASSIGNMENTS_DIGEST_DOMAIN)?;
    builder.field_bytes(bindings.assignment_digest().value().as_bytes())?;
    builder.field_bytes(execution.execution_digest().value().as_bytes())?;
    Ok(TargetAssignmentDigest::new(builder.finish()))
}

fn build_target_execution_wire(
    domains: &[LoopDomainSpec],
    mailboxes: &[MailboxExecutionSpec],
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(
        TARGET_EXECUTION_HEADER_BYTES
            + domains.len() * LOOP_DOMAIN_RECORD_BYTES
            + mailboxes.len() * MAILBOX_EXECUTION_RECORD_BYTES,
    );
    encoded.extend_from_slice(TARGET_EXECUTION_MAGIC);
    encoded.extend_from_slice(&TARGET_EXECUTION_PLAN_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(domains.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(mailboxes.len() as u32).to_be_bytes());
    for domain in domains {
        append_domain_record(&mut encoded, *domain);
    }
    for mailbox in mailboxes {
        append_mailbox_execution_record(&mut encoded, *mailbox);
    }
    encoded
}

fn append_domain_record(encoded: &mut Vec<u8>, domain: LoopDomainSpec) {
    encoded.extend_from_slice(domain.domain().as_bytes());
    encoded.extend_from_slice(&domain.max_outstanding().to_be_bytes());
    encoded.extend_from_slice(&domain.control_reserved().to_be_bytes());
    encoded.extend_from_slice(&domain.capacity_window().value().to_be_bytes());
    encoded.extend_from_slice(&domain.control_reserved_run_budget().value().to_be_bytes());
    encoded.extend_from_slice(&domain.start_budget().value().to_be_bytes());
    encoded.extend_from_slice(&domain.drain_budget().value().to_be_bytes());
    encoded.extend_from_slice(&domain.cleanup_budget().value().to_be_bytes());
}

fn append_mailbox_execution_record(encoded: &mut Vec<u8>, execution: MailboxExecutionSpec) {
    encoded.extend_from_slice(execution.binding_id().as_bytes());
    encoded.extend_from_slice(execution.mailbox().as_bytes());
    encoded.extend_from_slice(execution.target_instance().as_bytes());
    encoded.extend_from_slice(execution.domain().as_bytes());
    encoded.extend_from_slice(execution.card_definition().as_bytes());
    encoded.extend_from_slice(execution.card_implementation().as_bytes());
    encoded.extend_from_slice(execution.definition_digest().as_bytes());
    encoded.extend_from_slice(execution.artifact_digest().as_bytes());
    encoded.extend_from_slice(execution.config_digest().as_bytes());
    encoded.push(execution.call_model() as u8);
    encoded.push(execution.workload_kind() as u8);
    encoded.push(execution.blocking_risk() as u8);
    encoded.push(execution.run_bound_provenance() as u8);
    encoded.push(execution.dispatch_class() as u8);
    encoded.extend_from_slice(&execution.service_cost_tokens().to_be_bytes());
    encoded.extend_from_slice(&execution.minimum_service_weight().to_be_bytes());
    encoded.extend_from_slice(&execution.max_burst().to_be_bytes());
    encoded.extend_from_slice(&execution.max_arrivals_per_window().to_be_bytes());
    encoded.extend_from_slice(&execution.max_nonpreemptive_run().value().to_be_bytes());
    encoded.extend_from_slice(&execution.run_budget().value().to_be_bytes());
    encoded.extend_from_slice(&execution.cleanup_budget().value().to_be_bytes());
    encoded.push(execution.overrun_action() as u8);
}

fn build_runtime_apply_request_v2_wire(
    envelope: &RuntimeApplyEnvelope,
    slice: &RuntimePlanSliceV2,
) -> Vec<u8> {
    let binding_wire = slice.assignments().bindings().canonical_wire();
    let execution_wire = slice.assignments().execution().canonical_wire();
    let mut encoded = Vec::with_capacity(
        APPLY_REQUEST_V2_HEADER_BYTES
            + envelope.canonical_wire().len()
            + binding_wire.len()
            + execution_wire.len(),
    );
    encoded.extend_from_slice(RUNTIME_APPLY_REQUEST_MAGIC);
    encoded.extend_from_slice(&RUNTIME_APPLY_REQUEST_V2_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(envelope.canonical_wire().len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(binding_wire.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(execution_wire.len() as u32).to_be_bytes());
    encoded.extend_from_slice(envelope.canonical_wire());
    encoded.extend_from_slice(binding_wire);
    encoded.extend_from_slice(execution_wire);
    encoded
}

fn decode_target_execution(frame: &[u8]) -> Result<TargetExecutionPlan, ExecutionWireError> {
    if frame.len() > MAX_TARGET_EXECUTION_PLAN_BYTES {
        return Err(ExecutionWireError::new(
            ExecutionWireErrorCode::FrameTooLarge,
        ));
    }
    if frame.len() < TARGET_EXECUTION_HEADER_BYTES {
        return Err(ExecutionWireError::new(ExecutionWireErrorCode::Truncated));
    }
    if &frame[..4] != TARGET_EXECUTION_MAGIC {
        return Err(ExecutionWireError::new(
            ExecutionWireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != TARGET_EXECUTION_PLAN_VERSION {
        return Err(ExecutionWireError::new(
            ExecutionWireErrorCode::UnsupportedVersion,
        ));
    }
    let domain_count = read_u32(&frame[6..10]) as usize;
    let mailbox_count = read_u32(&frame[10..14]) as usize;
    if domain_count > MAX_LOOP_DOMAINS {
        return Err(ExecutionWireError::new(
            ExecutionWireErrorCode::DomainCountExceeded,
        ));
    }
    if mailbox_count > MAX_MAILBOX_EXECUTIONS {
        return Err(ExecutionWireError::new(
            ExecutionWireErrorCode::ExecutionCountExceeded,
        ));
    }
    let domain_bytes = domain_count
        .checked_mul(LOOP_DOMAIN_RECORD_BYTES)
        .ok_or_else(|| ExecutionWireError::new(ExecutionWireErrorCode::InvalidFrameLength))?;
    let mailbox_bytes = mailbox_count
        .checked_mul(MAILBOX_EXECUTION_RECORD_BYTES)
        .ok_or_else(|| ExecutionWireError::new(ExecutionWireErrorCode::InvalidFrameLength))?;
    let expected_length = TARGET_EXECUTION_HEADER_BYTES
        .checked_add(domain_bytes)
        .and_then(|length| length.checked_add(mailbox_bytes))
        .ok_or_else(|| ExecutionWireError::new(ExecutionWireErrorCode::InvalidFrameLength))?;
    if frame.len() < expected_length {
        return Err(ExecutionWireError::new(ExecutionWireErrorCode::Truncated));
    }
    if frame.len() != expected_length {
        return Err(ExecutionWireError::new(
            ExecutionWireErrorCode::InvalidFrameLength,
        ));
    }

    let domains_start = TARGET_EXECUTION_HEADER_BYTES;
    let mailboxes_start = domains_start + domain_bytes;
    let mut domains = Vec::with_capacity(domain_count);
    for (index, record) in frame[domains_start..mailboxes_start]
        .chunks_exact(LOOP_DOMAIN_RECORD_BYTES)
        .enumerate()
    {
        domains.push(decode_domain_record(record, index as u32)?);
    }
    let mut mailboxes = Vec::with_capacity(mailbox_count);
    for (index, record) in frame[mailboxes_start..]
        .chunks_exact(MAILBOX_EXECUTION_RECORD_BYTES)
        .enumerate()
    {
        mailboxes.push(decode_mailbox_execution_record(record, index as u32)?);
    }
    let decoded =
        TargetExecutionPlan::try_new(domains, mailboxes).map_err(execution_contract_wire_error)?;
    if decoded.canonical_wire() != frame {
        return Err(ExecutionWireError::new(
            ExecutionWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn decode_domain_record(
    record: &[u8],
    record_index: u32,
) -> Result<LoopDomainSpec, ExecutionWireError> {
    let mut cursor = RecordCursor::new(record);
    let domain = DomainRef::from_bytes(cursor.array());
    let capacity = LoopDomainCapacity::try_new(
        cursor.u32(),
        cursor.u32(),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
    );
    let lifecycle = LoopLifecycleBudgets::try_new(
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
    );
    match (capacity, lifecycle) {
        (Ok(capacity), Ok(lifecycle)) => Ok(LoopDomainSpec::new(domain, capacity, lifecycle)),
        _ => Err(ExecutionWireError::at(
            ExecutionWireErrorCode::InvalidDomain,
            ExecutionRecordSection::Domain,
            record_index,
        )),
    }
}

fn decode_mailbox_execution_record(
    record: &[u8],
    record_index: u32,
) -> Result<MailboxExecutionSpec, ExecutionWireError> {
    let mut cursor = RecordCursor::new(record);
    let binding_id = BindingId::from_bytes(cursor.array());
    let mailbox = MailboxRef::from_bytes(cursor.array());
    let target_instance = InstanceRef::from_bytes(cursor.array());
    let domain = DomainRef::from_bytes(cursor.array());
    let card_definition = CardDefinitionRef::from_bytes(cursor.array());
    let card_implementation = CardImplementationRef::from_bytes(cursor.array());
    let definition_digest = Digest32::from_bytes(cursor.array());
    let artifact_digest = Digest32::from_bytes(cursor.array());
    let config_digest = Digest32::from_bytes(cursor.array());
    let call_model = decode_call_model(cursor.u8(), record_index)?;
    let workload_kind = decode_workload_kind(cursor.u8(), record_index)?;
    let blocking_risk = decode_blocking_risk(cursor.u8(), record_index)?;
    let run_bound_provenance = decode_run_bound_provenance(cursor.u8(), record_index)?;
    let dispatch_class = decode_dispatch_class(cursor.u8(), record_index)?;
    let service_cost_tokens = cursor.u32();
    let minimum_service_weight = cursor.u32();
    let max_burst = cursor.u16();
    let max_arrivals_per_window = cursor.u32();
    let max_nonpreemptive_run = BoundedDuration::from_nanos(cursor.u64());
    let run_budget = BoundedDuration::from_nanos(cursor.u64());
    let cleanup_budget = BoundedDuration::from_nanos(cursor.u64());
    let overrun_action = decode_overrun_action(cursor.u8(), record_index)?;
    let subject = CardSubjectSpec::new(
        card_definition,
        card_implementation,
        definition_digest,
        artifact_digest,
        config_digest,
    );
    let requirements = LoopExecutionRequirements::try_new(
        call_model,
        workload_kind,
        blocking_risk,
        run_bound_provenance,
        max_nonpreemptive_run,
    );
    let callback_budgets = CallbackBudgets::try_new(run_budget, cleanup_budget, overrun_action);
    let dispatch = callback_budgets.and_then(|budgets| {
        MailboxDispatchPolicy::try_new(
            dispatch_class,
            service_cost_tokens,
            minimum_service_weight,
            max_burst,
            max_arrivals_per_window,
            budgets,
        )
    });
    let execution = match (requirements, dispatch) {
        (Ok(requirements), Ok(dispatch)) => MailboxExecutionSpec::try_new(
            binding_id,
            mailbox,
            target_instance,
            domain,
            subject,
            requirements,
            dispatch,
        ),
        _ => Err(ExecutionContractError::InvalidExecutionBudget),
    };
    execution.map_err(|_| {
        ExecutionWireError::at(
            ExecutionWireErrorCode::InvalidMailboxExecution,
            ExecutionRecordSection::Mailbox,
            record_index,
        )
    })
}

macro_rules! decode_enum {
    ($name:ident, $type:ty, $section:expr, {$($value:literal => $variant:path),+ $(,)?}) => {
        fn $name(value: u8, record_index: u32) -> Result<$type, ExecutionWireError> {
            match value {
                $($value => Ok($variant),)+
                _ => Err(ExecutionWireError::at(
                    ExecutionWireErrorCode::InvalidEnumValue,
                    $section,
                    record_index,
                )),
            }
        }
    };
}

decode_enum!(decode_call_model, CallModel, ExecutionRecordSection::Mailbox, {
    1 => CallModel::CooperativeAsync,
    2 => CallModel::Synchronous,
    3 => CallModel::Unknown,
});
decode_enum!(decode_workload_kind, WorkloadKind, ExecutionRecordSection::Mailbox, {
    1 => WorkloadKind::Io,
    2 => WorkloadKind::Routing,
    3 => WorkloadKind::Cpu,
    4 => WorkloadKind::Native,
    5 => WorkloadKind::Device,
    6 => WorkloadKind::Unknown,
});
decode_enum!(decode_blocking_risk, BlockingRisk, ExecutionRecordSection::Mailbox, {
    1 => BlockingRisk::None,
    2 => BlockingRisk::Bounded,
    3 => BlockingRisk::Unknown,
});
decode_enum!(decode_run_bound_provenance, RunBoundProvenance, ExecutionRecordSection::Mailbox, {
    1 => RunBoundProvenance::Declared,
    2 => RunBoundProvenance::Measured,
    3 => RunBoundProvenance::Certified,
    4 => RunBoundProvenance::Unknown,
});
decode_enum!(decode_dispatch_class, DispatchClass, ExecutionRecordSection::Mailbox, {
    1 => DispatchClass::Control,
    2 => DispatchClass::Interactive,
    3 => DispatchClass::Stream,
    4 => DispatchClass::Background,
});
decode_enum!(decode_overrun_action, OverrunAction, ExecutionRecordSection::Mailbox, {
    1 => OverrunAction::Continue,
    2 => OverrunAction::CooperativeCancel,
    3 => OverrunAction::Escalate,
    4 => OverrunAction::Uncertain,
});

fn decode_runtime_apply_request_v2(
    frame: &[u8],
) -> Result<RuntimeApplyRequestV2, RequestV2WireError> {
    if frame.len() > MAX_RUNTIME_APPLY_REQUEST_V2_BYTES {
        return Err(RequestV2WireError::new(
            RequestV2WireErrorCode::FrameTooLarge,
        ));
    }
    if frame.len() < APPLY_REQUEST_V2_HEADER_BYTES {
        return Err(RequestV2WireError::new(RequestV2WireErrorCode::Truncated));
    }
    if &frame[..4] != RUNTIME_APPLY_REQUEST_MAGIC {
        return Err(RequestV2WireError::new(
            RequestV2WireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != RUNTIME_APPLY_REQUEST_V2_VERSION {
        return Err(RequestV2WireError::new(
            RequestV2WireErrorCode::UnsupportedVersion,
        ));
    }
    let envelope_length = read_u32(&frame[6..10]) as usize;
    let bindings_length = read_u32(&frame[10..14]) as usize;
    let execution_length = read_u32(&frame[14..18]) as usize;
    let expected_length = APPLY_REQUEST_V2_HEADER_BYTES
        .checked_add(envelope_length)
        .and_then(|length| length.checked_add(bindings_length))
        .and_then(|length| length.checked_add(execution_length))
        .ok_or_else(|| RequestV2WireError::new(RequestV2WireErrorCode::InvalidFrameLength))?;
    if frame.len() < expected_length {
        return Err(RequestV2WireError::new(RequestV2WireErrorCode::Truncated));
    }
    if frame.len() != expected_length {
        return Err(RequestV2WireError::new(
            RequestV2WireErrorCode::InvalidFrameLength,
        ));
    }
    let envelope_start = APPLY_REQUEST_V2_HEADER_BYTES;
    let envelope_end = envelope_start + envelope_length;
    let bindings_end = envelope_end + bindings_length;
    let envelope = RuntimeApplyEnvelope::decode(&frame[envelope_start..envelope_end])
        .map_err(request_v2_envelope_wire_error)?;
    let bindings = TargetAssignments::decode(&frame[envelope_end..bindings_end])
        .map_err(request_v2_bindings_wire_error)?;
    let execution = TargetExecutionPlan::decode(&frame[bindings_end..])
        .map_err(request_v2_execution_wire_error)?;
    let assignments = TargetPlanAssignments::try_new(bindings, execution)
        .map_err(request_v2_target_plan_error)?;
    let slice = RuntimePlanSliceV2::try_new(envelope.control_commitment().slice(), assignments)
        .map_err(|_| RequestV2WireError::new(RequestV2WireErrorCode::CommitmentMismatch))?;
    RuntimeApplyRequestV2::try_new(envelope, slice)
        .map_err(|_| RequestV2WireError::new(RequestV2WireErrorCode::CommitmentMismatch))
}

fn request_v2_envelope_wire_error(error: WireError) -> RequestV2WireError {
    RequestV2WireError::with_detail(
        RequestV2WireErrorCode::EnvelopeRejected,
        error.code() as u16,
    )
}

fn request_v2_bindings_wire_error(error: AssignmentWireError) -> RequestV2WireError {
    RequestV2WireError::with_detail(
        RequestV2WireErrorCode::BindingsRejected,
        error.code() as u16,
    )
}

fn request_v2_execution_wire_error(error: ExecutionWireError) -> RequestV2WireError {
    RequestV2WireError::with_detail(
        RequestV2WireErrorCode::ExecutionRejected,
        error.code() as u16,
    )
}

fn request_v2_target_plan_error(error: TargetPlanContractError) -> RequestV2WireError {
    let code = match error {
        TargetPlanContractError::OrphanBinding => TargetPlanWireErrorCode::OrphanBinding,
        TargetPlanContractError::BindingMailboxMismatch => {
            TargetPlanWireErrorCode::BindingMailboxMismatch
        }
        TargetPlanContractError::BindingTargetMismatch => {
            TargetPlanWireErrorCode::BindingTargetMismatch
        }
        TargetPlanContractError::BlockUntilDeadlineForbidden => {
            TargetPlanWireErrorCode::BlockUntilDeadlineForbidden
        }
        TargetPlanContractError::SubjectExecutionMismatch => {
            TargetPlanWireErrorCode::SubjectExecutionMismatch
        }
        TargetPlanContractError::ControlStartSloExceeded => {
            TargetPlanWireErrorCode::ControlStartSloExceeded
        }
        _ => TargetPlanWireErrorCode::InvalidTargetPlan,
    };
    RequestV2WireError::with_detail(RequestV2WireErrorCode::TargetPlanRejected, code as u16)
}

fn execution_contract_wire_error(error: ExecutionContractError) -> ExecutionWireError {
    let code = match error {
        ExecutionContractError::DomainCountExceeded => ExecutionWireErrorCode::DomainCountExceeded,
        ExecutionContractError::ExecutionCountExceeded => {
            ExecutionWireErrorCode::ExecutionCountExceeded
        }
        ExecutionContractError::MissingLoopDomain
        | ExecutionContractError::MissingMailboxExecution => ExecutionWireErrorCode::MissingRecords,
        ExecutionContractError::DuplicateDomainRef => ExecutionWireErrorCode::DuplicateDomainRef,
        ExecutionContractError::DuplicateExecutionBinding => {
            ExecutionWireErrorCode::DuplicateExecutionBinding
        }
        ExecutionContractError::DuplicateExecutionMailbox => {
            ExecutionWireErrorCode::DuplicateExecutionMailbox
        }
        ExecutionContractError::OrphanDomainRef => ExecutionWireErrorCode::OrphanDomainRef,
        ExecutionContractError::UnusedDomainRef => ExecutionWireErrorCode::UnusedDomainRef,
        ExecutionContractError::UnsupportedLoopExecution => {
            ExecutionWireErrorCode::UnsupportedLoopExecution
        }
        ExecutionContractError::UnsafeLoopOverrunAction => {
            ExecutionWireErrorCode::UnsafeLoopOverrunAction
        }
        ExecutionContractError::SharedCapacityRequired => {
            ExecutionWireErrorCode::SharedCapacityRequired
        }
        ExecutionContractError::ControlReservationRequired => {
            ExecutionWireErrorCode::ControlReservationRequired
        }
        ExecutionContractError::ControlUtilizationExceeded => {
            ExecutionWireErrorCode::ControlUtilizationExceeded
        }
        ExecutionContractError::DomainUtilizationExceeded => {
            ExecutionWireErrorCode::DomainUtilizationExceeded
        }
        _ => ExecutionWireErrorCode::InvalidMailboxExecution,
    };
    ExecutionWireError::new(code)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

struct RecordCursor<'a> {
    record: &'a [u8],
    offset: usize,
}

impl<'a> RecordCursor<'a> {
    const fn new(record: &'a [u8]) -> Self {
        Self { record, offset: 0 }
    }

    fn array<const LENGTH: usize>(&mut self) -> [u8; LENGTH] {
        let end = self.offset + LENGTH;
        let mut value = [0; LENGTH];
        value.copy_from_slice(&self.record[self.offset..end]);
        self.offset = end;
        value
    }

    fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
    }
}

/// Fail-closed construction errors for the canonical execution body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionContractError {
    InvalidMaxOutstanding,
    InvalidControlReservation,
    InvalidControlBudget,
    InvalidDomainBudget,
    InvalidServiceCost,
    InvalidMinimumServiceWeight,
    InvalidMaxBurst,
    InvalidArrivalBound,
    InvalidExecutionBudget,
    RunBoundExceedsRunBudget,
    ExecutionBudgetExceedsDomain,
    DomainCountExceeded,
    ExecutionCountExceeded,
    MissingLoopDomain,
    MissingMailboxExecution,
    DuplicateDomainRef,
    DuplicateExecutionBinding,
    DuplicateExecutionMailbox,
    OrphanDomainRef,
    UnusedDomainRef,
    UnsupportedLoopExecution,
    UnsafeLoopOverrunAction,
    SharedCapacityRequired,
    ControlReservationRequired,
    ControlUtilizationExceeded,
    DomainUtilizationExceeded,
    UtilizationOverflow,
    Digest(DigestBuildError),
    CanonicalWireMismatch,
    ExecutionDigestMismatch,
}

impl From<DigestBuildError> for ExecutionContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ExecutionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::Digest(error) = self {
            return write!(formatter, "execution digest failed: {error}");
        }
        write!(formatter, "target execution contract error {self:?}")
    }
}

impl std::error::Error for ExecutionContractError {}

/// Fail-closed construction errors for the composite target plan and v2 request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetPlanContractError {
    Bindings(AssignmentContractError),
    Execution(ExecutionContractError),
    OrphanBinding,
    BindingMailboxMismatch,
    BindingTargetMismatch,
    BlockUntilDeadlineForbidden,
    SubjectExecutionMismatch,
    ControlStartSloExceeded,
    CompositeDigestMismatch,
    SliceAssignmentDigestMismatch,
    EnvelopeSliceMismatch,
    Provenance(ProvenanceContractError),
    Envelope(EnvelopeContractError),
    Digest(DigestBuildError),
    RequestFrameTooLarge,
    RequestCanonicalWireMismatch,
}

impl From<AssignmentContractError> for TargetPlanContractError {
    fn from(value: AssignmentContractError) -> Self {
        Self::Bindings(value)
    }
}

impl From<ExecutionContractError> for TargetPlanContractError {
    fn from(value: ExecutionContractError) -> Self {
        Self::Execution(value)
    }
}

impl From<ProvenanceContractError> for TargetPlanContractError {
    fn from(value: ProvenanceContractError) -> Self {
        Self::Provenance(value)
    }
}

impl From<EnvelopeContractError> for TargetPlanContractError {
    fn from(value: EnvelopeContractError) -> Self {
        Self::Envelope(value)
    }
}

impl From<DigestBuildError> for TargetPlanContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for TargetPlanContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "target plan contract error {self:?}")
    }
}

impl std::error::Error for TargetPlanContractError {}

/// Identifies the fixed-record section containing a PXTE wire error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionRecordSection {
    Domain = 1,
    Mailbox = 2,
}

/// Stable machine-readable reason for PXTE v1 rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ExecutionWireErrorCode {
    FrameTooLarge = 1,
    Truncated = 2,
    InvalidMagic = 3,
    UnsupportedVersion = 4,
    DomainCountExceeded = 5,
    ExecutionCountExceeded = 6,
    InvalidFrameLength = 7,
    InvalidEnumValue = 8,
    InvalidDomain = 9,
    InvalidMailboxExecution = 10,
    DuplicateDomainRef = 11,
    DuplicateExecutionBinding = 12,
    DuplicateExecutionMailbox = 13,
    OrphanDomainRef = 14,
    UnusedDomainRef = 15,
    UnsupportedLoopExecution = 16,
    ControlReservationRequired = 17,
    ControlUtilizationExceeded = 18,
    DomainUtilizationExceeded = 19,
    MissingRecords = 20,
    NonCanonicalFrame = 21,
    UnsafeLoopOverrunAction = 22,
    SharedCapacityRequired = 23,
}

/// PXTE rejection with an optional section and zero-based record index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionWireError {
    code: ExecutionWireErrorCode,
    section: Option<ExecutionRecordSection>,
    record_index: Option<u32>,
}

impl ExecutionWireError {
    const fn new(code: ExecutionWireErrorCode) -> Self {
        Self {
            code,
            section: None,
            record_index: None,
        }
    }

    const fn at(
        code: ExecutionWireErrorCode,
        section: ExecutionRecordSection,
        record_index: u32,
    ) -> Self {
        Self {
            code,
            section: Some(section),
            record_index: Some(record_index),
        }
    }

    #[must_use]
    pub const fn code(self) -> ExecutionWireErrorCode {
        self.code
    }

    #[must_use]
    pub const fn section(self) -> Option<ExecutionRecordSection> {
        self.section
    }

    #[must_use]
    pub const fn record_index(self) -> Option<u32> {
        self.record_index
    }
}

impl fmt::Display for ExecutionWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "target execution wire error {:?}", self.code)
    }
}

impl std::error::Error for ExecutionWireError {}

/// Stable detail reason for a cross-body v2 target-plan rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum TargetPlanWireErrorCode {
    OrphanBinding = 1,
    BindingMailboxMismatch = 2,
    BindingTargetMismatch = 3,
    BlockUntilDeadlineForbidden = 4,
    SubjectExecutionMismatch = 5,
    InvalidTargetPlan = 6,
    ControlStartSloExceeded = 7,
}

/// Stable machine-readable reason for PXAR v2 rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RequestV2WireErrorCode {
    FrameTooLarge = 1,
    Truncated = 2,
    InvalidMagic = 3,
    UnsupportedVersion = 4,
    InvalidFrameLength = 5,
    EnvelopeRejected = 6,
    BindingsRejected = 7,
    ExecutionRejected = 8,
    TargetPlanRejected = 9,
    CommitmentMismatch = 10,
}

/// PXAR v2 rejection with an optional nested stable reason code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestV2WireError {
    code: RequestV2WireErrorCode,
    detail_code: Option<u16>,
}

impl RequestV2WireError {
    const fn new(code: RequestV2WireErrorCode) -> Self {
        Self {
            code,
            detail_code: None,
        }
    }

    const fn with_detail(code: RequestV2WireErrorCode, detail_code: u16) -> Self {
        Self {
            code,
            detail_code: Some(detail_code),
        }
    }

    #[must_use]
    pub const fn code(self) -> RequestV2WireErrorCode {
        self.code
    }

    #[must_use]
    pub const fn detail_code(self) -> Option<u16> {
        self.detail_code
    }
}

impl fmt::Display for RequestV2WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v2 apply-request wire error {:?}", self.code)
    }
}

impl std::error::Error for RequestV2WireError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::BoundedDuration;

    use crate::assignment::{
        BindingAssignment, BindingId, DeliveryProfile, InstanceRef, InteractionKind, MailboxRef,
        MailboxSpec, OverflowPolicy, PortCardinality, PortDirection, PortEndpoint, PortRef,
        PortSpec, RequestWireErrorCode, RuntimeApplyRequest, SchemaRef, TargetAssignments,
    };
    use crate::provenance::{
        PlanProvenance, RuntimeSliceCommitment, RuntimeSliceHeader, SourcePlanDigest,
        SourcePlanRef, SourcePlanRevision, SourceScopeRef, TargetAssignmentDigest,
    };

    use super::{
        APPLY_REQUEST_V2_HEADER_BYTES, BlockingRisk, CallModel, CallbackBudgets, CardDefinitionRef,
        CardImplementationRef, CardSubjectSpec, DispatchClass, DomainRef, ExecutionContractError,
        ExecutionRecordSection, ExecutionWireErrorCode, LoopDomainCapacity, LoopDomainSpec,
        LoopExecutionRequirements, LoopLifecycleBudgets, MAILBOX_EXECUTION_RECORD_BYTES,
        MAX_LOOP_DOMAINS, MailboxDispatchPolicy, MailboxExecutionSpec, OverrunAction,
        RUNTIME_APPLY_REQUEST_MAGIC, RUNTIME_APPLY_REQUEST_V2_VERSION, RequestV2WireErrorCode,
        RunBoundProvenance, RuntimeApplyRequestV2, RuntimePlanSliceV2,
        TARGET_EXECUTION_HEADER_BYTES, TargetExecutionPlan, TargetPlanAssignments,
        TargetPlanContractError, TargetPlanWireErrorCode, WorkloadKind,
        request_v2_target_plan_error,
    };

    fn binding(
        binding_byte: u8,
        source_byte: u8,
        target_byte: u8,
        target_port_byte: u8,
        mailbox_byte: u8,
        overflow: OverflowPolicy,
    ) -> BindingAssignment {
        let Ok(schema) = SchemaRef::try_new([0x21; 16], 1, Digest32::from_bytes([0x22; 32])) else {
            panic!("fixture schema must be valid");
        };
        let source = PortEndpoint::new(
            InstanceRef::from_bytes([source_byte; 16]),
            PortRef::from_bytes([source_byte.wrapping_add(0x10); 16]),
            PortSpec::new(
                PortDirection::Out,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let target = PortEndpoint::new(
            InstanceRef::from_bytes([target_byte; 16]),
            PortRef::from_bytes([target_port_byte; 16]),
            PortSpec::new(
                PortDirection::In,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let Ok(delivery) =
            DeliveryProfile::try_new(128, BoundedDuration::from_nanos(1_000), overflow)
        else {
            panic!("fixture delivery must be valid");
        };
        let Ok(mailbox) =
            MailboxSpec::try_new(2, 256, BoundedDuration::from_nanos(500), 1, 256, overflow)
        else {
            panic!("fixture mailbox must be valid");
        };
        let Ok(value) = BindingAssignment::try_new(
            BindingId::from_bytes([binding_byte; 16]),
            source,
            target,
            MailboxRef::from_bytes([mailbox_byte; 16]),
            delivery,
            mailbox,
        ) else {
            panic!("fixture binding must be valid");
        };
        value
    }

    fn fixture_bindings(overflow: OverflowPolicy) -> TargetAssignments {
        let records = vec![
            binding(0x32, 0x42, 0x62, 0x72, 0x82, overflow),
            binding(0x31, 0x41, 0x61, 0x71, 0x81, overflow),
        ];
        let Ok(value) = TargetAssignments::try_new(records) else {
            panic!("fixture target assignments must be valid");
        };
        value
    }

    fn binding_with_queue_age(value: BindingAssignment, queue_age_nanos: u64) -> BindingAssignment {
        let original = value.mailbox_spec();
        let Ok(mailbox) = MailboxSpec::try_new(
            original.capacity_items(),
            original.capacity_bytes(),
            BoundedDuration::from_nanos(queue_age_nanos),
            original.max_inflight(),
            original.max_retained_bytes(),
            original.overflow_policy(),
        ) else {
            panic!("queue-age fixture mailbox must be valid");
        };
        let source = PortEndpoint::new(
            value.source_instance(),
            value.source_port(),
            value.source_spec(),
        );
        let target = PortEndpoint::new(
            value.target_instance(),
            value.target_port(),
            value.target_spec(),
        );
        let Ok(binding) = BindingAssignment::try_new(
            value.binding_id(),
            source,
            target,
            value.mailbox(),
            value.delivery(),
            mailbox,
        ) else {
            panic!("queue-age fixture binding must be valid");
        };
        binding
    }

    fn loop_domain() -> LoopDomainSpec {
        let Ok(capacity) = LoopDomainCapacity::try_new(
            2,
            1,
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(60),
        ) else {
            panic!("fixture capacity must be valid");
        };
        let Ok(lifecycle) = LoopLifecycleBudgets::try_new(
            BoundedDuration::from_nanos(20),
            BoundedDuration::from_nanos(30),
            BoundedDuration::from_nanos(20),
        ) else {
            panic!("fixture lifecycle must be valid");
        };
        LoopDomainSpec::new(DomainRef::from_bytes([0x91; 16]), capacity, lifecycle)
    }

    fn mailbox_execution() -> MailboxExecutionSpec {
        let subject = CardSubjectSpec::new(
            CardDefinitionRef::from_bytes([0xa1; 16]),
            CardImplementationRef::from_bytes([0xa2; 16]),
            Digest32::from_bytes([0xa3; 32]),
            Digest32::from_bytes([0xa4; 32]),
            Digest32::from_bytes([0xa5; 32]),
        );
        let Ok(requirements) = LoopExecutionRequirements::try_new(
            CallModel::CooperativeAsync,
            WorkloadKind::Io,
            BlockingRisk::None,
            RunBoundProvenance::Measured,
            BoundedDuration::from_nanos(10),
        ) else {
            panic!("fixture requirements must be valid");
        };
        let Ok(budgets) = CallbackBudgets::try_new(
            BoundedDuration::from_nanos(20),
            BoundedDuration::from_nanos(10),
            OverrunAction::CooperativeCancel,
        ) else {
            panic!("fixture callback budgets must be valid");
        };
        let Ok(dispatch) =
            MailboxDispatchPolicy::try_new(DispatchClass::Control, 2, 4, 2, 2, budgets)
        else {
            panic!("fixture dispatch policy must be valid");
        };
        let Ok(value) = MailboxExecutionSpec::try_new(
            BindingId::from_bytes([0x31; 16]),
            MailboxRef::from_bytes([0x81; 16]),
            InstanceRef::from_bytes([0x61; 16]),
            DomainRef::from_bytes([0x91; 16]),
            subject,
            requirements,
            dispatch,
        ) else {
            panic!("fixture mailbox execution must be valid");
        };
        value
    }

    fn execution_plan() -> TargetExecutionPlan {
        let Ok(value) =
            TargetExecutionPlan::try_new(vec![loop_domain()], vec![mailbox_execution()])
        else {
            panic!("fixture execution plan must be valid");
        };
        value
    }

    fn target_plan(overflow: OverflowPolicy) -> TargetPlanAssignments {
        let Ok(value) =
            TargetPlanAssignments::try_new(fixture_bindings(overflow), execution_plan())
        else {
            panic!("fixture target plan must be valid");
        };
        value
    }

    fn slice_commitment(digest: TargetAssignmentDigest) -> RuntimeSliceCommitment {
        let provenance = PlanProvenance::new(
            SourceScopeRef::from_bytes([1; 16]),
            SourcePlanRef::from_bytes([2; 16]),
            SourcePlanRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([4; 32])),
        );
        let header =
            RuntimeSliceHeader::new(RuntimeHostId::from_bytes([5; 16]), provenance, digest);
        let Ok(value) = RuntimeSliceCommitment::try_new(header) else {
            panic!("fixture Slice commitment must be valid");
        };
        value
    }

    #[test]
    fn grouped_scalar_contracts_fail_closed() {
        assert_eq!(
            LoopDomainCapacity::try_new(
                0,
                0,
                BoundedDuration::from_nanos(100),
                BoundedDuration::from_nanos(0),
            ),
            Err(ExecutionContractError::InvalidMaxOutstanding)
        );
        assert_eq!(
            LoopDomainCapacity::try_new(
                1,
                2,
                BoundedDuration::from_nanos(100),
                BoundedDuration::from_nanos(40),
            ),
            Err(ExecutionContractError::InvalidControlReservation)
        );
        assert_eq!(
            LoopExecutionRequirements::try_new(
                CallModel::CooperativeAsync,
                WorkloadKind::Io,
                BlockingRisk::None,
                RunBoundProvenance::Measured,
                BoundedDuration::from_nanos(0),
            ),
            Err(ExecutionContractError::InvalidExecutionBudget)
        );

        let mut execution = mailbox_execution();
        execution.requirements.max_nonpreemptive_run = BoundedDuration::from_nanos(21);
        assert_eq!(
            MailboxExecutionSpec::try_new(
                execution.binding_id,
                execution.mailbox,
                execution.target_instance,
                execution.domain,
                execution.subject,
                execution.requirements,
                execution.dispatch,
            ),
            Err(ExecutionContractError::RunBoundExceedsRunBudget)
        );
    }

    #[test]
    fn pxte_matches_independent_golden_and_round_trips() {
        let plan = execution_plan();
        let expected_digest = [
            0xc0, 0x1b, 0xec, 0x80, 0x02, 0xa6, 0xad, 0x6b, 0x2a, 0xf8, 0x83, 0x16, 0xec, 0xe8,
            0x2f, 0xd2, 0xc8, 0xda, 0x23, 0x44, 0x6d, 0x68, 0x2b, 0x7d, 0x8b, 0x3b, 0xca, 0xf8,
            0x01, 0x51, 0xd5, 0x7e,
        ];

        assert_eq!(plan.canonical_wire().len(), 314);
        assert_eq!(plan.execution_digest().value().as_bytes(), &expected_digest);
        assert_eq!(TargetExecutionPlan::decode(plan.canonical_wire()), Ok(plan));
    }

    #[test]
    fn composite_plan_accepts_binding_superset_and_matches_golden() {
        let plan = target_plan(OverflowPolicy::Latest);
        let expected = [
            0x65, 0x35, 0x0e, 0x94, 0x37, 0xc7, 0x4c, 0xe6, 0x91, 0x2d, 0x11, 0xb0, 0xbe, 0x08,
            0x4b, 0x6f, 0xea, 0x72, 0xa8, 0x84, 0x17, 0xae, 0x6d, 0x98, 0x33, 0x00, 0x8c, 0x39,
            0x74, 0x17, 0x7d, 0x34,
        ];

        assert_eq!(plan.bindings().len(), 2);
        assert_eq!(plan.execution().mailbox_executions().len(), 1);
        assert_eq!(plan.assignment_digest().value().as_bytes(), &expected);
        assert_eq!(plan.validate(), Ok(()));
    }

    #[test]
    fn loop_admission_rejects_unprovable_profiles_and_capacity() {
        let domain = loop_domain();

        let mut unsupported = mailbox_execution();
        unsupported.requirements.call_model = CallModel::Synchronous;
        assert_eq!(
            TargetExecutionPlan::try_new(vec![domain], vec![unsupported]),
            Err(ExecutionContractError::UnsupportedLoopExecution)
        );

        let mut unsafe_overrun = mailbox_execution();
        unsafe_overrun.dispatch.callback_budgets.overrun_action = OverrunAction::Continue;
        assert_eq!(
            TargetExecutionPlan::try_new(vec![domain], vec![unsafe_overrun]),
            Err(ExecutionContractError::UnsafeLoopOverrunAction)
        );
        unsafe_overrun.dispatch.callback_budgets.overrun_action = OverrunAction::Uncertain;
        assert_eq!(
            TargetExecutionPlan::try_new(vec![domain], vec![unsafe_overrun]),
            Err(ExecutionContractError::UnsafeLoopOverrunAction)
        );

        let mut overloaded = mailbox_execution();
        // Run alone is feasible, but the permit/reactor remains occupied for
        // post-overrun cleanup: 4 * 20 <= 100 while 4 * (20 + 10) > 100.
        overloaded.dispatch.max_arrivals_per_window = 4;
        assert_eq!(
            TargetExecutionPlan::try_new(vec![domain], vec![overloaded]),
            Err(ExecutionContractError::DomainUtilizationExceeded)
        );

        let Ok(insufficient_control_capacity) = LoopDomainCapacity::try_new(
            2,
            1,
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(50),
        ) else {
            panic!("control-overload fixture capacity must be valid");
        };
        let insufficient_control_domain = LoopDomainSpec::new(
            domain.domain(),
            insufficient_control_capacity,
            domain.lifecycle(),
        );
        assert_eq!(
            TargetExecutionPlan::try_new(
                vec![insufficient_control_domain],
                vec![mailbox_execution()],
            ),
            Err(ExecutionContractError::ControlUtilizationExceeded),
            "run demand 40 fits the reserve, but run plus cleanup demand 60 does not"
        );

        let Ok(no_control_capacity) = LoopDomainCapacity::try_new(
            2,
            0,
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(0),
        ) else {
            panic!("non-control fixture capacity must be valid");
        };
        let no_control_domain =
            LoopDomainSpec::new(domain.domain(), no_control_capacity, domain.lifecycle());
        assert_eq!(
            TargetExecutionPlan::try_new(vec![no_control_domain], vec![mailbox_execution()]),
            Err(ExecutionContractError::ControlReservationRequired)
        );

        let Ok(all_reserved_capacity) = LoopDomainCapacity::try_new(
            1,
            1,
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(60),
        ) else {
            panic!("all-reserved fixture capacity must be structurally valid");
        };
        let all_reserved_domain =
            LoopDomainSpec::new(domain.domain(), all_reserved_capacity, domain.lifecycle());
        let mut non_control = mailbox_execution();
        non_control.dispatch.dispatch_class = DispatchClass::Interactive;
        assert_eq!(
            TargetExecutionPlan::try_new(vec![all_reserved_domain], vec![non_control]),
            Err(ExecutionContractError::SharedCapacityRequired)
        );
        let mut overloaded_non_control = non_control;
        overloaded_non_control.dispatch.max_arrivals_per_window = 6;
        assert_eq!(
            TargetExecutionPlan::try_new(vec![all_reserved_domain], vec![overloaded_non_control]),
            Err(ExecutionContractError::DomainUtilizationExceeded),
            "existing utilization rejection precedence must remain stable"
        );
        assert!(
            TargetExecutionPlan::try_new(vec![all_reserved_domain], vec![mailbox_execution()])
                .is_ok(),
            "an all-Control domain may reserve every permit"
        );
        assert!(
            TargetExecutionPlan::try_new(vec![domain], vec![non_control]).is_ok(),
            "one shared permit must keep a non-Control execution dispatchable"
        );
    }

    #[test]
    fn target_plan_rejects_orphans_mismatches_and_blocking_delivery() {
        let bindings = fixture_bindings(OverflowPolicy::Latest);

        let mut orphan = mailbox_execution();
        orphan.binding_id = BindingId::from_bytes([0xff; 16]);
        let Ok(orphan_execution) = TargetExecutionPlan::try_new(vec![loop_domain()], vec![orphan])
        else {
            panic!("orphan fixture must remain a valid standalone PXTE body");
        };
        assert_eq!(
            TargetPlanAssignments::try_new(bindings.clone(), orphan_execution),
            Err(TargetPlanContractError::OrphanBinding)
        );

        let mut mailbox_mismatch = mailbox_execution();
        mailbox_mismatch.mailbox = MailboxRef::from_bytes([0xfe; 16]);
        let Ok(mismatch_execution) =
            TargetExecutionPlan::try_new(vec![loop_domain()], vec![mailbox_mismatch])
        else {
            panic!("mismatch fixture must remain a valid standalone PXTE body");
        };
        assert_eq!(
            TargetPlanAssignments::try_new(bindings, mismatch_execution),
            Err(TargetPlanContractError::BindingMailboxMismatch)
        );

        assert_eq!(
            TargetPlanAssignments::try_new(
                fixture_bindings(OverflowPolicy::BlockUntilDeadline),
                execution_plan(),
            ),
            Err(TargetPlanContractError::BlockUntilDeadlineForbidden)
        );
    }

    #[test]
    fn control_start_slo_is_strict_and_accounts_for_serial_cross_class_work() {
        let equality_bindings = TargetAssignments::try_new(vec![
            binding_with_queue_age(
                binding(0x31, 0x41, 0x61, 0x71, 0x81, OverflowPolicy::Latest),
                60,
            ),
            binding(0x32, 0x42, 0x62, 0x72, 0x82, OverflowPolicy::Latest),
        ])
        .unwrap_or_else(|error| panic!("equality fixture bindings must build: {error}"));
        assert_eq!(
            TargetPlanAssignments::try_new(equality_bindings, execution_plan()),
            Err(TargetPlanContractError::ControlStartSloExceeded),
            "deadline equality is already expired"
        );

        let just_after_bindings = TargetAssignments::try_new(vec![
            binding_with_queue_age(
                binding(0x31, 0x41, 0x61, 0x71, 0x81, OverflowPolicy::Latest),
                61,
            ),
            binding(0x32, 0x42, 0x62, 0x72, 0x82, OverflowPolicy::Latest),
        ])
        .unwrap_or_else(|error| panic!("strict-bound fixture bindings must build: {error}"));
        assert!(
            TargetPlanAssignments::try_new(just_after_bindings, execution_plan()).is_ok(),
            "one nanosecond beyond the proven wait bound must remain admissible"
        );

        let base = loop_domain();
        let capacity = LoopDomainCapacity::try_new(
            2,
            1,
            BoundedDuration::from_nanos(1_000),
            BoundedDuration::from_nanos(60),
        )
        .unwrap_or_else(|error| panic!("cross-class fixture capacity must build: {error}"));
        let domain = LoopDomainSpec::new(base.domain(), capacity, base.lifecycle());
        let control = mailbox_execution();
        let mut stream = control;
        stream.binding_id = BindingId::from_bytes([0x32; 16]);
        stream.mailbox = MailboxRef::from_bytes([0x82; 16]);
        stream.target_instance = InstanceRef::from_bytes([0x62; 16]);
        stream.dispatch.dispatch_class = DispatchClass::Stream;
        stream.dispatch.max_burst = 1;
        stream.dispatch.max_arrivals_per_window = 1;
        stream.requirements.max_nonpreemptive_run = BoundedDuration::from_nanos(1);
        stream.dispatch.callback_budgets.run_budget = BoundedDuration::from_nanos(590);
        stream.dispatch.callback_budgets.cleanup_budget = BoundedDuration::from_nanos(10);
        let plan = TargetExecutionPlan::try_new(vec![domain], vec![control, stream])
            .unwrap_or_else(|error| panic!("PXTE-only cross-class fixture must build: {error}"));
        assert_eq!(plan.validate(), Ok(()));
        assert_eq!(
            TargetPlanAssignments::try_new(fixture_bindings(OverflowPolicy::Latest), plan),
            Err(TargetPlanContractError::ControlStartSloExceeded),
            "a yielding Stream callback is still serialized through its full run and cleanup"
        );
    }

    #[test]
    fn pxte_decoder_is_strict_and_reports_stable_locations() {
        let mut invalid_enum = execution_plan().canonical_wire().to_vec();
        let enum_offset = TARGET_EXECUTION_HEADER_BYTES + 64 + 192;
        invalid_enum[enum_offset] = 0xff;
        let Err(error) = TargetExecutionPlan::decode(&invalid_enum) else {
            panic!("unknown PXTE enum must be rejected");
        };
        assert_eq!(error.code(), ExecutionWireErrorCode::InvalidEnumValue);
        assert_eq!(error.section(), Some(ExecutionRecordSection::Mailbox));
        assert_eq!(error.record_index(), Some(0));

        let mut orphan_domain = execution_plan().canonical_wire().to_vec();
        let domain_offset = TARGET_EXECUTION_HEADER_BYTES + 64 + 48;
        orphan_domain[domain_offset..domain_offset + 16].fill(0xff);
        let Err(error) = TargetExecutionPlan::decode(&orphan_domain) else {
            panic!("orphan PXTE DomainRef must be rejected");
        };
        assert_eq!(error.code(), ExecutionWireErrorCode::OrphanDomainRef);

        let mut no_shared_capacity = execution_plan().canonical_wire().to_vec();
        let max_outstanding_offset = TARGET_EXECUTION_HEADER_BYTES + 16;
        no_shared_capacity[max_outstanding_offset..max_outstanding_offset + 4]
            .copy_from_slice(&1_u32.to_be_bytes());
        let dispatch_class_offset = TARGET_EXECUTION_HEADER_BYTES + 64 + 196;
        no_shared_capacity[dispatch_class_offset] = DispatchClass::Interactive as u8;
        let Err(error) = TargetExecutionPlan::decode(&no_shared_capacity) else {
            panic!("non-Control execution without shared capacity must be rejected");
        };
        assert_eq!(error.code(), ExecutionWireErrorCode::SharedCapacityRequired);

        let mut too_many = vec![0_u8; TARGET_EXECUTION_HEADER_BYTES];
        too_many[..4].copy_from_slice(b"PXTE");
        too_many[4..6].copy_from_slice(&1_u16.to_be_bytes());
        too_many[6..10].copy_from_slice(&((MAX_LOOP_DOMAINS + 1) as u32).to_be_bytes());
        let Err(error) = TargetExecutionPlan::decode(&too_many) else {
            panic!("oversized domain count must be rejected");
        };
        assert_eq!(error.code(), ExecutionWireErrorCode::DomainCountExceeded);

        let mut trailing = execution_plan().canonical_wire().to_vec();
        trailing.push(0);
        let Err(error) = TargetExecutionPlan::decode(&trailing) else {
            panic!("trailing PXTE bytes must be rejected");
        };
        assert_eq!(error.code(), ExecutionWireErrorCode::InvalidFrameLength);
    }

    #[test]
    fn v2_slice_binds_the_composite_digest() {
        let assignments = target_plan(OverflowPolicy::Latest);
        let commitment = slice_commitment(assignments.assignment_digest());
        let Ok(slice) = RuntimePlanSliceV2::try_new(commitment, assignments.clone()) else {
            panic!("matching composite Slice must be valid");
        };
        assert_eq!(slice.assignments(), &assignments);
        assert_eq!(slice.validate(), Ok(()));

        let mismatched = slice_commitment(TargetAssignmentDigest::new(Digest32::from_bytes(
            [0xff; 32],
        )));
        assert_eq!(
            RuntimePlanSliceV2::try_new(mismatched, assignments),
            Err(TargetPlanContractError::SliceAssignmentDigestMismatch)
        );
    }

    #[test]
    fn wire_error_codes_are_append_only_and_v1_v2_do_not_fallback() {
        assert_eq!(
            [
                ExecutionWireErrorCode::FrameTooLarge as u16,
                ExecutionWireErrorCode::Truncated as u16,
                ExecutionWireErrorCode::InvalidMagic as u16,
                ExecutionWireErrorCode::UnsupportedVersion as u16,
                ExecutionWireErrorCode::DomainCountExceeded as u16,
                ExecutionWireErrorCode::ExecutionCountExceeded as u16,
                ExecutionWireErrorCode::InvalidFrameLength as u16,
                ExecutionWireErrorCode::InvalidEnumValue as u16,
                ExecutionWireErrorCode::InvalidDomain as u16,
                ExecutionWireErrorCode::InvalidMailboxExecution as u16,
                ExecutionWireErrorCode::DuplicateDomainRef as u16,
                ExecutionWireErrorCode::DuplicateExecutionBinding as u16,
                ExecutionWireErrorCode::DuplicateExecutionMailbox as u16,
                ExecutionWireErrorCode::OrphanDomainRef as u16,
                ExecutionWireErrorCode::UnusedDomainRef as u16,
                ExecutionWireErrorCode::UnsupportedLoopExecution as u16,
                ExecutionWireErrorCode::ControlReservationRequired as u16,
                ExecutionWireErrorCode::ControlUtilizationExceeded as u16,
                ExecutionWireErrorCode::DomainUtilizationExceeded as u16,
                ExecutionWireErrorCode::MissingRecords as u16,
                ExecutionWireErrorCode::NonCanonicalFrame as u16,
                ExecutionWireErrorCode::UnsafeLoopOverrunAction as u16,
                ExecutionWireErrorCode::SharedCapacityRequired as u16,
            ],
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            ]
        );
        assert_eq!(
            [
                TargetPlanWireErrorCode::OrphanBinding as u16,
                TargetPlanWireErrorCode::BindingMailboxMismatch as u16,
                TargetPlanWireErrorCode::BindingTargetMismatch as u16,
                TargetPlanWireErrorCode::BlockUntilDeadlineForbidden as u16,
                TargetPlanWireErrorCode::SubjectExecutionMismatch as u16,
                TargetPlanWireErrorCode::InvalidTargetPlan as u16,
                TargetPlanWireErrorCode::ControlStartSloExceeded as u16,
            ],
            [1, 2, 3, 4, 5, 6, 7]
        );
        let mapped = request_v2_target_plan_error(TargetPlanContractError::ControlStartSloExceeded);
        assert_eq!(mapped.code(), RequestV2WireErrorCode::TargetPlanRejected);
        assert_eq!(
            mapped.detail_code(),
            Some(TargetPlanWireErrorCode::ControlStartSloExceeded as u16)
        );

        let mut v2_header = vec![0_u8; APPLY_REQUEST_V2_HEADER_BYTES];
        v2_header[..4].copy_from_slice(RUNTIME_APPLY_REQUEST_MAGIC);
        v2_header[4..6].copy_from_slice(&RUNTIME_APPLY_REQUEST_V2_VERSION.to_be_bytes());
        let Err(v1_error) = RuntimeApplyRequest::decode(&v2_header) else {
            panic!("v1 decoder must reject PXAR v2");
        };
        assert_eq!(v1_error.code(), RequestWireErrorCode::UnsupportedVersion);

        v2_header[4..6].copy_from_slice(&1_u16.to_be_bytes());
        let Err(v2_error) = RuntimeApplyRequestV2::decode(&v2_header) else {
            panic!("v2 decoder must reject PXAR v1");
        };
        assert_eq!(v2_error.code(), RequestV2WireErrorCode::UnsupportedVersion);

        assert_eq!(MAILBOX_EXECUTION_RECORD_BYTES, 236);
    }
}
