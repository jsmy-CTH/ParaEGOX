//! Additive ThreadDomain execution contracts and PXAR v3 framing.
//!
//! PXTE v2 embeds an optional, unchanged PXTE v1 Loop plan and adds bounded
//! ThreadDomain records. The executor budget covers framework threads, every
//! declared ThreadDomain worker, and native-library threads reserved once per
//! distinct target instance. This module defines desired state only; it does
//! not create threads, processes, callbacks, dispatchers, or clocks.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::time::BoundedDuration;

use crate::assignment::{
    AssignmentContractError, AssignmentWireError, BindingId, InstanceRef, MAX_TARGET_ASSIGNMENTS,
    MAX_TARGET_ASSIGNMENTS_BYTES, MailboxRef, OverflowPolicy, TargetAssignments,
};
use crate::execution::{
    BlockingRisk, CallModel, CardSubjectSpec, DispatchClass, ExecutionContractError,
    ExecutionWireError, MAX_ARRIVALS_PER_WINDOW, MAX_EXECUTION_DURATION_NANOS,
    MAX_MINIMUM_SERVICE_WEIGHT, MAX_SERVICE_COST_TOKENS, MAX_TARGET_EXECUTION_PLAN_BYTES,
    RunBoundProvenance, TargetExecutionPlan, TargetPlanAssignments, TargetPlanContractError,
    WorkloadKind,
};
use crate::provenance::{ProvenanceContractError, RuntimeSliceCommitment, TargetAssignmentDigest};
use crate::wire::{
    EnvelopeContractError, MAX_RUNTIME_APPLY_ENVELOPE_BYTES, RuntimeApplyEnvelope, WireError,
};

/// Version of the additive Loop plus Thread execution body.
pub const TARGET_EXECUTION_PLAN_V2_VERSION: u16 = 2;
/// Version of the complete apply request carrying PXTA and PXTE v2.
pub const RUNTIME_APPLY_REQUEST_V3_VERSION: u16 = 3;
/// Maximum ThreadDomain records in one target execution body.
pub const MAX_THREAD_DOMAINS: usize = 64;
/// Maximum Thread Mailbox execution records in one target execution body.
pub const MAX_THREAD_MAILBOX_EXECUTIONS: usize = MAX_TARGET_ASSIGNMENTS;
/// Maximum total OS-thread budget expressible by this contract.
pub const MAX_EXECUTOR_THREADS: u32 = 65_535;

const TARGET_EXECUTION_MAGIC: &[u8; 4] = b"PXTE";
const RUNTIME_APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const TARGET_EXECUTION_V2_HEADER_BYTES: usize = 26;
const THREAD_DOMAIN_RECORD_BYTES: usize = 44;
const THREAD_MAILBOX_EXECUTION_RECORD_BYTES: usize = 239;
const APPLY_REQUEST_V3_HEADER_BYTES: usize = 18;
const TARGET_EXECUTION_V2_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.target-execution.sha256.v2";
const TARGET_PLAN_ASSIGNMENTS_V3_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.target-plan-assignments.sha256.v3";

/// Maximum canonical byte length of one PXTE v2 body.
pub const MAX_TARGET_EXECUTION_PLAN_V2_BYTES: usize = TARGET_EXECUTION_V2_HEADER_BYTES
    + MAX_TARGET_EXECUTION_PLAN_BYTES
    + MAX_THREAD_DOMAINS * THREAD_DOMAIN_RECORD_BYTES
    + MAX_THREAD_MAILBOX_EXECUTIONS * THREAD_MAILBOX_EXECUTION_RECORD_BYTES;
/// Maximum canonical byte length of one PXAR v3 request.
pub const MAX_RUNTIME_APPLY_REQUEST_V3_BYTES: usize = APPLY_REQUEST_V3_HEADER_BYTES
    + MAX_RUNTIME_APPLY_ENVELOPE_BYTES
    + MAX_TARGET_ASSIGNMENTS_BYTES
    + MAX_TARGET_EXECUTION_PLAN_V2_BYTES;

/// Desired identity of one target-local ThreadDomain slot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ThreadDomainRef([u8; 16]);

impl ThreadDomainRef {
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

/// Digest of one exact canonical PXTE v2 body.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TargetExecutionDigestV2(Digest32);

impl TargetExecutionDigestV2 {
    /// Wraps a digest assigned by the canonical PXTE v2 owner.
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

/// Process-wide worker and framework thread ceiling.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExecutorBudgetSpec {
    max_total_threads: u32,
    framework_threads: u32,
}

impl ExecutorBudgetSpec {
    /// Validates a finite executor budget with an explicit framework reserve.
    pub const fn try_new(
        max_total_threads: u32,
        framework_threads: u32,
    ) -> Result<Self, ThreadExecutionContractError> {
        if max_total_threads == 0
            || max_total_threads > MAX_EXECUTOR_THREADS
            || framework_threads == 0
            || framework_threads > max_total_threads
        {
            return Err(ThreadExecutionContractError::InvalidExecutorBudget);
        }
        Ok(Self {
            max_total_threads,
            framework_threads,
        })
    }

    /// Returns the global process thread ceiling.
    #[must_use]
    pub const fn max_total_threads(self) -> u32 {
        self.max_total_threads
    }

    /// Returns the non-domain framework thread reserve.
    #[must_use]
    pub const fn framework_threads(self) -> u32 {
        self.framework_threads
    }
}

/// Worker capacity and lifecycle budgets for one ThreadDomain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ThreadDomainSpec {
    domain: ThreadDomainRef,
    worker_count: u32,
    capacity_window: BoundedDuration,
    start_budget: BoundedDuration,
    drain_budget: BoundedDuration,
}

impl ThreadDomainSpec {
    /// Validates a bounded, nonempty ThreadDomain worker pool.
    pub const fn try_new(
        domain: ThreadDomainRef,
        worker_count: u32,
        capacity_window: BoundedDuration,
        start_budget: BoundedDuration,
        drain_budget: BoundedDuration,
    ) -> Result<Self, ThreadExecutionContractError> {
        if worker_count == 0 || worker_count > MAX_EXECUTOR_THREADS {
            return Err(ThreadExecutionContractError::InvalidWorkerCount);
        }
        if !valid_duration(capacity_window)
            || !valid_duration(start_budget)
            || !valid_duration(drain_budget)
        {
            return Err(ThreadExecutionContractError::InvalidDomainBudget);
        }
        Ok(Self {
            domain,
            worker_count,
            capacity_window,
            start_budget,
            drain_budget,
        })
    }

    /// Returns the desired ThreadDomain identity.
    #[must_use]
    pub const fn domain(self) -> ThreadDomainRef {
        self.domain
    }

    /// Returns the fixed worker count.
    #[must_use]
    pub const fn worker_count(self) -> u32 {
        self.worker_count
    }

    /// Returns the utilization capacity window.
    #[must_use]
    pub const fn capacity_window(self) -> BoundedDuration {
        self.capacity_window
    }

    /// Returns the bounded domain start budget.
    #[must_use]
    pub const fn start_budget(self) -> BoundedDuration {
        self.start_budget
    }

    /// Returns the bounded domain drain budget.
    #[must_use]
    pub const fn drain_budget(self) -> BoundedDuration {
        self.drain_budget
    }
}

/// Per-invocation run, cancellation, and native-library thread budgets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ThreadInvocationBudgets {
    max_nonpreemptive_run: BoundedDuration,
    run_budget: BoundedDuration,
    cancellation_grace: BoundedDuration,
    native_thread_reservation: u32,
}

impl ThreadInvocationBudgets {
    /// Validates finite invocation budgets and a bounded native thread reserve.
    pub const fn try_new(
        max_nonpreemptive_run: BoundedDuration,
        run_budget: BoundedDuration,
        cancellation_grace: BoundedDuration,
        native_thread_reservation: u32,
    ) -> Result<Self, ThreadExecutionContractError> {
        if !valid_duration(max_nonpreemptive_run)
            || !valid_duration(run_budget)
            || !valid_duration(cancellation_grace)
        {
            return Err(ThreadExecutionContractError::InvalidExecutionBudget);
        }
        if max_nonpreemptive_run.value() > run_budget.value() {
            return Err(ThreadExecutionContractError::RunBoundExceedsRunBudget);
        }
        if native_thread_reservation > MAX_EXECUTOR_THREADS {
            return Err(ThreadExecutionContractError::InvalidNativeThreadReservation);
        }
        Ok(Self {
            max_nonpreemptive_run,
            run_budget,
            cancellation_grace,
            native_thread_reservation,
        })
    }

    /// Returns the maximum non-preemptive run segment.
    #[must_use]
    pub const fn max_nonpreemptive_run(self) -> BoundedDuration {
        self.max_nonpreemptive_run
    }

    /// Returns the invocation run budget.
    #[must_use]
    pub const fn run_budget(self) -> BoundedDuration {
        self.run_budget
    }

    /// Returns the cooperative cancellation grace budget.
    #[must_use]
    pub const fn cancellation_grace(self) -> BoundedDuration {
        self.cancellation_grace
    }

    /// Returns the process-global native thread reservation for this instance.
    #[must_use]
    pub const fn native_thread_reservation(self) -> u32 {
        self.native_thread_reservation
    }
}

/// Proven synchronous execution properties and per-invocation budgets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ThreadExecutionRequirements {
    call_model: CallModel,
    workload_kind: WorkloadKind,
    blocking_risk: BlockingRisk,
    run_bound_provenance: RunBoundProvenance,
    budgets: ThreadInvocationBudgets,
}

impl ThreadExecutionRequirements {
    /// Records bounded evidence for one synchronous ThreadDomain subject.
    pub const fn try_new(
        call_model: CallModel,
        workload_kind: WorkloadKind,
        blocking_risk: BlockingRisk,
        run_bound_provenance: RunBoundProvenance,
        budgets: ThreadInvocationBudgets,
    ) -> Result<Self, ThreadExecutionContractError> {
        let value = Self {
            call_model,
            workload_kind,
            blocking_risk,
            run_bound_provenance,
            budgets,
        };
        if !value.is_thread_eligible() {
            return Err(ThreadExecutionContractError::UnsupportedThreadExecution);
        }
        Ok(value)
    }

    /// Returns the required call model.
    #[must_use]
    pub const fn call_model(self) -> CallModel {
        self.call_model
    }

    /// Returns the admitted workload kind.
    #[must_use]
    pub const fn workload_kind(self) -> WorkloadKind {
        self.workload_kind
    }

    /// Returns the bounded blocking classification.
    #[must_use]
    pub const fn blocking_risk(self) -> BlockingRisk {
        self.blocking_risk
    }

    /// Returns the evidence class for the run bound.
    #[must_use]
    pub const fn run_bound_provenance(self) -> RunBoundProvenance {
        self.run_bound_provenance
    }

    /// Returns the maximum non-preemptive run segment.
    #[must_use]
    pub const fn max_nonpreemptive_run(self) -> BoundedDuration {
        self.budgets.max_nonpreemptive_run()
    }

    /// Returns the invocation run budget.
    #[must_use]
    pub const fn run_budget(self) -> BoundedDuration {
        self.budgets.run_budget()
    }

    /// Returns the cooperative cancellation grace budget.
    #[must_use]
    pub const fn cancellation_grace(self) -> BoundedDuration {
        self.budgets.cancellation_grace()
    }

    /// Returns the process-global native thread reservation for this instance.
    #[must_use]
    pub const fn native_thread_reservation(self) -> u32 {
        self.budgets.native_thread_reservation()
    }

    const fn is_thread_eligible(self) -> bool {
        matches!(self.call_model, CallModel::Synchronous)
            && matches!(self.workload_kind, WorkloadKind::Io | WorkloadKind::Native)
            && matches!(self.blocking_risk, BlockingRisk::Bounded)
            && matches!(
                self.run_bound_provenance,
                RunBoundProvenance::Measured | RunBoundProvenance::Certified
            )
    }
}

/// Effective non-Control dispatch policy for one ThreadDomain Mailbox.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ThreadDispatchPolicy {
    dispatch_class: DispatchClass,
    service_cost_tokens: u32,
    minimum_service_weight: u32,
    max_burst: u16,
    max_arrivals_per_window: u32,
}

impl ThreadDispatchPolicy {
    /// Validates bounded fairness and arrival scalars.
    pub const fn try_new(
        dispatch_class: DispatchClass,
        service_cost_tokens: u32,
        minimum_service_weight: u32,
        max_burst: u16,
        max_arrivals_per_window: u32,
    ) -> Result<Self, ThreadExecutionContractError> {
        if matches!(dispatch_class, DispatchClass::Control) {
            return Err(ThreadExecutionContractError::ControlDispatchForbidden);
        }
        if service_cost_tokens == 0 || service_cost_tokens > MAX_SERVICE_COST_TOKENS {
            return Err(ThreadExecutionContractError::InvalidServiceCost);
        }
        if minimum_service_weight == 0 || minimum_service_weight > MAX_MINIMUM_SERVICE_WEIGHT {
            return Err(ThreadExecutionContractError::InvalidMinimumServiceWeight);
        }
        if max_burst == 0 {
            return Err(ThreadExecutionContractError::InvalidMaxBurst);
        }
        if max_arrivals_per_window == 0 || max_arrivals_per_window > MAX_ARRIVALS_PER_WINDOW {
            return Err(ThreadExecutionContractError::InvalidArrivalBound);
        }
        Ok(Self {
            dispatch_class,
            service_cost_tokens,
            minimum_service_weight,
            max_burst,
            max_arrivals_per_window,
        })
    }

    /// Returns the effective dispatch class.
    #[must_use]
    pub const fn dispatch_class(self) -> DispatchClass {
        self.dispatch_class
    }

    /// Returns the scheduler cost token.
    #[must_use]
    pub const fn service_cost_tokens(self) -> u32 {
        self.service_cost_tokens
    }

    /// Returns the minimum-service weight.
    #[must_use]
    pub const fn minimum_service_weight(self) -> u32 {
        self.minimum_service_weight
    }

    /// Returns the bounded dispatch burst.
    #[must_use]
    pub const fn max_burst(self) -> u16 {
        self.max_burst
    }

    /// Returns the bounded arrivals per domain capacity window.
    #[must_use]
    pub const fn max_arrivals_per_window(self) -> u32 {
        self.max_arrivals_per_window
    }
}

/// One exact Mailbox-to-ThreadDomain execution assignment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ThreadMailboxExecutionSpec {
    binding_id: BindingId,
    mailbox: MailboxRef,
    target_instance: InstanceRef,
    domain: ThreadDomainRef,
    subject: CardSubjectSpec,
    requirements: ThreadExecutionRequirements,
    dispatch: ThreadDispatchPolicy,
}

impl ThreadMailboxExecutionSpec {
    /// Combines already validated subject, requirements, and dispatch values.
    #[must_use]
    pub const fn new(
        binding_id: BindingId,
        mailbox: MailboxRef,
        target_instance: InstanceRef,
        domain: ThreadDomainRef,
        subject: CardSubjectSpec,
        requirements: ThreadExecutionRequirements,
        dispatch: ThreadDispatchPolicy,
    ) -> Self {
        Self {
            binding_id,
            mailbox,
            target_instance,
            domain,
            subject,
            requirements,
            dispatch,
        }
    }

    /// Returns the exact PXTA BindingId.
    #[must_use]
    pub const fn binding_id(self) -> BindingId {
        self.binding_id
    }

    /// Returns the exact PXTA Mailbox reference.
    #[must_use]
    pub const fn mailbox(self) -> MailboxRef {
        self.mailbox
    }

    /// Returns the exact PXTA target instance.
    #[must_use]
    pub const fn target_instance(self) -> InstanceRef {
        self.target_instance
    }

    /// Returns the desired ThreadDomain reference.
    #[must_use]
    pub const fn domain(self) -> ThreadDomainRef {
        self.domain
    }

    /// Returns the immutable Card subject.
    #[must_use]
    pub const fn subject(self) -> CardSubjectSpec {
        self.subject
    }

    /// Returns the synchronous execution requirements.
    #[must_use]
    pub const fn requirements(self) -> ThreadExecutionRequirements {
        self.requirements
    }

    /// Returns the effective Thread dispatch policy.
    #[must_use]
    pub const fn dispatch(self) -> ThreadDispatchPolicy {
        self.dispatch
    }

    /// Returns the declared per-window arrival bound.
    #[must_use]
    pub const fn max_arrivals_per_window(self) -> u32 {
        self.dispatch.max_arrivals_per_window()
    }

    fn same_subject_contract(self, other: Self) -> bool {
        self.target_instance == other.target_instance
            && self.domain == other.domain
            && self.subject == other.subject
            && self.requirements == other.requirements
    }
}

/// Canonically ordered PXTE v2 Loop and Thread desired execution records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetExecutionPlanV2 {
    loop_plan: Option<TargetExecutionPlan>,
    executor_budget: ExecutorBudgetSpec,
    thread_domains: Box<[ThreadDomainSpec]>,
    thread_mailboxes: Box<[ThreadMailboxExecutionSpec]>,
    canonical_wire: Box<[u8]>,
    execution_digest: TargetExecutionDigestV2,
}

impl TargetExecutionPlanV2 {
    /// Sorts, validates, bounds, and commits the additive execution body.
    pub fn try_new(
        loop_plan: Option<TargetExecutionPlan>,
        executor_budget: ExecutorBudgetSpec,
        mut thread_domains: Vec<ThreadDomainSpec>,
        mut thread_mailboxes: Vec<ThreadMailboxExecutionSpec>,
    ) -> Result<Self, ThreadExecutionContractError> {
        if thread_domains.is_empty() {
            return Err(ThreadExecutionContractError::MissingThreadDomain);
        }
        if thread_mailboxes.is_empty() {
            return Err(ThreadExecutionContractError::MissingThreadMailboxExecution);
        }
        if thread_domains.len() > MAX_THREAD_DOMAINS {
            return Err(ThreadExecutionContractError::DomainCountExceeded);
        }
        if thread_mailboxes.len() > MAX_THREAD_MAILBOX_EXECUTIONS {
            return Err(ThreadExecutionContractError::ExecutionCountExceeded);
        }
        if let Some(plan) = &loop_plan {
            plan.validate()
                .map_err(ThreadExecutionContractError::LoopExecution)?;
        }
        thread_domains.sort_by_key(|domain| domain.domain());
        thread_mailboxes.sort_by_key(|execution| {
            (
                execution.binding_id(),
                execution.mailbox(),
                execution.target_instance(),
                execution.domain(),
            )
        });
        validate_thread_execution_records(
            loop_plan.as_ref(),
            executor_budget,
            &thread_domains,
            &thread_mailboxes,
        )?;
        let canonical_wire = build_target_execution_v2_wire(
            loop_plan.as_ref(),
            executor_budget,
            &thread_domains,
            &thread_mailboxes,
        );
        let execution_digest = digest_target_execution_v2(&canonical_wire)?;
        Ok(Self {
            loop_plan,
            executor_budget,
            thread_domains: thread_domains.into_boxed_slice(),
            thread_mailboxes: thread_mailboxes.into_boxed_slice(),
            canonical_wire: canonical_wire.into_boxed_slice(),
            execution_digest,
        })
    }

    /// Strictly decodes one canonical PXTE v2 body.
    pub fn decode(frame: &[u8]) -> Result<Self, ThreadExecutionWireError> {
        decode_target_execution_v2(frame)
    }

    /// Returns the embedded unchanged PXTE v1 Loop plan, when present.
    #[must_use]
    pub const fn loop_plan(&self) -> Option<&TargetExecutionPlan> {
        self.loop_plan.as_ref()
    }

    /// Returns the process-wide executor budget.
    #[must_use]
    pub const fn executor_budget(&self) -> ExecutorBudgetSpec {
        self.executor_budget
    }

    /// Returns canonically ordered ThreadDomain records.
    #[must_use]
    pub fn thread_domains(&self) -> &[ThreadDomainSpec] {
        &self.thread_domains
    }

    /// Returns canonically ordered Thread Mailbox records.
    #[must_use]
    pub fn thread_mailbox_executions(&self) -> &[ThreadMailboxExecutionSpec] {
        &self.thread_mailboxes
    }

    /// Returns exact canonical PXTE v2 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Returns the PXTE v2 execution digest.
    #[must_use]
    pub const fn execution_digest(&self) -> TargetExecutionDigestV2 {
        self.execution_digest
    }

    /// Revalidates semantic records, canonical bytes, and digest.
    pub fn validate(&self) -> Result<(), ThreadExecutionContractError> {
        let rebuilt = Self::try_new(
            self.loop_plan.clone(),
            self.executor_budget,
            self.thread_domains.to_vec(),
            self.thread_mailboxes.to_vec(),
        )?;
        if rebuilt.loop_plan != self.loop_plan
            || rebuilt.thread_domains != self.thread_domains
            || rebuilt.thread_mailboxes != self.thread_mailboxes
            || rebuilt.canonical_wire != self.canonical_wire
        {
            return Err(ThreadExecutionContractError::CanonicalWireMismatch);
        }
        if rebuilt.execution_digest != self.execution_digest {
            return Err(ThreadExecutionContractError::ExecutionDigestMismatch);
        }
        Ok(())
    }
}

/// Complete PXTA bindings and their additive PXTE v2 execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetPlanAssignmentsV3 {
    bindings: TargetAssignments,
    execution: TargetExecutionPlanV2,
    assignment_digest: TargetAssignmentDigest,
}

impl TargetPlanAssignmentsV3 {
    /// Validates every Loop and Thread execution reference against exact PXTA records.
    pub fn try_new(
        bindings: TargetAssignments,
        execution: TargetExecutionPlanV2,
    ) -> Result<Self, TargetPlanV3ContractError> {
        bindings.validate()?;
        execution.validate()?;
        validate_target_plan_v3_references(&bindings, &execution)?;
        let assignment_digest = digest_target_plan_assignments_v3(&bindings, &execution)?;
        Ok(Self {
            bindings,
            execution,
            assignment_digest,
        })
    }

    /// Returns the complete PXTA body.
    #[must_use]
    pub const fn bindings(&self) -> &TargetAssignments {
        &self.bindings
    }

    /// Returns the complete PXTE v2 body.
    #[must_use]
    pub const fn execution(&self) -> &TargetExecutionPlanV2 {
        &self.execution
    }

    /// Returns the v3 composite assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.assignment_digest
    }

    /// Revalidates both bodies, exact references, and composite digest.
    pub fn validate(&self) -> Result<(), TargetPlanV3ContractError> {
        self.bindings.validate()?;
        self.execution.validate()?;
        validate_target_plan_v3_references(&self.bindings, &self.execution)?;
        if digest_target_plan_assignments_v3(&self.bindings, &self.execution)?
            != self.assignment_digest
        {
            return Err(TargetPlanV3ContractError::CompositeDigestMismatch);
        }
        Ok(())
    }
}

/// Complete v3 target Slice with one signed commitment and both canonical bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePlanSliceV3 {
    commitment: RuntimeSliceCommitment,
    assignments: TargetPlanAssignmentsV3,
}

impl RuntimePlanSliceV3 {
    /// Binds the v3 composite assignment digest to the existing Slice field.
    pub fn try_new(
        commitment: RuntimeSliceCommitment,
        assignments: TargetPlanAssignmentsV3,
    ) -> Result<Self, TargetPlanV3ContractError> {
        commitment.validate()?;
        assignments.validate()?;
        if commitment.header().assignment_digest() != assignments.assignment_digest() {
            return Err(TargetPlanV3ContractError::SliceAssignmentDigestMismatch);
        }
        Ok(Self {
            commitment,
            assignments,
        })
    }

    /// Returns the target Slice commitment.
    #[must_use]
    pub const fn commitment(&self) -> RuntimeSliceCommitment {
        self.commitment
    }

    /// Returns the v3 target assignments.
    #[must_use]
    pub const fn assignments(&self) -> &TargetPlanAssignmentsV3 {
        &self.assignments
    }

    /// Revalidates commitment and assignment equality.
    pub fn validate(&self) -> Result<(), TargetPlanV3ContractError> {
        self.commitment.validate()?;
        self.assignments.validate()?;
        if self.commitment.header().assignment_digest() != self.assignments.assignment_digest() {
            return Err(TargetPlanV3ContractError::SliceAssignmentDigestMismatch);
        }
        Ok(())
    }
}

/// PXAR v3 request carrying an unchanged signed envelope, PXTA, and PXTE v2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyRequestV3 {
    envelope: RuntimeApplyEnvelope,
    slice: RuntimePlanSliceV3,
    canonical_wire: Box<[u8]>,
}

impl RuntimeApplyRequestV3 {
    /// Builds a strict v3 outer request without changing the envelope format.
    pub fn try_new(
        envelope: RuntimeApplyEnvelope,
        slice: RuntimePlanSliceV3,
    ) -> Result<Self, TargetPlanV3ContractError> {
        envelope.validate()?;
        slice.validate()?;
        if envelope.control_commitment().slice() != slice.commitment() {
            return Err(TargetPlanV3ContractError::EnvelopeSliceMismatch);
        }
        let canonical_wire = build_runtime_apply_request_v3_wire(&envelope, &slice);
        if canonical_wire.len() > MAX_RUNTIME_APPLY_REQUEST_V3_BYTES {
            return Err(TargetPlanV3ContractError::RequestFrameTooLarge);
        }
        Ok(Self {
            envelope,
            slice,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes PXAR v3 without version fallback.
    pub fn decode(frame: &[u8]) -> Result<Self, RequestV3WireError> {
        decode_runtime_apply_request_v3(frame)
    }

    /// Returns the unchanged signed envelope.
    #[must_use]
    pub const fn envelope(&self) -> &RuntimeApplyEnvelope {
        &self.envelope
    }

    /// Returns the committed v3 target Slice.
    #[must_use]
    pub const fn slice(&self) -> &RuntimePlanSliceV3 {
        &self.slice
    }

    /// Returns the existing signed-envelope digest.
    #[must_use]
    pub const fn request_digest(&self) -> &Digest32 {
        self.envelope.request_digest()
    }

    /// Returns exact PXAR v3 canonical bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Revalidates both components and the outer canonical bytes.
    pub fn validate(&self) -> Result<(), TargetPlanV3ContractError> {
        self.envelope.validate()?;
        self.slice.validate()?;
        if self.envelope.control_commitment().slice() != self.slice.commitment() {
            return Err(TargetPlanV3ContractError::EnvelopeSliceMismatch);
        }
        if build_runtime_apply_request_v3_wire(&self.envelope, &self.slice)
            != self.canonical_wire.as_ref()
        {
            return Err(TargetPlanV3ContractError::RequestCanonicalWireMismatch);
        }
        Ok(())
    }
}

const fn valid_duration(value: BoundedDuration) -> bool {
    value.value() > 0 && value.value() <= MAX_EXECUTION_DURATION_NANOS
}

fn validate_thread_execution_records(
    loop_plan: Option<&TargetExecutionPlan>,
    executor_budget: ExecutorBudgetSpec,
    domains: &[ThreadDomainSpec],
    mailboxes: &[ThreadMailboxExecutionSpec],
) -> Result<(), ThreadExecutionContractError> {
    for (index, domain) in domains.iter().enumerate() {
        if domains
            .iter()
            .take(index)
            .any(|previous| previous.domain() == domain.domain())
        {
            return Err(ThreadExecutionContractError::DuplicateDomainRef);
        }
    }
    for (index, execution) in mailboxes.iter().enumerate() {
        for previous in mailboxes.iter().take(index) {
            if previous.binding_id() == execution.binding_id() {
                return Err(ThreadExecutionContractError::DuplicateExecutionBinding);
            }
            if previous.mailbox() == execution.mailbox() {
                return Err(ThreadExecutionContractError::DuplicateExecutionMailbox);
            }
            if previous.target_instance() == execution.target_instance()
                && !previous.same_subject_contract(*execution)
            {
                return Err(ThreadExecutionContractError::ThreadSubjectMismatch);
            }
        }
        if !domains
            .iter()
            .any(|domain| domain.domain() == execution.domain())
        {
            return Err(ThreadExecutionContractError::OrphanDomainRef);
        }
    }
    for domain in domains {
        if !mailboxes
            .iter()
            .any(|execution| execution.domain() == domain.domain())
        {
            return Err(ThreadExecutionContractError::UnusedDomainRef);
        }
        validate_thread_domain_utilization(*domain, mailboxes)?;
    }
    if let Some(loop_plan) = loop_plan {
        validate_loop_thread_separation(loop_plan, domains, mailboxes)?;
    }
    validate_executor_budget(executor_budget, domains, mailboxes)
}

fn validate_thread_domain_utilization(
    domain: ThreadDomainSpec,
    mailboxes: &[ThreadMailboxExecutionSpec],
) -> Result<(), ThreadExecutionContractError> {
    let mut demand = 0_u128;
    for execution in mailboxes
        .iter()
        .filter(|execution| execution.domain() == domain.domain())
    {
        let occupancy = u128::from(execution.requirements().run_budget().value())
            .checked_add(u128::from(
                execution.requirements().cancellation_grace().value(),
            ))
            .ok_or(ThreadExecutionContractError::UtilizationOverflow)?;
        let mailbox_demand = u128::from(execution.max_arrivals_per_window())
            .checked_mul(occupancy)
            .ok_or(ThreadExecutionContractError::UtilizationOverflow)?;
        demand = demand
            .checked_add(mailbox_demand)
            .ok_or(ThreadExecutionContractError::UtilizationOverflow)?;
    }
    let capacity = u128::from(domain.worker_count())
        .checked_mul(u128::from(domain.capacity_window().value()))
        .ok_or(ThreadExecutionContractError::UtilizationOverflow)?;
    if demand > capacity {
        return Err(ThreadExecutionContractError::ThreadUtilizationExceeded);
    }
    Ok(())
}

fn validate_executor_budget(
    budget: ExecutorBudgetSpec,
    domains: &[ThreadDomainSpec],
    mailboxes: &[ThreadMailboxExecutionSpec],
) -> Result<(), ThreadExecutionContractError> {
    let mut total = u128::from(budget.framework_threads());
    for domain in domains {
        total = total
            .checked_add(u128::from(domain.worker_count()))
            .ok_or(ThreadExecutionContractError::ExecutorBudgetExceeded)?;
    }
    for (index, execution) in mailboxes.iter().enumerate() {
        if !mailboxes
            .iter()
            .take(index)
            .any(|previous| previous.target_instance() == execution.target_instance())
        {
            total = total
                .checked_add(u128::from(
                    execution.requirements().native_thread_reservation(),
                ))
                .ok_or(ThreadExecutionContractError::ExecutorBudgetExceeded)?;
        }
    }
    if total > u128::from(budget.max_total_threads()) {
        return Err(ThreadExecutionContractError::ExecutorBudgetExceeded);
    }
    Ok(())
}

fn validate_loop_thread_separation(
    loop_plan: &TargetExecutionPlan,
    thread_domains: &[ThreadDomainSpec],
    thread_mailboxes: &[ThreadMailboxExecutionSpec],
) -> Result<(), ThreadExecutionContractError> {
    for loop_domain in loop_plan.domains() {
        if thread_domains.iter().any(|thread_domain| {
            loop_domain.domain().as_bytes() == thread_domain.domain().as_bytes()
        }) {
            return Err(ThreadExecutionContractError::CrossLoopThreadDomain);
        }
    }
    for loop_execution in loop_plan.mailbox_executions() {
        for thread_execution in thread_mailboxes {
            if loop_execution.binding_id() == thread_execution.binding_id() {
                return Err(ThreadExecutionContractError::CrossLoopThreadBinding);
            }
            if loop_execution.mailbox() == thread_execution.mailbox() {
                return Err(ThreadExecutionContractError::CrossLoopThreadMailbox);
            }
            if loop_execution.target_instance() == thread_execution.target_instance() {
                return Err(ThreadExecutionContractError::CrossLoopThreadInstance);
            }
        }
    }
    Ok(())
}

fn validate_target_plan_v3_references(
    bindings: &TargetAssignments,
    execution: &TargetExecutionPlanV2,
) -> Result<(), TargetPlanV3ContractError> {
    if bindings.as_slice().iter().any(|binding| {
        binding.delivery().overflow_policy() == OverflowPolicy::BlockUntilDeadline
            || binding.mailbox_spec().overflow_policy() == OverflowPolicy::BlockUntilDeadline
    }) {
        return Err(TargetPlanV3ContractError::BlockUntilDeadlineForbidden);
    }
    if let Some(loop_plan) = execution.loop_plan() {
        TargetPlanAssignments::try_new(bindings.clone(), loop_plan.clone())
            .map_err(TargetPlanV3ContractError::LoopTargetPlan)?;
    }
    for mailbox in execution.thread_mailbox_executions() {
        let Some(binding) = bindings
            .as_slice()
            .iter()
            .find(|binding| binding.binding_id() == mailbox.binding_id())
        else {
            return Err(TargetPlanV3ContractError::OrphanBinding);
        };
        if binding.mailbox() != mailbox.mailbox() {
            return Err(TargetPlanV3ContractError::BindingMailboxMismatch);
        }
        if binding.target_instance() != mailbox.target_instance() {
            return Err(TargetPlanV3ContractError::BindingTargetMismatch);
        }
    }
    Ok(())
}

fn digest_target_execution_v2(
    canonical_wire: &[u8],
) -> Result<TargetExecutionDigestV2, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TARGET_EXECUTION_V2_DIGEST_DOMAIN)?;
    builder.field_bytes(canonical_wire)?;
    Ok(TargetExecutionDigestV2::new(builder.finish()))
}

fn digest_target_plan_assignments_v3(
    bindings: &TargetAssignments,
    execution: &TargetExecutionPlanV2,
) -> Result<TargetAssignmentDigest, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TARGET_PLAN_ASSIGNMENTS_V3_DIGEST_DOMAIN)?;
    builder.field_bytes(bindings.assignment_digest().value().as_bytes())?;
    builder.field_bytes(execution.execution_digest().value().as_bytes())?;
    Ok(TargetAssignmentDigest::new(builder.finish()))
}

fn build_target_execution_v2_wire(
    loop_plan: Option<&TargetExecutionPlan>,
    executor_budget: ExecutorBudgetSpec,
    domains: &[ThreadDomainSpec],
    mailboxes: &[ThreadMailboxExecutionSpec],
) -> Vec<u8> {
    let loop_wire = loop_plan.map_or(&[][..], TargetExecutionPlan::canonical_wire);
    let mut encoded = Vec::with_capacity(
        TARGET_EXECUTION_V2_HEADER_BYTES
            + loop_wire.len()
            + domains.len() * THREAD_DOMAIN_RECORD_BYTES
            + mailboxes.len() * THREAD_MAILBOX_EXECUTION_RECORD_BYTES,
    );
    encoded.extend_from_slice(TARGET_EXECUTION_MAGIC);
    encoded.extend_from_slice(&TARGET_EXECUTION_PLAN_V2_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(loop_wire.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(domains.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(mailboxes.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&executor_budget.max_total_threads().to_be_bytes());
    encoded.extend_from_slice(&executor_budget.framework_threads().to_be_bytes());
    encoded.extend_from_slice(loop_wire);
    for domain in domains {
        append_thread_domain_record(&mut encoded, *domain);
    }
    for mailbox in mailboxes {
        append_thread_mailbox_record(&mut encoded, *mailbox);
    }
    encoded
}

fn append_thread_domain_record(encoded: &mut Vec<u8>, domain: ThreadDomainSpec) {
    encoded.extend_from_slice(domain.domain().as_bytes());
    encoded.extend_from_slice(&domain.worker_count().to_be_bytes());
    encoded.extend_from_slice(&domain.capacity_window().value().to_be_bytes());
    encoded.extend_from_slice(&domain.start_budget().value().to_be_bytes());
    encoded.extend_from_slice(&domain.drain_budget().value().to_be_bytes());
}

fn append_thread_mailbox_record(encoded: &mut Vec<u8>, execution: ThreadMailboxExecutionSpec) {
    encoded.extend_from_slice(execution.binding_id().as_bytes());
    encoded.extend_from_slice(execution.mailbox().as_bytes());
    encoded.extend_from_slice(execution.target_instance().as_bytes());
    encoded.extend_from_slice(execution.domain().as_bytes());
    let subject = execution.subject();
    encoded.extend_from_slice(subject.card_definition().as_bytes());
    encoded.extend_from_slice(subject.card_implementation().as_bytes());
    encoded.extend_from_slice(subject.definition_digest().as_bytes());
    encoded.extend_from_slice(subject.artifact_digest().as_bytes());
    encoded.extend_from_slice(subject.config_digest().as_bytes());
    let requirements = execution.requirements();
    encoded.push(requirements.call_model() as u8);
    encoded.push(requirements.workload_kind() as u8);
    encoded.push(requirements.blocking_risk() as u8);
    encoded.push(requirements.run_bound_provenance() as u8);
    let dispatch = execution.dispatch();
    encoded.push(dispatch.dispatch_class() as u8);
    encoded.extend_from_slice(&dispatch.service_cost_tokens().to_be_bytes());
    encoded.extend_from_slice(&dispatch.minimum_service_weight().to_be_bytes());
    encoded.extend_from_slice(&dispatch.max_burst().to_be_bytes());
    encoded.extend_from_slice(&dispatch.max_arrivals_per_window().to_be_bytes());
    encoded.extend_from_slice(&requirements.max_nonpreemptive_run().value().to_be_bytes());
    encoded.extend_from_slice(&requirements.run_budget().value().to_be_bytes());
    encoded.extend_from_slice(&requirements.cancellation_grace().value().to_be_bytes());
    encoded.extend_from_slice(&requirements.native_thread_reservation().to_be_bytes());
}

fn build_runtime_apply_request_v3_wire(
    envelope: &RuntimeApplyEnvelope,
    slice: &RuntimePlanSliceV3,
) -> Vec<u8> {
    let bindings = slice.assignments().bindings().canonical_wire();
    let execution = slice.assignments().execution().canonical_wire();
    let mut encoded = Vec::with_capacity(
        APPLY_REQUEST_V3_HEADER_BYTES
            + envelope.canonical_wire().len()
            + bindings.len()
            + execution.len(),
    );
    encoded.extend_from_slice(RUNTIME_APPLY_REQUEST_MAGIC);
    encoded.extend_from_slice(&RUNTIME_APPLY_REQUEST_V3_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(envelope.canonical_wire().len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(bindings.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(execution.len() as u32).to_be_bytes());
    encoded.extend_from_slice(envelope.canonical_wire());
    encoded.extend_from_slice(bindings);
    encoded.extend_from_slice(execution);
    encoded
}

fn decode_target_execution_v2(
    frame: &[u8],
) -> Result<TargetExecutionPlanV2, ThreadExecutionWireError> {
    if frame.len() > MAX_TARGET_EXECUTION_PLAN_V2_BYTES {
        return Err(ThreadExecutionWireError::new(
            ThreadExecutionWireErrorCode::FrameTooLarge,
        ));
    }
    if frame.len() < TARGET_EXECUTION_V2_HEADER_BYTES {
        return Err(ThreadExecutionWireError::new(
            ThreadExecutionWireErrorCode::Truncated,
        ));
    }
    if &frame[..4] != TARGET_EXECUTION_MAGIC {
        return Err(ThreadExecutionWireError::new(
            ThreadExecutionWireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != TARGET_EXECUTION_PLAN_V2_VERSION {
        return Err(ThreadExecutionWireError::new(
            ThreadExecutionWireErrorCode::UnsupportedVersion,
        ));
    }
    let loop_length = read_u32(&frame[6..10]) as usize;
    let domain_count = read_u32(&frame[10..14]) as usize;
    let execution_count = read_u32(&frame[14..18]) as usize;
    if loop_length > MAX_TARGET_EXECUTION_PLAN_BYTES {
        return Err(ThreadExecutionWireError::new(
            ThreadExecutionWireErrorCode::LoopBodyTooLarge,
        ));
    }
    if domain_count > MAX_THREAD_DOMAINS {
        return Err(ThreadExecutionWireError::new(
            ThreadExecutionWireErrorCode::DomainCountExceeded,
        ));
    }
    if execution_count > MAX_THREAD_MAILBOX_EXECUTIONS {
        return Err(ThreadExecutionWireError::new(
            ThreadExecutionWireErrorCode::ExecutionCountExceeded,
        ));
    }
    let domain_bytes = domain_count
        .checked_mul(THREAD_DOMAIN_RECORD_BYTES)
        .ok_or_else(|| {
            ThreadExecutionWireError::new(ThreadExecutionWireErrorCode::InvalidFrameLength)
        })?;
    let execution_bytes = execution_count
        .checked_mul(THREAD_MAILBOX_EXECUTION_RECORD_BYTES)
        .ok_or_else(|| {
            ThreadExecutionWireError::new(ThreadExecutionWireErrorCode::InvalidFrameLength)
        })?;
    let expected_length = TARGET_EXECUTION_V2_HEADER_BYTES
        .checked_add(loop_length)
        .and_then(|length| length.checked_add(domain_bytes))
        .and_then(|length| length.checked_add(execution_bytes))
        .ok_or_else(|| {
            ThreadExecutionWireError::new(ThreadExecutionWireErrorCode::InvalidFrameLength)
        })?;
    if frame.len() < expected_length {
        return Err(ThreadExecutionWireError::new(
            ThreadExecutionWireErrorCode::Truncated,
        ));
    }
    if frame.len() != expected_length {
        return Err(ThreadExecutionWireError::new(
            ThreadExecutionWireErrorCode::InvalidFrameLength,
        ));
    }
    let executor_budget =
        ExecutorBudgetSpec::try_new(read_u32(&frame[18..22]), read_u32(&frame[22..26])).map_err(
            |_| ThreadExecutionWireError::new(ThreadExecutionWireErrorCode::InvalidExecutorBudget),
        )?;
    let loop_start = TARGET_EXECUTION_V2_HEADER_BYTES;
    let loop_end = loop_start + loop_length;
    let domains_end = loop_end + domain_bytes;
    let loop_plan = if loop_length == 0 {
        None
    } else {
        Some(
            TargetExecutionPlan::decode(&frame[loop_start..loop_end])
                .map_err(thread_loop_wire_error)?,
        )
    };
    let mut domains = Vec::with_capacity(domain_count);
    for (index, record) in frame[loop_end..domains_end]
        .chunks_exact(THREAD_DOMAIN_RECORD_BYTES)
        .enumerate()
    {
        domains.push(decode_thread_domain_record(record, index as u32)?);
    }
    let mut mailboxes = Vec::with_capacity(execution_count);
    for (index, record) in frame[domains_end..]
        .chunks_exact(THREAD_MAILBOX_EXECUTION_RECORD_BYTES)
        .enumerate()
    {
        mailboxes.push(decode_thread_mailbox_record(record, index as u32)?);
    }
    let decoded = TargetExecutionPlanV2::try_new(loop_plan, executor_budget, domains, mailboxes)
        .map_err(thread_contract_wire_error)?;
    if decoded.canonical_wire() != frame {
        return Err(ThreadExecutionWireError::new(
            ThreadExecutionWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn decode_thread_domain_record(
    record: &[u8],
    record_index: u32,
) -> Result<ThreadDomainSpec, ThreadExecutionWireError> {
    let mut cursor = RecordCursor::new(record);
    ThreadDomainSpec::try_new(
        ThreadDomainRef::from_bytes(cursor.array()),
        cursor.u32(),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
    )
    .map_err(|_| {
        ThreadExecutionWireError::at(
            ThreadExecutionWireErrorCode::InvalidThreadDomain,
            ThreadExecutionRecordSection::ThreadDomain,
            record_index,
        )
    })
}

fn decode_thread_mailbox_record(
    record: &[u8],
    record_index: u32,
) -> Result<ThreadMailboxExecutionSpec, ThreadExecutionWireError> {
    let mut cursor = RecordCursor::new(record);
    let binding_id = BindingId::from_bytes(cursor.array());
    let mailbox = MailboxRef::from_bytes(cursor.array());
    let target_instance = InstanceRef::from_bytes(cursor.array());
    let domain = ThreadDomainRef::from_bytes(cursor.array());
    let subject = CardSubjectSpec::new(
        crate::execution::CardDefinitionRef::from_bytes(cursor.array()),
        crate::execution::CardImplementationRef::from_bytes(cursor.array()),
        Digest32::from_bytes(cursor.array()),
        Digest32::from_bytes(cursor.array()),
        Digest32::from_bytes(cursor.array()),
    );
    let call_model = decode_thread_call_model(cursor.u8(), record_index)?;
    let workload_kind = decode_thread_workload_kind(cursor.u8(), record_index)?;
    let blocking_risk = decode_thread_blocking_risk(cursor.u8(), record_index)?;
    let run_bound_provenance = decode_thread_run_bound_provenance(cursor.u8(), record_index)?;
    let dispatch_class = decode_thread_dispatch_class(cursor.u8(), record_index)?;
    let service_cost_tokens = cursor.u32();
    let minimum_service_weight = cursor.u32();
    let max_burst = cursor.u16();
    let max_arrivals_per_window = cursor.u32();
    let budgets = ThreadInvocationBudgets::try_new(
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        cursor.u32(),
    );
    let requirements = budgets.and_then(|budgets| {
        ThreadExecutionRequirements::try_new(
            call_model,
            workload_kind,
            blocking_risk,
            run_bound_provenance,
            budgets,
        )
    });
    let dispatch = ThreadDispatchPolicy::try_new(
        dispatch_class,
        service_cost_tokens,
        minimum_service_weight,
        max_burst,
        max_arrivals_per_window,
    );
    match (requirements, dispatch) {
        (Ok(requirements), Ok(dispatch)) => Ok(ThreadMailboxExecutionSpec::new(
            binding_id,
            mailbox,
            target_instance,
            domain,
            subject,
            requirements,
            dispatch,
        )),
        (Err(ThreadExecutionContractError::UnsupportedThreadExecution), _) => {
            Err(ThreadExecutionWireError::at(
                ThreadExecutionWireErrorCode::UnsupportedThreadExecution,
                ThreadExecutionRecordSection::ThreadMailbox,
                record_index,
            ))
        }
        (_, Err(ThreadExecutionContractError::ControlDispatchForbidden)) => {
            Err(ThreadExecutionWireError::at(
                ThreadExecutionWireErrorCode::ControlDispatchForbidden,
                ThreadExecutionRecordSection::ThreadMailbox,
                record_index,
            ))
        }
        _ => Err(ThreadExecutionWireError::at(
            ThreadExecutionWireErrorCode::InvalidThreadExecution,
            ThreadExecutionRecordSection::ThreadMailbox,
            record_index,
        )),
    }
}

macro_rules! decode_thread_enum {
    ($name:ident, $type:ty, {$($value:literal => $variant:path),+ $(,)?}) => {
        fn $name(value: u8, record_index: u32) -> Result<$type, ThreadExecutionWireError> {
            match value {
                $($value => Ok($variant),)+
                _ => Err(ThreadExecutionWireError::at(
                    ThreadExecutionWireErrorCode::InvalidEnumValue,
                    ThreadExecutionRecordSection::ThreadMailbox,
                    record_index,
                )),
            }
        }
    };
}

decode_thread_enum!(decode_thread_call_model, CallModel, {
    1 => CallModel::CooperativeAsync,
    2 => CallModel::Synchronous,
    3 => CallModel::Unknown,
});
decode_thread_enum!(decode_thread_workload_kind, WorkloadKind, {
    1 => WorkloadKind::Io,
    2 => WorkloadKind::Routing,
    3 => WorkloadKind::Cpu,
    4 => WorkloadKind::Native,
    5 => WorkloadKind::Device,
    6 => WorkloadKind::Unknown,
});
decode_thread_enum!(decode_thread_blocking_risk, BlockingRisk, {
    1 => BlockingRisk::None,
    2 => BlockingRisk::Bounded,
    3 => BlockingRisk::Unknown,
});
decode_thread_enum!(decode_thread_run_bound_provenance, RunBoundProvenance, {
    1 => RunBoundProvenance::Declared,
    2 => RunBoundProvenance::Measured,
    3 => RunBoundProvenance::Certified,
    4 => RunBoundProvenance::Unknown,
});
decode_thread_enum!(decode_thread_dispatch_class, DispatchClass, {
    1 => DispatchClass::Control,
    2 => DispatchClass::Interactive,
    3 => DispatchClass::Stream,
    4 => DispatchClass::Background,
});

fn decode_runtime_apply_request_v3(
    frame: &[u8],
) -> Result<RuntimeApplyRequestV3, RequestV3WireError> {
    if frame.len() > MAX_RUNTIME_APPLY_REQUEST_V3_BYTES {
        return Err(RequestV3WireError::new(
            RequestV3WireErrorCode::FrameTooLarge,
        ));
    }
    if frame.len() < APPLY_REQUEST_V3_HEADER_BYTES {
        return Err(RequestV3WireError::new(RequestV3WireErrorCode::Truncated));
    }
    if &frame[..4] != RUNTIME_APPLY_REQUEST_MAGIC {
        return Err(RequestV3WireError::new(
            RequestV3WireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != RUNTIME_APPLY_REQUEST_V3_VERSION {
        return Err(RequestV3WireError::new(
            RequestV3WireErrorCode::UnsupportedVersion,
        ));
    }
    let envelope_length = read_u32(&frame[6..10]) as usize;
    let bindings_length = read_u32(&frame[10..14]) as usize;
    let execution_length = read_u32(&frame[14..18]) as usize;
    let expected_length = APPLY_REQUEST_V3_HEADER_BYTES
        .checked_add(envelope_length)
        .and_then(|length| length.checked_add(bindings_length))
        .and_then(|length| length.checked_add(execution_length))
        .ok_or_else(|| RequestV3WireError::new(RequestV3WireErrorCode::InvalidFrameLength))?;
    if frame.len() < expected_length {
        return Err(RequestV3WireError::new(RequestV3WireErrorCode::Truncated));
    }
    if frame.len() != expected_length {
        return Err(RequestV3WireError::new(
            RequestV3WireErrorCode::InvalidFrameLength,
        ));
    }
    let envelope_start = APPLY_REQUEST_V3_HEADER_BYTES;
    let envelope_end = envelope_start + envelope_length;
    let bindings_end = envelope_end + bindings_length;
    let envelope = RuntimeApplyEnvelope::decode(&frame[envelope_start..envelope_end])
        .map_err(request_v3_envelope_wire_error)?;
    let bindings = TargetAssignments::decode(&frame[envelope_end..bindings_end])
        .map_err(request_v3_bindings_wire_error)?;
    let execution = TargetExecutionPlanV2::decode(&frame[bindings_end..])
        .map_err(request_v3_execution_wire_error)?;
    let assignments = TargetPlanAssignmentsV3::try_new(bindings, execution)
        .map_err(request_v3_target_plan_error)?;
    let slice = RuntimePlanSliceV3::try_new(envelope.control_commitment().slice(), assignments)
        .map_err(|_| RequestV3WireError::new(RequestV3WireErrorCode::CommitmentMismatch))?;
    RuntimeApplyRequestV3::try_new(envelope, slice)
        .map_err(|_| RequestV3WireError::new(RequestV3WireErrorCode::CommitmentMismatch))
}

fn request_v3_envelope_wire_error(error: WireError) -> RequestV3WireError {
    RequestV3WireError::with_detail(
        RequestV3WireErrorCode::EnvelopeRejected,
        error.code() as u16,
    )
}

fn request_v3_bindings_wire_error(error: AssignmentWireError) -> RequestV3WireError {
    RequestV3WireError::with_detail(
        RequestV3WireErrorCode::BindingsRejected,
        error.code() as u16,
    )
}

fn request_v3_execution_wire_error(error: ThreadExecutionWireError) -> RequestV3WireError {
    RequestV3WireError::with_detail(
        RequestV3WireErrorCode::ExecutionRejected,
        error.code() as u16,
    )
}

fn request_v3_target_plan_error(error: TargetPlanV3ContractError) -> RequestV3WireError {
    let code = match error {
        TargetPlanV3ContractError::OrphanBinding => TargetPlanV3WireErrorCode::OrphanBinding,
        TargetPlanV3ContractError::BindingMailboxMismatch => {
            TargetPlanV3WireErrorCode::BindingMailboxMismatch
        }
        TargetPlanV3ContractError::BindingTargetMismatch => {
            TargetPlanV3WireErrorCode::BindingTargetMismatch
        }
        TargetPlanV3ContractError::BlockUntilDeadlineForbidden => {
            TargetPlanV3WireErrorCode::BlockUntilDeadlineForbidden
        }
        _ => TargetPlanV3WireErrorCode::InvalidTargetPlan,
    };
    RequestV3WireError::with_detail(RequestV3WireErrorCode::TargetPlanRejected, code as u16)
}

fn thread_loop_wire_error(error: ExecutionWireError) -> ThreadExecutionWireError {
    ThreadExecutionWireError::with_detail(
        ThreadExecutionWireErrorCode::LoopExecutionRejected,
        ThreadExecutionRecordSection::LoopBody,
        0,
        error.code() as u16,
    )
}

fn thread_contract_wire_error(error: ThreadExecutionContractError) -> ThreadExecutionWireError {
    let code = match error {
        ThreadExecutionContractError::InvalidExecutorBudget => {
            ThreadExecutionWireErrorCode::InvalidExecutorBudget
        }
        ThreadExecutionContractError::DomainCountExceeded => {
            ThreadExecutionWireErrorCode::DomainCountExceeded
        }
        ThreadExecutionContractError::ExecutionCountExceeded => {
            ThreadExecutionWireErrorCode::ExecutionCountExceeded
        }
        ThreadExecutionContractError::MissingThreadDomain
        | ThreadExecutionContractError::MissingThreadMailboxExecution => {
            ThreadExecutionWireErrorCode::MissingRecords
        }
        ThreadExecutionContractError::DuplicateDomainRef => {
            ThreadExecutionWireErrorCode::DuplicateDomainRef
        }
        ThreadExecutionContractError::DuplicateExecutionBinding => {
            ThreadExecutionWireErrorCode::DuplicateExecutionBinding
        }
        ThreadExecutionContractError::DuplicateExecutionMailbox => {
            ThreadExecutionWireErrorCode::DuplicateExecutionMailbox
        }
        ThreadExecutionContractError::OrphanDomainRef => {
            ThreadExecutionWireErrorCode::OrphanDomainRef
        }
        ThreadExecutionContractError::UnusedDomainRef => {
            ThreadExecutionWireErrorCode::UnusedDomainRef
        }
        ThreadExecutionContractError::UnsupportedThreadExecution => {
            ThreadExecutionWireErrorCode::UnsupportedThreadExecution
        }
        ThreadExecutionContractError::ControlDispatchForbidden => {
            ThreadExecutionWireErrorCode::ControlDispatchForbidden
        }
        ThreadExecutionContractError::ThreadUtilizationExceeded
        | ThreadExecutionContractError::UtilizationOverflow => {
            ThreadExecutionWireErrorCode::ThreadUtilizationExceeded
        }
        ThreadExecutionContractError::ExecutorBudgetExceeded => {
            ThreadExecutionWireErrorCode::ExecutorBudgetExceeded
        }
        ThreadExecutionContractError::CrossLoopThreadDomain
        | ThreadExecutionContractError::CrossLoopThreadBinding
        | ThreadExecutionContractError::CrossLoopThreadMailbox
        | ThreadExecutionContractError::CrossLoopThreadInstance => {
            ThreadExecutionWireErrorCode::CrossLoopThreadConflict
        }
        ThreadExecutionContractError::ThreadSubjectMismatch => {
            ThreadExecutionWireErrorCode::ThreadSubjectMismatch
        }
        _ => ThreadExecutionWireErrorCode::InvalidThreadExecution,
    };
    ThreadExecutionWireError::new(code)
}

const fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

const fn read_u32(bytes: &[u8]) -> u32 {
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

/// Fail-closed construction errors for PXTE v2 Thread execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadExecutionContractError {
    /// The global executor budget is zero, inconsistent, or unbounded.
    InvalidExecutorBudget,
    /// A ThreadDomain has no workers or exceeds the scalar bound.
    InvalidWorkerCount,
    /// A ThreadDomain has an invalid capacity or lifecycle duration.
    InvalidDomainBudget,
    /// A Thread execution has an invalid run or cancellation duration.
    InvalidExecutionBudget,
    /// The non-preemptive run bound exceeds the total run budget.
    RunBoundExceedsRunBudget,
    /// A native thread reservation exceeds the fixed scalar bound.
    InvalidNativeThreadReservation,
    /// A service-cost token is zero or exceeds the fixed bound.
    InvalidServiceCost,
    /// A minimum-service weight is zero or exceeds the fixed bound.
    InvalidMinimumServiceWeight,
    /// A maximum dispatch burst is zero.
    InvalidMaxBurst,
    /// An arrival bound is zero or exceeds the fixed bound.
    InvalidArrivalBound,
    /// The first ThreadDomain contract does not admit Control dispatch.
    ControlDispatchForbidden,
    /// A required synchronous, bounded, evidenced profile was not supplied.
    UnsupportedThreadExecution,
    /// The embedded PXTE v1 Loop plan was invalid.
    LoopExecution(ExecutionContractError),
    /// The ThreadDomain record count exceeds the fixed bound.
    DomainCountExceeded,
    /// The Thread Mailbox record count exceeds the fixed bound.
    ExecutionCountExceeded,
    /// No ThreadDomain record was supplied.
    MissingThreadDomain,
    /// No Thread Mailbox execution record was supplied.
    MissingThreadMailboxExecution,
    /// Two ThreadDomain records share one identity.
    DuplicateDomainRef,
    /// Two Thread execution records share one BindingId.
    DuplicateExecutionBinding,
    /// Two Thread execution records share one Mailbox.
    DuplicateExecutionMailbox,
    /// A Thread execution references no declared ThreadDomain.
    OrphanDomainRef,
    /// A declared ThreadDomain has no execution record.
    UnusedDomainRef,
    /// Two Mailboxes for one instance disagree on subject execution identity.
    ThreadSubjectMismatch,
    /// A Loop and Thread domain share opaque identity bytes.
    CrossLoopThreadDomain,
    /// A BindingId is assigned to both Loop and Thread execution.
    CrossLoopThreadBinding,
    /// A Mailbox is assigned to both Loop and Thread execution.
    CrossLoopThreadMailbox,
    /// A target instance is assigned across Loop and Thread execution.
    CrossLoopThreadInstance,
    /// Checked ThreadDomain demand exceeds its worker capacity.
    ThreadUtilizationExceeded,
    /// A checked utilization calculation overflowed.
    UtilizationOverflow,
    /// Framework, worker, and distinct-instance native threads exceed the ceiling.
    ExecutorBudgetExceeded,
    /// Canonical digest construction failed.
    Digest(DigestBuildError),
    /// Stored canonical bytes differ from rebuilt values.
    CanonicalWireMismatch,
    /// Stored PXTE v2 digest differs from rebuilt bytes.
    ExecutionDigestMismatch,
}

impl From<DigestBuildError> for ThreadExecutionContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ThreadExecutionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Thread execution contract error {self:?}")
    }
}

impl std::error::Error for ThreadExecutionContractError {}

/// Fail-closed construction errors for composite v3 target plans and requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetPlanV3ContractError {
    /// The PXTA body was invalid.
    Bindings(AssignmentContractError),
    /// The additive PXTE v2 body was invalid.
    ThreadExecution(ThreadExecutionContractError),
    /// The embedded Loop plan failed existing v2 cross-body validation.
    LoopTargetPlan(TargetPlanContractError),
    /// A Thread execution has no exact PXTA BindingId.
    OrphanBinding,
    /// A Thread execution Mailbox differs from its exact PXTA binding.
    BindingMailboxMismatch,
    /// A Thread execution target differs from its exact PXTA binding.
    BindingTargetMismatch,
    /// Runtime execution plans cannot block an executor thread on Mailbox pressure.
    BlockUntilDeadlineForbidden,
    /// The stored v3 composite digest differs from both canonical bodies.
    CompositeDigestMismatch,
    /// The Slice header does not commit the v3 composite digest.
    SliceAssignmentDigestMismatch,
    /// The signed envelope carries a different Slice commitment.
    EnvelopeSliceMismatch,
    /// Slice provenance validation failed.
    Provenance(ProvenanceContractError),
    /// Signed-envelope validation failed.
    Envelope(EnvelopeContractError),
    /// Canonical digest construction failed.
    Digest(DigestBuildError),
    /// The PXAR v3 frame exceeds its fixed bound.
    RequestFrameTooLarge,
    /// Stored PXAR v3 bytes differ from rebuilt values.
    RequestCanonicalWireMismatch,
}

impl From<AssignmentContractError> for TargetPlanV3ContractError {
    fn from(value: AssignmentContractError) -> Self {
        Self::Bindings(value)
    }
}

impl From<ThreadExecutionContractError> for TargetPlanV3ContractError {
    fn from(value: ThreadExecutionContractError) -> Self {
        Self::ThreadExecution(value)
    }
}

impl From<ProvenanceContractError> for TargetPlanV3ContractError {
    fn from(value: ProvenanceContractError) -> Self {
        Self::Provenance(value)
    }
}

impl From<EnvelopeContractError> for TargetPlanV3ContractError {
    fn from(value: EnvelopeContractError) -> Self {
        Self::Envelope(value)
    }
}

impl From<DigestBuildError> for TargetPlanV3ContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for TargetPlanV3ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v3 target plan contract error {self:?}")
    }
}

impl std::error::Error for TargetPlanV3ContractError {}

/// Identifies the PXTE v2 subsection containing a wire error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ThreadExecutionRecordSection {
    /// Embedded, unchanged PXTE v1 Loop body.
    LoopBody = 1,
    /// Fixed ThreadDomain record section.
    ThreadDomain = 2,
    /// Fixed Thread Mailbox execution record section.
    ThreadMailbox = 3,
}

/// Stable machine-readable PXTE v2 rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ThreadExecutionWireErrorCode {
    /// The frame exceeds its fixed pre-parse bound.
    FrameTooLarge = 1,
    /// The frame ends before all declared bytes.
    Truncated = 2,
    /// The PXTE magic is invalid.
    InvalidMagic = 3,
    /// Only PXTE version 2 is accepted.
    UnsupportedVersion = 4,
    /// The embedded PXTE v1 body exceeds its bound.
    LoopBodyTooLarge = 5,
    /// The ThreadDomain count exceeds its bound.
    DomainCountExceeded = 6,
    /// The Thread execution count exceeds its bound.
    ExecutionCountExceeded = 7,
    /// Declared lengths do not equal exact frame length.
    InvalidFrameLength = 8,
    /// The embedded PXTE v1 decoder rejected the Loop body.
    LoopExecutionRejected = 9,
    /// A fixed record carries an unknown enum discriminant.
    InvalidEnumValue = 10,
    /// The executor budget is invalid.
    InvalidExecutorBudget = 11,
    /// A ThreadDomain record is invalid.
    InvalidThreadDomain = 12,
    /// A Thread execution record is invalid.
    InvalidThreadExecution = 13,
    /// Two ThreadDomain records share an identity.
    DuplicateDomainRef = 14,
    /// Two Thread execution records share a BindingId.
    DuplicateExecutionBinding = 15,
    /// Two Thread execution records share a Mailbox.
    DuplicateExecutionMailbox = 16,
    /// A Thread execution references no domain.
    OrphanDomainRef = 17,
    /// A ThreadDomain has no execution record.
    UnusedDomainRef = 18,
    /// A synchronous bounded evidenced profile was not supplied.
    UnsupportedThreadExecution = 19,
    /// Control dispatch is forbidden in this first Thread contract.
    ControlDispatchForbidden = 20,
    /// ThreadDomain demand exceeds declared worker capacity.
    ThreadUtilizationExceeded = 21,
    /// Global executor thread demand exceeds its ceiling.
    ExecutorBudgetExceeded = 22,
    /// Loop and Thread execution identities overlap.
    CrossLoopThreadConflict = 23,
    /// Mailboxes for one target instance disagree on subject execution identity.
    ThreadSubjectMismatch = 24,
    /// Required Thread records are absent.
    MissingRecords = 25,
    /// Record ordering or bytes are not canonical.
    NonCanonicalFrame = 26,
}

/// PXTE v2 rejection with optional section, record index, and nested v1 code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadExecutionWireError {
    code: ThreadExecutionWireErrorCode,
    section: Option<ThreadExecutionRecordSection>,
    record_index: Option<u32>,
    detail_code: Option<u16>,
}

impl ThreadExecutionWireError {
    const fn new(code: ThreadExecutionWireErrorCode) -> Self {
        Self {
            code,
            section: None,
            record_index: None,
            detail_code: None,
        }
    }

    const fn at(
        code: ThreadExecutionWireErrorCode,
        section: ThreadExecutionRecordSection,
        record_index: u32,
    ) -> Self {
        Self {
            code,
            section: Some(section),
            record_index: Some(record_index),
            detail_code: None,
        }
    }

    const fn with_detail(
        code: ThreadExecutionWireErrorCode,
        section: ThreadExecutionRecordSection,
        record_index: u32,
        detail_code: u16,
    ) -> Self {
        Self {
            code,
            section: Some(section),
            record_index: Some(record_index),
            detail_code: Some(detail_code),
        }
    }

    /// Returns the stable top-level reason.
    #[must_use]
    pub const fn code(self) -> ThreadExecutionWireErrorCode {
        self.code
    }

    /// Returns the rejected subsection, when record-local.
    #[must_use]
    pub const fn section(self) -> Option<ThreadExecutionRecordSection> {
        self.section
    }

    /// Returns the zero-based record index, when record-local.
    #[must_use]
    pub const fn record_index(self) -> Option<u32> {
        self.record_index
    }

    /// Returns a nested PXTE v1 error code for an embedded Loop rejection.
    #[must_use]
    pub const fn detail_code(self) -> Option<u16> {
        self.detail_code
    }
}

impl fmt::Display for ThreadExecutionWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PXTE v2 wire error {:?}", self.code)
    }
}

impl std::error::Error for ThreadExecutionWireError {}

/// Stable cross-body detail reason for a PXAR v3 rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum TargetPlanV3WireErrorCode {
    /// A Thread execution has no exact PXTA BindingId.
    OrphanBinding = 1,
    /// A Thread execution Mailbox differs from PXTA.
    BindingMailboxMismatch = 2,
    /// A Thread execution target differs from PXTA.
    BindingTargetMismatch = 3,
    /// A PXTA binding requests executor-thread blocking pressure.
    BlockUntilDeadlineForbidden = 4,
    /// Another semantic target-plan rule failed.
    InvalidTargetPlan = 5,
}

/// Stable machine-readable PXAR v3 rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RequestV3WireErrorCode {
    /// The frame exceeds its fixed pre-parse bound.
    FrameTooLarge = 1,
    /// The frame ends before all declared bytes.
    Truncated = 2,
    /// The PXAR magic is invalid.
    InvalidMagic = 3,
    /// Only PXAR version 3 is accepted.
    UnsupportedVersion = 4,
    /// Declared component lengths do not equal exact frame length.
    InvalidFrameLength = 5,
    /// The unchanged envelope decoder rejected its body.
    EnvelopeRejected = 6,
    /// The PXTA decoder rejected its body.
    BindingsRejected = 7,
    /// The PXTE v2 decoder rejected its body.
    ExecutionRejected = 8,
    /// Exact PXTA-to-execution semantic validation failed.
    TargetPlanRejected = 9,
    /// The signed Slice commitment does not match the bodies.
    CommitmentMismatch = 10,
}

/// PXAR v3 rejection with an optional nested stable reason code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestV3WireError {
    code: RequestV3WireErrorCode,
    detail_code: Option<u16>,
}

impl RequestV3WireError {
    const fn new(code: RequestV3WireErrorCode) -> Self {
        Self {
            code,
            detail_code: None,
        }
    }

    const fn with_detail(code: RequestV3WireErrorCode, detail_code: u16) -> Self {
        Self {
            code,
            detail_code: Some(detail_code),
        }
    }

    /// Returns the stable top-level reason.
    #[must_use]
    pub const fn code(self) -> RequestV3WireErrorCode {
        self.code
    }

    /// Returns the nested decoder or semantic reason, when present.
    #[must_use]
    pub const fn detail_code(self) -> Option<u16> {
        self.detail_code
    }
}

impl fmt::Display for RequestV3WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PXAR v3 wire error {:?}", self.code)
    }
}

impl std::error::Error for RequestV3WireError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};

    use crate::apply::{
        ApplyOperationId, ExpectedActive, PlanWriterContext, PlanWriterEpoch, PlanWriterRef,
        RuntimeApplyControl, RuntimeApplyControlCommitment, TenureAuthorityRef, TenureKeyRef,
        TenureProofAlgorithm, TenureProofAuthority, WriterTenureClaim, WriterTenureProof,
    };
    use crate::assignment::{
        BindingAssignment, DeliveryProfile, InteractionKind, MailboxSpec, PortCardinality,
        PortDirection, PortEndpoint, PortRef, PortSpec, RuntimeApplyRequest, SchemaRef,
    };
    use crate::execution::{
        CallbackBudgets, CardDefinitionRef, CardImplementationRef, LoopDomainCapacity,
        LoopDomainSpec, LoopExecutionRequirements, LoopLifecycleBudgets, MailboxDispatchPolicy,
        MailboxExecutionSpec, OverrunAction, RuntimeApplyRequestV2,
    };
    use crate::provenance::{
        PlanProvenance, RuntimeSliceHeader, SourcePlanDigest, SourcePlanRef, SourcePlanRevision,
        SourceScopeRef,
    };
    use crate::temporal::{ApplyTemporalConstraint, TemporalConstraintId};
    use crate::wire::{
        ApplyAuthAlgorithm, ApplyAuthKeyRef, ApplyRequestAuthClaim, RuntimeApplyEnvelopeDraft,
    };

    use super::*;

    fn subject(value: u8) -> CardSubjectSpec {
        CardSubjectSpec::new(
            CardDefinitionRef::from_bytes([value; 16]),
            CardImplementationRef::from_bytes([value.wrapping_add(1); 16]),
            Digest32::from_bytes([value.wrapping_add(2); 32]),
            Digest32::from_bytes([value.wrapping_add(3); 32]),
            Digest32::from_bytes([value.wrapping_add(4); 32]),
        )
    }

    fn thread_requirements(native_threads: u32) -> ThreadExecutionRequirements {
        let budgets = ThreadInvocationBudgets::try_new(
            BoundedDuration::from_nanos(5),
            BoundedDuration::from_nanos(10),
            BoundedDuration::from_nanos(5),
            native_threads,
        )
        .expect("fixture Thread invocation budgets must be valid");
        ThreadExecutionRequirements::try_new(
            CallModel::Synchronous,
            WorkloadKind::Native,
            BlockingRisk::Bounded,
            RunBoundProvenance::Measured,
            budgets,
        )
        .expect("fixture Thread requirements must be valid")
    }

    fn thread_dispatch(arrivals: u32) -> ThreadDispatchPolicy {
        ThreadDispatchPolicy::try_new(DispatchClass::Interactive, 2, 4, 2, arrivals)
            .expect("fixture Thread dispatch must be valid")
    }

    fn thread_domain(value: u8, workers: u32, window: u64) -> ThreadDomainSpec {
        ThreadDomainSpec::try_new(
            ThreadDomainRef::from_bytes([value; 16]),
            workers,
            BoundedDuration::from_nanos(window),
            BoundedDuration::from_nanos(20),
            BoundedDuration::from_nanos(30),
        )
        .expect("fixture ThreadDomain must be valid")
    }

    fn thread_mailbox(
        binding: u8,
        mailbox: u8,
        target: u8,
        domain: u8,
        subject_value: u8,
        native_threads: u32,
        arrivals: u32,
    ) -> ThreadMailboxExecutionSpec {
        ThreadMailboxExecutionSpec::new(
            BindingId::from_bytes([binding; 16]),
            MailboxRef::from_bytes([mailbox; 16]),
            InstanceRef::from_bytes([target; 16]),
            ThreadDomainRef::from_bytes([domain; 16]),
            subject(subject_value),
            thread_requirements(native_threads),
            thread_dispatch(arrivals),
        )
    }

    fn thread_plan_with(
        budget: u32,
        domains: Vec<ThreadDomainSpec>,
        mailboxes: Vec<ThreadMailboxExecutionSpec>,
    ) -> Result<TargetExecutionPlanV2, ThreadExecutionContractError> {
        TargetExecutionPlanV2::try_new(
            None,
            ExecutorBudgetSpec::try_new(budget, 1).expect("fixture executor budget"),
            domains,
            mailboxes,
        )
    }

    fn thread_plan() -> TargetExecutionPlanV2 {
        thread_plan_with(
            6,
            vec![thread_domain(0x91, 2, 100)],
            vec![thread_mailbox(0x31, 0x81, 0x61, 0x91, 0xa1, 3, 1)],
        )
        .expect("fixture Thread plan must be valid")
    }

    fn binding(
        binding_value: u8,
        source_value: u8,
        target_value: u8,
        mailbox_value: u8,
        overflow: OverflowPolicy,
    ) -> BindingAssignment {
        let schema = SchemaRef::try_new([0x21; 16], 1, Digest32::from_bytes([0x22; 32]))
            .expect("fixture schema must be valid");
        let source = PortEndpoint::new(
            InstanceRef::from_bytes([source_value; 16]),
            PortRef::from_bytes([source_value.wrapping_add(0x10); 16]),
            PortSpec::new(
                PortDirection::Out,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let target = PortEndpoint::new(
            InstanceRef::from_bytes([target_value; 16]),
            PortRef::from_bytes([target_value.wrapping_add(0x10); 16]),
            PortSpec::new(
                PortDirection::In,
                schema,
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let delivery = DeliveryProfile::try_new(128, BoundedDuration::from_nanos(1_000), overflow)
            .expect("fixture delivery must be valid");
        let mailbox =
            MailboxSpec::try_new(2, 256, BoundedDuration::from_nanos(500), 1, 256, overflow)
                .expect("fixture Mailbox must be valid");
        BindingAssignment::try_new(
            BindingId::from_bytes([binding_value; 16]),
            source,
            target,
            MailboxRef::from_bytes([mailbox_value; 16]),
            delivery,
            mailbox,
        )
        .expect("fixture binding must be valid")
    }

    fn bindings() -> TargetAssignments {
        TargetAssignments::try_new(vec![binding(
            0x31,
            0x41,
            0x61,
            0x81,
            OverflowPolicy::RejectNew,
        )])
        .expect("fixture assignments must be valid")
    }

    fn slice_commitment(digest: TargetAssignmentDigest) -> RuntimeSliceCommitment {
        let provenance = PlanProvenance::new(
            SourceScopeRef::from_bytes([1; 16]),
            SourcePlanRef::from_bytes([2; 16]),
            SourcePlanRevision::new(3),
            SourcePlanDigest::new(Digest32::from_bytes([4; 32])),
        );
        RuntimeSliceCommitment::try_new(RuntimeSliceHeader::new(
            RuntimeHostId::from_bytes([5; 16]),
            provenance,
            digest,
        ))
        .expect("fixture Slice commitment must be valid")
    }

    fn envelope(commitment: RuntimeSliceCommitment) -> RuntimeApplyEnvelope {
        let scope = commitment.header().provenance().source_scope();
        let algorithm = TenureProofAlgorithm::try_new(1).expect("tenure algorithm");
        let authority = TenureProofAuthority::try_new(
            TenureAuthorityRef::from_bytes([7; 16]),
            TenureKeyRef::from_bytes([8; 16]),
            algorithm,
            1,
        )
        .expect("tenure authority");
        let writer = PlanWriterRef::from_bytes([9; 16]);
        let claim = WriterTenureClaim::try_new(
            scope,
            writer,
            PlanWriterEpoch::new(2),
            PlanWriterEpoch::new(1),
        )
        .expect("tenure claim");
        let proof = WriterTenureProof::try_new(authority, claim, b"nonce", b"signature")
            .expect("tenure proof");
        let writer_context = PlanWriterContext::try_new(writer, PlanWriterEpoch::new(2), proof)
            .expect("writer context");
        let control = RuntimeApplyControl::new(
            writer_context,
            ExpectedActive::None,
            ApplyOperationId::from_bytes([10; 16]),
        );
        let control_commitment = RuntimeApplyControlCommitment::try_new(commitment, control)
            .expect("control commitment");
        let generation = ClockGeneration::try_new(13).expect("clock generation");
        let temporal = ApplyTemporalConstraint::try_new(
            TemporalConstraintId::from_bytes([11; 16]),
            ClockDomainRef::from_bytes([12; 16]),
            generation,
            BoundedDuration::from_nanos(1_000),
            BoundedDuration::from_nanos(750),
        )
        .expect("temporal constraint");
        let auth_algorithm = ApplyAuthAlgorithm::try_new(1).expect("auth algorithm");
        let auth_claim = ApplyRequestAuthClaim::try_new(
            PrincipalRef::from_bytes([14; 16]),
            ApplyAuthKeyRef::from_bytes([15; 16]),
            auth_algorithm,
            1,
            b"apply-nonce",
        )
        .expect("auth claim");
        RuntimeApplyEnvelopeDraft::try_new(control_commitment, temporal, auth_claim)
            .expect("envelope draft")
            .finalize(b"apply-signature")
            .expect("signed envelope")
    }

    fn loop_plan(
        binding_value: u8,
        mailbox_value: u8,
        target_value: u8,
        domain_value: u8,
    ) -> TargetExecutionPlan {
        let capacity = LoopDomainCapacity::try_new(
            2,
            0,
            BoundedDuration::from_nanos(100),
            BoundedDuration::from_nanos(0),
        )
        .expect("fixture Loop capacity must be valid");
        let lifecycle = LoopLifecycleBudgets::try_new(
            BoundedDuration::from_nanos(20),
            BoundedDuration::from_nanos(30),
            BoundedDuration::from_nanos(20),
        )
        .expect("fixture Loop lifecycle must be valid");
        let domain = LoopDomainSpec::new(
            crate::execution::DomainRef::from_bytes([domain_value; 16]),
            capacity,
            lifecycle,
        );
        let requirements = LoopExecutionRequirements::try_new(
            CallModel::CooperativeAsync,
            WorkloadKind::Io,
            BlockingRisk::None,
            RunBoundProvenance::Measured,
            BoundedDuration::from_nanos(5),
        )
        .expect("fixture Loop requirements must be valid");
        let budgets = CallbackBudgets::try_new(
            BoundedDuration::from_nanos(10),
            BoundedDuration::from_nanos(5),
            OverrunAction::CooperativeCancel,
        )
        .expect("fixture callback budgets must be valid");
        let dispatch =
            MailboxDispatchPolicy::try_new(DispatchClass::Interactive, 2, 4, 2, 1, budgets)
                .expect("fixture Loop dispatch must be valid");
        let mailbox = MailboxExecutionSpec::try_new(
            BindingId::from_bytes([binding_value; 16]),
            MailboxRef::from_bytes([mailbox_value; 16]),
            InstanceRef::from_bytes([target_value; 16]),
            crate::execution::DomainRef::from_bytes([domain_value; 16]),
            subject(0xb1),
            requirements,
            dispatch,
        )
        .expect("fixture Loop execution must be valid");
        TargetExecutionPlan::try_new(vec![domain], vec![mailbox])
            .expect("fixture Loop plan must be valid")
    }

    #[test]
    fn synchronous_bounded_evidenced_profiles_are_the_only_admitted_profiles() {
        let budgets = ThreadInvocationBudgets::try_new(
            BoundedDuration::from_nanos(5),
            BoundedDuration::from_nanos(10),
            BoundedDuration::from_nanos(5),
            0,
        )
        .expect("fixture invocation budgets");
        let build = |call_model, workload_kind, blocking_risk, provenance| {
            ThreadExecutionRequirements::try_new(
                call_model,
                workload_kind,
                blocking_risk,
                provenance,
                budgets,
            )
        };
        assert!(
            build(
                CallModel::Synchronous,
                WorkloadKind::Io,
                BlockingRisk::Bounded,
                RunBoundProvenance::Certified,
            )
            .is_ok()
        );
        for result in [
            build(
                CallModel::CooperativeAsync,
                WorkloadKind::Io,
                BlockingRisk::Bounded,
                RunBoundProvenance::Measured,
            ),
            build(
                CallModel::Synchronous,
                WorkloadKind::Cpu,
                BlockingRisk::Bounded,
                RunBoundProvenance::Measured,
            ),
            build(
                CallModel::Synchronous,
                WorkloadKind::Device,
                BlockingRisk::Bounded,
                RunBoundProvenance::Measured,
            ),
            build(
                CallModel::Synchronous,
                WorkloadKind::Unknown,
                BlockingRisk::Bounded,
                RunBoundProvenance::Measured,
            ),
            build(
                CallModel::Synchronous,
                WorkloadKind::Native,
                BlockingRisk::Unknown,
                RunBoundProvenance::Measured,
            ),
            build(
                CallModel::Synchronous,
                WorkloadKind::Native,
                BlockingRisk::Bounded,
                RunBoundProvenance::Declared,
            ),
        ] {
            assert_eq!(
                result,
                Err(ThreadExecutionContractError::UnsupportedThreadExecution)
            );
        }
        assert_eq!(
            ThreadDispatchPolicy::try_new(DispatchClass::Control, 1, 1, 1, 1),
            Err(ThreadExecutionContractError::ControlDispatchForbidden)
        );
    }

    #[test]
    fn executor_budget_counts_native_threads_once_per_distinct_instance() {
        let executions = vec![
            thread_mailbox(0x31, 0x81, 0x61, 0x91, 0xa1, 3, 1),
            thread_mailbox(0x32, 0x82, 0x61, 0x91, 0xa1, 3, 1),
        ];
        assert!(
            thread_plan_with(6, vec![thread_domain(0x91, 2, 100)], executions.clone(),).is_ok()
        );
        assert_eq!(
            thread_plan_with(5, vec![thread_domain(0x91, 2, 100)], executions),
            Err(ThreadExecutionContractError::ExecutorBudgetExceeded)
        );

        let distinct = vec![
            thread_mailbox(0x31, 0x81, 0x61, 0x91, 0xa1, 3, 1),
            thread_mailbox(0x32, 0x82, 0x62, 0x91, 0xb1, 3, 1),
        ];
        assert_eq!(
            thread_plan_with(8, vec![thread_domain(0x91, 2, 100)], distinct),
            Err(ThreadExecutionContractError::ExecutorBudgetExceeded)
        );
    }

    #[test]
    fn thread_utilization_is_checked_against_workers_times_window() {
        let execution = thread_mailbox(0x31, 0x81, 0x61, 0x91, 0xa1, 0, 1);
        assert_eq!(
            thread_plan_with(2, vec![thread_domain(0x91, 1, 14)], vec![execution]),
            Err(ThreadExecutionContractError::ThreadUtilizationExceeded)
        );
        assert!(thread_plan_with(2, vec![thread_domain(0x91, 1, 15)], vec![execution]).is_ok());
    }

    #[test]
    fn loop_and_thread_identities_cannot_cross_execution_kinds() {
        let loop_execution = loop_plan(0x21, 0x71, 0x51, 0x91);
        let result = TargetExecutionPlanV2::try_new(
            Some(loop_execution),
            ExecutorBudgetSpec::try_new(6, 1).expect("budget"),
            vec![thread_domain(0x91, 2, 100)],
            vec![thread_mailbox(0x31, 0x81, 0x61, 0x91, 0xa1, 3, 1)],
        );
        assert_eq!(
            result,
            Err(ThreadExecutionContractError::CrossLoopThreadDomain)
        );

        for (loop_binding, loop_mailbox, loop_target, expected) in [
            (
                0x31,
                0x71,
                0x51,
                ThreadExecutionContractError::CrossLoopThreadBinding,
            ),
            (
                0x21,
                0x81,
                0x51,
                ThreadExecutionContractError::CrossLoopThreadMailbox,
            ),
            (
                0x21,
                0x71,
                0x61,
                ThreadExecutionContractError::CrossLoopThreadInstance,
            ),
        ] {
            assert_eq!(
                TargetExecutionPlanV2::try_new(
                    Some(loop_plan(loop_binding, loop_mailbox, loop_target, 0x90)),
                    ExecutorBudgetSpec::try_new(6, 1).expect("budget"),
                    vec![thread_domain(0x91, 2, 100)],
                    vec![thread_mailbox(0x31, 0x81, 0x61, 0x91, 0xa1, 3, 1)],
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn target_plan_requires_exact_pxta_references_and_nonblocking_pressure() {
        assert!(TargetPlanAssignmentsV3::try_new(bindings(), thread_plan()).is_ok());
        let orphan = TargetAssignments::try_new(Vec::new()).expect("empty PXTA is canonical");
        assert_eq!(
            TargetPlanAssignmentsV3::try_new(orphan, thread_plan()),
            Err(TargetPlanV3ContractError::OrphanBinding)
        );
        let mismatched_mailbox = TargetAssignments::try_new(vec![binding(
            0x31,
            0x41,
            0x61,
            0x82,
            OverflowPolicy::RejectNew,
        )])
        .expect("mismatch fixture PXTA");
        assert_eq!(
            TargetPlanAssignmentsV3::try_new(mismatched_mailbox, thread_plan()),
            Err(TargetPlanV3ContractError::BindingMailboxMismatch)
        );
        let blocking = TargetAssignments::try_new(vec![binding(
            0x31,
            0x41,
            0x61,
            0x81,
            OverflowPolicy::BlockUntilDeadline,
        )])
        .expect("blocking fixture PXTA");
        assert_eq!(
            TargetPlanAssignmentsV3::try_new(blocking, thread_plan()),
            Err(TargetPlanV3ContractError::BlockUntilDeadlineForbidden)
        );
    }

    #[test]
    fn pxte_v2_round_trips_and_rejects_noncanonical_or_malformed_frames() {
        let plan = thread_plan();
        assert_eq!(plan.canonical_wire().len(), 309);
        assert_eq!(
            TargetExecutionPlanV2::decode(plan.canonical_wire()),
            Ok(plan.clone())
        );

        let mut trailing = plan.canonical_wire().to_vec();
        trailing.push(0);
        assert_eq!(
            TargetExecutionPlanV2::decode(&trailing)
                .expect_err("trailing bytes must fail")
                .code(),
            ThreadExecutionWireErrorCode::InvalidFrameLength
        );
        assert_eq!(
            TargetExecutionPlanV2::decode(&plan.canonical_wire()[..308])
                .expect_err("truncated record must fail")
                .code(),
            ThreadExecutionWireErrorCode::Truncated
        );

        let mut unknown_enum = plan.canonical_wire().to_vec();
        let call_model_offset = TARGET_EXECUTION_V2_HEADER_BYTES
            + THREAD_DOMAIN_RECORD_BYTES
            + 4 * 16
            + 2 * 16
            + 3 * 32;
        unknown_enum[call_model_offset] = 0xff;
        let error = TargetExecutionPlanV2::decode(&unknown_enum)
            .expect_err("unknown enum discriminant must fail");
        assert_eq!(error.code(), ThreadExecutionWireErrorCode::InvalidEnumValue);
        assert_eq!(
            error.section(),
            Some(ThreadExecutionRecordSection::ThreadMailbox)
        );
        assert_eq!(error.record_index(), Some(0));
    }

    #[test]
    fn unsorted_pxte_v2_records_are_rejected_instead_of_silently_normalized() {
        let plan = thread_plan_with(
            9,
            vec![thread_domain(0x91, 2, 100)],
            vec![
                thread_mailbox(0x31, 0x81, 0x61, 0x91, 0xa1, 3, 1),
                thread_mailbox(0x32, 0x82, 0x62, 0x91, 0xb1, 3, 1),
            ],
        )
        .expect("two-record plan must be valid");
        let mut wire = plan.canonical_wire().to_vec();
        let start = TARGET_EXECUTION_V2_HEADER_BYTES + THREAD_DOMAIN_RECORD_BYTES;
        let middle = start + THREAD_MAILBOX_EXECUTION_RECORD_BYTES;
        let end = middle + THREAD_MAILBOX_EXECUTION_RECORD_BYTES;
        let first = wire[start..middle].to_vec();
        let second = wire[middle..end].to_vec();
        wire[start..middle].copy_from_slice(&second);
        wire[middle..end].copy_from_slice(&first);
        assert_eq!(
            TargetExecutionPlanV2::decode(&wire)
                .expect_err("unsorted records must fail")
                .code(),
            ThreadExecutionWireErrorCode::NonCanonicalFrame
        );
    }

    #[test]
    fn old_and_new_decoders_do_not_fallback_across_versions() {
        let plan = thread_plan();
        assert_eq!(
            TargetExecutionPlan::decode(plan.canonical_wire())
                .expect_err("PXTE v1 must reject v2")
                .code(),
            crate::execution::ExecutionWireErrorCode::UnsupportedVersion
        );
        let old_loop = loop_plan(0x21, 0x71, 0x51, 0x90);
        assert_eq!(
            TargetExecutionPlanV2::decode(old_loop.canonical_wire())
                .expect_err("PXTE v2 must reject v1")
                .code(),
            ThreadExecutionWireErrorCode::UnsupportedVersion
        );

        let mut v3_header = [0_u8; APPLY_REQUEST_V3_HEADER_BYTES];
        v3_header[..4].copy_from_slice(RUNTIME_APPLY_REQUEST_MAGIC);
        v3_header[4..6].copy_from_slice(&RUNTIME_APPLY_REQUEST_V3_VERSION.to_be_bytes());
        assert_eq!(
            RuntimeApplyRequest::decode(&v3_header)
                .expect_err("PXAR v1 must reject v3")
                .code(),
            crate::assignment::RequestWireErrorCode::UnsupportedVersion
        );
        assert_eq!(
            RuntimeApplyRequestV2::decode(&v3_header)
                .expect_err("PXAR v2 must reject v3")
                .code(),
            crate::execution::RequestV2WireErrorCode::UnsupportedVersion
        );
        for version in [1_u16, 2] {
            v3_header[4..6].copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                RuntimeApplyRequestV3::decode(&v3_header)
                    .expect_err("PXAR v3 must reject older versions")
                    .code(),
                RequestV3WireErrorCode::UnsupportedVersion
            );
        }
    }

    #[test]
    fn stable_wire_error_codes_are_append_only() {
        assert_eq!(
            [
                ThreadExecutionWireErrorCode::FrameTooLarge as u16,
                ThreadExecutionWireErrorCode::Truncated as u16,
                ThreadExecutionWireErrorCode::InvalidMagic as u16,
                ThreadExecutionWireErrorCode::UnsupportedVersion as u16,
                ThreadExecutionWireErrorCode::LoopBodyTooLarge as u16,
                ThreadExecutionWireErrorCode::DomainCountExceeded as u16,
                ThreadExecutionWireErrorCode::ExecutionCountExceeded as u16,
                ThreadExecutionWireErrorCode::InvalidFrameLength as u16,
                ThreadExecutionWireErrorCode::LoopExecutionRejected as u16,
                ThreadExecutionWireErrorCode::InvalidEnumValue as u16,
                ThreadExecutionWireErrorCode::InvalidExecutorBudget as u16,
                ThreadExecutionWireErrorCode::InvalidThreadDomain as u16,
                ThreadExecutionWireErrorCode::InvalidThreadExecution as u16,
                ThreadExecutionWireErrorCode::DuplicateDomainRef as u16,
                ThreadExecutionWireErrorCode::DuplicateExecutionBinding as u16,
                ThreadExecutionWireErrorCode::DuplicateExecutionMailbox as u16,
                ThreadExecutionWireErrorCode::OrphanDomainRef as u16,
                ThreadExecutionWireErrorCode::UnusedDomainRef as u16,
                ThreadExecutionWireErrorCode::UnsupportedThreadExecution as u16,
                ThreadExecutionWireErrorCode::ControlDispatchForbidden as u16,
                ThreadExecutionWireErrorCode::ThreadUtilizationExceeded as u16,
                ThreadExecutionWireErrorCode::ExecutorBudgetExceeded as u16,
                ThreadExecutionWireErrorCode::CrossLoopThreadConflict as u16,
                ThreadExecutionWireErrorCode::ThreadSubjectMismatch as u16,
                ThreadExecutionWireErrorCode::MissingRecords as u16,
                ThreadExecutionWireErrorCode::NonCanonicalFrame as u16,
            ],
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26,
            ]
        );
        assert_eq!(
            [
                RequestV3WireErrorCode::FrameTooLarge as u16,
                RequestV3WireErrorCode::Truncated as u16,
                RequestV3WireErrorCode::InvalidMagic as u16,
                RequestV3WireErrorCode::UnsupportedVersion as u16,
                RequestV3WireErrorCode::InvalidFrameLength as u16,
                RequestV3WireErrorCode::EnvelopeRejected as u16,
                RequestV3WireErrorCode::BindingsRejected as u16,
                RequestV3WireErrorCode::ExecutionRejected as u16,
                RequestV3WireErrorCode::TargetPlanRejected as u16,
                RequestV3WireErrorCode::CommitmentMismatch as u16,
            ],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        );
    }

    #[test]
    fn pxte_v2_and_composite_digest_have_fixed_golden_vectors() {
        let plan = thread_plan();
        let target_plan =
            TargetPlanAssignmentsV3::try_new(bindings(), plan.clone()).expect("target plan");
        let expected_execution = [
            0x98, 0xa3, 0x87, 0x36, 0x64, 0xb5, 0x81, 0x17, 0x63, 0xc5, 0x57, 0x21, 0x3a, 0x7f,
            0x9f, 0x2f, 0x21, 0x21, 0x27, 0x9e, 0x29, 0xfd, 0x0e, 0xa3, 0x29, 0xfc, 0x2a, 0x98,
            0xb0, 0x42, 0x89, 0x81,
        ];
        let expected_composite = [
            0xdf, 0x07, 0x40, 0x0b, 0x3c, 0xfd, 0x7a, 0xb2, 0x8b, 0x64, 0xb7, 0xb1, 0xa4, 0xb6,
            0x71, 0x2e, 0xe8, 0xf7, 0x7c, 0xbe, 0x37, 0xbb, 0x79, 0x5e, 0xf8, 0x65, 0x2f, 0xf3,
            0x75, 0xaa, 0xe7, 0x8f,
        ];
        assert_eq!(
            plan.execution_digest().value().as_bytes(),
            &expected_execution
        );
        assert_eq!(
            target_plan.assignment_digest().value().as_bytes(),
            &expected_composite
        );
    }

    #[test]
    fn pxar_v3_round_trips_and_reports_nested_tamper_reasons() {
        let assignments =
            TargetPlanAssignmentsV3::try_new(bindings(), thread_plan()).expect("target plan");
        let commitment = slice_commitment(assignments.assignment_digest());
        let signed_envelope = envelope(commitment);
        let slice = RuntimePlanSliceV3::try_new(commitment, assignments).expect("v3 Slice");
        let request = RuntimeApplyRequestV3::try_new(signed_envelope, slice).expect("v3 request");
        assert_eq!(
            RuntimeApplyRequestV3::decode(request.canonical_wire()),
            Ok(request.clone())
        );
        assert_eq!(request.canonical_wire().len(), 1_360);
        let expected_request_digest = [
            0x40, 0xef, 0xc4, 0x8e, 0x4f, 0x99, 0xc0, 0xaa, 0x3e, 0xe3, 0xa1, 0xcc, 0x17, 0x80,
            0x66, 0xda, 0x88, 0xba, 0xa0, 0xc0, 0x67, 0x69, 0xc5, 0x58, 0xa2, 0xc5, 0x25, 0x20,
            0x97, 0x13, 0xf2, 0xef,
        ];
        assert_eq!(
            request.request_digest().as_bytes(),
            &expected_request_digest
        );

        let envelope_length = read_u32(&request.canonical_wire()[6..10]) as usize;
        let bindings_length = read_u32(&request.canonical_wire()[10..14]) as usize;
        let execution_start = APPLY_REQUEST_V3_HEADER_BYTES + envelope_length + bindings_length;
        let call_model_offset = execution_start
            + TARGET_EXECUTION_V2_HEADER_BYTES
            + THREAD_DOMAIN_RECORD_BYTES
            + 4 * 16
            + 2 * 16
            + 3 * 32;
        let mut unknown_enum = request.canonical_wire().to_vec();
        unknown_enum[call_model_offset] = 0xff;
        let error = RuntimeApplyRequestV3::decode(&unknown_enum)
            .expect_err("nested unknown enum must reject PXAR v3");
        assert_eq!(error.code(), RequestV3WireErrorCode::ExecutionRejected);
        assert_eq!(
            error.detail_code(),
            Some(ThreadExecutionWireErrorCode::InvalidEnumValue as u16)
        );

        let mut body_tamper = request.canonical_wire().to_vec();
        body_tamper[execution_start + TARGET_EXECUTION_V2_HEADER_BYTES + 20] ^= 1;
        assert_eq!(
            RuntimeApplyRequestV3::decode(&body_tamper)
                .expect_err("semantic body tamper must break the signed commitment")
                .code(),
            RequestV3WireErrorCode::ExecutionRejected
        );

        let mut trailing = request.canonical_wire().to_vec();
        trailing.push(0);
        assert_eq!(
            RuntimeApplyRequestV3::decode(&trailing)
                .expect_err("trailing PXAR bytes must fail")
                .code(),
            RequestV3WireErrorCode::InvalidFrameLength
        );
        assert_eq!(
            RuntimeApplyRequestV3::decode(
                &request.canonical_wire()[..request.canonical_wire().len() - 1]
            )
            .expect_err("truncated PXAR body must fail")
            .code(),
            RequestV3WireErrorCode::Truncated
        );
    }

    #[test]
    fn additive_plan_preserves_an_unchanged_loop_body() {
        let loop_body = loop_plan(0x21, 0x71, 0x51, 0x90);
        let plan = TargetExecutionPlanV2::try_new(
            Some(loop_body.clone()),
            ExecutorBudgetSpec::try_new(6, 1).expect("budget"),
            vec![thread_domain(0x91, 2, 100)],
            vec![thread_mailbox(0x31, 0x81, 0x61, 0x91, 0xa1, 3, 1)],
        )
        .expect("separated additive plan");
        assert_eq!(
            plan.loop_plan().expect("embedded Loop").canonical_wire(),
            loop_body.canonical_wire()
        );
        assert_eq!(
            TargetExecutionPlanV2::decode(plan.canonical_wire()),
            Ok(plan)
        );
    }

    #[test]
    fn one_thread_instance_cannot_change_subject_or_native_reservation() {
        let mismatched = vec![
            thread_mailbox(0x31, 0x81, 0x61, 0x91, 0xa1, 3, 1),
            thread_mailbox(0x32, 0x82, 0x61, 0x91, 0xa1, 2, 1),
        ];
        assert_eq!(
            thread_plan_with(9, vec![thread_domain(0x91, 2, 100)], mismatched),
            Err(ThreadExecutionContractError::ThreadSubjectMismatch)
        );
    }

    #[test]
    fn stored_digests_are_revalidated() {
        let mut plan = thread_plan();
        plan.execution_digest = TargetExecutionDigestV2::new(Digest32::from_bytes([0xff; 32]));
        assert_eq!(
            plan.validate(),
            Err(ThreadExecutionContractError::ExecutionDigestMismatch)
        );

        let mut target_plan = TargetPlanAssignmentsV3::try_new(bindings(), thread_plan())
            .expect("target plan must be valid");
        target_plan.assignment_digest =
            TargetAssignmentDigest::new(Digest32::from_bytes([0xff; 32]));
        assert_eq!(
            target_plan.validate(),
            Err(TargetPlanV3ContractError::CompositeDigestMismatch)
        );
    }
}
