//! Additive ProcessDomain execution contracts and strict PXAR v4 framing.
//!
//! PXTE v3 optionally embeds one byte-exact PXTE v2 Loop/Thread plan and adds
//! bounded process launch, capacity, lifecycle, resource, restart, and mailbox
//! execution records. These values are signed desired state only: they do not
//! describe live processes, epochs, health observations, restart facts, or IPC.

use core::fmt;

use paraegox_kernel::digest::{Digest32, Digest32Builder, DigestBuildError};
use paraegox_kernel::time::BoundedDuration;

use crate::assignment::{
    AssignmentContractError, AssignmentWireError, BindingId, InstanceRef, MAX_TARGET_ASSIGNMENTS,
    MAX_TARGET_ASSIGNMENTS_BYTES, MailboxRef, OverflowPolicy, TargetAssignments,
};
use crate::execution::{
    BlockingRisk, CallModel, CardSubjectSpec, DispatchClass, MAX_EXECUTION_DURATION_NANOS,
    RunBoundProvenance, WorkloadKind,
};
use crate::provenance::{ProvenanceContractError, RuntimeSliceCommitment, TargetAssignmentDigest};
use crate::thread_execution::{
    MAX_TARGET_EXECUTION_PLAN_V2_BYTES, TargetExecutionPlanV2, TargetPlanAssignmentsV3,
    TargetPlanV3ContractError, ThreadDispatchPolicy, ThreadExecutionContractError,
    ThreadExecutionWireError,
};
use crate::wire::{
    EnvelopeContractError, MAX_RUNTIME_APPLY_ENVELOPE_BYTES, RuntimeApplyEnvelope, WireError,
};

/// Version of the additive Loop, Thread, and Process execution body.
pub const TARGET_EXECUTION_PLAN_V3_VERSION: u16 = 3;
/// Version of the complete apply request carrying PXTA and PXTE v3.
pub const RUNTIME_APPLY_REQUEST_V4_VERSION: u16 = 4;
/// Maximum ProcessDomain records in one target execution body.
pub const MAX_PROCESS_DOMAINS: usize = 64;
/// Maximum Process Mailbox execution records in one target execution body.
pub const MAX_PROCESS_MAILBOX_EXECUTIONS: usize = MAX_TARGET_ASSIGNMENTS;
/// Maximum restart attempts in one declared restart window.
pub const MAX_PROCESS_RESTART_ATTEMPTS: u32 = 1_024;
/// Maximum canonical byte length of one live PXWP v1 frame.
pub const MAX_PROCESS_WORKER_FRAME_BYTES: usize = 1_048_576;
/// The only live worker protocol version expressible by signed PXTE v3 desired state.
pub const PROCESS_WORKER_PROTOCOL_VERSION: u16 = 1;
/// Fixed byte length of the PXWP v1 header.
pub const PROCESS_WORKER_HEADER_BYTES: usize = 148;
/// Maximum payload representable by the largest PXWP v1 payload-bearing body.
pub const MAX_PROCESS_WORKER_PAYLOAD_BYTES: usize =
    MAX_PROCESS_WORKER_FRAME_BYTES - PROCESS_WORKER_HEADER_BYTES - 24;
/// Hard PXWP v1 ceiling for simultaneously held invocation credits.
pub const MAX_PROCESS_WORKER_CREDITS: u32 = 4_096;
/// Hard PXWP v1 ceiling for retained bytes in one worker session.
pub const MAX_PROCESS_WORKER_RETAINED_BYTES: u64 = 4 * 1_024 * 1_024 * 1_024;
/// Maximum individual payload admitted to the signed process IPC contract.
pub const MAX_PROCESS_IPC_PAYLOAD_BYTES: u64 = MAX_PROCESS_WORKER_PAYLOAD_BYTES as u64;

const TARGET_EXECUTION_MAGIC: &[u8; 4] = b"PXTE";
const RUNTIME_APPLY_REQUEST_MAGIC: &[u8; 4] = b"PXAR";
const TARGET_EXECUTION_V3_HEADER_BYTES: usize = 18;
const PROCESS_DOMAIN_RECORD_BYTES: usize = 336;
const PROCESS_MAILBOX_EXECUTION_RECORD_BYTES: usize = 289;
const APPLY_REQUEST_V4_HEADER_BYTES: usize = 18;
const TARGET_EXECUTION_V3_DIGEST_DOMAIN: &[u8] = b"paraegox.runtime.target-execution.sha256.v3";
const TARGET_PLAN_ASSIGNMENTS_V4_DIGEST_DOMAIN: &[u8] =
    b"paraegox.runtime.target-plan-assignments.sha256.v4";

/// Maximum canonical byte length of one PXTE v3 body.
pub const MAX_TARGET_EXECUTION_PLAN_V3_BYTES: usize = TARGET_EXECUTION_V3_HEADER_BYTES
    + MAX_TARGET_EXECUTION_PLAN_V2_BYTES
    + MAX_PROCESS_DOMAINS * PROCESS_DOMAIN_RECORD_BYTES
    + MAX_PROCESS_MAILBOX_EXECUTIONS * PROCESS_MAILBOX_EXECUTION_RECORD_BYTES;
/// Maximum canonical byte length of one PXAR v4 request.
pub const MAX_RUNTIME_APPLY_REQUEST_V4_BYTES: usize = APPLY_REQUEST_V4_HEADER_BYTES
    + MAX_RUNTIME_APPLY_ENVELOPE_BYTES
    + MAX_TARGET_ASSIGNMENTS_BYTES
    + MAX_TARGET_EXECUTION_PLAN_V3_BYTES;

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
    ProcessDomainRef,
    "Desired identity of one target-local process slot."
);
opaque_ref!(
    ProcessLaunchProfileRef,
    "Resolved process launch profile identity."
);
opaque_ref!(
    ProcessTargetProfileRef,
    "Resolved process target profile identity."
);
opaque_ref!(
    ProcessSandboxProfileRef,
    "Resolved process sandbox profile identity."
);
opaque_ref!(
    ProcessEntrypointRef,
    "Resolved process invocation entrypoint identity."
);

/// Digest of one exact canonical PXTE v3 body.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TargetExecutionDigestV3(Digest32);

impl TargetExecutionDigestV3 {
    /// Wraps a digest assigned by the canonical PXTE v3 owner.
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

/// Worker runtime selected by an exact launch profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum WorkerRuntimeKind {
    /// A native executable process.
    NativeExecutable = 1,
    /// A Python worker process.
    Python = 2,
}

/// Per-generation workspace ownership policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum WorkspacePolicy {
    /// Create a fresh workspace for each instance generation.
    EphemeralPerInstanceGeneration = 1,
}

/// Process access boundary selected by the first process contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ProcessAccessPolicy {
    /// The worker receives no unmediated host access.
    NoRawHostAccess = 1,
}

/// Failure-containment unit selected by the first process contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum FailureContainmentPolicy {
    /// Failure and restart apply to the complete declared ProcessDomain.
    WholeProcessDomain = 1,
}

/// Whether an invocation is expected to produce an external side effect.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SideEffectClass {
    /// The invocation is proven effect-free outside its response.
    EffectFree = 1,
    /// The invocation may produce an external side effect.
    External = 2,
    /// Side effects have not been proven absent or present.
    Unknown = 3,
}

/// Replay policy admitted by this first process invocation contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InvocationReplayPolicy {
    /// Never replay an invocation automatically after ambiguity or failure.
    NoReplay = 1,
}

/// Inclusive runtime version range, compared lexicographically.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeVersionRange {
    min_major: u16,
    min_minor: u16,
    max_major: u16,
    max_minor: u16,
}

impl RuntimeVersionRange {
    /// Validates nonzero major versions and an ordered inclusive range.
    pub const fn try_new(
        min_major: u16,
        min_minor: u16,
        max_major: u16,
        max_minor: u16,
    ) -> Result<Self, ProcessExecutionContractError> {
        if min_major == 0
            || max_major == 0
            || min_major > max_major
            || (min_major == max_major && min_minor > max_minor)
        {
            return Err(ProcessExecutionContractError::InvalidLaunchSpec);
        }
        Ok(Self {
            min_major,
            min_minor,
            max_major,
            max_minor,
        })
    }

    /// Returns the inclusive minimum major version.
    #[must_use]
    pub const fn min_major(self) -> u16 {
        self.min_major
    }
    /// Returns the inclusive minimum minor version.
    #[must_use]
    pub const fn min_minor(self) -> u16 {
        self.min_minor
    }
    /// Returns the inclusive maximum major version.
    #[must_use]
    pub const fn max_major(self) -> u16 {
        self.max_major
    }
    /// Returns the inclusive maximum minor version.
    #[must_use]
    pub const fn max_minor(self) -> u16 {
        self.max_minor
    }
}

/// Immutable launch, target, and sandbox profile selections.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessProfileSelections {
    launch_profile: ProcessLaunchProfileRef,
    launch_profile_digest: Digest32,
    target_profile: ProcessTargetProfileRef,
    target_profile_digest: Digest32,
    sandbox_profile: ProcessSandboxProfileRef,
    sandbox_profile_digest: Digest32,
}

impl ProcessProfileSelections {
    /// Groups the three exact profile identities with their content digests.
    #[must_use]
    pub const fn new(
        launch_profile: ProcessLaunchProfileRef,
        launch_profile_digest: Digest32,
        target_profile: ProcessTargetProfileRef,
        target_profile_digest: Digest32,
        sandbox_profile: ProcessSandboxProfileRef,
        sandbox_profile_digest: Digest32,
    ) -> Self {
        Self {
            launch_profile,
            launch_profile_digest,
            target_profile,
            target_profile_digest,
            sandbox_profile,
            sandbox_profile_digest,
        }
    }

    /// Returns the launch profile reference.
    #[must_use]
    pub const fn launch_profile(self) -> ProcessLaunchProfileRef {
        self.launch_profile
    }
    /// Returns the launch profile content digest.
    #[must_use]
    pub const fn launch_profile_digest(self) -> Digest32 {
        self.launch_profile_digest
    }
    /// Returns the target profile reference.
    #[must_use]
    pub const fn target_profile(self) -> ProcessTargetProfileRef {
        self.target_profile
    }
    /// Returns the target profile content digest.
    #[must_use]
    pub const fn target_profile_digest(self) -> Digest32 {
        self.target_profile_digest
    }
    /// Returns the sandbox profile reference.
    #[must_use]
    pub const fn sandbox_profile(self) -> ProcessSandboxProfileRef {
        self.sandbox_profile
    }
    /// Returns the sandbox profile content digest.
    #[must_use]
    pub const fn sandbox_profile_digest(self) -> Digest32 {
        self.sandbox_profile_digest
    }
}

/// Exact process launch, runtime, target, and sandbox selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessLaunchSpec {
    profiles: ProcessProfileSelections,
    protocol_version: u16,
    runtime_kind: WorkerRuntimeKind,
    runtime_versions: RuntimeVersionRange,
}

impl ProcessLaunchSpec {
    /// Validates the exact shared PXWP version and immutable profile selections.
    pub const fn try_new(
        profiles: ProcessProfileSelections,
        protocol_version: u16,
        runtime_kind: WorkerRuntimeKind,
        runtime_versions: RuntimeVersionRange,
    ) -> Result<Self, ProcessExecutionContractError> {
        if protocol_version != PROCESS_WORKER_PROTOCOL_VERSION {
            return Err(ProcessExecutionContractError::InvalidLaunchSpec);
        }
        Ok(Self {
            profiles,
            protocol_version,
            runtime_kind,
            runtime_versions,
        })
    }

    /// Returns the immutable profile selections.
    #[must_use]
    pub const fn profiles(self) -> ProcessProfileSelections {
        self.profiles
    }

    /// Returns the launch profile reference.
    #[must_use]
    pub const fn launch_profile(self) -> ProcessLaunchProfileRef {
        self.profiles.launch_profile()
    }
    /// Returns the launch profile content digest.
    #[must_use]
    pub const fn launch_profile_digest(self) -> Digest32 {
        self.profiles.launch_profile_digest()
    }
    /// Returns the process protocol version.
    #[must_use]
    pub const fn protocol_version(self) -> u16 {
        self.protocol_version
    }
    /// Returns the selected worker runtime kind.
    #[must_use]
    pub const fn runtime_kind(self) -> WorkerRuntimeKind {
        self.runtime_kind
    }
    /// Returns the admitted runtime version range.
    #[must_use]
    pub const fn runtime_versions(self) -> RuntimeVersionRange {
        self.runtime_versions
    }
    /// Returns the target profile reference.
    #[must_use]
    pub const fn target_profile(self) -> ProcessTargetProfileRef {
        self.profiles.target_profile()
    }
    /// Returns the target profile content digest.
    #[must_use]
    pub const fn target_profile_digest(self) -> Digest32 {
        self.profiles.target_profile_digest()
    }
    /// Returns the sandbox profile reference.
    #[must_use]
    pub const fn sandbox_profile(self) -> ProcessSandboxProfileRef {
        self.profiles.sandbox_profile()
    }
    /// Returns the sandbox profile content digest.
    #[must_use]
    pub const fn sandbox_profile_digest(self) -> Digest32 {
        self.profiles.sandbox_profile_digest()
    }
}

/// ProcessDomain outstanding, concurrency, and IPC credit ceilings.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessCapacitySpec {
    max_outstanding: u32,
    max_concurrent: u32,
    capacity_window: BoundedDuration,
    ipc_credit_items: u32,
    ipc_credit_bytes: u64,
    max_retained_bytes: u64,
}

impl ProcessCapacitySpec {
    /// Validates finite concurrency and byte/item credits.
    pub const fn try_new(
        max_outstanding: u32,
        max_concurrent: u32,
        capacity_window: BoundedDuration,
        ipc_credit_items: u32,
        ipc_credit_bytes: u64,
        max_retained_bytes: u64,
    ) -> Result<Self, ProcessExecutionContractError> {
        if max_outstanding == 0
            || max_outstanding > MAX_PROCESS_WORKER_CREDITS
            || max_concurrent == 0
            || max_concurrent > max_outstanding
            || ipc_credit_items < max_concurrent
            || ipc_credit_items > max_outstanding
            || ipc_credit_bytes == 0
            || max_retained_bytes < ipc_credit_bytes
            || max_retained_bytes > MAX_PROCESS_WORKER_RETAINED_BYTES
            || !valid_duration(capacity_window)
        {
            return Err(ProcessExecutionContractError::InvalidIpcBudget);
        }
        Ok(Self {
            max_outstanding,
            max_concurrent,
            capacity_window,
            ipc_credit_items,
            ipc_credit_bytes,
            max_retained_bytes,
        })
    }

    /// Returns the maximum admitted outstanding invocations.
    #[must_use]
    pub const fn max_outstanding(self) -> u32 {
        self.max_outstanding
    }
    /// Returns the maximum concurrently running invocations.
    #[must_use]
    pub const fn max_concurrent(self) -> u32 {
        self.max_concurrent
    }
    /// Returns the utilization capacity window.
    #[must_use]
    pub const fn capacity_window(self) -> BoundedDuration {
        self.capacity_window
    }
    /// Returns the item credit advertised to the mediated IPC boundary.
    #[must_use]
    pub const fn ipc_credit_items(self) -> u32 {
        self.ipc_credit_items
    }
    /// Returns the byte credit advertised to the mediated IPC boundary.
    #[must_use]
    pub const fn ipc_credit_bytes(self) -> u64 {
        self.ipc_credit_bytes
    }
    /// Returns the maximum retained bytes for this process domain.
    #[must_use]
    pub const fn max_retained_bytes(self) -> u64 {
        self.max_retained_bytes
    }
}

/// Planned process start, heartbeat, and control-response budgets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessLivenessBudgets {
    start: BoundedDuration,
    heartbeat_interval: BoundedDuration,
    heartbeat_timeout: BoundedDuration,
    control_response: BoundedDuration,
}

impl ProcessLivenessBudgets {
    /// Validates finite liveness budgets and a timeout longer than the heartbeat interval.
    pub const fn try_new(
        start: BoundedDuration,
        heartbeat_interval: BoundedDuration,
        heartbeat_timeout: BoundedDuration,
        control_response: BoundedDuration,
    ) -> Result<Self, ProcessExecutionContractError> {
        if !valid_duration(start)
            || !valid_duration(heartbeat_interval)
            || !valid_duration(heartbeat_timeout)
            || !valid_duration(control_response)
            || heartbeat_timeout.value() <= heartbeat_interval.value()
        {
            return Err(ProcessExecutionContractError::InvalidLivenessBudget);
        }
        Ok(Self {
            start,
            heartbeat_interval,
            heartbeat_timeout,
            control_response,
        })
    }

    /// Returns the process start budget.
    #[must_use]
    pub const fn start(self) -> BoundedDuration {
        self.start
    }
    /// Returns the heartbeat interval.
    #[must_use]
    pub const fn heartbeat_interval(self) -> BoundedDuration {
        self.heartbeat_interval
    }
    /// Returns the heartbeat timeout.
    #[must_use]
    pub const fn heartbeat_timeout(self) -> BoundedDuration {
        self.heartbeat_timeout
    }
    /// Returns the control-response budget.
    #[must_use]
    pub const fn control_response(self) -> BoundedDuration {
        self.control_response
    }
}

/// Planned drain, stop escalation, and cleanup budgets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessShutdownBudgets {
    drain: BoundedDuration,
    cooperative_stop: BoundedDuration,
    terminate_grace: BoundedDuration,
    kill_grace: BoundedDuration,
    cleanup: BoundedDuration,
}

impl ProcessShutdownBudgets {
    /// Validates finite drain, stop-escalation, and cleanup budgets.
    pub const fn try_new(
        drain: BoundedDuration,
        cooperative_stop: BoundedDuration,
        terminate_grace: BoundedDuration,
        kill_grace: BoundedDuration,
        cleanup: BoundedDuration,
    ) -> Result<Self, ProcessExecutionContractError> {
        if !valid_duration(drain)
            || !valid_duration(cooperative_stop)
            || !valid_duration(terminate_grace)
            || !valid_duration(kill_grace)
            || !valid_duration(cleanup)
        {
            return Err(ProcessExecutionContractError::InvalidLivenessBudget);
        }
        Ok(Self {
            drain,
            cooperative_stop,
            terminate_grace,
            kill_grace,
            cleanup,
        })
    }

    /// Returns the drain budget.
    #[must_use]
    pub const fn drain(self) -> BoundedDuration {
        self.drain
    }
    /// Returns the cooperative-stop budget.
    #[must_use]
    pub const fn cooperative_stop(self) -> BoundedDuration {
        self.cooperative_stop
    }
    /// Returns the terminate grace budget.
    #[must_use]
    pub const fn terminate_grace(self) -> BoundedDuration {
        self.terminate_grace
    }
    /// Returns the forced-kill grace budget.
    #[must_use]
    pub const fn kill_grace(self) -> BoundedDuration {
        self.kill_grace
    }
    /// Returns the cleanup budget.
    #[must_use]
    pub const fn cleanup(self) -> BoundedDuration {
        self.cleanup
    }
}

/// Planned process start, liveness, control, stop, and cleanup budgets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessLifecycleBudgets {
    liveness: ProcessLivenessBudgets,
    shutdown: ProcessShutdownBudgets,
}

impl ProcessLifecycleBudgets {
    /// Combines already validated liveness and shutdown budgets.
    #[must_use]
    pub const fn new(liveness: ProcessLivenessBudgets, shutdown: ProcessShutdownBudgets) -> Self {
        Self { liveness, shutdown }
    }

    /// Returns the grouped process liveness budgets.
    #[must_use]
    pub const fn liveness(self) -> ProcessLivenessBudgets {
        self.liveness
    }
    /// Returns the grouped process shutdown budgets.
    #[must_use]
    pub const fn shutdown(self) -> ProcessShutdownBudgets {
        self.shutdown
    }
    /// Returns the process start budget.
    #[must_use]
    pub const fn start(self) -> BoundedDuration {
        self.liveness.start()
    }
    /// Returns the heartbeat interval.
    #[must_use]
    pub const fn heartbeat_interval(self) -> BoundedDuration {
        self.liveness.heartbeat_interval()
    }
    /// Returns the heartbeat timeout.
    #[must_use]
    pub const fn heartbeat_timeout(self) -> BoundedDuration {
        self.liveness.heartbeat_timeout()
    }
    /// Returns the control-response budget.
    #[must_use]
    pub const fn control_response(self) -> BoundedDuration {
        self.liveness.control_response()
    }
    /// Returns the drain budget.
    #[must_use]
    pub const fn drain(self) -> BoundedDuration {
        self.shutdown.drain()
    }
    /// Returns the cooperative-stop budget.
    #[must_use]
    pub const fn cooperative_stop(self) -> BoundedDuration {
        self.shutdown.cooperative_stop()
    }
    /// Returns the terminate grace budget.
    #[must_use]
    pub const fn terminate_grace(self) -> BoundedDuration {
        self.shutdown.terminate_grace()
    }
    /// Returns the forced-kill grace budget.
    #[must_use]
    pub const fn kill_grace(self) -> BoundedDuration {
        self.shutdown.kill_grace()
    }
    /// Returns the cleanup budget.
    #[must_use]
    pub const fn cleanup(self) -> BoundedDuration {
        self.shutdown.cleanup()
    }
}

/// Static resource ceilings for one ProcessDomain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessResourceLimits {
    max_memory_bytes: u64,
    max_open_fds: u32,
    max_process_tree_members: u32,
    max_cpu_time: BoundedDuration,
}

impl ProcessResourceLimits {
    /// Validates nonzero memory, descriptor, process-tree, and CPU ceilings.
    pub const fn try_new(
        max_memory_bytes: u64,
        max_open_fds: u32,
        max_process_tree_members: u32,
        max_cpu_time: BoundedDuration,
    ) -> Result<Self, ProcessExecutionContractError> {
        if max_memory_bytes == 0
            || max_open_fds == 0
            || max_process_tree_members == 0
            || !valid_duration(max_cpu_time)
        {
            return Err(ProcessExecutionContractError::InvalidResourceBudget);
        }
        Ok(Self {
            max_memory_bytes,
            max_open_fds,
            max_process_tree_members,
            max_cpu_time,
        })
    }

    /// Returns the memory ceiling.
    #[must_use]
    pub const fn max_memory_bytes(self) -> u64 {
        self.max_memory_bytes
    }
    /// Returns the open-file-descriptor ceiling.
    #[must_use]
    pub const fn max_open_fds(self) -> u32 {
        self.max_open_fds
    }
    /// Returns the complete process-tree member ceiling.
    #[must_use]
    pub const fn max_process_tree_members(self) -> u32 {
        self.max_process_tree_members
    }
    /// Returns the process CPU-time ceiling.
    #[must_use]
    pub const fn max_cpu_time(self) -> BoundedDuration {
        self.max_cpu_time
    }
}

/// Bounded whole-domain restart policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessRestartPolicy {
    max_attempts: u32,
    restart_window: BoundedDuration,
    initial_backoff: BoundedDuration,
    max_backoff: BoundedDuration,
    jitter_basis_points: u16,
}

impl ProcessRestartPolicy {
    /// Validates bounded attempts, window, ordered backoff, and jitter percentage.
    pub const fn try_new(
        max_attempts: u32,
        restart_window: BoundedDuration,
        initial_backoff: BoundedDuration,
        max_backoff: BoundedDuration,
        jitter_basis_points: u16,
    ) -> Result<Self, ProcessExecutionContractError> {
        if max_attempts > MAX_PROCESS_RESTART_ATTEMPTS
            || !valid_duration(restart_window)
            || !valid_duration(initial_backoff)
            || !valid_duration(max_backoff)
            || initial_backoff.value() > max_backoff.value()
            || max_backoff.value() > restart_window.value()
            || jitter_basis_points > 10_000
        {
            return Err(ProcessExecutionContractError::InvalidRestartPolicy);
        }
        Ok(Self {
            max_attempts,
            restart_window,
            initial_backoff,
            max_backoff,
            jitter_basis_points,
        })
    }

    /// Returns the maximum restart attempts in the window.
    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }
    /// Returns the restart accounting window.
    #[must_use]
    pub const fn restart_window(self) -> BoundedDuration {
        self.restart_window
    }
    /// Returns the initial restart backoff.
    #[must_use]
    pub const fn initial_backoff(self) -> BoundedDuration {
        self.initial_backoff
    }
    /// Returns the maximum restart backoff.
    #[must_use]
    pub const fn max_backoff(self) -> BoundedDuration {
        self.max_backoff
    }
    /// Returns bounded jitter in basis points.
    #[must_use]
    pub const fn jitter_basis_points(self) -> u16 {
        self.jitter_basis_points
    }
}

/// Workspace, mediated-access, and failure-containment policies for one ProcessDomain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessDomainPolicies {
    workspace: WorkspacePolicy,
    access: ProcessAccessPolicy,
    failure_containment: FailureContainmentPolicy,
}

impl ProcessDomainPolicies {
    /// Groups the non-resource isolation policies selected for one ProcessDomain.
    #[must_use]
    pub const fn new(
        workspace: WorkspacePolicy,
        access: ProcessAccessPolicy,
        failure_containment: FailureContainmentPolicy,
    ) -> Self {
        Self {
            workspace,
            access,
            failure_containment,
        }
    }

    /// Returns the workspace policy.
    #[must_use]
    pub const fn workspace(self) -> WorkspacePolicy {
        self.workspace
    }

    /// Returns the mediated access policy.
    #[must_use]
    pub const fn access(self) -> ProcessAccessPolicy {
        self.access
    }

    /// Returns the failure-containment policy.
    #[must_use]
    pub const fn failure_containment(self) -> FailureContainmentPolicy {
        self.failure_containment
    }
}

/// Complete desired ProcessDomain specification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessDomainSpec {
    domain: ProcessDomainRef,
    launch: ProcessLaunchSpec,
    capacity: ProcessCapacitySpec,
    lifecycle: ProcessLifecycleBudgets,
    resources: ProcessResourceLimits,
    restart: ProcessRestartPolicy,
    policies: ProcessDomainPolicies,
}

impl ProcessDomainSpec {
    /// Combines validated planned process-domain components.
    pub const fn try_new(
        domain: ProcessDomainRef,
        launch: ProcessLaunchSpec,
        capacity: ProcessCapacitySpec,
        lifecycle: ProcessLifecycleBudgets,
        resources: ProcessResourceLimits,
        restart: ProcessRestartPolicy,
        policies: ProcessDomainPolicies,
    ) -> Result<Self, ProcessExecutionContractError> {
        if capacity.max_retained_bytes() > resources.max_memory_bytes() {
            return Err(ProcessExecutionContractError::InvalidResourceBudget);
        }
        Ok(Self {
            domain,
            launch,
            capacity,
            lifecycle,
            resources,
            restart,
            policies,
        })
    }

    /// Returns the desired domain identity.
    #[must_use]
    pub const fn domain(self) -> ProcessDomainRef {
        self.domain
    }
    /// Returns the exact launch specification.
    #[must_use]
    pub const fn launch(self) -> ProcessLaunchSpec {
        self.launch
    }
    /// Returns the capacity and credit specification.
    #[must_use]
    pub const fn capacity(self) -> ProcessCapacitySpec {
        self.capacity
    }
    /// Returns the lifecycle and liveness budgets.
    #[must_use]
    pub const fn lifecycle(self) -> ProcessLifecycleBudgets {
        self.lifecycle
    }
    /// Returns the static resource ceilings.
    #[must_use]
    pub const fn resources(self) -> ProcessResourceLimits {
        self.resources
    }
    /// Returns the restart policy.
    #[must_use]
    pub const fn restart(self) -> ProcessRestartPolicy {
        self.restart
    }
    /// Returns the grouped isolation policies.
    #[must_use]
    pub const fn policies(self) -> ProcessDomainPolicies {
        self.policies
    }
    /// Returns the workspace policy.
    #[must_use]
    pub const fn workspace_policy(self) -> WorkspacePolicy {
        self.policies.workspace()
    }
    /// Returns the mediated access policy.
    #[must_use]
    pub const fn access_policy(self) -> ProcessAccessPolicy {
        self.policies.access()
    }
    /// Returns the whole-domain failure-containment policy.
    #[must_use]
    pub const fn failure_containment(self) -> FailureContainmentPolicy {
        self.policies.failure_containment()
    }
}

/// Per-invocation process acknowledgement, run, cancellation, and terminal budgets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessInvocationBudgets {
    invoke_ack: BoundedDuration,
    run: BoundedDuration,
    cancellation_grace: BoundedDuration,
    max_terminal_payload_bytes: u32,
}

impl ProcessInvocationBudgets {
    /// Validates finite time budgets and the fixed terminal IPC payload ceiling.
    pub const fn try_new(
        invoke_ack: BoundedDuration,
        run: BoundedDuration,
        cancellation_grace: BoundedDuration,
        max_terminal_payload_bytes: u32,
    ) -> Result<Self, ProcessExecutionContractError> {
        if !valid_duration(invoke_ack)
            || !valid_duration(run)
            || !valid_duration(cancellation_grace)
            || max_terminal_payload_bytes as u64 > MAX_PROCESS_IPC_PAYLOAD_BYTES
        {
            return Err(ProcessExecutionContractError::InvalidInvocationBudget);
        }
        Ok(Self {
            invoke_ack,
            run,
            cancellation_grace,
            max_terminal_payload_bytes,
        })
    }

    /// Returns the invocation acknowledgement budget.
    #[must_use]
    pub const fn invoke_ack(self) -> BoundedDuration {
        self.invoke_ack
    }
    /// Returns the execution budget.
    #[must_use]
    pub const fn run(self) -> BoundedDuration {
        self.run
    }
    /// Returns the cancellation grace budget.
    #[must_use]
    pub const fn cancellation_grace(self) -> BoundedDuration {
        self.cancellation_grace
    }
    /// Returns the maximum terminal payload bytes.
    #[must_use]
    pub const fn max_terminal_payload_bytes(self) -> u32 {
        self.max_terminal_payload_bytes
    }
}

/// Exact process invocation requirements and fail-closed replay policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessExecutionRequirements {
    call_model: CallModel,
    workload_kind: WorkloadKind,
    blocking_risk: BlockingRisk,
    run_bound_provenance: RunBoundProvenance,
    side_effect_class: SideEffectClass,
    replay_policy: InvocationReplayPolicy,
    budgets: ProcessInvocationBudgets,
}

impl ProcessExecutionRequirements {
    /// Records process execution characteristics; v1 replay is strictly NoReplay.
    #[must_use]
    pub const fn new(
        call_model: CallModel,
        workload_kind: WorkloadKind,
        blocking_risk: BlockingRisk,
        run_bound_provenance: RunBoundProvenance,
        side_effect_class: SideEffectClass,
        replay_policy: InvocationReplayPolicy,
        budgets: ProcessInvocationBudgets,
    ) -> Self {
        Self {
            call_model,
            workload_kind,
            blocking_risk,
            run_bound_provenance,
            side_effect_class,
            replay_policy,
            budgets,
        }
    }

    /// Returns the compiled call model.
    #[must_use]
    pub const fn call_model(self) -> CallModel {
        self.call_model
    }
    /// Returns the compiled workload kind.
    #[must_use]
    pub const fn workload_kind(self) -> WorkloadKind {
        self.workload_kind
    }
    /// Returns the blocking-risk classification.
    #[must_use]
    pub const fn blocking_risk(self) -> BlockingRisk {
        self.blocking_risk
    }
    /// Returns the run-bound evidence class.
    #[must_use]
    pub const fn run_bound_provenance(self) -> RunBoundProvenance {
        self.run_bound_provenance
    }
    /// Returns the side-effect classification.
    #[must_use]
    pub const fn side_effect_class(self) -> SideEffectClass {
        self.side_effect_class
    }
    /// Returns the invocation replay policy.
    #[must_use]
    pub const fn replay_policy(self) -> InvocationReplayPolicy {
        self.replay_policy
    }
    /// Returns the invocation budgets.
    #[must_use]
    pub const fn budgets(self) -> ProcessInvocationBudgets {
        self.budgets
    }
}

/// Immutable Card subject and process entrypoint selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessWorkloadSelection {
    subject: CardSubjectSpec,
    entrypoint: ProcessEntrypointRef,
    entrypoint_digest: Digest32,
}

impl ProcessWorkloadSelection {
    /// Groups one exact Card subject with its language-neutral entrypoint binding.
    #[must_use]
    pub const fn new(
        subject: CardSubjectSpec,
        entrypoint: ProcessEntrypointRef,
        entrypoint_digest: Digest32,
    ) -> Self {
        Self {
            subject,
            entrypoint,
            entrypoint_digest,
        }
    }

    /// Returns the immutable Card subject.
    #[must_use]
    pub const fn subject(self) -> CardSubjectSpec {
        self.subject
    }

    /// Returns the language-neutral entrypoint reference.
    #[must_use]
    pub const fn entrypoint(self) -> ProcessEntrypointRef {
        self.entrypoint
    }

    /// Returns the exact entrypoint content digest.
    #[must_use]
    pub const fn entrypoint_digest(self) -> Digest32 {
        self.entrypoint_digest
    }
}

/// One exact Mailbox-to-ProcessDomain execution assignment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessMailboxExecutionSpec {
    binding_id: BindingId,
    mailbox: MailboxRef,
    target_instance: InstanceRef,
    domain: ProcessDomainRef,
    workload: ProcessWorkloadSelection,
    requirements: ProcessExecutionRequirements,
    dispatch: ThreadDispatchPolicy,
}

impl ProcessMailboxExecutionSpec {
    /// Combines exact identity, subject, entrypoint, requirements, and dispatch.
    #[must_use]
    pub const fn new(
        binding_id: BindingId,
        mailbox: MailboxRef,
        target_instance: InstanceRef,
        domain: ProcessDomainRef,
        workload: ProcessWorkloadSelection,
        requirements: ProcessExecutionRequirements,
        dispatch: ThreadDispatchPolicy,
    ) -> Self {
        Self {
            binding_id,
            mailbox,
            target_instance,
            domain,
            workload,
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
    /// Returns the desired ProcessDomain reference.
    #[must_use]
    pub const fn domain(self) -> ProcessDomainRef {
        self.domain
    }
    /// Returns the grouped Card subject and entrypoint selection.
    #[must_use]
    pub const fn workload(self) -> ProcessWorkloadSelection {
        self.workload
    }
    /// Returns the immutable Card subject.
    #[must_use]
    pub const fn subject(self) -> CardSubjectSpec {
        self.workload.subject()
    }
    /// Returns the exact invocation entrypoint.
    #[must_use]
    pub const fn entrypoint(self) -> ProcessEntrypointRef {
        self.workload.entrypoint()
    }
    /// Returns the exact entrypoint content digest.
    #[must_use]
    pub const fn entrypoint_digest(self) -> Digest32 {
        self.workload.entrypoint_digest()
    }
    /// Returns the process execution requirements.
    #[must_use]
    pub const fn requirements(self) -> ProcessExecutionRequirements {
        self.requirements
    }
    /// Returns the effective process mailbox dispatch policy.
    #[must_use]
    pub const fn dispatch(self) -> ThreadDispatchPolicy {
        self.dispatch
    }

    fn same_subject_contract(self, other: Self) -> bool {
        self.target_instance == other.target_instance
            && self.domain == other.domain
            && self.workload == other.workload
            && self.requirements == other.requirements
    }
}

/// Canonically ordered PXTE v3 Loop, Thread, and Process desired records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetExecutionPlanV3 {
    thread_plan: Option<TargetExecutionPlanV2>,
    process_domains: Box<[ProcessDomainSpec]>,
    process_mailboxes: Box<[ProcessMailboxExecutionSpec]>,
    canonical_wire: Box<[u8]>,
    execution_digest: TargetExecutionDigestV3,
}

impl TargetExecutionPlanV3 {
    /// Sorts, validates, bounds, and commits the additive process execution body.
    pub fn try_new(
        thread_plan: Option<TargetExecutionPlanV2>,
        mut process_domains: Vec<ProcessDomainSpec>,
        mut process_mailboxes: Vec<ProcessMailboxExecutionSpec>,
    ) -> Result<Self, ProcessExecutionContractError> {
        if process_domains.is_empty() {
            return Err(ProcessExecutionContractError::MissingProcessDomain);
        }
        if process_mailboxes.is_empty() {
            return Err(ProcessExecutionContractError::MissingProcessMailboxExecution);
        }
        if process_domains.len() > MAX_PROCESS_DOMAINS {
            return Err(ProcessExecutionContractError::DomainCountExceeded);
        }
        if process_mailboxes.len() > MAX_PROCESS_MAILBOX_EXECUTIONS {
            return Err(ProcessExecutionContractError::ExecutionCountExceeded);
        }
        if let Some(plan) = &thread_plan {
            plan.validate()
                .map_err(ProcessExecutionContractError::ThreadExecution)?;
        }
        process_domains.sort_by_key(|domain| domain.domain());
        process_mailboxes.sort_by_key(|execution| {
            (
                execution.binding_id(),
                execution.mailbox(),
                execution.target_instance(),
                execution.domain(),
            )
        });
        validate_process_execution_records(
            thread_plan.as_ref(),
            &process_domains,
            &process_mailboxes,
        )?;
        let canonical_wire = build_target_execution_v3_wire(
            thread_plan.as_ref(),
            &process_domains,
            &process_mailboxes,
        );
        let execution_digest = digest_target_execution_v3(&canonical_wire)?;
        Ok(Self {
            thread_plan,
            process_domains: process_domains.into_boxed_slice(),
            process_mailboxes: process_mailboxes.into_boxed_slice(),
            canonical_wire: canonical_wire.into_boxed_slice(),
            execution_digest,
        })
    }

    /// Strictly decodes one canonical PXTE v3 body without version fallback.
    pub fn decode(frame: &[u8]) -> Result<Self, ProcessExecutionWireError> {
        decode_target_execution_v3(frame)
    }

    /// Returns the optional byte-exact PXTE v2 plan.
    #[must_use]
    pub const fn thread_plan(&self) -> Option<&TargetExecutionPlanV2> {
        self.thread_plan.as_ref()
    }
    /// Returns canonically ordered ProcessDomain records.
    #[must_use]
    pub fn process_domains(&self) -> &[ProcessDomainSpec] {
        &self.process_domains
    }
    /// Returns canonically ordered process Mailbox records.
    #[must_use]
    pub fn process_mailbox_executions(&self) -> &[ProcessMailboxExecutionSpec] {
        &self.process_mailboxes
    }
    /// Returns exact canonical PXTE v3 bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
    /// Returns the PXTE v3 execution digest.
    #[must_use]
    pub const fn execution_digest(&self) -> TargetExecutionDigestV3 {
        self.execution_digest
    }

    /// Revalidates semantic records, canonical bytes, and digest.
    pub fn validate(&self) -> Result<(), ProcessExecutionContractError> {
        let rebuilt = Self::try_new(
            self.thread_plan.clone(),
            self.process_domains.to_vec(),
            self.process_mailboxes.to_vec(),
        )?;
        if rebuilt.thread_plan != self.thread_plan
            || rebuilt.process_domains != self.process_domains
            || rebuilt.process_mailboxes != self.process_mailboxes
            || rebuilt.canonical_wire != self.canonical_wire
        {
            return Err(ProcessExecutionContractError::CanonicalWireMismatch);
        }
        if rebuilt.execution_digest != self.execution_digest {
            return Err(ProcessExecutionContractError::ExecutionDigestMismatch);
        }
        Ok(())
    }
}

/// Complete PXTA bindings and their additive PXTE v3 execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetPlanAssignmentsV4 {
    bindings: TargetAssignments,
    execution: TargetExecutionPlanV3,
    assignment_digest: TargetAssignmentDigest,
}

impl TargetPlanAssignmentsV4 {
    /// Validates every Loop, Thread, and Process reference against exact PXTA records.
    pub fn try_new(
        bindings: TargetAssignments,
        execution: TargetExecutionPlanV3,
    ) -> Result<Self, TargetPlanV4ContractError> {
        bindings.validate()?;
        execution.validate()?;
        validate_target_plan_v4_references(&bindings, &execution)?;
        let assignment_digest = digest_target_plan_assignments_v4(&bindings, &execution)?;
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
    /// Returns the complete PXTE v3 body.
    #[must_use]
    pub const fn execution(&self) -> &TargetExecutionPlanV3 {
        &self.execution
    }
    /// Returns the v4 composite assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> TargetAssignmentDigest {
        self.assignment_digest
    }

    /// Revalidates both bodies, exact references, limits, and composite digest.
    pub fn validate(&self) -> Result<(), TargetPlanV4ContractError> {
        self.bindings.validate()?;
        self.execution.validate()?;
        validate_target_plan_v4_references(&self.bindings, &self.execution)?;
        if digest_target_plan_assignments_v4(&self.bindings, &self.execution)?
            != self.assignment_digest
        {
            return Err(TargetPlanV4ContractError::CompositeDigestMismatch);
        }
        Ok(())
    }
}

/// Complete v4 target Slice with one signed commitment and canonical bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePlanSliceV4 {
    commitment: RuntimeSliceCommitment,
    assignments: TargetPlanAssignmentsV4,
}

impl RuntimePlanSliceV4 {
    /// Binds the v4 composite assignment digest to the existing Slice field.
    pub fn try_new(
        commitment: RuntimeSliceCommitment,
        assignments: TargetPlanAssignmentsV4,
    ) -> Result<Self, TargetPlanV4ContractError> {
        commitment.validate()?;
        assignments.validate()?;
        if commitment.header().assignment_digest() != assignments.assignment_digest() {
            return Err(TargetPlanV4ContractError::SliceAssignmentDigestMismatch);
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
    /// Returns the v4 target assignments.
    #[must_use]
    pub const fn assignments(&self) -> &TargetPlanAssignmentsV4 {
        &self.assignments
    }

    /// Revalidates commitment and assignment equality.
    pub fn validate(&self) -> Result<(), TargetPlanV4ContractError> {
        self.commitment.validate()?;
        self.assignments.validate()?;
        if self.commitment.header().assignment_digest() != self.assignments.assignment_digest() {
            return Err(TargetPlanV4ContractError::SliceAssignmentDigestMismatch);
        }
        Ok(())
    }
}

/// PXAR v4 request carrying an unchanged signed envelope, PXTA, and PXTE v3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApplyRequestV4 {
    envelope: RuntimeApplyEnvelope,
    slice: RuntimePlanSliceV4,
    canonical_wire: Box<[u8]>,
}

impl RuntimeApplyRequestV4 {
    /// Builds a strict v4 outer request without changing the envelope format.
    pub fn try_new(
        envelope: RuntimeApplyEnvelope,
        slice: RuntimePlanSliceV4,
    ) -> Result<Self, TargetPlanV4ContractError> {
        envelope.validate()?;
        slice.validate()?;
        if envelope.control_commitment().slice() != slice.commitment() {
            return Err(TargetPlanV4ContractError::EnvelopeSliceMismatch);
        }
        let canonical_wire = build_runtime_apply_request_v4_wire(&envelope, &slice);
        if canonical_wire.len() > MAX_RUNTIME_APPLY_REQUEST_V4_BYTES {
            return Err(TargetPlanV4ContractError::RequestFrameTooLarge);
        }
        Ok(Self {
            envelope,
            slice,
            canonical_wire: canonical_wire.into_boxed_slice(),
        })
    }

    /// Strictly decodes PXAR v4 without fallback to an earlier request version.
    pub fn decode(frame: &[u8]) -> Result<Self, RequestV4WireError> {
        decode_runtime_apply_request_v4(frame)
    }

    /// Returns the unchanged signed envelope.
    #[must_use]
    pub const fn envelope(&self) -> &RuntimeApplyEnvelope {
        &self.envelope
    }
    /// Returns the committed v4 target Slice.
    #[must_use]
    pub const fn slice(&self) -> &RuntimePlanSliceV4 {
        &self.slice
    }
    /// Returns the existing signed-envelope digest.
    #[must_use]
    pub const fn request_digest(&self) -> &Digest32 {
        self.envelope.request_digest()
    }
    /// Returns exact PXAR v4 canonical bytes.
    #[must_use]
    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }

    /// Revalidates both components and the outer canonical bytes.
    pub fn validate(&self) -> Result<(), TargetPlanV4ContractError> {
        self.envelope.validate()?;
        self.slice.validate()?;
        if self.envelope.control_commitment().slice() != self.slice.commitment() {
            return Err(TargetPlanV4ContractError::EnvelopeSliceMismatch);
        }
        if build_runtime_apply_request_v4_wire(&self.envelope, &self.slice)
            != self.canonical_wire.as_ref()
        {
            return Err(TargetPlanV4ContractError::RequestCanonicalWireMismatch);
        }
        Ok(())
    }
}

const fn valid_duration(value: BoundedDuration) -> bool {
    value.value() > 0 && value.value() <= MAX_EXECUTION_DURATION_NANOS
}

fn validate_process_execution_records(
    thread_plan: Option<&TargetExecutionPlanV2>,
    domains: &[ProcessDomainSpec],
    mailboxes: &[ProcessMailboxExecutionSpec],
) -> Result<(), ProcessExecutionContractError> {
    for (index, domain) in domains.iter().enumerate() {
        if domains
            .iter()
            .take(index)
            .any(|previous| previous.domain() == domain.domain())
        {
            return Err(ProcessExecutionContractError::DuplicateDomainRef);
        }
    }
    for (index, execution) in mailboxes.iter().enumerate() {
        for previous in mailboxes.iter().take(index) {
            if previous.binding_id() == execution.binding_id() {
                return Err(ProcessExecutionContractError::DuplicateExecutionBinding);
            }
            if previous.mailbox() == execution.mailbox() {
                return Err(ProcessExecutionContractError::DuplicateExecutionMailbox);
            }
            if previous.domain() == execution.domain()
                && !previous.same_subject_contract(*execution)
            {
                return Err(ProcessExecutionContractError::ProcessDomainSubjectMismatch);
            }
            if previous.target_instance() == execution.target_instance()
                && !previous.same_subject_contract(*execution)
            {
                return Err(ProcessExecutionContractError::ProcessSubjectMismatch);
            }
        }
        if !domains
            .iter()
            .any(|domain| domain.domain() == execution.domain())
        {
            return Err(ProcessExecutionContractError::OrphanDomainRef);
        }
    }
    for domain in domains {
        if !mailboxes
            .iter()
            .any(|execution| execution.domain() == domain.domain())
        {
            return Err(ProcessExecutionContractError::UnusedDomainRef);
        }
        validate_process_domain_utilization(*domain, mailboxes)?;
    }
    if let Some(thread_plan) = thread_plan {
        validate_prior_process_separation(thread_plan, domains, mailboxes)?;
    }
    Ok(())
}

fn validate_process_domain_utilization(
    domain: ProcessDomainSpec,
    mailboxes: &[ProcessMailboxExecutionSpec],
) -> Result<(), ProcessExecutionContractError> {
    let capacity_window = u128::from(domain.capacity().capacity_window().value());
    let mut demand = 0_u128;
    for execution in mailboxes
        .iter()
        .filter(|execution| execution.domain() == domain.domain())
    {
        let requirements = execution.requirements();
        let occupancy = u128::from(requirements.budgets().run().value())
            .checked_add(u128::from(
                requirements.budgets().cancellation_grace().value(),
            ))
            .ok_or(ProcessExecutionContractError::UtilizationOverflow)?;
        if occupancy > capacity_window {
            return Err(ProcessExecutionContractError::ExecutionBudgetExceedsDomain);
        }
        let mailbox_demand = u128::from(execution.dispatch().max_arrivals_per_window())
            .checked_mul(occupancy)
            .ok_or(ProcessExecutionContractError::UtilizationOverflow)?;
        demand = demand
            .checked_add(mailbox_demand)
            .ok_or(ProcessExecutionContractError::UtilizationOverflow)?;
    }
    let capacity = u128::from(domain.capacity().max_concurrent())
        .checked_mul(capacity_window)
        .ok_or(ProcessExecutionContractError::UtilizationOverflow)?;
    if demand > capacity {
        return Err(ProcessExecutionContractError::ProcessUtilizationExceeded);
    }
    Ok(())
}

fn validate_prior_process_separation(
    thread_plan: &TargetExecutionPlanV2,
    process_domains: &[ProcessDomainSpec],
    process_mailboxes: &[ProcessMailboxExecutionSpec],
) -> Result<(), ProcessExecutionContractError> {
    for process_domain in process_domains {
        if thread_plan.thread_domains().iter().any(|thread_domain| {
            thread_domain.domain().as_bytes() == process_domain.domain().as_bytes()
        }) {
            return Err(ProcessExecutionContractError::CrossExecutionDomain);
        }
        if thread_plan.loop_plan().is_some_and(|loop_plan| {
            loop_plan.domains().iter().any(|loop_domain| {
                loop_domain.domain().as_bytes() == process_domain.domain().as_bytes()
            })
        }) {
            return Err(ProcessExecutionContractError::CrossExecutionDomain);
        }
    }
    for process_execution in process_mailboxes {
        for thread_execution in thread_plan.thread_mailbox_executions() {
            validate_execution_identity_separation(
                process_execution,
                thread_execution.binding_id(),
                thread_execution.mailbox(),
                thread_execution.target_instance(),
            )?;
        }
        if let Some(loop_plan) = thread_plan.loop_plan() {
            for loop_execution in loop_plan.mailbox_executions() {
                validate_execution_identity_separation(
                    process_execution,
                    loop_execution.binding_id(),
                    loop_execution.mailbox(),
                    loop_execution.target_instance(),
                )?;
            }
        }
    }
    Ok(())
}

fn validate_execution_identity_separation(
    process: &ProcessMailboxExecutionSpec,
    binding_id: BindingId,
    mailbox: MailboxRef,
    target_instance: InstanceRef,
) -> Result<(), ProcessExecutionContractError> {
    if process.binding_id() == binding_id {
        return Err(ProcessExecutionContractError::CrossExecutionBinding);
    }
    if process.mailbox() == mailbox {
        return Err(ProcessExecutionContractError::CrossExecutionMailbox);
    }
    if process.target_instance() == target_instance {
        return Err(ProcessExecutionContractError::CrossExecutionInstance);
    }
    Ok(())
}

fn validate_target_plan_v4_references(
    bindings: &TargetAssignments,
    execution: &TargetExecutionPlanV3,
) -> Result<(), TargetPlanV4ContractError> {
    if bindings.as_slice().iter().any(|binding| {
        binding.delivery().overflow_policy() == OverflowPolicy::BlockUntilDeadline
            || binding.mailbox_spec().overflow_policy() == OverflowPolicy::BlockUntilDeadline
    }) {
        return Err(TargetPlanV4ContractError::BlockUntilDeadlineForbidden);
    }
    if let Some(thread_plan) = execution.thread_plan() {
        TargetPlanAssignmentsV3::try_new(bindings.clone(), thread_plan.clone())
            .map_err(TargetPlanV4ContractError::EmbeddedThreadTargetPlan)?;
    }
    for process in execution.process_mailbox_executions() {
        let Some(binding) = bindings
            .as_slice()
            .iter()
            .find(|binding| binding.binding_id() == process.binding_id())
        else {
            return Err(TargetPlanV4ContractError::OrphanBinding);
        };
        if binding.mailbox() != process.mailbox() {
            return Err(TargetPlanV4ContractError::BindingMailboxMismatch);
        }
        if binding.target_instance() != process.target_instance() {
            return Err(TargetPlanV4ContractError::BindingTargetMismatch);
        }
        let domain = execution
            .process_domains()
            .iter()
            .find(|domain| domain.domain() == process.domain())
            .ok_or(TargetPlanV4ContractError::OrphanProcessDomain)?;
        let max_payload = binding.delivery().max_payload_bytes();
        if max_payload > MAX_PROCESS_IPC_PAYLOAD_BYTES
            || max_payload > domain.capacity().ipc_credit_bytes()
            || max_payload > domain.capacity().max_retained_bytes()
            || u64::from(
                process
                    .requirements()
                    .budgets()
                    .max_terminal_payload_bytes(),
            ) > domain.capacity().ipc_credit_bytes()
        {
            return Err(TargetPlanV4ContractError::BindingPayloadExceedsIpcFrame);
        }
        if binding.mailbox_spec().max_inflight() > domain.capacity().max_outstanding()
            || binding.mailbox_spec().max_inflight() > domain.capacity().ipc_credit_items()
        {
            return Err(TargetPlanV4ContractError::BindingInflightExceedsCredit);
        }
    }
    Ok(())
}

fn digest_target_execution_v3(
    canonical_wire: &[u8],
) -> Result<TargetExecutionDigestV3, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TARGET_EXECUTION_V3_DIGEST_DOMAIN)?;
    builder.field_bytes(canonical_wire)?;
    Ok(TargetExecutionDigestV3::new(builder.finish()))
}

fn digest_target_plan_assignments_v4(
    bindings: &TargetAssignments,
    execution: &TargetExecutionPlanV3,
) -> Result<TargetAssignmentDigest, DigestBuildError> {
    let mut builder = Digest32Builder::try_new(TARGET_PLAN_ASSIGNMENTS_V4_DIGEST_DOMAIN)?;
    builder.field_bytes(bindings.assignment_digest().value().as_bytes())?;
    builder.field_bytes(execution.execution_digest().value().as_bytes())?;
    Ok(TargetAssignmentDigest::new(builder.finish()))
}

fn build_target_execution_v3_wire(
    thread_plan: Option<&TargetExecutionPlanV2>,
    domains: &[ProcessDomainSpec],
    mailboxes: &[ProcessMailboxExecutionSpec],
) -> Vec<u8> {
    let thread_wire = thread_plan.map_or(&[][..], TargetExecutionPlanV2::canonical_wire);
    let mut encoded = Vec::with_capacity(
        TARGET_EXECUTION_V3_HEADER_BYTES
            + thread_wire.len()
            + domains.len() * PROCESS_DOMAIN_RECORD_BYTES
            + mailboxes.len() * PROCESS_MAILBOX_EXECUTION_RECORD_BYTES,
    );
    encoded.extend_from_slice(TARGET_EXECUTION_MAGIC);
    encoded.extend_from_slice(&TARGET_EXECUTION_PLAN_V3_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(thread_wire.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(domains.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(mailboxes.len() as u32).to_be_bytes());
    encoded.extend_from_slice(thread_wire);
    for domain in domains {
        append_process_domain_record(&mut encoded, *domain);
    }
    for mailbox in mailboxes {
        append_process_mailbox_record(&mut encoded, *mailbox);
    }
    encoded
}

fn append_process_domain_record(encoded: &mut Vec<u8>, domain: ProcessDomainSpec) {
    encoded.extend_from_slice(domain.domain().as_bytes());
    let launch = domain.launch();
    encoded.extend_from_slice(launch.launch_profile().as_bytes());
    encoded.extend_from_slice(launch.launch_profile_digest().as_bytes());
    encoded.extend_from_slice(&launch.protocol_version().to_be_bytes());
    encoded.push(launch.runtime_kind() as u8);
    let versions = launch.runtime_versions();
    encoded.extend_from_slice(&versions.min_major().to_be_bytes());
    encoded.extend_from_slice(&versions.min_minor().to_be_bytes());
    encoded.extend_from_slice(&versions.max_major().to_be_bytes());
    encoded.extend_from_slice(&versions.max_minor().to_be_bytes());
    encoded.extend_from_slice(launch.target_profile().as_bytes());
    encoded.extend_from_slice(launch.target_profile_digest().as_bytes());
    encoded.extend_from_slice(launch.sandbox_profile().as_bytes());
    encoded.extend_from_slice(launch.sandbox_profile_digest().as_bytes());
    let capacity = domain.capacity();
    encoded.extend_from_slice(&capacity.max_outstanding().to_be_bytes());
    encoded.extend_from_slice(&capacity.max_concurrent().to_be_bytes());
    encoded.extend_from_slice(&capacity.capacity_window().value().to_be_bytes());
    encoded.extend_from_slice(&capacity.ipc_credit_items().to_be_bytes());
    encoded.extend_from_slice(&capacity.ipc_credit_bytes().to_be_bytes());
    encoded.extend_from_slice(&capacity.max_retained_bytes().to_be_bytes());
    let lifecycle = domain.lifecycle();
    for value in [
        lifecycle.start(),
        lifecycle.heartbeat_interval(),
        lifecycle.heartbeat_timeout(),
        lifecycle.control_response(),
        lifecycle.drain(),
        lifecycle.cooperative_stop(),
        lifecycle.terminate_grace(),
        lifecycle.kill_grace(),
        lifecycle.cleanup(),
    ] {
        encoded.extend_from_slice(&value.value().to_be_bytes());
    }
    let resources = domain.resources();
    encoded.extend_from_slice(&resources.max_memory_bytes().to_be_bytes());
    encoded.extend_from_slice(&resources.max_open_fds().to_be_bytes());
    encoded.extend_from_slice(&resources.max_process_tree_members().to_be_bytes());
    encoded.extend_from_slice(&resources.max_cpu_time().value().to_be_bytes());
    let restart = domain.restart();
    encoded.extend_from_slice(&restart.max_attempts().to_be_bytes());
    encoded.extend_from_slice(&restart.restart_window().value().to_be_bytes());
    encoded.extend_from_slice(&restart.initial_backoff().value().to_be_bytes());
    encoded.extend_from_slice(&restart.max_backoff().value().to_be_bytes());
    encoded.extend_from_slice(&restart.jitter_basis_points().to_be_bytes());
    encoded.push(domain.workspace_policy() as u8);
    encoded.push(domain.access_policy() as u8);
    encoded.push(domain.failure_containment() as u8);
}

fn append_process_mailbox_record(encoded: &mut Vec<u8>, execution: ProcessMailboxExecutionSpec) {
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
    encoded.extend_from_slice(execution.entrypoint().as_bytes());
    encoded.extend_from_slice(execution.entrypoint_digest().as_bytes());
    let requirements = execution.requirements();
    encoded.push(requirements.call_model() as u8);
    encoded.push(requirements.workload_kind() as u8);
    encoded.push(requirements.blocking_risk() as u8);
    encoded.push(requirements.run_bound_provenance() as u8);
    encoded.push(requirements.side_effect_class() as u8);
    encoded.push(requirements.replay_policy() as u8);
    let dispatch = execution.dispatch();
    encoded.push(dispatch.dispatch_class() as u8);
    encoded.extend_from_slice(&dispatch.service_cost_tokens().to_be_bytes());
    encoded.extend_from_slice(&dispatch.minimum_service_weight().to_be_bytes());
    encoded.extend_from_slice(&dispatch.max_burst().to_be_bytes());
    encoded.extend_from_slice(&dispatch.max_arrivals_per_window().to_be_bytes());
    let budgets = requirements.budgets();
    encoded.extend_from_slice(&budgets.invoke_ack().value().to_be_bytes());
    encoded.extend_from_slice(&budgets.run().value().to_be_bytes());
    encoded.extend_from_slice(&budgets.cancellation_grace().value().to_be_bytes());
    encoded.extend_from_slice(&budgets.max_terminal_payload_bytes().to_be_bytes());
}

fn build_runtime_apply_request_v4_wire(
    envelope: &RuntimeApplyEnvelope,
    slice: &RuntimePlanSliceV4,
) -> Vec<u8> {
    let bindings = slice.assignments().bindings().canonical_wire();
    let execution = slice.assignments().execution().canonical_wire();
    let mut encoded = Vec::with_capacity(
        APPLY_REQUEST_V4_HEADER_BYTES
            + envelope.canonical_wire().len()
            + bindings.len()
            + execution.len(),
    );
    encoded.extend_from_slice(RUNTIME_APPLY_REQUEST_MAGIC);
    encoded.extend_from_slice(&RUNTIME_APPLY_REQUEST_V4_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(envelope.canonical_wire().len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(bindings.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(execution.len() as u32).to_be_bytes());
    encoded.extend_from_slice(envelope.canonical_wire());
    encoded.extend_from_slice(bindings);
    encoded.extend_from_slice(execution);
    encoded
}

fn decode_target_execution_v3(
    frame: &[u8],
) -> Result<TargetExecutionPlanV3, ProcessExecutionWireError> {
    if frame.len() > MAX_TARGET_EXECUTION_PLAN_V3_BYTES {
        return Err(ProcessExecutionWireError::new(
            ProcessExecutionWireErrorCode::FrameTooLarge,
        ));
    }
    if frame.len() < TARGET_EXECUTION_V3_HEADER_BYTES {
        return Err(ProcessExecutionWireError::new(
            ProcessExecutionWireErrorCode::Truncated,
        ));
    }
    if &frame[..4] != TARGET_EXECUTION_MAGIC {
        return Err(ProcessExecutionWireError::new(
            ProcessExecutionWireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != TARGET_EXECUTION_PLAN_V3_VERSION {
        return Err(ProcessExecutionWireError::new(
            ProcessExecutionWireErrorCode::UnsupportedVersion,
        ));
    }
    let thread_length = read_u32(&frame[6..10]) as usize;
    let domain_count = read_u32(&frame[10..14]) as usize;
    let execution_count = read_u32(&frame[14..18]) as usize;
    if thread_length > MAX_TARGET_EXECUTION_PLAN_V2_BYTES {
        return Err(ProcessExecutionWireError::new(
            ProcessExecutionWireErrorCode::ThreadBodyTooLarge,
        ));
    }
    if domain_count > MAX_PROCESS_DOMAINS {
        return Err(ProcessExecutionWireError::new(
            ProcessExecutionWireErrorCode::DomainCountExceeded,
        ));
    }
    if execution_count > MAX_PROCESS_MAILBOX_EXECUTIONS {
        return Err(ProcessExecutionWireError::new(
            ProcessExecutionWireErrorCode::ExecutionCountExceeded,
        ));
    }
    let domain_bytes = domain_count
        .checked_mul(PROCESS_DOMAIN_RECORD_BYTES)
        .ok_or_else(|| {
            ProcessExecutionWireError::new(ProcessExecutionWireErrorCode::InvalidFrameLength)
        })?;
    let execution_bytes = execution_count
        .checked_mul(PROCESS_MAILBOX_EXECUTION_RECORD_BYTES)
        .ok_or_else(|| {
            ProcessExecutionWireError::new(ProcessExecutionWireErrorCode::InvalidFrameLength)
        })?;
    let expected_length = TARGET_EXECUTION_V3_HEADER_BYTES
        .checked_add(thread_length)
        .and_then(|length| length.checked_add(domain_bytes))
        .and_then(|length| length.checked_add(execution_bytes))
        .ok_or_else(|| {
            ProcessExecutionWireError::new(ProcessExecutionWireErrorCode::InvalidFrameLength)
        })?;
    if frame.len() < expected_length {
        return Err(ProcessExecutionWireError::new(
            ProcessExecutionWireErrorCode::Truncated,
        ));
    }
    if frame.len() != expected_length {
        return Err(ProcessExecutionWireError::new(
            ProcessExecutionWireErrorCode::InvalidFrameLength,
        ));
    }
    let thread_start = TARGET_EXECUTION_V3_HEADER_BYTES;
    let thread_end = thread_start + thread_length;
    let domains_end = thread_end + domain_bytes;
    let thread_plan = if thread_length == 0 {
        None
    } else {
        Some(
            TargetExecutionPlanV2::decode(&frame[thread_start..thread_end])
                .map_err(process_thread_wire_error)?,
        )
    };
    let mut domains = Vec::with_capacity(domain_count);
    for (index, record) in frame[thread_end..domains_end]
        .chunks_exact(PROCESS_DOMAIN_RECORD_BYTES)
        .enumerate()
    {
        domains.push(decode_process_domain_record(record, index as u32)?);
    }
    let mut mailboxes = Vec::with_capacity(execution_count);
    for (index, record) in frame[domains_end..]
        .chunks_exact(PROCESS_MAILBOX_EXECUTION_RECORD_BYTES)
        .enumerate()
    {
        mailboxes.push(decode_process_mailbox_record(record, index as u32)?);
    }
    let decoded = TargetExecutionPlanV3::try_new(thread_plan, domains, mailboxes)
        .map_err(process_contract_wire_error)?;
    if decoded.canonical_wire() != frame {
        return Err(ProcessExecutionWireError::new(
            ProcessExecutionWireErrorCode::NonCanonicalFrame,
        ));
    }
    Ok(decoded)
}

fn decode_process_domain_record(
    record: &[u8],
    record_index: u32,
) -> Result<ProcessDomainSpec, ProcessExecutionWireError> {
    let mut cursor = RecordCursor::new(record);
    let domain = ProcessDomainRef::from_bytes(cursor.array());
    let launch_profile = ProcessLaunchProfileRef::from_bytes(cursor.array());
    let launch_profile_digest = Digest32::from_bytes(cursor.array());
    let protocol_version = cursor.u16();
    let runtime_kind = decode_runtime_kind(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessDomain,
        record_index,
    )?;
    let versions =
        RuntimeVersionRange::try_new(cursor.u16(), cursor.u16(), cursor.u16(), cursor.u16())
            .map_err(|_| {
                process_record_error(
                    ProcessExecutionWireErrorCode::InvalidLaunchSpec,
                    ProcessExecutionRecordSection::ProcessDomain,
                    record_index,
                )
            })?;
    let target_profile = ProcessTargetProfileRef::from_bytes(cursor.array());
    let target_profile_digest = Digest32::from_bytes(cursor.array());
    let sandbox_profile = ProcessSandboxProfileRef::from_bytes(cursor.array());
    let sandbox_profile_digest = Digest32::from_bytes(cursor.array());
    let profiles = ProcessProfileSelections::new(
        launch_profile,
        launch_profile_digest,
        target_profile,
        target_profile_digest,
        sandbox_profile,
        sandbox_profile_digest,
    );
    let launch = ProcessLaunchSpec::try_new(profiles, protocol_version, runtime_kind, versions)
        .map_err(|_| {
            process_record_error(
                ProcessExecutionWireErrorCode::InvalidLaunchSpec,
                ProcessExecutionRecordSection::ProcessDomain,
                record_index,
            )
        })?;
    let capacity = ProcessCapacitySpec::try_new(
        cursor.u32(),
        cursor.u32(),
        BoundedDuration::from_nanos(cursor.u64()),
        cursor.u32(),
        cursor.u64(),
        cursor.u64(),
    )
    .map_err(|_| {
        process_record_error(
            ProcessExecutionWireErrorCode::InvalidIpcBudget,
            ProcessExecutionRecordSection::ProcessDomain,
            record_index,
        )
    })?;
    let liveness = ProcessLivenessBudgets::try_new(
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
    )
    .map_err(|_| {
        process_record_error(
            ProcessExecutionWireErrorCode::InvalidLivenessBudget,
            ProcessExecutionRecordSection::ProcessDomain,
            record_index,
        )
    })?;
    let shutdown = ProcessShutdownBudgets::try_new(
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
    )
    .map_err(|_| {
        process_record_error(
            ProcessExecutionWireErrorCode::InvalidLivenessBudget,
            ProcessExecutionRecordSection::ProcessDomain,
            record_index,
        )
    })?;
    let lifecycle = ProcessLifecycleBudgets::new(liveness, shutdown);
    let resources = ProcessResourceLimits::try_new(
        cursor.u64(),
        cursor.u32(),
        cursor.u32(),
        BoundedDuration::from_nanos(cursor.u64()),
    )
    .map_err(|_| {
        process_record_error(
            ProcessExecutionWireErrorCode::InvalidResourceBudget,
            ProcessExecutionRecordSection::ProcessDomain,
            record_index,
        )
    })?;
    let restart = ProcessRestartPolicy::try_new(
        cursor.u32(),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        cursor.u16(),
    )
    .map_err(|_| {
        process_record_error(
            ProcessExecutionWireErrorCode::InvalidRestartPolicy,
            ProcessExecutionRecordSection::ProcessDomain,
            record_index,
        )
    })?;
    let workspace_policy = decode_workspace_policy(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessDomain,
        record_index,
    )?;
    let access_policy = decode_access_policy(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessDomain,
        record_index,
    )?;
    let failure_containment = decode_failure_containment(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessDomain,
        record_index,
    )?;
    let policies = ProcessDomainPolicies::new(workspace_policy, access_policy, failure_containment);
    ProcessDomainSpec::try_new(
        domain, launch, capacity, lifecycle, resources, restart, policies,
    )
    .map_err(|_| {
        process_record_error(
            ProcessExecutionWireErrorCode::InvalidProcessDomain,
            ProcessExecutionRecordSection::ProcessDomain,
            record_index,
        )
    })
}

fn decode_process_mailbox_record(
    record: &[u8],
    record_index: u32,
) -> Result<ProcessMailboxExecutionSpec, ProcessExecutionWireError> {
    let mut cursor = RecordCursor::new(record);
    let binding_id = BindingId::from_bytes(cursor.array());
    let mailbox = MailboxRef::from_bytes(cursor.array());
    let target_instance = InstanceRef::from_bytes(cursor.array());
    let domain = ProcessDomainRef::from_bytes(cursor.array());
    let subject = CardSubjectSpec::new(
        crate::execution::CardDefinitionRef::from_bytes(cursor.array()),
        crate::execution::CardImplementationRef::from_bytes(cursor.array()),
        Digest32::from_bytes(cursor.array()),
        Digest32::from_bytes(cursor.array()),
        Digest32::from_bytes(cursor.array()),
    );
    let entrypoint = ProcessEntrypointRef::from_bytes(cursor.array());
    let entrypoint_digest = Digest32::from_bytes(cursor.array());
    let call_model = decode_call_model(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessMailbox,
        record_index,
    )?;
    let workload_kind = decode_workload_kind(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessMailbox,
        record_index,
    )?;
    let blocking_risk = decode_blocking_risk(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessMailbox,
        record_index,
    )?;
    let run_bound_provenance = decode_run_bound_provenance(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessMailbox,
        record_index,
    )?;
    let side_effect_class = decode_side_effect_class(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessMailbox,
        record_index,
    )?;
    let replay_policy = decode_replay_policy(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessMailbox,
        record_index,
    )?;
    let dispatch_class = decode_dispatch_class(
        cursor.u8(),
        ProcessExecutionRecordSection::ProcessMailbox,
        record_index,
    )?;
    let dispatch = ThreadDispatchPolicy::try_new(
        dispatch_class,
        cursor.u32(),
        cursor.u32(),
        cursor.u16(),
        cursor.u32(),
    )
    .map_err(|error| {
        let code = if error == ThreadExecutionContractError::ControlDispatchForbidden {
            ProcessExecutionWireErrorCode::UnsupportedProcessExecution
        } else {
            ProcessExecutionWireErrorCode::InvalidProcessExecution
        };
        process_record_error(
            code,
            ProcessExecutionRecordSection::ProcessMailbox,
            record_index,
        )
    })?;
    let budgets = ProcessInvocationBudgets::try_new(
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        BoundedDuration::from_nanos(cursor.u64()),
        cursor.u32(),
    )
    .map_err(|_| {
        process_record_error(
            ProcessExecutionWireErrorCode::InvalidProcessExecution,
            ProcessExecutionRecordSection::ProcessMailbox,
            record_index,
        )
    })?;
    let requirements = ProcessExecutionRequirements::new(
        call_model,
        workload_kind,
        blocking_risk,
        run_bound_provenance,
        side_effect_class,
        replay_policy,
        budgets,
    );
    let workload = ProcessWorkloadSelection::new(subject, entrypoint, entrypoint_digest);
    Ok(ProcessMailboxExecutionSpec::new(
        binding_id,
        mailbox,
        target_instance,
        domain,
        workload,
        requirements,
        dispatch,
    ))
}

fn process_record_error(
    code: ProcessExecutionWireErrorCode,
    section: ProcessExecutionRecordSection,
    record_index: u32,
) -> ProcessExecutionWireError {
    ProcessExecutionWireError::at(code, section, record_index)
}

macro_rules! decode_process_enum {
    ($name:ident, $type:ty, {$($value:literal => $variant:path),+ $(,)?}) => {
        fn $name(
            value: u8,
            section: ProcessExecutionRecordSection,
            record_index: u32,
        ) -> Result<$type, ProcessExecutionWireError> {
            match value {
                $($value => Ok($variant),)+
                _ => Err(ProcessExecutionWireError::at(
                    ProcessExecutionWireErrorCode::InvalidEnumValue,
                    section,
                    record_index,
                )),
            }
        }
    };
}

decode_process_enum!(decode_runtime_kind, WorkerRuntimeKind, {
    1 => WorkerRuntimeKind::NativeExecutable,
    2 => WorkerRuntimeKind::Python,
});
decode_process_enum!(decode_workspace_policy, WorkspacePolicy, {
    1 => WorkspacePolicy::EphemeralPerInstanceGeneration,
});
decode_process_enum!(decode_access_policy, ProcessAccessPolicy, {
    1 => ProcessAccessPolicy::NoRawHostAccess,
});
decode_process_enum!(decode_failure_containment, FailureContainmentPolicy, {
    1 => FailureContainmentPolicy::WholeProcessDomain,
});
decode_process_enum!(decode_side_effect_class, SideEffectClass, {
    1 => SideEffectClass::EffectFree,
    2 => SideEffectClass::External,
    3 => SideEffectClass::Unknown,
});
decode_process_enum!(decode_replay_policy, InvocationReplayPolicy, {
    1 => InvocationReplayPolicy::NoReplay,
});
decode_process_enum!(decode_call_model, CallModel, {
    1 => CallModel::CooperativeAsync,
    2 => CallModel::Synchronous,
    3 => CallModel::Unknown,
});
decode_process_enum!(decode_workload_kind, WorkloadKind, {
    1 => WorkloadKind::Io,
    2 => WorkloadKind::Routing,
    3 => WorkloadKind::Cpu,
    4 => WorkloadKind::Native,
    5 => WorkloadKind::Device,
    6 => WorkloadKind::Unknown,
});
decode_process_enum!(decode_blocking_risk, BlockingRisk, {
    1 => BlockingRisk::None,
    2 => BlockingRisk::Bounded,
    3 => BlockingRisk::Unknown,
});
decode_process_enum!(decode_run_bound_provenance, RunBoundProvenance, {
    1 => RunBoundProvenance::Declared,
    2 => RunBoundProvenance::Measured,
    3 => RunBoundProvenance::Certified,
    4 => RunBoundProvenance::Unknown,
});
decode_process_enum!(decode_dispatch_class, DispatchClass, {
    1 => DispatchClass::Control,
    2 => DispatchClass::Interactive,
    3 => DispatchClass::Stream,
    4 => DispatchClass::Background,
});

fn decode_runtime_apply_request_v4(
    frame: &[u8],
) -> Result<RuntimeApplyRequestV4, RequestV4WireError> {
    if frame.len() > MAX_RUNTIME_APPLY_REQUEST_V4_BYTES {
        return Err(RequestV4WireError::new(
            RequestV4WireErrorCode::FrameTooLarge,
        ));
    }
    if frame.len() < APPLY_REQUEST_V4_HEADER_BYTES {
        return Err(RequestV4WireError::new(RequestV4WireErrorCode::Truncated));
    }
    if &frame[..4] != RUNTIME_APPLY_REQUEST_MAGIC {
        return Err(RequestV4WireError::new(
            RequestV4WireErrorCode::InvalidMagic,
        ));
    }
    if read_u16(&frame[4..6]) != RUNTIME_APPLY_REQUEST_V4_VERSION {
        return Err(RequestV4WireError::new(
            RequestV4WireErrorCode::UnsupportedVersion,
        ));
    }
    let envelope_length = read_u32(&frame[6..10]) as usize;
    let bindings_length = read_u32(&frame[10..14]) as usize;
    let execution_length = read_u32(&frame[14..18]) as usize;
    let expected_length = APPLY_REQUEST_V4_HEADER_BYTES
        .checked_add(envelope_length)
        .and_then(|length| length.checked_add(bindings_length))
        .and_then(|length| length.checked_add(execution_length))
        .ok_or_else(|| RequestV4WireError::new(RequestV4WireErrorCode::InvalidFrameLength))?;
    if frame.len() < expected_length {
        return Err(RequestV4WireError::new(RequestV4WireErrorCode::Truncated));
    }
    if frame.len() != expected_length {
        return Err(RequestV4WireError::new(
            RequestV4WireErrorCode::InvalidFrameLength,
        ));
    }
    let envelope_start = APPLY_REQUEST_V4_HEADER_BYTES;
    let envelope_end = envelope_start + envelope_length;
    let bindings_end = envelope_end + bindings_length;
    let envelope = RuntimeApplyEnvelope::decode(&frame[envelope_start..envelope_end])
        .map_err(request_v4_envelope_wire_error)?;
    let bindings = TargetAssignments::decode(&frame[envelope_end..bindings_end])
        .map_err(request_v4_bindings_wire_error)?;
    let execution = TargetExecutionPlanV3::decode(&frame[bindings_end..])
        .map_err(request_v4_execution_wire_error)?;
    let assignments = TargetPlanAssignmentsV4::try_new(bindings, execution)
        .map_err(request_v4_target_plan_error)?;
    let slice = RuntimePlanSliceV4::try_new(envelope.control_commitment().slice(), assignments)
        .map_err(|_| RequestV4WireError::new(RequestV4WireErrorCode::CommitmentMismatch))?;
    RuntimeApplyRequestV4::try_new(envelope, slice)
        .map_err(|_| RequestV4WireError::new(RequestV4WireErrorCode::CommitmentMismatch))
}

fn request_v4_envelope_wire_error(error: WireError) -> RequestV4WireError {
    RequestV4WireError::with_detail(
        RequestV4WireErrorCode::EnvelopeRejected,
        error.code() as u16,
    )
}

fn request_v4_bindings_wire_error(error: AssignmentWireError) -> RequestV4WireError {
    RequestV4WireError::with_detail(
        RequestV4WireErrorCode::BindingsRejected,
        error.code() as u16,
    )
}

fn request_v4_execution_wire_error(error: ProcessExecutionWireError) -> RequestV4WireError {
    RequestV4WireError::with_detail(
        RequestV4WireErrorCode::ExecutionRejected,
        error.code() as u16,
    )
}

fn request_v4_target_plan_error(error: TargetPlanV4ContractError) -> RequestV4WireError {
    let code = match error {
        TargetPlanV4ContractError::OrphanBinding => TargetPlanV4WireErrorCode::OrphanBinding,
        TargetPlanV4ContractError::BindingMailboxMismatch => {
            TargetPlanV4WireErrorCode::BindingMailboxMismatch
        }
        TargetPlanV4ContractError::BindingTargetMismatch => {
            TargetPlanV4WireErrorCode::BindingTargetMismatch
        }
        TargetPlanV4ContractError::BlockUntilDeadlineForbidden => {
            TargetPlanV4WireErrorCode::BlockUntilDeadlineForbidden
        }
        TargetPlanV4ContractError::BindingPayloadExceedsIpcFrame => {
            TargetPlanV4WireErrorCode::BindingPayloadExceedsIpcFrame
        }
        TargetPlanV4ContractError::BindingInflightExceedsCredit => {
            TargetPlanV4WireErrorCode::BindingInflightExceedsCredit
        }
        _ => TargetPlanV4WireErrorCode::InvalidTargetPlan,
    };
    RequestV4WireError::with_detail(RequestV4WireErrorCode::TargetPlanRejected, code as u16)
}

fn process_thread_wire_error(error: ThreadExecutionWireError) -> ProcessExecutionWireError {
    ProcessExecutionWireError::with_detail(
        ProcessExecutionWireErrorCode::ThreadExecutionRejected,
        ProcessExecutionRecordSection::ThreadBody,
        0,
        error.code() as u16,
    )
}

fn process_contract_wire_error(error: ProcessExecutionContractError) -> ProcessExecutionWireError {
    let code = match error {
        ProcessExecutionContractError::InvalidLaunchSpec => {
            ProcessExecutionWireErrorCode::InvalidLaunchSpec
        }
        ProcessExecutionContractError::InvalidIpcBudget => {
            ProcessExecutionWireErrorCode::InvalidIpcBudget
        }
        ProcessExecutionContractError::InvalidLivenessBudget => {
            ProcessExecutionWireErrorCode::InvalidLivenessBudget
        }
        ProcessExecutionContractError::InvalidResourceBudget => {
            ProcessExecutionWireErrorCode::InvalidResourceBudget
        }
        ProcessExecutionContractError::InvalidRestartPolicy => {
            ProcessExecutionWireErrorCode::InvalidRestartPolicy
        }
        ProcessExecutionContractError::DomainCountExceeded => {
            ProcessExecutionWireErrorCode::DomainCountExceeded
        }
        ProcessExecutionContractError::ExecutionCountExceeded => {
            ProcessExecutionWireErrorCode::ExecutionCountExceeded
        }
        ProcessExecutionContractError::MissingProcessDomain
        | ProcessExecutionContractError::MissingProcessMailboxExecution => {
            ProcessExecutionWireErrorCode::MissingRecords
        }
        ProcessExecutionContractError::DuplicateDomainRef => {
            ProcessExecutionWireErrorCode::DuplicateDomainRef
        }
        ProcessExecutionContractError::DuplicateExecutionBinding => {
            ProcessExecutionWireErrorCode::DuplicateExecutionBinding
        }
        ProcessExecutionContractError::DuplicateExecutionMailbox => {
            ProcessExecutionWireErrorCode::DuplicateExecutionMailbox
        }
        ProcessExecutionContractError::OrphanDomainRef => {
            ProcessExecutionWireErrorCode::OrphanDomainRef
        }
        ProcessExecutionContractError::UnusedDomainRef => {
            ProcessExecutionWireErrorCode::UnusedDomainRef
        }
        ProcessExecutionContractError::ExecutionBudgetExceedsDomain => {
            ProcessExecutionWireErrorCode::InvalidLivenessBudget
        }
        ProcessExecutionContractError::ProcessUtilizationExceeded
        | ProcessExecutionContractError::UtilizationOverflow => {
            ProcessExecutionWireErrorCode::ProcessUtilizationExceeded
        }
        ProcessExecutionContractError::CrossExecutionDomain
        | ProcessExecutionContractError::CrossExecutionBinding
        | ProcessExecutionContractError::CrossExecutionMailbox
        | ProcessExecutionContractError::CrossExecutionInstance => {
            ProcessExecutionWireErrorCode::CrossExecutionConflict
        }
        ProcessExecutionContractError::ProcessSubjectMismatch => {
            ProcessExecutionWireErrorCode::ProcessSubjectMismatch
        }
        ProcessExecutionContractError::ProcessDomainSubjectMismatch => {
            ProcessExecutionWireErrorCode::ProcessSubjectMismatch
        }
        _ => ProcessExecutionWireErrorCode::InvalidProcessExecution,
    };
    ProcessExecutionWireError::new(code)
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

/// Fail-closed construction errors for PXTE v3 Process execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessExecutionContractError {
    /// The launch profile, protocol, runtime, target, or sandbox choice is invalid.
    InvalidLaunchSpec,
    /// Outstanding, concurrency, IPC credit, or retention bounds are inconsistent.
    InvalidIpcBudget,
    /// A process lifecycle or heartbeat budget is invalid.
    InvalidLivenessBudget,
    /// A process memory, descriptor, tree, or CPU ceiling is invalid.
    InvalidResourceBudget,
    /// A restart attempt, window, backoff, or jitter bound is invalid.
    InvalidRestartPolicy,
    /// Per-invocation acknowledgement, run, cancellation, or terminal bounds are invalid.
    InvalidInvocationBudget,
    /// The optional embedded PXTE v2 body is invalid.
    ThreadExecution(ThreadExecutionContractError),
    /// The ProcessDomain record count exceeds the fixed bound.
    DomainCountExceeded,
    /// The Process Mailbox record count exceeds the fixed bound.
    ExecutionCountExceeded,
    /// No ProcessDomain record was supplied.
    MissingProcessDomain,
    /// No process Mailbox execution record was supplied.
    MissingProcessMailboxExecution,
    /// Two ProcessDomain records share one identity.
    DuplicateDomainRef,
    /// Two process execution records share one BindingId.
    DuplicateExecutionBinding,
    /// Two process execution records share one Mailbox.
    DuplicateExecutionMailbox,
    /// A process execution references no declared ProcessDomain.
    OrphanDomainRef,
    /// A declared ProcessDomain has no execution record.
    UnusedDomainRef,
    /// Two Mailboxes for one instance disagree on process subject identity.
    ProcessSubjectMismatch,
    /// One ProcessDomain is assigned to more than one target instance or subject.
    ProcessDomainSubjectMismatch,
    /// A prior Loop/Thread and Process domain share opaque identity bytes.
    CrossExecutionDomain,
    /// A BindingId is assigned to both a prior execution class and Process.
    CrossExecutionBinding,
    /// A Mailbox is assigned to both a prior execution class and Process.
    CrossExecutionMailbox,
    /// A target instance is assigned across prior and Process execution classes.
    CrossExecutionInstance,
    /// One invocation occupancy exceeds its ProcessDomain capacity window.
    ExecutionBudgetExceedsDomain,
    /// Checked ProcessDomain demand exceeds its concurrency capacity.
    ProcessUtilizationExceeded,
    /// A checked utilization calculation overflowed.
    UtilizationOverflow,
    /// Canonical digest construction failed.
    Digest(DigestBuildError),
    /// Stored canonical bytes differ from rebuilt values.
    CanonicalWireMismatch,
    /// Stored PXTE v3 digest differs from rebuilt bytes.
    ExecutionDigestMismatch,
}

impl From<DigestBuildError> for ProcessExecutionContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for ProcessExecutionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Process execution contract error {self:?}")
    }
}

impl std::error::Error for ProcessExecutionContractError {}

/// Fail-closed construction errors for composite v4 target plans and requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetPlanV4ContractError {
    /// The PXTA body was invalid.
    Bindings(AssignmentContractError),
    /// The additive PXTE v3 body was invalid.
    ProcessExecution(ProcessExecutionContractError),
    /// The embedded PXTE v2 plan failed its existing cross-body validation.
    EmbeddedThreadTargetPlan(TargetPlanV3ContractError),
    /// A Process execution has no exact PXTA BindingId.
    OrphanBinding,
    /// A Process execution Mailbox differs from its exact PXTA binding.
    BindingMailboxMismatch,
    /// A Process execution target differs from its exact PXTA binding.
    BindingTargetMismatch,
    /// A process execution unexpectedly references no validated ProcessDomain.
    OrphanProcessDomain,
    /// Runtime execution plans cannot block an executor on Mailbox pressure.
    BlockUntilDeadlineForbidden,
    /// A binding or terminal payload exceeds the fixed process IPC/credit bound.
    BindingPayloadExceedsIpcFrame,
    /// A PXTA in-flight bound exceeds the ProcessDomain item credit.
    BindingInflightExceedsCredit,
    /// The stored v4 composite digest differs from both canonical bodies.
    CompositeDigestMismatch,
    /// The Slice header does not commit the v4 composite digest.
    SliceAssignmentDigestMismatch,
    /// The signed envelope carries a different Slice commitment.
    EnvelopeSliceMismatch,
    /// Slice provenance validation failed.
    Provenance(ProvenanceContractError),
    /// Signed-envelope validation failed.
    Envelope(EnvelopeContractError),
    /// Canonical digest construction failed.
    Digest(DigestBuildError),
    /// The PXAR v4 frame exceeds its fixed bound.
    RequestFrameTooLarge,
    /// Stored PXAR v4 bytes differ from rebuilt values.
    RequestCanonicalWireMismatch,
}

impl From<AssignmentContractError> for TargetPlanV4ContractError {
    fn from(value: AssignmentContractError) -> Self {
        Self::Bindings(value)
    }
}

impl From<ProcessExecutionContractError> for TargetPlanV4ContractError {
    fn from(value: ProcessExecutionContractError) -> Self {
        Self::ProcessExecution(value)
    }
}

impl From<ProvenanceContractError> for TargetPlanV4ContractError {
    fn from(value: ProvenanceContractError) -> Self {
        Self::Provenance(value)
    }
}

impl From<EnvelopeContractError> for TargetPlanV4ContractError {
    fn from(value: EnvelopeContractError) -> Self {
        Self::Envelope(value)
    }
}

impl From<DigestBuildError> for TargetPlanV4ContractError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for TargetPlanV4ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v4 target plan contract error {self:?}")
    }
}

impl std::error::Error for TargetPlanV4ContractError {}

/// Identifies the PXTE v3 subsection containing a wire error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProcessExecutionRecordSection {
    /// Embedded, unchanged PXTE v2 Loop/Thread body.
    ThreadBody = 1,
    /// Fixed ProcessDomain record section.
    ProcessDomain = 2,
    /// Fixed Process Mailbox execution record section.
    ProcessMailbox = 3,
}

/// Stable machine-readable PXTE v3 rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ProcessExecutionWireErrorCode {
    /// The frame exceeds its fixed pre-parse bound.
    FrameTooLarge = 1,
    /// The frame ends before all declared bytes.
    Truncated = 2,
    /// The PXTE magic is invalid.
    InvalidMagic = 3,
    /// Only PXTE version 3 is accepted.
    UnsupportedVersion = 4,
    /// The embedded PXTE v2 body exceeds its bound.
    ThreadBodyTooLarge = 5,
    /// The ProcessDomain count exceeds its bound.
    DomainCountExceeded = 6,
    /// The process execution count exceeds its bound.
    ExecutionCountExceeded = 7,
    /// Declared lengths do not equal exact frame length.
    InvalidFrameLength = 8,
    /// The embedded PXTE v2 decoder rejected the prior body.
    ThreadExecutionRejected = 9,
    /// A fixed record carries an unknown enum discriminant.
    InvalidEnumValue = 10,
    /// A process launch record is invalid.
    InvalidLaunchSpec = 11,
    /// A ProcessDomain record is invalid.
    InvalidProcessDomain = 12,
    /// A process Mailbox execution record is invalid.
    InvalidProcessExecution = 13,
    /// Two ProcessDomain records share an identity.
    DuplicateDomainRef = 14,
    /// Two process execution records share a BindingId.
    DuplicateExecutionBinding = 15,
    /// Two process execution records share a Mailbox.
    DuplicateExecutionMailbox = 16,
    /// A process execution references no domain.
    OrphanDomainRef = 17,
    /// A ProcessDomain has no execution record.
    UnusedDomainRef = 18,
    /// The execution requests a dispatch or replay behavior not admitted in v1.
    UnsupportedProcessExecution = 19,
    /// IPC credits, retention, or outstanding bounds are invalid.
    InvalidIpcBudget = 20,
    /// Lifecycle, heartbeat, or invocation occupancy bounds are invalid.
    InvalidLivenessBudget = 21,
    /// Static process resource bounds are invalid.
    InvalidResourceBudget = 22,
    /// The process restart policy is invalid.
    InvalidRestartPolicy = 23,
    /// ProcessDomain demand exceeds declared concurrency capacity.
    ProcessUtilizationExceeded = 24,
    /// Prior Loop/Thread and Process execution identities overlap.
    CrossExecutionConflict = 25,
    /// Mailboxes for one target instance disagree on subject execution identity.
    ProcessSubjectMismatch = 26,
    /// Required Process records are absent.
    MissingRecords = 27,
    /// Record ordering or bytes are not canonical.
    NonCanonicalFrame = 28,
}

/// PXTE v3 rejection with optional section, record index, and nested v2 code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessExecutionWireError {
    code: ProcessExecutionWireErrorCode,
    section: Option<ProcessExecutionRecordSection>,
    record_index: Option<u32>,
    detail_code: Option<u16>,
}

impl ProcessExecutionWireError {
    const fn new(code: ProcessExecutionWireErrorCode) -> Self {
        Self {
            code,
            section: None,
            record_index: None,
            detail_code: None,
        }
    }

    const fn at(
        code: ProcessExecutionWireErrorCode,
        section: ProcessExecutionRecordSection,
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
        code: ProcessExecutionWireErrorCode,
        section: ProcessExecutionRecordSection,
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
    pub const fn code(self) -> ProcessExecutionWireErrorCode {
        self.code
    }
    /// Returns the rejected subsection, when record-local.
    #[must_use]
    pub const fn section(self) -> Option<ProcessExecutionRecordSection> {
        self.section
    }
    /// Returns the zero-based record index, when record-local.
    #[must_use]
    pub const fn record_index(self) -> Option<u32> {
        self.record_index
    }
    /// Returns a nested PXTE v2 error code for an embedded rejection.
    #[must_use]
    pub const fn detail_code(self) -> Option<u16> {
        self.detail_code
    }
}

impl fmt::Display for ProcessExecutionWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PXTE v3 wire error {:?}", self.code)
    }
}

impl std::error::Error for ProcessExecutionWireError {}

/// Stable cross-body detail reason for a PXAR v4 rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum TargetPlanV4WireErrorCode {
    /// A Process execution has no exact PXTA BindingId.
    OrphanBinding = 1,
    /// A Process execution Mailbox differs from PXTA.
    BindingMailboxMismatch = 2,
    /// A Process execution target differs from PXTA.
    BindingTargetMismatch = 3,
    /// A PXTA binding requests executor blocking pressure.
    BlockUntilDeadlineForbidden = 4,
    /// A binding or terminal payload exceeds IPC frame/byte credit.
    BindingPayloadExceedsIpcFrame = 5,
    /// A Mailbox in-flight bound exceeds ProcessDomain item credit.
    BindingInflightExceedsCredit = 6,
    /// Another semantic target-plan rule failed.
    InvalidTargetPlan = 7,
}

/// Stable machine-readable PXAR v4 rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RequestV4WireErrorCode {
    /// The frame exceeds its fixed pre-parse bound.
    FrameTooLarge = 1,
    /// The frame ends before all declared bytes.
    Truncated = 2,
    /// The PXAR magic is invalid.
    InvalidMagic = 3,
    /// Only PXAR version 4 is accepted.
    UnsupportedVersion = 4,
    /// Declared component lengths do not equal exact frame length.
    InvalidFrameLength = 5,
    /// The unchanged envelope decoder rejected its body.
    EnvelopeRejected = 6,
    /// The PXTA decoder rejected its body.
    BindingsRejected = 7,
    /// The PXTE v3 decoder rejected its body.
    ExecutionRejected = 8,
    /// Exact PXTA-to-execution semantic validation failed.
    TargetPlanRejected = 9,
    /// The signed Slice commitment does not match the bodies.
    CommitmentMismatch = 10,
}

/// PXAR v4 rejection with an optional nested stable reason code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestV4WireError {
    code: RequestV4WireErrorCode,
    detail_code: Option<u16>,
}

impl RequestV4WireError {
    const fn new(code: RequestV4WireErrorCode) -> Self {
        Self {
            code,
            detail_code: None,
        }
    }
    const fn with_detail(code: RequestV4WireErrorCode, detail_code: u16) -> Self {
        Self {
            code,
            detail_code: Some(detail_code),
        }
    }
    /// Returns the stable top-level reason.
    #[must_use]
    pub const fn code(self) -> RequestV4WireErrorCode {
        self.code
    }
    /// Returns the nested decoder or semantic reason, when present.
    #[must_use]
    pub const fn detail_code(self) -> Option<u16> {
        self.detail_code
    }
}

impl fmt::Display for RequestV4WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PXAR v4 wire error {:?}", self.code)
    }
}

impl std::error::Error for RequestV4WireError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::time::BoundedDuration;

    use crate::assignment::{BindingId, InstanceRef, MailboxRef};
    use crate::execution::{
        BlockingRisk, CallModel, CardDefinitionRef, CardImplementationRef, CardSubjectSpec,
        DispatchClass, RunBoundProvenance, WorkloadKind,
    };
    use crate::thread_execution::{TargetExecutionPlanV2, ThreadDispatchPolicy};

    use super::*;

    fn duration(nanos: u64) -> BoundedDuration {
        BoundedDuration::from_nanos(nanos)
    }

    fn sample_domain(byte: u8, capacity_window: u64, max_concurrent: u32) -> ProcessDomainSpec {
        let profiles = ProcessProfileSelections::new(
            ProcessLaunchProfileRef::from_bytes([byte.wrapping_add(1); 16]),
            Digest32::from_bytes([byte.wrapping_add(2); 32]),
            ProcessTargetProfileRef::from_bytes([byte.wrapping_add(3); 16]),
            Digest32::from_bytes([byte.wrapping_add(4); 32]),
            ProcessSandboxProfileRef::from_bytes([byte.wrapping_add(5); 16]),
            Digest32::from_bytes([byte.wrapping_add(6); 32]),
        );
        let launch = ProcessLaunchSpec::try_new(
            profiles,
            1,
            WorkerRuntimeKind::Python,
            RuntimeVersionRange::try_new(3, 11, 3, 13).unwrap(),
        )
        .unwrap();
        let capacity = ProcessCapacitySpec::try_new(
            8,
            max_concurrent,
            duration(capacity_window),
            8,
            4_096,
            8_192,
        )
        .unwrap();
        let liveness = ProcessLivenessBudgets::try_new(
            duration(100),
            duration(10),
            duration(30),
            duration(20),
        )
        .unwrap();
        let shutdown = ProcessShutdownBudgets::try_new(
            duration(100),
            duration(100),
            duration(100),
            duration(100),
            duration(100),
        )
        .unwrap();
        let lifecycle = ProcessLifecycleBudgets::new(liveness, shutdown);
        let resources = ProcessResourceLimits::try_new(65_536, 32, 4, duration(100_000)).unwrap();
        let restart =
            ProcessRestartPolicy::try_new(3, duration(10_000), duration(100), duration(1_000), 50)
                .unwrap();
        let policies = ProcessDomainPolicies::new(
            WorkspacePolicy::EphemeralPerInstanceGeneration,
            ProcessAccessPolicy::NoRawHostAccess,
            FailureContainmentPolicy::WholeProcessDomain,
        );
        ProcessDomainSpec::try_new(
            ProcessDomainRef::from_bytes([byte; 16]),
            launch,
            capacity,
            lifecycle,
            resources,
            restart,
            policies,
        )
        .unwrap()
    }

    fn sample_mailbox(
        identities: [u8; 5],
        run_nanos: u64,
        cancellation_nanos: u64,
        arrivals: u32,
    ) -> ProcessMailboxExecutionSpec {
        let [binding, mailbox, instance, domain, entrypoint] = identities;
        let subject = CardSubjectSpec::new(
            CardDefinitionRef::from_bytes([0x31; 16]),
            CardImplementationRef::from_bytes([0x32; 16]),
            Digest32::from_bytes([0x33; 32]),
            Digest32::from_bytes([0x34; 32]),
            Digest32::from_bytes([0x35; 32]),
        );
        let budgets = ProcessInvocationBudgets::try_new(
            duration(10),
            duration(run_nanos),
            duration(cancellation_nanos),
            128,
        )
        .unwrap();
        let requirements = ProcessExecutionRequirements::new(
            CallModel::Synchronous,
            WorkloadKind::Native,
            BlockingRisk::Unknown,
            RunBoundProvenance::Unknown,
            SideEffectClass::Unknown,
            InvocationReplayPolicy::NoReplay,
            budgets,
        );
        let dispatch =
            ThreadDispatchPolicy::try_new(DispatchClass::Background, 5, 2, 2, arrivals).unwrap();
        let workload = ProcessWorkloadSelection::new(
            subject,
            ProcessEntrypointRef::from_bytes([entrypoint; 16]),
            Digest32::from_bytes([entrypoint.wrapping_add(1); 32]),
        );
        ProcessMailboxExecutionSpec::new(
            BindingId::from_bytes([binding; 16]),
            MailboxRef::from_bytes([mailbox; 16]),
            InstanceRef::from_bytes([instance; 16]),
            ProcessDomainRef::from_bytes([domain; 16]),
            workload,
            requirements,
            dispatch,
        )
    }

    fn sample_plan() -> TargetExecutionPlanV3 {
        TargetExecutionPlanV3::try_new(
            None,
            vec![sample_domain(0x71, 1_000_000, 2)],
            vec![sample_mailbox([0x11, 0x21, 0x41, 0x71, 0x51], 100, 100, 2)],
        )
        .unwrap()
    }

    fn fixture_hex_from(document: &str, field: &str) -> Vec<u8> {
        let marker = format!("\"{field}\": \"");
        let start = document.find(&marker).unwrap() + marker.len();
        let end = start + document[start..].find('"').unwrap();
        let hex = &document[start..end];
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap() as u8;
                let low = (pair[1] as char).to_digit(16).unwrap() as u8;
                (high << 4) | low
            })
            .collect()
    }

    fn fixture_hex(field: &str) -> Vec<u8> {
        fixture_hex_from(
            include_str!("../../../tests/fixtures/wire/s5_runtime_apply_request_v3.json"),
            field,
        )
    }

    #[test]
    fn maximum_sizes_match_fixed_record_arithmetic() {
        assert_eq!(MAX_TARGET_EXECUTION_PLAN_V3_BYTES, 224_058);
        assert_eq!(MAX_RUNTIME_APPLY_REQUEST_V4_BYTES, 293_718);
        assert_eq!(PROCESS_DOMAIN_RECORD_BYTES, 336);
        assert_eq!(PROCESS_MAILBOX_EXECUTION_RECORD_BYTES, 289);
        assert_eq!(MAX_PROCESS_WORKER_PAYLOAD_BYTES, 1_048_404);
        assert_eq!(PROCESS_WORKER_PROTOCOL_VERSION, 1);
        assert_eq!(MAX_PROCESS_WORKER_CREDITS, 4_096);
        assert_eq!(MAX_PROCESS_WORKER_RETAINED_BYTES, 4_294_967_296);
    }

    #[test]
    fn process_only_plan_round_trips_and_commits_exact_bytes() {
        let plan = sample_plan();
        assert_eq!(plan.canonical_wire().len(), 643);
        assert_eq!(&plan.canonical_wire()[..6], b"PXTE\0\x03");
        assert_eq!(
            TargetExecutionPlanV3::decode(plan.canonical_wire()).unwrap(),
            plan
        );
        assert_eq!(
            plan.execution_digest(),
            TargetExecutionPlanV3::decode(plan.canonical_wire())
                .unwrap()
                .execution_digest()
        );
    }

    #[test]
    fn independent_python_pxar_v4_golden_decodes_byte_exactly() {
        let document =
            include_str!("../../../tests/fixtures/wire/s6_runtime_apply_request_v4.json");
        let outer = fixture_hex_from(document, "outer_wire_hex");
        let request = RuntimeApplyRequestV4::decode(&outer).expect("independent PXAR v4 golden");
        assert_eq!(request.canonical_wire(), outer);
        assert_eq!(request.canonical_wire().len(), 2_962);
        let execution = request.slice().assignments().execution();
        assert_eq!(
            execution.execution_digest().value().as_bytes().as_slice(),
            fixture_hex_from(document, "pxte_v3_digest_hex")
        );
        assert_eq!(
            request
                .slice()
                .assignments()
                .assignment_digest()
                .value()
                .as_bytes()
                .as_slice(),
            fixture_hex_from(document, "composite_v4_digest_hex")
        );
        assert_eq!(
            request.request_digest().as_bytes().as_slice(),
            fixture_hex_from(document, "request_digest_hex")
        );
        assert_eq!(
            execution
                .thread_plan()
                .expect("embedded PXTE v2")
                .canonical_wire(),
            fixture_hex_from(document, "embedded_pxte_v2_body_hex")
        );
    }

    #[test]
    fn byte_exact_pxte_v2_embedding_round_trips() {
        let pxte_v2 = fixture_hex("pxte_v2_body_hex");
        let prior = TargetExecutionPlanV2::decode(&pxte_v2).unwrap();
        let plan = TargetExecutionPlanV3::try_new(
            Some(prior),
            vec![sample_domain(0xd1, 1_000_000, 2)],
            vec![sample_mailbox([0xd2, 0xd3, 0xd4, 0xd1, 0xd5], 100, 100, 2)],
        )
        .unwrap();
        assert_eq!(
            read_u32(&plan.canonical_wire()[6..10]) as usize,
            pxte_v2.len()
        );
        assert_eq!(&plan.canonical_wire()[18..18 + pxte_v2.len()], pxte_v2);
        let decoded = TargetExecutionPlanV3::decode(plan.canonical_wire()).unwrap();
        assert_eq!(decoded.thread_plan().unwrap().canonical_wire(), pxte_v2);
    }

    #[test]
    fn decoder_is_strictly_v3_and_no_replay() {
        let plan = sample_plan();
        let mut prior_version = plan.canonical_wire().to_vec();
        prior_version[5] = 2;
        assert_eq!(
            TargetExecutionPlanV3::decode(&prior_version)
                .unwrap_err()
                .code(),
            ProcessExecutionWireErrorCode::UnsupportedVersion,
        );
        let mut replay = plan.canonical_wire().to_vec();
        let replay_offset =
            TARGET_EXECUTION_V3_HEADER_BYTES + PROCESS_DOMAIN_RECORD_BYTES + 64 + 128 + 48 + 5;
        replay[replay_offset] = 2;
        let error = TargetExecutionPlanV3::decode(&replay).unwrap_err();
        assert_eq!(
            error.code(),
            ProcessExecutionWireErrorCode::InvalidEnumValue
        );
        assert_eq!(
            error.section(),
            Some(ProcessExecutionRecordSection::ProcessMailbox)
        );
        assert_eq!(error.record_index(), Some(0));

        let mut future_protocol = plan.canonical_wire().to_vec();
        let protocol_offset = TARGET_EXECUTION_V3_HEADER_BYTES + 16 + 16 + 32;
        future_protocol[protocol_offset..protocol_offset + 2].copy_from_slice(&2_u16.to_be_bytes());
        let error = TargetExecutionPlanV3::decode(&future_protocol).unwrap_err();
        assert_eq!(
            error.code(),
            ProcessExecutionWireErrorCode::InvalidLaunchSpec
        );
        assert_eq!(
            error.section(),
            Some(ProcessExecutionRecordSection::ProcessDomain)
        );
    }

    #[test]
    fn canonical_sorting_and_noncanonical_wire_are_enforced() {
        let plan = TargetExecutionPlanV3::try_new(
            None,
            vec![
                sample_domain(0x72, 1_000_000, 2),
                sample_domain(0x71, 1_000_000, 2),
            ],
            vec![
                sample_mailbox([0x12, 0x22, 0x42, 0x72, 0x52], 100, 100, 2),
                sample_mailbox([0x11, 0x21, 0x41, 0x71, 0x51], 100, 100, 2),
            ],
        )
        .unwrap();
        assert_eq!(
            plan.process_domains()[0].domain(),
            ProcessDomainRef::from_bytes([0x71; 16])
        );
        let mut noncanonical = plan.canonical_wire().to_vec();
        let first = TARGET_EXECUTION_V3_HEADER_BYTES;
        let second = first + PROCESS_DOMAIN_RECORD_BYTES;
        let (left, right) = noncanonical.split_at_mut(second);
        left[first..second].swap_with_slice(&mut right[..PROCESS_DOMAIN_RECORD_BYTES]);
        assert_eq!(
            TargetExecutionPlanV3::decode(&noncanonical)
                .unwrap_err()
                .code(),
            ProcessExecutionWireErrorCode::NonCanonicalFrame,
        );
    }

    #[test]
    fn duplicate_or_orphan_domain_references_fail_closed() {
        assert_eq!(
            TargetExecutionPlanV3::try_new(
                None,
                vec![
                    sample_domain(0x71, 1_000_000, 2),
                    sample_domain(0x71, 1_000_000, 2)
                ],
                vec![sample_mailbox([0x11, 0x21, 0x41, 0x71, 0x51], 100, 100, 2,)],
            )
            .unwrap_err(),
            ProcessExecutionContractError::DuplicateDomainRef,
        );
        assert_eq!(
            TargetExecutionPlanV3::try_new(
                None,
                vec![sample_domain(0x71, 1_000_000, 2)],
                vec![sample_mailbox([0x11, 0x21, 0x41, 0x72, 0x51], 100, 100, 2,)],
            )
            .unwrap_err(),
            ProcessExecutionContractError::OrphanDomainRef,
        );
    }

    #[test]
    fn one_process_domain_can_own_only_one_instance_subject() {
        let error = TargetExecutionPlanV3::try_new(
            None,
            vec![sample_domain(0x71, 1_000_000, 2)],
            vec![
                sample_mailbox([0x11, 0x21, 0x41, 0x71, 0x51], 100, 100, 1),
                sample_mailbox([0x12, 0x22, 0x42, 0x71, 0x51], 100, 100, 1),
            ],
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProcessExecutionContractError::ProcessDomainSubjectMismatch
        );
    }

    #[test]
    fn same_instance_across_domains_must_share_process_subject_contract() {
        let error = TargetExecutionPlanV3::try_new(
            None,
            vec![
                sample_domain(0x71, 1_000_000, 2),
                sample_domain(0x72, 1_000_000, 2),
            ],
            vec![
                sample_mailbox([0x11, 0x21, 0x41, 0x71, 0x51], 100, 100, 1),
                sample_mailbox([0x12, 0x22, 0x41, 0x72, 0x52], 100, 100, 1),
            ],
        )
        .unwrap_err();
        assert_eq!(error, ProcessExecutionContractError::ProcessSubjectMismatch);
    }

    #[test]
    fn process_domain_utilization_is_checked_with_u128_arithmetic() {
        let error = TargetExecutionPlanV3::try_new(
            None,
            vec![sample_domain(0x71, 100, 1)],
            vec![sample_mailbox([0x11, 0x21, 0x41, 0x71, 0x51], 40, 10, 3)],
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProcessExecutionContractError::ProcessUtilizationExceeded
        );
    }

    #[test]
    fn component_bounds_reject_invalid_liveness_credit_resource_and_restart() {
        assert_eq!(
            ProcessLaunchSpec::try_new(
                ProcessProfileSelections::new(
                    ProcessLaunchProfileRef::from_bytes([1; 16]),
                    Digest32::from_bytes([2; 32]),
                    ProcessTargetProfileRef::from_bytes([3; 16]),
                    Digest32::from_bytes([4; 32]),
                    ProcessSandboxProfileRef::from_bytes([5; 16]),
                    Digest32::from_bytes([6; 32]),
                ),
                2,
                WorkerRuntimeKind::Python,
                RuntimeVersionRange::try_new(3, 11, 3, 13).unwrap(),
            )
            .unwrap_err(),
            ProcessExecutionContractError::InvalidLaunchSpec,
        );
        assert_eq!(
            ProcessCapacitySpec::try_new(1, 2, duration(10), 2, 10, 10).unwrap_err(),
            ProcessExecutionContractError::InvalidIpcBudget,
        );
        assert_eq!(
            ProcessCapacitySpec::try_new(4_097, 1, duration(10), 1, 10, 10).unwrap_err(),
            ProcessExecutionContractError::InvalidIpcBudget,
        );
        assert_eq!(
            ProcessCapacitySpec::try_new(
                1,
                1,
                duration(10),
                1,
                10,
                MAX_PROCESS_WORKER_RETAINED_BYTES + 1,
            )
            .unwrap_err(),
            ProcessExecutionContractError::InvalidIpcBudget,
        );
        assert_eq!(
            ProcessLivenessBudgets::try_new(duration(1), duration(10), duration(10), duration(1),)
                .unwrap_err(),
            ProcessExecutionContractError::InvalidLivenessBudget,
        );
        assert_eq!(
            ProcessShutdownBudgets::try_new(
                duration(1),
                duration(1),
                duration(1),
                duration(1),
                duration(0),
            )
            .unwrap_err(),
            ProcessExecutionContractError::InvalidLivenessBudget,
        );
        assert_eq!(
            ProcessResourceLimits::try_new(0, 1, 1, duration(1)).unwrap_err(),
            ProcessExecutionContractError::InvalidResourceBudget,
        );
        assert_eq!(
            ProcessRestartPolicy::try_new(1_025, duration(10), duration(1), duration(2), 0)
                .unwrap_err(),
            ProcessExecutionContractError::InvalidRestartPolicy,
        );
        assert_eq!(
            ProcessInvocationBudgets::try_new(duration(1), duration(1), duration(1), 1_048_577,)
                .unwrap_err(),
            ProcessExecutionContractError::InvalidInvocationBudget,
        );
    }

    #[test]
    fn stable_wire_codes_are_append_only_values() {
        assert_eq!(ProcessExecutionWireErrorCode::UnsupportedVersion as u16, 4);
        assert_eq!(ProcessExecutionWireErrorCode::InvalidIpcBudget as u16, 20);
        assert_eq!(ProcessExecutionWireErrorCode::NonCanonicalFrame as u16, 28);
        assert_eq!(
            TargetPlanV4WireErrorCode::BindingInflightExceedsCredit as u16,
            6
        );
        assert_eq!(RequestV4WireErrorCode::CommitmentMismatch as u16, 10);
    }
}
