//! Minimal POSIX OS service-manager adapter for one RuntimeHost executable.
//!
//! This adapter is the sole owner of the child process, restart-window ledger,
//! restart action, and quarantine mutation. Its bounded evidence is an
//! external observation/action log only; it cannot be used as a Runtime or
//! ProcessDomain failure receipt. Cleanup proof covers the exact POSIX process
//! group created for the RuntimeHost executable. A ProcessDomain that creates
//! a distinct worker process group is outside that proof after an uncatchable
//! RuntimeHost SIGKILL; production containment still requires a common
//! cgroup/job object or an external ownership journal that can enumerate and
//! clean those independently grouped workers.

use core::fmt;
use core::time::Duration;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::Instant;

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use paraegox_runtime::host_watchdog::{
    HOST_WATCHDOG_ENABLE_ENV, HOST_WATCHDOG_FRAME_BYTES, HOST_WATCHDOG_GENERATION_ENV,
    HOST_WATCHDOG_HANDSHAKE_MILLIS_ENV, HOST_WATCHDOG_HEARTBEAT_MILLIS_ENV, HostBootstrapPhase,
    HostControlProbeNonce, HostWatchdogDirection, HostWatchdogFrame, HostWatchdogFrameBody,
    HostWatchdogGeneration, HostWatchdogSequence,
};

const MIN_TIMING: Duration = Duration::from_millis(5);
const MAX_TIMING: Duration = Duration::from_secs(60);
const MAX_RESTART_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_RESTART_ATTEMPTS: usize = 32;
const MIN_EVIDENCE_CAPACITY: usize = 16;
const MAX_EVIDENCE_CAPACITY: usize = 256;
const MAX_FRAMES_PER_POLL: usize = 32;

/// RuntimeHost heartbeat/bootstrap/control timing selected by the external
/// service-manager profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostWatchdogTiming {
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
    bootstrap_timeout: Duration,
    bootstrap_progress_timeout: Duration,
    control_probe_interval: Duration,
    control_response_timeout: Duration,
    handshake_timeout: Duration,
}

impl HostWatchdogTiming {
    /// Constructs a bounded observation profile.
    pub fn try_new(
        heartbeat_interval: Duration,
        heartbeat_timeout: Duration,
        bootstrap_timeout: Duration,
        bootstrap_progress_timeout: Duration,
        control_probe_interval: Duration,
        control_response_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<Self, ServiceManagerError> {
        let values = [
            heartbeat_interval,
            heartbeat_timeout,
            bootstrap_timeout,
            bootstrap_progress_timeout,
            control_probe_interval,
            control_response_timeout,
            handshake_timeout,
        ];
        if values
            .iter()
            .any(|value| *value < MIN_TIMING || *value > MAX_TIMING)
            || heartbeat_interval >= heartbeat_timeout
            || heartbeat_interval >= bootstrap_timeout
            || bootstrap_progress_timeout > bootstrap_timeout
            || heartbeat_interval >= control_response_timeout
            || handshake_timeout > bootstrap_timeout
        {
            return Err(ServiceManagerError::InvalidConfiguration);
        }
        Ok(Self {
            heartbeat_interval,
            heartbeat_timeout,
            bootstrap_timeout,
            bootstrap_progress_timeout,
            control_probe_interval,
            control_response_timeout,
            handshake_timeout,
        })
    }

    /// Interval passed to the RuntimeHost's same-reactor heartbeat task.
    #[must_use]
    pub const fn heartbeat_interval(self) -> Duration {
        self.heartbeat_interval
    }
}

/// Bounded TERM/KILL/reap timing owned by the external adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostTerminationTiming {
    term_grace: Duration,
    kill_grace: Duration,
    poll_interval: Duration,
}

impl HostTerminationTiming {
    /// Constructs bounded process-action timing.
    pub fn try_new(
        term_grace: Duration,
        kill_grace: Duration,
        poll_interval: Duration,
    ) -> Result<Self, ServiceManagerError> {
        if term_grace < MIN_TIMING
            || term_grace > MAX_TIMING
            || kill_grace < MIN_TIMING
            || kill_grace > MAX_TIMING
            || poll_interval < MIN_TIMING
            || poll_interval > term_grace
            || poll_interval > kill_grace
        {
            return Err(ServiceManagerError::InvalidConfiguration);
        }
        Ok(Self {
            term_grace,
            kill_grace,
            poll_interval,
        })
    }

    /// Recommended caller polling cadence.
    #[must_use]
    pub const fn poll_interval(self) -> Duration {
        self.poll_interval
    }
}

/// The single restart-window budget held and mutated by this adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostRestartPolicy {
    window: Duration,
    maximum_restarts: usize,
    initial_backoff: Duration,
    maximum_backoff: Duration,
    maximum_jitter: Duration,
}

impl HostRestartPolicy {
    /// Constructs a bounded restart/backoff/quarantine policy.
    pub fn try_new(
        window: Duration,
        maximum_restarts: usize,
        initial_backoff: Duration,
        maximum_backoff: Duration,
        maximum_jitter: Duration,
    ) -> Result<Self, ServiceManagerError> {
        if window < MIN_TIMING
            || window > MAX_RESTART_WINDOW
            || maximum_restarts == 0
            || maximum_restarts > MAX_RESTART_ATTEMPTS
            || initial_backoff < MIN_TIMING
            || initial_backoff > maximum_backoff
            || maximum_backoff > MAX_TIMING
            || maximum_jitter > maximum_backoff
        {
            return Err(ServiceManagerError::InvalidConfiguration);
        }
        Ok(Self {
            window,
            maximum_restarts,
            initial_backoff,
            maximum_backoff,
            maximum_jitter,
        })
    }
}

/// Complete policy for one external RuntimeHost lifecycle owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeHostServiceManagerPolicy {
    watchdog: HostWatchdogTiming,
    termination: HostTerminationTiming,
    restart: HostRestartPolicy,
    evidence_capacity: usize,
}

impl RuntimeHostServiceManagerPolicy {
    /// Combines independently bounded observation, action, and restart policy.
    pub fn try_new(
        watchdog: HostWatchdogTiming,
        termination: HostTerminationTiming,
        restart: HostRestartPolicy,
        evidence_capacity: usize,
    ) -> Result<Self, ServiceManagerError> {
        if !(MIN_EVIDENCE_CAPACITY..=MAX_EVIDENCE_CAPACITY).contains(&evidence_capacity) {
            return Err(ServiceManagerError::InvalidConfiguration);
        }
        Ok(Self {
            watchdog,
            termination,
            restart,
            evidence_capacity,
        })
    }

    /// Conservative local reference values; target profiles must validate
    /// their own scheduling and shutdown envelopes.
    pub fn reference_defaults() -> Result<Self, ServiceManagerError> {
        Self::try_new(
            HostWatchdogTiming::try_new(
                Duration::from_millis(100),
                Duration::from_millis(750),
                Duration::from_secs(5),
                Duration::from_secs(2),
                Duration::from_millis(250),
                Duration::from_secs(1),
                Duration::from_secs(2),
            )?,
            HostTerminationTiming::try_new(
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_millis(20),
            )?,
            HostRestartPolicy::try_new(
                Duration::from_secs(30),
                3,
                Duration::from_millis(100),
                Duration::from_secs(2),
                Duration::from_millis(50),
            )?,
            128,
        )
    }

    /// Recommended external polling cadence.
    #[must_use]
    pub const fn poll_interval(self) -> Duration {
        self.termination.poll_interval()
    }
}

/// Narrow exact executable selected by the surrounding OS profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeHostLaunch {
    executable: PathBuf,
}

impl RuntimeHostLaunch {
    /// Selects the exact RuntimeHost executable. This adapter deliberately
    /// offers no arbitrary command, shell, environment, or Deployment input.
    pub fn try_new(executable: impl Into<PathBuf>) -> Result<Self, ServiceManagerError> {
        let executable = executable.into();
        if executable.as_os_str().is_empty() {
            return Err(ServiceManagerError::InvalidConfiguration);
        }
        Ok(Self { executable })
    }

    /// Exact configured executable path.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

/// External-only failure classification. These observations do not claim a
/// Runtime failure reason, a ProcessDomain terminal state, or effect outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceManagerFailure {
    HostExited,
    BootstrapDeadlineExceeded,
    BootstrapProgressStalled,
    HeartbeatMissed,
    ControlUnresponsive,
    WatchdogStreamClosed,
    WatchdogProtocolViolation,
    SpawnSetupFailed,
    SpawnCleanupFailed,
    RestartSpawnFailed,
}

/// Bounded external observation/action evidence kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceManagerEvidenceKind {
    Spawned,
    BootstrapProgress(HostBootstrapPhase),
    RunningHeartbeat,
    ControlProbeSent(HostControlProbeNonce),
    ControlAcknowledged(HostControlProbeNonce),
    HostExitObserved,
    FailureDetected(ServiceManagerFailure),
    TermSent,
    KillSent,
    /// The direct child was reaped and its exact owned POSIX process group was
    /// observed absent. Neither condition alone may produce this evidence.
    Reaped,
    RestartScheduled {
        attempt: usize,
        delay: Duration,
    },
    Quarantined(ServiceManagerFailure),
    ShutdownRequested,
}

/// One entry in the fixed-capacity service-manager evidence ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceManagerEvidence {
    elapsed: Duration,
    generation: u64,
    pid: Option<u32>,
    kind: ServiceManagerEvidenceKind,
}

impl ServiceManagerEvidence {
    /// Real monotonic time since this manager instance started.
    #[must_use]
    pub const fn elapsed(self) -> Duration {
        self.elapsed
    }

    /// Child generation associated with this observation/action.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Exact active child PID, when the entry concerns a live/reaped child.
    #[must_use]
    pub const fn pid(self) -> Option<u32> {
        self.pid
    }

    /// External observation or service-manager action.
    #[must_use]
    pub const fn kind(self) -> ServiceManagerEvidenceKind {
        self.kind
    }
}

/// Current lifecycle state of the external adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeHostServiceManagerState {
    Bootstrapping,
    Running,
    RestartBackoff,
    Quarantined,
    Stopped,
}

/// Read-only bounded snapshot; it exposes no lifecycle mutation handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeHostServiceManagerSnapshot {
    state: RuntimeHostServiceManagerState,
    generation: u64,
    active_pid: Option<u32>,
    restart_attempts_in_window: usize,
    evidence_entries: usize,
}

impl RuntimeHostServiceManagerSnapshot {
    #[must_use]
    pub const fn state(self) -> RuntimeHostServiceManagerState {
        self.state
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn active_pid(self) -> Option<u32> {
        self.active_pid
    }

    #[must_use]
    pub const fn restart_attempts_in_window(self) -> usize {
        self.restart_attempts_in_window
    }

    #[must_use]
    pub const fn evidence_entries(self) -> usize {
        self.evidence_entries
    }
}

struct ManagedRuntimeHost {
    generation: HostWatchdogGeneration,
    pid: u32,
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    read_buffer: [u8; HOST_WATCHDOG_FRAME_BYTES],
    read_offset: usize,
    spawned_at: Instant,
    last_progress_at: Instant,
    last_heartbeat_at: Instant,
    bootstrap_phase: Option<HostBootstrapPhase>,
    next_host_sequence: u64,
    next_manager_sequence: u64,
    next_probe_nonce: u64,
    outstanding_probe: Option<(HostControlProbeNonce, Instant)>,
    last_probe_completed_at: Instant,
}

/// Sole owner retained when a child was spawned but could not be fully
/// installed or proven absent. It deliberately has no watchdog channels and
/// can only be retried for cleanup while the manager remains quarantined.
struct FailedSpawnCleanupOwner {
    generation: HostWatchdogGeneration,
    pid: u32,
    child: Child,
}

#[derive(Clone, Copy)]
struct PendingRestart {
    due: Instant,
    failure: ServiceManagerFailure,
}

impl ManagedRuntimeHost {
    fn is_running(&self) -> bool {
        self.bootstrap_phase == Some(HostBootstrapPhase::Running)
    }
}

/// The sole RuntimeHost child/restart/quarantine mutation owner for this
/// reference profile.
pub struct RuntimeHostServiceManager {
    launch: RuntimeHostLaunch,
    policy: RuntimeHostServiceManagerPolicy,
    origin: Instant,
    state: RuntimeHostServiceManagerState,
    generation: u64,
    active: Option<ManagedRuntimeHost>,
    failed_spawn_cleanup: Option<FailedSpawnCleanupOwner>,
    /// Timestamps of replacement spawn attempts that actually happened.
    /// A scheduled backoff is represented separately by `pending_restart`.
    restart_attempts: VecDeque<Instant>,
    pending_restart: Option<PendingRestart>,
    evidence: VecDeque<ServiceManagerEvidence>,
}

impl RuntimeHostServiceManager {
    /// Spawns the first child and installs the complete explicit watchdog
    /// profile. There is no second restart loop or mutation handle.
    pub fn try_start(
        launch: RuntimeHostLaunch,
        policy: RuntimeHostServiceManagerPolicy,
    ) -> Result<Self, ServiceManagerError> {
        let now = Instant::now();
        let mut manager = Self {
            launch,
            policy,
            origin: now,
            state: RuntimeHostServiceManagerState::Bootstrapping,
            generation: 0,
            active: None,
            failed_spawn_cleanup: None,
            restart_attempts: VecDeque::with_capacity(policy.restart.maximum_restarts),
            pending_restart: None,
            evidence: VecDeque::with_capacity(policy.evidence_capacity),
        };
        manager.spawn_next(now)?;
        Ok(manager)
    }

    /// Advances observation and at most one owner-controlled transition. This
    /// call never waits beyond the configured TERM/KILL recovery envelope.
    pub fn poll(&mut self) -> Result<RuntimeHostServiceManagerSnapshot, ServiceManagerError> {
        match self.state {
            RuntimeHostServiceManagerState::Quarantined
            | RuntimeHostServiceManagerState::Stopped => return Ok(self.snapshot()),
            RuntimeHostServiceManagerState::RestartBackoff => {
                let now = Instant::now();
                if self
                    .pending_restart
                    .is_some_and(|pending| now >= pending.due)
                    && let Some(pending) = self.pending_restart.take()
                    && self.commit_restart_attempt(pending.failure, now)
                    && self.spawn_next(now).is_err()
                {
                    let failure = ServiceManagerFailure::RestartSpawnFailed;
                    self.record(None, ServiceManagerEvidenceKind::FailureDetected(failure));
                    self.schedule_restart(failure, Instant::now());
                }
            }
            RuntimeHostServiceManagerState::Bootstrapping
            | RuntimeHostServiceManagerState::Running => self.poll_active()?,
        }
        Ok(self.snapshot())
    }

    /// Returns the current read-only state without driving recovery.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeHostServiceManagerSnapshot {
        RuntimeHostServiceManagerSnapshot {
            state: self.state,
            generation: self.generation,
            active_pid: self
                .active
                .as_ref()
                .map(|active| active.pid)
                .or_else(|| self.failed_spawn_cleanup.as_ref().map(|owner| owner.pid)),
            restart_attempts_in_window: self.restart_attempts.len(),
            evidence_entries: self.evidence.len(),
        }
    }

    /// Iterates the bounded evidence ring from oldest retained entry to newest.
    pub fn evidence(&self) -> impl ExactSizeIterator<Item = &ServiceManagerEvidence> {
        self.evidence.iter()
    }

    /// Stops and reaps the active process without spending or scheduling a
    /// restart. Repeated calls are idempotent.
    pub fn shutdown(&mut self) -> Result<(), ServiceManagerError> {
        if self.state == RuntimeHostServiceManagerState::Stopped {
            return Ok(());
        }
        self.pending_restart = None;
        if let Some(mut owner) = self.failed_spawn_cleanup.take() {
            self.record_for(
                owner.generation.value(),
                Some(owner.pid),
                ServiceManagerEvidenceKind::ShutdownRequested,
            );
            if let Err(error) = self.kill_and_reap_failed_spawn(&mut owner) {
                self.failed_spawn_cleanup = Some(owner);
                self.state = RuntimeHostServiceManagerState::Quarantined;
                return Err(error);
            }
        }
        if let Some(mut active) = self.active.take() {
            self.record_for(
                active.generation.value(),
                Some(active.pid),
                ServiceManagerEvidenceKind::ShutdownRequested,
            );
            if let Err(error) = self.terminate_and_reap(&mut active) {
                self.active = Some(active);
                self.state = RuntimeHostServiceManagerState::Quarantined;
                return Err(error);
            }
        }
        self.state = RuntimeHostServiceManagerState::Stopped;
        Ok(())
    }

    fn poll_active(&mut self) -> Result<(), ServiceManagerError> {
        let Some(mut active) = self.active.take() else {
            return Err(ServiceManagerError::StateInconsistent);
        };
        let now = Instant::now();
        match active.child.try_wait() {
            Ok(Some(_)) => {
                self.record_for(
                    active.generation.value(),
                    Some(active.pid),
                    ServiceManagerEvidenceKind::HostExitObserved,
                );
                self.record_for(
                    active.generation.value(),
                    Some(active.pid),
                    ServiceManagerEvidenceKind::FailureDetected(ServiceManagerFailure::HostExited),
                );
                if let Err(error) = self.terminate_and_reap(&mut active) {
                    self.active = Some(active);
                    self.state = RuntimeHostServiceManagerState::Quarantined;
                    return Err(error);
                }
                self.schedule_restart(ServiceManagerFailure::HostExited, now);
                return Ok(());
            }
            Ok(None) => {}
            Err(error) => {
                self.active = Some(active);
                return Err(ServiceManagerError::Io(error));
            }
        }

        let failure = self
            .read_host_frames(&mut active, now)
            .or_else(|| self.observation_timeout(&active, now))
            .or_else(|| self.maybe_send_probe(&mut active, now));
        if let Some(failure) = failure {
            self.record_for(
                active.generation.value(),
                Some(active.pid),
                ServiceManagerEvidenceKind::FailureDetected(failure),
            );
            if let Err(error) = self.terminate_and_reap(&mut active) {
                self.active = Some(active);
                self.state = RuntimeHostServiceManagerState::Quarantined;
                return Err(error);
            }
            self.schedule_restart(failure, Instant::now());
        } else {
            self.state = if active.is_running() {
                RuntimeHostServiceManagerState::Running
            } else {
                RuntimeHostServiceManagerState::Bootstrapping
            };
            self.active = Some(active);
        }
        Ok(())
    }

    fn read_host_frames(
        &mut self,
        active: &mut ManagedRuntimeHost,
        now: Instant,
    ) -> Option<ServiceManagerFailure> {
        for _ in 0..MAX_FRAMES_PER_POLL {
            match active
                .output
                .read(&mut active.read_buffer[active.read_offset..])
            {
                Ok(0) => return Some(ServiceManagerFailure::WatchdogStreamClosed),
                Ok(read) => {
                    active.read_offset += read;
                    if active.read_offset != HOST_WATCHDOG_FRAME_BYTES {
                        continue;
                    }
                    let decoded = HostWatchdogFrame::decode(&active.read_buffer);
                    active.read_offset = 0;
                    let Ok(frame) = decoded else {
                        return Some(ServiceManagerFailure::WatchdogProtocolViolation);
                    };
                    if self.accept_host_frame(active, frame, now).is_err() {
                        return Some(ServiceManagerFailure::WatchdogProtocolViolation);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return None,
                Err(_) => return Some(ServiceManagerFailure::WatchdogStreamClosed),
            }
        }
        None
    }

    fn accept_host_frame(
        &mut self,
        active: &mut ManagedRuntimeHost,
        frame: HostWatchdogFrame,
        now: Instant,
    ) -> Result<(), ()> {
        if frame.direction() != HostWatchdogDirection::HostToManager
            || frame.generation() != active.generation
            || frame.sequence().value() != active.next_host_sequence
        {
            return Err(());
        }
        active.next_host_sequence = active.next_host_sequence.checked_add(1).ok_or(())?;
        match frame.body() {
            HostWatchdogFrameBody::BootstrapProgress(phase) => {
                let expected = match active.bootstrap_phase {
                    None => HostBootstrapPhase::ReactorStarted,
                    Some(HostBootstrapPhase::ReactorStarted) => HostBootstrapPhase::ControlReady,
                    Some(HostBootstrapPhase::ControlReady) => HostBootstrapPhase::Running,
                    Some(HostBootstrapPhase::Running) => return Err(()),
                };
                if phase != expected {
                    return Err(());
                }
                active.bootstrap_phase = Some(phase);
                active.last_progress_at = now;
                if phase == HostBootstrapPhase::Running {
                    active.last_heartbeat_at = now;
                    if let Some((nonce, _)) = active.outstanding_probe {
                        active.outstanding_probe = Some((nonce, now));
                    }
                }
                self.record_for(
                    active.generation.value(),
                    Some(active.pid),
                    ServiceManagerEvidenceKind::BootstrapProgress(phase),
                );
            }
            HostWatchdogFrameBody::RunningHeartbeat => {
                if !active.is_running() {
                    return Err(());
                }
                active.last_heartbeat_at = now;
                self.record_for(
                    active.generation.value(),
                    Some(active.pid),
                    ServiceManagerEvidenceKind::RunningHeartbeat,
                );
            }
            HostWatchdogFrameBody::ControlAck(nonce) => {
                if active.outstanding_probe.map(|outstanding| outstanding.0) != Some(nonce) {
                    return Err(());
                }
                active.outstanding_probe = None;
                active.last_probe_completed_at = now;
                self.record_for(
                    active.generation.value(),
                    Some(active.pid),
                    ServiceManagerEvidenceKind::ControlAcknowledged(nonce),
                );
            }
            HostWatchdogFrameBody::ControlProbe(_) => return Err(()),
        }
        Ok(())
    }

    fn observation_timeout(
        &self,
        active: &ManagedRuntimeHost,
        now: Instant,
    ) -> Option<ServiceManagerFailure> {
        let control_timeout = if active.is_running() {
            self.policy.watchdog.control_response_timeout
        } else {
            self.policy.watchdog.bootstrap_timeout
        };
        if let Some((_, sent_at)) = active.outstanding_probe
            && now.duration_since(sent_at) > control_timeout
        {
            return Some(ServiceManagerFailure::ControlUnresponsive);
        }
        if active.is_running() {
            if now.duration_since(active.last_heartbeat_at) > self.policy.watchdog.heartbeat_timeout
            {
                return Some(ServiceManagerFailure::HeartbeatMissed);
            }
            return None;
        }
        if now.duration_since(active.spawned_at) > self.policy.watchdog.bootstrap_timeout {
            return Some(ServiceManagerFailure::BootstrapDeadlineExceeded);
        }
        if now.duration_since(active.last_progress_at)
            > self.policy.watchdog.bootstrap_progress_timeout
        {
            return Some(ServiceManagerFailure::BootstrapProgressStalled);
        }
        None
    }

    fn maybe_send_probe(
        &mut self,
        active: &mut ManagedRuntimeHost,
        now: Instant,
    ) -> Option<ServiceManagerFailure> {
        if active.outstanding_probe.is_some()
            || now.duration_since(active.last_probe_completed_at)
                < self.policy.watchdog.control_probe_interval
        {
            return None;
        }
        match send_control_probe(active, now) {
            Ok(nonce) => {
                self.record_for(
                    active.generation.value(),
                    Some(active.pid),
                    ServiceManagerEvidenceKind::ControlProbeSent(nonce),
                );
                None
            }
            Err(()) => Some(ServiceManagerFailure::WatchdogStreamClosed),
        }
    }

    fn spawn_next(&mut self, now: Instant) -> Result<(), ServiceManagerError> {
        if self.active.is_some() || self.failed_spawn_cleanup.is_some() {
            return Err(ServiceManagerError::StateInconsistent);
        }
        let generation_value = self
            .generation
            .checked_add(1)
            .ok_or(ServiceManagerError::GenerationExhausted)?;
        let generation = HostWatchdogGeneration::try_new(generation_value)
            .map_err(|_| ServiceManagerError::GenerationExhausted)?;
        let mut command = Command::new(self.launch.executable());
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env(HOST_WATCHDOG_ENABLE_ENV, "1")
            .env(HOST_WATCHDOG_GENERATION_ENV, generation_value.to_string())
            .env(
                HOST_WATCHDOG_HEARTBEAT_MILLIS_ENV,
                duration_millis(self.policy.watchdog.heartbeat_interval)?.to_string(),
            )
            .env(
                HOST_WATCHDOG_HANDSHAKE_MILLIS_ENV,
                duration_millis(self.policy.watchdog.handshake_timeout)?.to_string(),
            )
            .process_group(0);
        let mut child = command.spawn().map_err(ServiceManagerError::Io)?;
        let pid = child.id();
        // `Command::spawn` is the generation commit point. Once the OS has
        // returned a child owner, this identity is permanently consumed even
        // if installing the watchdog pipes or initial probe subsequently
        // fails.
        self.generation = generation_value;
        self.record_for(
            generation_value,
            Some(pid),
            ServiceManagerEvidenceKind::Spawned,
        );
        let Some(input) = child.stdin.take() else {
            return self.reject_spawned_child(
                FailedSpawnCleanupOwner {
                    generation,
                    pid,
                    child,
                },
                ServiceManagerError::MissingChildPipe,
            );
        };
        let Some(output) = child.stdout.take() else {
            return self.reject_spawned_child(
                FailedSpawnCleanupOwner {
                    generation,
                    pid,
                    child,
                },
                ServiceManagerError::MissingChildPipe,
            );
        };
        if let Err(error) = set_nonblocking(&output) {
            return self.reject_spawned_child(
                FailedSpawnCleanupOwner {
                    generation,
                    pid,
                    child,
                },
                error,
            );
        }
        let mut active = ManagedRuntimeHost {
            generation,
            pid,
            child,
            input,
            output,
            read_buffer: [0; HOST_WATCHDOG_FRAME_BYTES],
            read_offset: 0,
            spawned_at: now,
            last_progress_at: now,
            last_heartbeat_at: now,
            bootstrap_phase: None,
            next_host_sequence: 1,
            next_manager_sequence: 1,
            next_probe_nonce: 1,
            outstanding_probe: None,
            last_probe_completed_at: now
                .checked_sub(self.policy.watchdog.control_probe_interval)
                .unwrap_or(now),
        };
        let nonce = match send_control_probe(&mut active, now) {
            Ok(nonce) => nonce,
            Err(()) => {
                return self.reject_spawned_child(
                    FailedSpawnCleanupOwner {
                        generation: active.generation,
                        pid: active.pid,
                        child: active.child,
                    },
                    ServiceManagerError::WatchdogPipeFailed,
                );
            }
        };
        self.state = RuntimeHostServiceManagerState::Bootstrapping;
        self.record_for(
            generation_value,
            Some(pid),
            ServiceManagerEvidenceKind::ControlProbeSent(nonce),
        );
        self.active = Some(active);
        Ok(())
    }

    fn reject_spawned_child(
        &mut self,
        mut owner: FailedSpawnCleanupOwner,
        setup_error: ServiceManagerError,
    ) -> Result<(), ServiceManagerError> {
        self.record_for(
            owner.generation.value(),
            Some(owner.pid),
            ServiceManagerEvidenceKind::FailureDetected(ServiceManagerFailure::SpawnSetupFailed),
        );
        let cleanup = self.kill_and_reap_failed_spawn(&mut owner);
        self.finish_rejected_spawn(owner, setup_error, cleanup)
    }

    fn finish_rejected_spawn(
        &mut self,
        owner: FailedSpawnCleanupOwner,
        setup_error: ServiceManagerError,
        cleanup: Result<(), ServiceManagerError>,
    ) -> Result<(), ServiceManagerError> {
        match cleanup {
            Ok(()) => Err(setup_error),
            Err(_cleanup_error) => {
                let generation = owner.generation.value();
                let pid = owner.pid;
                self.pending_restart = None;
                self.state = RuntimeHostServiceManagerState::Quarantined;
                self.record_for(
                    generation,
                    Some(pid),
                    ServiceManagerEvidenceKind::FailureDetected(
                        ServiceManagerFailure::SpawnCleanupFailed,
                    ),
                );
                self.record_for(
                    generation,
                    Some(pid),
                    ServiceManagerEvidenceKind::Quarantined(
                        ServiceManagerFailure::SpawnCleanupFailed,
                    ),
                );
                self.failed_spawn_cleanup = Some(owner);
                Ok(())
            }
        }
    }

    fn kill_and_reap_failed_spawn(
        &mut self,
        owner: &mut FailedSpawnCleanupOwner,
    ) -> Result<(), ServiceManagerError> {
        signal_process_group(owner.pid, Signal::SIGKILL)?;
        self.record_for(
            owner.generation.value(),
            Some(owner.pid),
            ServiceManagerEvidenceKind::KillSent,
        );
        let _ = owner.child.kill();
        if !wait_for_owned_group_cleanup(
            &mut owner.child,
            owner.pid,
            self.policy.termination.kill_grace,
            self.policy.termination.poll_interval,
        )? {
            return Err(ServiceManagerError::OwnedProcessGroupDidNotExit);
        }
        self.record_for(
            owner.generation.value(),
            Some(owner.pid),
            ServiceManagerEvidenceKind::Reaped,
        );
        Ok(())
    }

    fn terminate_and_reap(
        &mut self,
        active: &mut ManagedRuntimeHost,
    ) -> Result<(), ServiceManagerError> {
        let leader_reaped = active
            .child
            .try_wait()
            .map_err(ServiceManagerError::Io)?
            .is_some();
        let group_exists = process_group_exists(active.pid)?;
        if leader_reaped && !group_exists {
            self.record_for(
                active.generation.value(),
                Some(active.pid),
                ServiceManagerEvidenceKind::Reaped,
            );
            return Ok(());
        }
        if !leader_reaped && !group_exists {
            return Err(ServiceManagerError::StateInconsistent);
        }

        signal_process_group(active.pid, Signal::SIGTERM)?;
        self.record_for(
            active.generation.value(),
            Some(active.pid),
            ServiceManagerEvidenceKind::TermSent,
        );
        if !wait_for_owned_group_cleanup(
            &mut active.child,
            active.pid,
            self.policy.termination.term_grace,
            self.policy.termination.poll_interval,
        )? {
            signal_process_group(active.pid, Signal::SIGKILL)?;
            self.record_for(
                active.generation.value(),
                Some(active.pid),
                ServiceManagerEvidenceKind::KillSent,
            );
            if !wait_for_owned_group_cleanup(
                &mut active.child,
                active.pid,
                self.policy.termination.kill_grace,
                self.policy.termination.poll_interval,
            )? {
                return Err(ServiceManagerError::OwnedProcessGroupDidNotExit);
            }
        }
        self.record_for(
            active.generation.value(),
            Some(active.pid),
            ServiceManagerEvidenceKind::Reaped,
        );
        Ok(())
    }

    fn prune_restart_attempts(&mut self, now: Instant) {
        while self
            .restart_attempts
            .front()
            .is_some_and(|attempt| now.duration_since(*attempt) > self.policy.restart.window)
        {
            self.restart_attempts.pop_front();
        }
    }

    /// Commits the window ledger at the instant a replacement spawn will
    /// actually be attempted. A pending backoff never consumes this budget.
    fn commit_restart_attempt(&mut self, failure: ServiceManagerFailure, now: Instant) -> bool {
        self.prune_restart_attempts(now);
        if self.restart_attempts.len() >= self.policy.restart.maximum_restarts {
            self.pending_restart = None;
            self.state = RuntimeHostServiceManagerState::Quarantined;
            self.record(None, ServiceManagerEvidenceKind::Quarantined(failure));
            return false;
        }
        self.restart_attempts.push_back(now);
        true
    }

    fn schedule_restart(&mut self, failure: ServiceManagerFailure, now: Instant) {
        self.prune_restart_attempts(now);
        if self.restart_attempts.len() >= self.policy.restart.maximum_restarts {
            self.pending_restart = None;
            self.state = RuntimeHostServiceManagerState::Quarantined;
            self.record(None, ServiceManagerEvidenceKind::Quarantined(failure));
            return;
        }
        let attempt = self.restart_attempts.len();
        let attempt = attempt.saturating_add(1);
        let delay = restart_delay(self.policy.restart, attempt, self.generation);
        let Some(restart_due) = now.checked_add(delay) else {
            self.pending_restart = None;
            self.state = RuntimeHostServiceManagerState::Quarantined;
            self.record(None, ServiceManagerEvidenceKind::Quarantined(failure));
            return;
        };
        self.pending_restart = Some(PendingRestart {
            due: restart_due,
            failure,
        });
        self.state = RuntimeHostServiceManagerState::RestartBackoff;
        self.record(
            None,
            ServiceManagerEvidenceKind::RestartScheduled { attempt, delay },
        );
    }

    fn record(&mut self, pid: Option<u32>, kind: ServiceManagerEvidenceKind) {
        self.record_for(self.generation, pid, kind);
    }

    fn record_for(&mut self, generation: u64, pid: Option<u32>, kind: ServiceManagerEvidenceKind) {
        if self.evidence.len() == self.policy.evidence_capacity {
            self.evidence.pop_front();
        }
        self.evidence.push_back(ServiceManagerEvidence {
            elapsed: self.origin.elapsed(),
            generation,
            pid,
            kind,
        });
    }
}

impl Drop for RuntimeHostServiceManager {
    fn drop(&mut self) {
        if let Some(mut owner) = self.failed_spawn_cleanup.take()
            && force_reap_owned_group(
                &mut owner.child,
                owner.pid,
                self.policy.termination.kill_grace,
                self.policy.termination.poll_interval,
            )
            .is_err()
        {
            reap_owned_group_without_detaching(
                &mut owner.child,
                owner.pid,
                self.policy.termination.poll_interval,
            );
        }
        if let Some(mut active) = self.active.take()
            && force_reap_owned_group(
                &mut active.child,
                active.pid,
                self.policy.termination.kill_grace,
                self.policy.termination.poll_interval,
            )
            .is_err()
        {
            // The external manager is the sole OS-process owner. An
            // unexpected destructor must fail-safe by retaining that
            // owner rather than detaching a live RuntimeHost group.
            reap_owned_group_without_detaching(
                &mut active.child,
                active.pid,
                self.policy.termination.poll_interval,
            );
        }
    }
}

fn send_control_probe(
    active: &mut ManagedRuntimeHost,
    now: Instant,
) -> Result<HostControlProbeNonce, ()> {
    let sequence = HostWatchdogSequence::try_new(active.next_manager_sequence).map_err(|_| ())?;
    let nonce = HostControlProbeNonce::try_new(active.next_probe_nonce).map_err(|_| ())?;
    let frame = HostWatchdogFrame::new(
        active.generation,
        sequence,
        HostWatchdogFrameBody::ControlProbe(nonce),
    )
    .encode();
    active.input.write_all(&frame).map_err(|_| ())?;
    active.input.flush().map_err(|_| ())?;
    active.next_manager_sequence = active.next_manager_sequence.checked_add(1).ok_or(())?;
    active.next_probe_nonce = active.next_probe_nonce.checked_add(1).ok_or(())?;
    active.outstanding_probe = Some((nonce, now));
    Ok(nonce)
}

fn set_nonblocking(output: &ChildStdout) -> Result<(), ServiceManagerError> {
    let flags = fcntl(output, FcntlArg::F_GETFL).map_err(ServiceManagerError::Signal)?;
    let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
    fcntl(output, FcntlArg::F_SETFL(flags)).map_err(ServiceManagerError::Signal)?;
    Ok(())
}

fn signal_process_group(process_group: u32, signal: Signal) -> Result<(), ServiceManagerError> {
    match killpg(pid(process_group)?, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(ServiceManagerError::Signal(error)),
    }
}

fn process_group_exists(process_group: u32) -> Result<bool, ServiceManagerError> {
    match killpg(pid(process_group)?, None) {
        Ok(()) | Err(Errno::EPERM) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(error) => Err(ServiceManagerError::Signal(error)),
    }
}

fn pid(value: u32) -> Result<Pid, ServiceManagerError> {
    i32::try_from(value)
        .map(Pid::from_raw)
        .map_err(|_| ServiceManagerError::InvalidProcessIdentity)
}

fn wait_for_owned_group_cleanup(
    child: &mut Child,
    process_group: u32,
    budget: Duration,
    poll_interval: Duration,
) -> Result<bool, ServiceManagerError> {
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or(ServiceManagerError::InvalidConfiguration)?;
    loop {
        let leader_reaped = child.try_wait().map_err(ServiceManagerError::Io)?.is_some();
        if leader_reaped && !process_group_exists(process_group)? {
            return Ok(true);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        thread::sleep(poll_interval.min(deadline.duration_since(now)));
    }
}

fn force_reap_owned_group(
    child: &mut Child,
    process_group: u32,
    budget: Duration,
    poll_interval: Duration,
) -> Result<(), ServiceManagerError> {
    signal_process_group(process_group, Signal::SIGKILL)?;
    let _ = child.kill();
    if wait_for_owned_group_cleanup(child, process_group, budget, poll_interval)? {
        Ok(())
    } else {
        Err(ServiceManagerError::OwnedProcessGroupDidNotExit)
    }
}

fn reap_owned_group_without_detaching(
    child: &mut Child,
    process_group: u32,
    poll_interval: Duration,
) {
    loop {
        let _ = signal_process_group(process_group, Signal::SIGKILL);
        let _ = child.kill();
        let leader_reaped = child.try_wait().ok().flatten().is_some();
        let group_gone = matches!(process_group_exists(process_group), Ok(false));
        if leader_reaped && group_gone {
            return;
        }
        thread::sleep(poll_interval);
    }
}

fn restart_delay(policy: HostRestartPolicy, attempt: usize, generation: u64) -> Duration {
    let shift = u32::try_from(attempt.saturating_sub(1).min(31)).unwrap_or(31);
    let multiplier = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
    let base = policy
        .initial_backoff
        .saturating_mul(multiplier)
        .min(policy.maximum_backoff);
    let jitter_limit = u64::try_from(policy.maximum_jitter.as_nanos()).unwrap_or(u64::MAX);
    if jitter_limit == 0 {
        return base;
    }
    let mixed = generation
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .rotate_left(17);
    base.saturating_add(Duration::from_nanos(mixed % jitter_limit.saturating_add(1)))
}

fn duration_millis(value: Duration) -> Result<u64, ServiceManagerError> {
    u64::try_from(value.as_millis()).map_err(|_| ServiceManagerError::InvalidConfiguration)
}

/// Adapter construction/action failure. Child liveness failures are instead
/// budgeted into bounded evidence and restart/quarantine state.
#[derive(Debug)]
pub enum ServiceManagerError {
    InvalidConfiguration,
    GenerationExhausted,
    MissingChildPipe,
    WatchdogPipeFailed,
    OwnedProcessGroupDidNotExit,
    StateInconsistent,
    InvalidProcessIdentity,
    Io(io::Error),
    Signal(Errno),
}

impl fmt::Display for ServiceManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => formatter.write_str("service-manager policy is invalid"),
            Self::GenerationExhausted => {
                formatter.write_str("RuntimeHost watchdog generation exhausted")
            }
            Self::MissingChildPipe => {
                formatter.write_str("RuntimeHost inherited watchdog pipe is unavailable")
            }
            Self::WatchdogPipeFailed => {
                formatter.write_str("initial RuntimeHost watchdog handshake write failed")
            }
            Self::OwnedProcessGroupDidNotExit => {
                formatter.write_str(
                    "RuntimeHost leader or its exact owned process group remained inside the KILL/reap budget",
                )
            }
            Self::StateInconsistent => {
                formatter.write_str("service-manager state has no expected active child")
            }
            Self::InvalidProcessIdentity => {
                formatter.write_str("RuntimeHost child PID cannot identify a POSIX process group")
            }
            Self::Io(error) => write!(formatter, "service-manager I/O failed: {error}"),
            Self::Signal(error) => {
                write!(formatter, "service-manager POSIX action failed: {error}")
            }
        }
    }
}

impl std::error::Error for ServiceManagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidConfiguration
            | Self::GenerationExhausted
            | Self::MissingChildPipe
            | Self::WatchdogPipeFailed
            | Self::OwnedProcessGroupDidNotExit
            | Self::StateInconsistent
            | Self::InvalidProcessIdentity
            | Self::Signal(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> RuntimeHostServiceManagerPolicy {
        RuntimeHostServiceManagerPolicy::try_new(
            HostWatchdogTiming::try_new(
                Duration::from_millis(10),
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(50),
                Duration::from_millis(20),
                Duration::from_millis(30),
                Duration::from_millis(50),
            )
            .expect("watchdog timing"),
            HostTerminationTiming::try_new(
                Duration::from_millis(10),
                Duration::from_millis(100),
                Duration::from_millis(5),
            )
            .expect("termination timing"),
            HostRestartPolicy::try_new(
                Duration::from_secs(1),
                2,
                Duration::from_millis(10),
                Duration::from_millis(20),
                Duration::ZERO,
            )
            .expect("restart policy"),
            32,
        )
        .expect("service-manager policy")
    }

    fn empty_manager(executable: &str) -> RuntimeHostServiceManager {
        let policy = test_policy();
        let now = Instant::now();
        RuntimeHostServiceManager {
            launch: RuntimeHostLaunch::try_new(executable).expect("test launch"),
            policy,
            origin: now,
            state: RuntimeHostServiceManagerState::Bootstrapping,
            generation: 0,
            active: None,
            failed_spawn_cleanup: None,
            restart_attempts: VecDeque::with_capacity(policy.restart.maximum_restarts),
            pending_restart: None,
            evidence: VecDeque::with_capacity(policy.evidence_capacity),
        }
    }

    fn manager_with_retained_failed_spawn() -> (RuntimeHostServiceManager, u32) {
        let mut manager = empty_manager("/bin/false");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("trap '' TERM; while :; do :; done")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let child = command.spawn().expect("owned test process");
        let pid = child.id();
        let generation = HostWatchdogGeneration::try_new(1).expect("test generation");
        manager.generation = generation.value();
        manager.record_for(
            generation.value(),
            Some(pid),
            ServiceManagerEvidenceKind::Spawned,
        );
        manager.record_for(
            generation.value(),
            Some(pid),
            ServiceManagerEvidenceKind::FailureDetected(ServiceManagerFailure::SpawnSetupFailed),
        );
        manager.record_for(
            generation.value(),
            Some(pid),
            ServiceManagerEvidenceKind::KillSent,
        );

        manager
            .finish_rejected_spawn(
                FailedSpawnCleanupOwner {
                    generation,
                    pid,
                    child,
                },
                ServiceManagerError::MissingChildPipe,
                Err(ServiceManagerError::OwnedProcessGroupDidNotExit),
            )
            .expect("failed cleanup must become retained quarantine state");
        (manager, pid)
    }

    #[test]
    fn delayed_backoff_commits_restart_window_at_actual_spawn_attempt() {
        let mut manager = empty_manager("/bin/false");
        let scheduled_at = Instant::now();

        manager.schedule_restart(ServiceManagerFailure::HostExited, scheduled_at);
        assert!(manager.restart_attempts.is_empty());
        assert!(manager.pending_restart.is_some());
        assert_eq!(manager.snapshot().restart_attempts_in_window(), 0);

        // Model a caller that did not poll until well after the restart
        // window. The replacement is charged at this delayed instant, not at
        // the earlier scheduling instant.
        let delayed_attempt = scheduled_at + manager.policy.restart.window + MIN_TIMING;
        manager.pending_restart = None;
        assert!(manager.commit_restart_attempt(ServiceManagerFailure::HostExited, delayed_attempt));
        assert_eq!(manager.restart_attempts.back(), Some(&delayed_attempt));

        manager.schedule_restart(ServiceManagerFailure::HostExited, delayed_attempt);
        assert_eq!(manager.restart_attempts.len(), 1);
        manager.pending_restart = None;
        let second_attempt = delayed_attempt + MIN_TIMING;
        assert!(manager.commit_restart_attempt(ServiceManagerFailure::HostExited, second_attempt));

        manager.schedule_restart(ServiceManagerFailure::HostExited, second_attempt);
        assert_eq!(manager.restart_attempts.len(), 2);
        assert!(manager.pending_restart.is_none());
        assert_eq!(
            manager.snapshot().state(),
            RuntimeHostServiceManagerState::Quarantined
        );
    }

    #[test]
    fn successful_post_spawn_rejection_consumes_generation_and_records_cleanup() {
        let mut manager = empty_manager("/bin/cat");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("while :; do :; done")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let child = command.spawn().expect("owned rejected process");
        let pid = child.id();
        let generation = HostWatchdogGeneration::try_new(1).expect("test generation");
        manager.generation = generation.value();
        manager.record_for(
            generation.value(),
            Some(pid),
            ServiceManagerEvidenceKind::Spawned,
        );

        let rejection = manager.reject_spawned_child(
            FailedSpawnCleanupOwner {
                generation,
                pid,
                child,
            },
            ServiceManagerError::MissingChildPipe,
        );
        assert!(matches!(
            rejection,
            Err(ServiceManagerError::MissingChildPipe)
        ));
        assert_eq!(manager.generation, 1);
        assert!(manager.active.is_none());
        assert!(manager.failed_spawn_cleanup.is_none());
        assert!(!process_group_exists(pid).expect("rejected process-group probe"));
        let generation_one = manager
            .evidence()
            .filter(|entry| entry.generation() == 1)
            .map(|entry| entry.kind())
            .collect::<Vec<_>>();
        assert_eq!(
            generation_one,
            vec![
                ServiceManagerEvidenceKind::Spawned,
                ServiceManagerEvidenceKind::FailureDetected(
                    ServiceManagerFailure::SpawnSetupFailed,
                ),
                ServiceManagerEvidenceKind::KillSent,
                ServiceManagerEvidenceKind::Reaped,
            ]
        );

        manager
            .spawn_next(Instant::now())
            .expect("next child must use the following generation");
        assert_eq!(manager.generation, 2);
        assert_eq!(
            manager
                .active
                .as_ref()
                .map(|active| active.generation.value()),
            Some(2)
        );
        manager.shutdown().expect("replacement cleanup");
    }

    #[test]
    fn failed_post_spawn_cleanup_retains_owner_and_forbids_replacement() {
        let (mut manager, pid) = manager_with_retained_failed_spawn();

        let quarantined = manager.snapshot();
        assert_eq!(
            quarantined.state(),
            RuntimeHostServiceManagerState::Quarantined
        );
        assert_eq!(quarantined.generation(), 1);
        assert_eq!(quarantined.active_pid(), Some(pid));
        assert!(manager.active.is_none());
        assert!(manager.failed_spawn_cleanup.is_some());
        for _ in 0..3 {
            assert_eq!(
                manager.poll().expect("quarantine poll").state(),
                RuntimeHostServiceManagerState::Quarantined
            );
        }
        assert!(!manager.evidence().any(|entry| matches!(
            entry.kind(),
            ServiceManagerEvidenceKind::RestartScheduled { .. }
        )));
        assert!(manager.evidence().any(|entry| {
            entry.kind()
                == ServiceManagerEvidenceKind::Quarantined(
                    ServiceManagerFailure::SpawnCleanupFailed,
                )
        }));

        manager
            .shutdown()
            .expect("retained failed spawn must be retryable to exact cleanup");
        assert_eq!(
            manager.snapshot().state(),
            RuntimeHostServiceManagerState::Stopped
        );
        assert_eq!(manager.snapshot().active_pid(), None);
        assert!(!process_group_exists(pid).expect("final process-group probe"));
    }

    #[test]
    fn manager_drop_never_detaches_a_retained_failed_spawn() {
        let (manager, pid) = manager_with_retained_failed_spawn();
        drop(manager);
        assert!(!process_group_exists(pid).expect("post-drop process-group probe"));
    }
}
