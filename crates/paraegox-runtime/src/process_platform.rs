//! Unix process ownership primitives for one RuntimeHost-owned ProcessDomain.
//!
//! This is the local/trusted baseline: every launched generation receives a
//! fresh process group, inherited environment is removed, and all IPC handles
//! stay owned by the Runtime. A stronger hostile-worker profile still needs an
//! external containment boundary (for example, a delegated cgroup on Linux).

use core::fmt;
use std::ffi::{OsStr, OsString};
#[cfg(any(target_os = "linux", test))]
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::io::unix::AsyncFd;

use paraegox_kernel::digest::Digest32;
use paraegox_runtime_contracts::process_execution::ProcessLaunchSpec;
#[cfg(any(target_os = "linux", test))]
use paraegox_runtime_contracts::process_execution::ProcessResourceLimits;

const MAX_ARGUMENTS: usize = 256;
const MAX_ENVIRONMENT_ENTRIES: usize = 256;
const MAX_LAUNCH_BYTES: usize = 64 * 1024;
const DROP_RETRY_DELAY: Duration = Duration::from_millis(1);
// Resource observation runs synchronously on the owning reactor. These fixed
// procfs work ceilings bound host-dependent traversal even when a signed
// resource ceiling is wider; exhaustion is an explicit failed census.
#[cfg(any(target_os = "linux", test))]
const MAX_PROCFS_HOST_ENTRIES_SCANNED: u32 = 4_096;
#[cfg(any(target_os = "linux", test))]
const MAX_PROCFS_FD_ENTRIES_SCANNED: u32 = 16_384;
// An owned process can transiently deny procfs inspection while Linux commits
// an exec. Retry the complete observation a fixed number of times; disappearance
// becomes `None`, successful inspection is counted, and persistent denial still
// fails closed without an unbounded reactor stall.
#[cfg(any(target_os = "linux", test))]
const MAX_TRANSIENT_PROCFS_PERMISSION_RETRIES: u8 = 32;

/// Trusted resolution of an immutable executable profile before a generation
/// specific workspace is allocated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedProcessProgram {
    launch_spec: ProcessLaunchSpec,
    worker_runtime_digest: Digest32,
    executable: PathBuf,
    arguments: Box<[OsString]>,
    environment: Box<[(OsString, OsString)]>,
}

impl ResolvedProcessProgram {
    /// Mints a local/trusted test harness profile. Production code has no mint
    /// path until a target adapter can verify the signed launch/target/sandbox
    /// content and enforce `NoRawHostAccess`; it therefore fails closed.
    #[cfg(test)]
    pub(crate) fn try_resolve_for_test(
        launch_spec: ProcessLaunchSpec,
        worker_runtime_digest: Digest32,
        executable: PathBuf,
        arguments: Vec<OsString>,
        environment: Vec<(OsString, OsString)>,
    ) -> Result<Self, ProcessPlatformError> {
        validate_program(&executable, &arguments, &environment)?;
        Ok(Self {
            launch_spec,
            worker_runtime_digest,
            executable,
            arguments: arguments.into_boxed_slice(),
            environment: environment.into_boxed_slice(),
        })
    }

    #[must_use]
    pub(crate) const fn launch_spec(&self) -> ProcessLaunchSpec {
        self.launch_spec
    }

    #[must_use]
    pub(crate) const fn worker_runtime_digest(&self) -> Digest32 {
        self.worker_runtime_digest
    }

    pub(crate) fn launch_in(
        &self,
        workspace: PathBuf,
    ) -> Result<ResolvedProcessLaunch, ProcessPlatformError> {
        ResolvedProcessLaunch::try_new(
            self.executable.clone(),
            self.arguments.to_vec(),
            self.environment.to_vec(),
            workspace,
        )
    }
}

/// Runtime-resolved executable data for one immutable launch profile.
///
/// Signed desired state carries profile references and digests. Resolution of
/// those references is a separate trusted operation; this value is the narrow
/// output consumed by the platform launcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedProcessLaunch {
    executable: PathBuf,
    arguments: Box<[OsString]>,
    environment: Box<[(OsString, OsString)]>,
    workspace: PathBuf,
}

impl ResolvedProcessLaunch {
    fn try_new(
        executable: PathBuf,
        arguments: Vec<OsString>,
        environment: Vec<(OsString, OsString)>,
        workspace: PathBuf,
    ) -> Result<Self, ProcessPlatformError> {
        validate_program(&executable, &arguments, &environment)?;
        if !workspace.is_absolute() {
            return Err(ProcessPlatformError::InvalidLaunchProfile);
        }

        let mut encoded_bytes = launch_bytes(&executable, &arguments, &environment)?;
        encoded_bytes = checked_launch_bytes(encoded_bytes, workspace.as_os_str())?;

        if workspace.as_os_str().as_bytes().contains(&0) || encoded_bytes > MAX_LAUNCH_BYTES {
            return Err(ProcessPlatformError::InvalidLaunchProfile);
        }

        Ok(Self {
            executable,
            arguments: arguments.into_boxed_slice(),
            environment: environment.into_boxed_slice(),
            workspace,
        })
    }

    #[cfg(test)]
    pub(crate) fn try_new_for_test(
        executable: PathBuf,
        arguments: Vec<OsString>,
        environment: Vec<(OsString, OsString)>,
        workspace: PathBuf,
    ) -> Result<Self, ProcessPlatformError> {
        Self::try_new(executable, arguments, environment, workspace)
    }

    #[must_use]
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub(crate) fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    #[must_use]
    pub(crate) fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }

    #[must_use]
    pub(crate) fn workspace(&self) -> &Path {
        &self.workspace
    }
}

/// One child leader plus the complete process group that the Runtime owns.
pub(crate) struct UnixChildProcess {
    child: Option<Child>,
    leader_pid: u32,
    process_group: Pid,
    stdin: Option<AsyncFd<ChildStdin>>,
    stdout: Option<AsyncFd<ChildStdout>>,
}

/// One bounded Linux `/proc` census for the complete owned process group.
///
/// The snapshot is enforcement evidence while the group is live, not final
/// cleanup proof: members can exit while `/proc` is being traversed. Final
/// absence is still established with group probing plus leader reaping.
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessResourceObservation {
    process_tree_members: u32,
    memory_bytes: u64,
    open_fds: u32,
    cpu_time_nanos: u64,
}

#[cfg(any(target_os = "linux", test))]
impl ProcessResourceObservation {
    #[must_use]
    pub(crate) const fn process_tree_members(self) -> u32 {
        self.process_tree_members
    }

    #[must_use]
    pub(crate) const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    #[must_use]
    pub(crate) const fn open_fds(self) -> u32 {
        self.open_fds
    }

    #[must_use]
    pub(crate) const fn cpu_time_nanos(self) -> u64 {
        self.cpu_time_nanos
    }
}

impl UnixChildProcess {
    /// Launches a fresh process-group leader with only explicit environment and
    /// bounded, nonblocking stdin/stdout pipes.
    pub(crate) fn spawn(profile: &ResolvedProcessLaunch) -> Result<Self, ProcessPlatformError> {
        let mut command = Command::new(profile.executable());
        command
            .args(profile.arguments())
            .env_clear()
            .envs(
                profile
                    .environment()
                    .iter()
                    .map(|(key, value)| (key, value)),
            )
            .current_dir(profile.workspace())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);

        let mut child = command.spawn().map_err(ProcessPlatformError::Io)?;
        let leader_pid = child.id();
        let process_group = Pid::from_raw(
            i32::try_from(leader_pid).map_err(|_| ProcessPlatformError::InvalidChildPid)?,
        );
        let Some(stdin) = child.stdin.take() else {
            reap_on_drop(child, process_group);
            return Err(ProcessPlatformError::MissingPipe);
        };
        let Some(stdout) = child.stdout.take() else {
            reap_on_drop(child, process_group);
            return Err(ProcessPlatformError::MissingPipe);
        };

        if let Err(error) = set_nonblocking(&stdin).and_then(|()| set_nonblocking(&stdout)) {
            reap_on_drop(child, process_group);
            return Err(error);
        }
        let stdin = match AsyncFd::new(stdin) {
            Ok(stdin) => stdin,
            Err(error) => {
                reap_on_drop(child, process_group);
                return Err(ProcessPlatformError::Io(error));
            }
        };
        let stdout = match AsyncFd::new(stdout) {
            Ok(stdout) => stdout,
            Err(error) => {
                reap_on_drop(child, process_group);
                return Err(ProcessPlatformError::Io(error));
            }
        };

        Ok(Self {
            child: Some(child),
            leader_pid,
            process_group,
            stdin: Some(stdin),
            stdout: Some(stdout),
        })
    }

    #[must_use]
    pub(crate) const fn process_group(&self) -> Pid {
        self.process_group
    }

    #[must_use]
    pub(crate) const fn leader_pid(&self) -> u32 {
        self.leader_pid
    }

    /// Writes the complete bounded frame. The caller owns the operation
    /// deadline; cancelling this future never detaches the child owner.
    pub(crate) async fn write_all(&mut self, bytes: &[u8]) -> Result<(), ProcessPlatformError> {
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(ProcessPlatformError::PipeClosed);
        };
        let mut offset = 0;
        while offset < bytes.len() {
            let mut guard = stdin
                .writable_mut()
                .await
                .map_err(ProcessPlatformError::Io)?;
            match guard.try_io(|inner| inner.get_mut().write(&bytes[offset..])) {
                Ok(Ok(0)) => return Err(ProcessPlatformError::PipeClosed),
                Ok(Ok(written)) => offset += written,
                Ok(Err(error)) => return Err(ProcessPlatformError::Io(error)),
                Err(_) => {}
            }
        }
        Ok(())
    }

    /// Reads up to `buffer.len()` bytes. Zero means the child closed stdout.
    pub(crate) async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ProcessPlatformError> {
        let Some(stdout) = self.stdout.as_mut() else {
            return Err(ProcessPlatformError::PipeClosed);
        };
        loop {
            let mut guard = stdout
                .readable_mut()
                .await
                .map_err(ProcessPlatformError::Io)?;
            match guard.try_io(|inner| inner.get_mut().read(buffer)) {
                Ok(Ok(read)) => return Ok(read),
                Ok(Err(error)) => return Err(ProcessPlatformError::Io(error)),
                Err(_) => {}
            }
        }
    }

    /// Reads exactly `length` bytes without permitting an unbounded allocation.
    pub(crate) async fn read_exact(
        &mut self,
        length: usize,
        maximum: usize,
    ) -> Result<Box<[u8]>, ProcessPlatformError> {
        if length > maximum {
            return Err(ProcessPlatformError::ReadLimitExceeded);
        }
        let mut bytes = vec![0; length];
        let mut offset = 0;
        while offset < length {
            let read = self.read(&mut bytes[offset..]).await?;
            if read == 0 {
                return Err(ProcessPlatformError::UnexpectedEof);
            }
            offset += read;
        }
        Ok(bytes.into_boxed_slice())
    }

    pub(crate) fn close_stdin(&mut self) {
        self.stdin = None;
    }

    pub(crate) fn close_stdout(&mut self) {
        self.stdout = None;
    }

    /// Attempts last-resort process-group reclamation for a fixed synchronous
    /// budget. A `false` result retains the sole `Child` owner so the caller
    /// can move it together with every resource the group may still access.
    pub(crate) fn reap_with_budget(&mut self, budget: Duration) -> bool {
        self.close_stdin();
        self.close_stdout();
        let started = Instant::now();
        loop {
            let Some(child) = self.child.as_mut() else {
                return true;
            };
            if try_reap_group(child, self.process_group) {
                self.child = None;
                return true;
            }
            if started.elapsed() >= budget {
                return false;
            }
            thread::sleep(DROP_RETRY_DELAY);
        }
    }

    /// Reclaims the complete process group and leader without detaching the
    /// sole `Child` owner. This is reserved for startup failure and the
    /// ProcessDomain fallback owner after normal signed cleanup was bypassed.
    pub(crate) fn reap_blocking(&mut self) {
        self.close_stdin();
        self.close_stdout();
        let Some(child) = self.child.take() else {
            return;
        };
        reap_until_gone(child, self.process_group);
    }

    /// Requests SIGTERM for the full owned group. `false` proves it is gone;
    /// `true` is conservative and also covers a transient EPERM observation.
    pub(crate) fn terminate_group(&self) -> Result<bool, ProcessPlatformError> {
        signal_group(self.process_group, Some(Signal::SIGTERM))
    }

    /// Requests SIGKILL for the full owned group. `false` proves it is gone;
    /// `true` is conservative and also covers a transient EPERM observation.
    pub(crate) fn kill_group(&self) -> Result<bool, ProcessPlatformError> {
        signal_group(self.process_group, Some(Signal::SIGKILL))
    }

    /// Probes whether any member of the owned process group still exists.
    pub(crate) fn group_exists(&self) -> Result<bool, ProcessPlatformError> {
        signal_group(self.process_group, None)
    }

    /// Counts current process-group members on Linux without retaining a
    /// host-wide process snapshot. Other Unix targets can still prove final
    /// absence, but cannot claim an exact live ownership census.
    #[cfg(target_os = "linux")]
    pub(crate) fn group_member_count(&self, maximum: u32) -> Result<u32, ProcessPlatformError> {
        Ok(observe_group(self.process_group, maximum, None)?.process_tree_members)
    }

    /// Observes and enforces aggregate RSS, open descriptors, process count,
    /// and scheduled CPU time for every currently visible group member.
    #[cfg(target_os = "linux")]
    pub(crate) fn enforce_resource_limits(
        &self,
        limits: ProcessResourceLimits,
    ) -> Result<ProcessResourceObservation, ProcessPlatformError> {
        observe_group(
            self.process_group,
            limits.max_process_tree_members(),
            Some(limits),
        )
    }

    /// Reaps the leader without blocking.
    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>, ProcessPlatformError> {
        self.child
            .as_mut()
            .ok_or(ProcessPlatformError::MissingChildOwner)?
            .try_wait()
            .map_err(ProcessPlatformError::Io)
    }

    /// Reaps the leader after external evidence says it must already be dead.
    pub(crate) fn wait(&mut self) -> Result<ExitStatus, ProcessPlatformError> {
        self.child
            .as_mut()
            .ok_or(ProcessPlatformError::MissingChildOwner)?
            .wait()
            .map_err(ProcessPlatformError::Io)
    }
}

impl fmt::Debug for UnixChildProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnixChildProcess")
            .field("leader_pid", &self.leader_pid)
            .field("process_group", &self.process_group)
            .field("stdin_open", &self.stdin.is_some())
            .field("stdout_open", &self.stdout.is_some())
            .finish()
    }
}

impl Drop for UnixChildProcess {
    fn drop(&mut self) {
        // Normal lifecycle uses signed async cleanup budgets and never reaches
        // this path with a live group. Unexpected Drop retains the Child owner
        // and reaps synchronously. ProcessDomain has a separate bounded handoff
        // that moves this owner together with its workspace when host reactor
        // responsiveness matters.
        self.reap_blocking();
    }
}

fn checked_launch_bytes(current: usize, value: &OsStr) -> Result<usize, ProcessPlatformError> {
    if value.as_bytes().contains(&0) {
        return Err(ProcessPlatformError::InvalidLaunchProfile);
    }
    current
        .checked_add(value.as_bytes().len())
        .and_then(|value| value.checked_add(1))
        .filter(|value| *value <= MAX_LAUNCH_BYTES)
        .ok_or(ProcessPlatformError::InvalidLaunchProfile)
}

fn validate_program(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
) -> Result<(), ProcessPlatformError> {
    if !executable.is_absolute()
        || arguments.len() > MAX_ARGUMENTS
        || environment.len() > MAX_ENVIRONMENT_ENTRIES
    {
        return Err(ProcessPlatformError::InvalidLaunchProfile);
    }
    let mut keys = environment
        .iter()
        .map(|(key, _)| key.as_os_str())
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ProcessPlatformError::InvalidLaunchProfile);
    }
    launch_bytes(executable, arguments, environment)?;
    Ok(())
}

fn launch_bytes(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
) -> Result<usize, ProcessPlatformError> {
    let mut encoded_bytes = checked_launch_bytes(0, executable.as_os_str())?;
    for argument in arguments {
        encoded_bytes = checked_launch_bytes(encoded_bytes, argument)?;
    }
    for (key, value) in environment {
        let key_bytes = key.as_bytes();
        if key_bytes.is_empty() || key_bytes.contains(&b'=') || key_bytes.contains(&0) {
            return Err(ProcessPlatformError::InvalidLaunchProfile);
        }
        encoded_bytes = checked_launch_bytes(encoded_bytes, key)?;
        encoded_bytes = checked_launch_bytes(encoded_bytes, value)?;
    }
    Ok(encoded_bytes)
}

fn set_nonblocking<Fd: std::os::fd::AsFd>(descriptor: &Fd) -> Result<(), ProcessPlatformError> {
    let flags = fcntl(descriptor, FcntlArg::F_GETFL).map_err(ProcessPlatformError::Nix)?;
    let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
    fcntl(descriptor, FcntlArg::F_SETFL(flags)).map_err(ProcessPlatformError::Nix)?;
    Ok(())
}

fn signal_group(process_group: Pid, signal: Option<Signal>) -> Result<bool, ProcessPlatformError> {
    match killpg(process_group, signal) {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        // macOS can report EPERM while the last member is an exiting orphan.
        // This remains positive existence evidence, never cleanup proof. For a
        // real permission failure the caller's bounded wait reaches quarantine.
        Err(Errno::EPERM) => Ok(true),
        Err(error) => Err(ProcessPlatformError::Nix(error)),
    }
}

#[cfg(any(target_os = "linux", test))]
fn observe_group(
    process_group: Pid,
    maximum_members: u32,
    limits: Option<ProcessResourceLimits>,
) -> Result<ProcessResourceObservation, ProcessPlatformError> {
    let mut work = ProcessCensusWork::production();
    observe_group_in(
        Path::new("/proc"),
        process_group,
        maximum_members,
        limits,
        &mut work,
    )
}

#[cfg(any(target_os = "linux", test))]
fn observe_group_in(
    proc_root: &Path,
    process_group: Pid,
    maximum_members: u32,
    limits: Option<ProcessResourceLimits>,
    work: &mut ProcessCensusWork,
) -> Result<ProcessResourceObservation, ProcessPlatformError> {
    let mut observation = ProcessResourceObservation {
        process_tree_members: 0,
        memory_bytes: 0,
        open_fds: 0,
        cpu_time_nanos: 0,
    };
    for entry in fs::read_dir(proc_root).map_err(ProcessPlatformError::Io)? {
        let entry = entry.map_err(ProcessPlatformError::Io)?;
        work.observe_host_entry()?;
        if entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_digit())
        {
            continue;
        }
        let path = entry.path();
        let Some(group) = retry_transient_procfs_permission(|| read_process_group(&path))? else {
            continue;
        };
        if group != process_group.as_raw() {
            continue;
        }
        observation.process_tree_members =
            account_process_tree_member(observation.process_tree_members, maximum_members)?;
        let Some(limits) = limits else {
            continue;
        };
        let Some(member) = retry_transient_procfs_permission(|| {
            observe_member(&path, observation.open_fds, limits, work)
        })?
        else {
            continue;
        };
        observation.memory_bytes = observation
            .memory_bytes
            .checked_add(member.memory_bytes)
            .ok_or(ProcessPlatformError::ResourceCounterOverflow)?;
        observation.open_fds = member.aggregate_open_fds;
        observation.cpu_time_nanos = observation
            .cpu_time_nanos
            .checked_add(member.cpu_time_nanos)
            .ok_or(ProcessPlatformError::ResourceCounterOverflow)?;
        enforce_observation(observation, maximum_members, limits)?;
    }
    Ok(observation)
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessCensusWork {
    host_entries_scanned: u32,
    fd_entries_scanned: u32,
    maximum_host_entries: u32,
    maximum_fd_entries: u32,
}

#[cfg(any(target_os = "linux", test))]
impl ProcessCensusWork {
    const fn production() -> Self {
        Self {
            host_entries_scanned: 0,
            fd_entries_scanned: 0,
            maximum_host_entries: MAX_PROCFS_HOST_ENTRIES_SCANNED,
            maximum_fd_entries: MAX_PROCFS_FD_ENTRIES_SCANNED,
        }
    }

    #[cfg(test)]
    const fn for_test(maximum_host_entries: u32, maximum_fd_entries: u32) -> Self {
        Self {
            host_entries_scanned: 0,
            fd_entries_scanned: 0,
            maximum_host_entries,
            maximum_fd_entries,
        }
    }

    fn observe_host_entry(&mut self) -> Result<(), ProcessPlatformError> {
        observe_census_work(&mut self.host_entries_scanned, self.maximum_host_entries)
    }

    fn observe_fd_entry(&mut self) -> Result<(), ProcessPlatformError> {
        observe_census_work(&mut self.fd_entries_scanned, self.maximum_fd_entries)
    }
}

#[cfg(any(target_os = "linux", test))]
fn observe_census_work(observed: &mut u32, maximum: u32) -> Result<(), ProcessPlatformError> {
    *observed = observed
        .checked_add(1)
        .filter(|next| *next <= maximum)
        .ok_or(ProcessPlatformError::ProcessCensusWorkLimitExceeded)?;
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn account_process_tree_member(observed: u32, maximum: u32) -> Result<u32, ProcessPlatformError> {
    if observed >= maximum {
        return Err(ProcessPlatformError::ProcessTreeLimitExceeded);
    }
    observed
        .checked_add(1)
        .ok_or(ProcessPlatformError::ResourceCounterOverflow)
}

#[cfg(any(target_os = "linux", test))]
fn enforce_observation(
    observation: ProcessResourceObservation,
    maximum_members: u32,
    limits: ProcessResourceLimits,
) -> Result<(), ProcessPlatformError> {
    if observation.process_tree_members > maximum_members {
        return Err(ProcessPlatformError::ProcessTreeLimitExceeded);
    }
    if observation.memory_bytes > limits.max_memory_bytes() {
        return Err(ProcessPlatformError::MemoryLimitExceeded);
    }
    if observation.open_fds > limits.max_open_fds() {
        return Err(ProcessPlatformError::OpenFileLimitExceeded);
    }
    if observation.cpu_time_nanos > limits.max_cpu_time().value() {
        return Err(ProcessPlatformError::CpuTimeLimitExceeded);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn read_process_group(path: &Path) -> Result<Option<i32>, ProcessPlatformError> {
    let Some(stat) = read_optional(path.join("stat"))? else {
        return Ok(None);
    };
    let command_end = stat
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or(ProcessPlatformError::InvalidProcessCensus)?;
    let fields = stat
        .get(command_end.saturating_add(2)..)
        .ok_or(ProcessPlatformError::InvalidProcessCensus)?;
    let mut fields = fields.split(|byte| *byte == b' ');
    let _state = fields.next();
    let _parent = fields.next();
    let group = fields
        .next()
        .and_then(parse_ascii_i32)
        .ok_or(ProcessPlatformError::InvalidProcessCensus)?;
    Ok(Some(group))
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy)]
struct ProcessMemberObservation {
    memory_bytes: u64,
    aggregate_open_fds: u32,
    cpu_time_nanos: u64,
}

#[cfg(any(target_os = "linux", test))]
fn observe_member(
    path: &Path,
    observed_open_fds: u32,
    limits: ProcessResourceLimits,
    work: &mut ProcessCensusWork,
) -> Result<Option<ProcessMemberObservation>, ProcessPlatformError> {
    let Some(status) = read_optional(path.join("status"))? else {
        return Ok(None);
    };
    let memory_bytes = resident_bytes(&status)?;
    let Some(schedstat) = read_optional(path.join("schedstat"))? else {
        return Ok(None);
    };
    let cpu_time_nanos = schedstat
        .split(|byte| byte.is_ascii_whitespace())
        .find(|field| !field.is_empty())
        .and_then(parse_ascii_u64)
        .ok_or(ProcessPlatformError::InvalidProcessCensus)?;
    let Some(aggregate_open_fds) =
        observe_open_fds(path, observed_open_fds, limits.max_open_fds(), work)?
    else {
        return Ok(None);
    };
    Ok(Some(ProcessMemberObservation {
        memory_bytes,
        aggregate_open_fds,
        cpu_time_nanos,
    }))
}

#[cfg(any(target_os = "linux", test))]
fn observe_open_fds(
    path: &Path,
    mut aggregate_open_fds: u32,
    maximum_open_fds: u32,
    work: &mut ProcessCensusWork,
) -> Result<Option<u32>, ProcessPlatformError> {
    if aggregate_open_fds > maximum_open_fds {
        return Err(ProcessPlatformError::OpenFileLimitExceeded);
    }
    let entries = match fs::read_dir(path.join("fd")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ProcessPlatformError::Io(error)),
    };
    for entry in entries {
        entry.map_err(ProcessPlatformError::Io)?;
        if aggregate_open_fds >= maximum_open_fds {
            return Err(ProcessPlatformError::OpenFileLimitExceeded);
        }
        work.observe_fd_entry()?;
        aggregate_open_fds = aggregate_open_fds
            .checked_add(1)
            .ok_or(ProcessPlatformError::ResourceCounterOverflow)?;
    }
    Ok(Some(aggregate_open_fds))
}

#[cfg(any(target_os = "linux", test))]
fn resident_bytes(status: &[u8]) -> Result<u64, ProcessPlatformError> {
    for line in status.split(|byte| *byte == b'\n') {
        let Some(value) = line.strip_prefix(b"VmRSS:") else {
            continue;
        };
        let kibibytes = value
            .split(|byte| byte.is_ascii_whitespace())
            .find(|field| !field.is_empty())
            .and_then(parse_ascii_u64)
            .ok_or(ProcessPlatformError::InvalidProcessCensus)?;
        return kibibytes
            .checked_mul(1_024)
            .ok_or(ProcessPlatformError::ResourceCounterOverflow);
    }
    // A zombie can expose no VmRSS while it is still visible in `/proc`.
    Ok(0)
}

#[cfg(any(target_os = "linux", test))]
fn read_optional(path: PathBuf) -> Result<Option<Vec<u8>>, ProcessPlatformError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ProcessPlatformError::Io(error)),
    }
}

#[cfg(any(target_os = "linux", test))]
fn retry_transient_procfs_permission<T>(
    mut operation: impl FnMut() -> Result<T, ProcessPlatformError>,
) -> Result<T, ProcessPlatformError> {
    let mut retries = 0;
    loop {
        match operation() {
            Err(ProcessPlatformError::Io(error))
                if error.kind() == io::ErrorKind::PermissionDenied
                    && retries < MAX_TRANSIENT_PROCFS_PERMISSION_RETRIES =>
            {
                retries += 1;
                thread::yield_now();
            }
            result => return result,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_ascii_u64(value: &[u8]) -> Option<u64> {
    std::str::from_utf8(value).ok()?.parse().ok()
}

#[cfg(any(target_os = "linux", test))]
fn parse_ascii_i32(value: &[u8]) -> Option<i32> {
    std::str::from_utf8(value).ok()?.parse().ok()
}

fn reap_on_drop(child: Child, process_group: Pid) {
    // Startup can fail before ProcessDomain exists to own a combined fallback.
    // Reap synchronously so the subsequently dropped workspace is never made
    // available to a still-running child.
    reap_until_gone(child, process_group);
}

fn reap_until_gone(mut child: Child, process_group: Pid) {
    while !try_reap_group(&mut child, process_group) {
        thread::sleep(DROP_RETRY_DELAY);
    }
}

fn try_reap_group(child: &mut Child, process_group: Pid) -> bool {
    let _ = signal_group(process_group, Some(Signal::SIGKILL));
    let leader_reaped = child.try_wait().ok().flatten().is_some();
    let group_gone = matches!(signal_group(process_group, None), Ok(false));
    leader_reaped && group_gone
}

#[derive(Debug)]
pub(crate) enum ProcessPlatformError {
    InvalidLaunchProfile,
    InvalidChildPid,
    MissingChildOwner,
    MissingPipe,
    PipeClosed,
    UnexpectedEof,
    ReadLimitExceeded,
    InvalidProcessCensus,
    ProcessCensusWorkLimitExceeded,
    ProcessTreeLimitExceeded,
    MemoryLimitExceeded,
    OpenFileLimitExceeded,
    CpuTimeLimitExceeded,
    ResourceCounterOverflow,
    Io(io::Error),
    Nix(Errno),
}

impl fmt::Display for ProcessPlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLaunchProfile => formatter.write_str("invalid resolved process launch"),
            Self::InvalidChildPid => formatter.write_str("spawned child PID cannot be represented"),
            Self::MissingChildOwner => formatter.write_str("process child owner is missing"),
            Self::MissingPipe => {
                formatter.write_str("spawned child is missing a required IPC pipe")
            }
            Self::PipeClosed => formatter.write_str("process IPC pipe is closed"),
            Self::UnexpectedEof => {
                formatter.write_str("process IPC pipe closed before the frame ended")
            }
            Self::ReadLimitExceeded => {
                formatter.write_str("process IPC read exceeds its fixed bound")
            }
            Self::InvalidProcessCensus => formatter.write_str("process-group census is invalid"),
            Self::ProcessCensusWorkLimitExceeded => {
                formatter.write_str("process-group census exceeds its fixed procfs work bound")
            }
            Self::ProcessTreeLimitExceeded => {
                formatter.write_str("process-group member count exceeds its fixed bound")
            }
            Self::MemoryLimitExceeded => {
                formatter.write_str("process-group resident memory exceeds its fixed bound")
            }
            Self::OpenFileLimitExceeded => {
                formatter.write_str("process-group open descriptors exceed their fixed bound")
            }
            Self::CpuTimeLimitExceeded => {
                formatter.write_str("process-group CPU time exceeds its fixed bound")
            }
            Self::ResourceCounterOverflow => {
                formatter.write_str("process-group resource census overflowed")
            }
            Self::Io(error) => write!(formatter, "process platform I/O failed: {error}"),
            Self::Nix(error) => write!(formatter, "process platform syscall failed: {error}"),
        }
    }
}

impl std::error::Error for ProcessPlatformError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::fs;

    use tokio::time::{Duration, timeout};

    use super::*;

    static WORKSPACE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestWorkspace(PathBuf);

    impl TestWorkspace {
        fn create() -> Self {
            let sequence = WORKSPACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "paraegox-process-platform-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test workspace should be unique");
            Self(path)
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("test workspace should be removable");
        }
    }

    fn shell_profile(workspace: &Path, script: &str) -> ResolvedProcessLaunch {
        ResolvedProcessLaunch::try_new_for_test(
            PathBuf::from("/bin/sh"),
            vec![OsString::from("-c"), OsString::from(script)],
            vec![(OsString::from("EXPLICIT"), OsString::from("present"))],
            workspace.to_path_buf(),
        )
        .expect("shell launch should be valid")
    }

    async fn read_to_end(process: &mut UnixChildProcess) -> Vec<u8> {
        let mut result = Vec::new();
        let mut chunk = [0_u8; 128];
        loop {
            let read = process.read(&mut chunk).await.expect("read should succeed");
            if read == 0 {
                return result;
            }
            result.extend_from_slice(&chunk[..read]);
        }
    }

    #[test]
    fn launch_profile_rejects_relative_paths_and_unbounded_arguments() {
        let workspace = TestWorkspace::create();
        let relative = ResolvedProcessLaunch::try_new_for_test(
            PathBuf::from("bin/worker"),
            Vec::new(),
            Vec::new(),
            workspace.0.clone(),
        );
        assert!(matches!(
            relative,
            Err(ProcessPlatformError::InvalidLaunchProfile)
        ));

        let too_many = ResolvedProcessLaunch::try_new_for_test(
            PathBuf::from("/bin/sh"),
            vec![OsString::from("x"); MAX_ARGUMENTS + 1],
            Vec::new(),
            workspace.0.clone(),
        );
        assert!(matches!(
            too_many,
            Err(ProcessPlatformError::InvalidLaunchProfile)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn launch_clears_environment_sets_workspace_and_round_trips_pipe() {
        let workspace = TestWorkspace::create();
        let profile = shell_profile(
            &workspace.0,
            "IFS= read -r line; printf '%s|%s|%s|%s' \"$PWD\" \"${HOME-unset}\" \"$EXPLICIT\" \"$line\"",
        );
        let mut process = UnixChildProcess::spawn(&profile).expect("worker should launch");

        process
            .write_all(b"hello\n")
            .await
            .expect("write should succeed");
        process.close_stdin();
        let output = timeout(Duration::from_secs(2), read_to_end(&mut process))
            .await
            .expect("worker should answer");
        let status = process.wait().expect("leader should be reaped");

        assert!(status.success());
        assert_eq!(
            String::from_utf8(output).expect("worker output should be utf-8"),
            format!(
                "{}|unset|present|hello",
                fs::canonicalize(&workspace.0)
                    .expect("workspace should canonicalize")
                    .display()
            )
        );
        assert!(!process.group_exists().expect("group probe should succeed"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn term_then_kill_reaps_an_uncooperative_group() {
        let workspace = TestWorkspace::create();
        let profile = shell_profile(
            &workspace.0,
            "trap '' TERM; printf r; while :; do sleep 1; done",
        );
        let mut process = UnixChildProcess::spawn(&profile).expect("worker should launch");
        assert_eq!(
            process
                .read_exact(1, 1)
                .await
                .expect("worker should become ready")
                .as_ref(),
            b"r"
        );

        assert!(process.terminate_group().expect("TERM should be delivered"));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            process
                .try_wait()
                .expect("leader probe should succeed")
                .is_none()
        );
        assert!(process.kill_group().expect("KILL should be delivered"));
        let mut status = None;
        timeout(Duration::from_secs(2), async {
            loop {
                if status.is_none() {
                    status = process.try_wait().expect("leader probe should succeed");
                }
                let group_gone = !process.group_exists().expect("group probe should succeed");
                if status.is_some() && group_gone {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("leader and complete process group should exit after KILL");

        assert!(!status.expect("leader status should be retained").success());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn group_kill_removes_a_same_group_grandchild() {
        let workspace = TestWorkspace::create();
        let profile = shell_profile(&workspace.0, "sleep 60 & printf '%s\\n' \"$!\"; wait");
        let mut process = UnixChildProcess::spawn(&profile).expect("worker should launch");
        let mut pid_bytes = Vec::new();
        let mut byte = [0_u8; 1];
        while byte[0] != b'\n' {
            assert_eq!(
                process
                    .read(&mut byte)
                    .await
                    .expect("pid read should succeed"),
                1
            );
            pid_bytes.push(byte[0]);
        }
        let grandchild: i32 = String::from_utf8(pid_bytes)
            .expect("pid should be utf-8")
            .trim()
            .parse()
            .expect("pid should be numeric");

        assert!(process.kill_group().expect("KILL should be delivered"));
        timeout(Duration::from_secs(2), async {
            loop {
                let leader_gone = process
                    .try_wait()
                    .expect("leader probe should succeed")
                    .is_some();
                let group_gone = !process.group_exists().expect("group probe should succeed");
                if leader_gone && group_gone {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("complete process group should disappear");
        assert!(matches!(
            nix::sys::signal::kill(Pid::from_raw(grandchild), None),
            Err(Errno::ESRCH)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn linux_group_census_enforces_aggregate_resource_limits() {
        let workspace = TestWorkspace::create();
        let profile = shell_profile(&workspace.0, "exec /bin/sleep 60");
        let process = UnixChildProcess::spawn(&profile).expect("worker should launch");
        tokio::time::sleep(Duration::from_millis(10)).await;
        let generous = ProcessResourceLimits::try_new(
            128 * 1_024 * 1_024,
            64,
            1,
            paraegox_kernel::time::BoundedDuration::from_nanos(1_000_000_000),
        )
        .expect("resource limits");
        let observed = process
            .enforce_resource_limits(generous)
            .expect("small worker must fit the generous limits");
        assert_eq!(observed.process_tree_members(), 1);
        assert!(observed.memory_bytes() > 0);
        assert!(observed.open_fds() >= 3);
        assert!(observed.cpu_time_nanos() <= generous.max_cpu_time().value());

        let memory_too_small = ProcessResourceLimits::try_new(
            1,
            64,
            1,
            paraegox_kernel::time::BoundedDuration::from_nanos(1_000_000_000),
        )
        .expect("resource limits");
        assert!(matches!(
            process.enforce_resource_limits(memory_too_small),
            Err(ProcessPlatformError::MemoryLimitExceeded)
        ));

        let fd_limit_too_small = ProcessResourceLimits::try_new(
            128 * 1_024 * 1_024,
            1,
            1,
            paraegox_kernel::time::BoundedDuration::from_nanos(1_000_000_000),
        )
        .expect("resource limits");
        assert!(matches!(
            process.enforce_resource_limits(fd_limit_too_small),
            Err(ProcessPlatformError::OpenFileLimitExceeded)
        ));
    }

    #[test]
    fn procfs_census_caps_fail_closed_without_partial_observations() {
        let workspace = TestWorkspace::create();
        let proc_root = workspace.0.join("proc");
        for pid in [101_u32, 102] {
            let member = proc_root.join(pid.to_string());
            fs::create_dir_all(&member).expect("synthetic proc member");
            fs::write(member.join("stat"), format!("{pid} (worker) S 1 42 0\n"))
                .expect("synthetic stat");
            fs::write(member.join("status"), b"VmRSS:\t1 kB\n").expect("synthetic status");
            fs::write(member.join("schedstat"), b"7 0 0\n").expect("synthetic schedstat");
            let fd_root = member.join("fd");
            fs::create_dir(&fd_root).expect("synthetic member fd root");
            fs::write(fd_root.join("0"), b"").expect("synthetic member fd");
        }

        let mut host_limited = ProcessCensusWork::for_test(1, 4);
        assert!(matches!(
            observe_group_in(&proc_root, Pid::from_raw(42), 2, None, &mut host_limited,),
            Err(ProcessPlatformError::ProcessCensusWorkLimitExceeded)
        ));

        let mut tree_limited = ProcessCensusWork::for_test(4, 4);
        assert!(matches!(
            observe_group_in(&proc_root, Pid::from_raw(42), 1, None, &mut tree_limited,),
            Err(ProcessPlatformError::ProcessTreeLimitExceeded)
        ));

        let limits = ProcessResourceLimits::try_new(
            4_096,
            2,
            2,
            paraegox_kernel::time::BoundedDuration::from_nanos(100),
        )
        .expect("synthetic resource limits");
        let mut complete = ProcessCensusWork::for_test(4, 4);
        let observation = observe_group_in(
            &proc_root,
            Pid::from_raw(42),
            2,
            Some(limits),
            &mut complete,
        )
        .expect("bounded synthetic census should complete");
        assert_eq!(observation.process_tree_members(), 2);
        assert_eq!(observation.memory_bytes(), 2_048);
        assert_eq!(observation.open_fds(), 2);
        assert_eq!(observation.cpu_time_nanos(), 14);

        let synthetic_member = workspace.0.join("member");
        let fd_root = synthetic_member.join("fd");
        fs::create_dir_all(&fd_root).expect("synthetic fd root");
        fs::write(fd_root.join("0"), b"").expect("synthetic fd");
        fs::write(fd_root.join("1"), b"").expect("synthetic fd");

        let mut fd_work_limited = ProcessCensusWork::for_test(4, 1);
        assert!(matches!(
            observe_open_fds(&synthetic_member, 0, 2, &mut fd_work_limited),
            Err(ProcessPlatformError::ProcessCensusWorkLimitExceeded)
        ));

        let mut signed_fd_limited = ProcessCensusWork::for_test(4, 4);
        assert!(matches!(
            observe_open_fds(&synthetic_member, 0, 1, &mut signed_fd_limited),
            Err(ProcessPlatformError::OpenFileLimitExceeded)
        ));
    }

    #[test]
    fn transient_procfs_permission_is_retried_but_persistent_denial_fails_closed() {
        let mut transient_attempts = 0_u8;
        let observed = retry_transient_procfs_permission(|| {
            transient_attempts += 1;
            if transient_attempts <= 3 {
                Err(ProcessPlatformError::Io(io::Error::from(
                    io::ErrorKind::PermissionDenied,
                )))
            } else {
                Ok(17_u8)
            }
        })
        .expect("a bounded transient exec window should be retried");
        assert_eq!(observed, 17);
        assert_eq!(transient_attempts, 4);

        let mut persistent_attempts = 0_u8;
        let denied = retry_transient_procfs_permission(|| {
            persistent_attempts += 1;
            Err::<(), _>(ProcessPlatformError::Io(io::Error::from(
                io::ErrorKind::PermissionDenied,
            )))
        });
        assert!(matches!(
            denied,
            Err(ProcessPlatformError::Io(error))
                if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(
            persistent_attempts,
            MAX_TRANSIENT_PROCFS_PERMISSION_RETRIES + 1
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drop_does_not_detach_the_owned_group() {
        let workspace = TestWorkspace::create();
        let profile = shell_profile(&workspace.0, "while :; do :; done");
        let process = UnixChildProcess::spawn(&profile).expect("worker should launch");
        let group = process.process_group();

        let started = std::time::Instant::now();
        drop(process);
        assert!(started.elapsed() < Duration::from_millis(500));

        assert!(matches!(killpg(group, None), Err(Errno::ESRCH)));
    }
}
