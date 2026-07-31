#![cfg(unix)]

use core::time::Duration;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::Pid;
use paraegox_runtime::host_watchdog::{
    HOST_WATCHDOG_ENABLE_ENV, HOST_WATCHDOG_GENERATION_ENV, HOST_WATCHDOG_HANDSHAKE_MILLIS_ENV,
    HOST_WATCHDOG_HEARTBEAT_MILLIS_ENV, HostBootstrapPhase,
};
use paraegox_runtime_host::service_manager::{
    HostRestartPolicy, HostTerminationTiming, HostWatchdogTiming, RuntimeHostLaunch,
    RuntimeHostServiceManager, RuntimeHostServiceManagerPolicy, RuntimeHostServiceManagerSnapshot,
    RuntimeHostServiceManagerState, ServiceManagerEvidenceKind, ServiceManagerFailure,
};

const POLL: Duration = Duration::from_millis(5);
const STATE_TIMEOUT: Duration = Duration::from_secs(15);
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn runtime_host_executable() -> &'static str {
    env!("CARGO_BIN_EXE_paraegox-runtime-host")
}

fn watchdog_executable() -> &'static str {
    env!("CARGO_BIN_EXE_paraegox-runtime-host-watchdog")
}

fn test_policy() -> RuntimeHostServiceManagerPolicy {
    RuntimeHostServiceManagerPolicy::try_new(
        HostWatchdogTiming::try_new(
            Duration::from_millis(20),
            Duration::from_secs(2),
            Duration::from_secs(10),
            Duration::from_secs(8),
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(5),
        )
        .expect("test watchdog timing must be valid"),
        HostTerminationTiming::try_new(Duration::from_millis(60), Duration::from_secs(2), POLL)
            .expect("test termination timing must be valid"),
        HostRestartPolicy::try_new(
            Duration::from_secs(5),
            2,
            Duration::from_millis(20),
            Duration::from_millis(40),
            Duration::ZERO,
        )
        .expect("test restart policy must be valid"),
        256,
    )
    .expect("test service-manager policy must be valid")
}

fn drive_until(
    manager: &mut RuntimeHostServiceManager,
    predicate: impl Fn(RuntimeHostServiceManagerSnapshot) -> bool,
) -> RuntimeHostServiceManagerSnapshot {
    let deadline = Instant::now() + STATE_TIMEOUT;
    loop {
        let snapshot = manager
            .poll()
            .unwrap_or_else(|error| panic!("external service-manager poll failed: {error}"));
        if predicate(snapshot) {
            return snapshot;
        }
        if Instant::now() >= deadline {
            let kinds = manager
                .evidence()
                .map(|entry| entry.kind())
                .collect::<Vec<_>>();
            panic!("service-manager state timed out at {snapshot:?}; evidence={kinds:?}");
        }
        thread::sleep(POLL);
    }
}

fn process_pid(pid: u32) -> Pid {
    Pid::from_raw(i32::try_from(pid).expect("test child PID must fit POSIX pid_t"))
}

fn assert_process_gone(pid: u32) {
    assert_eq!(
        kill(process_pid(pid), None),
        Err(Errno::ESRCH),
        "reaped RuntimeHost PID must no longer exist"
    );
}

fn assert_process_group_gone(process_group: u32) {
    assert_eq!(
        killpg(process_pid(process_group), None),
        Err(Errno::ESRCH),
        "owned RuntimeHost process group must be absent before restart"
    );
}

#[test]
fn external_manager_detects_real_stall_and_exit_then_quarantines_restart_storm() {
    let launch = RuntimeHostLaunch::try_new(runtime_host_executable())
        .expect("exact RuntimeHost executable must be valid");
    let mut manager = RuntimeHostServiceManager::try_start(launch, test_policy())
        .expect("external service manager must start RuntimeHost");

    let mut first = drive_until(&mut manager, |snapshot| {
        snapshot.state() == RuntimeHostServiceManagerState::Running
    });
    let live_evidence_deadline = Instant::now() + STATE_TIMEOUT;
    while !manager_has_live_evidence(&manager) {
        first = manager
            .poll()
            .expect("live RuntimeHost evidence poll must succeed");
        assert!(
            Instant::now() < live_evidence_deadline,
            "RuntimeHost heartbeat/control evidence timed out"
        );
        thread::sleep(POLL);
    }
    let first_pid = first
        .active_pid()
        .expect("running child must expose its PID");
    let initial_kinds = manager
        .evidence()
        .map(|entry| entry.kind())
        .collect::<Vec<_>>();
    assert_eq!(
        first.generation(),
        1,
        "first generation restarted before stable evidence: {initial_kinds:?}"
    );

    // The heartbeat deadline is deliberately shorter than the next control
    // probe interval. Remaining on generation 1 proves heartbeat output does
    // not depend on a probe unblocking the inherited input stream.
    let independent_heartbeat_deadline = Instant::now() + Duration::from_millis(350);
    while Instant::now() < independent_heartbeat_deadline {
        let stable = manager
            .poll()
            .expect("independent heartbeat poll must succeed");
        assert_eq!(stable.state(), RuntimeHostServiceManagerState::Running);
        assert_eq!(stable.generation(), 1);
        thread::sleep(POLL);
    }
    let heartbeat_count = manager
        .evidence()
        .filter(|entry| matches!(entry.kind(), ServiceManagerEvidenceKind::RunningHeartbeat))
        .count();
    let probe_count = manager
        .evidence()
        .filter(|entry| {
            matches!(
                entry.kind(),
                ServiceManagerEvidenceKind::ControlProbeSent(_)
            )
        })
        .count();
    assert!(heartbeat_count >= 5, "heartbeat must advance continuously");
    assert_eq!(probe_count, 1, "no second control probe should be required");

    kill(process_pid(first_pid), Signal::SIGSTOP).expect("test SIGSTOP must reach RuntimeHost");
    let second = drive_until(&mut manager, |snapshot| {
        snapshot.state() == RuntimeHostServiceManagerState::Running && snapshot.generation() == 2
    });
    let second_pid = second
        .active_pid()
        .expect("replacement RuntimeHost must expose its PID");
    assert_ne!(second_pid, first_pid);
    assert_process_gone(first_pid);

    kill(process_pid(second_pid), Signal::SIGKILL).expect("test SIGKILL must reach RuntimeHost");
    let third = drive_until(&mut manager, |snapshot| {
        snapshot.state() == RuntimeHostServiceManagerState::Running && snapshot.generation() == 3
    });
    let third_pid = third
        .active_pid()
        .expect("second replacement RuntimeHost must expose its PID");
    assert_process_gone(second_pid);

    kill(process_pid(third_pid), Signal::SIGKILL).expect("test restart storm kill must succeed");
    let quarantined = drive_until(&mut manager, |snapshot| {
        snapshot.state() == RuntimeHostServiceManagerState::Quarantined
    });
    assert_eq!(quarantined.generation(), 3);
    assert_eq!(quarantined.active_pid(), None);
    assert_eq!(quarantined.restart_attempts_in_window(), 2);
    assert_process_gone(third_pid);

    let retained = manager.evidence().copied().collect::<Vec<_>>();
    assert!(retained.len() <= 256);
    assert!(retained.iter().any(|entry| {
        entry.kind() == ServiceManagerEvidenceKind::BootstrapProgress(HostBootstrapPhase::Running)
    }));
    assert!(
        retained
            .iter()
            .any(|entry| matches!(entry.kind(), ServiceManagerEvidenceKind::RunningHeartbeat))
    );
    assert!(retained.iter().any(|entry| matches!(
        entry.kind(),
        ServiceManagerEvidenceKind::ControlAcknowledged(_)
    )));
    assert!(retained.iter().any(|entry| matches!(
        entry.kind(),
        ServiceManagerEvidenceKind::FailureDetected(
            ServiceManagerFailure::ControlUnresponsive | ServiceManagerFailure::HeartbeatMissed
        )
    )));
    assert!(
        retained
            .iter()
            .any(|entry| entry.kind() == ServiceManagerEvidenceKind::TermSent)
    );
    assert!(
        retained
            .iter()
            .any(|entry| entry.kind() == ServiceManagerEvidenceKind::KillSent)
    );
    assert!(retained.iter().any(|entry| matches!(
        entry.kind(),
        ServiceManagerEvidenceKind::Quarantined(ServiceManagerFailure::HostExited)
    )));

    let evidence_before = quarantined.evidence_entries();
    thread::sleep(Duration::from_millis(100));
    for _ in 0..10 {
        let unchanged = manager.poll().expect("quarantine poll must be read-only");
        assert_eq!(
            unchanged.state(),
            RuntimeHostServiceManagerState::Quarantined
        );
        assert_eq!(unchanged.generation(), 3);
        assert_eq!(unchanged.active_pid(), None);
        assert_eq!(unchanged.evidence_entries(), evidence_before);
    }
    manager
        .shutdown()
        .expect("quarantined manager shutdown must be idempotent");
}

fn manager_has_live_evidence(manager: &RuntimeHostServiceManager) -> bool {
    let mut heartbeat = false;
    let mut acknowledgement = false;
    for entry in manager.evidence() {
        heartbeat |= matches!(entry.kind(), ServiceManagerEvidenceKind::RunningHeartbeat);
        acknowledgement |= matches!(
            entry.kind(),
            ServiceManagerEvidenceKind::ControlAcknowledged(_)
        );
    }
    heartbeat && acknowledgement
}

#[test]
fn normal_manager_shutdown_reaps_leader_and_observes_exact_process_group_absent() {
    let launch = RuntimeHostLaunch::try_new(runtime_host_executable())
        .expect("exact RuntimeHost executable must be valid");
    let mut manager = RuntimeHostServiceManager::try_start(launch, test_policy())
        .expect("external service manager must start RuntimeHost");
    let running = drive_until(&mut manager, |snapshot| {
        snapshot.state() == RuntimeHostServiceManagerState::Running
    });
    assert_eq!(
        running.generation(),
        1,
        "startup must not restart under load"
    );
    let pid = running
        .active_pid()
        .expect("running RuntimeHost must expose its PID");

    manager
        .shutdown()
        .expect("normal service-manager shutdown must clean the exact group");
    assert_eq!(
        manager.snapshot().state(),
        RuntimeHostServiceManagerState::Stopped
    );
    assert_process_gone(pid);
    assert_process_group_gone(pid);
    let evidence = manager.evidence().copied().collect::<Vec<_>>();
    let shutdown = evidence
        .iter()
        .position(|entry| {
            entry.generation() == running.generation()
                && entry.pid() == Some(pid)
                && entry.kind() == ServiceManagerEvidenceKind::ShutdownRequested
        })
        .expect("normal shutdown request evidence must exist");
    let term = evidence
        .iter()
        .position(|entry| {
            entry.generation() == running.generation()
                && entry.pid() == Some(pid)
                && entry.kind() == ServiceManagerEvidenceKind::TermSent
        })
        .expect("normal shutdown must signal the owned group");
    let reaped = evidence
        .iter()
        .position(|entry| {
            entry.generation() == running.generation()
                && entry.pid() == Some(pid)
                && entry.kind() == ServiceManagerEvidenceKind::Reaped
        })
        .expect("normal shutdown must prove leader and group cleanup");
    assert!(shutdown < term);
    assert!(term < reaped);
    assert!(!evidence.iter().any(|entry| matches!(
        entry.kind(),
        ServiceManagerEvidenceKind::RestartScheduled { .. }
    )));
}

struct SameGroupDescendantFixture {
    directory: PathBuf,
    executable: PathBuf,
    descendant_pid: PathBuf,
}

impl SameGroupDescendantFixture {
    fn create() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test wall clock must follow the Unix epoch")
            .as_nanos();
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "paraegox-watchdog-pgid-{}-{unique}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("test fixture directory must be created");
        let executable = directory.join("runtime-host-fixture.sh");
        let descendant_pid = directory.join("descendant.pid");
        let quoted_pid_path = descendant_pid
            .as_os_str()
            .to_string_lossy()
            .replace('\'', "'\\''");
        let script = format!(
            "#!/bin/sh\ntrap '' TERM\n(\n  trap '' TERM\n  while :; do sleep 1; done\n) >/dev/null 2>&1 &\necho \"$!\" > '{quoted_pid_path}'\nsleep 0.2\nexit 23\n"
        );
        fs::write(&executable, script).expect("test fixture executable must be written");
        let mut permissions = fs::metadata(&executable)
            .expect("test fixture metadata must exist")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions)
            .expect("test fixture executable mode must be installed");
        Self {
            directory,
            executable,
            descendant_pid,
        }
    }

    fn wait_for_descendant_pid(&self) -> u32 {
        let deadline = Instant::now() + STATE_TIMEOUT;
        loop {
            if let Ok(contents) = fs::read_to_string(&self.descendant_pid)
                && let Ok(pid) = contents.trim().parse()
            {
                return pid;
            }
            assert!(
                Instant::now() < deadline,
                "fixture descendant PID was not published"
            );
            thread::sleep(POLL);
        }
    }
}

impl Drop for SameGroupDescendantFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn executable_quarantine_stays_signal_responsive_instead_of_falling_into_drop() {
    let fixture = SameGroupDescendantFixture::create();
    let failing_runtime = fixture.directory.join("failing-runtime-host.sh");
    fs::write(&failing_runtime, "#!/bin/sh\nsleep 0.1\nexit 23\n")
        .expect("failing RuntimeHost fixture must be written");
    let mut permissions = fs::metadata(&failing_runtime)
        .expect("failing RuntimeHost fixture metadata must exist")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&failing_runtime, permissions)
        .expect("failing RuntimeHost fixture mode must be installed");
    let quarantine_log = fixture.directory.join("watchdog.stderr");
    let log = fs::File::create(&quarantine_log).expect("watchdog log must be created");
    let child = Command::new(watchdog_executable())
        .arg(&failing_runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .expect("external watchdog executable must spawn");
    let mut child = ChildGuard(child);

    let deadline = Instant::now() + STATE_TIMEOUT;
    loop {
        if let Some(status) = child
            .0
            .try_wait()
            .expect("watchdog executable wait must succeed")
        {
            panic!("watchdog exited before operator-controlled quarantine shutdown: {status:?}");
        }
        let evidence = fs::read_to_string(&quarantine_log).unwrap_or_default();
        if evidence.contains("entered quarantine") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "watchdog executable did not expose quarantine"
        );
        thread::sleep(POLL);
    }

    kill(process_pid(child.0.id()), Signal::SIGTERM)
        .expect("operator terminate must reach quarantined watchdog");
    let status = wait_for_direct_child(&mut child);
    assert_eq!(status.code(), Some(3));
}

fn descendant_cleanup_policy() -> RuntimeHostServiceManagerPolicy {
    RuntimeHostServiceManagerPolicy::try_new(
        HostWatchdogTiming::try_new(
            Duration::from_millis(20),
            Duration::from_millis(250),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_millis(500),
            Duration::from_millis(200),
            Duration::from_secs(1),
        )
        .expect("descendant fixture watchdog timing must be valid"),
        HostTerminationTiming::try_new(Duration::from_millis(80), Duration::from_secs(1), POLL)
            .expect("descendant fixture termination timing must be valid"),
        HostRestartPolicy::try_new(
            Duration::from_secs(10),
            1,
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::ZERO,
        )
        .expect("descendant fixture restart policy must be valid"),
        64,
    )
    .expect("descendant fixture service-manager policy must be valid")
}

#[test]
fn leader_exit_does_not_restart_until_term_ignoring_same_group_descendant_is_killed() {
    let fixture = SameGroupDescendantFixture::create();
    let launch = RuntimeHostLaunch::try_new(&fixture.executable)
        .expect("fixture executable must be a valid exact launch");
    let mut manager = RuntimeHostServiceManager::try_start(launch, descendant_cleanup_policy())
        .expect("fixture service manager must start");
    let leader_pid = manager
        .snapshot()
        .active_pid()
        .expect("fixture leader PID must be active");
    let descendant_pid = fixture.wait_for_descendant_pid();
    assert_eq!(
        kill(process_pid(descendant_pid), None),
        Ok(()),
        "TERM-ignoring descendant must be live before manager cleanup"
    );
    // Do not poll the manager until the direct shell leader has certainly
    // exited. It remains waitable as our Child while the same-PG descendant
    // stays live, exercising the exact leader-exited cleanup branch.
    thread::sleep(Duration::from_secs(1));

    let backoff = drive_until(&mut manager, |snapshot| {
        snapshot.state() == RuntimeHostServiceManagerState::RestartBackoff
    });
    assert_eq!(backoff.generation(), 1);
    assert_eq!(backoff.active_pid(), None);
    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);

    let kinds = manager
        .evidence()
        .map(|entry| entry.kind())
        .collect::<Vec<_>>();
    let position = |expected| {
        kinds
            .iter()
            .position(|kind| *kind == expected)
            .unwrap_or_else(|| panic!("missing external cleanup evidence: {expected:?}"))
    };
    let observed = position(ServiceManagerEvidenceKind::HostExitObserved);
    let detected = position(ServiceManagerEvidenceKind::FailureDetected(
        ServiceManagerFailure::HostExited,
    ));
    let term = position(ServiceManagerEvidenceKind::TermSent);
    let kill = position(ServiceManagerEvidenceKind::KillSent);
    let reaped = position(ServiceManagerEvidenceKind::Reaped);
    let restart = kinds
        .iter()
        .position(|kind| matches!(kind, ServiceManagerEvidenceKind::RestartScheduled { .. }))
        .expect("restart must be scheduled only after exact PGID cleanup");
    assert!(observed < detected);
    assert!(detected < term);
    assert!(term < kill);
    assert!(kill < reaped);
    assert!(reaped < restart);
    manager
        .shutdown()
        .expect("backoff shutdown must not spawn a replacement");
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for_direct_child(child: &mut ChildGuard) -> std::process::ExitStatus {
    let deadline = Instant::now() + STATE_TIMEOUT;
    loop {
        if let Some(status) = child
            .0
            .try_wait()
            .expect("direct RuntimeHost wait must succeed")
        {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "direct RuntimeHost exit timed out"
        );
        thread::sleep(POLL);
    }
}

#[test]
fn explicit_watchdog_profile_fails_closed_without_a_control_handshake() {
    let child = Command::new(runtime_host_executable())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env(HOST_WATCHDOG_ENABLE_ENV, "1")
        .env(HOST_WATCHDOG_GENERATION_ENV, "1")
        .env(HOST_WATCHDOG_HEARTBEAT_MILLIS_ENV, "20")
        .env(HOST_WATCHDOG_HANDSHAKE_MILLIS_ENV, "50")
        .spawn()
        .expect("explicit watchdog RuntimeHost must spawn");
    let mut child = ChildGuard(child);
    let status = wait_for_direct_child(&mut child);
    assert!(
        !status.success(),
        "missing watchdog handshake must fail closed"
    );
}

#[test]
fn ordinary_runtime_host_without_watchdog_profile_still_exits_cleanly_on_interrupt() {
    // The wrapper installs an inherited SIGINT-ignore disposition and reports
    // that fact before exec. Repeated SIGINT remains harmless until the
    // RuntimeHost replaces it with Tokio's handler, avoiding a scheduler race
    // between `Command::spawn` returning and the child first being polled.
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("trap '' INT; printf R; exec \"$PARAEGOX_TEST_RUNTIME_HOST\"")
        .env("PARAEGOX_TEST_RUNTIME_HOST", runtime_host_executable())
        .env_remove(HOST_WATCHDOG_ENABLE_ENV)
        .env_remove(HOST_WATCHDOG_GENERATION_ENV)
        .env_remove(HOST_WATCHDOG_HEARTBEAT_MILLIS_ENV)
        .env_remove(HOST_WATCHDOG_HANDSHAKE_MILLIS_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("ordinary RuntimeHost must spawn");
    let mut wrapper_output = child
        .stdout
        .take()
        .expect("signal-safe wrapper must expose its readiness byte");
    let mut ready = [0_u8; 1];
    wrapper_output
        .read_exact(&mut ready)
        .expect("signal-safe wrapper must report readiness");
    assert_eq!(ready, *b"R");
    drop(wrapper_output);
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + STATE_TIMEOUT;
    loop {
        if let Some(status) = child
            .0
            .try_wait()
            .expect("ordinary RuntimeHost wait must succeed")
        {
            assert!(
                status.success(),
                "ordinary RuntimeHost must exit cleanly: {status:?}"
            );
            break;
        }
        kill(process_pid(child.0.id()), Signal::SIGINT)
            .expect("test interrupt must reach RuntimeHost");
        assert!(
            Instant::now() < deadline,
            "watchdog-disabled RuntimeHost did not install its signal handler"
        );
        thread::sleep(POLL);
    }
}
