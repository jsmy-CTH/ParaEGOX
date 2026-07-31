//! Runnable POSIX reference adapter for externally supervising RuntimeHost.

use std::process::ExitCode;

#[cfg(unix)]
use paraegox_runtime_host::service_manager::{
    RuntimeHostLaunch, RuntimeHostServiceManager, RuntimeHostServiceManagerPolicy,
    RuntimeHostServiceManagerState,
};

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchdogLoopMode {
    Supervising,
    Quarantined,
}

#[cfg(unix)]
impl WatchdogLoopMode {
    fn observe(&mut self, state: RuntimeHostServiceManagerState) {
        if state == RuntimeHostServiceManagerState::Quarantined {
            *self = Self::Quarantined;
        }
    }

    fn isolate(&mut self) {
        *self = Self::Quarantined;
    }

    const fn polling_enabled(self) -> bool {
        matches!(self, Self::Supervising)
    }

    fn shutdown_exit_code(self) -> ExitCode {
        match self {
            Self::Supervising => ExitCode::SUCCESS,
            Self::Quarantined => ExitCode::from(3),
        }
    }
}

#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(executable) = arguments.next() else {
        eprintln!("usage: paraegox-runtime-host-watchdog <exact-runtime-host-executable>");
        return ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("usage: paraegox-runtime-host-watchdog <exact-runtime-host-executable>");
        return ExitCode::from(2);
    }

    let result = async move {
        let policy = RuntimeHostServiceManagerPolicy::reference_defaults()?;
        let launch = RuntimeHostLaunch::try_new(executable)?;
        let mut manager = RuntimeHostServiceManager::try_start(launch, policy)?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut terminate_open = true;
        let mut interrupt_open = true;
        let mut mode = WatchdogLoopMode::Supervising;
        loop {
            if mode.polling_enabled() {
                match manager.poll() {
                    Ok(snapshot) => {
                        if snapshot.state() == RuntimeHostServiceManagerState::Quarantined {
                            eprintln!(
                                "RuntimeHost external watchdog entered quarantine: generation={} active_pid={:?}",
                                snapshot.generation(),
                                snapshot.active_pid()
                            );
                        }
                        mode.observe(snapshot.state());
                    }
                    Err(error) => {
                        // A poll error can accompany a transition that still
                        // retains the sole child owner. Stop polling (and thus
                        // forbid replacement) but keep the explicit control
                        // loop alive until a shutdown signal can drive cleanup.
                        eprintln!("RuntimeHost external watchdog isolated after poll failure: {error}");
                        mode.isolate();
                    }
                }
            }
            tokio::select! {
                () = tokio::time::sleep(policy.poll_interval()), if mode.polling_enabled() => {}
                signal = interrupt.recv(), if interrupt_open => {
                    if signal.is_none() {
                        interrupt_open = false;
                        continue;
                    }
                    match manager.shutdown() {
                        Ok(()) => return Ok::<_, Box<dyn std::error::Error>>(mode.shutdown_exit_code()),
                        Err(error) => {
                            eprintln!("RuntimeHost external watchdog retained ownership after interrupt cleanup failed: {error}");
                            mode.isolate();
                        }
                    }
                }
                signal = terminate.recv(), if terminate_open => {
                    if signal.is_none() {
                        terminate_open = false;
                        continue;
                    }
                    match manager.shutdown() {
                        Ok(()) => return Ok(mode.shutdown_exit_code()),
                        Err(error) => {
                            eprintln!("RuntimeHost external watchdog retained ownership after terminate cleanup failed: {error}");
                            mode.isolate();
                        }
                    }
                }
                () = std::future::pending::<()>() => {}
            }
        }
    }
    .await;

    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("RuntimeHost external watchdog failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!("the reference RuntimeHost watchdog adapter currently requires POSIX process groups");
    ExitCode::from(2)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn quarantined_loop_waits_for_signal_and_permanently_disables_polling() {
        let mut mode = WatchdogLoopMode::Supervising;
        assert!(mode.polling_enabled());

        mode.observe(RuntimeHostServiceManagerState::Quarantined);
        assert_eq!(mode, WatchdogLoopMode::Quarantined);
        assert!(!mode.polling_enabled());

        // An isolated loop cannot be returned to supervision by a later
        // observation, so no replacement path is reachable.
        mode.observe(RuntimeHostServiceManagerState::Bootstrapping);
        assert_eq!(mode, WatchdogLoopMode::Quarantined);
        assert!(!mode.polling_enabled());
    }

    #[test]
    fn poll_error_uses_the_same_signal_driven_quarantine_loop() {
        let mut mode = WatchdogLoopMode::Supervising;
        mode.isolate();
        assert_eq!(mode, WatchdogLoopMode::Quarantined);
        assert!(!mode.polling_enabled());
    }
}
