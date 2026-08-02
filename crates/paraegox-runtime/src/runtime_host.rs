//! Controlled current-thread reactor process owned by RuntimeHost.
//!
//! The executable exposes only the bootstrap substrate; S4 Loop and S5 Thread
//! component paths remain crate-private Harnesses. It does not expose an apply
//! endpoint, claim an active Deployment revision, or create a public Card runner.

use core::fmt;
use core::future::Future;
use core::num::NonZeroUsize;
use core::pin::Pin;
use core::time::Duration;
use std::env;
use std::io;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsFd;

#[cfg(unix)]
use nix::fcntl::{FcntlArg, OFlag, fcntl};
#[cfg(unix)]
use nix::unistd::dup;
use paraegox_kernel::time::{ClockDomainRef, ClockGeneration};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use tokio::runtime::Builder;
use tokio::time::MissedTickBehavior;

use crate::card_executor::catch_callback;
use crate::component_runtime::{
    ComponentRuntimeError, ComponentShutdownReport, SingleSubjectComponentRuntime,
};
use crate::core_service::{
    CoreServiceLifecycleError, CoreServiceLifecycleOwner, CoreServiceLifecycleReport,
    CoreServiceStartupEvidence,
};
use crate::host_watchdog::{
    HOST_WATCHDOG_ENABLE_ENV, HOST_WATCHDOG_FRAME_BYTES, HOST_WATCHDOG_GENERATION_ENV,
    HOST_WATCHDOG_HANDSHAKE_MILLIS_ENV, HOST_WATCHDOG_HEARTBEAT_MILLIS_ENV, HostBootstrapPhase,
    HostControlProbeNonce, HostWatchdogDirection, HostWatchdogFrame, HostWatchdogFrameBody,
    HostWatchdogGeneration, HostWatchdogProtocolError, HostWatchdogSequence,
};
use crate::runtime_clock::RuntimeClock;
use crate::task_registry::{
    CancellationSource, RuntimeTaskKind, TaskCompletion, TaskOutcome, TaskRegistry,
    TaskRegistryError,
};
use crate::thread_registry::{RuntimeThreadRegistry, ThreadRegistryError};

const RUNTIME_CLOCK_DOMAIN: ClockDomainRef = ClockDomainRef::from_bytes(*b"PX-runtime-clock");
const RUNTIME_CLOCK_GENERATION: u64 = 1;
const MAX_RUNTIME_TASKS: usize = 256;
const ROOT_CLEANUP_BUDGET: Duration = Duration::from_secs(5);
const MIN_WATCHDOG_MILLIS: u64 = 10;
const MAX_WATCHDOG_MILLIS: u64 = 60_000;

/// The only values an owned Runtime task can return to the root scope.
enum RuntimeOwnedTaskResult {
    Plain,
    HostWatchdog(Result<(), RuntimeHostWatchdogError>),
    Component(ComponentTaskResult),
    CoreServices(Result<CoreServiceTaskReport, CoreServiceLifecycleError>),
    CoreServiceConstructionPanicked,
}

#[derive(Clone, Copy, Debug)]
struct RuntimeHostWatchdogConfig {
    generation: HostWatchdogGeneration,
    heartbeat_interval: Duration,
    handshake_timeout: Duration,
}

#[derive(Debug)]
enum RuntimeHostWatchdogError {
    Io(io::Error),
    Protocol(HostWatchdogProtocolError),
    HandshakeTimeout,
    WrongDirection,
    WrongGeneration,
    WrongSequence,
    UnexpectedFrame,
    SequenceExhausted,
    #[cfg(not(unix))]
    UnsupportedPlatform,
}

impl RuntimeHostWatchdogConfig {
    fn from_environment() -> Result<Option<Self>, RuntimeHostProcessError> {
        match env::var(HOST_WATCHDOG_ENABLE_ENV) {
            Err(env::VarError::NotPresent) => return Ok(None),
            Ok(value) if value == "1" => {}
            Ok(_) | Err(env::VarError::NotUnicode(_)) => {
                return Err(RuntimeHostProcessError::WatchdogConfiguration);
            }
        }
        if !cfg!(unix) {
            return Err(RuntimeHostProcessError::WatchdogConfiguration);
        }

        let generation =
            required_environment_u64(HOST_WATCHDOG_GENERATION_ENV).and_then(|value| {
                HostWatchdogGeneration::try_new(value)
                    .map_err(|_| RuntimeHostProcessError::WatchdogConfiguration)
            })?;
        let heartbeat_millis = bounded_watchdog_millis(required_environment_u64(
            HOST_WATCHDOG_HEARTBEAT_MILLIS_ENV,
        )?)?;
        let handshake_millis = bounded_watchdog_millis(required_environment_u64(
            HOST_WATCHDOG_HANDSHAKE_MILLIS_ENV,
        )?)?;
        Ok(Some(Self {
            generation,
            heartbeat_interval: Duration::from_millis(heartbeat_millis),
            handshake_timeout: Duration::from_millis(handshake_millis),
        }))
    }
}

fn required_environment_u64(name: &str) -> Result<u64, RuntimeHostProcessError> {
    env::var(name)
        .map_err(|_| RuntimeHostProcessError::WatchdogConfiguration)?
        .parse()
        .map_err(|_| RuntimeHostProcessError::WatchdogConfiguration)
}

const fn bounded_watchdog_millis(value: u64) -> Result<u64, RuntimeHostProcessError> {
    if value < MIN_WATCHDOG_MILLIS || value > MAX_WATCHDOG_MILLIS {
        Err(RuntimeHostProcessError::WatchdogConfiguration)
    } else {
        Ok(value)
    }
}

/// Outcome of the source-adapter operation that runs inside the component
/// owner. Cleanup is recorded separately and always attempted afterwards.
enum ComponentOperationFact {
    Completed,
    Failed(ComponentRuntimeError),
    Panicked,
}

/// One task result keeps operation failure and terminal cleanup evidence
/// separate so neither can launder the other.
struct ComponentTaskReport {
    operation: ComponentOperationFact,
    cleanup: Result<ComponentShutdownReport, ComponentRuntimeError>,
}

enum ComponentTaskResult {
    /// Construction failed before any callback or lifecycle obligation could
    /// be admitted.
    ConstructionFailed(ComponentRuntimeError),
    ConstructionPanicked,
    Lifecycle(ComponentTaskReport),
}

/// Ready-time facts and terminal cleanup from the same owned lifecycle task.
struct CoreServiceTaskReport {
    startup: CoreServiceStartupEvidence,
    lifecycle: CoreServiceLifecycleReport,
}

/// Narrow inputs injected into one crate-private component lifecycle task.
///
/// It deliberately exposes neither a reactor handle nor an apply/readiness
/// capability. The task receives only the RuntimeHost clock and a descendant
/// of the structured root cancellation tree.
#[derive(Clone, Debug)]
struct ComponentTaskContext {
    clock: RuntimeClock,
    cancellation: CancellationSource,
}

type ComponentOperationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), ComponentRuntimeError>> + Send + 'a>>;
type ComponentOperation = Box<
    dyn for<'a> FnOnce(
            &'a mut SingleSubjectComponentRuntime,
            ComponentTaskContext,
        ) -> ComponentOperationFuture<'a>
        + Send
        + 'static,
>;

/// Concrete structured owner retained by the Runtime task across operation
/// failure and panic until component shutdown has produced terminal evidence.
struct OwnedComponentLifecycle {
    component: SingleSubjectComponentRuntime,
    context: ComponentTaskContext,
    operation: ComponentOperation,
}

impl OwnedComponentLifecycle {
    #[cfg(test)]
    fn new(
        component: SingleSubjectComponentRuntime,
        context: ComponentTaskContext,
        operation: ComponentOperation,
    ) -> Self {
        Self {
            component,
            context,
            operation,
        }
    }

    async fn run(self) -> ComponentTaskResult {
        let Self {
            mut component,
            context,
            operation,
        } = self;
        // The closure itself is invoked inside the contained Future, so a
        // constructor panic, poll panic, or Future destructor panic is caught
        // before the concrete component owner can be lost.
        let operation =
            match catch_callback(async { operation(&mut component, context).await }).await {
                Ok(Ok(())) => ComponentOperationFact::Completed,
                Ok(Err(error)) => ComponentOperationFact::Failed(error),
                Err(()) => ComponentOperationFact::Panicked,
            };
        let cleanup = component.shutdown().await;
        ComponentTaskResult::Lifecycle(ComponentTaskReport { operation, cleanup })
    }
}

type ComponentLifecycleFactory = Box<
    dyn FnOnce(ComponentTaskContext) -> Result<OwnedComponentLifecycle, ComponentRuntimeError>
        + Send
        + 'static,
>;

/// Narrow construction inputs for the fixed private provider -> consumer owner.
#[derive(Clone, Debug)]
struct CoreServiceTaskContext {
    clock: RuntimeClock,
    cancellation: CancellationSource,
}

type CoreServiceLifecycleFactory = Box<
    dyn FnOnce(
            CoreServiceTaskContext,
        ) -> Result<CoreServiceLifecycleOwner, CoreServiceLifecycleError>
        + Send
        + 'static,
>;

/// Starts the RuntimeHost reactor and waits for Ctrl-C or an OS termination
/// signal.
///
/// This process is intentionally idle until a later admitted control adapter
/// supplies canonical apply requests. Starting it proves the single owned
/// reactor and graceful root-scope exit only; it does not prove Card readiness,
/// Deployment assembly, persistence, Fabric, or production availability. The
/// external watchdog endpoint is disabled unless the complete explicit PXHW
/// environment profile is installed by the spawning service manager.
pub fn run_runtime_host_process() -> Result<(), RuntimeHostProcessError> {
    let watchdog = RuntimeHostWatchdogConfig::from_environment()?;
    run_reactor_until_with_watchdog(runtime_host_shutdown_signal(), watchdog)
}

async fn runtime_host_shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[cfg(test)]
fn run_reactor_until<F>(shutdown: F) -> Result<(), RuntimeHostProcessError>
where
    F: Future<Output = io::Result<()>>,
{
    run_reactor_until_with_setup(shutdown, |_| Ok(()))
}

#[cfg(test)]
fn run_reactor_until_with_setup<F, S>(shutdown: F, setup: S) -> Result<(), RuntimeHostProcessError>
where
    F: Future<Output = io::Result<()>>,
    S: FnOnce(&mut RuntimeHostScope) -> Result<(), RuntimeHostProcessError>,
{
    run_reactor_until_with_bootstrap(shutdown, None, setup)
}

#[cfg(test)]
fn run_reactor_until_with_bootstrap<F, S>(
    shutdown: F,
    component: Option<ComponentLifecycleFactory>,
    setup: S,
) -> Result<(), RuntimeHostProcessError>
where
    F: Future<Output = io::Result<()>>,
    S: FnOnce(&mut RuntimeHostScope) -> Result<(), RuntimeHostProcessError>,
{
    run_reactor_until_with_owned_lifecycles(shutdown, component, None, setup)
}

#[cfg(test)]
fn run_reactor_until_with_owned_lifecycles<F, S>(
    shutdown: F,
    component: Option<ComponentLifecycleFactory>,
    core_services: Option<CoreServiceLifecycleFactory>,
    setup: S,
) -> Result<(), RuntimeHostProcessError>
where
    F: Future<Output = io::Result<()>>,
    S: FnOnce(&mut RuntimeHostScope) -> Result<(), RuntimeHostProcessError>,
{
    run_reactor_until_with_watchdog_and_owned_lifecycles(
        shutdown,
        component,
        core_services,
        None,
        setup,
    )
}

fn run_reactor_until_with_watchdog<F>(
    shutdown: F,
    watchdog: Option<RuntimeHostWatchdogConfig>,
) -> Result<(), RuntimeHostProcessError>
where
    F: Future<Output = io::Result<()>>,
{
    run_reactor_until_with_watchdog_and_owned_lifecycles(shutdown, None, None, watchdog, |_| Ok(()))
}

fn run_reactor_until_with_watchdog_and_owned_lifecycles<F, S>(
    shutdown: F,
    component: Option<ComponentLifecycleFactory>,
    core_services: Option<CoreServiceLifecycleFactory>,
    watchdog: Option<RuntimeHostWatchdogConfig>,
    setup: S,
) -> Result<(), RuntimeHostProcessError>
where
    F: Future<Output = io::Result<()>>,
    S: FnOnce(&mut RuntimeHostScope) -> Result<(), RuntimeHostProcessError>,
{
    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .max_blocking_threads(1)
        .thread_name("paraegox-runtime-blocking")
        .build()
        .map_err(RuntimeHostProcessError::BuildReactor)?;
    runtime.block_on(async move {
        let mut scope = RuntimeHostScope::try_new()?;
        let root_cancellation = scope.cancellation().view();
        scope.spawn(RuntimeTaskKind::HostControl, move || async move {
            root_cancellation.cancelled().await;
        })?;
        let watchdog_setup =
            watchdog.map_or(Ok(()), |config| scope.spawn_host_watchdog_endpoint(config));
        let component_setup = watchdog_setup.and_then(|()| {
            component.map_or(Ok(()), |build| {
                scope.spawn_canonical_component_lifecycle(build)
            })
        });
        let lifecycle_setup = component_setup.and_then(|()| {
            core_services.map_or(Ok(()), |build| {
                scope.spawn_fixed_core_service_lifecycle(build)
            })
        });
        let operation = match lifecycle_setup.and_then(|()| setup(&mut scope)) {
            Ok(()) => scope.wait_for_shutdown_or_owned_exit(shutdown).await,
            Err(error) => Err(error),
        };
        let cleanup = scope.shutdown().await;
        match (operation, cleanup) {
            (_, Err(cleanup_error)) => Err(cleanup_error),
            (Err(operation_error), Ok(())) => Err(operation_error),
            (Ok(()), Ok(())) => Ok(()),
        }
    })
}

#[cfg(unix)]
async fn run_host_watchdog_endpoint(
    config: RuntimeHostWatchdogConfig,
    cancellation: crate::task_registry::CancellationView,
) -> Result<(), RuntimeHostWatchdogError> {
    let input = duplicate_nonblocking(&io::stdin())?;
    let output = duplicate_nonblocking(&io::stdout())?;
    let mut host_sequence = 1_u64;
    let mut manager_sequence = 1_u64;

    for phase in [
        HostBootstrapPhase::ReactorStarted,
        HostBootstrapPhase::ControlReady,
        HostBootstrapPhase::Running,
    ] {
        write_host_watchdog_frame(
            &output,
            config.generation,
            &mut host_sequence,
            HostWatchdogFrameBody::BootstrapProgress(phase),
        )
        .await?;
    }

    let first_probe = tokio::time::timeout(
        config.handshake_timeout,
        read_manager_probe(&input, config.generation, &mut manager_sequence),
    )
    .await
    .map_err(|_| RuntimeHostWatchdogError::HandshakeTimeout)??;
    write_host_watchdog_frame(
        &output,
        config.generation,
        &mut host_sequence,
        HostWatchdogFrameBody::ControlAck(first_probe),
    )
    .await?;

    let mut heartbeat = tokio::time::interval(config.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            probe = read_manager_probe(&input, config.generation, &mut manager_sequence) => {
                write_host_watchdog_frame(
                    &output,
                    config.generation,
                    &mut host_sequence,
                    HostWatchdogFrameBody::ControlAck(probe?),
                ).await?;
            }
            _ = heartbeat.tick() => {
                write_host_watchdog_frame(
                    &output,
                    config.generation,
                    &mut host_sequence,
                    HostWatchdogFrameBody::RunningHeartbeat,
                ).await?;
            }
        }
    }
}

#[cfg(not(unix))]
async fn run_host_watchdog_endpoint(
    _config: RuntimeHostWatchdogConfig,
    _cancellation: crate::task_registry::CancellationView,
) -> Result<(), RuntimeHostWatchdogError> {
    Err(RuntimeHostWatchdogError::UnsupportedPlatform)
}

#[cfg(unix)]
async fn write_host_watchdog_frame(
    output: &AsyncFd<std::fs::File>,
    generation: HostWatchdogGeneration,
    sequence: &mut u64,
    body: HostWatchdogFrameBody,
) -> Result<(), RuntimeHostWatchdogError> {
    let frame_sequence = take_watchdog_sequence(sequence)?;
    let frame = HostWatchdogFrame::new(generation, frame_sequence, body).encode();
    write_inherited_all(output, &frame).await
}

#[cfg(unix)]
async fn read_manager_probe(
    input: &AsyncFd<std::fs::File>,
    generation: HostWatchdogGeneration,
    expected_sequence: &mut u64,
) -> Result<HostControlProbeNonce, RuntimeHostWatchdogError> {
    let mut bytes = [0_u8; HOST_WATCHDOG_FRAME_BYTES];
    read_inherited_exact(input, &mut bytes).await?;
    let frame = HostWatchdogFrame::decode(&bytes).map_err(RuntimeHostWatchdogError::Protocol)?;
    if frame.direction() != HostWatchdogDirection::ManagerToHost {
        return Err(RuntimeHostWatchdogError::WrongDirection);
    }
    if frame.generation() != generation {
        return Err(RuntimeHostWatchdogError::WrongGeneration);
    }
    if frame.sequence().value() != *expected_sequence {
        return Err(RuntimeHostWatchdogError::WrongSequence);
    }
    *expected_sequence = expected_sequence
        .checked_add(1)
        .ok_or(RuntimeHostWatchdogError::SequenceExhausted)?;
    match frame.body() {
        HostWatchdogFrameBody::ControlProbe(nonce) => Ok(nonce),
        HostWatchdogFrameBody::BootstrapProgress(_)
        | HostWatchdogFrameBody::RunningHeartbeat
        | HostWatchdogFrameBody::ControlAck(_) => Err(RuntimeHostWatchdogError::UnexpectedFrame),
    }
}

#[cfg(unix)]
fn duplicate_nonblocking<Fd>(
    descriptor: &Fd,
) -> Result<AsyncFd<std::fs::File>, RuntimeHostWatchdogError>
where
    Fd: AsFd,
{
    let duplicate = dup(descriptor).map_err(nix_watchdog_error)?;
    let flags = fcntl(&duplicate, FcntlArg::F_GETFL).map_err(nix_watchdog_error)?;
    let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
    fcntl(&duplicate, FcntlArg::F_SETFL(flags)).map_err(nix_watchdog_error)?;
    AsyncFd::new(std::fs::File::from(duplicate)).map_err(RuntimeHostWatchdogError::Io)
}

#[cfg(unix)]
async fn read_inherited_exact(
    input: &AsyncFd<std::fs::File>,
    bytes: &mut [u8],
) -> Result<(), RuntimeHostWatchdogError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let mut ready = input
            .readable()
            .await
            .map_err(RuntimeHostWatchdogError::Io)?;
        match ready.try_io(|inner| {
            let mut file = inner.get_ref();
            file.read(&mut bytes[offset..])
        }) {
            Ok(Ok(0)) => {
                return Err(RuntimeHostWatchdogError::Io(io::Error::from(
                    io::ErrorKind::UnexpectedEof,
                )));
            }
            Ok(Ok(read)) => offset += read,
            Ok(Err(error)) => return Err(RuntimeHostWatchdogError::Io(error)),
            Err(_) => {}
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn write_inherited_all(
    output: &AsyncFd<std::fs::File>,
    bytes: &[u8],
) -> Result<(), RuntimeHostWatchdogError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let mut ready = output
            .writable()
            .await
            .map_err(RuntimeHostWatchdogError::Io)?;
        match ready.try_io(|inner| {
            let mut file = inner.get_ref();
            file.write(&bytes[offset..])
        }) {
            Ok(Ok(0)) => {
                return Err(RuntimeHostWatchdogError::Io(io::Error::from(
                    io::ErrorKind::WriteZero,
                )));
            }
            Ok(Ok(written)) => offset += written,
            Ok(Err(error)) => return Err(RuntimeHostWatchdogError::Io(error)),
            Err(_) => {}
        }
    }
    Ok(())
}

#[cfg(unix)]
fn nix_watchdog_error(error: nix::errno::Errno) -> RuntimeHostWatchdogError {
    RuntimeHostWatchdogError::Io(io::Error::from_raw_os_error(error as i32))
}

fn take_watchdog_sequence(
    sequence: &mut u64,
) -> Result<HostWatchdogSequence, RuntimeHostWatchdogError> {
    let current =
        HostWatchdogSequence::try_new(*sequence).map_err(RuntimeHostWatchdogError::Protocol)?;
    *sequence = sequence
        .checked_add(1)
        .ok_or(RuntimeHostWatchdogError::SequenceExhausted)?;
    Ok(current)
}

/// Internal root scope for the one reactor. Every spawned Runtime task must be
/// registered here; Card code receives only descendant cancellation views.
struct RuntimeHostScope {
    clock: RuntimeClock,
    tasks: TaskRegistry<RuntimeOwnedTaskResult>,
    thread_domains: Option<RuntimeThreadRegistry>,
}

impl RuntimeHostScope {
    fn try_new() -> Result<Self, RuntimeHostProcessError> {
        let generation = ClockGeneration::try_new(RUNTIME_CLOCK_GENERATION)
            .map_err(|_| RuntimeHostProcessError::InvalidConfiguration)?;
        let Some(maximum) = NonZeroUsize::new(MAX_RUNTIME_TASKS) else {
            return Err(RuntimeHostProcessError::InvalidConfiguration);
        };
        Ok(Self {
            clock: RuntimeClock::new(RUNTIME_CLOCK_DOMAIN, generation, 0),
            tasks: TaskRegistry::new(maximum),
            thread_domains: None,
        })
    }

    fn cancellation(&self) -> CancellationSource {
        self.tasks.root_cancellation()
    }

    /// Supervises the root signal and every owned task concurrently.
    ///
    /// An external shutdown that is ready in the same poll wins so a task
    /// completing as a consequence of that signal is classified by normal
    /// structured cleanup. Before that signal, however, every completion is a
    /// fail-closed process error; the caller still cancels and joins all
    /// remaining tasks after this method returns.
    async fn wait_for_shutdown_or_owned_exit<F>(
        &mut self,
        shutdown: F,
    ) -> Result<(), RuntimeHostProcessError>
    where
        F: Future<Output = io::Result<()>>,
    {
        let mut shutdown = Box::pin(shutdown);
        tokio::select! {
            biased;
            result = &mut shutdown => result.map_err(RuntimeHostProcessError::ShutdownSignal),
            completion = self.tasks.join_next() => {
                let Some(completion) = completion else {
                    return Err(RuntimeHostProcessError::OwnedTaskExitedEarly);
                };
                Err(early_completion_error(completion))
            }
        }
    }

    fn spawn<F, Build>(
        &mut self,
        kind: RuntimeTaskKind,
        build: Build,
    ) -> Result<(), RuntimeHostProcessError>
    where
        F: Future<Output = ()> + Send + 'static,
        Build: FnOnce() -> F,
    {
        self.tasks
            .try_spawn(kind, move || {
                let future = build();
                async move {
                    future.await;
                    RuntimeOwnedTaskResult::Plain
                }
            })
            .map(|_| ())
            .map_err(spawn_error)
    }

    /// Installs the explicitly configured PXHW endpoint as a structured child
    /// of this reactor. Its heartbeat and control acknowledgement are both
    /// polled by this same current-thread event loop, while every liveness
    /// conclusion and process action remains in the external manager.
    fn spawn_host_watchdog_endpoint(
        &mut self,
        config: RuntimeHostWatchdogConfig,
    ) -> Result<(), RuntimeHostProcessError> {
        let cancellation = self.tasks.root_cancellation().child().view();
        self.tasks
            .try_spawn(RuntimeTaskKind::HostControl, move || async move {
                RuntimeOwnedTaskResult::HostWatchdog(
                    run_host_watchdog_endpoint(config, cancellation).await,
                )
            })
            .map(|_| ())
            .map_err(spawn_error)
    }

    /// Admits one canonical component lifecycle as a structured child task.
    ///
    /// The factory runs only after TaskRegistry capacity admission. Success
    /// must carry the private report produced by component shutdown, allowing
    /// the root owner to reject a lifecycle that did not reach exact zero.
    /// This is an internal composition seam, not a public Card runner or P2e
    /// apply/readiness endpoint.
    fn spawn_canonical_component_lifecycle<Build>(
        &mut self,
        build: Build,
    ) -> Result<(), RuntimeHostProcessError>
    where
        Build: FnOnce(ComponentTaskContext) -> Result<OwnedComponentLifecycle, ComponentRuntimeError>
            + Send
            + 'static,
    {
        let context = ComponentTaskContext {
            clock: self.clock,
            cancellation: self.tasks.root_cancellation().child(),
        };
        debug_assert_eq!(context.clock.domain(), self.clock.domain());
        debug_assert_eq!(context.clock.generation(), self.clock.generation());
        debug_assert!(!context.cancellation.view().is_cancelled());
        self.tasks
            .try_spawn(RuntimeTaskKind::ComponentLifecycle, move || async move {
                let result = match catch_callback(async { build(context) }).await {
                    Ok(Ok(lifecycle)) => lifecycle.run().await,
                    Ok(Err(error)) => ComponentTaskResult::ConstructionFailed(error),
                    Err(()) => ComponentTaskResult::ConstructionPanicked,
                };
                RuntimeOwnedTaskResult::Component(result)
            })
            .map(|_| ())
            .map_err(spawn_error)
    }

    /// Admits the fixed provider -> consumer lifecycle only after task capacity
    /// admission. The same structured task owns startup, root cancellation,
    /// reverse cleanup, ready-time facts, and the terminal cleanup report.
    fn spawn_fixed_core_service_lifecycle<Build>(
        &mut self,
        build: Build,
    ) -> Result<(), RuntimeHostProcessError>
    where
        Build: FnOnce(
                CoreServiceTaskContext,
            ) -> Result<CoreServiceLifecycleOwner, CoreServiceLifecycleError>
            + Send
            + 'static,
    {
        let context = CoreServiceTaskContext {
            clock: self.clock,
            cancellation: self.tasks.root_cancellation().child(),
        };
        debug_assert_eq!(context.clock.domain(), self.clock.domain());
        debug_assert_eq!(context.clock.generation(), self.clock.generation());
        debug_assert!(!context.cancellation.view().is_cancelled());
        self.tasks
            .try_spawn(RuntimeTaskKind::CoreServiceLifecycle, move || async move {
                let owner = match catch_callback(async { build(context) }).await {
                    Ok(owner) => owner,
                    Err(()) => return RuntimeOwnedTaskResult::CoreServiceConstructionPanicked,
                };
                let result = async move {
                    let mut owner = owner?;
                    let startup = owner.startup().await;
                    let startup_evidence = owner.startup_evidence()?;
                    if startup.is_ready() && startup_evidence.is_ready() {
                        owner.root_cancellation().cancelled().await;
                    }
                    let _ = owner.shutdown().await;
                    let lifecycle = owner.terminal_report()?;
                    Ok(CoreServiceTaskReport {
                        startup: startup_evidence,
                        lifecycle,
                    })
                }
                .await;
                RuntimeOwnedTaskResult::CoreServices(result)
            })
            .map(|_| ())
            .map_err(spawn_error)
    }

    async fn shutdown(&mut self) -> Result<(), RuntimeHostProcessError> {
        let report = self.tasks.shutdown(ROOT_CLEANUP_BUDGET).await;
        let task_leak = !self.tasks.is_empty();
        let thread_cleanup = self
            .thread_domains
            .as_mut()
            .map(RuntimeThreadRegistry::shutdown)
            .transpose();
        if let Err(error) = thread_cleanup {
            return Err(thread_cleanup_error(error));
        }
        if task_leak {
            return Err(RuntimeHostProcessError::OwnedTaskLeak);
        }
        let forced = report.forced();
        let mut panicked = false;
        let mut cancelled = false;
        let mut component_failed = false;
        let mut component_nonzero = false;
        let mut core_service_failed = false;
        let mut core_service_nonzero = false;
        let mut watchdog_failure = None;
        for completion in report.into_completions() {
            match completion.into_outcome() {
                TaskOutcome::Completed(RuntimeOwnedTaskResult::Plain) => {}
                TaskOutcome::Completed(RuntimeOwnedTaskResult::HostWatchdog(Ok(()))) => {}
                TaskOutcome::Completed(RuntimeOwnedTaskResult::HostWatchdog(Err(error))) => {
                    watchdog_failure = Some(watchdog_process_error(error));
                }
                TaskOutcome::Completed(RuntimeOwnedTaskResult::Component(component)) => {
                    let facts = component_task_facts(component);
                    panicked |= facts.panicked;
                    component_failed |= facts.failed;
                    component_nonzero |= facts.nonzero_cleanup;
                }
                TaskOutcome::Completed(RuntimeOwnedTaskResult::CoreServices(Ok(services))) => {
                    core_service_failed |=
                        !services.startup.is_ready() || !services.lifecycle.startup().is_ready();
                    core_service_nonzero |= !services.lifecycle.cleanup().is_zero_cleanup();
                }
                TaskOutcome::Completed(RuntimeOwnedTaskResult::CoreServices(Err(_))) => {
                    core_service_failed = true;
                }
                TaskOutcome::Completed(RuntimeOwnedTaskResult::CoreServiceConstructionPanicked) => {
                    panicked = true;
                }
                TaskOutcome::Cancelled => cancelled = true,
                TaskOutcome::Panicked => panicked = true,
            }
        }
        if component_nonzero {
            return Err(RuntimeHostProcessError::OwnedComponentNonZeroCleanup);
        }
        if core_service_nonzero {
            return Err(RuntimeHostProcessError::OwnedCoreServiceNonZeroCleanup);
        }
        if let Some(error) = watchdog_failure {
            return Err(error);
        }
        if panicked {
            return Err(RuntimeHostProcessError::OwnedTaskPanicked);
        }
        if component_failed {
            return Err(RuntimeHostProcessError::OwnedComponentTaskFailed);
        }
        if core_service_failed {
            return Err(RuntimeHostProcessError::OwnedCoreServiceTaskFailed);
        }
        if forced || cancelled {
            return Err(RuntimeHostProcessError::OwnedTaskForcedAbort);
        }
        self.clock
            .reading()
            .map_err(|_| RuntimeHostProcessError::ClockFailed)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ComponentTaskFacts {
    failed: bool,
    panicked: bool,
    nonzero_cleanup: bool,
}

fn component_task_facts(result: ComponentTaskResult) -> ComponentTaskFacts {
    let mut facts = ComponentTaskFacts {
        failed: false,
        panicked: false,
        nonzero_cleanup: false,
    };
    match result {
        ComponentTaskResult::ConstructionFailed(error) => {
            let _ = error;
            facts.failed = true;
        }
        ComponentTaskResult::ConstructionPanicked => facts.panicked = true,
        ComponentTaskResult::Lifecycle(report) => {
            match report.operation {
                ComponentOperationFact::Completed => {}
                ComponentOperationFact::Failed(error) => {
                    let _ = error;
                    facts.failed = true;
                }
                ComponentOperationFact::Panicked => facts.panicked = true,
            }
            match report.cleanup {
                Ok(cleanup) => facts.nonzero_cleanup = !cleanup.is_zero_cleanup(),
                Err(error) => {
                    let _ = error;
                    facts.failed = true;
                }
            }
        }
    }
    facts
}

fn early_completion_error(
    completion: TaskCompletion<RuntimeOwnedTaskResult>,
) -> RuntimeHostProcessError {
    match completion.into_outcome() {
        TaskOutcome::Completed(RuntimeOwnedTaskResult::Plain) => {
            RuntimeHostProcessError::OwnedTaskExitedEarly
        }
        TaskOutcome::Completed(RuntimeOwnedTaskResult::HostWatchdog(Ok(()))) => {
            RuntimeHostProcessError::WatchdogExitedEarly
        }
        TaskOutcome::Completed(RuntimeOwnedTaskResult::HostWatchdog(Err(error))) => {
            watchdog_process_error(error)
        }
        TaskOutcome::Completed(RuntimeOwnedTaskResult::Component(component)) => {
            let facts = component_task_facts(component);
            if facts.nonzero_cleanup {
                RuntimeHostProcessError::OwnedComponentNonZeroCleanup
            } else if facts.panicked {
                RuntimeHostProcessError::OwnedTaskPanicked
            } else if facts.failed {
                RuntimeHostProcessError::OwnedComponentTaskFailed
            } else {
                RuntimeHostProcessError::OwnedTaskExitedEarly
            }
        }
        TaskOutcome::Completed(RuntimeOwnedTaskResult::CoreServices(Ok(services))) => {
            if !services.lifecycle.cleanup().is_zero_cleanup() {
                RuntimeHostProcessError::OwnedCoreServiceNonZeroCleanup
            } else if !services.startup.is_ready() || !services.lifecycle.startup().is_ready() {
                RuntimeHostProcessError::OwnedCoreServiceTaskFailed
            } else {
                RuntimeHostProcessError::OwnedTaskExitedEarly
            }
        }
        TaskOutcome::Completed(RuntimeOwnedTaskResult::CoreServices(Err(_))) => {
            RuntimeHostProcessError::OwnedCoreServiceTaskFailed
        }
        TaskOutcome::Completed(RuntimeOwnedTaskResult::CoreServiceConstructionPanicked) => {
            RuntimeHostProcessError::OwnedTaskPanicked
        }
        TaskOutcome::Cancelled => RuntimeHostProcessError::OwnedTaskForcedAbort,
        TaskOutcome::Panicked => RuntimeHostProcessError::OwnedTaskPanicked,
    }
}

fn watchdog_process_error(error: RuntimeHostWatchdogError) -> RuntimeHostProcessError {
    match error {
        RuntimeHostWatchdogError::Io(error) => {
            let _ = error;
            RuntimeHostProcessError::WatchdogIoFailed
        }
        RuntimeHostWatchdogError::HandshakeTimeout => {
            RuntimeHostProcessError::WatchdogHandshakeFailed
        }
        RuntimeHostWatchdogError::Protocol(error) => {
            let _ = error;
            RuntimeHostProcessError::WatchdogProtocolFailed
        }
        RuntimeHostWatchdogError::WrongDirection
        | RuntimeHostWatchdogError::WrongGeneration
        | RuntimeHostWatchdogError::WrongSequence
        | RuntimeHostWatchdogError::UnexpectedFrame
        | RuntimeHostWatchdogError::SequenceExhausted => {
            RuntimeHostProcessError::WatchdogProtocolFailed
        }
        #[cfg(not(unix))]
        RuntimeHostWatchdogError::UnsupportedPlatform => {
            RuntimeHostProcessError::WatchdogConfiguration
        }
    }
}

const fn spawn_error(error: TaskRegistryError) -> RuntimeHostProcessError {
    match error {
        TaskRegistryError::CapacityExhausted => RuntimeHostProcessError::TaskCapacityExhausted,
        TaskRegistryError::IdentifierExhausted => RuntimeHostProcessError::TaskIdentifierExhausted,
    }
}

/// Startup/termination errors for the narrow RuntimeHost executable surface.
#[derive(Debug)]
pub enum RuntimeHostProcessError {
    BuildReactor(io::Error),
    ShutdownSignal(io::Error),
    InvalidConfiguration,
    WatchdogConfiguration,
    WatchdogHandshakeFailed,
    WatchdogIoFailed,
    WatchdogProtocolFailed,
    WatchdogExitedEarly,
    ClockFailed,
    TaskCapacityExhausted,
    TaskIdentifierExhausted,
    OwnedTaskPanicked,
    OwnedComponentTaskFailed,
    OwnedComponentNonZeroCleanup,
    OwnedCoreServiceTaskFailed,
    OwnedCoreServiceNonZeroCleanup,
    OwnedThreadDomainFailed,
    OwnedThreadDomainNonZeroCleanup,
    OwnedTaskExitedEarly,
    OwnedTaskForcedAbort,
    OwnedTaskLeak,
}

impl fmt::Display for RuntimeHostProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuildReactor(error) => {
                write!(formatter, "RuntimeHost reactor build failed: {error}")
            }
            Self::ShutdownSignal(error) => {
                write!(formatter, "RuntimeHost shutdown signal failed: {error}")
            }
            Self::InvalidConfiguration => {
                formatter.write_str("RuntimeHost static configuration is invalid")
            }
            Self::WatchdogConfiguration => {
                formatter.write_str("RuntimeHost explicit watchdog profile is invalid")
            }
            Self::WatchdogHandshakeFailed => formatter
                .write_str("RuntimeHost watchdog control handshake did not complete in time"),
            Self::WatchdogIoFailed => {
                formatter.write_str("RuntimeHost watchdog inherited stream failed")
            }
            Self::WatchdogProtocolFailed => {
                formatter.write_str("RuntimeHost watchdog peer violated the PXHW contract")
            }
            Self::WatchdogExitedEarly => {
                formatter.write_str("RuntimeHost watchdog endpoint exited before root shutdown")
            }
            Self::ClockFailed => formatter.write_str("RuntimeHost clock failed"),
            Self::TaskCapacityExhausted => {
                formatter.write_str("RuntimeHost task capacity exhausted")
            }
            Self::TaskIdentifierExhausted => {
                formatter.write_str("RuntimeHost task identifier exhausted")
            }
            Self::OwnedTaskPanicked => formatter.write_str("an owned RuntimeHost task panicked"),
            Self::OwnedComponentTaskFailed => {
                formatter.write_str("an owned canonical component lifecycle task failed")
            }
            Self::OwnedComponentNonZeroCleanup => formatter
                .write_str("an owned canonical component task returned nonzero cleanup evidence"),
            Self::OwnedCoreServiceTaskFailed => {
                formatter.write_str("the owned fixed CoreService lifecycle task failed")
            }
            Self::OwnedCoreServiceNonZeroCleanup => formatter.write_str(
                "the owned fixed CoreService lifecycle returned nonzero cleanup evidence",
            ),
            Self::OwnedThreadDomainFailed => {
                formatter.write_str("an owned ThreadDomain lifecycle failed")
            }
            Self::OwnedThreadDomainNonZeroCleanup => {
                formatter.write_str("an owned ThreadDomain retained live or unjoined OS workers")
            }
            Self::OwnedTaskExitedEarly => {
                formatter.write_str("an owned RuntimeHost task exited before external shutdown")
            }
            Self::OwnedTaskForcedAbort => {
                formatter.write_str("an owned RuntimeHost task required forced abort")
            }
            Self::OwnedTaskLeak => {
                formatter.write_str("RuntimeHost shutdown retained an owned task")
            }
        }
    }
}

impl std::error::Error for RuntimeHostProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BuildReactor(error) | Self::ShutdownSignal(error) => Some(error),
            Self::InvalidConfiguration
            | Self::WatchdogConfiguration
            | Self::WatchdogHandshakeFailed
            | Self::WatchdogIoFailed
            | Self::WatchdogProtocolFailed
            | Self::WatchdogExitedEarly
            | Self::ClockFailed
            | Self::TaskCapacityExhausted
            | Self::TaskIdentifierExhausted
            | Self::OwnedTaskPanicked
            | Self::OwnedComponentTaskFailed
            | Self::OwnedComponentNonZeroCleanup
            | Self::OwnedCoreServiceTaskFailed
            | Self::OwnedCoreServiceNonZeroCleanup
            | Self::OwnedThreadDomainFailed
            | Self::OwnedThreadDomainNonZeroCleanup
            | Self::OwnedTaskExitedEarly
            | Self::OwnedTaskForcedAbort
            | Self::OwnedTaskLeak => None,
        }
    }
}

fn thread_cleanup_error(error: ThreadRegistryError) -> RuntimeHostProcessError {
    match error {
        ThreadRegistryError::DrainIncomplete => {
            RuntimeHostProcessError::OwnedThreadDomainNonZeroCleanup
        }
        ThreadRegistryError::Budget(_)
        | ThreadRegistryError::Observation(_)
        | ThreadRegistryError::DomainBuild(_)
        | ThreadRegistryError::Domain(_)
        | ThreadRegistryError::InvalidDomainConfiguration
        | ThreadRegistryError::ExecutorPlanMismatch
        | ThreadRegistryError::NativeOwnerUnavailable
        | ThreadRegistryError::DomainCapacityExhausted
        | ThreadRegistryError::DomainAlreadyOwned
        | ThreadRegistryError::DomainNotOwned
        | ThreadRegistryError::HandleOwnerMismatch
        | ThreadRegistryError::HandleTypeMismatch
        | ThreadRegistryError::ObservedCounterOverflow
        | ThreadRegistryError::OwnerCleanupFailed
        | ThreadRegistryError::StateInconsistent => {
            RuntimeHostProcessError::OwnedThreadDomainFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::time::Duration;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    use ed25519_dalek::SigningKey;
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::{PrincipalRef, RuntimeHostId};
    use paraegox_kernel::time::{
        BoundedDuration, ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant,
    };
    use paraegox_runtime_contracts::apply::{
        PlanWriterRef, TenureAuthorityRef, TenureKeyRef, TenureProofAlgorithm,
    };
    use paraegox_runtime_contracts::assignment::BindingAssignment;
    use paraegox_runtime_contracts::execution::{
        CardDefinitionRef, CardImplementationRef, MailboxExecutionSpec, RuntimePlanSliceV2,
    };
    use paraegox_runtime_contracts::provenance::SourceScopeRef;
    use paraegox_runtime_contracts::thread_execution::{
        ExecutorBudgetSpec, ThreadDomainRef, ThreadDomainSpec,
    };
    use paraegox_runtime_contracts::wire::{ApplyAuthAlgorithm, ApplyAuthKeyRef};

    use super::{
        ComponentLifecycleFactory, ComponentOperation, ComponentTaskContext,
        CoreServiceLifecycleFactory, OwnedComponentLifecycle, run_reactor_until,
        run_reactor_until_with_bootstrap, run_reactor_until_with_owned_lifecycles,
        run_reactor_until_with_setup,
    };
    use crate::admission::{
        AdmissionState, AdmissionStateLimits, ApplyAdmission, ApplyAdmissionPolicy,
        ED25519_ALGORITHM, ED25519_ALGORITHM_VERSION, TrustedApplyIdentity, TrustedApplyKey,
        TrustedTenureIdentity, TrustedTenureKey,
    };
    use crate::card_executor::{
        CardStartOutcome, CooperativeLoopImplementation, TrustedCardImplementation,
    };
    use crate::card_instance::{
        CallbackFailure, CardContext, CardFuture, CardImplementation, DomainEpoch, InputView,
        InstanceGeneration, OutputProposal, RuntimeHostEpoch,
    };
    use crate::component_runtime::{
        ComponentRuntimeEpochs, ComponentRuntimeError, SingleSubjectComponentRuntime,
    };
    use crate::core_service::{
        CoreService, CoreServiceFailure, CoreServiceFuture, CoreServiceIdentity,
        CoreServiceLifecycleBudgets, CoreServiceLifecycleOwner, CoreServiceReadiness,
        ServiceContext,
    };
    use crate::mailbox::{EnqueueOutcome, MessageId, PayloadHandle, ValidatedMessage};
    use crate::task_registry::RuntimeTaskKind;
    use crate::thread_domain::{ThreadCompletion, ThreadDomainLifecycle};
    use crate::thread_registry::RuntimeThreadRegistry;

    const PYTHON_EXECUTION_REQUEST_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/wire/s4_runtime_apply_request_v2.json");

    #[derive(Clone)]
    struct LifecycleCounters {
        starts: Arc<AtomicUsize>,
        inputs: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
        threads: Arc<Mutex<Vec<thread::ThreadId>>>,
    }

    impl LifecycleCounters {
        fn new() -> Self {
            Self {
                starts: Arc::new(AtomicUsize::new(0)),
                inputs: Arc::new(AtomicUsize::new(0)),
                stops: Arc::new(AtomicUsize::new(0)),
                threads: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn record_thread(&self) {
            let Ok(mut threads) = self.threads.lock() else {
                panic!("lifecycle thread census must remain usable");
            };
            threads.push(thread::current().id());
        }
    }

    struct LifecycleCard {
        counters: LifecycleCounters,
    }

    impl CardImplementation for LifecycleCard {
        fn on_start<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            self.counters.record_thread();
            self.counters.starts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }

        fn on_input<'a>(
            &'a mut self,
            _context: &'a CardContext,
            _input: InputView<'a>,
        ) -> CardFuture<'a, Result<Option<OutputProposal>, CallbackFailure>> {
            self.counters.record_thread();
            self.counters.inputs.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(None) })
        }

        fn on_stop<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            self.counters.record_thread();
            self.counters.stops.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    impl CooperativeLoopImplementation for LifecycleCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = CardDefinitionRef::from_bytes([0xa1; 16]);
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef =
            CardImplementationRef::from_bytes([0xa2; 16]);
        const BOUND_DEFINITION_DIGEST: Digest32 = Digest32::from_bytes([0xa3; 32]);
        const BOUND_ARTIFACT_DIGEST: Digest32 = Digest32::from_bytes([0xa4; 32]);
    }

    struct FailingStopCard {
        stops: Arc<AtomicUsize>,
    }

    struct HostCoreService {
        identity: CoreServiceIdentity,
        readiness: CoreServiceReadiness,
        stop_fails: bool,
        readiness_checks: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for HostCoreService {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl CoreService for HostCoreService {
        fn prepare<'a>(
            &'a mut self,
            context: &'a ServiceContext,
        ) -> CoreServiceFuture<'a, Result<(), CoreServiceFailure>> {
            let valid = context.identity() == self.identity
                && context.clock_reading().is_ok()
                && !context.cancellation().is_cancelled();
            Box::pin(async move {
                if valid {
                    Ok(())
                } else {
                    Err(CoreServiceFailure::Failed)
                }
            })
        }

        fn start(&mut self) -> CoreServiceFuture<'_, Result<(), CoreServiceFailure>> {
            Box::pin(async { Ok(()) })
        }

        fn readiness(
            &mut self,
        ) -> CoreServiceFuture<'_, Result<CoreServiceReadiness, CoreServiceFailure>> {
            self.readiness_checks.fetch_add(1, Ordering::SeqCst);
            let readiness = self.readiness;
            Box::pin(async move { Ok(readiness) })
        }

        fn drain(
            &mut self,
            _deadline: paraegox_kernel::time::MonotonicDeadline,
        ) -> CoreServiceFuture<'_, Result<(), CoreServiceFailure>> {
            Box::pin(async { Ok(()) })
        }

        fn stop(&mut self) -> CoreServiceFuture<'_, Result<(), CoreServiceFailure>> {
            let fails = self.stop_fails;
            Box::pin(async move {
                if fails {
                    Err(CoreServiceFailure::Failed)
                } else {
                    Ok(())
                }
            })
        }
    }

    impl CardImplementation for FailingStopCard {
        fn on_start<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            Box::pin(async { Ok(()) })
        }

        fn on_input<'a>(
            &'a mut self,
            _context: &'a CardContext,
            _input: InputView<'a>,
        ) -> CardFuture<'a, Result<Option<OutputProposal>, CallbackFailure>> {
            Box::pin(async { Ok(None) })
        }

        fn on_stop<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(CallbackFailure::Failed) })
        }
    }

    impl CooperativeLoopImplementation for FailingStopCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = CardDefinitionRef::from_bytes([0xa1; 16]);
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef =
            CardImplementationRef::from_bytes([0xa2; 16]);
        const BOUND_DEFINITION_DIGEST: Digest32 = Digest32::from_bytes([0xa3; 32]);
        const BOUND_ARTIFACT_DIGEST: Digest32 = Digest32::from_bytes([0xa4; 32]);
    }

    struct TaskExitWitness(Arc<AtomicBool>);

    impl Drop for TaskExitWitness {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn core_service_factory(
        readiness_checks: &Arc<AtomicUsize>,
        drops: &Arc<AtomicUsize>,
        consumer_readiness: CoreServiceReadiness,
        consumer_stop_fails: bool,
    ) -> CoreServiceLifecycleFactory {
        let task_readiness_checks = Arc::clone(readiness_checks);
        let task_drops = Arc::clone(drops);
        Box::new(move |context| {
            let budgets = CoreServiceLifecycleBudgets::try_new(
                BoundedDuration::from_nanos(1_000_000_000),
                BoundedDuration::from_nanos(1_000_000_000),
                BoundedDuration::from_nanos(1_000_000_000),
                BoundedDuration::from_nanos(1_000_000_000),
                BoundedDuration::from_nanos(1_000_000_000),
            )?;
            let provider_identity = CoreServiceIdentity::from_bytes([0x41; 16]);
            let consumer_identity = CoreServiceIdentity::from_bytes([0x42; 16]);
            CoreServiceLifecycleOwner::try_new(
                provider_identity,
                Box::new(HostCoreService {
                    identity: provider_identity,
                    readiness: CoreServiceReadiness::Ready,
                    stop_fails: false,
                    readiness_checks: Arc::clone(&task_readiness_checks),
                    drops: Arc::clone(&task_drops),
                }),
                consumer_identity,
                Box::new(HostCoreService {
                    identity: consumer_identity,
                    readiness: consumer_readiness,
                    stop_fails: consumer_stop_fails,
                    readiness_checks: task_readiness_checks,
                    drops: task_drops,
                }),
                context.clock,
                budgets,
                &context.cancellation,
            )
        })
    }

    fn admitted_lifecycle_slice() -> (RuntimePlanSliceV2, BindingAssignment, MailboxExecutionSpec) {
        let wire = fixture_hex_bytes("outer_wire_hex");
        let (admission, reading) = signed_fixture_admission();
        let transition = admission
            .admit_execution_request(&wire, &AdmissionState::for_new_boundary(), reading)
            .unwrap_or_else(|error| panic!("signed S4 fixture must admit: {error}"));
        let slice = transition.slice().clone();
        let execution = slice.assignments().execution().mailbox_executions()[0];
        let active = slice
            .assignments()
            .bindings()
            .as_slice()
            .iter()
            .copied()
            .find(|binding| binding.binding_id() == execution.binding_id())
            .unwrap_or_else(|| panic!("admitted execution binding must exist"));
        (slice, active, execution)
    }

    fn component_from_fixture<Implementation, Build>(
        context: &ComponentTaskContext,
        slice: &RuntimePlanSliceV2,
        execution: MailboxExecutionSpec,
        build: Build,
    ) -> Result<SingleSubjectComponentRuntime, ComponentRuntimeError>
    where
        Implementation: CooperativeLoopImplementation + 'static,
        Build: FnOnce() -> Implementation,
    {
        let selected = TrustedCardImplementation::try_resolve_loop(&[execution], build)?;
        let runtime_host = RuntimeHostEpoch::try_new(1)
            .unwrap_or_else(|error| panic!("host epoch must be valid: {error}"));
        let domain = DomainEpoch::try_new(1)
            .unwrap_or_else(|error| panic!("domain epoch must be valid: {error}"));
        let instance = InstanceGeneration::try_new(1)
            .unwrap_or_else(|error| panic!("instance generation must be valid: {error}"));
        SingleSubjectComponentRuntime::try_new(
            slice,
            selected,
            ComponentRuntimeEpochs::new(runtime_host, domain, instance),
            context.clock,
            &context.cancellation,
        )
    }

    fn offer_fixture_message(
        component: &mut SingleSubjectComponentRuntime,
        context: &ComponentTaskContext,
        binding: BindingAssignment,
        identity: u8,
    ) -> Result<(), ComponentRuntimeError> {
        let ingress = component
            .active_ingress(binding.binding_id())
            .ok_or(ComponentRuntimeError::InvalidLifecycle)?;
        let deadline = context
            .clock
            .deadline_after(BoundedDuration::from_nanos(4_000_000_000))?;
        let payload = PayloadHandle::try_from_vec(vec![identity])
            .unwrap_or_else(|error| panic!("task payload must be valid: {error}"));
        let message = ValidatedMessage::new(
            MessageId::from_bytes([identity; 16]),
            binding.target_spec().schema(),
            binding.target_spec().interaction(),
            None,
            deadline,
            payload,
        );
        let offer = component
            .try_offer(&ingress, message)
            .map_err(|failure| failure.error())?;
        if matches!(offer.outcome(), EnqueueOutcome::Admitted) {
            Ok(())
        } else {
            Err(ComponentRuntimeError::InvalidLifecycle)
        }
    }

    fn signed_fixture_admission() -> (ApplyAdmission, ClockReading) {
        let scope = SourceScopeRef::from_bytes([0x01; 16]);
        let target = RuntimeHostId::from_bytes([0x05; 16]);
        let writer = PlanWriterRef::from_bytes([0x09; 16]);
        let principal = PrincipalRef::from_bytes([0x09; 16]);
        let tenure_algorithm = TenureProofAlgorithm::try_new(ED25519_ALGORITHM)
            .unwrap_or_else(|error| panic!("fixture tenure algorithm must build: {error}"));
        let apply_algorithm = ApplyAuthAlgorithm::try_new(ED25519_ALGORITHM)
            .unwrap_or_else(|error| panic!("fixture apply algorithm must build: {error}"));
        let tenure_key = SigningKey::from_bytes(&[0x11; 32])
            .verifying_key()
            .to_bytes();
        let tenure = TrustedTenureKey::try_new(
            TrustedTenureIdentity::new(
                scope,
                PrincipalRef::from_bytes([0x06; 16]),
                1_001,
                1_002,
                TenureAuthorityRef::from_bytes([0x07; 16]),
            ),
            TenureKeyRef::from_bytes([0x08; 16]),
            tenure_algorithm,
            ED25519_ALGORITHM_VERSION,
            tenure_key,
        )
        .unwrap_or_else(|error| panic!("fixture tenure trust must build: {error}"));
        let apply_key = SigningKey::from_bytes(&[0x22; 32])
            .verifying_key()
            .to_bytes();
        let apply = TrustedApplyKey::try_new(
            TrustedApplyIdentity::new(scope, target, principal, writer),
            ApplyAuthKeyRef::from_bytes([0x0c; 16]),
            apply_algorithm,
            ED25519_ALGORITHM_VERSION,
            apply_key,
        )
        .unwrap_or_else(|error| panic!("fixture apply trust must build: {error}"));
        let limits = AdmissionStateLimits::try_new(4, 4, 4)
            .unwrap_or_else(|error| panic!("fixture state limits must build: {error}"));
        let policy = ApplyAdmissionPolicy::try_new(
            BoundedDuration::from_nanos(100),
            limits,
            [tenure],
            [apply],
        )
        .unwrap_or_else(|error| panic!("fixture admission policy must build: {error}"));
        let generation = ClockGeneration::try_new(3)
            .unwrap_or_else(|error| panic!("fixture clock generation must build: {error}"));
        let reading = ClockReading::new(
            ClockDomainRef::from_bytes([0x0b; 16]),
            generation,
            MonotonicInstant::from_ticks(0),
        );
        (ApplyAdmission::new(policy), reading)
    }

    fn fixture_hex_bytes(field: &str) -> Vec<u8> {
        let marker = format!("\"{field}\": \"");
        let Some((_, tail)) = PYTHON_EXECUTION_REQUEST_FIXTURE_JSON.split_once(&marker) else {
            panic!("fixture field must exist: {field}");
        };
        let Some((hex, _)) = tail.split_once('"') else {
            panic!("fixture hex must terminate: {field}");
        };
        assert_eq!(hex.len() % 2, 0, "fixture hex must contain full bytes");
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    const fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("fixture must contain hexadecimal digits"),
        }
    }

    #[test]
    fn controlled_reactor_runs_on_the_calling_thread_and_exits_at_root() {
        let expected = thread::current().id();
        let observed = Arc::new(Mutex::new(None));
        let task_observed = Arc::clone(&observed);

        assert!(
            run_reactor_until(async move {
                let Ok(mut slot) = task_observed.lock() else {
                    panic!("thread observation lock must remain usable");
                };
                *slot = Some(thread::current().id());
                Ok(())
            })
            .is_ok()
        );

        let Ok(slot) = observed.lock() else {
            panic!("thread observation lock must remain usable");
        };
        assert_eq!(*slot, Some(expected));
    }

    #[test]
    fn controlled_reactor_owns_an_enabled_timer_driver() {
        assert!(
            run_reactor_until(async {
                tokio::time::sleep(Duration::ZERO).await;
                Ok(())
            })
            .is_ok()
        );
    }

    #[test]
    fn fixed_core_services_are_ready_then_joined_with_exact_zero_cleanup() {
        let readiness_checks = Arc::new(AtomicUsize::new(0));
        let wait_checks = Arc::clone(&readiness_checks);
        let drops = Arc::new(AtomicUsize::new(0));
        let services = core_service_factory(
            &readiness_checks,
            &drops,
            CoreServiceReadiness::Ready,
            false,
        );

        let result = run_reactor_until_with_owned_lifecycles(
            async move {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while wait_checks.load(Ordering::SeqCst) != 2 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(std::io::Error::other)
            },
            None,
            Some(services),
            |_| Ok(()),
        );

        assert!(
            result.is_ok(),
            "fixed lifecycle must join at zero: {result:?}"
        );
        assert_eq!(readiness_checks.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn pending_shutdown_does_not_mask_core_service_readiness_failure() {
        let readiness_checks = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let sibling_cleaned = Arc::new(AtomicBool::new(false));
        let task_sibling_cleaned = Arc::clone(&sibling_cleaned);
        let services = core_service_factory(
            &readiness_checks,
            &drops,
            CoreServiceReadiness::NotReady,
            false,
        );

        let result = run_reactor_until_with_owned_lifecycles(
            core::future::pending::<std::io::Result<()>>(),
            None,
            Some(services),
            |scope| {
                let cancellation = scope.cancellation().view();
                scope.spawn(RuntimeTaskKind::HostControl, move || async move {
                    cancellation.cancelled().await;
                    task_sibling_cleaned.store(true, Ordering::SeqCst);
                })
            },
        );

        assert!(matches!(
            result,
            Err(super::RuntimeHostProcessError::OwnedCoreServiceTaskFailed)
        ));
        assert_eq!(readiness_checks.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert!(sibling_cleaned.load(Ordering::SeqCst));
    }

    #[test]
    fn pending_shutdown_contains_core_service_constructor_panic_and_cleans_siblings() {
        let sibling_cleaned = Arc::new(AtomicBool::new(false));
        let task_sibling_cleaned = Arc::clone(&sibling_cleaned);
        let services: CoreServiceLifecycleFactory = Box::new(|_context| {
            panic!("test CoreService owner constructor panic");
        });

        let result = run_reactor_until_with_owned_lifecycles(
            core::future::pending::<std::io::Result<()>>(),
            None,
            Some(services),
            |scope| {
                let cancellation = scope.cancellation().view();
                scope.spawn(RuntimeTaskKind::HostControl, move || async move {
                    cancellation.cancelled().await;
                    task_sibling_cleaned.store(true, Ordering::SeqCst);
                })
            },
        );

        assert!(matches!(
            result,
            Err(super::RuntimeHostProcessError::OwnedTaskPanicked)
        ));
        assert!(sibling_cleaned.load(Ordering::SeqCst));
    }

    #[test]
    fn fixed_core_service_nonzero_cleanup_is_joined_and_rejected_by_host() {
        let readiness_checks = Arc::new(AtomicUsize::new(0));
        let wait_checks = Arc::clone(&readiness_checks);
        let drops = Arc::new(AtomicUsize::new(0));
        let services =
            core_service_factory(&readiness_checks, &drops, CoreServiceReadiness::Ready, true);

        let result = run_reactor_until_with_owned_lifecycles(
            async move {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while wait_checks.load(Ordering::SeqCst) != 2 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(std::io::Error::other)
            },
            None,
            Some(services),
            |_| Ok(()),
        );

        assert!(matches!(
            result,
            Err(super::RuntimeHostProcessError::OwnedCoreServiceNonZeroCleanup)
        ));
        assert_eq!(readiness_checks.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn canonical_component_lifecycle_is_structurally_joined_with_exact_zero() {
        let expected_thread = thread::current().id();
        let (slice, binding, execution) = admitted_lifecycle_slice();
        let counters = LifecycleCounters::new();
        let card_counters = counters.clone();
        let callback_reached = Arc::new(AtomicBool::new(false));
        let task_callback_reached = Arc::clone(&callback_reached);

        let component: ComponentLifecycleFactory = Box::new(move |context| {
            let component =
                component_from_fixture(&context, &slice, execution, || LifecycleCard {
                    counters: card_counters,
                })?;
            let operation: ComponentOperation = Box::new(move |component, context| {
                Box::pin(async move {
                    if component.start().await? != CardStartOutcome::Started {
                        return Err(ComponentRuntimeError::InvalidLifecycle);
                    }
                    let ingress = component
                        .active_ingress(binding.binding_id())
                        .ok_or(ComponentRuntimeError::InvalidLifecycle)?;
                    let deadline = context
                        .clock
                        .deadline_after(BoundedDuration::from_nanos(4_000_000_000))?;
                    let first_payload = PayloadHandle::try_from_vec(vec![1])
                        .unwrap_or_else(|error| panic!("task payload must be valid: {error}"));
                    let first_message = ValidatedMessage::new(
                        MessageId::from_bytes([1; 16]),
                        binding.target_spec().schema(),
                        binding.target_spec().interaction(),
                        None,
                        deadline,
                        first_payload,
                    );
                    let first_offer = component
                        .try_offer(&ingress, first_message)
                        .map_err(|failure| failure.error())?;
                    if !matches!(first_offer.outcome(), EnqueueOutcome::Admitted) {
                        return Err(ComponentRuntimeError::InvalidLifecycle);
                    }
                    let first_batch = component.dispatch_ready_until_idle().await?;
                    if first_batch.invoked() != 1
                        || first_batch.pre_run_terminals() != 0
                        || first_batch.idle()
                            != crate::dispatcher::DispatchIdleReason::NoReadyMailbox
                    {
                        return Err(ComponentRuntimeError::InvalidLifecycle);
                    }
                    let second_payload = PayloadHandle::try_from_vec(vec![2])
                        .unwrap_or_else(|error| panic!("task payload must be valid: {error}"));
                    let second_message = ValidatedMessage::new(
                        MessageId::from_bytes([2; 16]),
                        binding.target_spec().schema(),
                        binding.target_spec().interaction(),
                        None,
                        deadline,
                        second_payload,
                    );
                    let second_offer = component
                        .try_offer(&ingress, second_message)
                        .map_err(|failure| failure.error())?;
                    if !matches!(second_offer.outcome(), EnqueueOutcome::Admitted) {
                        return Err(ComponentRuntimeError::InvalidLifecycle);
                    }
                    let second_batch = component.dispatch_ready_until_idle().await?;
                    if second_batch.invoked() != 1
                        || second_batch.pre_run_terminals() != 0
                        || second_batch.idle()
                            != crate::dispatcher::DispatchIdleReason::NoReadyMailbox
                    {
                        return Err(ComponentRuntimeError::InvalidLifecycle);
                    }
                    task_callback_reached.store(true, Ordering::SeqCst);

                    let cancellation = context.cancellation.view();
                    cancellation.cancelled().await;
                    Ok(())
                })
            });
            Ok(OwnedComponentLifecycle::new(component, context, operation))
        });
        let shutdown_ready = Arc::clone(&callback_reached);
        let result = run_reactor_until_with_bootstrap(
            async move {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !shutdown_ready.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(std::io::Error::other)
            },
            Some(component),
            |_| Ok(()),
        );

        assert!(
            result.is_ok(),
            "component task must join cleanly: {result:?}"
        );
        assert!(callback_reached.load(Ordering::SeqCst));
        assert_eq!(counters.starts.load(Ordering::SeqCst), 1);
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 2);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
        let threads = counters
            .threads
            .lock()
            .unwrap_or_else(|_| panic!("lifecycle thread census must remain usable"));
        assert_eq!(threads.as_slice(), [expected_thread; 4]);
    }

    #[test]
    fn pending_shutdown_does_not_mask_component_lifecycle_panic() {
        let (slice, binding, execution) = admitted_lifecycle_slice();
        let counters = LifecycleCounters::new();
        let card_counters = counters.clone();
        let task_exited = Arc::new(AtomicBool::new(false));
        let task_exit_evidence = Arc::clone(&task_exited);
        let sibling_cleaned = Arc::new(AtomicBool::new(false));
        let task_sibling_cleaned = Arc::clone(&sibling_cleaned);
        let component: ComponentLifecycleFactory = Box::new(move |context| {
            let component =
                component_from_fixture(&context, &slice, execution, || LifecycleCard {
                    counters: card_counters,
                })?;
            let operation: ComponentOperation = Box::new(move |component, context| {
                Box::pin(async move {
                    if component.start().await? != CardStartOutcome::Started {
                        return Err(ComponentRuntimeError::InvalidLifecycle);
                    }
                    offer_fixture_message(component, &context, binding, 3)?;
                    let _exit_witness = TaskExitWitness(task_exit_evidence);
                    panic!("test component lifecycle panic");
                })
            });
            Ok(OwnedComponentLifecycle::new(component, context, operation))
        });

        let result = run_reactor_until_with_bootstrap(
            core::future::pending::<std::io::Result<()>>(),
            Some(component),
            |scope| {
                let cancellation = scope.cancellation().view();
                scope.spawn(RuntimeTaskKind::HostControl, move || async move {
                    cancellation.cancelled().await;
                    task_sibling_cleaned.store(true, Ordering::SeqCst);
                })
            },
        );

        assert!(matches!(
            result,
            Err(super::RuntimeHostProcessError::OwnedTaskPanicked)
        ));
        assert!(task_exited.load(Ordering::SeqCst));
        assert!(sibling_cleaned.load(Ordering::SeqCst));
        assert_eq!(counters.starts.load(Ordering::SeqCst), 1);
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 0);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pending_shutdown_does_not_mask_component_lifecycle_failure() {
        let (slice, binding, execution) = admitted_lifecycle_slice();
        let counters = LifecycleCounters::new();
        let card_counters = counters.clone();
        let task_exited = Arc::new(AtomicBool::new(false));
        let task_exit_evidence = Arc::clone(&task_exited);
        let sibling_cleaned = Arc::new(AtomicBool::new(false));
        let task_sibling_cleaned = Arc::clone(&sibling_cleaned);
        let component: ComponentLifecycleFactory = Box::new(move |context| {
            let component =
                component_from_fixture(&context, &slice, execution, || LifecycleCard {
                    counters: card_counters,
                })?;
            let operation: ComponentOperation = Box::new(move |component, context| {
                Box::pin(async move {
                    if component.start().await? != CardStartOutcome::Started {
                        return Err(ComponentRuntimeError::InvalidLifecycle);
                    }
                    offer_fixture_message(component, &context, binding, 4)?;
                    let _exit_witness = TaskExitWitness(task_exit_evidence);
                    Err(ComponentRuntimeError::InvalidLifecycle)
                })
            });
            Ok(OwnedComponentLifecycle::new(component, context, operation))
        });

        let result = run_reactor_until_with_bootstrap(
            core::future::pending::<std::io::Result<()>>(),
            Some(component),
            |scope| {
                let cancellation = scope.cancellation().view();
                scope.spawn(RuntimeTaskKind::HostControl, move || async move {
                    cancellation.cancelled().await;
                    task_sibling_cleaned.store(true, Ordering::SeqCst);
                })
            },
        );

        assert!(matches!(
            result,
            Err(super::RuntimeHostProcessError::OwnedComponentTaskFailed)
        ));
        assert!(task_exited.load(Ordering::SeqCst));
        assert!(sibling_cleaned.load(Ordering::SeqCst));
        assert_eq!(counters.starts.load(Ordering::SeqCst), 1);
        assert_eq!(counters.inputs.load(Ordering::SeqCst), 0);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn component_stop_failure_is_nonzero_cleanup_and_leaves_no_task_leak() {
        let (slice, _, execution) = admitted_lifecycle_slice();
        let started = Arc::new(AtomicBool::new(false));
        let task_started = Arc::clone(&started);
        let stops = Arc::new(AtomicUsize::new(0));
        let card_stops = Arc::clone(&stops);
        let task_exited = Arc::new(AtomicBool::new(false));
        let task_exit_evidence = Arc::clone(&task_exited);
        let component: ComponentLifecycleFactory = Box::new(move |context| {
            let component = component_from_fixture(&context, &slice, execution, || {
                FailingStopCard { stops: card_stops }
            })?;
            let operation: ComponentOperation = Box::new(move |component, context| {
                Box::pin(async move {
                    let _exit_witness = TaskExitWitness(task_exit_evidence);
                    if component.start().await? != CardStartOutcome::Started {
                        return Err(ComponentRuntimeError::InvalidLifecycle);
                    }
                    task_started.store(true, Ordering::SeqCst);
                    context.cancellation.view().cancelled().await;
                    Ok(())
                })
            });
            Ok(OwnedComponentLifecycle::new(component, context, operation))
        });
        let shutdown_ready = Arc::clone(&started);
        let result = run_reactor_until_with_bootstrap(
            async move {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !shutdown_ready.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(std::io::Error::other)
            },
            Some(component),
            |_| Ok(()),
        );

        assert!(matches!(
            result,
            Err(super::RuntimeHostProcessError::OwnedComponentNonZeroCleanup)
        ));
        assert!(started.load(Ordering::SeqCst));
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(task_exited.load(Ordering::SeqCst));
    }

    #[test]
    fn pending_shutdown_rejects_normal_owned_task_early_exit_and_cleans_siblings() {
        let exited = Arc::new(AtomicBool::new(false));
        let task_exited = Arc::clone(&exited);
        let sibling_cleaned = Arc::new(AtomicBool::new(false));
        let task_sibling_cleaned = Arc::clone(&sibling_cleaned);

        let result = run_reactor_until_with_setup(
            core::future::pending::<std::io::Result<()>>(),
            move |scope| {
                scope.spawn(RuntimeTaskKind::HostControl, move || async move {
                    task_exited.store(true, Ordering::SeqCst);
                })?;
                let cancellation = scope.cancellation().view();
                scope.spawn(RuntimeTaskKind::HostControl, move || async move {
                    cancellation.cancelled().await;
                    task_sibling_cleaned.store(true, Ordering::SeqCst);
                })
            },
        );

        assert!(matches!(
            result,
            Err(super::RuntimeHostProcessError::OwnedTaskExitedEarly)
        ));
        assert!(exited.load(Ordering::SeqCst));
        assert!(sibling_cleaned.load(Ordering::SeqCst));
    }

    #[test]
    fn ready_external_shutdown_wins_over_a_simultaneous_normal_completion() {
        let result = run_reactor_until_with_setup(async { Ok(()) }, |scope| {
            scope.spawn(RuntimeTaskKind::HostControl, || async move {})
        });

        assert!(result.is_ok(), "external shutdown must win: {result:?}");
    }

    #[test]
    fn root_scope_cancels_and_joins_every_owned_task_before_exit() {
        assert!(
            run_reactor_until_with_setup(async { Ok(()) }, |scope| {
                let cancellation = scope.cancellation().view();
                scope.spawn(RuntimeTaskKind::HostControl, move || async move {
                    cancellation.cancelled().await;
                })
            },)
            .is_ok()
        );
    }

    #[test]
    fn root_scope_directly_owns_and_joins_the_planned_thread_inventory() {
        let caller = thread::current().id();
        let observed_worker = Arc::new(Mutex::new(None));
        let worker_fact = Arc::clone(&observed_worker);

        let result = run_reactor_until_with_setup(async { Ok(()) }, move |scope| {
            let budget = ExecutorBudgetSpec::try_new(2, 1)
                .unwrap_or_else(|error| panic!("fixture executor budget failed: {error}"));
            scope.thread_domains = Some(
                RuntimeThreadRegistry::try_new(budget)
                    .unwrap_or_else(|error| panic!("fixture registry failed: {error}")),
            );
            let registry = scope
                .thread_domains
                .as_mut()
                .unwrap_or_else(|| panic!("thread registry must remain root-owned"));
            let domain_spec = ThreadDomainSpec::try_new(
                ThreadDomainRef::from_bytes([0xf1; 16]),
                1,
                BoundedDuration::from_nanos(1_000_000_000),
                BoundedDuration::from_nanos(1_000_000_000),
                BoundedDuration::from_nanos(1_000_000_000),
            )
            .unwrap_or_else(|error| panic!("fixture ThreadDomain plan failed: {error}"));
            let domain_epoch = DomainEpoch::try_new(91)
                .unwrap_or_else(|error| panic!("fixture domain epoch failed: {error}"));
            let handle = registry
                .try_create::<u8>(domain_epoch, domain_spec, 0)
                .unwrap_or_else(|error| panic!("root ThreadDomain build failed: {error}"));
            let mut invocation = registry
                .with_domain_mut(&handle, |domain| {
                    domain.try_submit(|| {
                        move |_| {
                            *worker_fact
                                .lock()
                                .unwrap_or_else(|error| error.into_inner()) =
                                Some(thread::current().id());
                            73
                        }
                    })
                })
                .unwrap_or_else(|error| panic!("root domain visit failed: {error}"))
                .unwrap_or_else(|error| panic!("root domain submission failed: {error}"));
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                let completion = registry
                    .with_domain_mut(&handle, |domain| {
                        domain.try_take_completion(&mut invocation)
                    })
                    .unwrap_or_else(|error| panic!("root domain visit failed: {error}"))
                    .unwrap_or_else(|error| panic!("root completion failed: {error}"));
                match completion {
                    ThreadCompletion::Pending(_) => {}
                    ThreadCompletion::Returned(73) => break,
                    ThreadCompletion::Returned(value) => {
                        panic!("unexpected ThreadDomain value: {value}")
                    }
                    ThreadCompletion::Panicked | ThreadCompletion::LateRejected(_) => {
                        panic!("root-owned invocation did not complete normally")
                    }
                }
                assert!(Instant::now() < deadline, "root invocation timed out");
                thread::yield_now();
            }
            let snapshot = registry
                .with_domain_mut(&handle, |domain| domain.snapshot())
                .unwrap_or_else(|error| panic!("root domain census failed: {error}"));
            assert_eq!(snapshot.lifecycle(), ThreadDomainLifecycle::Accepting);
            assert_eq!(snapshot.live_workers(), 1);
            Ok(())
        });

        assert!(
            result.is_ok(),
            "root ThreadDomain cleanup failed: {result:?}"
        );
        let worker = observed_worker
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .unwrap_or_else(|| panic!("worker thread fact must be recorded"));
        assert_ne!(worker, caller);
    }

    #[test]
    fn owned_task_panic_is_a_process_error_not_a_detached_task() {
        let result = run_reactor_until_with_setup(async { Ok(()) }, |scope| {
            scope.spawn(RuntimeTaskKind::HostControl, || async move {
                panic!("test owned task panic");
            })
        });
        assert!(matches!(
            result,
            Err(super::RuntimeHostProcessError::OwnedTaskPanicked)
        ));
    }

    #[test]
    fn setup_failure_still_cancels_and_joins_tasks_it_already_spawned() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let task_cleaned = Arc::clone(&cleaned);
        let result = run_reactor_until_with_setup(async { Ok(()) }, |scope| {
            let cancellation = scope.cancellation().view();
            scope.spawn(RuntimeTaskKind::HostControl, move || async move {
                cancellation.cancelled().await;
                task_cleaned.store(true, Ordering::SeqCst);
            })?;
            Err(super::RuntimeHostProcessError::InvalidConfiguration)
        });
        assert!(matches!(
            result,
            Err(super::RuntimeHostProcessError::InvalidConfiguration)
        ));
        assert!(cleaned.load(Ordering::SeqCst));
    }
}
