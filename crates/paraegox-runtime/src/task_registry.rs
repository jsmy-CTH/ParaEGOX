//! Bounded structured ownership for every task spawned by one RuntimeHost.

use core::fmt;
use core::future::Future;
use core::num::NonZeroUsize;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::sync::Arc;

use tokio::sync::Notify;
use tokio::task::{Id as TokioTaskId, JoinError, JoinSet};
use tokio::time::{Instant, timeout_at};

/// Runtime-owned identifier that never exposes Tokio task identity publicly.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RuntimeTaskId(u64);

impl RuntimeTaskId {
    #[must_use]
    pub(crate) const fn value(self) -> u64 {
        self.0
    }
}

/// Bounded classification used by Runtime inspection and cleanup evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeTaskKind {
    HostControl,
    ComponentLifecycle,
    CoreServiceLifecycle,
}

#[derive(Debug)]
struct CancellationCell {
    cancelled: AtomicBool,
    notify: Arc<Notify>,
}

impl CancellationCell {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: Arc::new(Notify::new()),
        }
    }

    fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }
}

/// Runtime-owned cancellation source. Children inherit parent cancellation.
#[derive(Clone, Debug)]
pub(crate) struct CancellationSource {
    local: Arc<CancellationCell>,
    lineage: Arc<[Arc<CancellationCell>]>,
}

impl CancellationSource {
    #[must_use]
    pub(crate) fn root() -> Self {
        let local = Arc::new(CancellationCell::new());
        Self {
            local: Arc::clone(&local),
            lineage: Arc::from([local]),
        }
    }

    #[must_use]
    pub(crate) fn child(&self) -> Self {
        let local = Arc::new(CancellationCell::new());
        let mut lineage = self.lineage.to_vec();
        lineage.push(Arc::clone(&local));
        Self {
            local,
            lineage: lineage.into(),
        }
    }

    #[must_use]
    pub(crate) fn view(&self) -> CancellationView {
        CancellationView {
            lineage: Arc::clone(&self.lineage),
        }
    }

    pub(crate) fn cancel(&self) {
        self.local.cancel();
    }
}

/// Narrow callback-facing cancellation observation without a Tokio handle.
#[derive(Clone, Debug)]
pub(crate) struct CancellationView {
    lineage: Arc<[Arc<CancellationCell>]>,
}

impl CancellationView {
    #[must_use]
    pub(crate) fn is_cancelled(&self) -> bool {
        self.lineage
            .iter()
            .any(|cell| cell.cancelled.load(Ordering::Acquire))
    }

    /// Waits for this node or any ancestor to be cancelled.
    pub(crate) fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            loop {
                if self.is_cancelled() {
                    return;
                }
                let mut waiters = self
                    .lineage
                    .iter()
                    .map(|cell| Box::pin(Arc::clone(&cell.notify).notified_owned()))
                    .collect::<Vec<_>>();
                // Register every waiter before the second state check. Tokio
                // Notify does not retain `notify_waiters` calls for a Future
                // that has not been enabled yet; this ordering closes that
                // otherwise lost-wakeup window.
                for waiter in &mut waiters {
                    waiter.as_mut().enable();
                }
                if self.is_cancelled() {
                    return;
                }
                core::future::poll_fn(|context| {
                    if self.is_cancelled() {
                        return core::task::Poll::Ready(());
                    }
                    for waiter in &mut waiters {
                        if waiter.as_mut().poll(context).is_ready() {
                            return core::task::Poll::Ready(());
                        }
                    }
                    core::task::Poll::Pending
                })
                .await;
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskMetadata {
    runtime_id: RuntimeTaskId,
    tokio_id: TokioTaskId,
    kind: RuntimeTaskKind,
}

/// Terminal observation for one owned task.
#[derive(Debug)]
pub(crate) struct TaskCompletion<T> {
    id: RuntimeTaskId,
    kind: RuntimeTaskKind,
    outcome: TaskOutcome<T>,
}

impl<T> TaskCompletion<T> {
    #[must_use]
    pub(crate) const fn id(&self) -> RuntimeTaskId {
        self.id
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> RuntimeTaskKind {
        self.kind
    }

    pub(crate) fn into_outcome(self) -> TaskOutcome<T> {
        self.outcome
    }
}

/// Honest terminal state produced by join rather than inferred from intent.
#[derive(Debug)]
pub(crate) enum TaskOutcome<T> {
    Completed(T),
    Cancelled,
    Panicked,
}

/// Complete structured-shutdown evidence. The completion vector is bounded by
/// the registry's configured maximum task count.
#[derive(Debug)]
pub(crate) struct TaskShutdownReport<T> {
    forced: bool,
    completions: Vec<TaskCompletion<T>>,
}

impl<T> TaskShutdownReport<T> {
    #[must_use]
    pub(crate) const fn forced(&self) -> bool {
        self.forced
    }

    pub(crate) fn into_completions(self) -> Vec<TaskCompletion<T>> {
        self.completions
    }
}

/// The sole JoinSet owner for one bounded Runtime scope.
pub(crate) struct TaskRegistry<T: Send + 'static> {
    maximum: NonZeroUsize,
    next_id: u64,
    root_cancellation: CancellationSource,
    tasks: JoinSet<T>,
    metadata: Vec<TaskMetadata>,
}

impl<T: Send + 'static> TaskRegistry<T> {
    #[must_use]
    pub(crate) fn new(maximum: NonZeroUsize) -> Self {
        Self {
            maximum,
            next_id: 0,
            root_cancellation: CancellationSource::root(),
            tasks: JoinSet::new(),
            metadata: Vec::with_capacity(maximum.get()),
        }
    }

    #[must_use]
    pub(crate) fn root_cancellation(&self) -> CancellationSource {
        self.root_cancellation.clone()
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.metadata.len()
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.metadata.is_empty()
    }

    #[must_use]
    pub(crate) fn has_capacity(&self) -> bool {
        self.metadata.len() < self.maximum.get() && self.next_id != u64::MAX
    }

    /// Reserves capacity and an identifier before constructing the Future.
    ///
    /// The factory is never called when admission fails, so callers can prove
    /// that rejected work created neither a Future nor a Tokio task.
    pub(crate) fn try_spawn<F, Build>(
        &mut self,
        kind: RuntimeTaskKind,
        build: Build,
    ) -> Result<RuntimeTaskId, TaskRegistryError>
    where
        F: Future<Output = T> + Send + 'static,
        Build: FnOnce() -> F,
    {
        if self.metadata.len() >= self.maximum.get() {
            return Err(TaskRegistryError::CapacityExhausted);
        }
        let Some(next_id) = self.next_id.checked_add(1) else {
            return Err(TaskRegistryError::IdentifierExhausted);
        };
        let runtime_id = RuntimeTaskId(next_id);
        let abort = self.tasks.spawn(build());
        self.metadata.push(TaskMetadata {
            runtime_id,
            tokio_id: abort.id(),
            kind,
        });
        self.next_id = next_id;
        Ok(runtime_id)
    }

    /// Reaps one completed task and removes its census entry atomically.
    pub(crate) async fn join_next(&mut self) -> Option<TaskCompletion<T>> {
        let result = self.tasks.join_next_with_id().await?;
        Some(self.complete_join(result))
    }

    /// Cancels the root, waits cooperatively, then aborts and joins every
    /// remaining task when the cleanup deadline is reached.
    pub(crate) async fn shutdown(&mut self, budget: Duration) -> TaskShutdownReport<T> {
        self.root_cancellation.cancel();
        let deadline = Instant::now() + budget;
        let mut forced = false;
        let mut completions = Vec::with_capacity(self.metadata.len());

        while !self.tasks.is_empty() {
            match timeout_at(deadline, self.tasks.join_next_with_id()).await {
                Ok(Some(result)) => completions.push(self.complete_join(result)),
                Ok(None) => break,
                Err(_) => {
                    forced = true;
                    break;
                }
            }
        }

        if !self.tasks.is_empty() {
            self.tasks.abort_all();
            while let Some(result) = self.tasks.join_next_with_id().await {
                completions.push(self.complete_join(result));
            }
        }

        debug_assert!(self.metadata.is_empty());
        TaskShutdownReport {
            forced,
            completions,
        }
    }

    fn complete_join(&mut self, result: Result<(TokioTaskId, T), JoinError>) -> TaskCompletion<T> {
        let tokio_id = match &result {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        let position = self
            .metadata
            .iter()
            .position(|metadata| metadata.tokio_id == tokio_id)
            .unwrap_or_else(|| panic!("joined task must have one registry census entry"));
        let metadata = self.metadata.swap_remove(position);
        let outcome = match result {
            Ok((_, output)) => TaskOutcome::Completed(output),
            Err(error) if error.is_cancelled() => TaskOutcome::Cancelled,
            Err(_) => TaskOutcome::Panicked,
        };
        TaskCompletion {
            id: metadata.runtime_id,
            kind: metadata.kind,
            outcome,
        }
    }
}

/// Stable internal failures before a task is admitted to the registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskRegistryError {
    CapacityExhausted,
    IdentifierExhausted,
}

impl fmt::Display for TaskRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExhausted => formatter.write_str("runtime task capacity exhausted"),
            Self::IdentifierExhausted => formatter.write_str("runtime task identifier exhausted"),
        }
    }
}

impl std::error::Error for TaskRegistryError {}

#[cfg(test)]
mod tests {
    use core::num::NonZeroUsize;
    use core::time::Duration;

    use super::{RuntimeTaskKind, TaskOutcome, TaskRegistry, TaskRegistryError};

    fn capacity(value: usize) -> NonZeroUsize {
        let Some(value) = NonZeroUsize::new(value) else {
            panic!("fixture capacity must be nonzero");
        };
        value
    }

    #[tokio::test]
    async fn capacity_rejection_never_constructs_the_future() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let mut registry = TaskRegistry::new(capacity(1));
        let built = Arc::new(AtomicUsize::new(0));
        let first_built = Arc::clone(&built);
        let Ok(_) = registry.try_spawn(RuntimeTaskKind::ComponentLifecycle, move || {
            first_built.fetch_add(1, Ordering::SeqCst);
            async { 1_u8 }
        }) else {
            panic!("first task must fit");
        };
        let second_built = Arc::clone(&built);
        assert_eq!(
            registry.try_spawn(RuntimeTaskKind::ComponentLifecycle, move || {
                second_built.fetch_add(1, Ordering::SeqCst);
                async { 2_u8 }
            }),
            Err(TaskRegistryError::CapacityExhausted)
        );
        assert_eq!(built.load(Ordering::SeqCst), 1);

        let Some(completion) = registry.join_next().await else {
            panic!("first task must join");
        };
        assert!(matches!(
            completion.into_outcome(),
            TaskOutcome::Completed(1)
        ));
        assert!(registry.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn inherited_cancellation_completes_without_forced_abort() {
        let mut registry = TaskRegistry::new(capacity(2));
        let child = registry.root_cancellation().child();
        let view = child.view();
        let Ok(_) = registry.try_spawn(RuntimeTaskKind::ComponentLifecycle, move || async move {
            view.cancelled().await;
            7_u8
        }) else {
            panic!("dispatcher task must fit");
        };

        let report = registry.shutdown(Duration::from_millis(1)).await;

        assert!(!report.forced());
        assert!(registry.is_empty());
        assert!(matches!(
            report.into_completions()[0].outcome,
            TaskOutcome::Completed(7)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn notify_waiters_wakes_every_registered_descendant_without_loss() {
        let mut registry = TaskRegistry::new(capacity(16));
        for value in 0_u8..16 {
            let view = registry.root_cancellation().child().view();
            let Ok(_) =
                registry.try_spawn(RuntimeTaskKind::ComponentLifecycle, move || async move {
                    view.cancelled().await;
                    value
                })
            else {
                panic!("all bounded descendant waiters must fit");
            };
        }

        // Yield once so all Notified futures enable their wait-list entries,
        // then cancel the common ancestor through structured shutdown.
        tokio::task::yield_now().await;
        let report = registry.shutdown(Duration::from_millis(1)).await;
        assert!(!report.forced());
        assert_eq!(report.into_completions().len(), 16);
        assert!(registry.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn non_cooperative_task_is_aborted_and_fully_joined() {
        let mut registry = TaskRegistry::new(capacity(1));
        let Ok(_) = registry.try_spawn(RuntimeTaskKind::HostControl, || async {
            core::future::pending::<()>().await;
            1_u8
        }) else {
            panic!("pending task must fit");
        };

        let report = registry.shutdown(Duration::from_nanos(1)).await;

        assert!(report.forced());
        assert!(registry.is_empty());
        assert!(matches!(
            report.into_completions()[0].outcome,
            TaskOutcome::Cancelled
        ));
    }

    #[tokio::test]
    async fn panic_is_joined_as_a_fact_instead_of_detached() {
        let mut registry = TaskRegistry::new(capacity(1));
        let Ok(_) = registry.try_spawn(RuntimeTaskKind::CoreServiceLifecycle, || async {
            panic!("fixture panic");
        }) else {
            panic!("panic fixture must fit");
        };

        let Some(completion) = registry.join_next().await else {
            panic!("panic must still join");
        };
        assert_eq!(completion.kind(), RuntimeTaskKind::CoreServiceLifecycle);
        assert!(matches!(completion.into_outcome(), TaskOutcome::Panicked));
        assert!(registry.is_empty());
    }
}
