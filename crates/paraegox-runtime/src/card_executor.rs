//! RuntimeHost-owned execution of one trusted in-process Card implementation.
//!
//! This private layer turns an already-admitted PXTE subject into lifecycle
//! callbacks. It never creates a task, reactor, thread, binding, or payload
//! queue. The LoopDomain owner must acquire a domain permit and move a Message
//! to in-flight before calling [`CardCallbackOwner::invoke`].

use core::fmt;
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::time::Duration;
use std::panic::{AssertUnwindSafe, catch_unwind};

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::time::{BoundedDuration, ClockReading};
use paraegox_runtime_contracts::execution::{
    BlockingRisk, CallModel, CardDefinitionRef, CardImplementationRef, LoopDomainSpec,
    MailboxExecutionSpec, OverrunAction, RunBoundProvenance, WorkloadKind,
};

use crate::card_instance::{
    CallbackFailure, CardContext, CardImplementation, CardInstanceError, CardInstanceIdentity,
    CardInstanceOwner, CardLifecycle, InputView, InvocationFence,
};
use crate::loop_domain::{LoopDomainError, LoopDomainGrant, LoopDomainOwnerIdentity};
use crate::mailbox::TerminalReason;
use crate::task_registry::CancellationSource;

/// Explicit same-build review marker for implementations admitted to the
/// cooperative Loop profile.
///
/// This is intentionally crate-private and has no blanket implementation.
/// Implementing it records a static code-review assertion that callbacks do
/// not block, spin, enter unknown native/device code, or create ambient work.
/// Runtime budgets remain a backstop, not a dynamic detector for a callback
/// that never yields; implementations without this marker cannot be resolved.
pub(crate) trait CooperativeLoopImplementation: CardImplementation {
    const BOUND_CARD_DEFINITION: CardDefinitionRef;
    const BOUND_CARD_IMPLEMENTATION: CardImplementationRef;
    const BOUND_DEFINITION_DIGEST: Digest32;
    const BOUND_ARTIFACT_DIGEST: Digest32;
}

/// Trusted implementation selection made outside Card code.
///
/// The references and artifact digests must match the authenticated PXTE
/// subject exactly. Configuration remains the signed per-use value and is not
/// allowed to select another implementation here.
pub(crate) struct TrustedCardImplementation {
    card_definition: CardDefinitionRef,
    card_implementation: CardImplementationRef,
    definition_digest: Digest32,
    artifact_digest: Digest32,
    implementation: Box<dyn CardImplementation>,
}

impl TrustedCardImplementation {
    /// Resolves a trusted same-build implementation only after every signed
    /// execution record has proven eligible for the cooperative Loop profile.
    ///
    /// `build` is the future static Artifact-registry boundary: it must map the
    /// exact authenticated implementation reference and digest to same-build
    /// code. It is deliberately deferred until validation succeeds, so a
    /// sync/CPU/native fixture creates neither an implementation object nor a
    /// callback Future. This check does not claim to detect dishonesty inside
    /// trusted code at runtime; such code belongs in a stronger Domain.
    pub(crate) fn try_resolve_loop<Implementation, Build>(
        executions: &[MailboxExecutionSpec],
        build: Build,
    ) -> Result<Self, CardCallbackError>
    where
        Implementation: CooperativeLoopImplementation + 'static,
        Build: FnOnce() -> Implementation,
    {
        let Some(first) = executions.first().copied() else {
            return Err(CardCallbackError::MissingExecution);
        };
        if Implementation::BOUND_CARD_DEFINITION != first.card_definition()
            || Implementation::BOUND_CARD_IMPLEMENTATION != first.card_implementation()
            || Implementation::BOUND_DEFINITION_DIGEST != first.definition_digest()
            || Implementation::BOUND_ARTIFACT_DIGEST != first.artifact_digest()
        {
            return Err(CardCallbackError::ImplementationMismatch);
        }
        for execution in executions {
            if execution.card_definition() != first.card_definition()
                || execution.card_implementation() != first.card_implementation()
                || execution.definition_digest() != first.definition_digest()
                || execution.artifact_digest() != first.artifact_digest()
            {
                return Err(CardCallbackError::ExecutionSubjectMismatch);
            }
            if execution.call_model() != CallModel::CooperativeAsync
                || !matches!(
                    execution.workload_kind(),
                    WorkloadKind::Io | WorkloadKind::Routing
                )
                || execution.blocking_risk() != BlockingRisk::None
                || !matches!(
                    execution.run_bound_provenance(),
                    RunBoundProvenance::Measured | RunBoundProvenance::Certified
                )
            {
                return Err(CardCallbackError::LoopImplementationIneligible);
            }
            if !matches!(
                execution.overrun_action(),
                OverrunAction::CooperativeCancel | OverrunAction::Escalate
            ) {
                return Err(CardCallbackError::UnsupportedLoopOverrunAction);
            }
        }
        Ok(Self {
            card_definition: first.card_definition(),
            card_implementation: first.card_implementation(),
            definition_digest: first.definition_digest(),
            artifact_digest: first.artifact_digest(),
            implementation: Box::new(build()),
        })
    }

    /// Test-only escape hatch for exercising exact-subject mismatch handling.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_unchecked_for_test(
        card_definition: CardDefinitionRef,
        card_implementation: CardImplementationRef,
        definition_digest: Digest32,
        artifact_digest: Digest32,
        implementation: Box<dyn CardImplementation>,
    ) -> Self {
        Self {
            card_definition,
            card_implementation,
            definition_digest,
            artifact_digest,
            implementation,
        }
    }
}

/// Bounded result of the Card startup callback; it is not a readiness claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CardStartOutcome {
    Started,
    Failed(CallbackFailure),
    TimedOut,
    Cancelled,
    Panicked,
}

/// Bounded result of one callback after its generation fence was checked.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CardInvocationOutcome {
    Completed { output_discarded: bool },
    Failed(CallbackFailure),
    CancelledBeforeRun,
    NotRun(TerminalReason),
    TimedOutCooperative,
    TimedOutEscalated,
    Panicked,
}

/// Bounded result of the final cleanup callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CardStopOutcome {
    Stopped,
    Interrupted,
    Failed(CallbackFailure),
    TimedOut,
    Panicked,
}

/// Sole lifecycle and callback owner for one CardInstance generation.
pub(crate) struct CardCallbackOwner {
    card: CardInstanceOwner,
    cancellation: CancellationSource,
    domain: LoopDomainSpec,
    domain_owner: LoopDomainOwnerIdentity,
    executions: Box<[MailboxExecutionSpec]>,
    card_definition: CardDefinitionRef,
    card_implementation: CardImplementationRef,
    definition_digest: Digest32,
    artifact_digest: Digest32,
    config_digest: Digest32,
    pending_invocation: Option<InvocationFence>,
    terminal_stop_outcome: Option<CardStopOutcome>,
}

impl CardCallbackOwner {
    /// Selects one exact trusted implementation for the authenticated subject.
    pub(crate) fn try_new(
        identity: CardInstanceIdentity,
        domain: LoopDomainSpec,
        domain_owner: LoopDomainOwnerIdentity,
        executions: &[MailboxExecutionSpec],
        selected: TrustedCardImplementation,
        parent_cancellation: &CancellationSource,
    ) -> Result<Self, CardCallbackError> {
        let Some(first) = executions.first().copied() else {
            return Err(CardCallbackError::MissingExecution);
        };
        if domain_owner.planned_domain() != domain.domain()
            || domain_owner.domain_epoch() != identity.domain_epoch()
        {
            return Err(CardCallbackError::DomainMismatch);
        }
        for execution in executions {
            if identity.planned_instance() != execution.target_instance() {
                return Err(CardCallbackError::InstanceMismatch);
            }
            if execution.domain() != domain.domain() {
                return Err(CardCallbackError::DomainMismatch);
            }
            if execution.card_definition() != first.card_definition()
                || execution.card_implementation() != first.card_implementation()
                || execution.definition_digest() != first.definition_digest()
                || execution.artifact_digest() != first.artifact_digest()
                || execution.config_digest() != first.config_digest()
            {
                return Err(CardCallbackError::ExecutionSubjectMismatch);
            }
        }
        if selected.card_definition != first.card_definition()
            || selected.card_implementation != first.card_implementation()
            || selected.definition_digest != first.definition_digest()
            || selected.artifact_digest != first.artifact_digest()
        {
            return Err(CardCallbackError::ImplementationMismatch);
        }
        Ok(Self {
            card: CardInstanceOwner::new(identity, selected.implementation),
            cancellation: parent_cancellation.child(),
            domain,
            domain_owner,
            executions: executions.to_vec().into_boxed_slice(),
            card_definition: selected.card_definition,
            card_implementation: selected.card_implementation,
            definition_digest: selected.definition_digest,
            artifact_digest: selected.artifact_digest,
            config_digest: first.config_digest(),
            pending_invocation: None,
            terminal_stop_outcome: None,
        })
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> CardInstanceIdentity {
        self.card.identity()
    }

    #[must_use]
    pub(crate) const fn lifecycle(&self) -> CardLifecycle {
        self.card.lifecycle()
    }

    /// Runs the implementation startup callback under the signed Domain budget.
    pub(crate) async fn start(
        &mut self,
        reading: ClockReading,
    ) -> Result<CardStartOutcome, CardCallbackError> {
        self.card.begin_start()?;
        if self.cancellation.view().is_cancelled() {
            self.card.finish_start(false)?;
            return Ok(CardStartOutcome::Cancelled);
        }
        let context = self.context(reading, self.cancellation.view());
        // Keep callback construction inside the polled async block. The outer
        // poll catcher therefore contains both a synchronous constructor panic
        // and any later panic from the implementation Future.
        let callback = async { self.card.implementation_mut().on_start(&context).await };
        let result = tokio::time::timeout(
            duration(self.domain.start_budget()),
            catch_callback(callback),
        )
        .await;
        match result {
            Ok(Ok(Ok(()))) => {
                self.card.finish_start(true)?;
                Ok(CardStartOutcome::Started)
            }
            Ok(Ok(Err(failure))) => {
                self.card.finish_start(false)?;
                Ok(CardStartOutcome::Failed(failure))
            }
            Ok(Err(())) => {
                self.card.finish_start(false)?;
                self.card.poison();
                Ok(CardStartOutcome::Panicked)
            }
            Err(_) => {
                self.cancellation.cancel();
                self.card.finish_start(false)?;
                Ok(CardStartOutcome::TimedOut)
            }
        }
    }

    /// Executes one already-permitted, already-in-flight input callback.
    ///
    /// Rust Future drop is the cooperative cancellation boundary used by this
    /// in-process Loop profile. A callback that spins without yielding cannot
    /// be preempted; such workload is rejected by signed Loop admission before
    /// any task or Future is created. The cleanup budget bounds additional
    /// async polling after cancellation; destructors must remain non-blocking
    /// under the same trusted-implementation contract.
    pub(crate) async fn invoke(
        &mut self,
        grant: &mut LoopDomainGrant,
        reading: ClockReading,
    ) -> Result<CardInvocationOutcome, CardCallbackError> {
        if self.pending_invocation.is_some() {
            return Err(CardCallbackError::InterruptedInvocationRequiresCleanup);
        }
        let execution = grant.execution_spec();
        if execution.target_instance() != self.card.identity().planned_instance() {
            return Err(CardCallbackError::InstanceMismatch);
        }
        if execution.domain() != self.domain.domain() {
            return Err(CardCallbackError::DomainMismatch);
        }
        if !self.executions.contains(&execution) {
            return Err(CardCallbackError::ExecutionNotRegistered);
        }
        if execution.card_definition() != self.card_definition
            || execution.card_implementation() != self.card_implementation
            || execution.definition_digest() != self.definition_digest
            || execution.artifact_digest() != self.artifact_digest
            || execution.config_digest() != self.config_digest
        {
            return Err(CardCallbackError::ExecutionSubjectMismatch);
        }
        if !matches!(
            execution.overrun_action(),
            OverrunAction::CooperativeCancel | OverrunAction::Escalate
        ) {
            return Err(CardCallbackError::UnsupportedLoopOverrunAction);
        }
        if grant.owner_identity() != &self.domain_owner {
            return Err(CardCallbackError::DomainGrant(
                LoopDomainError::GrantMismatch,
            ));
        }
        grant
            .claim_callback()
            .map_err(CardCallbackError::DomainGrant)?;
        if let Some(reason) = grant
            .pre_run_terminal(reading)
            .map_err(CardCallbackError::DomainGrant)?
        {
            return Ok(CardInvocationOutcome::NotRun(reason));
        }
        if self.cancellation.view().is_cancelled() {
            return Ok(CardInvocationOutcome::CancelledBeforeRun);
        }

        let fence = self.card.begin_invocation()?;
        self.pending_invocation = Some(fence);
        let invocation_cancellation = self.cancellation.child();
        let context = self.context(reading, invocation_cancellation.view());
        let target_port = grant.target_port();
        let message = grant.message();
        let callback = async {
            self.card
                .implementation_mut()
                .on_input(
                    &context,
                    InputView::from_message(
                        execution.binding_id(),
                        execution.mailbox(),
                        target_port,
                        message,
                    ),
                )
                .await
        };
        let (outcome, poison) = {
            let mut callback = Box::pin(catch_callback(callback));
            let primary =
                tokio::time::timeout(duration(execution.run_budget()), callback.as_mut()).await;
            match primary {
                Ok(primary) => {
                    // Release the borrowing callback stack before consulting
                    // the Card owner at the output fence below.
                    drop(callback);
                    match primary {
                        Ok(Ok(proposal)) => {
                            let output_discarded = if let Some(proposal) = proposal.as_ref() {
                                // The S4 component has no production output
                                // route. Its local/diagnostic sink is therefore
                                // a synchronous discard observer, but the
                                // generation and invocation fence is still
                                // checked at that exact boundary.
                                self.card.observe_output(fence, proposal, |_| {})?;
                                true
                            } else {
                                false
                            };
                            drop(proposal);
                            (CardInvocationOutcome::Completed { output_discarded }, false)
                        }
                        Ok(Err(failure)) => (CardInvocationOutcome::Failed(failure), false),
                        Err(()) => (CardInvocationOutcome::Panicked, true),
                    }
                }
                Err(_) => {
                    invocation_cancellation.cancel();
                    let cleanup = tokio::time::timeout(
                        duration(execution.cleanup_budget()),
                        callback.as_mut(),
                    )
                    .await;
                    drop(callback);
                    if matches!(&cleanup, Ok(Err(()))) {
                        (CardInvocationOutcome::Panicked, true)
                    } else {
                        // A result produced after the signed run boundary has
                        // no output authority. Drop it inside the owner before
                        // classifying the already-observed overrun.
                        drop(cleanup);
                        match execution.overrun_action() {
                            OverrunAction::CooperativeCancel => {
                                (CardInvocationOutcome::TimedOutCooperative, false)
                            }
                            OverrunAction::Escalate => {
                                (CardInvocationOutcome::TimedOutEscalated, true)
                            }
                            OverrunAction::Continue | OverrunAction::Uncertain => {
                                unreachable!("unsupported action was rejected before callback")
                            }
                        }
                    }
                }
            }
        };
        self.finish_pending_invocation(fence, poison)?;
        Ok(outcome)
    }

    /// Stops admission at the Card boundary and runs final cleanup with a hard
    /// Runtime-owned budget. Success means the callback stack was released;
    /// it does not claim external effect completion or production readiness.
    pub(crate) async fn stop(
        &mut self,
        reading: ClockReading,
    ) -> Result<CardStopOutcome, CardCallbackError> {
        if let Some(outcome) = self.terminal_stop_outcome {
            return Ok(outcome);
        }
        self.cancellation.cancel();
        match self.card.lifecycle() {
            CardLifecycle::Starting => self.card.poison(),
            CardLifecycle::Stopping => {
                self.card.finish_stop()?;
                self.terminal_stop_outcome = Some(CardStopOutcome::Interrupted);
                return Ok(CardStopOutcome::Interrupted);
            }
            _ => {}
        }
        self.reconcile_interrupted_invocation()?;
        self.card.begin_draining()?;
        self.card.begin_stop()?;
        let context = self.context(reading, self.cancellation.view());
        let callback = async { self.card.implementation_mut().on_stop(&context).await };
        let result = tokio::time::timeout(
            duration(self.domain.cleanup_budget()),
            catch_callback(callback),
        )
        .await;
        let outcome = match result {
            Ok(Ok(Ok(()))) => {
                self.card.finish_stop()?;
                CardStopOutcome::Stopped
            }
            Ok(Ok(Err(failure))) => {
                self.card.poison();
                CardStopOutcome::Failed(failure)
            }
            Ok(Err(())) => {
                self.card.poison();
                CardStopOutcome::Panicked
            }
            Err(_) => {
                self.card.poison();
                CardStopOutcome::TimedOut
            }
        };
        self.terminal_stop_outcome = Some(outcome);
        Ok(outcome)
    }

    fn finish_pending_invocation(
        &mut self,
        fence: InvocationFence,
        poison: bool,
    ) -> Result<(), CardCallbackError> {
        if self.pending_invocation != Some(fence) {
            return Err(CardCallbackError::InterruptedInvocationRequiresCleanup);
        }
        self.card.finish_invocation(fence)?;
        self.pending_invocation = None;
        if poison {
            self.card.poison();
        }
        Ok(())
    }

    /// Closes a fence left behind only after the borrowing invocation Future
    /// was dropped. The caller can then terminal the separately retained grant
    /// as uncertain before final Card cleanup.
    fn reconcile_interrupted_invocation(&mut self) -> Result<bool, CardCallbackError> {
        let Some(fence) = self.pending_invocation else {
            return Ok(false);
        };
        self.card.finish_invocation(fence)?;
        self.pending_invocation = None;
        self.card.poison();
        Ok(true)
    }

    fn context(
        &self,
        reading: ClockReading,
        cancellation: crate::task_registry::CancellationView,
    ) -> CardContext {
        CardContext::new(
            self.card.identity(),
            reading,
            cancellation,
            self.definition_digest,
            self.artifact_digest,
            self.config_digest,
        )
    }
}

const fn duration(value: BoundedDuration) -> Duration {
    Duration::from_nanos(value.value())
}

/// Owns callback destruction behind the same panic boundary as polling.
struct PanicContainedFuture<F: Future> {
    inner: Option<Pin<Box<F>>>,
}

impl<F: Future> PanicContainedFuture<F> {
    fn new(future: F) -> Self {
        Self {
            inner: Some(Box::pin(future)),
        }
    }

    fn close(&mut self) -> Result<(), ()> {
        catch_unwind(AssertUnwindSafe(|| drop(self.inner.take()))).map_err(|_| ())
    }
}

impl<F: Future> Future for PanicContainedFuture<F> {
    type Output = Result<F::Output, ()>;

    fn poll(
        mut self: Pin<&mut Self>,
        context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let Some(inner) = self.inner.as_mut() else {
            return core::task::Poll::Ready(Err(()));
        };
        match catch_unwind(AssertUnwindSafe(|| inner.as_mut().poll(context))) {
            Ok(core::task::Poll::Ready(output)) => core::task::Poll::Ready(Ok(output)),
            Ok(core::task::Poll::Pending) => core::task::Poll::Pending,
            Err(_) => core::task::Poll::Ready(Err(())),
        }
    }
}

impl<F: Future> Drop for PanicContainedFuture<F> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Converts callback construction, polling, and completed-Future destruction
/// panics into an owned Runtime outcome. If the surrounding invocation Future
/// itself is cancelled, `Drop` still contains callback destructor panics.
pub(crate) async fn catch_callback<F>(callback: F) -> Result<F::Output, ()>
where
    F: Future,
{
    let mut callback = PanicContainedFuture::new(callback);
    let outcome = poll_fn(|context| Pin::new(&mut callback).poll(context)).await;
    callback.close()?;
    outcome
}

/// Fail-closed implementation selection and lifecycle failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CardCallbackError {
    MissingExecution,
    InstanceMismatch,
    DomainMismatch,
    ImplementationMismatch,
    ExecutionSubjectMismatch,
    ExecutionNotRegistered,
    LoopImplementationIneligible,
    UnsupportedLoopOverrunAction,
    InterruptedInvocationRequiresCleanup,
    DomainGrant(LoopDomainError),
    Instance(CardInstanceError),
}

impl From<CardInstanceError> for CardCallbackError {
    fn from(value: CardInstanceError) -> Self {
        Self::Instance(value)
    }
}

impl From<LoopDomainError> for CardCallbackError {
    fn from(value: LoopDomainError) -> Self {
        Self::DomainGrant(value)
    }
}

impl fmt::Display for CardCallbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingExecution => formatter.write_str("Card has no Loop execution record"),
            Self::InstanceMismatch => formatter.write_str("Card implementation instance mismatch"),
            Self::DomainMismatch => {
                formatter.write_str("Card execution belongs to another LoopDomain")
            }
            Self::ImplementationMismatch => {
                formatter.write_str("trusted Card implementation does not match signed subject")
            }
            Self::ExecutionSubjectMismatch => {
                formatter.write_str("Mailbox execution belongs to another Card subject")
            }
            Self::ExecutionNotRegistered => {
                formatter.write_str("Mailbox execution is not registered for this Card owner")
            }
            Self::LoopImplementationIneligible => formatter.write_str(
                "trusted implementation evidence is not eligible for the cooperative LoopDomain",
            ),
            Self::UnsupportedLoopOverrunAction => {
                formatter.write_str("overrun action is not executable in LoopDomain")
            }
            Self::InterruptedInvocationRequiresCleanup => {
                formatter.write_str("interrupted Card invocation requires cleanup")
            }
            Self::DomainGrant(error) => error.fmt(formatter),
            Self::Instance(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CardCallbackError {}

#[cfg(test)]
mod tests {
    use core::future::{Future, poll_fn};
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::Poll;
    use core::time::Duration;
    use std::sync::{Arc, Mutex};

    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
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
        LoopExecutionRequirements, LoopLifecycleBudgets, MailboxDispatchPolicy,
        MailboxExecutionSpec, OverrunAction, RunBoundProvenance, WorkloadKind,
    };
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};

    use super::{
        CardCallbackError, CardCallbackOwner, CardInvocationOutcome, CardStartOutcome,
        CardStopOutcome, CooperativeLoopImplementation, TrustedCardImplementation,
    };
    use crate::card_instance::{
        CallbackFailure, CardContext, CardFuture, CardImplementation, CardInstanceError,
        CardInstanceIdentity, CardLifecycle, DomainEpoch, InputView, InstanceGeneration,
        OutputProposal, RuntimeHostEpoch,
    };
    use crate::loop_domain::{
        LoopDomainCore, LoopDomainDispatchOutcome, LoopDomainError, LoopDomainGrant,
    };
    use crate::mailbox::{
        EnqueueOutcome, MessageId, PayloadHandle, TerminalReason, ValidatedMessage,
    };
    use crate::task_registry::CancellationSource;

    const DEFINITION: CardDefinitionRef = CardDefinitionRef::from_bytes([0x11; 16]);
    const IMPLEMENTATION: CardImplementationRef = CardImplementationRef::from_bytes([0x12; 16]);
    const INSTANCE: InstanceRef = InstanceRef::from_bytes([0x13; 16]);
    const MAILBOX: MailboxRef = MailboxRef::from_bytes([0x14; 16]);
    const DOMAIN: DomainRef = DomainRef::from_bytes([0x15; 16]);
    const CLOCK_DOMAIN: ClockDomainRef = ClockDomainRef::from_bytes([0x16; 16]);
    const DEFINITION_DIGEST: Digest32 = Digest32::from_bytes([0x21; 32]);
    const ARTIFACT_DIGEST: Digest32 = Digest32::from_bytes([0x22; 32]);
    const CONFIG_DIGEST: Digest32 = Digest32::from_bytes([0x23; 32]);

    #[derive(Clone, Copy)]
    struct CardBehavior {
        start_delay: Duration,
        input_delay: Duration,
        stop_delay: Duration,
        fail_start: bool,
        fail_input: bool,
        fail_stop: bool,
        panic_start: bool,
        panic_input: bool,
        panic_stop: bool,
        panic_start_constructor: bool,
        panic_input_constructor: bool,
        panic_stop_constructor: bool,
        panic_input_destructor: bool,
        emit_output: bool,
    }

    impl Default for CardBehavior {
        fn default() -> Self {
            Self {
                start_delay: Duration::ZERO,
                input_delay: Duration::ZERO,
                stop_delay: Duration::ZERO,
                fail_start: false,
                fail_input: false,
                fail_stop: false,
                panic_start: false,
                panic_input: false,
                panic_stop: false,
                panic_start_constructor: false,
                panic_input_constructor: false,
                panic_stop_constructor: false,
                panic_input_destructor: false,
                emit_output: false,
            }
        }
    }

    struct TestCard {
        behavior: CardBehavior,
        callback_count: Arc<AtomicUsize>,
    }

    struct RouteRecordingCard {
        routes: Arc<Mutex<Vec<(BindingId, MailboxRef, PortRef)>>>,
    }

    struct ReadyThenPanicOnDrop {
        output: Option<Result<Option<OutputProposal>, CallbackFailure>>,
    }

    impl Future for ReadyThenPanicOnDrop {
        type Output = Result<Option<OutputProposal>, CallbackFailure>;

        fn poll(
            self: Pin<&mut Self>,
            _context: &mut core::task::Context<'_>,
        ) -> Poll<Self::Output> {
            let this = self.get_mut();
            Poll::Ready(this.output.take().unwrap_or(Err(CallbackFailure::Failed)))
        }
    }

    impl Drop for ReadyThenPanicOnDrop {
        fn drop(&mut self) {
            panic!("test callback Future destructor panic");
        }
    }

    impl CardImplementation for TestCard {
        fn on_start<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            assert!(
                !self.behavior.panic_start_constructor,
                "test start constructor panic"
            );
            Box::pin(async move {
                tokio::time::sleep(self.behavior.start_delay).await;
                assert!(!self.behavior.panic_start, "test start panic");
                if self.behavior.fail_start {
                    Err(CallbackFailure::Failed)
                } else {
                    Ok(())
                }
            })
        }

        fn on_input<'a>(
            &'a mut self,
            _context: &'a CardContext,
            input: InputView<'a>,
        ) -> CardFuture<'a, Result<Option<OutputProposal>, CallbackFailure>> {
            self.callback_count.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.behavior.panic_input_constructor,
                "test input constructor panic"
            );
            if self.behavior.panic_input_destructor {
                return Box::pin(ReadyThenPanicOnDrop {
                    output: Some(Ok(None)),
                });
            }
            Box::pin(async move {
                tokio::time::sleep(self.behavior.input_delay).await;
                assert!(!self.behavior.panic_input, "test input panic");
                if self.behavior.fail_input {
                    return Err(CallbackFailure::Rejected);
                }
                if !self.behavior.emit_output {
                    return Ok(None);
                }
                let proposal = OutputProposal::try_new(
                    PortRef::from_bytes([0x31; 16]),
                    input.schema(),
                    input.payload().to_vec(),
                    64,
                )
                .unwrap_or_else(|error| panic!("test output must fit: {error}"));
                Ok(Some(proposal))
            })
        }

        fn on_stop<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            assert!(
                !self.behavior.panic_stop_constructor,
                "test stop constructor panic"
            );
            Box::pin(async move {
                tokio::time::sleep(self.behavior.stop_delay).await;
                assert!(!self.behavior.panic_stop, "test stop panic");
                if self.behavior.fail_stop {
                    Err(CallbackFailure::Failed)
                } else {
                    Ok(())
                }
            })
        }
    }

    impl CooperativeLoopImplementation for TestCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = DEFINITION;
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef = IMPLEMENTATION;
        const BOUND_DEFINITION_DIGEST: Digest32 = DEFINITION_DIGEST;
        const BOUND_ARTIFACT_DIGEST: Digest32 = ARTIFACT_DIGEST;
    }

    struct WrongArtifactCard;

    impl CardImplementation for WrongArtifactCard {
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
            Box::pin(async { Ok(()) })
        }
    }

    impl CooperativeLoopImplementation for WrongArtifactCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = DEFINITION;
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef = IMPLEMENTATION;
        const BOUND_DEFINITION_DIGEST: Digest32 = DEFINITION_DIGEST;
        const BOUND_ARTIFACT_DIGEST: Digest32 = Digest32::from_bytes([0xff; 32]);
    }

    impl CardImplementation for RouteRecordingCard {
        fn on_start<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            Box::pin(async { Ok(()) })
        }

        fn on_input<'a>(
            &'a mut self,
            _context: &'a CardContext,
            input: InputView<'a>,
        ) -> CardFuture<'a, Result<Option<OutputProposal>, CallbackFailure>> {
            let route = (input.binding(), input.mailbox(), input.target_port());
            let Ok(mut routes) = self.routes.lock() else {
                panic!("route observation lock must remain usable");
            };
            routes.push(route);
            Box::pin(async { Ok(None) })
        }

        fn on_stop<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            Box::pin(async { Ok(()) })
        }
    }

    impl CooperativeLoopImplementation for RouteRecordingCard {
        const BOUND_CARD_DEFINITION: CardDefinitionRef = DEFINITION;
        const BOUND_CARD_IMPLEMENTATION: CardImplementationRef = IMPLEMENTATION;
        const BOUND_DEFINITION_DIGEST: Digest32 = DEFINITION_DIGEST;
        const BOUND_ARTIFACT_DIGEST: Digest32 = ARTIFACT_DIGEST;
    }

    fn bounded(value: u64) -> BoundedDuration {
        BoundedDuration::from_nanos(value)
    }

    fn generation() -> ClockGeneration {
        ClockGeneration::try_new(1)
            .unwrap_or_else(|error| panic!("test generation must build: {error}"))
    }

    fn reading(now: u64) -> ClockReading {
        ClockReading::new(
            CLOCK_DOMAIN,
            generation(),
            MonotonicInstant::from_ticks(now),
        )
    }

    fn schema() -> SchemaRef {
        SchemaRef::try_new([0x41; 16], 1, Digest32::from_bytes([0x42; 32]))
            .unwrap_or_else(|error| panic!("test schema must build: {error}"))
    }

    fn identity() -> CardInstanceIdentity {
        identity_generation(1)
    }

    fn identity_generation(value: u64) -> CardInstanceIdentity {
        let host_epoch = RuntimeHostEpoch::try_new(1)
            .unwrap_or_else(|error| panic!("test host epoch must build: {error}"));
        let domain_epoch = DomainEpoch::try_new(1)
            .unwrap_or_else(|error| panic!("test domain epoch must build: {error}"));
        let generation = InstanceGeneration::try_new(value)
            .unwrap_or_else(|error| panic!("test instance generation must build: {error}"));
        CardInstanceIdentity::new(
            RuntimeHostId::from_bytes([0x51; 16]),
            host_epoch,
            INSTANCE,
            SourcePlanRevision::new(7),
            TargetSliceDigest::new(Digest32::from_bytes([0x52; 32])),
            domain_epoch,
            generation,
        )
    }

    fn execution(action: OverrunAction) -> MailboxExecutionSpec {
        execution_record(
            action,
            BindingId::from_bytes([0x61; 16]),
            MAILBOX,
            7_000_000,
        )
    }

    #[derive(Clone, Copy)]
    struct TestLoopProfile {
        call_model: CallModel,
        workload_kind: WorkloadKind,
        blocking_risk: BlockingRisk,
        run_bound_provenance: RunBoundProvenance,
    }

    impl TestLoopProfile {
        const ELIGIBLE: Self = Self {
            call_model: CallModel::CooperativeAsync,
            workload_kind: WorkloadKind::Io,
            blocking_risk: BlockingRisk::None,
            run_bound_provenance: RunBoundProvenance::Measured,
        };
    }

    fn execution_record(
        action: OverrunAction,
        binding: BindingId,
        mailbox: MailboxRef,
        cleanup_nanos: u64,
    ) -> MailboxExecutionSpec {
        execution_record_with_profile(
            action,
            binding,
            mailbox,
            cleanup_nanos,
            TestLoopProfile::ELIGIBLE,
        )
    }

    fn execution_record_with_profile(
        action: OverrunAction,
        binding: BindingId,
        mailbox: MailboxRef,
        cleanup_nanos: u64,
        profile: TestLoopProfile,
    ) -> MailboxExecutionSpec {
        let subject = CardSubjectSpec::new(
            DEFINITION,
            IMPLEMENTATION,
            DEFINITION_DIGEST,
            ARTIFACT_DIGEST,
            CONFIG_DIGEST,
        );
        let requirements = LoopExecutionRequirements::try_new(
            profile.call_model,
            profile.workload_kind,
            profile.blocking_risk,
            profile.run_bound_provenance,
            bounded(3_000_000),
        )
        .unwrap_or_else(|error| panic!("test requirements must build: {error}"));
        let budgets = CallbackBudgets::try_new(bounded(5_000_000), bounded(cleanup_nanos), action)
            .unwrap_or_else(|error| panic!("test budgets must build: {error}"));
        let dispatch =
            MailboxDispatchPolicy::try_new(DispatchClass::Interactive, 1, 1, 1, 1, budgets)
                .unwrap_or_else(|error| panic!("test dispatch must build: {error}"));
        MailboxExecutionSpec::try_new(
            binding,
            mailbox,
            INSTANCE,
            DOMAIN,
            subject,
            requirements,
            dispatch,
        )
        .unwrap_or_else(|error| panic!("test execution must build: {error}"))
    }

    fn domain_spec() -> LoopDomainSpec {
        let capacity =
            LoopDomainCapacity::try_new(2, 0, bounded(100_000_000), BoundedDuration::from_nanos(0))
                .unwrap_or_else(|error| panic!("test domain capacity must build: {error}"));
        let lifecycle = LoopLifecycleBudgets::try_new(
            bounded(5_000_000),
            bounded(6_000_000),
            bounded(7_000_000),
        )
        .unwrap_or_else(|error| panic!("test lifecycle budgets must build: {error}"));
        LoopDomainSpec::new(DOMAIN, capacity, lifecycle)
    }

    fn selected(
        behavior: CardBehavior,
        callback_count: Arc<AtomicUsize>,
    ) -> TrustedCardImplementation {
        TrustedCardImplementation::try_resolve_loop(
            &[execution(OverrunAction::CooperativeCancel)],
            move || TestCard {
                behavior,
                callback_count,
            },
        )
        .unwrap_or_else(|error| panic!("eligible test implementation must resolve: {error}"))
    }

    fn owner_from_selected(
        identity: CardInstanceIdentity,
        execution: MailboxExecutionSpec,
        selected: TrustedCardImplementation,
        parent: &CancellationSource,
    ) -> Result<CardCallbackOwner, CardCallbackError> {
        let domain = domain_for(execution);
        owner_from_selected_for_domain(identity, execution, &domain, selected, parent)
    }

    fn owner_from_selected_for_domain(
        identity: CardInstanceIdentity,
        execution: MailboxExecutionSpec,
        domain: &LoopDomainCore,
        selected: TrustedCardImplementation,
        parent: &CancellationSource,
    ) -> Result<CardCallbackOwner, CardCallbackError> {
        CardCallbackOwner::try_new(
            identity,
            domain_spec(),
            domain.owner_identity(),
            &[execution],
            selected,
            parent,
        )
    }

    fn binding_record(binding_id: BindingId, mailbox: MailboxRef) -> BindingAssignment {
        binding_record_with_target(binding_id, mailbox, PortRef::from_bytes([0x64; 16]))
    }

    fn binding_record_with_target(
        binding_id: BindingId,
        mailbox: MailboxRef,
        target_port: PortRef,
    ) -> BindingAssignment {
        let source = PortEndpoint::new(
            InstanceRef::from_bytes([0x62; 16]),
            PortRef::from_bytes([0x63; 16]),
            PortSpec::new(
                PortDirection::Out,
                schema(),
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let target = PortEndpoint::new(
            INSTANCE,
            target_port,
            PortSpec::new(
                PortDirection::In,
                schema(),
                InteractionKind::Signal,
                PortCardinality::One,
            ),
        );
        let delivery = DeliveryProfile::try_new(64, bounded(100), OverflowPolicy::RejectNew)
            .unwrap_or_else(|error| panic!("test delivery must build: {error}"));
        let mailbox_spec =
            MailboxSpec::try_new(2, 64, bounded(100), 1, 64, OverflowPolicy::RejectNew)
                .unwrap_or_else(|error| panic!("test mailbox spec must build: {error}"));
        BindingAssignment::try_new(binding_id, source, target, mailbox, delivery, mailbox_spec)
            .unwrap_or_else(|error| panic!("test binding must build: {error}"))
    }

    fn permitted(
        message: u8,
        execution: MailboxExecutionSpec,
    ) -> (LoopDomainCore, Box<LoopDomainGrant>) {
        permitted_with_deadlines(message, execution, 100, 100)
    }

    fn permitted_with_deadlines(
        message: u8,
        execution: MailboxExecutionSpec,
        fresh_until: u64,
        run_deadline: u64,
    ) -> (LoopDomainCore, Box<LoopDomainGrant>) {
        let mut domain = domain_for(execution);
        let binding = domain
            .binding_assignment(execution.mailbox())
            .unwrap_or_else(|| panic!("test binding must be installed"));
        let fresh_until = reading(0)
            .try_deadline_after(bounded(fresh_until))
            .unwrap_or_else(|error| panic!("test freshness must build: {error}"));
        let run_deadline = reading(0)
            .try_deadline_after(bounded(run_deadline))
            .unwrap_or_else(|error| panic!("test run deadline must build: {error}"));
        let payload = PayloadHandle::try_from_vec(vec![message; 3])
            .unwrap_or_else(|error| panic!("test payload must build: {error}"));
        let input = ValidatedMessage::new_with_deadlines(
            MessageId::from_bytes([message; 16]),
            schema(),
            InteractionKind::Signal,
            None,
            fresh_until,
            run_deadline,
            payload,
        );
        let ingress = domain
            .active_ingress(binding.binding_id())
            .unwrap_or_else(|| panic!("test binding must be active"));
        let offer = domain
            .try_offer(&ingress, input, reading(0))
            .unwrap_or_else(|failure| panic!("test offer failed: {}", failure.error()));
        assert!(matches!(offer.outcome(), EnqueueOutcome::Admitted));
        let dispatch = domain
            .try_dispatch(reading(0))
            .unwrap_or_else(|error| panic!("test dispatch failed: {error}"));
        let (outcome, expired) = dispatch.into_parts();
        assert!(expired.is_empty());
        let LoopDomainDispatchOutcome::Started(grant) = outcome else {
            panic!("test input must become in-flight");
        };
        (domain, grant)
    }

    fn domain_for(execution: MailboxExecutionSpec) -> LoopDomainCore {
        let binding = binding_record(execution.binding_id(), execution.mailbox());
        LoopDomainCore::try_new(
            domain_spec(),
            &[execution],
            &[binding],
            DomainEpoch::try_new(1)
                .unwrap_or_else(|error| panic!("test domain epoch must build: {error}")),
            CLOCK_DOMAIN,
            generation(),
        )
        .unwrap_or_else(|error| panic!("test domain must build: {error}"))
    }

    fn complete(domain: &mut LoopDomainCore, grant: Box<LoopDomainGrant>, reason: TerminalReason) {
        let mut release = domain
            .finish(*grant, reason)
            .unwrap_or_else(|failure| panic!("test finish failed: {}", failure.error()));
        domain
            .release(&mut release)
            .unwrap_or_else(|error| panic!("test permit release failed: {error}"));
    }

    #[tokio::test(start_paused = true)]
    async fn exact_signed_subject_runs_start_input_output_and_stop() {
        let count = Arc::new(AtomicUsize::new(0));
        let behavior = CardBehavior {
            emit_output: true,
            ..CardBehavior::default()
        };
        let execution = execution(OverrunAction::CooperativeCancel);
        let (mut domain, mut grant) = permitted(7, execution);
        let mut owner = owner_from_selected_for_domain(
            identity(),
            execution,
            &domain,
            selected(behavior, Arc::clone(&count)),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("test Card owner must build: {error}"));

        assert_eq!(owner.start(reading(0)).await, Ok(CardStartOutcome::Started));
        assert_eq!(owner.lifecycle(), CardLifecycle::Started);
        let outcome = owner
            .invoke(grant.as_mut(), reading(0))
            .await
            .unwrap_or_else(|error| panic!("test invocation failed: {error}"));
        assert_eq!(
            outcome,
            CardInvocationOutcome::Completed {
                output_discarded: true
            }
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(
            owner.invoke(grant.as_mut(), reading(0)).await,
            Err(CardCallbackError::DomainGrant(
                LoopDomainError::CallbackAlreadyClaimed
            ))
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        complete(&mut domain, grant, TerminalReason::Completed);
        assert_eq!(owner.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));
        assert_eq!(owner.lifecycle(), CardLifecycle::Stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn same_epoch_foreign_domain_grant_is_rejected_before_callback_construction() {
        let execution = execution(OverrunAction::CooperativeCancel);
        let count = Arc::new(AtomicUsize::new(0));
        let (mut old_domain, mut old_grant) = permitted(0x70, execution);
        let mut current_domain = domain_for(execution);
        assert_ne!(old_domain.owner_identity(), current_domain.owner_identity());
        let mut owner = owner_from_selected_for_domain(
            identity(),
            execution,
            &current_domain,
            selected(CardBehavior::default(), Arc::clone(&count)),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("current Card owner must build: {error}"));
        assert_eq!(owner.start(reading(0)).await, Ok(CardStartOutcome::Started));

        assert_eq!(
            owner.invoke(old_grant.as_mut(), reading(0)).await,
            Err(CardCallbackError::DomainGrant(
                LoopDomainError::GrantMismatch
            ))
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
        complete(&mut old_domain, old_grant, TerminalReason::Cancelled);
        assert_eq!(owner.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));
        current_domain
            .stop_accepting()
            .unwrap_or_else(|error| panic!("current domain stop failed: {error}"));
        assert!(
            current_domain
                .cancel_all_queued()
                .unwrap_or_else(|error| panic!("current domain cancel failed: {error}"))
                .is_empty()
        );
        assert!(
            current_domain
                .snapshot()
                .unwrap_or_else(|error| panic!("current domain snapshot failed: {error}"))
                .is_zero_cleanup()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn same_schema_multi_input_subject_preserves_signed_route_identity() {
        let first_binding = BindingId::from_bytes([0x61; 16]);
        let second_binding = BindingId::from_bytes([0x65; 16]);
        let first_mailbox = MAILBOX;
        let second_mailbox = MailboxRef::from_bytes([0x66; 16]);
        let first_port = PortRef::from_bytes([0x64; 16]);
        let second_port = PortRef::from_bytes([0x69; 16]);
        let first = execution_record(
            OverrunAction::CooperativeCancel,
            first_binding,
            first_mailbox,
            7_000_000,
        );
        let second = execution_record(
            OverrunAction::CooperativeCancel,
            second_binding,
            second_mailbox,
            7_000_000,
        );
        let assignments = [
            binding_record_with_target(first_binding, first_mailbox, first_port),
            binding_record_with_target(second_binding, second_mailbox, second_port),
        ];
        let mut domain = LoopDomainCore::try_new(
            domain_spec(),
            &[first, second],
            &assignments,
            DomainEpoch::try_new(1)
                .unwrap_or_else(|error| panic!("test domain epoch must build: {error}")),
            CLOCK_DOMAIN,
            generation(),
        )
        .unwrap_or_else(|error| panic!("multi-input domain must build: {error}"));
        let routes = Arc::new(Mutex::new(Vec::new()));
        let selected =
            TrustedCardImplementation::try_resolve_loop(&[first, second], || RouteRecordingCard {
                routes: Arc::clone(&routes),
            })
            .unwrap_or_else(|error| panic!("multi-input implementation must resolve: {error}"));
        let mut owner = CardCallbackOwner::try_new(
            identity(),
            domain_spec(),
            domain.owner_identity(),
            &[first, second],
            selected,
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("multi-input Card owner must build: {error}"));
        assert_eq!(owner.start(reading(0)).await, Ok(CardStartOutcome::Started));

        for (identity, assignment) in [(0x72, assignments[0]), (0x73, assignments[1])] {
            let deadline = reading(0)
                .try_deadline_after(bounded(100))
                .unwrap_or_else(|error| panic!("test deadline must build: {error}"));
            let payload = PayloadHandle::try_from_vec(vec![identity])
                .unwrap_or_else(|error| panic!("test payload must build: {error}"));
            let message = ValidatedMessage::new(
                MessageId::from_bytes([identity; 16]),
                schema(),
                InteractionKind::Signal,
                None,
                deadline,
                payload,
            );
            let ingress = domain
                .active_ingress(assignment.binding_id())
                .unwrap_or_else(|| panic!("multi-input route must be active"));
            let offer = domain
                .try_offer(&ingress, message, reading(0))
                .unwrap_or_else(|failure| panic!("route offer failed: {}", failure.error()));
            assert!(matches!(offer.outcome(), EnqueueOutcome::Admitted));
        }

        for _ in 0..2 {
            let report = domain
                .try_dispatch(reading(0))
                .unwrap_or_else(|error| panic!("multi-input dispatch failed: {error}"));
            let (outcome, terminals) = report.into_parts();
            assert!(terminals.is_empty());
            let LoopDomainDispatchOutcome::Started(mut grant) = outcome else {
                panic!("multi-input dispatch must start");
            };
            assert_eq!(
                owner.invoke(grant.as_mut(), reading(0)).await,
                Ok(CardInvocationOutcome::Completed {
                    output_discarded: false
                })
            );
            complete(&mut domain, grant, TerminalReason::Completed);
        }

        {
            let observed = routes
                .lock()
                .unwrap_or_else(|_| panic!("route observation lock must remain usable"));
            assert_eq!(observed.len(), 2);
            assert!(observed.contains(&(first_binding, first_mailbox, first_port)));
            assert!(observed.contains(&(second_binding, second_mailbox, second_port)));
        }
        assert_eq!(owner.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));
        domain
            .stop_accepting()
            .unwrap_or_else(|error| panic!("multi-input domain stop failed: {error}"));
        assert!(
            domain
                .cancel_all_queued()
                .unwrap_or_else(|error| panic!("multi-input cancel failed: {error}"))
                .is_empty()
        );
        assert!(
            domain
                .snapshot()
                .unwrap_or_else(|error| panic!("multi-input snapshot failed: {error}"))
                .is_zero_cleanup()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_is_cooperative_or_escalating_without_a_late_future() {
        for (action, expected, lifecycle) in [
            (
                OverrunAction::CooperativeCancel,
                CardInvocationOutcome::TimedOutCooperative,
                CardLifecycle::Started,
            ),
            (
                OverrunAction::Escalate,
                CardInvocationOutcome::TimedOutEscalated,
                CardLifecycle::Poisoned,
            ),
        ] {
            let count = Arc::new(AtomicUsize::new(0));
            let behavior = CardBehavior {
                input_delay: Duration::from_millis(10),
                ..CardBehavior::default()
            };
            let execution = execution(action);
            let (mut domain, mut grant) = permitted(action as u8, execution);
            let mut owner = owner_from_selected_for_domain(
                identity(),
                execution,
                &domain,
                selected(behavior, Arc::clone(&count)),
                &CancellationSource::root(),
            )
            .unwrap_or_else(|error| panic!("test Card owner must build: {error}"));
            assert_eq!(owner.start(reading(0)).await, Ok(CardStartOutcome::Started));
            let invocation_started = tokio::time::Instant::now();
            let outcome = owner
                .invoke(grant.as_mut(), reading(0))
                .await
                .unwrap_or_else(|error| panic!("test invocation failed: {error}"));
            assert_eq!(outcome, expected);
            assert_eq!(invocation_started.elapsed(), Duration::from_millis(10));
            assert_eq!(owner.lifecycle(), lifecycle);
            assert_eq!(count.load(Ordering::SeqCst), 1);
            complete(&mut domain, grant, TerminalReason::Cancelled);
            assert!(matches!(
                owner.stop(reading(0)).await,
                Ok(CardStopOutcome::Stopped)
            ));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn invocation_cleanup_budget_bounds_post_overrun_cooperation() {
        let execution = execution_record(
            OverrunAction::CooperativeCancel,
            BindingId::from_bytes([0x67; 16]),
            MailboxRef::from_bytes([0x68; 16]),
            3_000_000,
        );
        let count = Arc::new(AtomicUsize::new(0));
        let (mut domain, mut grant) = permitted(0x71, execution);
        let mut owner = owner_from_selected_for_domain(
            identity(),
            execution,
            &domain,
            selected(
                CardBehavior {
                    input_delay: Duration::from_millis(50),
                    ..CardBehavior::default()
                },
                Arc::clone(&count),
            ),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("cleanup-budget owner must build: {error}"));
        assert_eq!(owner.start(reading(0)).await, Ok(CardStartOutcome::Started));

        let started = tokio::time::Instant::now();
        assert_eq!(
            owner.invoke(grant.as_mut(), reading(0)).await,
            Ok(CardInvocationOutcome::TimedOutCooperative)
        );
        assert_eq!(started.elapsed(), Duration::from_millis(8));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        complete(&mut domain, grant, TerminalReason::Cancelled);
        assert_eq!(owner.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));
    }

    #[tokio::test(start_paused = true)]
    async fn startup_failure_and_timeout_never_become_started_or_ready() {
        for (behavior, expected) in [
            (
                CardBehavior {
                    fail_start: true,
                    ..CardBehavior::default()
                },
                CardStartOutcome::Failed(CallbackFailure::Failed),
            ),
            (
                CardBehavior {
                    start_delay: Duration::from_millis(10),
                    ..CardBehavior::default()
                },
                CardStartOutcome::TimedOut,
            ),
        ] {
            let execution = execution(OverrunAction::CooperativeCancel);
            let mut owner = owner_from_selected(
                identity(),
                execution,
                selected(behavior, Arc::new(AtomicUsize::new(0))),
                &CancellationSource::root(),
            )
            .unwrap_or_else(|error| panic!("test Card owner must build: {error}"));
            assert_eq!(owner.start(reading(0)).await, Ok(expected));
            assert_eq!(owner.lifecycle(), CardLifecycle::StartFailed);
            assert_eq!(owner.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn callback_panics_remain_owned_and_release_the_invocation_grant() {
        let execution = execution(OverrunAction::CooperativeCancel);

        let mut start_panic = owner_from_selected(
            identity(),
            execution,
            selected(
                CardBehavior {
                    panic_start: true,
                    ..CardBehavior::default()
                },
                Arc::new(AtomicUsize::new(0)),
            ),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("start panic owner must build: {error}"));
        assert_eq!(
            start_panic.start(reading(0)).await,
            Ok(CardStartOutcome::Panicked)
        );
        assert_eq!(start_panic.lifecycle(), CardLifecycle::Poisoned);
        assert_eq!(
            start_panic.stop(reading(0)).await,
            Ok(CardStopOutcome::Stopped)
        );

        let (mut domain, mut grant) = permitted(0x6b, execution);
        let mut input_panic = owner_from_selected_for_domain(
            identity(),
            execution,
            &domain,
            selected(
                CardBehavior {
                    panic_input: true,
                    ..CardBehavior::default()
                },
                Arc::new(AtomicUsize::new(0)),
            ),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("input panic owner must build: {error}"));
        assert_eq!(
            input_panic.start(reading(0)).await,
            Ok(CardStartOutcome::Started)
        );
        let outcome = input_panic
            .invoke(grant.as_mut(), reading(0))
            .await
            .unwrap_or_else(|error| panic!("panic invocation failed: {error}"));
        assert_eq!(outcome, CardInvocationOutcome::Panicked);
        assert_eq!(input_panic.lifecycle(), CardLifecycle::Poisoned);
        complete(&mut domain, grant, TerminalReason::Failed);
        assert_eq!(
            input_panic.stop(reading(0)).await,
            Ok(CardStopOutcome::Stopped)
        );

        let mut stop_panic = owner_from_selected(
            identity(),
            execution,
            selected(
                CardBehavior {
                    panic_stop: true,
                    ..CardBehavior::default()
                },
                Arc::new(AtomicUsize::new(0)),
            ),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("stop panic owner must build: {error}"));
        assert_eq!(
            stop_panic.start(reading(0)).await,
            Ok(CardStartOutcome::Started)
        );
        assert_eq!(
            stop_panic.stop(reading(0)).await,
            Ok(CardStopOutcome::Panicked)
        );
        assert_eq!(stop_panic.lifecycle(), CardLifecycle::Poisoned);
    }

    #[tokio::test(start_paused = true)]
    async fn synchronous_callback_construction_panics_are_contained() {
        let execution = execution(OverrunAction::CooperativeCancel);
        let root = CancellationSource::root();

        let mut start = owner_from_selected(
            identity(),
            execution,
            selected(
                CardBehavior {
                    panic_start_constructor: true,
                    ..CardBehavior::default()
                },
                Arc::new(AtomicUsize::new(0)),
            ),
            &root,
        )
        .unwrap_or_else(|error| panic!("start constructor owner must build: {error}"));
        assert_eq!(
            start.start(reading(0)).await,
            Ok(CardStartOutcome::Panicked)
        );
        assert_eq!(start.lifecycle(), CardLifecycle::Poisoned);

        let (mut domain, mut grant) = permitted(0x6c, execution);
        let mut input = owner_from_selected_for_domain(
            identity(),
            execution,
            &domain,
            selected(
                CardBehavior {
                    panic_input_constructor: true,
                    ..CardBehavior::default()
                },
                Arc::new(AtomicUsize::new(0)),
            ),
            &root,
        )
        .unwrap_or_else(|error| panic!("input constructor owner must build: {error}"));
        assert_eq!(input.start(reading(0)).await, Ok(CardStartOutcome::Started));
        let outcome = input
            .invoke(grant.as_mut(), reading(0))
            .await
            .unwrap_or_else(|error| panic!("input constructor invocation failed: {error}"));
        assert_eq!(outcome, CardInvocationOutcome::Panicked);
        complete(&mut domain, grant, TerminalReason::Failed);
        assert_eq!(input.lifecycle(), CardLifecycle::Poisoned);

        let mut stop = owner_from_selected(
            identity(),
            execution,
            selected(
                CardBehavior {
                    panic_stop_constructor: true,
                    ..CardBehavior::default()
                },
                Arc::new(AtomicUsize::new(0)),
            ),
            &root,
        )
        .unwrap_or_else(|error| panic!("stop constructor owner must build: {error}"));
        assert_eq!(stop.start(reading(0)).await, Ok(CardStartOutcome::Started));
        assert_eq!(stop.stop(reading(0)).await, Ok(CardStopOutcome::Panicked));
        assert_eq!(stop.lifecycle(), CardLifecycle::Poisoned);
    }

    #[tokio::test(start_paused = true)]
    async fn callback_future_destructor_panic_is_contained_before_grant_release() {
        let execution = execution(OverrunAction::CooperativeCancel);
        let (mut domain, mut grant) = permitted(0x6d, execution);
        let mut owner = owner_from_selected_for_domain(
            identity(),
            execution,
            &domain,
            selected(
                CardBehavior {
                    panic_input_destructor: true,
                    ..CardBehavior::default()
                },
                Arc::new(AtomicUsize::new(0)),
            ),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("destructor panic owner must build: {error}"));
        assert_eq!(owner.start(reading(0)).await, Ok(CardStartOutcome::Started));
        assert_eq!(
            owner.invoke(grant.as_mut(), reading(0)).await,
            Ok(CardInvocationOutcome::Panicked)
        );
        assert_eq!(owner.lifecycle(), CardLifecycle::Poisoned);
        complete(&mut domain, grant, TerminalReason::Failed);
        assert_eq!(owner.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));
    }

    #[tokio::test(start_paused = true)]
    async fn signed_domain_cleanup_budget_times_out_final_stop() {
        let execution = execution(OverrunAction::CooperativeCancel);
        let mut owner = owner_from_selected(
            identity(),
            execution,
            selected(
                CardBehavior {
                    stop_delay: Duration::from_millis(10),
                    ..CardBehavior::default()
                },
                Arc::new(AtomicUsize::new(0)),
            ),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("cleanup timeout owner must build: {error}"));
        assert_eq!(owner.start(reading(0)).await, Ok(CardStartOutcome::Started));
        assert_eq!(owner.stop(reading(0)).await, Ok(CardStopOutcome::TimedOut));
        assert_eq!(owner.lifecycle(), CardLifecycle::Poisoned);
    }

    #[tokio::test(start_paused = true)]
    async fn invocation_cleanup_budgets_do_not_shorten_final_card_cleanup() {
        let first = execution_record(
            OverrunAction::CooperativeCancel,
            BindingId::from_bytes([0x61; 16]),
            MAILBOX,
            7_000_000,
        );
        let second = execution_record(
            OverrunAction::CooperativeCancel,
            BindingId::from_bytes([0x62; 16]),
            MailboxRef::from_bytes([0x63; 16]),
            3_000_000,
        );
        let domain = domain_for(first);
        let mut owner = CardCallbackOwner::try_new(
            identity(),
            domain_spec(),
            domain.owner_identity(),
            &[first, second],
            selected(
                CardBehavior {
                    stop_delay: Duration::from_millis(5),
                    ..CardBehavior::default()
                },
                Arc::new(AtomicUsize::new(0)),
            ),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("multi-execution owner must build: {error}"));
        assert_eq!(owner.start(reading(0)).await, Ok(CardStartOutcome::Started));
        assert_eq!(owner.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));
        assert_eq!(owner.lifecycle(), CardLifecycle::Stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn inherited_root_cancellation_constructs_no_new_callback_future() {
        let execution = execution(OverrunAction::CooperativeCancel);
        let cancelled_parent = CancellationSource::root();
        cancelled_parent.cancel();
        let mut cancelled_start = owner_from_selected(
            identity(),
            execution,
            selected(CardBehavior::default(), Arc::new(AtomicUsize::new(0))),
            &cancelled_parent,
        )
        .unwrap_or_else(|error| panic!("test Card owner must build: {error}"));
        assert_eq!(
            cancelled_start.start(reading(0)).await,
            Ok(CardStartOutcome::Cancelled)
        );
        assert_eq!(cancelled_start.lifecycle(), CardLifecycle::StartFailed);

        let parent = CancellationSource::root();
        let count = Arc::new(AtomicUsize::new(0));
        let (mut domain, mut grant) = permitted(0x7a, execution);
        let mut owner = owner_from_selected_for_domain(
            identity(),
            execution,
            &domain,
            selected(CardBehavior::default(), Arc::clone(&count)),
            &parent,
        )
        .unwrap_or_else(|error| panic!("test Card owner must build: {error}"));
        assert_eq!(owner.start(reading(0)).await, Ok(CardStartOutcome::Started));
        parent.cancel();
        let outcome = owner
            .invoke(grant.as_mut(), reading(0))
            .await
            .unwrap_or_else(|error| panic!("cancelled invocation failed: {error}"));
        assert_eq!(outcome, CardInvocationOutcome::CancelledBeforeRun);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        complete(&mut domain, grant, TerminalReason::Cancelled);
        assert_eq!(owner.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));
    }

    #[tokio::test(start_paused = true)]
    async fn callback_start_rechecks_clock_deadline_and_freshness_before_construction() {
        let execution = execution(OverrunAction::CooperativeCancel);
        let count = Arc::new(AtomicUsize::new(0));

        let (mut deadline_domain, mut deadline_grant) =
            permitted_with_deadlines(0x7b, execution, 200, 100);
        let mut deadline_owner = owner_from_selected_for_domain(
            identity(),
            execution,
            &deadline_domain,
            selected(CardBehavior::default(), Arc::clone(&count)),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("pre-run owner must build: {error}"));
        assert_eq!(
            deadline_owner.start(reading(0)).await,
            Ok(CardStartOutcome::Started)
        );
        assert_eq!(
            deadline_owner
                .invoke(deadline_grant.as_mut(), reading(100))
                .await,
            Ok(CardInvocationOutcome::NotRun(
                TerminalReason::RunDeadlineExpired
            ))
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
        complete(
            &mut deadline_domain,
            deadline_grant,
            TerminalReason::RunDeadlineExpired,
        );
        assert_eq!(
            deadline_owner.stop(reading(0)).await,
            Ok(CardStopOutcome::Stopped)
        );

        let (mut stale_domain, mut stale_grant) =
            permitted_with_deadlines(0x7c, execution, 100, 200);
        let mut stale_owner = owner_from_selected_for_domain(
            identity(),
            execution,
            &stale_domain,
            selected(CardBehavior::default(), Arc::clone(&count)),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("stale owner must build: {error}"));
        assert_eq!(
            stale_owner.start(reading(0)).await,
            Ok(CardStartOutcome::Started)
        );
        assert_eq!(
            stale_owner.invoke(stale_grant.as_mut(), reading(100)).await,
            Ok(CardInvocationOutcome::NotRun(
                TerminalReason::StaleBeforeRun
            ))
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
        complete(
            &mut stale_domain,
            stale_grant,
            TerminalReason::StaleBeforeRun,
        );
        assert_eq!(
            stale_owner.stop(reading(0)).await,
            Ok(CardStopOutcome::Stopped)
        );

        let (mut mismatch_domain, mut mismatch_grant) = permitted(0x7d, execution);
        let mut mismatch_owner = owner_from_selected_for_domain(
            identity(),
            execution,
            &mismatch_domain,
            selected(CardBehavior::default(), Arc::clone(&count)),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("clock mismatch owner must build: {error}"));
        assert_eq!(
            mismatch_owner.start(reading(0)).await,
            Ok(CardStartOutcome::Started)
        );
        let wrong_clock = ClockReading::new(
            ClockDomainRef::from_bytes([0xff; 16]),
            generation(),
            MonotonicInstant::from_ticks(0),
        );
        assert_eq!(
            mismatch_owner
                .invoke(mismatch_grant.as_mut(), wrong_clock)
                .await,
            Err(CardCallbackError::DomainGrant(
                crate::loop_domain::LoopDomainError::ClockDomainMismatch
            ))
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
        complete(
            &mut mismatch_domain,
            mismatch_grant,
            TerminalReason::Cancelled,
        );
        assert_eq!(
            mismatch_owner.stop(reading(0)).await,
            Ok(CardStopOutcome::Stopped)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unregistered_real_domain_grant_constructs_no_callback_and_remains_recoverable() {
        let registered = execution(OverrunAction::CooperativeCancel);
        let unregistered = execution_record(
            OverrunAction::CooperativeCancel,
            BindingId::from_bytes([0x65; 16]),
            MailboxRef::from_bytes([0x66; 16]),
            7_000_000,
        );
        let count = Arc::new(AtomicUsize::new(0));
        let mut owner = owner_from_selected(
            identity(),
            registered,
            selected(CardBehavior::default(), Arc::clone(&count)),
            &CancellationSource::root(),
        )
        .unwrap_or_else(|error| panic!("registered owner must build: {error}"));
        assert_eq!(owner.start(reading(0)).await, Ok(CardStartOutcome::Started));
        let (mut foreign_domain, mut foreign_grant) = permitted(0x7e, unregistered);
        assert_eq!(
            owner.invoke(foreign_grant.as_mut(), reading(0)).await,
            Err(CardCallbackError::ExecutionNotRegistered)
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
        complete(
            &mut foreign_domain,
            foreign_grant,
            TerminalReason::Cancelled,
        );
        assert_eq!(owner.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_callback_cannot_emit_late_output_and_stop_recovers_its_fence() {
        let execution = execution(OverrunAction::CooperativeCancel);
        let behavior = CardBehavior {
            input_delay: Duration::from_millis(10),
            emit_output: true,
            ..CardBehavior::default()
        };
        let root = CancellationSource::root();
        let (mut domain, mut grant) = permitted(0x6a, execution);
        let mut old = owner_from_selected_for_domain(
            identity_generation(1),
            execution,
            &domain,
            selected(behavior, Arc::new(AtomicUsize::new(0))),
            &root,
        )
        .unwrap_or_else(|error| panic!("old Card owner must build: {error}"));
        assert_eq!(old.start(reading(0)).await, Ok(CardStartOutcome::Started));
        let mut invocation = Box::pin(old.invoke(grant.as_mut(), reading(0)));
        let pending =
            poll_fn(|context| Poll::Ready(invocation.as_mut().poll(context).is_pending())).await;
        assert!(pending);
        drop(invocation);
        complete(&mut domain, grant, TerminalReason::Uncertain);
        assert_eq!(old.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));

        let mut current = owner_from_selected(
            identity_generation(2),
            execution,
            selected(CardBehavior::default(), Arc::new(AtomicUsize::new(0))),
            &root,
        )
        .unwrap_or_else(|error| panic!("current Card owner must build: {error}"));
        assert_eq!(
            current.start(reading(0)).await,
            Ok(CardStartOutcome::Started)
        );
        tokio::time::advance(Duration::from_millis(20)).await;
        assert_eq!(current.stop(reading(0)).await, Ok(CardStopOutcome::Stopped));
    }

    #[test]
    fn ineligible_loop_profiles_never_construct_the_implementation_object() {
        let cases = [
            (
                CallModel::Synchronous,
                WorkloadKind::Io,
                BlockingRisk::None,
                RunBoundProvenance::Measured,
            ),
            (
                CallModel::CooperativeAsync,
                WorkloadKind::Cpu,
                BlockingRisk::None,
                RunBoundProvenance::Measured,
            ),
            (
                CallModel::CooperativeAsync,
                WorkloadKind::Native,
                BlockingRisk::Unknown,
                RunBoundProvenance::Unknown,
            ),
        ];
        for (call_model, workload_kind, blocking_risk, provenance) in cases {
            let execution = execution_record_with_profile(
                OverrunAction::CooperativeCancel,
                BindingId::from_bytes([0x61; 16]),
                MAILBOX,
                7_000_000,
                TestLoopProfile {
                    call_model,
                    workload_kind,
                    blocking_risk,
                    run_bound_provenance: provenance,
                },
            );
            let construction_count = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&construction_count);
            let result = TrustedCardImplementation::try_resolve_loop(&[execution], move || {
                observed.fetch_add(1, Ordering::SeqCst);
                TestCard {
                    behavior: CardBehavior::default(),
                    callback_count: Arc::new(AtomicUsize::new(0)),
                }
            });
            assert!(matches!(
                result,
                Err(CardCallbackError::LoopImplementationIneligible)
            ));
            assert_eq!(construction_count.load(Ordering::SeqCst), 0);
        }

        let unsafe_overrun = execution_record(
            OverrunAction::Continue,
            BindingId::from_bytes([0x61; 16]),
            MAILBOX,
            7_000_000,
        );
        let construction_count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&construction_count);
        let result = TrustedCardImplementation::try_resolve_loop(&[unsafe_overrun], move || {
            observed.fetch_add(1, Ordering::SeqCst);
            TestCard {
                behavior: CardBehavior::default(),
                callback_count: Arc::new(AtomicUsize::new(0)),
            }
        });
        assert!(matches!(
            result,
            Err(CardCallbackError::UnsupportedLoopOverrunAction)
        ));
        assert_eq!(construction_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mismatched_static_artifact_identity_never_constructs_the_implementation_object() {
        let execution = execution(OverrunAction::CooperativeCancel);
        let construction_count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&construction_count);
        let result = TrustedCardImplementation::try_resolve_loop(&[execution], move || {
            observed.fetch_add(1, Ordering::SeqCst);
            WrongArtifactCard
        });

        assert!(matches!(
            result,
            Err(CardCallbackError::ImplementationMismatch)
        ));
        assert_eq!(construction_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn trusted_selection_and_per_mailbox_subject_checks_fail_closed() {
        let execution = execution(OverrunAction::CooperativeCancel);
        let wrong = TrustedCardImplementation::new_unchecked_for_test(
            DEFINITION,
            IMPLEMENTATION,
            DEFINITION_DIGEST,
            Digest32::from_bytes([0xff; 32]),
            Box::new(TestCard {
                behavior: CardBehavior::default(),
                callback_count: Arc::new(AtomicUsize::new(0)),
            }),
        );
        assert!(matches!(
            owner_from_selected(identity(), execution, wrong, &CancellationSource::root()),
            Err(CardCallbackError::ImplementationMismatch)
        ));

        let other_identity = CardInstanceIdentity::new(
            RuntimeHostId::from_bytes([0x51; 16]),
            RuntimeHostEpoch::try_new(1)
                .unwrap_or_else(|error| panic!("test epoch must build: {error}")),
            InstanceRef::from_bytes([0xfe; 16]),
            SourcePlanRevision::new(7),
            TargetSliceDigest::new(Digest32::from_bytes([0x52; 32])),
            DomainEpoch::try_new(1)
                .unwrap_or_else(|error| panic!("test epoch must build: {error}")),
            InstanceGeneration::try_new(1)
                .unwrap_or_else(|error| panic!("test generation must build: {error}")),
        );
        assert!(matches!(
            owner_from_selected(
                other_identity,
                execution,
                selected(CardBehavior::default(), Arc::new(AtomicUsize::new(0))),
                &CancellationSource::root()
            ),
            Err(CardCallbackError::InstanceMismatch)
        ));
    }

    #[test]
    fn internal_epoch_zero_remains_rejected() {
        assert_eq!(
            RuntimeHostEpoch::try_new(0),
            Err(CardInstanceError::InvalidEpoch)
        );
    }
}
