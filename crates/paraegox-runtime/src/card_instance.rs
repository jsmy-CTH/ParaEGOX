//! RuntimeHost-owned CardInstance identity, callback seam, and generation fence.

use core::fmt;
use core::future::Future;
use core::num::NonZeroU64;
use core::pin::Pin;
use std::collections::BTreeSet;

use paraegox_kernel::digest::Digest32;
use paraegox_kernel::identity::RuntimeHostId;
use paraegox_kernel::time::{ClockReading, MonotonicDeadline};
use paraegox_runtime_contracts::assignment::{
    BindingId, InstanceRef, MailboxRef, PortRef, SchemaRef,
};
use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};

use crate::mailbox::{MessageId, ValidatedMessage};
use crate::task_registry::CancellationView;

/// Maximum one-shot callback output retained by an invocation task.
const MAX_OUTPUT_PROPOSAL_BYTES: usize = 1024 * 1024;

macro_rules! local_epoch {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub(crate) struct $name(NonZeroU64);

        impl $name {
            pub(crate) fn try_new(value: u64) -> Result<Self, CardInstanceError> {
                NonZeroU64::new(value)
                    .map(Self)
                    .ok_or(CardInstanceError::InvalidEpoch)
            }

            #[must_use]
            pub(crate) const fn value(self) -> u64 {
                self.0.get()
            }

            pub(crate) fn try_next(self) -> Result<Self, CardInstanceError> {
                self.0
                    .get()
                    .checked_add(1)
                    .and_then(NonZeroU64::new)
                    .map(Self)
                    .ok_or(CardInstanceError::EpochExhausted)
            }
        }
    };
}

local_epoch!(
    RuntimeHostEpoch,
    "One RuntimeHost process-incarnation epoch."
);
local_epoch!(DomainEpoch, "One RuntimeHost-owned LoopDomain generation.");
local_epoch!(
    InstanceGeneration,
    "One generation of a planned Card instance."
);
local_epoch!(
    InvocationId,
    "One invocation identity within a Card generation."
);

/// Runtime-owned identity assembled from authenticated plan and live epochs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CardInstanceIdentity {
    runtime_host: RuntimeHostId,
    runtime_host_epoch: RuntimeHostEpoch,
    planned_instance: InstanceRef,
    source_revision: SourcePlanRevision,
    target_slice_digest: TargetSliceDigest,
    domain_epoch: DomainEpoch,
    generation: InstanceGeneration,
}

impl CardInstanceIdentity {
    #[must_use]
    pub(crate) const fn new(
        runtime_host: RuntimeHostId,
        runtime_host_epoch: RuntimeHostEpoch,
        planned_instance: InstanceRef,
        source_revision: SourcePlanRevision,
        target_slice_digest: TargetSliceDigest,
        domain_epoch: DomainEpoch,
        generation: InstanceGeneration,
    ) -> Self {
        Self {
            runtime_host,
            runtime_host_epoch,
            planned_instance,
            source_revision,
            target_slice_digest,
            domain_epoch,
            generation,
        }
    }

    #[must_use]
    pub(crate) const fn planned_instance(self) -> InstanceRef {
        self.planned_instance
    }

    #[must_use]
    pub(crate) const fn source_revision(self) -> SourcePlanRevision {
        self.source_revision
    }

    #[must_use]
    pub(crate) const fn target_slice_digest(self) -> TargetSliceDigest {
        self.target_slice_digest
    }

    #[must_use]
    pub(crate) const fn domain_epoch(self) -> DomainEpoch {
        self.domain_epoch
    }

    #[must_use]
    pub(crate) const fn generation(self) -> InstanceGeneration {
        self.generation
    }
}

/// Card implementation lifecycle observed by its RuntimeHost owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CardLifecycle {
    Created,
    Starting,
    Started,
    StartFailed,
    Draining,
    Stopping,
    Stopped,
    Poisoned,
}

/// A boxed borrowing future keeps implementation details internal without an
/// async-trait dependency or a public Rust plugin ABI.
pub(crate) type CardFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trusted, same-build in-process implementation callback seam.
pub(crate) trait CardImplementation: Send {
    fn on_start<'a>(
        &'a mut self,
        context: &'a CardContext,
    ) -> CardFuture<'a, Result<(), CallbackFailure>>;

    fn on_input<'a>(
        &'a mut self,
        context: &'a CardContext,
        input: InputView<'a>,
    ) -> CardFuture<'a, Result<Option<OutputProposal>, CallbackFailure>>;

    fn on_stop<'a>(
        &'a mut self,
        context: &'a CardContext,
    ) -> CardFuture<'a, Result<(), CallbackFailure>>;
}

/// Narrow callback context. It deliberately contains no Runtime, Tokio,
/// PortBinding, Fabric, thread, process, or lifecycle mutation handle.
#[derive(Clone, Debug)]
pub(crate) struct CardContext {
    identity: CardInstanceIdentity,
    reading: ClockReading,
    cancellation: CancellationView,
    definition_digest: Digest32,
    artifact_digest: Digest32,
    config_digest: Digest32,
}

impl CardContext {
    #[must_use]
    pub(crate) const fn new(
        identity: CardInstanceIdentity,
        reading: ClockReading,
        cancellation: CancellationView,
        definition_digest: Digest32,
        artifact_digest: Digest32,
        config_digest: Digest32,
    ) -> Self {
        Self {
            identity,
            reading,
            cancellation,
            definition_digest,
            artifact_digest,
            config_digest,
        }
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> CardInstanceIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn reading(&self) -> ClockReading {
        self.reading
    }

    #[must_use]
    pub(crate) const fn cancellation(&self) -> &CancellationView {
        &self.cancellation
    }

    #[must_use]
    pub(crate) const fn definition_digest(&self) -> &Digest32 {
        &self.definition_digest
    }

    #[must_use]
    pub(crate) const fn artifact_digest(&self) -> &Digest32 {
        &self.artifact_digest
    }

    #[must_use]
    pub(crate) const fn config_digest(&self) -> &Digest32 {
        &self.config_digest
    }
}

/// Borrowed immutable view of the sole Mailbox-owned input payload.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InputView<'a> {
    binding: BindingId,
    mailbox: MailboxRef,
    target_port: PortRef,
    message_id: MessageId,
    schema: SchemaRef,
    payload: &'a [u8],
    run_deadline: MonotonicDeadline,
    fresh_until: MonotonicDeadline,
}

impl<'a> InputView<'a> {
    #[must_use]
    pub(crate) fn from_message(
        binding: BindingId,
        mailbox: MailboxRef,
        target_port: PortRef,
        message: &'a ValidatedMessage,
    ) -> Self {
        Self {
            binding,
            mailbox,
            target_port,
            message_id: message.id(),
            schema: message.schema(),
            payload: message.payload().as_bytes(),
            run_deadline: message.deadline(),
            fresh_until: message.fresh_until(),
        }
    }

    #[must_use]
    pub(crate) const fn binding(self) -> BindingId {
        self.binding
    }

    #[must_use]
    pub(crate) const fn mailbox(self) -> MailboxRef {
        self.mailbox
    }

    #[must_use]
    pub(crate) const fn target_port(self) -> PortRef {
        self.target_port
    }

    #[must_use]
    pub(crate) const fn message_id(self) -> MessageId {
        self.message_id
    }

    #[must_use]
    pub(crate) const fn schema(self) -> SchemaRef {
        self.schema
    }

    #[must_use]
    pub(crate) const fn payload(self) -> &'a [u8] {
        self.payload
    }

    #[must_use]
    pub(crate) const fn run_deadline(self) -> MonotonicDeadline {
        self.run_deadline
    }

    #[must_use]
    pub(crate) const fn fresh_until(self) -> MonotonicDeadline {
        self.fresh_until
    }
}

/// One bounded output value returned directly to the owning invocation task.
/// It is not a queue and cannot outlive the task without Runtime fencing.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OutputProposal {
    port: PortRef,
    schema: SchemaRef,
    payload: Box<[u8]>,
}

impl OutputProposal {
    pub(crate) fn try_new(
        port: PortRef,
        schema: SchemaRef,
        payload: Vec<u8>,
        assigned_maximum: u64,
    ) -> Result<Self, CardInstanceError> {
        let length = u64::try_from(payload.len()).map_err(|_| CardInstanceError::OutputTooLarge)?;
        let effective_maximum = assigned_maximum.min(MAX_OUTPUT_PROPOSAL_BYTES as u64);
        if length > effective_maximum {
            return Err(CardInstanceError::OutputTooLarge);
        }
        Ok(Self {
            port,
            schema,
            payload: payload.into_boxed_slice(),
        })
    }

    #[must_use]
    pub(crate) const fn port(&self) -> PortRef {
        self.port
    }

    #[must_use]
    pub(crate) const fn schema(&self) -> SchemaRef {
        self.schema
    }

    #[must_use]
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Implementation-provided failure is diagnostic input, not lifecycle truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CallbackFailure {
    Rejected,
    Failed,
}

/// Copy-only completion credential with no payload ownership.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct InvocationFence {
    runtime_host: RuntimeHostId,
    runtime_host_epoch: RuntimeHostEpoch,
    domain_epoch: DomainEpoch,
    planned_instance: InstanceRef,
    generation: InstanceGeneration,
    invocation: InvocationId,
    source_revision: SourcePlanRevision,
    target_slice_digest: TargetSliceDigest,
}

impl InvocationFence {
    #[must_use]
    pub(crate) const fn invocation(self) -> InvocationId {
        self.invocation
    }
}

/// The only owner allowed to advance one Card implementation lifecycle.
pub(crate) struct CardInstanceOwner {
    identity: CardInstanceIdentity,
    lifecycle: CardLifecycle,
    implementation: Box<dyn CardImplementation>,
    next_invocation: u64,
    active_invocations: BTreeSet<InvocationId>,
}

impl CardInstanceOwner {
    #[must_use]
    pub(crate) fn new(
        identity: CardInstanceIdentity,
        implementation: Box<dyn CardImplementation>,
    ) -> Self {
        Self {
            identity,
            lifecycle: CardLifecycle::Created,
            implementation,
            next_invocation: 0,
            active_invocations: BTreeSet::new(),
        }
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> CardInstanceIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn lifecycle(&self) -> CardLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub(crate) fn implementation_mut(&mut self) -> &mut dyn CardImplementation {
        &mut *self.implementation
    }

    pub(crate) fn begin_start(&mut self) -> Result<(), CardInstanceError> {
        self.transition(CardLifecycle::Created, CardLifecycle::Starting)
    }

    pub(crate) fn finish_start(&mut self, succeeded: bool) -> Result<(), CardInstanceError> {
        self.transition(
            CardLifecycle::Starting,
            if succeeded {
                CardLifecycle::Started
            } else {
                CardLifecycle::StartFailed
            },
        )
    }

    pub(crate) fn begin_invocation(&mut self) -> Result<InvocationFence, CardInstanceError> {
        if self.lifecycle != CardLifecycle::Started {
            return Err(CardInstanceError::InvalidLifecycleTransition);
        }
        let value = self
            .next_invocation
            .checked_add(1)
            .ok_or(CardInstanceError::InvocationExhausted)?;
        let invocation = InvocationId::try_new(value)?;
        if !self.active_invocations.insert(invocation) {
            return Err(CardInstanceError::InvocationAlreadyActive);
        }
        self.next_invocation = value;
        Ok(self.fence(invocation))
    }

    pub(crate) fn validate_completion(
        &self,
        fence: InvocationFence,
    ) -> Result<(), CardInstanceError> {
        if fence != self.fence(fence.invocation) {
            return Err(CardInstanceError::StaleCompletionFence);
        }
        if !self.active_invocations.contains(&fence.invocation) {
            return Err(CardInstanceError::InvocationNotActive);
        }
        Ok(())
    }

    /// Revalidates the invocation fence at the exact synchronous output
    /// observation boundary.
    ///
    /// S4 has no production output route, so the component owner currently
    /// supplies only a discard observer. Keeping the observer borrowing makes
    /// this neither a payload queue nor a new output owner. A later binding
    /// adapter must cross this same gate before it can copy or encode output.
    pub(crate) fn observe_output<F>(
        &self,
        fence: InvocationFence,
        proposal: &OutputProposal,
        observe: F,
    ) -> Result<(), CardInstanceError>
    where
        F: FnOnce(&OutputProposal),
    {
        self.validate_completion(fence)?;
        observe(proposal);
        Ok(())
    }

    pub(crate) fn finish_invocation(
        &mut self,
        fence: InvocationFence,
    ) -> Result<(), CardInstanceError> {
        self.validate_completion(fence)?;
        self.active_invocations.remove(&fence.invocation);
        Ok(())
    }

    pub(crate) fn begin_draining(&mut self) -> Result<(), CardInstanceError> {
        match self.lifecycle {
            CardLifecycle::Started | CardLifecycle::StartFailed | CardLifecycle::Poisoned => {
                self.lifecycle = CardLifecycle::Draining;
                Ok(())
            }
            CardLifecycle::Draining => Ok(()),
            _ => Err(CardInstanceError::InvalidLifecycleTransition),
        }
    }

    pub(crate) fn begin_stop(&mut self) -> Result<(), CardInstanceError> {
        if !self.active_invocations.is_empty() {
            return Err(CardInstanceError::InvocationsStillActive);
        }
        self.transition(CardLifecycle::Draining, CardLifecycle::Stopping)
    }

    pub(crate) fn finish_stop(&mut self) -> Result<(), CardInstanceError> {
        self.transition(CardLifecycle::Stopping, CardLifecycle::Stopped)
    }

    pub(crate) fn poison(&mut self) {
        self.lifecycle = CardLifecycle::Poisoned;
    }

    fn transition(
        &mut self,
        expected: CardLifecycle,
        next: CardLifecycle,
    ) -> Result<(), CardInstanceError> {
        if self.lifecycle != expected {
            return Err(CardInstanceError::InvalidLifecycleTransition);
        }
        self.lifecycle = next;
        Ok(())
    }

    fn fence(&self, invocation: InvocationId) -> InvocationFence {
        InvocationFence {
            runtime_host: self.identity.runtime_host,
            runtime_host_epoch: self.identity.runtime_host_epoch,
            domain_epoch: self.identity.domain_epoch,
            planned_instance: self.identity.planned_instance,
            generation: self.identity.generation,
            invocation,
            source_revision: self.identity.source_revision,
            target_slice_digest: self.identity.target_slice_digest,
        }
    }
}

/// Fail-closed Card owner and output-boundary errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CardInstanceError {
    InvalidEpoch,
    EpochExhausted,
    InvocationExhausted,
    InvalidLifecycleTransition,
    InvocationAlreadyActive,
    InvocationNotActive,
    InvocationsStillActive,
    StaleCompletionFence,
    OutputTooLarge,
}

impl fmt::Display for CardInstanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEpoch => "runtime-owned epoch must be nonzero",
            Self::EpochExhausted => "runtime-owned epoch exhausted",
            Self::InvocationExhausted => "invocation identity exhausted",
            Self::InvalidLifecycleTransition => "invalid Card lifecycle transition",
            Self::InvocationAlreadyActive => "invocation is already active",
            Self::InvocationNotActive => "invocation is no longer active",
            Self::InvocationsStillActive => "Card still owns active invocations",
            Self::StaleCompletionFence => "completion fence belongs to an old runtime generation",
            Self::OutputTooLarge => "callback output exceeds its bounded proposal limit",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CardInstanceError {}

#[cfg(test)]
mod tests {
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::identity::RuntimeHostId;
    use paraegox_kernel::time::{ClockDomainRef, ClockGeneration, ClockReading, MonotonicInstant};
    use paraegox_runtime_contracts::assignment::InstanceRef;
    use paraegox_runtime_contracts::provenance::{SourcePlanRevision, TargetSliceDigest};

    use super::{
        CallbackFailure, CardContext, CardFuture, CardImplementation, CardInstanceError,
        CardInstanceIdentity, CardInstanceOwner, CardLifecycle, DomainEpoch, InputView,
        InstanceGeneration, OutputProposal, RuntimeHostEpoch,
    };
    use crate::task_registry::CancellationSource;

    struct CountingCard {
        starts: u32,
        inputs: u32,
        stops: u32,
    }

    impl CountingCard {
        const fn new() -> Self {
            Self {
                starts: 0,
                inputs: 0,
                stops: 0,
            }
        }
    }

    impl CardImplementation for CountingCard {
        fn on_start<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            Box::pin(async move {
                self.starts += 1;
                Ok(())
            })
        }

        fn on_input<'a>(
            &'a mut self,
            _context: &'a CardContext,
            _input: InputView<'a>,
        ) -> CardFuture<'a, Result<Option<OutputProposal>, CallbackFailure>> {
            Box::pin(async move {
                self.inputs += 1;
                Ok(None)
            })
        }

        fn on_stop<'a>(
            &'a mut self,
            _context: &'a CardContext,
        ) -> CardFuture<'a, Result<(), CallbackFailure>> {
            Box::pin(async move {
                self.stops += 1;
                Ok(())
            })
        }
    }

    fn epoch<T>(build: impl FnOnce(u64) -> Result<T, CardInstanceError>) -> T {
        let Ok(value) = build(1) else {
            panic!("fixture epoch must build");
        };
        value
    }

    fn identity(generation: u64) -> CardInstanceIdentity {
        let Ok(generation) = InstanceGeneration::try_new(generation) else {
            panic!("fixture generation must build");
        };
        CardInstanceIdentity::new(
            RuntimeHostId::from_bytes([1; 16]),
            epoch(RuntimeHostEpoch::try_new),
            InstanceRef::from_bytes([2; 16]),
            SourcePlanRevision::new(3),
            TargetSliceDigest::new(Digest32::from_bytes([4; 32])),
            epoch(DomainEpoch::try_new),
            generation,
        )
    }

    fn context(identity: CardInstanceIdentity) -> CardContext {
        let Ok(generation) = ClockGeneration::try_new(1) else {
            panic!("clock generation must build");
        };
        CardContext::new(
            identity,
            ClockReading::new(
                ClockDomainRef::from_bytes([5; 16]),
                generation,
                MonotonicInstant::from_ticks(0),
            ),
            CancellationSource::root().view(),
            Digest32::from_bytes([6; 32]),
            Digest32::from_bytes([7; 32]),
            Digest32::from_bytes([8; 32]),
        )
    }

    #[tokio::test]
    async fn two_plain_implementation_objects_keep_private_state() {
        let mut first = CountingCard::new();
        let mut second = CountingCard::new();
        let context = context(identity(1));

        assert_eq!(first.on_start(&context).await, Ok(()));
        assert_eq!(first.starts, 1);
        assert_eq!(second.starts, 0);
        assert_eq!(second.on_start(&context).await, Ok(()));
        assert_eq!(first.starts, 1);
        assert_eq!(second.starts, 1);
    }

    #[test]
    fn old_generation_and_already_terminal_output_are_fenced_before_observation() {
        let mut old = CardInstanceOwner::new(identity(1), Box::new(CountingCard::new()));
        assert_eq!(old.begin_start(), Ok(()));
        assert_eq!(old.finish_start(true), Ok(()));
        let Ok(fence) = old.begin_invocation() else {
            panic!("started Card must admit one invocation");
        };
        let Ok(schema) = paraegox_runtime_contracts::assignment::SchemaRef::try_new(
            [10; 16],
            1,
            Digest32::from_bytes([11; 32]),
        ) else {
            panic!("schema fixture must build");
        };
        let Ok(proposal) = OutputProposal::try_new(
            paraegox_runtime_contracts::assignment::PortRef::from_bytes([9; 16]),
            schema,
            vec![12],
            1,
        ) else {
            panic!("bounded output proposal must build");
        };
        let mut observations = 0;

        let current = CardInstanceOwner::new(identity(2), Box::new(CountingCard::new()));
        assert_eq!(
            current.observe_output(fence, &proposal, |_| observations += 1),
            Err(CardInstanceError::StaleCompletionFence)
        );
        assert_eq!(observations, 0);
        assert_eq!(
            old.observe_output(fence, &proposal, |_| observations += 1),
            Ok(())
        );
        assert_eq!(observations, 1);
        assert_eq!(old.finish_invocation(fence), Ok(()));
        assert_eq!(
            old.observe_output(fence, &proposal, |_| observations += 1),
            Err(CardInstanceError::InvocationNotActive)
        );
        assert_eq!(observations, 1);
    }

    #[test]
    fn lifecycle_owner_does_not_equate_start_with_ready() {
        let mut owner = CardInstanceOwner::new(identity(1), Box::new(CountingCard::new()));
        assert_eq!(owner.lifecycle(), CardLifecycle::Created);
        assert_eq!(owner.begin_start(), Ok(()));
        assert_eq!(owner.lifecycle(), CardLifecycle::Starting);
        assert_eq!(owner.finish_start(true), Ok(()));
        assert_eq!(owner.lifecycle(), CardLifecycle::Started);
        assert_eq!(owner.begin_draining(), Ok(()));
        assert_eq!(owner.begin_stop(), Ok(()));
        assert_eq!(owner.finish_stop(), Ok(()));
        assert_eq!(owner.lifecycle(), CardLifecycle::Stopped);
    }
}
