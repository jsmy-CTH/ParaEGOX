//! Owner-neutral source adapter and projection-input assembly seam.
//!
//! This module performs no discovery, authentication, polling loop, retry,
//! transport I/O, or owner-specific interpretation. A real owner adapter must
//! verify its own source and return at most one already-validated
//! [`OwnerInspectionFactV1`]. An adapter error remains an error; it is never
//! converted into a `Missing` source slot.

use core::fmt;

use crate::{
    InspectionContractError, InspectionObservationClockRefV1, InspectionSourceOwnerV1,
    InspectionSourceSlotV1, LOCAL_INSPECTION_OWNER_COUNT, LocalInspectionProjectionInputV1,
    NodeInspectionFactV2, NodeInspectionSourceSlotV2, OwnerInspectionFactV1,
};

/// One owner-specific, caller-supplied source adapter.
///
/// The trait is deliberately synchronous and one-shot. It does not prescribe
/// where facts come from or give the adapter retry, discovery, authentication,
/// heartbeat, cache, or projection authority.
pub trait InspectionSourceAdapterV1 {
    type Error;

    /// Declares the exact fact owner represented by this adapter.
    fn owner(&self) -> InspectionSourceOwnerV1;

    /// Declares the public-safe subject reference represented by this adapter.
    fn subject_ref(&self) -> [u8; 16];

    /// Reads at most one already-verified owner fact.
    ///
    /// `Ok(None)` is an explicit observation that this expected source has no
    /// fact. Transport failures, timeouts, decode failures, and rejected owner
    /// facts must be returned as `Err`; callers must not downgrade them to
    /// `Missing`. The returned fact must use `observation_clock_ref` exactly.
    fn read_verified_fact_once(
        &mut self,
        observation_clock_ref: InspectionObservationClockRefV1,
    ) -> Result<Option<OwnerInspectionFactV1>, Self::Error>;
}

/// Failure from one owner-adapter read or from strict slot binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InspectionSourceAdapterReadErrorV1<E> {
    /// The owner-specific adapter failed. This is never converted to Missing.
    Adapter(E),
    /// The adapter result did not match its declared owner, subject, or clock.
    Contract(InspectionContractError),
}

impl<E> fmt::Display for InspectionSourceAdapterReadErrorV1<E>
where
    E: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adapter(error) => write!(formatter, "Inspection source adapter failed: {error}"),
            Self::Contract(error) => write!(formatter, "Inspection source slot rejected: {error}"),
        }
    }
}

impl<E> std::error::Error for InspectionSourceAdapterReadErrorV1<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Adapter(error) => Some(error),
            Self::Contract(error) => Some(error),
        }
    }
}

/// Performs exactly one source-adapter read and strictly binds its result.
///
/// Adapter identity is validated before the read. A returned fact must match
/// the captured owner, subject, and observation clock. The helper performs no
/// retry and never manufactures liveness, readiness, health, availability, or
/// partition state.
pub fn read_inspection_source_slot_once_v1<A>(
    adapter: &mut A,
    observation_clock_ref: InspectionObservationClockRefV1,
) -> Result<InspectionSourceSlotV1, InspectionSourceAdapterReadErrorV1<A::Error>>
where
    A: InspectionSourceAdapterV1,
{
    let owner = adapter.owner();
    let subject_ref = adapter.subject_ref();
    InspectionSourceSlotV1::try_new(owner, subject_ref, None)
        .map_err(InspectionSourceAdapterReadErrorV1::Contract)?;

    let fact = adapter
        .read_verified_fact_once(observation_clock_ref)
        .map_err(InspectionSourceAdapterReadErrorV1::Adapter)?;
    if fact.is_some_and(|value| value.fields().observation_clock_ref != observation_clock_ref) {
        return Err(InspectionSourceAdapterReadErrorV1::Contract(
            InspectionContractError::ObservationClockMismatch,
        ));
    }
    InspectionSourceSlotV1::try_new(owner, subject_ref, fact)
        .map_err(InspectionSourceAdapterReadErrorV1::Contract)
}

/// Strict assembly failure for one five-owner local projection input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalInspectionProjectionInputBuilderErrorV1 {
    /// More than one slot was supplied for the same owner.
    DuplicateOwner(InspectionSourceOwnerV1),
    /// No slot was supplied for this required owner.
    MissingOwner(InspectionSourceOwnerV1),
    /// A supplied slot violates the existing projection-input contract.
    Contract(InspectionContractError),
}

impl fmt::Display for LocalInspectionProjectionInputBuilderErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateOwner(owner) => {
                write!(formatter, "duplicate Inspection source owner: {owner:?}")
            }
            Self::MissingOwner(owner) => {
                write!(formatter, "missing Inspection source owner: {owner:?}")
            }
            Self::Contract(error) => write!(formatter, "Inspection input rejected: {error}"),
        }
    }
}

impl std::error::Error for LocalInspectionProjectionInputBuilderErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::DuplicateOwner(_) | Self::MissingOwner(_) => None,
        }
    }
}

/// Collects exactly one slot for each admitted owner and emits canonical order.
///
/// The builder owns no source facts beyond the bounded five-slot input under
/// construction. It performs no read, projection, caching, or revision change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalInspectionProjectionInputBuilderV1 {
    observation_clock_ref: InspectionObservationClockRefV1,
    slots: [Option<InspectionSourceSlotV1>; LOCAL_INSPECTION_OWNER_COUNT],
}

impl LocalInspectionProjectionInputBuilderV1 {
    /// Starts one empty bounded input assembly.
    #[must_use]
    pub const fn new(observation_clock_ref: InspectionObservationClockRefV1) -> Self {
        Self {
            observation_clock_ref,
            slots: [None; LOCAL_INSPECTION_OWNER_COUNT],
        }
    }

    /// Inserts exactly one already-bound slot for its declared owner.
    pub fn try_insert(
        &mut self,
        slot: InspectionSourceSlotV1,
    ) -> Result<(), LocalInspectionProjectionInputBuilderErrorV1> {
        let owner = slot.owner();
        let index = owner_index(owner);
        if self.slots[index].is_some() {
            return Err(LocalInspectionProjectionInputBuilderErrorV1::DuplicateOwner(owner));
        }
        if slot
            .fact()
            .is_some_and(|fact| fact.fields().observation_clock_ref != self.observation_clock_ref)
        {
            return Err(LocalInspectionProjectionInputBuilderErrorV1::Contract(
                InspectionContractError::ObservationClockMismatch,
            ));
        }
        self.slots[index] = Some(slot);
        Ok(())
    }

    /// Requires all five owners and constructs the existing strict input type.
    pub fn try_build(
        self,
    ) -> Result<LocalInspectionProjectionInputV1, LocalInspectionProjectionInputBuilderErrorV1>
    {
        let [authority, deployment, runtime, fabric, agent] = self.slots;
        let slots = [
            authority.ok_or(LocalInspectionProjectionInputBuilderErrorV1::MissingOwner(
                InspectionSourceOwnerV1::Authority,
            ))?,
            deployment.ok_or(LocalInspectionProjectionInputBuilderErrorV1::MissingOwner(
                InspectionSourceOwnerV1::DeploymentController,
            ))?,
            runtime.ok_or(LocalInspectionProjectionInputBuilderErrorV1::MissingOwner(
                InspectionSourceOwnerV1::RuntimeHost,
            ))?,
            fabric.ok_or(LocalInspectionProjectionInputBuilderErrorV1::MissingOwner(
                InspectionSourceOwnerV1::FabricService,
            ))?,
            agent.ok_or(LocalInspectionProjectionInputBuilderErrorV1::MissingOwner(
                InspectionSourceOwnerV1::AgentService,
            ))?,
        ];
        LocalInspectionProjectionInputV1::try_new(self.observation_clock_ref, slots)
            .map_err(LocalInspectionProjectionInputBuilderErrorV1::Contract)
    }
}

const fn owner_index(owner: InspectionSourceOwnerV1) -> usize {
    match owner {
        InspectionSourceOwnerV1::Authority => 0,
        InspectionSourceOwnerV1::DeploymentController => 1,
        InspectionSourceOwnerV1::RuntimeHost => 2,
        InspectionSourceOwnerV1::FabricService => 3,
        InspectionSourceOwnerV1::AgentService => 4,
    }
}

/// One caller-supplied source adapter for the PXIS-v2 NodeDaemon extension.
///
/// The adapter must authenticate and fence the complete NodeStatus before it
/// returns the public-safe projection fact. This trait does no discovery,
/// transport I/O, retry, polling, route projection, or key projection itself.
pub trait NodeInspectionSourceAdapterV2 {
    type Error;

    fn node_ref(&self) -> [u8; 16];

    fn node_incarnation_ref(&self) -> [u8; 16];

    fn read_verified_fact_once(
        &mut self,
        observation_clock_ref: InspectionObservationClockRefV1,
    ) -> Result<Option<NodeInspectionFactV2>, Self::Error>;
}

/// Failure from one NodeDaemon adapter read or strict identity/clock binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeInspectionSourceAdapterReadErrorV2<E> {
    Adapter(E),
    Contract(InspectionContractError),
}

impl<E> fmt::Display for NodeInspectionSourceAdapterReadErrorV2<E>
where
    E: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adapter(error) => {
                write!(formatter, "Node Inspection source adapter failed: {error}")
            }
            Self::Contract(error) => {
                write!(formatter, "Node Inspection source slot rejected: {error}")
            }
        }
    }
}

impl<E> std::error::Error for NodeInspectionSourceAdapterReadErrorV2<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Adapter(error) => Some(error),
            Self::Contract(error) => Some(error),
        }
    }
}

/// Performs exactly one NodeDaemon source read and binds only its public-safe
/// projection. Adapter failures are never downgraded to `Missing`.
pub fn read_node_inspection_source_slot_once_v2<A>(
    adapter: &mut A,
    observation_clock_ref: InspectionObservationClockRefV1,
) -> Result<NodeInspectionSourceSlotV2, NodeInspectionSourceAdapterReadErrorV2<A::Error>>
where
    A: NodeInspectionSourceAdapterV2,
{
    let node_ref = adapter.node_ref();
    let node_incarnation_ref = adapter.node_incarnation_ref();
    NodeInspectionSourceSlotV2::try_new(node_ref, node_incarnation_ref, None)
        .map_err(NodeInspectionSourceAdapterReadErrorV2::Contract)?;
    let fact = adapter
        .read_verified_fact_once(observation_clock_ref)
        .map_err(NodeInspectionSourceAdapterReadErrorV2::Adapter)?;
    if fact.is_some_and(|value| value.fields().observation_clock_ref != observation_clock_ref) {
        return Err(NodeInspectionSourceAdapterReadErrorV2::Contract(
            InspectionContractError::ObservationClockMismatch,
        ));
    }
    NodeInspectionSourceSlotV2::try_new(node_ref, node_incarnation_ref, fact)
        .map_err(NodeInspectionSourceAdapterReadErrorV2::Contract)
}
