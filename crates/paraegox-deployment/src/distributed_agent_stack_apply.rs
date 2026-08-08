//! Deployment-owned commit-before-send and authenticated terminal reducer for
//! one exact two-target PXAR v8 rollout, including the additive restricted
//! PXRC/PXDS v2 remote carrier path.
//!
//! The Controller owner supplies the only atomic/fsync callback. This module
//! creates no lock, retry loop, Runtime producer, or second store. Its narrow
//! Unix owner wrapper retains two exact Fabric preflight tokens across the
//! single durable pair claim and consumes them in one concurrent dispatch; it
//! is not a production process composition root or credential-provisioning
//! path.

use core::fmt;
#[cfg(unix)]
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
#[cfg(unix)]
use paraegox_fabric::{
    ResolvedRemoteMtlsIdentityFiles, RestrictedRuntimeApplyClientConfigV1,
    RestrictedRuntimeApplyClientV1, RestrictedRuntimeApplyConfigErrorV1,
    RestrictedRuntimeApplyErrorV1,
};
use paraegox_kernel::digest::{Digest32, DigestBuildError};
use paraegox_kernel::identity::RuntimeHostId;
#[cfg(unix)]
use paraegox_runtime_contracts::distributed_agent_stack_plan::RestrictedRuntimeApplyTransportProfileV1;
use paraegox_runtime_contracts::distributed_agent_stack_plan::{
    DistributedAgentStackApplyRequestV1, DistributedAgentStackRestrictedApplyRequestV1,
    DistributedAgentStackTerminalOutcomeV1, DistributedAgentStackTerminalReceiptV1,
    DistributedAgentStackTerminalReceiptV2, DistributedFabricObservedTransportProofV1,
    RestrictedRuntimeApplyCarrierBindingV1,
};

use crate::distributed_agent_stack_producer::{
    DistributedAgentStackRolloutIdV1, DistributedAgentStackRolloutV1,
    VerifiedDistributedAgentStackPredecessorV1,
    produce_distributed_agent_stack_restricted_apply_v1,
    validate_distributed_agent_stack_terminal_v1, validate_distributed_agent_stack_terminal_v2,
};
use crate::distributed_agent_stack_store::{
    DistributedAgentStackControllerStateV1, DistributedAgentStackDurableStoreV1,
    DistributedAgentStackRolloutStatusV1, DistributedAgentStackStoreError,
    DistributedAgentStackTargetPhaseV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedDistributedAgentStackTargetV1 {
    owner_anchor: Digest32,
    rollout_id: DistributedAgentStackRolloutIdV1,
    target: RuntimeHostId,
    request_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedDistributedAgentStackRolloutV1 {
    rollout_id: DistributedAgentStackRolloutIdV1,
    replayed_from_durable_state: bool,
    pending_targets: Box<[PreparedDistributedAgentStackTargetV1]>,
}

impl PreparedDistributedAgentStackRolloutV1 {
    #[must_use]
    pub(crate) const fn rollout_id(&self) -> DistributedAgentStackRolloutIdV1 {
        self.rollout_id
    }

    #[must_use]
    pub(crate) const fn replayed_from_durable_state(&self) -> bool {
        self.replayed_from_durable_state
    }

    #[must_use]
    pub(crate) fn pending_targets(&self) -> &[PreparedDistributedAgentStackTargetV1] {
        &self.pending_targets
    }
}

/// One exact Controller-signed PXRC prepared for Fabric's matching preflight.
/// This value is not send authority and is consumed by the later pair claim.
#[derive(Debug, Eq, PartialEq)]
struct PreparedDistributedAgentStackRestrictedTargetV1 {
    prepared: PreparedDistributedAgentStackTargetV1,
    request:
        crate::distributed_agent_stack_producer::VerifiedDistributedAgentStackRestrictedApplyV1,
}

impl PreparedDistributedAgentStackRestrictedTargetV1 {
    #[must_use]
    const fn target(&self) -> RuntimeHostId {
        self.prepared.target
    }

    #[must_use]
    const fn carrier(&self) -> &RestrictedRuntimeApplyCarrierBindingV1 {
        self.request.request().carrier()
    }

    /// Exact bytes that Fabric's async preflight must retain without sending.
    #[must_use]
    fn canonical_request_bytes(&self) -> &[u8] {
        self.request.request().canonical_wire()
    }

    #[must_use]
    const fn restricted_request_digest(&self) -> Digest32 {
        self.request.request().restricted_request_digest()
    }
}

/// Move-only pair that binds both exact PXRC values across asynchronous
/// transport preflights and the later single durable claim.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PreparedDistributedAgentStackRestrictedPairV1 {
    targets: [PreparedDistributedAgentStackRestrictedTargetV1; 2],
}

impl PreparedDistributedAgentStackRestrictedPairV1 {
    #[must_use]
    const fn targets(&self) -> &[PreparedDistributedAgentStackRestrictedTargetV1; 2] {
        &self.targets
    }
}

/// Move-only authority to transmit one exact PXAR v8 after Uncertain became
/// durable. Restart never recreates this value.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackSendActionV1 {
    owner_anchor: Digest32,
    rollout_id: DistributedAgentStackRolloutIdV1,
    target: RuntimeHostId,
    request: DistributedAgentStackApplyRequestV1,
}

impl DistributedAgentStackSendActionV1 {
    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &DistributedAgentStackApplyRequestV1 {
        &self.request
    }

    #[must_use]
    pub(crate) fn canonical_request_bytes(&self) -> &[u8] {
        self.request.canonical_wire()
    }

    /// Drops all request bytes and consumes send authority after the caller's
    /// one transport attempt.
    pub(crate) fn into_terminal_correlation(self) -> DistributedAgentStackTerminalCorrelationV1 {
        DistributedAgentStackTerminalCorrelationV1 {
            owner_anchor: self.owner_anchor,
            rollout_id: self.rollout_id,
            target: self.target,
            request_digest: self.request.envelope_request_digest(),
        }
    }
}

/// Copyable response-correlation view. It deliberately carries no PXAR bytes
/// and cannot authorize a send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackTerminalCorrelationV1 {
    owner_anchor: Digest32,
    rollout_id: DistributedAgentStackRolloutIdV1,
    target: RuntimeHostId,
    request_digest: Digest32,
}

/// Move-only authority for one exact Controller-signed PXRC. It is created
/// only after both transport preflights and the single pair-claim commit.
#[derive(Debug, Eq, PartialEq)]
struct DistributedAgentStackRestrictedSendActionV1 {
    owner_anchor: Digest32,
    rollout_id: DistributedAgentStackRolloutIdV1,
    target: RuntimeHostId,
    request: DistributedAgentStackRestrictedApplyRequestV1,
}

impl DistributedAgentStackRestrictedSendActionV1 {
    #[must_use]
    const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    const fn request(&self) -> &DistributedAgentStackRestrictedApplyRequestV1 {
        &self.request
    }

    #[must_use]
    fn canonical_request_bytes(&self) -> &[u8] {
        self.request.canonical_wire()
    }

    /// Consumes the only send authority and retains response correlation only.
    fn into_terminal_correlation(self) -> DistributedAgentStackRestrictedTerminalCorrelationV1 {
        DistributedAgentStackRestrictedTerminalCorrelationV1 {
            owner_anchor: self.owner_anchor,
            rollout_id: self.rollout_id,
            target: self.target,
            restricted_request_digest: self.request.restricted_request_digest(),
            carrier_digest: self.request.carrier().binding_digest(),
        }
    }
}

/// Copyable, non-authorizing PXDS v2 response correlation. It intentionally
/// contains neither PXRC bytes nor any API capable of recreating a send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackRestrictedTerminalCorrelationV1 {
    owner_anchor: Digest32,
    rollout_id: DistributedAgentStackRolloutIdV1,
    target: RuntimeHostId,
    restricted_request_digest: Digest32,
    carrier_digest: Digest32,
}

/// One target's post-claim transport result. The Fabric preflight token and
/// Controller send action have both been consumed before this value exists.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct DistributedAgentStackRestrictedDispatchOutcomeV1 {
    target: RuntimeHostId,
    correlation: DistributedAgentStackRestrictedTerminalCorrelationV1,
    transport_result: Result<Box<[u8]>, RestrictedRuntimeApplyErrorV1>,
}

#[cfg(unix)]
impl DistributedAgentStackRestrictedDispatchOutcomeV1 {
    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn correlation(&self) -> DistributedAgentStackRestrictedTerminalCorrelationV1 {
        self.correlation
    }

    pub(crate) fn into_transport_result(self) -> Result<Box<[u8]>, RestrictedRuntimeApplyErrorV1> {
        self.transport_result
    }
}

/// One target's failure while turning a completed restricted query into a
/// verified durable PXDS v2 terminal. A durability failure is distinguished
/// from validation/state rejection because the Controller owner must reopen
/// before attempting another publish.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) enum DistributedAgentStackRestrictedTerminalizeErrorV1 {
    TargetOrderMismatch,
    OutcomeCorrelationMismatch,
    PredecessorTargetMismatch,
    Transport(RestrictedRuntimeApplyErrorV1),
    Terminal(DistributedAgentStackApplyError),
    Durability {
        primary: DistributedAgentStackApplyError,
        outcome: Box<DistributedAgentStackRestrictedDispatchOutcomeV1>,
    },
    UnprocessedAfterDurabilityFailure {
        failed_target: RuntimeHostId,
        outcome: Box<DistributedAgentStackRestrictedDispatchOutcomeV1>,
    },
}

#[cfg(unix)]
impl DistributedAgentStackRestrictedTerminalizeErrorV1 {
    #[must_use]
    pub(crate) const fn durability_primary(&self) -> Option<&DistributedAgentStackApplyError> {
        match self {
            Self::Durability { primary, .. } => Some(primary),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) const fn failed_durability_target(&self) -> Option<RuntimeHostId> {
        match self {
            Self::UnprocessedAfterDurabilityFailure { failed_target, .. } => Some(*failed_target),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) fn unprocessed_dispatch_outcome(
        &self,
    ) -> Option<&DistributedAgentStackRestrictedDispatchOutcomeV1> {
        match self {
            Self::UnprocessedAfterDurabilityFailure { outcome, .. } => Some(outcome.as_ref()),
            _ => None,
        }
    }

    /// Returns response evidence that must be reconciled after reopening disk
    /// truth. This includes both the ambiguously published response and the
    /// later response that was deliberately left untouched.
    #[must_use]
    pub(crate) fn recoverable_dispatch_outcome(
        &self,
    ) -> Option<&DistributedAgentStackRestrictedDispatchOutcomeV1> {
        match self {
            Self::Durability { outcome, .. }
            | Self::UnprocessedAfterDurabilityFailure { outcome, .. } => Some(outcome.as_ref()),
            _ => None,
        }
    }

    /// Consumes an ambiguous first publish without losing either its primary
    /// error or its already-returned response evidence.
    pub(crate) fn into_durability_failure_parts(
        self,
    ) -> Result<
        (
            DistributedAgentStackApplyError,
            DistributedAgentStackRestrictedDispatchOutcomeV1,
        ),
        Self,
    > {
        match self {
            Self::Durability { primary, outcome } => Ok((primary, *outcome)),
            other => Err(other),
        }
    }

    /// Recovers the later untouched response together with the target whose
    /// ambiguous publish forced processing to stop. No query is recreated.
    pub(crate) fn into_unprocessed_after_durability_parts(
        self,
    ) -> Result<
        (
            RuntimeHostId,
            DistributedAgentStackRestrictedDispatchOutcomeV1,
        ),
        Self,
    > {
        match self {
            Self::UnprocessedAfterDurabilityFailure {
                failed_target,
                outcome,
            } => Ok((failed_target, *outcome)),
            other => Err(other),
        }
    }
}

#[cfg(unix)]
impl fmt::Display for DistributedAgentStackRestrictedTerminalizeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "distributed Agent stack restricted terminalization failed: {self:?}"
        )
    }
}

#[cfg(unix)]
impl std::error::Error for DistributedAgentStackRestrictedTerminalizeErrorV1 {}

/// Fixed-order result for one dispatched target. Success proves the exact
/// PXDS v2 was verified and published; an error never implies a retransmit.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct DistributedAgentStackRestrictedTerminalizeOutcomeV1 {
    target: RuntimeHostId,
    terminal_result: Result<
        DistributedAgentStackRestrictedTerminalCommitV1,
        DistributedAgentStackRestrictedTerminalizeErrorV1,
    >,
}

#[cfg(unix)]
impl DistributedAgentStackRestrictedTerminalizeOutcomeV1 {
    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    pub(crate) const fn terminal_result(
        &self,
    ) -> &Result<
        DistributedAgentStackRestrictedTerminalCommitV1,
        DistributedAgentStackRestrictedTerminalizeErrorV1,
    > {
        &self.terminal_result
    }

    pub(crate) fn into_terminal_result(
        self,
    ) -> Result<
        DistributedAgentStackRestrictedTerminalCommitV1,
        DistributedAgentStackRestrictedTerminalizeErrorV1,
    > {
        self.terminal_result
    }
}

/// Failure before any restricted query is issued. A preflight, stale claim,
/// or durability error drops every retained Fabric token without calling
/// `send_once`.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) enum DistributedAgentStackRestrictedDispatchErrorV1 {
    FirstPreflight(RestrictedRuntimeApplyErrorV1),
    SecondPreflight(RestrictedRuntimeApplyErrorV1),
    Apply(DistributedAgentStackApplyError),
}

#[cfg(unix)]
impl From<DistributedAgentStackApplyError> for DistributedAgentStackRestrictedDispatchErrorV1 {
    fn from(value: DistributedAgentStackApplyError) -> Self {
        Self::Apply(value)
    }
}

#[cfg(unix)]
impl fmt::Display for DistributedAgentStackRestrictedDispatchErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "distributed Agent stack restricted dispatch failed: {self:?}"
        )
    }
}

#[cfg(unix)]
impl std::error::Error for DistributedAgentStackRestrictedDispatchErrorV1 {}

#[cfg(unix)]
type DistributedAgentStackRestrictedShutdownAfterDispatchPartsV1 = (
    [DistributedAgentStackRestrictedDispatchOutcomeV1; 2],
    [Result<(), RestrictedRuntimeApplyErrorV1>; 2],
);

/// Stable Controller connector-composition failures. Primary start/dispatch
/// failures and every explicit session-cleanup result remain independently
/// observable; cleanup never overwrites the operation that made it necessary.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) enum DistributedAgentStackRestrictedConnectorErrorV1 {
    FirstConfiguration(RestrictedRuntimeApplyConfigErrorV1),
    SecondConfiguration(RestrictedRuntimeApplyConfigErrorV1),
    FirstStart(RestrictedRuntimeApplyErrorV1),
    SecondStart {
        primary: RestrictedRuntimeApplyErrorV1,
        first_shutdown: Result<(), RestrictedRuntimeApplyErrorV1>,
    },
    Dispatch {
        primary: DistributedAgentStackRestrictedDispatchErrorV1,
        first_shutdown: Result<(), RestrictedRuntimeApplyErrorV1>,
        second_shutdown: Result<(), RestrictedRuntimeApplyErrorV1>,
    },
    ShutdownAfterDispatch {
        outcomes: Box<[DistributedAgentStackRestrictedDispatchOutcomeV1; 2]>,
        first_shutdown: Result<(), RestrictedRuntimeApplyErrorV1>,
        second_shutdown: Result<(), RestrictedRuntimeApplyErrorV1>,
    },
}

#[cfg(unix)]
impl DistributedAgentStackRestrictedConnectorErrorV1 {
    /// Returns the dispatch primary without consuming its cleanup evidence.
    #[must_use]
    pub(crate) fn dispatch_primary(
        &self,
    ) -> Option<&DistributedAgentStackRestrictedDispatchErrorV1> {
        match self {
            Self::Dispatch { primary, .. } => Some(primary),
            _ => None,
        }
    }

    /// Returns successful per-target dispatch results retained by a later
    /// shutdown failure. The error remains available beside those results.
    #[must_use]
    pub(crate) fn dispatched_outcomes(
        &self,
    ) -> Option<&[DistributedAgentStackRestrictedDispatchOutcomeV1; 2]> {
        match self {
            Self::ShutdownAfterDispatch { outcomes, .. } => Some(outcomes.as_ref()),
            _ => None,
        }
    }

    /// Returns explicit cleanup results in fixed target order. A missing
    /// second entry means the second connector never started.
    #[must_use]
    pub(crate) fn shutdown_results(
        &self,
    ) -> [Option<&Result<(), RestrictedRuntimeApplyErrorV1>>; 2] {
        match self {
            Self::SecondStart { first_shutdown, .. } => [Some(first_shutdown), None],
            Self::Dispatch {
                first_shutdown,
                second_shutdown,
                ..
            }
            | Self::ShutdownAfterDispatch {
                first_shutdown,
                second_shutdown,
                ..
            } => [Some(first_shutdown), Some(second_shutdown)],
            _ => [None, None],
        }
    }

    /// Consumes one dispatch-primary failure without dropping either cleanup
    /// result. Non-dispatch variants are returned unchanged.
    pub(crate) fn into_dispatch_failure_parts(
        self,
    ) -> Result<
        (
            DistributedAgentStackRestrictedDispatchErrorV1,
            [Result<(), RestrictedRuntimeApplyErrorV1>; 2],
        ),
        Self,
    > {
        match self {
            Self::Dispatch {
                primary,
                first_shutdown,
                second_shutdown,
            } => Ok((primary, [first_shutdown, second_shutdown])),
            other => Err(other),
        }
    }

    /// Consumes a post-dispatch shutdown failure while returning both target
    /// outcomes beside both cleanup results. Other variants remain intact.
    pub(crate) fn into_shutdown_after_dispatch_parts(
        self,
    ) -> Result<DistributedAgentStackRestrictedShutdownAfterDispatchPartsV1, Self> {
        match self {
            Self::ShutdownAfterDispatch {
                outcomes,
                first_shutdown,
                second_shutdown,
            } => Ok((*outcomes, [first_shutdown, second_shutdown])),
            other => Err(other),
        }
    }
}

#[cfg(unix)]
impl fmt::Display for DistributedAgentStackRestrictedConnectorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "distributed Agent stack restricted connector composition failed: {self:?}"
        )
    }
}

#[cfg(unix)]
impl std::error::Error for DistributedAgentStackRestrictedConnectorErrorV1 {}

#[cfg(unix)]
fn finish_restricted_connector_dispatch(
    dispatch: Result<
        [DistributedAgentStackRestrictedDispatchOutcomeV1; 2],
        DistributedAgentStackRestrictedDispatchErrorV1,
    >,
    first_shutdown: Result<(), RestrictedRuntimeApplyErrorV1>,
    second_shutdown: Result<(), RestrictedRuntimeApplyErrorV1>,
) -> Result<
    [DistributedAgentStackRestrictedDispatchOutcomeV1; 2],
    DistributedAgentStackRestrictedConnectorErrorV1,
> {
    match (dispatch, first_shutdown, second_shutdown) {
        (Ok(outcomes), Ok(()), Ok(())) => Ok(outcomes),
        (Ok(outcomes), first_shutdown, second_shutdown) => Err(
            DistributedAgentStackRestrictedConnectorErrorV1::ShutdownAfterDispatch {
                outcomes: Box::new(outcomes),
                first_shutdown,
                second_shutdown,
            },
        ),
        (Err(primary), first_shutdown, second_shutdown) => {
            Err(DistributedAgentStackRestrictedConnectorErrorV1::Dispatch {
                primary,
                first_shutdown,
                second_shutdown,
            })
        }
    }
}

#[cfg(unix)]
fn validate_restricted_dispatch_terminal_candidate(
    state: &DistributedAgentStackControllerStateV1,
    target_index: usize,
    outcome: &DistributedAgentStackRestrictedDispatchOutcomeV1,
    predecessor: &VerifiedDistributedAgentStackPredecessorV1,
) -> Result<(), DistributedAgentStackRestrictedTerminalizeErrorV1> {
    if state.targets()[target_index].target() != outcome.target {
        return Err(DistributedAgentStackRestrictedTerminalizeErrorV1::TargetOrderMismatch);
    }
    if outcome.correlation.target != outcome.target {
        return Err(DistributedAgentStackRestrictedTerminalizeErrorV1::OutcomeCorrelationMismatch);
    }
    if predecessor.target() != outcome.target {
        return Err(DistributedAgentStackRestrictedTerminalizeErrorV1::PredecessorTargetMismatch);
    }
    validate_restricted_correlation(state, outcome.correlation)
        .map_err(DistributedAgentStackRestrictedTerminalizeErrorV1::Terminal)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackTerminalCommitV1 {
    target: RuntimeHostId,
    outcome: DistributedAgentStackTerminalOutcomeV1,
    rollout_status: DistributedAgentStackRolloutStatusV1,
    receipt: DistributedAgentStackTerminalReceiptV1,
    replayed_from_durable_state: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DistributedAgentStackRestrictedTerminalCommitV1 {
    target: RuntimeHostId,
    outcome: DistributedAgentStackTerminalOutcomeV1,
    rollout_status: DistributedAgentStackRolloutStatusV1,
    receipt: DistributedAgentStackTerminalReceiptV2,
    replayed_from_durable_state: bool,
}

impl DistributedAgentStackRestrictedTerminalCommitV1 {
    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn outcome(&self) -> DistributedAgentStackTerminalOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub(crate) const fn rollout_status(&self) -> DistributedAgentStackRolloutStatusV1 {
        self.rollout_status
    }

    #[must_use]
    pub(crate) fn canonical_receipt_bytes(&self) -> &[u8] {
        self.receipt.canonical_wire()
    }

    #[must_use]
    pub(crate) const fn replayed_from_durable_state(&self) -> bool {
        self.replayed_from_durable_state
    }
}

impl DistributedAgentStackTerminalCommitV1 {
    #[must_use]
    pub(crate) const fn target(&self) -> RuntimeHostId {
        self.target
    }

    #[must_use]
    pub(crate) const fn outcome(&self) -> DistributedAgentStackTerminalOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub(crate) const fn rollout_status(&self) -> DistributedAgentStackRolloutStatusV1 {
        self.rollout_status
    }

    #[must_use]
    pub(crate) fn canonical_receipt_bytes(&self) -> &[u8] {
        self.receipt.canonical_wire()
    }

    #[must_use]
    pub(crate) const fn replayed_from_durable_state(&self) -> bool {
        self.replayed_from_durable_state
    }
}

/// Move-only Controller journal handle. It delegates persistence to the
/// existing Controller owner's callback and owns no independent lock.
#[derive(Debug)]
pub(crate) struct DistributedAgentStackApplyJournalV1 {
    store: DistributedAgentStackDurableStoreV1,
}

impl DistributedAgentStackApplyJournalV1 {
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self {
            store: DistributedAgentStackDurableStoreV1::empty(),
        }
    }

    pub(crate) fn try_reopen(
        frame: &[u8],
        expected_owner_anchor: Digest32,
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
    ) -> Result<Self, DistributedAgentStackApplyError> {
        Ok(Self {
            store: DistributedAgentStackDurableStoreV1::try_reopen(
                frame,
                expected_owner_anchor,
                predecessors,
            )?,
        })
    }

    #[must_use]
    pub(crate) const fn state(&self) -> Option<&DistributedAgentStackControllerStateV1> {
        self.store.state()
    }

    #[must_use]
    pub(crate) fn durable_wire(&self) -> Option<&[u8]> {
        self.store.durable_wire()
    }

    #[must_use]
    pub(crate) fn status(&self) -> Option<DistributedAgentStackRolloutStatusV1> {
        self.store
            .state()
            .map(DistributedAgentStackControllerStateV1::status)
    }

    pub(crate) fn prepare_with<Commit>(
        &mut self,
        owner_anchor: Digest32,
        rollout: DistributedAgentStackRolloutV1,
        commit: Commit,
    ) -> Result<PreparedDistributedAgentStackRolloutV1, DistributedAgentStackApplyError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        if let Some(current) = self.store.state() {
            if current.owner_anchor() != owner_anchor {
                return Err(DistributedAgentStackApplyError::OwnerMismatch);
            }
            if current.rollout().rollout_id() != rollout.rollout_id() {
                return Err(DistributedAgentStackApplyError::ActiveRolloutConflict);
            }
            if current.rollout() != &rollout {
                return Err(DistributedAgentStackApplyError::DesiredConflict);
            }
            return prepared_rollout(current, true);
        }
        let next = DistributedAgentStackControllerStateV1::try_new(owner_anchor, rollout)?;
        self.store.initialize_with(next, commit)?;
        prepared_rollout(
            self.store
                .state()
                .ok_or(DistributedAgentStackApplyError::InvalidState)?,
            false,
        )
    }

    pub(crate) fn prepared_target(
        &self,
        target: RuntimeHostId,
    ) -> Result<PreparedDistributedAgentStackTargetV1, DistributedAgentStackApplyError> {
        let state = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        prepared_target(state, target)
    }

    pub(crate) fn claim_send_with<Commit>(
        &mut self,
        prepared: PreparedDistributedAgentStackTargetV1,
        commit: Commit,
    ) -> Result<DistributedAgentStackSendActionV1, DistributedAgentStackApplyError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        validate_prepared(current, prepared)?;
        let request = current
            .target(prepared.target)
            .ok_or(DistributedAgentStackApplyError::TargetMismatch)?
            .request()
            .clone();
        let next = current.try_claim_target(prepared.target)?;
        self.store.commit_with(next, commit)?;
        Ok(DistributedAgentStackSendActionV1 {
            owner_anchor: prepared.owner_anchor,
            rollout_id: prepared.rollout_id,
            target: prepared.target,
            request,
        })
    }

    /// Produces an opaque exact signed PXRC pair without journal mutation or
    /// send authority. Only the owner wrapper below can expose its bytes to
    /// Fabric preflight or consume it into the private pair claim.
    pub(crate) fn prepare_restricted_pair_for_preflight(
        &self,
        prepared: [PreparedDistributedAgentStackTargetV1; 2],
        carriers: [RestrictedRuntimeApplyCarrierBindingV1; 2],
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        controller_signer: &SigningKey,
    ) -> Result<PreparedDistributedAgentStackRestrictedPairV1, DistributedAgentStackApplyError>
    {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        for index in 0..2 {
            validate_prepared(current, prepared[index])?;
            if current.targets()[index].target() != prepared[index].target
                || predecessors[index].target() != prepared[index].target
                || carriers[index].target() != prepared[index].target
            {
                return Err(DistributedAgentStackApplyError::RestrictedPairOrderMismatch);
            }
        }
        Ok(PreparedDistributedAgentStackRestrictedPairV1 {
            targets: [
                PreparedDistributedAgentStackRestrictedTargetV1 {
                    prepared: prepared[0],
                    request: produce_distributed_agent_stack_restricted_apply_v1(
                        predecessors[0],
                        current.targets()[0].request(),
                        carriers[0].clone(),
                        controller_signer,
                    )?,
                },
                PreparedDistributedAgentStackRestrictedTargetV1 {
                    prepared: prepared[1],
                    request: produce_distributed_agent_stack_restricted_apply_v1(
                        predecessors[1],
                        current.targets()[1].request(),
                        carriers[1].clone(),
                        controller_signer,
                    )?,
                },
            ],
        })
    }

    /// Atomically makes both exact preflighted PXRC values Uncertain.
    ///
    /// This private reducer is entered only by the owner wrapper while it
    /// retains both successful Fabric preflight tokens produced from the exact
    /// prepared bytes. The sole commit runs before either move-only Controller
    /// send action exists. Commit failure leaves both rows PendingNotSent.
    fn claim_preflighted_restricted_pair_with<Commit>(
        &mut self,
        prepared: PreparedDistributedAgentStackRestrictedPairV1,
        commit: Commit,
    ) -> Result<[DistributedAgentStackRestrictedSendActionV1; 2], DistributedAgentStackApplyError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        let [first, second] = prepared.targets;
        validate_prepared(current, first.prepared)?;
        validate_prepared(current, second.prepared)?;
        if current.targets()[0].target() != first.prepared.target
            || current.targets()[1].target() != second.prepared.target
        {
            return Err(DistributedAgentStackApplyError::RestrictedPairOrderMismatch);
        }
        let durable_requests = [
            first.request.request().clone(),
            second.request.request().clone(),
        ];
        let owner_anchor = current.owner_anchor();
        let rollout_id = current.rollout().rollout_id();
        let targets = [first.prepared.target, second.prepared.target];
        let next = current.try_claim_restricted_pair([first.request, second.request])?;
        self.store.commit_with(next, commit)?;
        Ok([
            DistributedAgentStackRestrictedSendActionV1 {
                owner_anchor,
                rollout_id,
                target: targets[0],
                request: durable_requests[0].clone(),
            },
            DistributedAgentStackRestrictedSendActionV1 {
                owner_anchor,
                rollout_id,
                target: targets[1],
                request: durable_requests[1].clone(),
            },
        ])
    }

    /// Narrow Controller-owner seam for exact preflight -> durable pair claim
    /// -> concurrent one-shot transport dispatch.
    ///
    /// This is an internal mechanism, not production endpoint composition. It
    /// retains both Fabric preflight tokens locally, performs no journal claim
    /// or query when either preflight fails, commits both exact PXRC values in
    /// one PXDJ v3 successor, consumes both Controller actions into response
    /// correlations, and only then starts the two physical queries together.
    #[cfg(unix)]
    pub(crate) async fn preflight_claim_and_dispatch_restricted_pair_with<Commit>(
        &mut self,
        prepared: PreparedDistributedAgentStackRestrictedPairV1,
        clients: [&mut RestrictedRuntimeApplyClientV1; 2],
        commit: Commit,
    ) -> Result<
        [DistributedAgentStackRestrictedDispatchOutcomeV1; 2],
        DistributedAgentStackRestrictedDispatchErrorV1,
    >
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        if !clients[0].matches_restricted_target(
            prepared.targets()[0].carrier().target(),
            prepared.targets()[0].carrier().route(),
            prepared.targets()[0].carrier().runtime_principal(),
            prepared.targets()[0].carrier().binding_digest(),
        ) || !clients[1].matches_restricted_target(
            prepared.targets()[1].carrier().target(),
            prepared.targets()[1].carrier().route(),
            prepared.targets()[1].carrier().runtime_principal(),
            prepared.targets()[1].carrier().binding_digest(),
        ) {
            return Err(DistributedAgentStackApplyError::PreparedTokenMismatch.into());
        }
        let request_bytes = [
            prepared.targets()[0].canonical_request_bytes().to_vec(),
            prepared.targets()[1].canonical_request_bytes().to_vec(),
        ];
        let [first_client, second_client] = clients;
        let first_preflight = first_client
            .preflight(request_bytes[0].clone())
            .await
            .map_err(DistributedAgentStackRestrictedDispatchErrorV1::FirstPreflight)?;
        let second_preflight = second_client
            .preflight(request_bytes[1].clone())
            .await
            .map_err(DistributedAgentStackRestrictedDispatchErrorV1::SecondPreflight)?;

        let [first_action, second_action] =
            self.claim_preflighted_restricted_pair_with(prepared, commit)?;
        if first_action.canonical_request_bytes() != request_bytes[0]
            || second_action.canonical_request_bytes() != request_bytes[1]
        {
            return Err(DistributedAgentStackApplyError::PreparedTokenMismatch.into());
        }
        let targets = [first_action.target(), second_action.target()];
        let correlations = [
            first_action.into_terminal_correlation(),
            second_action.into_terminal_correlation(),
        ];
        let (first_result, second_result) =
            tokio::join!(first_preflight.send_once(), second_preflight.send_once());
        Ok([
            DistributedAgentStackRestrictedDispatchOutcomeV1 {
                target: targets[0],
                correlation: correlations[0],
                transport_result: first_result,
            },
            DistributedAgentStackRestrictedDispatchOutcomeV1 {
                target: targets[1],
                correlation: correlations[1],
                transport_result: second_result,
            },
        ])
    }

    /// Owns two short-lived Controller connectors around the exact restricted
    /// pair dispatch. Inputs must use the prepared pair's fixed target order.
    ///
    /// Both PXRP/PXCB mappings are validated before either session starts. A
    /// second-start failure explicitly closes the first session. Once both
    /// sessions exist, every dispatch outcome is followed by concurrent
    /// explicit shutdown, with primary and cleanup failures preserved
    /// separately. This remains an internal composition seam, not a production
    /// CLI, profile publisher, credential resolver, or retry owner.
    #[cfg(unix)]
    pub(crate) async fn start_dispatch_and_shutdown_restricted_pair_with<Commit>(
        &mut self,
        prepared: PreparedDistributedAgentStackRestrictedPairV1,
        connector_inputs: [(
            [u8; 16],
            RestrictedRuntimeApplyTransportProfileV1,
            PathBuf,
            ResolvedRemoteMtlsIdentityFiles,
        ); 2],
        commit: Commit,
    ) -> Result<
        [DistributedAgentStackRestrictedDispatchOutcomeV1; 2],
        DistributedAgentStackRestrictedConnectorErrorV1,
    >
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let [
            (
                first_profile_ref,
                first_profile,
                first_root_ca_certificate_file,
                first_connector_identity,
            ),
            (
                second_profile_ref,
                second_profile,
                second_root_ca_certificate_file,
                second_connector_identity,
            ),
        ] = connector_inputs;
        let first_config = RestrictedRuntimeApplyClientConfigV1::try_from_transport_profile(
            &first_profile,
            first_profile_ref,
            prepared.targets()[0].carrier(),
            first_root_ca_certificate_file,
            first_connector_identity,
        )
        .map_err(DistributedAgentStackRestrictedConnectorErrorV1::FirstConfiguration)?;
        let second_config = RestrictedRuntimeApplyClientConfigV1::try_from_transport_profile(
            &second_profile,
            second_profile_ref,
            prepared.targets()[1].carrier(),
            second_root_ca_certificate_file,
            second_connector_identity,
        )
        .map_err(DistributedAgentStackRestrictedConnectorErrorV1::SecondConfiguration)?;

        let mut first_client = RestrictedRuntimeApplyClientV1::start(first_config)
            .await
            .map_err(DistributedAgentStackRestrictedConnectorErrorV1::FirstStart)?;
        let mut second_client = match RestrictedRuntimeApplyClientV1::start(second_config).await {
            Ok(client) => client,
            Err(primary) => {
                let first_shutdown = first_client.shutdown().await;
                return Err(
                    DistributedAgentStackRestrictedConnectorErrorV1::SecondStart {
                        primary,
                        first_shutdown,
                    },
                );
            }
        };

        let dispatch = self
            .preflight_claim_and_dispatch_restricted_pair_with(
                prepared,
                [&mut first_client, &mut second_client],
                commit,
            )
            .await;
        let (first_shutdown, second_shutdown) =
            tokio::join!(first_client.shutdown(), second_client.shutdown());
        finish_restricted_connector_dispatch(dispatch, first_shutdown, second_shutdown)
    }

    /// Verifies and durably records the two PXDS v2 responses returned by one
    /// completed restricted pair dispatch. The dispatch's fixed target order,
    /// correlation digests, exact durable PXRC/PXCB, and predecessor pins are
    /// checked before either terminal reducer runs.
    ///
    /// Targets converge independently: transport or terminal validation
    /// failure on one target does not suppress the other. Durable publish
    /// failure is different because disk truth may be ambiguous; in that case
    /// no later publish is attempted and the unprocessed response is returned
    /// intact for restart recovery. This function has no connector, preflight,
    /// send-action, retry, or retransmit capability.
    #[cfg(unix)]
    pub(crate) fn consume_restricted_dispatch_pair_with<Commit>(
        &mut self,
        outcomes: [DistributedAgentStackRestrictedDispatchOutcomeV1; 2],
        predecessors: [&VerifiedDistributedAgentStackPredecessorV1; 2],
        mut commit: Commit,
    ) -> [DistributedAgentStackRestrictedTerminalizeOutcomeV1; 2]
    where
        Commit: FnMut(RuntimeHostId, &[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let admissions = match self.store.state() {
            Some(state) => [
                validate_restricted_dispatch_terminal_candidate(
                    state,
                    0,
                    &outcomes[0],
                    predecessors[0],
                ),
                validate_restricted_dispatch_terminal_candidate(
                    state,
                    1,
                    &outcomes[1],
                    predecessors[1],
                ),
            ],
            None => [
                Err(DistributedAgentStackRestrictedTerminalizeErrorV1::Terminal(
                    DistributedAgentStackApplyError::InvalidState,
                )),
                Err(DistributedAgentStackRestrictedTerminalizeErrorV1::Terminal(
                    DistributedAgentStackApplyError::InvalidState,
                )),
            ],
        };
        let [first_outcome, second_outcome] = outcomes;
        let [first_admission, second_admission] = admissions;
        let first_target = first_outcome.target;
        let second_target = second_outcome.target;
        let (first, first_durability_failed) = self.consume_restricted_dispatch_outcome_with(
            first_outcome,
            predecessors[0],
            first_admission,
            |wire| commit(first_target, wire),
        );
        if first_durability_failed {
            return [
                first,
                DistributedAgentStackRestrictedTerminalizeOutcomeV1 {
                    target: second_target,
                    terminal_result: Err(
                        DistributedAgentStackRestrictedTerminalizeErrorV1::UnprocessedAfterDurabilityFailure {
                            failed_target: first_target,
                            outcome: Box::new(second_outcome),
                        },
                    ),
                },
            ];
        }
        let (second, _) = self.consume_restricted_dispatch_outcome_with(
            second_outcome,
            predecessors[1],
            second_admission,
            |wire| commit(second_target, wire),
        );
        [first, second]
    }

    #[cfg(unix)]
    fn consume_restricted_dispatch_outcome_with<Commit>(
        &mut self,
        outcome: DistributedAgentStackRestrictedDispatchOutcomeV1,
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        admission: Result<(), DistributedAgentStackRestrictedTerminalizeErrorV1>,
        commit: Commit,
    ) -> (DistributedAgentStackRestrictedTerminalizeOutcomeV1, bool)
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let target = outcome.target;
        if let Err(error) = admission {
            return (
                DistributedAgentStackRestrictedTerminalizeOutcomeV1 {
                    target,
                    terminal_result: Err(error),
                },
                false,
            );
        }
        let correlation = outcome.correlation;
        let response = match outcome.transport_result {
            Ok(response) => response,
            Err(error) => {
                return (
                    DistributedAgentStackRestrictedTerminalizeOutcomeV1 {
                        target,
                        terminal_result: Err(
                            DistributedAgentStackRestrictedTerminalizeErrorV1::Transport(error),
                        ),
                    },
                    false,
                );
            }
        };
        let mut publish_attempted = false;
        let mut publish_failed = false;
        let terminal_result = self.consume_recovered_restricted_terminal_with(
            correlation,
            &response,
            predecessor,
            |wire| {
                publish_attempted = true;
                let result = commit(wire);
                publish_failed = result.is_err();
                result
            },
        );
        let durability_failed = publish_attempted && publish_failed;
        let terminal_result = match terminal_result {
            Ok(commit) => Ok(commit),
            Err(primary) if durability_failed => Err(
                DistributedAgentStackRestrictedTerminalizeErrorV1::Durability {
                    primary,
                    outcome: Box::new(DistributedAgentStackRestrictedDispatchOutcomeV1 {
                        target,
                        correlation,
                        transport_result: Ok(response),
                    }),
                },
            ),
            Err(error) => Err(DistributedAgentStackRestrictedTerminalizeErrorV1::Terminal(
                error,
            )),
        };
        (
            DistributedAgentStackRestrictedTerminalizeOutcomeV1 {
                target,
                terminal_result,
            },
            durability_failed,
        )
    }

    /// Reconstructs only response correlation for an Uncertain row. It never
    /// recreates request bytes or send authority after restart.
    pub(crate) fn terminal_correlation(
        &self,
        target: RuntimeHostId,
    ) -> Result<DistributedAgentStackTerminalCorrelationV1, DistributedAgentStackApplyError> {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        let row = current
            .target(target)
            .ok_or(DistributedAgentStackApplyError::TargetMismatch)?;
        if row.phase() != DistributedAgentStackTargetPhaseV1::Uncertain {
            return Err(DistributedAgentStackApplyError::OpaqueReplayForbidden);
        }
        if row.restricted_request().is_some() {
            return Err(DistributedAgentStackApplyError::OpaqueReplayForbidden);
        }
        Ok(DistributedAgentStackTerminalCorrelationV1 {
            owner_anchor: current.owner_anchor(),
            rollout_id: current.rollout().rollout_id(),
            target,
            request_digest: row.request().envelope_request_digest(),
        })
    }

    /// Reconstructs only PXDS v2 response correlation from a durable v3 row.
    /// Restart never recreates the exact PXRC send action.
    pub(crate) fn restricted_terminal_correlation(
        &self,
        target: RuntimeHostId,
    ) -> Result<DistributedAgentStackRestrictedTerminalCorrelationV1, DistributedAgentStackApplyError>
    {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        let row = current
            .target(target)
            .ok_or(DistributedAgentStackApplyError::TargetMismatch)?;
        let request = row
            .restricted_request()
            .ok_or(DistributedAgentStackApplyError::OpaqueReplayForbidden)?;
        if row.phase() != DistributedAgentStackTargetPhaseV1::Uncertain
            || row.restricted_receipt().is_some()
        {
            return Err(DistributedAgentStackApplyError::OpaqueReplayForbidden);
        }
        Ok(DistributedAgentStackRestrictedTerminalCorrelationV1 {
            owner_anchor: current.owner_anchor(),
            rollout_id: current.rollout().rollout_id(),
            target,
            restricted_request_digest: request.restricted_request_digest(),
            carrier_digest: request.carrier().binding_digest(),
        })
    }

    /// Consumes the original send authority while accepting one response.
    pub(crate) fn consume_terminal_with<Commit>(
        &mut self,
        action: DistributedAgentStackSendActionV1,
        receipt_wire: &[u8],
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        commit: Commit,
    ) -> Result<DistributedAgentStackTerminalCommitV1, DistributedAgentStackApplyError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        validate_action(current, &action)?;
        self.consume_correlated_terminal_with(
            action.into_terminal_correlation(),
            receipt_wire,
            predecessor,
            commit,
        )
    }

    /// Accepts a late response after restart using only non-authorizing durable
    /// correlation. No PXAR retry is implied or possible through this path.
    pub(crate) fn consume_recovered_terminal_with<Commit>(
        &mut self,
        correlation: DistributedAgentStackTerminalCorrelationV1,
        receipt_wire: &[u8],
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        commit: Commit,
    ) -> Result<DistributedAgentStackTerminalCommitV1, DistributedAgentStackApplyError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        self.consume_correlated_terminal_with(correlation, receipt_wire, predecessor, commit)
    }

    fn consume_correlated_terminal_with<Commit>(
        &mut self,
        correlation: DistributedAgentStackTerminalCorrelationV1,
        receipt_wire: &[u8],
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        commit: Commit,
    ) -> Result<DistributedAgentStackTerminalCommitV1, DistributedAgentStackApplyError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        validate_correlation(current, correlation)?;
        let request = current
            .target(correlation.target)
            .ok_or(DistributedAgentStackApplyError::TargetMismatch)?
            .request();
        let receipt = DistributedAgentStackTerminalReceiptV1::decode(receipt_wire)
            .map_err(|_| DistributedAgentStackApplyError::TerminalMismatch)?;
        let verified = validate_distributed_agent_stack_terminal_v1(predecessor, request, receipt)
            .map_err(|_| DistributedAgentStackApplyError::TerminalMismatch)?;
        let outcome = verified.receipt().facts().outcome();
        let durable_receipt = verified.receipt().clone();
        let next = current.try_terminal(correlation.target, verified)?;
        self.store.commit_with(next, commit)?;
        let status = self
            .status()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        Ok(DistributedAgentStackTerminalCommitV1 {
            target: correlation.target,
            outcome,
            rollout_status: status,
            receipt: durable_receipt,
            replayed_from_durable_state: false,
        })
    }

    /// Consumes one post-commit restricted send action while admitting the
    /// corresponding PXDS v2 through deployment's concrete pinned-key verifier.
    fn consume_restricted_terminal_with<Commit>(
        &mut self,
        action: DistributedAgentStackRestrictedSendActionV1,
        receipt_wire: &[u8],
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        commit: Commit,
    ) -> Result<DistributedAgentStackRestrictedTerminalCommitV1, DistributedAgentStackApplyError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        validate_restricted_action(current, &action)?;
        self.consume_restricted_correlated_terminal_with(
            action.into_terminal_correlation(),
            receipt_wire,
            predecessor,
            commit,
        )
    }

    /// Accepts a late PXDS v2 after restart using correlation only. This path
    /// cannot reconstruct or retransmit the durable PXRC.
    pub(crate) fn consume_recovered_restricted_terminal_with<Commit>(
        &mut self,
        correlation: DistributedAgentStackRestrictedTerminalCorrelationV1,
        receipt_wire: &[u8],
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        commit: Commit,
    ) -> Result<DistributedAgentStackRestrictedTerminalCommitV1, DistributedAgentStackApplyError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        self.consume_restricted_correlated_terminal_with(
            correlation,
            receipt_wire,
            predecessor,
            commit,
        )
    }

    fn consume_restricted_correlated_terminal_with<Commit>(
        &mut self,
        correlation: DistributedAgentStackRestrictedTerminalCorrelationV1,
        receipt_wire: &[u8],
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        commit: Commit,
    ) -> Result<DistributedAgentStackRestrictedTerminalCommitV1, DistributedAgentStackApplyError>
    where
        Commit: FnOnce(&[u8]) -> Result<(), DistributedAgentStackStoreError>,
    {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        validate_restricted_correlation(current, correlation)?;
        let row = current
            .target(correlation.target)
            .ok_or(DistributedAgentStackApplyError::TargetMismatch)?;
        let restricted = row
            .restricted_request()
            .ok_or(DistributedAgentStackApplyError::RestrictedTerminalMismatch)?;
        let receipt = DistributedAgentStackTerminalReceiptV2::decode(receipt_wire)
            .map_err(|_| DistributedAgentStackApplyError::RestrictedTerminalMismatch)?;
        let verified = validate_distributed_agent_stack_terminal_v2(
            predecessor,
            row.request(),
            restricted,
            receipt,
        )
        .map_err(|_| DistributedAgentStackApplyError::RestrictedTerminalMismatch)?;
        let outcome = verified.receipt().facts().outcome();
        let durable_receipt = verified.receipt().clone();
        let next = current.try_restricted_terminal(correlation.target, verified)?;
        self.store.commit_with(next, commit)?;
        let status = self
            .status()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        Ok(DistributedAgentStackRestrictedTerminalCommitV1 {
            target: correlation.target,
            outcome,
            rollout_status: status,
            receipt: durable_receipt,
            replayed_from_durable_state: false,
        })
    }

    /// Returns the exact already-durable terminal bytes without writing or
    /// recreating send authority.
    pub(crate) fn terminal_replay(
        &self,
        target: RuntimeHostId,
    ) -> Result<DistributedAgentStackTerminalCommitV1, DistributedAgentStackApplyError> {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        let receipt = current
            .target(target)
            .and_then(|row| row.receipt())
            .ok_or(DistributedAgentStackApplyError::TerminalNotDurable)?
            .clone();
        Ok(DistributedAgentStackTerminalCommitV1 {
            target,
            outcome: receipt.facts().outcome(),
            rollout_status: current.status(),
            receipt,
            replayed_from_durable_state: true,
        })
    }

    /// Returns exact already-durable PXDS v2 bytes without recreating PXRC
    /// send authority.
    pub(crate) fn restricted_terminal_replay(
        &self,
        target: RuntimeHostId,
    ) -> Result<DistributedAgentStackRestrictedTerminalCommitV1, DistributedAgentStackApplyError>
    {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        let receipt = current
            .target(target)
            .and_then(|row| row.restricted_receipt())
            .ok_or(DistributedAgentStackApplyError::TerminalNotDurable)?
            .clone();
        Ok(DistributedAgentStackRestrictedTerminalCommitV1 {
            target,
            outcome: receipt.facts().outcome(),
            rollout_status: current.status(),
            receipt,
            replayed_from_durable_state: true,
        })
    }

    /// Checks PXTP correlation but always refuses terminal promotion because
    /// the payload has no RuntimeHost signature on its own.
    pub(crate) fn observe_unsigned_pxtp(
        &self,
        correlation: DistributedAgentStackTerminalCorrelationV1,
        proof_wire: &[u8],
    ) -> Result<(), DistributedAgentStackApplyError> {
        let current = self
            .store
            .state()
            .ok_or(DistributedAgentStackApplyError::InvalidState)?;
        validate_correlation(current, correlation)?;
        let request = current
            .target(correlation.target)
            .ok_or(DistributedAgentStackApplyError::TargetMismatch)?
            .request();
        let proof = DistributedFabricObservedTransportProofV1::decode(proof_wire)
            .map_err(|_| DistributedAgentStackApplyError::TransportObservationMismatch)?;
        let topology = request
            .target_execution()
            .topology()
            .ok_or(DistributedAgentStackApplyError::TransportObservationMismatch)?;
        let peer = topology
            .peers()
            .iter()
            .find(|peer| peer.peer_runtime_host() == proof.fields().peer_runtime_host)
            .ok_or(DistributedAgentStackApplyError::TransportObservationMismatch)?;
        proof
            .validate_against(correlation.target, peer)
            .map_err(|_| DistributedAgentStackApplyError::TransportObservationMismatch)?;
        Err(DistributedAgentStackApplyError::UnauthenticatedTerminalForbidden)
    }
}

fn prepared_rollout(
    state: &DistributedAgentStackControllerStateV1,
    replayed_from_durable_state: bool,
) -> Result<PreparedDistributedAgentStackRolloutV1, DistributedAgentStackApplyError> {
    let pending_targets = state
        .targets()
        .iter()
        .filter(|row| row.phase() == DistributedAgentStackTargetPhaseV1::RequestDurableNotSent)
        .map(|row| prepared_target(state, row.target()))
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();
    Ok(PreparedDistributedAgentStackRolloutV1 {
        rollout_id: state.rollout().rollout_id(),
        replayed_from_durable_state,
        pending_targets,
    })
}

fn prepared_target(
    state: &DistributedAgentStackControllerStateV1,
    target: RuntimeHostId,
) -> Result<PreparedDistributedAgentStackTargetV1, DistributedAgentStackApplyError> {
    let row = state
        .target(target)
        .ok_or(DistributedAgentStackApplyError::TargetMismatch)?;
    if row.phase() != DistributedAgentStackTargetPhaseV1::RequestDurableNotSent {
        return Err(DistributedAgentStackApplyError::OpaqueReplayForbidden);
    }
    Ok(PreparedDistributedAgentStackTargetV1 {
        owner_anchor: state.owner_anchor(),
        rollout_id: state.rollout().rollout_id(),
        target,
        request_digest: row.request().envelope_request_digest(),
    })
}

fn validate_prepared(
    state: &DistributedAgentStackControllerStateV1,
    prepared: PreparedDistributedAgentStackTargetV1,
) -> Result<(), DistributedAgentStackApplyError> {
    let row = state
        .target(prepared.target)
        .ok_or(DistributedAgentStackApplyError::TargetMismatch)?;
    if state.owner_anchor() != prepared.owner_anchor
        || state.rollout().rollout_id() != prepared.rollout_id
        || row.phase() != DistributedAgentStackTargetPhaseV1::RequestDurableNotSent
        || row.request().envelope_request_digest() != prepared.request_digest
    {
        return Err(DistributedAgentStackApplyError::PreparedTokenMismatch);
    }
    Ok(())
}

fn validate_action(
    state: &DistributedAgentStackControllerStateV1,
    action: &DistributedAgentStackSendActionV1,
) -> Result<(), DistributedAgentStackApplyError> {
    let row = state
        .target(action.target)
        .ok_or(DistributedAgentStackApplyError::TargetMismatch)?;
    if state.owner_anchor() != action.owner_anchor
        || state.rollout().rollout_id() != action.rollout_id
        || row.phase() != DistributedAgentStackTargetPhaseV1::Uncertain
        || row.request() != &action.request
    {
        return Err(DistributedAgentStackApplyError::SendActionMismatch);
    }
    Ok(())
}

fn validate_restricted_action(
    state: &DistributedAgentStackControllerStateV1,
    action: &DistributedAgentStackRestrictedSendActionV1,
) -> Result<(), DistributedAgentStackApplyError> {
    let row = state
        .target(action.target)
        .ok_or(DistributedAgentStackApplyError::TargetMismatch)?;
    if state.owner_anchor() != action.owner_anchor
        || state.rollout().rollout_id() != action.rollout_id
        || row.phase() != DistributedAgentStackTargetPhaseV1::Uncertain
        || row.restricted_request() != Some(&action.request)
        || row.restricted_receipt().is_some()
    {
        return Err(DistributedAgentStackApplyError::RestrictedSendActionMismatch);
    }
    Ok(())
}

fn validate_correlation(
    state: &DistributedAgentStackControllerStateV1,
    correlation: DistributedAgentStackTerminalCorrelationV1,
) -> Result<(), DistributedAgentStackApplyError> {
    let row = state
        .target(correlation.target)
        .ok_or(DistributedAgentStackApplyError::TargetMismatch)?;
    if state.owner_anchor() != correlation.owner_anchor
        || state.rollout().rollout_id() != correlation.rollout_id
        || row.phase() != DistributedAgentStackTargetPhaseV1::Uncertain
        || row.request().envelope_request_digest() != correlation.request_digest
    {
        return Err(DistributedAgentStackApplyError::TerminalCorrelationMismatch);
    }
    Ok(())
}

fn validate_restricted_correlation(
    state: &DistributedAgentStackControllerStateV1,
    correlation: DistributedAgentStackRestrictedTerminalCorrelationV1,
) -> Result<(), DistributedAgentStackApplyError> {
    let row = state
        .target(correlation.target)
        .ok_or(DistributedAgentStackApplyError::TargetMismatch)?;
    let restricted = row
        .restricted_request()
        .ok_or(DistributedAgentStackApplyError::RestrictedTerminalCorrelationMismatch)?;
    if state.owner_anchor() != correlation.owner_anchor
        || state.rollout().rollout_id() != correlation.rollout_id
        || row.phase() != DistributedAgentStackTargetPhaseV1::Uncertain
        || row.restricted_receipt().is_some()
        || restricted.restricted_request_digest() != correlation.restricted_request_digest
        || restricted.carrier().binding_digest() != correlation.carrier_digest
    {
        return Err(DistributedAgentStackApplyError::RestrictedTerminalCorrelationMismatch);
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum DistributedAgentStackApplyError {
    Store(DistributedAgentStackStoreError),
    Producer(crate::distributed_agent_stack_producer::DistributedAgentStackProducerError),
    Digest(DigestBuildError),
    InvalidState,
    OwnerMismatch,
    ActiveRolloutConflict,
    DesiredConflict,
    TargetMismatch,
    PreparedTokenMismatch,
    RestrictedPairOrderMismatch,
    SendActionMismatch,
    RestrictedSendActionMismatch,
    TerminalCorrelationMismatch,
    RestrictedTerminalCorrelationMismatch,
    TerminalMismatch,
    RestrictedTerminalMismatch,
    TerminalNotDurable,
    OpaqueReplayForbidden,
    TransportObservationMismatch,
    UnauthenticatedTerminalForbidden,
}

impl From<DistributedAgentStackStoreError> for DistributedAgentStackApplyError {
    fn from(value: DistributedAgentStackStoreError) -> Self {
        Self::Store(value)
    }
}

impl From<crate::distributed_agent_stack_producer::DistributedAgentStackProducerError>
    for DistributedAgentStackApplyError
{
    fn from(
        value: crate::distributed_agent_stack_producer::DistributedAgentStackProducerError,
    ) -> Self {
        Self::Producer(value)
    }
}

impl From<DigestBuildError> for DistributedAgentStackApplyError {
    fn from(value: DigestBuildError) -> Self {
        Self::Digest(value)
    }
}

impl fmt::Display for DistributedAgentStackApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "distributed Agent stack apply failed: {self:?}")
    }
}

impl std::error::Error for DistributedAgentStackApplyError {}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use paraegox_kernel::digest::Digest32;
    use paraegox_runtime_contracts::distributed_agent_stack_plan::{
        DistributedAgentStackLocalBindingEvidenceFieldsV1,
        DistributedAgentStackRestrictedApplyRequestV1, DistributedAgentStackTerminalAuthClaimV1,
        DistributedAgentStackTerminalEvidenceFieldsV1, DistributedAgentStackTerminalFactsV1,
        DistributedAgentStackTerminalObservationsV1, DistributedAgentStackTerminalOutcomeV1,
        DistributedAgentStackTerminalReceiptDraftV1, DistributedAgentStackTerminalReceiptDraftV2,
        DistributedAgentStackTerminalReceiptV2, DistributedFabricObservedTransportProofFieldsV1,
        DistributedFabricObservedTransportProofV1, DistributedFabricSessionEpochV1,
        DistributedFabricTransportEvidenceRefV1, RestrictedRuntimeApplyCarrierBindingFieldsV1,
        RestrictedRuntimeApplyCarrierBindingV1,
        distributed_agent_stack_installed_binding_set_digest_v1,
    };
    use paraegox_runtime_contracts::managed_service::ManagedServiceGeneration;
    use paraegox_runtime_contracts::reference_control::ed25519_control_key_fingerprint;
    use paraegox_runtime_contracts::wire::ApplyAuthAlgorithm;

    use super::{
        DistributedAgentStackApplyError, DistributedAgentStackApplyJournalV1,
        DistributedAgentStackRestrictedConnectorErrorV1,
        DistributedAgentStackRestrictedDispatchErrorV1,
        DistributedAgentStackRestrictedDispatchOutcomeV1,
        DistributedAgentStackRestrictedTerminalCorrelationV1,
        DistributedAgentStackRestrictedTerminalizeErrorV1, RestrictedRuntimeApplyErrorV1,
        RuntimeHostId, finish_restricted_connector_dispatch,
    };
    use crate::distributed_agent_stack_producer::tests::{
        conflicting_rollout_same_id, fixture_bundle, runtime_signer,
    };
    use crate::distributed_agent_stack_producer::{
        DistributedAgentStackRolloutIdV1, VerifiedDistributedAgentStackPredecessorV1,
        validate_distributed_agent_stack_restricted_apply_v1,
    };
    use crate::distributed_agent_stack_store::{
        DistributedAgentStackRolloutStatusV1, DistributedAgentStackStoreError,
        DistributedAgentStackTargetPhaseV1,
    };

    fn owner_anchor() -> Digest32 {
        Digest32::from_bytes([0xd1; 32])
    }

    #[derive(Clone, Copy)]
    struct TerminalFences {
        runtime_host_epoch: u64,
        completion_snapshot_sequence: u64,
        fabric_generation: Option<ManagedServiceGeneration>,
        agent_generation: Option<ManagedServiceGeneration>,
    }

    fn terminal_receipt(
        request: &paraegox_runtime_contracts::distributed_agent_stack_plan::DistributedAgentStackApplyRequestV1,
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        outcome: DistributedAgentStackTerminalOutcomeV1,
        signer: &SigningKey,
    ) -> paraegox_runtime_contracts::distributed_agent_stack_plan::DistributedAgentStackTerminalReceiptV1{
        terminal_receipt_with_binding_seed(
            request,
            predecessor,
            outcome,
            signer,
            request.target().as_bytes()[0] + 0x60,
        )
    }

    fn terminal_receipt_with_binding_seed(
        request: &paraegox_runtime_contracts::distributed_agent_stack_plan::DistributedAgentStackApplyRequestV1,
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        outcome: DistributedAgentStackTerminalOutcomeV1,
        signer: &SigningKey,
        binding_seed: u8,
    ) -> paraegox_runtime_contracts::distributed_agent_stack_plan::DistributedAgentStackTerminalReceiptV1{
        let ready = outcome == DistributedAgentStackTerminalOutcomeV1::ActiveReady;
        terminal_receipt_with_fences(
            request,
            predecessor,
            outcome,
            signer,
            binding_seed,
            TerminalFences {
                runtime_host_epoch: 6,
                completion_snapshot_sequence: 8,
                fabric_generation: ready
                    .then(|| ManagedServiceGeneration::try_new(3).expect("Fabric generation")),
                agent_generation: ready
                    .then(|| ManagedServiceGeneration::try_new(4).expect("Agent generation")),
            },
        )
    }

    fn terminal_receipt_with_fences(
        request: &paraegox_runtime_contracts::distributed_agent_stack_plan::DistributedAgentStackApplyRequestV1,
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        outcome: DistributedAgentStackTerminalOutcomeV1,
        signer: &SigningKey,
        binding_seed: u8,
        fences: TerminalFences,
    ) -> paraegox_runtime_contracts::distributed_agent_stack_plan::DistributedAgentStackTerminalReceiptV1{
        let ready = outcome == DistributedAgentStackTerminalOutcomeV1::ActiveReady;
        let proofs = if ready {
            let topology = request
                .target_execution()
                .topology()
                .expect("distributed topology");
            topology
                .peers()
                .iter()
                .enumerate()
                .map(|(index, peer)| {
                    DistributedFabricObservedTransportProofV1::try_new(
                        request.target(),
                        peer,
                        DistributedFabricObservedTransportProofFieldsV1 {
                            local_runtime_host: request.target(),
                            peer_runtime_host: peer.peer_runtime_host(),
                            session_epoch: DistributedFabricSessionEpochV1::try_from_bytes(
                                [request.target().as_bytes()[0] + 0x30; 16],
                            )
                            .expect("session epoch"),
                            authenticated_peer_identity_ref: peer
                                .authentication()
                                .expected_peer_identity_ref(),
                            selected_local_credential_ref: peer
                                .authentication()
                                .local_credential_ref(),
                            transport_evidence_ref:
                                DistributedFabricTransportEvidenceRefV1::try_from_bytes(
                                    [u8::try_from(index).expect("bounded peer") + 0x70; 16],
                                )
                                .expect("transport evidence"),
                            observation_sequence: u64::try_from(index).expect("bounded peer") + 1,
                        },
                    )
                    .expect("correlated PXTP")
                })
                .collect()
        } else {
            Vec::new()
        };
        let observations = DistributedAgentStackTerminalObservationsV1::try_new(request, proofs)
            .expect("terminal observations");
        let local_bindings = DistributedAgentStackLocalBindingEvidenceFieldsV1 {
            physical_binding_census: if ready { 2 } else { 0 },
            census_complete: ready,
            fabric_ready: ready,
            agent_ready: ready,
            dependency_satisfied: ready,
            exact_zero: false,
            quarantined: false,
            installed_binding_set_digest: distributed_agent_stack_installed_binding_set_digest_v1(
                Digest32::from_bytes([binding_seed; 32]),
                Digest32::from_bytes([binding_seed + 1; 32]),
            )
            .expect("installed binding set"),
            raw_outcome_digest: Digest32::from_bytes([0xa3; 32]),
        };
        let facts = DistributedAgentStackTerminalFactsV1::try_new(
            request,
            outcome,
            DistributedAgentStackTerminalEvidenceFieldsV1 {
                runtime_host_epoch: fences.runtime_host_epoch,
                completion_snapshot_sequence: fences.completion_snapshot_sequence,
                selection_clock_generation: request.temporal().target_clock_generation(),
                selection_observed_at_nanos: 9,
                fabric_generation: fences.fabric_generation,
                agent_generation: fences.agent_generation,
                local_bindings,
            },
            observations,
        )
        .expect("terminal facts");
        let channel = predecessor.runtime_channel();
        let auth = DistributedAgentStackTerminalAuthClaimV1::try_new(
            channel,
            predecessor.runtime_response_key(),
            ApplyAuthAlgorithm::try_new(1).expect("Ed25519"),
            1,
        )
        .expect("terminal auth claim");
        let draft =
            DistributedAgentStackTerminalReceiptDraftV1::try_new(request, facts, channel, auth)
                .expect("terminal draft");
        let signature = signer.sign(
            draft
                .signing_transcript()
                .expect("terminal transcript")
                .as_bytes(),
        );
        draft.finalize(&signature.to_bytes()).expect("signed PXDS")
    }

    fn controller_signer() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    fn restricted_carrier(
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        seed: u8,
    ) -> RestrictedRuntimeApplyCarrierBindingV1 {
        let route = format!("paraegox/runtime-{seed:02x}/apply");
        RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: predecessor.target(),
                runtime_principal: predecessor.runtime_principal(),
                controller_principal: predecessor.controller_principal(),
                endpoint_ref: [seed; 16],
                endpoint_generation: u64::from(seed),
                route: &route,
                controller_request_key: predecessor.request_key(),
                controller_request_key_fingerprint: ed25519_control_key_fingerprint(
                    controller_signer().verifying_key().as_bytes(),
                )
                .expect("Controller fingerprint"),
                runtime_response_key: predecessor.runtime_response_key(),
                runtime_response_key_fingerprint: ed25519_control_key_fingerprint(
                    runtime_signer(predecessor.target())
                        .verifying_key()
                        .as_bytes(),
                )
                .expect("Runtime fingerprint"),
                control_transport_profile_ref: [seed + 1; 16],
                control_transport_profile_digest: Digest32::from_bytes([seed + 2; 32]),
            },
        )
        .expect("restricted carrier")
    }

    fn restricted_terminal_receipt(
        restricted: &DistributedAgentStackRestrictedApplyRequestV1,
        request: &paraegox_runtime_contracts::distributed_agent_stack_plan::DistributedAgentStackApplyRequestV1,
        predecessor: &VerifiedDistributedAgentStackPredecessorV1,
        outcome: DistributedAgentStackTerminalOutcomeV1,
        signer: &SigningKey,
    ) -> DistributedAgentStackTerminalReceiptV2 {
        let authenticated = restricted
            .verify_controller_carrier_before_mutation(
                restricted.carrier(),
                |principal, key, fingerprint, transcript, signature| {
                    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
                        return false;
                    };
                    principal == predecessor.controller_principal()
                        && key == predecessor.request_key()
                        && fingerprint
                            == ed25519_control_key_fingerprint(
                                controller_signer().verifying_key().as_bytes(),
                            )
                            .expect("Controller fingerprint")
                        && controller_signer()
                            .verifying_key()
                            .verify_strict(transcript, &signature)
                            .is_ok()
                },
            )
            .expect("authenticated PXRC");
        let legacy = terminal_receipt(request, predecessor, outcome, signer);
        let draft = DistributedAgentStackTerminalReceiptDraftV2::try_new(
            authenticated,
            legacy.facts().clone(),
        )
        .expect("PXDS v2 draft");
        let signature = signer.sign(
            draft
                .signing_transcript()
                .expect("PXDS v2 transcript")
                .as_bytes(),
        );
        draft
            .finalize(&signature.to_bytes())
            .expect("signed PXDS v2")
    }

    #[test]
    fn prepare_is_durable_before_token_and_same_id_replay_is_exact() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        assert!(matches!(
            journal.prepare_with(owner_anchor(), fixture.rollout.clone(), |_| {
                Err(DistributedAgentStackStoreError::DurabilityRejected)
            }),
            Err(DistributedAgentStackApplyError::Store(
                DistributedAgentStackStoreError::DurabilityRejected
            ))
        ));
        assert!(journal.state().is_none());

        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("durable prepare");
        assert_eq!(prepared.pending_targets().len(), 2);
        assert!(!prepared.replayed_from_durable_state());
        let replay = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| {
                panic!("exact replay does not write")
            })
            .expect("exact durable replay");
        assert!(replay.replayed_from_durable_state());
        assert!(matches!(
            journal.prepare_with(
                owner_anchor(),
                conflicting_rollout_same_id(&fixture.predecessors),
                |_| panic!("conflict does not write"),
            ),
            Err(DistributedAgentStackApplyError::DesiredConflict)
        ));
    }

    #[test]
    fn restart_reconstructs_correlation_but_never_send_authority() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let target = prepared.pending_targets()[0].target;
        let action = journal
            .claim_send_with(prepared.pending_targets()[0], |_| Ok(()))
            .expect("uncertain before send authority");
        assert!(!action.canonical_request_bytes().is_empty());
        let correlation = action.into_terminal_correlation();
        assert_eq!(
            journal
                .terminal_correlation(target)
                .expect("live correlation"),
            correlation
        );
        assert!(matches!(
            journal.prepared_target(target),
            Err(DistributedAgentStackApplyError::OpaqueReplayForbidden)
        ));

        let durable = journal.durable_wire().expect("uncertain state").to_vec();
        let reopened = DistributedAgentStackApplyJournalV1::try_reopen(
            &durable,
            owner_anchor(),
            [&fixture.predecessors[0], &fixture.predecessors[1]],
        )
        .expect("restart");
        assert_eq!(reopened.durable_wire(), Some(durable.as_slice()));
        assert_eq!(
            reopened
                .terminal_correlation(target)
                .expect("recovered correlation"),
            correlation
        );
        assert!(matches!(
            reopened.prepared_target(target),
            Err(DistributedAgentStackApplyError::OpaqueReplayForbidden)
        ));
    }

    #[test]
    fn unsigned_pxtp_and_partial_authenticated_terminal_never_make_ready() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let action = journal
            .claim_send_with(prepared.pending_targets()[0], |_| Ok(()))
            .expect("send authority");
        let request = action.request();
        let peer = &request
            .target_execution()
            .topology()
            .expect("topology")
            .peers()[0];
        let proof = DistributedFabricObservedTransportProofV1::try_new(
            action.target(),
            peer,
            DistributedFabricObservedTransportProofFieldsV1 {
                local_runtime_host: action.target(),
                peer_runtime_host: peer.peer_runtime_host(),
                session_epoch: DistributedFabricSessionEpochV1::try_from_bytes([0xe1; 16])
                    .expect("session epoch"),
                authenticated_peer_identity_ref: peer.authentication().expected_peer_identity_ref(),
                selected_local_credential_ref: peer.authentication().local_credential_ref(),
                transport_evidence_ref: DistributedFabricTransportEvidenceRefV1::try_from_bytes(
                    [0xe2; 16],
                )
                .expect("evidence"),
                observation_sequence: 1,
            },
        )
        .expect("PXTP");
        let correlation = action.into_terminal_correlation();
        let before = journal.durable_wire().expect("uncertain").to_vec();
        assert!(matches!(
            journal.observe_unsigned_pxtp(correlation, proof.canonical_wire()),
            Err(DistributedAgentStackApplyError::UnauthenticatedTerminalForbidden)
        ));
        assert_eq!(journal.durable_wire(), Some(before.as_slice()));

        let receipt = terminal_receipt(
            &fixture.rollout.requests()[0],
            &fixture.predecessors[0],
            DistributedAgentStackTerminalOutcomeV1::IndeterminateUncertain,
            &runtime_signer(fixture.rollout.requests()[0].target()),
        );
        let committed = journal
            .consume_recovered_terminal_with(
                correlation,
                receipt.canonical_wire(),
                &fixture.predecessors[0],
                |_| Ok(()),
            )
            .expect("authenticated uncertain terminal");
        assert_eq!(
            committed.rollout_status(),
            DistributedAgentStackRolloutStatusV1::IndeterminateUncertain
        );
    }

    #[test]
    fn ready_requires_both_distinct_authenticated_reciprocal_terminals() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let first_action = journal
            .claim_send_with(prepared.pending_targets()[0], |_| Ok(()))
            .expect("first send");
        let second_action = journal
            .claim_send_with(prepared.pending_targets()[1], |_| Ok(()))
            .expect("second send");
        let first_receipt = terminal_receipt(
            &fixture.rollout.requests()[0],
            &fixture.predecessors[0],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(fixture.rollout.requests()[0].target()),
        );
        let second_receipt = terminal_receipt(
            &fixture.rollout.requests()[1],
            &fixture.predecessors[1],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(fixture.rollout.requests()[1].target()),
        );
        let first = journal
            .consume_terminal_with(
                first_action,
                first_receipt.canonical_wire(),
                &fixture.predecessors[0],
                |_| Ok(()),
            )
            .expect("first ActiveReady receipt");
        assert_eq!(
            first.rollout_status(),
            DistributedAgentStackRolloutStatusV1::Uncertain
        );
        let second = journal
            .consume_terminal_with(
                second_action,
                second_receipt.canonical_wire(),
                &fixture.predecessors[1],
                |_| Ok(()),
            )
            .expect("second ActiveReady receipt");
        assert_eq!(
            second.rollout_status(),
            DistributedAgentStackRolloutStatusV1::ActiveReady
        );
        assert_eq!(
            journal.status(),
            Some(DistributedAgentStackRolloutStatusV1::ActiveReady)
        );
    }

    #[test]
    fn duplicated_cross_target_local_binding_set_is_not_reciprocal_ready() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let first_action = journal
            .claim_send_with(prepared.pending_targets()[0], |_| Ok(()))
            .expect("first send");
        let second_action = journal
            .claim_send_with(prepared.pending_targets()[1], |_| Ok(()))
            .expect("second send");
        let shared_binding_seed = fixture.rollout.requests()[0].target().as_bytes()[0] + 0x60;
        let first_receipt = terminal_receipt_with_binding_seed(
            &fixture.rollout.requests()[0],
            &fixture.predecessors[0],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(fixture.rollout.requests()[0].target()),
            shared_binding_seed,
        );
        let second_receipt = terminal_receipt_with_binding_seed(
            &fixture.rollout.requests()[1],
            &fixture.predecessors[1],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(fixture.rollout.requests()[1].target()),
            shared_binding_seed,
        );
        journal
            .consume_terminal_with(
                first_action,
                first_receipt.canonical_wire(),
                &fixture.predecessors[0],
                |_| Ok(()),
            )
            .expect("first terminal");
        let before = journal
            .durable_wire()
            .expect("first terminal bytes")
            .to_vec();
        assert!(matches!(
            journal.consume_terminal_with(
                second_action,
                second_receipt.canonical_wire(),
                &fixture.predecessors[1],
                |_| panic!("binding conflict cannot commit"),
            ),
            Err(DistributedAgentStackApplyError::Store(
                DistributedAgentStackStoreError::ReciprocalTerminalMismatch
            ))
        ));
        assert_eq!(journal.durable_wire(), Some(before.as_slice()));
        assert_eq!(
            journal.status(),
            Some(DistributedAgentStackRolloutStatusV1::Uncertain)
        );
    }

    #[test]
    fn wrong_key_tamper_and_cross_target_receipt_fail_without_mutation() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let action = journal
            .claim_send_with(prepared.pending_targets()[0], |_| Ok(()))
            .expect("send");
        let correlation = action.into_terminal_correlation();
        let wrong_signed = terminal_receipt(
            &fixture.rollout.requests()[0],
            &fixture.predecessors[0],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &SigningKey::from_bytes(&[0xf1; 32]),
        );
        let before = journal.durable_wire().expect("uncertain").to_vec();
        assert!(matches!(
            journal.consume_recovered_terminal_with(
                correlation,
                wrong_signed.canonical_wire(),
                &fixture.predecessors[0],
                |_| panic!("wrong key never commits"),
            ),
            Err(DistributedAgentStackApplyError::TerminalMismatch)
        ));

        let valid = terminal_receipt(
            &fixture.rollout.requests()[0],
            &fixture.predecessors[0],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(fixture.rollout.requests()[0].target()),
        );
        let mut tampered = valid.canonical_wire().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            journal.consume_recovered_terminal_with(
                correlation,
                &tampered,
                &fixture.predecessors[0],
                |_| panic!("tamper never commits"),
            ),
            Err(DistributedAgentStackApplyError::TerminalMismatch)
        ));
        let other = terminal_receipt(
            &fixture.rollout.requests()[1],
            &fixture.predecessors[1],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(fixture.rollout.requests()[1].target()),
        );
        assert!(matches!(
            journal.consume_recovered_terminal_with(
                correlation,
                other.canonical_wire(),
                &fixture.predecessors[0],
                |_| panic!("cross-target receipt never commits"),
            ),
            Err(DistributedAgentStackApplyError::TerminalMismatch)
        ));
        assert_eq!(journal.durable_wire(), Some(before.as_slice()));
    }

    #[test]
    fn predecessor_generation_and_host_snapshot_replay_are_rejected() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let action = journal
            .claim_send_with(prepared.pending_targets()[0], |_| Ok(()))
            .expect("send");
        let correlation = action.into_terminal_correlation();
        let request = &fixture.rollout.requests()[0];
        let predecessor = &fixture.predecessors[0];
        let signer = runtime_signer(request.target());
        let stale_generations = terminal_receipt_with_fences(
            request,
            predecessor,
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &signer,
            request.target().as_bytes()[0] + 0x60,
            TerminalFences {
                runtime_host_epoch: 6,
                completion_snapshot_sequence: 8,
                fabric_generation: Some(
                    ManagedServiceGeneration::try_new(1).expect("old Fabric generation"),
                ),
                agent_generation: Some(
                    ManagedServiceGeneration::try_new(2).expect("old Agent generation"),
                ),
            },
        );
        assert!(matches!(
            journal.consume_recovered_terminal_with(
                correlation,
                stale_generations.canonical_wire(),
                predecessor,
                |_| panic!("stale generations cannot commit"),
            ),
            Err(DistributedAgentStackApplyError::TerminalMismatch)
        ));

        let stale_snapshot = terminal_receipt_with_fences(
            request,
            predecessor,
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &signer,
            request.target().as_bytes()[0] + 0x60,
            TerminalFences {
                runtime_host_epoch: 5,
                completion_snapshot_sequence: 7,
                fabric_generation: Some(
                    ManagedServiceGeneration::try_new(3).expect("fresh Fabric generation"),
                ),
                agent_generation: Some(
                    ManagedServiceGeneration::try_new(4).expect("fresh Agent generation"),
                ),
            },
        );
        assert!(matches!(
            journal.consume_recovered_terminal_with(
                correlation,
                stale_snapshot.canonical_wire(),
                predecessor,
                |_| panic!("stale host snapshot cannot commit"),
            ),
            Err(DistributedAgentStackApplyError::TerminalMismatch)
        ));
        assert_eq!(
            journal.status(),
            Some(DistributedAgentStackRolloutStatusV1::Uncertain)
        );
    }

    #[test]
    fn terminal_commit_precedes_report_and_restart_replays_exact_bytes_once() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let action = journal
            .claim_send_with(prepared.pending_targets()[0], |_| Ok(()))
            .expect("send");
        let target = action.target();
        let receipt = terminal_receipt(
            &fixture.rollout.requests()[0],
            &fixture.predecessors[0],
            DistributedAgentStackTerminalOutcomeV1::TerminalNonReady,
            &runtime_signer(target),
        );
        assert!(matches!(
            journal.consume_terminal_with(
                action,
                receipt.canonical_wire(),
                &fixture.predecessors[0],
                |_| Err(DistributedAgentStackStoreError::DurabilityRejected),
            ),
            Err(DistributedAgentStackApplyError::Store(
                DistributedAgentStackStoreError::DurabilityRejected
            ))
        ));
        let correlation = journal
            .terminal_correlation(target)
            .expect("failed commit retains only response correlation");
        let committed = journal
            .consume_recovered_terminal_with(
                correlation,
                receipt.canonical_wire(),
                &fixture.predecessors[0],
                |_| Ok(()),
            )
            .expect("durable terminal");
        assert_eq!(committed.target(), target);
        assert_eq!(
            committed.outcome(),
            DistributedAgentStackTerminalOutcomeV1::TerminalNonReady
        );
        assert_eq!(
            committed.canonical_receipt_bytes(),
            receipt.canonical_wire()
        );
        assert!(!committed.replayed_from_durable_state());

        let durable = journal.durable_wire().expect("terminal state").to_vec();
        let reopened = DistributedAgentStackApplyJournalV1::try_reopen(
            &durable,
            owner_anchor(),
            [&fixture.predecessors[0], &fixture.predecessors[1]],
        )
        .expect("restart terminal state");
        assert_eq!(reopened.durable_wire(), Some(durable.as_slice()));
        let replay = reopened.terminal_replay(target).expect("durable replay");
        assert!(replay.replayed_from_durable_state());
        assert_eq!(replay.canonical_receipt_bytes(), receipt.canonical_wire());
        assert!(matches!(
            reopened.terminal_correlation(target),
            Err(DistributedAgentStackApplyError::OpaqueReplayForbidden)
        ));
        assert!(matches!(
            reopened.prepared_target(target),
            Err(DistributedAgentStackApplyError::OpaqueReplayForbidden)
        ));
    }

    #[test]
    fn restricted_pair_claim_has_two_preflights_one_commit_and_zero_publish_on_failure() {
        use std::cell::Cell;

        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let prepared_pair = [prepared.pending_targets()[0], prepared.pending_targets()[1]];
        let carriers = [
            restricted_carrier(&fixture.predecessors[0], 0x31),
            restricted_carrier(&fixture.predecessors[1], 0x41),
        ];
        let before = journal.durable_wire().expect("pending state").to_vec();
        let preflights = Cell::new(0_u8);
        let commits = Cell::new(0_u8);
        let restricted_prepared = journal
            .prepare_restricted_pair_for_preflight(
                prepared_pair,
                carriers.clone(),
                [&fixture.predecessors[0], &fixture.predecessors[1]],
                &controller_signer(),
            )
            .expect("exact PXRC pair for async preflight");
        let rejected_preflight_bytes: [Vec<u8>; 2] = core::array::from_fn(|index| {
            restricted_prepared.targets()[index]
                .canonical_request_bytes()
                .to_vec()
        });
        for target in restricted_prepared.targets() {
            assert!(!target.canonical_request_bytes().is_empty());
            assert_eq!(target.carrier().target(), target.target());
            assert_ne!(
                target.restricted_request_digest(),
                Digest32::from_bytes([0; 32])
            );
            preflights.set(preflights.get() + 1);
        }
        assert!(matches!(
            journal.claim_preflighted_restricted_pair_with(restricted_prepared, |_| {
                assert_eq!(preflights.get(), 2);
                commits.set(commits.get() + 1);
                Err(DistributedAgentStackStoreError::DurabilityRejected)
            },),
            Err(DistributedAgentStackApplyError::Store(
                DistributedAgentStackStoreError::DurabilityRejected
            ))
        ));
        assert_eq!(preflights.get(), 2);
        assert_eq!(commits.get(), 1);
        assert_eq!(journal.durable_wire(), Some(before.as_slice()));
        assert_eq!(
            journal.status(),
            Some(DistributedAgentStackRolloutStatusV1::PendingNotSent)
        );

        preflights.set(0);
        commits.set(0);
        let restricted_prepared = journal
            .prepare_restricted_pair_for_preflight(
                prepared_pair,
                carriers,
                [&fixture.predecessors[0], &fixture.predecessors[1]],
                &controller_signer(),
            )
            .expect("retry exact PXRC pair after rejected durability");
        let preflight_bytes: [Vec<u8>; 2] = core::array::from_fn(|index| {
            restricted_prepared.targets()[index]
                .canonical_request_bytes()
                .to_vec()
        });
        assert_eq!(preflight_bytes, rejected_preflight_bytes);
        for target in restricted_prepared.targets() {
            assert!(!target.canonical_request_bytes().is_empty());
            preflights.set(preflights.get() + 1);
        }
        let actions = journal
            .claim_preflighted_restricted_pair_with(restricted_prepared, |_| {
                assert_eq!(preflights.get(), 2);
                commits.set(commits.get() + 1);
                Ok(())
            })
            .expect("atomic restricted pair claim");
        assert_eq!(preflights.get(), 2);
        assert_eq!(commits.get(), 1);
        assert_eq!(actions[0].target(), fixture.rollout.requests()[0].target());
        assert_eq!(actions[1].target(), fixture.rollout.requests()[1].target());
        assert_eq!(actions[0].canonical_request_bytes(), preflight_bytes[0]);
        assert_eq!(actions[1].canonical_request_bytes(), preflight_bytes[1]);
        assert!(actions.iter().all(|action| {
            !action.canonical_request_bytes().is_empty()
                && action.request().carrier().target() == action.target()
        }));
        assert!(journal
            .state()
            .expect("claimed state")
            .targets()
            .iter()
            .all(|row| {
                row.phase()
                    == crate::distributed_agent_stack_store::DistributedAgentStackTargetPhaseV1::Uncertain
                    && row.restricted_request().is_some()
            }));
    }

    #[test]
    fn restricted_pair_rejects_order_pins_and_non_pending_state() {
        let fixture = fixture_bundle();
        let carriers = [
            restricted_carrier(&fixture.predecessors[0], 0x31),
            restricted_carrier(&fixture.predecessors[1], 0x41),
        ];
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let pair = [prepared.pending_targets()[0], prepared.pending_targets()[1]];
        let before = journal.durable_wire().expect("pending").to_vec();
        let forged_draft = paraegox_runtime_contracts::distributed_agent_stack_plan::DistributedAgentStackRestrictedApplyRequestDraftV1::try_new(
            fixture.rollout.requests()[0].clone(),
            carriers[0].clone(),
        )
        .expect("forged PXRC draft");
        let forged_signature = SigningKey::from_bytes(&[0xfa; 32]).sign(
            forged_draft
                .signing_transcript()
                .expect("forged transcript")
                .as_bytes(),
        );
        let forged = forged_draft
            .finalize(&forged_signature.to_bytes())
            .expect("structural forged PXRC");
        assert!(
            validate_distributed_agent_stack_restricted_apply_v1(
                &fixture.predecessors[0],
                &fixture.rollout.requests()[0],
                forged,
            )
            .is_err()
        );
        assert!(matches!(
            journal.prepare_restricted_pair_for_preflight(
                pair,
                [carriers[1].clone(), carriers[0].clone()],
                [&fixture.predecessors[0], &fixture.predecessors[1]],
                &controller_signer(),
            ),
            Err(DistributedAgentStackApplyError::RestrictedPairOrderMismatch)
        ));

        let wrong_pin = RestrictedRuntimeApplyCarrierBindingV1::try_new(
            RestrictedRuntimeApplyCarrierBindingFieldsV1 {
                target: carriers[0].target(),
                runtime_principal: carriers[0].runtime_principal(),
                controller_principal: carriers[0].controller_principal(),
                endpoint_ref: carriers[0].endpoint_ref(),
                endpoint_generation: carriers[0].endpoint_generation(),
                route: carriers[0].route(),
                controller_request_key: carriers[0].controller_request_key(),
                controller_request_key_fingerprint: Digest32::from_bytes([0xee; 32]),
                runtime_response_key: carriers[0].runtime_response_key(),
                runtime_response_key_fingerprint: carriers[0].runtime_response_key_fingerprint(),
                control_transport_profile_ref: carriers[0].control_transport_profile_ref(),
                control_transport_profile_digest: carriers[0].control_transport_profile_digest(),
            },
        )
        .expect("structurally valid but unpinned carrier");
        assert!(matches!(
            journal.prepare_restricted_pair_for_preflight(
                pair,
                [wrong_pin, carriers[1].clone()],
                [&fixture.predecessors[0], &fixture.predecessors[1]],
                &controller_signer(),
            ),
            Err(DistributedAgentStackApplyError::Producer(_))
        ));
        assert_eq!(journal.durable_wire(), Some(before.as_slice()));

        let stale_preflighted = journal
            .prepare_restricted_pair_for_preflight(
                pair,
                carriers.clone(),
                [&fixture.predecessors[0], &fixture.predecessors[1]],
                &controller_signer(),
            )
            .expect("preflight pair before concurrent state change");
        journal
            .claim_send_with(pair[0], |_| Ok(()))
            .expect("make one target non-Pending");
        assert!(matches!(
            journal.claim_preflighted_restricted_pair_with(stale_preflighted, |_| panic!(
                "stale preflight pair never commits"
            ),),
            Err(DistributedAgentStackApplyError::PreparedTokenMismatch)
        ));
        assert!(matches!(
            journal.prepare_restricted_pair_for_preflight(
                pair,
                carriers,
                [&fixture.predecessors[0], &fixture.predecessors[1]],
                &controller_signer(),
            ),
            Err(DistributedAgentStackApplyError::PreparedTokenMismatch)
        ));
    }

    #[test]
    fn restricted_restart_has_correlation_only_and_two_receipts_converge_independently() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let pair = [prepared.pending_targets()[0], prepared.pending_targets()[1]];
        let restricted_prepared = journal
            .prepare_restricted_pair_for_preflight(
                pair,
                [
                    restricted_carrier(&fixture.predecessors[0], 0x31),
                    restricted_carrier(&fixture.predecessors[1], 0x41),
                ],
                [&fixture.predecessors[0], &fixture.predecessors[1]],
                &controller_signer(),
            )
            .expect("pair for two async Fabric preflights");
        assert!(
            restricted_prepared
                .targets()
                .iter()
                .all(|target| !target.canonical_request_bytes().is_empty())
        );
        let [first_action, second_action] = journal
            .claim_preflighted_restricted_pair_with(restricted_prepared, |_| Ok(()))
            .expect("pair claim");
        let first_correlation = first_action.into_terminal_correlation();
        let second_receipt = restricted_terminal_receipt(
            second_action.request(),
            &fixture.rollout.requests()[1],
            &fixture.predecessors[1],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(fixture.rollout.requests()[1].target()),
        );
        let durable_claim = journal.durable_wire().expect("pair claim").to_vec();
        assert_eq!(&durable_claim[..6], b"PXDJ\0\x03");
        let mut reopened = DistributedAgentStackApplyJournalV1::try_reopen(
            &durable_claim,
            owner_anchor(),
            [&fixture.predecessors[0], &fixture.predecessors[1]],
        )
        .expect("v3 restart reauthenticates both PXRC values");
        assert_eq!(
            reopened
                .restricted_terminal_correlation(pair[0].target)
                .expect("first response correlation"),
            first_correlation
        );
        assert!(matches!(
            reopened.prepared_target(pair[0].target),
            Err(DistributedAgentStackApplyError::OpaqueReplayForbidden)
        ));

        let first_receipt = restricted_terminal_receipt(
            reopened.state().expect("state").targets()[0]
                .restricted_request()
                .expect("durable PXRC"),
            &fixture.rollout.requests()[0],
            &fixture.predecessors[0],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(fixture.rollout.requests()[0].target()),
        );
        let before_cross_carrier = reopened.durable_wire().expect("pair claim").to_vec();
        assert!(matches!(
            reopened.consume_recovered_restricted_terminal_with(
                first_correlation,
                second_receipt.canonical_wire(),
                &fixture.predecessors[0],
                |_| panic!("cross-carrier receipt never commits"),
            ),
            Err(DistributedAgentStackApplyError::RestrictedTerminalMismatch)
        ));
        assert_eq!(
            reopened.durable_wire(),
            Some(before_cross_carrier.as_slice())
        );
        let first = reopened
            .consume_recovered_restricted_terminal_with(
                first_correlation,
                first_receipt.canonical_wire(),
                &fixture.predecessors[0],
                |_| Ok(()),
            )
            .expect("first independent PXDS v2");
        assert_eq!(
            first.rollout_status(),
            DistributedAgentStackRolloutStatusV1::Uncertain
        );
        assert_eq!(
            first.canonical_receipt_bytes(),
            first_receipt.canonical_wire()
        );
        assert!(!first.replayed_from_durable_state());

        let wrong_signature = restricted_terminal_receipt(
            second_action.request(),
            &fixture.rollout.requests()[1],
            &fixture.predecessors[1],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &SigningKey::from_bytes(&[0xf3; 32]),
        );
        let before_wrong = reopened.durable_wire().expect("first receipt").to_vec();
        assert!(matches!(
            reopened.consume_restricted_terminal_with(
                second_action,
                wrong_signature.canonical_wire(),
                &fixture.predecessors[1],
                |_| panic!("wrong Runtime key never commits"),
            ),
            Err(DistributedAgentStackApplyError::RestrictedTerminalMismatch)
        ));
        assert_eq!(reopened.durable_wire(), Some(before_wrong.as_slice()));

        let second_correlation = reopened
            .restricted_terminal_correlation(pair[1].target)
            .expect("second recovered correlation after failed response");
        let second = reopened
            .consume_recovered_restricted_terminal_with(
                second_correlation,
                second_receipt.canonical_wire(),
                &fixture.predecessors[1],
                |_| Ok(()),
            )
            .expect("second independent PXDS v2");
        assert_eq!(second.target(), pair[1].target);
        assert_eq!(
            second.outcome(),
            DistributedAgentStackTerminalOutcomeV1::ActiveReady
        );
        assert_eq!(
            second.rollout_status(),
            DistributedAgentStackRolloutStatusV1::ActiveReady
        );
        let replay = reopened
            .restricted_terminal_replay(pair[0].target)
            .expect("durable v2 replay");
        assert!(replay.replayed_from_durable_state());
        assert!(matches!(
            reopened.restricted_terminal_correlation(pair[0].target),
            Err(DistributedAgentStackApplyError::OpaqueReplayForbidden)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn restricted_dispatch_pair_verifies_and_durably_converges_both_responses() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let pair = [prepared.pending_targets()[0], prepared.pending_targets()[1]];
        let restricted_prepared = journal
            .prepare_restricted_pair_for_preflight(
                pair,
                [
                    restricted_carrier(&fixture.predecessors[0], 0x31),
                    restricted_carrier(&fixture.predecessors[1], 0x41),
                ],
                [&fixture.predecessors[0], &fixture.predecessors[1]],
                &controller_signer(),
            )
            .expect("restricted pair");
        let [first_action, second_action] = journal
            .claim_preflighted_restricted_pair_with(restricted_prepared, |_| Ok(()))
            .expect("durable restricted claim");
        let first_target = first_action.target();
        let second_target = second_action.target();
        let first_receipt = restricted_terminal_receipt(
            first_action.request(),
            &fixture.rollout.requests()[0],
            &fixture.predecessors[0],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(first_target),
        );
        let second_receipt = restricted_terminal_receipt(
            second_action.request(),
            &fixture.rollout.requests()[1],
            &fixture.predecessors[1],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(second_target),
        );
        let outcomes = [
            DistributedAgentStackRestrictedDispatchOutcomeV1 {
                target: first_target,
                correlation: first_action.into_terminal_correlation(),
                transport_result: Ok(first_receipt.canonical_wire().into()),
            },
            DistributedAgentStackRestrictedDispatchOutcomeV1 {
                target: second_target,
                correlation: second_action.into_terminal_correlation(),
                transport_result: Ok(second_receipt.canonical_wire().into()),
            },
        ];
        let mut committed_targets = Vec::new();
        let [first, second] = journal.consume_restricted_dispatch_pair_with(
            outcomes,
            [&fixture.predecessors[0], &fixture.predecessors[1]],
            |target, wire| {
                assert_eq!(&wire[..6], b"PXDJ\0\x03");
                committed_targets.push(target);
                Ok(())
            },
        );
        assert_eq!(first.target(), first_target);
        assert_eq!(second.target(), second_target);
        let first = first.into_terminal_result().expect("first durable PXDS v2");
        let second = second
            .into_terminal_result()
            .expect("second durable PXDS v2");
        assert_eq!(first.target(), first_target);
        assert_eq!(
            first.rollout_status(),
            DistributedAgentStackRolloutStatusV1::Uncertain
        );
        assert_eq!(second.target(), second_target);
        assert_eq!(
            second.rollout_status(),
            DistributedAgentStackRolloutStatusV1::ActiveReady
        );
        assert_eq!(committed_targets, [first_target, second_target]);
        assert_eq!(
            journal.status(),
            Some(DistributedAgentStackRolloutStatusV1::ActiveReady)
        );
    }

    #[cfg(unix)]
    #[test]
    fn restricted_dispatch_pair_keeps_validation_results_independent() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let pair = [prepared.pending_targets()[0], prepared.pending_targets()[1]];
        let restricted_prepared = journal
            .prepare_restricted_pair_for_preflight(
                pair,
                [
                    restricted_carrier(&fixture.predecessors[0], 0x31),
                    restricted_carrier(&fixture.predecessors[1], 0x41),
                ],
                [&fixture.predecessors[0], &fixture.predecessors[1]],
                &controller_signer(),
            )
            .expect("restricted pair");
        let [first_action, second_action] = journal
            .claim_preflighted_restricted_pair_with(restricted_prepared, |_| Ok(()))
            .expect("durable restricted claim");
        let first_target = first_action.target();
        let second_target = second_action.target();
        let wrong_first_receipt = restricted_terminal_receipt(
            first_action.request(),
            &fixture.rollout.requests()[0],
            &fixture.predecessors[0],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &SigningKey::from_bytes(&[0xf4; 32]),
        );
        let second_receipt = restricted_terminal_receipt(
            second_action.request(),
            &fixture.rollout.requests()[1],
            &fixture.predecessors[1],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(second_target),
        );
        let first_correlation = first_action.into_terminal_correlation();
        let second_correlation = second_action.into_terminal_correlation();
        let before_cross_target = journal.durable_wire().expect("pair claim").to_vec();
        let [cross_first, cross_second] = journal.consume_restricted_dispatch_pair_with(
            [
                DistributedAgentStackRestrictedDispatchOutcomeV1 {
                    target: first_target,
                    correlation: second_correlation,
                    transport_result: Ok(wrong_first_receipt.canonical_wire().into()),
                },
                DistributedAgentStackRestrictedDispatchOutcomeV1 {
                    target: second_target,
                    correlation: first_correlation,
                    transport_result: Ok(second_receipt.canonical_wire().into()),
                },
            ],
            [&fixture.predecessors[0], &fixture.predecessors[1]],
            |_, _| panic!("cross-target responses never publish"),
        );
        assert!(matches!(
            cross_first.terminal_result(),
            Err(DistributedAgentStackRestrictedTerminalizeErrorV1::OutcomeCorrelationMismatch)
        ));
        assert!(matches!(
            cross_second.terminal_result(),
            Err(DistributedAgentStackRestrictedTerminalizeErrorV1::OutcomeCorrelationMismatch)
        ));
        assert_eq!(journal.durable_wire(), Some(before_cross_target.as_slice()));
        let outcomes = [
            DistributedAgentStackRestrictedDispatchOutcomeV1 {
                target: first_target,
                correlation: first_correlation,
                transport_result: Ok(wrong_first_receipt.canonical_wire().into()),
            },
            DistributedAgentStackRestrictedDispatchOutcomeV1 {
                target: second_target,
                correlation: second_correlation,
                transport_result: Ok(second_receipt.canonical_wire().into()),
            },
        ];
        let mut committed_targets = Vec::new();
        let [first, second] = journal.consume_restricted_dispatch_pair_with(
            outcomes,
            [&fixture.predecessors[0], &fixture.predecessors[1]],
            |target, _| {
                committed_targets.push(target);
                Ok(())
            },
        );
        assert!(matches!(
            first.terminal_result(),
            Err(DistributedAgentStackRestrictedTerminalizeErrorV1::Terminal(
                DistributedAgentStackApplyError::RestrictedTerminalMismatch,
            ))
        ));
        assert!(second.terminal_result().is_ok());
        assert_eq!(committed_targets, [second_target]);
        assert_eq!(
            journal.state().expect("one durable response").targets()[0].phase(),
            DistributedAgentStackTargetPhaseV1::Uncertain
        );
        assert_eq!(
            journal.state().expect("one durable response").targets()[1].phase(),
            DistributedAgentStackTargetPhaseV1::ReceiptDurable
        );
    }

    #[cfg(unix)]
    #[test]
    fn restricted_dispatch_pair_stops_after_durability_failure_without_losing_response() {
        let fixture = fixture_bundle();
        let mut journal = DistributedAgentStackApplyJournalV1::empty();
        let prepared = journal
            .prepare_with(owner_anchor(), fixture.rollout.clone(), |_| Ok(()))
            .expect("prepare");
        let pair = [prepared.pending_targets()[0], prepared.pending_targets()[1]];
        let restricted_prepared = journal
            .prepare_restricted_pair_for_preflight(
                pair,
                [
                    restricted_carrier(&fixture.predecessors[0], 0x31),
                    restricted_carrier(&fixture.predecessors[1], 0x41),
                ],
                [&fixture.predecessors[0], &fixture.predecessors[1]],
                &controller_signer(),
            )
            .expect("restricted pair");
        let [first_action, second_action] = journal
            .claim_preflighted_restricted_pair_with(restricted_prepared, |_| Ok(()))
            .expect("durable restricted claim");
        let first_target = first_action.target();
        let second_target = second_action.target();
        let first_receipt = restricted_terminal_receipt(
            first_action.request(),
            &fixture.rollout.requests()[0],
            &fixture.predecessors[0],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(first_target),
        );
        let second_receipt = restricted_terminal_receipt(
            second_action.request(),
            &fixture.rollout.requests()[1],
            &fixture.predecessors[1],
            DistributedAgentStackTerminalOutcomeV1::ActiveReady,
            &runtime_signer(second_target),
        );
        let first_receipt_bytes = first_receipt.canonical_wire().to_vec();
        let second_receipt_bytes = second_receipt.canonical_wire().to_vec();
        let first_correlation = first_action.into_terminal_correlation();
        let second_correlation = second_action.into_terminal_correlation();
        let outcomes = [
            DistributedAgentStackRestrictedDispatchOutcomeV1 {
                target: first_target,
                correlation: first_correlation,
                transport_result: Ok(first_receipt_bytes.clone().into_boxed_slice()),
            },
            DistributedAgentStackRestrictedDispatchOutcomeV1 {
                target: second_target,
                correlation: second_correlation,
                transport_result: Ok(second_receipt_bytes.clone().into_boxed_slice()),
            },
        ];
        let before = journal.durable_wire().expect("durable pair claim").to_vec();
        let mut commit_calls = Vec::new();
        let [first, second] = journal.consume_restricted_dispatch_pair_with(
            outcomes,
            [&fixture.predecessors[0], &fixture.predecessors[1]],
            |target, _| {
                commit_calls.push(target);
                Err(DistributedAgentStackStoreError::DurabilityRejected)
            },
        );
        let first_error = first
            .into_terminal_result()
            .expect_err("first durable publish remains ambiguous");
        assert!(matches!(
            first_error.durability_primary(),
            Some(DistributedAgentStackApplyError::Store(
                DistributedAgentStackStoreError::DurabilityRejected,
            ))
        ));
        let retained_first = first_error
            .recoverable_dispatch_outcome()
            .expect("borrowed ambiguous first response");
        assert_eq!(retained_first.target(), first_target);
        assert_eq!(retained_first.correlation(), first_correlation);
        let (first_primary, retained_first) = first_error
            .into_durability_failure_parts()
            .expect("owned primary and ambiguous first response");
        assert!(matches!(
            first_primary,
            DistributedAgentStackApplyError::Store(
                DistributedAgentStackStoreError::DurabilityRejected,
            )
        ));
        assert_eq!(
            retained_first
                .into_transport_result()
                .expect("first PXDS v2 bytes")
                .as_ref(),
            first_receipt_bytes.as_slice()
        );
        let second_error = second
            .into_terminal_result()
            .expect_err("second response is retained, not published");
        assert_eq!(second_error.failed_durability_target(), Some(first_target));
        let retained = second_error
            .unprocessed_dispatch_outcome()
            .expect("borrowed unprocessed response");
        assert_eq!(retained.target(), second_target);
        assert_eq!(retained.correlation(), second_correlation);
        let (failed_target, retained) = second_error
            .into_unprocessed_after_durability_parts()
            .expect("owned failed target and unprocessed response");
        assert_eq!(failed_target, first_target);
        assert_eq!(
            retained
                .into_transport_result()
                .expect("PXDS v2 bytes")
                .as_ref(),
            second_receipt_bytes.as_slice()
        );
        assert_eq!(commit_calls, [first_target]);
        assert_eq!(journal.durable_wire(), Some(before.as_slice()));
    }

    #[test]
    fn restricted_dispatch_terminalization_seals_verify_commit_and_no_resend_order() {
        let source = include_str!("distributed_agent_stack_apply.rs");
        let start = source
            .find("pub(crate) fn consume_restricted_dispatch_pair_with")
            .expect("restricted terminalization seam");
        let tail = &source[start..];
        let end = tail
            .find("/// Reconstructs only response correlation")
            .expect("terminalization seam end");
        let wrapper = &tail[..end];
        let admissions = wrapper.find("let admissions").expect("pair admissions");
        let first_consume = wrapper
            .find(".consume_restricted_dispatch_outcome_with(")
            .expect("first terminal reducer");
        let stop = wrapper
            .find("if first_durability_failed")
            .expect("durability stop boundary");
        let second_consume = wrapper
            .rfind("self.consume_restricted_dispatch_outcome_with(")
            .expect("second terminal reducer");
        assert!(admissions < first_consume);
        assert!(first_consume < stop);
        assert!(stop < second_consume);
        assert!(wrapper.contains("UnprocessedAfterDurabilityFailure"));
        assert!(wrapper.contains("consume_recovered_restricted_terminal_with"));
        assert!(!wrapper.contains("send_once"));
        assert!(!wrapper.contains("preflight"));
        assert!(!wrapper.contains("RestrictedRuntimeApplyClientV1"));

        let verify = source
            .find("let verified = validate_distributed_agent_stack_terminal_v2")
            .expect("pinned PXDS v2 verifier");
        let terminal_commit = source[verify..]
            .find("self.store.commit_with(next, commit)?")
            .expect("durable terminal commit");
        assert!(terminal_commit > 0);
        assert!(source.contains("validate_restricted_correlation(state, outcome.correlation)"));
    }

    #[test]
    fn restricted_owner_wrapper_seals_preflight_claim_and_concurrent_send_order() {
        let source = include_str!("distributed_agent_stack_apply.rs");
        let start = source
            .find("pub(crate) async fn preflight_claim_and_dispatch_restricted_pair_with")
            .expect("restricted owner wrapper");
        let tail = &source[start..];
        let end = tail
            .find("/// Reconstructs only response correlation")
            .expect("wrapper end");
        let wrapper = &tail[..end];
        let preflights = wrapper
            .match_indices(".preflight(")
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        assert_eq!(preflights.len(), 2);
        let target_matches = wrapper
            .match_indices(".matches_restricted_target(")
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        assert_eq!(target_matches.len(), 2);
        assert_eq!(wrapper.match_indices(".binding_digest(),").count(), 2);
        assert!(target_matches[1] < preflights[0]);
        let claim = wrapper
            .find("claim_preflighted_restricted_pair_with")
            .expect("single pair claim");
        assert!(claim > preflights[1]);
        assert_eq!(
            wrapper.match_indices("into_terminal_correlation()").count(),
            2
        );
        let consume_actions = wrapper
            .rfind("into_terminal_correlation()")
            .expect("both actions consumed");
        let concurrent_send = wrapper.find("tokio::join!(").expect("concurrent sends");
        assert!(consume_actions > claim);
        assert!(concurrent_send > consume_actions);
        assert_eq!(wrapper.match_indices(".send_once()").count(), 2);
        assert!(wrapper.contains("DistributedAgentStackRestrictedDispatchOutcomeV1"));
        let production = source
            .split_once("#[cfg(test)]\nmod tests")
            .map(|(production, _)| production)
            .expect("test module boundary");
        assert!(production.contains("\nstruct DistributedAgentStackRestrictedSendActionV1"));
        assert!(production.contains("\n    fn claim_preflighted_restricted_pair_with<Commit>"));
        assert!(
            !production.contains("pub(crate) fn claim_preflighted_restricted_pair_with<Commit>")
        );
    }

    #[test]
    fn restricted_connector_owner_seam_orders_config_start_dispatch_and_shutdown() {
        let source = include_str!("distributed_agent_stack_apply.rs");
        let start = source
            .find("pub(crate) async fn start_dispatch_and_shutdown_restricted_pair_with")
            .expect("restricted connector owner seam");
        let tail = &source[start..];
        let end = tail
            .find("/// Reconstructs only response correlation")
            .expect("connector seam end");
        let wrapper = &tail[..end];

        let configs = wrapper
            .match_indices("RestrictedRuntimeApplyClientConfigV1::try_from_transport_profile")
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        let starts = wrapper
            .match_indices("RestrictedRuntimeApplyClientV1::start(")
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        assert_eq!(configs.len(), 2);
        assert_eq!(starts.len(), 2);
        assert!(configs[1] < starts[0]);
        assert!(starts[0] < starts[1]);
        assert!(wrapper.contains("prepared.targets()[0].carrier()"));
        assert!(wrapper.contains("prepared.targets()[1].carrier()"));

        let dispatch = wrapper
            .find("preflight_claim_and_dispatch_restricted_pair_with")
            .expect("dispatch after both starts");
        assert!(dispatch > starts[1]);
        let second_start_cleanup = wrapper
            .find("let first_shutdown = first_client.shutdown().await;")
            .expect("first connector cleanup after second start failure");
        assert!(second_start_cleanup > starts[1]);
        assert!(second_start_cleanup < dispatch);
        assert!(wrapper.contains("DistributedAgentStackRestrictedConnectorErrorV1::SecondStart"));

        let concurrent_shutdown = wrapper
            .find("tokio::join!(first_client.shutdown(), second_client.shutdown())")
            .expect("concurrent explicit connector shutdown");
        let finish = wrapper
            .find("finish_restricted_connector_dispatch")
            .expect("primary/cleanup result composition");
        assert!(concurrent_shutdown > dispatch);
        assert!(finish > concurrent_shutdown);
    }

    #[cfg(unix)]
    #[test]
    fn restricted_connector_finish_preserves_primary_cleanup_and_per_target_results() {
        fn outcomes() -> [DistributedAgentStackRestrictedDispatchOutcomeV1; 2] {
            [0x31, 0x32].map(|seed| {
                let target = RuntimeHostId::from_bytes([seed; 16]);
                DistributedAgentStackRestrictedDispatchOutcomeV1 {
                    target,
                    correlation: DistributedAgentStackRestrictedTerminalCorrelationV1 {
                        owner_anchor: Digest32::from_bytes([seed + 1; 32]),
                        rollout_id: DistributedAgentStackRolloutIdV1::try_from_bytes(
                            [seed + 2; 16],
                        )
                        .expect("rollout identity"),
                        target,
                        restricted_request_digest: Digest32::from_bytes([seed + 3; 32]),
                        carrier_digest: Digest32::from_bytes([seed + 4; 32]),
                    },
                    transport_result: Ok(vec![seed].into_boxed_slice()),
                }
            })
        }

        let completed = finish_restricted_connector_dispatch(Ok(outcomes()), Ok(()), Ok(()))
            .expect("dispatch and both shutdowns");
        assert_eq!(completed[0].target(), RuntimeHostId::from_bytes([0x31; 16]));
        assert_eq!(completed[1].target(), RuntimeHostId::from_bytes([0x32; 16]));

        let second_start = DistributedAgentStackRestrictedConnectorErrorV1::SecondStart {
            primary: RestrictedRuntimeApplyErrorV1::SessionOpenFailed,
            first_shutdown: Err(RestrictedRuntimeApplyErrorV1::SessionCloseFailed),
        };
        assert!(matches!(
            second_start.shutdown_results(),
            [
                Some(Err(RestrictedRuntimeApplyErrorV1::SessionCloseFailed)),
                None
            ]
        ));

        let cleanup_failure = finish_restricted_connector_dispatch(
            Ok(outcomes()),
            Err(RestrictedRuntimeApplyErrorV1::SessionCloseFailed),
            Ok(()),
        )
        .expect_err("cleanup failure must remain visible");
        let retained_outcomes = cleanup_failure
            .dispatched_outcomes()
            .expect("successful per-target results remain extractable");
        assert_eq!(
            retained_outcomes[0].target(),
            RuntimeHostId::from_bytes([0x31; 16])
        );
        let cleanup_results = cleanup_failure.shutdown_results();
        assert!(cleanup_results[0].is_some());
        assert!(cleanup_results[1].is_some());
        let (retained_outcomes, cleanup_results) = cleanup_failure
            .into_shutdown_after_dispatch_parts()
            .expect("owned per-target and cleanup results remain extractable");
        let [first_outcome, second_outcome] = retained_outcomes;
        assert_eq!(
            first_outcome.target(),
            RuntimeHostId::from_bytes([0x31; 16])
        );
        assert_eq!(
            second_outcome.target(),
            RuntimeHostId::from_bytes([0x32; 16])
        );
        assert_eq!(
            first_outcome
                .into_transport_result()
                .expect("first response")
                .as_ref(),
            &[0x31]
        );
        assert!(matches!(
            cleanup_results,
            [
                Err(RestrictedRuntimeApplyErrorV1::SessionCloseFailed),
                Ok(())
            ]
        ));

        let primary_and_cleanup = finish_restricted_connector_dispatch(
            Err(
                DistributedAgentStackRestrictedDispatchErrorV1::SecondPreflight(
                    RestrictedRuntimeApplyErrorV1::OperationTimedOut,
                ),
            ),
            Err(RestrictedRuntimeApplyErrorV1::QuerierUndeclarationFailed),
            Err(RestrictedRuntimeApplyErrorV1::SessionCloseFailed),
        )
        .expect_err("primary and cleanup failures must both remain visible");
        assert!(primary_and_cleanup.dispatch_primary().is_some());
        let cleanup_results = primary_and_cleanup.shutdown_results();
        assert!(cleanup_results[0].is_some());
        assert!(cleanup_results[1].is_some());
        let (primary, cleanup_results) = primary_and_cleanup
            .into_dispatch_failure_parts()
            .expect("owned primary and cleanup results remain extractable");
        assert!(matches!(
            primary,
            DistributedAgentStackRestrictedDispatchErrorV1::SecondPreflight(
                RestrictedRuntimeApplyErrorV1::OperationTimedOut,
            )
        ));
        assert!(matches!(
            cleanup_results,
            [
                Err(RestrictedRuntimeApplyErrorV1::QuerierUndeclarationFailed),
                Err(RestrictedRuntimeApplyErrorV1::SessionCloseFailed),
            ]
        ));
    }

    #[test]
    fn owner_authority_handles_are_not_clone_derived() {
        fn derive_block_before<'a>(source: &'a str, declaration: &str) -> &'a str {
            let position = source.find(declaration).expect("type declaration");
            source[..position]
                .rsplit("\n\n")
                .next()
                .expect("derive block")
        }
        let apply_source = include_str!("distributed_agent_stack_apply.rs");
        let store_source = include_str!("distributed_agent_stack_store.rs");
        assert!(
            !derive_block_before(
                apply_source,
                "pub(crate) struct DistributedAgentStackSendActionV1"
            )
            .contains("Clone")
        );
        assert!(
            !derive_block_before(
                apply_source,
                "pub(crate) struct DistributedAgentStackApplyJournalV1"
            )
            .contains("Clone")
        );
        assert!(
            !derive_block_before(
                apply_source,
                "struct DistributedAgentStackRestrictedSendActionV1"
            )
            .contains("Clone")
        );
        assert!(
            !derive_block_before(
                apply_source,
                "pub(crate) struct PreparedDistributedAgentStackRestrictedPairV1"
            )
            .contains("Clone")
        );
        assert!(
            !derive_block_before(
                apply_source,
                "pub(crate) struct DistributedAgentStackRestrictedDispatchOutcomeV1"
            )
            .contains("Clone")
        );
        assert!(
            !derive_block_before(
                store_source,
                "pub(crate) struct DistributedAgentStackDurableStoreV1"
            )
            .contains("Clone")
        );
    }
}
