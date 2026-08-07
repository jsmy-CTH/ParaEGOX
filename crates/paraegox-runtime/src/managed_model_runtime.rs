//! Runtime-owned lifecycle assembly for one managed Model service.
//!
//! The Model service is a provider-neutral capacity owner. Process composition
//! resolves the exact committed provider and adapter selection, while Runtime
//! repeats the complete plan comparison before installing the backend. The
//! Agent-facing dependency handle is generation fenced and never falls back to
//! an embedded or deterministic provider.

use core::{fmt, time::Duration};
use std::sync::{Arc, Mutex, Weak};

use paraegox_agent_contracts::AgentConversationRequestV1;
use paraegox_agent_service::{
    AgentConversationModelCancellation, AgentConversationModelFuture,
    AgentConversationModelOutcomeV1, AgentConversationModelProvider,
    AgentConversationModelServiceProviderV1,
};
use paraegox_kernel::time::MonotonicDeadline;
use paraegox_model::{
    ModelBackendIdentityV1, ModelBackendV1, ModelServiceConfigV1, ModelServiceV1,
};
use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
    ManagedModelCapabilityIdV1, ManagedModelServicePlanV1,
};
use paraegox_runtime_contracts::managed_service::{
    ManagedServiceGeneration, ManagedServiceId, ManagedServiceLifecycleStage,
};

use crate::managed_service_assembly::{
    ManagedServiceAssembly, ManagedServiceAttempt, ManagedServiceCompletion, ManagedServiceContext,
    ManagedServiceFuture, ManagedServiceImplementation, ManagedServiceReadiness,
    ManagedServiceStageFact, ManagedServiceStartupOutcome,
};
use crate::runtime_clock::RuntimeClock;
use crate::task_registry::CancellationSource;

type SharedModelService = ModelServiceV1<Arc<dyn ModelBackendV1>>;

/// Stable, display-safe failure from process-composition backend resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeModelBackendResolveError {
    ResolutionFailed,
}

impl fmt::Display for RuntimeModelBackendResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Runtime model backend resolution failed closed")
    }
}

impl std::error::Error for RuntimeModelBackendResolveError {}

/// A concrete backend and the complete managed plan that its resolver built.
///
/// Runtime compares `plan` with committed desired state before the backend can
/// own capacity. Debug deliberately never traverses or formats the backend.
pub struct RuntimeResolvedModelBackendV1 {
    plan: ManagedModelServicePlanV1,
    backend: Arc<dyn ModelBackendV1>,
}

impl RuntimeResolvedModelBackendV1 {
    #[must_use]
    pub fn new<B>(plan: ManagedModelServicePlanV1, backend: B) -> Self
    where
        B: ModelBackendV1,
    {
        Self {
            plan,
            backend: Arc::new(backend),
        }
    }

    #[must_use]
    pub fn from_shared(plan: ManagedModelServicePlanV1, backend: Arc<dyn ModelBackendV1>) -> Self {
        Self { plan, backend }
    }

    #[must_use]
    pub const fn plan(&self) -> &ManagedModelServicePlanV1 {
        &self.plan
    }

    fn into_parts(self) -> (ManagedModelServicePlanV1, Arc<dyn ModelBackendV1>) {
        (self.plan, self.backend)
    }
}

impl fmt::Debug for RuntimeResolvedModelBackendV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeResolvedModelBackendV1")
            .field("plan", &self.plan)
            .field("backend", &"<redacted-backend>")
            .finish()
    }
}

/// Repeatable process-composition seam for one exact managed Model plan.
///
/// A resolver may own Secret material, but it must return the complete plan it
/// resolved. Runtime admits no partial provider echo and supplies no fallback.
pub trait RuntimeModelBackendResolverV1: Send + Sync + 'static {
    fn resolve(
        &self,
        plan: &ManagedModelServicePlanV1,
    ) -> Result<RuntimeResolvedModelBackendV1, RuntimeModelBackendResolveError>;
}

#[derive(Debug)]
pub(crate) struct UnavailableRuntimeModelBackendResolver;

impl RuntimeModelBackendResolverV1 for UnavailableRuntimeModelBackendResolver {
    fn resolve(
        &self,
        _plan: &ManagedModelServicePlanV1,
    ) -> Result<RuntimeResolvedModelBackendV1, RuntimeModelBackendResolveError> {
        Err(RuntimeModelBackendResolveError::ResolutionFailed)
    }
}

/// Agent-facing capability for exactly one live Model service generation.
///
/// Cloning this value does not extend service lifetime. Every call upgrades a
/// weak owner reference and rechecks Model identity, generation, consuming
/// Agent identity, capability, and Ready state before no-queue admission.
#[derive(Clone)]
pub(crate) struct ManagedModelDependencyHandle {
    model_service_id: ManagedServiceId,
    model_generation: ManagedServiceGeneration,
    consumer_agent_service_id: ManagedServiceId,
    capability_id: ManagedModelCapabilityIdV1,
    slot: Weak<ManagedModelSlot>,
}

impl ManagedModelDependencyHandle {
    #[must_use]
    pub(crate) const fn model_service_id(&self) -> ManagedServiceId {
        self.model_service_id
    }

    #[must_use]
    pub(crate) const fn model_generation(&self) -> ManagedServiceGeneration {
        self.model_generation
    }

    #[must_use]
    pub(crate) const fn consumer_agent_service_id(&self) -> ManagedServiceId {
        self.consumer_agent_service_id
    }

    #[must_use]
    pub(crate) const fn capability_id(&self) -> ManagedModelCapabilityIdV1 {
        self.capability_id
    }

    fn failed() -> AgentConversationModelFuture {
        Box::pin(std::future::ready(AgentConversationModelOutcomeV1::Failed))
    }
}

impl fmt::Debug for ManagedModelDependencyHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedModelDependencyHandle")
            .field("model_service_id", &self.model_service_id)
            .field("model_generation", &self.model_generation)
            .field("consumer_agent_service_id", &self.consumer_agent_service_id)
            .field("capability_id", &self.capability_id)
            .finish_non_exhaustive()
    }
}

impl AgentConversationModelProvider for ManagedModelDependencyHandle {
    fn complete(
        &mut self,
        request: AgentConversationRequestV1,
        cancellation: AgentConversationModelCancellation,
    ) -> AgentConversationModelFuture {
        if self.capability_id != ManagedModelCapabilityIdV1::bounded_text_v1() {
            return Self::failed();
        }
        let Some(slot) = self.slot.upgrade() else {
            return Self::failed();
        };
        if slot.model_service_id != self.model_service_id
            || slot.model_generation != self.model_generation
            || slot.consumer_agent_service_id != self.consumer_agent_service_id
            || slot.capability_id != self.capability_id
        {
            return Self::failed();
        }

        // Invocation construction happens while the state lock still proves
        // Ready. ModelService increments its in-flight lease synchronously, so
        // drain cannot pass this admission point and miss the operation.
        let Ok(state) = slot.state.lock() else {
            return Self::failed();
        };
        let ManagedModelSlotState::Ready(service) = &*state else {
            return Self::failed();
        };
        let mut provider = AgentConversationModelServiceProviderV1::new(service.clone());
        provider.complete(request, cancellation)
    }
}

struct ManagedModelSlot {
    model_service_id: ManagedServiceId,
    model_generation: ManagedServiceGeneration,
    consumer_agent_service_id: ManagedServiceId,
    capability_id: ManagedModelCapabilityIdV1,
    state: Mutex<ManagedModelSlotState>,
}

enum ManagedModelSlotState {
    Cold,
    Prepared,
    Started(SharedModelService),
    Ready(SharedModelService),
    Draining(SharedModelService),
    Stopped,
}

struct RuntimeManagedModelService {
    plan: ManagedModelServicePlanV1,
    generation: ManagedServiceGeneration,
    resolver: Arc<dyn RuntimeModelBackendResolverV1>,
    prepared: Option<RuntimeResolvedModelBackendV1>,
    slot: Arc<ManagedModelSlot>,
}

impl RuntimeManagedModelService {
    fn context_matches(&self, context: &ManagedServiceContext) -> bool {
        context.service_id() == self.plan.service().service_id()
            && context.generation() == self.generation
            && self.slot.model_service_id == context.service_id()
            && self.slot.model_generation == context.generation()
    }

    fn backend_identity_matches(
        plan: &ManagedModelServicePlanV1,
        identity: ModelBackendIdentityV1,
    ) -> bool {
        identity.provider_ref() == plan.provider().provider_ref().as_bytes()
            && identity.config_digest() == plan.provider().config_digest()
    }

    fn service_matches_plan(
        plan: &ManagedModelServicePlanV1,
        service: &SharedModelService,
    ) -> bool {
        let snapshot = service.snapshot();
        Self::backend_identity_matches(plan, snapshot.identity())
            && snapshot.capacity() == usize::from(plan.max_in_flight())
    }

    fn lock_state(&self) -> Option<std::sync::MutexGuard<'_, ManagedModelSlotState>> {
        self.slot.state.lock().ok()
    }
}

impl ManagedServiceImplementation for RuntimeManagedModelService {
    fn prepare<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
        Box::pin(async move {
            if !self.context_matches(context)
                || self.plan.adapter_binding().capability_id()
                    != ManagedModelCapabilityIdV1::bounded_text_v1()
                || self.prepared.is_some()
            {
                return ManagedServiceCompletion::failed(attempt);
            }
            let Ok(resolved) = self.resolver.resolve(&self.plan) else {
                return ManagedServiceCompletion::failed(attempt);
            };
            if resolved.plan() != &self.plan
                || !Self::backend_identity_matches(&self.plan, resolved.backend.identity())
            {
                return ManagedServiceCompletion::failed(attempt);
            }
            let Some(mut state) = self.lock_state() else {
                return ManagedServiceCompletion::failed(attempt);
            };
            if !matches!(*state, ManagedModelSlotState::Cold) {
                return ManagedServiceCompletion::failed(attempt);
            }
            *state = ManagedModelSlotState::Prepared;
            drop(state);
            self.prepared = Some(resolved);
            ManagedServiceCompletion::succeeded(attempt, ())
        })
    }

    fn start<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
        Box::pin(async move {
            if !self.context_matches(context) {
                return ManagedServiceCompletion::failed(attempt);
            }
            let Some(resolved) = self.prepared.take() else {
                return ManagedServiceCompletion::failed(attempt);
            };
            let (resolved_plan, backend) = resolved.into_parts();
            if resolved_plan != self.plan {
                return ManagedServiceCompletion::failed(attempt);
            }
            let Ok(config) = ModelServiceConfigV1::try_new(usize::from(self.plan.max_in_flight()))
            else {
                return ManagedServiceCompletion::failed(attempt);
            };
            let service = ModelServiceV1::new(config, backend);
            if !Self::service_matches_plan(&self.plan, &service) {
                return ManagedServiceCompletion::failed(attempt);
            }
            let Some(mut state) = self.lock_state() else {
                return ManagedServiceCompletion::failed(attempt);
            };
            if !matches!(*state, ManagedModelSlotState::Prepared) {
                return ManagedServiceCompletion::failed(attempt);
            }
            *state = ManagedModelSlotState::Started(service);
            ManagedServiceCompletion::succeeded(attempt, ())
        })
    }

    fn readiness<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<ManagedServiceReadiness>> {
        Box::pin(async move {
            if !self.context_matches(context)
                || self.slot.capability_id != ManagedModelCapabilityIdV1::bounded_text_v1()
            {
                return ManagedServiceCompletion::failed(attempt);
            }
            let Some(mut state) = self.lock_state() else {
                return ManagedServiceCompletion::failed(attempt);
            };
            let ManagedModelSlotState::Started(service) = &*state else {
                return ManagedServiceCompletion::succeeded(
                    attempt,
                    ManagedServiceReadiness::NotReady,
                );
            };
            if !Self::service_matches_plan(&self.plan, service) {
                return ManagedServiceCompletion::succeeded(
                    attempt,
                    ManagedServiceReadiness::NotReady,
                );
            }
            let service = service.clone();
            *state = ManagedModelSlotState::Ready(service);
            ManagedServiceCompletion::succeeded(attempt, ManagedServiceReadiness::Ready)
        })
    }

    fn drain<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
        deadline: MonotonicDeadline,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
        Box::pin(async move {
            if !self.context_matches(context) {
                return ManagedServiceCompletion::failed(attempt);
            }
            let service = {
                let Some(mut state) = self.lock_state() else {
                    return ManagedServiceCompletion::failed(attempt);
                };
                let service = match &*state {
                    ManagedModelSlotState::Started(service)
                    | ManagedModelSlotState::Ready(service)
                    | ManagedModelSlotState::Draining(service) => service.clone(),
                    ManagedModelSlotState::Cold
                    | ManagedModelSlotState::Prepared
                    | ManagedModelSlotState::Stopped => {
                        return ManagedServiceCompletion::succeeded(attempt, ());
                    }
                };
                // Reject every new handle call before observing in-flight.
                *state = ManagedModelSlotState::Draining(service.clone());
                service
            };

            loop {
                if service.snapshot().counters().in_flight() == 0 {
                    return ManagedServiceCompletion::succeeded(attempt, ());
                }
                let Ok(reading) = context.clock_reading() else {
                    return ManagedServiceCompletion::failed(attempt);
                };
                match deadline.is_expired_at(reading) {
                    Ok(false) => tokio::time::sleep(Duration::from_millis(1)).await,
                    Ok(true) | Err(_) => return ManagedServiceCompletion::failed(attempt),
                }
            }
        })
    }

    fn stop<'a>(
        &'a mut self,
        context: &'a ManagedServiceContext,
        attempt: ManagedServiceAttempt,
    ) -> ManagedServiceFuture<'a, ManagedServiceCompletion<()>> {
        Box::pin(async move {
            if !self.context_matches(context) {
                return ManagedServiceCompletion::failed(attempt);
            }
            let Some(mut state) = self.lock_state() else {
                return ManagedServiceCompletion::failed(attempt);
            };
            let can_stop = match &*state {
                ManagedModelSlotState::Cold
                | ManagedModelSlotState::Prepared
                | ManagedModelSlotState::Stopped => true,
                ManagedModelSlotState::Draining(service) => {
                    service.snapshot().counters().in_flight() == 0
                }
                ManagedModelSlotState::Started(_) | ManagedModelSlotState::Ready(_) => false,
            };
            if !can_stop {
                return ManagedServiceCompletion::failed(attempt);
            }
            *state = ManagedModelSlotState::Stopped;
            drop(state);
            self.prepared = None;
            ManagedServiceCompletion::succeeded(attempt, ())
        })
    }
}

/// Exact terminal cleanup evidence for one managed Model generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedModelCleanupEvidenceV1 {
    model_service_id: ManagedServiceId,
    model_generation: ManagedServiceGeneration,
    drain: ManagedServiceStageFact,
    stop: ManagedServiceStageFact,
    exact_zero: bool,
}

impl ManagedModelCleanupEvidenceV1 {
    #[must_use]
    pub(crate) const fn model_service_id(self) -> ManagedServiceId {
        self.model_service_id
    }

    #[must_use]
    pub(crate) const fn model_generation(self) -> ManagedServiceGeneration {
        self.model_generation
    }

    #[must_use]
    pub(crate) const fn drain(self) -> ManagedServiceStageFact {
        self.drain
    }

    #[must_use]
    pub(crate) const fn stop(self) -> ManagedServiceStageFact {
        self.stop
    }

    #[must_use]
    pub(crate) const fn exact_zero(self) -> bool {
        self.exact_zero
    }
}

/// Stable startup failures with the cleanup evidence produced before return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedModelAssemblyError {
    InvalidConsumerAgentIdentity,
    DependencyIdentityCollision,
    StartupFailed {
        stage: ManagedServiceLifecycleStage,
        fact: ManagedServiceStageFact,
        cleanup: ManagedModelCleanupEvidenceV1,
    },
}

impl fmt::Display for ManagedModelAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConsumerAgentIdentity => {
                formatter.write_str("managed Model consumer Agent identity is invalid")
            }
            Self::DependencyIdentityCollision => {
                formatter.write_str("managed Model and consumer Agent identities collide")
            }
            Self::StartupFailed { stage, fact, .. } => {
                write!(
                    formatter,
                    "managed Model startup failed at {stage:?}: {fact:?}"
                )
            }
        }
    }
}

impl std::error::Error for ManagedModelAssemblyError {}

/// Runtime lifecycle owner for one exact Model service generation.
pub(crate) struct ManagedModelAssembly {
    lifecycle: ManagedServiceAssembly,
    slot: Arc<ManagedModelSlot>,
}

impl ManagedModelAssembly {
    pub(crate) async fn start(
        plan: ManagedModelServicePlanV1,
        generation: ManagedServiceGeneration,
        consumer_agent_service_id: ManagedServiceId,
        resolver: Arc<dyn RuntimeModelBackendResolverV1>,
        clock: RuntimeClock,
        parent_cancellation: &CancellationSource,
    ) -> Result<(Self, ManagedModelDependencyHandle), ManagedModelAssemblyError> {
        let model_service_id = plan.service().service_id();
        if consumer_agent_service_id
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(ManagedModelAssemblyError::InvalidConsumerAgentIdentity);
        }
        if model_service_id == consumer_agent_service_id {
            return Err(ManagedModelAssemblyError::DependencyIdentityCollision);
        }
        let capability_id = plan.adapter_binding().capability_id();
        let slot = Arc::new(ManagedModelSlot {
            model_service_id,
            model_generation: generation,
            consumer_agent_service_id,
            capability_id,
            state: Mutex::new(ManagedModelSlotState::Cold),
        });
        let implementation = RuntimeManagedModelService {
            plan: plan.clone(),
            generation,
            resolver,
            prepared: None,
            slot: Arc::clone(&slot),
        };
        let mut assembly = Self {
            lifecycle: ManagedServiceAssembly::new(
                plan.service(),
                generation,
                Box::new(implementation),
                clock,
                parent_cancellation,
            ),
            slot: Arc::clone(&slot),
        };
        match assembly.lifecycle.startup().await {
            ManagedServiceStartupOutcome::Ready => {
                let handle = ManagedModelDependencyHandle {
                    model_service_id,
                    model_generation: generation,
                    consumer_agent_service_id,
                    capability_id,
                    slot: Arc::downgrade(&slot),
                };
                Ok((assembly, handle))
            }
            ManagedServiceStartupOutcome::Failed { stage, fact } => {
                let cleanup = assembly.shutdown().await;
                Err(ManagedModelAssemblyError::StartupFailed {
                    stage,
                    fact,
                    cleanup,
                })
            }
        }
    }

    pub(crate) async fn shutdown(&mut self) -> ManagedModelCleanupEvidenceV1 {
        let report = self.lifecycle.shutdown().await;
        ManagedModelCleanupEvidenceV1 {
            model_service_id: self.slot.model_service_id,
            model_generation: self.slot.model_generation,
            drain: report.drain(),
            stop: report.stop(),
            exact_zero: report.exact_zero(),
        }
    }
}

impl Drop for ManagedModelAssembly {
    fn drop(&mut self) {
        // Async cleanup is explicit. Dropping an owner without it still fences
        // every weak dependency immediately; it never leaves a callable Ready
        // handle or silently installs another backend.
        if let Ok(mut state) = self.slot.state.lock() {
            *state = ManagedModelSlotState::Stopped;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use paraegox_agent_contracts::{
        AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationSessionId,
        AgentConversationTurnId,
    };
    use paraegox_agent_service::{AgentService, AgentServiceConfigV1};
    use paraegox_kernel::digest::Digest32;
    use paraegox_kernel::time::{BoundedDuration, ClockDomainRef, ClockGeneration};
    use paraegox_model::{
        ModelBackendFuture, ModelCancellationViewV1, ModelInvocationOutcomeV1,
        ModelInvocationRequestV1,
    };
    use paraegox_runtime_contracts::managed_agent_stack_plan::{
        ManagedAgentProviderRefV1, ManagedAgentProviderSelectionV1,
    };
    use paraegox_runtime_contracts::managed_model_agent_stack_plan::{
        ManagedModelAdapterBindingV1, ManagedModelAdapterVersionV1,
    };
    use paraegox_runtime_contracts::managed_service::{
        ManagedServiceLifecycleBudgetsV1, ManagedServiceSpecV1,
    };
    use tokio::sync::oneshot;

    #[derive(Clone)]
    struct EchoBackend {
        identity: ModelBackendIdentityV1,
    }

    impl ModelBackendV1 for EchoBackend {
        fn identity(&self) -> ModelBackendIdentityV1 {
            self.identity
        }

        fn invoke(
            &self,
            request: ModelInvocationRequestV1,
            _cancellation: ModelCancellationViewV1,
        ) -> ModelBackendFuture {
            let output = format!("model: {}", request.prompt()).into_boxed_str();
            Box::pin(async move { ModelInvocationOutcomeV1::Success(output) })
        }
    }

    struct HeldBackend {
        identity: ModelBackendIdentityV1,
        release: Mutex<Option<oneshot::Receiver<()>>>,
    }

    impl ModelBackendV1 for HeldBackend {
        fn identity(&self) -> ModelBackendIdentityV1 {
            self.identity
        }

        fn invoke(
            &self,
            request: ModelInvocationRequestV1,
            _cancellation: ModelCancellationViewV1,
        ) -> ModelBackendFuture {
            let release = self
                .release
                .lock()
                .ok()
                .and_then(|mut release| release.take());
            let output = format!("model: {}", request.prompt()).into_boxed_str();
            Box::pin(async move {
                let Some(release) = release else {
                    return ModelInvocationOutcomeV1::Failed;
                };
                if release.await.is_err() {
                    return ModelInvocationOutcomeV1::Failed;
                }
                ModelInvocationOutcomeV1::Success(output)
            })
        }
    }

    struct FixedResolver {
        plan: ManagedModelServicePlanV1,
        backend: Arc<dyn ModelBackendV1>,
    }

    impl RuntimeModelBackendResolverV1 for FixedResolver {
        fn resolve(
            &self,
            _plan: &ManagedModelServicePlanV1,
        ) -> Result<RuntimeResolvedModelBackendV1, RuntimeModelBackendResolveError> {
            Ok(RuntimeResolvedModelBackendV1::from_shared(
                self.plan,
                Arc::clone(&self.backend),
            ))
        }
    }

    fn generation(value: u64) -> ManagedServiceGeneration {
        ManagedServiceGeneration::try_new(value).expect("fixture generation must be nonzero")
    }

    fn clock() -> RuntimeClock {
        RuntimeClock::new(
            ClockDomainRef::from_bytes([0x61; 16]),
            ClockGeneration::try_new(1).expect("fixture clock generation must be nonzero"),
            0,
        )
    }

    fn service_spec(seed: u8) -> ManagedServiceSpecV1 {
        let budget = BoundedDuration::from_nanos(5_000_000_000);
        let budgets =
            ManagedServiceLifecycleBudgetsV1::try_new(budget, budget, budget, budget, budget)
                .expect("fixture lifecycle budgets must be valid");
        ManagedServiceSpecV1::new(ManagedServiceId::from_bytes([seed; 16]), budgets)
    }

    fn plan(service_seed: u8, adapter_seed: u8, max_in_flight: u16) -> ManagedModelServicePlanV1 {
        let provider = ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            ManagedAgentProviderRefV1::try_from_bytes([0x71; 16])
                .expect("fixture provider reference must be nonzero"),
            Digest32::from_bytes([0x72; 32]),
        )
        .expect("fixture provider selection must be valid");
        let binding = ManagedModelAdapterBindingV1::try_new(
            [adapter_seed; 16],
            ManagedModelAdapterVersionV1::try_new(1)
                .expect("fixture adapter version must be nonzero"),
            ManagedModelCapabilityIdV1::bounded_text_v1(),
        )
        .expect("fixture adapter binding must be valid");
        ManagedModelServicePlanV1::try_new(
            service_spec(service_seed),
            max_in_flight,
            provider,
            binding,
        )
        .expect("fixture Model plan must be valid")
    }

    fn identity(plan: &ManagedModelServicePlanV1) -> ModelBackendIdentityV1 {
        ModelBackendIdentityV1::try_new(
            *plan.provider().provider_ref().as_bytes(),
            plan.provider().config_digest(),
        )
        .expect("fixture backend identity must be valid")
    }

    fn resolver(
        resolved_plan: ManagedModelServicePlanV1,
        backend: impl ModelBackendV1,
    ) -> Arc<dyn RuntimeModelBackendResolverV1> {
        Arc::new(FixedResolver {
            plan: resolved_plan,
            backend: Arc::new(backend),
        })
    }

    fn agent_call(
        seed: u8,
        input: &str,
    ) -> (
        AgentConversationRequestV1,
        AgentConversationModelCancellation,
    ) {
        let deck_run_id = AgentConversationDeckRunId::try_from_bytes([seed; 16])
            .expect("fixture DeckRun identity must be nonzero");
        let session_id = AgentConversationSessionId::try_from_bytes([seed.wrapping_add(1); 16])
            .expect("fixture Session identity must be nonzero");
        let turn_id = AgentConversationTurnId::try_from_bytes([seed.wrapping_add(2); 16])
            .expect("fixture Turn identity must be nonzero");
        let request_id = AgentConversationRequestId::try_from_bytes([seed.wrapping_add(3); 16])
            .expect("fixture request identity must be nonzero");
        let request = AgentConversationRequestV1::try_new(
            deck_run_id,
            session_id,
            turn_id,
            request_id,
            1_000_000_000,
            input,
        )
        .expect("fixture request must be valid");
        let mut agent = AgentService::new(AgentServiceConfigV1::default());
        agent
            .open_session(deck_run_id, session_id)
            .expect("fixture Session must open");
        agent
            .accept_request(request.clone())
            .expect("fixture request must be accepted");
        let invocation = agent
            .begin_execution(deck_run_id, session_id, request_id)
            .expect("fixture execution must begin");
        (invocation.request().clone(), invocation.cancellation())
    }

    #[tokio::test]
    async fn resolver_plan_drift_fails_in_prepare_with_exact_zero_cleanup() {
        let requested = plan(0x11, 0x21, 2);
        let drifted = plan(0x11, 0x22, 2);
        let parent = CancellationSource::root();
        let result = ManagedModelAssembly::start(
            requested,
            generation(7),
            ManagedServiceId::from_bytes([0x31; 16]),
            resolver(
                drifted,
                EchoBackend {
                    identity: identity(&drifted),
                },
            ),
            clock(),
            &parent,
        )
        .await;

        let Err(ManagedModelAssemblyError::StartupFailed { stage, cleanup, .. }) = result else {
            panic!("resolver drift must fail managed Model startup");
        };
        assert_eq!(stage, ManagedServiceLifecycleStage::Prepare);
        assert!(cleanup.exact_zero());
    }

    #[tokio::test]
    async fn backend_identity_drift_fails_before_capacity_is_installed() {
        let requested = plan(0x15, 0x26, 2);
        let drifted_identity =
            ModelBackendIdentityV1::try_new([0x73; 16], Digest32::from_bytes([0x74; 32]))
                .expect("fixture drifted backend identity must be valid");
        let parent = CancellationSource::root();
        let result = ManagedModelAssembly::start(
            requested,
            generation(12),
            ManagedServiceId::from_bytes([0x35; 16]),
            resolver(
                requested,
                EchoBackend {
                    identity: drifted_identity,
                },
            ),
            clock(),
            &parent,
        )
        .await;

        let Err(ManagedModelAssemblyError::StartupFailed { stage, cleanup, .. }) = result else {
            panic!("backend identity drift must fail managed Model startup");
        };
        assert_eq!(stage, ManagedServiceLifecycleStage::Prepare);
        assert!(cleanup.exact_zero());
    }

    #[tokio::test]
    async fn ready_generation_maps_agent_call_through_model_service() {
        let requested = plan(0x12, 0x23, 2);
        let parent = CancellationSource::root();
        let (mut assembly, mut handle) = ManagedModelAssembly::start(
            requested,
            generation(8),
            ManagedServiceId::from_bytes([0x32; 16]),
            resolver(
                requested,
                EchoBackend {
                    identity: identity(&requested),
                },
            ),
            clock(),
            &parent,
        )
        .await
        .expect("matching resolved Model must become Ready");
        let (request, cancellation) = agent_call(0x41, "hello");

        assert_eq!(
            handle.complete(request, cancellation).await,
            AgentConversationModelOutcomeV1::Success("model: hello".into())
        );
        assert!(assembly.shutdown().await.exact_zero());
    }

    #[tokio::test]
    async fn stale_generation_and_stopped_owner_fail_closed() {
        let requested = plan(0x13, 0x24, 2);
        let parent = CancellationSource::root();
        let (mut assembly, mut handle) = ManagedModelAssembly::start(
            requested,
            generation(9),
            ManagedServiceId::from_bytes([0x33; 16]),
            resolver(
                requested,
                EchoBackend {
                    identity: identity(&requested),
                },
            ),
            clock(),
            &parent,
        )
        .await
        .expect("matching resolved Model must become Ready");
        let mut stale = handle.clone();
        stale.model_generation = generation(10);
        let (stale_request, stale_cancellation) = agent_call(0x51, "stale");
        assert_eq!(
            stale.complete(stale_request, stale_cancellation).await,
            AgentConversationModelOutcomeV1::Failed
        );

        assert!(assembly.shutdown().await.exact_zero());
        let (stopped_request, stopped_cancellation) = agent_call(0x61, "stopped");
        assert_eq!(
            handle.complete(stopped_request, stopped_cancellation).await,
            AgentConversationModelOutcomeV1::Failed
        );
    }

    #[tokio::test]
    async fn drain_rejects_new_calls_then_stop_waits_for_exact_zero() {
        let requested = plan(0x14, 0x25, 2);
        let (release_sender, release_receiver) = oneshot::channel();
        let parent = CancellationSource::root();
        let (mut assembly, mut handle) = ManagedModelAssembly::start(
            requested,
            generation(11),
            ManagedServiceId::from_bytes([0x34; 16]),
            resolver(
                requested,
                HeldBackend {
                    identity: identity(&requested),
                    release: Mutex::new(Some(release_receiver)),
                },
            ),
            clock(),
            &parent,
        )
        .await
        .expect("matching held Model must become Ready");
        let slot = handle
            .slot
            .upgrade()
            .expect("live assembly must retain its dependency slot");
        let (held_request, held_cancellation) = agent_call(0x71, "held");
        let held_operation = handle.complete(held_request, held_cancellation);
        let held_task = tokio::spawn(held_operation);
        let shutdown_task = tokio::spawn(async move { assembly.shutdown().await });

        let mut observed_draining = false;
        for _ in 0..64 {
            if slot
                .state
                .lock()
                .is_ok_and(|state| matches!(*state, ManagedModelSlotState::Draining(_)))
            {
                observed_draining = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(observed_draining);
        let (rejected_request, rejected_cancellation) = agent_call(0x75, "new");
        assert_eq!(
            handle
                .complete(rejected_request, rejected_cancellation)
                .await,
            AgentConversationModelOutcomeV1::Failed
        );

        release_sender
            .send(())
            .expect("held backend release receiver must remain live");
        assert_eq!(
            held_task.await.expect("held operation task must join"),
            AgentConversationModelOutcomeV1::Success("model: held".into())
        );
        let cleanup = shutdown_task
            .await
            .expect("managed Model shutdown task must join");
        assert!(cleanup.exact_zero());
        assert_eq!(cleanup.drain(), ManagedServiceStageFact::Succeeded);
        assert_eq!(cleanup.stop(), ManagedServiceStageFact::Succeeded);
    }
}
