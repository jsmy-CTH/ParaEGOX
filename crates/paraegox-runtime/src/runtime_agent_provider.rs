//! Runtime-owned abstraction for rebuilding one exact Agent model provider.
//!
//! Provider-specific configuration and Secret resolution stay in the process
//! composition layer. The Runtime retains only this repeatable factory seam and
//! rechecks the selection returned by it before admitting any provider into an
//! Agent service.

use core::fmt;

use paraegox_agent_service::{
    AgentConversationModelCancellation, AgentConversationModelFuture,
    AgentConversationModelProvider,
};
use paraegox_runtime_contracts::managed_agent_stack_plan::ManagedAgentProviderSelectionV1;

/// Stable, display-safe resolver failures. Provider-specific errors and Secret
/// material must never cross this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAgentProviderResolveError {
    ResolutionFailed,
}

impl fmt::Display for RuntimeAgentProviderResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Runtime provider resolution failed closed")
    }
}

impl std::error::Error for RuntimeAgentProviderResolveError {}

/// One concrete provider together with the exact selection its resolver built.
///
/// Runtime compares this repeated selection with durable desired state before
/// the provider can be started. Both currently admitted profiles use this same
/// wrapper; profile-specific construction remains composition-owned. Debug
/// deliberately omits the provider object.
pub struct RuntimeResolvedAgentProviderV1 {
    selection: ManagedAgentProviderSelectionV1,
    provider: Box<dyn AgentConversationModelProvider>,
}

impl RuntimeResolvedAgentProviderV1 {
    #[must_use]
    pub fn new<P>(selection: ManagedAgentProviderSelectionV1, provider: P) -> Self
    where
        P: AgentConversationModelProvider + 'static,
    {
        Self {
            selection,
            provider: Box::new(provider),
        }
    }

    #[must_use]
    pub const fn selection(&self) -> ManagedAgentProviderSelectionV1 {
        self.selection
    }
}

impl fmt::Debug for RuntimeResolvedAgentProviderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeResolvedAgentProviderV1")
            .field("selection", &self.selection)
            .field("provider", &"<redacted-provider>")
            .finish()
    }
}

impl AgentConversationModelProvider for RuntimeResolvedAgentProviderV1 {
    fn complete(
        &mut self,
        request: paraegox_agent_contracts::AgentConversationRequestV1,
        cancellation: AgentConversationModelCancellation,
    ) -> AgentConversationModelFuture {
        self.provider.complete(request, cancellation)
    }
}

/// Repeatable process-composition seam for one exact selected provider.
///
/// Implementations may retain resolver-owned Secret material, but must return
/// only a provider and the exact non-secret selection it built. Runtime calls
/// this method again during durable recovery; implementations must not consume
/// their factory on the first build.
pub trait RuntimeAgentProviderResolverV1: Send + Sync + 'static {
    fn resolve(
        &self,
        selection: ManagedAgentProviderSelectionV1,
    ) -> Result<RuntimeResolvedAgentProviderV1, RuntimeAgentProviderResolveError>;
}

#[derive(Debug)]
pub(crate) struct UnavailableRuntimeAgentProviderResolver;

impl RuntimeAgentProviderResolverV1 for UnavailableRuntimeAgentProviderResolver {
    fn resolve(
        &self,
        _selection: ManagedAgentProviderSelectionV1,
    ) -> Result<RuntimeResolvedAgentProviderV1, RuntimeAgentProviderResolveError> {
        Err(RuntimeAgentProviderResolveError::ResolutionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use paraegox_agent_contracts::AgentConversationRequestV1;
    use paraegox_agent_service::{
        AgentConversationModelCancellation, AgentConversationModelFuture,
        AgentConversationModelOutcomeV1,
    };
    use paraegox_kernel::digest::Digest32;
    use paraegox_runtime_contracts::managed_agent_stack_plan::{
        ManagedAgentProviderRefV1, ManagedAgentSecretRefV1,
    };

    struct TestProvider;

    impl AgentConversationModelProvider for TestProvider {
        fn complete(
            &mut self,
            _request: AgentConversationRequestV1,
            _cancellation: AgentConversationModelCancellation,
        ) -> AgentConversationModelFuture {
            Box::pin(async { AgentConversationModelOutcomeV1::Failed })
        }
    }

    fn deterministic_selection() -> ManagedAgentProviderSelectionV1 {
        ManagedAgentProviderSelectionV1::try_deterministic_fixture(
            ManagedAgentProviderRefV1::try_from_bytes([0x11; 16])
                .expect("test provider ref must be valid"),
            Digest32::from_bytes([0x12; 32]),
        )
        .expect("deterministic selection must be valid")
    }

    fn provisioned_selection() -> ManagedAgentProviderSelectionV1 {
        ManagedAgentProviderSelectionV1::try_provisioned(
            ManagedAgentProviderRefV1::try_from_bytes([0x21; 16])
                .expect("test provider ref must be valid"),
            Digest32::from_bytes([0x22; 32]),
            ManagedAgentSecretRefV1::try_from_bytes([0x23; 16])
                .expect("test Secret ref must be valid"),
        )
        .expect("provisioned selection must be valid")
    }

    #[test]
    fn resolved_provider_is_profile_neutral_and_retains_the_exact_selection() {
        for selection in [deterministic_selection(), provisioned_selection()] {
            let resolved = RuntimeResolvedAgentProviderV1::new(selection, TestProvider);
            assert_eq!(resolved.selection(), selection);
            assert!(!format!("{resolved:?}").contains("TestProvider"));
        }
    }

    #[test]
    fn unavailable_resolver_fails_closed_for_every_admitted_profile() {
        let resolver = UnavailableRuntimeAgentProviderResolver;
        for selection in [deterministic_selection(), provisioned_selection()] {
            assert!(matches!(
                resolver.resolve(selection),
                Err(RuntimeAgentProviderResolveError::ResolutionFailed)
            ));
        }
    }
}
