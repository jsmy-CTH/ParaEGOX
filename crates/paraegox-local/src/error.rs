use crate::config::ConfigError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalProcessError {
    Configuration(ConfigError),
    UnsafeExecutionIdentity,
    SignalHandling,
    IdentityManifest,
    LayoutPreparation,
    IdentityDerivation,
    ProviderSecret,
    ProviderConfiguration,
    AuthorityStartup,
    RuntimeStartup,
    NodeBootstrap,
    NodeCredentialFiles,
    NodeStartup,
    DeploymentPreparation,
    DeploymentStartup,
    DeploymentReconcileRequired,
    DeploymentOwnerExit,
    DeploymentReadyOutput,
    DeploymentJoinedShutdown,
    DeploymentActivation,
    ConversationConfiguration,
    ConversationCapability,
    ConversationIpc,
    InspectionIpc,
    ConversationChild,
    NodeChild,
    JoinedShutdown,
    DistributedIdentityInitialization,
    DistributedIdentityManifest,
    DistributedEnrollmentPlan,
    DistributedLayoutPreparation,
    DistributedAuthorityStartup,
    DistributedRuntimeAStartup,
    DistributedRuntimeBStartup,
    DistributedNodeAStartup,
    DistributedNodeBStartup,
    DistributedDeploymentActivation,
    DistributedJoinedShutdown,
}

impl LocalProcessError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Configuration(error) => error.code(),
            Self::UnsafeExecutionIdentity => "PXLC-EXECUTION-IDENTITY",
            Self::SignalHandling => "PXLC-SIGNAL-HANDLING",
            Self::IdentityManifest => "PXLC-IDENTITY-MANIFEST",
            Self::LayoutPreparation => "PXLC-LAYOUT-PREPARATION",
            Self::IdentityDerivation => "PXLC-IDENTITY-DERIVATION",
            Self::ProviderSecret => "PXLC-PROVIDER-SECRET",
            Self::ProviderConfiguration => "PXLC-PROVIDER-CONFIGURATION",
            Self::AuthorityStartup => "PXLC-AUTHORITY-STARTUP",
            Self::RuntimeStartup => "PXLC-RUNTIME-STARTUP",
            Self::NodeBootstrap => "PXLC-NODE-BOOTSTRAP",
            Self::NodeCredentialFiles => "PXLC-NODE-CREDENTIAL-FILES",
            Self::NodeStartup => "PXLC-NODE-STARTUP",
            Self::DeploymentPreparation => "PXLC-DEPLOYMENT-PREPARATION",
            Self::DeploymentStartup => "PXLC-DEPLOYMENT-STARTUP",
            Self::DeploymentReconcileRequired => "PXLC-DEPLOYMENT-RECONCILE-REQUIRED",
            Self::DeploymentOwnerExit => "PXLC-DEPLOYMENT-OWNER-EXIT",
            Self::DeploymentReadyOutput => "PXLC-DEPLOYMENT-READY-OUTPUT",
            Self::DeploymentJoinedShutdown => "PXLC-DEPLOYMENT-JOINED-SHUTDOWN",
            Self::DeploymentActivation => "PXLC-DEPLOYMENT-ACTIVATION",
            Self::ConversationConfiguration => "PXLC-CONVERSATION-CONFIGURATION",
            Self::ConversationCapability => "PXLC-CONVERSATION-CAPABILITY",
            Self::ConversationIpc => "PXLC-CONVERSATION-IPC",
            Self::InspectionIpc => "PXLC-INSPECTION-IPC",
            Self::ConversationChild => "PXLC-CONVERSATION-CHILD",
            Self::NodeChild => "PXLC-NODE-CHILD",
            Self::JoinedShutdown => "PXLC-JOINED-SHUTDOWN",
            Self::DistributedIdentityInitialization => "PXLC-DISTRIBUTED-IDENTITY-INITIALIZATION",
            Self::DistributedIdentityManifest => "PXLC-DISTRIBUTED-IDENTITY-MANIFEST",
            Self::DistributedEnrollmentPlan => "PXLC-DISTRIBUTED-ENROLLMENT-PLAN",
            Self::DistributedLayoutPreparation => "PXLC-DISTRIBUTED-LAYOUT-PREPARATION",
            Self::DistributedAuthorityStartup => "PXLC-DISTRIBUTED-AUTHORITY-STARTUP",
            Self::DistributedRuntimeAStartup => "PXLC-DISTRIBUTED-RUNTIME-A-STARTUP",
            Self::DistributedRuntimeBStartup => "PXLC-DISTRIBUTED-RUNTIME-B-STARTUP",
            Self::DistributedNodeAStartup => "PXLC-DISTRIBUTED-NODE-A-STARTUP",
            Self::DistributedNodeBStartup => "PXLC-DISTRIBUTED-NODE-B-STARTUP",
            Self::DistributedDeploymentActivation => "PXLC-DISTRIBUTED-DEPLOYMENT-ACTIVATION",
            Self::DistributedJoinedShutdown => "PXLC-DISTRIBUTED-JOINED-SHUTDOWN",
        }
    }

    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::Configuration(error) => error.message(),
            Self::UnsafeExecutionIdentity => {
                "DeveloperLocal commands require a non-root user and group"
            }
            Self::SignalHandling => "DeveloperLocal process signal handling failed closed",
            Self::IdentityManifest => "DeveloperLocal identity manifest failed closed",
            Self::LayoutPreparation => "DeveloperLocal filesystem layout failed closed",
            Self::IdentityDerivation => "DeveloperLocal identity derivation failed closed",
            Self::ProviderSecret => "provisioned model provider Secret resolution failed closed",
            Self::ProviderConfiguration => "provisioned model provider configuration failed closed",
            Self::AuthorityStartup => "DeveloperLocal tenure Authority failed to start",
            Self::RuntimeStartup => "DeveloperLocal Runtime failed to start",
            Self::NodeBootstrap => "DeveloperLocal Node registration bootstrap failed closed",
            Self::NodeCredentialFiles => "DeveloperLocal Node TLS credential files failed closed",
            Self::NodeStartup => "DeveloperLocal NodeDaemon failed to start",
            Self::DeploymentPreparation => {
                "DeveloperLocal DeploymentController inputs or owner layout failed closed"
            }
            Self::DeploymentStartup => {
                "DeveloperLocal DeploymentController owner graph failed to start"
            }
            Self::DeploymentReconcileRequired => {
                "DeveloperLocal DeploymentController requires explicit reconciliation before readiness"
            }
            Self::DeploymentOwnerExit => {
                "DeveloperLocal DeploymentController owner exited before process shutdown"
            }
            Self::DeploymentReadyOutput => {
                "DeveloperLocal DeploymentController readiness output failed"
            }
            Self::DeploymentJoinedShutdown => {
                "DeveloperLocal DeploymentController owners did not complete joined shutdown"
            }
            Self::DeploymentActivation => {
                "DeploymentController failed to activate the Fabric and Agent stack"
            }
            Self::ConversationConfiguration => "local conversation configuration is invalid",
            Self::ConversationCapability => {
                "Runtime refused the committed Agent conversation capability"
            }
            Self::ConversationIpc => "Runtime-backed local conversation IPC failed closed",
            Self::InspectionIpc => "node-local read-only Inspection IPC failed closed",
            Self::ConversationChild => {
                "local Textual console child failed to complete joined execution"
            }
            Self::NodeChild => "DeveloperLocal NodeDaemon child process failed",
            Self::JoinedShutdown => "DeveloperLocal owners did not complete joined shutdown",
            Self::DistributedIdentityInitialization => {
                "distributed DeveloperLocal identity initialization failed closed"
            }
            Self::DistributedIdentityManifest => {
                "distributed DeveloperLocal identity manifest failed closed"
            }
            Self::DistributedEnrollmentPlan => {
                "distributed DeveloperLocal certificate enrollment plan failed closed"
            }
            Self::DistributedLayoutPreparation => {
                "distributed DeveloperLocal filesystem layout failed closed"
            }
            Self::DistributedAuthorityStartup => {
                "distributed DeveloperLocal tenure Authority failed to start"
            }
            Self::DistributedRuntimeAStartup => {
                "distributed DeveloperLocal Runtime A failed to start"
            }
            Self::DistributedRuntimeBStartup => {
                "distributed DeveloperLocal Runtime B failed to start"
            }
            Self::DistributedNodeAStartup => {
                "distributed DeveloperLocal logical Node A failed to start"
            }
            Self::DistributedNodeBStartup => {
                "distributed DeveloperLocal logical Node B failed to start"
            }
            Self::DistributedDeploymentActivation => {
                "distributed DeploymentController failed to activate both target stacks"
            }
            Self::DistributedJoinedShutdown => {
                "distributed DeveloperLocal owners did not complete joined shutdown"
            }
        }
    }

    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::Configuration(_) => 2,
            _ => 1,
        }
    }
}

impl From<ConfigError> for LocalProcessError {
    fn from(error: ConfigError) -> Self {
        Self::Configuration(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_and_integration_failures_have_distinct_exit_codes() {
        let configuration = LocalProcessError::Configuration(ConfigError::MissingMode);
        assert_eq!(configuration.exit_code(), 2);
        assert_eq!(configuration.code(), "PXLC-MODE-MISSING");

        let integration = LocalProcessError::DeploymentActivation;
        assert_eq!(integration.exit_code(), 1);
        assert_eq!(integration.code(), "PXLC-DEPLOYMENT-ACTIVATION");
        assert!(!integration.message().contains("ready"));
    }

    #[test]
    fn distributed_owner_stages_have_distinct_stable_error_codes() {
        let stages = [
            LocalProcessError::DistributedIdentityInitialization,
            LocalProcessError::DistributedIdentityManifest,
            LocalProcessError::DistributedEnrollmentPlan,
            LocalProcessError::DistributedLayoutPreparation,
            LocalProcessError::DistributedAuthorityStartup,
            LocalProcessError::DistributedRuntimeAStartup,
            LocalProcessError::DistributedRuntimeBStartup,
            LocalProcessError::DistributedNodeAStartup,
            LocalProcessError::DistributedNodeBStartup,
            LocalProcessError::DistributedDeploymentActivation,
            LocalProcessError::DistributedJoinedShutdown,
        ];
        let mut codes = std::collections::BTreeSet::new();
        for stage in stages {
            assert!(stage.code().starts_with("PXLC-DISTRIBUTED-"));
            assert!(codes.insert(stage.code()), "duplicate stage error code");
            assert!(!stage.message().is_empty());
            assert_eq!(stage.exit_code(), 1);
        }
    }

    #[test]
    fn public_deployment_lifecycle_failures_are_distinct_and_never_claim_ready() {
        let stages = [
            LocalProcessError::DeploymentPreparation,
            LocalProcessError::DeploymentStartup,
            LocalProcessError::DeploymentReconcileRequired,
            LocalProcessError::DeploymentOwnerExit,
            LocalProcessError::DeploymentReadyOutput,
            LocalProcessError::DeploymentJoinedShutdown,
        ];
        let mut codes = std::collections::BTreeSet::new();
        for stage in stages {
            assert!(stage.code().starts_with("PXLC-DEPLOYMENT-"));
            assert!(codes.insert(stage.code()), "duplicate Deployment stage code");
            assert_eq!(stage.exit_code(), 1);
        }
        assert!(!LocalProcessError::DeploymentReconcileRequired
            .message()
            .contains("is ready"));
        assert!(!LocalProcessError::DeploymentOwnerExit
            .message()
            .contains("is ready"));
    }
}
